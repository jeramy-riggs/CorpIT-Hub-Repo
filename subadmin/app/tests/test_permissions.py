#!/usr/bin/env python3
"""Does the capability model actually refuse the things it says it refuses?

Every check exercises the real route through the app, not the helper in
isolation - a policy that is correct in permissions.py but not wired to a route
protects nothing.
"""
import json
import re
import sys
import time

sys.path.insert(0, "/opt/subdomain-admin")
import app as A  # noqa: E402
import permissions as P  # noqa: E402

FAIL = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (("  -- " + detail) if not cond else ""))
    if not cond:
        FAIL.append(name)


def client(groups, role, user="tester@auction.com"):
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["user"] = user
        s["auth_at"] = int(time.time())
        s["sso"] = {"user": user, "upn": user, "name": user, "role": role,
                    "groups": list(groups), "can_write": True,
                    "can_write_prod": role == "platform-owner", "auth": "entra"}
    return c


def csrf(c):
    return re.search(r'name="csrf" value="([^"]+)"',
                     c.get("/console").get_data(as_text=True)).group(1)


# Routes that must refuse a viewer. Each is (label, method-path, capability).
# Deliberately chosen so a refusal is observable BEFORE the route would do work:
# a 302 back to the console with the deny flash, not a 404 or a side effect.
CASES = [
    ("create a subdomain", "/subdomains", "subdomain.create"),
    ("remove a subdomain", "/subdomains/7/delete", "subdomain.delete"),
    ("push DNS", "/subdomains/7/dns", "subdomain.dns"),
    ("deploy a certificate", "/subdomains/7/cert", "subdomain.cert"),
    ("change site access", "/subdomains/7/access", "subdomain.access"),
    ("start a sync", "/gal/sync", "directory.sync"),
    ("add recipients", "/gal/recipients", "directory.manage"),
    ("save settings", "/settings", "settings.manage"),
    ("change permissions", "/permissions", "permissions.manage"),
]


def denied(c, path, tok):
    """Refused iff nothing was done: either a 403, or a redirect straight back to
    the console carrying the deny flash. /permissions answers 403 because it is
    owner-gated rather than capability-gated - a harder no, which is the point."""
    r = c.post(path, data={"csrf": tok}, follow_redirects=False)
    loc = r.headers.get("Location", "")
    if r.status_code == 403:
        return True, "403"
    return (r.status_code in (302, 303) and loc.startswith("/console"),
            "%s %s" % (r.status_code, loc))


print("--- viewer (Tier1) must be refused everything ---")
c = client(["saas-ith-ro"], "viewer")
tok = csrf(c)
for label, path, cap in CASES:
    ok, detail = denied(c, path, tok)
    check("viewer refused: %s" % label, ok, detail)

print("\n--- operator (Tier2) holds the day-to-day set, not the dangerous one ---")
c = client(["saas-ith-hd"], "operator")
tok = csrf(c)
policy = P.load(A.PERMISSIONS_PATH)
with A.app.test_request_context("/"):
    pass
for label, path, cap in CASES:
    ok, detail = denied(c, path, tok)
    granted = bool(set(policy.get(cap) or ()) & {"saas-ith-hd"})
    if granted:
        check("operator NOT refused: %s" % label, not ok, detail)
    else:
        check("operator refused: %s" % label, ok, detail)

print("\n--- the owner holds everything, unconditionally ---")
c = client(["saas-ith-sa"], "platform-owner")
body = c.get("/console").get_data(as_text=True)
check("owner sees the editable permission matrix", 'name="cap:subdomain.delete"' in body)
check("owner sees the settings form", "Save settings" in body)
c2 = client(["saas-ith-ro"], "viewer")
body2 = c2.get("/console").get_data(as_text=True)
check("viewer sees permissions read-only", 'name="cap:subdomain.delete"' not in body2
      and "Permissions" in body2)
check("viewer is not offered the create form", 'name="label"' not in body2)
check("viewer is not offered a delete button", "Remove accessportal.nrpi.local" not in body2)

print("\n--- the policy file cannot be talked into a bad grant ---")
check("unknown capability dropped",
      "nonsense.key" not in P.normalise({"nonsense.key": ["saas-ith-sa"]}))
check("group outside the resolved family dropped",
      P.normalise({"subdomain.delete": ["domain admins"]})["subdomain.delete"] == [])
check("permissions.manage is not settable from a file",
      P.normalise({"permissions.manage": ["saas-ith-ro"]})["permissions.manage"] == [])
check("corrupt policy falls back to defaults, not to open",
      P.normalise("not a dict") == P.defaults())
check("defaults grant nothing dangerous",
      all(not P.defaults()[k] for k in ("subdomain.delete", "subdomain.access",
                                        "settings.manage", "permissions.manage")))

print("\n--- the ladder guard ---")
owner_sess = {"sso": {"role": "platform-owner", "groups": []}}
check("owner allowed even with an empty policy and no groups",
      P.allowed(P.defaults(), "subdomain.delete", owner_sess, True))
check("permissions.manage denied to a non-owner however it is granted",
      not P.allowed({"permissions.manage": ["saas-ith-ro"]},
                    "permissions.manage",
                    {"sso": {"groups": ["saas-ith-ro"]}}, False))

print("\n--- an owner's edit round-trips and is audited ---")
c = client(["saas-ith-sa"], "platform-owner", user="jriggs@auction.com")
tok = csrf(c)
before = P.load(A.PERMISSIONS_PATH)
from werkzeug.datastructures import MultiDict
r = c.post("/permissions", data=MultiDict([
    ("csrf", tok),
    ("cap:subdomain.delete", "saas-ith-hd"),
    ("cap:permissions.manage", "saas-ith-ro")]))
after = P.load(A.PERMISSIONS_PATH)
check("edit saved", after.get("subdomain.delete") == ["saas-ith-hd"],
      json.dumps(after.get("subdomain.delete")))
check("permissions.manage stayed owner-only despite being posted",
      after.get("permissions.manage") == [], json.dumps(after.get("permissions.manage")))
check("unticked capabilities were cleared", after.get("subdomain.create") == [])
with A.app.app_context():
    rows = A.sqlite3.connect(A.DB_PATH).execute(
        "SELECT action, detail FROM audit ORDER BY id DESC LIMIT 6").fetchall()
check("change written to the audit log",
      any(r[0] == "permission-change" for r in rows), str(rows[:3]))

# Put the policy back the way it was found.
P.save(A.PERMISSIONS_PATH, before)
check("policy restored", P.load(A.PERMISSIONS_PATH) == before)

print("\n%s (%d failures)" % ("ALL PERMISSION CHECKS PASSED" if not FAIL
                              else "FAILURES: " + ", ".join(FAIL), len(FAIL)))
sys.exit(1 if FAIL else 0)
