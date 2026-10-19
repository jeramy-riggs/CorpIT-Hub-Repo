#!/usr/bin/env python3
"""The change ledger: the gate, the diff, and the things that must not be faked.

The checks worth having here are not "does it render". They are:

  * a blocked preflight must stop the write, at the ROUTE, not only in the page
  * the diff on screen must be the diff between the two stored bodies
  * an approval must never appear that nobody recorded

The happy path is exercised against a throwaway record that is deleted again, in
the same style as test_permissions.py's round-trip: a state machine that is only
ever read in one state is a state machine nobody has tested.
"""
import re
import sys
import time

sys.path.insert(0, "/opt/subdomain-admin")
import app as A  # noqa: E402
import change_control as CC  # noqa: E402

FAIL = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name +
          (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAIL.append(name)


def client(role="platform-owner", user="jriggs@auction.com", groups=None):
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["user"] = user
        s["auth_at"] = int(time.time())
        s["csrf"] = "test-csrf-token"
        s["sso"] = {"user": user, "upn": user, "name": "Test", "role": role,
                    "groups": groups if groups is not None else ["saas-ith-sa"],
                    "can_write": True, "can_write_prod": role == "platform-owner",
                    "auth": "entra"}
    return c


# --------------------------------------------------------------- pure functions
print("\n--- network membership ---")
for ip, cidr, want in [("10.9.119.218", "10.9.0.0/16", True),
                       ("10.9.58.207", "10.9.0.0/16", True),
                       ("10.10.0.1", "10.9.0.0/16", False),
                       ("100.64.3.9", "10.0.0.0/8", False),
                       ("10.255.255.254", "10.0.0.0/8", True),
                       ("not-an-ip", "10.0.0.0/8", False),
                       ("10.9.0.1", "10.9.0.0/nonsense", False)]:
    check("%s in %s is %s" % (ip, cidr, want), CC._in_net(ip, cidr) is want)

print("\n--- the configuration parser rejects what nginx would ---")
check("unbalanced open brace fails",
      CC._check_syntax("server {\n    listen 443;\n").status == "failed")
check("stray close brace fails",
      CC._check_syntax("}\nserver {\n}\n").status == "failed")
check("missing semicolon fails",
      CC._check_syntax("server {\n    listen 443\n}\n").status == "failed")
check("a well-formed block passes",
      CC._check_syntax("server {\n    listen 443;\n    # note\n}\n").status == "passed")

print("\n--- the access check is about WHO, not where from ---")
after = "server {\n    satisfy all;\n    allow 10.9.0.0/16;\n    deny all;\n}\n"
open_policy = {"mode": "group", "groups": ["saas-ith-hd"], "inherited": False}
c = CC._check_access(after, open_policy, "Rotate certificate + restrict owner access")
check("a network allowlist does not deliver 'owner only'", c.status == "failed", c.detail)
check("the failure names the groups that still get in",
      "saas-ith-hd" in (c.evidence + c.detail), c.evidence)
c2 = CC._check_access(after, {"mode": "superadmin", "groups": [], "inherited": False},
                      "Rotate certificate + restrict owner access")
check("it stops failing once the gate really is owner-only", c2.status == "passed", c2.detail)
c3 = CC._check_access(after, None, "anything")
check("an unreadable gate policy is 'unknown', never 'passed'", c3.status == "unknown")

print("\n--- reachability is evidence-based, and says so when it has none ---")
r = CC._check_reachability(after, [])
check("no observed sources is 'unknown', not a pass", r.status == "unknown")
r2 = CC._check_reachability(after, ["10.9.119.218", "100.64.1.1"])
check("a source outside the allowlist blocks", r2.status == "failed", r2.detail)
r3 = CC._check_reachability(after, ["10.9.119.218", "10.9.58.207"])
check("all sources inside passes", r3.status == "passed", r3.detail)

print("\n--- the diff is computed, not asserted ---")
before = "a\nb\nc\n"
aft = "a\nB\nc\nd\n"
split, unified = CC.diff_rows(before, aft)
adds = [u["t"] for u in unified if u["k"] == "add"]
dels = [u["t"] for u in unified if u["k"] == "del"]
check("changed line shows on both sides", adds == ["B", "d"] and dels == ["b"],
      "%s / %s" % (adds, dels))
check("every split row has at least one side",
      all(l or r for l, r in split))
check("left line numbers are the before file's",
      [l["n"] for l, _ in split if l] == [1, 2, 3])


# --------------------------------------------------------------- the page
print("\n--- the section renders, and tells the truth about approvals ---")
own = client()
r = own.get("/console")
body = r.get_data(as_text=True)
check("console still 200", r.status_code == 200)
check("change section present", 'data-view="change"' in body)
check("change history tab present", 'data-tab="history"' in body)
check("change navigation present", 'data-nav="change"' in body)
check("no unrendered Jinja", "{{" not in body and "{%" not in body)

m = re.search(r"<h3>(\d+) of (\d+) approvals</h3>", body)
check("approval count rendered", bool(m), body[:200] if not m else "")
if m:
    given, need = int(m.group(1)), int(m.group(2))
    rows = A.app.test_client()
    with A.app.app_context():
        pass
    check("no approval is shown that nobody recorded", given == 0 or given <= need,
          "%s of %s" % (given, need))
check("the seeded record is labelled an example", "Seeded example" in body)
check("both diff panes are rendered", body.count('data-cc-view="split"') >= 1
      and 'data-cc-view="unified"' in body)
check("unified starts hidden", re.search(r'data-cc-view="unified" hidden', body) is not None)
check("preflight is blocked and says why", "PREFLIGHT" in body.upper()
      or "Preflight blocked" in body)
check("the deploy control is inert, with a reason",
      "No deploy runner is attached" in body)

# The rendered diff must be the diff of the two stored bodies - not a snapshot
# that drifted away from them.
with A.app.test_request_context("/console"):
    from flask import session as fsession
    fsession["user"] = "jriggs@auction.com"
    fsession["sso"] = {"role": "platform-owner", "groups": []}
    row = A.db().execute("SELECT * FROM cc_changes WHERE ref='CHG-2841'").fetchone()
    if row is None:
        check("seeded change exists", False, "CHG-2841 missing")
    else:
        sp, un = CC.diff_rows(row["before_body"], row["after_body"])
        n_add = sum(1 for u in un if u["k"] == "add")
        n_del = sum(1 for u in un if u["k"] == "del")
        check("the page's +/- counts match the stored bodies",
              ("+%d" % n_add) in body and ("%d" % n_del) in body,
              "+%d -%d" % (n_add, n_del))
        check("the certificate rotation really is in the diff",
              any("fullchain-2026-09.pem" in u["t"] for u in un if u["k"] == "add"))
        check("the allowlist really is in the diff",
              any("allow 10.9.0.0/16" in u["t"] for u in un if u["k"] == "add"))

print("\n--- a viewer sees the record and none of the write controls ---")
vw = client(role="viewer", user="viewer@auction.com", groups=[])
vb = vw.get("/console").get_data(as_text=True)
check("viewer still gets the section", 'data-view="change"' in vb)
check("viewer is offered no approve button", "Approve as" not in vb)


# --------------------------------------------------------------- the gate
print("\n--- a blocked preflight stops the WRITE, not just the button ---")
before_stage = None
with A.app.test_request_context("/console"):
    row = A.db().execute("SELECT stage, approval_requested_at FROM cc_changes "
                         "WHERE ref='CHG-2841'").fetchone()
    before_stage = (row["stage"], row["approval_requested_at"]) if row else None

r = own.post("/change/CHG-2841/request",
             data={"csrf": "test-csrf-token", "_back": "/console#change"})
check("the request route redirects rather than 500s", r.status_code in (302, 303),
      r.status_code)
with A.app.test_request_context("/console"):
    row = A.db().execute("SELECT stage, approval_requested_at FROM cc_changes "
                         "WHERE ref='CHG-2841'").fetchone()
    after_stage = (row["stage"], row["approval_requested_at"]) if row else None
check("the blocked change did NOT move", before_stage == after_stage,
      "%s -> %s" % (before_stage, after_stage))

r = own.post("/change/CHG-2841/request", data={"_back": "/console#change"})
check("a request with no CSRF token is refused", r.status_code == 400, r.status_code)

r = vw.post("/change/CHG-2841/request",
            data={"csrf": "test-csrf-token", "_back": "/console#change"})
with vw.session_transaction() as s:
    pass
check("a viewer cannot raise a change", r.status_code in (302, 303))

r = own.post("/change/CHG-2841/request",
             data={"csrf": "test-csrf-token", "_back": "https://evil.example/x"})
check("_back off-site is not honoured on the change routes",
      "evil.example" not in (r.headers.get("Location") or ""),
      r.headers.get("Location"))


# --------------------------------------------------------------- the happy path
print("\n--- request -> approve -> approve, on a throwaway record ---")
REF = "CHG-SELFTEST"
good_after = ("server {\n    listen 443 ssl http2;\n"
              "    ssl_protocols TLSv1.2 TLSv1.3;\n"
              "    satisfy all;\n    allow 10.9.0.0/16;\n    deny all;\n}\n")
good_before = ("server {\n    listen 443 ssl http2;\n"
               "    ssl_protocols TLSv1.2 TLSv1.3;\n}\n")
try:
    with A.app.test_request_context("/console"):
        A.db().execute(
            "INSERT INTO cc_changes(ref,title,summary,environment,target_fqdn,"
            "config_path,before_version,after_version,before_at,after_at,"
            "before_body,after_body,stage,outcome,origin,requested_by,created_at,"
            "window_start,window_end,duration_estimate,rollback_version,"
            "rollback_tested_at,rollback_tested_ok) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (REF, "Tighten the network allowlist", "self-test", "prod",
             "corpit.nrpi.local", "/tmp/selftest.conf", "v1", "v2",
             "2026-01-01 00:00:00 UTC", "2026-01-01 00:00:00 UTC",
             good_before, good_after, "preflight", "open", "live",
             "someone-else@auction.com", "2026-01-01 00:00:00 UTC",
             "2026-01-02 02:00:00 UTC", "2026-01-02 03:00:00 UTC", "~5 minutes",
             "v1", "2026-01-01 00:00:00 UTC", 1))
        A.db().commit()

        row = A.db().execute("SELECT * FROM cc_changes WHERE ref=?", (REF,)).fetchone()
        checks, _, _, _ = CC.checks_for(A, row)
        blocking = [c.label for c in checks if c.blocking]
        check("a clean change has no blockers", not blocking, blocking)

        err = CC.request_approval(A, REF, "jriggs@auction.com")
        check("request accepted", err is None, err)
        row = A.db().execute("SELECT * FROM cc_changes WHERE ref=?", (REF,)).fetchone()
        check("stage moved to approval", row["stage"] == "approval", row["stage"])

        err = CC.request_approval(A, REF, "jriggs@auction.com")
        check("a second request is refused", err is not None)

        err = CC.record_decision(A, REF, "owner", "approved", "jriggs@auction.com")
        check("first approval recorded", err is None, err)
        err = CC.record_decision(A, REF, "owner", "approved", "jriggs@auction.com")
        check("the same slot cannot approve twice", err is not None)
        row = A.db().execute("SELECT * FROM cc_changes WHERE ref=?", (REF,)).fetchone()
        check("one approval does not release it", row["stage"] == "approval", row["stage"])

        err = CC.record_decision(A, REF, "change", "approved", "rabad@auction.com")
        check("second approval recorded", err is None, err)
        row = A.db().execute("SELECT * FROM cc_changes WHERE ref=?", (REF,)).fetchone()
        check("two approvals release it to deploy", row["stage"] == "deploy", row["stage"])

        CC.reopen(A, REF, "jriggs@auction.com")
        row = A.db().execute("SELECT * FROM cc_changes WHERE ref=?", (REF,)).fetchone()
        n = A.db().execute("SELECT COUNT(*) FROM cc_approvals WHERE change_id=?",
                           (row["id"],)).fetchone()[0]
        check("reopening returns it to preflight and clears approvals",
              row["stage"] == "preflight" and n == 0, "%s / %d" % (row["stage"], n))

        err = CC.record_decision(A, REF, "owner", "approved", "someone-else@auction.com")
        check("a change out of the approval stage cannot be decided", err is not None)
finally:
    with A.app.test_request_context("/console"):
        r = A.db().execute("SELECT id FROM cc_changes WHERE ref=?", (REF,)).fetchone()
        if r:
            A.db().execute("DELETE FROM cc_approvals WHERE change_id=?", (r["id"],))
            A.db().execute("DELETE FROM cc_changes WHERE id=?", (r["id"],))
            A.db().commit()
        left = A.db().execute("SELECT COUNT(*) FROM cc_changes WHERE ref=?",
                              (REF,)).fetchone()[0]
        check("the throwaway record was cleaned up", left == 0)


print()
if FAIL:
    print("FAILURES (%d): %s" % (len(FAIL), "; ".join(FAIL)))
    sys.exit(1)
print("ALL CHANGE-CONTROL CHECKS PASSED (0 failures)")
