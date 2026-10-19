#!/usr/bin/env python3
"""Directory Sync: holding people back without touching AD.

What is worth checking here is not that the page renders, it is:

  * a rule saved on the console is what the engine will read (file shape)
  * the route refuses junk (bad mode, no addresses, over the cap) and never
    starts from an empty list when the file on disk is damaged
  * the roster endpoint lays a rule over the snapshot immediately (pending),
    keeps a rule that matches nobody visible, and never carries a phone number
  * restore removes exactly one rule and 404s on a rule that is not there
  * the "only people with a mobile number" switch is written in the shape the
    engine reads (policy + who/when), refuses unknown keys, is a no-op when
    already set, survives a damaged file untouched, and is reported by /gal/roster
  * every write is audited and kicks a sync (stubbed - nothing touches Graph)

Runs against throwaway files; the live lists/exclusions/roster are untouched.
"""
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/opt/subdomain-admin")
import app as A  # noqa: E402

FAIL = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name +
          (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAIL.append(name)


def client(role="platform-owner", user="jriggs@auction.com"):
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["user"] = user
        s["auth_at"] = int(time.time())
        s["csrf"] = "test-csrf-token"
        s["sso"] = {"user": user, "upn": user, "name": "Test", "role": role,
                    "groups": ["saas-ith-sa"], "can_write": True,
                    "can_write_prod": role == "platform-owner"}
    return c


tmp = tempfile.mkdtemp(prefix="gal-excl-test-")
# Audit rows go to a throwaway copy of the console database - a test must not
# leave "gal-exclude alice@" lines in the live audit log for someone to chase.
import shutil
shutil.copy(A.DB_PATH, os.path.join(tmp, "subdomains.db"))
A.DB_PATH = os.path.join(tmp, "subdomains.db")
A.GAL_EXCLUSIONS_JSON = os.path.join(tmp, "exclusions.json")
A.GAL_ROSTER_JSON = os.path.join(tmp, "roster.json")
A.GAL_LISTS_JSON = os.path.join(tmp, "lists.json")
A.GAL_STATE_JSON = os.path.join(tmp, "state.json")
kicks = []
A._gal_kick_sync = lambda: (kicks.append(1), True)[1]
TEST_RUN_AT = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

with open(A.GAL_ROSTER_JSON, "w") as fh:
    json.dump({
        "generatedAt": TEST_RUN_AT, "mode": "apply", "fetched": 3, "published": 2,
        "policy": {"requireMobile": False}, "heldByPolicy": 0,
        "people": [
            {"id": "id-1", "upn": "Alice@auction.com", "mail": "Alice@auction.com", "name": "Alice Example",
             "published": True, "reason": None, "exclusion": None, "title": "CEO", "dept": "Exec",
             "mobile": "yes", "desk": "yes", "lists": ["company"]},
            {"id": "id-2", "upn": "bob@auction.com", "mail": "bob@auction.com", "name": "Bob Example",
             "published": True, "reason": None, "exclusion": None, "mobile": "none", "desk": "yes", "lists": ["company"]},
            {"id": "id-3", "upn": "old@auction.com", "mail": "old@auction.com", "name": "Old Account",
             "published": False, "reason": "account disabled", "exclusion": None},
        ]}, fh)

with open(A.GAL_STATE_JSON, "w") as fh:
    json.dump({
        "mode": "apply", "startedAt": TEST_RUN_AT, "finishedAt": TEST_RUN_AT,
        "opsFailed": 0, "rosterCount": 2,
    }, fh)

with open(A.GAL_LISTS_JSON, "w") as fh:
    json.dump([{
        "id": "company", "name": "Company Directory", "category": "Company Directory",
        "source": {"type": "all"}, "recipients": ["legacy@auction.com"], "enabled": True,
    }], fh)

print("\n[fence helper fails closed]")
real_fence_add = A._gal_fence_add
real_run = A.subprocess.run
A._gal_add_ready = lambda: True
A.subprocess.run = lambda *args, **kwargs: type(
    "Run", (), {"returncode": 1, "stdout": "", "stderr": "PowerShell failed"}
)()
added, already, failed = real_fence_add(["alice@auction.com"])
check("nonzero helper exit confirms nobody", not added and not already and len(failed) == 1, failed)
A.subprocess.run = lambda *args, **kwargs: type(
    "Run", (), {
        "returncode": 0,
        "stdout": json.dumps([{"email": "alice@auction.com", "result": "already"}]),
        "stderr": "",
    }
)()
added, already, failed = real_fence_add(["alice@auction.com", "bob@auction.com"])
check("partial helper response fails every unconfirmed mailbox",
      not added and already == ["alice@auction.com"] and failed == [
          ("bob@auction.com", "fence helper returned no result for this recipient")
      ], (added, already, failed))
A.subprocess.run = real_run

fence_calls = []
A._gal_fence_add = lambda emails: (fence_calls.append(list(emails)) or (list(emails), [], []))

c = client()
POST = {"csrf": "test-csrf-token", "_back": "/console#directory"}

print("\n[roster endpoint, no rules]")
r = c.get("/gal/roster", headers={"Accept-Encoding": "gzip"})
check("200", r.status_code == 200, r.status_code)
check("gzip honoured", r.headers.get("Content-Encoding") == "gzip")
import gzip
d = json.loads(gzip.decompress(r.data))
check("three people", len(d["people"]) == 3)
check("no phone numbers in any row",
      not any(k in ("mobilePhone", "businessPhones") for p in d["people"] for k in p))
check("modes advertised", set(d["modes"]) == {"hide", "no-mobile", "no-phones"})

print("\n[validation]")
r = c.post("/gal/exclusions", data=dict(POST, emails="", mode="hide"), follow_redirects=False)
check("no addresses -> refused (no file written)", not os.path.exists(A.GAL_EXCLUSIONS_JSON))
r = c.post("/gal/exclusions", data=dict(POST, emails="alice@auction.com", mode="vanish"))
check("bad mode -> refused", not os.path.exists(A.GAL_EXCLUSIONS_JSON))
too_many = " ".join("u%d@auction.com" % i for i in range(A.GAL_EXCLUDE_MAX + 1))
r = c.post("/gal/exclusions", data=dict(POST, emails=too_many, mode="hide"))
check("over the cap -> refused", not os.path.exists(A.GAL_EXCLUSIONS_JSON))
r = c.post("/gal/exclusions", data=dict(POST, emails="alice@auction.com", mode="hide", csrf="wrong"))
check("bad CSRF -> 400", r.status_code == 400, r.status_code)
check("nothing kicked a sync so far", not kicks)

print("\n[add: hide the CEO, keep bob's card but drop the mobile, plus a typo]")
r = c.post("/gal/exclusions", data=dict(POST, emails="Alice@auction.com", mode="hide",
                                        reason="Exec\x00 — not for\x1f distribution"))
check("redirects back to the console view", r.status_code in (302, 303) and r.headers["Location"] == "/console#directory", r.headers.get("Location"))
doc = json.load(open(A.GAL_EXCLUSIONS_JSON))
check("file has the engine's shape", doc.get("version") == 1 and isinstance(doc.get("rules"), list))
rule = doc["rules"][0]
check("upn lowercased", rule["upn"] == "alice@auction.com", rule)
check("stable id + name copied from the snapshot", rule.get("id") == "id-1" and rule.get("name") == "Alice Example", rule)
check("control chars scrubbed from the reason", "\x00" not in rule["reason"] and "\x1f" not in rule["reason"], repr(rule["reason"]))
check("by/at recorded", rule["by"] == "jriggs@auction.com" and rule["at"].endswith("Z") or "T" in rule["at"])
check("sync kicked", len(kicks) == 1)

c.post("/gal/exclusions", data=dict(POST, emails="bob@auction.com, typo@auction.com", mode="no-mobile", reason="test"))
doc = json.load(open(A.GAL_EXCLUSIONS_JSON))
check("three rules now", len(doc["rules"]) == 3, [x["upn"] for x in doc["rules"]])
check("typo rule saved without an id", not next(x for x in doc["rules"] if x["upn"] == "typo@auction.com").get("id"))

c.post("/gal/exclusions", data=dict(POST, emails="alice@auction.com", mode="no-phones", reason="changed"))
doc = json.load(open(A.GAL_EXCLUSIONS_JSON))
check("re-adding the same person replaces, never duplicates",
      len(doc["rules"]) == 3 and next(x for x in doc["rules"] if x["upn"] == "alice@auction.com")["mode"] == "no-phones")
c.post("/gal/exclusions", data=dict(POST, emails="alice@auction.com", mode="no-phones", reason="changed"))
check("identical re-save is a no-op (no extra sync kick)", len(kicks) == 3, len(kicks))

print("\n[roster endpoint, with rules]")
d = json.loads(c.get("/gal/roster").data)
alice = next(p for p in d["people"] if p["upn"] == "Alice@auction.com")
check("rule laid over the snapshot row", alice["rule"]["mode"] == "no-phones")
check("shows as pending until a sync applies it", alice["ruleState"] == "pending", alice.get("ruleState"))
typo = next((p for p in d["people"] if p["upn"] == "typo@auction.com"), None)
check("rule matching nobody is still listed", typo is not None and typo.get("unmatched") is True, typo)
check("rules count", d["rules"] == 3)

print("\n[damaged file never silently becomes an empty list]")
with open(A.GAL_EXCLUSIONS_JSON, "w") as fh:
    fh.write('{"version":1,"rules":"nope"}')
r = c.post("/gal/exclusions", data=dict(POST, emails="carol@auction.com", mode="hide"))
check("add refused, file left as it was", open(A.GAL_EXCLUSIONS_JSON).read() == '{"version":1,"rules":"nope"}')
d = json.loads(c.get("/gal/roster").data)
check("roster endpoint reports the damage", bool(d.get("rulesError")))
with open(A.GAL_EXCLUSIONS_JSON, "w") as fh:
    json.dump(doc, fh)

print("\n[restore]")
r = c.post("/gal/exclusions/remove", data=dict(POST, upn="TYPO@auction.com"))
doc2 = json.load(open(A.GAL_EXCLUSIONS_JSON))
check("removes exactly that rule (case-insensitive)", [x["upn"] for x in doc2["rules"]] == ["alice@auction.com", "bob@auction.com"], doc2)
r = c.post("/gal/exclusions/remove", data=dict(POST, upn="nobody@auction.com"))
check("unknown rule -> 404", r.status_code == 404, r.status_code)

print("\n[the mobile-number switch]")
d = c.get("/gal/roster").get_json()
check("roster reports the switch off and the snapshot's view of it",
      d["policy"] == {"requireMobile": False} and d["snapshotPolicy"] == {"requireMobile": False}, (d.get("policy"), d.get("snapshotPolicy")))
check("roster names the engine's reason string", d.get("policyReason") == "no mobile number")
n_kicks = len(kicks)
r = c.post("/gal/policy", data=dict(POST, key="requireMobile", value="1"))
docp = json.load(open(A.GAL_EXCLUSIONS_JSON))
check("switch on -> redirects back", r.status_code in (302, 303) and r.headers["Location"] == "/console#directory", r.status_code)
check("policy written as a bool the engine accepts", docp.get("policy") == {"requireMobile": True}, docp.get("policy"))
check("who flipped it and when, beside the policy", docp.get("policyChanged", {}).get("by") == "jriggs@auction.com" and "T" in str(docp.get("policyChanged", {}).get("at")), docp.get("policyChanged"))
check("rules untouched by the switch", [x["upn"] for x in docp["rules"]] == [x["upn"] for x in doc2["rules"]])
check("sync kicked", len(kicks) == n_kicks + 1, len(kicks))
d = c.get("/gal/roster").get_json()
check("roster shows the switch on before any sync ran", d["policy"] == {"requireMobile": True} and d["snapshotPolicy"] == {"requireMobile": False})
r = c.post("/gal/policy", data=dict(POST, key="requireMobile", value="1"))
check("setting it on again is a no-op (no extra kick, file unchanged)", len(kicks) == n_kicks + 1 and json.load(open(A.GAL_EXCLUSIONS_JSON)) == docp)
r = c.post("/gal/policy", data=dict(POST, key="requireDesk", value="1"))
check("unknown switch -> 400, nothing written", r.status_code == 400 and json.load(open(A.GAL_EXCLUSIONS_JSON)) == docp, r.status_code)
r = c.post("/gal/policy", data=dict(POST, csrf="wrong", key="requireMobile", value="0"))
check("bad CSRF -> 400", r.status_code == 400, r.status_code)
with open(A.GAL_EXCLUSIONS_JSON, "w") as fh:
    fh.write('{"version":1,"rules":[],"policy":"yes"}')
r = c.post("/gal/policy", data=dict(POST, key="requireMobile", value="0"))
check("damaged policy -> refused, file left as it was", open(A.GAL_EXCLUSIONS_JSON).read() == '{"version":1,"rules":[],"policy":"yes"}')
check("roster endpoint reports the damage", bool(c.get("/gal/roster").get_json().get("rulesError")))
with open(A.GAL_EXCLUSIONS_JSON, "w") as fh:
    json.dump(docp, fh)
r = c.post("/gal/policy", data=dict(POST, key="requireMobile", value="0"))
docp2 = json.load(open(A.GAL_EXCLUSIONS_JSON))
check("switch off again", docp2.get("policy") == {"requireMobile": False} and len(kicks) == n_kicks + 2, (docp2.get("policy"), len(kicks)))
doc2 = docp2

print("\n[one-click mobile rollout]")
snapshot = json.load(open(A.GAL_ROSTER_JSON))
state = json.load(open(A.GAL_STATE_JSON))
facts = A._gal_mobile_rollout_facts(snapshot=snapshot, state=state)
check("recent successful apply is accepted as rollout proof",
      facts["available"] and facts["recipients"] == ["alice@auction.com"], facts)
dry_run = dict(snapshot, mode="dry-run")
check("dry-run roster is rejected as rollout proof",
      not A._gal_mobile_rollout_facts(snapshot=dry_run, state=state)["available"])
stale_at = datetime.now(timezone.utc) - timedelta(hours=A.GAL_MOBILE_SNAPSHOT_MAX_AGE_HOURS + 1)
stale = dict(snapshot, generatedAt=stale_at.isoformat().replace("+00:00", "Z"))
check("stale roster is rejected as rollout proof",
      not A._gal_mobile_rollout_facts(snapshot=stale, state=state)["available"])
failed_state = dict(state, opsFailed=1)
check("apply run with mailbox failures is rejected as rollout proof",
      not A._gal_mobile_rollout_facts(snapshot=snapshot, state=failed_state)["available"])

before_blocked_lists = json.load(open(A.GAL_LISTS_JSON))
before_blocked_policy = json.load(open(A.GAL_EXCLUSIONS_JSON))
before_blocked_kicks = len(kicks)
A._gal_fence_add = lambda emails: ([], [], [(emails[0], "test failure")])
r = c.post("/gal/lists/company/mobile-rollout", data=POST, follow_redirects=False)
check("fence failure leaves list and policy unchanged",
      r.status_code in (302, 303) and
      json.load(open(A.GAL_LISTS_JSON)) == before_blocked_lists and
      json.load(open(A.GAL_EXCLUSIONS_JSON)) == before_blocked_policy,
      r.status_code)
check("fence failure starts no sync", len(kicks) == before_blocked_kicks, len(kicks))
A._gal_fence_add = lambda emails: (fence_calls.append(list(emails)) or (list(emails), [], []))

before_rollout_kicks = len(kicks)
r = c.post("/gal/lists/company/mobile-rollout", data=POST, follow_redirects=False)
rolled_lists = json.load(open(A.GAL_LISTS_JSON))
rolled_policy = json.load(open(A.GAL_EXCLUSIONS_JSON))
check("rollout redirects back", r.status_code in (302, 303) and r.headers["Location"] == "/console#directory", r.status_code)
check("mobile roster becomes the exact recipient set",
      rolled_lists[0]["recipients"] == ["alice@auction.com"], rolled_lists[0]["recipients"])
check("rollout enables the mobile-only publishing policy",
      rolled_policy.get("policy") == {"requireMobile": True}, rolled_policy.get("policy"))
check("every target is reconciled with the Exchange fence", fence_calls[-1] == ["alice@auction.com"], fence_calls[-1])
check("rollout starts a sync", len(kicks) == before_rollout_kicks + 1, len(kicks))

before_repeat = (json.load(open(A.GAL_LISTS_JSON)), json.load(open(A.GAL_EXCLUSIONS_JSON)), len(kicks))
r = c.post("/gal/lists/company/mobile-rollout", data=POST)
after_repeat = (json.load(open(A.GAL_LISTS_JSON)), json.load(open(A.GAL_EXCLUSIONS_JSON)), len(kicks))
check("repeating the rollout is idempotent but rechecks the sync",
      before_repeat[0] == after_repeat[0] and before_repeat[1] == after_repeat[1]
      and after_repeat[2] == before_repeat[2] + 1)

with open(A.GAL_LISTS_JSON, "w") as fh:
    json.dump(rolled_lists + [{
        "id": "leaders", "name": "Leaders", "category": "Leaders",
        "source": {"type": "group", "group": "group-id"},
        "recipients": ["boss@auction.com"], "enabled": True,
    }], fh)
r = c.post("/gal/lists/leaders/mobile-rollout", data=POST)
check("a narrow-source list is never widened by the bulk action",
      json.load(open(A.GAL_LISTS_JSON))[1]["recipients"] == ["boss@auction.com"])
doc2 = json.load(open(A.GAL_EXCLUSIONS_JSON))

print("\n[permission gate]")
c2 = client(role="viewer")
with c2.session_transaction() as s:
    s["sso"]["groups"] = ["some-other-group"]
r = c2.post("/gal/exclusions", data=dict(POST, emails="alice@auction.com", mode="hide"))
doc3 = json.load(open(A.GAL_EXCLUSIONS_JSON))
check("a session without directory.manage cannot add", doc3 == doc2)
r = c2.post("/gal/policy", data=dict(POST, key="requireMobile", value="1"))
check("a session without directory.manage cannot flip the switch", json.load(open(A.GAL_EXCLUSIONS_JSON)) == doc2)
lists_before_denied = json.load(open(A.GAL_LISTS_JSON))
r = c2.post("/gal/lists/company/mobile-rollout", data=POST)
check("a session without directory.manage cannot run a mobile rollout",
      r.status_code in (302, 303) and json.load(open(A.GAL_LISTS_JSON)) == lists_before_denied,
      r.status_code)

print("\n[audit]")
rows = A.sqlite3.connect(A.DB_PATH).execute(
    "SELECT action, detail FROM audit WHERE action LIKE 'gal-%' ORDER BY id DESC LIMIT 24").fetchall()
acts = [r[0] for r in rows]
check("adds and removes audited", "gal-exclude" in acts and "gal-exclude-remove" in acts, acts)
check("switch flips audited with the direction", ("gal-policy", "requireMobile=on") in rows and ("gal-policy", "requireMobile=off") in rows, rows)
check("mobile rollout is audited", "gal-mobile-rollout" in acts, acts)
check("blocked mobile rollout is audited", "gal-mobile-rollout-blocked" in acts, acts)

shutil.rmtree(tmp, ignore_errors=True)
print("\n%s" % ("ALL OK" if not FAIL else "FAILED: " + ", ".join(FAIL)))
sys.exit(1 if FAIL else 0)
