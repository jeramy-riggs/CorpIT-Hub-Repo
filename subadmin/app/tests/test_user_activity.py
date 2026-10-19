#!/usr/bin/env python3
"""User activity lookup sources (settingsfold W6, 2026-10-12).

Part 1 loads user_activity.py (W6_UA, default the installed copy) into a small
Flask app with an in-memory audit table and scratch launch pad / backup files
under /var/tmp, and checks the source contract: id, label, state, count,
truncated, note; exact-email match only; no free text or values; unreadable or
absent stores are reported honestly. Part 2 reads the REAL stores on this host
the way the service does (run it as the subadmin user): the launch pad log must
be readable, the backup console audit log must not be, and neither is changed.
Nothing here writes outside its own temp dir. Run as subadmin, not root.
"""
import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

from flask import Flask

FAIL = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (("  -- " + str(detail)[:300]) if detail and not cond else ""))
    if not cond:
        FAIL.append(name)


UA_PATH = os.environ.get("W6_UA", "/opt/subdomain-admin/user_activity.py")
spec = importlib.util.spec_from_file_location("user_activity_under_test", UA_PATH)
UA = importlib.util.module_from_spec(spec)
spec.loader.exec_module(UA)
print("module under test: %s" % UA_PATH)
check("running as a non-root user (permission checks need it)", os.geteuid() != 0, "euid=%d" % os.geteuid())

T = tempfile.mkdtemp(prefix="w6-ua-", dir="/var/tmp")
now = datetime.now(timezone.utc)
iso = lambda d: (now - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
ME = "w6-person@example.com"
SECRETS = ["W6NOTEsecret", "W6REASONsecret", "W6ERRORsecret", "W6VALUEsecret", "W6WHYsecret"]


def make_app(lp_dir, bk_dir, audit_ok=True):
    UA.LAUNCHPAD_DIR, UA.LAUNCHPAD_LOG = lp_dir, os.path.join(lp_dir, "release.log")
    UA.BACKUP_DIR, UA.BACKUP_AUDIT = bk_dir, os.path.join(bk_dir, "audit.jsonl")
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute('CREATE TABLE audit(id INTEGER PRIMARY KEY, ts TEXT, "user" TEXT, action TEXT, detail TEXT)')
    con.execute('INSERT INTO audit(ts,"user",action,detail) VALUES(?,?,?,?)', (iso(1)[:19], ME, "settings-save", "x"))
    con.execute('INSERT INTO audit(ts,"user",action,detail) VALUES(?,?,?,?)', (iso(2)[:19], "other@example.com", "settings-save", "x"))
    looked = []

    def audit(action, detail=""):
        if not audit_ok:
            raise RuntimeError("audit down")
        looked.append((action, detail))

    app = Flask("w6ua")
    UA.register(app, lambda f: f, lambda: con, audit)
    return app.test_client(), looked


def get(c, email=ME, days=30):
    r = c.get("/health/activity/person?email=%s&days=%d" % (email, days))
    return r.status_code, r.get_json(), r


def src(body, sid):
    return next((s for s in (body.get("data", {}).get("sources") or []) if s.get("id") == sid), None)


lp = os.path.join(T, "dev-release")
bk = os.path.join(T, "bkp")
os.makedirs(lp)
os.makedirs(bk)
lines = [
    {"ts": iso(1), "event": "cab-settings", "site": "itam", "by": ME, "via": "web",
     "changed": {"cab_required": {"from": "W6VALUEsecret", "to": "no"}}, "note": "W6NOTEsecret"},
    {"ts": iso(2), "event": "signoff", "site": "corpit", "rel": "r-20261010-1", "by": ME.upper(), "reason": "W6REASONsecret"},
    {"ts": iso(3), "event": "publish-failed", "site": "corpit", "rel": "r-2", "by": ME, "error": "W6ERRORsecret"},
    {"ts": iso(4), "event": "lanes-hold", "site": "itam", "by": ME, "sev": "warn", "why": "W6WHYsecret"},
    {"ts": iso(1), "event": "open", "site": "itam", "by": "claude for " + ME},
    {"ts": iso(1), "event": "open", "site": "itam", "by": "W6 Person"},
    {"ts": iso(1), "event": "open", "site": "itam", "by": "other@example.com"},
    {"ts": iso(1), "event": "cab-lifecycle", "site": "itam", "note": ME},
    {"ts": iso(45), "event": "prepare", "site": "itam", "by": ME},
]
with open(os.path.join(lp, "release.log"), "w") as f:
    for l in lines:
        f.write(json.dumps(l) + "\n")
    f.write('{"ts": "broken", "by": "' + ME + '"\n')
with open(os.path.join(bk, "audit.jsonl"), "w") as f:
    f.write(json.dumps({"action": "settings", "actor": ME, "at": iso(1), "details": {"x": 1}}) + "\n")
os.chmod(os.path.join(bk, "audit.jsonl"), 0o000)

def part1():
    global c, looked
    print("\n--- contract ---")
    c, looked = make_app(lp, bk)
    code, body, r = get(c)
    check("200 and no-store", code == 200 and "no-store" in r.headers.get("Cache-Control", ""), code)
    check("lookup itself audited before any read", looked and looked[0][0] == "user-activity-lookup" and ME in looked[0][1], looked)
    d = body["data"]
    check("data.source is still the Subadmin audit (older pages keep working)", d.get("source", {}).get("id") == "subadmin" and d["source"]["count"] == 1, d.get("source"))
    check("data.sources lists subadmin, launchpad, backup in that order", [s["id"] for s in d.get("sources") or []] == ["subadmin", "launchpad", "backup"], d.get("sources"))
    for s in d.get("sources") or []:
        check("source %s has id/label/state/count/truncated/note" % s.get("id"),
              all(k in s for k in ("id", "label", "state", "count", "truncated", "note")) and s["state"] in ("available", "unavailable") and s["note"], s)
    L = src(body, "launchpad")
    lev = [e for e in d["events"] if e["source"] == "launchpad"]
    check("launch pad available, 4 exact matches in window", L and L["state"] == "available" and L["count"] == 4 and len(lev) == 4, (L, [e["event"] for e in lev]))
    check("email match is case-insensitive on the stored value", any(e["event"] == "signoff" for e in lev))
    check("phrase 'claude for <email>', display names, other actors, notes naming the email: NOT matched",
          not any(e["event"] in ("open", "cab-lifecycle") for e in lev))
    check("older than the window: not returned", not any(e["event"] == "prepare" for e in lev))
    check("newest first", [e["event"] for e in lev] == ["cab-settings", "signoff", "publish-failed", "lanes-hold"], [e["event"] for e in lev])
    raw = json.dumps(body)
    check("no note/reason/error/why text and no changed VALUES in the response", not any(s in raw for s in SECRETS), [s for s in SECRETS if s in raw])
    cs = next(e for e in lev if e["event"] == "cab-settings")
    check("cab-settings shows changed field NAMES", "Changed: cab_required" in cs["detail"] and cs["summary"] == "cab settings · itam", cs)
    so = next(e for e in lev if e["event"] == "signoff")
    check("release id in detail", so["detail"] == "Release r-20261010-1", so)
    check("severity: publish-failed error, sev warn -> warn, others info",
          next(e for e in lev if e["event"] == "publish-failed")["severity"] == "error"
          and next(e for e in lev if e["event"] == "lanes-hold")["severity"] == "warn" and so["severity"] == "info")
    check("every launch pad event names the source and relationship", all(e["source_label"] == "Launch pad" and e["relationship"] == "Recorded actor" and e["id"].startswith("launchpad-") for e in lev))
    check("unreadable line counted in the note", "1 unreadable line" in L["note"], L["note"])
    B = src(body, "backup")
    check("backup console unavailable, count null, honest note, no events",
          B and B["state"] == "unavailable" and B["count"] is None and "not readable" in B["note"].lower() and not any(e["source"] == "backup" for e in d["events"]), B)
    check("subadmin events unchanged (exact actor only)", [e["source"] for e in d["events"]].count("subadmin") == 1)
    check("backup placeholder marked fetched_by=browser and names /bkp-api/activity (follow-up d)",
          B.get("fetched_by") == "browser" and "/bkp-api/activity" in B["note"], B)
    check("only the backup placeholder carries fetched_by", [s["id"] for s in d["sources"] if "fetched_by" in s] == ["backup"], d["sources"])

    print("\n--- other actor, other states ---")
    code, body, _ = get(c, "other@example.com")
    check("other@example.com: one launch pad event, one subadmin event", src(body, "launchpad")["count"] == 1 and src(body, "subadmin")["count"] == 1)
    os.chmod(os.path.join(bk, "audit.jsonl"), 0o644)
    code, body, _ = get(c)
    B = src(body, "backup")
    check("backup readable but no reader built: still unavailable, says so", B["state"] == "unavailable" and "no reader" in B["note"], B)
    os.chmod(os.path.join(lp, "release.log"), 0o000)
    code, body, _ = get(c)
    L = src(body, "launchpad")
    check("launch pad log unreadable: unavailable with a note, no events", L["state"] == "unavailable" and "could not be read" in L["note"] and not any(e["source"] == "launchpad" for e in body["data"]["events"]), L)
    os.chmod(os.path.join(lp, "release.log"), 0o644)
    os.remove(os.path.join(lp, "release.log"))
    code, body, _ = get(c)
    L = src(body, "launchpad")
    check("launch pad dir present, log missing: unavailable, says no log", L["state"] == "unavailable" and "No launch pad release log" in L["note"], L)
    c2, _ = make_app(os.path.join(T, "absent-lp"), os.path.join(T, "absent-bk"))
    code, body, _ = get(c2)
    check("store directories absent on this host: sources left out (no dead entries)", [s["id"] for s in body["data"]["sources"]] == ["subadmin"], body["data"]["sources"])
    c, looked = make_app(lp, bk)   # make_app sets module paths; point them back at the scratch stores
    with open(os.path.join(lp, "release.log"), "w") as f:
        for i in range(UA.LIMIT + 7):
            f.write(json.dumps({"ts": iso(1), "event": "verify", "site": "itam", "rel": "r-%d" % i, "by": ME}) + "\n")
    code, body, _ = get(c)
    L = src(body, "launchpad")
    rels = [e.get("detail") for e in body["data"]["events"] if e["source"] == "launchpad"]
    check("more than 500 matches: 500 newest returned, truncated true", L["count"] == UA.LIMIT and L["truncated"] is True
          and rels[0] == "Release r-%d" % (UA.LIMIT + 6) and "Release r-6" not in rels and "Release r-7" in rels, (L, rels[:2], rels[-2:]))
    c3, _ = make_app(lp, bk, audit_ok=False)
    code, body, _ = get(c3)
    check("lookup audit down: 503 and nothing read", code == 503 and "data" not in (body or {}), (code, body))
    code, body, _ = get(c, "not-an-email")
    check("bad email: 400", code == 400)


try:
    part1()
except Exception as e:  # report, do not crash
    check("contract section ran to the end", False, repr(e))
finally:
    shutil.rmtree(T, ignore_errors=True)
check("temp dir removed", not os.path.exists(T))

print("\n--- real stores on this host, read as this user ---")
REAL_LP, REAL_BK = "/var/lib/dev-release/release.log", "/var/lib/bkp/audit.jsonl"
if os.environ.get("W6_REAL", "1") == "1" and os.path.isdir("/var/lib/dev-release"):
    UA.LAUNCHPAD_DIR, UA.LAUNCHPAD_LOG, UA.BACKUP_DIR, UA.BACKUP_AUDIT = "/var/lib/dev-release", REAL_LP, "/var/lib/bkp", REAL_BK
    since = (now - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S")
    ev, s = UA._launchpad("jriggs@auction.com", since)
    check("real launch pad log readable as this user, source available", s["state"] == "available", s)
    check("real launch pad events carry no free text keys", all(set(e) == {"id", "ts", "event", "summary", "detail", "source", "source_label", "relationship", "severity"} for e in ev))
    ev, s = UA._launchpad("w6-nobody@example.com", since)
    check("unknown email: available with 0 records", s["state"] == "available" and s["count"] == 0, s)
    check("real backup console audit log NOT readable as this user (not widened)", not os.access(REAL_BK, os.R_OK))
    ev, s = UA._backup()
    check("real backup source: unavailable, honest note", s["state"] == "unavailable" and "not readable" in s["note"].lower(), s)
else:
    print("  (skipped: no launch pad on this host or W6_REAL=0)")

print()
if FAIL:
    print("FAILURES (%d): %s" % (len(FAIL), "; ".join(FAIL)))
    sys.exit(1)
print("ALL USER ACTIVITY CHECKS PASSED (0 failures)")
