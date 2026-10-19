#!/usr/bin/env python3
"""Housekeeping: does it delete exactly what it says, and nothing else?

The destructive path is exercised against a throwaway tree with the allowlist
pointed at it - never against the real backups. Everything that protects a file
is asserted, not assumed: the age floor, the keep-newest rule, containment, and
symlink refusal.
"""
import os
import shutil
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, "/opt/subdomain-admin")
import housekeeping as H  # noqa: E402
import app as A  # noqa: E402

FAIL = []
DAY = 86400


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (("  -- " + detail) if not cond else ""))
    if not cond:
        FAIL.append(name)


def touch(path, age_days, size=16, is_dir=False):
    if is_dir:
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "f"), "wb") as fh:
            fh.write(b"x" * size)
    else:
        with open(path, "wb") as fh:
            fh.write(b"x" * size)
    t = time.time() - age_days * DAY
    os.utime(path, (t, t))


print("--- the real allowlist is a fixed list, not a walk ---")
check("every root is absolute", all(r.startswith("/") for r in H.ALLOWED_ROOTS))
check("no root is '/' or a parent of the app itself",
      all(r not in ("/", "/opt", "/home", "/etc", "/var") for r in H.ALLOWED_ROOTS),
      str(H.ALLOWED_ROOTS))
check("retired templates are not in scope",
      not any("retired" in r for r in H.ALLOWED_ROOTS))
check("live files are never deletable",
      not any(H._allowed(p) for p in (A.DB_PATH, A.CONFIG_PATH,
                                      "/opt/subdomain-admin/app.py",
                                      "/opt/subdomain-admin/permissions.py",
                                      "/opt/subdomain-admin/permissions.json")),
      "a live file passed the delete guard")
check("the venv and the retired archive are never deletable",
      not H._allowed("/opt/subdomain-admin/venv/bin/python")
      and not H._allowed("/opt/subdomain-admin/templates/retired/base.html"))
check("key material under /etc/ssl is never deletable",
      not H._allowed("/etc/ssl/subdomains/corpit.nrpi.local/server.key"))

# ---------------------------------------------------------------- sandbox
tmp = tempfile.mkdtemp(prefix="hk-test-")
real_roots, real_allowed = H.ROOTS, H.ALLOWED_ROOTS
try:
    H.ROOTS = [(tmp, "*.bak-*", "test backups", False),
               (tmp, "*-backup-*", "test sets", True)]
    H.ALLOWED_ROOTS = (tmp,)

    touch(os.path.join(tmp, "a.bak-000"), 400)          # oldest  -> candidate
    touch(os.path.join(tmp, "b.bak-001"), 300)          #         -> candidate
    touch(os.path.join(tmp, "c.bak-002"), 200)          #         -> candidate
    touch(os.path.join(tmp, "d.bak-003"), 100)          # 2nd newest -> kept
    touch(os.path.join(tmp, "e.bak-004"), 90)           # newest  -> kept
    touch(os.path.join(tmp, "young.bak-005"), 2)        # inside floor -> kept
    # Three dirs, so keep-newest-2 leaves one that can actually be a candidate.
    touch(os.path.join(tmp, "old-backup-set"), 500, is_dir=True)   # dir candidate
    touch(os.path.join(tmp, "mid-backup-set"), 200, is_dir=True)   # kept (2nd newest)
    touch(os.path.join(tmp, "new-backup-set"), 1, is_dir=True)     # kept (newest)

    outside = tempfile.mkdtemp(prefix="hk-outside-")
    with open(os.path.join(outside, "precious"), "w") as fh:
        fh.write("do not delete")
    link = os.path.join(tmp, "sneaky.bak-999")
    os.symlink(os.path.join(outside, "precious"), link)
    t = time.time() - 900 * DAY
    os.utime(link, (t, t), follow_symlinks=False)

    print("\n--- what the scan calls a candidate ---")
    plan = H.scan(30)
    names = {os.path.basename(i["path"]): i for i in plan["items"]}
    cands = {os.path.basename(i["path"]) for i in plan["removable"]}
    check("old files are candidates", {"a.bak-000", "b.bak-001", "c.bak-002"} <= cands, str(cands))
    check("the two newest in the group are kept regardless of age",
          "young.bak-005" not in cands and "e.bak-004" not in cands, str(cands))
    check("the third newest IS a candidate once it is past retention",
          "d.bak-003" in cands, str(cands))
    check("a file inside the %d-day floor is kept" % H.HARD_AGE_FLOOR_DAYS,
          "young.bak-005" not in cands)
    check("an aged backup DIRECTORY is a candidate", "old-backup-set" in cands, str(cands))
    check("a symlink is never even listed", "sneaky.bak-999" not in names, str(list(names)))

    print("\n--- the floor holds even at the minimum retention ---")
    tiny = {os.path.basename(i["path"]) for i in H.scan(1)["removable"]}
    check("retention of 1 day still cannot touch a 2-day-old file",
          "young.bak-005" not in tiny, str(tiny))

    print("\n--- prune deletes exactly the candidates ---")
    removed, failed, freed = H.prune(30)
    gone = {os.path.basename(p) for p, _ in removed}
    left = set(os.listdir(tmp))
    check("removed exactly the candidate set", gone == cands, "%s vs %s" % (gone, cands))
    check("kept files survive", {"e.bak-004", "young.bak-005",
                                 "mid-backup-set", "new-backup-set"} <= left, str(left))
    check("the symlink survives", "sneaky.bak-999" in left)
    check("the symlink TARGET is untouched",
          os.path.exists(os.path.join(outside, "precious")))
    check("nothing failed", not failed, str(failed))
    check("freed bytes reported", freed > 0, str(freed))

    print("\n--- a second run is a no-op ---")
    removed2, failed2, freed2 = H.prune(30)
    check("second prune removes nothing", not removed2 and not failed2, str(removed2))
finally:
    H.ROOTS, H.ALLOWED_ROOTS = real_roots, real_allowed
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(outside, ignore_errors=True)

print("\n--- containment cannot be walked out of ---")
check("a path with .. is refused", not H._allowed("/home/ubuntu/backups/../../etc/passwd"))
check("a private sibling directory is refused", not H._allowed("/home/ubuntu/.ssh/id_rsa"))
check("a home file that matches no pattern is refused",
      not H._allowed("/home/ubuntu/notes.txt"))
check("a nested path under a root is refused (parent must BE the root)",
      not H._allowed("/home/ubuntu/somedir/x.bak-1"))
check("an allowed path is accepted", H._allowed("/home/ubuntu/backups/anything"))
check("a matching backup name in the home root is accepted",
      H._allowed("/home/ubuntu/app.py.bak-old"))

print("\n--- audit pruning keeps what matters ---")
db = sqlite3.connect(":memory:")
db.execute('CREATE TABLE audit (id INTEGER PRIMARY KEY, ts TEXT, "user" TEXT, '
           "action TEXT, detail TEXT)")
old_ts = "2020-01-01 00:00:00 UTC"
for action in ("gate-login", "logout", "permission-denied", "permission-change",
               "settings-change", "create", "remove", "deploy-cert", "access-set"):
    db.execute("INSERT INTO audit (ts, action) VALUES (?, ?)", (old_ts, action))
db.execute("INSERT INTO audit (ts, action) VALUES (datetime('now'), 'gate-login')")
db.commit()
n = H.audit_prune(db, 365, dry_run=True)
check("dry run counts only routine rows", n == 2, "counted %d" % n)
check("dry run changed nothing",
      db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 10)
H.audit_prune(db, 365, dry_run=False)
kept = {r[0] for r in db.execute("SELECT action FROM audit")}
check("security rows kept",
      {"permission-denied", "permission-change", "settings-change"} <= kept, str(kept))
check("provisioning rows kept", {"create", "remove", "deploy-cert", "access-set"} <= kept)
check("today's routine row kept", "gate-login" in kept)
check("aged routine rows gone",
      db.execute("SELECT COUNT(*) FROM audit WHERE ts=?", (old_ts,)).fetchone()[0] == 7)

print("\n--- the sync-staleness rule (the branch that is almost never taken) ---")
import console_data as CD  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)


def hours_for(finished):
    return CD.sync_stale_hours({"lastRun": {"finishedAt": finished}}, now=NOW)


check("a run 30 hours ago reports ~30",
      abs(hours_for("2026-09-02T06:00:00.000Z") - 30) < 0.01, str(hours_for("2026-09-02T06:00:00.000Z")))
check("a run a minute ago reports ~0",
      abs(hours_for("2026-09-03T11:59:00.000Z")) < 0.02)
check("no lastRun at all is 'unknown', not 'stale'",
      CD.sync_stale_hours({}) is None and CD.sync_stale_hours({"lastRun": {}}) is None)
check("an unparseable timestamp is 'unknown', not zero",
      CD.sync_stale_hours({"lastRun": {"finishedAt": "not a date"}}) is None)
check("30h crosses a 48h threshold? no", not (hours_for("2026-09-02T06:00:00.000Z") > 48))
check("60h crosses a 48h threshold? yes", hours_for("2026-09-01T00:00:00.000Z") > 48)

print("\n--- the route is capability-gated ---")


def client(role, groups):
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["user"] = "t@auction.com"
        s["auth_at"] = int(time.time())
        s["sso"] = {"user": "t@auction.com", "role": role, "groups": groups,
                    "can_write_prod": role == "platform-owner", "name": "t"}
    return c


import re  # noqa: E402
c = client("viewer", ["saas-ith-ro"])
tok = re.search(r'name="csrf" value="([^"]+)"',
                c.get("/console").get_data(as_text=True)).group(1)
r = c.post("/housekeeping", data={"csrf": tok})
check("viewer refused", r.status_code in (302, 303)
      and r.headers.get("Location", "").startswith("/console"),
      "%s %s" % (r.status_code, r.headers.get("Location")))

owner = client("platform-owner", ["saas-ith-sa"])
body = owner.get("/console").get_data(as_text=True)
check("owner sees the housekeeping panel", 'id="housekeeping"' in body)
check("panel names the retention", "retention" in body.lower())
check("cleanup button present", "Clean up now" in body)
check("button disabled while nothing is due",
      'disabled title="Nothing is old enough to remove"' in body
      or "will be removed" in body)

print("\n%s (%d failures)" % ("ALL HOUSEKEEPING CHECKS PASSED" if not FAIL
                              else "FAILURES: " + ", ".join(FAIL), len(FAIL)))
sys.exit(1 if FAIL else 0)
