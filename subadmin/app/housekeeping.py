"""Housekeeping: what has piled up on this box, and removing it from the console.

Backups and pre-change copies accumulate here and nothing has ever pruned them.
This module finds them, reports what would be freed, and removes them - but it is
written on the assumption that a bug in it deletes something that mattered, so the
constraints below are not negotiable and are all tested:

* **A fixed allowlist of roots and glob patterns.** Nothing is discovered by
  walking the filesystem, so a path can only ever be a candidate if it was named
  here.
* **A hard age floor**, independent of the configured retention. Setting the
  retention to its minimum still cannot delete something from this morning.
* **The newest few in every group are always kept**, whatever their age. A
  retention window that happens to exceed the age of every backup must not leave
  you with none.
* **Symlinks are never followed and never removed**, and every path is re-checked
  against its root with `realpath` immediately before deletion, so a symlink or a
  `..` cannot walk the delete out of the allowlist.
* **Preview and removal share one function.** The list you are shown is the list
  that gets deleted, recomputed at the moment of deletion - not a stale one from
  page render.

What this deliberately does NOT do: touch anything it does not own. Most of the
existing pile was written by root, and the console runs unprivileged. Those are
reported with the command to clear them rather than silently skipped, because a
cleanup that quietly leaves 60% behind is worse than one that says so.
"""
import fnmatch
import glob
import os
import shutil
import stat
import time

# (root, glob pattern, human label, may_be_dir)
# templates/retired is deliberately absent: that is an archive, not a backup.
ROOTS = [
    ("/home/ubuntu/backups", "*", "operator backups", False),
    ("/home/ubuntu", "*.bak-*", "app file backups", False),
    ("/home/ubuntu", "*.bak", "app file backups", False),
    ("/home/ubuntu", "*-backup-*", "pre-change backup sets", True),
    ("/opt/subdomain-admin", "*.bak*", "console app backups", False),
    ("/opt/subdomain-admin", ".bak-*", "console app backups", False),
    ("/opt/subdomain-admin/templates", "*.bak*", "template backups", False),
]

ALLOWED_ROOTS = tuple(sorted({r for r, _, _, _ in ROOTS}))

# Defence in depth. Being under an allowed root is NOT sufficient - _allowed()
# re-matches the pattern too - but these are named outright so that a future
# pattern edit that is too broad still cannot reach them. The live database, the
# code, the venv, the retired-template archive, the key material.
NEVER = frozenset((
    "/opt/subdomain-admin/app.py",
    "/opt/subdomain-admin/config.json",
    "/opt/subdomain-admin/permissions.json",
    "/opt/subdomain-admin/subdomains.db",
    "/opt/subdomain-admin/settings_registry.py",
    "/opt/subdomain-admin/sso.py",
    "/opt/subdomain-admin/permissions.py",
    "/opt/subdomain-admin/console_data.py",
    "/opt/subdomain-admin/housekeeping.py",
    "/opt/subdomain-admin/setpw.py",
    "/opt/subdomain-admin/corpit_paths.py",
))
NEVER_UNDER = (
    "/opt/subdomain-admin/venv",
    "/opt/subdomain-admin/private",
    "/opt/subdomain-admin/static",
    "/opt/subdomain-admin/tests",
    "/opt/subdomain-admin/templates/retired",
    # PATH-RELEASE-20260929: the live database, config and permissions moved here.
    "/var/lib/subdomain-admin/state",
    "/var/lib/gal-directory",
    "/var/lib/corpit-session",
    "/etc/corpit/shared",
    "/home/ubuntu/.ssh",
    "/home/ubuntu/.gnupg",
    "/etc/ssl",
)

# Nothing younger than this is ever a candidate, whatever the retention says.
HARD_AGE_FLOOR_DAYS = 7
# Newest N in each group survive regardless of age, so a group can never empty.
KEEP_NEWEST = 2

# Audit rows safe to age out: high volume, low forensic value. Everything else -
# every denial, grant, provisioning action and settings change - is kept forever.
# The default is to keep, not to prune: a log that quietly drops the row you need
# is worse than a large one.
PRUNABLE_AUDIT_ACTIONS = ("gate-login", "login", "logout", "beta-regen")


def _size(path):
    """Bytes used, following no symlinks. Directories are summed."""
    try:
        if os.path.islink(path):
            return 0
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode):
            return st.st_size
    except OSError:
        return 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                pass
    return total


def _owner(path):
    try:
        import pwd
        return pwd.getpwuid(os.lstat(path).st_uid).pw_name
    except (OSError, KeyError, ImportError):
        return "?"


def _allowed(path):
    """True only if the RESOLVED path still matches one of the (root, pattern)
    pairs exactly.

    Being merely *under* an allowed root is not enough, and that distinction is
    the point: `/home/ubuntu` is a root, so a containment-only check would have
    accepted anything at all in the home directory. Here the parent directory
    must be the root itself and the basename must match the glob, so a name the
    allowlist would never have offered can never be deleted either.

    Re-run immediately before every deletion, not just at scan time, so a symlink
    swapped in between the two cannot move the target.
    """
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    if real in NEVER:
        return False
    if any(real == u or real.startswith(u + os.sep) for u in NEVER_UNDER):
        return False
    parent, base = os.path.split(real)
    for root, pattern, _, _ in ROOTS:
        try:
            if parent == os.path.realpath(root) and fnmatch.fnmatch(base, pattern):
                return True
        except OSError:
            continue
    return False


def scan(keep_days, now=None):
    """Everything the allowlist matches, classified. Removes nothing.

    Returns {"items": [...], "total_bytes", "candidate_bytes", "removable",
             "needs_root", "unlisted_roots"} where each item carries why it is or is not a
    candidate, so the page can explain itself rather than just showing a number.
    """
    now = now or time.time()
    try:
        keep_days = max(int(keep_days), HARD_AGE_FLOOR_DAYS)
    except (TypeError, ValueError):
        keep_days = 30
    cutoff = now - keep_days * 86400
    floor = now - HARD_AGE_FLOOR_DAYS * 86400
    me = os.geteuid()

    groups = {}
    # glob() returns [] for a folder it cannot read, which would look exactly like
    # "nothing there". A root that is absent is genuinely empty; one this process
    # cannot list is reported, so the page never shows a false all-clear.
    unlisted = set()
    for root, pattern, label, may_be_dir in ROOTS:
        if root in unlisted:
            continue
        try:
            os.listdir(root)
        except FileNotFoundError:
            continue
        except OSError:
            unlisted.add(root)
            continue
        for path in glob.glob(os.path.join(root, pattern)):
            if os.path.islink(path) or not _allowed(path):
                continue
            try:
                st = os.lstat(path)
            except OSError:
                continue
            is_dir = stat.S_ISDIR(st.st_mode)
            if is_dir and not may_be_dir:
                continue
            groups.setdefault((root, pattern), []).append((path, st, label, is_dir))

    items = []
    for key, found in groups.items():
        found.sort(key=lambda t: t[1].st_mtime, reverse=True)
        for idx, (path, st, label, is_dir) in enumerate(found):
            age_days = (now - st.st_mtime) / 86400.0
            owner = _owner(path)
            writable = (st.st_uid == me) or me == 0
            if idx < KEEP_NEWEST:
                why = "kept - one of the %d newest in its group" % KEEP_NEWEST
                candidate = False
            elif st.st_mtime > cutoff or st.st_mtime > floor:
                why = "kept - only %d days old" % int(age_days)
                candidate = False
            elif not writable:
                why = "needs root - owned by %s" % owner
                candidate = False
            else:
                why = "older than %d days" % keep_days
                candidate = True
            items.append({
                "path": path, "label": label, "owner": owner, "is_dir": is_dir,
                "bytes": _size(path), "age_days": int(age_days),
                "candidate": candidate, "needs_root": (not writable and
                                                       idx >= KEEP_NEWEST and
                                                       st.st_mtime <= cutoff),
                "why": why,
            })

    items.sort(key=lambda i: (-i["bytes"], i["path"]))
    return {
        "items": items,
        "keep_days": keep_days,
        "total_bytes": sum(i["bytes"] for i in items),
        "candidate_bytes": sum(i["bytes"] for i in items if i["candidate"]),
        "removable": [i for i in items if i["candidate"]],
        "needs_root": [i for i in items if i["needs_root"]],
        "unlisted_roots": sorted(unlisted),
    }


def prune(keep_days, now=None):
    """Delete exactly what scan() calls a candidate, re-checked at delete time.

    Returns (removed[list of (path, bytes)], failed[list of (path, reason)],
    bytes_freed). Never raises: a file that cannot be removed is reported, not
    fatal, because a partial cleanup must still tell the truth about what it did.
    """
    plan = scan(keep_days, now=now)
    removed, failed, freed = [], [], 0
    for item in plan["removable"]:
        path = item["path"]
        # Everything is verified again here rather than trusted from the plan.
        if os.path.islink(path) or not _allowed(path):
            failed.append((path, "no longer matches an allowed location"))
            continue
        try:
            st = os.lstat(path)
        except OSError as exc:
            failed.append((path, str(exc)))
            continue
        if (now or time.time()) - st.st_mtime < HARD_AGE_FLOOR_DAYS * 86400:
            failed.append((path, "changed since the plan was made"))
            continue
        try:
            if stat.S_ISDIR(st.st_mode):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        except OSError as exc:
            failed.append((path, getattr(exc, "strerror", None) or str(exc)))
            continue
        removed.append((path, item["bytes"]))
        freed += item["bytes"]
    return removed, failed, freed


def audit_prune(conn, keep_days, dry_run=True):
    """Age out only the high-volume routine actions. Returns the row count."""
    try:
        keep_days = max(int(keep_days), 30)
    except (TypeError, ValueError):
        keep_days = 365
    marks = ",".join("?" for _ in PRUNABLE_AUDIT_ACTIONS)
    where = ("WHERE action IN (%s) AND ts < datetime('now', ?)" % marks)
    args = list(PRUNABLE_AUDIT_ACTIONS) + ["-%d days" % keep_days]
    n = conn.execute("SELECT COUNT(*) FROM audit " + where, args).fetchone()[0]
    if n and not dry_run:
        conn.execute("DELETE FROM audit " + where, args)
        conn.commit()
    return n


def human(nbytes):
    n = float(nbytes or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%.0f %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
