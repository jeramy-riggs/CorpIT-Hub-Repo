#!/usr/bin/env python3
"""Rotate an admin login password. Run from /opt/subdomain-admin:
       ./venv/bin/python setpw.py [username]      (defaults to 'admin')
   Then apply it:   sudo systemctl restart subdomain-admin
"""
import getpass
import json
import os
import sys

from werkzeug.security import generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import corpit_paths  # noqa: E402

# PATH-RELEASE-20260929: config.json lives in SUBADMIN_STATE_DIR (default
# /var/lib/subdomain-admin/state, subadmin:subadmin 2770), so run this as subadmin or root.
# The write below stays in place (truncate + write) so the file keeps its owner and mode.
CONFIG = os.path.join(corpit_paths.subadmin_state_dir(), "config.json")


def main():
    user = sys.argv[1] if len(sys.argv) > 1 else "admin"
    cfg = json.load(open(CONFIG))
    pw = getpass.getpass(f"New password for {user}: ")
    if len(pw) < 10:
        sys.exit("Password must be at least 10 characters.")
    if pw != getpass.getpass("Confirm: "):
        sys.exit("Passwords do not match.")
    cfg.setdefault("users", {})[user] = generate_password_hash(pw)
    with open(CONFIG, "w") as fh:
        json.dump(cfg, fh, indent=2)
    print(f"Updated password for '{user}'. Run: sudo systemctl restart subdomain-admin")


if __name__ == "__main__":
    main()
