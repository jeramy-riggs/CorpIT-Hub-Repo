"""
NRPI Subdomain Admin — request/provision *.nrpi.local department subdomains.

Runs as the 'ubuntu' user behind nginx (gunicorn on 127.0.0.1:5000). Privileged
work (writing vhosts, generating certs, reloading nginx) is delegated to
/usr/local/sbin/nrpi-subdomain via a restricted NOPASSWD sudoers rule.
"""
import contextlib
import fcntl
import hashlib
import json
from corpit_durable import atomic_write_durable
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlsplit

from flask import (Flask, g, redirect, render_template, request, session,
                   url_for, flash, abort, Response)
from werkzeug.security import check_password_hash, generate_password_hash

import sso as sso_mod
import settings_registry as settings_mod
import updates_panel
import webwatch_panel
import change_control
import console_data
import access_governance
import housekeeping
import landing
import permissions
import corpit_paths

APP_DIR = os.path.dirname(os.path.abspath(__file__))
# PATH-RELEASE-20260929: replicated state lives in SUBADMIN_STATE_DIR (default
# /var/lib/subdomain-admin/state), not beside the code. corpit_paths raises at import
# if the directory is missing, so the console never starts on an empty database.
STATE_DIR = corpit_paths.subadmin_state_dir()
DB_PATH = os.path.join(STATE_DIR, "subdomains.db")
CONFIG_PATH = os.path.join(STATE_DIR, "config.json")
HELPER = "/usr/local/sbin/nrpi-subdomain"
UPLOAD_DIR = "/var/lib/subdomain-admin/uploads"
BASE_DOMAIN = "nrpi.local"
# PATH-RELEASE-20260929: node-local (env CORPIT_HOST_IP or /etc/corpit/node.env), never
# hardcoded, so node B does not publish node A's address. Raises if absent.
HOST_IP = corpit_paths.host_ip()
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$")
RESERVED = {"www", "subadmin", "admin", "localhost", "corpitpen", "default"}

MIN_PASSWORD_LEN = 10
_config_lock = threading.Lock()


def load_config():
    """Read config.json fresh from disk (so password changes are seen by every
    gunicorn worker without a restart)."""
    with open(CONFIG_PATH) as fh:
        return json.load(fh)


def load_config_rev():
    """config.json plus the revision of exactly those bytes. A form carries the
    revision it was drawn from; a save made from an older revision is refused."""
    with open(CONFIG_PATH, "rb") as fh:
        raw = fh.read()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()[:20]


# PROD-READINESS 2026-10-12: every read-modify-write of config.json holds this
# lock, so two gunicorn workers cannot interleave and drop each other's change.
# A threading lock in front, because flock is per open file, not per thread.
CONFIG_LOCK_PATH = os.path.join(STATE_DIR, "config.lock")
_config_txn_lock = threading.Lock()


@contextlib.contextmanager
def config_write_lock():
    with _config_txn_lock:
        fd = os.open(CONFIG_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def save_config(cfg):
    """Durably persist config.json (0600), preserving the secret key. Callers
    that read, modify and write hold config_write_lock() around all three."""
    with _config_lock:
        atomic_write_durable(CONFIG_PATH, json.dumps(cfg, indent=2), mode=0o600)


CONFIG = load_config()

app = Flask(__name__)
app.secret_key = CONFIG["secret_key"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=8 * 3600,
    # Hard ceiling on a session regardless of activity. The lifetime above is
    # only an IDLE timeout - Flask re-issues the cookie on every response, so
    # without this an open tab renews indefinitely.
    SESSION_ABSOLUTE_MAX=int(CONFIG.get('session_absolute_max_seconds') or 12 * 3600),
    MAX_CONTENT_LENGTH=256 * 1024,
)

# ---------------------------------------------------------------- db helpers
def _connect_db():
    """Keep existing journal mode; EXTRA also syncs rollback-journal removal."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA synchronous=EXTRA")
        if conn.execute("PRAGMA synchronous").fetchone()[0] != 3:
            raise RuntimeError("SQLite writer requires synchronous=EXTRA")
        return conn
    except BaseException:
        conn.close()
        raise


def db():
    if "db" not in g:
        g.db = _connect_db()
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def init_db():
    con = _connect_db()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT UNIQUE NOT NULL,
            fqdn TEXT UNIQUE NOT NULL,
            department TEXT,
            notes TEXT,
            status TEXT NOT NULL DEFAULT 'parked',
            cert_type TEXT NOT NULL DEFAULT 'self-signed',
            csr_path TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, "user" TEXT, action TEXT, detail TEXT
        );
        CREATE TABLE IF NOT EXISTS beta_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            description TEXT,
            sort_order INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            new_tab INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL
        );
        """
    )
    con.commit()
    con.close()


def _migrate_db():
    """Additive column migrations (ALTER TABLE has no IF NOT EXISTS)."""
    con = _connect_db()
    cols = {r[1] for r in con.execute("PRAGMA table_info(subdomains)")}
    for col in ("cert_issuer", "cert_expires", "cert_deployed_at",
                "dns_status", "dns_pushed_at"):
        if col not in cols:
            con.execute(f"ALTER TABLE subdomains ADD COLUMN {col} TEXT")
    con.commit()
    con.close()


# Schema setup must run at IMPORT time, not only under __main__: gunicorn
# imports this module and never executes the __main__ block, so any newly
# added table would otherwise never be created on a deploy.
init_db()
_migrate_db()
# The change ledger's tables, created at import for the same reason: gunicorn
# never runs __main__, so a table added here would otherwise never exist.
change_control.init(DB_PATH)
# The home-page tables, same reason.
landing.init(DB_PATH)
# Access-governance proposals are local review records.  The owning module has
# no directory-write path; AD remains authoritative for every entitlement.
access_governance.init(DB_PATH)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# Named once so the audit row and any future banner cannot drift apart from the
# path the helper actually writes.
OBS_PUBLISHED_PATH = corpit_paths.shared_file("observability.json")
# CORPIT-SPEND-ALERTS - same publish-to-/etc/corpit/shared contract as observability.
SPEND_PUBLISHED_PATH = corpit_paths.shared_file("spend-alerts.json")
# CORPIT-REPORTING-RETURN - same publish-to-/etc/corpit/shared contract: the console
# stores the allowlist, the root helper publishes it where the Hub API reads it.
REPORTING_RETURN_PUBLISHED_PATH = corpit_paths.shared_file("reporting-return.json")
# CORPIT-OPS-ALERT - who is emailed when a backup, sync or scheduled job fails,
# plus the stuck-sync threshold. NOTE (PATH-RELEASE-20260929): no runtime reader of this
# file exists on A today; the ops-alert.js named here was never found.
OPS_ALERTS_PUBLISHED_PATH = corpit_paths.shared_file("ops-alerts.json")


def audit(action, detail=""):
    db().execute(
        'INSERT INTO audit(ts,"user",action,detail) VALUES(?,?,?,?)',
        (now_iso(), session.get("user", "-"), action, detail),
    )
    db().commit()


# ---------------------------------------------------------------- auth
# Sessions issued before this cap existed carry no auth_at. They are treated as
# expired rather than grandfathered: failing open here would silently exempt every
# session that predates the control, which is the opposite of the point.
_AUTH_EXEMPT = {"login", "auth_login", "auth_callback", "static", "healthz"}


# --- CORPIT-HUB-GATE-IDENTITY -----------------------------------------
# CorpIT Hub SSO is the front door for this vhost (2026-09-02). nginx has already
# verified the signed it_session cookie via auth_request before anything reaches
# here, and hands us the identity it verified.
GATE_HEADER = "X-Gate-Email"

# The header is only meaningful from nginx on this box. Gunicorn listens on
# 127.0.0.1 so this is always the peer in production; the check exists so that
# binding the app to a routable address later cannot silently turn a client
# header into an identity.
_GATE_TRUSTED_PEERS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

# Re-resolving AD group membership on every request would put an LDAP round trip
# in front of every page load. Resolve on adoption and on identity change; the
# absolute session cap already forces everyone back through Entra periodically.
@app.before_request
def _adopt_hub_gate_identity():
    email = (request.headers.get(GATE_HEADER) or "").strip().lower()
    if not email or request.remote_addr not in _GATE_TRUSTED_PEERS:
        return None

    if session.get("user") and session.get("gate_email") == email:
        return None

    # A different person signed in on this browser: do not inherit the old role.
    if session.get("gate_email") and session.get("gate_email") != email:
        session.clear()

    ident = {"upn": email, "upn_raw": email, "name": email, "oid": ""}
    try:
        cfg = load_config()
        ctx = sso_mod.authorize(_ldap_cfg(), ident,
                                (cfg.get("sso") or {}).get("owners") or [])
    except sso_mod.SSOError as e:
        # Authenticated by the platform, but not entitled to THIS console. Must be
        # a terminal 403, never a redirect to sign in again - they already did, and
        # bouncing them back to the gate would loop forever.
        audit("gate-denied", "%s %s" % (email, str(e)[:300]))
        session.clear()
        return render_template("gate_denied.html", email=email, reason=str(e)), 403

    session.clear()
    session.permanent = True
    session["auth_at"] = int(time.time())
    session["auth_cap"] = _session_cap_now()
    session["user"] = ctx["user"]
    session["sso"] = ctx
    session["gate_email"] = email
    audit("gate-login", "%s role=%s prod-write=%s"
          % (ctx["user"], ctx["role"], ctx["can_write_prod"]))
    return None


def _session_cap_now():
    """The configured session hard limit, read from disk on every call so a saved
    value reaches every worker without a restart."""
    try:
        return int(load_config().get("session_absolute_max_seconds") or app.config["SESSION_ABSOLUTE_MAX"])
    except Exception:
        return app.config["SESSION_ABSOLUTE_MAX"]


@app.before_request
def _enforce_absolute_session_cap():
    if not session.get("user"):
        return None
    if request.endpoint in _AUTH_EXEMPT:
        return None
    issued = session.get("auth_at")
    age = int(time.time()) - int(issued) if issued else None
    # The limit in force when the session started (Settings > Sessions says a new
    # value applies to sessions created after the change). Sessions started before
    # auth_cap existed use the value configured now.
    cap = session.get("auth_cap") or _session_cap_now()
    if issued and age < cap:
        return None
    who = session.get("user", "")
    audit("session-expired", "%s reason=%s" % (who, "no-auth_at" if not issued else "age=%ds" % age))
    session.clear()
    flash("Your session reached its maximum length. Please sign in again.", "error")
    return redirect(url_for("login", next=request.path if request.method == "GET" else "/"))


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapper


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            abort(400, "CSRF token mismatch")


def safe_next(target):
    """Return target only if it is a same-site absolute path; else None.
    Rejects protocol-relative (//host) and backslash (/\\host) forms that
    browsers resolve to an external origin, and anything with a scheme/host."""
    if not target or not target.startswith("/"):
        return None
    if target.startswith("//") or target.startswith("/\\"):
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return None
    return target


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def sec_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    return resp


# ---------------------------------------------------------------------------
# CORPIT-CONSOLE-IS-THE-FRONT-DOOR
#
# The console posts to the same routes the standalone pages used to. Those
# routes still redirect wherever they always did; a "_back" field on the form
# asks the browser to land on the console view the action was fired from
# instead, so an action never bounces the operator out of context.
#
# The value is matched against a fixed pattern - this console's own path plus a
# short view anchor - and anything else is ignored. It is never used as an
# open redirect, and it can only ever point at this origin.
# ---------------------------------------------------------------------------
_CONSOLE_BACK_RE = re.compile(r"^/console(#[a-z]{2,20})?$")


@app.after_request
def console_back(resp):
    if request.method == "POST" and resp.status_code in (301, 302, 303, 307, 308):
        target = request.form.get("_back", "")
        if _CONSOLE_BACK_RE.match(target):
            resp.headers["Location"] = target
    return resp


# ---- login brute-force guard ------------------------------------------------
# Per-username failure counter, in-process only: gunicorn runs 2 sync workers
# with their own copies, so the effective threshold is up to 2x LOGIN_MAX_FAILS.
# Per-IP throttling is nginx limit_req on /login; fail2ban bans on the journal
# line written by _log_auth() (filter.d/subadmin-auth.conf).
LOGIN_MAX_FAILS = 6
LOGIN_LOCK_SECS = 15 * 60
_login_fails = {}            # username -> {"n": fails, "ts": last fail, "until": locked until}
_login_fails_lock = threading.Lock()
_LOG_UNSAFE_RE = re.compile(r"[^\w.@+-]", re.ASCII)
# Random hash so an unknown username still pays for one real check_password_hash().
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))


def _log_safe(value, limit=64):
    """Collapse anything that could split or forge a log line (newlines, spaces)."""
    return _LOG_UNSAFE_RE.sub("_", str(value))[:limit] or "-"


def _client_ip():
    ip = request.headers.get("X-Real-IP") or request.remote_addr or "-"
    return ip if re.fullmatch(r"[0-9A-Fa-f.:]{1,45}", ip) else "-"


def _log_auth(event, user):
    """One line on stderr -> journald (unit subdomain-admin) for fail2ban.
    ip= is written first so a crafted username can never move the <ADDR> field."""
    print(f"subadmin-auth: {event} ip={_client_ip()} user={_log_safe(user)}",
          file=sys.stderr, flush=True)


def _login_locked_for(user):
    """Whole minutes left on this username's lockout, or 0 if not locked."""
    now = time.monotonic()
    with _login_fails_lock:
        rec = _login_fails.get(user[:128])
        if rec and rec["until"] > now:
            return int((rec["until"] - now) // 60) + 1
    return 0


def _login_failed(user):
    key = user[:128]
    now = time.monotonic()
    with _login_fails_lock:
        if len(_login_fails) >= 5000:        # bound memory under username spraying
            stale = [k for k, v in _login_fails.items() if now - v["ts"] > LOGIN_LOCK_SECS]
            for k in stale or sorted(_login_fails, key=lambda k: _login_fails[k]["ts"])[:2500]:
                del _login_fails[k]
        rec = _login_fails.get(key)
        if not rec or now - rec["ts"] > LOGIN_LOCK_SECS:
            rec = {"n": 0, "ts": now, "until": 0.0}
        rec["n"] += 1
        rec["ts"] = now
        if rec["n"] >= LOGIN_MAX_FAILS:
            rec["n"] = 0
            rec["until"] = now + LOGIN_LOCK_SECS
        _login_fails[key] = rec


def _login_clear(user):
    with _login_fails_lock:
        _login_fails.pop(user[:128], None)


# ==========================================================================
# Entra ID single sign-on.
#
# Authentication is OIDC authorization-code + PKCE against a dedicated app
# registration; authorization is AD group membership read over LDAP (see
# sso.py). The local username/password login below stays available as the
# break-glass path - it is the only way in if Entra or the DC is unreachable,
# and removing it would make an outage unrecoverable.
# ==========================================================================
LDAP_ENV_PATH = "/var/www/corpit-hub-api/.env"


def _ldap_cfg():
    """LDAP settings are read from the API's env file rather than copied here,
    so the directory bind password exists in exactly one place on this box."""
    env = {}
    try:
        with open(LDAP_ENV_PATH) as fh:
            for line in fh:
                m = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
                if m:
                    env[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    except OSError as e:
        raise sso_mod.SSOError("cannot read directory settings: %s" % e)
    try:
        return {"url": env["LDAP_URL"], "bind_user": env["LDAP_BIND_USER"],
                "bind_pass": env["LDAP_BIND_PASS"], "base_dn": env["LDAP_BASE_DN"]}
    except KeyError as k:
        raise sso_mod.SSOError("directory settings incomplete: missing %s" % k)


def sso_enabled():
    try:
        return sso_mod.sso_config(load_config()) is not None
    except sso_mod.SSOError:
        return False


# --- CORPIT-SITE-ACCESS-CONSOLE ------------------------------------------------------
ACCESS_MODES = ("authenticated", "groups", "superadmin")


def _helper_json(args, timeout=30):
    """Run the privileged helper and parse its JSON. Returns (data, error)."""
    try:
        out = subprocess.run(["sudo", "-n", HELPER] + list(args),
                             capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "helper timed out"
    except Exception as exc:
        # The dev egress guard deliberately blocks privileged subprocesses.
        # Treat that (and any other spawn failure) as unavailable evidence so
        # the read-only console can still render with an explicit unknown state.
        return None, "helper unavailable: %s" % str(exc)[:240]
    try:
        data = json.loads(out.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return None, (out.stderr.strip() or "helper returned no JSON")
    if out.returncode != 0 or not data.get("ok"):
        # P-8. This used to be `data.get("error") or out.stderr.strip()`. The
        # helper's die() writes a GENERIC wrapper to stdout as JSON -- "could
        # not publish observability settings" -- while the step that actually
        # failed writes the specific cause to stderr, e.g.
        #   setting obs.sample_percent is out of range (0..100)
        # Because the generic string is always truthy, the `or` short-circuited
        # and the specific one, already captured and sitting in out.stderr, was
        # thrown away every time. The operator got a restatement of what they
        # had asked for and no way to tell which field was wrong. Prefer the
        # specific line, and keep the generic one for context when it adds any.
        generic = (data.get("error") or "").strip()
        detail = ""
        lines = [ln.strip() for ln in (out.stderr or "").splitlines() if ln.strip()]
        if lines:
            # A python sys.exit(msg) is one line; a traceback puts the exception
            # last. Either way the final line is the diagnosis. Clip it: this
            # goes into a flash message, and a stray traceback should not be
            # able to fill the page.
            detail = lines[-1][:300]
        if detail and detail != generic:
            return None, ("%s: %s" % (generic, detail)) if generic else detail
        return None, generic or "helper failed"
    return data, None


def site_policy():
    """The whole per-site access policy, or {} if it cannot be read."""
    data, err = _helper_json(["get-access"])
    if err:
        return {}
    return (data or {}).get("policy") or {}


def site_access_for(fqdn):
    pol = site_policy()
    site = (pol.get("sites") or {}).get(str(fqdn).lower())
    if not site:
        d = pol.get("default") or {"mode": "superadmin"}
        return {"mode": d.get("mode", "superadmin"), "groups": [], "inherited": True}
    return {"mode": site.get("mode", "superadmin"),
            "groups": site.get("groups") or [], "inherited": False,
            "page_limits": site.get("page_limits") or {}}   # SECPAGELIMIT-20261019


def _ldap_search_groups(flt, limit=200):
    """CNs of groups matching an LDAP filter. [] on any directory problem."""
    import ldap3
    try:
        cfg = _ldap_cfg()
    except sso_mod.SSOError:
        return []
    try:
        server = ldap3.Server(cfg["url"], get_info=None, connect_timeout=5)
        conn = ldap3.Connection(server, user=cfg["bind_user"], password=cfg["bind_pass"],
                                auto_bind=False, receive_timeout=10, raise_exceptions=False)
        if not conn.bind():
            return []
        try:
            conn.search(cfg["base_dn"], flt, attributes=["cn"], size_limit=limit)
            return sorted({str(e.cn.value) for e in conn.entries if "cn" in e})
        finally:
            try: conn.unbind()
            except Exception: pass
    except Exception:
        return []


def ad_group_suggestions():
    """Groups offered in the picker: the platform's own, plus any already in use.

    Deliberately not the whole directory - enumerating every group would be slow
    and useless. Any other group can still be typed; it is validated on save.
    """
    names = set(_ldap_search_groups("(&(objectCategory=group)(cn=SaaS-ITH-*))"))
    pol = site_policy()
    for site in (pol.get("sites") or {}).values():
        for g in (site.get("groups") or []):
            names.add(g)
    for g in (pol.get("superadmin_groups") or []):
        names.add(g)
    return sorted(names, key=lambda x: x.lower())


def missing_ad_groups(names):
    """Which of these group names do NOT exist in the directory.

    Returns None when the directory cannot be reached at all - the caller must
    treat that as 'cannot verify' and refuse, rather than as 'all fine'.
    """
    wanted = [n for n in names if n.strip()]
    if not wanted:
        return []
    parts = "".join("(cn=%s)" % sso_mod._escape_filter(n) for n in wanted)
    found = _ldap_search_groups("(&(objectCategory=group)(|%s))" % parts)
    if not found:
        probe = _ldap_search_groups("(&(objectCategory=group)(cn=*))", limit=1)
        if not probe:
            return None
    lower = {f.lower() for f in found}
    return [n for n in wanted if n.strip().lower() not in lower]


def parse_groups_field(raw):
    """Split the console's free-text group field. Commas or newlines."""
    out, seen = [], set()
    for chunk in str(raw or "").replace("\n", ",").split(","):
        g = chunk.strip()
        if g and g.lower() not in seen:
            seen.add(g.lower())
            out.append(g)
    return out


def apply_site_access(label, mode, groups):
    """Validate, then have the ROOT helper write the policy. (ok, message)."""
    if mode not in ACCESS_MODES:
        return False, "Unknown access mode."
    if mode == "groups":
        if not groups:
            return False, "Choose at least one AD security group, or pick another access mode."
        missing = missing_ad_groups(groups)
        if missing is None:
            return False, ("The directory could not be reached, so these group names "
                           "could not be verified. Nothing was changed.")
        if missing:
            return False, ("Not found in Active Directory: %s. A group name that does "
                           "not exist would lock everyone out of the site."
                           % ", ".join(missing))
    args = ["set-access", label, mode]
    if mode == "groups":
        args.append(",".join(groups))
    _, err = _helper_json(args)
    if err:
        return False, "Could not update access policy: %s" % err
    return True, None


app.jinja_env.globals["sso_enabled"] = sso_enabled
app.jinja_env.globals["safe_next"] = safe_next


@app.route("/auth/login")
def auth_login():
    try:
        s_cfg = sso_mod.sso_config(load_config())
    except sso_mod.SSOError as e:
        flash("Single sign-on is misconfigured: %s" % e, "error")
        return redirect(url_for("login"))
    if not s_cfg:
        return redirect(url_for("login"))
    url, pending = sso_mod.begin_login(s_cfg, safe_next(request.args.get("next", "/")))
    session["sso_pending"] = pending
    return redirect(url)


@app.route("/auth/callback")
def auth_callback():
    try:
        s_cfg = sso_mod.sso_config(load_config())
        if not s_cfg:
            raise sso_mod.SSOError("single sign-on is not enabled")
        pending = session.pop("sso_pending", None)
        claims = sso_mod.complete_login(s_cfg, pending, request.args)
        ident = sso_mod.identity_from_claims(claims)
        cfg = load_config()
        ctx = sso_mod.authorize(_ldap_cfg(), ident,
                                (cfg.get("sso") or {}).get("owners") or [])
    except sso_mod.SSOError as e:
        audit("sso-denied", str(e)[:400])
        flash("Sign-in failed. %s" % e, "error")
        return redirect(url_for("login"))

    session.clear()
    session.permanent = True
    session["auth_at"] = int(time.time())
    session["auth_cap"] = _session_cap_now()
    session["user"] = ctx["user"]
    session["sso"] = ctx
    audit("sso-login", "%s role=%s prod-write=%s groups=%s"
          % (ctx["user"], ctx["role"], ctx["can_write_prod"], ",".join(ctx["groups"])))
    return redirect(safe_next((pending or {}).get("next", "/")))


@app.route("/auth/logout", methods=["POST"])
@login_required
def auth_logout():
    check_csrf()
    ctx = session.get("sso") or {}
    audit("sso-logout", ctx.get("user", session.get("user", "")))
    session.clear()
    try:
        s_cfg = sso_mod.sso_config(load_config())
    except sso_mod.SSOError:
        s_cfg = None
    if s_cfg:
        # Ends the Entra session too, so the next visit is a real sign-in
        # rather than a silent re-auth from a still-live browser session.
        return redirect(sso_mod.logout_url(s_cfg, "/login"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        user = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        wait = _login_locked_for(user)
        if wait:
            _log_auth("login-locked", user)
            flash(f"Too many failed attempts. Try again in {wait} min.", "error")
            return render_template("login.html"), 429
        h = load_config().get("users", {}).get(user)
        # Always run one real hash check so an unknown username costs the same
        # as a wrong password (no timing oracle on which accounts exist).
        if check_password_hash(h or _DUMMY_HASH, pw) and h:
            _login_clear(user)
            session.clear()
            session.permanent = True
            session["auth_at"] = int(time.time())
            session["auth_cap"] = _session_cap_now()
            session["user"] = user
            audit("login", f"user={user}")
            return redirect(safe_next(request.args.get("next", "")) or url_for("dashboard"))
        _login_failed(user)
        audit("login-failed", f"user={_log_safe(user)}")
        _log_auth("login-failed", user)
        flash("Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    check_csrf()
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


# ==========================================================================
# Settings — every tunable admin setting, managed here rather than by editing
# config.json on the box. Settings are declared in settings_registry.py; this
# page renders whatever is declared, so adding one is a declaration and not a
# page change.
#
# Gated to the platform owner. Under SSO that is the SaaS-ITH-SA group
# (mapped to the platform-owner role in sso.py). Before SSO is enabled the only
# way in is the local break-glass account, which is the owner account, so it is
# allowed through — otherwise nobody could configure SSO in the first place.
# ==========================================================================
def _break_glass_owners(cfg):
    """Local accounts allowed to administer settings when SSO is not in play.

    Without this, ANY local account was a platform owner. Today there is exactly
    one (the break-glass admin), so that was not live exposure - but adding a
    second local account would silently have handed it the console. Explicit list
    wins; otherwise a lone local account is taken to be the break-glass owner; and
    if several exist with no list, nobody qualifies. Fails closed on purpose.
    """
    listed = cfg.get("break_glass_owners")
    if listed:
        return {str(x).strip().lower() for x in listed if str(x).strip()}
    users = list((cfg.get("users") or {}).keys())
    return {users[0].lower()} if len(users) == 1 else set()


def platform_owner_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        ctx = session.get("sso")
        if ctx:
            if ctx.get("role") != "platform-owner":
                audit("settings-denied", "%s role=%s" % (ctx.get("user", ""), ctx.get("role")))
                abort(403)
        elif session.get("user", "").lower() not in _break_glass_owners(load_config()):
            audit("settings-denied", "%s local-account-not-break-glass-owner"
                  % session.get("user", ""))
            abort(403)
        return fn(*a, **kw)
    return wrapper


def is_platform_owner():
    """For the nav: show the link only to someone who can actually open the page."""
    if not session.get("user"):
        return False
    ctx = session.get("sso")
    if ctx:
        return ctx.get("role") == "platform-owner"
    return session.get("user", "").lower() in _break_glass_owners(load_config())


app.jinja_env.globals["is_platform_owner"] = is_platform_owner


# ===========================================================================
# CORPIT-CONSOLE-CAPABILITIES
#
# Who may do what used to be decided by the decorator on each route, and nearly
# every action carried only @login_required - so anyone who could open the
# console could also delete a production vhost, and changing that meant editing
# code. Each privileged action is now a named capability granted to Active
# Directory groups from the console itself (Identity & Access > Permissions).
#
# The check is a set intersection against the groups already resolved into the
# session at sign-in, so it costs nothing on the request path and the gate stays
# free of directory round trips. The consequence, which the page states, is that
# a grant reaches someone already signed in only at their next sign-in.
#
# The platform owner holds every capability unconditionally. That is what makes
# it impossible to lock every administrator out of the console with one edit.
# ===========================================================================
PERMISSIONS_PATH = os.path.join(STATE_DIR, "permissions.json")


def permission_policy():
    """The grant table, read once per request."""
    if "perm_policy" not in g:
        g.perm_policy = permissions.load(PERMISSIONS_PATH)
    return g.perm_policy


def can(cap):
    """May the current session use this capability? Used by routes and templates
    alike, so a control is never rendered that the request would then refuse."""
    if not session.get("user"):
        return False
    return permissions.allowed(permission_policy(), cap, session, is_platform_owner())


app.jinja_env.globals["can"] = can
app.jinja_env.globals["capabilities"] = permissions.CAPABILITIES


def requires(cap):
    """Gate a route on a capability.

    A refusal is audited and lands the operator back on the console with an
    explanation naming the capability - not a bare 403 they cannot act on, and
    never a silent no-op.
    """
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("user"):
                return redirect(url_for("login", next=request.path))
            if not can(cap):
                label = permissions.BY_KEY[cap].label if cap in permissions.BY_KEY else cap
                audit("permission-denied", "%s lacks %s" % (session.get("user", "?"), cap))
                flash("You do not have permission to: %s. That capability is granted to "
                      "Active Directory groups under Identity & Access." % label, "error")
                back = request.form.get("_back", "")
                return redirect(back if _CONSOLE_BACK_RE.match(back or "") else "/console")
            return fn(*a, **kw)
        return wrapper
    return deco


@app.route("/permissions", methods=["POST"])
@platform_owner_required
def permissions_page():
    """Save the grant table. Owner-only and not delegable - see permissions.py."""
    check_csrf()
    before = permissions.load(PERMISSIONS_PATH)
    submitted = {c.key: request.form.getlist("cap:" + c.key)
                 for c in permissions.CAPABILITIES if c.editable}
    saved = permissions.save(PERMISSIONS_PATH, submitted)
    changes = permissions.diff(before, saved)
    for label, added, removed in changes:
        audit("permission-change", "%s: +[%s] -[%s]"
              % (label, ", ".join(added), ", ".join(removed)))
    if changes:
        flash("Saved %d permission change%s. Group membership is read at sign-in, so "
              "anyone already signed in keeps their current access until they sign in "
              "again." % (len(changes), "" if len(changes) == 1 else "s"), "ok")
    else:
        flash("No permission changes to save.", "ok")
    return redirect("/console#iam")


@app.route("/access-governance/proposals", methods=["POST"])
@requires("access.propose")
def access_governance_proposal():
    """Record intended AD work without changing the directory."""
    check_csrf()
    data, problems = access_governance.validate_proposal(request.form)
    if problems:
        flash("Nothing was recorded. " + problems[0], "error")
        return redirect("/console#iam/governance")
    proposal_id = access_governance.save_proposal(
        db(), session.get("user", "unknown"), data)
    audit("access-proposal", "AG-%04d %s %s" % (
        proposal_id, data["action"], data["group_name"]))
    flash("Recorded proposal AG-%04d. Active Directory was not changed." % proposal_id, "ok")
    return redirect("/console#iam/governance")


def _settings_unfinished(days=7, settle=60):
    """Settings saves that recorded an intent but no outcome: the worker stopped
    between the intent row and the end of the save. Shown on the settings page so
    an operator can compare the current values with what that save meant to do."""
    try:
        rows = db().execute(
            'SELECT ts, "user" AS user, action, detail FROM audit WHERE action IN '
            '(\'settings-save-intent\', \'settings-save-done\', \'settings-save-failed\') '
            'AND ts >= ? ORDER BY id', (
                datetime.fromtimestamp(time.time() - days * 86400, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),)
        ).fetchall()
    except Exception:
        return []
    # audit ts is now_iso(): "YYYY-MM-DD HH:MM:SS UTC", so compare the first 19 characters.
    open_ops, cutoff = {}, datetime.fromtimestamp(time.time() - settle, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    for r in rows:
        m = re.match(r"op=([0-9a-f]{12})\b", r["detail"] or "")
        if not m:
            continue
        if r["action"] == "settings-save-intent":
            open_ops[m.group(1)] = r
        else:
            open_ops.pop(m.group(1), None)
    return [("warn", "A settings save by %s at %s (op %s) recorded what it was about to change "
             "but no result. Compare the current values with that settings-save-intent row in "
             "the audit log." % (r["user"], r["ts"], op))
            for op, r in open_ops.items() if (r["ts"] or "")[:19] < cutoff]


def _settings_recent(limit=12):
    try:
        rows = db().execute(
            'SELECT ts, "user" AS user, detail FROM audit WHERE action = ? ORDER BY id DESC LIMIT ?',
            ("settings-change", limit)).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


@app.route("/settings", methods=["GET", "POST"])
@requires("settings.manage")
def settings_page():
    cfg = load_config()
    problems = []

    if request.method == "POST":
        check_csrf()
        # PROD-READINESS 2026-10-12. The whole read/compare/apply/audit/write runs
        # under one cross-worker lock, so it is judged against the file as it is
        # now, not as it was when the form was drawn.
        with config_write_lock():
            cfg, rev = load_config_rev()
            sent_rev = (request.form.get("config_rev") or "").strip()
            if sent_rev != rev:
                # Another save landed after this form was drawn. Applying it would
                # put back every value that save changed, because the form submits
                # all groups. The browser keeps the operator's edits (noc-workspaces.js).
                session["settings_restore_draft"] = True
                try:
                    audit("settings-stale-refused", "form revision %s, current %s" % (sent_rev[:20] or "none", rev))
                except Exception:
                    pass
                flash("Nothing was saved. Console settings were changed by another save after "
                      "this page was opened. Your edits are kept below: check them against the "
                      "current values and Save again.", "error")
                return redirect(url_for("settings_page"))
            changes, problems = settings_mod.apply_form(cfg, request.form, session.get("user", ""))
            if not problems:
                problems = settings_mod.preflight(cfg)
            if not problems and changes:
                # The audit record is a precondition of the change: no intent row,
                # no write. The intent row names every change, so a process that
                # dies after the write still leaves a record of what it applied.
                op = secrets.token_hex(6)
                try:
                    audit("settings-save-intent", "op=%s from=%s; %s" % (op, rev, "; ".join(
                        "%s: %r -> %r" % (label, before, after) for label, before, after in changes)))
                except Exception:
                    session["settings_restore_draft"] = True
                    flash("Nothing was saved. The audit log could not record this change, and "
                          "a change that cannot be audited is not applied.", "error")
                    return redirect(url_for("settings_page"))
                try:
                    save_config(cfg)
                except Exception as e:
                    session["settings_restore_draft"] = True
                    try:
                        audit("settings-save-failed", "op=%s %s" % (op, type(e).__name__))
                    except Exception:
                        pass
                    flash("Nothing was saved. The settings file could not be written (%s)."
                          % type(e).__name__, "error")
                    return redirect(url_for("settings_page"))
                try:
                    for label, before, after in changes:
                        audit("settings-change", "%s: %r -> %r" % (label, before, after))
                    audit("settings-save-done", "op=%s" % op)
                except Exception:
                    flash("Saved, but the per-setting audit rows could not be written. The "
                          "change is recorded by its intent row (op %s)." % op, "error")
        if problems:
            session["settings_restore_draft"] = True
            flash("Nothing was saved. " + problems[0], "error")
        else:

            # The Observability settings are consumed by the Hub API, which runs
            # as a different user and cannot read this app's 0600 config.json.
            # Saving them here is only half the act: the root helper publishes
            # them to /etc/corpit/shared/observability.json, which that API re-reads
            # every 30 seconds. This runs on every accepted submission --
            # INCLUDING one that changed nothing -- so a published file that was
            # lost or never written repairs itself when an operator opens
            # Settings and clicks Save. It used to sit inside the "something
            # changed" branch, which made that one gesture a no-op with a green
            # flash: recovering actually meant editing a value, saving, editing
            # it back and saving again, for two audit rows nobody wanted and
            # nothing on the page saying why.
            #
            # A failure is reported, never swallowed. A setting stored in the
            # console but never delivered to the thing it configures is exactly
            # the kind of control that looks like it works and does not.
            _, obs_err = _helper_json(["sync-obs"])
            if obs_err:
                # Wording follows the path: on a no-change Save nothing was
                # saved, and claiming otherwise is the small lie that teaches
                # operators to stop reading these banners.
                lead = "Saved, but the" if changes else "The"
                flash("%s observability settings could not be published to the "
                      "Hub API (%s). The values on this page are stored but "
                      "NOT yet in force." % (lead, obs_err), "error")
                audit("settings-obs-publish-failed", str(obs_err))
                return redirect(url_for("settings_page"))

            # The Claude spend-alert tunables travel the same road for the same
            # reason: the Hub API runs as `corpit` and cannot read this app's
            # 0600 config.json. One of these three settings is the switch that
            # starts email going to real managers, so a value stored here but
            # never delivered is not a cosmetic failure - it is the console
            # showing "on" while nothing sends, or "off" while something does.
            _, spend_err = _helper_json(["sync-spend"])
            if spend_err:
                lead = "Saved, but the" if changes else "The"
                flash("%s Claude spend alert settings could not be published to "
                      "the Hub API (%s). The values on this page are stored but "
                      "NOT yet in force." % (lead, spend_err), "error")
                audit("settings-spend-publish-failed", str(spend_err))
                return redirect(url_for("settings_page"))

            # The AI-Reporting return allowlist travels the same road: stored in
            # this app's 0600 config.json, published by the root helper to a file
            # the Hub API (user `corpit`) can read. A list stored here but never
            # delivered is a link that grants or denies the wrong people.
            _, rr_err = _helper_json(["sync-reporting-return"])
            if rr_err:
                lead = "Saved, but the" if changes else "The"
                flash("%s AI Reporting return allowlist could not be published to "
                      "the Hub API (%s). The values on this page are stored but "
                      "NOT yet in force." % (lead, rr_err), "error")
                audit("settings-reporting-return-publish-failed", str(rr_err))
                return redirect(url_for("settings_page"))

            # The ops-failure email settings travel the same road. Stored here but
            # never delivered means the console names a recipient while failures
            # go unmailed -- the silent gap this setting exists to close.
            _, oa_err = _helper_json(["sync-ops-alerts"])
            if oa_err:
                lead = "Saved, but the" if changes else "The"
                flash("%s ops failure email settings could not be published "
                      "(%s). The values on this page are stored but NOT yet in "
                      "force." % (lead, oa_err), "error")
                audit("settings-ops-alerts-publish-failed", str(oa_err))
                return redirect(url_for("settings_page"))

            # Server updates: the root corpit-updates service enforces these, so
            # Save hands them over its socket. Only on a host that runs the
            # service (itam); elsewhere the group is hidden and this is skipped.
            up_err = updates_panel.publish_policy(session.get("user", ""), settings_mod.updates_policy(cfg))
            if up_err:
                lead = "Saved, but the" if changes else "The"
                flash("%s server updates settings could not be handed to the updates "
                      "service (%s). The values on this page are stored but NOT yet "
                      "in force." % (lead, up_err), "error")
                audit("settings-updates-publish-failed", str(up_err))
                return redirect(url_for("settings_page"))

            # Prod web watch: the root corpit-webwatch service enforces the operator
            # list and hands the reminder interval to the HA alert evaluator. Same
            # road, same rule: itam only, and a failure is reported, never swallowed.
            ww_err = webwatch_panel.publish_policy(session.get("user", ""), settings_mod.webwatch_policy(cfg))
            if ww_err:
                lead = "Saved, but the" if changes else "The"
                flash("%s prod web watch settings could not be handed to the web watch "
                      "service (%s). The values on this page are stored but NOT yet "
                      "in force." % (lead, ww_err), "error")
                audit("settings-webwatch-publish-failed", str(ww_err))
                return redirect(url_for("settings_page"))

            if changes:
                flash("Saved %d change%s." % (len(changes), "" if len(changes) == 1 else "s"), "ok")
            else:
                # A no-change Save is no longer a no-op: it invoked a root helper
                # that rewrote a file outside this app. A privileged write with
                # no trace is not something this console should be capable of,
                # so record it. The change path needs no equivalent -- its
                # settings-change rows already imply the publish.
                audit("settings-obs-republish", "no-change save; %s, %s, %s and %s rewritten"
                      % (OBS_PUBLISHED_PATH, SPEND_PUBLISHED_PATH, REPORTING_RETURN_PUBLISHED_PATH,
                         OPS_ALERTS_PUBLISHED_PATH))
                flash("No changes to save. Observability and Claude spend alert "
                      "settings republished.", "ok")
            return redirect(url_for("settings_page"))
        cfg = load_config()

    # Retired as a page. The console renders the registry-driven form (and the
    # advisories, problems and change history with it); this route is now only
    # the write path. A rejected save has already flashed why, so both outcomes
    # land the operator back on the same section.
    return redirect("/console#system")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user = session["user"]
    if request.method == "POST":
        check_csrf()
        cur = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        cfg = load_config()
        stored = cfg.get("users", {}).get(user)

        if not stored or not check_password_hash(stored, cur):
            flash("Current password is incorrect.", "error")
        elif len(new) < MIN_PASSWORD_LEN:
            flash(f"New password must be at least {MIN_PASSWORD_LEN} characters.", "error")
        elif new != confirm:
            flash("New password and confirmation do not match.", "error")
        elif check_password_hash(stored, new):
            flash("New password must be different from the current one.", "error")
        else:
            # Re-read under the config lock so a settings save in another worker
            # between the read above and this write is not undone.
            with config_write_lock():
                cfg = load_config()
                cfg.setdefault("users", {})[user] = generate_password_hash(new)
                save_config(cfg)
            audit("password-change", f"user={user}")
            flash("Password updated.", "ok")
            return redirect(url_for("account"))
    # Retired as a page - the break-glass password form lives on the console.
    return redirect("/console#system")


# ---------------------------------------------------------------- views
@app.route("/")
@login_required
def dashboard():
    """The console is the front door. The old subdomain dashboard, the beta-link
    page, the directory-sync page, settings and account are all sections of it
    now; the endpoint name is kept because url_for("dashboard") is referenced
    from a dozen redirects."""
    return _console()


def _push_dns(label):
    """Run the privileged DNS push (helper verb push-dns). Returns
    (result_dict, None) on success or (None, error_message) on failure.
    The helper creates/verifies the A record on all three DCs, taking a zone
    backup first and refusing to touch a name that points elsewhere."""
    try:
        out = subprocess.run(
            ["sudo", "-n", HELPER, "push-dns", label],
            capture_output=True, text=True, timeout=200,
        )
    except subprocess.TimeoutExpired:
        return None, ("DNS push timed out — the record may still land via "
                      "replication; use Push DNS again to re-check")
    try:
        result = json.loads(out.stdout.strip() or "{}")
    except json.JSONDecodeError:
        result = {}
    if out.returncode != 0 or not result.get("ok"):
        return None, result.get("error") or (out.stderr.strip() or "DNS push failed")
    return result, None


def _record_dns_result(sub_id, fqdn, result, err):
    """Persist + audit + flash one DNS push outcome."""
    if err:
        db().execute("UPDATE subdomains SET dns_status='failed' WHERE id=?", (sub_id,))
        db().commit()
        audit("push-dns-failed", f"{fqdn}: {err}")
        flash(f"DNS push for {fqdn} failed: {err}", "error")
        return
    pending = [d for d, st in (result.get("dcs") or {}).items() if st != "ok"]
    status = "pending" if pending else "live"
    db().execute("UPDATE subdomains SET dns_status=?, dns_pushed_at=? WHERE id=?",
                 (status, now_iso(), sub_id))
    db().commit()
    audit("push-dns", f"{fqdn} -> {result.get('ip')} "
                      f"({result.get('action')}; dcs={result.get('dcs')})")
    if pending:
        flash(f"DNS record for {fqdn} is live on the primary DC; still replicating "
              f"to: {', '.join(pending)}. Re-run Push DNS in a few minutes to "
              f"confirm.", "ok")
    else:
        flash(f"DNS record {fqdn} → {result.get('ip')} verified on all domain "
              f"controllers. New names can take a few minutes to reach Macs "
              f"over ZPA.", "ok")


@app.route("/subdomains", methods=["POST"])
@requires("subdomain.create")
def create_subdomain():
    check_csrf()
    label = request.form.get("label", "").strip().lower()
    department = request.form.get("department", "").strip()
    notes = request.form.get("notes", "").strip()

    # validation
    if not LABEL_RE.match(label) or "--" in label:
        flash("Invalid subdomain label. Use lowercase letters, digits and hyphens (1–40 chars).", "error")
        return redirect(url_for("dashboard"))
    if label in RESERVED:
        flash(f"'{label}' is a reserved name.", "error")
        return redirect(url_for("dashboard"))
    if db().execute("SELECT 1 FROM subdomains WHERE label=?", (label,)).fetchone():
        flash(f"{label}.{BASE_DOMAIN} already exists.", "error")
        return redirect(url_for("dashboard"))

    # CORPIT-SITE-ACCESS-CONSOLE Who may open this site, decided at registration rather than
    # left for later - a site with no answer is reachable only by platform owners.
    access_mode = request.form.get("access_mode", "groups").strip()
    access_groups = parse_groups_field(request.form.get("access_groups", ""))
    if access_mode not in ACCESS_MODES:
        flash("Choose a valid access level for the new site.", "error")
        return redirect(url_for("dashboard"))
    if access_mode == "groups":
        if not access_groups:
            flash("Name at least one AD security group that may open this site "
                  "(or choose 'Platform owners only' for now).", "error")
            return redirect(url_for("dashboard"))
        missing = missing_ad_groups(access_groups)
        if missing is None:
            flash("The directory could not be reached, so the group names could not "
                  "be verified. The subdomain was not created.", "error")
            return redirect(url_for("dashboard"))
        if missing:
            flash("Not found in Active Directory: %s. Nothing was created."
                  % ", ".join(missing), "error")
            return redirect(url_for("dashboard"))

    # provision via the privileged helper
    helper_args = ["sudo", "-n", HELPER, "create", label]
    if access_mode == "groups":
        helper_args.append(",".join(access_groups))
    try:
        out = subprocess.run(
            helper_args,
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        flash("Provisioning timed out.", "error")
        return redirect(url_for("dashboard"))

    try:
        result = json.loads(out.stdout.strip() or "{}")
    except json.JSONDecodeError:
        result = {}
    if out.returncode != 0 or not result.get("ok"):
        msg = result.get("error") or (out.stderr.strip() or "provisioning failed")
        flash(f"Could not create subdomain: {msg}", "error")
        audit("create-failed", f"{label}: {msg}")
        return redirect(url_for("dashboard"))

    fqdn = result["fqdn"]
    db().execute(
        """INSERT INTO subdomains(label,fqdn,department,notes,status,cert_type,csr_path,created_at,created_by)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (label, fqdn, department, notes, result.get("status", "parked"),
         result.get("cert_type", "self-signed"), result.get("csr_path", ""),
         now_iso(), session["user"]),
    )
    db().commit()
    audit("create", fqdn)
    # The helper defaults a group-less site to platform-owners-only; if the
    # console asked for 'authenticated', set that now.
    if access_mode == "authenticated":
        ok, msg = apply_site_access(label, "authenticated", [])
        if not ok:
            flash(msg, "error")
    audit("access-set", "%s mode=%s groups=%s"
          % (fqdn, access_mode, ",".join(access_groups) or "-"))
    sub_id = db().execute(
        "SELECT id FROM subdomains WHERE label=?", (label,)).fetchone()["id"]
    flash(f"{fqdn} created and serving the parked page. Finish go-live: install "
          f"the NRPI-CA cert.", "ok")
    # DNS is pushed automatically so a fresh subdomain resolves with no manual
    # step; failure here never rolls back the subdomain itself.
    result, err = _push_dns(label)
    _record_dns_result(sub_id, fqdn, result, err)
    return redirect(url_for("detail", sub_id=sub_id))


@app.route("/subdomains/<int:sub_id>/access", methods=["POST"])
@requires("subdomain.access")
def set_access(sub_id):
    """CORPIT-SITE-ACCESS-CONSOLE Change who may open one site.

    Platform-owner only: this is the control that decides who sees a site, so it
    sits at a higher bar than creating one.
    """
    check_csrf()
    row = db().execute("SELECT * FROM subdomains WHERE id=?", (sub_id,)).fetchone()
    if not row:
        abort(404)
    mode = request.form.get("access_mode", "").strip()
    groups = parse_groups_field(request.form.get("access_groups", ""))
    ok, msg = apply_site_access(row["label"], mode, groups)
    if not ok:
        flash(msg, "error")
    else:
        audit("access-set", "%s mode=%s groups=%s"
              % (row["fqdn"], mode, ",".join(groups) or "-"))
        if mode == "groups":
            flash("Access updated. Anyone already signed in must sign in again for "
                  "this to apply to them - group membership is read at sign-in.", "ok")
        else:
            flash("Access updated.", "ok")
    return redirect(url_for("detail", sub_id=sub_id))


# SECPAGELIMIT-20261019 (itam dev): hold one of a site's groups to a few pages.
_PAGE_LIMIT_RE = re.compile(r"/[A-Za-z0-9_-][A-Za-z0-9._/-]{0,150}\.html")


@app.route("/subdomains/<int:sub_id>/page-limits", methods=["POST"])
@requires("subdomain.access")
def set_page_limits(sub_id):
    """Members of one group that opens this site get only the listed pages; the gate
    refuses every other page document. Empty pages clears the limit. Same bar as
    set_access: this decides what people see."""
    check_csrf()
    row = db().execute("SELECT * FROM subdomains WHERE id=?", (sub_id,)).fetchone()
    if not row:
        abort(404)
    group = request.form.get("limit_group", "").strip()
    pages = parse_groups_field(request.form.get("limit_pages", ""))
    acc = site_access_for(row["fqdn"])
    if acc["mode"] != "groups" or group.lower() not in {g.lower() for g in acc["groups"]}:
        flash("Pick one of the AD groups that opens this site.", "error")
        return redirect(url_for("detail", sub_id=sub_id))
    bad = [p for p in pages if not _PAGE_LIMIT_RE.fullmatch(p) or ".." in p or "//" in p]
    if bad or len(pages) > 50:
        flash("Pages must be site paths ending in .html, like /ai-governance.html (at most 50)%s."
              % (": " + ", ".join(bad[:5]) if bad else ""), "error")
        return redirect(url_for("detail", sub_id=sub_id))
    _, err = _helper_json(["set-page-limit", row["label"], group, ",".join(pages) if pages else "-"])
    if err:
        flash("Could not update page limits: %s" % err, "error")
    else:
        audit("page-limit-set", "%s group=%s pages=%s" % (row["fqdn"], group, ",".join(pages) or "-"))
        flash("Page limit for %s %s. Takes effect at once." % (group, "saved" if pages else "cleared"), "ok")
    return redirect(url_for("detail", sub_id=sub_id))


# DEVACCESS-W3-20261019 (itam dev): who may open the launch pad, dev-releases.nrpi.local. It has no
# subdomain row, so it gets its own form under Identity & Access > Site access. The launch pad lets only
# its signers (jriggs, rabad) change anything and only superadmins open its Settings, so a group added
# here can look and nothing more. Only the dev helper lists the launch pad (get-access "dev_view").
@app.route("/launch-pad/access", methods=["POST"])
@requires("subdomain.access")
def set_launchpad_access():
    check_csrf()
    back = "/console#iam/siteaccess"
    if not site_policy().get("dev_view"):
        flash("The launch pad's access is set only on the itam dev server, and its policy could not be read "
              "here. Nothing was changed.", "error")
        return redirect(back)
    mode = request.form.get("access_mode", "").strip()
    groups = parse_groups_field(request.form.get("access_groups", ""))
    if mode not in ("groups", "superadmin"):
        flash("The launch pad is open either to the AD groups you list or to platform owners only.", "error")
        return redirect(back)
    ok, msg = apply_site_access("releases", mode, groups)
    if not ok:
        flash(msg, "error")
    else:
        audit("access-set", "dev-releases.nrpi.local mode=%s groups=%s" % (mode, ",".join(groups) or "-"))
        flash("Launch pad access updated. People in these groups can look; only jriggs and rabad can act. "
              "Anyone already signed in must sign in again for this to apply to them.", "ok")
    return redirect(back)
@app.route("/subdomains/<int:sub_id>")
@login_required
def detail(sub_id):
    """Retired as a page. The console renders every subdomain with its own
    drawer - access, certificate, CSR and removal - so there is nothing left
    here to show. The endpoint stays because several routes redirect to it."""
    if not db().execute("SELECT 1 FROM subdomains WHERE id=?", (sub_id,)).fetchone():
        abort(404)
    return redirect("/console#subdomains")


@app.route("/subdomains/<int:sub_id>/delete", methods=["POST"])
@requires("subdomain.delete")
def delete_subdomain(sub_id):
    check_csrf()
    row = db().execute("SELECT * FROM subdomains WHERE id=?", (sub_id,)).fetchone()
    if not row:
        abort(404)
    out = subprocess.run(["sudo", "-n", HELPER, "remove", row["label"]],
                         capture_output=True, text=True, timeout=60)
    try:
        ok = json.loads(out.stdout.strip() or "{}").get("ok")
    except json.JSONDecodeError:
        ok = False
    if out.returncode != 0 or not ok:
        flash("Removal failed on the server; nothing changed.", "error")
        return redirect(url_for("dashboard"))
    db().execute("DELETE FROM subdomains WHERE id=?", (sub_id,))
    db().commit()
    audit("remove", row["fqdn"])
    flash(f"{row['fqdn']} removed.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/subdomains/<int:sub_id>/dns", methods=["POST"])
@requires("subdomain.dns")
def push_dns(sub_id):
    """Manual Push DNS — retro-fit for subdomains created before the automatic
    push existed, and the retry path when a push failed or a replica lagged.
    Idempotent: the helper reports already-present as success and refuses to
    touch a name that resolves elsewhere."""
    check_csrf()
    row = db().execute("SELECT * FROM subdomains WHERE id=?", (sub_id,)).fetchone()
    if not row:
        abort(404)
    result, err = _push_dns(row["label"])
    _record_dns_result(sub_id, row["fqdn"], result, err)
    return redirect(url_for("detail", sub_id=sub_id))


@app.route("/subdomains/<int:sub_id>/cert", methods=["POST"])
@requires("subdomain.cert")
def deploy_cert(sub_id):
    """Upload the file NRPI-CA returned (p7b best; .cer/.pem fine) and hand it
    to the privileged helper, which verifies it against this subdomain's key
    BEFORE touching nginx, installs the ordered fullchain, reloads, and
    confirms the new cert is served (by serial). All heavy validation is in
    the helper; this route only stages the upload and records the result."""
    check_csrf()
    row = db().execute("SELECT * FROM subdomains WHERE id=?", (sub_id,)).fetchone()
    if not row:
        abort(404)

    f = request.files.get("cert_file")
    if f is None or not f.filename:
        flash("Choose the certificate file the CA returned (.p7b, .cer or .pem).", "error")
        return redirect(url_for("detail", sub_id=sub_id))
    data = f.read()
    if not (100 <= len(data) <= 128 * 1024):
        flash("That file does not look like a certificate (wrong size).", "error")
        return redirect(url_for("detail", sub_id=sub_id))

    staged = os.path.join(UPLOAD_DIR, f"{row['label']}-{secrets.token_hex(8)}.bundle")
    try:
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except OSError:
        flash("Could not stage the upload on the server.", "error")
        return redirect(url_for("detail", sub_id=sub_id))

    try:
        try:
            out = subprocess.run(
                ["sudo", "-n", HELPER, "deploy-cert", row["label"], staged],
                capture_output=True, text=True, timeout=90,
            )
        except subprocess.TimeoutExpired:
            flash("Certificate deployment timed out; nothing was changed past the last verified step.", "error")
            audit("deploy-cert-failed", f"{row['fqdn']}: timeout")
            return redirect(url_for("detail", sub_id=sub_id))

        try:
            result = json.loads(out.stdout.strip() or "{}")
        except json.JSONDecodeError:
            result = {}
        if out.returncode != 0 or not result.get("ok"):
            msg = result.get("error") or (out.stderr.strip() or "deployment failed")
            flash(f"Certificate not deployed: {msg}", "error")
            audit("deploy-cert-failed", f"{row['fqdn']}: {msg}")
            return redirect(url_for("detail", sub_id=sub_id))

        db().execute(
            """UPDATE subdomains SET cert_type=?, cert_issuer=?, cert_expires=?,
               cert_deployed_at=? WHERE id=?""",
            (result.get("cert_type", "NRPI-CA"), result.get("issuer", ""),
             result.get("not_after", ""), now_iso(), sub_id),
        )
        db().commit()
        audit("deploy-cert",
              f"{row['fqdn']} serial={result.get('serial','?')} expires={result.get('not_after','?')}")
        flash(f"Certificate deployed and verified live for {row['fqdn']} — "
              f"issued by {result.get('issuer','?')}, expires {result.get('not_after','?')}.", "ok")
        return redirect(url_for("detail", sub_id=sub_id))
    finally:
        try:
            os.unlink(staged)
        except OSError:
            pass


# ------------------------------------------------------- beta links (corpit)
# The public beta hub at https://corpit.nrpi.local/ is a STATIC file. Every
# mutation below rewrites it, so the page has no runtime dependency on this
# app: if gunicorn is down the hub keeps serving the last good render.
BETA_PAGE_PATH = "/var/www/corpit/index.html"
BETA_HOST_FQDN = "corpit." + BASE_DOMAIN


def _beta_rows(enabled_only=False):
    q = "SELECT * FROM beta_links"
    if enabled_only:
        q += " WHERE enabled=1"
    return db().execute(q + " ORDER BY sort_order ASC, id ASC").fetchall()


def safe_link_url(raw):
    """Allow only http(s) absolute URLs or single-slash site-relative paths.

    Rejects javascript:, data:, and protocol-relative //evil.example so a link
    on the hub can never be turned into a redirect off-host or a script URL.
    """
    raw = (raw or "").strip()
    if not raw or len(raw) > 500:
        return None
    if raw.startswith("/"):
        return None if raw.startswith("//") or "\\" in raw else raw
    parts = urlsplit(raw)
    if parts.scheme in ("http", "https") and parts.netloc:
        return raw
    return None


def regenerate_beta_page():
    """Render the hub to disk atomically (tempfile + os.replace)."""
    html = render_template(
        "corpit_page.html",
        links=_beta_rows(enabled_only=True),
        generated=now_iso(),
        base_domain=BASE_DOMAIN,
        host_ip=HOST_IP,
        host_fqdn=BETA_HOST_FQDN,
    )
    target_dir = os.path.dirname(BETA_PAGE_PATH)
    fd, tmp = tempfile.mkstemp(dir=target_dir, prefix=".index-", suffix=".html")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(html)
        os.chmod(tmp, 0o644)
        os.replace(tmp, BETA_PAGE_PATH)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _regen_or_flash():
    """Regenerate, but never let a write failure hide the DB change."""
    try:
        regenerate_beta_page()
        return True
    except OSError as exc:
        flash(f"Saved, but the public page could not be rewritten: {exc}", "error")
        audit("beta-regen-failed", str(exc))
        return False


def _next_order():
    row = db().execute("SELECT MAX(sort_order) AS m FROM beta_links").fetchone()
    return (row["m"] or 0) + 10


@app.route("/beta-links")
@login_required
def beta_links_page():
    """Retired as a page - the link directory is a section of the console."""
    return redirect("/console#subdomains")


@app.route("/beta-links", methods=["POST"])
@requires("links.manage")
def beta_links_add():
    check_csrf()
    title = request.form.get("title", "").strip()
    url = safe_link_url(request.form.get("url"))
    desc = request.form.get("description", "").strip()
    if not title:
        flash("A title is required.", "error")
        return redirect(url_for("beta_links_page"))
    if not url:
        flash("Link must be an http(s) URL or a /path on this host.", "error")
        return redirect(url_for("beta_links_page"))
    db().execute(
        """INSERT INTO beta_links(title,url,description,sort_order,enabled,new_tab,
                                  created_at,created_by)
           VALUES(?,?,?,?,1,?,?,?)""",
        (title[:80], url, desc[:160], _next_order(),
         1 if request.form.get("new_tab") else 0, now_iso(), session["user"]),
    )
    db().commit()
    audit("beta-link-add", f"{title} -> {url}")
    if _regen_or_flash():
        flash(f"Added “{title}”. The beta page is updated.", "ok")
    return redirect(url_for("beta_links_page"))


@app.route("/beta-links/<int:link_id>/edit", methods=["GET", "POST"])
@requires("links.manage")
def beta_links_edit(link_id):
    row = db().execute("SELECT * FROM beta_links WHERE id=?", (link_id,)).fetchone()
    if not row:
        abort(404)
    if request.method == "GET":
        # Retired as a page - the console edits a link in place.
        return redirect("/console#subdomains")
    check_csrf()
    title = request.form.get("title", "").strip()
    url = safe_link_url(request.form.get("url"))
    if not title or not url:
        flash("Title and a valid link are both required.", "error")
        return redirect(url_for("beta_links_edit", link_id=link_id))
    db().execute(
        "UPDATE beta_links SET title=?,url=?,description=?,new_tab=? WHERE id=?",
        (title[:80], url, request.form.get("description", "").strip()[:160],
         1 if request.form.get("new_tab") else 0, link_id),
    )
    db().commit()
    audit("beta-link-edit", f"{title} -> {url}")
    if _regen_or_flash():
        flash("Link updated.", "ok")
    return redirect(url_for("beta_links_page"))


@app.route("/beta-links/<int:link_id>/toggle", methods=["POST"])
@requires("links.manage")
def beta_links_toggle(link_id):
    check_csrf()
    row = db().execute("SELECT * FROM beta_links WHERE id=?", (link_id,)).fetchone()
    if not row:
        abort(404)
    new = 0 if row["enabled"] else 1
    db().execute("UPDATE beta_links SET enabled=? WHERE id=?", (new, link_id))
    db().commit()
    audit("beta-link-toggle", f"{row['title']}: {'visible' if new else 'hidden'}")
    _regen_or_flash()
    return redirect(url_for("beta_links_page"))


@app.route("/beta-links/<int:link_id>/move", methods=["POST"])
@requires("links.manage")
def beta_links_move(link_id):
    check_csrf()
    rows = _beta_rows()
    idx = next((i for i, r in enumerate(rows) if r["id"] == link_id), None)
    if idx is None:
        abort(404)
    swap = idx - 1 if request.form.get("dir") == "up" else idx + 1
    if 0 <= swap < len(rows):
        a, b = rows[idx], rows[swap]
        # normalised positions, so equal/duplicate sort_order values still swap
        db().execute("UPDATE beta_links SET sort_order=? WHERE id=?", ((swap + 1) * 10, a["id"]))
        db().execute("UPDATE beta_links SET sort_order=? WHERE id=?", ((idx + 1) * 10, b["id"]))
        db().commit()
        audit("beta-link-move", f"{a['title']} {request.form.get('dir')}")
        _regen_or_flash()
    return redirect(url_for("beta_links_page"))


@app.route("/beta-links/<int:link_id>/delete", methods=["POST"])
@requires("links.manage")
def beta_links_delete(link_id):
    check_csrf()
    row = db().execute("SELECT * FROM beta_links WHERE id=?", (link_id,)).fetchone()
    if not row:
        abort(404)
    db().execute("DELETE FROM beta_links WHERE id=?", (link_id,))
    db().commit()
    audit("beta-link-delete", row["title"])
    if _regen_or_flash():
        flash(f"Removed “{row['title']}”.", "ok")
    return redirect(url_for("beta_links_page"))


@app.route("/beta-links/regenerate", methods=["POST"])
@requires("links.manage")
def beta_links_regen():
    check_csrf()
    if _regen_or_flash():
        audit("beta-regen", BETA_PAGE_PATH)
        flash("Beta page rebuilt.", "ok")
    return redirect(url_for("beta_links_page"))


# ---------------------------------------------------------------------------
# CORPIT-HOUSEKEEPING-RUN
#
# Retention lives in the settings registry; this route is only the act of
# applying it. The plan is recomputed inside housekeeping.prune() rather than
# submitted from the page, so what gets deleted is what is true now - a form
# posted from a stale tab cannot remove something that has since become the
# newest backup in its group.
#
# A partial result is reported as a partial result. Anything that could not be
# removed is named, because a cleanup that silently skips most of its work is
# how a disk fills up while the console says it is tidy.
# ---------------------------------------------------------------------------
@app.route("/housekeeping", methods=["POST"])
@requires("housekeeping.run")
def housekeeping_run():
    check_csrf()
    cfg = load_config()
    hk_cfg = cfg.get("housekeeping") or {}
    try:
        keep_days = int(hk_cfg.get("backup_keep_days") or 30)
    except (TypeError, ValueError):
        keep_days = 30
    try:
        audit_days = int(hk_cfg.get("audit_keep_days") or 365)
    except (TypeError, ValueError):
        audit_days = 365

    removed, failed, freed = housekeeping.prune(keep_days)
    rows = housekeeping.audit_prune(db(), audit_days, dry_run=False)

    if removed:
        audit("housekeeping", "removed %d item(s), %s: %s"
              % (len(removed), housekeeping.human(freed),
                  ", ".join(p for p, _ in removed)[:600]))
    if rows:
        audit("housekeeping", "aged out %d routine audit row(s) older than %d days"
              % (rows, audit_days))

    parts = []
    if removed:
        parts.append("removed %d backup item%s (%s)"
                     % (len(removed), "" if len(removed) == 1 else "s",
                         housekeeping.human(freed)))
    if rows:
        parts.append("aged out %d routine audit row%s" % (rows, "" if rows == 1 else "s"))
    if parts:
        flash("Cleanup: " + " and ".join(parts) + ".", "ok")
    else:
        flash("Nothing was old enough to remove.", "ok")
    for path, why in failed[:6]:
        flash("Could not remove %s - %s" % (path, why), "error")
    if len(failed) > 6:
        flash("%d more could not be removed." % (len(failed) - 6), "error")

    return redirect("/console#ops")


@app.route("/healthz")
def healthz():
    return Response("ok\n", mimetype="text/plain")


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)




# ============================================================================
# Directory Sync (GAL -> mailboxes) console - v2 multi-list, 2026-08-28.
#
# lists.json is the authority on what gets published to whom; this page edits
# it, shows per-person status from the job's state.json, kicks manual syncs,
# and (when the EXO cert grants exist) keeps the Exchange fence group in step.
# Graph cannot modify mail-enabled security groups, hence the pwsh helper.
# ============================================================================
# PATH-RELEASE-20260929: GAL_DIR stays the CODE dir (scripts, .env, exo-app.pfx, the manual
# run log, subprocess cwd). Everything the jobs and this page write lives in GAL_STATE_DIR
# (default /var/lib/gal-directory; same resolver rules as gal-paths.js), including the
# .sync.lock the timers flock on.
GAL_DIR = "/opt/gal-directory"
GAL_STATE_DIR = corpit_paths.gal_state_dir()
GAL_SYNC_LOCK = corpit_paths.gal_lock_file()
GAL_MANUAL_LOG = os.path.join(GAL_DIR, "last-manual-run.log")
GAL_LISTS_JSON = os.path.join(GAL_STATE_DIR, "lists.json")
GAL_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
GAL_ADD_MAX = 300
# Do-not-publish rules, written here and read by the sync engine
# (gal-exclusions.js). A sync-side overlay only: AD, Entra and Exchange are
# never touched, so the person keeps their numbers and stays in Outlook's GAL.
GAL_EXCLUSIONS_JSON = os.path.join(GAL_STATE_DIR, "exclusions.json")
# What the last run saw: every fetched account, published or not and why. The
# engine writes it; the "Who is published" view reads it. No phone numbers.
GAL_ROSTER_JSON = os.path.join(GAL_STATE_DIR, "roster.json")
GAL_STATE_JSON = os.path.join(GAL_STATE_DIR, "state.json")
GAL_MOBILE_SNAPSHOT_MAX_AGE_HOURS = 24
GAL_EXCLUDE_MODES = {
    "hide": "left out of the directory",
    "no-mobile": "published without their mobile number",
    "no-phones": "published without any phone numbers",
}
GAL_EXCLUDE_MAX = 50
GAL_REASON_MAX = 120
# Directory-wide switches live beside the rules in exclusions.json. The engine
# refuses a policy key it does not know, so only these names are ever written.
GAL_POLICY_KEYS = ("requireMobile",)
GAL_POLICY_REASON = "no mobile number"     # the engine's not-published reason under requireMobile
GAL_POLICY_FLASH = {
    "requireMobile": ("Only people with a mobile number are published from the next sync - everyone "
                      "without one is held back. Nothing changes in AD; anyone who later gets a "
                      "number is published again by itself.",
                      "People without a mobile number are published again from the next sync."),
}

_gal_run = {"thread": None, "started": None}


def _gal_sync_running():
    t = _gal_run["thread"]
    return bool(t and t.is_alive())


def _gal_run_sync():
    with open(GAL_MANUAL_LOG, "w") as fh:
        fh.write("started %s\n" % now_iso())
        fh.flush()
        subprocess.run(
            ["/usr/bin/flock", "-w", "600", GAL_SYNC_LOCK, "/usr/bin/node", "gal-mailbox-sync.js", "--apply"],
            cwd=GAL_DIR, stdout=fh, stderr=subprocess.STDOUT, timeout=1800,
        )
        fh.write("finished %s\n" % now_iso())


def _gal_kick_sync():
    if _gal_sync_running():
        return False
    t = threading.Thread(target=_gal_run_sync, daemon=True)
    t.start()
    _gal_run["thread"] = t
    _gal_run["started"] = now_iso()
    return True


def _gal_add_ready():
    return os.path.exists(os.path.join(GAL_DIR, "exo-app.pfx")) and \
           os.path.exists(os.path.join(GAL_STATE_DIR, "exo-app.configured"))


def _gal_lists_load():
    with open(GAL_LISTS_JSON) as fh:
        return json.load(fh)


def _gal_lists_save(lists):
    atomic_write_durable(GAL_LISTS_JSON, json.dumps(lists, indent=1))


def _gal_exclusions_load():
    """{"version": 1, "rules": [...]} - a missing file is an empty list; a
    malformed one raises, and the caller says so rather than silently starting
    from empty (that would let one Save wipe every rule)."""
    try:
        with open(GAL_EXCLUSIONS_JSON) as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return {"version": 1, "rules": []}
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise ValueError("exclusions.json has no rules array")
    if doc.get("policy") is not None and not isinstance(doc["policy"], dict):
        raise ValueError("exclusions.json policy is not an object")
    return doc


def _gal_policy(doc):
    """The directory-wide switches as the engine will read them: every known
    key, as a bool, unknown keys ignored."""
    raw = doc.get("policy") if isinstance(doc.get("policy"), dict) else {}
    return {k: bool(raw.get(k)) for k in GAL_POLICY_KEYS}


def _gal_exclusions_save(doc):
    atomic_write_durable(GAL_EXCLUSIONS_JSON, json.dumps(doc, indent=1))


def _gal_roster_load():
    """The engine's last snapshot, or None before the first run."""
    try:
        with open(GAL_ROSTER_JSON) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _gal_state_load():
    """Last completed engine run, used to prove a roster snapshot is current."""
    try:
        with open(GAL_STATE_JSON) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _gal_roster_index(snapshot):
    """upn/mail (lowercase) -> snapshot row, so a rule can carry the person's
    stable object id and display name from the moment it is written."""
    idx = {}
    for p in (snapshot or {}).get("people") or []:
        for k in (p.get("upn"), p.get("mail")):
            if k:
                idx[k.lower()] = p
    return idx


def _gal_mobile_recipient_upns(snapshot):
    """Return the current published, mobile-enabled roster as mailbox UPNs.

    The roster deliberately carries only the *presence* of a mobile number,
    never the number itself.  Keep that privacy boundary here: this helper is
    for resolving who receives the directory, not for exporting phone data.
    """
    seen, out = set(), []
    for person in (snapshot or {}).get("people") or []:
        if person.get("published") is not True or person.get("mobile") != "yes":
            continue
        address = str(person.get("upn") or person.get("mail") or "").strip().lower()
        if not GAL_EMAIL_RE.fullmatch(address) or address in seen:
            continue
        seen.add(address)
        out.append(address)
    return sorted(out)


def _gal_mobile_rollout_facts(snapshot=None, state=None, now=None):
    """Validate the roster proof used by the exact-match mobile rollout.

    A nonempty file is not enough: the snapshot must come from a recent apply
    run whose state finished without mailbox errors, and both artifacts must
    describe the same roster.  This keeps a stale or dry-run preview from ever
    becoming the authoritative recipient set.
    """
    snapshot = _gal_roster_load() if snapshot is None else snapshot
    state = _gal_state_load() if state is None else state
    recipients = _gal_mobile_recipient_upns(snapshot)
    facts = {
        "available": False,
        "generatedAt": (snapshot or {}).get("generatedAt"),
        "target": len(recipients),
        "recipients": recipients,
        "reason": "Run Sync now, wait for it to finish successfully, then reload this page.",
    }

    if not snapshot or not snapshot.get("generatedAt"):
        facts["reason"] = "No roster snapshot is available. " + facts["reason"]
        return facts
    if snapshot.get("mode") != "apply":
        facts["reason"] = "The latest roster is only a dry-run preview. " + facts["reason"]
        return facts
    if not recipients:
        facts["reason"] = "The latest roster contains no published users with a mobile number. Nothing can be rolled out."
        return facts

    def parsed(value):
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None

    generated = parsed(snapshot.get("generatedAt"))
    current = now or datetime.now(timezone.utc)
    age_hours = ((current - generated).total_seconds() / 3600.0) if generated else None
    facts["ageHours"] = age_hours
    if generated is None or age_hours < -0.1 or age_hours > GAL_MOBILE_SNAPSHOT_MAX_AGE_HOURS:
        facts["reason"] = "The roster snapshot is not recent enough for an exact recipient replacement. " + facts["reason"]
        return facts

    if not state or state.get("mode") != "apply" or state.get("opsFailed") != 0:
        facts["reason"] = "The last apply run did not finish cleanly. " + facts["reason"]
        return facts
    started, finished = parsed(state.get("startedAt")), parsed(state.get("finishedAt"))
    if not started or not finished or finished < generated or abs((generated - started).total_seconds()) > 900:
        facts["reason"] = "The roster snapshot cannot be matched to the last successful apply run. " + facts["reason"]
        return facts
    if state.get("rosterCount") != snapshot.get("published"):
        facts["reason"] = "The roster and last-run counts disagree, so the rollout is disabled. " + facts["reason"]
        return facts

    facts.update(available=True, reason=None, finishedAt=state.get("finishedAt"))
    return facts


def _gal_extract_emails(blob):
    seen, out = set(), []
    for m in GAL_EMAIL_RE.findall(blob or ""):
        e = m.strip().lower()
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def _gal_form_emails():
    blob = request.form.get("emails", "")
    up = request.files.get("csv")
    if up and up.filename:
        try:
            blob += "\n" + up.read(512 * 1024).decode("utf-8", "replace")
        except OSError:
            pass
    return _gal_extract_emails(blob)


def _gal_fence_add(emails):
    """Add emails to the Exchange fence group via the cert-auth helper.
    Returns (added, already, failed[(email, why)]). No-op if not configured."""
    if not emails:
        return [], [], []
    if not _gal_add_ready():
        return [], [], [(e, "fence add not configured - add via PowerShell") for e in emails]
    try:
        out = subprocess.run(
            ["pwsh", "-NoProfile", "-File", os.path.join(GAL_DIR, "gal-add-members.ps1")],
            input=json.dumps(emails), capture_output=True, text=True,
            timeout=300, cwd=GAL_DIR,
        )
        if out.returncode != 0:
            detail = (out.stderr or out.stdout or "PowerShell helper exited without a result").strip()[:120]
            return [], [], [(e, detail) for e in emails]
        results = json.loads(out.stdout.strip() or "[]")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        return [], [], [(e, str(exc)[:120]) for e in emails]
    if not isinstance(results, list):
        return [], [], [(e, "fence helper returned an invalid response") for e in emails]
    by_email = {}
    for result in results:
        if not isinstance(result, dict) or not result.get("email"):
            continue
        by_email[str(result["email"]).strip().lower()] = result
    added, already, failed = [], [], []
    for email in emails:
        key = str(email).strip().lower()
        result = by_email.get(key)
        if not result:
            failed.append((email, "fence helper returned no result for this recipient"))
        elif result.get("result") == "added":
            added.append(email)
        elif result.get("result") == "already":
            already.append(email)
        else:
            failed.append((email, result.get("detail") or "fence helper did not confirm membership"))
    return added, already, failed


def _gal_slug(name):
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:32]
    return s or None


# CORPIT-ACCESS-FOLD: the standalone Hub Access Control page (corpit /access-admin.html, and
# /saas-admin.html before it) now lives under People & Access. corpit 302s its old URLs here.
@app.route("/access-control")
@login_required
def access_control_page():
    return redirect("/console#iam/access")


@app.route("/operations")
@login_required
def operations_page():
    """Stable launch URL for the integrated Server Health experience.

    Unlike a bare URL fragment, this path survives the shared sign-in round
    trip.  Old bookmarks and the CorpIT hub can land here, authenticate if
    needed, and then enter the server resource register in the workspace.
    """
    return redirect("/console#resources/server")


@app.route("/gal")
@login_required
def gal_page():
    """Retired as a page - Directory Sync is a section of the console, which
    collects the same status itself. Redirecting rather than collecting again
    keeps the node call off this path."""
    return redirect("/console#directory")


@app.route("/gal/sync", methods=["POST"])
@requires("directory.sync")
def gal_sync():
    check_csrf()
    if _gal_kick_sync():
        audit("gal-sync", "manual run from console")
        flash("Sync started - this page refreshes itself while it runs.", "ok")
    else:
        flash("A sync is already running - hold on.", "error")
    return redirect(url_for("gal_page"))


@app.route("/gal/lists", methods=["POST"])
@requires("directory.manage")
def gal_list_create():
    check_csrf()
    name = (request.form.get("name") or "").strip()[:60]
    lid = _gal_slug(name)
    if not lid:
        flash("Give the list a name.", "error")
        return redirect(url_for("gal_page"))

    lists = _gal_lists_load()
    if any(l["id"] == lid for l in lists):
        flash(f'A list with id "{lid}" already exists.', "error")
        return redirect(url_for("gal_page"))

    stype = request.form.get("source_type", "all")
    source = {"type": "all"}
    if stype == "group":
        gq = (request.form.get("source_group_id") or request.form.get("source_group") or "").strip()[:120]
        if not re.fullmatch(r"[\w\s@.\-']{1,120}", gq):
            flash("Group name contains characters I will not pass along.", "error")
            return redirect(url_for("gal_page"))
        try:
            out = subprocess.run(
                ["/usr/bin/node", "gal-resolve-group.js", gq],
                cwd=GAL_DIR, capture_output=True, text=True, timeout=60,
            )
            res = json.loads(out.stdout.strip() or "{}")
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            res = {"ok": False, "error": "group lookup failed"}
        if not res.get("ok"):
            flash("Group lookup: %s" % res.get("error", "failed"), "error")
            return redirect(url_for("gal_page"))
        source = {"type": "group", "group": res["id"]}
        flash('Source group resolved: %s' % res["name"], "ok")
    elif stype == "upns":
        upns = _gal_extract_emails(request.form.get("source_upns", ""))
        if not upns:
            flash("Hand-picked source chosen but no addresses given.", "error")
            return redirect(url_for("gal_page"))
        source = {"type": "upns", "upns": upns}

    recipients = _gal_form_emails()
    lists.append({
        "id": lid, "name": name,
        "category": (request.form.get("category") or name).strip()[:60] or name,
        "source": source, "recipients": recipients, "enabled": True,
    })
    _gal_lists_save(lists)
    audit("gal-list-create", "%s source=%s recipients=%d" % (lid, source["type"], len(recipients)))

    if recipients:
        added, already, failed = _gal_fence_add(recipients)
        if added:
            flash("Fence: added %s" % ", ".join(added), "ok")
        for email, why in failed[:5]:
            flash("Fence add failed for %s - %s" % (email, why), "error")

    flash(f'List "{name}" created.', "ok")
    if recipients and _gal_kick_sync():
        flash("Sync started for the new list.", "ok")
    return redirect(url_for("gal_page"))


@app.route("/gal/lists/<lid>/delete", methods=["POST"])
@requires("directory.manage")
def gal_list_delete(lid):
    check_csrf()
    lists = _gal_lists_load()
    if len(lists) == 1:
        flash("Refusing to delete the last list - disable it instead.", "error")
        return redirect(url_for("gal_page"))
    keep = [l for l in lists if l["id"] != lid]
    if len(keep) == len(lists):
        abort(404)
    _gal_lists_save(keep)
    audit("gal-list-delete", lid)
    flash(f'List "{lid}" deleted. Its contacts are removed from mailboxes on the next sync '
          "(a big list may trip the delete safety guard - the run log will say so).", "ok")
    return redirect(url_for("gal_page"))


@app.route("/gal/lists/<lid>/toggle", methods=["POST"])
@requires("directory.manage")
def gal_list_toggle(lid):
    check_csrf()
    lists = _gal_lists_load()
    for l in lists:
        if l["id"] == lid:
            l["enabled"] = not l.get("enabled", True)
            _gal_lists_save(lists)
            audit("gal-list-toggle", "%s -> %s" % (lid, l["enabled"]))
            flash(f'List "{lid}" {"enabled" if l["enabled"] else "disabled - its cards are cleaned up on the next sync"}.', "ok")
            return redirect(url_for("gal_page"))
    abort(404)


@app.route("/gal/recipients", methods=["POST"])
@requires("directory.manage")
def gal_recipients_add():
    check_csrf()
    lid = request.form.get("list", "")
    emails = _gal_form_emails()
    if not emails:
        flash("No email addresses found in the input.", "error")
        return redirect(url_for("gal_page"))
    if len(emails) > GAL_ADD_MAX:
        flash(f"{len(emails)} addresses is over the {GAL_ADD_MAX} per-batch cap - split it up.", "error")
        return redirect(url_for("gal_page"))

    lists = _gal_lists_load()
    target = next((l for l in lists if l["id"] == lid), None)
    if not target:
        flash("Pick a list.", "error")
        return redirect(url_for("gal_page"))

    existing = {r.lower() for r in target["recipients"]}
    new = [e for e in emails if e not in existing]
    target["recipients"].extend(new)
    _gal_lists_save(lists)
    audit("gal-recipients-add", "%s +%d : %s" % (lid, len(new), ",".join(new)[:400]))

    if new:
        flash('Added %d to "%s": %s' % (len(new), target["name"], ", ".join(new)), "ok")
    if len(new) < len(emails):
        flash("%d were already on the list." % (len(emails) - len(new)), "ok")

    added, already, failed = _gal_fence_add(new)
    for email, why in failed[:5]:
        flash("Fence add failed for %s - %s (they will show as error until fenced)" % (email, why), "error")

    if new and _gal_kick_sync():
        flash("Sync started for the new members.", "ok")
    return redirect(url_for("gal_page"))


@app.route("/gal/lists/<lid>/mobile-rollout", methods=["POST"])
@requires("directory.manage")
def gal_mobile_rollout(lid):
    """Make one all-directory list serve every currently published mobile user.

    This is the console's one-click rollout.  It enables the existing
    mobile-only publishing policy, replaces the target list's recipient set
    with the same mobile-enabled roster, ensures those mailboxes are inside
    the Exchange application-access fence, audits the change, and starts the
    sync.  Repeating it is safe: it simply reconciles drift and runs again.
    """
    check_csrf()
    proof = _gal_mobile_rollout_facts()
    recipients = proof["recipients"]
    if not proof["available"]:
        flash(proof["reason"], "error")
        return redirect(url_for("gal_page"))
    if not _gal_add_ready():
        flash("The Exchange fence helper is not configured, so the mobile rollout was not changed. "
              "Configure the fence helper first so every recipient can be written safely.", "error")
        return redirect(url_for("gal_page"))

    try:
        lists = _gal_lists_load()
    except (OSError, json.JSONDecodeError) as exc:
        flash("The directory list file cannot be read (%s). Nothing changed." % str(exc)[:160], "error")
        return redirect(url_for("gal_page"))
    target = next((item for item in lists if item.get("id") == lid), None)
    if not target:
        abort(404)
    if (target.get("source") or {}).get("type") != "all":
        flash("Mobile rollout is available only for a list that publishes everyone. "
              "This list has a narrower source, so nothing changed.", "error")
        return redirect(url_for("gal_page"))

    try:
        exclusions = _gal_exclusions_load()
    except ValueError as exc:
        flash("The exclusion list on disk is damaged (%s). Nothing changed." % exc, "error")
        return redirect(url_for("gal_page"))

    existing = {str(upn).strip().lower() for upn in target.get("recipients") or [] if upn}
    wanted = set(recipients)
    added = wanted - existing
    removed = existing - wanted
    policy = _gal_policy(exclusions)
    policy_changed = not policy["requireMobile"]

    # Fence first and fail closed.  An exact-recipient rollout is unsafe if
    # even one mailbox is outside the Graph application-access boundary.
    fence_added, fence_already, fence_failed = _gal_fence_add(recipients)
    if fence_failed or len(fence_added) + len(fence_already) != len(recipients):
        audit("gal-mobile-rollout-blocked", "%s recipients=%d fence=%d/%d/%d" % (
            lid, len(recipients), len(fence_added), len(fence_already), len(fence_failed)))
        flash("Mobile rollout stopped before changing the list: the Exchange fence did not confirm "
              "all %d recipients (%d failed or missing). Review the fence helper, then retry." %
              (len(recipients), max(len(fence_failed),
                                    len(recipients) - len(fence_added) - len(fence_already))), "error")
        return redirect(url_for("gal_page"))

    lists_before = json.loads(json.dumps(lists))
    exclusions_before = json.loads(json.dumps(exclusions))
    try:
        if added or removed:
            target["recipients"] = recipients
            _gal_lists_save(lists)
        if policy_changed:
            policy["requireMobile"] = True
            exclusions["policy"] = policy
            exclusions["policyChanged"] = {"by": session.get("user", "-"), "at": now_iso()}
            _gal_exclusions_save(exclusions)
    except OSError as exc:
        rollback_failed = []
        try:
            _gal_lists_save(lists_before)
        except OSError as rollback_exc:
            rollback_failed.append("lists: %s" % str(rollback_exc)[:80])
        try:
            _gal_exclusions_save(exclusions_before)
        except OSError as rollback_exc:
            rollback_failed.append("policy: %s" % str(rollback_exc)[:80])
        audit("gal-mobile-rollout-blocked", "%s config-write=%s rollback=%s" %
              (lid, str(exc)[:120], "; ".join(rollback_failed) or "restored"))
        flash("The mobile rollout could not save its configuration. %s" %
              ("Rollback also needs attention: " + "; ".join(rollback_failed)
               if rollback_failed else "The prior list and policy were restored; nothing will sync."), "error")
        return redirect(url_for("gal_page"))

    audit("gal-mobile-rollout", "%s recipients=%d +%d -%d policy=%s fence=%d/%d/%d" % (
        lid, len(recipients), len(added), len(removed),
        "enabled" if policy_changed else "kept", len(fence_added), len(fence_already), len(fence_failed)))

    if added or removed or policy_changed:
        flash('Mobile rollout configured for "%s": %d mobile users publish to %d mobile mailboxes '
              '(%d added, %d removed).' %
              (target.get("name") or lid, len(recipients), len(recipients), len(added), len(removed)), "ok")
    else:
        flash('"%s" already matches all %d mobile users. The fence and sync are being rechecked.' %
              (target.get("name") or lid, len(recipients)), "ok")

    if _gal_kick_sync():
        flash("Sync started. The first all-mobile rollout can take several minutes.", "ok")
    else:
        flash("A sync is already running; the reconciled mobile rollout is picked up by the next one.", "ok")
    return redirect(url_for("gal_page"))


@app.route("/gal/recipients/remove", methods=["POST"])
@requires("directory.manage")
def gal_recipients_remove():
    check_csrf()
    lid = request.form.get("list", "")
    upn = (request.form.get("upn") or "").strip().lower()
    lists = _gal_lists_load()
    for l in lists:
        if l["id"] == lid:
            before = len(l["recipients"])
            l["recipients"] = [r for r in l["recipients"] if r.lower() != upn]
            if len(l["recipients"]) != before:
                _gal_lists_save(lists)
                audit("gal-recipients-remove", "%s -%s" % (lid, upn))
                flash(f'Removed {upn} from "{l["name"]}". Their cards from this list are '
                      "cleaned from their mailbox on the next sync.", "ok")
            return redirect(url_for("gal_page"))
    abort(404)


@app.route("/gal/roster")
@login_required
def gal_roster():
    """Who the last sync published, who it did not and why, with the current
    rules laid over the top so a rule added a moment ago shows at once instead
    of after the next run. Gzipped by hand: nginx does not compress JSON here
    and the snapshot is ~500 KB for 1,800 accounts."""
    snapshot = _gal_roster_load()
    try:
        doc = _gal_exclusions_load()
        rules, rules_error, policy = doc["rules"], None, _gal_policy(doc)
    except ValueError as exc:
        rules, rules_error, policy = [], str(exc), None
    by_addr = {}
    for r in rules:
        for k in (r.get("upn"), r.get("id")):
            if k:
                by_addr[str(k).lower()] = r
    people = []
    seen = set()
    for p in (snapshot or {}).get("people") or []:
        rule = (by_addr.get(str(p.get("id") or "").lower())
                or by_addr.get(str(p.get("upn") or "").lower())
                or by_addr.get(str(p.get("mail") or "").lower()))
        row = dict(p)
        if rule:
            seen.add(id(rule))
            row["rule"] = {k: rule.get(k) for k in ("upn", "mode", "reason", "by", "at")}
            # applied = the snapshot already reflects this mode; else pending
            row["ruleState"] = "applied" if p.get("exclusion") == rule.get("mode") else "pending"
        people.append(row)
    # Rules that matched nobody in the snapshot still need to be visible - a
    # typo'd address is exactly the rule that must not vanish from view.
    for r in rules:
        if id(r) in seen:
            continue
        people.append({
            "id": r.get("id"), "upn": r.get("upn"), "mail": None, "name": r.get("name") or r.get("upn"),
            "published": False, "reason": "no account with this address in the last sync",
            "exclusion": None, "unmatched": True,
            "rule": {k: r.get(k) for k in ("upn", "mode", "reason", "by", "at")},
            "ruleState": "pending" if not snapshot or (r.get("at") or "") > (snapshot.get("generatedAt") or "") else "unmatched",
        })
    body = json.dumps({
        "ok": True,
        "generatedAt": (snapshot or {}).get("generatedAt"),
        "mode": (snapshot or {}).get("mode"),
        "fetched": (snapshot or {}).get("fetched"),
        "published": (snapshot or {}).get("published"),
        "rules": len(rules), "rulesError": rules_error,
        "modes": GAL_EXCLUDE_MODES,
        "policy": policy, "snapshotPolicy": (snapshot or {}).get("policy") or {},
        "policyReason": GAL_POLICY_REASON,
        "people": people,
    }).encode("utf-8")
    resp = app.response_class(body, mimetype="application/json")
    if "gzip" in (request.headers.get("Accept-Encoding") or ""):
        import gzip
        resp.set_data(gzip.compress(body, 6))
        resp.headers["Content-Encoding"] = "gzip"
        resp.headers["Vary"] = "Accept-Encoding"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/gal/exclusions", methods=["POST"])
@requires("directory.manage")
def gal_exclusions_add():
    """Add or change do-not-publish rules. One rule per person; a second Save
    for the same address replaces the mode and reason. Kicks a sync so the
    change reaches phones now rather than at 04:50."""
    check_csrf()
    emails = _gal_extract_emails(request.form.get("emails", ""))
    mode = (request.form.get("mode") or "").strip()
    reason = re.sub(r"[\x00-\x1f\x7f]", " ", request.form.get("reason") or "").strip()[:GAL_REASON_MAX]
    if not emails:
        flash("No email addresses found in the input.", "error")
        return redirect(url_for("gal_page"))
    if len(emails) > GAL_EXCLUDE_MAX:
        flash(f"{len(emails)} addresses is over the {GAL_EXCLUDE_MAX} per-batch cap - split it up.", "error")
        return redirect(url_for("gal_page"))
    if mode not in GAL_EXCLUDE_MODES:
        flash("Pick what to hold back.", "error")
        return redirect(url_for("gal_page"))
    try:
        doc = _gal_exclusions_load()
    except ValueError as exc:
        flash("The exclusion list on disk is damaged (%s) - nothing changed. Fix the file before adding rules." % exc, "error")
        return redirect(url_for("gal_page"))

    idx = _gal_roster_index(_gal_roster_load())
    by_upn = {r["upn"].lower(): r for r in doc["rules"] if r.get("upn")}
    now, who = now_iso(), session.get("user", "-")
    added, changed, unknown = [], [], []
    for e in emails:
        row = idx.get(e)
        if not row:
            unknown.append(e)
        rule = by_upn.get(e)
        if rule:
            if rule.get("mode") == mode and (rule.get("reason") or "") == reason:
                continue
            rule.update(mode=mode, reason=reason, by=who, at=now)
            changed.append(e)
        else:
            rule = {"upn": e, "mode": mode, "reason": reason, "by": who, "at": now}
            if row:
                rule["id"] = row.get("id")
                rule["name"] = row.get("name")
            doc["rules"].append(rule)
            by_upn[e] = rule
            added.append(e)
    if not added and not changed:
        flash("Those rules are already in place - nothing changed.", "ok")
        return redirect(url_for("gal_page"))
    _gal_exclusions_save(doc)
    audit("gal-exclude", "%s +%d ~%d : %s" % (mode, len(added), len(changed), ",".join(added + changed)[:400]))

    what = GAL_EXCLUDE_MODES[mode]
    if added:
        flash("%d now %s: %s" % (len(added), what, ", ".join(added)), "ok")
    if changed:
        flash("%d changed to %s: %s" % (len(changed), what, ", ".join(changed)), "ok")
    for e in unknown[:5]:
        flash("%s was not in the last sync's roster - the rule is saved and will apply if they ever are, "
              "but check the address for a typo." % e, "error")
    if _gal_kick_sync():
        flash("Sync started - the change reaches every recipient's phone within a few minutes.", "ok")
    else:
        flash("A sync is already running; the change is picked up by the next one.", "ok")
    return redirect(url_for("gal_page"))


@app.route("/gal/exclusions/remove", methods=["POST"])
@requires("directory.manage")
def gal_exclusions_remove():
    check_csrf()
    upn = (request.form.get("upn") or "").strip().lower()
    try:
        doc = _gal_exclusions_load()
    except ValueError as exc:
        flash("The exclusion list on disk is damaged (%s) - nothing changed." % exc, "error")
        return redirect(url_for("gal_page"))
    keep = [r for r in doc["rules"] if (r.get("upn") or "").lower() != upn]
    if len(keep) == len(doc["rules"]):
        abort(404)
    doc["rules"] = keep
    _gal_exclusions_save(doc)
    audit("gal-exclude-remove", upn)
    flash("%s is published normally again from the next sync." % upn, "ok")
    if _gal_kick_sync():
        flash("Sync started.", "ok")
    return redirect(url_for("gal_page"))


@app.route("/gal/policy", methods=["POST"])
@requires("directory.manage")
def gal_policy_set():
    """Flip a directory-wide switch. One today: only publish people who have a
    mobile number. It is a policy the sync re-judges every run, not 485 rules -
    a number added in AD brings the person back with nobody touching this page.
    Same file as the rules, same overlay: nothing in AD, Entra or Exchange moves."""
    check_csrf()
    key = (request.form.get("key") or "").strip()
    if key not in GAL_POLICY_KEYS:
        abort(400)
    want = request.form.get("value") == "1"
    try:
        doc = _gal_exclusions_load()
    except ValueError as exc:
        flash("The exclusion list on disk is damaged (%s) - nothing changed." % exc, "error")
        return redirect(url_for("gal_page"))
    policy = _gal_policy(doc)
    if policy[key] == want:
        flash("That is already %s - nothing changed." % ("on" if want else "off"), "ok")
        return redirect(url_for("gal_page"))
    policy[key] = want
    doc["policy"] = policy
    doc["policyChanged"] = {"by": session.get("user", "-"), "at": now_iso()}
    _gal_exclusions_save(doc)
    audit("gal-policy", "%s=%s" % (key, "on" if want else "off"))
    flash(GAL_POLICY_FLASH[key][0 if want else 1], "ok")
    if _gal_kick_sync():
        flash("Sync started - phones update within a few minutes.", "ok")
    else:
        flash("A sync is already running; the change is picked up by the next one.", "ok")
    return redirect(url_for("gal_page"))


# ---- Directory Sync: group directory for the type-ahead picker --------------
# Dumps all tenant groups via Graph once, caches ~10 min in-process; the page
# filters client-side so typing costs nothing.
_gal_groups_cache = {"ts": 0.0, "data": None}


@app.route("/gal/groups")
@login_required
def gal_groups():
    import time
    now = time.time()
    if _gal_groups_cache["data"] is None or now - _gal_groups_cache["ts"] > 600:
        try:
            out = subprocess.run(
                ["/usr/bin/node", "gal-groups.js"],
                cwd=GAL_DIR, capture_output=True, text=True, timeout=120,
            )
            data = json.loads(out.stdout.strip() or "{}")
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            data = {"ok": False, "error": "group directory fetch failed"}
        if data.get("ok"):
            _gal_groups_cache["data"] = data
            _gal_groups_cache["ts"] = now
        else:
            return app.response_class(json.dumps(data), mimetype="application/json"), 502
    return app.response_class(json.dumps(_gal_groups_cache["data"]), mimetype="application/json")

# ---------------------------------------------------------------------------
# CORPIT admin console. Static prototype for now, served behind this app's
# login so the estate detail it shows is not readable without signing in.
# ---------------------------------------------------------------------------
CONSOLE_PATH = os.path.join(APP_DIR, "private", "console.html")


CONSOLE_JS_PATH = os.path.join(APP_DIR, "private", "console.js")


@app.route("/console.js")
@login_required
def console_js():
    # Served from here rather than /static so the console's JS sits behind the
    # same login as the page - it carries hostnames, findings and people.
    try:
        with open(CONSOLE_JS_PATH, encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        abort(404)
    return Response(body, mimetype="text/javascript")


def _console():
    """Render the console. Every section that has a backend is filled from live
    state read at this moment; sections with no backend say so."""
    ctx = console_data.build(sys.modules[__name__])
    access_governance.build(sys.modules[__name__], ctx)
    _build_access_workspace_context(ctx)
    # The change ledger reuses that context rather than re-reading the vhosts and
    # the access policy - a second helper call would double the page's cost for
    # information it already has.
    ctx.update(change_control.build(sys.modules[__name__], ctx))
    # The CorpIT home page section: sections, links, icon library, publish state.
    landing.build(sys.modules[__name__], ctx)
    return render_template("console.html", **ctx)


@app.route("/health")
@login_required
def health_page():
    """Canonical launch path: preserve the requested section through sign-in."""
    section = request.args.get("section", "status")
    if section not in {"status", "settings", "journeys"}:
        section = "status"
    return redirect("/console#health/" + section)


@app.route("/console")
@login_required
def console_page():
    return _console()


def _build_access_workspace_context(ctx=None):
    """Add the read-only ZPA, Entra and sign-in evidence used by access review."""
    snapshot_path = os.path.join(APP_DIR, "private", "access-governance-site-snapshot.json")
    try:
        with open(snapshot_path, encoding="utf-8") as fh:
            lab_snapshot = json.load(fh)
    except (OSError, ValueError, TypeError):
        lab_snapshot = {}
    # ACCESS-EVIDENCE (2026-10-07): the snapshot is written by the read-only
    # collector on corpit A (collect-access-evidence.js). Say how old it is;
    # an old file must never read as current.
    captured_raw = str(lab_snapshot.get("captured_at") or "")
    captured_age_h = None
    try:
        captured_dt = datetime.strptime(captured_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        captured_age_h = (datetime.now(timezone.utc) - captured_dt).total_seconds() / 3600.0
    except ValueError:
        pass
    activity = lab_snapshot.get("sign_in_activity") or {}
    evidence = {
        "captured_at": captured_raw.replace("T", " ").replace("Z", " UTC") if captured_raw else "unknown",
        "age_hours": captured_age_h,
        "stale": captured_age_h is None or captured_age_h > 24,
        "live": bool(lab_snapshot.get("zpa_detail")),
        "errors": lab_snapshot.get("errors") or [],
        "entra_source": lab_snapshot.get("entra_apps_source") or "audit snapshot",
        "signin_window": activity.get("hub_window") or "",
        "signin_since": activity.get("hub_since") or "",
    }
    policy = site_policy()
    policy_source = "Live SubAdmin policy"
    if not (policy.get("sites") or {}):
        if lab_snapshot.get("sites"):
            policy = lab_snapshot
            policy_source = "%s · captured %s" % (
                policy.get("source") or "Policy snapshot",
                policy.get("captured_at") or "unknown",
            )
        else:
            policy = {"sites": {}}
            policy_source = "Policy unavailable"
    def _lab_site_order(item):
        fqdn = item[0].lower()
        return (0 if "corpit." in fqdn else 2 if "accessportal." in fqdn else 1, fqdn)
    policy_rows = sorted((policy.get("sites") or {}).items(), key=_lab_site_order)
    if ctx is None:
        ctx = {}
    # The console context already carries console_data's policy, policy_rows
    # (each rule with sub_id for the Sites section), user_display and role, and
    # change_control.build reads policy_rows after this runs - never overwrite
    # them. Only the standalone lab route starts from an empty context.
    ctx.setdefault("policy", permission_policy())
    ctx.setdefault("policy_rows", policy_rows)
    if "access_registry" not in ctx:
        access_governance.build(sys.modules[__name__], ctx)
    ctx.setdefault("user_display", (session.get("sso") or {}).get("name") or session.get("user", ""))
    ctx.setdefault("role", (session.get("sso") or {}).get("role") or "signed in")
    # Where the console knows the SubAdmin record for a site, the review pane can
    # jump to its settings (the only place an admission rule is changed).
    console_sub_ids = {
        str(fqdn).lower(): rule.get("sub_id")
        for fqdn, rule in (ctx.get("policy_rows") or []) if isinstance(rule, dict)
    }
    entra_apps = lab_snapshot.get("entra_apps") or []
    entra_by_key = {app_row.get("key"): app_row for app_row in entra_apps}
    entra_by_group = {}
    for app_row in entra_apps:
        for group_name in app_row.get("groups") or []:
            entra_by_group.setdefault(group_name.lower(), []).append({
                "name": app_row.get("name") or "Unknown enterprise app",
                "app_id": app_row.get("app_id") or "",
                "assignment_required": bool(app_row.get("assignment_required")),
            })
    ctx["access_lab_rows"] = [
        {
            "name": row["name"], "description": row.get("description") or "",
            "owner": row.get("owner") or "", "member_count": row.get("member_count"),
            "scope": row.get("scope") or "unknown", "changed": row.get("changed") or "unknown",
            "role": row.get("role") or "", "capabilities": row.get("capabilities") or [],
            "sites": row.get("sites") or [], "level": row.get("level") or "review",
            "issues": row.get("issues") or [], "missing": bool(row.get("missing")),
            "referenced": bool(row.get("referenced")),
            "entra_apps": entra_by_group.get(row["name"].lower(), []),
        }
        for row in ctx["access_registry"]
    ]
    zpa_segments = lab_snapshot.get("zpa_segments") or policy.get("zpa_segments") or {}
    zpa_detail = lab_snapshot.get("zpa_detail") or {}
    # Access rules that decide each site's exact segment, first match first (collector).
    zpa_policy = lab_snapshot.get("zpa_policy") or {}
    site_people = lab_snapshot.get("site_people") or {}
    pending_changes = lab_snapshot.get("pending_changes") or []
    site_sso_apps = lab_snapshot.get("site_sso_apps") or {}
    registry_by_name = {
        row["name"].lower(): row for row in ctx["access_registry"] if row.get("name")
    }

    def _approver_groups():
        rows = []
        for mapping in lab_snapshot.get("access_portal_approver_groups") or []:
            directory_row = registry_by_name.get(str(mapping.get("group") or "").lower())
            rows.append({
                "role": mapping.get("role") or "",
                "label": mapping.get("label") or mapping.get("role") or "Approver",
                "group": mapping.get("group") or "",
                "member_count": directory_row.get("member_count") if directory_row else mapping.get("snapshot_member_count"),
                "owner": directory_row.get("owner") if directory_row else "",
                "directory_status": "Live AD" if directory_row and not directory_row.get("missing") else "Audit snapshot",
                "approval_steps": mapping.get("approval_steps") or [],
                "page_access": mapping.get("page_access") or "Read",
                "note": mapping.get("note") or "",
            })
        return rows

    access_portal_approver_groups = _approver_groups()

    def _production_fqdn(fqdn):
        return fqdn[4:] if fqdn.lower().startswith("dev-") else fqdn

    def _site_apps(fqdn, groups):
        group_keys = {str(group).lower() for group in groups}
        rows = []
        for app_key in site_sso_apps.get(_production_fqdn(fqdn).lower(), []):
            app_row = entra_by_key.get(app_key) or {}
            assigned = app_row.get("groups") or []
            rows.append({
                "name": app_row.get("name") or app_key,
                "app_id": app_row.get("app_id") or "",
                "assignment_required": bool(app_row.get("assignment_required")),
                "assigned_group_count": len(assigned),
                "assigned_groups": assigned,
                "matched_groups": [group for group in assigned if group.lower() in group_keys],
                "direct_users": int(app_row.get("direct_users") or 0),
            })
        return rows

    ctx["access_lab_sites"] = [
        {
            "fqdn": fqdn,
            "sub_id": console_sub_ids.get(fqdn.lower()),
            "label": rule.get("label") or fqdn.split(".", 1)[0].replace("-", " ").title(),
            "mode": rule.get("mode") or "superadmin",
            "groups": rule.get("groups") or [],
            "inherited": bool(rule.get("inherited")),
            "zpa_segment": zpa_segments.get(fqdn) or zpa_segments.get(_production_fqdn(fqdn)) or "",
            "separate_governance": "accessportal." in fqdn.lower(),
            "sso_apps": _site_apps(fqdn, rule.get("groups") or []),
            "approver_groups": access_portal_approver_groups if "accessportal." in fqdn.lower() else [],
            "approver_role_gaps": (lab_snapshot.get("access_portal_role_gaps") or []) if "accessportal." in fqdn.lower() else [],
            "approver_url": ("https://%s/approver.html" % fqdn) if "accessportal." in fqdn.lower() else "",
            "zpa_matches": zpa_detail.get(_production_fqdn(fqdn).lower()) or [],
            "zpa_policy": zpa_policy.get(_production_fqdn(fqdn).lower()) or [],
            "people": site_people.get(_production_fqdn(fqdn).lower()),
            "pending": [c for c in pending_changes if str(c.get("site") or "").lower() == _production_fqdn(fqdn).lower()],
        }
        for fqdn, rule in policy_rows
    ]
    for site in ctx["access_lab_sites"]:
        cleanup_items = []
        if site["approver_role_gaps"]:
            cleanup_items.append({
                "id": "approver-roles", "label": "Resolve approver role mappings",
                "reason": "%s Access Portal roles are not fully backed by the current AD role and policy mapping." % len(site["approver_role_gaps"]),
                "target": "portal-approvers", "action": "Review approver groups",
            })
        unowned = [
            name for name in site["groups"]
            if registry_by_name.get(name.lower()) and not registry_by_name[name.lower()].get("owner")
        ]
        if unowned:
            cleanup_items.append({
                "id": "group-owners", "label": "Assign accountable group owners",
                "reason": "%s allowed AD group%s %s no managedBy owner." % (
                    len(unowned), "" if len(unowned) == 1 else "s", "has" if len(unowned) == 1 else "have"
                ),
                "target": "allow-list-title", "action": "Review AD groups",
            })
        if not site["zpa_segment"]:
            cleanup_items.append({
                "id": "zpa-segment", "label": "Record the ZPA segment",
                "reason": "The hostname has no recorded ZPA segment mapping in the available evidence.",
                "target": "site-route-zpa", "action": "Review access path",
            })
        people = site["people"] or {}
        unused = [p for p in people.get("allowed_not_seen") or [] if p.get("via") != "superadmin"]
        if site["mode"] == "groups" and unused:
            cleanup_items.append({
                "id": "unused-access", "label": "Review people who hold access but have not signed in",
                "reason": "%s %s through an allow-list group but %s not signed in to this site %s." % (
                    len(unused), "person is admitted" if len(unused) == 1 else "people are admitted",
                    "has" if len(unused) == 1 else "have",
                    ("since " + evidence["signin_since"]) if evidence["signin_since"] else "in the available log"),
                "target": "site-people-title", "action": "Review sign-in evidence",
            })
        outside = [p for p in people.get("signed_in") or [] if p.get("via") == "not in allow list"]
        if outside:
            cleanup_items.append({
                "id": "outside-allow-list", "label": "Sign-ins from people outside the allow list",
                "reason": "%s %s signed in here without a qualifying group; the gate refuses them, so they may be expecting access." % (
                    len(outside), "person" if len(outside) == 1 else "people"),
                "target": "site-people-title", "action": "Review sign-in evidence",
            })
        if not site["sso_apps"]:
            cleanup_items.append({
                "id": "entra-app", "label": "Confirm the sign-in application",
                "reason": "No Entra enterprise application is mapped to this site in the collected evidence.",
                "target": "entra-apps-title", "action": "Review Entra apps",
            })
        site["cleanup_items"] = cleanup_items
        site["cleanup_count"] = len(cleanup_items)
    recommended_site = max(
        enumerate(ctx["access_lab_sites"]),
        key=lambda item: (item[1]["cleanup_count"], bool(item[1]["approver_role_gaps"])),
        default=(0, {}),
    )
    ctx.update(
        access_lab_policy_source=policy_source,
        access_lab_evidence=evidence,
        access_lab_site_summary={
            "sites": len(ctx["access_lab_sites"]),
            "group_rules": sum(1 for row in ctx["access_lab_sites"] if row["mode"] == "groups"),
            "zpa_unmapped": sum(1 for row in ctx["access_lab_sites"] if not row["zpa_segment"]),
            "attention_sites": sum(1 for row in ctx["access_lab_sites"] if row["cleanup_count"]),
            "cleanup_items": sum(row["cleanup_count"] for row in ctx["access_lab_sites"]),
            "role_gaps": sum(len(row["approver_role_gaps"]) for row in ctx["access_lab_sites"]),
        },
        access_lab_recommended={"index": recommended_site[0], **recommended_site[1]},
    )
    return ctx


@app.route("/access-governance-lab")
@login_required
def access_governance_lab():
    """Compatibility preview for the access workspace now shared by the console."""
    ctx = _build_access_workspace_context()
    return render_template("access_governance_lab.html", **ctx)


ACCESS_GOVERNANCE_LAB_JS = os.path.join(APP_DIR, "private", "access-governance-lab.js")


@app.route("/access-governance-lab.js")
@login_required
def access_governance_lab_js():
    try:
        with open(ACCESS_GOVERNANCE_LAB_JS, encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        abort(404)
    return Response(body, mimetype="text/javascript")


# ===========================================================================
# CORPIT-CONSOLE-CHANGE-CONTROL
#
# The change ledger's three writes. Reads live in change_control.py; these are
# the only things that move a record, and each one is audited by reference.
#
# The preflight gate is enforced inside change_control.request_approval, not
# here and not in the template: the disabled button on the page is a courtesy,
# the check on the way in is the control.
# ===========================================================================
def _change_back():
    back = request.form.get("_back", "")
    return redirect(back if _CONSOLE_BACK_RE.match(back or "") else "/console#change")


@app.route("/change/<ref>/request", methods=["POST"])
@requires("change.request")
def change_request(ref):
    check_csrf()
    err = change_control.request_approval(sys.modules[__name__], ref,
                                          session.get("user", "-"))
    if err:
        audit("change-request-refused", "%s: %s" % (ref, err))
        flash(err, "error")
    else:
        audit("change-request", "%s sent for approval" % ref)
        flash("%s is out for approval. Nothing has been deployed." % ref, "ok")
    return _change_back()


@app.route("/change/<ref>/decide", methods=["POST"])
@requires("change.approve")
def change_decide(ref):
    check_csrf()
    decision = request.form.get("decision", "")
    slot = request.form.get("slot", "")
    err = change_control.record_decision(sys.modules[__name__], ref, slot,
                                         decision, session.get("user", "-"),
                                         request.form.get("note", ""))
    if err:
        audit("change-decision-refused", "%s/%s: %s" % (ref, slot, err))
        flash(err, "error")
    else:
        audit("change-decision", "%s: %s as %s" % (ref, decision, slot))
        flash("Recorded: %s %s as %s." % (ref, decision, slot), "ok")
    return _change_back()


@app.route("/change/<ref>/reopen", methods=["POST"])
@requires("change.request")
def change_reopen(ref):
    check_csrf()
    err = change_control.reopen(sys.modules[__name__], ref, session.get("user", "-"))
    if err:
        flash(err, "error")
    else:
        audit("change-reopen", "%s returned to preflight" % ref)
        flash("%s is back in preflight; recorded approvals were cleared." % ref, "ok")
    return _change_back()


# CORPIT-HUB-LANDING: the home-page routes live in landing.py and are attached
# here, after requires()/check_csrf()/audit() exist for them to use.
landing.register(sys.modules[__name__])

# Person-level diagnostics inherit the existing platform-owner gate.
import user_activity
user_activity.register(app, platform_owner_required, db, audit)

# Server updates (System > Updates): owner-gated, and live only where the root
# corpit-updates service has its socket (itam).
updates_panel.register(app, platform_owner_required, audit, check_csrf)
webwatch_panel.register(app, platform_owner_required, audit, check_csrf)
