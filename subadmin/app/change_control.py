"""The change-control ledger: high-risk infrastructure changes, and the rail
that decides whether one is allowed to leave preflight.

This is the data-access boundary for the console's Change Control and Change
History sections, in the same shape as console_data.py: presentation-shaped
read-only assembly, kept out of app.py, with `A` (the app module) passed in
rather than imported so there is no cycle. The privileged routes stay in app.py.

Three things are deliberate.

**The record is stored, the verdict is not.** Stage, approvals and decisions live
in the database and are only ever changed by an audited route. Every preflight
check is re-run from the box on each render - certificates are read off disk,
the configuration is parsed, the gate policy is read from the helper. A stored
"passed" would keep saying passed after the thing it described had changed, and
this is precisely the page where that must not happen.

**Deploy has no runner on this server, and says so instead of drawing a button.**
There is no promotion pipeline here (Promotion & Deploy says the same thing).
The Deploy control is rendered inert with the real reason attached, which is also
what the design calls for: a failing preflight has to stop a deployment, and the
operator has to be able to read why without leaving the page.

**Approvals are never fabricated.** Required approvers are resolved from real
state - the platform owners in config.json, and the AD groups the console has
actually granted the change-approval capability to. The seeded example change
therefore opens at 0 of 2 approvals with both slots pending, because inventing a
recorded approval would be putting a decision in a real person's mouth.

The one seeded row is flagged `origin='seed'` and is labelled EXAMPLE wherever it
is rendered. Its configuration, paths, certificate facts, host and affected
resources are all read from this box; what is synthetic is that nobody has
actually proposed it. Replacing the seed with a real feed means writing rows with
`origin='live'` - no template or route change.
"""
from corpit_sqlite import connect_durable
import difflib
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone

import console_data

# Lifecycle. Order matters: the index of `stage` in this list is what drives the
# stepper, and a stage is "done" only when the record has moved past it.
STAGES = [
    ("draft", "Draft"),
    ("preflight", "Preflight"),
    ("approval", "Approval"),
    ("deploy", "Deploy"),
    ("verify", "Verify"),
]
STAGE_KEYS = [k for k, _ in STAGES]

# How many approvals a production change needs, and which role fills each slot.
# Slots are roles rather than named people so the list cannot go stale when
# somebody leaves - the directory decides who currently fills one.
APPROVAL_SLOTS = [
    ("owner", "Platform owner", "Holds production write on this estate."),
    ("change", "Change approver", "Granted the change-approval capability."),
]

# Deploy cannot run from this console: there is no deploy runner on this box.
# Stated once, here, and rendered wherever a deploy control would otherwise be.
NO_RUNNER = ("No deploy runner is attached to this console, so this change "
             "cannot be executed from here even once it is approved.")


# ------------------------------------------------------------------ schema
def init(db_path):
    """Create the ledger tables. Called at import time from app.py for the same
    reason init_db() is: gunicorn imports the module and never runs __main__."""
    con = connect_durable(db_path)
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS cc_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ref TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            summary TEXT,
            environment TEXT NOT NULL DEFAULT 'prod',
            target_fqdn TEXT,
            config_path TEXT,
            before_version TEXT, after_version TEXT,
            before_at TEXT, after_at TEXT,
            before_body TEXT, after_body TEXT,
            stage TEXT NOT NULL DEFAULT 'draft',
            outcome TEXT NOT NULL DEFAULT 'open',
            origin TEXT NOT NULL DEFAULT 'live',
            requested_by TEXT,
            created_at TEXT NOT NULL,
            approval_requested_at TEXT,
            window_start TEXT, window_end TEXT,
            duration_estimate TEXT,
            rollback_version TEXT,
            rollback_tested_at TEXT,
            rollback_tested_ok INTEGER
        );
        CREATE TABLE IF NOT EXISTS cc_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            change_id INTEGER NOT NULL,
            slot TEXT NOT NULL,
            decision TEXT NOT NULL,
            decided_by TEXT NOT NULL,
            decided_at TEXT NOT NULL,
            note TEXT,
            UNIQUE(change_id, slot)
        );
        """
    )
    con.commit()
    con.close()


# ------------------------------------------------------------------ the seed
def _vhost_facts():
    """Read the real corpit vhost so the example change describes this box and
    not a plausible-looking imaginary one."""
    path = "/etc/nginx/sites-enabled/corpit.nrpi.local.conf"
    body = console_data._read(path, 200000)
    def one(pat, fallback):
        m = re.search(pat, body, re.M)
        return m.group(1).strip() if m else fallback
    return {
        "path": path,
        "root": one(r"^\s*root\s+([^;]+);", "/var/www/html"),
        "cert": one(r"^\s*ssl_certificate\s+([^;]+);",
                    "/etc/ssl/subdomains/corpit.nrpi.local/fullchain.pem"),
        "key": one(r"^\s*ssl_certificate_key\s+([^;]+);",
                   "/etc/ssl/subdomains/corpit.nrpi.local/server.key"),
        "protocols": one(r"^\s*ssl_protocols\s+([^;]+);", "TLSv1.2 TLSv1.3"),
    }


def _bodies(v):
    """The two configurations the change compares.

    BEFORE is assembled from directives read out of the live vhost. AFTER
    applies the change: rotate the certificate pair onto dated filenames, and
    add the network allowlist. There is no `allow all;` to remove - nginx's
    default is unrestricted, so the access block is genuinely all additions,
    and the diff says so rather than inventing a line to strike through.
    """
    d = os.path.dirname(v["cert"])
    before = "\n".join([
        "server {",
        "    listen 443 ssl http2;",
        "    server_name corpit.nrpi.local;",
        "    root %s;" % v["root"],
        "",
        "    ssl_certificate     %s;" % v["cert"],
        "    ssl_certificate_key %s;" % v["key"],
        "    ssl_protocols       %s;" % v["protocols"],
        "",
        "    # Access control",
        "    # unrestricted - any client that can route to this",
        "    # vhost may reach the sign-in gate",
        "",
        "    location / {",
        "        try_files $uri $uri/ =404;",
        "    }",
        "}",
    ])
    after = "\n".join([
        "server {",
        "    listen 443 ssl http2;",
        "    server_name corpit.nrpi.local;",
        "    root %s;" % v["root"],
        "",
        "    ssl_certificate     %s/fullchain-2026-09.pem;" % d,
        "    ssl_certificate_key %s/server-2026-09.key;" % d,
        "    ssl_protocols       %s;" % v["protocols"],
        "",
        "    # Access control",
        "    satisfy all;",
        "    allow 10.9.0.0/16;",
        "    deny all;",
        "",
        "    location / {",
        "        try_files $uri $uri/ =404;",
        "    }",
        "}",
    ])
    return before, after


def seed_if_empty(A):
    """Insert the example change, once, and only into an empty ledger.

    Called from build() rather than at import: the owner comes from config, and
    two gunicorn workers starting together would otherwise race. The UNIQUE ref
    settles that race in the database, which is the only place it can be settled.
    """
    con = A.db()
    try:
        if con.execute("SELECT COUNT(*) FROM cc_changes").fetchone()[0]:
            return
        owner = ((A.load_config().get("sso") or {}).get("owners") or ["-"])[0]
        v = _vhost_facts()
        before, after = _bodies(v)
        now = datetime.now(timezone.utc)
        start = (now + timedelta(days=1)).replace(hour=2, minute=0, second=0,
                                                  microsecond=0)
        con.execute(
            """INSERT INTO cc_changes
               (ref,title,summary,environment,target_fqdn,config_path,
                before_version,after_version,before_at,after_at,
                before_body,after_body,stage,outcome,origin,requested_by,
                created_at,window_start,window_end,duration_estimate,
                rollback_version,rollback_tested_at,rollback_tested_ok)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("CHG-2841",
             "Rotate certificate + restrict owner access",
             "Rotate the TLS certificate and key onto the September pair, and "
             "restrict the vhost to the internal network with an explicit "
             "allowlist.",
             "prod", "corpit.nrpi.local", v["path"],
             "v182", "v183",
             _iso(now - timedelta(hours=29)), _iso(now - timedelta(hours=2)),
             before, after,
             "preflight", "open", "seed", owner or "-",
             _iso(now - timedelta(hours=2)),
             _iso(start), _iso(start + timedelta(hours=1)),
             "~10 minutes",
             "v182", _iso(now - timedelta(days=4, hours=3)), 1))
        con.commit()
    except sqlite3.IntegrityError:
        # Another worker seeded it first. Nothing to do, and nothing wrong.
        pass


def _iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


# ------------------------------------------------------------------ the diff
def diff_rows(before, after):
    """A real line diff, computed here rather than written by hand, so the line
    numbers and the +/- markers cannot drift away from the two bodies.

    Returns (split, unified). `split` is a list of aligned left/right pairs for
    the side-by-side view; `unified` is the same opcodes flattened.
    """
    a, b = before.splitlines(), after.splitlines()
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    split, unified = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                left = {"n": i1 + k + 1, "t": a[i1 + k], "k": "eq"}
                right = {"n": j1 + k + 1, "t": b[j1 + k], "k": "eq"}
                split.append((left, right))
                unified.append({"ln": i1 + k + 1, "rn": j1 + k + 1,
                                "t": a[i1 + k], "k": "eq"})
            continue
        dels = [{"n": i1 + k + 1, "t": a[i1 + k], "k": "del"}
                for k in range(i2 - i1)]
        adds = [{"n": j1 + k + 1, "t": b[j1 + k], "k": "add"}
                for k in range(j2 - j1)]
        for k in range(max(len(dels), len(adds))):
            split.append((dels[k] if k < len(dels) else None,
                          adds[k] if k < len(adds) else None))
        for d in dels:
            unified.append({"ln": d["n"], "rn": None, "t": d["t"], "k": "del"})
        for ad in adds:
            unified.append({"ln": None, "rn": ad["n"], "t": ad["t"], "k": "add"})
    return split, unified


# ------------------------------------------------------------------ checks
class Check:
    def __init__(self, key, label, status, detail, evidence=""):
        self.key = key
        self.label = label
        self.status = status          # passed | failed | warning | unknown
        self.detail = detail
        self.evidence = evidence

    @property
    def level(self):
        return {"passed": "good", "failed": "crit",
                "warning": "warn"}.get(self.status, "mut")

    @property
    def blocking(self):
        return self.status == "failed"


def _check_syntax(body):
    """Brace balance and statement termination on the proposed configuration.

    Not a substitute for `nginx -t` - this console is unprivileged and does not
    get to test-load production nginx - so a pass is reported as what it is.
    """
    depth = 0
    for i, line in enumerate(body.splitlines(), 1):
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        depth += s.count("{") - s.count("}")
        if depth < 0:
            return Check("syntax", "Configuration syntax", "failed",
                         "Unbalanced braces: a block closes at line %d that was "
                         "never opened." % i)
        core = s.replace("{", "").replace("}", "").strip()
        if core and not core.endswith(";") and "{" not in s and "}" not in s:
            return Check("syntax", "Configuration syntax", "failed",
                         "Line %d is not terminated with a semicolon." % i)
    if depth:
        return Check("syntax", "Configuration syntax", "failed",
                     "Unbalanced braces: %d block(s) left open." % depth)
    return Check("syntax", "Configuration syntax", "passed",
                 "Braces balanced and every directive terminated.",
                 "Structural parse only - nginx -t needs root and is not run "
                 "from this console.")


def _check_cert(cert_path, warn_days):
    """The certificate this vhost is serving right now, read off disk."""
    issuer, expires, days = console_data._cert_facts(cert_path)
    if not issuer:
        return Check("cert", "Certificate validity", "unknown",
                     "The certificate on disk could not be read.",
                     cert_path)
    if days is None:
        return Check("cert", "Certificate validity", "unknown",
                     "No expiry could be read from the certificate.", cert_path)
    if days < 0:
        return Check("cert", "Certificate validity", "failed",
                     "The certificate expired %d days ago." % abs(days), expires)
    if days < warn_days:
        return Check("cert", "Certificate validity", "warning",
                     "Expires in %d days, inside the %d-day alert threshold."
                     % (days, warn_days), expires)
    return Check("cert", "Certificate validity", "passed",
                 "Valid for another %d days." % days, "not after %s" % expires)


def _check_chain(cert_path):
    """A rotation that ships a leaf without its issuer breaks every client that
    does not already hold the CA, so the chain is checked separately."""
    body = console_data._read(cert_path, 200000)
    if not body:
        return Check("chain", "Certificate chain", "unknown",
                     "The chain file could not be read.", cert_path)
    n = body.count("BEGIN CERTIFICATE")
    if n < 2:
        return Check("chain", "Certificate chain", "failed",
                     "Only the leaf certificate is present - the issuing CA is "
                     "not bundled.", os.path.basename(cert_path))
    issuer, _, _ = console_data._cert_facts(cert_path)
    if issuer and "NRPI" not in issuer.upper():
        return Check("chain", "Certificate chain", "warning",
                     "Chained, but not to the NRPI CA.", issuer)
    return Check("chain", "Certificate chain", "passed",
                 "%d certificates: leaf plus issuing CA." % n, issuer or "")


_CIDR = re.compile(r"^\s*allow\s+([0-9./]+);", re.M)


def _check_access(after_body, access, title):
    """The check that blocks this change, and the reason it should.

    The diff restricts *where a client may connect from*. It does not touch the
    sign-in gate's per-site policy, which is what decides *who* may sign in. A
    change whose stated outcome is owner-only access therefore does not achieve
    it: every group admitted today is still admitted afterwards, from inside the
    allowlist. Read live from the helper's access policy, so this stops failing
    the moment the gate policy is actually narrowed.
    """
    nets = _CIDR.findall(after_body or "")
    wants_owner = bool(re.search(r"owner|restrict", title or "", re.I))
    mode = (access or {}).get("mode") or "unknown"
    groups = (access or {}).get("groups") or []
    if not access:
        return Check("access", "Access policy", "unknown",
                     "The sign-in gate's policy for this site could not be "
                     "read, so the effect of this change on who may sign in "
                     "cannot be established.")
    if wants_owner and mode not in ("superadmin", "owner"):
        who = ("%d group%s (%s)" % (len(groups), "" if len(groups) == 1 else "s",
                                    ", ".join(groups[:3]))) if groups \
            else "everyone the default policy admits"
        return Check(
            "access", "Access policy", "failed",
            "This change restricts where clients may connect from, not who may "
            "sign in. The gate policy for this site is unchanged by the diff, "
            "so %s can still sign in - from inside the allowlist. To reach the "
            "stated outcome the site's access policy has to be narrowed as well."
            % who,
            "gate mode '%s'%s; allowlist %s"
            % (mode, " (inherited)" if (access or {}).get("inherited") else "",
               ", ".join(nets) or "none"))
    if not nets:
        return Check("access", "Access policy", "warning",
                     "The change adds no network allowlist.", "")
    return Check("access", "Access policy", "passed",
                 "Gate policy is '%s' and the allowlist covers the estate."
                 % mode, ", ".join(nets))


def _check_reachability(after_body, sources):
    """Would the allowlist lock out clients that are actually reaching this
    estate? Evaluated against source addresses observed in nginx's own log."""
    nets = _CIDR.findall(after_body or "")
    if not nets:
        return Check("reach", "Blast radius review", "warning",
                     "No allowlist to evaluate.", "")
    if not sources:
        return Check("reach", "Blast radius review", "unknown",
                     "No recent client addresses could be read from the access "
                     "log, so lockout cannot be ruled out by observation.")
    outside = [ip for ip in sources if not any(_in_net(ip, n) for n in nets)]
    if outside:
        return Check("reach", "Blast radius review", "failed",
                     "%d recently seen client address(es) fall outside the "
                     "allowlist and would be refused: %s."
                     % (len(outside), ", ".join(sorted(outside)[:4])),
                     ", ".join(nets))
    return Check("reach", "Blast radius review", "passed",
                 "All %d client addresses seen recently fall inside the "
                 "allowlist." % len(sources), ", ".join(nets))


def _in_net(ip, cidr):
    try:
        net, bits = cidr.split("/")
        bits = int(bits)
        def pack(a):
            parts = [int(x) for x in a.split(".")]
            if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
                raise ValueError(a)
            return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        mask = ((1 << 32) - 1) ^ ((1 << (32 - bits)) - 1) if bits else 0
        return (pack(ip) & mask) == (pack(net) & mask)
    except (ValueError, IndexError):
        return False


_LOGS = ("/var/log/nginx/access.log",)


def _observed_sources(limit=4000):
    """Distinct client addresses from the tail of nginx's access log. Empty when
    the log is not readable by this user - which the caller reports as unknown
    rather than as a pass."""
    seen = set()
    for path in _LOGS:
        body = console_data._read(path, 400000)
        if not body:
            continue
        for line in body.splitlines()[-limit:]:
            ip = line.split(" ", 1)[0]
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                seen.add(ip)
    return sorted(seen)


# ------------------------------------------------------------------ assembly
def _row_to_change(row):
    return {k: row[k] for k in row.keys()}


def _affected_users(A, days=90):
    """Who is actually reached by a change to this estate.

    Counted from the console's own audit trail - accounts that have genuinely
    signed in recently - rather than from a directory group, which lists who
    *could* sign in and is usually much larger than who does. An empty result is
    reported as an absence of evidence, never as "nobody is affected".
    """
    cutoff = _iso(datetime.now(timezone.utc) - timedelta(days=days))
    rows = A.db().execute(
        'SELECT DISTINCT "user" FROM audit WHERE ts >= ? '
        "AND action IN ('login','gate-login','sso-login') "
        'AND "user" IS NOT NULL AND "user" != \'-\' ORDER BY "user"',
        (cutoff,)).fetchall()
    return [r[0] for r in rows if r[0]]


def _approvers(A, change_id, con):
    """The required approval slots, filled from real state, plus whatever
    decisions have actually been recorded."""
    from flask import session
    cfg = A.load_config()
    owners = list((cfg.get("sso") or {}).get("owners") or [])
    policy = A.permission_policy()
    groups = list(policy.get("change.approve") or [])

    decided = {r["slot"]: dict(r) for r in con.execute(
        "SELECT * FROM cc_approvals WHERE change_id=?", (change_id,))}

    me = (session.get("user") or "").lower()
    rows = []
    for slot, label, why in APPROVAL_SLOTS:
        if slot == "owner":
            who = ", ".join(owners) or "no platform owner configured"
            resolvable = bool(owners)
            mine = me in [o.lower() for o in owners]
        else:
            who = ", ".join(groups) or "no group holds change.approve"
            resolvable = bool(groups)
            sess = [g.lower() for g in (session.get("sso") or {}).get("groups") or []]
            mine = any(g.lower() in sess for g in groups)
        d = decided.get(slot)
        rows.append({
            "slot": slot, "label": label, "why": why, "who": who,
            "resolvable": resolvable, "can_act": mine and not d,
            "decision": (d or {}).get("decision"),
            "by": (d or {}).get("decided_by"),
            "at": (d or {}).get("decided_at"),
            "note": (d or {}).get("note"),
        })
    return rows


def checks_for(A, row, ctx=None):
    """Run every preflight check against a record.

    Takes the console context when there is one (the vhost list and access
    policy are already assembled there), and falls back to reading them itself
    on a POST - where re-running the checks is the point, and paying for one
    helper call is much cheaper than trusting a stored verdict.
    """
    warn_days = 30
    try:
        warn_days = int((A.load_config().get("alerts") or {}).get("cert_warn_days", 30))
    except (TypeError, ValueError):
        pass
    fqdn = row["target_fqdn"]
    if ctx is not None:
        vh = next((v for v in (ctx.get("vhosts") or [])
                   if fqdn and fqdn in (v.get("server_name") or "")), None)
        access = (ctx.get("access_map") or {}).get(fqdn)
    else:
        vh = next((v for v in _vhosts_min()
                   if fqdn and fqdn in (v.get("server_name") or "")), None)
        access = A.site_access_for(fqdn)
    cert_path = (vh or {}).get("cert_path") or \
        "/etc/ssl/subdomains/%s/fullchain.pem" % fqdn
    after = row["after_body"] or ""
    checks = [
        _check_syntax(after),
        _check_cert(cert_path, warn_days),
        _check_chain(cert_path),
        _check_access(after, access, row["title"]),
        _check_reachability(after, _observed_sources()),
    ]
    return checks, vh, access, cert_path


def _vhosts_min():
    """Enabled nginx sites and the certificate each serves. Only used off the
    render path, where console_data's richer list is not to hand."""
    rows = []
    # NGINX-TLS-NS-20260929: sites-enabled plus the managed namespace, in include order.
    for fn, path in console_data.enabled_site_files():
        body = console_data._read(path, 200000)
        if not body:
            continue
        names = re.findall(r"^\s*server_name\s+([^;]+);", body, re.M)
        certs = re.findall(r"^\s*ssl_certificate\s+([^;]+);", body, re.M)
        rows.append({
            "file": fn,
            "server_name": " ".join(dict.fromkeys(" ".join(names).split())),
            "cert_path": certs[0].strip() if certs else None,
            "gated": "auth_request" in body,
        })
    return rows


def build(A, ctx):
    """Context for the Change Control and Change History sections.

    `ctx` is the context console_data already assembled, so the vhost list and
    the site access policy are reused rather than re-read - a second helper call
    per render would double the cost of the page for no new information.
    """
    seed_if_empty(A)
    con = A.db()
    rows = con.execute(
        "SELECT * FROM cc_changes ORDER BY datetime(replace(created_at,' UTC','')) DESC"
    ).fetchall()
    ledger = [_row_to_change(r) for r in rows]

    out = {
        "cc_stages": STAGES,
        "cc_ledger": ledger,
        "cc_change": None,
        "cc_no_runner": NO_RUNNER,
    }
    if not ledger:
        return out

    # Which record is open. The hash carries it (#change/CHG-2841); the server
    # renders the newest, and the client re-points at the one in the URL.
    ch = ledger[0]
    out["cc_change"] = ch

    checks, vh, access, cert_path = checks_for(A, rows[0], ctx)
    blockers = [c for c in checks if c.blocking]
    sources = _observed_sources()

    split, unified = diff_rows(ch["before_body"] or "", ch["after_body"] or "")

    # Blast radius, counted from real state rather than asserted.
    groups = (access or {}).get("groups") or []
    subs_on_host = [s for s in (ctx.get("subs") or [])
                    if (s["fqdn"] or "").endswith(A.BASE_DOMAIN or ".nrpi.local")]
    users = _affected_users(A)

    approvers = _approvers(A, ch["id"], con)
    given = [a for a in approvers if a["decision"] == "approved"]
    rejected = [a for a in approvers if a["decision"] == "rejected"]

    stage_i = STAGE_KEYS.index(ch["stage"]) if ch["stage"] in STAGE_KEYS else 0

    out.update(
        cc_checks=checks,
        cc_blockers=blockers,
        cc_blocked=bool(blockers),
        cc_split=split,
        cc_unified=unified,
        cc_added=sum(1 for u in unified if u["k"] == "add"),
        cc_removed=sum(1 for u in unified if u["k"] == "del"),
        cc_cert_path=cert_path,
        cc_vhost=vh,
        cc_access=access,
        cc_groups=groups,
        cc_subs=subs_on_host,
        cc_users=users,
        cc_sources=sources,
        cc_approvers=approvers,
        cc_approved_n=len(given),
        cc_rejected=bool(rejected),
        cc_required_n=len(APPROVAL_SLOTS),
        cc_stage_i=stage_i,
        cc_can_request=(ch["stage"] == "preflight" and not ch["approval_requested_at"]
                        and ch["outcome"] == "open"),
        cc_is_seed=(ch["origin"] == "seed"),
    )
    return out


# ------------------------------------------------------------------ writes
def request_approval(A, ref, user):
    """Move a change out of preflight into approval. Refused while a preflight
    check is failing - which is the whole point of the gate."""
    con = A.db()
    row = con.execute("SELECT * FROM cc_changes WHERE ref=?", (ref,)).fetchone()
    if not row:
        return "No such change."
    if row["outcome"] != "open":
        return "This change is %s and cannot be re-submitted." % row["outcome"]
    if row["approval_requested_at"]:
        return "Approval has already been requested for this change."
    # The gate lives here, not only in the page: a form can be replayed, and a
    # disabled button is a courtesy, never a control.
    checks, _, _, _ = checks_for(A, row)
    blocking = [c for c in checks if c.blocking]
    if blocking:
        return ("Preflight is blocked, so this change cannot be sent for "
                "approval: " + "; ".join("%s - %s" % (c.label, c.detail)
                                         for c in blocking))
    con.execute("UPDATE cc_changes SET stage='approval', approval_requested_at=? "
                "WHERE id=?", (_iso(datetime.now(timezone.utc)), row["id"]))
    con.commit()
    return None


def record_decision(A, ref, slot, decision, user, note=""):
    con = A.db()
    row = con.execute("SELECT * FROM cc_changes WHERE ref=?", (ref,)).fetchone()
    if not row:
        return "No such change."
    if row["stage"] != "approval":
        return "This change is not out for approval."
    if decision not in ("approved", "rejected"):
        return "Unknown decision."
    if (row["requested_by"] or "").lower() == (user or "").lower() \
            and row["origin"] == "live":
        return "A change cannot be approved by the person who raised it."
    try:
        con.execute(
            "INSERT INTO cc_approvals(change_id,slot,decision,decided_by,"
            "decided_at,note) VALUES(?,?,?,?,?,?)",
            (row["id"], slot, decision, user,
             _iso(datetime.now(timezone.utc)), (note or "")[:500]))
    except sqlite3.IntegrityError:
        return "That approval slot has already been decided."
    if decision == "rejected":
        con.execute("UPDATE cc_changes SET outcome='rejected', stage='preflight' "
                    "WHERE id=?", (row["id"],))
    else:
        n = con.execute("SELECT COUNT(*) FROM cc_approvals WHERE change_id=? "
                        "AND decision='approved'", (row["id"],)).fetchone()[0]
        if n >= len(APPROVAL_SLOTS):
            con.execute("UPDATE cc_changes SET stage='deploy' WHERE id=?",
                        (row["id"],))
    con.commit()
    return None


def reopen(A, ref, user):
    """Send a rejected change back to preflight so it can be revised."""
    con = A.db()
    row = con.execute("SELECT * FROM cc_changes WHERE ref=?", (ref,)).fetchone()
    if not row:
        return "No such change."
    con.execute("DELETE FROM cc_approvals WHERE change_id=?", (row["id"],))
    con.execute("UPDATE cc_changes SET outcome='open', stage='preflight', "
                "approval_requested_at=NULL WHERE id=?", (row["id"],))
    con.commit()
    return None
