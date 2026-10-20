"""Context for the live CORPIT admin console (templates/console.html).

Everything the console renders is read here, at request time, from the box
itself: the subdomain registry, the root helper's access policy, nginx's own
enabled sites, the certificates actually on disk, systemd, and the directory
sync's state file. Nothing is cached across requests except where noted, and
nothing is invented - a section with no backing data says so rather than
showing a plausible number.

Kept out of app.py deliberately: this is presentation-shaped read-only code,
and app.py holds the privileged routes.
"""
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone

NGINX_SITES = "/etc/nginx/sites-enabled"
# NGINX-TLS-NS-20260929: sites the root helper manages live in their own namespace,
# included by nginx.conf right after sites-enabled/*. Absent on a node that holds no
# namespace (HA passive), which is not an error.
NGINX_MANAGED_SITES = "/etc/nginx/corpit-ha/enabled"
_CERT_CACHE = {}          # path -> (mtime, issuer, not_after_iso, days_left)
_TLS_CERT_CACHE = {}      # hostname -> (checked_at, issuer, not_after_iso, days_left)

# Two reads dominate the page: the directory-sync collector (a node process) and
# the LDAP group lookup. Both describe things that change on the order of hours,
# so a short in-process TTL takes the page from ~800ms to ~250ms without ever
# showing anything meaningfully stale. Deliberately NOT cached: whether a sync is
# running right now, and everything read from the database.
_GAL_TTL = 15.0
_GROUPS_TTL = 120.0
_gal_cache = {"ts": 0.0, "data": None}
_groups_cache = {"ts": 0.0, "data": None}
# The housekeeping scan stats a few dozen paths and walks a couple of small
# directories. Cheap, but there is no reason to redo it on every render.
_HK_TTL = 60.0
_hk_cache = {"ts": 0.0, "keep": None, "data": None}


# --------------------------------------------------------------- host facts
def _read(path, limit=4096):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _host_facts():
    facts = {}
    facts["host_name"] = (_read("/etc/hostname").strip() or "this server")

    up = _read("/proc/uptime").split()
    if up:
        secs = int(float(up[0]))
        d, rem = divmod(secs, 86400)
        h, rem = divmod(rem, 3600)
        m = rem // 60
        facts["host_uptime"] = ("%dd %dh %dm" % (d, h, m)) if d else ("%dh %dm" % (h, m))
    else:
        facts["host_uptime"] = "unknown"

    la = _read("/proc/loadavg").split()
    facts["host_load"] = " ".join(la[:3]) if la else "unknown"

    mem = {}
    for line in _read("/proc/meminfo", 2048).splitlines():
        k, _, v = line.partition(":")
        mem[k.strip()] = v.strip()

    def _kb(key):
        try:
            return int(mem.get(key, "0").split()[0])
        except (ValueError, IndexError):
            return 0

    total, avail = _kb("MemTotal"), _kb("MemAvailable")
    if total:
        facts["host_mem"] = "%.1f GB available of %.1f GB (%d%% used)" % (
            avail / 1048576.0, total / 1048576.0,
            round((total - avail) * 100.0 / total))
    else:
        facts["host_mem"] = "unknown"

    try:
        st = os.statvfs("/")
        tot = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        facts["host_disk"] = "%.0f GB free of %.0f GB (%d%% used)" % (
            free / 1e9, tot / 1e9, round((tot - free) * 100.0 / tot) if tot else 0)
    except OSError:
        facts["host_disk"] = "unknown"

    facts["now_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return facts


def sync_stale_hours(status, now=None):
    """Hours since the directory sync last completed, or None if unknown.

    A named function rather than four lines inline, because "has the scheduled
    job silently stopped" is the check most worth being sure about and the least
    likely to be exercised by chance - the sync usually HAS just run, so the
    branch is almost never taken when you look.
    """
    finished = (status.get("lastRun") or {}).get("finishedAt")
    if not finished:
        return None
    try:
        last = datetime.strptime(str(finished)[:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return ((now or datetime.now(timezone.utc)) - last).total_seconds() / 3600.0


def _setting(cfg, group, key, fallback):
    """One nested integer setting, with the fallback used for anything unusable.
    A bad value must not take the page down - it should behave as unset."""
    try:
        v = int((cfg.get(group) or {}).get(key))
        return v if v > 0 else fallback
    except (TypeError, ValueError, AttributeError):
        return fallback


def _systemd(units):
    """(unit, state) for each unit. 'unknown' rather than a guess on failure."""
    try:
        out = subprocess.run(["systemctl", "is-active"] + list(units),
                             capture_output=True, text=True, timeout=8)
        states = out.stdout.split()
    except (OSError, subprocess.SubprocessError):
        states = []
    while len(states) < len(units):
        states.append("unknown")
    return list(zip(units, states))


def _dns_addresses(name):
    """Return the live IPv4 answers for ``name``; None means the check failed.

    The registry columns record what the console last pushed. They are useful
    audit metadata, but they are not evidence that DNS still resolves now. The
    UI therefore uses the resolver on this host and keeps a failed lookup
    distinct from a verified empty answer.
    """
    try:
        out = subprocess.run(
            ["getent", "ahostsv4", str(name)], capture_output=True,
            text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode not in (0, 2):
        return None
    addresses = []
    for line in out.stdout.splitlines():
        value = line.split()[0] if line.split() else ""
        if value and value not in addresses:
            addresses.append(value)
    return addresses


def _timers(limit=10):
    try:
        out = subprocess.run(
            ["systemctl", "list-timers", "--no-pager", "--no-legend", "--all"],
            capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for line in out.stdout.splitlines():
        # NEXT(3) LEFT(2) LAST(3) PASSED(2) UNIT ACTIVATES - split from the right,
        # which is stable even though the date columns vary in width.
        parts = line.split()
        if len(parts) < 6:
            continue
        unit = parts[-2]
        if not unit.endswith(".timer"):
            continue
        rows.append({"unit": unit,
                     "next": " ".join(parts[0:4]) if parts[0] != "n/a" else "not scheduled",
                     "last": " ".join(parts[6:10]) if len(parts) > 9 else "-"})
        if len(rows) >= limit:
            break
    return rows


# --------------------------------------------------------------- certificates
def _parse_cert_output(output):
    issuer = expires = None
    days = None
    for line in str(output or "").splitlines():
        if line.startswith("issuer="):
            issuer = line[7:].strip()
        elif line.startswith("notAfter="):
            expires = line[9:].strip()
    if expires:
        try:
            dt = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (dt - datetime.now(timezone.utc)).days
            expires = dt.strftime("%Y-%m-%d")
        except ValueError:
            days = None
    return issuer, expires, days


def _cert_facts(path):
    """(issuer, expires, days_left) read off the file, cached by mtime.

    The issuer is read from the certificate that is actually installed - never
    inferred from the filename or from a previous deploy having 'worked'.
    """
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return (None, None, None)
    hit = _CERT_CACHE.get(path)
    if hit and hit[0] == mtime:
        return hit[1:]
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-issuer", "-enddate"],
            capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return (None, None, None)
    issuer, expires, days = _parse_cert_output(out.stdout)
    _CERT_CACHE[path] = (mtime, issuer, expires, days)
    return (issuer, expires, days)


def _served_cert_facts(hostname):
    """Read the certificate nginx actually presents on loopback.

    This is also the safe fallback when the unprivileged console cannot traverse
    a private-key directory. The public certificate stays private-directory
    adjacent, the key permissions remain untouched, and the console still bases
    its verdict on the real TLS endpoint rather than a stale database column.
    """
    now = time.time()
    hit = _TLS_CERT_CACHE.get(hostname)
    if hit and now - hit[0] < 60:
        return hit[1:]
    try:
        handshake = subprocess.run(
            ["openssl", "s_client", "-connect", "127.0.0.1:443",
             "-servername", hostname, "-showcerts"],
            input="", capture_output=True, text=True, timeout=10)
        if "-----BEGIN CERTIFICATE-----" not in handshake.stdout:
            return (None, None, None)
        parsed = subprocess.run(
            ["openssl", "x509", "-noout", "-issuer", "-enddate"],
            input=handshake.stdout, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return (None, None, None)
    facts = _parse_cert_output(parsed.stdout)
    _TLS_CERT_CACHE[hostname] = (now,) + facts
    return facts


def enabled_site_files():
    """(file name, path) of every enabled nginx site, in nginx's include order:
    sites-enabled/* sorted, then the managed namespace sorted. [] when sites-enabled
    itself cannot be listed (the old behaviour); the managed dir is skipped when
    missing or unreadable."""
    try:
        fixed = sorted(os.listdir(NGINX_SITES))
    except OSError:
        return []
    out = [(fn, os.path.join(NGINX_SITES, fn)) for fn in fixed]
    try:
        managed = sorted(os.listdir(NGINX_MANAGED_SITES))
    except OSError:
        managed = []
    out += [(fn, os.path.join(NGINX_MANAGED_SITES, fn)) for fn in managed]
    return out


def _vhosts(access_lookup, warn_days=30):
    """Every enabled nginx site, with the certificate it actually serves.

    'gated' is true only when the vhost really carries auth_request - read from
    the config, never assumed from the hostname.
    """
    rows = []
    for fn, path in enabled_site_files():
        body = _read(path, 200000)
        if not body:
            continue
        names = re.findall(r"^\s*server_name\s+([^;]+);", body, re.M)
        certs = re.findall(r"^\s*ssl_certificate\s+([^;]+);", body, re.M)
        name = " ".join(dict.fromkeys(" ".join(names).split())) or "(no server_name)"
        cert_path = certs[0].strip() if certs else None
        issuer = expires = None
        days = None
        if cert_path:
            issuer, expires, days = _cert_facts(cert_path)
        # The Flask worker may be unable to traverse the directory that also
        # contains nginx's private key. Read the public certificate through the
        # endpoint instead of weakening that directory's permissions.
        first_name = name.split()[0] if name and name != "(no server_name)" else None
        if not issuer and first_name:
            issuer, expires, days = _served_cert_facts(first_name)
        self_signed = bool(issuer) and "NRPI" not in issuer.upper()
        expiring = days is not None and days < warn_days
        if not issuer:
            cert_summary, cert_level = "could not be read", "warn"
        elif self_signed:
            cert_summary, cert_level = "self-signed", "warn"
        elif expiring:
            cert_summary, cert_level = "NRPI-CA - %d days left" % days, "warn"
        else:
            cert_summary, cert_level = "NRPI-CA", "good"
        gated = "auth_request" in body
        acc = access_lookup(name.split()[0]) if name and name != "(no server_name)" else None
        rows.append({
            "file": fn, "server_name": name, "gated": gated,
            "cert_path": cert_path, "cert_issuer": issuer, "cert_expires": expires,
            "cert_days": days, "cert_summary": cert_summary, "cert_level": cert_level,
            "access": acc,
            "level": "good" if (cert_level == "good" and gated) else "warn",
        })
    return rows


# --------------------------------------------------------------- the context
def build(A):
    """Assemble the console context. `A` is the app module (passed in rather
    than imported, so this file has no import cycle with it)."""
    from flask import session

    cfg, cfg_rev = A.load_config_rev()
    user = session.get("user", "")
    sso_ctx = session.get("sso") or {}
    users_cfg = cfg.get("users") or {}

    ctx = _host_facts()

    # ---- identity -------------------------------------------------------
    display = sso_ctx.get("name") or user
    initials = "".join(p[0] for p in re.split(r"[\s.@_]+", display) if p)[:2].upper() or "?"
    ctx.update(
        user=user, user_display=display, user_initials=initials,
        role=sso_ctx.get("role"), sso_groups=sso_ctx.get("groups") or [],
        sso_session=bool(sso_ctx), local_account=user in users_cfg,
        min_password_len=A.MIN_PASSWORD_LEN,
        session_cap_hours=round(A.app.config["SESSION_ABSOLUTE_MAX"] / 3600.0, 1),
        owners=list((cfg.get("sso") or {}).get("owners") or []),
        can_write_prod=bool(sso_ctx.get("can_write_prod")),
        hub_sso=bool(A.request.headers.get("X-Gate-Email")),
        base_domain=A.BASE_DOMAIN, host_ip=A.HOST_IP,
        reserved_labels=", ".join(sorted(A.RESERVED)),
    )

    # ---- subdomains, access policy, CSRs ---------------------------------
    subs = A.db().execute("SELECT * FROM subdomains ORDER BY created_at DESC").fetchall()
    ctx["subs"] = subs

    policy = A.site_policy()
    sites = (policy.get("sites") or {})
    default_mode = (policy.get("default") or {}).get("mode", "superadmin")

    def access_for(fqdn):
        site = sites.get(str(fqdn).lower())
        if not site:
            return {"mode": default_mode, "groups": [], "inherited": True}
        return {"mode": site.get("mode", "superadmin"),
                "groups": site.get("groups") or [], "inherited": False,
                "page_limits": site.get("page_limits") or {}}   # SECPAGELIMIT-20261019

    access_map, policy_rows, csr_map = {}, [], {}
    for s in subs:
        a = access_for(s["fqdn"])
        access_map[s["fqdn"]] = a
        policy_rows.append((s["fqdn"], dict(a, sub_id=s["id"])))
        path = s["csr_path"]
        if path and os.path.exists(path):
            csr_map[s["id"]] = _read(path, 8192)
    ctx.update(access_map=access_map, policy_rows=policy_rows, csr_map=csr_map)
    # DEVACCESS-W3-20261019: the launch pad (dev-releases) has no subdomain row. Only the itam dev helper lists it.
    ctx["launchpad_access"] = access_for("releases.nrpi.local") if policy.get("dev_view") else None

    def access_summary(fqdn):
        a = access_for(fqdn)
        if a["mode"] == "authenticated":
            return "any platform sign-in"
        if a["mode"] == "groups":
            return "%d AD group%s" % (len(a["groups"]), "" if len(a["groups"]) == 1 else "s")
        return "owners only"

    now = time.time()
    if _groups_cache["data"] is not None and now - _groups_cache["ts"] < _GROUPS_TTL:
        ctx["group_suggestions"] = _groups_cache["data"]
    else:
        groups = A.ad_group_suggestions()
        # An empty list means the directory could not be reached. Caching that
        # would keep saying "unreachable" for two minutes after it recovered,
        # and the page tells the operator saves will be refused - so retry.
        if groups:
            _groups_cache.update(ts=now, data=groups)
        ctx["group_suggestions"] = groups
    ctx["role_map"] = sorted(A.sso_mod.GROUP_ROLE_MAP.items())

    # ---- audit ----------------------------------------------------------
    ctx["audit"] = A.db().execute(
        "SELECT * FROM audit ORDER BY id DESC LIMIT 12").fetchall()
    ctx["audit_full"] = A.db().execute(
        "SELECT * FROM audit ORDER BY id DESC LIMIT 120").fetchall()
    ctx["audit_total"] = A.db().execute(
        "SELECT COUNT(*) AS n FROM audit").fetchone()["n"]

    # ---- link directory --------------------------------------------------
    ctx["links"] = A._beta_rows()
    ctx["page_path"] = A.BETA_PAGE_PATH
    ctx["beta_host"] = A.BETA_HOST_FQDN
    try:
        ctx["page_mtime"] = datetime.fromtimestamp(
            os.path.getmtime(A.BETA_PAGE_PATH), timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except OSError:
        ctx["page_mtime"] = None

    # ---- directory sync --------------------------------------------------
    running = A._gal_sync_running()
    now = time.time()
    if (_gal_cache["data"] is not None and now - _gal_cache["ts"] < _GAL_TTL
            and not running):
        status = _gal_cache["data"]
    else:
        status = {"ok": False, "error": "status collector did not run"}
        try:
            out = subprocess.run(["/usr/bin/node", "gal-status.js"], cwd=A.GAL_DIR,
                                 capture_output=True, text=True, timeout=45)
            status = json.loads(out.stdout.strip() or "{}")
        except subprocess.TimeoutExpired:
            status = {"ok": False, "error": "status collector timed out"}
        except (json.JSONDecodeError, OSError) as exc:
            status = {"ok": False, "error": str(exc)[:200]}
        # Only a good read is cached - a failure must be retried, not remembered.
        if status.get("ok"):
            _gal_cache.update(ts=now, data=status)
    try:
        gal_lists = A._gal_lists_load()
    except (OSError, json.JSONDecodeError):
        gal_lists = []
    # Exclusions and the roster summary come from the same collector; when it
    # is down, read the rules file directly so the list itself never vanishes
    # from the page along with the status.
    gal_excl = status.get("exclusions") if status.get("ok") else None
    if gal_excl is None:
        try:
            rules = A._gal_exclusions_load()["rules"]
            gal_excl = {"ok": True, "rules": [dict(r, status="unknown") for r in rules],
                        "counts": {"total": len(rules), "pending": 0, "unmatched": 0, "applied": 0}}
        except ValueError as exc:
            gal_excl = {"ok": False, "error": str(exc), "rules": [],
                        "counts": {"total": 0, "pending": 0, "unmatched": 0, "applied": 0}}
    # The directory-wide switch: what the file says, whether the last run
    # already honoured it, and how many people it moves either way. When the
    # collector is down the file is read directly and "applied" is unknowable.
    gal_roster = status.get("roster") if status.get("ok") else None
    if gal_excl.get("policy") is not None:
        pol_on, pol_status = bool(gal_excl["policy"].get("requireMobile")), gal_excl.get("policyStatus") or "unknown"
    else:
        try:
            pol_on = A._gal_policy(A._gal_exclusions_load())["requireMobile"]
        except ValueError:
            pol_on = False
        pol_status = "unknown"
    gal_policy = {
        "requireMobile": pol_on, "status": pol_status, "changed": gal_excl.get("policyChanged"),
        "withoutMobile": (gal_roster or {}).get("withoutMobile"),
        "heldByPolicy": (gal_roster or {}).get("heldByPolicy") or 0,
    }
    # The one-click mobile rollout uses the privacy-safe roster snapshot: it
    # records only whether a mobile exists, never the number.  Pre-compute the
    # exact add/remove delta per all-directory list so the confirmation can say
    # precisely what the action will do before an operator commits it.
    mobile_proof = A._gal_mobile_rollout_facts()
    mobile_upns = set(mobile_proof["recipients"])
    gal_mobile_rollouts = {}
    for gal_list in gal_lists:
        if (gal_list.get("source") or {}).get("type") != "all":
            continue
        current = {str(upn).strip().lower() for upn in gal_list.get("recipients") or [] if upn}
        gal_mobile_rollouts[gal_list.get("id")] = {
            "available": mobile_proof["available"],
            "generatedAt": mobile_proof.get("generatedAt"),
            "finishedAt": mobile_proof.get("finishedAt"),
            "reason": mobile_proof.get("reason"),
            "target": len(mobile_upns),
            "current": len(current),
            "add": len(mobile_upns - current),
            "remove": len(current - mobile_upns),
            "matched": bool(pol_on and mobile_upns and current == mobile_upns),
        }
    ctx.update(
        gal_status=status, gal_lists=gal_lists, gal_running=A._gal_sync_running(),
        gal_add_max=A.GAL_ADD_MAX, gal_add_ready=A._gal_add_ready(),
        gal_recipient_count=sum(len(l.get("recipients") or []) for l in gal_lists),
        gal_log="".join((_read(A.GAL_MANUAL_LOG, 20000) or "").splitlines(True)[-25:]),
        gal_exclusions=gal_excl, gal_roster=gal_roster, gal_policy=gal_policy,
        gal_mobile_rollouts=gal_mobile_rollouts,
        gal_exclude_modes=A.GAL_EXCLUDE_MODES, gal_exclude_max=A.GAL_EXCLUDE_MAX,
        gal_reason_max=A.GAL_REASON_MAX,
    )

    # ---- permissions -----------------------------------------------------
    # Only groups the sign-in path resolves AND maps to a console role can ever
    # match a grant: a user whose groups carry no role is refused at sign-in
    # altogether. Offering the rest would be offering a control that could never
    # fire, so they are named as excluded instead.
    import permissions as perms
    ctx["policy"] = A.permission_policy()
    ctx["capability_sections"] = perms.CAP_GROUPS
    role_map = A.sso_mod.GROUP_ROLE_MAP
    grantable, denied, names = [], [], {}
    for display in ctx["group_suggestions"]:
        key = display.strip().lower()
        if not key.startswith(perms.GROUP_PREFIX):
            continue
        names[key] = display
        short = display
        for pfx in ("SaaS-ITH-",):
            if display.lower().startswith(pfx.lower()):
                short = display[len(pfx):]
                break
        if key in role_map:
            grantable.append({"key": key, "name": display, "short": short,
                              "role": role_map[key]})
        else:
            denied.append(display)
    grantable.sort(key=lambda g: (perms.OWNER_ROLE != g["role"], g["short"].lower()))
    ctx.update(grantable_groups=grantable, denied_groups=sorted(denied),
               group_names=names)

    # ---- settings (gated - a user without the capability never has the
    #      values built, so nothing sensitive is rendered to them) -----------
    ctx.update(settings=[], setting_groups=[], setting_values={}, setting_secrets={},
               settings_problems=[], settings_advisories=[], settings_recent=[],
               settings_rev="", settings_restore_draft=False)
    if A.can("settings.manage"):
        values, secrets_set = {}, {}
        for s in A.settings_mod.SETTINGS:
            values[s.key] = A.settings_mod.display(cfg, s)
            secrets_set[s.key] = A.settings_mod.is_set(cfg, s) if s.sensitive else False
        ctx.update(settings=A.settings_mod.SETTINGS, setting_groups=A.settings_mod.visible_groups(),
                   setting_values=values, setting_secrets=secrets_set,
                   settings_problems=A.settings_mod.preflight(cfg),
                   settings_advisories=A.settings_mod.advisories(cfg) + A._settings_unfinished(),
                   settings_recent=A._settings_recent(),
                   # The form posts this back; a save drawn from an older file is refused.
                   settings_rev=cfg_rev,
                   settings_restore_draft=bool(session.pop("settings_restore_draft", False)))

    # ---- hosts, services, timers ----------------------------------------
    cert_warn_days = _setting(cfg, "alerts", "cert_warn_days", 45)
    vhosts = _vhosts(access_summary, cert_warn_days)
    ctx["vhosts"] = vhosts
    ctx["cert_warn_count"] = sum(1 for v in vhosts if v["cert_level"] != "good")

    # The sites page and attention queue use what resolves and what nginx serves
    # now. Database fields stay visible as last-push metadata in the drawer, but
    # never produce a false outage on their own.
    site_state = {}
    for s in subs:
        fqdn = str(s["fqdn"]).lower()
        addresses = _dns_addresses(fqdn)
        dns_live = addresses is not None and A.HOST_IP in addresses
        if addresses is None:
            dns_summary, dns_level = "could not be checked", "mut"
        elif dns_live:
            dns_summary, dns_level = "live", "good"
        elif addresses:
            dns_summary, dns_level = "points to %s" % ", ".join(addresses), "warn"
        else:
            dns_summary, dns_level = "not found", "warn"

        served = next((v for v in vhosts if fqdn in
                       [n.lower() for n in v["server_name"].split()]), None)
        if served:
            cert_ok = served["cert_level"] == "good"
            cert_summary = served["cert_summary"]
            cert_issuer = served["cert_issuer"]
            cert_expires = served["cert_expires"]
            cert_level = served["cert_level"]
            cert_path = served["cert_path"]
        else:
            cert_issuer = s["cert_issuer"]
            cert_expires = s["cert_expires"]
            cert_ok = bool(cert_issuer) and "NRPI" in str(cert_issuer).upper()
            cert_summary = "NRPI-CA" if cert_ok else "not served by nginx"
            cert_level = "good" if cert_ok else "warn"
            cert_path = None
        site_state[fqdn] = {
            "dns_addresses": addresses, "dns_live": dns_live,
            "dns_summary": dns_summary, "dns_level": dns_level,
            "cert_ok": cert_ok, "cert_summary": cert_summary,
            "cert_issuer": cert_issuer, "cert_expires": cert_expires,
            "cert_level": cert_level, "cert_path": cert_path,
            "ok": dns_live and cert_ok,
        }
    ctx["site_state"] = site_state
    ctx["dns_live_count"] = sum(1 for state in site_state.values() if state["dns_live"])
    ctx["cert_ca_count"] = sum(1 for state in site_state.values() if state["cert_ok"])
    ctx["go_live_pending"] = sum(1 for state in site_state.values() if not state["ok"])
    svc_states = dict(_systemd(["nginx", "subdomain-admin"]))
    ctx["nginx_state"] = svc_states.get("nginx", "unknown")
    ctx["services"] = [
        {"unit": "nginx", "state": svc_states.get("nginx", "unknown"),
         "what": "serves every vhost on this box and enforces the sign-in gate"},
        {"unit": "subdomain-admin", "state": svc_states.get("subdomain-admin", "unknown"),
         "what": "this console - gunicorn on 127.0.0.1:5000, running unprivileged"},
    ]
    ctx["timers"] = _timers()
    try:
        ctx["db_size"] = "%.0f KB" % (os.path.getsize(A.DB_PATH) / 1024.0)
    except OSError:
        ctx["db_size"] = "unknown"

    # ---- housekeeping ----------------------------------------------------
    import housekeeping as hk
    keep_days = _setting(cfg, "housekeeping", "backup_keep_days", 30)
    audit_days = _setting(cfg, "housekeeping", "audit_keep_days", 365)
    now = time.time()
    if (_hk_cache["data"] is not None and _hk_cache["keep"] == keep_days
            and now - _hk_cache["ts"] < _HK_TTL):
        scan = _hk_cache["data"]
    else:
        scan = hk.scan(keep_days)
        _hk_cache.update(ts=now, keep=keep_days, data=scan)
    try:
        audit_prunable = hk.audit_prune(A.db(), audit_days, dry_run=True)
    except Exception:
        audit_prunable = 0
    ctx.update(housekeeping=scan, hk_keep_days=keep_days, hk_audit_days=audit_days,
               hk_audit_prunable=audit_prunable, hk_human=hk.human,
               hk_floor_days=hk.HARD_AGE_FLOOR_DAYS, hk_keep_newest=hk.KEEP_NEWEST,
               hk_audit_actions=", ".join(hk.PRUNABLE_AUDIT_ACTIONS))

    # Disk pressure. Below the configured threshold the disk is not mentioned at
    # all - a dashboard that always shows a disk figure trains you to ignore it.
    disk_warn = _setting(cfg, "alerts", "disk_warn_percent", 85)
    disk_pct = None
    try:
        st = os.statvfs("/")
        if st.f_blocks:
            disk_pct = round((st.f_blocks - st.f_bavail) * 100.0 / st.f_blocks)
    except OSError:
        pass
    ctx.update(disk_pct=disk_pct, disk_warn_percent=disk_warn,
               cert_warn_days=cert_warn_days,
               sync_stale_hours=_setting(cfg, "alerts", "sync_stale_hours", 48))

    # ---- needs attention: derived, never stored --------------------------
    att = []
    for s in subs:
        live = site_state.get(str(s["fqdn"]).lower()) or {}
        if not live.get("dns_live"):
            att.append({"level": "warn", "nav": "sites",
                        "title": "%s DNS: %s" % (s["fqdn"], live.get("dns_summary", "unknown")),
                        "detail": ("the live resolver could not verify this name; this is unknown, not an outage"
                                   if live.get("dns_addresses") is None else
                                   "the live A record does not point to %s" % A.HOST_IP)})
        if not live.get("cert_ok"):
            att.append({"level": "warn", "nav": "sites",
                        "title": "%s certificate: %s" % (s["fqdn"], live.get("cert_summary", "unknown")),
                        "detail": "certificate evidence read from nginx%s" %
                                  ((" at " + live["cert_path"]) if live.get("cert_path") else "")})
    for v in vhosts:
        registered = any(name.lower() in site_state for name in v["server_name"].split())
        if v["cert_level"] != "good" and not registered:
            att.append({"level": "warn", "nav": "sites",
                        "title": "%s: %s" % (v["server_name"], v["cert_summary"]),
                        "detail": "certificate served from %s" % (v["cert_path"] or "an unknown path")})
    last = status.get("lastRun") or {}
    if last.get("opsFailed"):
        att.append({"level": "crit", "nav": "directory",
                    "title": "Directory sync reported %s failed operation(s)" % last["opsFailed"],
                    "detail": "last run finished %s" % last.get("finishedAt", "?")})
    if not status.get("ok"):
        att.append({"level": "warn", "nav": "directory",
                    "title": "Directory sync status could not be read",
                    "detail": status.get("error", "the collector returned nothing")})
    for m in (status.get("members") or []):
        if m.get("status") == "error":
            att.append({"level": "crit", "nav": "directory",
                        "title": "%s is not receiving the directory" % m.get("upn", "?"),
                        "detail": m.get("detail") or "the last sync could not write to this mailbox"})
    # Do-not-publish rules: a damaged file stops every sync (the engine refuses
    # to publish past a list it cannot read); a rule nobody matches is a typo
    # that is quietly protecting no one; a rule still pending after the sync
    # that was kicked for it should have run is a rule not yet on the phones.
    if not gal_excl.get("ok"):
        att.append({"level": "crit", "nav": "directory",
                    "title": "Directory exclusion list cannot be read - syncs will refuse to run",
                    "detail": gal_excl.get("error", "")})
    for r in gal_excl.get("rules") or []:
        if r.get("status") == "unmatched":
            att.append({"level": "warn", "nav": "directory",
                        "title": "Exclusion for %s matches nobody" % r.get("upn", "?"),
                        "detail": "no account with that address came back from Entra in the last sync - "
                                  "check it for a typo; until then it protects no one"})
        elif r.get("status") == "pending" and not running:
            try:
                age_min = (datetime.now(timezone.utc)
                           - datetime.fromisoformat(str(r.get("at")).replace("Z", "+00:00"))).total_seconds() / 60
            except (TypeError, ValueError):
                age_min = 0
            if age_min > 30:
                att.append({"level": "warn", "nav": "directory",
                            "title": "Exclusion for %s has not been applied yet" % r.get("upn", "?"),
                            "detail": "added %d minutes ago and no sync has run since - run one from Directory Sync"
                                      % int(age_min)})
    # The mobile-number switch was flipped, the sync it kicked should have run
    # by now, and the last snapshot still shows the old setting.
    if gal_policy["status"] == "pending" and not running:
        try:
            age_min = (datetime.now(timezone.utc)
                       - datetime.fromisoformat(str((gal_policy.get("changed") or {}).get("at")).replace("Z", "+00:00"))).total_seconds() / 60
        except (TypeError, ValueError):
            age_min = 0
        if age_min > 30:
            att.append({"level": "warn", "nav": "directory",
                        "title": "The \"only people with a mobile number\" switch has not been applied yet",
                        "detail": "changed %d minutes ago and no sync has run since - run one from Directory Sync"
                                  % int(age_min)})
    for p in ctx["settings_problems"]:
        att.append({"level": "crit", "nav": "system",
                    "title": "Platform setting needs attention", "detail": p})
    for level, msg in ctx["settings_advisories"]:
        att.append({"level": "crit" if level == "urgent" else "warn",
                    "nav": "system", "title": "Advisory", "detail": msg})
    if disk_pct is not None and disk_pct >= disk_warn:
        att.append({"level": "crit" if disk_pct >= 95 else "warn", "nav": "operations",
                    "title": "Root filesystem is %d%% full" % disk_pct,
                    "detail": "past the %d%% threshold set under Alerts" % disk_warn})
    # The failure nobody notices is not a sync that errors - it is a scheduled
    # sync that quietly stopped running.
    stale_h = ctx["sync_stale_hours"]
    hours = sync_stale_hours(status)
    if hours is not None and hours > stale_h:
        att.append({"level": "warn", "nav": "directory",
                    "title": "Directory sync has not run for %d hours" % hours,
                    "detail": "last completed %s UTC; the threshold is %d hours"
                              % (str((status.get("lastRun") or {}).get("finishedAt"))[:16]
                                 .replace("T", " "), stale_h)})
    if scan["removable"]:
        att.append({"level": "warn", "nav": "operations",
                    "title": "%s of aged backups can be cleaned up"
                             % hk.human(scan["candidate_bytes"]),
                    "detail": "%d item(s) older than %d days"
                              % (len(scan["removable"]), keep_days)})
    att.append({"level": "warn", "nav": "operations",
                "title": "No off-box backup of this server",
                "detail": "the console database, the access policy and the directory list "
                          "definitions exist only on this machine"})
    ctx["attention"] = att

    # ---- workspace lines + command palette -------------------------------
    ctx["lines"] = {
        "corpit": ("<b>corpit</b> &middot; prod &middot; %s &middot; %s &middot; %d virtual host%s "
                   "&middot; %d subdomain%s &middot; up %s &middot; load %s"
                   % (ctx["host_name"], A.HOST_IP, len(vhosts), "" if len(vhosts) == 1 else "s",
                      len(subs), "" if len(subs) == 1 else "s",
                      ctx["host_uptime"], ctx["host_load"])),
        "itam": ("<b>itam.nrpi.local</b> &middot; staging &middot; not reachable from this "
                 "console &mdash; it reads only the box it runs on"),
        "estate": ("<b>Estate</b> &middot; read-only roll-up &middot; this console reports on "
                   "%s only" % ctx["host_name"]),
    }

    items = []
    for s in subs:
        live = site_state.get(str(s["fqdn"]).lower()) or {}
        items.append({"g": "Sites", "t": s["fqdn"], "nav": "sites", "srv": "corpit",
                      "i": "sub", "meta": "%s / %s" % (live.get("dns_summary", "DNS unknown"),
                                                       live.get("cert_summary", "certificate unknown"))})
    for v in vhosts:
        items.append({"g": "Hosts", "t": v["server_name"], "nav": "sites", "srv": "corpit",
                      "i": "host", "meta": "%s / %s" % ("gated" if v["gated"] else "open",
                                                        v["cert_summary"])})
    for l in gal_lists:
        items.append({"g": "Directory Sync", "t": l.get("name", l.get("id", "list")),
                      "nav": "directory", "srv": "corpit", "i": "dir",
                      "meta": "%d recipients" % len(l.get("recipients") or [])})
    for a in att[:12]:
        items.append({"g": "Needs attention", "t": a["title"], "nav": a["nav"],
                      "srv": "corpit", "i": "find", "meta": a["level"]})
    for t in ctx["timers"]:
        items.append({"g": "Jobs", "t": t["unit"], "nav": "operations", "srv": "corpit",
                      "i": "job", "meta": "next %s" % t["next"]})
    for g, r in ctx["role_map"]:
        items.append({"g": "Roles", "t": g, "nav": "iam", "srv": None, "i": "user",
                      "meta": r})
    for cap in perms.CAPABILITIES:
        held = ctx["policy"].get(cap.key) or []
        items.append({"g": "Permissions", "t": cap.label, "nav": "iam", "srv": None,
                      "i": "user",
                      "meta": ("owner only" if not cap.editable or not held
                               else "%d group%s" % (len(held), "" if len(held) == 1 else "s"))})
    ctx["cmdk_json"] = json.dumps(
        {"items": items, "lines": ctx["lines"]}, ensure_ascii=True
    ).replace("<", "\\u003c")

    return ctx
