"""CORPIT-HUB-LANDING

The CorpIT Hub home page (https://corpit.nrpi.local/) is a static file. What it
shows - the sections, the links in each one, which links are favorites and which
are the quick buttons under the search box, and the icon on every tile - is kept
here, edited from the console, and published as ONE JSON file the page reads:

    /var/www/html/landing/landing.json

The page keeps its built-in list as a fallback, so if this file is missing or
broken the home page still renders. Publishing writes the file atomically, the
same way the link directory rewrites its static page.

Icons come from a library shipped with the console at private/landing-icons/
(a manifest plus one file per icon). The console serves the library to the icon
picker; at publish time the chosen icon's markup is embedded in the JSON, so the
home page never has to fetch an icon file and the library never has to be
readable from the corpit host.

Kept out of app.py for the same reason change_control.py is: app.py holds the
privileged plumbing, this file holds one feature. It is handed the app module
(`A`) rather than importing it, so there is no import cycle.
"""
from corpit_sqlite import connect_durable
import base64
import json
import os
import re
import secrets
import sqlite3
import tempfile
from datetime import datetime, timezone

from flask import (Response, abort, flash, jsonify, redirect, request,
                   send_from_directory, session)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ICON_DIR = os.path.join(APP_DIR, "private", "landing-icons")
PUBLISH_PATH = "/var/www/html/landing/landing.json"
HUB_URL = "https://corpit.nrpi.local/"
BACK = "/console#landing"


def _back_link(link_id):
    return "/console#landing/link/%d" % link_id


def _back_section(sec_id):
    return "/console#landing/section/%d" % sec_id

# The colour behind a tile's icon. Keys match the .t-<tone> classes on the page.
TONES = [
    ("blue", "Blue", "#3B5BDB"),
    ("teal", "Teal", "#0D9488"),
    ("purple", "Purple", "#7C3AED"),
    ("amber", "Amber", "#D97706"),
    ("red", "Red", "#DC2626"),
    ("green", "Green", "#16A34A"),
    ("slate", "Gray", "#475569"),
]
TONE_KEYS = {t[0] for t in TONES}
DEFAULT_ICON = "glyph-link"
ICON_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

TITLE_MAX, URL_MAX, DESC_MAX, SECTION_MAX = 60, 500, 120, 40


# ---------------------------------------------------------------- schema
def init(db_path):
    con = connect_durable(db_path)
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS landing_sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT, created_by TEXT
        );
        CREATE TABLE IF NOT EXISTS landing_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            section_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            description TEXT,
            icon TEXT,
            tone TEXT NOT NULL DEFAULT 'blue',
            new_tab INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            favorite INTEGER NOT NULL DEFAULT 0,
            quick INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT, created_by TEXT,
            updated_at TEXT, updated_by TEXT
        );
        """
    )
    n = con.execute("SELECT COUNT(*) FROM landing_sections").fetchone()[0]
    if n == 0:
        _seed(con)
    con.commit()
    con.close()


def _seed(con):
    """First run: load what the hand-built home page shows today, so nothing
    disappears the moment the console takes over."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    itam = "https://itam.nrpi.local"
    sections = ["Devices", "Identity & Access", "Applications & SSO", "Security",
                "Data & Collaboration", "Network & Monitoring", "Service Desk", "Resources"]
    sid = {}
    for i, name in enumerate(sections):
        cur = con.execute(
            "INSERT INTO landing_sections(name,sort_order,enabled,created_at,created_by) VALUES(?,?,1,?,?)",
            (name, (i + 1) * 10, ts, "seed"))
        sid[name] = cur.lastrowid
    # (section, title, url, description, icon, tone, favorite, quick)
    links = [
        ("Devices", "Asset Inventory", "/IT_Inventory_App.html",
         "Track hardware, warranties, Intune endpoints & patch health.", "glyph-monitor", "teal", 1, 1),
        ("Identity & Access", "Identity Diagnostics", itam + "/identity-diag.html",
         "Diagnose AD lockouts, password issues & group access.", "glyph-user-search", "blue", 1, 1),
        ("Identity & Access", "AD Management", itam + "/ad-management.html",
         "Clean up stale accounts, groups & computers; GPO audit for super-admins.", "active-directory", "blue", 0, 0),
        ("Identity & Access", "User Projects", itam + "/beta-user-projects.html",
         "Grant time-bound AD group access for POCs.", "glyph-users", "blue", 0, 0),
        ("Identity & Access", "Access Portal", "https://accessportal.itam.nrpi.local/",
         "Submit access, AI-tool and security-exception requests.", "glyph-ticket", "blue", 0, 0),
        ("Applications & SSO", "App Migration", itam + "/app-migration.html",
         "Move SSO apps from Okta to Entra & confirm matches.", "glyph-arrow-left-right", "purple", 0, 0),
        ("Applications & SSO", "Okta Dashboard", itam + "/helpdesk/okta",
         "SSO usage, account health & security events.", "okta", "purple", 0, 0),
        ("Applications & SSO", "AI Usage & Credits", "https://reporting.nrpi.local/ai-usage-credits.html",
         "Track shared AI service usage, credit balances & per-user spend.", "claude", "purple", 0, 0),
        ("Security", "Cert Watchtower", itam + "/cert-watchtower.html",
         "Monitor TLS & Windows cert expiry with alerts.", "glyph-lock", "amber", 0, 0),
        ("Security", "Sign-In Watch", itam + "/signin-watch.html",
         "Monitor sign-ins for watched accounts & alert on untrusted networks.", "glyph-shield", "red", 0, 0),
        ("Security", "M365 Control Center", itam + "/tenant-sentinel.html",
         "Security score, findings & fix tracking.", "microsoft-365", "red", 0, 0),
        ("Data & Collaboration", "SharePoint Governance", itam + "/sharepoint-governance-dashboard.html",
         "Audit site lifecycle, external sharing & tenant storage.", "microsoft-sharepoint", "amber", 0, 0),
        ("Network & Monitoring", "Network Health", itam + "/network-health.html",
         "Switch, firewall and Wi-Fi health, plus ports and devices needing attention.", "glyph-radio", "green", 0, 0),
        ("Network & Monitoring", "Device Trace", itam + "/device-trace.html",
         "Look up any IP, MAC or user to see its switch port, Wi-Fi and firewall path.", "glyph-search", "teal", 1, 0),
        ("Network & Monitoring", "Switches", itam + "/network-switches.html",
         "Every switch: model, serial, IOS version, uptime and port utilization.", "cisco", "blue", 0, 0),
        ("Network & Monitoring", "Zscaler Command Center", itam + "/zscaler-command-center.html",
         "Live visibility into users, web activity, DLP & policy.", "zscaler", "blue", 0, 0),
        ("Network & Monitoring", "Server Health", "https://subadmin.nrpi.local/operations",
         "Unified infrastructure health, findings & maintenance.", "glyph-server", "purple", 1, 0),
        ("Service Desk", "Service Desk Portal", itam + "/service-desk-portal.html",
         "Submit and track IT service desk tickets.", "glyph-headset", "blue", 1, 1),
        ("Service Desk", "Report a Bug", itam + "/report-bug.html",
         "Flag something broken; get emailed when it is fixed.", "glyph-bug", "red", 0, 0),
        ("Resources", "IT Quick Start", itam + "/it-command-quickstart.html",
         "What each tool does & when to use it.", "glyph-rocket", "amber", 1, 0),
    ]
    order = {}
    for sec, title, url, desc, icon, tone, fav, quick in links:
        order[sec] = order.get(sec, 0) + 10
        con.execute(
            """INSERT INTO landing_links(section_id,title,url,description,icon,tone,new_tab,enabled,
                                         favorite,quick,sort_order,created_at,created_by)
               VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?)""",
            (sid[sec], title, url, desc, icon, tone, 0 if url.startswith("/") else 1,
             fav, quick, order[sec], ts, "seed"))


# ---------------------------------------------------------------- icon library
_manifest_cache = {"mtime": None, "by_id": {}, "count": 0}


def manifest():
    """{icon id: entry}. Re-read only when the file on disk changes."""
    path = os.path.join(ICON_DIR, "manifest.json")
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return {}
    if _manifest_cache["mtime"] != mt:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            icons = data.get("icons") or []
            _manifest_cache.update(mtime=mt, by_id={i["id"]: i for i in icons}, count=len(icons))
        except (OSError, ValueError):
            return _manifest_cache["by_id"]
    return _manifest_cache["by_id"]


def icon_src(icon_id):
    """Console-side URL for an icon (served by this app, behind the login)."""
    e = manifest().get(icon_id or "")
    if not e:
        e = manifest().get(DEFAULT_ICON)
    return "/landing/icons/%s" % e["file"] if e else ""


def icon_kind(icon_id):
    e = manifest().get(icon_id or "")
    return e["kind"] if e else "glyph"


def icon_markup(icon_id):
    """The markup the home page will show for this icon: inline SVG (glyphs use
    currentColor, so the tile's tone colours them) or a data: PNG for the few
    vendor logos that only exist as bitmaps."""
    e = manifest().get(icon_id or "") or manifest().get(DEFAULT_ICON)
    if not e:
        return ""
    path = os.path.join(ICON_DIR, e["file"])
    try:
        if path.endswith(".svg"):
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        with open(path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode("ascii")
        return '<img alt="" src="data:image/png;base64,%s">' % b64
    except OSError:
        return ""


# ---------------------------------------------------------------- reads
def _sections(A, enabled_only=False):
    q = "SELECT * FROM landing_sections"
    if enabled_only:
        q += " WHERE enabled=1"
    return A.db().execute(q + " ORDER BY sort_order ASC, id ASC").fetchall()


def _links(A, section_id=None, enabled_only=False):
    q, args = "SELECT * FROM landing_links", []
    where = []
    if section_id is not None:
        where.append("section_id=?")
        args.append(section_id)
    if enabled_only:
        where.append("enabled=1")
    if where:
        q += " WHERE " + " AND ".join(where)
    return A.db().execute(q + " ORDER BY sort_order ASC, id ASC", args).fetchall()


def _published_at():
    try:
        return datetime.fromtimestamp(os.path.getmtime(PUBLISH_PATH), timezone.utc
                                      ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except OSError:
        return None


def build(A, ctx):
    """Console context for the Home Page section, plus its search entries."""
    secs = []
    total = hidden = 0
    for s in _sections(A):
        rows = [dict(r) for r in _links(A, s["id"])]
        for r in rows:
            r["icon_src"] = icon_src(r["icon"])
            r["icon_kind"] = icon_kind(r["icon"])
            r["icon_label"] = (manifest().get(r["icon"] or "") or {}).get("label", r["icon"] or "")
            total += 1
            hidden += 0 if r["enabled"] else 1
        secs.append(dict(s, links=rows))
    ctx.update(
        landing_sections=secs,
        landing_total=total, landing_hidden=hidden,
        landing_published=_published_at(),
        landing_publish_path=PUBLISH_PATH,
        landing_hub_url=HUB_URL,
        landing_tones=TONES,
        landing_icon_count=(_manifest_cache["count"] if manifest() else 0),
        landing_default_icon=DEFAULT_ICON,
        landing_default_icon_src=icon_src(DEFAULT_ICON),
    )
    # Home page links join the command palette. cmdk_json is already a string
    # by the time we run, so add to it rather than rebuild it.
    try:
        data = json.loads(ctx.get("cmdk_json") or "{}")
        items = data.setdefault("items", [])
        for s in secs:
            for r in s["links"]:
                items.append({"g": "Home page", "t": r["title"], "nav": "landing", "srv": None,
                              "i": "app", "meta": s["name"] + ("" if r["enabled"] else " / hidden")})
        ctx["cmdk_json"] = json.dumps(data, ensure_ascii=True).replace("<", "\\u003c")
    except ValueError:
        pass
    return ctx


# ---------------------------------------------------------------- publish
def publish(A):
    """Write landing.json atomically. Returns None, or an error string."""
    secs = []
    for s in _sections(A, enabled_only=True):
        rows = []
        for r in _links(A, s["id"], enabled_only=True):
            rows.append({
                "id": r["id"], "title": r["title"], "url": r["url"],
                "description": r["description"] or "",
                "icon": r["icon"] or DEFAULT_ICON, "icon_kind": icon_kind(r["icon"]),
                "icon_html": icon_markup(r["icon"]),
                "tone": r["tone"] if r["tone"] in TONE_KEYS else "blue",
                "new_tab": bool(r["new_tab"]), "favorite": bool(r["favorite"]),
                "quick": bool(r["quick"]),
            })
        if rows:
            secs.append({"id": s["id"], "name": s["name"], "links": rows})
    doc = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "by": session.get("user", "-"),
        "sections": secs,
    }
    d = os.path.dirname(PUBLISH_PATH)
    try:
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".landing-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"))
            os.chmod(tmp, 0o644)
            os.replace(tmp, PUBLISH_PATH)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
    except OSError as exc:
        return str(exc)
    return None


def _publish_or_flash(A):
    err = publish(A)
    if err:
        flash("Saved, but the home page could not be updated: %s" % err, "error")
        A.audit("landing-publish-failed", err)
        return False
    return True


# ---------------------------------------------------------------- form helpers
def _clean_icon(raw):
    raw = (raw or "").strip()
    if raw and ICON_ID_RE.match(raw) and raw in manifest():
        return raw
    return DEFAULT_ICON


def _clean_tone(raw):
    raw = (raw or "").strip().lower()
    return raw if raw in TONE_KEYS else "blue"


def _next_order(A, table, where="", args=()):
    row = A.db().execute("SELECT MAX(sort_order) AS m FROM %s %s" % (table, where), args).fetchone()
    return (row["m"] or 0) + 10


def _renumber(A, table, rows):
    for i, r in enumerate(rows):
        A.db().execute("UPDATE %s SET sort_order=? WHERE id=?" % table, ((i + 1) * 10, r["id"]))


def _link_form(A):
    """Validate the add/edit link form. Returns (values, error)."""
    title = (request.form.get("title") or "").strip()
    url = A.safe_link_url(request.form.get("url"))
    desc = (request.form.get("description") or "").strip()
    try:
        section_id = int(request.form.get("section_id") or 0)
    except ValueError:
        section_id = 0
    if not title:
        return None, "Give the link a name."
    if not url:
        return None, "The web address must start with https:// (or be a /path on this site)."
    sec = A.db().execute("SELECT id FROM landing_sections WHERE id=?", (section_id,)).fetchone()
    if not sec:
        return None, "Pick a section for the link."
    return {
        "title": title[:TITLE_MAX], "url": url[:URL_MAX], "description": desc[:DESC_MAX],
        "section_id": section_id, "icon": _clean_icon(request.form.get("icon")),
        "tone": _clean_tone(request.form.get("tone")),
        "new_tab": 1 if request.form.get("new_tab") else 0,
        "favorite": 1 if request.form.get("favorite") else 0,
        "quick": 1 if request.form.get("quick") else 0,
    }, None


# ---------------------------------------------------------------- routes
def register(A):
    app = A.app

    # ---- icon library (behind the login; the picker fetches these) ----
    @app.route("/landing/icons.json")
    @A.login_required
    def landing_icons_manifest():
        path = os.path.join(ICON_DIR, "manifest.json")
        if not os.path.exists(path):
            return Response('{"count":0,"icons":[]}', mimetype="application/json")
        resp = send_from_directory(ICON_DIR, "manifest.json", mimetype="application/json")
        resp.headers["Cache-Control"] = "private, max-age=3600"
        return resp

    @app.route("/landing/icons/<kind>/<name>")
    @A.login_required
    def landing_icon_file(kind, name):
        if kind not in ("svg", "png"):
            abort(404)
        stem, dot, ext = name.rpartition(".")
        if ext != kind or not ICON_ID_RE.match(stem):
            abort(404)
        resp = send_from_directory(os.path.join(ICON_DIR, kind), name,
                                   mimetype="image/svg+xml" if kind == "svg" else "image/png")
        resp.headers["Cache-Control"] = "private, max-age=86400"
        return resp

    # ---- sections ----
    @app.route("/landing/sections", methods=["POST"])
    @A.requires("landing.manage")
    def landing_section_add():
        A.check_csrf()
        name = (request.form.get("name") or "").strip()[:SECTION_MAX]
        if not name:
            flash("Give the section a name.", "error")
            return redirect(BACK)
        A.db().execute(
            "INSERT INTO landing_sections(name,sort_order,enabled,created_at,created_by) VALUES(?,?,1,?,?)",
            (name, _next_order(A, "landing_sections"), A.now_iso(), session["user"]))
        A.db().commit()
        A.audit("landing-section-add", name)
        if _publish_or_flash(A):
            flash("Added the section “%s”. It shows on the home page once it has a link." % name, "ok")
        return redirect(BACK)

    @app.route("/landing/sections/<int:sec_id>/rename", methods=["POST"])
    @A.requires("landing.manage")
    def landing_section_rename(sec_id):
        A.check_csrf()
        row = A.db().execute("SELECT * FROM landing_sections WHERE id=?", (sec_id,)).fetchone()
        if not row:
            abort(404)
        name = (request.form.get("name") or "").strip()[:SECTION_MAX]
        if not name:
            flash("Give the section a name.", "error")
            return redirect(BACK)
        A.db().execute("UPDATE landing_sections SET name=? WHERE id=?", (name, sec_id))
        A.db().commit()
        A.audit("landing-section-rename", "%s -> %s" % (row["name"], name))
        if _publish_or_flash(A):
            flash("Renamed to “%s”." % name, "ok")
        return redirect(_back_section(sec_id))

    @app.route("/landing/sections/<int:sec_id>/move", methods=["POST"])
    @A.requires("landing.manage")
    def landing_section_move(sec_id):
        A.check_csrf()
        rows = _sections(A)
        idx = next((i for i, r in enumerate(rows) if r["id"] == sec_id), None)
        if idx is None:
            abort(404)
        swap = idx - 1 if request.form.get("dir") == "up" else idx + 1
        if 0 <= swap < len(rows):
            rows = list(rows)
            rows[idx], rows[swap] = rows[swap], rows[idx]
            _renumber(A, "landing_sections", rows)
            A.db().commit()
            A.audit("landing-section-move", "%s %s" % (rows[swap]["name"], request.form.get("dir")))
            _publish_or_flash(A)
        return redirect(_back_section(sec_id))

    @app.route("/landing/sections/<int:sec_id>/toggle", methods=["POST"])
    @A.requires("landing.manage")
    def landing_section_toggle(sec_id):
        A.check_csrf()
        row = A.db().execute("SELECT * FROM landing_sections WHERE id=?", (sec_id,)).fetchone()
        if not row:
            abort(404)
        new = 0 if row["enabled"] else 1
        A.db().execute("UPDATE landing_sections SET enabled=? WHERE id=?", (new, sec_id))
        A.db().commit()
        A.audit("landing-section-toggle", "%s: %s" % (row["name"], "shown" if new else "hidden"))
        if _publish_or_flash(A):
            flash("“%s” is now %s on the home page." % (row["name"], "showing" if new else "hidden"), "ok")
        return redirect(_back_section(sec_id))

    @app.route("/landing/sections/<int:sec_id>/delete", methods=["POST"])
    @A.requires("landing.manage")
    def landing_section_delete(sec_id):
        A.check_csrf()
        row = A.db().execute("SELECT * FROM landing_sections WHERE id=?", (sec_id,)).fetchone()
        if not row:
            abort(404)
        n = A.db().execute("SELECT COUNT(*) AS n FROM landing_links WHERE section_id=?", (sec_id,)).fetchone()["n"]
        if n:
            flash("“%s” still has %d link%s. Move or remove them first." % (row["name"], n, "" if n == 1 else "s"), "error")
            return redirect(BACK)
        A.db().execute("DELETE FROM landing_sections WHERE id=?", (sec_id,))
        A.db().commit()
        A.audit("landing-section-delete", row["name"])
        if _publish_or_flash(A):
            flash("Removed the section “%s”." % row["name"], "ok")
        return redirect(BACK)

    # ---- links ----
    @app.route("/landing/links", methods=["POST"])
    @A.requires("landing.manage")
    def landing_link_add():
        A.check_csrf()
        v, err = _link_form(A)
        if err:
            flash(err, "error")
            return redirect(BACK)
        A.db().execute(
            """INSERT INTO landing_links(section_id,title,url,description,icon,tone,new_tab,enabled,
                                         favorite,quick,sort_order,created_at,created_by)
               VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?)""",
            (v["section_id"], v["title"], v["url"], v["description"], v["icon"], v["tone"],
             v["new_tab"], v["favorite"], v["quick"],
             _next_order(A, "landing_links", "WHERE section_id=?", (v["section_id"],)),
             A.now_iso(), session["user"]))
        new_id = A.db().execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        A.db().commit()
        A.audit("landing-link-add", "%s -> %s" % (v["title"], v["url"]))
        if _publish_or_flash(A):
            flash("Added “%s”. It is live on the home page." % v["title"], "ok")
        return redirect(_back_link(new_id))

    @app.route("/landing/links/<int:link_id>/edit", methods=["POST"])
    @A.requires("landing.manage")
    def landing_link_edit(link_id):
        A.check_csrf()
        row = A.db().execute("SELECT * FROM landing_links WHERE id=?", (link_id,)).fetchone()
        if not row:
            abort(404)
        v, err = _link_form(A)
        if err:
            flash(err, "error")
            return redirect(BACK)
        moved = v["section_id"] != row["section_id"]
        A.db().execute(
            """UPDATE landing_links SET section_id=?,title=?,url=?,description=?,icon=?,tone=?,new_tab=?,
                                        favorite=?,quick=?,updated_at=?,updated_by=?%s WHERE id=?"""
            % (",sort_order=%d" % _next_order(A, "landing_links", "WHERE section_id=?", (v["section_id"],))
               if moved else ""),
            (v["section_id"], v["title"], v["url"], v["description"], v["icon"], v["tone"], v["new_tab"],
             v["favorite"], v["quick"], A.now_iso(), session["user"], link_id))
        A.db().commit()
        A.audit("landing-link-edit", "%s -> %s (icon %s)" % (v["title"], v["url"], v["icon"]))
        if _publish_or_flash(A):
            flash("Saved “%s”." % v["title"], "ok")
        return redirect(_back_link(link_id))

    @app.route("/landing/links/<int:link_id>/move", methods=["POST"])
    @A.requires("landing.manage")
    def landing_link_move(link_id):
        A.check_csrf()
        row = A.db().execute("SELECT * FROM landing_links WHERE id=?", (link_id,)).fetchone()
        if not row:
            abort(404)
        rows = list(_links(A, row["section_id"]))
        idx = next((i for i, r in enumerate(rows) if r["id"] == link_id), None)
        swap = idx - 1 if request.form.get("dir") == "up" else idx + 1
        if idx is not None and 0 <= swap < len(rows):
            rows[idx], rows[swap] = rows[swap], rows[idx]
            _renumber(A, "landing_links", rows)
            A.db().commit()
            A.audit("landing-link-move", "%s %s" % (row["title"], request.form.get("dir")))
            _publish_or_flash(A)
        return redirect(_back_link(link_id))

    @app.route("/landing/links/<int:link_id>/toggle", methods=["POST"])
    @A.requires("landing.manage")
    def landing_link_toggle(link_id):
        A.check_csrf()
        row = A.db().execute("SELECT * FROM landing_links WHERE id=?", (link_id,)).fetchone()
        if not row:
            abort(404)
        new = 0 if row["enabled"] else 1
        A.db().execute("UPDATE landing_links SET enabled=?,updated_at=?,updated_by=? WHERE id=?",
                       (new, A.now_iso(), session["user"], link_id))
        A.db().commit()
        A.audit("landing-link-toggle", "%s: %s" % (row["title"], "shown" if new else "hidden"))
        if _publish_or_flash(A):
            flash("“%s” is now %s." % (row["title"], "showing" if new else "hidden"), "ok")
        return redirect(_back_link(link_id))

    @app.route("/landing/links/<int:link_id>/delete", methods=["POST"])
    @A.requires("landing.manage")
    def landing_link_delete(link_id):
        A.check_csrf()
        row = A.db().execute("SELECT * FROM landing_links WHERE id=?", (link_id,)).fetchone()
        if not row:
            abort(404)
        A.db().execute("DELETE FROM landing_links WHERE id=?", (link_id,))
        A.db().commit()
        A.audit("landing-link-delete", "%s (%s)" % (row["title"], row["url"]))
        if _publish_or_flash(A):
            flash("Removed “%s” from the home page." % row["title"], "ok")
        return redirect(BACK)

    @app.route("/landing/reorder", methods=["POST"])
    @A.requires("landing.manage")
    def landing_reorder():
        """Drag-and-drop order from the canvas. JSON in, JSON out; the CSRF token
        travels in a header because there is no form. Body:
          {"links": {"<section id>": [link ids in order], ...}, "sections": [section ids in order]}
        A link listed under a section is moved into it."""
        tok = request.headers.get("X-CSRF", "")
        if not secrets.compare_digest(tok, session.get("csrf", "x")):
            return jsonify(ok=False, error="Your session changed. Reload the page."), 400
        data = request.get_json(silent=True) or {}
        db = A.db()
        moved = 0
        for sid, ids in (data.get("links") or {}).items():
            try:
                sid = int(sid)
                ids = [int(x) for x in ids][:500]
            except (TypeError, ValueError):
                return jsonify(ok=False, error="bad request"), 400
            if not db.execute("SELECT 1 FROM landing_sections WHERE id=?", (sid,)).fetchone():
                return jsonify(ok=False, error="that section no longer exists"), 400
            for i, lid in enumerate(ids):
                db.execute("UPDATE landing_links SET section_id=?, sort_order=?, updated_at=?, updated_by=? WHERE id=?",
                           (sid, (i + 1) * 10, A.now_iso(), session["user"], lid))
                moved += 1
        secs = data.get("sections") or []
        try:
            secs = [int(x) for x in secs][:200]
        except (TypeError, ValueError):
            return jsonify(ok=False, error="bad request"), 400
        for i, sid in enumerate(secs):
            db.execute("UPDATE landing_sections SET sort_order=? WHERE id=?", ((i + 1) * 10, sid))
        db.commit()
        A.audit("landing-reorder", "%d link(s), %d section(s)" % (moved, len(secs)))
        err = publish(A)
        if err:
            A.audit("landing-publish-failed", err)
            return jsonify(ok=False, error=err), 500
        return jsonify(ok=True, published=_published_at())

    @app.route("/landing/publish", methods=["POST"])
    @A.requires("landing.manage")
    def landing_publish():
        A.check_csrf()
        if _publish_or_flash(A):
            A.audit("landing-publish", PUBLISH_PATH)
            flash("Home page published.", "ok")
        return redirect(BACK)
