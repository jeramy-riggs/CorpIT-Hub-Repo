#!/usr/bin/env python3
"""
Enterprise Approval Portal — Backend API
accessportal.nrpi.local

Pure Python 3 standard library. Zero pip dependencies. Python 3.8+.
Provides persistence, email delivery, and admin auth for the portal frontend.

Usage:
    python3 app.py
    PORT=8001 DB_PATH=/opt/portal/portal.db python3 app.py

Environment variables:
    PORT            Port to listen on (default: 8001)
    DB_PATH         SQLite database path (default: portal.db next to app.py)
    CORS_ORIGIN     Allowed CORS origin (default: https://accessportal.nrpi.local)
    PORTAL_BASE_URL Public base URL used in outbound email links (default: CORS_ORIGIN)
    SMTP_HOST       SMTP server hostname
    SMTP_PORT       SMTP port (default: 587)
    SMTP_USER       SMTP username
    SMTP_PASS       SMTP password
    SMTP_TLS        Set to 0 to disable STARTTLS (default: 1)
    FROM_EMAIL      Sender address (default: portal@auction.com)
    HELPDESK_EMAIL  Service Desk address: approved-request fulfilment and
                    unroutable-step escalation (default: ServiceDesk@auction.com)

    CYBERSEC_EMAIL and PROCUREMENT_EMAIL are no longer read. Those two fixed
    recipients were removed on 2026-09-16; per-step recipients are configured by
    an administrator under Administration -> Notification Emails instead. Any
    leftover values in portal.env are ignored.
"""

from corpit_sqlite import connect_durable
import http.server
import uuid
from portal_activity import audit_events, route_name
import json
from corpit_durable import atomic_write_durable, durable_makedirs
import sqlite3
import os
import sys
import hashlib
import hmac
import shutil
import subprocess
import tempfile
import csv
import io
import re
import html
from html.parser import HTMLParser
import threading
import queue
import time
import traceback
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, quote as url_quote, urlencode
import base64
import secrets
import urllib.request
import urllib.error
from pathlib import Path

# ── CONFIG ──────────────────────────────────────────────────────────────────

PORT         = int(os.environ.get("PORT", 8001))
DB_PATH      = Path(os.environ.get("DB_PATH", Path(__file__).parent / "portal.db"))
BACKUP_DIR   = DB_PATH.parent / "backups"
KEEP_BACKUPS = 30
CORS_ORIGIN  = os.environ.get("CORS_ORIGIN", "https://accessportal.nrpi.local")
# Public base URL for links in outbound mail. Was hardcoded to the itam host, which
# would have sent every approver back to the old box after the corpit port.
PORTAL_BASE_URL = os.environ.get("PORTAL_BASE_URL", CORS_ORIGIN).rstrip("/")

# Hardening constants (2026-08-24)
MAX_BODY_BYTES = 512 * 1024                       # cap request bodies (DoS guard)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")  # also blocks CR/LF header injection
# Addresses the system ROUTES to (manager, ACL, per-step recipients) get the
# strict form: no angle brackets/quotes, so they are safe in mail HTML and audit.
ADDR_RE  = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
SUBMIT_WINDOW  = 3600                              # public-submission rate window (s)
SUBMIT_MAX     = int(os.environ.get("SUBMIT_MAX", "20"))  # max public submissions / IP / window
LOOKUP_WINDOW  = 600                               # public directory-lookup window (s)
LOOKUP_MAX     = 30                                # max lookups / IP / window
STATUS_WINDOW  = 600                               # public status-check window (s)
STATUS_MAX     = 60                                # max status checks / IP / window

# ── Directory lookup (R1, 2026-09-14/15) ─────────────────────────────────────
# The requester form's "Look up" used to hit the hub identity endpoint straight
# through nginx with every identity header blanked, so the hub refused it (401)
# and every requester record was hand-typed. app.py now proxies the lookup
# server-side to the hub's loopback-only, key-guarded relay
# (corpit-hub-api /internal/portal-lookup, built 2026-09-15 — same pattern as the
# mail relay), exact-match on email, and returns only the fields the form uses.
# The key never reaches the browser. Both values live in /etc/accessportal/portal.env.
LOOKUP_URL  = os.environ.get("PORTAL_LOOKUP_RELAY", "http://127.0.0.1:3001/internal/portal-lookup")
LOOKUP_KEY  = os.environ.get("PORTAL_LOOKUP_KEY",   "")
LOOKUP_KEY_HEADER = "X-Portal-Lookup-Key"
LOOKUP_ALLOWED_DOMAINS = [d.strip().lower() for d in
                          os.environ.get("PORTAL_LOOKUP_DOMAINS", "auction.com").split(",") if d.strip()]

# ── Silent corporate identity (2026-09-23) ───────────────────────────────────
# The requester side of this portal is deliberately NOT behind the SSO gate:
# anyone who can reach the host can file a request, because the people who file
# them are not all in the CorpIT Hub app-assignment groups. The cost of that is
# that "Full Name" and "Work Email" are free text, so a request can be filed
# under somebody else's name — by accident on a shared machine, or on purpose.
#
# This block adds a SILENT sign-in: a full-page redirect to Entra with
# prompt=none, which comes straight back if the browser already has a Microsoft
# session and returns an error (never a prompt, never a password box) if it does
# not. A requester who is signed in gets their own details filled in and locked;
# everyone else sees exactly the form that exists today. Nothing here can block
# a submission: every failure path falls through to the typed flow.
#
# It uses its OWN app registration, not the hub's. The hub's is
# assignment-required by design and requesters are deliberately not assigned to
# it, so reusing it would fail with AADSTS50105 for precisely the people this is
# for. See /etc/accessportal/portal.env.
#
# SILENT_AUTH_ON is false until all four values are set, and while it is false
# this whole feature is inert — the portal behaves exactly as it did before.
ENTRA_TENANT   = os.environ.get("PORTAL_ENTRA_TENANT_ID",     "").strip()
ENTRA_CLIENT   = os.environ.get("PORTAL_ENTRA_CLIENT_ID",     "").strip()
ENTRA_SECRET   = os.environ.get("PORTAL_ENTRA_CLIENT_SECRET", "").strip()
ENTRA_REDIRECT = os.environ.get("PORTAL_ENTRA_REDIRECT_URI",
                                "https://accessportal.nrpi.local/api/portal/identity/callback").strip()
ENTRA_AUTHORITY   = "https://login.microsoftonline.com"
IDENTITY_TTL_MIN  = int(os.environ.get("PORTAL_IDENTITY_TTL_MIN", "480") or 480)
IDENTITY_COOKIE   = "portal_identity"
IDENTITY_TRIED_COOKIE = "portal_silent_tried"   # readable by the page: "do not retry"
SILENT_AUTH_ON = bool(ENTRA_TENANT and ENTRA_CLIENT and ENTRA_SECRET and ENTRA_REDIRECT)

# ── Policy documents (2026-09-18) ────────────────────────────────────────────
# An administrator can upload the policy a form's acknowledgement refers to.
# The original is kept privately under POLICY_DIR; the PDF the form displays is
# written under POLICY_PUBLIC_DIR (served statically by nginx at
# POLICY_PUBLIC_URL). Word/PowerPoint are converted to PDF by LibreOffice when
# it is installed on this host; without it only PDF can be uploaded.
POLICY_DIR        = os.environ.get("POLICY_DIR",        "/var/lib/accessportal/policy")
POLICY_PUBLIC_DIR = os.environ.get("POLICY_PUBLIC_DIR", "/var/www/accessportal/policy")
POLICY_PUBLIC_URL = (os.environ.get("POLICY_PUBLIC_URL", "/policy") or "/policy").rstrip("/")
POLICY_MAX_BYTES  = int(os.environ.get("POLICY_MAX_BYTES", str(25 * 1024 * 1024)))
POLICY_FORMS      = {"aia", "cla"}                 # forms that carry an acknowledgement document
#   aia - AI Use Case Intake (step 4 of the request form)
#   cla - AI Policy acknowledgment (standalone; FTE intake path, 2026-09-23). Product-agnostic.
#         Not a REQUEST_TYPE: nothing is submitted for approval, the
#         person acknowledges a policy and that is the whole record.
# Forms whose acknowledgement is a record in its own right rather than a step
# inside a request. "aia" is NOT one of these: its checkbox lives in the AI
# Use Case Intake form and is captured with that request.
ACK_FORMS         = {"cla"}
ACK_LABELS        = {"cla": "Claude Access – Artificial Intelligence Policy Acknowledgment"}
SOFFICE           = os.environ.get("SOFFICE_BIN") or shutil.which("soffice") or shutil.which("libreoffice") or ""
_POLICY_EXT_ZIP   = {"docx", "pptx", "odt", "odp"}
_POLICY_EXT_OLE   = {"doc", "ppt"}
_POLICY_EXT_OK    = {"pdf"} | _POLICY_EXT_ZIP | _POLICY_EXT_OLE

# ── Mail relay config ─────────────────────────────────────────────────────────
# Mail goes through the api-beta loopback relay; Graph credentials and the
# sender identity live only on that side, where the portal cannot override them.
RELAY_URL = os.environ.get("PORTAL_MAIL_RELAY", "http://127.0.0.1:3001/internal/portal-mail/send")
RELAY_KEY = os.environ.get("PORTAL_MAIL_KEY",   "")

# The single fixed recipient: the Service Desk. Everything else is configured
# per approval step by an administrator under Notification Emails.
RECIPIENT_HELPDESK   = os.environ.get("HELPDESK_EMAIL",    "ServiceDesk@auction.com")

REQUEST_TYPES = {
    "oca": {"label": "Out-of-Country Access",      "prefix": "OCA",
            "workflow": ["manager","security","hr","clo"]},      # clo replaced legal 2026-09-18
    "aia": {"label": "AI Use Case Intake",          "prefix": "AIA",
            "workflow": ["manager","security","legal"]},
    "wua": {"label": "Website / URL Access",        "prefix": "WUA",
            "workflow": ["manager","security"]},
    "paa": {"label": "Privileged / Admin Access",   "prefix": "PAA",
            "workflow": ["manager","security","hr","legal"]},
    "ser": {"label": "Security Exception Request",  "prefix": "SER",
            "workflow": ["manager","security","legal","cto","ceo"]},
    "sir": {"label": "IT Security Incident Form",   "prefix": "SIR",
            "workflow": ["manager","security"]},
}

STEP_LABELS = {
    "manager":  "Dept. Manager",
    "security": "Security & Compliance",
    "hr":       "Human Resources",
    "legal":    "Legal",
    "clo":      "Chief Legal Officer",
    "cto":      "Chief Technology Officer",
    "ceo":      "Chief Executive Officer",
}

STEP_DESCRIPTIONS = {
    "manager":  "The requester's direct manager. Routed per request from the directory lookup; the address below is the fallback when a request carries no manager email.",
    "security": "Security & Compliance review of access, tooling, policy requests, security exceptions and incidents. Formerly split as Security & Compliance and Information Security; merged 2026-09-17.",
    "hr":       "Human Resources review for personnel-related access.",
    "legal":    "Legal review and sign-off.",
    "clo":      "Chief Legal Officer final approval for out-of-country access. A step of its own, so the CLO's address and name are set here without affecting the Legal team on other forms.",
    "cto":      "Chief Technology Officer sign-off on security exceptions.",
    "ceo":      "Chief Executive Officer sign-off on security exceptions.",
}

# Fields an administrator may correct on a submitted request (R8). Status,
# workflow and decisions are never editable — those only move through /decide.
EDITABLE_SUBMITTER_KEYS = {"name", "email", "dept", "title", "employee_id",
                           "manager_name", "manager_email", "manager_id"}

# ── DATABASE ─────────────────────────────────────────────────────────────────

DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS counters (
    type TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS requests (
    id            TEXT PRIMARY KEY,
    type          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    priority      TEXT NOT NULL DEFAULT 'normal',
    submitter     TEXT NOT NULL,   -- JSON blob
    details       TEXT NOT NULL,   -- JSON blob
    workflow      TEXT NOT NULL,   -- JSON array of step keys
    current_step  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id    TEXT NOT NULL REFERENCES requests(id),
    step          INTEGER NOT NULL,
    step_key      TEXT NOT NULL,
    step_label    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    approver_name TEXT,
    approver_role TEXT,
    comments      TEXT,
    signature     TEXT,
    decided_at    TEXT,
    UNIQUE(request_id, step)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    event      TEXT NOT NULL,
    actor      TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Approval Access (2026-09-16): who may SEE and DECIDE workflow steps. A
-- principal is an RBAC role key (ad_group, matched against X-ITAM-Roles) or a
-- lower-case email (user). 'all' = every key in STEP_LABELS, now and in the
-- future, resolved at request time; 'steps' = exactly the JSON-listed keys.
CREATE TABLE IF NOT EXISTS approval_access_policies (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL,
    principal_type TEXT    NOT NULL CHECK (principal_type IN ('ad_group','user')),
    principal_key  TEXT    NOT NULL,
    view_scope     TEXT    NOT NULL CHECK (view_scope   IN ('all','steps')),
    view_steps     TEXT    NOT NULL DEFAULT '[]',
    decide_scope   TEXT    NOT NULL CHECK (decide_scope IN ('all','steps')),
    decide_steps   TEXT    NOT NULL DEFAULT '[]',
    enabled        INTEGER NOT NULL DEFAULT 1,
    origin         TEXT    NOT NULL DEFAULT 'console',
    created_at     TEXT    NOT NULL, created_by TEXT NOT NULL DEFAULT '',
    updated_at     TEXT    NOT NULL, updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE (principal_type, principal_key)
);

-- A browser that proved a corporate identity (silent Entra sign-in). Only the
-- SHA-256 of the cookie value is stored, so a copy of this database is not a
-- pile of live sessions. "source" is 'entra' while the identity is in force and
-- 'discarded' once the requester has said "this is not me" -- the row is kept in
-- that case so the request can record that a verified identity was set aside.
CREATE TABLE IF NOT EXISTS identity_sessions (
    token_hash    TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    dept          TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    employee_id   TEXT NOT NULL DEFAULT '',
    manager_name  TEXT NOT NULL DEFAULT '',
    manager_email TEXT NOT NULL DEFAULT '',
    manager_id    TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT 'entra',
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_identity_expires ON identity_sessions(expires_at);

-- CLA-VERSIONING: every acknowledgement document ever published, kept forever.
-- Replacing a policy used to delete the previous PDF and overwrite the setting,
-- which meant an acknowledgement record could not show WHAT was acknowledged.
-- Rows here are never rewritten; retired_at is stamped when a newer version
-- takes over. The files they point at are never removed while a row survives.
CREATE TABLE IF NOT EXISTS policy_versions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    form           TEXT    NOT NULL,
    version        INTEGER NOT NULL,
    sha            TEXT    NOT NULL,
    url            TEXT    NOT NULL,
    file_name      TEXT    NOT NULL DEFAULT '',
    ext            TEXT    NOT NULL DEFAULT '',
    pages          INTEGER NOT NULL DEFAULT 0,
    pdf_size       INTEGER NOT NULL DEFAULT 0,
    effective_date TEXT    NOT NULL DEFAULT '',
    published_by   TEXT    NOT NULL DEFAULT '',
    published_at   TEXT    NOT NULL,
    retired_at     TEXT    NOT NULL DEFAULT '',
    UNIQUE (form, version)
);
CREATE INDEX IF NOT EXISTS ix_policy_versions_form ON policy_versions(form, version DESC);

-- One row per person per acknowledgement. Append-only: a correction is a new
-- row, never an edit, because this is the evidence that somebody agreed to a
-- specific version of a specific document on a specific day.
--
-- employment_* records WHY the person was on this path at the time. matched is
-- stored as text ('true' / 'false' / 'unknown') rather than a boolean because
-- "HR has no row for them" and "we could not ask HR" are different facts and
-- an audit that collapses them is worse than useless.
CREATE TABLE IF NOT EXISTS acknowledgments (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    form               TEXT    NOT NULL,
    email              TEXT    NOT NULL,
    name               TEXT    NOT NULL DEFAULT '',
    dept               TEXT    NOT NULL DEFAULT '',
    title              TEXT    NOT NULL DEFAULT '',
    manager_email      TEXT    NOT NULL DEFAULT '',
    policy_version_id  INTEGER,
    policy_version     INTEGER NOT NULL DEFAULT 0,
    policy_sha         TEXT    NOT NULL DEFAULT '',
    policy_url         TEXT    NOT NULL DEFAULT '',
    statement_sha      TEXT    NOT NULL DEFAULT '',
    ack_via            TEXT    NOT NULL DEFAULT '',
    employment_class   TEXT    NOT NULL DEFAULT '',
    employment_matched TEXT    NOT NULL DEFAULT '',
    employment_source  TEXT    NOT NULL DEFAULT '',
    identity_source    TEXT    NOT NULL DEFAULT '',
    employee_id        TEXT    NOT NULL DEFAULT '',
    statements_json    TEXT    NOT NULL DEFAULT '',
    signature          TEXT    NOT NULL DEFAULT '',
    sample             INTEGER NOT NULL DEFAULT 0,
    user_agent         TEXT    NOT NULL DEFAULT '',
    created_at         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ack_form_email ON acknowledgments(form, email, created_at DESC);

CREATE TABLE IF NOT EXISTS schema_migrations (
    key        TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"""

APPROVAL_ACCESS_SEED = [
    # name,                             type,       key,                 view,   view_steps,   decide, decide_steps
    ("Tier 2",                          "ad_group", "tier2",             "all",   [],           "all",   []),
    ("Manager approvers",               "ad_group", "approver-manager",  "steps", ["manager"],  "steps", ["manager"]),
    ("Security & Compliance approvers", "ad_group", "approver-security", "steps", ["security"], "steps", ["security"]),
    ("Human Resources approvers",       "ad_group", "approver-hr",       "steps", ["hr"],       "steps", ["hr"]),
    ("Legal approvers",                 "ad_group", "approver-legal",    "steps", ["legal"],    "steps", ["legal"]),
    ("Information Security approvers",  "ad_group", "approver-infosec",  "steps", ["security"],  "steps", ["security"]),
    ("CTO approvers",                   "ad_group", "approver-cto",      "steps", ["cto"],      "steps", ["cto"]),
    ("CEO approvers",                   "ad_group", "approver-ceo",      "steps", ["ceo"],      "steps", ["ceo"]),
]

# One SQLite connection PER THREAD (ThreadingHTTPServer runs a thread per
# request). The previous single shared connection let one thread's commit flush
# another thread's half-written transaction and raised cursor errors under load.
# WAL mode + busy_timeout let these connections read concurrently; write_lock
# serialises the few multi-statement writes that must be atomic (ID minting,
# decisions).
_thread_local = threading.local()
_schema_ready = False
_schema_lock  = threading.Lock()
write_lock    = threading.RLock()

def db():
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(str(DB_PATH), timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if conn.execute("PRAGMA synchronous").fetchone()[0] != 2:
            conn.close()
            raise RuntimeError("SQLite writer requires synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        global _schema_ready
        if not _schema_ready:
            with _schema_lock:
                if not _schema_ready:
                    conn.executescript(DDL)
                    conn.commit()
                    _seed_counters(conn)
                    _seed_approval_access(conn)
                    _migrate_department_access(conn)
                    _migrate_acknowledgments(conn)
                    _migrate_ack_eligibility(conn)
                    _migrate_archive(conn)
                    _migrate_ai_inventory(conn)
                    _retire_legacy_access(conn)
                    _schema_ready = True
        _thread_local.conn = conn
    return conn

def _migrate_acknowledgments(conn):
    """The acknowledgement page went from one tick box to a signed statement
    set. The record has to say which statements were on screen and what was
    signed, or it proves nothing later. Additive: existing rows keep ''."""
    columns = {r[1] for r in conn.execute("PRAGMA table_info(acknowledgments)")}
    for name, declaration in {
        "employee_id":     "TEXT NOT NULL DEFAULT ''",
        "statements_json": "TEXT NOT NULL DEFAULT ''",
        "signature":       "TEXT NOT NULL DEFAULT ''",
        "record_sha":      "TEXT NOT NULL DEFAULT ''",   # ACK-AUDIT: fingerprint of the immutable fields
        "client_ip":       "TEXT NOT NULL DEFAULT ''",   # ACK-AUDIT: X-Real-IP at signing
        "eligibility_source": "TEXT NOT NULL DEFAULT ''", # ACK-ELIG: hr_roster | admin_grant
        "superseded_at":     "TEXT NOT NULL DEFAULT ''",  # ACK-REACK: administrator asked this person to acknowledge again
        "superseded_by":     "TEXT NOT NULL DEFAULT ''",
        "superseded_reason": "TEXT NOT NULL DEFAULT ''",
        "reack_notified_at": "TEXT NOT NULL DEFAULT ''",  # ACK-REACK: last "please re-acknowledge" email
        "reack_notified_version": "INTEGER NOT NULL DEFAULT 0",
    }.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE acknowledgments ADD COLUMN {name} {declaration}")
    conn.commit()


def _migrate_archive(conn):
    """ARCHIVE (2026-09-30): a flag, never a delete. Archived rows leave the working views
    but stay in the database, the audit trail, exports and the requester's tracker. Additive."""
    for table in ("requests", "acknowledgments"):
        columns = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name in ("archived_at", "archived_by", "archived_reason", "archived_batch"):
            if name not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
    conn.commit()

ARCHIVE_EVENTS = ("request.archived", "request.unarchived", "acknowledgment.archived", "acknowledgment.unarchived", "archive.sweep")

def _archived_clause(qs: dict, alias: str = "") -> str:
    """SQL fragment for the ?archived= switch: '' (default) active only · '1' archived only · 'all' both."""
    mode = ((qs.get("archived") or [""])[0] or "").strip().lower()
    col = f"{alias}archived_at"
    if mode in ("1", "true", "yes"): return f"COALESCE({col},'')<>''"
    if mode == "all": return ""
    return f"COALESCE({col},'')=''"

# ── AI INVENTORY (2026-10-14) ────────────────────────────────────────────────
# InfoSec / Legal working register of AI/ML use cases: the AI_ML_Use_Inventory_Tracker
# workbook, column for column, kept inside the portal. Visible to administrators and to
# anyone holding the Security & Compliance ("security") or Legal step. Rows are created
# automatically when an AI Use Case Intake request is approved (intake values tagged
# "intake"), typed in by InfoSec / Legal, or imported from the workbook. Nothing is asked
# of requesters; the intake form is unchanged.
INV_STEPS = ("security", "legal")
# key, label, required, allowed values (None = free text), section, kind
INV_FIELDS = [
    ("dept",        "Department", 1, None, "Identity & ownership", "text"),
    ("name",        "Name of AI/ML use or system", 1, None, "Identity & ownership", "text"),
    ("what",        "What it does / business process it supports", 1, None, "Identity & ownership", "long"),
    ("cat",         "Category", 1, ["Built in-house (API/agent/automation/app)", "Embedded AI feature in SaaS", "Standalone AI tool/platform", "Dev tooling (coding assistant / CI-CD / IDE)", "Other"], "Identity & ownership", "select"),
    ("status",      "Status", 1, ["Production", "Pilot / POC", "In development", "Retired"], "Identity & ownership", "select"),
    ("golive",      "Go-live date (actual or planned)", 0, None, "Identity & ownership", "date"),
    ("bowner",      "Business owner", 1, None, "Identity & ownership", "text"),
    ("towner",      "Technical owner / custodian", 1, None, "Identity & ownership", "text"),
    ("vendor",      "AI vendor / platform", 1, None, "Platform & access", "text"),
    ("model",       "Model and version", 0, None, "Platform & access", "text"),
    ("access",      "Access method", 1, ["API", "MCP", "Embedded SaaS feature", "SDK / library", "Browser or desktop app", "In-house hosted model", "Other"], "Platform & access", "select"),
    ("agentic",     "Agentic? (multi-step actions without per-step human approval)", 1, ["Yes", "No", "Unsure"], "Platform & access", "select"),
    ("agtools",     "If agentic: tools and permissions it holds", 0, None, "Platform & access", "long"),
    ("host",        "Hosting / runtime", 0, None, "Platform & access", "text"),
    ("systems",     "Systems and data sources connected", 0, None, "Platform & access", "long"),
    ("sso",         "Okta / SSO used?", 1, ["Yes", "No", "Partial", "N/A"], "Platform & access", "select"),
    ("keys",        "Service account / API key management", 0, None, "Platform & access", "long"),
    ("instance",    "Instance type", 1, ["Private / enterprise", "Public / consumer", "Unsure"], "Platform & access", "select"),
    ("npi",         "Processes NPI?", 1, ["Yes", "No", "Unsure"], "Data", "select"),
    ("pii",         "Processes other PII?", 1, ["Yes", "No", "Unsure"], "Data", "select"),
    ("ip",          "Processes company IP / confidential?", 1, ["Yes", "No", "Unsure"], "Data", "select"),
    ("client",      "Processes client data (incl. loan-level data, client O365 content)?", 1, ["Yes", "No", "Unsure"], "Data", "select"),
    ("clients",     "If client data: which client(s)?", 0, None, "Data", "text"),
    ("consumer",    "Processes consumer (SmartSale) data?", 1, ["Yes", "No", "Unsure"], "Data", "select"),
    ("third",       "Data sent to or retained by a third party?", 1, ["Yes", "No", "Unsure"], "Third party & monitoring", "select"),
    ("training",    "Vendor training / retention status", 0, ["Contractually prohibited", "Opt-out configured", "Not prohibited", "Unknown"], "Third party & monitoring", "select"),
    ("siem",        "Logs sent to SIEM?", 1, ["Yes", "No", "Partial", "Unknown"], "Third party & monitoring", "select"),
    ("mon",         "Other monitoring", 0, None, "Third party & monitoring", "long"),
    ("aud",         "Users / audience", 1, ["Internal staff", "Clients / customers", "Buyers / sellers / consumers", "Automated - no users", "Mixed"], "Users & oversight", "select"),
    ("ext",         "Does any output reach clients, buyers, sellers, or consumers?", 1, ["Yes", "No", "Unsure"], "Users & oversight", "select"),
    ("oversight",   "Human oversight", 1, ["Human reviews before action", "Human reviews after action", "Fully automated", "N/A"], "Users & oversight", "select"),
    ("contractors", "Contractors / vendors involved in build or operation", 0, None, "Users & oversight", "text"),
    ("oss",         "Restrictive open-source components used or trained on?", 0, ["Yes", "No", "Unsure"], "Users & oversight", "select"),
    ("intake",      "Intake form submitted?", 1, ["Yes", "No", "Unsure"], "Governance", "select"),
    ("notes",       "Notes / open issues", 0, None, "Governance", "long"),
    # InfoSec / Legal review
    ("window",      "Reported during disclosure window?", 0, ["Yes", "No", "Unsure"], "InfoSec / Legal review", "select"),
    ("tier",        "Risk tier (InfoSec / Legal)", 0, ["Low", "Medium", "High"], "InfoSec / Legal review", "select"),
    ("capprov",     "Client approval required?", 0, ["Yes", "No", "TBD"], "InfoSec / Legal review", "select"),
    ("revby",       "Reviewed by", 0, None, "InfoSec / Legal review", "text"),
    ("revdate",     "Review date", 0, None, "InfoSec / Legal review", "date"),
    ("followup",    "InfoSec follow-up / gaps", 0, None, "InfoSec / Legal review", "long"),
]
INV_KEYS = [f[0] for f in INV_FIELDS]
INV_REQUIRED = [f[0] for f in INV_FIELDS if f[2]]
INV_REVIEW = ("window", "tier", "capprov", "revby", "revdate", "followup")
INV_ALLOWED = {f[0]: f[3] for f in INV_FIELDS if f[3]}
# workbook column headers (Inventory tab row 4) -> keys, for import and export
INV_SHEET_COLS = [("ID (InfoSec assigns)", "inv_id")] + [(f[1], f[0]) for f in INV_FIELDS[:35]] + [
    ("Required fields still blank", "blank"), ("Reported during disclosure window?", "window"),
    ("Auto-flag: high-risk trigger present", "flag"), ("Risk tier (InfoSec / Legal)", "tier"),
    ("Client approval required?", "capprov"), ("Reviewed by", "revby"), ("Review date", "revdate"),
    ("Next review due", "next"), ("InfoSec follow-up / gaps", "followup")]

INV_DDL = """
CREATE TABLE IF NOT EXISTS ai_inventory (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_id      TEXT NOT NULL UNIQUE,
    request_id  TEXT NOT NULL DEFAULT '',
    data        TEXT NOT NULL DEFAULT '{}',    -- {key: value}
    sources     TEXT NOT NULL DEFAULT '{}',    -- {key: 'intake' | 'intake_partial' | 'infosec' | 'import'}
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL,
    updated_by  TEXT NOT NULL DEFAULT '',
    import_ref  TEXT NOT NULL DEFAULT '',
    archived_at TEXT NOT NULL DEFAULT '',
    archived_by TEXT NOT NULL DEFAULT '',
    archived_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_ai_inventory_req ON ai_inventory(request_id);
"""

def _migrate_ai_inventory(conn):
    conn.executescript(INV_DDL); conn.commit()

def inventory_allowed(session: dict) -> bool:
    """Administrators, and anyone holding the Security & Compliance or Legal step (view or decide)."""
    if not session: return False
    if is_superadmin(session) or session.get("role") == "admin": return True
    try:
        acc = effective_access(session)
        held = set(acc.get("view_steps") or []) | set(acc.get("decide_steps") or [])
        return bool(held.intersection(INV_STEPS))
    except Exception:
        return False

def inv_next_id(conn) -> str:
    year = now_iso()[:4]
    row = conn.execute("SELECT inv_id FROM ai_inventory WHERE inv_id LIKE ? ORDER BY inv_id DESC LIMIT 1", (f"INV-{year}-%",)).fetchone()
    n = int(row[0].rsplit("-", 1)[1]) + 1 if row else 1
    return f"INV-{year}-{n:05d}"

def inv_calc(d: dict) -> dict:
    """The workbook's three formulas."""
    blank = sum(1 for k in INV_REQUIRED if not str(d.get(k) or "").strip())
    flag = "Review for High" if (d.get("npi") == "Yes" or d.get("client") == "Yes" or d.get("consumer") == "Yes"
                                 or d.get("ext") == "Yes" or d.get("oversight") == "Fully automated") else "-"
    nxt = ""
    tier, rd = d.get("tier") or "", (d.get("revdate") or "")[:10]
    if tier and rd:
        if tier == "Low": nxt = "On material change"
        else:
            try:
                y, m, dd = int(rd[:4]), int(rd[5:7]), int(rd[8:10]); m += 3 if tier == "High" else 12
                y += (m - 1) // 12; m = (m - 1) % 12 + 1
                import calendar
                dd = min(dd, calendar.monthrange(y, m)[1]); nxt = f"{y:04d}-{m:02d}-{dd:02d}"
            except Exception: nxt = ""
    overdue = bool(re.match(r"^\d{4}-\d{2}-\d{2}$", nxt) and nxt < now_iso()[:10])
    return {"blank": blank, "flag": flag, "next": nxt, "overdue": overdue}

def inv_row_public(row) -> dict:
    r = dict(row); d = json.loads(r.get("data") or "{}"); s = json.loads(r.get("sources") or "{}")
    out = {"id": r["id"], "inv_id": r["inv_id"], "request_id": r.get("request_id", ""), "created_at": r["created_at"], "created_by": r.get("created_by", ""),
           "updated_at": r["updated_at"], "updated_by": r.get("updated_by", ""), "import_ref": r.get("import_ref", ""),
           "archived_at": r.get("archived_at", ""), "data": {k: d.get(k, "") for k in INV_KEYS}, "sources": s}
    out.update(inv_calc(out["data"]))
    return out

def inventory_from_request(req: dict) -> tuple:
    """Pre-fill from an approved AI Use Case Intake request. Returns (data, sources).
    Only what the form actually asks; everything else stays blank for InfoSec / Legal."""
    sub = req.get("submitter") or {}; det = req.get("details") or {}
    data, src = {}, {}
    def put(k, v, how="intake"):
        v = str(v or "").strip()
        if v: data[k] = v; src[k] = how
    put("dept", sub.get("dept"))
    put("name", det.get("tool_name"))
    put("what", det.get("use_case"))
    put("bowner", sub.get("name"), "intake_partial")
    put("vendor", det.get("tool_vendor"), "intake_partial")
    cats = []
    if det.get("cat_automation"): cats.append("automation")
    if det.get("cat_productivity"): cats.append("productivity")
    if det.get("access_sysint") or det.get("access_agent"): put("cat", "Built in-house (API/agent/automation/app)", "intake_partial")
    elif det.get("tool_existing") in ("yes", "Yes", True): put("cat", "Standalone AI tool/platform", "intake_partial")
    if det.get("access_agent"): put("agentic", "Yes", "intake_partial")
    acc = []
    if det.get("access_sysint"): acc.append("API")
    elif det.get("access_agent"): acc.append("Other")
    elif any(det.get(k) for k in ("access_view", "access_individual", "access_team", "access_enterprise")): acc.append("Browser or desktop app")
    if acc: put("access", acc[0], "intake_partial")
    systems = [x for x in (det.get("adc_systems"), det.get("client_systems")) if x]
    put("systems", "; ".join(systems))
    pii = det.get("data_customer_pii") or det.get("data_employee")
    put("pii", "Yes" if pii else ("No" if det else ""))
    put("ip", "Yes" if det.get("data_confidential") else "No")
    put("client", "Yes" if det.get("data_client_sensitive") else "No")
    put("npi", "Yes" if (det.get("data_customer_pii") or det.get("data_client_sensitive")) else "Unsure", "intake_partial")
    tp = det.get("is_thirdparty")
    put("third", "Yes" if str(tp).lower() in ("yes", "true") else ("No" if str(tp).lower() == "no" else "Unsure"), "intake_partial")
    auds = [k for k in ("aud_individual", "aud_internal", "aud_customers", "aud_clients") if det.get(k)]
    if auds:
        if len(auds) > 1 and any(a in ("aud_customers", "aud_clients") for a in auds): put("aud", "Mixed")
        elif auds[0] in ("aud_individual", "aud_internal"): put("aud", "Internal staff")
        elif auds[0] == "aud_customers": put("aud", "Buyers / sellers / consumers")
        else: put("aud", "Clients / customers")
        put("ext", "Yes" if any(a in ("aud_customers", "aud_clients") for a in auds) else "No", "intake_partial")
    rp = str(det.get("review_process") or "").strip()
    if rp:
        low = rp.lower()
        if "before" in low or "prior" in low: put("oversight", "Human reviews before action", "intake_partial")
        elif "after" in low: put("oversight", "Human reviews after action", "intake_partial")
        elif "automat" in low and "no " in low: put("oversight", "Fully automated", "intake_partial")
        data["_review_text"] = rp
    put("intake", "Yes")
    put("notes", det.get("notes"))
    return data, src

def inventory_on_request_approved(req: dict):
    """Called after a decision. Creates the inventory row once, when an AIA request becomes approved. Never fatal."""
    try:
        if not req or req.get("type") != "aia" or req.get("status") != "approved": return
        conn = db()
        if conn.execute("SELECT 1 FROM ai_inventory WHERE request_id=?", (req["id"],)).fetchone(): return
        data, src = inventory_from_request(req)
        now = now_iso(); inv_id = inv_next_id(conn)
        with write_lock:
            conn.execute("INSERT INTO ai_inventory(inv_id,request_id,data,sources,created_at,created_by,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?)",
                         (inv_id, req["id"], json.dumps(data), json.dumps(src), now, "system:intake", now, "system:intake")); conn.commit()
        audit(req["id"], "inventory.created", "System", "Automation", f"{inv_id} created from approved intake · {len(src)} fields pre-filled")
        audit(inv_id, "inventory.created", "System", "Automation", f"from {req['id']}")
    except Exception as e:
        print(f"[INVENTORY] auto-create failed: {e}", file=sys.stderr)

def _xlsx_rows(data: bytes, sheet_name: str = "Inventory") -> list:
    """Minimal .xlsx reader (stdlib only): rows of the named sheet as lists of strings."""
    import zipfile, xml.etree.ElementTree as ET
    z = zipfile.ZipFile(io.BytesIO(data))
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main", "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
    rid_to_target = {r.get("Id"): r.get("Target") for r in rels}
    target = None
    for s in wb.find("m:sheets", ns):
        if s.get("name") == sheet_name:
            t = rid_to_target.get(s.get("{%s}id" % ns["r"])); target = t if t.startswith("/") else "xl/" + t; break
    if not target: raise ValueError(f"No '{sheet_name}' sheet in the workbook")
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", ns):
            shared.append("".join(t.text or "" for t in si.iter("{%s}t" % ns["m"])))
    sheet = ET.fromstring(z.read(target.lstrip("/")))
    def col_idx(ref):
        n = 0
        for ch in ref:
            if ch.isalpha(): n = n * 26 + (ord(ch.upper()) - 64)
            else: break
        return n - 1
    rows = []
    for row in sheet.iter("{%s}row" % ns["m"]):
        vals = []
        for c in row.findall("m:c", ns):
            i = col_idx(c.get("r") or ""); v = c.find("m:v", ns); t = c.get("t"); text = ""
            if t == "s" and v is not None: text = shared[int(v.text)] if v.text and int(v.text) < len(shared) else ""
            elif t == "inlineStr": text = "".join(x.text or "" for x in c.iter("{%s}t" % ns["m"]))
            elif v is not None: text = v.text or ""
            if text and t != "s" and t != "inlineStr" and c.get("s") and re.match(r"^\d+(\.\d+)?$", text) and 20000 < float(text) < 80000:
                # Excel serial date -> ISO (the workbook asks for YYYY-MM-DD; departments type dates anyway)
                try:
                    base = datetime(1899, 12, 30); text = (base + timedelta(days=int(float(text)))).strftime("%Y-%m-%d")
                except Exception: pass
            while len(vals) <= i: vals.append("")
            vals[i] = text.strip()
        rows.append(vals)
    return rows

def _xlsx_bytes(headers: list, rows: list, sheet_name: str = "Inventory") -> bytes:
    """Minimal .xlsx writer (inline strings) in the workbook's column order."""
    import zipfile
    def X(s): return html.escape(str(s if s is not None else ""), quote=True)
    def cell(ci, ri, v):
        col = ""; n = ci + 1
        while n: n, r = divmod(n - 1, 26); col = chr(65 + r) + col
        return f'<c r="{col}{ri}" t="inlineStr"><is><t xml:space="preserve">{X(v)}</t></is></c>'
    body = "".join(f'<row r="{ri}">' + "".join(cell(ci, ri, v) for ci, v in enumerate(r)) + "</row>" for ri, r in enumerate([headers] + rows, start=1))
    sheet = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{body}</sheetData></worksheet>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml", f'<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="{X(sheet_name)}" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue()

def inv_validate(d: dict) -> list:
    """Allowed-value check. Returns list of 'Field: problem' strings."""
    probs = []
    for k, allowed in INV_ALLOWED.items():
        v = str(d.get(k) or "").strip()
        if v and v not in allowed:
            probs.append(f"{dict((f[0], f[1]) for f in INV_FIELDS)[k]}: \"{v}\" is not an allowed value")
    for k in ("golive", "revdate"):
        v = str(d.get(k) or "").strip()
        if v and not re.match(r"^\d{4}-\d{2}-\d{2}$", v): probs.append(f"{k}: use YYYY-MM-DD")
    return probs
# Coverage map: workbook field -> what the live AI Use Case Intake form (AIA) provides. Shown on the Coverage gaps page.
INV_COVERAGE = [
 {
  "key": "id",
  "field": "ID (InfoSec assigns)",
  "required": 0,
  "coverage": "calc",
  "intake_field": "\u2014",
  "how": "Portal assigns INV-YYYY-NNNNN on creation (request ID kept as link)",
  "section": "Identity & ownership"
 },
 {
  "key": "dept",
  "field": "Department",
  "required": 1,
  "coverage": "ok",
  "intake_field": "Requester \u2192 Department (Step 1)",
  "how": "Copied from the submitter record",
  "section": "Identity & ownership"
 },
 {
  "key": "name",
  "field": "Name of AI/ML use or system",
  "required": 1,
  "coverage": "ok",
  "intake_field": "What tool, agent, or AI functionality are you requesting? (f-toolname)",
  "how": "Copied; Field Guide calls it \"Use Case / Project Name\"",
  "section": "Identity & ownership"
 },
 {
  "key": "what",
  "field": "What it does / business process",
  "required": 1,
  "coverage": "ok",
  "intake_field": "Business Purpose / AI Use Case (f-usecase)",
  "how": "Copied; Field Guide calls it \"Intended Use\"",
  "section": "Identity & ownership"
 },
 {
  "key": "cat",
  "field": "Category",
  "required": 1,
  "coverage": "warn",
  "intake_field": "Purpose Category (productivity / automation / other) + Existing-or-new tool",
  "how": "Different taxonomy; suggest a 5-value pick-list in the intake",
  "section": "Identity & ownership"
 },
 {
  "key": "status",
  "field": "Status",
  "required": 1,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Not asked. Add pick-list: Production / Pilot-POC / In development / Retired",
  "section": "Identity & ownership"
 },
 {
  "key": "golive",
  "field": "Go-live date (actual or planned)",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014 (Field Guide expects \"Target Go-Live\")",
  "how": "Not on the live form. Add date field",
  "section": "Identity & ownership"
 },
 {
  "key": "bowner",
  "field": "Business owner",
  "required": 1,
  "coverage": "warn",
  "intake_field": "Requester name (Step 1)",
  "how": "Requester is not always the business owner; add an explicit field",
  "section": "Identity & ownership"
 },
 {
  "key": "towner",
  "field": "Technical owner / custodian",
  "required": 1,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add name/email field",
  "section": "Identity & ownership"
 },
 {
  "key": "vendor",
  "field": "AI vendor / platform",
  "required": 1,
  "coverage": "warn",
  "intake_field": "Vendor / tool name and website (f-vendor) \u2014 only when \"new tool\"",
  "how": "Approved-tool path has no vendor field; add always-on field",
  "section": "Platform & access"
 },
 {
  "key": "model",
  "field": "Model and version",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add free text (\"Unknown\" allowed)",
  "section": "Platform & access"
 },
 {
  "key": "access",
  "field": "Access method",
  "required": 1,
  "coverage": "warn",
  "intake_field": "Level of Access Sought (view / individual / team / enterprise / system integration / agent)",
  "how": "Overlaps but not the same list (API, MCP, SDK\u2026); add pick-list",
  "section": "Platform & access"
 },
 {
  "key": "agentic",
  "field": "Agentic?",
  "required": 1,
  "coverage": "warn",
  "intake_field": "Level of Access: \"agent\" checkbox",
  "how": "Derived Yes when checked; otherwise unknown. Add explicit Yes/No/Unsure",
  "section": "Platform & access"
 },
 {
  "key": "agtools",
  "field": "If agentic: tools and permissions",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add conditional free text",
  "section": "Platform & access"
 },
 {
  "key": "host",
  "field": "Hosting / runtime",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add free text",
  "section": "Platform & access"
 },
 {
  "key": "systems",
  "field": "Systems and data sources connected",
  "required": 0,
  "coverage": "ok",
  "intake_field": "Which systems / applications? (f-adc-systems) + Which Customer or Client systems? (f-client-systems)",
  "how": "Concatenated",
  "section": "Platform & access"
 },
 {
  "key": "sso",
  "field": "Okta / SSO used?",
  "required": 1,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add Yes / No / Partial / N/A",
  "section": "Platform & access"
 },
 {
  "key": "keys",
  "field": "Service account / API key management",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add free text",
  "section": "Platform & access"
 },
 {
  "key": "instance",
  "field": "Instance type",
  "required": 1,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add Private-enterprise / Public-consumer / Unsure",
  "section": "Platform & access"
 },
 {
  "key": "npi",
  "field": "Processes NPI?",
  "required": 1,
  "coverage": "warn",
  "intake_field": "Data Types: Customer Personal Information / Client sensitive data (loan-level\u2026)",
  "how": "NPI is not its own checkbox; derived Yes if either ticked, else Unsure",
  "section": "Data"
 },
 {
  "key": "pii",
  "field": "Processes other PII?",
  "required": 1,
  "coverage": "ok",
  "intake_field": "Data Types: Customer Personal Information, Employee Information",
  "how": "Yes if either ticked",
  "section": "Data"
 },
 {
  "key": "ip",
  "field": "Processes company IP / confidential?",
  "required": 1,
  "coverage": "ok",
  "intake_field": "Data Types: Company confidential or proprietary",
  "how": "Yes if ticked",
  "section": "Data"
 },
 {
  "key": "client",
  "field": "Processes client data?",
  "required": 1,
  "coverage": "ok",
  "intake_field": "Data Types: Client sensitive data (loan-level, client O365\u2026)",
  "how": "Yes if ticked",
  "section": "Data"
 },
 {
  "key": "clients",
  "field": "If client data: which client(s)?",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add conditional free text",
  "section": "Data"
 },
 {
  "key": "consumer",
  "field": "Processes consumer (SmartSale) data?",
  "required": 1,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add Yes / No / Unsure",
  "section": "Data"
 },
 {
  "key": "third",
  "field": "Data sent to or retained by a third party?",
  "required": 1,
  "coverage": "warn",
  "intake_field": "\"Is this a third-party tool or vendor?\" (Section 2) \u00b7 Data Types: Third-party / licensed data",
  "how": "Different question (data *from* third parties). Add explicit Yes/No/Unsure",
  "section": "Third party & monitoring"
 },
 {
  "key": "training",
  "field": "Vendor training / retention status",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014 (Field Guide expects \"Training Restrictions, Data Retention\")",
  "how": "Not on the live form. Add 4-value pick-list",
  "section": "Third party & monitoring"
 },
 {
  "key": "siem",
  "field": "Logs sent to SIEM?",
  "required": 1,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "InfoSec usually knows; add Yes / No / Partial / Unknown, default Unknown",
  "section": "Third party & monitoring"
 },
 {
  "key": "mon",
  "field": "Other monitoring",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add free text",
  "section": "Third party & monitoring"
 },
 {
  "key": "aud",
  "field": "Users / audience",
  "required": 1,
  "coverage": "ok",
  "intake_field": "Users & Audience checkboxes (individual / internal / customers / clients)",
  "how": "Mapped to the 5-value list; Mixed when several ticked",
  "section": "Users & oversight"
 },
 {
  "key": "ext",
  "field": "Output reaches clients, buyers, sellers, consumers?",
  "required": 1,
  "coverage": "warn",
  "intake_field": "Users & Audience: Customers / Clients ticked",
  "how": "Derived Yes; Field Guide expects \"External Consumption\". Add explicit question",
  "section": "Users & oversight"
 },
 {
  "key": "oversight",
  "field": "Human oversight",
  "required": 1,
  "coverage": "warn",
  "intake_field": "What process of human review or audit\u2026 (f-review-process, free text)",
  "how": "Free text; needs the 4-value pick-list to be comparable",
  "section": "Users & oversight"
 },
 {
  "key": "contractors",
  "field": "Contractors / vendors involved",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add free text or \"None\"",
  "section": "Users & oversight"
 },
 {
  "key": "oss",
  "field": "Restrictive open-source components?",
  "required": 0,
  "coverage": "bad",
  "intake_field": "\u2014",
  "how": "Add Yes / No / Unsure",
  "section": "Users & oversight"
 },
 {
  "key": "intake",
  "field": "Intake form submitted?",
  "required": 1,
  "coverage": "ok",
  "intake_field": "The request itself (AIA-YYYY-NNNNN)",
  "how": "Yes with ID when created from a request; No for department returns",
  "section": "Governance"
 },
 {
  "key": "notes",
  "field": "Notes / open issues",
  "required": 0,
  "coverage": "ok",
  "intake_field": "Additional Notes (f-notes)",
  "how": "Copied",
  "section": "Governance"
 },
 {
  "key": "blank",
  "field": "Required fields still blank",
  "required": 0,
  "coverage": "calc",
  "intake_field": "\u2014",
  "how": "Count of the 23 required columns that are empty",
  "section": "Calculated"
 },
 {
  "key": "window",
  "field": "Reported during disclosure window?",
  "required": 0,
  "coverage": "legal",
  "intake_field": "\u2014",
  "how": "InfoSec sets; only if the window is authorized by the CLO",
  "section": "InfoSec / Legal review"
 },
 {
  "key": "flag",
  "field": "Auto-flag: high-risk trigger present",
  "required": 0,
  "coverage": "calc",
  "intake_field": "\u2014",
  "how": "\"Review for High\" when NPI, client, consumer, external output = Yes or oversight = Fully automated",
  "section": "Calculated"
 },
 {
  "key": "tier",
  "field": "Risk tier (InfoSec / Legal)",
  "required": 0,
  "coverage": "legal",
  "intake_field": "\u2014 (Field Guide: \"Risk Assessment\")",
  "how": "Set after review: Low / Medium / High",
  "section": "InfoSec / Legal review"
 },
 {
  "key": "capprov",
  "field": "Client approval required?",
  "required": 0,
  "coverage": "legal",
  "intake_field": "\u2014",
  "how": "Yes / No / TBD",
  "section": "InfoSec / Legal review"
 },
 {
  "key": "revby",
  "field": "Reviewed by",
  "required": 0,
  "coverage": "legal",
  "intake_field": "\u2014",
  "how": "Signed-in reviewer, auto-filled on Save review",
  "section": "InfoSec / Legal review"
 },
 {
  "key": "revdate",
  "field": "Review date",
  "required": 0,
  "coverage": "legal",
  "intake_field": "\u2014",
  "how": "Set on Save review",
  "section": "InfoSec / Legal review"
 },
 {
  "key": "next",
  "field": "Next review due",
  "required": 0,
  "coverage": "calc",
  "intake_field": "\u2014",
  "how": "High +3 months \u00b7 Medium +12 months \u00b7 Low \"On material change\"",
  "section": "Calculated"
 },
 {
  "key": "followup",
  "field": "InfoSec follow-up / gaps",
  "required": 0,
  "coverage": "legal",
  "intake_field": "\u2014",
  "how": "Free text; shown on the dashboard as \"open follow-up\"",
  "section": "InfoSec / Legal review"
 }
]
# ── end AI INVENTORY helpers ─────────────────────────────────────────────────

def _migrate_ack_eligibility(conn):
    """ACK-ELIG: administrator exception list for the acknowledgement option. HR status
    (Regular FT) is the automatic path; rows here ADD (allow) or WITHHOLD (block).
    Soft-removed so the history of who granted what stays."""
    conn.execute("""CREATE TABLE IF NOT EXISTS ack_eligibility (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        form TEXT NOT NULL DEFAULT 'cla',
        email TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        mode TEXT NOT NULL,                      -- allow | block
        reason TEXT NOT NULL DEFAULT '',
        added_by TEXT NOT NULL DEFAULT '',
        added_at TEXT NOT NULL,
        removed_by TEXT NOT NULL DEFAULT '',
        removed_at TEXT NOT NULL DEFAULT '',
        notified_at TEXT NOT NULL DEFAULT ''
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_ack_elig_email ON ack_eligibility(form, email, removed_at)")
    conn.commit()

def _retire_legacy_access(conn):
    """Refuse to discard any unconverted grant; old data remains in backups."""
    marker = "approval_access_single_owner_v1"
    if conn.execute("SELECT 1 FROM schema_migrations WHERE key=?", (marker,)).fetchone():
        return
    for row in conn.execute("SELECT key,value FROM settings WHERE key LIKE 'approver_acl_%'"):
        value = json.loads(row["value"])
        if value:
            raise RuntimeError("Legacy approver assignments need reconciliation before cleanup: " + row["key"])
    conn.execute("DELETE FROM settings WHERE key LIKE 'approver_acl_%' OR key='approver_directory'")
    conn.execute("INSERT INTO schema_migrations(key,applied_at) VALUES(?,?)", (marker, now_iso()))
    conn.commit()

def _seed_counters(conn):
    for t in REQUEST_TYPES:
        conn.execute(
            "INSERT OR IGNORE INTO counters(type, value) VALUES (?,0)", (t,))
    conn.commit()

def _seed_approval_access(conn):
    """Idempotent first-run seed of approval_access_policies, gated by the
    schema_migrations marker so it runs exactly once per database."""
    marker = "approval_access_v1"
    if conn.execute("SELECT 1 FROM schema_migrations WHERE key=?", (marker,)).fetchone():
        return
    ts = now_iso()
    for name, ptype, pkey, vscope, vsteps, dscope, dsteps in APPROVAL_ACCESS_SEED:
        conn.execute(
            """INSERT OR IGNORE INTO approval_access_policies
               (name,principal_type,principal_key,view_scope,view_steps,decide_scope,decide_steps,
                enabled,origin,created_at,created_by,updated_at,updated_by)
               VALUES(?,?,?,?,?,?,?,1,'seed',?,'seed',?,'seed')""",
            (name, ptype, pkey, vscope, json.dumps(vsteps), dscope, json.dumps(dsteps), ts, ts))
    conn.execute("INSERT OR IGNORE INTO schema_migrations(key,applied_at) VALUES(?,?)", (marker, ts))
    conn.commit()


def _migrate_department_access(conn):
    """Additive migration. Preserve policy ids, disabled grants and current workflows."""
    columns = {r[1] for r in conn.execute("PRAGMA table_info(approval_access_policies)")}
    for name, declaration in {
        "request_types": "TEXT NOT NULL DEFAULT '[]'",
        "expires_at": "TEXT", "reason": "TEXT NOT NULL DEFAULT ''",
        "effect": "TEXT NOT NULL DEFAULT 'allow'",
    }.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE approval_access_policies ADD COLUMN {name} {declaration}")
    marker = "department_access_v2"
    if not conn.execute("SELECT 1 FROM schema_migrations WHERE key=?", (marker,)).fetchone():
        # InfoSec was merged into security in the live workflows on September 17.
        for row in conn.execute("SELECT id,view_steps,decide_steps FROM approval_access_policies"):
            for field in ("view_steps", "decide_steps"):
                steps = json.loads(row[field])
                if "infosec" in steps:
                    steps = list(dict.fromkeys("security" if x == "infosec" else x for x in steps))
                    conn.execute(f"UPDATE approval_access_policies SET {field}=? WHERE id=?", (json.dumps(steps), row["id"]))
        # Bring the existing per-step manual lists into the same person editor.
        # If a user already has a policy, preserve that independent legacy grant.
        legacy = {}
        original = {}
        for step in STEP_LABELS:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (f"approver_acl_{step}",)).fetchone()
            emails = json.loads(row[0]) if row else []
            if isinstance(emails, str): emails = emails.split(",")
            original[step] = [str(e).strip().lower() for e in emails if str(e).strip()]
            for email in original[step]: legacy.setdefault(email, []).append(step)
        migrated = set()
        ts = now_iso()
        for email, steps in legacy.items():
            if conn.execute("SELECT 1 FROM approval_access_policies WHERE principal_type='user' AND principal_key=?", (email,)).fetchone():
                continue
            conn.execute("""INSERT INTO approval_access_policies
                (name,principal_type,principal_key,view_scope,view_steps,decide_scope,decide_steps,enabled,origin,created_at,created_by,updated_at,updated_by,reason)
                VALUES(?,'user',?,'steps',?,'steps',?,1,'legacy-manual',?,'migration',?,'migration',?)""",
                (email[:80],email,json.dumps(steps),json.dumps(steps),ts,ts,"Preserved existing manual department assignments"))
            migrated.add(email)
        for step, emails in original.items():
            conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (f"approver_acl_{step}",json.dumps([e for e in emails if e not in migrated])))
        if migrated:
            conn.execute("INSERT INTO audit_log(request_id,event,actor,role,note,created_at) VALUES(NULL,?,?,?,?,?)",
                         ("approval_access.migrated","System","migration",json.dumps({"users":sorted(migrated),"reason":"Consolidated existing assignments; no new grants"}),ts))
        conn.execute("INSERT INTO schema_migrations(key,applied_at) VALUES(?,?)", (marker, now_iso()))
    conn.commit()

def next_request_id(type_key: str) -> str:
    conn = db()
    with write_lock:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE counters SET value=value+1 WHERE type=?", (type_key,))
        row = conn.execute("SELECT value FROM counters WHERE type=?", (type_key,)).fetchone()
        conn.commit()
    prefix = REQUEST_TYPES[type_key]["prefix"]
    year   = datetime.now(timezone.utc).year
    return f"{prefix}-{year}-{row['value']:05d}"

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ── BACKUP ────────────────────────────────────────────────────────────────────

def take_backup():
    if not DB_PATH.exists():
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest  = BACKUP_DIR / f"portal_{stamp}.db"
    # Online backup API: captures WAL-pending writes and yields a transactionally
    # consistent copy (a plain file copy misses the -wal sidecar → empty/torn DB).
    _src = sqlite3.connect(str(DB_PATH))
    try:
        _dst = connect_durable(str(dest))
        with _dst:
            _src.backup(_dst)
        _dst.close()
    finally:
        _src.close()
    # prune old backups
    backups = sorted(BACKUP_DIR.glob("portal_*.db"))
    for old in backups[:-KEEP_BACKUPS]:
        old.unlink(missing_ok=True)

# ── AUTH ──────────────────────────────────────────────────────────────────────

def _parse_roles(raw) -> list:
    """X-ITAM-Roles → ordered, lower-cased, de-duplicated list of role keys."""
    out = []
    for x in (raw or "").split(","):
        k = x.strip().lower()
        if k and k not in out:
            out.append(k)
    return out


def session_from_request(handler) -> dict | None:
    # PRIMARY: the nginx gate verifies the company Entra session and injects the
    # user's email as X-ITAM-User-Email on gated routes (and strips any client
    # copy). A present value is therefore an authenticated ITAM user — identity
    # is SSO, not the app's own password.
    sso_email = (handler.headers.get("X-ITAM-User-Email") or "").strip().lower()
    if sso_email:
        # The shared gate is the sole authority for identity and configuration
        # level. Retired local account rows cannot elevate a corporate identity.
        sso_tier  = (handler.headers.get("X-ITAM-Tier") or "").strip().lower()
        # X-ITAM-Level is the RBAC page level for 'approver-portal' (read|admin) and
        # X-ITAM-Sections the tabs this user may see — both resolved by the gate from
        # the ITAM RBAC console, both nginx-authoritative (blanked on public paths).
        sso_level = (handler.headers.get("X-ITAM-Level") or "").strip().lower()
        # X-ITAM-Roles: the user's RBAC role keys (e.g. "tier2,approver-legal"),
        # resolved by the gate. A role grants NOTHING by itself — it only matches
        # enabled ad_group rows in approval_access_policies (effective_access()).
        # X-ITAM-Steps is LEGACY (2026-09-16) and deliberately not read: AD group
        # membership confers approval rights only through a policy row.
        sso_roles = _parse_roles(handler.headers.get("X-ITAM-Roles"))
        # Page-level admin (Administrator tile + config pages). Never a decision right.
        is_admin  = (sso_level == "admin") or (sso_tier == "superadmin")
        # Portal super-admin: unfiltered visibility + policy administration.
        # Decisions still need an explicit grant covering the step.
        is_super  = (sso_tier == "superadmin")
        return {"email": sso_email,
                "name": sso_email.split("@")[0],
                "role": "admin" if is_admin else "approver",
                "source": "sso", "tier": sso_tier,
                "level": sso_level,
                "roles": sso_roles, "is_superadmin": is_super}
    return None


# ── SETTINGS ──────────────────────────────────────────────────────────────────

def get_setting(key: str, default=None):
    row = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row:
        try:
            return json.loads(row["value"])
        except Exception:
            return row["value"]
    return default

def set_setting(key: str, value):
    db().execute(
        "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)))
    db().commit()


# ── Site content: Administrator-editable front-facing text ───────────────────
# Stored in the existing settings KV table as "content.<key>". GET is public and
# returns ONLY these keys; writes require role=admin. Values are plain text —
# tags stripped, whitespace collapsed, length-capped, placeholders whitelisted.
CONTENT_KEYS = {
    "site.title": (60, "text"),            "site.subtitle": (60, "text"),
    "hero.badge": (40, "text"),            "hero.heading": (80, "text"),
    "hero.body": (220, "multiline"),       "hero.search_placeholder": (90, "text"),
    "hero.note": (120, "text"),
    "types.heading": (80, "text"),         "types.intro": (100, "text"),
    "type.oca.label": (40, "text"),        "type.oca.desc": (160, "text"),
    "type.aia.label": (40, "text"),        "type.aia.desc": (160, "text"),
    "type.wua.label": (40, "text"),        "type.wua.desc": (160, "text"),
    "type.paa.label": (40, "text"),        "type.paa.desc": (160, "text"),
    "type.ser.label": (40, "text"),        "type.ser.desc": (160, "text"),
    "type.sir.label": (40, "text"),        "type.sir.desc": (160, "text"),
    "footer.org": (80, "text"),            "footer.contact_label": (40, "text"),
    "footer.contact_email": (120, "email"),
    "confirm.heading": (60, "text"),       "confirm.body": (240, "multiline"),
    "approver.role_subtitle": (80, "text"),"approver.greeting_suffix": (120, "text"),
    # ── notification email wording (2026-09-16) ──────────────────────────────
    # Administrator-editable sentences inside the outbound emails. Structure,
    # subject lines and the HTML shell stay fixed in this service; these are the
    # lines that get reworded in practice. Values are plain text: content_clean
    # strips tags, and email_text() escapes on render, so an administrator
    # cannot inject markup into a requester's inbox.
    "email.footer":            (120, "text"),
    "email.submitted.intro":   (300, "multiline"),
    "email.submitted.closing": (200, "multiline"),
    "email.approver.intro":    (300, "multiline"),
    "email.approved.closing":  (300, "multiline"),
    "email.rejected.closing":  (400, "multiline"),
    "email.returned.closing":  (400, "multiline"),
    # ── approval step display names (2026-09-17) ─────────────────────────────
    # Renaming a step changes only what people READ. The step key and its AD
    # group (approver-<key>) are structural and never change, so nothing about
    # who may approve moves when a label is edited. Edited from Manage Roles.
    "step.manager.label":  (40, "text"),
    "step.security.label": (40, "text"),
    "step.hr.label":       (40, "text"),
    "step.legal.label":    (40, "text"),
    "step.clo.label":      (40, "text"),
    "step.cto.label":      (40, "text"),
    "step.ceo.label":      (40, "text"),
    # ── form policy text (2026-09-18) ────────────────────────────────────────
    # Rich text: a fixed allow-list of tags (p br strong b em i u ul ol li a)
    # with href the only attribute, sanitized on save by sanitize_richtext().
    # Rendered inside the AI Use Case Intake form; the acknowledgement checkbox
    # there unlocks only after the reader scrolls to the end or opens a link.
    "policy.aia.ack":      (6000, "richtext"),
    # The Claude acknowledgement statement, shown above its checkbox on the
    # standalone Claude page (the FTE intake path, 2026-09-23). Same rich-text
    # allow-list and the same scroll-to-end unlock as the AI one.
    "policy.cla.ack":      (6000, "richtext"),
    # "1" once Legal's document and statement are in place and the page may go
    # live. ABSENT OR ANYTHING ELSE MEANS SAMPLE -- the default is deliberately
    # the safe one, so a page that nobody has explicitly released still says so
    # on its face and stamps every record it takes as a sample.
    "policy.cla.live":     (1, "text"),
    # ACK-NOTIFY (2026-09-24): who else hears about a completed acknowledgment.
    # Console-managed like every other content key. Absent notify -> nobody but
    # the employee; absent notify_mode -> "each"; absent notify_manager -> "1".
    "policy.cla.notify":         (2000, "multiline"),
    "policy.cla.notify_mode":    (5, "text"),
    "policy.cla.notify_manager": (1, "text"),
    # ACK-ELIG (2026-09-24): key requirements shown above the checkboxes; provisioning lead time (business days)
    "policy.cla.highlights":      (3000, "multiline"),
    "policy.cla.intro":           (1500, "multiline"),   # ACK-WORDING: intro callout on the acknowledgement page
    "policy.cla.provision_days":  (2, "text"),
}
CONTENT_PLACEHOLDERS = {
    "confirm.body": {"{id}", "{email}"},
    "approver.greeting_suffix": {"{role}"},
    # Optional — allowed, not required. Unknown placeholders are rejected.
    "email.submitted.intro":   {"{id}", "{type}"},
    "email.submitted.closing": {"{id}"},
    "email.approver.intro":    {"{id}", "{type}", "{step}"},
    "email.approved.closing":  {"{id}", "{type}"},
    "email.rejected.closing":  {"{id}", "{type}", "{step}"},
    "email.returned.closing":  {"{id}", "{type}", "{step}"},
}

# Built-in wording, used when an administrator has not overridden the key.
# MUST stay in step with the same keys in portal-content.js (guarded by a test).
EMAIL_TEXT_DEFAULTS = {
    "email.footer":            "Enterprise Approval Portal · IT Security & Compliance · auction.com",
    "email.submitted.intro":   "Your request has been received and the approval workflow has been started.",
    "email.submitted.closing": "Save your Request ID to track status at any time.",
    "email.approver.intro":    "A {type} request has been submitted and is pending your review as {step}.",
    "email.approved.closing":  "IT will action the access grant. If you don't hear from the IT Service Desk within one business day, please reach out directly.",
    "email.rejected.closing":  "What happens next: this request is now closed. If you believe the decision is incorrect, or you can address the reason above, submit a new request with additional justification and reference {id} in it.",
    "email.returned.closing":  "What you need to do: this request is now closed and cannot be edited or resubmitted. Please submit a new request that addresses the point above, and reference {id} in it so the approvers have the history.",
}
_CONTENT_TAG = re.compile(r"<[^>]*>")
_CONTENT_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def content_all() -> dict:
    out = {}
    for r in db().execute("SELECT key, value FROM settings WHERE key LIKE 'content.%'").fetchall():
        k = r["key"][8:]
        try:
            v = json.loads(r["value"])
        except Exception:
            v = r["value"]
        if isinstance(v, str) and k in CONTENT_KEYS:
            out[k] = v
    if "footer.contact_email" not in out:
        hd = ((get_setting("smtp", {}) or {}).get("helpdesk") or get_smtp().get("helpdesk") or "").strip()
        if hd:
            out["footer.contact_email"] = hd
    return out

# ── rich text (administrator-authored HTML shown on the public portal) ───────
# Allow-list, not deny-list. Anything not named here is dropped; the text
# inside a dropped element is kept EXCEPT for the containers whose content
# is itself code or hidden (script/style/...). Attributes are dropped except
# href on <a>, and href must be http(s), mailto or a same-site path.
_RT_ALLOWED  = {"p", "br", "strong", "b", "em", "i", "u", "ul", "ol", "li", "a"}
_RT_VOID     = {"br"}
_RT_DROP_ALL = {"script", "style", "iframe", "object", "embed", "svg", "math", "template", "noscript", "textarea", "select", "button", "form", "input"}
_RT_HREF_OK  = re.compile(r"^(https?://[^\s<>\"']+|mailto:[^\s<>\"']+|/[^\s<>\"']*)$", re.I)

class _RichTextSanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.stack, self.skip = [], [], 0
    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _RT_DROP_ALL:
            self.skip += 1; return
        if self.skip or tag not in _RT_ALLOWED:
            return
        if tag in _RT_VOID:
            self.out.append("<br>"); return
        if tag == "a":
            href = next((v for k, v in attrs if k.lower() == "href" and v), "")
            href = href.strip()
            if not _RT_HREF_OK.match(href):
                # a link with no usable target is just its text
                self.stack.append(None); return
            self.out.append('<a href="%s">' % html.escape(href, quote=True))
        else:
            self.out.append("<%s>" % tag)
        self.stack.append(tag)
    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() not in _RT_VOID: self.handle_endtag(tag)
    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _RT_DROP_ALL:
            if self.skip: self.skip -= 1
            return
        if self.skip or tag not in _RT_ALLOWED or tag in _RT_VOID:
            return
        # close back to the matching open tag (tolerates sloppy nesting)
        if tag in self.stack:
            while self.stack:
                t = self.stack.pop()
                if t is not None: self.out.append("</%s>" % t)
                if t == tag: break
    def handle_data(self, data):
        if not self.skip: self.out.append(html.escape(data, quote=False))
    def result(self):
        while self.stack:
            t = self.stack.pop()
            if t is not None: self.out.append("</%s>" % t)
        return "".join(self.out)

def sanitize_richtext(raw: str) -> str:
    p = _RichTextSanitizer()
    p.feed(raw or ""); p.close()
    v = p.result()
    v = re.sub(r"[ \t\r\f\v]+", " ", v)          # collapse runs of spaces
    v = re.sub(r"\n\s*\n+", "\n", v).strip()   # and blank lines
    return v

def richtext_is_blank(v: str) -> bool:
    return not re.sub(r"<[^>]+>", "", v or "").strip()

def content_clean(key: str, val):
    """Return (clean_value, error). Empty string / None means 'reset to default'."""
    if key not in CONTENT_KEYS:
        return None, f"unknown key: {key}"
    if val is None or val == "":
        return None, None
    if not isinstance(val, str):
        return None, f"{key}: must be text"
    maxlen, kind = CONTENT_KEYS[key]
    if kind == "richtext":
        v = sanitize_richtext(val)
        if richtext_is_blank(v):
            return None, f"{key}: no readable text after removing unsupported markup"
        if len(v) > maxlen:
            return None, f"{key}: maximum {maxlen} characters"
        return v, None
    v = _CONTENT_TAG.sub("", val).replace("\r\n", "\n").replace("\r", "\n")
    if kind == "multiline":
        v = "\n".join(" ".join(line.split()) for line in v.split("\n")).strip()
    else:
        v = " ".join(v.split())
    if kind == "email":
        v = v.lower()
        if not _CONTENT_EMAIL.match(v):
            return None, f"{key}: enter a complete email address"
    if len(v) > maxlen:
        return None, f"{key}: maximum {maxlen} characters"
    for ph in set(re.findall(r"\{[a-z_]+\}", v)):
        if ph not in CONTENT_PLACEHOLDERS.get(key, set()):
            return None, f"{key}: unknown placeholder {ph}"
    return v, None

def audit(request_id: str, event: str, actor: str, role: str = "", note: str = ""):
    """Best-effort audit row; must never break the caller."""
    try:
        db().execute(
            "INSERT INTO audit_log(request_id,event,actor,role,note,created_at) VALUES(?,?,?,?,?,?)",
            (request_id or "", event, actor or "System", role or "", (note or "")[:4000], now_iso()))
        db().commit()
    except Exception as e:  # noqa
        print(f"[audit] write skipped ({event}):", e, file=sys.stderr)

def content_audit(session: dict, diff: list):
    note = json.dumps({"keys": [d["key"] for d in diff], "diff": diff})
    audit("", "content.updated", (session or {}).get("email") or "admin",
          (session or {}).get("role") or "", note)

def get_smtp():
    """Kept for recipient-key compatibility. Returns recipient addresses only.
    Only the Service Desk remains a fixed recipient (2026-09-16)."""
    return {
        "helpdesk":    RECIPIENT_HELPDESK,
    }

# ── EMAIL (api-beta portal-mail relay) ────────────────────────────────────────

# ── Administrator-editable workflows (2026-09-18) ────────────────────────────
# REQUEST_TYPES[...]["workflow"] is the BUILT-IN chain. An administrator may
# override it per request type from Manage Roles; the override lives in the
# settings table (key "workflows", {type: [step keys]}) and a request type may
# also be hidden from the public portal (key "types.hidden", [type keys]).
# Every place that needs "the chain a new request gets" calls type_workflow().
# Requests already submitted are untouched — each carries its own snapshot.
WORKFLOW_FIRST_STEP = "manager"          # Rey's rule: the department manager is always first
WORKFLOW_MIN_STEPS  = 2

def workflow_overrides() -> dict:
    v = get_setting("workflows", {}) or {}
    return v if isinstance(v, dict) else {}

def hidden_types() -> list:
    v = get_setting("types.hidden", []) or []
    return [t for t in v if isinstance(t, str) and t in REQUEST_TYPES] if isinstance(v, list) else []

def validate_workflow(type_key: str, wf) -> tuple:
    """(clean_list, error). The rules an administrator's chain must satisfy."""
    if type_key not in REQUEST_TYPES:
        return None, f"unknown request type '{type_key}'"
    if not isinstance(wf, list) or not all(isinstance(x, str) for x in wf):
        return None, f"{type_key}: workflow must be a list of step keys"
    wf = [x.strip().lower() for x in wf if x and x.strip()]
    bad = [x for x in wf if x not in STEP_LABELS]
    if bad:
        return None, f"{type_key}: unknown step(s) {', '.join(bad)}"
    if len(wf) != len(set(wf)):
        return None, f"{type_key}: a step may appear only once"
    if len(wf) < WORKFLOW_MIN_STEPS:
        return None, f"{type_key}: a workflow needs at least {WORKFLOW_MIN_STEPS} steps"
    if wf[0] != WORKFLOW_FIRST_STEP:
        return None, f"{type_key}: {step_label(WORKFLOW_FIRST_STEP)} must be the first step"
    return wf, None

def type_workflow(type_key: str) -> list:
    """The chain a NEW request of this type receives: the administrator's
    override when one is saved and still valid, else the built-in chain."""
    ov = workflow_overrides().get(type_key)
    if ov:
        clean, err_ = validate_workflow(type_key, ov)
        if clean:
            return clean
    return list(REQUEST_TYPES[type_key]["workflow"])

# Steps that no longer appear in any workflow. Kept only so that historical
# data (audit rows, decided approvals on old requests) still renders a readable
# name instead of a bare key. Never offered in the UI.
RETIRED_STEP_LABELS = {"infosec": "Information Security (merged into Security & Compliance)"}


def step_label(key: str) -> str:
    """Display name of an approval step.

    An administrator may rename a step from Manage Roles; the override lives in
    settings as content.step.<key>.label and STEP_LABELS is the built-in default.
    Only the label moves — the step key and the AD group approver-<key> are
    structural, so renaming never changes who may approve. Falls back to the
    built-in name, then to the raw key."""
    try:
        v = get_setting(f"content.step.{key}.label", None)
        if isinstance(v, str) and v.strip():
            return v.strip()
    except Exception:
        pass
    return STEP_LABELS.get(key) or RETIRED_STEP_LABELS.get(key) or key


def email_text(key: str, **subs) -> str:
    """An administrator-editable email sentence, ready to drop into a template.

    Falls back to EMAIL_TEXT_DEFAULTS when the key is unset or the stored value
    is blank. The stored value is plain text (content_clean strips tags), and it
    is HTML-escaped here before any placeholder substitution result is inserted,
    so nothing an administrator types can become markup in a requester's inbox.
    Newlines become <br>. Unknown placeholders are left as written rather than
    raising, because the email must still send."""
    raw = ""
    try:
        stored = get_setting(f"content.{key}", None)
        if isinstance(stored, str):
            raw = stored.strip()
    except Exception:
        raw = ""
    if not raw:
        raw = EMAIL_TEXT_DEFAULTS.get(key, "")
    out = html.escape(raw)
    for name, value in subs.items():
        out = out.replace("{" + name + "}", html.escape(str(value or "")))
    return out.replace("\n", "<br>")


# ── Per-step approver notification email (settingsfold W3, 2026-10-12) ───────
# The approver console's "Edit email" dialog (Notification Emails) sends a
# subject and an opening paragraph per step. Stored beside the per-step
# recipient as settings approver_subject_<step> / approver_body_<step>.
# Blank = the built-in wording: today's hard-coded subject line, and the shared
# content.email.approver.intro sentence. Values are plain text, cleaned the way
# content_clean() cleans a "multiline" content key (tags stripped, whitespace
# collapsed, length-capped, placeholders white-listed — the same three the
# shared email.approver.intro allows). The body is HTML-escaped on render
# exactly like email_text(); the subject is a header, so it carries no markup
# and no line breaks.
APPROVER_MAIL_LIMITS = {"subject": 160, "body": 1200}
APPROVER_MAIL_PLACEHOLDERS = ("{id}", "{type}", "{step}")
APPROVER_SUBJECT_DEFAULT = "{step} Review Required \u2013 {type} \u2014 {id}"
_APPROVER_MAIL_PH = re.compile(r"\{([a-z_]+)\}")

def approver_mail_clean(field: str, val):
    """(clean_value, error). '' means use the built-in wording."""
    if val is None:
        return "", None
    if not isinstance(val, str):
        return None, f"{field}: must be text"
    v = _CONTENT_TAG.sub("", val).replace("\r\n", "\n").replace("\r", "\n")
    if field == "subject":
        v = " ".join(v.split())
    else:
        v = "\n".join(" ".join(line.split()) for line in v.split("\n")).strip()
    if len(v) > APPROVER_MAIL_LIMITS[field]:
        return None, f"{field}: maximum {APPROVER_MAIL_LIMITS[field]} characters"
    for ph in sorted(set(re.findall(r"\{[a-z_]+\}", v))):
        if ph not in APPROVER_MAIL_PLACEHOLDERS:
            return None, f"{field}: unknown placeholder {ph} (allowed: {' '.join(APPROVER_MAIL_PLACEHOLDERS)})"
    return v, None

def _approver_mail_stored(step_key: str, field: str) -> str:
    try:
        v = get_setting(f"approver_{field}_{step_key}", "")
    except Exception:
        v = ""
    return v.strip() if isinstance(v, str) else ""

def _approver_mail_fill(raw: str, subs: dict, escape: bool) -> str:
    def one(m):
        if m.group(1) not in subs:
            return m.group(0)
        v = str(subs[m.group(1)] or "")
        return html.escape(v) if escape else v
    return _APPROVER_MAIL_PH.sub(one, raw)

def approver_mail_subject(step_key: str, **subs) -> str:
    """Subject of the "approval needed" mail for a step: the step's saved
    subject, else today's built-in line. Never contains a line break."""
    raw = _approver_mail_stored(step_key, "subject") or APPROVER_SUBJECT_DEFAULT
    return re.sub(r"[\r\n]+", " ", _approver_mail_fill(raw, subs, escape=False))

def approver_mail_body(step_key: str, **subs) -> str:
    """Opening paragraph of the "approval needed" mail, ready for the template:
    the step's saved body, else the shared email.approver.intro (email_text)."""
    raw = _approver_mail_stored(step_key, "body")
    if not raw:
        return email_text("email.approver.intro", **subs)
    return _approver_mail_fill(html.escape(raw), subs, escape=True).replace("\n", "<br>")

def approver_contacts_view() -> dict:
    return {s: {"name":    get_setting(f"approver_name_{s}", "") or "",
                "email":   get_setting(f"approver_email_{s}", "") or "",
                "subject": _approver_mail_stored(s, "subject"),
                "body":    _approver_mail_stored(s, "body")}
            for s in STEP_LABELS}

def approver_mail_meta() -> dict:
    """What the Edit-email dialog shows as placeholder text and hints."""
    shared = ""
    try:
        stored = get_setting("content.email.approver.intro", None)
        if isinstance(stored, str):
            shared = stored.strip()
    except Exception:
        shared = ""
    return {"default_subject": APPROVER_SUBJECT_DEFAULT,
            "default_body":    shared or EMAIL_TEXT_DEFAULTS["email.approver.intro"],
            "placeholders":    list(APPROVER_MAIL_PLACEHOLDERS),
            "limits":          dict(APPROVER_MAIL_LIMITS)}


_mail_state = threading.local()
def mail_last_error() -> str:
    """Why the most recent send_email() on this thread failed ('' if it did not)."""
    return getattr(_mail_state, "err", "") or ""

def send_email(to: str | list, subject: str, body_html: str, body_text: str = "") -> bool:
    """Send via the api-beta loopback relay. Drop-in for the old Graph version.
    The relay pins the sender and enforces the recipient allowlist server-side.
    Returns True only when the relay ACCEPTED the message; the reason for a
    False is left in mail_last_error() so the caller can audit it."""
    _mail_state.err = ""
    if isinstance(to, str):
        to = [to]
    to = [a.strip() for a in to if a and a.strip()]
    if not to:
        _mail_state.err = "no recipient address"
        return False
    if not RELAY_KEY:
        _mail_state.err = "PORTAL_MAIL_KEY not set"
        print("[EMAIL ERROR] PORTAL_MAIL_KEY not set", file=sys.stderr)
        return False
    req = urllib.request.Request(
        RELAY_URL,
        data=json.dumps({"to": to, "subject": subject, "html": body_html}).encode(),
        headers={"Content-Type": "application/json",
                 "X-Portal-Mail-Key": RELAY_KEY})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            if r.status in (200, 202):
                return True
            _mail_state.err = f"relay answered HTTP {r.status}"
            return False
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        _mail_state.err = f"relay HTTP {e.code}: {detail}".strip()
        print(f"[EMAIL ERROR] relay HTTP {e.code}: {detail}", file=sys.stderr)
        return False
    except Exception as e:
        _mail_state.err = f"relay unreachable: {e}"
        print(f"[EMAIL ERROR] {e}", file=sys.stderr)
        return False

def mail_and_audit(req_id: str, to, subject: str, body_html: str, what: str) -> bool:
    """Send, THEN write the audit row that says what happened.

    Until 2026-09-18 notification.sent was written before the relay was even
    called and the relay's answer was thrown away — a refused or undeliverable
    message looked identical to a delivered one in the Audit Trail. Now:
      notification.sent    the relay accepted the message
      notification.failed  it did not, with the relay's reason
    `what` names the audience in plain words, e.g. "Dept. Manager step".
    Both rows name every address so a typo is visible in the trail."""
    addrs = [to] if isinstance(to, str) else list(to or [])
    addrs = [a for a in addrs if a and str(a).strip()]
    shown = ", ".join(addrs) if addrs else "(no address)"
    okk = send_email(addrs, subject, body_html)
    if okk:
        audit(req_id, "notification.sent", "System", "Automation", f"{what}: {shown}")
    else:
        audit(req_id, "notification.failed", "System", "Automation",
              f"{what}: {shown} — NOT delivered ({mail_last_error() or 'unknown error'})")
    return okk

def _esc_map(d: dict) -> dict:
    """Every value that can reach an f-string in outbound mail is HTML-escaped —
    strings, numbers and lists alike (public submitters control these)."""
    out = {}
    for k, v in (d or {}).items():
        if isinstance(v, (list, tuple)):
            out[k] = ", ".join(html.escape(str(x)) for x in v)
        elif v is None:
            out[k] = ""
        else:
            out[k] = html.escape(str(v))
    return out

EMAIL_ART_URL = (os.environ.get("EMAIL_ART_URL", PORTAL_BASE_URL + "/email-art") or "").rstrip("/")
EMAIL_HERO_URL = os.environ.get("EMAIL_HERO_URL", EMAIL_ART_URL + "/hero.jpg")
_EMAIL_ART_KEYS = {"oca", "aia", "wua", "paa", "ser", "sir", "portal", "approved", "rejected", "returned", "warning"}
def email_art(key: str, w: int = 52, h: int = 26, alt: str = "") -> str:
    """The same artwork the portal tiles use, as a hosted PNG chip for email
    clients (inline SVG and data: URIs are unreliable in Outlook). Unknown keys
    fall back to the portal mark. alt carries the label when images are blocked."""
    k = key if key in _EMAIL_ART_KEYS else "portal"
    return (f'<img src="{EMAIL_ART_URL}/{k}.png" width="{w}" height="{h}" alt="{html.escape(alt or "")}" '
            f'style="display:inline-block;vertical-align:middle;border-radius:6px;border:0;width:{w}px;height:{h}px">')
def type_art(t: str, w: int = 52, h: int = 26) -> str:
    return email_art(t, w, h, (REQUEST_TYPES.get(t) or {}).get("label", ""))

def _email_html_wrapper(icon: str, title: str, body: str, req_id: str = "", footer: str = "") -> str:
    portal_url = PORTAL_BASE_URL
    # icon is artwork markup (email_art) or, for older callers, an emoji
    if not icon.lstrip().startswith("<img"):
        icon = email_art({"✅": "approved", "❌": "rejected", "↩️": "returned", "⚠️": "warning"}.get(icon.strip(), "portal"))
    icon = re.sub(r'width="\d+" height="\d+"', 'width="72" height="36"', icon).replace("width:52px;height:26px", "width:72px;height:36px")
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:'Segoe UI',system-ui,sans-serif;background:#f8fafb;margin:0;padding:24px">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e3e7ea">
  <!--[if gte mso 9]><v:rect xmlns:v="urn:schemas-microsoft-com:vml" fill="true" stroke="false" style="width:600px;height:118px"><v:fill type="frame" src="{EMAIL_HERO_URL}" color="#0f1a2a"/><v:textbox inset="0,0,0,0"><![endif]-->
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0f1a2a url('{EMAIL_HERO_URL}') right 40%/cover no-repeat;background-color:#0f1a2a">
    <tr><td style="padding:0;background:linear-gradient(90deg,rgba(9,17,30,.90) 0%,rgba(9,17,30,.62) 48%,rgba(9,17,30,.10) 100%)">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="padding:38px 16px 38px 32px;line-height:0"><div style="border-radius:8px;overflow:hidden;line-height:0;box-shadow:0 2px 6px rgba(0,0,0,.45)">{icon}</div></td>
        <td style="padding:38px 32px 38px 0;vertical-align:middle">
          <div style="color:#ffffff;font-size:17px;font-weight:800;letter-spacing:-.2px">Enterprise Approval Portal</div>
          <div style="color:#41B6E6;font-size:12px;margin-top:3px;font-weight:600">IT Security &amp; Compliance · auction.com</div>
        </td></tr></table>
    </td></tr>
  </table>
  <!--[if gte mso 9]></v:textbox></v:rect><![endif]-->
  <div style="height:4px;background:#509E2F;background-image:linear-gradient(90deg,#509E2F,#78BE20)"></div>
  <div style="padding:28px 32px">{body}</div>
  {f'<div style="padding:16px 32px;text-align:center"><a href="{portal_url}" style="display:inline-block;background:#509E2F;color:#ffffff;text-decoration:none;padding:13px 30px;border-radius:8px;font-size:14px;font-weight:700">View Request{" · " + req_id if req_id else ""} →</a></div>' if req_id else ""}
  <div style="background:#f8fafb;border-top:1px solid #e3e7ea;padding:14px 32px;font-size:11px;color:#5B6770">{footer or email_text("email.footer")}</div>
</div></body></html>"""

def notify_submission(req: dict):
    """Send emails when a new request is submitted."""
    rt   = REQUEST_TYPES.get(req["type"], {})
    icon = type_art(req["type"])
    raw_subm = req["submitter"]
    to_email = (raw_subm.get("email") or "")
    subm = _esc_map(raw_subm)

    # 1. Confirmation to requester
    if subm.get("email"):
        body = f"""
<p style="font-size:15px;color:#1f2937">Hi <strong>{subm.get('name','')}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">{email_text("email.submitted.intro", id=req["id"], type=rt.get("label",""))}</p>
<table style="width:100%;border-collapse:collapse;border:1px solid #e3e7ea;border-radius:8px;overflow:hidden;font-size:13px">
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600;width:40%">Request ID</td><td style="padding:10px 14px;font-family:ui-monospace,Menlo,monospace;color:#509E2F;font-weight:700">{req['id']}</td></tr>
  <tr><td style="padding:10px 14px;color:#5B6770;font-weight:600">Request Type</td><td style="padding:10px 14px">{icon}&nbsp; {rt.get('label','')}</td></tr>
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600">Status</td><td style="padding:10px 14px"><span style="background:#fff7e6;color:#9a5b00;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:700">PENDING APPROVAL</span></td></tr>
  <tr><td style="padding:10px 14px;color:#5B6770;font-weight:600">Submitted</td><td style="padding:10px 14px">{req['created_at'][:10]}</td></tr>
</table>
<p style="font-size:13px;color:#5B6770;margin-top:16px">{email_text("email.submitted.closing", id=req["id"])}</p>"""
        mail_and_audit(req["id"], to_email,
                   f"Your {rt.get('label','')} request has been received",
                   _email_html_wrapper(icon, "Request Received", body, req["id"]), "Requester confirmation")

    # CyberSecurity and Procurement fixed-recipient notifications were removed on
    # 2026-09-16. Those audiences are now reached, where wanted, through the
    # per-step recipients an administrator sets under Notification Emails.

    # 2. Notify first approver in workflow
    _notify_next_approver(req, 0)

def request_manager_email(req: dict) -> str:
    """The requester's own manager, as captured by the directory lookup (R2).
    Empty when the request predates the lookup fix or the lookup returned no
    manager. Only a syntactically valid address is honoured."""
    subm = req.get("submitter") or {}
    if isinstance(subm, str):
        try: subm = json.loads(subm)
        except Exception: subm = {}
    m = (subm.get("manager_email") or "").strip().lower()
    if not ADDR_RE.match(m) or m == (subm.get("email") or "").strip().lower():
        return ""
    return m

def step_recipient(req: dict, step_key: str) -> tuple:
    """Who is notified for a step: (email, display_name, source).
    R3: the 'manager' step routes to the requester's actual manager when the
    request carries one; every step falls back to the global per-step address
    (settings.approver_email_<step>). source ∈ {'request','step',''}."""
    step_name = step_label(step_key)
    if step_key == "manager":
        m = request_manager_email(req)
        if m:
            subm = req.get("submitter") or {}
            return m, (subm.get("manager_name") or "Manager"), "request"
    email = (get_setting(f"approver_email_{step_key}") or "").strip().lower()
    name  = get_setting(f"approver_name_{step_key}") or step_name
    if email and ADDR_RE.match(email):
        return email, name, "step"
    return "", step_name, ""

def _notify_next_approver(req: dict, step_idx: int):
    """Email the approver at step_idx. Never silent: an unroutable step is
    written to the audit log and escalated to the Service Desk address (R5)."""
    workflow = req.get("workflow", [])
    if step_idx >= len(workflow):
        return
    step_key   = workflow[step_idx]
    step_name = step_label(step_key)
    rt         = REQUEST_TYPES.get(req["type"], {})

    approver_email, approver_name, source = step_recipient(req, step_key)

    if not approver_email:
        helpdesk = get_smtp().get("helpdesk", "")
        audit(req["id"], "notification.unroutable", "System", "Automation",
              f"No recipient configured for step '{step_key}' ({step_name}). "
              + (f"Escalated to {helpdesk}." if helpdesk else "No Service Desk address configured either — nobody was notified."))
        print(f"[NOTIFY] {req['id']}: step '{step_key}' has no recipient", file=sys.stderr)
        if helpdesk:
            body = f"""
<div style="background:#fef2f2;border-left:4px solid #ef4444;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#991b1b;font-weight:600">
  Approval step has no recipient — request is waiting on nobody
</div>
<p style="font-size:14px;color:#1f2937">Request <strong>{req['id']}</strong> ({html.escape(rt.get('label',''))}) reached the <strong>{html.escape(step_name)}</strong> step, but no notification address is configured for that step and the request carries no routable approver.</p>
<p style="font-size:13px;color:#5B6770">An administrator should set the recipient under <em>Notification Emails</em> in the approver console, grant access under <em>Approval Access</em>. The request stays pending until someone assigned to this step acts on it.</p>"""
            mail_and_audit(req["id"], helpdesk,
                       f"[No approver configured] {step_name} step — {req['id']}",
                       _email_html_wrapper("⚠️", "Approval step has no recipient", body, req["id"]),
                       f"Service Desk escalation for the {step_name} step")
        return

    via = "requester's manager" if source == "request" else "step recipient"
    icon = type_art(req["type"])
    subm = _esc_map(req["submitter"])

    body = f"""
<div style="background:#eef8fd;border-left:4px solid #41B6E6;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#0b5d80;font-weight:600">
  Action Required — Your approval is needed
</div>
<p style="font-size:15px;color:#1f2937">Hi <strong>{html.escape(str(approver_name))}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">{approver_mail_body(step_key, id=req["id"], type=rt.get("label",""), step=step_name)}{" — you are listed as the requester's direct manager" if source == "request" else ""}{" (address entered by the requester; not verified against the directory)" if source == "request" and (req.get("submitter") or {}).get("manager_source") == "manual" else ""}</p>
<table style="width:100%;border-collapse:collapse;border:1px solid #e3e7ea;border-radius:8px;overflow:hidden;font-size:13px">
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600;width:40%">Request ID</td><td style="padding:10px 14px;font-family:ui-monospace,Menlo,monospace;color:#509E2F;font-weight:700">{req['id']}</td></tr>
  <tr><td style="padding:10px 14px;color:#5B6770;font-weight:600">Request Type</td><td style="padding:10px 14px">{icon}&nbsp; {rt.get('label','')}</td></tr>
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600">Submitted By</td><td style="padding:10px 14px">{subm.get('name','')} · {subm.get('dept','')}</td></tr>
  <tr><td style="padding:10px 14px;color:#5B6770;font-weight:600">Your Step</td><td style="padding:10px 14px"><span style="background:#e3f4fb;color:#0b5d80;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700">{step_name}</span></td></tr>
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600">Priority</td><td style="padding:10px 14px">{req.get('priority','normal').upper()}</td></tr>
</table>"""
    mail_and_audit(req["id"], approver_email,
               approver_mail_subject(step_key, id=req["id"], type=rt.get("label",""), step=step_name),
               _email_html_wrapper(icon, f"Approval Needed: {step_name}", body, req["id"],
                                   f"Sent to {html.escape(approver_email)} · You are the {step_name} approver for this workflow."),
               f"{step_name} step approval request ({via})")

def _last_comment(req: dict, *statuses: str) -> str:
    """The most recent approver comment carrying one of `statuses`, HTML-escaped.
    Used to tell the requester *why* a request was denied or returned."""
    return html.escape(str(next(
        (a["comments"] for a in reversed(req.get("approvals", []))
         if a.get("status") in statuses and a.get("comments")), "")))


def _deciding_step_label(req: dict, *statuses: str) -> str:
    """Display label of the step that produced the decision, for the email."""
    wf = req.get("workflow") or []
    for a in reversed(req.get("approvals", [])):
        if a.get("status") in statuses:
            idx = a.get("step")
            if isinstance(idx, int) and 0 <= idx < len(wf):
                return step_label(wf[idx])
    return ""


def _progress_recipients(req: dict, exclude: str = "") -> list:
    """The requester and their manager, deduplicated, minus one address.

    `exclude` is the approver who was just emailed the "approval needed" notice
    for the step the request moved to — without it, a manager who is also the
    next step's recipient would get two mails about the same move."""
    subm = req.get("submitter") or {}
    if isinstance(subm, str):
        try: subm = json.loads(subm)
        except Exception: subm = {}
    skip = {(exclude or "").strip().lower()}
    out, seen = [], set()
    for addr in (subm.get("email"), subm.get("manager_email")):
        addr = (addr or "").strip()
        low = addr.lower()
        if not addr or low in seen or low in skip or not ADDR_RE.match(low):
            continue
        seen.add(low)
        out.append(addr)
    return out

def _progress_chain(workflow: list, next_idx: int) -> str:
    """The workflow as table rows: what is done, what is waiting, what is next."""
    rows = []
    for i, k in enumerate(workflow):
        mark  = ('<span style="display:inline-block;width:18px;height:18px;border-radius:50%;background:#78BE20;color:#fff;font-size:12px;line-height:18px;text-align:center;font-weight:800">&#10003;</span>' if i < next_idx
                 else '<span style="display:inline-block;width:14px;height:14px;border-radius:50%;background:#41B6E6;box-shadow:0 0 0 3px rgba(65,182,230,.25)"></span>' if i == next_idx
                 else '<span style="display:inline-block;width:14px;height:14px;border-radius:50%;border:2px solid #c9d1d6"></span>')
        state = ('<span style="color:#509E2F;font-weight:700">Approved</span>' if i < next_idx
                 else '<span style="color:#0b5d80;font-weight:700">Waiting now</span>' if i == next_idx else "Not yet reached")
        bg    = ' style="background:#f8fafb"' if i % 2 == 0 else ""
        rows.append("<tr" + bg + '><td style="padding:8px 14px;width:34px;color:#5B6770">' + mark
                    + '</td><td style="padding:8px 14px;color:#1f2937">' + html.escape(step_label(k))
                    + '</td><td style="padding:8px 14px;color:#5B6770;font-size:12px">' + state
                    + "</td></tr>")
    return "".join(rows)

def notify_progress(req: dict, decided_idx: int, next_idx: int):
    """Tell the requester and their manager that the request advanced a step.

    Added 2026-09-18. Before this, nobody outside the approval chain heard
    anything between submission and the final outcome: a request could sit at
    step 3 of 5 for a week with the requester unable to tell whether it had
    moved at all. This is the "in progress / waiting" notice — it carries no
    decision and asks for nothing."""
    workflow = req.get("workflow") or []
    if not (0 <= decided_idx < len(workflow)) or not (0 <= next_idx < len(workflow)):
        return
    rt   = REQUEST_TYPES.get(req["type"], {})
    icon = type_art(req["type"])
    done_name = step_label(workflow[decided_idx])
    next_name = step_label(workflow[next_idx])

    # Whoever was just asked to act is already informed; don't mail them twice.
    next_email, _n, _src = step_recipient(req, workflow[next_idx])
    to = _progress_recipients(req, exclude=next_email)
    if not to:
        return

    subm  = _esc_map(req.get("submitter") or {})
    total = len(workflow)
    chain = _progress_chain(workflow, next_idx)

    body = f"""
<div style="background:#eef8fd;border-left:4px solid #41B6E6;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#0b5d80;font-weight:600">
  In progress — step {next_idx + 1} of {total}
</div>
<p style="font-size:15px;color:#1f2937">Hi <strong>{subm.get('name','')}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">Your <strong>{rt.get('label','')}</strong> request <strong>{req['id']}</strong> was approved at the <strong>{html.escape(done_name)}</strong> step and is now waiting at <strong>{html.escape(next_name)}</strong>.</p>
<table style="width:100%;border-collapse:collapse;border:1px solid #e3e7ea;border-radius:8px;overflow:hidden;font-size:13px">{chain}</table>
<p style="font-size:13px;color:#5B6770;margin-top:16px">No action is needed from you. You will be emailed again when the request is approved, rejected or returned. This notice also goes to the requester's manager.</p>"""

    mail_and_audit(req["id"], to,
               f"In progress — your {rt.get('label','')} request is now at {next_name}",
               _email_html_wrapper(icon, "Request In Progress", body, req["id"]),
               f"In-progress notice ({done_name} approved, now at {next_name}) to requester + manager")

def _service_desk_outcome(req: dict, status: str):
    """Copy the Service Desk on every terminal outcome, for every request type.

    Approved previously reached the Service Desk only for the four access
    types, and rejected/returned reached it for none — so SER and SIR could
    close without the Service Desk ever hearing. All six types and all three
    outcomes are reported now; the approved notice keeps its fulfilment
    wording, the other two are for the record."""
    desk = (get_smtp().get("helpdesk") or "").strip()
    if not desk:
        return
    rt   = REQUEST_TYPES.get(req["type"], {})
    icon = type_art(req["type"])
    subm = _esc_map(req.get("submitter") or {})
    needs_fulfilment = (status == "approved" and req["type"] in ("aia", "oca", "paa", "wua"))
    label, colour, banner = {
        "approved": ("Approved", "#78BE20", "Fully approved"),
        "rejected": ("Rejected", "#ef4444", "Rejected — closed without approval"),
        "returned": ("Returned", "#41B6E6", "Returned to the requester — closed"),
    }[status]
    note = _last_comment(req, status) if status in ("rejected", "returned") else ""
    by   = _deciding_step_label(req, status) if status in ("rejected", "returned") else ""
    if needs_fulfilment:
        lead = "The following request has been <strong>fully approved</strong> and requires fulfillment."
    else:
        at   = (" at the <strong>" + html.escape(by) + "</strong> step") if by else ""
        lead = ("The following request is now <strong>" + label.lower() + "</strong>" + at
                + ". No fulfilment action is required — this notice is for the record.")
    comment_block = ""
    if note:
        comment_block = ('<p style="font-size:13px;color:#5B6770;background:#f8fafb;'
                         'border:1px solid #e3e7ea;border-radius:8px;padding:12px;margin-top:14px">'
                         '<strong>Approver comment:</strong><br>' + note + '</p>')
    outcome_cell = label + ((" &middot; " + html.escape(by)) if by else "")
    body = f"""
<div style="background:#f8fafb;border-left:4px solid {colour};border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#1f2937;font-weight:600">
  {banner}
</div>
<p style="font-size:14px;color:#1f2937;margin-bottom:16px">{lead}</p>
<table style="width:100%;border-collapse:collapse;border:1px solid #e3e7ea;border-radius:8px;overflow:hidden;font-size:13px">
  <tr style="background:#f8fafb"><td style="padding:9px 14px;color:#5B6770;font-weight:600;width:38%">Request ID</td><td style="padding:9px 14px;font-family:ui-monospace,Menlo,monospace;color:#509E2F;font-weight:700">{req['id']}</td></tr>
  <tr><td style="padding:9px 14px;color:#5B6770;font-weight:600">Type</td><td style="padding:9px 14px">{icon}&nbsp; {rt.get('label','')}</td></tr>
  <tr style="background:#f8fafb"><td style="padding:9px 14px;color:#5B6770;font-weight:600">Outcome</td><td style="padding:9px 14px"><strong>{outcome_cell}</strong></td></tr>
  <tr><td style="padding:9px 14px;color:#5B6770;font-weight:600">Requester</td><td style="padding:9px 14px">{subm.get('name','')} &middot; {subm.get('email','')}</td></tr>
  <tr style="background:#f8fafb"><td style="padding:9px 14px;color:#5B6770;font-weight:600">Department</td><td style="padding:9px 14px">{subm.get('dept','')} &middot; {subm.get('title','')}</td></tr>
</table>
{comment_block}"""
    if needs_fulfilment:
        subject = f"[Fulfillment Required] Approved — {req['id']}"
    else:
        subject = f"[{label}] {rt.get('label','')} — {req['id']}"
    mail_and_audit(req["id"], desk, subject, _email_html_wrapper(icon, "Request " + label, body, req["id"]),
                   f"Service Desk notice — {label.lower()}")

def notify_final_outcome(req: dict):
    """Email the requester on every terminal outcome — approved, rejected or
    returned — and the Service Desk on approval for fulfilment.

    Every decision an approver can take reaches the requester: `approve` on the
    last step (approved), `reject` (rejected) and `return` (returned) all land
    here. An approver never has to email the requester by hand."""
    rt   = REQUEST_TYPES.get(req["type"], {})
    icon = type_art(req["type"])
    raw_subm = req["submitter"]
    to_email = (raw_subm.get("email") or "")
    subm = _esc_map(raw_subm)
    status = req["status"]

    if status == "approved":
        # Email requester
        if subm.get("email"):
            body = f"""
<div style="background:#f1f9e8;border-left:4px solid #78BE20;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#2f6b1c;font-weight:600">
  ✓ Your request has been fully approved
</div>
<p style="font-size:15px;color:#1f2937">Hi <strong>{subm.get('name','')}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">Great news — your <strong>{rt.get('label','')}</strong> request <strong>{req['id']}</strong> has been approved through all workflow steps.</p>
<p style="font-size:13px;color:#5B6770">{email_text("email.approved.closing", id=req["id"], type=rt.get("label",""))}</p>"""
            mail_and_audit(req["id"], to_email,
                       f"Approved — your {rt.get('label','')} request",
                       _email_html_wrapper("✅", "Request Approved", body), "Requester notice — approved")

    elif status == "rejected":
        if subm.get("email"):
            last_denial = _last_comment(req, "rejected")
            denied_by   = _deciding_step_label(req, "rejected")
            body = f"""
<div style="background:#fef2f2;border-left:4px solid #ef4444;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#991b1b;font-weight:600">
  ✗ Your request has been denied
</div>
<p style="font-size:15px;color:#1f2937">Hi <strong>{subm.get('name','')}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">Your <strong>{rt.get('label','')}</strong> request <strong>{req['id']}</strong> has been denied{f" at the <strong>{denied_by}</strong> step" if denied_by else ""}.</p>
{"<p style='font-size:13px;color:#5B6770;background:#f8fafb;border:1px solid #e3e7ea;border-radius:8px;padding:12px'><strong>Reason given by the approver:</strong><br>" + last_denial + "</p>" if last_denial else ""}
<p style="font-size:13px;color:#5B6770;margin-top:14px">{email_text("email.rejected.closing", id=req["id"], type=rt.get("label",""), step=denied_by)}</p>"""
            mail_and_audit(req["id"], to_email,
                       f"Denied — your {rt.get('label','')} request",
                       _email_html_wrapper("❌", "Request Denied", body), "Requester notice — rejected")

    elif status == "returned":
        # A returned request is closed and needs a fresh submission. The requester
        # is told which step returned it and what the approver asked for, so they
        # never have to chase the approver to find out.
        if subm.get("email"):
            last_note   = _last_comment(req, "returned")
            returned_by = _deciding_step_label(req, "returned")
            body = f"""
<div style="background:#eef8fd;border-left:4px solid #41B6E6;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#0b5d80;font-weight:600">
  ↩ Your request was returned — more information is needed
</div>
<p style="font-size:15px;color:#1f2937">Hi <strong>{subm.get('name','')}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">Your <strong>{rt.get('label','')}</strong> request <strong>{req['id']}</strong> has been returned{f" by the <strong>{returned_by}</strong> step" if returned_by else ""} because more information is needed.</p>
{"<p style='font-size:13px;color:#5B6770;background:#f8fafb;border:1px solid #e3e7ea;border-radius:8px;padding:12px'><strong>What the approver asked for:</strong><br>" + last_note + "</p>" if last_note else "<p style='font-size:13px;color:#5B6770;background:#f8fafb;border:1px solid #e3e7ea;border-radius:8px;padding:12px'>The approver did not leave a note. Please contact them or the IT Service Desk for detail before resubmitting.</p>"}
<p style="font-size:13px;color:#5B6770;margin-top:14px">{email_text("email.returned.closing", id=req["id"], type=rt.get("label",""), step=returned_by)}</p>"""
            mail_and_audit(req["id"], to_email,
                       f"Returned — your {rt.get('label','')} request",
                       _email_html_wrapper("↩️", "Request Returned", body), "Requester notice — returned")

    # Every terminal outcome is reported to the Service Desk, for all six
    # request types — approved (fulfilment), rejected and returned (record).
    if status in ("approved", "rejected", "returned"):
        _service_desk_outcome(req, status)

# ── REQUEST HELPERS ───────────────────────────────────────────────────────────

def _build_request_dict(row, approvals=None) -> dict:
    """Convert a DB row + approvals list into the JSON shape the portal expects."""
    r = dict(row)
    r["submitter"] = json.loads(r["submitter"])
    r["details"]   = json.loads(r["details"])
    r["workflow"]  = json.loads(r["workflow"])

    if approvals is None:
        ap_rows = db().execute(
            "SELECT * FROM approvals WHERE request_id=? ORDER BY step",
            (r["id"],)).fetchall()
        approvals = [dict(a) for a in ap_rows]

    r["approvals"] = approvals

    audit_rows = db().execute(
        "SELECT * FROM audit_log WHERE request_id=? ORDER BY created_at",
        (r["id"],)).fetchall()
    r["audit"] = [dict(a) for a in audit_rows]
    return r

def create_request(type_key: str, submitter: dict, details: dict,
                   priority: str = "normal", signature: str = "") -> dict:
    rt      = REQUEST_TYPES[type_key]
    req_id  = next_request_id(type_key)
    workflow = type_workflow(type_key)          # administrator override or built-in
    ts       = now_iso()

    db().execute(
        """INSERT INTO requests(id,type,status,priority,submitter,details,workflow,current_step,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (req_id, type_key, "pending", priority,
         json.dumps(submitter), json.dumps(details),
         json.dumps(workflow), 0, ts, ts))

    for i, step in enumerate(workflow):
        db().execute(
            """INSERT INTO approvals(request_id,step,step_key,step_label,status)
               VALUES(?,?,?,?,?)""",
            (req_id, i, step, step_label(step), "pending"))

    db().execute(
        """INSERT INTO audit_log(request_id,event,actor,role,note,created_at)
           VALUES(?,?,?,?,?,?)""",
        (req_id, "Request Submitted", submitter.get("name","Unknown"),
         "Employee", f"Submitted via Employee Portal. Signature: {signature[:60]}", ts))

    db().commit()

    req = _build_request_dict(
        db().execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone())
    return req

def record_decision(req_id: str, step_key: str, action: str,
                    approver_name: str, approver_role: str,
                    comments: str, signature: str, actor_email: str = "",
                    notify: bool = True, grant: str = "") -> dict:
    """action: 'approve' | 'reject' | 'return'. With notify=False the caller
    sends the mails itself (used to keep relay I/O outside write_lock)."""
    req_row = db().execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    if not req_row:
        raise ValueError(f"Request {req_id} not found")

    r        = dict(req_row)
    workflow = json.loads(r["workflow"])
    cur_step = r["current_step"]

    if step_key not in workflow:
        raise ValueError(f"Step '{step_key}' not in workflow for {req_id}")

    step_idx = workflow.index(step_key)
    ts       = now_iso()

    status_map = {"approve": "approved", "reject": "rejected", "return": "returned"}
    step_status = status_map.get(action, "pending")

    db().execute(
        """UPDATE approvals
           SET status=?,approver_name=?,approver_role=?,comments=?,signature=?,decided_at=?
           WHERE request_id=? AND step=?""",
        (step_status, approver_name, approver_role, comments, signature, ts, req_id, step_idx))

    event_label = {
        "approve": f"Approved by {step_label(step_key)}",
        "reject":  f"Rejected by {step_label(step_key)}",
        "return":  f"Returned by {step_label(step_key)}",
    }[action]

    db().execute(
        """INSERT INTO audit_log(request_id,event,actor,role,note,created_at)
           VALUES(?,?,?,?,?,?)""",
        (req_id, event_label, approver_name, approver_role,
         ((comments or "") + (f" [{actor_email}]" if actor_email else "") + (f" [grant: {grant}]" if grant else "")), ts))

    if action == "approve":
        next_step = step_idx + 1
        if next_step >= len(workflow):
            # Fully approved
            db().execute(
                "UPDATE requests SET status='approved',current_step=?,updated_at=? WHERE id=?",
                (next_step, ts, req_id))
            db().execute(
                """INSERT INTO audit_log(request_id,event,actor,role,note,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (req_id, "Request Fully Approved", "System", "Automation",
                 "All approval steps completed.", ts))
        else:
            db().execute(
                "UPDATE requests SET current_step=?,updated_at=? WHERE id=?",
                (next_step, ts, req_id))
    else:
        new_status = "rejected" if action == "reject" else "returned"
        db().execute(
            "UPDATE requests SET status=?,updated_at=? WHERE id=?",
            (new_status, ts, req_id))

    db().commit()

    req = _build_request_dict(
        db().execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone())

    if notify:
        _notify_after_decision(req, action, step_idx)
    return req

def notify_reopened(req: dict, step_idx: int, reason: str, actor: str):
    """REOPEN (2026-10-15): an administrator sent a completed request back to a
    step. The step approver gets an explicit 'reopened' approval request (not
    the generic one), and the requester + manager get a notice with the reason."""
    workflow = req.get("workflow") or []
    if not (0 <= step_idx < len(workflow)):
        return
    step_key  = workflow[step_idx]
    step_name = step_label(step_key)
    rt   = REQUEST_TYPES.get(req["type"], {})
    icon = type_art(req["type"])
    subm = _esc_map(req.get("submitter") or {})
    rsn  = html.escape(reason or "")
    who  = html.escape(actor or "an administrator")
    banner = f"""
<div style="background:#fff7ed;border-left:4px solid #f59e0b;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#92400e;font-weight:600">
  Request reopened — sent back to {html.escape(step_name)} by {who}
</div>"""
    table = f"""
<table style="width:100%;border-collapse:collapse;border:1px solid #e3e7ea;border-radius:8px;overflow:hidden;font-size:13px">
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600;width:40%">Request ID</td><td style="padding:10px 14px;font-family:ui-monospace,Menlo,monospace;color:#509E2F;font-weight:700">{req['id']}</td></tr>
  <tr><td style="padding:10px 14px;color:#5B6770;font-weight:600">Request Type</td><td style="padding:10px 14px">{icon}&nbsp; {rt.get('label','')}</td></tr>
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600">Submitted By</td><td style="padding:10px 14px">{subm.get('name','')} · {subm.get('dept','')}</td></tr>
  <tr><td style="padding:10px 14px;color:#5B6770;font-weight:600">Reopened To</td><td style="padding:10px 14px"><span style="background:#fef3c7;color:#92400e;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700">{html.escape(step_name)}</span></td></tr>
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600">Reason</td><td style="padding:10px 14px">{rsn}</td></tr>
</table>"""
    approver_email, approver_name, _src = step_recipient(req, step_key)
    if approver_email:
        body = banner + f"""
<p style="font-size:15px;color:#1f2937">Hi <strong>{html.escape(str(approver_name))}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">Request <strong>{req['id']}</strong> ({rt.get('label','')}) was previously completed and has been <strong>reopened</strong> at your <strong>{html.escape(step_name)}</strong> step. Please review it again and approve, reject, or return it in the Approver Portal.</p>""" + table
        mail_and_audit(req["id"], approver_email,
                       f"[Reopened] {step_name} approval needed — {req['id']}",
                       _email_html_wrapper(icon, f"Reopened: {step_name} approval needed", body, req["id"],
                                           f"Sent to {html.escape(approver_email)} · You are the {step_name} approver for this workflow."),
                       f"Reopened — {step_name} step approval request")
    else:
        audit(req["id"], "notification.unroutable", "System", "Automation",
              f"Reopened to '{step_key}' ({step_name}) but no recipient is configured for that step.")
    try:
        to = _progress_recipients(req, exclude=approver_email)
    except Exception:  # noqa
        to = []
    if isinstance(to, str):
        to = [to]
    for addr in (to or []):
        body = banner + f"""
<p style="font-size:15px;color:#1f2937">Hi <strong>{subm.get('name','')}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">Your <strong>{rt.get('label','')}</strong> request <strong>{req['id']}</strong> has been reopened and is waiting again at the <strong>{html.escape(step_name)}</strong> step. No action is needed from you unless the approver contacts you.</p>""" + table
        mail_and_audit(req["id"], addr,
                       f"[Reopened] {rt.get('label','')} request {req['id']} — back at {step_name}",
                       _email_html_wrapper(icon, "Your request was reopened", body, req["id"]),
                       "Reopened — requester/manager notice")

def _notify_after_decision(req: dict, action: str, step_idx: int):
    """Route the post-decision notification.

    Terminal outcomes always notify the requester. `returned` was previously
    omitted from this tuple, which is why a returned request told nobody — the
    status was set, the comment was audited, and no mail was ever sent. All
    three terminal statuses are now handled by notify_final_outcome().

    An `approve` that is not the final step advances the workflow instead: the
    next step's recipient is asked to act, and the requester and their manager
    get an "in progress" notice so the request is never silently mid-chain."""
    if req["status"] in ("approved", "rejected", "returned"):
        notify_final_outcome(req)
    elif action == "approve":
        _notify_next_approver(req, step_idx + 1)
        # ... and tell the requester and their manager where it now sits.
        notify_progress(req, step_idx, step_idx + 1)

# ── POLICY DOCUMENTS ─────────────────────────────────────────────────────────

def policy_doc_meta(form: str):
    m = get_setting(f"policy.{form}.doc", None)
    return m if isinstance(m, dict) and m.get("url") else None

# ONE-POLICY (2026-09-24): the New AI Use Case form and the AI Policy Acknowledgment
# show the SAME document. `cla` is the single slot administrators publish to; an
# earlier `aia` upload remains the fallback until the first cla publish.
def policy_doc_form(form: str) -> str:
    if form == "aia" and policy_doc_meta("cla"):
        return "cla"
    return form
def policy_doc_public_shown(form: str):
    d = policy_doc_public(policy_doc_form(form))
    if d:
        cur = current_policy_version(policy_doc_form(form)); d = dict(d)
        d["version"] = int(cur["version"]) if cur else 0; d["effective_date"] = (cur or {}).get("effective_date", "")
    return d

def policy_doc_public(form: str):
    """What the public content endpoint says about a form's document — enough
    to render it, no uploader identity."""
    m = policy_doc_meta(form)
    if not m:
        return None
    return {k: m.get(k) for k in ("name", "ext", "pages", "size", "url", "sha", "uploaded_at", "converted")}

# ── ACK-NOTIFY / ACK-AUDIT helpers (v5, 2026-09-24) ─────────────────────────
def emp_class_text(rec: dict) -> str:
    try: return employment_class(rec.get('email') or '').get('pay_class') or '\u2014'
    except Exception: return '\u2014'

def ack_notify_recipients(content: dict = None) -> list:
    raw = ((content if content is not None else content_all()).get("policy.cla.notify") or "")
    out, seen = [], set()
    for part in re.split(r"[\s,;]+", raw):
        p = part.strip().lower()
        if p and EMAIL_RE.match(p) and p not in seen:
            seen.add(p); out.append(p)
    return out[:25]

def ack_fte_roster_emails():
    """Set of FTE emails when the HR roster is available locally; None when the
    portal only sees pay class per person through the relay (today). The admin
    page then shows 'roster not exposed' instead of a wrong number."""
    try:
        cols = {r[1] for r in db().execute("PRAGMA table_info(hr_roster)")}
        if not cols or "email" not in cols or "pay_class" not in cols: return None
        return {r[0].lower() for r in db().execute("SELECT email FROM hr_roster WHERE LOWER(pay_class) IN ('regular ft','contingent worker')").fetchall() if r[0]}
    except Exception:
        return None

# ── RECORD EXPORTS (2026-09-24): one document model -> HTML / DOCX / PDF ────────
def _x(t) -> str:
    return html.escape("" if t is None else str(t), quote=True)

def record_docx_bytes(title: str, subtitle: str, sections: list) -> bytes:
    """Minimal, valid OOXML built with zipfile. sections = [(heading, rows)] where rows is a list of
    (label, value) pairs -> 2-column table, or a list of strings -> paragraphs."""
    import zipfile
    def p(text, bold=False, size=None, color=None, space=120):
        rpr = "".join(x for x in ["<w:b/>" if bold else "", f'<w:sz w:val="{size}"/>' if size else "", f'<w:color w:val="{color}"/>' if color else ""])
        return (f'<w:p><w:pPr><w:spacing w:after="{space}"/></w:pPr><w:r><w:rPr>{rpr}</w:rPr>'
                f'<w:t xml:space="preserve">{_x(text)}</w:t></w:r></w:p>')
    def cell(text, w, shade=None, bold=False):
        sh = f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>' if shade else ""
        lines = str(text if text is not None else "").split("\n")
        paras = "".join(f'<w:p><w:pPr><w:spacing w:after="40"/></w:pPr><w:r><w:rPr>{"<w:b/>" if bold else ""}<w:sz w:val="20"/></w:rPr><w:t xml:space="preserve">{_x(l)}</w:t></w:r></w:p>' for l in lines) or "<w:p/>"
        return f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{sh}</w:tcPr>{paras}</w:tc>'
    body = [p(title, bold=True, size=32, color="111827", space=40), p(subtitle, size=18, color="6B7280", space=240)]
    tblpr = ('<w:tblPr><w:tblW w:w="9360" w:type="dxa"/><w:tblBorders>'
             + "".join(f'<w:{b} w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/>' for b in ("top", "left", "bottom", "right", "insideH", "insideV"))
             + '</w:tblBorders><w:tblCellMar><w:left w:w="100" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar></w:tblPr>')
    for heading, rows in sections:
        body.append(p(heading.upper(), bold=True, size=18, color="5B6770", space=80))
        if rows and isinstance(rows[0], (tuple, list)):
            trs = "".join(f"<w:tr>{cell(k, 3000, shade='F3F4F6', bold=True)}{cell(v, 6360)}</w:tr>" for k, v in rows)
            body.append(f'<w:tbl>{tblpr}<w:tblGrid><w:gridCol w:w="3000"/><w:gridCol w:w="6360"/></w:tblGrid>{trs}</w:tbl>' + p("", space=120))
        else:
            for line in (rows or ["—"]):
                body.append(p(line, size=20, space=60))
    body.append(p(f"Generated by the Enterprise Approval Portal · {now_iso()[:16].replace('T', ' ')} UTC", size=16, color="9CA3AF", space=0))
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
           + "".join(body) +
           '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1200" w:right="1440" w:bottom="1200" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>'
           '</w:body></w:document>')
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
              '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults></w:styles>')
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
    drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct); z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", doc); z.writestr("word/styles.xml", styles); z.writestr("word/_rels/document.xml.rels", drels)
    return buf.getvalue()

def record_pdf_bytes(docx: bytes) -> bytes:
    """PDF via the LibreOffice already used for policy uploads."""
    d = tempfile.mkdtemp(prefix="rec-pdf-")
    try:
        path = os.path.join(d, "record.docx")
        with open(path, "wb") as f: f.write(docx)
        return _convert_to_pdf(path, timeout=90)
    finally:
        shutil.rmtree(d, ignore_errors=True)

def record_html_generic(title: str, subtitle: str, sections: list, stamp: str = "") -> str:
    """Printable HTML in the same style as the acknowledgment audit record."""
    parts = []
    for heading, rows in sections:
        parts.append(f"<h3>{_x(heading)}</h3>")
        if rows and isinstance(rows[0], (tuple, list)):
            parts.append("<table>" + "".join(f"<tr><td>{_x(k)}</td><td>{_x(v).replace(chr(10), '<br>')}</td></tr>" for k, v in rows) + "</table>")
        else:
            parts.append("".join(f"<p style='margin:4px 0;font-size:12.5px'>{_x(l)}</p>" for l in (rows or ['—'])))
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{_x(title)}</title>
<style>body{{font-family:'Segoe UI',system-ui,sans-serif;color:#111827;margin:0;background:#f3f4f6}}.doc{{background:#fff;max-width:820px;margin:24px auto;padding:44px 52px;border:1px solid #e5e7eb;position:relative}}
.top{{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #509E2F;padding-bottom:14px;margin-bottom:18px}}h1{{font-size:20px;margin:0}}.s{{color:#6b7280;font-size:12px;margin-top:4px}}
h3{{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#5B6770;margin:20px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}}table{{width:100%;border-collapse:collapse}}td{{padding:6px 8px;font-size:12.5px;border-bottom:1px dotted #e5e7eb;vertical-align:top}}td:first-child{{color:#6b7280;width:220px}}
.stamp{{position:absolute;right:52px;top:110px;border:2px solid #147299;color:#147299;border-radius:8px;padding:6px 12px;font-size:12px;font-weight:800;transform:rotate(-6deg);letter-spacing:.06em}}
.foot{{margin-top:22px;font-size:10.5px;color:#6b7280;border-top:1px solid #e5e7eb;padding-top:8px}}.bar{{max-width:820px;margin:16px auto 0;text-align:right}}.bar button{{font:inherit;padding:8px 14px;border-radius:8px;border:1px solid #d1d5db;background:#fff;cursor:pointer}}
@media print{{body{{background:#fff}}.doc{{border:0;margin:0;padding:0 0 20px}}.bar{{display:none}}}}</style></head><body>
<div class=bar><button onclick="window.print()">Print / Save as PDF</button></div>
<div class=doc>{f'<div class=stamp>{_x(stamp)}</div>' if stamp else ''}<div class=top><div><h1>{_x(title)}</h1><div class=s>{_x(subtitle)}</div></div><div style="width:44px;height:44px;border-radius:10px;background:#3a7d2c"></div></div>
{''.join(parts)}<div class=foot>Generated by the Enterprise Approval Portal from the record stored in the portal database.</div></div></body></html>"""

def request_record_model(r: dict) -> tuple:
    """(title, subtitle, sections, stamp) for a request row as _build_request_dict returns it."""
    sub = r.get("submitter") or {}; det = r.get("details") or {}
    label = REQUEST_TYPES.get(r["type"], {}).get("label", r["type"])
    status = {"pending": "Awaiting approval", "approved": "Approved", "rejected": "Rejected", "returned": "Returned to requester"}.get(r.get("status"), r.get("status", ""))
    wf = r.get("workflow") or []; aps = {a.get("step"): a for a in (r.get("approvals") or [])}
    cur = (r.get("current_step") or 0)
    ident = [("Request ID", r["id"]), ("Request type", label), ("Status", status + (f" · current step: {step_label(wf[cur])}" if r.get("status") == "pending" and cur < len(wf) else "")),
             ("Priority", (r.get("priority") or "normal").title()), ("Submitted", (r.get("created_at") or "")[:19].replace("T", " ") + " UTC"),
             ("Last updated", (r.get("updated_at") or "")[:19].replace("T", " ") + " UTC")]
    if r.get("archived_at"):   # ARCHIVE
        ident.append(("ARCHIVED", f"{(r.get('archived_at') or '')[:19].replace('T', ' ')} UTC by {r.get('archived_by') or ''}" + (f" — {r.get('archived_reason')}" if r.get("archived_reason") else "")))
    req = [("Name", sub.get("name", "")), ("Email", sub.get("email", "")), ("Department", sub.get("dept", "")), ("Job title", sub.get("title", "")),
           ("Manager", " ".join(x for x in (sub.get("manager_name", ""), f"<{sub.get('manager_email')}>" if sub.get("manager_email") else "") if x)),
           ("Identity", {"entra": "Corporate sign-in (Entra) · directory", "directory": "Directory lookup", "manual": "Typed by requester"}.get(str(sub.get("identity_source") or sub.get("source") or ""), str(sub.get("identity_source") or sub.get("source") or "—")))]
    skip = {"policy_reviewed", "policy_ack_via"}
    details = [(str(k).replace("_", " ").strip().capitalize(), ("Yes" if v is True else "No" if v is False else ", ".join(map(str, v)) if isinstance(v, list) else str(v)))
               for k, v in det.items() if k not in skip and v not in (None, "", [], {})]
    steps = []
    for i, k in enumerate(wf):
        a = aps.get(i) or {}
        st = a.get("status") or "pending"
        txt = {"approved": "Approved", "rejected": "Rejected", "returned": "Returned"}.get(st, "Awaiting review" if (r.get("status") == "pending" and i == cur) else "Pending")
        who = a.get("approver_name") or ""; when = (a.get("decided_at") or "")[:19].replace("T", " ")
        note = a.get("comments") or ""
        steps.append((f"{i+1}. {step_label(k)}", " · ".join(x for x in (txt, who, when + (" UTC" if when else ""), (f"“{note}”" if note else "")) if x)))
    hist = [f"{(e.get('created_at') or '')[:19].replace('T', ' ')} UTC · {e.get('event', '')} · {e.get('actor', '')}" + (f" — {str(e.get('note'))[:300]}" if e.get("note") else "") for e in (r.get("audit") or [])]
    sig = str(r.get("signature") or ""); sigtxt = ("Typed name: " + sig[6:]) if sig.startswith("typed:") else ("Drawn signature on file" if sig.startswith("canvas:") else "—")
    sections = [("Request", ident), ("Requester", req), ("Submitted details", details or [("—", "")]), ("Approval workflow", steps or [("—", "")]),
                ("Signature", [("Requester signature", sigtxt)]), ("History", hist or ["—"])]
    return (f"{label} — {r['id']}", f"Enterprise Approval Portal · {PORTAL_BASE_URL.replace('https://','').replace('http://','')} · status {status}", sections, status.upper())

def ack_record_model(p: dict, ver, aud: list, viewer: str) -> tuple:
    ver = ver or {}
    stmts = [f"{i+1}. {t}" for i, t in enumerate(p.get("statements") or [])] or ["—"]
    notes = [f"{a['event'][7:]}: {(a['note'] or '').replace('->', '→')}" for a in aud if a["event"].startswith("notify.")]
    corr = [f"{a['created_at'][:19].replace('T',' ')} UTC · {a['actor']} · {str(a['note'])[:300]}" for a in aud if a["event"] == "acknowledgment.identity_corrected"]
    sections = [
        ("Employee", [("Name", p.get("name", "")), ("Corporate email", p.get("email", "")), ("Employee / worker ID", p.get("employee_id") or "—"),
                      ("Department · Title", " · ".join(x for x in (p.get("dept"), p.get("title")) if x) or "—"),
                      ("Worker type (HR roster)", (p.get("employment_class") or "—") + (" · matched" if p.get("employment_matched") == "true" else " · unverified")),
                      ("Eligible via", {"admin_grant": "Administrator grant", "hr_roster": "HR status (FTE)"}.get(p.get("eligibility_source"), "—")),
                      ("Manager at signing", p.get("manager_email") or "—")]),
        ("Policy acknowledged", [("Document", f"{ver.get('file_name') or 'AI Policy'} — version {p.get('policy_version') or '-'}" + (f" · {ver.get('pages')} pages" if ver.get("pages") else "") + (f" · effective {ver.get('effective_date')}" if ver.get("effective_date") else "")),
                                 ("Document fingerprint", f"sha256 {p.get('policy_sha') or '—'}"), ("Published", ((ver.get("published_at") or "")[:10] + " by " + (ver.get("published_by") or "")).strip() or "—")]),
        ("Statements accepted", stmts),
        ("Acknowledgment", [("Record ID", f"ACK-{int(p['id']):06d}")] + ([("ARCHIVED", f"{(p.get('archived_at') or '')[:19].replace('T', ' ')} UTC by {p.get('archived_by') or ''}" + (f" — {p.get('archived_reason')}" if p.get('archived_reason') else ""))] if p.get("archived_at") else []) + [ ("Status", {"completed": "Completed · current version at time of export", "requires_reack": "Superseded — re-acknowledgment required"}.get(p.get("status"), p.get("status", ""))),
                            ("Acknowledged (UTC)", p.get("created_at") or ""), ("Electronic signature", ("Typed name: " + p.get("signature_text", "")) if p.get("signature_kind") == "typed" else ("Drawn signature on file" if p.get("signature_kind") == "canvas" else "—")),
                            ("Policy reviewed via", p.get("ack_via") or "—")]),
        ("System audit information", [("Identity source", (p.get("identity_source") or "—") + " · HR roster pay class"),
                                      ("Client", ((p.get("user_agent") or "—")[:120] + ((" · " + p["client_ip"]) if viewer == "admin" and p.get("client_ip") else ""))),
                                      ("Notifications", "\n".join(notes) if notes else "—"), ("Corrections", "\n".join(corr) if corr else "none"),
                                      ("Record integrity", f"SHA-256 {p.get('record_sha') or '—'}")]),
    ]
    return (f"Claude Access – Artificial Intelligence Policy Acknowledgment — Audit Record ACK-{int(p['id']):06d}", f"Enterprise Approval Portal · {PORTAL_BASE_URL.replace('https://','').replace('http://','')}", sections, f"RECORDED · ACK-{int(p['id']):06d}")

def ack_record_sha(f: dict) -> str:
    canon = "|".join(str(f.get(k, "")) for k in ("id", "form", "email", "policy_version", "policy_sha", "statement_sha", "signature", "created_at"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()

def ack_team_count(email: str) -> int:
    try:
        e = (email or "").lower()
        if not e: return 0
        return int(db().execute("SELECT COUNT(*) FROM acknowledgments WHERE LOWER(manager_email)=?", (e,)).fetchone()[0])
    except Exception:
        return 0

def ack_record_html(p: dict, ver, aud: list, generated_by: str, viewer: str) -> str:
    """Self-contained printable audit record (letter, print stylesheet). Same file for
    managers and administrators; the client IP shows only for administrators."""
    E = html.escape
    def row(k, v): return f"<tr><td>{E(k)}</td><td>{v}</td></tr>"
    stmts = "".join(f"<li>{E(t)}</li>" for t in (p.get("statements") or [])) or "<li>—</li>"
    sig = (f"<span class=sig>{E(p.get('signature_text') or '')}</span> <span class=mut>typed name · e-signature</span>" if p.get("signature_kind") == "typed"
           else ("<span class=mut>drawn signature (image on file in the portal)</span>" if p.get("signature_kind") == "canvas" else "—"))
    notes = []
    for a in aud:
        if a["event"].startswith("notify."): notes.append(f"{a['event'][7:]}: {(a['note'] or '').replace('->', '→')}")
    def _corr_text(a):
        try:
            j = json.loads(a["note"]); ch = "; ".join(f"{c.get('field')}: “{c.get('old') or '—'}” → “{c.get('new') or '—'}”" for c in j.get("changes", []))
            return f"{ch} · reason: {j.get('reason', '')}"
        except Exception:
            return (a["note"] or "")[:300]
    corr = [a for a in aud if a["event"] == "acknowledgment.identity_corrected"]
    corr_html = "<br>".join(f"{E(a['created_at'][:19].replace('T', ' '))} UTC · {E(a['actor'])} · {E(_corr_text(a))}" for a in corr) or "none"
    ver = ver or {}
    status = {"completed": "Completed · current version at time of export", "requires_reack": "Superseded — a newer policy version is published; re-acknowledgment required"}.get(p.get("status"), p.get("status", ""))
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>ACK-{p['id']:06d} · Claude Access – Artificial Intelligence Policy Acknowledgment — Audit Record</title>
<style>body{{font-family:'Segoe UI',system-ui,sans-serif;color:#111827;margin:0;background:#f3f4f6}}.doc{{background:#fff;max-width:820px;margin:24px auto;padding:44px 52px;border:1px solid #e5e7eb;position:relative}}
.top{{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #509E2F;padding-bottom:14px;margin-bottom:18px}}h1{{font-size:20px;margin:0}}.s{{color:#6b7280;font-size:12px}}
h3{{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#5B6770;margin:20px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}}table{{width:100%;border-collapse:collapse}}td{{padding:6px 8px;font-size:12.5px;border-bottom:1px dotted #e5e7eb;vertical-align:top}}td:first-child{{color:#6b7280;width:220px}}
.stamp{{position:absolute;right:52px;top:110px;border:2px solid #059669;color:#059669;border-radius:8px;padding:6px 12px;font-size:12px;font-weight:800;transform:rotate(-6deg);letter-spacing:.06em}}.sig{{font-family:'Brush Script MT','Snell Roundhand',cursive;font-size:28px}}.mut{{color:#6b7280;font-size:12px}}.mono{{font-family:ui-monospace,Menlo,monospace;font-size:12px}}
.foot{{margin-top:22px;font-size:10.5px;color:#6b7280;border-top:1px solid #e5e7eb;padding-top:8px;line-height:1.5}}.bar{{max-width:820px;margin:16px auto 0;text-align:right}}.bar button{{font:inherit;padding:8px 14px;border-radius:8px;border:1px solid #d1d5db;background:#fff;cursor:pointer}}
@media print{{body{{background:#fff}}.doc{{border:0;margin:0;padding:0 0 20px}}.bar{{display:none}}}}</style></head><body>
<div class=bar><button onclick="window.print()">Print / Save as PDF</button></div>
<div class=doc><div class=stamp>RECORDED · ACK-{p['id']:06d}</div>
<div class=top><div><h1>Claude Access – Artificial Intelligence Policy Acknowledgment — Audit Record</h1><div class=s>Enterprise Approval Portal · {E(PORTAL_BASE_URL.replace('https://','').replace('http://',''))} · generated {E(now_iso()[:16].replace('T',' '))} UTC by {E(generated_by or 'portal')}</div></div><div style="width:44px;height:44px;border-radius:10px;background:#3a7d2c"></div></div>
<h3>Employee</h3><table>{row('Name', E(p.get('name') or ''))}{row('Corporate email', E(p.get('email') or ''))}{row('Employee / worker ID', E(p.get('employee_id') or '—'))}{row('Department · Title', E(' · '.join(x for x in (p.get('dept'), p.get('title')) if x) or '—'))}{row('Worker type (HR roster)', E((p.get('employment_class') or '—') + (' · matched' if p.get('employment_matched') == 'true' else ' · unverified')))}{row('Manager at signing', E(p.get('manager_email') or '—'))}</table>
<h3>Policy acknowledged</h3><table>{row('Document', f"{E(ver.get('file_name') or 'AI Policy')} — <b>version {E(str(p.get('policy_version') or '-'))}</b>" + (f" · {ver.get('pages')} pages" if ver.get('pages') else '') + (f" · effective {E(ver.get('effective_date'))}" if ver.get('effective_date') else ''))}{row('Document fingerprint', f"<span class=mono>sha256 {E(p.get('policy_sha') or '—')}</span>")}{row('Published', E(((ver.get('published_at') or '')[:10] + ' by ' + (ver.get('published_by') or '')).strip() or '—'))}{row('Statements accepted', f"<ol style='margin:0;padding-left:18px'>{stmts}</ol>")}</table>
<h3>Acknowledgment</h3><table>{row('Record ID', f"<span class=mono>ACK-{p['id']:06d}</span>")}{row('Status', E(status))}{row('Acknowledged (UTC)', E(p.get('created_at') or ''))}{row('Electronic signature', sig)}{row('Policy reviewed via', E({'scroll': 'Scrolled to the last page before the acknowledgment was enabled', 'download': 'Downloaded the document', 'open': 'Opened the document in a new tab', 'visible': 'Document fully visible on screen'}.get(p.get('ack_via'), p.get('ack_via') or '—')))}</table>
<h3>System audit information</h3><table>{row('Identity source', E((p.get('identity_source') or '—') + ' · HR roster pay class'))}{row('Client', E((p.get('user_agent') or '—')[:120] + ((' · ' + p['client_ip']) if viewer == 'admin' and p.get('client_ip') else '')))}{row('Notifications', '<br>'.join(E(n) for n in notes) if notes else '—')}{row('Corrections', corr_html)}{row('Record integrity', f"<span class=mono>SHA-256 {E(p.get('record_sha') or '—')}</span><br><span class=mut>computed at signing over id · form · email · policy version · policy sha · statement sha · signature · time; re-verifiable in the Administrator console</span>")}</table>
<div class=foot>This record was generated by the Enterprise Approval Portal from the acknowledgment stored in the portal database. The acknowledgment itself (statements, signature, policy version, time) is immutable; identity fields may be corrected only by a portal administrator, and every correction is logged above.</div></div></body></html>"""

def _ack_daily_summary_once(today_local: str):
    """Send the daily admin/IT summary if mode is daily and something happened yesterday."""
    content = content_all()
    if (content.get("policy.cla.notify_mode") or "each").strip().lower() != "daily": return
    rcpts = ack_notify_recipients(content)
    if not rcpts: return
    last = get_setting("policy.cla.notify_last_daily", "") or ""
    since = last if last else (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    rows = [dict(r) for r in db().execute("SELECT * FROM acknowledgments WHERE form='cla' AND sample=0 AND substr(created_at,1,10)>=? AND substr(created_at,1,10)<? ORDER BY created_at", (since, today_local)).fetchall()]
    set_setting("policy.cla.notify_last_daily", today_local)
    if not rows: return
    cur = current_policy_version("cla"); cur_v = int(cur["version"]) if cur else 0
    total = db().execute("SELECT COUNT(DISTINCT LOWER(email)) FROM acknowledgments WHERE form='cla' AND sample=0 AND policy_version=?", (cur_v,)).fetchone()[0]
    label = ACK_LABELS.get("cla", "Claude Access – Artificial Intelligence Policy Acknowledgment")
    trs = "".join(f"<tr><td>{html.escape(r.get('name') or '')}<br><span style=\"color:#6b7280\">{html.escape(r.get('email') or '')}</span></td><td>{html.escape(r.get('dept') or '')}</td><td>{html.escape(r.get('manager_email') or '')}</td><td>v{r.get('policy_version')}</td><td>{html.escape((r.get('created_at') or '')[:16].replace('T',' '))}</td><td>ACK-{r['id']}</td></tr>" for r in rows)
    body = (f"<p><strong>{len(rows)}</strong> acknowledgment(s) recorded since {html.escape(since)}. <strong>{total}</strong> people are on the current version (v{cur_v}).</p>"
            f"<table cellpadding=\"5\" style=\"font-size:12.5px;border-collapse:collapse\"><tr style=\"text-align:left;color:#6b7280\"><th>Person</th><th>Department</th><th>Manager</th><th>Ver</th><th>When (UTC)</th><th>Record</th></tr>{trs}</table>"
            f"<p><a href=\"{PORTAL_BASE_URL}/approver.html\">Open the Approver Portal</a> → Administration → Claude Access Acknowledgments.</p>")
    try: body = _email_html_wrapper(email_art("approved"), f"{label} — daily summary", body)
    except Exception: pass
    okm = send_email(rcpts, f"{label} \u2014 daily summary \u00b7 {len(rows)} new", body, f"{len(rows)} acknowledgment(s) since {since}; {total} on v{cur_v}.")
    audit("", "acknowledgments.daily_summary", "system", "", (f"sent -> {', '.join(rcpts)} · {len(rows)} record(s)" if okm else f"FAILED -> {', '.join(rcpts)} · {mail_last_error() or 'relay refused'}"))

def ack_daily_thread():
    """08:00 server-local, once per day, in-process (no extra service). Cheap: one check a minute."""
    def loop():
        while True:
            try:
                now = datetime.now()
                if now.hour == 8 and (get_setting("policy.cla.notify_last_daily", "") or "") != now.strftime("%Y-%m-%d"):
                    _ack_daily_summary_once(now.strftime("%Y-%m-%d"))
            except Exception as e:
                print(f"[ACK] daily summary error: {e}", file=sys.stderr)
            time.sleep(60)
    t = threading.Thread(target=loop, name="ack-daily-summary", daemon=True); t.start()

# ── APPROVER-REMINDERS (2026-10-16) ──────────────────────────────────────────
# Daily sweep: a request that has waited at its current step for N days reminds
# the step recipient (direct manager, or the step's configured address); repeats
# every M days up to a cap; cc Service Desk from the escalation count onward.
# Form-agnostic: driven by requests.current_step + step_recipient(). Reminder
# history lives in audit_log (event notification.reminder), so no new table.
REMINDER_DEFAULTS = {"enabled": True, "first_days": 3, "every_days": 3, "max": 5, "escalate_after": 3, "hour": 8}

def reminder_settings() -> dict:
    s = dict(REMINDER_DEFAULTS); v = get_setting("reminders.settings", None)
    if isinstance(v, dict): s.update({k: v[k] for k in REMINDER_DEFAULTS if k in v})
    return s

def _iso_dt(x):
    try: return datetime.fromisoformat(str(x).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception: return None

def _reminder_candidates(now=None) -> list:
    """Pending, unarchived requests with their current-step age and reminder history."""
    now = now or datetime.now(timezone.utc); cfg = reminder_settings(); out = []
    for r in db().execute("SELECT * FROM requests WHERE status='pending' AND COALESCE(archived_at,'')='' ORDER BY created_at"):
        wf = json.loads(r["workflow"]); idx = r["current_step"]
        if idx >= len(wf): continue
        step = wf[idx]
        since = _iso_dt(r["created_at"])
        prev = db().execute("SELECT MAX(decided_at) FROM approvals WHERE request_id=? AND step<? AND decided_at IS NOT NULL", (r["id"], idx)).fetchone()[0]
        reop = db().execute("SELECT MAX(created_at) FROM audit_log WHERE request_id=? AND event LIKE 'Reopened to %'", (r["id"],)).fetchone()[0]
        for cand in (prev, reop):
            d = _iso_dt(cand)
            if d and (since is None or d > since): since = d
        if since is None: continue
        age = (now - since).total_seconds() / 86400.0
        hist = db().execute("SELECT created_at FROM audit_log WHERE request_id=? AND event='notification.reminder' AND created_at>=? AND note LIKE ? ORDER BY created_at",
                            (r["id"], since.isoformat(), f"step={step};%")).fetchall()
        n = len(hist); last = _iso_dt(hist[-1]["created_at"]) if hist else None
        due = age >= cfg["first_days"] and n < cfg["max"] and (last is None or (now - last).total_seconds() / 86400.0 >= cfg["every_days"])
        req = _build_request_dict(r)
        email, name, source = step_recipient(req, step)
        out.append({"id": r["id"], "type": r["type"], "step": step, "step_label": step_label(step), "age_days": round(age, 1),
                    "since": since.isoformat(), "sent": n, "last": last.isoformat() if last else None, "due": due,
                    "to": email or "", "to_name": name or "", "source": source or "", "escalate": due and (n + 1) >= cfg["escalate_after"],
                    "submitter": (req.get("submitter") or {}).get("name"), "_req": req})
    return out

def _send_reminder(c: dict, cfg: dict) -> bool:
    req = c["_req"]; rt = REQUEST_TYPES.get(req["type"], {}); icon = type_art(req["type"]); subm = _esc_map(req.get("submitter") or {})
    age = int(c["age_days"]); nth = c["sent"] + 1
    if not c["to"]:
        audit(c["id"], "notification.reminder", "System", "Automation", f"step={c['step']}; n={nth}; UNROUTABLE — no recipient for {c['step_label']}")
        return False
    body = f"""
<div style="background:#fff7ed;border-left:4px solid #f59e0b;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:18px;font-size:13px;color:#92400e;font-weight:600">
  Reminder {nth}{' — escalated to the Service Desk' if c['escalate'] else ''} · waiting {age} day{'s' if age != 1 else ''} at your step
</div>
<p style="font-size:15px;color:#1f2937">Hi <strong>{html.escape(str(c['to_name'] or ''))}</strong>,</p>
<p style="font-size:14px;color:#5B6770;line-height:1.6;margin:12px 0">Request <strong>{req['id']}</strong> ({rt.get('label','')}) is still waiting for your <strong>{html.escape(c['step_label'])}</strong> decision. Please approve, reject or return it in the Approver Portal.</p>
<table style="width:100%;border-collapse:collapse;border:1px solid #e3e7ea;border-radius:8px;overflow:hidden;font-size:13px">
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600;width:40%">Request ID</td><td style="padding:10px 14px;font-family:ui-monospace,Menlo,monospace;color:#509E2F;font-weight:700">{req['id']}</td></tr>
  <tr><td style="padding:10px 14px;color:#5B6770;font-weight:600">Request Type</td><td style="padding:10px 14px">{icon}&nbsp; {rt.get('label','')}</td></tr>
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600">Submitted By</td><td style="padding:10px 14px">{subm.get('name','')} · {subm.get('dept','')}</td></tr>
  <tr><td style="padding:10px 14px;color:#5B6770;font-weight:600">Your Step</td><td style="padding:10px 14px"><span style="background:#fef3c7;color:#92400e;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700">{html.escape(c['step_label'])}</span></td></tr>
  <tr style="background:#f8fafb"><td style="padding:10px 14px;color:#5B6770;font-weight:600">Waiting since</td><td style="padding:10px 14px">{html.escape(c['since'][:10])} · {age} day{'s' if age != 1 else ''}</td></tr>
</table>
<p style="font-size:12.5px;color:#5B6770;margin-top:14px"><a href="{PORTAL_BASE_URL}/approver.html">Open the Approver Portal</a></p>"""
    subject = f"Reminder: {c['step_label']} approval waiting {age}d — {req['id']}"
    okm = mail_and_audit(req["id"], c["to"], subject,
                         _email_html_wrapper(icon, f"Still waiting: {c['step_label']} approval", body, req["id"],
                                             f"Reminder {nth} of {cfg['max']} · sent to {html.escape(c['to'])}"),
                         f"approval reminder {nth} ({c['step_label']})")
    if c["escalate"]:
        hd = get_smtp().get("helpdesk", "")
        if hd and hd.lower() != (c["to"] or "").lower():
            mail_and_audit(req["id"], hd, f"[Escalation] {subject}",
                           _email_html_wrapper("⚠️", f"Escalation: {c['step_label']} approval overdue", body, req["id"], f"Reminder {nth} · approver {html.escape(c['to'])} copied the Service Desk"),
                           f"approval reminder {nth} escalation (Service Desk)")
    audit(req["id"], "notification.reminder", "System", "Automation",
          f"step={c['step']}; n={nth}; to={c['to']}; age={age}d; escalate={'yes' if c['escalate'] else 'no'}; {'sent' if okm else 'FAILED'}")
    return bool(okm)

def reminders_run(dry: bool = False) -> dict:
    cfg = reminder_settings(); cands = _reminder_candidates(); due = [c for c in cands if c["due"]]
    sent = 0
    if not dry:
        for c in due:
            try:
                if _send_reminder(c, cfg): sent += 1
            except Exception as e:  # noqa
                print(f"[REMIND] {c['id']}: {e}", file=sys.stderr)
    return {"settings": cfg, "checked": len(cands), "due": len(due), "sent": sent, "dry": dry,
            "rows": [{k: v for k, v in c.items() if k != "_req"} for c in cands]}

def reminder_daily_thread():
    """Once per day at reminders.hour server-local, in-process (same pattern as ack_daily_thread)."""
    def loop():
        while True:
            try:
                cfg = reminder_settings(); now = datetime.now()
                if cfg["enabled"] and now.hour == int(cfg["hour"]) and (get_setting("reminders.last_run", "") or "") != now.strftime("%Y-%m-%d"):
                    set_setting("reminders.last_run", now.strftime("%Y-%m-%d"))
                    res = reminders_run(False)
                    audit("", "reminders.daily_run", "system", "", f"checked={res['checked']} due={res['due']} sent={res['sent']}")
            except Exception as e:
                print(f"[REMIND] daily error: {e}", file=sys.stderr)
            time.sleep(60)
    threading.Thread(target=loop, name="approver-reminders", daemon=True).start()
# ── end APPROVER-REMINDERS ────────────────────────────────────────────────────

def _publish_policy_document(form, data, pdf, name, ext, converted, effective, pages, actor, role):
    """Durable files followed by one serialized metadata/settings/audit commit.

    Files from an aborted transaction remain recoverable. Their version numbers
    stay reserved so a later upload cannot overwrite an orphaned original.
    """
    with write_lock:
        conn = db()
        if conn.in_transaction:
            raise RuntimeError("Policy publication requires a clean transaction")
        # The database lock also serializes publishers in separate processes.
        conn.execute("BEGIN IMMEDIATE")
        try:
            private_dir = os.path.join(POLICY_DIR, form)
            durable_makedirs(private_dir)
            durable_makedirs(POLICY_PUBLIC_DIR)
            row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM policy_versions WHERE form=?", (form,)).fetchone()
            version = int(row[0] or 0) + 1
            for existing in os.listdir(private_dir):
                match = re.fullmatch(r"original-v(\d+)\.[A-Za-z0-9]+", existing)
                if match:
                    version = max(version, int(match.group(1)) + 1)
            sha = hashlib.sha256(pdf).hexdigest()[:10]
            pub_name = f"{form}-policy-{sha}.pdf"
            public_path = os.path.join(POLICY_PUBLIC_DIR, pub_name)
            if os.path.exists(public_path):
                with open(public_path, "rb") as existing:
                    if existing.read() != pdf:
                        raise RuntimeError("Policy filename collision; existing document preserved")
            atomic_write_durable(os.path.join(private_dir, f"original-v{version}.{ext}"), data)
            atomic_write_durable(public_path, pdf, mode=0o644)
            # No SQL reference is changed until both files and directory entries
            # are durable. Do not call helpers that commit or swallow audit errors.
            now = now_iso()
            url = f"{POLICY_PUBLIC_URL}/{pub_name}"
            meta = {"name": name, "ext": ext, "size": len(data), "pdf_size": len(pdf), "pages": pages,
                    "sha": sha, "url": url, "converted": converted, "version": version,
                    "effective_date": effective, "uploaded_by": actor, "uploaded_at": now}
            conn.execute("UPDATE policy_versions SET retired_at=? WHERE form=? AND retired_at=''", (now, form))
            conn.execute(
                "INSERT INTO policy_versions (form,version,sha,url,file_name,ext,pages,pdf_size,"
                " effective_date,published_by,published_at,retired_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,'')",
                (form, version, sha, url, name, ext, pages, len(pdf), effective, actor, now))
            conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (f"policy.{form}.doc", json.dumps(meta)))
            note = (f"{form} v{version}: {name} ({len(data)} bytes, {pages} page(s)"
                    f"{', converted to PDF' if converted else ''}{', effective ' + effective if effective else ''}) -> {url}")
            conn.execute(
                "INSERT INTO audit_log(request_id,event,actor,role,note,created_at) VALUES(?,?,?,?,?,?)",
                ("", "policy.document.uploaded", actor or "System", role or "", note[:4000], now))
            conn.commit()
        except BaseException:
            try:
                if conn.in_transaction:
                    conn.rollback()
            except BaseException:
                # Never leave a failed transaction available for another helper
                # to accidentally commit on a later request in this thread.
                try:
                    conn.close()
                finally:
                    if getattr(_thread_local, "conn", None) is conn:
                        del _thread_local.conn
                raise
            raise
        return meta


def next_policy_version(form: str) -> int:
    row = db().execute("SELECT COALESCE(MAX(version), 0) FROM policy_versions WHERE form=?", (form,)).fetchone()
    return int(row[0] or 0) + 1

def current_policy_version(form: str):
    """The version row a new acknowledgement should point at, or None."""
    row = db().execute(
        "SELECT * FROM policy_versions WHERE form=? AND retired_at='' ORDER BY version DESC LIMIT 1",
        (form,)).fetchone()
    return dict(row) if row else None

def _pdf_page_count(data: bytes) -> int:
    n = len(re.findall(rb"/Type\s*/Page(?![s/])", data))
    return n if n > 0 else 1

def _convert_to_pdf(src_path: str, timeout: int = 150) -> bytes:
    """LibreOffice headless -> PDF bytes. Raises RuntimeError with a message
    fit for the administrator on any failure."""
    if not SOFFICE:
        raise RuntimeError("Only PDF can be uploaded on this server — export the document to PDF first. "
                           "(Word/PowerPoint conversion needs LibreOffice: sudo apt-get install -y --no-install-recommends libreoffice-writer libreoffice-impress)")
    out = tempfile.mkdtemp(prefix="policy-conv-")
    try:
        # A private profile dir keeps concurrent conversions from fighting over the lock file.
        prof = "-env:UserInstallation=file://" + out + "/profile"
        r = subprocess.run([SOFFICE, prof, "--headless", "--norestore", "--nologo", "--convert-to", "pdf", "--outdir", out, src_path],
                           capture_output=True, text=True, timeout=timeout)
        pdfs = [f for f in os.listdir(out) if f.lower().endswith(".pdf")]
        if r.returncode != 0 or not pdfs:
            raise RuntimeError("Conversion to PDF failed: " + ((r.stderr or r.stdout or "").strip()[-300:] or "no output"))
        with open(os.path.join(out, pdfs[0]), "rb") as f:
            data = f.read()
        if not data.startswith(b"%PDF-"):
            raise RuntimeError("Conversion produced an unreadable file")
        return data
    except subprocess.TimeoutExpired:
        raise RuntimeError("Conversion timed out — the document may be too large or complex; export it to PDF instead")
    finally:
        shutil.rmtree(out, ignore_errors=True)

# ── HTTP HANDLER ──────────────────────────────────────────────────────────────

def parse_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length", 0) or 0)
    if length <= 0:
        return {}
    if length > MAX_BODY_BYTES:
        try: handler.rfile.read(min(length, MAX_BODY_BYTES))
        except Exception: pass
        return {}
    raw = handler.rfile.read(length).decode("utf-8", errors="replace")
    try:
        return json.loads(raw)
    except Exception:
        return {}

def respond(handler, status: int, data, extra_headers: dict = None):
    body = json.dumps(data, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
    handler.send_header("Access-Control-Allow-Credentials", "true")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization,Cookie")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
    if extra_headers:
        for k, v in extra_headers.items():
            handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)

def ok(handler, data=None, **kwargs):
    respond(handler, 200, {"ok": True, "data": kwargs if data is None else data})

def err(handler, status: int, message: str):
    respond(handler, status, {"ok": False, "error": message})

# ── AUTHORIZATION (separation of duties) ────────────────────────────────────

def is_superadmin(session: dict) -> bool:
    """Portal super-admin = X-ITAM-Tier 'superadmin'. Unfiltered visibility and
    policy administration only — never a decision right by itself."""
    return bool((session or {}).get("is_superadmin")) or \
        (str((session or {}).get("tier") or "").strip().lower() == "superadmin")

ADMIN_GUIDE_READERS = frozenset({"jriggs@auction.com", "rabad@auction.com"})

def can_read_access_guide(session: dict) -> bool:
    """Private documentation: current corporate admin identity + named owner."""
    return bool(session and session.get("source") == "sso"
                and session.get("role") == "admin"
                and str(session.get("email") or "").strip().lower() in ADMIN_GUIDE_READERS)

def _steps_json(raw) -> list:
    """Decode a policy's stored step list: known keys only, de-duplicated, in
    STEP_LABELS order. Garbled storage degrades to [] (grants nothing)."""
    try:
        v = json.loads(raw) if isinstance(raw, (str, bytes)) else (raw or [])
    except Exception:
        v = []
    if not isinstance(v, list):
        v = []
    keep = {str(x).strip().lower() for x in v}
    return [s for s in STEP_LABELS if s in keep]

def _policy_dict(row) -> dict:
    """approval_access_policies row → the Policy JSON shape (DESIGN §5)."""
    p = dict(row)
    p["view_steps"]   = _steps_json(p.get("view_steps"))
    p["decide_steps"] = _steps_json(p.get("decide_steps"))
    p["enabled"]      = bool(p.get("enabled"))
    p["request_types"] = json.loads(p.get("request_types") or "[]")
    p["effect"] = p.get("effect") or "allow"
    p["expires_at"] = p.get("expires_at") or None
    p["reason"] = p.get("reason") or ""
    p["expired"] = bool(p["expires_at"] and p["expires_at"] <= now_iso())
    # ad_group policies may name several RBAC role keys (sorted, comma-joined in principal_key)
    p["principal_keys"] = _policy_keys(p.get("principal_type"), p.get("principal_key"))
    return p

def _policy_keys(ptype, pkey) -> list:
    if ptype == "ad_group":
        return [k for k in str(pkey or "").split(",") if k]
    return [str(pkey or "")] if pkey else []

def effective_access(session: dict, conn=None, request_type=None) -> dict:
    """One evaluator for admission, reads and decisions. Grants union; user blocks win.
    request_type=None is a tile summary; actual data/decisions always evaluate a type.
    HR Department metadata is never an authorization input.
    """
    conn = conn or db()
    cache_key = "_effective_access_" + (request_type or "summary")
    if cache_key in session:
        return session[cache_key]
    email = (session.get("email") or "").strip().lower()
    roles = set(session.get("roles") or [])
    view, decide, denied, sources = set(), set(), set(), []
    all_steps = set(STEP_LABELS)
    rows = conn.execute("SELECT * FROM approval_access_policies WHERE enabled=1 ORDER BY id").fetchall()
    for row in rows:
        p = _policy_dict(row)
        if p["expired"] or (request_type and p["request_types"] and request_type not in p["request_types"]):
            continue
        matched = sorted(roles.intersection(p["principal_keys"])) if p["principal_type"] == "ad_group" else []
        if (p["principal_type"] == "ad_group" and not matched) or (p["principal_type"] == "user" and p["principal_key"] != email):
            continue
        vs = all_steps if p["view_scope"] == "all" else set(p["view_steps"])
        ds = all_steps if p["decide_scope"] == "all" else set(p["decide_steps"])
        if p["effect"] == "block":
            if request_type or not p["request_types"]:
                denied.update(vs)
        else:
            view.update(vs | ds)
            decide.update(ds)
        sources.append({"kind": "policy", "id": p["id"], "name": p["name"],
                        "principal_type": p["principal_type"], "principal_key": p["principal_key"],
                        "matched_key": "+".join(matched) or p["principal_key"],
                        "view": p["view_scope"], "view_steps": p["view_steps"],
                        "decide": p["decide_scope"], "decide_steps": p["decide_steps"],
                        "effect": p["effect"], "request_types": p["request_types"], "expires_at": p["expires_at"]})
    # Person blocks also override request-specific manager access.
    view -= denied; decide -= denied
    mgr_ids = sorted(_manager_request_ids(email)) if "manager" not in denied else []
    if request_type and mgr_ids:
        mgr_ids = [r["id"] for r in conn.execute("SELECT id FROM requests WHERE type=?", (request_type,)) if r["id"] in mgr_ids]
    if mgr_ids:
        sources.append({"kind": "direct_manager", "requests": len(mgr_ids)})
    acc = {"is_superadmin": is_superadmin(session), "view_all": view == all_steps,
           "view_steps": [x for x in STEP_LABELS if x in view], "decide_all": decide == all_steps,
           "decide_steps": [x for x in STEP_LABELS if x in decide], "blocked_steps": [x for x in STEP_LABELS if x in denied],
           "manager_of_requests": mgr_ids, "sources": sources,
           "blocked": denied == all_steps}
    session[cache_key] = acc
    return acc

# Policy validation (DESIGN §5). Same role-key rule as the hub's saas-admin KEY_RE.
POLICY_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
POLICY_FIELDS = ("name", "principal_type", "principal_key",
                 "view_scope", "view_steps", "decide_scope", "decide_steps", "enabled",
                 "request_types", "expires_at", "reason", "effect")

def _clean_steps(raw, field: str) -> tuple:
    """(steps, error): keys ⊆ STEP_LABELS, de-duplicated, STEP_LABELS order."""
    if raw is None or raw == "":
        return [], None
    if isinstance(raw, str):
        raw = raw.split(",")
    if not isinstance(raw, list):
        return None, f"{field} must be a list of step keys"
    out = []
    for x in raw:
        k = str(x).strip().lower()
        if k not in STEP_LABELS:
            return None, f"{field}: unknown step '{k}'"
        if k not in out:
            out.append(k)
    return [s for s in STEP_LABELS if s in out], None

def _validate_policy(data: dict) -> tuple:
    """Validate a COMPLETE policy record → (clean, error). Enforces
    'you cannot decide what you cannot see': decide_steps ⊆ view_steps and
    decide=all requires view=all."""
    name = " ".join(str(data.get("name") or "").split())
    if not 1 <= len(name) <= 80:
        return None, "name must be 1-80 characters"
    ptype = str(data.get("principal_type") or "").strip().lower()
    if ptype not in ("ad_group", "user"):
        return None, "principal_type must be 'ad_group' or 'user'"
    pkey = str(data.get("principal_key") or "").strip().lower()
    if ptype == "ad_group":
        # one or more role keys: principal_keys (list) and/or principal_key (comma-separated)
        raw = data.get("principal_keys")
        raw = list(raw) if isinstance(raw, (list, tuple)) else []
        raw += pkey.split(",")
        keys = []
        for k in raw:
            k = str(k).strip().lower()
            if not k:
                continue
            if not POLICY_KEY_RE.match(k):
                return None, f"principal_key must be a role key: lower-case letters, digits and hyphens (max 64) — not '{k}'"
            if k not in keys:
                keys.append(k)
        if not keys:
            return None, "principal_key must name at least one RBAC role key"
        if len(keys) > 20:
            return None, "principal_key may name at most 20 role keys"
        pkey = ",".join(sorted(keys))
    elif len(pkey) > 254 or not ADDR_RE.match(pkey):
        return None, "principal_key must be a valid email address"
    vscope = str(data.get("view_scope") or "").strip().lower()
    dscope = str(data.get("decide_scope") or "").strip().lower()
    if vscope not in ("all", "steps"):
        return None, "view_scope must be 'all' or 'steps'"
    if dscope not in ("all", "steps"):
        return None, "decide_scope must be 'all' or 'steps'"
    vsteps, e = _clean_steps(data.get("view_steps"), "view_steps")
    if e:
        return None, e
    dsteps, e = _clean_steps(data.get("decide_steps"), "decide_steps")
    if e:
        return None, e
    if vscope == "steps" and not vsteps:
        return None, "view_steps must list at least one step when view_scope is 'steps'"

    if dscope == "all" and vscope != "all":
        return None, "decide_scope 'all' requires view_scope 'all' — you cannot decide what you cannot see"
    if dscope == "steps" and vscope == "steps" and not set(dsteps) <= set(vsteps):
        return None, "decide_steps must be a subset of view_steps — you cannot decide what you cannot see"
    # MANAGER-STEP GUARD — the Dept. Manager step is routed per request to the
    # requester's direct manager (submitter.manager_email); granting it by policy
    # exposes every manager-step request portal-wide.  Blocks remain allowed.
    if (data.get("effect") or "allow") != "block" and "manager" in set(vsteps) | set(dsteps):
        return None, ("The Dept. Manager step cannot be granted by policy. Managers see their own "
                      "direct reports' requests automatically; remove 'manager' from the steps.")
    enabled = data.get("enabled", True)
    if not isinstance(enabled, (bool, int)):
        return None, "enabled must be true or false"
    types = data.get("request_types") or []
    if not isinstance(types, list) or any(t not in REQUEST_TYPES for t in types):
        return None, "request_types must contain valid request type keys"
    effect = data.get("effect") or "allow"
    if effect not in ("allow", "block") or (effect == "block" and ptype != "user"):
        return None, "Blocks are available only for individual users"
    expiry = data.get("expires_at") or None
    if expiry:
        try:
            dt = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                raise ValueError()
            expiry = dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError):
            return None, "expires_at must be an ISO timestamp with a timezone"
    reason = str(data.get("reason") or "").strip()
    if len(reason) > 1000:
        return None, "reason must be at most 1000 characters"
    return {"request_types": sorted(set(types)), "expires_at": expiry, "reason": reason, "effect": effect,
            "name": name, "principal_type": ptype, "principal_key": pkey,
            "view_scope": vscope, "view_steps": vsteps,
            "decide_scope": dscope, "decide_steps": dsteps,
            "enabled": bool(enabled)}, None

def verify_policy_principal(clean):
    """Validate real directory objects before a new principal gets a grant."""
    if clean["principal_type"] == "user":
        state, _ = directory_lookup_server(clean["principal_key"])
        return None if state == "found" else "An enabled directory person could not be confirmed. Check the email and retry."
    payload = json.dumps({"keys": _policy_keys("ad_group", clean["principal_key"])}).encode()
    parsed = urlparse(LOOKUP_URL)
    url = f"{parsed.scheme}://{parsed.netloc}/internal/department-principal"
    try:
        req = urllib.request.Request(url, data=payload, headers={LOOKUP_KEY_HEADER: LOOKUP_KEY, "Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            result = json.loads(r.read())
        return None if result.get("ok") else "Choose a mapped directory security group"
    except urllib.error.HTTPError as e:
        try: return str(json.loads(e.read()).get("error") or "Directory group validation failed")
        except Exception: return "Directory group validation failed"
    except Exception:
        return "Directory validation is unavailable. Retry before saving."

def _grant_source(session: dict, step_key: str, req: dict = None) -> str | None:
    """The grant that lets this session decide step_key, or None. Checked in
    order: policy grants (first enabled policy covering the step, by id), the
    manual ACL, then the direct-manager per-request rule. The string is what
    record_decision() writes into the audit note ('[grant: …]')."""
    acc = effective_access(session, request_type=(req or {}).get("type"))
    if step_key in acc["blocked_steps"]:
        return None
    for src in acc["sources"]:
        if src["kind"] == "policy" and src.get("effect") != "block" and (src["decide"] == "all" or step_key in src["decide_steps"]):
            return f"policy:{src['id']}:{src.get('matched_key') or src['principal_key']}"
    for src in acc["sources"]:
        if src["kind"] == "manual" and src["step"] == step_key:
            return f"manual:{step_key}"
    if req is not None and step_key == "manager":
        email = (session.get("email") or "").strip().lower()
        if email and email == request_manager_email(req):
            return "direct-manager"
    return None

def is_authorized_for_step(session: dict, step_key: str, req: dict = None) -> bool:
    """Deny-by-default decision check (DESIGN §3 rule 4). A step is decidable
    only through an explicit grant in effective_access():
      1. an enabled policy (RBAC role or user) whose decide scope covers it,
      2. an explicit entry in the portal's per-step email list,
      3. (R3) for the 'manager' step only: being the manager the request itself
         names in submitter.manager_email — a per-request grant.
    Super-admin and page-level admin grant nothing here. Separation of duties:
    nobody decides their own request, whatever they hold."""
    email = (session.get("email") or "").strip().lower()
    if req is not None and email:
        subm = req.get("submitter") or {}
        if isinstance(subm, str):
            try: subm = json.loads(subm)
            except Exception: subm = {}
        if email == (subm.get("email") or "").strip().lower():
            return False                     # separation of duties: never your own request
    return _grant_source(session, step_key, req) is not None

def _my_steps(session: dict) -> set:
    """Steps this session may SEE (view_steps). Feeds the list/visibility
    gates only — decisions go through is_authorized_for_step()."""
    return set(effective_access(session)["view_steps"])

def _manager_request_ids(email: str) -> set:
    """IDs of requests that name this email as the requester's manager (R3)."""
    email = (email or "").strip().lower()
    if not email:
        return set()
    try:
        rows = db().execute(
            "SELECT id FROM requests WHERE lower(json_extract(submitter,'$.manager_email'))=?",
            (email,)).fetchall()
        return {r["id"] for r in rows}
    except sqlite3.OperationalError:          # SQLite built without JSON1
        out = set()
        for r in db().execute("SELECT id, submitter FROM requests").fetchall():
            try:
                if (json.loads(r["submitter"]).get("manager_email") or "").strip().lower() == email:
                    out.add(r["id"])
            except Exception:
                pass
        return out

def is_any_approver(session: dict) -> bool:
    """True for super-admins and page-level admins (the Administrator tile;
    what they then see is still filtered by visible_request_ids), for anyone
    who may view at least one step, and for a manager named on at least one
    request. Gates the request list/detail so a merely-authenticated employee
    can't browse others' requests (PII)."""
    if is_superadmin(session) or session.get("role") == "admin":
        return True
    if _my_steps(session):
        return True
    return bool(effective_access(session)["manager_of_requests"])

def visible_request_ids(session: dict) -> set | None:
    if is_superadmin(session):
        return None  # Explicit emergency oversight; never an implicit decision grant.
    ids = set()
    access = {t: effective_access(session, request_type=t) for t in REQUEST_TYPES}
    for r in db().execute("SELECT id,type,workflow FROM requests"):
        acc = access.get(r["type"])
        if not acc:
            continue
        workflow = json.loads(r["workflow"])
        if r["id"] in acc["manager_of_requests"] or any(s in acc["view_steps"] for s in workflow):
            ids.add(r["id"])
    return ids

def directory_lookup_server(q: str) -> tuple:
    """Server-to-hub directory lookup, for the service's own use (no client
    rate limit, no HTTP response). Returns (status, record):
      ("found", {...})      an enabled account with exactly this address
      ("notfound", None)    the directory answered and has no such person
      ("error", reason)     the directory could not be consulted
    The requester's browser may be unable to reach the directory (off the
    company network); this process always can, so a typed address is checked
    here before anything is sent to it."""
    q = (q or "").strip().lower()
    if not EMAIL_RE.match(q) or len(q) > 254:
        return "notfound", None
    if LOOKUP_ALLOWED_DOMAINS and q.rsplit("@", 1)[1] not in LOOKUP_ALLOWED_DOMAINS:
        return "notfound", None
    if not LOOKUP_URL or not LOOKUP_KEY:
        return "error", "directory lookup not configured"
    headers = {"Accept": "application/json", LOOKUP_KEY_HEADER: LOOKUP_KEY}
    try:
        rq = urllib.request.Request(LOOKUP_URL + "?q=" + url_quote(q, safe=""), headers=headers)
        with urllib.request.urlopen(rq, timeout=8) as r:
            raw = json.loads(r.read().decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "notfound", None
        return "error", f"hub HTTP {e.code}"
    except Exception as e:
        return "error", str(e)[:120]
    me = _normalize_lookup(raw)
    if not me or (me.get("email") or "").lower() != q or raw.get("accountEnabled") is False:
        return "notfound", None
    me["id"] = str(raw.get("id") or raw.get("objectId") or "")   # the person's own directory id (normalize keeps only the manager's)
    emp = raw.get("employment")
    me["employment"] = emp if isinstance(emp, dict) else None    # hr_roster class; _normalize_lookup keeps only form fields
    return "found", me


# ── CLA-EMPLOYMENT: which intake path a requester gets ──────────────────────
# The signal is hr_roster.pay_class, delivered by the hub lookup relay, because
# Entra carries nothing usable: employeeType is null for every enabled user and
# the extension attributes are sync/routing markers.
#
# Deliberately NOT read from the relay's is_contingent flag: that is 1 for
# Temporary PT as well as Contingent Worker, so routing on it would put temps
# on the FTE path.
FTE_PAY_CLASSES = {"regular ft", "contingent worker"}   # compared lowercased
FTE_CACHE_TTL   = 3600                                  # HR reloads daily; pay class rarely moves
_FTE_CACHE      = {}
_FTE_CACHE_LOCK = threading.Lock()


def employment_class(email: str) -> dict:
    """What HR says this address is. Never raises. Returns:
        {"fte": bool, "pay_class": str, "matched": True|False|None, "source": str}

    `matched` is three-valued, mirroring the relay:
        True  - hr_roster had a row for this person
        False - the lookup ran; this person is not in the HR export
        None  - the lookup could not be made; we do not know

    Only matched-True with a listed pay class is an FTE. An unresolved
    identity, a person HR does not carry, and a genuinely part-time person all
    take the PTA path -- that is the decision on record. The three stay
    distinguishable here so an acknowledgement record can say WHICH applied
    rather than only "not FTE"."""
    email = (email or "").strip().lower()
    if not email:
        return {"fte": False, "pay_class": "", "matched": None, "source": "no-email"}

    now = time.time()
    with _FTE_CACHE_LOCK:
        hit = _FTE_CACHE.get(email)
        if hit and now - hit[0] < FTE_CACHE_TTL:
            return dict(hit[1])

    status, rec = directory_lookup_server(email)
    if status == "found":
        emp     = (rec or {}).get("employment") or {}
        matched = emp.get("matched")
        pay     = str(emp.get("payClass") or "")
        out = {"fte": matched is True and pay.strip().lower() in FTE_PAY_CLASSES,
               "pay_class": pay, "matched": matched, "source": "hr_roster"}
    elif status == "notfound":
        out = {"fte": False, "pay_class": "", "matched": False, "source": "directory-notfound"}
    else:
        out = {"fte": False, "pay_class": "", "matched": None, "source": "directory-error"}

    # An error is never cached: a hub blip must not pin somebody to the PTA
    # path for an hour. It re-asks on the next call and self-heals.
    if out["source"] != "directory-error":
        with _FTE_CACHE_LOCK:
            if len(_FTE_CACHE) > 4000:
                _FTE_CACHE.clear()
            _FTE_CACHE[email] = (now, dict(out))
    return out


def is_fte(email: str) -> bool:
    return employment_class(email)["fte"]

# ── ACK-ELIG: who may complete the acknowledgement (and so obtain Claude access) ──
def ack_eligibility_rows(email: str, form: str = "cla") -> list:
    e = (email or "").strip().lower()
    if not e: return []
    return [dict(r) for r in db().execute(
        "SELECT * FROM ack_eligibility WHERE form=? AND LOWER(email)=? AND removed_at='' ORDER BY id DESC", (form, e)).fetchall()]

def ack_eligibility_for(email: str, emp: dict = None, form: str = "cla") -> dict:
    """eligible = (HR says FTE or active Allow) and not active Block.
    Returns {eligible, source: hr_roster|admin_grant|none, blocked: bool}."""
    emp = emp if isinstance(emp, dict) else employment_class(email)
    rows = ack_eligibility_rows(email, form)
    if any(r["mode"] == "block" for r in rows):
        return {"eligible": False, "source": "none", "blocked": True}
    if emp.get("fte"):
        return {"eligible": True, "source": "hr_roster", "blocked": False}
    if any(r["mode"] == "allow" for r in rows):
        return {"eligible": True, "source": "admin_grant", "blocked": False}
    return {"eligible": False, "source": "none", "blocked": False}

def is_ack_eligible(email: str) -> bool:
    return ack_eligibility_for(email)["eligible"]

def ack_provision_days() -> str:
    v = (content_all().get("policy.cla.provision_days") or "").strip()
    return v if v.isdigit() else "2"

# ── SILENT CORPORATE IDENTITY ───────────────────────────────────────────────
# Authorization-code flow with PKCE and prompt=none. The round trip is short
# lived and single use; its state lives in this process only (one python3 on
# :8001), never in a cookie the browser could replay.

_ID_TX      = {}                       # state -> {verifier, nonce, ts, next}
_ID_TX_LOCK = threading.Lock()
ID_TX_TTL   = 300                      # an authorization round trip is seconds
ID_TX_MAX   = 5000
_GUID_RE    = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
IDENTITY_FIELDS = ("email", "name", "dept", "title", "employee_id",
                   "manager_name", "manager_email", "manager_id")

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def _b64url_json(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
                      .decode("utf-8", errors="replace"))

def _id_tx_new(next_url: str, visit: str = "", mode: str = "") -> tuple:
    """state, verifier, nonce for one authorization round trip."""
    state    = _b64url(secrets.token_bytes(24))
    verifier = _b64url(secrets.token_bytes(48))
    nonce    = _b64url(secrets.token_bytes(24))
    now      = time.time()
    with _ID_TX_LOCK:
        for k in [k for k, v in _ID_TX.items() if now - v["ts"] > ID_TX_TTL]:
            _ID_TX.pop(k, None)
        if len(_ID_TX) >= ID_TX_MAX:          # bounded; oldest go first
            for k in sorted(_ID_TX, key=lambda k: _ID_TX[k]["ts"])[:ID_TX_MAX // 5]:
                _ID_TX.pop(k, None)
        _ID_TX[state] = {"verifier": verifier, "nonce": nonce, "ts": now, "next": next_url,
                         "visit": visit, "mode": mode}
    return state, verifier, nonce

def _id_tx_pop(state: str):
    """Single use: the state is removed whether or not it is still valid."""
    with _ID_TX_LOCK:
        tx = _ID_TX.pop(state or "", None)
    if not tx or time.time() - tx["ts"] > ID_TX_TTL:
        return None
    return tx

def _id_hash(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()

def _cookie(handler, name: str) -> str:
    for part in (handler.headers.get("Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v.strip()
    return ""

def identity_put(rec: dict, source: str = "entra") -> str:
    """Store a verified identity; return the opaque cookie value (never stored)."""
    token = _b64url(secrets.token_bytes(32))
    exp   = (datetime.now(timezone.utc) + timedelta(minutes=IDENTITY_TTL_MIN)).isoformat()
    vals  = [str(rec.get(k) or "")[:200] for k in IDENTITY_FIELDS]
    with write_lock:
        db().execute(
            "INSERT OR REPLACE INTO identity_sessions"
            " (token_hash,email,name,dept,title,employee_id,manager_name,manager_email,"
            "  manager_id,source,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [_id_hash(token)] + vals + [source, now_iso(), exp])
        db().execute("DELETE FROM identity_sessions WHERE expires_at < ?", (now_iso(),))
        db().commit()
    return token

def verified_identity(handler):
    """The corporate identity this browser proved, or None. Cheap enough for
    every public endpoint to call."""
    tok = _cookie(handler, IDENTITY_COOKIE)
    if not tok or not re.match(r"^[A-Za-z0-9_\-]{16,128}$", tok):
        return None
    try:
        row = db().execute("SELECT * FROM identity_sessions WHERE token_hash=? AND expires_at > ?",
                           (_id_hash(tok), now_iso())).fetchone()
    except Exception:
        return None
    return dict(row) if row else None

def identity_discard(handler) -> bool:
    """'This is not me.' The row is kept and marked, so a request filed after
    this can say that a verified identity was set aside rather than silently
    look like an ordinary typed one."""
    tok = _cookie(handler, IDENTITY_COOKIE)
    if not tok or not re.match(r"^[A-Za-z0-9_\-]{16,128}$", tok):
        return False
    with write_lock:
        cur = db().execute("UPDATE identity_sessions SET source='discarded' WHERE token_hash=?",
                           (_id_hash(tok),))
        db().commit()
    return cur.rowcount > 0

def _safe_next(raw: str) -> str:
    """A same-origin path, or "/".

    Control characters are removed BEFORE the check, not after: browsers strip
    TAB, LF and CR from a URL, so "/<TAB>/evil.com" becomes "//evil.com" -- a
    protocol-relative URL to somebody else's host -- if you validate first."""
    s = "".join(c for c in (raw or "") if c not in "\t\n\r" and ord(c) >= 0x20)
    if not s.startswith("/") or s.startswith("//") or "\\" in s:
        return "/"
    return s[:512]

def _redirect(handler, url: str, cookies: list = None):
    handler.send_response(302)
    handler.send_header("Location", url)
    handler.send_header("Content-Length", "0")
    handler.send_header("Cache-Control", "no-store, private")
    for c in (cookies or []):
        handler.send_header("Set-Cookie", c)
    handler.end_headers()

def _entra_token_exchange(code: str, verifier: str) -> tuple:
    """Redeem the authorization code. Returns (status, payload-or-reason).
    The reason is Microsoft's error CODE only -- error_description can quote the
    request back, and this value is logged."""
    data = urlencode({
        "client_id":     ENTRA_CLIENT,
        "client_secret": ENTRA_SECRET,
        "code":          code,
        "redirect_uri":  ENTRA_REDIRECT,
        "grant_type":    "authorization_code",
        "code_verifier": verifier,
        "scope":         "openid profile email",
    }).encode("ascii")
    url = f"{ENTRA_AUTHORITY}/{url_quote(ENTRA_TENANT, safe='')}/oauth2/v2.0/token"
    rq  = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept":       "application/json"})
    try:
        with urllib.request.urlopen(rq, timeout=10) as r:
            return "ok", json.loads(r.read().decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode("utf-8", errors="replace") or "{}")
        except Exception:
            detail = {}
        return "error", str(detail.get("error") or f"HTTP {e.code}")[:80]
    except Exception as e:
        return "error", str(e)[:120]

def _entra_claims(id_token: str, nonce: str) -> tuple:
    """Validate an ID token and return its claims.

    The signature is not re-checked. OIDC Core 3.1.3.7 permits that when the
    token came straight from the token endpoint over a TLS channel whose server
    was authenticated and the client authenticated itself -- which is the only
    way a token reaches this function; nothing browser-supplied gets here. The
    claims that bind it to THIS request are checked: audience, issuer, tenant,
    nonce and expiry."""
    parts = (id_token or "").split(".")
    if len(parts) != 3:
        return "error", "malformed id_token"
    try:
        c = _b64url_json(parts[1])
    except Exception:
        return "error", "unreadable id_token"
    if not isinstance(c, dict):
        return "error", "unreadable id_token"
    if c.get("aud") != ENTRA_CLIENT:
        return "error", "audience mismatch"
    tid = str(c.get("tid") or "")
    if not tid or str(c.get("iss") or "") != f"{ENTRA_AUTHORITY}/{tid}/v2.0":
        return "error", "issuer mismatch"
    if _GUID_RE.match(ENTRA_TENANT) and tid.lower() != ENTRA_TENANT.lower():
        return "error", "tenant mismatch"
    if not nonce or c.get("nonce") != nonce:
        return "error", "nonce mismatch"
    try:
        if int(c.get("exp") or 0) < time.time() - 60:
            return "error", "expired id_token"
    except Exception:
        return "error", "bad exp"
    return "ok", c

def _clean_submitter(sub: dict) -> dict:
    """Normalise the requester block. Emails lower-cased and validated; the
    manager email/id (R2) are kept only when syntactically valid so downstream
    routing (R3) never acts on a typo."""
    out = {}
    for k in ("name", "email", "dept", "title", "employee_id", "manager_name", "manager_email", "manager_id"):
        v = sub.get(k, "")
        out[k] = " ".join(str(v if v is not None else "").split())[:200]
    out["email"] = out["email"].lower()
    out["manager_email"] = out["manager_email"].lower()
    if out["manager_email"]:
        m = out["manager_email"]
        if (not ADDR_RE.match(m)
                or m == out["email"]                                     # nobody is their own manager
                or (LOOKUP_ALLOWED_DOMAINS and m.rsplit("@", 1)[1] not in LOOKUP_ALLOWED_DOMAINS)):
            out["manager_email"] = ""
    if not re.match(r"^[A-Za-z0-9._@\-]{0,128}$", out["manager_id"]):
        out["manager_id"] = ""
    # How the manager was captured: from the directory lookup, or typed by the
    # requester because the directory could not be reached. Anything else -> "".
    ms = str(sub.get("manager_source") or "").strip().lower()
    out["manager_source"] = ms if ms in ("directory", "manual") else ""
    # keep any extra keys the form sent, minus anything that looks like markup
    for k, v in sub.items():
        if k not in out and isinstance(v, (str, int, float, bool)) and re.match(r"^[A-Za-z0-9_\-]{1,64}$", str(k)):
            out[k] = v
    return out

def _first(d: dict, *keys):
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""

def _normalize_lookup(raw) -> dict | None:
    """Reduce whatever the hub returns to the five fields the form uses plus the
    manager's email/id (R2). Accepts Graph-style keys (displayName, mail,
    jobTitle, manager{…}) and the hub's flattened variants."""
    if isinstance(raw, dict) and isinstance(raw.get("data"), dict):
        raw = raw["data"]
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not isinstance(raw, dict):
        return None
    mgr = raw.get("manager")
    if isinstance(mgr, dict):
        mgr_name  = _first(mgr, "displayName", "display_name", "name")
        mgr_email = _first(mgr, "mail", "email", "userPrincipalName", "upn").lower()
        mgr_id    = _first(mgr, "id", "objectId")
    else:
        mgr_name  = str(mgr or "").strip()
        mgr_email = _first(raw, "managerEmail", "manager_email", "managerMail", "manager_mail", "managerUpn").lower()  # hub: managerEmail (falls back to UPN)
        mgr_id    = _first(raw, "managerId", "manager_id", "managerObjectId")
    out = {
        "name":       _first(raw, "name", "displayName", "display_name"),
        "email":      _first(raw, "email", "mail", "userPrincipalName", "upn").lower(),   # hub relay: email/upn
        "department": _first(raw, "department", "dept"),
        "title":      _first(raw, "title", "jobTitle", "job_title"),
        "manager":    mgr_name,
        "manager_email": mgr_email if ADDR_RE.match(mgr_email) else "",
        "manager_id":    mgr_id if re.match(r"^[A-Za-z0-9._@\-]{1,128}$", mgr_id) else "",
    }
    return out if out["email"] else None

def _csv_safe(v):
    """Neutralise spreadsheet formula injection in exported cells."""
    s = "" if v is None else str(v)
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

# ── RATE LIMITING (public submissions) ──────────────────────────────────────
_rl_lock = threading.Lock()
_rl_hits = {}

def _rate_limited(ip: str, bucket: str = "submit",
                  window: int = SUBMIT_WINDOW, limit: int = SUBMIT_MAX) -> bool:
    now = time.time()
    key = f"{bucket}:{ip}"
    with _rl_lock:
        hits = [t for t in _rl_hits.get(key, []) if now - t < window]
        if len(hits) >= limit:
            _rl_hits[key] = hits
            return True
        hits.append(now)
        _rl_hits[key] = hits
        return False


# ── JOURNEY LOG (2026-10-08) ─────────────────────────────────────────────────
# A record of what a requester's browser showed and what this server decided
# for them, kept JOURNEY_KEEP_DAYS days, so "I never got the two cards" can be
# answered from a record rather than reconstructed afterwards. Read by the
# CorpIT Health Center (super-admins only) through /internal/journey/*.
#
# Never recorded: anything typed into a form, keystrokes, form contents. The
# page may send only the event names in JOURNEY_EVENTS, each with only the
# keys listed for it; everything else is dropped here. Who the requester is
# comes from the sign-in cookie on this side, never from the page.
#
# Its own SQLite file beside portal.db, written by one background thread in
# batches: a busy page never contends with request writes, and the 90-day
# purge never touches a request record. A full queue or a full file drops
# events (counted) rather than slowing anything down.
JOURNEY_DB_PATH     = DB_PATH.parent / "journey.db"
JOURNEY_KEEP_DAYS   = 90                       # fixed retention (decided 2026-10-08)
JOURNEY_MAX_BYTES   = 1024 * 1024 * 1024       # stop writing past 1 GiB of live pages
JOURNEY_QUEUE_MAX   = 20000
JOURNEY_POST_EVENTS = 40                       # events accepted per page POST
JOURNEY_POST_BYTES  = 32 * 1024
JOURNEY_VISIT_MAX   = 300                      # page POSTs per visit per 10 minutes
JOURNEY_VISIT_RE    = re.compile(r"^[0-9a-f]{16}$")

# Event name -> the keys it may carry and their type: "b" bool, "i" int,
# "f" float, ("s", n) string of at most n characters.
JOURNEY_EVENTS = {
    "api_result": {"path": ("s", 100), "method": ("s", 8), "status": "i", "ms": "i", "request_id": ("s", 36)},
    "load":        {"w": "i", "h": "i", "sw": "i", "sh": "i", "dpr": "f", "zoom": "f",
                    "nav": ("s", 16), "cached": "b", "size": "i", "lm": ("s", 32),
                    "rev": ("s", 24), "lsc": "b", "cla": "b", "intake": ("s", 8),
                    "path": ("s", 64)},
    "identity":    {"verified": "b", "fte": "b", "enabled": "b", "leaving": "b", "failed": "b"},
    "whoami_failed": {},
    "view":        {"page": ("s", 24), "w": "i", "h": "i", "c2": ("s", 10), "c2vis": "b",
                    "c2top": "i", "stacked": "b", "cards": "i"},
    "card2_seen":  {"ms": "i", "c2": ("s", 10), "w": "i"},
    "click":       {"fn": ("s", 24), "arg": ("s", 8), "page": ("s", 24)},
    "form_start":  {"type": ("s", 8), "via": ("s", 16)},
    "step":        {"type": ("s", 8), "n": "i"},
    "cla_open":    {"via": ("s", 16)},
    "lookup":      {"found": "b", "offline": "b"},
    "dir_offline": {},
    "submit_ok":   {"type": ("s", 8), "id": ("s", 24)},
    "submit_fail": {"type": ("s", 8), "msg": ("s", 160)},
    "ack_ok":      {"already": "b"},
    "ack_fail":    {"msg": ("s", 160)},
    "resize":      {"w": "i", "h": "i", "b": ("s", 8)},
    "jserr":       {"msg": ("s", 200), "src": ("s", 80), "line": "i", "col": "i"},
    "leave":       {"page": ("s", 24), "ms": "i"},
}
# The onclick handlers a "click" may name. Anything else is stored as "other".
JOURNEY_CLICK_FNS = {
    "startRequest", "startForm", "renderAIAChoose", "renderCla", "claBackHome", "goHome",
    "formNext", "formPrev", "formSubmit", "claSubmit", "apNotMe", "autoFillFromEntra",
    "retryDirectory", "policyReviewed", "setSigMode", "clearSig", "showTrackModal",
    "trackFromHero", "trackRequestById", "doTrack", "toggleTheme",
}
# What the page attaches to a submission: its own account of how it got there.
JOURNEY_STAMP = {"rev": ("s", 24), "via": ("s", 16), "c2shown": "b", "c2en": "b",
                 "c2seen": "b", "w": "i", "fte": "b", "idv": "b", "lookup": "b"}

JOURNEY_DDL = """
CREATE TABLE IF NOT EXISTS journey_events (
    id      INTEGER PRIMARY KEY,
    ts      TEXT    NOT NULL,              -- UTC, ms: 2026-10-08T18:35:34.123Z
    visit   TEXT    NOT NULL DEFAULT '',   -- one browser tab, kept across sign-in
    seq     INTEGER NOT NULL DEFAULT 0,    -- page order within the visit
    origin  TEXT    NOT NULL,              -- page | server
    event   TEXT    NOT NULL,
    email   TEXT    NOT NULL DEFAULT '',   -- from the sign-in cookie, never the page
    idsrc   TEXT    NOT NULL DEFAULT '',   -- entra | discarded | typed | ''
    data    TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_journey_ts    ON journey_events(ts);
CREATE INDEX IF NOT EXISTS ix_journey_email ON journey_events(email, ts);
CREATE INDEX IF NOT EXISTS ix_journey_visit ON journey_events(visit, ts);
"""

_jq         = queue.Queue(maxsize=JOURNEY_QUEUE_MAX)
_jstat      = {"written": 0, "dropped": 0, "rejected": 0, "purged": 0,
               "last_purge": "", "bytes": 0, "full": False, "error": ""}
_jstat_lock = threading.Lock()
_jrl        = {}
_jrl_lock   = threading.Lock()
_J_CTRL     = re.compile(r"[\x00-\x1f\x7f]")
_J_ADDR     = re.compile(r"[^\s@<>\"'(),;:]+@[^\s@<>\"'(),;:]+")   # an address in an error text

def _j_ts(ms=None) -> str:
    ms = time.time() * 1000 if ms is None else ms
    return (datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{int(ms % 1000):03d}Z")

def _j_count(key: str, n: int = 1):
    with _jstat_lock:
        _jstat[key] = _jstat.get(key, 0) + n

def _j_val(spec, v):
    """One value coerced to its declared type, or None to drop it."""
    if spec == "b":
        return v if isinstance(v, bool) else None
    if spec in ("i", "f"):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v:
            return None
        v = max(-1e9, min(1e9, v))
        return int(v) if spec == "i" else round(float(v), 3)
    if isinstance(spec, tuple) and isinstance(v, str):
        return _J_ADDR.sub("<address>", _J_CTRL.sub(" ", v))[:spec[1]]
    return None

def _j_clean(spec: dict, d) -> dict:
    out = {}
    if isinstance(d, dict):
        for k, s in spec.items():
            if k in d:
                val = _j_val(s, d[k])
                if val is not None:
                    out[k] = val
    return out

def journey_put(origin, event, visit="", email="", idsrc="", seq=0, data=None, ts=None):
    """Queue one event. Never raises and never blocks the caller."""
    try:
        if _jstat["full"]:
            return _j_count("dropped")
        _jq.put_nowait((ts or _j_ts(), visit if JOURNEY_VISIT_RE.match(visit or "") else "",
                        int(seq or 0), origin, event, (email or "").strip().lower()[:200],
                        (idsrc or "")[:20],
                        json.dumps(data or {}, separators=(",", ":"), default=str)[:4000]))
    except Exception:
        _j_count("dropped")

def journey_server(event, visit="", email="", idsrc="", ts=None, **data):
    journey_put("server", event, visit, email, idsrc, 0, data, ts)

def journey_stamp(raw) -> tuple:
    """(visit, data) from the stamp a page sends with a submission. A page
    older than this build sends none, and the record says so."""
    if not isinstance(raw, dict):
        return "", {"stamp": False}
    visit = str(raw.get("v") or "")
    return (visit if JOURNEY_VISIT_RE.match(visit) else ""), dict(_j_clean(JOURNEY_STAMP, raw), stamp=True)

def _journey_rate_ok(visit: str) -> bool:
    now = time.time()
    with _jrl_lock:
        if len(_jrl) > 50000:                  # bounded: a flood of made-up visits cannot grow this
            _jrl.clear()
        start, n = _jrl.get(visit, (now, 0))
        if now - start > 600:
            start, n = now, 0
        _jrl[visit] = (start, n + 1)
        return n + 1 <= JOURNEY_VISIT_MAX

def _journey_conn():
    conn = sqlite3.connect(str(JOURNEY_DB_PATH), timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    if conn.execute("PRAGMA synchronous").fetchone()[0] != 2:
        conn.close()
        raise RuntimeError("SQLite writer requires synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn

def _journey_read():
    """A read-only connection, or None before the first event was written."""
    if not JOURNEY_DB_PATH.exists():
        return None
    conn = sqlite3.connect(f"file:{JOURNEY_DB_PATH}?mode=ro", uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn

def _journey_purge(conn):
    cutoff = _j_ts((time.time() - JOURNEY_KEEP_DAYS * 86400) * 1000)
    total = 0
    while True:                                # small batches: the writer is not held for long
        with conn:
            n = conn.execute("DELETE FROM journey_events WHERE id IN "
                             "(SELECT id FROM journey_events WHERE ts < ? LIMIT 5000)", (cutoff,)).rowcount
        total += n
        if n < 5000:
            break
    pc, fl, ps = (conn.execute(f"PRAGMA {p}").fetchone()[0]
                  for p in ("page_count", "freelist_count", "page_size"))
    used = (pc - fl) * ps
    with _jstat_lock:
        _jstat["purged"] += total
        _jstat["last_purge"] = now_iso()
        _jstat["bytes"] = used
        _jstat["full"] = used >= JOURNEY_MAX_BYTES
    if total:
        print(f"[JOURNEY] purged {total} event(s) older than {JOURNEY_KEEP_DAYS} days", file=sys.stderr)

def _journey_writer():
    conn, last_purge = None, 0.0
    while True:
        batch = []
        try:
            if conn is None:
                conn = _journey_conn()
                conn.executescript(JOURNEY_DDL)
                conn.commit()
                try:
                    os.chmod(JOURNEY_DB_PATH, 0o600)
                except OSError:
                    pass
                with _jstat_lock:
                    _jstat["error"] = ""
            try:
                batch.append(_jq.get(timeout=2))
                while len(batch) < 2000:
                    batch.append(_jq.get_nowait())
            except queue.Empty:
                pass
            if batch:
                with conn:
                    conn.executemany("INSERT INTO journey_events (ts,visit,seq,origin,event,email,idsrc,data)"
                                     " VALUES (?,?,?,?,?,?,?,?)", batch)
                _j_count("written", len(batch))
            if time.time() - last_purge > 600:     # purge + size check every 10 minutes
                last_purge = time.time()
                _journey_purge(conn)
        except Exception as e:
            if batch:
                _j_count("dropped", len(batch))
            with _jstat_lock:
                _jstat["error"] = f"{type(e).__name__}: {e}"[:200]
            print(f"[JOURNEY] writer: {e}", file=sys.stderr)
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
            conn = None
            time.sleep(5)

def journey_start():
    threading.Thread(target=_journey_writer, name="journey-writer", daemon=True).start()

def _j_rows_to_events(rows) -> list:
    out = []
    for r in rows:
        try:
            d = json.loads(r["data"] or "{}")
        except Exception:
            d = {}
        out.append({"ts": r["ts"], "visit": r["visit"], "seq": r["seq"], "origin": r["origin"],
                    "event": r["event"], "email": r["email"], "idsrc": r["idsrc"], "data": d})
    return out

def journey_flag(submit: dict, visit_events: list):
    """Why an AI Use Case Intake filed by someone eligible for card 2 may have
    been the wrong form, or None. Uses the page's own stamp and, where the
    page sent events, what this visit recorded; either one is enough to clear
    a reason. A page that sent neither is reported as unknown, not as fine."""
    # Later views cannot retroactively clear an earlier wrong-form submission.
    if submit.get("ts"):
        visit_events = [e for e in visit_events if e.get("ts") and e["ts"] <= submit["ts"]]
    d = submit.get("data") or {}
    if d.get("type") != "aia" or d.get("fte_srv") is not True:
        return None
    views   = [e for e in visit_events if e["event"] == "view" and e["data"].get("page") == "aiachoose"]
    shown   = bool(d.get("c2shown")) or bool(views)
    enabled = bool(d.get("c2en")) or any(e["data"].get("c2") == "enabled" for e in views)
    seen    = bool(d.get("c2seen")) or any(e["event"] == "card2_seen" and e["data"].get("c2") != "disabled"
                                           for e in visit_events)
    if not d.get("stamp") and not any(e["origin"] == "page" for e in visit_events):
        return "no page record (page older than this logging, or its logging failed)"
    if not shown:
        return "chooser never shown"
    if not enabled:
        return "card 2 shown disabled"
    if not seen:
        return "card 2 never on screen"
    return None


class PortalHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # suppress default per-request logging

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization,Cookie")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def send_response(self, code, message=None):
        self._activity_status = code
        super().send_response(code, message)
        if getattr(self, "_activity_id", None):
            self.send_header("X-Request-ID", self._activity_id)

    def _dispatch(self, method: str):
        self._activity_id = str(uuid.uuid4())
        self._activity_status = 499
        started = time.monotonic()
        path = urlparse(self.path).path
        email, source = "", ""
        try:
            try:
                if path.startswith("/api/portal/") and path != "/api/portal/journey":
                    ident = verified_identity(self)
                    if ident and ident.get("source") == "entra":
                        email, source = ident.get("email", ""), "entra"
                    else:
                        actor = session_from_request(self)
                        if actor:
                            email, source = actor.get("email", ""), "gate"
            except Exception:
                pass  # Diagnostics must not change request handling.
            return self._dispatch_request(method)
        finally:
            if path.startswith("/api/portal/") and path != "/api/portal/journey":
                journey_server("http_request", "", email, source,
                               request_id=self._activity_id, method=method,
                               path=route_name(path), status=self._activity_status,
                               duration_ms=round((time.monotonic()-started)*1000))

    def _dispatch_request(self, method: str):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        try:
            if path == "/internal/approval-access" and method == "POST":
                return self._internal_access()
            if path == "/internal/activity/person" and method == "POST":
                return self._internal_activity_person()
            if path == "/internal/journey/person" and method == "POST":
                return self._internal_journey_person()
            if path == "/internal/journey/summary" and method == "POST":
                return self._internal_journey_summary()
            # ── Public endpoints ─────────────────────────────────────────
            if path in ("/api/portal/setup", "/api/portal/auth/login", "/api/portal/auth/sso", "/api/portal/approvers") or path == "/api/portal/admins" or path.startswith("/api/portal/admins/"):
                return err(self, 410, "This legacy endpoint is retired. Use corporate sign-in and Administrator > Approval Access.")
            if method == "POST" and path == "/api/portal/auth/logout":
                return self._logout()
            if method == "GET"  and path == "/api/portal/auth/me":
                return self._me()
            if method == "POST" and path == "/api/portal/requests":
                return self._submit_request()
            if method == "GET"  and path == "/api/portal/status":
                # ?id=AIA-2026-00001 — public tracker: minimal, PII-free shape
                return self._public_status(qs.get("id",[""])[0])
            if method == "GET"  and path == "/api/portal/lookup":
                return self._directory_lookup(qs.get("q",[""])[0])   # R1 proxy
            if method == "GET"  and path == "/api/portal/content":
                return self._get_content()   # public: front-facing copy only

            # Silent corporate identity. Public by necessity — the requester has
            # no session, and establishing one is the entire point.
            if method == "GET"  and path == "/api/portal/identity/whoami":
                return self._identity_whoami(qs)
            if method == "GET"  and path == "/api/portal/identity/start":
                return self._identity_start(qs)
            if method == "GET"  and path == "/api/portal/identity/callback":
                return self._identity_callback(qs)
            if method == "POST" and path == "/api/portal/identity/forget":
                return self._identity_forget(qs)
            # JOURNEY: page events (public, like the identity routes; see _journey_post)
            if method == "POST" and path == "/api/portal/journey":
                return self._journey_post()

            # CLA-ACK-ENDPOINTS — public by necessity, like the identity routes
            # above: the person acknowledging a policy is a requester with no
            # portal session. They are not unauthenticated, though: both refuse
            # without a verified corporate identity, which is the gate this
            # build was told to use rather than /_gate.
            if method == "GET"  and path == "/api/portal/acknowledgments/me":
                return self._ack_me(qs)
            if method == "POST" and path == "/api/portal/acknowledgments":
                return self._ack_submit()

            # AI-GOV SYNC: service-token feed for the CorpIT AI Governance worker.
            # No portal session — the caller is a server, not a person. Read-only,
            # AIA type only, every call audited. Token managed under /sync/token.
            if method == "GET" and path == "/api/portal/sync/aia":
                return self._sync_aia(qs)
            if method == "POST" and path == "/api/portal/sync/governance-summary":   # AI-GOV SUMMARY (push)
                return self._sync_summary_put()

            if method in ("POST", "PATCH", "DELETE") and self.headers.get("Origin") and self.headers.get("Origin") != CORS_ORIGIN:
                return err(self, 403, "Use this portal to make access changes")
            # ── Auth-gated endpoints ──────────────────────────────────────
            session = session_from_request(self)
            if not session:
                return err(self, 401, "Authentication required")

            if method == "GET" and path == "/api/portal/admin-guide":
                return self._access_guide(session)

            # ACK-ADMIN: administrator reporting/correction for policy acknowledgments (2026-09-23)
            if method == "GET"  and path == "/api/portal/acknowledgments":
                return self._ack_admin_list(session, qs)
            if method == "GET"  and re.match(r"^/api/portal/acknowledgments/\d+$", path):
                return self._ack_admin_get(session, int(path.rsplit("/", 1)[1]))
            if method == "GET"  and re.match(r"^/api/portal/acknowledgments/\d+/record$", path):
                return self._ack_record(session, int(path.split("/")[4]), qs)
            if method == "GET"  and path == "/api/portal/acknowledgments/export.zip":
                return self._ack_export_zip(session, qs)
            # ACK-ELIG (admin)
            if method == "GET"  and path == "/api/portal/ack-eligibility":
                return self._elig_list(session, qs)
            if method == "POST" and path == "/api/portal/ack-eligibility":
                return self._elig_add(session)
            if method == "DELETE" and re.match(r"^/api/portal/ack-eligibility/\d+$", path):
                return self._elig_remove(session, int(path.rsplit("/", 1)[1]))
            if method == "POST" and re.match(r"^/api/portal/ack-eligibility/\d+/resend$", path):
                return self._elig_resend(session, int(path.split("/")[4]))
            # AI INVENTORY (InfoSec / Legal / admin)
            if method == "GET"  and path == "/api/portal/inventory":
                return self._inv_list(session, qs)
            if method == "POST" and path == "/api/portal/inventory":
                return self._inv_write(session, None)
            if method == "GET"  and path == "/api/portal/inventory/coverage":
                return self._inv_coverage(session)
            if method == "GET"  and path == "/api/portal/inventory/export":
                return self._inv_export(session, qs)
            if method == "POST" and path == "/api/portal/inventory/import":
                return self._inv_import(session)
            if method == "GET"  and re.match(r"^/api/portal/inventory/\d+$", path):
                return self._inv_get(session, int(path.rsplit("/", 1)[1]))
            if method == "PATCH" and re.match(r"^/api/portal/inventory/\d+$", path):
                return self._inv_write(session, int(path.rsplit("/", 1)[1]))
            if method == "POST" and re.match(r"^/api/portal/inventory/\d+/archive$", path):
                return self._inv_archive(session, int(path.split("/")[4]), False)
            if method == "POST" and re.match(r"^/api/portal/inventory/\d+/unarchive$", path):
                return self._inv_archive(session, int(path.split("/")[4]), True)
            # APPROVER-REMINDERS (admin)
            if path == "/api/portal/reminders/settings" and method in ("GET", "PUT"):
                return self._reminders_settings(session, method)
            if method == "POST" and path == "/api/portal/reminders/run":
                return self._reminders_run(session, qs)
            # AI-GOV SYNC token (admin)
            if path == "/api/portal/sync/token" and method in ("GET", "POST", "DELETE"):
                return self._sync_token(session, method)
            if method == "GET" and path == "/api/portal/sync/governance-summary":
                return self._sync_summary_get(session)
            if method == "POST" and path == "/api/portal/sync/governance-refresh":   # AI-GOV REFRESH
                return self._sync_refresh(session)
            if path == "/api/portal/sync/refresh-url" and method in ("GET", "PUT"):
                return self._sync_refresh_url(session, method)
            # ARCHIVE
            m_reopen = re.match(r"^/api/portal/requests/([A-Za-z0-9-]+)/reopen$", path)   # REOPEN
            if m_reopen and method in ("GET", "POST"): return self._reopen(m_reopen.group(1), session)
            if method == "POST" and path == "/api/portal/archive":
                return self._archive_items(session)
            if method == "POST" and path == "/api/portal/archive/sweep":
                return self._archive_sweep(session)
            if method == "GET"  and path == "/api/portal/archive/recent":
                return self._archive_recent(session)
            # ACK-REACK (admin)
            if method == "POST" and re.match(r"^/api/portal/acknowledgments/\d+/request-reack$", path):
                return self._ack_request_reack(session, int(path.split("/")[4]))
            if method == "POST" and path == "/api/portal/acknowledgments/notify-outdated":
                return self._ack_notify_outdated(session)
            if method == "PATCH" and re.match(r"^/api/portal/acknowledgments/\d+/identity$", path):
                return self._ack_admin_identity(session, int(path.split("/")[4]))
            if method == "GET"  and path == "/api/portal/policy-versions":
                return self._policy_versions_list(session, qs)
            if method == "POST" and re.match(r"^/api/portal/policy-versions/\d+/retire$", path):
                return self._policy_version_retire(session, int(path.split("/")[4]))

            if method == "GET"  and path == "/api/portal/requests":
                return self._list_requests(session, qs)
            if method == "GET"  and re.match(r"^/api/portal/requests/[^/]+/record$", path):
                return self._request_record(path.split("/")[4], session, qs)
            if method == "GET"  and re.match(r"^/api/portal/requests/[^/]+$", path):
                req_id = path[len("/api/portal/requests/"):]
                return self._get_request(req_id, session)
            if method == "PATCH" and re.match(r"^/api/portal/requests/[^/]+$", path):
                req_id = path[len("/api/portal/requests/"):]
                return self._edit_request(req_id, session)          # R8
            if method == "POST" and re.match(r"^/api/portal/requests/[^/]+/decide$", path):
                req_id = path.split("/")[4]
                return self._decide(req_id, session)
            if method == "GET"  and path == "/api/portal/roles":
                return self._roles(session)                            # O3: one source of truth
            if method == "GET"  and path == "/api/portal/reports/summary":
                return self._reports_summary(session)
            if method == "GET"  and path == "/api/portal/reports/audit":
                return self._reports_audit(session, qs)
            if method == "GET"  and path == "/api/portal/export":
                return self._export_csv(session, qs)
            if method == "POST" and path == "/api/portal/content":
                return self._save_content(session)
            if method == "POST" and path == "/api/portal/workflows":
                return self._save_workflows(session)
            if re.match(r"^/api/portal/policy-doc/[a-z]{3}$", path) and method in ("POST", "DELETE"):
                form = path.rsplit("/", 1)[1]
                return self._upload_policy_doc(form, session) if method == "POST" else self._delete_policy_doc(form, session)
            if method == "GET"  and path == "/api/portal/settings":
                return self._get_settings(session)
            if method == "POST" and path == "/api/portal/settings":
                return self._save_settings(session)
            if method == "POST" and path == "/api/portal/settings/test-email":
                return self._test_email(session)
            # Approval Access policies — super-admin only (checked in each handler)
            if method == "GET"  and path == "/api/portal/approval-access":
                return self._list_policies(session)
            if method == "POST" and path == "/api/portal/approval-access":
                return self._create_policy(session)
            if method == "PATCH" and re.match(r"^/api/portal/approval-access/\d+$", path):
                return self._update_policy(int(path.split("/")[-1]), session)
            if method == "DELETE" and re.match(r"^/api/portal/approval-access/\d+$", path):
                return self._delete_policy(int(path.split("/")[-1]), session)


            err(self, 404, "Endpoint not found")

        except Exception:
            tb = traceback.format_exc()
            print(f"[ERROR] {method} {path}\n{tb}", file=sys.stderr)
            err(self, 500, "Internal server error")

    # ── JOURNEY (2026-10-08) ─────────────────────────────────────────────
    def _j_reply(self, status: int):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store, private")
        self.end_headers()

    def _j_visit(self, qs) -> str:
        v = ((qs or {}).get("v", [""])[0] or "").strip()
        return v if JOURNEY_VISIT_RE.match(v) else ""

    def _journey_post(self):
        """Page events. The page never reads the answer; nothing here may slow
        or break it, so every refusal is a bare status."""
        origin = self.headers.get("Origin")
        if origin and origin != CORS_ORIGIN:
            return self._j_reply(403)
        sfs = self.headers.get("Sec-Fetch-Site")
        if sfs and sfs != "same-origin":
            return self._j_reply(403)
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > JOURNEY_POST_BYTES:
            _j_count("rejected")
            return self._j_reply(413 if length > 0 else 400)
        body  = parse_body(self)
        visit = str(body.get("v") or "")
        events = body.get("events")
        if not JOURNEY_VISIT_RE.match(visit) or not isinstance(events, list):
            _j_count("rejected")
            return self._j_reply(400)
        if not _journey_rate_ok(visit):
            _j_count("rejected")
            return self._j_reply(429)

        rec = verified_identity(self)
        email, idsrc = "", ""
        if rec and rec.get("source") in ("entra", "discarded"):
            email, idsrc = rec.get("email", ""), rec["source"]
        # Page times are page-clock; each is placed on this server's clock by
        # its age when the batch was sent, so page and server events interleave.
        now_ms  = time.time() * 1000
        sent_ms = body.get("n")
        for ev in events[:JOURNEY_POST_EVENTS]:
            if not isinstance(ev, dict) or not isinstance(ev.get("e"), str):
                _j_count("rejected"); continue
            spec = JOURNEY_EVENTS.get(ev["e"])
            if spec is None:
                _j_count("rejected"); continue
            data = _j_clean(spec, ev.get("d"))
            if ev["e"] == "click" and data.get("fn") not in JOURNEY_CLICK_FNS:
                data = {"fn": "other", **({"page": data["page"]} if "page" in data else {})}
            if ev["e"] == "load":
                data["ua"] = (self.headers.get("User-Agent") or "")[:200]
            ts_ms, t = now_ms, ev.get("t")
            if (isinstance(t, (int, float)) and isinstance(sent_ms, (int, float))
                    and not isinstance(t, bool) and not isinstance(sent_ms, bool)
                    and 0 <= sent_ms - t <= 6 * 3600 * 1000):
                ts_ms = now_ms - (sent_ms - t)
            seq = ev.get("s")
            seq = max(0, min(seq, 10 ** 6)) if isinstance(seq, int) and not isinstance(seq, bool) else 0
            journey_put("page", ev["e"], visit, email, idsrc, seq, data, _j_ts(ts_ms))
        return self._j_reply(204)

    def _internal_ok(self) -> bool:
        return (self.client_address[0] in ("127.0.0.1", "::1") and bool(LOOKUP_KEY)
                and hmac.compare_digest(self.headers.get(LOOKUP_KEY_HEADER, ""), LOOKUP_KEY))

    def _internal_activity_person(self):
        if not self._internal_ok():
            return err(self, 403, "Forbidden")
        body = parse_body(self)
        email = str(body.get("email") or "").strip().lower()
        if not EMAIL_RE.match(email):
            return err(self, 400, "Valid email required")
        try:
            days = max(1, min(90, int(body.get("days") or 30)))
        except (TypeError, ValueError):
            days = 30
        since = _j_ts((time.time()-days*86400)*1000)
        return ok(self, {"events": audit_events(db(), email, since)})

    def _internal_journey_person(self):
        """One person's visits: every event carrying their address, plus every
        event in a visit that carried it (so the part before sign-in shows)."""
        if not self._internal_ok():
            return err(self, 403, "Forbidden")
        b = parse_body(self)
        email = str(b.get("email") or "").strip().lower()
        if not EMAIL_RE.match(email):
            return err(self, 400, "Valid email required")
        try:
            days = max(1, min(int(b.get("days") or 30), JOURNEY_KEEP_DAYS))
        except (TypeError, ValueError):
            days = 30
        since = _j_ts((time.time() - days * 86400) * 1000)
        conn = _journey_read()
        if conn is None:
            return ok(self, {"email": email, "days": days, "visits": [], "truncated": False,
                             "keep_days": JOURNEY_KEEP_DAYS})
        try:
            visits = [r[0] for r in conn.execute(
                "SELECT DISTINCT visit FROM journey_events WHERE email=? AND ts>=? AND visit<>''"
                " GROUP BY visit ORDER BY MAX(ts) DESC LIMIT 201", (email, since))]
            visit_truncated = len(visits) > 200
            visits = visits[:200]
            sql = ("SELECT ts,visit,seq,origin,event,email,idsrc,data FROM journey_events WHERE ts>=? AND ((email=? AND visit='')"
                   + (" OR visit IN (" + ",".join("?" * len(visits)) + ")" if visits else "")
                   + ") ORDER BY ts DESC, seq DESC LIMIT 5001")
            rows = _j_rows_to_events(conn.execute(sql, [since, email] + visits).fetchall())
        finally:
            conn.close()
        truncated = len(rows) > 5000 or visit_truncated
        rows = list(reversed(rows[:5000]))
        groups = {}
        for e in rows:
            g = groups.setdefault(e["visit"], {"visit": e["visit"], "first": e["ts"], "events": []})
            g["last"] = e["ts"]
            g["events"].append(e)
        out = []
        for g in groups.values():
            load = next((e for e in g["events"] if e["event"] == "load"), None)
            g["ua"] = (load or {}).get("data", {}).get("ua", "")
            g["w"]  = (load or {}).get("data", {}).get("w")
            g["flags"] = [{"ts": e["ts"], "id": e["data"].get("id", ""), "reason": f}
                          for e in g["events"] if e["event"] == "submit"
                          for f in [journey_flag(e, g["events"] if g["visit"] else [])] if f]
            out.append(g)
        out.sort(key=lambda g: g["first"], reverse=True)
        ok(self, {"email": email, "days": days, "visits": out, "truncated": truncated,
                  "keep_days": JOURNEY_KEEP_DAYS})

    def _internal_journey_summary(self):
        if not self._internal_ok():
            return err(self, 403, "Forbidden")
        b = parse_body(self)
        try:
            hours = max(1, min(int(b.get("hours") or 24), JOURNEY_KEEP_DAYS * 24))
        except (TypeError, ValueError):
            hours = 24
        since = _j_ts((time.time() - hours * 3600) * 1000)
        with _jstat_lock:
            store = dict(_jstat)
        store.update(queue=_jq.qsize(), keep_days=JOURNEY_KEEP_DAYS, max_bytes=JOURNEY_MAX_BYTES)
        conn = _journey_read()
        if conn is None:
            return ok(self, {"hours": hours, "since": since, "store": store, "empty": True})
        CAP = 300000
        try:
            store["rows"]   = conn.execute("SELECT COUNT(*) FROM journey_events").fetchone()[0]
            store["oldest"] = conn.execute("SELECT MIN(ts) FROM journey_events").fetchone()[0] or ""
            rows = _j_rows_to_events(conn.execute(
                "SELECT ts,visit,seq,origin,event,email,idsrc,data FROM journey_events"
                " WHERE ts>=? ORDER BY ts, seq LIMIT ?", (since, CAP + 1)).fetchall())
        finally:
            conn.close()
        truncated = len(rows) > CAP
        rows = rows[:CAP]

        def bump(d, k, n=1):
            d[k] = d.get(k, 0) + n
        def wb(w):
            if not isinstance(w, int): return "unknown"
            return "<600" if w < 600 else "600-859" if w < 860 else "860-1199" if w < 1200 else "1200+"

        by_visit, people = {}, set()
        loads = {"count": 0, "width": {}, "cached": 0, "rev": {}, "nav": {}}
        ident = {"verified": 0, "unverified": 0, "eligible": 0, "not_eligible": 0, "blocked": 0,
                 "emp_source": {}, "elig_source": {}}
        chooser = {"views": 0, "visits": set(), "c2_disabled": 0, "c2_below_fold": 0,
                   "stacked": 0, "c2_seen_visits": set()}
        signin, submits, acks = {}, {}, {"new": 0, "already": 0, "refused": 0}
        errs, fails = {}, {}
        for e in rows:
            d, ev = e["data"], e["event"]
            if e["visit"]:
                by_visit.setdefault(e["visit"], []).append(e)
            if e["email"]:
                people.add(e["email"])
            if ev == "load":
                loads["count"] += 1
                bump(loads["width"], wb(d.get("w")))
                if d.get("cached"): loads["cached"] += 1
                bump(loads["rev"], d.get("rev") or "none")
                bump(loads["nav"], d.get("nav") or "unknown")
            elif ev == "whoami":
                if d.get("verified"):
                    ident["verified"] += 1
                    ident["eligible" if d.get("fte") else "not_eligible"] += 1
                    if d.get("blocked"): ident["blocked"] += 1
                    bump(ident["emp_source"], d.get("emp") or "unknown")
                    bump(ident["elig_source"], d.get("src") or "unknown")
                else:
                    ident["unverified"] += 1
            elif ev == "view" and d.get("page") == "aiachoose":
                chooser["views"] += 1
                if e["visit"]: chooser["visits"].add(e["visit"])
                if d.get("c2") == "disabled": chooser["c2_disabled"] += 1
                if d.get("c2") == "enabled" and d.get("c2vis") is False: chooser["c2_below_fold"] += 1
                if d.get("stacked"): chooser["stacked"] += 1
            elif ev == "card2_seen":
                # same rule as journey_flag: a greyed-out card 2 on screen is not a usable card 2
                if e["visit"] and d.get("c2") != "disabled": chooser["c2_seen_visits"].add(e["visit"])
            elif ev == "signin_start":
                bump(signin, "start:" + (d.get("mode") or "?"))
            elif ev == "signin_result":
                bump(signin, (d.get("result") or "?") + (":" + d["aadsts"] if d.get("aadsts") else "")
                     + (":" + d["error"] if d.get("error") and not d.get("aadsts") else ""))
            elif ev == "submit":
                bump(submits, f"{d.get('type') or '?'} via {d.get('via') or ('no stamp' if not d.get('stamp') else '?')}"
                              f" ({e['idsrc'] or '?'})")
            elif ev == "ack":
                acks["already" if d.get("already") else "new"] += 1
            elif ev == "ack_refused":
                acks["refused"] += 1
            elif ev == "jserr":
                bump(errs, (d.get("msg") or "?")[:120])
            elif ev in ("submit_fail", "ack_fail"):
                bump(fails, ev + ": " + (d.get("msg") or "?")[:120])

        flags = []
        for e in rows:
            if e["event"] == "submit":
                f = journey_flag(e, by_visit.get(e["visit"], []) if e["visit"] else [])
                if f:
                    flags.append({"ts": e["ts"], "email": e["email"], "id": e["data"].get("id", ""),
                                  "type": e["data"].get("type", ""), "idsrc": e["idsrc"],
                                  "via": e["data"].get("via", ""), "visit": e["visit"], "reason": f})
        top = lambda d, n=10: sorted(({"k": k, "n": v} for k, v in d.items()), key=lambda x: -x["n"])[:n]
        ok(self, {
            "hours": hours, "since": since, "truncated": truncated, "events": len(rows),
            "visits": len(by_visit), "people": len(people),
            "loads": {**loads, "width": loads["width"], "rev": top(loads["rev"]), "nav": loads["nav"]},
            "identity": ident,
            "chooser": {"views": chooser["views"], "visits": len(chooser["visits"]),
                        "c2_disabled": chooser["c2_disabled"], "c2_below_fold": chooser["c2_below_fold"],
                        "stacked": chooser["stacked"],
                        "c2_seen_visits": len(chooser["c2_seen_visits"]),
                        "c2_never_seen_visits": len(chooser["visits"] - chooser["c2_seen_visits"])},
            "signin": top(signin, 20), "submits": top(submits, 20), "acks": acks,
            "js_errors": top(errs), "form_failures": top(fails),
            "flags": flags[-200:][::-1], "flags_total": len(flags), "flags_truncated": len(flags) > 200, "store": store,
        })

    def _logout(self):
        # Clear a retired browser cookie; only the platform owns active sessions.
        respond(self, 200, {"ok": True},
                extra_headers={"Set-Cookie": "portal_session=; Path=/; Max-Age=0"})

    def _me(self):
        session = session_from_request(self)
        if not session:
            return err(self, 401, "Not authenticated")
        acc      = effective_access(session)
        assigned = list(acc["decide_steps"])  # explicit decision grants
        steps    = list(assigned)
        if acc["manager_of_requests"] and "manager" not in steps:
            steps.append("manager")          # per-request grant (R3): named as a requester's manager
        # NB: the session's RBAC roles are deliberately NOT echoed — only the
        # user's own resolved grants (DESIGN §4).
        ok(self, {
            "can_read_access_guide": can_read_access_guide(session),
            "inventory": inventory_allowed(session),   # AI INVENTORY: InfoSec / Legal / admin
            "name":  session["name"],
            "email": session["email"],
            "role":  session["role"],
            "is_admin": session.get("role") == "admin",
            "source": session.get("source", "legacy"),
            "tier":  session.get("tier", ""),
            "level": session.get("level", ""),
            "can_approve_steps": steps,
            "assigned_steps": assigned,
            "manager_of_requests": list(acc["manager_of_requests"]),
            # ACK-TEAM: how many acknowledgment records name this person as manager
            "team_ack_count": ack_team_count(session.get("email", "")),
            "all_steps": list(STEP_LABELS.keys()),
            "step_labels": {k: step_label(k) for k in STEP_LABELS},
            "approval_access": {**acc, "resources": {t: effective_access(session, request_type=t) for t in REQUEST_TYPES}},
        })


    # ── REQUESTS ──────────────────────────────────────────────────────────

    # ── Silent corporate identity ────────────────────────────────────────
    def _identity_cookie(self, token: str) -> str:
        return (f"{IDENTITY_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; "
                f"Max-Age={IDENTITY_TTL_MIN * 60}")

    def _tried_cookie(self) -> str:
        """Deliberately NOT HttpOnly: the page reads it to know it has already
        had its one silent attempt. A failed prompt=none that retries on every
        load is an infinite redirect, so there are two independent guards — this
        and the page's own sessionStorage flag."""
        return f"{IDENTITY_TRIED_COOKIE}=1; Path=/; Secure; SameSite=Lax; Max-Age=600"

    def _identity_whoami(self, qs=None):
        """What the page needs to decide whether to attempt a silent sign-in and
        what to show. Returns only the caller's own identity, and answers
        normally when there is none."""
        rec = verified_identity(self)
        visit = self._j_visit(qs)
        if rec and rec.get("source") == "entra":
            email = rec.get("email", "")
            emp   = employment_class(email)
            elig  = ack_eligibility_for(email, emp)
            # JOURNEY: the decision that picks the intake path, as it was made.
            journey_server("whoami", visit, email, "entra", verified=True, fte=elig["eligible"],
                           src=elig["source"], blocked=elig["blocked"], emp=emp.get("source", ""),
                           matched=emp.get("matched"), enabled=SILENT_AUTH_ON)
            # `fte` is the requester's own classification and nothing more --
            # the pay class itself stays server-side. The page uses it to pick
            # the intake path; the server re-checks before it records anything.
            return respond(self, 200, {"ok": True, "data": {
                "enabled": SILENT_AUTH_ON, "verified": True,
                "identity": {k: rec.get(k, "") for k in IDENTITY_FIELDS},
                # ACK-ELIG: `fte` is what the page gates the option on; it now means "eligible"
                # (HR status OR administrator grant, minus block). Source is reporting only.
                "fte": elig["eligible"],
                "eligibility_source": elig["source"],
            }}, {"Cache-Control": "no-store, private"})
        discarded = bool(rec and rec.get("source") == "discarded")
        journey_server("whoami", visit, rec.get("email", "") if discarded else "",
                       "discarded" if discarded else "", verified=False, discarded=discarded,
                       enabled=SILENT_AUTH_ON)
        return respond(self, 200, {"ok": True, "data": {
            "enabled": SILENT_AUTH_ON, "verified": False,
            "discarded": bool(rec and rec.get("source") == "discarded"),
            "identity": None,
        }}, {"Cache-Control": "no-store, private"})

    def _identity_start(self, qs):
        nxt = _safe_next(qs.get("next", [""])[0])
        # SIGNIN-FIRST (2026-10-07): mode=signin is the requester asking to sign
        # in -- AI Use Case Intake when the silent attempt found no session. Same
        # round trip and callback; only the prompt differs.
        signin = qs.get("mode", [""])[0] == "signin"
        visit  = self._j_visit(qs)
        journey_server("signin_start", visit, mode="signin" if signin else "silent",
                       on=SILENT_AUTH_ON, next=nxt[:64])
        if not SILENT_AUTH_ON:
            # Not configured. Send the requester back to the form they asked
            # for, with the guard cookie set so the page does not try again.
            return _redirect(self, nxt, [self._tried_cookie()])
        state, verifier, nonce = _id_tx_new(nxt, visit, "signin" if signin else "silent")
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        url = (f"{ENTRA_AUTHORITY}/{url_quote(ENTRA_TENANT, safe='')}/oauth2/v2.0/authorize?"
               + urlencode({
                   "client_id":             ENTRA_CLIENT,
                   "response_type":         "code",
                   "redirect_uri":          ENTRA_REDIRECT,
                   "response_mode":         "query",
                   "scope":                 "openid profile email",
                   "state":                 state,
                   "nonce":                 nonce,
                   "code_challenge":        challenge,
                   "code_challenge_method": "S256",
                   # Silent: return an error, never a sign-in prompt. Sign-in:
                   # select_account, so a shared workstation can pick or add
                   # the right account instead of reusing whoever is signed in.
                   "prompt":                "select_account" if signin else "none",
               }))
        return _redirect(self, url)

    def _identity_callback(self, qs):
        """Back from Entra. Every exit sets the guard cookie, because every exit
        means the one silent attempt has been spent."""
        state = qs.get("state", [""])[0]
        tx    = _id_tx_pop(state)
        nxt   = _safe_next(tx["next"]) if tx else "/"
        guard = [self._tried_cookie()]
        # JOURNEY: how this round trip ended, joined to the page by its visit.
        aerr  = str(qs.get("error", [""])[0])[:40]
        m     = re.search(r"AADSTS\d{4,8}", qs.get("error_description", [""])[0] or "")
        def jr(result, email="", **k):
            journey_server("signin_result", (tx or {}).get("visit", ""), email, "entra" if email else "",
                           result=result, mode=(tx or {}).get("mode", ""), error=aerr,
                           aadsts=m.group(0) if m else "", **k)

        if not tx:
            jr("no_tx")                                   # stale, replayed, forged, or lost in a restart
            return _redirect(self, nxt, guard)            # stale, replayed or forged
        if qs.get("error"):
            # login_required / interaction_required mean "nobody is signed in
            # here" — the ordinary answer for a requester on a personal device,
            # and not an error worth showing anyone.
            jr("error")
            return _redirect(self, nxt, guard)
        code = qs.get("code", [""])[0]
        if not code:
            jr("no_code")
            return _redirect(self, nxt, guard)

        status, payload = _entra_token_exchange(code, tx["verifier"])
        if status != "ok":
            print(f"[IDENTITY] token exchange failed: {payload}", file=sys.stderr)
            jr("token_failed")
            return _redirect(self, nxt, guard)
        status, claims = _entra_claims(payload.get("id_token", ""), tx["nonce"])
        if status != "ok":
            print(f"[IDENTITY] id_token rejected: {claims}", file=sys.stderr)
            jr("claims_rejected")
            return _redirect(self, nxt, guard)

        email = str(claims.get("preferred_username") or claims.get("email")
                    or claims.get("upn") or "").strip().lower()
        if not EMAIL_RE.match(email) or (
                LOOKUP_ALLOWED_DOMAINS and email.rsplit("@", 1)[1] not in LOOKUP_ALLOWED_DOMAINS):
            print("[IDENTITY] sign-in rejected: address outside the allowed domains", file=sys.stderr)
            jr("domain_rejected", email if EMAIL_RE.match(email) else "")
            return _redirect(self, nxt, guard)

        # The token says who they are; the directory says the rest. Same source
        # the typed flow already uses, so a verified form and a looked-up form
        # are filled from the same place.
        rec = {"email": email, "name": str(claims.get("name") or "")[:200]}
        dstatus, dr = directory_lookup_server(email)
        if dstatus == "found":
            rec.update({
                "name":          dr.get("name") or rec["name"],
                "dept":          dr.get("department") or "",
                "title":         dr.get("title") or "",
                "manager_name":  dr.get("manager") or "",
                "manager_email": (dr.get("manager_email") or "").lower(),
                "manager_id":    dr.get("manager_id") or "",
            })
        else:
            # The directory could not confirm the rest. The address is still
            # proven, and locking the address is most of the value.
            print(f"[IDENTITY] {email} signed in but directory lookup was {dstatus}", file=sys.stderr)

        token = identity_put(rec)
        jr("ok", email, dir=dstatus)
        return _redirect(self, nxt, [self._identity_cookie(token)] + guard)

    def _journey_submit(self, req, type_key, submitter, identity_source, raw_stamp):
        """JOURNEY: one 'submit' event per filed request. For AI Use Case
        Intake the server also records whether the person was eligible for
        card 2, worked out here and not taken from the page; that lookup runs
        off the request thread so the requester is never kept waiting."""
        try:
            visit, data = journey_stamp(raw_stamp)
            data.update(id=req.get("id", ""), type=type_key)
            email, ts = (submitter.get("email") or "").strip().lower(), _j_ts()
            if type_key != "aia":
                return journey_server("submit", visit, email, identity_source, ts, **data)
            def later():
                try:
                    emp  = employment_class(email)
                    elig = ack_eligibility_for(email, emp)
                    data.update(fte_srv=elig["eligible"], src=elig["source"], emp=emp.get("source", ""))
                except Exception as e:
                    data.update(fte_srv=None, src_error=str(e)[:120])
                journey_server("submit", visit, email, identity_source, ts, **data)
            threading.Thread(target=later, name="journey-submit", daemon=True).start()
        except Exception as e:
            print(f"[JOURNEY] submit event skipped: {e}", file=sys.stderr)

    def _identity_forget(self, qs=None):
        rec = verified_identity(self)
        had = identity_discard(self)
        journey_server("forget", self._j_visit(qs), (rec or {}).get("email", ""),
                       (rec or {}).get("source", ""), had=had)
        return respond(self, 200, {"ok": True, "data": {"verified": False}},
                       {"Cache-Control": "no-store, private"})

    def _submit_request(self):
        ip = (self.headers.get("X-Real-IP") or self.client_address[0] or "?")
        if _rate_limited(ip):
            return err(self, 429, "Too many submissions from this address. Please try again later.")
        body      = parse_body(self)
        type_key  = (body.get("type") or "").lower().strip()
        if type_key not in REQUEST_TYPES:
            return err(self, 400, f"Invalid request type. Must be one of: {', '.join(REQUEST_TYPES)}")
        if type_key in hidden_types():
            return err(self, 400, f"{REQUEST_TYPES[type_key]['label']} is not accepting new requests at the moment")
        submitter = body.get("submitter") or {}
        details   = body.get("details")   or {}
        priority  = body.get("priority", "normal")
        signature = body.get("signature", "")

        if not isinstance(submitter, dict) or not isinstance(details, dict):
            return err(self, 400, "submitter and details must be objects")

        # ── Who is actually filing this? ─────────────────────────────────────
        # When the browser proved a corporate identity, that identity wins
        # outright and the posted fields are ignored: the form is a convenience,
        # not the source of truth. Every request is stamped with how identity
        # was established so an approver can tell "verified" from "typed" — and
        # a requester who set a verified identity aside is recorded as such.
        ident = verified_identity(self)
        identity_source, identity_note = "typed", ""
        if ident and ident.get("source") == "entra":
            identity_source = "entra"
            for k in IDENTITY_FIELDS:
                if ident.get(k):
                    submitter[k] = ident[k]
            if ident.get("manager_email"):
                submitter["manager_source"] = "directory"
        elif ident and ident.get("source") == "discarded":
            identity_source = "typed_over_verified"
            identity_note   = ("This browser was signed in to Microsoft as "
                               f"{ident.get('email','')}, and the requester chose "
                               "\"This is not me\" and filled the form in by hand.")

        if not submitter.get("name"):
            return err(self, 400, "submitter.name is required")
        if not EMAIL_RE.match((submitter.get("email") or "").strip()):
            return err(self, 400, "A valid submitter.email is required")
        raw_mgr_email = str((submitter.get("manager_email") or "")).strip()
        submitter = _clean_submitter(submitter)
        # Authoritative, and set after cleaning: a client cannot post its own.
        submitter["identity_source"] = identity_source
        if submitter.get("manager_source") == "manual":
            # Typed by hand because the directory was unreachable. A bad address
            # must be an error the requester can fix, not a silent fallback to
            # the Service Desk they would never know about.
            if not submitter.get("manager_email"):
                dom = ", ".join("@" + d for d in LOOKUP_ALLOWED_DOMAINS) or "a company domain"
                why = "is required" if not raw_mgr_email else f"must be a valid company address ({dom}) and not your own"
                return err(self, 400, f"Manager email {why}")
        if priority not in ("low", "normal", "high"):
            priority = "normal"

        # A typed manager address is checked against the directory from HERE —
        # the requester's browser could not reach it, this process can. A typo
        # is refused before any mail goes out; only when the directory itself is
        # down is the address accepted as typed.
        manual_note = ""
        if submitter.get("manager_source") == "manual":
            status, rec = directory_lookup_server(submitter["manager_email"])
            if status == "notfound":
                return err(self, 400, f"No employee found with the manager address {submitter['manager_email']} — check the spelling")
            if status == "found":
                submitter["manager_name"]   = (rec.get("name") or submitter.get("manager_name") or "").strip()[:200]
                submitter["manager_email"]  = (rec.get("email") or submitter["manager_email"]).strip().lower()
                if rec.get("id"): submitter["manager_id"] = str(rec["id"])[:128]
                submitter["manager_source"] = "directory"
                manual_note = (f"Manager address typed by the requester (directory unreachable from their device) and "
                               f"VERIFIED server-side: {submitter['manager_name']} <{submitter['manager_email']}>.")
            else:
                manual_note = (f"Directory unavailable at submission ({rec}); manager entered by hand and NOT verified: "
                               f"{submitter.get('manager_name','')} <{submitter.get('manager_email','')}>.")

        # ONE-POLICY: record which AI Policy version/sha the requester ticked (audit).
        if type_key == "aia" and details.get("policy_ack"):
            try:
                _pf = policy_doc_form("aia"); _cur = current_policy_version(_pf); _m = policy_doc_meta(_pf) or {}
                details["ai_policy_form"] = _pf
                details["ai_policy_version"] = int(_cur["version"]) if _cur else 0
                details["ai_policy_sha"] = (_cur or {}).get("sha") or _m.get("sha") or ""
                details["ai_policy_file"] = (_cur or {}).get("file_name") or _m.get("name") or ""
            except Exception as _e:
                print(f"[ONE-POLICY] version stamp skipped: {_e}", file=sys.stderr)
        req = create_request(type_key, submitter, details, priority, signature)
        self._journey_submit(req, type_key, submitter, identity_source, body.get("journey"))
        if identity_source == "entra":
            audit(req["id"], "submission.identity", submitter.get("email") or "Requester", "Requester",
                  "Requester identity verified by corporate sign-in (Microsoft Entra). Name, email, "
                  "department, title and manager were taken from the directory, not typed.")
        elif identity_note:
            audit(req["id"], "submission.identity", submitter.get("email") or "Requester", "Requester",
                  identity_note)
        if manual_note:
            audit(req["id"], "submission.manual_manager", submitter.get("email") or "Requester", "Requester", manual_note)
        notify_submission(req)
        ok(self, req)

    def _send_record(self, fmt: str, title: str, subtitle: str, sections: list, stamp: str, basename: str):
        """Shared writer for html / docx / pdf exports."""
        fmt = (fmt or "html").lower()
        if fmt == "docx":
            data = record_docx_bytes(title, subtitle, sections); ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"; ext = "docx"; disp = "attachment"
        elif fmt == "pdf":
            try:
                data = record_pdf_bytes(record_docx_bytes(title, subtitle, sections))
            except RuntimeError as e:
                return err(self, 503, f"PDF export unavailable: {e}")
            ctype = "application/pdf"; ext = "pdf"; disp = "attachment"
        else:
            data = record_html_generic(title, subtitle, sections, stamp).encode("utf-8"); ctype = "text/html; charset=utf-8"; ext = "html"; disp = "inline"
        self.send_response(200)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("Content-Disposition", f'{disp}; filename="{basename}.{ext}"')
        self.end_headers(); self.wfile.write(data)

    def _request_record(self, req_id: str, session: dict, qs: dict):
        """Downloadable copy of a request (Word / PDF / printable) — same visibility rule as opening it."""
        if not is_any_approver(session):
            return err(self, 403, "You are not an approver.")
        row = db().execute("SELECT * FROM requests WHERE id=?", ((req_id or "").upper(),)).fetchone()
        if not row:
            return err(self, 404, f"No request found with ID {req_id}")
        vis = visible_request_ids(session)
        if vis is not None and row["id"] not in vis:
            return err(self, 403, "This request is not in a workflow step you hold.")
        r = _build_request_dict(row)
        title, subtitle, sections, stamp = request_record_model(r)
        fmt = ((qs.get("format") or ["html"])[0]).lower()
        audit(r["id"], "request.exported", (session or {}).get("email") or "approver", (session or {}).get("role") or "", f"{fmt} export")
        return self._send_record(fmt, title, subtitle, sections, stamp, f"{r['id']}-record")

    def _get_request(self, req_id: str, session: dict):
        """Full record — approver console only (nginx gates the path; the
        session check here is defence in depth)."""
        if not req_id:
            return err(self, 400, "Request ID is required")
        if not is_any_approver(session):
            return err(self, 403, "You are not an approver.")
        row = db().execute("SELECT * FROM requests WHERE id=?", (req_id.upper(),)).fetchone()
        if not row:
            return err(self, 404, f"No request found with ID {req_id}")
        vis = visible_request_ids(session)
        if vis is not None and row["id"] not in vis:
            return err(self, 403, "This request is not in a workflow step you hold.")
        ok(self, _build_request_dict(row))

    def _public_status(self, req_id: str):
        """Requester tracker. Public, so it returns only what the confirmation
        page already told the requester: ID, type, status and the step ladder.
        No submitter, details, comments or approver identities."""
        ip = (self.headers.get("X-Real-IP") or self.client_address[0] or "?")
        if _rate_limited(ip, "status", STATUS_WINDOW, STATUS_MAX):
            return err(self, 429, "Too many status checks. Please try again later.")
        req_id = (req_id or "").strip().upper()
        if not re.match(r"^[A-Z]{3}-\d{4}-\d{5}$", req_id):
            return err(self, 400, "Request ID is required (example: OCA-2026-00012)")
        row = db().execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
        if not row:
            return err(self, 404, f"No request found with ID {req_id}")
        r = dict(row)
        ap_rows = db().execute(
            "SELECT step, step_key, step_label, status, decided_at FROM approvals WHERE request_id=? ORDER BY step",
            (req_id,)).fetchall()
        ok(self, {
            "archived": bool(r.get("archived_at")),   # ARCHIVE: the requester sees a note, not a missing request
            "id": r["id"], "type": r["type"], "status": r["status"],
            "current_step": r["current_step"],
            "workflow": json.loads(r["workflow"]),
            "approvals": [dict(a) for a in ap_rows],
            "created_at": r["created_at"], "updated_at": r["updated_at"],
        })

    def _directory_lookup(self, q: str):
        """R1 — server-side proxy for the requester form's directory lookup.
        Exact-match on a company email, minimal fields, rate-limited, and the
        hub credential stays on this side of the trust boundary."""
        ip = (self.headers.get("X-Real-IP") or self.client_address[0] or "?")
        if _rate_limited(ip, "lookup", LOOKUP_WINDOW, LOOKUP_MAX):
            return err(self, 429, "Too many lookups. Please try again in a few minutes.")
        q = (q or "").strip().lower()
        if not EMAIL_RE.match(q) or len(q) > 254:
            return err(self, 400, "Enter your full work email address")
        if LOOKUP_ALLOWED_DOMAINS and q.rsplit("@", 1)[1] not in LOOKUP_ALLOWED_DOMAINS:
            return err(self, 404, "User not found")
        if not LOOKUP_URL or not LOOKUP_KEY:
            print("[LOOKUP] PORTAL_LOOKUP_RELAY / PORTAL_LOOKUP_KEY not set", file=sys.stderr)
            return err(self, 503, "Directory lookup is not configured")
        # X-Real-IP lands in the hub's audit line as "client" (the requester's address).
        headers = {"Accept": "application/json", "X-Real-IP": ip, LOOKUP_KEY_HEADER: LOOKUP_KEY}
        try:
            rq = urllib.request.Request(LOOKUP_URL + "?q=" + url_quote(q, safe=""), headers=headers)
            with urllib.request.urlopen(rq, timeout=10) as r:
                raw = json.loads(r.read().decode("utf-8", errors="replace") or "{}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return err(self, 404, "User not found")
            if e.code == 429:
                return err(self, 503, "Directory lookup is busy — try again in a minute")
            detail = e.read().decode(errors="replace")[:200]
            print(f"[LOOKUP] hub HTTP {e.code}: {detail}" + (" (check PORTAL_LOOKUP_KEY matches the hub)" if e.code == 401 else ""), file=sys.stderr)
            return err(self, 502, "Directory lookup is unavailable right now")
        except Exception as e:
            print(f"[LOOKUP] {e}", file=sys.stderr)
            return err(self, 502, "Directory lookup is unavailable right now")

        me = _normalize_lookup(raw)
        if not me or (me.get("email") or "").lower() != q:
            return err(self, 404, "User not found")
        if raw.get("accountEnabled") is False:
            return err(self, 404, "User not found")     # disabled account: nothing to pre-fill
        ok(self, me)

    def _edit_request(self, req_id: str, session: dict):
        """R8 — administrator correction of submitter/details fields. Status,
        workflow and decisions are untouchable; every change is audited old→new."""
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        body = parse_body(self)
        new_sub = body.get("submitter") if isinstance(body.get("submitter"), dict) else None
        new_det = body.get("details")   if isinstance(body.get("details"), dict) else None
        new_pri = body.get("priority")
        if new_sub is None and new_det is None and new_pri is None:
            return err(self, 400, "Nothing to update: send submitter, details and/or priority")
        with write_lock:
            row = db().execute("SELECT * FROM requests WHERE id=?", (req_id.upper(),)).fetchone()
            if not row:
                return err(self, 404, f"No request found with ID {req_id}")
            vis = visible_request_ids(session)          # None = super-admin
            if vis is not None and row["id"] not in vis:
                return err(self, 403, "This request is not in a workflow step you hold.")
            r = dict(row)
            sub = json.loads(r["submitter"]); det = json.loads(r["details"])
            changes = []
            if new_sub is not None:
                bad = [k for k in new_sub if k not in EDITABLE_SUBMITTER_KEYS]
                if bad:
                    return err(self, 400, f"submitter fields not editable: {', '.join(sorted(bad))}")
                cleaned = _clean_submitter({**sub, **{k: ("" if v is None else str(v)) for k, v in new_sub.items()}})
                if not cleaned.get("name"):
                    return err(self, 400, "submitter.name cannot be empty")
                if not EMAIL_RE.match(cleaned.get("email") or ""):
                    return err(self, 400, "submitter.email must be a valid address")
                if new_sub.get("manager_email") and not cleaned.get("manager_email"):
                    return err(self, 400, "submitter.manager_email must be a valid company address and not the requester's own")
                # The requester and direct-manager identities feed the decision model
                # (SoD refusal, per-request manager grant), so an editor — super-admin
                # included — may never move either of them onto or off themself.
                me = (session.get("email") or "").strip().lower()
                if me:
                    old_mgr, new_mgr = (sub.get("manager_email") or "").lower(), (cleaned.get("manager_email") or "").lower()
                    old_req, new_req = (sub.get("email") or "").lower(),         (cleaned.get("email") or "").lower()
                    if new_mgr == me and old_mgr != me:
                        return err(self, 403, "You cannot name yourself as the requester's manager")
                    if old_req == me and new_req != me:
                        return err(self, 403, "You cannot change the requester on your own request")
                    if new_req == me and old_req != me:
                        return err(self, 403, "You cannot make yourself the requester")
                for k in sorted(set(sub) | set(cleaned)):
                    if sub.get(k, "") != cleaned.get(k, ""):
                        changes.append({"field": f"submitter.{k}", "old": sub.get(k, ""), "new": cleaned.get(k, "")})
                sub = cleaned
            if new_det is not None:
                for k, v in new_det.items():
                    if not re.match(r"^[A-Za-z0-9_\-]{1,64}$", str(k)):
                        return err(self, 400, f"invalid details key: {k!r}")
                    if not isinstance(v, (str, int, float, bool)) and v is not None:
                        return err(self, 400, f"details.{k}: only text, numbers and yes/no values are editable")
                    if isinstance(v, str) and len(v) > 8000:
                        return err(self, 400, f"details.{k}: too long")
                    if det.get(k) != v:
                        changes.append({"field": f"details.{k}", "old": det.get(k), "new": v})
                        det[k] = v
            if new_pri is not None:
                if new_pri not in ("low", "normal", "high"):
                    return err(self, 400, "priority must be low, normal or high")
                if new_pri != r["priority"]:
                    changes.append({"field": "priority", "old": r["priority"], "new": new_pri})
            if not changes:
                return ok(self, {"changed": 0, "request": _build_request_dict(row)})
            ts = now_iso()
            db().execute(
                "UPDATE requests SET submitter=?, details=?, priority=?, updated_at=? WHERE id=?",
                (json.dumps(sub), json.dumps(det), new_pri if new_pri is not None else r["priority"], ts, r["id"]))
            db().execute(
                "INSERT INTO audit_log(request_id,event,actor,role,note,created_at) VALUES(?,?,?,?,?,?)",
                (r["id"], "Request Edited by Administrator", session.get("name") or session.get("email") or "admin",
                 "admin", json.dumps({"by": session.get("email"), "changes": changes})[:4000], ts))
            db().commit()
        fresh = _build_request_dict(db().execute("SELECT * FROM requests WHERE id=?", (r["id"],)).fetchone())
        # A corrected manager on a request still waiting at the manager step must
        # actually hear about it — otherwise the fix leaves the request waiting on nobody.
        mgr_changed = any(c["field"] == "submitter.manager_email" for c in changes)
        if mgr_changed and fresh["status"] == "pending" and (fresh["workflow"] or [None])[fresh["current_step"]] == "manager":
            _notify_next_approver(fresh, fresh["current_step"])
        ok(self, {"changed": len(changes), "changes": changes, "request": fresh})


    def _roles(self, session: dict):
        """O3 — one source of truth for the console: every workflow step with its
        label, description, which request types use it, who may act (ACL), the
        notification recipient and whether the step is currently routable."""
        if not is_any_approver(session):
            return err(self, 403, "You are not an approver.")
        is_admin = session.get("role") == "admin"
        steps = []
        for key in STEP_LABELS:
            label = step_label(key)
            email = (get_setting(f"approver_email_{key}") or "").strip()
            steps.append({
                "step": key, "label": label,
                # the built-in name, so the console can offer "clear to restore X"
                "builtin_label": STEP_LABELS.get(key, key),
                "renamed": label != STEP_LABELS.get(key, key),
                "description": STEP_DESCRIPTIONS.get(key, ""),
                "request_types": [t for t in REQUEST_TYPES if key in type_workflow(t)],
                "recipient": {"name": get_setting(f"approver_name_{key}", "") or "",
                              "email": email} if is_admin else None,
                "routable": bool(email and ADDR_RE.match(email)) or key == "manager",
                "dynamic": key == "manager",
            })
        ok(self, {
            "steps": steps,
            "request_types": {t: {"label": rt["label"], "prefix": rt["prefix"],
                                  "workflow": type_workflow(t),
                                  "workflow_default": list(rt["workflow"]),
                                  "workflow_custom": type_workflow(t) != list(rt["workflow"]),
                                  "hidden": t in hidden_types()}
                              for t, rt in REQUEST_TYPES.items()},
            "workflow_rules": {"first_step": WORKFLOW_FIRST_STEP, "min_steps": WORKFLOW_MIN_STEPS},
            "fixed_recipients": get_smtp() if is_admin else None,
        })

    def _list_requests(self, session: dict, qs: dict):
        if not is_any_approver(session):
            return err(self, 403, "You are not an approver.")
        visible = visible_request_ids(session)   # None = admin, sees everything
        filters = []
        params  = []

        status_filter = qs.get("status", [""])[0]
        type_filter   = qs.get("type",   [""])[0]
        search        = qs.get("q",      [""])[0].strip()

        if status_filter:
            filters.append("r.status=?")
            params.append(status_filter)
        if type_filter:
            filters.append("r.type=?")
            params.append(type_filter)
        _ac = _archived_clause(qs, "r.")          # ARCHIVE: active only unless ?archived=1|all
        if _ac: filters.append(_ac)

        where = ("WHERE " + " AND ".join(filters)) if filters else ""
        rows  = db().execute(
            f"SELECT * FROM requests r {where} ORDER BY r.created_at DESC",
            params).fetchall()

        result = []
        for row in rows:
            if visible is not None and row["id"] not in visible:
                continue
            r = _build_request_dict(row)
            if search:
                s = search.lower()
                haystack = json.dumps(r).lower()
                if s not in haystack:
                    continue
            result.append(r)

        ok(self, result)

    def _decide(self, req_id: str, session: dict):
        body        = parse_body(self)
        action      = body.get("action") or ""
        posted_step = str(body.get("step") or "").strip().lower()
        posted_upd  = body.get("updated_at")      # optional optimistic-concurrency token
        comments    = body.get("comments", "")
        signature   = body.get("signature", "")

        if action not in ("approve", "reject", "return"):
            return err(self, 400, "action must be 'approve', 'reject', or 'return'")
        if action in ("reject", "return") and not comments:
            return err(self, 400, "comments are required when rejecting or returning")

        # Whole decision is atomic against other writers, and every guard is
        # enforced server-side: request open, the client's step == the ACTUAL
        # current step loaded here (never the client's idea of it), the row
        # unchanged since the client loaded it, and the SSO-verified caller
        # holding an explicit grant for THIS step (deny-by-default).
        with write_lock:
            req_row = db().execute("SELECT * FROM requests WHERE id=?", (req_id.upper(),)).fetchone()
            if not req_row:
                return err(self, 404, f"No request found with ID {req_id}")
            req = dict(req_row)
            # Scope first: a request outside the caller's visibility gets the same
            # answer as a GET would — nothing about its status or step is disclosed.
            vis = visible_request_ids(session)
            if vis is not None and req["id"] not in vis:
                return err(self, 403, "This request is not in a workflow step you hold.")
            workflow = json.loads(req["workflow"])
            if req["status"] != "pending":
                return err(self, 409, f"Request {req_id} is {req['status']} and cannot be decided")
            if req.get("archived_at"):   # ARCHIVE: nobody acts on an archived request; un-archive first
                return err(self, 409, f"Request {req_id} is archived — un-archive it before deciding")
            cur_idx = req["current_step"]
            if cur_idx >= len(workflow):
                return err(self, 409, "Request has no pending step")
            step_key = workflow[cur_idx]
            if posted_step != step_key:
                return err(self, 409, f"It is not this step's turn — the current step is '{step_key}'")
            if posted_upd is not None and str(posted_upd) != (req.get("updated_at") or ""):
                return respond(self, 409, {"ok": False, "error": "stale",
                                           "message": "This request changed since you loaded it"})
            req["submitter"] = json.loads(req["submitter"]) if isinstance(req["submitter"], str) else req["submitter"]
            if not is_authorized_for_step(session, step_key, req):
                return err(self, 403, f"You are not an assigned approver for the '{STEP_LABELS.get(step_key, step_key)}' step")
            grant = _grant_source(session, step_key, req)
            approver_name = session.get("name") or session.get("email") or "Unknown"
            result = record_decision(req_id.upper(), step_key, action,
                                     approver_name, step_key, comments, signature,
                                     actor_email=(session.get("email") or ""), notify=False,
                                     grant=grant or "")
        # Mail goes out after the lock is released: a slow relay must not stall
        # every other submission and decision.
        _notify_after_decision(result, action, cur_idx)
        inventory_on_request_approved(result)   # AI INVENTORY: row appears once an AIA request is approved
        ok(self, result)


    # ── REPORTS ───────────────────────────────────────────────────────────

    def _reports_summary(self, session: dict):
        """Counts over the requests this session may see (admin: all)."""
        if not is_any_approver(session):
            return err(self, 403, "You are not an approver.")
        vis = visible_request_ids(session)
        rows = db().execute("SELECT id, type, status, created_at FROM requests WHERE COALESCE(archived_at,'')=''").fetchall()   # ARCHIVE
        rows = [r for r in rows if vis is None or r["id"] in vis]
        total    = len(rows)
        pending  = sum(1 for r in rows if r["status"] == "pending")
        approved = sum(1 for r in rows if r["status"] == "approved")
        rejected = sum(1 for r in rows if r["status"] == "rejected")
        draft    = sum(1 for r in rows if r["status"] == "draft")
        by_type  = {t: sum(1 for r in rows if r["type"] == t) for t in REQUEST_TYPES}
        by_month = {}
        for r in rows:
            m = (r["created_at"] or "")[:7]
            by_month[m] = by_month.get(m, 0) + 1
        by_month = dict(sorted(by_month.items(), reverse=True)[:12])
        ok(self, {
            "total": total, "pending": pending, "approved": approved,
            "rejected": rejected, "draft": draft,
            "approval_rate": round(approved / total * 100) if total else 0,
            "by_type": by_type, "by_month": by_month,
        })

    def _reports_audit(self, session: dict, qs: dict):
        # The audit log carries PII (edit diffs, decision comments, addresses): admin only.
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        try:
            limit  = max(1, min(int(qs.get("limit",  [500])[0]), 2000))
            offset = max(0, int(qs.get("offset", [0])[0]))
        except ValueError:
            return err(self, 400, "limit and offset must be integers")
        if is_superadmin(session):
            rows = db().execute(
                "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)).fetchall()
            return ok(self, [dict(r) for r in rows])
        # Scoped view: request rows only for requests the caller may see, plus
        # non-request rows (settings/content/policy changes) for page admins.
        # Paging is applied AFTER the filter so offsets stay meaningful.
        vis      = visible_request_ids(session) or set()
        is_admin = session.get("role") == "admin"
        out, skipped = [], 0
        for r in db().execute("SELECT * FROM audit_log ORDER BY created_at DESC"):
            rid = r["request_id"] or ""
            if rid:
                if rid not in vis:
                    continue
            else:
                continue  # global access-policy audit is super-admin only
            if skipped < offset:
                skipped += 1
                continue
            out.append(dict(r))
            if len(out) >= limit:
                break
        ok(self, out)


    def _export_csv(self, session: dict, qs: dict):
        # Admin-only (unchanged) AND scoped: a page admin who is not a super-admin
        # exports only the requests they can see.
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        vis = visible_request_ids(session)           # None = super-admin
        type_filter = qs.get("type", [""])[0]
        where  = "WHERE type=?" if type_filter else ""
        params = (type_filter,) if type_filter else ()
        rows   = db().execute(
            f"SELECT * FROM requests {where} ORDER BY created_at DESC",
            params).fetchall()

        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow(["Request ID","Type","Status","Priority","Submitter Name",
                    "Submitter Email","Department","Title","Submitted","Updated"])
        for row in rows:
            if vis is not None and row["id"] not in vis:
                continue
            r   = dict(row)
            sub = json.loads(r["submitter"])
            w.writerow([_csv_safe(x) for x in (
                r["id"], r["type"], r["status"], r["priority"],
                sub.get("name",""), sub.get("email",""),
                sub.get("dept",""), sub.get("title",""),
                r["created_at"][:10], r["updated_at"][:10],
            )])

        body = out.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition",
                         f'attachment; filename="portal-export-{now_iso()[:10]}.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)


    # ── SETTINGS ──────────────────────────────────────────────────────────

    def _get_content(self):
        # PUBLIC — front-facing copy only. Never returns smtp_* or credentials.
        ok(self, {"content": content_all(),
                  "keys": {k: {"max": v[0], "kind": v[1]} for k, v in CONTENT_KEYS.items()},
                  "docs": {f: policy_doc_public_shown(f) for f in sorted(POLICY_FORMS)},
                  "workflows": {t: type_workflow(t) for t in REQUEST_TYPES},
                  "hidden_types": hidden_types(),
                  "docs_convert": bool(SOFFICE),
                  "docs_max_bytes": POLICY_MAX_BYTES})

    # ── ACKNOWLEDGEMENTS ─────────────────────────────────────────────────

    def _ack_identity(self):
        """The corporate identity this acknowledgement belongs to, or None.
        A discarded identity ('this is not me') does not count: an
        acknowledgement has to name somebody."""
        rec = verified_identity(self)
        return rec if rec and rec.get("source") == "entra" else None

    # ── ACK-ADMIN ─────────────────────────────────────────────────────────
    ACK_IDENTITY_FIELDS = ("name", "dept", "title", "manager_email", "employee_id")

    def _ack_row_public(self, r: dict, cur_v: int) -> dict:
        v = int(r.get("policy_version") or 0)
        return {
            "id": r["id"], "form": r["form"], "email": r["email"], "name": r.get("name", ""),
            "dept": r.get("dept", ""), "title": r.get("title", ""), "manager_email": r.get("manager_email", ""),
            "employee_id": r.get("employee_id", ""), "policy_version": v, "policy_sha": r.get("policy_sha", ""),
            "policy_url": r.get("policy_url", ""), "ack_via": r.get("ack_via", ""),
            "employment_class": r.get("employment_class", ""), "employment_matched": r.get("employment_matched", ""),
            "identity_source": r.get("identity_source", ""), "sample": bool(r.get("sample")),
            "eligibility_source": r.get("eligibility_source", ""),
            "signature_kind": (r.get("signature") or "").split(":", 1)[0],
            "signature_text": (r.get("signature") or "")[6:] if (r.get("signature") or "").startswith("typed:") else "",
            "statements": (json.loads(r["statements_json"]) if r.get("statements_json") else []),
            "created_at": r.get("created_at", ""),
            # Completed = on the version now published; otherwise the person must re-acknowledge.
            "status": "completed" if (cur_v and v == cur_v and not r.get("superseded_at")) else "requires_reack",
            # ACK-REACK
            "superseded_at": r.get("superseded_at", ""), "superseded_by": r.get("superseded_by", ""), "superseded_reason": r.get("superseded_reason", ""),
            "reack_notified_at": r.get("reack_notified_at", ""), "reack_notified_version": int(r.get("reack_notified_version") or 0),
            # ARCHIVE
            "archived_at": r.get("archived_at", ""), "archived_by": r.get("archived_by", ""), "archived_reason": r.get("archived_reason", ""),
        }

    def _ack_admin_list(self, session: dict, qs: dict):
        scope = ((qs.get("scope") or [""])[0] or "").strip().lower()
        me = ((session or {}).get("email") or "").lower()
        if (session or {}).get("role") != "admin":
            # ACK-TEAM: a manager may list the records that name them as manager -- nothing else.
            if scope != "team" or not me:
                return err(self, 403, "Admin role required")
        form = (qs.get("form") or ["cla"])[0]
        if form not in ACK_FORMS:
            return err(self, 404, f"No acknowledgment form '{form}'")
        q = ((qs.get("q") or [""])[0] or "").strip().lower()
        want = ((qs.get("status") or [""])[0] or "").strip().lower()
        cur = current_policy_version(form); cur_v = int(cur["version"]) if cur else 0
        rows = self._ack_filtered_rows(form, qs, me if scope == "team" else None)
        # latest record per person is what the status view reports; history stays reachable per record
        latest, seen = [], set()
        for r in rows:
            k = (r.get("email") or "").lower()
            if k in seen: continue
            seen.add(k); latest.append(self._ack_row_public(r, cur_v))
        if q:
            latest = [x for x in latest if q in " ".join(str(x.get(f, "")) for f in ("email", "name", "dept", "manager_email", "employee_id")).lower()]
        if want in ("completed", "requires_reack"):
            latest = [x for x in latest if x["status"] == want]
        summary = {
            "people": len(seen), "records": len(rows),
            "completed": sum(1 for x in latest if x["status"] == "completed"),
            "requires_reack": sum(1 for x in latest if x["status"] == "requires_reack"),
            "sample_records": sum(1 for r in rows if r.get("sample")),
            "archived_records": db().execute("SELECT COUNT(*) FROM acknowledgments WHERE form=? AND COALESCE(archived_at,'')<>''", (form,)).fetchone()[0],   # ARCHIVE
            "current_version": cur_v, "current_effective": (cur or {}).get("effective_date", ""),
            "current_file": (cur or {}).get("file_name", ""), "live": (get_setting(f"content.policy.{form}.live", "") or "").strip() == "1",
        }
        # ACK-ELIG: eligible population = HR FTE roster (when the relay exposes a count) + active allows - active blocks.
        try:
            allows = {r[0].lower() for r in db().execute("SELECT email FROM ack_eligibility WHERE form=? AND mode='allow' AND removed_at=''", (form,)).fetchall()}
            blocks = {r[0].lower() for r in db().execute("SELECT email FROM ack_eligibility WHERE form=? AND mode='block' AND removed_at=''", (form,)).fetchall()}
            roster = ack_fte_roster_emails()
            eligible = ((roster | allows) - blocks) if roster is not None else None
            summary["admin_allows"] = len(allows); summary["admin_blocks"] = len(blocks)
            summary["eligible_people"] = len(eligible) if eligible is not None else None
            signed_cur = {x["email"].lower() for x in latest if x["status"] == "completed"}
            summary["not_yet_acknowledged"] = (len(eligible - signed_cur) if eligible is not None else None)
            summary["roster_known"] = roster is not None
        except Exception as _e:
            summary["eligible_people"] = None; summary["not_yet_acknowledged"] = None; summary["roster_known"] = False
        if scope == "team":
            summary = {k: summary[k] for k in ("people", "records", "completed", "requires_reack", "current_version", "current_effective", "current_file")}
        return ok(self, {"form": form, "label": ACK_LABELS.get(form, form), "summary": summary, "rows": latest, "scope": scope or "all"})

    def _ack_admin_get(self, session: dict, rid: int):
        row = db().execute("SELECT * FROM acknowledgments WHERE id=?", (rid,)).fetchone()
        if not row:
            return err(self, 404, "No such acknowledgment")
        r = dict(row); viewer = self._ack_viewer(session, r)
        if not viewer:
            return err(self, 403, "Admin role required")
        cur = current_policy_version(r["form"]); cur_v = int(cur["version"]) if cur else 0
        out = self._ack_row_public(r, cur_v); out["viewer"] = viewer; out["record_sha"] = r.get("record_sha", "")
        if viewer == "admin": out["client_ip"] = r.get("client_ip", "")
        out["history"] = [self._ack_row_public(dict(x), cur_v) for x in db().execute(
            "SELECT * FROM acknowledgments WHERE form=? AND LOWER(email)=? ORDER BY id DESC", (r["form"], (r["email"] or "").lower())).fetchall()]
        out["audit"] = [dict(x) for x in db().execute(
            "SELECT event, actor, role, note, created_at FROM audit_log WHERE request_id=? ORDER BY created_at", (f"ACK-{rid}",)).fetchall()]
        if viewer != "admin":
            for a in out["audit"]:
                if a["event"] == "acknowledgment.identity_corrected": a["note"] = "identity fields corrected by an administrator"
        ver = db().execute("SELECT * FROM policy_versions WHERE form=? AND version=?", (r["form"], int(r.get("policy_version") or 0))).fetchone()
        out["version"] = dict(ver) if ver else None
        return ok(self, out)

    def _ack_admin_identity(self, session: dict, rid: int):
        """Administrators only: correct the identity fields captured with an
        acknowledgment (e.g. a directory typo). The acknowledgment itself --
        statements, signature, version, time -- is never editable. Old -> new
        is written to the audit log against ACK-<id>."""
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        row = db().execute("SELECT * FROM acknowledgments WHERE id=?", (rid,)).fetchone()
        if not row:
            return err(self, 404, "No such acknowledgment")
        body = parse_body(self)
        if not isinstance(body, dict):
            return err(self, 400, "Body must be a JSON object")
        reason = str(body.get("reason") or "").strip()[:500]
        if not reason:
            return err(self, 400, "A reason is required for an identity correction")
        old = dict(row); changes, sets, vals = [], [], []
        for f in self.ACK_IDENTITY_FIELDS:
            if f not in body: continue
            new = str(body.get(f) or "").strip()[:200]
            if f == "manager_email" and new and not EMAIL_RE.match(new):
                return err(self, 400, "manager_email must be a valid address")
            if new != (old.get(f) or ""):
                changes.append({"field": f, "old": old.get(f) or "", "new": new}); sets.append(f"{f}=?"); vals.append(new)
        if not changes:
            return ok(self, {"changed": 0})
        with write_lock:
            db().execute(f"UPDATE acknowledgments SET {', '.join(sets)} WHERE id=?", (*vals, rid))
            db().commit()
        audit(f"ACK-{rid}", "acknowledgment.identity_corrected", (session or {}).get("email") or "admin",
              (session or {}).get("role") or "", json.dumps({"reason": reason, "changes": changes}))
        return ok(self, {"changed": len(changes), "changes": changes})

    # ── AI INVENTORY (InfoSec / Legal / admin) ──────────────────────────────
    def _inv_gate(self, session):
        if not inventory_allowed(session):
            err(self, 403, "The AI inventory is available to InfoSec, Legal and administrators"); return False
        return True

    def _inv_list(self, session: dict, qs: dict):
        if not self._inv_gate(session): return
        arch = ((qs.get("archived") or [""])[0] or "").lower()
        where = "" if arch == "all" else ("WHERE COALESCE(archived_at,'')<>''" if arch in ("1", "true") else "WHERE COALESCE(archived_at,'')=''")
        rows = [inv_row_public(r) for r in db().execute(f"SELECT * FROM ai_inventory {where} ORDER BY id DESC").fetchall()]
        act = [r for r in rows if not r["archived_at"]]
        D = lambda r, k: (r["data"].get(k) or "")
        summary = {
            "total": len(act), "archived": db().execute("SELECT COUNT(*) FROM ai_inventory WHERE COALESCE(archived_at,'')<>''").fetchone()[0],
            "by_status": {s: sum(1 for r in act if D(r, "status") == s) for s in INV_ALLOWED["status"]},
            "by_cat": {s: sum(1 for r in act if D(r, "cat") == s) for s in INV_ALLOWED["cat"]},
            "by_tier": {s: sum(1 for r in act if D(r, "tier") == s) for s in INV_ALLOWED["tier"]},
            "untiered": sum(1 for r in act if not D(r, "tier")),
            "flagged": sum(1 for r in act if r["flag"] == "Review for High"),
            "overdue": sum(1 for r in act if r["overdue"]),
            "needs_details": sum(1 for r in act if r["blank"] > 0),
            "no_intake": sum(1 for r in act if D(r, "intake") != "Yes"),
            "risk": {"npi": sum(1 for r in act if D(r, "npi") == "Yes"), "client": sum(1 for r in act if D(r, "client") == "Yes"),
                     "consumer": sum(1 for r in act if D(r, "consumer") == "Yes"), "ext": sum(1 for r in act if D(r, "ext") == "Yes"),
                     "agentic": sum(1 for r in act if D(r, "agentic") == "Yes"), "automated": sum(1 for r in act if D(r, "oversight") == "Fully automated"),
                     "public": sum(1 for r in act if D(r, "instance") == "Public / consumer"), "third": sum(1 for r in act if D(r, "third") == "Yes"),
                     "training_gap": sum(1 for r in act if D(r, "training") in ("Unknown", "Not prohibited"))},
            "controls": {"no_sso": sum(1 for r in act if D(r, "sso") in ("No", "Partial")), "siem_gap": sum(1 for r in act if D(r, "siem") in ("No", "Partial", "Unknown")),
                         "capprov": sum(1 for r in act if D(r, "capprov") == "Yes")},
            "as_of": now_iso()[:10],
        }
        return ok(self, {"rows": rows, "summary": summary, "fields": [{"key": f[0], "label": f[1], "required": bool(f[2]), "allowed": f[3], "section": f[4], "kind": f[5]} for f in INV_FIELDS]})

    def _inv_get(self, session: dict, iid: int):
        if not self._inv_gate(session): return
        row = db().execute("SELECT * FROM ai_inventory WHERE id=?", (iid,)).fetchone()
        if not row: return err(self, 404, "No such inventory record")
        out = inv_row_public(row)
        out["audit"] = [dict(x) for x in db().execute("SELECT event, actor, role, note, created_at FROM audit_log WHERE request_id=? ORDER BY created_at", (out["inv_id"],)).fetchall()]
        if out["request_id"]:
            rq = db().execute("SELECT id, status, created_at, submitter FROM requests WHERE id=?", (out["request_id"],)).fetchone()
            out["request"] = {"id": rq["id"], "status": rq["status"], "created_at": rq["created_at"]} if rq else None
        return ok(self, out)

    def _inv_write(self, session: dict, iid):
        """POST (create) or PATCH (edit). Body {data:{key:value}, reason?}. Every changed field is audited with old -> new."""
        if not self._inv_gate(session): return
        body = parse_body(self)
        if not isinstance(body, dict): return err(self, 400, "Body must be a JSON object")
        incoming = body.get("data") if isinstance(body.get("data"), dict) else {}
        incoming = {k: str(incoming.get(k) if incoming.get(k) is not None else "").strip()[:4000] for k in INV_KEYS if k in incoming}
        probs = inv_validate(incoming)
        if probs: return err(self, 400, "; ".join(probs[:4]))
        actor = (session or {}).get("email") or "approver"; role = (session or {}).get("role") or ""; now = now_iso()
        with write_lock:
            if iid is None:
                if not incoming.get("name"): return err(self, 400, "Name of AI/ML use or system is required")
                inv_id = inv_next_id(db()); src = {k: "infosec" for k, v in incoming.items() if v}
                if incoming.get("tier") and not incoming.get("revdate"): incoming["revdate"] = now[:10]
                if incoming.get("tier") and not incoming.get("revby"): incoming["revby"] = actor
                db().execute("INSERT INTO ai_inventory(inv_id,request_id,data,sources,created_at,created_by,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?)",
                             (inv_id, str(body.get("request_id") or "")[:40], json.dumps(incoming), json.dumps(src), now, actor, now, actor)); db().commit()
                row = db().execute("SELECT * FROM ai_inventory WHERE inv_id=?", (inv_id,)).fetchone()
                audit(inv_id, "inventory.created", actor, role, f"entered by InfoSec / Legal · {sum(1 for v in incoming.values() if v)} fields")
                return ok(self, inv_row_public(row))
            row = db().execute("SELECT * FROM ai_inventory WHERE id=?", (iid,)).fetchone()
            if not row: return err(self, 404, "No such inventory record")
            d = json.loads(row["data"] or "{}"); s = json.loads(row["sources"] or "{}"); changes = []
            for k, v in incoming.items():
                old = str(d.get(k) or "")
                if v != old:
                    changes.append({"field": k, "old": old, "new": v}); d[k] = v
                    if v: s[k] = "infosec"
                    else: s.pop(k, None)
            if any(c["field"] == "tier" and c["new"] for c in changes):
                if "revdate" not in incoming or not incoming.get("revdate"): d["revdate"] = now[:10]; s["revdate"] = "infosec"
                if "revby" not in incoming or not incoming.get("revby"): d["revby"] = actor; s["revby"] = "infosec"
            if not changes: return ok(self, {"changed": 0, **inv_row_public(row)})
            db().execute("UPDATE ai_inventory SET data=?, sources=?, updated_at=?, updated_by=? WHERE id=?", (json.dumps(d), json.dumps(s), now, actor, iid)); db().commit()
            row = db().execute("SELECT * FROM ai_inventory WHERE id=?", (iid,)).fetchone()
        audit(row["inv_id"], "inventory.updated", actor, role, json.dumps({"reason": str(body.get("reason") or "")[:300], "changes": changes}))
        out = inv_row_public(row); out["changed"] = len(changes); return ok(self, out)

    def _inv_archive(self, session: dict, iid: int, undo: bool):
        if not self._inv_gate(session): return
        body = parse_body(self); reason = str((body or {}).get("reason") or "").strip()[:500]
        if not reason: return err(self, 400, "A reason is required")
        row = db().execute("SELECT * FROM ai_inventory WHERE id=?", (iid,)).fetchone()
        if not row: return err(self, 404, "No such inventory record")
        actor = (session or {}).get("email") or "approver"; now = now_iso()
        with write_lock:
            if undo: db().execute("UPDATE ai_inventory SET archived_at='', archived_by='', archived_reason='' WHERE id=?", (iid,))
            else: db().execute("UPDATE ai_inventory SET archived_at=?, archived_by=?, archived_reason=? WHERE id=?", (now, actor, reason, iid))
            db().commit()
        audit(row["inv_id"], "inventory.unarchived" if undo else "inventory.archived", actor, (session or {}).get("role") or "", reason)
        return ok(self, {"archived": not undo})

    def _inv_import(self, session: dict):
        """Raw .xlsx body (X-File-Name header), ?commit=1 to write. Matches rows on Department + Name;
        existing rows gain only their blank fields (intake values are never overwritten); new rows are created."""
        if not self._inv_gate(session): return
        name = os.path.basename((self.headers.get("X-File-Name") or "workbook.xlsx").strip().replace("\\", "/"))[:160]
        commit = ((parse_qs(urlparse(self.path).query).get("commit") or ["0"])[0] == "1")
        try: length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError: length = 0
        if length <= 0: return err(self, 400, "Empty upload")
        if length > 25 * 1024 * 1024: return err(self, 413, "File is larger than 25 MB")
        buf, remaining = io.BytesIO(), length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 16))
            if not chunk: break
            buf.write(chunk); remaining -= len(chunk)
        data = buf.getvalue()
        if len(data) != length or not data.startswith(b"PK\x03\x04"): return err(self, 400, "That file is not a valid .xlsx workbook")
        try: rows = _xlsx_rows(data, "Inventory")
        except Exception as e: return err(self, 400, f"Could not read the workbook: {e}")
        # header row = the one containing "Name of AI/ML use or system"
        hdr_i = next((i for i, r in enumerate(rows) if any("Name of AI/ML use" in c for c in r)), None)
        if hdr_i is None: return err(self, 400, "Inventory tab: header row with 'Name of AI/ML use or system' not found")
        header = rows[hdr_i]; col = {}
        label_to_key = {lab: key for lab, key in INV_SHEET_COLS}
        for i, h in enumerate(header):
            h2 = re.sub(r"\s*\*\s*$", "", h).strip()
            for lab, key in label_to_key.items():
                if h2 == lab or (h2 and lab.startswith(h2[:40])): col[key] = i; break
        existing = {}
        for r in db().execute("SELECT * FROM ai_inventory WHERE COALESCE(archived_at,'')=''").fetchall():
            d = json.loads(r["data"] or "{}"); existing[((d.get("dept") or "").strip().lower(), (d.get("name") or "").strip().lower())] = r
        results, to_create, to_update = [], [], []
        for n, r in enumerate(rows[hdr_i + 1:], start=hdr_i + 2):
            def g(k): i = col.get(k); return (r[i] if i is not None and i < len(r) else "").strip()
            if not any(g(k) for k in INV_KEYS): continue
            if g("name").upper() == "EXAMPLE" or (g("inv_id") or "").upper() == "EXAMPLE": results.append({"row": n, "name": g("name"), "result": "skipped", "why": "example row"}); continue
            d = {k: g(k) for k in INV_KEYS[:35]}
            for k in INV_REVIEW: d[k] = g(k)
            probs = []
            if not d.get("name"): probs.append("Name is required")
            if not d.get("dept"): probs.append("Department is required")
            probs += inv_validate(d)
            if probs: results.append({"row": n, "name": d.get("name") or "(blank)", "dept": d.get("dept"), "result": "rejected", "why": "; ".join(probs)}); continue
            key = (d["dept"].lower(), d["name"].lower()); ex = existing.get(key)
            if ex:
                ed = json.loads(ex["data"] or "{}"); fill = {k: v for k, v in d.items() if v and not str(ed.get(k) or "").strip()}
                to_update.append((ex, fill, n)); results.append({"row": n, "name": d["name"], "dept": d["dept"], "result": "update", "why": f"matches {ex['inv_id']} · fills {len(fill)} blank field(s)", "inv_id": ex["inv_id"]})
            else:
                to_create.append((d, n)); results.append({"row": n, "name": d["name"], "dept": d["dept"], "result": "create", "why": f"{sum(1 for k in INV_REQUIRED if not d.get(k))} required blank" + (" · auto-flag Review for High" if inv_calc(d)["flag"] != "-" else "")})
        summary = {"file": name, "rows": len(results), "create": len(to_create), "update": len(to_update), "rejected": sum(1 for x in results if x["result"] == "rejected"), "skipped": sum(1 for x in results if x["result"] == "skipped")}
        if not commit: return ok(self, {"preview": True, "summary": summary, "results": results})
        actor = (session or {}).get("email") or "approver"; role = (session or {}).get("role") or ""; now = now_iso(); created, updated = [], []
        with write_lock:
            for d, n in to_create:
                inv_id = inv_next_id(db()); src = {k: "import" for k, v in d.items() if v}
                db().execute("INSERT INTO ai_inventory(inv_id,request_id,data,sources,created_at,created_by,updated_at,updated_by,import_ref) VALUES(?,?,?,?,?,?,?,?,?)",
                             (inv_id, "", json.dumps(d), json.dumps(src), now, actor, now, actor, f"{name} row {n}")); db().commit()
                created.append(inv_id); audit(inv_id, "inventory.created", actor, role, f"imported from {name} row {n}")
            for ex, fill, n in to_update:
                if not fill: continue
                ed = json.loads(ex["data"] or "{}"); es = json.loads(ex["sources"] or "{}"); ed.update(fill)
                for k in fill: es[k] = "import"
                db().execute("UPDATE ai_inventory SET data=?, sources=?, updated_at=?, updated_by=? WHERE id=?", (json.dumps(ed), json.dumps(es), now, actor, ex["id"])); db().commit()
                updated.append(ex["inv_id"]); audit(ex["inv_id"], "inventory.updated", actor, role, json.dumps({"reason": f"import {name} row {n}", "changes": [{"field": k, "old": "", "new": v} for k, v in fill.items()]}))
        audit("", "inventory.import", actor, role, json.dumps({**summary, "created": created, "updated": updated}))
        for x in results:
            if x["result"] == "create" and created: x["inv_id"] = created.pop(0)
        return ok(self, {"preview": False, "summary": summary, "results": results})

    def _inv_export(self, session: dict, qs: dict):
        if not self._inv_gate(session): return
        fmt = ((qs.get("format") or ["xlsx"])[0]).lower()
        arch = ((qs.get("archived") or [""])[0] or "").lower()
        where = "" if arch == "all" else "WHERE COALESCE(archived_at,'')=''"
        rows = [inv_row_public(r) for r in db().execute(f"SELECT * FROM ai_inventory {where} ORDER BY id").fetchall()]
        headers = [lab for lab, _ in INV_SHEET_COLS]
        def val(r, key):
            if key == "inv_id": return r["inv_id"]
            if key in ("blank", "flag", "next"): return r[key]
            return r["data"].get(key, "")
        out_rows = [[val(r, key) for _, key in INV_SHEET_COLS] for r in rows]
        stamp = now_iso()[:10]
        audit("", "inventory.exported", (session or {}).get("email") or "approver", (session or {}).get("role") or "", f"{fmt} · {len(rows)} rows")
        if fmt == "csv":
            o = io.StringIO(); w = csv.writer(o); w.writerow(headers)
            for r in out_rows: w.writerow([_csv_safe(x) for x in r])
            b = o.getvalue().encode("utf-8-sig"); ctype = "text/csv; charset=utf-8"; fname = f"AI_ML_Use_Inventory_{stamp}.csv"
        else:
            b = _xlsx_bytes(headers, out_rows); ctype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"; fname = f"AI_ML_Use_Inventory_{stamp}.xlsx"
        self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(b))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)

    def _inv_coverage(self, session: dict):
        if not self._inv_gate(session): return
        return ok(self, INV_COVERAGE)
    # ── end AI INVENTORY handlers ───────────────────────────────────────────

    # ── ARCHIVE: flag, never delete ─────────────────────────────────────────
    # ── REOPEN (admin): send a completed request back to a workflow step ──
    def _reopen(self, req_id: str, session: dict):
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        rid = req_id.upper()
        if self.command == "GET":
            row = db().execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
            if not row:
                return err(self, 404, f"No request found with ID {rid}")
            wf = json.loads(row["workflow"])
            aps = {a["step"]: dict(a) for a in db().execute(
                "SELECT step,status,approver_name,decided_at FROM approvals WHERE request_id=?", (rid,))}
            return ok(self, {"id": rid, "status": row["status"], "archived": bool(row["archived_at"] or ""),
                             "steps": [{"idx": i, "key": k, "label": step_label(k),
                                        "status": (aps.get(i) or {}).get("status", "pending"),
                                        "approver": (aps.get(i) or {}).get("approver_name") or "",
                                        "decided_at": (aps.get(i) or {}).get("decided_at") or ""} for i, k in enumerate(wf)]})
        body   = parse_body(self)
        step   = str(body.get("step") or "").strip().lower()
        reason = str(body.get("reason") or "").strip()
        if not reason:
            return err(self, 400, "A reason is required to reopen a request")
        with write_lock:
            row = db().execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
            if not row:
                return err(self, 404, f"No request found with ID {rid}")
            if row["archived_at"]:
                return err(self, 409, f"Request {rid} is archived — un-archive it before reopening")
            if row["status"] not in ("approved", "rejected", "returned"):
                return err(self, 409, f"Request {rid} is {row['status']} — only completed requests can be reopened")
            wf = json.loads(row["workflow"])
            if step not in wf:
                return err(self, 400, f"Step must be one of: {', '.join(wf)}")
            idx = wf.index(step)
            ts  = now_iso()
            db().execute("""UPDATE approvals SET status='pending',approver_name='',approver_role='',
                            comments='',signature='',decided_at=NULL WHERE request_id=? AND step>=?""", (rid, idx))
            db().execute("UPDATE requests SET status='pending',current_step=?,updated_at=? WHERE id=?", (idx, ts, rid))
            db().commit()
            actor = session.get("name") or session.get("email") or "Admin"
            audit(rid, f"Reopened to {step_label(step)}", actor, session.get("role") or "admin",
                  f"{reason} [{session.get('email') or ''}] previous status: {row['status']}")
            req = _build_request_dict(db().execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone())
        try:
            notify_reopened(req, idx, reason, actor)
        except Exception as e:  # noqa
            print("[reopen] notify skipped:", e, file=sys.stderr)
        ok(self, req)

    # ── AI-GOV SYNC: Portal → CorpIT AI Governance one-way feed ──────────
    def _sync_token(self, session: dict, method: str):
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        actor = session.get("email") or "admin"
        meta  = get_setting("sync.aia.token_meta", None) or {}
        if method == "GET":
            return ok(self, {"configured": bool(get_setting("sync.aia.token_sha256", None)),
                             "created_at": meta.get("created_at"), "created_by": meta.get("created_by"),
                             "last_used": get_setting("sync.aia.last_used", None),
                             "endpoint": "/api/portal/sync/aia", "header": "X-Portal-Service-Token"})
        if method == "DELETE":
            set_setting("sync.aia.token_sha256", None)
            set_setting("sync.aia.token_meta", {"revoked_at": now_iso(), "revoked_by": actor})
            audit("", "sync.token.revoked", actor, "admin", "AI Governance sync token revoked")
            return ok(self, {"configured": False})
        token = secrets.token_urlsafe(36)
        set_setting("sync.aia.token_sha256", hashlib.sha256(token.encode("utf-8")).hexdigest())
        set_setting("sync.aia.token_meta", {"created_at": now_iso(), "created_by": actor})
        audit("", "sync.token.issued", actor, "admin", "AI Governance sync token issued (shown once)")
        return ok(self, {"configured": True, "token": token, "created_at": now_iso(),
                         "note": "Shown once. Store it in the CorpIT worker configuration; re-issue to rotate."})

    def _reminders_settings(self, session: dict, method: str):
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        if method == "GET":
            return ok(self, {"settings": reminder_settings(), "last_run": get_setting("reminders.last_run", "") or None,
                             "helpdesk": get_smtp().get("helpdesk", "")})
        body = parse_body(self); cur = reminder_settings(); new = dict(cur)
        if "enabled" in body: new["enabled"] = bool(body["enabled"])
        for k, lo, hi in (("first_days", 1, 60), ("every_days", 1, 60), ("max", 1, 20), ("escalate_after", 1, 20), ("hour", 0, 23)):
            if k in body:
                try: v = int(body[k])
                except (TypeError, ValueError): return err(self, 400, f"{k} must be a whole number")
                if not (lo <= v <= hi): return err(self, 400, f"{k} must be between {lo} and {hi}")
                new[k] = v
        set_setting("reminders.settings", new)
        audit("", "reminders.settings", session.get("email") or "admin", "admin", json.dumps({"from": cur, "to": new}))
        return ok(self, {"settings": new})

    def _reminders_run(self, session: dict, qs: dict):
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        dry = (qs.get("dry", ["0"])[0] or "0") not in ("0", "false", "")
        res = reminders_run(dry)
        audit("", "reminders.manual_run", session.get("email") or "admin", "admin", f"dry={dry} checked={res['checked']} due={res['due']} sent={res['sent']}")
        return ok(self, res)

    def _sync_token_ok(self) -> bool:
        want = get_setting("sync.aia.token_sha256", None)
        got  = (self.headers.get("X-Portal-Service-Token") or "").strip()
        return bool(want and got and hmac.compare_digest(hashlib.sha256(got.encode("utf-8")).hexdigest(), want))

    def _sync_summary_put(self):
        """CorpIT worker pushes the at-a-glance snapshot (status, attention rows, due-soon, recent)."""
        if not self._sync_token_ok():
            return err(self, 401, "Service token required")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > 262144:
            return err(self, 413, "Summary larger than 256 KiB")
        body = parse_body(self)
        if not isinstance(body, dict) or not body.get("as_of"):
            return err(self, 400, "as_of is required")
        def lst(key, cap):
            v = body.get(key) or []
            return [x for x in v if isinstance(x, dict)][:cap] if isinstance(v, list) else []
        snap = {
            "as_of": str(body.get("as_of"))[:40],
            "status": body.get("status") if isinstance(body.get("status"), dict) else {},
            "attention": lst("attention", 100), "due_soon": lst("due_soon", 50), "recent": lst("recent", 50),
            "received_at": now_iso(), "source": (self.headers.get("User-Agent") or "")[:120],
        }
        set_setting("sync.gov.summary", snap)
        audit("", "sync.summary.received", "CorpIT AI Governance", "service",
              f"as_of={snap['as_of']} attention={len(snap['attention'])} due_soon={len(snap['due_soon'])} recent={len(snap['recent'])}")
        return ok(self, {"received_at": snap["received_at"], "attention": len(snap["attention"])})

    def _sync_refresh_url(self, session: dict, method: str):
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        if method == "GET":
            return ok(self, {"refresh_url": get_setting("sync.gov.refresh_url", "") or ""})
        url = str((parse_body(self) or {}).get("refresh_url") or "").strip()
        if url and not re.match(r"^https?://(127\.0\.0\.1|localhost|[a-z0-9.-]+\.nrpi\.local)(:\d+)?/[^\s]*$", url, re.I):
            return err(self, 400, "refresh_url must be an http(s) URL on localhost or *.nrpi.local")
        set_setting("sync.gov.refresh_url", url)
        audit("", "sync.refresh_url", session.get("email") or "admin", "admin", f"refresh_url={'(cleared)' if not url else url}")
        return ok(self, {"refresh_url": url})

    def _sync_refresh(self, session: dict):
        """Refresh button: ask CorpIT to push a fresh snapshot now (if a hook is configured), then return it."""
        if not inventory_allowed(session):
            return err(self, 403, "InfoSec, Legal or administrator access required")
        last = get_setting("sync.gov.refresh_last", None) or {}
        try:
            if last.get("at") and (datetime.now(timezone.utc) - datetime.fromisoformat(last["at"])).total_seconds() < 30:
                return err(self, 429, "Refreshed less than 30 seconds ago — try again shortly")
        except Exception:
            pass
        url = get_setting("sync.gov.refresh_url", "") or ""
        before = (get_setting("sync.gov.summary", None) or {}).get("received_at")
        result = {"hook": bool(url), "pushed": False, "message": ""}
        if url:
            tok_meta = get_setting("sync.aia.token_meta", None) or {}
            try:
                req = urllib.request.Request(url, method="POST", data=b"{}",
                                             headers={"Content-Type": "application/json", "User-Agent": "AccessPortal-refresh/1",
                                                      "X-Portal-Service-Token-Issued": str(tok_meta.get("created_at") or "")})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    code = resp.getcode(); body = resp.read(4096).decode("utf-8", "replace")
                result["message"] = f"CorpIT answered {code}"
                after = (get_setting("sync.gov.summary", None) or {}).get("received_at")
                result["pushed"] = bool(after and after != before)
                if not result["pushed"]:
                    result["message"] += " — no new snapshot arrived yet; it may land in a moment"
            except urllib.error.HTTPError as e:
                result["message"] = f"CorpIT refused the refresh ({e.code})"
            except Exception as e:  # noqa
                result["message"] = f"CorpIT could not be reached ({type(e).__name__})"
        else:
            result["message"] = "No refresh hook configured — CorpIT pushes on its hourly schedule"
        set_setting("sync.gov.refresh_last", {"at": now_iso(), "by": session.get("email") or "", "pushed": result["pushed"]})
        audit("", "sync.refresh", session.get("email") or "", session.get("role") or "", f"hook={'yes' if url else 'no'} pushed={result['pushed']} {result['message']}")
        snap = get_setting("sync.gov.summary", None)
        return ok(self, {"refresh": result, "snapshot": snap, "now": now_iso()})

    def _sync_summary_get(self, session: dict):
        """Snapshot + this person's live Portal queue (AIA requests at a step they decide)."""
        if not inventory_allowed(session):
            return err(self, 403, "InfoSec, Legal or administrator access required")
        snap = get_setting("sync.gov.summary", None)
        acc  = effective_access(session)
        vis  = visible_request_ids(session)
        mine = []
        for r in db().execute("SELECT id,type,status,submitter,workflow,current_step,created_at,updated_at FROM requests WHERE type='aia' AND status='pending' AND COALESCE(archived_at,'')='' ORDER BY created_at"):
            if vis is not None and r["id"] not in vis:
                continue
            wf = json.loads(r["workflow"]); idx = r["current_step"]
            if idx >= len(wf):
                continue
            step = wf[idx]
            if not (acc.get("decide_all") or step in (acc.get("decide_steps") or [])):
                continue
            sub = json.loads(r["submitter"]) if isinstance(r["submitter"], str) else (r["submitter"] or {})
            reopened = bool(db().execute("SELECT 1 FROM audit_log WHERE request_id=? AND event LIKE 'Reopened to %' LIMIT 1", (r["id"],)).fetchone())
            mine.append({"id": r["id"], "name": sub.get("name"), "dept": sub.get("dept"), "step": step,
                         "step_label": step_label(step), "created_at": r["created_at"], "updated_at": r["updated_at"], "reopened": reopened,
                         "chain": [{"key": k, "label": step_label(k), "state": ("done" if i < idx else "current" if i == idx else "next")} for i, k in enumerate(wf)]})
        held = [k for k in STEP_LABELS if acc.get("decide_all") or k in (acc.get("decide_steps") or [])]
        return ok(self, {"snapshot": snap, "portal_queue": mine[:50], "held": held, "now": now_iso()})

    def _sync_aia(self, qs: dict):
        want = get_setting("sync.aia.token_sha256", None)
        got  = (self.headers.get("X-Portal-Service-Token") or "").strip()
        if not want or not got or not hmac.compare_digest(hashlib.sha256(got.encode("utf-8")).hexdigest(), want):
            return err(self, 401, "Service token required")
        since  = (qs.get("since", [""])[0] or "").strip()
        cursor = (qs.get("cursor", [""])[0] or "").strip().upper()
        try:
            limit = max(1, min(int(qs.get("limit", [200])[0]), 500))
        except ValueError:
            return err(self, 400, "limit must be an integer")
        if since:
            try:
                datetime.fromisoformat(since.replace("Z", "+00:00"))
            except ValueError:
                return err(self, 400, "since must be an ISO timestamp")
        rows = db().execute(
            """SELECT * FROM requests WHERE type='aia' AND updated_at >= ? AND id > ?
               ORDER BY id LIMIT ?""", (since or "", cursor, limit + 1)).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        out = []
        for r in rows:
            d = _build_request_dict(r)
            d["governance"] = {
                "approved": (r["status"] == "approved") and not (r["archived_at"] or ""),
                "archived": bool(r["archived_at"] or ""),
                "archived_at": r["archived_at"] or None, "archived_reason": r["archived_reason"] or None,
                "status": r["status"], "updated_at": r["updated_at"],
            }
            out.append(d)
        ts = now_iso()
        set_setting("sync.aia.last_used", {"at": ts, "count": len(out), "since": since or None,
                                            "ua": (self.headers.get("User-Agent") or "")[:120]})
        audit("", "sync.read", "CorpIT AI Governance", "service",
              f"aia feed: {len(out)} rows, since={since or '-'}, cursor={cursor or '-'}, more={more}")
        return ok(self, {"rows": out, "count": len(out), "next_cursor": (out[-1]["id"] if more and out else None),
                         "since": since or None, "generated_at": ts, "type": "aia",
                         "note": "approved = status approved and not archived; reopened requests return status pending"})

    def _archive_items(self, session: dict):
        """Archive / un-archive named records. Approvers: completed requests in their own scope.
        Administrators: any request (pending included), acknowledgments, and undo. Reason required; every row audited."""
        if not is_any_approver(session):
            return err(self, 403, "You are not an approver.")
        body = parse_body(self)
        if not isinstance(body, dict): return err(self, 400, "Body must be a JSON object")
        reason = str(body.get("reason") or "").strip()[:500]
        if not reason: return err(self, 400, "A reason is required (it is written to the audit trail)")
        undo = body.get("undo") is True
        req_ids = [str(x).strip().upper() for x in (body.get("requests") or []) if str(x).strip()][:500]
        ack_ids = [int(x) for x in (body.get("acknowledgments") or []) if str(x).strip().isdigit()][:500]
        is_admin = (session or {}).get("role") == "admin"
        if (undo or ack_ids) and not is_admin:
            return err(self, 403, "Administrator role required to un-archive or to archive acknowledgments")
        if not req_ids and not ack_ids: return err(self, 400, "Nothing selected")
        vis = visible_request_ids(session); actor = (session or {}).get("email") or "approver"; role = (session or {}).get("role") or ""
        now = now_iso(); done, skipped = [], []
        with write_lock:
            for rid in req_ids:
                row = db().execute("SELECT id, status, archived_at FROM requests WHERE id=?", (rid,)).fetchone()
                if not row: skipped.append({"id": rid, "why": "not found"}); continue
                if vis is not None and rid not in vis: skipped.append({"id": rid, "why": "not in your scope"}); continue
                if undo:
                    if not row["archived_at"]: skipped.append({"id": rid, "why": "not archived"}); continue
                    db().execute("UPDATE requests SET archived_at='', archived_by='', archived_reason='', archived_batch='' WHERE id=?", (rid,))
                    audit(rid, "request.unarchived", actor, role, reason); done.append(rid); continue
                if row["archived_at"]: skipped.append({"id": rid, "why": "already archived"}); continue
                if row["status"] == "pending" and not is_admin: skipped.append({"id": rid, "why": "still pending — administrators only"}); continue
                db().execute("UPDATE requests SET archived_at=?, archived_by=?, archived_reason=?, archived_batch='' WHERE id=?", (now, actor, reason, rid))
                audit(rid, "request.archived", actor, role, reason + (" · was pending" if row["status"] == "pending" else "")); done.append(rid)
            for aid in ack_ids:
                row = db().execute("SELECT id, archived_at FROM acknowledgments WHERE id=?", (aid,)).fetchone()
                if not row: skipped.append({"id": f"ACK-{aid}", "why": "not found"}); continue
                if undo:
                    if not row["archived_at"]: skipped.append({"id": f"ACK-{aid}", "why": "not archived"}); continue
                    db().execute("UPDATE acknowledgments SET archived_at='', archived_by='', archived_reason='', archived_batch='' WHERE id=?", (aid,))
                    audit(f"ACK-{aid}", "acknowledgment.unarchived", actor, role, reason); done.append(f"ACK-{aid}"); continue
                if row["archived_at"]: skipped.append({"id": f"ACK-{aid}", "why": "already archived"}); continue
                db().execute("UPDATE acknowledgments SET archived_at=?, archived_by=?, archived_reason=?, archived_batch='' WHERE id=?", (now, actor, reason, aid))
                audit(f"ACK-{aid}", "acknowledgment.archived", actor, role, reason); done.append(f"ACK-{aid}")
            db().commit()
        return ok(self, {"undo": undo, "done": done, "skipped": skipped, "count": len(done)})

    def _archive_sweep(self, session: dict):
        """Administrator: archive everything submitted before a date. preview=true returns counts only;
        executing requires confirm == 'ARCHIVE'. One batch id ties the rows together; one audit event summarises."""
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Administrator role required")
        body = parse_body(self)
        if not isinstance(body, dict): return err(self, 400, "Body must be a JSON object")
        before = str(body.get("before") or "").strip()[:10]
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", before): return err(self, 400, "before must be a date, YYYY-MM-DD")
        scope = str(body.get("scope") or "both").lower()
        if scope not in ("both", "requests", "acknowledgments"): return err(self, 400, "scope must be both | requests | acknowledgments")
        include_pending = body.get("include_pending") is not False
        preview = body.get("preview") is True
        reason = str(body.get("reason") or "").strip()[:500]
        reqs = [] if scope == "acknowledgments" else [dict(r) for r in db().execute(
            "SELECT id, status FROM requests WHERE substr(created_at,1,10)<? AND COALESCE(archived_at,'')=''" + ("" if include_pending else " AND status<>'pending'"), (before,)).fetchall()]
        acks = [] if scope == "requests" else [dict(r) for r in db().execute(
            "SELECT id FROM acknowledgments WHERE substr(created_at,1,10)<? AND COALESCE(archived_at,'')=''", (before,)).fetchall()]
        already = db().execute("SELECT (SELECT COUNT(*) FROM requests WHERE substr(created_at,1,10)<? AND COALESCE(archived_at,'')<>'') + (SELECT COUNT(*) FROM acknowledgments WHERE substr(created_at,1,10)<? AND COALESCE(archived_at,'')<>'')", (before, before)).fetchone()[0]
        by_status = {}
        for r in reqs: by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        summary = {"before": before, "scope": scope, "include_pending": include_pending, "requests": len(reqs), "by_status": by_status,
                   "acknowledgments": len(acks), "already_archived": already, "total": len(reqs) + len(acks)}
        if preview: return ok(self, {"preview": True, **summary})
        if not reason: return err(self, 400, "A reason is required (it is written to the audit trail)")
        if str(body.get("confirm") or "") != "ARCHIVE": return err(self, 400, "Type ARCHIVE to confirm")
        if not summary["total"]: return ok(self, {"preview": False, **summary, "batch": ""})
        now = now_iso(); actor = (session or {}).get("email") or "admin"; batch = f"sweep-{now[:19].replace(':', '').replace('-', '')}"
        with write_lock:
            for r in reqs:
                db().execute("UPDATE requests SET archived_at=?, archived_by=?, archived_reason=?, archived_batch=? WHERE id=?", (now, actor, reason, batch, r["id"]))
                audit(r["id"], "request.archived", actor, "admin", f"{reason} · {batch}" + (" · was pending" if r["status"] == "pending" else ""))
            for a in acks:
                db().execute("UPDATE acknowledgments SET archived_at=?, archived_by=?, archived_reason=?, archived_batch=? WHERE id=?", (now, actor, reason, batch, a["id"]))
                audit(f"ACK-{a['id']}", "acknowledgment.archived", actor, "admin", f"{reason} · {batch}")
            db().commit()
        audit("", "archive.sweep", actor, "admin", json.dumps({**summary, "reason": reason, "batch": batch}))
        return ok(self, {"preview": False, **summary, "batch": batch})

    def _archive_recent(self, session: dict):
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Administrator role required")
        q = "SELECT request_id, event, actor, note, created_at FROM audit_log WHERE event IN (%s) ORDER BY created_at DESC LIMIT 60" % ",".join("?" * len(ARCHIVE_EVENTS))
        rows = [dict(r) for r in db().execute(q, ARCHIVE_EVENTS).fetchall()]
        counts = {"requests": db().execute("SELECT COUNT(*) FROM requests WHERE COALESCE(archived_at,'')<>''").fetchone()[0],
                  "acknowledgments": db().execute("SELECT COUNT(*) FROM acknowledgments WHERE COALESCE(archived_at,'')<>''").fetchone()[0]}
        return ok(self, {"events": rows, "archived": counts})

    # ── ACK-REACK: ask people to acknowledge again ─────────────────────────
    def _reack_email(self, row: dict, cur, reason: str, actor: str, kind: str) -> bool:
        """One email: 'please complete the acknowledgement again'. kind = 'admin' (per-record request) | 'version' (new policy)."""
        try:
            label = ACK_LABELS.get(row.get("form") or "cla", "Claude Access – Artificial Intelligence Policy Acknowledgment")
            email = (row.get("email") or "").strip(); first = html.escape((row.get("name") or email).split(" ")[0].split("@")[0].title())
            link = f"{PORTAL_BASE_URL}/"; cur_v = int(cur["version"]) if cur else 0
            if kind == "admin":
                why = (f"An administrator has asked you to complete the <strong>{html.escape(label)}</strong> again."
                       + (f" Reason on record: <em>{html.escape(reason)}</em>." if reason else ""))
            else:
                why = (f"A new version of the Artificial Intelligence Policy has been published"
                       + (f" (version {cur_v}" + (f", effective {html.escape(cur.get('effective_date') or '')}" if cur and cur.get("effective_date") else "") + ")" if cur_v else "")
                       + f". Your previous acknowledgment was against an earlier version, so the <strong>{html.escape(label)}</strong> must be completed again.")
            body = (f"<p>Hello {first},</p><p>{why}</p>"
                    f"<p>It takes about five minutes: review the policy, confirm the provisions, and sign. Your earlier record is kept for audit. Your Claude access is not affected while you do this.</p>"
                    f"<p><a href=\"{link}\" style=\"display:inline-block;background:#3a7d2c;color:#ffffff;padding:11px 18px;border-radius:8px;font-weight:700;text-decoration:none\">Complete the {html.escape(label)} &rarr;</a></p>"
                    f"<p style=\"color:#6b7280;font-size:12.5px\">In the portal choose <em>AI Use Case Intake</em>, then the acknowledgement option on the right. Requested by {html.escape(actor)}.</p>")
            subject = f"Action required: complete the {label} again"
            try: body = _email_html_wrapper(email_art("aia"), "Please complete the acknowledgment again", body)
            except Exception: pass
            plain = (f"Please complete the {label} again in the portal ({link}). " + (f"Reason: {reason}. " if reason else "") + f"Requested by {actor}.")
            okm = send_email(email, subject, body, plain)
            if okm:
                with write_lock:
                    db().execute("UPDATE acknowledgments SET reack_notified_at=?, reack_notified_version=? WHERE id=?", (now_iso(), cur_v, row["id"])); db().commit()
            audit(f"ACK-{row['id']}", "notify.reack", "system", "", (f"sent -> {email}" if okm else f"FAILED -> {email} · {mail_last_error() or 'relay refused'}") + f" · {kind}")
            return bool(okm)
        except Exception as e:
            print(f"[ACK-REACK] email failed: {e}", file=sys.stderr); return False

    def _ack_request_reack(self, session: dict, rid: int):
        """Administrator: mark ONE person's current acknowledgment superseded so the full form is shown
        again on their next visit. Reason required; audited; the person is emailed unless notify=false."""
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        row = db().execute("SELECT * FROM acknowledgments WHERE id=?", (rid,)).fetchone()
        if not row: return err(self, 404, "No such acknowledgment")
        r = dict(row)
        latest = db().execute("SELECT id FROM acknowledgments WHERE form=? AND LOWER(email)=? ORDER BY id DESC LIMIT 1", (r["form"], (r["email"] or "").lower())).fetchone()
        if not latest or int(latest["id"]) != rid:
            return err(self, 409, "Only the person's most recent acknowledgment can be superseded")
        if r.get("superseded_at"):
            return err(self, 409, "A re-acknowledgment has already been requested for this record")
        body = parse_body(self)
        if not isinstance(body, dict): return err(self, 400, "Body must be a JSON object")
        reason = str(body.get("reason") or "").strip()[:500]
        if not reason: return err(self, 400, "A reason is required (it is written to the audit trail and shown to the person)")
        notify = body.get("notify") is not False
        now = now_iso(); actor = (session or {}).get("email") or "admin"
        with write_lock:
            db().execute("UPDATE acknowledgments SET superseded_at=?, superseded_by=?, superseded_reason=? WHERE id=?", (now, actor, reason, rid)); db().commit()
        audit(f"ACK-{rid}", "acknowledgment.reack_requested", actor, "admin", json.dumps({"reason": reason, "email": r["email"]}))
        sent = self._reack_email(r, current_policy_version(r["form"]), reason, actor, "admin") if notify else False
        return ok(self, {"superseded": True, "notified": sent})

    def _ack_notify_outdated(self, session: dict):
        """Administrator: one email to everyone whose LATEST acknowledgment is not on the current version
        (or was superseded). People already emailed for this version are skipped unless force=true."""
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        body = parse_body(self); body = body if isinstance(body, dict) else {}
        form = (body.get("form") or "cla").lower()
        if form not in ACK_FORMS: return err(self, 404, f"No acknowledgment form '{form}'")
        force = body.get("force") is True
        cur = current_policy_version(form); cur_v = int(cur["version"]) if cur else 0
        if not cur_v: return err(self, 409, "No policy version is published")
        rows = [dict(x) for x in db().execute("SELECT * FROM acknowledgments WHERE form=? AND COALESCE(archived_at,'')='' ORDER BY id DESC", (form,)).fetchall()]   # ARCHIVE
        latest, seen = [], set()
        for r in rows:
            k = (r.get("email") or "").lower()
            if k in seen: continue
            seen.add(k); latest.append(r)
        due = [r for r in latest if int(r.get("policy_version") or 0) != cur_v or r.get("superseded_at")]
        actor = (session or {}).get("email") or "admin"
        sent = failed = skipped = 0
        for r in due:
            if not force and int(r.get("reack_notified_version") or 0) == cur_v and r.get("reack_notified_at"):
                skipped += 1; continue
            if not EMAIL_RE.match(r.get("email") or ""): failed += 1; continue
            if self._reack_email(r, cur, "", actor, "version"): sent += 1
            else: failed += 1
        audit("", "acknowledgment.reack_broadcast", actor, "admin", json.dumps({"version": cur_v, "due": len(due), "sent": sent, "failed": failed, "skipped": skipped, "force": force}))
        return ok(self, {"version": cur_v, "due": len(due), "sent": sent, "failed": failed, "skipped": skipped})

    def _policy_versions_list(self, session: dict, qs: dict):
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        form = (qs.get("form") or ["cla"])[0]
        if form not in POLICY_FORMS:
            return err(self, 404, f"No policy document for form '{form}'")
        vers = [dict(r) for r in db().execute("SELECT * FROM policy_versions WHERE form=? ORDER BY version DESC", (form,)).fetchall()]
        counts = {int(r[0] or 0): int(r[1]) for r in db().execute(
            "SELECT policy_version, COUNT(*) FROM acknowledgments WHERE form=? GROUP BY policy_version", (form,)).fetchall()}
        for v in vers:
            v["acknowledged"] = counts.get(int(v["version"]), 0)
            v["current"] = not v.get("retired_at")
        return ok(self, {"form": form, "versions": vers})

    def _policy_version_retire(self, session: dict, vid: int):
        """Withdraw a version without deleting anything: the row, the file and every
        acknowledgment against it stay. A retired current version leaves the form with
        no current document until a new one is published."""
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        row = db().execute("SELECT * FROM policy_versions WHERE id=?", (vid,)).fetchone()
        if not row:
            return err(self, 404, "No such version")
        if row["retired_at"]:
            return ok(self, {"retired": False, "already": True})
        now = now_iso()
        with write_lock:
            db().execute("UPDATE policy_versions SET retired_at=? WHERE id=?", (now, vid))
            # if it was the published pointer, clear it so the page stops showing it
            meta = policy_doc_meta(row["form"])
            if meta and meta.get("sha") == row["sha"]:
                db().execute("DELETE FROM settings WHERE key=?", (f"policy.{row['form']}.doc",))
            db().commit()
        audit("", "policy.version_retired", (session or {}).get("email") or "admin", (session or {}).get("role") or "",
              f"{row['form']} v{row['version']} ({row['sha']}) retired")
        return ok(self, {"retired": True, "version": int(row["version"])})

    # ── ACK-NOTIFY / ACK-AUDIT (v5, 2026-09-24) ─────────────────────────────
    def _ack_notify(self, rid: int, form: str, rec: dict, cur, when: str, is_live: bool):
        """Employee confirmation (as before) + manager copy + admin/IT notice, each
        written to the record's audit trail with its result. Never fatal."""
        try:
            content = content_all()
            label   = ACK_LABELS.get(form, "policy acknowledgment")
            okm     = self._ack_confirmation(form, rec, cur, when, is_live)
            audit(f"ACK-{rid}", "notify.employee", "system", "",
                  (f"sent -> {rec.get('email','')}" if okm else f"FAILED -> {rec.get('email','')} · {mail_last_error() or 'relay refused'}"))
            if not is_live:
                audit(f"ACK-{rid}", "notify.manager", "system", "", "skipped · sample record"); audit(f"ACK-{rid}", "notify.admin", "system", "", "skipped · sample record"); return
            vtxt   = f"version {cur['version']}" if cur else "current version"
            when_s = (when or "")[:19].replace("T", " ") + " UTC"
            who    = f"{html.escape(rec.get('name') or '')} &lt;{html.escape(rec.get('email') or '')}&gt;"
            link   = f"{PORTAL_BASE_URL}/approver.html"
            # manager copy
            mgr = (rec.get("manager_email") or "").strip().lower()
            if (content.get("policy.cla.notify_manager") or "1").strip() != "0":
                if mgr and EMAIL_RE.match(mgr):
                    body = (f"<p>Hello,</p><p>{who} — a member of your team — completed the <strong>{html.escape(label)}</strong> ({html.escape(vtxt)}) on {html.escape(when_s)}.</p>"
                            f"<p>Record <strong>ACK-{rid}</strong>. Nothing is needed from you; this copy is for your records. "
                            f"You can open the record under <em>Team Acknowledgments</em> in the <a href=\"{link}\">Approver Portal</a>.</p>")
                    try: body = _email_html_wrapper(email_art("approved"), "Team member acknowledged the AI Policy", body)
                    except Exception: pass
                    okm = send_email(mgr, f"{label} \u2014 {rec.get('name') or rec.get('email')} completed", body,
                                     f"{rec.get('name') or ''} <{rec.get('email') or ''}> completed the {label} ({vtxt}) on {when_s}. Record ACK-{rid}.")
                    audit(f"ACK-{rid}", "notify.manager", "system", "", (f"sent -> {mgr}" if okm else f"FAILED -> {mgr} · {mail_last_error() or 'relay refused'}"))
                else:
                    audit(f"ACK-{rid}", "notify.manager", "system", "", "skipped · no manager address on record")
            else:
                audit(f"ACK-{rid}", "notify.manager", "system", "", "skipped · manager copy turned off")
            # admin / IT
            rcpts = ack_notify_recipients(content)
            mode  = (content.get("policy.cla.notify_mode") or "each").strip().lower()
            if not rcpts:
                audit(f"ACK-{rid}", "notify.admin", "system", "", "skipped · no recipients configured")
            elif mode == "daily":
                audit(f"ACK-{rid}", "notify.admin", "system", "", f"queued for daily summary -> {', '.join(rcpts)}")
            else:
                body = (f"<p><strong>Claude access to provision.</strong> {who} completed the <strong>{html.escape(label)}</strong> ({html.escape(vtxt)}) on {html.escape(when_s)}.</p>"
                        f"<p>Provision Claude for <strong>{html.escape(rec.get('email') or '')}</strong> within {html.escape(ack_provision_days())} business days; the employee has been told to expect it.</p>"
                        f"<table cellpadding=\"4\" style=\"font-size:13px\"><tr><td><b>Record</b></td><td>ACK-{rid}</td></tr>"
                        f"<tr><td><b>Worker type</b></td><td>{html.escape(rec.get('pay_class') or emp_class_text(rec))}</td></tr>"
                        f"<tr><td><b>Department</b></td><td>{html.escape(rec.get('dept') or '—')}</td></tr>"
                        f"<tr><td><b>Manager</b></td><td>{html.escape(mgr or '—')}</td></tr></table>"
                        f"<p><a href=\"{link}\">Open in the Approver Portal</a> → Administration → Claude Access Acknowledgments.</p>")
                try: body = _email_html_wrapper(email_art("approved"), "AI Policy acknowledgment recorded", body)
                except Exception: pass
                okm = send_email(rcpts, f"Claude access to provision \u2014 {rec.get('name') or rec.get('email')} \u00b7 ACK-{rid}", body,
                                 f"{rec.get('name') or ''} <{rec.get('email') or ''}> completed the {label} ({vtxt}) on {when_s}. Record ACK-{rid}.")
                audit(f"ACK-{rid}", "notify.admin", "system", "", (f"sent -> {', '.join(rcpts)}" if okm else f"FAILED -> {', '.join(rcpts)} · {mail_last_error() or 'relay refused'}"))
        except Exception as e:
            print(f"[ACK] notify failed: {e}", file=sys.stderr)
            try: audit(f"ACK-{rid}", "notify.error", "system", "", str(e)[:300])
            except Exception: pass

    def _ack_viewer(self, session: dict, row: dict) -> str:
        """'admin', 'manager' (the record names this session as manager) or ''."""
        if (session or {}).get("role") == "admin": return "admin"
        me = ((session or {}).get("email") or "").lower()
        if me and (row.get("manager_email") or "").lower() == me: return "manager"
        return ""

    def _ack_record(self, session: dict, rid: int, qs: dict):
        row = db().execute("SELECT * FROM acknowledgments WHERE id=?", (rid,)).fetchone()
        if not row:
            return err(self, 404, "No such acknowledgment")
        r = dict(row); viewer = self._ack_viewer(session, r)
        if not viewer:
            return err(self, 403, "Not your team's record")
        cur = current_policy_version(r["form"]); cur_v = int(cur["version"]) if cur else 0
        pub = self._ack_row_public(r, cur_v)
        pub["record_sha"] = r.get("record_sha", ""); pub["client_ip"] = r.get("client_ip", "") if viewer == "admin" else ""
        pub["user_agent"] = r.get("user_agent", "")
        ver = db().execute("SELECT * FROM policy_versions WHERE form=? AND version=?", (r["form"], int(r.get("policy_version") or 0))).fetchone()
        aud = [dict(x) for x in db().execute("SELECT event, actor, role, note, created_at FROM audit_log WHERE request_id=? ORDER BY created_at", (f"ACK-{rid}",)).fetchall()]
        if viewer != "admin":
            aud = [a for a in aud if a["event"] in ("acknowledgment.recorded",) or a["event"].startswith("notify.") or a["event"] == "acknowledgment.identity_corrected"]
            for a in aud:
                if a["event"] == "acknowledgment.identity_corrected": a["note"] = "identity fields corrected by an administrator"
        fmt = ((qs.get("format") or [""])[0]).lower()
        if fmt in ("docx", "pdf"):
            title, subtitle, sections, stamp = ack_record_model(pub, dict(ver) if ver else None, aud, viewer)
            audit(f"ACK-{rid}", "acknowledgment.exported", (session or {}).get("email") or "", viewer, f"{fmt} export")
            return self._send_record(fmt, title, subtitle, sections, stamp, f"ACK-{rid:06d}-record")
        if fmt == "json":
            return ok(self, {"record": pub, "version": dict(ver) if ver else None, "audit": aud, "generated_at": now_iso(), "generated_by": (session or {}).get("email", "")})
        page = ack_record_html(pub, dict(ver) if ver else None, aud, (session or {}).get("email", ""), viewer)
        b = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("Content-Disposition", f"inline; filename=\"ACK-{rid:06d}-{re.sub(r'[^A-Za-z0-9]+', '-', pub.get('name') or 'record').strip('-')}.html\"")
        self.end_headers(); self.wfile.write(b)

    def _ack_export_zip(self, session: dict, qs: dict):
        """Administrator audit pack: CSV index + one printable record per acknowledgment in the filter."""
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        import zipfile
        form = (qs.get("form") or ["cla"])[0]
        rows = self._ack_filtered_rows(form, qs, None)
        cur = current_policy_version(form); cur_v = int(cur["version"]) if cur else 0
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            cols = ["id", "record_id", "name", "email", "employee_id", "dept", "title", "manager_email", "employment_class", "employment_matched",
                    "status", "policy_version", "policy_sha", "ack_via", "signature_kind", "sample", "identity_source", "created_at", "record_sha", "client_ip"]
            out = io.StringIO(); w = csv.writer(out); w.writerow(cols)
            for r in rows:
                p = self._ack_row_public(r, cur_v); p["record_id"] = f"ACK-{r['id']}"; p["record_sha"] = r.get("record_sha", ""); p["client_ip"] = r.get("client_ip", "")
                w.writerow([p.get(c, "") for c in cols])
                ver = db().execute("SELECT * FROM policy_versions WHERE form=? AND version=?", (form, int(r.get("policy_version") or 0))).fetchone()
                aud = [dict(x) for x in db().execute("SELECT event, actor, role, note, created_at FROM audit_log WHERE request_id=? ORDER BY created_at", (f"ACK-{r['id']}",)).fetchall()]
                p["user_agent"] = r.get("user_agent", "")
                z.writestr(f"records/ACK-{r['id']:06d}.html", ack_record_html(p, dict(ver) if ver else None, aud, (session or {}).get("email", ""), "admin"))
            z.writestr("index.csv", out.getvalue())
            z.writestr("README.txt", f"Claude Access – Artificial Intelligence Policy Acknowledgment audit pack\nGenerated {now_iso()} by {(session or {}).get('email','')}\n{len(rows)} record(s); filters {json.dumps({k: v[0] for k, v in qs.items()})}\nindex.csv lists every record; records/ holds one printable audit record each (open in a browser, Save as PDF).\nrecord_sha = SHA-256 over id|form|email|policy_version|policy_sha|statement_sha|signature|created_at.\n")
        b = buf.getvalue()
        audit("", "acknowledgments.exported", (session or {}).get("email") or "admin", "admin", f"{form}: {len(rows)} record(s), filters {json.dumps({k: v[0] for k, v in qs.items()})}")
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Content-Disposition", f"attachment; filename=\"ai-policy-acknowledgments-{now_iso()[:10]}.zip\"")
        self.send_header("Cache-Control", "no-store, private")
        self.end_headers(); self.wfile.write(b)

    def _ack_filtered_rows(self, form: str, qs: dict, manager_email):
        """Rows for the list/export, newest first, with the shared filters applied.
        manager_email set = team scope (server-enforced)."""
        sql = "SELECT * FROM acknowledgments WHERE form=?"; args = [form]
        _ac = _archived_clause(qs)                # ARCHIVE: active only unless ?archived=1|all
        if _ac: sql += " AND " + _ac
        if manager_email is not None:
            sql += " AND LOWER(manager_email)=?"; args.append(manager_email.lower())
        v = ((qs.get("version") or [""])[0] or "").strip()
        if v.isdigit(): sql += " AND policy_version=?"; args.append(int(v))
        m = ((qs.get("manager") or [""])[0] or "").strip().lower()
        if m: sql += " AND LOWER(manager_email) LIKE ?"; args.append(f"%{m}%")
        d1 = ((qs.get("from") or [""])[0] or "").strip()[:10]; d2 = ((qs.get("to") or [""])[0] or "").strip()[:10]
        if re.match(r"^\d{4}-\d{2}-\d{2}$", d1): sql += " AND substr(created_at,1,10)>=?"; args.append(d1)
        if re.match(r"^\d{4}-\d{2}-\d{2}$", d2): sql += " AND substr(created_at,1,10)<=?"; args.append(d2)
        sql += " ORDER BY created_at DESC, id DESC"
        return [dict(r) for r in db().execute(sql, args).fetchall()]

    # ── ACK-ELIG admin API ──────────────────────────────────────────────────
    def _elig_list(self, session: dict, qs: dict):
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        form = (qs.get("form") or ["cla"])[0]
        rows = [dict(r) for r in db().execute("SELECT * FROM ack_eligibility WHERE form=? AND removed_at='' ORDER BY added_at DESC, id DESC", (form,)).fetchall()]
        cur = current_policy_version(form); cur_v = int(cur["version"]) if cur else 0
        for r in rows:
            emp = employment_class(r["email"]); r["hr_class"] = emp.get("pay_class", ""); r["hr_matched"] = emp.get("matched")
            last = db().execute("SELECT policy_version, created_at FROM acknowledgments WHERE form=? AND LOWER(email)=? ORDER BY id DESC LIMIT 1", (form, r["email"].lower())).fetchone()
            r["ack_status"] = ("completed" if last and int(last["policy_version"] or 0) == cur_v else ("requires_reack" if last else "pending"))
            r["ack_at"] = last["created_at"] if last else ""
        hist = [dict(r) for r in db().execute("SELECT * FROM ack_eligibility WHERE form=? AND removed_at<>'' ORDER BY removed_at DESC LIMIT 50", (form,)).fetchall()]
        return ok(self, {"form": form, "rows": rows, "removed": hist})

    def _elig_add(self, session: dict):
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        body = parse_body(self)
        if not isinstance(body, dict): return err(self, 400, "Body must be a JSON object")
        form = (body.get("form") or "cla").lower()
        if form not in ACK_FORMS: return err(self, 404, f"No acknowledgment form '{form}'")
        email = str(body.get("email") or "").strip().lower(); mode = str(body.get("mode") or "allow").strip().lower()
        reason = str(body.get("reason") or "").strip()[:500]; name = str(body.get("name") or "").strip()[:160]
        notify = body.get("notify") is not False
        if not EMAIL_RE.match(email): return err(self, 400, "Enter a valid corporate email address")
        if mode not in ("allow", "block"): return err(self, 400, "mode must be allow or block")
        if not reason: return err(self, 400, "A reason is required (it is written to the audit trail)")
        existing = ack_eligibility_rows(email, form)
        if any(r["mode"] == mode for r in existing): return err(self, 409, f"{email} already has an active {mode} entry")
        now = now_iso(); actor = (session or {}).get("email") or "admin"
        with write_lock:
            # an allow replaces an active block and vice versa -- one active entry per person
            db().execute("UPDATE ack_eligibility SET removed_at=?, removed_by=? WHERE form=? AND LOWER(email)=? AND removed_at=''", (now, actor, form, email))
            cur = db().execute("INSERT INTO ack_eligibility(form,email,name,mode,reason,added_by,added_at) VALUES(?,?,?,?,?,?,?)", (form, email, name, mode, reason, actor, now))
            rid = cur.lastrowid; db().commit()
        audit("", "acknowledgment.eligibility_added", actor, "admin", json.dumps({"id": rid, "email": email, "mode": mode, "reason": reason}))
        sent = False
        if mode == "allow" and notify:
            sent = self._elig_notify(rid, email, name, reason, actor)
        row = dict(db().execute("SELECT * FROM ack_eligibility WHERE id=?", (rid,)).fetchone())
        return ok(self, {"row": row, "notified": sent})

    def _elig_notify(self, rid: int, email: str, name: str, reason: str, actor: str) -> bool:
        try:
            label = ACK_LABELS.get("cla", "Claude Access – Artificial Intelligence Policy Acknowledgment")
            first = html.escape((name or email).split(" ")[0].split("@")[0].title())
            link = f"{PORTAL_BASE_URL}/"
            body = (f"<p>Hello {first},</p>"
                    f"<p>You have been approved to use Claude for individual productivity. To obtain access, complete the <strong>{html.escape(label)}</strong> in the portal "
                    f"&mdash; it takes about five minutes: review the AI Policy, confirm the key requirements, and sign. No approval chain is involved.</p>"
                    f"<p><a href=\"{link}\" style=\"display:inline-block;background:#3a7d2c;color:#ffffff;padding:11px 18px;border-radius:8px;font-weight:700;text-decoration:none\">Complete the Claude Access &ndash; Artificial Intelligence Policy Acknowledgment &rarr;</a></p>"
                    f"<p style=\"color:#6b7280;font-size:12.5px\">In the portal choose <em>AI Use Case Intake</em>, then the acknowledgement option on the right. "
                    f"Approved by {html.escape(actor)} &middot; reason on record: {html.escape(reason)}</p>")
            try: body = _email_html_wrapper(email_art("aia"), "You can now complete the Claude Access – Artificial Intelligence Policy Acknowledgment", body)
            except Exception: pass
            okm = send_email(email, "You can now complete the Claude Access – Artificial Intelligence Policy Acknowledgment", body,
                             f"You have been approved to use Claude. Complete the {label} in the portal ({link}) to obtain access. Approved by {actor}; reason: {reason}.")
            if okm:
                db().execute("UPDATE ack_eligibility SET notified_at=? WHERE id=?", (now_iso(), rid)); db().commit()
            audit("", "acknowledgment.eligibility_notified", "system", "", (f"sent -> {email}" if okm else f"FAILED -> {email} · {mail_last_error() or 'relay refused'}"))
            return bool(okm)
        except Exception as e:
            print(f"[ACK-ELIG] notify failed: {e}", file=sys.stderr); return False

    def _elig_remove(self, session: dict, rid: int):
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        row = db().execute("SELECT * FROM ack_eligibility WHERE id=? AND removed_at=''", (rid,)).fetchone()
        if not row: return err(self, 404, "No such active entry")
        now = now_iso(); actor = (session or {}).get("email") or "admin"
        with write_lock:
            db().execute("UPDATE ack_eligibility SET removed_at=?, removed_by=? WHERE id=?", (now, actor, rid)); db().commit()
        audit("", "acknowledgment.eligibility_removed", actor, "admin", json.dumps({"id": rid, "email": row["email"], "mode": row["mode"]}))
        return ok(self, {"removed": True})

    def _elig_resend(self, session: dict, rid: int):
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        row = db().execute("SELECT * FROM ack_eligibility WHERE id=? AND removed_at='' AND mode='allow'", (rid,)).fetchone()
        if not row: return err(self, 404, "No such active allow entry")
        return ok(self, {"notified": self._elig_notify(rid, row["email"], row["name"], row["reason"], (session or {}).get("email") or "admin")})

    def _ack_state(self, form: str, email: str) -> dict:
        """Everything the page needs to decide what to show: the current
        version, this person's latest acknowledgement, and whether that
        acknowledgement is still against the version now published."""
        cur = current_policy_version(form)
        row = db().execute(
            "SELECT * FROM acknowledgments WHERE form=? AND LOWER(email)=? AND COALESCE(archived_at,'')='' ORDER BY id DESC LIMIT 1",   # ARCHIVE: an archived (test) record counts as never signed
            (form, email)).fetchone()
        last = dict(row) if row else None
        cur_v = int(cur["version"]) if cur else 0
        # The acknowledgement page shows the person their own worker type,
        # because the obligation is scoped by it. /identity/whoami deliberately
        # withholds the pay class -- the intake path only needs the fte flag --
        # but this endpoint exists for one page that has to print the value, and
        # it is the caller's own HR record. Never anybody else's.
        emp = employment_class(email)
        return {
            "form": form,
            "worker_type": emp.get("pay_class", ""),
            "worker_type_known": emp.get("matched") is True,
            "acknowledged": bool(last),
            "current_version": cur_v,
            "current_effective": (cur or {}).get("effective_date", ""),
            "provision_days": ack_provision_days(),
            # True only when they HAVE acknowledged and the document has moved
            # on since. Never true for somebody who has not acknowledged at all
            # -- that is "not done", not "out of date".
            "needs_reacknowledgement": bool(last and ((cur_v and int(last.get("policy_version") or 0) != cur_v) or last.get("superseded_at"))),
            # ACK-REACK: an administrator asked for a fresh acknowledgement (reason shown to the person)
            "reack_requested": bool(last and last.get("superseded_at")),
            "reack_reason": (last.get("superseded_reason", "") if last else ""),
            "record": None if not last else {
                "acknowledged_at": last.get("created_at", ""),
                "policy_version":  int(last.get("policy_version") or 0),
                "policy_url":      last.get("policy_url", ""),
                "sample":          bool(last.get("sample")),
                # ACK-LOCKED (2026-09-24): the caller's own record, so the completed page can show
                # exactly what was signed, read-only. Never another person's row.
                "id":              last.get("id"),
                "record_id":       f"ACK-{int(last.get('id') or 0):06d}",
                "name":            last.get("name", ""), "dept": last.get("dept", ""), "title": last.get("title", ""),
                "manager_email":   last.get("manager_email", ""), "employee_id": last.get("employee_id", ""),
                "employment_class": last.get("employment_class", ""),
                "statements":      (json.loads(last["statements_json"]) if last.get("statements_json") else []),
                "signature_kind":  (last.get("signature") or "").split(":", 1)[0],
                "signature_text":  (last.get("signature") or "")[6:] if (last.get("signature") or "").startswith("typed:") else "",
                "signature_image": (last.get("signature") or "")[7:] if (last.get("signature") or "").startswith("canvas:") else "",
                "ack_via":         last.get("ack_via", ""),
                "policy_file":     (lambda v: (v["file_name"] if v else ""))(db().execute("SELECT file_name FROM policy_versions WHERE form=? AND version=?", (form, int(last.get("policy_version") or 0))).fetchone()),
                "policy_effective": (lambda v: (v["effective_date"] if v else ""))(db().execute("SELECT effective_date FROM policy_versions WHERE form=? AND version=?", (form, int(last.get("policy_version") or 0))).fetchone()),
                "record_sha":      last.get("record_sha", ""),
            },
        }

    def _ack_me(self, qs):
        rec = self._ack_identity()
        if not rec:
            return err(self, 403, "This page needs your corporate sign-in.")
        form = (qs.get("form", ["cla"])[0] or "cla").lower().strip()
        if form not in ACK_FORMS:
            return err(self, 404, f"No acknowledgement is recorded for '{form}'")
        state = self._ack_state(form, (rec.get("email") or "").lower())
        ok(self, state, )

    def _ack_submit(self):
        rec = self._ack_identity()
        if not rec:
            return err(self, 403, "This page needs your corporate sign-in.")
        body = parse_body(self)
        form = (body.get("form") or "").lower().strip()
        if form not in ACK_FORMS:
            return err(self, 404, f"No acknowledgement is recorded for '{form}'")
        if body.get("agree") is not True:
            return err(self, 400, "Tick the box to acknowledge the policy.")

        # The statements the page actually put on screen, in order. Stored
        # verbatim: an audit record that only says "they agreed" cannot say
        # WHAT they agreed to once the wording is edited.
        raw_stmts = body.get("statements")
        statements = []
        if isinstance(raw_stmts, list):
            statements = [str(s)[:1000] for s in raw_stmts[:20] if str(s).strip()]

        # typed:<name> or canvas:<data-url>, the same shape the request forms
        # use, so one reader understands both.
        signature = str(body.get("signature") or "")[:200000]
        if signature and not signature.startswith(("typed:", "canvas:")):
            return err(self, 400, "That signature was not in a form this portal accepts.")
        if statements and not signature:
            return err(self, 400, "Sign the acknowledgement before submitting it.")

        # How they got to the end of the document, as the viewer observed it.
        ack_via = str(body.get("ack_via") or "")[:20]
        if ack_via not in ("scroll", "download", "open", "visible"):
            ack_via = ""

        email   = (rec.get("email") or "").lower()
        content = content_all()
        cur     = current_policy_version(form)
        cur_v   = int(cur["version"]) if cur else 0

        # Already on record against the version now published: say so instead of
        # writing a second row. Re-acknowledging a NEW version does add one.
        existing = db().execute(
            "SELECT * FROM acknowledgments WHERE form=? AND LOWER(email)=? AND policy_version=?"
            " ORDER BY id DESC LIMIT 1", (form, email, cur_v)).fetchone()
        jvisit, jdata = journey_stamp(body.get("journey"))
        if existing:
            journey_server("ack", jvisit, email, "entra", form=form, already=True, **jdata)
            state = self._ack_state(form, email)
            state["already"] = True
            return ok(self, state)

        statement  = "\n".join(statements) if statements else (content.get(f"policy.{form}.ack") or "")
        stmt_sha   = hashlib.sha256(statement.encode("utf-8")).hexdigest()[:16]
        is_live    = (content.get(f"policy.{form}.live") or "").strip() == "1"
        emp        = employment_class(email)
        # ACK-ELIG: the same rule the chooser used -- an ineligible person cannot post by URL.
        elig       = ack_eligibility_for(email, emp)
        if not elig["eligible"]:
            journey_server("ack_refused", jvisit, email, "entra", form=form, blocked=elig["blocked"],
                           emp=emp.get("source", ""), **jdata)
            audit("", "acknowledgment.refused", email, "", f"{form}: not eligible ({'blocked' if elig['blocked'] else 'no HR/FTE status and no administrator grant'})")
            return err(self, 403, "The Claude Access – Artificial Intelligence Policy Acknowledgment is not available for your account. Contact the IT Service Desk if you believe it should be.")
        matched    = emp.get("matched")
        matched_s  = "true" if matched is True else ("false" if matched is False else "unknown")
        now        = now_iso()

        client_ip = (self.headers.get("X-Real-IP") or self.client_address[0] or "")[:64]
        with write_lock:
            _cur = db().execute(
                "INSERT INTO acknowledgments (form,email,name,dept,title,manager_email,"
                " policy_version_id,policy_version,policy_sha,policy_url,statement_sha,ack_via,"
                " employment_class,employment_matched,employment_source,identity_source,"
                " employee_id,statements_json,signature,sample,"
                " user_agent,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (form, email, rec.get("name", ""), rec.get("dept", ""), rec.get("title", ""),
                 rec.get("manager_email", ""),
                 (cur or {}).get("id"), cur_v, (cur or {}).get("sha", ""), (cur or {}).get("url", ""),
                 stmt_sha, ack_via,
                 emp.get("pay_class", ""), matched_s, emp.get("source", ""),
                 rec.get("source", ""),
                 rec.get("employee_id", ""), json.dumps(statements) if statements else "", signature,
                 0 if is_live else 1,
                 (self.headers.get("User-Agent") or "")[:300], now))
            rid = _cur.lastrowid
            # ACK-AUDIT: fingerprint the immutable part of the record so an exported copy
            # can be checked against the database later.
            rsha = ack_record_sha({"id": rid, "form": form, "email": email, "policy_version": cur_v,
                                   "policy_sha": (cur or {}).get("sha", ""), "statement_sha": stmt_sha,
                                   "signature": signature, "created_at": now})
            db().execute("UPDATE acknowledgments SET record_sha=?, client_ip=?, eligibility_source=? WHERE id=?", (rsha, client_ip, elig["source"], rid))
            db().commit()

        audit("", "policy.acknowledged", email, "",
              f"{form} v{cur_v or '-'} acknowledged"
              f"{' via ' + ack_via if ack_via else ''}"
              f" (class {emp.get('pay_class') or 'unknown'}/{matched_s})"
              f"{' [SAMPLE]' if not is_live else ''}")
        audit(f"ACK-{rid}", "acknowledgment.recorded", email, "",
              f"v{cur_v or '-'} · {'typed' if signature.startswith('typed:') else ('drawn' if signature.startswith('canvas:') else 'no')} signature"
              f" · {ack_via or 'unknown'} · {len(statements)} statement(s) · ip {client_ip or '?'} · sha {rsha[:16]}")

        journey_server("ack", jvisit, email, "entra", form=form, id=rid, already=False,
                       src=elig["source"], emp=emp.get("source", ""), sample=not is_live, **jdata)
        self._ack_notify(rid, form, rec, cur, now, is_live)

        state = self._ack_state(form, email)
        state["already"] = False
        ok(self, state)

    def _ack_confirmation(self, form: str, rec: dict, cur, when: str, is_live: bool):
        """One email, to the person who acknowledged. Never fatal: the record is
        already written, and failing the request because mail is down would tell
        them it did not save when it did."""
        try:
            label  = ACK_LABELS.get(form, "policy acknowledgement")
            vtxt   = f" (version {cur['version']})" if cur else ""
            when_s = (when or "")[:19].replace("T", " ") + " UTC"
            pre    = "" if is_live else "<p><strong>SAMPLE — this is a test record, not a live acknowledgement.</strong></p>"
            # NB: not named `html` -- that would shadow the html module this
            # function calls html.escape() from, in this same scope.
            body_html = (f"{pre}<p>Hello {html.escape(rec.get('name') or '')},</p>"
                    f"<p>This confirms that you acknowledged the <strong>{html.escape(label)}</strong>"
                    f"{html.escape(vtxt)} on {html.escape(when_s)}.</p>"
                    + (f"<p>The document you acknowledged: "
                       f"<a href=\"{html.escape(cur['url'])}\">{html.escape(cur.get('file_name') or 'policy')}</a></p>"
                       if cur and cur.get("url") else "")
                    + (f"<p><strong>What happens next:</strong> IT has been notified and will provision your Claude access within {html.escape(ack_provision_days())} business days. "
                       f"You will receive an email when it is ready. Automation, integrations or business-process use still need a New AI Use Case.</p>" if is_live else "")
                    + "<p>Keep this message for your records.</p>")
            body_text = (("SAMPLE - test record, not a live acknowledgement.\n\n" if not is_live else "")
                    + f"You acknowledged the {label}{vtxt} on {when_s}. No action is needed.")
            try: body_html = _email_html_wrapper(email_art("approved"), "Acknowledgment recorded", body_html)
            except Exception: pass
            return send_email(rec.get("email") or "", f"Acknowledged \u2014 {label}", body_html, body_text)
        except Exception as e:
            print(f"[ACK] confirmation email failed: {e}", file=sys.stderr)
            return False

    def _upload_policy_doc(self, form: str, session: dict):
        """Administrator uploads the acknowledgement document for a form.
        Raw body, filename in X-File-Name. PDF is stored as-is; Word/PowerPoint
        are converted to PDF (LibreOffice) or refused with the reason."""
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        if form not in POLICY_FORMS:
            return err(self, 404, f"No acknowledgement document for form '{form}'")
        name = os.path.basename((self.headers.get("X-File-Name") or "").strip().replace("\\", "/"))[:160]
        ext  = name.rsplit(".", 1)[1].lower() if "." in name else ""
        if ext not in _POLICY_EXT_OK:
            return err(self, 400, "Upload a PDF, Word (.docx) or PowerPoint (.pptx) file")
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return err(self, 400, "Empty upload")
        if length > POLICY_MAX_BYTES:
            return err(self, 413, f"File is larger than {POLICY_MAX_BYTES // (1024*1024)} MB")
        buf, remaining = io.BytesIO(), length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 16))
            if not chunk:
                break
            buf.write(chunk); remaining -= len(chunk)
        data = buf.getvalue()
        if len(data) != length:
            return err(self, 400, "Upload was cut short — try again")
        # the bytes must be what the name claims
        if ext == "pdf" and not data.startswith(b"%PDF-"):
            return err(self, 400, "That file is not a PDF")
        if ext in _POLICY_EXT_ZIP and not data.startswith(b"PK\x03\x04"):
            return err(self, 400, f"That file is not a valid .{ext}")
        if ext in _POLICY_EXT_OLE and not data.startswith(b"\xd0\xcf\x11\xe0"):
            return err(self, 400, f"That file is not a valid .{ext}")

        converted = ext != "pdf"
        if converted:
            if not SOFFICE:
                return err(self, 400, "Only PDF can be uploaded on this server — export the document to PDF first. "
                                      "(Word/PowerPoint conversion needs LibreOffice installed on the portal host.)")
            tmpdir = tempfile.mkdtemp(prefix="policy-src-")
            try:
                src = os.path.join(tmpdir, "source." + ext)
                with open(src, "wb") as f: f.write(data)
                pdf = _convert_to_pdf(src)
            except RuntimeError as e:
                return err(self, 400, str(e))
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
        else:
            pdf = data

        effective = (self.headers.get("X-Policy-Effective") or "").strip()[:10]
        if effective and not re.match(r"^\d{4}-\d{2}-\d{2}$", effective):
            effective = ""
        try:
            meta = _publish_policy_document(
                form, data, pdf, name, ext, converted, effective, _pdf_page_count(pdf),
                session.get("email") or "admin", session.get("role") or "")
        except (OSError, sqlite3.Error, RuntimeError) as e:
            print(f"[POLICY] publication not confirmed ({type(e).__name__}): {e}", file=sys.stderr)
            return err(self, 500, "Document publication could not be confirmed. "
                       "Refresh the document list before retrying; the upload may have completed.")
        # Return this committed operation's snapshot, even if another publisher
        # changes the current document before this response is serialized.
        public_doc = {key: meta.get(key) for key in
                      ("name", "ext", "pages", "size", "url", "sha", "uploaded_at", "converted")}
        ok(self, {"doc": public_doc, "meta": meta})

    def _delete_policy_doc(self, form: str, session: dict):
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        if form not in POLICY_FORMS:
            return err(self, 404, f"No acknowledgement document for form '{form}'")
        meta = policy_doc_meta(form)
        if not meta:
            return err(self, 404, "No document is uploaded for this form")

        # CLA-VERSIONING: taking a document down stops it being SHOWN; it does
        # not erase it. Anything already acknowledged has to stay retrievable,
        # so the files and the version rows survive and only the current-document
        # pointer is cleared. Files are removed only for a version nobody has
        # acknowledged -- an unused upload, typically a mistake being corrected.
        n_acks = db().execute(
            "SELECT COUNT(*) FROM acknowledgments WHERE form=?", (form,)).fetchone()[0]
        now = now_iso()
        removed_files = 0
        if not n_acks:
            keep = set()
            for (u,) in db().execute(
                    "SELECT DISTINCT policy_url FROM acknowledgments WHERE policy_url<>''").fetchall():
                keep.add(os.path.basename(u))
            pdir = os.path.join(POLICY_DIR, form)
            if os.path.isdir(pdir):
                for n in os.listdir(pdir):
                    try: os.remove(os.path.join(pdir, n)); removed_files += 1
                    except OSError: pass
            if os.path.isdir(POLICY_PUBLIC_DIR):
                for n in os.listdir(POLICY_PUBLIC_DIR):
                    if n.startswith(f"{form}-policy-") and n.endswith(".pdf") and n not in keep:
                        try: os.remove(os.path.join(POLICY_PUBLIC_DIR, n)); removed_files += 1
                        except OSError: pass
            with write_lock:
                db().execute("DELETE FROM policy_versions WHERE form=?", (form,))
                db().commit()
        else:
            with write_lock:
                db().execute("UPDATE policy_versions SET retired_at=? WHERE form=? AND retired_at=''",
                             (now, form))
                db().commit()

        with write_lock:
            db().execute("DELETE FROM settings WHERE key=?", (f"policy.{form}.doc",))
            db().commit()
        note = (f"{form}: {meta.get('name','')} taken down; the form shows the text again")
        if n_acks:
            note += f" — {n_acks} acknowledgement(s) on record, so the document and its version history were KEPT"
        elif removed_files:
            note += f" — no acknowledgements on record, {removed_files} unused file(s) removed"
        audit("", "policy.document.removed", session.get("email") or "admin", session.get("role") or "", note)
        ok(self, {"removed": True, "doc": None, "kept_for_acknowledgments": bool(n_acks), "acknowledgments": n_acks})

    def _save_workflows(self, session: dict):
        """Administrator edits a request type's approval chain and/or hides it.
        Body: {"workflows": {type: [steps] | null}, "hidden": {type: bool}}.
        null (or []) resets that type to its built-in chain. Applies to NEW
        requests only. Audited old -> new."""
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        body = parse_body(self)
        wfs = body.get("workflows") if isinstance(body, dict) else None
        hid = body.get("hidden")    if isinstance(body, dict) else None
        if not isinstance(wfs, dict) and not isinstance(hid, dict):
            return err(self, 400, "send workflows and/or hidden")
        cur_over, cur_hidden = workflow_overrides(), set(hidden_types())
        new_over, errors, diff = dict(cur_over), [], []
        for t, wf in (wfs or {}).items():
            if t not in REQUEST_TYPES:
                errors.append(f"unknown request type '{t}'"); continue
            before = type_workflow(t)
            if wf in (None, [], ""):
                new_over.pop(t, None)
                after = list(REQUEST_TYPES[t]["workflow"])
            else:
                clean, e = validate_workflow(t, wf)
                if e:
                    errors.append(e); continue
                if clean == list(REQUEST_TYPES[t]["workflow"]):
                    new_over.pop(t, None)              # identical to built-in: no override needed
                else:
                    new_over[t] = clean
                after = clean
            if after != before:
                diff.append({"type": t, "field": "workflow", "old": before, "new": after})
        new_hidden = set(cur_hidden)
        for t, flag in (hid or {}).items():
            if t not in REQUEST_TYPES:
                errors.append(f"unknown request type '{t}'"); continue
            if bool(flag) != (t in cur_hidden):
                diff.append({"type": t, "field": "hidden", "old": t in cur_hidden, "new": bool(flag)})
            (new_hidden.add if flag else new_hidden.discard)(t)
        if errors:
            return err(self, 400, "; ".join(errors))
        if diff:
            set_setting("workflows", new_over)
            set_setting("types.hidden", sorted(new_hidden))
            for d in diff:
                lbl = REQUEST_TYPES[d["type"]]["label"]
                if d["field"] == "workflow":
                    note = (f"{lbl}: {' -> '.join(step_label(k) for k in d['old'])}  =>  {' -> '.join(step_label(k) for k in d['new'])}"
                            + ("  (built-in chain)" if d["type"] not in new_over else ""))
                else:
                    note = f"{lbl}: {'hidden from the portal' if d['new'] else 'shown on the portal again'}"
                audit("", "workflow.updated", session.get("email") or "admin", session.get("role") or "", note)
        ok(self, {"saved": len(diff), "changes": diff,
                  "request_types": {t: {"workflow": type_workflow(t), "workflow_default": list(REQUEST_TYPES[t]["workflow"]),
                                        "workflow_custom": type_workflow(t) != list(REQUEST_TYPES[t]["workflow"]),
                                        "hidden": t in hidden_types()} for t in REQUEST_TYPES}})

    def _save_content(self, session: dict):
        if (session or {}).get("role") != "admin":
            return err(self, 403, "Admin role required")
        body = parse_body(self)
        changes = body.get("content") if isinstance(body, dict) else None
        if not isinstance(changes, dict) or not changes:
            return err(self, 400, "content object required")
        current, cleaned, errors = content_all(), {}, []
        for k, v in changes.items():
            cv, e = content_clean(k, v)
            if e:
                errors.append(e)
            else:
                cleaned[k] = cv
        if errors:
            return err(self, 400, "; ".join(errors))
        diff = []
        for k, v in cleaned.items():
            old = current.get(k)
            if v is None:
                db().execute("DELETE FROM settings WHERE key=?", ("content." + k,))
                db().commit()
            else:
                set_setting("content." + k, v)
            if old != v:
                diff.append({"key": k, "old": old, "new": v})
        if diff:
            content_audit(session, diff)
        ok(self, {"saved": len(diff), "changes": diff, "content": content_all()})

    def _get_settings(self, session: dict):
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        ok(self, {
            # Fixed recipients come from the service environment (read-only here).
            "recipients": get_smtp(),
            "approver_contacts": approver_contacts_view(),
            "approver_mail": approver_mail_meta(),
        })

    def _save_settings(self, session: dict):
        """R4 — the per-step notification recipient, validated and audited.
        The vestigial SMTP host/port/user/password form was removed (O5): mail
        goes through the loopback relay and nothing read those keys."""
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        body = parse_body(self)
        contacts = body.get("approver_contacts")
        if not isinstance(contacts, dict) or not contacts:
            return err(self, 400, "approver_contacts object required")
        cleaned = {}
        for step, contact in contacts.items():
            if step not in STEP_LABELS:
                return err(self, 400, f"Unknown step '{step}'")
            if not isinstance(contact, dict):
                return err(self, 400, f"{step}: expected an object with name/email")
            c = {}
            if "email" in contact:
                email = str(contact.get("email") or "").strip().lower()
                if email and not ADDR_RE.match(email):
                    return err(self, 400, f"{step_label(step)}: enter a complete email address or leave it blank")
                c["email"] = email
            if "name" in contact:
                c["name"] = " ".join(str(contact.get("name") or "").split())[:80]
            for field in ("subject", "body"):
                if field in contact:
                    v, e = approver_mail_clean(field, contact.get(field))
                    if e:
                        return err(self, 400, f"{step_label(step)}: {e}")
                    c[field] = v
            cleaned[step] = c
        diff = []
        for step, c in cleaned.items():            # all valid — now write
            for field in ("email", "name", "subject", "body"):
                if field not in c:
                    continue
                old = (get_setting(f"approver_{field}_{step}", "") or "")
                if old != c[field]:
                    set_setting(f"approver_{field}_{step}", c[field])
                    diff.append({"step": step, "field": field, "old": old, "new": c[field]})
        if diff:
            audit("", "settings.recipients.updated", session.get("email") or "admin", "admin",
                  json.dumps({"changes": diff}))
        ok(self, {"saved": len(diff), "changes": diff,
                  "approver_contacts": approver_contacts_view(),
                  "approver_mail": approver_mail_meta()})

    def _test_email(self, session: dict):
        if session.get("role") != "admin":
            return err(self, 403, "Admin role required")
        body = parse_body(self)
        to   = body.get("to") or session.get("email")
        sent = send_email(to,
                          "[Test] Enterprise Approval Portal — mail relay verified",
                          _email_html_wrapper("✅", "Mail Relay Test",
                              "<p>This is a test email from the Enterprise Approval Portal backend. The outbound mail relay is configured correctly.</p>"))
        if sent:
            ok(self, message=f"Test email sent to {to}")
        else:
            err(self, 500, "Email send failed — check the relay key and server logs")

    # ── ADMINS ────────────────────────────────────────────────────────────

    def _access_guide(self, session):
        if not can_read_access_guide(session):
            return err(self, 403, "This guide is restricted to the designated portal owners")
        content = (Path(__file__).resolve().parent / "private" / "group-access-guide.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("Vary", "Cookie")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _resource_access(self, session):
        # Preview the teams that can actually occur in current or saved chains.
        # Old request snapshots remain authoritative after a workflow edit.
        available = {t: set(type_workflow(t)) for t in REQUEST_TYPES}
        for row in db().execute("SELECT type,workflow FROM requests"):
            if row["type"] in available:
                available[row["type"]].update(json.loads(row["workflow"]))
        return {t: {**effective_access(session, request_type=t),
                    "applicable_steps": [s for s in STEP_LABELS if s in available[t]]}
                for t in REQUEST_TYPES}

    def _internal_access(self):
        if self.client_address[0] not in ("127.0.0.1", "::1") or not LOOKUP_KEY or not hmac.compare_digest(self.headers.get(LOOKUP_KEY_HEADER, ""), LOOKUP_KEY):
            return err(self, 403, "Forbidden")
        b = parse_body(self)
        email = str(b.get("email") or "").strip().lower()
        if not ADDR_RE.match(email):
            return err(self, 400, "Valid email required")
        session = {"email": email, "roles": _parse_roles(",".join(b.get("roles") or [])), "tier": "", "role": "approver"}
        resources = self._resource_access(session)
        acc = effective_access(session)
        admitted = any(a["view_steps"] or a["manager_of_requests"] for a in resources.values())
        ok(self, {"admitted": bool(admitted), "blocked": acc["blocked"], "access": acc, "resources": resources})

    def _list_policies(self, session: dict):
        if not is_superadmin(session):
            return err(self, 403, "super-admin only")
        rows = db().execute("SELECT * FROM approval_access_policies ORDER BY id").fetchall()
        ok(self, {
            "policies": [_policy_dict(r) for r in rows],
            "steps":  [{"step": s, "label": step_label(s)} for s in STEP_LABELS],
            "request_types": [{"key": t, "label": v["label"]} for t,v in REQUEST_TYPES.items()],
        })


    def _create_policy(self, session: dict):
        if not is_superadmin(session):
            return err(self, 403, "super-admin only")
        body = parse_body(self)
        if not isinstance(body, dict):
            body = {}
        clean, e = _validate_policy(body)
        if e:
            return err(self, 400, e)
        e = verify_policy_principal(clean)
        if e: return err(self, 400, e)
        actor = session.get("email") or "admin"
        ts    = now_iso()
        with write_lock:
            dup = db().execute(
                "SELECT id FROM approval_access_policies WHERE principal_type=? AND principal_key=?",
                (clean["principal_type"], clean["principal_key"])).fetchone()
            if dup:
                return respond(self, 409, {"ok": False, "id": dup["id"],
                                           "error": "a policy for this principal already exists"})
            try:
                cur = db().execute(
                    """INSERT INTO approval_access_policies
                       (name,principal_type,principal_key,view_scope,view_steps,decide_scope,decide_steps,
                        enabled,origin,created_at,created_by,updated_at,updated_by)
                       VALUES(?,?,?,?,?,?,?,?,'console',?,?,?,?)""",
                    (clean["name"], clean["principal_type"], clean["principal_key"],
                     clean["view_scope"], json.dumps(clean["view_steps"]),
                     clean["decide_scope"], json.dumps(clean["decide_steps"]),
                     1 if clean["enabled"] else 0, ts, actor, ts, actor))
            except sqlite3.IntegrityError:
                db().rollback()
                return respond(self, 409, {"ok": False, "id": None,
                                           "error": "a policy for this principal already exists"})
            new_id = cur.lastrowid
            db().execute("UPDATE approval_access_policies SET request_types=?,expires_at=?,reason=?,effect=? WHERE id=?",
                         (json.dumps(clean["request_types"]), clean["expires_at"], clean["reason"], clean["effect"], new_id))
            db().commit()
        p = _policy_dict(db().execute(
            "SELECT * FROM approval_access_policies WHERE id=?", (new_id,)).fetchone())
        audit(None, "approval_access.created", actor, "superadmin",
              json.dumps(p, separators=(",", ":"), default=str))
        respond(self, 201, {"ok": True, "data": {"policy": p}})


    def _update_policy(self, pid: int, session: dict):
        if not is_superadmin(session):
            return err(self, 403, "super-admin only")
        body = parse_body(self)
        if not isinstance(body, dict) or not body:
            return err(self, 400, "Nothing to update: send one or more policy fields")
        unknown = sorted(k for k in body if k not in POLICY_FIELDS and k not in ("principal_keys", "expected_updated_at"))
        if unknown:
            return err(self, 400, f"unknown field: {', '.join(unknown)}")
        actor = session.get("email") or "admin"
        with write_lock:
            row = db().execute("SELECT * FROM approval_access_policies WHERE id=?", (pid,)).fetchone()
            if not row:
                return err(self, 404, f"No policy with id {pid}")
            before = _policy_dict(row)
            if body.get("expected_updated_at") and body["expected_updated_at"] != before["updated_at"]:
                return err(self, 409, "This policy changed. Refresh before saving.")
            merged = {**before, **body}                        # validate the MERGED record
            if "principal_keys" in body and "principal_key" not in body:     # a new key set replaces the old one
                merged.pop("principal_key", None)
            elif "principal_key" in body and "principal_keys" not in body:
                merged.pop("principal_keys", None)
            clean, e = _validate_policy(merged)
            if e:
                return err(self, 400, e)
            if (clean["principal_type"], clean["principal_key"]) != (before["principal_type"], before["principal_key"]):
                e = verify_policy_principal(clean)
                if e: return err(self, 400, e)
                dup = db().execute(
                    "SELECT id FROM approval_access_policies WHERE principal_type=? AND principal_key=? AND id<>?",
                    (clean["principal_type"], clean["principal_key"], pid)).fetchone()
                if dup:
                    return respond(self, 409, {"ok": False, "id": dup["id"],
                                               "error": "a policy for this principal already exists"})
            changed = [k for k in POLICY_FIELDS if before.get(k) != clean[k]]
            if not changed:
                return ok(self, {"policy": before})
            ts = now_iso()
            db().execute(
                """UPDATE approval_access_policies
                   SET name=?,principal_type=?,principal_key=?,view_scope=?,view_steps=?,
                       decide_scope=?,decide_steps=?,enabled=?,updated_at=?,updated_by=?
                   WHERE id=?""",
                (clean["name"], clean["principal_type"], clean["principal_key"],
                 clean["view_scope"], json.dumps(clean["view_steps"]),
                 clean["decide_scope"], json.dumps(clean["decide_steps"]),
                 1 if clean["enabled"] else 0, ts, actor, pid))
            db().execute("UPDATE approval_access_policies SET request_types=?,expires_at=?,reason=?,effect=? WHERE id=?",
                         (json.dumps(clean["request_types"]), clean["expires_at"], clean["reason"], clean["effect"], pid))
            db().commit()
        after = _policy_dict(db().execute(
            "SELECT * FROM approval_access_policies WHERE id=?", (pid,)).fetchone())
        audit(None, "approval_access.updated", actor, "superadmin",
              json.dumps({"id": pid, "principal_type": after["principal_type"],
                          "principal_key": after["principal_key"],
                          "before": {k: before.get(k) for k in changed},
                          "after":  {k: after.get(k)  for k in changed}},
                         separators=(",", ":"), default=str))
        ok(self, {"policy": after})


    def _delete_policy(self, pid: int, session: dict):
        if not is_superadmin(session):
            return err(self, 403, "super-admin only")
        actor = session.get("email") or "admin"
        with write_lock:
            row = db().execute("SELECT * FROM approval_access_policies WHERE id=?", (pid,)).fetchone()
            if not row:
                return err(self, 404, f"No policy with id {pid}")
            before = _policy_dict(row)
            db().execute("DELETE FROM approval_access_policies WHERE id=?", (pid,))
            db().commit()
        audit(None, "approval_access.deleted", actor, "superadmin",
              json.dumps(before, separators=(",", ":"), default=str))
        ok(self, {"ok": True, "id": pid})


# ── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    print(f"[portal-api] Starting — port {PORT}, DB {DB_PATH}")
    take_backup()
    db()  # initialise schema

    journey_start()     # JOURNEY: background writer + 90-day purge for journey.db
    ack_daily_thread()  # ACK-NOTIFY: daily summary (only acts when notify_mode is "daily")
    reminder_daily_thread()  # APPROVER-REMINDERS: daily sweep
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), PortalHandler)
    print(f"[portal-api] Listening on http://127.0.0.1:{PORT}")
    print(f"[portal-api] CORS origin: {CORS_ORIGIN}")
    print(f"[portal-api] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[portal-api] Stopped.")
