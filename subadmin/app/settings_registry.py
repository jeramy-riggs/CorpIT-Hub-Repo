"""
settings_registry.py — every tunable admin setting, declared once.

The rule this exists to enforce: no admin setting may live only in a config file.
A setting is DECLARED here and the console renders a control for it automatically,
so adding the next one is a declaration, never a page rebuild.

Storage is config.json (already atomic + 0600). A setting's `path` is a dotted key
into that document, so nesting like "sso.client_id" needs no special handling.

Sensitive settings are write-only: their current value is never rendered back to the
browser and never written to the audit log — only the fact that they changed.
"""

import hashlib
import os
import re
from datetime import date as _date
from urllib.parse import urlsplit

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}$")
PLACEHOLDER_RE = re.compile(r"^(PASTE|CHANGE|REPLACE|TODO|<)", re.I)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# CORPIT-SECRET-EXPIRY - how far ahead a secret expiry starts being shouted about.
EXPIRY_URGENT_DAYS = 30
EXPIRY_NOTICE_DAYS = 60

# The Hub API keeps its own copy of the SAME client secret. Only the copy is
# read (and only ever hashed), never written from here - rotating it is a file
# edit plus a pm2 restart, and pretending otherwise from this page would be a
# control that cannot do its job.
HUB_ENV_PATH = "/var/www/corpit-hub-api/.env"


# CORPIT-OBSERVABILITY-SETTINGS - shared restart hint. The Hub API re-reads
# /etc/corpit/observability.json every 30 seconds, so none of these need a
# service restart.
OBS_APPLIES_HINT = ("Applies within 30 seconds. No restart, and nothing "
                    "already buffered is lost.")

# CORPIT-SPEND-ALERTS - the same publish-to-/etc/corpit shape as the observability
# block below: saved here, published by the root helper to
# /etc/corpit/spend-alerts.json, re-read by the Hub API within 30 seconds.
SPEND_APPLIES_HINT = ("Applies within 30 seconds. Managers who have chosen their "
                      "own percentage keep it; this is the default for everyone else.")
APPROVALS_APPLIES_HINT = "Applies within 30 seconds of Save; no restart needed."


class SettingError(ValueError):
    """A rejected value, with a message meant for the person typing it."""


class Setting:
    def __init__(self, path, label, group, kind, default=None, help="",
                 sensitive=False, minimum=None, maximum=None, restart_hint=None, step=None):
        self.path = path
        self.key = path.replace(".", "__")      # form-field-safe
        self.label = label
        self.group = group
        self.kind = kind                        # bool int str guid url email_list secret
        self.default = default
        self.help = help
        self.sensitive = sensitive
        self.minimum = minimum
        self.maximum = maximum
        self.restart_hint = restart_hint
        self.step = step                        # int only: the value must be a multiple of this


# CORPIT-SETTINGS-FOLD (2026-10-12): help that depends on what this host actually runs.
# `host_note` is a (test, sentence) pair; the sentence is inserted into the help only
# while test() is true, so a host where the condition does not hold never shows it.
class HostNoteSetting(Setting):
    def __init__(self, *args, host_note=None, **kwargs):
        self._host_note = host_note
        super().__init__(*args, **kwargs)

    @property
    def help(self):
        base = self._help
        if self._host_note:
            # A callable returns the sentence for this host, or "" for none.
            try:
                sentence = self._host_note() or ""
            except Exception:
                sentence = ""
            if sentence:
                return base.replace("{host_note}", " " + sentence)
        return base.replace("{host_note}", "")

    @help.setter
    def help(self, value):
        self._help = value


# The dev server runs the ops check in practice mode (Jeramy, 2026-10-12 20:07Z):
# corpit-ops-sync-watch-dryrun.timer is enabled there and sends nothing. Its
# enablement symlink is the test, read with a plain stat (no privilege needed).
OPS_DRYRUN_TIMER_LINK = "/etc/systemd/system/timers.target.wants/corpit-ops-sync-watch-dryrun.timer"
# PROD-READINESS 2026-10-12: the real check. Where neither timer is enabled
# (corpit A/B today) nothing reads the published recipients, and the help says so
# instead of implying failures are mailed.
OPS_TIMER_LINK = "/etc/systemd/system/timers.target.wants/corpit-ops-sync-watch.timer"


def _ops_alert_host_note():
    if os.path.lexists(OPS_TIMER_LINK):
        return ""
    if os.path.lexists(OPS_DRYRUN_TIMER_LINK):
        return ("On this dev server the sync check runs every 15 minutes in "
                "practice mode: would-be alerts are written to the system log, "
                "never emailed.")
    return ("NOT IN FORCE ON THIS HOST: no ops failure check is installed here, so "
            "nothing reads this list and no failure email is sent. The value is "
            "stored and published for when the check is installed.")


# ---------------------------------------------------------------------------
# The registry. Add a Setting here and it appears in the console.
# ---------------------------------------------------------------------------
SETTINGS = [
    Setting("sso.enabled", "Single sign-on enabled", "Entra single sign-on", "bool",
            default=False,
            help="When off, only the break-glass password login is available. "
                 "Turning this on requires a client ID and secret below."),
    Setting("sso.tenant_id", "Directory (tenant) ID", "Entra single sign-on", "guid",
            help="The Entra tenant this console authenticates against."),
    Setting("sso.client_id", "Application (client) ID", "Entra single sign-on", "guid",
            help="From the app registration's Overview page."),
    Setting("sso.client_secret", "Client secret", "Entra single sign-on", "secret",
            sensitive=True,
            help="The secret VALUE, not the Secret ID. Shown once by Entra. "
                 "Leave blank to keep the current secret."),
    Setting("sso.redirect_uri", "Redirect URI", "Entra single sign-on", "url",
            default="https://subadmin.nrpi.local/auth/callback",
            help="Must match the Web redirect URI on the app registration exactly."),
    Setting("sso.owners", "Production-write allowlist", "Entra single sign-on", "email_list",
            help="Comma or newline separated. Being in SaaS-ITH-SA grants the "
                 "platform-owner role; production writes additionally require "
                 "membership of this list."),

    Setting("sso.client_secret_expires", "Client secret expires",
            "Entra single sign-on", "date",
            help="Expiry date of the client secret above, from Entra "
                 "(Certificates & secrets). This one secret is shared by the "
                 "console AND the Hub API, so when it expires everything that "
                 "signs in stops at once. Recording the date here is what turns "
                 "a silent outage into a warning on this page."),

    Setting("session_absolute_max_seconds", "Session hard limit", "Sessions", "int",
            default=12 * 3600, minimum=900, maximum=7 * 24 * 3600,
            help="Maximum age of a session regardless of activity, in seconds. "
                 "The idle timeout is separate. 43200 = 12 hours.",
            restart_hint="Applies to sessions started after Save, on every worker, with no "
                         "restart. A session already open keeps the limit it started with."),

    # ---------------------------------------------------------------- CORPIT-HOUSEKEEPING-SETTINGS
    # Retention and alert thresholds. These were constants in the code or, worse,
    # nowhere at all - nothing pruned the backups and nothing watched the disk.
    # A threshold nobody can see is a threshold nobody tunes.
    Setting("housekeeping.backup_keep_days", "Keep backups for", "Housekeeping", "int",
            default=30, minimum=7, maximum=3650,
            help="Days. Pre-change backups and .bak files older than this are offered "
                 "for cleanup under Operations. The two newest in each group are "
                 "always kept whatever their age, and nothing younger than 7 days is "
                 "ever a candidate - so a short window cannot leave you with none."),

    Setting("housekeeping.audit_keep_days", "Keep routine audit entries for",
            "Housekeeping", "int",
            default=365, minimum=30, maximum=3650,
            help="Days. Applies ONLY to high-volume routine rows (sign-in, sign-out, "
                 "page rebuilds). Every denial, permission change, settings change and "
                 "provisioning action is kept indefinitely regardless of this."),

    Setting("alerts.cert_warn_days", "Warn before a certificate expires", "Alerts", "int",
            default=45, minimum=7, maximum=365,
            help="Days of notice on Overview and Hosts & Servers. NRPI-CA enrollment "
                 "needs a person, so leave enough time for one to be available."),

    Setting("alerts.disk_warn_percent", "Warn when the disk passes", "Alerts", "int",
            default=85, minimum=50, maximum=99,
            help="Percent of the root filesystem used. Below this the disk is not "
                 "mentioned on Overview at all."),

    Setting("alerts.sync_stale_hours", "Warn if the directory sync has not run for",
            "Alerts", "int",
            default=48, minimum=1, maximum=720,
            help="Hours. Catches the failure nobody notices: not a sync that errors, "
                 "but a scheduled sync that quietly stopped running. The same number "
                 "of hours is how long an Entra/Okta sync run may stay 'running' "
                 "before it is emailed as stuck (see 'Email ops failures to')."),

    # CORPIT-OPS-ALERT (2026-09-25, DECISIONS C1-C9). Who is emailed when the
    # nightly backup, an Entra/Okta sync or a corpit-cronwrap-wrapped scheduled
    # job fails. Published on Save by the root helper (nrpi-subdomain
    # sync-ops-alerts) to /etc/corpit/ops-alerts.json, which
    # /var/www/corpit-hub-api/ops-alert.js reads on every check. EMPTY = nobody
    # is mailed (failures are still logged to /var/log/corpit/ops-alert.log).
    # Sign-in alerts are separate and stay disabled.
    HostNoteSetting("ops_alerts.recipients", "Email ops failures to", "Alerts", "email_list",
            default=[],
            help="Who is emailed when a host failure is detected (backup, Entra/Okta "
                 "sync failed/partial/stuck, wrapped scheduled jobs).{host_note} Comma "
                 "or newline separated; empty = nobody.",
            host_note=_ops_alert_host_note,
            restart_hint="Applies to the next check after Save; no restart needed."),

    # ---------------------------------------------------------------- CORPIT-OBSERVABILITY-SETTINGS
    # The tunables behind /observability.html. They were environment variables in
    # the Hub API's .env, which means they were invisible here and changing one
    # needed a shell. Saving on this page publishes them to
    # /etc/corpit/observability.json via the root helper; the API re-reads that
    # file every 30 seconds. If publishing fails the save says so - a value that
    # is stored here but never reaches the API would be a control that cannot do
    # its job.
    Setting("obs.enabled", "Record observability data", "Observability", "bool",
            default=True,
            help="Master switch for request logging, upstream dependency logging and "
                 "the browser error beacon. Turning this off stops all recording; the "
                 "pages themselves keep working and the dashboard says plainly that "
                 "collection is off rather than showing an empty all-clear. "
                 "OBS_ENABLED=0 in the API's own .env is a separate emergency stop "
                 "that overrides this box.",
            restart_hint=OBS_APPLIES_HINT),

    Setting("obs.sample_percent", "Keep this share of routine requests",
            "Observability", "int",
            default=2, minimum=0, maximum=100,
            help="Percent. Requests that FAILED or were slow are always kept whatever "
                 "this says - the sample applies only to fast, successful ones, which "
                 "are the overwhelming majority and are only useful as a baseline. "
                 "Raise it while chasing something; 100 records everything and will "
                 "grow the table quickly.",
            restart_hint=OBS_APPLIES_HINT),

    Setting("obs.slow_ms", "Always keep requests slower than", "Observability", "int",
            default=2000, minimum=100, maximum=60000,
            help="Milliseconds. A request over this threshold is recorded regardless "
                 "of the sample above, because a slow request that was never sampled "
                 "is the one you end up wishing you had.",
            restart_hint=OBS_APPLIES_HINT),

    Setting("obs.buffer_max", "Hold at most this many pending rows",
            "Observability", "int",
            default=2000, minimum=100, maximum=50000,
            help="Per table. Events are written in batches, and if the database is "
                 "unreachable they queue here. Past this limit the OLDEST are dropped, "
                 "on the reasoning that during an incident the newest events describe "
                 "what is happening now. Anything dropped is counted and shown on the "
                 "dashboard - it is never silent.",
            restart_hint=OBS_APPLIES_HINT),

    Setting("obs.flush_seconds", "Write batched events every", "Observability", "int",
            default=5, minimum=1, maximum=300,
            help="Seconds. Lower means the dashboard is fresher and a crash loses less; "
                 "higher means fewer, larger inserts. There is little reason to change "
                 "this unless the database is under strain.",
            restart_hint=OBS_APPLIES_HINT),

    Setting("obs.client_max_body_kb", "Largest browser report accepted",
            "Observability", "int",
            default=64, minimum=1, maximum=1024,
            help="Kilobytes. A cap on the JSON a single page may post to the error "
                 "beacon, so a page stuck in a render loop cannot post an unbounded "
                 "body. The browser also caps itself at 100 events per page load.",
            restart_hint=OBS_APPLIES_HINT),

    # Until 2026-09-07 nothing on this platform deleted an observability row.
    # The tables only grew, and the fastest-growing one is not sampled at all -
    # every outbound call to every vendor is a row. A telemetry table that fills
    # the disk takes down the application it was installed to observe, so how
    # long to keep the data is an operator decision and belongs here.
    Setting("obs.retention_days", "Keep observability data for", "Observability", "int",
            default=30, minimum=1, maximum=365,
            help="Days. Covers request logs, upstream dependency calls and browser "
                 "error reports. An hourly job deletes anything older in small "
                 "batches; lowering this works through the backlog over the next few "
                 "hours rather than in one long lock, and the job's progress is on "
                 "the dashboard. Browser reports are aged by when the SERVER received "
                 "them, not the timestamp the browser sent, so a machine with a wrong "
                 "clock cannot keep its rows past this.",
            restart_hint=OBS_APPLIES_HINT),

    Setting("obs.job_run_retention_days", "Keep scheduled-job history for",
            "Observability", "int",
            default=90, minimum=1, maximum=730,
            help="Days. Longer than the setting above on purpose: this history is how "
                 "'when did that cron actually stop running?' gets answered. The "
                 "incident this whole system was built after went unnoticed for four "
                 "months, so a 30-day window would have thrown away the evidence "
                 "before anyone thought to look for it.",
            restart_hint=OBS_APPLIES_HINT),

    # ---------------------------------------------------------------- CORPIT-SPEND-ALERTS
    # Managers are told when a report approaches their monthly Claude spend limit.
    # The percentage that counts as "approaching" was a constant in the alert
    # library and then a row in a MySQL table only a super-admin API could write -
    # two homes, neither of them here. This is the one home: a manager may still
    # choose their own number for their own list, and this is what applies to
    # everyone who has not.
    Setting("spend_alerts.threshold", "Alert a manager at", "Claude spend alerts", "int",
            default=75, minimum=1, maximum=99,
            help="Percent of a person's monthly Claude spend limit. At or above this "
                 "they appear on their manager's My Profile page with a recommended "
                 "new limit and a button to raise a Service Desk ticket. Set it low "
                 "and every seat is always on the list, which is the same as no list.",
            restart_hint=SPEND_APPLIES_HINT),

    Setting("spend_alerts.digest_enabled", "Email managers a daily digest",
            "Claude spend alerts", "bool",
            default=False,
            help="OFF by default, and mail to managers starts the moment it is on. "
                 "The in-app card works either way. Preview exactly what would be "
                 "sent first: spend-alert-digest-job.js --preview writes the real "
                 "message to a file and sends it to nobody.",
            restart_hint=SPEND_APPLIES_HINT),

    Setting("spend_alerts.digest_hour", "Send the digest at", "Claude spend alerts", "int",
            default=13, minimum=0, maximum=23,
            help="Hour of the day, UTC (13 is about 6am Pacific). The job wakes hourly "
                 "and only sends in this hour. A manager whose list has not changed is "
                 "left alone for a week rather than mailed the same names daily.",
            restart_hint=SPEND_APPLIES_HINT),

    # ---------------------------------------------------------------- CORPIT-LIMIT-APPROVALS
    # My Profile Claude limit raises: a person at the default raises themselves one
    # step; above that their manager approves; above the manager ceiling their
    # functional leader approves too. Applied in Anthropic, logged on SDP tickets,
    # reset to the prior cap on the 1st. Published with the spend alert settings
    # (nrpi-subdomain sync-spend -> /etc/corpit/spend-alerts.json "approvals").
    Setting("spend_alerts.approvals_enabled", "Allow limit raises from My Profile",
            "Claude limit approvals", "bool",
            default=False,
            help="OFF by default. When on, people can raise their own Claude limit and "
                 "managers and functional leaders can approve raises in My Profile, and "
                 "each approval CHANGES THE LIMIT IN ANTHROPIC, using the Hub's Anthropic "
                 "key (it reads and writes spend limits). If Anthropic refuses a change, the "
                 "request stays 'Approved, not applied' with its ticket open and can be "
                 "retried from My Profile. Turning it off stops new raises; raises already "
                 "made are still reset on the 1st.",
            restart_hint=APPROVALS_APPLIES_HINT),
    # The raise sizes, not totals: the hub adds them to the limit a person started the
    # month with. Jeramy 2026-09-25: whole $100 steps only. The hub refuses a published
    # pair that is out of order, so preflight() checks the same order before a save.
    Setting("spend_alerts.approvals_self_raise", "One-click self-raise (+$)",
            "Claude limit approvals", "int",
            default=100, minimum=100, maximum=100000, step=100,
            help="How much a person can add to their own limit with one click, once a "
                 "month, when it has not already been raised that month. Their manager is "
                 "emailed; nobody approves it. Any other raise that month goes to their "
                 "manager. Whole $100 steps; must be less than the manager amount below.",
            restart_hint=APPROVALS_APPLIES_HINT),
    Setting("spend_alerts.approvals_manager_raise", "Manager approves raises up to (+$)",
            "Claude limit approvals", "int",
            default=500, minimum=100, maximum=1000000, step=100,
            help="A raise up to this much over the limit a person started the month with "
                 "needs their manager only. A bigger raise needs the manager and then the "
                 "person's functional leader (HR roster). Whole $100 steps; must be more "
                 "than the one-click self-raise. Changing either amount does not change "
                 "anybody's limit in Anthropic; a page left open with the old amounts is "
                 "refused and refreshed.",
            restart_hint=APPROVALS_APPLIES_HINT),
    Setting("spend_alerts.approvals_escalation_emails", "When nobody can approve, email",
            "Claude limit approvals", "email_list",
            default=["rabad@auction.com", "jriggs@auction.com", "spark@auction.com"],
            help="A request from someone with no manager on record, or with no functional "
                 "leader for the final step, goes to the Service Desk: it gets an OPEN "
                 "ticket and these people are emailed with it. Nothing is changed in "
                 "Anthropic until someone acts on the ticket. Comma or newline separated.",
            restart_hint=APPROVALS_APPLIES_HINT),
    Setting("spend_alerts.approvals_seat_owners", "Claude seat owners",
            "Claude limit approvals", "email_list",
            default=["rabad@auction.com", "jriggs@auction.com", "spark@auction.com"],
            help="These people see every Claude limit request on My Profile (the All tab, "
                 "90 days back) and can try again when a limit was approved but the change "
                 "could not be written to Anthropic. They cannot approve or deny a request "
                 "that is waiting on a manager or functional leader. Comma or newline separated.",
            restart_hint=APPROVALS_APPLIES_HINT),

    # Who sees the 'Back to AI Reporting' link on My Profile. Defaults to
    # the leadership set; this is the one home for granting or revoking it.
    # An empty list means nobody. Published to the Hub API on Save via the
    # root helper (nrpi-subdomain sync-reporting-return).
    Setting("reporting_return.allow_emails", "Who may return to AI Reporting",
            "AI Reporting", "email_list",
            default=[
                "ali@auction.com", "jasona@auction.com", "dosborn@auction.com",
                "mkilander@auction.com", "jcutrona@auction.com", "glane@auction.com",
                "mbaig@auction.com", "kboothe@auction.com", "bsigala@auction.com",
                "snarayan@auction.com", "asteinhaus@auction.com", "rabad@auction.com",
                "jriggs@auction.com",
            ],
            help="These people see a 'Back to AI Reporting' link on their My "
                 "Profile page, taking them to https://reporting.nrpi.local/. "
                 "Comma or newline separated. Defaults to the leadership set; "
                 "add anyone here to grant the link, remove someone to take it "
                 "away. An EMPTY list means nobody sees it. Only people with a "
                 "reporting line have a team roll-up to view there.",
            restart_hint="Applies within ~30 seconds of Save; no restart needed."),
    # ---------------------------------------------------------------- CORPIT-SERVER-UPDATES
    # Weekly patching for itam and the corpit A/B pair (System > Updates). Saved
    # here, then published over the root corpit-updates service's socket, which
    # is the thing that enforces them. The group exists only on a host running
    # that service (itam): everywhere else it is hidden and never applied, so no
    # host shows a control that does nothing.
    Setting("updates.allowed_actors", "Who may run server updates", "Server updates", "email_list",
            default=["jriggs@auction.com"],
            help="These people may check for updates, install them and reboot from System > "
                 "Updates. They must also be platform owners to open the tab. The kernel "
                 "reboot with an HA switch is further limited to jriggs@auction.com, the one "
                 "operator the planned HA controller accepts. 1-10 addresses; an EMPTY list "
                 "is refused.",
            restart_hint="Applies on Save; the updates service reads it on every request."),
    Setting("updates.overdue_days", "Days before pending updates are overdue", "Server updates", "int",
            default=7, minimum=1, maximum=60,
            help="A server with pending updates or a pending reboot for longer than this is "
                 "marked overdue on System > Updates, and the ops alerts mail about it.",
            restart_hint="Applies at the next check."),
    Setting("updates.check_hours", "Check for updates every (hours)", "Server updates", "int",
            default=6, minimum=1, maximum=24,
            help="How often the updates service reads the state of itam, A and B (pending "
                 "packages, kernel, cluster health). It only reads; nothing is installed "
                 "until someone presses a button on System > Updates.",
            restart_hint="Applies within 5 minutes."),
    Setting("updates.switch_back_default", "Switch back to the original owner after a kernel reboot",
            "Server updates", "bool", default=True,
            help="The starting position of the 'switch back afterwards' toggle on the kernel "
                 "reboot. On: prod web ends on the node that owned it before. Off: it stays "
                 "on the other node. The operator can change it for each run.",
            restart_hint="Applies to the next run."),
    # ---------------------------------------------------------------- CORPIT-WEBWATCH
    # Prod web watch (System > Web watch): published over the root corpit-webwatch
    # service's socket. That service enforces the operator list for "Clear fence
    # failure" and writes /etc/corpit-webwatch/policy.json, which the HA alert
    # evaluator (1.7.0+) reads for the reminder interval. itam only, like updates.
    Setting("webwatch.allowed_actors", "Who may clear a fence failure", "Prod web watch", "email_list",
            default=["jriggs@auction.com"],
            help="These people may press Clear fence failure on System > Web watch, which runs "
                 "crm_resource --cleanup for fence-A or fence-B on the prod pair. They must also "
                 "be platform owners to open the tab. 1-10 addresses; an EMPTY list is refused.",
            restart_hint="Applies on Save; the web watch service reads it on every request."),
    Setting("webwatch.repeat_critical_minutes", "Re-mail open critical HA alerts every (minutes)",
            "Prod web watch", "int", default=30, minimum=0, maximum=240,
            help="While a critical HA alert (for example prod web down) stays open and the monitor "
                 "keeps confirming it, mail it again this often until it resolves. 0 = mail once "
                 "only. 15-240 otherwise. Reminders count toward the mailer's 20 per hour cap and go "
                 "to the same HA alert recipients as every other alert.",
            restart_hint="Applies at the next alert evaluation (within a minute)."),
]

BY_KEY = {s.key: s for s in SETTINGS}
BY_PATH = {s.path: s for s in SETTINGS}
GROUPS = []
for _s in SETTINGS:
    if _s.group not in GROUPS:
        GROUPS.append(_s.group)

# Groups that only mean something where their service runs. Hidden and never
# applied elsewhere - a stored value nothing reads is a control that does nothing.
UPDATES_SOCKET = "/run/corpit-updates/updates.sock"
WEBWATCH_SOCKET = "/run/corpit-webwatch/webwatch.sock"
HOST_GATED = {"Server updates": lambda: _exists(UPDATES_SOCKET),
              "Prod web watch": lambda: _exists(WEBWATCH_SOCKET)}


def _exists(path):
    try:
        return os.path.exists(path)
    except OSError:
        return False


def group_visible(group):
    test = HOST_GATED.get(group)
    return test is None or bool(test())


def visible_groups():
    return [g for g in GROUPS if group_visible(g)]


def updates_policy(cfg):
    """The Server updates values as the updates service expects them."""
    out = {}
    for s in SETTINGS:
        if s.group == "Server updates":
            v = _get(cfg, s.path)
            out[s.path.split(".", 1)[1]] = s.default if v is None else v
    return out


def webwatch_policy(cfg):
    """The Prod web watch values as the web watch service expects them."""
    out = {}
    for s in SETTINGS:
        if s.group == "Prod web watch":
            v = _get(cfg, s.path)
            out[s.path.split(".", 1)[1]] = s.default if v is None else v
    return out


# ---------------------------------------------------------------------------
# Reading and writing dotted paths in the config document
# ---------------------------------------------------------------------------
def _get(cfg, path):
    node = cfg
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _set(cfg, path, value):
    parts = path.split(".")
    node = cfg
    for part in parts[:-1]:
        if not isinstance(node.get(part), dict):
            node[part] = {}
        node = node[part]
    node[parts[-1]] = value


def current(cfg, s):
    """The value to render. Never returns a sensitive value."""
    v = _get(cfg, s.path)
    if s.sensitive:
        return ""
    if v is None:
        return s.default
    return v


def is_set(cfg, s):
    """Whether a sensitive setting currently holds a real (non-placeholder) value."""
    v = _get(cfg, s.path)
    if not v or not isinstance(v, str):
        return bool(v)
    return not PLACEHOLDER_RE.match(v.strip())


def display(cfg, s):
    """Human-readable current value for non-sensitive settings."""
    v = current(cfg, s)
    if s.kind == "email_list":
        return ", ".join(v or [])
    if s.kind == "bool":
        return bool(v)
    return "" if v is None else str(v)


def coerce(s, raw):
    """Validate and convert one submitted value. Raises SettingError."""
    if s.kind == "bool":
        return str(raw).lower() in ("1", "true", "on", "yes")

    raw = "" if raw is None else str(raw).strip()

    if s.kind == "int":
        if raw == "":
            raise SettingError("%s cannot be blank." % s.label)
        try:
            n = int(raw)
        except ValueError:
            raise SettingError("%s must be a whole number." % s.label)
        if s.minimum is not None and n < s.minimum:
            raise SettingError("%s must be at least %d." % (s.label, s.minimum))
        if s.maximum is not None and n > s.maximum:
            raise SettingError("%s must be at most %d." % (s.label, s.maximum))
        if s.step and n % s.step:
            raise SettingError("%s must be in steps of %d." % (s.label, s.step))
        return n

    if s.kind == "date":
        if not raw:
            return ""                     # blank = not recorded yet
        if not DATE_RE.match(raw):
            raise SettingError("%s must be a date in YYYY-MM-DD form." % s.label)
        try:
            _d = _date.fromisoformat(raw)
        except ValueError:
            raise SettingError("%s is not a real date." % s.label)
        if _d.year < 2000 or _d.year > 2100:
            raise SettingError("%s is out of range." % s.label)
        return raw

    if s.kind == "guid":
        if raw and not GUID_RE.match(raw):
            raise SettingError("%s must look like a GUID "
                               "(8-4-4-4-12 hex). Placeholder text is not accepted." % s.label)
        return raw

    if s.kind == "url":
        if not raw:
            return raw
        if not raw.startswith("https://"):
            raise SettingError("%s must start with https://." % s.label)
        # REDIRECT_HOST_PIN: must stay on this console's own origin.
        if s.default and s.default.startswith("https://"):
            want = urlsplit(s.default).netloc.lower()
            got = urlsplit(raw).netloc.lower()
            if got != want:
                raise SettingError(
                    "%s must be on %s (got %s). The redirect URI is where the "
                    "authorization code is delivered; it may not point off-host."
                    % (s.label, want, got or "nothing"))
        return raw

    if s.kind == "email_list":
        items = [p.strip().lower() for p in re.split(r"[,\n]", raw) if p.strip()]
        bad = [p for p in items if not EMAIL_RE.match(p)]
        if bad:
            raise SettingError("%s: not an email address: %s" % (s.label, ", ".join(bad[:3])))
        seen, out = set(), []
        for p in items:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    if s.kind == "secret":
        # SECRET_ID_SHAPE: Entra lists "Secret ID" next to "Value" and the ID is the
        # one that looks tidy, so it gets copied by mistake. A real secret Value is
        # never a bare GUID. Catch it here rather than at the first failed sign-in.
        if raw and GUID_RE.match(raw):
            raise SettingError(
                "%s looks like the Secret ID, not the secret Value. In Entra, copy the "
                "'Value' column (roughly 40 characters, mixed case with symbols) - the "
                "Value is shown only once, so if it is gone, generate a new secret."
                % s.label)
        if raw and len(raw) < 20:
            raise SettingError("%s looks too short to be a client secret Value." % s.label)
        return raw          # blank means "keep current"; the caller handles that

    return raw


def _days_until(iso):
    """Whole days from today to an ISO date, or None if unusable."""
    if not iso or not DATE_RE.match(str(iso)):
        return None
    try:
        return (_date.fromisoformat(str(iso)) - _date.today()).days
    except ValueError:
        return None


def _hub_secret_digest():
    """SHA-256 of the Hub API's copy of the client secret, or None.

    Hashed, never returned or logged in the clear - this only ever answers
    "are the two copies the same string?".
    """
    try:
        with open(HUB_ENV_PATH) as fh:
            for line in fh:
                m = re.match(r"^SSO_CLIENT_SECRET=(.*)$", line.rstrip("\n"))
                if m:
                    v = m.group(1).strip().strip('"').strip("'")
                    if not v:
                        return None
                    return hashlib.sha256(v.encode("utf-8")).hexdigest()
    except OSError:
        return None
    return None


def advisories(cfg):
    """Non-blocking warnings for the settings page. (%s)

    Separate from preflight() on purpose: preflight stops a save, and an
    approaching secret expiry must never prevent saving an unrelated setting.
    Returns a list of (level, message).
    """
    out = []
    sso = cfg.get("sso") or {}
    if not sso.get("enabled"):
        return out

    rotate = ("Rotating it means updating BOTH copies: the Client secret field "
              "on this page, and SSO_CLIENT_SECRET in %s followed by "
              "'pm2 restart corpit-hub-api --update-env'." % HUB_ENV_PATH)

    iso = sso.get("client_secret_expires")
    days = _days_until(iso)
    if days is None:
        out.append(("warn",
                    "No expiry date is recorded for the Entra client secret. "
                    "Until one is, this page cannot warn you before sign-in "
                    "breaks - and the same secret is used by every vhost."))
    elif days < 0:
        out.append(("urgent",
                    "The Entra client secret EXPIRED %d day%s ago (%s). Sign-in "
                    "is either already broken or about to be, on the console and "
                    "on every vhost. %s"
                    % (-days, "" if days == -1 else "s", iso, rotate)))
    elif days <= EXPIRY_URGENT_DAYS:
        out.append(("urgent",
                    "The Entra client secret expires in %d day%s (%s). It is "
                    "shared by the console and every vhost, so all sign-in stops "
                    "that day. %s" % (days, "" if days == 1 else "s", iso, rotate)))
    elif days <= EXPIRY_NOTICE_DAYS:
        out.append(("warn",
                    "The Entra client secret expires in %d days (%s). %s"
                    % (days, iso, rotate)))

    # Drift: the Hub API holds a second copy of the same secret. If they have
    # diverged, one of the two sign-in surfaces is already broken or about to be.
    stored = sso.get("client_secret")
    hub = _hub_secret_digest()
    if stored and hub:
        mine = hashlib.sha256(str(stored).encode("utf-8")).hexdigest()
        if mine != hub:
            out.append(("urgent",
                        "The client secret stored here and the Hub API's copy in "
                        "%s are DIFFERENT. Only one of them can be the current "
                        "secret, so one sign-in path is broken. %s"
                        % (HUB_ENV_PATH, rotate)))
    elif stored and hub is None:
        out.append(("warn",
                    "Could not read the Hub API's copy of the client secret from "
                    "%s, so the two cannot be compared." % HUB_ENV_PATH))
    return out


def preflight(cfg):
    """Cross-field checks that a single value cannot catch on its own.

    Returns a list of human-readable problems. Enabling SSO with a placeholder
    client ID is the one that actually bites: the value is a non-empty string, so
    a truthiness check calls it configured and the first real sign-in fails.
    """
    problems = []
    sso = cfg.get("sso") or {}
    if sso.get("enabled"):
        for field, label in (("tenant_id", "Directory (tenant) ID"),
                             ("client_id", "Application (client) ID"),
                             ("client_secret", "Client secret"),
                             ("redirect_uri", "Redirect URI")):
            v = sso.get(field)
            if not v or (isinstance(v, str) and PLACEHOLDER_RE.match(v.strip())):
                problems.append("Single sign-on is enabled but %s is not set." % label)
            elif field == "client_secret" and isinstance(v, str) and GUID_RE.match(v.strip()):
                problems.append(
                    "The stored Client secret is a GUID, which means it is the Secret ID "
                    "rather than the secret Value. Generate a new secret in Entra and "
                    "paste the Value.")
        for field in ("tenant_id", "client_id"):
            v = sso.get(field)
            if v and isinstance(v, str) and not PLACEHOLDER_RE.match(v) and not GUID_RE.match(v.strip()):
                problems.append("%s is not a valid GUID." % field)

    # Claude limit approvals: the one-click raise must be smaller than the manager
    # amount. The root helper and the hub refuse the same thing, so this is the
    # readable version of that refusal.
    def _eff(path):
        v = _get(cfg, path)
        return BY_PATH[path].default if v is None else v
    sr = _eff("spend_alerts.approvals_self_raise")
    mr = _eff("spend_alerts.approvals_manager_raise")
    if isinstance(sr, int) and isinstance(mr, int) and not (sr < mr):
        problems.append("Claude limit approvals: the one-click self-raise (+$%d) must be less "
                        "than the manager amount (+$%d)." % (sr, mr))
    if _eff("spend_alerts.approvals_enabled") is True and not _eff("spend_alerts.approvals_escalation_emails"):
        problems.append("Claude limit approvals are on but nobody is listed to email when a "
                        "request cannot be routed.")
    if group_visible("Server updates"):
        ua = _eff("updates.allowed_actors")
        if not ua:
            problems.append("Server updates: list at least one person who may run them.")
        elif len(ua) > 10:
            problems.append("Server updates: list at most 10 people who may run them.")
    if group_visible("Prod web watch"):
        wa = _eff("webwatch.allowed_actors")
        if not wa:
            problems.append("Prod web watch: list at least one person who may clear a fence failure.")
        elif len(wa) > 10:
            problems.append("Prod web watch: list at most 10 people who may clear a fence failure.")
        wm = _eff("webwatch.repeat_critical_minutes")
        if isinstance(wm, int) and 0 < wm < 15:
            problems.append("Prod web watch: the reminder interval is 0 (off) or 15-240 minutes, not %d." % wm)
    return problems


def apply_form(cfg, form, actor):
    """Apply a submitted form. Returns (changes, problems).

    `changes` is a list of (label, before, after) for the audit log, with sensitive
    values reduced to a marker so a secret never reaches the log.
    """
    changes, problems = [], []
    for s in SETTINGS:
        if not group_visible(s.group):
            continue                              # not on this host's page; never applied
        if s.kind == "bool":
            raw = form.get(s.key)                 # unchecked box submits nothing
        elif s.key not in form:
            continue
        else:
            raw = form.get(s.key)

        try:
            value = coerce(s, raw)
        except SettingError as e:
            problems.append(str(e))
            continue

        if s.kind == "secret" and value == "":
            continue                              # blank = keep the existing secret

        before = _get(cfg, s.path)
        if before == value:
            continue
        _set(cfg, s.path, value)
        if s.sensitive:
            changes.append((s.label, "(set)" if before else "(unset)", "(replaced)"))
        elif s.kind == "email_list":
            changes.append((s.label, ", ".join(before or []), ", ".join(value)))
        else:
            changes.append((s.label, before, value))

    return changes, problems
