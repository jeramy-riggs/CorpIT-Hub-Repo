'use strict';
/* =====================================================================
 * ai-tools-lib.js — who is entitled to which AI tool, and the team
 * roll-up behind My Profile's "AI tools & usage" section.  (2026-09-09)
 *
 * TWO RULES SHAPE EVERY FUNCTION IN HERE.
 *
 * 1. ENTITLEMENT IS NEVER INFERRED FROM USAGE. A seat that has spent
 *    nothing is not an absent seat, and spend without a roster row is a
 *    data-quality problem, not a licence. Access comes from the Claude
 *    Admin API member roster (claude_member) and from the Microsoft
 *    licence-assignment report (insight_user_activity.licenses); usage
 *    comes from the cost and activity feeds. They are shown side by side
 *    and never substituted for one another.
 *
 * 2. THERE ARE THREE ANSWERS, NOT TWO: has access / does not have access
 *    / we could not determine it. The third is the one that gets dropped,
 *    and dropping it is how a stale feed renders as "nobody has Copilot".
 *    So the ABSENCE of a row is only reported as "no access" when the feed
 *    that would have carried it is fresh. Otherwise it is 'unavailable',
 *    with the reason and the as-of date attached, and the UI says so.
 *
 * The same distinction runs through usage: a month with no rows for an
 * entitled member is a measured zero (the cost report covers the whole
 * organisation for every synced day, and reconciles to the invoice), but
 * a month outside the collector's coverage window is not zero — it is
 * unknown, and periodCoverage says which of the two you are looking at.
 *
 * Authorization is NOT decided here. Callers resolve a scope with
 * scope-lib (the platform's one answer to "how much of the data may you
 * see") and hand it in; this module only turns a scope into a population.
 * ===================================================================== */

const fs = require('fs');
const orgTree = require('./org-tree-lib');
const spendAlert = require('./spend-alert-lib');

/* A roster older than this can still prove that somebody HAS a seat — a row is
 * positive evidence and carries its own date — but it can no longer prove that
 * somebody does NOT, because the seat may have been granted since. */
const CLAUDE_ROSTER_STALE_HOURS = 48;
/* Microsoft's licence report is published on its own multi-day cadence, so the
 * window is days, not hours. */
const COPILOT_FEED_STALE_DAYS = 10;

/* The one SKU that means "this person can use Microsoft 365 Copilot". Copilot
 * Studio trials also carry the word and are deliberately reported separately —
 * a viral trial is not the licence anybody is asking about. */
const M365_COPILOT = 'MICROSOFT 365 COPILOT';

const TEAM_SCOPE_KINDS = ['manager', 'director'];

/* The spend-limit early warning is a policy decision, not a constant, so it is
 * read rather than compiled in. Defaults are used verbatim when nothing has been
 * published, so the feature works before anybody configures it. */
const SPEND_ALERT_DEFAULTS = { threshold: spendAlert.THRESHOLD_DEFAULT, digestEnabled: false, digestHour: 13 };

/* Where the admin console publishes these. The console stores settings in its own
 * 0600 config.json, which this API (running as `corpit`) cannot read, so a root
 * helper republishes the three non-secret tunables to a root-owned, corpit-readable
 * file on every save — the same road /etc/corpit/shared/site-access.json and
 * /etc/corpit/shared/observability.json already travel.
 *
 * This used to be a MySQL table an API route wrote. That made two homes for one
 * setting and no audit trail; the console is now the only writer. */
// PATH-RELEASE-20260929: /etc/corpit/shared/spend-alerts.json via corpit-paths.js.
const SPEND_CFG_PATH = require('./corpit-paths').sharedFile('spend-alerts.json', 'SPEND_ALERT_CONFIG_PATH');
const SPEND_CFG_TTL_MS = 30000;
let spendCfgCache = { at: 0, value: null };

/* Values are re-validated HERE as well as in the helper. This process does not own
 * that file and must not trust its contents merely because a trusted writer usually
 * produces it. A key that is absent leaves the default alone: the console publishes
 * only what it manages, and silence is not an instruction to reset. */
function readSpendCfg() {
  const out = Object.assign({}, SPEND_ALERT_DEFAULTS, { source: 'default', path: SPEND_CFG_PATH, error: null });
  let raw;
  try {
    raw = fs.readFileSync(SPEND_CFG_PATH, 'utf8');
  } catch (e) {
    // No file yet is the normal state before the first console save, and the
    // defaults are genuinely in force. That is 'default', not a fault.
    if (e.code !== 'ENOENT') { out.source = 'unknown'; out.error = e.message; }
    return out;
  }
  let doc;
  try { doc = JSON.parse(raw); } catch (e) {
    // The file exists but cannot be read. Reporting this as 'default' would tell
    // an operator their console setting is in force when it is not.
    out.source = 'unknown'; out.error = 'not valid JSON: ' + e.message;
    return out;
  }
  if (!doc || typeof doc !== 'object') { out.source = 'unknown'; out.error = 'not an object'; return out; }
  out.source = 'console';
  // Which numbers the console actually published, as opposed to which ones fell
  // back to the constants in this file. The console only stores a setting an
  // operator CHANGED, so a threshold left on its declared default is never
  // written to the published file — and reporting that as "console" would hide a
  // future divergence between the registry's default and this file's.
  out.published = { threshold: false, digestHour: false };
  const t = Number(doc.threshold);
  if (Number.isFinite(t) && t >= 1 && t <= 99) { out.threshold = t; out.published.threshold = true; }
  const h = Number(doc.digestHour);
  if (Number.isFinite(h) && h >= 0 && h <= 23) { out.digestHour = h; out.published.digestHour = true; }
  // Only a literal true sends mail. Anything else — absent, "true", 1 — is off.
  out.digestEnabled = doc.digestEnabled === true;
  return out;
}

/* Cached for 30 seconds, so a console save takes effect without a restart and a
 * page render does not stat the file once per member. */
async function spendAlertConfig() {
  const now = Date.now();
  if (spendCfgCache.value && (now - spendCfgCache.at) < SPEND_CFG_TTL_MS) return spendCfgCache.value;
  const v = readSpendCfg();
  spendCfgCache = { at: now, value: v };
  return v;
}

/* A manager may choose their own percentage for their own list; this is that
 * choice, or null when they have never made one. Bounds are enforced on the way
 * in AND here — a row edited by hand must not be able to alert on everybody. */
async function managerThreshold(pool, email) {
  if (!email) return null;
  try {
    const [rows] = await pool.query(
      'SELECT threshold FROM ai_spend_alert_manager WHERE manager_email = ?', [String(email).toLowerCase()]);
    if (!rows.length) return null;
    return spendAlert.usableThreshold(rows[0].threshold);
  } catch (e) { return null; }
}

/* Whether this manager has switched their OWN spend-alert emails on. Default off:
 * the manager owns this, not the console, so it is theirs to turn on as they see
 * fit. Stored on the same per-manager row as their threshold. */
async function managerEmailAlert(pool, email) {
  if (!email) return false;
  try {
    const [rows] = await pool.query(
      'SELECT email_alert FROM ai_spend_alert_manager WHERE manager_email = ?', [String(email).toLowerCase()]);
    return !!(rows.length && Number(rows[0].email_alert) === 1);
  } catch (e) { return false; }
}



function lc(v) { return String(v == null ? '' : v).trim().toLowerCase(); }
function n2(v) { return Math.round((Number(v) || 0) * 100) / 100; }
function int(v) { return Number(v) || 0; }
/* claude_user_cost_daily.amount_cents is DECIMAL(18,6) — FRACTIONAL cents. One
 * person's September is 607.612540 cents, i.e. $6.0761254. Rounding each person
 * to the penny and then adding the pennies up is off by two cents across 63
 * people, and an AI spend report that does not tie to the invoice gets argued
 * with rather than acted on. So every row carries both: `spend` rounded for
 * display, and `spendRaw` at full precision for anything that adds. Totals are
 * summed raw and rounded exactly once, including when the front end recomputes
 * them for a filtered subset. */
function raw(v) { return Number(v) || 0; }

/* mysql2 hands DATE and DATETIME columns back as JS Date objects, and
 * String(date).slice(0,10) yields "Tue Sep 01" rather than an ISO date. Both
 * formatters below are explicit for that reason. */
function ymd(v) {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  if (isNaN(d)) return null;
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
function iso(v) {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return isNaN(d) ? null : d.toISOString();
}
function monthOf(s) { return /^\d{4}-(0[1-9]|1[0-2])$/.test(String(s || '')) ? String(s) : null; }
function currentMonth() { return new Date().toISOString().slice(0, 7); }
function monthLabel(m) {
  const d = new Date(Date.UTC(+String(m).slice(0, 4), +String(m).slice(5, 7) - 1, 1));
  return d.toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
}
function monthDays(m) { return new Date(Date.UTC(+String(m).slice(0, 4), +String(m).slice(5, 7), 0)).getUTCDate(); }

/* ───────────────────────── feed health ─────────────────────────
 * Every "we could not determine it" answer in this file traces back to one of
 * these. They are cheap (two indexed reads) and are read on every request
 * rather than cached, because a cached freshness stamp is exactly the thing
 * that goes stale without anyone noticing. */

/* ── how often a feed actually lands, measured rather than declared ──────────
 *
 * The page used to carry the sentence "refreshed hourly" as a literal. That was
 * true of the admin endpoints and FALSE of activity: the hourly cron passes
 * --skip-activity, so user_activity_daily only lands at 05:40 and 13:25. A
 * hard-coded cadence is also a promise this file cannot keep — the schedule
 * lives in root's crontab, which this process cannot read, so the moment an
 * operator edits it the page starts lying with no way to notice.
 *
 * So the cadence is INFERRED from the feed's own successful runs. It is
 * self-correcting: change the crontab and the page follows within a day. Three
 * answers, never two — as everywhere else in this file: a feed with too few
 * runs to measure reports confidence 'unknown' and NO cadence, rather than a
 * number derived from two samples.
 *
 * The window, not a point. Gaps are not uniform (the cost feed lands hourly
 * plus twice more a day; activity alternates ~8h and ~16h), so a single
 * "next refresh at HH:MM" would be wrong about half the time. p25/p75 of the
 * observed gaps give an honest range, and `confidence` says how tight it is.
 */
const CADENCE_MIN_SAMPLES = 5;      // 5 runs = 4 gaps; below this we do not guess
const CADENCE_WINDOW = 40;          // runs to look back over
const CADENCE_MAX_GAP_H = 24 * 14;  // a fortnight-long gap is an outage, not a cadence

function quantile(sorted, q) {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos), hi = Math.ceil(pos);
  return lo === hi ? sorted[lo] : sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

/* A phrase a person reads without doing arithmetic. Deliberately vague where the
 * measurement is vague: "about" is doing real work in every one of these.
 *
 * Driven by runsPerDay MEASURED over the observed span, not by 24/medianGap.
 * Those two disagree whenever the schedule is uneven, and the activity feed is
 * exactly that: 05:40 and 13:25 give gaps of ~7.75h and ~16.25h, so the median
 * gap is 7.75 and 24/7.75 reads as "3 times a day" for a feed that lands twice.
 * Counting the runs cannot make that mistake. */
function cadenceLabel(medianGapH, runsPerDay) {
  if (medianGapH == null || runsPerDay == null) return null;
  if (runsPerDay >= 20) return 'about every hour';
  if (runsPerDay >= 9) return 'every couple of hours';
  if (runsPerDay >= 1.6) {
    const perDay = Math.round(runsPerDay);
    return 'about ' + (perDay === 2 ? 'twice' : perDay + ' times') + ' a day';
  }
  if (runsPerDay >= 0.7) return 'about once a day';
  if (runsPerDay > 0) {
    const days = Math.max(2, Math.round(1 / runsPerDay));
    return 'about every ' + days + ' days';
  }
  return null;
}

/**
 * @param {Date[]} runs successful run timestamps, NEWEST FIRST
 * @param {Date|null} okAt the last successful run (runs[0] normally)
 */
function inferCadence(runs, okAt) {
  const none = {
    confidence: 'unknown', label: null, medianGapHours: null, runsPerDay: null,
    samples: runs.length, nextExpectedAt: null, nextExpectedFrom: null,
    nextExpectedTo: null, overdue: null,
  };
  if (!okAt || runs.length < CADENCE_MIN_SAMPLES) return none;

  const gaps = [];
  for (let i = 0; i < runs.length - 1; i++) {
    const a = new Date(runs[i]).getTime(), b = new Date(runs[i + 1]).getTime();
    if (!isFinite(a) || !isFinite(b)) continue;
    const h = (a - b) / 36e5;
    // A non-positive gap means two rows share a timestamp (a manual re-run
    // racing the cron); an enormous one is an outage. Neither describes the
    // schedule, so neither is allowed to move the median.
    if (h > 0.01 && h < CADENCE_MAX_GAP_H) gaps.push(h);
  }
  if (gaps.length < CADENCE_MIN_SAMPLES - 1) return Object.assign(none, { samples: gaps.length + 1 });

  // Runs per day, measured. This — not 24/medianGap — is what the human-readable
  // label is built from.
  //
  // Measured over the sum of the VALID gaps rather than newest-minus-oldest. The
  // two differ whenever a gap was rejected above: a feed that ran hourly for two
  // days, then nothing for a month, then hourly again spans 30+ days but only
  // ~48 hours of actual schedule. Dividing by the raw span reports that hourly
  // feed as "about once a day". Summing the gaps that survived the filter counts
  // only the time the feed was actually keeping to a cadence.
  const observedHours = gaps.reduce((a, b) => a + b, 0);
  const runsPerDay = observedHours > 12 ? gaps.length / (observedHours / 24) : null;

  gaps.sort((x, y) => x - y);
  const med = quantile(gaps, 0.5);
  const p25 = quantile(gaps, 0.25);
  const p75 = quantile(gaps, 0.75);
  // Spread relative to the middle. A tight schedule (hourly cron) lands near 0;
  // a bimodal one (05:40 + 13:25) lands high, and we say so instead of pretending
  // to know the minute.
  const spread = med > 0 ? (p75 - p25) / med : null;
  const confidence = spread == null ? 'unknown' : (spread <= 0.35 ? 'firm' : 'rough');

  const base = new Date(okAt).getTime();
  const now = Date.now();
  const to = base + p75 * 36e5;
  return {
    confidence,
    label: cadenceLabel(med, runsPerDay),
    medianGapHours: Math.round(med * 100) / 100,
    runsPerDay: runsPerDay == null ? null : Math.round(runsPerDay * 10) / 10,
    samples: gaps.length + 1,
    nextExpectedAt: new Date(base + med * 36e5).toISOString(),
    nextExpectedFrom: new Date(base + p25 * 36e5).toISOString(),
    nextExpectedTo: new Date(to).toISOString(),
    // Past the far edge of its own observed window. Not the same as `fresh`,
    // which asks a different question (is the DATA too old to reason from);
    // this one asks whether the JOB looks like it has missed a turn.
    overdue: now > to,
  };
}

async function claudeFeedHealth(pool, endpoint, staleHours) {
  const [lastRows] = await pool.query(
    'SELECT ran_at, status, error FROM claude_sync_log WHERE endpoint = ? ORDER BY id DESC LIMIT 1', [endpoint]);
  const [okRows] = await pool.query(
    "SELECT MAX(ran_at) AS ok_at, MAX(data_refreshed_at) AS data_at" +
    ' FROM claude_sync_log WHERE endpoint = ? AND status = ?', [endpoint, 'ok']);
  /* The successful runs behind the inferred cadence. Newest first, and ONLY
   * successful ones: a feed erroring every ten minutes is not a feed that
   * refreshes every ten minutes. */
  const [runRows] = await pool.query(
    'SELECT ran_at FROM claude_sync_log WHERE endpoint = ? AND status = ?' +
    ' ORDER BY ran_at DESC LIMIT ' + CADENCE_WINDOW, [endpoint, 'ok']);

  const last = lastRows[0] || null;
  const okAt = okRows[0] && okRows[0].ok_at ? new Date(okRows[0].ok_at) : null;
  /* Anthropic's OWN watermark, straight from data_refreshed_at on their response.
   * It is not the same clock as ran_at and is routinely behind it: ran_at is when
   * WE pulled, this is how current ANTHROPIC says the figures were when we did.
   * Presenting the pull time as "data current as of" is how a four-hour-old
   * number gets read as a live one, so both travel to the page and the page
   * labels them differently. */
  const dataAt = okRows[0] && okRows[0].data_at ? new Date(okRows[0].data_at) : null;
  const ageHours = okAt ? (Date.now() - okAt.getTime()) / 36e5 : null;
  const dataAgeHours = dataAt ? (Date.now() - dataAt.getTime()) / 36e5 : null;
  return {
    feed: endpoint,
    asOf: iso(okAt),
    ageHours: ageHours == null ? null : Math.round(ageHours * 10) / 10,
    dataAsOf: iso(dataAt),
    dataAgeHours: dataAgeHours == null ? null : Math.round(dataAgeHours * 10) / 10,
    lastRunAt: last ? iso(last.ran_at) : null,
    lastStatus: last ? last.status : null,
    lastError: last && last.error ? String(last.error).slice(0, 200) : null,
    everSynced: !!okAt,
    fresh: !!okAt && ageHours <= staleHours,
    staleAfterHours: staleHours,
    cadence: inferCadence(runRows.map((r) => r.ran_at), okAt),
  };
}

/* The Microsoft feeds write no sync log of their own, so freshness comes from
 * the rows: collected_at is when we pulled, report_date/report_refresh_date is
 * the date Microsoft's own report claims. Both are published, because they are
 * days apart and answering "how current is this?" with the wrong one is how a
 * four-day-old report gets presented as today's truth. */
async function copilotFeedHealth(pool) {
  const [licRows] = await pool.query(
    'SELECT MAX(collected_at) AS at, MAX(report_date) AS report_date, COUNT(*) AS n FROM insight_user_activity');
  const [useRows] = await pool.query(
    'SELECT MAX(collected_at) AS at, MAX(report_refresh_date) AS report_date, COUNT(*) AS n FROM copilot_app_usage');
  const shape = (r) => {
    const rows = int(r && r.n);
    const at = r && r.at ? new Date(r.at) : null;
    const ageDays = at ? (Date.now() - at.getTime()) / 864e5 : null;
    return {
      asOf: iso(at),
      reportDate: ymd(r && r.report_date),
      rows,
      ageDays: ageDays == null ? null : Math.round(ageDays * 10) / 10,
      fresh: ageDays != null && ageDays <= COPILOT_FEED_STALE_DAYS && rows > 0,
      staleAfterDays: COPILOT_FEED_STALE_DAYS,
    };
  };
  return { licence: shape(licRows[0]), usage: shape(useRows[0]) };
}

/** All the freshness stamps a caller needs to label a screen honestly. */
async function feeds(pool) {
  const [roster, limits, cost, activity, copilot] = await Promise.all([
    claudeFeedHealth(pool, 'members', CLAUDE_ROSTER_STALE_HOURS),
    claudeFeedHealth(pool, 'spend_limits', CLAUDE_ROSTER_STALE_HOURS),
    claudeFeedHealth(pool, 'user_cost_daily', CLAUDE_ROSTER_STALE_HOURS),
    claudeFeedHealth(pool, 'user_activity_daily', 72),
    copilotFeedHealth(pool),
  ]);
  return { claudeRoster: roster, claudeLimits: limits, claudeCost: cost, claudeActivity: activity, copilot };
}

/* ───────────────────────── licence parsing ───────────────────────── */

function parseCopilotLicences(txt) {
  const all = String(txt || '').split('+').map((s) => s.trim()).filter(Boolean);
  const copilot = all.filter((s) => s.toUpperCase().includes('COPILOT'));
  return {
    m365: copilot.filter((s) => s.toUpperCase() === M365_COPILOT),
    other: copilot.filter((s) => s.toUpperCase() !== M365_COPILOT),
  };
}

const COPILOT_APPS = [
  ['chat_last_active', 'Copilot chat'],
  ['teams_last_active', 'Teams'],
  ['outlook_last_active', 'Outlook'],
  ['word_last_active', 'Word'],
  ['excel_last_active', 'Excel'],
  ['powerpoint_last_active', 'PowerPoint'],
  ['onenote_last_active', 'OneNote'],
  ['loop_last_active', 'Loop'],
];

/* ───────────────────────── entitlement ─────────────────────────
 * One round trip per source for a whole population, so the team table costs the
 * same four queries as a single profile. */

/**
 * @param {object} pool
 * @param {string[]} emails
 * @param {object} [known] pre-fetched feed health, to avoid re-reading it per call
 * @returns {Promise<{rows: Map<string,object>, feeds: object}>}
 */
async function entitlements(pool, emails, known) {
  const list = Array.from(new Set((emails || []).map(lc).filter(Boolean)));
  const f = known || await feeds(pool);
  const rows = new Map();
  if (!list.length) return { rows, feeds: f };

  const [members, limits, licences, copuse] = await Promise.all([
    pool.query('SELECT LOWER(email) AS email, user_id, display_name, role, added_at FROM claude_member WHERE LOWER(email) IN (?)', [list]).then((r) => r[0]),
    pool.query("SELECT LOWER(email) AS email, amount_cents, currency, source_type, ptd_spend_cents FROM claude_spend_limit WHERE period = 'monthly' AND deleted = 0 AND LOWER(email) IN (?)", [list]).then((r) => r[0]),
    pool.query('SELECT LOWER(upn) AS email, licenses, report_date FROM insight_user_activity WHERE LOWER(upn) IN (?)', [list]).then((r) => r[0]),
    pool.query('SELECT LOWER(email) AS email, last_activity_date, chat_last_active, teams_last_active, word_last_active, excel_last_active, powerpoint_last_active, outlook_last_active, onenote_last_active, loop_last_active, report_refresh_date FROM copilot_app_usage WHERE LOWER(email) IN (?)', [list]).then((r) => r[0]),
  ]);

  const memberBy = new Map(members.map((r) => [r.email, r]));
  const limitBy = new Map(limits.map((r) => [r.email, r]));
  const licBy = new Map(licences.map((r) => [r.email, r]));
  const useBy = new Map(copuse.map((r) => [r.email, r]));

  for (const email of list) {
    const m = memberBy.get(email) || null;
    const lim = limitBy.get(email) || null;
    const lic = licBy.get(email) || null;
    const use = useBy.get(email) || null;

    // ── Claude. A member row is proof of a seat whatever the roster's age; the
    // absence of one only means "no seat" while the roster is fresh.
    let cAccess, cReason = null;
    if (!f.claudeRoster.everSynced) { cAccess = 'unavailable'; cReason = 'roster-never-synced'; }
    else if (m) { cAccess = 'active'; }
    else if (f.claudeRoster.fresh) { cAccess = 'none'; }
    else { cAccess = 'unavailable'; cReason = 'roster-stale'; }

    // ── Copilot, on exactly the same rule against the licence report.
    let pAccess, pReason = null, m365 = [], other = [];
    if (lic) {
      const p = parseCopilotLicences(lic.licenses);
      m365 = p.m365; other = p.other;
      if (m365.length) pAccess = 'licensed';
      else if (f.copilot.licence.fresh) pAccess = 'none';
      else { pAccess = 'unavailable'; pReason = 'licence-report-stale'; }
    } else if (!f.copilot.licence.fresh) { pAccess = 'unavailable'; pReason = 'licence-report-stale'; }
    else { pAccess = 'unavailable'; pReason = 'not-in-licence-report'; }

    rows.set(email, {
      email,
      claude: {
        access: cAccess,
        reason: cReason,
        userId: m ? m.user_id : null,
        displayName: m ? m.display_name : null,
        role: m ? m.role : null,
        addedAt: m ? iso(m.added_at) : null,
        asOf: f.claudeRoster.asOf,
        source: 'Claude Admin API — organization members',
        limit: lim ? {
          amount: n2(Number(lim.amount_cents) / 100),
          currency: lim.currency || 'USD',
          // 'seat_tier' is the plan-wide default every seat inherits; 'user' is a
          // limit somebody set for this person specifically. Saying which it is
          // stops a shared default reading as a personal decision.
          basis: lim.source_type === 'user' ? 'individual' : 'plan default',
          sourceType: lim.source_type || null,
          periodToDateSpend: n2(Number(lim.ptd_spend_cents) / 100),
          asOf: f.claudeLimits.asOf,
        } : null,
      },
      copilot: {
        access: pAccess,
        reason: pReason,
        licences: m365,
        otherCopilotLicences: other,
        asOf: f.copilot.licence.asOf,
        reportDate: ymd(lic && lic.report_date) || f.copilot.licence.reportDate,
        source: 'Microsoft 365 licence assignment report',
        // Activity is reported only when the person appears in Microsoft's Copilot
        // usage report at all. Absence there is not "never used it" — the report
        // only covers licensed users, and it lags its own refresh date.
        lastActivity: use ? ymd(use.last_activity_date) : null,
        activityKnown: !!use,
        activityAsOf: use ? ymd(use.report_refresh_date) : f.copilot.usage.reportDate,
        apps: use ? COPILOT_APPS.map(([col, name]) => ({ app: name, lastActive: ymd(use[col]) })).filter((a) => a.lastActive) : [],
      },
    });
  }
  return { rows, feeds: f };
}

/** Entitlement for exactly one person, with the feed stamps that qualify it. */
async function entitlementFor(pool, email, known) {
  const { rows, feeds: f } = await entitlements(pool, [email], known);
  return { entitlement: rows.get(lc(email)) || null, feeds: f };
}

/* ───────────────────────── reporting periods ─────────────────────────
 * The supported periods are the months the cost feed actually holds, not the
 * last N calendar months: offering a month the collector never covered invites
 * a screen full of zeroes that mean "we have no data", which is the one thing
 * this section must never say by drawing a zero. */

async function availablePeriods(pool, limit) {
  const n = Math.max(1, Math.min(24, int(limit) || 12));
  const [rows] = await pool.query(
    "SELECT DATE_FORMAT(day, '%Y-%m') AS month, COUNT(DISTINCT day) AS days, SUM(amount_cents)/100 AS spend " +
    'FROM claude_user_cost_daily GROUP BY month ORDER BY month DESC LIMIT ' + n);
  const cur = currentMonth();
  const out = rows.map((r) => ({
    month: r.month, label: monthLabel(r.month), isCurrent: r.month === cur,
    daysWithData: int(r.days), spend: n2(r.spend),
  }));
  // The current month belongs in the picker from its first day, before the first
  // day of data has landed.
  if (!out.some((p) => p.month === cur)) {
    out.unshift({ month: cur, label: monthLabel(cur), isCurrent: true, daysWithData: 0, spend: 0 });
  }
  return out;
}

/** Is this month inside what the cost feed can actually speak for? */
async function periodCoverage(pool, month, known) {
  const f = known || await feeds(pool);
  const [rows] = await pool.query('SELECT MIN(day) AS first_day, MAX(day) AS last_day FROM claude_user_cost_daily');
  const first = rows[0] && rows[0].first_day ? ymd(rows[0].first_day) : null;
  const last = rows[0] && rows[0].last_day ? ymd(rows[0].last_day) : null;
  const cur = currentMonth();
  const days = monthDays(month);
  const now = new Date();
  const elapsed = month === cur ? now.getUTCDate() : (month > cur ? 0 : days);

  let state = 'covered', note = null, partialFrom = null;
  if (!first) { state = 'unavailable'; note = 'The Claude usage feed holds no data at all.'; }
  else if (month > cur) { state = 'future'; note = 'That month has not started.'; }
  else if (month < first.slice(0, 7)) {
    state = 'before-coverage';
    note = 'Usage collection starts ' + first + '. Earlier months are not missing usage — they were never collected.';
  } else if (!f.claudeCost.everSynced) { state = 'unavailable'; note = 'The Claude usage collector has never completed a run.'; }
  else if (!f.claudeCost.fresh) {
    state = 'stale';
    note = 'The Claude usage collector last succeeded ' + (f.claudeCost.asOf || 'at an unknown time') + '; figures may be incomplete.';
  }
  // The first month of collection starts mid-month, so its total is a real number
  // over a shorter span — not a full month, and not comparable to one.
  if (first && month === first.slice(0, 7) && Number(first.slice(8, 10)) > 1) {
    partialFrom = first;
    note = note || ('Collection began ' + first + ', so this month covers ' + first.slice(8, 10) + '–' + days + ' only.');
  }
  return {
    month, label: monthLabel(month), isCurrent: month === cur,
    daysInMonth: days, daysElapsed: elapsed,
    state, note, partialFrom, usageFrom: first, usageThrough: last,
    // A zero is only a measured zero while the period is covered.
    zeroIsMeasured: state === 'covered' || state === 'stale',
  };
}

/* ───────────────────────── scope → population ─────────────────────────
 * scope-lib.scopeEmailSet() narrows to ai_user_org, which is Claude members
 * only. That is right for a spend report and wrong here: a manager has to be
 * able to see the report who has NO seat, clearly labelled, or the table
 * silently answers a different question ("my team's spenders") than the one it
 * is titled with. So the population comes from the AD-derived reporting closure
 * (org-tree-lib; the HR roster only fills gaps AD is missing), which is why a
 * no-seat report is still a row.
 *
 * The viewer is deliberately NOT in their own team roll-up: their own numbers
 * are the My usage tab, and keeping them out matches the population every other
 * scoped surface on the platform reports (scope-lib's chain walk is reports-only). */

/**
 * Who may see a team report, and whose.
 *
 * This is deliberately NOT the platform's `reporting` data-scope ladder. That
 * ladder grants org-wide reporting to members of an AD group, which is right for
 * the finance-style surfaces it was built for but wrong here: it handed the whole
 * company's AI usage to individual contributors who manage nobody. On this page
 * the only thing that opens a team view is actually having reports.
 *
 * The tree comes from Active Directory (`manager_upn` — the "Manager" and
 * "Direct reports" fields in the AD Organization tab), cached by org-tree-lib.
 * `manager` = has direct reports; `director` = manages managers. Nobody gets a
 * view wider than their own subtree, so there is no org-wide mode to leak.
 */
async function resolveTeamScope(pool, viewerEmail) {
  const email = lc(viewerEmail);
  const cache = await orgTree.ensureFresh(pool);
  const base = {
    email, kind: 'none', label: 'You', jobTitle: null, department: null, deptCode: null,
    directReports: 0, totalReports: 0, depthFromRoot: null, cache,
  };
  if (!email) return Object.assign(base, { note: 'No signed-in identity, so no team scope.' });
  if (cache.state === 'never') {
    return Object.assign(base, {
      kind: 'unavailable',
      note: 'The reporting hierarchy has not been built yet, so team access cannot be determined.',
    });
  }
  const p = await orgTree.person(pool, email);
  if (!p) {
    return Object.assign(base, {
      note: 'You are not in the Active Directory org tree, so no reporting line could be resolved.',
    });
  }
  const directs = Number(p.direct_reports) || 0;
  const scope = Object.assign(base, {
    displayName: p.display_name || email,
    jobTitle: p.job_title || null,
    department: p.department || null,
    deptCode: p.dept_code || null,
    managerEmail: p.manager_email || null,
    directReports: directs,
    totalReports: Number(p.total_reports) || 0,
    depthFromRoot: p.depth_from_root == null ? null : Number(p.depth_from_root),
  });
  if (!directs) {
    scope.note = 'Team reporting is for people with direct reports in Active Directory. Nobody reports to you, so you see only your own usage.';
    return scope;
  }
  scope.kind = Number(p.manages_managers) === 1 ? 'director' : 'manager';
  scope.label = (p.display_name || email) + (p.job_title ? ' · ' + p.job_title : '');
  return scope;
}

function teamScopeKind(scope) {
  return scope && TEAM_SCOPE_KINDS.includes(scope.kind) ? scope.kind : null;
}

/** Everyone at or below the viewer, with the depth that separates them. */
async function teamRows(pool, scope) {
  if (!teamScopeKind(scope)) return [];
  const [rows] = await pool.query(
    `SELECT e.member_email AS email, e.depth, p.display_name, p.job_title,
            p.department, p.dept_code, p.in_hr, p.direct_reports, p.total_reports,
            p.manager_email, mp.display_name AS manager_name
       FROM org_reporting_edge e
       JOIN org_reporting_person p ON p.email = e.member_email
       LEFT JOIN org_reporting_person mp ON mp.email = p.manager_email
      WHERE e.manager_email = ?`, [scope.email]);
  return rows;
}

async function teamEmails(pool, scope) {
  return (await teamRows(pool, scope)).map((r) => r.email);
}

/**
 * May this viewer open a named person's usage? Their own row always; otherwise
 * only somebody inside their subtree. One indexed lookup, no tree walk.
 */
async function mayViewMember(pool, scope, targetEmail) {
  const t = lc(targetEmail);
  if (!t) return false;
  if (scope && lc(scope.email) === t) return true;
  if (!teamScopeKind(scope)) return false;
  return (await orgTree.isManagerOf(pool, scope.email, t)) > 0;
}

function publicScope(scope, viewingAs) {
  return {
    kind: scope ? scope.kind : 'none',
    label: scope ? scope.label : 'You',
    jobTitle: scope ? scope.jobTitle || null : null,
    department: scope ? scope.department || null : null,
    deptCode: scope ? scope.deptCode || null : null,
    directReports: scope ? scope.directReports || 0 : 0,
    totalReports: scope ? scope.totalReports || 0 : 0,
    teamReporting: !!teamScopeKind(scope),
    source: 'active-directory',
    hierarchy: scope && scope.cache ? {
      state: scope.cache.state, refreshedAt: scope.cache.refreshedAt,
      ageMinutes: scope.cache.ageMinutes, people: scope.cache.people, managers: scope.cache.managers,
    } : null,
    note: scope ? scope.note || null : null,
    viewingAs: viewingAs || null,
  };
}

/* ───────────────────────── the team roll-up ───────────────────────── */

function inClause(column, emails) {
  return emails === null ? { sql: '', params: [] } : { sql: ' AND ' + column + ' IN (?)', params: [emails] };
}

/**
 * Everyone in scope, with entitlement and the selected month's usage.
 * @returns {Promise<object>} summary + departments + members, all computed from
 *          the same member rows so no tile can disagree with the table under it.
 */
async function teamReport(pool, scope, opts) {
  const o = opts || {};
  const month = monthOf(o.month) || currentMonth();
  const f = await feeds(pool);
  const coverage = await periodCoverage(pool, month, f);
  const rows = await teamRows(pool, scope);
  const emails = rows.map((r) => r.email);

  if (!emails.length) {
    return {
      scope: publicScope(scope, o.viewingAs), period: coverage,
      summary: emptySummary(), departments: [], members: [],
      viewerIncluded: false, viewerNote: null, reconciliation: null, feeds: f,
      note: 'Nobody reports to you in Active Directory, so there is no team to report on.',
    };
  }

  // The team's population is the AD subtree, so a person with no Claude seat and
  // no HR row still appears. `depth` is kept so the UI can separate the people who
  // report to the viewer directly from the rest of the organisation below them.
  const people = new Map();
  for (const r of rows) {
    people.set(r.email, {
      email: r.email,
      name: r.display_name || r.email,
      title: r.job_title || null,
      department: r.department || null,
      deptCode: r.dept_code || null,
      managerName: r.manager_name || null,
      managerEmail: r.manager_email || null,
      depth: Number(r.depth) || 1,
      direct: Number(r.depth) === 1,
      directReports: Number(r.direct_reports) || 0,
      totalReports: Number(r.total_reports) || 0,
      onRoster: Number(r.in_hr) === 1,
      contingent: false,
    });
  }

  const list = Array.from(people.keys());
  if (!list.length) {
    return { scope: publicScope(scope, o.viewingAs), period: coverage, summary: emptySummary(),
             departments: [], members: [], viewerIncluded: false, viewerNote: null, reconciliation: null, feeds: f };
  }

  const scoped = inClause('LOWER(email)', list);
  const prevSameSpan = coverage.isCurrent ? coverage.daysElapsed : 0;

  const [cost, act, tok, prev] = await Promise.all([
    pool.query(
      "SELECT LOWER(email) AS email, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests, " +
      'COUNT(DISTINCT day) AS days FROM claude_user_cost_daily ' +
      "WHERE DATE_FORMAT(day, '%Y-%m') = ?" + scoped.sql + ' GROUP BY LOWER(email)',
      [month].concat(scoped.params)).then((r) => r[0]),
    pool.query(
      'SELECT LOWER(email) AS email, SUM(cc_sessions) AS ccSessions, SUM(chat_conversations) AS chats, ' +
      'SUM(cowork_sessions) AS cowork, MAX(last_activity_date) AS lastActivity, ' +
      'COUNT(DISTINCT day) AS activeDays FROM claude_user_activity_daily ' +
      "WHERE DATE_FORMAT(day, '%Y-%m') = ?" + scoped.sql + ' GROUP BY LOWER(email)',
      [month].concat(scoped.params)).then((r) => r[0]),
    pool.query(
      'SELECT LOWER(email) AS email, SUM(total_tokens) AS tokens FROM claude_user_usage_daily ' +
      "WHERE DATE_FORMAT(day, '%Y-%m') = ?" + scoped.sql + ' GROUP BY LOWER(email)',
      [month].concat(scoped.params)).then((r) => r[0]),
    pool.query(
      'SELECT LOWER(email) AS email, SUM(amount_cents)/100 AS spend FROM claude_user_cost_daily ' +
      "WHERE DATE_FORMAT(day, '%Y-%m') = DATE_FORMAT(DATE_SUB(CONCAT(?, '-01'), INTERVAL 1 MONTH), '%Y-%m') " +
      'AND (? = 0 OR DAYOFMONTH(day) <= ?)' + scoped.sql + ' GROUP BY LOWER(email)',
      [month, prevSameSpan, prevSameSpan || 31].concat(scoped.params)).then((r) => r[0]),
  ]);

  const costBy = new Map(cost.map((r) => [r.email, r]));
  const actBy = new Map(act.map((r) => [r.email, r]));
  const tokBy = new Map(tok.map((r) => [r.email, r]));
  const prevBy = new Map(prev.map((r) => [r.email, r]));

  const { rows: ent } = await entitlements(pool, list, f);
  const alertCfg = await spendAlertConfig();
  // scope.email is whose team this is — the viewer, or the subject under View-As.
  // The threshold belongs to that person, so a borrowed view shows the number the
  // borrowed-from manager chose, not the borrower's.
  const ownThreshold = await managerThreshold(pool, scope.email);
  const ownEmailAlert = await managerEmailAlert(pool, scope.email);
  const eff = spendAlert.effectiveThreshold(ownThreshold, alertCfg.threshold);
  const threshold = eff.threshold;

  const members = [];
  for (const email of list) {
    const p = people.get(email);
    const e = ent.get(email) || { claude: { access: 'unavailable', reason: 'not-resolved' }, copilot: { access: 'unavailable', reason: 'not-resolved' } };
    const c = costBy.get(email) || null;
    const a = actBy.get(email) || null;
    const t = tokBy.get(email) || null;

    // usage is a NUMBER only when the period can speak for it. Outside coverage
    // it is null and renders as "—", never as 0.
    const measured = coverage.zeroIsMeasured;
    const hasAny = !!(c || a || t);
    members.push(Object.assign({}, p, {
      claudeAccess: e.claude.access,
      claudeAccessReason: e.claude.reason,
      claudeRole: e.claude.role,
      claudeAddedAt: e.claude.addedAt,
      claudeLimit: e.claude.limit,
      copilotAccess: e.copilot.access,
      copilotAccessReason: e.copilot.reason,
      copilotLastActivity: e.copilot.lastActivity,
      copilotLicences: e.copilot.licences,
      spend: measured ? n2(c ? c.spend : 0) : null,
      spendRaw: measured ? raw(c && c.spend) : null,
      requests: measured ? int(c && c.requests) : null,
      daysWithSpend: measured ? int(c && c.days) : null,
      sessions: measured ? int(a && a.ccSessions) : null,
      chats: measured ? int(a && a.chats) : null,
      coworkSessions: measured ? int(a && a.cowork) : null,
      activeDays: measured ? int(a && a.activeDays) : null,
      lastActivity: a ? ymd(a.lastActivity) : null,
      tokens: measured ? int(t && t.tokens) : null,
      prevSpend: measured ? n2(prevBy.has(email) ? prevBy.get(email).spend : 0) : null,
      prevSpendRaw: measured ? raw(prevBy.has(email) && prevBy.get(email).spend) : null,
      // How close this person is to their OWN Claude cap. Both numbers come from
      // the same Anthropic pull (claude_spend_limit), never from the cost feed --
      // a percentage mixing the two bases is one neither source would stand behind.
      limitPct: e.claude.limit ? spendAlert.pctOf(e.claude.limit.periodToDateSpend, e.claude.limit.amount) : null,
      limitState: e.claude.limit ? spendAlert.stateFor(e.claude.limit.periodToDateSpend, e.claude.limit.amount, threshold) : null,
      // The three usage states, decided once here so every renderer agrees.
      usageState: !measured ? 'unavailable'
        : e.claude.access === 'none' ? 'no-access'
          : hasAny ? 'active' : 'no-usage',
    }));
  }

  members.sort((x, y) => (y.spend || 0) - (x.spend || 0) || String(x.name).localeCompare(String(y.name)));

  const summary = summarise(members, coverage);
  const viewer = lc(o.viewerEmail);
  // Org scope is literally everybody, so the viewer is one of the rows. A leader or
  // manager scope is their REPORTS (scope-lib's chain walk excludes the root), so
  // their own usage is not in these totals — which the tab has to say out loud, or
  // a director reads a number they assume includes them.
  const viewerIncluded = !!viewer && members.some((m) => m.email === viewer);
  summary.directReports = members.filter((m) => m.direct).length;
  summary.extendedReports = members.length - summary.directReports;

  // Reconciliation to the organisation invoice was an org-scope concept. A
  // manager's subtree is a slice of the company by design, so a "remainder" here
  // would be meaningless rather than informative, and is deliberately not shown.
  const reconciliation = null;

  return {
    scope: publicScope(scope, o.viewingAs),
    period: coverage,
    summary, departments: byDepartment(members, coverage), members,
    // Direct reports at or over the threshold, worst first. Computed here so the
    // page, the ticket and the digest cannot disagree about who is in trouble.
    // A director is accountable for the whole subtree on this page, so the alert
    // list follows the same population; each entry says whose report it is.
    spendAlerts: spendAlert.alertsFor(members, coverage, threshold, { includeIndirect: scope.kind === 'director' }),
    alertThreshold: threshold,
    alertConfig: {
      threshold,
      // Which of the three the number came from, so the card can say so rather
      // than presenting a default as somebody's decision.
      thresholdSource: eff.source,
      consoleThreshold: alertCfg.threshold,
      managerThreshold: ownThreshold,
      configSource: alertCfg.source,
      configError: alertCfg.error || null,
      digestEnabled: alertCfg.digestEnabled,
      emailAlert: ownEmailAlert,
      includesIndirect: scope.kind === 'director',
    },
    viewerIncluded,
    viewerNote: viewerIncluded ? null : 'These figures cover the people who report to you. Your own usage is on the My usage tab.',
    reconciliation,
    feeds: f,
  };
}

function emptySummary() {
  return {
    people: 0, claudeActive: 0, claudeNone: 0, claudeUnknown: 0,
    copilotLicensed: 0, copilotNone: 0, copilotUnknown: 0,
    activeInPeriod: 0, noUsageInPeriod: 0, noAccessInPeriod: 0, usageUnavailable: 0,
    spend: 0, requests: 0, sessions: 0, chats: 0, coworkSessions: 0,
    tokens: 0, prevSpend: 0, momPct: null, spendKnown: false,
  };
}

function summarise(members, coverage) {
  const s = emptySummary();
  s.people = members.length;
  s.spendKnown = coverage.zeroIsMeasured;
  let spend = 0, prev = 0;
  for (const m of members) {
    if (m.claudeAccess === 'active') s.claudeActive++;
    else if (m.claudeAccess === 'none') s.claudeNone++;
    else s.claudeUnknown++;
    if (m.copilotAccess === 'licensed') s.copilotLicensed++;
    else if (m.copilotAccess === 'none') s.copilotNone++;
    else s.copilotUnknown++;
    // The four usage states are exhaustive and add up to `people`, so a team where
    // nobody has a seat reports 88 without access rather than an empty tile row.
    if (m.usageState === 'active') s.activeInPeriod++;
    else if (m.usageState === 'no-usage') s.noUsageInPeriod++;
    else if (m.usageState === 'no-access') s.noAccessInPeriod++;
    else if (m.usageState === 'unavailable') s.usageUnavailable++;
    spend += raw(m.spendRaw);
    prev += raw(m.prevSpendRaw);
    s.requests += int(m.requests);
    // Claude Code sessions are only one of the ways this organisation uses Claude —
    // a group that lives in chat and Cowork shows 0 sessions and is not idle. All
    // three are carried so no roll-up can call a team inactive on the wrong metric.
    s.sessions += int(m.sessions);
    s.chats += int(m.chats);
    s.coworkSessions += int(m.coworkSessions);
    s.tokens += int(m.tokens);
  }
  s.spend = n2(spend);
  s.prevSpend = n2(prev);
  s.momPct = coverage.zeroIsMeasured && prev > 0 ? n2((spend / prev - 1) * 100) : null;
  s.momBasis = coverage.isCurrent ? 'same-span' : 'full-month';
  if (!coverage.zeroIsMeasured) {
    s.spend = null; s.requests = null; s.sessions = null; s.chats = null;
    s.coworkSessions = null; s.tokens = null; s.prevSpend = null;
  }
  return s;
}

function byDepartment(members, coverage) {
  const map = new Map();
  for (const m of members) {
    const key = m.department || 'Unassigned';
    if (!map.has(key)) map.set(key, { department: key, deptCode: m.deptCode || null, people: 0, claudeActive: 0, copilotLicensed: 0, activeInPeriod: 0, spend: 0, sessions: 0, chats: 0, coworkSessions: 0 });
    const d = map.get(key);
    d.people++;
    if (m.claudeAccess === 'active') d.claudeActive++;
    if (m.copilotAccess === 'licensed') d.copilotLicensed++;
    if (m.usageState === 'active') d.activeInPeriod++;
    d.spend += raw(m.spendRaw);
    d.sessions += int(m.sessions);
    d.chats += int(m.chats);
    d.coworkSessions += int(m.coworkSessions);
  }
  const out = Array.from(map.values()).map((d) => Object.assign(d, {
    spend: coverage.zeroIsMeasured ? n2(d.spend) : null,
    sessions: coverage.zeroIsMeasured ? d.sessions : null,
    chats: coverage.zeroIsMeasured ? d.chats : null,
    coworkSessions: coverage.zeroIsMeasured ? d.coworkSessions : null,
  }));
  out.sort((a, b) => (b.spend || 0) - (a.spend || 0) || b.claudeActive - a.claudeActive || String(a.department).localeCompare(String(b.department)));
  return out;
}

// Test seam: the feed-health probe, so a harness can exercise the inferred
// cadence against a fake pool without a database.
module.exports = {
  __test_feedHealth: claudeFeedHealth,

  entitlements, entitlementFor, feeds, availablePeriods, periodCoverage,
  resolveTeamScope, teamScopeKind, teamEmails, teamRows, mayViewMember, teamReport, publicScope,
  spendAlertConfig, managerThreshold, managerEmailAlert, SPEND_ALERT_DEFAULTS,
  parseCopilotLicences, monthLabel, currentMonth,
  CLAUDE_ROSTER_STALE_HOURS, COPILOT_FEED_STALE_DAYS, M365_COPILOT,
};
