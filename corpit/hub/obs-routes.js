// ---------------------------------------------------------------------------
// obs-routes.js - the observability API.                            2026-09-06
//
// Mount: app.use('/api/observe', require('./obs-routes'));
//
// Two very different kinds of route live here, with deliberately different
// gates:
//
//   POST /api/observe/client   INGEST. Any signed-in user, no page grant.
//       Every page must be able to report its own failure. Gating this on a
//       page grant would mean the pages whose users cannot see the dashboard
//       are exactly the pages that never report - which is backwards.
//
//   GET  /api/observe/*        READ. Requires the 'observability' page grant.
//       These aggregate failures across every page and every user, so they are
//       a genuine cross-surface view and are gated like one.
//
// The page key is registered explicitly in rbac_pages. An UNLISTED page key
// does not fail closed on this platform - it inherits each role's
// default_access, which would silently hand tier2 (10 users) admin. Registering
// it makes the access an intentional decision instead of an accident.
//
// Every read applies the four-state rule the rest of this platform now uses:
// a query that FAILS reports 'unknown'. It never reports zero rows, because
// zero rows reads as an all-clear and "I could not measure" is not an
// all-clear. That confusion is what let Cert Watchtower report ok/142d for
// four months after its cron died.
// ---------------------------------------------------------------------------
'use strict';

const express = require('express');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const obs = require('./obs-lib');
const obsJob = require('./obs-job');
const obsDep = require('./obs-dependency');

const router = express.Router();

const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT) || 3306,
  database:           process.env.DB_NAME,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:    4,
  charset:            'utf8mb4',
});

const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

const PAGE = 'observability';
const needRead = rbac.requirePage(PAGE, 'read');

// This pool serves the dashboard's own gated reads and NOTHING else. It used
// to be handed to obs.setPool() here as well, which -- because this file is
// required long after server.js sets the pool -- silently moved the buffer
// flusher onto these four connections. Opening the observability page then took
// connections away from the writer whose output the page was rendering.

// ---------------------------------------------------------------------------
// INGEST
// ---------------------------------------------------------------------------

// Must not be below it-observe.js MAX_QUEUE. envelope() ships the WHOLE queue
// in one POST, so a server cap below the client cap discards the tail of every
// full payload -- and the tail, during a cascading failure, is the newest and
// most diagnostic part. It was 50 against a client queue of 100: half of every
// full report was dropped with no counter and no log, while both ends reported
// success (the client resolves on any response and this route answers 204 by
// design). Anything still over the cap is counted below.
const MAX_EVENTS = 100;         // per POST; matches it-observe.js MAX_QUEUE
const KINDS = new Set(['error', 'rejection', 'fetch_fail', 'resource_fail', 'degraded', 'slow']);
const SEVERITIES = new Set(['info', 'warn', 'error']);

// A per-actor minute budget, on top of the global rate limiter. A page stuck in
// a render loop can emit thousands of identical errors a second; without this
// one broken tile could fill the table. Dropped events are COUNTED and reported
// by /summary, so the dashboard can say it is not seeing everything rather than
// quietly under-reporting.
const budget = new Map();       // actorKey -> { minute, used }
let ingestDropped = 0;
// Events past MAX_EVENTS in a single POST. Separate from ingestDropped because
// the causes and the fixes differ: budget drops mean a page is too loud,
// truncation means the two halves of this feature disagree about their own cap.
let ingestTruncated = 0;
const PER_ACTOR_PER_MIN = 200;

function withinBudget(key) {
  const m = Math.floor(Date.now() / 60000);
  let b = budget.get(key);
  if (!b || b.minute !== m) { b = { minute: m, used: 0 }; budget.set(key, b); }
  // FC-13. This used to be budget.clear(): at the 501st distinct actor it wiped
  // EVERY actor's counter in the same tick. The one moment 500+ actors appear at
  // once is a platform-wide incident -- exactly when the storm control has to
  // hold -- and that is precisely when it forgave everyone and let the flood
  // through. Drop only entries belonging to a minute that has already passed:
  // they can never deny anything again, so losing them costs nothing.
  if (budget.size > 500) {
    for (const [k, v] of budget) if (v.minute !== m) budget.delete(k);
    // Still >5000 live counters inside ONE minute means something pathological.
    // Refuse the newcomer rather than forgive the incumbents; the caller counts
    // the refusal in ingestDropped, so it is reported rather than silent.
    if (budget.size > 5000) return false;
  }
  if (b.used >= PER_ACTOR_PER_MIN) return false;
  b.used++;
  return true;
}

// The raw User-Agent is a strong fingerprinting vector and is not needed. What
// IS diagnostic is "which engine and platform", so only that is kept.
function uaFamily(ua) {
  const s = String(ua || '');
  let br = 'other';
  if (/Edg\//.test(s)) br = 'Edge';
  else if (/OPR\//.test(s)) br = 'Opera';
  else if (/Chrome\/(\d+)/.test(s)) br = 'Chrome ' + RegExp.$1;
  else if (/Firefox\/(\d+)/.test(s)) br = 'Firefox ' + RegExp.$1;
  else if (/Version\/(\d+).*Safari/.test(s)) br = 'Safari ' + RegExp.$1;
  let os = 'other';
  if (/Windows NT/.test(s)) os = 'Windows';
  else if (/Mac OS X/.test(s)) os = 'macOS';
  else if (/Android/.test(s)) os = 'Android';
  else if (/iPhone|iPad/.test(s)) os = 'iOS';
  else if (/Linux/.test(s)) os = 'Linux';
  return (br + ' / ' + os).slice(0, 48);
}

const CLIENT_TABLE = 'obs_client_event';
const CLIENT_COLS = ['occurred_at', 'kind', 'severity', 'page', 'app_key', 'widget',
                     'message', 'detail', 'source', 'line', 'col', 'target_url',
                     'http_status', 'duration_ms', 'actor_key', 'session_key',
                     'viewport', 'ua_family', 'app_version', 'fingerprint', 'request_id'];

router.post('/client', function (req, res) {
  // Ingest answers 204 in every case, including when it rejects the payload.
  // A beacon has nobody to show an error to, and a page that starts logging
  // "my error logger returned 400" has made the original problem worse.
  try {
    const body = req.body || {};
    const sent = Array.isArray(body.events) ? body.events : [];
    const events = sent.slice(0, MAX_EVENTS);
    if (sent.length > events.length) ingestTruncated += sent.length - events.length;
    if (!events.length) return res.status(204).end();

    const u = req.user || {};
    const actor = obs.actorKey(u.upn || u.email || u.username || null);
    const uaf = uaFamily(req.get('user-agent'));
    // Identity comes from the SESSION, never from the payload. A client-supplied
    // actor would let any signed-in user attribute events to anyone else.
    const page = obs.clip(obs.normalizePath(String(body.page || '').split('?')[0]), 160) || '';
    // P-2. clip() is String().slice() and nothing else, so these two were the
    // only client-supplied strings on this route reaching the database with no
    // redaction and no character class -- an ingest POST could put anything in
    // them. They are an app slug and a version, so constrain them to that.
    const appKey = obs.clip(String(body.appKey || '').replace(/[^A-Za-z0-9._-]/g, ''), 64) || null;
    const appVersion = obs.clip(String(body.appVersion || '').replace(/[^A-Za-z0-9._+-]/g, ''), 32) || null;
    const sessionKey = obs.clip(String(body.sessionKey || '').replace(/[^A-Za-z0-9]/g, ''), 16);
    const viewport = obs.clip(String(body.viewport || '').replace(/[^0-9x]/g, ''), 16);

    for (const e of events) {
      if (!e || typeof e !== 'object') continue;
      if (!withinBudget(actor || 'anon')) { ingestDropped++; continue; }

      const kind = KINDS.has(e.kind) ? e.kind : 'error';
      const severity = SEVERITIES.has(e.severity) ? e.severity
                     : (kind === 'degraded' ? 'warn' : 'error');
      // Redaction happens HERE, on the way in. Storing raw and redacting on
      // display would mean the unredacted value is what is actually persisted.
      const message = obs.clip(obs.scrub(e.message), 512) || '';
      // scrubText, not scrub: both of these routinely carry a whole page URL
      // (ev.filename is the document url on a single-file page, and every stack
      // frame repeats it), and scrub() cannot see a query string.
      const detail = obs.clip(obs.scrubText(e.detail), 2000);
      const source = obs.clip(obs.scrubText(e.source), 255);
      const target = obs.clip(obs.redactUrl(e.url), 512);
      // P-3. The character filter alone was worse than nothing here: '@' is not
      // in the allowed set, so an address arriving as a widget key had its '@'
      // DELETED and everything else kept -- jkeith@auction.com stored as
      // jkeithauction.com, which no downstream email pattern can find. Scrub
      // first (that is what turns an address into a token), then constrain.
      const widget = obs.clip(String(obs.scrub(e.widget) || '').replace(/[^\w .:/-]/g, ''), 96);
      const at = parseAt(e.at);

      obs.push(CLIENT_TABLE, CLIENT_COLS, [
        at, kind, severity, page, appKey, widget, message, detail, source,
        intOrNull(e.line, 0, INT32), intOrNull(e.col, 0, INT32), target,
        intOrNull(e.status, 0, SMALLINT), intOrNull(e.durationMs, 0, INT32),
        actor, sessionKey || null, viewport || null, uaf, appVersion,
        // Grouping key. Excludes the actor and the timestamp so one broken
        // widget is ONE row on the dashboard, not one row per person who hit it.
        obs.fingerprint([kind, page, widget, message, source, e.line, target, e.status]),
        /^[a-f0-9-]{36}$/.test(String(e.requestId || '')) ? e.requestId : null,
      ]);
    }
    return res.status(204).end();
  } catch (err) {
    return res.status(204).end();
  }
});

// Clamped to the COLUMN, not merely "is it a number". The body of this POST is
// open to any signed-in user with no page grant, and obs-lib flushes buffered
// rows in one multi-row INSERT: under STRICT_TRANS_TABLES a single crafted
// http_status=99999 is error 1264 for the whole statement, so one caller could
// discard everyone else's events indefinitely. Verified against this schema -
// a 3-row INSERT with one out-of-range value fails whole.
const INT32 = 2147483647;
const SMALLINT = 32767;   // obs_client_event.http_status
function intOrNull(v, lo, hi) {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  const t = Math.trunc(n);
  return (lo == null) ? t : Math.min(hi, Math.max(lo, t));
}

// A client clock can be wrong or deliberately wrong. Anything outside a sane
// window around now is replaced with now, so one machine with a bad clock
// cannot park rows in 2031 and make every "last 24h" query miss them.
function parseAt(v) {
  const now = Date.now();
  const t = v ? Date.parse(v) : NaN;
  if (!Number.isFinite(t) || Math.abs(now - t) > 6 * 3600 * 1000) return obs.nowSql();
  return obs.nowSql(new Date(t));
}

// ---------------------------------------------------------------------------
// READ
// ---------------------------------------------------------------------------

function hoursOf(req) {
  const h = Number(req.query.hours);
  return (Number.isFinite(h) && h > 0 && h <= 720) ? Math.round(h) : 24;
}

// Wraps a read so a failed query becomes state:'unknown' instead of an empty
// list. This is the whole discipline of the exercise in four lines.
function measured(handler) {
  return async function (req, res) {
    try {
      const data = await handler(req);
      // Every read carries the recording state. A panel that gets zero rows
      // cannot otherwise tell "measured, and it really is zero" from "the
      // collector was switched off for this whole window", and those must not
      // render the same way. See emptyBlock() on the dashboard.
      res.json(Object.assign({
        ok: true, state: 'measured',
        recording: {
          enabled: obs.CFG.enabled,
          note: 'Read from this process. A second app also writes obs_request / ' +
                'obs_dependency and can be switched off independently by ' +
                'OBS_ENABLED in its own environment.',
        },
      }, data));
    } catch (e) {
      res.status(200).json({
        ok: false, state: 'unknown',
        error: e.code || e.message,
        detail: 'This panel could not be measured. It is NOT reporting an all-clear.',
      });
    }
  };
}

router.get('/summary', needRead, measured(async function (req) {
  const hours = hoursOf(req);
  const kindsPromise = pool.query(
    'SELECT kind, severity, COUNT(*) n FROM obs_client_event ' +
    'WHERE occurred_at >= NOW() - INTERVAL ? HOUR GROUP BY kind, severity', [hours]);
  // COALESCE is load-bearing, not tidiness. An aggregate with no GROUP BY
  // returns exactly one row, and over zero matching rows MySQL's SUM() returns
  // NULL while COUNT(*) correctly returns 0. The dashboard renders NULL as the
  // em-dash -- this platform's own symbol for "not measured" -- but colours it
  // from n(null)===0, so an empty window painted a GREEN em-dash on the
  // "Upstream failures" and "Server 5xx" tiles. A measured zero must read as
  // the digit 0. MAX(duration_ms) is deliberately left NULL: with no rows there
  // genuinely is no slowest request, and the page renders that as unmeasured.
  const reqAggPromise = pool.query(
    'SELECT COUNT(*) total, COALESCE(SUM(status >= 500),0) e5, ' +
    // 499 is obs-middleware's marker for "the connection closed before the
    // response completed" -- nginx's convention, not a status any client
    // received. It is excluded from e4 because it is not a client error the
    // application produced, and reported on its own so that adding the ability
    // to see aborts does not silently inflate the 4xx figure that was already
    // on the page.
    '       COALESCE(SUM(status BETWEEN 400 AND 498),0) e4, ' +
    '       COALESCE(SUM(status = 499),0) aborted, ' +
    '       COALESCE(SUM(sampled = 1),0) sampled, MAX(duration_ms) slowest ' +
    'FROM obs_request WHERE at >= NOW() - INTERVAL ? HOUR', [hours]);
  const depAggPromise = pool.query(
    'SELECT COUNT(*) total, COALESCE(SUM(ok = 0),0) failed, COUNT(DISTINCT vendor) vendors ' +
    'FROM obs_dependency WHERE at >= NOW() - INTERVAL ? HOUR', [hours]);
  const jobsPromise = obsJob.resolve(pool);
  const [[kinds], [reqAgg], [depAgg], jobs] = await Promise.all([
    kindsPromise, reqAggPromise, depAggPromise, jobsPromise,
  ]);

  return {
    hours: hours,
    client: kinds,
    // `sampled` is reported alongside the total precisely so nobody reads
    // obs_request as a complete access log. It is not one, by design.
    requests: Object.assign({}, reqAgg[0], {
      note: 'Failures and slow requests are recorded in full; ordinary fast 2xx ' +
            'are sampled at ' + (obs.CFG.sampleRate * 100).toFixed(1) + '%. ' +
            'Totals here are NOT total traffic.',
    }),
    dependencies: depAgg[0],
    // `declared` travels with the counts deliberately: the strip renders from
    // this payload alone, and counts:{} is identical whether nothing is wrong or
    // nothing is declared. That ambiguity is what painted the tile green.
    // `undeclared` is the other half of the same honesty problem: counts are
    // computed over the registry, so a job nobody declared contributes nothing
    // to them and cannot be missing from them either. null means the check did
    // not run - which is not the same as "none", and must not render as none.
    jobs: { state: jobs.state, counts: jobs.counts, declared: jobs.declared,
            undeclared: jobs.undeclared === null ? null : jobs.undeclared.length,
            host: jobs.host },
    pipeline: Object.assign({}, obs.stats(), obsDep.stats(),
                            { ingestDropped: ingestDropped, ingestTruncated: ingestTruncated }),
  };
}));

// Grouped client failures. This is the layer-1 payoff: a tile that renders an
// em-dash for one user is invisible today, and becomes a counted row here.
router.get('/client', needRead, measured(async function (req) {
  const hours = hoursOf(req);
  const kind = KINDS.has(req.query.kind) ? req.query.kind : null;
  const params = [hours];
  let where = 'occurred_at >= NOW() - INTERVAL ? HOUR';
  if (kind) { where += ' AND kind = ?'; params.push(kind); }
  const [rows] = await pool.query(
    'SELECT fingerprint, kind, severity, page, app_key, widget, message, source, line, ' +
    '       target_url, http_status, COUNT(*) n, COUNT(DISTINCT actor_key) actors, ' +
    '       MIN(occurred_at) first_seen, MAX(occurred_at) last_seen ' +
    'FROM obs_client_event WHERE ' + where + ' ' +
    'GROUP BY fingerprint, kind, severity, page, app_key, widget, message, source, line, target_url, http_status ' +
    'ORDER BY n DESC LIMIT 200', params);
  // A count is not a list length: say plainly when the list was truncated, so
  // nobody reads 200 as "there were 200".
  return { hours: hours, groups: rows, truncated: rows.length === 200 };
}));

// The degraded-render signal on its own. "How often does this page tell a user
// it does not know, and which tile is responsible?"
// B-12. it-observe.js reports at most MAX_PER_FP (5) events per fingerprint per
// page-load, and appends this sentence to the detail of the last one it lets
// through. So COUNT(*) here is how many times the tile was REPORTED, not how
// many times it degraded -- a render loop that painted 'unknown' 500 times
// arrives as n=5. Below the cap the two numbers are equal, which is exactly why
// nobody would notice the column was wrong until an incident made them differ.
// Coupled by text to the string in it-observe.js record(); change both together.
const CAP_MARK = '%from this page-load are suppressed%';

router.get('/degraded', needRead, measured(async function (req) {
  const hours = hoursOf(req);
  const [rows] = await pool.query(
    'SELECT page, app_key, widget, message, COUNT(*) n, COUNT(DISTINCT actor_key) actors, ' +
    '       SUM(detail LIKE ?) capped, MAX(occurred_at) last_seen ' +
    'FROM obs_client_event WHERE kind = ? AND occurred_at >= NOW() - INTERVAL ? HOUR ' +
    'GROUP BY page, app_key, widget, message ORDER BY n DESC LIMIT 200',
    [CAP_MARK, 'degraded', hours]);
  return { hours: hours, widgets: rows, truncated: rows.length === 200 };
}));

router.get('/requests', needRead, measured(async function (req) {
  const hours = hoursOf(req);
  const [rows] = await pool.query(
    'SELECT app, method, route, COUNT(*) n, SUM(status >= 500) e5, ' +
    '       SUM(status BETWEEN 400 AND 498) e4, SUM(status = 499) aborted, ' +
    '       ROUND(AVG(duration_ms)) avg_ms, ' +
    '       MAX(duration_ms) max_ms, MAX(at) last_seen, SUM(sampled = 0) kept_because_failed_or_slow ' +
    'FROM obs_request WHERE at >= NOW() - INTERVAL ? HOUR ' +
    'GROUP BY app, method, route ORDER BY e5 DESC, n DESC LIMIT 200', [hours]);
  const [recent] = await pool.query(
    'SELECT at, app, method, route, status, duration_ms, err FROM obs_request ' +
    'WHERE at >= NOW() - INTERVAL ? HOUR AND status >= 400 ORDER BY at DESC LIMIT 100', [hours]);
  // SL-14. That list is capped at 100 and reported the cap nowhere. Right now
  // the window holds 152 failures, so the panel showed 100 of them and read as
  // complete -- the same trap as outdatedCount 569 beside a 500-long array: a
  // count is not a list length. Send both numbers and let the page say which is
  // which. ix_or_status_time covers (status, at), so this count is index-only.
  const [[rc]] = await pool.query(
    'SELECT COUNT(*) n FROM obs_request ' +
    'WHERE at >= NOW() - INTERVAL ? HOUR AND status >= 400', [hours]);
  return { hours: hours, routes: rows, recentFailures: recent,
           recentFailuresTotal: rc.n, truncated: rows.length === 200 };
}));

router.get('/dependencies', needRead, measured(async function (req) {
  const hours = hoursOf(req);
  const [rows] = await pool.query(
    'SELECT vendor, COUNT(*) n, SUM(ok = 0) failed, SUM(status IS NULL) no_response, ' +
    '       SUM(status = 429) throttled, SUM(status IN (401,403)) refused, ' +
    '       ROUND(AVG(duration_ms)) avg_ms, MAX(duration_ms) max_ms, MAX(at) last_seen ' +
    'FROM obs_dependency WHERE at >= NOW() - INTERVAL ? HOUR ' +
    'GROUP BY vendor ORDER BY failed DESC, n DESC', [hours]);
  const [recent] = await pool.query(
    'SELECT at, vendor, operation, method, host, path, status, duration_ms, err ' +
    'FROM obs_dependency WHERE at >= NOW() - INTERVAL ? HOUR AND ok = 0 ' +
    'ORDER BY at DESC LIMIT 100', [hours]);
  // OBS-12. Same cap, and this route carried no truncation flag of any kind --
  // the vendor rollup above it is unlimited, so the only capped thing on the
  // panel was the one list nothing described. ix_od_vendor_ok covers (vendor,
  // ok, at); this is a range scan over the window, not a table scan.
  const [[rc]] = await pool.query(
    'SELECT COUNT(*) n FROM obs_dependency ' +
    'WHERE at >= NOW() - INTERVAL ? HOUR AND ok = 0', [hours]);
  return { hours: hours, vendors: rows, recentFailures: recent,
           recentFailuresTotal: rc.n, coverage: obsDep.stats() };
}));

router.get('/jobs', needRead, measured(async function () {
  const r = await obsJob.resolve(pool);
  if (r.state === 'unknown') throw Object.assign(new Error(r.error || 'job join failed'), { code: r.error });
  return { jobs: r.jobs, counts: r.counts, declared: r.declared, jobsState: r.state,
           undeclared: r.undeclared, host: r.host,
           unattributedMeasured: r.unattributedMeasured, scannedAt: r.scannedAt };
}));

// Health of the observability system itself. If this is broken, every panel
// above is reporting less than it appears to, and that must be visible.
router.get('/self', needRead, measured(async function () {
  const tables = ['obs_client_event', 'obs_request', 'obs_dependency', 'obs_job'];
  const out = {};
  for (const t of tables) {
    try {
      const [r] = await pool.query('SELECT COUNT(*) n FROM `' + t + '`');
      out[t] = { state: 'ok', rows: r[0].n };
    } catch (e) {
      out[t] = { state: 'unknown', error: e.code || e.message };
    }
  }
  return { tables: out, pipeline: Object.assign({}, obs.stats(), obsDep.stats(),
           { ingestDropped: ingestDropped, ingestTruncated: ingestTruncated,
             perActorPerMin: PER_ACTOR_PER_MIN, maxEventsPerPost: MAX_EVENTS }) };
}));

module.exports = router;
