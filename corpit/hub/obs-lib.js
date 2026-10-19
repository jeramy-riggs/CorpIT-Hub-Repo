// ---------------------------------------------------------------------------
// obs-lib.js - the shared spine of CorpIT observability.            2026-09-06
//
// Everything that records anything goes through here, so that redaction and
// the "never break the thing you are observing" rule are written ONCE.
//
// Three hard rules, in priority order:
//
//   1. Observability must never break the request it observes. Every public
//      function is wrapped so that a failure inside it is swallowed. A logger
//      that can 500 a page is worse than no logger.
//   2. Observability must never block. Writes go into a bounded in-memory
//      buffer and are flushed on a timer by a single-flight flusher. If the
//      database is down the buffer drops its OLDEST entries and keeps serving.
//   3. Observability must never become a second copy of the data it watches.
//      No bodies, no headers, no employee identifiers. URLs are redacted
//      before they are stored, not after.
//
// Rule 3 is not decoration. These pages carry employee UPNs in query strings
// (/api/photo?upn=...@auction.com), in path segments (/api/identity/user/...),
// and in row payloads (user_upn in the ZCC drift rows). An unredacted request
// log would quietly build a searchable index of who looked up whom.
// ---------------------------------------------------------------------------
'use strict';

const crypto = require('crypto');
const fs = require('fs');

// -- configuration ----------------------------------------------------------
// Settings an operator may want to change belong in the console (the standing
// rule: no setting lives outside the console). These are the floor values used
// before the console has said otherwise, plus the kill switch.
function numEnv(k, d) { const v = Number(process.env[k]); return Number.isFinite(v) ? v : d; }

const CFG = {
  enabled:       process.env.OBS_ENABLED !== '0',   // default ON; OBS_ENABLED=0 disables everything
  app:           process.env.OBS_APP || 'hub-api',
  sampleRate:    numEnv('OBS_SAMPLE_RATE', 0.02),   // fraction of ordinary fast 2xx kept
  slowMs:        numEnv('OBS_SLOW_MS', 2000),       // always keep requests slower than this
  bufferMax:     numEnv('OBS_BUFFER_MAX', 2000),    // per-table cap; oldest dropped past it
  flushMs:       numEnv('OBS_FLUSH_MS', 5000),
  clientMaxBody: numEnv('OBS_CLIENT_MAX_BODY', 65536),
  // Retention. Nothing in this build deleted a row until obs-prune.js, and
  // obs_dependency is not sampled -- every outbound vendor call is a row. A
  // telemetry table that fills the disk takes down the application it was
  // installed to observe, which is the one failure this build must not cause.
  retentionDays:       numEnv('OBS_RETENTION_DAYS', 30),
  // Job runs are kept longer and deliberately: they are how "when did this
  // cron actually stop?" gets answered, and the incident that started all of
  // this went unnoticed for four months.
  jobRunRetentionDays: numEnv('OBS_JOB_RUN_RETENTION_DAYS', 90),
};

// The env/default floor, captured BEFORE any console overlay is applied.
// readConsoleCfg() mutates CFG in place; without a saved floor there is nothing
// to go back to when the published file later stops being applicable, so the
// console's last values stayed silently in force while stats() reported
// source:'absent'/'unknown' -- and the dashboard turned that into the sentence
// "so it is running its own defaults", printed directly above a table of the
// console's numbers. The state word was honest and the sentence beside it was
// not. Restoring from here is what makes both true at once.
const FLOOR = Object.assign({}, CFG);

// -- the console overlay ----------------------------------------------------
// The standing rule is that no setting lives outside the console, and the
// values above are only the floor used before the console has said anything.
// The console cannot reach this process directly: it runs as `ubuntu`, stores
// its own settings in a 0600 config.json it alone can read, and has exactly one
// privileged path (the root helper). So it publishes the operator's decision
// the same way site access is already published -- the helper writes a
// root-owned file under /etc/corpit/shared and the API reads it. This file is NOT a
// secret store: only non-secret tunables land here.
//
// Precedence is console > env > built-in default, with ONE deliberate
// exception: OBS_ENABLED=0 in the environment always wins. That is the
// documented emergency stop, and an emergency stop a config file can
// countermand is not an emergency stop.
//
// Values are re-validated HERE as well as in the helper. This process does not
// own that file and must not trust its contents just because a trusted writer
// usually produces it.
// PATH-RELEASE-20260929: /etc/corpit/shared/observability.json via corpit-paths.js (OBS_CONFIG_PATH
// still overrides; a missing shared dir throws at load, a missing file is still 'absent').
const CONSOLE_CFG_PATH = require('./corpit-paths').sharedFile('observability.json', 'OBS_CONFIG_PATH');
const HARD_OFF = process.env.OBS_ENABLED === '0';

// state: 'absent'  - no file yet; the env floor is authoritative and that is normal
//        'applied' - read and applied
//        'unknown' - the file exists but could not be read or parsed. NOT 'absent'.
//                    Reporting this as absent would tell an operator their console
//                    setting is in force when it is not.
const consoleCfg = { state: 'absent', path: CONSOLE_CFG_PATH, error: null, at: null, mtimeMs: 0, applied: {} };

function clampNum(v, lo, hi) {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.min(hi, Math.max(lo, n));
}

// Every field: [config key, CFG key, low, high]. A field absent from the file
// leaves the env/default value alone -- the console publishes only what it
// manages, and silence is not an instruction to reset.
const OVERLAY_NUM = [
  ['sampleRate',    'sampleRate',    0,    1],
  ['slowMs',        'slowMs',        100,  60000],
  ['bufferMax',     'bufferMax',     100,  50000],
  ['flushMs',       'flushMs',       1000, 300000],
  ['clientMaxBody', 'clientMaxBody', 1024, 1048576],
  ['retentionDays',       'retentionDays',       1, 365],
  ['jobRunRetentionDays', 'jobRunRetentionDays', 1, 730],
];

// Put CFG back to the env/default floor and record that nothing from the
// console is in force. Returns true if anything actually changed, so the
// callers do not re-arm a timer for a no-op.
function restoreFloor() {
  let changed = false;
  const beforeFlush = CFG.flushMs;
  for (const k of Object.keys(FLOOR)) {
    if (CFG[k] !== FLOOR[k]) { CFG[k] = FLOOR[k]; changed = true; }
  }
  if (HARD_OFF) CFG.enabled = false;   // the emergency stop still wins
  if (Object.keys(consoleCfg.applied || {}).length) { consoleCfg.applied = {}; changed = true; }
  if (CFG.flushMs !== beforeFlush) rearmTimer();
  if (changed) ensureTimer();
  return changed;
}

function readConsoleCfg() {
  let st;
  try {
    st = fs.statSync(CONSOLE_CFG_PATH);
  } catch (e) {
    if (e && e.code === 'ENOENT') {
      // Genuinely not published yet. Distinct from unreadable. If a file HAD
      // been applied and has since been removed, the values it published stop
      // being in force here -- otherwise the API keeps running the console's
      // numbers while telling the operator it is running its own.
      consoleCfg.state = 'absent'; consoleCfg.error = null; consoleCfg.mtimeMs = 0;
      restoreFloor();
      consoleCfg.applied = {};
      return;
    }
    consoleCfg.state = 'unknown';
    consoleCfg.error = 'stat: ' + (e.code || e.message);
    consoleCfg.mtimeMs = 0;
    restoreFloor();
    return;
  }
  if (st.mtimeMs === consoleCfg.mtimeMs && consoleCfg.state === 'applied') return;

  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(CONSOLE_CFG_PATH, 'utf8'));
  } catch (e) {
    // Do not fall back silently. The operator believes the console is in force.
    // Falling back LOUDLY is still required: the file is unusable, so the values
    // it published are no longer in force and CFG must say so.
    consoleCfg.state = 'unknown';
    consoleCfg.error = 'parse: ' + (e.code || e.message);
    consoleCfg.mtimeMs = 0;
    restoreFloor();
    return;
  }
  if (!doc || typeof doc !== 'object') {
    consoleCfg.state = 'unknown';
    consoleCfg.error = 'parse: not an object';
    consoleCfg.mtimeMs = 0;
    restoreFloor();
    return;
  }

  const applied = {};
  if (typeof doc.enabled === 'boolean') {
    CFG.enabled = HARD_OFF ? false : doc.enabled;
    applied.enabled = CFG.enabled;
  }
  const beforeFlush = CFG.flushMs;
  for (const f of OVERLAY_NUM) {
    if (doc[f[0]] === undefined || doc[f[0]] === null) continue;
    const v = clampNum(doc[f[0]], f[2], f[3]);
    if (v === null) continue;          // a junk value leaves the floor in place
    CFG[f[1]] = v;
    applied[f[1]] = v;
  }
  consoleCfg.applied = applied;
  consoleCfg.state = 'applied';
  consoleCfg.error = null;
  consoleCfg.mtimeMs = st.mtimeMs;
  consoleCfg.at = new Date().toISOString();

  // The flush timer was scheduled once with the old interval; changing the
  // number without rescheduling would be a setting that appears to apply and
  // does not.
  if (CFG.flushMs !== beforeFlush) rearmTimer();
  // The console can switch recording back ON at any poll, and the setting's own
  // help text promises that applies within 30s without a restart. ensureTimer()
  // is idempotent, and calling it here is what makes that promise true: without
  // it a process that started with enabled=false accepts rows into the buffers
  // and never flushes one, which is a silent, total loss of the very data this
  // module exists to keep.
  ensureTimer();
}

// -- identity: a stable handle that is not an identifier --------------------
// HMAC, not a bare hash: a plain SHA-256 of an email is trivially reversible by
// dictionary, since the corpus of employee addresses is small and known. The
// key is RBAC_SESSION_SECRET, which already exists and is already secret.
const ACTOR_SALT = process.env.OBS_ACTOR_SALT || process.env.RBAC_SESSION_SECRET || '';
function actorKey(id) {
  if (!id || !ACTOR_SALT) return null;
  return crypto.createHmac('sha256', ACTOR_SALT)
    .update(String(id).toLowerCase()).digest('hex').slice(0, 16);
}

// -- redaction --------------------------------------------------------------
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const GUID_RE  = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const LONGHEX  = /\b[0-9a-f]{24,}\b/gi;

// Query keys whose VALUE may be stored. Everything else is redacted.
//
// This was a deny-list of personal key names (upn, email, q, samaccountname,
// token...) and it silently failed twice: /api/identity/sync-status?identity=
// carries a sAMAccountName and /api/rapid7/web-failures?name= carries a person,
// and neither key was on it -- so the row stored 'upn=<redacted>&identity=jkeith'
// next to the actor_key of whoever ran the search. A deny-list of names cannot
// keep up with 40+ routes written by different hands, and every miss is silent
// and permanent, because redaction happens on the way IN.
//
// Inverted: a value is kept only if its key is known to be a number, an enum or
// a flag. The list below was built from every ?key= actually used by the
// deployed pages (grep over /var/www/html on 2026-09-06), not guessed. A route
// that adds a new key gets '<redacted>' until someone deliberately adds it here
// -- the failure mode of a miss is now a lost diagnostic, not a stored identity.
const SAFE_QS = new Set([
  'hours', 'days', 'limit', 'offset', 'page', 'pagesize', 'size', 'max', 'min',
  'count', 'top', 'depth', 'window', 'period', 'preset', 'range',
  'kind', 'type', 'status', 'sort', 'sortby', 'sortdir', 'order', 'dir',
  'format', 'mode', 'tab', 'view', 'app', 'v', 'version', 'refresh', 'force',
  'include', 'include_resolved', 'include_inactive', 'exclude', 'expired',
  'signedout', 'missing', 'mon', 'dow', 'family', 'cell', 'conntot',
  'blocked_only', 'temperature_unit', 'latitude', 'longitude',
]);

// Routes whose existence may be logged but whose parameters never are, because
// they carry or set credentials. Nothing beyond method+route+status is kept.
const SENSITIVE_ROUTES = [
  /\/password-reset/i, /\/reset-password/i, /\/unlock/i, /\/breakglass/i,
  /\/localdev\/login/i, /\/auth\/(callback|accept|token)/i,
  /\/gate\/(check|refresh|session-info)/i,
];
function isSensitiveRoute(p) {
  return SENSITIVE_ROUTES.some(function (re) { return re.test(p || ''); });
}

// Replace anything that names a person or is a one-off identifier.
function scrub(s) {
  if (s == null) return null;
  return String(s)
    .replace(EMAIL_RE, '<email>')
    .replace(GUID_RE, '<guid>')
    .replace(LONGHEX, '<hash>');
}

// Free text that may CONTAIN urls - a stack trace, an error filename, an
// exception message. scrub() alone is not enough here: it knows three patterns
// (email, guid, long hex) and has no concept of a query string, so a deep link
// like /identity-diag.html?q=jeramy.keith%40auction.com survived it intact --
// percent-encoded, so EMAIL_RE could not even see the '@'. Every page here is
// one HTML file with inline <script>, which makes ev.filename the DOCUMENT url
// and puts that query string in every frame of every stack we store.
//
// So: redact url-shaped tokens through the same allow-list the route column
// uses, THEN decode percent-escapes and scrub what is left, so an encoded
// address sitting in plain prose is caught too.
const URL_TOKEN_RE = /(?:https?:\/\/[^\s'"()<>\]]+|\/[A-Za-z0-9_.~%-][^\s'"()<>\]]*\?[^\s'"()<>\]]*)/g;
function scrubText(s) {
  if (s == null) return null;
  const urlsRedacted = String(s).replace(URL_TOKEN_RE, function (m) {
    // Keep a trailing :line:col. It is the single most useful token in a stack
    // frame and it is not a query value -- the greedy match swallows it into
    // the query string otherwise, and redacting a whole stack down to bare urls
    // would make this table useless for the debugging it exists to serve.
    let tail = '';
    const lc = /:\d+(?::\d+)?$/.exec(m);
    if (lc) { tail = lc[0]; m = m.slice(0, m.length - tail.length); }
    return (redactUrl(m) || '') + tail;
  });
  return scrub(decodeSafe(urlsRedacted));
}

// A path segment that is an id becomes ':id', so a million distinct URLs group
// into one route. Without this, grouping by route is useless AND the table
// grows one row per employee looked up.
function normalizePath(pathname) {
  const parts = String(pathname || '').split('/');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (!p) continue;
    if (p.indexOf('@') !== -1 || /%40/i.test(p)) { parts[i] = ':id'; continue; }
    if (/^[0-9]+$/.test(p) && p.length > 2) { parts[i] = ':id'; continue; }
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(p)) { parts[i] = ':id'; continue; }
    if (/^[0-9a-f]{16,}$/i.test(p)) { parts[i] = ':id'; continue; }
  }
  return parts.join('/') || '/';
}

function decodeSafe(v) { try { return decodeURIComponent(v); } catch (e) { return v; } }

// Full URL -> storable string. Query VALUES for sensitive keys are dropped but
// the KEY is kept, because "this call was made with a upn=" is diagnostic while
// the address itself is not ours to keep.
function redactUrl(u) {
  if (!u) return null;
  let pathname = String(u), query = '';
  const h = pathname.indexOf('#'); if (h !== -1) pathname = pathname.slice(0, h);
  const q = pathname.indexOf('?');
  if (q !== -1) { query = pathname.slice(q + 1); pathname = pathname.slice(0, q); }
  let out = normalizePath(pathname);
  if (query) {
    const kept = query.split('&').map(function (kv) {
      const eq = kv.indexOf('=');
      const k = (eq === -1 ? kv : kv.slice(0, eq));
      if (eq === -1) return k;
      if (!SAFE_QS.has(k.toLowerCase())) return k + '=<redacted>';
      return k + '=' + scrub(decodeSafe(kv.slice(eq + 1)));
    }).join('&');
    if (kept) out += '?' + kept;
  }
  return scrub(out).slice(0, 500);
}

// -- fingerprinting ---------------------------------------------------------
// What makes two failures "the same failure" for grouping. Deliberately
// excludes the actor and the timestamp, so one broken widget is one row on the
// dashboard rather than one row per user who happened to hit it.
function fingerprint(parts) {
  return crypto.createHash('sha1')
    .update(parts.filter(Boolean).map(String).join(' ')).digest('hex');
}

// -- the buffer -------------------------------------------------------------
// Bounded, per table. Dropping the OLDEST is deliberate: during an incident the
// newest events describe what is happening now. The buffer overflowing is itself
// a fact worth reporting, which `dropped` does.
const buffers = new Map();     // table -> { cols, rows, dropped }
let pool = null;
let poolSource = 'none';    // 'own' | 'injected' - reported, never inferred
let poolConflicts = 0;      // setPool() calls refused because a pool was already set
let timer = null;
let cfgTimer = null;
let flushing = false;
let lastError = null;
// Reports refused by obs-ingest-cap for exceeding clientMaxBody. Counted so the
// enforced cap can be shown as enforced rather than merely declared -- a cap
// that silently discards is a different kind of fake control.
let oversizeRejected = 0;
function noteOversize(n) { oversizeRejected += (Number.isFinite(n) ? n : 1); }

function ensureTimer() {
  if (timer || !CFG.enabled) return;
  timer = setInterval(function () { flush().catch(function () {}); }, CFG.flushMs);
  if (timer.unref) timer.unref();   // never hold the process open
}

// Called when the console changes flushMs. Declared as a function statement so
// the overlay reader above can call it despite being defined earlier in the file.
function rearmTimer() {
  // Deliberately NOT `if (!timer) return`. A null timer is exactly the state
  // that needs re-arming: a process that booted while the console had recording
  // switched off never armed one, and an early return here made that permanent.
  if (timer) { clearInterval(timer); timer = null; }
  ensureTimer();
}

// -- the writer's own connections ------------------------------------------
// The buffer used to flush through whichever pool called setPool() LAST, and
// two callers disagreed. server.js hands over the application pool at startup,
// with the comment "set as early as the pool exists so nothing recorded during
// startup is lost"; obs-routes.js then hands over the DASHBOARD's 4-connection
// pool at require() time, 400 lines later. Last writer won, so the flusher was
// writing through the pool that serves the observability page itself -- and
// opening that page fires seven gated panel requests, each holding a connection
// while it runs. The page throttled the collection it was displaying.
//
// On the core API the sharing was worse still: obs was given rbacPool, the
// 5-connection pool that authenticates EVERY request on that process. A slow
// obs INSERT there is a slow sign-in.
//
// So obs owns two connections of its own and competes with nobody.
// waitForConnections:false is the deliberate part: if both are busy, the flush
// fails at once and the rows are counted as dropped instead of queuing. An
// observability writer that waits is an observability writer that can amplify
// the outage it exists to describe -- the same rule the browser client follows
// by never retrying a failed report.
//
// The database is named literally because it must be: obs_* live in corpit_hub
// on BOTH processes, and the core API's own DB_NAME is it_inventory. The
// credentials are the ones both apps already hold, so no new secret appears.
function initPool() {
  if (pool) return pool;
  try {
    const mysql = require('mysql2/promise');
    pool = mysql.createPool({
      host:               process.env.DB_HOST,
      port:               parseInt(process.env.DB_PORT, 10) || 3306,
      database:           'corpit_hub',
      user:               process.env.DB_USER,
      password:           process.env.DB_PASSWORD,
      waitForConnections: false,
      connectionLimit:    2,
      connectTimeout:     5000,
      charset:            'utf8mb4',
    });
    poolSource = 'own';
  } catch (e) {
    lastError = 'pool: ' + (e.code || e.message);
    return null;
  }
  armPool();
  return pool;
}

// Kept for the two servers that inject a pool today. First writer wins: a
// second, different pool is refused and COUNTED rather than silently swapped,
// because a silent swap is precisely how the flusher ended up on the dashboard's
// connections with both call sites looking correct in isolation.
function setPool(p) {
  if (pool) {
    if (p !== pool) poolConflicts++;
    return;
  }
  pool = p;
  poolSource = 'injected';
  armPool();
}

function armPool() {
  readConsoleCfg();          // apply the console's decision before the first flush
  ensureTimer();
  // Re-read on a slow timer rather than on every request: this is a stat() on a
  // small local file, and 30s is well inside the time it takes an operator to
  // click Save and then look at a page. Unref'd, so it never holds the process.
  if (!cfgTimer) {
    cfgTimer = setInterval(function () {
      try { readConsoleCfg(); } catch (e) { consoleCfg.state = 'unknown'; consoleCfg.error = 'poll: ' + e.message; }
    }, 30000);
    if (cfgTimer.unref) cfgTimer.unref();
  }
  armHeartbeat();
}

// -- the heartbeat ----------------------------------------------------------
// FC-10. If obs fails to start inside an app, the only trace is a line on that
// process's stdout, and /api/observe/self answers for the HUB's pipeline only --
// it is served BY the hub, so it can only ever report the hub. The core API
// (:3000) could have a dead recorder indefinitely and every dashboard on this
// platform would look exactly the same as if it were healthy. That is the
// founding defect of this whole build wearing a different hat: a status ladder
// with no rung for "not measured".
//
// The fix is not another status field -- a field written by a dead recorder is
// not written at all. It is an ABSENCE that something else already knows how to
// read. Each app beats into srv_job_run under its own name, both beats are
// declared in the job registry, and obs-job's resolver turns a missing beat
// into `overdue` using the same code path that catches a dead cron. No new
// concept, no new page, no new place to look.
//
// It beats only while CFG.enabled. A beat that continued after an operator
// switched recording off would report a live recorder that is recording
// nothing, which is the exact class of lie this file exists to prevent. The
// registry entry says so, and obs.enabled is on the same dashboard.
const HEARTBEAT_MS = 600000;   // 10 min; registry declares cadence 10 + grace 10
let beatTimer = null;
let lastBeatAt = null;

function beat() {
  if (!pool || !CFG.enabled) return;
  const at = new Date();
  // Required lazily: obs-job requires this module, so a top-level require here
  // would be a cycle and obs-job's exports would be {} at load time.
  let job;
  try { job = require('./obs-job'); } catch (e) { lastError = 'beat: ' + e.message; return; }
  // Written straight through, not buffered: the buffer is what this is checking.
  job.record(pool, 'obs-heartbeat-' + CFG.app, {
    startedAt: at, finishedAt: at, exitCode: 0, state: 'success',
  }).then(function () { lastBeatAt = at.toISOString(); })
    .catch(function (e) { lastError = 'beat: ' + (e.code || e.message); });
}

function armHeartbeat() {
  if (beatTimer) return;
  beat();                                  // one immediately, so a restart shows up at once
  beatTimer = setInterval(beat, HEARTBEAT_MS);
  if (beatTimer.unref) beatTimer.unref();  // never hold the process open
}

function push(table, cols, row) {
  if (!CFG.enabled) return;
  let b = buffers.get(table);
  if (!b) { b = { cols: cols, rows: [], dropped: 0 }; buffers.set(table, b); }
  b.rows.push(row);
  while (b.rows.length > CFG.bufferMax) { b.rows.shift(); b.dropped++; }
}

const FLUSH_CHUNK = 200;

async function flush() {
  if (flushing || !pool) return;
  flushing = true;
  try {
    for (const entry of buffers) {
      const table = entry[0], b = entry[1];
      if (!b.rows.length) continue;
      const rows = b.rows.splice(0, b.rows.length);
      const cols = b.cols.map(function (c) { return '`' + c + '`'; }).join(',');
      const one = '(' + b.cols.map(function () { return '?'; }).join(',') + ')';
      // Chunked, because one INSERT for the whole buffer means one rejected row
      // destroys every unrelated row queued beside it. Under STRICT_TRANS_TABLES
      // an out-of-range value is error 1264 for the whole statement (verified
      // against this schema), and the catch below deliberately does not retry.
      // Clamping at ingest is the real fix for the crafted case; this bounds
      // what any single bad row - crafted or a genuine schema drift - can cost.
      for (let i = 0; i < rows.length; i += FLUSH_CHUNK) {
        const part = rows.slice(i, i + FLUSH_CHUNK);
        const sql = 'INSERT INTO `' + table + '` (' + cols + ') VALUES ' +
                    part.map(function () { return one; }).join(',');
        try {
          await pool.query(sql, part.flat());
        } catch (e) {
          // The write failed. Do NOT put the rows back: a table that is broken
          // (missing, wrong shape, disk full) would otherwise retry the same
          // batch forever and the buffer would never drain.
          b.dropped += part.length;
          lastError = table + ': ' + (e.code || e.message);
        }
      }
    }
  } finally { flushing = false; }
}

function stats() {
  const out = {
    enabled: CFG.enabled, app: CFG.app, lastError: lastError, buffers: {},
    // Reported as a fact rather than inferred: "enabled" is an intention, and
    // a dead flusher with enabled:true is indistinguishable from a healthy one
    // until rows start being dropped. The dashboard can now say which it is.
    flusherArmed: !!timer,
    // Which connections the writer is using, and whether anyone tried to change
    // them out from under it. 'injected' is not wrong, but a non-zero conflict
    // count means two call sites disagree and one of them is being ignored.
    poolSource: poolSource,
    poolConflicts: poolConflicts,
    // An explicit "these buffer figures were reported" flag. The dashboard has
    // an amber branch for absent buffers, and it was unreachable: `buffers` is
    // always initialised to {}, which is truthy and typeof 'object', so an
    // un-run or failed collector still rendered a green "0 - nothing lost".
    // A flag the payload can genuinely lack is what makes that guard real.
    buffersMeasured: true,
    oversizeRejected: oversizeRejected,
    // The beat this process is publishing into srv_job_run. null means it has
    // not managed one yet -- which is the whole point: the dashboard reads the
    // ABSENCE from the job registry, not a self-report from a process that may
    // not be running.
    heartbeatJob: 'obs-heartbeat-' + CFG.app,
    heartbeatArmed: !!beatTimer,
    lastHeartbeatAt: lastBeatAt,
    // Where the live numbers came from, so the dashboard can say so rather than
    // implying every value is console-managed.
    config: {
      source: consoleCfg.state,        // absent | applied | unknown
      path: consoleCfg.path,
      error: consoleCfg.error,
      readAt: consoleCfg.at,
      applied: consoleCfg.applied,
      envHardOff: HARD_OFF,
    },
    effective: {
      sampleRate: CFG.sampleRate, slowMs: CFG.slowMs, bufferMax: CFG.bufferMax,
      flushMs: CFG.flushMs, clientMaxBody: CFG.clientMaxBody,
      retentionDays: CFG.retentionDays, jobRunRetentionDays: CFG.jobRunRetentionDays,
    },
  };
  buffers.forEach(function (b, t) { out.buffers[t] = { pending: b.rows.length, dropped: b.dropped }; });
  return out;
}

// -- safety wrapper ---------------------------------------------------------
// Rule 1, applied mechanically rather than remembered case by case.
function safe(fn) {
  return function () {
    if (!CFG.enabled) return;
    try { return fn.apply(null, arguments); } catch (e) { lastError = 'lib: ' + e.message; }
  };
}

function nowSql(d) {
  const t = (d instanceof Date) ? d : new Date();
  return t.toISOString().slice(0, 19).replace('T', ' ');
}

function clip(v, n) { return v == null ? null : String(v).slice(0, n); }

module.exports = {
  CFG, setPool, initPool, flush, stats, push, safe, noteOversize,
  actorKey, redactUrl, normalizePath, scrub, scrubText, fingerprint,
  isSensitiveRoute, nowSql, clip,
};
