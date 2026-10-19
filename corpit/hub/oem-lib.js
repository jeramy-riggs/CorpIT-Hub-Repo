/**
 * oem-lib.js — shared plumbing for the merged Okta → Entra migration workspace.
 *
 *   pool          mysql2 pool that returns BIGINT/DECIMAL as strings, so 18-digit Zscaler ids
 *                 survive the trip through JavaScript (2^53 rounds 288258444836732930 to …900).
 *   okta*         paced Okta client (SSWS token from .env). Honours 429 and the per-bucket
 *                 x-rate-limit headers; /api/v1/apps is a 50-per-minute bucket on this org.
 *   graph*        Graph client with a cached app-only token and the live roles claim.
 *   oktaIdentity  who the SSWS token really is (user + admin roles), read live and cached.
 *   zscalerProbe  what the Zscaler OneAPI client can read right now (server groups / connectors).
 *   jobs          persisted job runner: one row per run in oem_job, a DB lock row per job_key,
 *                 step log flushed as it happens, survives page refresh, refuses duplicates.
 *   redact        strips secret-looking keys before anything is stored or displayed.
 */
'use strict';
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 6,
  supportBigNumbers: true,
  bigNumberStrings: true,
});

/** mysql2 pre-parses JSON columns; JSON.parse on an object throws. */
const j = (v, dflt) => {
  if (v === null || v === undefined) return dflt;
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch (e) { return dflt; }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nowIso = () => new Date().toISOString();

/* ------------------------------------------------------------------ redact */
const SECRET_KEY = /(secret|password|passwd|token|credential|private[_-]?key|client_secret|api[_-]?key|authorization|cookie)/i;
function redact(v, depth = 0) {
  if (depth > 12) return '[depth]';
  if (Array.isArray(v)) return v.map((x) => redact(x, depth + 1));
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, val] of Object.entries(v)) {
      // Okta's `credentials.signing.kid` and `credentials.userNameTemplate` are not secrets;
      // the rule keys on the leaf name, so a `credentials` branch is walked, not dropped.
      if (SECRET_KEY.test(k) && k !== 'credentials') o[k] = '[redacted]';
      else o[k] = redact(val, depth + 1);
    }
    return o;
  }
  return v;
}

/* ------------------------------------------------------- record scrub (v2) */
/*
 * scrubAppRecord(obj) — the narrow scrub every okta_apps.raw_json / entra_apps.raw_json writer runs (v2 secrets-1/2/3).
 * Deep-copies and replaces ONLY the value under a key that IS a secret name (case-insensitive, exact) with "[redacted]".
 * It is deliberately not L.redact: that key regex matches "token" and "credential" and would blank
 * `settings.oauthClient.token_endpoint_auth_method`, `credentials.signing.kid` and other public fields the migration
 * engine and discovery read back from the mirror. client_id, token_endpoint_auth_method, kid, thumbprints stay.
 */
const SCRUB_KEYS = new Set(['client_secret', 'clientsecret', 'secret', 'sharedsecret', 'shared_secret', 'password', 'passwd', 'private_key', 'privatekey', 'api_key', 'apikey', 'access_token', 'refresh_token', 'id_token', 'session_token', 'cookie', 'mfa_code', 'otp']);
function scrubAppRecord(v, depth = 0) {
  if (depth > 12) return '[depth]';
  if (Array.isArray(v)) return v.map((x) => scrubAppRecord(x, depth + 1));
  if (v instanceof Date) return new Date(v.getTime());
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, val] of Object.entries(v)) o[k] = SCRUB_KEYS.has(String(k).toLowerCase()) ? '[redacted]' : scrubAppRecord(val, depth + 1);
    return o;
  }
  return v;
}

/*
 * redactText(str) — the string counterpart of redact for error messages, job logs and 500 bodies (v2 secrets-6):
 * masks `Bearer <token>` / `SSWS <token>` headers, `client_secret=…` / `password=…` style pairs (also `key: value`
 * and JSON `"key":"value"` forms), JWTs (eyJ…​.…​.…) and PEM private-key blocks. Non-strings are stringified first, so
 * `(L.redactText || String)(msg)` is a drop-in for String(msg). Never throws.
 */
const RT_PEM = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
const RT_JWT = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
const RT_AUTH = /\b(Bearer|SSWS)\s+[A-Za-z0-9._~+\/=-]{4,}|\b(Basic)\s+[A-Za-z0-9+\/]{8,}={0,2}(?![A-Za-z0-9])/gi; // Basic only in its base64 shape, so prose like "Basic auth" is kept
const RT_PAIR = /("?)\b(client_secret|clientsecret|password|passwd|access_token|refresh_token|id_token|session_token|api_key|apikey|private_key|privatekey|shared_secret|sharedsecret|otp|mfa_code)\b("?)\s*([=:])\s*("?)[^&\s"',;}\]]+/gi;
function redactText(v) {
  let s;
  try { s = typeof v === 'string' ? v : String(v); } catch (e) { return '[unprintable]'; }
  return s.replace(RT_PEM, '[redacted-pem]').replace(RT_JWT, '[redacted-jwt]').replace(RT_AUTH, '$1$2 [redacted]').replace(RT_PAIR, '$1$2$3$4$5[redacted]');
}

/* -------------------------------------------------------------------- Okta */
const OKTA_BASE = (process.env.OKTA_BASE_URL || '').replace(/\/+$/, '');
const OKTA_TOKEN = process.env.OKTA_API_TOKEN;

/**
 * GET one Okta URL. Returns { status, body, next, headers }. 429 → waits for the bucket reset
 * (capped) and retries; a low remaining count pauses before the next call instead of after
 * the failure. Errors other than 429 are returned, not thrown, so a caller can record
 * "denied" for one object class and keep discovering the others.
 */
async function oktaGet(pathOrUrl, attempt = 0) {
  if (!OKTA_BASE || !OKTA_TOKEN) return { status: 0, body: null, next: null, error: 'Okta credentials not configured' };
  const url = /^https?:/i.test(pathOrUrl) ? pathOrUrl : OKTA_BASE + pathOrUrl;
  let res;
  try {
    res = await fetch(url, { headers: { Authorization: 'SSWS ' + OKTA_TOKEN, Accept: 'application/json' } });
  } catch (e) {
    return { status: 0, body: null, next: null, error: e.message };
  }
  if (res.status === 429) {
    if (attempt >= 4) return { status: 429, body: null, next: null, error: 'rate limit exhausted after 5 attempts' };
    const reset = parseInt(res.headers.get('x-rate-limit-reset') || '0', 10) * 1000;
    const wait = Math.min(65000, Math.max(2000, reset ? reset - Date.now() + 500 : 10000));
    await sleep(wait);
    return oktaGet(pathOrUrl, attempt + 1);
  }
  const link = res.headers.get('link') || '';
  const m = link.match(/<([^>]+)>;\s*rel="next"/);
  let body = null;
  const text = await res.text();
  try { body = text ? JSON.parse(text) : null; } catch (e) { body = null; }
  const remaining = parseInt(res.headers.get('x-rate-limit-remaining') || '99', 10);
  if (remaining <= 3) {
    const reset = parseInt(res.headers.get('x-rate-limit-reset') || '0', 10) * 1000;
    await sleep(Math.min(65000, Math.max(1000, reset ? reset - Date.now() + 500 : 5000)));
  }
  return {
    status: res.status, body, next: m ? m[1] : null,
    error: res.ok ? null : ((body && (body.errorSummary || body.errorCode)) || ('HTTP ' + res.status)),
  };
}

/** Follow Link: rel=next. Returns { ok, items, pages, error, status }. Never partial-as-complete. */
async function oktaAll(path, { maxPages = 60 } = {}) {
  let url = path, items = [], pages = 0, r;
  while (url && pages < maxPages) {
    r = await oktaGet(url);
    pages++;
    if (r.status !== 200) return { ok: false, items, pages, error: r.error, status: r.status, partial: items.length > 0 };
    if (Array.isArray(r.body)) items = items.concat(r.body);
    url = r.next;
  }
  return { ok: !url, items, pages, error: url ? 'page cap reached' : null, status: 200, partial: !!url };
}


/** Non-GET Okta call. Used only by routes that require a scoped confirmation. Never retried. */
async function oktaRequest(method, path, body) {
  if (!OKTA_BASE || !OKTA_TOKEN) return { status: 0, body: null, error: 'Okta credentials are not configured' };
  try {
    const r = await fetch(OKTA_BASE + path, { method, headers: { Authorization: 'SSWS ' + OKTA_TOKEN, Accept: 'application/json', 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    let parsed = null; try { parsed = text ? JSON.parse(text) : null; } catch (e) { parsed = { raw: text.slice(0, 300) }; }
    return { status: r.status, body: parsed, error: r.ok ? null : ((parsed && (parsed.errorSummary || parsed.errorCode)) || ('HTTP ' + r.status)) };
  } catch (e) { return { status: 0, body: null, error: e.message }; }
}

/** Run a node script as a child process inside a job, streaming its output lines into the job log. */
function runScript(log, scriptPath, args = [], { timeoutMs = 600000, env = {} } = {}) {
  const { spawn } = require('child_process');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [scriptPath, ...args], { cwd: require('path').dirname(scriptPath), env: Object.assign({}, process.env, env) });
    let buf = '', errBuf = '', lines = 0;
    const onData = (chunk, level) => {
      buf += chunk.toString();
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trimEnd(); buf = buf.slice(i + 1);
        if (line) { lines++; if (lines <= 400) log(line.slice(0, 400), level); }
      }
    };
    child.stdout.on('data', (c) => onData(c, 'info'));
    child.stderr.on('data', (c) => { errBuf += c.toString().slice(0, 2000); onData(c, 'warn'); });
    const timer = setTimeout(() => { log('script timed out; sending SIGTERM', 'error'); child.kill('SIGTERM'); }, timeoutMs);
    const poll = setInterval(() => { if (log.cancelled()) { log('cancel requested; stopping the script (nothing after the last logged step is applied)', 'warn'); child.kill('SIGTERM'); } }, 1000);
    child.on('close', (code, signal) => {
      clearTimeout(timer); clearInterval(poll);
      if (buf.trim()) log(buf.trim().slice(0, 400));
      resolve({ code, signal, ok: code === 0, lines, stderrTail: errBuf.slice(-600) });
    });
    child.on('error', (e) => { clearTimeout(timer); clearInterval(poll); log('could not start script: ' + e.message, 'error'); resolve({ code: -1, ok: false, error: e.message }); });
  });
}

let oktaIdCache = { at: 0, v: null };
/** The SSWS token's real identity and admin roles. A token named "ReadOnly" can be a super admin. */
async function oktaIdentity() {
  if (oktaIdCache.v && Date.now() - oktaIdCache.at < 300000) return oktaIdCache.v;
  const me = await oktaGet('/api/v1/users/me');
  if (me.status !== 200 || !me.body) {
    oktaIdCache = { at: Date.now(), v: { known: false, error: me.error || ('HTTP ' + me.status), checkedAt: nowIso() } };
    return oktaIdCache.v;
  }
  const roles = await oktaGet(`/api/v1/users/${me.body.id}/roles`);
  const v = {
    known: true, checkedAt: nowIso(),
    userId: me.body.id, login: me.body.profile && me.body.profile.login,
    roles: roles.status === 200 && Array.isArray(roles.body) ? roles.body.map((r) => r.type) : null,
    rolesError: roles.status === 200 ? null : roles.error,
  };
  v.canWriteOkta = v.roles === null ? null : v.roles.some((r) => ['SUPER_ADMIN', 'ORG_ADMIN', 'APP_ADMIN'].includes(r));
  oktaIdCache = { at: Date.now(), v };
  return v;
}

/* ------------------------------------------------------------------- Graph */
/* Two Graph credentials: the platform's read credential (ENTRA_CLIENT_ID, IT-Command-IdentityDiag) and,
   when configured, a separate write credential for the migration engine (ENTRA_MIGRATE_CLIENT_ID,
   IT-Command-Migrate). Every Graph write goes through the write credential; without one configured the
   write side reports itself as unconfigured rather than silently using the read credential's consent. */
const GRAPH_CREDS = {
  read:  { id: process.env.ENTRA_CLIENT_ID, secret: process.env.ENTRA_CLIENT_SECRET, name: process.env.ENTRA_APP_NAME || 'IT-Command-IdentityDiag' },
  write: process.env.ENTRA_MIGRATE_CLIENT_ID && process.env.ENTRA_MIGRATE_CLIENT_SECRET
    ? { id: process.env.ENTRA_MIGRATE_CLIENT_ID, secret: process.env.ENTRA_MIGRATE_CLIENT_SECRET, name: process.env.ENTRA_MIGRATE_APP_NAME || 'IT-Command-Migrate' }
    : null,
};
const graphCaches = { read: { at: 0, token: null, roles: null, exp: 0, error: null }, write: { at: 0, token: null, roles: null, exp: 0, error: null } };
async function graphToken(force, cred = 'read') {
  const c = GRAPH_CREDS[cred];
  if (!c) return { at: Date.now(), token: null, roles: null, exp: 0, error: 'no ' + cred + ' credential configured (' + (process.env.ENTRA_MIGRATE_CLIENT_ID ? 'ENTRA_MIGRATE_CLIENT_ID is set; ENTRA_MIGRATE_CLIENT_SECRET is missing' : 'ENTRA_MIGRATE_CLIENT_ID / ENTRA_MIGRATE_CLIENT_SECRET not set') + ')', configured: false, cred, name: null };
  const cache = graphCaches[cred];
  if (!force && cache.token && Date.now() < cache.exp - 60000) return cache;
  let next;
  try {
    const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: c.id, client_secret: c.secret,
        scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials',
      }),
    });
    const t = await r.json();
    if (!t.access_token) throw new Error(t.error_description || 'no token');
    const claims = JSON.parse(Buffer.from(t.access_token.split('.')[1], 'base64').toString('utf8'));
    next = { at: Date.now(), token: t.access_token, roles: claims.roles || [], exp: (claims.exp || 0) * 1000, error: null,
      appId: claims.appid || null, tenantId: claims.tid || null, configured: true, cred, name: c.name };
  } catch (e) {
    next = { at: Date.now(), token: null, roles: null, exp: 0, error: e.message, configured: true, cred, name: c.name };
  }
  graphCaches[cred] = next;
  return next;
}
/** Which registration the write side runs as (name only; never the secret). */
function graphWriteCredential() {
  const c = GRAPH_CREDS.write;
  return c ? { configured: true, name: c.name, clientId: c.id } : { configured: false, name: null, clientId: null };
}

/** GET one Graph URL (absolute or /v1.0|/beta path). Returns { status, body, next, error }. */
async function graphGet(pathOrUrl, attempt = 0) {
  const g = await graphToken();
  if (!g.token) return { status: 0, body: null, next: null, error: 'Graph token: ' + g.error };
  const url = /^https?:/i.test(pathOrUrl) ? pathOrUrl : 'https://graph.microsoft.com' + pathOrUrl;
  let res;
  try { res = await fetch(url, { headers: { Authorization: 'Bearer ' + g.token, Accept: 'application/json', ConsistencyLevel: 'eventual' } }); }
  catch (e) { return { status: 0, body: null, next: null, error: e.message }; }
  if ((res.status === 429 || res.status === 503) && attempt < 4) {
    const ra = parseInt(res.headers.get('retry-after') || '5', 10);
    await sleep(Math.min(60000, ra * 1000));
    return graphGet(pathOrUrl, attempt + 1);
  }
  const text = await res.text();
  let body = null; try { body = text ? JSON.parse(text) : null; } catch (e) { body = null; }
  return {
    status: res.status, body, next: body && body['@odata.nextLink'] || null,
    error: res.ok ? null : ((body && body.error && (body.error.code + ': ' + body.error.message)) || ('HTTP ' + res.status)),
  };
}

/**
 * Non-GET Graph call (POST/PATCH/DELETE). Used only by the migration executor, only after the live
 * roles claim shows the permission, and only inside a job that recorded a snapshot first. Never retried:
 * a write that timed out is verified by a read, not repeated. Returns { status, body, error, location }.
 */
async function graphRequest(method, path, body, { cred } = {}) {
  const g = await graphToken(false, cred || (String(method).toUpperCase() === 'GET' ? 'read' : 'write'));
  if (!g.token) return { status: 0, body: null, error: 'Graph token: ' + g.error };
  const url = /^https?:/i.test(path) ? path : 'https://graph.microsoft.com' + path;
  try {
    const res = await fetch(url, { method, headers: { Authorization: 'Bearer ' + g.token, Accept: 'application/json', 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let parsed = null; try { parsed = text ? JSON.parse(text) : null; } catch (e) { parsed = { raw: text.slice(0, 300) }; }
    return { status: res.status, body: parsed, location: res.headers.get('location') || null,
      error: res.ok ? null : ((parsed && parsed.error && (parsed.error.code + ': ' + parsed.error.message)) || ('HTTP ' + res.status)) };
  } catch (e) { return { status: 0, body: null, error: e.message }; }
}

async function graphAll(path, { maxPages = 50 } = {}) {
  let url = path, items = [], pages = 0;
  while (url && pages < maxPages) {
    const r = await graphGet(url);
    pages++;
    if (r.status !== 200) return { ok: false, items, pages, error: r.error, status: r.status, partial: items.length > 0 };
    items = items.concat((r.body && r.body.value) || []);
    url = r.next;
  }
  return { ok: !url, items, pages, error: url ? 'page cap reached' : null, status: 200, partial: !!url };
}

/* ----------------------------------------------------------------- Zscaler */
let zsCache = { at: 0, v: null };
/** What the OneAPI client can read now. Probed, not assumed: the mirror job needs both. */
async function zscalerProbe(force) {
  if (!force && zsCache.v && Date.now() - zsCache.at < 600000) return zsCache.v;
  const out = { checkedAt: nowIso(), serverGroups: 'unknown', connectors: 'unknown', gateways: 'unknown', error: null };
  try {
    const { zpaAuth, ziaAuth, httpsRequest } = require('./zscaler-lookup');
    const cid = process.env.ZPA_CUSTOMER_ID;
    const t = await zpaAuth();
    const base = 'https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/' + cid;
    const sg = await httpsRequest(new URL(base + '/serverGroup?page=1&pagesize=1'), { method: 'GET', headers: { Authorization: 'Bearer ' + t } });
    out.serverGroups = sg.status === 200 ? 'ok' : sg.status === 403 ? 'denied' : 'error:' + sg.status;
    const cn = await httpsRequest(new URL(base + '/connector?page=1&pagesize=1'), { method: 'GET', headers: { Authorization: 'Bearer ' + t } });
    out.connectors = cn.status === 200 ? 'ok' : cn.status === 403 ? 'denied' : 'error:' + cn.status;
    const zt = await ziaAuth();
    const gw = await httpsRequest(new URL(process.env.ZIA_BASE_URL + '/zpaGateways'), { method: 'GET', headers: { Authorization: 'Bearer ' + zt } });
    out.gateways = gw.status === 200 ? 'ok' : gw.status === 403 ? 'denied' : 'error:' + gw.status;
  } catch (e) { out.error = e.message; }
  zsCache = { at: Date.now(), v: out };
  return out;
}

/* -------------------------------------------------------------------- jobs */
const JOB_STALE_MS = 2 * 3600 * 1000;
const running = new Map(); // id -> { cancel: bool }

async function releaseStaleLocks() {
  // A lock whose job row is no longer 'running', or whose owning process stopped
  // refreshing it, is stale. Job age alone is not evidence of a crash: a large
  // tenant migration can legitimately run longer than JOB_STALE_MS.
  await pool.query(
    `DELETE l FROM oem_job_lock l LEFT JOIN oem_job x ON x.id=l.job_id
      WHERE x.id IS NULL OR x.status<>'running' OR l.locked_at < DATE_SUB(NOW(), INTERVAL ? SECOND)`,
    [Math.floor(JOB_STALE_MS / 1000)]);
  await pool.query(
    `UPDATE oem_job x LEFT JOIN oem_job_lock l ON l.job_id=x.id
      SET x.status='failed', x.finished_at=NOW(), x.error='process restarted while the job was running; nothing after the last logged step was applied'
      WHERE x.status='running' AND x.started_at < DATE_SUB(NOW(), INTERVAL ? SECOND) AND l.job_id IS NULL`,
    [Math.floor(JOB_STALE_MS / 1000)]);
}

/**
 * Start a job. fn(log, ctx) runs detached; the HTTP caller gets the job id immediately.
 * Duplicate protection is the primary key on oem_job_lock, so two API processes cannot
 * both run the same job_key. Returns { id } or { conflict: {jobId, since} }.
 */
async function startJob(jobKey, actor, fn) {
  await releaseStaleLocks();
  const [ins] = await pool.query(`INSERT INTO oem_job (job_key, status, actor_email, steps) VALUES (?,'queued',?, JSON_ARRAY())`, [jobKey, actor || null]);
  const id = ins.insertId;
  try {
    await pool.query(`INSERT INTO oem_job_lock (job_key, job_id, locked_at) VALUES (?,?,NOW())`, [jobKey, id]);
  } catch (e) {
    const [[lock]] = await pool.query(`SELECT job_id, locked_at FROM oem_job_lock WHERE job_key=?`, [jobKey]);
    await pool.query(`UPDATE oem_job SET status='cancelled', finished_at=NOW(), error=? WHERE id=?`,
      ['not started: job ' + (lock ? lock.job_id : '?') + ' is already running', id]);
    return { conflict: { jobId: lock ? lock.job_id : null, since: lock ? lock.locked_at : null } };
  }
  const steps = [];
  const state = { cancel: false };
  running.set(id, state);
  const heartbeat = setInterval(() => {
    pool.query(`UPDATE oem_job_lock SET locked_at=NOW() WHERE job_key=? AND job_id=?`, [jobKey, id]).catch(() => {});
  }, 60000);
  if (typeof heartbeat.unref === 'function') heartbeat.unref();
  let flushTimer = null;
  const flush = async () => {
    flushTimer = null;
    try { await pool.query(`UPDATE oem_job SET steps=? WHERE id=?`, [JSON.stringify(steps.slice(-400)), id]); } catch (e) { /* keep going */ }
  };
  const log = (msg, level = 'info', data) => {
    steps.push({ t: nowIso(), level, msg: redactText(String(msg)).slice(0, 500), data: data === undefined ? undefined : redact(data) });
    if (!flushTimer) flushTimer = setTimeout(flush, 400);
  };
  log.cancelled = () => state.cancel;
  await pool.query(`UPDATE oem_job SET status='running', started_at=NOW() WHERE id=?`, [id]);
  (async () => {
    try {
      const result = await fn(log, { id, jobKey, actor });
      if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
      await pool.query(`UPDATE oem_job SET status=?, finished_at=NOW(), steps=?, result=? WHERE id=?`,
        [state.cancel ? 'cancelled' : 'success', JSON.stringify(steps.slice(-400)), JSON.stringify(redact(result === undefined ? null : result)), id]);
    } catch (e) {
      if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
      steps.push({ t: nowIso(), level: 'error', msg: redactText(String(e.message || e)).slice(0, 500) });
      await pool.query(`UPDATE oem_job SET status='failed', finished_at=NOW(), steps=?, error=? WHERE id=?`,
        [JSON.stringify(steps.slice(-400)), redactText(String(e.message || e)).slice(0, 2000), id]).catch(() => {});
    } finally {
      clearInterval(heartbeat);
      running.delete(id);
      await pool.query(`DELETE FROM oem_job_lock WHERE job_key=? AND job_id=?`, [jobKey, id]).catch(() => {});
    }
  })();
  return { id };
}

function requestCancel(id) {
  const s = running.get(Number(id));
  if (!s) return false;
  s.cancel = true;
  return true;
}

async function getJob(id) {
  const [[r]] = await pool.query(`SELECT * FROM oem_job WHERE id=?`, [id]);
  if (!r) return null;
  return { id: r.id, jobKey: r.job_key, status: r.status, actor: r.actor_email, startedAt: r.started_at, finishedAt: r.finished_at,
    steps: j(r.steps, []), result: j(r.result, null), error: r.error, createdAt: r.created_at, cancelRequested: !!(running.get(Number(id)) || {}).cancel };
}

async function listJobs({ limit = 40, jobKey = null, active = false } = {}) {
  const where = [], args = [];
  if (jobKey) { where.push('job_key=?'); args.push(jobKey); }
  if (active) where.push(`status IN ('queued','running')`);
  const [rows] = await pool.query(
    `SELECT id, job_key, status, actor_email, started_at, finished_at, error, created_at,
            JSON_LENGTH(steps) step_count, result
       FROM oem_job ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT ?`, [...args, Math.min(200, limit)]);
  return rows.map((r) => ({ id: r.id, jobKey: r.job_key, status: r.status, actor: r.actor_email, startedAt: r.started_at,
    finishedAt: r.finished_at, error: r.error, createdAt: r.created_at, stepCount: r.step_count, result: j(r.result, null) }));
}

async function lastSuccessful(jobKey) {
  const [[r]] = await pool.query(`SELECT id, finished_at, result FROM oem_job WHERE job_key=? AND status='success' ORDER BY id DESC LIMIT 1`, [jobKey]);
  return r ? { id: r.id, finishedAt: r.finished_at, result: j(r.result, null) } : null;
}

/* -------------------------------------------------------------------- meta */
async function metaGet(k, dflt) {
  const [[r]] = await pool.query(`SELECT v, updated_at FROM oem_meta WHERE k=?`, [k]);
  return r ? { v: j(r.v, dflt), at: r.updated_at } : { v: dflt, at: null };
}
async function metaSet(k, v) {
  await pool.query(`INSERT INTO oem_meta (k, v) VALUES (?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)`, [k, JSON.stringify(v)]);
}

/* ------------------------------------------------------------------- names */
const ENV_WORDS = { sandbox: 'sandbox', sbx: 'sandbox', prod: 'prod', production: 'prod', qa: 'qa', uat: 'uat', ci: 'ci', dev: 'dev', development: 'dev', test: 'test', testing: 'test', staging: 'staging', stage: 'staging', stg: 'staging', preview: 'preview', demo: 'demo', pilot: 'pilot' };
const STOP = new Set(['sso', 'saml', 'oidc', 'oauth', 'app', 'apps', 'application', 'the', 'and', 'of', 'for', 'inc', 'llc', 'com', 'net', 'io', 'cloud', 'online', 'portal', 'login', 'admin', 'dashboard', 'web', 'enterprise', 'us', 'auction', 'adc', 'okta', 'entra', 'azure', 'microsoft']);
function envOf(s) {
  const found = new Set();
  for (const t of String(s || '').toLowerCase().split(/[^a-z0-9]+/)) if (ENV_WORDS[t]) found.add(ENV_WORDS[t]);
  return found.size ? [...found].sort().join('+') : null;
}
function tokens(s) {
  return [...new Set(String(s || '').toLowerCase().replace(/^sso-/, '').split(/[^a-z0-9]+/)
    .filter((t) => t.length >= 2 && !STOP.has(t) && !ENV_WORDS[t]))];
}
function jaccard(a, b) {
  if (!a.length || !b.length) return 0;
  const B = new Set(b); let inter = 0;
  for (const x of a) if (B.has(x)) inter++;
  return inter / (new Set([...a, ...b]).size);
}
function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return null; } }
function normUrl(u) { return String(u || '').trim().toLowerCase().replace(/\/+$/, ''); }

module.exports = { pool, j, sleep, nowIso, redact,
  oktaGet, oktaAll, oktaRequest, runScript, oktaIdentity, graphToken, graphGet, graphAll, graphRequest, graphWriteCredential, GRAPH_CREDS, zscalerProbe,
  startJob, requestCancel, getJob, listJobs, lastSuccessful, releaseStaleLocks,
  metaGet, metaSet, envOf, tokens, jaccard, hostOf, normUrl, ENV_WORDS };

/* v2 additions (secrets-1/6): new names only; nothing above changes. */
Object.assign(module.exports, { scrubAppRecord, redactText, SCRUB_KEYS });
