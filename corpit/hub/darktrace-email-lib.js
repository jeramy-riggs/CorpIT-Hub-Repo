'use strict';
// DARKTRACE-EMAIL 2026-10-14 — read-only client for the Darktrace /EMAIL API (agemail v1.0)
// and the hub tables it fills. Used by darktrace-email-sync.js (the 30-min puller in
// syncs-worker) and darktrace-email-routes.js (the console API).
//
// Read-only on the Darktrace side: GETs, plus POST emails/search, which is a query.
// Nothing here calls hold / release / action endpoints, and nothing should.
//
// Auth (Darktrace API token): DTAPI-Token = public token, DTAPI-Date = UTC
// YYYYMMDDTHHMMSS, DTAPI-Signature = HMAC-SHA1(private, "<path?query>\n<public>\n<date>").
// For a JSON POST the JSON string is appended to the path after "?" in the signed text.
//
// The token lives in dt_email_config (row id 1), set from subadmin Settings > Darktrace
// email. It is never returned by any route and never written to the audit log.

const crypto = require('crypto');
const mysql = require('mysql2/promise');

const API = '/agemail/api/v1.0/';
const PAGE = 20;                      // emails/search refuses itemsPerPage > 20
const TIMEOUT_MS = 20000;
const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

let _pool = null;
function pool() {
  if (!_pool) {
    _pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '3306', 10),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 3,
    });
  }
  return _pool;
}

// ── config ───────────────────────────────────────────────────────────────
const CONFIG_COLS = 'id, enabled, host, public_token, private_token, cadence_min, updated_by, updated_at';
async function loadConfig(p) {
  const [rows] = await (p || pool()).query('SELECT ' + CONFIG_COLS + ' FROM dt_email_config WHERE id = 1');
  return rows[0] || null;
}
function configured(cfg) {
  return !!(cfg && cfg.host && cfg.public_token && cfg.private_token);
}
// What a browser may see: never the tokens, only whether each is set.
function publicConfig(cfg) {
  const c = cfg || {};
  return {
    enabled: c.enabled === 1 || c.enabled === true,
    host: c.host || '',
    cadence_min: c.cadence_min == null ? 30 : Number(c.cadence_min),
    public_token_set: !!c.public_token,
    private_token_set: !!c.private_token,
    updated_by: c.updated_by || null,
    updated_at: c.updated_at || null,
  };
}
function consoleUrl(cfg) {
  return cfg && cfg.host ? 'https://' + cfg.host + '/agemail/' : null;
}

// ── HTTP ─────────────────────────────────────────────────────────────────
function dtDate(d) { return d.toISOString().replace(/[-:]/g, '').slice(0, 15); }   // 20261014T172500

class DtError extends Error {
  constructor(msg, status) { super(msg); this.name = 'DtError'; this.status = status || null; }
}

async function call(cfg, method, path, query, body) {
  if (!configured(cfg)) throw new DtError('Darktrace email is not configured (host and both tokens are needed)');
  if (!HOST_RE.test(cfg.host)) throw new DtError('Darktrace host is not a valid host name');
  const qs = query ? Object.keys(query).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(query[k])).join('&') : '';
  const reqPath = API + path + (qs ? '?' + qs : '');
  const json = body === undefined ? null : JSON.stringify(body);
  const signed = json === null ? reqPath : reqPath + (qs ? '&' : '?') + json;
  const date = dtDate(new Date());
  const sig = crypto.createHmac('sha1', cfg.private_token).update(signed + '\n' + cfg.public_token + '\n' + date).digest('hex');
  const headers = { 'DTAPI-Token': cfg.public_token, 'DTAPI-Date': date, 'DTAPI-Signature': sig, 'Accept': 'application/json' };
  if (json !== null) headers['Content-Type'] = 'application/json';
  let r;
  try {
    r = await fetch('https://' + cfg.host + reqPath, { method, headers, body: json === null ? undefined : json, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    throw new DtError(method + ' ' + path + ': ' + ((e && (e.cause && e.cause.code || e.code || e.message)) || String(e)));
  }
  const text = await r.text();
  if (r.status < 200 || r.status >= 300) {
    throw new DtError(method + ' ' + path + ': HTTP ' + r.status + (text ? ' ' + text.replace(/\s+/g, ' ').slice(0, 200) : ''), r.status);
  }
  try { return JSON.parse(text); }
  catch (e) { throw new DtError(method + ' ' + path + ': response was not JSON (HTTP ' + r.status + ')', r.status); }
}
const get = (cfg, path, query) => call(cfg, 'GET', path, query);
const post = (cfg, path, body) => call(cfg, 'POST', path, null, body);

// Every page of one search. The API returns a bare array and no total, so the only
// count is the paging itself. Stops after maxPages and says so (capped).
async function searchAll(cfg, criteriaList, fromMs, toMs, maxPages) {
  const seen = new Map();
  for (let page = 0; page < maxPages; page++) {
    const rows = await post(cfg, 'emails/search', {
      itemsPerPage: PAGE, page, timeFrom: fromMs, timeTo: toMs,
      query: { mode: 'and', criteriaList },
    });
    if (!Array.isArray(rows)) throw new DtError('emails/search returned a ' + typeof rows + ', not a list');
    for (const m of rows) if (m && m.uuid) seen.set(m.uuid, m);
    if (rows.length < PAGE) return { rows: [...seen.values()], pages: page + 1, capped: false };
  }
  return { rows: [...seen.values()], pages: maxPages, capped: true };
}

module.exports = {
  API, PAGE, HOST_RE, pool, loadConfig, configured, publicConfig, consoleUrl,
  call, get, post, searchAll, DtError, dtDate, CONFIG_COLS,
};
