// user360-routes.js
// Unified User 360 aggregator. Seeds from /api/identity/lookup, then fans out
// to sdp, entra, user-project, and identity/devices in parallel.
//
// Design:
//  - Passthrough auth: forwards the caller's Authorization header to each
//    internal endpoint so per-endpoint RBAC still applies (tami-routes pattern).
//  - All fan-out calls run under Promise.allSettled; any single failure is
//    captured in _errors and nulled in its section, so the page degrades
//    gracefully instead of 500-ing wholesale.
//  - Read-only. Mounted at /api/user360.

const express = require('express');
const mysql = require('mysql2/promise');
const router = express.Router();

// RBAC — reuse identity-diag read gate (same data domain as the seed lookup).
// createRbac is a factory that needs its own pool (mirrors identity-routes.js).
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(rbacPool);

// Populate req.user from the Bearer id_token before any requirePage gate.
// (identity-routes.js does the same via router.use at its top.)
router.use(rbac.loadCurrentUser);

const BASE = process.env.INTERNAL_API_BASE || 'http://127.0.0.1:3001';
const TIMEOUT_MS = parseInt(process.env.USER360_TIMEOUT_MS || '12000', 10);

// Node 18+ has global fetch. Guard in case of older runtime.
const _fetch = global.fetch;

/**
 * Internal GET with the caller's auth forwarded. Returns parsed JSON or throws.
 */
async function passthru(path, cred) {
  if (!_fetch) throw new Error('global fetch unavailable (Node < 18)');
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await _fetch(BASE + path, {
      headers: { ...(cred.authorization ? { Authorization: cred.authorization } : {}), ...(cred.cookie ? { Cookie: cred.cookie } : {}) },
      signal: ctrl.signal,
    });
    const text = await r.text();
    let body;
    try { body = text ? JSON.parse(text) : null; } catch { body = { raw: text }; }
    if (!r.ok) {
      const err = new Error(`upstream ${r.status} for ${path}`);
      err.status = r.status;
      err.body = body;
      throw err;
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

router.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'user360', base: BASE, timeoutMs: TIMEOUT_MS });
});

router.get('/:q', rbac.requirePage('identity-diag', 'read'), async (req, res) => {
  const q = (req.params.q || '').trim();
  if (!q) return res.status(400).json({ error: 'path parameter q is required' });
  if (q.length > 256) return res.status(400).json({ error: 'query too long' });

  const auth = { authorization: req.headers.authorization || '', cookie: req.headers.cookie || '' };
  const _errors = {};

  // 1) Seed lookup — must succeed; everything else keys off it.
  let identity;
  try {
    identity = await passthru(`/api/identity/lookup?q=${encodeURIComponent(q)}`, auth);
  } catch (e) {
    const status = e.status === 404 ? 404 : 502;
    return res.status(status).json({
      error: status === 404 ? 'user not found' : 'seed lookup failed',
      detail: e.message,
      upstream: e.body || null,
    });
  }

  const email = identity.email || identity.upn || '';
  const sam = identity.samAccountName || '';

  // 2) Fan-out. Each entry: [sectionKey, promise]. null section on failure.
  const jobs = [];
  const add = (key, path) => {
    jobs.push([key, passthru(path, auth)
      .catch(e => { _errors[key] = { detail: e.message, status: e.status || null }; return null; })]);
  };

  const entraKey = email || identity.upn || '';
  if (entraKey) {
    // Entra directory record (migration side-by-side with AD). search matches
    // UPN/display_name/mail; limit=1 — we resolve to the single best match below.
    add('entra', `/api/entra/users?search=${encodeURIComponent(entraKey)}&limit=1`);
  }
  if (email) {
    add('tickets', `/api/sdp/tickets?email=${encodeURIComponent(email)}`);
    add('signins', `/api/entra/signins?user=${encodeURIComponent(email)}&hours=168&limit=25`);
  }
  if (sam) {
    add('groups', `/api/user-project/users/${encodeURIComponent(sam)}/groups`);
  }
  // devices keyed on same free-form q the seed accepted
  add('devices', `/api/identity/devices?q=${encodeURIComponent(q)}`);
  // grants: route has no per-user filter; pull active, filter to this user below.
  add('grants', `/api/user-project/grants?status=active`);

  const results = await Promise.allSettled(jobs.map(([, p]) => p));
  const sections = {};
  jobs.forEach(([key], i) => {
    const r = results[i];
    sections[key] = r.status === 'fulfilled' ? r.value : null;
  });

  // Resolve entra: /users returns a wrapped list; take the first row or null.
  // null is meaningful during migration — user exists in AD but not yet in Entra.
  let entra = null;
  const es = sections.entra;
  if (es) {
    const list = Array.isArray(es) ? es : (es.data || es.rows || es.users || []);
    entra = (Array.isArray(list) && list.length) ? list[0] : null;
  }

  // Filter active grants to this user (route returns the full active set).
  let grants = sections.grants ?? null;
  if (grants) {
    const list = Array.isArray(grants) ? grants : (grants.data || grants.grants || grants.rows || []);
    const needleSam = (sam || '').toLowerCase();
    const needleEmail = (email || '').toLowerCase();
    if (Array.isArray(list)) {
      grants = list.filter(g => {
        const hay = JSON.stringify(g).toLowerCase();
        return (needleSam && hay.includes(needleSam)) || (needleEmail && hay.includes(needleEmail));
      });
    }
  }

  // Identity block: AD (seed) + Entra side-by-side, plus enrichment already on seed.
  const identityBlock = {
    ad: identity,                 // full AD record + actions + riskScore
    entra,                        // Entra directory record or null (not migrated)
    okta: identity.okta ?? null,
    zscaler: identity.zscaler ?? null,
  };

  res.json({
    query: q,
    identity: identityBlock,
    devices: sections.devices ?? null,
    tickets: sections.tickets ?? null,
    signins: sections.signins ?? null,
    groups: sections.groups ?? null,
    grants,
    _errors: Object.keys(_errors).length ? _errors : undefined,
  });
});

module.exports = router;
