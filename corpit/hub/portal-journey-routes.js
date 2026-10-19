// ──────────────────────────────────────────────────────────────
// portal-journey-routes.js — Access Portal journey log for the Health Center page.
//
// Mount: app.use('/api/system/portal-journey', require('./portal-journey-routes').router);
//
// Read-only. Relays to the Access Portal backend's own loopback-only, key-guarded
// /internal/journey/summary and /internal/journey/person (the same PORTAL_LOOKUP_KEY
// portal-access.js uses). The backend keeps the log for 90 days in its own
// journey.db and does all the counting; this file only gates and relays.
//
// Super-admins only, per route (requireSuperAdmin, as /api/system/cluster). The
// router has its own mount path so its loadCurrentUser never runs for the other
// /api/system routes. A person lookup reads one person's activity, so each one
// also writes its own audit row naming who was looked up: requireSuperAdmin
// de-duplicates reads per path, which would hide the second address.
//
// The portal backend runs on the node that holds its data. Anywhere else the
// call fails and the page says the log is unavailable; it never shows zeros.
// ──────────────────────────────────────────────────────────────
'use strict';

const express = require('express');
const http = require('http');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const MAX_BYTES = 8 * 1024 * 1024;
const KEEP_DAYS = 90;
const EMAIL_RE = /^[^\s@<>"'(),;:]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,}$/i;

function portalCall(path, payload, timeoutMs) {
  return new Promise(function (resolve, reject) {
    const body = JSON.stringify(payload);
    let deadline;
    const req = http.request({
      host: '127.0.0.1', port: 8001, path: path, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        'X-Portal-Lookup-Key': process.env.PORTAL_LOOKUP_KEY || '' },
    }, function (res) {
      let chunks = [], size = 0;
      res.on('data', function (c) {
        size += c.length;
        if (size > MAX_BYTES) { req.destroy(new Error('the journey log answer was too large')); return; }
        chunks.push(c);
      });
      res.on('aborted', function () { req.destroy(new Error('the journey log response was interrupted')); });
      res.on('error', function (e) { req.destroy(e); });
      res.on('end', function () {
        let j = null;
        try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) { return reject(new Error('the journey log did not answer in JSON')); }
        if (res.statusCode !== 200 || !j || !j.ok) return reject(new Error('the journey log answered HTTP ' + res.statusCode));
        resolve(j.data);
      });
    });
    deadline = setTimeout(function () { req.destroy(new Error('the journey log exceeded its time limit')); }, timeoutMs);
    req.on('close', function () { clearTimeout(deadline); });
    req.setTimeout(timeoutMs, function () { req.destroy(new Error('the journey log did not answer within ' + (timeoutMs / 1000) + ' s')); });
    req.on('error', function (e) {
      reject(new Error(e && e.code === 'ECONNREFUSED' ? 'the Access Portal backend is not running on this node' : (e && e.message) || 'the journey log could not be reached'));
    });
    req.end(body);
  });
}

function intIn(v, lo, hi, dflt) {
  const n = parseInt(v, 10);
  return isFinite(n) ? Math.max(lo, Math.min(hi, n)) : dflt;
}

const router = express.Router();
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 2,
  charset: 'utf8mb4',
});
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

router.get('/summary', rbac.requireSuperAdmin, async function (req, res) {
  const hours = intIn(req.query.hours, 1, KEEP_DAYS * 24, 24);
  try {
    res.set('Cache-Control', 'no-store');
    res.json({ ok: true, data: await portalCall('/internal/journey/summary', { hours: hours }, 30000) });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Journey log unavailable: ' + e.message });
  }
});

router.get('/person', rbac.requireSuperAdmin, async function (req, res) {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'Enter a full email address.' });
  const days = intIn(req.query.days, 1, KEEP_DAYS, KEEP_DAYS);
  res.set('Cache-Control', 'no-store, private');
  try {
    const peer = String(req.socket && req.socket.remoteAddress || '');
    const local = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(peer);
    const ip = String((local && req.get('X-Real-IP')) || peer).split(',')[0].trim().slice(0,45) || null;
    await pool.execute(
      `INSERT INTO rbac_audit_log (actor_email, action, target_email, target_page_key, details, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [req.user.email, 'portal_journey_lookup', email, 'health-center', JSON.stringify({days: days}), ip,
       String(req.get('User-Agent') || '').slice(0,500) || null]);
  } catch (e) {
    console.error('[portal-journey] required lookup audit failed:', e.message);
    return res.status(503).json({ok: false, error: 'The audit log could not record this lookup. No personal journey was read. Retry when the audit service is available.'});
  }
  try {
    res.set('Cache-Control', 'no-store');
    res.json({ ok: true, data: await portalCall('/internal/journey/person', { email: email, days: days }, 20000) });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Journey log unavailable: ' + e.message });
  }
});

require('./user-activity').register({router, pool, rbac, portalCall});

module.exports = { router: router, portalCall: portalCall };
