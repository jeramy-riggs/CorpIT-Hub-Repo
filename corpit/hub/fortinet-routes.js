'use strict';
/**
 * fortinet-routes.js
 * Express router — mounts FortiGate endpoints at /api/fortinet/
 *
 * Routes:
 *   GET /api/fortinet/health          — quick connectivity test (no username needed)
 *   GET /api/fortinet/user-check      — full lookup chain for a username
 *     ?username=jsmith
 */

const express = require('express');
const https   = require('https');
const router  = express.Router();
const { checkUserFirewall } = require('./fortinet-lookup');

// RBAC (same idiom as identity-routes.js): these answer 'is this user on the
// firewall' for the Identity Diagnostics detail view, so they carry its gate.
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 2,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
const requireRead = rbac.requirePage('identity-diag', 'read');

// ── Health check ──────────────────────────────────────────────────────────────
// Verifies FortiGate credentials are configured and the appliance responds.
// Safe to call at any time — read-only, no username needed.
router.get('/health', requireRead, async (req, res) => {
  const host  = (process.env.FORTIGATE_HOST  || '').replace(/\/$/, '');
  const token = process.env.FORTIGATE_API_TOKEN;

  if (!host || !token) {
    return res.json({
      status: 'unconfigured',
      message: 'FORTIGATE_HOST or FORTIGATE_API_TOKEN not set in .env'
    });
  }

  try {
    const url = new URL(host + '/api/v2/monitor/system/status');
    const result = await new Promise((resolve, reject) => {
      const req = https.request(url, {
        method:  'GET',
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
        rejectUnauthorized: false
      }, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try   { resolve({ status: r.statusCode, body: JSON.parse(d) }); }
          catch { resolve({ status: r.statusCode, body: d }); }
        });
      });
      req.on('error', reject);
      req.setTimeout(10000, () => { req.destroy(); reject(new Error('Connection timed out')); });
      req.end();
    });

    if (result.status === 200 && result.body && result.body.status === 'success') {
      const r = result.body.results || {};
      return res.json({
        status:   'ok',
        hostname: r.hostname   || null,
        model:    r.model_name || null,
        version:  result.body.version || null,
        serial:   result.body.serial  || null
      });
    }
    return res.json({ status: 'error', httpStatus: result.status });

  } catch (e) {
    return res.json({ status: 'error', message: e.message });
  }
});

// ── User firewall check ───────────────────────────────────────────────────────
// Full lookup chain: DB → DHCP → FortiGate sessions + blocked traffic
// Only returns FortiGate data for Irvine in-office users.
router.get('/user-check', requireRead, async (req, res) => {
  const username = (req.query.username || '').trim().toLowerCase();

  if (!username) {
    return res.status(400).json({ error: 'username query parameter is required' });
  }

  try {
    const result = await checkUserFirewall(username);
    return res.json(result);
  } catch (e) {
    return res.status(500).json({
      error: `FortiGate lookup failed: ${e.message}`
    });
  }
});

module.exports = router;
