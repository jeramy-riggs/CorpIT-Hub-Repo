'use strict';
/**
 * meraki-routes.js
 * Express router — mounts Meraki NOC endpoints at /api/meraki/
 *
 * GET /api/meraki/health      — verify API key works
 * GET /api/meraki/noc         — full NOC dashboard data
 * GET /api/meraki/ap/:serial  — per-AP detail (wireless status + clients)
 */

const express = require('express');
const router  = express.Router();
// ---- RBAC enforcement (Slice 7: meraki-noc) ----
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
// ---------------------------------------------------------------------
const { getNocData, getApDetail, getClientByMac, getWifiConnectionHistory } = require('./meraki-lookup');

// Simple in-memory cache — NOC data is expensive (multiple API calls)
// Cache for 30 seconds to avoid hammering Meraki API on every browser refresh
let nocCache     = null;
let nocCacheTime = 0;
const CACHE_TTL  = 30 * 1000; // 30 seconds

// ── Health check ──────────────────────────────────────────────────────────────
router.get('/health', rbac.requirePage('meraki-noc','read'), async (req, res) => {
  const token = process.env.MERAKI_API_KEY;
  if (!token) {
    return res.json({ status: 'unconfigured', message: 'MERAKI_API_KEY not set in .env' });
  }
  const https = require('https');
  try {
    const result = await new Promise((resolve, reject) => {
      const url = new URL('https://api.meraki.com/api/v1/organizations');
      const req = https.request(url, {
        method:  'GET',
        headers: { 'X-Cisco-Meraki-API-Key': token, 'Accept': 'application/json' }
      }, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try   { resolve({ status: r.statusCode, body: JSON.parse(d) }); }
          catch { resolve({ status: r.statusCode, body: d }); }
        });
      });
      req.on('error', reject);
      req.setTimeout(10000, () => { req.destroy(); reject(new Error('Timeout')); });
      req.end();
    });

    if (result.status === 200 && Array.isArray(result.body) && result.body.length > 0) {
      return res.json({
        status: 'ok',
        org:    result.body[0].name,
        orgId:  result.body[0].id
      });
    }
    return res.json({ status: 'error', httpStatus: result.status });
  } catch (e) {
    return res.json({ status: 'error', message: e.message });
  }
});

// ── NOC dashboard data ────────────────────────────────────────────────────────
router.get('/noc', rbac.requirePage('meraki-noc','read'), async (req, res) => {
  try {
    const now = Date.now();
    const forceRefresh = req.query.refresh === '1';

    if (!forceRefresh && nocCache && (now - nocCacheTime) < CACHE_TTL) {
      return res.json({ ...nocCache, cached: true,
                        cacheAge: Math.round((now - nocCacheTime) / 1000) });
    }

    const data = await getNocData();
    if (data.success) {
      nocCache     = data;
      nocCacheTime = now;
    }
    return res.json({ ...data, cached: false });
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// ── Per-AP detail ─────────────────────────────────────────────────────────────
router.get('/ap/:serial', rbac.requirePage('meraki-noc','read'), async (req, res) => {
  const { serial } = req.params;
  if (!serial || serial.length < 10) {
    return res.status(400).json({ error: 'Invalid serial number' });
  }
  try {
    const data = await getApDetail(serial);
    return res.json(data);
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});


// ── Client lookup by MAC ──────────────────────────────────────────────────────
// Used by identity-diag to show WiFi status for a specific user device.
// GET /api/meraki/client?mac=00:ce:39:d3:a3:f0
router.get('/client', rbac.requirePage('meraki-noc','read'), async (req, res) => {
  const mac = (req.query.mac || '').trim();
  if (!mac) {
    return res.status(400).json({ found: false, error: 'mac query parameter is required' });
  }
  try {
    const data = await getClientByMac(mac);
    return res.json(data);
  } catch (e) {
    return res.status(500).json({ found: false, error: e.message });
  }
});


router.get('/wifi-events', rbac.requirePage('meraki-noc','read'), async (req, res) => {
  const mac   = (req.query.mac || '').trim();
  const hours = req.query.hours || '24';
  if (!mac) {
    return res.status(400).json({ found: false, error: 'mac query parameter is required' });
  }
  try {
    const data = await getWifiConnectionHistory(mac, hours);
    return res.json(data);
  } catch (e) {
    return res.status(500).json({ found: false, error: e.message });
  }
});


// Legacy alias for /apstats/:serial — frontend expected connectionStats field
// that was never wired up. Returns empty stub so frontend try/catch handles cleanly.
router.get('/apstats/:serial', rbac.requirePage('meraki-noc','read'), (req, res) => {
  res.json({ serial: req.params.serial, connectionStats: null });
});

module.exports = router;
