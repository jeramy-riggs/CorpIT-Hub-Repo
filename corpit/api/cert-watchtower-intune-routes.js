'use strict';
// =============================================================================
// Cert Watchtower — Intune Cloud Cert Routes (v1.2.0)
// File: /var/www/api/cert-watchtower-intune-routes.js
//
// Mounts at /api/cert/intune
// GET  /api/cert/intune        — list all cert_intune rows
// POST /api/cert/intune/sync   — trigger manual sync from Graph API
// PATCH /api/cert/intune/:id/prtg — save PRTG token/enable for a row
// POST /api/cert/intune/:id/push  — manual test push to PRTG
// =============================================================================

const express = require('express');
const path    = require('path');

module.exports = function createIntuneRouter(pool, rbac) {
  const router = express.Router();
  router.use(rbac.loadCurrentUser);

  // ──────────────────────────────────────────────────────────────────────────
  // GET /api/cert/intune
  // List all cert_intune rows (Cloud Services section in UI)
  // ──────────────────────────────────────────────────────────────────────────
  router.get('/api/cert/intune', rbac.requirePage('cert-watchtower', 'read'), async (req, res) => {
    try {
      const [rows] = await pool.query(
        `SELECT id, source_key, display_name, subject, serial_number, apple_identifier,
                not_after, last_modified, upload_status, cert_status, days_remaining,
                last_synced_at, prtg_push_enabled, prtg_token, prtg_sensor_id,
                prtg_last_push_at, prtg_last_push_status
         FROM cert_intune
         ORDER BY not_after ASC`
      );
      // The PRTG push token is a credential: publish whether one is set, never the value
      // (the agent/file list routes already do this; the UI reads prtg_token_set).
      res.json({ certs: rows.map(r => { const { prtg_token, ...rest } = r; return { ...rest, prtg_token_set: !!(prtg_token && prtg_token !== '') }; }) });
    } catch (err) {
      console.error('GET /api/cert/intune failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ──────────────────────────────────────────────────────────────────────────
  // POST /api/cert/intune/sync
  // Trigger a manual sync from Microsoft Graph API
  // ──────────────────────────────────────────────────────────────────────────
  router.post('/api/cert/intune/sync', rbac.requirePage('cert-watchtower', 'admin'), async (req, res) => {
    try {
      const { syncIntuneApnsCert, syncIntuneVppToken } = require('./cert-watchtower-intune-sync');
      const [apnsResult, vppResult] = await Promise.all([
        syncIntuneApnsCert(pool),
        syncIntuneVppToken(pool),
      ]);
      const allOk = apnsResult.status === 'ok' && vppResult.status === 'ok';
      res.status(allOk ? 200 : 502).json({ ok: allOk, apns: apnsResult, vpp: vppResult });
    } catch (err) {
      console.error('POST /api/cert/intune/sync failed:', err);
      res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
  });

  // ──────────────────────────────────────────────────────────────────────────
  // PATCH /api/cert/intune/:id/prtg
  // Save PRTG token/enable for a cert_intune row
  // ──────────────────────────────────────────────────────────────────────────
  router.patch('/api/cert/intune/:id/prtg', rbac.requirePage('cert-watchtower', 'admin'), express.json(), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const { prtg_push_enabled, prtg_token, prtg_sensor_id } = req.body || {};
      await pool.query(
        `UPDATE cert_intune SET
           prtg_push_enabled = ?,
           prtg_token        = ?,
           prtg_sensor_id    = ?
         WHERE id = ?`,
        [
          prtg_push_enabled === '1' || prtg_push_enabled === 1 ? 1 : 0,
          prtg_token   ? String(prtg_token).trim()   : null,
          prtg_sensor_id ? String(prtg_sensor_id).trim() : null,
          id
        ]
      );
      res.json({ ok: true });
    } catch (err) {
      console.error('PATCH /api/cert/intune/:id/prtg failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ──────────────────────────────────────────────────────────────────────────
  // POST /api/cert/intune/:id/push
  // Manual test push to PRTG for a cert_intune row
  // ──────────────────────────────────────────────────────────────────────────
  router.post('/api/cert/intune/:id/push', rbac.requirePage('cert-watchtower', 'admin'), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const [[row]] = await pool.query('SELECT * FROM cert_intune WHERE id = ?', [id]);
      if (!row) return res.status(404).json({ error: 'Cert not found' });
      if (!row.prtg_token) return res.status(400).json({ error: 'No PRTG token configured' });

      // Load global PRTG config
      const [cfgRows] = await pool.query(
        `SELECT config_key, config_value FROM cert_config WHERE config_key IN
         ('prtg_enabled','prtg_core_host','prtg_push_port','prtg_push_protocol','prtg_verify_tls','prtg_timeout_ms','prtg_retry_count')`
      );
      const cfg = Object.fromEntries(cfgRows.map(r => [r.config_key, r.config_value]));
      if (cfg.prtg_enabled !== '1') return res.status(400).json({ error: 'PRTG push is globally disabled' });

      const { pushToPrtg } = require('./cert-watchtower-prtg-helper');
      const statusNum = { ok: 0, warning: 1, critical: 2, expired: 3, error: 4 }[row.cert_status] ?? 4;
      const result = await pushToPrtg({
        host:      cfg.prtg_core_host,
        port:      parseInt(cfg.prtg_push_port, 10) || 5050,
        protocol:  cfg.prtg_push_protocol || 'http',
        verifyTls: cfg.prtg_verify_tls === '1',
        timeoutMs: parseInt(cfg.prtg_timeout_ms, 10) || 5000,
        token:     row.prtg_token,
        channels: [
          { name: 'Days Until Expiry', value: Math.max(row.days_remaining || 0, 0), customUnit: 'days' },
          { name: 'Cert Status',       value: statusNum }
        ],
        statusText: `${row.display_name} cert posture ${row.cert_status}`
      });

      // Record outcome
      const status = result.ok ? 'ok' : (result.error || 'error').startsWith('sensor-mismatch') ? 'mismatch' : 'error';
      await pool.query(
        `UPDATE cert_intune SET prtg_last_push_at = NOW(), prtg_last_push_status = ?, prtg_last_push_response = ? WHERE id = ?`,
        [status, (result.body || result.error || '').toString().slice(0, 1000), id]
      );

      res.json({ ok: result.ok, result });
    } catch (err) {
      console.error('POST /api/cert/intune/:id/push failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
};
