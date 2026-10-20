// =============================================================================
// Cert Watchtower — Phase 2: Express API Routes
// File: /var/www/api/cert-watchtower-routes.js
//
// Mounts as a router under /api/certs and /api/alerts in the main app.
// No changes to existing routes — fully additive.
//
// Dependencies: express, mysql2/promise, multer (for CSV upload)
//   npm install multer csv-parse
//   (express and mysql2 are already in your stack)
// =============================================================================

const express = require('express');

// === CORPIT-SECRET-CONFIG (2026-09-06) =======================================
// Config rows that hold a live credential. These must never reach a browser:
// each has an admin-gated path of its own for the rare case an operator needs
// the value. Callers get "<key>_set" instead so the UI can still render state.
const CORPIT_SECRET_CONFIG_KEYS = ['agent_enrollment_token'];

function corpitRedactConfig(config) {
  const out = Object.assign({}, config || {});
  for (const k of CORPIT_SECRET_CONFIG_KEYS) {
    if (Object.prototype.hasOwnProperty.call(out, k)) {
      out[k + '_set'] = !!(out[k] !== null && out[k] !== undefined && String(out[k]) !== '');
      delete out[k];
    }
  }
  return out;
}
// === end CORPIT-SECRET-CONFIG ================================================

const multer = require('multer');
const { parse: csvParse } = require('csv-parse/sync');
const tls = require('tls');
const certificateConnectHost = require('./cert-self-target');
const net = require('net');
const crypto = require('crypto');
// settingsfold W6 2026-10-12: PUT /api/cert-config writes an rbac_audit_log row
// (corpit_hub, via the rbac passed in by server.js).
const SA = require('./settings-audit');

// Multer config: in-memory, 1MB max (CSV files are tiny). No disk writes.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 1024 * 1024 } // 1 MB
});

// -----------------------------------------------------------------------------
// Factory: takes the existing mysql2 pool from the main app, returns a router.
// This keeps the DB pool singleton instead of creating a second one.
// -----------------------------------------------------------------------------
module.exports = function createCertWatchtowerRouter(pool, rbac) {
  const router = express.Router();
  router.use(rbac.loadCurrentUser);

  // ===========================================================================
  // Helper: load all config into a plain object for easy access
  // ===========================================================================
  async function loadConfig() {
    const [rows] = await pool.query('SELECT config_key, config_value FROM cert_config');
    return Object.fromEntries(rows.map(r => [r.config_key, r.config_value]));
  }

  // ===========================================================================
  // Helper: TLS handshake against host:port, return cert metadata.
  // Used by both /check endpoints and the cron (cron will require this file).
  // Exported below for reuse.
  // ===========================================================================
  function performCertCheck(hostname, port, sni, timeoutMs = 10000) {
    return new Promise((resolve) => {
      const startTime = Date.now();
      let resolved = false;
      const finish = (result) => {
        if (resolved) return;
        resolved = true;
        result.handshake_ms = Date.now() - startTime;
        resolve(result);
      };

      const socket = tls.connect({
        host: certificateConnectHost(hostname, port),
        port: port,
        servername: sni || hostname,
        rejectUnauthorized: false, // we WANT to inspect bad/self-signed certs
        timeout: timeoutMs
      }, () => {
        try {
          // getPeerCertificate(true) returns the full chain
          const peerCert = socket.getPeerCertificate(true);
          const resolvedIp = socket.remoteAddress;

          // Walk the chain to determine depth and self-signed status
          let depth = 1;
          let cur = peerCert;
          const seen = new Set();
          while (cur && cur.issuerCertificate && cur.issuerCertificate !== cur) {
            if (seen.has(cur.fingerprint256)) break; // safety against loops
            seen.add(cur.fingerprint256);
            depth++;
            cur = cur.issuerCertificate;
          }
          // Self-signed = subject == issuer on the leaf cert
          const subjectStr = JSON.stringify(peerCert.subject || {});
          const issuerStr = JSON.stringify(peerCert.issuer || {});
          const isSelfSigned = subjectStr === issuerStr ? 1 : 0;

          // Chain complete = the topmost cert in the chain is self-signed (root)
          // OR Node was able to walk all the way up. Incomplete = chain stops short.
          const topCert = cur;
          const topSubject = JSON.stringify(topCert?.subject || {});
          const topIssuer = JSON.stringify(topCert?.issuer || {});
          const chainComplete = (topSubject === topIssuer) ? 1 : 0;

          // Parse SANs from the "subjectaltname" string ("DNS:foo, DNS:bar, IP:1.2.3.4")
          const sanList = peerCert.subjectaltname
            ? peerCert.subjectaltname.split(',').map(s => s.trim())
            : [];

          socket.end();
          finish({
            ok: true,
            not_before: peerCert.valid_from ? new Date(peerCert.valid_from) : null,
            not_after: peerCert.valid_to ? new Date(peerCert.valid_to) : null,
            subject_cn: peerCert.subject?.CN || null,
            issuer_cn: peerCert.issuer?.CN || null,
            san_list: sanList,
            serial_number: peerCert.serialNumber || null,
            fingerprint_sha256: peerCert.fingerprint256 || null,
            is_self_signed: isSelfSigned,
            chain_complete: chainComplete,
            chain_depth: depth,
            resolved_ip: resolvedIp,
            error_message: null
          });
        } catch (err) {
          socket.destroy();
          finish({ ok: false, error_message: `parse error: ${err.message}` });
        }
      });

      socket.on('error', (err) => {
        finish({ ok: false, error_message: err.message });
      });
      socket.on('timeout', () => {
        socket.destroy();
        finish({ ok: false, error_message: 'connection timed out' });
      });
    });
  }

  // ===========================================================================
  // Helper: classify status from days_remaining + thresholds.
  // Returns one of: ok, info, warning, critical, expired
  // ===========================================================================
  function classifyStatus(daysRemaining, thresholds) {
    if (daysRemaining === null || daysRemaining === undefined) return 'error';
    if (daysRemaining < 0) return 'expired';
    if (daysRemaining <= thresholds.critical) return 'critical';
    if (daysRemaining <= thresholds.warning) return 'warning';
    if (daysRemaining <= thresholds.info) return 'info';
    return 'ok';
  }

  // ===========================================================================
  // Helper: write a check result + update cert_current. Used by both manual
  // /check endpoint and the cron. Returns the new check id.
  // ===========================================================================
  async function recordCheckResult(monitorId, result, thresholds) {
    let status, daysRemaining = null;

    if (!result.ok) {
      status = 'unreachable';
    } else {
      const msPerDay = 1000 * 60 * 60 * 24;
      daysRemaining = Math.floor((result.not_after - new Date()) / msPerDay);
      status = classifyStatus(daysRemaining, thresholds);
    }

    // Insert into cert_checks
    const [insertRes] = await pool.query(
      `INSERT INTO cert_checks
        (monitor_id, status, not_before, not_after, days_remaining,
         subject_cn, issuer_cn, san_list, serial_number, fingerprint_sha256,
         is_self_signed, chain_complete, chain_depth, resolved_ip,
         handshake_ms, error_message)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        monitorId, status,
        result.not_before || null, result.not_after || null, daysRemaining,
        result.subject_cn || null, result.issuer_cn || null,
        result.san_list ? JSON.stringify(result.san_list) : null,
        result.serial_number || null, result.fingerprint_sha256 || null,
        result.is_self_signed ?? null, result.chain_complete ?? null,
        result.chain_depth ?? null, result.resolved_ip || null,
        result.handshake_ms || null, result.error_message || null
      ]
    );
    const checkId = insertRes.insertId;

    // Compute unreachable_since: keep existing if still unreachable, set if newly so, null if recovered
    const [[currentRow]] = await pool.query(
      'SELECT unreachable_since, status FROM cert_current WHERE monitor_id = ?',
      [monitorId]
    );
    let unreachableSince = null;
    if (status === 'unreachable') {
      unreachableSince = currentRow?.unreachable_since || new Date();
    }

    // Upsert cert_current
    await pool.query(
      `INSERT INTO cert_current
        (monitor_id, last_check_id, status, not_after, days_remaining,
         subject_cn, issuer_cn, is_self_signed, chain_complete,
         unreachable_since, last_checked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
         last_check_id = VALUES(last_check_id),
         status = VALUES(status),
         not_after = VALUES(not_after),
         days_remaining = VALUES(days_remaining),
         subject_cn = VALUES(subject_cn),
         issuer_cn = VALUES(issuer_cn),
         is_self_signed = VALUES(is_self_signed),
         chain_complete = VALUES(chain_complete),
         unreachable_since = VALUES(unreachable_since),
         last_checked_at = VALUES(last_checked_at)`,
      [
        monitorId, checkId, status,
        result.not_after || null, daysRemaining,
        result.subject_cn || null, result.issuer_cn || null,
        result.is_self_signed ?? null, result.chain_complete ?? null,
        unreachableSince
      ]
    );

    return { checkId, status, daysRemaining };
  }

  // ===========================================================================
  // Helper: input validation
  // ===========================================================================
  function validateHostname(s) {
    // Accept DNS names and IPv4/IPv6 literals. Reject empty, whitespace, control chars.
    if (typeof s !== 'string') return false;
    const trimmed = s.trim();
    if (trimmed.length === 0 || trimmed.length > 255) return false;
    // Conservative: alphanumerics, dots, dashes, colons (for IPv6), no spaces or shell metachars
    return /^[a-zA-Z0-9.\-:_]+$/.test(trimmed);
  }
  function validatePort(p) {
    const n = Number(p);
    return Number.isInteger(n) && n >= 1 && n <= 65535;
  }
  function validateEmail(s) {
    if (s === null || s === undefined || s === '') return true; // optional field
    if (typeof s !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 255;
  }

  // ===========================================================================
  // Per-monitor manual check rate limiter (in-memory)
  // Map<monitor_id, last_check_timestamp_ms>
  // Server restart resets it; that's fine for this use case.
  // ===========================================================================
  const lastManualCheck = new Map();

  // ===========================================================================
  // ROUTES
  // ===========================================================================


  // === CORPIT-STALE-TRUTH (2026-09-06) =====================================
  // Re-derive the time-based fields from the certificate's own not_after before
  // they reach the dashboard. See the header note on GET /api/certs.
  //
  // A snapshot is "stale" once it is older than twice the daily check interval,
  // which is the point at which a run has definitively been missed.
  const CORPIT_STALE_AFTER_HOURS = 48;
  const CORPIT_TIME_DERIVED = new Set(['ok', 'info', 'warning', 'critical', 'expired']);

  async function corpitFreshen(rows) {
    let thresholds;
    try {
      const config = await loadConfig();
      thresholds = {
        info:     Number(config.threshold_info_days)     || 90,
        warning:  Number(config.threshold_warning_days)  || 60,
        critical: Number(config.threshold_critical_days) || 30
      };
    } catch (err) {
      // Without thresholds we cannot reclassify. Return the stored values
      // untouched rather than inventing a status -- but still flag staleness.
      console.error('corpitFreshen: threshold load failed, serving stored status:', err.message);
      thresholds = null;
    }

    return rows.map(r => {
      const ageH = r.check_age_hours;
      const out = Object.assign({}, r, {
        days_remaining_at_check: r.days_remaining,
        status_at_check:         r.status,
        stale: ageH === null || ageH === undefined ? null : Number(ageH) >= CORPIT_STALE_AFTER_HOURS
      });

      const live = r.days_remaining_live;
      if (thresholds && live !== null && live !== undefined &&
          CORPIT_TIME_DERIVED.has(r.status)) {
        out.days_remaining = Number(live);
        out.status = classifyStatus(Number(live), thresholds);
      }
      delete out.days_remaining_live;
      return out;
    });
  }
  // === end CORPIT-STALE-TRUTH ==============================================

  // ---- GET /api/certs ------------------------------------------------------
  // List all monitors with their current status. Powers the dashboard.
  router.get('/api/certs', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const [rows] = await pool.query(
        `SELECT m.id, m.hostname, m.port, m.label, m.owner_email, m.servername_sni,
                m.notes, m.enabled, m.created_by, m.created_at, m.updated_at,
                m.prtg_push_enabled, m.prtg_last_push_status,
                -- CORPIT: boolean only; the raw token is a write credential
                -- for a sensor on a PRTG core shared with itam.nrpi.local.
                (m.prtg_token IS NOT NULL AND m.prtg_token <> '') AS prtg_token_set,
                c.status, c.not_after, c.days_remaining,
                c.subject_cn, c.issuer_cn,
                c.is_self_signed, c.chain_complete,
                c.unreachable_since, c.last_checked_at,
                -- CORPIT-STALE-TRUTH: days recomputed from the observed
                -- not_after, so the figure stays right when the checker is down.
                DATEDIFF(c.not_after, NOW())                  AS days_remaining_live,
                TIMESTAMPDIFF(HOUR, c.last_checked_at, NOW()) AS check_age_hours
         FROM cert_monitors m
         LEFT JOIN cert_current c ON c.monitor_id = m.id
         ORDER BY
           CASE c.status
             WHEN 'expired' THEN 0
             WHEN 'critical' THEN 1
             WHEN 'unreachable' THEN 2
             WHEN 'warning' THEN 3
             WHEN 'info' THEN 4
             WHEN 'ok' THEN 5
             ELSE 6
           END,
           c.days_remaining ASC,
           m.hostname ASC`
      );
      res.json({ monitors: await corpitFreshen(rows) });
    } catch (err) {
      console.error('GET /api/certs failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- POST /api/certs -----------------------------------------------------
  // Add a single monitor (GUI form). Defaults to disabled per design.
  router.post('/api/certs', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const { hostname, port = 443, label, owner_email, servername_sni, notes, created_by } = req.body || {};

      if (!validateHostname(hostname)) return res.status(400).json({ error: 'Invalid hostname' });
      if (!validatePort(port)) return res.status(400).json({ error: 'Invalid port (1-65535)' });
      if (owner_email && !validateEmail(owner_email)) return res.status(400).json({ error: 'Invalid owner_email' });
      if (servername_sni && !validateHostname(servername_sni)) return res.status(400).json({ error: 'Invalid SNI hostname' });

      const [result] = await pool.query(
        `INSERT INTO cert_monitors
          (hostname, port, label, owner_email, servername_sni, notes, enabled, created_by)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
        [hostname.trim(), Number(port), label || null, owner_email || null,
         servername_sni || null, notes || null, created_by || null]
      );
      res.status(201).json({ id: result.insertId });
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'A monitor with this hostname:port already exists' });
      }
      console.error('POST /api/certs failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- PUT /api/certs/:id --------------------------------------------------
  // Edit monitor (incl. toggling enabled). Partial updates allowed.
  router.put('/api/certs/:id', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const allowed = ['hostname', 'port', 'label', 'owner_email', 'servername_sni', 'notes', 'enabled'];
      const updates = [];
      const values = [];

      for (const field of allowed) {
        if (Object.prototype.hasOwnProperty.call(req.body || {}, field)) {
          const v = req.body[field];
          // Per-field validation
          if (field === 'hostname' && !validateHostname(v)) return res.status(400).json({ error: 'Invalid hostname' });
          if (field === 'port' && !validatePort(v)) return res.status(400).json({ error: 'Invalid port' });
          if (field === 'owner_email' && v && !validateEmail(v)) return res.status(400).json({ error: 'Invalid owner_email' });
          if (field === 'servername_sni' && v && !validateHostname(v)) return res.status(400).json({ error: 'Invalid SNI' });
          if (field === 'enabled' && (v !== 0 && v !== 1 && v !== true && v !== false)) return res.status(400).json({ error: 'enabled must be 0/1' });

          updates.push(`${field} = ?`);
          values.push(field === 'enabled' ? (v ? 1 : 0) : v);
        }
      }

      if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

      values.push(id);
      const [result] = await pool.query(
        `UPDATE cert_monitors SET ${updates.join(', ')} WHERE id = ?`,
        values
      );
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Monitor not found' });
      res.json({ ok: true });
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'A monitor with this hostname:port already exists' });
      }
      console.error('PUT /api/certs/:id failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- DELETE /api/certs/:id -----------------------------------------------
  // Removes monitor + cascades cert_checks, cert_current, cert_alerts.
  router.delete('/api/certs/:id', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const [result] = await pool.query('DELETE FROM cert_monitors WHERE id = ?', [id]);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Monitor not found' });
      res.json({ ok: true });
    } catch (err) {
      console.error('DELETE /api/certs/:id failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- POST /api/certs/:id/check -------------------------------------------
  // Trigger an immediate check. Rate-limited per monitor (configurable cooldown).
  router.post('/api/certs/:id/check', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const config = await loadConfig();
      const cooldownMs = (Number(config.manual_check_cooldown_s) || 300) * 1000;

      const last = lastManualCheck.get(id);
      if (last && Date.now() - last < cooldownMs) {
        const waitS = Math.ceil((cooldownMs - (Date.now() - last)) / 1000);
        return res.status(429).json({ error: `Cooldown active. Try again in ${waitS}s.` });
      }

      const [[monitor]] = await pool.query(
        'SELECT id, hostname, port, servername_sni FROM cert_monitors WHERE id = ?',
        [id]
      );
      if (!monitor) return res.status(404).json({ error: 'Monitor not found' });

      lastManualCheck.set(id, Date.now());

      const result = await performCertCheck(monitor.hostname, monitor.port, monitor.servername_sni);
      const thresholds = {
        info: Number(config.threshold_info_days) || 90,
        warning: Number(config.threshold_warning_days) || 60,
        critical: Number(config.threshold_critical_days) || 30
      };
      const recorded = await recordCheckResult(id, result, thresholds);
      res.json({ ok: true, ...recorded });
    } catch (err) {
      console.error('POST /api/certs/:id/check failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- GET /api/certs/:id/history ------------------------------------------
  // History for the per-monitor detail view. Returns last N checks (default 90).
  router.get('/api/certs/:id/history', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });
      const limit = Math.min(Math.max(Number(req.query.limit) || 90, 1), 365);

      const [rows] = await pool.query(
        `SELECT id, checked_at, status, not_before, not_after, days_remaining,
                subject_cn, issuer_cn, san_list, serial_number, fingerprint_sha256,
                is_self_signed, chain_complete, chain_depth, resolved_ip,
                handshake_ms, error_message
         FROM cert_checks
         WHERE monitor_id = ?
         ORDER BY checked_at DESC
         LIMIT ?`,
        [id, limit]
      );
      res.json({ history: rows });
    } catch (err) {
      console.error('GET /api/certs/:id/history failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- POST /api/certs/import ----------------------------------------------
  // CSV bulk import. Columns: hostname, port, label, owner_email, servername_sni, notes
  // Header row required. All imported monitors are created disabled.
  router.post('/api/certs/import', rbac.requirePage('cert-watchtower','admin'), upload.single('file'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded (field name: file)' });

      const csvText = req.file.buffer.toString('utf8');
      let records;
      try {
        records = csvParse(csvText, { columns: true, skip_empty_lines: true, trim: true });
      } catch (e) {
        return res.status(400).json({ error: `CSV parse error: ${e.message}` });
      }

      const results = { added: 0, skipped: [], errors: [] };
      const conn = await pool.getConnection();
      try {
        for (let i = 0; i < records.length; i++) {
          const row = records[i];
          const lineNum = i + 2; // +1 for header, +1 for 1-indexing
          const hostname = (row.hostname || '').trim();
          const port = row.port ? Number(row.port) : 443;
          const label = row.label?.trim() || null;
          const owner_email = row.owner_email?.trim() || null;
          const servername_sni = row.servername_sni?.trim() || null;
          const notes = row.notes?.trim() || null;

          if (!validateHostname(hostname)) {
            results.errors.push({ line: lineNum, error: 'invalid hostname', row });
            continue;
          }
          if (!validatePort(port)) {
            results.errors.push({ line: lineNum, error: 'invalid port', row });
            continue;
          }
          if (owner_email && !validateEmail(owner_email)) {
            results.errors.push({ line: lineNum, error: 'invalid owner_email', row });
            continue;
          }

          try {
            await conn.query(
              `INSERT INTO cert_monitors
                (hostname, port, label, owner_email, servername_sni, notes, enabled, created_by)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
              [hostname, port, label, owner_email, servername_sni, notes, 'csv-import']
            );
            results.added++;
          } catch (e) {
            if (e.code === 'ER_DUP_ENTRY') {
              results.skipped.push({ line: lineNum, reason: 'duplicate', hostname, port });
            } else {
              results.errors.push({ line: lineNum, error: e.message, row });
            }
          }
        }
      } finally {
        conn.release();
      }
      res.json(results);
    } catch (err) {
      console.error('POST /api/certs/import failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- GET /api/alerts -----------------------------------------------------
  // Powers the Alerts tab. Returns active alerts by default, or includes
  // recently-resolved if ?include_resolved=true (last 30 days).
  router.get('/api/alerts', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const includeResolved = req.query.include_resolved === 'true';
      const sql = includeResolved
        ? `SELECT a.*, m.hostname, m.port, m.label
           FROM cert_alerts a
           JOIN cert_monitors m ON m.id = a.monitor_id
           WHERE a.resolved_at IS NULL
              OR a.resolved_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
           ORDER BY
             CASE a.severity
               WHEN 'expired' THEN 0
               WHEN 'critical' THEN 1
               WHEN 'unreachable' THEN 2
               WHEN 'warning' THEN 3
               WHEN 'info' THEN 4
             END,
             a.triggered_at DESC`
        : `SELECT a.*, m.hostname, m.port, m.label
           FROM cert_alerts a
           JOIN cert_monitors m ON m.id = a.monitor_id
           WHERE a.resolved_at IS NULL
           ORDER BY
             CASE a.severity
               WHEN 'expired' THEN 0
               WHEN 'critical' THEN 1
               WHEN 'unreachable' THEN 2
               WHEN 'warning' THEN 3
               WHEN 'info' THEN 4
             END,
             a.triggered_at DESC`;
      const [rows] = await pool.query(sql);
      res.json({ alerts: rows });
    } catch (err) {
      console.error('GET /api/alerts failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- POST /api/alerts/:id/ack --------------------------------------------
  // Mark alert as acknowledged. Body: { acknowledged_by: 'username' }
  router.post('/api/alerts/:id/ack', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });
      const ackBy = (req.body?.acknowledged_by || 'unknown').toString().slice(0, 255);

      const [result] = await pool.query(
        `UPDATE cert_alerts
         SET acknowledged_at = NOW(), acknowledged_by = ?
         WHERE id = ? AND acknowledged_at IS NULL`,
        [ackBy, id]
      );
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Alert not found or already acknowledged' });
      res.json({ ok: true });
    } catch (err) {
      console.error('POST /api/alerts/:id/ack failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- GET /api/cert-config ------------------------------------------------
  // Read current config (thresholds, fallback email, etc.)
  router.get('/api/cert-config', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const config = await loadConfig();
      res.json({ config: corpitRedactConfig(config) });
    } catch (err) {
      console.error('GET /api/cert-config failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- PUT /api/cert-config ------------------------------------------------
  // Update one or more config keys. Body: { key1: 'value1', key2: 'value2' }
  // Only known keys are accepted; unknown keys silently ignored.
  router.put('/api/cert-config', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const allowed = new Set([
        'threshold_info_days', 'threshold_warning_days', 'threshold_critical_days',
        'unreachable_alert_days', 'history_retention_days', 'manual_check_cooldown_s',
        'fallback_alert_email'
        // PRTG keys deliberately excluded — Phase 2 of cert-watchtower itself
      ]);
      const updates = [];
      for (const [k, v] of Object.entries(req.body || {})) {
        if (!allowed.has(k)) continue;
        updates.push([k, String(v)]);
      }
      if (updates.length === 0) return res.status(400).json({ error: 'No valid config keys provided' });

      const saBefore = await SA.byKey(pool, 'SELECT config_key, config_value FROM cert_config', [], 'config_key', 'config_value');
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        for (const [k, v] of updates) {
          await conn.query(
            'UPDATE cert_config SET config_value = ? WHERE config_key = ?',
            [v, k]
          );
        }
        await conn.commit();
      } catch (e) {
        await conn.rollback();
        throw e;
      } finally {
        conn.release();
      }
      const saAfter = await SA.byKey(pool, 'SELECT config_key, config_value FROM cert_config', [], 'config_key', 'config_value');
      await SA.record(rbac, req, 'cert-watchtower', 'settings_saved', SA.entry({ what: 'cert_config', op: 'update',
        before: saBefore, after: saAfter, keys: updates.map(u => u[0]), secretKeys: CORPIT_SECRET_CONFIG_KEYS }));
      res.json({ ok: true, updated: updates.map(u => u[0]) });
    } catch (err) {
      console.error('PUT /api/cert-config failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- GET /api/certs/status-summary ---------------------------------------
  // Compact summary for the portal home card badge. Returns counts per severity.
  router.get('/api/certs/status-summary', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const [rows] = await pool.query(
        `SELECT c.status, COUNT(*) AS count
         FROM cert_current c
         JOIN cert_monitors m ON m.id = c.monitor_id
         WHERE m.enabled = 1
         GROUP BY c.status`
      );
      const summary = { ok: 0, info: 0, warning: 0, critical: 0, expired: 0, unreachable: 0, error: 0 };
      for (const r of rows) summary[r.status] = r.count;
      const totalAlerting = summary.info + summary.warning + summary.critical + summary.expired + summary.unreachable;
      res.json({ summary, total_alerting: totalAlerting });
    } catch (err) {
      console.error('GET /api/certs/status-summary failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Expose helpers for the cron job to reuse
  router._certHelpers = { performCertCheck, recordCheckResult, loadConfig, classifyStatus };

  return router;
};
