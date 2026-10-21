// =============================================================================
// Cert Watchtower — Phase 2: Agent Routes
// File: /var/www/api/cert-watchtower-agent-routes.js
//
// Mounts as a router under /api/agents and /api/findings.
// Adds endpoints for the Windows agent (and future Linux/Mac agents) plus
// management/dashboard endpoints for the internal portal.
//
// AUTHENTICATION:
//   - /api/agents/checkin requires Authorization: Bearer <token>
//     Token must match cert_config.agent_enrollment_token.
//   - All other endpoints are unauthenticated (internal portal pattern).
//
// No new npm packages — uses crypto (built-in).
// =============================================================================

const express = require('express');
const crypto = require('crypto');
// hotfix-bundle3 2026-10-21 (F19/F20/F21): scan-target policy shared with the
// cron scanner — *.nrpi.local / 10.x hosts only, no 'basic' transport, strict
// scan_stores format.
const {
  isAllowedWinrmHost, isAllowedWinrmTransport, isValidScanStores, winrmTargetRefusal
} = require('./cert-watchtower-guards');

module.exports = function createAgentRouter(pool, rbac) {
  const router = express.Router();
  // DEV: no enrolled per-agent credentials exist yet. Reject before session
  // lookup or body parsing; the server-side WinRM scanner uses other routes.
  router.post('/api/agents/checkin', (_req, res) =>
    res.status(503).json({ error: 'Agent check-in is disabled on DEV' }));
  router.use(rbac.loadCurrentUser);

  // ---------------------------------------------------------------------------
  // Helper: load config (same pattern as cert-watchtower-routes.js)
  // ---------------------------------------------------------------------------
  async function loadConfig() {
    const [rows] = await pool.query('SELECT config_key, config_value FROM cert_config');
    return Object.fromEntries(rows.map(r => [r.config_key, r.config_value]));
  }

  // ---------------------------------------------------------------------------
  // Helper: classify cert status from days_remaining + thresholds.
  // Mirrors the routes file so manual + agent + cron all behave the same.
  // ---------------------------------------------------------------------------
  function classifyStatus(daysRemaining, thresholds) {
    if (daysRemaining === null || daysRemaining === undefined) return 'error';
    if (daysRemaining < 0) return 'expired';
    if (daysRemaining <= thresholds.critical) return 'critical';
    if (daysRemaining <= thresholds.warning) return 'warning';
    if (daysRemaining <= thresholds.info) return 'info';
    return 'ok';
  }

  // ---------------------------------------------------------------------------
  // Helper: validate FQDN. Conservative — DNS-safe characters only.
  // ---------------------------------------------------------------------------
  function validateFqdn(s) {
    if (typeof s !== 'string') return false;
    const t = s.trim();
    if (t.length === 0 || t.length > 255) return false;
    return /^[a-zA-Z0-9.\-_]+$/.test(t);
  }

  // ---------------------------------------------------------------------------
  // Helper: validate CA name (H-8). ca_name is interpolated into a certutil
  // command line run through cmd.exe on the CA host, so only a conservative
  // character set is allowed — no quotes, ampersand, pipe, semicolons, etc.
  // ---------------------------------------------------------------------------
  function validateCaName(s) {
    if (typeof s !== 'string') return false;
    return /^[A-Za-z0-9._ -]{1,255}$/.test(s);
  }

  // ---------------------------------------------------------------------------
  // Helper: constant-time string comparison for token check.
  // Prevents timing attacks even though it's an internal API.
  // ---------------------------------------------------------------------------
  function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const aBuf = Buffer.from(a);
    const bBuf = Buffer.from(b);
    if (aBuf.length !== bBuf.length) return false;
    return crypto.timingSafeEqual(aBuf, bBuf);
  }

  // ---------------------------------------------------------------------------
  // Middleware: require valid bearer token matching agent_enrollment_token.
  // Used on /api/agents/checkin only.
  // ---------------------------------------------------------------------------
  async function requireAgentToken(req, res, next) {
    try {
      const auth = req.get('Authorization') || '';
      const m = auth.match(/^Bearer\s+(.+)$/);
      if (!m) return res.status(401).json({ error: 'Missing bearer token' });

      const config = await loadConfig();
      const expected = config.agent_enrollment_token || '';
      if (expected.length === 0) {
        return res.status(503).json({ error: 'Agent enrollment is disabled (no token configured)' });
      }
      if (!timingSafeEqual(m[1], expected)) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      next();
    } catch (err) {
      console.error('Agent token check failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // ===========================================================================
  // POST /api/agents/checkin
  // The single most important endpoint. Called by every agent on every run.
  //
  // Body shape:
  // {
  //   "fqdn":            "SERVER01.nrpi.local",
  //   "hostname":        "SERVER01",
  //   "os_family":       "windows",
  //   "os_version":      "Windows Server 2022",
  //   "agent_version":   "1.0.0",
  //   "findings": [
  //     {
  //       "store_name":         "LocalMachine\\My",
  //       "store_location":     null,
  //       "thumbprint_sha1":    "ABC123...",
  //       "fingerprint_sha256": "DEF456...",
  //       "serial_number":      "01:23:...",
  //       "subject":            "CN=foo.com, O=...",
  //       "subject_cn":         "foo.com",
  //       "issuer":             "CN=Let's Encrypt R3, ...",
  //       "issuer_cn":          "Let's Encrypt R3",
  //       "san_list":           ["foo.com", "www.foo.com"],
  //       "not_before":         "2025-01-01T00:00:00Z",
  //       "not_after":          "2026-04-01T00:00:00Z",
  //       "has_private_key":    true,
  //       "is_self_signed":     false,
  //       "key_algorithm":      "RSA",
  //       "key_size":           2048,
  //       "signature_algorithm":"SHA256-RSA"
  //     }
  //   ]
  // }
  //
  // Response:
  //   { ok: true, agent_id: 12, findings_processed: 47, findings_new: 3, findings_updated: 44 }
  // ===========================================================================
  // DEV has no successful agent check-ins; its certificate hosts are scanned
  // server-side through WinRM. Keep the shared-token ingress unavailable until
  // per-agent credentials are implemented and the clients are migrated.
  router.post('/api/agents/checkin',
    requireAgentToken,
    express.json({ limit: '5mb' }),
    async (req, res) => {
      const body = req.body || {};
      const { fqdn, hostname, os_family = 'windows', os_version, agent_version, findings } = body;

      // --- Validate envelope ---
      if (!validateFqdn(fqdn)) {
        return res.status(400).json({ error: 'Invalid or missing fqdn' });
      }
      if (!Array.isArray(findings)) {
        return res.status(400).json({ error: 'findings must be an array' });
      }
      if (findings.length > 5000) {
        return res.status(413).json({ error: 'Too many findings in one check-in (max 5000)' });
      }
      const validOs = ['windows', 'linux', 'macos', 'other'];
      if (!validOs.includes(os_family)) {
        return res.status(400).json({ error: `os_family must be one of ${validOs.join(', ')}` });
      }

      // --- Source IP (informational only) ---
      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
        .split(',')[0].trim().slice(0, 64);

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();

        // --- Upsert the agent row ---
        const [existing] = await conn.query(
          'SELECT id, enabled FROM cert_agents WHERE fqdn = ?',
          [fqdn]
        );

        let agentId;
        if (existing.length > 0) {
          if (existing[0].enabled === 0) {
            await conn.rollback();
            return res.status(403).json({ error: 'Agent is disabled' });
          }
          agentId = existing[0].id;
          await conn.query(
            `UPDATE cert_agents
             SET hostname = ?, os_family = ?, os_version = ?, agent_version = ?,
                 ip_address = ?, last_checkin_at = NOW(), last_checkin_status = 'ok',
                 last_error = NULL
             WHERE id = ?`,
            [hostname || null, os_family, os_version || null, agent_version || null, ip, agentId]
          );
        } else {
          const [insertResult] = await conn.query(
            `INSERT INTO cert_agents
              (fqdn, hostname, os_family, os_version, agent_version, ip_address,
               last_checkin_at, last_checkin_status)
             VALUES (?, ?, ?, ?, ?, ?, NOW(), 'ok')`,
            [fqdn, hostname || null, os_family, os_version || null, agent_version || null, ip]
          );
          agentId = insertResult.insertId;
        }

        // --- Load thresholds for status classification ---
        const [configRows] = await conn.query('SELECT config_key, config_value FROM cert_config');
        const config = Object.fromEntries(configRows.map(r => [r.config_key, r.config_value]));
        const thresholds = {
          info: Number(config.threshold_info_days) || 90,
          warning: Number(config.threshold_warning_days) || 60,
          critical: Number(config.threshold_critical_days) || 30
        };

        // --- Process each finding ---
        let newCount = 0, updatedCount = 0, errorCount = 0;
        for (const f of findings) {
          // Per-finding validation. A bad finding is skipped, not fatal.
          if (!f.thumbprint_sha1 || !f.store_name) {
            errorCount++;
            continue;
          }

          // Compute days_remaining + status server-side from not_after
          let daysRemaining = null;
          let status = 'error';
          if (f.not_after) {
            const ms = new Date(f.not_after) - new Date();
            daysRemaining = Math.floor(ms / (1000 * 60 * 60 * 24));
            status = classifyStatus(daysRemaining, thresholds);
          }

          // Upsert by (agent_id, store_name, store_location, thumbprint_sha1)
          // The unique key handles the race; ON DUPLICATE KEY does the update.
          const [result] = await conn.query(
            `INSERT INTO cert_findings
              (agent_id, store_name, store_location, thumbprint_sha1,
               fingerprint_sha256, serial_number,
               subject, subject_cn, issuer, issuer_cn, san_list,
               not_before, not_after, days_remaining,
               has_private_key, is_self_signed,
               key_algorithm, key_size, signature_algorithm,
               status, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
               fingerprint_sha256 = VALUES(fingerprint_sha256),
               serial_number = VALUES(serial_number),
               subject = VALUES(subject),
               subject_cn = VALUES(subject_cn),
               issuer = VALUES(issuer),
               issuer_cn = VALUES(issuer_cn),
               san_list = VALUES(san_list),
               not_before = VALUES(not_before),
               not_after = VALUES(not_after),
               days_remaining = VALUES(days_remaining),
               has_private_key = VALUES(has_private_key),
               is_self_signed = VALUES(is_self_signed),
               key_algorithm = VALUES(key_algorithm),
               key_size = VALUES(key_size),
               signature_algorithm = VALUES(signature_algorithm),
               status = VALUES(status),
               last_seen_at = NOW()`,
            [
              agentId,
              String(f.store_name).slice(0, 128),
              String(f.store_location || '').slice(0, 255),
              String(f.thumbprint_sha1).toUpperCase().replace(/[^A-F0-9]/g, '').slice(0, 64),
              f.fingerprint_sha256 || null,
              f.serial_number || null,
              f.subject || null,
              f.subject_cn || null,
              f.issuer || null,
              f.issuer_cn || null,
              f.san_list ? JSON.stringify(f.san_list) : null,
              f.not_before || null,
              f.not_after || null,
              daysRemaining,
              f.has_private_key === undefined ? null : (f.has_private_key ? 1 : 0),
              f.is_self_signed === undefined ? null : (f.is_self_signed ? 1 : 0),
              f.key_algorithm || null,
              f.key_size || null,
              f.signature_algorithm || null,
              status
            ]
          );
          // affectedRows: 1 = inserted, 2 = updated, 0 = no change
          if (result.affectedRows === 1) newCount++;
          else updatedCount++;
        }

        await conn.commit();

        res.json({
          ok: true,
          agent_id: agentId,
          findings_processed: newCount + updatedCount,
          findings_new: newCount,
          findings_updated: updatedCount,
          findings_errored: errorCount
        });
      } catch (err) {
        await conn.rollback();
        console.error('POST /api/agents/checkin failed:', err);
        // Update agent status to error if we have an ID — best effort
        try {
          await pool.query(
            `UPDATE cert_agents SET last_checkin_status = 'error', last_error = ?
             WHERE fqdn = ?`,
            [err.message.slice(0, 1000), fqdn]
          );
        } catch (e) { /* swallow — already failing */ }
        res.status(500).json({ error: 'Check-in failed' });
      } finally {
        conn.release();
      }
    });

  // ===========================================================================
  // GET /api/agents
  // List all agents with summary status (last check-in, finding counts).
  // ===========================================================================
  router.get('/api/agents', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const config = await loadConfig();
      const warnDays = Number(config.agent_stale_warning_days) || 3;
      const critDays = Number(config.agent_stale_critical_days) || 7;

      const [rows] = await pool.query(
        `SELECT
           a.id, a.fqdn, a.hostname, a.os_family, a.os_version, a.agent_version,
           a.ip_address, a.enabled, a.notes, a.first_seen_at,
           a.last_checkin_at, a.last_checkin_status, a.last_error,
           a.prtg_push_enabled, a.prtg_last_push_status,
           -- CORPIT: boolean only; see cert-watchtower-routes.js
           (a.prtg_token IS NOT NULL AND a.prtg_token <> '') AS prtg_token_set,
           TIMESTAMPDIFF(SECOND, a.last_checkin_at, NOW()) AS seconds_since_checkin,
           (SELECT COUNT(*) FROM cert_findings f WHERE f.agent_id = a.id) AS finding_count,
           (SELECT COUNT(*) FROM cert_findings f
            WHERE f.agent_id = a.id
              AND f.status IN ('info','warning','critical','expired')) AS finding_alerting_count,
           (SELECT COUNT(*) FROM cert_issued ci
            WHERE ci.ca_agent_id = a.id AND ci.is_watched = 1 AND ci.is_revoked = 0) AS watched_issued_count
         FROM cert_agents a
         ORDER BY a.fqdn`
      );

      // Compute staleness band
      const now = Date.now();
      const enriched = rows.map(r => {
        let staleness = 'fresh';
        if (r.last_checkin_at) {
          const ageDays = r.seconds_since_checkin / 86400;
          if (ageDays >= critDays) staleness = 'stale_critical';
          else if (ageDays >= warnDays) staleness = 'stale_warning';
        } else {
          staleness = 'never';
        }
        return { ...r, staleness };
      });

      res.json({ agents: enriched, thresholds: { warning_days: warnDays, critical_days: critDays } });
    } catch (err) {
      console.error('GET /api/agents failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // POST /api/agents
  // Manually create a new scan target (UI-driven, no auth — internal tool).
  // Required: fqdn. Optional: target_host (defaults to fqdn), winrm_port,
  // winrm_transport, winrm_use_ssl, scan_stores, scan_iis, notes, enabled.
  // ===========================================================================
  router.post('/api/agents', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const {
        fqdn,
        target_host = null,
        winrm_port = 5985,
        winrm_transport = 'ntlm',
        winrm_use_ssl = 0,
        scan_stores = 'LocalMachine\\My',
        scan_iis = 1,
        notes = null,
        enabled = 1,
        os_family = 'windows',
        is_ca = 0,
        ca_name = null
      } = req.body || {};

      if (!validateFqdn(fqdn)) return res.status(400).json({ error: 'Invalid or missing fqdn' });
      if (target_host && !validateFqdn(target_host))
        return res.status(400).json({ error: 'Invalid target_host' });
      // The scanner connects to target_host, or fqdn when target_host is empty.
      if (!isAllowedWinrmHost(target_host || fqdn))
        return res.status(400).json({ error: 'Scan host must be a *.nrpi.local name or a 10.x address' });
      const portNum = Number(winrm_port);
      if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535)
        return res.status(400).json({ error: 'winrm_port must be 1-65535' });
      if (!isAllowedWinrmTransport(winrm_transport))
        return res.status(400).json({ error: 'winrm_transport invalid (ntlm, kerberos or credssp)' });
      if (scan_stores && !isValidScanStores(scan_stores))
        return res.status(400).json({ error: 'scan_stores invalid: comma-separated LocalMachine\\<Store> or CurrentUser\\<Store> (letters, digits, space, _ -)' });
      if (!['windows','linux','macos','other'].includes(os_family))
        return res.status(400).json({ error: 'os_family invalid' });
      if (ca_name && !validateCaName(ca_name))
        return res.status(400).json({ error: 'ca_name invalid: only letters, digits, space, . _ - allowed (max 255)' });

      const [result] = await pool.query(
        `INSERT INTO cert_agents
          (fqdn, target_host, winrm_port, winrm_transport, winrm_use_ssl,
           scan_stores, scan_iis, os_family, enabled, notes, is_ca, ca_name)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          fqdn.trim(),
          target_host ? target_host.trim() : null,
          portNum,
          winrm_transport,
          winrm_use_ssl ? 1 : 0,
          scan_stores,
          scan_iis ? 1 : 0,
          os_family,
          enabled ? 1 : 0,
          notes,
          is_ca ? 1 : 0,
          ca_name || null
        ]
      );
      res.status(201).json({ id: result.insertId });
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'A scan target with this FQDN already exists' });
      }
      console.error('POST /api/agents failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // GET /api/agents/:id
  // Single agent detail with finding summary.
  // ===========================================================================
  router.get('/api/agents/:id', rbac.requirePage('cert-watchtower','read'), async (req, res, next) => {
    try {
      if (!/^\d+$/.test(req.params.id)) return next();
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const [[agent]] = await pool.query('SELECT * FROM cert_agents WHERE id = ?', [id]);
      if (!agent) return res.status(404).json({ error: 'Agent not found' });

      // The list route (above) publishes a prtg_token_set boolean and never the
      // token itself. This detail route shipped the raw column to any read-tier
      // caller, which is a live PRTG push credential. Match the list contract.
      agent.prtg_token_set = !!(agent.prtg_token && agent.prtg_token !== '');
      delete agent.prtg_token;

      const [findings] = await pool.query(
        `SELECT id, store_name, store_location, thumbprint_sha1, subject_cn, issuer_cn,
                not_after, days_remaining, status, has_private_key, is_self_signed,
                last_seen_at
         FROM cert_findings
         WHERE agent_id = ?
         ORDER BY
           CASE status
             WHEN 'expired' THEN 0
             WHEN 'critical' THEN 1
             WHEN 'warning' THEN 2
             WHEN 'info' THEN 3
             WHEN 'ok' THEN 4
             ELSE 5
           END,
           days_remaining ASC`,
        [id]
      );

      res.json({ agent, findings });
    } catch (err) {
      console.error('GET /api/agents/:id failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // PUT /api/agents/:id
  // Edit agent (toggle enabled, update notes).
  // ===========================================================================
  router.put('/api/agents/:id', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res, next) => {
    try {
      if (!/^\d+$/.test(req.params.id)) return next();
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      // Phase 2 (WinRM) fields are editable; the original `enabled`+`notes`
      // remain. fqdn intentionally NOT editable — it's the unique identifier.
      const allowed = [
        'enabled', 'notes',
        'target_host', 'winrm_port', 'winrm_transport',
        'winrm_use_ssl', 'scan_stores', 'scan_iis',
        'is_ca', 'ca_name'
      ];
      const updates = [];
      const values = [];
      for (const field of allowed) {
        if (Object.prototype.hasOwnProperty.call(req.body || {}, field)) {
          const v = req.body[field];
          if (field === 'enabled' && (v !== 0 && v !== 1 && v !== true && v !== false)) {
            return res.status(400).json({ error: 'enabled must be 0/1' });
          }
          if (field === 'scan_iis' && (v !== 0 && v !== 1 && v !== true && v !== false)) {
            return res.status(400).json({ error: 'scan_iis must be 0/1' });
          }
          if (field === 'is_ca' && (v !== 0 && v !== 1 && v !== true && v !== false)) {
            return res.status(400).json({ error: 'is_ca must be 0/1' });
          }
          if (field === 'ca_name' && v && !validateCaName(v)) {
            return res.status(400).json({ error: 'ca_name invalid: only letters, digits, space, . _ - allowed (max 255)' });
          }
          if (field === 'winrm_use_ssl' && (v !== 0 && v !== 1 && v !== true && v !== false)) {
            return res.status(400).json({ error: 'winrm_use_ssl must be 0/1' });
          }
          if (field === 'winrm_port') {
            const n = Number(v);
            if (!Number.isInteger(n) || n < 1 || n > 65535) {
              return res.status(400).json({ error: 'winrm_port must be 1-65535' });
            }
          }
          if (field === 'winrm_transport' && !isAllowedWinrmTransport(v)) {
            return res.status(400).json({ error: 'winrm_transport invalid (ntlm, kerberos or credssp)' });
          }
          if (field === 'target_host' && v && !validateFqdn(v)) {
            return res.status(400).json({ error: 'Invalid target_host' });
          }
          if (field === 'target_host') {
            // Clearing target_host makes the scanner fall back to fqdn.
            let host = v;
            if (!host) {
              const [[row]] = await pool.query('SELECT fqdn FROM cert_agents WHERE id = ?', [id]);
              if (!row) return res.status(404).json({ error: 'Agent not found' });
              host = row.fqdn;
            }
            if (!isAllowedWinrmHost(host)) {
              return res.status(400).json({ error: 'Scan host must be a *.nrpi.local name or a 10.x address' });
            }
          }
          if (field === 'scan_stores' && v && String(v).length > 512) {
            return res.status(400).json({ error: 'scan_stores too long (max 512)' });
          }
          if (field === 'scan_stores' && v && !isValidScanStores(v)) {
            return res.status(400).json({ error: 'scan_stores invalid: comma-separated LocalMachine\\<Store> or CurrentUser\\<Store> (letters, digits, space, _ -)' });
          }
          updates.push(`${field} = ?`);
          if (field === 'enabled' || field === 'scan_iis' || field === 'winrm_use_ssl' || field === 'is_ca') {
            values.push(v ? 1 : 0);
          } else {
            values.push(v);
          }
        }
      }
      if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

      values.push(id);
      const [result] = await pool.query(
        `UPDATE cert_agents SET ${updates.join(', ')} WHERE id = ?`,
        values
      );
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Agent not found' });
      res.json({ ok: true });
    } catch (err) {
      console.error('PUT /api/agents/:id failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // DELETE /api/agents/:id
  // Removes agent + cascades all findings.
  // ===========================================================================
  router.delete('/api/agents/:id', rbac.requirePage('cert-watchtower','admin'), async (req, res, next) => {
    try {
      if (!/^\d+$/.test(req.params.id)) return next();
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const [result] = await pool.query('DELETE FROM cert_agents WHERE id = ?', [id]);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Agent not found' });
      res.json({ ok: true });
    } catch (err) {
      console.error('DELETE /api/agents/:id failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // POST /api/agents/:id/scan-now
  // Trigger an immediate WinRM scan against this target. Spawns the Python
  // helper (same one cert-watchtower-winrm-scan.js uses), waits for results,
  // upserts findings.
  //
  // This is rate-limited per-target (uses the manual_check_cooldown_s config
  // value to match the TLS handshake "Check Now" pattern).
  // ===========================================================================
  const lastScanNow = new Map(); // monitor_id -> timestamp

  router.post('/api/agents/:id/scan-now', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const config = await loadConfig();
      const cooldownMs = (Number(config.manual_check_cooldown_s) || 300) * 1000;
      const last = lastScanNow.get(id);
      if (last && Date.now() - last < cooldownMs) {
        const waitS = Math.ceil((cooldownMs - (Date.now() - last)) / 1000);
        return res.status(429).json({ error: `Cooldown active. Try again in ${waitS}s.` });
      }

      const [[target]] = await pool.query(
        `SELECT id, fqdn, target_host, winrm_port, winrm_transport,
                winrm_use_ssl, scan_stores, scan_iis
         FROM cert_agents WHERE id = ?`,
        [id]
      );
      if (!target) return res.status(404).json({ error: 'Agent not found' });
      // Never hand the WinRM credential to a target outside policy (rows saved
      // before hotfix-bundle3 are not re-validated on their own).
      const refusal = winrmTargetRefusal(target);
      if (refusal) return res.status(400).json({ error: `Scan target refused: ${refusal}` });

      lastScanNow.set(id, Date.now());

      // Load WinRM creds from api-beta's .env (same source the cron uses)
      const fs = require('fs');
      const envPath = '/var/www/corpit-hub-api/.env';
      if (!fs.existsSync(envPath)) {
        return res.status(503).json({ error: 'WinRM env file not available' });
      }
      const envText = fs.readFileSync(envPath, 'utf8');
      const env = {};
      for (const line of envText.split(/\r?\n/)) {
        const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/i);
        if (!m) continue;
        let v = m[2];
        if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
          v = v.slice(1, -1);
        }
        env[m[1]] = v;
      }
      if (!env.WINRM_USER || !env.WINRM_PASS) {
        return res.status(503).json({ error: 'WINRM_USER/PASS not configured' });
      }

      // Spawn helper
      const { spawn } = require('child_process');
      const timeoutS = Math.max(10, Number(config.winrm_scan_timeout_s) || 60);
      const args = [
        '/var/www/api/cert-watchtower-winrm-helper.py',
        '--host', target.target_host || target.fqdn,
        '--port', String(target.winrm_port || 5985),
        '--transport', target.winrm_transport || 'ntlm',
        '--stores', target.scan_stores || 'LocalMachine\\My',
        '--timeout', String(timeoutS)
      ];
      if (target.winrm_use_ssl) args.push('--ssl');
      if (target.scan_iis) args.push('--scan-iis');

      const child = spawn('/usr/bin/python3', args, {
        env: { ...process.env, WINRM_USER: env.WINRM_USER, WINRM_PASS: env.WINRM_PASS },
        stdio: ['ignore', 'pipe', 'pipe']
      });
      let stdout = '', stderr = '';
      child.stdout.on('data', d => { stdout += d.toString(); });
      child.stderr.on('data', d => { stderr += d.toString(); });

      const killTimer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (_) {}
      }, (timeoutS + 30) * 1000);

      const exitCode = await new Promise(resolve => {
        child.on('close', code => { clearTimeout(killTimer); resolve(code); });
        child.on('error', () => { clearTimeout(killTimer); resolve(-1); });
      });

      let result;
      try {
        result = JSON.parse(stdout.trim() || '{}');
      } catch (e) {
        return res.status(502).json({
          error: 'Helper output not JSON',
          exit_code: exitCode,
          stderr: stderr.slice(0, 500)
        });
      }

      if (!result.ok) {
        await pool.query(
          `UPDATE cert_agents SET last_checkin_at = NOW(), last_checkin_status = 'error',
                                  last_error = ? WHERE id = ?`,
          [(result.error || 'unknown error').slice(0, 1000), id]
        );
        return res.status(502).json({ error: result.error || 'scan failed', detail: result });
      }

      // Successful scan — upsert findings using same logic as the cron.
      const thresholds = {
        info: Number(config.threshold_info_days) || 90,
        warning: Number(config.threshold_warning_days) || 60,
        critical: Number(config.threshold_critical_days) || 30
      };
      const toMysqlDateTime = (iso) => {
        if (!iso) return null;
        const d = new Date(iso);
        if (isNaN(d.getTime())) return null;
        const pad = n => String(n).padStart(2, '0');
        return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ` +
               `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
      };

      const conn = await pool.getConnection();
      let processed = 0;
      try {
        await conn.beginTransaction();
        await conn.query(
          `UPDATE cert_agents SET
             hostname = COALESCE(?, hostname),
             os_version = COALESCE(?, os_version),
             last_checkin_at = NOW(),
             last_checkin_status = 'ok',
             last_error = NULL
           WHERE id = ?`,
          [result.hostname || null, result.os_version || null, id]
        );
        for (const f of (result.findings || [])) {
          if (!f.thumbprint_sha1 || !f.store_name) continue;
          let daysRemaining = null;
          let status = 'error';
          if (f.not_after) {
            const ms = new Date(f.not_after) - new Date();
            daysRemaining = Math.floor(ms / (1000 * 60 * 60 * 24));
            if (daysRemaining < 0) status = 'expired';
            else if (daysRemaining <= thresholds.critical) status = 'critical';
            else if (daysRemaining <= thresholds.warning) status = 'warning';
            else if (daysRemaining <= thresholds.info) status = 'info';
            else status = 'ok';
          }
          await conn.query(
            `INSERT INTO cert_findings
              (agent_id, store_name, store_location, thumbprint_sha1,
               fingerprint_sha256, serial_number,
               subject, subject_cn, issuer, issuer_cn, san_list,
               not_before, not_after, days_remaining,
               has_private_key, is_self_signed,
               key_algorithm, key_size, signature_algorithm,
               status, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
               fingerprint_sha256=VALUES(fingerprint_sha256),
               serial_number=VALUES(serial_number),
               subject=VALUES(subject), subject_cn=VALUES(subject_cn),
               issuer=VALUES(issuer), issuer_cn=VALUES(issuer_cn),
               san_list=VALUES(san_list),
               not_before=VALUES(not_before), not_after=VALUES(not_after),
               days_remaining=VALUES(days_remaining),
               has_private_key=VALUES(has_private_key),
               is_self_signed=VALUES(is_self_signed),
               key_algorithm=VALUES(key_algorithm),
               key_size=VALUES(key_size),
               signature_algorithm=VALUES(signature_algorithm),
               status=VALUES(status), last_seen_at=NOW()`,
            [
              id,
              String(f.store_name).slice(0, 128),
              String(f.store_location || '').slice(0, 255),
              String(f.thumbprint_sha1).toUpperCase().replace(/[^A-F0-9]/g, '').slice(0, 64),
              f.fingerprint_sha256 || null,
              f.serial_number || null,
              f.subject || null, f.subject_cn || null,
              f.issuer || null, f.issuer_cn || null,
              f.san_list ? JSON.stringify(f.san_list) : null,
              toMysqlDateTime(f.not_before),
              toMysqlDateTime(f.not_after),
              daysRemaining,
              f.has_private_key === undefined ? null : (f.has_private_key ? 1 : 0),
              f.is_self_signed === undefined ? null : (f.is_self_signed ? 1 : 0),
              f.key_algorithm || null, f.key_size || null,
              f.signature_algorithm || null,
              status
            ]
          );
          processed++;
        }
        await conn.commit();
      } catch (err) {
        await conn.rollback();
        return res.status(500).json({ error: 'finding upsert failed: ' + err.message });
      } finally {
        conn.release();
      }

      res.json({
        ok: true,
        agent_id: id,
        findings_processed: processed,
        store_count: result.store_count,
        iis_count: result.iis_count
      });
    } catch (err) {
      console.error('POST /api/agents/:id/scan-now failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // POST /api/agents/token/rotate
  // Generate a new enrollment token. Existing agents keep working — only
  // *new* agent registrations need the new token.
  // ===========================================================================
  router.post('/api/agents/token/rotate', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const newToken = crypto.randomBytes(32).toString('hex');
      await pool.query(
        `UPDATE cert_config SET config_value = ? WHERE config_key = 'agent_enrollment_token'`,
        [newToken]
      );
      res.json({ ok: true, token: newToken });
    } catch (err) {
      console.error('POST /api/agents/token/rotate failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // GET /api/agents/token
  // Read the current enrollment token. Internal portal — same trust model
  // as the rest of the dashboard.
  // ===========================================================================
  router.get('/api/agents/token', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const config = await loadConfig();
      res.json({ token: config.agent_enrollment_token || '' });
    } catch (err) {
      console.error('GET /api/agents/token failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // GET /api/findings
  // Unified finding list. Filters: ?agent_id, ?status, ?store, ?missing=1
  // (missing=1 returns findings whose last_seen_at is older than the grace
  // period — i.e. cert is gone from the store).
  // ===========================================================================
  router.get('/api/findings', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const where = [];
      const params = [];
      if (req.query.agent_id) {
        where.push('f.agent_id = ?');
        params.push(Number(req.query.agent_id));
      }
      if (req.query.status) {
        where.push('f.status = ?');
        params.push(String(req.query.status));
      }
      if (req.query.store) {
        where.push('f.store_name = ?');
        params.push(String(req.query.store));
      }
      if (req.query.missing === '1') {
        const config = await loadConfig();
        const graceDays = Number(config.agent_checkin_grace_days) || 2;
        where.push('f.last_seen_at < DATE_SUB(NOW(), INTERVAL ? DAY)');
        params.push(graceDays);
      }
      const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

      const [rows] = await pool.query(
        `SELECT f.id, f.agent_id, a.fqdn, a.hostname,
                f.store_name, f.store_location,
                f.thumbprint_sha1, f.subject_cn, f.issuer_cn,
                f.not_before, f.not_after, f.days_remaining, f.status,
                f.has_private_key, f.is_self_signed, f.is_watched,
                f.prtg_push_enabled, f.prtg_last_push_status,
                -- CORPIT: boolean only; see cert-watchtower-routes.js
                (f.prtg_token IS NOT NULL AND f.prtg_token <> '') AS prtg_token_set,
                f.first_seen_at, f.last_seen_at
         FROM cert_findings f
         JOIN cert_agents a ON a.id = f.agent_id
         ${whereSql}
         ORDER BY
           CASE f.status
             WHEN 'expired' THEN 0
             WHEN 'critical' THEN 1
             WHEN 'warning' THEN 2
             WHEN 'info' THEN 3
             WHEN 'ok' THEN 4
             ELSE 5
           END,
           f.days_remaining ASC,
           a.fqdn ASC`,
        params
      );
      res.json({ findings: rows });
    } catch (err) {
      console.error('GET /api/findings failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // GET /api/findings/:id
  // Single finding with full detail (subject, issuer, SANs, etc.)
  // ===========================================================================
  router.get('/api/findings/:id', rbac.requirePage('cert-watchtower','read'), async (req, res, next) => {
    try {
      if (!/^\d+$/.test(req.params.id)) return next();
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const [[row]] = await pool.query(
        `SELECT f.*, a.fqdn, a.hostname, a.os_family
         FROM cert_findings f
         JOIN cert_agents a ON a.id = f.agent_id
         WHERE f.id = ?`,
        [id]
      );
      if (!row) return res.status(404).json({ error: 'Finding not found' });

      // The list route (above) publishes a prtg_token_set boolean and never the
      // token itself. This detail route shipped the raw column to any read-tier
      // caller, which is a live PRTG push credential. Match the list contract.
      row.prtg_token_set = !!(row.prtg_token && row.prtg_token !== '');
      delete row.prtg_token;

      res.json({ finding: row });
    } catch (err) {
      console.error('GET /api/findings/:id failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // GET /api/findings/summary
  // Counts per status — for dashboard tile / portal badge.
  // ===========================================================================
  router.get('/api/findings/summary', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const [rows] = await pool.query(
        `SELECT status, COUNT(*) AS count
         FROM cert_findings
         GROUP BY status`
      );
      const summary = { ok: 0, info: 0, warning: 0, critical: 0, expired: 0, error: 0 };
      for (const r of rows) summary[r.status] = r.count;
      const totalAlerting = summary.info + summary.warning + summary.critical + summary.expired;
      res.json({ summary, total_alerting: totalAlerting });
    } catch (err) {
      console.error('GET /api/findings/summary failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // POST /api/agents/:id/rescan
  // On-demand CA issued cert scan via certutil over WinRM.
  // Queries the CA's issued certificate store on the target, stores results
  // in cert_issued. Does NOT push to PRTG — inventory refresh only.
  // Rate-limited by the same manual_check_cooldown_s as scan-now.
  // ===========================================================================
  const lastRescan = new Map();

  router.post('/api/agents/:id/rescan', rbac.requirePage('cert-watchtower', 'admin'), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const config = await loadConfig();
      const cooldownMs = (Number(config.manual_check_cooldown_s) || 300) * 1000;
      const last = lastRescan.get(id);
      if (last && Date.now() - last < cooldownMs) {
        const waitS = Math.ceil((cooldownMs - (Date.now() - last)) / 1000);
        return res.status(429).json({ error: `Cooldown active. Try again in ${waitS}s.` });
      }

      const [[target]] = await pool.query(
        `SELECT id, fqdn, target_host, winrm_port, winrm_transport, winrm_use_ssl, is_ca, ca_name
         FROM cert_agents WHERE id = ?`,
        [id]
      );
      if (!target) return res.status(404).json({ error: 'Agent not found' });
      if (!target.is_ca || !target.ca_name) {
        return res.status(400).json({ error: 'This target is not configured as a CA server. Set is_ca=1 and ca_name in the target settings.' });
      }
      const refusal = winrmTargetRefusal(target);
      if (refusal) return res.status(400).json({ error: `Scan target refused: ${refusal}` });

      // Load WinRM creds from api-beta's .env
      const fsSync = require('fs');
      const envPath = '/var/www/corpit-hub-api/.env';
      if (!fsSync.existsSync(envPath)) {
        return res.status(503).json({ error: 'WinRM env file not available' });
      }
      const envText = fsSync.readFileSync(envPath, 'utf8');
      const winrmEnv = {};
      for (const line of envText.split(/\r?\n/)) {
        const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/i);
        if (!m) continue;
        let v = m[2];
        if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
          v = v.slice(1, -1);
        }
        winrmEnv[m[1]] = v;
      }
      if (!winrmEnv.WINRM_USER || !winrmEnv.WINRM_PASS) {
        return res.status(503).json({ error: 'WINRM_USER/PASS not configured' });
      }

      lastRescan.set(id, Date.now());

      const { spawn } = require('child_process');
      const timeoutS = Math.max(30, Number(config.winrm_scan_timeout_s) || 120);

      const args = [
        '/var/www/api/cert-watchtower-ca-scan-helper.py',
        '--host',     target.target_host || target.fqdn,
        '--ca-name',  target.ca_name,
        '--port',     String(target.winrm_port || 5985),
        '--transport', target.winrm_transport || 'ntlm',
        '--timeout',  String(timeoutS)
      ];
      if (target.winrm_use_ssl) args.push('--ssl');

      const child = spawn('/usr/bin/python3', args, {
        env: { ...process.env, WINRM_USER: winrmEnv.WINRM_USER, WINRM_PASS: winrmEnv.WINRM_PASS },
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '', stderr = '';
      child.stdout.on('data', d => { stdout += d.toString(); });
      child.stderr.on('data', d => { stderr += d.toString(); });

      const killTimer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (_) {}
      }, (timeoutS + 30) * 1000);

      const exitCode = await new Promise(resolve => {
        child.on('close', code => { clearTimeout(killTimer); resolve(code); });
        child.on('error', () => { clearTimeout(killTimer); resolve(-1); });
      });

      let result;
      try {
        result = JSON.parse(stdout.trim() || '{}');
      } catch (e) {
        return res.status(502).json({
          error: 'CA scan helper output not JSON',
          exit_code: exitCode,
          stderr: stderr.slice(0, 500)
        });
      }

      if (!result.ok) {
        return res.status(502).json({ error: result.error || 'CA scan failed', detail: result });
      }

      // Upsert issued certs into cert_issued
      const thresholds = {
        info:     Number(config.threshold_info_days)     || 90,
        warning:  Number(config.threshold_warning_days)  || 60,
        critical: Number(config.threshold_critical_days) || 30
      };

      const toMysqlDT = (iso) => {
        if (!iso) return null;
        const d = new Date(iso);
        if (isNaN(d.getTime())) return null;
        const pad = n => String(n).padStart(2, '0');
        return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ` +
               `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
      };

      let upserted = 0;
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        for (const cert of (result.certs || [])) {
          if (!cert.serial_number) continue;

          let daysRemaining = null;
          let certStatus = 'error';
          if (cert.not_after) {
            const ms = new Date(cert.not_after) - new Date();
            daysRemaining = Math.floor(ms / 86400000);
            certStatus = classifyStatus(daysRemaining, thresholds);
          }

          await conn.query(
            `INSERT INTO cert_issued
              (ca_agent_id, request_id, serial_number, requester_name, cert_template,
               subject_cn, not_before, not_after, days_remaining, cert_status, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
               requester_name  = VALUES(requester_name),
               cert_template   = VALUES(cert_template),
               subject_cn      = VALUES(subject_cn),
               not_before      = VALUES(not_before),
               not_after       = VALUES(not_after),
               days_remaining  = VALUES(days_remaining),
               cert_status     = VALUES(cert_status),
               last_seen_at    = NOW()`,
            [
              id,
              cert.request_id   || null,
              cert.serial_number,
              cert.requester_name || null,
              cert.cert_template  || null,
              cert.subject_cn     || null,
              toMysqlDT(cert.not_before),
              toMysqlDT(cert.not_after),
              daysRemaining,
              certStatus
            ]
          );
          upserted++;
        }
        await conn.commit();
      } catch (err) {
        await conn.rollback();
        return res.status(500).json({ error: 'cert_issued upsert failed: ' + err.message });
      } finally {
        conn.release();
      }

      // Return the updated cert_issued list for this agent
      const [issued] = await pool.query(
        `SELECT id, request_id, serial_number, requester_name, cert_template,
                subject_cn, not_before, not_after, days_remaining, cert_status,
                is_watched, is_revoked, first_seen_at, last_seen_at
         FROM cert_issued
         WHERE ca_agent_id = ? AND is_revoked = 0
         ORDER BY not_after ASC`,
        [id]
      );

      res.json({ ok: true, upserted, certs: issued });
    } catch (err) {
      console.error('POST /api/agents/:id/rescan failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // GET /api/agents/:id/issued
  // Returns the cert_issued list for a CA scan target.
  // Used to populate the cert selection panel in the modal on page load.
  // ===========================================================================
  router.get('/api/agents/:id/issued', rbac.requirePage('cert-watchtower', 'read'), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const [issued] = await pool.query(
        `SELECT id, request_id, serial_number, requester_name, cert_template,
                subject_cn, not_before, not_after, days_remaining, cert_status,
                is_watched, first_seen_at, last_seen_at
         FROM cert_issued
         WHERE ca_agent_id = ? AND is_revoked = 0
         ORDER BY not_after ASC`,
        [id]
      );

      res.json({ certs: issued });
    } catch (err) {
      console.error('GET /api/agents/:id/issued failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // PATCH /api/agents/:id/issued/watch
  // Sets is_watched=1 for the provided serial numbers, is_watched=0 for all
  // others on this agent. Atomic — one transaction.
  //
  // Body: { "serials": ["3200000067c...", "32000000155a..."] }
  // Response: { ok: true, watched: N, unwatched: N }
  // ===========================================================================
  router.patch('/api/agents/:id/issued/watch', rbac.requirePage('cert-watchtower', 'admin'), express.json(), async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

      const { serials } = req.body || {};
      if (!Array.isArray(serials)) {
        return res.status(400).json({ error: 'serials must be an array' });
      }

      // Validate each serial — hex characters only, max 128 chars
      const clean = serials
        .map(s => String(s).trim().toUpperCase())
        .filter(s => s.length > 0 && s.length <= 128 && /^[A-F0-9]+$/.test(s));

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();

        // Unwatch everything on this agent first
        await conn.query(
          `UPDATE cert_issued SET is_watched = 0 WHERE ca_agent_id = ?`,
          [id]
        );

        // Watch the selected serials
        let watched = 0;
        if (clean.length > 0) {
          const placeholders = clean.map(() => '?').join(',');
          const [result] = await conn.query(
            `UPDATE cert_issued SET is_watched = 1
             WHERE ca_agent_id = ? AND serial_number IN (${placeholders})`,
            [id, ...clean]
          );
          watched = result.affectedRows;
        }

        await conn.commit();

        // Return updated counts
        const [[counts]] = await conn.query(
          `SELECT
             SUM(is_watched) AS watched,
             SUM(1 - is_watched) AS unwatched
           FROM cert_issued WHERE ca_agent_id = ? AND is_revoked = 0`,
          [id]
        );

        res.json({ ok: true, watched: Number(counts.watched) || 0, unwatched: Number(counts.unwatched) || 0 });
      } catch (err) {
        await conn.rollback();
        return res.status(500).json({ error: 'watch update failed: ' + err.message });
      } finally {
        conn.release();
      }
    } catch (err) {
      console.error('PATCH /api/agents/:id/issued/watch failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
};
