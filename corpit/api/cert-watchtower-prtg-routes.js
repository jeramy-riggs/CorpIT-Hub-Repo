// =============================================================================
// Cert Watchtower — Phase 2.5: PRTG Integration Routes
// File: /var/www/api/cert-watchtower-prtg-routes.js
//
// Mounts as a router under /api/prtg/* in the main app.
// Fully additive — does not touch any existing routes or behaviour.
//
// Endpoints:
//   GET    /api/prtg/config         — read all prtg_* rows from cert_config
//   PUT    /api/prtg/config         — update one or more PRTG config keys
//   POST   /api/prtg/test-push      — passthrough test-push (validates a token before saving)
//   GET    /api/prtg/status         — summary: enabled? counts? last activity?
//
// Dependencies: express, mysql2/promise, cert-watchtower-prtg-helper
//   (no new npm installs required)
// =============================================================================

const express = require('express');

// === CORPIT-SECRET-CONFIG (2026-09-06) =======================================
// Config rows that hold a live credential never reach a browser; callers get
// "<key>_set" instead. hotfix-bundle3 2026-10-21 (F6/F32): the key list now
// lives in cert-watchtower-guards.js so this file and the cert-config router
// redact the same set (it was ['prtg_summary_sensor_token'] here only).
const { CORPIT_SECRET_CONFIG_KEYS, corpitRedactConfig } = require('./cert-watchtower-guards');
// === end CORPIT-SECRET-CONFIG ================================================

const { pushToPrtg } = require('./cert-watchtower-prtg-helper');
// settingsfold W6 2026-10-12: PUT /api/prtg/config writes an rbac_audit_log row.
// prtg_summary_sensor_token is recorded only as (set)/(changed)/(cleared).
const SA = require('./settings-audit');

// -----------------------------------------------------------------------------
// Allow-list of PRTG config keys this router is permitted to read/write.
// Keeping this central so changes happen in one place. Anything not on this
// list is silently ignored on PUT and excluded from GET.
//
// Note on legacy keys (prtg_auth_token, prtg_push_url): these are Phase 2
// stubs that became deprecated when we moved to per-cert tokens. They are
// intentionally NOT in this allow-list — exposing them via this API would
// imply they're still meaningful. They remain in the cert_config table as
// harmless rows; we just don't surface them.
// -----------------------------------------------------------------------------
const ALLOWED_KEYS = new Set([
  'prtg_enabled',
  'prtg_core_host',
  'prtg_push_port',
  'prtg_push_protocol',
  'prtg_verify_tls',
  'prtg_timeout_ms',
  'prtg_summary_sensor_token',
  'prtg_heartbeat_enabled',
  'prtg_push_on_transition',
  'prtg_retry_count'
]);

// -----------------------------------------------------------------------------
// Per-key validation. Run on PUT before any DB write. Reject obviously bad
// values rather than letting them be persisted as strings PRTG can't use.
// -----------------------------------------------------------------------------
function validateKeyValue(key, value) {
  // All values arrive as strings via JSON; coerce as appropriate per key.
  const v = value === null || value === undefined ? '' : String(value);

  switch (key) {
    case 'prtg_enabled':
    case 'prtg_verify_tls':
    case 'prtg_heartbeat_enabled':
    case 'prtg_push_on_transition':
      if (v !== '0' && v !== '1') return `Must be "0" or "1"`;
      return null;

    case 'prtg_core_host':
      if (v === '') return null; // empty = unset, allowed
      if (v.length > 253) return 'Host too long (max 253 chars)';
      // Allow letters, digits, dots, hyphens. No whitespace, no schemes.
      if (!/^[a-zA-Z0-9][a-zA-Z0-9\.\-]*$/.test(v)) return 'Invalid hostname format';
      return null;

    case 'prtg_push_port': {
      const n = parseInt(v, 10);
      if (!Number.isInteger(n) || n < 1 || n > 65535) return 'Port must be 1–65535';
      return null;
    }

    case 'prtg_push_protocol':
      if (v !== 'http' && v !== 'https') return `Must be "http" or "https"`;
      return null;

    case 'prtg_timeout_ms': {
      const n = parseInt(v, 10);
      if (!Number.isInteger(n) || n < 100 || n > 60000) return 'Timeout must be 100–60000 ms';
      return null;
    }

    case 'prtg_summary_sensor_token':
      if (v === '') return null; // empty = disabled, allowed
      if (v.length > 128) return 'Token too long (max 128 chars)';
      if (/[\s\/?#]/.test(v)) return 'Token contains invalid characters';
      return null;

    case 'prtg_retry_count': {
      const n = parseInt(v, 10);
      if (!Number.isInteger(n) || n < 0 || n > 10) return 'Retry count must be 0–10';
      return null;
    }

    default:
      return 'Unknown key';
  }
}

// -----------------------------------------------------------------------------
// Factory: takes the existing mysql2 pool, returns a router.
// -----------------------------------------------------------------------------
module.exports = function createCertWatchtowerPrtgRouter(pool, rbac) {
  const router = express.Router();
  router.use(rbac.loadCurrentUser);

  // ---------------------------------------------------------------------------
  // Helper: load all prtg_* config keys as an object. Includes only the keys
  // on the allow-list — deprecated stubs are not exposed.
  // ---------------------------------------------------------------------------
  async function loadPrtgConfig() {
    const [rows] = await pool.query(
      "SELECT config_key, config_value FROM cert_config WHERE config_key LIKE 'prtg_%'"
    );
    const out = {};
    for (const r of rows) {
      if (ALLOWED_KEYS.has(r.config_key)) {
        out[r.config_key] = r.config_value;
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // GET /api/prtg/config
  // Returns the current PRTG configuration (allow-listed keys only).
  // ---------------------------------------------------------------------------
  router.get('/api/prtg/config', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const config = await loadPrtgConfig();
      res.json({ config: corpitRedactConfig(config) });
    } catch (err) {
      console.error('GET /api/prtg/config failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---------------------------------------------------------------------------
  // PUT /api/prtg/config
  // Update one or more PRTG config keys. Body: { key: value, ... }.
  // Only allow-listed keys are accepted; unknown keys silently ignored.
  // Per-key validation runs before any DB write.
  // ---------------------------------------------------------------------------
  router.put('/api/prtg/config', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const body = req.body || {};
      const accepted = [];
      const rejected = [];

      for (const [k, v] of Object.entries(body)) {
        if (!ALLOWED_KEYS.has(k)) {
          // Silently skip unknown keys (matches existing PUT /api/cert-config)
          continue;
        }
        const err = validateKeyValue(k, v);
        if (err) {
          rejected.push({ key: k, reason: err });
        } else {
          accepted.push([k, String(v === null || v === undefined ? '' : v)]);
        }
      }

      if (rejected.length > 0) {
        return res.status(400).json({
          error: 'Validation failed',
          rejected
        });
      }
      if (accepted.length === 0) {
        return res.status(400).json({ error: 'No valid PRTG config keys provided' });
      }

      const saBefore = await SA.byKey(pool, "SELECT config_key, config_value FROM cert_config WHERE config_key LIKE 'prtg_%'", [], 'config_key', 'config_value');
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        for (const [k, v] of accepted) {
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

      const saAfter = await SA.byKey(pool, "SELECT config_key, config_value FROM cert_config WHERE config_key LIKE 'prtg_%'", [], 'config_key', 'config_value');
      await SA.record(rbac, req, 'cert-watchtower', 'settings_saved', SA.entry({ what: 'prtg_config', op: 'update',
        before: saBefore, after: saAfter, keys: accepted.map(u => u[0]), secretKeys: CORPIT_SECRET_CONFIG_KEYS }));
      res.json({ ok: true, updated: accepted.map(u => u[0]) });
    } catch (err) {
      console.error('PUT /api/prtg/config failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---------------------------------------------------------------------------
  // POST /api/prtg/test-push
  //
  // PURE PASSTHROUGH — does NOT read or write any DB rows.
  // Caller supplies all push parameters explicitly. Lets the UI verify a
  // freshly-created PRTG sensor token works before saving it on a monitor.
  //
  // Body:
  //   {
  //     host:        string,            // required
  //     port:        integer 1-65535,   // required
  //     protocol:    "http" | "https",  // optional, default "http"
  //     token:       string,            // required (PRTG identtoken)
  //     value:       number,            // optional, default 1
  //     channelName: string,            // optional, default "Test Value"
  //     statusText:  string,            // optional
  //     verifyTls:   boolean,           // optional, default false
  //     timeoutMs:   integer            // optional, default 5000
  //   }
  //
  // Returns the helper's full structured result (status + matchingSensors etc).
  // ---------------------------------------------------------------------------
  router.post('/api/prtg/test-push', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      if (await prtgPushBlocked(res)) return;
      const b = req.body || {};
      const port = parseInt(b.port, 10);
      const value = (b.value === undefined || b.value === null || b.value === '')
        ? 1
        : Number(b.value);

      if (!Number.isFinite(value)) {
        return res.status(400).json({ error: 'value must be a finite number' });
      }

      const result = await pushToPrtg({
        host: typeof b.host === 'string' ? b.host : '',
        port: Number.isInteger(port) ? port : -1,
        protocol: b.protocol === 'https' ? 'https' : 'http',
        token: typeof b.token === 'string' ? b.token : '',
        channels: [{ name: typeof b.channelName === 'string' && b.channelName.trim()
                       ? b.channelName : 'Test Value',
                     value }],
        statusText: typeof b.statusText === 'string' ? b.statusText : undefined,
        verifyTls: b.verifyTls === true,
        timeoutMs: Number.isInteger(parseInt(b.timeoutMs, 10))
                   ? parseInt(b.timeoutMs, 10) : 5000
      });

      // The helper's own validation errors come back as result.error starting
      // with "validation:". Map those to 400; everything else is 200 with the
      // structured result so the UI can show "ok: false, error: ..." details.
      if (result.error && result.error.startsWith('validation:')) {
        return res.status(400).json({ error: result.error, result });
      }

      res.json({ ok: result.ok, result });
    } catch (err) {
      console.error('POST /api/prtg/test-push failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---------------------------------------------------------------------------
  // GET /api/prtg/status
  //
  // Summary for the Settings UI: is PRTG push globally enabled?  How many
  // monitors and findings are configured to push?  When was the last
  // successful push?  Useful to display "PRTG Integration: 12 sensors active,
  // last push 6 minutes ago" without the UI having to query 4 endpoints.
  // ---------------------------------------------------------------------------
  router.get('/api/prtg/status', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const config = await loadPrtgConfig();

      const [[mCounts]] = await pool.query(
        `SELECT
           COUNT(*)                                         AS total_monitors,
           SUM(CASE WHEN prtg_token IS NOT NULL AND prtg_token <> ''
                    THEN 1 ELSE 0 END)                      AS with_token_monitors,
           SUM(CASE WHEN prtg_push_enabled=1 THEN 1 ELSE 0 END) AS push_enabled_monitors,
           SUM(CASE WHEN prtg_push_enabled=1 AND prtg_token IS NOT NULL AND prtg_token <> ''
                    THEN 1 ELSE 0 END)                      AS push_configured_monitors,
           MAX(prtg_last_push_at)                           AS last_monitor_push_at
         FROM cert_monitors`
      );

      const [[fCounts]] = await pool.query(
        `SELECT
           COUNT(*)                                         AS total_findings,
           SUM(CASE WHEN prtg_token IS NOT NULL AND prtg_token <> ''
                    THEN 1 ELSE 0 END)                      AS with_token_findings,
           SUM(CASE WHEN prtg_push_enabled=1 THEN 1 ELSE 0 END) AS push_enabled_findings,
           SUM(CASE WHEN prtg_push_enabled=1 AND prtg_token IS NOT NULL AND prtg_token <> ''
                    THEN 1 ELSE 0 END)                      AS push_configured_findings,
           MAX(prtg_last_push_at)                           AS last_finding_push_at
         FROM cert_findings`
      );

      // Step 8.5: agents (scan targets) — server-level rollup pushes.
      // Only counts ENABLED agents (matches the cron's WHERE filter).
      const [[aCounts]] = await pool.query(
        `SELECT
           SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END)       AS total_agents,
           SUM(CASE WHEN enabled=1 AND prtg_token IS NOT NULL AND prtg_token <> ''
                    THEN 1 ELSE 0 END)                      AS with_token_agents,
           SUM(CASE WHEN enabled=1 AND prtg_push_enabled=1 THEN 1 ELSE 0 END) AS push_enabled_agents,
           SUM(CASE WHEN enabled=1 AND prtg_push_enabled=1 AND prtg_token IS NOT NULL AND prtg_token <> ''
                    THEN 1 ELSE 0 END)                      AS push_configured_agents,
           MAX(prtg_last_push_at)                           AS last_agent_push_at
         FROM cert_agents`
      );

      res.json({
        enabled: config.prtg_enabled === '1',
        config_present: !!(config.prtg_core_host && config.prtg_push_port && config.prtg_push_protocol),
        summary_sensor_configured: !!(config.prtg_summary_sensor_token && config.prtg_summary_sensor_token.length),
        monitors: {
          total: Number(mCounts.total_monitors) || 0,
          with_token: Number(mCounts.with_token_monitors) || 0,
          push_enabled: Number(mCounts.push_enabled_monitors) || 0,
          push_configured: Number(mCounts.push_configured_monitors) || 0,
          last_push_at: mCounts.last_monitor_push_at
        },
        findings: {
          total: Number(fCounts.total_findings) || 0,
          with_token: Number(fCounts.with_token_findings) || 0,
          push_enabled: Number(fCounts.push_enabled_findings) || 0,
          push_configured: Number(fCounts.push_configured_findings) || 0,
          last_push_at: fCounts.last_finding_push_at
        },
        agents: {
          total: Number(aCounts.total_agents) || 0,
          with_token: Number(aCounts.with_token_agents) || 0,
          push_enabled: Number(aCounts.push_enabled_agents) || 0,
          push_configured: Number(aCounts.push_configured_agents) || 0,
          last_push_at: aCounts.last_agent_push_at
        }
      });
    } catch (err) {
      console.error('GET /api/prtg/status failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // PER-CERT ENDPOINTS (Step 8 — UX for token entry + test push from detail modals)
  // ===========================================================================

  /**
   * Internal helper: build channels for a monitor row using the same logic
   * as cert-watchtower-cron.js. Kept here (not factored into the helper module)
   * because it mixes DB-row shape with channel layout, which is a route-level
   * concern. If the cron's logic changes, this needs to track it.
   *
   * STATUS_TO_INT mapping must match cert-watchtower-cron.js exactly.
   */
  const STATUS_TO_INT = {
    ok: 0, info: 1, warning: 2, critical: 3,
    expired: 4, unreachable: 5, error: 6
  };
  function statusToInt(s) {
    return Object.prototype.hasOwnProperty.call(STATUS_TO_INT, s) ? STATUS_TO_INT[s] : 6;
  }
  function buildMonitorChannels(row) {
    const days = Number.isFinite(Number(row.days_remaining))
      ? Number(row.days_remaining) : 0;
    const handshakeMs = Number.isFinite(Number(row.handshake_ms))
      ? Number(row.handshake_ms) : 0;
    let daysSinceIssue = 0;
    if (row.not_before) {
      const issued = new Date(row.not_before).getTime();
      if (!Number.isNaN(issued)) {
        daysSinceIssue = Math.max(0, Math.floor((Date.now() - issued) / 86400000));
      }
    }
    return [
      { name: 'Days Until Expiry', value: days },
      { name: 'Cert Status',       value: statusToInt(row.status) },
      { name: 'Handshake Time',    value: handshakeMs, unit: 'TimeResponse' },
      { name: 'Days Since Issue',  value: daysSinceIssue }
    ];
  }
  function buildFindingChannels(row) {
    const days = Number.isFinite(Number(row.days_remaining))
      ? Number(row.days_remaining) : 0;
    let daysSinceLastSeen = 0;
    if (row.last_seen_at) {
      const lastSeen = new Date(row.last_seen_at).getTime();
      if (!Number.isNaN(lastSeen)) {
        daysSinceLastSeen = Math.max(0, Math.floor((Date.now() - lastSeen) / 86400000));
      }
    }
    let daysSinceIssue = 0;
    if (row.not_before) {
      const issued = new Date(row.not_before).getTime();
      if (!Number.isNaN(issued)) {
        daysSinceIssue = Math.max(0, Math.floor((Date.now() - issued) / 86400000));
      }
    }
    return [
      { name: 'Days Until Expiry',    value: days },
      { name: 'Cert Status',          value: statusToInt(row.status) },
      { name: 'Days Since Last Seen', value: daysSinceLastSeen },
      { name: 'Days Since Issue',     value: daysSinceIssue }
    ];
  }

  /**
   * Step 8.5: Build channels for an agent (scan target) rollup push.
   * Five channels reflecting whole-server cert posture:
   *   1. Total Certs            — count of findings on this agent
   *   2. Min Days Remaining     — soonest-expiring cert (the one to worry about first)
   *   3. Worst Status           — highest numeric status across findings (ok=0..error=6)
   *   4. Days Since Check-in    — agent freshness signal (server health)
   *   5. Findings Alerting      — count of findings in non-ok states
   *
   * Empty store → zeros across the board (Worst Status=0); the Total Certs
   * channel disambiguates "no certs yet" from "all certs healthy".
   *
   * Caller passes a row with: id, fqdn, last_checkin_at, plus the AGGREGATE
   * fields total_certs / min_days / worst_status_int / alerting_count, computed
   * via SQL by the caller (not re-queried inside the helper).
   */
  function buildAgentChannels(row) {
    const totalCerts = Number(row.total_certs) || 0;
    const minDays = (row.min_days === null || row.min_days === undefined)
      ? 0 : Math.max(0, Number(row.min_days));
    const worstStatus = Number(row.worst_status_int) || 0;
    const alertingCount = Number(row.alerting_count) || 0;
    let daysSinceCheckin = 0;
    if (row.last_checkin_at) {
      const lc = new Date(row.last_checkin_at).getTime();
      if (!Number.isNaN(lc)) {
        daysSinceCheckin = Math.max(0, Math.floor((Date.now() - lc) / 86400000));
      }
    }
    return [
      { name: 'Total Certs',           value: totalCerts },
      { name: 'Min Days Remaining',    value: minDays },
      { name: 'Worst Status',          value: worstStatus },
      { name: 'Days Since Check-in',   value: daysSinceCheckin },
      { name: 'Findings Alerting',     value: alertingCount }
    ];
  }

  /**
   * Internal helper: validate per-cert PRTG settings on PUT.
   * Returns { ok: true } or { ok: false, error: string }.
   * Same shape as the global PUT validation but per-field.
   */
  function validatePerCertPrtg(body) {
    if (body.prtg_push_enabled !== undefined) {
      const v = String(body.prtg_push_enabled);
      if (v !== '0' && v !== '1') {
        return { ok: false, error: 'prtg_push_enabled must be "0" or "1"' };
      }
    }
    if (body.prtg_token !== undefined && body.prtg_token !== null && body.prtg_token !== '') {
      const t = String(body.prtg_token);
      if (t.length > 128) return { ok: false, error: 'prtg_token too long (max 128 chars)' };
      if (/[\s\/?#]/.test(t)) return { ok: false, error: 'prtg_token contains invalid characters' };
    }
    if (body.prtg_sensor_id !== undefined && body.prtg_sensor_id !== null && body.prtg_sensor_id !== '') {
      const s = String(body.prtg_sensor_id);
      if (s.length > 64) return { ok: false, error: 'prtg_sensor_id too long (max 64 chars)' };
    }
    return { ok: true };
  }

  /**
   * Internal helper: load PRTG connection settings from cert_config for
   * test-push endpoints. Returns { host, port, protocol, verifyTls, timeoutMs }
   * or null if unconfigured.
   */
  // === CORPIT-HARDENING (2026-09-06) =======================================
  // Never hand a PRTG push token to a browser. The GET routes below are gated
  // at 'read', but the token they used to return is a write credential for a
  // sensor on a PRTG core shared with itam.nrpi.local. The admin-only PUT
  // already treats an absent prtg_token as "leave unchanged", so the UI does
  // not need the current value to edit the rest of the form -- it only needs
  // to know whether one is set.
  function redactPrtg(row) {
    if (!row) return row;
    const out = Object.assign({}, row);
    out.prtg_token_set = !!(out.prtg_token !== null &&
                            out.prtg_token !== undefined &&
                            String(out.prtg_token) !== '');
    delete out.prtg_token;
    return out;
  }

  // The PRTG core is a shared resource. cert_config.prtg_enabled is the master
  // switch, and it must hold on EVERY path that can write to that core -- not
  // just the scheduled collectors. Without this, a UI "Test Push" button pushes
  // to the shared core even when the integration is switched off here.
  async function prtgPushBlocked(res) {
    const config = await loadPrtgConfig();
    if (config.prtg_enabled !== '1') {
      res.status(409).json({
        error: 'PRTG push is disabled for this deployment (cert_config.prtg_enabled = 0). ' +
               'The PRTG core is shared with itam.nrpi.local, which pushes to the same ' +
               'sensors; enabling push here would write to another host\'s sensor history.'
      });
      return true;
    }
    return false;
  }
  // === end CORPIT-HARDENING ================================================

  async function loadPrtgConn() {
    const config = await loadPrtgConfig();
    if (!config.prtg_core_host) return null;
    return {
      host:      config.prtg_core_host,
      port:      parseInt(config.prtg_push_port, 10) || 5050,
      protocol:  config.prtg_push_protocol === 'https' ? 'https' : 'http',
      verifyTls: config.prtg_verify_tls === '1',
      timeoutMs: parseInt(config.prtg_timeout_ms, 10) || 5000
    };
  }

  // ---------------------------------------------------------------------------
  // GET /api/certs/:id/prtg — read per-monitor PRTG settings + last push state
  // ---------------------------------------------------------------------------
  router.get('/api/certs/:id/prtg', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const [rows] = await pool.query(
        `SELECT id, hostname, port,
                prtg_push_enabled, prtg_token, prtg_sensor_id,
                prtg_last_push_at, prtg_last_push_status, prtg_last_push_response
           FROM cert_monitors
          WHERE id = ?`,
        [id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
      res.json({ prtg: redactPrtg(rows[0]) });
    } catch (err) {
      console.error('GET /api/certs/:id/prtg failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---------------------------------------------------------------------------
  // PUT /api/certs/:id/prtg — update per-monitor PRTG settings
  // Body: { prtg_push_enabled?, prtg_token?, prtg_sensor_id? }
  // Empty string for token/sensor_id = NULL.
  // ---------------------------------------------------------------------------
  router.put('/api/certs/:id/prtg', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const body = req.body || {};
      const v = validatePerCertPrtg(body);
      if (!v.ok) return res.status(400).json({ error: v.error });

      const updates = [];
      const params = [];
      if (body.prtg_push_enabled !== undefined) {
        updates.push('prtg_push_enabled = ?');
        params.push(parseInt(body.prtg_push_enabled, 10) ? 1 : 0);
      }
      if (body.prtg_token !== undefined) {
        updates.push('prtg_token = ?');
        // empty string -> NULL (clears the token)
        params.push(body.prtg_token === '' || body.prtg_token === null ? null : String(body.prtg_token));
      }
      if (body.prtg_sensor_id !== undefined) {
        updates.push('prtg_sensor_id = ?');
        params.push(body.prtg_sensor_id === '' || body.prtg_sensor_id === null ? null : String(body.prtg_sensor_id));
      }
      if (updates.length === 0) {
        return res.status(400).json({ error: 'No PRTG fields provided' });
      }
      params.push(id);

      const [result] = await pool.query(
        `UPDATE cert_monitors SET ${updates.join(', ')} WHERE id = ?`,
        params
      );
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Not found' });

      res.json({ ok: true, updated: updates.length });
    } catch (err) {
      console.error('PUT /api/certs/:id/prtg failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---------------------------------------------------------------------------
  // POST /api/certs/:id/prtg/test — push current cert state to PRTG NOW
  // Uses the saved per-monitor token + global connection config. Validates
  // both are present before pushing.
  // ---------------------------------------------------------------------------
  router.post('/api/certs/:id/prtg/test', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      // Load monitor + cert state via JOINs (same shape as the cron query)
      const [rows] = await pool.query(
        `SELECT m.id, m.hostname, m.prtg_token,
                c.status, c.days_remaining, c.subject_cn, c.not_after,
                ch.handshake_ms, ch.not_before
           FROM cert_monitors m
           JOIN cert_current  c  ON c.monitor_id = m.id
           LEFT JOIN cert_checks ch ON ch.id = c.last_check_id
          WHERE m.id = ?`,
        [id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Monitor not found or has no cert state yet — try Check Now first' });
      }
      const row = rows[0];
      if (!row.prtg_token) {
        return res.status(400).json({ error: 'No PRTG token configured for this monitor' });
      }

      if (await prtgPushBlocked(res)) return;
      const prtgConn = await loadPrtgConn();
      if (!prtgConn) {
        return res.status(400).json({ error: 'PRTG core host not configured (Settings > PRTG Integration)' });
      }

      const channels = buildMonitorChannels(row);
      const cn = row.subject_cn || row.hostname || 'unknown';
      const dr = (row.days_remaining === null || row.days_remaining === undefined)
        ? '?' : String(row.days_remaining);
      const statusText = `${cn} — ${dr} days remaining — status: ${row.status || 'unknown'} (manual test)`;

      const result = await pushToPrtg({
        host: prtgConn.host,
        port: prtgConn.port,
        protocol: prtgConn.protocol,
        verifyTls: prtgConn.verifyTls,
        timeoutMs: prtgConn.timeoutMs,
        token: row.prtg_token,
        channels,
        statusText
      });

      // Record outcome (same as cron does) so the UI shows it
      const status = result.ok
        ? 'ok'
        : (result.error || '').startsWith('validation:') ? 'validation'
        : (result.error || '').startsWith('timeout:')    ? 'timeout'
        : (result.error || '').startsWith('sensor-mismatch:') ? 'mismatch'
        : 'error';
      const responseSnippet = (result.body || result.error || '').toString().slice(0, 1000);
      try {
        await pool.query(
          `UPDATE cert_monitors
              SET prtg_last_push_at       = NOW(),
                  prtg_last_push_status   = ?,
                  prtg_last_push_response = ?
            WHERE id = ?`,
          [status, responseSnippet, id]
        );
      } catch (e) {
        // Non-fatal: response goes back even if we couldn't record
        console.error('test-push: failed to record outcome', e);
      }

      res.json({ ok: result.ok, result, channels });
    } catch (err) {
      console.error('POST /api/certs/:id/prtg/test failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---------------------------------------------------------------------------
  // GET /api/findings/:id/prtg — read per-finding PRTG settings + last push
  // ---------------------------------------------------------------------------
  router.get('/api/findings/:id/prtg', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const [rows] = await pool.query(
        `SELECT id, subject_cn, agent_id,
                prtg_push_enabled, prtg_token, prtg_sensor_id,
                prtg_last_push_at, prtg_last_push_status, prtg_last_push_response
           FROM cert_findings
          WHERE id = ?`,
        [id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
      res.json({ prtg: redactPrtg(rows[0]) });
    } catch (err) {
      console.error('GET /api/findings/:id/prtg failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---------------------------------------------------------------------------
  // PUT /api/findings/:id/prtg — update per-finding PRTG settings
  // ---------------------------------------------------------------------------
  router.put('/api/findings/:id/prtg', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const body = req.body || {};
      const v = validatePerCertPrtg(body);
      if (!v.ok) return res.status(400).json({ error: v.error });

      const updates = [];
      const params = [];
      if (body.prtg_push_enabled !== undefined) {
        updates.push('prtg_push_enabled = ?');
        params.push(parseInt(body.prtg_push_enabled, 10) ? 1 : 0);
      }
      if (body.prtg_token !== undefined) {
        updates.push('prtg_token = ?');
        params.push(body.prtg_token === '' || body.prtg_token === null ? null : String(body.prtg_token));
      }
      if (body.prtg_sensor_id !== undefined) {
        updates.push('prtg_sensor_id = ?');
        params.push(body.prtg_sensor_id === '' || body.prtg_sensor_id === null ? null : String(body.prtg_sensor_id));
      }
      if (updates.length === 0) {
        return res.status(400).json({ error: 'No PRTG fields provided' });
      }
      params.push(id);

      const [result] = await pool.query(
        `UPDATE cert_findings SET ${updates.join(', ')} WHERE id = ?`,
        params
      );
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Not found' });

      res.json({ ok: true, updated: updates.length });
    } catch (err) {
      console.error('PUT /api/findings/:id/prtg failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---------------------------------------------------------------------------
  // POST /api/findings/:id/prtg/test — push current finding state to PRTG NOW
  // ---------------------------------------------------------------------------
  router.post('/api/findings/:id/prtg/test', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const [rows] = await pool.query(
        `SELECT f.id, f.subject_cn, f.status, f.days_remaining,
                f.not_before, f.last_seen_at, f.prtg_token,
                a.fqdn AS agent_fqdn
           FROM cert_findings f
           JOIN cert_agents   a ON a.id = f.agent_id
          WHERE f.id = ?`,
        [id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Finding not found' });
      }
      const row = rows[0];
      if (!row.prtg_token) {
        return res.status(400).json({ error: 'No PRTG token configured for this finding' });
      }

      if (await prtgPushBlocked(res)) return;
      const prtgConn = await loadPrtgConn();
      if (!prtgConn) {
        return res.status(400).json({ error: 'PRTG core host not configured (Settings > PRTG Integration)' });
      }

      const channels = buildFindingChannels(row);
      const cn = row.subject_cn || '(unknown subject)';
      const fqdn = row.agent_fqdn || '(unknown server)';
      const dr = (row.days_remaining === null || row.days_remaining === undefined)
        ? '?' : String(row.days_remaining);
      const statusText = `${cn} on ${fqdn} — ${dr} days remaining — status: ${row.status || 'unknown'} (manual test)`;

      const result = await pushToPrtg({
        host: prtgConn.host,
        port: prtgConn.port,
        protocol: prtgConn.protocol,
        verifyTls: prtgConn.verifyTls,
        timeoutMs: prtgConn.timeoutMs,
        token: row.prtg_token,
        channels,
        statusText
      });

      const status = result.ok
        ? 'ok'
        : (result.error || '').startsWith('validation:') ? 'validation'
        : (result.error || '').startsWith('timeout:')    ? 'timeout'
        : (result.error || '').startsWith('sensor-mismatch:') ? 'mismatch'
        : 'error';
      const responseSnippet = (result.body || result.error || '').toString().slice(0, 1000);
      try {
        await pool.query(
          `UPDATE cert_findings
              SET prtg_last_push_at       = NOW(),
                  prtg_last_push_status   = ?,
                  prtg_last_push_response = ?
            WHERE id = ?`,
          [status, responseSnippet, id]
        );
      } catch (e) {
        console.error('test-push (finding): failed to record outcome', e);
      }

      res.json({ ok: result.ok, result, channels });
    } catch (err) {
      console.error('POST /api/findings/:id/prtg/test failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // PER-AGENT ENDPOINTS (Step 8.5 — server-level rollup push for scan targets)
  // ===========================================================================

  /**
   * Internal helper: fetch one agent + its rollup aggregates from cert_findings.
   * Returns the row shape expected by buildAgentChannels.
   * Includes prtg_token so callers can validate before pushing.
   */
  async function loadAgentRollup(agentId) {
    const [rows] = await pool.query(
      `SELECT a.id, a.fqdn, a.hostname, a.last_checkin_at, a.last_checkin_status,
              a.prtg_token,
              COUNT(f.id) AS total_certs,
              MIN(f.days_remaining) AS min_days,
              MAX(CASE f.status
                    WHEN 'ok'       THEN 0
                    WHEN 'info'     THEN 1
                    WHEN 'warning'  THEN 2
                    WHEN 'critical' THEN 3
                    WHEN 'expired'  THEN 4
                    WHEN 'error'    THEN 6
                    ELSE 0
                  END) AS worst_status_int,
              SUM(CASE WHEN f.status IN ('info','warning','critical','expired')
                       THEN 1 ELSE 0 END) AS alerting_count
         FROM cert_agents a
         LEFT JOIN cert_findings f ON f.agent_id = a.id
        WHERE a.id = ?
        GROUP BY a.id`,
      [agentId]
    );
    return rows[0] || null;
  }

  router.get('/api/agents/:id/prtg', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const [rows] = await pool.query(
        `SELECT id, fqdn, hostname,
                prtg_push_enabled, prtg_token, prtg_sensor_id,
                prtg_last_push_at, prtg_last_push_status, prtg_last_push_response
           FROM cert_agents
          WHERE id = ?`,
        [id]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
      res.json({ prtg: redactPrtg(rows[0]) });
    } catch (err) {
      console.error('GET /api/agents/:id/prtg failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.put('/api/agents/:id/prtg', rbac.requirePage('cert-watchtower','admin'), express.json(), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const body = req.body || {};
      const v = validatePerCertPrtg(body);
      if (!v.ok) return res.status(400).json({ error: v.error });

      const updates = [];
      const params = [];
      if (body.prtg_push_enabled !== undefined) {
        updates.push('prtg_push_enabled = ?');
        params.push(parseInt(body.prtg_push_enabled, 10) ? 1 : 0);
      }
      if (body.prtg_token !== undefined) {
        updates.push('prtg_token = ?');
        params.push(body.prtg_token === '' || body.prtg_token === null ? null : String(body.prtg_token));
      }
      if (body.prtg_sensor_id !== undefined) {
        updates.push('prtg_sensor_id = ?');
        params.push(body.prtg_sensor_id === '' || body.prtg_sensor_id === null ? null : String(body.prtg_sensor_id));
      }
      if (updates.length === 0) {
        return res.status(400).json({ error: 'No PRTG fields provided' });
      }
      params.push(id);
      const [result] = await pool.query(
        `UPDATE cert_agents SET ${updates.join(', ')} WHERE id = ?`,
        params
      );
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Not found' });
      res.json({ ok: true, updated: updates.length });
    } catch (err) {
      console.error('PUT /api/agents/:id/prtg failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.post('/api/agents/:id/prtg/test', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const row = await loadAgentRollup(id);
      if (!row) {
        return res.status(404).json({ error: 'Scan target not found' });
      }
      if (!row.prtg_token) {
        return res.status(400).json({ error: 'No PRTG token configured for this scan target' });
      }
      if (await prtgPushBlocked(res)) return;
      const prtgConn = await loadPrtgConn();
      if (!prtgConn) {
        return res.status(400).json({ error: 'PRTG core host not configured (Settings > PRTG Integration)' });
      }

      const channels = buildAgentChannels(row);
      const fqdn = row.fqdn || row.hostname || 'unknown';
      const totals = Number(row.total_certs) || 0;
      const minDays = row.min_days === null || row.min_days === undefined
        ? '?' : String(Math.max(0, Number(row.min_days)));
      const statusText = `${fqdn} — ${totals} cert${totals === 1 ? '' : 's'}, soonest expires in ${minDays}d (manual test)`;

      const result = await pushToPrtg({
        host: prtgConn.host,
        port: prtgConn.port,
        protocol: prtgConn.protocol,
        verifyTls: prtgConn.verifyTls,
        timeoutMs: prtgConn.timeoutMs,
        token: row.prtg_token,
        channels,
        statusText
      });

      const status = result.ok
        ? 'ok'
        : (result.error || '').startsWith('validation:') ? 'validation'
        : (result.error || '').startsWith('timeout:')    ? 'timeout'
        : (result.error || '').startsWith('sensor-mismatch:') ? 'mismatch'
        : 'error';
      const responseSnippet = (result.body || result.error || '').toString().slice(0, 1000);
      try {
        await pool.query(
          `UPDATE cert_agents
              SET prtg_last_push_at       = NOW(),
                  prtg_last_push_status   = ?,
                  prtg_last_push_response = ?
            WHERE id = ?`,
          [status, responseSnippet, id]
        );
      } catch (e) {
        console.error('test-push (agent): failed to record outcome', e);
      }

      res.json({ ok: result.ok, result, channels });
    } catch (err) {
      console.error('POST /api/agents/:id/prtg/test failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ===========================================================================
  // STEP 9: Push status table + bulk retry
  // ===========================================================================

  /**
   * GET /api/prtg/push-history?limit=50
   *
   * Returns the most recent push status across BOTH cert_monitors AND
   * cert_findings, unioned and sorted by last_push_at DESC.
   *
   * Caveat: each row reflects the single MOST-RECENT push for that cert.
   * The DB doesn't store true history per push (only last_push_*); the
   * cert-watchtower table is the per-cert latest snapshot. PRTG itself
   * holds true historical sensor data.
   */
  router.get('/api/prtg/push-history', rbac.requirePage('cert-watchtower','read'), async (req, res) => {
    try {
      const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 500);
      const [rows] = await pool.query(
        `(
          SELECT 'monitor' AS kind, m.id, m.hostname AS subject,
                 c.subject_cn, c.status AS cert_status, c.days_remaining,
                 (m.prtg_token IS NOT NULL AND m.prtg_token <> '') AS prtg_token_set,
                 m.prtg_sensor_id,
                 m.prtg_last_push_at  AS last_push_at,
                 m.prtg_last_push_status AS last_push_status,
                 m.prtg_last_push_response AS last_push_response,
                 m.prtg_push_enabled
            FROM cert_monitors m
            LEFT JOIN cert_current c ON c.monitor_id = m.id
           WHERE m.prtg_last_push_at IS NOT NULL
        )
        UNION ALL
        (
          SELECT 'finding' AS kind, f.id, a.fqdn AS subject,
                 f.subject_cn, f.status AS cert_status, f.days_remaining,
                 (f.prtg_token IS NOT NULL AND f.prtg_token <> '') AS prtg_token_set,
                 f.prtg_sensor_id,
                 f.prtg_last_push_at  AS last_push_at,
                 f.prtg_last_push_status AS last_push_status,
                 f.prtg_last_push_response AS last_push_response,
                 f.prtg_push_enabled
            FROM cert_findings f
            JOIN cert_agents a ON a.id = f.agent_id
           WHERE f.prtg_last_push_at IS NOT NULL
        )
        UNION ALL
        (
          SELECT 'agent' AS kind, a.id, a.fqdn AS subject,
                 NULL AS subject_cn, NULL AS cert_status, NULL AS days_remaining,
                 (a.prtg_token IS NOT NULL AND a.prtg_token <> '') AS prtg_token_set,
                 a.prtg_sensor_id,
                 a.prtg_last_push_at  AS last_push_at,
                 a.prtg_last_push_status AS last_push_status,
                 a.prtg_last_push_response AS last_push_response,
                 a.prtg_push_enabled
            FROM cert_agents a
           WHERE a.prtg_last_push_at IS NOT NULL
        )
        ORDER BY last_push_at DESC
        LIMIT ?`,
        [limit]
      );
      res.json({ history: rows, limit });
    } catch (err) {
      console.error('GET /api/prtg/push-history failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * POST /api/prtg/retry-failed
   *
   * Re-pushes every monitor/finding where:
   *   - prtg_push_enabled = 1
   *   - prtg_token IS NOT NULL AND <> ''
   *   - prtg_last_push_status IS NOT NULL AND <> 'ok'
   *
   * Concurrency: 5 in flight (matches the cron pattern). Each retry uses the
   * same code path as the per-cert test endpoints (real cert data).
   *
   * Returns { attempted, succeeded, failed, results: [...] }.
   *
   * Skips if global prtg_enabled='0' (returns 400 — encourages user to flip
   * the master switch first).
   */
  router.post('/api/prtg/retry-failed', rbac.requirePage('cert-watchtower','admin'), async (req, res) => {
    try {
      const config = await loadPrtgConfig();
      if (config.prtg_enabled !== '1') {
        return res.status(400).json({
          error: 'Global PRTG push is disabled. Enable it in Settings before retrying.'
        });
      }
      if (await prtgPushBlocked(res)) return;
      const prtgConn = await loadPrtgConn();
      if (!prtgConn) {
        return res.status(400).json({ error: 'PRTG core host not configured' });
      }

      // Find failed monitors and findings
      const [monRows] = await pool.query(
        `SELECT m.id, m.hostname, m.prtg_token,
                c.status, c.days_remaining, c.subject_cn, c.not_after,
                ch.handshake_ms, ch.not_before
           FROM cert_monitors m
           JOIN cert_current  c  ON c.monitor_id = m.id
           LEFT JOIN cert_checks ch ON ch.id = c.last_check_id
          WHERE m.prtg_push_enabled = 1
            AND m.prtg_token IS NOT NULL AND m.prtg_token <> ''
            AND m.prtg_last_push_status IS NOT NULL
            AND m.prtg_last_push_status <> 'ok'`
      );
      const [findRows] = await pool.query(
        `SELECT f.id, f.subject_cn, f.status, f.days_remaining,
                f.not_before, f.last_seen_at, f.prtg_token,
                a.fqdn AS agent_fqdn
           FROM cert_findings f
           JOIN cert_agents   a ON a.id = f.agent_id
          WHERE f.prtg_push_enabled = 1
            AND f.prtg_token IS NOT NULL AND f.prtg_token <> ''
            AND f.prtg_last_push_status IS NOT NULL
            AND f.prtg_last_push_status <> 'ok'`
      );

      // Step 8.5: agents with failed last push.
      // Use loadAgentRollup per ID to get the row shape buildAgentChannels expects.
      const [agentIdRows] = await pool.query(
        `SELECT id FROM cert_agents
          WHERE enabled = 1
            AND prtg_push_enabled = 1
            AND prtg_token IS NOT NULL AND prtg_token <> ''
            AND prtg_last_push_status IS NOT NULL
            AND prtg_last_push_status <> 'ok'`
      );
      const agentRows = [];
      for (const idRow of agentIdRows) {
        const r = await loadAgentRollup(idRow.id);
        if (r) agentRows.push(r);
      }

      const targets = [
        ...monRows.map(r => ({ kind: 'monitor', row: r })),
        ...findRows.map(r => ({ kind: 'finding', row: r })),
        ...agentRows.map(r => ({ kind: 'agent', row: r }))
      ];

      if (targets.length === 0) {
        return res.json({ attempted: 0, succeeded: 0, failed: 0, results: [] });
      }

      // Concurrency runner — same pattern as cron
      const results = new Array(targets.length);
      let nextIdx = 0;
      const CONCURRENCY = 5;

      async function lane() {
        while (true) {
          const idx = nextIdx++;
          if (idx >= targets.length) return;
          const t = targets[idx];
          try {
            const channels = t.kind === 'monitor'
              ? buildMonitorChannels(t.row)
              : t.kind === 'finding'
                ? buildFindingChannels(t.row)
                : buildAgentChannels(t.row);

            // Build statusText per kind
            let statusText;
            if (t.kind === 'agent') {
              const fqdn = t.row.fqdn || t.row.hostname || 'unknown';
              const totals = Number(t.row.total_certs) || 0;
              const minDays = (t.row.min_days === null || t.row.min_days === undefined)
                ? '?' : String(Math.max(0, Number(t.row.min_days)));
              statusText = `${fqdn} — ${totals} cert${totals === 1 ? '' : 's'}, soonest expires in ${minDays}d (retry)`;
            } else {
              const cn = t.row.subject_cn || t.row.hostname || t.row.agent_fqdn || 'unknown';
              const fqdnSuffix = t.row.agent_fqdn ? ` on ${t.row.agent_fqdn}` : '';
              const dr = (t.row.days_remaining === null || t.row.days_remaining === undefined)
                ? '?' : String(t.row.days_remaining);
              statusText = `${cn}${fqdnSuffix} — ${dr} days remaining — status: ${t.row.status || 'unknown'} (retry)`;
            }

            const result = await pushToPrtg({
              host: prtgConn.host,
              port: prtgConn.port,
              protocol: prtgConn.protocol,
              verifyTls: prtgConn.verifyTls,
              timeoutMs: prtgConn.timeoutMs,
              token: t.row.prtg_token,
              channels,
              statusText
            });

            // Persist outcome
            const status = result.ok ? 'ok'
              : (result.error || '').startsWith('validation:') ? 'validation'
              : (result.error || '').startsWith('timeout:')    ? 'timeout'
              : (result.error || '').startsWith('sensor-mismatch:') ? 'mismatch'
              : 'error';
            const responseSnippet = (result.body || result.error || '').toString().slice(0, 1000);
            const table = t.kind === 'monitor' ? 'cert_monitors'
                        : t.kind === 'finding' ? 'cert_findings'
                        : 'cert_agents';
            try {
              await pool.query(
                `UPDATE ${table}
                    SET prtg_last_push_at       = NOW(),
                        prtg_last_push_status   = ?,
                        prtg_last_push_response = ?
                  WHERE id = ?`,
                [status, responseSnippet, t.row.id]
              );
            } catch (dbErr) {
              console.error('retry-failed: failed to record outcome', dbErr);
            }

            results[idx] = {
              kind: t.kind, id: t.row.id,
              subject: t.row.subject_cn || t.row.hostname || t.row.agent_fqdn || t.row.fqdn,
              ok: result.ok,
              status,
              error: result.error,
              durationMs: result.durationMs
            };
          } catch (err) {
            results[idx] = {
              kind: t.kind, id: t.row.id,
              subject: t.row.subject_cn || t.row.hostname || t.row.agent_fqdn || t.row.fqdn,
              ok: false,
              status: 'error',
              error: err.message,
              durationMs: 0
            };
          }
        }
      }

      const lanes = Array(Math.min(CONCURRENCY, targets.length)).fill(0).map(() => lane());
      await Promise.all(lanes);

      const succeeded = results.filter(r => r.ok).length;
      const failed = results.length - succeeded;

      res.json({
        attempted: targets.length,
        succeeded,
        failed,
        results
      });
    } catch (err) {
      console.error('POST /api/prtg/retry-failed failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
};
