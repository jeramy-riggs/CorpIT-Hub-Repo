#!/usr/bin/env node
// =============================================================================
// Cert Watchtower — Phase 2: Node WinRM Scanner
// File: /var/www/api/cert-watchtower-winrm-scan.js
//
// Daily cron job. Walks every enabled cert_agents row, spawns the Python
// WinRM helper for each, stores the returned findings.
//
// Reuses the cert classification logic from cert-watchtower-routes.js so
// status thresholds stay consistent across all sources (TLS, agent, manual).
//
// Logs to /var/log/cert-watchtower/scan.log (created by the agent log dir
// we set up in Phase 1).
//
// Phase 2.5 (May 2026): also pushes findings to PRTG sensors after the scan
// phase completes, gated by global enable + per-finding opt-in. PRTG failures
// never abort the scan — they're logged and per-finding status is recorded
// in cert_findings.
//
// Exit codes:
//   0 = success (every target processed, even if some scans failed individually)
//   1 = fatal (DB unavailable, env missing, etc.)
// =============================================================================

require('dotenv').config({ path: '/var/www/api/.env' });
const mysql = require('mysql2/promise');
const { spawn } = require('child_process');
const fs = require('fs');

// -----------------------------------------------------------------------------
// Phase 2.5: PRTG push helper. Pure function, no DB access.
// -----------------------------------------------------------------------------
const { pushToPrtg } = require('./cert-watchtower-prtg-helper');

// -----------------------------------------------------------------------------
// Config — environment & paths
// -----------------------------------------------------------------------------
const HELPER_PATH = '/var/www/api/cert-watchtower-winrm-helper.py';
const PYTHON_BIN = '/usr/bin/python3';
// WinRM creds live in api-beta's .env (where Identity Diagnostics already
// uses them). We read directly from that file rather than copying values
// across to keep one source of truth.
const WINRM_ENV_PATH = '/var/www/corpit-hub-api/.env';

// -----------------------------------------------------------------------------
// Logging — timestamped, grep-friendly. Captured by cron redirect.
// -----------------------------------------------------------------------------
function log(level, msg, extra) {
  const ts = new Date().toISOString();
  const line = extra
    ? `${ts} [${level}] ${msg} ${JSON.stringify(extra)}`
    : `${ts} [${level}] ${msg}`;
  if (level === 'ERROR') console.error(line);
  else console.log(line);
}

// -----------------------------------------------------------------------------
// MySQL pool — small, short-lived
// -----------------------------------------------------------------------------
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 5,
  charset: 'utf8mb4'
});

// -----------------------------------------------------------------------------
// Read WINRM_USER / WINRM_PASS from the api-beta .env file.
// We strip wrapping quotes the same way Node's dotenv does — but since we're
// reading manually here (not via require('dotenv')) we handle it ourselves.
// -----------------------------------------------------------------------------
function loadWinrmCreds() {
  if (!fs.existsSync(WINRM_ENV_PATH)) {
    throw new Error(`WinRM env file not found: ${WINRM_ENV_PATH}`);
  }
  const text = fs.readFileSync(WINRM_ENV_PATH, 'utf8');
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/i);
    if (!m) continue;
    let value = m[2];
    // Strip surrounding double or single quotes (matches dotenv behavior)
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[m[1]] = value;
  }
  if (!out.WINRM_USER || !out.WINRM_PASS) {
    throw new Error('WINRM_USER and WINRM_PASS must be set in ' + WINRM_ENV_PATH);
  }
  return { user: out.WINRM_USER, pass: out.WINRM_PASS };
}

// -----------------------------------------------------------------------------
// Load all config rows into a plain object
// -----------------------------------------------------------------------------
async function loadConfig() {
  const [rows] = await pool.query('SELECT config_key, config_value FROM cert_config');
  return Object.fromEntries(rows.map(r => [r.config_key, r.config_value]));
}

// -----------------------------------------------------------------------------
// Status classifier — same as routes file
// -----------------------------------------------------------------------------
function classifyStatus(daysRemaining, thresholds) {
  if (daysRemaining === null || daysRemaining === undefined) return 'error';
  if (daysRemaining < 0) return 'expired';
  if (daysRemaining <= thresholds.critical) return 'critical';
  if (daysRemaining <= thresholds.warning) return 'warning';
  if (daysRemaining <= thresholds.info) return 'info';
  return 'ok';
}

// -----------------------------------------------------------------------------
// Convert any ISO-8601 string to a MySQL DATETIME-friendly form.
// MySQL DATETIME accepts "YYYY-MM-DD HH:MM:SS" (no T, no Z, no fractional).
// We parse via Date() which accepts wide variety, then format ourselves.
// Returns null for null/empty input. Returns null if Date() can't parse.
// -----------------------------------------------------------------------------
function toMysqlDateTime(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  // Format as UTC YYYY-MM-DD HH:MM:SS
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ` +
         `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

// -----------------------------------------------------------------------------
// Spawn the Python helper for a single target. Returns parsed JSON or rejects.
// -----------------------------------------------------------------------------
function runHelper(target, creds, timeoutS) {
  return new Promise((resolve, reject) => {
    const args = [
      HELPER_PATH,
      '--host', target.target_host || target.fqdn,
      '--port', String(target.winrm_port || 5985),
      '--transport', target.winrm_transport || 'ntlm',
      '--stores', target.scan_stores || 'LocalMachine\\My',
      '--timeout', String(timeoutS)
    ];
    if (target.winrm_use_ssl) args.push('--ssl');
    if (target.scan_iis) args.push('--scan-iis');

    const child = spawn(PYTHON_BIN, args, {
      env: {
        ...process.env,
        WINRM_USER: creds.user,
        WINRM_PASS: creds.pass,
        // Don't inherit DB_* vars to avoid confusion in helper logs
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });

    // Hard timeout — kill the helper if it hangs
    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
      reject(new Error(`helper timeout after ${timeoutS + 30}s`));
    }, (timeoutS + 30) * 1000);

    child.on('error', err => {
      clearTimeout(killTimer);
      reject(err);
    });
    child.on('close', code => {
      clearTimeout(killTimer);
      // Helper always prints JSON on stdout — even for errors. Try to parse.
      try {
        const parsed = JSON.parse(stdout.trim() || '{}');
        if (code !== 0 && parsed.ok !== false) {
          // Helper exited non-zero but didn't print error JSON — wrap it
          return reject(new Error(`helper exit ${code}: ${stderr.slice(0,500) || stdout.slice(0,500)}`));
        }
        resolve(parsed);
      } catch (e) {
        reject(new Error(`helper output not JSON (exit ${code}): ${stdout.slice(0,500) || stderr.slice(0,500)}`));
      }
    });
  });
}

// -----------------------------------------------------------------------------
// Apply a successful helper result to the database.
// Updates cert_agents row + upserts cert_findings rows.
// -----------------------------------------------------------------------------
async function applyResult(agentId, result, thresholds) {
  if (!result.ok) {
    // Helper returned an error JSON — record it on the agent row
    await pool.query(
      `UPDATE cert_agents SET
         last_checkin_at = NOW(),
         last_checkin_status = 'error',
         last_error = ?
       WHERE id = ?`,
      [(result.error || 'unknown error').slice(0, 1000), agentId]
    );
    return { findings_processed: 0, status: 'error' };
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Update cert_agents with the latest snapshot
    await conn.query(
      `UPDATE cert_agents SET
         hostname = COALESCE(?, hostname),
         os_version = COALESCE(?, os_version),
         last_checkin_at = NOW(),
         last_checkin_status = 'ok',
         last_error = NULL
       WHERE id = ?`,
      [result.hostname || null, result.os_version || null, agentId]
    );

    // Process each finding (same upsert logic as agent-routes checkin endpoint)
    let processed = 0, errors = 0;
    for (const f of (result.findings || [])) {
      if (!f.thumbprint_sha1 || !f.store_name) {
        errors++;
        continue;
      }
      let daysRemaining = null;
      let status = 'error';
      if (f.not_after) {
        const ms = new Date(f.not_after) - new Date();
        daysRemaining = Math.floor(ms / (1000 * 60 * 60 * 24));
        status = classifyStatus(daysRemaining, thresholds);
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
          toMysqlDateTime(f.not_before),
          toMysqlDateTime(f.not_after),
          daysRemaining,
          f.has_private_key === undefined ? null : (f.has_private_key ? 1 : 0),
          f.is_self_signed === undefined ? null : (f.is_self_signed ? 1 : 0),
          f.key_algorithm || null,
          f.key_size || null,
          f.signature_algorithm || null,
          status
        ]
      );
      processed++;
    }
    await conn.commit();
    return { findings_processed: processed, findings_errored: errors, status: 'ok' };
  } catch (err) {
    await conn.rollback();
    // Mark the agent as having a partial result
    try {
      await pool.query(
        `UPDATE cert_agents SET last_checkin_status = 'error', last_error = ? WHERE id = ?`,
        [err.message.slice(0, 1000), agentId]
      );
    } catch (_) {}
    throw err;
  } finally {
    conn.release();
  }
}

// -----------------------------------------------------------------------------
// Concurrency-limited runner
// -----------------------------------------------------------------------------
async function runWithConcurrency(items, limit, worker) {
  const results = [];
  let nextIdx = 0;
  async function lane() {
    while (true) {
      const idx = nextIdx++;
      if (idx >= items.length) return;
      try {
        results[idx] = { ok: true, item: items[idx], value: await worker(items[idx]) };
      } catch (err) {
        results[idx] = { ok: false, item: items[idx], error: err.message };
      }
    }
  }
  const lanes = Array(Math.min(limit, items.length)).fill(0).map(() => lane());
  await Promise.all(lanes);
  return results;
}

// =============================================================================
// PRTG push (Phase 2.5)
// =============================================================================

// PRTG push concurrency. Lower than scan because PRTG push is cheap but we
// want to be polite to the probe. 5 in flight is a sane default.
const MAX_CONCURRENT_PRTG_PUSHES = 5;

// Status enum -> integer mapping for the "Cert Status" PRTG channel.
// Findings have one fewer state than monitors (no 'unreachable') but we
// keep the same numeric mapping for cross-sensor consistency.
const STATUS_TO_INT = {
  ok: 0,
  info: 1,
  warning: 2,
  critical: 3,
  expired: 4,
  unreachable: 5,
  error: 6
};

function statusToInt(s) {
  return Object.prototype.hasOwnProperty.call(STATUS_TO_INT, s) ? STATUS_TO_INT[s] : 6;
}

// Build the 4 channels for a per-finding PRTG push.
// For findings, channel #3 is "Days Since Last Seen" (how stale the finding
// is — informative because findings can disappear when a Windows server is
// offline) instead of "Handshake Time" (TLS-only concept).
function buildFindingChannels(row) {
  const days = Number.isFinite(Number(row.days_remaining))
    ? Number(row.days_remaining) : 0;

  // Days Since Last Seen: how many days ago we last successfully scanned this cert
  let daysSinceLastSeen = 0;
  if (row.last_seen_at) {
    const lastSeen = new Date(row.last_seen_at).getTime();
    if (!Number.isNaN(lastSeen)) {
      daysSinceLastSeen = Math.max(0, Math.floor((Date.now() - lastSeen) / 86400000));
    }
  }

  // Days Since Issue: derive from not_before
  let daysSinceIssue = 0;
  if (row.not_before) {
    const issued = new Date(row.not_before).getTime();
    if (!Number.isNaN(issued)) {
      daysSinceIssue = Math.max(0, Math.floor((Date.now() - issued) / 86400000));
    }
  }

  return [
    { name: 'Days Until Expiry',     value: days },
    { name: 'Cert Status',           value: statusToInt(row.status) },
    { name: 'Days Since Last Seen',  value: daysSinceLastSeen },
    { name: 'Days Since Issue',      value: daysSinceIssue }
  ];
}

// Build the human-readable PRTG sensor status text per design:
//   "<subject_cn> on <fqdn> — <N> days remaining — status: <state>"
function buildFindingStatusText(row) {
  const cn = row.subject_cn || '(unknown subject)';
  const fqdn = row.agent_fqdn || '(unknown server)';
  const dr = (row.days_remaining === null || row.days_remaining === undefined)
    ? '?' : String(row.days_remaining);
  const st = row.status || 'unknown';
  return `${cn} on ${fqdn} — ${dr} days remaining — status: ${st}`;
}

// Push one finding with retry. Returns the helper's structured result.
async function pushOneFinding(prtgConn, row, retryCount) {
  const channels = buildFindingChannels(row);
  const statusText = buildFindingStatusText(row);

  let lastResult = null;
  const attempts = Math.max(1, retryCount + 1);
  for (let attempt = 1; attempt <= attempts; attempt++) {
    lastResult = await pushToPrtg({
      host: prtgConn.host,
      port: prtgConn.port,
      protocol: prtgConn.protocol,
      verifyTls: prtgConn.verifyTls,
      timeoutMs: prtgConn.timeoutMs,
      token: row.prtg_token,
      channels,
      statusText
    });
    if (lastResult.ok) return lastResult;
    // Don't retry validation errors or sensor-mismatch — those won't change
    if (lastResult.error && (
      lastResult.error.startsWith('validation:') ||
      lastResult.error.startsWith('sensor-mismatch:')
    )) return lastResult;
  }
  return lastResult;
}

// Map helper result.error -> short status code for cert_findings.prtg_last_push_status
function classifyPushStatus(result) {
  if (result.ok) return 'ok';
  if (!result.error) return 'error';
  if (result.error.startsWith('validation:'))      return 'validation';
  if (result.error.startsWith('timeout:'))         return 'timeout';
  if (result.error.startsWith('sensor-mismatch:')) return 'mismatch';
  if (result.error.startsWith('http:'))            return 'error';
  return 'error';
}

// Persist the per-finding push outcome. Best-effort — DB failure here is
// logged but does not propagate.
async function recordFindingPushOutcome(findingId, result) {
  const status = classifyPushStatus(result);
  const responseSnippet = (result.body || result.error || '').toString().slice(0, 1000);
  try {
    await pool.query(
      `UPDATE cert_findings
         SET prtg_last_push_at       = NOW(),
             prtg_last_push_status   = ?,
             prtg_last_push_response = ?
       WHERE id = ?`,
      [status, responseSnippet, findingId]
    );
  } catch (err) {
    log('ERROR', 'failed to record prtg push outcome (finding)', {
      finding_id: findingId, error: err.message
    });
  }
}

// Run all PRTG pushes for findings on this scan tick. Reads global config +
// per-finding settings, walks every push-eligible finding concurrently. Never
// throws.
//
// NOTE: this does NOT push the fleet summary sensor — that's handled by the
// TLS cron (cert-watchtower-cron.js) so we don't double-push. The summary
// reflects the entire fleet state across both TLS monitors and findings.
async function runPrtgPushesForFindings(config) {
  if (config.prtg_enabled !== '1') {
    log('INFO', 'prtg push skipped — disabled in cert_config');
    return;
  }

  const prtgConn = {
    host:      config.prtg_core_host || '',
    port:      parseInt(config.prtg_push_port, 10) || 5050,
    protocol:  config.prtg_push_protocol === 'https' ? 'https' : 'http',
    verifyTls: config.prtg_verify_tls === '1',
    timeoutMs: parseInt(config.prtg_timeout_ms, 10) || 5000
  };
  const retryCount = parseInt(config.prtg_retry_count, 10);
  const retries = Number.isFinite(retryCount) && retryCount >= 0 ? retryCount : 2;

  if (!prtgConn.host) {
    log('INFO', 'prtg push skipped — prtg_core_host not configured');
    return;
  }

  // Fetch all push-eligible findings + their parent agent's FQDN for status
  // text. WHERE filters: agent enabled, finding push-enabled, has token.
  let pushRows;
  try {
    const [rows] = await pool.query(
      `SELECT f.id, f.subject_cn, f.status, f.days_remaining,
              f.not_before, f.last_seen_at, f.prtg_token,
              a.fqdn AS agent_fqdn
         FROM cert_findings f
         JOIN cert_agents   a ON a.id = f.agent_id
        WHERE a.enabled = 1
          AND f.is_watched = 1
          AND f.prtg_push_enabled = 1
          AND f.prtg_token IS NOT NULL
          AND f.prtg_token <> ''`
    );
    pushRows = rows;
  } catch (err) {
    log('ERROR', 'failed to load prtg finding push rows', { error: err.message });
    return;
  }

  log('INFO', `prtg finding push phase start`, {
    eligible: pushRows.length,
    host: prtgConn.host, port: prtgConn.port, protocol: prtgConn.protocol
  });

  let okCount = 0, failCount = 0;
  if (pushRows.length > 0) {
    const results = await runWithConcurrency(
      pushRows, MAX_CONCURRENT_PRTG_PUSHES,
      async (row) => {
        const result = await pushOneFinding(prtgConn, row, retries);
        await recordFindingPushOutcome(row.id, result);
        return { row, result };
      }
    );
    for (const r of results) {
      if (r.ok && r.value.result.ok) {
        okCount++;
      } else {
        failCount++;
        const err = r.ok ? r.value.result.error : r.error;
        const id  = r.ok ? r.value.row.id : (r.item && r.item.id);
        log('ERROR', 'prtg finding push failed', { finding_id: id, error: err });
      }
    }
  }
  log('INFO', 'prtg finding push phase complete', { ok: okCount, fail: failCount });
}

// =============================================================================
// PRTG agent rollup push (Step 8.5)
// =============================================================================
// Server-level rollup push — one PRTG sensor per scan target with whole-server
// cert posture (5 channels). Uses the same connection settings as the per-finding
// push but pushes AGGREGATE data (count, min days, worst status, freshness,
// alerting count) rather than per-cert data.
//
// Runs after the per-finding push phase. Independent — finding push failures
// don't block agent push, and vice versa.

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

function buildAgentStatusText(row) {
  const fqdn = row.fqdn || row.hostname || 'unknown';
  const totals = Number(row.total_certs) || 0;
  const minDays = (row.min_days === null || row.min_days === undefined)
    ? '?' : String(Math.max(0, Number(row.min_days)));
  const alerting = Number(row.alerting_count) || 0;
  const alertingNote = alerting > 0 ? `, ${alerting} alerting` : '';
  return `${fqdn} — ${totals} cert${totals === 1 ? '' : 's'}, soonest expires in ${minDays}d${alertingNote}`;
}

async function pushOneAgent(prtgConn, row, retryCount) {
  const channels = buildAgentChannels(row);
  const statusText = buildAgentStatusText(row);

  let lastResult = null;
  const attempts = Math.max(1, retryCount + 1);
  for (let attempt = 1; attempt <= attempts; attempt++) {
    lastResult = await pushToPrtg({
      host: prtgConn.host,
      port: prtgConn.port,
      protocol: prtgConn.protocol,
      verifyTls: prtgConn.verifyTls,
      timeoutMs: prtgConn.timeoutMs,
      token: row.prtg_token,
      channels,
      statusText
    });
    if (lastResult.ok) return lastResult;
    if (lastResult.error && (
      lastResult.error.startsWith('validation:') ||
      lastResult.error.startsWith('sensor-mismatch:')
    )) return lastResult;
  }
  return lastResult;
}

async function recordAgentPushOutcome(agentId, result) {
  const status = classifyPushStatus(result);
  const responseSnippet = (result.body || result.error || '').toString().slice(0, 1000);
  try {
    await pool.query(
      `UPDATE cert_agents
         SET prtg_last_push_at       = NOW(),
             prtg_last_push_status   = ?,
             prtg_last_push_response = ?
       WHERE id = ?`,
      [status, responseSnippet, agentId]
    );
  } catch (err) {
    log('ERROR', 'failed to record prtg push outcome (agent)', {
      agent_id: agentId, error: err.message
    });
  }
}

async function runPrtgPushesForAgents(config) {
  if (config.prtg_enabled !== '1') {
    // Already logged "skipped — disabled" by runPrtgPushesForFindings; don't double-log.
    return;
  }

  const prtgConn = {
    host:      config.prtg_core_host || '',
    port:      parseInt(config.prtg_push_port, 10) || 5050,
    protocol:  config.prtg_push_protocol === 'https' ? 'https' : 'http',
    verifyTls: config.prtg_verify_tls === '1',
    timeoutMs: parseInt(config.prtg_timeout_ms, 10) || 5000
  };
  const retryCount = parseInt(config.prtg_retry_count, 10);
  const retries = Number.isFinite(retryCount) && retryCount >= 0 ? retryCount : 2;

  if (!prtgConn.host) {
    return; // already logged by findings phase
  }

  // Fetch all push-eligible agents + rollup aggregates.
  // GROUP BY a.id so each agent gets one row, with totals computed across its findings.
  // CASE-mapping for status to int must match cert-watchtower-prtg-routes.js.
  let pushRows;
  try {
    const [rows] = await pool.query(
      `SELECT a.id, a.fqdn, a.hostname, a.last_checkin_at, a.prtg_token,
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
         LEFT JOIN cert_findings f ON f.agent_id = a.id AND f.is_watched = 1
        WHERE a.enabled = 1
          AND a.prtg_push_enabled = 1
          AND a.prtg_token IS NOT NULL
          AND a.prtg_token <> ''
        GROUP BY a.id`
    );
    pushRows = rows;
  } catch (err) {
    log('ERROR', 'failed to load prtg agent push rows', { error: err.message });
    return;
  }

  log('INFO', 'prtg agent push phase start', {
    eligible: pushRows.length,
    host: prtgConn.host, port: prtgConn.port, protocol: prtgConn.protocol
  });

  let okCount = 0, failCount = 0;
  if (pushRows.length > 0) {
    const results = await runWithConcurrency(
      pushRows, MAX_CONCURRENT_PRTG_PUSHES,
      async (row) => {
        const result = await pushOneAgent(prtgConn, row, retries);
        await recordAgentPushOutcome(row.id, result);
        return { row, result };
      }
    );
    for (const r of results) {
      if (r.ok && r.value.result.ok) {
        okCount++;
      } else {
        failCount++;
        const err = r.ok ? r.value.result.error : r.error;
        const id  = r.ok ? r.value.row.id : (r.item && r.item.id);
        log('ERROR', 'prtg agent push failed', { agent_id: id, error: err });
      }
    }
  }
  log('INFO', 'prtg agent push phase complete', { ok: okCount, fail: failCount });
}


// -----------------------------------------------------------------------------
// CA issued cert scan — runs after the normal store scan for is_ca=1 targets
// -----------------------------------------------------------------------------
const CA_HELPER_PATH = '/var/www/api/cert-watchtower-ca-scan-helper.py';

async function runCaScan(target, creds) {
  return new Promise((resolve) => {
    const args = [
      CA_HELPER_PATH,
      '--host',     target.target_host || target.fqdn,
      '--ca-name',  target.ca_name,
      '--port',     String(target.winrm_port || 5985),
      '--transport', target.winrm_transport || 'ntlm',
      '--timeout',  '120'
    ];
    if (target.winrm_use_ssl) args.push('--ssl');

    const child = spawn(PYTHON_BIN, args, {
      env: { ...process.env, WINRM_USER: creds.user, WINRM_PASS: creds.pass },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });

    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
      resolve({ ok: false, error: 'CA scan helper timeout' });
    }, 150000);

    child.on('error', err => { clearTimeout(killTimer); resolve({ ok: false, error: err.message }); });
    child.on('close', () => {
      clearTimeout(killTimer);
      try {
        const parsed = JSON.parse(stdout.trim() || '{}');
        resolve(parsed);
      } catch (e) {
        resolve({ ok: false, error: `CA helper output not JSON: ${stdout.slice(0, 200)}` });
      }
    });
  });
}

async function applyCaScanResult(agentId, result, thresholds) {
  if (!result.ok) {
    log('ERROR', `CA scan failed for agent ${agentId}`, { error: result.error });
    return { ca_certs_processed: 0, status: 'error' };
  }

  const certs = result.certs || [];
  if (certs.length === 0) {
    log('INFO', `CA scan for agent ${agentId}: 0 issued certs returned`);
    return { ca_certs_processed: 0, status: 'ok' };
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    let processed = 0;
    for (const cert of certs) {
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
          agentId,
          cert.request_id   || null,
          cert.serial_number,
          cert.requester_name || null,
          cert.cert_template  || null,
          cert.subject_cn     || null,
          toMysqlDateTime(cert.not_before),
          toMysqlDateTime(cert.not_after),
          daysRemaining,
          certStatus
        ]
      );
      processed++;
    }
    await conn.commit();
    return { ca_certs_processed: processed, status: 'ok' };
  } catch (err) {
    await conn.rollback();
    log('ERROR', `CA scan DB upsert failed for agent ${agentId}`, { error: err.message });
    return { ca_certs_processed: 0, status: 'error' };
  } finally {
    conn.release();
  }
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
async function main() {
  const startTime = Date.now();
  log('INFO', '===== cert watchtower WinRM scan run start =====');

  let creds;
  try {
    creds = loadWinrmCreds();
    log('INFO', `loaded WinRM creds (user=${creds.user.replace(/./g, '*')})`);
  } catch (err) {
    log('ERROR', 'failed to load WinRM creds', { error: err.message });
    process.exit(1);
  }

  let config;
  try {
    config = await loadConfig();
  } catch (err) {
    log('ERROR', 'failed to load config', { error: err.message });
    process.exit(1);
  }

  const thresholds = {
    info: Number(config.threshold_info_days) || 90,
    warning: Number(config.threshold_warning_days) || 60,
    critical: Number(config.threshold_critical_days) || 30
  };
  const concurrency = Math.max(1, Number(config.winrm_scan_concurrency) || 5);
  const timeoutS = Math.max(10, Number(config.winrm_scan_timeout_s) || 60);

  log('INFO', 'config', { thresholds, concurrency, timeoutS });

  // Fetch enabled targets
  let targets;
  try {
    const [rows] = await pool.query(
      `SELECT id, fqdn, target_host, winrm_port, winrm_transport,
              winrm_use_ssl, scan_stores, scan_iis, is_ca, ca_name
       FROM cert_agents
       WHERE enabled = 1
       ORDER BY id`
    );
    targets = rows;
  } catch (err) {
    log('ERROR', 'failed to load targets', { error: err.message });
    process.exit(1);
  }

  if (targets.length === 0) {
    log('INFO', 'no enabled scan targets — nothing to do');
  } else {
    log('INFO', `processing ${targets.length} target(s)`);

    const scanResults = await runWithConcurrency(targets, concurrency, async (target) => {
      const tStart = Date.now();
      log('INFO', `scanning ${target.fqdn}`);
      try {
        const result = await runHelper(target, creds, timeoutS);
        const applied = await applyResult(target.id, result, thresholds);
        log('INFO', `done ${target.fqdn}`, {
          duration_ms: Date.now() - tStart,
          ...applied
        });

        // CA issued cert scan (only for CA servers)
        if (target.is_ca && target.ca_name) {
          log('INFO', `CA scan ${target.fqdn} (${target.ca_name})`);
          try {
            const caResult = await runCaScan(target, creds);
            const caApplied = await applyCaScanResult(target.id, caResult, thresholds);
            log('INFO', `CA scan done ${target.fqdn}`, caApplied);
          } catch (caErr) {
            log('ERROR', `CA scan threw for ${target.fqdn}`, { error: caErr.message });
          }
        }

        return applied;
      } catch (err) {
        log('ERROR', `scan failed ${target.fqdn}`, {
          duration_ms: Date.now() - tStart,
          error: err.message
        });
        // Record the error on the agent row
        try {
          await pool.query(
            `UPDATE cert_agents SET
               last_checkin_at = NOW(),
               last_checkin_status = 'error',
               last_error = ?
             WHERE id = ?`,
            [err.message.slice(0, 1000), target.id]
          );
        } catch (_) {}
        throw err;
      }
    });

    let okCount = 0, errCount = 0, totalFindings = 0;
    for (const r of scanResults) {
      if (r.ok) {
        okCount++;
        totalFindings += (r.value.findings_processed || 0);
      } else {
        errCount++;
      }
    }
    log('INFO', 'scan phase complete', {
      ok: okCount,
      errors: errCount,
      total_findings: totalFindings
    });
  }

  // ---------------------------------------------------------------------------
  // Phase 2.5: PRTG push step. Runs unconditionally — internally checks
  // prtg_enabled and short-circuits if the integration is off. Never throws.
  // ---------------------------------------------------------------------------
  try {
    await runPrtgPushesForFindings(config);
  } catch (err) {
    log('ERROR', 'prtg finding push step threw unexpectedly', {
      error: err.message, stack: err.stack
    });
    // Intentionally do not propagate — PRTG failures must not break the scan.
  }

  // Step 8.5: agent (scan target) rollup push. Independent of finding push.
  try {
    await runPrtgPushesForAgents(config);
  } catch (err) {
    log('ERROR', 'prtg agent push step threw unexpectedly', {
      error: err.message, stack: err.stack
    });
  }

  const durationMs = Date.now() - startTime;
  log('INFO', `===== cert watchtower WinRM scan run end (${durationMs}ms) =====`);

  await pool.end();
  process.exit(0);
}

main().catch(err => {
  log('ERROR', 'unhandled error in main()', { error: err.message, stack: err.stack });
  process.exit(1);
});
