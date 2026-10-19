#!/usr/bin/env node
// =============================================================================
// Cert Watchtower — Phase 3: Cron Checker
// File: /var/www/api/cert-watchtower-cron.js
//
// Run once per day by system cron. Walks every enabled monitor, performs
// a TLS handshake, records results, generates/resolves alerts based on
// threshold crossings, and prunes old check history.
//
// Reuses the cert-check helpers from cert-watchtower-routes.js so manual
// checks and cron checks behave identically (no logic drift).
//
// Phase 2.5 (May 2026): also pushes to PRTG sensors after alert reconciliation,
// gated by global enable + per-monitor opt-in. PRTG failures never abort the
// cron — they're logged and per-monitor status is recorded in cert_monitors.
//
// Exit codes:
//   0 = success (all monitors processed, even if individual checks failed)
//   1 = fatal error (DB unavailable, config missing, etc.)
//
// Usage:
//   node /var/www/api/cert-watchtower-cron.js
//
// Logging:
//   stdout/stderr captured by cron redirect to /var/log/cert-watchtower/cron.log
// =============================================================================

require('dotenv').config({ path: '/var/www/api/.env' });
const mysql = require('mysql2/promise');

// -----------------------------------------------------------------------------
// Concurrency limit. Keeps the box from opening hundreds of TCP sockets at once.
// 10 in flight is plenty fast for any realistic cert count.
// -----------------------------------------------------------------------------
const MAX_CONCURRENT_CHECKS = 10;

// PRTG push concurrency. Lower than checks because PRTG push is cheap but we
// want to be polite to the probe. 5 in flight is a sane default.
const MAX_CONCURRENT_PRTG_PUSHES = 5;

// Per-check timeout (ms). Same as routes default.
const CHECK_TIMEOUT_MS = 10000;

// -----------------------------------------------------------------------------
// Lightweight logging helper. Tags each line with a timestamp and level so
// the log file is grep-friendly.
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
// Pool — same env vars the API uses. Reads /var/www/api/.env via dotenv above.
// Small pool because this is a short-lived script.
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
// Pull the cert helpers from the routes module. This is the key bit that
// keeps cron and manual checks behaviorally identical.
// -----------------------------------------------------------------------------
const createRouter = require('./cert-watchtower-routes');

// The router factory has required an rbac module since 2026-05-08:
// cert-watchtower-routes.js line 32 runs `router.use(rbac.loadCurrentUser)` at
// construction time. This call site was never updated, so every scheduled run
// since 2026-05-08 06:00 died at module load with
//   TypeError: Cannot read properties of undefined (reading 'loadCurrentUser')
// and no public certificate has been checked since. This process only wants the
// pure helpers hanging off the router; it never serves HTTP, so the middleware
// can never legitimately run. Fail CLOSED if that assumption is ever violated --
// a no-op shim here would silently become an unauthenticated router.
const CRON_ONLY_RBAC = {
  loadCurrentUser(req, res, next) {
    next(new Error('cert-watchtower-cron: helper-only router must never serve HTTP'));
  },
  requirePage() {
    return function (req, res, next) {
      next(new Error('cert-watchtower-cron: helper-only router must never serve HTTP'));
    };
  }
};

const { performCertCheck, recordCheckResult, loadConfig } =
  createRouter(pool, CRON_ONLY_RBAC)._certHelpers;

// -----------------------------------------------------------------------------
// Phase 2.5: PRTG push helper (Phase 2.5). Pure function, no DB access of
// its own — the cron handles all DB reads/writes.
// -----------------------------------------------------------------------------
const { pushToPrtg } = require('./cert-watchtower-prtg-helper');

// -----------------------------------------------------------------------------
// Concurrency runner: process items with a max-N-in-flight worker pool.
// Returns when all are done. Errors per-item are caught and logged; one
// bad monitor never blocks others (requirement N4).
// -----------------------------------------------------------------------------
async function runWithConcurrency(items, limit, worker) {
  const results = [];
  let nextIdx = 0;
  async function lane() {
    while (true) {
      const idx = nextIdx++;
      if (idx >= items.length) return;
      try {
        results[idx] = { ok: true, value: await worker(items[idx]) };
      } catch (err) {
        results[idx] = { ok: false, error: err.message, item: items[idx] };
      }
    }
  }
  const lanes = Array(Math.min(limit, items.length)).fill(0).map(() => lane());
  await Promise.all(lanes);
  return results;
}

// -----------------------------------------------------------------------------
// Alert generation logic.
//
// Rules:
//  - For each monitor's current status, compute the "expected severity":
//      ok          -> no alert
//      info        -> info
//      warning     -> warning
//      critical    -> critical
//      expired     -> expired
//      unreachable -> unreachable, BUT only if unreachable_since is >= N days ago
//                     (configurable via unreachable_alert_days)
//      error       -> no alert (transient/unknown — surfaces in dashboard only)
//
//  - If there's no active alert at expected severity, OPEN one (insert row).
//  - If there IS an active alert AT a different severity, RESOLVE the old
//    one and OPEN a new one at the new severity (so history shows the
//    progression: info → warning → critical).
//  - If status returned to ok, RESOLVE all active alerts for the monitor.
//
//  - Dedup: never open two alerts at the same severity for the same monitor
//           while the old one is still active.
// -----------------------------------------------------------------------------
// The alert ladder has THREE outcomes, not two. `null` means MEASURED and
// healthy (resolve open alerts). UNKNOWN means this run COULD NOT MEASURE the
// monitor at all — a failed handshake, or an 'error' row. An unmeasured run is
// not evidence that the problem went away, so it must never resolve an alert a
// SUCCESSFUL check opened. Hold, open nothing, stay quiet.
const UNKNOWN = 'unknown';

function expectedSeverity(currentStatus, unreachableSince, unreachableAlertDays) {
  if (currentStatus === 'ok') return null;
  // Could-not-measure statuses. 'error' is always unmeasured. 'unreachable' is
  // unmeasured too, and only becomes a real alert once it has persisted past
  // unreachable_alert_days; inside that window it is UNKNOWN, not "healthy".
  if (currentStatus === 'error') return UNKNOWN;
  if (currentStatus === 'unreachable') {
    if (!unreachableSince) return UNKNOWN;
    const ageMs = Date.now() - new Date(unreachableSince).getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    return ageDays >= unreachableAlertDays ? 'unreachable' : UNKNOWN;
  }
  // info / warning / critical / expired all map to themselves
  return currentStatus;
}

async function reconcileAlerts(monitorId, currentRow, config) {
  const expected = expectedSeverity(
    currentRow.status,
    currentRow.unreachable_since,
    Number(config.unreachable_alert_days) || 2
  );

  // Fetch active (unresolved) alerts for this monitor
  const [activeAlerts] = await pool.query(
    `SELECT id, severity FROM cert_alerts
     WHERE monitor_id = ? AND resolved_at IS NULL`,
    [monitorId]
  );

  // Could not measure this monitor on this run. An alert may only be RESOLVED
  // by a SUCCESSFUL check that observes the condition cleared — never by an
  // error path. Hold whatever is open and open nothing new.
  if (expected === UNKNOWN) {
    if (activeAlerts.length > 0) {
      log('INFO', `check could not measure — holding ${activeAlerts.length} active alert(s)`, {
        monitor_id: monitorId, status: currentRow.status
      });
    }
    return;
  }

  if (expected === null) {
    // Resolve all active alerts (cert measured healthy on this run)
    if (activeAlerts.length > 0) {
      await pool.query(
        `UPDATE cert_alerts SET resolved_at = NOW()
         WHERE monitor_id = ? AND resolved_at IS NULL`,
        [monitorId]
      );
      log('INFO', `resolved ${activeAlerts.length} alert(s)`, { monitor_id: monitorId });
    }
    return;
  }

  // We expect an alert at `expected` severity.
  const matching = activeAlerts.find(a => a.severity === expected);
  if (matching) {
    // Already have an active alert at this severity — nothing to do (dedup).
    return;
  }

  // Resolve any active alerts at OTHER severities (status changed)
  if (activeAlerts.length > 0) {
    await pool.query(
      `UPDATE cert_alerts SET resolved_at = NOW()
       WHERE monitor_id = ? AND resolved_at IS NULL`,
      [monitorId]
    );
  }

  // Open a new alert at the expected severity
  const message = buildAlertMessage(expected, currentRow);
  await pool.query(
    `INSERT INTO cert_alerts
      (monitor_id, severity, days_remaining, not_after, subject_cn, message)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      monitorId, expected,
      currentRow.days_remaining ?? null,
      currentRow.not_after || null,
      currentRow.subject_cn || null,
      message
    ]
  );
  log('INFO', `opened ${expected} alert`, { monitor_id: monitorId, message });
}

function buildAlertMessage(severity, row) {
  if (severity === 'expired') {
    return `Certificate EXPIRED (${Math.abs(row.days_remaining)} days ago)`;
  }
  if (severity === 'unreachable') {
    return `Host unreachable since ${row.unreachable_since}`;
  }
  return `Certificate expires in ${row.days_remaining} day(s)`;
}

// =============================================================================
// PRTG push (Phase 2.5)
// =============================================================================

// Status enum -> integer mapping for the "Cert Status" PRTG channel.
// Pair this mapping with cert-status-lookup.ovl in PRTG so dashboards
// display human labels (e.g. "Critical") instead of raw integers.
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

// Build the 4 channels for a per-cert PRTG push. PRTG channel definitions
// (units, thresholds, lookups) are configured ONCE on the sensor template
// in PRTG; we only push values here.
function buildCertChannels(row) {
  const days = Number.isFinite(Number(row.days_remaining))
    ? Number(row.days_remaining) : 0;
  const handshakeMs = Number.isFinite(Number(row.handshake_ms))
    ? Number(row.handshake_ms) : 0;

  // Days Since Issue: derive from not_before if available, else 0
  let daysSinceIssue = 0;
  if (row.not_before) {
    const issued = new Date(row.not_before).getTime();
    if (!Number.isNaN(issued)) {
      daysSinceIssue = Math.max(0, Math.floor((Date.now() - issued) / 86400000));
    }
  }

  return [
    { name: 'Days Until Expiry',  value: days },
    { name: 'Cert Status',        value: statusToInt(row.status) },
    { name: 'Handshake Time',     value: handshakeMs, unit: 'TimeResponse' },
    { name: 'Days Since Issue',   value: daysSinceIssue }
  ];
}

// Build the human-readable PRTG sensor status text per Q3:
//   "<subject_cn> — <N> days remaining — status: <state>"
function buildCertStatusText(row) {
  const cn = row.subject_cn || row.hostname || 'unknown';
  const dr = (row.days_remaining === null || row.days_remaining === undefined)
    ? '?' : String(row.days_remaining);
  const st = row.status || 'unknown';
  return `${cn} — ${dr} days remaining — status: ${st}`;
}

// Push channels for a single monitor with retry. Returns the helper's
// structured result (always — never throws).
async function pushOneMonitor(prtgConn, row, retryCount) {
  const channels = buildCertChannels(row);
  const statusText = buildCertStatusText(row);

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

// Map helper result.error -> short status code for cert_monitors.prtg_last_push_status
function classifyPushStatus(result) {
  if (result.ok) return 'ok';
  if (!result.error) return 'error';
  if (result.error.startsWith('validation:'))      return 'validation';
  if (result.error.startsWith('timeout:'))         return 'timeout';
  if (result.error.startsWith('sensor-mismatch:')) return 'mismatch';
  if (result.error.startsWith('http:'))            return 'error';
  return 'error';
}

// Persist the per-monitor push outcome. Best-effort — DB failure here is
// logged but does not propagate.
async function recordPushOutcome(monitorId, result) {
  const status = classifyPushStatus(result);
  const responseSnippet = (result.body || result.error || '').toString().slice(0, 1000);
  try {
    await pool.query(
      `UPDATE cert_monitors
         SET prtg_last_push_at       = NOW(),
             prtg_last_push_status   = ?,
             prtg_last_push_response = ?
       WHERE id = ?`,
      [status, responseSnippet, monitorId]
    );
  } catch (err) {
    log('ERROR', 'failed to record prtg push outcome', {
      monitor_id: monitorId, error: err.message
    });
  }
}

// Build the 5 channels for the fleet summary sensor.
function buildSummaryChannels(stats) {
  return [
    { name: 'Total Certs Watched',  value: stats.total },
    { name: 'Expiring < 30 days',   value: stats.expiring30 },
    { name: 'Expiring < 7 days',    value: stats.expiring7 },
    { name: 'Expired',              value: stats.expired },
    { name: 'Unreachable',          value: stats.unreachable }
  ];
}

// Run all PRTG pushes for this cron tick. Reads config + per-monitor PRTG
// settings, walks every push-eligible monitor concurrently, then optionally
// pushes the fleet summary sensor. Never throws.
async function runPrtgPushes(config) {
  if (config.prtg_enabled !== '1') {
    log('INFO', 'prtg push skipped — disabled in cert_config');
    return;
  }

  // Connection settings shared across all pushes
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

  // Fetch all push-eligible monitors with the data needed for the 4 channels.
  // JOINs cert_current and cert_checks (last_check_id) for handshake_ms +
  // not_before. WHERE filters: enabled monitor, push-enabled, has token.
  let pushRows;
  try {
    const [rows] = await pool.query(
      `SELECT m.id, m.hostname, m.prtg_token,
              c.status, c.days_remaining, c.subject_cn, c.not_after,
              ch.handshake_ms, ch.not_before
         FROM cert_monitors m
         JOIN cert_current  c  ON c.monitor_id = m.id
         LEFT JOIN cert_checks ch ON ch.id = c.last_check_id
        WHERE m.enabled = 1
          AND m.prtg_push_enabled = 1
          AND m.prtg_token IS NOT NULL
          AND m.prtg_token <> ''`
    );
    pushRows = rows;
  } catch (err) {
    log('ERROR', 'failed to load prtg push rows', { error: err.message });
    return;
  }

  log('INFO', `prtg push phase start`, {
    eligible: pushRows.length,
    host: prtgConn.host, port: prtgConn.port, protocol: prtgConn.protocol
  });

  // Run pushes with concurrency cap. Each result is recorded individually.
  let okCount = 0, failCount = 0;
  if (pushRows.length > 0) {
    const results = await runWithConcurrency(
      pushRows, MAX_CONCURRENT_PRTG_PUSHES,
      async (row) => {
        const result = await pushOneMonitor(prtgConn, row, retries);
        await recordPushOutcome(row.id, result);
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
        log('ERROR', 'prtg push failed', { monitor_id: id, error: err });
      }
    }
  }
  log('INFO', 'prtg push phase complete', { ok: okCount, fail: failCount });

  // ---------------------------------------------------------------------------
  // Summary sensor (optional — only if token configured)
  // ---------------------------------------------------------------------------
  const summaryToken = (config.prtg_summary_sensor_token || '').trim();
  if (!summaryToken) {
    log('INFO', 'prtg summary push skipped — no summary sensor token');
    return;
  }

  let stats;
  try {
    const [[s]] = await pool.query(
      `SELECT
         (SELECT COUNT(*) FROM cert_monitors WHERE enabled=1)                  AS total,
         (SELECT COUNT(*) FROM cert_current c JOIN cert_monitors m ON m.id=c.monitor_id
            WHERE m.enabled=1 AND c.days_remaining IS NOT NULL
              AND c.days_remaining BETWEEN 0 AND 30)                           AS expiring30,
         (SELECT COUNT(*) FROM cert_current c JOIN cert_monitors m ON m.id=c.monitor_id
            WHERE m.enabled=1 AND c.days_remaining IS NOT NULL
              AND c.days_remaining BETWEEN 0 AND 7)                            AS expiring7,
         (SELECT COUNT(*) FROM cert_current c JOIN cert_monitors m ON m.id=c.monitor_id
            WHERE m.enabled=1 AND c.status='expired')                          AS expired,
         (SELECT COUNT(*) FROM cert_current c JOIN cert_monitors m ON m.id=c.monitor_id
            WHERE m.enabled=1 AND c.status='unreachable')                      AS unreachable
      `
    );
    stats = {
      total:       Number(s.total) || 0,
      expiring30:  Number(s.expiring30) || 0,
      expiring7:   Number(s.expiring7) || 0,
      expired:     Number(s.expired) || 0,
      unreachable: Number(s.unreachable) || 0
    };
  } catch (err) {
    log('ERROR', 'failed to compute summary stats', { error: err.message });
    return;
  }

  const summaryText = `Fleet: ${stats.total} watched · ${stats.expiring30} <30d · ${stats.expiring7} <7d · ${stats.expired} expired · ${stats.unreachable} unreachable`;
  let summaryResult = null;
  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    summaryResult = await pushToPrtg({
      host: prtgConn.host,
      port: prtgConn.port,
      protocol: prtgConn.protocol,
      verifyTls: prtgConn.verifyTls,
      timeoutMs: prtgConn.timeoutMs,
      token: summaryToken,
      channels: buildSummaryChannels(stats),
      statusText: summaryText
    });
    if (summaryResult.ok) break;
    if (summaryResult.error && (
      summaryResult.error.startsWith('validation:') ||
      summaryResult.error.startsWith('sensor-mismatch:')
    )) break;
  }
  if (summaryResult && summaryResult.ok) {
    log('INFO', 'prtg summary pushed', { stats });
  } else {
    log('ERROR', 'prtg summary push failed', {
      error: summaryResult ? summaryResult.error : 'unknown'
    });
  }
}

// -----------------------------------------------------------------------------
// Prune old cert_checks rows. Configurable retention (default 365d).
// Done in batches to avoid long-running locks on a big table.
// -----------------------------------------------------------------------------
async function pruneHistory(retentionDays) {
  const days = Number(retentionDays) || 365;
  let totalDeleted = 0;
  // Delete in chunks of 5000 to keep transactions short.
  while (true) {
    const [result] = await pool.query(
      `DELETE FROM cert_checks
       WHERE checked_at < DATE_SUB(NOW(), INTERVAL ? DAY)
       LIMIT 5000`,
      [days]
    );
    totalDeleted += result.affectedRows;
    if (result.affectedRows < 5000) break;
  }
  if (totalDeleted > 0) {
    log('INFO', `pruned old check history`, { deleted_rows: totalDeleted, retention_days: days });
  }
  return totalDeleted;
}

// -----------------------------------------------------------------------------
// Main run
// -----------------------------------------------------------------------------
async function main() {
  const startTime = Date.now();
  log('INFO', '===== cert watchtower cron run start =====');

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
  log('INFO', 'thresholds loaded', thresholds);

  // Fetch enabled monitors
  let monitors;
  try {
    const [rows] = await pool.query(
      `SELECT id, hostname, port, servername_sni
       FROM cert_monitors
       WHERE enabled = 1
       ORDER BY id`
    );
    monitors = rows;
  } catch (err) {
    log('ERROR', 'failed to load monitors', { error: err.message });
    process.exit(1);
  }
  log('INFO', `processing ${monitors.length} enabled monitor(s)`);

  if (monitors.length === 0) {
    log('INFO', 'no enabled monitors — nothing to check');
  } else {
    // Run TLS handshakes with concurrency cap
    const checkResults = await runWithConcurrency(monitors, MAX_CONCURRENT_CHECKS, async (m) => {
      const result = await performCertCheck(m.hostname, m.port, m.servername_sni, CHECK_TIMEOUT_MS);
      const recorded = await recordCheckResult(m.id, result, thresholds);
      return { monitor: m, result, recorded };
    });

    // Summary
    let okCount = 0, alertCount = 0, errCount = 0;
    for (const r of checkResults) {
      if (!r.ok) {
        errCount++;
        log('ERROR', 'monitor check threw', { item: r.item, error: r.error });
        continue;
      }
      const st = r.value.recorded.status;
      if (st === 'ok') okCount++;
      else alertCount++;
    }
    log('INFO', 'check phase complete', { ok: okCount, alerting: alertCount, errors: errCount });

    // Reconcile alerts for every monitor (must read fresh cert_current rows)
    const [currentRows] = await pool.query(
      `SELECT c.monitor_id, c.status, c.days_remaining, c.not_after,
              c.subject_cn, c.unreachable_since
       FROM cert_current c
       JOIN cert_monitors m ON m.id = c.monitor_id
       WHERE m.enabled = 1`
    );
    for (const row of currentRows) {
      try {
        await reconcileAlerts(row.monitor_id, row, config);
      } catch (err) {
        log('ERROR', 'alert reconcile failed', { monitor_id: row.monitor_id, error: err.message });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Phase 2.5: PRTG push step. Runs unconditionally — internally checks
  // prtg_enabled and short-circuits if the integration is off. Never throws.
  // ---------------------------------------------------------------------------
  try {
    await runPrtgPushes(config);
  } catch (err) {
    log('ERROR', 'prtg push step threw unexpectedly', {
      error: err.message, stack: err.stack
    });
    // Intentionally do not propagate — PRTG failures must not break the cron.
  }

  // Prune
  try {
    await pruneHistory(config.history_retention_days);
  } catch (err) {
    log('ERROR', 'history prune failed', { error: err.message });
    // Don't exit non-zero — pruning failure is not fatal
  }

  const durationMs = Date.now() - startTime;
  log('INFO', `===== cert watchtower cron run end (${durationMs}ms) =====`);

  // Clean shutdown
  await pool.end();
  process.exit(0);
}

// -----------------------------------------------------------------------------
// Top-level error handling. Anything that escapes main() should still exit
// non-zero so cron sends the failure email (if configured).
// -----------------------------------------------------------------------------
main().catch(err => {
  log('ERROR', 'unhandled error in main()', { error: err.message, stack: err.stack });
  process.exit(1);
});
