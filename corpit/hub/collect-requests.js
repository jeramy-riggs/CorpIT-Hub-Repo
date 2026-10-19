// collect-requests.js
// Pulls all ServiceDesk Plus requests via sdp-lookup.js's getAllRequests(),
// upserts them into sdops_request, and logs the run to sdops_collector_run.
// Run manually first: sudo -u ubuntu node /var/www/corpit-hub-api/collect-requests.js
// Later: scheduled via cron.

const mysql = require('mysql2/promise');
const sdp = require('./sdp-lookup');

async function getPool() {
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 5,
  });
}

async function upsertRequests(pool, rows) {
  if (!rows.length) return 0;

  const ids = rows.map(r => r.id);
  const [priorRows] = await pool.query(
    `SELECT id, status, reopen_count FROM sdops_request WHERE id IN (?)`,
    [ids]
  );
  const priorMap = new Map(priorRows.map(p => [p.id, p]));

  const statusLogEntries = [];

  const sql = `
    INSERT INTO sdops_request
      (id, sdp_internal_id, subject, requester, requester_email, technician, technician_email, priority, status,
       department, category, subcategory, mode, created_by_technician, created_by_name, site, site_id, created_at, due_by, last_updated_at, resolved_at, reopen_count, aging_days, overdue, collected_at)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      sdp_internal_id = VALUES(sdp_internal_id),
      subject = VALUES(subject),
      requester = VALUES(requester),
      requester_email = VALUES(requester_email),
      technician = VALUES(technician),
      technician_email = VALUES(technician_email),
      priority = VALUES(priority),
      status = VALUES(status),
      department = VALUES(department),
      category = VALUES(category),
      subcategory = VALUES(subcategory),
      mode = VALUES(mode),
      created_by_technician = VALUES(created_by_technician),
      created_by_name = VALUES(created_by_name),
      site = VALUES(site),
      site_id = VALUES(site_id),
      due_by = VALUES(due_by),
      last_updated_at = VALUES(last_updated_at),
      resolved_at = VALUES(resolved_at),
      reopen_count = VALUES(reopen_count),
      aging_days = VALUES(aging_days),
      overdue = VALUES(overdue),
      collected_at = NOW()
  `;

  const now = new Date();
  const CLOSED_STATES = ['Resolved', 'Closed'];

  const values = rows.map(r => {
    const agingDays = r.created_at
      ? Math.floor((now - r.created_at) / (1000 * 60 * 60 * 24))
      : null;
    const overdue = r.due_by ? (now > r.due_by ? 1 : 0) : 0;

    const prior = priorMap.get(r.id);
    let reopenCount = prior?.reopen_count || 0;

    if (prior && prior.status !== r.status) {
      statusLogEntries.push([r.id, prior.status, r.status, now]);
      if (CLOSED_STATES.includes(prior.status) && !CLOSED_STATES.includes(r.status)) {
        reopenCount += 1;
      }
    }

    return [
      r.id, r.sdp_internal_id || null, r.subject, r.requester, r.requester_email, r.technician, r.technician_email || null,
      r.priority, r.status, r.department, r.category, r.subcategory || null,
      r.mode || null, r.created_by_technician || 0, r.created_by_name || null, r.site || null, r.site_id || null,
      r.created_at, r.due_by, r.last_updated_at, r.resolved_at || null, reopenCount,
      agingDays, overdue, now
    ];
  });

  const [result] = await pool.query(sql, [values]);

  if (statusLogEntries.length) {
    await pool.query(
      `INSERT INTO sdops_request_status_log (request_id, old_status, new_status, changed_at) VALUES ?`,
      [statusLogEntries]
    );
  }

  return result.affectedRows;
}
async function logRun(pool, status, error, startedAt) {
  await pool.query(
    `INSERT INTO sdops_collector_run (module, started_at, finished_at, status, error) VALUES (?, ?, NOW(), ?, ?)`,
    ['requests', startedAt, status, error || null]
  );
}


// Direct SDP confirmation that a display_id is truly gone (merged/deleted).
// Returns true only if SDP explicitly reports it absent (empty list / 404-style).
async function confirmGoneInSdp(displayId) {
  try {
    const res = await sdp.getRequestByDisplayId
      ? await sdp.getRequestByDisplayId(displayId)
      : null;
    // If sdp-lookup exposes a helper, use it; otherwise treat unknown as NOT gone (safe).
    if (res === null) return null; // helper unavailable -> caller skips flagging
    return res.absent === true;
  } catch (e) {
    return null; // any error -> do NOT flag (safe)
  }
}

async function reconcileGone(pool, seenIds) {
  // Candidates: currently NOT gone, non-closed, within the 6-month window,
  // and NOT seen in this run's full pull.
  const [candidates] = await pool.query(
    `SELECT id FROM sdops_request
      WHERE (gone IS NULL OR gone = 0)
        AND status NOT IN ('Closed','Resolved','Canceled')
        AND created_at >= (NOW() - INTERVAL 6 MONTH)`
  );
  const missing = candidates.map(r => String(r.id)).filter(id => !seenIds.has(id));
  if (!missing.length) { console.log('[collect-requests] reconcile: 0 missing, nothing to check.'); return; }
  console.log(`[collect-requests] reconcile: ${missing.length} non-closed in-window ticket(s) absent from pull; confirming with SDP...`);

  let flagged = 0, skipped = 0;
  for (const displayId of missing) {
    const gone = await confirmGoneInSdp(displayId);
    if (gone === true) {
      await pool.query('UPDATE sdops_request SET gone = 1 WHERE id = ?', [displayId]);
      flagged += 1;
      console.log(`[collect-requests] reconcile: ${displayId} confirmed gone -> hidden.`);
    } else {
      skipped += 1; // null/false: unavailable or still present -> leave untouched (safe)
    }
  }
  console.log(`[collect-requests] reconcile: flagged ${flagged}, left ${skipped} untouched.`);
}

async function main() {
  const startedAt = new Date();
  const pool = await getPool();

  try {
    await pool.query("DELETE FROM sdops_request WHERE created_at < (NOW() - INTERVAL 6 MONTH)");
    let page = 1;
    let totalRows = 0;
    let hasMore = true;
    const seenIds = new Set();

    while (hasMore) {
      const { rows, hasMoreRows } = await sdp.getAllRequests({ page, rowCount: 100 });
      for (const r of rows) { if (r.id != null) seenIds.add(String(r.id)); }
      const affected = await upsertRequests(pool, rows);
      totalRows += rows.length;
      console.log(`[collect-requests] page ${page}: fetched ${rows.length}, upserted ${affected}`);
      hasMore = hasMoreRows;
      page += 1;

      if (page > 200) {
        console.warn('[collect-requests] hit safety cap of 200 pages, stopping.');
        break;
      }
    }

    // Reconcile: flag non-closed, in-window tickets that vanished from SDP
    // (merged or deleted). Confirmed individually before flagging.
    await reconcileGone(pool, seenIds);

    await logRun(pool, 'ok', null, startedAt);
    console.log(`[collect-requests] done. total requests processed: ${totalRows}`);
    process.exit(0);
  } catch (err) {
    console.error('[collect-requests] error:', err.message);
    await logRun(pool, 'error', err.message, startedAt).catch(() => {});
    process.exit(1);
  } finally {
    await pool.end().catch(() => {});
  }
}

main();
