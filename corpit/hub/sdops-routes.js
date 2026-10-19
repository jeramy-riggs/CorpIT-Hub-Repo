// sdops-routes.js
// API routes for the Service Desk Ops Portal — Requests module.
// Reads from sdops_request / sdops_collector_run (populated by collect-requests.js).
// RBAC page key: service-desk-portal

const express = require('express');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const router = express.Router();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});

const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

const PAGE_KEY = 'service-desk-portal';

// Vonage call-report importer. The script only ever lived at /home/ubuntu on
// ITAM and is not deployed here; the route says so (501) and the page hides
// its Import button, instead of accepting an upload and failing afterwards.
const IMPORT_CALLS_SCRIPT = process.env.SDOPS_IMPORT_CALLS_SCRIPT || require('path').join(__dirname, 'import-calls.py');
function importCallsAvailable() { try { return require('fs').existsSync(IMPORT_CALLS_SCRIPT); } catch (e) { return false; } }
router.get('/calls/import/status', rbac.requirePage(PAGE_KEY, 'read'), (req, res) => res.json({ available: importCallsAvailable() }));

// ---- Feed freshness --------------------------------------------------------
// A count over a window is only a measurement if the window was actually
// observed. These two fields let a caller tell "nothing happened" from
// "nothing was collected"; a caller that gets anything other than 'ok' must
// not present its window-scoped counts as measurements.
//
// Evidence, in order of preference:
//   1. a sdops_collector_run row for the module that fills the table. This is
//      the only evidence that survives a legitimately empty table -- an empty
//      table is not proof that collection failed, and MAX(timestamp) cannot
//      tell those apart.
//   2. MAX(<timestamp column>) on the table itself, for the feeds whose
//      writers leave no run row (the Vonage call import, the Entra/Okta
//      syncs). For these, an empty table really is indistinguishable from a
//      dead loader, so it reports 'unknown' rather than guessing.
// A feed with neither is 'unknown'. Nothing here ever reports 'ok' by default.
//
// Table and column names come from this literal map only; nothing here is
// built from request input.
const FEEDS = {
  requests: { module: 'requests',        maxAgeMin: 30 },
  adAuth:   { module: 'ad_auth_events',  maxAgeMin: 180 },
  calls:    { table: 'sdops_call',           col: 'collected_at',   maxAgeMin: 1440 },
  email:    { table: 'sdops_email_activity', col: 'collected_at',   maxAgeMin: 180 },
  entra:    { table: 'entra_users',          col: 'last_synced_at', maxAgeMin: 1440 },
  okta:     { table: 'okta_users',           col: 'last_synced_at', maxAgeMin: 1440 },
  // collect-lockout-state.js leaves no collector_run row; its last-run stamps
  // live in sdops_lockout_state_meta. Without this the lockouts strip reported
  // the AD auth feed's freshness and called a frozen lockout feed current.
  lockoutState: { sql: "SELECT MAX(key_value) AS at FROM sdops_lockout_state_meta WHERE key_name IN ('ad_last_run_at','okta_last_run_at')", maxAgeMin: 120 },
};
const RUNG_ORDER = { ok: 0, stale: 1, failed: 2, unknown: 3 };

// A feed assembled from several sources is only as fresh as its worst source.
async function feedFreshness(names) {
  let best = null;
  for (const name of names) {
    const spec = FEEDS[name];
    if (!spec) continue;
    let at = null;
    let status = 'unknown';
    try {
      if (spec.module) {
        const [[run]] = await pool.query(
          'SELECT status, finished_at FROM sdops_collector_run WHERE module = ? ORDER BY id DESC LIMIT 1',
          [spec.module]
        );
        if (run && run.finished_at) {
          at = run.finished_at;
          status = run.status !== 'ok'
            ? 'failed'
            : ((Date.now() - new Date(run.finished_at).getTime()) > spec.maxAgeMin * 60000 ? 'stale' : 'ok');
        }
      } else if (spec.sql) {
        const [[row]] = await pool.query(spec.sql);
        if (row && row.at) {
          at = row.at;
          status = (Date.now() - new Date(row.at).getTime()) > spec.maxAgeMin * 60000 ? 'stale' : 'ok';
        }
      } else {
        const [[row]] = await pool.query(
          'SELECT MAX(`' + spec.col + '`) AS at FROM `' + spec.table + '`'
        );
        if (row && row.at) {
          at = row.at;
          status = (Date.now() - new Date(row.at).getTime()) > spec.maxAgeMin * 60000 ? 'stale' : 'ok';
        }
      }
    } catch (e) {
      console.error('[sdops] freshness probe failed for %s: %s', name, e.message);
      at = null;
      status = 'unknown';
    }
    const cand = { collectedAt: at, collectorStatus: status };
    if (!best) { best = cand; continue; }
    const worseRung = RUNG_ORDER[cand.collectorStatus] > RUNG_ORDER[best.collectorStatus];
    const sameRungOlder = cand.collectorStatus === best.collectorStatus &&
      cand.collectedAt && best.collectedAt &&
      new Date(cand.collectedAt).getTime() < new Date(best.collectedAt).getTime();
    if (worseRung || sameRungOlder) best = cand;
  }
  if (!best) return { collectedAt: null, collectorStatus: 'unknown' };
  return {
    collectedAt: best.collectedAt ? new Date(best.collectedAt).toISOString() : null,
    collectorStatus: best.collectorStatus,
  };
}

const SORT_COLUMNS = {
  agingDays: 'aging_days',
  createdAt: 'created_at',
  dueBy: 'due_by',
  priority: 'priority',
  status: 'status',
};

function parseSort(sortParam) {
  if (!sortParam) return 'created_at DESC';
  const desc = sortParam.startsWith('-');
  const key = desc ? sortParam.slice(1) : sortParam;
  const col = SORT_COLUMNS[key] || 'created_at';
  return `${col} ${desc ? 'DESC' : 'ASC'}`;
}

router.get('/requests/summary', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [[counts]] = await pool.query(`
      SELECT
        SUM(DATE(CONVERT_TZ(created_at,'+00:00','-07:00')) = DATE(CONVERT_TZ(UTC_TIMESTAMP(),'+00:00','-07:00'))) AS createdToday,
        SUM(DATE(CONVERT_TZ(created_at,'+00:00','-07:00')) = DATE(CONVERT_TZ(UTC_TIMESTAMP(),'+00:00','-07:00')) AND created_by_technician = 1) AS createdByTechnicianToday,
        SUM(DATE(CONVERT_TZ(created_at,'+00:00','-07:00')) >= (DATE(CONVERT_TZ(UTC_TIMESTAMP(),'+00:00','-07:00')) - INTERVAL 6 DAY)) AS createdThisWeek,
        SUM(status NOT IN ('Resolved', 'Closed', 'Canceled')) AS open,
        -- Open tickets with nobody holding them. Additive: existing consumers of
        -- this endpoint are unaffected. The predicate is copied verbatim from
        -- /requests/mine's unassignedCount (technician_email IS NULL) ON PURPOSE:
        -- two endpoints in one API reporting different 'unassigned' numbers is a
        -- bug the moment the display-name column and the email column disagree.
        -- Verified equal on live data 2026-09-08 (3 = 3); tied together so they
        -- stay equal. Change both or neither.
        SUM(status NOT IN ('Resolved', 'Closed', 'Canceled')
            AND technician_email IS NULL) AS unassigned,
        SUM(overdue = 1) AS overdue,
        SUM(overdue = 1 AND status NOT IN ('Resolved','Closed','Canceled')) AS openOverdue,
        SUM(overdue = 1 AND status IN ('Resolved','Closed') AND DATE(resolved_at) = CURDATE()) AS closedTodayOverdue,
        SUM(status IN ('Resolved','Closed') AND resolved_at >= '2026-07-17') AS resolvedSinceTracking,
        SUM(status IN ('Resolved','Closed') AND resolved_at >= '2026-07-17' AND reopen_count = 0) AS resolvedNoReopenSinceTracking
      FROM sdops_request
      WHERE gone = 0
    `);

    const [byTech] = await pool.query(`
      SELECT technician,
        SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week,
        SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month,
        COUNT(*) AS total
      FROM sdops_request
      WHERE gone = 0 AND technician IS NOT NULL AND technician != 'Unassigned'
        AND technician NOT IN ('Heather Graham', 'Jeniffer Doe', 'Shawn Adams')
      GROUP BY technician
      ORDER BY total DESC
      LIMIT 10
    `);

    const [[lastRun]] = await pool.query(`
      SELECT status, finished_at FROM sdops_collector_run
      WHERE module = 'requests' ORDER BY id DESC LIMIT 1
    `);

    const stale = !lastRun || lastRun.status !== 'ok' ||
      (Date.now() - new Date(lastRun.finished_at).getTime()) > 2 * 15 * 60 * 1000;

    // Freshness the page can actually render, with an explicit unknown rung.
    const collectedAt = lastRun && lastRun.finished_at
      ? new Date(lastRun.finished_at).toISOString()
      : null;
    const collectorStatus = !lastRun
      ? 'unknown'
      : (lastRun.status !== 'ok' ? 'failed' : (stale ? 'stale' : 'ok'));

    const openTotal = counts.open || 0;
    const openOverdueCount = counts.openOverdue || 0;
    const openNotOverdue = Math.max(0, openTotal - openOverdueCount);
    const slaScore = openTotal > 0 ? (openNotOverdue / openTotal) * 100 : 100;

    const createdThisWeekCount = counts.createdThisWeek || 0;
    const backlogRatio = createdThisWeekCount > 0 ? (openTotal / createdThisWeekCount) * 10 : 0;
    const backlogScore = Math.max(0, 100 - Math.min(100, backlogRatio));

    const reopenPct = counts.resolvedSinceTracking ? (1 - counts.resolvedNoReopenSinceTracking / counts.resolvedSinceTracking) * 100 : 0;
    const reopenScore = Math.max(0, 100 - reopenPct);

    const healthScore = counts.resolvedSinceTracking
      ? Math.round(0.40 * slaScore + 0.30 * backlogScore + 0.30 * reopenScore)
      : Math.round(0.60 * slaScore + 0.40 * backlogScore); // reopen data still cold-starting

    res.json({
      createdToday: counts.createdToday || 0,
      createdThisWeek: counts.createdThisWeek || 0,
      createdByTechnicianToday: counts.createdByTechnicianToday || 0,
      open: counts.open || 0,
      unassigned: counts.unassigned || 0,
      overdue: counts.overdue || 0,
      openOverdue: counts.openOverdue || 0,
      closedTodayOverdue: counts.closedTodayOverdue || 0,
      resolvedSinceTracking: counts.resolvedSinceTracking || 0,
      resolvedNoReopenSinceTracking: counts.resolvedNoReopenSinceTracking || 0,
      reopenRatePct: counts.resolvedSinceTracking ? Math.round(1000 * (1 - counts.resolvedNoReopenSinceTracking / counts.resolvedSinceTracking)) / 10 : null,
      healthScore,
      healthScoreComponents: {
        slaScore: Math.round(slaScore * 10) / 10,
        backlogScore: Math.round(backlogScore * 10) / 10,
        reopenScore: counts.resolvedSinceTracking ? Math.round(reopenScore * 10) / 10 : null
      },
      closedByTechnician: byTech,
      generatedAt: new Date().toISOString(),
      source: 'servicedesk-plus',
      stale,
      collectedAt,
      collectorStatus,
    });
  } catch (err) {
    console.error('[sdops] requests/summary error:', err.message);
    res.status(500).json({ error: 'Failed to load summary', detail: err.message });
  }
});

// ── GET /api/sdops/requests/mine ──────────────────────────────────────────
// The signed-in technician's own open queue.
//
// SECURITY: this endpoint takes NO parameters. The identity comes from
// req.user.email, which rbac-middleware only sets after verifying the Azure
// id_token against the tenant JWKS (signature, issuer, audience, expiry). The
// browser cannot express "whose queue" — there is no input to tamper with, so
// the only way to receive a different queue is to hold a different valid token.
//
// The match is email-to-email against technician_email, written from Service
// Desk's own technician.email_id and lowercased at both write and read time.
// Display names are NEVER used at query time: two staff can share a name, and
// that is exactly how one person's queue would leak to another.
//
// No page permission is required beyond authenticated-and-active. The result is
// self-scoped by construction, and a technician may own tickets without holding
// a grant on the Service Desk portal page.
router.get('/requests/mine', async (req, res) => {
  if (!req.user || !req.user.email) {
    return res.status(401).json({ error: 'AUTH_REQUIRED' });
  }
  const email = String(req.user.email).trim().toLowerCase();
  const OPEN = "gone = 0 AND status NOT IN ('Resolved','Closed','Canceled')";
  // Service Desk priority is two vocabularies fused by an import (9 values).
  // Collapse to 3 tiers HERE so the mapping is auditable in one place.
  // 'Normal' is SDP's untriaged default — if it were amber, most of the band
  // would be amber and colour would stop meaning anything.
  const SEVERITY = `CASE WHEN priority IN ('High','Major') THEN 3
                         WHEN priority = 'Medium'          THEN 2
                         ELSE 1 END`;
  try {
    const [rows] = await pool.query(
      `SELECT id, subject, requester, department, status, priority,
              created_at, due_by, last_updated_at, aging_days, overdue, site,
              ${SEVERITY} AS severity_rank
         FROM sdops_request
        WHERE technician_email = ? AND ${OPEN}
        ORDER BY overdue DESC, severity_rank DESC, aging_days DESC
        LIMIT 25`, [email]);

    // Total is its own COUNT so "+N more" stays truthful past the LIMIT.
    const [[tot]] = await pool.query(
      `SELECT COUNT(*) AS openCount, SUM(overdue = 1) AS overdueCount,
              MAX(aging_days) AS oldestDays
         FROM sdops_request WHERE technician_email = ? AND ${OPEN}`, [email]);

    // Distinguishes "nothing assigned" from "not a technician at all" — the
    // latter renders no band rather than a permanent empty box.
    const [[known]] = await pool.query(
      `SELECT COUNT(*) AS n FROM sdops_request WHERE technician_email = ? LIMIT 1`, [email]);

    const [[unassigned]] = await pool.query(
      `SELECT COUNT(*) AS n FROM sdops_request
        WHERE technician_email IS NULL AND ${OPEN}`);

    const [[fresh]] = await pool.query(
      `SELECT MAX(collected_at) AS generatedAt FROM sdops_request`);

    const portal = process.env.SDP_PORTAL || '';
    const sev = r => (r.severity_rank === 3 ? 'high' : r.severity_rank === 2 ? 'medium' : 'baseline');

    res.json({
      isTechnician:    Number(known.n || 0) > 0,
      openCount:       Number(tot.openCount || 0),
      overdueCount:    Number(tot.overdueCount || 0),
      oldestDays:      tot.oldestDays == null ? null : Number(tot.oldestDays),
      unassignedCount: Number(unassigned.n || 0),
      generatedAt:     fresh.generatedAt || null,
      tickets: rows.map(r => ({
        id:        r.id,
        subject:   r.subject,
        requester: r.requester,
        status:    r.status,
        severity:  sev(r),
        priorityRaw: r.priority,
        ageDays:   r.aging_days == null ? null : Number(r.aging_days),
        overdue:   r.overdue === 1,
        // built server-side so the portal slug never reaches the HTML
        url: portal
          ? `https://sdpondemand.manageengine.com/app/${portal}/WorkOrder.do?woMode=viewWO&woID=${encodeURIComponent(r.id)}`
          : null,
      })),
    });
  } catch (err) {
    console.error('[sdops/requests/mine]', err.message);
    res.status(500).json({ error: 'queue query failed' });
  }
});

router.get('/requests', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(10000, Math.max(1, parseInt(req.query.pageSize, 10) || 25));
    const offset = (page - 1) * pageSize;
    const sort = parseSort(req.query.sort);

    const where = ['gone = 0'];
    const params = [];

    if (req.query.status) {
      where.push('status = ?');
      params.push(req.query.status);
    } else if (req.query.includeClosed !== '1') {
      // Default: active requests, plus today's closed SLA-missed rows so the
      // 'Closed Today - SLA Missed' KPI tile can filter to them client-side.
      where.push("(status NOT IN ('Closed','Resolved','Canceled') OR (overdue = 1 AND status IN ('Resolved','Closed') AND DATE(last_updated_at) = CURDATE()))");
    }
    if (req.query.search) {
      where.push('(subject LIKE ? OR requester LIKE ? OR id LIKE ?)');
      const like = `%${req.query.search}%`;
      params.push(like, like, like);
    }

    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM sdops_request ${whereClause}`,
      params
    );

    const [rows] = await pool.query(
      `SELECT id, sdp_internal_id AS sdpInternalId, subject, requester, technician, priority, status, category, subcategory, mode, created_by_technician AS createdByTechnician,
              department, created_at AS createdAt, due_by AS dueBy,
              aging_days AS agingDays, overdue, last_updated_at AS lastUpdatedAt
       FROM sdops_request ${whereClause}
       ORDER BY ${sort}
       LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );

    const rowsWithLinks = rows.map(r => ({
      ...r,
      sdpUrl: r.sdpInternalId
        ? `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${r.sdpInternalId}`
        : null
    }));

    const [[lastRun]] = await pool.query(`
      SELECT status, finished_at FROM sdops_collector_run
      WHERE module = 'requests' ORDER BY id DESC LIMIT 1
    `);
    const stale = !lastRun || lastRun.status !== 'ok' ||
      (Date.now() - new Date(lastRun.finished_at).getTime()) > 2 * 15 * 60 * 1000;

    // Freshness the page can actually render, with an explicit unknown rung.
    const collectedAt = lastRun && lastRun.finished_at
      ? new Date(lastRun.finished_at).toISOString()
      : null;
    const collectorStatus = !lastRun
      ? 'unknown'
      : (lastRun.status !== 'ok' ? 'failed' : (stale ? 'stale' : 'ok'));

    res.json({
      data: rowsWithLinks,
      page,
      pageSize,
      total,
      generatedAt: new Date().toISOString(),
      source: 'servicedesk-plus',
      stale,
      collectedAt,
      collectorStatus,
    });
  } catch (err) {
    console.error('[sdops] requests error:', err.message);
    res.status(500).json({ error: 'Failed to load requests', detail: err.message });
  }
});


router.get('/stale', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, sdp_internal_id AS sdpInternalId, requester, technician, priority, status,
             created_at AS createdAt, last_updated_at AS lastUpdatedAt,
             DATEDIFF(NOW(), created_at) AS daysOpen
      FROM sdops_request
      WHERE gone = 0
        AND status NOT IN ('Resolved', 'Closed', 'Canceled')
        AND created_at < (NOW() - INTERVAL 3 DAY)
      ORDER BY daysOpen DESC
    `);

    const rowsWithLinks = rows.map(r => ({
      ...r,
      sdpUrl: r.sdpInternalId
        ? `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${r.sdpInternalId}`
        : null
    }));

    const [[lastRun]] = await pool.query(`
      SELECT status, finished_at FROM sdops_collector_run
      WHERE module = 'requests' ORDER BY id DESC LIMIT 1
    `);
    const stale = !lastRun || lastRun.status !== 'ok' ||
      (Date.now() - new Date(lastRun.finished_at).getTime()) > 2 * 15 * 60 * 1000;

    // Freshness the page can actually render, with an explicit unknown rung.
    const collectedAt = lastRun && lastRun.finished_at
      ? new Date(lastRun.finished_at).toISOString()
      : null;
    const collectorStatus = !lastRun
      ? 'unknown'
      : (lastRun.status !== 'ok' ? 'failed' : (stale ? 'stale' : 'ok'));

    res.json({
      data: rowsWithLinks,
      total: rows.length,
      generatedAt: new Date().toISOString(),
      source: 'servicedesk-plus',
      stale,
      collectedAt,
      collectorStatus,
    });
  } catch (err) {
    console.error('[sdops] stale error:', err.message);
    res.status(500).json({ error: 'Failed to load stale requests', detail: err.message });
  }
});
// ---------- Phone Calls module (Vonage VBC) ----------
// Reads from sdops_call (to be populated by collect-calls.js once VBC
// API credentials arrive). Routes are live but return empty data until then.

// GET /api/sdops/calls — list calls, optional ?from=YYYY-MM-DD&to=YYYY-MM-DD&agent=Name
router.get('/calls', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const clauses = [];
    const params = [];
    if (req.query.from) { clauses.push('started_at >= ?'); params.push(req.query.from); }
    if (req.query.to)   { clauses.push('started_at < DATE_ADD(?, INTERVAL 1 DAY)'); params.push(req.query.to); }
    if (req.query.agent){ clauses.push('agent_name = ?'); params.push(req.query.agent); }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';

    const [rows] = await pool.query(`
      SELECT call_id AS id, agent_name AS agent, from_number AS fromNumber,
             to_number AS toNumber, direction, disposition,
             talk_time_sec AS talkTimeSec, wait_time_sec AS waitTimeSec,
             started_at AS startedAt
      FROM sdops_call
      ${where}
      ORDER BY started_at DESC
      LIMIT 1000
    `, params);

    res.json({
      ...(await feedFreshness(['calls'])),
      data: rows,
      total: rows.length,
      generatedAt: new Date().toISOString(),
      source: 'vonage-vbc',
      pendingIntegration: rows.length === 0,
    });
  } catch (err) {
    console.error('[sdops] calls error:', err.message);
    res.status(500).json({ error: 'Failed to load calls', detail: err.message });
  }
});

// GET /api/sdops/calls/summary — KPI tile aggregates
router.get('/calls/summary', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    // 30-day window, not "today": at ~2 calls/day a daily tile reads 0 almost
    // every day, which is a number that carries no signal.
    const [[s]] = await pool.query(`
      SELECT COUNT(*) AS totalCalls,
             SUM(disposition = 'Answered') AS answered,
             SUM(disposition IN ('Missed','Abandoned')) AS missed,
             ROUND(AVG(talk_time_sec)) AS avgTalkSec,
             ROUND(AVG(wait_time_sec)) AS avgWaitSec
      FROM sdops_call
      WHERE started_at >= (NOW() - INTERVAL 30 DAY)
    `);
    // Freshness matters here: sdops_call is fed by a manual PDF import, not a
    // live feed (the Vonage Reports API still 401s for this account), so the
    // caller must be able to say how old the newest call is.
    const [[f]] = await pool.query(
      `SELECT MAX(started_at) AS latestCall, COUNT(*) AS everCollected FROM sdops_call`);
    const total = Number(s.totalCalls || 0);
    res.json({
      ...s,
      totalCalls: total,
      answered:   Number(s.answered || 0),
      missed:     Number(s.missed || 0),
      missedPct:  total ? Math.round(100 * Number(s.missed || 0) / total) : null,
      windowDays: 30,
      latestCall: f.latestCall || null,
      hasData:    Number(f.everCollected || 0) > 0,
      generatedAt: new Date().toISOString(),
      source: 'vonage-vbc (manual import)',
    });
  } catch (err) {
    console.error('[sdops] calls summary error:', err.message);
    res.status(500).json({ error: 'Failed to load call summary', detail: err.message });
  }
});
// ---------- Phone Calls PDF import (admin) ----------
// POST /api/sdops/calls/import  body: { filename, data: <base64 pdf> }
// Runs the importer script (IMPORT_CALLS_SCRIPT) server-side and executes its upserts.
router.post('/calls/import', rbac.requirePage(PAGE_KEY, 'admin'),
  express.json({ limit: '15mb' }), async (req, res) => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const { execFile } = require('child_process');
  let tmpPath = null;
  try {
    if (!importCallsAvailable()) return res.status(501).json({ error: 'Call import is not available on this host (importer script not deployed)' });
    const { data, filename } = req.body || {};
    if (!data) return res.status(400).json({ error: 'No file data' });
    const buf = Buffer.from(data, 'base64');
    if (buf.length > 12 * 1024 * 1024) return res.status(400).json({ error: 'File too large' });
    if (buf.slice(0, 5).toString() !== '%PDF-') return res.status(400).json({ error: 'Not a PDF' });

    tmpPath = path.join(os.tmpdir(), 'sdops-upload-' + Date.now() + '.pdf');
    fs.writeFileSync(tmpPath, buf);

    const stdout = await new Promise((resolve, reject) => {
      execFile('python3', [IMPORT_CALLS_SCRIPT, tmpPath],
        { maxBuffer: 20 * 1024 * 1024, timeout: 60000 },
        (err, out, errOut) => err ? reject(new Error(errOut || err.message)) : resolve(out));
    });

    const stmts = stdout.split('\n').filter(l => l.startsWith('INSERT INTO sdops_call'));
    if (!stmts.length) return res.status(422).json({ error: 'No call records found in PDF' });

    let imported = 0;
    for (const s of stmts) { await pool.query(s); imported++; }

    const [[range]] = await pool.query(
      'SELECT COUNT(*) AS total, MIN(started_at) AS earliest, MAX(started_at) AS latest FROM sdops_call');
    console.log('[sdops] calls import:', imported, 'records from', filename || 'upload');
    res.json({ imported, filename: filename || null, table: range });
  } catch (err) {
    console.error('[sdops] calls import error:', err.message);
    res.status(500).json({ error: 'Import failed', detail: err.message.slice(0, 300) });
  } finally {
    if (tmpPath) { try { require('fs').unlinkSync(tmpPath); } catch (e) {} }
  }
});
// ---------- HR modules (Entra-derived: Active Employees / New Hires / Terminations) ----------

// GET /api/sdops/employees — active members
router.get('/employees', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT u.display_name AS name, u.job_title AS title, u.department,
             u.manager_upn AS manager, u.office_location AS office,
             u.mail, u.last_login AS lastLogin, u.status,
             o.status AS oktaStatus
      FROM entra_users u
      LEFT JOIN okta_users o ON o.login = u.user_principal_name
      WHERE u.user_type = 'Member' AND u.account_enabled = 1
        AND u.user_principal_name LIKE '%@auction.com'
        AND u.display_name NOT LIKE '.%'
        AND ( (u.department IS NOT NULL AND u.department != 'N/A') OR u.manager_upn IS NOT NULL )
      ORDER BY u.display_name
    `);
    const now = Date.now();
    const stale30 = rows.filter(r => r.lastLogin && (now - new Date(r.lastLogin).getTime()) > 30 * 86400000).length;
    const never = rows.filter(r => !r.lastLogin).length;
    const [byDept] = await pool.query(`
      SELECT COALESCE(department,'(none)') AS department, COUNT(*) AS count
      FROM entra_users
      WHERE user_type = 'Member' AND account_enabled = 1
        AND user_principal_name LIKE '%@auction.com'
        AND display_name NOT LIKE '.%'
        AND ( (department IS NOT NULL AND department != 'N/A') OR manager_upn IS NOT NULL )
      GROUP BY department ORDER BY count DESC
    `);
    res.json({ ...(await feedFreshness(['entra', 'okta'])),
               data: rows, total: rows.length, staleLogins30d: stale30,
               neverLoggedIn: never, byDepartment: byDept,
               generatedAt: new Date().toISOString(), source: 'entra' });
  } catch (err) {
    console.error('[sdops] employees error:', err.message);
    res.status(500).json({ error: 'Failed to load employees', detail: err.message });
  }
});

// GET /api/sdops/newhires — accounts created in last N days (default 30)
router.get('/newhires', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '30', 10) || 30, 365);
    const [rows] = await pool.query(`
      SELECT u.display_name AS name, u.job_title AS title, u.department,
             u.manager_upn AS manager, u.created_at_entra AS createdAt,
             u.account_enabled AS accountEnabled, u.last_login AS lastLogin,
             o.status AS oktaStatus
      FROM entra_users u
      LEFT JOIN okta_users o ON o.login = u.user_principal_name
      WHERE u.user_type = 'Member'
        AND u.user_principal_name LIKE '%@auction.com'
        AND u.display_name NOT LIKE '.%'
        AND u.created_at_entra >= DATE_SUB(NOW(), INTERVAL ? DAY)
      ORDER BY u.created_at_entra DESC
    `, [days]);
    res.json({ ...(await feedFreshness(['entra', 'okta'])),
               data: rows, total: rows.length, windowDays: days,
               generatedAt: new Date().toISOString(), source: 'entra' });
  } catch (err) {
    console.error('[sdops] newhires error:', err.message);
    res.status(500).json({ error: 'Failed to load new hires', detail: err.message });
  }
});

// GET /api/sdops/terminations — accounts disabled in last N days (default 90)
router.get('/terminations', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '90', 10) || 90, 365);
    const [rows] = await pool.query(`
      SELECT u.display_name AS name, u.job_title AS title, u.department,
             u.manager_upn AS manager, a.activity_date_time AS disabledAt,
             DATEDIFF(NOW(), a.activity_date_time) AS daysSince,
             a.initiated_by_user_upn AS disabledBy,
             o.status AS oktaStatus
      FROM entra_audit_logs a
      JOIN entra_users u
        ON u.entra_id = JSON_UNQUOTE(JSON_EXTRACT(a.target_resources_json, '$[0].id'))
      LEFT JOIN okta_users o ON o.login = u.user_principal_name
      WHERE a.activity_display_name = 'Disable account'
        AND a.result = 'success'
        AND a.activity_date_time >= DATE_SUB(NOW(), INTERVAL ? DAY)
        AND u.account_enabled = 0
        AND u.user_principal_name LIKE '%@auction.com'
        AND u.display_name NOT LIKE '.%'
      ORDER BY a.activity_date_time DESC
    `, [days]);
    res.json({ ...(await feedFreshness(['entra', 'okta'])),
               data: rows, total: rows.length, windowDays: days,
               generatedAt: new Date().toISOString(), source: 'entra' });
  } catch (err) {
    console.error('[sdops] terminations error:', err.message);
    res.status(500).json({ error: 'Failed to load terminations', detail: err.message });
  }
});
// GET /api/sdops/lockouts — Entra account lockouts (errorCode 50053), last N days (default 7)
router.get('/lockouts', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '7', 10) || 7, 90);
    const includeSuppressed = req.query.includeSuppressed === '1';
    const [rows] = await pool.query(`
      SELECT l.id, l.created_at AS createdAt, l.upn, l.display_name AS name,
             l.ip, l.country, l.city, l.app_display_name AS app,
             l.client_app AS clientApp, l.os,
             l.is_managed AS isManaged, l.is_trusted_ip AS isTrustedIp,
             l.is_out_of_country AS isOutOfCountry, l.is_impossible_travel AS isImpossibleTravel,
             l.risk_state AS riskState, l.is_suppressed AS isSuppressed,
             l.resolution_status AS resolutionStatus, l.resolution_detail AS resolutionDetail,
             l.resolution_source AS resolutionSource, l.resolved_at AS resolvedAt,
             l.resolution_ticket_id AS resolutionTicketId,
             l.resolution_ticket_internal_id AS resolutionTicketInternalId,
             o.status AS oktaStatus,
             e.account_enabled AS accountEnabled, e.department AS department,
             (SELECT MAX(a.published_at) FROM sdops_ad_auth_event a
                WHERE a.upn_lower = LOWER(l.upn) AND a.outcome = 'SUCCESS') AS lastAdAuthSuccess,
             (SELECT COUNT(*) FROM sdops_ad_auth_event a
                WHERE a.upn_lower = LOWER(l.upn) AND a.outcome = 'SUCCESS'
                  AND a.ip_address IN ('34.223.75.130','34.223.75.128','34.223.75.129','64.58.136.121','64.58.136.122','65.240.83.51')
                  AND a.published_at BETWEEN DATE_SUB(l.created_at, INTERVAL 4 HOUR) AND DATE_ADD(l.created_at, INTERVAL 4 HOUR)
             ) > 0 AS verifiedNearby
      FROM sdops_lockout l
      LEFT JOIN okta_users o ON o.login = l.upn
      LEFT JOIN entra_users e ON e.user_principal_name = l.upn
      WHERE l.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
      ORDER BY l.created_at DESC
    `, [days]);

    const uniqueUsers = new Set(rows.map(r => r.upn)).size;
    const foreign = rows.filter(r => r.isOutOfCountry).length;
    const impossibleTravel = rows.filter(r => r.isImpossibleTravel).length;
    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const today = rows.filter(r => r.createdAt && new Date(r.createdAt) >= todayStart).length;
    const unresolvedCount = rows.filter(r => r.resolutionStatus === 'unresolved').length;
    const autoClearedCount = rows.filter(r => r.resolutionStatus === 'auto_cleared').length;
    const rowsWithLinks = rows.map(r => ({
      ...r,
      resolutionTicketUrl: r.resolutionTicketInternalId
        ? `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${r.resolutionTicketInternalId}`
        : null
    }));

    res.json({ data: rowsWithLinks, total: rowsWithLinks.length, uniqueUsers, foreign, impossibleTravel, today,
               unresolved: unresolvedCount, autoCleared: autoClearedCount,
               includeSuppressed, windowDays: days, generatedAt: new Date().toISOString(), source: 'entra-signin' });
  } catch (err) {
    console.error('[sdops] lockouts error:', err.message);
    res.status(500).json({ error: 'Failed to load lockouts', detail: err.message });
  }
});

// GET /api/sdops/resets — password/unlock helpdesk tickets from SDP, dept from Entra
router.get('/resets', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '90', 10) || 90, 365);
    const [rows] = await pool.query(`
      SELECT r.id, r.subject, r.requester, r.requester_email AS requesterEmail,
             r.technician, r.status, r.created_at AS createdAt,
             r.sdp_internal_id AS sdpInternalId,
             e.department,
             o.status AS oktaStatus
      FROM sdops_request r
      LEFT JOIN entra_users e ON e.user_principal_name = r.requester_email
      LEFT JOIN okta_users o ON o.login = r.requester_email
      WHERE r.gone = 0
        AND (r.subject LIKE '%password%' OR r.subject LIKE '%reset%'
             OR r.subject LIKE '%locked out%' OR r.subject LIKE '%unlock%')
        AND r.subject NOT LIKE '%complexity%'
        AND r.subject NOT LIKE '%zscaler%'
        AND r.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
      ORDER BY r.created_at DESC
    `, [days]);

    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const today = rows.filter(r => r.createdAt && new Date(r.createdAt) >= todayStart).length;
    const openCount = rows.filter(r => r.status !== 'Resolved' && r.status !== 'Closed').length;

    const mappedRows = rows.map(r => ({
      ...r,
      sdpUrl: r.sdpInternalId
        ? ('https://sdpondemand.manageengine.com/app/' + process.env.SDP_PORTAL +
           '/WorkOrder.do?woMode=viewWO&woID=' + r.sdpInternalId)
        : null
    }));
    res.json({ ...(await feedFreshness(['requests', 'entra', 'okta'])),
               data: mappedRows, total: mappedRows.length, today, open: openCount,
               windowDays: days, generatedAt: new Date().toISOString(), source: 'sdp+entra' });
  } catch (err) {
    console.error('[sdops] resets error:', err.message);
    res.status(500).json({ error: 'Failed to load password resets', detail: err.message });
  }
});

// GET /api/sdops/email-activity — helpdesk@auction.com mail matched against SDP tickets
router.get('/email-activity', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '1', 10) || 1, 30);
    const [rows] = await pool.query(`
      SELECT message_id AS id, received_at AS receivedAt, subject,
             from_name AS fromName, from_email AS fromEmail,
             matched_ticket_id AS matchedTicketId, match_type AS matchType,
             technician
      FROM sdops_email_activity
      WHERE received_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
      ORDER BY received_at DESC
    `, [days]);

    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const today = rows.filter(r => r.receivedAt && new Date(r.receivedAt) >= todayStart).length;
    const noTicket = rows.filter(r => r.matchType === 'no_ticket').length;
    const unassigned = rows.filter(r => r.matchType !== 'no_ticket' &&
      (!r.technician || r.technician.trim().toLowerCase() === 'unassigned')).length;

    res.json({ ...(await feedFreshness(['email'])),
               data: rows, total: rows.length, today, noTicket, unassigned,
               windowDays: days, generatedAt: new Date().toISOString(), source: 'graph+sdp' });
  } catch (err) {
    console.error('[sdops] email-activity error:', err.message);
    res.status(500).json({ error: 'Failed to load email activity', detail: err.message });
  }
});

// GET /api/sdops/manual-content — all manual-content rows (change freeze, maintenance, highlights)
router.get('/manual-content', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT content_key AS contentKey, content_type AS contentType,
             content_value AS contentValue, updated_by AS updatedBy, updated_at AS updatedAt
      FROM sdops_manual_content
    `);
    const data = {};
    for (const r of rows) {
      let value = r.contentValue;
      if (r.contentType === 'json') {
        try { value = JSON.parse(r.contentValue); } catch (e) { value = []; }
      } else if (r.contentType === 'flag') {
        value = r.contentValue === 'true';
      }
      data[r.contentKey] = { value, updatedBy: r.updatedBy, updatedAt: r.updatedAt };
    }
    res.json({ data, generatedAt: new Date().toISOString() });
  } catch (err) {
    console.error('[sdops] manual-content GET error:', err.message);
    res.status(500).json({ error: 'Failed to load manual content', detail: err.message });
  }
});

// POST /api/sdops/manual-content/:key — admin-only update of a single content row
router.post('/manual-content/:key', rbac.requirePage(PAGE_KEY, 'admin'), async (req, res) => {
  try {
    const key = req.params.key;
    const allowedKeys = ['change_freeze', 'change_freeze_note', 'upcoming_maintenance', 'team_highlights'];
    if (!allowedKeys.includes(key)) {
      return res.status(400).json({ error: 'Unknown content key' });
    }
    const { value, contentType } = req.body;
    let storedValue = value;
    if (contentType === 'json') storedValue = JSON.stringify(value);
    else if (contentType === 'flag') storedValue = value ? 'true' : 'false';

    const updatedBy = (req.user && (req.user.email || req.user.name)) || 'unknown';

    await pool.query(`
      INSERT INTO sdops_manual_content (content_key, content_type, content_value, updated_by)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        content_type = VALUES(content_type),
        content_value = VALUES(content_value),
        updated_by = VALUES(updated_by)
    `, [key, contentType, storedValue, updatedBy]);

    res.json({ ok: true, key, updatedBy });
  } catch (err) {
    console.error('[sdops] manual-content POST error:', err.message);
    res.status(500).json({ error: 'Failed to save manual content', detail: err.message });
  }
});

// GET /api/sdops/did-you-know — auto-computed stat, no manual entry required
router.get('/did-you-know', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [[email]] = await pool.query(`
      SELECT COUNT(*) AS total,
             SUM(match_type IN ('converted','reply_logged')) AS autoMatched
      FROM sdops_email_activity
      WHERE received_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
    `);
    const total = email.total || 0;
    const autoMatched = email.autoMatched || 0;
    const pct = total ? Math.round((autoMatched / total) * 100) : 0;

    const minutesPerEmail = parseFloat(process.env.AUTOMATION_MINUTES_PER_EMAIL || '4');
    const loadedHourlyRate = parseFloat(process.env.AUTOMATION_LOADED_HOURLY_RATE || '40');
    const minutesSaved = autoMatched * minutesPerEmail;
    const dollarsSaved = Math.round((minutesSaved / 60) * loadedHourlyRate * 100) / 100;

    let stat = null;
    if (total > 0) {
      stat = `${autoMatched} of ${total} helpdesk emails today (${pct}%) were automatically matched to tickets — no manual triage needed.`;
    }

    res.json({
      stat, total, autoMatched, pct,
      automationSavings: {
        minutesSaved, dollarsSaved, minutesPerEmail, loadedHourlyRate,
        note: 'Based on today\'s auto-matched emails only; figure grows as trailing history accumulates.'
      },
      generatedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('[sdops] did-you-know error:', err.message);
    res.status(500).json({ error: 'Failed to compute stat', detail: err.message });
  }
});


// GET /api/sdops/teams-requests — SDP tickets that ARRIVED through MS Teams.
//
// Filters on sdops_request.mode, the channel SDP records on the request
// itself. This was a subject keyword match until 2026-10-08, which was wrong
// in both directions: measured over the trailing 90 days it missed 47 of the
// 50 tickets that actually came in via Teams (their subject never says
// "teams" — e.g. #24347 "Sharepoint Permissions", mode 'Walk-ups & MS Teams')
// and it showed 7 that merely mentioned the word but arrived by mail or phone.
//
// Only two mode values contain Teams in the whole table, so they are listed
// explicitly rather than matched with LIKE. ADD TO THIS LIST if ServiceDesk
// Plus gains another Teams channel — a silent miss is exactly the failure
// this replaced.
//
// created_by_technician = 1 was dropped at the same time. A request belongs
// here because of how it arrived, not who logged it; that clause hid a
// further 4 requester-raised Teams tickets.
router.get('/teams-requests', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '90', 10) || 90, 365);
    const [rows] = await pool.query(`
      SELECT id, sdp_internal_id AS sdpInternalId, subject, requester, requester_email AS requesterEmail,
             technician, status, created_at AS createdAt, created_by_technician AS createdByTechnician,
             mode
      FROM sdops_request
      WHERE gone = 0
        AND mode IN ('MS Teams', 'Walk-ups & MS Teams')
        AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
      ORDER BY created_at DESC
    `, [days]);

    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const today = rows.filter(r => r.createdAt && new Date(r.createdAt) >= todayStart).length;
    const openCount = rows.filter(r => r.status !== 'Resolved' && r.status !== 'Closed').length;
    const rowsWithLinks = rows.map(r => ({
      ...r,
      sdpUrl: r.sdpInternalId
        ? `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${r.sdpInternalId}`
        : null
    }));

    res.json({ ...(await feedFreshness(['requests'])),
               data: rowsWithLinks, total: rowsWithLinks.length, today, open: openCount,
               windowDays: days, generatedAt: new Date().toISOString(), source: 'servicedesk-plus' });
  } catch (err) {
    console.error('[sdops] teams-requests error:', err.message);
    res.status(500).json({ error: 'Failed to load Teams requests', detail: err.message });
  }
});


// ---- Top categories (day|week|month|year) for the dashboard ----
router.get('/categories/top', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const windows = { day: 0, week: 6, month: 29, year: 364 };
    const w = String(req.query.window || 'week').toLowerCase();
    const days = Object.prototype.hasOwnProperty.call(windows, w) ? windows[w] : 6;
    const col = String(req.query.group || 'category').toLowerCase() === 'subcategory' ? 'subcategory' : 'category';
    const [rows] = await pool.query(
      `SELECT ${col} AS label, COUNT(*) AS count
         FROM sdops_request
        WHERE gone = 0
          AND created_at >= (CONVERT_TZ(CURDATE(), '+00:00', '-07:00') - INTERVAL ${days} DAY)
          AND ${col} IS NOT NULL AND TRIM(${col}) <> ''
          AND LOWER(TRIM(category)) NOT IN ('general', 'general / other', 'system notifications')
        GROUP BY ${col}
        ORDER BY count DESC`);
    const total = rows.reduce((a, r) => a + Number(r.count), 0);
    const [[lastRun]] = await pool.query('SELECT MAX(collected_at) AS last_collected FROM sdops_request');
    res.json({ ...(await feedFreshness(['requests'])),
               window: w, days, group: col, total, items: rows, categories: rows,
               last_collected: lastRun ? lastRun.last_collected : null });
  } catch (e) {
    console.error('[categories/top]', e.message);
    res.status(500).json({ error: 'failed to load top categories' });
  }
});


// ---- Request volume trend (day|week|month|year) for the dashboard ----
router.get('/requests/trend', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const ymd = (d) => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
    const w = String(req.query.window || 'week').toLowerCase();
    let rows, buckets = [];
    if (w === 'day') {
      [rows] = await pool.query('SELECT HOUR(created_at) k, COUNT(*) c FROM sdops_request WHERE gone = 0 AND created_at >= CURDATE() GROUP BY k');
      const map = {}; rows.forEach(r => { map[r.k] = Number(r.c); });
      for (let h = 0; h < 24; h++) buckets.push({ label: (h % 12 === 0 ? 12 : h % 12) + (h < 12 ? 'a' : 'p'), count: map[h] || 0 });
    } else if (w === 'year') {
      [rows] = await pool.query("SELECT DATE_FORMAT(created_at,'%Y-%m') k, COUNT(*) c FROM sdops_request WHERE gone = 0 AND created_at >= DATE_FORMAT(CURDATE() - INTERVAL 11 MONTH,'%Y-%m-01') GROUP BY k");
      const map = {}; rows.forEach(r => { map[r.k] = Number(r.c); });
      const now = new Date();
      for (let i = 11; i >= 0; i--) {
        const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
        const key = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
        buckets.push({ label: d.toLocaleString('en-US', { month: 'short' }), count: map[key] || 0 });
      }
    } else {
      const days = w === 'month' ? 29 : 6;
      [rows] = await pool.query(`SELECT DATE(created_at) k, COUNT(*) c FROM sdops_request WHERE gone = 0 AND created_at >= (CURDATE() - INTERVAL ${days} DAY) GROUP BY k`);
      const map = {}; rows.forEach(r => { const key = (r.k instanceof Date) ? ymd(r.k) : String(r.k).slice(0, 10); map[key] = Number(r.c); });
      for (let i = days; i >= 0; i--) {
        const d = new Date(); d.setDate(d.getDate() - i);
        buckets.push({ label: (d.getMonth() + 1) + '/' + d.getDate(), count: map[ymd(d)] || 0 });
      }
    }
    const total = buckets.reduce((a, b) => a + b.count, 0);
    res.json({ ...(await feedFreshness(['requests'])), window: w, total, buckets });
  } catch (e) {
    console.error('[requests/trend]', e.message);
    res.status(500).json({ error: 'failed to load trend' });
  }
});


// ---- On-demand mirror sync (runs collect-requests.js, like the cron) ----
let _syncInFlight = false;
router.post('/requests/sync', rbac.requirePage(PAGE_KEY, 'admin'), async (req, res) => {
  if (_syncInFlight) return res.status(409).json({ error: 'sync already running' });
  _syncInFlight = true;
  const { execFile } = require('child_process');
  const env = { ...process.env };
  const child = execFile(process.execPath, ['/var/www/corpit-hub-api/collect-requests.js'],
    { cwd: '/var/www/corpit-hub-api', env, timeout: 120000, maxBuffer: 1024 * 1024 * 8 },
    (err, stdout, stderr) => {
      _syncInFlight = false;
      if (err) {
        console.error('[requests/sync]', err.message, (stderr || '').slice(0, 400));
        return res.status(500).json({ error: 'sync failed', detail: err.message });
      }
      const mm = (stdout || '').match(/total requests processed:\s*(\d+)/);
      res.json({ ok: true, processed: mm ? Number(mm[1]) : null });
    });
  child.on('error', (e) => { _syncInFlight = false; try { res.status(500).json({ error: e.message }); } catch (_) {} });
});

// ---- Home Office Assignment: compare SDP site vs Entra office ----
router.get('/homeoffice/review', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT r.id, r.sdp_internal_id AS sdpInternalId, r.requester, r.requester_email AS requesterEmail,
             r.site, r.site_id AS siteId, r.status, r.created_at AS createdAt,
             COALESCE(e1.office_location, e2.office_location) AS officeLocation
      FROM sdops_request r
      LEFT JOIN entra_users e1 ON LOWER(e1.mail) = LOWER(r.requester_email)
      LEFT JOIN entra_users e2 ON LOWER(e2.user_principal_name) = LOWER(r.requester_email)
      WHERE r.gone = 0
        AND DATE(r.created_at) != '2026-02-26'
    `);
    const IRV = { id: '259065000000222001', name: 'Irvine Location' };
    const PLA = { id: '259065000000391179', name: 'Plano Location' };
    const REMOTE = { id: '259065000005353177', name: 'Remote' };
    const KNOWN_OFFICE_HINTS = ['mineola','atlanta','las vegas','redwood','chicago','phoenix','new york','belmont','newport','san mateo'];
    const out = [];
    const counts = { needsCorrection: 0, toIrvine: 0, toPlano: 0, toRemote: 0, alreadyCorrect: 0, noMatch: 0, total: rows.length };
    for (const r of rows) {
      const off = (r.officeLocation || '').toLowerCase().trim();
      let target = null;
      const isNA = !off || off === 'n/a' || off === 'na';
      if (!isNA) {
        if (off.includes('remote')) target = REMOTE;
        else if (off.includes('irvine') || off.includes('mauchly')) target = IRV;
        else if (off.includes('plano')) target = PLA;
        else if (KNOWN_OFFICE_HINTS.some(h => off.includes(h))) target = REMOTE;
      }
      if (!target) { counts.noMatch++; continue; }
      if (String(r.siteId) === target.id) { counts.alreadyCorrect++; continue; }
      counts.needsCorrection++;
      if (target === IRV) counts.toIrvine++; else if (target === PLA) counts.toPlano++; else counts.toRemote++;
      out.push({ id: r.id, sdpInternalId: r.sdpInternalId, requester: r.requester,
        requesterEmail: r.requesterEmail, officeLocation: r.officeLocation,
        currentSite: r.site, targetSite: target.name, status: r.status, createdAt: r.createdAt,
        sdpUrl: r.sdpInternalId ? 'https://sdpondemand.manageengine.com/app/' + process.env.SDP_PORTAL + '/WorkOrder.do?woMode=viewWO&woID=' + r.sdpInternalId : null });
    }
    res.json({ ...(await feedFreshness(['requests', 'entra'])),
               data: out, counts, generatedAt: new Date().toISOString() });
  } catch (err) {
    console.error('[sdops] homeoffice/review error:', err.message);
    res.status(500).json({ error: 'Failed to load home office review', detail: err.message });
  }
});

// ---- Home Office: ticket volume by office (all-time, all tickets) ----
router.get('/homeoffice/volume', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT COALESCE(e1.office_location, e2.office_location) AS office, COUNT(*) AS c
      FROM sdops_request r
      LEFT JOIN entra_users e1 ON LOWER(e1.mail) = LOWER(r.requester_email)
      LEFT JOIN entra_users e2 ON LOWER(e2.user_principal_name) = LOWER(r.requester_email)
      WHERE r.gone = 0
      GROUP BY office
      ORDER BY c DESC
    `);
    const norm = (s) => {
      const off = (s || '').toLowerCase().trim();
      if (!off || off === 'n/a' || off === 'na') return 'Unknown / N/A';
      if (off.includes('irvine') || off.includes('mauchly')) return 'Irvine, CA';
      if (off.includes('plano')) return 'Plano, TX';
      if (off.includes('mineola')) return 'Mineola, NY';
      if (off.includes('atlanta')) return 'Atlanta, GA';
      if (off.includes('las vegas')) return 'Las Vegas, NV';
      if (off.includes('redwood')) return 'Redwood City, CA';
      if (off.includes('chicago')) return 'Chicago, IL';
      if (off.includes('phoenix')) return 'Phoenix, AZ';
      if (off.includes('new york')) return 'New York, NY';
      if (off.includes('belmont')) return 'Belmont, CA';
      return 'Other';
    };
    const grouped = {};
    for (const r of rows) {
      const key = norm(r.office);
      grouped[key] = (grouped[key] || 0) + Number(r.c);
    }
    const out = Object.entries(grouped).filter(([office]) => office !== 'Unknown / N/A').map(([office, count]) => ({ office, count })).sort((a, b) => b.count - a.count);
    res.json({ data: out, generatedAt: new Date().toISOString() });
  } catch (err) {
    console.error('[sdops] homeoffice/volume error:', err.message);
    res.status(500).json({ error: 'Failed to load office volume', detail: err.message });
  }
});

// ---- Home Office: ticket volume by office, broken into week/month/quarter/year ----
router.get('/homeoffice/volume-periods', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT COALESCE(e1.office_location, e2.office_location) AS office, r.created_at AS createdAt
      FROM sdops_request r
      LEFT JOIN entra_users e1 ON LOWER(e1.mail) = LOWER(r.requester_email)
      LEFT JOIN entra_users e2 ON LOWER(e2.user_principal_name) = LOWER(r.requester_email)
      WHERE r.gone = 0
        AND NOT (r.created_by_name = 'Rey Abad' AND DATE(r.created_at) = '2026-02-26')
    `);
    const norm = (s) => {
      const off = (s || '').toLowerCase().trim();
      if (!off || off === 'n/a' || off === 'na') return null;
      if (off.includes('irvine') || off.includes('mauchly')) return 'Irvine, CA';
      if (off.includes('plano')) return 'Plano, TX';
      if (off.includes('mineola')) return 'Mineola, NY';
      if (off.includes('atlanta')) return 'Atlanta, GA';
      if (off.includes('las vegas')) return 'Las Vegas, NV';
      if (off.includes('redwood')) return 'Redwood City, CA';
      if (off.includes('chicago')) return 'Chicago, IL';
      if (off.includes('phoenix')) return 'Phoenix, AZ';
      if (off.includes('new york')) return 'New York, NY';
      if (off.includes('belmont')) return 'Belmont, CA';
      return 'Other';
    };
    const now = Date.now();
    const WINDOWS = { week: 6 * 86400000, month: 29 * 86400000, quarter: 91 * 86400000, year: 364 * 86400000 };
    const counts = { week: {}, month: {}, quarter: {}, year: {} };
    for (const r of rows) {
      const key = norm(r.office);
      if (!key) continue;
      const t = new Date(r.createdAt).getTime();
      const age = now - t;
      for (const win of Object.keys(WINDOWS)) {
        if (age <= WINDOWS[win]) counts[win][key] = (counts[win][key] || 0) + 1;
      }
    }
    const toSorted = (obj) => Object.entries(obj).map(([office, count]) => ({ office, count })).sort((a, b) => b.count - a.count);
    res.json({
      ...(await feedFreshness(['requests', 'entra'])),
      periods: {
        week: toSorted(counts.week),
        month: toSorted(counts.month),
        quarter: toSorted(counts.quarter),
        year: toSorted(counts.year)
      },
      generatedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('[sdops] homeoffice/volume-periods error:', err.message);
    res.status(500).json({ error: 'Failed to load office volume periods', detail: err.message });
  }
});

// ---- Home Office: full ticket list by office, per period (backs both chart and table) ----
router.get('/homeoffice/list-periods', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT r.id, r.requester, r.status, r.created_at AS createdAt, r.sdp_internal_id AS sdpInternalId,
             COALESCE(e1.office_location, e2.office_location) AS office
      FROM sdops_request r
      LEFT JOIN entra_users e1 ON LOWER(e1.mail) = LOWER(r.requester_email)
      LEFT JOIN entra_users e2 ON LOWER(e2.user_principal_name) = LOWER(r.requester_email)
      WHERE r.gone = 0
        AND DATE(r.created_at) != '2026-02-26'
    `);
    const norm = (s) => {
      const off = (s || '').toLowerCase().trim();
      if (!off || off === 'n/a' || off === 'na') return null;
      if (off.includes('irvine') || off.includes('mauchly')) return 'Irvine, CA';
      if (off.includes('plano')) return 'Plano, TX';
      if (off.includes('mineola')) return 'Mineola, NY';
      if (off.includes('atlanta')) return 'Atlanta, GA';
      if (off.includes('las vegas')) return 'Las Vegas, NV';
      if (off.includes('redwood')) return 'Redwood City, CA';
      if (off.includes('chicago')) return 'Chicago, IL';
      if (off.includes('phoenix')) return 'Phoenix, AZ';
      if (off.includes('new york')) return 'New York, NY';
      if (off.includes('belmont')) return 'Belmont, CA';
      return 'Other';
    };
    const now = Date.now();
    const WINDOWS = { week: 6 * 86400000, month: 29 * 86400000, quarter: 91 * 86400000, year: 364 * 86400000 };
    const mapped = rows.map(r => ({
      id: r.id, requester: r.requester || '', status: r.status || '',
      office: norm(r.office), createdTs: new Date(r.createdAt).getTime(),
      officeRaw: r.office || '',
      sdpUrl: r.sdpInternalId ? 'https://sdpondemand.manageengine.com/app/' + process.env.SDP_PORTAL + '/WorkOrder.do?woMode=viewWO&woID=' + r.sdpInternalId : null
    })).filter(r => r.office);
    const out = {};
    for (const win of Object.keys(WINDOWS)) {
      const cutoff = now - WINDOWS[win];
      out[win] = mapped.filter(r => r.createdTs >= cutoff).map(r => ({ id: r.id, requester: r.requester, status: r.status, office: r.office, officeRaw: r.officeRaw, sdpUrl: r.sdpUrl }));
    }
    res.json({ periods: out, generatedAt: new Date().toISOString() });
  } catch (err) {
    console.error('[sdops] homeoffice/list-periods error:', err.message);
    res.status(500).json({ error: 'Failed to load office list periods', detail: err.message });
  }
});

// ---- Account Lockouts (v2): authoritative AD/Okta state, strict ticket match ----
router.get('/lockouts/state', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [episodes] = await pool.query(
      "SELECT id, upn, source, display_name AS displayName, department, " +
      "opened_at AS openedAt, last_seen_locked_at AS lastSeenLockedAt, closed_at AS closedAt, " +
      "resolution_method AS resolutionMethod, resolved_by AS resolvedBy, resolution_source AS resolutionSource " +
      "FROM sdops_lockout_state " +
      "WHERE closed_at IS NULL OR closed_at >= (NOW() - INTERVAL 24 HOUR) " +
      "ORDER BY opened_at DESC"
    );

    const [metaRows] = await pool.query("SELECT key_name, key_value FROM sdops_lockout_state_meta");
    const meta = {};
    metaRows.forEach(r => { meta[r.key_name] = r.key_value; });

    // group episodes by UPN so multi-system lockouts show as one row
    const byUpn = {};
    for (const ep of episodes) {
      const key = String(ep.upn).toLowerCase();
      if (!byUpn[key]) byUpn[key] = { upn: ep.upn, displayName: ep.displayName, department: ep.department, ad: null, okta: null };
      const entry = { openedAt: ep.openedAt, lastSeenLockedAt: ep.lastSeenLockedAt, closedAt: ep.closedAt, currentlyLocked: !ep.closedAt, resolutionMethod: ep.resolutionMethod || null, resolvedBy: ep.resolvedBy || null, resolutionSource: ep.resolutionSource || null };
      if (ep.source === 'AD') byUpn[key].ad = entry;
      if (ep.source === 'OKTA') byUpn[key].okta = entry;
      if (ep.displayName) byUpn[key].displayName = ep.displayName;
      if (ep.department) byUpn[key].department = ep.department;
    }

    const rows = Object.values(byUpn);

    // strict ticket match: exact requester_email + within 2 hours of the lockout being opened
    for (const r of rows) {
      const anchor = (r.ad && r.ad.openedAt) || (r.okta && r.okta.openedAt);
      if (!anchor) { r.ticket = null; continue; }
      const [tix] = await pool.query(
        "SELECT id, status, technician, sdp_internal_id AS sdpInternalId " +
        "FROM sdops_request " +
        "WHERE gone = 0 " +
        "AND LOWER(requester_email) = LOWER(?) " +
        "AND created_at BETWEEN (? - INTERVAL 2 HOUR) AND (? + INTERVAL 2 HOUR) " +
        "ORDER BY created_at DESC LIMIT 1",
        [r.upn, anchor, anchor]
      );
      r.ticket = tix.length ? { id: tix[0].id, status: tix[0].status, technician: tix[0].technician, sdpUrl: tix[0].sdpInternalId ? ('https://sdpondemand.manageengine.com/app/' + process.env.SDP_PORTAL + '/WorkOrder.do?woMode=viewWO&woID=' + tix[0].sdpInternalId) : null } : null;

      // ADDITIVE (does not alter r.ticket / hasTicket above): technician-engaged signal only
      // — either the ticket was created by a technician, or it was resolved/closed by a
      // named technician (excludes self-service / unassigned). Same anchor + 2hr window as above.
      const [techTix] = await pool.query(
        "SELECT id, status, technician, created_by_technician AS createdByTechnician, sdp_internal_id AS sdpInternalId " +
        "FROM sdops_request " +
        "WHERE gone = 0 " +
        "AND LOWER(requester_email) = LOWER(?) " +
        "AND created_at BETWEEN (? - INTERVAL 2 HOUR) AND (? + INTERVAL 2 HOUR) " +
        "AND (created_by_technician = 1 OR (status IN ('Resolved','Closed') AND technician IS NOT NULL AND technician NOT IN ('Unassigned','Self-Service'))) " +
        "ORDER BY created_at DESC LIMIT 1",
        [r.upn, anchor, anchor]
      );
      r.technicianTicket = techTix.length ? { id: techTix[0].id, status: techTix[0].status, technician: techTix[0].technician, createdByTechnician: !!techTix[0].createdByTechnician, sdpUrl: techTix[0].sdpInternalId ? ('https://sdpondemand.manageengine.com/app/' + process.env.SDP_PORTAL + '/WorkOrder.do?woMode=viewWO&woID=' + techTix[0].sdpInternalId) : null } : null;
    }

    const currentlyLocked = rows.filter(r => (r.ad && r.ad.currentlyLocked) || (r.okta && r.okta.currentlyLocked));
    const multiSystem = currentlyLocked.filter(r => r.ad && r.ad.currentlyLocked && r.okta && r.okta.currentlyLocked);
    const noTicket = currentlyLocked.filter(r => !r.ticket);
    const withTicket = currentlyLocked.filter(r => !!r.ticket);
    const recentlyResolved = rows.filter(r => !currentlyLocked.includes(r));

    res.json({
      ...(await feedFreshness(['lockoutState', 'adAuth', 'requests'])),
      rows,
      counts: {
        currentlyLocked: currentlyLocked.length,
        adLocked: rows.filter(r => r.ad && r.ad.currentlyLocked).length,
        oktaLocked: rows.filter(r => r.okta && r.okta.currentlyLocked).length,
        multiSystem: multiSystem.length,
        noTicket: noTicket.length,
        withTicket: withTicket.length,
        recentlyResolved: recentlyResolved.length,
        // ADDITIVE comparison signal — does not replace withTicket/noTicket above
        withTechnicianTicket: rows.filter(r => !!r.technicianTicket).length,
        ticketButNotTechnician: rows.filter(r => !!r.ticket && !r.technicianTicket).length
      },
      lastCheckedAd: meta.ad_last_run_at || null,
      lastCheckedAdError: meta.ad_last_error || null,
      lastCheckedOkta: meta.okta_last_run_at || null,
      lastCheckedOktaError: meta.okta_last_error || null,
      generatedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('[sdops] lockouts/state error:', err.message);
    res.status(500).json({ error: 'Failed to load lockout state', detail: err.message });
  }
});

// ---- Lockout tickets audit: last 30 days, watchlist-excluded, cross-referenced against authoritative AD/Okta episodes ----
router.get('/lockouts/ticket-audit', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [trackingRows] = await pool.query(
      "SELECT key_value FROM sdops_lockout_state_meta WHERE key_name = 'tracking_started_at'"
    );
    const trackingStart = trackingRows.length ? trackingRows[0].key_value : null;

    const [watchRows] = await pool.query("SELECT LOWER(upn) AS upn FROM signin_watchlist WHERE active = 1");
    const watchSet = new Set(watchRows.map(r => r.upn));

    const [tickets] = await pool.query(
      "SELECT id, requester_email AS requesterEmail, status, created_at AS createdAt, sdp_internal_id AS sdpInternalId " +
      "FROM sdops_request " +
      "WHERE gone = 0 " +
      "AND subcategory = 'Account Lockout' " +
      "AND status IN ('Resolved','Closed') " +
      "AND created_at >= (NOW() - INTERVAL 30 DAY) " +
      "ORDER BY created_at DESC"
    );

    const rows = [];
    for (const t of tickets) {
      const email = (t.requesterEmail || '').toLowerCase();
      if (watchSet.has(email)) continue; // exclude active spray-target / watchlist accounts

      const preTracking = trackingStart ? (new Date(t.createdAt) < new Date(trackingStart)) : true;

      let hasEpisode = false;
      if (!preTracking) {
        const [ep] = await pool.query(
          "SELECT id FROM sdops_lockout_state WHERE LOWER(upn) = LOWER(?) LIMIT 1",
          [email]
        );
        hasEpisode = ep.length > 0;
      }

      rows.push({
        id: t.id, requesterEmail: t.requesterEmail, status: t.status, createdAt: t.createdAt,
        preTracking, hasEpisode,
        sdpUrl: t.sdpInternalId ? ('https://sdpondemand.manageengine.com/app/' + process.env.SDP_PORTAL + '/WorkOrder.do?woMode=viewWO&woID=' + t.sdpInternalId) : null
      });
    }

    const confirmed = rows.filter(r => !r.preTracking && r.hasEpisode).length;
    const noEpisode = rows.filter(r => !r.preTracking && !r.hasEpisode).length;
    const preTrackingCount = rows.filter(r => r.preTracking).length;

    // These rows come from sdops_request, so the ServiceDesk Plus request
    // collector governs them -- the same rungs /requests reports. Without this
    // the four audit tiles are a 30-day window drawn against the wall clock
    // over a dataset that stops whenever collection stopped.
    const [[auditRun]] = await pool.query(`
      SELECT status, finished_at FROM sdops_collector_run
      WHERE module = 'requests' ORDER BY id DESC LIMIT 1
    `);
    const auditStale = !auditRun || auditRun.status !== 'ok' ||
      (Date.now() - new Date(auditRun.finished_at).getTime()) > 2 * 15 * 60 * 1000;
    const auditCollectedAt = auditRun && auditRun.finished_at
      ? new Date(auditRun.finished_at).toISOString()
      : null;
    const auditCollectorStatus = !auditRun
      ? 'unknown'
      : (auditRun.status !== 'ok' ? 'failed' : (auditStale ? 'stale' : 'ok'));

    res.json({
      rows,
      counts: { total: rows.length, confirmed, noEpisode, preTracking: preTrackingCount },
      trackingStart,
      stale: auditStale,
      collectedAt: auditCollectedAt,
      collectorStatus: auditCollectorStatus,
      generatedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('[sdops] lockouts/ticket-audit error:', err.message);
    res.status(500).json({ error: 'Failed to load ticket audit', detail: err.message });
  }
});

module.exports = router;
