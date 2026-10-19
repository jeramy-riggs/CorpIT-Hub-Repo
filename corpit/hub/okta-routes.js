// okta-routes.js — read-only Okta tenant view for the Okta Dashboard page.
// Mount point: /api/okta  (corpit-hub-api, port 3001)
//                                                            CorpIT 2026-09-07
//   GET /summary  — headline counts for users, MFA enrolment and applications
//   GET /users    — the user list, filterable, with each user's factor summary
//   GET /apps     — the application inventory
//
// SOURCES, and how fresh each one is
//   okta_users         collect-okta-users.js    cron 05:06 daily
//   okta_user_factors  collect-okta-factors.js  cron 05:22 daily
//   okta_apps          okta-apps-sync-job.js    cron 04:40 daily  (added 09-07;
//                      before that the collector was deployed but effectively
//                      unscheduled and this table held a 2026-08-27 snapshot)
//
// WHY EVERY RESPONSE CARRIES ITS OWN TIMESTAMP
// --------------------------------------------
// These are mirrors, not live Okta calls. A mirror that stops advancing keeps
// answering, and every count it returns stays plausible -- which is exactly how
// okta_apps showed 239 applications as current fact for eleven days. So each
// response states the age of the table it was computed from and whether that
// age is within the collector's own interval, and the page renders the verdict
// next to the number. `fresh` has three values, never two: true, false, and
// null for "the table is empty so there is nothing to date" -- a table nobody
// has ever filled must not read the same as one filled an hour ago.
//
// This router is read-only: SELECT only, no write path, no Okta API call. It
// reads corpit_hub on this host and touches nothing on ITAM.
'use strict';
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

const PAGE_KEY = 'helpdesk-okta';
const read = () => rbac.requirePage(PAGE_KEY, 'read');

// Collector intervals, in hours. Kept beside the cron entries they describe so
// the page's verdict and /api/feeds/freshness cannot drift apart.
const MAX_AGE_H = { okta_users: 24, okta_user_factors: 24, okta_apps: 24 };

// A user list is bounded so one request cannot pull 2,131 rows of JSON. The
// bound is reported alongside the unbounded total -- a truncated page that
// prints its own length as the total is how "everything is fine" gets rendered
// over the rows that were dropped.
const PAGE_MAX = 200;

async function freshness(table) {
  const [[row]] = await pool.query(
    `SELECT MAX(last_synced_at) AS syncedAt, COUNT(*) AS rows_ FROM ${table}`);
  const syncedAt = row.syncedAt;
  const rows = Number(row.rows_ || 0);
  if (!syncedAt) {
    // Empty, or filled by something that never stamped a time. Either way the
    // age is unknown, and unknown is not the same as fresh.
    return { table, syncedAt: null, rows, ageHours: null, maxAgeHours: MAX_AGE_H[table] || 24, fresh: null };
  }
  const ageHours = (Date.now() - new Date(syncedAt).getTime()) / 3600000;
  const maxAgeHours = MAX_AGE_H[table] || 24;
  return {
    table, rows,
    syncedAt: new Date(syncedAt).toISOString(),
    ageHours: Math.round(ageHours * 10) / 10,
    maxAgeHours,
    fresh: ageHours <= maxAgeHours,
  };
}

// GET /api/okta/summary
router.get('/summary', read(), async (req, res) => {
  try {
    const [fUsers, fFactors, fApps] = await Promise.all([
      freshness('okta_users'), freshness('okta_user_factors'), freshness('okta_apps'),
    ]);

    const [statusRows] = await pool.query(
      `SELECT COALESCE(status,'(unknown)') AS status, COUNT(*) AS n
         FROM okta_users GROUP BY 1 ORDER BY n DESC`);

    // MFA coverage is measured over ACTIVE users only. Deprovisioned accounts
    // cannot sign in, so counting them would drag the percentage down by more
    // than half (1,403 of 2,131 rows) and describe a risk nobody has.
    //
    // A factor counts only when its own status is ACTIVE. PENDING_ACTIVATION
    // means enrolment was started and never finished -- that account is not
    // protected, and rolling it into "enrolled" would overstate coverage.
    const [[cov]] = await pool.query(
      `SELECT COUNT(*) AS activeUsers,
              SUM(EXISTS (SELECT 1 FROM okta_user_factors f
                           WHERE f.okta_id = u.okta_id AND f.status = 'ACTIVE')) AS enrolled,
              SUM(EXISTS (SELECT 1 FROM okta_user_factors f
                           WHERE f.okta_id = u.okta_id AND f.status <> 'ACTIVE')
                  AND NOT EXISTS (SELECT 1 FROM okta_user_factors f2
                           WHERE f2.okta_id = u.okta_id AND f2.status = 'ACTIVE')) AS pendingOnly
         FROM okta_users u WHERE u.status = 'ACTIVE'`);

    const [factorTypes] = await pool.query(
      `SELECT f.factor_type AS factorType, f.provider, f.status,
              COUNT(DISTINCT f.okta_id) AS users
         FROM okta_user_factors f
         JOIN okta_users u ON u.okta_id = f.okta_id AND u.status = 'ACTIVE'
        GROUP BY 1,2,3 ORDER BY users DESC`);

    // Sign-in recency, ACTIVE users only. NULL is its own bucket: an account
    // that has never signed in is a different finding from one that signed in
    // long ago, and bucketing it as "90d+" would hide it among the merely idle.
    const [[recency]] = await pool.query(
      `SELECT SUM(last_login IS NULL)                                   AS never_,
              SUM(last_login >= NOW() - INTERVAL 7 DAY)                 AS d7,
              SUM(last_login <  NOW() - INTERVAL 7 DAY
                  AND last_login >= NOW() - INTERVAL 30 DAY)            AS d30,
              SUM(last_login <  NOW() - INTERVAL 30 DAY
                  AND last_login >= NOW() - INTERVAL 90 DAY)            AS d90,
              SUM(last_login <  NOW() - INTERVAL 90 DAY)                AS older
         FROM okta_users WHERE status = 'ACTIVE'`);

    const [appStatus] = await pool.query(
      `SELECT COALESCE(status,'(unknown)') AS status, COUNT(*) AS n
         FROM okta_apps GROUP BY 1 ORDER BY n DESC`);
    const [signOn] = await pool.query(
      `SELECT COALESCE(sign_on_mode,'(unknown)') AS mode, COUNT(*) AS n
         FROM okta_apps GROUP BY 1 ORDER BY n DESC`);

    const activeUsers = Number(cov.activeUsers || 0);
    const enrolled = Number(cov.enrolled || 0);

    res.json({
      freshness: { okta_users: fUsers, okta_user_factors: fFactors, okta_apps: fApps },
      users: {
        total: statusRows.reduce((a, r) => a + Number(r.n), 0),
        byStatus: statusRows.map(r => ({ status: r.status, n: Number(r.n) })),
      },
      mfa: {
        activeUsers,
        enrolled,
        notEnrolled: activeUsers - enrolled,
        pendingOnly: Number(cov.pendingOnly || 0),
        // Undefined rather than 0 when there are no active users: 0% coverage
        // of nobody is not a finding, and rendering it as one is a false alarm.
        coveragePct: activeUsers ? Math.round((enrolled / activeUsers) * 1000) / 10 : null,
        factorTypes: factorTypes.map(r => ({
          factorType: r.factorType, provider: r.provider, status: r.status, users: Number(r.users),
        })),
      },
      recency: {
        never: Number(recency.never_ || 0),
        d7: Number(recency.d7 || 0),
        d30: Number(recency.d30 || 0),
        d90: Number(recency.d90 || 0),
        older: Number(recency.older || 0),
      },
      apps: {
        total: appStatus.reduce((a, r) => a + Number(r.n), 0),
        byStatus: appStatus.map(r => ({ status: r.status, n: Number(r.n) })),
        bySignOnMode: signOn.map(r => ({ mode: r.mode, n: Number(r.n) })),
      },
    });
  } catch (e) {
    console.error('[okta] /summary', e.message);
    res.status(500).json({ error: 'summary failed' });
  }
});

// GET /api/okta/users?status=&q=&mfa=&limit=
router.get('/users', read(), async (req, res) => {
  try {
    const where = [];
    const args = [];
    const status = String(req.query.status || '').trim().toUpperCase();
    if (status && status !== 'ALL') { where.push('u.status = ?'); args.push(status); }

    const q = String(req.query.q || '').trim();
    if (q) {
      where.push('(u.email LIKE ? OR u.login LIKE ? OR CONCAT(u.first_name," ",u.last_name) LIKE ?)');
      const like = '%' + q + '%';
      args.push(like, like, like);
    }

    // mfa=none is the actionable one: an ACTIVE account with no ACTIVE factor.
    const mfa = String(req.query.mfa || '').trim().toLowerCase();
    if (mfa === 'none') {
      where.push(`NOT EXISTS (SELECT 1 FROM okta_user_factors f
                               WHERE f.okta_id = u.okta_id AND f.status = 'ACTIVE')`);
    } else if (mfa === 'enrolled') {
      where.push(`EXISTS (SELECT 1 FROM okta_user_factors f
                           WHERE f.okta_id = u.okta_id AND f.status = 'ACTIVE')`);
    }

    const sql = where.length ? ' WHERE ' + where.join(' AND ') : '';
    const [[cnt]] = await pool.query(`SELECT COUNT(*) AS n FROM okta_users u${sql}`, args);

    const limit = Math.min(PAGE_MAX, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const [rows] = await pool.query(
      `SELECT u.okta_id AS oktaId, u.login, u.email, u.first_name AS firstName,
              u.last_name AS lastName, u.status, u.last_login AS lastLogin,
              u.created_at_okta AS createdAt, u.status_changed_at AS statusChangedAt,
              (SELECT COUNT(*) FROM okta_user_factors f
                WHERE f.okta_id = u.okta_id AND f.status = 'ACTIVE')      AS activeFactors,
              (SELECT COUNT(*) FROM okta_user_factors f
                WHERE f.okta_id = u.okta_id AND f.status <> 'ACTIVE')     AS otherFactors,
              (SELECT GROUP_CONCAT(DISTINCT f.factor_type ORDER BY f.factor_type)
                 FROM okta_user_factors f
                WHERE f.okta_id = u.okta_id AND f.status = 'ACTIVE')      AS factorTypes
         FROM okta_users u${sql}
        ORDER BY (u.status = 'ACTIVE') DESC, u.last_login IS NULL, u.last_login DESC
        LIMIT ?`, args.concat([limit]));

    const total = Number(cnt.n || 0);
    res.json({
      total,                       // rows matching the filter
      returned: rows.length,       // rows in this response
      limit,
      truncated: total > rows.length,
      freshness: {
        okta_users: await freshness('okta_users'),
        okta_user_factors: await freshness('okta_user_factors'),
      },
      rows: rows.map(r => ({
        ...r,
        activeFactors: Number(r.activeFactors || 0),
        otherFactors: Number(r.otherFactors || 0),
        factorTypes: r.factorTypes ? r.factorTypes.split(',') : [],
      })),
    });
  } catch (e) {
    console.error('[okta] /users', e.message);
    res.status(500).json({ error: 'user query failed' });
  }
});

// GET /api/okta/apps?status=&q=
router.get('/apps', read(), async (req, res) => {
  try {
    const where = [];
    const args = [];
    const status = String(req.query.status || '').trim().toUpperCase();
    if (status && status !== 'ALL') { where.push('status = ?'); args.push(status); }
    const q = String(req.query.q || '').trim();
    if (q) {
      where.push('(label LIKE ? OR name LIKE ?)');
      const like = '%' + q + '%';
      args.push(like, like);
    }
    const sql = where.length ? ' WHERE ' + where.join(' AND ') : '';
    const [[cnt]] = await pool.query(`SELECT COUNT(*) AS n FROM okta_apps${sql}`, args);

    // No LIMIT: the whole inventory is 240 rows and the page shows all of them.
    // If it ever outgrows that, add the same total/returned/truncated contract
    // used by /users rather than silently capping here.
    const [rows] = await pool.query(
      `SELECT okta_id AS oktaId, name, label, status, sign_on_mode AS signOnMode,
              assigned_user_count AS assignedUsers, assigned_group_count AS assignedGroups,
              created_at_okta AS createdAt, last_updated_at_okta AS updatedAt,
              seen_in_last_sync AS seenInLastSync
         FROM okta_apps${sql}
        ORDER BY (status = 'ACTIVE') DESC, assigned_user_count DESC, label`, args);

    res.json({
      total: Number(cnt.n || 0),
      returned: rows.length,
      truncated: false,
      freshness: { okta_apps: await freshness('okta_apps') },
      rows: rows.map(r => ({
        ...r,
        assignedUsers: r.assignedUsers === null ? null : Number(r.assignedUsers),
        assignedGroups: r.assignedGroups === null ? null : Number(r.assignedGroups),
        seenInLastSync: r.seenInLastSync === null ? null : !!r.seenInLastSync,
      })),
    });
  } catch (e) {
    console.error('[okta] /apps', e.message);
    res.status(500).json({ error: 'app query failed' });
  }
});

module.exports = router;
