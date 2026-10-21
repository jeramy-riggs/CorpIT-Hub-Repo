// =============================================================================
// entra-routes.js — Express routes for Entra dashboard data
// Mounted at /api/entra in server.js
//
// NOTE: LIMIT/OFFSET are interpolated as validated integers (from pagination()),
// not bound via ? placeholders, because mysql2's prepared-statement protocol
// rejects LIMIT ? in some configurations.
// =============================================================================

const express = require('express');
const router = express.Router();
// ---- RBAC enforcement ----
// Gated on the 'app-migration' page key (rbac_pages.url_path
// /app-migration.html). Was 'entra-dashboard', whose url_path names a page
// that exists on neither host; the app-migration row's description records
// the split, which had never been applied here.
// GETs are gated too. They previously carried no page-level check, unlike
// every comparable module in this codebase.
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
const entraSync = require('./entra-sync');
const db = entraSync.db;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
const ok = (res, data, meta) => res.json({ ok: true, data, ...(meta ? { meta } : {}) });
const fail = (res, code, message, status = 500) =>
  res.status(status).json({ ok: false, error: { code, message } });

function pagination(req) {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 500);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  return { limit, offset };
}

const wrap = fn => (req, res) => Promise.resolve(fn(req, res)).catch(err => {
  console.error('[entra-routes]', req.path, err.message);
  fail(res, 'SERVER_ERROR', err.message);
});

// -----------------------------------------------------------------------------
// Health & summary
// -----------------------------------------------------------------------------
router.get('/health', rbac.requirePage('app-migration','read'), wrap(async (_req, res) => {
  const [rows] = await db.execute(
    `SELECT job,
            MAX(CASE WHEN status='success' THEN completed_at END) AS last_success,
            MAX(started_at) AS last_attempt,
            (SELECT status FROM entra_sync_status s2
               WHERE s2.job = s1.job ORDER BY started_at DESC LIMIT 1) AS last_status
     FROM entra_sync_status s1
     GROUP BY job
     ORDER BY job`
  );
  const [[{ user_count }]] = await db.execute(`SELECT COUNT(*) AS user_count FROM entra_users`);
  const [[{ app_count }]]  = await db.execute(`SELECT COUNT(*) AS app_count  FROM entra_apps`);
  ok(res, { jobs: rows, user_count, app_count, tenant: process.env.ENTRA_TENANT_ID });
}));

router.get('/summary', rbac.requirePage('app-migration','read'), wrap(async (_req, res) => {
  const [[e]] = await db.execute(`
    SELECT
      (SELECT COUNT(*) FROM entra_users)                                               AS total_users,
      (SELECT COUNT(*) FROM entra_users WHERE account_enabled = 1 AND status='ACTIVE') AS active_users,
      (SELECT COUNT(*) FROM entra_users WHERE is_likely_locked = 1)                    AS locked_out,
      (SELECT COUNT(*) FROM entra_users WHERE account_enabled = 0)                     AS disabled,
      (SELECT COUNT(*) FROM entra_users WHERE status = 'STALE')                        AS stale,
      (SELECT COUNT(*) FROM entra_users WHERE last_login IS NULL AND account_enabled=1) AS never_logged_in,
      (SELECT COUNT(*) FROM entra_apps)                                                AS total_apps,
      (SELECT COUNT(*) FROM entra_apps WHERE preferred_single_sign_on_mode IN ('saml','oidc')) AS sso_apps,
      (SELECT COUNT(*) FROM entra_signin_logs
         WHERE outcome = 'FAILURE'
           AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR))                         AS failed_logins_24h,
      (SELECT COUNT(*) FROM entra_risky_users WHERE risk_state = 'atRisk')             AS at_risk_users,
      (SELECT MAX(completed_at) FROM entra_sync_status WHERE status='success')         AS last_sync
  `);
  // Okta side: deferred to Phase 5 (needs bridge to port 3002 or Okta->MySQL sync)
  ok(res, { entra: e, okta: null });
}));

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------
router.get('/users', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const { limit, offset } = pagination(req);
  const search     = req.query.search || null;
  const enabled    = req.query.enabled;
  const department = req.query.department || null;
  const status     = req.query.status || null;

  const where = [];
  const params = [];

  if (search) {
    where.push(`(user_principal_name LIKE ? OR display_name LIKE ? OR mail LIKE ?)`);
    const s = `%${search}%`;
    params.push(s, s, s);
  }
  if (enabled === 'true')  where.push(`account_enabled = 1`);
  if (enabled === 'false') where.push(`account_enabled = 0`);
  if (department) { where.push(`department = ?`); params.push(department); }
  if (status)     { where.push(`status = ?`);     params.push(status); }

  const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const [[{ total }]] = await db.execute(
    `SELECT COUNT(*) AS total FROM entra_users ${whereSql}`, params
  );
  const [rows] = await db.execute(
    `SELECT entra_id, user_principal_name, display_name, mail, job_title,
            department, account_enabled, status, is_likely_locked,
            last_login, last_password_change, created_at_entra
     FROM entra_users ${whereSql}
     ORDER BY display_name
     LIMIT ${limit} OFFSET ${offset}`,
    params
  );

  ok(res, rows, { total, limit, offset, hasMore: offset + rows.length < total });
}));

router.get('/users/status-breakdown', rbac.requirePage('app-migration','read'), wrap(async (_req, res) => {
  const [rows] = await db.execute(
    `SELECT status, COUNT(*) AS count
     FROM entra_users
     GROUP BY status
     ORDER BY count DESC`
  );
  ok(res, rows);
}));

router.get('/users/:id', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const [[user]] = await db.execute(
    `SELECT * FROM entra_users WHERE entra_id = ? OR user_principal_name = ?`,
    [req.params.id, req.params.id]
  );
  if (!user) return fail(res, 'NOT_FOUND', 'User not found', 404);

  const [apps] = await db.execute(
    `SELECT a.resource_id, a.resource_display_name, a.app_role_id, a.created_at_entra,
            app.preferred_single_sign_on_mode
     FROM entra_app_assignments a
     LEFT JOIN entra_apps app ON app.entra_id = a.resource_id
     WHERE a.principal_id = ? AND a.principal_type = 'User'
     ORDER BY a.resource_display_name`,
    [user.entra_id]
  );

  const [groups] = await db.execute(
    `SELECT g.entra_id, g.display_name, g.mail_enabled, g.security_enabled
     FROM entra_group_memberships m
     JOIN entra_groups g ON g.entra_id = m.group_id
     WHERE m.member_id = ?
     ORDER BY g.display_name`,
    [user.entra_id]
  );

  const [methods] = await db.execute(
    `SELECT method_id, method_type, display_name, created_date_time
     FROM entra_auth_methods
     WHERE user_id = ?
     ORDER BY method_type`,
    [user.entra_id]
  );

  const [signins] = await db.execute(
    `SELECT entra_id, created_at, app_display_name, ip_address, location_city,
            location_country, outcome, status_error_code, status_failure_reason,
            risk_level_during_signin
     FROM entra_signin_logs
     WHERE user_id = ?
     ORDER BY created_at DESC
     LIMIT 50`,
    [user.entra_id]
  );

  const [[risky]] = await db.execute(
    `SELECT risk_level, risk_state, risk_detail, risk_last_updated_date_time
     FROM entra_risky_users WHERE user_id = ?`,
    [user.entra_id]
  );

  ok(res, { user, apps, groups, methods, signins, risky: risky || null });
}));

// -----------------------------------------------------------------------------
// Apps
// -----------------------------------------------------------------------------
router.get('/apps', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const { limit, offset } = pagination(req);
  const search = req.query.search || null;
  const required = req.query.assignmentRequired;
  const ssoMode = req.query.ssoMode || null;

  const where = [];
  const params = [];

  if (search) {
    where.push(`(display_name LIKE ? OR publisher_name LIKE ?)`);
    const s = `%${search}%`;
    params.push(s, s);
  }
  if (required === 'true')  where.push(`app_role_assignment_required = 1`);
  if (required === 'false') where.push(`app_role_assignment_required = 0`);
  if (ssoMode) { where.push(`preferred_single_sign_on_mode = ?`); params.push(ssoMode); }

  const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const [[{ total }]] = await db.execute(
    `SELECT COUNT(*) AS total FROM entra_apps ${whereSql}`, params
  );
  const [rows] = await db.execute(
    `SELECT entra_id, app_id, display_name, publisher_name,
            preferred_single_sign_on_mode, account_enabled,
            app_role_assignment_required, assigned_user_count,
            assigned_group_count, logo_url, created_at_entra
     FROM entra_apps ${whereSql}
     ORDER BY display_name
     LIMIT ${limit} OFFSET ${offset}`,
    params
  );

  ok(res, rows, { total, limit, offset, hasMore: offset + rows.length < total });
}));

router.get('/apps/usage-summary', rbac.requirePage('app-migration','read'), wrap(async (_req, res) => {
  const [mostUsed] = await db.execute(
    `SELECT entra_id, display_name, assigned_user_count
     FROM entra_apps ORDER BY assigned_user_count DESC LIMIT 10`
  );
  const [leastUsed] = await db.execute(
    `SELECT entra_id, display_name, assigned_user_count
     FROM entra_apps WHERE assigned_user_count > 0
     ORDER BY assigned_user_count ASC LIMIT 10`
  );
  const [unused] = await db.execute(
    `SELECT entra_id, display_name
     FROM entra_apps
     WHERE assigned_user_count = 0 AND assigned_group_count = 0
       AND service_principal_type = 'Application' LIMIT 25`
  );
  const [ssoModes] = await db.execute(
    `SELECT COALESCE(preferred_single_sign_on_mode, 'none') AS mode,
            COUNT(*) AS count
     FROM entra_apps GROUP BY mode ORDER BY count DESC`
  );
  ok(res, { mostUsed, leastUsed, unused, ssoModes });
}));

router.get('/apps/:id', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const [[app]] = await db.execute(
    `SELECT * FROM entra_apps WHERE entra_id = ?`,
    [req.params.id]
  );
  if (!app) return fail(res, 'NOT_FOUND', 'App not found', 404);

  const [assignments] = await db.execute(
    `SELECT principal_id, principal_type, principal_display_name, app_role_id, created_at_entra
     FROM entra_app_assignments
     WHERE resource_id = ?
     ORDER BY principal_display_name`,
    [req.params.id]
  );

  ok(res, { app, assignments });
}));

router.get('/apps/:id/assignments', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const [rows] = await db.execute(
    `SELECT principal_id, principal_type, principal_display_name, app_role_id, created_at_entra
     FROM entra_app_assignments
     WHERE resource_id = ?
     ORDER BY principal_display_name`,
    [req.params.id]
  );
  ok(res, rows);
}));

// -----------------------------------------------------------------------------
// Groups
// -----------------------------------------------------------------------------
router.get('/groups', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const { limit, offset } = pagination(req);
  const search = req.query.search || null;
  const where = [];
  const params = [];
  if (search) {
    where.push(`display_name LIKE ?`);
    params.push(`%${search}%`);
  }
  const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const [[{ total }]] = await db.execute(
    `SELECT COUNT(*) AS total FROM entra_groups ${whereSql}`, params
  );
  const [rows] = await db.execute(
    `SELECT entra_id, display_name, mail, mail_enabled, security_enabled,
            visibility, created_at_entra
     FROM entra_groups ${whereSql}
     ORDER BY display_name
     LIMIT ${limit} OFFSET ${offset}`,
    params
  );
  ok(res, rows, { total, limit, offset, hasMore: offset + rows.length < total });
}));

router.get('/groups/:id', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const [[group]] = await db.execute(
    `SELECT * FROM entra_groups WHERE entra_id = ?`,
    [req.params.id]
  );
  if (!group) return fail(res, 'NOT_FOUND', 'Group not found', 404);

  const [members] = await db.execute(
    `SELECT m.member_id, m.member_type,
            COALESCE(u.user_principal_name, g.display_name) AS display,
            u.display_name AS user_display_name, u.mail AS user_mail
     FROM entra_group_memberships m
     LEFT JOIN entra_users u  ON m.member_type = 'User'  AND u.entra_id = m.member_id
     LEFT JOIN entra_groups g ON m.member_type = 'Group' AND g.entra_id = m.member_id
     WHERE m.group_id = ?
     ORDER BY display`,
    [req.params.id]
  );
  ok(res, { group, members });
}));

// -----------------------------------------------------------------------------
// Sign-in logs
// -----------------------------------------------------------------------------
router.get('/signins', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const { limit, offset } = pagination(req);
  const user = req.query.user || null;
  const app  = req.query.app  || null;
  const outcome = req.query.outcome || null;
  const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 24, 1), 8760);

  const where = [`created_at > DATE_SUB(NOW(), INTERVAL ${hours} HOUR)`];
  const params = [];

  if (user) {
    where.push(`(user_principal_name LIKE ? OR user_display_name LIKE ?)`);
    const s = `%${user}%`;
    params.push(s, s);
  }
  if (app) {
    where.push(`app_display_name LIKE ?`);
    params.push(`%${app}%`);
  }
  if (outcome) { where.push(`outcome = ?`); params.push(outcome); }

  const whereSql = 'WHERE ' + where.join(' AND ');

  const [[{ total }]] = await db.execute(
    `SELECT COUNT(*) AS total FROM entra_signin_logs ${whereSql}`, params
  );
  const [rows] = await db.execute(
    `SELECT entra_id, created_at, user_principal_name, user_display_name,
            app_display_name, ip_address, location_city, location_country,
            outcome, status_error_code, status_failure_reason,
            risk_level_during_signin, client_app_used, is_interactive
     FROM entra_signin_logs ${whereSql}
     ORDER BY created_at DESC
     LIMIT ${limit} OFFSET ${offset}`,
    params
  );
  ok(res, rows, { total, limit, offset, hasMore: offset + rows.length < total });
}));

router.get('/signins/failed-recent', rbac.requirePage('app-migration','read'), wrap(async (_req, res) => {
  const [rows] = await db.execute(
    `SELECT user_principal_name, COUNT(*) AS fail_count,
            MAX(created_at) AS most_recent,
            GROUP_CONCAT(DISTINCT ip_address SEPARATOR ', ') AS ips
     FROM entra_signin_logs
     WHERE outcome = 'FAILURE'
       AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
     GROUP BY user_principal_name
     ORDER BY fail_count DESC LIMIT 20`
  );
  ok(res, rows);
}));

// -----------------------------------------------------------------------------
// Audit logs
// -----------------------------------------------------------------------------
router.get('/audit', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const { limit, offset } = pagination(req);
  const category = req.query.category || null;
  const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 168, 1), 8760);

  const where = [`activity_date_time > DATE_SUB(NOW(), INTERVAL ${hours} HOUR)`];
  const params = [];
  if (category) { where.push(`category = ?`); params.push(category); }

  const whereSql = 'WHERE ' + where.join(' AND ');

  const [[{ total }]] = await db.execute(
    `SELECT COUNT(*) AS total FROM entra_audit_logs ${whereSql}`, params
  );
  const [rows] = await db.execute(
    `SELECT entra_id, activity_date_time, activity_display_name, category,
            result, initiated_by_user_upn, initiated_by_app_name
     FROM entra_audit_logs ${whereSql}
     ORDER BY activity_date_time DESC
     LIMIT ${limit} OFFSET ${offset}`,
    params
  );
  ok(res, rows, { total, limit, offset, hasMore: offset + rows.length < total });
}));

// -----------------------------------------------------------------------------
// Risk
// -----------------------------------------------------------------------------
router.get('/risky-users', rbac.requirePage('app-migration','read'), wrap(async (_req, res) => {
  const [rows] = await db.execute(
    `SELECT entra_id, user_principal_name, user_display_name,
            risk_level, risk_state, risk_detail, risk_last_updated_date_time
     FROM entra_risky_users
     ORDER BY
       FIELD(risk_level, 'high', 'medium', 'low', 'hidden', 'none'),
       risk_last_updated_date_time DESC`
  );
  ok(res, rows);
}));

router.get('/risk-detections', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const { limit, offset } = pagination(req);
  const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 168, 1), 8760);
  const [[{ total }]] = await db.execute(
    `SELECT COUNT(*) AS total FROM entra_risk_detections
     WHERE detected_date_time > DATE_SUB(NOW(), INTERVAL ${hours} HOUR)`
  );
  const [rows] = await db.execute(
    `SELECT entra_id, user_principal_name, ip_address, location_city, location_country,
            risk_event_type, risk_level, risk_state, detected_date_time
     FROM entra_risk_detections
     WHERE detected_date_time > DATE_SUB(NOW(), INTERVAL ${hours} HOUR)
     ORDER BY detected_date_time DESC
     LIMIT ${limit} OFFSET ${offset}`
  );
  ok(res, rows, { total, limit, offset, hasMore: offset + rows.length < total });
}));

// -----------------------------------------------------------------------------
// Sync status & triggers
// -----------------------------------------------------------------------------
router.get('/sync-status', rbac.requirePage('app-migration','read'), wrap(async (_req, res) => {
  const [rows] = await db.execute(
    `SELECT id, job, started_at, completed_at, status,
            records_fetched, records_upserted, records_deleted,
            error_message, graph_api_calls
     FROM entra_sync_status
     ORDER BY started_at DESC LIMIT 100`
  );
  ok(res, rows);
}));

router.post('/sync/run', rbac.requirePage('app-migration','admin'), wrap(async (_req, res) => {
  if (await require('./sync-lock').isHeld(entraSync.FULL_LOCK)) {
    return fail(res, 'SYNC_RUNNING', 'A full Entra sync is already running. Poll /sync-status for progress.', 409);
  }
  entraSync.runFullSync().catch(e => console.error('[entra-routes] runFullSync:', e.message));
  ok(res, { started: true, note: 'Full sync started in background. Poll /sync-status for progress.' });
}));

router.post('/sync/run/:job', rbac.requirePage('app-migration','admin'), wrap(async (req, res) => {
  const job = req.params.job;
  if (!entraSync.JOBS.includes(job)) {
    return fail(res, 'UNKNOWN_JOB', `Unknown job: ${job}. Valid: ${entraSync.JOBS.join(', ')}`, 400);
  }
  entraSync.runSyncJob(job).catch(e => console.error(`[entra-routes] runSyncJob ${job}:`, e.message));
  ok(res, { started: true, job });
}));

// -----------------------------------------------------------------------------
// App matching — Okta ↔ Entra migration tracker
// -----------------------------------------------------------------------------
const oktaSync = require('./okta-sync');

// Migration progress summary — the headline metric
router.get('/matches/summary', rbac.requirePage('app-migration','read'), wrap(async (_req, res) => {
  const [[counts]] = await db.execute(`
    SELECT
      SUM(match_confidence = 'auto_high')         AS migrated_high,
      SUM(match_confidence = 'auto_medium')       AS migrated_medium,
      SUM(match_confidence = 'auto_low')          AS migrated_low,
      SUM(match_confidence = 'manual_confirmed')  AS migrated_confirmed,
      SUM(match_confidence = 'manual_rejected')   AS rejected,
      SUM(match_confidence = 'manual_staged')     AS migrated_staged,
      SUM(match_confidence = 'both_missing' AND entra_app_id IS NULL) AS not_migrated,
      SUM(match_method LIKE 'bookmark%')          AS via_bookmark,
      SUM(match_method LIKE 'tokens%')            AS via_saml_oidc,
      COUNT(*)                                    AS total_okta_sso_apps
    FROM app_matches
  `);
  const [[entra]] = await db.execute(
    `SELECT COUNT(*) AS total FROM entra_apps WHERE preferred_single_sign_on_mode IS NOT NULL`
  );
  ok(res, { counts, total_entra_sso_apps: entra.total });
}));

// List all matches with filtering
router.get('/matches', rbac.requirePage('app-migration','read'), wrap(async (req, res) => {
  const { limit, offset } = pagination(req);
  const confidence = req.query.confidence || null;
  const status = req.query.status || null;  // 'migrated' | 'not_migrated' | 'rejected'

  const where = [];
  const params = [];
  if (confidence) { where.push(`match_confidence = ?`); params.push(confidence); }
  if (status === 'migrated') where.push(`entra_app_id IS NOT NULL AND match_confidence NOT IN ('manual_rejected')`);
  if (status === 'not_migrated') where.push(`entra_app_id IS NULL OR match_confidence = 'manual_rejected'`);
  if (status === 'rejected') where.push(`match_confidence = 'manual_rejected'`);

  const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const [[{ total }]] = await db.execute(
    `SELECT COUNT(*) AS total FROM app_matches ${whereSql}`, params
  );
  const [rows] = await db.execute(
    `SELECT id, okta_app_id, okta_app_label, entra_app_id, entra_app_display_name,
            match_confidence, match_method, notes, created_at, last_verified_at, created_by
     FROM app_matches ${whereSql}
     ORDER BY FIELD(match_confidence,
                    'manual_rejected','auto_low','auto_medium','auto_high',
                    'manual_confirmed','both_missing'),
              okta_app_label
     LIMIT ${limit} OFFSET ${offset}`,
    params
  );
  ok(res, rows, { total, limit, offset, hasMore: offset + rows.length < total });
}));

// Confirm a match (manually set as definitive)
router.post('/matches/:id/confirm', rbac.requirePage('app-migration','admin'), wrap(async (req, res) => {
  const { id } = req.params;
  const notes = req.body?.notes || null;
  const by = (req.user && req.user.email) || 'unknown';   // session identity, not a body field
  const [result] = await db.execute(
    `UPDATE app_matches
       SET match_confidence = 'manual_confirmed',
           notes = ?,
           last_verified_at = NOW(),
           created_by = ?
     WHERE id = ?`,
    [notes, by, id]
  );
  if (result.affectedRows === 0) return fail(res, 'NOT_FOUND', 'Match not found', 404);
  ok(res, { id, confidence: 'manual_confirmed' });
}));

// Reject a match (set as definitively not a match)
router.post('/matches/:id/reject', rbac.requirePage('app-migration','admin'), wrap(async (req, res) => {
  const { id } = req.params;
  const notes = req.body?.notes || null;
  const by = (req.user && req.user.email) || 'unknown';   // session identity, not a body field
  const [result] = await db.execute(
    `UPDATE app_matches
       SET match_confidence = 'manual_rejected',
           notes = ?,
           last_verified_at = NOW(),
           created_by = ?
     WHERE id = ?`,
    [notes, by, id]
  );
  if (result.affectedRows === 0) return fail(res, 'NOT_FOUND', 'Match not found', 404);
  ok(res, { id, confidence: 'manual_rejected' });
}));

// Stage a match (mark as in-progress migration work)
router.post('/matches/:id/stage', rbac.requirePage('app-migration','admin'), wrap(async (req, res) => {
  const { id } = req.params;
  const notes = req.body?.notes || null;
  const by = (req.user && req.user.email) || 'unknown';   // session identity, not a body field
  const [result] = await db.execute(
    `UPDATE app_matches
       SET match_confidence = 'manual_staged',
           notes = ?,
           last_verified_at = NOW(),
           created_by = ?
     WHERE id = ?`,
    [notes, by, id]
  );
  if (result.affectedRows === 0) return fail(res, 'NOT_FOUND', 'Match not found', 404);
  ok(res, { id, confidence: 'manual_staged' });
}));

// Manually create a match (pair an Okta app with a specific Entra app)
router.post('/matches/create', rbac.requirePage('app-migration','admin'), wrap(async (req, res) => {
  const { okta_app_id, entra_app_id, notes } = req.body || {};
  const by = (req.user && req.user.email) || 'unknown';   // session identity, not a body field
  if (!okta_app_id || !entra_app_id) {
    return fail(res, 'MISSING_FIELDS', 'okta_app_id and entra_app_id required', 400);
  }
  const [[okta]] = await db.execute(`SELECT label FROM okta_apps WHERE okta_id = ?`, [okta_app_id]);
  const [[entra]] = await db.execute(`SELECT display_name FROM entra_apps WHERE entra_id = ?`, [entra_app_id]);
  if (!okta || !entra) return fail(res, 'NOT_FOUND', 'Okta or Entra app not found', 404);

  // Remove any existing auto-match for this okta app
  await db.execute(
    `DELETE FROM app_matches
     WHERE okta_app_id = ? AND match_confidence NOT IN ('manual_confirmed','manual_rejected')`,
    [okta_app_id]
  );
  const [result] = await db.execute(
    `INSERT INTO app_matches
       (okta_app_id, okta_app_label, entra_app_id, entra_app_display_name,
        match_confidence, match_method, notes, last_verified_at, created_by)
     VALUES (?,?,?,?,'manual_confirmed','manual', ?, NOW(), ?)`,
    [okta_app_id, okta.label, entra_app_id, entra.display_name, notes || null, by]
  );
  ok(res, { id: result.insertId, match_confidence: 'manual_confirmed' });
}));

// Trigger matcher manually
router.post('/matches/run', rbac.requirePage('app-migration','admin'), wrap(async (_req, res) => {
  oktaSync.runMatcher()
    .then(stats => console.log('[entra-routes] matcher result:', stats))
    .catch(e => console.error('[entra-routes] matcher:', e.message));
  ok(res, { started: true });
}));

// Trigger Okta apps sync manually
router.post('/okta-sync/run', rbac.requirePage('app-migration','admin'), wrap(async (_req, res) => {
  oktaSync.runSyncJob('okta_apps')
    .catch(e => console.error('[entra-routes] okta-sync:', e.message));
  ok(res, { started: true });
}));

module.exports = router;
