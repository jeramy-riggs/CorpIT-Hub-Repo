/**
 * oem-test-signin.js — "Test sign-in": open the confirmed Entra application's sign-in and then PROVE it from
 * the Entra sign-in log for the tester's own username. Removable: delete this file, the `require` in
 * oem-migrate-routes.js and the hook in oem-migrate.js queue(); schema 009 is additive and stays.
 *
 * Honesty rules this module enforces:
 *   - start() only hands back the launch URL and records who is testing and when. Opening a portal proves nothing.
 *   - check() reads the Entra sign-in log (Graph auditLogs/signIns, with the platform mirror as a fallback) for
 *     THAT username, for THAT application (client appId or resourceId), created after the start time.
 *       a successful entry  → verified (the entry's id, time and source are stored)
 *       only failed entries → failed, with Entra's failure reason
 *       nothing yet         → stays "started"; the response says the log can lag several minutes
 *       nothing in 24 h     → expired
 *   - nothing here marks the work item Verified: the Verify card reads the latest verified test and the
 *     technician still records the six checks.
 */
'use strict';
const L = require('./oem-lib');
const { pool, j, nowIso } = L;

const CONFIRMED = new Set(['manual_confirmed', 'auto_high']);
const EXPIRE_MS = 24 * 3600 * 1000;
const GRACE_MS = 2 * 60 * 1000;            // clock skew between this host and Entra
const LAG_NOTE = 'Entra sign-in logs usually appear within a few minutes but can lag longer; check again after signing in. Nothing is recorded as verified until a matching successful entry is read.';
const UPN = /^[^\s@'"<>]+@[^\s@'"<>]+$/;
const odataStr = (s) => String(s).replace(/'/g, "''");

function rowOut(r) {
  if (!r) return null;
  return { id: r.id, oktaId: r.okta_id, entraId: r.entra_id, appId: r.app_id, entraName: r.entra_name, launchUrl: r.launch_url, startedBy: r.started_by, upn: r.test_upn, startedAt: r.started_at,
    status: r.status, checks: r.checks, checkedAt: r.checked_at, source: r.source, signInId: r.signin_id, signInAt: r.signin_at, outcome: r.signin_outcome, error: r.signin_error, note: r.note,
    label: { started: 'Started — no Entra log entry read yet', verified: 'Verified — successful Entra sign-in read from the log', failed: 'Failed — Entra logged only failed sign-ins', expired: 'Expired — no matching sign-in within 24 hours' }[r.status] || r.status };
}

async function targetOf(oktaId) {
  const [[w]] = await pool.query(`SELECT facts FROM oem_work_item WHERE item_key=?`, ['app:' + oktaId]);
  const facts = w ? (j(w.facts, {}) || {}) : {};
  const match = facts.match || {}; const entra = facts.entra || null;
  if (!CONFIRMED.has(match.decision) || !entra || !entra.appId) return { ok: false, reason: 'No confirmed Entra application for this Okta app. Confirm the match first (Review the application match); a test sign-in needs a known destination.' };
  return { ok: true, entra, decision: match.decision };
}

/** Record the start and return what to open. */
async function start(oktaId, { actor, upn }) {
  const t = await targetOf(oktaId);
  if (!t.ok) return { error: 'no confirmed target', status: 409, note: t.reason };
  const who = String(upn || actor || '').trim().toLowerCase();
  if (!UPN.test(who)) return { error: 'bad username', status: 400, note: 'The test username must be a user principal name (name@domain).' };
  const tenant = process.env.ENTRA_TENANT_ID || '';
  const launch = `https://launcher.myapps.microsoft.com/api/signin/${String(t.entra.appId).toLowerCase()}${tenant ? '?tenantId=' + encodeURIComponent(tenant) : ''}`;
  const [r] = await pool.query(`INSERT INTO oem_test_signin (okta_id, entra_id, app_id, entra_name, launch_url, started_by, test_upn, started_at, status) VALUES (?,?,?,?,?,?,?,NOW(),'started')`,
    [oktaId, t.entra.id || null, String(t.entra.appId).toLowerCase(), t.entra.name || null, launch, actor, who]);
  const [[row]] = await pool.query(`SELECT * FROM oem_test_signin WHERE id=?`, [r.insertId]);
  return { ok: true, test: rowOut(row), launchUrl: launch, loginUrl: t.entra.loginUrl || null, upn: who,
    effect: 'Opens the Entra sign-in for "' + (t.entra.name || 'the Entra application') + '" in a new tab (My Apps launcher). Nothing is changed; nothing is verified until the log is read.',
    note: 'Sign in as ' + who + ', then press "Check the Entra log". ' + LAG_NOTE };
}

/** Read the log for one started test. */
async function check(oktaId, id, { actor }) {
  const [[r]] = await pool.query(`SELECT * FROM oem_test_signin WHERE id=? AND okta_id=?`, [id, oktaId]);
  if (!r) return { error: 'not found', status: 404 };
  if (r.status === 'verified') return { ok: true, test: rowOut(r), changed: false, note: 'Already verified.' };
  const since = new Date(new Date(r.started_at).getTime() - GRACE_MS);
  const appId = String(r.app_id || '').toLowerCase();
  const read = { source: null, entries: [], error: null, partial: false };
  /* 1. live Graph read, filtered to this user and the start time; the app match is done here (appId OR resourceId) */
  const g = await L.graphGet(`/v1.0/auditLogs/signIns?$top=50&$orderby=createdDateTime desc&$filter=${encodeURIComponent(`userPrincipalName eq '${odataStr(r.test_upn)}' and createdDateTime ge ${since.toISOString()}`)}`);
  if (g.status === 200 && g.body && Array.isArray(g.body.value)) {
    read.source = 'graph';
    read.entries = g.body.value.filter((s) => String(s.appId || '').toLowerCase() === appId || String(s.resourceId || '').toLowerCase() === appId || (r.entra_id && String(s.servicePrincipalId || '').toLowerCase() === String(r.entra_id).toLowerCase()))
      /* failureReason reads "Other." on a SUCCESS too, so a reason is only a reason when the entry failed */
      .map((s) => { const ok = !!(s.status && Number(s.status.errorCode) === 0); return { id: s.id, at: s.createdDateTime, ok, error: ok ? null : (s.status && s.status.failureReason) || null, app: s.appDisplayName || null }; });
  } else {
    read.error = g.error || ('HTTP ' + g.status);
    /* 2. the platform mirror — honest about its lag */
    try {
      const [m] = await pool.query(`SELECT entra_id, created_at, outcome, status_error_code, status_failure_reason, app_display_name FROM entra_signin_logs WHERE LOWER(user_principal_name)=? AND app_id=? AND created_at >= ? ORDER BY created_at DESC LIMIT 50`, [r.test_upn, appId, since]);
      read.source = 'mirror'; read.partial = true;
      read.entries = m.map((s) => { const ok = String(s.outcome) === 'SUCCESS'; return { id: s.entra_id, at: s.created_at, ok, error: ok ? null : (s.status_failure_reason || null), app: s.app_display_name || null }; });
    } catch (e) { read.error += '; mirror: ' + e.message; }
  }
  const success = read.entries.find((e) => e.ok) || null;
  const failure = read.entries.find((e) => !e.ok) || null;
  let status = r.status, note = null;
  if (success) status = 'verified';
  else if (failure) { status = 'failed'; note = 'Entra logged a failed sign-in for ' + r.test_upn + (failure.error ? ': ' + failure.error : '') + '. Fix the cause and start a new test.'; }
  else if (Date.now() - new Date(r.started_at).getTime() > EXPIRE_MS) { status = 'expired'; note = 'No matching sign-in in 24 hours. Start a new test when you are ready to sign in.'; }
  else if (read.error && !read.source) note = 'Could not read the Entra sign-in log: ' + read.error;
  else note = (read.source === 'mirror' ? 'Live Graph read failed (' + read.error + '); the platform mirror was checked instead and it lags behind Entra. ' : '') + 'No matching entry yet. ' + LAG_NOTE;
  const hit = success || failure;
  await pool.query(`UPDATE oem_test_signin SET status=?, checks=checks+1, checked_at=NOW(), source=?, signin_id=?, signin_at=?, signin_outcome=?, signin_error=?, note=? WHERE id=?`,
    [status, read.source, hit ? String(hit.id).slice(0, 64) : null, hit ? new Date(hit.at) : null, hit ? (hit.ok ? 'SUCCESS' : 'FAILURE') : null, hit && hit.error ? String(hit.error).slice(0, 500) : (read.error ? String(read.error).slice(0, 500) : null), note ? String(note).slice(0, 500) : null, r.id]);
  if (status === 'verified') {
    try {
      await pool.query(`INSERT INTO oem_work_event (item_key, event, from_state, to_state, note, actor_email, evidence) VALUES (?,?,?,?,?,?,?)`, ['app:' + oktaId, 'test_signin_verified', null, null,
        'Test sign-in verified: Entra logged a successful sign-in by ' + r.test_upn + ' at ' + success.at + ' (read from ' + read.source + ')', actor,
        JSON.stringify({ testId: r.id, upn: r.test_upn, appId, entraName: r.entra_name, signInId: success.id, signInAt: success.at, source: read.source })]);
    } catch (e) { /* the test row is the record of truth; the event is a convenience for the timeline */ }
  }
  const [[row]] = await pool.query(`SELECT * FROM oem_test_signin WHERE id=?`, [r.id]);
  return { ok: true, test: rowOut(row), changed: row.status !== r.status, read: { source: read.source, entries: read.entries.length, error: read.error, partial: read.partial }, note: note || (status === 'verified' ? 'Verified: Entra logged a successful sign-in by ' + r.test_upn + ' to ' + (success.app || r.entra_name || 'the application') + ' at ' + success.at + ' (read from ' + read.source + ').' : null) };
}

async function list(oktaId, limit = 10) {
  const [rows] = await pool.query(`SELECT * FROM oem_test_signin WHERE okta_id=? ORDER BY id DESC LIMIT ?`, [oktaId, Math.max(1, Math.min(50, Number(limit) || 10))]);
  const items = rows.map(rowOut);
  return { items, latest: items[0] || null, verified: items.find((t) => t.status === 'verified') || null, lagNote: LAG_NOTE };
}

/** Newest test per app for queue rows; never throws (the table may not exist until 009 runs). */
async function latestMap() {
  const m = new Map();
  try {
    const [rows] = await pool.query(`SELECT t.* FROM oem_test_signin t JOIN (SELECT okta_id, MAX(id) id FROM oem_test_signin GROUP BY okta_id) x ON x.id=t.id`);
    for (const r of rows) m.set(r.okta_id, { id: r.id, status: r.status, upn: r.test_upn, startedAt: r.started_at, checkedAt: r.checked_at, signInAt: r.signin_at, source: r.source });
  } catch (e) { /* absent table = no tests */ }
  return m;
}

/** Mount on the migrate router. deps: { json, admin, read, idOk, fail, actorOf, audit } from oem-migrate-routes.js */
function mount(router, d) {
  // GET /api/oem/migrate/apps/:id/test-signin — history + the latest verified test
  router.get('/apps/:id/test-signin', d.read(), async (req, res) => { if (!d.idOk(req, res)) return; try { res.json(await list(req.params.id)); } catch (e) { d.fail(res, e, 'test-signin list'); } });
  // POST /api/oem/migrate/apps/:id/test-signin/start {upn?} — record the start, return the launch URL (no change to any tenant)
  router.post('/apps/:id/test-signin/start', d.json, d.admin(), async (req, res) => {
    if (!d.idOk(req, res)) return;
    try {
      const r = await start(req.params.id, { actor: d.actorOf(req), upn: req.body && req.body.upn });
      if (r.error) return res.status(r.status || 400).json(r);
      await d.audit(req, 'oem_test_signin_start', { okta_id: req.params.id, test_id: r.test.id, upn: r.upn, app_id: r.test.appId });
      res.json(r);
    } catch (e) { d.fail(res, e, 'test-signin start'); }
  });
  // POST /api/oem/migrate/apps/:id/test-signin/:tid/check — one Entra sign-in log read for that user + app after the start
  router.post('/apps/:id/test-signin/:tid/check', d.json, d.admin(), async (req, res) => {
    if (!d.idOk(req, res)) return;
    if (!/^\d{1,10}$/.test(String(req.params.tid))) return res.status(400).json({ error: 'bad test id' });
    try {
      const r = await check(req.params.id, Number(req.params.tid), { actor: d.actorOf(req) });
      if (r.error) return res.status(r.status || 400).json(r);
      await d.audit(req, 'oem_test_signin_check', { okta_id: req.params.id, test_id: Number(req.params.tid), status: r.test.status, source: r.read.source, error: r.read.error });
      res.json(r);
    } catch (e) { d.fail(res, e, 'test-signin check'); }
  });
}

module.exports = { start, check, list, latestMap, mount, LAG_NOTE };
