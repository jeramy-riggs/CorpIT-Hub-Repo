'use strict';
/* Reset only CorpIT's workflow. No Graph or Okta calls and no history deletion. */
const crypto = require('crypto');
const L = require('./oem-lib');
const fail = (status, error, why) => Object.assign(new Error(error), { status, error, why });
const digest = (x) => crypto.createHash('sha256').update(JSON.stringify(x)).digest('hex');

// Shared by v2 app mutations. A separate connection holds the advisory lock for
// the HTTP request; transactions below use that same connection when resetting.
async function acquire(oktaId) {
  const conn = await L.pool.getConnection();
  const name = 'oem-app:' + digest(oktaId).slice(0, 48);
  try {
    const [[r]] = await conn.query('SELECT GET_LOCK(?, 0) AS acquired', [name]);
    if (!r || Number(r.acquired) !== 1) throw fail(409, 'application is busy', 'Another action is changing this application. Wait for it to finish, then reload.');
    let released = false;
    return { conn, release: async () => {
      if (released) return; released = true;
      try { await conn.query('SELECT RELEASE_LOCK(?)', [name]); }
      finally { conn.release(); }
    } };
  } catch (e) { conn.release(); throw e; }
}

async function snapshot(oktaId, q, locking) {
  q = q || L.pool;
  const suffix = locking ? ' FOR UPDATE' : '';
  const read = async (sql, args) => (await q.query(sql + suffix, args || [oktaId]))[0];
  const apps = await read('SELECT okta_id, label, status FROM okta_apps WHERE okta_id=?');
  if (!apps.length) throw fail(404, 'unknown Okta app', 'Refresh the Okta inventory before resetting this application.');
  const work = await read('SELECT item_key, state, disposition, assignee, assigned_at, state_actor, state_note, evidence, facts FROM oem_work_item WHERE item_key=?', ['app:' + oktaId]);
  const revisions = await read("SELECT id, revision_no, state, version, entra_sp_id, migration_id FROM oem_config_revision WHERE okta_app_id=? ORDER BY id DESC");
  const matches = await read("SELECT id, state, entra_sp_id, reason, updated_at FROM oem_app_match WHERE okta_app_id=? AND state<>'superseded' ORDER BY id DESC");
  const legacy = await read('SELECT * FROM app_matches WHERE okta_app_id=? ORDER BY id DESC');
  const migrations = await read('SELECT id, status, job_id, entra_sp_object_id FROM oem_migration WHERE okta_id=? ORDER BY id DESC');
  const scans = await read('SELECT inputs FROM oem_app_scan WHERE okta_id=?');
  const marks = await read('SELECT * FROM oem_app_migrated WHERE okta_id=? AND cleared_at IS NULL');
  const attempts = await read("SELECT id, status FROM oem_verification_attempt WHERE okta_app_id=? AND status='running'");
  const keys = revisions.flatMap((r) => ['okta-bookmark-handoff:' + r.id, 'entra-assignment-rollout:' + r.id]);
  const meta = keys.length ? await read('SELECT k, v FROM oem_meta WHERE k IN (?) ORDER BY k', [keys]) : [];
  const resets = await read("SELECT id FROM oem_work_event WHERE item_key=? AND event='migration_reset' ORDER BY id DESC LIMIT 1", ['app:' + oktaId]);
  const [locks] = await q.query('SELECT job_key FROM oem_job_lock');
  const globalJobs = ['discover', 'discover-okta', 'rebuild-work', 'okta-apps', 'entra-apps', 'migrate-bulk-preflight', 'migrate-bulk-push'];
  const jobKeys = ['migrate-push-' + oktaId, 'migrate-rollback-' + oktaId, 'v2-refresh-app:' + oktaId, 'okta-app-deactivate:' + oktaId, 'okta-app-reactivate:' + oktaId];
  revisions.forEach((r) => ['v2-shell-poll:', 'v2-configure-poll:', 'v2-assignment-rollout-poll:'].forEach((p) => jobKeys.push(p + r.id)));
  const busy = migrations.some((m) => m.status === 'running') || attempts.length ||
    (locks || []).some((l) => jobKeys.includes(l.job_key) || globalJobs.includes(l.job_key));
  const activeHandoff = meta.some((m) => {
    const value = L.j(m.v, {}) || {};
    return m.k.startsWith('okta-bookmark-handoff:')
      ? !['none', 'rolled_back'].includes(value.status || 'none')
      : !['not_started', 'none'].includes(value.status || 'not_started');
  });
  let why = null;
  if (busy) why = 'A migration, verification, or inventory job is running. Wait for it to finish, then reload the reset preview.';
  else if (activeHandoff) why = 'Production rollout or an Okta Bookmark handoff is recorded. Resolve or restore that handoff before restarting.';
  else if (revisions.some((r) => r.state === 'live') || work.some((w) => w.state === 'retired')) why = 'This application is Live or retired. Resolve its cutover before restarting the migration.';
  else if (apps[0].status !== 'ACTIVE') why = 'The source Okta application is not active. Review its lifecycle before restarting.';
  const state = { apps, work, revisions, matches, legacy, migrations, scans, marks, meta, resets };
  return { state, preview: {
    oktaId, label: apps[0].label || oktaId, allowed: !why, why,
    expected: digest(state), confirmation: 'RESET ' + (apps[0].label || oktaId),
    revisions: revisions.filter((r) => r.state !== 'superseded').length,
    migrationRuns: migrations.filter((r) => !['cancelled', 'rolled_back'].includes(r.status)).length,
    previousDestinations: [...new Set(matches.map((m) => m.entra_sp_id).concat(revisions.map((r) => r.entra_sp_id)).filter(Boolean))]
  } };
}

async function preview(oktaId) { return (await snapshot(oktaId)).preview; }

async function reset(oktaId, opts, connection) {
  const o = opts || {};
  const reason = String(o.reason || '').trim();
  if (reason.length < 10 || reason.length > 500) throw fail(400, 'reason required', 'Enter a reason between 10 and 500 characters.');
  if (!o.expected) throw fail(400, 'reset preview required', 'Open Reset migration and review the current record first.');
  const lease = connection ? null : await acquire(oktaId);
  const q = connection || lease.conn;
  try {
    await q.beginTransaction();
    const { state: s, preview: p } = await snapshot(oktaId, q, true);
    if (!p.allowed) throw fail(409, 'reset is blocked', p.why);
    if (o.expected !== p.expected) throw fail(409, 'application changed', 'The migration changed after you opened this preview. Reload the reset preview and review it again.');
    if (o.confirm !== p.confirmation) throw fail(400, 'confirmation does not match', 'Type exactly: ' + p.confirmation);
    const actor = o.actor;
    // The reset event is in the SAME transaction as every change. Keep original
    // statuses/decisions and setup input keys, but never copy secrets into history.
    const evidence = { revisions: s.revisions, matches: s.matches, legacy: L.redact(s.legacy), migrations: s.migrations,
      work: s.work.map(({ facts, ...w }) => w), migratedMarks: L.redact(s.marks), inputKeys: Object.keys(L.j(s.scans[0] && s.scans[0].inputs, {}) || {}), expected: p.expected };
    await q.query("INSERT INTO oem_work_event (item_key, event, from_state, to_state, note, actor_email, evidence) VALUES (?,'migration_reset',?,'needs_review',?,?,?)",
      ['app:' + oktaId, s.work[0] ? s.work[0].state : null, reason, actor, JSON.stringify(L.redact(evidence))]);
    await q.query("UPDATE oem_config_revision SET state='superseded', superseded_at=NOW(), version=version+1 WHERE okta_app_id=? AND state<>'superseded'", [oktaId]);
    await q.query("UPDATE oem_app_match SET state='superseded' WHERE okta_app_id=? AND state<>'superseded'", [oktaId]);
    await q.query('DELETE FROM app_matches WHERE okta_app_id=?', [oktaId]);
    await q.query('DELETE FROM oem_match_candidate WHERE okta_app_id=?', [oktaId]);
    // Cancel old executable plans and completed staging records without removing
    // their results, created-object IDs, verification, snapshots, or event logs.
    await q.query("UPDATE oem_migration SET status='cancelled', error=?, finished_at=COALESCE(finished_at,NOW()) WHERE okta_id=? AND status NOT IN ('cancelled','rolled_back')", ['Archived by migration reset: ' + reason, oktaId]);
    await q.query('UPDATE oem_app_scan SET inputs=NULL WHERE okta_id=?', [oktaId]);
    await q.query('UPDATE oem_app_migrated SET cleared_by=?, cleared_at=NOW(), cleared_note=? WHERE okta_id=? AND cleared_at IS NULL', [actor, 'Migration reset: ' + reason, oktaId]);
    const facts = L.j(s.work[0] && s.work[0].facts, {}) || {};
    delete facts.match; delete facts.nextAction;
    await q.query("UPDATE oem_work_item SET state='needs_review', auto_state='needs_review', disposition='migrate', assignee=NULL, assigned_at=NULL, assigned_by=NULL, state_actor=?, state_note=?, state_updated_at=NOW(), evidence=NULL, facts=? WHERE item_key=?", [actor, 'Migration reset: ' + reason, JSON.stringify(facts), 'app:' + oktaId]);
    await q.commit();
    return { ok: true, oktaId, state: 'no_destination', note: 'Migration reset. Choose a destination to start again. Previous attempts remain in the audit history.' };
  } catch (e) { await q.rollback(); throw e; }
  finally { if (lease) await lease.release(); }
}

module.exports = { acquire, preview, reset };
