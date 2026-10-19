'use strict';
/**
 * Reversible Okta assignment handoff.
 *
 * The source SSO application is never deleted, deactivated, or reconfigured here. A
 * separate Bookmark app points at the Entra My Apps launcher. Staging leaves that
 * Bookmark inactive and unassigned. Cutover copies and verifies the current source
 * assignments, activates the Bookmark, and only then removes those assignments from
 * the source. Rollback restores the source first.
 */
const L = require('./oem-lib');

const META_PREFIX = 'okta-bookmark-handoff:';
const JOB_PREFIX = 'okta-bookmark-handoff:';
const ACTIVE = 'ACTIVE';

function now() { return typeof L.nowIso === 'function' ? L.nowIso() : new Date().toISOString(); }
function textError(e) {
  const value = e && e.message ? e.message : e;
  return (typeof L.redactText === 'function' ? L.redactText(value) : String(value || 'request failed')).slice(0, 500);
}
function fail(message, code) { const e = new Error(message); e.code = code || 'HANDOFF_FAILED'; return e; }
function key(revisionId) { return META_PREFIX + String(revisionId); }
function phrase(action, label) { return action + ' ' + label; }
function ids(rows) { return [...new Set((rows || []).map((r) => r && r.id).filter(Boolean))].sort(); }
function same(a, b) { return a.length === b.length && a.every((x, i) => x === b[i]); }
function missing(required, actual) { const have = new Set(actual); return required.filter((x) => !have.has(x)); }
function extras(expected, actual) { const want = new Set(expected); return actual.filter((x) => !want.has(x)); }
function overlap(a, b) { const right = new Set(b); return a.filter((x) => right.has(x)); }

function baseRecord(ctx) {
  return {
    version: 1,
    revisionId: ctx.revisionId,
    oktaId: ctx.oktaId,
    sourceLabel: ctx.label,
    bookmarkId: null,
    bookmarkLabel: null,
    launcherUrl: ctx.launcherUrl,
    launcherUrlSource: ctx.launcherUrlSource || null,
    status: 'none',
    stageSnapshot: null,
    cutoverSnapshot: null,
    counts: { groups: 0, directUsers: 0 },
    bookmarkActive: null,
    sourceActive: null,
    jobId: null,
    lastError: null,
    warning: null,
    createdAt: now(),
    updatedAt: now(),
  };
}

async function readRecord(ctx) {
  if (!L.metaGet) return baseRecord(ctx);
  const got = await L.metaGet(key(ctx.revisionId), null);
  return got && got.v && typeof got.v === 'object' ? Object.assign(baseRecord(ctx), got.v) : baseRecord(ctx);
}
async function save(rec, changes) {
  const next = Object.assign({}, rec, changes || {}, { updatedAt: now() });
  if (!L.metaSet) throw fail('The metadata store is unavailable; assignment handoff cannot run safely.', 'META_UNAVAILABLE');
  await L.metaSet(key(next.revisionId), next);
  return next;
}

function publicRecord(rec) {
  if (!rec) return null;
  return {
    version: rec.version || 1,
    revisionId: rec.revisionId,
    status: rec.status || 'none',
    sourceLabel: rec.sourceLabel || null,
    bookmarkId: rec.bookmarkId || null,
    bookmarkLabel: rec.bookmarkLabel || null,
    launcherUrl: rec.launcherUrl || null,
    launcherUrlSource: rec.launcherUrlSource || null,
    counts: rec.counts || { groups: 0, directUsers: 0 },
    bookmarkActive: rec.bookmarkActive === true,
    sourceActive: rec.sourceActive === true,
    jobId: rec.jobId || null,
    lastError: rec.lastError || null,
    warning: rec.warning || null,
    stagedAt: rec.stagedAt || null,
    cutoverAt: rec.cutoverAt || null,
    rolledBackAt: rec.rolledBackAt || null,
    updatedAt: rec.updatedAt || null,
    confirmations: {
      stage: phrase('STAGE BOOKMARK', rec.sourceLabel || ''),
      cutover: phrase('MOVE ASSIGNMENTS', rec.sourceLabel || ''),
      rollback: phrase('RESTORE ASSIGNMENTS', rec.sourceLabel || ''),
    },
  };
}

async function get(ctx) { return publicRecord(await readRecord(ctx)); }

function assertInput(ctx, action, confirm, reason) {
  if (!ctx || !Number.isInteger(Number(ctx.revisionId)) || !ctx.oktaId || !ctx.label) throw fail('The revision, source application, and label are required.', 'BAD_CONTEXT');
  if (!ctx.appId || !ctx.tenantId || !ctx.launcherUrl) throw fail('The Entra application ID and tenant ID are required to build the My Apps bookmark.', 'BAD_DESTINATION');
  const expected = phrase(action, ctx.label);
  if (String(confirm || '') !== expected) { const e = fail('Type "' + expected + '" exactly to continue.', 'BAD_CONFIRMATION'); e.expected = expected; throw e; }
  if (String(reason || '').trim().length < 10) throw fail('Add a reason of at least 10 characters.', 'BAD_REASON');
}

async function all(path, what) {
  const r = await L.oktaAll(path, { maxPages: 60 });
  if (!r || !r.ok) throw fail('Could not read ' + what + ' from Okta: ' + ((r && r.error) || 'unknown error'), 'OKTA_READ_FAILED');
  return r.items || [];
}
async function request(method, path, body, okStatuses, what) {
  const r = await L.oktaRequest(method, path, body);
  if (!r || !okStatuses.includes(r.status)) throw fail(what + ' failed in Okta: ' + ((r && r.error) || ('HTTP ' + (r && r.status))), 'OKTA_WRITE_FAILED');
  return r;
}
async function app(appId) {
  const r = await L.oktaGet('/api/v1/apps/' + encodeURIComponent(appId));
  if (!r || r.status !== 200 || !r.body) throw fail('Could not read Okta application ' + appId + ': ' + ((r && r.error) || ('HTTP ' + (r && r.status))), 'OKTA_READ_FAILED');
  return r.body;
}
function canonicalUrl(value) {
  try { return new URL(String(value || '')).href; } catch (e) { return null; }
}
async function ensureBookmarkTarget(ctx, appId) {
  const bookmark = await app(appId);
  const target = bookmark.settings && bookmark.settings.app && bookmark.settings.app.url;
  if (String(bookmark.name || '').toLowerCase() !== 'bookmark' || String(bookmark.signOnMode || '').toUpperCase() !== 'BOOKMARK') {
    throw fail('The staged Okta application is no longer a Bookmark application. The original assignments were not moved.', 'BOOKMARK_TYPE_CHANGED');
  }
  if (!canonicalUrl(target) || canonicalUrl(target) !== canonicalUrl(ctx.launcherUrl)) {
    throw fail('The Bookmark target changed after staging. The original assignments were not moved.', 'BOOKMARK_TARGET_CHANGED');
  }
  return bookmark;
}
async function assignments(appId) {
  const enc = encodeURIComponent(appId);
  const groups = await all('/api/v1/apps/' + enc + '/groups?limit=200', 'application group assignments');
  const users = await all('/api/v1/apps/' + enc + '/users?limit=200', 'application user assignments');
  return {
    groups: groups.filter((g) => g && g.id).map((g) => ({ id: g.id, name: g.profile && g.profile.name || null })),
    directUsers: users.filter((u) => u && u.id && String(u.scope || 'USER').toUpperCase() !== 'GROUP').map((u) => ({ id: u.id, login: u.credentials && u.credentials.userName || u.profile && u.profile.login || null })),
  };
}
function compactSnapshot(s) {
  return { groups: (s.groups || []).map((g) => ({ id: g.id, name: g.name || null })), directUsers: (s.directUsers || []).map((u) => ({ id: u.id, login: u.login || null })), capturedAt: now() };
}
function countOf(s) { return { groups: (s.groups || []).length, directUsers: (s.directUsers || []).length }; }

async function ensureSourceActive(ctx) {
  const source = await app(ctx.oktaId);
  if (source.status !== ACTIVE) throw fail('The original Okta application is ' + (source.status || 'not active') + '. Reactivate it before moving assignments.', 'SOURCE_NOT_ACTIVE');
  return source;
}
async function ensureActive(appId) {
  let current = await app(appId);
  if (current.status !== ACTIVE) {
    await request('POST', '/api/v1/apps/' + encodeURIComponent(appId) + '/lifecycle/activate', undefined, [200], 'Activating the Okta application');
    current = await app(appId);
  }
  if (current.status !== ACTIVE) throw fail('Okta did not report the application as ACTIVE after activation.', 'ACTIVATE_VERIFY_FAILED');
  return current;
}
async function deactivate(appId) {
  const current = await app(appId);
  if (current.status === 'INACTIVE') return current;
  await request('POST', '/api/v1/apps/' + encodeURIComponent(appId) + '/lifecycle/deactivate', undefined, [200], 'Deactivating the Bookmark application');
  return app(appId);
}

async function addMissing(appId, snapshot, log) {
  const current = await assignments(appId);
  const haveGroups = new Set(ids(current.groups));
  const haveUsers = new Set(ids(current.directUsers));
  for (const group of snapshot.groups || []) {
    if (haveGroups.has(group.id)) continue;
    await request('PUT', '/api/v1/apps/' + encodeURIComponent(appId) + '/groups/' + encodeURIComponent(group.id), {}, [200], 'Assigning group ' + (group.name || group.id));
    if (log) log('Assigned group ' + (group.name || group.id) + ' to the Bookmark app.');
  }
  for (const user of snapshot.directUsers || []) {
    if (haveUsers.has(user.id)) continue;
    await request('POST', '/api/v1/apps/' + encodeURIComponent(appId) + '/users', { id: user.id }, [200], 'Assigning direct user ' + (user.login || user.id));
    if (log) log('Assigned direct user ' + (user.login || user.id) + ' to the Bookmark app.');
  }
  return assignments(appId);
}
async function verifyContains(appId, snapshot, label) {
  const got = await assignments(appId);
  const mg = missing(ids(snapshot.groups), ids(got.groups));
  const mu = missing(ids(snapshot.directUsers), ids(got.directUsers));
  if (mg.length || mu.length) throw fail(label + ' is missing ' + mg.length + ' group(s) and ' + mu.length + ' direct user(s).', 'ASSIGNMENT_VERIFY_FAILED');
  return got;
}
async function verifyExact(appId, snapshot, label) {
  const got = await verifyContains(appId, snapshot, label);
  const eg = extras(ids(snapshot.groups), ids(got.groups));
  const eu = extras(ids(snapshot.directUsers), ids(got.directUsers));
  if (eg.length || eu.length) throw fail(label + ' has ' + eg.length + ' unexpected group(s) and ' + eu.length + ' unexpected direct user(s); nothing was removed automatically.', 'UNEXPECTED_ASSIGNMENTS');
  return got;
}
async function removeSnapshot(appId, snapshot, log) {
  const current = await assignments(appId);
  const haveGroups = new Set(ids(current.groups));
  const haveUsers = new Set(ids(current.directUsers));
  for (const user of snapshot.directUsers || []) {
    if (!haveUsers.has(user.id)) continue;
    await request('DELETE', '/api/v1/apps/' + encodeURIComponent(appId) + '/users/' + encodeURIComponent(user.id) + '?sendEmail=false', undefined, [204], 'Removing direct user ' + (user.login || user.id));
    if (log) log('Removed direct user ' + (user.login || user.id) + ' from the original app.');
  }
  for (const group of snapshot.groups || []) {
    if (!haveGroups.has(group.id)) continue;
    await request('DELETE', '/api/v1/apps/' + encodeURIComponent(appId) + '/groups/' + encodeURIComponent(group.id), undefined, [204], 'Removing group ' + (group.name || group.id));
    if (log) log('Removed group ' + (group.name || group.id) + ' from the original app.');
  }
  return assignments(appId);
}
async function verifyEmpty(appId, label) {
  const got = await assignments(appId);
  if (got.groups.length || got.directUsers.length) throw fail(label + ' still has ' + got.groups.length + ' group(s) and ' + got.directUsers.length + ' direct user(s). The captured assignments will be restored.', 'SOURCE_NOT_EMPTY');
  return got;
}

async function createBookmark(ctx, rec, log) {
  if (rec.bookmarkId) return { rec, app: await ensureBookmarkTarget(ctx, rec.bookmarkId) };
  const suffix = ' - Entra';
  const bookmarkLabel = String(ctx.label).slice(0, Math.max(1, 100 - suffix.length)) + suffix;
  const body = { name: 'bookmark', label: bookmarkLabel, signOnMode: 'BOOKMARK', settings: { app: { requestIntegration: false, url: ctx.launcherUrl } } };
  const made = await request('POST', '/api/v1/apps?activate=false', body, [200, 201], 'Creating the Okta Bookmark application');
  if (!made.body || !made.body.id) throw fail('Okta created the Bookmark application without returning its id.', 'CREATE_VERIFY_FAILED');
  rec = await save(rec, { bookmarkId: made.body.id, bookmarkLabel, bookmarkActive: false, createdBookmarkAt: now() });
  await ensureBookmarkTarget(ctx, rec.bookmarkId);
  if (log) log('Created inactive Bookmark app "' + bookmarkLabel + '".');
  return { rec, app: made.body };
}

async function emit(ctx, event, note, evidence) {
  if (typeof ctx.onEvent !== 'function') return;
  try { await ctx.onEvent(event, { actor: ctx.actor, note, evidence: Object.assign({ revisionId: ctx.revisionId }, evidence || {}) }); } catch (e) { /* the operation must not fail because activity logging did */ }
}

async function stageRun(ctx, log, job) {
  let rec = await readRecord(ctx);
  let sourceActive = false;
  try {
    rec = await save(rec, { status: 'staging', jobId: job.id, lastError: null, warning: null, reason: ctx.reason });
    await ensureSourceActive(ctx);
    sourceActive = true;
    log('Reading the original app assignments. The original app is not changed during staging.');
    const snapshot = compactSnapshot(await assignments(ctx.oktaId));
    rec = await save(rec, { stageSnapshot: snapshot, counts: countOf(snapshot), sourceActive: true });
    const made = await createBookmark(ctx, rec, log); rec = made.rec;
    await ensureBookmarkTarget(ctx, rec.bookmarkId);
    const present = await assignments(rec.bookmarkId);
    if (present.groups.length || present.directUsers.length) throw fail('The inactive Bookmark already has assignments. Remove or reconcile them before staging so the final swap starts from a known empty target.', 'UNEXPECTED_ASSIGNMENTS');
    const inactive = await deactivate(rec.bookmarkId);
    if (inactive.status !== 'INACTIVE') throw fail('Okta did not report the staged Bookmark as inactive.', 'DEACTIVATE_VERIFY_FAILED');
    rec = await save(rec, { status: 'staged', bookmarkActive: false, stagedAt: now(), lastError: null });
    await emit(ctx, 'okta_bookmark_staged', 'Inactive Bookmark app staged and target verified; no assignments were copied and the original app is unchanged.', { jobId: job.id, bookmarkId: rec.bookmarkId, counts: rec.counts, launcherUrlSource: rec.launcherUrlSource });
    log('Staging verified. The Bookmark is inactive and unassigned; the original app is unchanged.');
    return publicRecord(rec);
  } catch (e) {
    rec = await save(rec, { status: 'stage_failed', jobId: job.id, lastError: textError(e), sourceActive });
    await emit(ctx, 'okta_bookmark_stage_failed', 'Bookmark staging failed; the original app and its assignments were not changed.', { jobId: job.id, error: textError(e), bookmarkId: rec.bookmarkId });
    throw e;
  }
}

async function restoreSource(ctx, snapshot, log) {
  if (!snapshot) throw fail('No captured source assignments are available to restore.', 'NO_SNAPSHOT');
  await addMissing(ctx.oktaId, snapshot, log);
  await verifyContains(ctx.oktaId, snapshot, 'The original Okta application');
  await ensureActive(ctx.oktaId);
}

async function cutoverRun(ctx, log, job) {
  let rec = await readRecord(ctx);
  let snapshot = null;
  try {
    if (!['staged', 'cutover_failed'].includes(rec.status)) throw fail('Stage and verify the Bookmark app before moving assignments.', 'NOT_STAGED');
    if (!rec.bookmarkId) throw fail('The staged Bookmark app id is missing.', 'NO_BOOKMARK');
    await ensureSourceActive(ctx);
    await ensureBookmarkTarget(ctx, rec.bookmarkId);
    log('Re-reading the original assignments so changes made after staging are included.');
    snapshot = compactSnapshot(await assignments(ctx.oktaId));
    await addMissing(rec.bookmarkId, snapshot, log);
    await verifyExact(rec.bookmarkId, snapshot, 'The Bookmark application');
    await ensureActive(rec.bookmarkId);
    rec = await save(rec, { status: 'cutting_over', jobId: job.id, cutoverSnapshot: snapshot, counts: countOf(snapshot), lastError: null, warning: null, sourceActive: true, bookmarkActive: true });
    log('Bookmark coverage and activation verified. Removing only the captured assignments from the original app.');
    await removeSnapshot(ctx.oktaId, snapshot, log);
    await verifyEmpty(ctx.oktaId, 'The original Okta application');
    await ensureBookmarkTarget(ctx, rec.bookmarkId);
    await verifyContains(rec.bookmarkId, snapshot, 'The Bookmark application');
    await ensureSourceActive(ctx);
    rec = await save(rec, { status: 'swapped', cutoverAt: now(), sourceActive: true, bookmarkActive: true, lastError: null });
    await emit(ctx, 'okta_bookmark_cutover', 'Assignments moved to the Bookmark app. The original SSO app remains active and configured.', { jobId: job.id, bookmarkId: rec.bookmarkId, counts: rec.counts });
    log('Cutover verified. The original app remains ACTIVE and configured with no assignments.');
    return publicRecord(rec);
  } catch (e) {
    let recovery = null;
    if (snapshot) {
      try {
        log('Cutover did not complete. Restoring the original assignments before reporting failure.', 'warn');
        await restoreSource(ctx, snapshot, log);
        await removeSnapshot(rec.bookmarkId, snapshot, log);
        const left = await assignments(rec.bookmarkId);
        if (!left.groups.length && !left.directUsers.length) await deactivate(rec.bookmarkId);
        recovery = 'restored; Bookmark assignments removed and Bookmark deactivated';
      } catch (re) { recovery = 'failed: ' + textError(re); }
    }
    const status = recovery && recovery.indexOf('failed:') === 0 ? 'recovery_failed' : 'cutover_failed';
    const restored = !!(recovery && recovery.indexOf('restored') === 0);
    rec = await save(rec, { status, jobId: job.id, lastError: textError(e), warning: recovery ? 'Automatic source recovery ' + recovery + '.' : null, sourceActive: restored, bookmarkActive: restored ? false : rec.bookmarkActive });
    await emit(ctx, 'okta_bookmark_cutover_failed', 'Assignment cutover failed. ' + (restored ? 'The original assignments were restored and the Bookmark was cleaned up automatically.' : 'Automatic recovery needs attention.'), { jobId: job.id, error: textError(e), recovery });
    if (recovery && recovery.indexOf('failed:') === 0) throw fail(textError(e) + ' Automatic source recovery also ' + recovery + '.', 'RECOVERY_FAILED');
    throw e;
  }
}

async function rollbackRun(ctx, log, job) {
  let rec = await readRecord(ctx);
  try {
    if (!rec.bookmarkId) throw fail('No Bookmark app has been staged for this revision.', 'NO_BOOKMARK');
    const snapshot = rec.cutoverSnapshot || rec.stageSnapshot;
    if (!snapshot) throw fail('No captured assignments are available to restore.', 'NO_SNAPSHOT');
    rec = await save(rec, { status: 'rolling_back', jobId: job.id, lastError: null, warning: null });
    log('Restoring and verifying the original app before changing the Bookmark app.');
    await restoreSource(ctx, snapshot, log);
    rec = await save(rec, { sourceActive: true });
    log('Original assignments verified. Removing only the transferred assignments from the Bookmark app.');
    await removeSnapshot(rec.bookmarkId, snapshot, log);
    const left = await assignments(rec.bookmarkId);
    const leftGroups = ids(left.groups), leftUsers = ids(left.directUsers);
    const transferredGroupsLeft = overlap(leftGroups, ids(snapshot.groups));
    const transferredUsersLeft = overlap(leftUsers, ids(snapshot.directUsers));
    if (transferredGroupsLeft.length || transferredUsersLeft.length) throw fail('Transferred assignments still remain on the Bookmark app.', 'ROLLBACK_VERIFY_FAILED');
    const extraCount = leftGroups.length + leftUsers.length;
    let warning = null;
    let bookmarkActive = true;
    if (!extraCount) {
      const inactive = await deactivate(rec.bookmarkId);
      bookmarkActive = inactive.status === ACTIVE;
      if (bookmarkActive) throw fail('Okta did not report the Bookmark app as inactive after rollback.', 'DEACTIVATE_VERIFY_FAILED');
    } else {
      warning = 'The Bookmark app has ' + extraCount + ' assignment(s) that were not part of this handoff, so it was left active.';
      log(warning, 'warn');
    }
    rec = await save(rec, { status: 'rolled_back', rolledBackAt: now(), sourceActive: true, bookmarkActive, warning, lastError: null });
    await emit(ctx, 'okta_bookmark_rolled_back', 'Original assignments restored first; transferred Bookmark assignments removed. Neither app was deleted.', { jobId: job.id, bookmarkId: rec.bookmarkId, warning });
    log('Rollback verified. Neither Okta application was deleted.');
    return publicRecord(rec);
  } catch (e) {
    rec = await save(rec, { status: 'rollback_failed', jobId: job.id, lastError: textError(e) });
    await emit(ctx, 'okta_bookmark_rollback_failed', 'Rollback needs attention; the Bookmark app was not deleted.', { jobId: job.id, error: textError(e), bookmarkId: rec.bookmarkId });
    throw e;
  }
}

async function start(ctx, action, confirm, reason, runner) {
  assertInput(ctx, action, confirm, reason);
  ctx.reason = String(reason).trim();
  const out = await L.startJob(JOB_PREFIX + ctx.oktaId, ctx.actor, (log, job) => runner(ctx, log, job));
  return out && out.conflict ? out : { id: out.id };
}
async function startStage(ctx, input) { return start(ctx, 'STAGE BOOKMARK', input && input.confirm, input && input.reason, stageRun); }
async function startCutover(ctx, input) { return start(ctx, 'MOVE ASSIGNMENTS', input && input.confirm, input && input.reason, cutoverRun); }
async function startRollback(ctx, input) { return start(ctx, 'RESTORE ASSIGNMENTS', input && input.confirm, input && input.reason, rollbackRun); }

module.exports = { get, startStage, startCutover, startRollback, _test: { assignments, publicRecord, phrase, stageRun, cutoverRun, rollbackRun, key } };
