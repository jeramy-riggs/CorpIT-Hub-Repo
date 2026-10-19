'use strict';
/**
 * oem-v2-store.js — every read and write of the v2 tables (sql/010-oem-v2.sql) plus the legacy write-through into
 * app_matches. DESIGN.md section 3. Pure data access: no Express, no Graph, no Okta. Returns plain camelCase objects.
 *
 *   generations  beginGeneration / commitGeneration / failGeneration / latestGeneration / latestGenerations
 *   tombstones   recordTombstone([q,] rec) / tombstonedIds([q]) / listTombstones / tombstonesByIds / getTombstone / markReappeared
 *   matches      syncMatches / syncAllMatches / listMatches / destinationFor / confirmedElsewhere / setMatch / candidatesFor / recomputeCandidates
 *   revisions    createDraft / updateDraft / approvePlan / transition / setRevisionFields / markLive / supersede /
 *                getRevision / listRevisions / draftFor / liveRevision / latestRevision / newerDraftExists
 *   attempts     createAttempt / finishAttempt / getAttempt / latestAttempt / listAttempts
 *   overrides    recordOverride / listOverrides
 *   mirrors      workItem / workItemByKey / oktaApp / entraApp / spExtras / listWorkApps / addEvent / addEventKey
 *   technician   userPrefs / setUserPref / latestHandoffs / assignedWorkItems / setAssignee   (drop 8)
 *
 * Invariants enforced here, not in the routes:
 *   - a config carrying a secret-looking key is refused (M.assertNoSecrets plus a store-level superset) on every revision write;
 *   - a draft edit is optimistic on `version` (409 {error:'edited by someone else', current});
 *   - a finished attempt and a live/superseded revision are never UPDATEd (except superseded_by/superseded_at);
 *   - a generation row is only ever finished by the run that created it (WHERE id=? AND status='running');
 *   - a tombstone is recorded if absent and never deleted; an invalidated match is never deleted.
 * Errors thrown as {status, error, why, ...} are answered as-is by the routes.
 */
const L = require('./oem-lib');
const M = require('./oem-v2-model');
const { pool, j } = L;

const iso = (d) => (d ? new Date(d).toISOString() : null);
const isQ = (x) => !!(x && typeof x.query === 'function');
const err = (status, error, why, extra) => Object.assign(new Error(error), { status, error, why }, extra || {});
const lc = (s) => (s === null || s === undefined ? null : String(s).toLowerCase());

/* Secrets are never stored (DESIGN.md hard rule). The model's SECRET_KEY_RE is the shared definition; the store is the
   LAST line and refuses a superset of key spellings the model regex does not cover (api_key, credential, access_key...).
   Refusal happens before any write; the stored copy is stripped by the same superset so a value can never land. */
const EXTRA_SECRET_RE = /api[_-]?key|apikey|credential|client[_-]?secret|access[_-]?key|signing[_-]?key|shared[_-]?key|passphrase|bearer/i;
const isSecretKey = (k) => M.SECRET_KEY_RE.test(String(k)) || EXTRA_SECRET_RE.test(String(k));
function assertNoSecrets(cfg) {
  M.assertNoSecrets(cfg);
  const seen = new Set();
  const walk = (v, path) => {
    if (!v || typeof v !== 'object' || seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) { v.forEach((x, i) => walk(x, path + '[' + i + ']')); return; }
    for (const [k, val] of Object.entries(v)) {
      const at = path ? path + '.' + k : k;
      if (isSecretKey(k)) throw err(400, 'secrets are never stored', `The field "${at}" looks like a secret. Secrets are entered once in the Entra portal or handed to the vendor out of band; this tool never stores, displays or logs them.`);
      walk(val, at);
    }
  };
  walk(cfg, '');
}
function stripSecrets(cfg) {
  const seen = new Set();
  const strip = (v) => {
    if (!v || typeof v !== 'object') return v;
    if (seen.has(v)) return null;
    seen.add(v);
    if (Array.isArray(v)) return v.map(strip);
    const out = {};
    for (const [k, val] of Object.entries(v)) if (!isSecretKey(k)) out[k] = strip(val);
    return out;
  };
  return strip(M.stripSecrets(cfg));
}
function lazyDiscovery() { try { return require('./oem-discovery'); } catch (e) { return null; } }
async function rebuildWork() {
  const D = lazyDiscovery();
  if (D && typeof D.buildWorkItems === 'function') { try { await D.buildWorkItems(() => {}); return true; } catch (e) { console.error('[oem-v2-store] buildWorkItems:', e && e.message || e); } }
  return false;
}

/* ------------------------------------------------------------ generations */

async function beginGeneration(sourceKey, opts) {
  const o = opts || {};
  const [r] = await pool.query(`INSERT INTO oem_source_generation (source_key, scope, job_id, status, actor_email) VALUES (?,?,?,'running',?)`, [sourceKey, o.scope || null, o.jobId || null, o.actor || null]);
  return r && r.insertId ? r.insertId : null;
}
async function commitGeneration(id, records, status) {
  if (!id) return false;
  const st = status === 'partial' ? 'partial' : 'success';
  const n = records === undefined || records === null || Number.isNaN(Number(records)) ? null : Number(records);
  const [r] = await pool.query(`UPDATE oem_source_generation SET status='${st}', finished_at=NOW(), records=? WHERE id=? AND status='running'`, [n, id]);
  return !!(r && r.affectedRows);
}
async function failGeneration(id, error) {
  if (!id) return false;
  const [r] = await pool.query(`UPDATE oem_source_generation SET status='failed', finished_at=NOW(), error=? WHERE id=? AND status='running'`, [String(error && error.message || error || 'failed').slice(0, 500), id]);
  return !!(r && r.affectedRows);
}
const genAttempt = (g) => (g ? { id: g.id, at: iso(g.finished_at || g.started_at), status: g.status, error: g.error || null, jobId: g.job_id || null, records: g.records === undefined ? null : g.records } : null);
const genSuccess = (g) => (g ? { id: g.id, at: iso(g.finished_at || g.started_at), records: g.records === undefined ? null : g.records, jobId: g.job_id || null } : null);
/** {lastAttempt, lastSuccess} for one source (scope null = global, scope = Okta id for per-app refreshes). */
async function latestGeneration(sourceKey, scope) {
  const [[la]] = await pool.query(`SELECT id, source_key, scope, job_id, status, started_at, finished_at, records, error FROM oem_source_generation WHERE source_key=? AND scope <=> ? ORDER BY id DESC LIMIT 1`, [sourceKey, scope || null]);
  const [[ls]] = await pool.query(`SELECT id, source_key, scope, job_id, status, started_at, finished_at, records, error FROM oem_source_generation WHERE source_key=? AND scope <=> ? AND status='success' ORDER BY id DESC LIMIT 1`, [sourceKey, scope || null]);
  return { lastAttempt: genAttempt(la), lastSuccess: genSuccess(ls) };
}
/**
 * Map sourceKey -> {lastAttempt,lastSuccess} for every source at one scope.
 * stateflow-10: one query per source (latestGeneration) instead of a LIMIT 400 window over every source — a busy
 * source can push another source's last success out of a fixed window and make it read as "never succeeded".
 */
async function latestGenerations(scope) {
  const [keys] = await pool.query(`SELECT DISTINCT source_key FROM oem_source_generation WHERE scope <=> ?`, [scope || null]);
  const out = {};
  for (const k of keys || []) {
    const key = k.source_key; if (!key) continue;
    out[key] = await latestGeneration(key, scope || null);
  }
  return out;
}

/* ------------------------------------------------------------- tombstones */

const tombRow = (t) => (t ? { entraId: t.entra_id, appId: t.app_id || null, name: t.display_name || null, displayName: t.display_name || null, lastSeenAt: iso(t.last_seen_at), detectedAt: iso(t.detected_at), detectedBy: t.detected_by || null, snapshot: j(t.snapshot, null), reappearedAt: iso(t.reappeared_at) } : null);
/**
 * recordTombstone([q,] rec) — record-if-absent. Accepts (connection, rec) from discovery and (rec) from the routes.
 * rec = {entraId, appId, displayName|name, lastSeenAt, detectedBy, snapshot}. Never deletes, never overwrites.
 */
async function recordTombstone(a, b) {
  const q = isQ(a) ? a : pool; const rec = isQ(a) ? b : a;
  if (!rec || !rec.entraId) throw err(400, 'entraId required', 'A tombstone names the Entra object id that disappeared.');
  const id = lc(rec.entraId);
  const already = !!(await getTombstone(id)); // affectedRows of an ODKU no-op depends on the FOUND_ROWS flag; read first
  const snap = rec.snapshot === undefined || rec.snapshot === null ? null : JSON.stringify(L.redact(rec.snapshot));
  const [r] = await q.query(`INSERT INTO oem_entra_tombstone (entra_id, app_id, display_name, last_seen_at, detected_by, snapshot) VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE entra_id=entra_id`,
    [id, rec.appId || null, rec.displayName || rec.name || null, rec.lastSeenAt ? new Date(rec.lastSeenAt) : null, rec.detectedBy ? String(rec.detectedBy).slice(0, 64) : null, snap]);
  return { entraId: id, name: rec.displayName || rec.name || null, recorded: !already && !!(r && r.affectedRows) };
}
async function tombstonedIds(a) {
  const q = isQ(a) ? a : pool;
  const [rows] = await q.query(`SELECT entra_id FROM oem_entra_tombstone WHERE reappeared_at IS NULL`);
  return new Set((rows || []).map((r) => lc(r.entra_id)));
}
async function listTombstones() {
  const [rows] = await pool.query(`SELECT * FROM oem_entra_tombstone ORDER BY detected_at DESC`);
  return (rows || []).map(tombRow);
}
/** Standing reconciliation state for the refresh center (SPEC 85): open tombstones and matches still invalidated. */
async function reconciliationCounts() {
  const [[t]] = await pool.query(`SELECT COUNT(*) AS c FROM oem_entra_tombstone WHERE reappeared_at IS NULL`);
  const [[m]] = await pool.query(`SELECT COUNT(DISTINCT okta_app_id) AS c FROM oem_app_match WHERE state='invalidated'`);
  return { deletedDestinations: Number(t && t.c) || 0, invalidatedMatches: Number(m && m.c) || 0 };
}
async function tombstonesByIds(ids) {
  const list = [...new Set((ids || []).filter(Boolean).map(lc))];
  const out = {};
  if (!list.length) return out;
  const [rows] = await pool.query(`SELECT * FROM oem_entra_tombstone WHERE entra_id IN (?) AND reappeared_at IS NULL`, [list]);
  for (const r of rows || []) out[lc(r.entra_id)] = tombRow(r);
  return out;
}
async function getTombstone(entraId) { if (!entraId) return null; const m = await tombstonesByIds([entraId]); return m[lc(entraId)] || null; }
/** The same OBJECT id seen again (never a same-name recreation: that has a new id and is never rebound). */
async function markReappeared(entraId) {
  const [r] = await pool.query(`UPDATE oem_entra_tombstone SET reappeared_at=NOW() WHERE entra_id=? AND reappeared_at IS NULL`, [lc(entraId)]);
  return !!(r && r.affectedRows);
}

/* ---------------------------------------------------------------- matches */

const LEGACY_STATE = { manual_confirmed: 'confirmed', manual_staged: 'shortlisted', manual_rejected: 'rejected' };
const matchRow = (m) => (m ? { id: m.id, oktaId: m.okta_app_id, entraId: lc(m.entra_sp_id), name: m.entra_display_name || null, state: m.state, score: m.score === null || m.score === undefined ? null : Number(m.score), method: m.method || null, evidence: j(m.evidence, null), note: m.reason || null, legacyRowId: m.legacy_row_id || null, by: m.created_by || null, at: iso(m.updated_at || m.created_at), createdAt: iso(m.created_at), invalidatedAt: iso(m.invalidated_at), invalidatedReason: m.invalidated_reason || null, supersededBy: m.superseded_by || null } : null);

async function listMatches(oktaId) {
  const [rows] = await pool.query(`SELECT * FROM oem_app_match WHERE okta_app_id=? ORDER BY id DESC`, [oktaId]);
  return (rows || []).map(matchRow);
}
async function invalidateMatchesFor(entraId, reason) {
  const [r] = await pool.query(`UPDATE oem_app_match SET state='invalidated', invalidated_at=NOW(), invalidated_reason=? WHERE entra_sp_id=? AND state IN ('suggested','shortlisted','confirmed')`, [String(reason || 'deleted in Entra').slice(0, 255), lc(entraId)]);
  return r ? r.affectedRows || 0 : 0;
}
/**
 * syncMatches(oktaId) — bring oem_app_match in line with the legacy decision table and the matcher's candidates:
 * confirmed=manual_confirmed, shortlisted=manual_staged, rejected=manual_rejected, suggested=candidates. A tombstoned
 * target becomes invalidated (never deleted); a confirmed/shortlisted row with no legacy decision left is superseded.
 */
async function syncMatches(oktaId) {
  const [legacy] = await pool.query(`SELECT id, entra_app_id, entra_app_display_name, match_confidence, match_method, notes, created_by FROM app_matches WHERE okta_app_id=?`, [oktaId]);
  const [cands] = await pool.query(`SELECT c.entra_app_id, c.score, c.method, c.evidence, e.display_name FROM oem_match_candidate c LEFT JOIN entra_apps e ON e.entra_id=c.entra_app_id WHERE c.okta_app_id=?`, [oktaId]);
  const existing = await listMatches(oktaId);
  const tomb = await tombstonedIds();
  const desired = new Map();
  for (const r of legacy || []) {
    const id = lc(r.entra_app_id); if (!id) continue;
    const state = LEGACY_STATE[r.match_confidence] || 'suggested';
    const cur = desired.get(id);
    if (cur && cur.rank <= rank(state)) continue;
    desired.set(id, { state, rank: rank(state), name: r.entra_app_display_name || null, method: r.match_method || null, note: r.notes || null, by: r.created_by || null, legacyRowId: r.id, score: null, evidence: null });
  }
  for (const c of cands || []) {
    const id = lc(c.entra_app_id); if (!id || desired.has(id)) continue;
    desired.set(id, { state: 'suggested', rank: rank('suggested'), name: c.display_name || null, method: c.method || null, note: null, by: 'matcher', legacyRowId: null, score: c.score === null ? null : Number(c.score), evidence: j(c.evidence, null) });
  }
  const byEntra = new Map();
  for (const m of existing) if (!byEntra.has(m.entraId)) byEntra.set(m.entraId, m);
  let changed = 0;
  for (const [id, d] of desired) {
    if (tomb.has(id)) { changed += await invalidateMatchesFor(id, 'deleted in Entra'); if (!byEntra.has(id)) { await pool.query(`INSERT INTO oem_app_match (okta_app_id, entra_sp_id, entra_display_name, state, score, method, evidence, reason, legacy_row_id, created_by, invalidated_at, invalidated_reason) VALUES (?,?,?,'invalidated',?,?,?,?,?,?,NOW(),'deleted in Entra')`, [oktaId, id, d.name, d.score, d.method, d.evidence === null ? null : JSON.stringify(d.evidence), d.note, d.legacyRowId, d.by]); changed++; } continue; }
    const cur = byEntra.get(id);
    if (!cur) { await pool.query(`INSERT INTO oem_app_match (okta_app_id, entra_sp_id, entra_display_name, state, score, method, evidence, reason, legacy_row_id, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)`, [oktaId, id, d.name, d.state, d.score, d.method, d.evidence === null ? null : JSON.stringify(d.evidence), d.note, d.legacyRowId, d.by]); changed++; continue; }
    if (cur.state === 'suggested' && d.state === 'suggested' && d.score !== null && (cur.score !== d.score || cur.method !== d.method)) {
      // conf-1: a re-scored candidate refreshes its suggested row, so the reliable pick reads the matcher's latest evidence
      await pool.query(`UPDATE oem_app_match SET score=?, method=?, evidence=? WHERE id=?`, [d.score, d.method, d.evidence === null ? null : JSON.stringify(d.evidence), cur.id]); changed++; continue;
    }
    if (cur.state === d.state || cur.state === 'invalidated') continue; // tombstone-5: an invalidated row stays invalidated even after the target reappears; a person re-confirms
    if (cur.state === 'rejected' && d.state === 'suggested') continue;
    await pool.query(`UPDATE oem_app_match SET state=?, entra_display_name=COALESCE(?, entra_display_name), reason=COALESCE(?, reason), legacy_row_id=COALESCE(?, legacy_row_id), created_by=COALESCE(?, created_by) WHERE id=?`, [d.state, d.name, d.note, d.legacyRowId, d.by, cur.id]);
    changed++;
  }
  for (const m of existing) {
    if (!['confirmed', 'shortlisted'].includes(m.state)) continue;
    const d = desired.get(m.entraId);
    if (d && (d.state === 'confirmed' || d.state === 'shortlisted')) continue;
    await pool.query(`UPDATE oem_app_match SET state='superseded' WHERE id=? AND state IN ('confirmed','shortlisted')`, [m.id]); changed++;
  }
  return { changed, matches: await listMatches(oktaId) };
}
const RANK = { confirmed: 0, shortlisted: 1, rejected: 2, invalidated: 3, suggested: 4, superseded: 5 };
/**
 * syncAllMatches(ids?) — syncMatches for every application work item (or the given Okta ids). Runs at the end of every
 * work-item rebuild so oem_app_match (what listWorkApps and the workspace read) never lags the legacy decisions, the
 * matcher's candidates or the tombstones. One app failing never stops the rest; failures are returned, not thrown.
 */
async function syncAllMatches(ids) {
  let list = Array.isArray(ids) ? ids.filter(Boolean) : null;
  if (!list) {
    const [rows] = await pool.query(`SELECT DISTINCT source_id FROM oem_work_item WHERE category='applications' AND source_kind='okta_app' AND source_id IS NOT NULL`);
    list = (rows || []).map((r) => r.source_id).filter(Boolean);
  }
  const out = { apps: list.length, changed: 0, failed: [] };
  for (const id of list) {
    try { const r = await syncMatches(id); out.changed += r.changed || 0; }
    catch (e) { out.failed.push({ oktaId: id, error: String(e && e.message || e).slice(0, 200) }); }
  }
  return out;
}
function rank(state) { return RANK[state] === undefined ? 9 : RANK[state]; }

/**
 * destinationFor(oktaId) -> {state:'none'|'suggested'|'shortlisted'|'confirmed'|'invalidated', entraId, name, appId, portal,
 * enabled, ssoMode, users, groups, lastSeenAt, tombstone, match}. A confirmed/shortlisted target that is tombstoned reads
 * as invalidated even if the invalidation write has not landed yet (bug 1: never a stale destination).
 */
/**
 * conf-1: which suggested row, if any, is reliable enough to be the destination (model.reliableSuggestion decides:
 * endpoint evidence, score >= RELIABLE_SCORE, strictly ahead). Returns {row, why, reason}; `why` is the sentence the page
 * shows when nothing qualifies ("No reliable match found — …"), null when a row qualifies or nothing is suggested.
 */
function pickSuggested(rows) {
  const sug = (rows || []).filter((m) => m && m.state === 'suggested');
  if (!sug.length) return { row: null, why: null, reason: 'no_candidates' };
  const r = M.reliableSuggestion(sug.map((m) => ({ row: m, entraId: m.entraId, name: m.name, score: m.score, state: m.state, hostMatch: hostMatchOf([m.method], m.evidence) })));
  return { row: r.ok && r.best ? r.best.row : null, why: r.ok ? null : r.why, reason: r.reason };
}
async function destinationFor(oktaId, matches) {
  const rows = matches || await listMatches(oktaId);
  const pick = (st) => rows.find((m) => m.state === st) || null;
  let m = pick('confirmed') || pick('shortlisted') || pick('invalidated') || null;
  const none = { state: 'none', entraId: null, name: null, appId: null, portal: null, enabled: null, ssoMode: null, users: null, groups: null, lastSeenAt: null, tombstone: null, match: null };
  if (!m) {
    // a suggestion for a deleted app is not a candidate (stateflow-1); the reliable pick is made among the live ones
    const tombs = rows.some((r) => r.state === 'suggested') ? await tombstonedIds() : null;
    const sug = pickSuggested(rows.filter((r) => r.state === 'suggested' && !(tombs && tombs.has(r.entraId))));
    m = sug.row;
    if (!m) return sug.why ? Object.assign({}, none, { noReliable: sug.why, reliability: sug.reason }) : none;
  }
  const tomb = await getTombstone(m.entraId);
  if (tomb && m.state === 'suggested') return none; // stateflow-1: a bare suggestion for a deleted app is not a destination
  let state = m.state === 'suggested' ? 'suggested' : m.state;
  if (tomb && state !== 'invalidated') state = 'invalidated';
  const e = await entraApp(m.entraId);
  return {
    state, entraId: m.entraId, name: (e && e.name) || m.name || (tomb && tomb.name) || null, appId: (e && e.appId) || (tomb && tomb.appId) || null,
    portal: portalUrl(m.entraId, (e && e.appId) || (tomb && tomb.appId) || null),
    enabled: e ? e.enabled : null, ssoMode: e ? e.ssoMode : null, users: e ? e.users : null, groups: e ? e.groups : null, lastSeenAt: e ? e.lastSeenAt : (tomb ? tomb.lastSeenAt : null),
    tombstone: tomb ? { entraId: tomb.entraId, name: tomb.name, lastSeenAt: tomb.lastSeenAt, detectedAt: tomb.detectedAt } : null,
    match: { id: m.id, state: m.state, score: m.score, method: m.method, hostMatch: hostMatchOf([m.method], m.evidence), by: m.by, at: m.at, note: m.note, invalidatedReason: m.invalidatedReason },
  };
}
const portalUrl = (entraId, appId) => (entraId ? `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/${entraId}/appId/${appId || ''}` : null);

/** Another Okta app that already holds this Entra principal as confirmed (v2 table first, legacy second). */
async function confirmedElsewhere(entraId, oktaId) {
  const id = lc(entraId);
  const [v2] = await pool.query(`SELECT okta_app_id FROM oem_app_match WHERE entra_sp_id=? AND state='confirmed' AND okta_app_id<>? LIMIT 1`, [id, oktaId]);
  let other = v2 && v2[0] ? v2[0].okta_app_id : null;
  if (!other) { const [lg] = await pool.query(`SELECT okta_app_id, okta_app_label FROM app_matches WHERE entra_app_id=? AND match_confidence='manual_confirmed' AND okta_app_id<>? LIMIT 1`, [id, oktaId]); if (lg && lg[0]) return { oktaId: lg[0].okta_app_id, label: lg[0].okta_app_label || null }; return null; }
  const [[o]] = await pool.query(`SELECT label FROM okta_apps WHERE okta_id=?`, [other]);
  return { oktaId: other, label: o ? o.label : null };
}

/**
 * setMatch(oktaId, {action:'shortlist'|'confirm'|'reject'|'unreject'|'clear', entraId, note, actor})
 *  -> {ok, destination, undo:{action, entraId}, legacy}. Writes oem_app_match, writes through to app_matches exactly as
 * POST /api/oem/matches/decide does, records the work event and rebuilds the work item. Refuses a tombstoned target (409)
 * and a target another Okta app holds as confirmed unless a note explains it (409).
 */
async function setMatch(oktaId, opts) {
  const o = opts || {};
  const action = String(o.action || '');
  if (!['shortlist', 'confirm', 'reject', 'unreject', 'clear'].includes(action)) throw err(400, 'unknown action', 'action must be shortlist, confirm, reject, unreject or clear.');
  const actor = o.actor || 'anonymous';
  if (o.note) M.assertNoSecretText(o.note, 'note'); // secrets-4: a note is free text that lands in two tables and the event log
  const note = o.note ? String(o.note).slice(0, 500) : null;
  const [[okta]] = await pool.query(`SELECT okta_id, label FROM okta_apps WHERE okta_id=?`, [oktaId]);
  if (!okta) throw err(404, 'unknown Okta app', 'No Okta application with id ' + oktaId + ' is in the mirror.');
  const entraId = action === 'clear' ? null : lc(o.entraId);
  let entra = null;
  if (action !== 'clear') {
    if (!entraId) throw err(400, 'entraId required', 'Name the Entra service principal (object id) the decision is about.');
    const tomb = await getTombstone(entraId);
    if (tomb && action !== 'reject' && action !== 'unreject') throw err(409, `That application was deleted from Entra on ${(tomb.detectedAt || '').slice(0, 10)}; pick a replacement or create a new Entra app`, 'The Entra object id is recorded as a tombstone. A recreated app has a new object id and must be matched again.', { tombstone: tomb });
    const [[e]] = await pool.query(`SELECT entra_id, display_name FROM entra_apps WHERE entra_id=?`, [entraId]);
    if (!e && !tomb) throw err(404, 'unknown Entra app (not in the mirror)', 'Refresh the Entra mirror, then choose again.');
    entra = e || { entra_id: entraId, display_name: tomb ? tomb.name : null };
    if (action === 'confirm' || action === 'shortlist') {
      const other = await confirmedElsewhere(entraId, oktaId);
      if (other && !note) throw err(409, `${entra.display_name || entraId} is already confirmed for ${other.label || other.oktaId}`, 'Two Okta applications cannot share one Entra destination unless you say why; add a note to record the decision anyway.', { conflict: other });
    }
  }
  const before = await destinationFor(oktaId);
  // stateflow-7: the caller says what it rendered; a decision taken against a destination someone else has since
  // changed is refused instead of silently replacing their choice.
  if (o.expect && typeof o.expect === 'object') {
    const ex = o.expect;
    const exState = ex.state === undefined || ex.state === null ? undefined : String(ex.state);
    const exId = ex.entraId === undefined ? undefined : (ex.entraId === null || ex.entraId === '' ? null : lc(ex.entraId));
    const stateMismatch = exState !== undefined && exState !== before.state;
    const idMismatch = exId !== undefined && exId !== (before.entraId || null);
    if (stateMismatch || idMismatch) throw err(409, 'destination changed by someone else', `You decided against ${exState || 'a destination'}${exId ? ' ' + exId : ''}, but the destination is now ${before.state}${before.entraId ? ' ' + before.entraId : ''}. Reload and decide again.`, { current: before, expected: { state: exState, entraId: exId } });
  }
  const undo = undoFor(action, entraId, before);

  /* legacy write-through: identical to POST /api/oem/matches/decide */
  const [rows] = await pool.query(`SELECT id, entra_app_id, match_confidence FROM app_matches WHERE okta_app_id=?`, [oktaId]);
  const prior = rows.filter((r) => /^manual_(confirmed|staged)$/.test(r.match_confidence));
  let legacy;
  if (action === 'confirm' || action === 'shortlist') {
    const conf = action === 'confirm' ? 'manual_confirmed' : 'manual_staged';
    const drop = rows.filter((r) => !/^manual_rejected$/.test(r.match_confidence) && !(r.match_confidence === conf && lc(r.entra_app_id) === entraId));
    if (drop.length) await pool.query(`DELETE FROM app_matches WHERE id IN (?)`, [drop.map((r) => r.id)]);
    const same = rows.find((r) => r.match_confidence === conf && lc(r.entra_app_id) === entraId);
    if (same) { await pool.query(`UPDATE app_matches SET notes=?, created_by=?, last_verified_at=NOW() WHERE id=?`, [note, actor, same.id]); legacy = { id: same.id }; }
    else { const [ins] = await pool.query(`INSERT INTO app_matches (okta_app_id, okta_app_label, entra_app_id, entra_app_display_name, match_confidence, match_method, notes, created_by, last_verified_at) VALUES (?,?,?,?,?,'manual',?,?,NOW())`, [oktaId, okta.label, entraId, entra.display_name, conf, note, actor]); legacy = { id: ins.insertId }; }
    const rej = rows.find((r) => r.match_confidence === 'manual_rejected' && lc(r.entra_app_id) === entraId);
    if (rej) await pool.query(`DELETE FROM app_matches WHERE id=?`, [rej.id]);
    legacy.replaced = prior.filter((p) => lc(p.entra_app_id) !== entraId).map((p) => lc(p.entra_app_id));
  } else if (action === 'reject') {
    const autoSame = rows.find((r) => lc(r.entra_app_id) === entraId && !/^manual_/.test(r.match_confidence));
    if (autoSame) await pool.query(`UPDATE app_matches SET match_confidence='manual_rejected', notes=?, created_by=?, last_verified_at=NOW() WHERE id=?`, [note, actor, autoSame.id]);
    else if (!rows.some((r) => lc(r.entra_app_id) === entraId && r.match_confidence === 'manual_rejected')) await pool.query(`INSERT INTO app_matches (okta_app_id, okta_app_label, entra_app_id, entra_app_display_name, match_confidence, match_method, notes, created_by, last_verified_at) VALUES (?,?,?,?,'manual_rejected','manual',?,?,NOW())`, [oktaId, okta.label, entraId, entra.display_name, note, actor]);
    const conf = rows.find((r) => lc(r.entra_app_id) === entraId && /^manual_(confirmed|staged)$/.test(r.match_confidence));
    if (conf) await pool.query(`DELETE FROM app_matches WHERE id=?`, [conf.id]);
    legacy = { rejected: entraId };
  } else if (action === 'unreject') {
    const rej = rows.filter((r) => lc(r.entra_app_id) === entraId && r.match_confidence === 'manual_rejected');
    if (rej.length) await pool.query(`DELETE FROM app_matches WHERE id IN (?)`, [rej.map((r) => r.id)]);
    legacy = { unrejected: entraId };
  } else {
    if (prior.length) await pool.query(`DELETE FROM app_matches WHERE id IN (?)`, [prior.map((r) => r.id)]);
    legacy = { cleared: prior.map((p) => lc(p.entra_app_id)) };
  }

  /* v2 table */
  const v2 = await listMatches(oktaId);
  // stateflow-1: an invalidated (tombstoned) row is still the destination the workspace shows, so a clear or a
  // decision for another id must supersede it too; otherwise destinationFor keeps returning the deleted app.
  const ACTIVE_STATES = ['confirmed', 'shortlisted', 'invalidated'];
  const active = v2.filter((m) => ACTIVE_STATES.includes(m.state));
  const upsert = async (state) => {
    const cur = v2.find((m) => m.entraId === entraId && m.state !== 'superseded' && m.state !== 'invalidated');
    if (cur) { await pool.query(`UPDATE oem_app_match SET state=?, entra_display_name=?, reason=?, created_by=?, legacy_row_id=COALESCE(?, legacy_row_id) WHERE id=?`, [state, entra.display_name, note, actor, legacy.id || null, cur.id]); return cur.id; }
    const [ins] = await pool.query(`INSERT INTO oem_app_match (okta_app_id, entra_sp_id, entra_display_name, state, method, reason, legacy_row_id, created_by) VALUES (?,?,?,?,'manual',?,?,?)`, [oktaId, entraId, entra.display_name, state, note, legacy.id || null, actor]);
    return ins.insertId;
  };
  if (action === 'confirm' || action === 'shortlist') {
    const id = await upsert(action === 'confirm' ? 'confirmed' : 'shortlisted');
    const others = active.filter((m) => m.entraId !== entraId);
    if (others.length) await pool.query(`UPDATE oem_app_match SET state='superseded', superseded_by=? WHERE id IN (?) AND state IN ('confirmed','shortlisted','invalidated')`, [id, others.map((m) => m.id)]);
  } else if (action === 'reject') {
    await upsert('rejected');
  } else if (action === 'unreject') {
    const cur = v2.find((m) => m.entraId === entraId && m.state === 'rejected');
    if (cur) await pool.query(`UPDATE oem_app_match SET state='suggested', reason=?, created_by=? WHERE id=? AND state='rejected'`, [note, actor, cur.id]);
  } else if (active.length) {
    await pool.query(`UPDATE oem_app_match SET state='superseded' WHERE id IN (?) AND state IN ('confirmed','shortlisted','invalidated')`, [active.map((m) => m.id)]);
  }

  await addEvent(oktaId, 'match_' + (action === 'shortlist' ? 'stage' : action), { note, actor, evidence: { entraAppId: entraId, entraName: entra ? entra.display_name : null, replaced: legacy.replaced || legacy.cleared || null } });
  await rebuildWork();
  const destination = await destinationFor(oktaId);
  return { ok: true, action, destination, undo, legacy };
}
function undoFor(action, entraId, before) {
  const prevAction = before.state === 'confirmed' ? 'confirm' : before.state === 'shortlisted' ? 'shortlist' : null;
  switch (action) {
    case 'confirm': case 'shortlist':
      if (prevAction && before.entraId && before.entraId !== entraId) return { action: prevAction, entraId: before.entraId };
      if (prevAction === 'shortlist' && action === 'confirm' && before.entraId === entraId) return { action: 'shortlist', entraId };
      return { action: 'clear', entraId };
    case 'reject': return { action: 'unreject', entraId };
    case 'unreject': return { action: 'reject', entraId };
    default: return prevAction && before.entraId ? { action: prevAction, entraId: before.entraId } : null;
  }
}

/** Candidates for the workspace: matcher rows plus suggested/rejected v2 rows, joined to the mirror, tombstones excluded. */
async function candidatesFor(oktaId, matches) {
  const v2 = matches || await listMatches(oktaId);
  const [cands] = await pool.query(`SELECT c.entra_app_id, c.score, c.method, c.evidence, c.env_conflict FROM oem_match_candidate c WHERE c.okta_app_id=? ORDER BY c.score DESC`, [oktaId]);
  const tomb = await tombstonedIds();
  const byId = new Map();
  for (const c of cands || []) { const id = lc(c.entra_app_id); if (!id || tomb.has(id)) continue; byId.set(id, { entraId: id, score: c.score === null ? 0 : Number(c.score), methods: [c.method].filter(Boolean), evidence: j(c.evidence, null), envConflict: !!c.env_conflict, state: 'suggested' }); }
  for (const m of v2) {
    if (!['suggested', 'rejected', 'shortlisted', 'confirmed'].includes(m.state) || tomb.has(m.entraId)) continue;
    const cur = byId.get(m.entraId) || { entraId: m.entraId, score: m.score || 0, methods: [], evidence: m.evidence, envConflict: false, state: 'suggested' };
    if (m.name && !cur.name) cur.name = m.name;   /* conf-1: the name the match recorded survives the Entra row leaving the mirror */
    if (m.method && !cur.methods.includes(m.method)) cur.methods.push(m.method);
    if (m.score !== null && m.score > cur.score) cur.score = m.score;
    cur.state = m.state;
    byId.set(m.entraId, cur);
  }
  const ids = [...byId.keys()];
  if (!ids.length) return [];
  const [apps] = await pool.query(`SELECT entra_id, app_id, display_name, preferred_single_sign_on_mode, account_enabled, assigned_user_count, assigned_group_count, homepage_url FROM entra_apps WHERE entra_id IN (?)`, [ids]);
  const mirror = new Map((apps || []).map((a) => [lc(a.entra_id), a]));
  return ids.map((id) => {
    const c = byId.get(id), a = mirror.get(id);
    const ev = c.evidence && typeof c.evidence === 'object' ? c.evidence : null;
    const why = ev ? (Array.isArray(ev.why) ? ev.why.join('; ') : ev.why || ev.reason || Object.entries(ev).filter(([k, v]) => typeof v === 'string').map(([k, v]) => k + ': ' + v).join('; ')) : (c.methods.length ? 'matched on ' + c.methods.join(', ') : '');
    return { entraId: id, name: a ? a.display_name : (c.name || null), inMirror: !!a, appId: a ? a.app_id : null, score: c.score, pct: Math.round(Math.min(1, Math.max(0, c.score)) * 100), methods: c.methods, why: why || null, hostMatch: hostMatchOf(c.methods, ev), ssoMode: a ? a.preferred_single_sign_on_mode : null, enabled: a ? !!a.account_enabled : null, users: a ? a.assigned_user_count : null, groups: a ? a.assigned_group_count : null, state: c.state, envConflict: c.envConflict };
  }).sort((x, y) => ((y.hostMatch ? 1 : 0) - (x.hostMatch ? 1 : 0)) || (y.score - x.score) || String(x.name || '').localeCompare(String(y.name || ''))); // conf-1: endpoint-backed first, then score
}
/**
 * honesty-13: the server decides whether a candidate was matched on an endpoint (host / reply URL / ACS / redirect /
 * domain) or on its name only. Any method name or evidence kind/key/why naming an endpoint counts; the page prints
 * "host match" / "name only" from this field and nothing else.
 */
const HOST_MATCH_RE = /host|reply|acs|url|uri|redirect|domain|launcher|audience/i;
function hostMatchOf(methods, ev) {
  if ((methods || []).some((m) => HOST_MATCH_RE.test(String(m)))) return true;
  if (!ev || typeof ev !== 'object') return false;
  const texts = [];
  if (Array.isArray(ev.why)) texts.push(...ev.why); else if (ev.why) texts.push(ev.why);
  for (const k of ['kind', 'method', 'reason', 'matchedOn', 'matched_on']) if (ev[k]) texts.push(Array.isArray(ev[k]) ? ev[k].join(' ') : ev[k]);
  if (texts.some((t) => HOST_MATCH_RE.test(String(t)))) return true;
  return Object.keys(ev).some((k) => k !== 'why' && HOST_MATCH_RE.test(k) && ev[k] !== null && ev[k] !== undefined && ev[k] !== false && ev[k] !== '');
}
/** Name/host similarity over the mirror (no network); the best hits are recorded as suggested rows in oem_app_match. */
async function recomputeCandidates(oktaId) {
  const [[okta]] = await pool.query(`SELECT okta_id, name, label, raw_json FROM okta_apps WHERE okta_id=?`, [oktaId]);
  if (!okta) throw err(404, 'unknown Okta app', 'No Okta application with id ' + oktaId + ' is in the mirror.');
  const raw = j(okta.raw_json, {}) || {};
  const settings = (raw.settings && raw.settings.app) || {};
  const hosts = new Set();
  for (const u of [settings.url, settings.loginUrl, settings.baseUrl, settings.siteUrl, settings.audience, (raw._links && raw._links.appLinks && raw._links.appLinks[0] && raw._links.appLinks[0].href)]) { const h = typeof L.hostOf === 'function' ? L.hostOf(u) : null; if (h) hosts.add(String(h).toLowerCase()); }
  const oktaTokens = typeof L.tokens === 'function' ? L.tokens((okta.label || '') + ' ' + (okta.name || '')) : [];
  const tomb = await tombstonedIds();
  const v2 = await listMatches(oktaId);
  const [apps] = await pool.query(`SELECT entra_id, display_name, homepage_url, raw_json FROM entra_apps`);
  const hits = [];
  for (const a of apps || []) {
    const id = lc(a.entra_id); if (!id || tomb.has(id)) continue;
    const methods = [];
    let score = 0;
    const nameScore = typeof L.jaccard === 'function' ? L.jaccard(oktaTokens, L.tokens(a.display_name || '')) : 0;
    if (nameScore >= 0.5) { methods.push('name'); score = Math.max(score, nameScore); }
    if (hosts.size) {
      const er = j(a.raw_json, {}) || {};
      const eh = new Set();
      for (const u of [a.homepage_url, er.homepage, er.loginUrl].concat(er.replyUrls || [], er.servicePrincipalNames || [])) { const h = typeof L.hostOf === 'function' ? L.hostOf(u) : null; if (h) eh.add(String(h).toLowerCase()); }
      if ([...hosts].some((h) => eh.has(h))) { methods.push('host'); score = Math.max(score, 0.9); }
    }
    if (!methods.length) continue;
    hits.push({ entraId: id, name: a.display_name || null, score: +score.toFixed(3), methods });
  }
  hits.sort((x, y) => y.score - x.score);
  const top = hits.slice(0, 10);
  for (const h of top) {
    const cur = v2.find((m) => m.entraId === h.entraId && m.state !== 'superseded');
    if (cur) continue;
    await pool.query(`INSERT INTO oem_app_match (okta_app_id, entra_sp_id, entra_display_name, state, score, method, evidence, created_by) VALUES (?,?,?,'suggested',?,?,?,'recompute')`, [oktaId, h.entraId, h.name, h.score, h.methods.join('+'), JSON.stringify({ why: h.methods.map((m) => (m === 'name' ? 'display name resembles the Okta label' : 'destination host matches')) })]);
  }
  return candidatesFor(oktaId);
}

/* -------------------------------------------------------------- revisions */

const REV_STATES = ['draft', 'plan_approved', 'entra_configured', 'awaiting_vendor', 'awaiting_verification', 'awaiting_live_approval', 'live', 'superseded'];
const FROZEN = new Set(['live', 'superseded']);
function revRow(r) {
  if (!r) return null;
  const plan = j(r.plan, null);
  const config = stripSecrets(j(r.config, {}) || {});
  // honesty-9 (F2 writes it): owner_confirmed_note holds the attestation object as a JSON string; expose it parsed.
  const noteRaw = r.owner_confirmed_note || null;
  let ownerAttestation = null;
  if (noteRaw && /^\s*\{/.test(String(noteRaw))) { const parsed = j(noteRaw, null); if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) ownerAttestation = parsed; }
  return {
    id: r.id, oktaId: r.okta_app_id, revisionNo: r.revision_no, matchId: r.match_id || null, entraId: lc(r.entra_sp_id), protocol: r.protocol, state: r.state,
    config, createNew: config.createNew === true, adopt: config.adopt === true, adopted: config.adopt === true && config.adopted && typeof config.adopted === 'object' ? config.adopted : null, plan: plan ? { steps: plan.steps || [], hash: plan.hash || r.plan_hash || null } : null, planHash: r.plan_hash || null,
    ownerAttestation,
    liveAttemptId: r.live_attempt_id === null || r.live_attempt_id === undefined ? null : Number(r.live_attempt_id), liveGenerations: j(r.live_generations, null),
    planApproved: r.plan_approved_hash ? { by: r.plan_approved_by || null, at: iso(r.plan_approved_at), hash: r.plan_approved_hash } : null, planApprovedHash: r.plan_approved_hash || null,
    migrationId: r.migration_id || null, entraConfiguredAt: iso(r.entra_configured_at),
    vendor: r.vendor_template_key || r.vendor_ready_at ? { templateKey: r.vendor_template_key || null, templateVersion: r.vendor_template_version || null, readyBy: r.vendor_ready_by || null, readyAt: iso(r.vendor_ready_at), note: r.vendor_ready_note || null } : null,
    ownerConfirm: r.owner_confirmed_at ? { by: r.owner_confirmed_by || null, at: iso(r.owner_confirmed_at), note: r.owner_confirmed_note || null } : null, ownerConfirmedAt: iso(r.owner_confirmed_at), ownerConfirmedBy: r.owner_confirmed_by || null,
    live: r.live_at ? { by: r.live_by || null, at: iso(r.live_at) } : null, supersededBy: r.superseded_by || null, supersededAt: iso(r.superseded_at),
    version: r.version, createdBy: r.created_by || null, createdAt: iso(r.created_at), updatedAt: iso(r.updated_at), editable: r.state === 'draft',
  };
}
async function getRevision(id) { const [[r]] = await pool.query(`SELECT * FROM oem_config_revision WHERE id=?`, [id]); return revRow(r); }
async function listRevisions(oktaId) { const [rows] = await pool.query(`SELECT * FROM oem_config_revision WHERE okta_app_id=? ORDER BY id DESC`, [oktaId]); return (rows || []).map(revRow); }
async function draftFor(oktaId) { const [[r]] = await pool.query(`SELECT * FROM oem_config_revision WHERE okta_app_id=? AND state='draft' ORDER BY id DESC LIMIT 1`, [oktaId]); return revRow(r); }
async function liveRevision(oktaId) { const [[r]] = await pool.query(`SELECT * FROM oem_config_revision WHERE okta_app_id=? AND state='live' ORDER BY id DESC LIMIT 1`, [oktaId]); return revRow(r); }
/** The revision the workspace shows: the newest that is not superseded. */
async function latestRevision(oktaId) { const [[r]] = await pool.query(`SELECT * FROM oem_config_revision WHERE okta_app_id=? AND state<>'superseded' ORDER BY id DESC LIMIT 1`, [oktaId]); return revRow(r); }
async function newerDraftExists(rev) {
  if (!rev) return false;
  const [rows] = await pool.query(`SELECT id FROM oem_config_revision WHERE okta_app_id=? AND id>? AND state<>'superseded' LIMIT 1`, [rev.oktaId, rev.id]);
  return !!(rows && rows.length);
}
function buildPlan(protocol, cfg, entraId) { return M.planFor(protocol, { entraId: cfg.createNew ? null : entraId, config: cfg, createNew: !!cfg.createNew, displayName: cfg.displayName }); }

/**
 * createDraft(oktaId, {protocol, config, entraId, matchId, actor}) — one draft per app at a time (409 with the existing
 * draft). Forks the live revision's config when there is one (revision_no + 1). Secrets refused.
 */
/** States a draft may overtake: in flight, not yet live. Live rows are only ever superseded by markLive. */
const IN_FLIGHT = ['plan_approved', 'entra_configured', 'awaiting_vendor', 'awaiting_verification', 'awaiting_live_approval'];
/**
 * createDraft(oktaId, {config, protocol, entraId, matchId, actor, createNew})
 * stateflow-8: forks from latestRevision (the newest non-superseded row, live or in flight) so an edit after
 * plan approval carries the approved config forward, and the in-flight sibling is superseded by the new draft
 * (event 'revision_superseded_by_draft') so two revisions can never both be "the current one".
 * stateflow-5: `createNew` is server-owned — the client copy is dropped; only opts.createNew === true sets it.
 */
async function createDraft(oktaId, opts) {
  const o = opts || {};
  /* f14: adopt === true records a revision that keeps the existing Entra configuration as-is (server-owned like
     createNew; the snapshot in opts.adopted is what the adopt route just read from Graph). It does not fork the base
     config — the adopted config IS the Entra configuration — and supersedeDraft lets it replace an open draft. */
  const adopt = o.adopt === true;
  const existing = await draftFor(oktaId);
  if (existing && !adopt) throw err(409, 'a draft already exists', 'Edit or approve the existing draft; a second draft would fork the same revision.', { existing });
  const base = await latestRevision(oktaId);
  /* f15: an adopted revision replaces exactly the revision the adopt route saw (opts.replaces: a draft, or an earlier
     adopted revision that is not Live — re-adopting re-reads Entra and records the new state). The check is made here,
     after the route's Graph reads, so a revision that appeared or moved meanwhile (someone approved the draft and
     started an Entra write) is refused rather than superseded underneath its engine run. */
  let replaces = null;
  if (adopt) {
    const cur = base && base.state !== 'live' ? base : null;
    const want = o.replaces === undefined || o.replaces === null ? null : Number(o.replaces);
    const curAdopted = !!(cur && (cur.adopt === true || (cur.config && cur.config.adopt === true)));
    if (cur && !(cur.state === 'draft' || curAdopted)) throw err(409, 'a revision is already in progress', `Revision ${cur.revisionNo} is ${M.STATE_LABEL[cur.state] || cur.state}; adoption starts from a confirmed match with no revision under way.`, { current: cur });
    if ((cur ? cur.id : null) !== want) throw err(409, 'revision changed underneath this step', cur ? `Revision ${cur.revisionNo} (${M.STATE_LABEL[cur.state] || cur.state}) appeared while Entra was being read; reload and adopt again.` : 'The revision this adoption was replacing is gone; reload and adopt again.', { current: cur });
    replaces = cur;
  }
  const createNew = !adopt && o.createNew === true;
  const baseCfg = Object.assign({}, base && !adopt ? base.config : {});
  const clientCfg = Object.assign({}, o.config || {});
  delete baseCfg.createNew; delete clientCfg.createNew; delete baseCfg.adopt; delete clientCfg.adopt; delete baseCfg.adopted; delete clientCfg.adopted;
  delete clientCfg._sourceInventory;
  const cfg = Object.assign({}, baseCfg, clientCfg);
  if (o.sourceInventory && typeof o.sourceInventory === 'object') cfg._sourceInventory = stripSecrets(o.sourceInventory);
  if (createNew) cfg.createNew = true;
  if (adopt) { cfg.adopt = true; cfg.adopted = stripSecrets(Object.assign({}, o.adopted || {})); }
  assertNoSecrets(cfg);
  const protocol = M.PROTOCOLS.includes(o.protocol) ? o.protocol : (base ? base.protocol : 'unknown_custom');
  const [[mx]] = await pool.query(`SELECT MAX(revision_no) n FROM oem_config_revision WHERE okta_app_id=?`, [oktaId]);
  const no = (mx && mx.n ? Number(mx.n) : 0) + 1;
  const entraId = createNew ? null : (o.entraId !== undefined ? lc(o.entraId) : (base ? base.entraId : null));
  if (adopt && !entraId) throw err(409, 'adoption needs a destination', 'An adopted revision keeps an existing Entra application; none is confirmed.');
  /* f13: the vendor template is recorded at creation when the route resolved one (Okta name/label or destination name), else carried from the base revision */
  const vendor = adopt ? null : (o.vendor && o.vendor.templateKey ? { templateKey: o.vendor.templateKey, templateVersion: o.vendor.templateVersion || null } : (base && base.vendor ? base.vendor : null));
  const plan = buildPlan(protocol, cfg, entraId);
  const [ins] = await pool.query(`INSERT INTO oem_config_revision (okta_app_id, revision_no, match_id, entra_sp_id, protocol, state, config, plan, plan_hash, vendor_template_key, vendor_template_version, version, created_by) VALUES (?,?,?,?,?,'draft',?,?,?,?,?,1,?)`,
    [oktaId, no, o.matchId || null, entraId, protocol, JSON.stringify(stripSecrets(cfg)), JSON.stringify({ steps: plan.steps, hash: plan.hash }), plan.hash, vendor ? vendor.templateKey : null, vendor ? vendor.templateVersion : null, o.actor || null]);
  const newId = ins.insertId;
  await addEvent(oktaId, 'revision_created', { actor: o.actor, note: `Revision ${no} ${adopt ? 'adopted from the existing Entra configuration' : 'drafted'} (${M.PROTOCOL_LABEL[protocol] || protocol})${base && !adopt ? ' from revision ' + base.revisionNo + ' (' + (M.STATE_LABEL[base.state] || base.state) + ')' : ''}${o.protocolNote ? ' — ' + o.protocolNote : ''}`, evidence: { revisionId: newId, revisionNo: no, forkedFrom: base ? base.id : null, forkedFromState: base ? base.state : null, createNew, adopt, protocol, protocolSource: o.protocolSource || null, oktaProtocol: o.oktaProtocol || null, vendorTemplate: vendor ? vendor.templateKey : null } });
  // stateflow-8: in-flight siblings are superseded by this draft; live rows are untouched. f14/f15: an adopted revision supersedes only the revision it replaces (checked above).
  const states = adopt ? IN_FLIGHT.concat(['draft']) : IN_FLIGHT;
  const [inFlight] = adopt
    ? (replaces ? await pool.query(`SELECT id, revision_no, state FROM oem_config_revision WHERE okta_app_id=? AND id=? AND state IN (?)`, [oktaId, replaces.id, states]) : [[]])
    : await pool.query(`SELECT id, revision_no, state FROM oem_config_revision WHERE okta_app_id=? AND id<>? AND state IN (?)`, [oktaId, newId, states]);
  if (inFlight && inFlight.length) {
    await pool.query(`UPDATE oem_config_revision SET state='superseded', superseded_by=?, superseded_at=NOW() WHERE id IN (?) AND state IN (?)`, [newId, inFlight.map((r) => r.id), states]);
    for (const r of inFlight) await addEvent(oktaId, 'revision_superseded_by_draft', { actor: o.actor, fromState: r.state, toState: 'superseded', note: `Revision ${r.revision_no} (${M.STATE_LABEL[r.state] || r.state}) superseded by ${adopt ? 'adopted' : 'draft'} revision ${no}`, evidence: { revisionId: r.id, revisionNo: r.revision_no, supersededBy: newId } });
  }
  return getRevision(newId);
}
/** updateDraft(id, {config, version, actor}) — draft only; optimistic on version (409 edited by someone else). */
async function updateDraft(id, opts) {
  const o = opts || {};
  const rev = await getRevision(id);
  if (!rev) throw err(404, 'unknown revision', 'No revision ' + id + '.');
  if (rev.state !== 'draft') throw err(409, 'revision is not editable', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; edits fork a new draft.`, { current: rev });
  if (!Number.isInteger(Number(o.version))) throw err(400, 'version required', 'Send the version you loaded so a concurrent edit is detected.');
  const cfg = Object.assign({}, o.config || {});
  delete cfg.createNew; delete cfg.adopt; delete cfg.adopted; delete cfg._sourceInventory; // server-owned fields are carried, never set by an edit
  if (rev.config && rev.config.createNew === true) cfg.createNew = true;
  if (rev.config && rev.config.adopt === true) { cfg.adopt = true; cfg.adopted = rev.config.adopted || null; }
  if (rev.config && rev.config._sourceInventory) cfg._sourceInventory = rev.config._sourceInventory;
  assertNoSecrets(cfg);
  const entraId = o.entraId !== undefined ? lc(o.entraId) : rev.entraId;
  const plan = buildPlan(rev.protocol, cfg, cfg.createNew ? null : entraId);
  const [r] = await pool.query(`UPDATE oem_config_revision SET config=?, plan=?, plan_hash=?, entra_sp_id=?, version=version+1 WHERE id=? AND state='draft' AND version=?`,
    [JSON.stringify(stripSecrets(cfg)), JSON.stringify({ steps: plan.steps, hash: plan.hash }), plan.hash, cfg.createNew ? null : entraId, id, Number(o.version)]);
  if (!r || !r.affectedRows) throw err(409, 'edited by someone else', 'The draft changed since you loaded it; reload and apply your edit again.', { current: await getRevision(id) });
  return getRevision(id);
}
/** approvePlan(id, {hash, actor}) — binds the approval to the plan hash the approver saw; idempotent on a repeat. */
async function approvePlan(id, opts) {
  const o = opts || {};
  const rev = await getRevision(id);
  if (!rev) throw err(404, 'unknown revision', 'No revision ' + id + '.');
  const hash = String(o.hash || '');
  if (rev.state === 'plan_approved' && rev.planApprovedHash === hash) return { revision: rev, alreadyApproved: true };
  if (rev.state !== 'draft') throw err(409, 'revision is not a draft', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}.`, { current: rev });
  // stateflow-5: a plan against no destination cannot be approved (only a createNew revision has no id yet).
  if (!rev.createNew && !rev.entraId) throw err(409, 'no Entra destination bound', `Revision ${rev.revisionNo} has no Entra application to configure; confirm a destination (or create a new Entra app) and plan again.`, { current: rev });
  if (!hash || hash !== rev.planHash) throw err(409, 'Plan changed since you loaded it', 'The plan hash you approved is not the current plan; reload the plan and approve again.', { current: rev });
  const [r] = await pool.query(`UPDATE oem_config_revision SET state='plan_approved', plan_approved_by=?, plan_approved_at=NOW(), plan_approved_hash=?, version=version+1 WHERE id=? AND state='draft' AND plan_hash=?`, [o.actor || null, hash, id, hash]);
  if (!r || !r.affectedRows) {
    const now = await getRevision(id);
    if (now && now.state === 'plan_approved' && now.planApprovedHash === hash) return { revision: now, alreadyApproved: true };
    throw err(409, 'Plan changed since you loaded it', 'The draft changed while you were approving it; reload and approve again.', { current: now });
  }
  await addEvent(rev.oktaId, 'plan_approved', { actor: o.actor, note: `Plan for revision ${rev.revisionNo} approved`, evidence: { revisionId: id, hash } });
  return { revision: await getRevision(id), alreadyApproved: false };
}
const COLS = { migrationId: 'migration_id', entraConfiguredAt: 'entra_configured_at', vendorTemplateKey: 'vendor_template_key', vendorTemplateVersion: 'vendor_template_version', vendorReadyBy: 'vendor_ready_by', vendorReadyAt: 'vendor_ready_at', vendorReadyNote: 'vendor_ready_note', ownerConfirmedBy: 'owner_confirmed_by', ownerConfirmedAt: 'owner_confirmed_at', ownerConfirmedNote: 'owner_confirmed_note', liveBy: 'live_by', liveAt: 'live_at', liveAttemptId: 'live_attempt_id', liveGenerations: 'live_generations', matchId: 'match_id', entraId: 'entra_sp_id' };
function setClause(fields) {
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(fields || {})) {
    const col = COLS[k]; if (!col) continue;
    if (v === 'NOW()') sets.push(`${col}=NOW()`); else { sets.push(`${col}=?`); vals.push(v === undefined ? null : v); }
  }
  return { sets, vals };
}
/**
 * transition(id, fromStates, toState, fields, {actor, note}) — one guarded UPDATE: the row must still be in one of
 * fromStates. A live or superseded revision is never a valid source (immutable); 409 otherwise.
 */
async function transition(id, fromStates, toState, fields, opts) {
  const from = (Array.isArray(fromStates) ? fromStates : [fromStates]).filter((s) => REV_STATES.includes(s) && !FROZEN.has(s));
  if (!REV_STATES.includes(toState) || toState === 'superseded') throw err(400, 'bad state', toState + ' is not a state this call can set.');
  const { sets, vals } = setClause(fields);
  const rev = await getRevision(id);
  if (!rev) throw err(404, 'unknown revision', 'No revision ' + id + '.');
  if (!from.includes(rev.state)) throw err(409, 'revision is not in the expected state', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; this step needs ${from.map((s) => M.STATE_LABEL[s] || s).join(' or ')}.`, { current: rev });
  const [r] = await pool.query(`UPDATE oem_config_revision SET state=?${sets.length ? ', ' + sets.join(', ') : ''}, version=version+1 WHERE id=? AND state IN (?)`, [toState, ...vals, id, from]);
  if (!r || !r.affectedRows) throw err(409, 'revision changed underneath this step', 'Another actor moved the revision; reload.', { current: await getRevision(id) });
  const o = opts || {};
  await addEvent(rev.oktaId, 'revision_' + toState, { actor: o.actor, fromState: rev.state, toState, note: o.note || null, evidence: Object.assign({ revisionId: id, revisionNo: rev.revisionNo }, o.evidence || {}) });
  return getRevision(id);
}
/**
 * Non-state field writes on a revision that is not frozen (migration id, vendor template stamp, owner confirmation).
 * authz-2: `{whereState}` (string or list) makes the write conditional on the row STILL being in that state — the
 * guard is in the UPDATE itself, not in a read the caller did earlier — and 409s when nothing was affected.
 * secrets-4: note fields are scanned for secret values before the write.
 */
async function setRevisionFields(id, fields, opts) {
  const f = fields || {};
  if (f.vendorReadyNote) M.assertNoSecretText(f.vendorReadyNote, 'vendor-ready note');
  if (f.ownerConfirmedNote) M.assertNoSecretText(f.ownerConfirmedNote, 'owner confirmation');
  const { sets, vals } = setClause(f);
  const o = opts || {};
  const where = o.whereState === undefined || o.whereState === null ? null : (Array.isArray(o.whereState) ? o.whereState : [o.whereState]).map(String).filter((s) => REV_STATES.includes(s) && !FROZEN.has(s));
  if (where && !where.length) throw err(400, 'bad state', 'whereState names no state this call can write in.');
  if (!sets.length) return getRevision(id);
  const [r] = where
    ? await pool.query(`UPDATE oem_config_revision SET ${sets.join(', ')} WHERE id=? AND state IN (?)`, [...vals, id, where])
    : await pool.query(`UPDATE oem_config_revision SET ${sets.join(', ')} WHERE id=? AND state NOT IN ('live','superseded')`, [...vals, id]);
  if (!r || !r.affectedRows) {
    const current = await getRevision(id);
    if (!current) throw err(404, 'unknown revision', 'No revision ' + id + '.');
    if (where) throw err(409, 'revision is not in the expected state', `Revision ${current.revisionNo} is ${M.STATE_LABEL[current.state] || current.state}; this step needs ${where.map((s) => M.STATE_LABEL[s] || s).join(' or ')}.`, { current });
    throw err(409, 'revision is immutable', 'A live or superseded revision is never changed.', { current });
  }
  return getRevision(id);
}
/** Newest successful generation id for one source across the per-app and global scopes (null when none). */
function newestSuccessId(per, glob, key) {
  const a = per && per[key] && per[key].lastSuccess, b = glob && glob[key] && glob[key].lastSuccess;
  if (a && b) return (new Date(b.at).getTime() || 0) > (new Date(a.at).getTime() || 0) ? b.id : a.id;
  return (a || b) ? (a || b).id : null;
}
/**
 * markLive(id, {actor, override, attemptId, generations}) — awaiting_live_approval -> live; the previous live
 * revision becomes superseded.
 * authz-7: the row freezes WHAT went live — live_attempt_id (the passing attempt, or the one the caller names) and
 * live_generations {okta, entra} (the mirror generations the sign-off was judged against) — so the evidence package
 * never drifts to a later attempt or a later mirror.
 */
async function markLive(id, opts) {
  const o = opts || {};
  const rev0 = await getRevision(id);
  if (!rev0) throw err(404, 'unknown revision', 'No revision ' + id + '.');
  let attemptId = o.attemptId === undefined || o.attemptId === null ? null : Number(o.attemptId);
  if (attemptId !== null) {
    const a = await getAttempt(attemptId);
    if (!a || String(a.revisionId) !== String(id)) throw err(400, 'attempt does not belong to this revision', `Attempt ${attemptId} is not a verification attempt of revision ${rev0.revisionNo}.`);
  } else {
    const la = await latestAttempt(id);
    attemptId = la && la.status === 'pass' ? la.id : null;
  }
  let generations = o.generations && typeof o.generations === 'object' ? { okta: o.generations.okta === undefined ? null : o.generations.okta, entra: o.generations.entra === undefined ? null : o.generations.entra } : null;
  if (!generations) {
    const per = await latestGenerations(rev0.oktaId);
    const glob = await latestGenerations(null);
    generations = { okta: newestSuccessId(per, glob, 'okta_apps'), entra: newestSuccessId(per, glob, 'entra_apps') };
  }
  const rev = await transition(id, ['awaiting_live_approval'], 'live', { liveBy: o.actor || null, liveAt: 'NOW()', liveAttemptId: attemptId, liveGenerations: JSON.stringify(generations) },
    { actor: o.actor, note: o.override ? 'Live by override' : 'Signed off as Live', evidence: Object.assign({ attemptId, generations }, o.override ? { override: true } : {}) });
  await pool.query(`UPDATE oem_config_revision SET state='superseded', superseded_by=?, superseded_at=NOW() WHERE okta_app_id=? AND id<>? AND state='live'`, [id, rev.oktaId, id]);
  return rev;
}
/** supersede(id, byId) — the only write a live revision ever receives. */
async function supersede(id, byId) {
  const [r] = await pool.query(`UPDATE oem_config_revision SET state='superseded', superseded_by=?, superseded_at=NOW() WHERE id=? AND state='live'`, [byId || null, id]);
  return !!(r && r.affectedRows);
}

/* --------------------------------------------------------------- attempts */

function attRow(a) {
  if (!a) return null;
  return { id: a.id, attemptId: a.id, revisionId: a.revision_id, oktaId: a.okta_app_id, status: a.status, startedAt: iso(a.started_at), finishedAt: iso(a.finished_at), checks: j(a.checks, []) || [], summary: j(a.summary, null), actor: a.actor_email || null, planHash: a.plan_hash || null, plan_hash: a.plan_hash || null, revision_id: a.revision_id, finished_at: iso(a.finished_at) };
}
async function createAttempt(o) {
  const [ins] = await pool.query(`INSERT INTO oem_verification_attempt (revision_id, okta_app_id, status, actor_email, plan_hash) VALUES (?,?,'running',?,?)`, [o.revisionId, o.oktaId, o.actor || null, o.planHash || null]);
  return ins.insertId;
}
/** finishAttempt(id, {status, checks, summary}) — once; a finished attempt is immutable (409). */
async function finishAttempt(id, o) {
  const status = ['pass', 'fail', 'inconclusive'].includes(o.status) ? o.status : 'inconclusive';
  const [r] = await pool.query(`UPDATE oem_verification_attempt SET status=?, finished_at=NOW(), checks=?, summary=? WHERE id=? AND status='running'`, [status, JSON.stringify(L.redact(o.checks || [])), JSON.stringify(L.redact(o.summary || null)), id]);
  if (!r || !r.affectedRows) throw err(409, 'attempt already finished', 'A finished verification attempt is immutable; run a new test.', { current: await getAttempt(id) });
  return getAttempt(id);
}
async function getAttempt(id) { const [[a]] = await pool.query(`SELECT * FROM oem_verification_attempt WHERE id=?`, [id]); return attRow(a); }
async function latestAttempt(revisionId) { const [[a]] = await pool.query(`SELECT * FROM oem_verification_attempt WHERE revision_id=? AND status<>'running' ORDER BY id DESC LIMIT 1`, [revisionId]); return attRow(a); }
/**
 * authz-7: the attempt a live/superseded revision went live on (live_attempt_id), never the latest one.
 * Accepts a revision object or id. Null when the revision froze without a recorded attempt (override with no pass).
 */
async function frozenAttempt(revOrId) {
  const rev = revOrId && typeof revOrId === 'object' ? revOrId : await getRevision(revOrId);
  if (!rev) return null;
  const fid = rev.liveAttemptId;
  return fid === null || fid === undefined ? null : getAttempt(fid);
}
/** The attempt the evidence package shows: frozen for live/superseded revisions, latest otherwise. */
async function attemptFor(revOrId) {
  const rev = revOrId && typeof revOrId === 'object' ? revOrId : await getRevision(revOrId);
  if (!rev) return null;
  return FROZEN.has(rev.state) ? frozenAttempt(rev) : latestAttempt(rev.id);
}
async function listAttempts(oktaId, limit) { const [rows] = await pool.query(`SELECT * FROM oem_verification_attempt WHERE okta_app_id=? ORDER BY id DESC LIMIT ?`, [oktaId, Math.min(Number(limit) || 20, 200)]); return (rows || []).map(attRow); }

/* -------------------------------------------------------------- overrides */

async function recordOverride(o) {
  M.assertNoSecretText(o.reason, 'override reason'); // secrets-4
  const [ins] = await pool.query(`INSERT INTO oem_live_override (revision_id, okta_app_id, actor_email, reason, failed_predicates) VALUES (?,?,?,?,?)`, [o.revisionId, o.oktaId, o.actor, String(o.reason).slice(0, 1000), JSON.stringify(o.failedPredicates || [])]);
  return ins.insertId;
}
async function listOverrides(revisionId) {
  const [rows] = await pool.query(`SELECT * FROM oem_live_override WHERE revision_id=? ORDER BY id DESC`, [revisionId]);
  return (rows || []).map((r) => ({ id: r.id, revisionId: r.revision_id, oktaId: r.okta_app_id, actor: r.actor_email, reason: r.reason, failedPredicates: j(r.failed_predicates, []) || [], at: iso(r.created_at) }));
}

/* ---------------------------------------------------------------- mirrors */

async function workItem(oktaId) { return workItemByKey('app:' + oktaId); }
async function workItemByKey(key) {
  const [[w]] = await pool.query(`SELECT * FROM oem_work_item WHERE item_key=?`, [key]);
  if (!w) return null;
  w.facts = j(w.facts, {}) || {}; w.evidence = j(w.evidence, null);
  return w;
}
function oktaRow(o) {
  if (!o) return null;
  const raw = j(o.raw_json, {}) || {};
  const feats = j(o.features_json, []) || [];
  return { oktaId: o.okta_id, name: o.name, label: o.label, status: o.status, signOnMode: o.sign_on_mode || raw.signOnMode || null, features: Array.isArray(feats) ? feats : [], users: o.assigned_user_count === undefined ? null : o.assigned_user_count, groups: o.assigned_group_count === undefined ? null : o.assigned_group_count, lastUpdatedOkta: iso(o.last_updated_at_okta), lastSyncedAt: iso(o.last_synced_at), raw };
}
async function oktaApp(oktaId) { const [[o]] = await pool.query(`SELECT * FROM okta_apps WHERE okta_id=?`, [oktaId]); return oktaRow(o); }
function entraRow(e) {
  if (!e) return null;
  return { entraId: lc(e.entra_id), appId: e.app_id || null, name: e.display_name || null, ssoMode: e.preferred_single_sign_on_mode || null, enabled: e.account_enabled === null || e.account_enabled === undefined ? null : !!e.account_enabled, assignmentRequired: !!e.app_role_assignment_required, users: e.assigned_user_count === undefined ? null : e.assigned_user_count, groups: e.assigned_group_count === undefined ? null : e.assigned_group_count, homepage: e.homepage_url || null, lastSeenAt: iso(e.last_synced_at), seenInLastSync: e.seen_in_last_sync === undefined ? null : !!e.seen_in_last_sync, raw: j(e.raw_json, {}) || {} };
}
async function entraApp(entraId) { if (!entraId) return null; const [[e]] = await pool.query(`SELECT * FROM entra_apps WHERE entra_id=?`, [lc(entraId)]); return entraRow(e); }
async function spExtras(entraId) {
  if (!entraId) return null;
  const [[s]] = await pool.query(`SELECT * FROM oem_entra_sp WHERE sp_id=?`, [lc(entraId)]);
  if (!s) return null;
  const saml = j(s.saml_settings, {}) || {};
  return { spId: lc(s.sp_id), appId: s.app_id || null, certificateThumbprint: s.cert_thumbprint || null, certificateExpires: iso(s.cert_expires), syncJobs: j(s.sync_jobs, []) || [], syncStatus: s.sync_status || null, replyUrls: saml.replyUrls || null, identifierUris: saml.identifierUris || null, collectedAt: iso(s.collected_at) };
}
/** The Applications list in a few reads, never one per app: work items + latest revision + destinations + tombstones. */
async function listWorkApps() {
  const [items] = await pool.query(`SELECT item_key, source_id, title, source_status, disposition, state, facts, assignee, assigned_at, state_updated_at, last_seen_at FROM oem_work_item WHERE category='applications' AND source_kind='okta_app'`);
  const [revs] = await pool.query(`SELECT id, okta_app_id, revision_no, state, protocol, config, updated_at FROM oem_config_revision WHERE state<>'superseded' ORDER BY id DESC`);
  const [matches] = await pool.query(`SELECT id, okta_app_id, entra_sp_id, entra_display_name, state, score, method, evidence FROM oem_app_match WHERE state IN ('confirmed','shortlisted','invalidated','suggested') ORDER BY FIELD(state,'confirmed','shortlisted','invalidated','suggested'), id DESC`);
  const tomb = await tombstonesByIds((matches || []).map((m) => m.entra_sp_id));
  /* f14: the list row's destination carries the mirror's enabled/ssoMode/assignment counts so the row CTA can say
     "Verify the existing Entra setup" exactly when the workspace does (adoptable() reads those fields). */
  const ids = Array.from(new Set((matches || []).map((m) => lc(m.entra_sp_id)).filter(Boolean)));
  const [entra] = ids.length ? await pool.query(`SELECT entra_id, app_id, display_name, preferred_single_sign_on_mode, account_enabled, assigned_user_count, assigned_group_count, last_synced_at FROM entra_apps WHERE entra_id IN (?)`, [ids]) : [[]];
  const entraOf = new Map(); for (const e of entra || []) entraOf.set(lc(e.entra_id), entraRow(e));
  const revOf = new Map(); for (const r of revs || []) if (!revOf.has(r.okta_app_id)) revOf.set(r.okta_app_id, r);
  /* conf-1: the row's destination is picked exactly as destinationFor picks it — a human decision first, then only a
     reliable suggestion (pickSuggested); a weak one leaves the row at 'none' with the "No reliable match found" sentence. */
  const rowsOf = new Map(); for (const m of matches || []) { const k = m.okta_app_id; if (!rowsOf.has(k)) rowsOf.set(k, []); rowsOf.get(k).push(m); }
  const matchOf = new Map(), whyOf = new Map();
  for (const [k, rs] of rowsOf) {
    const human = rs.find((m) => m.state === 'confirmed') || rs.find((m) => m.state === 'shortlisted') || rs.find((m) => m.state === 'invalidated') || null;
    if (human) { matchOf.set(k, human); continue; }
    const sug = pickSuggested(rs.filter((m) => m.state === 'suggested' && !tomb[lc(m.entra_sp_id)]).map(matchRow));
    if (sug.row) matchOf.set(k, rs.find((m) => m.id === sug.row.id) || null); else if (sug.why) whyOf.set(k, sug.why);
  }
  return (items || []).map((w) => {
    const facts = j(w.facts, {}) || {};
    const r = revOf.get(w.source_id) || null;
    const rc = r ? (j(r.config, {}) || {}) : {};
    const m = matchOf.get(w.source_id) || null;
    const t = m ? tomb[lc(m.entra_sp_id)] || null : null;
    const e = m ? entraOf.get(lc(m.entra_sp_id)) || null : null;
    return { item: Object.assign(w, { facts }), revision: r ? { id: r.id, state: r.state, revisionNo: r.revision_no, protocol: r.protocol, adopt: rc.adopt === true, config: { adopt: rc.adopt === true }, updatedAt: iso(r.updated_at) } : null,
      destination: m ? { state: t && m.state !== 'invalidated' ? 'invalidated' : m.state, entraId: lc(m.entra_sp_id), name: (e && e.name) || m.entra_display_name || (t ? t.name : null), enabled: e ? e.enabled : null, ssoMode: e ? e.ssoMode : null, users: e ? e.users : null, groups: e ? e.groups : null, lastSeenAt: e ? e.lastSeenAt : null, tombstone: t ? { entraId: t.entraId, name: t.name, lastSeenAt: t.lastSeenAt, detectedAt: t.detectedAt } : null } : Object.assign({ state: 'none', entraId: null, name: null, enabled: null, ssoMode: null, users: null, groups: null, lastSeenAt: null, tombstone: null }, whyOf.has(w.source_id) ? { noReliable: whyOf.get(w.source_id) } : {}) };
  });
}
async function addEvent(oktaId, event, o) { return addEventKey('app:' + oktaId, event, o); }
async function addEventKey(itemKey, event, o) {
  const x = o || {};
  await pool.query(`INSERT INTO oem_work_event (item_key, event, from_state, to_state, note, actor_email, evidence) VALUES (?,?,?,?,?,?,?)`, [itemKey, event, x.fromState || null, x.toState || null, x.note ? String(x.note).slice(0, 500) : null, x.actor || 'v2', x.evidence === undefined ? null : JSON.stringify(L.redact(x.evidence))]);
}

/* ---------------------------------------------------------------- drop 8: technician flow */
/* Per-user page preferences live in the platform's rbac_user_prefs table (email, pref_key, pref_value — the same table
   /api/profile writes); this page owns two keys: oem_mode (technician | advanced) and oem_intro_seen (ISO time the intro was
   dismissed). UPDATE first, INSERT when the row is absent, and a lost race on the insert falls back to the UPDATE. */
const PREF_KEYS = { mode: 'oem_mode', introSeen: 'oem_intro_seen' };
async function userPrefs(email) {
  const out = { mode: null, introSeenAt: null };
  if (!email) return out;
  const [rows] = await pool.query(`SELECT pref_key, pref_value FROM rbac_user_prefs WHERE email=? AND pref_key IN (?)`, [lc(email), Object.values(PREF_KEYS)]);
  for (const r of rows || []) { if (r.pref_key === PREF_KEYS.mode) out.mode = r.pref_value || null; if (r.pref_key === PREF_KEYS.introSeen) out.introSeenAt = r.pref_value || null; }
  return out;
}
async function setUserPref(email, key, value) {
  const pk = PREF_KEYS[key];
  if (!pk || !email) throw err(400, 'unknown preference', 'This page keeps only the mode and the intro-seen preference.');
  const v = value === null || value === undefined ? null : String(value).slice(0, 64);
  const [r] = await pool.query(`UPDATE rbac_user_prefs SET pref_value=?, updated_at=NOW() WHERE email=? AND pref_key=?`, [v, lc(email), pk]);
  if (r && r.affectedRows) return;
  try { await pool.query(`INSERT INTO rbac_user_prefs (email, pref_key, pref_value) VALUES (?,?,?)`, [lc(email), pk, v]); }
  catch (e) { if (e && e.code === 'ER_DUP_ENTRY') await pool.query(`UPDATE rbac_user_prefs SET pref_value=?, updated_at=NOW() WHERE email=? AND pref_key=?`, [v, lc(email), pk]); else throw e; }
}
/** The latest handoff event per work item: Map item_key -> {at, by, reason, to, note}. */
async function latestHandoffs() {
  const [rows] = await pool.query(`SELECT item_key, event, actor_email, note, evidence, created_at FROM oem_work_event WHERE event IN ('handoff','migration_reset','returned_to_queue','unassigned') ORDER BY id DESC LIMIT 1000`);
  const out = new Map();
  const seen = new Set();
  for (const r of rows || []) {
    if (seen.has(r.item_key)) continue;
    seen.add(r.item_key);
    if (r.event !== 'handoff') continue;
    const ev = j(r.evidence, {}) || {};
    out.set(r.item_key, { at: iso(r.created_at), by: r.actor_email || null, reason: ev.reason || null, reasonLabel: ev.reasonLabel || null, to: ev.to || null, note: ev.note || (r.note ? String(r.note) : null) });
  }
  return out;
}
/** Open work items assigned to one person, any category (the technician's queue also carries policy / MFA / network items). */
async function assignedWorkItems(email) {
  if (!email) return [];
  const [rows] = await pool.query(`SELECT item_key, category, title, state, disposition, assignee, assigned_at, state_updated_at FROM oem_work_item WHERE assignee=? AND state NOT IN ('verified','retired') AND disposition<>'exclude' ORDER BY assigned_at ASC`, [lc(email)]);
  return (rows || []).map((w) => ({ key: w.item_key, category: w.category, title: w.title, state: w.state, disposition: w.disposition, assignee: w.assignee || null, assignedAt: iso(w.assigned_at), updatedAt: iso(w.state_updated_at) }));
}
/** Assignment is a record of who is working an item; it grants nothing. who = email or null (unassign). */
async function setAssignee(itemKey, who, actor) {
  const w = who ? lc(String(who).trim()) : null;
  if (w) await pool.query(`UPDATE oem_work_item SET assignee=?, assigned_at=NOW(), assigned_by=? WHERE item_key=?`, [w, actor || 'v2', itemKey]);
  else await pool.query(`UPDATE oem_work_item SET assignee=NULL, assigned_at=NULL, assigned_by=NULL WHERE item_key=?`, [itemKey]);
  return w;
}

/** Release a technician's task, preserving every migration and evidence field. */
async function returnToQueue(itemKey, { expectedAssignee, actor }, connection) {
  const q = connection || await pool.getConnection();
  try {
    await q.beginTransaction();
    const [[item]] = await q.query('SELECT item_key, category, state, assignee, assigned_at, assigned_by FROM oem_work_item WHERE item_key=? FOR UPDATE', [itemKey]);
    if (!item || item.category !== 'applications') throw err(404, 'no such application task', 'Refresh Applications and open the task again.');
    if (lc(item.assignee || '') !== lc(expectedAssignee || '')) throw err(409, 'assignment changed', 'Someone changed the assignment. Refresh before returning this application to the queue.');
    await q.query('UPDATE oem_work_item SET assignee=NULL, assigned_at=NULL, assigned_by=NULL WHERE item_key=?', [itemKey]);
    await q.query("INSERT INTO oem_work_event (item_key, event, from_state, to_state, note, actor_email, evidence) VALUES (?,'returned_to_queue',?,?,?,?,?)", [
      itemKey, item.state, item.state, 'Returned to the unassigned Applications queue; migration progress preserved.', actor,
      JSON.stringify({ previousAssignee: item.assignee || null, assignedAt: iso(item.assigned_at), assignedBy: item.assigned_by || null })
    ]);
    await q.commit();
    return { ok: true, key: itemKey, assignee: null, from: item.assignee || null, state: item.state, handoff: null };
  } catch (e) { await q.rollback(); throw e; }
  finally { if (!connection) q.release(); }
}

module.exports = {
  beginGeneration, commitGeneration, failGeneration, latestGeneration, latestGenerations,
  recordTombstone, tombstonedIds, listTombstones, tombstonesByIds, getTombstone, markReappeared, reconciliationCounts,
  syncMatches, syncAllMatches, listMatches, invalidateMatchesFor, destinationFor, confirmedElsewhere, setMatch, candidatesFor, recomputeCandidates, portalUrl,
  createDraft, updateDraft, approvePlan, transition, setRevisionFields, markLive, supersede, getRevision, listRevisions, draftFor, liveRevision, latestRevision, newerDraftExists, IN_FLIGHT,
  createAttempt, finishAttempt, getAttempt, latestAttempt, frozenAttempt, attemptFor, listAttempts,
  hostMatchOf, pickSuggested,
  recordOverride, listOverrides,
  workItem, workItemByKey, oktaApp, entraApp, spExtras, listWorkApps, addEvent, addEventKey, rebuildWork,
  userPrefs, setUserPref, latestHandoffs, assignedWorkItems, setAssignee, returnToQueue, PREF_KEYS,
  REV_STATES,
};
