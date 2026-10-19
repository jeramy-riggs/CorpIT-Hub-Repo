/**
 * oem-work-routes.js — the merged Okta → Entra migration workspace API.
 * Mount BEFORE ./oem-routes on the same prefix:
 *   app.use('/api/oem', require('./oem-work-routes'));
 *   app.use('/api/oem', require('./oem-routes'));
 *
 * Everything the technician sees about scope, matching, the work queue, jobs and
 * "can we retire Okta" comes from here. Vendor reads are paced; vendor writes exist
 * in exactly one place (Okta app deactivate / reactivate) and need a typed, scoped
 * confirmation plus a live check that the credential actually holds the role.
 */
'use strict';
const express = require('express');
const path = require('path');
const createRbac = require('./rbac-middleware');
const L = require('./oem-lib');
const D = require('./oem-discovery');
const { MAPPINGS } = require('./oem-mapping');
// removable: without oem-usage the bookmark acknowledgement below simply refuses (it can no longer
// re-derive the facts), and every other retirement path is untouched.
let USAGE = null;
try { USAGE = require('./oem-usage'); } catch (e) { USAGE = null; }
const { pool, j } = L;

/* ---------------------------------------------------------------- v2 glue */
/* oem-v2-store / oem-v2-model land with the v2 build and are required lazily: a missing module never breaks a
   v1 route, and a lazy require avoids a cycle through oem-discovery (which itself requires the store lazily). */
function lazy(name) {
  try { return require(name); }
  catch (e) { if (!(e && e.code === 'MODULE_NOT_FOUND')) console.error(`[oem-work] ${name}:`, e && e.message || e); return null; }
}
const iso = (d) => (d ? new Date(d).toISOString() : null);

/* Source generations (oem_source_generation, sql/010-oem-v2.sql). One row per job run: begin → success|failed.
   Every statement is scoped to the row this run created (WHERE id=?), so a failed run can never touch the previous
   success row — that is what keeps "last success" honest (bug 11). The table may not exist yet on an older
   database: every call is try/catch and a job never fails because its bookkeeping did. */
const SOURCE_KEY_OF_JOB = { 'okta-apps': 'okta_apps', 'discover-okta': 'okta_objects', 'entra-apps': 'entra_apps', 'entra-extras': 'entra_sp_extras', 'mfa-evidence': 'mfa_registration', 'policy-snapshot': 'okta_entra_policy_snapshot', 'zsnet-refresh': 'zscaler_mirror', 'rebuild-work': 'work_queue', 'discover': 'all', 'match': 'match', 'entra-gallery': 'entra_gallery', 'staged-signins': 'staged_signins' };
async function genBegin(sourceKey, scope, jobId, actor) {
  try {
    const [r] = await pool.query(`INSERT INTO oem_source_generation (source_key, scope, job_id, status, actor_email) VALUES (?,?,?,'running',?)`, [sourceKey, scope || null, jobId || null, actor || null]);
    return r && r.insertId ? r.insertId : null;
  } catch (e) { return null; }
}
async function genCommit(id, records) {
  if (!id) return;
  try { await pool.query(`UPDATE oem_source_generation SET status='success', finished_at=NOW(), records=? WHERE id=? AND status='running'`, [records === undefined || records === null || Number.isNaN(Number(records)) ? null : Number(records), id]); } catch (e) { /* bookkeeping only */ }
}
async function genFail(id, err) {
  if (!id) return;
  try { await pool.query(`UPDATE oem_source_generation SET status='failed', finished_at=NOW(), error=? WHERE id=? AND status='running'`, [String(err && err.message || err || 'failed').slice(0, 500), id]); } catch (e) { /* bookkeeping only */ }
}
/* How many records a job run produced, read from its own result; null (never 0) when the result does not say. */
function recordsOf(r, depth = 0) {
  if (r === null || r === undefined) return null;
  if (typeof r === 'number') return Number.isFinite(r) ? r : null;
  if (typeof r !== 'object' || depth > 2) return null;
  for (const k of ['records', 'records_fetched', 'recordsFetched', 'count', 'total', 'upserted', 'apps', 'items', 'principals', 'events']) {
    const v = r[k];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (Array.isArray(v)) return v.length;
  }
  for (const k of ['work', 'okta', 'matcher', 'extras', 'collector', 'result']) if (r[k] && typeof r[k] === 'object') { const n = recordsOf(r[k], depth + 1); if (n !== null) return n; }
  return null;
}
async function currentGeneration() {
  try { if (typeof D.currentGeneration === 'function') { const g = await D.currentGeneration(); return g === undefined ? null : g; } } catch (e) { /* unknown, not invented */ }
  return null;
}

/* Entra tombstones (oem_entra_tombstone). Recorded through the v2 store when it is present; otherwise the same
   "record if absent" insert inline, so the record exists whichever module ran first. */
function tombstoneSnapshot(row) {
  if (!row) return null;
  return L.redact({ entra_id: row.entra_id || row.entraId || null, app_id: row.app_id || row.appId || null, display_name: row.display_name || row.displayName || null,
    preferred_single_sign_on_mode: row.preferred_single_sign_on_mode || null, account_enabled: row.account_enabled === undefined ? null : row.account_enabled,
    assigned_user_count: row.assigned_user_count === undefined ? null : row.assigned_user_count, assigned_group_count: row.assigned_group_count === undefined ? null : row.assigned_group_count,
    last_synced_at: row.last_synced_at || null, raw: row.raw_json === undefined ? null : j(row.raw_json, null) });
}
async function recordTombstone(t) {
  const rec = { entraId: String(t.entraId || '').toLowerCase(), appId: t.appId || null, displayName: t.displayName || null, lastSeenAt: t.lastSeenAt || null, detectedBy: t.detectedBy || 'oem-work', snapshot: t.snapshot || null };
  if (!rec.entraId) return null;
  const S = lazy('./oem-v2-store');
  if (S && typeof S.recordTombstone === 'function') {
    try { const r = await S.recordTombstone(rec); return r || rec; } catch (e) { console.error('[oem-work] store.recordTombstone:', e && e.message || e); }
  }
  try {
    await pool.query(`INSERT INTO oem_entra_tombstone (entra_id, app_id, display_name, last_seen_at, detected_by, snapshot) VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE entra_id=entra_id`,
      [rec.entraId, rec.appId, rec.displayName, rec.lastSeenAt ? new Date(rec.lastSeenAt) : null, rec.detectedBy, rec.snapshot ? JSON.stringify(rec.snapshot) : null]);
    return rec;
  } catch (e) { console.error('[oem-work] recordTombstone:', e && e.message || e); return null; }
}
/* A match whose target is gone is invalidated, never deleted: app_matches keeps the decision (who/when) as history and
   buildWorkItems reads the absence as decision 'invalidated' (bug 1, oem-discovery). The v2 match table is updated when
   it exists. */
async function invalidateMatchesFor(entraId, reason) {
  try { await pool.query(`UPDATE oem_app_match SET state='invalidated', invalidated_at=NOW(), invalidated_reason=? WHERE entra_sp_id=? AND state IN ('suggested','shortlisted','confirmed')`, [String(reason || 'deleted in Entra').slice(0, 255), entraId]); } catch (e) { /* v2 table not created yet */ }
}
/* Ids that were in the mirror before a sync and are not after it were deleted in Entra: each becomes a tombstone that
   keeps its last mirror row, and every match pointing at it is invalidated. Used by the entra-apps job wrapper. */
async function captureTombstones(beforeIds, afterIds, byId) {
  const after = new Set(Array.from(afterIds || []).map((x) => String(x).toLowerCase()));
  const get = (id) => { if (!byId) return null; if (typeof byId.get === 'function') return byId.get(id) || byId.get(String(id).toLowerCase()) || null; return byId[id] || byId[String(id).toLowerCase()] || null; };
  const out = [];
  for (const id0 of Array.from(beforeIds || [])) {
    const id = String(id0).toLowerCase();
    if (!id || after.has(id)) continue;
    const row = get(id0) || get(id);
    const t = await recordTombstone({ entraId: id, appId: row ? (row.app_id || row.appId || null) : null, displayName: row ? (row.display_name || row.displayName || null) : null, lastSeenAt: row ? (row.last_synced_at || row.lastSeenAt || null) : null, detectedBy: 'entra-apps', snapshot: tombstoneSnapshot(row) });
    await invalidateMatchesFor(id, 'deleted in Entra (entra-apps sync)');
    out.push({ entraId: id, name: row ? (row.display_name || row.displayName || null) : null, recorded: !!t });
  }
  return out;
}
const MIRROR_COLS = 'entra_id, app_id, display_name, preferred_single_sign_on_mode, account_enabled, assigned_user_count, assigned_group_count, last_synced_at, raw_json';
async function mirrorSnapshot() {
  try { const [rows] = await pool.query(`SELECT ${MIRROR_COLS} FROM entra_apps`); return { ids: rows.map((r) => r.entra_id), byId: new Map(rows.map((r) => [String(r.entra_id).toLowerCase(), r])) }; }
  catch (e) { return null; }
}
async function mirrorIds() { const [rows] = await pool.query(`SELECT entra_id FROM entra_apps`); return rows.map((r) => r.entra_id); }

const router = express.Router();
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const PAGE_KEY = 'okta-entra-migration';
const read = () => rbac.requirePage(PAGE_KEY, 'read');
const admin = () => rbac.requirePage(PAGE_KEY, 'admin');
const json = express.json({ limit: '256kb' });
const fail = (res, e, where) => { console.error(`[oem-work] ${where}:`, (L.redactText || String)(e && e.stack || e)); res.status(500).json({ error: 'request failed', where, detail: (L.redactText || String)(e && e.message || e).slice(0, 300) }); };
const actorOf = (req) => (req.user && req.user.email) || 'anonymous';
const audit = (req, action, details, target) => { try { if (rbac.audit) return rbac.audit(req, action, target || null, PAGE_KEY, details); } catch (e) { /* audit never breaks a request */ } };

const STATES = ['discovered', 'needs_review', 'ready', 'running', 'waiting_technician', 'blocked', 'awaiting_validation', 'verified', 'retired'];
const STATE_LABEL = { discovered: 'Discovered', needs_review: 'Needs Review', ready: 'Ready', running: 'Running', waiting_technician: 'Waiting for Technician', blocked: 'Blocked', awaiting_validation: 'Awaiting Validation', verified: 'Verified', retired: 'Retired' };
const CATEGORY_LABEL = { applications: 'Applications', policies: 'Policies and Sign-in Rules', mfa: 'MFA', network_device: 'Network and Device Prerequisites', dependencies: 'Remaining Okta Dependencies' };

/* ------------------------------------------------------------- page level */

async function pageLevel(req) {
  try {
    if (req.user && req.user.email && rbac.computeEffectivePages) {
      const pages = await rbac.computeEffectivePages(req.user.email, req.user.roles || [], !!req.user.isSuperAdmin);
      return pages[PAGE_KEY] || 'none';
    }
  } catch (e) { console.error('[oem-work] pageLevel:', e.message); }
  return null;
}
const canAct = (lvl, req) => lvl === 'admin' && !(req.user && req.user.readOnly);

/* ------------------------------------------------------------------ access */

const GRAPH_KEYS = ['Application.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'Reports.Read.All', 'UserAuthenticationMethod.Read.All', 'Synchronization.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod', 'Application.ReadWrite.All', 'Group.ReadWrite.All', 'Domain.Read.All', 'UserAuthenticationMethod.ReadWrite.All'];
const ENTRA_GRANTOR = 'an Entra Global Administrator (admin consent on the IT-Command-IdentityDiag app registration)';
const OKTA_GRANTOR = 'an Okta Super Administrator (assign the role to the API token owner, or issue a scoped token)';
const ZS_GRANTOR = 'a ZPA administrator (add Connector read to the API client role)';

function actionTable({ graph, okta, zs, lvl, req }) {
  const roles = graph.roles || [];
  const has = (r) => (graph.roles === null ? null : roles.includes(r));
  const acting = canAct(lvl, req);
  const need = (perm, grantedBy) => ({ permission: perm, grantedBy });
  const rows = [];
  const push = (code, label, cls, available, reason, needs = []) => rows.push({ code, label, cls, available, reason, needs });
  push('discover', 'Discover / Refresh', 'analysis', graph.roles !== null && okta.known !== false && acting, graph.roles === null ? 'Graph credential could not be read (unknown, not denied).' : okta.known === false ? 'Okta token could not be verified: ' + okta.error : !acting ? 'Needs admin level on this page.' : 'Reads Okta and Entra with the roles already granted; writes only the local mirror.', [need('Application.Read.All', ENTRA_GRANTOR), need('Okta API token (read)', OKTA_GRANTOR)].filter((n) => n.permission !== 'Application.Read.All' || has('Application.Read.All') === false));
  push('compare', 'Compare', 'analysis', true, 'Reads the mirrors only.');
  push('review_match', 'Review Match', 'technician', acting, acting ? 'A person decides; the decision is recorded here with your name.' : 'Needs admin level on this page.');
  push('preview_change', 'Preview Change', 'analysis', true, 'Shows the target, the diff and the rollback. Changes nothing.');
  push('generate_configuration', 'Generate Configuration', 'analysis', true, 'Produces the payload to paste or the settings to enter. Changes nothing.');
  push('run_approved_change_entra', 'Run Approved Change (Entra Conditional Access)', has('Policy.ReadWrite.ConditionalAccess') ? 'auto' : 'blocked', !!has('Policy.ReadWrite.ConditionalAccess') && acting, has('Policy.ReadWrite.ConditionalAccess') ? 'The credential can write Conditional Access.' : has('Policy.ReadWrite.ConditionalAccess') === null ? 'Unknown until the credential is read.' : 'Blocked: Policy.ReadWrite.ConditionalAccess is not consented. Every Entra policy change is a handoff (Open Admin Page + Copy Claude Instructions).', has('Policy.ReadWrite.ConditionalAccess') ? [] : [need('Policy.ReadWrite.ConditionalAccess', ENTRA_GRANTOR)]);
  push('run_approved_change_entra_app', 'Run Approved Change (Entra enterprise app)', has('Application.ReadWrite.All') ? 'auto' : 'blocked', !!has('Application.ReadWrite.All') && acting, has('Application.ReadWrite.All') ? 'The credential can write applications.' : 'Blocked: Application.ReadWrite.All is not consented. Creating or editing an enterprise app is a handoff.', has('Application.ReadWrite.All') ? [] : [need('Application.ReadWrite.All', ENTRA_GRANTOR)]);
  push('okta_deactivate_app', 'Run Approved Change (deactivate an Okta app)', okta.canWriteOkta ? 'auto' : okta.canWriteOkta === null ? 'blocked' : 'blocked', !!okta.canWriteOkta && acting, okta.canWriteOkta ? `Okta token belongs to ${okta.login} with ${(okta.roles || []).join(', ')}. Requires a verified item, the app label typed back, and a reason. Rollback: reactivate.` : okta.canWriteOkta === null ? 'Okta roles unknown: ' + (okta.rolesError || okta.error || 'could not read') : 'Blocked: the Okta token has no app-admin role.', okta.canWriteOkta ? [] : [need('Okta APP_ADMIN (or higher) on the token owner', OKTA_GRANTOR)]);
  push('open_admin_page', 'Open Admin Page', 'technician', true, 'Opens the Okta or Entra admin page in a new tab. You act with your own signed-in permissions.');
  push('continue_with_claude', 'Continue with Claude in Chrome', 'browser', true, 'Handoff: copy the instructions and paste them to Claude in Chrome, which drives the admin page inside your own browser session with your own permissions. This page cannot launch or control the extension, and a handoff is never counted as an automatic execution.');
  push('validate', 'Validate', 'analysis', has('AuditLog.Read.All') !== false, has('AuditLog.Read.All') === false ? 'Blocked: AuditLog.Read.All is not consented.' : 'Reads sign-in evidence and the Entra object. Missing evidence stays inconclusive.', has('AuditLog.Read.All') === false ? [need('AuditLog.Read.All', ENTRA_GRANTOR)] : []);
  push('zsnet_refresh', 'Discover / Refresh (Zscaler mirror)', 'analysis', zs.serverGroups === 'ok' && acting, zs.serverGroups === 'ok' ? (zs.connectors === 'ok' ? 'ZPA and ZIA readable.' : 'ZPA segments, server groups and gateways are readable; the connector list is ' + zs.connectors + ' so connector rows are kept from the last successful read and labelled with their date.') : 'Zscaler API not readable: ' + (zs.error || zs.serverGroups), zs.connectors === 'denied' ? [need('ZPA API client role: Connector (read)', ZS_GRANTOR)] : []);
  push('export_record', 'Export Record', 'analysis', true, 'Downloads the dated migration record.');
  push('retry', 'Retry', 'analysis', acting, 'Re-runs a failed job. Jobs are idempotent: they rebuild the mirror and the queue, never vendor state.');
  return rows;
}

// GET /api/oem/access
/* The Okta admin console host for this org, derived from OKTA_BASE_URL
   (https://acme.okta.com -> https://acme-admin.okta.com). Null when unset. */
function oktaAdminBase(){
  const b = (process.env.OKTA_BASE_URL || '').replace(/\/+$/, '');
  if (!b) return null;
  return b.replace(/\.okta(preview|-emea)?\.com$/i, (m) => '-admin' + m);
}

router.get('/access', read(), async (req, res) => {
  try {
    const [graph, okta, zs, lvl] = await Promise.all([L.graphToken(), L.oktaIdentity(), L.zscalerProbe(), pageLevel(req)]);
    const roles = graph.roles || [];
    const key = {};
    for (const k of GRAPH_KEYS) key[k] = graph.roles === null ? 'unknown' : roles.includes(k) ? 'granted' : 'missing';
    res.json({
      user: { email: actorOf(req), pageLevel: lvl, canAct: canAct(lvl, req), readOnly: !!(req.user && req.user.readOnly) },
      graph: { known: graph.roles !== null, checkedAt: graph.at ? new Date(graph.at).toISOString() : null, appId: graph.appId || null, tenantId: graph.tenantId || null, roleCount: graph.roles === null ? null : roles.length, roles, key, error: graph.error || null,
        identity: 'app-only (client credentials) — IT-Command-IdentityDiag' },
      okta: { known: !!okta.known, checkedAt: okta.checkedAt, login: okta.login || null, userId: okta.userId || null, roles: okta.roles || null, canWriteOkta: okta.known ? okta.canWriteOkta : null, error: okta.error || okta.rolesError || null, identity: 'SSWS API token', adminBase: oktaAdminBase() },
      zscaler: { checkedAt: zs.checkedAt, serverGroups: zs.serverGroups, connectors: zs.connectors, gateways: zs.gateways, error: zs.error || null, identity: 'OneAPI client (read-only)' },
      claudeInChrome: { mode: 'handoff', note: 'This page cannot launch or drive the Claude in Chrome extension. "Continue with Claude in Chrome" copies instructions; the extension acts inside your own browser session with your own permissions, and the result must be validated here afterwards.' },
      actions: actionTable({ graph, okta, zs, lvl, req }),
    });
  } catch (e) { fail(res, e, 'access'); }
});

/* --------------------------------------------------------------- freshness */

async function freshness() {
  const now = Date.now();
  const age = (d) => (d ? +((now - new Date(d).getTime()) / 3600000).toFixed(1) : null);
  const rows = [];
  const add = (key, label, at, status, note, live = false, extra = {}) => rows.push(Object.assign({ key, label, at: at ? new Date(at).toISOString() : null, ageHours: age(at), status, note, live, lastAttempt: null, lastSuccess: null }, extra));
  const [[oa]] = await pool.query(`SELECT completed_at, status, records_fetched FROM entra_sync_status WHERE job='okta_apps' ORDER BY id DESC LIMIT 1`);
  add('okta_apps', 'Okta applications (mirror)', oa && oa.completed_at, !oa ? 'unknown' : oa.status !== 'success' ? 'error' : age(oa.completed_at) > 30 ? 'stale' : 'ok', oa ? `${oa.records_fetched} apps read; nightly 04:40 + on demand` : 'never run');
  const cov = await L.metaGet('discovery_coverage', null);
  const classes = cov.v ? cov.v.classes : null;
  const denied = classes ? Object.entries(classes).filter(([k, c]) => c && (c.status === 'denied' || c.status === 'error')).map(([k]) => k) : [];
  add('okta_objects', 'Okta policies, authenticators, agents, hooks, tokens, zones (discovery)', cov.v && cov.v.at, !cov.v ? 'unknown' : denied.length ? 'partial' : age(cov.v.at) > 30 ? 'stale' : 'ok', cov.v ? (denied.length ? 'could not read: ' + denied.join(', ') : 'all classes read') : 'discovery has not run', false, { coverage: classes });
  const lr = await L.metaGet('last_run', null);
  add('okta_entra_policy_snapshot', 'Okta policies + Entra Conditional Access snapshot', lr.v && lr.v.finished, !lr.v ? 'unknown' : lr.v.ok === false ? 'error' : age(lr.v.finished) > 30 ? 'stale' : 'ok', lr.v ? ((lr.v.warnings || []).length ? (lr.v.warnings || []).length + ' warning(s)' : 'collector 05:36 + on demand') : 'never run');
  const [[ea]] = await pool.query(`SELECT completed_at, status, records_fetched FROM entra_sync_status WHERE job='apps' ORDER BY id DESC LIMIT 1`);
  const [[eaIds]] = await pool.query(`SELECT SUM(JSON_EXTRACT(raw_json,'$.replyUrls') IS NOT NULL) with_ids, COUNT(*) total FROM entra_apps`);
  add('entra_apps', 'Entra enterprise applications (mirror)', ea && ea.completed_at, !ea ? 'unknown' : ea.status !== 'success' ? 'error' : age(ea.completed_at) > 30 ? 'stale' : 'ok', ea ? `${ea.records_fetched} principals; ${eaIds.with_ids || 0} of ${eaIds.total} carry reply URLs (identifier matching needs them)` : 'never run', false, { identifiersKnown: eaIds.with_ids || 0, total: eaIds.total });
  const [[sp]] = await pool.query(`SELECT MAX(collected_at) at, COUNT(*) n, SUM(sync_status='denied') denied FROM oem_entra_sp`);
  add('entra_sp_extras', 'Entra provisioning jobs + signing certificates', sp && sp.at, !sp || !sp.n ? 'unknown' : sp.denied ? 'partial' : age(sp.at) > 30 ? 'stale' : 'ok', sp && sp.n ? `${sp.n} principals read${sp.denied ? '; provisioning denied for ' + sp.denied : ''}` : 'not read yet');
  // zsnet-sync writes one summary row (source='all', status ok|partial|error) plus per-source rows.
  // Older runs wrote only source='all'/'ok', so the filter below reads both generations.
  const [[zl]] = await pool.query(`SELECT finished_at, status, error FROM zsnet_sync_log WHERE source='all' ORDER BY id DESC LIMIT 1`);
  const [[zok]] = await pool.query(`SELECT finished_at, status, error FROM zsnet_sync_log WHERE source='all' AND status IN ('ok','partial') ORDER BY id DESC LIMIT 1`);
  const [[zconn]] = await pool.query(`SELECT finished_at FROM zsnet_sync_log WHERE ((source='zpa_connector' AND status='ok') OR (source='all' AND status='ok')) ORDER BY id DESC LIMIT 1`);
  add('zscaler_mirror', 'Zscaler ZPA/ZIA mirror (SIPA segments, server groups, gateways)', zok && zok.finished_at,
    !zok ? 'unknown' : age(zok.finished_at) > 48 ? 'stale' : zok.status === 'partial' ? 'partial' : 'ok',
    zok ? `last successful sync ${new Date(zok.finished_at).toISOString().slice(0, 10)}${zok.status === 'partial' ? ' (partial: ' + (zok.error || '').slice(0, 120) + ')' : ''}${zl && zl.status === 'error' ? '; latest attempt failed: ' + (zl.error || '').slice(0, 120) : ''}; connector rows last refreshed ${zconn && zconn.finished_at ? new Date(zconn.finished_at).toISOString().slice(0, 10) : 'never'}` : 'never synced');
  const zs = await L.zscalerProbe();
  add('zscaler_live', 'Zscaler live read (this page probes the API)', zs.checkedAt, zs.serverGroups === 'ok' ? (zs.connectors === 'ok' ? 'ok' : 'partial') : 'error', `server groups ${zs.serverGroups}, connectors ${zs.connectors}, ZIA gateways ${zs.gateways}`, true);
  const me = await L.metaGet('mfa_evidence', null);
  add('signin_evidence', 'Entra sign-in evidence (MFA measurement)', me.v && me.v.at, !me.v ? 'unknown' : me.v.ok === false ? 'error' : age(me.v.at) > 48 ? 'stale' : 'ok', me.v ? `${me.v.events} interactive sign-ins, ${me.v.spanStart ? me.v.spanStart.slice(0, 10) + ' → ' + (me.v.spanEnd || '').slice(0, 10) : ''}` : 'not measured yet');
  const mr = await L.metaGet('mfa_registration', null);
  add('mfa_registration', 'Entra MFA registration report', mr.v && (mr.v.measured_at || mr.at), !mr.v ? 'unknown' : age(mr.v.measured_at || mr.at) > 48 ? 'stale' : 'ok', mr.v ? `${mr.v.total} users in the report` : 'not read');
  const wi = await L.metaGet('work_items_last', null);
  add('work_queue', 'Work queue build', wi.v && wi.v.at, !wi.v ? 'unknown' : age(wi.v.at) > 30 ? 'stale' : 'ok', wi.v ? Object.entries(wi.v.counts || {}).map(([k, v]) => `${k} ${v}`).join(', ') : 'never built');
  await attachGenerations(rows);
  return rows;
}

/* Last attempt and last success are two different facts (SPEC: never overwrite a last-success timestamp with a failed
   attempt). Both come from oem_source_generation (latest row of any status, latest success) merged with the older
   entra_sync_status rows for the two mirrors, newest wins. Missing table or no row → the fields stay null. */
async function attachGenerations(rows) {
  const la = {}, ls = {};
  try {
    const [gens] = await pool.query(`SELECT id, source_key, status, started_at, finished_at, records, error, job_id FROM oem_source_generation WHERE scope IS NULL ORDER BY id DESC LIMIT 400`);
    for (const g of gens || []) {
      if (!la[g.source_key]) la[g.source_key] = { at: iso(g.finished_at || g.started_at), status: g.status, error: g.error || null, jobId: g.job_id || null, generationId: g.id };
      if (!ls[g.source_key] && g.status === 'success') ls[g.source_key] = { at: iso(g.finished_at || g.started_at), records: g.records === undefined ? null : g.records, generationId: g.id };
    }
  } catch (e) { /* oem_source_generation not created yet: fields stay null */ }
  const newer = (a, b) => (!a ? b : !b ? a : (new Date(b.at).getTime() || 0) > (new Date(a.at).getTime() || 0) ? b : a);
  for (const [key, job] of [['okta_apps', 'okta_apps'], ['entra_apps', 'apps']]) {
    try {
      const [[att]] = await pool.query(`SELECT id, completed_at, started_at, status, records_fetched, error_message FROM entra_sync_status WHERE job=? ORDER BY id DESC LIMIT 1`, [job]);
      const [[suc]] = await pool.query(`SELECT id, completed_at, records_fetched FROM entra_sync_status WHERE job=? AND status='success' ORDER BY id DESC LIMIT 1`, [job]);
      if (att && (att.completed_at || att.started_at)) la[key] = newer(la[key], { at: iso(att.completed_at || att.started_at), status: att.status === 'success' ? 'success' : att.status === 'running' ? 'running' : 'failed', error: att.error_message || null, jobId: null, syncId: att.id });
      if (suc && suc.completed_at) ls[key] = newer(ls[key], { at: iso(suc.completed_at), records: suc.records_fetched === undefined ? null : suc.records_fetched, syncId: suc.id });
    } catch (e) { /* column set differs on an older schema: keep what the generation table said */ }
  }
  for (const r of rows) { r.lastAttempt = la[r.key] || null; r.lastSuccess = ls[r.key] || null; }
  return rows;
}

/* --------------------------------------------------------------- dashboard */

function recommendNext(items, retirement, freshnessRows, active) {
  if (active.length) return { code: 'wait', title: `A job is running: ${active[0].jobKey}`, why: 'Wait for it to finish; the queue rebuilds when it does.', jobId: active[0].id };
  const fr = Object.fromEntries(freshnessRows.map((r) => [r.key, r]));
  if (!fr.work_queue || fr.work_queue.status === 'unknown') return { code: 'discover', title: 'Run Discover to build the work queue from Okta', why: 'Nothing has been discovered yet. Discovery reads Okta and Entra with existing permissions and changes nothing.', action: 'discover' };
  if (fr.entra_apps && fr.entra_apps.identifiersKnown === 0) return { code: 'discover', title: 'Run Discover so the Entra mirror carries reply URLs', why: 'Identifier-based matching needs reply URLs and identifier URIs; the mirror has none yet.', action: 'discover' };
  const fed = items.find((i) => i.item_key.startsWith('dep:app:') && /Domain federation/.test(i.title) && !['verified', 'retired'].includes(i.state));
  const highApps = items.filter((i) => i.category === 'applications' && i.source_status === 'ACTIVE' && i.state === 'needs_review');
  const conflicts = items.filter((i) => i.category === 'applications' && i.facts && i.facts.match && i.facts.match.conflict);
  if (conflicts.length) return { code: 'conflict', title: `Resolve ${conflicts.length} match conflict${conflicts.length === 1 ? '' : 's'}`, why: 'A confirmed decision disagrees with a new identifier match. Confirmed decisions are kept; the conflict needs a person.', itemKey: conflicts[0].item_key };
  const highMatches = highApps.filter((i) => i.facts && i.facts.match && i.facts.match.decision === 'auto_high');
  if (highMatches.length) return { code: 'review', title: `Confirm ${highMatches.length} identifier-matched application${highMatches.length === 1 ? '' : 's'}`, why: 'These matched on a durable identifier (launcher link, ACS URL or audience). Confirming them moves them to Ready with one click each.', itemKey: highMatches[0].item_key, filter: { category: 'applications', state: 'needs_review' } };
  const ready = items.filter((i) => i.category === 'applications' && i.state === 'ready');
  if (ready.length) return { code: 'validate', title: `Validate ${ready.length} ready application${ready.length === 1 ? '' : 's'} in Entra`, why: 'Configuration matches on every field we can read; a test sign-in through Entra is what turns Ready into Verified.', itemKey: ready[0].item_key, filter: { category: 'applications', state: 'ready' } };
  if (highApps.length) return { code: 'review', title: `Review ${highApps.length} application${highApps.length === 1 ? '' : 's'} with no confirmed Entra match`, why: 'Each needs a decision: confirm a suggested match, create the Entra app, or retire it.', itemKey: highApps[0].item_key, filter: { category: 'applications', state: 'needs_review' } };
  if (fed) return { code: 'federation', title: 'Plan the auction.com domain cutover away from Okta federation', why: 'Applications are handled; the federated domain is the last large dependency.', itemKey: fed.item_key };
  const dep = (retirement.blockers || [])[0];
  if (dep) return { code: 'dependency', title: 'Work the next Okta dependency: ' + dep.title, why: dep.nextAction, itemKey: dep.key };
  return { code: 'done', title: 'Nothing is blocking retirement — do the final sign-in log review', why: retirement.verdict };
}

// GET /api/oem/dashboard
router.get('/dashboard', read(), async (req, res) => {
  try {
    const [items] = await pool.query(`SELECT item_key, category, title, source_kind, source_status, disposition, state, facts, first_seen_at, last_seen_at, seen_in_last_discovery FROM oem_work_item`);
    for (const it of items) it.facts = j(it.facts, {});
    const seen = items.filter((i) => i.seen_in_last_discovery);
    const gone = items.filter((i) => !i.seen_in_last_discovery);
    const wi = await L.metaGet('work_items_last', null);
    const lastBuild = wi.v ? new Date(wi.v.at) : null;
    const newSince = lastBuild ? seen.filter((i) => i.first_seen_at && Math.abs(new Date(i.first_seen_at) - lastBuild) < 5000).length : 0;
    const categories = {};
    for (const cat of Object.keys(CATEGORY_LABEL)) {
      const list = seen.filter((i) => i.category === cat);
      const byState = {}; for (const s of STATES) byState[s] = 0;
      let excluded = 0;
      for (const i of list) { if (i.disposition === 'exclude') { excluded++; continue; } byState[i.state]++; }
      const inScope = list.length - excluded;
      const done = byState.verified + byState.retired;
      categories[cat] = { key: cat, label: CATEGORY_LABEL[cat], total: list.length, inScope, excluded, byState, done, pct: inScope ? Math.round(100 * done / inScope) : 0,
        denominator: cat === 'applications' ? 'unique Okta applications (active and inactive), each counted once even when several share one Entra app' : cat === 'policies' ? 'Okta policies plus the translation steps that produce Entra policies' : cat === 'mfa' ? 'Okta authenticators and MFA enrolment policies' : cat === 'network_device' ? 'Okta network zones, SIPA egress addresses and the device-coverage prerequisite' : 'Okta platform pieces something still depends on (federation, agents, LDAP, RADIUS, hooks, tokens)',
        blocked: byState.blocked, waiting: byState.waiting_technician + byState.awaiting_validation };
      if (cat === 'applications') {
        // Active apps are what the Applications view lists by default; activeOpen is that list minus verified/retired, so the
        // sidebar can show the count before the queue has loaded.
        const act = list.filter((i) => i.disposition !== 'exclude' && String(i.source_status || 'ACTIVE').toUpperCase() === 'ACTIVE');
        categories[cat].active = act.length;
        categories[cat].activeOpen = act.filter((i) => i.state !== 'verified' && i.state !== 'retired').length;
      }
    }
    const retirement = await D.assessRetirement();
    const fr = await freshness();
    const active = await L.listJobs({ active: true, limit: 5 });
    // A mapping's "why" is the key of the translation it waits on; say that translation's name, not its key.
    const titleOf = (k) => { const t = seen.find((x) => x.item_key === k); return t ? String(t.title).replace(/^Translation — /, '') : null; };
    const blockNote = (i) => {
      const why = i.facts.nextAction ? i.facts.nextAction.why : null;
      const pre = why && i.facts.mapping && i.facts.mapping.blockedBy === why ? titleOf('mapping:' + why) : null;
      return pre ? 'Waits on the prerequisite “' + pre + '”.' : (i.state_note || why || null);
    };
    const blockers = seen.filter((i) => i.state === 'blocked' && i.disposition !== 'exclude').map((i) => ({ key: i.item_key, title: i.title, category: i.category, note: blockNote(i) }));
    const stale = fr.filter((r) => r.status === 'stale' || r.status === 'error');
    const totals = Object.values(categories).reduce((a, c) => ({ inScope: a.inScope + c.inScope, done: a.done + c.done }), { inScope: 0, done: 0 });
    res.json({
      generatedAt: L.nowIso(),
      generation: await currentGeneration(),
      categories, stateLabels: STATE_LABEL, states: STATES,
      progress: { inScope: totals.inScope, done: totals.done, pct: totals.inScope ? Math.round(100 * totals.done / totals.inScope) : 0, note: 'Done = Verified + Retired. Verified needs tested evidence, never a generated payload or an opened portal.' },
      blockers: blockers.slice(0, 12), blockerCount: blockers.length,
      nextAction: recommendNext(seen, retirement, fr, active),
      retirement: { canRetire: retirement.canRetire, verdict: retirement.verdict, reasons: retirement.reasons, blockerCount: retirement.blockers.length, critical: retirement.blockers.filter((b) => b.severity === 'critical').length },
      freshness: fr, staleSources: stale.map((s) => s.key),
      changes: { newInLastDiscovery: newSince, noLongerInOkta: gone.length, noLongerInOktaItems: gone.slice(0, 20).map((g) => ({ key: g.item_key, title: g.title, state: g.state })) },
      jobsActive: active,
      matcher: (await L.metaGet('matcher_last', null)).v,
    });
  } catch (e) { fail(res, e, 'dashboard'); }
});

/* -------------------------------------------------------------- work queue */

/* The item list reads evidence as a raw column; only the detail route parses it. Either shape answers the one
   question this asks, so the label is right on the queue row and in the drawer without a second query. */
function bmRetained(it) {
  if (it.state !== 'retired') return false;
  const e = it.evidence;
  if (!e) return false;
  return typeof e === 'string' ? e.indexOf('bookmarkRetirement') >= 0 : !!e.bookmarkRetirement;
}
function lean(it) {
  const f = it.facts || {};
  const out = { key: it.item_key, category: it.category, categoryLabel: CATEGORY_LABEL[it.category], title: it.title, sourceKind: it.source_kind, sourceId: it.source_id, sourceStatus: it.source_status, disposition: it.disposition, state: it.state, stateLabel: bmRetained(it) ? 'Retired \u2014 bookmark retained' : STATE_LABEL[it.state], bookmarkRetained: bmRetained(it), autoState: it.auto_state, stateNote: it.state_note, stateActor: it.state_actor, stateUpdatedAt: it.state_updated_at, lastSeenAt: it.last_seen_at, seen: !!it.seen_in_last_discovery, nextAction: f.nextAction || null, assignee: it.assignee || null, assignedAt: it.assigned_at || null, assignedBy: it.assigned_by || null };
  if (it.category === 'applications' && f.okta) out.summary = { signOnMode: f.okta.signOnMode, users: f.okta.users, groups: f.okta.groups, provisioning: f.okta.provisioning, decision: f.match ? f.match.decision : null, entraName: f.match ? f.match.entraName : null, entraId: f.match ? f.match.entraId : null, highDiffs: (f.differences || []).filter((d) => d.severity === 'high').length, missing: (f.missing || []).length, conflict: !!(f.match && f.match.conflict), hidden: f.okta.hidden };
  else if (f.okta) out.summary = { status: f.okta.status, kind: f.kind || f.okta.type || null, users: f.okta.users };
  else if (f.mapping) out.summary = { phase: f.mapping.phase, blockedBy: f.mapping.blockedBy, noEquivalent: !!f.mapping.noEquivalent };
  else if (f.anchor) out.summary = { trusted: f.anchor.entraTrusted, site: f.anchor.site };
  return out;
}

// GET /api/oem/work?category=&state=&q=&disposition=&kind=&decision=&includeExcluded=1&includeGone=1
router.get('/work', read(), async (req, res) => {
  try {
    const q = req.query || {};
    const where = [], params = [];
    if (q.category) { where.push('category=?'); params.push(q.category); }
    if (q.state) { where.push('state IN (?)'); params.push(String(q.state).split(',')); }
    if (q.disposition) { where.push('disposition=?'); params.push(q.disposition); }
    else if (q.includeExcluded !== '1') where.push(`(disposition IS NULL OR disposition<>'exclude')`);
    if (q.includeGone !== '1') where.push('seen_in_last_discovery=1');
    if (q.sourceStatus) { where.push('source_status=?'); params.push(q.sourceStatus); }
    if (q.assignee === 'me') { where.push('assignee=?'); params.push(actorOf(req)); }
    else if (q.assignee === 'none') where.push('assignee IS NULL');
    else if (q.assignee) { where.push('assignee=?'); params.push(String(q.assignee).slice(0, 255)); }
    if (q.q) { where.push('(title LIKE ? OR source_id LIKE ? OR item_key LIKE ?)'); const like = '%' + q.q + '%'; params.push(like, like, like); }
    const [rows] = await pool.query(`SELECT * FROM oem_work_item ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY FIELD(state,'blocked','needs_review','ready','running','waiting_technician','awaiting_validation','discovered','verified','retired'), title`, params);
    let items = rows.map((r) => { r.facts = j(r.facts, {}); return lean(r); });
    if (q.decision) items = items.filter((i) => i.summary && i.summary.decision === q.decision);
    if (q.kind) items = items.filter((i) => i.summary && (i.summary.kind === q.kind || i.summary.signOnMode === q.kind));
    const counts = {}; for (const i of items) counts[i.state] = (counts[i.state] || 0) + 1;
    res.json({ total: items.length, counts, generation: await currentGeneration(), items: items.slice(0, Math.min(parseInt(q.limit || '2000', 10) || 2000, 5000)) });
  } catch (e) { fail(res, e, 'work list'); }
});

async function loadItem(key) {
  const [[it]] = await pool.query(`SELECT * FROM oem_work_item WHERE item_key=?`, [key]);
  if (!it) return null;
  it.facts = j(it.facts, {}); it.evidence = j(it.evidence, null);
  return it;
}

// GET /api/oem/work/:key
router.get('/work/:key', read(), async (req, res) => {
  try {
    const it = await loadItem(req.params.key);
    if (!it) return res.status(404).json({ error: 'no such work item' });
    const [events] = await pool.query(`SELECT id, event, from_state, to_state, note, actor_email, evidence, created_at FROM oem_work_event WHERE item_key=? ORDER BY id DESC LIMIT 100`, [req.params.key]);
    const out = Object.assign(lean(it), { facts: it.facts, evidence: it.evidence, events: events.map((e) => Object.assign(e, { evidence: j(e.evidence, null) })) });
    if (it.category === 'applications' && it.facts.okta) {
      const [rows] = await pool.query(`SELECT id, entra_app_id, entra_app_display_name, match_confidence, match_method, notes, created_by, created_at, last_verified_at FROM app_matches WHERE okta_app_id=? ORDER BY created_at`, [it.source_id]);
      out.decisions = rows;
      const [[okta]] = await pool.query(`SELECT raw_json, last_synced_at FROM okta_apps WHERE okta_id=?`, [it.source_id]);
      const raw = okta ? (j(okta.raw_json, {}) || {}) : {};
      out.oktaDetail = L.redact({ settings: raw.settings || null, visibility: raw.visibility || null, credentials: raw.credentials ? { scheme: raw.credentials.scheme, userNameTemplate: raw.credentials.userNameTemplate, signingKid: raw.credentials.signing && raw.credentials.signing.kid } : null, licensing: raw.licensing || null, accessibility: raw.accessibility || null, links: raw._links ? Object.fromEntries(Object.entries(raw._links).filter(([k]) => ['appLinks', 'metadata', 'logo'].includes(k))) : null, mirroredAt: okta ? okta.last_synced_at : null });
      if (it.facts.match && it.facts.match.entraId) {
        const [[e]] = await pool.query(`SELECT raw_json, last_synced_at FROM entra_apps WHERE entra_id=?`, [it.facts.match.entraId]);
        const er = e ? (j(e.raw_json, {}) || {}) : {};
        out.entraDetail = { appId: er.appId, replyUrls: er.replyUrls || null, servicePrincipalNames: er.servicePrincipalNames || null, loginUrl: er.loginUrl || null, logoutUrl: er.logoutUrl || null, preferredSingleSignOnMode: er.preferredSingleSignOnMode || null, notificationEmailAddresses: er.notificationEmailAddresses || null, tags: er.tags || null, mirroredAt: e ? e.last_synced_at : null, portal: er.appId ? `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/${it.facts.match.entraId}/appId/${er.appId}` : null };
      }
      out.oktaAdminUrl = oktaAdminBase() ? `${oktaAdminBase()}/admin/app/${it.facts.okta.name}/instance/${it.source_id}` : null;
    }
    if (it.facts.mapping) out.mappingUrl = '#security/' + it.facts.mapping.key;
    res.json(out);
  } catch (e) { fail(res, e, 'work detail'); }
});

const VERIFY_KEYS = ['authentication', 'assignments', 'claims', 'provisioning', 'security', 'residualOkta'];
/* Conditional Access is a later phase, not a gate on moving an application: Okta stays the enforcement point
   until that contract is cancelled, so an application record is not held open waiting for a CA policy. The
   security line stays REQUIRED for policy items — there it IS the work. An application record may still carry
   a security line (older records do); it is simply no longer demanded. */
const APP_VERIFY_KEYS = VERIFY_KEYS.filter((k) => k !== 'security');
const verifyKeysFor = (it) => (it.category === 'applications' ? APP_VERIFY_KEYS : VERIFY_KEYS);

/* The one write that moves a work item between states. Every caller (the manual state route below, the v2 Live
   sign-off) goes through it, so the item row and its event row can never disagree. Returns the transition; throws
   {status:404} for an unknown key. `evidence` (object|null) is merged over the stored evidence by the caller and
   written whole; null keeps the stored evidence. */
async function setWorkState(key, state, actor, note, evidence) {
  if (!STATES.includes(state)) { const e = new Error('state must be one of ' + STATES.join(', ')); e.status = 400; throw e; }
  const it = await loadItem(key);
  if (!it) { const e = new Error('no such work item'); e.status = 404; throw e; }
  const ev = evidence && typeof evidence === 'object' ? evidence : null;
  const from = it.state;
  await pool.query(`UPDATE oem_work_item SET state=?, state_note=?, state_actor=?, state_updated_at=NOW(), evidence=COALESCE(?, evidence) WHERE item_key=?`, [state, note || null, actor || null, ev ? JSON.stringify(ev) : null, it.item_key]);
  await pool.query(`INSERT INTO oem_work_event (item_key, event, from_state, to_state, note, actor_email, evidence) VALUES (?,?,?,?,?,?,?)`, [it.item_key, 'state_set', from, state, note || null, actor || null, ev ? JSON.stringify(ev) : null]);
  /* The bookmark handoff is its own retirement status, not a footnote on "Retired": the tile is kept on
     purpose, so the label has to say so wherever the state is shown. */
  const label = state === 'retired' && ev && ev.bookmarkRetirement ? 'Retired — bookmark retained' : STATE_LABEL[state];
  return { ok: true, key: it.item_key, from, to: state, stateLabel: label };
}

// POST /api/oem/work/:key/state  {state, note, evidence, confirm}
router.post('/work/:key/state', json, admin(), async (req, res) => {
  try {
    const it = await loadItem(req.params.key);
    if (!it) return res.status(404).json({ error: 'no such work item' });
    const { state, note, confirm } = req.body || {};
    if (!STATES.includes(state)) return res.status(400).json({ error: 'state must be one of ' + STATES.join(', ') });
    if (state === 'running') return res.status(400).json({ error: 'Running is set by jobs, not by hand.' });
    /* Verified is a predicate, not a choice (bug 7): a passing verification attempt sets it through setWorkState from
       the v2 sign-off. The old typed-evidence path let a record move Needs Review → Verified after "0 pass, 1 fail". */
    if (state === 'verified') return res.status(403).json({ error: 'Verified is set by a passing verification, not by hand', how: 'Open the application and run Test and verify' });
    const actor = actorOf(req);
    let ev = null;
    if (state === 'retired') {
      /* Bookmark acknowledgement. An Okta tile that is a BOOKMARK pointing at the confirmed Entra
         application, with people signing in there, has no Okta sign-in path left to retire: the tile is a
         link into Entra. Acknowledging that is a decision, so it is recorded like one — but the facts
         behind it are re-derived HERE, from the same oem-usage code the page reads. The client may ask for
         the acknowledgement; it may not assert that it applies. Because that re-derivation IS the proof, an
         acknowledged bookmark does not wait on the typed Verified step — a confirmed My Apps bookmark with
         live Entra sign-ins is migrated, and this records it directly. The typed-title retirement below is a
         human statement rather than a re-derived fact, so it still follows Verified. */
      const wantAck = (req.body || {}).bookmarkAck === true;
      let ack = null;
      if (wantAck) {
        if (it.source_kind !== 'okta_app') return res.status(400).json({ error: 'The bookmark acknowledgement applies to Okta applications only.' });
        if (!USAGE) return res.status(503).json({ error: 'Usage data is unavailable, so the bookmark cannot be re-checked. Retire with the typed confirmation instead.' });
        const oktaId = it.source_id || String(it.item_key).replace(/^app:/, '');
        let u = null;
        try { u = await USAGE.forApp(oktaId); } catch (e) { return res.status(502).json({ error: 'Could not re-read the usage data to check the bookmark: ' + String(e && e.message || e).slice(0, 200) }); }
        const b = u && u.bookmark;
        if (!b || !b.isBookmark) return res.status(400).json({ error: 'This Okta application is not a bookmark tile, so it cannot be retired as one. Use the typed confirmation.' });
        if (!b.retirable || !b.retirable.ok) return res.status(400).json({ error: 'The bookmark does not qualify to retire with the migration.', problems: (b.retirable && b.retirable.blockers) || ['The tile does not open the confirmed Entra application.'] });
        ack = { basis: b.retirable.basis, destination: b.destination, tileUrl: b.url || null,
          entraApp: (u.entra && (u.entra.name || u.entra.appId)) || null, entraUsers30: (u.entra && u.entra.users30) != null ? u.entra.users30 : null,
          checkedAt: u.checkedAt || L.nowIso(), acknowledgedBy: actor, acknowledgedAt: L.nowIso() };
      } else {
        if (!(it.state === 'verified' || it.disposition === 'retire' || it.disposition === 'exclude')) return res.status(400).json({ error: 'Retired follows Verified, or a Retire disposition. Configuration, testing and retirement are tracked separately.' });
        if (String(confirm || '') !== it.title) return res.status(400).json({ error: 'Type the item title exactly to confirm retirement.', expected: it.title });
      }
      if (ack) ev = Object.assign({}, it.evidence || {}, { bookmarkRetirement: ack,
        retiredNote: 'Retired — bookmark retained. The Okta tile is a link into Entra and stays; nothing in Okta was changed.' });
      else if (it.source_status === 'ACTIVE' && it.source_kind === 'okta_app') ev = Object.assign({}, it.evidence || {}, { retiredNote: 'Recorded as retired while Okta still shows the app ACTIVE. This record does not deactivate anything in Okta.' });
    }
    if (['blocked', 'waiting_technician'].includes(state) && !(note && String(note).trim().length >= 3)) return res.status(400).json({ error: 'Say what is blocking / what the technician must do.' });
    const out = await setWorkState(it.item_key, state, actor, note || null, ev);
    await audit(req, 'oem_work_state', { item: it.item_key, from: out.from, to: state });
    res.json(out);
  } catch (e) { fail(res, e, 'work state'); }
});

// POST /api/oem/work/:key/assign {assignee}  — 'me', an email, or null/'' to unassign. Assignment is a record of who
// is working the item; it grants nothing and changes no state.
router.post('/work/:key/assign', json, admin(), async (req, res) => {
  try {
    const it = await loadItem(req.params.key);
    if (!it) return res.status(404).json({ error: 'no such work item' });
    const actor = actorOf(req);
    let who = (req.body || {}).assignee;
    if (who === 'me') who = actor;
    who = who ? String(who).trim().toLowerCase() : null;
    if (who && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(who)) return res.status(400).json({ error: 'assignee must be an email address, "me", or empty to unassign' });
    const from = it.assignee || null;
    await pool.query(`UPDATE oem_work_item SET assignee=?, assigned_at=IF(? IS NULL, NULL, NOW()), assigned_by=IF(? IS NULL, NULL, ?) WHERE item_key=?`, [who, who, who, actor, it.item_key]);
    await pool.query(`INSERT INTO oem_work_event (item_key, event, note, actor_email) VALUES (?,?,?,?)`, [it.item_key, who ? 'assigned' : 'unassigned', who ? (from ? `${from} → ${who}` : who) : (from || null), actor]);
    await audit(req, 'oem_work_assign', { item: it.item_key, from, to: who });
    res.json({ ok: true, key: it.item_key, assignee: who, from });
  } catch (e) { fail(res, e, 'work assign'); }
});

// POST /api/oem/work/:key/disposition {disposition, reason}
router.post('/work/:key/disposition', json, admin(), async (req, res) => {
  try {
    const it = await loadItem(req.params.key);
    if (!it) return res.status(404).json({ error: 'no such work item' });
    const { disposition, reason } = req.body || {};
    if (!['migrate', 'investigate', 'retire', 'exclude'].includes(disposition)) return res.status(400).json({ error: 'disposition must be migrate, investigate, retire or exclude' });
    if (disposition === 'exclude' && !(reason && String(reason).trim().length >= 5)) return res.status(400).json({ error: 'An exclusion needs a reason; it is recorded and shown in the counts.' });
    const actor = actorOf(req);
    await pool.query(`UPDATE oem_work_item SET disposition=?, state_note=COALESCE(?, state_note), state_actor=?, state_updated_at=NOW() WHERE item_key=?`, [disposition, reason || null, actor, it.item_key]);
    await pool.query(`INSERT INTO oem_work_event (item_key, event, note, actor_email) VALUES (?,?,?,?)`, [it.item_key, 'disposition_' + disposition, reason || null, actor]);
    await audit(req, 'oem_work_disposition', { item: it.item_key, disposition, reason: reason || null });
    res.json({ ok: true, key: it.item_key, disposition });
  } catch (e) { fail(res, e, 'work disposition'); }
});

/* ------------------------------------------------------------ validation */

/* The automated checks for one work item, as data: [{name, result: pass|fail|inconclusive|info|not_applicable, detail,
   data}]. Reads Okta, Graph and the snapshot tables; changes nothing. The /validate route below records the result on
   the item; the v2 verification (oem-v2-routes) turns the same list into an immutable attempt. `opts.since14d` /
   `opts.since7d` override the sign-in windows (tests). */
async function validationScanModel(oktaId) {
  try {
    const [[row]] = await pool.query(`SELECT normalized FROM oem_app_scan WHERE okta_id=?`, [oktaId]);
    return row ? j(row.normalized, null) : null;
  } catch (e) { return null; }
}

function synchronizationMappings(schema) {
  const out = [];
  const rules = schema && Array.isArray(schema.synchronizationRules) ? schema.synchronizationRules : [];
  for (const rule of rules) for (const object of Array.isArray(rule.objectMappings) ? rule.objectMappings : []) {
    for (const a of Array.isArray(object.attributeMappings) ? object.attributeMappings : []) {
      out.push({ objectName: object.name || null, enabled: object.enabled !== false,
        targetAttributeName: a.targetAttributeName || null,
        matchingPriority: Number(a.matchingPriority || 0), flowType: a.flowType || null,
        flowBehavior: a.flowBehavior || null, source: a.source || null });
    }
  }
  return out;
}

function provisioningTargetKey(v) {
  return String(v || '').trim().toLowerCase().replace(/\s+/g, '');
}

async function validateProvisioningJob(spId, jobs, scanModel) {
  const failures = [];
  const data = { sourceFingerprint: scanModel && scanModel.provisioning && scanModel.provisioning.fingerprint || null, jobs: [], entraMappings: [] };
  if (!jobs.length) return { result: 'fail', detail: 'Okta provisions this app; Entra has no provisioning job.', data };
  for (const job of jobs) {
    const s = job.status || {};
    const code = s.code || 'unknown';
    const successive = Number(s.countSuccessiveCompleteFailures || 0);
    const lastSuccess = s.lastSuccessfulExecution && s.lastSuccessfulExecution.timeBegan || null;
    const lastExport = s.lastSuccessfulExecutionWithExports && s.lastSuccessfulExecutionWithExports.timeBegan || null;
    data.jobs.push({ id: job.id, template: job.templateId, state: code, successiveFailures: successive,
      lastSuccess, lastSuccessfulExport: lastExport, quarantine: s.quarantine || null });
    if (code !== 'Active') failures.push(`job ${job.id || job.templateId || 'unknown'} is ${code}, not Active`);
    if (s.quarantine) failures.push(`job ${job.id || job.templateId || 'unknown'} is quarantined${s.quarantine.reason ? ': ' + s.quarantine.reason : ''}`);
    if (successive > 0) failures.push(`job ${job.id || job.templateId || 'unknown'} has ${successive} successive complete failure(s)`);
    if (!lastSuccess) failures.push(`job ${job.id || job.templateId || 'unknown'} has no successful cycle`);
    if (!lastExport) failures.push(`job ${job.id || job.templateId || 'unknown'} has no successful export`);
    if (!job.id) { failures.push('a provisioning job has no readable id'); continue; }
    const sr = await L.graphGet(`/v1.0/servicePrincipals/${spId}/synchronization/jobs/${encodeURIComponent(job.id)}/schema`);
    if (sr.status !== 200 || !sr.body) failures.push(`job ${job.id} schema could not be read: ${sr.error || ('HTTP ' + sr.status)}`);
    else data.entraMappings.push(...synchronizationMappings(sr.body));
  }
  const p = scanModel && scanModel.provisioning;
  if (!p || !p.inventory || p.inventory.complete !== true) failures.push('the current Okta provisioning inventory is incomplete');
  else {
    const expected = (p.mappings || []).filter((x) => x.direction === 'to_app' && String(x.pushStatus || 'PUSH') !== 'DONT_PUSH')
      .map((x) => ({ key: provisioningTargetKey(x.externalName || x.targetAttribute), label: x.externalName || x.targetAttribute }))
      .filter((x) => x.key);
    const have = new Set(data.entraMappings.filter((x) => x.enabled).map((x) => provisioningTargetKey(x.targetAttributeName)));
    const missing = expected.filter((x) => !have.has(x.key));
    if (missing.length) failures.push(`${missing.length} Okta target attribute(s) are absent from the Entra synchronization schema: ${missing.slice(0, 8).map((x) => x.label).join(', ')}`);
    const matching = data.entraMappings.filter((x) => x.enabled && x.matchingPriority > 0);
    if (!matching.length) failures.push('the Entra synchronization schema has no enabled matching attribute');
  }
  return { result: failures.length ? 'fail' : 'pass',
    detail: failures.length ? failures.join('; ') : `${jobs.length} Active job(s), successful export recorded, ${(data.entraMappings || []).length} Entra attribute mapping(s) checked against the current Okta contract.`, data };
}

async function runValidationChecks(it, opts = {}) {
  const checks = [];
  const push = (name, result, detail, data) => checks.push({ name, result, detail, data: data === undefined ? undefined : L.redact(data) });
  if (!it || !it.facts) { push('Automated validation', 'not_applicable', 'No work item facts to check.'); return checks; }
  {
    if (it.category === 'applications') {
      const m = it.facts.match || {};
      if (!m.entraId || !/^(manual_confirmed|manual_staged)$/.test(m.decision)) push('Entra app confirmed', 'fail', 'No confirmed Entra app. Confirm a match first.');
      else {
        const sp = await L.graphGet(`/v1.0/servicePrincipals/${m.entraId}?$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,preferredSingleSignOnMode,replyUrls,servicePrincipalNames,loginUrl`);
        if (sp.status !== 200) push('Entra app exists (live)', sp.status === 404 ? 'fail' : 'inconclusive', sp.status === 404 ? 'The service principal no longer exists in Entra.' : 'Could not read it: ' + (sp.error || sp.status));
        else {
          const b = sp.body;
          const scanModel = await validationScanModel(it.source_id || it.facts.okta.id);
          push('Entra app exists (live)', 'pass', `${b.displayName} (${b.appId}) accountEnabled=${b.accountEnabled} ssoMode=${b.preferredSingleSignOnMode || 'not set'}`, { replyUrls: b.replyUrls, identifierUris: (b.servicePrincipalNames || []).filter((x) => !/^[0-9a-f-]{36}$/i.test(x)) });
          push('Entra app enabled', b.accountEnabled ? 'pass' : 'fail', b.accountEnabled ? 'accountEnabled = true' : 'accountEnabled = false');
          if (it.facts.okta.signOnMode === 'SAML_2_0') {
            push('SSO mode is SAML', b.preferredSingleSignOnMode === 'saml' ? 'pass' : 'fail', 'preferredSingleSignOnMode = ' + (b.preferredSingleSignOnMode || 'not set'));
            const ids = it.facts.okta.identifiers || {};
            const ar = await L.graphGet(`/v1.0/applications?$filter=appId eq '${b.appId}'&$select=id,appId,identifierUris,web`);
            const app = ar.status === 200 && ar.body && ar.body.value && ar.body.value[0];
            if (!app) {
              if (ids.acs && ids.acs.length) push('Reply URL matches Okta ACS URL', 'inconclusive', 'The backing application registration could not be read: ' + (ar.error || ('HTTP ' + ar.status)));
              if (ids.audience && ids.audience.length) push('Identifier (Entity ID) matches Okta audience', 'inconclusive', 'The backing application registration could not be read.');
            } else {
              const replies = app.web && app.web.redirectUris || [];
              const rep = new Set(replies.map(L.normUrl)), identifiers = new Set((app.identifierUris || []).map(L.normUrl));
              if (ids.acs && ids.acs.length) push('Reply URL matches Okta ACS URL', ids.acs.some((x) => rep.has(L.normUrl(x))) ? 'pass' : 'fail', ids.acs[0] + (ids.acs.some((x) => rep.has(L.normUrl(x))) ? ' is a reply URL' : ' is not among the application registration reply URLs: ' + replies.slice(0, 3).join(', ')));
              if (ids.audience && ids.audience.length) push('Identifier (Entity ID) matches Okta audience', ids.audience.some((x) => identifiers.has(L.normUrl(x))) ? 'pass' : 'fail', ids.audience[0]);
            }
          }
          const asg = await L.graphGet(`/v1.0/servicePrincipals/${m.entraId}/appRoleAssignedTo?$top=999&$count=true`);
          if (asg.status === 200) {
            const n = (asg.body.value || []).length;
            const sourceAssignments = scanModel && scanModel.assignments;
            const su = sourceAssignments && sourceAssignments.users;
            const sg = sourceAssignments && sourceAssignments.groups;
            const direct = su && Number(su.direct);
            const sourceComplete = !!sourceAssignments && !!su && su.directComplete === true && su.partial === false &&
              Number.isFinite(direct) && direct >= 0 && Array.isArray(sg) && !sourceAssignments.groupsError;
            const expected = sourceComplete ? direct + sg.length : null;
            const truncated = !!(asg.next || asg.body && asg.body['@odata.nextLink']);
            const ok = expected === null ? false : !truncated && n === expected && b.appRoleAssignmentRequired === true;
            push('Assignments in Entra', ok ? 'pass' : (expected === null || truncated ? 'inconclusive' : 'fail'), `${n} assignment${n === 1 ? '' : 's'}${truncated ? '+' : ''}; expected exactly ${expected === null ? 'an unknown number because the Okta scan is incomplete' : expected + ' (' + direct + ' direct user(s) + ' + sg.length + ' group(s))'}; assignment required=${b.appRoleAssignmentRequired === true}.`);
          }
          else push('Assignments in Entra', 'inconclusive', 'Could not read: ' + (asg.error || asg.status));
          const sj = await L.graphGet(`/v1.0/servicePrincipals/${m.entraId}/synchronization/jobs`);
          if (it.facts.okta.provisioning) {
            if (sj.status === 200) { const pv = await validateProvisioningJob(m.entraId, sj.body.value || [], scanModel); push('Provisioning job in Entra', pv.result, pv.detail, pv.data); }
            else push('Provisioning job in Entra', 'inconclusive', sj.status === 403 ? 'Denied: needs Synchronization.Read.All (an Entra Global Administrator can consent).' : 'Could not read: ' + (sj.error || sj.status));
          } else push('Provisioning', 'not_applicable', 'Okta does not provision this app.');
          const since = opts.since14d || new Date(Date.now() - 14 * 86400000).toISOString();
          const s1 = await L.graphGet(`/v1.0/auditLogs/signIns?$top=50&$filter=createdDateTime ge ${since} and appId eq '${b.appId}'`);
          const s2 = await L.graphGet(`/v1.0/auditLogs/signIns?$top=50&$filter=createdDateTime ge ${since} and resourceId eq '${m.entraId}'`);
          const seenIds = new Set();
          const rows = [].concat(s1.status === 200 ? (s1.body.value || []) : [], s2.status === 200 ? (s2.body.value || []) : [])
            .filter((r) => { const id = r.id || (r.createdDateTime + '|' + r.userPrincipalName); if (seenIds.has(id)) return false; seenIds.add(id); return true; })
            .sort((a, b) => String(b.createdDateTime || '').localeCompare(String(a.createdDateTime || ''))); // newest first (the two reads overlap)
          const dayAgo = new Date(Date.now() - 86400000).toISOString();
          if (s1.status !== 200 && s2.status !== 200) push('Sign-ins through Entra (14 days)', 'inconclusive', 'Sign-in log not readable: ' + (s1.error || s1.status));
          else {
            const okN = rows.filter((r) => r.status && r.status.errorCode === 0).length, failN = rows.length - okN;
            const ca = {}; for (const r of rows) for (const p of (r.appliedConditionalAccessPolicies || [])) if (p.result !== 'notApplied') ca[p.displayName] = (ca[p.displayName] || 0) + 1;
            push('Sign-ins through Entra (14 days)', rows.length ? (okN ? 'pass' : 'fail') : 'inconclusive', rows.length ? `${okN} successful, ${failN} failed (as client: ${s1.status === 200 ? (s1.body.value || []).length : '?'}, as resource: ${s2.status === 200 ? (s2.body.value || []).length : '?'})` : 'No sign-in through Entra recorded in 14 days — inconclusive, not a failure. Ask an assigned user to sign in from My Apps, then validate again.', { window: '14d', total: rows.length, ok: okN, recent24h: rows.filter((r) => String(r.createdDateTime || '') >= dayAgo).length, users: [...new Set(rows.map((r) => r.userPrincipalName))].slice(0, 10), appliedPolicies: ca, latest: rows.slice(0, 10).map((r) => ({ id: r.id || null, at: r.createdDateTime, user: r.userPrincipalName, error: r.status && r.status.errorCode, mfa: r.authenticationRequirement, ca: r.conditionalAccessStatus })) });
          }
        }
      }
      const live = await L.oktaGet(`/api/v1/apps/${it.source_id}`);
      if (live.status === 200) push('Okta app status (live)', live.body.status === 'ACTIVE' ? 'info' : 'pass', `Okta still shows ${live.body.status}${live.body.status === 'ACTIVE' ? ' — the app remains an Okta dependency until it is deactivated or its assignments are removed' : ''}`, { lastUpdated: live.body.lastUpdated });
      else push('Okta app status (live)', 'inconclusive', 'Could not read Okta: ' + (live.error || live.status));
    } else if (it.category === 'policies' && it.facts.mapping) {
      const [cas] = await pool.query(`SELECT ca_id, display_name, state, collected_at FROM oem_entra_ca`);
      const hint = String(it.facts.mapping.entra && it.facts.mapping.entra.name || '').split(',')[0].trim();
      const hit = cas.find((c) => hint && c.display_name && c.display_name.toLowerCase().includes(hint.toLowerCase().slice(0, 24)));
      if (!hit) push('Entra policy exists (snapshot)', 'inconclusive', 'No Conditional Access policy in the snapshot resembles "' + hint + '". Refresh the snapshot after creating it.');
      else {
        push('Entra policy exists (snapshot)', 'pass', `${hit.display_name} — state ${hit.state} (snapshot ${new Date(hit.collected_at).toISOString().slice(0, 16)}Z)`);
        push('Entra policy enforced', hit.state === 'enabled' ? 'pass' : 'fail', hit.state === 'enabled' ? 'enabled' : hit.state + ' — report-only and disabled policies do not count as enforced replacements');
        const since = opts.since7d || new Date(Date.now() - 7 * 86400000).toISOString();
        const s = await L.graphGet(`/v1.0/auditLogs/signIns?$top=200&$filter=createdDateTime ge ${since}`);
        if (s.status !== 200) push('Policy applied on real sign-ins (7 days)', 'inconclusive', 'Sign-in log not readable: ' + (s.error || s.status));
        else { const applied = (s.body.value || []).filter((r) => (r.appliedConditionalAccessPolicies || []).some((p) => p.id === hit.ca_id && p.result !== 'notApplied')).length; push('Policy applied on real sign-ins (7 days, first 200)', applied ? 'pass' : 'inconclusive', applied ? `${applied} sign-ins show it applied` : 'Not seen applied in the sample — inconclusive, not proof of failure.'); }
      }
    } else if (it.category === 'mfa') {
      // Live read: the mirror facts are from the last discovery and would validate stale state.
      const reg = await L.metaGet('mfa_registration', null);
      const f = it.facts.entra || {};
      const amp = await L.graphGet('/v1.0/policies/authenticationMethodsPolicy');
      const liveOk = amp.status === 200 && amp.body;
      const mig = liveOk ? (amp.body.policyMigrationState || 'unknown') : null;
      const liveState = (key) => { const c = liveOk ? (amp.body.authenticationMethodConfigurations || []).find((x) => x.id === key) : null; return c ? c.state : null; };
      const legacy = mig && mig !== 'migrationComplete' ? ` (policy migration ${mig}: the legacy per-user MFA/SSPR settings still govern registration)` : '';
      if (it.source_kind === 'entra_auth_methods_policy') {
        push('Authentication methods policy migration complete (live)', !liveOk ? 'inconclusive' : mig === 'migrationComplete' ? 'pass' : 'fail', liveOk ? `policyMigrationState = ${mig}` : 'Policy not readable: ' + (amp.error || amp.status));
        if (liveOk) { const en = (amp.body.authenticationMethodConfigurations || []).filter((x) => x.state === 'enabled').map((x) => x.id); push('Methods enabled (live)', en.length ? 'info' : 'fail', en.join(', ') || 'none'); }
      } else {
        const st = f.policyKey ? liveState(f.policyKey) : null;
        push('Method enabled in Entra (live)', !liveOk ? 'inconclusive' : st === 'enabled' ? 'pass' : st === 'disabled' ? 'fail' : 'inconclusive', liveOk ? `${f.policyKey || 'method'}: ${st || 'not in the policy'}${legacy}` : 'Policy not readable: ' + (amp.error || amp.status));
        push('Users registered', f.registered === null || f.registered === undefined ? 'inconclusive' : f.registered > 0 ? 'info' : 'fail', `${f.registered === null ? 'unknown' : f.registered} of ${reg.v ? reg.v.total : '?'} registered (${reg.v ? 'report as of ' + (reg.v.measured_at || reg.at) : 'no report'})`);
      }
    } else if (it.category === 'network_device' && it.facts.anchor) {
      push('Named location contains the address', it.facts.anchor.entraLocations && it.facts.anchor.entraLocations.length ? 'pass' : 'fail', (it.facts.anchor.entraLocations || []).join(', ') || 'in no Entra named location');
      push('Marked trusted', it.facts.anchor.entraTrusted === null ? 'inconclusive' : it.facts.anchor.entraTrusted ? 'pass' : 'info', it.facts.anchor.entraTrusted ? 'trusted' : 'not trusted (may be intended)');
    } else push('Automated validation', 'not_applicable', 'No automated check exists for this item; validate by hand and record the evidence.');
  }
  return checks;
}

// POST /api/oem/work/:key/validate — automated checks that can be read; never sets Verified by itself.
router.post('/work/:key/validate', json, admin(), async (req, res) => {
  try {
    const it = await loadItem(req.params.key);
    if (!it) return res.status(404).json({ error: 'no such work item' });
    const at = L.nowIso();
    const checks = await runValidationChecks(it);
    const summary = { at, checks, pass: checks.filter((c) => c.result === 'pass').length, fail: checks.filter((c) => c.result === 'fail').length, inconclusive: checks.filter((c) => c.result === 'inconclusive').length };
    const merged = Object.assign({}, it.evidence || {}, { automated: summary });
    const to = summary.fail ? it.state : (it.state === 'ready' || it.state === 'needs_review' ? 'awaiting_validation' : it.state);
    await pool.query(`UPDATE oem_work_item SET evidence=?, state=?, state_updated_at=NOW() WHERE item_key=?`, [JSON.stringify(merged), to, it.item_key]);
    await pool.query(`INSERT INTO oem_work_event (item_key, event, from_state, to_state, note, actor_email, evidence) VALUES (?,?,?,?,?,?,?)`, [it.item_key, 'validated', it.state, to, `${summary.pass} pass, ${summary.fail} fail, ${summary.inconclusive} inconclusive`, actorOf(req), JSON.stringify(summary)]);
    await audit(req, 'oem_work_validate', { item: it.item_key, pass: summary.pass, fail: summary.fail });
    res.json({ ok: true, key: it.item_key, state: to, stateLabel: STATE_LABEL[to], summary, note: summary.fail ? 'Failures keep the item where it is.' : 'Automated checks passed or were inconclusive; a person still records the tested evidence to mark it Verified.' });
  } catch (e) { fail(res, e, 'validate'); }
});

/* ---------------------------------------------------------- applications */

// GET /api/oem/apps/summary
router.get('/apps/summary', read(), async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT source_status, disposition, state, facts FROM oem_work_item WHERE category='applications' AND seen_in_last_discovery=1`);
    const out = { oktaApps: rows.length, active: 0, inactive: 0, byDecision: {}, byKind: {}, byState: {}, excluded: 0, provisioning: 0, sharedTargets: 0, uniqueTargets: 0 };
    const targets = new Map();
    for (const r of rows) {
      const f = j(r.facts, {});
      if (r.source_status === 'ACTIVE') out.active++; else out.inactive++;
      if (r.disposition === 'exclude') out.excluded++;
      const d = (f.match && f.match.decision) || 'none'; out.byDecision[d] = (out.byDecision[d] || 0) + 1;
      const k = (f.okta && f.okta.signOnMode) || 'unknown'; out.byKind[k] = (out.byKind[k] || 0) + 1;
      out.byState[r.state] = (out.byState[r.state] || 0) + 1;
      if (f.okta && f.okta.provisioning) out.provisioning++;
      if (f.match && f.match.entraId && /^(manual_confirmed|manual_staged|auto_)/.test(d)) targets.set(f.match.entraId, (targets.get(f.match.entraId) || 0) + 1);
    }
    out.uniqueTargets = targets.size; out.sharedTargets = [...targets.values()].filter((n) => n > 1).length;
    const [[dep]] = await pool.query(`SELECT COUNT(*) n FROM oem_work_item WHERE category='dependencies' AND source_kind='okta_app' AND seen_in_last_discovery=1`);
    out.platformApps = dep.n;
    out.note = 'Counts are unique Okta applications. Platform apps (Okta dashboard, agents, federation) are listed under Remaining Okta Dependencies, not here.';
    res.json(out);
  } catch (e) { fail(res, e, 'apps summary'); }
});

// GET /api/oem/entra/catalog?scope=sso|all&q=&limit=
router.get('/entra/catalog', read(), async (req, res) => {
  try {
    const scope = req.query.scope === 'all' ? 'all' : 'sso';
    const q = String(req.query.q || '').trim();
    const limit = Math.min(parseInt(req.query.limit || '300', 10) || 300, 2000);
    const [matched] = await pool.query(`SELECT entra_app_id, okta_app_label, match_confidence FROM app_matches WHERE entra_app_id IS NOT NULL AND match_confidence IN ('manual_confirmed','manual_staged','auto_high','auto_medium','auto_low')`);
    const matchBy = new Map(); for (const m of matched) { if (!matchBy.has(m.entra_app_id)) matchBy.set(m.entra_app_id, []); matchBy.get(m.entra_app_id).push({ okta: m.okta_app_label, decision: m.match_confidence }); }
    const where = [`service_principal_type <> 'ManagedIdentity'`], params = [];
    if (scope === 'sso') { where.push(`(display_name LIKE 'SSO-%' OR entra_id IN (?))`); params.push(matched.length ? matched.map((m) => m.entra_app_id) : ['-']); }
    if (q) { where.push(`(display_name LIKE ? OR app_id LIKE ? OR entra_id LIKE ? OR homepage_url LIKE ?)`); const like = '%' + q + '%'; params.push(like, like, like, like); }
    const [rows] = await pool.query(`SELECT entra_id, app_id, display_name, preferred_single_sign_on_mode, account_enabled, app_role_assignment_required, assigned_user_count, assigned_group_count, homepage_url, publisher_name, service_principal_type, last_synced_at, JSON_EXTRACT(raw_json,'$.replyUrls') reply_urls FROM entra_apps WHERE ${where.join(' AND ')} ORDER BY (display_name LIKE 'SSO-%') DESC, display_name LIMIT ?`, params.concat([limit]));
    const [extras] = await pool.query(`SELECT sp_id, sync_status, cert_expires, collected_at FROM oem_entra_sp`);
    const exBy = new Map(extras.map((x) => [x.sp_id, x]));
    const [[tot]] = await pool.query(`SELECT COUNT(*) total, SUM(display_name LIKE 'SSO-%') sso FROM entra_apps WHERE service_principal_type <> 'ManagedIdentity'`);
    const items = rows.map((r) => { const ex = exBy.get(r.entra_id); const ms = matchBy.get(r.entra_id) || []; const isSso = /^SSO-/.test(r.display_name || ''); return { entraId: r.entra_id, appId: r.app_id, name: r.display_name, ssoMode: r.preferred_single_sign_on_mode, enabled: !!r.account_enabled, assignmentRequired: !!r.app_role_assignment_required, users: r.assigned_user_count, groups: r.assigned_group_count, homepage: r.homepage_url, publisher: r.publisher_name, type: r.service_principal_type, replyUrls: j(r.reply_urls, null), mirroredAt: r.last_synced_at, isSsoPrefixed: isSso, matchedOkta: ms, whyShown: isSso ? 'SSO- prefix (naming convention; not proof the app works)' : ms.length ? 'matched or confirmed for an Okta app' : 'full catalog (Advanced)', provisioning: ex ? ex.sync_status : 'unknown', certExpires: ex ? ex.cert_expires : null }; });
    res.json({ scope, total: items.length, catalogTotal: tot.total, ssoPrefixed: tot.sso, matchedNonSso: items.filter((i) => !i.isSsoPrefixed && i.matchedOkta.length).length, note: scope === 'sso' ? 'Default view: SSO- prefixed apps plus any app matched to an Okta app. The full catalog (' + tot.total + ' principals, mostly Microsoft first-party and OAuth consents) is under Advanced.' : 'Full catalog. Most of these are not migration targets.', items });
  } catch (e) { fail(res, e, 'entra catalog'); }
});

/* An Entra object id as a person actually has it: the bare GUID, or pasted out of the portal address bar
   (".../ManagedAppMenuBlade/~/Overview/objectId/<object>/appId/<app>"), where objectId is the one that names the
   enterprise application. Anything else with a GUID in it falls back to the first GUID in the string. */
const GUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const OBJECT_ID_RE = /objectid\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
function guidOf(sIn) {
  const t = String(sIn || '');
  const m = t.match(OBJECT_ID_RE);
  if (m) return m[1].toLowerCase();
  const g = t.match(GUID_RE);
  return g ? g[0].toLowerCase() : null;
}
const entraPortal = (objectId, appId) => (objectId && appId ? `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/${objectId}/appId/${appId}` : null);

// GET /api/oem/matches/compare?oktaAppId=&entraId=
/* The matcher pairs applications by identifier, then host, then name. When an Entra application is named
   differently from its Okta application and carries no reply URL the mirror can read, that scoring finds nothing
   and the application reads as unmatched even though a person can see it in the portal. This route scores ONE
   named Entra object against ONE Okta application with runMatcher's own scorePair, so the comparison a technician
   reads here is the comparison the matcher made — not a second opinion that could disagree with it.
   Read-only: it records nothing. POST /matches/decide is still the only thing that writes a match. */
router.get('/matches/compare', read(), async (req, res) => {
  try {
    const oktaAppId = String(req.query.oktaAppId || '').trim();
    const typed = String(req.query.entraId || '').trim();
    const id = guidOf(typed);
    if (!oktaAppId) return res.status(400).json({ error: 'oktaAppId required' });
    if (!id) return res.status(400).json({ error: 'That is not an Entra object id. Paste the Object ID from the enterprise application in Entra (a GUID), or the portal address that contains it.' });
    const [[okta]] = await pool.query(`SELECT okta_id, name, label, status, sign_on_mode, raw_json FROM okta_apps WHERE okta_id=?`, [oktaAppId]);
    if (!okta) return res.status(404).json({ error: 'unknown Okta app' });

    const [[row]] = await pool.query(`SELECT entra_id, app_id, display_name, preferred_single_sign_on_mode, homepage_url, account_enabled, app_role_assignment_required, assigned_user_count, assigned_group_count, publisher_name, service_principal_type, last_synced_at, raw_json FROM entra_apps WHERE entra_id=? OR app_id=?`, [id, id]);
    let eRow = row || null, live = null, liveErr = null;
    /* Not in the mirror is not the same as not in Entra. One read-only Graph call separates "this application does
       not exist" from "this platform has not mirrored it yet", because those need opposite things from a person. */
    if (!eRow) {
      const sel = '$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,preferredSingleSignOnMode,replyUrls,servicePrincipalNames,loginUrl,homepage,publisherName,servicePrincipalType';
      let g = await L.graphGet(`/v1.0/servicePrincipals/${encodeURIComponent(id)}?${sel}`);
      if (g.status === 404) g = await L.graphGet(`/v1.0/servicePrincipals(appId='${encodeURIComponent(id)}')?${sel}`);
      if (g.status === 200 && g.body) live = g.body; else liveErr = g.error || ('HTTP ' + g.status);
    }
    if (!eRow && !live) {
      return res.json({ ok: true, entraId: id, typed, found: false, mirrored: false, liveError: liveErr,
        note: liveErr ? 'No Entra application with that object id is in this platform’s mirror, and the live read did not find one either: ' + liveErr : 'No Entra application with that object id is in this platform’s mirror.' });
    }

    const eRaw = eRow ? (j(eRow.raw_json, {}) || {}) : live;
    const shim = eRow || { entra_id: live.id, app_id: live.appId, display_name: live.displayName, homepage_url: live.homepage || null };
    const eIds = D.entraIdentifiers(eRaw, shim);
    const entraId = String(shim.entra_id).toLowerCase(), appId = String(shim.app_id || '').toLowerCase();
    const pastedAs = id === entraId ? 'objectId' : id === appId ? 'appId' : 'objectId';

    const oRaw = j(okta.raw_json, {}) || {};
    const oIds = D.oktaIdentifiers(oRaw);
    const oSide = { ids: oIds, tok: D.tokens((okta.label || '') + ' ' + (okta.name || '')), env: D.envOf((okta.label || '') + ' ' + oIds.acs.join(' ') + ' ' + oIds.audience.join(' ') + ' ' + (oIds.bookmarkUrl || '')) };
    const eTok = D.tokens(shim.display_name);
    const eSide = { ids: eIds, tok: eTok, tokSet: new Set(eTok), env: D.envOf(shim.display_name + ' ' + eIds.replyHosts.join(' ') + ' ' + eIds.identifierUris.join(' ')) };
    const pair = D.scorePair(oSide, eSide);

    const [mine] = await pool.query(`SELECT entra_app_id, entra_app_display_name, match_confidence, created_by, created_at FROM app_matches WHERE okta_app_id=?`, [oktaAppId]);
    const [theirs] = await pool.query(`SELECT okta_app_id, okta_app_label, match_confidence FROM app_matches WHERE entra_app_id=? AND okta_app_id<>? AND match_confidence IN ('manual_confirmed','manual_staged','auto_high','auto_medium','auto_low')`, [entraId, oktaAppId]);
    const current = mine.find((m) => /^manual_(confirmed|staged)$/.test(m.match_confidence)) || null;
    const rejectedHere = mine.some((m) => m.match_confidence === 'manual_rejected' && m.entra_app_id === entraId);
    const [[cand]] = await pool.query(`SELECT score, method FROM oem_match_candidate WHERE okta_app_id=? AND entra_app_id=?`, [oktaAppId, entraId]);

    res.json({
      ok: true, entraId, typed, pastedAs, found: true, mirrored: !!eRow, source: eRow ? 'mirror' : 'live',
      /* Only a mirrored application can be recorded: POST /matches/decide reads entra_apps, and a decision pointing
         at a row this platform does not hold would show as a match with nothing behind it. */
      matchable: !!eRow,
      okta: { id: okta.okta_id, label: okta.label, name: okta.name, status: okta.status, signOnMode: okta.sign_on_mode, identifiers: oIds },
      entra: {
        entraId, appId, name: shim.display_name,
        ssoMode: eRow ? eRow.preferred_single_sign_on_mode : (live.preferredSingleSignOnMode || null),
        enabled: eRow ? !!eRow.account_enabled : !!live.accountEnabled,
        assignmentRequired: eRow ? !!eRow.app_role_assignment_required : !!live.appRoleAssignmentRequired,
        users: eRow ? eRow.assigned_user_count : null, groups: eRow ? eRow.assigned_group_count : null,
        publisher: eRow ? eRow.publisher_name : (live.publisherName || null),
        type: eRow ? eRow.service_principal_type : (live.servicePrincipalType || null),
        mirroredAt: eRow ? eRow.last_synced_at : null,
        isSsoPrefixed: /^SSO-/.test(shim.display_name || ''),
        identifiers: eIds, portal: entraPortal(entraId, appId),
      },
      pair: pair ? { score: pair.score, evidence: pair.evidence, envConflict: pair.envConflict, envUnclear: pair.envUnclear, envOkta: pair.envOkta, envEntra: pair.envEntra } : null,
      confidence: pair ? D.confidenceFor(pair.score) : 'none',
      /* What the last matcher run actually stored for this pair, so "the matcher never saw this" and "the matcher
         scored it and ranked it below the top five" do not read the same. */
      candidate: cand ? { score: Number(cand.score), method: cand.method } : null,
      current: current ? { entraId: current.entra_app_id, name: current.entra_app_display_name, decision: current.match_confidence, by: current.created_by, at: current.created_at } : null,
      rejectedHere,
      matchedOkta: theirs.map((t) => ({ oktaId: t.okta_app_id, label: t.okta_app_label, decision: t.match_confidence })),
    });
  } catch (e) { fail(res, e, 'match compare'); }
});

/* ======================================================================================================================
   Staged — an Entra application only named individuals can reach.
   Not a record and not a guess: Entra's own configuration says it. The enterprise application REQUIRES assignment,
   NO group is assigned, and at least one user is. Groups are how a population gets access, so individuals-only means
   the rollout has not happened yet, whatever else is true of the app.
   Because assignment is required and no group grants it, anybody in the sign-in log had to be assigned at that moment:
   a successful sign-in is proof the staged configuration works, not a second opinion about it. An application with no
   successful sign-in is "not tested yet" — never "not working", because nobody may have tried. And if the sign-in
   mirror itself has nothing in the window, every count here is unknown rather than zero.
   Read-only: this route records nothing, and nothing on the page writes from it.
   ====================================================================================================================== */
const STAGED_RULE = 'Assignment is required, no group is assigned, and at least one user is. Only the named people below can reach the application, so it is not rolled out yet.';
const STAGED_DAYS = 30;

router.get('/staged', read(), async (req, res) => {
  try {
    const days = STAGED_DAYS;
    const [apps] = await pool.query(
      `SELECT entra_id, app_id, display_name, assigned_user_count, assigned_group_count, account_enabled,
              preferred_single_sign_on_mode, last_synced_at
         FROM entra_apps
        WHERE seen_in_last_sync=1 AND app_role_assignment_required=1
          AND assigned_group_count=0 AND assigned_user_count>0
        ORDER BY display_name`);

    /* Is the sign-in mirror answerable at all? An empty mirror must read as "not measured" everywhere below —
       a zero that means "we did not look" is the one number this page is never allowed to print. */
    const [[span]] = await pool.query(
      `SELECT COUNT(*) total, MAX(created_at) newest FROM entra_signin_logs WHERE created_at > NOW() - INTERVAL ? DAY`, [days]);
    const measured = Number(span && span.total || 0) > 0;

    const appIds = apps.map((a) => a.app_id).filter(Boolean);
    const byApp = new Map();
    if (measured && appIds.length) {
      const [sRows] = await pool.query(
        `SELECT LOWER(app_id) app_id, LOWER(user_principal_name) upn, COUNT(*) events, MAX(created_at) last
           FROM entra_signin_logs
          WHERE outcome='SUCCESS' AND created_at > NOW() - INTERVAL ? DAY
            AND app_id IN (?) AND user_principal_name IS NOT NULL
          GROUP BY 1, 2`, [days, appIds]);
      for (const r of sRows) {
        const k = String(r.app_id).toLowerCase();
        let e = byApp.get(k);
        if (!e) { e = { people: [], events: 0, last: null }; byApp.set(k, e); }
        e.people.push({ upn: r.upn, events: Number(r.events || 0), last: r.last });
        e.events += Number(r.events || 0);
        if (!e.last || new Date(r.last) > new Date(e.last)) e.last = r.last;
      }
      for (const e of byApp.values()) e.people.sort((a, b) => b.events - a.events || String(a.upn).localeCompare(String(b.upn)));
    }

    /* The Okta side. facts.entra.id is the Entra application this platform already treats as this Okta app's
       destination, so linking on it shows the same pairing the rest of the page shows — never a second opinion. */
    const [items] = await pool.query(
      `SELECT item_key, title, state, source_id, source_status, facts FROM oem_work_item WHERE category='applications'`);
    const linked = new Map();
    for (const it of items) {
      const f = (typeof it.facts === 'string' ? j(it.facts, {}) : it.facts) || {};
      const e = f.entra || null; if (!e) continue;
      for (const key of [e.id, e.appId]) {
        if (!key) continue;
        const k = String(key).toLowerCase();
        if (!linked.has(k)) linked.set(k, []);
        linked.get(k).push({ key: it.item_key, title: it.title, state: it.state, oktaId: it.source_id,
          oktaStatus: it.source_status, link: 'destination' });
      }
    }
    /* Anything with no destination yet still deserves the matcher's own suggestion, clearly labelled as one. */
    const allIds = [];
    for (const a of apps) { if (a.entra_id) allIds.push(a.entra_id); if (a.app_id) allIds.push(a.app_id); }
    const suggested = new Map();
    if (allIds.length) {
      const [cands] = await pool.query(
        `SELECT okta_app_id, entra_app_id, score, method FROM oem_match_candidate WHERE entra_app_id IN (?)`, [allIds]);
      const titleOf = new Map(items.map((it) => [String(it.source_id), it]));
      for (const c of cands) {
        const k = String(c.entra_app_id).toLowerCase();
        if (!suggested.has(k)) suggested.set(k, []);
        const it = titleOf.get(String(c.okta_app_id));
        suggested.get(k).push({ key: it ? it.item_key : null, title: it ? it.title : c.okta_app_id, state: it ? it.state : null,
          oktaId: c.okta_app_id, oktaStatus: it ? it.source_status : null, link: 'suggested',
          score: c.score === null || c.score === undefined ? null : Number(c.score), method: c.method || null });
      }
      for (const v of suggested.values()) v.sort((a, b) => (b.score || 0) - (a.score || 0));
    }

    const out = apps.map((a) => {
      const k = String(a.app_id || '').toLowerCase();
      const s = byApp.get(k) || null;
      const people = s ? s.people : [];
      const okta = (linked.get(String(a.entra_id).toLowerCase()) || linked.get(k) || []).slice();
      if (!okta.length) for (const c of (suggested.get(String(a.entra_id).toLowerCase()) || suggested.get(k) || [])) okta.push(c);
      /* Tested is a three-value answer. Unknown when the mirror could not be read; it never collapses to "no". */
      const tested = !measured ? null : people.length > 0;
      return {
        objectId: a.entra_id, appId: a.app_id, name: a.display_name,
        ssoMode: a.preferred_single_sign_on_mode || null, enabled: !!a.account_enabled,
        assigned: { users: a.assigned_user_count, groups: a.assigned_group_count, required: true },
        mirroredAt: a.last_synced_at,
        signIns: { measured: measured, users: measured ? people.length : null, events: measured ? (s ? s.events : 0) : null,
          last: s ? s.last : null, people: people.slice(0, 12), truncated: Math.max(0, people.length - 12),
          note: measured ? null : 'The Entra sign-in mirror has nothing in this window, so sign-ins could not be measured.' },
        tested: tested,
        okta: okta,
        portal: entraPortal(a.entra_id, a.app_id)
      };
    });

    res.json({
      window: days, rule: STAGED_RULE, measured: measured,
      signInMirror: { newest: span ? span.newest : null, eventsInWindow: Number(span && span.total || 0) },
      counts: { total: out.length,
        tested: out.filter((x) => x.tested === true).length,
        untested: out.filter((x) => x.tested === false).length,
        unknown: out.filter((x) => x.tested === null).length,
        retiredOkta: out.filter((x) => x.okta.some((o) => o.state === 'retired')).length },
      items: out
    });
  } catch (e) { fail(res, e, 'staged'); }
});

// POST /api/oem/matches/decide {oktaAppId, entraAppId, decision: confirm|reject|stage|clear, note}
router.post('/matches/decide', json, admin(), async (req, res) => {
  try {
    const { oktaAppId, entraAppId, decision, note } = req.body || {};
    if (!oktaAppId || !['confirm', 'reject', 'stage', 'clear'].includes(decision)) return res.status(400).json({ error: 'oktaAppId and decision (confirm|reject|stage|clear) required' });
    const [[okta]] = await pool.query(`SELECT okta_id, label FROM okta_apps WHERE okta_id=?`, [oktaAppId]);
    if (!okta) return res.status(404).json({ error: 'unknown Okta app' });
    let entra = null;
    if (decision !== 'clear') {
      if (!entraAppId) return res.status(400).json({ error: 'entraAppId required' });
      [[entra]] = await pool.query(`SELECT entra_id, display_name FROM entra_apps WHERE entra_id=?`, [entraAppId]);
      if (!entra) return res.status(404).json({ error: 'unknown Entra app (not in the mirror)' });
    }
    const actor = actorOf(req);
    const [rows] = await pool.query(`SELECT id, entra_app_id, match_confidence FROM app_matches WHERE okta_app_id=?`, [oktaAppId]);
    const prior = rows.filter((r) => /^manual_(confirmed|staged)$/.test(r.match_confidence));
    let result;
    if (decision === 'confirm' || decision === 'stage') {
      const conf = decision === 'confirm' ? 'manual_confirmed' : 'manual_staged';
      // Superseded: auto rows and any earlier staged/confirmed row for a different target (kept in the event log).
      const drop = rows.filter((r) => !/^manual_rejected$/.test(r.match_confidence) && !(r.match_confidence === conf && r.entra_app_id === entraAppId));
      if (drop.length) await pool.query(`DELETE FROM app_matches WHERE id IN (?)`, [drop.map((r) => r.id)]);
      const same = rows.find((r) => r.match_confidence === conf && r.entra_app_id === entraAppId);
      if (same) { await pool.query(`UPDATE app_matches SET notes=?, created_by=?, last_verified_at=NOW() WHERE id=?`, [note || null, actor, same.id]); result = { id: same.id }; }
      else { const [ins] = await pool.query(`INSERT INTO app_matches (okta_app_id, okta_app_label, entra_app_id, entra_app_display_name, match_confidence, match_method, notes, created_by, last_verified_at) VALUES (?,?,?,?,?,'manual',?,?,NOW())`, [oktaAppId, okta.label, entraAppId, entra.display_name, conf, note || null, actor]); result = { id: ins.insertId }; }
      // A rejected row for the same pair is contradicted by this confirmation; remove it and say so.
      const rej = rows.find((r) => r.match_confidence === 'manual_rejected' && r.entra_app_id === entraAppId);
      if (rej) await pool.query(`DELETE FROM app_matches WHERE id=?`, [rej.id]);
      result.replaced = prior.filter((p) => p.entra_app_id !== entraAppId).map((p) => p.entra_app_id);
    } else if (decision === 'reject') {
      const autoSame = rows.find((r) => r.entra_app_id === entraAppId && !/^manual_/.test(r.match_confidence));
      if (autoSame) await pool.query(`UPDATE app_matches SET match_confidence='manual_rejected', notes=?, created_by=?, last_verified_at=NOW() WHERE id=?`, [note || null, actor, autoSame.id]);
      else if (!rows.some((r) => r.entra_app_id === entraAppId && r.match_confidence === 'manual_rejected')) await pool.query(`INSERT INTO app_matches (okta_app_id, okta_app_label, entra_app_id, entra_app_display_name, match_confidence, match_method, notes, created_by, last_verified_at) VALUES (?,?,?,?,'manual_rejected','manual',?,?,NOW())`, [oktaAppId, okta.label, entraAppId, entra.display_name, note || null, actor]);
      const conf = rows.find((r) => r.entra_app_id === entraAppId && /^manual_(confirmed|staged)$/.test(r.match_confidence));
      if (conf) await pool.query(`DELETE FROM app_matches WHERE id=?`, [conf.id]);
      result = { rejected: entraAppId };
    } else {
      if (prior.length) await pool.query(`DELETE FROM app_matches WHERE id IN (?)`, [prior.map((r) => r.id)]);
      result = { cleared: prior.map((p) => p.entra_app_id) };
    }
    await pool.query(`INSERT INTO oem_work_event (item_key, event, note, actor_email, evidence) VALUES (?,?,?,?,?)`, ['app:' + oktaAppId, 'match_' + decision, note || null, actor, JSON.stringify({ entraAppId: entraAppId || null, entraName: entra ? entra.display_name : null, replaced: result.replaced || result.cleared || null })]);
    await audit(req, 'oem_match_' + decision, { oktaAppId, entraAppId: entraAppId || null });
    await D.buildWorkItems(() => {});
    const it = await loadItem('app:' + oktaAppId);
    res.json({ ok: true, decision, result, item: it ? lean(it) : null });
  } catch (e) { fail(res, e, 'match decide'); }
});

/* -------------------------------------------------------------------- jobs */

const HUB = __dirname;
const RAW_JOB_DEFS = {
  'discover': { label: 'Discover / Refresh everything', run: (log) => D.discoverAll(log), vendor: 'Okta + Entra (read only)' },
  'discover-okta': { label: 'Discover Okta scope', run: async (log) => ({ okta: await D.discoverOktaScope(log), work: await D.buildWorkItems(log) }), vendor: 'Okta (read only)' },
  'match': { label: 'Match applications', run: async (log) => ({ matcher: await D.runMatcher(log), work: await D.buildWorkItems(log) }), vendor: 'none (mirror only)' },
  'entra-extras': { label: 'Read Entra provisioning + certificates', run: async (log) => ({ extras: await D.refreshEntraSpExtras(log), work: await D.buildWorkItems(log) }), vendor: 'Entra (read only)' },
  'entra-apps': { label: 'Refresh Entra apps mirror', run: async (log) => { const es = require('./entra-sync'); log('entra-sync apps (paged, $select with reply URLs)'); const r = await es.runSyncJob('apps'); log('done: ' + JSON.stringify(r)); return r; }, vendor: 'Entra (read only)' },
  'okta-apps': { label: 'Refresh Okta apps mirror (paced: 50 calls/min)', run: async (log) => { const r = await L.runScript(log, path.join(HUB, 'okta-apps-sync-job.js'), [], { timeoutMs: 900000 }); if (!r.ok) throw new Error('okta-apps-sync-job exited ' + r.code + ' ' + (r.stderrTail || '')); return r; }, vendor: 'Okta (read only)' },
  'policy-snapshot': { label: 'Refresh the policy snapshot (Okta policies, zones, Entra CA, named locations)', run: async (log) => { const r = await L.runScript(log, path.join(HUB, 'collect-okta-entra.js'), [], { timeoutMs: 300000 }); if (!r.ok) throw new Error('collector exited ' + r.code + ' ' + (r.stderrTail || '')); const work = await D.buildWorkItems(log); return { collector: r, work }; }, vendor: 'Okta + Entra (read only)' },
  'mfa-evidence': { label: 'Measure MFA evidence from Entra sign-ins', run: (log) => D.measureMfaEvidence(log), vendor: 'Entra (read only)' },
  'zsnet-refresh': { label: 'Refresh the Zscaler mirror', run: async (log) => { const r = await L.runScript(log, path.join(HUB, 'zsnet-sync.js'), [], { timeoutMs: 300000 }); if (!r.ok) throw new Error('zsnet-sync exited ' + r.code + ' ' + (r.stderrTail || '')); return r; }, vendor: 'Zscaler (read only)' },
  'rebuild-work': { label: 'Rebuild the work queue from the mirrors', run: (log) => D.buildWorkItems(log), vendor: 'none' },
  /* drop 8e (oem-staged.js): the Entra gallery mirror (which products have an OpenID Connect template) and the Entra-export
     sign-in check (a staged application becomes complete on its first successful interactive Entra sign-in). Both read only. */
  'entra-gallery': { label: 'Read the Entra gallery (SSO templates)', run: (log) => require('./oem-staged').refreshGallery(log), vendor: 'Entra (read only)' },
  'staged-signins': { label: 'Check Entra sign-ins for the exported applications (Staged → Complete)', run: (log, ctx) => require('./oem-staged').checkStagedSignIns(log, ctx), vendor: 'Entra (read only)' },
};
/* Each job run is one source generation: a running row when it starts, success (with the record count when the result
   says one) or failed (with the error) when it ends. The entra-apps run also diffs the mirror before and after the sync
   (entra-sync deletes principals Entra no longer returns) and records the ones that vanished as tombstones. `runRaw` is
   the unwrapped function for a caller that manages its own generation row (oem-v2-routes). */
function withGeneration(key, def) {
  const sourceKey = SOURCE_KEY_OF_JOB[key] || key;
  const runRaw = def.run;
  const run = async (log, ctx) => {
    const genId = await genBegin(sourceKey, null, ctx && ctx.id, ctx && ctx.actor);
    const before = key === 'entra-apps' ? await mirrorSnapshot() : null;
    try {
      const r = await runRaw(log, ctx);
      if (before) {
        try {
          const gone = await captureTombstones(before.ids, await mirrorIds(), before.byId);
          if (gone.length) {
            log(`${gone.length} Entra application(s) present before this sync are gone: recorded as tombstones, their matches invalidated`, 'warn', gone.map((g) => ({ entraId: g.entraId, name: g.name })));
            /* tombstone-4: the work items still say manual_staged/manual_confirmed with the old target until they are rebuilt;
               rebuild them now so facts.match.decision = 'invalidated' and nextAction = resolve_destination land in this
               same generation, not at the next discover run. */
            try { await D.buildWorkItems(log); log('work items rebuilt: the invalidated matches now read Resolve destination'); }
            catch (e) { log('work item rebuild after tombstones failed: ' + (L.redactText || String)(e && e.message || e).slice(0, 200) + ' — run "Rebuild the work queue" to refresh their facts', 'error'); }
          }
        } catch (e) { log('tombstone capture failed: ' + (L.redactText || String)(e && e.message || e).slice(0, 200), 'warn'); }
      }
      await genCommit(genId, recordsOf(r));
      return r;
    } catch (e) { await genFail(genId, e); throw e; }
  };
  return Object.assign({}, def, { run, runRaw, sourceKey });
}
const JOB_DEFS = {};
for (const [k, d] of Object.entries(RAW_JOB_DEFS)) JOB_DEFS[k] = withGeneration(k, d);

// GET /api/oem/jobs/defs
router.get('/jobs/defs', read(), (req, res) => res.json(Object.entries(JOB_DEFS).map(([key, d]) => ({ key, label: d.label, vendor: d.vendor }))));

// POST /api/oem/jobs/:key
router.post('/jobs/:key', json, admin(), async (req, res) => {
  const def = JOB_DEFS[req.params.key];
  if (!def) return res.status(404).json({ error: 'unknown job', known: Object.keys(JOB_DEFS) });
  try {
    const r = await L.startJob(req.params.key, actorOf(req), def.run);
    if (r.conflict) return res.status(409).json({ error: 'already running', conflict: r.conflict, note: 'Duplicate runs are refused; follow the running job instead.' });
    await audit(req, 'oem_job_start', { job: req.params.key, id: r.id });
    res.status(202).json({ ok: true, id: r.id, key: req.params.key, label: def.label });
  } catch (e) { fail(res, e, 'job start'); }
});

// GET /api/oem/jobs?key=&limit=&active=1
router.get('/jobs', read(), async (req, res) => {
  try { res.json(await L.listJobs({ limit: parseInt(req.query.limit || '40', 10) || 40, jobKey: req.query.key || null, active: req.query.active === '1' })); }
  catch (e) { fail(res, e, 'jobs'); }
});

// GET /api/oem/jobs/:id
router.get('/jobs/:id(\\d+)', read(), async (req, res) => {
  try { const jb = await L.getJob(parseInt(req.params.id, 10)); if (!jb) return res.status(404).json({ error: 'no such job' }); res.json(jb); }
  catch (e) { fail(res, e, 'job'); }
});

// POST /api/oem/jobs/:id/cancel
router.post('/jobs/:id(\\d+)/cancel', json, admin(), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const jb = await L.getJob(id);
    if (!jb) return res.status(404).json({ error: 'no such job' });
    if (jb.status !== 'running') return res.status(409).json({ error: 'job is not running', status: jb.status });
    const inProcess = L.requestCancel(id);
    await audit(req, 'oem_job_cancel', { id });
    res.json({ ok: true, id, inProcess, note: inProcess ? 'Stop requested. The job stops at its next step; everything already written to the mirror stays, nothing after the last logged step is applied, and vendor state is untouched.' : 'This job is running in another API process; it will be marked failed if it does not finish within 2 hours. Nothing in Okta or Entra changes either way.' });
  } catch (e) { fail(res, e, 'job cancel'); }
});

/* -------------------------------------------------------------- retirement */

router.get('/retirement', read(), async (req, res) => { try { res.json(await D.assessRetirement()); } catch (e) { fail(res, e, 'retirement'); } });

/* ---------------------------------------------------------------- evidence */

router.get('/evidence/mfa', read(), async (req, res) => {
  try {
    const me = await L.metaGet('mfa_evidence', null);
    const old = await L.metaGet('mfa_claim', null);
    res.json({ measurement: me.v, measuredAt: me.at, priorSample: old.v ? Object.assign({}, old.v, { label: 'Earlier collector sample (kept as history). It counted sign-ins whose authenticationRequirement was not multiFactor; that field is not an MFA claim, so it must not be read as "MFA disabled".' }) : null });
  } catch (e) { fail(res, e, 'evidence mfa'); }
});

/* ---------------------------------------------------------------- activity */

/* Timeline grouping (bug 9). Prefers model.groupActivity; this fallback applies the same rules so the route reads the
   same with or without the v2 model: identical (kind, text, actor) within 2 minutes collapse into one row with a
   count; poll rows fold into their parent job row (count) and never stand alone; an rbac audit row that duplicates a
   work event (same actor within 60 s) is dropped; newest first. */
function groupActivityFallback(rows) {
  const ms = (d) => { const t = new Date(d).getTime(); return Number.isFinite(t) ? t : 0; };
  const sorted = (rows || []).slice().sort((a, b) => ms(b.at) - ms(a.at));
  const jobsByKey = new Map();
  for (const r of sorted) if (r.kind === 'job' && r.jobKey) { if (!jobsByKey.has(r.jobKey)) jobsByKey.set(r.jobKey, []); jobsByKey.get(r.jobKey).push(r); }
  const workByActor = new Map();
  for (const r of sorted) if (r.kind === 'work') { const k = String(r.actor || '').toLowerCase(); if (!workByActor.has(k)) workByActor.set(k, []); workByActor.get(k).push(ms(r.at)); }
  const out = [];
  for (const r of sorted) {
    if (r.kind === 'poll') {
      const parents = jobsByKey.get(r.parentKey) || [];
      const parent = (r.parentJobId !== undefined ? sorted.find((p) => p.kind === 'job' && p.ref && p.ref.jobId === r.parentJobId) : null)
        || parents.find((p) => ms(p.at) <= ms(r.at) + 5000) || parents[0];
      if (parent) parent.count = (parent.count || 1) + 1;
      continue;
    }
    if (r.kind === 'audit' && /^oem_/.test(String(r.action || ''))) {
      const near = workByActor.get(String(r.actor || '').toLowerCase()) || [];
      if (near.some((t) => Math.abs(t - ms(r.at)) <= 60000)) continue;
    }
    const prev = out.find((o) => o.kind === r.kind && o.text === r.text && String(o.actor || '') === String(r.actor || '') && Math.abs(ms(o.at) - ms(r.at)) <= 120000);
    if (prev) { prev.count = (prev.count || 1) + 1; continue; }
    out.push(r);
  }
  return out;
}
function groupActivity(rows) {
  const M = lazy('./oem-v2-model');
  if (M && typeof M.groupActivity === 'function') { try { const g = M.groupActivity(rows); if (Array.isArray(g)) return g; } catch (e) { console.error('[oem-work] model.groupActivity:', e && e.message || e); } }
  return groupActivityFallback(rows);
}
const POLL_JOB_RE = /(^|[:_-])poll(ing)?([:_-]|$)/i;

// GET /api/oem/activity?limit=
router.get('/activity', read(), async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '150', 10) || 150, 500);
    const [jobs] = await pool.query(`SELECT id, job_key, status, actor_email, started_at, finished_at, error, created_at FROM oem_job ORDER BY id DESC LIMIT ?`, [limit]);
    const [events] = await pool.query(`SELECT e.id, e.item_key, e.event, e.from_state, e.to_state, e.note, e.actor_email, e.created_at, w.title FROM oem_work_event e LEFT JOIN oem_work_item w ON w.item_key=e.item_key WHERE e.actor_email<>'discovery' ORDER BY e.id DESC LIMIT ?`, [limit]);
    const [decisions] = await pool.query(`SELECT id, okta_app_id, okta_app_label, entra_app_display_name, match_confidence, notes, created_by, created_at FROM app_matches WHERE match_confidence LIKE 'manual_%' ORDER BY created_at DESC LIMIT ?`, [limit]);
    const [actions] = await pool.query(`SELECT id, mapping_key, action, actor_email, outcome, created_at FROM oem_action_log ORDER BY id DESC LIMIT ?`, [limit]);
    const [steps] = await pool.query(`SELECT step_key, state, note, actor_email, updated_at FROM oem_step_status ORDER BY updated_at DESC`);
    const [auditRows] = await pool.query(`SELECT id, actor_email, action, target_page_key, details, created_at FROM rbac_audit_log WHERE target_page_key IN ('okta-entra-migration','app-migration') ORDER BY id DESC LIMIT ?`, [limit]);
    const tl = [];
    /* A poll job (v2 migration polling, live status checks) is a step of the job it watches, not an event: it folds
       into its parent job row (parentJobId) and never stands alone. A poll whose parent is outside the window is
       dropped rather than shown as its own row. */
    const jobRows = [], polls = [];
    for (const x of jobs) {
      const key = String(x.job_key || '');
      if (POLL_JOB_RE.test(key)) { polls.push({ x, key, parentKey: key.replace(POLL_JOB_RE, (m, a, ing, c) => (a && c) ? c : '') }); continue; }
      jobRows.push({ kind: 'job', at: x.created_at, actor: x.actor_email, text: `${key}: ${x.status}${x.error ? ' — ' + x.error.slice(0, 160) : ''}`, ref: { jobId: x.id }, status: x.status, jobKey: key });
    }
    tl.push(...jobRows);
    let pollsDropped = 0;
    for (const { x, key, parentKey } of polls) {
      const parent = jobRows.find((p) => p.jobKey === parentKey && p.ref.jobId <= x.id) || jobRows.find((p) => p.jobKey === parentKey);
      if (!parent) { pollsDropped++; continue; }
      tl.push({ kind: 'poll', at: x.created_at, actor: x.actor_email, text: `${key}: ${x.status}`, ref: { jobId: x.id }, status: x.status, jobKey: key, parentKey, parentJobId: parent.ref.jobId });
    }
    for (const x of events) tl.push({ kind: 'work', at: x.created_at, actor: x.actor_email, text: `${x.title || x.item_key}: ${x.event.replace(/_/g, ' ')}${x.from_state ? ' ' + STATE_LABEL[x.from_state] + ' → ' + STATE_LABEL[x.to_state] : ''}${x.note ? ' — ' + x.note.slice(0, 160) : ''}`, ref: { itemKey: x.item_key }, event: x.event });
    for (const x of decisions) tl.push({ kind: 'decision', at: x.created_at, actor: x.created_by, text: `${x.okta_app_label} ${x.match_confidence.replace('manual_', '')} ${x.entra_app_display_name || ''}${x.notes ? ' — ' + x.notes.slice(0, 120) : ''}`, ref: { itemKey: 'app:' + x.okta_app_id } });
    for (const x of actions) tl.push({ kind: 'payload', at: x.created_at, actor: x.actor_email, text: `${x.mapping_key}: ${x.action} (${x.outcome || 'recorded'}) — a generated payload, not an applied change`, ref: { mappingKey: x.mapping_key } });
    for (const x of steps) tl.push({ kind: 'history', at: x.updated_at, actor: x.actor_email, text: `Old page step "${x.step_key}" recorded as ${x.state}${x.note ? ' — ' + x.note.slice(0, 120) : ''} (recorded history, not verified evidence)`, ref: { mappingKey: x.step_key } });
    /* Audit rows that merely mirror a work event, a job start or a match decision (all already on the timeline as the
       event itself) are noise here; the rest go through the 60 s same-actor rule in the grouping. */
    for (const x of auditRows) if (!/^oem_(job_start|work_state|work_disposition|work_assign|work_validate|match_|v2_)/.test(x.action)) tl.push({ kind: 'audit', at: x.created_at, actor: x.actor_email, text: `${x.action} on ${x.target_page_key}`, ref: {}, action: x.action });
    const grouped = groupActivity(tl);
    res.json({ total: grouped.length, raw: tl.length + pollsDropped, items: grouped.slice(0, limit) });
  } catch (e) { fail(res, e, 'activity'); }
});

/* ------------------------------------------------------- okta app lifecycle */

/* tombstone-2: the Entra destination this Okta app was verified against must still exist. The v2 store's destinationFor
   (required lazily: the legacy router loads without it) reads oem_app_match + oem_entra_tombstone directly; the work
   item facts are the fallback when the store is absent. Returns a prerequisite row, or null when nothing is known. */
async function destinationPrerequisite(it) {
  const m = (it.facts && it.facts.match) || null;
  let dest = null;
  const S = lazy('./oem-v2-store');
  if (S && typeof S.destinationFor === 'function') { try { dest = await S.destinationFor(it.source_id); } catch (e) { console.error('[oem-work] destinationFor:', (L.redactText || String)(e && e.message || e)); dest = null; } }
  const gone = !!((dest && (dest.tombstone || dest.state === 'invalidated')) || (m && m.decision === 'invalidated'));
  if (gone) {
    const t = (dest && dest.tombstone) || (m && m.tombstone) || {};
    const name = t.name || (dest && dest.name) || (m && m.entraName) || (dest && dest.entraId) || (m && m.entraId) || 'unknown';
    const when = t.detectedAt ? iso(t.detectedAt).slice(0, 10) : null;
    return { ok: false, code: 'destination_invalidated', text: `Destination invalidated or deleted: the matched Entra application "${name}" no longer exists in Entra${when ? ' (detected ' + when + ')' : ''}. Resolve the destination and verify again before retiring Okta.` };
  }
  if (dest && dest.entraId && dest.state !== 'none') return { ok: true, code: 'destination_present', text: `Entra destination "${dest.name || dest.entraId}" is ${dest.state} and present in the mirror.` };
  return null;
}

async function deactivatePreview(it, req) {
  const okta = await L.oktaIdentity();
  const live = await L.oktaGet(`/api/v1/apps/${it.source_id}`);
  const users = live.status === 200 ? await L.oktaGet(`/api/v1/apps/${it.source_id}/users?limit=200`) : null;
  const lvl = await pageLevel(req);
  const prereq = [];
  if (it.state !== 'verified') prereq.push({ ok: false, text: `Work item must be Verified (it is ${STATE_LABEL[it.state]}).` });
  else prereq.push({ ok: true, text: 'Work item is Verified with recorded evidence.' });
  const destPre = await destinationPrerequisite(it);
  if (destPre) prereq.push(destPre);
  if (!okta.known) prereq.push({ ok: false, text: 'Okta token identity could not be read: ' + okta.error });
  else if (okta.canWriteOkta === null) prereq.push({ ok: false, text: 'Okta roles unknown: ' + (okta.rolesError || 'could not read') });
  else prereq.push({ ok: !!okta.canWriteOkta, text: okta.canWriteOkta ? `Okta token (${okta.login}) holds ${okta.roles.join(', ')}.` : `Okta token (${okta.login}) has no app-admin role; minimum: APP_ADMIN, granted by ${OKTA_GRANTOR}.` });
  prereq.push({ ok: canAct(lvl, req), text: canAct(lvl, req) ? 'You have admin level on this page.' : 'Needs admin level on this page.' });
  if (live.status !== 200) prereq.push({ ok: false, text: 'Could not read the app live from Okta: ' + (live.error || live.status) });
  else prereq.push({ ok: live.body.status === 'ACTIVE', text: `Okta shows ${live.body.status} (last updated ${live.body.lastUpdated}).` });
  const n = users && users.status === 200 ? users.body.length : null;
  return {
    target: { oktaAppId: it.source_id, label: it.title, oktaStatus: live.status === 200 ? live.body.status : 'unknown', assignedUsersSample: n, assignedUsersNote: n === null ? 'unknown' : n >= 200 ? '200+ (first page)' : String(n), entraTarget: it.facts.match ? { id: it.facts.match.entraId, name: it.facts.match.entraName } : null },
    diff: [{ field: 'status', from: live.status === 200 ? live.body.status : 'unknown', to: 'INACTIVE' }],
    scope: 'One Okta application. Users assigned to it lose the Okta tile and Okta-initiated sign-in for this app immediately. Nothing changes in Entra.',
    prerequisites: prereq, canRun: prereq.every((p) => p.ok),
    verification: 'After the change: Okta shows INACTIVE (read live below); an assigned user signs in through Entra My Apps; the work item is then recorded Retired.',
    rollback: 'Reactivate (POST lifecycle/activate) restores the app with its assignments; available on this page with the same confirmation.',
    confirmation: { type: 'typed-label', expected: it.title, reasonRequired: true },
    emergencyAccess: 'Keep at least one Okta super-admin session and the Entra break-glass account available before disabling anything users sign in with.',
  };
}

// GET /api/oem/okta/apps/:id/deactivate/preview
router.get('/okta/apps/:id/deactivate/preview', admin(), async (req, res) => {
  try { const it = await loadItem('app:' + req.params.id); if (!it) return res.status(404).json({ error: 'no work item for that app' }); res.json(await deactivatePreview(it, req)); }
  catch (e) { fail(res, e, 'deactivate preview'); }
});

/* The Okta app lifecycle write (deactivate | activate) as a function: returns {status, body} exactly as the route
   answers, so the v2 Retire Okta step (oem-v2-routes) runs the same prerequisites, the same typed confirmation and the
   same job. `body` is {confirmLabel, reason}. Throws only on an unexpected error (the route turns that into 500). */
async function startOktaLifecycle(req, id, verb, body) {
  if (!['deactivate', 'activate'].includes(verb)) return { status: 400, body: { error: 'verb must be deactivate or activate' } };
  const it = await loadItem('app:' + id);
  if (!it) return { status: 404, body: { error: 'no work item for that app' } };
  const { confirmLabel, reason } = body || {};
  const prev = await deactivatePreview(it, req);
  const blocking = verb === 'deactivate' ? prev.prerequisites.filter((p) => !p.ok) : prev.prerequisites.filter((p) => !p.ok && !/Verified|shows/.test(p.text) && p.code !== 'destination_invalidated');
  if (blocking.length) return { status: 409, body: { error: 'prerequisites not met', prerequisites: prev.prerequisites } };
  if (String(confirmLabel || '') !== it.title) return { status: 400, body: { error: 'Type the application label exactly to confirm.', expected: it.title } };
  if (!(reason && String(reason).trim().length >= 10)) return { status: 400, body: { error: 'A reason of at least 10 characters is required; it is recorded with your name.' } };
  const actor = actorOf(req);
  const r = await L.startJob('okta-app-' + verb + ':' + it.source_id, actor, async (log) => {
    log(`${verb} ${it.title} (${it.source_id}) requested by ${actor}: ${reason}`);
    const call = await L.oktaRequest('POST', `/api/v1/apps/${it.source_id}/lifecycle/${verb}`);
    log(`Okta responded HTTP ${call.status}${call.error ? ' — ' + call.error : ''}`, call.status === 200 ? 'info' : 'error');
    if (call.status !== 200) throw new Error('Okta refused: ' + call.error);
    const live = await L.oktaGet(`/api/v1/apps/${it.source_id}`);
    const status = live.status === 200 ? live.body.status : 'unknown';
    log(`verified live: Okta now shows ${status}`, status === (verb === 'deactivate' ? 'INACTIVE' : 'ACTIVE') ? 'info' : 'warn');
    if (live.status === 200) await pool.query(`UPDATE okta_apps SET status=?, last_updated_at_okta=?, raw_json=? WHERE okta_id=?`, [status, live.body.lastUpdated ? new Date(live.body.lastUpdated) : null, JSON.stringify((L.scrubAppRecord || L.redact)(live.body)), it.source_id]); // secrets-3: raw_json never carries credentials.*
    await pool.query(`UPDATE oem_work_item SET source_status=? WHERE item_key=?`, [status, it.item_key]);
    await pool.query(`INSERT INTO oem_work_event (item_key, event, note, actor_email, evidence) VALUES (?,?,?,?,?)`, [it.item_key, 'okta_' + verb, reason, actor, JSON.stringify({ http: call.status, liveStatus: status })]);
    return { http: call.status, liveStatus: status };
  });
  if (r.conflict) return { status: 409, body: { error: 'already running', conflict: r.conflict } };
  await audit(req, 'oem_okta_app_' + verb, { oktaAppId: it.source_id, label: it.title, reason });
  return { status: 202, body: { ok: true, jobId: r.id, note: 'The change is running as a job; watch it for the live Okta status. Nothing is marked done until Okta confirms the new status.' } };
}
async function lifecycle(req, res, verb) {
  try { const r = await startOktaLifecycle(req, req.params.id, verb, req.body); res.status(r.status).json(r.body); }
  catch (e) { fail(res, e, verb); }
}
router.post('/okta/apps/:id/deactivate', json, admin(), (req, res) => lifecycle(req, res, 'deactivate'));
router.post('/okta/apps/:id/reactivate', json, admin(), (req, res) => lifecycle(req, res, 'activate'));

/* The Entra service principal this Okta app is matched to (confirmed or staged), from the work item facts first and
   app_matches second. Null when there is no usable decision. */
async function matchedEntraIdFor(oktaId, it) {
  const f = (it && it.facts) || {};
  const m = f.match || null;
  if (m && m.entraId && /^(manual_confirmed|manual_staged)$/.test(String(m.decision || ''))) return { entraId: String(m.entraId).toLowerCase(), name: m.entraName || null, decision: m.decision };
  try {
    const [rows] = await pool.query(`SELECT entra_app_id, entra_app_display_name, match_confidence FROM app_matches WHERE okta_app_id=? AND match_confidence IN ('manual_confirmed','manual_staged') ORDER BY FIELD(match_confidence,'manual_confirmed','manual_staged'), id DESC LIMIT 1`, [oktaId]);
    const r = rows && rows[0];
    if (r && r.entra_app_id) return { entraId: String(r.entra_app_id).toLowerCase(), name: r.entra_app_display_name || null, decision: r.match_confidence };
  } catch (e) { /* no decision readable */ }
  return null;
}
const SP_SELECT = 'id,appId,displayName,appRoleAssignmentRequired,accountEnabled,signInAudience,preferredSingleSignOnMode,homepage,tags,publisherName,servicePrincipalType,info,createdDateTime,replyUrls,servicePrincipalNames,loginUrl,logoutUrl,notificationEmailAddresses,preferredTokenSigningKeyThumbprint';

// GET /api/oem/okta/apps/:id/live — "Discover / Refresh (this app, live)": one paced Okta read AND one Graph read of
// the matched Entra service principal (bug 3), each refreshing its mirror row. A Graph 404 is the one fact the mirror
// cannot learn by itself: the principal is recorded as a tombstone, the match is invalidated and the work item rebuilt.
router.get('/okta/apps/:id/live', read(), async (req, res) => {
  try {
    const id = req.params.id;
    const live = await L.oktaGet(`/api/v1/apps/${id}`);
    if (live.status !== 200) return res.status(502).json({ error: 'Okta read failed', status: live.status, detail: live.error });
    const b = (L.scrubAppRecord || L.redact)(live.body); // secrets-2: the mirror row and everything below read the scrubbed copy
    await pool.query(`UPDATE okta_apps SET status=?, label=?, last_updated_at_okta=?, raw_json=?, last_synced_at=NOW() WHERE okta_id=?`, [b.status, b.label, b.lastUpdated ? new Date(b.lastUpdated) : null, JSON.stringify(b), id]);
    await pool.query(`UPDATE oem_work_item SET source_status=? WHERE item_key=?`, [b.status, 'app:' + id]);
    const readAt = L.nowIso();
    const okta = { status: b.status, label: b.label, lastUpdated: b.lastUpdated, signOnMode: b.signOnMode || null, readAt };
    let entra = null, tombstone = null, entraError = null;
    const it = await loadItem('app:' + id);
    const m = await matchedEntraIdFor(id, it);
    if (m) {
      const g = await L.graphGet(`/v1.0/servicePrincipals/${encodeURIComponent(m.entraId)}?$select=${SP_SELECT}`);
      if (g.status === 200 && g.body) {
        const e = g.body;
        try {
          await pool.query(`UPDATE entra_apps SET app_id=?, display_name=?, app_role_assignment_required=?, account_enabled=?, sign_in_audience=?, preferred_single_sign_on_mode=?, homepage_url=?, publisher_name=?, service_principal_type=?, tags_json=?, raw_json=?, last_synced_at=NOW(), seen_in_last_sync=1 WHERE entra_id=?`,
            [e.appId || null, e.displayName || null, e.appRoleAssignmentRequired ? 1 : 0, e.accountEnabled ? 1 : 0, e.signInAudience || null, e.preferredSingleSignOnMode || null, e.homepage || null, e.publisherName || null, e.servicePrincipalType || null, JSON.stringify(e.tags || []), JSON.stringify((L.scrubAppRecord || L.redact)(e)), m.entraId]); // review-2: every raw_json writer scrubs
        } catch (err) { entraError = 'mirror update failed: ' + String(err && err.message || err).slice(0, 160); }
        entra = { entraId: m.entraId, appId: e.appId || null, name: e.displayName || null, enabled: !!e.accountEnabled, ssoMode: e.preferredSingleSignOnMode || null, assignmentRequired: !!e.appRoleAssignmentRequired, replyUrls: e.replyUrls || null, readAt, mirrorUpdated: !entraError };
      } else if (g.status === 404) {
        let row = null;
        try { const [[r]] = await pool.query(`SELECT ${MIRROR_COLS} FROM entra_apps WHERE entra_id=?`, [m.entraId]); row = r || null; } catch (err) { row = null; }
        const t = await recordTombstone({ entraId: m.entraId, appId: row ? row.app_id : null, displayName: (row && row.display_name) || m.name || null, lastSeenAt: row ? row.last_synced_at : null, detectedBy: 'okta-app-live', snapshot: tombstoneSnapshot(row) });
        try { await pool.query(`DELETE FROM entra_apps WHERE entra_id=?`, [m.entraId]); } catch (err) { /* the tombstone is the record; the next sync removes the row */ }
        await invalidateMatchesFor(m.entraId, 'deleted in Entra (live read)');
        try { await pool.query(`INSERT INTO oem_work_event (item_key, event, note, actor_email, evidence) VALUES (?,?,?,?,?)`, ['app:' + id, 'destination_deleted', `The matched Entra application "${(row && row.display_name) || m.name || m.entraId}" no longer exists in Entra.`, actorOf(req), JSON.stringify({ entraId: m.entraId, name: (row && row.display_name) || m.name || null, lastSeenAt: row ? row.last_synced_at : null })]); } catch (err) { /* event is best effort */ }
        try { await D.buildWorkItems(() => {}); } catch (err) { console.error('[oem-work] buildWorkItems after tombstone:', err && err.message || err); }
        tombstone = { entraId: m.entraId, name: (row && row.display_name) || m.name || null, lastSeenAt: iso(row ? row.last_synced_at : null), detectedAt: readAt, recorded: !!t, matchInvalidated: true };
        await audit(req, 'oem_entra_tombstone', { oktaAppId: id, entraId: m.entraId, name: tombstone.name });
      } else entraError = 'Graph read failed: ' + (g.error || ('HTTP ' + g.status));
    }
    res.json({ ok: true, status: b.status, label: b.label, lastUpdated: b.lastUpdated, readAt, okta, entra, entraId: m ? m.entraId : null, entraError, tombstone });
  } catch (e) { fail(res, e, 'okta app live'); }
});

/* ------------------------------------------------------------------ export */

router.get('/export/record', read(), async (req, res) => {
  try {
    const [items] = await pool.query(`SELECT * FROM oem_work_item ORDER BY category, title`);
    const [events] = await pool.query(`SELECT * FROM oem_work_event ORDER BY id`);
    const [decisions] = await pool.query(`SELECT * FROM app_matches ORDER BY okta_app_label`);
    const [jobs] = await pool.query(`SELECT id, job_key, status, actor_email, started_at, finished_at, error, result FROM oem_job ORDER BY id DESC LIMIT 200`);
    const [steps] = await pool.query(`SELECT * FROM oem_step_status`);
    const retirement = await D.assessRetirement();
    const fr = await freshness();
    const cov = await L.metaGet('discovery_coverage', null);
    const me = await L.metaGet('mfa_evidence', null);
    res.setHeader('Content-Disposition', `attachment; filename="okta-retirement-record-${new Date().toISOString().slice(0, 10)}.json"`);
    res.json({ generatedAt: L.nowIso(), generatedBy: actorOf(req), freshness: fr, discoveryCoverage: cov.v, retirement, mfaEvidence: me.v,
      workItems: items.map((i) => Object.assign(i, { facts: j(i.facts, null), evidence: j(i.evidence, null) })), events: events.map((e) => Object.assign(e, { evidence: j(e.evidence, null) })),
      matchDecisions: decisions, jobs: jobs.map((x) => Object.assign(x, { result: j(x.result, null) })), oldPageStepHistory: steps, stateLabels: STATE_LABEL, note: 'Verified items carry tested evidence; old-page step history is recorded history only.' });
  } catch (e) { fail(res, e, 'export record'); }
});

/* v2 hooks (oem-v2-routes, oem-v2-store). The router stays the export; these ride on it. */
router.JOB_DEFS = JOB_DEFS;
router.SOURCE_KEY_OF_JOB = SOURCE_KEY_OF_JOB;
router.runValidationChecks = runValidationChecks;
router.setWorkState = setWorkState;
router.startOktaLifecycle = startOktaLifecycle;
router.captureTombstones = captureTombstones;
router.recordTombstone = recordTombstone;
router.freshness = freshness;
router.groupActivity = groupActivity;
router.STATES = STATES;
router.STATE_LABEL = STATE_LABEL;
module.exports = router;
