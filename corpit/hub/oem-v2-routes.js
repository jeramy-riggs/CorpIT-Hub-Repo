'use strict';
/**
 * oem-v2-routes.js — /api/oem/v2: the push-button Okta -> Entra migration workspace (DESIGN.md section 3).
 *   app.use('/api/oem/v2', require('./oem-v2-routes'));   // before /api/oem/migrate
 *
 * Every mutation checks permission, the revision state predicate and (where it matters) the plan hash on the server;
 * every 4xx answers {error, why}. The model (oem-v2-model) decides; the store (oem-v2-store) writes; this file only
 * wires them to HTTP. Entra/Okta are reached only through L.graphGet / L.oktaGet (reads) and the existing engine
 * (oem-migrate-exec: preflight -> approve -> push) and lifecycle (oem-work-routes.startOktaLifecycle) code paths.
 * Nothing in a response or a log ever carries a secret: configs are refused when they hold one and L.redact runs on
 * everything logged.
 */
const express = require('express');
const createRbac = require('./rbac-middleware');
const L = require('./oem-lib');
const M = require('./oem-v2-model');
const S = require('./oem-v2-store');
const Reset = require('./oem-reset');
const Saml = require('./oem-saml-handoff');
const { defaultEntraName } = require('./oem-app-name');
const { pool, j } = L;

/* Hooks of other modules are required lazily: a build that lacks one answers 501 for the route that needs it. */
function lazy(name) { try { return require(name); } catch (e) { if (!(e && e.code === 'MODULE_NOT_FOUND')) console.error(`[oem-v2] ${name}:`, e && e.message || e); return null; } }
const W = () => lazy('./oem-work-routes');
const X = () => lazy('./oem-migrate-exec');
const Mg = () => lazy('./oem-migrate');
const D = () => lazy('./oem-discovery');
const St = () => lazy('./oem-staged');   /* drop 8e: Entra gallery mirror + Entra export Staged/Complete ledger */
const B = () => lazy('./oem-okta-bookmark'); /* reversible assignment handoff; never deletes the source or Bookmark app */
const hook = (mod, name) => (mod && typeof mod[name] === 'function' ? mod[name] : null);
const errText = (e) => (typeof L.redactText === 'function' ? L.redactText : String)(e && e.message || e || '').slice(0, 300);
/* staged-2: the export ledger is read guarded — a build without the module or a database without the tables reads as
   "no export", never a failed workspace. */
async function stagedOf(oktaId) { const Sm = St(); if (!hook(Sm, 'stagedFor')) return null; try { return await Sm.stagedFor(oktaId); } catch (e) { console.error('[oem-v2] stagedFor ' + oktaId + ':', errText(e)); return null; } }
async function stagedMapSafe() { const Sm = St(); if (!hook(Sm, 'stagedMap')) return { byOkta: new Map(), byEntra: new Map() }; try { return await Sm.stagedMap(); } catch (e) { console.error('[oem-v2] stagedMap:', errText(e)); return { byOkta: new Map(), byEntra: new Map() }; } }

const router = express.Router();
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const PAGE_KEY = 'okta-entra-migration';
/* Every 4xx under /api/oem/v2 carries {error, why}: the rbac gate answers its own 401/403 with {error, code}, so the
   gate is wrapped to add the why before the body leaves. Nothing else about the gate changes. */
const GATE_WHY = { UNAUTHENTICATED: 'Sign in first; this page needs a signed-in session.', INACTIVE_USER: 'Your account is not active.', UNKNOWN_PAGE: 'The page key is not registered; an administrator must add it.', NO_ACCESS: 'You have no grant on the Okta to Entra migration page.', INSUFFICIENT_LEVEL: 'This step needs the admin level on the Okta to Entra migration page.' };
const gate = (level) => {
  const mw = rbac.requirePage(PAGE_KEY, level);
  return (req, res, next) => {
    const orig = res.json;
    res.json = function (body) {
      if (res.statusCode >= 400 && res.statusCode < 500 && body && typeof body === 'object' && !Array.isArray(body) && !body.why) body = Object.assign({}, body, { why: GATE_WHY[body.code] || (body.error ? String(body.error) + '.' : 'The request did not meet a server-side rule.') });
      return orig.call(this, body);
    };
    return mw(req, res, next);
  };
};
const read = () => gate('read');
const admin = () => gate('admin');
const json = express.json({ limit: '256kb' });
const iso = (d) => (d ? new Date(d).toISOString() : null);
const actorOf = (req) => (req.user && req.user.email) || 'anonymous';
const bad = (res, status, error, why, extra) => res.status(status).json(Object.assign({ error, why }, extra || {}));
const notAvailable = (res, what) => bad(res, 501, 'not available in this build', what + ' is not exported by the module this build ships; the step cannot run here.');
/* secrets-6: error text (messages, stacks, engine log lines) goes through L.redactText; secrets-1: mirror records through the narrow
   L.scrubAppRecord (never L.redact: its key regex would blank token_endpoint_auth_method and other public fields). Both guarded — the
   test harness mock may ship without them. */
const redactText = (v) => { try { return typeof L.redactText === 'function' ? L.redactText(v) : String(v); } catch (e) { return '[unprintable]'; } };
const scrubRecord = (v) => (typeof L.scrubAppRecord === 'function' ? L.scrubAppRecord(v) : L.redact(v));
/* An error thrown by the store carries {status, error, why, ...}; it is answered as-is (never its stack). */
function fail(res, e, where) {
  if (e && Number.isInteger(e.status) && e.status >= 400 && e.status < 500) {
    const body = {};
    for (const k of ['error', 'why', 'current', 'existing', 'predicates', 'tombstone', 'conflict', 'checks', 'expected', 'rollout']) if (e[k] !== undefined) body[k] = e[k];
    if (!body.error) body.error = e.message || 'request refused';
    if (!body.why) body.why = 'The request did not meet a server-side rule.';
    return res.status(e.status).json(L.redact(body));
  }
  console.error(`[oem-v2] ${where}:`, redactText(e && e.stack || e)); // secrets-6
  res.status(500).json({ error: 'request failed', where, why: redactText(e && e.message || e).slice(0, 300) });
}
const audit = (req, action, details, target) => { try { if (rbac.audit) return rbac.audit(req, action, target || null, PAGE_KEY, L.redact(details)); } catch (e) { /* audit is best effort */ } return undefined; };
async function pageLevel(req) {
  if (!req.user) return 'none';
  if (req.user.isSuperAdmin) return 'admin';
  try { const pages = await rbac.computeEffectivePages(req.user.email, req.user.roles || [], !!req.user.isSuperAdmin); return (pages && pages[PAGE_KEY]) || 'none'; } catch (e) { return 'none'; }
}
async function permissions(req) {
  const level = await pageLevel(req);
  const readOnly = !!(req.user && req.user.readOnly);
  const can = level === 'admin' && !readOnly;
  return { level, readOnly, canEdit: can, canApprove: can, canConfigureEntra: can, canVerify: can, canSignOff: can, canOverride: !!(req.user && req.user.isSuperAdmin) && !readOnly, canRetire: can, canHandoffAssignments: can };
}
/* Every mutation: page admin (requirePage) AND not a read-only session, with the permission set on req for later checks. */
const mutating = async (req, res, next) => {
  try {
    req.v2 = await permissions(req);
    if (req.v2.readOnly) return bad(res, 403, 'read-only session', 'Your session is read-only on this page; nothing can be changed from it.');
    if (req.v2.level !== 'admin') return bad(res, 403, 'admin level required', 'This step needs the admin level on the Okta to Entra migration page.');
    const lockId = req.params.oktaId || (req.params.id && (await S.getRevision(Number(req.params.id)) || {}).oktaId);
    if (lockId) {
      req.appLease = await Reset.acquire(lockId);
      // Release when the handler answers, including on a disconnected socket.
      // Releasing on socket close could unlock while the handler still writes.
      const send = res.json;
      res.json = function (body) {
        try { return send.call(this, body); }
        finally { req.appLease.release().catch((e) => console.error('[oem-v2] app lock:', errText(e))); }
      };
    }
    next();
  } catch (e) { fail(res, e, 'permissions'); }
};
const OKTA_ID_RE = /^[0-9a-zA-Z]{1,64}$/;
const oktaIdParam = (req, res) => { const id = String(req.params.oktaId || ''); if (!OKTA_ID_RE.test(id)) { bad(res, 400, 'bad Okta id', 'An Okta application id is 1-64 letters and digits.'); return null; } return id; };
const revIdParam = (req, res) => { const id = Number(req.params.id); if (!Number.isInteger(id) || id <= 0) { bad(res, 400, 'bad revision id', 'A revision id is a positive integer.'); return null; } return id; };
async function loadRevision(req, res) {
  const id = revIdParam(req, res); if (!id) return null;
  const rev = await S.getRevision(id);
  if (!rev) { bad(res, 404, 'unknown revision', 'No revision ' + id + '.'); return null; }
  return rev;
}
/* Bug 1: a deleted destination stops every step after Match. */
/* f14: the profile of a revision — an adopted one (existing Entra configuration kept as-is) has no Entra write and no vendor step. */
const profileOf = (rev) => M.protocolProfile(rev ? rev.protocol : 'unknown_custom', { adopt: !!(rev && rev.adopt === true) });
function tombstoneBlock(res, dest) {
  if (dest && (dest.tombstone || dest.state === 'invalidated')) {
    const t = dest.tombstone || {};
    bad(res, 409, `That application was deleted from Entra on ${(t.detectedAt || '').slice(0, 10) || 'an earlier refresh'}; pick a replacement or create a new Entra app`, 'The matched Entra service principal no longer exists; resolve the destination before continuing.', { tombstone: dest.tombstone, destination: { state: dest.state, entraId: dest.entraId, name: dest.name } });
    return true;
  }
  return false;
}
const oktaAdminBase = () => { const b = (process.env.OKTA_BASE_URL || '').replace(/\/+$/, ''); return b ? b.replace(/\.okta(preview|-emea)?\.com$/i, (m) => '-admin' + m) : null; };
function exactMyAppsUrl(value) {
  try {
    const u = new URL(String(value || '').trim());
    return u.protocol === 'https:' && u.hostname.toLowerCase() === 'myapps.microsoft.com' && /^\/signin\//i.test(u.pathname) ? u.href : null;
  } catch (e) { return null; }
}
function bookmarkContext(rev, label, appId, actor) {
  const tenantId = process.env.ENTRA_TENANT_ID || null;
  const cfg = rev && rev.config || {};
  const exact = exactMyAppsUrl(cfg.userAccessUrl);
  const displayName = cfg.displayName || label || rev.oktaId;
  const launcherUrl = exact || (appId && tenantId ? `https://myapps.microsoft.com/signin/${encodeURIComponent(displayName)}/${encodeURIComponent(appId)}?tenantId=${encodeURIComponent(tenantId)}` : null);
  return {
    revisionId: rev.id, oktaId: rev.oktaId, label: label || rev.oktaId, appId: appId || null,
    tenantId, launcherUrl, launcherUrlSource: exact ? 'recorded_user_access_url' : 'documented_myapps_pattern', actor: actor || null,
    onEvent: (event, details) => S.addEvent(rev.oktaId, event, details),
  };
}
const assignmentRolloutKey = (revisionId) => 'entra-assignment-rollout:' + String(revisionId);
async function assignmentRolloutGet(rev) {
  if (!rev || !L.metaGet) return { status: 'not_started' };
  const got = await L.metaGet(assignmentRolloutKey(rev.id), null);
  return got && got.v && typeof got.v === 'object' ? got.v : { status: 'not_started', revisionId: rev.id };
}
async function assignmentRolloutSave(rev, changes) {
  if (!L.metaSet) throw new Error('The metadata store is unavailable; production assignment rollout cannot be tracked safely.');
  const cur = await assignmentRolloutGet(rev);
  const next = Object.assign({}, cur, changes || {}, { revisionId: rev.id, updatedAt: L.nowIso() });
  await L.metaSet(assignmentRolloutKey(rev.id), next);
  return next;
}

/* A compact, server-owned summary that makes provisioning part of the approved plan hash.
   The full mapping worksheet remains in oem_app_scan; no user profile values or credentials
   are copied into a revision. */
async function sourceInventoryFor(oktaId, identity) {
  const fallback = { contractFingerprint: null, contractComplete: false, scannedAt: null,
    provisioning: { enabled: !!(identity && identity.provisioning), features: [],
    inventoryComplete: !(identity && identity.provisioning), outbound: 0, inbound: 0, groupPush: 0,
    manual: 0, specialistRequired: false, fingerprint: null } };
  const mm = Mg();
  const load = hook(mm, 'loadScan');
  if (!load) return fallback;
  try {
    const scan = await load(oktaId);
    const p = scan && scan.model && scan.model.provisioning;
    if (!p) return fallback;
    const maps = Array.isArray(p.mappings) ? p.mappings : [];
    const semantics = hook(mm, 'provisioningSemantics') ? mm.provisioningSemantics(p.features) : p.semantics || {};
    const outbound = maps.filter((m) => m && m.direction === 'to_app');
    const fingerprint = hook(mm, 'migrationSourceFingerprint') ? mm.migrationSourceFingerprint(scan.model) : scan.model.sourceFingerprint || null;
    const complete = hook(mm, 'migrationSourceComplete') ? mm.migrationSourceComplete(scan.model) : scan.model.sourceContractComplete === true;
    return { contractFingerprint: fingerprint, contractComplete: complete === true, scannedAt: scan.scannedAt || null,
      provisioning: { enabled: !!p.enabled, features: Array.isArray(p.features) ? p.features.slice(0, 30) : [],
      inventoryComplete: !!(p.inventory && p.inventory.complete === true),
      outbound: outbound.length, inbound: maps.filter((m) => m && m.direction === 'from_app').length,
      groupPush: Array.isArray(p.groupPush) ? p.groupPush.length : 0,
      manual: outbound.filter((m) => !(m.mapping && m.mapping.mappable)).length,
      specialistRequired: semantics.specialistRequired === true,
      sourceAuthorityReview: semantics.sourceAuthorityReview === true,
      unsupportedCredentialFlow: semantics.unsupportedCredentialFlow === true,
      fingerprint: p.fingerprint || null } };
  } catch (e) {
    console.error('[oem-v2] source inventory ' + oktaId + ':', errText(e));
    return fallback;
  }
}
const protocolOf = (okta, facts) => M.normalizeProtocol({ signOnMode: (okta && okta.signOnMode) || (facts && facts.okta && facts.okta.signOnMode) || '', features: (okta && okta.features) || (facts && facts.okta && facts.okta.features) || [], name: okta ? okta.name : (facts && facts.okta && facts.okta.name), label: okta ? okta.label : '' });
/* f13: the protocols a draft may be created with (OIDC primary when documented, always pickable by hand) — one function for the
   workspace payload and for every draft-creating route, so the page can only offer what the server will accept. */
async function draftOptionsFor(identity, destination, base) {
  const live = base && base.state !== 'superseded' ? base : null;
  const vendorKey = M.vendorKeyFor({ vendorKey: live && live.vendor ? live.vendor.templateKey : null, name: identity.name, label: identity.label, destinationName: destination ? destination.name : null });
  /* gallery-1: the Entra gallery mirror is the third source of "OIDC is documented for this vendor" (read, never guessed;
     an empty mirror or a missing table simply adds nothing). */
  let gallery = null;
  const Sm = St();
  if (hook(Sm, 'galleryFor')) { try { gallery = await Sm.galleryFor([identity.name, identity.label, destination ? destination.name : null]); } catch (e) { console.error('[oem-v2] galleryFor:', errText(e)); } }
  const o = M.protocolOptions({ oktaProtocol: identity.protocol, signOnMode: identity.signOnMode, vendorKey, destination: destination || {}, baseProtocol: live ? live.protocol : null, gallery });
  return Object.assign(o, { forks: live ? { id: live.id, revisionNo: live.revisionNo, state: live.state } : null, galleryTemplates: gallery ? { oidc: gallery.oidc, saml: gallery.saml } : null });
}
/* Resolve the protocol a draft-creating POST asked for against the offered list. Returns {protocol, pick, note, source} or
   sends a 400 and returns null. No protocol in the body -> the primary (OIDC when documented; the forked revision's otherwise). */
function pickProtocol(res, body, opts, identity) {
  const asked = body && body.protocol !== undefined && body.protocol !== null && String(body.protocol) !== '';
  let pick;
  if (asked) {
    pick = opts.options.find((o) => o.protocol === body.protocol);
    if (!pick) { bad(res, 400, 'protocol not offered', `${String(body.protocol).slice(0, 40)} is not an offered protocol for this application; choose one of ${opts.options.map((o) => o.protocol).join(', ')}.`, { draftOptions: opts }); return null; }
  } else pick = opts.options.find((o) => o.protocol === opts.primary) || opts.options[0];
  const parts = [];
  if (asked) parts.push(pick.source === 'manual' ? 'chosen by hand: ' + M.MANUAL_WHY.replace(/\.$/, '') : 'chosen (' + pick.why + ')');
  else parts.push('the primary choice (' + pick.why + ')');
  if (identity && identity.protocol && identity.protocol !== pick.protocol) parts.push('Okta signs in with ' + (M.PROTOCOL_LABEL[identity.protocol] || identity.protocol));
  return { protocol: pick.protocol, pick, source: pick.source, chosen: asked, note: parts.join('; ') };
}

/* ------------------------------------------------------------ workspace */

const AFTER = { draft: 0, plan_approved: 0, entra_configured: 1, awaiting_vendor: 1, awaiting_verification: 2, awaiting_live_approval: 3, live: 4 };
function stageStatuses(profile, revision, destination, appState) {
  const order = ['configure_entra', 'vendor_setup', 'verify', 'live'];
  let cur;
  if (appState === 'live' || appState === 'retired') cur = 99;
  else if (!revision || revision.state === 'superseded') cur = destination && destination.state === 'confirmed' ? 0 : -1;
  else cur = AFTER[revision.state] === undefined ? 0 : AFTER[revision.state];
  return profile.stages.map((s) => {
    let status;
    if (s.key === 'discover') status = 'done';
    else if (s.key === 'match') status = cur >= 0 ? 'done' : 'current';
    else if (!s.applicable) status = 'na';
    else { const i = order.indexOf(s.key); status = i < cur ? 'done' : i === cur ? 'current' : 'todo'; }
    return Object.assign({}, s, { status });
  });
}
function identityOf(oktaId, okta, wi) {
  const facts = (wi && wi.facts) || {};
  const fo = facts.okta || {};
  const raw = okta ? okta.raw : {};
  const Dm = D();
  let ids = fo.identifiers || null;
  if (!ids && Dm && typeof Dm.oktaIdentifiers === 'function') { try { ids = Dm.oktaIdentifiers(raw); } catch (e) { ids = null; } }
  ids = ids || {};
  const protocol = protocolOf(okta, facts);
  const base = oktaAdminBase();
  return {
    oktaId, name: okta ? okta.name : fo.name || null, label: okta ? okta.label : (wi ? wi.title : null), status: okta ? okta.status : (wi ? wi.source_status : null),
    signOnMode: okta ? okta.signOnMode : fo.signOnMode || null, protocol, protocolLabel: M.PROTOCOL_LABEL[protocol] || protocol,
    hidden: fo.hidden === undefined ? null : !!fo.hidden, users: okta && okta.users !== null ? okta.users : (fo.users === undefined ? null : fo.users), groups: okta && okta.groups !== null ? okta.groups : (fo.groups === undefined ? null : fo.groups),
    oktaAdminUrl: base && okta ? `${base}/admin/app/${okta.name}/instance/${oktaId}` : null,
    acsUrls: ids.acs || [], audience: (ids.audience || [])[0] || null, redirectUris: ids.redirects || [], loginUrl: ids.loginUrl || ids.bookmarkUrl || null,
    lastUpdatedOkta: okta ? okta.lastUpdatedOkta : fo.lastUpdated || null, disposition: wi ? wi.disposition : null,
    provisioning: !!fo.provisioning,
  };
}
function checkList(attempt) {
  return (attempt && Array.isArray(attempt.checks) ? attempt.checks : []).map((c) => Object.assign({ key: c.key, label: c.label || M.CHECK_LABEL[c.key] || c.key, result: c.result || c.status || 'inconclusive', detail: c.detail || null }, c.data && typeof c.data === 'object' ? { data: c.data } : {}));
}
/* drop 8: what the sign-in check read, shaped for the page and for the attestation prefill. The rows come newest first
   (oem-work-routes sorts and dedupes them); "mine" is the caller's own latest successful sign-in through Entra, "latestOk"
   anyone's. Null when the attempt carries no sign-in rows (attempts recorded before drop 8, or a check that did not run). */
function signInEvidence(attempt, me) {
  const c = (attempt && Array.isArray(attempt.checks) ? attempt.checks : []).find((x) => x.key === 'signins_via_entra');
  if (!c || !c.data || typeof c.data !== 'object') return null;
  const d = c.data;
  const latest = (Array.isArray(d.latest) ? d.latest : []).filter((r) => r && r.at).map((r) => ({ id: r.id || null, at: r.at, user: r.user || null, ok: r.ok === true || r.error === 0 || r.error === '0', mfa: r.mfa || null }));
  const meL = String(me || '').toLowerCase();
  const mine = latest.find((r) => r.ok && r.user && String(r.user).toLowerCase() === meL) || null;
  const latestOk = latest.find((r) => r.ok) || null;
  return { result: c.result || 'inconclusive', detail: c.detail || null, window: d.window || '14d', total: d.total === undefined ? null : d.total, ok: d.ok === undefined ? null : d.ok, recent24h: d.recent24h === undefined ? null : d.recent24h, users: Array.isArray(d.users) ? d.users : [], latest, mine, latestOk, readAt: attempt.finishedAt || null };
}
function summaryOf(checks) {
  const s = { pass: 0, fail: 0, inconclusive: 0, notApplicable: 0 };
  for (const c of checks) { const r = c.result || c.status; if (r === 'pass') s.pass++; else if (r === 'fail') s.fail++; else if (r === 'not_applicable') s.notApplicable++; else s.inconclusive++; }
  return s;
}
function evidencePackage(oktaId, title, revision, attempt, okta) {
  if (!revision || !['live', 'awaiting_live_approval', 'superseded'].includes(revision.state) && !attempt) return null;
  const checks = checkList(attempt);
  const lines = M.dedupeEvidence(checks.filter((c) => c.detail).map((c) => c.detail));
  return {
    oktaId, title, protocol: revision.protocol, protocolLabel: M.PROTOCOL_LABEL[revision.protocol] || revision.protocol, oktaStatus: okta ? okta.status : null,
    revision: { id: revision.id, revisionNo: revision.revisionNo, state: revision.state, planHash: revision.planHash, planApproved: revision.planApproved, migrationId: revision.migrationId, entraId: revision.entraId, createNew: revision.createNew === true, adopt: revision.adopt === true, adopted: revision.adopt === true ? (revision.adopted || null) : null, liveAttemptId: revision.liveAttemptId === undefined ? null : revision.liveAttemptId, liveGenerations: revision.liveGenerations || null },
    attempt: attempt ? { attemptId: attempt.id, status: attempt.status, startedAt: attempt.startedAt, finishedAt: attempt.finishedAt, actor: attempt.actor, planHash: attempt.planHash, frozen: ['live', 'superseded'].includes(revision.state) } : null,
    checks, summary: summaryOf(checks), evidenceLines: lines,
    ownerConfirm: revision.ownerConfirm, ownerAttestation: revision.ownerAttestation || null, live: revision.live,
    vendorClaim: revision.vendor && revision.vendor.readyAt ? { readyBy: revision.vendor.readyBy, readyAt: revision.vendor.readyAt, note: revision.vendor.note, text: `Vendor setup marked ready for test by ${revision.vendor.readyBy || 'the owner'} — a claim, not verified` } : null,
    generatedAt: L.nowIso(),
  };
}
const ACTIVITY_LIMIT = 500;
async function activityRows(oktaId, limit) {
  const lim = Math.min(Math.max(Number(limit) || 100, 1), ACTIVITY_LIMIT);
  const rows = [];
  const key = oktaId ? 'app:' + oktaId : null;
  const [events] = key
    ? await pool.query(`SELECT e.id, e.item_key, e.event, e.from_state, e.to_state, e.note, e.actor_email, e.created_at, e.evidence FROM oem_work_event e WHERE e.item_key=? ORDER BY e.id DESC LIMIT ?`, [key, lim])
    : await pool.query(`SELECT e.id, e.item_key, e.event, e.from_state, e.to_state, e.note, e.actor_email, e.created_at, e.evidence FROM oem_work_event e WHERE e.actor_email<>'discovery' ORDER BY e.id DESC LIMIT ?`, [lim]);
  for (const x of events || []) rows.push({ kind: 'work', at: x.created_at, actor: x.actor_email, text: `${String(x.event || '').replace(/_/g, ' ')}${x.note ? ' — ' + String(x.note).slice(0, 200) : ''}`, ref: { itemKey: x.item_key, eventId: x.id }, event: x.event, action: x.event });
  const [jobs] = oktaId
    ? await pool.query(`SELECT id, job_key, status, actor_email, started_at, finished_at, error, created_at FROM oem_job WHERE job_key LIKE ? ORDER BY id DESC LIMIT ?`, ['%' + oktaId + '%', lim])
    : await pool.query(`SELECT id, job_key, status, actor_email, started_at, finished_at, error, created_at FROM oem_job ORDER BY id DESC LIMIT ?`, [lim]);
  const POLL = /(^|[:_-])poll(ing)?([:_-]|$)/i;
  const parents = [];
  for (const x of jobs || []) {
    const k = String(x.job_key || '');
    if (POLL.test(k)) continue; // polling never becomes a timeline row (bug 9)
    parents.push({ kind: 'job', at: x.created_at, actor: x.actor_email, text: `${k}: ${x.status}${x.error ? ' — ' + String(x.error).slice(0, 160) : ''}`, ref: { jobId: x.id }, status: x.status, jobKey: k });
  }
  rows.push(...parents);
  try {
    const [mig] = oktaId
      ? await pool.query(`SELECT id, migration_id, okta_id, at, actor, event, step_key, result, detail FROM oem_migration_event WHERE okta_id=? ORDER BY id DESC LIMIT ?`, [oktaId, lim])
      : await pool.query(`SELECT id, migration_id, okta_id, at, actor, event, step_key, result, detail FROM oem_migration_event ORDER BY id DESC LIMIT ?`, [lim]);
    for (const x of mig || []) {
      const isStep = !!x.step_key;
      rows.push({ kind: isStep ? 'step' : 'migration', at: x.at, actor: x.actor, text: `migration ${x.migration_id}: ${x.event}${x.step_key ? ' ' + x.step_key : ''}${x.result ? ' (' + x.result + ')' : ''}`, ref: { migrationId: x.migration_id }, parentJobId: isStep ? 'mig:' + x.migration_id : undefined, action: x.event });
      if (isStep && !rows.some((r) => r.kind === 'migration' && r.ref.migrationId === x.migration_id)) { /* step of a migration whose parent row is outside the window: folded on the migration id */ }
    }
  } catch (e) { /* oem_migration_event absent on an older schema */ }
  try {
    const [aud] = oktaId
      ? await pool.query(`SELECT id, actor_email, action, target_page_key, details, created_at FROM rbac_audit_log WHERE target_page_key=? AND action LIKE 'oem_%' AND details LIKE ? ORDER BY id DESC LIMIT ?`, [PAGE_KEY, '%' + oktaId + '%', lim])
      : await pool.query(`SELECT id, actor_email, action, target_page_key, details, created_at FROM rbac_audit_log WHERE target_page_key=? AND action LIKE 'oem_%' ORDER BY id DESC LIMIT ?`, [PAGE_KEY, lim]);
    for (const x of aud || []) {
      /* the job an audit started (refresh_source/refresh_app carry jobId, oem_job_start carries id): the model folds it into the job row */
      let jobRef;
      try { const d = typeof x.details === 'string' ? JSON.parse(x.details) : (x.details || {}); jobRef = d && d.jobId !== undefined ? d.jobId : (d && x.action === 'oem_job_start' ? d.id : undefined); } catch (e) { jobRef = undefined; }
      rows.push({ kind: 'audit', at: x.created_at, actor: x.actor_email, text: `${x.action}`, ref: { auditId: x.id }, action: x.action, jobRef });
    }
  } catch (e) { /* audit table absent */ }
  const grouped = M.groupActivity(rows);
  return grouped.slice(0, lim).map((r) => ({ at: iso(r.at), kind: r.kind, actor: r.actor || null, title: r.title || r.text || '', detail: r.detail || null, count: r.count || 1, ref: r.ref || null }));
}
async function sourcesFor(oktaId) {
  const per = await S.latestGenerations(oktaId);
  const glob = await S.latestGenerations(null);
  const one = (key) => {
    const p = per[key] || {}, g = glob[key] || {};
    const newer = (a, b) => (!a ? b : !b ? a : (new Date(b.at).getTime() || 0) > (new Date(a.at).getTime() || 0) ? b : a);
    const lastAttempt = newer(p.lastAttempt, g.lastAttempt) || null, lastSuccess = newer(p.lastSuccess, g.lastSuccess) || null;
    return { lastAttempt, lastSuccess, status: M.sourceStatus({ lastAttempt, lastSuccess, staleAfterMs: 30 * 3600 * 1000 }) };
  };
  return { okta: one('okta_apps'), entra: one('entra_apps') };
}

async function buildWorkspace(oktaId, req) {
  const okta = await S.oktaApp(oktaId);
  const wi = await S.workItem(oktaId);
  if (!okta && !wi) return null;
  // The v2 match rows are derived (legacy decisions + candidates + tombstones); reconcile before reading so a target
  // deleted in Entra reads as invalidated the first time anyone opens the app, not only after the next rebuild.
  let matches = null;
  try { matches = (await S.syncMatches(oktaId)).matches; } catch (e) { console.error('[oem-v2] syncMatches ' + oktaId + ':', e && e.message || e); }
  if (!matches) matches = await S.listMatches(oktaId);
  const destination = await S.destinationFor(oktaId, matches);
  const candidates = await S.candidatesFor(oktaId, matches);
  const revision = await S.latestRevision(oktaId);
  const revisions = await S.listRevisions(oktaId);
  const attempt = revision ? await S.attemptFor(revision) : null; // authz-7: frozen for live/superseded, latest otherwise
  const attempts = await S.listAttempts(oktaId, 10);
  const identity = identityOf(oktaId, okta, wi);
  const protocol = revision ? revision.protocol : identity.protocol;
  const profile = M.protocolProfile(protocol, { adopt: !!(revision && revision.adopt === true) });
  const newerDraft = revision ? await S.newerDraftExists(revision) : false;
  const perms = await permissions(req);
  const actor = { email: actorOf(req), canSignOff: perms.canSignOff, readOnly: perms.readOnly, isSuperAdmin: !!(req.user && req.user.isSuperAdmin) };
  const liveEligibility = M.liveEligibility({ revision, attempt, destination, actor, newerDraft });
  const staged = await stagedOf(oktaId);
  const x = { oktaId, destination, revision, attempt, workItem: wi ? { key: wi.item_key, state: wi.state, disposition: wi.disposition } : null, okta: { id: oktaId, status: identity.status, protocol }, profile, candidates, actor, liveEligibility, staged, newerDraft };
  const { state, cta, secondary } = M.ctaFor(x);
  const entra = destination.entraId ? await S.entraApp(destination.entraId) : null;
  const extras = destination.entraId ? await S.spExtras(destination.entraId) : null;
  const values = revision ? M.entraValues(protocol, { tenantId: process.env.ENTRA_TENANT_ID || null, appId: entra ? entra.appId : destination.appId, spObjectId: destination.entraId, mirrorRow: entra ? entra.raw : null, spExtras: extras }) : null;
  const evidence = evidencePackage(oktaId, identity.label, revision, attempt, okta);
  let bookmarkHandoff = null;
  const assignmentRollout = revision ? await assignmentRolloutGet(revision) : null;
  const Bm = B();
  if (revision && hook(Bm, 'get')) {
    try { bookmarkHandoff = await Bm.get(bookmarkContext(revision, identity.label, entra && entra.appId, actorOf(req))); }
    catch (e) { console.error('[oem-v2] bookmark handoff ' + revision.id + ':', errText(e)); bookmarkHandoff = { status: 'unavailable', lastError: 'The assignment handoff record could not be read.' }; }
  }
  return {
    generation: await currentGeneration(),
    identity, destination, candidates,
    profile: { protocol: profile.protocol, label: profile.label, stages: stageStatuses(profile, revision, destination, state), entraWrites: profile.entraWrites, rollback: profile.rollback, adopt: profile.adopt === true },
    draftOptions: await draftOptionsFor(identity, destination, revision),
    revision: revision ? Object.assign({}, revision, { stateLabel: M.STATE_LABEL[revision.state] || revision.state, entra: { configuredAt: revision.entraConfiguredAt, values }, editable: revision.state === 'draft' && perms.canEdit }) : null,
    revisions: revisions.map((r) => ({ id: r.id, revisionNo: r.revisionNo, state: r.state, createdAt: r.createdAt, createdBy: r.createdBy })),
    verification: attempt ? { attemptId: attempt.id, status: attempt.status, startedAt: attempt.startedAt, finishedAt: attempt.finishedAt, actor: attempt.actor, checks: checkList(attempt), summary: attempt.summary || summaryOf(checkList(attempt)), signIns: signInEvidence(attempt, actorOf(req)) } : null,
    attempts: attempts.map((a) => ({ attemptId: a.id, status: a.status, finishedAt: a.finishedAt, actor: a.actor, revisionId: a.revisionId })),
    liveEligibility, state, cta, secondary,
    staged,
    assignmentRollout,
    bookmarkHandoff,
    sources: await sourcesFor(oktaId),
    evidence: { package: evidence },
    activity: await activityRows(oktaId, 60),
    permissions: perms,
    workItem: wi ? { key: wi.item_key, state: wi.state, assignee: wi.assignee || null, nextAction: (wi.facts && wi.facts.nextAction) || null } : null,
  };
}
async function currentGeneration() {
  const Dm = D();
  try { if (Dm && typeof Dm.currentGeneration === 'function') { const g = await Dm.currentGeneration(); if (g) return { id: g.id === undefined ? null : g.id, at: g.at || null }; } } catch (e) { /* unknown, not invented */ }
  return { id: null, at: null };
}

/* ------------------------------------------------------------------- apps */

const COMPLETED = new Set(['live', 'retired', 'nothing_to_migrate', 'not_migrating', 'complete']);
const STAGED = new Set(['entra_configured', 'awaiting_vendor', 'awaiting_verification', 'awaiting_live_approval']);
function viewOf(state, revision) { if (COMPLETED.has(state)) return 'completed'; if (state === 'staged' || (revision && STAGED.has(revision.state))) return 'staged'; return 'todo'; }
async function listItems(req) {
  const rows = await S.listWorkApps();
  const stagedMap = (await stagedMapSafe()).byOkta;
  const perms = await permissions(req);
  const actor = { email: actorOf(req), canSignOff: perms.canSignOff, readOnly: perms.readOnly };
  return rows.map(({ item, revision, destination }) => {
    const facts = item.facts || {}, fo = facts.okta || {};
    const protocol = revision && revision.protocol ? revision.protocol : protocolOf(null, facts);
    const candidates = (facts.match && Array.isArray(facts.match.candidates)) ? facts.match.candidates.filter((c) => !c.rejected) : [];
    const x = { oktaId: item.source_id, destination, revision, attempt: null, workItem: { key: item.item_key, state: item.state, disposition: item.disposition }, okta: { id: item.source_id, status: item.source_status, protocol }, profile: M.protocolProfile(protocol, { adopt: !!(revision && revision.adopt === true) }), candidates, actor, staged: stagedMap.get(item.source_id) || null };
    const { state, cta } = M.ctaFor(x);
    return { oktaId: item.source_id, title: item.title, protocol, protocolLabel: M.PROTOCOL_LABEL[protocol] || protocol, oktaStatus: item.source_status, users: fo.users === undefined ? null : fo.users, groups: fo.groups === undefined ? null : fo.groups,
      state, cta, destination, revision: revision ? { id: revision.id, state: revision.state, revisionNo: revision.revisionNo } : null, assignee: item.assignee || null, assignedAt: iso(item.assigned_at), workKey: item.item_key, workState: item.state, updatedAt: iso(item.state_updated_at || item.last_seen_at), view: viewOf(state, revision),
      staged: x.staged ? { status: x.staged.status, name: x.staged.name, entraId: x.staged.entraId, completedAt: x.staged.completedAt, completedUser: x.staged.completedUser, completedSigninAt: x.staged.completedSigninAt, lastOkAt: x.staged.lastOkAt, signinOk: x.staged.signinOk, lastCheckedAt: x.staged.lastCheckedAt, window: x.staged.window } : null };
  });
}

// GET /apps?view=todo|staged|completed|all&q=
router.get('/apps', read(), async (req, res) => {
  try {
    const view = ['todo', 'staged', 'completed', 'all'].includes(req.query.view) ? req.query.view : 'todo';
    const q = String(req.query.q || '').trim().toLowerCase();
    const all = await listItems(req);
    const counts = { todo: 0, staged: 0, completed: 0, all: all.length };
    for (const it of all) counts[it.view]++;
    let items = view === 'all' ? all : all.filter((it) => it.view === view);
    if (q) items = items.filter((it) => [it.title, it.oktaId, it.destination && it.destination.name, it.protocolLabel].some((s) => s && String(s).toLowerCase().includes(q)));
    items.sort((a, b) => String(a.title || '').localeCompare(String(b.title || '')));
    res.json({ generation: await currentGeneration(), view, items, counts });
  } catch (e) { fail(res, e, 'apps'); }
});

// GET /apps/:oktaId — the workspace payload
router.get('/apps/:oktaId', read(), async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const ws = await buildWorkspace(id, req);
    if (!ws) return bad(res, 404, 'unknown Okta app', 'No Okta application with id ' + id + ' is in the mirror or the work queue.');
    res.json(ws);
  } catch (e) { fail(res, e, 'workspace'); }
});

// Reset is a local workflow operation, with the same page-admin gate as planning.
router.get('/apps/:oktaId/reset', read(), async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    res.json(await Reset.preview(id));
  } catch (e) { fail(res, e, 'reset preview'); }
});
router.post('/apps/:oktaId/reset', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const b = req.body || {};
    const out = await Reset.reset(id, { expected: b.expected, confirm: b.confirm, reason: b.reason, actor: actorOf(req) }, req.appLease.conn);
    await audit(req, 'oem_v2_migration_reset', { oktaId: id, reason: b.reason });
    res.json(out);
  } catch (e) { fail(res, e, 'reset migration'); }
});

// POST /apps/:oktaId/return-to-queue {expectedAssignee} — preserve progress, release technician ownership.
router.post('/apps/:oktaId/return-to-queue', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const body = req.body || {};
    if (!Object.prototype.hasOwnProperty.call(body, 'expectedAssignee') ||
        (body.expectedAssignee !== null && typeof body.expectedAssignee !== 'string')) return bad(res, 400, 'current assignment required', 'Refresh the application before returning it to the queue.');
    const out = await S.returnToQueue('app:' + id, { expectedAssignee: body.expectedAssignee, actor: actorOf(req) }, req.appLease.conn);
    await audit(req, 'oem_v2_return_to_queue', { oktaId: id, from: out.from });
    res.json(out);
  } catch (e) { fail(res, e, 'return to queue'); }
});

// POST /apps/:oktaId/match {action, entraId, note}
router.post('/apps/:oktaId/match', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const { action, entraId, note, expect } = req.body || {};
    /* stateflow-7: the page says which destination it rendered ({state, entraId}); the store refuses (409) when it changed underneath. */
    const expectOpt = expect && typeof expect === 'object' && !Array.isArray(expect) ? { state: expect.state, entraId: expect.entraId } : undefined;
    const r = await S.setMatch(id, { action, entraId, note, actor: actorOf(req), expect: expectOpt });
    await audit(req, 'oem_v2_match_' + action, { oktaId: id, entraId: entraId || null, note: note || null });
    res.json({ ok: true, action: r.action, destination: r.destination, undo: r.undo });
  } catch (e) { fail(res, e, 'match'); }
});

// POST /apps/:oktaId/match/recompute -> {candidates}
router.post('/apps/:oktaId/match/recompute', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const candidates = await S.recomputeCandidates(id);
    await audit(req, 'oem_v2_match_recompute', { oktaId: id, candidates: candidates.length });
    res.json({ ok: true, candidates });
  } catch (e) { fail(res, e, 'recompute'); }
});

// POST /apps/:oktaId/create-entra-app {displayName} — a draft with createNew; no Graph call here (configure-entra does the write through the engine)
router.post('/apps/:oktaId/create-entra-app', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const okta = await S.oktaApp(id);
    if (!okta) return bad(res, 404, 'unknown Okta app', 'No Okta application with id ' + id + ' is in the mirror.');
    const dest = await S.destinationFor(id);
    if (dest.state === 'confirmed' || dest.state === 'shortlisted') return bad(res, 409, 'a destination is already chosen', `${dest.name || dest.entraId} is ${dest.state}; clear it first if a new Entra app is really wanted.`, { destination: dest });
    const requestedName = req.body && req.body.displayName;
    const displayName = requestedName === undefined
      ? defaultEntraName(okta.label || id)
      : typeof requestedName === 'string' ? requestedName.trim() : '';
    if (!displayName || displayName.length > 120) return bad(res, 400, 'invalid displayName', 'Enter an Entra application name between 1 and 120 characters.');
    const wi = await S.workItem(id);
    const identity = identityOf(id, okta, wi);
    const opts = await draftOptionsFor(identity, null, await S.latestRevision(id));   /* f13: no destination yet — OIDC is primary only when the vendor documents it */
    const choice = pickProtocol(res, req.body || {}, opts, identity); if (!choice) return;
    const protocol = choice.protocol;
    const tmpl = M.templateFor(protocol, opts.vendorKey);
    const sourceInventory = await sourceInventoryFor(id, identity);
    const rev = await S.createDraft(id, { protocol, config: { displayName, assignmentScope: 'pilot', pilotUserUpns: [actorOf(req)] }, sourceInventory, entraId: null, actor: actorOf(req), createNew: true,   // stateflow-5: the flag is server-owned; only this route sets it
      vendor: tmpl && !tmpl.generic ? { templateKey: tmpl.key, templateVersion: tmpl.version } : null, protocolNote: choice.note, protocolSource: choice.source, oktaProtocol: identity.protocol });
    await audit(req, 'oem_v2_create_entra_app', { oktaId: id, revisionId: rev.id, displayName, protocol, protocolSource: choice.source, chosen: choice.chosen, primary: opts.primary, oktaProtocol: identity.protocol });
    res.status(201).json({ ok: true, revision: rev, note: 'Nothing was created in Entra yet. Approve the plan, then stage an isolated shell or configure the application now.' });
  } catch (e) { fail(res, e, 'create-entra-app'); }
});

/* ---------------------------------------------------------------- refresh */

// A name-only write: a confirmed destination, explicit Save, current name, and the app mutation lease.
router.post('/apps/:oktaId/entra-name', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const b = req.body || {};
    const name = typeof b.displayName === 'string' ? b.displayName.trim() : '';
    if (!name || name.length > 120 || typeof b.expectedName !== 'string') return bad(res, 400, 'invalid displayName', 'Enter an Entra application name between 1 and 120 characters.');
    const dest = await S.destinationFor(id);
    if (dest.state !== 'confirmed' || dest.tombstone || !dest.entraId || b.entraId !== dest.entraId) return bad(res, 409, 'destination changed', 'Confirm the current, existing Entra destination before changing its name.');
    const [running] = await pool.query("SELECT id FROM oem_migration WHERE okta_id=? AND status='running'", [id]);
    const [locks] = await pool.query('SELECT job_key FROM oem_job_lock');
    const globalJobs = ['discover', 'discover-okta', 'rebuild-work', 'okta-apps', 'entra-apps', 'migrate-bulk-preflight', 'migrate-bulk-push'];
    if (running.length || locks.some((l) => globalJobs.includes(l.job_key) || String(l.job_key).includes(id))) return bad(res, 409, 'application is busy', 'Wait for running inventory or migration jobs to finish, then save the name.');
    const engine = X();
    if (!hook(engine, 'renameEntraApp')) return bad(res, 501, 'name editing unavailable', 'The Entra name editor is not installed on the server.');
    await S.addEvent(id, 'entra_name_requested', { actor: actorOf(req), note: 'Rename the confirmed Entra application', evidence: { entraId: dest.entraId, previousName: b.expectedName, name } });
    const out = await engine.renameEntraApp({ oktaId: id, entraId: dest.entraId, expectedName: b.expectedName, displayName: name, actor: actorOf(req) });
    try {
      const [[row]] = await pool.query('SELECT raw_json FROM entra_apps WHERE entra_id=?', [dest.entraId]);
      const raw = Object.assign({}, j(row && row.raw_json, {}), { displayName: out.name });
      await pool.query('UPDATE entra_apps SET display_name=?, raw_json=? WHERE entra_id=?', [out.name, JSON.stringify(scrubRecord(raw)), dest.entraId]);
      await S.addEvent(id, 'entra_name_changed', { actor: actorOf(req), note: 'Entra application renamed to ' + out.name, evidence: out });
    } catch (e) {
      return bad(res, 502, 'Entra name saved; local refresh needed', 'Entra confirmed the new name, but the local record could not be updated. Use Refresh both before editing again.');
    }
    await audit(req, 'oem_v2_entra_name_changed', out);
    res.json(out);
  } catch (e) { fail(res, e, 'rename Entra application'); }
});

const SP_SELECT = 'id,appId,displayName,appRoleAssignmentRequired,accountEnabled,signInAudience,preferredSingleSignOnMode,homepage,tags,publisherName,servicePrincipalType,createdDateTime,replyUrls,servicePrincipalNames,loginUrl,logoutUrl,preferredTokenSigningKeyThumbprint';
const ENTRA_MIRROR_COLS = 'entra_id, app_id, display_name, app_role_assignment_required, account_enabled, sign_in_audience, preferred_single_sign_on_mode, homepage_url, publisher_name, service_principal_type, tags_json, raw_json, last_synced_at, seen_in_last_sync';
const entraMirrorVals = (e) => [e.appId || null, e.displayName || null, e.appRoleAssignmentRequired ? 1 : 0, e.accountEnabled ? 1 : 0, e.signInAudience || null, e.preferredSingleSignOnMode || null, e.homepage || null, e.publisherName || null, e.servicePrincipalType || null, JSON.stringify(e.tags || []), JSON.stringify(scrubRecord(e))];
/* One per-app refresh: both reads happen first, then both generations commit together — or both fail and nothing is written
   (authz-6: an Okta 200 next to a Graph 503 must not leave a half-new pair). raw_json is scrubbed (secrets-1). A tombstoned
   destination is still read (tombstone-5): a 200 marks the tombstone reappeared, re-inserts the mirror row and records
   destination_reappeared — the match STAYS invalidated; a person rebinds. */
async function refreshOne(oktaId, sources, actor, log, jobId) {
  const out = { okta: null, entra: null };
  const wantOkta = sources.includes('okta');
  if (sources.includes('entra')) { try { await S.syncMatches(oktaId); } catch (e) { log('match sync before refresh failed: ' + redactText(e && e.message || e).slice(0, 200), 'warn'); } }
  const dest = sources.includes('entra') ? await S.destinationFor(oktaId) : null;
  const wantEntra = !!(dest && dest.entraId);
  if (dest && !dest.entraId) out.entra = { skipped: 'no destination' };
  const gens = {};
  if (wantOkta) gens.okta = await S.beginGeneration('okta_apps', { scope: oktaId, jobId, actor });
  if (wantEntra) gens.entra = await S.beginGeneration('entra_apps', { scope: oktaId, jobId, actor });
  const failAll = async (e) => {
    const msg = redactText(e && e.message || e).slice(0, 200);
    for (const k of Object.keys(gens)) { try { await S.failGeneration(gens[k], e); } catch (x) { /* the failure is the record */ } }
    if (wantOkta && !(out.okta && out.okta.error)) out.okta = { error: msg };
    if (wantEntra && !(out.entra && out.entra.error)) out.entra = { error: msg };
    return out;
  };
  /* 1. reads only */
  let oktaBody = null, entraRead = null;
  try {
    if (wantOkta) {
      const live = await L.oktaGet(`/api/v1/apps/${encodeURIComponent(oktaId)}`);
      if (live.status !== 200) throw new Error('Okta read failed: ' + (live.error || ('HTTP ' + live.status)));
      oktaBody = live.body;
    }
  } catch (e) { out.okta = { error: redactText(e && e.message || e).slice(0, 200) }; log('Okta read failed: ' + out.okta.error, 'error'); return failAll(e); }
  try {
    if (wantEntra) {
      const g = await L.graphGet(`/v1.0/servicePrincipals/${encodeURIComponent(dest.entraId)}?$select=${SP_SELECT}`);
      if (g.status === 200 && g.body) entraRead = { body: g.body };
      else if (g.status === 404) entraRead = { gone: true };
      else throw new Error('Graph read failed: ' + (g.error || ('HTTP ' + g.status)));
    }
  } catch (e) { out.entra = { error: redactText(e && e.message || e).slice(0, 200) }; log('Entra read failed: ' + out.entra.error, 'error'); return failAll(e); }
  /* 2. writes, then both generations commit */
  try {
    if (oktaBody) {
      const b = oktaBody;
      await pool.query(`UPDATE okta_apps SET status=?, label=?, last_updated_at_okta=?, raw_json=?, last_synced_at=NOW() WHERE okta_id=?`, [b.status, b.label, b.lastUpdated ? new Date(b.lastUpdated) : null, JSON.stringify(scrubRecord(b)), oktaId]);
      await pool.query(`UPDATE oem_work_item SET source_status=? WHERE item_key=?`, [b.status, 'app:' + oktaId]);
      out.okta = { status: b.status, label: b.label, lastUpdated: b.lastUpdated || null, readAt: L.nowIso() };
      log(`Okta: ${b.label} is ${b.status}`);
    }
    if (entraRead && entraRead.body) {
      const e = entraRead.body;
      const [u] = await pool.query(`UPDATE entra_apps SET app_id=?, display_name=?, app_role_assignment_required=?, account_enabled=?, sign_in_audience=?, preferred_single_sign_on_mode=?, homepage_url=?, publisher_name=?, service_principal_type=?, tags_json=?, raw_json=?, last_synced_at=NOW(), seen_in_last_sync=1 WHERE entra_id=?`, entraMirrorVals(e).concat([dest.entraId]));
      out.entra = { entraId: dest.entraId, name: e.displayName || null, enabled: !!e.accountEnabled, ssoMode: e.preferredSingleSignOnMode || null, readAt: L.nowIso() };
      if (dest.tombstone) {
        /* tombstone-5: the object is back under the same id; the tombstone is closed and the mirror row returns — the match stays invalidated. */
        if (!(u && u.affectedRows)) await pool.query(`INSERT INTO entra_apps (${ENTRA_MIRROR_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW(),1)`, [dest.entraId].concat(entraMirrorVals(e))); // 12 columns + NOW() + 1 = ENTRA_MIRROR_COLS
        const reopened = await S.markReappeared(dest.entraId);
        await S.addEvent(oktaId, 'destination_reappeared', { actor, note: `The Entra application "${e.displayName || dest.entraId}" recorded as deleted on ${((dest.tombstone && dest.tombstone.detectedAt) || '').slice(0, 10) || 'an earlier refresh'} is readable again; the match stays invalidated until a person rebinds it.`, evidence: { entraId: dest.entraId, name: e.displayName || null, tombstoneClosed: !!reopened } });
        out.entra.reappeared = true; out.entra.matchInvalidated = true;
        log(`Entra: ${e.displayName || dest.entraId} reappeared; match stays invalidated`, 'warn');
      } else log(`Entra: ${e.displayName} read live`);
    } else if (entraRead && entraRead.gone) {
      if (dest.tombstone) {
        out.entra = { entraId: dest.entraId, tombstone: true, recorded: false, matchInvalidated: true, stillGone: true };
        log(`Entra: ${dest.entraId} is still gone (404); tombstone already recorded`, 'warn');
      } else {
        const row = await S.entraApp(dest.entraId);
        const t = await S.recordTombstone({ entraId: dest.entraId, appId: row ? row.appId : dest.appId, displayName: (row && row.name) || dest.name || null, lastSeenAt: row ? row.lastSeenAt : dest.lastSeenAt, detectedBy: 'v2-refresh-app', snapshot: row ? { entra_id: row.entraId, app_id: row.appId, display_name: row.name, last_synced_at: row.lastSeenAt } : null });
        try { await pool.query(`DELETE FROM entra_apps WHERE entra_id=?`, [dest.entraId]); } catch (err) { /* the tombstone is the record */ }
        await S.invalidateMatchesFor(dest.entraId, 'deleted in Entra (v2 refresh)');
        await S.addEvent(oktaId, 'destination_deleted', { actor, note: `The matched Entra application "${(row && row.name) || dest.name || dest.entraId}" no longer exists in Entra.`, evidence: { entraId: dest.entraId, name: (row && row.name) || dest.name || null, lastSeenAt: row ? row.lastSeenAt : null } });
        out.entra = { entraId: dest.entraId, tombstone: true, recorded: !!(t && t.recorded), matchInvalidated: true };
        log(`Entra: ${dest.entraId} is gone (404): tombstoned, match invalidated`, 'warn');
      }
    }
    if (gens.okta) await S.commitGeneration(gens.okta, oktaBody ? 1 : 0);
    if (gens.entra) await S.commitGeneration(gens.entra, entraRead && entraRead.body ? 1 : 0);
  } catch (e) { log('refresh write failed: ' + redactText(e && e.message || e).slice(0, 200), 'error'); return failAll(e); }
  await S.rebuildWork();
  return out;
}

// POST /apps/:oktaId/refresh {sources:['okta','entra']} -> 202 {ok,id}
router.post('/apps/:oktaId/refresh', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const wanted = Array.isArray(req.body && req.body.sources) && req.body.sources.length ? req.body.sources.map(String) : ['okta', 'entra'];
    const sources = wanted.filter((s) => s === 'okta' || s === 'entra');
    if (!sources.length) return bad(res, 400, 'sources must name okta and/or entra', 'This refresh reads the Okta application and its matched Entra service principal; nothing else.');
    const actor = actorOf(req);
    const r = await L.startJob('v2-refresh-app:' + id, actor, (log, ctx) => refreshOne(id, sources, actor, log, ctx && ctx.id));
    if (r.conflict) return bad(res, 409, 'already running', 'A refresh for this application is still running; wait for it.', { conflict: r.conflict });
    await audit(req, 'oem_v2_refresh_app', { oktaId: id, sources, jobId: r.id });
    res.status(202).json({ ok: true, id: r.id, jobKey: 'v2-refresh-app:' + id, sources });
  } catch (e) { fail(res, e, 'refresh app'); }
});

const SOURCE_DEFS = [
  { key: 'okta_apps', label: 'Okta applications (mirror)', system: 'Okta', jobKey: 'okta-apps', affects: ['Applications list', 'identity', 'assignments'] },
  { key: 'okta_objects', label: 'Okta policies, authenticators, agents, hooks, tokens, zones', system: 'Okta', jobKey: 'discover-okta', affects: ['dependencies', 'retirement blockers'] },
  { key: 'entra_apps', label: 'Entra enterprise applications (mirror)', system: 'Entra', jobKey: 'entra-apps', affects: ['destinations', 'candidates', 'tombstones'] },
  { key: 'entra_sp_extras', label: 'Entra provisioning jobs + signing certificates', system: 'Entra', jobKey: 'entra-extras', affects: ['provisioning checks', 'certificate expiry'] },
  { key: 'signin_evidence', label: 'Entra sign-in evidence', system: 'Entra', jobKey: null, affects: ['sign-in checks', 'MFA evidence'] },
  { key: 'mfa_registration', label: 'Entra MFA registration report', system: 'Entra', jobKey: 'mfa-evidence', affects: ['MFA evidence'] },
  { key: 'okta_entra_policy_snapshot', label: 'Okta policies + Entra Conditional Access snapshot', system: 'Okta + Entra', jobKey: 'policy-snapshot', affects: ['policy translation'] },
  { key: 'zscaler_mirror', label: 'Zscaler ZPA/ZIA mirror', system: 'Zscaler', jobKey: 'zsnet-refresh', affects: ['network dependencies'] },
  { key: 'work_queue', label: 'Work queue build', system: 'CorpIT', jobKey: 'rebuild-work', affects: ['every list and CTA'] },
  { key: 'entra_gallery', label: 'Entra gallery (SSO templates)', system: 'Entra', jobKey: 'entra-gallery', affects: ['protocol choice (OpenID Connect available)'] },
  { key: 'staged_signins', label: 'Entra export sign-in check (Staged → Complete)', system: 'Entra', jobKey: 'staged-signins', affects: ['Staged / Complete', 'sign-in evidence'] },
];
const REFRESH_JOB_OF = { entra_gallery: 'entra-gallery', staged_signins: 'staged-signins', okta_apps: 'okta-apps', okta_objects: 'discover-okta', entra_apps: 'entra-apps', entra_sp_extras: 'entra-extras', mfa_registration: 'mfa-evidence', okta_entra_policy_snapshot: 'policy-snapshot', zscaler_mirror: 'zsnet-refresh', work_queue: 'rebuild-work', all: 'discover' };

/* What POST /refresh/all (job 'discover' = D.discoverAll) actually reads, in order: the Entra application mirror,
   the Okta objects, the matcher + reconciliation, provisioning/certificates, then the work queue build. The Okta
   application mirror (paced: 50 calls a minute, shared tenant with ITAM), the MFA registration report, the policy
   snapshot and the Zscaler mirror are separate jobs refreshed per source; a banner that showed them "running" under
   Refresh everything was false (codex F2). The page renders exactly this set. */
const GLOBAL_STAGE_KEYS = ['entra_apps', 'okta_objects', 'reconcile', 'entra_sp_extras', 'work_queue'];
const GLOBAL_SOURCES = new Set(GLOBAL_STAGE_KEYS.filter((k) => k !== 'reconcile'));
const RECONCILE_STAGE = { key: 'reconcile', label: 'Match Okta applications to Entra, reconcile deleted destinations, invalidate stale decisions', system: 'CorpIT' };

// GET /refresh — the refresh center
router.get('/refresh', read(), async (req, res) => {
  try {
    const gens = await S.latestGenerations(null);
    const Wm = W();
    let fresh = {};
    if (hook(Wm, 'freshness')) { try { for (const r of await Wm.freshness()) fresh[r.key] = r; } catch (e) { fresh = {}; } }
    const activeJobs = await L.listJobs({ active: true, limit: 10 });
    const active = activeJobs && activeJobs[0] ? activeJobs[0] : null;
    const activeJob = active ? { id: active.id, jobKey: active.jobKey, status: active.status, actor: active.actor, startedAt: iso(active.startedAt) } : null;
    const runningKeys = new Set((activeJobs || []).map((jb) => { const k = String(jb.jobKey || ''); return Object.keys(REFRESH_JOB_OF).find((s) => REFRESH_JOB_OF[s] === k) || null; }).filter(Boolean));
    const globalRunning = runningKeys.has('all');
    const sources = SOURCE_DEFS.map((d) => {
      const g = gens[d.key] || {}, f = fresh[d.key] || {};
      const newer = (a, b) => (!a ? b : !b ? a : (new Date(b.at).getTime() || 0) > (new Date(a.at).getTime() || 0) ? b : a);
      // codex-6: a source measured only by the legacy freshness registry (a meta key or a sync-log row, no
      // oem_source_generation yet) still has a real last attempt: the registry timestamp with the registry verdict.
      // Without it the row read "Never attempted" beside a status of "Current".
      const regAttempt = f.at ? { at: f.at, status: f.status === 'error' ? 'failed' : f.status === 'partial' ? 'partial' : 'success', error: f.status === 'error' ? (f.note || null) : null, jobId: null, via: 'registry' } : null;
      const regSuccess = regAttempt && regAttempt.status !== 'failed' ? { at: f.at, jobId: null, via: 'registry' } : null;
      const lastAttempt = newer(newer(g.lastAttempt, f.lastAttempt), regAttempt) || null;
      const lastSuccess = newer(newer(g.lastSuccess, f.lastSuccess), regSuccess) || null;
      const running = runningKeys.has(d.key) || (globalRunning && GLOBAL_SOURCES.has(d.key));
      const staleAfterMs = (['zscaler_mirror', 'signin_evidence', 'mfa_registration'].includes(d.key) ? 48 : 30) * 3600 * 1000;
      const computed = M.sourceStatus({ lastAttempt, lastSuccess, staleAfterMs });
      const regFallback = f.status && f.status !== 'error' && f.status !== 'failed' ? f.status : null;   /* a failed registry verdict is the attempt column's, not the status column's */
      const status = running ? 'running' : (computed === 'unknown' && regFallback ? regFallback : computed);
      const hasJob = !!(d.jobKey && Wm && Wm.JOB_DEFS && Wm.JOB_DEFS[d.jobKey] && typeof Wm.JOB_DEFS[d.jobKey].run === 'function');
      const action = d.jobKey
        ? { jobKey: d.jobKey, label: 'Refresh ' + d.label.replace(/\s*\(.*\)$/, ''), enabled: !running && hasJob, why: running ? 'A refresh is running.' : hasJob ? null : 'The job is not available in this build.' }
        : { jobKey: null, label: 'Measured by the MFA evidence job', enabled: false, why: 'Sign-in evidence is produced by the mfa_registration refresh; it has no job of its own.' };
      return { key: d.key, label: d.label, system: d.system, lastAttempt: lastAttempt ? { at: lastAttempt.at, status: lastAttempt.status, error: lastAttempt.error || null, jobId: lastAttempt.jobId || null } : null, lastSuccess: lastSuccess ? { at: lastSuccess.at, records: lastSuccess.records === undefined ? null : lastSuccess.records } : null, status, note: f.note || null, affects: d.affects, action };
    });
    const allGen = gens.all || {};
    const stageOf = (key) => {
      if (key === 'reconcile') {
        const la = allGen.lastAttempt || null;
        return Object.assign({}, RECONCILE_STAGE, { status: globalRunning ? 'running' : !la ? 'idle' : la.status === 'failed' ? 'failed' : la.status === 'running' ? 'running' : 'done' });
      }
      const d = SOURCE_DEFS.find((x) => x.key === key), sx = sources.find((x) => x.key === key);
      return { key, label: d ? d.label : key, system: d ? d.system : null, status: globalRunning ? 'running' : !sx || !sx.lastAttempt ? 'idle' : sx.lastAttempt.status === 'failed' ? 'failed' : sx.lastAttempt.status === 'running' ? 'running' : 'done' };
    };
    const stages = GLOBAL_STAGE_KEYS.map(stageOf);
    const notCovered = SOURCE_DEFS.filter((d) => !GLOBAL_SOURCES.has(d.key)).map((d) => ({ key: d.key, label: d.label, jobKey: d.jobKey || null }));
    // SPEC 85: what the last global run reconciled, from the job result (buildWorkItems counts); older results lack the fields.
    let lastRunSummary = null;
    if (allGen.lastAttempt && allGen.lastAttempt.jobId && typeof L.getJob === 'function') {
      try {
        const jb = await L.getJob(allGen.lastAttempt.jobId);
        const w = jb && jb.result && jb.result.work && typeof jb.result.work === 'object' ? jb.result.work : null;
        const mt = jb && jb.result && jb.result.matcher && typeof jb.result.matcher === 'object' ? jb.result.matcher : null;
        if (w) lastRunSummary = {
          applications: w.applications !== undefined ? Number(w.applications) : null,
          destinationsDeleted: w.destinationsDeleted !== undefined ? Number(w.destinationsDeleted) : null,
          matchesInvalidated: w.matchesInvalidated !== undefined ? Number(w.matchesInvalidated) : null,
          matchRowsChanged: w.matchRowsChanged !== undefined ? Number(w.matchRowsChanged) : null,
          staleDecisions: mt && mt.staleDecisions !== undefined ? Number(mt.staleDecisions) : null,
          workQueueRebuilt: true,
        };
      } catch (e) { lastRunSummary = null; }
    }
    let reconciliation = null;
    if (typeof S.reconciliationCounts === 'function') { try { reconciliation = await S.reconciliationCounts(); } catch (e) { reconciliation = null; } }
    res.json({ global: { activeJob, stages, notCovered, reconciliation, lastRun: allGen.lastAttempt ? { at: allGen.lastAttempt.at, status: allGen.lastAttempt.status, error: allGen.lastAttempt.error || null, jobId: allGen.lastAttempt.jobId || null, summary: lastRunSummary } : null, lastSuccess: allGen.lastSuccess || null, action: { jobKey: 'discover', label: 'Discover / Refresh everything', enabled: !active, why: active ? 'A job is running.' : null } }, sources });
  } catch (e) { fail(res, e, 'refresh center'); }
});

// POST /refresh/:sourceKey — start the collector job for one source (or all)
router.post('/refresh/:sourceKey', json, admin(), mutating, async (req, res) => {
  try {
    const key = String(req.params.sourceKey || '');
    const jobKey = REFRESH_JOB_OF[key];
    if (!jobKey) return bad(res, 400, 'unknown source', `sourceKey must be one of ${Object.keys(REFRESH_JOB_OF).join(', ')}.`);
    const Wm = W();
    const def = Wm && Wm.JOB_DEFS && Wm.JOB_DEFS[jobKey];
    if (!def || typeof def.run !== 'function') return notAvailable(res, 'JOB_DEFS.' + jobKey);
    const r = await L.startJob(jobKey, actorOf(req), def.run);
    if (r.conflict) return bad(res, 409, 'already running', `${def.label || jobKey} is already running (job ${r.conflict.jobId}); wait for it.`, { conflict: r.conflict });
    await audit(req, 'oem_v2_refresh_source', { sourceKey: key, jobKey, jobId: r.id });
    res.status(202).json({ ok: true, id: r.id, jobKey, sourceKey: key });
  } catch (e) { fail(res, e, 'refresh source'); }
});

/* -------------------------------------------------------------- revisions */

// POST /apps/:oktaId/revisions {protocol?, config?} -> 201 draft (409 with the existing draft)
router.post('/apps/:oktaId/revisions', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const okta = await S.oktaApp(id);
    const wi = await S.workItem(id);
    if (!okta && !wi) return bad(res, 404, 'unknown Okta app', 'No Okta application with id ' + id + ' is in the mirror.');
    const body = req.body || {};
    const dest = await S.destinationFor(id);
    if (tombstoneBlock(res, dest)) return;
    const existing = await S.draftFor(id);
    if (existing) return bad(res, 409, 'a draft already exists', 'Edit or approve the existing draft; a second draft would fork the same revision.', { revision: existing });
    /* review-2: a new draft supersedes the in-flight revision (authz-2) — never while that revision's Entra write is still running,
       or the finished write would land on a superseded revision and be orphaned. Only a terminal engine failure lets a new draft through. */
    const inflight = await S.latestRevision(id);
    if (body.expectedRevisionId !== undefined && (!inflight || inflight.id !== Number(body.expectedRevisionId) || inflight.version !== Number(body.expectedVersion))) {
      return bad(res, 409, 'revision changed', 'Reload the current revision before saving the vendor values. Your pasted values have not been applied.');
    }
    if (inflight && inflight.migrationId && inflight.state === 'plan_approved') {
      const getM = hook(X(), 'getMigration');
      const prev = getM ? await getM(inflight.migrationId, { events: false }) : null;
      const st = prev ? String(prev.status || '') : '';
      if (!getM || !prev || !ENGINE_FAILED.has(st)) return bad(res, 409, 'an Entra write is already in flight', `Revision ${inflight.revisionNo} started migration ${inflight.migrationId}${st ? ' (' + st + ')' : ''}; wait for it to finish or fail before drafting again.`, { migrationId: inflight.migrationId, engineStatus: st || null, current: inflight });
    }
    const identity = identityOf(id, okta, wi);
    const opts = await draftOptionsFor(identity, dest, inflight);
    const choice = pickProtocol(res, body, opts, identity); if (!choice) return;
    const protocol = choice.protocol;
    const cfg = Object.assign({}, body.config || {});
    if (cfg.samlEndpointUpdate === true) {
      const why = Saml.validateVendorValues(cfg);
      if (protocol !== 'saml2' || why) return bad(res, 400, 'invalid vendor values', why || 'This handoff requires a SAML revision.');
    }
    delete cfg.createNew; // stateflow-5: server-owned — only POST /apps/:oktaId/create-entra-app sets it; a client cannot plan "new app" here
    if (!cfg.assignmentScope) cfg.assignmentScope = 'pilot';
    if (cfg.assignmentScope === 'pilot' && !cfg.pilotUserUpns) cfg.pilotUserUpns = [actorOf(req)];
    if (cfg.userAccessUrl && !exactMyAppsUrl(cfg.userAccessUrl)) return bad(res, 400, 'invalid Entra User access URL', 'Copy the HTTPS User access URL from Enterprise applications > Properties. It must start with https://myapps.microsoft.com/signin/.');
    M.assertNoSecrets(cfg); // refused here and again in the store (the store is the last line); nothing is written
    /* A pre-create revision may need a replacement draft after approval (for example, to add a
       vendor bootstrap value or choose a collision-free display name). Preserve the server-owned
       createNew decision only while no Entra object has been created or bound. */
    const continueCreateNew = dest.state === 'none' && !!(inflight && inflight.createNew === true && !inflight.entraId);
    if (dest.state !== 'confirmed' && !continueCreateNew) return bad(res, 409, 'destination not confirmed', dest.state === 'none' ? 'Choose and confirm the Entra destination (or create a new Entra app) before planning.' : `The destination is ${dest.state}; confirm it first.`, { destination: dest });
    if (!cfg.displayName) cfg.displayName = continueCreateNew
      ? (inflight.config && inflight.config.displayName) || defaultEntraName(okta ? okta.label : wi.title)
      : dest.name || (okta ? okta.label : wi.title);
    const tmpl = M.templateFor(protocol, opts.vendorKey);
    const sourceInventory = await sourceInventoryFor(id, identity);
    const rev = await S.createDraft(id, { protocol, config: cfg, sourceInventory, entraId: dest.entraId, matchId: dest.match ? dest.match.id : null, actor: actorOf(req), createNew: continueCreateNew,
      vendor: tmpl && !tmpl.generic ? { templateKey: tmpl.key, templateVersion: tmpl.version } : null, protocolNote: choice.note, protocolSource: choice.source, oktaProtocol: identity.protocol });
    await audit(req, 'oem_v2_revision_create', { oktaId: id, revisionId: rev.id, protocol, protocolSource: choice.source, chosen: choice.chosen, primary: opts.primary, oktaProtocol: identity.protocol, vendorTemplate: tmpl && !tmpl.generic ? tmpl.key : null });
    res.status(201).json({ ok: true, revision: rev });
  } catch (e) { fail(res, e, 'create revision'); }
});

// GET /revisions/:id
router.get('/revisions/:id', read(), async (req, res) => {
  try { const rev = await loadRevision(req, res); if (!rev) return; res.json({ revision: rev, attempts: await S.listAttempts(rev.oktaId, 10), overrides: await S.listOverrides(rev.id) }); }
  catch (e) { fail(res, e, 'revision'); }
});

// POST /revisions/:id {config, version} — draft only; 409 edited by someone else
router.post('/revisions/:id', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    const body = req.body || {};
    if (rev.state !== 'draft') return bad(res, 409, 'revision is not editable', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; create a new draft to change it.`, { current: rev });
    if (body.config === undefined || typeof body.config !== 'object' || body.config === null) return bad(res, 400, 'config required', 'Send the whole draft config object.');
    if (Object.prototype.hasOwnProperty.call(body.config, 'displayName')) {
      const name = typeof body.config.displayName === 'string' ? body.config.displayName.trim() : '';
      if (!name || name.length > 120) return bad(res, 400, 'invalid displayName', 'Enter an Entra application name between 1 and 120 characters.');
      body.config.displayName = name;
    }
    if (body.config.userAccessUrl && !exactMyAppsUrl(body.config.userAccessUrl)) return bad(res, 400, 'invalid Entra User access URL', 'Copy the HTTPS User access URL from Enterprise applications > Properties. It must start with https://myapps.microsoft.com/signin/.');
    if (body.config.samlEndpointUpdate === true) {
      const why = Saml.validateVendorValues(body.config);
      if (rev.protocol !== 'saml2' || why) return bad(res, 400, 'invalid vendor values', why || 'This handoff requires a SAML revision.');
    }
    M.assertNoSecrets(body.config); // refused here and again in the store (the store is the last line); nothing is written
    const out = await S.updateDraft(rev.id, { config: body.config, version: body.version, actor: actorOf(req) });
    await audit(req, 'oem_v2_revision_edit', { oktaId: rev.oktaId, revisionId: rev.id });
    res.json({ ok: true, revision: out });
  } catch (e) { fail(res, e, 'edit revision'); }
});

// POST /revisions/:id/approve-plan {planHash}
router.post('/revisions/:id/approve-plan', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    const hash = String((req.body && req.body.planHash) || '');
    if (!hash) return bad(res, 400, 'planHash required', 'Approval binds to the plan you saw; send its hash.');
    const dest = await S.destinationFor(rev.oktaId);
    if (!rev.createNew) {
      if (tombstoneBlock(res, dest)) return;
      if (!rev.entraId) return bad(res, 409, 'no Entra destination bound', `Revision ${rev.revisionNo} has no Entra application to configure; confirm a destination (or create a new Entra app) and plan again.`, { current: rev }); // stateflow-5
      if (dest.entraId !== rev.entraId) return bad(res, 409, 'destination changed since the plan', `The plan targets ${rev.entraId} but the confirmed destination is now ${dest.entraId || 'none'}; draft a new revision.`, { destination: dest, current: rev }); // review-2: approval binds the plan to the destination it was drafted against
    }
    const source = rev.config && rev.config._sourceInventory;
    if (profileOf(rev).entraWrites && (!source || source.contractComplete !== true || !source.contractFingerprint)) {
      return bad(res, 409, 'source inventory is incomplete', 'Run a fresh application scan before approval. The plan must bind to complete Okta groups, direct users, Okta-native group membership, claims and provisioning configuration.', { current: rev, sourceInventory: source || null });
    }
    const r = await S.approvePlan(rev.id, { hash, actor: actorOf(req) });
    if (!r.alreadyApproved) await audit(req, 'oem_v2_plan_approve', { oktaId: rev.oktaId, revisionId: rev.id, planHash: hash });
    res.json({ ok: true, revision: r.revision, alreadyApproved: r.alreadyApproved });
  } catch (e) { fail(res, e, 'approve plan'); }
});

const ENGINE_OK = new Set(['succeeded', 'warnings']);
const ENGINE_FAILED = new Set(['failed', 'rolled_back', 'cancelled', 'preflight_failed']);
const ENGINE_END = new Set([...ENGINE_OK, ...ENGINE_FAILED]);
/* resume-1: how a 404 on a recorded service principal is classified. A fresh SP can answer 404 purely from Graph replication lag, so a
   404 is called a real deletion only on the resume path, only once the failed run is older than GONE_MIN_AGE_MS (the lag window has
   closed), and only after GONE_CONFIRM_READS confirming re-reads still 404. */
const GONE_MIN_AGE_MS = 120000;
const GONE_CONFIRM_READS = 2;
const GONE_CONFIRM_MS = 2000;
/* The vendor instructions a revision gets (template + values) — one function for the GET and for the stamp (stateflow-9). */
async function vendorInstructionsFor(rev) {
  const okta = await S.oktaApp(rev.oktaId);
  const entra = rev.entraId ? await S.entraApp(rev.entraId) : null;
  const extras = rev.entraId ? await S.spExtras(rev.entraId) : null;
  const values = M.entraValues(rev.protocol, { tenantId: process.env.ENTRA_TENANT_ID || null, appId: entra ? entra.appId : null, spObjectId: rev.entraId, mirrorRow: entra ? entra.raw : null, spExtras: extras });
  const cfg = rev.config || {};
  const dest0 = await S.destinationFor(rev.oktaId);
  const vendorKey = cfg.vendorKey || (rev.vendor && rev.vendor.templateKey) || M.vendorKeyFor({ name: okta ? okta.name : null, label: okta ? okta.label : null, destinationName: dest0 ? dest0.name : null }) || (okta ? String(okta.name || '').toLowerCase().replace(/[^a-z0-9]+/g, '_') : null);   /* f13: the vendor is matched by name, not slug equality */
  const instructions = M.vendorInstructions(rev.protocol, { vendorKey, oktaName: okta ? okta.name : null, oktaLabel: okta ? okta.label : null, values, ownerEmail: cfg.ownerEmail || null, adopt: rev.adopt === true }); // f15: an adopted revision has no vendor step
  return { instructions, values };
}
/* stateflow-9: the template a revision was handed is stamped by the write path (entra_configured -> awaiting_vendor, or
   vendor-ready when still unstamped), never by a GET. Best effort: no template, no stamp. */
async function vendorTemplateStamp(rev) {
  if (rev.vendor && rev.vendor.templateKey) return {};
  try { const { instructions } = await vendorInstructionsFor(rev); return instructions && instructions.templateKey ? { vendorTemplateKey: instructions.templateKey, vendorTemplateVersion: String(instructions.templateVersion || '') } : {}; }
  catch (e) { return {}; }
}
async function afterEntraConfigured(rev, actor, extra) {
  const profile = profileOf(rev);
  const vendor = profile.stages.find((s) => s.key === 'vendor_setup');
  let out = await S.transition(rev.id, ['plan_approved'], 'entra_configured', { entraConfiguredAt: 'NOW()' }, { actor, note: 'Entra configured by the migration engine', evidence: extra || {} });
  const stamp = vendor && vendor.applicable ? await vendorTemplateStamp(out) : {};
  out = await S.transition(rev.id, ['entra_configured'], vendor && vendor.applicable ? 'awaiting_vendor' : 'awaiting_verification', stamp, { actor, note: vendor && vendor.applicable ? 'Waiting for the application owner to configure the vendor' : 'No vendor setup for this sign-on method; ready to verify', evidence: stamp.vendorTemplateKey ? { vendorTemplateKey: stamp.vendorTemplateKey, vendorTemplateVersion: stamp.vendorTemplateVersion } : undefined });
  return out;
}
/* stateflow-6: the engine records the service principal it created as oem_migration.entra_sp_object_id (getMigration ->
   entraSpObjectId) and as a createdObjects entry {type:'servicePrincipal', id}. A createNew revision binds it as the confirmed
   destination before it advances; without an id the revision stays at Plan approved and the event names what to do. */
function createdSpId(m) {
  if (!m) return null;
  if (m.entraSpObjectId) return String(m.entraSpObjectId).toLowerCase();
  const sp = (Array.isArray(m.createdObjects) ? m.createdObjects : []).find((o) => o && o.type === 'servicePrincipal' && o.id);
  return sp ? String(sp.id).toLowerCase() : null;
}
async function bindCreatedApp(rev, m, actor, opts = {}) {
  const entraId = createdSpId(m);
  const migrationId = m && m.id !== undefined ? m.id : rev.migrationId;
  if (!entraId) {
    await S.addEvent(rev.oktaId, 'entra_configure_unbound', { actor, note: `Migration ${migrationId} succeeded but recorded no created service principal id; confirm the new Entra app as the destination by hand, then bind it to revision ${rev.revisionNo}. The revision stays at Plan approved.`, evidence: { revisionId: rev.id, migrationId } });
    return { ok: false, why: 'engine recorded no created service principal id' };
  }
  try {
    /* A just-created service principal is not in the scheduled mirror yet. Read it back and
       insert the narrow mirror row before setMatch(), so binding never depends on a later refresh. */
    let live = await L.graphGet(`/v1.0/servicePrincipals/${encodeURIComponent(entraId)}?$select=${SP_SELECT}`);
    if (live && live.status === 404) {
      /* resume-1: a fresh service principal answers 404 purely from Graph replication lag (2026-09-21 Calendly: the object and its
         roles surfaced in Entra only minutes after the create). A 404 is called a real deletion ONLY on the resume path AND only once
         lag is ruled out: the failed run finished more than GONE_MIN_AGE_MS ago (its objects would have replicated by now) and a short
         confirming re-read still 404s. Every other 404 - a poll-job read seconds after the create, or a recent failed run - is recorded
         as not-readable-yet, so the caller keeps the revision at Plan approved for a retry instead of accusing a manual deletion and
         steering the person into a destructive rollback of an object that is only lagging. */
      const finishedMs = m && m.finishedAt ? Date.parse(m.finishedAt) : NaN;
      const oldEnough = Number.isFinite(finishedMs) && (Date.now() - finishedMs) > GONE_MIN_AGE_MS;
      if (opts.resume === true && oldEnough) {
        for (let i = 0; i < GONE_CONFIRM_READS && live && live.status === 404; i++) {
          await L.sleep(GONE_CONFIRM_MS);
          live = await L.graphGet(`/v1.0/servicePrincipals/${encodeURIComponent(entraId)}?$select=${SP_SELECT}`);
        }
      }
      if (live && live.status === 404) {
        if (opts.resume === true && oldEnough) {
          const ageS = Math.round((Date.now() - finishedMs) / 1000);
          await S.addEvent(rev.oktaId, 'entra_configure_bind_failed', { actor, note: `Migration ${migrationId} created service principal ${entraId}, but Entra still has no such service principal ${ageS} s after that run finished; it was removed outside CorpIT. Revision ${rev.revisionNo} stays at Plan approved.`, evidence: { revisionId: rev.id, migrationId, entraId, gone: true } });
          return { ok: false, gone: true, entraId, why: 'Entra no longer has service principal ' + entraId + '; it was removed outside CorpIT' };
        }
        await S.addEvent(rev.oktaId, 'entra_configure_bind_failed', { actor, note: `Migration ${migrationId} created service principal ${entraId}, but Entra has not made it readable yet (HTTP 404); this is usually replication lag right after a create. Revision ${rev.revisionNo} stays at Plan approved; run Configure Entra again shortly.`, evidence: { revisionId: rev.id, migrationId, entraId, notReadable: true } });
        return { ok: false, why: 'created service principal is not readable yet: HTTP 404' };
      }
    }
    if (!live || live.status !== 200 || !live.body) throw new Error('created service principal is not readable yet: ' + ((live && live.error) || ('HTTP ' + (live && live.status))));
    const e = live.body;
    const [u] = await pool.query(`UPDATE entra_apps SET app_id=?, display_name=?, app_role_assignment_required=?, account_enabled=?, sign_in_audience=?, preferred_single_sign_on_mode=?, homepage_url=?, publisher_name=?, service_principal_type=?, tags_json=?, raw_json=?, last_synced_at=NOW(), seen_in_last_sync=1 WHERE entra_id=?`, entraMirrorVals(e).concat([entraId]));
    if (!(u && u.affectedRows)) await pool.query(`INSERT INTO entra_apps (${ENTRA_MIRROR_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW(),1)`, [entraId].concat(entraMirrorVals(e)));
    await S.setMatch(rev.oktaId, { action: 'confirm', entraId, note: 'created by revision ' + rev.revisionNo, actor });
    await S.setRevisionFields(rev.id, { entraId }, { whereState: 'plan_approved' });
    return { ok: true, entraId };
  } catch (e) {
    await S.addEvent(rev.oktaId, 'entra_configure_bind_failed', { actor, note: `Migration ${migrationId} created service principal ${entraId} but it could not be bound to revision ${rev.revisionNo}: ${redactText(e && e.message || e).slice(0, 200)}. The revision stays at Plan approved.`, evidence: { revisionId: rev.id, migrationId, entraId } });
    return { ok: false, why: 'binding the created app failed: ' + redactText(e && e.message || e).slice(0, 200) };
  }
}
/* stateflow-3: what the engine planned against — plan.mode is 'adopt' | 'create' | 'none'; the assessment target carries the
   Entra id the engine will adopt (its legacy match id may be an appId, so both the object id and the appId are accepted). */
function engineTarget(mig) {
  const plan = (mig && mig.plan) || {};
  const t = (mig && mig.assessment && mig.assessment.target) || {};
  return { mode: plan.mode || null, entraId: t.entraId ? String(t.entraId).toLowerCase() : null, entraName: t.entraName || null };
}
function engineInputsFor(rev, actor, extra) {
  const cfg = rev.config || {};
  const inputs = {};
  for (const [k, v] of Object.entries({
    entityId: cfg.entityId || cfg.audience,
    acsUrls: cfg.samlEndpointUpdate === true ? cfg.replyUrls : (cfg.acsUrls || cfg.replyUrls),
    displayName: cfg.displayName,
    skipGroupCreate: cfg.skipGroupCreate,
    assignmentScope: cfg.assignmentScope || 'pilot',
    pilotGroupIds: cfg.pilotGroupIds,
    pilotUserUpns: cfg.pilotUserUpns || (actor ? [actor] : []),
    samlEndpointUpdate: cfg.samlEndpointUpdate === true,
    configureSaml: rev.protocol === 'saml2' && cfg.samlEndpointUpdate !== true,
    samlHandoffThumbprint: cfg.samlHandoffThumbprint,
    relayState: cfg.relayState,
  })) if (v !== undefined && v !== null && v !== '') inputs[k] = v;
  return Object.assign(inputs, extra || {});
}
function sourceFingerprintOf(mig) {
  const currentModel = mig && mig.snapshot && mig.snapshot.model;
  const mm = Mg();
  return currentModel && (hook(mm, 'migrationSourceFingerprint') ? mm.migrationSourceFingerprint(currentModel) : currentModel.sourceFingerprint);
}

// POST /revisions/:id/stage-shell — create and bind an isolated Entra shell; keep the approved revision open for configuration
router.post('/revisions/:id/stage-shell', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    if (rev.state !== 'plan_approved') return bad(res, 409, 'plan not approved', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; shell staging needs an approved plan.`, { current: rev });
    if (!rev.createNew) return bad(res, 409, 'shell staging is only for a new application', 'This revision updates an existing Entra application; run Configure Entra instead.');
    if (rev.entraId) return bad(res, 409, 'the Entra shell already exists', 'Continue with the bound shell or create a new draft; a second shell would be a duplicate.', { current: rev });
    if (await S.newerDraftExists(rev)) return bad(res, 409, 'a newer draft exists', `A newer draft than revision ${rev.revisionNo} is open; work from the newest revision.`, { current: rev });
    const dest = await S.destinationFor(rev.oktaId);
    if (dest.state !== 'none') return bad(res, 409, 'a destination is still recorded', `This revision creates a new Entra app but ${dest.name || dest.entraId} is ${dest.state}; clear or resolve it first.`, { destination: dest });
    const cfg = rev.config || {};
    const hashNow = M.planFor(rev.protocol, { entraId: null, config: cfg, createNew: true, displayName: cfg.displayName }).hash;
    if (!rev.planApprovedHash || hashNow !== rev.planApprovedHash || rev.planHash !== rev.planApprovedHash) return bad(res, 409, 'Plan changed since approval', 'The plan no longer matches the approved hash; approve it again before staging the shell.', { current: rev });
    const Xm = X();
    if (!hook(Xm, 'preflight') || !hook(Xm, 'approve') || !hook(Xm, 'push')) return notAvailable(res, 'oem-migrate-exec preflight/approve/push');
    if (rev.migrationId) {
      const getM = hook(Xm, 'getMigration');
      const prev = getM ? await getM(rev.migrationId, { events: false }) : null;
      const st = prev ? String(prev.status || '') : '';
      if (!prev || !ENGINE_FAILED.has(st)) return bad(res, 409, 'a shell write is already in flight', `Migration ${rev.migrationId} is ${st || 'of unknown status'}; a second run could create a duplicate.`, { migrationId: rev.migrationId, engineStatus: st || null });
    }
    const actor = actorOf(req);
    const mig = await Xm.preflight(rev.oktaId, actor, { inputs: engineInputsFor(rev, actor, { shellOnly: true, assignmentScope: 'none' }), targetMode: 'create', log: (m) => console.log('[oem-v2] shell preflight', rev.oktaId, redactText(m)) });
    if (!mig || (mig.error && mig.id === undefined)) return bad(res, mig && Number.isInteger(mig.status) ? mig.status : 409, (mig && mig.error) || 'pre-flight failed', 'The migration engine refused shell staging; nothing was written.', { migrationId: mig && mig.id !== undefined ? mig.id : null, checks: L.redact((mig && mig.preflight && mig.preflight.checks) || []) });
    const pf = mig.preflight || {};
    if (pf.passed === false || (pf.summary && pf.summary.failed > 0)) return bad(res, 409, 'pre-flight failed', 'Fix the failing checks, then stage the shell again; nothing was written.', { checks: L.redact(pf.checks || []), migrationId: mig.id });
    const approvedSource = cfg._sourceInventory || {};
    const currentFingerprint = sourceFingerprintOf(mig);
    if (!approvedSource.contractFingerprint || !currentFingerprint || approvedSource.contractFingerprint !== currentFingerprint) return bad(res, 409, 'Okta source changed after plan approval', 'The live pre-flight found a different source contract. Nothing was written; create and approve a fresh draft.', { migrationId: mig.id, approvedFingerprint: approvedSource.contractFingerprint || null, currentFingerprint: currentFingerprint || null, checks: L.redact(pf.checks || []) });
    const target = engineTarget(mig);
    if (target.mode !== 'create') return bad(res, 409, 'engine target differs from the plan', 'The shell run did not resolve to a create operation; nothing was written.', { migrationId: mig.id, engineTarget: target, checks: L.redact(pf.checks || []) });
    const ack = (pf.checks || []).filter((c) => c && c.status === 'warn').map((c) => c.key);
    const ap = await Xm.approve(mig.id, actor, { confirm: (mig.plan && mig.plan.displayName) || cfg.displayName, reason: 'v2 isolated shell revision ' + rev.id, acknowledge: ack });
    if (ap && ap.error) return bad(res, Number.isInteger(ap.status) ? ap.status : 409, ap.error, 'The engine did not accept the shell approval; nothing was written.', { migrationId: mig.id });
    const pu = await Xm.push(mig.id, actor);
    if (pu && pu.error) return bad(res, Number.isInteger(pu.status) ? pu.status : 409, pu.error, 'The engine did not start shell staging.', { migrationId: mig.id, conflict: pu.conflict });
    await S.setRevisionFields(rev.id, { migrationId: mig.id }, { whereState: 'plan_approved' });
    await S.addEvent(rev.oktaId, 'entra_shell_started', { actor, note: `Isolated Entra shell started (migration ${mig.id})`, evidence: { revisionId: rev.id, migrationId: mig.id, jobId: pu && pu.jobId } });
    await audit(req, 'oem_v2_stage_shell', { oktaId: rev.oktaId, revisionId: rev.id, migrationId: mig.id });
    const poll = await L.startJob('v2-shell-poll:' + rev.id, actor, async (log) => {
      const get = hook(Xm, 'getMigration');
      if (!get) { log('engine status unavailable; the shell write may still be running', 'warn'); return { status: 'unknown', migrationId: mig.id }; }
      for (let i = 0; i < 200; i++) {
        const m = await get(mig.id, { events: false });
        const st = m ? String(m.status || '') : '';
        if (ENGINE_OK.has(st)) {
          const bound = await bindCreatedApp(rev, m, actor);
          if (!bound.ok) { log('shell write ' + st + ' but ' + bound.why, 'error'); return { status: st, migrationId: mig.id, bound: false }; }
          await S.setRevisionFields(rev.id, { migrationId: null }, { whereState: 'plan_approved' });
          await S.addEvent(rev.oktaId, 'entra_shell_staged', { actor, note: `Isolated Entra shell ${bound.entraId} is visible, assignment-required and unassigned`, evidence: { revisionId: rev.id, migrationId: mig.id, entraId: bound.entraId } });
          log('isolated shell staged and bound to ' + bound.entraId);
          return { status: st, migrationId: mig.id, entraId: bound.entraId };
        }
        if (ENGINE_END.has(st)) {
          await S.setRevisionFields(rev.id, { migrationId: null }, { whereState: 'plan_approved' });
          await S.addEvent(rev.oktaId, 'entra_shell_failed', { actor, note: `Shell staging ended ${st}; the approved revision remains open`, evidence: { revisionId: rev.id, migrationId: mig.id } });
          log('shell staging ended: ' + st, 'error'); return { status: st, migrationId: mig.id };
        }
        await L.sleep(3000);
      }
      log('gave up waiting for the shell migration', 'warn'); return { status: 'timeout', migrationId: mig.id };
    });
    res.status(202).json({ ok: true, migrationId: mig.id, jobId: pu && pu.jobId ? pu.jobId : null, pollJobId: poll && poll.id ? poll.id : null, state: 'plan_approved', note: 'The isolated Entra shell is being created. It will be visible and assignment-required, with no users, groups or SSO configuration.' });
  } catch (e) { fail(res, e, 'stage Entra shell'); }
});
// POST /revisions/:id/configure-entra — engine preflight -> approve -> push; the revision advances only on engine success
router.post('/revisions/:id/configure-entra', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    if (rev.state !== 'plan_approved') return bad(res, 409, 'plan not approved', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; Configure Entra needs an approved plan.`, { current: rev });
    const profile = profileOf(rev);
    if (!profile.entraWrites) return bad(res, 409, 'not automated for this sign-on method', (profile.stages.find((s) => s.key === 'configure_entra') || {}).why || 'Nothing is written to Entra for this protocol.');
    const cfg = rev.config || {};
    const createNew = rev.createNew === true; // stateflow-5: server-owned flag
    let engineCreates = createNew && !rev.entraId;
    if (await S.newerDraftExists(rev)) return bad(res, 409, 'a newer draft exists', `A newer draft than revision ${rev.revisionNo} is open; configure Entra from the newest revision.`, { current: rev }); // stateflow-4
    let dest = await S.destinationFor(rev.oktaId);
    if (engineCreates) {
      if (dest.state !== 'none') return bad(res, 409, 'a destination is still recorded', `This revision creates a new Entra app but ${dest.name || dest.entraId} is ${dest.state}; clear or resolve it first.`, { destination: dest });
    } else {
      if (tombstoneBlock(res, dest)) return;
      if (!rev.entraId) return bad(res, 409, 'no Entra destination bound', `Revision ${rev.revisionNo} names no Entra application; confirm a destination and plan again.`, { current: rev }); // stateflow-5
      if (dest.state !== 'confirmed') return bad(res, 409, 'destination not confirmed', `The destination is ${dest.state}; confirm it before writing to Entra.`, { destination: dest });
      if (dest.entraId !== rev.entraId) return bad(res, 409, 'destination changed since the plan', `The plan targets ${rev.entraId} but the confirmed destination is now ${dest.entraId}; draft a new revision.`, { destination: dest });
    }
    const hashNow = M.planFor(rev.protocol, { entraId: createNew ? null : rev.entraId, config: cfg, createNew, displayName: cfg.displayName }).hash;
    if (!rev.planApprovedHash || hashNow !== rev.planApprovedHash || rev.planHash !== rev.planApprovedHash) return bad(res, 409, 'Plan changed since approval', 'The plan no longer matches the approved hash; approve it again before configuring Entra.', { current: rev });
    const Xm = X();
    if (!hook(Xm, 'preflight') || !hook(Xm, 'approve') || !hook(Xm, 'push')) return notAvailable(res, 'oem-migrate-exec preflight/approve/push');
    /* authz-5: a revision that already started an engine write is not written twice; only a terminal failure lets it run again. */
    if (rev.migrationId) {
      const getM = hook(Xm, 'getMigration');
      if (!getM) return bad(res, 409, 'an Entra write is already in flight', `Migration ${rev.migrationId} was started for revision ${rev.revisionNo} and its status cannot be read in this build; nothing is written twice.`, { migrationId: rev.migrationId, engineStatus: null });
      const prev = await getM(rev.migrationId, { events: false });
      const st = prev ? String(prev.status || '') : '';
      if (!prev || !ENGINE_FAILED.has(st)) return bad(res, 409, 'an Entra write is already in flight', `Migration ${rev.migrationId} is ${st || 'of unknown status'}; a second write would create duplicate Entra objects.${ENGINE_OK.has(st) ? ' It succeeded: the revision advances when the created app is bound (see the activity record).' : ' Reload its status before continuing.'}`, { migrationId: rev.migrationId, engineStatus: st || null });
      // Recover only the exact application recorded by this revision's failed create.
      // Binding lets the existing managed-shell path preflight an update, never another create.
      const objects = Array.isArray(prev.createdObjects) ? prev.createdObjects : [];
      if (engineCreates && st !== 'rolled_back' && (createdSpId(prev) || prev.entraAppObjectId || objects.length)) {
        const spId = createdSpId(prev);
        const ownedSp = objects.find((o) => o.type === 'servicePrincipal' && String(o.id).toLowerCase() === spId);
        if (st !== 'failed' || prev.oktaId !== rev.oktaId || (prev.plan || {}).mode !== 'create' || !ownedSp ||
            !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(spId || '')) {
          return bad(res, 409, 'partial Entra creation needs review', 'The previous run recorded Entra objects but their ownership cannot be confirmed. Review its migration record before continuing; no second application was created.', { migrationId: rev.migrationId });
        }
        const bound = await bindCreatedApp(rev, prev, actorOf(req), { resume: true });
        /* resume-2: the recorded service principal is gone from Entra. No second create and no automatic rollback from here: the
           person rolls back staging run #prev.id (the engine records a 404 on delete as already gone), then runs Configure Entra
           again, which takes the fresh create path. The migration record is not touched by this route. */
        if (!bound.ok && bound.gone) return bad(res, 409, 'the application created by the previous attempt no longer exists', `Staging run #${prev.id} created service principal ${bound.entraId} for revision ${rev.revisionNo}, but Entra no longer has it: it was removed outside CorpIT. Roll back staging run #${prev.id} (it removes whatever of that run still exists in Entra and records the rest as already gone), then run Configure Entra again. No second application was created.`, { migrationId: prev.id, action: 'rollback', entraId: bound.entraId });
        if (!bound.ok) return bad(res, 409, 'could not resume the created application', bound.why, { migrationId: rev.migrationId });
        rev.entraId = bound.entraId;
        dest = await S.destinationFor(rev.oktaId);
        if (dest.state !== 'confirmed' || dest.entraId !== rev.entraId) return bad(res, 409, 'destination changed during recovery', 'Reload and review the destination before continuing.');
        engineCreates = false;
        await S.addEvent(rev.oktaId, 'entra_configure_resumed', { actor: actorOf(req), note: 'Resuming setup of the application created by the previous attempt', evidence: { revisionId: rev.id, migrationId: prev.id, entraId: rev.entraId } });
      }
    }
    const actor = actorOf(req);
    const inputs = engineInputsFor(rev, actor);
    if (cfg.samlEndpointUpdate === true) {
      const why = Saml.validateVendorValues(cfg);
      if (engineCreates || rev.protocol !== 'saml2' || why) return bad(res, 409, 'invalid vendor update', why || 'Vendor values must update the prepared SAML application.');
      const handoff = await Saml.readHandoff({ revision: rev, destination: dest, tenantId: process.env.ENTRA_TENANT_ID, graphGet: L.graphGet });
      if (!handoff.available || handoff.values.certificateThumbprint !== cfg.samlHandoffThumbprint) return bad(res, 409, 'signing certificate changed', handoff.why || 'Reload Vendor setup and copy the current certificate before applying the vendor values.');
    }
    const mig = await Xm.preflight(rev.oktaId, actor, { inputs, targetMode: engineCreates ? 'create' : 'adopt', log: (m) => console.log('[oem-v2] preflight', rev.oktaId, redactText(m)) }); // secrets-6
    /* secrets-5: a 4xx carries the migration id and the check list only, never the engine record (snapshot, raw, inputs). */
    if (!mig || (mig.error && mig.id === undefined)) return bad(res, mig && Number.isInteger(mig.status) ? mig.status : 409, (mig && mig.error) || 'pre-flight failed', 'The migration engine refused the pre-flight; nothing was written.', { migrationId: mig && mig.id !== undefined ? mig.id : null, checks: L.redact((mig && mig.preflight && mig.preflight.checks) || []) });
    const pf = mig.preflight || {};
    if (pf.passed === false || (pf.summary && pf.summary.failed > 0)) return bad(res, 409, 'pre-flight failed', 'Fix the failing checks, then run Configure Entra again; nothing was written.', { checks: L.redact(pf.checks || []), migrationId: mig.id });
    /* The engine deliberately performs a fresh live scan. It may write only when that scan is
       byte-for-byte equivalent to the source contract inside the human-approved revision. */
    const approvedSource = cfg._sourceInventory || {};
    const currentModel = mig.snapshot && mig.snapshot.model;
    const mm = Mg();
    const currentFingerprint = currentModel && (hook(mm, 'migrationSourceFingerprint') ? mm.migrationSourceFingerprint(currentModel) : currentModel.sourceFingerprint);
    if (!approvedSource.contractFingerprint || !currentFingerprint || approvedSource.contractFingerprint !== currentFingerprint) {
      return bad(res, 409, 'Okta source changed after plan approval', 'The live pre-flight found different claims, assignments, group membership or provisioning settings. Nothing was written. Create a fresh draft, review the changed source contract and approve the new plan.', { migrationId: mig.id, approvedFingerprint: approvedSource.contractFingerprint || null, currentFingerprint: currentFingerprint || null, checks: L.redact(pf.checks || []) });
    }
    /* stateflow-3: the engine plans from its own assessment; it must target what this revision was approved against. */
    const target = engineTarget(mig);
    if (target.mode === 'create' && !engineCreates) return bad(res, 409, 'engine target differs from the plan', `The engine would create a new Entra application, but revision ${rev.revisionNo} updates ${dest.name || rev.entraId}; refresh the match and plan again.`, { migrationId: mig.id, engineTarget: target, checks: L.redact(pf.checks || []) });
    if (target.mode === 'adopt' && engineCreates) return bad(res, 409, 'engine target differs from the plan', `The engine would update ${target.entraName || target.entraId || 'an existing Entra application'}, but revision ${rev.revisionNo} has no staged shell and creates a new one; clear the stale match and plan again.`, { migrationId: mig.id, engineTarget: target, checks: L.redact(pf.checks || []) });
    if (!engineCreates && target.entraId && target.entraId !== rev.entraId && target.entraId !== String(dest.appId || '').toLowerCase()) return bad(res, 409, 'engine target differs from the plan', `The engine would update ${target.entraName || target.entraId}, but revision ${rev.revisionNo} targets ${dest.name || rev.entraId}; refresh the match and plan again.`, { migrationId: mig.id, engineTarget: target, checks: L.redact(pf.checks || []) });
    const ack = (pf.checks || []).filter((c) => c && c.status === 'warn').map((c) => c.key);
    const ap = await Xm.approve(mig.id, actor, { confirm: (mig.plan && mig.plan.displayName) || cfg.displayName, reason: 'v2 revision ' + rev.id, acknowledge: ack });
    if (ap && ap.error) return bad(res, Number.isInteger(ap.status) ? ap.status : 409, ap.error, 'The engine did not accept the approval; nothing was written.', { migrationId: mig.id });
    const pu = await Xm.push(mig.id, actor);
    if (pu && pu.error) return bad(res, Number.isInteger(pu.status) ? pu.status : 409, pu.error, 'The engine did not start the Entra write.', { migrationId: mig.id, conflict: pu.conflict });
    await S.setRevisionFields(rev.id, { migrationId: mig.id });
    await S.addEvent(rev.oktaId, 'entra_configure_started', { actor, note: `Configure Entra started (migration ${mig.id})`, evidence: { revisionId: rev.id, migrationId: mig.id, jobId: pu && pu.jobId, acknowledged: ack } }); // resume-4: the warn checks this route waved through
    await audit(req, 'oem_v2_configure_entra', { oktaId: rev.oktaId, revisionId: rev.id, migrationId: mig.id });
    /* The engine runs the write as its own job; this poll job watches it and advances the revision on success only. */
    const poll = await L.startJob('v2-configure-poll:' + rev.id, actor, async (log) => {
      const get = hook(Xm, 'getMigration');
      if (!get) { // authz-5: the write started; with no way to read the engine its status is unknown, never "failed"
        await S.addEvent(rev.oktaId, 'entra_configure_status_unknown', { actor, note: `Configure Entra started (migration ${mig.id}) but the engine status cannot be read in this build; the revision stays at Plan approved until a person checks the migration`, evidence: { revisionId: rev.id, migrationId: mig.id } });
        log('engine status unavailable; the Entra write may still be running', 'warn');
        return { status: 'unknown', migrationId: mig.id };
      }
      for (let i = 0; i < 200; i++) {
        const m = await get(mig.id, { events: false });
        const st = m ? String(m.status || '') : '';
        if (ENGINE_OK.has(st)) {
          if (engineCreates) { const bound = await bindCreatedApp(rev, m, actor); if (!bound.ok) { log('Entra write ' + st + ' but ' + bound.why, 'error'); return { status: st, migrationId: mig.id, bound: false }; } log('created Entra app ' + bound.entraId + ' bound as the destination'); } // stateflow-6
          await afterEntraConfigured(rev, actor, { migrationId: mig.id, engineStatus: st }); log('Entra configured: ' + st); return { status: st, migrationId: mig.id };
        }
        if (ENGINE_END.has(st)) {
          /* resume-3: the failed step and the engine's error (redacted, 300 chars) ride on the event, so history shows WHY without
             opening the migration record (2026-09-21: assign_users hit a 404 on a fresh service principal). */
          const steps = m && m.results && Array.isArray(m.results.steps) ? m.results.steps : [];
          const failedStep = steps.filter((s) => s && s.status === 'failed').pop() || null;
          const reason = (m && m.error) || (failedStep && failedStep.detail) || null;
          const evidence = { revisionId: rev.id, migrationId: mig.id, engineStatus: st };
          if (failedStep && failedStep.key) evidence.failedStep = String(failedStep.key);
          if (reason) evidence.error = redactText(reason).slice(0, 300); // secrets-6
          await S.addEvent(rev.oktaId, 'entra_configure_failed', { actor, note: `Configure Entra did not succeed (${st}${evidence.failedStep ? ' at ' + evidence.failedStep : ''}); the revision stays at Plan approved`, evidence });
          log('Entra configure ended: ' + st + (evidence.failedStep ? ' at ' + evidence.failedStep : '') + (evidence.error ? ': ' + evidence.error : ''), 'error');
          return { status: st, migrationId: mig.id, failedStep: evidence.failedStep || null };
        }
        await L.sleep(3000);
      }
      await S.addEvent(rev.oktaId, 'entra_configure_timeout', { actor, note: `Configure Entra (migration ${mig.id}) reported no end state in time; the revision stays at Plan approved until a person checks the migration`, evidence: { revisionId: rev.id, migrationId: mig.id } }); // authz-5
      log('gave up waiting for the migration engine', 'warn');
      return { status: 'timeout', migrationId: mig.id };
    });
    res.status(202).json({ ok: true, migrationId: mig.id, jobId: pu && pu.jobId ? pu.jobId : null, pollJobId: poll && poll.id ? poll.id : null, state: 'plan_approved', note: 'The Entra write is running; the revision advances when the engine reports success.' });
  } catch (e) { fail(res, e, 'configure entra'); }
});

// POST /revisions/:id/vendor-ready {note} — the owner's claim; never verification
router.post('/revisions/:id/vendor-ready', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    if (!['entra_configured', 'awaiting_vendor'].includes(rev.state)) return bad(res, 409, 'not waiting for the vendor', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}.`, { current: rev });
    if (await S.newerDraftExists(rev)) return bad(res, 409, 'a newer draft exists', `A newer draft than revision ${rev.revisionNo} is open; the vendor claim belongs to the newest revision.`, { current: rev }); // stateflow-4
    const dest = await S.destinationFor(rev.oktaId);
    if (tombstoneBlock(res, dest)) return;
    const actor = actorOf(req);
    const note = req.body && req.body.note ? String(req.body.note).slice(0, 500) : null;
    if (note && typeof M.assertNoSecretText === 'function') M.assertNoSecretText(note, 'vendor-ready note'); // secrets-4: transition() does not scan free text
    const fields = Object.assign({ vendorReadyBy: actor, vendorReadyAt: 'NOW()', vendorReadyNote: note }, await vendorTemplateStamp(rev)); // stateflow-9
    const out = await S.transition(rev.id, ['entra_configured', 'awaiting_vendor'], 'awaiting_verification', fields, { actor, note: `Vendor setup marked ready for test by ${actor} — not verified`, evidence: { claim: true } });
    await audit(req, 'oem_v2_vendor_ready', { oktaId: rev.oktaId, revisionId: rev.id });
    res.json({ ok: true, revision: out, note: 'Recorded as a claim by the owner. Test and verify decides.' });
  } catch (e) { fail(res, e, 'vendor ready'); }
});

// GET /revisions/:id/vendor-instructions
router.get('/revisions/:id/vendor-instructions', read(), async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    const { instructions, values } = await vendorInstructionsFor(rev); // stateflow-9: a GET reads; the template stamp is written by vendor-ready / the entra_configured transition
    const samlHandoff = rev.protocol === 'saml2' ? await Saml.readHandoff({ revision: rev, destination: await S.destinationFor(rev.oktaId), tenantId: process.env.ENTRA_TENANT_ID, graphGet: L.graphGet }) : null;
    res.json({ revision: { id: rev.id, revisionNo: rev.revisionNo, state: rev.state, protocol: rev.protocol, entraId: rev.entraId, vendor: rev.vendor || null }, instructions: M.stripSecrets(instructions), values, samlHandoff });
  } catch (e) { fail(res, e, 'vendor instructions'); }
});

/* ------------------------------------------------------------- verify */

const NAME_TO_KEY = [[/exists/i, 'entra_exists'], [/enabled/i, 'entra_enabled'], [/sso mode/i, 'sso_mode'], [/reply url|redirect/i, 'reply_or_redirect'], [/identifier|entity id|client id/i, 'identifier'], [/assignments?/i, 'assignments'], [/provisioning/i, 'provisioning'], [/sign-?ins/i, 'signins_via_entra'], [/okta app status|okta status/i, 'okta_status']];
const keyOfName = (name) => { for (const [re, k] of NAME_TO_KEY) if (re.test(String(name || ''))) return k; return null; };
const mapResult = (r) => { const s = String(r || '').toLowerCase(); return s === 'pass' || s === 'info' ? 'pass' : s === 'fail' ? 'fail' : s === 'not_applicable' ? 'not_applicable' : 'inconclusive'; };
async function runChecks(rev, dest, identity, wi) {
  const facts = Object.assign({}, (wi && wi.facts) || {});
  facts.okta = Object.assign({ id: rev.oktaId, label: identity.label, name: identity.name, status: identity.status, signOnMode: identity.signOnMode, provisioning: identity.provisioning, identifiers: { acs: identity.acsUrls, audience: identity.audience ? [identity.audience] : [], redirects: identity.redirectUris } }, facts.okta || {});
  facts.match = { decision: 'manual_confirmed', entraId: dest.entraId, entraName: dest.name }; // the v2 destination is authoritative
  const item = Object.assign({ item_key: 'app:' + rev.oktaId, source_id: rev.oktaId, title: identity.label, state: wi ? wi.state : 'ready', source_status: identity.status }, wi || {}, { facts });
  const adopt = rev.adopt === true;
  const defs = M.verificationChecks(rev.protocol, { provisioning: !!(facts.okta && facts.okta.provisioning), adopt });
  const raw = new Map();
  const Wm = W();
  const run = hook(Wm, 'runValidationChecks');
  if (run) {
    const list = await run(item, { protocol: rev.protocol, v2: true });
    for (const c of list || []) { const k = keyOfName(c.name || c.key); if (k && !raw.has(k)) raw.set(k, { result: mapResult(c.result), detail: c.detail || null, data: c.data && typeof c.data === 'object' ? c.data : undefined }); }
  }
  const approvedProvisioning = rev.config && rev.config._sourceInventory && rev.config._sourceInventory.provisioning;
  const currentProvisioning = raw.get('provisioning');
  if (approvedProvisioning && approvedProvisioning.enabled && approvedProvisioning.fingerprint) {
    const currentFingerprint = currentProvisioning && currentProvisioning.data && currentProvisioning.data.sourceFingerprint;
    if (!currentFingerprint) raw.set('provisioning', { result: 'inconclusive', detail: 'The current Okta provisioning contract fingerprint could not be read; rescan before verification.' });
    else if (currentFingerprint !== approvedProvisioning.fingerprint) raw.set('provisioning', { result: 'fail', detail: 'Okta provisioning mappings, schema, Group Push configuration or lifecycle features changed after plan approval. Rescan and approve a new plan.', data: currentProvisioning.data });
  }
  const needsSp = defs.some((d) => d.applies && (d.key === 'linked_url' || d.key === 'password_mode')) || (!run && dest.entraId) || adopt;
  if (needsSp && dest.entraId) {
    const g = await L.graphGet(`/v1.0/servicePrincipals/${encodeURIComponent(dest.entraId)}?$select=id,accountEnabled,preferredSingleSignOnMode,homepage,loginUrl,appRoleAssignmentRequired,displayName`);
    if (g.status === 200 && g.body) {
      const sp = g.body;
      if (!raw.has('entra_exists')) raw.set('entra_exists', { result: 'pass', detail: `${sp.displayName || dest.entraId} exists in Entra.` });
      if (!raw.has('entra_enabled')) raw.set('entra_enabled', { result: sp.accountEnabled ? 'pass' : 'fail', detail: sp.accountEnabled ? 'accountEnabled is true.' : 'accountEnabled is false.' });
      const url = sp.loginUrl || sp.homepage || null;
      const want = adopt ? ((rev.adopted && rev.adopted.loginUrl) || null) : ((rev.config && rev.config.url) || identity.loginUrl || null); // f15: adopted as-is — the snapshot is the reference, not the Okta bookmark
      raw.set('linked_url', { result: url ? (want ? (L.normUrl(url) === L.normUrl(want) ? 'pass' : 'fail') : 'inconclusive') : 'fail', detail: url ? `Entra launches ${url}${want ? (L.normUrl(url) === L.normUrl(want) ? (adopt ? ', as adopted.' : ', the same destination as Okta.') : (adopt ? '; ' + want + ' was adopted. Re-read Entra and adopt again to record the new destination, or plan changes.' : ', Okta launches ' + want + '.')) : (adopt ? '; the adopted snapshot recorded no destination.' : '; no Okta destination to compare.')}` : 'The Entra application has no destination URL.' });
      raw.set('password_mode', { result: sp.preferredSingleSignOnMode === 'password' ? 'pass' : 'fail', detail: `preferredSingleSignOnMode is ${sp.preferredSingleSignOnMode || 'not set'}.` });
      if (!raw.has('sso_mode')) raw.set('sso_mode', { result: sp.preferredSingleSignOnMode ? 'pass' : 'inconclusive', detail: `preferredSingleSignOnMode is ${sp.preferredSingleSignOnMode || 'not set'}.` });
      /* f14: an adopted revision is verified against what was adopted — the mode must still be the one recorded.
         f15: assignments are read live when the validation module did not supply them; the mirror is never the reference. */
      if (adopt) {
        const a = rev.adopted || {};
        const same = !a.ssoMode || String(sp.preferredSingleSignOnMode || '').toLowerCase() === String(a.ssoMode).toLowerCase();
        raw.set('sso_mode', { result: sp.preferredSingleSignOnMode ? (same ? 'pass' : 'fail') : 'fail', detail: sp.preferredSingleSignOnMode ? (same ? `preferredSingleSignOnMode is ${sp.preferredSingleSignOnMode}, as adopted.` : `preferredSingleSignOnMode is now ${sp.preferredSingleSignOnMode}; ${a.ssoMode} was adopted. Re-read Entra and adopt again to record the new mode, or plan changes.`) : 'preferredSingleSignOnMode is no longer set.' });
        if (!raw.has('assignments')) {
          const la = await liveAssignments(dest.entraId);
          raw.set('assignments', { result: la.ok ? (la.total > 0 ? 'pass' : 'fail') : 'inconclusive', detail: la.ok ? `${la.users} user${la.users === 1 ? '' : 's'} and ${la.groups} group${la.groups === 1 ? '' : 's'} assigned in Entra${la.truncated ? ' (first page)' : ''}.` : 'Could not read the Entra assignments: ' + (la.error || ('HTTP ' + la.status)) });
        }
      }
    } else if (g.status === 404) {
      raw.set('entra_exists', { result: 'fail', detail: 'The Entra service principal no longer exists (HTTP 404).' });
    } else {
      raw.set('entra_exists', { result: 'inconclusive', detail: 'Graph read failed: ' + (g.error || ('HTTP ' + g.status)) });
    }
  }
  const checks = defs.map((d) => {
    if (!d.applies) return { key: d.key, label: d.label, applies: false, result: 'not_applicable', detail: null };
    const r = raw.get(d.key);
    const out = { key: d.key, label: d.label, applies: true, result: r ? r.result : 'inconclusive', detail: r ? r.detail : 'Not measured in this run.' };
    if (r && r.data) out.data = r.data; // live evidence stays with the immutable attempt
    return out;
  });
  return checks;
}
// POST /revisions/:id/verify — one immutable attempt; pass -> awaiting_live_approval
router.post('/revisions/:id/verify', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    const profile = profileOf(rev);
    const vendorNa = !(profile.stages.find((s) => s.key === 'vendor_setup') || {}).applicable;
    const from = ['awaiting_verification', 'awaiting_live_approval'].concat(vendorNa ? ['entra_configured'] : []);
    if (!from.includes(rev.state)) return bad(res, 409, 'not ready to verify', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; verification runs after Entra is configured${vendorNa ? '' : ' and the vendor is marked ready'}.`, { current: rev });
    if (!(profile.stages.find((s) => s.key === 'verify') || {}).applicable) return bad(res, 409, 'nothing to verify', (profile.stages.find((s) => s.key === 'verify') || {}).why || 'Not verifiable from this page.');
    const dest = await S.destinationFor(rev.oktaId);
    if (tombstoneBlock(res, dest)) return;
    if (!rev.createNew && !rev.entraId) return bad(res, 409, 'no Entra destination bound', `Revision ${rev.revisionNo} names no Entra application; confirm a destination and plan again.`, { current: rev }); // stateflow-5
    if (dest.state !== 'confirmed') return bad(res, 409, 'destination not confirmed', `The destination is ${dest.state}; confirm it before verifying.`, { destination: dest });
    if (rev.entraId && dest.entraId !== rev.entraId) return bad(res, 409, 'destination changed since the plan', `The plan targets ${rev.entraId} but the confirmed destination is now ${dest.entraId}; draft a new revision.`, { destination: dest, current: rev }); // authz-1 / stateflow-2
    const okta = await S.oktaApp(rev.oktaId);
    const wi = await S.workItem(rev.oktaId);
    const identity = identityOf(rev.oktaId, okta, wi);
    res.json(Object.assign({ ok: true }, await runAttempt(req, rev, dest, identity, wi)));
  } catch (e) { fail(res, e, 'verify'); }
});
/* One immutable verification attempt against a revision (shared by POST /revisions/:id/verify and the adopt route). */
async function runAttempt(req, rev, dest, identity, wi) {
  const actor = actorOf(req);
  const attemptId = await S.createAttempt({ revisionId: rev.id, oktaId: rev.oktaId, actor, planHash: rev.planApprovedHash || rev.planHash });
  let checks;
  try { checks = await runChecks(rev, dest, identity, wi); }
  catch (e) { checks = M.verificationChecks(rev.protocol, { adopt: rev.adopt === true }).map((d) => ({ key: d.key, label: d.label, applies: d.applies, result: d.applies ? 'inconclusive' : 'not_applicable', detail: d.applies ? 'Check did not run: ' + redactText(e && e.message || e).slice(0, 160) : null })); }
  const status = M.verdict(checks);
  const summary = summaryOf(checks);
  const attempt = await S.finishAttempt(attemptId, { status, checks, summary });
  let revision = rev;
  /* authz-4 (DESIGN section 3): a fail/inconclusive attempt leaves the revision where it is — awaiting_live_approval stays, and the
     attempt_pass predicate blocks Live until a later attempt passes. Only a pass moves the revision forward. */
  // every attempt is its own work event (verification_<status>: what the audit echo oem_v2_verify folds on — authz-3); a pass also moves the revision
  await S.addEvent(rev.oktaId, 'verification_' + status, { actor, note: `Verification attempt ${attemptId} ${status}`, evidence: { attemptId, revisionId: rev.id } });
  if (status === 'pass' && rev.state !== 'awaiting_live_approval') revision = await S.transition(rev.id, ['awaiting_verification', 'entra_configured'], 'awaiting_live_approval', {}, { actor, note: `Verification attempt ${attemptId} passed`, evidence: { attemptId } });
  await audit(req, 'oem_v2_verify', { oktaId: rev.oktaId, revisionId: rev.id, attemptId, status });
  return { attempt, verification: { attemptId, status, startedAt: attempt.startedAt, finishedAt: attempt.finishedAt, actor, checks: checkList(attempt), summary, signIns: signInEvidence(attempt, actor) }, revision };
}

/* -------------------------------------------------------------- adopt (f14) */
const SSO_MODE_LABEL = { saml: 'SAML', oidc: 'OpenID Connect', password: 'Password-based', linked: 'Linked (bookmark)', notsupported: 'Not supported' };
const ADOPT_SELECT = '$select=id,appId,displayName,accountEnabled,preferredSingleSignOnMode,appRoleAssignmentRequired,loginUrl,homepage,replyUrls,servicePrincipalNames';
/* f15: live assignment counts (users and groups) — one page of appRoleAssignedTo; a second page is reported as truncated. */
async function liveAssignments(entraId) {
  const g = await L.graphGet(`/v1.0/servicePrincipals/${encodeURIComponent(entraId)}/appRoleAssignedTo?$top=999`);
  if (g.status !== 200 || !g.body) return { ok: false, status: g.status, error: g.error ? redactText(String(g.error)) : null, users: null, groups: null, total: null, truncated: false };
  const v = Array.isArray(g.body.value) ? g.body.value : [];
  const users = v.filter((a) => String(a.principalType || '').toLowerCase() === 'user').length;
  const groups = v.filter((a) => String(a.principalType || '').toLowerCase() === 'group').length;
  return { ok: true, status: 200, error: null, users, groups, total: v.length, truncated: !!(g.body['@odata.nextLink'] || g.next) };
}
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/* POST /apps/:oktaId/adopt {acknowledge?} — the confirmed Entra destination is already configured and in use: record a
   revision that keeps it exactly as it is (nothing is written to Entra, nothing is asked of the vendor), auto-approve its
   one-step plan, and run the real verification straight away. The tail is unchanged — the owner's attestation, Sign off as
   Live and Retire Okta stay separate steps with their own guards (SPEC 91). The decision is taken on live Graph reads (the
   service principal and its assignments), never on the mirror alone.
   f15: what the caller must acknowledge is enforced here, not by the button — replacing an open draft (its id is echoed
   back), and a SAML application whose Entra reply URL / identifier differ from what Okta used (the caller's reason is
   recorded with the snapshot — drop 8: any reason, no invented length). A previous adopted revision that is not Live is replaced by a fresh one
   (adoption that stopped part-way resumes this way; a drifted one is re-read). */
router.post('/apps/:oktaId/adopt', json, admin(), mutating, async (req, res) => {
  try {
    const id = oktaIdParam(req, res); if (!id) return;
    const okta = await S.oktaApp(id);
    const wi = await S.workItem(id);
    if (!okta && !wi) return bad(res, 404, 'unknown Okta app', 'No Okta application with id ' + id + ' is in the mirror.');
    const identity = identityOf(id, okta, wi);
    /* f15: the page's disabled CTA is not the guard — an inactive or not-migrating application is refused here too */
    if (String(identity.status || '').toUpperCase() === 'INACTIVE') return bad(res, 409, 'nothing to migrate', 'The application is inactive in Okta; nobody signs in through it, so there is nothing to adopt.');
    if (identity.disposition === 'retire' || identity.disposition === 'exclude') return bad(res, 409, 'not migrating', `The application is marked "${identity.disposition}"; change its disposition before adopting an Entra configuration.`);
    const dest = await S.destinationFor(id);
    if (tombstoneBlock(res, dest)) return;
    if (dest.state !== 'confirmed' || !dest.entraId) return bad(res, 409, 'destination not confirmed', dest.state === 'none' ? 'Confirm the Entra destination first; adoption keeps an application that already exists.' : `The destination is ${dest.state}; confirm it first.`, { destination: dest });
    const current = await S.latestRevision(id);
    const cur = current && current.state !== 'live' ? current : null;
    const curAdopted = !!(cur && cur.adopt === true);
    if (cur && !(cur.state === 'draft' || curAdopted)) return bad(res, 409, 'a revision is already in progress', `Revision ${cur.revisionNo} is ${M.STATE_LABEL[cur.state] || cur.state}; adoption starts from a confirmed match with no revision under way.`, { current: cur });
    const mirror = M.adoptable(dest);
    const g = await L.graphGet(`/v1.0/servicePrincipals/${encodeURIComponent(dest.entraId)}?${ADOPT_SELECT}`);
    if (g.status === 404) return bad(res, 409, 'the Entra application was not found', 'Graph returned 404 for the confirmed destination; it may have been deleted. Refresh Entra applications and resolve the destination.', { destination: { entraId: dest.entraId, name: dest.name } });
    if (g.status !== 200 || !g.body) return bad(res, 502, 'could not read the Entra application', 'Graph did not answer; nothing was recorded. Try again.', { status: g.status, detail: g.error ? redactText(String(g.error)) : null });
    const sp = g.body;
    const la = await liveAssignments(dest.entraId);
    if (!la.ok) return bad(res, 502, 'could not read the Entra assignments', 'Graph did not answer for the assignments; nothing was recorded. Try again.', { status: la.status, detail: la.error });
    const live = { state: 'confirmed', entraId: dest.entraId, name: sp.displayName || dest.name, enabled: sp.accountEnabled === true, ssoMode: sp.preferredSingleSignOnMode || null, users: la.users, groups: la.groups, tombstone: null };
    const ad = M.adoptable(live);
    if (!ad.ok) return bad(res, 409, 'not configured in Entra', ad.why + ' Use Review plan to configure it.', { destination: live, mirror: mirror.ok ? null : mirror.why });
    const mode = String(sp.preferredSingleSignOnMode).toLowerCase();
    /* what the caller must acknowledge */
    const ack = req.body && req.body.acknowledge && typeof req.body.acknowledge === 'object' ? req.body.acknowledge : {};
    const needs = [];
    if (cur && cur.state === 'draft' && !curAdopted) needs.push({ key: 'replace_draft', revisionId: cur.id, revisionNo: cur.revisionNo, text: `Draft revision ${cur.revisionNo} is replaced by the adopted revision; its edits stay in history only.`, ok: Number(ack.replace_draft) === cur.id });
    /* the Okta application federates (SAML / OIDC / WS-Fed) but the Entra application only launches a link or stores a
       password: if the vendor still trusts Okta, retiring Okta locks its users out — the caller says the vendor has moved.
       A federation protocol that changed (SAML -> OIDC) is acknowledged the same way. */
    const FED = ['saml2', 'oidc', 'ws_fed'];
    if (FED.includes(identity.protocol) && ad.protocol !== identity.protocol) {
      const downgrade = !FED.includes(ad.protocol);
      needs.push({ key: 'protocol_differs', okta: identity.protocol, entra: ad.protocol, text: downgrade
        ? `Okta signs users in with ${M.PROTOCOL_LABEL[identity.protocol] || identity.protocol}, but the Entra application only ${ad.protocol === 'bookmark' ? 'launches a link' : 'stores a password'}. If the vendor still trusts Okta for sign-in, retiring Okta will lock its users out. Adopt only if the vendor has already been moved off Okta.`
        : `Okta signs users in with ${M.PROTOCOL_LABEL[identity.protocol] || identity.protocol}; the Entra application uses ${M.PROTOCOL_LABEL[ad.protocol] || ad.protocol}. Adopt only if the vendor was already switched to it.`, ok: ack.protocol_differs === true });
    }
    /* same federation protocol on both sides: the endpoints must be comparable — a SAML reply URL / identifier or an OIDC
       redirect that Okta used and Entra does not answer for is a different vendor instance until the caller says otherwise */
    if (ad.protocol === identity.protocol && (ad.protocol === 'saml2' || ad.protocol === 'oidc')) {
      const rep = new Set((sp.replyUrls || []).map(L.normUrl)), spn = new Set((sp.servicePrincipalNames || []).map(L.normUrl));
      const acs = ad.protocol === 'saml2' ? (identity.acsUrls || []).filter(Boolean) : [], aud = ad.protocol === 'saml2' && identity.audience ? [identity.audience] : [], red = ad.protocol === 'oidc' ? (identity.redirectUris || []).filter(Boolean) : [];
      const acsOk = !acs.length || !rep.size ? null : acs.some((x) => rep.has(L.normUrl(x)));
      const audOk = !aud.length || !spn.size ? null : aud.some((x) => spn.has(L.normUrl(x)));
      const redOk = !red.length || !rep.size ? null : red.some((x) => rep.has(L.normUrl(x)));
      if (acsOk === false || audOk === false || redOk === false) {
        const reason = String((ack.endpoints_differ && ack.endpoints_differ.reason) || '').trim();
        needs.push({ key: 'endpoints_differ', text: 'The Entra application answers for different endpoints than the Okta application did. Adopt it only if it serves the same vendor instance — say why (for example, the vendor uses a separate callback per identity provider).',
          okta: ad.protocol === 'saml2' ? { acs, audience: aud } : { redirectUris: red }, entra: { replyUrls: sp.replyUrls || [], identifiers: (sp.servicePrincipalNames || []).filter((x) => !GUID_RE.test(x)) }, needsReason: true, ok: reason.length > 0, reason: reason ? reason.slice(0, 500) : null });
      }
    }
    const missing = needs.filter((n) => !n.ok);
    if (missing.length) return bad(res, 409, 'adoption needs your acknowledgement', 'Confirm the points below, then adopt again; nothing has been recorded.', { code: 'needs_acknowledgement', needs: missing.map((n) => { const c = Object.assign({}, n); delete c.ok; delete c.reason; return c; }) });
    const actor = actorOf(req);
    const acknowledged = needs.map((n) => n.key === 'endpoints_differ' ? { key: n.key, reason: n.reason, by: actor, okta: n.okta, entra: n.entra } : n.key === 'protocol_differs' ? { key: n.key, okta: n.okta, entra: n.entra, by: actor } : { key: n.key, revisionId: n.revisionId, revisionNo: n.revisionNo, by: actor });
    const adopted = { entraId: dest.entraId, appId: sp.appId || dest.appId || null, displayName: sp.displayName || dest.name || null, ssoMode: mode, ssoModeLabel: SSO_MODE_LABEL[mode] || sp.preferredSingleSignOnMode, accountEnabled: sp.accountEnabled === true, assignmentRequired: sp.appRoleAssignmentRequired === true, loginUrl: sp.loginUrl || sp.homepage || null,
      replyUrls: (sp.replyUrls || []).slice(0, 20), identifiers: (sp.servicePrincipalNames || []).filter((x) => !GUID_RE.test(x)).slice(0, 20),
      users: la.users, groups: la.groups, assignmentsTruncated: la.truncated, mirrorUsers: dest.users === undefined ? null : dest.users, mirrorGroups: dest.groups === undefined ? null : dest.groups, readAt: new Date().toISOString(), acknowledged };
    const name = adopted.displayName || dest.entraId;
    let rev = await S.createDraft(id, { protocol: ad.protocol, config: { displayName: name }, adopt: true, adopted, replaces: cur ? cur.id : null, entraId: dest.entraId, matchId: dest.match ? dest.match.id : null, actor,
      protocolNote: 'adopted from the Entra configuration (' + adopted.ssoModeLabel + ')' + (curAdopted ? ' — replaces adopted revision ' + cur.revisionNo : ''), protocolSource: 'entra', oktaProtocol: identity.protocol });
    rev = (await S.approvePlan(rev.id, { hash: rev.planHash, actor })).revision;
    rev = await S.transition(rev.id, ['plan_approved'], 'entra_configured', { entraConfiguredAt: 'NOW()' }, { actor, note: `Existing Entra configuration adopted as-is (${name}, ${adopted.ssoModeLabel}); nothing was written`, evidence: { adopted } });
    rev = await S.transition(rev.id, ['entra_configured'], 'awaiting_verification', {}, { actor, note: 'No vendor step: the configuration is already in use; verification checks that sign-ins flow through Entra' });
    await audit(req, 'oem_v2_adopt', { oktaId: id, revisionId: rev.id, protocol: ad.protocol, entraId: dest.entraId, ssoMode: mode, users: adopted.users, groups: adopted.groups, replaces: cur ? cur.id : null, acknowledged: acknowledged.map((a) => a.key) });
    /* f15: the adoption is recorded before the attempt runs; an attempt that cannot even be recorded still answers 201 with
       the revision (at awaiting_verification, its CTA runs the verification) rather than a 500 that reads as "not adopted" */
    let out;
    try { out = await runAttempt(req, rev, dest, identity, wi); }
    catch (e) { out = { attempt: null, verification: null, revision: await S.getRevision(rev.id), attemptError: 'The adoption was recorded but the verification attempt could not be: ' + redactText(String(e && e.message || e)).slice(0, 160) }; }
    res.status(201).json(Object.assign({ ok: true, adopted, acknowledged: acknowledged.map((a) => a.key) }, out));
  } catch (e) { fail(res, e, 'adopt'); }
});


/* honesty-9: the owner's attestation — who tested, as whom, when, what loaded — is the record, not a free-text note.
   Stored as one JSON string in owner_confirmed_note (the store exposes it parsed as ownerAttestation); the per-field caps keep
   the JSON inside that column's 500 characters. */
const ATTEST_FIELDS = [['ownerEmail', 120], ['testedUser', 120], ['testedAt', 40], ['whatLoaded', 500], ['claimsSeen', 500], ['note', 500], ['loaded', 10], ['claims', 10], ['source', 24], ['signInId', 64]]; // owner_confirmed_note is TEXT since sql/011
/* drop 8: nothing the system already knows is asked for. The owner is the signed-in person; the tested user and time come from
   the Entra sign-in log the verification read (source entra_signin_log — the caller's own latest successful sign-in, else the
   latest anyone's) or, when the log holds nothing, from the caller (source reported). The two things no system can read are
   asked as choices: loaded (yes | partial | no) and claims (yes | no | unsure). Free text is optional; a caller may still send
   ownerEmail / testedUser / testedAt / whatLoaded / claimsSeen explicitly (the drop 7 contract) and those win. */
const LOADED_TEXT = { yes: 'The application loaded and worked after sign-in through Entra.', partial: 'The application loaded after sign-in through Entra, but not everything worked.', no: 'The application did not load or did not work after sign-in through Entra.' };
const CLAIMS_TEXT = { yes: 'The role / claims appeared as expected.', no: 'The role / claims did not appear as expected.', unsure: 'Role / claims not checked.' };
function attestationOf(body, ctx) {
  const b = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  const c = ctx || {};
  const has = (k) => b[k] !== undefined && b[k] !== null && String(b[k]).trim() !== '';
  const loaded = has('loaded') ? String(b.loaded).trim().toLowerCase() : null;
  if (loaded && !LOADED_TEXT[loaded]) return { invalid: 'loaded' };
  const claims = has('claims') ? String(b.claims).trim().toLowerCase() : null;
  if (claims && !CLAIMS_TEXT[claims]) return { invalid: 'claims' };
  if (!has('whatLoaded') && !loaded) return { missing: 'loaded' };
  const att = {};
  for (const [k, max] of ATTEST_FIELDS) if (has(k)) att[k] = String(b[k]).trim().slice(0, max);
  const fromLog = c.signIn && c.signIn.at ? c.signIn : null;
  const filledFromLog = !has('testedUser') && !has('testedAt') && !!fromLog;
  if (!att.ownerEmail) att.ownerEmail = c.actor || null;
  if (!att.testedUser) att.testedUser = fromLog ? fromLog.user : (c.actor || null);
  if (!att.testedAt) att.testedAt = fromLog ? fromLog.at : new Date().toISOString();
  if (!att.whatLoaded) att.whatLoaded = LOADED_TEXT[loaded];
  if (!att.claimsSeen && claims) att.claimsSeen = CLAIMS_TEXT[claims];
  if (loaded) att.loaded = loaded;
  if (claims) att.claims = claims;
  att.source = filledFromLog ? 'entra_signin_log' : 'reported';
  if (filledFromLog && fromLog.id) att.signInId = String(fromLog.id).slice(0, 64); else delete att.signInId;
  if (!att.ownerEmail || !att.testedUser) return { missing: !att.ownerEmail ? 'ownerEmail' : 'testedUser' };
  if (Number.isNaN(new Date(att.testedAt).getTime())) return { invalid: 'testedAt' };
  return { att, loaded };
}
// POST /revisions/:id/owner-confirm {loaded, claims?, note?, ownerEmail?, testedUser?, testedAt?, whatLoaded?, claimsSeen?} — after a passing attempt on this revision.
// loaded:'no' records the owner's failed test as an exception (event owner_test_failed, a note is required) and confirms nothing.
router.post('/revisions/:id/owner-confirm', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    if (rev.state !== 'awaiting_live_approval') return bad(res, 409, 'not awaiting Live approval', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; the owner confirms after a passing verification.`, { current: rev });
    const dest = await S.destinationFor(rev.oktaId);
    if (tombstoneBlock(res, dest)) return;
    if (rev.entraId && dest.entraId !== rev.entraId) return bad(res, 409, 'destination changed since the plan', `The plan targets ${rev.entraId} but the confirmed destination is now ${dest.entraId}; draft a new revision.`, { destination: dest, current: rev }); // authz-1 / stateflow-2
    const attempt = await S.latestAttempt(rev.id);
    if (!attempt || attempt.status !== 'pass') return bad(res, 409, 'no passing verification attempt', attempt ? `The latest attempt is ${attempt.status}; run Test and verify again.` : 'Run Test and verify first.', { attempt });
    const actor = actorOf(req);
    const si = signInEvidence(attempt, actor);
    const a = attestationOf(req.body, { actor, signIn: si ? (si.mine || si.latestOk || null) : null });
    if (a.missing) return bad(res, 400, a.missing + ' required', a.missing === 'loaded' ? 'Say whether the application loaded after sign-in through Entra (loaded: yes, partial or no) — the one thing no system can read.' : `The attestation names who owns the app (ownerEmail) and who signed in (testedUser); ${a.missing} could not be filled in.`, { missing: a.missing });
    if (a.invalid) return bad(res, 400, a.invalid + ' is not valid', a.invalid === 'testedAt' ? 'Send testedAt as an ISO timestamp or a datetime-local value.' : a.invalid === 'loaded' ? 'loaded is yes, partial or no.' : 'claims is yes, no or unsure.', { invalid: a.invalid });
    const att = a.att;
    if (typeof M.assertNoSecretText === 'function') for (const [k, v] of Object.entries(att)) M.assertNoSecretText(v, 'owner attestation ' + k); // secrets-4
    if (a.loaded === 'no') {
      /* an exception, not a confirmation: recorded with what the owner saw so the next person can act on it */
      if (!att.note) return bad(res, 400, 'note required', 'A failed test is an exception: say what you saw after signing in, so the next person can act on it.', { missing: 'note' });
      await S.addEvent(rev.oktaId, 'owner_test_failed', { actor, note: `${att.testedUser} signed in through Entra at ${att.testedAt}; the application did not work — ${att.note}`, evidence: { revisionId: rev.id, attemptId: attempt.id, attestation: att } });
      await audit(req, 'oem_v2_owner_test_failed', { oktaId: rev.oktaId, revisionId: rev.id, attemptId: attempt.id, testedUser: att.testedUser });
      return res.json({ ok: true, recorded: 'owner_test_failed', attestation: att, revision: rev });
    }
    /* stateflow-8: the write is conditional on the state read above; a concurrent move answers 409 instead of stamping a superseded row. */
    const out = await S.setRevisionFields(rev.id, { ownerConfirmedBy: actor, ownerConfirmedAt: 'NOW()', ownerConfirmedNote: JSON.stringify(att) }, { whereState: 'awaiting_live_approval' });
    await S.addEvent(rev.oktaId, 'owner_confirmed', { actor, note: `Application owner ${att.ownerEmail} confirmed the test (recorded by ${actor}): ${att.testedUser} at ${att.testedAt}${att.source === 'entra_signin_log' ? ' (from the Entra sign-in log)' : ' (as reported)'} — ${att.whatLoaded}${att.claimsSeen ? ' ' + att.claimsSeen : ''}${att.note ? ' — ' + att.note : ''}`, evidence: { revisionId: rev.id, attemptId: attempt.id, attestation: att } });
    await audit(req, 'oem_v2_owner_confirm', { oktaId: rev.oktaId, revisionId: rev.id, attemptId: attempt.id, ownerEmail: att.ownerEmail });
    res.json({ ok: true, revision: out, ownerAttestation: (out && out.ownerAttestation) || att });
  } catch (e) { fail(res, e, 'owner confirm'); }
});

async function liveContext(req, rev) {
  const dest = await S.destinationFor(rev.oktaId);
  const attempt = await S.attemptFor(rev); // authz-7: the frozen attempt once live/superseded
  const newerDraft = await S.newerDraftExists(rev);
  const perms = req.v2 || await permissions(req);
  const actor = { email: actorOf(req), canSignOff: perms.canSignOff, readOnly: perms.readOnly };
  return { dest, attempt, newerDraft, perms, eligibility: M.liveEligibility({ revision: rev, attempt, destination: dest, actor, newerDraft }) };
}
/* stateflow-12: the work item is set to Verified FIRST; if that write throws, the error propagates (500) and nothing goes Live.
   authz-7: markLive freezes the passing attempt id (and the generations it computes) on the revision. */
async function goLive(req, rev, opts) {
  const o = opts || {};
  const actor = actorOf(req);
  let workItem = null;
  const Wm = W();
  const set = hook(Wm, 'setWorkState');
  const wi = await S.workItem(rev.oktaId);
  if (!set || !wi) throw Object.assign(new Error(!set ? 'the work item cannot be set Verified in this build (no setWorkState hook); nothing goes Live' : `work item app:${rev.oktaId} not found; nothing goes Live without a Verified work item`), { status: 500 }); // review-2 (stateflow-12): absent = failed write, never a pass
  const moved = !!(wi.state !== 'verified' && wi.state !== 'retired');
  if (moved) {
    const r = await set(wi.item_key, 'verified', 'v2', (o.override ? 'Live by override on revision ' : 'Live sign-off on revision ') + rev.revisionNo, { revisionId: rev.id, attemptId: o.attemptId || null, override: !!o.override });
    workItem = { key: wi.item_key, from: (r && r.from) || wi.state, state: (r && r.to) || 'verified', stateLabel: (r && r.stateLabel) || null };
  }
  let revision;
  try { revision = await S.markLive(rev.id, { actor, override: !!o.override, attemptId: o.attemptId || null }); }
  catch (e) {
    if (moved) { try { await set(wi.item_key, wi.state, 'v2', `Live sign-off on revision ${rev.revisionNo} failed (${redactText(e && e.error || e && e.message || e).slice(0, 120)}); work item put back`, { revisionId: rev.id, revert: true }); } catch (x) { console.error('[oem-v2] setWorkState revert:', redactText(x && x.message || x)); } }
    throw e;
  }
  return { revision, workItem: workItem || (wi ? { key: wi.item_key, state: wi.state } : null) };
}
// POST /revisions/:id/sign-off-live — every Live predicate, server-side
router.post('/revisions/:id/sign-off-live', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    const ctx = await liveContext(req, rev);
    if (tombstoneBlock(res, ctx.dest)) return;
    if (rev.entraId && ctx.dest.entraId !== rev.entraId) return bad(res, 409, 'destination changed since the plan', `The plan targets ${rev.entraId} but the confirmed destination is now ${ctx.dest.entraId}; draft a new revision.`, { destination: ctx.dest, current: rev, predicates: ctx.eligibility.predicates }); // authz-1 / stateflow-2
    if (!ctx.eligibility.eligible) { const first = ctx.eligibility.predicates.find((p) => !p.ok); return bad(res, 403, 'not eligible for Live', first ? first.label + ': ' + first.detail : 'A Live predicate is not met.', { predicates: ctx.eligibility.predicates }); }
    const out = await goLive(req, rev, { attemptId: ctx.attempt ? ctx.attempt.id : null });
    await audit(req, 'oem_v2_live', { oktaId: rev.oktaId, revisionId: rev.id, attemptId: ctx.attempt ? ctx.attempt.id : null });
    res.json(Object.assign({ ok: true, predicates: ctx.eligibility.predicates }, out));
  } catch (e) { fail(res, e, 'sign off live'); }
});

// POST /revisions/:id/override-live {reason} — super admin only; recorded with the failed predicates
router.post('/revisions/:id/override-live', json, admin(), mutating, async (req, res) => {
  try {
    if (!(req.user && req.user.isSuperAdmin)) return bad(res, 403, 'Override needs a super admin', 'Only a super admin can mark a revision Live without every predicate; the override is recorded with the reason.');
    const rev = await loadRevision(req, res); if (!rev) return;
    const reason = String((req.body && req.body.reason) || '').trim();
    if (!reason) return bad(res, 400, 'reason required', 'An override is recorded with your name and the reason; say why the Live predicates are being overridden.');
    if (rev.state !== 'awaiting_live_approval') return bad(res, 409, 'not awaiting Live approval', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; an override only replaces the Live predicates, not the earlier stages.`, { current: rev });
    const ctx = await liveContext(req, rev);
    if (tombstoneBlock(res, ctx.dest)) return;
    const failed = ctx.eligibility.predicates.filter((p) => !p.ok);
    const overrideId = await S.recordOverride({ revisionId: rev.id, oktaId: rev.oktaId, actor: actorOf(req), reason, failedPredicates: failed });
    const out = await goLive(req, rev, { override: true, attemptId: ctx.attempt ? ctx.attempt.id : null });
    await S.addEvent(rev.oktaId, 'live_override', { actor: actorOf(req), note: `Live by override — ${reason}`, evidence: { revisionId: rev.id, overrideId, failedPredicates: failed.map((p) => p.key) } });
    await audit(req, 'oem_v2_live_override', { oktaId: rev.oktaId, revisionId: rev.id, overrideId, reason, failedPredicates: failed.map((p) => p.key) });
    res.json(Object.assign({ ok: true, overrideId, failedPredicates: failed }, out));
  } catch (e) { fail(res, e, 'override live'); }
});

/* POST /revisions/:id/assignment-rollout — after the verified pilot is Live, expand the source groups/direct users on
   the same Entra app. The Okta assignment swap is blocked until this run succeeds without warnings. */
router.post('/revisions/:id/assignment-rollout', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    if (rev.state !== 'live') return bad(res, 409, 'revision is not Live', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; production assignments expand only after the pilot is verified and signed off Live.`, { current: rev });
    const dest = await S.destinationFor(rev.oktaId);
    if (tombstoneBlock(res, dest)) return;
    if (!dest || dest.state !== 'confirmed' || !rev.entraId || dest.entraId !== rev.entraId) return bad(res, 409, 'destination changed since verification', 'The Live revision is not bound to the currently confirmed Entra application; resolve the destination before expanding assignments.', { destination: dest, current: rev });
    const prior = await assignmentRolloutGet(rev);
    if (prior.status === 'completed') return res.json({ ok: true, alreadyCompleted: true, rollout: prior, note: 'Production assignments were already verified on this Entra application.' });
    if (prior.status === 'running') return bad(res, 409, 'production assignment rollout is already running', 'Wait for the current rollout to finish.', { rollout: prior });
    const Xm = X();
    if (!hook(Xm, 'preflight') || !hook(Xm, 'approve') || !hook(Xm, 'push') || !hook(Xm, 'getMigration')) return notAvailable(res, 'oem-migrate-exec preflight/approve/push/getMigration');
    const actor = actorOf(req);
    const cfg = rev.config || {};
    const mig = await Xm.preflight(rev.oktaId, actor, { inputs: engineInputsFor(rev, actor, { assignmentsOnly: true, assignmentScope: 'all' }), targetMode: 'adopt', log: (m) => console.log('[oem-v2] assignment rollout preflight', rev.oktaId, redactText(m)) });
    if (!mig || (mig.error && mig.id === undefined)) return bad(res, mig && Number.isInteger(mig.status) ? mig.status : 409, (mig && mig.error) || 'pre-flight failed', 'The production assignment pre-flight was refused; nothing was written.', { migrationId: mig && mig.id !== undefined ? mig.id : null, checks: L.redact((mig && mig.preflight && mig.preflight.checks) || []) });
    const pf = mig.preflight || {};
    if (pf.passed === false || (pf.summary && pf.summary.failed > 0)) return bad(res, 409, 'pre-flight failed', 'Fix the failing assignment checks, then run production rollout again; nothing was written.', { checks: L.redact(pf.checks || []), migrationId: mig.id });
    const approvedSource = cfg._sourceInventory || {};
    const currentFingerprint = sourceFingerprintOf(mig);
    if (!approvedSource.contractFingerprint || !currentFingerprint || approvedSource.contractFingerprint !== currentFingerprint) return bad(res, 409, 'Okta source changed since the Live revision was approved', 'The source assignments or migration contract changed. Create and approve a fresh revision before production rollout.', { migrationId: mig.id, approvedFingerprint: approvedSource.contractFingerprint || null, currentFingerprint: currentFingerprint || null, checks: L.redact(pf.checks || []) });
    const target = engineTarget(mig);
    if (target.mode !== 'adopt' || (target.entraId && target.entraId !== rev.entraId && target.entraId !== String(dest.appId || '').toLowerCase())) return bad(res, 409, 'engine target differs from the Live revision', `The engine would update ${target.entraName || target.entraId || 'another application'}, not ${dest.name || rev.entraId}; nothing was written.`, { migrationId: mig.id, engineTarget: target, checks: L.redact(pf.checks || []) });
    const ack = (pf.checks || []).filter((c) => c && c.status === 'warn').map((c) => c.key);
    const ap = await Xm.approve(mig.id, actor, { confirm: (mig.plan && mig.plan.displayName) || cfg.displayName, reason: 'v2 production assignment rollout revision ' + rev.id, acknowledge: ack });
    if (ap && ap.error) return bad(res, Number.isInteger(ap.status) ? ap.status : 409, ap.error, 'The engine did not accept the rollout approval; nothing was written.', { migrationId: mig.id });
    const pu = await Xm.push(mig.id, actor);
    if (pu && pu.error) return bad(res, Number.isInteger(pu.status) ? pu.status : 409, pu.error, 'The engine did not start production assignment rollout.', { migrationId: mig.id, conflict: pu.conflict });
    await assignmentRolloutSave(rev, { status: 'running', migrationId: mig.id, jobId: pu && pu.jobId || null, startedAt: L.nowIso(), startedBy: actor, lastError: null });
    await S.addEvent(rev.oktaId, 'entra_assignment_rollout_started', { actor, note: `Production assignment rollout started (migration ${mig.id})`, evidence: { revisionId: rev.id, migrationId: mig.id } });
    await audit(req, 'oem_v2_assignment_rollout', { oktaId: rev.oktaId, revisionId: rev.id, migrationId: mig.id });
    const poll = await L.startJob('v2-assignment-rollout-poll:' + rev.id, actor, async (log) => {
      const get = hook(Xm, 'getMigration');
      for (let i = 0; i < 200; i++) {
        const m = await get(mig.id, { events: false });
        const st = m ? String(m.status || '') : '';
        if (ENGINE_OK.has(st)) {
          const handoffs = (m.results && m.results.handoffs) || [];
          const assignmentHandoffs = handoffs.filter((k) => ['assign_everyone', 'create_groups_manual', 'sync_groups'].includes(k));
          const verified = !!(m.verification && m.verification.ok === true);
          if (st !== 'succeeded' || !verified || assignmentHandoffs.length) {
            const why = assignmentHandoffs.length ? 'Manual assignment work remains: ' + assignmentHandoffs.join(', ') : (st === 'warnings' ? 'The assignment run completed with warnings.' : 'The live re-read did not verify every assignment write.');
            const out = await assignmentRolloutSave(rev, { status: 'needs_attention', migrationId: mig.id, finishedAt: L.nowIso(), lastError: why, handoffs: assignmentHandoffs });
            await S.addEvent(rev.oktaId, 'entra_assignment_rollout_attention', { actor, note: why, evidence: { revisionId: rev.id, migrationId: mig.id, handoffs: assignmentHandoffs } });
            log(why, 'warn'); return out;
          }
          const out = await assignmentRolloutSave(rev, { status: 'completed', migrationId: mig.id, finishedAt: L.nowIso(), completedBy: actor, lastError: null, handoffs: [] });
          await S.addEvent(rev.oktaId, 'entra_assignment_rollout_completed', { actor, note: 'Production Entra assignments expanded and verified; the reversible Okta assignment swap is now available.', evidence: { revisionId: rev.id, migrationId: mig.id } });
          log('production Entra assignments expanded and verified'); return out;
        }
        if (ENGINE_END.has(st)) {
          const out = await assignmentRolloutSave(rev, { status: 'failed', migrationId: mig.id, finishedAt: L.nowIso(), lastError: 'The assignment migration ended ' + (st || 'without a status') + '.' });
          await S.addEvent(rev.oktaId, 'entra_assignment_rollout_failed', { actor, note: out.lastError, evidence: { revisionId: rev.id, migrationId: mig.id } });
          log(out.lastError, 'error'); return out;
        }
        await L.sleep(3000);
      }
      const out = await assignmentRolloutSave(rev, { status: 'unknown', migrationId: mig.id, lastError: 'The assignment migration did not report an end state in time.' });
      log(out.lastError, 'warn'); return out;
    });
    await assignmentRolloutSave(rev, { pollJobId: poll && poll.id || null });
    res.status(202).json({ ok: true, migrationId: mig.id, jobId: pu && pu.jobId || null, pollJobId: poll && poll.id || null, note: 'Production Entra assignments are being expanded and verified. Okta assignments remain unchanged.' });
  } catch (e) { fail(res, e, 'production assignment rollout'); }
});

/* A live migration can keep its original Okta SSO app as an immediately usable fallback. The worker first creates an
   inactive, unassigned Bookmark. At cutover it copies and verifies group/direct-user assignments, activates the
   Bookmark, and only then removes the source assignments. Neither this router nor the worker deletes either app. */
async function bookmarkRoute(req, res, action) {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    if (rev.state !== 'live') return bad(res, 409, 'revision is not Live', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; assignment handoff is available only after Live sign-off.`, { current: rev });
    const dest = await S.destinationFor(rev.oktaId);
    if (tombstoneBlock(res, dest)) return;
    if (!dest || !dest.entraId || (rev.entraId && rev.entraId !== dest.entraId)) return bad(res, 409, 'destination changed since the plan', 'The Live revision is not bound to the currently confirmed Entra application; resolve the destination before moving Okta assignments.', { destination: dest, current: rev });
    if (action === 'cutover') {
      const rollout = await assignmentRolloutGet(rev);
      if (rollout.status !== 'completed') return bad(res, 409, 'production Entra assignments are not verified', 'Expand and verify the production assignments on the Entra application before removing any assignment from the original Okta app.', { rollout });
    }
    const entra = await S.entraApp(dest.entraId);
    if (!entra || !entra.appId) return bad(res, 409, 'Entra application ID is unavailable', 'Refresh Entra applications so the Bookmark can target the destination My Apps launcher URL.');
    if (!process.env.ENTRA_TENANT_ID) return bad(res, 409, 'Entra tenant ID is unavailable', 'ENTRA_TENANT_ID must be configured before an Okta Bookmark URL can be created.');
    const okta = await S.oktaApp(rev.oktaId);
    const wi = await S.workItem(rev.oktaId);
    const label = (wi && wi.title) || (okta && okta.label) || rev.oktaId;
    const input = req.body && typeof req.body === 'object' ? req.body : {};
    const reason = String(input.reason || '').trim();
    if (typeof M.assertNoSecretText === 'function') M.assertNoSecretText(reason, 'assignment handoff reason');
    const Bm = B();
    const fn = hook(Bm, action === 'stage' ? 'startStage' : action === 'cutover' ? 'startCutover' : 'startRollback');
    if (!fn) return notAvailable(res, 'oem-okta-bookmark');
    const ctx = bookmarkContext(rev, label, entra.appId, actorOf(req));
    let r;
    try { r = await fn(ctx, input); }
    catch (e) {
      const expected = e && e.expected;
      const status = e && ['BAD_CONFIRMATION', 'BAD_REASON', 'BAD_CONTEXT', 'BAD_DESTINATION'].includes(e.code) ? 400 : 409;
      return bad(res, status, textErrorForBookmark(e), textErrorForBookmark(e), expected ? { expected } : null);
    }
    if (r && r.conflict) return bad(res, 409, 'another assignment handoff job is running', 'Wait for the current assignment handoff job to finish before starting another action.', { conflict: r.conflict });
    const event = action === 'stage' ? 'oem_v2_bookmark_stage_requested' : action === 'cutover' ? 'oem_v2_bookmark_cutover_requested' : 'oem_v2_bookmark_rollback_requested';
    await audit(req, event, { oktaId: rev.oktaId, revisionId: rev.id, jobId: r.id, reason });
    res.status(202).json({ ok: true, jobId: r.id, action, note: action === 'stage' ? 'Bookmark staging started. The original assignments are unchanged.' : action === 'cutover' ? 'Assignment cutover started. Any failure restores the original assignments.' : 'Rollback started. The original assignments are restored before the Bookmark is changed.' });
  } catch (e) { fail(res, e, 'Okta Bookmark ' + action); }
}
function textErrorForBookmark(e) { return redactText(e && e.message || e || 'Assignment handoff request refused.').slice(0, 300); }

router.post('/revisions/:id/bookmark-handoff/stage', json, admin(), mutating, (req, res) => bookmarkRoute(req, res, 'stage'));
router.post('/revisions/:id/bookmark-handoff/cutover', json, admin(), mutating, (req, res) => bookmarkRoute(req, res, 'cutover'));
router.post('/revisions/:id/bookmark-handoff/rollback', json, admin(), mutating, (req, res) => bookmarkRoute(req, res, 'rollback'));

// POST /revisions/:id/retire-okta {confirm, reason} — the existing lifecycle path, after Live only
router.post('/revisions/:id/retire-okta', json, admin(), mutating, async (req, res) => {
  try {
    const rev = await loadRevision(req, res); if (!rev) return;
    if (rev.state !== 'live') return bad(res, 409, 'revision is not Live', `Revision ${rev.revisionNo} is ${M.STATE_LABEL[rev.state] || rev.state}; Okta is retired only after Live sign-off.`, { current: rev });
    const dest = await S.destinationFor(rev.oktaId);
    if (tombstoneBlock(res, dest)) return;
    const okta = await S.oktaApp(rev.oktaId);
    const wi = await S.workItem(rev.oktaId);
    /* stateflow-11: one label source — startOktaLifecycle compares against the work item title, so that is what is expected here
       and what is passed on; the Okta mirror label only stands in when no work item exists (the lifecycle step then 404s). */
    const label = (wi && wi.title) || (okta && okta.label) || null;
    const confirm = String((req.body && req.body.confirm) || '');
    /* drop 8: no invented minimum — a reason is optional; without one the record says what actually happened */
    const reason = String((req.body && req.body.reason) || '').trim() || `Retired after Live sign-off on revision ${rev.revisionNo} (recorded by ${actorOf(req)})`;
    if (!label || confirm !== label) return bad(res, 400, 'Confirm the application label to retire it.', 'The confirmation must name the application label shown on the work item.', { expected: label });
    if (typeof M.assertNoSecretText === 'function') M.assertNoSecretText(reason, 'retire reason'); // secrets-4: the reason is stored in four places
    const Wm = W();
    const start = hook(Wm, 'startOktaLifecycle');
    if (!start) return notAvailable(res, 'startOktaLifecycle');
    const r = await start(req, rev.oktaId, 'deactivate', { confirmLabel: label, reason });
    const body = Object.assign({}, r.body || {});
    if (r.status >= 400 && !body.why) body.why = body.error ? 'The Okta lifecycle step refused the request: ' + body.error : 'The Okta lifecycle step refused the request.';
    if (r.status === 202) { await S.addEvent(rev.oktaId, 'retire_okta_requested', { actor: actorOf(req), note: reason, evidence: { revisionId: rev.id, jobId: body.jobId } }); await audit(req, 'oem_v2_retire_okta', { oktaId: rev.oktaId, revisionId: rev.id, jobId: body.jobId }); }
    res.status(r.status).json(L.redact(body));
  } catch (e) { fail(res, e, 'retire okta'); }
});

/* ------------------------------------------------- drop 8: technician flow (me, prefs, one task, handoff) */

const MODES = ['technician', 'advanced'];
// GET /me — who is signed in, what they may do here, and the page preferences (mode, intro seen)
router.get('/me', read(), async (req, res) => {
  try {
    const email = actorOf(req);
    const prefs = await S.userPrefs(email);
    res.json({ email, permissions: await permissions(req), prefs: { mode: MODES.includes(prefs.mode) ? prefs.mode : null, introSeenAt: prefs.introSeenAt || null }, modes: MODES });
  } catch (e) { fail(res, e, 'me'); }
});
// POST /me/prefs {mode?, introSeen?} — the caller's own preferences (any signed-in level; a read-only session changes nothing)
router.post('/me/prefs', json, read(), async (req, res) => {
  try {
    if (req.user && req.user.readOnly) return bad(res, 403, 'read-only session', 'Your session is read-only on this page; preferences are not saved from it.');
    const email = actorOf(req);
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    if (b.mode !== undefined) {
      if (!MODES.includes(b.mode)) return bad(res, 400, 'unknown mode', 'mode is technician or advanced.');
      await S.setUserPref(email, 'mode', b.mode);
    }
    if (b.introSeen !== undefined) await S.setUserPref(email, 'introSeen', b.introSeen ? L.nowIso() : null);
    const prefs = await S.userPrefs(email);
    res.json({ ok: true, prefs: { mode: MODES.includes(prefs.mode) ? prefs.mode : null, introSeenAt: prefs.introSeenAt || null } });
  } catch (e) { fail(res, e, 'me prefs'); }
});

/* The one task a technician receives: their own assignments first (closest to finished first), then a recommendation from
   the open queue — never a blocked item, never one somebody handed off (those wait for an advanced technician). */
const TASK_ORDER = ['live', 'awaiting_live_approval', 'awaiting_verification', 'entra_configured', 'awaiting_vendor', 'plan_approved', 'draft', 'match_confirmed_no_revision', 'match_suggested', 'no_destination', 'destination_unresolved', 'not_migrating'];
const taskRank = (it) => { const i = TASK_ORDER.indexOf(it.state); return i < 0 ? TASK_ORDER.length : i; };
const byRank = (a, b) => taskRank(a) - taskRank(b) || String(a.title || '').localeCompare(String(b.title || ''));
const lower = (v) => String(v || '').toLowerCase();
/* handed off = the latest handoff on the item is newer than its latest assignment (a take-over clears it) */
function handedOff(it, hm) {
  const h = hm && hm.get(it.workKey);
  if (!h) return null;
  if (h.to && it.assignee && lower(it.assignee) === lower(h.to)) return h; // handed to this person: the context stays with them (NOW() is second-precise, so the timestamps alone cannot tell)
  if (it.assignee && it.assignedAt && new Date(it.assignedAt).getTime() >= new Date(h.at).getTime()) return null;
  return h;
}
const CATEGORY_LABEL = { applications: 'Application', policies: 'Sign-in policy', mfa: 'MFA', network_device: 'Network device', dependencies: 'Dependency' };
function taskBrief(it) { return { oktaId: it.oktaId, title: it.title, state: it.state, stateLabel: M.STATE_LABEL[it.state] || it.state, cta: it.cta ? { code: it.cta.code, label: it.cta.label, kind: it.cta.kind } : null, workKey: it.workKey, assignee: it.assignee || null }; }
// GET /tasks/mine — {me, task, counts, next}
router.get('/tasks/mine', read(), async (req, res) => {
  try {
    const me = actorOf(req);
    const perms = await permissions(req);
    const all = (await listItems(req)).filter((it) => it.view !== 'completed');
    const hm = await S.latestHandoffs();
    for (const it of all) it.handoff = handedOff(it, hm);
    const mine = all.filter((it) => it.assignee && lower(it.assignee) === lower(me)).sort(byRank);
    const open = all.filter((it) => !it.assignee && !it.handoff && !(it.cta && it.cta.kind === 'blocked')).sort(byRank);
    const handed = all.filter((it) => it.handoff);
    const others = (await S.assignedWorkItems(me)).filter((w) => w.category !== 'applications');
    let task = null;
    const pick = mine[0] || null;
    if (pick) task = { kind: 'app', source: 'assigned', oktaId: pick.oktaId, title: pick.title, workKey: pick.workKey, assignee: pick.assignee, handoff: pick.handoff, workspace: await buildWorkspace(pick.oktaId, req) };
    else if (others.length) { const w = others[0]; task = { kind: 'work', source: 'assigned', key: w.key, title: w.title, category: w.category, categoryLabel: CATEGORY_LABEL[w.category] || w.category, state: w.state }; }
    else if (perms.canEdit && open.length) { const r = open[0]; task = { kind: 'app', source: 'recommended', oktaId: r.oktaId, title: r.title, workKey: r.workKey, assignee: null, handoff: null, workspace: await buildWorkspace(r.oktaId, req) }; }
    res.json({ me, permissions: perms, task, counts: { assigned: mine.length + others.length, open: open.length, handedOff: handed.length, all: all.length }, next: mine.slice(1, 6).map(taskBrief), why: task ? null : (perms.canEdit ? 'Nothing is assigned to you and the open queue is empty.' : 'Nothing is assigned to you. Tasks are recommended only to technicians who can act on them.') });
  } catch (e) { fail(res, e, 'tasks mine'); }
});

const HANDOFF_REASONS = { unsure: "I'm not sure what to do", wrong: 'Something looks wrong', access: 'Needs someone with more access', owner: 'Needs the vendor or the application owner', other: 'Other' };
const BUNDLE_MAX = 60000;
/* Everything the next person needs, gathered by the server — never typed by the technician: where the app is, what the
   checks found, every attempt, the errors and the recent activity. Bounded, redacted, stored on the handoff event. */
function handoffBundle(ws) {
  if (!ws) return null;
  const pkg = ws.evidence && ws.evidence.package;
  const failedish = (r) => /fail|error|refused|denied|could not|not eligible|timed out/i.test(String(r.title || '') + ' ' + String(r.detail || ''));
  const act = Array.isArray(ws.activity) ? ws.activity : [];
  const bundle = {
    context: { state: ws.state, stateLabel: M.STATE_LABEL[ws.state] || ws.state, cta: ws.cta ? { code: ws.cta.code, label: ws.cta.label, kind: ws.cta.kind, why: ws.cta.why || null } : null, identity: ws.identity ? { label: ws.identity.label, status: ws.identity.status, protocol: ws.identity.protocol } : null,
      destination: ws.destination ? { state: ws.destination.state, entraId: ws.destination.entraId, name: ws.destination.name } : null, revision: ws.revision ? { id: ws.revision.id, revisionNo: ws.revision.revisionNo, state: ws.revision.state, protocol: ws.revision.protocol, adopt: ws.revision.adopt === true } : null,
      workItem: ws.workItem || null, generation: ws.generation || null },
    evidence: pkg ? { summary: pkg.summary, evidenceLines: (pkg.evidenceLines || []).slice(0, 20), ownerAttestation: pkg.ownerAttestation || null, live: pkg.live || null, vendorClaim: pkg.vendorClaim || null } : null,
    verification: ws.verification ? { attemptId: ws.verification.attemptId, status: ws.verification.status, finishedAt: ws.verification.finishedAt, checks: (ws.verification.checks || []).map((c) => ({ key: c.key, label: c.label, result: c.result, detail: c.detail })), signIns: ws.verification.signIns ? { total: ws.verification.signIns.total, ok: ws.verification.signIns.ok, recent24h: ws.verification.signIns.recent24h, latest: ws.verification.signIns.latest.slice(0, 5) } : null } : null,
    attempts: (ws.attempts || []).slice(0, 10),
    liveEligibility: ws.liveEligibility ? { eligible: ws.liveEligibility.eligible, failed: (ws.liveEligibility.predicates || []).filter((p) => !p.ok).map((p) => ({ key: p.key, label: p.label, detail: p.detail })) } : null,
    errors: act.filter(failedish).slice(0, 20),
    activity: act.slice(0, 30),
  };
  if (JSON.stringify(bundle).length > BUNDLE_MAX) { bundle.activity = act.slice(0, 10); bundle.errors = bundle.errors.slice(0, 8); bundle.evidence && (bundle.evidence.evidenceLines = bundle.evidence.evidenceLines.slice(0, 5)); }
  return bundle;
}
// POST /handoff {oktaId | key, reason, note, to?} — "I'm not sure / Hand off": the task is released (or given to `to`) with the bundle
router.post('/handoff', json, admin(), mutating, async (req, res) => {
  try {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const reason = String(b.reason || '').trim();
    if (!HANDOFF_REASONS[reason]) return bad(res, 400, 'reason required', 'Pick why you are handing off: ' + Object.keys(HANDOFF_REASONS).join(', ') + '.', { reasons: HANDOFF_REASONS });
    const note = String(b.note || '').trim().slice(0, 500);
    if (!note) return bad(res, 400, 'note required', 'A handoff carries a note for the next person — one line about what you saw or what you need. Everything else (state, evidence, attempts, errors, activity) is attached automatically.', { missing: 'note' });
    if (typeof M.assertNoSecretText === 'function') M.assertNoSecretText(note, 'handoff note'); // secrets-4
    const to = b.to ? lower(String(b.to).trim()) : null;
    if (to && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return bad(res, 400, 'to must be an email address', 'Hand off to a person by email, or leave it empty to release the task to the queue.');
    let key = null, oktaId = null;
    if (b.oktaId !== undefined && b.oktaId !== null && b.oktaId !== '') { oktaId = String(b.oktaId); if (!OKTA_ID_RE.test(oktaId)) return bad(res, 400, 'bad Okta id', 'An Okta application id is 1-64 letters and digits.'); key = 'app:' + oktaId; }
    else if (b.key) { key = String(b.key).slice(0, 160); if (/^app:/.test(key)) oktaId = key.slice(4); }
    if (!key) return bad(res, 400, 'oktaId or key required', 'Name the task being handed off.');
    const wi = await S.workItemByKey(key);
    if (!wi) return bad(res, 404, 'no such work item', 'The task named is not in the work queue.');
    const actor = actorOf(req);
    const ws = oktaId ? await buildWorkspace(oktaId, req) : null;
    const bundle = ws ? handoffBundle(ws) : { context: { key, title: wi.title, category: wi.category, state: wi.state, disposition: wi.disposition }, activity: await activityRows(null, 30).then((rows) => rows.filter((r) => r.ref && r.ref.itemKey === key).slice(0, 30)).catch(() => []) };
    const from = wi.assignee || null;
    await S.addEventKey(key, 'handoff', { actor, note: `${HANDOFF_REASONS[reason]} — ${note}`, evidence: { reason, reasonLabel: HANDOFF_REASONS[reason], note, from: actor, previousAssignee: from, to, bundle } });
    await S.setAssignee(key, to, actor);
    await audit(req, 'oem_v2_handoff', { key, oktaId, reason, to, from });
    res.json({ ok: true, key, oktaId, handoff: { at: L.nowIso(), by: actor, reason, reasonLabel: HANDOFF_REASONS[reason], to, note }, assignee: to, bundle: { attempts: bundle.attempts ? bundle.attempts.length : 0, errors: bundle.errors ? bundle.errors.length : 0, activity: bundle.activity ? bundle.activity.length : 0 } });
  } catch (e) { fail(res, e, 'handoff'); }
});

/* ------------------------------------------------- work queue / evidence / activity */

const QUEUE_FILTERS = [
  { key: 'assigned_to_me', label: 'Assigned to me', test: (it, me) => it.assignee && String(it.assignee).toLowerCase() === String(me).toLowerCase() },
  { key: 'needs_decision', label: 'Needs a decision', test: (it) => ['no_destination', 'match_suggested', 'destination_unresolved', 'match_confirmed_no_revision', 'draft', 'not_migrating'].includes(it.state) },
  { key: 'blocked', label: 'Blocked', test: (it) => (it.cta && it.cta.kind === 'blocked') || it.workState === 'blocked' || it.state === 'destination_unresolved' },
  { key: 'awaiting_verification', label: 'Awaiting verification', test: (it) => !!(it.revision && ['entra_configured', 'awaiting_vendor', 'awaiting_verification'].includes(it.revision.state)) },
  { key: 'ready_for_live', label: 'Ready for Live', test: (it) => !!(it.revision && it.revision.state === 'awaiting_live_approval') },
  { key: 'handed_off', label: 'Handed off', test: (it) => !!it.handoff }, // drop 8: released by a technician with a bundle; an advanced technician takes it over
];
// GET /work-queue?filter=&limit=
router.get('/work-queue', read(), async (req, res) => {
  try {
    const all = (await listItems(req)).filter((it) => it.view !== 'completed');
    const me = actorOf(req);
    const hm = await S.latestHandoffs();
    for (const it of all) it.handoff = handedOff(it, hm);
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 500);
    const filters = QUEUE_FILTERS.map((f) => ({ key: f.key, label: f.label, count: all.filter((it) => f.test(it, me)).length }));
    const f = QUEUE_FILTERS.find((x) => x.key === req.query.filter) || null;
    const matched = f ? all.filter((it) => f.test(it, me)) : all;
    const items = matched.slice(0, limit);
    // codex-7: total is the count of what the filter matched (what the header states), not the whole open queue;
    // shown/limit/truncated say how much of it this page carries. unfiltered is the open queue size.
    res.json({ filter: f ? f.key : null, filters, items, total: matched.length, shown: items.length, limit, truncated: matched.length > items.length, unfiltered: all.length });
  } catch (e) { fail(res, e, 'work queue'); }
});

// GET /evidence?oktaId=
router.get('/evidence', read(), async (req, res) => {
  try {
    const packages = [];
    const pkg = async (oktaId, rev) => {
      const attempt = await S.attemptFor(rev); // authz-7: a live/superseded revision reads its frozen attempt, never the latest
      const okta = await S.oktaApp(oktaId);
      const wi = await S.workItem(oktaId);
      const p = evidencePackage(oktaId, (okta && okta.label) || (wi && wi.title) || oktaId, rev, attempt, okta);
      if (p) packages.push(p);
    };
    const one = async (oktaId) => { const rev = await S.liveRevision(oktaId) || await S.latestRevision(oktaId); if (rev) await pkg(oktaId, rev); };
    if (req.query.revisionId !== undefined) { // authz-10: one exact revision (a former Live one included)
      const rid = Number(req.query.revisionId);
      if (!Number.isInteger(rid) || rid <= 0) return bad(res, 400, 'bad revision id', 'A revision id is a positive integer.');
      const rev = await S.getRevision(rid);
      if (!rev) return bad(res, 404, 'unknown revision', 'No revision ' + rid + '.');
      await pkg(rev.oktaId, rev);
    } else if (req.query.oktaId) { const id = String(req.query.oktaId); if (!OKTA_ID_RE.test(id)) return bad(res, 400, 'bad Okta id', 'An Okta application id is 1-64 letters and digits.'); await one(id); }
    else {
      const [rows] = await pool.query(`SELECT id, okta_app_id, state, live_at FROM oem_config_revision WHERE state IN ('live','awaiting_live_approval','superseded') ORDER BY id LIMIT 400`);
      const apps = []; const formerLive = [];
      for (const r of rows || []) { if (r.state === 'superseded') { if (r.live_at) formerLive.push(r.id); } else if (!apps.includes(r.okta_app_id)) apps.push(r.okta_app_id); }
      for (const id of apps.sort()) await one(id);
      for (const rid of formerLive) { const rev = await S.getRevision(rid); if (rev) await pkg(rev.oktaId, rev); } // authz-10: a revision that was Live keeps its frozen package
    }
    /* staged-3: the Entra export ledger with its sign-in evidence (every row, whatever the query scoped the packages to). */
    let staged = null;
    const Sm = St();
    if (hook(Sm, 'stagedList')) { try { staged = await Sm.stagedList(); } catch (e) { console.error('[oem-v2] stagedList:', errText(e)); staged = { error: 'The Entra export ledger could not be read.' }; } }
    res.json({ packages, staged, generatedAt: L.nowIso() });
  } catch (e) { fail(res, e, 'evidence'); }
});

// GET /staged — the Entra export ledger alone (what /evidence carries under `staged`)
router.get('/staged', read(), async (req, res) => {
  try {
    const Sm = St();
    if (!hook(Sm, 'stagedList')) return notAvailable(res, 'oem-staged.stagedList');
    res.json(await Sm.stagedList());
  } catch (e) { fail(res, e, 'staged'); }
});

// POST /staged/import {csv, sourceFile?} — load an Entra "export service principals" CSV into the ledger (admin). Every row not
// already known starts Staged; a re-import never changes a status (Complete is terminal) and marks rows no longer exported.
router.post('/staged/import', json, admin(), mutating, async (req, res) => {
  try {
    const Sm = St();
    if (!hook(Sm, 'importExport')) return notAvailable(res, 'oem-staged.importExport');
    const csv = req.body && typeof req.body.csv === 'string' ? req.body.csv : '';
    if (!csv.trim()) return bad(res, 400, 'csv required', 'Send the Entra enterprise-applications export as {csv: "<file contents>"}.');
    if (csv.length > 200000) return bad(res, 400, 'csv too large', 'The export is over 200,000 characters; export a smaller scope.');
    const sourceFile = req.body.sourceFile ? String(req.body.sourceFile).slice(0, 255) : null;
    let r;
    try { r = await Sm.importExport({ csv, sourceFile, actor: actorOf(req) }); }
    catch (e) { return bad(res, 400, 'import failed', errText(e)); }
    await audit(req, 'oem_v2_staged_import', { sourceFile, imported: r.imported, added: r.added, updated: r.updated, removed: r.removed, skipped: r.skipped.length });
    /* the check runs right away so the imported rows read Staged/Complete without a second click; 409 = one is already running */
    const Wm = W();
    const def = Wm && Wm.JOB_DEFS && Wm.JOB_DEFS['staged-signins'];
    let job = null;
    if (def && typeof def.run === 'function') { const j2 = await L.startJob('staged-signins', actorOf(req), def.run); job = j2.conflict ? { conflict: j2.conflict } : { id: j2.id }; }
    res.status(201).json(Object.assign({ ok: true, job }, r));
  } catch (e) { fail(res, e, 'staged import'); }
});

// GET /activity?oktaId=&limit=
router.get('/activity', read(), async (req, res) => {
  try {
    const id = req.query.oktaId ? String(req.query.oktaId) : null;
    if (id && !OKTA_ID_RE.test(id)) return bad(res, 400, 'bad Okta id', 'An Okta application id is 1-64 letters and digits.');
    const items = await activityRows(id, req.query.limit || 100);
    res.json({ oktaId: id, items, total: items.length });
  } catch (e) { fail(res, e, 'activity'); }
});

router.buildWorkspace = buildWorkspace;
router.activityRows = activityRows;
router.SOURCE_DEFS = SOURCE_DEFS;
router.REFRESH_JOB_OF = REFRESH_JOB_OF;
module.exports = router;
/* server.js mounts the router directly (app.use('/api/oem/v2', router)); .router is the same object for loaders that look for {router}. */
module.exports.router = router;
module.exports.mount = (app, base) => { app.use(base || '/api/oem/v2', router); return router; };
