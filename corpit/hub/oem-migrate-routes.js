/**
 * oem-migrate-routes.js — HTTP surface of the Okta → Entra application migration engine.
 * Mount under /api/oem/migrate, before ./oem-work-routes:
 *   app.use('/api/oem/migrate', require('./oem-migrate-routes'));
 *
 * Reads are page-level "read"; anything that touches a vendor (even read-only scans that refresh the
 * mirror) or records a decision is page-level "admin". Every response about capability comes from the
 * live roles claim; nothing here reports a step as automatic unless the credential actually holds it.
 */
'use strict';
const express = require('express');
const createRbac = require('./rbac-middleware');
const L = require('./oem-lib');
const M = require('./oem-migrate');
const X = require('./oem-migrate-exec');
const CX = require('./oem-coexistence');
const VG = require('./oem-vendor-guides');
const LP = require('./oem-link-probe');
let USAGE = null, TSI = null; // removable (Drop 8)
try { USAGE = require('./oem-usage'); } catch (e) { USAGE = null; }
try { TSI = require('./oem-test-signin'); } catch (e) { TSI = null; }
const { pool, j, nowIso } = L;

const router = express.Router();
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const PAGE_KEY = 'okta-entra-migration';
const read = () => rbac.requirePage(PAGE_KEY, 'read');
const admin = () => rbac.requirePage(PAGE_KEY, 'admin');
const json = express.json({ limit: '256kb' });
const fail = (res, e, where) => { console.error(`[oem-migrate] ${where}:`, e && e.stack || e); res.status(500).json({ error: 'request failed', where, detail: String(e && e.message || e).slice(0, 300) }); };
const actorOf = (req) => (req.user && req.user.email) || 'anonymous';
const audit = (req, action, details, target) => { try { if (rbac.audit) return rbac.audit(req, action, target || null, PAGE_KEY, details); } catch (e) { /* audit never breaks a request */ } };
const OKTA_ID = /^[0-9a-zA-Z]{16,24}$/;
async function pageLevel(req) {
  try {
    if (req.user && req.user.email && rbac.computeEffectivePages) {
      const pages = await rbac.computeEffectivePages(req.user.email, req.user.roles || [], !!req.user.isSuperAdmin);
      return pages[PAGE_KEY] || 'none';
    }
  } catch (e) { console.error('[oem-migrate] pageLevel:', e.message); }
  return null;
}
const canAct = (lvl, req) => lvl === 'admin' && !(req.user && req.user.readOnly);
const idOk = (req, res) => { if (!OKTA_ID.test(req.params.id)) { res.status(400).json({ error: 'bad Okta app id' }); return false; } return true; };
if (TSI) TSI.mount(router, { json, admin, read, idOk, fail, actorOf, audit }); // GET /apps/:id/test-signin, POST …/test-signin/start, POST …/test-signin/:tid/check

/* ------------------------------------------------------------- capability */

// GET /api/oem/migrate/access — what the engine can do right now, per permission, with who grants it
router.get('/access', read(), async (req, res) => {
  try {
    const [ctx, lvl] = await Promise.all([M.context(), pageLevel(req)]);
    // read-only sets (…Read.All) belong to the read credential; CONSENT / GROUP_* only gate optional steps (handed off when missing)
    const OPTIONAL = { CONSENT: 'admin consent for the app (handed off when missing)', GROUP_CREATE: 'creating Entra groups for Okta-native groups (handed off when missing)', GROUP_MEMBER: 'populating created groups (handed off when missing)' };
    const isRead = (alts) => alts.every((x) => /\.Read\.All$/.test(x));
    const rows = Object.entries(M.PERM).map(([key, alts]) => {
      const readSet = isRead(alts);
      const pc = M.permCheck(alts, readSet ? (ctx.readRoles === undefined ? ctx.roles : ctx.readRoles) : ctx.roles);
      return { key, alternatives: alts, credential: readSet ? 'read' : 'write', optional: !!OPTIONAL[key], gates: OPTIONAL[key] || null, granted: pc.ok, have: pc.have, missing: pc.missing, grantedBy: pc.ok ? null : (readSet ? M.READ_GRANTOR || M.ENTRA_GRANTOR : M.ENTRA_GRANTOR) };
    });
    const requiredMissing = rows.filter((r) => r.credential === 'write' && !r.optional && r.granted !== true).map((r) => r.missing || r.alternatives[0]);
    const optionalMissing = rows.filter((r) => r.optional && r.granted !== true).map((r) => r.missing || r.alternatives[0]);
    res.json({ checkedAt: L.nowIso(), user: { email: actorOf(req), login: actorOf(req), pageLevel: lvl, canAct: canAct(lvl, req), readOnly: !!(req.user && req.user.readOnly) }, graph: { rolesKnown: ctx.roles !== null, error: ctx.graphError, roles: ctx.roles, readRoles: ctx.readRoles, readError: ctx.readError }, write: ctx.write, okta: ctx.okta, permissions: rows,
      requiredMissing, optionalMissing, grantedBy: M.ENTRA_GRANTOR,
      pushPossible: M.permCheck(M.PERM.APP_WRITE, ctx.roles).ok === true, wizard: true, note: 'A write step whose permission is not consented is reported as AUTO — blocked with the permission named; Push refuses with the same reason. Optional grants only affect steps that are otherwise handed off. Nothing is simulated.' });
  } catch (e) { fail(res, e, 'access'); }
});

/* ------------------------------------------------------------------ logos */

// GET /api/oem/migrate/logo/:source/:id — the vendor logo the Okta / Entra mirror points at, fetched by the
// server from the STORED url (never a client url), cached in oem_logo, served same-origin (CSP img-src 'self').
// 404 = no real logo (Okta's default placeholder counts as none); the page falls back to a monogram.
const LOGO_MAX = 512 * 1024, LOGO_TTL_MS = 7 * 86400e3, LOGO_MISS_TTL_MS = 86400e3;
const OKTA_PLACEHOLDER = /\/assets\/img\/logos\/default\./;
const ENTRA_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOGO_HOSTS = /(^|\.)(oktacdn\.com|msftauthimages\.net|microsoftonline-p\.com)$/i;
function logoServe(res, row) {
  res.set('Content-Type', row.content_type || 'application/octet-stream');
  res.set('Cache-Control', 'private, max-age=86400');
  res.set('X-Content-Type-Options', 'nosniff');
  res.send(row.body);
}
async function logoUpsert(source, id, url, ct, body, status, error) {
  await pool.query(`INSERT INTO oem_logo (source, id, url, content_type, body, status, error, fetched_at) VALUES (?,?,?,?,?,?,?,NOW())
                    ON DUPLICATE KEY UPDATE url=VALUES(url), content_type=VALUES(content_type), body=COALESCE(VALUES(body), IF(VALUES(status)='ok', NULL, body)), status=VALUES(status), error=VALUES(error), fetched_at=NOW()`,
    [source, id, url ? String(url).slice(0, 512) : null, ct, body, status, error ? String(error).slice(0, 255) : null]);
}
router.get('/logo/:source/:id', read(), async (req, res) => {
  try {
    const { source, id } = req.params;
    if (source !== 'okta' && source !== 'entra') return res.status(404).end();
    if (source === 'okta' ? !OKTA_ID.test(id) : !ENTRA_ID.test(id)) return res.status(404).end();
    const [[row]] = await pool.query(`SELECT url, content_type, body, status, fetched_at FROM oem_logo WHERE source=? AND id=?`, [source, id]);
    const age = row && row.fetched_at ? Date.now() - new Date(row.fetched_at).getTime() : Infinity;
    if (row && age < (row.status === 'ok' ? LOGO_TTL_MS : LOGO_MISS_TTL_MS)) return row.status === 'ok' && row.body ? logoServe(res, row) : res.status(404).end();
    let url = null;
    if (source === 'okta') { const [[a]] = await pool.query(`SELECT JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$._links.logo[0].href')) AS href FROM okta_apps WHERE okta_id=?`, [id]); url = a && a.href && !OKTA_PLACEHOLDER.test(a.href) ? a.href : null; }
    else { const [[e]] = await pool.query(`SELECT logo_url FROM entra_apps WHERE entra_id=?`, [id]); url = e && e.logo_url ? e.logo_url : null; }
    let host = null; try { host = url ? new URL(url).hostname : null; } catch (e) { host = null; }
    if (!url || !/^https:\/\//i.test(url) || !host || !LOGO_HOSTS.test(host)) { await logoUpsert(source, id, url, null, null, 'none', url ? 'logo host not mirrored: ' + host : 'no logo in the mirror'); return res.status(404).end(); }
    let ct, buf;
    try {
      const ac = new AbortController(); const timer = setTimeout(() => ac.abort(), 8000);
      const r = await fetch(url, { signal: ac.signal, redirect: 'follow', headers: { Accept: 'image/*' } });
      clearTimeout(timer);
      ct = String(r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
      if (!r.ok || !/^image\/(png|jpeg|gif|webp|svg\+xml|x-icon|vnd\.microsoft\.icon)$/.test(ct)) throw new Error('upstream ' + r.status + ' ' + (ct || 'no content-type'));
      const ab = await r.arrayBuffer();
      if (ab.byteLength > LOGO_MAX || ab.byteLength === 0) throw new Error('size ' + ab.byteLength);
      buf = Buffer.from(ab);
    } catch (e) {
      await logoUpsert(source, id, url, row ? row.content_type : null, null, 'error', e && e.name === 'AbortError' ? 'timeout' : (e && e.message || e));
      if (row && row.status === 'ok' && row.body) return logoServe(res, row);   // stale but real beats nothing
      return res.status(404).end();
    }
    await logoUpsert(source, id, url, ct, buf, 'ok', null);
    return logoServe(res, { content_type: ct, body: buf });
  } catch (e) { fail(res, e, 'logo'); }
});

/* ------------------------------------------------------------------ queue */

// GET /api/oem/migrate/queue?inactive=1
router.get('/queue', read(), async (req, res) => {
  try { res.json(await M.queue({ includeInactive: req.query.inactive === '1' })); }
  catch (e) { fail(res, e, 'queue'); }
});

// GET /api/oem/migrate/coverage
router.get('/coverage', read(), async (req, res) => {
  try { res.json(await M.coverage()); }
  catch (e) { fail(res, e, 'coverage'); }
});

/* ------------------------------------------------------------------- scan */

// POST /api/oem/migrate/apps/:id/scan — live Okta (+ Graph read) scan of one app; returns the assessment
router.post('/apps/:id/scan', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const steps = [];
    const r = await M.scanApp(req.params.id, (m, level) => steps.push({ level: level || 'info', msg: m }), { actor: actorOf(req) });
    await audit(req, 'oem_migrate_scan', { okta_id: req.params.id, ok: r.ok, complete: r.complete, errors: r.errors });
    if (!r.ok) return res.status(502).json({ ok: false, error: 'Okta read failed', errors: r.errors });
    const a = await M.assessment(req.params.id);
    res.json({ ok: true, complete: r.complete, errors: r.errors, log: steps, assessment: a });
  } catch (e) { fail(res, e, 'scan'); }
});

// POST /api/oem/migrate/scan-all  {onlyActive?: bool, ids?: []}
router.post('/scan-all', json, admin(), async (req, res) => {
  try {
    const onlyActive = !!(req.body && req.body.onlyActive);
    const ids = req.body && Array.isArray(req.body.ids) ? req.body.ids.filter((x) => OKTA_ID.test(String(x))).slice(0, 500) : null;
    const r = await L.startJob('migrate-scan-all', actorOf(req), (log) => M.scanAll(log, { actor: actorOf(req), onlyActive, ids }));
    if (r.conflict) return res.status(409).json({ error: 'already running', conflict: r.conflict, note: 'Duplicate runs are refused; follow the running job instead.' });
    await audit(req, 'oem_job_start', { job: 'migrate-scan-all', id: r.id, onlyActive, ids: ids ? ids.length : null });
    res.status(202).json({ ok: true, id: r.id, key: 'migrate-scan-all', label: 'Scan Okta applications (live, paced)' });
  } catch (e) { fail(res, e, 'scan-all'); }
});

// GET /api/oem/migrate/apps/:id/scan — the stored scan (normalized model + redacted raw)
router.get('/apps/:id/scan', read(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const s = await M.loadScan(req.params.id);
    if (!s) return res.status(404).json({ error: 'not scanned', note: 'Run a scan first; nothing is assumed about an unscanned app.' });
    res.json(s);
  } catch (e) { fail(res, e, 'scan detail'); }
});

// GET /api/oem/migrate/apps/:id/assessment
router.get('/apps/:id/assessment', read(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const a = await M.assessment(req.params.id);
    if (!a) return res.status(404).json({ error: 'not scanned', note: 'Run a scan first.' });
    const [migs] = await pool.query(`SELECT id, status, protocol, readiness, created_by, created_at, approved_by, approved_at, pushed_by, pushed_at, finished_at, error, job_id FROM oem_migration WHERE okta_id=? ORDER BY id DESC LIMIT 10`, [req.params.id]);
    a.migrations = migs;
    a.action = M.actionFor(a, latestOf(migs), { workState: a.workState, vendorRepointed: a.vendorRepointed, manual: a.migratedManual, migrated: a.migrated });
    if (USAGE) { try { a.usage = await USAGE.forApp(req.params.id); } catch (e) { a.usage = { error: e.message }; } }
    if (TSI) { try { a.testSignIn = await TSI.list(req.params.id, 5); } catch (e) { a.testSignIn = null; } }
    res.json(a);
  } catch (e) { fail(res, e, 'assessment'); }
});
/* The migration whose status decides the row's action: the newest one that is not a discarded plan. */
const latestOf = (migs) => (migs || []).find((m) => !['cancelled', 'rolled_back', 'preflight_failed'].includes(m.status)) || null;
const appEvent = (oktaId, actor, ev, previous, value, detail) => pool.query(`INSERT INTO oem_migration_event (migration_id, okta_id, actor, event, previous, new_value, result, detail) VALUES (0,?,?,?,?,?,'ok',?)`,
  [oktaId, actor, ev, previous === undefined ? null : JSON.stringify(previous), value === undefined ? null : JSON.stringify(value), String(detail || '').slice(0, 2000)]);

// GET /api/oem/migrate/sso-methods — Entra SSO methods (Microsoft Learn, dated) and what this engine does for each
router.get('/sso-methods', read(), (req, res) => res.json(M.SSO_METHODS));

// POST /api/oem/migrate/apps/:id/inputs {values:{key: value|null}} — what a person supplies because the scan cannot know it
router.post('/apps/:id/inputs', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const id = req.params.id; const actor = actorOf(req);
    const [[row]] = await pool.query(`SELECT inputs, owner FROM oem_app_scan WHERE okta_id=?`, [id]);
    if (!row) return res.status(404).json({ error: 'not scanned', note: 'Scan the app first; inputs are recorded on the scan.' });
    const { values, errors } = M.sanitizeInputs(req.body && req.body.values);
    if (errors.length) return res.status(400).json({ error: 'invalid input', fields: errors });
    const cur = j(row.inputs, null) || {}; const vals = Object.assign({}, cur.values || {}); const meta = Object.assign({}, cur.meta || {});
    const at = nowIso(); const changed = []; let owner = row.owner || null; let ownerChanged = false;
    for (const [k, v] of Object.entries(values)) {
      if (k === 'owner') { if ((v || null) !== owner) { ownerChanged = true; owner = v || null; } continue; }
      const prev = vals[k] === undefined ? null : vals[k];
      if (JSON.stringify(prev) === JSON.stringify(v)) continue;
      changed.push({ key: k, previous: prev, value: v });
      if (v === null) { delete vals[k]; delete meta[k]; } else { vals[k] = v; meta[k] = { by: actor, at }; }
    }
    if (ownerChanged) {
      await pool.query(`UPDATE oem_app_scan SET owner=? WHERE okta_id=?`, [owner, id]);
      await appEvent(id, actor, 'owner_recorded', { owner: row.owner || null }, { owner }, 'Application owner recorded by ' + actor);
    }
    if (changed.length) {
      await pool.query(`UPDATE oem_app_scan SET inputs=? WHERE okta_id=?`, [JSON.stringify({ values: vals, meta }), id]);
      await appEvent(id, actor, 'inputs_recorded', Object.fromEntries(changed.map((c) => [c.key, c.previous])), Object.fromEntries(changed.map((c) => [c.key, c.value])), 'Inputs recorded by ' + actor + ': ' + changed.map((c) => c.key).join(', '));
    }
    await audit(req, 'oem_migrate_inputs', { okta_id: id, changed: changed.map((c) => c.key), owner_changed: ownerChanged }, id);
    const a = await M.assessment(id);
    res.json({ ok: true, changed: changed.map((c) => c.key), ownerChanged, owner, inputs: a ? a.inputs : null, inputsNeeded: a ? a.inputsNeeded : null, inputsSummary: a ? a.inputsSummary : null, assessment: a });
  } catch (e) { fail(res, e, 'inputs'); }
});

// POST /api/oem/migrate/apps/:id/link-probe {target?} — follow the tile's link (this app or a same-name twin) and record where it lands
router.post('/apps/:id/link-probe', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const id = req.params.id; const actor = actorOf(req);
    const [[wi]] = await pool.query(`SELECT facts FROM oem_work_item WHERE item_key=?`, ['app:' + id]);
    const facts = wi ? j(wi.facts, {}) || {} : {};
    const before = await M.migratedContext(id, facts, null);
    const target = String((req.body && req.body.target) || id);
    const t = before.probeTargets.find((x) => x.oktaId === target);
    if (!t) return res.status(400).json({ error: 'nothing to follow', note: 'Only this app\'s own tile URL or a same-name twin\'s can be checked.', targets: before.probeTargets.map((x) => ({ oktaId: x.oktaId, label: x.label, relation: x.relation })) });
    if (t.launcher) return res.status(409).json({ error: 'already evidence', note: 'This tile is an Entra My Apps launcher link; no probe is needed.' });
    const probe = await LP.probe(t.oktaId, t.url, actor);
    await appEvent(id, actor, 'link_probed', null, { target: t.oktaId, url: t.url, idp: probe.idp, finalUrl: probe.finalUrl }, `"Check where it points" on ${t.label} (${t.relation}): ${probe.detail}`);
    await audit(req, 'oem_migrate_link_probe', { okta_id: id, target: t.oktaId, idp: probe.idp }, id);
    const a = await M.assessment(id);
    const migrated = a ? a.migrated : (await M.migratedContext(id, facts, null)).migrated;
    res.json({ ok: true, probe, migrated, probeTargets: a ? a.probeTargets : before.probeTargets });
  } catch (e) { fail(res, e, 'link probe'); }
});

// POST /api/oem/migrate/apps/:id/mark-migrated {note, entraId?, signInTested?, confirm:true}
// A person records that users already sign in to this application through Entra (e.g. the vendor rebranded and the
// twin detection cannot see it). A record, not verification: it hides Stage in Entra so nobody stages a second copy.
// Reversible with /mark-migrated/clear; cleared records stay as history.
router.post('/apps/:id/mark-migrated', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const id = req.params.id; const actor = actorOf(req); const b = req.body || {};
    const note = String(b.note || '').trim().slice(0, 1000);
    if (note.length < 5) return res.status(400).json({ error: 'Say how you know (at least 5 characters): e.g. which Entra app is live and how it was checked.' });
    if (b.confirm !== true) return res.status(400).json({ error: 'Tick the confirmation: users sign in to this application through Entra today.' });
    const [[app]] = await pool.query(`SELECT okta_id, label FROM okta_apps WHERE okta_id=?`, [id]);
    if (!app) return res.status(404).json({ error: 'no such Okta application in the mirror' });
    let entra = null;
    const wanted = String(b.entraId || '').trim();
    if (wanted) {
      const [rows] = await pool.query(`SELECT entra_id, app_id, display_name FROM entra_apps WHERE entra_id=? OR app_id=? LIMIT 2`, [wanted, wanted]);
      if (!rows.length) return res.status(400).json({ error: 'No Entra application with that object id / app id in the mirror. Pick one from the list, or leave it empty.' });
      entra = rows[0];
    } else {
      const [[wi]] = await pool.query(`SELECT facts FROM oem_work_item WHERE item_key=?`, ['app:' + id]);
      const f = wi ? j(wi.facts, {}) || {} : {};
      if (f.match && f.match.decision === 'manual_confirmed' && f.match.entraId) entra = { entra_id: f.match.entraId, display_name: f.match.entraName || null };
    }
    const [[prev]] = await pool.query(`SELECT okta_id, entra_id, entra_name, note, sign_in_tested, marked_by, marked_at, cleared_at FROM oem_app_migrated WHERE okta_id=?`, [id]);
    const tested = !!b.signInTested;
    await pool.query(`INSERT INTO oem_app_migrated (okta_id, entra_id, entra_name, note, sign_in_tested, marked_by, marked_at, cleared_by, cleared_at, cleared_note) VALUES (?,?,?,?,?,?,NOW(),NULL,NULL,NULL)
      ON DUPLICATE KEY UPDATE entra_id=VALUES(entra_id), entra_name=VALUES(entra_name), note=VALUES(note), sign_in_tested=VALUES(sign_in_tested), marked_by=VALUES(marked_by), marked_at=NOW(), cleared_by=NULL, cleared_at=NULL, cleared_note=NULL`,
      [id, entra ? entra.entra_id : null, entra ? entra.display_name : null, note, tested ? 1 : 0, actor]);
    const rec = { by: actor, at: nowIso(), note, entraId: entra ? entra.entra_id : null, entraName: entra ? entra.display_name : null, signInTested: tested };
    await appEvent(id, actor, 'marked_migrated', prev && !prev.cleared_at ? { by: prev.marked_by, at: prev.marked_at, note: prev.note, entraId: prev.entra_id } : null, rec, `Marked as migrated by ${actor}: ${note}${entra ? ' (Entra app: ' + entra.display_name + ')' : ''}. A record, not verification; Stage in Entra is hidden for this application.`);
    await audit(req, 'oem_migrate_mark_migrated', { okta_id: id, entra_id: rec.entraId, sign_in_tested: tested }, id);
    const a = await M.assessment(id);
    const [migs] = await pool.query(`SELECT id, status, finished_at, created_at, job_id FROM oem_migration WHERE okta_id=? ORDER BY id DESC LIMIT 10`, [id]);
    res.json({ ok: true, migratedManual: rec, alreadyMigrated: a ? a.alreadyMigrated : null, action: a ? M.actionFor(a, latestOf(migs), { workState: a.workState, vendorRepointed: a.vendorRepointed, manual: rec, migrated: a.migrated }) : { code: 'done', label: 'Migrated — recorded by ' + actor + ' (not verified)' } });
  } catch (e) { fail(res, e, 'mark migrated'); }
});
router.post('/apps/:id/mark-migrated/clear', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const id = req.params.id; const actor = actorOf(req);
    const note = String((req.body && req.body.note) || '').trim().slice(0, 500);
    if (note.length < 5) return res.status(400).json({ error: 'Say why the record is wrong (at least 5 characters).' });
    const [[prev]] = await pool.query(`SELECT entra_id, entra_name, note, sign_in_tested, marked_by, marked_at FROM oem_app_migrated WHERE okta_id=? AND cleared_at IS NULL`, [id]);
    if (!prev) return res.status(404).json({ error: 'no active "marked as migrated" record for this application' });
    await pool.query(`UPDATE oem_app_migrated SET cleared_by=?, cleared_at=NOW(), cleared_note=? WHERE okta_id=?`, [actor, note, id]);
    await appEvent(id, actor, 'marked_migrated_cleared', { by: prev.marked_by, at: prev.marked_at, note: prev.note, entraId: prev.entra_id }, null, `"Marked as migrated" record cleared by ${actor}: ${note}. The earlier record stays as history.`);
    await audit(req, 'oem_migrate_mark_migrated_clear', { okta_id: id }, id);
    const a = await M.assessment(id);
    const [migs] = await pool.query(`SELECT id, status, finished_at, created_at, job_id FROM oem_migration WHERE okta_id=? ORDER BY id DESC LIMIT 10`, [id]);
    res.json({ ok: true, migratedManual: null, alreadyMigrated: a ? a.alreadyMigrated : null, action: a ? M.actionFor(a, latestOf(migs), { workState: a.workState, vendorRepointed: a.vendorRepointed, manual: null, migrated: a.migrated }) : null });
  } catch (e) { fail(res, e, 'mark migrated clear'); }
});

// POST /api/oem/migrate/apps/:id/vendor-repointed {done, note} — a person records that the vendor was repointed (history, not verification)
router.post('/apps/:id/vendor-repointed', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const id = req.params.id; const actor = actorOf(req);
    const [[row]] = await pool.query(`SELECT inputs FROM oem_app_scan WHERE okta_id=?`, [id]);
    if (!row) return res.status(404).json({ error: 'not scanned' });
    const cur = j(row.inputs, null) || {}; const meta = Object.assign({}, cur.meta || {});
    const prev = meta.vendorRepointed || null;
    const done = !!(req.body && req.body.done);
    const note = String((req.body && req.body.note) || '').trim().slice(0, 500);
    if (done) meta.vendorRepointed = { by: actor, at: nowIso(), note: note || null }; else delete meta.vendorRepointed;
    await pool.query(`UPDATE oem_app_scan SET inputs=? WHERE okta_id=?`, [JSON.stringify({ values: cur.values || {}, meta }), id]);
    await appEvent(id, actor, done ? 'vendor_repointed' : 'vendor_repointed_cleared', prev, meta.vendorRepointed || null, (done ? 'Vendor repointed — recorded by ' + actor + (note ? ': ' + note : '') : 'Vendor-repointed record cleared by ' + actor) + '. History, not verification.');
    await audit(req, 'oem_migrate_vendor_repointed', { okta_id: id, done, note }, id);
    const a = await M.assessment(id);
    const [migs] = await pool.query(`SELECT id, status, finished_at, created_at, job_id FROM oem_migration WHERE okta_id=? ORDER BY id DESC LIMIT 10`, [id]);
    res.json({ ok: true, vendorRepointed: meta.vendorRepointed || null, action: a ? M.actionFor(a, latestOf(migs), { workState: a.workState, vendorRepointed: meta.vendorRepointed || null, manual: a.migratedManual, migrated: a.migrated }) : null, appSide: a ? a.appSide : null });
  } catch (e) { fail(res, e, 'vendor repointed'); }
});

// POST /api/oem/migrate/apps/:id/owner {owner}
router.post('/apps/:id/owner', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const owner = String((req.body && req.body.owner) || '').trim().slice(0, 255);
    const [[cur]] = await pool.query(`SELECT owner FROM oem_app_scan WHERE okta_id=?`, [req.params.id]);
    if (!cur) return res.status(404).json({ error: 'not scanned', note: 'Scan the app first; the owner is recorded on the scan.' });
    await pool.query(`UPDATE oem_app_scan SET owner=? WHERE okta_id=?`, [owner || null, req.params.id]);
    await pool.query(`INSERT INTO oem_migration_event (migration_id, okta_id, actor, event, previous, new_value, result, detail) VALUES (0,?,?,'owner_recorded',?,?,'ok',?)`, [req.params.id, actorOf(req), JSON.stringify({ owner: cur.owner || null }), JSON.stringify({ owner: owner || null }), 'Application owner recorded by ' + actorOf(req)]);
    await audit(req, 'oem_migrate_owner', { okta_id: req.params.id, owner });
    res.json({ ok: true, owner: owner || null, previous: cur.owner || null });
  } catch (e) { fail(res, e, 'owner'); }
});

/* ------------------------------------------------- dual-IdP priority + vendor guides */

// GET /api/oem/migrate/guides — every written vendor guide (summary) and what "written" means
router.get('/guides', read(), async (req, res) => {
  try { res.json({ guides: VG.list(), note: 'A guide exists only when the vendor documentation was fetched and read on checkedAt; every source is linked. Applications without a guide say so — nothing is generated from memory.', browserSurface: VG.SURFACE }); }
  catch (e) { fail(res, e, 'guides'); }
});

// GET /api/oem/migrate/apps/:id/guide — the vendor guide + this app's coexistence signal (works before a scan)
router.get('/apps/:id/guide', read(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const [[a]] = await pool.query(`SELECT a.okta_id, a.name, a.label, a.status, a.sign_on_mode, s.coexistence, s.owner, w.facts FROM okta_apps a LEFT JOIN oem_app_scan s ON s.okta_id=a.okta_id LEFT JOIN oem_work_item w ON w.item_key=CONCAT('app:', a.okta_id) WHERE a.okta_id=?`, [req.params.id]);
    if (!a) return res.status(404).json({ error: 'unknown Okta app' });
    const facts = j(a.facts, {}) || {};
    const ev = await CX.loadEvidence();
    const app = { oktaId: a.okta_id, name: a.name, label: a.label, oktaStatus: a.status, signOnMode: a.sign_on_mode };
    const cx = CX.coexistenceFor({ app, facts, recorded: j(a.coexistence, null), evidence: ev });
    const g = VG.guideFor(app);
    // tenant facts the guide's steps refer to (Okta's current SAML values; Entra apps that already exist) — read, not assumed
    const scan = await M.loadScan(req.params.id);
    const m = scan && scan.model;
    const okta = m ? { signOnMode: m.auth.type, acs: (m.saml && m.saml.acsUrls) || [], entityId: (m.saml && m.saml.entityId) || null, loginUrl: (m.identity && m.identity.loginUrl) || null, users: m.assignments && m.assignments.users && m.assignments.users.count !== undefined ? m.assignments.users.count : null, usersPartial: !!(m.assignments && m.assignments.users && m.assignments.users.partial), groups: ((m.assignments && m.assignments.groups) || []).length } : null;
    const [entraApps] = await pool.query(`SELECT entra_id, app_id, display_name, preferred_single_sign_on_mode, account_enabled, assigned_user_count, assigned_group_count, last_synced_at FROM entra_apps WHERE seen_in_last_sync=1 AND (entra_id=? OR display_name LIKE ?) LIMIT 6`, [facts.match && facts.match.entraId || '', '%' + String(a.label || '').replace(/[%_]/g, '').split(/\s+/)[0] + '%']);
    res.json({ oktaId: a.okta_id, label: a.label, name: a.name, oktaStatus: a.status, owner: a.owner || null, scanned: !!scan, coexistence: cx, guide: g || null,
      tenant: { okta, entraApps: entraApps.map((e) => ({ entraId: e.entra_id, appId: e.app_id, name: e.display_name, ssoMode: e.preferred_single_sign_on_mode, enabled: !!e.account_enabled, users: e.assigned_user_count, groups: e.assigned_group_count, mirroredAt: e.last_synced_at })), match: facts.match ? { decision: facts.match.decision, entraName: facts.match.entraName || null, entraId: facts.match.entraId || null } : null },
      canAct: canAct(await pageLevel(req), req) });
  } catch (e) { fail(res, e, 'guide'); }
});

// POST /api/oem/migrate/apps/:id/coexistence {supported: true|false|null, note} — the technician's answer
router.post('/apps/:id/coexistence', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const b = req.body || {};
    const supported = b.supported === null || b.supported === undefined || b.supported === '' ? null : (b.supported === true || b.supported === 'true' || b.supported === 'yes');
    const note = String(b.note || '').trim().slice(0, 500);
    if (supported !== null && supported === false && !note) return res.status(400).json({ error: 'note required', note: 'Say how you know the vendor accepts only one IdP (doc link, vendor ticket, console observation).' });
    const r = await CX.record(req.params.id, { supported, note, actor: actorOf(req) });
    if (r.error) return send(res, r);
    await pool.query(`INSERT INTO oem_migration_event (migration_id, okta_id, actor, event, previous, new_value, result, detail) VALUES (0,?,?,'coexistence_recorded',?,?,'ok',?)`, [req.params.id, actorOf(req), JSON.stringify(r.previous), JSON.stringify(r.coexistence), (supported === null ? 'Dual-IdP answer cleared' : supported ? 'Recorded: accepts two IdPs' : 'Recorded: single IdP') + ' by ' + actorOf(req)]);
    await audit(req, 'oem_migrate_coexistence', { okta_id: req.params.id, supported, note });
    res.json(r);
  } catch (e) { fail(res, e, 'coexistence'); }
});

// POST /api/oem/migrate/apps/:id/okta-usage — one live Okta System Log read (SSO events naming the app), cached
router.post('/apps/:id/okta-usage', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const r = await CX.checkOktaUsage(req.params.id, { actor: actorOf(req) });
    await audit(req, 'oem_migrate_okta_usage', { okta_id: req.params.id, count: r.count, error: r.error });
    res.json(r);
  } catch (e) { fail(res, e, 'okta usage'); }
});

// POST /api/oem/migrate/okta-usage/sweep — the same read for every candidate (active app with a confirmed, SSO-configured Entra app)
router.post('/okta-usage/sweep', json, admin(), async (req, res) => {
  try {
    const [apps] = await pool.query(`SELECT a.okta_id, a.name, a.label, a.status, w.facts FROM okta_apps a LEFT JOIN oem_work_item w ON w.item_key=CONCAT('app:', a.okta_id) WHERE a.seen_in_last_sync=1 AND a.status='ACTIVE'`);
    const cands = apps.filter((a) => CX.sweepCandidate({ oktaId: a.okta_id, oktaStatus: a.status }, j(a.facts, {}) || {}));
    if (cands.length > 60) return res.status(409).json({ error: 'too many candidates', count: cands.length, note: 'More than 60 Okta System Log reads in one sweep would hit the log rate limit; check apps one at a time from the drawer.' });
    const results = [];
    for (const a of cands) { try { results.push(await CX.checkOktaUsage(a.okta_id, { actor: actorOf(req) })); } catch (e) { results.push({ oktaId: a.okta_id, error: e.message, count: null }); } }
    await audit(req, 'oem_migrate_okta_usage_sweep', { candidates: cands.length, failed: results.filter((r) => r.error).length });
    res.json({ checkedAt: L.nowIso(), candidates: cands.length, results, note: 'Only applications with a confirmed, SSO-configured Entra app were read; everything else stays "not checked".' });
  } catch (e) { fail(res, e, 'okta usage sweep'); }
});

// GET /api/oem/migrate/apps/:id/events — audit history for the app (owner records, migrations, steps)
router.get('/apps/:id/events', read(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const [rows] = await pool.query(`SELECT id, migration_id, at, actor, event, step_key, previous, new_value, result, detail FROM oem_migration_event WHERE okta_id=? ORDER BY id DESC LIMIT 200`, [req.params.id]);
    res.json(rows.map((r) => Object.assign(r, { previous: j(r.previous, null), new_value: j(r.new_value, null) })));
  } catch (e) { fail(res, e, 'events'); }
});

/* ----------------------------------------------------- migration wizard */
// Pre-flight → Plan → Approve → Push (job) → Verify → Rollback. Every state below is read back from
// oem_migration; a response never says "succeeded" unless the exec engine recorded that after verification.

const MIG_ID = /^\d{1,9}$/;
const migOk = (req, res) => { if (!MIG_ID.test(req.params.mid)) { res.status(400).json({ error: 'bad migration id' }); return false; } return true; };
// Refusals are {error, status?: <http code>}; a migration record carries an id, a status WORD and may legitimately
// hold an error text (failed / cancelled), so it must never be mistaken for a refusal.
const send = (res, r, okStatus = 200) => {
  if (r && r.error && r.id === undefined) return res.status(Number.isInteger(r.status) ? r.status : 400).json(r);
  res.status(okStatus).json(r);
};

// POST /api/oem/migrate/apps/:id/preflight {inputs?: {entityId, acsUrls:[], displayName}} — live rescan + plan + safety checks + snapshot
router.post('/apps/:id/preflight', json, admin(), async (req, res) => {
  if (!idOk(req, res)) return;
  try {
    const raw = (req.body && req.body.inputs) || {};
    const inputs = {};
    if (raw.entityId) inputs.entityId = String(raw.entityId).trim().slice(0, 500);
    if (raw.acsUrls) inputs.acsUrls = [].concat(raw.acsUrls).map((u) => String(u).trim().slice(0, 500)).filter(Boolean).slice(0, 20);
    if (raw.displayName) inputs.displayName = String(raw.displayName).trim().slice(0, 120);
    if (raw.skipGroupCreate) inputs.skipGroupCreate = true;
    const before = await M.assessment(req.params.id);
    if (before && before.alreadyMigrated) return res.status(409).json({ error: 'already migrated: ' + before.alreadyMigrated.label + ' — nothing to stage.', alreadyMigrated: before.alreadyMigrated, note: 'Staging would create a second Entra application. If the record is wrong, clear it under "Already migrated" on the application first.' });
    const steps = [];
    const m = await X.preflight(req.params.id, actorOf(req), { inputs, log: (msg, level) => steps.push({ level: level || 'info', msg }) });
    await audit(req, 'oem_migrate_preflight', { okta_id: req.params.id, migration_id: m.id, status: m.status, failed: m.preflight.summary.failed, warnings: m.preflight.summary.warnings, inputs: Object.keys(inputs) });
    res.json(Object.assign({ log: steps }, m));
  } catch (e) { fail(res, e, 'preflight'); }
});

// GET /api/oem/migrate/migrations?okta=<id>&limit=50
router.get('/migrations', read(), async (req, res) => {
  try {
    const oktaId = req.query.okta && OKTA_ID.test(String(req.query.okta)) ? String(req.query.okta) : null;
    res.json(await X.listMigrations({ oktaId, limit: Math.min(200, Number(req.query.limit) || 50) }));
  } catch (e) { fail(res, e, 'migrations'); }
});

// GET /api/oem/migrate/migrations/:mid — full record: plan, pre-flight, results, verification, events
router.get('/migrations/:mid', read(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const m = await X.getMigration(Number(req.params.mid));
    if (!m) return res.status(404).json({ error: 'no such migration' });
    m.secretHeld = X.secretHeld(m.id);
    if (m.snapshot) m.snapshot = { takenAt: m.snapshot.takenAt, oktaId: m.snapshot.oktaId, assessment: m.snapshot.assessment, model: m.snapshot.model, raw: L.redact(m.snapshot.raw) };
    res.json(m);
  } catch (e) { fail(res, e, 'migration'); }
});

// POST /api/oem/migrate/migrations/:mid/approve {confirm: "<app name>", reason, acknowledge: [warning keys]}
router.post('/migrations/:mid/approve', json, admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const b = req.body || {};
    const r = await X.approve(Number(req.params.mid), actorOf(req), { confirm: b.confirm, reason: b.reason, acknowledge: Array.isArray(b.acknowledge) ? b.acknowledge.map(String) : [] });
    await audit(req, 'oem_migrate_approve', { migration_id: req.params.mid, ok: !r.error, error: r.error || null, reason: b.reason ? String(b.reason).slice(0, 300) : null });
    send(res, r);
  } catch (e) { fail(res, e, 'approve'); }
});

// POST /api/oem/migrate/migrations/:mid/push — starts the push job (202 {jobId}); refuses when a permission is missing
router.post('/migrations/:mid/push', json, admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const r = await X.push(Number(req.params.mid), actorOf(req));
    await audit(req, 'oem_migrate_push', { migration_id: req.params.mid, ok: !r.error, error: r.error || null, job: r.jobId || null });
    send(res, r, 202);
  } catch (e) { fail(res, e, 'push'); }
});

// POST /api/oem/migrate/migrations/:mid/verify — live re-read of the Entra objects + sign-in evidence
router.post('/migrations/:mid/verify', json, admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const r = await X.verify(Number(req.params.mid), actorOf(req));
    await audit(req, 'oem_migrate_verify', { migration_id: req.params.mid, ok: !r.error, status: r.status || null, summary: r.verification ? r.verification.summary : null });
    send(res, r);
  } catch (e) { fail(res, e, 'verify'); }
});

// POST /api/oem/migrate/migrations/:mid/rollback {confirm: "ROLLBACK <app name>", reason} — removes created objects in reverse order (job)
router.post('/migrations/:mid/rollback', json, admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const b = req.body || {};
    const r = await X.rollback(Number(req.params.mid), actorOf(req), { confirm: b.confirm, reason: b.reason });
    await audit(req, 'oem_migrate_rollback', { migration_id: req.params.mid, ok: !r.error, error: r.error || null, reason: b.reason ? String(b.reason).slice(0, 300) : null });
    send(res, r, 202);
  } catch (e) { fail(res, e, 'rollback'); }
});

// POST /api/oem/migrate/migrations/:mid/cancel {reason} — discard a plan that has not been pushed
router.post('/migrations/:mid/cancel', json, admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const b = req.body || {};
    const r = await X.cancel(Number(req.params.mid), actorOf(req), { reason: b.reason });
    await audit(req, 'oem_migrate_cancel', { migration_id: req.params.mid, ok: !r.error, error: r.error || null, reason: b.reason ? String(b.reason).slice(0, 300) : null });
    send(res, r);
  } catch (e) { fail(res, e, 'cancel'); }
});

// GET /api/oem/migrate/migrations/:mid/secret — one-time read of a client secret created by the push (pusher only)
router.get('/migrations/:mid/secret', admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const m = await X.getMigration(Number(req.params.mid), { events: false });
    if (!m) return res.status(404).json({ error: 'no such migration' });
    if (m.pushedBy && m.pushedBy !== actorOf(req)) { await audit(req, 'oem_migrate_secret_denied', { migration_id: req.params.mid, pushed_by: m.pushedBy }); return res.status(403).json({ error: 'only the technician who pushed can read the secret', pushedBy: m.pushedBy }); }
    const r = X.secretOnce(m.id, actorOf(req));
    await audit(req, 'oem_migrate_secret_read', { migration_id: req.params.mid, ok: !r.error });
    res.set('Cache-Control', 'no-store');
    send(res, r);
  } catch (e) { fail(res, e, 'secret'); }
});

// GET /api/oem/migrate/migrations/:mid/secrets — key ids / names / dates of the secrets on the pushed application (no values)
router.get('/migrations/:mid/secrets', admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try { send(res, await X.listSecrets(Number(req.params.mid))); } catch (e) { fail(res, e, 'secrets'); }
});
// POST /api/oem/migrate/migrations/:mid/secrets {days, reason} — issue a NEW client secret for the vendor hand-off; shown once, never stored
router.post('/migrations/:mid/secrets', json, admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const r = await X.issueSecret(Number(req.params.mid), actorOf(req), { days: req.body && req.body.days, reason: req.body && req.body.reason });
    await audit(req, 'oem_migrate_secret_issued', { migration_id: req.params.mid, ok: !r.error, key_id: r.keyId || null });
    res.set('Cache-Control', 'no-store');
    send(res, r, 201);
  } catch (e) { fail(res, e, 'issue secret'); }
});
// POST /api/oem/migrate/migrations/:mid/secrets/remove {keyId, confirm:"REMOVE <keyId[0:8]>", reason} — destructive
router.post('/migrations/:mid/secrets/remove', json, admin(), async (req, res) => {
  if (!migOk(req, res)) return;
  try {
    const b = req.body || {};
    const r = await X.removeSecret(Number(req.params.mid), actorOf(req), { keyId: b.keyId, confirm: b.confirm, reason: b.reason });
    await audit(req, 'oem_migrate_secret_removed', { migration_id: req.params.mid, ok: !r.error, key_id: b.keyId || null });
    send(res, r);
  } catch (e) { fail(res, e, 'remove secret'); }
});

/* ------------------------------------------------------------------- bulk */

const idList = (v, re, cap) => (Array.isArray(v) ? v.map(String).filter((x) => re.test(x)).slice(0, cap) : []);

// POST /api/oem/migrate/bulk/preflight {ids: [oktaId]} → 202 job; each app pre-flights independently
router.post('/bulk/preflight', json, admin(), async (req, res) => {
  try {
    const ids = idList(req.body && req.body.ids, OKTA_ID, 200);
    if (!ids.length) return res.status(400).json({ error: 'ids required' });
    const r = await X.bulkPreflight(ids, actorOf(req));
    if (r.conflict) return res.status(409).json({ error: 'already running', conflict: r.conflict });
    await audit(req, 'oem_job_start', { job: 'migrate-bulk-preflight', id: r.id, count: ids.length });
    res.status(202).json({ ok: true, id: r.id, key: 'migrate-bulk-preflight', label: `Pre-flight ${ids.length} application(s)` });
  } catch (e) { fail(res, e, 'bulk preflight'); }
});

// POST /api/oem/migrate/bulk/approve {migrationIds: [], confirm: "MIGRATE <n> APPLICATIONS", reason}
router.post('/bulk/approve', json, admin(), async (req, res) => {
  try {
    const b = req.body || {};
    const ids = idList(b.migrationIds, MIG_ID, 200).map(Number);
    if (!ids.length) return res.status(400).json({ error: 'migrationIds required' });
    const r = await X.bulkApprove(ids, actorOf(req), { confirm: b.confirm, reason: b.reason });
    await audit(req, 'oem_migrate_bulk_approve', { count: ids.length, approved: r.approved, error: r.error || null });
    send(res, r);
  } catch (e) { fail(res, e, 'bulk approve'); }
});

// POST /api/oem/migrate/bulk/push {migrationIds: []} → 202 job; apps are pushed one after another, each independently
router.post('/bulk/push', json, admin(), async (req, res) => {
  try {
    const ids = idList(req.body && req.body.migrationIds, MIG_ID, 200).map(Number);
    if (!ids.length) return res.status(400).json({ error: 'migrationIds required' });
    const r = await X.bulkPush(ids, actorOf(req));
    await audit(req, 'oem_migrate_bulk_push', { count: ids.length, ok: !r.error, error: r.error || null, job: r.jobId || null });
    send(res, r, 202);
  } catch (e) { fail(res, e, 'bulk push'); }
});

module.exports = router;
