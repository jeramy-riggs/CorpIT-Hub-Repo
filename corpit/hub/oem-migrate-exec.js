/**
 * oem-migrate-exec.js — the part of the Okta → Entra application migration engine that changes things.
 *
 *   Pre-Flight → Plan → Approve → Stage in Entra (push job) → Application side → Verify → (Rollback)
 *
 * This is the ONLY module that writes to Microsoft Entra. Every write goes through graphCall(), which
 * refuses when the write credential does not hold the permission the call needs, records the call as an
 * oem_migration_event with the previous value where one exists, and never retries. Nothing here writes to
 * Okta: the Okta application stays active until the existing lifecycle action deactivates it with its own
 * typed confirmation. A migration only reaches "succeeded" after every planned Entra write returned 2xx
 * AND a live re-read matched the plan; anything less is "warnings" (with the list) or "failed" (with the
 * step, the error, what succeeded, what did not run, and how to recover).
 */
'use strict';
const crypto = require('crypto');
const L = require('./oem-lib');
const { defaultEntraName } = require('./oem-app-name');
const M = require('./oem-migrate');
const { pool, j, nowIso } = L;
const { PERM, CLS, permCheck } = M;

const NON_GALLERY_TEMPLATE = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621';
const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';
// Microsoft Graph delegated scopes an OIDC relying party normally needs (well-known ids, v1.0).
const GRAPH_SCOPE_IDS = { openid: '37f7f235-527c-4136-accd-4a02d197296e', profile: '14dad69e-099b-42c9-810b-d002981feec1', email: '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0', 'User.Read': 'e1fe6dd8-ba31-4d61-89e7-88639da4683d', offline_access: '7427e0e9-2fba-42fe-b0c0-848c9e6a8182' };
const DEFAULT_ROLE = '00000000-0000-0000-0000-000000000000';
const NAMEID_CLAIM = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';
const STATUS = { PLANNED: 'planned', PF_FAIL: 'preflight_failed', PF_PASS: 'preflight_passed', APPROVED: 'approved', RUNNING: 'running', OK: 'succeeded', WARN: 'warnings', FAILED: 'failed', ROLLED: 'rolled_back', CANCELLED: 'cancelled' };

/* ------------------------------------------------------------------ small helpers */

/** Key-order-independent hash: MySQL JSON columns reorder object keys, so the stored plan must hash the same. */
function stable(v) { if (Array.isArray(v)) return v.map(stable); if (v && typeof v === 'object') { const o = {}; for (const k of Object.keys(v).sort()) if (v[k] !== undefined) o[k] = stable(v[k]); return o; } return v; }
const hash = (v) => crypto.createHash('sha256').update(JSON.stringify(stable(v))).digest('hex').slice(0, 24);
const plusDays = (d) => new Date(Date.now() + d * 86400000).toISOString();
const short = (v, n = 300) => String(v === undefined ? '' : v).slice(0, n);
const uniq = (a) => [...new Set(a.filter(Boolean))];
const isHttps = (u) => /^https:\/\//i.test(String(u || ''));
const isLocal = (u) => /^https?:\/\/(localhost|127\.0\.0\.1)([:/]|$)/i.test(String(u || ''));

/** Substitute {{appObjectId}} / {{spObjectId}} / {{appId}} / {{templateRoleId}} in a plan payload at run time. */
function fill(v, state) {
  if (typeof v === 'string') return v.replace(/\{\{(\w+)\}\}/g, (m, k) => (state[k] === undefined || state[k] === null ? m : String(state[k])));
  if (Array.isArray(v)) return v.map((x) => fill(x, state));
  if (v && typeof v === 'object') { const o = {}; for (const [k, x] of Object.entries(v)) o[k] = fill(x, state); return o; }
  return v;
}
const unresolved = (v) => /\{\{\w+\}\}/.test(JSON.stringify(v));

async function event(migrationId, oktaId, actor, ev, stepKey, previous, newValue, result, detail) {
  try {
    await pool.query(`INSERT INTO oem_migration_event (migration_id, okta_id, at, actor, event, step_key, previous, new_value, result, detail) VALUES (?,?,NOW(),?,?,?,?,?,?,?)`,
      [migrationId, oktaId, actor || null, ev, stepKey || null, previous === undefined ? null : JSON.stringify(L.redact(previous)), newValue === undefined ? null : JSON.stringify(L.redact(newValue)), result || null, short(detail, 2000) || null]);
  } catch (e) { console.error('[oem-migrate-exec] event:', e.message); }
}

async function getMigration(id, { events = true } = {}) {
  const [[r]] = await pool.query(`SELECT * FROM oem_migration WHERE id=?`, [id]);
  if (!r) return null;
  const m = {
    id: r.id, oktaId: r.okta_id, status: r.status, protocol: r.protocol, readiness: r.readiness, scanAt: r.scan_at,
    assessment: j(r.assessment, null), plan: j(r.plan, null), preflight: j(r.preflight, null), snapshot: j(r.snapshot, null),
    results: j(r.results, null), verification: j(r.verification, null), createdObjects: j(r.created_objects, []),
    entraAppObjectId: r.entra_app_object_id, entraSpObjectId: r.entra_sp_object_id, jobId: r.job_id,
    createdBy: r.created_by, createdAt: r.created_at, approvedBy: r.approved_by, approvedAt: r.approved_at,
    pushedBy: r.pushed_by, pushedAt: r.pushed_at, finishedAt: r.finished_at, error: r.error,
  };
  if (events) {
    const [ev] = await pool.query(`SELECT id, at, actor, event, step_key, previous, new_value, result, detail FROM oem_migration_event WHERE migration_id=? ORDER BY id`, [id]);
    m.events = ev.map((e) => ({ id: e.id, at: e.at, actor: e.actor, event: e.event, stepKey: e.step_key, previous: j(e.previous, null), newValue: j(e.new_value, null), result: e.result, detail: e.detail }));
  }
  return m;
}

async function setStatus(id, status, extra = {}) {
  const sets = ['status=?']; const vals = [status];
  // Dates go to DATETIME columns as-is (mysql2 formats them); every other object is a JSON column.
  for (const [k, v] of Object.entries(extra)) { sets.push(k + '=?'); vals.push(v instanceof Date ? v : (v !== null && typeof v === 'object' ? JSON.stringify(v) : v)); }
  vals.push(id);
  await pool.query(`UPDATE oem_migration SET ${sets.join(', ')} WHERE id=?`, vals);
}

/**
 * The one Graph write path. `perm` = alternatives (or nested groups) the call needs; `roles` = the write
 * credential's roles. A missing permission is a refusal before the network, never a retry-later.
 */
async function graphCall(method, path, body, { perm, roles, migrationId, oktaId, actor, stepKey, previous, log }) {
  const pc = permCheck(perm || [], roles);
  if (pc.ok !== true) {
    const why = roles === null ? 'the Entra write credential could not be read' : 'needs ' + pc.missing;
    if (log) log(`${stepKey}: refused ${method} ${path} — ${why}`, 'error');
    await event(migrationId, oktaId, actor, 'graph_refused', stepKey, previous, { method, path, body }, 'refused', why);
    return { ok: false, refused: true, status: 0, body: null, error: 'refused: ' + why };
  }
  const r = await L.graphRequest(method, path, body, { cred: 'write' });
  const ok = r.status >= 200 && r.status < 300;
  if (log) log(`${stepKey}: ${method} ${path} → ${r.status}${ok ? '' : ' ' + short(r.error, 200)}`, ok ? 'info' : 'error');
  await event(migrationId, oktaId, actor, ok ? 'graph_write' : 'graph_error', stepKey, previous, { method, path, body, response: ok ? summarize(r.body) : r.body }, ok ? 'ok' : 'error', ok ? null : r.error);
  return Object.assign({ ok }, r);
}
function summarize(b) { if (!b || typeof b !== 'object') return b; const o = {}; for (const k of ['id', 'appId', 'displayName', 'thumbprint', 'keyId', 'principalId', 'appRoleId', 'startDateTime', 'endDateTime']) if (b[k] !== undefined) o[k] = b[k]; if (b.application) o.application = summarize(b.application); if (b.servicePrincipal) o.servicePrincipal = summarize(b.servicePrincipal); return o; }

/** An explicit display-name correction, using the same credential and audit path as staging. */
async function renameEntraApp({ oktaId, entraId, expectedName, displayName, actor }) {
  const refuse = (status, why) => { throw Object.assign(new Error(why), { status, error: 'Entra name not saved', why }); };
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(entraId || '') || typeof expectedName !== 'string' ||
      typeof displayName !== 'string' || !displayName.trim() || displayName.trim().length > 120) {
    refuse(400, 'Enter a name between 1 and 120 characters and reload the destination before saving.');
  }
  const name = displayName.trim();
  const path = '/v1.0/servicePrincipals/' + encodeURIComponent(entraId);
  const current = await L.graphGet(path + '?$select=id,displayName');
  if (current.status !== 200 || !current.body) refuse(current.status === 404 ? 410 : 502,
    current.status === 404 ? 'This Entra application no longer exists. Refresh the application before continuing.' : 'The current Entra name could not be read. Refresh and try again.');
  if (current.body.displayName !== expectedName) refuse(409, 'The Entra name changed since you opened it. Refresh and review the current name.');
  if (name === expectedName) return { ok: true, entraId, name, previousName: expectedName, changed: false };
  const credential = await L.graphToken(false, 'write');
  const written = await graphCall('PATCH', path, { displayName: name }, { perm: PERM.APP_WRITE,
    roles: credential.roles, migrationId: 0, oktaId, actor, stepKey: 'rename_application', previous: { displayName: expectedName } });
  if (!written.ok) refuse(written.refused || written.status === 403 ? 403 : 502,
    'Entra refused the name change: ' + L.redactText(written.error || 'HTTP ' + written.status));
  const after = await L.graphGet(path + '?$select=id,displayName');
  if (after.status !== 200 || !after.body || after.body.displayName !== name) refuse(502,
    'The name change was sent to Entra, but could not be confirmed yet. Refresh before trying again.');
  return { ok: true, entraId, name, previousName: expectedName, changed: true };
}

/** Read back a freshly created object; Graph is eventually consistent for a few seconds after a create. */
async function readBack(path, tries = 6) {
  let r = null;
  for (let i = 0; i < tries; i++) {
    r = await L.graphGet(path);
    if (r.status === 200) return r;
    if (r.status !== 404) return r;
    await L.sleep(2000 * (i + 1));
  }
  return r;
}

/* Assignment storage can lag behind the service-principal read API, and a gallery
   template publishes its app roles a little after the instantiate call returns.
   Retry only for the SP this run just created, and only on the two shapes that lag
   produces: a definitive resource-not-found response naming that SP, or a 400 saying
   the role being assigned is not on the application (the default-access role was
   chosen while the role list was still empty). Before each retry the role is resolved
   again and written back to state.appRoleId, so the re-filled body carries the current
   role id. Permission errors, conflicts, server errors, ambiguous outcomes and
   assignments to existing (adopted or shell) apps are not retried. */
const ASSIGN_RETRIES = 4;
function assignmentLag(r, spId) {
  if (!r || r.ok || r.refused) return null;
  const err = String(r.error || '');
  if (r.status === 404 && /Request_ResourceNotFound/i.test(err) && err.toLowerCase().includes(String(spId).toLowerCase())) return 'not_found';
  if (r.status === 400 && /permission being assigned|app ?role|not found on application/i.test(err) && !/already exists/i.test(err)) return 'role_missing';
  return null;
}
async function assignAfterCreate(send, spId, created, log, opts = {}) {
  const state = opts.state || null;
  const fresh = created.some((o) => o.type === 'servicePrincipal' && o.id === spId);
  const fromTemplate = opts.fromTemplate !== undefined ? opts.fromTemplate === true : !!(state && state.spFromTemplate === true);
  let r = await send();
  for (let i = 0; fresh && i < ASSIGN_RETRIES; i++) {
    const lag = assignmentLag(r, spId);
    if (!lag) break;
    if (lag === 'not_found') log('Waiting for Entra to make the new application available for assignment (' + (i + 1) + '/' + ASSIGN_RETRIES + ').', 'warn');
    else log('The new application\'s roles are not published yet; retrying the assignment (' + (i + 1) + '/' + ASSIGN_RETRIES + ').', 'warn');
    await L.sleep(3000 * (i + 1));
    if (state) {
      const ar = await resolveAppRole(spId, { created, fromTemplate, log });
      if (ar.sp && ar.roleId !== state.appRoleId) { log('assignments now use ' + ar.why + ' (was ' + state.appRoleId + ')'); state.appRoleId = ar.roleId; } // guard: a re-resolve that could not read the SP (sp:null -> default-access GUID) must not downgrade an already-good role
    }
    r = await send();
  }
  return r;
}

/* --------------------------------------------------------------------- planning */

/** Which Entra attribute source backs an Okta attribute statement, or null when it cannot be automated. */
function claimSource(mapping) {
  if (!mapping || !mapping.mappable) return null;
  if (mapping.kind === 'attribute') { const id = String(mapping.source).replace(/^user\./, ''); return { Source: 'user', ID: id }; }
  if (mapping.kind === 'constant') return { Value: mapping.source };
  return null;
}
function nameIdSource(template) {
  const t = String(template || '');
  if (/user\.email/.test(t)) return { Source: 'user', ID: 'mail', why: 'Okta NameID template uses user.email' };
  if (/user\.userName|user\.login/.test(t)) return { Source: 'user', ID: 'userprincipalname', why: 'Okta NameID template uses the Okta login (= UPN in this tenant)' };
  if (!t) return { Source: 'user', ID: 'userprincipalname', why: 'Okta uses its default NameID (login); Entra default is the UPN' };
  return null;
}
function inputList(value) {
  const rows = Array.isArray(value) ? value : (typeof value === 'string' ? value.split(/[\n,]/) : []);
  return uniq(rows.map((v) => String(v || '').trim()).filter(Boolean));
}

/**
 * Turn the assessment's step list into an executable plan: exact Graph calls with payload previews,
 * the inputs that must be supplied before staging, and per-step rollback. Values that are not on the Okta
 * app object are placeholders the pre-flight reports as required inputs; nothing is guessed.
 */
function buildPlan(a, scan, ctx, inputs = {}) {
  const m = scan.model; const t = m.auth.type; const P = a.protocol.recommended;
  const e = M.entraProto(m); // protocol staged in Entra (OIDC for a SAML → OIDC switch)
  const adopt = a.target && a.target.mode === 'adopt' && a.target.entraId;
  const roles = ctx.roles;
  const tenant = process.env.ENTRA_TENANT_ID;
  const label = m.identity.label;
  const displayName = inputs.displayName || (adopt ? (a.target.entraName || label) : defaultEntraName(label));
  const steps = []; const required = []; const notes = [];
  const byKey = {}; for (const s of a.automation.steps) byKey[s.key] = s;
  const add = (key, exec, opts = {}) => {
    const base = byKey[key] || { key, label: opts.label || key, cls: opts.cls || CLS.AUTO, side: 'entra', requires: [], reversible: null, rollback: null, applicable: true };
    if (base.applicable === false) return null;
    const perm = exec ? (opts.perm || base.requires || []) : [];
    const pc = permCheck(perm, roles);
    const s = { order: steps.length + 1, key, label: opts.label || base.label, cls: opts.cls || base.cls, side: base.side, requires: perm, runnable: pc.ok === true, missing: pc.ok === true ? null : (pc.missing || null),
      exec: exec || null, note: opts.note || base.reason || '', reversible: opts.reversible !== undefined ? opts.reversible : base.reversible, rollback: opts.rollback || base.rollback || null,
      optional: !!opts.optional, blocking: opts.blocking !== false, handoff: opts.handoff || null };
    steps.push(s); return s;
  };
  const need = (key, what, why) => { required.push({ key, what, why, provided: inputs[key] !== undefined && inputs[key] !== '' }); return inputs[key]; };
  const notesText = `Migrated from Okta application ${m.identity.id} ("${label}") by the CorpIT Okta→Entra migration engine on ${nowIso().slice(0, 10)}.`;
  const shellOnly = inputs.shellOnly === true;
  const assignmentsOnly = inputs.assignmentsOnly === true;
  const assignmentScope = shellOnly ? 'none' : (assignmentsOnly ? 'all' : (inputs.assignmentScope === 'all' ? 'all' : 'pilot'));

  add('snapshot', { method: 'LOCAL', path: 'snapshot', body: null }, { note: 'The scanned Okta configuration (config, users, groups, sign-on policy, claims, URLs, certificate) is stored with this migration before anything is written.' });

  /* The vendor has now returned its real endpoints. This second SAML pass
     updates the prepared app only; it must not rotate the certificate the
     owner just installed or recreate claims, groups or assignments. */
  if (inputs.samlEndpointUpdate === true) {
    const why = require('./oem-saml-handoff').validateVendorValues({ entityId: inputs.entityId, replyUrls: inputs.acsUrls, relayState: inputs.relayState, samlHandoffThumbprint: inputs.samlHandoffThumbprint });
    if (!adopt || e !== 'saml' || why) throw new Error(why || 'Vendor values require the confirmed, prepared SAML application.');
    add('adopt_target', { method: 'GET', path: '/v1.0/servicePrincipals/' + a.target.entraId + '?$select=id,appId,displayName,preferredSingleSignOnMode,preferredTokenSigningKeyThumbprint,samlSingleSignOnSettings', body: null }, { perm: [], label: 'Recheck the prepared SAML application and signing certificate' });
    add('redirect_uris', { method: 'PATCH', path: '/v1.0/applications/{{appObjectId}}', body: { identifierUris: [inputs.entityId], web: { redirectUris: inputs.acsUrls } } }, { perm: PERM.APP_ADOPT, label: 'Apply the vendor Audience and ACS URLs' });
    add('configure_saml', { method: 'PATCH', path: '/v1.0/servicePrincipals/{{spObjectId}}', body: { samlSingleSignOnSettings: { relayState: inputs.relayState || '' } } }, { perm: PERM.APP_ADOPT, label: 'Apply the vendor relay state' });
    return { builtAt: nowIso(), mode: 'adopt', protocol: P, displayName, steps, required, notes: ['Keep the prepared application, preferred signing certificate, claims and assignments.'], tenant,
      samlEndpointUpdate: true, samlHandoffThumbprint: inputs.samlHandoffThumbprint, handoffValues: null };
  }

  /* A shell is a real, isolated Entra object, not a fake SSO configuration. It is visible,
     enabled and assignment-required, but it has no assignments, endpoints, claims, secrets,
     consent or provisioning job. A later approved run adopts this exact object and fills it in. */
  if (shellOnly) {
    if (e === 'oidc') {
      add('create_app', { method: 'POST', path: '/v1.0/applications', body: {
        displayName, signInAudience: 'AzureADMyOrg', notes: notesText,
        tags: ['okta-migration', 'okta:' + m.identity.id, 'okta-migration-shell'],
      } }, { perm: PERM.APP_WRITE, label: 'Create the isolated app registration', rollback: 'DELETE /v1.0/applications/{{appObjectId}} (recoverable from Deleted applications for 30 days).' });
      add('configure_oidc', { method: 'POST', path: '/v1.0/servicePrincipals', body: {
        appId: '{{appId}}', accountEnabled: true, appRoleAssignmentRequired: true,
        tags: ['WindowsAzureActiveDirectoryIntegratedApp', 'okta-migration', 'okta-migration-shell'], notes: notesText,
      } }, { perm: PERM.APP_WRITE, label: 'Create the visible, assignment-required enterprise app', rollback: 'DELETE /v1.0/servicePrincipals/{{spObjectId}}' });
    } else {
      add('create_app', { method: 'POST', path: `/v1.0/applicationTemplates/${NON_GALLERY_TEMPLATE}/instantiate`, body: { displayName } }, { perm: PERM.APP_WRITE, label: 'Create the isolated enterprise app shell', rollback: 'DELETE the service principal and application.' });
      add('shell_settings', { method: 'PATCH', path: '/v1.0/servicePrincipals/{{spObjectId}}', body: {
        accountEnabled: true, appRoleAssignmentRequired: true, notes: notesText,
        tags: ['WindowsAzureActiveDirectoryIntegratedApp', 'okta-migration', 'okta-migration-shell'],
      } }, { perm: PERM.APP_WRITE, label: 'Make the shell visible and require assignment', note: 'No user or group is assigned, so the shell grants no access.' });
    }
    add('validate', { method: 'LOCAL', path: 'verify', body: null }, { label: 'Verify the isolated shell', cls: CLS.AUTO, perm: [] });
    M.annotateLanes(steps, m, a.protocol, { mode: 'create' }, { name: displayName }, ctx.okta || {});
    return { builtAt: nowIso(), mode: 'create', protocol: P, shellOnly: true, assignmentsOnly: false, assignmentScope: 'none', templateId: e === 'oidc' ? null : NON_GALLERY_TEMPLATE, displayName, steps, required, notes: notes.concat(['This run creates an isolated shell only. It does not configure sign-on or copy production assignments.']), tenant, handoffValues: null };
  }

  if (P === 'unsupported' || P === 'unknown' || t === 'unknown') {
    add('unsupported', null, { cls: CLS.UNSUPPORTED, label: 'Application migration', note: a.protocol.reason });
    M.annotateLanes(steps, m, a.protocol, a.target, { name: displayName }, ctx.okta || {});
    return { builtAt: nowIso(), mode: 'none', protocol: P, displayName, steps, required, notes, tenant };
  }
  if (!assignmentsOnly && t === 'bookmark' && m.bookmark.target === 'entra_launcher') {
    add('verify_launcher', { method: 'GET', path: `/v1.0/servicePrincipals?$filter=appId eq '${m.bookmark.launcherAppId}'&$select=id,displayName,accountEnabled`, body: null }, { perm: [] });
    add('retire_okta', null, { cls: CLS.APPROVAL, handoff: 'Use the Okta lifecycle action on the work item (typed confirmation) once users open the app from My Apps.' });
    M.annotateLanes(steps, m, a.protocol, a.target, { name: displayName }, ctx.okta || {});
    return { builtAt: nowIso(), mode: 'none', protocol: 'linked', displayName, steps, required, notes, tenant };
  }

  if (!assignmentsOnly && e === 'oidc' && m.oidc && m.oidc.shape === 'vendor_consent') {
    add('vendor_consent', null, { cls: CLS.MANUAL, handoff: 'An Entra administrator signs in from the vendor console and accepts the Microsoft consent; the enterprise application then appears in the tenant. Not yet automated from here.' });
    add('assign_groups', null, { cls: CLS.MANUAL, handoff: 'Assign the Entra groups to the enterprise application the consent created (portal), or confirm the match here afterwards to adopt it.' });
    add('validate', null, { cls: CLS.MANUAL, handoff: 'Test a sign-in through Entra and record it on the work item.' });
    add('retire_okta', null, { cls: CLS.APPROVAL, handoff: 'Use the Okta lifecycle action on the work item (typed confirmation) once users sign in through Entra.' });
    notes.push('OpenID Connect for this vendor is the vendor\'s own Entra integration (consent); nothing is written to Entra from this page. Choose "Target protocol in Entra: SAML" under Provide inputs to stage a SAML application from here instead.');
    M.annotateLanes(steps, m, a.protocol, a.target, { name: displayName }, ctx.okta || {});
    return { builtAt: nowIso(), mode: 'none', protocol: P, shape: 'vendor_consent', displayName, steps, required, notes, tenant };
  }
  function configureSaml(createObject) {
    const s = m.saml;
    const entityId = inputs.entityId || s.entityId || need('entityId', 'SAML entity id (audience) the vendor expects', 'not on the Okta app object (OIN template)');
    const acs = inputs.acsUrls ? [].concat(inputs.acsUrls) : (s.acsUrls.length ? s.acsUrls : (need('acsUrls', 'ACS (reply) URL(s) the vendor expects', 'not on the Okta app object (OIN template)'), []));
    if (createObject) add('create_app', { method: 'POST', path: `/v1.0/applicationTemplates/${templateId}/instantiate`, body: { displayName } }, { perm: adopt ? PERM.APP_ADOPT : PERM.APP_WRITE, note: templateId === NON_GALLERY_TEMPLATE ? 'Non-gallery (custom) SAML application.' : `Gallery template "${a.protocol.template.displayName}".`, rollback: 'DELETE the service principal and the application (recoverable from Deleted applications for 30 days).' });
    /* Application-type service principals inherit reply URLs from their backing application.
       Write them only on the application object: Graph rejects a duplicate direct write on
       template-instantiated service principals with a property-mismatch error. */
    add('redirect_uris', { method: 'PATCH', path: '/v1.0/applications/{{appObjectId}}', body: Object.assign({ identifierUris: entityId ? [entityId] : ['{{entityId}}'], web: { redirectUris: acs.length ? acs : ['{{acsUrl}}'] } }, s.slo && s.slo.enabled && isHttps(s.slo.logoutUrl) ? { web: { redirectUris: acs.length ? acs : ['{{acsUrl}}'], logoutUrl: s.slo.logoutUrl } } : {}) }, { perm: adopt ? PERM.APP_ADOPT : PERM.APP_WRITE, label: 'Set the entity id (identifier URI) and reply URL(s)' + (s.slo && s.slo.enabled ? ' and the SLO logout URL' : ''), cls: (entityId && acs.length) ? CLS.AUTO : CLS.APPROVAL });
    add('configure_saml', { method: 'PATCH', path: '/v1.0/servicePrincipals/{{spObjectId}}', body: Object.assign({ preferredSingleSignOnMode: 'saml', accountEnabled: true, appRoleAssignmentRequired: true, notes: notesText, tags: ['WindowsAzureActiveDirectoryIntegratedApp', 'okta-migration'] }, m.identity.loginUrl && isHttps(m.identity.loginUrl) ? { loginUrl: m.identity.loginUrl } : {}, s.relayState ? { samlSingleSignOnSettings: { relayState: s.relayState } } : {}) }, { perm: adopt ? PERM.APP_ADOPT : PERM.APP_WRITE, note: 'Sets SAML mode, makes the enterprise app visible in My Apps, and requires assignment. Reply URLs are configured on the backing application registration in the preceding step.' });
    add('signing_certificate', { method: 'POST', path: '/v1.0/servicePrincipals/{{spObjectId}}/addTokenSigningCertificate', body: { displayName: 'CN=' + displayName.replace(/[^A-Za-z0-9 ._-]/g, '').slice(0, 60), endDateTime: plusDays(3 * 365) } }, { perm: adopt ? PERM.APP_ADOPT : PERM.APP_WRITE, note: 'Entra issues its own SAML signing certificate (3 years); the vendor must trust the new certificate — that is the owner hand-off.', rollback: 'Deleted with the service principal.' });
    // claims: attribute statements that map cleanly become a claims-mapping policy; the rest is a hand-off
    const schema = []; const manualClaims = [];
    const nid = nameIdSource(s.nameId && s.nameId.template);
    if (nid) schema.push({ Source: nid.Source, ID: nid.ID, SamlClaimType: NAMEID_CLAIM });
    else manualClaims.push({ name: 'NameID', value: s.nameId && s.nameId.template, reason: 'NameID template is an expression; set it in the portal (Attributes & Claims → Unique User Identifier).' });
    for (const at of s.attributes) {
      if (at.type === 'GROUP') continue;
      const src = claimSource(at.mapping);
      if (src) schema.push(Object.assign({}, src, { SamlClaimType: at.name }));
      else manualClaims.push({ name: at.name, value: at.values[0], reason: at.mapping && at.mapping.reason });
    }
    const needsPolicy = schema.some((c) => c.SamlClaimType !== NAMEID_CLAIM) || (nid && nid.ID !== 'userprincipalname');
    if (needsPolicy && byKey.claims) {
      const definition = JSON.stringify({ ClaimsMappingPolicy: { Version: 1, IncludeBasicClaimSet: 'true', ClaimsSchema: schema } });
      add('claims', { method: 'POST', path: '/v1.0/policies/claimsMappingPolicies', body: { definition: [definition], displayName: 'okta-migration ' + m.identity.id + ' ' + displayName.slice(0, 40), isOrganizationDefault: false } }, { perm: PERM.CLAIMS, cls: CLS.AUTO, label: `Create the claims-mapping policy (${schema.length} claim(s))`, note: `${schema.length} claim(s) mapped: ${schema.map((c) => c.SamlClaimType.split('/').pop() + '←' + (c.ID || '"' + c.Value + '"')).join(', ')}. Custom signing key (previous step) makes the policy effective without acceptMappedClaims.`, rollback: 'Remove the $ref and DELETE the claimsMappingPolicy.' });
      add('claims_attach', { method: 'POST', path: '/v1.0/servicePrincipals/{{spObjectId}}/claimsMappingPolicies/$ref', body: { '@odata.id': 'https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/{{claimsPolicyId}}' } }, { perm: PERM.CLAIMS, label: 'Attach the claims-mapping policy to the service principal', cls: CLS.AUTO, reversible: true, rollback: 'DELETE /servicePrincipals/{{spObjectId}}/claimsMappingPolicies/{{claimsPolicyId}}/$ref' });
    }
    if (!needsPolicy && byKey.claims) add('claims', null, { cls: CLS.AUTO, note: 'No attribute statements beyond the defaults; Entra emits its standard SAML claims and the UPN as NameID.' });
    if (manualClaims.length) add('claims_manual', null, { cls: CLS.MANUAL, handoff: manualClaims, label: `${manualClaims.length} claim(s) need a deliberate rebuild in Entra (expressions / custom attributes)` });
    if (s.groupClaims.length && byKey.group_claims) add('group_claims', { method: 'PATCH', path: '/v1.0/applications/{{appObjectId}}', body: { groupMembershipClaims: 'ApplicationGroup', optionalClaims: { saml2Token: [{ name: 'groups', additionalProperties: ['sam_account_name'] }] } } }, { perm: adopt ? PERM.APP_ADOPT : PERM.APP_WRITE, note: `Okta emits ${s.groupClaims.length} group attribute(s) (${s.groupClaims.map((g) => g.name).join(', ')}). Entra is restricted to groups assigned to this application to avoid unrelated-group disclosure and SAML group overage. Verify the emitted value for cloud-only groups and rebuild the Okta filter "${s.groupClaims[0].filterValue || 'none recorded'}" through assignments.` });
    if (s.encryption && s.encryption.enabled && byKey.token_encryption) add('token_encryption', null, { cls: CLS.MANUAL, handoff: 'Okta encrypts the assertion; upload the vendor encryption certificate under Token encryption in the portal (Graph has no write for this on a service principal).' });
    if (byKey.inline_hook) add('inline_hook', null, { cls: CLS.MANUAL, handoff: 'The Okta SAML inline hook has no Entra equivalent; rebuild the logic as a custom claims provider or drop it with the owner.' });
  }
  // ---- target object
  let mode = adopt ? 'adopt' : 'create';
  const writePerm = adopt ? PERM.APP_ADOPT : PERM.APP_WRITE;
  const templateId = (e === 'saml' && a.protocol.template && a.protocol.template.id && !a.protocol.nonGallery) ? a.protocol.template.id : NON_GALLERY_TEMPLATE;
  if (adopt) {
    notes.push(`Adopting the confirmed Entra application "${a.target.entraName}" (${a.target.entraId}); existing settings are read first and every changed field is recorded with its previous value.`);
    add('adopt_target', { method: 'GET', path: `/v1.0/servicePrincipals/${a.target.entraId}?$select=id,appId,displayName,preferredSingleSignOnMode,replyUrls,loginUrl,accountEnabled,appRoleAssignmentRequired,tags`, body: null }, { perm: [], note: 'Reads the confirmed Entra service principal by object id (read credential); its object ids feed the later steps.' });
    if (e === 'saml' && inputs.configureSaml === true) configureSaml(false);
  } else if (e === 'oidc') {
    const o = m.oidc;
    const web = [], spa = [], pub = [];
    for (const u of o.redirectUris) { if (o.applicationType === 'browser') spa.push(u); else if (o.applicationType === 'native' || o.applicationType === 'service') pub.push(u); else web.push(u); }
    const body = {
      displayName, signInAudience: 'AzureADMyOrg', notes: notesText, tags: ['okta-migration', 'okta:' + m.identity.id],
      web: { redirectUris: web, logoutUrl: o.postLogoutRedirectUris[0] || null, implicitGrantSettings: { enableIdTokenIssuance: !!o.implicit, enableAccessTokenIssuance: false } },
      requiredResourceAccess: [{ resourceAppId: GRAPH_APP_ID, resourceAccess: ['openid', 'profile', 'email', 'User.Read'].concat(o.refreshTokens ? ['offline_access'] : []).map((s) => ({ id: GRAPH_SCOPE_IDS[s], type: 'Scope' })) }],
    };
    if (spa.length) body.spa = { redirectUris: spa };
    if (pub.length) body.publicClient = { redirectUris: pub };
    if (o.applicationType === 'native') body.isFallbackPublicClient = true;
    add('create_app', { method: 'POST', path: '/v1.0/applications', body }, { perm: PERM.APP_WRITE, rollback: 'DELETE /v1.0/applications/{{appObjectId}} (recoverable from Deleted applications for 30 days).' });
    add('configure_oidc', { method: 'POST', path: '/v1.0/servicePrincipals', body: { appId: '{{appId}}', accountEnabled: true, appRoleAssignmentRequired: true, tags: ['WindowsAzureActiveDirectoryIntegratedApp', 'okta-migration'], notes: notesText } }, { perm: PERM.APP_WRITE, label: 'Create the service principal (visible in My Apps; assignment required)', rollback: 'DELETE /v1.0/servicePrincipals/{{spObjectId}}' });
    if (byKey.redirect_uris) add('redirect_uris', null, { note: `${o.redirectUris.length} redirect URI(s) are part of the application create payload above (${web.length} web, ${spa.length} spa, ${pub.length} public client).`, cls: CLS.AUTO });
    if (byKey.logout_urls) add('logout_urls', null, { note: o.postLogoutRedirectUris.length ? 'Front-channel logout URL is part of the create payload.' : 'No post-logout URI in Okta; nothing to set.', cls: CLS.AUTO });
    if (byKey.claims) {
      const wantsGroups = !!(o.claims && JSON.stringify(o.claims).toLowerCase().includes('groups'));
      if (wantsGroups) add('claims', { method: 'PATCH', path: '/v1.0/applications/{{appObjectId}}', body: { groupMembershipClaims: 'SecurityGroup', optionalClaims: { idToken: [{ name: 'groups', additionalProperties: ['sam_account_name'] }], accessToken: [{ name: 'groups', additionalProperties: ['sam_account_name'] }] } } }, { perm: PERM.APP_WRITE, note: 'Groups claim emitted as SAM account names (matches Okta group names for AD-mastered groups).' });
      else add('claims', null, { cls: CLS.AUTO, note: 'Standard OIDC claims (sub, oid, preferred_username, email, name) are issued by default; Okta-side custom claims live on the authorization server policy and are listed for the owner in the hand-off.' });
    }
    if (byKey.permissions) add('permissions', null, { cls: CLS.APPROVAL, optional: true, handoff: 'The tenant-wide consent for openid/profile/email/User.Read is granted in the next step; any additional API permission the application needs must be added by an administrator.' , exec: null });
    add('consent', { method: 'POST', path: '/v1.0/oauth2PermissionGrants', body: { clientId: '{{spObjectId}}', consentType: 'AllPrincipals', resourceId: '{{graphSpObjectId}}', scope: ['openid', 'profile', 'email', 'User.Read'].concat(o.refreshTokens ? ['offline_access'] : []).join(' ') } }, { perm: PERM.CONSENT, cls: CLS.APPROVAL, label: 'Grant tenant-wide consent for the sign-in scopes (openid, profile, email, User.Read)', optional: true, note: 'Without it every user sees a consent prompt on first sign-in. Optional: a failure here is a warning, not a failed migration.', reversible: true, rollback: 'DELETE the oauth2PermissionGrant.' });
    if (o.secretRequired) add('client_secret', { method: 'POST', path: '/v1.0/applications/{{appObjectId}}/addPassword', body: { passwordCredential: { displayName: 'okta-migration ' + nowIso().slice(0, 10), endDateTime: plusDays(180) } } }, { perm: PERM.APP_WRITE, note: 'The secret is shown ONCE to the technician who staged, on the Application side step, and is never stored. Valid 180 days.', reversible: true, rollback: 'POST /applications/{{appObjectId}}/removePassword.' });
  } else if (e === 'saml') {
    configureSaml(true);
  } else if (t === 'bookmark') {
    add('create_app', { method: 'POST', path: `/v1.0/applicationTemplates/${NON_GALLERY_TEMPLATE}/instantiate`, body: { displayName } }, { perm: PERM.APP_WRITE, label: 'Create the application (My Apps tile)', rollback: 'DELETE the service principal and the application.' });
    add('linked_mode', { method: 'PATCH', path: '/v1.0/servicePrincipals/{{spObjectId}}', body: { homepage: m.bookmark.url, loginUrl: m.bookmark.url, accountEnabled: true, appRoleAssignmentRequired: true, notes: notesText, tags: ['WindowsAzureActiveDirectoryIntegratedApp', 'okta-migration'] } }, { perm: PERM.APP_WRITE, cls: CLS.AUTO, label: 'Set the visible My Apps tile URL (homepage / sign-on URL)', handoff: 'Linked single sign-on mode itself is a portal setting (Single sign-on → Linked); Graph exposes the URL only.' });
  } else if (t === 'swa') {
    add('create_app', { method: 'POST', path: `/v1.0/applicationTemplates/${NON_GALLERY_TEMPLATE}/instantiate`, body: { displayName } }, { perm: PERM.APP_WRITE, rollback: 'DELETE the service principal and the application.' });
    add('password_sso', { method: 'PATCH', path: '/v1.0/servicePrincipals/{{spObjectId}}', body: { preferredSingleSignOnMode: 'password', loginUrl: m.swa.url, accountEnabled: true, appRoleAssignmentRequired: true, notes: notesText, tags: ['WindowsAzureActiveDirectoryIntegratedApp', 'okta-migration'] } }, { perm: PERM.APP_WRITE, cls: CLS.APPROVAL, note: 'Password-based SSO mode; the app is visible in My Apps and requires assignment. The sign-in form capture is done once in the portal (My Apps Secure Sign-in Extension).' });
    if (byKey.user_credentials) add('user_credentials', null, { cls: CLS.MANUAL, handoff: 'Stored per-user passwords cannot be exported from Okta; users re-enter them once in My Apps.' });
  }

  // ---- groups and users
  const groups = m.assignments.groups || [];
  const resolved = groups.filter((g) => g.entra && g.entra.entraId);
  const native = groups.filter((g) => g.type === 'okta' && !(g.entra && g.entra.entraId));
  const adMissing = groups.filter((g) => g.type === 'ad' && !(g.entra && g.entra.entraId));
  const users = m.assignments.users || {};
  if (assignmentScope === 'all') {
    if (byKey.resolve_groups || assignmentsOnly) add('resolve_groups', null, { cls: CLS.AUTO, note: `${resolved.length} of ${groups.length} Okta group(s) resolved to Entra groups by SID or exact name during the scan.` });
    if (native.length && inputs.skipGroupCreate) add('create_groups_manual', null, { cls: CLS.MANUAL, handoff: native.map((g) => ({ group: g.name, oktaId: g.id })), label: `${native.length} Okta-native group(s) handed off: create them in Entra and assign them to the app by hand (chosen at pre-flight)` });
    else for (const g of native) add('create_groups', { method: 'POST', path: '/v1.0/groups', body: { displayName: g.name, mailEnabled: false, mailNickname: String(g.name).replace(/[^A-Za-z0-9]/g, '').slice(0, 60) || 'oktagroup', securityEnabled: true, description: `Created from Okta group ${g.id} by the Okta→Entra migration; ${g.description || ''}`.slice(0, 1000) } }, { perm: [PERM.GROUP_CREATE, PERM.GROUP_MEMBER], label: `Create Entra group "${g.name}" (Okta-native) and copy its members by UPN`, cls: CLS.APPROVAL, rollback: 'DELETE /v1.0/groups/{id}' });
    const builtinG = groups.filter((g) => g.type === 'builtin');
    if (builtinG.length) add('assign_everyone', null, { cls: CLS.MANUAL, handoff: builtinG.map((g) => g.name), label: `Okta assigned ${builtinG.map((g) => '"' + g.name + '"').join(', ')}: assign the intended Entra population (for example All Users) before the Okta assignment swap` });
    if (adMissing.length) add('sync_groups', null, { cls: CLS.MANUAL, handoff: adMissing.map((g) => ({ group: g.name, sam: g.sam, dn: g.dn })), label: `${adMissing.length} AD group(s) are not in Entra: extend the Entra Connect sync scope, then run production assignment again` });
    if (resolved.length) add('assign_groups', { method: 'POST', path: '/v1.0/servicePrincipals/{{spObjectId}}/appRoleAssignedTo', body: resolved.map((g) => ({ principalId: g.entra.entraId, principalType: 'Group', resourceId: '{{spObjectId}}', appRoleId: '{{appRoleId}}', _group: g.name })) }, { perm: PERM.ASSIGN, label: `Assign ${resolved.length} production group(s) to the application`, rollback: 'DELETE each appRoleAssignment.' });
    if (native.length && !inputs.skipGroupCreate) add('assign_created_groups', { method: 'POST', path: '/v1.0/servicePrincipals/{{spObjectId}}/appRoleAssignedTo', body: native.map((g) => ({ principalId: '{{createdGroup:' + g.id + '}}', principalType: 'Group', resourceId: '{{spObjectId}}', appRoleId: '{{appRoleId}}', _group: g.name })) }, { perm: PERM.ASSIGN, label: `Assign the ${native.length} created production group(s)`, cls: CLS.AUTO, rollback: 'DELETE each appRoleAssignment.' });
    if (users.direct > 0) add('assign_users', { method: 'POST', path: '/v1.0/servicePrincipals/{{spObjectId}}/appRoleAssignedTo', body: (users.directSample || []).map((u) => ({ principalId: '{{user:' + u.userName + '}}', principalType: 'User', resourceId: '{{spObjectId}}', appRoleId: '{{appRoleId}}', _user: u.userName })) }, { perm: PERM.ASSIGN, label: `Assign ${users.direct} production user(s) by UPN` + (users.directComplete === false || users.direct > (users.directSample || []).length ? ` (${(users.directSample || []).length} known; rollout is blocked until the scan is complete)` : ''), rollback: 'DELETE each appRoleAssignment.' });
  } else if (assignmentScope === 'pilot') {
    const pilotGroups = inputList(inputs.pilotGroupIds).filter((id) => /^[0-9a-f-]{36}$/i.test(id));
    const pilotUsers = inputList(inputs.pilotUserUpns).filter((upn) => /^[^\s@]+@[^\s@]+$/.test(upn));
    if (pilotGroups.length) add('assign_groups', { method: 'POST', path: '/v1.0/servicePrincipals/{{spObjectId}}/appRoleAssignedTo', body: pilotGroups.map((id) => ({ principalId: id, principalType: 'Group', resourceId: '{{spObjectId}}', appRoleId: '{{appRoleId}}', _group: 'pilot group ' + id })) }, { perm: PERM.ASSIGN, label: `Assign ${pilotGroups.length} pilot group(s)`, rollback: 'DELETE each appRoleAssignment.' });
    if (pilotUsers.length) add('assign_users', { method: 'POST', path: '/v1.0/servicePrincipals/{{spObjectId}}/appRoleAssignedTo', body: pilotUsers.map((upn) => ({ principalId: '{{user:' + upn + '}}', principalType: 'User', resourceId: '{{spObjectId}}', appRoleId: '{{appRoleId}}', _user: upn })) }, { perm: PERM.ASSIGN, label: `Assign ${pilotUsers.length} pilot user(s) by UPN`, rollback: 'DELETE each appRoleAssignment.' });
    if (!pilotGroups.length && !pilotUsers.length) add('pilot_assignment', null, { cls: CLS.MANUAL, label: 'Assign at least one pilot before testing', handoff: 'No valid pilot user UPN or Entra group object id was supplied. The application remains isolated by assignment required.' });
  }
  if (byKey.assignment_required) add('assignment_required', null, { cls: CLS.AUTO, note: 'appRoleAssignmentRequired=true is part of the service principal payload: only assigned users and groups can sign in.' });
  if (byKey.conditional_access) add('conditional_access', null, { cls: 'N/A', blocking: false,
    handoff: 'Okta sign-on policy evidence is retained for the separate Security & MFA project. It is not copied, required or written by this application staging run.',
    label: 'Security & MFA policy evidence (separate project)' });
  if (byKey.provisioning) {
    const pm = m.provisioning || {};
    const outbound = (pm.mappings || []).filter((x) => x.direction === 'to_app');
    const inbound = (pm.mappings || []).filter((x) => x.direction === 'from_app');
    const manual = outbound.filter((x) => !(x.mapping && x.mapping.mappable));
    add('provisioning', null, { cls: CLS.MANUAL,
      label: `Rebuild Entra provisioning (${outbound.length} outbound attribute mapping(s))`,
      handoff: {
        features: pm.features || [], connection: pm.connection || null,
        outbound, inbound,
        groupPush: pm.groupPush || [],
        semantics: pm.semantics || null,
        fingerprint: pm.fingerprint || null,
        appUserSchema: pm.schema || null,
        inventory: pm.inventory || null,
        instructions: [
          'The vendor creates a new SCIM base URL and bearer token for Entra. Okta credentials are never exported or reused.',
          'Create or select the Entra provisioning job, enter the credential directly in Entra and test the connection.',
          'Rebuild the outbound mappings from this worksheet. Direct user attributes/constants can be translated; expressions and appuser values need an explicit Entra source or transformation.',
          'Rebuild every Group Push mapping as an Entra group object mapping or a documented application-side group assignment; verify memberships separately.',
          'Stop if Okta imports profiles, masters attributes, pushes passwords or performs delegated authentication. Those flows need a source-of-authority decision and do not translate as ordinary outbound SCIM.',
          'Scope only pilot users/groups, run on-demand provisioning, and verify create, update and deactivate behavior.',
          'Keep the pilot populations mutually exclusive so Okta and Entra never manage the same target account at the same time.',
          'Keep Okta provisioning enabled until the Entra cycle succeeds and the owner confirms the target records; cut over by stopping Okta before expanding Entra scope.'
        ],
      },
      note: `${outbound.length} outbound / ${inbound.length} inbound Okta profile mapping(s) inventoried; ${manual.length} outbound mapping(s) require manual translation. A new vendor credential is required and is never stored here.` });
  }
  add('validate', { method: 'LOCAL', path: 'verify', body: null }, { label: 'Live re-read of the Entra objects against this plan', cls: CLS.AUTO, perm: [] });
  if (byKey.vendor_reconfigure) add('vendor_reconfigure', null, { cls: CLS.MANUAL, side: 'owner', handoff: 'owner', label: 'Application owner repoints the vendor at Entra (issuer, sign-on URL, certificate / client id)', blocking: false });
  if (byKey.test_signin) add('test_signin', null, { cls: CLS.MANUAL, label: 'Test sign-in by an assigned user; record the evidence on the work item', blocking: false });

  // who does each step (page / Claude Code + extension / a person) — same rules as the assessment, applied to the plan's own steps
  M.annotateLanes(steps, m, a.protocol, a.target, { name: displayName }, ctx.okta || {});
  return { builtAt: nowIso(), mode, protocol: P, shellOnly: false, assignmentsOnly, assignmentScope, templateId: e === 'saml' || t === 'bookmark' || t === 'swa' ? templateId : null, displayName, steps, required, notes, tenant,
    handoffValues: e === 'saml' ? { issuer: `https://sts.windows.net/${tenant}/`, loginUrl: `https://login.microsoftonline.com/${tenant}/saml2`, logoutUrl: `https://login.microsoftonline.com/${tenant}/saml2`, metadataUrl: `https://login.microsoftonline.com/${tenant}/federationmetadata/2007-06/federationmetadata.xml?appid={{appId}}`, certificate: 'download from the enterprise app → Single sign-on → SAML certificates after staging' }
      : e === 'oidc' ? { issuer: `https://login.microsoftonline.com/${tenant}/v2.0`, discovery: `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`, clientId: '{{appId}}', clientSecret: m.oidc.secretRequired ? 'shown once in the staging result' : 'not required (public client / PKCE)' } : null };
}

/* -------------------------------------------------------------------- pre-flight */

/**
 * Critical checks. Each returns {key, label, severity, status: pass|fail|warn|unknown, detail, fix}.
 * A `fail` on a critical check blocks approval; `warn` is shown and must be acknowledged by the approval.
 */
async function runChecks(a, scan, ctx, plan) {
  const m = scan.model; const checks = []; const roles = ctx.roles;
  const C = (key, label, severity, status, detail, fix) => checks.push({ key, label, severity, status, detail: short(detail, 600) || null, fix: short(fix, 400) || null });
  const t = m.auth.type; const e = M.entraProto(m); // Entra-side protocol (OIDC for a SAML → OIDC switch)
  const shellOnly = plan.shellOnly === true;
  const assignmentsOnly = plan.assignmentsOnly === true;
  const productionAssignments = plan.assignmentScope === 'all';

  const blockingScanErrors = typeof M.migrationBlockingScanErrors === 'function' ? M.migrationBlockingScanErrors(scan.errors) : (scan.errors || []);
  const policyScanErrors = typeof M.migrationPolicyScanErrors === 'function' ? M.migrationPolicyScanErrors(scan.errors) : [];
  const appScanComplete = typeof M.migrationScanComplete === 'function' ? M.migrationScanComplete(scan) : !!scan.complete;
  C('scan_complete', 'Migration-affecting Okta data was read completely', 'critical', appScanComplete ? 'pass' : 'fail', appScanComplete ? `Scanned ${new Date(scan.scannedAt).toISOString()}` : 'Read errors: ' + blockingScanErrors.map((e) => e.read + ': ' + e.error).join('; '), appScanComplete ? null : 'Fix the Okta read (token scope or rate limit) and re-run pre-flight.');
  C('security_policy_evidence', 'Okta sign-on policy evidence (separate Security & MFA project)', 'info', 'pass',
    policyScanErrors.length ? `Policy evidence could not be read (${policyScanErrors.map((e) => e.read).join(', ')}); this does not block application staging.` : 'Policy evidence was retained, but is not copied or required by this application migration.',
    policyScanErrors.length ? 'Review or rescan it in the separate Security & MFA project; no action is required to stage this application.' : null);
  const sourceComplete = typeof M.migrationSourceComplete === 'function' && M.migrationSourceComplete(m);
  C('source_contract_complete', 'Okta claims, assignments, group membership and provisioning were read completely', 'critical',
    sourceComplete ? 'pass' : 'fail',
    sourceComplete ? 'The migration source contract is complete and can be bound to approval.' : 'One or more migration-affecting Okta reads are missing or partial.',
    sourceComplete ? null : 'Fix the reported Okta read permission or pagination failure, then run pre-flight again. An incomplete source contract cannot be approved.');
  // already migrated? a verified/retired work item, a person's record, or evidence → staging would create a second Entra application
  const done = a.alreadyMigrated || (a.push && a.push.alreadyMigrated) || null;
  if (assignmentsOnly) C('already_migrated', 'Application configuration is already Live', 'info', 'pass', 'This run expands production assignments on the verified Entra application; it does not recreate or reconfigure it.', null);
  else if (done) C('already_migrated', 'Application is not already migrated', 'critical', 'fail', done.label + '. ' + (done.detail || ''), 'Nothing to stage: this application already signs in through Entra as far as the record shows. If the record is wrong, clear it under "Already migrated" on the application and run pre-flight again.');
  else if (a.caution) C('already_migrated', 'Application is not already migrated', 'warning', 'warn', a.caution.label + ': ' + (a.caution.detail || ''), 'Check before staging: run "Check where it points" or "Check Okta usage"; if users already sign in through Entra, Mark as migrated instead of staging.');
  else C('already_migrated', 'Application is not already migrated', 'critical', 'pass', a.migrated && a.migrated.level === 'okta' ? 'The tile still sends users to Okta.' : 'No verified, recorded or evidenced Entra migration for this application.', null);
  // a same-named enterprise application in the tenant that is not the adopt target → a second copy would be created
  if (plan.mode === 'create') {
    const [dup] = await pool.query(`SELECT entra_id, display_name, preferred_single_sign_on_mode, account_enabled FROM entra_apps WHERE LOWER(display_name) IN (?) AND service_principal_type <> 'ManagedIdentity' LIMIT 5`, [[String(plan.displayName || '').toLowerCase(), String(m.identity.label || '').toLowerCase(), 'sso-' + String(m.identity.label || '').toLowerCase()]]);
    C('duplicate_name', 'No same-named Entra application', 'warning', dup.length ? 'warn' : 'pass', dup.length ? `Entra already has ${dup.map((d) => `"${d.display_name}" (${d.entra_id}, SSO ${d.preferred_single_sign_on_mode || 'none'}, ${d.account_enabled ? 'enabled' : 'disabled'})`).join('; ')}. Staging creates another one.` : 'No enterprise application with this name in the Entra mirror.', dup.length ? 'If that is the migrated app: confirm the match (Review match) to adopt it, or Mark as migrated. Only acknowledge if a second application is really intended.' : null);
  }
  C('okta_active', 'Okta application is active', 'critical', m.identity.status === 'ACTIVE' ? 'pass' : 'fail', 'Okta status ' + m.identity.status, m.identity.status === 'ACTIVE' ? null : 'An inactive Okta app has no users to move; migrate only active applications.');
  const noneOk = plan.mode === 'none' && (plan.protocol === 'linked' || plan.shape === 'vendor_consent');
  if (plan.shape === 'vendor_consent') C('nothing_to_stage', 'Something to stage from this page', 'critical', 'fail', 'OpenID Connect for this vendor is its own Entra integration (Microsoft consent from the vendor console): nothing is written to Entra from here — not yet automated.', 'Work the Application side (consent from the vendor console), then confirm the match and record the tested sign-in on the work item. To stage a SAML application from here instead, record "Target protocol in Entra: SAML" under Provide inputs and run pre-flight again.');
  C('unsupported_auth', 'Sign-on method is supported by the engine', 'critical', plan.mode === 'none' && !noneOk ? 'fail' : 'pass', `Okta ${t} → Entra ${plan.protocol}` + (plan.shape === 'vendor_consent' ? ' (vendor consent: nothing is staged from here — not yet automated)' : ''), plan.mode === 'none' && !noneOk ? a.protocol.reason : null);

  // write credential and permissions for every step that will run
  const runSteps = plan.steps.filter((s) => s.exec && s.exec.method !== 'LOCAL' && s.exec.method !== 'GET');
  const missing = uniq(runSteps.filter((s) => !s.runnable && !s.optional).map((s) => s.missing || 'unknown'));
  if (!ctx.write || !ctx.write.configured) C('write_credential', 'Entra write credential configured', 'critical', 'fail', 'ENTRA_MIGRATE_CLIENT_ID / ENTRA_MIGRATE_CLIENT_SECRET are not set on the platform.', 'Register IT-Command-Migrate, grant the application permissions, add the credential to the hub .env and restart the API.');
  else if (ctx.roles === null) C('write_credential', 'Entra write credential can sign in', 'critical', 'fail', ctx.write.error || 'token error', 'Check the client secret (expired?) and the tenant id.');
  else C('write_credential', `Entra write credential (${ctx.write.name})`, 'critical', 'pass', `${ctx.roles.length} application permission(s) consented`, null);
  C('permissions', 'Permissions for every automatic step', 'critical', ctx.roles === null ? 'unknown' : (missing.length ? 'fail' : 'pass'), missing.length ? 'Missing: ' + missing.join(', ') : `${runSteps.length} write step(s) covered`, missing.length ? `Grant ${missing.join(', ')} to ${ctx.write && ctx.write.name ? ctx.write.name : 'the write credential'} (admin consent by an Entra Global Administrator).` : null);
  const optMissing = uniq(runSteps.filter((s) => !s.runnable && s.optional).map((s) => s.missing));
  if (optMissing.length) C('permissions_optional', 'Permissions for optional steps', 'warning', 'warn', 'Missing: ' + optMissing.join(', ') + ' — those steps will be skipped and reported.', 'Grant them or accept the manual follow-up.');

  // required inputs
  const reqMissing = plan.required.filter((r) => !r.provided);
  C('inputs_required', 'Vendor values that are not on the Okta app', 'critical', reqMissing.length ? 'fail' : 'pass', reqMissing.length ? reqMissing.map((r) => `${r.key}: ${r.what} (${r.why})`).join('; ') : 'Nothing to supply', reqMissing.length ? 'Read them from the vendor SP metadata / admin console and re-run pre-flight with the values.' : null);

  // ambiguity / target
  const hard = a.stops.filter((s) => s.severity === 'stop');
  C('ambiguous_target', 'Entra target is unambiguous', 'critical', a.stops.some((s) => s.key === 'ambiguous_target') ? 'fail' : 'pass', a.target && a.target.entraName ? `${plan.mode === 'adopt' ? 'Adopting' : 'Suggested, not confirmed:'} ${a.target.entraName}` : 'New application', a.stops.some((s) => s.key === 'ambiguous_target') ? 'Confirm or reject the suggested Entra match on the work item first.' : null);
  if (plan.mode === 'adopt') {
    const sp = await L.graphGet(`/v1.0/servicePrincipals/${a.target.entraId}?$select=id,appId,displayName,accountEnabled,preferredSingleSignOnMode,replyUrls`);
    const row = sp.status === 200 && sp.body && sp.body.id ? sp.body : null;
    if (!row) C('target_state', 'Confirmed Entra application exists', 'critical', sp.status === 200 ? 'fail' : 'unknown', sp.status === 200 ? 'Not found by service-principal object id ' + a.target.entraId : 'Graph: ' + sp.error, 'Re-check the match; the Entra app may have been deleted.');
    else {
      C('target_state', 'Confirmed Entra application exists', 'critical', 'pass', `${row.displayName} — ${row.accountEnabled ? 'enabled' : 'DISABLED'}, SSO mode ${row.preferredSingleSignOnMode || 'not set'}`, null);
      const asg = await L.graphGet(`/v1.0/servicePrincipals/${row.id}/appRoleAssignedTo?$top=1&$count=true`);
      const shared = a.target.entra && a.target.entra.sharedBy > 1;
      if (shared) C('shared_target', 'Entra application is not shared by other Okta apps', 'critical', 'warn', a.target.entra.sharedBy + ' Okta apps point at this Entra app.', 'Changes affect every Okta app that maps here; approve only if intended.');
      if (asg.status === 200 && asg.body && asg.body.value && asg.body.value.length) C('production_dependency', 'Existing users on the Entra application', 'warning', 'warn', 'The Entra app already has assignments; staging adds, never removes.', null);
    }
  } else {
    // duplicate / conflict scan in Entra: same display name, same identifier URI
    const q = String(plan.displayName).replace(/'/g, "''");
    const [apps, sps] = await Promise.all([
      L.graphGet(`/v1.0/applications?$filter=displayName eq '${encodeURIComponent(q)}'&$select=id,appId,displayName,identifierUris,createdDateTime`),
      L.graphGet(`/v1.0/servicePrincipals?$filter=displayName eq '${encodeURIComponent(q)}'&$select=id,appId,displayName,servicePrincipalType,accountEnabled`)]);
    const dupA = apps.status === 200 ? (apps.body.value || []) : null; const dupS = sps.status === 200 ? (sps.body.value || []) : null;
    if (dupA === null || dupS === null) C('duplicate_app', 'No Entra application with the same name', 'critical', 'unknown', 'Graph read failed: ' + (apps.error || sps.error), 'Retry pre-flight.');
    else if (dupA.length || dupS.length) C('duplicate_app', 'No Entra application with the same name', 'critical', 'fail', `${dupA.length} application(s) / ${dupS.length} enterprise app(s) named "${plan.displayName}" already exist (${uniq(dupA.map((x) => x.appId).concat(dupS.map((x) => x.appId))).join(', ')}).`, 'Confirm one of them as the target on the work item (adopt), or pre-flight with a different displayName input.');
    else C('duplicate_app', 'No Entra application with the same name', 'critical', 'pass', 'No application or enterprise app carries this name.', null);
    if (e === 'saml' && m.saml.entityId) {
      const eid = m.saml.entityId.replace(/'/g, "''");
      const r = await L.graphGet(`/v1.0/applications?$filter=identifierUris/any(x:x eq '${encodeURIComponent(eid)}')&$select=id,appId,displayName`);
      if (r.status !== 200) C('existing_conflict', 'Entity id is not registered on another Entra application', 'critical', 'unknown', 'Graph: ' + r.error, 'Retry pre-flight.');
      else if ((r.body.value || []).length) C('existing_conflict', 'Entity id is not registered on another Entra application', 'critical', 'fail', `identifierUri ${m.saml.entityId} is on "${r.body.value[0].displayName}" (${r.body.value[0].appId}); Entra requires identifier URIs to be unique.`, 'Adopt that application or change the entity id with the vendor.');
      else C('existing_conflict', 'Entity id is not registered on another Entra application', 'critical', 'pass', m.saml.entityId, null);
    }
  }
  // redirect / reply URL sanity
  if (!shellOnly && !assignmentsOnly && e === 'oidc') {
    const bad = m.oidc.redirectUris.filter((u) => !(isHttps(u) || isLocal(u) || /^[a-z][a-z0-9+.-]*:\/\//i.test(u) && !/^http:/i.test(u)));
    const wild = m.oidc.redirectUris.filter((u) => u.includes('*'));
    C('redirect_conflict', 'Redirect URIs are acceptable to Entra', 'critical', (bad.length || wild.length) ? 'fail' : (m.oidc.redirectUris.length ? 'pass' : 'fail'), wild.length ? 'Wildcard redirect URIs are not allowed in Entra: ' + wild.join(', ') : bad.length ? 'Plain http (non-localhost) redirect URIs are rejected: ' + bad.join(', ') : m.oidc.redirectUris.length ? m.oidc.redirectUris.length + ' URI(s)' : 'No redirect URI on the Okta client', (bad.length || wild.length) ? 'Agree exact https redirect URIs with the owner; wildcards must be enumerated.' : null);
  }
  if (!shellOnly && !assignmentsOnly && e === 'saml') {
    const redirectStep = plan.steps.find((s) => s.key === 'redirect_uris');
    const plannedAcs = redirectStep && redirectStep.exec && redirectStep.exec.body && redirectStep.exec.body.web
      ? redirectStep.exec.body.web.redirectUris : [];
    const acs = (plannedAcs.length ? plannedAcs : m.saml.acsUrls).filter(Boolean);
    const bad = acs.filter((u) => !isHttps(u));
    if (acs.length) C('redirect_conflict', 'Reply (ACS) URLs are https', 'critical', bad.length ? 'fail' : 'pass', bad.length ? 'Not https: ' + bad.join(', ') : acs.join(', '), bad.length ? 'Entra requires https reply URLs.' : null);
    const cert = m.saml.signing && m.saml.signing.cert;
    C('invalid_certificate', 'Signing certificate', 'info', 'pass', plan.samlEndpointUpdate ? 'The current preferred Entra signing certificate is kept and checked again before the update.' : cert && cert.daysLeft !== null && cert.daysLeft !== undefined ? `Okta certificate has ${cert.daysLeft} day(s) left; Entra issues its own certificate at staging and the vendor must trust it.` : 'Entra issues its own certificate at staging; the vendor must trust it.', null);
    const manual = plan.steps.find((s) => s.key === 'claims_manual');
    if (manual) C('missing_claim', 'Every attribute statement can be reproduced automatically', 'warning', 'warn', `${manual.handoff.length} claim(s) need a manual rebuild: ` + manual.handoff.map((c) => c.name).join(', '), 'Rebuild them in the portal before the owner repoints the vendor; staging emits the mappable claims only.');
    else C('missing_claim', 'Every attribute statement can be reproduced automatically', 'warning', 'pass', `${m.saml.attributes.length} attribute statement(s)`, null);
    const mappedClaims = 1 + m.saml.attributes.filter((x) => x.type !== 'GROUP' && x.mapping && x.mapping.mappable).length;
    C('claims_limit', 'Claims mapping stays within the Entra policy limit', 'critical', mappedClaims <= 50 ? 'pass' : 'fail', `${mappedClaims} claim schema entries would be created.`, mappedClaims <= 50 ? null : 'Reduce the claims to 50 or fewer with the owner; Entra ignores claims after the policy limit.');
  }
  // groups
  const groups = m.assignments.groups || [];
  const unresolvedAd = groups.filter((g) => g.type === 'ad' && !(g.entra && g.entra.entraId));
  const nativeG = groups.filter((g) => g.type === 'okta' && !(g.entra && g.entra.entraId));
  const builtin = groups.filter((g) => g.type === 'builtin');
  const unknownG = groups.filter((g) => !['ad', 'okta', 'builtin'].includes(g.type) && !(g.entra && g.entra.entraId));
  const users = m.assignments.users || {};
  if (productionAssignments) {
    if (builtin.length) C('everyone_group', 'Okta built-in group assignment', 'warning', 'warn', `Okta assigns the built-in group(s) ${builtin.map((g) => '"' + g.name + '"').join(', ')} (${users.count !== null ? users.count + ' users' : 'count unknown'}). Entra has no equivalent object: assign the intended Entra group (for example All Users) before the Okta assignment swap.`, 'Decide the Entra population with the owner; nothing is assigned automatically for a built-in group.');
    if (unresolvedAd.length || unknownG.length) C('missing_group', 'Every production group exists in Entra', 'critical', 'fail', `${unresolvedAd.length} AD group(s) not in Entra (${unresolvedAd.map((g) => g.name).slice(0, 5).join(', ')})${unknownG.length ? '; ' + unknownG.length + ' of unknown type' : ''}`, 'Bring the groups into the Entra Connect sync scope (or create them) and run production assignment again.');
    else C('missing_group', 'Every production group exists in Entra', 'critical', nativeG.length ? 'warn' : 'pass', nativeG.length ? `${nativeG.length} Okta-native group(s) will be created in Entra (${nativeG.map((g) => g.name).join(', ')}); membership copied by UPN.` : `${groups.length} group(s) resolved`, null);
  } else {
    C('production_groups_deferred', shellOnly ? 'Production assignments stay out of the shell' : 'Production assignments wait for rollout', 'info', 'pass', shellOnly ? 'The shell is created with assignment required and no users or groups.' : 'Only the approved pilot is assigned during configuration; source groups and direct users are expanded after Live verification.', null);
  }
  if (users.partial || users.directComplete === false) C('assignments_partial', 'Assignment list read completely', 'critical', 'fail', `Only ${users.seen} assignment(s) were read before the page cap; the remaining direct assignments are unknown.`, 'Raise the scan page limit or reduce the assignment scope, then rescan. Staging cannot safely copy only a sample.');
  // production / risk / owner
  C('production_dependency', 'Production impact acknowledged', 'warning', (users.count >= 50 || groups.length >= 10) ? 'warn' : 'pass', `${users.count} assignment(s) through ${groups.length} group(s); Okta stays active until the owner cutover, so nobody loses access at staging.`, null);
  const privileged = a.stops.find((s) => s.key === 'privileged_app');
  C('high_risk_change', 'Privileged application', 'warning', privileged ? 'warn' : 'pass', privileged ? privileged.why : 'No privileged-app hint in the name.', privileged ? 'Approve with a named second reviewer.' : null);
  const ca = (a.policyMapping || []).filter((r) => r.status === 'not_transferable');
  C('ca_conflict', 'Sign-on policy evidence is separated from application migration', 'info', 'pass', ca.length ? ca.length + ' rule element(s) have no Entra equivalent; recorded for the separate Security & MFA project and not an app blocker.' : `${(a.policyMapping || []).length} mapping row(s) recorded for the separate project; none gate this application.`, null);
  if (!shellOnly && !assignmentsOnly && m.provisioning && m.provisioning.enabled) {
    const pi = m.provisioning.inventory || {};
    const maps = m.provisioning.mappings || [];
    const outbound = maps.filter((x) => x.direction === 'to_app');
    const manual = outbound.filter((x) => !(x.mapping && x.mapping.mappable));
    const groupPush = m.provisioning.groupPush || [];
    const semantics = M.provisioningSemantics(m.provisioning.features);
    C('provisioning_inventory', 'Okta provisioning schema and mappings are inventoried', 'critical',
      pi.complete === true ? 'pass' : 'fail',
      pi.complete === true
        ? `${outbound.length} outbound mapping(s); ${manual.length} require deliberate translation; ${groupPush.length} group-push mapping(s); connection ${m.provisioning.connection && m.provisioning.connection.status || 'status unknown'}.`
        : `Provisioning is active, but the inventory is incomplete${(pi.errors || []).length ? ': ' + pi.errors.join('; ') : '.'}`,
      pi.complete === true ? null : 'Grant okta.profileMappings.read, okta.schemas.read and okta.apps.read (or use an admin API token), then run the scan again. Group Push is part of this inventory.');
    C('provisioning_source_authority', 'Provisioning source of authority is safe to translate', 'critical',
      semantics.specialistRequired ? 'fail' : 'pass',
      semantics.specialistRequired
        ? `Specialist decision required. Inbound/mastering: ${(semantics.inbound || []).join(', ') || 'none'}; password/delegated-authentication: ${(semantics.credential || []).join(', ') || 'none'}.`
        : 'No Okta import, profile-mastering, password-push or delegated-authentication feature is active.',
      semantics.specialistRequired ? 'Record the future source of authority or replacement design, rescan, and approve a specialist plan before staging.' : null);
    C('provisioning_group_push', 'Every Okta Group Push mapping is in the worksheet', 'critical',
      pi.complete === true && (!semantics.groupPush || semantics.groupPush.length === 0 || pi.reads && pi.reads.groupPush && pi.reads.groupPush.complete === true) ? 'pass' : 'fail',
      `${groupPush.length} group-push mapping(s) recorded.`,
      pi.complete === true ? null : 'Rescan after the Group Push API can be read.');
    C('provisioning_cutover', 'Provisioning cutover is a separate verified lane', 'warning', 'warn',
      'A new vendor SCIM credential must be entered directly in Entra. Okta provisioning stays enabled until an Entra pilot cycle verifies create, update and deactivate behavior.',
      'Do not reuse or paste the Okta provisioning credential. Configure the Entra job, rebuild the mapping worksheet, test a pilot, then retire Okta provisioning separately.');
  }
  C('owner_recorded', 'Application owner recorded', 'warning', m.identity.owner ? 'pass' : 'warn', m.identity.owner || 'No owner recorded; the vendor-side change and the test sign-in need one.', m.identity.owner ? null : 'Record the owner on the assessment.');
  // dual-IdP: with coexistence Okta stays live while Entra is tested; a single-IdP vendor is a hard cutover that needs the owner's window
  const cx = a.coexistence || null;
  if (cx) C('cutover_strategy', 'Cutover strategy (does the vendor accept two IdPs?)', 'warning', cx.strategy === 'coexist' || cx.strategy === 'retire' ? 'pass' : 'warn', `${cx.label}. ${cx.strategyLabel}. ${(cx.evidence || [])[0] || ''}`,
    cx.strategy === 'coexist' || cx.strategy === 'retire' ? null : cx.strategy === 'cutover' ? 'Agree the switch window with the owner before the application is repointed: Okta sign-in stops when the vendor is repointed. If the vendor turns out to accept a second IdP, record it on the Vendor guide tab.' : 'Ask the owner or vendor whether a second IdP can be added and record the answer on the Vendor guide tab; until then plan it as a hard cutover.');
  if (!shellOnly && !assignmentsOnly && hard.filter((s) => !['ambiguous_target', 'unsupported_protocol', 'inactive'].includes(s.key)).length) C('hard_stops', 'Other hard stops', 'critical', 'fail', hard.map((s) => s.key + ': ' + s.why).join(' | '), 'Resolve them and re-run pre-flight.');
  return checks;
}

/** Pre-flight: live rescan → assessment → plan → checks → snapshot; stores an oem_migration row. */
async function preflight(oktaId, actor, { inputs = {}, targetMode = null, log = () => {} } = {}) {
  const scanRes = await M.scanApp(oktaId, log, { actor });
  if (!scanRes.ok) throw new Error('scan failed: ' + (scanRes.error || 'unknown'));
  const ctx = await M.context();
  let a = await M.assessment(oktaId, ctx);
  const scan = await M.loadScan(oktaId);
  if (!a || !scan) throw new Error('no assessment after scan');
  /* The v2 revision owns the create/adopt decision and binds approval to its plan hash. A suggested
     mirror match must not silently override an explicitly approved create-new revision. Keep the
     suggestion as evidence, but make the engine target and ambiguity checks match that decision. */
  if (targetMode === 'create') {
    a = Object.assign({}, a, {
      suggestedTarget: a.target || null,
      target: { mode: 'create', entraId: null, entraName: null, reason: 'Explicit create-new revision' },
      stops: (a.stops || []).filter((s) => s && s.key !== 'ambiguous_target')
    });
  }
  const plan = buildPlan(a, scan, ctx, inputs || {});
  const checks = await runChecks(a, scan, ctx, plan);
  const failed = checks.filter((c) => c.severity === 'critical' && c.status === 'fail');
  const unknown = checks.filter((c) => c.severity === 'critical' && c.status === 'unknown');
  const warned = checks.filter((c) => c.status === 'warn');
  const status = failed.length || unknown.length ? STATUS.PF_FAIL : STATUS.PF_PASS;
  const preflightRec = { ranAt: nowIso(), by: actor, inputs: inputs || {}, checks, summary: { critical: checks.filter((c) => c.severity === 'critical').length, failed: failed.length, unknown: unknown.length, warnings: warned.length }, passed: status === STATUS.PF_PASS, planHash: hash(plan) };
  const snapshot = { takenAt: nowIso(), oktaId, model: scan.model, raw: scan.raw, owner: scan.owner, assessment: { readiness: a.readiness, classification: a.classification, protocol: a.protocol } };
  // supersede any open plan for the same app
  await pool.query(`UPDATE oem_migration SET status='cancelled', error=CONCAT('superseded by a newer pre-flight at ', ?), finished_at=NOW() WHERE okta_id=? AND status IN ('planned','preflight_failed','preflight_passed','approved')`, [nowIso(), oktaId]);
  const [ins] = await pool.query(`INSERT INTO oem_migration (okta_id, status, protocol, readiness, scan_at, assessment, plan, preflight, snapshot, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,NOW())`,
    [oktaId, status, plan.protocol, a.readiness.score, scan.scannedAt ? new Date(scan.scannedAt) : null, JSON.stringify(a), JSON.stringify(plan), JSON.stringify(preflightRec), JSON.stringify(snapshot), actor]);
  await event(ins.insertId, oktaId, actor, 'preflight', null, null, { status, failed: failed.map((c) => c.key), warnings: warned.map((c) => c.key), inputs: Object.keys(inputs || {}) }, status, failed.map((c) => c.key + ': ' + c.detail).join(' | '));
  return getMigration(ins.insertId);
}

/* ---------------------------------------------------------------------- approve */

async function approve(id, actor, { confirm, reason, acknowledge = [] } = {}) {
  const mig = await getMigration(id, { events: false });
  if (!mig) return { error: 'no such migration', status: 404 };
  if (mig.status !== STATUS.PF_PASS) return { error: `migration is ${mig.status}; only a passed pre-flight can be approved`, status: 409 };
  const label = mig.plan.displayName;
  if (String(confirm || '') !== String(label)) return { error: 'typed confirmation must equal the application name exactly', expected: label, status: 400 };
  if (!reason || String(reason).trim().length < 5) return { error: 'a reason of at least 5 characters is required', status: 400 };
  const warns = mig.preflight.checks.filter((c) => c.status === 'warn').map((c) => c.key);
  const notAck = warns.filter((k) => !acknowledge.includes(k));
  if (notAck.length) return { error: 'every pre-flight warning must be acknowledged', warnings: notAck, status: 400 };
  // the application may have been marked migrated / verified after pre-flight: never stage a second copy
  const live = await M.assessment(mig.oktaId);
  if (live && live.alreadyMigrated && !(mig.plan && mig.plan.assignmentsOnly)) return { error: 'already migrated: ' + live.alreadyMigrated.label + ' — nothing to stage. Clear the record under "Already migrated" if it is wrong, then run pre-flight again.', status: 409 };
  // permissions could have changed since pre-flight: re-check the write credential now
  const ctx = await M.context();
  const runSteps = mig.plan.steps.filter((s) => s.exec && s.exec.method !== 'LOCAL' && s.exec.method !== 'GET' && !s.optional);
  const missing = uniq(runSteps.map((s) => permCheck(s.requires, ctx.roles)).filter((pc) => pc.ok !== true).map((pc) => pc.missing || 'write credential unreadable'));
  if (missing.length) return { error: 'staging is not enabled: needs ' + missing.join(', '), missing, grantedBy: M.ENTRA_GRANTOR, status: 403 };
  if (Date.now() - new Date(mig.createdAt).getTime() > 24 * 3600000) return { error: 'pre-flight is older than 24 hours; run it again', status: 409 };
  await setStatus(id, STATUS.APPROVED, { approved_by: actor, approved_at: new Date() });
  await event(id, mig.oktaId, actor, 'approved', null, null, { reason: String(reason).slice(0, 500), acknowledged: acknowledge, planHash: mig.preflight.planHash }, 'approved', reason);
  return getMigration(id);
}

/* -------------------------------------------------------------------------- push */

const secretStore = new Map(); // migrationId → { secret, expiresAt, keyId } — memory only, one read, 15 minutes

/** Re-read every source value that can affect the write immediately before staging. The v2
    route performs the same check for a clearer response, but the engine is also callable from
    legacy and bulk routes and must enforce the invariant itself. */
async function validateFreshSource(mig, actor, log = () => {}) {
  if (!mig || !mig.snapshot || !mig.snapshot.model || typeof M.migrationSourceFingerprint !== 'function' || typeof M.migrationSourceComplete !== 'function') {
    return { ok: false, error: 'the approved migration has no source contract; run pre-flight again', status: 409 };
  }
  let scanned;
  try { scanned = await M.scanApp(mig.oktaId, log, { actor }); }
  catch (e) { return { ok: false, error: 'fresh Okta scan failed: ' + short(e && e.message || e), status: 409 }; }
  if (!scanned || scanned.ok !== true) return { ok: false, error: 'fresh Okta scan failed; nothing was written', status: 409 };
  const current = await M.loadScan(mig.oktaId);
  if (!current || !current.model || !M.migrationSourceComplete(current.model)) {
    return { ok: false, error: 'the fresh Okta source contract is incomplete; fix the read errors and run pre-flight again', status: 409 };
  }
  const approvedFingerprint = M.migrationSourceFingerprint(mig.snapshot.model);
  const currentFingerprint = M.migrationSourceFingerprint(current.model);
  if (approvedFingerprint !== currentFingerprint) {
    return { ok: false, error: 'Okta claims, assignments, group membership or provisioning changed after approval; run pre-flight again', status: 409,
      approvedFingerprint, currentFingerprint };
  }
  return { ok: true, currentFingerprint };
}

/* The app role the assignments use. A service principal instantiated from a gallery
   template answers reads before Entra has published its app roles, so an empty list on
   a fresh template SP is not final: it is re-read on a widening cadence (45 s in total)
   before falling back to the default-access role. A plain /applications create, an
   adopted target or a managed shell keeps the list exactly as read, with no waiting. */
const ROLE_WAIT_READS = 5;
const ROLE_WAIT_MS = 3000;
const userAssignableRoles = (sp) => ((sp && sp.appRoles) || []).filter((x) => x.isEnabled !== false && (x.allowedMemberTypes || []).includes('User'));
async function resolveAppRole(spObjectId, opts = {}) {
  const created = Array.isArray(opts.created) ? opts.created : [];
  const log = typeof opts.log === 'function' ? opts.log : () => {};
  const fresh = created.some((o) => o.type === 'servicePrincipal' && o.id === spObjectId);
  const waitForRoles = fresh && opts.fromTemplate === true;
  const path = `/v1.0/servicePrincipals/${spObjectId}?$select=id,appId,appRoles,displayName`;
  const r = await readBack(path);
  if (r.status !== 200) return { roleId: DEFAULT_ROLE, why: 'service principal not readable: ' + r.error, sp: null };
  let sp = r.body; let roles = userAssignableRoles(sp);
  for (let i = 0; waitForRoles && !roles.length && i < ROLE_WAIT_READS; i++) {
    log(`Waiting for Entra to publish the new application's roles (${i + 1}/${ROLE_WAIT_READS})`, 'warn');
    await L.sleep(ROLE_WAIT_MS * (i + 1));
    const again = await L.graphGet(path);
    if (again.status !== 200) { log('service principal not readable during the role wait (' + again.status + '); still waiting', 'warn'); continue; }
    sp = again.body; roles = userAssignableRoles(sp);
  }
  const pick = roles.find((x) => /^(user|msiam_access)$/i.test(x.displayName || x.value || '')) || roles[0];
  const why = pick ? `app role "${pick.displayName || pick.value}"` : (waitForRoles ? 'default access role (no app roles published yet)' : 'default access role');
  return { roleId: pick ? pick.id : DEFAULT_ROLE, why, sp };
}

/** Run one migration's plan. Returns the final status; everything is recorded as it happens. */
async function runPush(mig, actor, log) {
  const id = mig.id, oktaId = mig.oktaId; const plan = mig.plan;
  const ctx = await M.context();
  const state = { appObjectId: mig.entraAppObjectId || null, spObjectId: mig.entraSpObjectId || null, appId: null, appRoleId: null, claimsPolicyId: null, graphSpObjectId: null, createdGroup: {}, users: {}, expectedAssignments: [] };
  const results = []; const created = mig.createdObjects || []; const warnings = []; let failure = null;
  const rec = (s, status, detail, extra) => results.push(Object.assign({ order: s.order, key: s.key, label: s.label, cls: s.cls, status, at: nowIso(), detail: short(detail, 600) }, extra || {}));
  const persist = async () => setStatus(id, STATUS.RUNNING, { results: { steps: results, warnings, state: { appObjectId: state.appObjectId, spObjectId: state.spObjectId, appId: state.appId, expectedAssignments: state.expectedAssignments } }, created_objects: created, entra_app_object_id: state.appObjectId, entra_sp_object_id: state.spObjectId });
  const G = (method, path, body, s, previous) => graphCall(method, path, body, { perm: s.requires, roles: ctx.roles, migrationId: id, oktaId, actor, stepKey: s.key, previous, log });

  // adopt: the target's current values are read first so every PATCH carries its previous value
  if (plan.mode === 'adopt') {
    const s = plan.steps.find((x) => x.key === 'adopt_target');
    const r = await L.graphGet(s.exec.path);
    const row = r.status === 200 && r.body && (r.body.id ? r.body : (r.body.value && r.body.value[0]));
    if (!row) { failure = { step: 'adopt_target', error: 'confirmed Entra app not readable: ' + (r.error || 'not found') }; rec(s, 'failed', failure.error); }
    else { state.spObjectId = row.id; state.appId = row.appId; state.previousSp = row; const app = await L.graphGet(`/v1.0/applications?$filter=appId eq '${row.appId}'&$select=id,identifierUris,web,groupMembershipClaims,optionalClaims`); state.appObjectId = app.status === 200 && app.body.value[0] ? app.body.value[0].id : null; state.previousApp = app.status === 200 ? app.body.value[0] : null; rec(s, 'ok', `adopting ${row.displayName} (sp ${row.id}${state.appObjectId ? ', app ' + state.appObjectId : ', application object not readable'})`); }
  }
  if (plan.samlEndpointUpdate && (!state.appObjectId || !state.previousSp || state.previousSp.preferredSingleSignOnMode !== 'saml' || String(state.previousSp.preferredTokenSigningKeyThumbprint || '').toUpperCase() !== String(plan.samlHandoffThumbprint).toUpperCase())) {
    failure = { step: 'adopt_target', error: 'The prepared SAML application or signing certificate changed. Reload Vendor setup before applying the returned values.' };
  }
  for (const s of plan.steps) {
    if (failure) { rec(s, 'not_run', 'a previous step failed'); continue; }
    if (log.cancelled && log.cancelled()) { failure = { step: s.key, error: 'cancelled by the technician' }; rec(s, 'not_run', 'cancelled'); continue; }
    if (s.key === 'adopt_target') continue;
    if (!s.exec) { rec(s, s.cls === CLS.UNSUPPORTED ? 'unsupported' : 'handoff', s.handoff ? (typeof s.handoff === 'string' ? s.handoff : JSON.stringify(s.handoff).slice(0, 500)) : s.note); continue; }
    if (s.exec.method === 'LOCAL') {
      if (s.exec.path === 'snapshot') { rec(s, 'ok', 'snapshot stored at pre-flight ' + (mig.snapshot && mig.snapshot.takenAt)); continue; }
      if (s.exec.path === 'verify') { rec(s, 'ok', 'verification runs after the last write (below)'); continue; }
    }
    if (s.exec.method === 'GET') { const r = await L.graphGet(s.exec.path); rec(s, r.status === 200 ? 'ok' : 'failed', r.status === 200 ? JSON.stringify(summarize(r.body.value ? r.body.value[0] : r.body)) : r.error); if (r.status !== 200 && s.blocking) failure = { step: s.key, error: r.error }; continue; }
    // ---- writes
    try {
      if (s.key === 'create_app' && /\/applications$/.test(s.exec.path)) {
        const r = await G('POST', s.exec.path, s.exec.body, s);
        if (!r.ok) { failure = { step: s.key, error: r.error }; rec(s, 'failed', r.error); break; }
        state.appObjectId = r.body.id; state.appId = r.body.appId; created.push({ type: 'application', id: r.body.id, appId: r.body.appId, at: nowIso() });
        rec(s, 'ok', `application ${r.body.id} (appId ${r.body.appId})`); await persist(); continue;
      }
      if (s.key === 'create_app' && /instantiate$/.test(s.exec.path)) {
        const r = await G('POST', s.exec.path, s.exec.body, s);
        if (!r.ok) { failure = { step: s.key, error: r.error }; rec(s, 'failed', r.error); break; }
        state.appObjectId = r.body.application && r.body.application.id; state.spObjectId = r.body.servicePrincipal && r.body.servicePrincipal.id; state.appId = r.body.application && r.body.application.appId;
        state.spFromTemplate = true; // a template publishes its app roles after instantiate returns; the assignment steps wait for them
        created.push({ type: 'servicePrincipal', id: state.spObjectId, at: nowIso() }, { type: 'application', id: state.appObjectId, appId: state.appId, at: nowIso() });
        rec(s, 'ok', `application ${state.appObjectId}, service principal ${state.spObjectId}, appId ${state.appId}`); await persist();
        const rb = await readBack(`/v1.0/servicePrincipals/${state.spObjectId}?$select=id`); if (rb.status !== 200) log('service principal not readable yet (' + rb.status + '); continuing', 'warn');
        continue;
      }
      if (s.key === 'configure_oidc') {
        const r = await G('POST', s.exec.path, fill(s.exec.body, state), s);
        if (!r.ok) { failure = { step: s.key, error: r.error }; rec(s, 'failed', r.error); break; }
        state.spObjectId = r.body.id; created.push({ type: 'servicePrincipal', id: r.body.id, at: nowIso() }); rec(s, 'ok', `service principal ${r.body.id}`); await persist(); continue;
      }
      if (s.key === 'consent') {
        if (!state.graphSpObjectId) { const g = await L.graphGet(`/v1.0/servicePrincipals?$filter=appId eq '${GRAPH_APP_ID}'&$select=id`); state.graphSpObjectId = g.status === 200 && g.body.value[0] ? g.body.value[0].id : null; }
        if (!state.graphSpObjectId) { warnings.push('consent: Microsoft Graph service principal not found; consent not granted'); rec(s, 'skipped', 'Graph service principal not readable'); continue; }
        const r = await G('POST', s.exec.path, fill(s.exec.body, state), s);
        if (!r.ok) { warnings.push('consent: ' + r.error); rec(s, r.refused ? 'skipped' : 'failed', r.error); continue; }
        created.push({ type: 'oauth2PermissionGrant', id: r.body.id, at: nowIso() }); rec(s, 'ok', 'grant ' + r.body.id); continue;
      }
      if (s.key === 'client_secret') {
        const r = await G('POST', fill(s.exec.path, state), s.exec.body, s);
        if (!r.ok) { failure = { step: s.key, error: r.error }; rec(s, 'failed', r.error); break; }
        secretStore.set(id, { secret: r.body.secretText, keyId: r.body.keyId, expiresAt: Date.now() + 15 * 60000, endDateTime: r.body.endDateTime, actor: String(actor || '').trim().toLowerCase() });
        created.push({ type: 'passwordCredential', id: r.body.keyId, appObjectId: state.appObjectId, at: nowIso() });
        rec(s, 'ok', `secret ${r.body.keyId} created; readable once by the technician who staged, for 15 minutes`, { secretKeyId: r.body.keyId, secretEnds: r.body.endDateTime }); continue;
      }
      if (s.key === 'claims' && /claimsMappingPolicies$/.test(s.exec.path)) {
        const r = await G('POST', s.exec.path, s.exec.body, s);
        if (!r.ok) { failure = { step: s.key, error: r.error }; rec(s, 'failed', r.error); break; }
        state.claimsPolicyId = r.body.id; created.push({ type: 'claimsMappingPolicy', id: r.body.id, at: nowIso() }); rec(s, 'ok', 'policy ' + r.body.id); continue;
      }
      if (s.key === 'signing_certificate') {
        const r = await G('POST', fill(s.exec.path, state), s.exec.body, s);
        if (!r.ok) { failure = { step: s.key, error: r.error }; rec(s, 'failed', r.error); break; }
        const thumb = r.body.thumbprint;
        const p = await G('PATCH', `/v1.0/servicePrincipals/${state.spObjectId}`, { preferredTokenSigningKeyThumbprint: thumb }, s, { preferredTokenSigningKeyThumbprint: state.previousSp ? state.previousSp.preferredTokenSigningKeyThumbprint : null });
        if (!p.ok) { warnings.push('signing_certificate: certificate created but not set as preferred: ' + p.error); rec(s, 'warning', 'created ' + thumb + ' but preferred key not set: ' + p.error); continue; }
        rec(s, 'ok', 'certificate ' + thumb + ' (ends ' + r.body.endDateTime + ')', { thumbprint: thumb, endDateTime: r.body.endDateTime }); continue;
      }
      if (s.key === 'create_groups') {
        const r = await G('POST', s.exec.path, s.exec.body, s);
        if (!r.ok) { failure = { step: s.key, error: r.error }; rec(s, 'failed', r.error); break; }
        const gid = r.body.id; created.push({ type: 'group', id: gid, name: s.exec.body.displayName, at: nowIso() });
        const okGroup = (mig.snapshot.model.assignments.groups || []).find((g) => g.name === s.exec.body.displayName);
        state.createdGroup[okGroup ? okGroup.id : s.exec.body.displayName] = gid;
        // Membership is the complete set captured by the approved pre-flight snapshot. Never
        // re-read Okta here: that would let a source change bypass approval, and a partial page
        // could silently create an incomplete Entra group.
        let added = 0, missed = [];
        if (okGroup) {
          if (okGroup.membersComplete !== true || !Array.isArray(okGroup.members)) {
            failure = { step: s.key, error: `approved membership snapshot for Okta group ${okGroup.name || okGroup.id} is incomplete` };
            rec(s, 'failed', failure.error); break;
          }
          for (const u of okGroup.members) {
            const upn = u.userName; if (!upn) { missed.push((u.id || '?') + ': no login/email in approved snapshot'); continue; }
            const eu = await L.graphGet(`/v1.0/users?$filter=userPrincipalName eq '${encodeURIComponent(String(upn).replace(/'/g, "''"))}'&$select=id`);
            const uid = eu.status === 200 && eu.body.value[0] ? eu.body.value[0].id : null;
            if (!uid) { missed.push(upn); continue; }
            const ar = await G('POST', `/v1.0/groups/${gid}/members/$ref`, { '@odata.id': 'https://graph.microsoft.com/v1.0/directoryObjects/' + uid }, s);
            if (ar.ok) added++; else missed.push(upn + ' (' + short(ar.error, 80) + ')');
          }
        }
        if (missed.length) {
          failure = { step: s.key, error: `group ${s.exec.body.displayName}: ${missed.length} approved member(s) were not added: ${missed.slice(0, 10).join(', ')}` };
          rec(s, 'failed', failure.error); break;
        }
        rec(s, 'ok', `group ${gid}; ${added} member(s) added from the approved snapshot`); await persist(); continue;
      }
      if (s.key === 'assign_groups' || s.key === 'assign_created_groups' || s.key === 'assign_users') {
        if (!state.appRoleId) { const ar = await resolveAppRole(state.spObjectId, { created, fromTemplate: state.spFromTemplate === true, log }); state.appRoleId = ar.roleId; log(`assignments use ${ar.why}`); }
        let ok = 0; const errs = [];
        for (const item of s.exec.body) {
          const b = Object.assign({}, item); delete b._group; delete b._user;
          if (/\{\{createdGroup:(.+?)\}\}/.test(b.principalId)) { const k = b.principalId.match(/\{\{createdGroup:(.+?)\}\}/)[1]; b.principalId = state.createdGroup[k] || null; }
          if (/\{\{user:(.+?)\}\}/.test(b.principalId)) { const upn = b.principalId.match(/\{\{user:(.+?)\}\}/)[1]; const eu = await L.graphGet(`/v1.0/users?$filter=userPrincipalName eq '${encodeURIComponent(upn.replace(/'/g, "''"))}'&$select=id`); b.principalId = eu.status === 200 && eu.body.value[0] ? eu.body.value[0].id : null; if (!b.principalId) { errs.push((item._user || '?') + ': not found in Entra by UPN'); continue; } }
          if (!b.principalId) { errs.push((item._group || item._user || '?') + ': no Entra object'); continue; }
          if (!state.expectedAssignments.some((x) => x.principalId === b.principalId)) state.expectedAssignments.push({ principalId: b.principalId, principalType: b.principalType || null, label: item._group || item._user || b.principalId });
          const r = await assignAfterCreate(() => G('POST', fill(s.exec.path, state), fill(b, state), s), state.spObjectId, created, log, { state });
          if (r.ok) { ok++; created.push({ type: 'appRoleAssignment', id: r.body.id, spObjectId: state.spObjectId, principalId: b.principalId, principal: item._group || item._user, at: nowIso() }); }
          else if (r.status === 400 && /already exists|Permission being assigned already exists/i.test(r.error || '')) ok++;
          else errs.push((item._group || item._user || '?') + ': ' + short(r.error, 120));
        }
        if (errs.length) warnings.push(`${s.key}: ${errs.length} assignment(s) failed: ${errs.slice(0, 8).join('; ')}`);
        rec(s, errs.length ? (ok ? 'warning' : 'failed') : 'ok', `${ok} of ${s.exec.body.length} assigned${errs.length ? '; ' + errs.join('; ') : ''}`);
        if (!ok && errs.length && s.blocking) { failure = { step: s.key, error: errs[0] }; break; }
        await persist(); continue;
      }
      // generic PATCH / POST with placeholders (configure_saml, redirect_uris, linked_mode, password_sso, group_claims, claims_attach, claims (OIDC PATCH))
      const path = fill(s.exec.path, state); const body = fill(s.exec.body, state);
      if (unresolved(path) || unresolved(body)) { failure = { step: s.key, error: 'unresolved value in the payload: ' + JSON.stringify(body).match(/\{\{\w+\}\}/)[0] }; rec(s, 'failed', failure.error); break; }
      let previous = null;
      if (s.exec.method === 'PATCH') { const cur = await L.graphGet(path.split('?')[0] + '?$select=' + Object.keys(body).filter((k) => !k.startsWith('@')).join(',')); previous = cur.status === 200 ? cur.body : null; }
      let r = await G(s.exec.method, path, body, s, previous);
      for (let i = 0; !r.ok && r.status === 404 && created.length && i < 4; i++) { log(`${s.key}: object not visible yet (404) — waiting ${3 * (i + 1)}s for directory replication`, 'warn'); await L.sleep(3000 * (i + 1)); r = await G(s.exec.method, path, body, s, previous); }
      if (!r.ok) { if (s.optional) { warnings.push(s.key + ': ' + r.error); rec(s, r.refused ? 'skipped' : 'failed', r.error); continue; } failure = { step: s.key, error: r.error }; rec(s, 'failed', r.error); break; }
      if (s.key === 'claims_attach') created.push({ type: 'claimsMappingPolicyRef', spObjectId: state.spObjectId, policyId: state.claimsPolicyId, at: nowIso() });
      if (previous && plan.mode === 'adopt') created.push({ type: 'patch', path, previous, at: nowIso() });
      rec(s, 'ok', s.exec.method + ' ' + path);
    } catch (e) {
      failure = { step: s.key, error: e.message }; rec(s, 'failed', e.message); break;
    }
  }
  // ---- outcome
  const ran = results.filter((r) => r.status === 'ok' || r.status === 'warning').map((r) => r.key);
  const notRun = plan.steps.filter((s) => !results.find((r) => r.key === s.key && r.status !== 'not_run')).map((s) => s.key);
  const handoffs = results.filter((r) => r.status === 'handoff').map((r) => r.key);
  let status, verification = null;
  if (failure) {
    status = STATUS.FAILED;
    const recovery = [`Step "${failure.step}" failed: ${failure.error}.`, `Succeeded before it: ${ran.length ? ran.join(', ') : 'nothing'}.`, `Did not run: ${notRun.length ? notRun.join(', ') : 'nothing'}.`,
      created.length ? `Entra objects created so far: ${created.map((c) => c.type + ' ' + (c.id || '')).join(', ')} — Rollback removes them; fixing the cause and re-running pre-flight creates a fresh plan.` : 'No Entra object was created.', 'Okta was not changed; users keep signing in through Okta.'];
    await setStatus(id, status, { results: { steps: results, warnings, state, failure, recovery }, created_objects: created, entra_app_object_id: state.appObjectId, entra_sp_object_id: state.spObjectId, finished_at: new Date(), error: short(failure.step + ': ' + failure.error, 2000) });
    await event(id, oktaId, actor, 'push_failed', failure.step, null, { failure, ran, notRun }, 'failed', failure.error);
    log('staging failed at ' + failure.step + ': ' + failure.error, 'error');
    return { status, failure, recovery };
  }
  verification = await verifyLive({ id, oktaId, plan, state, created, mig }, log);
  status = verification.ok && !warnings.length ? STATUS.OK : STATUS.WARN;
  const handoffValues = fill(plan.handoffValues || {}, state);
  await setStatus(id, status, { results: { steps: results, warnings, state, handoffs, handoffValues }, verification, created_objects: created, entra_app_object_id: state.appObjectId, entra_sp_object_id: state.spObjectId, finished_at: new Date(), error: null });
  await event(id, oktaId, actor, status === STATUS.OK ? 'push_succeeded' : 'push_warnings', null, null, { ran, handoffs, warnings, verification: verification.summary }, status, warnings.concat(verification.mismatches.map((x) => x.what + ': ' + x.detail)).join(' | ') || null);
  log(`staging ${status}: ${ran.length} step(s) applied, ${handoffs.length} hand-off(s), ${warnings.length} warning(s); verification ${verification.summary}`, status === STATUS.OK ? 'info' : 'warn');
  return { status, warnings, verification, handoffValues };
}

/* ----------------------------------------------------------------------- verify */

/** Live re-read of what the plan said would exist. Never infers success from the absence of an error. */
async function verifyLive({ id, oktaId, plan, state, created, mig }, log = () => {}) {
  const checks = []; const mismatches = [];
  const chk = (what, expected, actual, ok, detail) => { checks.push({ what, expected: short(JSON.stringify(expected), 300), actual: short(JSON.stringify(actual), 300), ok }); if (ok === false) mismatches.push({ what, detail: detail || `expected ${short(JSON.stringify(expected), 120)}, read ${short(JSON.stringify(actual), 120)}` }); };
  const t = M.entraProto(mig.snapshot.model); // protocol staged in Entra
  const shellOnly = plan.shellOnly === true;
  const assignmentsOnly = plan.assignmentsOnly === true;
  if (!state.spObjectId && !state.appObjectId) return { verifiedAt: nowIso(), ok: false, summary: 'nothing to verify (no Entra object recorded)', checks, mismatches: [{ what: 'objects', detail: 'no Entra object was recorded for this migration' }] };
  const sp = state.spObjectId ? await readBack(`/v1.0/servicePrincipals/${state.spObjectId}?$select=id,appId,displayName,accountEnabled,preferredSingleSignOnMode,replyUrls,loginUrl,homepage,appRoleAssignmentRequired,tags,preferredTokenSigningKeyThumbprint,samlSingleSignOnSettings,notes`) : null;
  const app = state.appObjectId ? await readBack(`/v1.0/applications/${state.appObjectId}?$select=id,appId,displayName,identifierUris,web,spa,publicClient,groupMembershipClaims,optionalClaims,passwordCredentials,requiredResourceAccess`) : null;
  if (sp) { chk('service principal readable', 'HTTP 200', 'HTTP ' + sp.status, sp.status === 200, sp.error); }
  if (app) { chk('application readable', 'HTTP 200', 'HTTP ' + app.status, app.status === 200, app.error); }
  const S = sp && sp.status === 200 ? sp.body : null; const A = app && app.status === 200 ? app.body : null;
  if (S) {
    if (plan.samlEndpointUpdate) {
      chk('signing certificate unchanged', plan.samlHandoffThumbprint, S.preferredTokenSigningKeyThumbprint, S.preferredTokenSigningKeyThumbprint === plan.samlHandoffThumbprint);
      const wantRelay = plan.steps.find((s) => s.key === 'configure_saml').exec.body.samlSingleSignOnSettings.relayState;
      const haveRelay = (S.samlSingleSignOnSettings || {}).relayState || '';
      chk('vendor relay state', wantRelay, haveRelay, wantRelay === haveRelay);
    }
    chk('enterprise app enabled', true, S.accountEnabled, S.accountEnabled === true);
    chk('assignment required', true, S.appRoleAssignmentRequired, S.appRoleAssignmentRequired === true);
    if (plan.mode === 'create') {
      const tags = Array.isArray(S.tags) ? S.tags : [];
      chk('visible in My Apps', true, !tags.includes('HideApp'), !tags.includes('HideApp'),
        'The service principal contains the HideApp tag. Remove it so assigned users can find the application in My Apps.');
    }
    if (!shellOnly && !assignmentsOnly && t === 'saml') {
      chk('SSO mode', 'saml', S.preferredSingleSignOnMode, S.preferredSingleSignOnMode === 'saml');
      chk('preferred signing certificate set', 'thumbprint', S.preferredTokenSigningKeyThumbprint, !!S.preferredTokenSigningKeyThumbprint);
      const pol = await L.graphGet(`/v1.0/servicePrincipals/${S.id}/claimsMappingPolicies?$select=id,displayName`);
      if (plan.steps.find((s) => s.key === 'claims_attach')) chk('claims-mapping policy attached', state.claimsPolicyId, pol.status === 200 ? (pol.body.value || []).map((p) => p.id) : pol.error, pol.status === 200 && (pol.body.value || []).some((p) => p.id === state.claimsPolicyId));
    }
    if (!shellOnly && !assignmentsOnly && t === 'swa') chk('SSO mode', 'password', S.preferredSingleSignOnMode, S.preferredSingleSignOnMode === 'password');
    if (!shellOnly && !assignmentsOnly && t === 'bookmark') chk('tile URL', mig.snapshot.model.bookmark.url, S.homepage || S.loginUrl, (S.homepage || S.loginUrl) === mig.snapshot.model.bookmark.url);
    const asg = await L.graphAll(`/v1.0/servicePrincipals/${S.id}/appRoleAssignedTo?$top=999`, { maxPages: 10 });
    const expected = Array.isArray(state.expectedAssignments) ? state.expectedAssignments : [];
    const have = (asg.items || []).length;
    if (shellOnly) chk('shell assignments', 0, have, asg.error ? null : have === 0, asg.error || 'A staged shell must remain isolated until configuration starts.');
    else {
      const actualIds = new Set((asg.items || []).map((x) => x.principalId).filter(Boolean));
      const missing = expected.filter((x) => !actualIds.has(x.principalId));
      chk(assignmentsOnly ? 'production assignments present' : 'pilot assignments present', expected.map((x) => x.label), (asg.items || []).map((x) => x.principalDisplayName || x.principalId), asg.error ? null : missing.length === 0,
        asg.error || (missing.length ? 'Missing approved assignment(s): ' + missing.map((x) => x.label).join(', ') : null));
    }
  }
  if (A) {
    if (!shellOnly && !assignmentsOnly && t === 'oidc') {
      const want = mig.snapshot.model.oidc.redirectUris;
      const haveUris = [].concat((A.web && A.web.redirectUris) || [], (A.spa && A.spa.redirectUris) || [], (A.publicClient && A.publicClient.redirectUris) || []);
      chk('redirect URIs', want, haveUris, want.every((u) => haveUris.includes(u)));
      if (mig.snapshot.model.oidc.secretRequired) chk('client secret present', '1 credential', (A.passwordCredentials || []).length, (A.passwordCredentials || []).length >= 1);
    }
    if (!shellOnly && !assignmentsOnly && t === 'saml') {
      const samlApp = (plan.steps.find((s) => s.key === 'redirect_uris') || { exec: { body: {} } }).exec.body;
      const eid = samlApp.identifierUris || [];
      if (eid.length && !unresolved(eid)) chk('entity id (identifier URI)', eid, A.identifierUris, eid.every((u) => (A.identifierUris || []).includes(u)));
      const reply = (samlApp.web && samlApp.web.redirectUris) || [];
      if (reply.length && !unresolved(reply)) chk('reply URLs', reply, (A.web && A.web.redirectUris) || [], reply.every((u) => ((A.web && A.web.redirectUris) || []).includes(u)));
      if (plan.steps.find((s) => s.key === 'group_claims')) chk('groups claim', 'ApplicationGroup', A.groupMembershipClaims, A.groupMembershipClaims === 'ApplicationGroup');
    }
  }
  // sign-in evidence: inconclusive when absent; a count is evidence only when > 0
  let signIns = { status: 'unknown', count: null, since: null };
  if (state.appId) {
    const since = new Date(Date.now() - 24 * 3600000).toISOString();
    const r = await L.graphGet(`/v1.0/auditLogs/signIns?$filter=appId eq '${state.appId}' and createdDateTime ge ${since}&$top=50`);
    signIns = r.status === 200 ? { status: (r.body.value || []).length ? 'seen' : 'none_yet', count: (r.body.value || []).length, since, note: (r.body.value || []).length ? null : 'No sign-in through Entra yet: expected until the owner repoints the vendor and a user tests. Inconclusive, not a failure.' } : { status: 'unknown', count: null, since, note: 'sign-in log not readable: ' + r.error };
  }
  const okAll = checks.length > 0 && checks.every((c) => c.ok === true);
  const summary = `${checks.filter((c) => c.ok === true).length} of ${checks.length} checks matched` + (mismatches.length ? `; ${mismatches.length} mismatch(es)` : '') + (checks.some((c) => c.ok === null) ? '; some unreadable' : '');
  log('verification: ' + summary, okAll ? 'info' : 'warn');
  return { verifiedAt: nowIso(), ok: okAll, summary, checks, mismatches, signIns, okta: { status: mig.snapshot.model.identity.status, note: 'Okta is not changed by staging; deactivate it with the lifecycle action after the owner cutover and a verified sign-in.' } };
}

async function verify(id, actor) {
  const mig = await getMigration(id, { events: false });
  if (!mig) return { error: 'no such migration', status: 404 };
  if (![STATUS.OK, STATUS.WARN, STATUS.FAILED].includes(mig.status)) return { error: `migration is ${mig.status}; verification applies after staging`, status: 409 };
  const state = (mig.results && mig.results.state) || { appObjectId: mig.entraAppObjectId, spObjectId: mig.entraSpObjectId, appId: null };
  if (!state.appId && state.appObjectId) { const a = await L.graphGet(`/v1.0/applications/${state.appObjectId}?$select=appId`); state.appId = a.status === 200 ? a.body.appId : null; }
  const v = await verifyLive({ id, oktaId: mig.oktaId, plan: mig.plan, state, created: mig.createdObjects || [], mig });
  const status = mig.status === STATUS.FAILED ? STATUS.FAILED : (v.ok && !(mig.results && mig.results.warnings && mig.results.warnings.length) ? STATUS.OK : STATUS.WARN);
  await setStatus(id, status, { verification: v });
  await event(id, mig.oktaId, actor, 'verified', null, null, { summary: v.summary, ok: v.ok, signIns: v.signIns }, status, v.mismatches.map((x) => x.what + ': ' + x.detail).join(' | ') || null);
  return getMigration(id);
}

/* --------------------------------------------------------------------- push job */

async function push(id, actor) {
  const mig = await getMigration(id, { events: false });
  if (!mig) return { error: 'no such migration', status: 404 };
  if (mig.status !== STATUS.APPROVED) return { error: `migration is ${mig.status}; only an approved migration can be staged in Entra`, status: 409 };
  if (hash(mig.plan) !== mig.preflight.planHash) return { error: 'the plan changed after approval; run pre-flight again', status: 409 };
  const live = await M.assessment(mig.oktaId);
  if (live && live.alreadyMigrated && !(mig.plan && mig.plan.assignmentsOnly)) return { error: 'already migrated: ' + live.alreadyMigrated.label + ' — nothing to stage. Clear the record under "Already migrated" if it is wrong, then run pre-flight again.', status: 409 };
  const fresh = await validateFreshSource(mig, actor);
  if (!fresh.ok) return fresh;
  const ctx = await M.context();
  const runSteps = mig.plan.steps.filter((s) => s.exec && s.exec.method !== 'LOCAL' && s.exec.method !== 'GET' && !s.optional);
  const missing = uniq(runSteps.map((s) => permCheck(s.requires, ctx.roles)).filter((pc) => pc.ok !== true).map((pc) => pc.missing || 'write credential unreadable'));
  if (missing.length) return { error: 'staging is not enabled: needs ' + missing.join(', '), missing, grantedBy: M.ENTRA_GRANTOR, status: 403 };
  const started = await L.startJob('migrate-push-' + mig.oktaId, actor, async (log) => {
    // A reset can cancel the plan during pre-push reads. Claim it atomically
    // before any tenant write; a stale page cannot execute an archived plan.
    const [claimed] = await pool.query("UPDATE oem_migration SET status='running', pushed_by=?, pushed_at=NOW() WHERE id=? AND status='approved'", [actor, id]);
    if (!claimed || !claimed.affectedRows) throw new Error('The migration changed before staging started; reload and review the current plan.');
    await event(id, mig.oktaId, actor, 'push_started', null, null, { steps: mig.plan.steps.length }, 'running', null);
    log(`staging started for ${mig.plan.displayName}: ${mig.plan.steps.length} step(s), mode ${mig.plan.mode}`);
    const out = await runPush(mig, actor, log);
    return { migrationId: id, status: out.status, warnings: out.warnings || [], failure: out.failure || null, recovery: out.recovery || null, verification: out.verification ? out.verification.summary : null, handoffValues: out.handoffValues || null };
  });
  if (started.conflict) return { error: 'a staging run for this application is already running', conflict: started.conflict, status: 409 };
  await pool.query(`UPDATE oem_migration SET job_id=? WHERE id=?`, [started.id, id]);
  return { ok: true, jobId: started.id, migrationId: id };
}

/** One-time read of a client secret created by staging (memory only, 15 minutes, the technician who staged only). */
function secretOnce(id, actor) {
  const s = secretStore.get(id);
  if (!s) return { error: 'no secret is held for this migration (already read, older than 15 minutes, or none was created)', status: 404 };
  if (Date.now() > s.expiresAt) { secretStore.delete(id); return { error: 'the secret handoff window has expired; create a new secret in the Entra portal', status: 410 }; }
  if (!s.actor || s.actor !== String(actor || '').trim().toLowerCase()) return { error: 'only the technician who pushed can read the secret', status: 403 };
  secretStore.delete(id);
  return { ok: true, migrationId: id, keyId: s.keyId, endDateTime: s.endDateTime, secret: s.secret, note: 'Shown once. Not stored anywhere on the platform.' };
}
function secretHeld(id) { const s = secretStore.get(id); return !!(s && Date.now() <= s.expiresAt); }

/* ------------------------------------------------- client secrets for the application-side hand-off */
/** The secrets on the application staging created — key ids, names, hints and dates only (Graph never returns a value). */
async function listSecrets(id) {
  const mig = await getMigration(id, { events: false });
  if (!mig) return { error: 'no such migration', status: 404 };
  if (mig.protocol !== 'oidc') return { error: 'not an OpenID Connect migration: SAML applications use the signing certificate, not a client secret', status: 409 };
  if (!mig.entraAppObjectId) return { error: 'this migration recorded no Entra application object', status: 409 };
  const r = await readBack(`/v1.0/applications/${mig.entraAppObjectId}?$select=id,appId,displayName,passwordCredentials`, 1);
  if (r.status !== 200) return { error: 'application not readable: ' + (r.error || r.status), status: 502 };
  const mine = new Set((mig.createdObjects || []).filter((o) => o.type === 'passwordCredential').map((o) => o.id));
  const now = Date.now();
  return { ok: true, migrationId: id, appId: r.body.appId, appObjectId: r.body.id, displayName: r.body.displayName, held: secretHeld(id), heldFor: mig.pushedBy || null,
    secrets: (r.body.passwordCredentials || []).map((c) => ({ keyId: c.keyId, displayName: c.displayName || null, hint: c.hint || null, startDateTime: c.startDateTime, endDateTime: c.endDateTime, expired: c.endDateTime ? new Date(c.endDateTime).getTime() < now : null, createdHere: mine.has(c.keyId) })),
    note: 'A secret value is shown once, to the person who created it. It is never stored on this platform; if the window passed, issue a new one and remove the old one once the vendor works.' };
}
/** Issue a NEW client secret for the application-side hand-off (the one-time window passed, or a rotation).
    Shown once to the requester, never stored; recorded as a created object so a rollback removes it too. */
async function issueSecret(id, actor, { days = 180, reason } = {}) {
  const mig = await getMigration(id, { events: false });
  if (!mig) return { error: 'no such migration', status: 404 };
  if (![STATUS.OK, STATUS.WARN].includes(mig.status)) return { error: `migration is ${mig.status}; a secret can only be issued after a completed staging run`, status: 409 };
  if (mig.protocol !== 'oidc') return { error: 'not an OpenID Connect migration: SAML applications use the signing certificate, not a client secret', status: 409 };
  if (!mig.entraAppObjectId) return { error: 'this migration recorded no Entra application object', status: 409 };
  if (!reason || String(reason).trim().length < 5) return { error: 'a reason of at least 5 characters is required (for example: entering it in the vendor console)', status: 400 };
  const d = Math.min(730, Math.max(1, parseInt(days, 10) || 180));
  const ctx = await M.context();
  const r = await graphCall('POST', `/v1.0/applications/${mig.entraAppObjectId}/addPassword`, { passwordCredential: { displayName: short('okta-migration reissue ' + nowIso().slice(0, 10) + ' ' + (actor || ''), 100), endDateTime: plusDays(d) } },
    { perm: PERM.APP_WRITE, roles: ctx.roles, migrationId: id, oktaId: mig.oktaId, actor, stepKey: 'issue_secret', previous: null, log: null });
  if (!r.ok) return { error: r.error || ('Graph returned ' + r.status), status: r.refused ? 403 : 502, grantedBy: r.refused ? M.ENTRA_GRANTOR : undefined };
  const created = (mig.createdObjects || []).concat([{ type: 'passwordCredential', id: r.body.keyId, appObjectId: mig.entraAppObjectId, at: nowIso(), reissued: true, by: actor }]);
  await pool.query(`UPDATE oem_migration SET created_objects=? WHERE id=?`, [JSON.stringify(created), id]);
  await event(id, mig.oktaId, actor, 'secret_issued', 'issue_secret', null, { keyId: r.body.keyId, endDateTime: r.body.endDateTime, days: d }, 'ok', short(reason, 300));
  return { ok: true, migrationId: id, keyId: r.body.keyId, endDateTime: r.body.endDateTime, secret: r.body.secretText, note: 'Shown once. Not stored anywhere on the platform — paste it straight into the vendor field. Remove the previous secret once the vendor signs in with this one.' };
}
/** Remove one client secret. Destructive: a vendor still using it stops signing in — typed confirmation required. */
async function removeSecret(id, actor, { keyId, confirm, reason } = {}) {
  const mig = await getMigration(id, { events: false });
  if (!mig) return { error: 'no such migration', status: 404 };
  if (mig.protocol !== 'oidc' || !mig.entraAppObjectId) return { error: 'no Entra application with client secrets on this migration', status: 409 };
  if (!/^[0-9a-f-]{36}$/i.test(String(keyId || ''))) return { error: 'keyId must be the secret\'s key id (a GUID)', status: 400 };
  const expected = 'REMOVE ' + String(keyId).slice(0, 8);
  if (String(confirm || '') !== expected) return { error: 'typed confirmation must be exactly: ' + expected, status: 400 };
  if (!reason || String(reason).trim().length < 5) return { error: 'a reason of at least 5 characters is required', status: 400 };
  const ctx = await M.context();
  const r = await graphCall('POST', `/v1.0/applications/${mig.entraAppObjectId}/removePassword`, { keyId }, { perm: PERM.APP_WRITE, roles: ctx.roles, migrationId: id, oktaId: mig.oktaId, actor, stepKey: 'remove_secret', previous: null, log: null });
  if (!r.ok && r.status !== 404) return { error: r.error || ('Graph returned ' + r.status), status: r.refused ? 403 : 502, grantedBy: r.refused ? M.ENTRA_GRANTOR : undefined };
  const created = (mig.createdObjects || []).filter((o) => !(o.type === 'passwordCredential' && o.id === keyId));
  await pool.query(`UPDATE oem_migration SET created_objects=? WHERE id=?`, [JSON.stringify(created), id]);
  await event(id, mig.oktaId, actor, 'secret_removed', 'remove_secret', { keyId }, null, 'ok', short(reason, 300));
  return { ok: true, migrationId: id, keyId, removed: true };
}

/* ----------------------------------------------------------------------- cancel */

/** Discard a plan that has not been staged. Records who and why; the row stays as history. */
async function cancel(id, actor, { reason } = {}) {
  const mig = await getMigration(id, { events: false });
  if (!mig) return { error: 'no such migration', status: 404 };
  if (![STATUS.PLANNED, STATUS.PF_FAIL, STATUS.PF_PASS, STATUS.APPROVED].includes(mig.status)) return { error: `migration is ${mig.status}; only a plan that has not been staged can be cancelled`, status: 409 };
  const why = short(reason, 300) || 'no reason given';
  await setStatus(id, STATUS.CANCELLED, { error: `cancelled by ${actor}: ${why}`, finished_at: new Date() });
  await event(id, mig.oktaId, actor, 'cancelled', null, mig.status, STATUS.CANCELLED, 'cancelled', why);
  return getMigration(id);
}

/* --------------------------------------------------------------------- rollback */

async function rollback(id, actor, { confirm, reason } = {}) {
  const mig = await getMigration(id, { events: false });
  if (!mig) return { error: 'no such migration', status: 404 };
  if (![STATUS.OK, STATUS.WARN, STATUS.FAILED].includes(mig.status)) return { error: `migration is ${mig.status}; rollback applies after staging`, status: 409 };
  if (String(confirm || '') !== 'ROLLBACK ' + mig.plan.displayName) return { error: 'typed confirmation must be exactly: ROLLBACK ' + mig.plan.displayName, status: 400 };
  if (!reason || String(reason).trim().length < 5) return { error: 'a reason of at least 5 characters is required', status: 400 };
  const ctx = await M.context();
  const started = await L.startJob('migrate-rollback-' + mig.oktaId, actor, async (log) => {
    await event(id, mig.oktaId, actor, 'rollback_started', null, null, { reason, objects: (mig.createdObjects || []).length }, 'running', reason);
    const objs = (mig.createdObjects || []).slice().reverse(); const done = []; const errs = [];
    const G = (method, path, body, perm, key, previous) => graphCall(method, path, body, { perm, roles: ctx.roles, migrationId: id, oktaId: mig.oktaId, actor, stepKey: key, previous, log });
    for (const o of objs) {
      let r;
      if (o.type === 'appRoleAssignment') r = await G('DELETE', `/v1.0/servicePrincipals/${o.spObjectId}/appRoleAssignedTo/${o.id}`, undefined, PERM.ASSIGN, 'rollback_assignment');
      else if (o.type === 'claimsMappingPolicyRef') r = await G('DELETE', `/v1.0/servicePrincipals/${o.spObjectId}/claimsMappingPolicies/${o.policyId}/$ref`, undefined, PERM.CLAIMS, 'rollback_claims_ref');
      else if (o.type === 'claimsMappingPolicy') r = await G('DELETE', `/v1.0/policies/claimsMappingPolicies/${o.id}`, undefined, PERM.CLAIMS, 'rollback_claims');
      else if (o.type === 'oauth2PermissionGrant') r = await G('DELETE', `/v1.0/oauth2PermissionGrants/${o.id}`, undefined, PERM.CONSENT, 'rollback_consent');
      else if (o.type === 'passwordCredential') r = await G('POST', `/v1.0/applications/${o.appObjectId}/removePassword`, { keyId: o.id }, PERM.APP_WRITE, 'rollback_secret');
      else if (o.type === 'group') r = await G('DELETE', `/v1.0/groups/${o.id}`, undefined, [PERM.GROUP_CREATE], 'rollback_group');
      else if (o.type === 'servicePrincipal') r = await G('DELETE', `/v1.0/servicePrincipals/${o.id}`, undefined, mig.plan.mode === 'adopt' ? PERM.APP_ADOPT : PERM.APP_WRITE, 'rollback_sp');
      else if (o.type === 'application') r = await G('DELETE', `/v1.0/applications/${o.id}`, undefined, mig.plan.mode === 'adopt' ? PERM.APP_ADOPT : PERM.APP_WRITE, 'rollback_app');
      else if (o.type === 'patch') { const prev = {}; for (const k of Object.keys(o.previous || {})) if (!k.startsWith('@') && k !== 'id') prev[k] = o.previous[k]; r = await G('PATCH', o.path, prev, PERM.APP_ADOPT, 'rollback_patch', null); }
      else { errs.push(o.type + ': no rollback handler'); continue; }
      if (r.ok || r.status === 404) done.push(o.type + ' ' + (o.id || o.path || '')); else errs.push(o.type + ' ' + (o.id || '') + ': ' + r.error);
      if (log.cancelled && log.cancelled()) { errs.push('cancelled before the remaining objects were removed'); break; }
    }
    const status = errs.length ? mig.status : STATUS.ROLLED;
    await setStatus(id, status, { results: Object.assign({}, mig.results || {}, { rollback: { at: nowIso(), by: actor, reason, done, errors: errs } }), finished_at: new Date() });
    await event(id, mig.oktaId, actor, errs.length ? 'rollback_incomplete' : 'rolled_back', null, null, { done, errors: errs }, status, errs.join(' | ') || null);
    log(`rollback ${errs.length ? 'incomplete' : 'complete'}: ${done.length} removed${errs.length ? ', ' + errs.length + ' error(s)' : ''}. Deleted applications stay recoverable in Entra for 30 days.`, errs.length ? 'error' : 'info');
    return { migrationId: id, status, done, errors: errs };
  });
  if (started.conflict) return { error: 'a rollback for this application is already running', conflict: started.conflict, status: 409 };
  return { ok: true, jobId: started.id, migrationId: id };
}

/* -------------------------------------------------------------------------- bulk */

async function bulkPreflight(ids, actor) {
  return L.startJob('migrate-bulk-preflight', actor, async (log) => {
    const out = [];
    for (const id of ids) {
      if (log.cancelled()) { log('cancelled', 'warn'); break; }
      try { const m = await preflight(id, actor, { log: (msg, level) => log(id + ': ' + msg, level) }); out.push({ oktaId: id, migrationId: m.id, status: m.status, failed: m.preflight.checks.filter((c) => c.severity === 'critical' && c.status === 'fail').map((c) => c.key) }); log(`${id}: ${m.status}`, m.status === STATUS.PF_PASS ? 'info' : 'warn'); }
      catch (e) { out.push({ oktaId: id, error: e.message }); log(id + ': ' + e.message, 'error'); }
    }
    return { total: ids.length, passed: out.filter((x) => x.status === STATUS.PF_PASS).length, failed: out.filter((x) => x.status === STATUS.PF_FAIL).length, errors: out.filter((x) => x.error).length, items: out };
  });
}

async function bulkApprove(migrationIds, actor, { confirm, reason } = {}) {
  const expected = `MIGRATE ${migrationIds.length} APPLICATIONS`;
  if (String(confirm || '') !== expected) return { error: 'typed confirmation must be exactly: ' + expected, status: 400 };
  const out = [];
  for (const id of migrationIds) {
    const mig = await getMigration(id, { events: false });
    if (!mig) { out.push({ id, error: 'no such migration' }); continue; }
    const warns = (mig.preflight && mig.preflight.checks || []).filter((c) => c.status === 'warn').map((c) => c.key);
    const r = await approve(id, actor, { confirm: mig.plan && mig.plan.displayName, reason, acknowledge: warns });
    out.push(r.error ? { id, error: r.error, missing: r.missing } : { id, status: r.status });
  }
  return { items: out, approved: out.filter((x) => x.status === STATUS.APPROVED).length };
}

async function bulkPush(migrationIds, actor) {
  const migs = [];
  for (const id of migrationIds) { const m = await getMigration(id, { events: false }); if (!m) return { error: 'no such migration ' + id, status: 404 }; if (m.status !== STATUS.APPROVED) return { error: `migration ${id} is ${m.status}; only approved migrations can be staged in Entra`, status: 409 }; migs.push(m); }
  const ctx = await M.context();
  for (const m of migs) {
    const runSteps = m.plan.steps.filter((s) => s.exec && s.exec.method !== 'LOCAL' && s.exec.method !== 'GET' && !s.optional);
    const missing = uniq(runSteps.map((s) => permCheck(s.requires, ctx.roles)).filter((pc) => pc.ok !== true).map((pc) => pc.missing || 'write credential unreadable'));
    if (missing.length) return { error: `push is not enabled for migration ${m.id}: needs ` + missing.join(', '), missing, status: 403 };
  }
  const started = await L.startJob('migrate-bulk-push', actor, async (log) => {
    const out = [];
    for (const m of migs) {
      if (log.cancelled()) { log('cancelled before ' + m.plan.displayName, 'warn'); out.push({ migrationId: m.id, status: 'not_started' }); continue; }
      const fresh = await validateFreshSource(m, actor, (msg, level) => log(m.plan.displayName + ': ' + msg, level));
      if (!fresh.ok) { log(m.plan.displayName + ': ' + fresh.error, 'error'); out.push({ migrationId: m.id, oktaId: m.oktaId, label: m.plan.displayName, status: 'source_changed', failure: { error: fresh.error } }); continue; }
      await setStatus(m.id, STATUS.RUNNING, { pushed_by: actor, pushed_at: new Date() });
      await event(m.id, m.oktaId, actor, 'push_started', null, null, { bulk: true }, 'running', null);
      log(`— ${m.plan.displayName} (${m.oktaId}) —`);
      try { const r = await runPush(m, actor, log); out.push({ migrationId: m.id, oktaId: m.oktaId, label: m.plan.displayName, status: r.status, warnings: r.warnings || [], failure: r.failure || null }); }
      catch (e) { await setStatus(m.id, STATUS.FAILED, { error: e.message, finished_at: new Date() }); out.push({ migrationId: m.id, oktaId: m.oktaId, status: STATUS.FAILED, failure: { error: e.message } }); log(m.plan.displayName + ': ' + e.message, 'error'); }
    }
    return { total: migs.length, succeeded: out.filter((x) => x.status === STATUS.OK).length, warnings: out.filter((x) => x.status === STATUS.WARN).length, failed: out.filter((x) => x.status === STATUS.FAILED).length, items: out };
  });
  if (started.conflict) return { error: 'a bulk staging run is already running', conflict: started.conflict, status: 409 };
  for (const m of migs) await pool.query(`UPDATE oem_migration SET job_id=? WHERE id=?`, [started.id, m.id]);
  return { ok: true, jobId: started.id, migrationIds: migs.map((m) => m.id) };
}

async function listMigrations({ oktaId, limit = 50 } = {}) {
  const [rows] = await pool.query(`SELECT id, okta_id, status, protocol, readiness, created_by, created_at, approved_by, approved_at, pushed_by, pushed_at, finished_at, error, job_id, entra_app_object_id, entra_sp_object_id FROM oem_migration ${oktaId ? 'WHERE okta_id=?' : ''} ORDER BY id DESC LIMIT ?`, oktaId ? [oktaId, Number(limit)] : [Number(limit)]);
  return rows.map((r) => ({ id: r.id, oktaId: r.okta_id, status: r.status, protocol: r.protocol, readiness: r.readiness, createdBy: r.created_by, createdAt: r.created_at, approvedBy: r.approved_by, approvedAt: r.approved_at, pushedBy: r.pushed_by, pushedAt: r.pushed_at, finishedAt: r.finished_at, error: r.error, jobId: r.job_id, entraAppObjectId: r.entra_app_object_id, entraSpObjectId: r.entra_sp_object_id, secretHeld: secretHeld(r.id) }));
}

module.exports = { STATUS, buildPlan, runChecks, preflight, approve, push, verify, rollback, cancel, secretOnce, secretHeld, listSecrets, issueSecret, removeSecret, getMigration, listMigrations, bulkPreflight, bulkApprove, bulkPush, fill, validateFreshSource, renameEntraApp };
// Test seam for vm/server-assign-replication.js; routes go through push().
module.exports._internals = { resolveAppRole, assignAfterCreate, runPush, DEFAULT_ROLE };
