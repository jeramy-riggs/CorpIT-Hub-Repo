/**
 * oem-ca-push.js — Conditional Access changes: translate an Okta rule into a Graph policy body, stage it
 * as a reviewed change, push it (POST a new policy / PATCH an existing one), read it back, roll it back.
 * Mount in server.js next to the compare router:  app.use('/api/oem/ca', require('./oem-ca-push'));
 *
 *   POST /api/oem/ca/translate            { ruleKey }            → proposed body + provenance + unresolved (no write)
 *   GET  /api/oem/ca/policy/:id/live                             → the policy as Graph holds it right now (read credential)
 *   GET  /api/oem/ca/pick/:kind?q=        groups|users|apps|locations|strengths → picker rows from the mirrors
 *   GET  /api/oem/ca/changes[/:id]                               → change records (+ pre-flight on the detail)
 *   POST /api/oem/ca/changes              { kind, entraPolicyId?, oktaRuleKey?, policy }   → draft   (admin)
 *   POST /api/oem/ca/changes/:id          { policy }             → edit a draft                        (admin)
 *   POST /api/oem/ca/changes/:id/approve                                                      (admin)
 *   POST /api/oem/ca/changes/:id/push     { confirm? }           → the Graph write + read-back          (admin)
 *   POST /api/oem/ca/changes/:id/rollback { confirm }            → DELETE (create) / PATCH before (update) (admin)
 *   POST /api/oem/ca/changes/:id/cancel                                                       (admin)
 *
 * Rules this file enforces rather than documents:
 *   - A write needs Policy.ReadWrite.ConditionalAccess (+ Application.Read.All or higher) on the WRITE credential.
 *     Missing → refused before the network, with the permission and the grantor named. Never simulated.
 *   - A policy is pushed in the state the reviewer chose. 'enabled' (enforcing) needs the scoped confirmation
 *     phrase and at least one emergency-access exclusion; report-only and disabled never count as enforcement.
 *   - Update pushes re-read the live policy first and stop if it changed since the draft was built.
 *   - Every Graph call is recorded with its exact request; a failure stops, keeps state, and says what to do.
 */
'use strict';
const express = require('express');
const createRbac = require('./rbac-middleware');
const L = require('./oem-lib');
const M = require('./oem-migrate');
const CMP = require('./oem-ca-compare');
const { pool, j, nowIso } = L;

const router = express.Router();
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const PAGE_KEY = 'okta-entra-migration';
const read = () => rbac.requirePage(PAGE_KEY, 'read');
const admin = () => rbac.requirePage(PAGE_KEY, 'admin');
const json = express.json({ limit: '256kb' });
const fail = (res, e, where) => { console.error(`[oem-ca] ${where}:`, e && e.stack || e); res.status(500).json({ error: 'request failed', where, detail: String(e && e.message || e).slice(0, 300) }); };
const actorOf = (req) => (req.user && req.user.email) || 'anonymous';
const audit = (req, action, details, target) => { try { if (rbac.audit) return rbac.audit(req, action, target || null, PAGE_KEY, details); } catch (e) { /* audit never breaks a request */ } };
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const short = (s, n) => (s === null || s === undefined ? null : String(s).slice(0, n));

/* ------------------------------------------------------------- constants */

const STATE_LABEL = { enabled: 'Enforced', enabledForReportingButNotEnforced: 'Report-only', disabled: 'Disabled' };
const STATES = ['disabled', 'enabledForReportingButNotEnforced', 'enabled'];
const PLATFORMS = ['android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'all'];
const CLIENT_TYPES = ['browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other', 'all'];
const CONTROLS = ['block', 'mfa', 'compliantDevice', 'domainJoinedDevice', 'approvedApplication', 'compliantApplication', 'passwordChange'];
const RISK = ['low', 'medium', 'high', 'none'];
const BUILTIN_STRENGTHS = [
  { id: '00000000-0000-0000-0000-000000000002', displayName: 'Multifactor authentication', builtIn: true },
  { id: '00000000-0000-0000-0000-000000000003', displayName: 'Passwordless MFA', builtIn: true },
  { id: '00000000-0000-0000-0000-000000000004', displayName: 'Phishing-resistant MFA', builtIn: true },
];
const PERM_CA = M.PERM.CA;                       // ['Policy.ReadWrite.ConditionalAccess']
const PERM_APPREAD = ['Application.Read.All', 'Application.ReadWrite.All'];   // Graph requires app read alongside CA write
const GRANTOR = M.ENTRA_GRANTOR;

/* --------------------------------------------------------------- helpers */

const lc = (s) => String(s || '').trim().toLowerCase();
const groupKey = CMP._internal.groupKey;
const uniq = (a) => a.filter((v, i) => a.indexOf(v) === i);

/** Same inert detection the snapshot collector uses (a policy that can never match a sign-in). */
function detectInert(p) {
  const c = p.conditions || {}; const reasons = [];
  const apps = c.applications || {}, users = c.users || {};
  if ((apps.includeApplications || []).length === 1 && apps.includeApplications[0] === 'None') reasons.push('Target resources is set to None, so no application is in scope.');
  const anyUserInclude = (users.includeUsers || []).filter((u) => u !== 'None').length + (users.includeGroups || []).length + (users.includeRoles || []).length;
  if (!anyUserInclude) reasons.push('No users, groups or roles are included, so no principal is in scope.');
  const platIn = (c.platforms && c.platforms.includePlatforms) || [], platEx = (c.platforms && c.platforms.excludePlatforms) || [];
  if (platIn.length && !platIn.includes('all') && !platIn.filter((x) => !platEx.includes(x)).length) reasons.push('Every included device platform also appears in the exclude list, and exclude wins, so the platform condition matches nothing.');
  const locIn = (c.locations && c.locations.includeLocations) || [], locEx = (c.locations && c.locations.excludeLocations) || [];
  if (locIn.length && !locIn.includes('All') && !locIn.filter((x) => !locEx.includes(x)).length) reasons.push('Every included location also appears in the exclude list, so the location condition matches nothing.');
  return { isInert: reasons.length > 0, reason: reasons.join(' ') || null };
}

/** Keep the mirror honest after a write: the snapshot row for one policy, from the read-back. */
async function upsertSnapshot(p) {
  const { isInert, reason } = detectInert(p);
  await pool.query(`INSERT INTO oem_entra_ca (ca_id,display_name,state,conditions,grant_controls,session_controls,is_inert,inert_reason) VALUES (?,?,?,?,?,?,?,?)
     ON DUPLICATE KEY UPDATE display_name=VALUES(display_name),state=VALUES(state),conditions=VALUES(conditions),grant_controls=VALUES(grant_controls),session_controls=VALUES(session_controls),is_inert=VALUES(is_inert),inert_reason=VALUES(inert_reason)`,
    [p.id, p.displayName, p.state, JSON.stringify(p.conditions || {}), JSON.stringify(p.grantControls || {}), JSON.stringify(p.sessionControls || {}), isInert ? 1 : 0, reason]);
}

/** Only the fields Conditional Access accepts, in the shape Graph wants. Anything else is dropped and reported. */
function sanitizePolicy(input) {
  const errors = [], notes = []; const p = input && typeof input === 'object' ? input : {};
  const out = { displayName: short(String(p.displayName || '').trim(), 256), state: p.state, conditions: {}, grantControls: null, sessionControls: null };
  if (!out.displayName) errors.push('displayName is required');
  if (!STATES.includes(out.state)) errors.push('state must be one of ' + STATES.join(', '));
  const c = p.conditions || {};
  const ids = (arr, allow, what) => uniq((Array.isArray(arr) ? arr : []).map(String)).filter((x) => { if (allow.includes(x) || GUID.test(x)) return true; errors.push(what + ': "' + x + '" is not an id'); return false; });
  const u = c.users || {};
  out.conditions.users = { includeUsers: ids(u.includeUsers, ['All', 'None', 'GuestsOrExternalUsers'], 'includeUsers'), excludeUsers: ids(u.excludeUsers, ['GuestsOrExternalUsers'], 'excludeUsers'), includeGroups: ids(u.includeGroups, [], 'includeGroups'), excludeGroups: ids(u.excludeGroups, [], 'excludeGroups'), includeRoles: ids(u.includeRoles, [], 'includeRoles'), excludeRoles: ids(u.excludeRoles, [], 'excludeRoles') };
  const a = c.applications || {};
  out.conditions.applications = { includeApplications: ids(a.includeApplications, ['All', 'None', 'Office365', 'MicrosoftAdminPortals'], 'includeApplications'), excludeApplications: ids(a.excludeApplications, ['Office365', 'MicrosoftAdminPortals'], 'excludeApplications'), includeUserActions: uniq((Array.isArray(a.includeUserActions) ? a.includeUserActions : []).filter((x) => ['urn:user:registersecurityinfo', 'urn:user:registerdevice'].includes(x))) };
  out.conditions.clientAppTypes = uniq((Array.isArray(c.clientAppTypes) ? c.clientAppTypes : []).filter((x) => CLIENT_TYPES.includes(x)));
  if (!out.conditions.clientAppTypes.length || out.conditions.clientAppTypes.includes('all')) out.conditions.clientAppTypes = ['all'];
  if (c.platforms && (Array.isArray(c.platforms.includePlatforms) && c.platforms.includePlatforms.length)) out.conditions.platforms = { includePlatforms: uniq(c.platforms.includePlatforms.filter((x) => PLATFORMS.includes(x))), excludePlatforms: uniq((c.platforms.excludePlatforms || []).filter((x) => PLATFORMS.includes(x))) };
  if (c.locations && (Array.isArray(c.locations.includeLocations) && c.locations.includeLocations.length)) out.conditions.locations = { includeLocations: ids(c.locations.includeLocations, ['All', 'AllTrusted'], 'includeLocations'), excludeLocations: ids(c.locations.excludeLocations, ['AllTrusted'], 'excludeLocations') };
  if (Array.isArray(c.signInRiskLevels) && c.signInRiskLevels.length) out.conditions.signInRiskLevels = uniq(c.signInRiskLevels.filter((x) => RISK.includes(x)));
  if (Array.isArray(c.userRiskLevels) && c.userRiskLevels.length) out.conditions.userRiskLevels = uniq(c.userRiskLevels.filter((x) => RISK.includes(x)));
  if (c.devices && c.devices.deviceFilter && c.devices.deviceFilter.rule) out.conditions.devices = { deviceFilter: { mode: c.devices.deviceFilter.mode === 'include' ? 'include' : 'exclude', rule: short(String(c.devices.deviceFilter.rule), 1024) } };
  const g = p.grantControls || null;
  if (g && (Array.isArray(g.builtInControls) && g.builtInControls.length || (g.authenticationStrength && g.authenticationStrength.id))) {
    const controls = uniq(g.builtInControls.filter((x) => CONTROLS.includes(x)));
    if (controls.includes('block') && controls.length > 1) errors.push('block cannot be combined with other grant controls');
    out.grantControls = { operator: g.operator === 'AND' ? 'AND' : 'OR', builtInControls: controls };
    if (g.authenticationStrength && g.authenticationStrength.id) { if (!GUID.test(String(g.authenticationStrength.id))) errors.push('authenticationStrength.id is not an id'); else { out.grantControls.authenticationStrength = { id: String(g.authenticationStrength.id) }; if (controls.includes('mfa')) { out.grantControls.builtInControls = controls.filter((x) => x !== 'mfa'); notes.push('mfa dropped from builtInControls: an authentication strength already requires MFA (Graph rejects both together).'); } } }
  }
  const s = p.sessionControls || null;
  if (s) {
    const sc = {};
    const sf = s.signInFrequency;
    if (sf && sf.isEnabled !== false && (sf.frequencyInterval === 'everyTime' || (sf.value > 0))) {
      sc.signInFrequency = sf.frequencyInterval === 'everyTime' ? { isEnabled: true, frequencyInterval: 'everyTime', authenticationType: 'primaryAndSecondaryAuthentication', value: null, type: null }
        : { isEnabled: true, frequencyInterval: 'timeBased', authenticationType: 'primaryAndSecondaryAuthentication', value: Math.max(1, Math.round(Number(sf.value))), type: sf.type === 'days' ? 'days' : 'hours' };
      if (sc.signInFrequency.type === 'hours' && sc.signInFrequency.value > 23) { const d = Math.round(sc.signInFrequency.value / 24); sc.signInFrequency = Object.assign(sc.signInFrequency, { type: 'days', value: Math.max(1, d) }); notes.push('sign-in frequency expressed in days (Graph accepts 1–23 hours or 1–365 days).'); }
      if (sc.signInFrequency.type === 'days' && sc.signInFrequency.value > 365) { sc.signInFrequency.value = 365; notes.push('sign-in frequency capped at 365 days.'); }
    }
    if (s.persistentBrowser && s.persistentBrowser.isEnabled !== false && ['always', 'never'].includes(s.persistentBrowser.mode)) sc.persistentBrowser = { isEnabled: true, mode: s.persistentBrowser.mode };
    if (Object.keys(sc).length) out.sessionControls = sc;
  }
  if (!out.grantControls && !out.sessionControls) errors.push('a policy needs at least one grant control (block, mfa, compliant device…) or a session control');
  if (out.sessionControls && out.sessionControls.persistentBrowser && !out.conditions.applications.includeApplications.includes('All')) errors.push('persistent browser session requires Target resources = All cloud apps (Graph rejects it otherwise)');
  return { policy: out, errors, notes };
}

/* --------------------------------------------------------- translation */

let strengthCache = { at: 0, list: null, error: null };
async function strengths() {
  if (strengthCache.list && Date.now() - strengthCache.at < 3600e3) return strengthCache;
  const r = await L.graphGet('/v1.0/policies/authenticationStrengthPolicies');
  if (r.status === 200 && r.body && Array.isArray(r.body.value)) strengthCache = { at: Date.now(), list: r.body.value.map((x) => ({ id: x.id, displayName: x.displayName, builtIn: x.policyType === 'builtIn', allowed: x.allowedCombinations || [] })), error: null };
  else strengthCache = { at: Date.now(), list: BUILTIN_STRENGTHS, error: r.error || ('HTTP ' + r.status) };
  return strengthCache;
}

/**
 * Okta rule (normalised by oem-ca-compare) → proposed Graph body.
 * Every field carries its origin; anything that cannot be resolved from the mirrors goes to `unresolved`
 * with what the reviewer must pick, and is left OUT of the body (never guessed).
 */
async function translate(ruleKey, report) {
  const o = report.okta.find((r) => r.key === ruleKey);
  if (!o) return null;
  const prov = [], unresolved = [], notes = [];
  const P = (field, from, value, why) => prov.push({ field, from, value, why });
  const body = { displayName: short(('OKTA · ' + o.policyName + ' · ' + o.rule.name).replace(/\s+/g, ' '), 200), state: 'disabled', conditions: { users: { includeUsers: [], excludeUsers: [], includeGroups: [], excludeGroups: [], includeRoles: [], excludeRoles: [] }, applications: { includeApplications: [], excludeApplications: [], includeUserActions: [] }, clientAppTypes: ['all'] }, grantControls: null, sessionControls: null };
  P('displayName', 'Okta policy + rule name', body.displayName, 'Editable. Prefixed OKTA so the source is obvious in the Entra portal.');
  P('state', 'default', 'disabled', 'Pushed as disabled unless you choose report-only or enforced. Enforced needs the typed confirmation.');
  /* who */
  const [gRows] = await pool.query(`SELECT entra_id, display_name FROM entra_groups`);
  const gByKey = new Map(); gRows.forEach((g) => { const k = groupKey(g.display_name); if (!k) return; if (!gByKey.has(k)) gByKey.set(k, []); gByKey.get(k).push(g); });
  const pickGroup = (og, side) => {
    if (og.source === 'unresolved') { unresolved.push({ field: side, what: 'Okta group ' + og.id + ' has no name in the mirror — pick the Entra group by hand', okta: og.id }); return null; }
    const hits = gByKey.get(groupKey(og.name)) || [];
    if (hits.length === 1) return hits[0];
    unresolved.push({ field: side, what: hits.length ? 'Okta group "' + og.name + '" matches ' + hits.length + ' Entra groups by name — pick one' : 'No Entra group is named like Okta group "' + og.name + '" — pick one or create it first', okta: og.name, candidates: hits.slice(0, 5).map((h) => ({ id: h.entra_id, name: h.display_name })) });
    return null;
  };
  const upns = o.who.users.concat(o.who.exUsers).map((u) => u.login).filter(Boolean);
  const [uRows] = upns.length ? await pool.query(`SELECT entra_id, user_principal_name, display_name FROM entra_users WHERE LOWER(user_principal_name) IN (?)`, [upns.map(lc)]) : [[]];
  const uByUpn = new Map(uRows.map((r) => [lc(r.user_principal_name), r]));
  const pickUser = (ou, side) => { const r = ou.login ? uByUpn.get(lc(ou.login)) : null; if (r) return r; unresolved.push({ field: side, what: ou.login ? 'No Entra user has UPN ' + ou.login + ' — pick the user by hand' : 'Okta user ' + ou.id + ' is not in the mirror — pick the user by hand', okta: ou.login || ou.id }); return null; };
  if (o.who.kind === 'all') { body.conditions.users.includeUsers = ['All']; P('conditions.users.includeUsers', o.policyType === 'app' ? 'Okta rule applies to everyone assigned to the app' : 'Okta rule applies to everyone', ['All'], o.policyType === 'app' ? 'Entra scopes by policy, not by app assignment: "All users" here plus the app under Target resources gives the same reach. Narrow it to the group assigned to the Entra app if you prefer.' : 'Everyone.'); }
  else {
    o.who.groups.forEach((g) => { const e = pickGroup(g, 'conditions.users.includeGroups'); if (e) { body.conditions.users.includeGroups.push(e.entra_id); P('conditions.users.includeGroups', 'Okta group "' + g.name + '"', e.display_name, 'Matched by name; membership is not compared.'); } });
    o.who.users.forEach((u) => { const e = pickUser(u, 'conditions.users.includeUsers'); if (e) { body.conditions.users.includeUsers.push(e.entra_id); P('conditions.users.includeUsers', 'Okta user ' + (u.login || u.id), e.display_name || e.user_principal_name, 'Matched by UPN = Okta login.'); } });
  }
  o.who.exGroups.forEach((g) => { const e = pickGroup(g, 'conditions.users.excludeGroups'); if (e) { body.conditions.users.excludeGroups.push(e.entra_id); P('conditions.users.excludeGroups', 'Okta excluded group "' + g.name + '"', e.display_name, 'Matched by name.'); } });
  o.who.exUsers.forEach((u) => { const e = pickUser(u, 'conditions.users.excludeUsers'); if (e) { body.conditions.users.excludeUsers.push(e.entra_id); P('conditions.users.excludeUsers', 'Okta excluded user ' + (u.login || u.id), e.display_name || e.user_principal_name, 'Matched by UPN.'); } });
  /* what */
  if (o.policyType === 'session') { body.conditions.applications.includeApplications = ['All']; P('conditions.applications.includeApplications', 'Okta global session policy', ['All'], 'A session policy applies to every Okta sign-in; the Entra equivalent is All cloud apps.'); }
  else {
    o.apps.forEach((a) => {
      if (/^(office ?365|microsoft 365|o365)/i.test(a.label)) { body.conditions.applications.includeApplications.push('Office365'); P('conditions.applications.includeApplications', 'Okta app "' + a.label + '"', 'Office365 (app group)', 'Office 365 is a built-in Conditional Access target covering Exchange, SharePoint, Teams and the rest.'); return; }
      if (a.entra && a.entra.appId) { body.conditions.applications.includeApplications.push(a.entra.appId); P('conditions.applications.includeApplications', 'Okta app "' + a.label + '"', a.entra.name, 'From the Applications tab (' + String(a.entra.decision).replace(/_/g, ' ') + ').' + (a.entra.decision === 'manual_confirmed' || a.entra.decision === 'marked_migrated' ? '' : ' Not a confirmed match — confirm it on the Applications tab or pick another app.')); return; }
      unresolved.push({ field: 'conditions.applications.includeApplications', what: 'Okta app "' + a.label + '" has no Entra app yet — match it on the Applications tab or pick one here', okta: a.label });
    });
    body.conditions.applications.includeApplications = uniq(body.conditions.applications.includeApplications);
  }
  /* where */
  if (o.where.kind !== 'anywhere') {
    const locs = [];
    o.where.zones.forEach((z) => {
      const cands = (report.zoneMap[z.name] || []);
      const byCov = cands.filter((l) => l.by === 'coverage').sort((a, b) => b.covered - a.covered);
      const pick = byCov[0] || (cands.length === 1 ? cands[0] : null);
      if (pick && GUID.test(pick.id)) { locs.push(pick.id); P(o.where.kind === 'in-zones' ? 'conditions.locations.includeLocations' : 'conditions.locations.excludeLocations', 'Okta zone "' + z.name + '"', pick.name, pick.by === 'coverage' ? pick.covered + ' of ' + pick.total + ' Okta ranges fall inside this named location — check the Okta zones tab for the ranges that do not.' : 'Matched by name only; the ranges were not compared.'); }
      else unresolved.push({ field: o.where.kind === 'in-zones' ? 'conditions.locations.includeLocations' : 'conditions.locations.excludeLocations', what: cands.length ? 'Okta zone "' + z.name + '" corresponds to ' + cands.length + ' named locations — pick one' : 'Okta zone "' + z.name + '" has no Entra named location — create one (Entra portal → Named locations) with its ranges first, then pick it here', okta: z.name, candidates: cands.map((c) => ({ id: c.id, name: c.name })) });
    });
    if (o.where.kind === 'in-zones') body.conditions.locations = { includeLocations: locs, excludeLocations: [] };
    else { body.conditions.locations = { includeLocations: ['All'], excludeLocations: locs }; P('conditions.locations.includeLocations', 'Okta network condition "not in zone"', ['All'], 'Okta denies outside its zones; Entra says it as "any location except these".'); }
  }
  /* platforms, clients, risk */
  if (o.platforms && o.platforms.length) { const inc = o.platforms.filter((x) => PLATFORMS.includes(x)); if (inc.length) { body.conditions.platforms = { includePlatforms: inc, excludePlatforms: [] }; P('conditions.platforms.includePlatforms', 'Okta platform condition', inc, 'Same platform names.'); } const dropped = o.platforms.filter((x) => !PLATFORMS.includes(x)); if (dropped.length) notes.push('Okta platform(s) ' + dropped.join(', ') + ' have no Conditional Access platform and were left out.'); }
  if (o.clientApps && o.clientApps.length) { body.conditions.clientAppTypes = o.clientApps.filter((x) => CLIENT_TYPES.includes(x)); if (!body.conditions.clientAppTypes.length) body.conditions.clientAppTypes = ['all']; P('conditions.clientAppTypes', 'Okta Office 365 client condition', body.conditions.clientAppTypes, 'WEB→browser, MODERN_AUTH→mobile apps and desktop clients, ACTIVE_SYNC→Exchange ActiveSync, LEGACY_AUTH→other clients.'); }
  if (o.risk && o.risk !== 'ANY') { body.conditions.signInRiskLevels = [lc(o.risk)]; P('conditions.signInRiskLevels', 'Okta risk level ' + o.risk, [lc(o.risk)], 'Sign-in risk in Entra needs Entra ID P2 (Identity Protection) and scores risk differently from Okta.'); }
  /* effect */
  const controls = [];
  if (o.effect === 'block') {
    if (o.device && o.device.managed === false) { controls.push('compliantDevice'); P('grantControls.builtInControls', 'Okta DENY on an unmanaged device', ['compliantDevice'], 'Conditional Access says "deny unmanaged" as "grant only to a compliant device" (Intune compliance). Same intent, different mechanism.'); }
    else if (o.device && o.device.registered === false) { controls.push('domainJoinedDevice'); P('grantControls.builtInControls', 'Okta DENY on an unregistered device', ['domainJoinedDevice'], 'Nearest Conditional Access control: require an Entra hybrid joined device (or use compliantDevice).'); }
    else { controls.push('block'); P('grantControls.builtInControls', 'Okta DENY', ['block'], 'Block access.'); }
  } else {
    if (o.requiresMfa) { controls.push('mfa'); P('grantControls.builtInControls', 'Okta ' + o.factor, ['mfa'], o.deviceBound ? 'Okta demands a device-bound authenticator; "mfa" accepts any registered method. Pick the Phishing-resistant MFA authentication strength if that is the intent.' : 'Require multifactor authentication.'); }
    if (o.device && o.device.managed === true) { controls.push('compliantDevice'); P('grantControls.builtInControls', 'Okta managed-device condition', ['compliantDevice'], 'Require a compliant device (Intune compliance stands in for Okta device management).'); }
    else if (o.device && o.device.registered === true) { controls.push('domainJoinedDevice'); P('grantControls.builtInControls', 'Okta registered-device condition', ['domainJoinedDevice'], 'Nearest control: Entra hybrid joined device (or compliantDevice).'); }
  }
  if (controls.length) body.grantControls = { operator: controls.length > 1 ? 'AND' : 'OR', builtInControls: controls };
  else if (o.effect === 'grant') notes.push('This Okta rule allows with password only and adds no requirement. Conditional Access can only ADD requirements, so there is nothing to push for it on its own — express it as an exclusion on a stricter policy instead.');
  /* session */
  const rh = o.session.reauthHours;
  if (rh === 0) { body.sessionControls = { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } }; P('sessionControls.signInFrequency', 'Okta re-authenticate PT0S', 'every time', 'Prompt on every sign-in.'); }
  else if (rh !== null && rh > 0 && rh < 24 * 365) { body.sessionControls = { signInFrequency: { isEnabled: true, frequencyInterval: 'timeBased', value: rh >= 24 && rh % 24 === 0 ? rh / 24 : Math.round(rh), type: rh >= 24 && rh % 24 === 0 ? 'days' : 'hours' } }; P('sessionControls.signInFrequency', 'Okta re-authenticate ' + CMP._internal.hoursText(rh), (rh >= 24 && rh % 24 === 0 ? rh / 24 + ' days' : Math.round(rh) + ' h'), 'Sign-in frequency.'); if (rh < 24 && rh > 23) notes.push('Graph accepts 1–23 hours; ' + rh + 'h became 1 day.'); }
  else if (o.session.lifetimeMinutes && o.session.lifetimeMinutes >= 60) { const h = Math.round(o.session.lifetimeMinutes / 60); body.sessionControls = { signInFrequency: { isEnabled: true, frequencyInterval: 'timeBased', value: h >= 24 && h % 24 === 0 ? h / 24 : h, type: h >= 24 && h % 24 === 0 ? 'days' : 'hours' } }; P('sessionControls.signInFrequency', 'Okta session lifetime ' + o.session.lifetimeMinutes + ' min', h + ' h', 'Nearest Conditional Access equivalent of the Okta session lifetime (idle timeout has no CA equivalent).'); }
  if (o.rule.shadowed) notes.push('This Okta rule is shadowed by a higher-priority rule and never fires in Okta today.');
  if (!o.active) notes.push('This Okta rule (or its policy) is INACTIVE in Okta.');
  const san = sanitizePolicy(body);
  return { ruleKey, okta: o, policy: san.policy, errors: san.errors, notes: notes.concat(san.notes), provenance: prov, unresolved };
}

/* ------------------------------------------------------------- pre-flight */

/**
 * What must be true before the write. `stop` blocks the push; `warn` and `note` do not. Every check names
 * the real state it saw. `live` = the policy as Graph holds it now (update only).
 */
async function preflight(ch, ctx, live) {
  const checks = []; const C = (key, label, level, status, detail, fix) => checks.push({ key, label, level, status, detail, fix: fix || null });
  const p = ch.payload;
  const w = ctx.write;
  if (!w || !w.configured) C('write_credential', 'Entra write credential configured', 'stop', 'fail', 'ENTRA_MIGRATE_CLIENT_ID / ENTRA_MIGRATE_CLIENT_SECRET are not set on the platform.', 'Configure the IT-Command-Migrate credential on the hub and restart the API.');
  else if (ctx.roles === null) C('write_credential', 'Entra write credential can sign in', 'stop', 'fail', w.error || 'token error', 'Check the client secret (expired?) and the tenant id.');
  else {
    C('write_credential', 'Entra write credential (' + w.name + ')', 'stop', 'pass', ctx.roles.length + ' application permission(s) consented', null);
    const pc = M.permCheck(PERM_CA, ctx.roles), pa = M.permCheck(PERM_APPREAD, ctx.roles);
    C('perm_ca', 'Policy.ReadWrite.ConditionalAccess on ' + w.name, 'stop', pc.ok === true ? 'pass' : 'fail', pc.ok === true ? 'granted (' + pc.have + ')' : 'missing', pc.ok === true ? null : 'Grant Policy.ReadWrite.ConditionalAccess to ' + w.name + ' — ' + GRANTOR + '.');
    C('perm_app', 'Application.Read.All (or higher) on ' + w.name, 'stop', pa.ok === true ? 'pass' : 'fail', pa.ok === true ? 'granted (' + pa.have + ')' : 'missing — Graph rejects Conditional Access writes without it', pa.ok === true ? null : 'Grant Application.Read.All to ' + w.name + ' — ' + GRANTOR + '.');
  }
  const san = sanitizePolicy(p);
  C('payload', 'Payload is a valid Conditional Access policy', 'stop', san.errors.length ? 'fail' : 'pass', san.errors.length ? san.errors.join('; ') : 'displayName, state, conditions and controls are well-formed', san.errors.length ? 'Edit the draft.' : null);
  const un = (ch.provenance && ch.provenance.unresolved) || [];
  C('unresolved', 'Every Okta condition resolved to an Entra object', 'stop', un.length ? 'fail' : 'pass', un.length ? un.length + ' item(s) still need a pick: ' + un.map((x) => x.what).join(' · ') : 'nothing left to pick', un.length ? 'Pick the missing objects in the draft (or remove that condition on purpose).' : null);
  const inert = detectInert(p);
  C('inert', 'Policy would match real sign-ins', 'stop', inert.isInert ? 'fail' : 'pass', inert.isInert ? inert.reason : 'users and applications are in scope', inert.isInert ? 'Fix the include/exclude lists.' : null);
  /* ids exist in the mirrors */
  const u = p.conditions.users || {}, a = p.conditions.applications || {}, l = p.conditions.locations || {};
  const need = { users: uniq([].concat(u.includeUsers || [], u.excludeUsers || []).filter((x) => GUID.test(x))), groups: uniq([].concat(u.includeGroups || [], u.excludeGroups || []).filter((x) => GUID.test(x))), apps: uniq([].concat(a.includeApplications || [], a.excludeApplications || []).filter((x) => GUID.test(x))), locs: uniq([].concat(l.includeLocations || [], l.excludeLocations || []).filter((x) => GUID.test(x))) };
  const missing = [];
  if (need.users.length) { const [r] = await pool.query(`SELECT entra_id FROM entra_users WHERE entra_id IN (?)`, [need.users]); const have = new Set(r.map((x) => x.entra_id)); need.users.filter((x) => !have.has(x)).forEach((x) => missing.push('user ' + x)); }
  if (need.groups.length) { const [r] = await pool.query(`SELECT entra_id FROM entra_groups WHERE entra_id IN (?)`, [need.groups]); const have = new Set(r.map((x) => x.entra_id)); need.groups.filter((x) => !have.has(x)).forEach((x) => missing.push('group ' + x)); }
  if (need.apps.length) { const [r] = await pool.query(`SELECT app_id FROM entra_apps WHERE app_id IN (?)`, [need.apps]); const have = new Set(r.map((x) => x.app_id)); need.apps.filter((x) => !have.has(x) && !CMP_ALIAS[x]).forEach((x) => missing.push('app ' + x)); }
  if (need.locs.length) { const [r] = await pool.query(`SELECT loc_id FROM oem_entra_named_location WHERE loc_id IN (?)`, [need.locs]); const have = new Set(r.map((x) => x.loc_id)); need.locs.filter((x) => !have.has(x)).forEach((x) => missing.push('named location ' + x)); }
  C('ids', 'Referenced users, groups, apps and locations exist in the directory mirror', 'stop', missing.length ? 'fail' : 'pass', missing.length ? 'not in the mirror: ' + missing.join(', ') : (need.users.length + need.groups.length + need.apps.length + need.locs.length) + ' object id(s) checked', missing.length ? 'Pick them again from the picker (the mirror is the source), or refresh the directory mirror first.' : null);
  /* emergency access */
  const exclusions = (u.excludeUsers || []).length + (u.excludeGroups || []).length + (u.excludeRoles || []).length;
  const enforcing = p.state === 'enabled';
  const wide = (u.includeUsers || []).includes('All');
  C('breakglass', 'Emergency-access exclusion', enforcing ? 'stop' : 'warn', exclusions ? 'pass' : enforcing ? 'fail' : 'warn', exclusions ? exclusions + ' excluded user(s)/group(s)' : (wide ? 'No exclusion: an enforced policy on All users with no break-glass exclusion can lock every administrator out.' : 'No exclusion. Microsoft guidance is to exclude the emergency-access accounts from every policy.'), exclusions ? null : 'Add the break-glass account(s) or group under Exclude before enforcing.');
  /* state */
  if (enforcing) C('enforce', 'Enforcement confirmation', 'stop', 'confirm', 'State is ENABLED: this changes production sign-in the moment Graph accepts it. Type the phrase ' + JSON.stringify(confirmPhrase(ch, 'enforce')) + ' on Push.', 'Prefer report-only first; check the Entra sign-in log for "reportOnly" results, then enforce.');
  else if (p.state === 'enabledForReportingButNotEnforced') C('state', 'Report-only', 'note', 'pass', 'Evaluated and logged, never enforced. Not counted as a replacement for the Okta rule.' + ((p.grantControls && (p.grantControls.builtInControls || []).some((x) => /Device$/.test(x))) ? ' NOTE: report-only policies with a device control can still prompt Mac/iOS/Android users to pick a device certificate during evaluation.' : ''), null);
  else C('state', 'Disabled', 'note', 'pass', 'Created but off. Nothing changes for users; switch to report-only or enforced as a later change.', null);
  if (Array.isArray(p.conditions.signInRiskLevels) && p.conditions.signInRiskLevels.length) C('p2', 'Sign-in risk condition', 'note', 'pass', 'Needs Entra ID P2 (Identity Protection) licences for the targeted users.', null);
  /* create: duplicate name */
  if (ch.kind === 'create') {
    const [[dup]] = await pool.query(`SELECT ca_id, display_name FROM oem_entra_ca WHERE LOWER(display_name)=LOWER(?) LIMIT 1`, [p.displayName]);
    const lv = await liveByName(p.displayName);
    if (lv.policy) C('dup', 'No existing policy with this name', 'stop', 'fail', 'Entra already has a policy named "' + lv.policy.displayName + '" (' + lv.policy.id + ', ' + (STATE_LABEL[lv.policy.state] || lv.policy.state) + ') — read live just now. Creating another would leave two same-named policies.', 'Amend the existing policy instead, or rename the draft.');
    else if (dup) C('dup', 'No existing policy with this name', 'warn', 'warn', 'The last snapshot had a policy named "' + dup.display_name + '" (' + dup.ca_id + ') but the live list does not have it now.', 'Refresh the policy snapshot; rename if in doubt.');
    else C('dup', 'No existing policy with this name', 'warn', lv.known ? 'pass' : 'warn', lv.known ? 'name is unique (live list + snapshot)' : 'name is unique in the last snapshot; the live list could not be read (' + lv.error + ')', lv.known ? null : 'Retry so the live list can be checked.');
    C('rollback', 'Rollback', 'note', 'pass', 'DELETE the created policy (one click on this record; needs the typed phrase). A disabled or report-only policy can also simply be left in place.', null);
  } else {
    if (!live) C('live', 'Target policy readable in Entra', 'stop', 'fail', 'The policy could not be read from Graph right now.', 'Retry; check the read credential.');
    else {
      const b = ch.before || {};
      const changed = b.modifiedDateTime && live.modifiedDateTime && b.modifiedDateTime !== live.modifiedDateTime;
      C('live', 'Target policy unchanged since this draft was built', 'stop', changed ? 'fail' : 'pass', changed ? 'Modified in Entra at ' + live.modifiedDateTime + ' (draft built against ' + b.modifiedDateTime + ').' : 'live modifiedDateTime ' + (live.modifiedDateTime || 'unknown') + ' matches the draft', changed ? 'Re-open the policy and draft the change again.' : null);
      C('live_state', 'Live state', live.state === 'enabled' ? 'warn' : 'note', 'pass', 'The policy is currently ' + ({ enabled: 'ENFORCED', enabledForReportingButNotEnforced: 'report-only', disabled: 'disabled' }[live.state] || live.state) + (live.state === 'enabled' && p.state === 'enabled' ? ' — the PATCH changes production sign-in immediately.' : '.'), null);
      C('rollback', 'Rollback', 'note', 'pass', 'PATCH the saved before-state back (one click on this record; needs the typed phrase).', null);
    }
  }
  const stops = checks.filter((c) => c.level === 'stop' && c.status === 'fail');
  const confirms = checks.filter((c) => c.status === 'confirm');
  return { checkedAt: nowIso(), checks, stops: stops.length, ok: !stops.length, needsConfirm: confirms.length > 0, confirmPhrase: confirms.length ? confirmPhrase(ch, 'enforce') : null };
}
const CMP_ALIAS = { '00000002-0000-0ff1-ce00-000000000000': 1, '00000003-0000-0ff1-ce00-000000000000': 1, '00000002-0000-0000-c000-000000000000': 1, '00000003-0000-0000-c000-000000000000': 1, '797f4846-ba00-4fd7-ba43-dac1f8f63013': 1, 'd4ebce55-015a-49b5-a083-c84d1797ae8c': 1, '0000000a-0000-0000-c000-000000000000': 1 };
function confirmPhrase(ch, what) { return (what === 'enforce' ? 'ENFORCE ' : what === 'delete' ? 'DELETE ' : 'REVERT ') + ch.displayName; }

/* ------------------------------------------------------------ persistence */

async function event(changeId, actor, ev, request, response, result, detail) {
  try { await pool.query(`INSERT INTO oem_ca_change_event (change_id, at, actor, event, request, response, result, detail) VALUES (?,NOW(),?,?,?,?,?,?)`, [changeId, actor || null, ev, request === undefined ? null : JSON.stringify(L.redact(request)), response === undefined ? null : JSON.stringify(L.redact(response)), result || null, short(detail, 2000)]); }
  catch (e) { console.error('[oem-ca] event:', e.message); }
}
function rowToChange(r) {
  return { id: r.id, kind: r.kind, entraPolicyId: r.entra_policy_id, oktaRuleKey: r.okta_rule_key, displayName: r.display_name, requestedState: r.requested_state, payload: j(r.payload, null), provenance: j(r.provenance, null), before: j(r.before_state, null), after: j(r.after_state, null), verification: j(r.verification, null), status: r.status, error: r.error,
    createdBy: r.created_by, createdAt: r.created_at, updatedBy: r.updated_by, updatedAt: r.updated_at, approvedBy: r.approved_by, approvedAt: r.approved_at, pushedBy: r.pushed_by, pushedAt: r.pushed_at, verifiedAt: r.verified_at, rolledBackBy: r.rolled_back_by, rolledBackAt: r.rolled_back_at, cancelledBy: r.cancelled_by, cancelledAt: r.cancelled_at };
}
async function getChange(id, { events = true } = {}) {
  const [[r]] = await pool.query(`SELECT * FROM oem_ca_change WHERE id=?`, [id]);
  if (!r) return null;
  const ch = rowToChange(r);
  if (events) { const [ev] = await pool.query(`SELECT id, at, actor, event, request, response, result, detail FROM oem_ca_change_event WHERE change_id=? ORDER BY id`, [id]); ch.events = ev.map((e) => ({ id: e.id, at: e.at, actor: e.actor, event: e.event, request: j(e.request, null), response: j(e.response, null), result: e.result, detail: e.detail })); }
  return ch;
}
async function setStatus(id, status, extra = {}) {
  const sets = ['status=?']; const vals = [status];
  for (const [k, v] of Object.entries(extra)) { sets.push(k + '=?'); vals.push(v instanceof Date ? v : (v !== null && typeof v === 'object' ? JSON.stringify(v) : v)); }
  vals.push(id);
  await pool.query(`UPDATE oem_ca_change SET ${sets.join(', ')} WHERE id=?`, vals);
}
async function livePolicy(id) {
  const r = await L.graphGet('/v1.0/identity/conditionalAccess/policies/' + encodeURIComponent(id));
  return { status: r.status, policy: r.status === 200 ? r.body : null, error: r.error };
}
/** Live list (id, name, state only) — used to catch a same-named policy that an earlier, timed-out attempt may have created. */
let liveListCache = { at: 0, rows: null, error: null };
async function liveList(fresh) {
  if (!fresh && liveListCache.rows && Date.now() - liveListCache.at < 30000) return liveListCache;
  const r = await L.graphGet('/v1.0/identity/conditionalAccess/policies?$select=id,displayName,state');
  liveListCache = { at: Date.now(), rows: r.status === 200 && r.body && Array.isArray(r.body.value) ? r.body.value : null, error: r.status === 200 ? null : (r.error || ('HTTP ' + r.status)) };
  return liveListCache;
}
async function liveByName(name, fresh) {
  const l = await liveList(fresh);
  if (!l.rows) return { known: false, error: l.error, policy: null };
  return { known: true, error: null, policy: l.rows.find((x) => lc(x.displayName) === lc(name)) || null };
}
/** Read back after a write; Graph is eventually consistent for a few seconds after a create. */
async function readBack(id, tries = 6) {
  let r = null;
  for (let i = 0; i < tries; i++) { r = await livePolicy(id); if (r.status === 200 || (r.status !== 404 && r.status !== 0)) return r; await L.sleep(1500 * (i + 1)); }
  return r;
}
/** Did the read-back match what was requested? Compares the fields the write set. */
function verify(payload, live) {
  const diffs = [];
  const eqSet = (a, b) => { const A = uniq((a || []).map(String)).sort(), B = uniq((b || []).map(String)).sort(); return JSON.stringify(A) === JSON.stringify(B); };
  if (payload.displayName !== undefined && live.displayName !== payload.displayName) diffs.push('displayName: wanted ' + JSON.stringify(payload.displayName) + ', live ' + JSON.stringify(live.displayName));
  if (payload.state !== undefined && live.state !== payload.state) diffs.push('state: wanted ' + payload.state + ', live ' + live.state);
  if (payload.conditions) {
    const lu = (live.conditions || {}).users || {}, pu = payload.conditions.users || {}, la = (live.conditions || {}).applications || {}, pa = payload.conditions.applications || {};
    for (const k of ['includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups']) if (!eqSet(pu[k], lu[k])) diffs.push('users.' + k + ' differ');
    for (const k of ['includeApplications', 'excludeApplications']) if (!eqSet(pa[k], la[k])) diffs.push('applications.' + k + ' differ');
    if (!eqSet(payload.conditions.clientAppTypes, (live.conditions || {}).clientAppTypes)) diffs.push('clientAppTypes differ');
    if (payload.conditions.locations && !eqSet(payload.conditions.locations.excludeLocations, ((live.conditions || {}).locations || {}).excludeLocations)) diffs.push('locations.excludeLocations differ');
    if (payload.conditions.locations && !eqSet(payload.conditions.locations.includeLocations, ((live.conditions || {}).locations || {}).includeLocations)) diffs.push('locations.includeLocations differ');
  }
  if (payload.grantControls !== undefined) { const lg = live.grantControls || {}, pg = payload.grantControls || {}; if (!eqSet(pg.builtInControls, lg.builtInControls)) diffs.push('grantControls.builtInControls: wanted [' + (pg.builtInControls || []).join(', ') + '], live [' + (lg.builtInControls || []).join(', ') + ']'); if ((pg.authenticationStrength && pg.authenticationStrength.id) !== (lg.authenticationStrength && lg.authenticationStrength.id) && (pg.authenticationStrength || lg.authenticationStrength)) diffs.push('authenticationStrength differs'); }
  if (payload.sessionControls !== undefined) { const ls = (live.sessionControls || {}).signInFrequency, ps = (payload.sessionControls || {}).signInFrequency; if (!!(ls && ls.isEnabled) !== !!(ps && ps.isEnabled) || (ps && ls && (ps.frequencyInterval !== ls.frequencyInterval || (ps.frequencyInterval === 'timeBased' && (ps.value !== ls.value || ps.type !== ls.type))))) diffs.push('signInFrequency differs'); }
  return { ok: !diffs.length, diffs, checkedAt: nowIso() };
}

/* ----------------------------------------------------------------- routes */

let reportCache = { at: 0, p: null };
function report(fresh) { if (!fresh && reportCache.p && Date.now() - reportCache.at < 20000) return reportCache.p; reportCache = { at: Date.now(), p: CMP._internal.buildReport({}).catch((e) => { reportCache = { at: 0, p: null }; throw e; }) }; return reportCache.p; }

// POST /translate { ruleKey } — a proposal, nothing written
router.post('/translate', json, read(), async (req, res) => {
  try {
    const key = String(req.body && req.body.ruleKey || '');
    if (!/^[0-9a-zA-Z]{16,24}:[0-9a-zA-Z]{16,24}$/.test(key)) return res.status(400).json({ error: 'bad ruleKey' });
    const t = await translate(key, await report(false));
    if (!t) return res.status(404).json({ error: 'Okta rule not in the last snapshot' });
    const st = await strengths();
    res.json(Object.assign(t, { strengths: st.list, strengthsError: st.error, readOnly: true, note: 'A proposal built from the snapshot. Nothing is written until a change is drafted, approved and pushed.' }));
  } catch (e) { fail(res, e, 'translate'); }
});

// GET /policy/:id/live — the policy as Graph holds it right now
router.get('/policy/:id/live', read(), async (req, res) => {
  try {
    if (!GUID.test(req.params.id)) return res.status(400).json({ error: 'bad policy id' });
    const r = await livePolicy(req.params.id);
    if (r.status !== 200) return res.status(r.status === 404 ? 404 : 502).json({ error: r.error || ('HTTP ' + r.status), status: r.status });
    const st = await strengths();
    res.json({ policy: r.policy, strengths: st.list, readAt: nowIso(), source: 'Graph GET /identity/conditionalAccess/policies/' + req.params.id + ' (read credential)' });
  } catch (e) { fail(res, e, 'policy/live'); }
});

// GET /pick/:kind?q= — picker rows from the mirrors (groups | users | apps | locations | strengths | roles)
router.get('/pick/:kind', read(), async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().slice(0, 80); const like = '%' + q.replace(/[%_]/g, '\\$&') + '%';
    const kind = req.params.kind; let rows = [];
    if (kind === 'groups') [rows] = await pool.query(`SELECT entra_id id, display_name name FROM entra_groups WHERE display_name LIKE ? ORDER BY display_name LIMIT 25`, [like]);
    else if (kind === 'users') [rows] = await pool.query(`SELECT entra_id id, display_name name, user_principal_name upn FROM entra_users WHERE display_name LIKE ? OR user_principal_name LIKE ? ORDER BY display_name LIMIT 25`, [like, like]);
    else if (kind === 'apps') [rows] = await pool.query(`SELECT app_id id, display_name name, entra_id objectId FROM entra_apps WHERE display_name LIKE ? AND app_id IS NOT NULL ORDER BY display_name LIMIT 25`, [like]);
    else if (kind === 'locations') [rows] = await pool.query(`SELECT loc_id id, display_name name, loc_type type, is_trusted trusted FROM oem_entra_named_location WHERE display_name LIKE ? ORDER BY display_name LIMIT 50`, [like]);
    else if (kind === 'strengths') { const st = await strengths(); rows = st.list.filter((s) => !q || lc(s.displayName).includes(lc(q))); }
    else return res.status(400).json({ error: 'kind must be groups | users | apps | locations | strengths' });
    res.json({ kind, q, rows, source: kind === 'strengths' ? 'Graph authenticationStrengthPolicies' : 'directory mirror' });
  } catch (e) { fail(res, e, 'pick'); }
});

// GET /changes — every change record (newest first)
router.get('/changes', read(), async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM oem_ca_change ORDER BY id DESC LIMIT 500`);
    res.json({ changes: rows.map(rowToChange).map((c) => Object.assign(c, { payload: undefined, provenance: undefined, before: undefined, after: undefined })), count: rows.length });
  } catch (e) { fail(res, e, 'changes'); }
});

// GET /changes/:id — one record with its events and a fresh pre-flight
router.get('/changes/:id', read(), async (req, res) => {
  try {
    const ch = await getChange(+req.params.id);
    if (!ch) return res.status(404).json({ error: 'no such change' });
    res.json(await detail(req, ch));
  } catch (e) { fail(res, e, 'changes/:id'); }
});
/* the record + a fresh pre-flight (drafts / approved only) + what this caller may do — the shape every mutating route answers with */
async function detail(req, ch) {
  let pf = null;
  if (ch.status === 'draft' || ch.status === 'approved') {
    const ctx = await M.context();
    const live = ch.kind === 'update' && ch.entraPolicyId ? (await livePolicy(ch.entraPolicyId)).policy : null;
    pf = await preflight(ch, ctx, live);
  }
  const lvl = await pageLevel(req);
  return Object.assign(ch, { preflight: pf, canAct: canAct(lvl, req), confirmPhrases: { enforce: confirmPhrase(ch, 'enforce'), rollback: confirmPhrase(ch, ch.kind === 'create' ? 'delete' : 'revert') } });
}
async function pageLevel(req) { try { if (req.user && req.user.email && rbac.computeEffectivePages) { const pages = await rbac.computeEffectivePages(req.user.email, req.user.roles || [], !!req.user.isSuperAdmin); return pages[PAGE_KEY] || 'none'; } } catch (e) { console.error('[oem-ca] pageLevel:', e.message); } return null; }
const canAct = (lvl, req) => lvl === 'admin' && !(req.user && req.user.readOnly);
async function mustAct(req, res) { const lvl = await pageLevel(req); if (!canAct(lvl, req)) { res.status(403).json({ error: 'read-only: this account cannot stage Conditional Access changes' }); return false; } return true; }

// POST /changes — draft
router.post('/changes', json, admin(), async (req, res) => {
  try {
    if (!(await mustAct(req, res))) return;
    const b = req.body || {}; const kind = b.kind === 'update' ? 'update' : 'create';
    const san = sanitizePolicy(b.policy || {});
    if (san.errors.length) return res.status(400).json({ error: 'policy rejected', errors: san.errors });
    let before = null, entraPolicyId = null;
    if (kind === 'update') {
      if (!GUID.test(String(b.entraPolicyId || ''))) return res.status(400).json({ error: 'entraPolicyId required for an update' });
      const live = await livePolicy(b.entraPolicyId);
      if (live.status !== 200) return res.status(502).json({ error: 'could not read the live policy: ' + (live.error || live.status) });
      before = live.policy; entraPolicyId = b.entraPolicyId;
    }
    const prov = { provenance: Array.isArray(b.provenance) ? b.provenance.slice(0, 200) : [], unresolved: Array.isArray(b.unresolved) ? b.unresolved.slice(0, 100) : [], notes: Array.isArray(b.notes) ? b.notes.slice(0, 50) : [], sanitizerNotes: san.notes };
    const [r] = await pool.query(`INSERT INTO oem_ca_change (kind, entra_policy_id, okta_rule_key, display_name, requested_state, payload, provenance, before_state, status, created_by) VALUES (?,?,?,?,?,?,?,?, 'draft', ?)`,
      [kind, entraPolicyId, b.oktaRuleKey && /^[0-9a-zA-Z]{16,24}:[0-9a-zA-Z]{16,24}$/.test(b.oktaRuleKey) ? b.oktaRuleKey : null, san.policy.displayName, san.policy.state, JSON.stringify(san.policy), JSON.stringify(prov), before ? JSON.stringify(before) : null, actorOf(req)]);
    await event(r.insertId, actorOf(req), 'drafted', { kind, entraPolicyId, oktaRuleKey: b.oktaRuleKey || null }, { state: san.policy.state }, 'ok', kind === 'update' ? 'before-state read from Graph' : null);
    audit(req, 'oem_ca_draft', { id: r.insertId, kind, displayName: san.policy.displayName, state: san.policy.state }, null);
    res.json(await detail(req, await getChange(r.insertId)));
  } catch (e) { fail(res, e, 'changes/draft'); }
});

// POST /changes/:id — edit a draft (payload replaced; before-state kept)
router.post('/changes/:id', json, admin(), async (req, res) => {
  try {
    if (!(await mustAct(req, res))) return;
    const ch = await getChange(+req.params.id, { events: false });
    if (!ch) return res.status(404).json({ error: 'no such change' });
    if (ch.status !== 'draft' && ch.status !== 'approved') return res.status(409).json({ error: 'only a draft can be edited (status ' + ch.status + ')' });
    const b = req.body || {}; const san = sanitizePolicy(b.policy || {});
    if (san.errors.length) return res.status(400).json({ error: 'policy rejected', errors: san.errors });
    const prov = Object.assign({}, ch.provenance || {}, { unresolved: Array.isArray(b.unresolved) ? b.unresolved.slice(0, 100) : (ch.provenance && ch.provenance.unresolved) || [], sanitizerNotes: san.notes });
    // an edit after approval drops the approval: the approver saw a different payload
    await pool.query(`UPDATE oem_ca_change SET payload=?, provenance=?, display_name=?, requested_state=?, status='draft', approved_by=NULL, approved_at=NULL, updated_by=?, updated_at=NOW() WHERE id=?`, [JSON.stringify(san.policy), JSON.stringify(prov), san.policy.displayName, san.policy.state, actorOf(req), ch.id]);
    await event(ch.id, actorOf(req), 'edited', null, { state: san.policy.state, wasApproved: ch.status === 'approved' }, 'ok', ch.status === 'approved' ? 'approval cleared by the edit' : null);
    res.json(await detail(req, await getChange(ch.id)));
  } catch (e) { fail(res, e, 'changes/edit'); }
});

// POST /changes/:id/approve
router.post('/changes/:id/approve', json, admin(), async (req, res) => {
  try {
    if (!(await mustAct(req, res))) return;
    const ch = await getChange(+req.params.id, { events: false });
    if (!ch) return res.status(404).json({ error: 'no such change' });
    if (ch.status !== 'draft') return res.status(409).json({ error: 'only a draft can be approved (status ' + ch.status + ')' });
    const ctx = await M.context();
    const live = ch.kind === 'update' ? (await livePolicy(ch.entraPolicyId)).policy : null;
    const pf = await preflight(ch, ctx, live);
    if (!pf.ok) return res.status(409).json({ error: 'pre-flight has ' + pf.stops + ' stop(s); fix them before approving', preflight: pf });
    await setStatus(ch.id, 'approved', { approved_by: actorOf(req), approved_at: new Date() });
    await event(ch.id, actorOf(req), 'approved', null, { preflight: pf.checks.map((c) => c.key + ':' + c.status) }, 'ok', null);
    audit(req, 'oem_ca_approve', { id: ch.id, displayName: ch.displayName, state: ch.requestedState }, null);
    res.json(await getChange(ch.id));
  } catch (e) { fail(res, e, 'changes/approve'); }
});

// POST /changes/:id/push { confirm? } — the Graph write, then the read-back
router.post('/changes/:id/push', json, admin(), async (req, res) => {
  try {
    if (!(await mustAct(req, res))) return;
    const ch = await getChange(+req.params.id, { events: false });
    if (!ch) return res.status(404).json({ error: 'no such change' });
    if (ch.status !== 'approved') return res.status(409).json({ error: 'approve the change first (status ' + ch.status + ')' });
    const actor = actorOf(req);
    const ctx = await M.context();
    const liveR = ch.kind === 'update' ? await livePolicy(ch.entraPolicyId) : null;
    const pf = await preflight(ch, ctx, liveR ? liveR.policy : null);
    await event(ch.id, actor, 'preflight', null, { checks: pf.checks.map((c) => ({ key: c.key, status: c.status, detail: c.detail })) }, pf.ok ? 'ok' : 'stop', pf.ok ? null : pf.stops + ' stop(s)');
    if (!pf.ok) return res.status(409).json({ error: 'pre-flight stopped the push', preflight: pf, change: await getChange(ch.id) });
    if (pf.needsConfirm && String(req.body && req.body.confirm || '') !== pf.confirmPhrase) { await event(ch.id, actor, 'graph_refused', null, null, 'refused', 'enforcement confirmation phrase missing or wrong'); return res.status(428).json({ error: 'this push ENFORCES a policy: type the confirmation phrase exactly', confirmPhrase: pf.confirmPhrase, preflight: pf }); }
    // a write that was already recorded as pushed is never repeated: verify by read instead
    const [ev] = await pool.query(`SELECT id FROM oem_ca_change_event WHERE change_id=? AND event='graph_write' LIMIT 1`, [ch.id]);
    if (ev.length) return res.status(409).json({ error: 'a Graph write was already recorded for this change; verify by reading the policy instead of pushing again' });
    const payload = ch.payload;
    const isCreate = ch.kind === 'create';
    const method = isCreate ? 'POST' : 'PATCH';
    const path = isCreate ? '/v1.0/identity/conditionalAccess/policies' : '/v1.0/identity/conditionalAccess/policies/' + ch.entraPolicyId;
    const body = isCreate ? payload : { displayName: payload.displayName, state: payload.state, conditions: payload.conditions, grantControls: payload.grantControls, sessionControls: payload.sessionControls };
    audit(req, isCreate ? 'oem_ca_create' : 'oem_ca_update', { id: ch.id, displayName: ch.displayName, state: payload.state, policyId: ch.entraPolicyId }, null);
    const r = await L.graphRequest(method, path, body, { cred: 'write' });
    const ok = r.status >= 200 && r.status < 300;
    await event(ch.id, actor, ok ? 'graph_write' : 'graph_error', { method, path, body }, ok ? (isCreate && r.body ? { id: r.body.id, state: r.body.state, displayName: r.body.displayName } : { status: r.status }) : r.body, ok ? 'ok' : 'error', ok ? null : r.error);
    if (!ok) {
      // a 4xx is a definite refusal; anything else (5xx, timeout, no status) leaves the outcome unknown until the live state is read
      const refused = r.status >= 400 && r.status < 500;
      let recovery, outcome = refused ? 'refused' : 'unknown';
      if (isCreate) {
        if (refused) recovery = 'Nothing was created. Fix the draft (the Graph message names the field) and stage a new change.';
        else {
          const lv = await liveByName(payload.displayName, true);
          if (lv.policy) { outcome = 'created'; recovery = 'Graph did not answer cleanly but a policy named "' + lv.policy.displayName + '" now exists (' + lv.policy.id + ', ' + (STATE_LABEL[lv.policy.state] || lv.policy.state) + '). Treat it as this change: verify it on the Conditional Access tab before staging anything else.'; const rb = await livePolicy(lv.policy.id); if (rb.policy) await upsertSnapshot(rb.policy); }
          else if (lv.known) { outcome = 'not-created'; recovery = 'Graph did not answer cleanly and no policy with this name exists in the live list. Nothing was created; stage a new change.'; }
          else recovery = 'Graph did not answer and the live list could not be read either. Do NOT stage this again until the Conditional Access tab (refresh) shows whether the policy exists.';
        }
      } else {
        if (refused) recovery = 'The policy was not modified. Re-read it, fix the draft and stage a new change.';
        else { const rb = await livePolicy(ch.entraPolicyId); if (rb.policy) { const v = verify(payload, rb.policy); outcome = v.ok ? 'applied' : 'not-applied'; recovery = v.ok ? 'Graph did not answer cleanly but the live policy now matches the request. Treat the change as applied; re-verify before relying on it.' : 'Graph did not answer cleanly; the live policy does not match the request (' + v.diffs.join('; ') + '). Stage a new change after checking it.'; await upsertSnapshot(rb.policy); } else recovery = 'Graph did not answer and the policy could not be re-read. Check it on the Conditional Access tab before staging anything else.'; }
      }
      await setStatus(ch.id, 'failed', { error: short(method + ' ' + path + ' → ' + (r.error || r.status) + ' · outcome ' + outcome, 2000), pushed_by: actor, pushed_at: new Date() });
      await event(ch.id, actor, 'outcome', null, { outcome }, outcome === 'refused' || outcome === 'not-created' ? 'ok' : 'check', recovery);
      reportCache = { at: 0, p: null };
      return res.status(502).json({ error: 'Graph rejected the write: ' + (r.error || ('HTTP ' + r.status)), status: r.status, outcome, recovery, change: await getChange(ch.id) });
    }
    const policyId = isCreate ? (r.body && r.body.id) || null : ch.entraPolicyId;
    await setStatus(ch.id, 'pushed', { entra_policy_id: policyId, pushed_by: actor, pushed_at: new Date(), error: null });
    // read-back = the only source of "done"
    let ver = { ok: false, diffs: ['read-back failed'], checkedAt: nowIso() }, after = null;
    if (policyId) {
      const rb = await readBack(policyId);
      if (rb.status === 200 && rb.policy) { after = rb.policy; ver = verify(payload, after); await upsertSnapshot(after); }
      else ver = { ok: false, diffs: ['read-back: ' + (rb.error || ('HTTP ' + rb.status))], checkedAt: nowIso() };
    } else ver = { ok: false, diffs: ['Graph returned no policy id'], checkedAt: nowIso() };
    await setStatus(ch.id, ver.ok ? 'verified' : 'pushed', { after_state: after, verification: ver, verified_at: ver.ok ? new Date() : null });
    await event(ch.id, actor, 'verified', null, ver, ver.ok ? 'ok' : 'mismatch', ver.ok ? 'read-back matches the request' : ver.diffs.join('; '));
    reportCache = { at: 0, p: null };
    res.json(Object.assign(await getChange(ch.id), { note: ver.ok ? 'Graph accepted the write and the read-back matches. The policy is ' + ({ enabled: 'ENFORCED', enabledForReportingButNotEnforced: 'report-only (not enforced)', disabled: 'disabled' }[after && after.state] || 'in the state shown') + '.' : 'Graph accepted the write but the read-back does not match yet: ' + ver.diffs.join('; ') + '. Re-open this record to check again before relying on it.' }));
  } catch (e) { fail(res, e, 'changes/push'); }
});

// POST /changes/:id/rollback { confirm } — DELETE the created policy / PATCH the before-state back
router.post('/changes/:id/rollback', json, admin(), async (req, res) => {
  try {
    if (!(await mustAct(req, res))) return;
    const ch = await getChange(+req.params.id, { events: false });
    if (!ch) return res.status(404).json({ error: 'no such change' });
    if (!['pushed', 'verified'].includes(ch.status)) return res.status(409).json({ error: 'nothing to roll back (status ' + ch.status + ')' });
    const phrase = confirmPhrase(ch, ch.kind === 'create' ? 'delete' : 'revert');
    if (String(req.body && req.body.confirm || '') !== phrase) return res.status(428).json({ error: 'type the confirmation phrase exactly', confirmPhrase: phrase });
    const actor = actorOf(req); const ctx = await M.context();
    const pc = M.permCheck(PERM_CA, ctx.roles);
    if (pc.ok !== true) { await event(ch.id, actor, 'graph_refused', null, null, 'refused', 'needs ' + pc.missing); return res.status(409).json({ error: 'refused: needs ' + pc.missing + ' — ' + GRANTOR }); }
    let method, path, body;
    if (ch.kind === 'create') { method = 'DELETE'; path = '/v1.0/identity/conditionalAccess/policies/' + ch.entraPolicyId; body = undefined; }
    else { const b = ch.before || {}; method = 'PATCH'; path = '/v1.0/identity/conditionalAccess/policies/' + ch.entraPolicyId; body = { displayName: b.displayName, state: b.state, conditions: b.conditions, grantControls: b.grantControls, sessionControls: b.sessionControls }; }
    audit(req, 'oem_ca_rollback', { id: ch.id, displayName: ch.displayName, method, policyId: ch.entraPolicyId }, null);
    const r = await L.graphRequest(method, path, body, { cred: 'write' });
    const ok = r.status >= 200 && r.status < 300;
    await event(ch.id, actor, ok ? 'graph_write' : 'graph_error', { method, path, body: body === undefined ? null : body }, ok ? { status: r.status } : r.body, ok ? 'ok' : 'error', ok ? 'rollback' : r.error);
    if (!ok) { await setStatus(ch.id, ch.status, { error: short('rollback ' + method + ' ' + path + ' → ' + (r.error || r.status), 2000) }); return res.status(502).json({ error: 'Graph rejected the rollback: ' + (r.error || ('HTTP ' + r.status)), recovery: ch.kind === 'create' ? 'The policy still exists. Delete it in the Entra portal (Protection → Conditional Access) or retry.' : 'The policy still holds the pushed change. Retry, or restore it in the Entra portal from the before-state on this record.', change: await getChange(ch.id) }); }
    if (ch.kind === 'create') { await pool.query(`DELETE FROM oem_entra_ca WHERE ca_id=?`, [ch.entraPolicyId]); }
    else { const rb = await readBack(ch.entraPolicyId); if (rb.status === 200 && rb.policy) await upsertSnapshot(rb.policy); }
    await setStatus(ch.id, 'rolled_back', { rolled_back_by: actor, rolled_back_at: new Date(), error: null });
    await event(ch.id, actor, 'rolled_back', null, null, 'ok', null);
    reportCache = { at: 0, p: null };
    res.json(await getChange(ch.id));
  } catch (e) { fail(res, e, 'changes/rollback'); }
});

// POST /changes/:id/cancel — drop a draft / approved change (no Graph call)
router.post('/changes/:id/cancel', json, admin(), async (req, res) => {
  try {
    if (!(await mustAct(req, res))) return;
    const ch = await getChange(+req.params.id, { events: false });
    if (!ch) return res.status(404).json({ error: 'no such change' });
    if (!['draft', 'approved', 'failed'].includes(ch.status)) return res.status(409).json({ error: 'cannot cancel a change in status ' + ch.status });
    await setStatus(ch.id, 'cancelled', { cancelled_by: actorOf(req), cancelled_at: new Date() });
    await event(ch.id, actorOf(req), 'cancelled', null, null, 'ok', short(req.body && req.body.note, 500));
    res.json(await getChange(ch.id));
  } catch (e) { fail(res, e, 'changes/cancel'); }
});

module.exports = router;
module.exports._internal = { sanitizePolicy, translate, preflight, verify, detectInert, confirmPhrase, STATES, CONTROLS, PLATFORMS, CLIENT_TYPES, resetCaches: () => { liveListCache = { at: 0, rows: null, error: null }; reportCache = { at: 0, p: null }; } };
