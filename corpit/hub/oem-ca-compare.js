/**
 * oem-ca-compare.js — Conditional Access review and Okta comparison (read-only).
 * Mount in server.js:  app.use('/api/oem/ca', require('./oem-ca-compare'));
 *
 * GET /api/oem/ca/compare
 *   Reads the last policy snapshot (oem_entra_ca, oem_okta_policy, zones, named locations,
 *   zone parity) plus the directory mirrors (entra_users/groups/apps, okta_apps, okta_users,
 *   app_matches) and returns every Entra Conditional Access policy and every Okta sign-on /
 *   app sign-on rule in one normalised shape, with a tolerant, explained comparison between
 *   them. Nothing here writes to Okta or Entra, and nothing is scored from a name alone:
 *   every dimension carries the two sides and the reason for its verdict.
 *
 *   FACTS come from the snapshot tables. The only live call is a capped, cached read of Okta
 *   group names that the mirror does not hold (the policy snapshot already reads groups with
 *   the same token; no broader access). An id the mirrors cannot name is returned as the id
 *   with source 'unresolved' — never a guessed name.
 *
 *   A report-only or disabled Entra policy is compared like any other, but it is never
 *   counted as an enforced replacement: coverage counts only enabled, non-inert policies.
 */
'use strict';
const express = require('express');
const createRbac = require('./rbac-middleware');
const L = require('./oem-lib');
const { pool, j } = L;

const router = express.Router();
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const PAGE_KEY = 'okta-entra-migration';
const read = () => rbac.requirePage(PAGE_KEY, 'read');

/* ------------------------------------------------------------------ helpers */

const lc = (s) => String(s || '').trim().toLowerCase();
/** Group names on both sides share the SaaS- / SSO- conventions; compare the core. */
const groupKey = (s) => lc(s).replace(/^(saas|sso|okta|entra|aad|grp|group)[-_ ]+/, '').replace(/[^a-z0-9]+/g, '');
const uniq = (a) => a.filter((v, i) => a.indexOf(v) === i);
const plural = (n, s, p) => n + ' ' + (n === 1 ? s : (p || s + 's'));

/** ISO-8601 duration (PT12H, PT0S, PT43800H, P1D) -> hours, or null. */
function isoHours(s) {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(String(s || ''));
  if (!m) return null;
  const d = +(m[1] || 0), h = +(m[2] || 0), mi = +(m[3] || 0), se = +(m[4] || 0);
  return d * 24 + h + mi / 60 + se / 3600;
}
function hoursText(h) {
  if (h === null || h === undefined) return null;
  if (h === 0) return 'every sign-in';
  if (h >= 24 * 365) return 'never (' + Math.round(h / 24) + ' days)';
  if (h >= 48 && h % 24 === 0) return (h / 24) + ' days';
  return h + 'h';
}

/* Well-known Conditional Access application groups and first-party ids. */
const CA_APP_ALIAS = {
  All: 'All cloud apps', None: 'No apps', Office365: 'Office 365 (app group)', MicrosoftAdminPortals: 'Microsoft Admin Portals',
  '00000002-0000-0ff1-ce00-000000000000': 'Office 365 Exchange Online', '00000003-0000-0ff1-ce00-000000000000': 'Office 365 SharePoint Online',
  '00000002-0000-0000-c000-000000000000': 'Windows Azure Active Directory', '00000003-0000-0000-c000-000000000000': 'Microsoft Graph',
  '797f4846-ba00-4fd7-ba43-dac1f8f63013': 'Windows Azure Service Management API', 'd4ebce55-015a-49b5-a083-c84d1797ae8c': 'Microsoft Intune Enrollment',
  '0000000a-0000-0000-c000-000000000000': 'Microsoft Intune',
};
const OKTA_CLIENT_MAP = { WEB: 'browser', MODERN_AUTH: 'mobileAppsAndDesktopClients', ACTIVE_SYNC: 'exchangeActiveSync', LEGACY_AUTH: 'other' };
const ALL_CLIENTS = ['browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other'];
const CLIENT_LABEL = { browser: 'browser', mobileAppsAndDesktopClients: 'modern auth clients', exchangeActiveSync: 'Exchange ActiveSync', other: 'legacy auth clients' };
const OKTA_OS_MAP = { MACOS: 'macOS', WINDOWS: 'windows', IOS: 'iOS', ANDROID: 'android', CHROMEOS: 'chromeOS', LINUX: 'linux', OTHER: 'other' };
const CONTROL_LABEL = { block: 'Block', mfa: 'MFA', compliantDevice: 'compliant device', domainJoinedDevice: 'Entra hybrid joined device', approvedApplication: 'approved client app', compliantApplication: 'app protection policy', passwordChange: 'password change' };
const STATE_LABEL = { enabled: 'Enforced', enabledForReportingButNotEnforced: 'Report-only', disabled: 'Disabled' };
const STATE_KEY = { enabled: 'enforced', enabledForReportingButNotEnforced: 'report', disabled: 'disabled' };

/* --------------------------------------------------------- normalise: Entra */

/** names: { user(id), group(id), role(id), app(appId), loc(id) } -> { name, source } */
function normEntra(p, names) {
  const c = p.conditions || {}, g = p.grantControls || {}, s = p.sessionControls || {};
  const nm = (kind, id) => { const r = names[kind](id); return { id, name: r.name, source: r.source }; };
  const u = c.users || {};
  const incU = (u.includeUsers || []), incG = (u.includeGroups || []), incR = (u.includeRoles || []);
  const who = {
    kind: incU.indexOf('All') >= 0 ? 'all' : (incU.indexOf('None') >= 0 || (!incU.length && !incG.length && !incR.length)) ? 'none' : 'some',
    users: incU.filter((x) => x !== 'All' && x !== 'None' && x !== 'GuestsOrExternalUsers').map((id) => nm('user', id)),
    guests: incU.indexOf('GuestsOrExternalUsers') >= 0,
    groups: incG.map((id) => nm('group', id)), roles: incR.map((id) => nm('role', id)),
    exUsers: (u.excludeUsers || []).map((id) => nm('user', id)), exGroups: (u.excludeGroups || []).map((id) => nm('group', id)), exRoles: (u.excludeRoles || []).map((id) => nm('role', id)),
  };
  who.summary = who.kind === 'all' ? 'Everyone' : who.kind === 'none' ? 'Nobody (no principal included)'
    : [who.users.length ? plural(who.users.length, 'user') : '', who.groups.length ? plural(who.groups.length, 'group') : '', who.roles.length ? plural(who.roles.length, 'directory role') : '', who.guests ? 'guests' : ''].filter(Boolean).join(', ');
  const ex = who.exUsers.length + who.exGroups.length + who.exRoles.length;
  if (ex) who.summary += ' minus ' + plural(ex, 'exclusion');

  const a = c.applications || {};
  const incA = a.includeApplications || [], exA = a.excludeApplications || [], acts = a.includeUserActions || [];
  const what = {
    kind: incA.indexOf('All') >= 0 ? 'all' : acts.length ? 'actions' : (incA.indexOf('None') >= 0 || !incA.length) ? 'none' : 'apps',
    apps: incA.filter((x) => x !== 'All' && x !== 'None').map((id) => nm('app', id)),
    exApps: exA.map((id) => nm('app', id)), actions: acts.slice(),
  };
  what.summary = what.kind === 'all' ? 'All cloud apps' : what.kind === 'actions' ? 'User actions: ' + acts.join(', ') : what.kind === 'none' ? 'No apps' : what.apps.map((x) => x.name).join(', ');
  if (what.exApps.length) what.summary += ' minus ' + plural(what.exApps.length, 'app');

  const l = c.locations || null;
  const incL = l ? (l.includeLocations || []) : [], exL = l ? (l.excludeLocations || []) : [];
  const where = {
    kind: !l || !incL.length || (incL.indexOf('All') >= 0 && !exL.length) ? 'anywhere' : incL.indexOf('AllTrusted') >= 0 ? 'trusted' : incL.indexOf('All') >= 0 ? 'anywhere-except' : 'some',
    include: incL.filter((x) => x !== 'All' && x !== 'AllTrusted').map((id) => nm('loc', id)), exclude: exL.filter((x) => x !== 'AllTrusted').map((id) => nm('loc', id)), excludeTrusted: exL.indexOf('AllTrusted') >= 0,
  };
  where.summary = where.kind === 'anywhere' ? 'Anywhere' : where.kind === 'trusted' ? 'Trusted locations only' : where.kind === 'anywhere-except' ? 'Anywhere except ' + (where.exclude.map((x) => x.name).concat(where.excludeTrusted ? ['all trusted locations'] : []).join(', ') || '?')
    : 'Only ' + where.include.map((x) => x.name).join(', ') + (where.exclude.length ? ' minus ' + where.exclude.map((x) => x.name).join(', ') : '');

  const pl = c.platforms || null;
  const platforms = pl ? { include: (pl.includePlatforms || []).slice(), exclude: (pl.excludePlatforms || []).slice() } : null;
  const ca = c.clientAppTypes || [];
  const clientApps = !ca.length || ca.indexOf('all') >= 0 ? ALL_CLIENTS.slice() : uniq(ca);
  const dev = c.devices && c.devices.deviceFilter ? { mode: c.devices.deviceFilter.mode, rule: c.devices.deviceFilter.rule } : null;
  const flows = c.authenticationFlows && c.authenticationFlows.transferMethods ? String(c.authenticationFlows.transferMethods).split(',').map((x) => x.trim()).filter((x) => x && x !== 'none') : [];
  const controls = (g.builtInControls || []).slice();
  const strength = g.authenticationStrength && g.authenticationStrength.displayName ? g.authenticationStrength.displayName : null;
  const sf = s.signInFrequency && s.signInFrequency.isEnabled ? s.signInFrequency : null;
  const sfHours = sf ? (sf.frequencyInterval === 'everyTime' ? 0 : sf.type === 'days' ? (sf.value || 0) * 24 : (sf.value || 0)) : null;
  const sessionOnly = !controls.length && !strength && !!(sf || (s.persistentBrowser && s.persistentBrowser.isEnabled) || (s.cloudAppSecurity && s.cloudAppSecurity.isEnabled) || (s.applicationEnforcedRestrictions && s.applicationEnforcedRestrictions.isEnabled));
  const effect = controls.indexOf('block') >= 0 ? 'block' : (controls.length || strength) ? 'grant' : sessionOnly ? 'session' : 'none';
  const requiresMfa = controls.indexOf('mfa') >= 0 || !!strength;
  const requiresDevice = controls.indexOf('compliantDevice') >= 0 || controls.indexOf('domainJoinedDevice') >= 0;
  const controlText = controls.filter((x) => x !== 'block').map((x) => CONTROL_LABEL[x] || x).concat(strength ? ['authentication strength "' + strength + '"'] : []);
  const effectLabel = effect === 'block' ? 'Block' : effect === 'grant' ? 'Allow with ' + controlText.join((g.operator === 'AND' ? ' and ' : ' or ')) : effect === 'session' ? 'Allow (session controls only)' : 'No controls (allows as-is)';
  return {
    id: p.id, name: p.name, state: STATE_KEY[p.state] || p.state, stateRaw: p.state, stateLabel: STATE_LABEL[p.state] || p.state,
    inert: !!p.isInert, inertReason: p.inertReason || null, enforced: p.state === 'enabled' && !p.isInert,
    effect, effectLabel, controls, operator: g.operator || null, strength, requiresMfa, requiresDevice,
    who, what, where, platforms, clientApps, deviceFilter: dev, flows,
    signInRisk: (c.signInRiskLevels || []).slice(), userRisk: (c.userRiskLevels || []).slice(),
    session: { signInFrequencyHours: sfHours, everyTime: !!(sf && sf.frequencyInterval === 'everyTime'), persistentBrowser: s.persistentBrowser && s.persistentBrowser.isEnabled ? s.persistentBrowser.mode : null },
    collectedAt: p.collectedAt || null,
  };
}

/* ---------------------------------------------------------- normalise: Okta */

/**
 * policy: row from oem_okta_policy (rules parsed). ctx: { zone(id), oktaGroup(id), oktaUser(id), appByLabel(label) -> { oktaId, entra } }
 * Returns one entry per rule.
 */
function normOktaPolicy(policy, ctx) {
  const isApp = policy.type === 'ACCESS_POLICY';
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const shadowed = new Set((policy.shadowedRules || []).map((s) => lc(s.name || s)));
  const apps = isApp ? (policy.appNames || []).map((label) => { const r = ctx.appByLabel(label); return { label, oktaId: r ? r.oktaId : null, entra: r ? r.entra : null }; }) : [];
  const assignG = ((policy.assignments || {}).groups || []).map((g) => ({ id: g.id, name: g.name || g.id, source: g.name ? 'snapshot' : 'unresolved', count: g.count }));
  const assignEveryone = !isApp && (assignG.some((g) => lc(g.name) === 'everyone') || !assignG.length);
  return rules.map((r, i) => {
    const cond = r.conditions || {}, act = r.actions || {};
    const ap = act.appSignOn || null, so = act.signon || null;
    const people = cond.people || {};
    const pu = people.users || {}, pg = people.groups || {};
    const incU = (pu.include || []).map((id) => Object.assign({ id }, ctx.oktaUser(id)));
    const incG = (pg.include || []).map((id) => Object.assign({ id }, ctx.oktaGroup(id)));
    const exU = (pu.exclude || []).map((id) => Object.assign({ id }, ctx.oktaUser(id)));
    const exG = (pg.exclude || []).map((id) => Object.assign({ id }, ctx.oktaGroup(id)));
    const narrowed = incU.length || incG.length;
    const who = {
      kind: narrowed ? 'some' : (isApp || assignEveryone) ? 'all' : 'some',
      users: incU, groups: narrowed ? incG : (isApp ? [] : assignG.filter((g) => lc(g.name) !== 'everyone')), exUsers: exU, exGroups: exG,
      fromPolicyAssignment: !narrowed && !isApp,
    };
    who.summary = who.kind === 'all' ? (isApp ? 'Everyone assigned to the app' : 'Everyone') : [who.users.length ? plural(who.users.length, 'user') : '', who.groups.length ? (who.groups.length <= 3 ? who.groups.map((g) => g.name).join(', ') : plural(who.groups.length, 'group')) : ''].filter(Boolean).join(', ') || 'nobody';
    if (exU.length + exG.length) who.summary += ' minus ' + plural(exU.length + exG.length, 'exclusion');
    const net = cond.network || {};
    const zinc = (net.include || []).map((id) => Object.assign({ id }, ctx.zone(id))), zexc = (net.exclude || []).map((id) => Object.assign({ id }, ctx.zone(id)));
    const where = net.connection === 'ZONE' ? (zinc.length ? { kind: 'in-zones', zones: zinc } : { kind: 'not-in-zones', zones: zexc }) : { kind: 'anywhere', zones: [] };
    where.summary = where.kind === 'anywhere' ? 'Anywhere' : (where.kind === 'in-zones' ? 'Only from ' : 'Only when NOT in ') + where.zones.map((z) => z.name).join(', ');
    const dev = cond.device ? { registered: typeof cond.device.registered === 'boolean' ? cond.device.registered : null, managed: typeof cond.device.managed === 'boolean' ? cond.device.managed : null } : null;
    const plat = cond.platform && Array.isArray(cond.platform.include) && cond.platform.include.length ? uniq(cond.platform.include.map((x) => OKTA_OS_MAP[(x.os || {}).type] || lc((x.os || {}).type) || x.type).filter(Boolean)) : null;
    const o365 = cond.office365Client && Array.isArray(cond.office365Client.include) && cond.office365Client.include.length ? uniq(cond.office365Client.include.map((x) => OKTA_CLIENT_MAP[x] || x)) : null;
    const risk = cond.riskScore && cond.riskScore.level ? cond.riskScore.level : 'ANY';
    const access = ap ? ap.access : so ? so.access : null;
    const vm = ap && ap.verificationMethod ? ap.verificationMethod : null;
    const factor = vm ? vm.factorMode : so ? (so.requireFactor ? '2FA' : '1FA') : null;
    const cons = vm && Array.isArray(vm.constraints) ? vm.constraints : [];
    const deviceBound = cons.some((k) => k.possession && k.possession.deviceBound === 'REQUIRED');
    const reauthH = vm ? isoHours(vm.reauthenticateIn) : null;
    const sess = so && so.session ? so.session : null;
    const effect = access === 'DENY' ? 'block' : 'grant';
    const requiresMfa = effect === 'grant' && (factor === '2FA' || factor === '2FA_If_Possible');
    const ruleSummary = effect === 'block'
      ? 'Deny' + (where.kind === 'not-in-zones' ? ' when not in ' + where.zones.map((z) => z.name).join(', ') : where.kind === 'in-zones' ? ' from ' + where.zones.map((z) => z.name).join(', ') : '') + (dev && dev.managed === false ? ' on an unmanaged device' : dev && dev.registered === false ? ' on an unregistered device' : '') + (risk !== 'ANY' ? ' at ' + lc(risk) + ' risk' : '')
      : 'Allow' + (factor === '2FA' ? ' with a second factor' + (deviceBound ? ' (device-bound)' : '') : factor === '2FA_If_Possible' ? ' with a second factor if the user has one' : ' with password only') + (dev && dev.managed ? ' on a managed device' : dev && dev.registered ? ' on a registered device' : '') + (where.kind === 'in-zones' ? ' from ' + where.zones.map((z) => z.name).join(', ') : '') + (risk !== 'ANY' ? ' at ' + lc(risk) + ' risk' : '') + (reauthH !== null && reauthH > 0 && reauthH < 24 * 365 ? ', re-authenticate every ' + hoursText(reauthH) : reauthH === 0 ? ', re-authenticate every time' : '');
    return {
      key: policy.id + ':' + (r.id || i), policyId: policy.id, policyName: policy.name, policyType: isApp ? 'app' : 'session', policyPriority: policy.priority,
      rule: { id: r.id || null, name: r.name || ('Rule ' + (i + 1)), status: r.status || 'ACTIVE', priority: r.priority !== undefined ? r.priority : i + 1, system: !!r.system, shadowed: shadowed.has(lc(r.name)), lastUpdated: r.lastUpdated || null },
      active: policy.status === 'ACTIVE' && (r.status || 'ACTIVE') === 'ACTIVE',
      apps, appsKnown: isApp ? apps.filter((a) => a.entra).length : null, appsTotal: isApp ? apps.length : null,
      who, where, device: dev, platforms: plat, clientApps: o365, risk,
      effect, factor, deviceBound, requiresMfa,
      session: { reauthHours: reauthH, idleMinutes: sess ? sess.maxSessionIdleMinutes : null, lifetimeMinutes: sess ? sess.maxSessionLifetimeMinutes : null },
      summary: ruleSummary, collectedAt: policy.collectedAt || null,
    };
  });
}

/* ---------------------------------------------------------------- compare */

const W = { effect: 2, apps: 2, who: 1.5, where: 1.5, client: 1, device: 1, risk: 0.5, session: 0.5 };
const VAL = { match: 1, partial: 0.5, different: 0 };
/* A dimension where NEITHER side sets a condition (both "anyone / anywhere / any device") is weak evidence of a match,
 * so it carries a quarter of its weight (salient=false). Dimensions where at least one side has a condition carry full weight. */
const QUIET = 0.25;
const dim = (key, label, okta, entra, state, why, salient, extra) => Object.assign({ key, label, okta, entra, state, why, salient: salient !== false, oneSided: false, narrower: null }, extra || {});
/* the dimensions that decide WHEN a policy fires; a block that fires under different conditions is a different rule */
const TRIGGER = ['where', 'client', 'device', 'risk'];

/** ctx.zoneToLocs(zone) -> [{ id, name, trusted, by: 'coverage'|'name', covered, total }] */
function compareRule(o, e, ctx) {
  const dims = [];
  /* effect */
  {
    const oT = o.effect === 'block' ? 'Deny' : 'Allow with ' + (o.factor === '2FA' ? 'a second factor' : o.factor === '2FA_If_Possible' ? 'a second factor if enrolled' : 'password only');
    const eT = e.effectLabel;
    let st, why;
    if (o.effect === 'block' && e.effect === 'block') { st = 'match'; why = 'Both deny the sign-in.'; }
    else if (o.effect === 'block' && e.effect !== 'block') {
      if (o.device && o.device.managed === false && e.requiresDevice) { st = 'partial'; why = 'Okta denies unmanaged devices outright; Entra grants only to a compliant or joined device. Same intent, expressed as a grant condition.'; }
      else { st = 'different'; why = 'Okta denies; Entra allows (' + eT + ').'; }
    }
    else if (e.effect === 'block') { st = 'different'; why = 'Okta allows; Entra blocks.'; }
    else if (e.effect === 'none') { st = o.requiresMfa ? 'different' : 'partial'; why = 'The Entra policy carries no grant or session control, so it changes nothing' + (o.requiresMfa ? '; Okta requires a second factor.' : '.'); }
    else if (e.effect === 'session') { st = o.requiresMfa ? 'partial' : 'match'; why = o.requiresMfa ? 'Entra sets session controls only; Okta requires a second factor that Entra does not.' : 'Both allow without a second factor; Entra only adds session controls.'; }
    else if (o.requiresMfa && e.requiresMfa) { st = 'match'; why = 'Both require a second factor' + (o.deviceBound ? ' (Okta demands a device-bound authenticator; check the Entra authentication strength covers that)' : '') + '.'; }
    else if (o.requiresMfa && !e.requiresMfa) { st = 'partial'; why = 'Okta requires a second factor; Entra requires ' + (e.controls.map((c) => CONTROL_LABEL[c] || c).join(', ') || 'something else') + ' instead of MFA.'; }
    else if (!o.requiresMfa && e.requiresMfa) { st = 'partial'; why = 'Entra requires MFA that this Okta rule does not (stricter in Entra).'; }
    else { st = 'partial'; why = 'Both allow without MFA; Entra adds ' + e.controls.map((c) => CONTROL_LABEL[c] || c).join(', ') + '.'; }
    dims.push(dim('effect', 'Effect', oT + (o.deviceBound ? ' (device-bound)' : ''), eT, st, why));
  }
  /* apps */
  {
    if (o.policyType === 'session') {
      const st = e.what.kind === 'all' ? 'match' : e.what.kind === 'apps' ? 'partial' : 'different';
      dims.push(dim('apps', 'Applications', 'Every Okta sign-in (global session policy)', e.what.summary, st, st === 'match' ? 'Both apply to every sign-in.' : st === 'partial' ? 'Entra limits this to ' + plural(e.what.apps.length, 'app') + '; the Okta session policy applies to every sign-in.' : 'The Entra policy targets no application.', st !== 'match', { narrower: st === 'partial' ? 'entra' : null }));
    } else {
      const counterparts = o.apps.filter((a) => a.entra && a.entra.appId);
      const oT = o.apps.map((a) => a.label).join(', ') || 'no app assigned';
      if (e.what.kind === 'all') dims.push(dim('apps', 'Applications', oT, 'All cloud apps', 'partial', 'Entra applies to every cloud app; the Okta policy applies to ' + plural(o.apps.length, 'named app') + '. Broader in Entra.', true, { narrower: 'okta' }));
      else if (e.what.kind !== 'apps') dims.push(dim('apps', 'Applications', oT, e.what.summary, 'different', 'The Entra policy targets ' + (e.what.kind === 'actions' ? 'user actions, not applications.' : 'no application.')));
      else {
        const eIds = new Set(e.what.apps.map((x) => x.id));
        const exIds = new Set(e.what.exApps.map((x) => x.id));
        const o365 = eIds.has('Office365') && o.apps.some((a) => /office ?365|microsoft 365|o365/i.test(a.label));
        const hit = counterparts.filter((a) => eIds.has(a.entra.appId) && !exIds.has(a.entra.appId));
        const eT = e.what.summary;
        if (!counterparts.length && !o365) dims.push(dim('apps', 'Applications', oT, eT, 'unknown', 'None of the Okta apps has a confirmed or suggested Entra app yet, so application overlap cannot be judged. Match the apps on the Applications tab first.'));
        else if (o365 || hit.length === counterparts.length) dims.push(dim('apps', 'Applications', oT, eT, 'match', (o365 ? 'Okta Office 365 ↔ the Entra Office 365 app group. ' : '') + (hit.length ? hit.map((a) => a.label + ' → ' + a.entra.name + (a.entra.decision === 'manual_confirmed' ? '' : ' (' + a.entra.decision.replace(/_/g, ' ') + ')')).join('; ') + '. ' : '') + (counterparts.length < o.apps.length ? plural(o.apps.length - counterparts.length, 'Okta app') + ' in this policy still has no Entra app.' : '')));
        else if (hit.length) dims.push(dim('apps', 'Applications', oT, eT, 'partial', hit.map((a) => a.label + ' → ' + a.entra.name).join('; ') + ' overlap; ' + counterparts.filter((a) => !eIds.has(a.entra.appId)).map((a) => a.label).join(', ') + ' not in the Entra policy.', true, { narrower: 'entra' }));
        else dims.push(dim('apps', 'Applications', oT, eT, 'different', 'No application in common (' + counterparts.map((a) => a.label + ' → ' + a.entra.name).join('; ') + ' vs ' + e.what.apps.map((x) => x.name).join(', ') + ').'));
      }
    }
  }
  /* who */
  {
    const oT = o.who.summary, eT = e.who.summary;
    const og = o.who.groups.map((g) => groupKey(g.name)).filter(Boolean), eg = e.who.groups.map((g) => groupKey(g.name)).filter((k) => k && !/^[0-9a-f]{8}-/.test(k));
    const common = og.filter((k) => eg.indexOf(k) >= 0);
    const ou = o.who.users.map((u) => lc(u.login || u.name)).filter(Boolean), eu = e.who.users.map((u) => lc(u.upn || u.name)).filter(Boolean);
    const commonU = ou.filter((k) => eu.indexOf(k) >= 0);
    let st, why, quiet = false, narrower = null;
    if (e.who.kind === 'none') { st = 'different'; why = 'The Entra policy includes no one.'; }
    else if (o.who.kind === 'all' && e.who.kind === 'all') { st = 'match'; why = 'Both apply to everyone.'; quiet = true; }
    else if (o.who.kind === 'all') { st = 'partial'; narrower = 'entra'; why = 'Entra is narrower: ' + eT + '. The Okta rule applies to ' + (o.policyType === 'app' ? 'everyone assigned to the app.' : 'everyone.'); }
    else if (e.who.kind === 'all') { st = 'partial'; narrower = 'okta'; why = 'Entra is broader (everyone); the Okta rule applies to ' + oT + '.'; }
    else if ((common.length && common.length === uniq(og).length && common.length === uniq(eg).length) || (commonU.length && !og.length && !eg.length && commonU.length === uniq(ou).length && commonU.length === uniq(eu).length)) { st = 'match'; why = 'Same ' + (common.length ? 'group' + (common.length > 1 ? 's' : '') + ' by name: ' + o.who.groups.filter((g) => common.indexOf(groupKey(g.name)) >= 0).map((g) => g.name).join(', ') : 'users') + ' (name match — membership is not compared).'; }
    else if (common.length || commonU.length) { st = 'partial'; narrower = 'entra'; why = 'Some overlap by name (' + o.who.groups.filter((g) => common.indexOf(groupKey(g.name)) >= 0).map((g) => g.name).concat(o.who.users.filter((u) => commonU.indexOf(lc(u.login || u.name)) >= 0).map((u) => u.name || u.login)).join(', ') + '); the rest differs.'; }
    else { st = 'different'; why = 'No principal in common by name: Okta ' + oT + ' vs Entra ' + eT + '.'; }
    const exNote = (o.who.exUsers.length + o.who.exGroups.length) !== (e.who.exUsers.length + e.who.exGroups.length + e.who.exRoles.length) ? ' Exclusions differ (Okta ' + (o.who.exUsers.length + o.who.exGroups.length) + ', Entra ' + (e.who.exUsers.length + e.who.exGroups.length + e.who.exRoles.length) + ').' : '';
    dims.push(dim('who', 'Who', oT, eT, st, why + exNote, !quiet, { narrower }));
  }
  /* where */
  {
    const oT = o.where.summary, eT = e.where.summary;
    let st, why, quiet = false, narrower = null;
    const oneSided = (o.where.kind === 'anywhere') !== (e.where.kind === 'anywhere');
    const mapped = o.where.zones.map((z) => ({ zone: z, locs: ctx.zoneToLocs(z) }));
    const locNames = (ls) => ls.map((l) => l.name + (l.by === 'coverage' ? ' (' + l.covered + '/' + l.total + ' ranges)' : ' (by name)')).join(', ');
    if (o.where.kind === 'anywhere' && e.where.kind === 'anywhere') { st = 'match'; why = 'Neither side keys off the network.'; quiet = true; }
    else if (o.where.kind === 'anywhere') { st = 'partial'; narrower = 'entra'; why = 'Entra adds a location condition (' + eT + ') that the Okta rule does not have.'; }
    else if (e.where.kind === 'anywhere') { st = 'partial'; narrower = 'okta'; why = 'Okta keys off ' + o.where.zones.map((z) => z.name).join(', ') + '; the Entra policy has no location condition.' + (mapped.some((m) => m.locs.length) ? ' Entra locations that correspond: ' + mapped.map((m) => m.zone.name + ' → ' + locNames(m.locs)).join('; ') + '.' : ''); }
    else {
      // Okta "not in zones" == Entra "anywhere except"; Okta "in zones" == Entra "only these" (or "trusted" when the mapped locations are trusted)
      const eIds = new Set((o.where.kind === 'not-in-zones' ? e.where.exclude : e.where.include).map((l) => l.id));
      const sameShape = (o.where.kind === 'not-in-zones' && e.where.kind === 'anywhere-except') || (o.where.kind === 'in-zones' && (e.where.kind === 'some' || e.where.kind === 'trusted'));
      const hits = mapped.filter((m) => m.locs.some((l) => eIds.has(l.id) || (e.where.kind === 'trusted' && l.trusted)));
      const unmapped = mapped.filter((m) => !m.locs.length);
      if (!sameShape) { st = 'different'; why = 'Opposite shapes: Okta ' + (o.where.kind === 'not-in-zones' ? 'denies outside' : 'applies inside') + ' its zones; Entra ' + (e.where.kind === 'anywhere-except' ? 'excludes' : 'includes') + ' its locations.'; }
      else if (hits.length === mapped.length) { st = 'match'; why = 'Each Okta zone corresponds to a location the Entra policy uses: ' + hits.map((m) => m.zone.name + ' → ' + locNames(m.locs.filter((l) => eIds.has(l.id) || l.trusted))).join('; ') + '. Correspondence is by address coverage or by name — check the ranges on the Okta zones tab.'; }
      else if (hits.length) { st = 'partial'; why = hits.map((m) => m.zone.name + ' → ' + locNames(m.locs)).join('; ') + '; ' + mapped.filter((m) => hits.indexOf(m) < 0).map((m) => m.zone.name + (m.locs.length ? ' maps to ' + locNames(m.locs) + ', which this policy does not use' : ' has no Entra location')).join('; ') + '.'; }
      else { st = 'different'; why = (unmapped.length === mapped.length ? 'No Entra named location corresponds to ' + unmapped.map((m) => m.zone.name).join(', ') + ' (neither by address coverage nor by name).' : 'The Entra policy uses ' + (e.where.kind === 'anywhere-except' ? e.where.exclude : e.where.include).map((l) => l.name).join(', ') + ', not the locations that correspond to ' + mapped.map((m) => m.zone.name + ' (' + locNames(m.locs) + ')').join('; ') + '.'); }
      if (e.where.kind === 'trusted' && st !== 'different') why += ' Entra keys off the Trusted flag: only locations marked trusted satisfy it.';
    }
    dims.push(dim('where', 'Network', oT, eT, st, why, !quiet, { oneSided, narrower }));
  }
  /* client apps + platforms */
  {
    const oc = o.clientApps, ec = e.clientApps;
    const ocT = oc ? oc.map((x) => CLIENT_LABEL[x] || x).join(', ') : 'any client (no client condition)';
    const ecT = ec.length === ALL_CLIENTS.length ? 'all client types' : ec.map((x) => CLIENT_LABEL[x] || x).join(', ');
    let cSt, cWhy;
    const ecAll = ec.length === ALL_CLIENTS.length;
    if (e.flows.length) { cSt = 'different'; cWhy = 'The Entra policy applies only to the ' + e.flows.map((f) => f === 'deviceCodeFlow' ? 'device code flow' : f === 'authenticationTransfer' ? 'authentication transfer flow' : f).join(', ') + '; Okta has no equivalent condition, so this policy answers a different question.'; }
    else if (!oc && ecAll) { cSt = 'match'; cWhy = 'Neither side limits the client type.'; }
    else if (!oc) { cSt = 'partial'; cWhy = 'Entra limits this to ' + ecT + '; Okta does not.'; }
    else { const common = oc.filter((x) => ec.indexOf(x) >= 0); cSt = common.length === oc.length && common.length === ec.length ? 'match' : common.length ? 'partial' : 'different'; cWhy = cSt === 'match' ? 'Same client types.' : cSt === 'partial' ? 'Overlap on ' + common.map((x) => CLIENT_LABEL[x] || x).join(', ') + '; Okta ' + ocT + ' vs Entra ' + ecT + '.' : 'No client type in common (Okta ' + ocT + '; Entra ' + ecT + ').'; }
    const op = o.platforms, ep = e.platforms ? e.platforms.include.filter((x) => (e.platforms.exclude || []).indexOf(x) < 0) : null;
    const opT = op ? op.join(', ') : 'any platform', epT = e.platforms ? (ep.length ? ep.join(', ') : 'none (include cancelled by exclude)') + (e.platforms.exclude.length ? ' minus ' + e.platforms.exclude.join(', ') : '') : 'any platform';
    let pSt = null, pWhy = '';
    if (!op && !e.platforms) { pSt = 'match'; pWhy = ' Neither side limits the platform.'; }
    else if (!op) { pSt = 'partial'; pWhy = ' Entra limits the platform to ' + epT + '; Okta does not.'; }
    else if (!e.platforms) { pSt = 'partial'; pWhy = ' Okta limits the platform to ' + opT + '; Entra does not.'; }
    else { const common = op.filter((x) => ep.indexOf(x) >= 0); pSt = common.length === op.length && common.length === ep.length ? 'match' : common.length ? 'partial' : 'different'; pWhy = pSt === 'match' ? ' Same platforms.' : pSt === 'partial' ? ' Platforms overlap on ' + common.join(', ') + ' (Okta ' + opT + '; Entra ' + epT + ').' : ' No platform in common (Okta ' + opT + '; Entra ' + epT + ').'; }
    const order = { different: 0, partial: 1, match: 2 };
    const st = order[cSt] <= order[pSt] ? cSt : pSt;
    dims.push(dim('client', 'Client & platform', ocT + ' · ' + opT, ecT + ' · ' + epT, st, cWhy + pWhy, !(!oc && ecAll && !op && !e.platforms && !e.flows.length), { oneSided: (!oc) !== ecAll && !e.flows.length, narrower: (!oc && !ecAll) || (!op && !!e.platforms) ? 'entra' : (oc && ecAll) || (op && !e.platforms) ? 'okta' : null, flows: e.flows.slice() }));
  }
  /* device */
  {
    const od = o.device, oT = od ? (od.managed ? 'managed device' : od.managed === false ? 'unmanaged device' : '') + (od.registered ? (od.managed !== null ? ', ' : '') + 'registered' : od.registered === false ? (od.managed !== null ? ', ' : '') + 'not registered' : '') : 'no device condition';
    const eT = e.requiresDevice ? e.controls.filter((c) => /Device$/.test(c)).map((c) => CONTROL_LABEL[c]).join(' or ') : e.deviceFilter ? 'device filter (' + e.deviceFilter.mode + ': ' + e.deviceFilter.rule + ')' : 'no device requirement';
    let st, why, quiet = false;
    const oktaWantsManaged = od && (od.managed === true || (o.effect === 'block' && od.managed === false));
    const oktaWantsRegistered = od && !oktaWantsManaged && (od.registered === true || (o.effect === 'block' && od.registered === false));
    if (!od && !e.requiresDevice && !e.deviceFilter) { st = 'match'; why = 'Neither side looks at the device.'; quiet = true; }
    else if (oktaWantsManaged && e.requiresDevice) { st = 'match'; why = 'Okta management ↔ Entra device compliance / join (different systems judge it: Okta Verify + Kandji/Intune vs Intune compliance).'; }
    else if (oktaWantsManaged && e.deviceFilter) { st = 'partial'; why = 'Okta wants a managed device; Entra uses a device filter rather than the compliance control.'; }
    else if (oktaWantsRegistered && (e.requiresDevice || e.deviceFilter)) { st = 'partial'; why = 'Okta only needs a registered device; Entra demands compliance / join — stricter.'; }
    else if (od && !e.requiresDevice && !e.deviceFilter) { st = 'partial'; why = 'Okta looks at the device (' + oT + '); the Entra policy has no device requirement.'; }
    else if (!od) { st = 'partial'; why = 'Entra adds a device requirement (' + eT + ') that the Okta rule does not have.'; }
    else { st = 'partial'; why = 'Both look at the device but differently: Okta ' + oT + '; Entra ' + eT + '.'; }
    dims.push(dim('device', 'Device', oT, eT, st, why, !quiet, { oneSided: (!od) !== (!e.requiresDevice && !e.deviceFilter) }));
  }
  /* risk */
  {
    const or = o.risk, er = e.signInRisk.map(lc);
    const oT = or === 'ANY' ? 'any risk level' : lc(or) + ' risk', eT = er.length ? 'sign-in risk ' + er.join(', ') : (e.userRisk.length ? 'user risk ' + e.userRisk.join(', ') : 'any risk level');
    let st, why, quiet = false;
    const eAny = !er.length && !e.userRisk.length;
    if (or === 'ANY' && eAny) { st = 'match'; why = 'Neither side keys off risk.'; quiet = true; }
    else if (or === 'ANY') { st = 'partial'; why = 'Entra applies only at ' + eT + '; Okta applies at any risk.'; }
    else if (!er.length) { st = 'partial'; why = 'Okta applies only at ' + oT + '; Entra does not look at sign-in risk.'; }
    else { st = er.indexOf(lc(or)) >= 0 ? (er.length === 1 ? 'match' : 'partial') : 'different'; why = st === 'match' ? 'Same risk level.' : st === 'partial' ? 'Entra covers ' + er.join(', ') + '; Okta only ' + lc(or) + '.' : 'Risk levels differ (Okta ' + lc(or) + '; Entra ' + er.join(', ') + '). Okta and Entra also score risk differently.'; }
    dims.push(dim('risk', 'Risk', oT, eT, st, why, !quiet, { oneSided: (or === 'ANY') !== eAny, narrower: or === 'ANY' && !eAny ? 'entra' : or !== 'ANY' && eAny ? 'okta' : null }));
  }
  /* session */
  {
    const oh = o.session.reauthHours !== null ? o.session.reauthHours : (o.session.lifetimeMinutes ? o.session.lifetimeMinutes / 60 : o.session.idleMinutes ? o.session.idleMinutes / 60 : null);
    const oT = o.session.reauthHours !== null ? 're-authenticate: ' + hoursText(o.session.reauthHours) : o.session.lifetimeMinutes || o.session.idleMinutes ? 'session ' + (o.session.lifetimeMinutes ? 'lifetime ' + hoursText(o.session.lifetimeMinutes / 60) : '') + (o.session.idleMinutes ? (o.session.lifetimeMinutes ? ', ' : '') + 'idle ' + hoursText(o.session.idleMinutes / 60) : '') : 'no session setting';
    const eh = e.session.signInFrequencyHours;
    const eT = eh !== null ? 'sign-in frequency: ' + hoursText(eh) : 'no sign-in frequency';
    let st, why;
    const oNever = oh !== null && oh >= 24 * 365;
    if ((oh === null || oNever) && eh === null) { st = 'unknown'; why = 'Neither side sets a re-authentication interval (Okta ' + oT + ').'; }
    else if (oh === null || oNever) { st = 'partial'; why = 'Entra re-prompts every ' + hoursText(eh) + '; the Okta rule ' + (oNever ? 'never re-authenticates' : 'sets no interval') + '.'; }
    else if (eh === null) { st = 'partial'; why = 'Okta re-prompts (' + oT + '); the Entra policy sets no sign-in frequency.'; }
    else if (Math.abs(oh - eh) < 0.01) { st = 'match'; why = 'Same interval.'; }
    else { st = 'partial'; why = 'Intervals differ: Okta ' + hoursText(oh) + ', Entra ' + hoursText(eh) + '.'; }
    dims.push(dim('session', 'Session', oT, eT, st, why));
  }
  let num = 0, den = 0;
  dims.forEach((d) => { if (d.state === 'unknown') return; const w = W[d.key] * (d.salient ? 1 : QUIET); num += w * VAL[d.state]; den += w; });
  const score = den ? num / den : 0;
  const eff = dims[0].state, appsD = dims[1];
  /* a trigger dimension mismatches when it differs outright, or — for a block — when only one side has the condition
   * (a block that fires everywhere is not the same rule as a block that fires off-network) */
  const triggerDiff = dims.filter((d) => TRIGGER.indexOf(d.key) >= 0 && d.salient && (d.state === 'different' || (o.effect === 'block' && d.oneSided))).map((d) => d.label);
  const cap = { close: 3, partial: 2, loose: 1, none: 0 };
  let verdict = score >= 0.8 ? 'close' : score >= 0.5 ? 'partial' : score >= 0.25 ? 'loose' : 'none';
  const limit = (v) => { if (cap[verdict] > cap[v]) verdict = v; };
  const caps = [];
  if (eff === 'different' && verdict !== 'none') { limit('loose'); caps.push('the effect differs'); }
  if (appsD.state === 'different') { limit('partial'); caps.push('no application in common'); }
  if (triggerDiff.length) { limit(o.effect === 'block' ? 'loose' : 'partial'); caps.push('fires under a different ' + triggerDiff.join(' / ').toLowerCase() + ' condition'); }
  /* covers = the Entra policy would actually stand in for the Okta rule (right apps, same effect family, same trigger).
   * Whether it is ENFORCED is a separate question answered from the policy state. */
  const covers = (verdict === 'close' || verdict === 'partial') && eff !== 'different' && (appsD.state === 'match' || appsD.state === 'partial') && !triggerDiff.length;
  /* coversFully = additionally the same effect and Entra at least as broad on who / apps / network / client / risk — the only basis for calling an Okta rule REPLACED */
  const narrowerIn = dims.filter((d) => ['apps', 'who', 'where', 'client', 'risk'].indexOf(d.key) >= 0 && d.narrower === 'entra').map((d) => d.label.toLowerCase());
  const coversFully = covers && eff === 'match' && !narrowerIn.length;
  return { score: Math.round(score * 100) / 100, verdict, covers, coversFully, narrowerIn, capNote: caps.length ? 'Verdict capped at ' + VERDICT_LABEL[verdict].toLowerCase() + ': ' + caps.join('; ') + '.' : '', dims };
}

const VERDICT_LABEL = { close: 'Close match', partial: 'Partial match', loose: 'Loosely related', none: 'No counterpart' };

/* ------------------------------------------------------------ build report */

async function buildReport(opts = {}) {
  const [caRows] = await pool.query(`SELECT * FROM oem_entra_ca`);
  const [polRows] = await pool.query(`SELECT * FROM oem_okta_policy WHERE policy_type IN ('ACCESS_POLICY','OKTA_SIGN_ON')`);
  const [zoneRows] = await pool.query(`SELECT zone_id, name, zone_type, status, usage_kind, entry_count, cidrs, countries FROM oem_okta_zone`);
  const [locRows] = await pool.query(`SELECT loc_id, display_name, loc_type, is_trusted, cidrs, countries FROM oem_entra_named_location`);
  const [parRows] = await pool.query(`SELECT okta_zone, cidr, kind, entra_location, entra_trusted FROM oem_zone_parity WHERE okta_zone IS NOT NULL AND okta_zone<>'(none)'`);
  const [appRows] = await pool.query(`SELECT okta_id, label FROM okta_apps`);
  const [entraApps] = await pool.query(`SELECT entra_id, app_id, display_name FROM entra_apps`);
  const [matchRows] = await pool.query(`SELECT okta_app_id, entra_app_id, match_confidence FROM app_matches WHERE entra_app_id IS NOT NULL AND match_confidence IN ('manual_confirmed','manual_staged','auto_high','auto_medium','auto_low')`);
  const [markRows] = await pool.query(`SELECT okta_id, entra_id, entra_name FROM oem_app_migrated WHERE cleared_at IS NULL`);

  const ca = caRows.map((r) => ({ id: r.ca_id, name: r.display_name, state: r.state, conditions: j(r.conditions, {}), grantControls: j(r.grant_controls, {}), sessionControls: j(r.session_controls, {}), isInert: !!r.is_inert, inertReason: r.inert_reason, collectedAt: r.collected_at }));
  const pols = polRows.map((r) => ({ id: r.policy_id, type: r.policy_type, name: r.name, status: r.status, priority: r.priority, assignments: j(r.assignments, {}), rules: j(r.rules, []), appNames: j(r.app_names, []), shadowedRules: j(r.shadowed_rules, []), collectedAt: r.collected_at }));

  /* ids referenced by the Entra policies -> mirror lookups */
  const ids = { user: new Set(), group: new Set(), app: new Set(), role: new Set(), loc: new Set() };
  ca.forEach((p) => { const c = p.conditions || {}; const u = c.users || {}, a = c.applications || {}, l = c.locations || {};
    [].concat(u.includeUsers || [], u.excludeUsers || []).forEach((x) => ids.user.add(x)); [].concat(u.includeGroups || [], u.excludeGroups || []).forEach((x) => ids.group.add(x)); [].concat(u.includeRoles || [], u.excludeRoles || []).forEach((x) => ids.role.add(x));
    [].concat(a.includeApplications || [], a.excludeApplications || []).forEach((x) => ids.app.add(x)); [].concat(l.includeLocations || [], l.excludeLocations || []).forEach((x) => ids.loc.add(x)); });
  const guid = (x) => /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(x);
  const userIds = [...ids.user].filter(guid), groupIds = [...ids.group].filter(guid);
  const [uRows] = userIds.length ? await pool.query(`SELECT entra_id, display_name, user_principal_name FROM entra_users WHERE entra_id IN (?)`, [userIds]) : [[]];
  const [gRows] = groupIds.length ? await pool.query(`SELECT entra_id, display_name FROM entra_groups WHERE entra_id IN (?)`, [groupIds]) : [[]];
  const userBy = new Map(uRows.map((r) => [r.entra_id, r])), groupBy = new Map(gRows.map((r) => [r.entra_id, r]));
  const appByAppId = new Map(entraApps.map((r) => [r.app_id, r])), appByObj = new Map(entraApps.map((r) => [r.entra_id, r]));
  const locBy = new Map(locRows.map((r) => [r.loc_id, r]));
  const unresolved = { user: 0, group: 0, app: 0, role: 0, loc: 0, oktaGroup: 0, oktaUser: 0 };
  const names = {
    user: (id) => { const r = userBy.get(id); if (r) return { name: r.display_name || r.user_principal_name, upn: r.user_principal_name, source: 'mirror' }; if (!guid(id)) return { name: id, source: 'builtin' }; unresolved.user++; return { name: id, source: 'unresolved' }; },
    group: (id) => { const r = groupBy.get(id); if (r) return { name: r.display_name, source: 'mirror' }; unresolved.group++; return { name: id, source: 'unresolved' }; },
    role: (id) => ({ name: ROLE_NAMES[id] || id, source: ROLE_NAMES[id] ? 'builtin' : 'unresolved' }),
    app: (id) => { if (CA_APP_ALIAS[id]) return { name: CA_APP_ALIAS[id], source: 'builtin' }; const r = appByAppId.get(id); if (r) return { name: r.display_name, entraId: r.entra_id, source: 'mirror' }; unresolved.app++; return { name: id, source: 'unresolved' }; },
    loc: (id) => { const r = locBy.get(id); if (r) return { name: r.display_name, trusted: r.is_trusted === null ? null : !!r.is_trusted, source: 'mirror' }; unresolved.loc++; return { name: id, source: 'unresolved' }; },
  };
  const entra = ca.map((p) => normEntra(p, names));
  entra.forEach((e) => { e.who.users.forEach((u) => { const r = userBy.get(u.id); if (r) u.upn = r.user_principal_name; }); e.what.apps.forEach((a) => { const r = appByAppId.get(a.id); if (r) a.entraId = r.entra_id; }); e.where.include.concat(e.where.exclude).forEach((l) => { const r = locBy.get(l.id); if (r) l.trusted = r.is_trusted === null ? null : !!r.is_trusted; }); });

  /* Okta side: app label -> okta id -> Entra app (decision), zone ids, group/user names */
  const oktaIdByLabel = new Map(appRows.map((r) => [lc(r.label), r.okta_id]));
  const RANK = { manual_confirmed: 5, manual_staged: 4, auto_high: 3, auto_medium: 2, auto_low: 1 };
  const decision = new Map();
  matchRows.forEach((m) => { const cur = decision.get(m.okta_app_id); if (!cur || RANK[m.match_confidence] > RANK[cur.match_confidence]) decision.set(m.okta_app_id, m); });
  markRows.forEach((m) => { if (m.entra_id) decision.set(m.okta_id, { okta_app_id: m.okta_id, entra_app_id: m.entra_id, match_confidence: 'marked_migrated' }); });
  const appByLabel = (label) => {
    const oktaId = oktaIdByLabel.get(lc(label)); if (!oktaId) return null;
    const d = decision.get(oktaId); const e = d ? appByObj.get(d.entra_app_id) : null;
    return { oktaId, entra: e ? { entraId: e.entra_id, appId: e.app_id, name: e.display_name, decision: d.match_confidence } : null };
  };
  const zoneBy = new Map(zoneRows.map((r) => [r.zone_id, r]));
  const oktaGroupIds = new Set(), oktaUserIds = new Set();
  pols.forEach((p) => (p.rules || []).forEach((r) => { const pe = (r.conditions || {}).people || {}; [].concat((pe.groups || {}).include || [], (pe.groups || {}).exclude || []).forEach((x) => oktaGroupIds.add(x)); [].concat((pe.users || {}).include || [], (pe.users || {}).exclude || []).forEach((x) => oktaUserIds.add(x)); }));
  const [ouRows] = oktaUserIds.size ? await pool.query(`SELECT okta_id, login, first_name, last_name FROM okta_users WHERE okta_id IN (?)`, [[...oktaUserIds]]) : [[]];
  const ouBy = new Map(ouRows.map((r) => [r.okta_id, r]));
  const knownGroups = new Map();
  pols.forEach((p) => ((p.assignments || {}).groups || []).forEach((g) => { if (g.id && g.name) knownGroups.set(g.id, g.name); }));
  const liveGroups = opts.noLive ? new Map() : await resolveOktaGroups([...oktaGroupIds].filter((id) => !knownGroups.has(id)));
  const ctx = {
    appByLabel,
    zone: (id) => { const z = zoneBy.get(id); return z ? { name: z.name, type: z.zone_type, status: z.status, source: 'mirror' } : { name: id, type: null, status: null, source: 'unresolved' }; },
    oktaGroup: (id) => { if (knownGroups.has(id)) return { name: knownGroups.get(id), source: 'snapshot' }; if (liveGroups.has(id)) return { name: liveGroups.get(id), source: 'okta-live' }; unresolved.oktaGroup++; return { name: id, source: 'unresolved' }; },
    oktaUser: (id) => { const r = ouBy.get(id); if (r) return { name: [r.first_name, r.last_name].filter(Boolean).join(' ') || r.login, login: r.login, source: 'mirror' }; unresolved.oktaUser++; return { name: id, login: null, source: 'unresolved' }; },
  };
  const okta = [];
  pols.forEach((p) => normOktaPolicy(p, ctx).forEach((r) => okta.push(r)));

  /* zone -> Entra locations: by address coverage (parity) first, then by name */
  const covBy = new Map();
  parRows.forEach((r) => { if (!r.entra_location) return; const k = r.okta_zone + '|' + r.entra_location; covBy.set(k, (covBy.get(k) || 0) + 1); });
  const zoneTotal = new Map(); parRows.forEach((r) => zoneTotal.set(r.okta_zone, (zoneTotal.get(r.okta_zone) || 0) + 1));
  const locByName = new Map(locRows.map((r) => [lc(r.display_name), r]));
  const nameKey = (s) => lc(s).replace(/\b(ip|zone|zones|list|policy|access|locations?|block)\b/g, '').replace(/[^a-z0-9]+/g, '');
  const zoneMap = {};
  const zoneToLocs = (z) => {
    if (zoneMap[z.name]) return zoneMap[z.name];
    const out = [];
    covBy.forEach((n, k) => { const [zn, ln] = k.split('|'); if (zn !== z.name) return; const l = locByName.get(lc(ln)); out.push({ id: l ? l.loc_id : ln, name: ln, trusted: l ? (l.is_trusted === null ? null : !!l.is_trusted) : null, by: 'coverage', covered: n, total: zoneTotal.get(z.name) || n }); });
    const zk = nameKey(z.name);
    if (zk) locRows.forEach((l) => { const lk = nameKey(l.display_name); if (lk && (lk === zk || (zk.length >= 4 && lk.indexOf(zk) >= 0) || (lk.length >= 4 && zk.indexOf(lk) >= 0)) && !out.some((o) => o.id === l.loc_id)) out.push({ id: l.loc_id, name: l.display_name, trusted: l.is_trusted === null ? null : !!l.is_trusted, by: 'name', covered: null, total: zoneTotal.get(z.name) || null }); });
    zoneMap[z.name] = out; return out;
  };
  const cctx = { zoneToLocs };
  zoneRows.forEach((z) => zoneToLocs({ name: z.name }));

  /* compare every Okta rule with every Entra policy; keep the ranked list per side */
  const pairs = new Map();
  okta.forEach((o) => { entra.forEach((e) => { pairs.set(o.key + '|' + e.id, compareRule(o, e, cctx)); }); });
  const VR = { close: 3, partial: 2, loose: 1, none: 0 };
  const rank = (a, b) => (VR[b.verdict] - VR[a.verdict]) || (b.score - a.score) || ((b.enforced ? 1 : 0) - (a.enforced ? 1 : 0)) || String(a.name || a.ruleName).localeCompare(String(b.name || b.ruleName));
  okta.forEach((o) => {
    const list = entra.map((e) => { const r = pairs.get(o.key + '|' + e.id); return { id: e.id, name: e.name, state: e.state, stateLabel: e.stateLabel, enforced: e.enforced, inert: e.inert, effect: e.effect, effectLabel: e.effectLabel, score: r.score, verdict: r.verdict, verdictLabel: VERDICT_LABEL[r.verdict], covers: r.covers, coversFully: r.coversFully, narrowerIn: r.narrowerIn }; }).sort(rank);
    o.candidates = list.filter((c) => c.verdict !== 'none').slice(0, 5);
    o.best = o.candidates[0] || null;
    /* coverage — only a policy that COVERS the rule (see compareRule) counts:
     *   enforced = an enabled, non-inert policy covers it fully; partial = an enabled, non-inert policy covers it but is narrower (who / apps / network / client / risk);
     *   report | disabled | inert = the best covering policy is not enforced; none = nothing covers it. */
    const covering = list.filter((c) => c.covers);
    const enforcedFull = covering.find((c) => c.enforced && c.coversFully) || null;
    const enforcedPart = covering.find((c) => c.enforced) || null;
    const otherBest = covering[0] || null;
    o.coverage = enforcedFull ? 'enforced' : enforcedPart ? 'partial' : otherBest ? (otherBest.state === 'report' ? 'report' : otherBest.state === 'disabled' ? 'disabled' : 'inert') : 'none';
    o.coverageBy = enforcedFull || enforcedPart || otherBest;
    o.coverageNote = o.coverage === 'partial' ? 'Enforced in Entra for part of the scope only — narrower in ' + (enforcedPart.narrowerIn || []).join(', ') + '.' : o.coverage === 'none' ? (o.best ? 'Nearest Entra policy: ' + o.best.name + ' (' + o.best.verdictLabel.toLowerCase() + ').' : 'No Entra policy resembles this rule.') : '';
  });
  entra.forEach((e) => {
    const list = okta.map((o) => { const r = pairs.get(o.key + '|' + e.id); return { key: o.key, policyName: o.policyName, ruleName: o.rule.name, policyType: o.policyType, active: o.active, effect: o.effect, summary: o.summary, score: r.score, verdict: r.verdict, verdictLabel: VERDICT_LABEL[r.verdict] }; }).sort((a, b) => (VR[b.verdict] - VR[a.verdict]) || (b.score - a.score) || ((b.active ? 1 : 0) - (a.active ? 1 : 0)) || a.policyName.localeCompare(b.policyName));
    e.candidates = list.filter((c) => c.verdict !== 'none').slice(0, 5);
    e.best = e.candidates[0] || null;
  });

  const activeOkta = okta.filter((o) => o.active);
  const summary = {
    entra: { total: entra.length, enforced: entra.filter((e) => e.state === 'enforced').length, report: entra.filter((e) => e.state === 'report').length, disabled: entra.filter((e) => e.state === 'disabled').length, inert: entra.filter((e) => e.inert).length, block: entra.filter((e) => e.effect === 'block').length, grant: entra.filter((e) => e.effect === 'grant').length, session: entra.filter((e) => e.effect === 'session').length, withCounterpart: entra.filter((e) => e.best).length, withoutCounterpart: entra.filter((e) => !e.best).length },
    okta: { policies: pols.length, appPolicies: pols.filter((p) => p.type === 'ACCESS_POLICY').length, sessionPolicies: pols.filter((p) => p.type === 'OKTA_SIGN_ON').length, rules: okta.length, activeRules: activeOkta.length, block: activeOkta.filter((o) => o.effect === 'block').length, mfa: activeOkta.filter((o) => o.effect === 'grant' && o.requiresMfa).length, passwordOnly: activeOkta.filter((o) => o.effect === 'grant' && !o.requiresMfa).length,
      coverage: { enforced: activeOkta.filter((o) => o.coverage === 'enforced').length, partial: activeOkta.filter((o) => o.coverage === 'partial').length, report: activeOkta.filter((o) => o.coverage === 'report').length, disabled: activeOkta.filter((o) => o.coverage === 'disabled').length, inert: activeOkta.filter((o) => o.coverage === 'inert').length, none: activeOkta.filter((o) => o.coverage === 'none').length } },
    unresolved,
  };
  const collectedAt = { entra: ca.reduce((m, p) => (!m || (p.collectedAt && p.collectedAt > m) ? p.collectedAt : m), null), okta: pols.reduce((m, p) => (!m || (p.collectedAt && p.collectedAt > m) ? p.collectedAt : m), null) };
  return { collectedAt, summary, entra, okta, zoneMap, pairs: Object.fromEntries(pairs), readOnly: true,
    note: 'Compared from the last policy snapshot. Nothing on this view writes to Okta or Entra. A report-only or disabled Entra policy enforces nothing and is never counted as a replacement.' };
}

/* Directory role template ids that appear in Conditional Access policies. */
const ROLE_NAMES = { '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': 'Conditional Access Administrator', '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator', 'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator', 'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator', '729827e3-9c14-49f7-bb1b-9608f156bbb8': 'Helpdesk Administrator', 'c4e39bd9-1100-46d3-8c65-fb160da0071f': 'Authentication Administrator', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator', '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator', '966707d0-3269-4727-9be2-8c3a10f19b9d': 'Password Administrator', 'f2ef992c-3afb-46b9-b7cf-a126ee74c451': 'Global Reader' };

/* Okta group names the mirror does not hold: capped, cached, read-only. */
const groupCache = new Map(); // id -> { name, at }
const GROUP_TTL = 6 * 3600 * 1000, GROUP_CAP = 25;
async function resolveOktaGroups(ids) {
  const out = new Map(); let calls = 0;
  for (const id of ids) {
    const c = groupCache.get(id);
    if (c && Date.now() - c.at < GROUP_TTL) { if (c.name) out.set(id, c.name); continue; }
    if (calls >= GROUP_CAP) break;
    calls++;
    try { const r = await L.oktaGet('/api/v1/groups/' + encodeURIComponent(id)); const name = r && r.body && r.body.profile ? r.body.profile.name : null; groupCache.set(id, { name, at: Date.now() }); if (name) out.set(id, name); }
    catch (e) { groupCache.set(id, { name: null, at: Date.now() }); }
  }
  return out;
}

/* ----------------------------------------------------------------- routes */

// GET /api/oem/ca/compare — the full comparison (read-only; snapshot + mirrors + capped Okta group-name reads)
/* The page gets the pair comparisons it can reach (each side's candidates); every pair is available with ?full=1.
   With ~90 Okta rules × 14 Entra policies the full matrix is ~1,300 comparisons and dwarfs the rest of the report. */
function trimPairs(R) {
  const keep = new Set();
  R.okta.forEach((o) => (o.candidates || []).forEach((c) => keep.add(o.key + '|' + c.id)));
  R.entra.forEach((e) => (e.candidates || []).forEach((c) => keep.add(c.key + '|' + e.id)));
  const pairs = {};
  keep.forEach((k) => { if (R.pairs[k]) pairs[k] = R.pairs[k]; });
  return Object.assign({}, R, { pairs, pairsNote: 'pairs holds the comparisons for each side\'s candidates (' + keep.size + ' of ' + Object.keys(R.pairs).length + '); ?full=1 returns every pair.' });
}
router.get('/compare', read(), async (req, res) => {
  try {
    const R = await buildReport({ noLive: req.query.noLive === '1' });
    res.json(req.query.full === '1' ? R : trimPairs(R));
  } catch (e) { res.status(500).json({ error: 'ca/compare: ' + (e && e.message ? e.message : String(e)) }); }
});

module.exports = router;
module.exports._internal = { normEntra, normOktaPolicy, compareRule, isoHours, hoursText, groupKey, buildReport, trimPairs, VERDICT_LABEL, W };
