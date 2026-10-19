#!/usr/bin/env node
/**
 * collect-okta-entra.js — snapshot collector for the Okta -> Entra migration workspace.
 *
 * Writes oem_* only. Overlaps collect-ca-policies.js (which fills sentinel_ca_policy at
 * 03:20) on CA policies alone; this one is kept self-contained because it needs the full
 * conditions blob and the named locations in the same pass to compute parity, and because
 * the migration page should not break if the sentinel schema moves.
 *
 * Reads: Okta /api/v1/policies (+ rules per policy), /groups, /zones, /apps
 *        Graph  /identity/conditionalAccess/{policies,namedLocations}
 * Also records which Graph app roles the credential actually holds, from the token's own
 * roles claim. That is what the page's "Claude can automate" labels are derived from, so
 * a label can never claim an ability we do not have.
 *
 * Cron: 15 4 * * *  -> /var/log/collect-okta-entra.log
 */
'use strict';
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');
const dns = require('dns').promises;
const net = require('./oem-net.js');

const OKTA_BASE = (process.env.OKTA_BASE_URL || '').replace(/\/+$/, '');
const OKTA_TOKEN = process.env.OKTA_API_TOKEN;
const POLICY_TYPES = ['OKTA_SIGN_ON', 'ACCESS_POLICY', 'MFA_ENROLL', 'PASSWORD',
                      'IDP_DISCOVERY', 'PROFILE_ENROLLMENT', 'USER_LIFECYCLE'];

/** The three anchored SIPA egress addresses. Facts about them are computed, not asserted. */
const SIPA_IPS = [
  { ip: '64.58.136.121', label: 'SNA01 office egress', site: 'SNA01', carrier: 'Cox Communications', connectorGroup: 'SNA01-Connector Group' },
  { ip: '64.58.136.122', label: 'SNA01 office egress', site: 'SNA01', carrier: 'Cox Communications', connectorGroup: 'SNA01-Connector Group' },
  { ip: '34.223.75.130', label: 'AWS us-west-2 connector egress', site: 'AWS us-west-2', carrier: 'Amazon AWS', connectorGroup: 'AWS-W2 App Connector Group' },
];

const log = (...a) => console.log(new Date().toISOString(), ...a);
const warns = [];
const warn = (m) => { warns.push(m); console.error(new Date().toISOString(), 'WARN', m); };

/* ------------------------------------------------------------------ okta */

async function oktaGet(path) {
  const url = path.startsWith('http') ? path : OKTA_BASE + path;
  const r = await fetch(url, {
    headers: { Authorization: 'SSWS ' + OKTA_TOKEN, Accept: 'application/json' },
  });
  if (!r.ok) throw new Error(`Okta ${r.status} on ${url.replace(OKTA_BASE, '')}: ${(await r.text()).slice(0, 300)}`);
  const link = r.headers.get('link') || '';
  const nextM = link.split(',').find((s) => s.includes('rel="next"'));
  const next = nextM ? (nextM.match(/<([^>]+)>/) || [])[1] : null;
  return { body: await r.json(), next };
}

async function oktaAll(path) {
  const out = [];
  let cur = path;
  let guard = 0;
  while (cur && guard++ < 60) {
    const { body, next } = await oktaGet(cur);
    if (Array.isArray(body)) out.push(...body); else out.push(body);
    cur = next;
  }
  return out;
}

/* ----------------------------------------------------------------- graph */

/** Returns { token, roles } — roles is the app-permission list actually consented. */
async function getGraphToken() {
  const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.ENTRA_CLIENT_ID,
      client_secret: process.env.ENTRA_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('Graph token fetch failed: ' + (j.error_description || JSON.stringify(j)).slice(0, 200));
  let roles = [];
  try {
    const claims = JSON.parse(Buffer.from(j.access_token.split('.')[1], 'base64').toString('utf8'));
    roles = claims.roles || [];
  } catch (e) { warn('could not decode roles claim: ' + e.message); }
  return { token: j.access_token, roles };
}

async function graphAll(token, path) {
  const out = [];
  let url = 'https://graph.microsoft.com/v1.0' + path;
  let guard = 0;
  while (url && guard++ < 40) {
    const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error(`Graph ${r.status} on ${path}: ${(await r.text()).slice(0, 300)}`);
    const j = await r.json();
    out.push(...(j.value || [j]));
    url = j['@odata.nextLink'] || null;
  }
  return out;
}

/**
 * Sample the MFA claim rate. authenticationRequirement is a beta-only property, and the
 * local sign-in mirror does not carry it, so this is the only way to measure the gap.
 * Both event types are sampled: judging blast radius from interactive sign-ins alone
 * leaves out every service account and device flow.
 */
async function sampleMfaClaim(token) {
  const out = { measured_at: new Date().toISOString(), interactive: null, non_interactive: null, error: null };
  const one = async (evt) => {
    const url = 'https://graph.microsoft.com/beta/auditLogs/signIns'
      + '?$top=500&$filter=' + encodeURIComponent(`signInEventTypes/any(t:t eq '${evt}')`);
    const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error(`${r.status} ${evt}`);
    const j = await r.json();
    const tally = { single: 0, multi: 0, other: 0 };
    for (const x of (j.value || [])) {
      if ((x.status || {}).errorCode !== 0) continue;
      const a = x.authenticationRequirement;
      if (a === 'singleFactorAuthentication') tally.single++;
      else if (a === 'multiFactorAuthentication') tally.multi++;
      else tally.other++;
    }
    const total = tally.single + tally.multi + tally.other;
    return Object.assign(tally, { total, single_pct: total ? +(100 * tally.single / total).toFixed(1) : null });
  };
  try { out.interactive = await one('interactiveUser'); } catch (e) { out.error = e.message; }
  try { out.non_interactive = await one('nonInteractiveUser'); } catch (e) { out.error = (out.error ? out.error + '; ' : '') + e.message; }
  return out;
}

/** Registration coverage, from the authentication-methods report. Reports.Read.All is consented. */
async function sampleRegistration(token) {
  const out = { measured_at: new Date().toISOString(), total: 0, mfa_registered: 0,
                passwordless: 0, phishing_resistant: 0, by_method: {}, error: null };
  try {
    let url = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999';
    let guard = 0;
    while (url && guard++ < 20) {
      const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
      if (!r.ok) throw new Error(String(r.status));
      const jr = await r.json();
      for (const u of (jr.value || [])) {
        out.total++;
        if (u.isMfaRegistered) out.mfa_registered++;
        if (u.isPasswordlessCapable) out.passwordless++;
        if (u.isSystemPreferredAuthenticationMethodEnabled === true) { /* informational only */ }
        for (const m of (u.methodsRegistered || [])) out.by_method[m] = (out.by_method[m] || 0) + 1;
        if ((u.methodsRegistered || []).some((m) => /fido2|windowsHelloForBusiness|certificate/i.test(m))) out.phishing_resistant++;
      }
      url = jr['@odata.nextLink'] || null;
    }
  } catch (e) { out.error = e.message; }
  return out;
}

/* -------------------------------------------------- inert-policy detection */

/**
 * A policy can read as configured in the portal and still never match a sign-in.
 * This is the defect class that left Block Legacy Authentication inert for six years
 * with includeApplications ["None"], so it is detected explicitly rather than inferred
 * from state. A conflicting include/exclude pair is the same bug in a different field:
 * in Conditional Access exclude always wins, so an item on both lists cancels itself.
 */
function detectInert(p) {
  const c = p.conditions || {};
  const reasons = [];
  const apps = c.applications || {};
  const users = c.users || {};

  if ((apps.includeApplications || []).length === 1 && apps.includeApplications[0] === 'None')
    reasons.push('Target resources is set to None, so no application is in scope.');

  const anyUserInclude = (users.includeUsers || []).filter((u) => u !== 'None').length
    + (users.includeGroups || []).length + (users.includeRoles || []).length;
  if (!anyUserInclude)
    reasons.push('No users, groups or roles are included, so no principal is in scope.');

  const platIn = (c.platforms && c.platforms.includePlatforms) || [];
  const platEx = (c.platforms && c.platforms.excludePlatforms) || [];
  if (platIn.length) {
    const survives = platIn.filter((x) => x !== 'all' && !platEx.includes(x));
    const allIncluded = platIn.includes('all');
    if (!allIncluded && !survives.length)
      reasons.push('Every included device platform (' + platIn.join(', ') + ') also appears in the exclude list, and exclude wins, so the platform condition matches nothing.');
  }

  const locIn = (c.locations && c.locations.includeLocations) || [];
  const locEx = (c.locations && c.locations.excludeLocations) || [];
  if (locIn.length && !locIn.includes('All')) {
    const survives = locIn.filter((x) => !locEx.includes(x));
    if (!survives.length)
      reasons.push('Every included location also appears in the exclude list, so the location condition matches nothing.');
  }

  return { isInert: reasons.length > 0, reason: reasons.join(' ') || null };
}

/** Okta rules are priority-ordered and first match wins, so a broad rule shadows later ones. */
function detectShadowedRules(rules) {
  const act = (rules || []).filter((r) => r.status === 'ACTIVE')
    .slice().sort((a, b) => (a.priority || 0) - (b.priority || 0));
  const out = [];
  let shadowedFrom = null;
  for (const r of act) {
    if (shadowedFrom) { out.push({ name: r.name, priority: r.priority, shadowedBy: shadowedFrom }); continue; }
    const c = r.conditions || {};
    const peopleAll = !c.people || (!((c.people.groups || {}).include || []).length && !((c.people.users || {}).include || []).length)
      || (((c.people.groups || {}).include || [])[0] === 'EVERYONE');
    const netAny = !c.network || c.network.connection === 'ANYWHERE';
    const noAuthCtx = !c.authContext || !c.authContext.authType || c.authContext.authType === 'ANY';
    const noDevice = !c.device;
    const noPlatform = !c.platform;
    const noRisk = !c.riskScore || c.riskScore.level === 'ANY';
    const noClient = !c.clients && !c.userType && !c.elCondition;
    if (peopleAll && netAny && noAuthCtx && noDevice && noPlatform && noRisk && noClient) {
      shadowedFrom = { name: r.name, priority: r.priority };
    }
  }
  return out;
}

/* ------------------------------------------------------------------ main */

async function main() {
  if (!OKTA_BASE || !OKTA_TOKEN) throw new Error('OKTA_BASE_URL / OKTA_API_TOKEN not set in .env');
  const pool = mysql.createPool({
    host: process.env.DB_HOST, port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME, connectionLimit: 3,
    supportBigNumbers: true, bigNumberStrings: true, // zsnet_* ids are bigint; keep them as strings
  });
  const started = new Date();
  const counts = {};

  try {
    /* ---- Okta groups, so an assignment reads as a name and a headcount ---- */
    log('okta: groups');
    // expand=stats is what makes usersCount present; without it every count is undefined.
    const groups = await oktaAll('/api/v1/groups?limit=200&expand=stats');
    const gById = new Map();
    for (const g of groups) {
      gById.set(g.id, { name: (g.profile || {}).name || g.id, type: g.type,
                        count: (g._embedded && g._embedded.stats && g._embedded.stats.usersCount) || null });
    }
    log(`okta: ${groups.length} groups`);

    // usersCount is not returned by the list endpoint. It is fetched after the policy
    // loop, for the groups that are actually compared: the ones a policy references,
    // plus the exclusion groups the Entra drift view lines up against.
    const DRIFT_GROUPS = ['SaaS-MFA-Exclusion', 'SaaS-OktaInternationalUsers',
      'SaaS-OktaSessionTesters', 'SaaS-SFTP', 'SaaS-MFA-WarRoom', 'SaaS-MFA-TOTP',
      'SaaS-MFA-Bypass', 'SaaS-MFA-Server'];
    const wantStats = new Set();
    for (const [gid, g] of gById) if (DRIFT_GROUPS.includes(g.name)) wantStats.add(gid);
    const groupCounts = {};

    /* ---- Okta apps, to count what sits on each access policy ---- */
    log('okta: apps');
    const apps = await oktaAll('/api/v1/apps?filter=status+eq+%22ACTIVE%22&limit=200');
    const appsByPolicy = new Map();
    for (const a of apps) {
      const href = ((a._links || {}).accessPolicy || {}).href || '';
      const pid = href.split('/').pop();
      if (!pid) continue;
      if (!appsByPolicy.has(pid)) appsByPolicy.set(pid, []);
      appsByPolicy.get(pid).push(a.label || a.name);
    }
    log(`okta: ${apps.length} active apps across ${appsByPolicy.size} access policies`);

    /* ---- Okta policies + rules ---- */
    const policyRows = [];
    for (const type of POLICY_TYPES) {
      let list;
      try { list = await oktaAll(`/api/v1/policies?type=${type}&limit=200`); }
      catch (e) { warn(`policy type ${type} unavailable: ${e.message.slice(0, 160)}`); continue; }
      for (const p of list) {
        // expand=rules is not honoured for ACCESS_POLICY, so rules are always fetched per policy.
        let rules = [];
        try { rules = await oktaAll(`/api/v1/policies/${p.id}/rules`); }
        catch (e) { warn(`rules for ${p.name}: ${e.message.slice(0, 120)}`); }

        const cond = p.conditions || {};
        const gIds = ((cond.people || {}).groups || {}).include || [];
        const uIds = ((cond.people || {}).users || {}).include || [];
        for (const id of gIds) wantStats.add(id);
        const assignments = {
          groups: gIds.map((id) => ({ id, name: (gById.get(id) || {}).name || id,
                                      type: (gById.get(id) || {}).type || null, count: null })),
          users: uIds,
          unresolved: gIds.filter((id) => !gById.has(id)),
        };
        const appNames = appsByPolicy.get(p.id) || [];
        policyRows.push({
          policy_id: p.id, policy_type: p.type, name: p.name, description: p.description || null,
          status: p.status, priority: p.priority == null ? null : p.priority,
          is_system: p.system ? 1 : 0,
          assignments,   // stringified at insert, after headcounts are backfilled
          rules: JSON.stringify(rules),
          rule_count: rules.length,
          app_count: appNames.length,
          app_names: JSON.stringify(appNames.slice(0, 200)),
          shadowed: JSON.stringify(detectShadowedRules(rules)),
        });
      }
      log(`okta: ${type} -> ${list.length}`);
    }
    /* ---- group headcounts, for the groups that are actually compared ---- */
    let statsOk = 0;
    const statsWanted = wantStats.size;
    for (const [gid, g] of gById) if (g.count != null) { wantStats.delete(gid); statsOk++; }
    for (const gid of wantStats) {
      try {
        const g = await oktaGet(`/api/v1/groups/${gid}?expand=stats`);
        const cnt = (((g.body || {})._embedded || {}).stats || {}).usersCount;
        if (cnt != null && gById.has(gid)) { gById.get(gid).count = cnt; statsOk++; }
      } catch (e) { warn(`group stats ${gid}: ${e.message.slice(0, 100)}`); }
    }
    // Backfill into the assignment snapshots already built.
    for (const r of policyRows) {
      for (const g of ((r.assignments || {}).groups || [])) {
        const hit = gById.get(g.id);
        if (hit && hit.count != null) g.count = hit.count;
      }
    }
    for (const [, g] of gById) {
      if (g.count != null && DRIFT_GROUPS.includes(g.name)) groupCounts[g.name] = g.count;
    }
    log(`okta: ${statsOk} group headcounts resolved (${statsWanted} compared groups needed one, ${wantStats.size} unresolved)`);

    counts.okta_policies = policyRows.length;
    counts.okta_rules = policyRows.reduce((n, r) => n + r.rule_count, 0);

    /* ---- Okta zones ---- */
    log('okta: zones');
    const zones = await oktaAll('/api/v1/zones?limit=200');
    // Three different shapes come back here. IP zones use gateways/proxies as arrays of
    // {type,value}; DYNAMIC uses locations as an array of {country,region}; DYNAMIC_V2 uses
    // locations/asns/ipServiceCategories as objects with include/exclude arrays. Iterating
    // the V2 object as an array is what broke the first run.
    const zoneRows = zones.map((z) => {
      const raw = [];
      const countries = [];
      const extras = [];
      const eat = (v) => {
        if (!v) return;
        if (Array.isArray(v)) {
          for (const e of v) {
            if (typeof e === 'string') raw.push(e);
            else if (e && typeof e === 'object') {
              if (e.value) raw.push(e.value);
              else if (e.country) countries.push(e.region ? e.country + '/' + e.region : e.country);
            }
          }
        } else if (typeof v === 'object') {
          eat(v.include);                       // DYNAMIC_V2 include/exclude form
          for (const e of (v.exclude || [])) extras.push('excluded: ' + (typeof e === 'string' ? e : JSON.stringify(e)));
        }
      };
      eat(z.gateways); eat(z.proxies); eat(z.locations);
      // ASN and IP-service-category conditions have no Entra named-location equivalent at all.
      for (const key of ['asns', 'ipServiceCategories']) {
        const v = z[key];
        if (!v) continue;
        const inc = Array.isArray(v) ? v : (v.include || []);
        for (const e of inc) extras.push(key + ': ' + (typeof e === 'string' ? e : JSON.stringify(e)));
      }
      const iv = net.normalize(raw);
      // A POLICY-usage zone only does something if a rule names it. A BLOCKLIST-usage zone is
      // enforced org-wide by Okta without any rule, so a zero reference count is normal there.
      const refs = policyRows.filter((pr) => pr.rules.includes(z.id)).length;
      return {
        zone_id: z.id, name: z.name, zone_type: z.type, status: z.status,
        usage_kind: z.usage || null, referenced_by: refs,
        entry_count: raw.length + countries.length + extras.length,
        cidrs: JSON.stringify(iv.flatMap((i) => net.toCidrs(i))),
        countries: JSON.stringify(countries),
        extras: JSON.stringify(extras),
        _iv: iv,
      };
    });
    counts.okta_zones = zoneRows.length;
    log(`okta: ${zoneRows.length} zones`);

    /* ---- Entra ---- */
    log('graph: token + roles');
    const { token, roles } = await getGraphToken();
    log(`graph: ${roles.length} app roles consented`);

    log('graph: conditional access policies');
    const cas = await graphAll(token, '/identity/conditionalAccess/policies');
    const caRows = cas.map((p) => {
      const { isInert, reason } = detectInert(p);
      return {
        ca_id: p.id, display_name: p.displayName, state: p.state,
        conditions: JSON.stringify(p.conditions || {}),
        grant_controls: JSON.stringify(p.grantControls || {}),
        session_controls: JSON.stringify(p.sessionControls || {}),
        is_inert: isInert ? 1 : 0, inert_reason: reason,
      };
    });
    counts.entra_ca = caRows.length;
    counts.entra_ca_inert = caRows.filter((r) => r.is_inert).length;

    log('graph: mfa claim sample');
    const mfaClaim = await sampleMfaClaim(token);
    if (mfaClaim.error) warn('mfa claim sample partial: ' + mfaClaim.error);
    else log(`graph: interactive ${mfaClaim.interactive.single_pct}% single-factor, non-interactive ${mfaClaim.non_interactive.single_pct}%`);

    log('graph: registration coverage');
    const registration = await sampleRegistration(token);
    if (registration.error) warn('registration sample failed: ' + registration.error);
    else log(`graph: ${registration.mfa_registered}/${registration.total} users have an MFA method, ${registration.phishing_resistant} phishing-resistant`);

    log('graph: named locations');
    const locs = await graphAll(token, '/identity/conditionalAccess/namedLocations');
    const locRows = locs.map((l) => {
      const isIp = (l['@odata.type'] || '').includes('ipNamedLocation');
      const ranges = (l.ipRanges || []).map((r) => r.cidrAddress).filter(Boolean);
      return {
        loc_id: l.id, display_name: l.displayName,
        loc_type: isIp ? 'ip' : 'country',
        is_trusted: isIp ? (l.isTrusted ? 1 : 0) : null,
        cidrs: JSON.stringify(ranges),
        countries: JSON.stringify(l.countriesAndRegions || []),
        _iv: isIp ? net.normalize(ranges) : [],
        _trusted: isIp && !!l.isTrusted,
      };
    });
    counts.entra_locations = locRows.length;
    log(`graph: ${caRows.length} CA policies (${counts.entra_ca_inert} inert), ${locRows.length} named locations`);

    /* ---- zone parity ----
     * The question is different per zone role, and asking one question for all of them is
     * what produced a wall of false gaps on the first pass:
     *   POLICY zone referenced by a rule -> must be inside a TRUSTED Entra location, because
     *     that is what a "corporate network only" policy keys off.
     *   BLOCKLIST zone -> must be present in some Entra location, and must NOT be trusted.
     *     A blocked range sitting inside a trusted location is an inversion, not a gap.
     *   POLICY zone no rule references -> nothing depends on it, so nothing to reconcile.
     */
    const ipLocs = locRows.filter((l) => l.loc_type === 'ip');
    const trustedIv = net.normalize(ipLocs.filter((l) => l._trusted).flatMap((l) => JSON.parse(l.cidrs)));
    const allLocIv = net.normalize(ipLocs.flatMap((l) => JSON.parse(l.cidrs)));
    const locFor = (ip) => ipLocs.find((l) => net.contains(l._iv, ip)) || null;
    const parityRows = [];
    const push = (r) => parityRows.push(Object.assign({ entra_location: null, entra_trusted: null, is_sipa_anchor: 0 }, r));
    const sipaHit = (cidr) => SIPA_IPS.some((x) => net.contains(net.normalize([cidr]), x.ip)) ? 1 : 0;

    for (const z of zoneRows) {
      if (!z._iv.length) continue;
      const isBlock = z.usage_kind === 'BLOCKLIST';

      if (!isBlock && !z.referenced_by) {
        push({ okta_zone: z.name, cidr: '(whole zone)', direction: 'unused',
               kind: 'zone_unused', detail: 'Usage is POLICY but no policy rule references this zone, so it currently has no effect in Okta and nothing needs reconciling in Entra.' });
        continue;
      }

      if (isBlock) {
        for (const gap of net.uncovered(z._iv, allLocIv)) {
          for (const cidr of net.toCidrs(gap))
            push({ okta_zone: z.name, cidr, direction: 'okta_only', kind: 'block_missing',
                   detail: 'Blocked in Okta but present in no Entra named location, so no Entra policy can block it.',
                   is_sipa_anchor: sipaHit(cidr) });
        }
        // Inversion: something Okta blocks that Entra treats as a trusted location.
        for (const [lo, hi] of z._iv) {
          const overlap = net.uncovered([[lo, hi]], net.uncovered([[lo, hi]], trustedIv));
          for (const ov of overlap) {
            for (const cidr of net.toCidrs(ov)) {
              const l = locFor(cidr.split('/')[0]);
              push({ okta_zone: z.name, cidr, direction: 'conflict', kind: 'block_trusted_in_entra',
                     entra_location: l ? l.display_name : null, entra_trusted: 1,
                     detail: 'Okta blocks this range while Entra has it inside a location marked trusted. Trust and block disagree.',
                     is_sipa_anchor: sipaHit(cidr) });
            }
          }
        }
        continue;
      }

      // Trust-granting zone that rules depend on.
      for (const gap of net.uncovered(z._iv, trustedIv)) {
        for (const cidr of net.toCidrs(gap)) {
          const l = locFor(cidr.split('/')[0]);
          push({ okta_zone: z.name, cidr, direction: 'okta_only',
                 kind: l ? 'in_untrusted_location' : 'no_entra_location',
                 entra_location: l ? l.display_name : null,
                 entra_trusted: l ? 0 : null,
                 detail: l
                   ? 'Trusted by Okta. Present in the Entra location "' + l.display_name + '", but that location is not marked trusted, so a trusted-location policy ignores it.'
                   : 'Trusted by Okta and present in no Entra named location at all.',
                 is_sipa_anchor: sipaHit(cidr) });
        }
      }
    }

    // Reverse direction: trusted in Entra, unknown to any Okta POLICY zone.
    const oktaPolicyIv = net.normalize(zoneRows.filter((z) => z.usage_kind !== 'BLOCKLIST')
      .flatMap((z) => JSON.parse(z.cidrs)));
    for (const l of ipLocs.filter((x) => x._trusted)) {
      for (const gap of net.uncovered(l._iv, oktaPolicyIv)) {
        for (const cidr of net.toCidrs(gap))
          push({ okta_zone: '(none)', cidr, direction: 'entra_only', kind: 'entra_only',
                 entra_location: l.display_name, entra_trusted: 1,
                 detail: 'Trusted in Entra but in no Okta policy zone. Okta\'s list is the stale one here.',
                 is_sipa_anchor: sipaHit(cidr) });
      }
    }
    for (const k of ['okta_only', 'entra_only', 'conflict', 'unused'])
      counts['parity_' + k] = parityRows.filter((r) => r.direction === k).length;
    log('parity: ' + ['okta_only', 'entra_only', 'conflict', 'unused'].map((k) => counts['parity_' + k] + ' ' + k).join(', '));

    /* ---- SIPA anchors ---- */
    const [segRows] = await pool.query(
      'SELECT id, name, domain_names FROM zsnet_zpa_app WHERE name LIKE ? ORDER BY name', ['%SIPA%']
    ).catch(() => [[]]);
    const anchorRows = [];
    for (const s of SIPA_IPS) {
      let ptr = null;
      try { ptr = (await dns.reverse(s.ip))[0] || null; } catch (e) { /* no PTR is a fact, not an error */ }
      const inZones = zoneRows.filter((z) => net.contains(z._iv, s.ip)).map((z) => z.name);
      const inLocs = locRows.filter((l) => l.loc_type === 'ip' && net.contains(l._iv, s.ip));
      const seg = (segRows || []).find((r) => {
        try {
          const d = typeof r.domain_names === 'string' ? JSON.parse(r.domain_names) : r.domain_names;
          return (d || []).some((x) => net.contains(net.normalize([x]), s.ip));
        } catch (e) { return false; }
      });
      anchorRows.push({
        ip: s.ip, label: s.label, site: s.site, ptr, carrier: s.carrier,
        okta_zones: JSON.stringify(inZones),
        entra_locations: JSON.stringify(inLocs.map((l) => l.display_name)),
        entra_trusted: inLocs.length ? (inLocs.some((l) => l._trusted) ? 1 : 0) : null,
        in_zpa_segment: seg ? seg.name : null,
        notes: s.connectorGroup,
      });
    }
    counts.sipa_anchors = anchorRows.length;

    /* ---- write ---- */
    const c = await pool.getConnection();
    try {
      await c.beginTransaction();

      for (const r of policyRows) {
        await c.query(
          `INSERT INTO oem_okta_policy (policy_id,policy_type,name,description,status,priority,is_system,
             assignments,rules,rule_count,app_count,app_names,shadowed_rules)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE policy_type=VALUES(policy_type),name=VALUES(name),
             description=VALUES(description),status=VALUES(status),priority=VALUES(priority),
             is_system=VALUES(is_system),assignments=VALUES(assignments),rules=VALUES(rules),
             rule_count=VALUES(rule_count),app_count=VALUES(app_count),app_names=VALUES(app_names),
             shadowed_rules=VALUES(shadowed_rules)`,
          [r.policy_id, r.policy_type, r.name, r.description, r.status, r.priority, r.is_system,
           JSON.stringify(r.assignments), r.rules, r.rule_count, r.app_count, r.app_names, r.shadowed]);
      }
      if (policyRows.length)
        await c.query('DELETE FROM oem_okta_policy WHERE policy_id NOT IN (' + policyRows.map(() => '?').join(',') + ')',
          policyRows.map((r) => r.policy_id));

      for (const z of zoneRows) {
        await c.query(
          `INSERT INTO oem_okta_zone (zone_id,name,zone_type,status,usage_kind,entry_count,cidrs,countries,extras,referenced_by)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE name=VALUES(name),zone_type=VALUES(zone_type),status=VALUES(status),
             usage_kind=VALUES(usage_kind),entry_count=VALUES(entry_count),cidrs=VALUES(cidrs),
             countries=VALUES(countries),extras=VALUES(extras),referenced_by=VALUES(referenced_by)`,
          [z.zone_id, z.name, z.zone_type, z.status, z.usage_kind, z.entry_count, z.cidrs, z.countries, z.extras, z.referenced_by]);
      }
      if (zoneRows.length)
        await c.query('DELETE FROM oem_okta_zone WHERE zone_id NOT IN (' + zoneRows.map(() => '?').join(',') + ')',
          zoneRows.map((z) => z.zone_id));

      for (const r of caRows) {
        await c.query(
          `INSERT INTO oem_entra_ca (ca_id,display_name,state,conditions,grant_controls,session_controls,is_inert,inert_reason)
           VALUES (?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE display_name=VALUES(display_name),state=VALUES(state),
             conditions=VALUES(conditions),grant_controls=VALUES(grant_controls),
             session_controls=VALUES(session_controls),is_inert=VALUES(is_inert),inert_reason=VALUES(inert_reason)`,
          [r.ca_id, r.display_name, r.state, r.conditions, r.grant_controls, r.session_controls, r.is_inert, r.inert_reason]);
      }
      if (caRows.length)
        await c.query('DELETE FROM oem_entra_ca WHERE ca_id NOT IN (' + caRows.map(() => '?').join(',') + ')',
          caRows.map((r) => r.ca_id));

      for (const r of locRows) {
        await c.query(
          `INSERT INTO oem_entra_named_location (loc_id,display_name,loc_type,is_trusted,cidrs,countries)
           VALUES (?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE display_name=VALUES(display_name),loc_type=VALUES(loc_type),
             is_trusted=VALUES(is_trusted),cidrs=VALUES(cidrs),countries=VALUES(countries)`,
          [r.loc_id, r.display_name, r.loc_type, r.is_trusted, r.cidrs, r.countries]);
      }
      if (locRows.length)
        await c.query('DELETE FROM oem_entra_named_location WHERE loc_id NOT IN (' + locRows.map(() => '?').join(',') + ')',
          locRows.map((r) => r.loc_id));

      await c.query('DELETE FROM oem_zone_parity');
      for (const r of parityRows) {
        await c.query(
          `INSERT INTO oem_zone_parity (okta_zone,cidr,direction,kind,detail,entra_location,entra_trusted,is_sipa_anchor)
           VALUES (?,?,?,?,?,?,?,?)`,
          [r.okta_zone, r.cidr, r.direction, r.kind, r.detail, r.entra_location, r.entra_trusted, r.is_sipa_anchor]);
      }

      for (const r of anchorRows) {
        await c.query(
          `INSERT INTO oem_sipa_anchor (ip,label,site,ptr,carrier,okta_zones,entra_locations,entra_trusted,in_zpa_segment,notes)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE label=VALUES(label),site=VALUES(site),ptr=VALUES(ptr),carrier=VALUES(carrier),
             okta_zones=VALUES(okta_zones),entra_locations=VALUES(entra_locations),entra_trusted=VALUES(entra_trusted),
             in_zpa_segment=VALUES(in_zpa_segment),notes=VALUES(notes)`,
          [r.ip, r.label, r.site, r.ptr, r.carrier, r.okta_zones, r.entra_locations, r.entra_trusted, r.in_zpa_segment, r.notes]);
      }

      await c.query(
        `INSERT INTO oem_meta (k,v) VALUES ('last_run',?) ON DUPLICATE KEY UPDATE v=VALUES(v)`,
        [JSON.stringify({ started: started.toISOString(), finished: new Date().toISOString(),
                          counts, warnings: warns, ok: true })]);
      await c.query(
        `INSERT INTO oem_meta (k,v) VALUES ('graph_roles',?) ON DUPLICATE KEY UPDATE v=VALUES(v)`,
        [JSON.stringify({ roles, checked: new Date().toISOString() })]);
      await c.query(
        `INSERT INTO oem_meta (k,v) VALUES ('mfa_claim',?) ON DUPLICATE KEY UPDATE v=VALUES(v)`,
        [JSON.stringify(Object.assign({}, mfaClaim, {
          superseded_by: 'mfa_evidence',
          note: 'Prior sample: counts sign-ins whose token carried no MFA claim. It cannot tell whether MFA happened at the Okta hop, so it is kept as history; the "Measure MFA evidence" job writes the current, per-method reading.',
        }))]);
      await c.query(
        `INSERT INTO oem_meta (k,v) VALUES ('mfa_registration',?) ON DUPLICATE KEY UPDATE v=VALUES(v)`,
        [JSON.stringify(registration)]);
      await c.query(
        `INSERT INTO oem_meta (k,v) VALUES ('okta_group_counts',?) ON DUPLICATE KEY UPDATE v=VALUES(v)`,
        [JSON.stringify({ measured_at: new Date().toISOString(), counts: groupCounts })]);

      await c.commit();
    } catch (e) { await c.rollback(); throw e; }
    finally { c.release(); }

    log('done', JSON.stringify(counts));
    if (warns.length) log(`${warns.length} warning(s)`);
    await pool.end();
    process.exit(0);
  } catch (e) {
    console.error('FATAL', e.message);
    try {
      await pool.query(`INSERT INTO oem_meta (k,v) VALUES ('last_run',?) ON DUPLICATE KEY UPDATE v=VALUES(v)`,
        [JSON.stringify({ started: started.toISOString(), finished: new Date().toISOString(),
                          counts, warnings: warns, ok: false, error: e.message })]);
    } catch (_) { /* the failure is already on stderr */ }
    await pool.end().catch(() => {});
    process.exit(1);
  }
}

main();
