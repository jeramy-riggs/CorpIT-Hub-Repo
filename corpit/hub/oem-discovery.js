/**
 * oem-discovery.js — Okta is the source of migration scope.
 *
 * discoverOktaScope   every Okta object class the migration must account for, live, with
 *                     per-class coverage recorded (ok / denied / error) — never zero-as-empty.
 * refreshEntraSpExtras provisioning jobs + signing cert for SSO- and matched principals.
 * runMatcher          identifier-first matching (launcher app id, ACS/audience, reply URL hosts,
 *                     tenant hints) with environment words as hard separators; names only
 *                     ever produce a suggestion. Recorded decisions are never deleted.
 * buildWorkItems      one work item per unique piece of Okta work across five categories,
 *                     with What / What changes / Can Claude do it / What to click / How verified.
 * measureMfaEvidence  windowed sign-in evidence with the fields that exist, and an honest
 *                     "inconclusive" for the federated hop.
 * assessRetirement    "Can we retire Okta?" from the discovered dependencies.
 */
'use strict';
const L = require('./oem-lib');
const { pool, j, oktaGet, oktaAll, graphGet, graphAll, envOf, tokens, jaccard, hostOf, normUrl } = L;

/* ------------------------------------------------------- v2 helpers */
// oem-v2-store / oem-v2-model are required lazily: discovery must keep working when either is absent,
// and the store requires this module (D.buildWorkItems) — a top-level require would be a cycle.
function v2Store() { try { return require('./oem-v2-store'); } catch (e) { return null; } }
function v2Model() { try { return require('./oem-v2-model'); } catch (e) { return null; } }

const dateOnly = (d) => { try { return new Date(d).toISOString().slice(0, 10); } catch (e) { return String(d); } };

/** Unique sentences, order preserved (bug 8). The model's dedupeEvidence when present, else an inline dedupe. */
function dedupeLines(lines) {
  const arr = (Array.isArray(lines) ? lines : []).filter((x) => x !== null && x !== undefined && x !== '');
  const M = v2Model();
  if (M && typeof M.dedupeEvidence === 'function') { try { const r = M.dedupeEvidence(arr); if (Array.isArray(r)) return r; } catch (e) { /* inline fallback below */ } }
  const seen = new Set(), out = [];
  for (const s of arr) {
    const k = typeof s === 'string' ? s.trim().replace(/\s+/g, ' ').toLowerCase() : JSON.stringify(s);
    if (seen.has(k)) continue;
    seen.add(k); out.push(s);
  }
  return out;
}
function dedupeBy(arr, keyFn) { const seen = new Set(), out = []; for (const x of arr || []) { const k = keyFn(x); if (seen.has(k)) continue; seen.add(k); out.push(x); } return out; }

/** Entra service-principal object ids recorded as deleted: never a candidate, never a destination. */
async function tombstonedSet(q) {
  const S = v2Store();
  if (!S || typeof S.tombstonedIds !== 'function') return new Set();
  try { const s = await S.tombstonedIds(q); return s instanceof Set ? s : new Set(Array.isArray(s) ? s : []); } catch (e) { return new Set(); }
}
/** Record-if-absent through the store; a missing store or a failed write never stops discovery. */
async function recordTombstone(q, t, log) {
  const S = v2Store();
  if (!S || typeof S.recordTombstone !== 'function') return { ok: false, reason: 'store unavailable' };
  try { const r = await S.recordTombstone(q, t); return { ok: true, row: r || null }; }
  catch (e) { if (typeof log === 'function') log('tombstone for ' + t.entraId + ' not recorded: ' + e.message, 'warn'); return { ok: false, reason: e.message }; }
}

/** Copy depends on how Okta signs the user in (bug 6): a bookmark launches, SWA fills a password, neither has claims. */
function launcherWords(okta) {
  const mode = String((okta && okta.signOnMode) || '');
  if (mode === 'BOOKMARK') return { kind: 'bookmark', noun: 'bookmark', still: 'Okta still launches this bookmark until it is verified in Entra', verifyClaims: 'The link opens the intended destination and any sign-in there happens through Entra, not Okta — a bookmark carries no claims.', verifyCutover: 'The Okta assignment is removed or the Okta app is deactivated, and the link still opens from Entra My Apps.' };
  if ((okta && okta.classKind === 'swa_app') || /^(AUTO_LOGIN|BROWSER_PLUGIN|SECURE_PASSWORD_STORE|BASIC_AUTH)$/.test(mode)) return { kind: 'swa', noun: 'password-filled app', still: 'Okta still fills the password for this app until it is verified in Entra', verifyClaims: 'The My Apps browser extension fills the stored credentials and the app signs the user in — no claims are issued.', verifyCutover: 'The Okta assignment is removed or the Okta app is deactivated, and password sign-in from Entra My Apps still works.' };
  if (mode === 'OPENID_CONNECT') return { kind: 'oidc', noun: 'app', still: 'Okta still authenticates this app until it is verified in Entra', verifyClaims: 'The ID token carries the claims the app needs (subject, email, groups) — check the app side.', verifyCutover: 'The Okta assignment is removed or the Okta app is deactivated, and sign-in still works.' };
  if (mode === 'WS_FEDERATION') return { kind: 'ws_fed', noun: 'app', still: 'Okta still authenticates this app until it is verified in Entra', verifyClaims: 'The WS-Fed token carries the claims the app needs — check the app side.', verifyCutover: 'The Okta assignment is removed or the Okta app is deactivated, and sign-in still works.' };
  return { kind: 'saml', noun: 'app', still: 'Okta still authenticates this app until it is verified in Entra', verifyClaims: 'Claims / attributes the app needs arrive (name ID, email, groups) — check the app side.', verifyCutover: 'The Okta assignment is removed or the Okta app is deactivated, and sign-in still works.' };
}

/* ------------------------------------------------------- okta object model */

/** Catalog names / modes that are Okta platform pieces or dependencies, not SSO apps to match. */
function classifyOktaApp(a) {
  const name = String(a.name || '').toLowerCase();
  const label = String(a.label || '');
  const mode = String(a.sign_on_mode || a.signOnMode || '');
  if (name === 'office365' && mode === 'SAML_1_1') return { kind: 'federation', category: 'dependencies' };
  if (name === 'active_directory') return { kind: 'ad_agent', category: 'dependencies' };
  if (name === 'ldap' || /^ldap interface$/i.test(label) || name === 'okta_ldap') return { kind: 'ldap_interface', category: 'dependencies' };
  if (/^RADIUS/i.test(mode) || /radius/i.test(name)) return { kind: 'radius', category: 'dependencies' };
  if (mode === 'MFA_AS_SERVICE' || name === 'mfa_rdp') return { kind: 'mfa_service', category: 'dependencies' };
  if (name === 'saasure' || name === 'okta_enduser' || name === 'okta_browser_plugin' || /^okta (admin console|dashboard|browser plugin)$/i.test(label)) return { kind: 'okta_platform', category: 'dependencies' };
  if (/okta_flow|workflows/i.test(name) || /^okta workflows/i.test(label)) return { kind: 'workflows', category: 'dependencies' };
  if (name === 'okta_org2org') return { kind: 'org2org', category: 'dependencies' };
  if (mode === 'AUTO_LOGIN' || mode === 'BROWSER_PLUGIN' || mode === 'SECURE_PASSWORD_STORE' || mode === 'BASIC_AUTH') return { kind: 'swa_app', category: 'applications' };
  if (mode === 'SAML_2_0' || mode === 'OPENID_CONNECT' || mode === 'BOOKMARK' || mode === 'WS_FEDERATION' || mode === 'SAML_1_1') return { kind: 'sso_app', category: 'applications' };
  return { kind: 'other_app', category: 'applications' };
}

const PROVISIONING_FEATURES = new Set(['SCIM_PROVISIONING', 'PUSH_NEW_USERS', 'PUSH_PROFILE_UPDATES', 'PUSH_USER_DEACTIVATION', 'REACTIVATE_USERS', 'GROUP_PUSH', 'IMPORT_NEW_USERS', 'IMPORT_PROFILE_UPDATES', 'PUSH_PASSWORD_UPDATES', 'PROFILE_MASTERING', 'IMPORT_USER_SCHEMA', 'OUTBOUND_DEL_AUTH']);

/* conf-1: identity-provider / platform hosts say nothing about which vendor an application is — every Okta-format entity
 * ID is http://www.okta.com/exk…, Okta's own Graph clients reply to okta.com, Microsoft's first-party apps reply to
 * microsoftonline.com. Such a host is never a vendor hint and never matched by one (endpoint-equality rules still apply). */
const IDP_HOST_RE = /(^|\.)(okta\.com|oktapreview\.com|okta-emea\.com|microsoftonline\.com|microsoft\.com|windows\.net|windowsazure\.com|google\.com|localhost)$/i;
const hostMatches = (a, b) => a === b || a.endsWith('.' + b) || b.endsWith('.' + a); // label boundary, never a substring
/** conf-1: the environment an Entra app belongs to. Its name / identifier URIs name it; reply hosts only count when every
 *  one of them agrees — a six-host app with one *-uat host is production with a UAT endpoint, not a UAT app. */
function entraEnv(name, ids) {
  const named = envOf(String(name || '') + ' ' + ((ids && ids.identifierUris) || []).join(' '));
  if (named) return named;
  const hosts = (ids && ids.replyHosts) || [];
  if (!hosts.length) return null;
  const envs = hosts.map((h) => envOf(h));
  if (envs.some((x) => !x)) return null;
  return envs.every((x) => x === envs[0]) ? envs[0] : null;
}

function oktaIdentifiers(raw) {
  const s = (raw && raw.settings) || {};
  const so = s.signOn || {};
  const app = s.app || {};
  const ids = { acs: [], audience: [], redirects: [], bookmarkUrl: null, launcherAppId: null, oktaHosted: null, vendorHints: [], clientId: null, loginUrl: null };
  for (const k of ['ssoAcsUrl', 'destination', 'recipient']) if (so[k]) ids.acs.push(String(so[k]));
  if (Array.isArray(so.acsEndpoints)) for (const e of so.acsEndpoints) if (e && e.url) ids.acs.push(String(e.url));
  if (so.audience) ids.audience.push(String(so.audience));
  if (so.audienceOverride) ids.audience.push(String(so.audienceOverride));
  if (so.ssoAcsUrlOverride) ids.acs.push(String(so.ssoAcsUrlOverride));
  if (so.defaultRelayState && /^https?:/i.test(so.defaultRelayState)) ids.loginUrl = so.defaultRelayState;
  const oc = s.oauthClient || {};
  if (Array.isArray(oc.redirect_uris)) ids.redirects = oc.redirect_uris.map(String);
  if (raw && raw.credentials && raw.credentials.oauthClient && raw.credentials.oauthClient.client_id) ids.clientId = raw.credentials.oauthClient.client_id;
  if (app.url) {
    ids.bookmarkUrl = String(app.url);
    const m = ids.bookmarkUrl.match(/launcher\.myapps\.microsoft\.com\/api\/signin\/([0-9a-f-]{36})/i);
    if (m) ids.launcherAppId = m[1].toLowerCase();
    if (/\.okta\.com\//i.test(ids.bookmarkUrl) || /okta-emea\.com/i.test(ids.bookmarkUrl)) ids.oktaHosted = ids.bookmarkUrl;
  }
  // conf-1: OIN template apps keep their SAML endpoints in settings.app (acsUrl / audienceUrl / entityId …), not in
  // settings.signOn. They are the strongest evidence there is; read them as ACS / audience, not as vendor hints.
  for (const [k, v] of Object.entries(app)) {
    if (typeof v !== 'string' || v.length < 4) continue;
    if (/acs|assertionconsumer/i.test(k) && /^https?:/i.test(v)) ids.acs.push(v);
    else if (/audience|entityid/i.test(k) && /^(https?:|urn:)/i.test(v)) ids.audience.push(v);
  }
  for (const [k, v] of Object.entries(app)) {
    if (typeof v === 'string' && v.length >= 4 && /(subdomain|domain|instance|site|tenant|company|org|account|host|baseurl|url|realm|customer)/i.test(k)) {
      const h = /^https?:/i.test(v) ? hostOf(v) : v.toLowerCase();
      if (h && !IDP_HOST_RE.test(h)) ids.vendorHints.push(h);
    }
  }
  return ids;
}

function entraIdentifiers(raw, row) {
  const replyUrls = (raw && Array.isArray(raw.replyUrls) ? raw.replyUrls : []).map(String);
  const spns = (raw && Array.isArray(raw.servicePrincipalNames) ? raw.servicePrincipalNames : []).map(String);
  return {
    appId: String(row.app_id || (raw && raw.appId) || '').toLowerCase(),
    replyUrls, replyHosts: [...new Set(replyUrls.map(hostOf).filter(Boolean))],
    identifierUris: spns.filter((x) => !/^[0-9a-f-]{36}$/i.test(x)),
    loginUrl: (raw && raw.loginUrl) || null,
    homepage: row.homepage_url || (raw && raw.homepage) || null,
    identifiersKnown: !!(raw && (Array.isArray(raw.replyUrls) || Array.isArray(raw.servicePrincipalNames))),
  };
}

/* ------------------------------------------------------- discover: Okta */

const OKTA_CLASSES = [
  { kind: 'authenticator', path: '/api/v1/authenticators', name: (x) => x.name, status: (x) => x.status },
  { kind: 'factor', path: '/api/v1/org/factors', name: (x) => x.factorType + (x.provider ? ' (' + x.provider + ')' : ''), status: (x) => x.status, id: (x) => x.id || (x.provider + ':' + x.factorType) },
  { kind: 'agent_pool', path: '/api/v1/agentPools', name: (x) => x.name, status: (x) => x.operationalStatus || (x.agents && x.agents.some((a) => a.operationalStatus === 'OPERATIONAL') ? 'OPERATIONAL' : 'UNKNOWN'), id: (x) => x.id },
  { kind: 'idp', path: '/api/v1/idps', name: (x) => x.name, status: (x) => x.status },
  { kind: 'trusted_origin', path: '/api/v1/trustedOrigins', name: (x) => x.name + ' ' + x.origin, status: (x) => x.status },
  { kind: 'event_hook', path: '/api/v1/eventHooks', name: (x) => x.name, status: (x) => x.status },
  { kind: 'inline_hook', path: '/api/v1/inlineHooks', name: (x) => x.name, status: (x) => x.status },
  { kind: 'api_token', path: '/api/v1/api-tokens', name: (x) => x.name, status: (x) => (x.expiresAt && new Date(x.expiresAt) < new Date() ? 'EXPIRED' : 'ACTIVE') },
  { kind: 'zone', path: '/api/v1/zones', name: (x) => x.name, status: (x) => x.status },
  { kind: 'domain', path: '/api/v1/domains', name: (x) => x.domain, status: (x) => x.validationStatus, list: (b) => (b && b.domains) || [] },
  { kind: 'brand', path: '/api/v1/brands', name: (x) => x.name, status: () => 'ACTIVE' },
  { kind: 'group_rule', path: '/api/v1/groups/rules?limit=200', name: (x) => x.name, status: (x) => x.status },
  { kind: 'behavior', path: '/api/v1/behaviors', name: (x) => x.name, status: (x) => x.status },
  { kind: 'device_assurance', path: '/api/v1/device-assurances', name: (x) => x.name, status: () => 'ACTIVE' },
];

async function discoverOktaScope(log) {
  const coverage = {};
  const at = new Date();
  await pool.query(`UPDATE oem_okta_object SET seen_in_last_discovery=0`);
  // Apps come from the okta_apps mirror (its own paced job owns the 50/min bucket).
  const [apps] = await pool.query(`SELECT okta_id, name, label, status, sign_on_mode, features_json, assigned_user_count, assigned_group_count, last_synced_at, seen_in_last_sync, raw_json FROM okta_apps`);
  const [[appSync]] = await pool.query(`SELECT completed_at, status FROM entra_sync_status WHERE job='okta_apps' ORDER BY id DESC LIMIT 1`);
  coverage.app = { status: apps.length ? 'mirror' : 'empty', count: apps.length, at: appSync ? appSync.completed_at : null, lastJobStatus: appSync ? appSync.status : null,
    note: 'From the nightly okta_apps mirror. Run "Refresh Okta apps" for a live read (paced: this endpoint allows 50 calls a minute).' };
  for (const a of apps) {
    const c = classifyOktaApp(a);
    await pool.query(`INSERT INTO oem_okta_object (kind, okta_id, name, status, details, collected_at, seen_in_last_discovery) VALUES ('app',?,?,?,?,?,1)
      ON DUPLICATE KEY UPDATE name=VALUES(name), status=VALUES(status), details=VALUES(details), collected_at=VALUES(collected_at), seen_in_last_discovery=1`,
      [a.okta_id, a.label, a.status, JSON.stringify({ name: a.name, signOnMode: a.sign_on_mode, classKind: c.kind, category: c.category, users: a.assigned_user_count, groups: a.assigned_group_count }), at]);
  }
  log(`apps: ${apps.length} from mirror (synced ${appSync ? appSync.completed_at : 'never'})`);

  for (const cls of OKTA_CLASSES) {
    if (log.cancelled()) throw new Error('cancelled');
    const r = await oktaGet(cls.path);
    if (r.status !== 200) {
      coverage[cls.kind] = { status: r.status === 403 || r.status === 401 ? 'denied' : 'error', count: null, at: at.toISOString(), note: r.error || ('HTTP ' + r.status) };
      log(`${cls.kind}: ${coverage[cls.kind].status} — ${coverage[cls.kind].note}`, 'warn');
      continue;
    }
    const list = cls.list ? cls.list(r.body) : (Array.isArray(r.body) ? r.body : []);
    let n = 0;
    for (const x of list) {
      const id = String((cls.id ? cls.id(x) : x.id) || '');
      if (!id) continue;
      await pool.query(`INSERT INTO oem_okta_object (kind, okta_id, name, status, details, collected_at, seen_in_last_discovery) VALUES (?,?,?,?,?,?,1)
        ON DUPLICATE KEY UPDATE name=VALUES(name), status=VALUES(status), details=VALUES(details), collected_at=VALUES(collected_at), seen_in_last_discovery=1`,
        [cls.kind, id, String(cls.name(x) || '').slice(0, 255), String(cls.status(x) || '').slice(0, 32), JSON.stringify(L.redact(x)), at]);
      n++;
    }
    coverage[cls.kind] = { status: 'ok', count: n, at: at.toISOString(), pagesFollowed: r.next ? 'more pages exist (only the first was read)' : undefined };
    log(`${cls.kind}: ${n}`);
  }
  // Policy classes are already mirrored by the policy collector; report their coverage from oem_meta.
  const lr = await L.metaGet('last_run', null);
  coverage.policy = { status: lr.v && lr.v.ok ? 'mirror' : (lr.v ? 'error' : 'empty'), count: lr.v && lr.v.counts ? lr.v.counts.okta_policies : null, at: lr.v ? lr.v.finished : null, note: 'From the policy snapshot (Refresh snapshot).' };
  const okta = await L.oktaIdentity();
  coverage._token = okta.known ? { login: okta.login, roles: okta.roles, canWriteOkta: okta.canWriteOkta } : { error: okta.error };
  await L.metaSet('discovery_coverage', { at: at.toISOString(), classes: coverage });
  return coverage;
}

/* ------------------------------------------------ discover: Entra extras */

async function refreshEntraSpExtras(log, { onlyIds = null } = {}) {
  let ids;
  if (onlyIds) ids = onlyIds;
  else {
    const [rows] = await pool.query(
      `SELECT DISTINCT e.entra_id FROM entra_apps e
        WHERE e.display_name LIKE 'SSO-%'
           OR e.entra_id IN (SELECT entra_app_id FROM app_matches WHERE entra_app_id IS NOT NULL)`);
    ids = rows.map((r) => r.entra_id);
  }
  const at = new Date();
  let ok = 0, denied = 0, err = 0;
  for (const id of ids) {
    if (log.cancelled()) throw new Error('cancelled');
    const row = { sp_id: id, app_id: null, sync_jobs: null, sync_status: null, cert_thumbprint: null, cert_expires: null, saml_settings: null, fetch_error: null };
    const sp = await graphGet(`/v1.0/servicePrincipals/${id}?$select=id,appId,keyCredentials,preferredTokenSigningKeyThumbprint,samlSingleSignOnSettings,preferredSingleSignOnMode,notificationEmailAddresses`);
    if (sp.status === 200 && sp.body) {
      row.app_id = sp.body.appId || null;
      const thumb = sp.body.preferredTokenSigningKeyThumbprint || null;
      const keys = Array.isArray(sp.body.keyCredentials) ? sp.body.keyCredentials : [];
      const signing = keys.filter((k) => k.usage === 'Sign' || k.usage === 'Verify');
      let chosen = null;
      if (thumb) chosen = signing.find((k) => k.customKeyIdentifier && Buffer.from(k.customKeyIdentifier, 'base64').toString('hex').toUpperCase() === thumb.toUpperCase()) || null;
      if (!chosen && signing.length) chosen = signing.slice().sort((a, b) => new Date(b.endDateTime) - new Date(a.endDateTime))[0];
      row.cert_thumbprint = thumb || (chosen && chosen.customKeyIdentifier ? Buffer.from(chosen.customKeyIdentifier, 'base64').toString('hex').toUpperCase() : null);
      row.cert_expires = chosen && chosen.endDateTime ? new Date(chosen.endDateTime) : null;
      row.saml_settings = JSON.stringify({ samlSingleSignOnSettings: sp.body.samlSingleSignOnSettings || null, preferredSingleSignOnMode: sp.body.preferredSingleSignOnMode || null, notificationEmailAddresses: sp.body.notificationEmailAddresses || [], signingCertCount: signing.length });
    } else row.fetch_error = 'sp: ' + (sp.error || sp.status);
    const jobs = await graphGet(`/v1.0/servicePrincipals/${id}/synchronization/jobs`);
    if (jobs.status === 200) {
      const list = (jobs.body && jobs.body.value) || [];
      row.sync_jobs = JSON.stringify(list.map((x) => ({ id: x.id, templateId: x.templateId, state: x.status && x.status.code, lastExecution: x.status && x.status.lastExecution && x.status.lastExecution.timeBegan, lastSuccess: x.status && x.status.lastSuccessfulExecution && x.status.lastSuccessfulExecution.timeBegan, escrows: x.status && x.status.escrowsPruned, quarantine: x.status && x.status.quarantine ? { reason: x.status.quarantine.reason, current: x.status.quarantine.currentBegan } : null })));
      row.sync_status = list.length ? 'configured' : 'none';
      ok++;
    } else if (jobs.status === 403) { row.sync_status = 'denied'; denied++; row.fetch_error = (row.fetch_error ? row.fetch_error + '; ' : '') + 'sync: ' + jobs.error; }
    else if (jobs.status === 404 || jobs.status === 400) { row.sync_status = 'not_supported'; ok++; }
    else { row.sync_status = 'error'; err++; row.fetch_error = (row.fetch_error ? row.fetch_error + '; ' : '') + 'sync: ' + (jobs.error || jobs.status); }
    await pool.query(`INSERT INTO oem_entra_sp (sp_id, app_id, sync_jobs, sync_status, cert_thumbprint, cert_expires, saml_settings, fetch_error, collected_at) VALUES (?,?,?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE app_id=VALUES(app_id), sync_jobs=VALUES(sync_jobs), sync_status=VALUES(sync_status), cert_thumbprint=VALUES(cert_thumbprint), cert_expires=VALUES(cert_expires), saml_settings=VALUES(saml_settings), fetch_error=VALUES(fetch_error), collected_at=VALUES(collected_at)`,
      [row.sp_id, row.app_id, row.sync_jobs, row.sync_status, row.cert_thumbprint, row.cert_expires, row.saml_settings, row.fetch_error, at]);
  }
  log(`entra principal extras: ${ids.length} read (provisioning ok ${ok}, denied ${denied}, error ${err})`);
  return { read: ids.length, ok, denied, err };
}

/* ------------------------------------------------------------- matcher */

function scorePair(o, e) {
  const ev = [];
  let score = 0;
  const push = (s, m, detail) => { ev.push({ method: m, score: s, detail }); if (s > score) score = s; };
  if (o.ids.launcherAppId && e.ids.appId && o.ids.launcherAppId === e.ids.appId) push(1.0, 'launcher_app_id', o.ids.launcherAppId);
  const spn = new Set(e.ids.identifierUris.map(normUrl));
  const reply = new Set(e.ids.replyUrls.map(normUrl));
  const replyHosts = new Set(e.ids.replyHosts);
  for (const a of o.ids.audience) if (spn.has(normUrl(a))) push(1.0, 'audience_equals_identifier_uri', a);
  for (const a of o.ids.acs) if (reply.has(normUrl(a))) push(1.0, 'acs_equals_reply_url', a);
  for (const a of o.ids.acs) { const h = hostOf(a); if (h && replyHosts.has(h)) push(0.8, 'acs_host_equals_reply_host', h); }
  for (const r of o.ids.redirects) { const h = hostOf(r); if (h && replyHosts.has(h)) push(0.8, 'redirect_host_equals_reply_host', h); }
  for (const h of o.ids.vendorHints) {
    if (h.length < 4 || /^(www|app|login|auth|sso|api)$/.test(h) || IDP_HOST_RE.test(h)) continue;
    const hostLike = h.includes('.'); // a host hint matches on label boundaries; a bare tenant word may appear inside a host
    for (const rh of e.ids.replyHosts) { if (IDP_HOST_RE.test(rh)) continue; if (hostLike ? hostMatches(h, rh) : rh.includes(h)) { push(0.65, 'tenant_hint_in_reply_host', h + ' ~ ' + rh); break; } }
    for (const u of e.ids.identifierUris) {
      const ul = u.toLowerCase(), uh = hostOf(ul);
      if (uh && IDP_HOST_RE.test(uh)) continue;
      if (hostLike ? (!!uh && hostMatches(h, uh)) : ul.includes(h)) { push(0.65, 'tenant_hint_in_identifier_uri', h); break; }
    }
  }
  const shared = o.tok.filter((t) => e.tokSet.has(t));
  const jac = jaccard(o.tok, e.tok);
  if (shared.length >= 2 && jac >= 0.5) push(0.5, 'name_similarity', shared.join(' '));
  else if (shared.length >= 1 && jac >= 0.25) push(0.35, 'name_similarity', shared.join(' '));
  else if (shared.length >= 1 && shared.some((t) => t.length >= 5)) push(0.2, 'name_similarity', shared.join(' '));
  if (!ev.length) return null;
  const identifierMatch = ev.some((x) => x.score >= 0.95);
  if (identifierMatch && shared.length) score = Math.min(1, score + 0.0); // identifiers already decisive
  let envConflict = false, envUnclear = false;
  if (o.env && e.env && o.env !== e.env) { envConflict = true; score = identifierMatch ? 0.75 : score * 0.3; }
  else if ((o.env && !e.env) || (!o.env && e.env)) { envUnclear = true; if (!identifierMatch) score = score * 0.5; } // one side names an environment, the other (usually production) does not
  return { score: +score.toFixed(3), evidence: ev.sort((a, b) => b.score - a.score), envConflict, envUnclear, envOkta: o.env, envEntra: e.env };
}

function confidenceFor(score) {
  if (score >= 0.95) return 'auto_high';
  if (score >= 0.6) return 'auto_medium';
  if (score >= 0.2) return 'auto_low';
  return null;
}

async function runMatcher(log) {
  const at = new Date();
  const [oktaRows] = await pool.query(`SELECT okta_id, name, label, status, sign_on_mode, raw_json FROM okta_apps`);
  const [entraRows] = await pool.query(`SELECT entra_id, app_id, display_name, preferred_single_sign_on_mode, homepage_url, account_enabled, service_principal_type, seen_in_last_sync, raw_json FROM entra_apps`);
  const [existing] = await pool.query(`SELECT id, okta_app_id, entra_app_id, entra_app_display_name, match_confidence, match_method, created_by, created_at, last_verified_at, notes FROM app_matches`);
  const tombstoned = await tombstonedSet(pool);
  const mirrorKnown = entraRows.length > 0; // an empty mirror is "unknown", never "everything was deleted"
  const byOkta = new Map();
  for (const r of existing) { if (!byOkta.has(r.okta_app_id)) byOkta.set(r.okta_app_id, []); byOkta.get(r.okta_app_id).push(r); }

  const entra = entraRows
    .filter((e) => e.service_principal_type !== 'ManagedIdentity')
    .filter((e) => e.seen_in_last_sync !== 0 && !tombstoned.has(e.entra_id)) // a principal the last sync did not see, or a recorded tombstone, is not a target
    .map((e) => {
      const raw = j(e.raw_json, {}) || {};
      const ids = entraIdentifiers(raw, e);
      const tok = tokens(e.display_name);
      return { row: e, ids, tok, tokSet: new Set(tok), env: entraEnv(e.display_name, ids) };
    });
  const entraAlive = new Set(entra.map((e) => e.row.entra_id));
  const identifiersKnown = entra.filter((e) => e.ids.identifiersKnown).length;
  log(`entra principals: ${entra.length} (${identifiersKnown} with reply URLs / identifier URIs in the mirror)`);
  if (identifiersKnown === 0) log('the Entra mirror carries no reply URLs yet — only launcher links and names can match until "Refresh Entra apps" runs', 'warn');

  await pool.query(`DELETE FROM oem_match_candidate`);
  const stats = { scope: 0, auto_high: 0, auto_medium: 0, auto_low: 0, none: 0, manualKept: 0, staleDecisions: 0, conflicts: 0, updated: 0, inserted: 0, autoRowsRemoved: 0 };
  const targetCount = new Map();

  for (const o of oktaRows) {
    if (log.cancelled()) throw new Error('cancelled');
    const cls = classifyOktaApp(o);
    if (cls.category !== 'applications' || cls.kind === 'other_app') continue;
    stats.scope++;
    const raw = j(o.raw_json, {}) || {};
    const ids = oktaIdentifiers(raw);
    const tok = tokens((o.label || '') + ' ' + (o.name || ''));
    const os = { ids, tok, env: envOf((o.label || '') + ' ' + ids.acs.join(' ') + ' ' + ids.audience.join(' ') + ' ' + (ids.bookmarkUrl || '')) };
    const rows = byOkta.get(o.okta_id) || [];
    const rejected = new Set(rows.filter((r) => r.match_confidence === 'manual_rejected').map((r) => r.entra_app_id));
    const confirmed = rows.find((r) => r.match_confidence === 'manual_confirmed');
    const staged = rows.find((r) => r.match_confidence === 'manual_staged');
    const alive = (r) => !!(r && r.entra_app_id) && (!mirrorKnown || entraAlive.has(r.entra_app_id));
    const confirmedAlive = alive(confirmed);

    const cands = [];
    for (const e of entra) {
      const s = scorePair(os, e);
      if (s && s.score >= 0.2) cands.push({ e, ...s });
    }
    // conf-1: equal scores are ordered by how much evidence backs them, then by name — never by insertion order
    cands.sort((a, b) => (b.score - a.score) || (b.evidence.length - a.evidence.length) || String(a.e.row.display_name || '').localeCompare(String(b.e.row.display_name || '')));
    const top = cands.slice(0, 5);
    for (const c of top) {
      await pool.query(`INSERT INTO oem_match_candidate (okta_app_id, entra_app_id, score, method, evidence, env_okta, env_entra, env_conflict, computed_at) VALUES (?,?,?,?,?,?,?,?,?)
        ON DUPLICATE KEY UPDATE score=VALUES(score), method=VALUES(method), evidence=VALUES(evidence), env_okta=VALUES(env_okta), env_entra=VALUES(env_entra), env_conflict=VALUES(env_conflict), computed_at=VALUES(computed_at)`,
        [o.okta_id, c.e.row.entra_id, c.score, c.evidence[0].method, JSON.stringify({ evidence: c.evidence, envUnclear: c.envUnclear, rejected: rejected.has(c.e.row.entra_id), conflictsWithConfirmed: !!(confirmedAlive && confirmed.entra_app_id !== c.e.row.entra_id && c.score >= 0.95) }), c.envOkta, c.envEntra, c.envConflict ? 1 : 0, at]);
    }
    const best = top.find((c) => !rejected.has(c.e.row.entra_id)) || null;
    const autoRows = rows.filter((r) => !/^manual_/.test(r.match_confidence));

    if (confirmed || staged) {
      stats.manualKept++;
      const keep = confirmed || staged;
      const keepAlive = alive(keep);
      if (!keepAlive && keep.entra_app_id) {
        // bug 1: the recorded decision points at an object id the Entra mirror no longer has. The decision
        // stays in app_matches (history); a tombstone records what it pointed at, and the candidates just
        // computed above are the replacements the panel offers. Nothing is bound automatically.
        stats.staleDecisions++;
        await recordTombstone(pool, { entraId: keep.entra_app_id, appId: null, displayName: keep.entra_app_display_name || null, lastSeenAt: keep.last_verified_at || keep.created_at || null, detectedBy: 'matcher',
          snapshot: { oktaAppId: o.okta_id, oktaLabel: o.label, matchRowId: keep.id, matchConfidence: keep.match_confidence, by: keep.created_by, at: keep.created_at } }, log);
        log(`${o.label}: ${keep.match_confidence} target ${keep.entra_app_id} (${keep.entra_app_display_name || 'unnamed'}) is gone from the Entra mirror — tombstoned; ${top.length} replacement candidate(s) recorded`, 'warn');
      }
      if (keepAlive && best && best.score >= 0.95 && best.e.row.entra_id !== keep.entra_app_id) stats.conflicts++;
      // A recorded decision owns this app: any auto rows beside it are the double-row bug.
      if (autoRows.length) { await pool.query(`DELETE FROM app_matches WHERE id IN (?)`, [autoRows.map((r) => r.id)]); stats.autoRowsRemoved += autoRows.length; }
      if (keepAlive) targetCount.set(keep.entra_app_id, (targetCount.get(keep.entra_app_id) || 0) + 1);
      continue;
    }
    const conf = best ? confidenceFor(best.score) : null;
    const method = best ? `${best.evidence[0].method}=${best.score}${best.envConflict ? ' env-conflict' : ''}${o.status === 'INACTIVE' ? ' inactive' : ''}` : (rejected.size ? 'all_candidates_rejected' : 'okta_only');
    const target = conf ? best.e.row : null;
    if (conf) { stats[conf]++; targetCount.set(target.entra_id, (targetCount.get(target.entra_id) || 0) + 1); } else stats.none++;
    const keepRow = autoRows[0] || null;
    const extra = autoRows.slice(1);
    if (extra.length) { await pool.query(`DELETE FROM app_matches WHERE id IN (?)`, [extra.map((r) => r.id)]); stats.autoRowsRemoved += extra.length; }
    if (keepRow) {
      await pool.query(`UPDATE app_matches SET okta_app_label=?, entra_app_id=?, entra_app_display_name=?, match_confidence=?, match_method=?, last_verified_at=?, created_by=IF(created_by IS NULL OR created_by='', 'auto-matcher', created_by) WHERE id=?`,
        [o.label, target ? target.entra_id : null, target ? target.display_name : null, conf || 'both_missing', method.slice(0, 64), at, keepRow.id]);
      stats.updated++;
    } else {
      await pool.query(`INSERT INTO app_matches (okta_app_id, okta_app_label, entra_app_id, entra_app_display_name, match_confidence, match_method, created_by, last_verified_at) VALUES (?,?,?,?,?,?,'auto-matcher',?)`,
        [o.okta_id, o.label, target ? target.entra_id : null, target ? target.display_name : null, conf || 'both_missing', method.slice(0, 64), at]);
      stats.inserted++;
    }
  }
  const shared = [...targetCount.entries()].filter(([, n]) => n > 1).length;
  await L.metaSet('matcher_last', { at: at.toISOString(), stats, sharedTargets: shared, identifiersKnown, entraTotal: entra.length });
  log(`matcher: scope ${stats.scope}, high ${stats.auto_high}, medium ${stats.auto_medium}, low ${stats.auto_low}, none ${stats.none}, decisions kept ${stats.manualKept} (${stats.staleDecisions} pointing at a deleted principal), conflicts ${stats.conflicts}, shared targets ${shared}`);
  return { ...stats, sharedTargets: shared };
}

/* --------------------------------------------------------- work items */

const KEEP_STATES = new Set(['running', 'waiting_technician', 'blocked', 'awaiting_validation', 'verified', 'retired']);

/** Writes one item on `q` — the transaction connection buildWorkItems opened (bug 11), never the pool. */
async function upsertItem(q, item, at) {
  const [[cur]] = await q.query(`SELECT state, disposition, first_seen_at FROM oem_work_item WHERE item_key=?`, [item.key]);
  let state = item.autoState;
  let note = 'discovery re-evaluated this item';
  /* tombstone-2: Verified / Awaiting Validation cannot stand once the matched Entra application is gone — the evidence
     was recorded against a destination that no longer exists. Those two drop to needs_review (the recomputed auto state)
     with an auto_state_changed event; retired and the in-flight technician states are kept as before. */
  const destinationGone = !!(item.facts && item.facts.match && item.facts.match.decision === 'invalidated');
  if (cur && KEEP_STATES.has(cur.state)) {
    if (destinationGone && (cur.state === 'verified' || cur.state === 'awaiting_validation')) {
      state = 'needs_review';
      const t = (item.facts.match.tombstone) || {};
      note = `the matched Entra application "${t.name || item.facts.match.entraName || item.facts.match.entraId || 'unknown'}" no longer exists in Entra; ${cur.state === 'verified' ? 'Verified' : 'Awaiting Validation'} cannot stand without a destination — resolve the destination and verify again`;
    } else state = cur.state;
  }
  const disposition = cur && cur.disposition ? cur.disposition : (item.disposition || null);
  await q.query(`INSERT INTO oem_work_item (item_key, category, title, source_kind, source_id, source_status, disposition, state, auto_state, facts, first_seen_at, last_seen_at, seen_in_last_discovery)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)
    ON DUPLICATE KEY UPDATE title=VALUES(title), source_status=VALUES(source_status), disposition=VALUES(disposition), state=VALUES(state), auto_state=VALUES(auto_state), facts=VALUES(facts), last_seen_at=VALUES(last_seen_at), seen_in_last_discovery=1`,
    [item.key, item.category, item.title.slice(0, 255), item.sourceKind, String(item.sourceId).slice(0, 96), item.sourceStatus || null, disposition, state, item.autoState, JSON.stringify(item.facts), at, at]);
  if (!cur) await q.query(`INSERT INTO oem_work_event (item_key, event, to_state, note, actor_email) VALUES (?,'discovered',?,?, 'discovery')`, [item.key, state, item.title.slice(0, 200)]);
  else if (cur.state !== state) await q.query(`INSERT INTO oem_work_event (item_key, event, from_state, to_state, note, actor_email) VALUES (?,'auto_state_changed',?,?,?, 'discovery')`, [item.key, cur.state, state, note.slice(0, 500)]);
}

/**
 * One next action per application. Codes: review_retire, resolve_destination, review_swa, compare, validate,
 * review_match, create_entra, choose_destination. The label never mentions SAML for a bookmark or SWA app (bug 6),
 * "Review the suggested match" needs a living target or candidate (bug 5), and a deleted target is
 * "Resolve destination" — never "Finish the staged review" (bug 1).
 */
function nextActionForApp(f) {
  const okta = f.okta, m = f.match || {};
  const w = launcherWords(okta);
  const cands = (m.candidates || []).filter((c) => c && !c.rejected && !c.tombstoned);
  if (okta.status === 'INACTIVE') return { code: 'review_retire', label: 'Review for retirement', cls: 'technician', why: 'Inactive in Okta. Confirm nothing depends on it, then record it as retired or excluded.' };
  if (m.decision === 'invalidated') {
    const t = m.tombstone || {};
    const name = t.name || m.entraName || m.entraId || 'unknown';
    return { code: 'resolve_destination', label: 'Resolve destination', cls: 'technician',
      why: `The matched Entra application "${name}" no longer exists in Entra${t.lastSeenAt ? ' (last seen ' + dateOnly(t.lastSeenAt) + ')' : ''}. The previous decision is kept in history but cannot be used: pick a replacement${cands.length ? ' (' + cands.length + ' suggested)' : ''}, create a new Entra app, or clear the stale match.` };
  }
  if (w.kind === 'swa') return { code: 'review_swa', label: 'Decide: password SSO in Entra, or retire', cls: 'technician', why: 'Okta signs users in by filling a password (SWA). Entra offers password-based SSO through the My Apps extension; there is no identifier to match automatically.' };
  if (m.decision === 'manual_confirmed') {
    if (f.differences.some((d) => d.severity === 'high')) return { code: 'compare', label: 'Compare configuration', cls: 'analysis', why: 'The confirmed Entra app differs from Okta in a way that would change ' + (w.kind === 'bookmark' ? 'where the link lands' : 'sign-in') + '. Resolve the differences before validating.' };
    return { code: 'validate', label: 'Validate sign-in and assignments', cls: 'technician',
      why: w.kind === 'bookmark' ? 'Configuration matches on the fields we can read. A person opens the Entra My Apps tile, confirms it reaches the right destination, and checks the assignments — a bookmark has no claims to verify.'
        : 'Configuration matches on the fields we can read. A person must sign in through Entra and confirm assignments, claims and provisioning.' };
  }
  if (m.decision === 'manual_staged' && f.entra) return { code: 'review_match', label: 'Finish the staged review', cls: 'technician', why: 'Somebody staged this pair without confirming it.' };
  const noCandidate = !f.entra && !cands.length;
  if (m.decision === 'manual_rejected' && noCandidate) return { code: 'create_entra', label: 'Create the Entra enterprise app', cls: 'browser', why: 'Every suggested Entra app was rejected and nothing else matches this Okta ' + w.noun + ' on identifiers or launcher link. Create it in Entra (Claude in Chrome can drive the portal), then rerun matching.' };
  if (noCandidate) return { code: 'choose_destination', label: 'Find the Entra app', cls: 'technician', why: 'No Entra application matches this Okta ' + w.noun + ' on identifiers or launcher link, and no candidate was suggested. Search the Entra catalog for the right application, or create a new Entra app.' };
  return { code: 'review_match', label: 'Review the suggested match', cls: 'technician', why: m.decision === 'auto_high' ? 'Matched on a durable identifier. Confirm it to move on.' : 'Matched on a weaker signal (host or name). Check the evidence before confirming.' };
}

async function buildWorkItems(log) {
  const at = new Date();
  const generation = at.getTime();
  const items = [];             // every row is computed first; nothing is written until the transaction at the end (bug 11)
  const tombstones = new Map(); // entraId -> record for oem_entra_tombstone, written in the same transaction (bug 1)
  // destinationsDeleted / matchesInvalidated / matchRowsChanged: what this build reconciled (SPEC 85: the refresh center
  // reports deleted objects, invalidated matches and reconciliation changes per run, from the job result).
  const counts = { applications: 0, policies: 0, mfa: 0, network_device: 0, dependencies: 0, destinationsDeleted: 0, matchesInvalidated: 0, matchRowsChanged: 0 };

  /* ---- applications + app-shaped dependencies ---- */
  const [apps] = await pool.query(`SELECT okta_id, name, label, status, sign_on_mode, features_json, assigned_user_count, assigned_group_count, created_at_okta, last_updated_at_okta, last_synced_at, raw_json FROM okta_apps`);
  const [matches] = await pool.query(`SELECT * FROM app_matches`);
  const [cands] = await pool.query(`SELECT * FROM oem_match_candidate ORDER BY okta_app_id, score DESC`);
  const [entraRows] = await pool.query(`SELECT entra_id, app_id, display_name, preferred_single_sign_on_mode, account_enabled, app_role_assignment_required, assigned_user_count, assigned_group_count, homepage_url, seen_in_last_sync, raw_json, last_synced_at FROM entra_apps`);
  const [extras] = await pool.query(`SELECT * FROM oem_entra_sp`);
  const [policies] = await pool.query(`SELECT policy_id, name, policy_type, app_names FROM oem_okta_policy WHERE policy_type='ACCESS_POLICY'`);
  const tombstoned = await tombstonedSet(pool);
  const mirrorKnown = entraRows.length > 0; // an empty mirror is "unknown", never "everything was deleted"
  const entraById = new Map(entraRows.filter((e) => e.seen_in_last_sync !== 0 && !tombstoned.has(e.entra_id)).map((e) => [e.entra_id, e]));
  const staleById = new Map(entraRows.filter((e) => !entraById.has(e.entra_id)).map((e) => [e.entra_id, e]));
  const extraById = new Map(extras.map((x) => [x.sp_id, x]));
  const matchBy = new Map(); for (const m of matches) { if (!matchBy.has(m.okta_app_id)) matchBy.set(m.okta_app_id, []); matchBy.get(m.okta_app_id).push(m); }
  const candBy = new Map(); for (const c of cands) { if (!candBy.has(c.okta_app_id)) candBy.set(c.okta_app_id, []); candBy.get(c.okta_app_id).push(c); }
  const targetUse = new Map(); for (const m of matches) if (m.entra_app_id && /^(manual_confirmed|auto_)/.test(m.match_confidence)) targetUse.set(m.entra_app_id, (targetUse.get(m.entra_app_id) || 0) + 1);
  const policyByApp = new Map(); for (const p of policies) for (const n of j(p.app_names, [])) policyByApp.set(n, p.name);

  const depApps = [];
  for (const a of apps) {
    const cls = classifyOktaApp(a);
    const raw = j(a.raw_json, {}) || {};
    if (cls.category === 'dependencies') { depApps.push({ a, cls, raw }); continue; }
    const feats = j(a.features_json, []) || [];
    const ids = oktaIdentifiers(raw);
    const rows = matchBy.get(a.okta_id) || [];
    const decisionRow = rows.find((r) => r.match_confidence === 'manual_confirmed') || rows.find((r) => r.match_confidence === 'manual_staged') || rows.find((r) => /^auto_/.test(r.match_confidence)) || rows.find((r) => r.match_confidence === 'both_missing') || null;
    const rejectedRows = rows.filter((r) => r.match_confidence === 'manual_rejected');
    let decision = decisionRow ? decisionRow.match_confidence : (rejectedRows.length ? 'manual_rejected' : 'none');
    const target = (decisionRow && decisionRow.entra_app_id ? entraById.get(decisionRow.entra_app_id) : null) || null;
    let tombstone = null;
    if (decisionRow && decisionRow.entra_app_id && !target && mirrorKnown) {
      // bug 1: the decision points at an object id the current Entra generation does not have. The row stays
      // (history); the destination becomes a tombstone and the next action is "Resolve destination".
      const gone = staleById.get(decisionRow.entra_app_id) || null;
      const ex = extraById.get(decisionRow.entra_app_id) || null;
      const name = decisionRow.entra_app_display_name || (gone && gone.display_name) || decisionRow.entra_app_id;
      const lastSeenAt = (gone && gone.last_synced_at) || decisionRow.last_verified_at || decisionRow.created_at || null;
      tombstone = { entraId: decisionRow.entra_app_id, appId: (gone && gone.app_id) || (ex && ex.app_id) || null, name, lastSeenAt, detectedAt: at, detectedBy: 'discovery', previousDecision: decision, by: decisionRow.created_by || null, at: decisionRow.created_at || null };
      if (!tombstones.has(tombstone.entraId)) tombstones.set(tombstone.entraId, { entraId: tombstone.entraId, appId: tombstone.appId, displayName: name, lastSeenAt, detectedBy: 'discovery',
        snapshot: { oktaAppId: a.okta_id, oktaLabel: a.label, matchRowId: decisionRow.id, matchConfidence: decision, by: decisionRow.created_by || null, at: decisionRow.created_at || null } });
      decision = 'invalidated'; counts.matchesInvalidated++;
    }
    const targetRaw = target ? (j(target.raw_json, {}) || {}) : null;
    const tIds = target ? entraIdentifiers(targetRaw, target) : null;
    const tExtra = target ? extraById.get(target.entra_id) : null;
    // candidates: only principals that exist in the current generation; a tombstoned id is never offered again
    const cl = (candBy.get(a.okta_id) || []).filter((c) => !tombstoned.has(c.entra_app_id) && !tombstones.has(c.entra_app_id) && (!mirrorKnown || entraById.has(c.entra_app_id))).map((c) => { const e = entraById.get(c.entra_app_id); const ev = j(c.evidence, {}); return { entraId: c.entra_app_id, name: e ? e.display_name : c.entra_app_id, score: Number(c.score), method: c.method, evidence: ev.evidence || [], envConflict: !!c.env_conflict, envOkta: c.env_okta, envEntra: c.env_entra, rejected: !!ev.rejected, conflictsWithConfirmed: !!ev.conflictsWithConfirmed }; });
    const conflict = cl.find((c) => c.conflictsWithConfirmed) || null;
    const provisioning = feats.some((x) => PROVISIONING_FEATURES.has(x));
    const okta = {
      id: a.okta_id, label: a.label, name: a.name, status: a.status, signOnMode: a.sign_on_mode, classKind: cls.kind,
      users: a.assigned_user_count, groups: a.assigned_group_count, features: feats, provisioning,
      created: a.created_at_okta, lastUpdated: a.last_updated_at_okta, mirroredAt: a.last_synced_at,
      accessPolicy: policyByApp.get(a.label) || null,
      identifiers: ids,
      hidden: !!(raw.visibility && raw.visibility.hide && raw.visibility.hide.web),
      signingKid: raw.credentials && raw.credentials.signing ? raw.credentials.signing.kid : null,
    };
    const entra = target ? {
      id: target.entra_id, appId: target.app_id, name: target.display_name, ssoMode: target.preferred_single_sign_on_mode, enabled: !!target.account_enabled,
      assignmentRequired: !!target.app_role_assignment_required, users: target.assigned_user_count, groups: target.assigned_group_count,
      replyUrls: tIds.replyUrls, identifierUris: tIds.identifierUris, loginUrl: tIds.loginUrl, identifiersKnown: tIds.identifiersKnown, mirroredAt: target.last_synced_at,
      isSsoPrefixed: /^SSO-/.test(target.display_name || ''),
      provisioning: tExtra ? { status: tExtra.sync_status, jobs: j(tExtra.sync_jobs, []), collectedAt: tExtra.collected_at } : { status: 'unknown', jobs: [], collectedAt: null },
      cert: tExtra ? { thumbprint: tExtra.cert_thumbprint, expires: tExtra.cert_expires } : null,
      sharedBy: targetUse.get(target.entra_id) || 1,
    } : null;
    const differences = [], missing = [];
    if (entra) {
      if (a.sign_on_mode === 'BOOKMARK') differences.push({ kind: 'protocol', severity: 'info', text: 'The Okta tile is a bookmark: it does not authenticate. Where the link actually signs in is what matters (' + (ids.launcherAppId ? 'it points at Entra My Apps' : ids.oktaHosted ? 'it points at an Okta-hosted SAML link — still an Okta dependency' : 'it points at ' + (hostOf(ids.bookmarkUrl) || 'an unknown host')) + ').' });
      if (a.sign_on_mode === 'SAML_2_0' && entra.ssoMode && entra.ssoMode !== 'saml') differences.push({ kind: 'protocol', severity: 'high', text: `Okta uses SAML; the Entra app is configured for ${entra.ssoMode}.` });
      if (a.sign_on_mode === 'OPENID_CONNECT' && entra.ssoMode && entra.ssoMode !== 'oidc') differences.push({ kind: 'protocol', severity: 'high', text: `Okta uses OpenID Connect; the Entra app is configured for ${entra.ssoMode}.` });
      if (!entra.ssoMode && a.sign_on_mode !== 'BOOKMARK') differences.push({ kind: 'protocol', severity: 'high', text: 'The Entra app has no single sign-on mode configured yet.' });
      const eo = envOf(a.label), ee = entraEnv(entra.name, { identifierUris: entra.identifierUris || [], replyHosts: (entra.replyUrls || []).map(hostOf).filter(Boolean) });
      if (eo && ee && eo !== ee) differences.push({ kind: 'environment', severity: 'high', text: `Environment mismatch: Okta "${a.label}" reads as ${eo}; the Entra app reads as ${ee}.` });
      else if (!eo && ee) differences.push({ kind: 'environment', severity: 'high', text: `Environment mismatch: the Entra app reads as ${ee} (name or reply URL); the Okta app names no environment, which usually means production.` });
      else if (eo && !ee) differences.push({ kind: 'environment', severity: 'medium', text: `Environment: the Okta app reads as ${eo}; the Entra app names no environment. Confirm it is the ${eo} tenant of the vendor.` });
      if (a.sign_on_mode === 'SAML_2_0' && entra.identifiersKnown) {
        const spn = new Set(entra.identifierUris.map(normUrl)), rep = new Set(entra.replyUrls.map(normUrl));
        if (ids.audience.length && !ids.audience.some((x) => spn.has(normUrl(x)))) differences.push({ kind: 'audience', severity: 'medium', text: `Okta audience (${ids.audience[0]}) is not one of the Entra identifier URIs${entra.identifierUris.length ? ' (' + entra.identifierUris.slice(0, 2).join(', ') + ')' : ' (none set)'}.` });
        if (ids.acs.length && !ids.acs.some((x) => rep.has(normUrl(x)))) differences.push({ kind: 'acs', severity: 'medium', text: `Okta ACS URL (${ids.acs[0]}) is not one of the Entra reply URLs${entra.replyUrls.length ? ' (' + entra.replyUrls.slice(0, 2).join(', ') + ')' : ' (none set)'}.` });
      } else if (a.sign_on_mode === 'SAML_2_0' && !entra.identifiersKnown) missing.push('Entra reply URLs / identifier URIs are not in the mirror yet — run "Refresh Entra apps".');
      if (!entra.enabled) differences.push({ kind: 'enabled', severity: 'high', text: 'The Entra app is disabled (accountEnabled = false).' });
      if (entra.assignmentRequired && (entra.users || 0) + (entra.groups || 0) === 0 && (a.assigned_user_count || 0) > 0) differences.push({ kind: 'assignments', severity: 'high', text: `Entra requires assignment and has none; Okta has ${a.assigned_user_count} users / ${a.assigned_group_count} groups assigned.` });
      else if ((a.assigned_user_count || 0) > 0 && (entra.users || 0) === 0 && (entra.groups || 0) === 0) differences.push({ kind: 'assignments', severity: 'medium', text: `Okta has ${a.assigned_user_count} assigned users; the Entra mirror shows no assignments.` });
      if (provisioning && entra.provisioning.status === 'none') differences.push({ kind: 'provisioning', severity: 'high', text: 'Okta provisions this app (' + feats.filter((x) => PROVISIONING_FEATURES.has(x)).join(', ') + '); the Entra app has no provisioning job.' });
      if (provisioning && entra.provisioning.status === 'unknown') missing.push('Entra provisioning state not read yet.');
      if (provisioning && entra.provisioning.status === 'denied') missing.push('Entra provisioning state could not be read (Graph denied). Minimum permission: Application.Read.All is granted; synchronization jobs also need Synchronization.Read.All — an Entra Global Administrator can consent.');
      if (entra.cert && entra.cert.expires && new Date(entra.cert.expires) < new Date(Date.now() + 30 * 86400000)) differences.push({ kind: 'certificate', severity: 'high', text: `The Entra signing certificate expires ${new Date(entra.cert.expires).toISOString().slice(0, 10)}.` });
      if (entra.sharedBy > 1) differences.push({ kind: 'shared', severity: 'info', text: `${entra.sharedBy} Okta apps point at this Entra app. Each keeps its own SSO and provisioning requirement.` });
      if (!entra.isSsoPrefixed) differences.push({ kind: 'naming', severity: 'info', text: 'The Entra app is not SSO- prefixed; it is shown here only because it is matched or confirmed.' });
    } else if (tombstone) {
      missing.push(`The matched Entra application "${tombstone.name}" no longer exists in Entra (last seen ${tombstone.lastSeenAt ? dateOnly(tombstone.lastSeenAt) : 'unknown'}).`);
    } else {
      if (a.status === 'ACTIVE' && cls.kind === 'sso_app') missing.push('No Entra enterprise application is matched to this Okta app.');
    }
    if (ids.oktaHosted) differences.push({ kind: 'okta_dependency', severity: 'high', text: 'This link signs in through Okta (' + hostOf(ids.oktaHosted) + '). It stays an Okta dependency until the target app is migrated and the link is repointed.' });
    if (provisioning) missing.push('Provisioning must be rebuilt in Entra (SCIM job) — Okta features: ' + feats.filter((x) => PROVISIONING_FEATURES.has(x)).join(', ') + '.');
    const w = launcherWords({ signOnMode: a.sign_on_mode, classKind: cls.kind });
    const facts = { okta, match: { decision, entraId: decisionRow ? decisionRow.entra_app_id : null, entraName: decisionRow ? decisionRow.entra_app_display_name : null, method: decisionRow ? decisionRow.match_method : null, by: decisionRow ? decisionRow.created_by : null, at: decisionRow ? decisionRow.created_at : null, verifiedAt: decisionRow ? decisionRow.last_verified_at : null, note: decisionRow ? decisionRow.notes : null, rowId: decisionRow ? decisionRow.id : null, tombstone, candidates: cl, rejected: rejectedRows.map((r) => ({ entraId: r.entra_app_id, name: r.entra_app_display_name, by: r.created_by, at: r.created_at })), conflict }, entra,
      differences: dedupeBy(differences, (d) => d.kind + '|' + d.text), missing: dedupeLines(missing) };
    facts.nextAction = nextActionForApp(facts);
    facts.verifyHow = dedupeLines([w.kind === 'bookmark' ? 'A user assigned in Entra opens the Entra My Apps tile and lands on the intended destination.' : 'A user assigned in Entra signs in from the Entra My Apps tile and lands in the app.', w.verifyClaims, provisioning ? 'A provisioning cycle runs in Entra without quarantine and the app shows the user.' : 'No provisioning to test (Okta did not provision this app).', w.verifyCutover]);
    facts.dependencyOnOkta = ids.oktaHosted ? 'Okta-hosted link' : (a.status === 'ACTIVE' ? w.still : null);
    let autoState = 'needs_review';
    if (decision === 'manual_confirmed' && !differences.some((d) => d.severity === 'high') && a.status === 'ACTIVE') autoState = 'ready';
    if (a.status === 'INACTIVE') autoState = 'needs_review';
    items.push({ key: 'app:' + a.okta_id, category: 'applications', title: a.label || a.name || a.okta_id, sourceKind: 'okta_app', sourceId: a.okta_id, sourceStatus: a.status, disposition: a.status === 'INACTIVE' ? 'retire' : (cls.kind === 'swa_app' ? 'investigate' : 'migrate'), autoState, facts });
    counts.applications++;
  }

  /* ---- dependencies: app-shaped ---- */
  const DEP_TEXT = {
    federation: { what: 'The auction.com domain is federated: Microsoft 365 sends every password sign-in to Okta (WS-Federation through the Okta "Office 365" app). This is the single biggest Okta dependency.', change: 'Convert auction.com to a managed domain with password hash sync or cloud authentication (Entra Connect already syncs users), then remove the Okta Office 365 app.', verify: 'Sign in to office.com with a test user after the domain is managed and no Okta page appears; then a second user; then remove the WS-Fed app.' },
    ad_agent: { what: 'Okta AD agents import users and groups from NRPI.LOCAL and check passwords against Active Directory.', change: 'Entra Connect already syncs NRPI.LOCAL. Once nothing signs in through Okta, the agents can be uninstalled.', verify: 'Okta shows the agent pool as inactive after the last Okta-authenticated app is retired; the service accounts are disabled.' },
    ldap_interface: { what: 'The Okta LDAP Interface lets applications bind with LDAP against Okta users.', change: 'Find every consumer (network devices, appliances, scripts). Re-point them to Active Directory or an Entra-backed alternative.', verify: 'Okta System Log shows no LDAP bind events for 30 days.' },
    radius: { what: 'Okta RADIUS agents answer VPN / wireless authentications with Okta MFA.', change: 'Move the RADIUS clients to NPS with the Entra MFA extension, or to certificate authentication.', verify: 'The RADIUS clients authenticate without Okta and the agent pool is decommissioned.' },
    mfa_service: { what: 'Okta MFA for RDP: Windows sign-ins on protected servers require an Okta factor.', change: 'Replace with Entra-joined device sign-in plus Conditional Access, Windows Hello for Business, or another RDP MFA product.', verify: 'A protected server no longer prompts through Okta and the Okta app is deactivated.' },
    okta_platform: { what: 'Okta platform application (dashboard, admin console, browser plugin). Retires with the tenant.', change: 'Nothing to migrate; it disappears when Okta is switched off.', verify: 'No user relies on the Okta dashboard as their launcher (Entra My Apps replaces it).' },
    workflows: { what: 'Okta Workflows automations (and their OAuth client).', change: 'List every flow; rebuild in Entra lifecycle workflows, Power Automate or scripts.', verify: 'Each flow has a replacement that ran successfully, then the Workflows app is deactivated.' },
    org2org: { what: 'Okta Org2Org hub/spoke link.', change: 'Confirm whether the other org is still in use.', verify: 'The link is removed.' },
  };
  for (const { a, cls, raw } of depApps) {
    const t = DEP_TEXT[cls.kind] || { what: 'Okta application that is part of the platform.', change: 'Assess.', verify: 'Recorded as retired.' };
    const facts = { okta: { id: a.okta_id, label: a.label, name: a.name, status: a.status, signOnMode: a.sign_on_mode, users: a.assigned_user_count, groups: a.assigned_group_count, lastUpdated: a.last_updated_at_okta, mirroredAt: a.last_synced_at },
      what: t.what, change: t.change, verifyHow: [t.verify], kind: cls.kind, owner: null,
      nextAction: a.status === 'ACTIVE' ? { code: 'plan_dependency', label: cls.kind === 'federation' ? 'Plan the domain cutover' : 'Inventory the consumers', cls: 'technician', why: t.change } : { code: 'record_retired', label: 'Record as retired', cls: 'technician', why: 'Inactive in Okta.' } };
    if (cls.kind === 'federation') facts.evidenceLive = { oktaUsers: a.assigned_user_count, note: 'Graph cannot read the federation configuration with this credential (Domain.Read.All is not consented; an Entra Global Administrator can grant it). The Okta app assignment count is the evidence shown.' };
    items.push({ key: 'dep:app:' + a.okta_id, category: 'dependencies', title: (cls.kind === 'federation' ? 'Domain federation via Okta — ' : '') + (a.label || a.name), sourceKind: 'okta_app', sourceId: a.okta_id, sourceStatus: a.status, disposition: a.status === 'ACTIVE' ? 'migrate' : 'retire', autoState: a.status === 'ACTIVE' ? 'needs_review' : 'needs_review', facts });
    counts.dependencies++;
  }

  /* ---- dependencies: other Okta object classes ---- */
  const [objs] = await pool.query(`SELECT kind, okta_id, name, status, details, collected_at FROM oem_okta_object WHERE seen_in_last_discovery=1 AND kind IN ('agent_pool','idp','trusted_origin','event_hook','inline_hook','api_token','domain','group_rule','behavior','device_assurance')`);
  const OBJ_TEXT = {
    agent_pool: { title: 'Agent pool', what: 'Okta agents installed on servers (AD, RADIUS, on-prem provisioning).', change: 'Uninstall after the last dependent app is retired; disable the service accounts.', verify: 'Pool shows no operational agents.' },
    idp: { title: 'Inbound identity provider', what: 'An external IdP configured in Okta.', change: 'Recreate as an Entra external identity or federation if still needed.', verify: 'Users of that IdP sign in through Entra.' },
    trusted_origin: { title: 'Trusted origin', what: 'A web origin allowed to call Okta (CORS / redirect).', change: 'The application behind it must stop calling Okta; nothing to create in Entra unless it becomes an app registration.', verify: 'The origin no longer references Okta.' },
    event_hook: { title: 'Event hook', what: 'Okta calls an external URL on events.', change: 'Rebuild on Entra audit log / Graph change notifications.', verify: 'Replacement receives events.' },
    inline_hook: { title: 'Inline hook', what: 'Okta calls out during token/registration/password flows.', change: 'Rebuild as an Entra custom authentication extension.', verify: 'Replacement is invoked in a test sign-in.' },
    api_token: { title: 'API token', what: 'A script or integration calls the Okta API with this token.', change: 'Find the owner and the consumer; re-point it to Graph or retire it.', verify: 'Token revoked, nothing broke.' },
    domain: { title: 'Custom domain', what: 'A custom Okta sign-in domain.', change: 'Redirect or retire the hostname; certificates lapse with it.', verify: 'DNS no longer points at Okta.' },
    group_rule: { title: 'Group rule', what: 'Okta assigns group membership by rule.', change: 'Recreate as Entra dynamic group membership rules.', verify: 'Dynamic group membership matches the Okta group.' },
    behavior: { title: 'Behavior detection', what: 'Okta behavioural risk signal used by sign-on rules.', change: 'Entra ID Protection risk conditions replace it.', verify: 'Risk-based CA policy enforced.' },
    device_assurance: { title: 'Device assurance policy', what: 'Okta device posture requirement.', change: 'Recreate as Intune compliance + Conditional Access device filter.', verify: 'CA requires compliant device for the same apps.' },
  };
  for (const o of objs) {
    const t = OBJ_TEXT[o.kind];
    const d = j(o.details, {}) || {};
    const facts = { okta: { id: o.okta_id, name: o.name, status: o.status, kind: o.kind, collectedAt: o.collected_at, details: d }, what: t.what, change: t.change, verifyHow: [t.verify], kind: o.kind, owner: null,
      nextAction: { code: 'plan_dependency', label: o.kind === 'api_token' ? 'Find the token owner and consumer' : 'Plan the replacement', cls: 'technician', why: t.change } };
    if (o.kind === 'api_token') facts.owner = d.userId ? 'Okta user ' + d.userId : null;
    const active = !/^(INACTIVE|EXPIRED|DEACTIVATED)$/i.test(o.status || '');
    items.push({ key: 'dep:' + o.kind + ':' + o.okta_id, category: 'dependencies', title: t.title + ' — ' + (o.name || o.okta_id), sourceKind: 'okta_' + o.kind, sourceId: o.okta_id, sourceStatus: o.status, disposition: active ? 'investigate' : 'retire', autoState: 'needs_review', facts });
    counts.dependencies++;
  }

  /* ---- policies ---- */
  const { MAPPINGS } = require('./oem-mapping');
  const [pols] = await pool.query(`SELECT policy_id, policy_type, name, status, priority, is_system, rule_count, app_count, app_names, shadowed_rules, collected_at FROM oem_okta_policy`);
  const [steps] = await pool.query(`SELECT step_key, state, note, actor_email, updated_at FROM oem_step_status`);
  const stepBy = new Map(steps.map((s) => [s.step_key, s]));
  const mappingByPolicy = new Map();
  for (const m of MAPPINGS) for (const id of (JSON.stringify(m).match(/00p[a-zA-Z0-9]{17}|rst[a-zA-Z0-9]{17}/g) || [])) mappingByPolicy.set(id, m.key);
  for (const p of pols) {
    const mk = mappingByPolicy.get(p.policy_id) || null;
    const hist = mk ? stepBy.get(mk) : null;
    const facts = { okta: { id: p.policy_id, name: p.name, type: p.policy_type, status: p.status, priority: p.priority, system: !!p.is_system, rules: p.rule_count, apps: p.app_count, appNames: j(p.app_names, []), shadowed: j(p.shadowed_rules, []), collectedAt: p.collected_at },
      mappingKey: mk, history: hist ? { state: hist.state, note: hist.note, by: hist.actor_email, at: hist.updated_at, label: 'Recorded on the old page — history, not evidence' } : null,
      what: ({ ACCESS_POLICY: 'An app sign-on policy: who may reach these apps, and with which factors, from where.', OKTA_SIGN_ON: 'A global session policy: how users get an Okta session (MFA, session length, network).', MFA_ENROLL: 'Which authenticators users must or may enrol.', PASSWORD: 'Password complexity, lockout and recovery rules.', IDP_DISCOVERY: 'Routing rules that send some users to another identity provider.', PROFILE_ENROLLMENT: 'Self-service registration rules.', USER_LIFECYCLE: 'Lifecycle automation (deactivate after inactivity).' })[p.policy_type] || 'Okta policy.',
      change: mk ? 'Translated by the mapping "' + mk + '" (Security and MFA → Sign-in rules).' : (p.policy_type === 'ACCESS_POLICY' ? 'Each app it protects needs the equivalent Conditional Access assignment once the app is in Entra.' : 'Needs a translation decision (no mapping recorded).'),
      verifyHow: ['The Entra policy is enabled (not report-only) and a test sign-in shows it applied in the sign-in log.'],
      nextAction: mk ? { code: 'open_mapping', label: 'Open the translation', cls: 'analysis', why: 'A mapping exists.' } : { code: 'decide_policy', label: 'Decide how this policy translates', cls: 'technician', why: 'No mapping recorded.' } };
    items.push({ key: 'policy:' + p.policy_id, category: 'policies', title: p.policy_type + ' — ' + p.name, sourceKind: 'okta_policy', sourceId: p.policy_id, sourceStatus: p.status, disposition: p.status === 'ACTIVE' ? 'migrate' : 'retire', autoState: mk ? 'ready' : 'needs_review', facts });
    counts.policies++;
  }
  for (const m of MAPPINGS) {
    const hist = stepBy.get(m.key);
    const facts = { mapping: { key: m.key, phase: m.phase, title: m.title, okta: m.oktaObject, entra: m.entraObject, plain: m.plain, blockedBy: m.blockedBy || null, noEquivalent: m.noEquivalentNote || null, actions: (m.actions || []).map((a) => ({ id: a.id, label: a.label, cls: a.cls, requires: a.requires || [], verify: a.verify || null })) },
      history: hist ? { state: hist.state, note: hist.note, by: hist.actor_email, at: hist.updated_at, label: 'Recorded on the old page — history, not evidence' } : null,
      what: m.plain, change: m.entraObject ? (m.entraObject.type + (m.entraObject.name ? ': ' + m.entraObject.name : '')) : 'See the mapping.', verifyHow: (m.actions || []).map((a) => a.verify).filter(Boolean).slice(0, 3).concat(['A policy counts as verified only when a real sign-in in the Entra log shows it applied (not report-only).']),
      nextAction: m.blockedBy ? { code: 'blocked', label: 'Waits on the prerequisite "' + ((MAPPINGS.find((x) => x.key === m.blockedBy) || {}).title || m.blockedBy) + '"', cls: 'blocked', why: m.blockedBy } : { code: 'open_mapping', label: 'Work the translation', cls: 'analysis', why: 'Preview, generate and validate from the mapping.' } };
    items.push({ key: 'mapping:' + m.key, category: 'policies', title: 'Translation — ' + m.title, sourceKind: 'oem_mapping', sourceId: m.key, sourceStatus: null, disposition: m.noEquivalentNote ? 'investigate' : 'migrate', autoState: m.blockedBy ? 'blocked' : 'ready', facts });
    counts.policies++;
  }

  /* ---- MFA ---- */
  const reg = await L.metaGet('mfa_registration', null);
  const by = (reg.v && reg.v.by_method) || {};
  const total = reg.v ? reg.v.total : null;
  const amp = await graphGet('/v1.0/policies/authenticationMethodsPolicy');
  const entraMethods = {};
  if (amp.status === 200 && amp.body && Array.isArray(amp.body.authenticationMethodConfigurations)) for (const c of amp.body.authenticationMethodConfigurations) entraMethods[c.id] = c.state;
  // Until policyMigrationState is migrationComplete the legacy per-user MFA and SSPR settings still
  // govern registration, so "disabled" in the converged policy does not mean nobody can register.
  const ampMigration = amp.status === 200 && amp.body ? (amp.body.policyMigrationState || 'unknown') : 'unknown';
  const legacyGoverns = ampMigration !== 'migrationComplete';
  if (amp.status === 200) {
    const enabled = Object.keys(entraMethods).filter((k) => entraMethods[k] === 'enabled');
    const disabled = Object.keys(entraMethods).filter((k) => entraMethods[k] !== 'enabled');
    items.push({ key: 'mfa:entra-methods-policy', category: 'mfa', title: 'Entra authentication methods policy — migration ' + ampMigration, sourceKind: 'entra_auth_methods_policy', sourceId: 'authenticationMethodsPolicy', sourceStatus: ampMigration, disposition: 'migrate',
      autoState: ampMigration === 'migrationComplete' ? 'needs_review' : 'waiting_technician',
      facts: { entra: { policyMigrationState: ampMigration, enabled, disabled, readAt: at },
        what: 'The tenant-wide Entra policy that decides which MFA methods users may register. Its state is "' + ampMigration + '"' + (legacyGoverns ? ': the legacy per-user MFA and SSPR settings still govern registration, and the converged policy is not yet the single source of truth.' : ': the converged policy governs registration.'),
        change: legacyGoverns ? 'Enable the methods the Okta authenticators map to (' + ['MicrosoftAuthenticator', 'SoftwareOath', 'Fido2', 'TemporaryAccessPass'].filter((k) => entraMethods[k] !== 'enabled').join(', ') + '), then complete the migration so the converged policy is authoritative. Every MFA item below depends on this.' : 'Confirm the enabled methods cover every Okta authenticator that stays in use.',
        verifyHow: ['GET /policies/authenticationMethodsPolicy shows policyMigrationState = migrationComplete and the required methods enabled for the intended groups.', 'A test user can register each required method from https://aka.ms/mysecurityinfo.'],
        nextAction: { code: 'open_admin_page', label: 'Open the authentication methods policy', cls: 'browser', why: 'A portal change. This credential lacks Policy.ReadWrite.AuthenticationMethod (an Entra Global Administrator could consent it), so it cannot be written from here.', url: 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods' } } });
    counts.mfa++;
  }
  const MFA_MAP = {
    okta_verify: { entra: 'Microsoft Authenticator (push / number match)', entraKey: 'MicrosoftAuthenticator', reg: 'microsoftAuthenticatorPush', reenrol: true, note: 'Every user must register Microsoft Authenticator; Okta Verify enrolments do not carry over.' },
    google_otp: { entra: 'Software OATH token (Authenticator or any TOTP app)', entraKey: 'SoftwareOath', reg: 'softwareOneTimePasscode', reenrol: true, note: 'A new TOTP secret is issued by Entra; the Google Authenticator entry for Okta stops working.' },
    phone_number: { entra: 'SMS / voice call', entraKey: 'Sms', reg: 'mobilePhone', reenrol: true, note: 'Phone numbers can be pre-loaded by an admin (needs UserAuthenticationMethod.ReadWrite.All — not consented; an Entra Global Administrator can grant it).' },
    yubikey_token: { entra: 'FIDO2 security key', entraKey: 'Fido2', reg: 'passwordless', reenrol: true, note: 'YubiKey OTP has no Entra equivalent; the same key can be registered as a FIDO2 credential once FIDO2 is enabled.' },
    webauthn: { entra: 'FIDO2 / passkeys', entraKey: 'Fido2', reg: 'passwordless', reenrol: true, note: 'Register again in Entra.' },
    okta_email: { entra: 'Email OTP (self-service password reset only)', entraKey: 'Email', reg: null, reenrol: false, note: 'Entra does not accept email as an MFA method for sign-in. Users who only have email in Okta need another method.' },
    security_question: { entra: 'Security questions (self-service password reset only)', entraKey: null, reg: null, reenrol: false, note: 'Not an Entra sign-in method.' },
    custom_otp: { entra: 'Hardware OATH token', entraKey: 'HardwareOath', reg: null, reenrol: true, note: 'Tokens must be uploaded to Entra with their seeds.' },
    okta_password: { entra: 'Password (Entra / AD via Entra Connect)', entraKey: null, reg: null, reenrol: false, note: 'Passwords already sync through Entra Connect if password hash sync is on — confirm.' },
    smart_card_idp: { entra: 'Certificate-based authentication', entraKey: 'X509Certificate', reg: null, reenrol: false, note: 'Configure CBA with the NRPI-CA chain.' },
  };
  const [auths] = await pool.query(`SELECT okta_id, name, status, details FROM oem_okta_object WHERE kind='authenticator' AND seen_in_last_discovery=1`);
  for (const a of auths) {
    const d = j(a.details, {}) || {};
    const key = d.key || a.name;
    const m = MFA_MAP[key] || { entra: 'No direct Entra equivalent identified', entraKey: null, reg: null, reenrol: null, note: 'Assess.' };
    const entraState = m.entraKey ? (entraMethods[m.entraKey] || 'unknown') : null;
    const registered = m.reg ? (by[m.reg] !== undefined ? by[m.reg] : null) : null;
    const facts = { okta: { id: a.okta_id, key, name: a.name, status: a.status, type: d.type, settings: d.settings || null },
      entra: { method: m.entra, policyKey: m.entraKey, state: entraState, policyMigrationState: ampMigration, legacySettingsGovern: legacyGoverns, registered, registeredOf: total, registrationAsOf: reg.at },
      reenrolRequired: m.reenrol, what: `Okta authenticator "${a.name}" (${a.status}).`, change: 'Entra equivalent: ' + m.entra + (entraState ? ` — currently ${entraState} in the authentication methods policy.` : '') + ' ' + m.note,
      verifyHow: ['The method is enabled in Entra, the target users have registered it (registration report), and a test sign-in with a CA policy requiring MFA succeeds with it.'],
      nextAction: a.status !== 'ACTIVE' ? { code: 'record_retired', label: 'Nothing to migrate (inactive in Okta)', cls: 'analysis', why: 'Inactive.' }
        : entraState === 'disabled' ? { code: 'enable_method', label: 'Enable the method in Entra', cls: 'browser', why: m.entra + ' is disabled in the converged authentication methods policy' + (legacyGoverns ? ' (policy migration is "' + ampMigration + '", so the legacy MFA/SSPR settings still decide what users can register today)' : '') + '. Enabling it is a portal change: this credential lacks Policy.ReadWrite.AuthenticationMethod, which an Entra Global Administrator could consent, but the admin center needs no new permission.' }
        : m.reenrol ? { code: 'enrolment_campaign', label: 'Run the registration campaign', cls: 'technician', why: `${registered === null ? 'Unknown' : registered} of ${total === null ? '?' : total} users have registered ${m.entra}.` }
        : { code: 'assess', label: 'Decide the replacement', cls: 'technician', why: m.note } };
    items.push({ key: 'mfa:' + key, category: 'mfa', title: 'Authenticator — ' + a.name, sourceKind: 'okta_authenticator', sourceId: a.okta_id, sourceStatus: a.status, disposition: a.status === 'ACTIVE' ? 'migrate' : 'retire', autoState: a.status !== 'ACTIVE' ? 'needs_review' : (entraState === 'disabled' ? 'waiting_technician' : 'needs_review'), facts });
    counts.mfa++;
  }
  const [mfaPol] = await pool.query(`SELECT policy_id, name, status, rule_count, priority FROM oem_okta_policy WHERE policy_type='MFA_ENROLL'`);
  for (const p of mfaPol) {
    const facts = { okta: { id: p.policy_id, name: p.name, status: p.status, rules: p.rule_count }, what: 'Okta MFA enrolment policy: which users must enrol which authenticators.', change: 'Entra: authentication methods policy (tenant-wide) + registration campaign + CA policy requiring MFA for the same users.', verifyHow: ['Registration report shows the target group registered; CA policy requiring MFA is enabled for them.'], nextAction: { code: 'open_mapping', label: 'Work the MFA translation', cls: 'analysis', why: 'Covered by the MFA mappings.' } };
    items.push({ key: 'mfa:policy:' + p.policy_id, category: 'mfa', title: 'MFA enrolment policy — ' + p.name, sourceKind: 'okta_policy', sourceId: p.policy_id, sourceStatus: p.status, disposition: 'migrate', autoState: 'needs_review', facts });
    counts.mfa++;
  }

  /* ---- network + device ---- */
  const [zones] = await pool.query(`SELECT zone_id, name, zone_type, status, usage_kind, referenced_by, entry_count, cidrs, countries, collected_at FROM oem_okta_zone`);
  const [parity] = await pool.query(`SELECT okta_zone, cidr, direction, kind, detail, entra_location, entra_trusted, is_sipa_anchor FROM oem_zone_parity`);
  const parityBy = new Map(); for (const r of parity) { if (!parityBy.has(r.okta_zone)) parityBy.set(r.okta_zone, []); parityBy.get(r.okta_zone).push(r); }
  for (const z of zones) {
    const rows = parityBy.get(z.name) || [];
    const cidrs = j(z.cidrs, []) || [];
    const shared = cidrs.filter((c) => isSharedEgress(c));
    const dedicated = cidrs.filter((c) => !isSharedEgress(c));
    const facts = { okta: { id: z.zone_id, name: z.name, type: z.zone_type, status: z.status, usage: z.usage_kind, referencedBy: z.referenced_by, entries: z.entry_count, cidrs, countries: j(z.countries, []), collectedAt: z.collected_at },
      parity: { rows: rows.map((r) => ({ cidr: r.cidr, direction: r.direction, kind: r.kind, detail: r.detail, entraLocation: r.entra_location, entraTrusted: r.entra_trusted === null ? null : !!r.entra_trusted, sipaAnchor: !!r.is_sipa_anchor })), oktaOnly: rows.filter((r) => r.direction === 'okta_only').length, unused: rows.some((r) => r.direction === 'unused') },
      sharedEgress: shared, dedicated,
      what: `Okta network zone "${z.name}" (${z.zone_type}, ${z.usage_kind}${z.referenced_by ? ', referenced by ' + z.referenced_by + ' rule' + (z.referenced_by === 1 ? '' : 's') : ', referenced by no rule'}).`,
      change: z.zone_type === 'IP'
        ? (shared.length ? `${shared.length} of ${cidrs.length} ranges are shared Zscaler cloud egress (any Zscaler customer can arrive from them). Do not copy those into a trusted Entra named location; trust only the dedicated ranges (${dedicated.length}) and rely on SIPA/device signals for the rest.` : 'Create or extend an Entra named location with the same ranges; mark it trusted only if Okta treats the zone as trusted network.')
        : 'Dynamic zone (country / proxy type). Entra: countries named location (GPS or IP) with the same country list.',
      verifyHow: ['A sign-in from inside the range shows the named location in the Entra sign-in log; one from outside does not.'],
      nextAction: z.referenced_by === 0 && z.usage_kind === 'POLICY' ? { code: 'record_excluded', label: 'Exclude (no rule uses it)', cls: 'technician', why: 'Unused in Okta.' } : { code: 'open_mapping', label: 'Work the named-location translation', cls: 'analysis', why: 'Prerequisite for location-based policies.' } };
    items.push({ key: 'net:zone:' + z.zone_id, category: 'network_device', title: 'Network zone — ' + z.name, sourceKind: 'okta_zone', sourceId: z.zone_id, sourceStatus: z.status, disposition: z.referenced_by === 0 && z.usage_kind === 'POLICY' ? 'exclude' : 'migrate', autoState: z.status !== 'ACTIVE' ? 'needs_review' : (rows.some((r) => r.direction === 'okta_only') ? 'needs_review' : 'ready'), facts });
    counts.network_device++;
  }
  const [anchors] = await pool.query(`SELECT * FROM oem_sipa_anchor`);
  for (const a of anchors) {
    const facts = { anchor: { ip: a.ip, label: a.label, site: a.site, ptr: a.ptr, carrier: a.carrier, oktaZones: j(a.okta_zones, []), entraLocations: j(a.entra_locations, []), entraTrusted: a.entra_trusted === null ? null : !!a.entra_trusted, inZpaSegment: a.in_zpa_segment, collectedAt: a.collected_at },
      what: `Zscaler egress address ${a.ip} (${a.label}). Sign-ins routed through SIPA arrive from here.`, change: a.entra_trusted ? 'Already trusted in Entra.' : 'Present in "' + (j(a.entra_locations, []).join(', ') || 'no Entra location') + '" but not marked trusted. Decide whether this dedicated egress should be a trusted location; the ZPA segment must forward the Entra sign-in hosts for that to hold.',
      verifyHow: ['A sign-in from a SIPA-routed client shows this address and the expected named location in the Entra sign-in log.'],
      nextAction: { code: 'open_sipa', label: 'Open the SIPA prerequisite', cls: 'analysis', why: 'Segment destinations and gateway attachment must be confirmed live.' } };
    items.push({ key: 'net:sipa:' + a.ip, category: 'network_device', title: 'SIPA egress — ' + a.ip + ' (' + a.site + ')', sourceKind: 'sipa_anchor', sourceId: a.ip, sourceStatus: null, disposition: 'migrate', autoState: a.entra_trusted ? 'ready' : 'needs_review', facts });
    counts.network_device++;
  }
  const [devAss] = await pool.query(`SELECT COUNT(*) n FROM oem_okta_object WHERE kind='device_assurance' AND seen_in_last_discovery=1`);
  const facts = { what: 'Device requirements: Okta device assurance / managed-device conditions versus Intune compliance + Conditional Access device filters.', oktaDeviceAssurancePolicies: devAss[0].n, change: 'Every rule that requires a managed or assured device needs an Entra policy requiring a compliant device; device coverage (Intune enrolment) must be high enough first.', verifyHow: ['Device coverage report shows the target population enrolled; a non-compliant device is blocked in a test.'], nextAction: { code: 'open_devices', label: 'Check device coverage', cls: 'analysis', why: 'Prerequisite for compliant-device policies.' } };
  items.push({ key: 'net:device-coverage', category: 'network_device', title: 'Device coverage prerequisite', sourceKind: 'analysis', sourceId: 'device-coverage', sourceStatus: null, disposition: 'migrate', autoState: 'needs_review', facts });
  counts.network_device++;

  /* ---- publish: one transaction, one generation (bug 11) ---- */
  // Readers see either the previous generation or this one, never a mix: the unseen flag reset, every
  // row, the tombstones and the generation stamp commit together, or none of them do.
  const conn = typeof pool.getConnection === 'function' ? await pool.getConnection() : null;
  const q = conn || pool;
  const meta = { at: at.toISOString(), counts, generation };
  const retryTombstones = [];
  try {
    if (conn) await conn.beginTransaction();
    await q.query(`UPDATE oem_work_item SET seen_in_last_discovery=0`);
    for (const it of items) await upsertItem(q, it, at);
    for (const t of tombstones.values()) { const r = await recordTombstone(q, t, log); if (!r.ok && r.reason !== 'store unavailable') retryTombstones.push(t); }
    await q.query(`INSERT INTO oem_meta (k, v) VALUES ('work_items_last', ?) ON DUPLICATE KEY UPDATE v=VALUES(v)`, [JSON.stringify(meta)]);
    if (conn) await conn.commit();
    lastGeneration = meta;
  } catch (e) {
    if (conn) { try { await conn.rollback(); } catch (e2) { /* the connection is already gone; nothing was committed */ } }
    log(`work items: not published — ${e.message}; the previous generation stays in place`, 'error');
    throw e;
  } finally { if (conn) conn.release(); }
  // A store that cannot write on a transaction connection gets the tombstones again on the pool (record-if-absent).
  for (const t of retryTombstones) await recordTombstone(pool, t, log);
  counts.destinationsDeleted = tombstones.size;
  if (tombstones.size) log(`work items: ${tombstones.size} matched Entra principal(s) no longer exist — tombstoned, matches invalidated`, 'warn');
  // v2 matches (oem_app_match) are derived from the legacy decisions, the candidates and the tombstones this build just
  // wrote; bring them in line now so the v2 list and workspace never lag the mirrors. A sync failure is logged, never fatal.
  const S = v2Store();
  if (S && typeof S.syncAllMatches === 'function') {
    try { const r = await S.syncAllMatches(); counts.matchRowsChanged = Number(r.changed) || 0; if (r.changed || (r.failed && r.failed.length)) log(`v2 matches: ${r.changed} row(s) changed across ${r.apps} application(s)` + (r.failed.length ? `; ${r.failed.length} failed (${r.failed.slice(0, 3).map((f) => f.oktaId + ': ' + f.error).join('; ')})` : ''), r.failed.length ? 'warn' : 'info'); }
    catch (e) { log('v2 matches: not synced — ' + e.message, 'warn'); }
  }
  log(`work items: ${JSON.stringify(counts)} (generation ${generation})`);
  return counts;
}

let lastGeneration = null;
/**
 * The last committed work-queue generation: { id: <ms stamp>, at, counts }. id is null until a build has
 * committed with this version (an older stamp has no generation — shown as unknown, never invented).
 */
async function currentGeneration() {
  try {
    const m = await L.metaGet('work_items_last', null);
    if (m && m.v) { lastGeneration = { id: m.v.generation || null, at: m.v.at || (m.at ? new Date(m.at).toISOString() : null), counts: m.v.counts || null }; return lastGeneration; }
  } catch (e) { /* fall back to the in-process copy */ }
  return lastGeneration || { id: null, at: null, counts: null };
}

/** Shared Zscaler cloud egress (zscalertwo/ZIA public ranges). Anyone on Zscaler can arrive from these. */
const SHARED_EGRESS_PREFIXES = ['104.129.192.', '104.129.204.', '128.177.', '136.226.', '137.83.', '147.161.', '165.225.', '170.85.', '185.46.212.', '199.168.148.', '199.168.149.', '199.168.150.', '199.168.151.', '213.152.228.', '216.52.207.', '216.218.133.', '64.74.126.', '70.39.159.', '89.167.131.', '8.25.203.', '8.36.116.', '8.34.34.', '8.34.70.', '8.35.53.', '8.39.140.'];
function isSharedEgress(cidr) { const ip = String(cidr).split('/')[0]; return SHARED_EGRESS_PREFIXES.some((p) => ip.startsWith(p)); }

/* ------------------------------------------------------- MFA evidence */

async function measureMfaEvidence(log, { days = 7, maxPages = 12 } = {}) {
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const url = `/beta/auditLogs/signIns?$top=500&$filter=createdDateTime ge ${since} and signInEventTypes/any(t:t eq 'interactiveUser')`;
  const r = await graphAll(url, { maxPages });
  const ev = r.items;
  if (!ev.length && !r.ok) { await L.metaSet('mfa_evidence', { at: L.nowIso(), ok: false, error: r.error }); throw new Error('sign-in read failed: ' + r.error); }
  const tally = (k) => (o, v) => { o[k] = o[k] || {}; o[k][v] = (o[k][v] || 0) + 1; };
  const out = { at: L.nowIso(), ok: true, requestedDays: days, events: ev.length, pages: r.pages, complete: r.ok, spanStart: null, spanEnd: null,
    byRequirement: {}, byFirstMethod: {}, byIssuer: {}, byCa: {}, byError: {}, mfaDetail: 0, methodsUsedNonEmpty: 0, federatedStepSeen: 0, apps: {} };
  const tR = tally('byRequirement'), tM = tally('byFirstMethod'), tI = tally('byIssuer'), tC = tally('byCa'), tE = tally('byError'), tA = tally('apps');
  for (const e of ev) {
    const t = e.createdDateTime; if (!out.spanStart || t < out.spanStart) out.spanStart = t; if (!out.spanEnd || t > out.spanEnd) out.spanEnd = t;
    tR(out, e.authenticationRequirement || 'unknown');
    tI(out, e.tokenIssuerType || 'unknown');
    tC(out, e.conditionalAccessStatus || 'unknown');
    tE(out, String((e.status && e.status.errorCode) || 0));
    tA(out, e.appDisplayName || 'unknown');
    const d = Array.isArray(e.authenticationDetails) ? e.authenticationDetails : [];
    tM(out, d.length ? String(d[0].authenticationMethod || d[0].authenticationStepResultDetail || 'unknown') : '(no authenticationDetails)');
    if (e.mfaDetail && (e.mfaDetail.authMethod || e.mfaDetail.authDetail)) out.mfaDetail++;
    if (Array.isArray(e.authenticationMethodsUsed) && e.authenticationMethodsUsed.length) out.methodsUsedNonEmpty++;
    if (d.some((s) => /federat/i.test(JSON.stringify(s)))) out.federatedStepSeen++;
  }
  out.apps = Object.fromEntries(Object.entries(out.apps).sort((a, b) => b[1] - a[1]).slice(0, 12));
  const multi = out.byRequirement.multiFactorAuthentication || 0;
  const single = out.byRequirement.singleFactorAuthentication || 0;
  const prev = out.byFirstMethod['Previously satisfied'] || 0;
  out.conclusion = [
    `${ev.length} interactive sign-ins between ${out.spanStart} and ${out.spanEnd}${r.ok ? '' : ' (page cap reached: the window is shorter than requested)'}.`,
    `${multi} carried an Entra multi-factor requirement; ${single} were single-factor as Entra recorded them. ${prev} of the first steps were "Previously satisfied" (a token reused, no credential presented), so most rows say nothing about how the user originally authenticated.`,
    out.federatedStepSeen ? `${out.federatedStepSeen} rows show a federated step.` : 'No row records a federated step in the fields this credential can read, so whether the MFA Okta enforced on the federated hop reaches Entra as a claim is inconclusive from this data.',
    'This is not evidence that MFA is disabled. It is evidence that Entra does not see an MFA claim it can rely on for most sessions, which is why an Entra MFA policy must be piloted with a scoped group before it is broadened.'];
  await L.metaSet('mfa_evidence', out);
  log(`mfa evidence: ${ev.length} events, multi ${multi}, single ${single}, previously-satisfied ${prev}, federated-step rows ${out.federatedStepSeen}`);
  return out;
}

/* -------------------------------------------------------- retirement */

async function assessRetirement() {
  const [items] = await pool.query(`SELECT item_key, category, title, source_kind, source_status, disposition, state, facts FROM oem_work_item WHERE seen_in_last_discovery=1`);
  const [[cov]] = await pool.query(`SELECT v FROM oem_meta WHERE k='discovery_coverage'`);
  const coverage = j(cov && cov.v, null);
  const blockers = [];
  const byCat = {};
  for (const it of items) {
    byCat[it.category] = byCat[it.category] || { total: 0, verified: 0, retired: 0, excluded: 0, open: 0 };
    const c = byCat[it.category];
    c.total++;
    if (it.state === 'verified') c.verified++;
    else if (it.state === 'retired') c.retired++;
    else if (it.disposition === 'exclude') c.excluded++;
    else c.open++;
  }
  const dep = items.filter((i) => i.category === 'dependencies' && i.state !== 'retired' && i.disposition !== 'exclude' && !/^(INACTIVE|EXPIRED)$/i.test(i.source_status || 'x'));
  for (const d of dep) {
    const f = j(d.facts, {}) || {};
    blockers.push({ key: d.item_key, title: d.title, state: d.state, kind: f.kind || d.source_kind, owner: f.owner || 'unassigned', nextAction: f.nextAction ? f.nextAction.label : 'Assess', evidence: f.okta ? { status: f.okta.status, users: f.okta.users, lastUpdated: f.okta.lastUpdated } : null, severity: f.kind === 'federation' ? 'critical' : (['ad_agent', 'radius', 'ldap_interface', 'mfa_service', 'workflows'].includes(f.kind) ? 'high' : 'medium') });
  }
  const activeApps = items.filter((i) => i.category === 'applications' && i.source_status === 'ACTIVE' && !['verified', 'retired'].includes(i.state) && i.disposition !== 'exclude');
  const activePolicies = items.filter((i) => i.category === 'policies' && i.source_kind === 'okta_policy' && i.source_status === 'ACTIVE' && !['verified', 'retired'].includes(i.state));
  const mfaOpen = items.filter((i) => i.category === 'mfa' && !['verified', 'retired'].includes(i.state) && i.disposition !== 'exclude');
  const order = { critical: 0, high: 1, medium: 2 };
  blockers.sort((a, b) => order[a.severity] - order[b.severity]);
  return {
    canRetire: false,
    verdict: blockers.length || activeApps.length ? 'No. Okta still authenticates users and applications.' : 'Every discovered dependency is verified or retired; a final sign-in log review is the last check.',
    reasons: [
      blockers.length ? `${blockers.length} platform dependencies are still active (${blockers.filter((b) => b.severity === 'critical').length} critical).` : null,
      activeApps.length ? `${activeApps.length} active Okta applications are not yet verified in Entra.` : null,
      activePolicies.length ? `${activePolicies.length} active Okta policies have no verified Entra replacement.` : null,
      mfaOpen.length ? `${mfaOpen.length} authenticator items are open (re-enrolment not verified).` : null,
      coverage && Object.values(coverage.classes || {}).some((c) => c.status === 'denied' || c.status === 'error') ? 'Some Okta object classes could not be read, so the dependency list may be incomplete.' : null,
    ].filter(Boolean),
    counts: byCat,
    blockers,
    openApps: activeApps.length,
    openPolicies: activePolicies.length,
    openMfa: mfaOpen.length,
    coverageAt: coverage ? coverage.at : null,
    coverage: coverage ? coverage.classes : null,
  };
}

/* ---------------------------------------------------------- pipeline */

async function discoverAll(log, opts = {}) {
  const out = {};
  if (opts.syncEntraApps !== false) {
    log('step 1/5 — refresh the Entra service-principal mirror (reply URLs, identifier URIs)');
    try { const es = require('./entra-sync'); out.entraApps = await es.runSyncJob('apps'); log(`entra apps: ${JSON.stringify(out.entraApps)}`); }
    catch (e) { log('entra apps sync failed: ' + e.message + ' — continuing with the existing mirror', 'warn'); out.entraApps = { error: e.message }; }
  }
  if (log.cancelled()) throw new Error('cancelled');
  log('step 2/5 — discover Okta scope');
  out.okta = await discoverOktaScope(log);
  if (log.cancelled()) throw new Error('cancelled');
  log('step 3/5 — match identifiers');
  out.matcher = await runMatcher(log);
  if (log.cancelled()) throw new Error('cancelled');
  log('step 4/5 — read Entra provisioning + certificates for SSO- and matched apps');
  out.extras = await refreshEntraSpExtras(log);
  if (log.cancelled()) throw new Error('cancelled');
  log('step 5/5 — build the work queue');
  out.work = await buildWorkItems(log);
  return out;
}

module.exports = { discoverOktaScope, refreshEntraSpExtras, runMatcher, buildWorkItems, measureMfaEvidence, assessRetirement, discoverAll, classifyOktaApp, oktaIdentifiers, entraIdentifiers, scorePair, confidenceFor, tokens, envOf, entraEnv, IDP_HOST_RE, isSharedEgress, PROVISIONING_FEATURES,
  // v2 (A3): pure pieces for tests and the v2 routes
  currentGeneration, nextActionForApp, launcherWords, dedupeLines };
