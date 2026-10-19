/**
 * oem-migrate.js — the Okta → Entra application migration engine (services, no HTTP).
 *
 *   Discovery → Normalization → Assessment → Mapping → Pre-Flight → Migration → Validation → Audit
 *
 *   normalizeOktaApp   one Okta app (raw API JSON + the live extras) → a normalized model
 *   scanApp / scanAll  live, paced reads of everything Okta knows about an app; stored in oem_app_scan
 *   assessApp          protocol recommendation, readiness score, per-step automation class,
 *                      safety stops and the policy-mapping table — computed from the scan, never static
 *   planApp            the ordered Graph/Okta calls a push would make (payload previews, rollback per step)
 *   queue / coverage   "what can I migrate right now" and the automation-coverage metric
 *
 * Nothing here writes to Okta or Entra. The executor (oem-migrate-exec.js) is the only module that
 * does, and every write step is gated on the live Graph roles: a step whose permission is not
 * consented is reported as AUTO — blocked, with the exact permission and who can grant it.
 */
'use strict';
const crypto = require('crypto');
const L = require('./oem-lib');
const D = require('./oem-discovery');
const CX = require('./oem-coexistence');
// removable modules (Drop 8): side-by-side sign-in usage and the test sign-in record; a missing file = no `usage` / `testSignIn` on rows
let USAGE = null, TSI = null;
try { USAGE = require('./oem-usage'); } catch (e) { USAGE = null; }
try { TSI = require('./oem-test-signin'); } catch (e) { TSI = null; }
const VG = require('./oem-vendor-guides');
const { pool, j, nowIso, hostOf, normUrl } = L;

/* ------------------------------------------------------------ permissions */

/** Graph application permissions, least privilege first. Any listed alternative satisfies the step. */
const PERM = {
  APP_WRITE:  ['Application.ReadWrite.OwnedBy', 'Application.ReadWrite.All'],
  APP_ADOPT:  ['Application.ReadWrite.All'],
  ASSIGN:     ['AppRoleAssignment.ReadWrite.All'],
  CLAIMS:     ['Policy.ReadWrite.ApplicationConfiguration'],
  CA:         ['Policy.ReadWrite.ConditionalAccess'],
  GROUP_CREATE: ['Group.Create', 'Group.ReadWrite.All'],
  GROUP_MEMBER: ['GroupMember.ReadWrite.All', 'Group.ReadWrite.All'],
  CONSENT:    ['DelegatedPermissionGrant.ReadWrite.All'],
  DIR_READ:   ['Directory.Read.All'],
  APP_READ:   ['Application.Read.All'],
  AUDIT_READ: ['AuditLog.Read.All'],
};
const WRITE_CRED = L.graphWriteCredential ? L.graphWriteCredential() : { configured: false, name: null };
const ENTRA_GRANTOR = WRITE_CRED.configured
  ? `an Entra Global Administrator (admin consent on the ${WRITE_CRED.name} app registration)`
  : 'an Entra Global Administrator (admin consent on the IT-Command-Migrate app registration, once ENTRA_MIGRATE_CLIENT_ID / ENTRA_MIGRATE_CLIENT_SECRET are configured on the platform)';
const READ_CRED = L.graphReadCredential ? L.graphReadCredential() : { configured: !!process.env.ENTRA_CLIENT_ID, name: 'IT-Command-IdentityDiag' };
const READ_GRANTOR = `an Entra Global Administrator (admin consent on the ${READ_CRED.name || 'IT-Command-IdentityDiag'} app registration — the read credential)`;
const OKTA_GRANTOR = 'an Okta Super Administrator (assign the role to the API token owner)';

const CLS = { AUTO: 'AUTO', APPROVAL: 'AUTO WITH APPROVAL', MANUAL: 'MANUAL', UNSUPPORTED: 'NOT SUPPORTED' };

/** Given the live roles, is a permission set satisfied? Returns { ok, missing, have }. */
function permCheck(alts, roles) {
  if (!alts || !alts.length) return { ok: true, missing: null, have: null };
  // nested arrays = every group must be satisfied by one of its alternatives
  if (Array.isArray(alts[0])) {
    const parts = alts.map((a) => permCheck(a, roles));
    const missing = parts.filter((x) => x.ok !== true).map((x) => x.missing).filter(Boolean);
    return { ok: parts.every((x) => x.ok === true) ? true : (parts.some((x) => x.ok === false) ? false : null), missing: missing.length ? missing.join(' + ') : null, have: parts.map((x) => x.have).filter(Boolean).join(' + ') || null };
  }
  if (roles === null) return { ok: null, missing: alts[0], have: null };
  const have = alts.find((r) => roles.includes(r)) || null;
  return { ok: !!have, missing: have ? null : alts[0], have };
}

/* --------------------------------------------------------------- helpers */

const asArr = (v) => (Array.isArray(v) ? v : v === null || v === undefined ? [] : [v]);
const str = (v) => (v === null || v === undefined ? null : String(v));
const isHttps = (u) => /^https:\/\//i.test(String(u || ''));
const PRIVILEGED_HINTS = /(admin|okta|entra|azure|aws|gcp|google cloud|github|gitlab|vault|1password|cyberark|crowdstrike|zscaler|sailpoint|jamf|intune|kandji|palo alto|fortinet|cisco|meraki|jenkins|terraform|datadog|splunk|sentinel|pagerduty|active directory|domain|root|privileged|security)/i;

/* Okta app sign-on policies are evidence for the separate Security & MFA project.
   The application migration neither reproduces nor writes those policies, so a
   policy read must never become an application-migration gate. */
const SEPARATE_SECURITY_READS = new Set(['policy', 'policy-rules']);
function migrationBlockingScanErrors(errors) {
  return asArr(errors).filter((e) => !SEPARATE_SECURITY_READS.has(e && e.read));
}
function migrationPolicyScanErrors(errors) {
  return asArr(errors).filter((e) => SEPARATE_SECURITY_READS.has(e && e.read));
}
function migrationScanComplete(scan) {
  if (!scan) return false;
  if (scan.complete) return true;
  const errors = asArr(scan.errors);
  return errors.length > 0 && migrationBlockingScanErrors(errors).length === 0;
}

const PROVISIONING_SEMANTIC = {
  outbound: new Set(['SCIM_PROVISIONING', 'PUSH_NEW_USERS', 'PUSH_PROFILE_UPDATES', 'PUSH_USER_DEACTIVATION', 'REACTIVATE_USERS']),
  groups: new Set(['GROUP_PUSH']),
  inbound: new Set(['IMPORT_NEW_USERS', 'IMPORT_PROFILE_UPDATES', 'IMPORT_USER_SCHEMA', 'PROFILE_MASTERING']),
  credential: new Set(['PUSH_PASSWORD_UPDATES', 'OUTBOUND_DEL_AUTH']),
};

function provisioningSemantics(features) {
  const fs = asArr(features).map(String);
  const pick = (set) => fs.filter((f) => set.has(f)).sort();
  const inbound = pick(PROVISIONING_SEMANTIC.inbound);
  const credential = pick(PROVISIONING_SEMANTIC.credential);
  return {
    outbound: pick(PROVISIONING_SEMANTIC.outbound), groupPush: pick(PROVISIONING_SEMANTIC.groups),
    inbound, credential,
    sourceAuthorityReview: inbound.length > 0,
    unsupportedCredentialFlow: credential.length > 0,
    specialistRequired: inbound.length > 0 || credential.length > 0,
  };
}

function stableProvisioningJson(v) {
  if (v === undefined) return 'null';
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stableProvisioningJson).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stableProvisioningJson(v[k])).join(',') + '}';
}

function provisioningContract(p) {
  p = p || {};
  return {
    features: asArr(p.features).map(String).sort(),
    semantics: p.semantics || provisioningSemantics(p.features),
    userNameTemplate: p.userNameTemplate || null,
    connection: p.connection ? { status: p.connection.status || null, authScheme: p.connection.authScheme || null } : null,
    mappings: asArr(p.mappings).map((m) => ({
      direction: m.direction || null, targetAttribute: m.targetAttribute || null,
      expression: m.expression || null, pushStatus: m.pushStatus || null, array: m.array === true,
      externalName: m.externalName || null,
    })).sort((a, b) => stableProvisioningJson(a).localeCompare(stableProvisioningJson(b))),
    schema: asArr(p.schema && p.schema.attributes).map((a) => ({
      scope: a.scope || null, name: a.name || null, externalName: a.externalName || null,
      externalNamespace: a.externalNamespace || null, type: a.type || null,
      required: a.required === true, mutability: a.mutability || null, format: a.format || null,
      minLength: a.minLength === undefined ? null : a.minLength,
      maxLength: a.maxLength === undefined ? null : a.maxLength,
      master: a.master || null,
    })).sort((a, b) => stableProvisioningJson(a).localeCompare(stableProvisioningJson(b))),
    groupPush: asArr(p.groupPush).map((g) => ({
      id: g.id || null, status: g.status || null, sourceGroupId: g.sourceGroupId || null,
      sourceGroupName: g.sourceGroupName || null, targetGroupId: g.targetGroupId || null,
      targetGroupName: g.targetGroupName || null,
    })).sort((a, b) => stableProvisioningJson(a).localeCompare(stableProvisioningJson(b))),
  };
}

function provisioningFingerprint(p) {
  return crypto.createHash('sha256').update(stableProvisioningJson(provisioningContract(p))).digest('hex');
}

/** The exact Okta-derived values that can change an Entra staging plan. This deliberately
    excludes timestamps and display-only evidence, and includes assignment membership so a
    fresh pre-flight cannot silently stage source changes that were not in the approved draft. */
function migrationSourceContract(model) {
  const m = model || {};
  const a = m.assignments || {};
  const u = a.users || {};
  const groups = asArr(a.groups).map((g) => ({
    id: g.id || null, name: g.name || null, type: g.type || null, sid: g.sid || null,
    entraId: g.entra && g.entra.entraId || null,
    membersComplete: g.membersComplete === true,
    members: asArr(g.members).map((x) => ({ id: x.id || null, userName: x.userName || null, status: x.status || null }))
      .sort((x, y) => stableProvisioningJson(x).localeCompare(stableProvisioningJson(y))),
  })).sort((x, y) => stableProvisioningJson(x).localeCompare(stableProvisioningJson(y)));
  const directUsers = asArr(u.directSample).map((x) => ({ id: x.id || null, userName: x.userName || null, status: x.status || null }))
    .sort((x, y) => stableProvisioningJson(x).localeCompare(stableProvisioningJson(y)));
  const saml = m.saml ? {
    entityId: m.saml.entityId || null, acsUrls: asArr(m.saml.acsUrls).map(String).sort(),
    relayState: m.saml.relayState || null, nameId: m.saml.nameId || null,
    attributes: asArr(m.saml.attributes).map((x) => ({ name: x.name || null, namespace: x.namespace || null,
      type: x.type || null, values: asArr(x.values).map(String), filterType: x.filterType || null,
      filterValue: x.filterValue || null, mapping: x.mapping || null }))
      .sort((x, y) => stableProvisioningJson(x).localeCompare(stableProvisioningJson(y))),
    slo: m.saml.slo || null, encryption: m.saml.encryption || null, inlineHooks: Number(m.saml.inlineHooks || 0),
  } : null;
  const oidc = m.oidc ? {
    redirectUris: asArr(m.oidc.redirectUris).map(String).sort(),
    postLogoutRedirectUris: asArr(m.oidc.postLogoutRedirectUris).map(String).sort(),
    grantTypes: asArr(m.oidc.grantTypes).map(String).sort(), responseTypes: asArr(m.oidc.responseTypes).map(String).sort(),
    applicationType: m.oidc.applicationType || null, implicit: m.oidc.implicit === true,
    refreshTokens: m.oidc.refreshTokens === true, secretRequired: m.oidc.secretRequired,
    claims: m.oidc.claims || null,
  } : null;
  return {
    auth: m.auth ? { type: m.auth.type || null, mode: m.auth.mode || null } : null,
    identity: m.identity ? { status: m.identity.status || null, loginUrl: m.identity.loginUrl || null } : null,
    saml, oidc,
    bookmark: m.bookmark ? { url: m.bookmark.url || null, target: m.bookmark.target || null, launcherAppId: m.bookmark.launcherAppId || null } : null,
    swa: m.swa ? { url: m.swa.url || null } : null,
    assignments: {
      groupsError: a.groupsError || null, groups,
      users: { direct: u.direct === undefined ? null : u.direct, partial: u.partial, directComplete: u.directComplete === true,
        error: u.error || null, directUsers },
    },
    provisioning: provisioningContract(m.provisioning),
  };
}

function migrationSourceComplete(model) {
  const m = model || {};
  const a = m.assignments || {};
  const u = a.users || {};
  const groups = a.groups;
  const assignmentsComplete = Array.isArray(groups) && !a.groupsError && u.directComplete === true &&
    u.partial === false && Number.isFinite(Number(u.direct)) && Number(u.direct) >= 0 &&
    groups.filter((g) => g && g.type === 'okta').every((g) => g.membersComplete === true);
  const p = m.provisioning || {};
  const provisioningComplete = !p.enabled || !!(p.inventory && p.inventory.complete === true);
  return assignmentsComplete && provisioningComplete;
}

function migrationSourceFingerprint(model) {
  return crypto.createHash('sha256').update(stableProvisioningJson(migrationSourceContract(model))).digest('hex');
}

/** Okta attribute-statement expressions that map 1:1 onto Entra claim sources. */
const OKTA_TO_ENTRA_CLAIM = {
  'user.email': { source: 'user.mail', label: 'Email' },
  'user.login': { source: 'user.userprincipalname', label: 'User principal name' },
  'user.firstName': { source: 'user.givenname', label: 'Given name' },
  'user.lastName': { source: 'user.surname', label: 'Surname' },
  'user.displayName': { source: 'user.displayname', label: 'Display name' },
  'user.title': { source: 'user.jobtitle', label: 'Job title' },
  'user.department': { source: 'user.department', label: 'Department' },
  'user.employeeNumber': { source: 'user.employeeid', label: 'Employee id' },
  'user.mobilePhone': { source: 'user.mobilephone', label: 'Mobile phone' },
  'user.primaryPhone': { source: 'user.telephonenumber', label: 'Telephone' },
  'user.city': { source: 'user.city', label: 'City' },
  'user.state': { source: 'user.state', label: 'State' },
  'user.countryCode': { source: 'user.country', label: 'Country' },
  'user.streetAddress': { source: 'user.streetaddress', label: 'Street address' },
  'user.zipCode': { source: 'user.postalcode', label: 'Postal code' },
  'user.organization': { source: 'user.companyname', label: 'Company' },
  'user.manager': { source: 'user.manager', label: 'Manager (requires a claims-mapping policy)' },
  'user.managerId': { source: 'user.manager', label: 'Manager (requires a claims-mapping policy)' },
  'user.id': { source: 'user.objectid', label: 'Object id' },
  'user.secondEmail': { source: 'user.othermail', label: 'Other mail' },
  'user.preferredLanguage': { source: 'user.preferredlanguage', label: 'Preferred language' },
  'user.nickName': { source: 'user.mailnickname', label: 'Mail nickname' },
  'user.samAccountName': { source: 'user.onpremisessamaccountname', label: 'On-premises sAMAccountName' },
  'user.userPrincipalName': { source: 'user.userprincipalname', label: 'User principal name' },
};

function mapClaimExpression(expr) {
  const e = String(expr || '').trim();
  if (!e) return { mappable: false, kind: 'empty', reason: 'empty expression' };
  const direct = OKTA_TO_ENTRA_CLAIM[e];
  if (direct) return { mappable: true, kind: 'attribute', source: direct.source, label: direct.label };
  if (/^appuser\./.test(e)) return { mappable: false, kind: 'appuser', reason: 'reads an application-user attribute that Okta stores per assignment; Entra has no per-assignment attribute store — the value must come from a directory attribute or an extension attribute' };
  if (/^user\.[A-Za-z0-9_]+$/.test(e)) return { mappable: false, kind: 'custom-attribute', reason: 'reads a custom Okta profile attribute (' + e + '); map it to a directory extension attribute or a fixed value in Entra' };
  if (/^"[^"]*"$/.test(e) || /^'[^']*'$/.test(e)) return { mappable: true, kind: 'constant', source: e.slice(1, -1), label: 'Constant value' };
  return { mappable: false, kind: 'expression', reason: 'Okta Expression Language (' + e.slice(0, 80) + ') — Entra claim transformations cover joins, substrings and regex; rebuild it deliberately, do not translate it blindly' };
}

/**
 * Reduce Okta Profile Mapping objects to a secret-free migration worksheet.
 * A mapping whose target is the app is outbound provisioning; a mapping whose
 * source is the app is import/profile-mastering. Property expressions are
 * configuration, not user data. They are classified with the same conservative
 * translator used for SAML claims: only direct directory attributes and constants
 * are called automatic; everything else stays a deliberate manual mapping.
 */
function normalizeProfileMappings(rows, appId) {
  const out = [];
  for (const row of asArr(rows)) {
    if (!row || !row.id) continue;
    const source = row.source || {}, target = row.target || {};
    const direction = String(target.id || '') === String(appId) ? 'to_app'
      : String(source.id || '') === String(appId) ? 'from_app' : 'related';
    for (const [targetAttribute, prop0] of Object.entries(row.properties || {})) {
      const prop = prop0 || {};
      const expression = str(prop.expression) || '';
      const translated = mapClaimExpression(expression);
      out.push({
        mappingId: row.id,
        direction,
        source: { id: source.id || null, name: source.name || null, type: source.type || null },
        target: { id: target.id || null, name: target.name || null, type: target.type || null },
        targetAttribute,
        expression: expression.slice(0, 500),
        pushStatus: prop.pushStatus || null,
        array: prop.array === true,
        mapping: translated,
      });
    }
  }
  return out;
}

function normalizeGroupPushMappings(rows) {
  return asArr(rows).map((row) => {
    row = row || {};
    const source = row.sourceGroup || row.source || {};
    const target = row.targetGroup || row.target || {};
    return {
      id: row.id || row.mappingId || null,
      status: row.status || null,
      sourceGroupId: row.sourceGroupId || row.userGroupId || source.id || null,
      sourceGroupName: row.sourceGroupName || source.name || null,
      targetGroupId: row.targetGroupId || row.appGroupId || target.id || null,
      targetGroupName: row.targetGroupName || row.appGroupName || target.name || null,
      created: row.created || null,
      lastUpdated: row.lastUpdated || null,
    };
  }).filter((row) => row.id || row.sourceGroupId || row.targetGroupId || row.targetGroupName);
}

/** Only schema definitions are kept. Per-user application-profile values never enter the scan. */
function normalizeAppUserSchema(schema) {
  const defs = [];
  const add = (scope, props) => {
    for (const [name, p0] of Object.entries(props || {})) {
      const p = p0 || {};
      defs.push({ scope, name, title: p.title || name, type: p.type || null,
        required: p.required === true, mutability: p.mutability || null,
        permissions: asArr(p.permissions).map(String), union: p.union || null,
        externalName: p.externalName || null, externalNamespace: p.externalNamespace || null,
        format: p.format || null,
        minLength: p.minLength === undefined ? null : p.minLength,
        maxLength: p.maxLength === undefined ? null : p.maxLength,
        master: p.master || null });
    }
  };
  add('base', schema && schema.definitions && schema.definitions.base && schema.definitions.base.properties);
  add('custom', schema && schema.definitions && schema.definitions.custom && schema.definitions.custom.properties);
  return { id: schema && schema.id || null, name: schema && schema.name || null, attributes: defs };
}

function attachProvisioningExternalNames(mappings, schema) {
  const byName = new Map(asArr(schema && schema.attributes).map((a) => [String(a.name || ''), a]));
  for (const m of asArr(mappings)) {
    const a = byName.get(String(m.targetAttribute || ''));
    m.externalName = a && a.externalName ? a.externalName : null;
    m.externalNamespace = a && a.externalNamespace ? a.externalNamespace : null;
  }
  return mappings;
}

function normalizeProvisioningConnection(body) {
  body = body || {};
  return { status: body.status || (body.enabled === true ? 'ENABLED' : body.enabled === false ? 'DISABLED' : null),
    authScheme: body.authScheme || body.authType || null };
}

/* --------------------------------------------------------- normalization */

/**
 * Raw Okta app JSON (+ optional extras from the live scan) → one shape every later stage reads.
 * Values Okta does not expose stay null and are reported as unknown, never as absent-so-fine.
 */
function normalizeOktaApp(raw, extras = {}) {
  raw = raw || {};
  const s = raw.settings || {};
  const so = s.signOn || {};
  const sapp = s.app || {};
  const oc = s.oauthClient || null;
  const coc = (raw.credentials && raw.credentials.oauthClient) || {};
  const links = raw._links || {};
  const mode = str(raw.signOnMode) || null;
  const cls = D.classifyOktaApp({ name: raw.name, label: raw.label, sign_on_mode: mode });
  const feats = asArr(raw.features);
  const base = (process.env.OKTA_BASE_URL || '').replace(/\/+$/, '');

  let authType = 'unknown';
  if (mode === 'OPENID_CONNECT') authType = 'oidc';
  else if (mode === 'SAML_2_0') authType = 'saml';
  else if (mode === 'SAML_1_1') authType = 'saml11';
  else if (mode === 'WS_FEDERATION') authType = 'wsfed';
  else if (mode === 'BOOKMARK') authType = 'bookmark';
  else if (['BROWSER_PLUGIN', 'AUTO_LOGIN', 'SECURE_PASSWORD_STORE', 'BASIC_AUTH'].includes(mode)) authType = 'swa';
  else if (mode === 'MFA_AS_SERVICE') authType = 'mfa_service';
  else if (/^RADIUS/i.test(mode || '')) authType = 'radius';
  else if (mode === 'AUTO_LOGIN') authType = 'swa';
  if (cls.kind === 'federation') authType = 'federation';
  if (cls.kind === 'ad_agent') authType = 'ad_agent';
  if (cls.kind === 'ldap_interface') authType = 'ldap_interface';

  const isCustomSaml = authType === 'saml' && !!(so.ssoAcsUrl || so.audience);
  const model = {
    identity: {
      id: raw.id, name: raw.name, label: raw.label, status: raw.status, signOnMode: mode, classKind: cls.kind, category: cls.category,
      created: raw.created || null, lastUpdated: raw.lastUpdated || null,
      appUrl: sapp.url || sapp.loginUrl || sapp.baseUrl || null,
      loginUrl: so.defaultRelayState && /^https?:/i.test(so.defaultRelayState) ? so.defaultRelayState : (sapp.loginUrl || null),
      logoutUrl: (so.slo && so.slo.logoutUrl) || (oc && asArr(oc.post_logout_redirect_uris)[0]) || null,
      helpUrl: links.help ? links.help.href : null,
      vendor: raw.name && !/^auction_/i.test(raw.name) && !/^oidc_client|^bookmark|^template_/i.test(raw.name) ? raw.name : null,
      oin: !!(raw.name && !/^(auction_|oidc_client|bookmark|template_)/i.test(raw.name)),
      hidden: !!(raw.visibility && raw.visibility.hide && (raw.visibility.hide.web || raw.visibility.hide.iOS)),
      owner: extras.owner || null,
      adminUrl: null,
    },
    auth: { type: authType, mode, custom: authType === 'oidc' ? /^oidc_client/i.test(raw.name || '') : isCustomSaml, supports: { oidc: authType === 'oidc' ? true : null, saml: authType === 'saml' ? true : null, wsfed: authType === 'wsfed' ? true : null } },
    oidc: null, saml: null, bookmark: null, swa: null,
    assignments: {
      users: extras.users || { count: null, direct: null, viaGroup: null, sample: [], partial: null, error: 'not scanned' },
      groups: extras.groups || null,
      groupsError: extras.groupsError || null,
      accessPolicy: extras.accessPolicy || null,
    },
    provisioning: {
      enabled: feats.some((f) => D.PROVISIONING_FEATURES.has(f)),
      features: feats.filter((f) => D.PROVISIONING_FEATURES.has(f)),
      semantics: provisioningSemantics(feats.filter((f) => D.PROVISIONING_FEATURES.has(f))),
      userNameTemplate: raw.credentials && raw.credentials.userNameTemplate ? raw.credentials.userNameTemplate.template : null,
      connection: extras.provisioningConnection || null,
      mappings: extras.profileMappings || [],
      schema: extras.appUserSchema || null,
      groupPush: extras.groupPushMappings || [],
      inventory: extras.provisioningInventory || { complete: false, reads: {}, errors: ['not scanned'] },
    },
    features: feats,
    universalLogout: raw.universalLogout || null,
    links: { metadata: links.metadata ? links.metadata.href : null, accessPolicy: links.accessPolicy ? links.accessPolicy.href : null, appLinks: links.appLinks ? links.appLinks.href : null },
  };

  if (authType === 'oidc') {
    const gt = asArr(oc && oc.grant_types), rt = asArr(oc && oc.response_types);
    const issuer = oc && oc.issuer_mode === 'CUSTOM_URL' ? 'custom domain (unknown from the app object)' : base;
    model.oidc = {
      clientId: coc.client_id || null,
      tokenEndpointAuthMethod: coc.token_endpoint_auth_method || null,
      pkceRequired: coc.pkce_required === undefined ? null : !!coc.pkce_required,
      autoKeyRotation: coc.autoKeyRotation === undefined ? null : !!coc.autoKeyRotation,
      secretRequired: coc.token_endpoint_auth_method ? coc.token_endpoint_auth_method !== 'none' : null,
      redirectUris: asArr(oc && oc.redirect_uris).map(String),
      postLogoutRedirectUris: asArr(oc && oc.post_logout_redirect_uris).map(String),
      grantTypes: gt, responseTypes: rt,
      refreshTokens: gt.includes('refresh_token'),
      implicit: gt.includes('implicit'),
      applicationType: (oc && oc.application_type) || null,
      initiateLoginUri: (oc && oc.initiate_login_uri) || null,
      clientUri: (oc && oc.client_uri) || null,
      issuerMode: (oc && oc.issuer_mode) || null,
      issuer,
      wildcardRedirect: (oc && oc.wildcard_redirect) || null,
      consentMethod: (oc && oc.consent_method) || null,
      idpInitiatedLogin: (oc && oc.idp_initiated_login) || null,
      dpop: !!(oc && oc.dpop_bound_access_tokens),
      endpoints: { discovery: base + '/.well-known/openid-configuration', authorization: base + '/oauth2/v1/authorize', token: base + '/oauth2/v1/token', jwks: base + '/oauth2/v1/keys', logout: base + '/oauth2/v1/logout', userinfo: base + '/oauth2/v1/userinfo' },
      scopes: extras.oidcScopes || null,   // per authorization-server policy; unknown unless scanned
      claims: extras.oidcClaims || null,
    };
  }
  if (authType === 'saml' || authType === 'saml11') {
    const attrs = asArr(so.attributeStatements).map((a) => ({ name: a.name, namespace: a.namespace || null, type: a.type || 'EXPRESSION', values: asArr(a.values).map(String), filterType: a.filterType || null, filterValue: a.filterValue || null, mapping: a.type === 'GROUP' ? { mappable: true, kind: 'group', source: 'groups', label: 'Group claim (groupMembershipClaims)' } : mapClaimExpression(asArr(a.values)[0]) }));
    const acs = [so.ssoAcsUrl, so.ssoAcsUrlOverride].filter(Boolean).map(String);
    for (const e of asArr(so.acsEndpoints)) if (e && e.url) acs.push(String(e.url));
    model.saml = {
      custom: isCustomSaml,
      entityId: so.audience || so.audienceOverride || null,
      acsUrls: [...new Set(acs)],
      acsIndexed: asArr(so.acsEndpoints).map((e) => ({ url: e.url, index: e.index })),
      recipient: so.recipient || so.recipientOverride || null,
      destination: so.destination || so.destinationOverride || null,
      relayState: so.defaultRelayState || null,
      nameId: { format: so.subjectNameIdFormat || null, template: so.subjectNameIdTemplate || null },
      attributes: attrs,
      groupClaims: attrs.filter((a) => a.type === 'GROUP'),
      signing: {
        responseSigned: so.responseSigned === undefined ? null : !!so.responseSigned,
        assertionSigned: so.assertionSigned === undefined ? null : !!so.assertionSigned,
        signatureAlgorithm: so.signatureAlgorithm || null, digestAlgorithm: so.digestAlgorithm || null,
        kid: raw.credentials && raw.credentials.signing ? raw.credentials.signing.kid : null,
        cert: extras.signingCert || null,
      },
      encryption: { enabled: !!so.assertionEncryption && so.assertionEncryption !== 'UNENCRYPTED', algorithm: so.assertionEncryption || null, keyTransport: so.keyTransportAlgorithm || null },
      slo: so.slo ? { enabled: !!so.slo.enabled, logoutUrl: so.slo.logoutUrl || null, spIssuer: so.slo.issuer || null } : { enabled: false, logoutUrl: null, spIssuer: null },
      honorForceAuthn: so.honorForceAuthn === undefined ? null : !!so.honorForceAuthn,
      authnContextClassRef: so.authnContextClassRef || null,
      idpIssuer: so.idpIssuer || null,
      allowMultipleAcs: so.allowMultipleAcsEndpoints === undefined ? null : !!so.allowMultipleAcsEndpoints,
      inlineHooks: asArr(so.inlineHooks).length,
      metadataUrl: model.links.metadata,
      overrides: isCustomSaml ? null : { audience: so.audienceOverride || null, acs: so.ssoAcsUrlOverride || null, recipient: so.recipientOverride || null, destination: so.destinationOverride || null },
      entraTemplate: extras.entraTemplate || null,
    };
  }
  if (authType === 'bookmark') {
    const ids = D.oktaIdentifiers(raw);
    model.bookmark = { url: ids.bookmarkUrl, target: ids.launcherAppId ? 'entra_launcher' : ids.oktaHosted ? 'okta_hosted' : 'external', launcherAppId: ids.launcherAppId, host: hostOf(ids.bookmarkUrl) };
  }
  if (authType === 'swa') {
    model.swa = { url: sapp.url || sapp.loginUrl || null, credentialScheme: raw.credentials ? raw.credentials.scheme : null, revealPassword: raw.credentials && raw.credentials.revealPassword !== undefined ? !!raw.credentials.revealPassword : null, usernameTemplate: model.provisioning.userNameTemplate };
  }
  model.provisioning.fingerprint = provisioningFingerprint(model.provisioning);
  model.sourceFingerprint = migrationSourceFingerprint(model);
  model.sourceContractComplete = migrationSourceComplete(model);
  return model;
}

/* --------------------------------------------------------------- scanning */

function normPolicyRule(r) {
  const c = r.conditions || {};
  const vm = (r.actions && r.actions.appSignOn && r.actions.appSignOn.verificationMethod) || {};
  const people = c.people || {};
  const net = c.network || {};
  const dev = c.device || {};
  const constraints = asArr(vm.constraints);
  const needsPossession = constraints.some((k) => k.possession && k.possession.required);
  const needsKnowledge = constraints.some((k) => k.knowledge && k.knowledge.required);
  const phishingResistant = constraints.some((k) => k.possession && k.possession.phishingResistant === 'REQUIRED');
  const hardwareProtected = constraints.some((k) => k.possession && k.possession.hardwareProtection === 'REQUIRED');
  return {
    id: r.id, name: r.name, status: r.status, priority: r.priority, system: !!r.system,
    access: (r.actions && r.actions.appSignOn && r.actions.appSignOn.access) || null,
    factorMode: vm.factorMode || null, type: vm.type || null, reauthenticateIn: vm.reauthenticateIn || null, inactivityPeriod: vm.inactivityPeriod || null,
    constraints, needsPossession, needsKnowledge, phishingResistant, hardwareProtected,
    mfa: vm.factorMode === '2FA' || (needsPossession && needsKnowledge),
    conditions: {
      groupsInclude: asArr(people.groups && people.groups.include), groupsExclude: asArr(people.groups && people.groups.exclude),
      usersInclude: asArr(people.users && people.users.include), usersExclude: asArr(people.users && people.users.exclude),
      network: net.connection ? { connection: net.connection, include: asArr(net.include), exclude: asArr(net.exclude) } : null,
      device: Object.keys(dev).length ? { registered: dev.registered === undefined ? null : dev.registered, managed: dev.managed === undefined ? null : dev.managed, assurance: dev.assurance || null } : null,
      platform: c.platform ? asArr(c.platform.include).map((p) => (p.os && p.os.type) || JSON.stringify(p)) : null,
      riskScore: c.riskScore ? c.riskScore.level : null,
      userType: c.userType ? { include: asArr(c.userType.include), exclude: asArr(c.userType.exclude) } : null,
      elCondition: c.elCondition ? c.elCondition.condition : null,
    },
  };
}

/** Resolve one Okta group to an Entra group, live, by SID first (AD-synced) then exact display name. */
async function resolveGroupLive(g, cache) {
  const key = g.sid ? 'sid:' + g.sid : 'name:' + g.name;
  if (cache.has(key)) return cache.get(key);
  let out = { entraId: null, displayName: null, how: null, candidates: 0, error: null };
  const sel = '$select=id,displayName,onPremisesSamAccountName,onPremisesSecurityIdentifier,securityEnabled,mailEnabled,groupTypes,onPremisesSyncEnabled';
  try {
    if (g.sid) {
      const r = await L.graphGet(`/v1.0/groups?$filter=onPremisesSecurityIdentifier eq '${g.sid}'&${sel}`);
      if (r.status === 200) { const v = (r.body && r.body.value) || []; if (v.length === 1) out = { entraId: v[0].id, displayName: v[0].displayName, how: 'sid', candidates: 1, error: null, synced: !!v[0].onPremisesSyncEnabled, securityEnabled: !!v[0].securityEnabled, groupTypes: v[0].groupTypes || [] }; else out.candidates = v.length; }
      else out.error = r.error;
    }
    if (!out.entraId && !out.error && g.name) {
      const name = String(g.name).replace(/'/g, "''");
      const r = await L.graphGet(`/v1.0/groups?$filter=displayName eq '${encodeURIComponent(name)}'&${sel}`);
      if (r.status === 200) { const v = (r.body && r.body.value) || []; if (v.length === 1) out = { entraId: v[0].id, displayName: v[0].displayName, how: 'displayName', candidates: 1, error: null, synced: !!v[0].onPremisesSyncEnabled, securityEnabled: !!v[0].securityEnabled, groupTypes: v[0].groupTypes || [] }; else out.candidates = Math.max(out.candidates, v.length); }
      else out.error = r.error;
    }
  } catch (e) { out.error = e.message; }
  cache.set(key, out);
  return out;
}

/**
 * Gallery lookup for an OIN app: which Entra gallery template matches, and which single-sign-on modes it
 * supports. applicationTemplates only filters by startswith(displayName), so several probes are tried and
 * the candidates are ranked by token overlap with the Okta label; below the bar nothing is claimed.
 */
async function entraTemplateFor(label, name, cache) {
  const clean = (x) => String(x || '').replace(/\s*\(.*?\)\s*/g, ' ').replace(/\.(com|net|io|org|co)\b/gi, ' ').replace(/[^A-Za-z0-9 .+-]/g, ' ').replace(/\s+/g, ' ').trim();
  const cap = (x) => x ? x[0].toUpperCase() + x.slice(1) : x;
  const lbl = clean(label);
  const words = lbl.split(' ').filter(Boolean);
  const nm = clean(String(name || '').replace(/[_-]+/g, ' '));
  const probes = [];
  const pushProbe = (x) => { x = String(x || '').trim(); if (x.length >= 3 && !probes.includes(x) && !/^(the|sso|saml|okta|app|prod|test|dev)$/i.test(x)) probes.push(x); };
  pushProbe(lbl); if (words.length > 2) pushProbe(words.slice(0, 2).join(' ')); if (words[0]) pushProbe(words[0]);
  const nw = nm.split(' ').filter(Boolean); if (nw[0] && nw[0].length >= 4) pushProbe(cap(nw[0]));   // Graph startswith is case-sensitive
  const key = probes.join('|');
  if (cache.has(key)) return cache.get(key);
  const seen = new Map(); let err = null;
  for (const p of probes) {
    const q = p.replace(/'/g, "''");
    const r = await L.graphGet(`/v1.0/applicationTemplates?$filter=startswith(displayName,'${encodeURIComponent(q)}')&$select=id,displayName,supportedSingleSignOnModes,supportedProvisioningTypes,categories&$top=40`);
    if (r.status !== 200) { err = r.error; continue; }
    for (const t of (r.body && r.body.value) || []) if (!seen.has(t.id)) seen.set(t.id, t);
  }
  // rank: exact name = 1; else half token overlap (jaccard) + half "how much of the Okta label the template name covers"
  const lt = L.tokens(lbl);
  const ranked = [...seen.values()].map((t) => {
    const tt = L.tokens(t.displayName);
    const exact = String(t.displayName).toLowerCase() === lbl.toLowerCase();
    const recall = lt.length ? lt.filter((x) => tt.includes(x)).length / lt.length : 0;
    const deprecated = /deprecated|legacy/i.test(t.displayName);
    const score = exact ? 1 : Math.min(0.95, Math.round(100 * (0.5 * L.jaccard(lt, tt) + 0.5 * recall) * (deprecated ? 0.7 : 1)) / 100);
    return { id: t.id, displayName: t.displayName, modes: t.supportedSingleSignOnModes || [], provisioning: t.supportedProvisioningTypes || [], score };
  }).sort((a, b) => (b.score - a.score) || (a.displayName.length - b.displayName.length));
  const best = ranked[0] && ranked[0].score >= 0.4 ? ranked[0] : null;
  const ambiguous = !!(best && best.score < 1 && ranked[1] && ranked[1].score >= 0.4 && best.score - ranked[1].score < 0.12);
  const base = { matches: ranked.length, ambiguous, candidates: ranked.slice(0, 5), probes, checkedAt: nowIso(), error: err };
  const out = best ? Object.assign({}, best, base) : Object.assign({ id: null }, base);
  cache.set(key, out);
  return out;
}

/**
 * Live scan of one Okta app. Reads (all GET, all paced by oem-lib): the app, its group assignments
 * (expanded, so AD-synced groups carry SID/sAMAccountName), direct user assignments (paged, capped),
 * the app sign-on policy and its rules, the signing key (expiry), and — for OIN SAML apps — the
 * matching Entra gallery template. Everything is stored in oem_app_scan with per-read errors, so a
 * partial scan is a partial scan, never a clean one.
 */
async function scanApp(oktaId, log = () => {}, { actor = null, caches = null, maxUserPages = 25 } = {}) {
  caches = caches || { groups: new Map(), templates: new Map() };
  const errors = [];
  const app = await L.oktaGet(`/api/v1/apps/${oktaId}`);
  if (app.status !== 200 || !app.body) {
    errors.push({ read: 'app', status: app.status, error: app.error });
    await pool.query(`INSERT INTO oem_app_scan (okta_id, scanned_at, scanned_by, complete, errors) VALUES (?,NOW(),?,0,?) ON DUPLICATE KEY UPDATE scanned_at=NOW(), scanned_by=VALUES(scanned_by), complete=0, errors=VALUES(errors)`, [oktaId, actor, JSON.stringify(errors)]);
    return { ok: false, oktaId, errors };
  }
  const raw = app.body;
  const extras = {};
  // keep the mirror fresh with the live object (same as the existing /okta/apps/:id/live route)
  await pool.query(`UPDATE okta_apps SET status=?, label=?, sign_on_mode=?, features_json=?, last_updated_at_okta=?, raw_json=?, last_synced_at=NOW() WHERE okta_id=?`,
    [raw.status, raw.label, raw.signOnMode || null, JSON.stringify(asArr(raw.features)), raw.lastUpdated ? new Date(raw.lastUpdated) : null,
      // raw_json never carries a secret (v2 secrets-1): L.scrubAppRecord keeps client_id / token_endpoint_auth_method (L.redact would not); the same key list inline if oem-lib is older
      JSON.stringify(typeof L.scrubAppRecord === 'function' ? L.scrubAppRecord(raw) : (function walk(x, d) { const KEYS = /^(client_secret|clientsecret|secret|sharedsecret|shared_secret|password|passwd|private_key|privatekey|api_key|apikey|access_token|refresh_token|id_token|session_token|cookie|mfa_code|otp)$/i; return d > 12 ? '[depth]' : Array.isArray(x) ? x.map((y) => walk(y, d + 1)) : (x && typeof x === 'object') ? Object.fromEntries(Object.entries(x).map(([k, y]) => [k, KEYS.test(k) ? '[redacted]' : walk(y, d + 1)])) : x; })(raw, 0)),
      oktaId]).catch((e) => errors.push({ read: 'mirror', error: e.message }));

  // groups (expanded)
  const gr = await L.oktaAll(`/api/v1/apps/${oktaId}/groups?expand=group&limit=200`, { maxPages: 10 });
  if (gr.ok || gr.partial) {
    extras.groups = gr.items.map((g) => {
      const e = (g._embedded && g._embedded.group) || {};
      const p = e.profile || {};
      const ad = e.type === 'APP_GROUP' && (p.objectSid || p.windowsDomainQualifiedName || p.samAccountName);
      return { id: g.id, priority: g.priority, name: p.name || e.profile && e.profile.name || null, type: ad ? 'ad' : e.type === 'OKTA_GROUP' ? 'okta' : e.type === 'BUILT_IN' ? 'builtin' : e.type ? 'app' : 'unknown', oktaType: e.type || null, sam: p.samAccountName || null, sid: p.objectSid || null, dn: p.dn || null, domain: p.windowsDomainQualifiedName ? String(p.windowsDomainQualifiedName).split('\\')[0] : null, description: p.description || null, sourceApp: e.source ? e.source.id : null, entra: null };
    });
    if (!gr.ok) errors.push({ read: 'groups', status: gr.status, error: gr.error, partial: true });
  } else { extras.groupsError = gr.error; errors.push({ read: 'groups', status: gr.status, error: gr.error }); }

  // Okta-native groups have no Entra directory object to carry their membership. Inventory the
  // complete member set now so approval binds to it; execution must never re-read a changed or
  // partial set after the technician approved the plan.
  for (const g of (extras.groups || []).filter((x) => x.type === 'okta')) {
    const mr = await L.oktaAll(`/api/v1/groups/${encodeURIComponent(g.id)}/users?limit=200`, { maxPages: maxUserPages });
    g.members = (mr.items || []).map((x) => ({ id: x.id, userName: x.profile && (x.profile.login || x.profile.email) || x.credentials && x.credentials.userName || null, status: x.status || null }));
    g.membersComplete = !!mr.ok;
    if (!mr.ok) errors.push({ read: 'group-members-' + g.id, status: mr.status, error: mr.error || 'incomplete group membership read', partial: !!mr.partial, permission: 'okta.groups.read' });
  }

  // Direct user assignments (scope USER vs GROUP). Keep the complete direct list when pagination completes;
  // assigning only a sample would silently remove access when Entra requires assignment.
  const ur = await L.oktaAll(`/api/v1/apps/${oktaId}/users?limit=200`, { maxPages: maxUserPages });
  if (ur.status === 200) {
    const items = ur.items;
    const direct = items.filter((u) => u.scope === 'USER');
    extras.users = { count: ur.partial ? null : items.length, seen: items.length, direct: ur.partial ? null : direct.length, viaGroup: ur.partial ? null : items.length - direct.length, partial: !!ur.partial,
      directComplete: !ur.partial,
      directSample: direct.map((u) => ({ id: u.id, userName: u.credentials && u.credentials.userName, status: u.status })),
      statuses: items.reduce((m, u) => { m[u.status] = (m[u.status] || 0) + 1; return m; }, {}),
      error: ur.partial ? 'more than ' + (maxUserPages * 200) + ' assignments; the direct-assignment list beyond the first ' + items.length + ' is unknown' : null };
  } else { extras.users = { count: null, direct: null, viaGroup: null, partial: null, error: ur.error }; errors.push({ read: 'users', status: ur.status, error: ur.error }); }

  /* Provisioning dependency inventory. Okta never returns the SCIM bearer token here and this
     code never requests or stores one. What we do need before a migration can be called complete
     is the application-user schema plus both directions of the profile mapping. Those definitions
     become the Entra provisioning mapping worksheet after the vendor creates a new endpoint/token. */
  const provisioningEnabled = asArr(raw.features).some((f) => D.PROVISIONING_FEATURES.has(f));
  if (provisioningEnabled) {
    const reads = {}; const invErrors = []; const summaries = [];
    for (const q of [
      { key: 'toApp', path: `/api/v1/mappings?targetId=${encodeURIComponent(oktaId)}&limit=200` },
      { key: 'fromApp', path: `/api/v1/mappings?sourceId=${encodeURIComponent(oktaId)}&limit=200` },
    ]) {
      const mr = await L.oktaAll(q.path, { maxPages: 5 });
      reads[q.key] = { status: mr.status, count: mr.items.length, complete: !!mr.ok };
      if (mr.ok) summaries.push(...mr.items);
      else {
        const er = { read: 'profile-mappings-' + q.key, status: mr.status, error: mr.error, permission: 'okta.profileMappings.read' };
        errors.push(er); invErrors.push(er.error || ('HTTP ' + mr.status));
      }
    }
    const detail = [];
    const ids = [...new Set(summaries.map((m) => m && m.id).filter(Boolean))];
    for (const id of ids) {
      const md = await L.oktaGet(`/api/v1/mappings/${encodeURIComponent(id)}`);
      if (md.status === 200 && md.body) detail.push(md.body);
      else {
        const er = { read: 'profile-mapping-' + id, status: md.status, error: md.error, permission: 'okta.profileMappings.read' };
        errors.push(er); invErrors.push(er.error || ('HTTP ' + md.status));
      }
    }
    extras.profileMappings = normalizeProfileMappings(detail.length ? detail : summaries, oktaId);
    reads.mappingDetails = { status: invErrors.length ? 'partial' : 200, count: extras.profileMappings.length, complete: invErrors.length === 0 };

    const sr = await L.oktaGet(`/api/v1/meta/schemas/apps/${encodeURIComponent(oktaId)}/default`);
    reads.appUserSchema = { status: sr.status, complete: sr.status === 200 };
    if (sr.status === 200 && sr.body) extras.appUserSchema = normalizeAppUserSchema(sr.body);
    else {
      const er = { read: 'app-user-schema', status: sr.status, error: sr.error, permission: 'okta.schemas.read' };
      errors.push(er); invErrors.push(er.error || ('HTTP ' + sr.status));
    }
    attachProvisioningExternalNames(extras.profileMappings, extras.appUserSchema);

    if (asArr(raw.features).includes('GROUP_PUSH')) {
      const gp = await L.oktaAll(`/api/v1/apps/${encodeURIComponent(oktaId)}/group-push/mappings?limit=100`, { maxPages: 25 });
      reads.groupPush = { status: gp.status, count: gp.items.length, complete: !!gp.ok };
      if (gp.ok) extras.groupPushMappings = normalizeGroupPushMappings(gp.items);
      else {
        extras.groupPushMappings = normalizeGroupPushMappings(gp.items);
        const er = { read: 'group-push-mappings', status: gp.status, error: gp.error, permission: 'okta.apps.read' };
        errors.push(er); invErrors.push(er.error || ('HTTP ' + gp.status));
      }
    } else {
      extras.groupPushMappings = [];
      reads.groupPush = { status: 'not_applicable', count: 0, complete: true };
    }

    const cr = await L.oktaGet(`/api/v1/apps/${encodeURIComponent(oktaId)}/connections/default`);
    reads.connection = { status: cr.status, complete: cr.status === 200 };
    if (cr.status === 200 && cr.body) extras.provisioningConnection = normalizeProvisioningConnection(cr.body);
    else {
      const er = { read: 'provisioning-connection', status: cr.status, error: cr.error, permission: 'okta.apps.read' };
      errors.push(er); invErrors.push(er.error || ('HTTP ' + cr.status));
    }
    extras.provisioningInventory = { complete: invErrors.length === 0, reads, errors: invErrors,
      outbound: extras.profileMappings.filter((m) => m.direction === 'to_app').length,
      inbound: extras.profileMappings.filter((m) => m.direction === 'from_app').length,
      groupPush: extras.groupPushMappings.length };
  } else {
    extras.provisioningInventory = { complete: true, reads: {}, errors: [], outbound: 0, inbound: 0, groupPush: 0 };
  }

  // app sign-on policy + rules
  const apHref = raw._links && raw._links.accessPolicy && raw._links.accessPolicy.href;
  if (apHref) {
    const p = await L.oktaGet(apHref);
    if (p.status === 200 && p.body) {
      const rr = await L.oktaGet(apHref.replace(/\/+$/, '') + '/rules');
      extras.accessPolicy = { id: p.body.id, name: p.body.name, status: p.body.status, type: p.body.type, rules: rr.status === 200 ? asArr(rr.body).map(normPolicyRule) : null, rulesError: rr.status === 200 ? null : rr.error };
      if (rr.status !== 200) errors.push({ read: 'policy-rules', status: rr.status, error: rr.error });
    } else { extras.accessPolicy = { id: null, error: p.error }; errors.push({ read: 'policy', status: p.status, error: p.error }); }
  } else extras.accessPolicy = { id: null, error: 'the app object exposes no accessPolicy link (legacy sign-on mode or platform app)' };

  // signing key expiry (SAML)
  const kid = raw.credentials && raw.credentials.signing && raw.credentials.signing.kid;
  if (kid && raw.signOnMode === 'SAML_2_0') {
    const k = await L.oktaGet(`/api/v1/apps/${oktaId}/credentials/keys/${kid}`);
    if (k.status === 200 && k.body) extras.signingCert = { kid: k.body.kid, created: k.body.created || null, expiresAt: k.body.expiresAt || null, x5tS256: k.body['x5t#S256'] || null, keyType: k.body.kty || null, daysLeft: k.body.expiresAt ? Math.round((new Date(k.body.expiresAt) - Date.now()) / 86400000) : null };
    else errors.push({ read: 'signing-key', status: k.status, error: k.error });
  }

  // Entra gallery template (OIN SAML/OIDC apps only)
  const mode = raw.signOnMode;
  const oin = !!(raw.name && !/^(auction_|oidc_client|bookmark|template_)/i.test(raw.name));
  if (oin && (mode === 'SAML_2_0' || mode === 'OPENID_CONNECT')) {
    try { extras.entraTemplate = await entraTemplateFor(raw.label, raw.name, caches.templates); }
    catch (e) { extras.entraTemplate = { id: null, error: e.message }; }
  }

  // resolve groups in Entra (live Graph reads)
  if (extras.groups) {
    for (const g of extras.groups) {
      if (g.type === 'ad' || g.type === 'okta' || g.type === 'unknown') g.entra = await resolveGroupLive(g, caches.groups);
      else g.entra = { entraId: null, how: null, candidates: 0, error: null, note: 'app-sourced or built-in group; not a directory group' };
    }
  }

  const [[prev]] = await pool.query(`SELECT owner FROM oem_app_scan WHERE okta_id=?`, [oktaId]);
  extras.owner = prev && prev.owner ? prev.owner : null;
  const model = normalizeOktaApp(raw, extras);
  const complete = errors.length === 0;
  const rawStore = L.redact({ app: raw, groups: extras.groups || null, users: extras.users || null,
    accessPolicy: extras.accessPolicy || null, signingCert: extras.signingCert || null,
    entraTemplate: extras.entraTemplate || null, profileMappings: extras.profileMappings || null,
    appUserSchema: extras.appUserSchema || null, provisioningConnection: extras.provisioningConnection || null,
    groupPushMappings: extras.groupPushMappings || null, provisioningInventory: extras.provisioningInventory || null });
  const normalized = L.redact(model);
  /* redact() blanks any key whose name merely contains "secret"/"token"; three OIDC
     fields carry those substrings but hold non-secret client configuration, not secret
     material. Restore them from the pre-redaction model so buildPlan and assessApp do
     not read a blanked value as truthy -- that made every native OIDC migration create a
     client secret and grant offline_access (app + tenant consent) unconditionally. */
  if (normalized.oidc && model.oidc) {
    normalized.oidc.secretRequired = model.oidc.secretRequired;
    normalized.oidc.refreshTokens = model.oidc.refreshTokens;
    normalized.oidc.tokenEndpointAuthMethod = model.oidc.tokenEndpointAuthMethod;
  }
  await pool.query(`INSERT INTO oem_app_scan (okta_id, scanned_at, scanned_by, complete, errors, normalized, raw)
                    VALUES (?,NOW(),?,?,?,?,?)
                    ON DUPLICATE KEY UPDATE scanned_at=NOW(), scanned_by=VALUES(scanned_by), complete=VALUES(complete), errors=VALUES(errors), normalized=VALUES(normalized), raw=VALUES(raw)`,
    [oktaId, actor, complete ? 1 : 0, JSON.stringify(errors), JSON.stringify(normalized), JSON.stringify(rawStore)]);
  log(`scanned ${raw.label} (${raw.signOnMode || 'no mode'}): ${(extras.groups || []).length} groups, ${extras.users && extras.users.seen !== undefined ? extras.users.seen : '?'} assignments, policy ${extras.accessPolicy && extras.accessPolicy.rules ? extras.accessPolicy.rules.length + ' rules' : 'unknown'}${provisioningEnabled ? ', provisioning ' + ((extras.profileMappings || []).length) + ' attribute mapping(s), ' + ((extras.groupPushMappings || []).length) + ' group-push mapping(s)' : ''}${errors.length ? ', ' + errors.length + ' read error(s)' : ''}`, errors.length ? 'warn' : 'info');
  return { ok: true, oktaId, complete, errors, model };
}

/** Scan every application-category Okta app (active first). Paced by the Okta client; cancellable. */
async function scanAll(log, { actor = null, onlyActive = false, ids = null } = {}) {
  const where = [];
  if (onlyActive) where.push(`status='ACTIVE'`);
  if (ids && ids.length) where.push(`okta_id IN (${ids.map(() => '?').join(',')})`);
  const [apps] = await pool.query(`SELECT okta_id, name, label, status, sign_on_mode FROM okta_apps ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY status='ACTIVE' DESC, assigned_user_count DESC`, ids || []);
  const scope = apps.filter((a) => D.classifyOktaApp(a).category === 'applications');
  log(`scan-all: ${scope.length} applications (${apps.length - scope.length} platform/dependency apps skipped). Okta /apps bucket is 50 calls/min; expect ~${Math.ceil(scope.length * 6 / 50)} min.`);
  const caches = { groups: new Map(), templates: new Map() };
  const out = { scanned: 0, complete: 0, withErrors: 0, failed: 0, cancelled: false };
  let i = 0;
  for (const a of scope) {
    if (log.cancelled && log.cancelled()) { out.cancelled = true; log('cancel requested; stopping after ' + out.scanned + ' apps (each stored scan is whole)', 'warn'); break; }
    i++;
    try {
      const r = await scanApp(a.okta_id, log, { actor, caches });
      out.scanned++;
      if (!r.ok) out.failed++; else if (r.complete) out.complete++; else out.withErrors++;
    } catch (e) { out.failed++; log(`scan failed for ${a.label}: ${e.message}`, 'error'); }
    if (i % 10 === 0) log(`progress ${i}/${scope.length}`);
  }
  log(`scan-all done: ${out.scanned} scanned, ${out.complete} complete, ${out.withErrors} with read errors, ${out.failed} failed`);
  return out;
}

async function loadScan(oktaId) {
  const [[r]] = await pool.query(`SELECT okta_id, scanned_at, scanned_by, complete, errors, normalized, raw, owner, inputs FROM oem_app_scan WHERE okta_id=?`, [oktaId]);
  if (!r) return null;
  const model = j(r.normalized, null);
  const inputs = j(r.inputs, null) || {};
  applyInputs(model, inputs, r.owner); // technician-supplied values fill only what the scan lacks; each is labelled in model.inputSources
  if (model && model.auth) resolveTarget(model, guideForModel(model)); // SAML → OIDC switch: synthesise the OIDC client model from the recorded inputs
  if (model) {
    model.provisioning.fingerprint = provisioningFingerprint(model.provisioning);
    model.sourceFingerprint = migrationSourceFingerprint(model);
    model.sourceContractComplete = migrationSourceComplete(model);
  }
  return { oktaId: r.okta_id, scannedAt: r.scanned_at, scannedBy: r.scanned_by, complete: !!r.complete, errors: j(r.errors, []), model, raw: j(r.raw, null), owner: r.owner || null, inputs };
}

module.exports = { PERM, CLS, ENTRA_GRANTOR, READ_GRANTOR, OKTA_GRANTOR, permCheck,
  mapClaimExpression, normalizeProfileMappings, normalizeGroupPushMappings, normalizeAppUserSchema,
  normalizeProvisioningConnection, provisioningSemantics, provisioningContract, provisioningFingerprint,
  migrationSourceContract, migrationSourceComplete, migrationSourceFingerprint,
  migrationBlockingScanErrors, migrationPolicyScanErrors, migrationScanComplete,
  normalizeOktaApp, normPolicyRule, resolveGroupLive, entraTemplateFor, scanApp, scanAll, loadScan,
  asArr, isHttps, PRIVILEGED_HINTS };

/* ============================================================= assessment */

/** Non-gallery ("custom") application template: instantiating it creates app + service principal in one call. */
const NON_GALLERY_TEMPLATE = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621';

/** Is OpenID Connect evidenced as supported by the vendor, and on what evidence: owner answer > vendor documentation > Entra gallery. */
function oidcSupport(m, guide, tpl) {
  const answer = (m.identity && m.identity.vendorOidc) || null;
  const g = guide && guide.ssoSupport;
  const gOidc = !!(g && Array.isArray(g.protocols) && g.protocols.some((p) => /openid|oidc/i.test(p)));
  const gRec = !!(g && g.recommended && g.recommended.protocol === 'oidc');
  const tplOidc = !!(tpl && Array.isArray(tpl.modes) && tpl.modes.includes('oidc'));
  if (answer === 'no') return { level: 'owner_no', available: false, short: 'the owner answered no', detail: 'The application owner answered that the vendor does not support OpenID Connect.' };
  if (answer === 'yes') return { level: 'owner', available: true, shape: 'app_registration', short: 'owner confirmed', detail: 'The application owner confirmed the vendor accepts a custom OpenID Connect identity provider (issuer, client id, secret).' };
  if (gRec || gOidc) return { level: 'vendor_doc', available: true, shape: (g.oidcShape || 'vendor_consent'), short: 'vendor documentation', detail: `${guide.vendor}: vendor documentation (checked ${guide.checkedAt}) lists OpenID Connect${gRec ? ', and the guide recommends it for coexistence' : ''}.` };
  if (tplOidc) return { level: 'gallery', available: true, shape: 'vendor_consent', short: 'Entra gallery', detail: `The Entra gallery entry "${tpl.displayName}" offers OpenID Connect for this vendor (the vendor's own multi-tenant application, added by consent); not yet confirmed by the owner for this application.` };
  return { level: 'none', available: false, short: 'no evidence', detail: 'No evidence either way: the scan cannot see vendor capabilities. Record the owner\'s answer under Provide inputs.' };
}
/** The protocol staged in Entra: differs from the Okta sign-on type only for a SAML → OIDC switch. */
function entraProto(m) { return m && m.oidc && m.oidc.switched ? 'oidc' : (m && m.auth ? m.auth.type : null); }
/** Protocol recommendation with the reason, from the scanned configuration, the vendor evidence and the recorded choice.
    OpenID Connect is preferred for every application evidenced to support it, whatever Okta uses today; a recorded
    "Target protocol in Entra: SAML" keeps the vendor-side integration as it is. Nothing is switched without evidence or a choice. */
function recommendProtocol(m, guide) {
  const t = m.auth.type;
  const tpl = m.saml && m.saml.entraTemplate;
  const tplModes = tpl && Array.isArray(tpl.modes) ? tpl.modes : null;
  if (t === 'oidc') return { recommended: 'oidc', reason: 'The application already signs in with OpenID Connect against Okta. An Entra app registration replaces the Okta client; the application keeps the same protocol and only its issuer, client id and secret change.', alternatives: [{ protocol: 'saml', why: 'Only if the application cannot take a new OIDC issuer; it would mean re-integrating the app, which the scan cannot justify.' }], confidence: 'high' };
  if (t === 'saml') {
    const ev = oidcSupport(m, guide, tpl);
    const choice = (m.identity && m.identity.protocolChoice) || null;
    const cs = (m.inputSources && m.inputSources.protocolChoice) || {};
    const chosenBy = choice ? ` (recorded by ${cs.by || 'a technician'} on ${dOnly(cs.at)})` : '';
    const samlHow = m.saml.custom ? 'Custom SAML integration in Okta (explicit ACS URL and entity id): Entra reproduces it as a non-gallery SAML application with the same entity id, reply URL and claims.'
      : tpl && tpl.id ? (tplModes && !tplModes.includes('saml') ? `The Entra gallery entry "${tpl.displayName}" lists ${tplModes.join(', ') || 'no'} single sign-on modes, so SAML is configured as a non-gallery (custom) application.` : `SAML through the Okta Integration Network; the Entra gallery has a matching entry ("${tpl.displayName}", modes: ${tplModes.join(', ')}).`)
      : 'SAML through the Okta Integration Network; no matching Entra gallery entry was found, so it becomes a non-gallery SAML application.';
    const samlNonGallery = !(tpl && tpl.id) || !!(tplModes && !tplModes.includes('saml'));
    const samlConf = tpl && tpl.id && !(tplModes && !tplModes.includes('saml')) ? 'high' : 'medium';
    if (choice === 'saml') return { recommended: 'saml', reason: `Staged as SAML by choice${chosenBy}: the vendor-side integration stays as it is today. ${samlHow}${ev.available ? ' OpenID Connect is available (' + ev.short + ') and stays the preferred target if the owner agrees later.' : ''}`, alternatives: ev.available ? [{ protocol: 'oidc', why: 'Preferred wherever the vendor supports it; change "Target protocol in Entra" under Provide inputs.' }] : [], confidence: samlConf, template: tpl || null, nonGallery: samlNonGallery, kept: true, evidence: ev.level };
    if (choice === 'oidc' || ev.available) return { recommended: 'oidc', reason: `OpenID Connect is preferred for every application that supports it, whatever Okta uses today — ${choice === 'oidc' ? 'recorded choice' + chosenBy + (ev.available ? '; ' + ev.short : '') : ev.short}: ${choice === 'oidc' && !ev.available ? 'the technician recorded OIDC as the target protocol.' : ev.detail} The application side is reconfigured either way when it moves to Entra (SAML: new identity-provider metadata and certificate; OIDC: issuer, client id and secret), and OIDC avoids certificate rotation later. ${(choice === 'oidc' && !ev.available ? 'app_registration' : (ev.shape || 'app_registration')) === 'vendor_consent' ? 'The vendor creates the Entra integration itself (an Entra administrator signs in from the vendor console and accepts the Microsoft consent); nothing is staged from this page for that shape — not yet automated. Choose SAML to stage from here instead.' : 'Staging creates an Entra app registration; the redirect URI(s) come from the vendor\'s OpenID Connect settings or the application owner.'}`, alternatives: [{ protocol: 'saml', why: 'Keeps the vendor-side integration as it is today: record "Target protocol in Entra: SAML" under Provide inputs.' }], confidence: choice === 'oidc' || ev.level === 'owner' || ev.level === 'vendor_doc' ? 'high' : 'medium', template: tpl || null, nonGallery: false, switch: { from: 'saml', to: 'oidc', evidence: ev.level, chosen: choice === 'oidc', shape: choice === 'oidc' && !ev.available ? 'app_registration' : (ev.shape || 'app_registration') }, evidence: ev.level };
    return { recommended: 'saml', reason: `${samlHow} OpenID Connect is not chosen because ${ev.level === 'owner_no' ? 'the application owner answered that the vendor does not support it' : 'the scan finds no evidence the application supports it (record the owner\'s answer under Provide inputs)'}.`, alternatives: ev.level === 'owner_no' ? [] : [{ protocol: 'oidc', why: 'Preferred if the vendor supports it: record the owner\'s answer, or "Target protocol in Entra: OIDC", under Provide inputs.' }], confidence: samlConf, template: tpl || null, nonGallery: samlNonGallery, evidence: ev.level };
  }
  if (t === 'bookmark') {
    if (m.bookmark.target === 'entra_launcher') return { recommended: 'none', reason: 'The Okta tile already points at Entra My Apps (launcher link). Nothing authenticates through Okta; the tile can be retired once users find the app in My Apps.', alternatives: [], confidence: 'high' };
    if (m.bookmark.target === 'okta_hosted') return { recommended: 'depends', reason: 'The tile links to an Okta-hosted sign-in URL, so it depends on another Okta app. Migrate that application first; then repoint or retire this tile.', alternatives: [], confidence: 'high' };
    return { recommended: 'linked', reason: `The tile is a bookmark to ${m.bookmark.host || 'an external URL'} and does not authenticate. In Entra this is a linked (bookmark) application on My Apps; no protocol is involved.`, alternatives: [], confidence: 'high' };
  }
  if (t === 'swa') return { recommended: 'password', reason: 'Okta signs users in by filling a stored password (SWA). Entra offers password-based single sign-on through the My Apps browser extension; the sign-in form must be captured in the portal, and users re-enter their credentials once. Consider retiring the app or moving it to federation with the vendor instead.', alternatives: [{ protocol: 'saml', why: 'If the vendor supports SAML/OIDC, a federation integration is the better target.' }], confidence: 'medium' };
  if (t === 'saml11' || t === 'federation') return { recommended: 'unsupported', reason: 'This is the Office 365 / WS-Federation domain federation. Moving it is a domain-level cutover (Set-MsolDomainAuthentication / Graph domain federation), not an application migration; it is tracked under Remaining Okta Dependencies.', alternatives: [], confidence: 'high' };
  if (t === 'radius') return { recommended: 'unsupported', reason: 'RADIUS is not an Entra application. The equivalent is the NPS extension for Entra MFA on the RADIUS server, or moving the VPN/appliance to SAML.', alternatives: [], confidence: 'high' };
  if (t === 'mfa_service') return { recommended: 'unsupported', reason: 'Okta MFA-as-a-service (RDP/credential provider). The equivalent is Entra MFA via the NPS extension or Windows Hello / passwordless; not an application migration.', alternatives: [], confidence: 'high' };
  if (t === 'wsfed') return { recommended: 'wsfed', reason: 'WS-Federation apps are supported in Entra only through gallery templates that offer WS-Fed; otherwise the application must move to SAML.', alternatives: [{ protocol: 'saml', why: 'When no gallery template offers WS-Fed.' }], confidence: 'medium' };
  return { recommended: 'unknown', reason: 'The sign-on mode (' + (m.auth.mode || 'none') + ') is not one this engine recognises; classify it by hand.', alternatives: [], confidence: 'low' };
}

/** Okta app sign-on policy rule → Entra Conditional Access mapping rows. */
function policyMappingRows(m) {
  const ap = m.assignments.accessPolicy;
  const rows = [];
  const add = (okta, entra, status, note, ruleName) => rows.push({ okta, entra, status, note: note || null, rule: ruleName || null });
  if (!ap || ap.error) { add('App sign-on policy', 'Conditional Access policy targeting the app', 'unknown', ap && ap.error ? ap.error : 'not scanned'); return rows; }
  const rules = (ap.rules || []).filter((r) => r.status === 'ACTIVE');
  if (!rules.length) { add('App sign-on policy "' + ap.name + '"', 'Conditional Access', 'unknown', ap.rulesError || 'no active rules read'); return rows; }
  for (const r of rules) {
    const scope = [];
    if (r.conditions.groupsInclude.length) scope.push(r.conditions.groupsInclude.length + ' included group(s)');
    if (r.conditions.groupsExclude.length) scope.push(r.conditions.groupsExclude.length + ' excluded group(s)');
    if (r.conditions.usersInclude.length || r.conditions.usersExclude.length) scope.push('user-level include/exclude');
    if (scope.length) add(`Rule "${r.name}": ${scope.join(', ')}`, 'CA policy users/groups include/exclude', r.conditions.usersInclude.length || r.conditions.usersExclude.length ? 'review' : 'ready', r.conditions.usersInclude.length || r.conditions.usersExclude.length ? 'User-level scoping must be rebuilt with Entra user object ids (resolved by UPN at staging time).' : 'Groups are resolved to Entra groups by SID.', r.name);
    if (r.access === 'DENY') add(`Rule "${r.name}": DENY`, 'CA policy: Block access', 'review', 'Block rules are order-sensitive in Okta; in Entra every matching block applies. Confirm the intended population.', r.name);
    if (r.mfa) add(`Rule "${r.name}": ${r.factorMode} / possession required`, 'CA grant: Require authentication strength (' + (r.phishingResistant ? 'Phishing-resistant MFA' : 'Multifactor authentication') + ')', 'ready', null, r.name);
    else if (r.access === 'ALLOW') add(`Rule "${r.name}": ${r.factorMode || '1FA'} (password only)`, 'CA grant: none (single factor) — the tenant baseline still applies', 'review', 'Okta allows single-factor for this population; confirm that matches the Entra tenant baseline (do not weaken it to match).', r.name);
    if (r.reauthenticateIn && r.reauthenticateIn !== 'PT0S') add(`Rule "${r.name}": re-authenticate every ${r.reauthenticateIn}`, 'CA session: Sign-in frequency', /^PT(\d+)H$/.test(r.reauthenticateIn) && parseInt(r.reauthenticateIn.slice(2), 10) <= 24 * 365 ? 'ready' : 'review', 'Sign-in frequency takes hours or days; ' + r.reauthenticateIn + (r.reauthenticateIn === 'PT43800H' ? ' is Okta\'s "never" (5 years) — leave Entra at the tenant default.' : ''), r.name);
    if (r.conditions.network) add(`Rule "${r.name}": network ${r.conditions.network.connection}${r.conditions.network.include.length ? ' (' + r.conditions.network.include.length + ' zone(s))' : ''}`, 'CA condition: Named location' + (r.conditions.network.connection === 'ZONE' ? ' (zone parity from the Security section)' : ''), r.conditions.network.connection === 'ZONE' ? 'review' : 'ready', r.conditions.network.connection === 'ZONE' ? 'Each Okta zone must have an Entra named location with the same CIDRs (see Zone parity).' : 'ANYWHERE maps to all locations.', r.name);
    if (r.conditions.device) add(`Rule "${r.name}": device ${[r.conditions.device.registered !== null ? 'registered=' + r.conditions.device.registered : null, r.conditions.device.managed !== null ? 'managed=' + r.conditions.device.managed : null, r.conditions.device.assurance ? 'assurance policy' : null].filter(Boolean).join(', ')}`, 'CA grant: Require compliant device / Hybrid joined (Intune compliance replaces Okta Verify device trust)', 'review', 'Device trust semantics differ: Okta "managed" is asserted by the Okta Verify integration; Entra uses Intune compliance or hybrid join. Confirm every user population has enrolled devices before enforcing.', r.name);
    if (r.conditions.platform && r.conditions.platform.length) add(`Rule "${r.name}": platforms ${r.conditions.platform.join(', ')}`, 'CA condition: Device platforms', 'ready', null, r.name);
    if (r.conditions.riskScore && r.conditions.riskScore !== 'ANY') add(`Rule "${r.name}": risk ${r.conditions.riskScore}`, 'CA condition: Sign-in risk (Entra ID Protection, requires P2)', 'review', 'Risk levels are not equivalent between vendors; start in report-only.', r.name);
    if (r.conditions.userType && (r.conditions.userType.include.length || r.conditions.userType.exclude.length)) add(`Rule "${r.name}": user type`, 'CA users: guest/external user types', 'review', null, r.name);
    if (r.conditions.elCondition) add(`Rule "${r.name}": expression condition`, 'no equivalent', 'not_transferable', 'Okta EL rule conditions have no Conditional Access equivalent; rebuild the intent with groups or filters.', r.name);
  }
  return rows;
}

/**
 * Readiness score + status, per-step automation class, safety stops and classification.
 * ctx: { roles: string[]|null, okta: identity, facts: work-item facts (match + entra), migration: latest row|null }
 */
function assessApp(scan, ctx) {
  const m = scan.model;
  const blockingScanErrors = migrationBlockingScanErrors(scan.errors);
  const policyScanErrors = migrationPolicyScanErrors(scan.errors);
  const scanComplete = migrationScanComplete(scan);
  const roles = ctx.roles === undefined ? null : ctx.roles;
  const facts = ctx.facts || {};
  const match = facts.match || { decision: 'none' };
  const entra = facts.entra || null;
  const guide = ctx.guide !== undefined ? ctx.guide : guideForModel(m);
  const proto = resolveTarget(m, guide);
  const t = m.auth.type;
  const e = entraProto(m); // the protocol staged in Entra (differs from t only for a SAML → OIDC switch)
  const unsupported = ['saml11', 'federation', 'radius', 'mfa_service', 'ad_agent', 'ldap_interface'].includes(t) || proto.recommended === 'unsupported' || proto.recommended === 'unknown';
  const users = m.assignments.users || {};
  const groups = m.assignments.groups || [];
  const cats = {};
  const cat = (key, label, max) => { cats[key] = { key, label, max, score: max, status: 'ok', findings: [], na: false }; return cats[key]; };
  const hit = (c, points, status, text) => { c.score = Math.max(0, c.score - points); if (status === 'blocked' || (status === 'action' && c.status !== 'blocked') || (status === 'review' && c.status === 'ok')) c.status = status; c.findings.push({ status, text }); };
  const na = (c, text) => { c.na = true; c.status = 'na'; c.score = 0; c.max = 0; if (text) c.findings.push({ status: 'na', text }); };
  const stops = [];
  const stop = (key, severity, why) => stops.push({ key, severity, why });

  /* 1 authentication */
  const cAuth = cat('authentication', 'Authentication method', 8);
  if (t === 'unknown') hit(cAuth, 8, 'blocked', 'Sign-on mode not recognised.');
  else if (unsupported) hit(cAuth, 8, 'blocked', proto.reason);
  else if (t === 'swa') hit(cAuth, 5, 'action', 'Password-based (SWA): the sign-in form must be captured in the Entra portal; users re-enter credentials once.');
  else if (t === 'bookmark' && m.bookmark.target === 'okta_hosted') hit(cAuth, 6, 'action', 'Bookmark to an Okta-hosted sign-in link: depends on another Okta app.');
  /* 2 protocol */
  const cProto = cat('protocol', 'Protocol / integration path', 10);
  if (proto.confidence === 'medium') hit(cProto, 3, 'review', 'Protocol recommendation has medium confidence: ' + (proto.nonGallery ? 'no Entra gallery entry matched; a non-gallery application is used.' : 'confirm with the application owner.'));
  if (proto.confidence === 'low') hit(cProto, 10, 'blocked', proto.reason);
  if (proto.switch) cProto.findings.push({ status: 'info', text: `Protocol switch SAML → OpenID Connect (${proto.switch.chosen ? 'recorded choice' : 'evidence: ' + String(proto.switch.evidence).replace('_', ' ')}). On the application side the SAML identity-provider settings are replaced by an OIDC client configuration; keep SAML instead by recording "Target protocol in Entra: SAML" under Provide inputs.` });
  if (t === 'oidc' && m.oidc.issuerMode === 'CUSTOM_URL') hit(cProto, 2, 'review', 'The Okta client uses a custom-domain issuer; the application must accept the Entra issuer (login.microsoftonline.com/<tenant>/v2.0).');
  /* 3 claims */
  const cClaims = cat('claims', 'Claims / attributes', 10);
  if (e === 'saml') {
    const bad = m.saml.attributes.filter((a) => !a.mapping.mappable);
    if (bad.length) { hit(cClaims, Math.min(10, 4 + bad.length * 2), 'action', bad.length + ' attribute statement(s) do not map 1:1: ' + bad.map((a) => a.name + ' = ' + a.values.join(',') + ' (' + a.mapping.reason + ')').join('; ')); stop('claims_ambiguous', 'review', 'Attribute statements use expressions or app-user attributes that cannot be translated automatically; a person defines the Entra claim.'); }
    if (m.saml.nameId.format && !/unspecified|emailAddress|persistent|transient/i.test(m.saml.nameId.format)) hit(cClaims, 2, 'review', 'NameID format ' + m.saml.nameId.format + ' — Entra supports unspecified, emailAddress, persistent and transient.');
    if (m.saml.nameId.template && !/^\$\{user\.(login|email|userName)\}$/.test(m.saml.nameId.template) && !/^\$\{(user\.)?(login|email)\}$/.test(m.saml.nameId.template)) hit(cClaims, 2, 'review', 'NameID uses template ' + m.saml.nameId.template + '; Entra NameID sources are UPN, email, employee id, on-premises sAMAccountName or an extension attribute.');
    if (m.saml.inlineHooks) hit(cClaims, 4, 'action', 'A SAML inline hook rewrites assertions in Okta; Entra has no equivalent — the logic must move to a custom claims provider or be dropped.');
  } else if (e === 'oidc') {
    if (m.oidc.shape === 'vendor_consent') cClaims.findings.push({ status: 'info', text: 'Claims are defined by the vendor\'s own Entra integration (consent); nothing to map here.' });
    else if (m.oidc.switched) cClaims.findings.push({ status: 'info', text: 'Protocol switch SAML → OIDC: ' + (m.saml.attributes.length ? m.saml.attributes.length + ' SAML attribute statement(s) (' + m.saml.attributes.map((a) => a.name).join(', ') + ') are not carried over automatically; standard OIDC claims cover email, name and UPN' + (m.saml.groupClaims.length ? ', the group claim is configured' : '') + ', anything else is defined as optional claims with the owner.' : 'no SAML attribute statements beyond the defaults; standard OIDC claims (sub, oid, email, name, preferred_username) are issued.') });
    else if (m.oidc.claims === null) cClaims.findings.push({ status: 'info', text: 'Custom claims come from the Okta authorization server policy, which is not part of the app object; standard OIDC claims (sub, email, name, preferred_username, groups if configured) are assumed. Confirm any custom claim with the application owner.' });
  } else na(cClaims, 'No claims for this sign-on mode.');
  /* 4 redirect / ACS */
  const cUri = cat('redirect', 'Redirect URIs / reply URLs', 10);
  if (e === 'oidc') {
    if (m.oidc.shape === 'vendor_consent') cUri.findings.push({ status: 'info', text: 'No redirect URI is needed here: the vendor\'s own Entra integration (Microsoft consent) owns the redirect URIs.' });
    else if (!m.oidc.redirectUris.length) hit(cUri, 10, 'blocked', m.oidc.switched ? 'No redirect URI recorded for the OpenID Connect registration (the Okta app is SAML, so there is nothing to copy). Take the callback / redirect URL from the vendor\'s OpenID Connect settings and record it under Provide inputs.' : 'No redirect URI on the Okta client.');
    const http = m.oidc.redirectUris.filter((u) => !isHttps(u) && !/^http:\/\/localhost/i.test(u) && !/^[a-z][a-z0-9+.-]*:\/\//i.test(u));
    if (http.length) hit(cUri, 3, 'review', 'Non-HTTPS redirect URI(s): ' + http.join(', '));
    if (m.oidc.wildcardRedirect === 'SUBDOMAIN' || m.oidc.redirectUris.some((u) => u.includes('*'))) hit(cUri, 4, 'action', 'Wildcard redirect URIs are not allowed on an Entra app registration; enumerate the exact URIs.');
    if (m.oidc.applicationType === 'native' && m.oidc.redirectUris.some((u) => /^https?:/.test(u))) cUri.findings.push({ status: 'info', text: 'Native client with web redirect URIs: registered under publicClient/redirectUris.' });
  } else if (e === 'saml') {
    const tplHit = !!(m.saml.entraTemplate && m.saml.entraTemplate.id);
    if (tplHit && m.saml.entraTemplate.ambiguous) hit(cProto, 2, 'review', `More than one Entra gallery template matches this app (${m.saml.entraTemplate.candidates.slice(0, 2).map((c) => '"' + c.displayName + '"').join(', ')}); confirm the template at pre-flight.`);
    if (m.saml.custom) {
      if (!m.saml.acsUrls.length) hit(cUri, 10, 'blocked', 'No ACS URL on the Okta app.');
      if (!m.saml.entityId) hit(cUri, 6, 'blocked', 'No entity id (audience) on the Okta app.');
    } else if (!m.saml.acsUrls.length || !m.saml.entityId) {
      if (tplHit) hit(cUri, 2, 'review', `OIN app: reply URL / entity id come from the vendor template, not the app object. The Entra gallery template "${m.saml.entraTemplate.displayName}" carries the vendor defaults; confirm them against the vendor metadata at pre-flight.`);
      else hit(cUri, 6, 'action', 'OIN app with no matching Entra gallery template: the reply URL and entity id must be taken from the vendor SP metadata before staging.');
    }
    if (m.saml.acsUrls.some((u) => !isHttps(u))) hit(cUri, 3, 'review', 'ACS URL is not HTTPS.');
    if (m.saml.acsIndexed.length > 1) cUri.findings.push({ status: 'info', text: m.saml.acsIndexed.length + ' indexed ACS endpoints; Entra supports multiple reply URLs with an index.' });
  } else if (t === 'bookmark') { if (!m.bookmark.url) hit(cUri, 10, 'blocked', 'Bookmark has no URL.'); }
  else na(cUri);
  for (const [k, sIn] of Object.entries(m.inputSources || {})) { const f = FIELD[k]; if (f) cUri.findings.push({ status: 'info', text: `${f.label}: supplied by ${sIn.by || 'a technician'} on ${dOnly(sIn.at)} — not on the Okta app object; confirm it at pre-flight.` }); }
  /* 5 assignments */
  const cAssign = cat('assignments', 'Groups and assignments', 12);
  if (m.assignments.groupsError) hit(cAssign, 12, 'blocked', 'Group assignments could not be read: ' + m.assignments.groupsError);
  else {
    const unresolved = groups.filter((g) => (g.type === 'ad' || g.type === 'okta' || g.type === 'unknown') && !(g.entra && g.entra.entraId));
    const ambiguous = unresolved.filter((g) => g.entra && g.entra.candidates > 1);
    const graphErr = unresolved.filter((g) => g.entra && g.entra.error);
    const nativeMissing = unresolved.filter((g) => g.type === 'okta' && !(g.entra && (g.entra.error || g.entra.candidates > 1)));
    const adMissing = unresolved.filter((g) => g.type === 'ad' && !(g.entra && (g.entra.error || g.entra.candidates > 1)));
    if (graphErr.length) hit(cAssign, 6, 'blocked', graphErr.length + ' group lookup(s) failed in Graph: ' + graphErr[0].entra.error);
    if (ambiguous.length) hit(cAssign, 3, 'review', ambiguous.length + ' group name(s) match several Entra groups: ' + ambiguous.map((g) => g.name).join(', '));
    if (adMissing.length) hit(cAssign, 4, 'action', adMissing.length + ' AD group(s) assigned in Okta are not synced to Entra (no group with that SID): ' + adMissing.map((g) => g.name).slice(0, 6).join(', ') + (adMissing.length > 6 ? '…' : '') + '. Add them to the Entra Connect sync scope.');
    if (nativeMissing.length) hit(cAssign, 3, 'action', nativeMissing.length + ' Okta-native group(s) have no Entra group: ' + nativeMissing.map((g) => g.name).slice(0, 6).join(', ') + '. They can be created in Entra (approval) and membership rebuilt.');
    if (users.direct === null && users.error) hit(cAssign, 1, 'review', 'Direct user assignments: ' + users.error);
    else if (users.direct > 0) cAssign.findings.push({ status: 'info', text: users.direct + ' user(s) assigned directly (not through a group); recreated as user assignments by UPN.' });
    if (!groups.length && !(users.count > 0)) cAssign.findings.push({ status: 'info', text: 'Nobody is assigned in Okta.' });
  }
  /* 6 MFA — evidence only. MFA is owned by the separate Security & MFA project. */
  const cMfa = cat('mfa', 'MFA evidence (separate project)', 0);
  const ap = m.assignments.accessPolicy;
  const rules = ap && ap.rules ? ap.rules.filter((r) => r.status === 'ACTIVE') : null;
  na(cMfa, 'MFA and authentication-strength requirements are handled by the separate Security & MFA project. They are not copied or required by this application migration.');
  if (!rules) {
    cMfa.findings.push({ status: 'info', text: 'The Okta app sign-on policy was not available. This is recorded as evidence only and does not block application staging.' });
  } else {
    const mfaRules = rules.filter((r) => r.mfa && r.access === 'ALLOW');
    const oneFa = rules.filter((r) => !r.mfa && r.access === 'ALLOW');
    if (mfaRules.length) cMfa.findings.push({ status: 'info', text: `${mfaRules.length} active Okta rule(s) require MFA; retained for the Security & MFA project, not copied here.` });
    if (oneFa.length) cMfa.findings.push({ status: 'info', text: `${oneFa.length} active Okta rule(s) allow single-factor sign-in; Entra tenant policy is evaluated separately and is not weakened by this migration.` });
    if (mfaRules.some((r) => r.phishingResistant || r.hardwareProtected)) cMfa.findings.push({ status: 'info', text: 'Phishing-resistant / hardware-protected factor evidence was recorded for the Security & MFA project.' });
  }
  /* 7 sign-on policy — evidence only. The application runner never writes CA. */
  const cCa = cat('conditionalAccess', 'Sign-on policy evidence (separate project)', 0);
  const pm = policyMappingRows(m);
  const notTransferable = pm.filter((r) => r.status === 'not_transferable');
  const review = pm.filter((r) => r.status === 'review');
  na(cCa, 'Okta sign-on rules are retained as evidence for the separate Security & MFA project and do not gate this application migration.');
  if (!rules) cCa.findings.push({ status: 'info', text: 'No Okta policy rules were available; application staging can continue.' });
  else if (notTransferable.length || review.length) cCa.findings.push({ status: 'info', text: `${notTransferable.length} non-transferable and ${review.length} review mapping row(s) were recorded for the separate project.` });
  else cCa.findings.push({ status: 'info', text: `${pm.length} policy mapping row(s) were recorded for the separate project.` });
  /* 8 provisioning */
  const cProv = cat('provisioning', 'Provisioning', 6);
  if (m.provisioning.enabled) {
    const pi = m.provisioning.inventory || {};
    const maps = m.provisioning.mappings || [];
    const outbound = maps.filter((x) => x.direction === 'to_app');
    const inbound = maps.filter((x) => x.direction === 'from_app');
    const manual = outbound.filter((x) => !(x.mapping && x.mapping.mappable));
    const gp = m.provisioning.groupPush || [];
    // Stored summaries pass through redaction, including credential-named keys.
    // Rebuild these derived flags/lists from the public Okta feature identifiers.
    const sem = provisioningSemantics(m.provisioning.features);
    hit(cProv, pi.complete === true ? 4 : 6, 'action', 'Okta provisions this app (' + m.provisioning.features.join(', ') + '). ' +
      (pi.complete === true
        ? `${outbound.length} outbound and ${inbound.length} inbound attribute mapping(s), plus ${gp.length} group-push mapping(s), were inventoried; ${manual.length} outbound mapping(s) need a deliberate Entra expression.`
        : 'The profile mappings, application-user schema or provisioning connection could not all be read.'));
    if (pi.complete !== true) stop('provisioning_inventory_incomplete', 'stop', 'Provisioning is active but its Okta schema, profile mappings, group-push mappings or connection could not all be read. Grant okta.profileMappings.read, okta.schemas.read and okta.apps.read (or use an admin API token), then rescan.');
    if (sem.sourceAuthorityReview) stop('provisioning_source_authority', 'stop', 'Okta imports profiles or acts as a profile master (' + sem.inbound.join(', ') + '). Choose the future source of authority before configuring outbound Entra provisioning.');
    if (sem.unsupportedCredentialFlow) stop('provisioning_credential_flow', 'stop', 'Okta uses a password or delegated-authentication provisioning feature (' + sem.credential.join(', ') + '). Entra SCIM does not reproduce this automatically; a specialist must select a replacement or record that it is intentionally retired.');
    else stop('provisioning_cutover', 'review', 'Keep Okta provisioning running until the Entra synchronization job has a successful pilot cycle and the owner confirms create, update and deactivate behavior.');
  }
  else na(cProv, 'Okta does not provision this app.');
  /* 9 app configuration */
  const cCfg = cat('appConfig', 'Application configuration', 10);
  if (e === 'saml') {
    if (!m.saml.custom && m.saml.signing.assertionSigned === null) cCfg.findings.push({ status: 'info', text: 'OIN template app: signing and NameID settings are template-defined in Okta and not on the app object; Entra signs response and assertion with SHA-256 by default.' });
    if (m.saml.slo.enabled && !m.saml.slo.logoutUrl) hit(cCfg, 1, 'review', 'SLO enabled without a logout URL.');
    if (m.saml.honorForceAuthn === false) cCfg.findings.push({ status: 'info', text: 'ForceAuthn is ignored in Okta; Entra honours ForceAuthn by default.' });
  } else if (e === 'oidc') {
    if (m.oidc.implicit) hit(cCfg, 3, 'review', 'Implicit grant enabled on the Okta client; enable id-token implicit flow on the Entra registration only if the app really uses it.');
    if (!m.oidc.postLogoutRedirectUris.length) cCfg.findings.push({ status: 'info', text: 'No post-logout redirect URI; front-channel logout URL stays empty.' });
    if (m.oidc.dpop) hit(cCfg, 2, 'review', 'DPoP-bound tokens are enabled; Entra does not support DPoP for this flow.');
  } else if (t === 'swa') hit(cCfg, 6, 'action', 'Form capture for password SSO happens in the portal.');
  if (m.identity.hidden) cCfg.findings.push({ status: 'info', text: 'Hidden from the Okta end-user dashboard; keep it hidden in My Apps (visibleToUsers = false).' });
  /* 10 security */
  const cSec = cat('security', 'Security configuration', 8);
  if (e === 'saml') {
    if (m.saml.signing.signatureAlgorithm && /SHA1/i.test(m.saml.signing.signatureAlgorithm)) { hit(cSec, 4, 'action', 'SHA-1 signature algorithm; Entra signs with SHA-256 — confirm the application accepts it.'); stop('missing_security', 'review', 'Weak signing algorithm on the Okta side; verify the application accepts SHA-256 before cutover.'); }
    if (m.saml.signing.assertionSigned === false && m.saml.signing.responseSigned === false) hit(cSec, 8, 'blocked', 'Neither response nor assertion is signed.');
    if (m.saml.encryption.enabled) hit(cSec, 3, 'action', 'Assertion encryption is on; upload the application\'s encryption certificate to the Entra app (Token encryption) before cutover.');
    if (m.saml.signing.cert && m.saml.signing.cert.daysLeft !== null && m.saml.signing.cert.daysLeft < 30) cSec.findings.push({ status: 'info', text: 'Okta signing certificate expires in ' + m.saml.signing.cert.daysLeft + ' days — irrelevant after migration, urgent if the migration slips.' });
  } else if (e === 'oidc') {
    if (m.oidc.tokenEndpointAuthMethod === 'none' && !m.oidc.pkceRequired) hit(cSec, 3, 'review', 'Public client without PKCE required.');
    if (m.oidc.secretRequired) cSec.findings.push({ status: 'info', text: 'A client secret (or certificate) is required; it is created at staging and shown once, never stored.' });
  } else if (t === 'swa') hit(cSec, 2, 'review', 'Shared/stored passwords; prefer federation.');
  /* 11 automation capability + 12 manual actions — filled after the steps are classified */
  const cAutoCap = cat('automation', 'Automation capability', 6);
  const cManual = cat('manualActions', 'Required manual actions', 4);

  /* ---- safety stops (spec §16) ---- */
  const label = (m.identity.label || '') + ' ' + (m.identity.name || '');
  if (PRIVILEGED_HINTS.test(label)) stop('privileged_app', 'review', 'The application name suggests privileged or security tooling; a failed cutover could lock administrators out. Requires approval and a tested rollback.');
  if (!m.identity.owner) stop('unknown_owner', 'review', 'No application owner is recorded. Record the owner (who confirms the vendor-side change and tests sign-in) before staging.');
  if ((users.count || users.seen || 0) >= 50 || groups.length >= 10) stop('production_impact', 'review', `Production-impacting change: ${users.count !== null && users.count !== undefined ? users.count : '≥' + (users.seen || 0)} assignments / ${groups.length} groups. Staging requires approval and keeps Okta active until validation.`);
  if (match.decision && /^auto_/.test(match.decision)) stop('ambiguous_target', 'stop', `An existing Entra application (${match.entraName || match.entraId}) matches this app but is not confirmed. Confirm it (adopt and update) or reject it (create new) in Review Match first — otherwise staging would create a duplicate.`);
  if (match.decision === 'manual_staged') stop('ambiguous_target', 'stop', 'A staged match is unresolved; finish the review.');
  if (entra && entra.sharedBy > 1) stop('shared_target', 'review', `${entra.sharedBy} Okta apps point at the same Entra app; confirm the migration of this one does not change the others.`);
  if (m.identity.status !== 'ACTIVE') stop('inactive', 'stop', 'The Okta app is ' + m.identity.status + '; migrate active apps, review inactive ones for retirement.');
  if (!scanComplete) stop('scan_incomplete', 'review', 'The last scan had migration-affecting read errors (' + blockingScanErrors.map((e) => e.read).join(', ') + '); rescan before staging.');
  if (unsupported) stop('unsupported_protocol', 'stop', proto.reason);

  /* ---- automation steps ---- */
  const steps = automationSteps(m, proto, { roles, graphError: ctx.graphError || null, readRoles: ctx.readRoles === undefined ? roles : ctx.readRoles, readError: ctx.readError || null, okta: ctx.okta || {}, match, entra, groups, users, stops });
  annotateLanes(steps, m, proto, match, entra, ctx.okta || {});
  const applicable = steps.filter((s) => s.cls !== 'N/A');
  const autoNow = applicable.filter((s) => (s.cls === CLS.AUTO || s.cls === CLS.APPROVAL) && s.runnable);
  const autoDesign = applicable.filter((s) => s.cls === CLS.AUTO || s.cls === CLS.APPROVAL);
  const manual = applicable.filter((s) => s.cls === CLS.MANUAL);
  const unsup = applicable.filter((s) => s.cls === CLS.UNSUPPORTED);
  const entraSide = applicable.filter((s) => s.side === 'entra');
  const entraManual = entraSide.filter((s) => s.cls === CLS.MANUAL || s.cls === CLS.UNSUPPORTED);
  const ownerSteps = applicable.filter((s) => s.side === 'owner');
  if (applicable.length) {
    const pct = autoDesign.length / applicable.length;
    cAutoCap.score = Math.round(6 * pct);
    if (pct < 0.6) { cAutoCap.status = 'action'; cAutoCap.findings.push({ status: 'action', text: Math.round(pct * 100) + '% of steps are automatable.' }); }
    const blocked = autoDesign.filter((s) => !s.runnable);
    if (blocked.length) cAutoCap.findings.push({ status: 'info', text: blocked.length + ' automatic step(s) are blocked today by missing consent: ' + [...new Set(blocked.map((s) => s.missing).filter(Boolean))].join(', ') + '. This does not lower the readiness of the application; it blocks staging.' });
  }
  cManual.score = Math.max(0, 4 - manual.length);
  if (manual.length) cManual.findings.push({ status: manual.length > 2 ? 'action' : 'review', text: manual.length + ' manual step(s): ' + manual.map((s) => s.label).join('; ') });
  if (manual.length > 2) cManual.status = 'action'; else if (manual.length) cManual.status = 'review';

  /* ---- score + status ---- */
  const list = Object.values(cats);
  const maxSum = list.reduce((a, c) => a + c.max, 0);
  const score = maxSum ? Math.round(100 * list.reduce((a, c) => a + c.score, 0) / maxSum) : 0;
  const anyBlocked = list.some((c) => c.status === 'blocked');
  const anyAction = list.some((c) => c.status === 'action');
  const anyReview = list.some((c) => c.status === 'review') || stops.some((s) => s.severity === 'review');
  const hardStop = stops.some((s) => s.severity === 'stop');
  let status, statusLabel;
  if (unsupported) { status = 'blocked'; statusLabel = 'Blocked — not supported'; }
  else if (anyBlocked || hardStop) { status = 'blocked'; statusLabel = 'Blocked'; }
  else if (anyAction || t === 'swa') { status = 'manual'; statusLabel = 'Manual action required'; }
  else if (anyReview || score < 90) { status = 'review'; statusLabel = 'Ready with review'; }
  else { status = 'ready'; statusLabel = 'Ready to migrate'; }

  /* ---- classification ---- */
  let classification, classLabel;
  if (unsupported) { classification = 'unsupported'; classLabel = 'Unsupported'; }
  else if (!scanComplete && m.assignments.groupsError) { classification = 'blocked_info'; classLabel = 'Blocked by missing information'; }
  else if (t === 'swa') { classification = 'manual'; classLabel = 'Manual migration required'; }
  else if (t === 'bookmark' && m.bookmark.target === 'okta_hosted') { classification = 'blocked_info'; classLabel = 'Blocked: depends on another Okta app'; }
  else if (entraManual.length === 0 && ownerSteps.length === 0) { classification = 'fully'; classLabel = 'Fully automatable'; }
  else if (entraManual.length === 0) { classification = 'mostly'; classLabel = 'Mostly automatable'; }
  else if (autoDesign.length >= manual.length) { classification = 'partially'; classLabel = 'Partially automatable'; }
  else { classification = 'manual'; classLabel = 'Manual migration required'; }
  if (classification === 'mostly' && ownerSteps.length && manual.filter((s) => s.side !== 'owner' && s.key !== 'test_signin').length === 0) classLabel = 'Mostly automatable — application owner repoints the app';
  if (!unsupported && proto.switch && proto.switch.shape === 'vendor_consent') { classification = 'manual'; classLabel = 'Requires application-owner action — Entra integration by vendor consent (not automated here)'; }

  const risk = hardStop || stops.some((s) => s.key === 'privileged_app') ? 'high' : stops.some((s) => s.key === 'production_impact') ? 'medium' : 'low';
  const pushable = !unsupported && !hardStop && classification !== 'manual' && classification !== 'blocked_info' && entraSide.some((s) => s.cls === CLS.AUTO || s.cls === CLS.APPROVAL);
  const pushBlockedBy = pushable ? [...new Set(entraSide.filter((s) => (s.cls === CLS.AUTO || s.cls === CLS.APPROVAL) && !s.runnable && !s.optional).map((s) => s.missing).filter(Boolean))] : [];
  const pushHandoffs = pushable ? entraSide.filter((s) => (s.cls === CLS.AUTO || s.cls === CLS.APPROVAL) && !s.runnable && s.optional).map((s) => ({ key: s.key, label: s.label, missing: s.missing })) : [];

  return {
    oktaId: m.identity.id, label: m.identity.label, scannedAt: scan.scannedAt, scanComplete, scanEvidenceComplete: !!scan.complete,
    scanErrors: scan.errors, scanPolicyErrors: policyScanErrors,
    auth: m.auth, protocol: proto,
    readiness: { score, status, statusLabel, categories: list },
    classification, classLabel, ownerAction: ownerSteps.length ? ownerSteps.map((s) => s.label) : [], risk,
    automation: { steps, counts: { total: applicable.length, auto: applicable.filter((s) => s.cls === CLS.AUTO).length, approval: applicable.filter((s) => s.cls === CLS.APPROVAL).length, manual: manual.length, unsupported: unsup.length, runnableNow: autoNow.length, lanes: laneCounts(steps) }, rolesKnown: roles !== null },
    stops, policyMapping: pm,
    target: { decision: match.decision || 'none', entraId: match.entraId || null, entraName: match.entraName || null, mode: match.decision === 'manual_confirmed' ? 'adopt' : 'create', entra },
    push: { possible: pushable, blockedBy: pushBlockedBy, handoffs: pushHandoffs, grantedBy: pushBlockedBy.length || pushHandoffs.length ? ENTRA_GRANTOR : null, requiresApproval: stops.some((s) => s.severity === 'review') || applicable.some((s) => s.cls === CLS.APPROVAL) },
    assessedAt: nowIso(),
  };
}

/** The per-step automation classification (spec §6), gated on the live roles. */
/** A requirement set made only of *.Read.All roles runs on the read credential (IdentityDiag), not the write one. */
/** Decide the Entra-side protocol and, for a SAML → OIDC switch, synthesise the OIDC client model from the recorded
    inputs (there is no Okta OIDC client to copy). Idempotent; m.saml stays for the Okta side and a later "keep SAML". */
function resolveTarget(m, guide) {
  const proto = recommendProtocol(m, guide);
  if (m.auth.type !== 'saml' || !m.saml) return proto;
  if (!proto.switch) { if (m.oidc && m.oidc.switched) delete m.oidc; return proto; }
  const si = m.switchInputs || {};
  const uris = Array.isArray(si.redirectUris) ? si.redirectUris.slice() : [];
  if (uris.length) { m.inputSources = m.inputSources || {}; m.inputSources.redirectUris = si.meta || { by: null, at: null }; }
  const gc = (m.saml.groupClaims || []);
  const consent = proto.switch.shape === 'vendor_consent';
  m.oidc = { switched: true, from: 'saml', shape: proto.switch.shape, evidence: proto.switch.evidence, clientId: null, tokenEndpointAuthMethod: consent ? null : 'client_secret_post', pkceRequired: null, autoKeyRotation: null, secretRequired: !consent,
    redirectUris: uris, redirectUrisOkta: null, postLogoutRedirectUris: m.saml.slo && m.saml.slo.logoutUrl ? [m.saml.slo.logoutUrl] : [], grantTypes: ['authorization_code'], responseTypes: ['code'], refreshTokens: false, implicit: false,
    applicationType: 'web', initiateLoginUri: m.identity.loginUrl || null, clientUri: null, issuerMode: null, issuer: null, wildcardRedirect: null, consentMethod: null, idpInitiatedLogin: null, dpop: false, endpoints: null, scopes: null,
    claims: gc.length ? { fromSaml: true, groups: gc.map((g) => g.name) } : null };
  return proto;
}
const guideForModel = (m) => m && m.identity ? VG.guideFor({ oktaId: m.identity.id, name: m.identity.name, label: m.identity.label, oktaStatus: m.identity.status, signOnMode: m.identity.signOnMode }) : null;
const isReadReq = (req) => Array.isArray(req) && req.length > 0 && req.every((x) => typeof x === 'string' && /\.Read\.All$/.test(x));
function automationSteps(m, proto, { roles, graphError, readRoles, readError, okta, match, entra, groups, users, stops }) {
  const t = m.auth.type;
  const P = proto.recommended;
  const steps = [];
  const add = (key, label, side, cls, opts = {}) => {
    const s = Object.assign({ key, label, side, cls, requires: [], missing: null, have: null, runnable: false, reason: '', grantedBy: null, reversible: null, rollback: null, applicable: true }, opts);
    if (s.cls === CLS.AUTO || s.cls === CLS.APPROVAL) {
      const readOnly = isReadReq(s.requires);
      const useRoles = readOnly ? (readRoles === undefined ? roles : readRoles) : roles;
      const pc = permCheck(s.requires, useRoles);
      if (s.requires.length && typeof s.requires[0] === 'string' && s.requires[0].startsWith('okta:')) { s.runnable = !!okta.canWriteOkta; s.missing = okta.canWriteOkta ? null : s.requires[0].slice(5); s.grantedBy = s.runnable ? null : OKTA_GRANTOR; }
      else { s.runnable = pc.ok === true; s.missing = pc.missing; s.have = pc.have; s.grantedBy = pc.ok === true ? null : ENTRA_GRANTOR; }
      if (!s.runnable && s.missing && useRoles !== null) s.reason = (s.reason ? s.reason + ' ' : '') + 'Blocked today: needs ' + s.missing + ' (granted by ' + s.grantedBy + (readOnly ? ' on the read credential' : '') + ').';
      else if (!s.runnable && useRoles === null) s.reason = (s.reason ? s.reason + ' ' : '') + 'Blocked today: ' + (readOnly ? (readError || 'the Entra read credential could not be read') : (graphError || 'the Entra write credential could not be read')) + '. Needs ' + (s.missing || 'the permission') + ' (granted by ' + s.grantedBy + ').';
    }
    steps.push(s);
    return s;
  };
  const adopt = match.decision === 'manual_confirmed' && entra;
  const isCreate = !adopt;
  const write = adopt ? PERM.APP_ADOPT : PERM.APP_WRITE;

  add('snapshot', 'Capture the Okta configuration snapshot (config, users, groups, policy, claims, URLs, certificate)', 'okta', CLS.AUTO, { requires: [], runnable: true, reason: 'Read-only; stored with the migration for rollback.', reversible: true });
  if (t === 'bookmark' && m.bookmark.target === 'entra_launcher') {
    add('verify_launcher', 'Verify the Entra app behind the launcher link exists and is enabled', 'entra', CLS.AUTO, { requires: PERM.APP_READ, reason: 'The tile already points at Entra.', reversible: true });
    add('retire_okta', 'Deactivate the Okta bookmark once users use My Apps', 'okta', CLS.APPROVAL, { requires: ['okta:APP_ADMIN or higher'], reason: 'Typed confirmation and a reason; reversible by reactivation.', reversible: true, rollback: 'Reactivate the Okta app.' });
    return steps;
  }
  if (['saml11', 'federation', 'radius', 'mfa_service', 'ad_agent', 'ldap_interface'].includes(t) || P === 'unsupported' || P === 'unknown') {
    add('unsupported', 'Application migration', 'entra', CLS.UNSUPPORTED, { reason: proto.reason });
    return steps;
  }
  if (t === 'bookmark' && m.bookmark.target === 'okta_hosted') {
    add('dependency', 'Migrate the application this bookmark signs into first', 'entra', CLS.MANUAL, { reason: 'This tile depends on another Okta app; it is repointed after that app is verified in Entra.' });
    return steps;
  }
  if (t === 'swa') {
    add('create_app', 'Create the enterprise application (non-gallery)', 'entra', CLS.AUTO, { requires: write, reason: 'POST /applicationTemplates/' + NON_GALLERY_TEMPLATE + '/instantiate.', reversible: true, rollback: 'Delete the created application and service principal.' });
    add('password_sso', 'Configure password-based single sign-on (capture the sign-in form)', 'entra', CLS.MANUAL, { reason: 'Form capture runs in the Entra portal with the My Apps extension; Graph cannot capture a sign-in form.' });
    add('assign_groups', 'Assign the Okta groups to the Entra app', 'entra', CLS.AUTO, { requires: PERM.ASSIGN, reason: 'POST /servicePrincipals/{id}/appRoleAssignedTo for each resolved group.', reversible: true, rollback: 'Delete the created appRoleAssignments.' });
    add('user_credentials', 'Users enter their application credentials once in My Apps', 'owner', CLS.MANUAL, { reason: 'Okta stored passwords cannot be exported.' });
    add('test_signin', 'Test sign-in with an assigned user', 'owner', CLS.MANUAL, { reason: 'A person signs in; the sign-in log check afterwards is automatic.' });
    add('retire_okta', 'Deactivate the Okta app after validation', 'okta', CLS.APPROVAL, { requires: ['okta:APP_ADMIN or higher'], reversible: true, rollback: 'Reactivate the Okta app.' });
    return steps;
  }
  if (t === 'bookmark') {
    add('create_app', 'Create the linked application (My Apps tile with the URL)', 'entra', CLS.AUTO, { requires: write, reason: 'POST /applicationTemplates/' + NON_GALLERY_TEMPLATE + '/instantiate, then PATCH the service principal homepage/loginUrl.', reversible: true, rollback: 'Delete the created application and service principal.' });
    add('linked_mode', 'Set single sign-on mode to Linked', 'entra', CLS.MANUAL, { reason: 'Graph exposes preferredSingleSignOnMode password/saml/oidc/notSupported; Linked is set in the portal.' });
    add('assign_groups', 'Assign the Okta groups to the Entra app', 'entra', CLS.AUTO, { requires: PERM.ASSIGN, reversible: true, rollback: 'Delete the created appRoleAssignments.' });
    add('retire_okta', 'Deactivate the Okta bookmark after validation', 'okta', CLS.APPROVAL, { requires: ['okta:APP_ADMIN or higher'], reversible: true, rollback: 'Reactivate the Okta app.' });
    return steps;
  }

  /* ---- OIDC by vendor consent: the vendor's own Entra integration; nothing is written to Entra from here ---- */
  if (P === 'oidc' && m.oidc && m.oidc.shape === 'vendor_consent') {
    add('vendor_consent', 'Entra administrator adds Entra as the identity provider from the vendor console (Microsoft consent creates the enterprise application in the tenant)', 'owner', CLS.MANUAL, { reason: 'This vendor integrates with Entra through its own multi-tenant application: an Entra administrator signs in from the vendor console and accepts the consent. No app registration is created from here — not yet automated.' });
    add('assign_groups', 'Assign the Entra groups to the enterprise application the consent created', 'entra', CLS.MANUAL, { reason: 'The application object does not exist until the consent is accepted; assign in the Entra portal, or confirm the match here afterwards to adopt it.' });
    add('test_signin', 'Test sign-in with an assigned user', 'owner', CLS.MANUAL, { reason: 'A person signs in; the sign-in log check afterwards is automatic.' });
    add('retire_okta', 'Deactivate the Okta app after validation', 'okta', CLS.APPROVAL, { requires: ['okta:APP_ADMIN or higher'], reversible: true, rollback: 'Reactivate the Okta app.' });
    return steps;
  }
  /* ---- OIDC / SAML ---- */
  if (adopt) add('adopt_target', `Adopt the confirmed Entra application "${entra.name}" (update in place)`, 'entra', CLS.AUTO, { requires: write, reason: 'Confirmed match; existing object is updated, nothing new is created.', reversible: true, rollback: 'Restore the previous values recorded in the snapshot.' });
  else if (P === 'saml' && proto.template && proto.template.id && !proto.nonGallery) add('create_app', `Create the enterprise application from the gallery template "${proto.template.displayName}"`, 'entra', CLS.AUTO, { requires: write, reason: 'POST /applicationTemplates/{templateId}/instantiate creates the application and the service principal.', reversible: true, rollback: 'Delete the created application (the service principal goes with it).' });
  else if (P === 'saml') add('create_app', 'Create the non-gallery SAML application (application + service principal)', 'entra', CLS.AUTO, { requires: write, reason: 'POST /applicationTemplates/' + NON_GALLERY_TEMPLATE + '/instantiate.', reversible: true, rollback: 'Delete the created application.' });
  else add('create_app', 'Create the app registration and its service principal', 'entra', CLS.AUTO, { requires: write, reason: 'POST /applications then POST /servicePrincipals.', reversible: true, rollback: 'Delete the created application.' });

  if (P === 'oidc') {
    add('configure_oidc', 'Configure OpenID Connect (redirect URIs, logout URL, token settings, sign-in audience)', 'entra', CLS.AUTO, { requires: write, reason: m.oidc.switched ? 'PATCH /applications/{id} web from the recorded redirect URIs (the Okta app is SAML; there is no Okta OIDC client to copy).' : 'PATCH /applications/{id} web/spa/publicClient from the Okta client settings.', reversible: true, rollback: 'Delete the application (create) or restore the recorded values (adopt).' });
    add('redirect_uris', `Import ${m.oidc.redirectUris.length} redirect URI(s)`, 'entra', m.oidc.redirectUris.some((u) => u.includes('*')) ? CLS.MANUAL : CLS.AUTO, { requires: write, reason: m.oidc.redirectUris.some((u) => u.includes('*')) ? 'Wildcard URIs must be enumerated by hand.' : 'Part of the application PATCH.', reversible: true });
    add('logout_urls', m.oidc.postLogoutRedirectUris.length ? `Import ${m.oidc.postLogoutRedirectUris.length} post-logout URI(s) as the front-channel logout URL` : 'Logout URL (none configured in Okta)', 'entra', m.oidc.postLogoutRedirectUris.length ? CLS.AUTO : 'N/A', { requires: write, reversible: true });
    add('claims', 'Map claims (standard OIDC claims; optional claims for email/upn/groups)', 'entra', CLS.AUTO, { requires: write, reason: m.oidc.switched ? 'PATCH optionalClaims. The SAML attribute statements are listed for the owner; standard claims and the group claim (when Okta sent one) are configured.' : 'PATCH optionalClaims. Custom Okta authorization-server claims are unknown to the app object and must be confirmed with the owner.', reversible: true });
    add('permissions', 'Add Microsoft Graph User.Read (openid, profile, email) and grant admin consent', 'entra', CLS.APPROVAL, { requires: PERM.CONSENT, optional: true, reason: 'requiredResourceAccess PATCH plus POST /oauth2PermissionGrants; consent is a tenant-wide grant. Without the permission staging still runs and this step is handed off (grant consent in the Entra portal).', reversible: true, rollback: 'Delete the oauth2PermissionGrant.' });
    if (m.oidc.secretRequired !== false) add('client_secret', 'Create the client secret (shown once to the technician, never stored)', 'entra', CLS.APPROVAL, { requires: write, reason: 'POST /applications/{id}/addPassword. The value is displayed once and handed to the application owner.', reversible: true, rollback: 'removePassword with the recorded keyId.' });
  } else {
    add('configure_saml', 'Configure SAML (entity id, reply URLs, sign-on URL, relay state, logout URL, SAML mode)', 'entra', CLS.AUTO, { requires: write, reason: 'PATCH /applications/{id} identifierUris + web.redirectUris; PATCH /servicePrincipals/{id} preferredSingleSignOnMode=saml, loginUrl, logoutUrl, samlSingleSignOnSettings.', reversible: true, rollback: 'Delete the application (create) or restore the recorded values (adopt).' });
    if (m.saml.acsUrls.length) add('redirect_uris', `Import ${m.saml.acsUrls.length} reply URL(s) and the entity id`, 'entra', CLS.AUTO, { requires: write, reason: 'Part of the application PATCH.', reversible: true });
    else if (proto.template && proto.template.id && !proto.nonGallery) add('redirect_uris', 'Reply URL and entity id from the gallery template defaults (confirmed at pre-flight against the vendor metadata)', 'entra', CLS.APPROVAL, { requires: write, reason: 'The instantiated gallery app carries the vendor defaults; the technician confirms them before staging.', reversible: true });
    else add('redirect_uris', 'Enter the reply URL and entity id from the vendor SP metadata', 'entra', CLS.MANUAL, { reason: 'Not on the Okta app object (OIN template) and no Entra gallery template matched.', reversible: true });
    add('signing_certificate', 'Create the Entra token-signing certificate', 'entra', CLS.AUTO, { requires: write, reason: 'POST /servicePrincipals/{id}/addTokenSigningCertificate (3-year, SHA-256).', reversible: true, rollback: 'Delete the application; certificates go with it.' });
    const unmappable = m.saml.attributes.filter((a) => !a.mapping.mappable);
    const mappable = m.saml.attributes.filter((a) => a.mapping.mappable && a.type !== 'GROUP');
    add('claims', `Configure ${mappable.length} attribute claim(s)` + (unmappable.length ? ` (${unmappable.length} need a person)` : ''), 'entra', mappable.length ? CLS.AUTO : (unmappable.length ? CLS.MANUAL : 'N/A'), { requires: mappable.length ? PERM.CLAIMS : [], reason: mappable.length ? 'POST /policies/claimsMappingPolicies + assign to the service principal; the Entra defaults (givenname, surname, emailaddress, name) are kept.' : 'Nothing mappable automatically.', reversible: true, rollback: 'Delete the claims-mapping policy.' });
    if (unmappable.length) add('claims_manual', `Define ${unmappable.length} claim(s) that use expressions or app-user attributes: ${unmappable.map((a) => a.name).join(', ')}`, 'entra', CLS.MANUAL, { reason: 'Claim transformations are defined in the portal after review.' });
    add('group_claims', m.saml.groupClaims.length ? 'Emit the group claim (' + m.saml.groupClaims.map((g) => g.name).join(', ') + ')' : 'Group claim (none in Okta)', 'entra', m.saml.groupClaims.length ? CLS.AUTO : 'N/A', { requires: write, reason: 'PATCH groupMembershipClaims = SecurityGroup / ApplicationGroup; the group filter from Okta is rebuilt as assigned-groups-only.', reversible: true });
    if (m.saml.encryption.enabled) add('token_encryption', 'Upload the application encryption certificate (token encryption)', 'entra', CLS.MANUAL, { reason: 'The public certificate must come from the application; uploaded in the portal.' });
    if (m.saml.inlineHooks) add('inline_hook', 'Replace the SAML inline hook', 'entra', CLS.UNSUPPORTED, { reason: 'No Entra equivalent for Okta inline hooks (custom claims provider is a separate project).' });
  }
  const resolvable = groups.filter((g) => g.entra && g.entra.entraId);
  const native = groups.filter((g) => g.type === 'okta' && !(g.entra && g.entra.entraId));
  const adMissing = groups.filter((g) => g.type === 'ad' && !(g.entra && g.entra.entraId));
  add('resolve_groups', `Resolve ${groups.length} Okta group(s) to Entra groups (${resolvable.length} resolved by SID/name)`, 'entra', CLS.AUTO, { requires: PERM.DIR_READ, reason: 'Live Graph lookups by onPremisesSecurityIdentifier, then exact display name.', reversible: true });
  if (native.length) add('create_groups', `Create ${native.length} Okta-native group(s) in Entra and rebuild membership`, 'entra', CLS.APPROVAL, { requires: [PERM.GROUP_CREATE, PERM.GROUP_MEMBER], optional: true, reason: 'POST /groups + members; membership is copied from Okta by UPN (or handed off when the permission is missing or the technician opts out at pre-flight). Creates directory objects, so approval is required.', reversible: true, rollback: 'Delete the created groups.' });
  if (adMissing.length) add('sync_groups', `Bring ${adMissing.length} AD group(s) into the Entra Connect sync scope`, 'entra', CLS.MANUAL, { reason: 'Groups exist in AD but are not synced; adjust the sync scope (OU/attribute filter) and wait for a cycle.' });
  add('assign_groups', `Assign ${resolvable.length + native.length} group(s) to the Entra app`, 'entra', groups.length ? CLS.AUTO : 'N/A', { requires: PERM.ASSIGN, reason: 'POST /servicePrincipals/{id}/appRoleAssignedTo per group.', reversible: true, rollback: 'Delete the created appRoleAssignments.' });
  add('assign_users', users.direct ? `Assign ${users.direct} directly-assigned user(s)` : 'Direct user assignments (none)', 'entra', users.direct ? CLS.AUTO : (users.direct === null ? CLS.MANUAL : 'N/A'), { requires: PERM.ASSIGN, reason: users.direct === null ? 'Direct assignments are unknown (' + (users.error || 'not read') + ').' : 'Users are resolved by UPN and assigned individually.', reversible: true, rollback: 'Delete the created appRoleAssignments.' });
  add('assignment_required', 'Require assignment (appRoleAssignmentRequired = true)', 'entra', CLS.AUTO, { requires: write, reason: 'Okta only shows apps to assigned users; Entra must match.', reversible: true });
  const ap = m.assignments.accessPolicy;
  const policyRules = ap && Array.isArray(ap.rules) ? ap.rules.filter((r) => r.status === 'ACTIVE') : [];
  add('conditional_access', policyRules.length ? `Record ${policyRules.length} active Okta sign-on policy rule(s) for the separate Security & MFA project` : 'Security & MFA policy evidence (separate project)', 'entra', 'N/A', { requires: [], reason: 'Application staging does not copy or require Okta MFA / sign-on policy settings. Tenant Conditional Access and MFA are handled in the separate Security & MFA project.', reversible: null });
  add('validate', 'Validate the Entra configuration against the plan (live re-read)', 'entra', CLS.AUTO, { requires: PERM.APP_READ, reason: 'GET the application, service principal and assignments; compare expected vs actual. Security & MFA policy validation is a separate project.', reversible: true });
  add('vendor_reconfigure', P === 'oidc' ? (m.oidc && m.oidc.switched ? 'Application owner switches the application from SAML to OpenID Connect against Entra (issuer, client id, secret) — Okta stays active meanwhile' : 'Application owner points the application at Entra (issuer, client id, secret) — Okta stays active meanwhile') : 'Application owner uploads the Entra federation metadata / certificate to the application — Okta stays active meanwhile', 'owner', CLS.MANUAL, { reason: 'The service-provider side is outside both tenants. Until this is done the app still authenticates through Okta.' });
  add('test_signin', 'Test sign-in through Entra with an assigned user; check the sign-in log', 'owner', CLS.MANUAL, { reason: 'A person signs in; the sign-in evidence check is automatic (AuditLog.Read.All).' });
  add('enable_app', adopt && entra && entra.enabled === false ? 'Enable the Entra app (accountEnabled = true)' : 'Enable the Entra app (created enabled)', 'entra', adopt && entra && entra.enabled === false ? CLS.APPROVAL : 'N/A', { requires: write, reversible: true });
  if (m.provisioning.enabled) add('provisioning', 'Configure provisioning (SCIM) in Entra', 'entra', CLS.MANUAL, { reason: 'Needs the vendor SCIM endpoint and token plus Synchronization.ReadWrite.All; configured in the portal.' });
  add('retire_okta', 'Deactivate the Okta app after validation (typed confirmation; reversible)', 'okta', CLS.APPROVAL, { requires: ['okta:APP_ADMIN or higher'], reason: 'Existing lifecycle route: app label typed back + reason; rollback is reactivation.', reversible: true, rollback: 'Reactivate the Okta app.' });
  return steps;
}

/* ================================================================ lanes */
/*
 * Who does each step, in plain words. Three lanes, never mixed (spec: a hand-off is not an automatic execution):
 *   page   — this page runs it at button click (the wizard Stage in Entra, Rescan, the Okta lifecycle action)
 *   claude — a technician pastes a ready prompt into Claude Code; the Claude in Chrome extension drives the
 *            technician's own signed-in Entra admin tab (the built-in browser pane has no sign-in session)
 *   person — a named person does it outside the platform (Entra Connect admin, application owner, end users)
 *   none   — not applicable / not supported (no lane; the step is shown so nothing is hidden)
 * Prompts are built from the scanned configuration only; nothing here is marked done by copying a prompt.
 */
const LANE = { PAGE: 'page', CLAUDE: 'claude', PERSON: 'person', NONE: 'none' };
const LANE_LABEL = { page: 'Runs from this page', claude: 'Paste into Claude Code', person: 'A person does this', none: 'No lane' };
const EXT_RULE = 'Use the Claude in Chrome extension on my signed-in Entra admin center tab (https://entra.microsoft.com). Do not use the built-in browser pane or open a new browser — only the extension on my tab carries my sign-in.';
const PROMPT_RULES = 'Act only with my signed-in permissions; do not request, add or grant any permission or role. Change only what this step describes; do not touch other applications, users or policies. If anything is missing, ambiguous or looks different from what I describe, stop and ask me before changing anything.';
const PROMPT_REPORT = 'Then report back: exactly what you changed (object names and ids), what you could not do and why. I will record the result on the CorpIT migration page (Validate); nothing is marked done by copying this prompt.';

function buildPrompt(m, step, doLines, verify, where) {
  const head = `Okta → Entra migration — ${m.identity.label} (Okta app ${m.identity.id}). Step: ${step.label}.`;
  const body = doLines.map((l, i) => `${i + 1}. ${l}`).join('\n');
  return [head, where === 'entra-portal' || where === 'okta-admin' ? EXT_RULE : null, PROMPT_RULES, 'Do this:', body, verify ? 'Verify: ' + verify : null, PROMPT_REPORT].filter(Boolean).join('\n');
}

function groupsPrompt(m, s, native, regNote) {
  return buildPrompt(m, s, [
    'Open Entra admin center → Groups → All groups → New group.',
    ...native.map((g) => `Create a Security group named exactly "${g.name}" (membership type Assigned; no owners beyond me; description: "Created from Okta group ${g.id || g.oktaId || '?'} by the Okta→Entra migration").`),
    'Copy each group\'s members from Okta: open Okta Admin → Directory → Groups → the group with the same name → People, and add the same people to the Entra group by UPN (same email address). Do not add anyone who is not in the Okta group.',
    regNote || 'Do not assign the groups to any application; the migration page does that at staging.',
  ], 'each new group exists with the expected member count; list group name → object id → member count.', 'entra-portal');
}
function linkedPrompt(m, s, appPath) {
  const url = (m.bookmark && m.bookmark.url) || '(tile URL unknown)';
  return buildPrompt(m, s, [`Open ${appPath} → Single sign-on → select "Linked".`, `Sign on URL: ${url} → Save.`], 'the Single sign-on blade shows "Linked" with that URL.', 'entra-portal');
}
/** Annotate every automation step with lane / who / where / browser / prompt (mutates the step objects).
 *  Works on assessment steps (no exec field) and on plan steps (exec: Graph call | null; handoff: text | list). */
function annotateLanes(steps, m, proto, match, entra, okta) {
  const P = proto.recommended;
  const appName = (entra && entra.name) || m.identity.label;
  const appPath = `Entra admin center → Enterprise applications → "${appName}"`;
  const regPath = `Entra admin center → App registrations → "${appName}"`;
  const migrateName = WRITE_CRED.name || 'IT-Command-Migrate';
  for (const s of steps) {
    const set = (lane, who, where, extra = {}) => Object.assign(s, { lane, laneLabel: LANE_LABEL[lane], who, where, browser: lane === LANE.CLAUDE, prompt: null, laneNote: null, unblockPrompt: null }, extra);
    if (s.cls === 'N/A') { set(LANE.NONE, null, null, { laneNote: 'Not applicable to this app.' }); continue; }
    if (s.cls === CLS.UNSUPPORTED) { set(LANE.NONE, null, null, { laneNote: 'Not supported: ' + (s.reason || 'no Entra equivalent.') }); continue; }
    if (s.cls === CLS.AUTO || s.cls === CLS.APPROVAL) {
      const isOkta = (s.requires || []).length && typeof s.requires[0] === 'string' && s.requires[0].startsWith('okta:');
      /* a plan step with no Graph call and a hand-off text is handed off by staging even when no permission is missing */
      const handed = s.exec === null && !!s.handoff;
      if (s.key === 'retire_okta' && (s.runnable || handed)) { set(LANE.PAGE, 'Migration technician (admin on this page)', 'corpit', { laneNote: 'Work item → Okta lifecycle → Deactivate; the app label is typed back and a reason is recorded. Reversible.' }); continue; }
      if (s.runnable && !handed) {
        if (s.key === 'snapshot' || s.key === 'resolve_groups' || s.key === 'validate' || s.key === 'verify_launcher') set(LANE.PAGE, 'This page', 'corpit', { laneNote: s.cls === CLS.APPROVAL ? 'Runs in the migration wizard after approval.' : 'Runs in the migration wizard (pre-flight / stage in Entra / verify).' });
        else set(LANE.PAGE, 'Migration technician (admin on this page)', 'corpit', { laneNote: s.cls === CLS.APPROVAL ? 'Runs at Stage in Entra after a typed approval in the wizard.' : 'Runs at Stage in Entra in the wizard.' });
        /* staging sets the URL; selecting "Linked" as the SSO mode remains a portal click */
        if (s.key === 'linked_mode' && typeof s.handoff === 'string') Object.assign(s, { laneNote: s.laneNote + ' ' + s.handoff, prompt: linkedPrompt(m, s, appPath) });
        continue;
      }
      /* automatable by design, blocked today by a missing permission */
      if (s.optional && s.key === 'permissions') {
        set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension (must hold Global Administrator or Privileged Role Administrator to grant consent)', 'entra-portal', {
          laneNote: 'Staging runs without this and hands it off. Consent is tenant-wide; grant it deliberately.',
          prompt: buildPrompt(m, s, [
            `Open ${regPath} → API permissions.`,
            'Confirm the list contains Microsoft Graph delegated permissions: openid, profile, email, User.Read. If they are missing, add them (Add a permission → Microsoft Graph → Delegated permissions → openid, profile, email, User.Read). If any other permission is listed, stop and ask me.',
            'Click "Grant admin consent for <tenant>" and confirm.',
          ], 'the Status column shows "Granted for <tenant>" for each of the four permissions.', 'entra-portal'),
        });
        continue;
      }
      if (s.optional && s.key === 'create_groups') {
        const native = (m.assignments.groups || []).filter((g) => g.type === 'okta' && !(g.entra && g.entra.entraId));
        set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension (Groups Administrator or higher)', 'entra-portal', {
          laneNote: 'Staging runs without this and hands it off; the group assignment step then needs these groups.',
          prompt: groupsPrompt(m, s, native),
        });
        continue;
      }
      /* any other plan hand-off that is automatable by design but not called by this staging run */
      if (handed) {
        set(LANE.PERSON, 'Migration technician', 'entra-portal', { laneNote: typeof s.handoff === 'string' ? s.handoff : JSON.stringify(s.handoff).slice(0, 300) });
        continue;
      }
      /* required and blocked: the page will run it once the permission exists — say so, and give the Global Admin the exact consent */
      set(LANE.PAGE, 'This page — after ' + (s.grantedBy || 'the permission is granted'), 'corpit', {
        laneNote: 'Blocked today: needs ' + (s.missing || 'a permission') + ' (granted by ' + (s.grantedBy || 'an administrator') + '). Until then the wizard refuses to run this step; nothing is faked.',
        unblockPrompt: isOkta ? null : [
          `CorpIT platform access change — grant "${s.missing}" to the ${migrateName} app registration so the Okta → Entra migration page can run "${s.label}" for ${m.identity.label}.`,
          'This BROADENS what the CorpIT platform can change in the Entra tenant. Only do it if the change is approved (change record) — do not proceed on my say-so alone.',
          EXT_RULE, PROMPT_RULES.replace('do not request, add or grant any permission or role', 'add only the one application permission named here'),
          'Do this:',
          `1. Open Entra admin center → App registrations → "${migrateName}" → API permissions → Add a permission → Microsoft Graph → Application permissions → search "${(s.missing || '').split(' ')[0]}" → add it.`,
          '2. Click "Grant admin consent for <tenant>" and confirm (requires Global Administrator or Privileged Role Administrator).',
          `Verify: the permission shows "Granted for <tenant>". Then report back the exact permission granted. I will re-run pre-flight on the migration page; the step turns runnable only when the live token carries the role.`,
        ].join('\n'),
      });
      continue;
    }
    /* MANUAL steps, by key */
    switch (s.key) {
      case 'password_sso': {
        const url = (m.swa && m.swa.url) || m.identity.appUrl || '(sign-in URL unknown — ask the application owner)';
        set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension', 'entra-portal', {
          laneNote: 'Form capture needs the My Apps Secure Sign-in browser extension on the same signed-in tab; Graph cannot capture a sign-in form.',
          prompt: buildPrompt(m, s, [
            `Open ${appPath} → Single sign-on → select "Password-based".`,
            `Sign-on URL: ${url} → Save.`,
            'If Entra asks to capture the sign-in fields, use the "My Apps Secure Sign-in" extension prompt in my tab to capture the username and password fields; do not type any real credentials.',
          ], 'the Single sign-on blade shows Password-based with the sign-on URL saved.', 'entra-portal'),
        });
        break;
      }
      case 'linked_mode':
        set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension', 'entra-portal', { prompt: linkedPrompt(m, s, appPath) });
        break;
      case 'create_groups_manual': {
        const hand = Array.isArray(s.handoff) ? s.handoff.map((g) => ({ name: g.group || g.name, id: g.oktaId || g.id })) : (m.assignments.groups || []).filter((g) => g.type === 'okta' && !(g.entra && g.entra.entraId));
        set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension (Groups Administrator or higher)', 'entra-portal', {
          laneNote: 'Chosen at pre-flight: staging does not create these groups. After they exist, assign them to the app (below) and Rescan.',
          prompt: groupsPrompt(m, s, hand, `Then open ${appPath} → Users and groups → Add user/group → select each new group → Assign.`),
        });
        break;
      }
      case 'assign_everyone': {
        const names = Array.isArray(s.handoff) ? s.handoff : [];
        set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension (after the owner confirms the intended population)', 'entra-portal', {
          laneNote: 'Okta assigned a built-in group (' + names.join(', ') + '); Entra has no equivalent of Okta "Everyone". The owner names the population first (a group, or All Users).',
          prompt: buildPrompt(m, s, [
            `I will name the intended population before you start (an Entra group name, or "All Users"). If I have not, stop and ask me. Okta assigned: ${names.join(', ') || '(unknown)'}.`,
            `Open ${appPath} → Users and groups → Add user/group → Users and groups → select exactly the population I named → Select → Assign.`,
            'Do not assign anyone else and do not remove existing assignments.',
          ], 'the Users and groups blade lists the named population; report the object id assigned.', 'entra-portal'),
        });
        break;
      }
      case 'inline_hook':
        set(LANE.PERSON, 'Application owner with the migration technician', 'vendor', { laneNote: 'The Okta SAML inline hook has no Entra equivalent: rebuild the logic as a custom claims provider (separate project) or agree with the owner to drop it. Decide before the owner repoints the vendor.' });
        break;
      case 'redirect_uris': {
        if (P === 'oidc') {
          const uris = (m.oidc && m.oidc.redirectUris) || [];
          set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension (after the application owner enumerates each wildcard)', 'entra-portal', {
            laneNote: 'Okta accepts wildcard redirect URIs; Entra does not. The owner must list every real URI first.',
            prompt: buildPrompt(m, s, [
              `Open ${regPath} → Authentication.`,
              `Under the ${m.oidc && m.oidc.applicationType === 'browser' ? 'Single-page application' : 'Web'} platform add exactly these redirect URIs (I have already expanded the Okta wildcards; if any still contains "*", stop and ask me): ${uris.join(' ; ')}`,
              'Save.',
            ], 'the Authentication blade lists exactly those URIs and no others were removed.', 'entra-portal'),
          });
        } else {
          set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension (after the application owner supplies the SP metadata)', 'entra-portal', {
            laneNote: 'The Okta app object does not carry the reply URL / entity id (OIN template). Get them from the vendor SP metadata first.',
            prompt: buildPrompt(m, s, [
              'I will paste the vendor SP metadata values here before you start: Identifier (Entity ID) = <paste>; Reply URL (ACS) = <paste>. If I have not pasted them, stop and ask me.',
              `Open ${appPath} → Single sign-on → SAML → Basic SAML Configuration → Edit.`,
              'Enter the Identifier (Entity ID) and the Reply URL exactly as pasted; leave Sign on URL / Relay State empty unless I pasted them → Save.',
            ], 'Basic SAML Configuration shows the pasted values.', 'entra-portal'),
          });
        }
        break;
      }
      case 'claims_manual': {
        const un = ((m.saml && m.saml.attributes) || []).filter((a) => !a.mapping.mappable && a.type !== 'GROUP');
        set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension', 'entra-portal', {
          laneNote: 'These claims use Okta expressions or app-user attributes; rebuild them deliberately, do not guess.',
          prompt: buildPrompt(m, s, [
            `Open ${appPath} → Single sign-on → SAML → Attributes & Claims → Edit.`,
            ...un.map((a) => `Add a claim named "${a.name}"${a.namespace ? ` (namespace ${a.namespace})` : ''}. The Okta value expression is: ${(a.values || []).join(' | ') || '(none recorded)'} — translate it to the Entra source attribute or transformation that produces the same value; if there is no faithful equivalent, stop and ask me instead of approximating.`),
            'Do not delete or change the existing claims.',
          ], 'each new claim is listed with its source; report the exact source/transformation chosen per claim.', 'entra-portal'),
        });
        break;
      }
      case 'token_encryption':
        set(LANE.CLAUDE, 'Migration technician with Claude Code + Chrome extension (the application owner supplies the public certificate)', 'entra-portal', {
          laneNote: 'The application owner must provide the vendor encryption certificate (.cer) first.',
          prompt: buildPrompt(m, s, [
            'I will attach the vendor encryption certificate (.cer/.pem, public part only) before you start; if I have not, stop and ask me.',
            `Open ${appPath} → Token encryption → Import certificate → upload the file.`,
            'Activate the certificate (Activate token encryption certificate).',
          ], 'Token encryption shows the certificate as Active with its thumbprint; report the thumbprint.', 'entra-portal'),
        });
        break;
      case 'sync_groups': {
        const ad = (m.assignments.groups || []).filter((g) => g.type === 'ad' && !(g.entra && g.entra.entraId));
        set(LANE.PERSON, 'Entra Connect (directory sync) administrator', 'entra-connect', {
          laneNote: 'On-premises: ' + ad.map((g) => g.name).join(', ') + ' exist in AD but are outside the Entra Connect sync scope. Extend the OU / attribute filter on the Entra Connect server, wait for a sync cycle, then Rescan on this page. Not a portal action; no prompt.',
        });
        break;
      }
      case 'assign_users':
        set(LANE.PAGE, 'This page (Rescan), then the migration technician', 'corpit', { laneNote: 'Direct user assignments are unknown (' + ((m.assignments.users || {}).error || 'not read') + '). Rescan the app; if the read keeps failing, fix the Okta read permission first.' });
        break;
      case 'provisioning':
        set(LANE.PERSON, 'Migration technician, in the Entra admin center (SCIM token typed by a person, never pasted into Claude)', 'entra-portal', {
          laneNote: `${appPath} → Provisioning → Automatic → Tenant URL + Secret token from the vendor → Test connection → Save → start provisioning after the app is verified. Needs the vendor SCIM endpoint and token; keep the token out of chats and prompts.`,
        });
        break;
      case 'vendor_reconfigure':
        set(LANE.PERSON, 'Application owner (' + (m.identity.owner || 'owner not recorded — record one on the work item') + ')', 'vendor', {
          laneNote: (P === 'oidc' ? 'The owner points the vendor at Entra (issuer, client id, secret). The exact values are shown after staging under the Application side step. Okta stays active until this is done.' : 'The owner uploads the Entra federation metadata / signing certificate to the vendor. The exact values are shown after staging under the Application side step. Okta stays active until this is done.') + (m.identity.adminUrl ? ' Vendor console: ' + m.identity.adminUrl : ' Vendor console URL not recorded — add it under Provide inputs.'),
        });
        break;
      case 'test_signin':
        set(LANE.PERSON, 'Application owner or an assigned user', 'users', { laneNote: 'A real person signs in through Entra (My Apps or the vendor URL). The sign-in log check on this page is automatic afterwards (Verify).' });
        break;
      case 'user_credentials':
        set(LANE.PERSON, 'End users', 'users', { laneNote: 'Each user enters their application password once in My Apps. Okta stored passwords cannot be exported.' });
        break;
      case 'dependency':
        set(LANE.PERSON, 'Migration technician', 'corpit', { laneNote: 'Sequence only: migrate and verify the application this bookmark signs into first, then repoint or retire this tile.' });
        break;
      default:
        set(LANE.PERSON, s.side === 'owner' ? 'Application owner' : 'Migration technician', s.side === 'owner' ? 'vendor' : 'entra-portal', { laneNote: s.reason || null });
    }
  }
  return steps;
}

function laneCounts(steps) {
  const c = { page: 0, pageBlocked: 0, claude: 0, person: 0, none: 0 };
  for (const s of steps) {
    if (s.cls === 'N/A') continue;
    if (s.lane === LANE.PAGE) { c.page++; if (!s.runnable && (s.cls === CLS.AUTO || s.cls === CLS.APPROVAL)) c.pageBlocked++; }
    else if (s.lane === LANE.CLAUDE) c.claude++;
    else if (s.lane === LANE.PERSON) c.person++;
    else c.none++;
  }
  return c;
}

/* ================================================================ queue */

/* ====================================================== provided inputs / app side / migrated */
/* What a person supplies because the Okta scan cannot know it. Stored on oem_app_scan.inputs as
   {values:{key:value}, meta:{key:{by,at}, vendorRepointed:{by,at,note}}}; the owner keeps its own column.
   Values are merged into the scanned model by applyInputs() only where the scan has nothing, and each
   merged value is labelled in model.inputSources so the assessment says who supplied it and when. */
const LP = require('./oem-link-probe');
const INPUT_FIELDS = [
  { key: 'owner', label: 'Application owner', type: 'text', max: 255, appliesTo: ['saml', 'oidc', 'swa', 'bookmark'], why: 'Confirms the vendor-side change and tests sign-in. Pre-flight warns without one and the approver must acknowledge it; staging itself is not blocked, but the hand-off and the test sign-in cannot be assigned without an owner.' },
  { key: 'adminUrl', label: 'Vendor admin console URL (the SSO settings page)', type: 'url', max: 500, appliesTo: ['saml', 'oidc'], why: 'Where the Entra values are entered on the application side; it goes into the owner hand-off and the Claude prompt.' },
  { key: 'vendorOidc', label: 'Does the vendor support OpenID Connect?', type: 'choice', choices: ['yes', 'no', 'unknown'], appliesTo: ['saml'], why: 'The scan cannot see vendor capabilities for a SAML app. "Yes" makes OpenID Connect the preferred target for staging (the redirect URI is then required); "no" keeps SAML.' },
  { key: 'protocolChoice', label: 'Target protocol in Entra', type: 'choice', choices: ['oidc', 'saml'], appliesTo: ['saml'], why: 'OpenID Connect is preferred wherever the vendor supports it. Choose SAML to keep the vendor-side integration as it is today; choose OIDC to stage an app registration without recorded evidence (you are asserting the vendor supports it).' },
  { key: 'entityId', label: 'Identifier (Entity ID) the vendor expects', type: 'text', max: 500, appliesTo: ['saml'], why: 'Not on the Okta app object for OIN-template apps. Read it from the vendor SP metadata (EntityDescriptor entityID) or the vendor SSO settings page.' },
  { key: 'acsUrls', label: 'Reply URL(s) — Assertion Consumer Service', type: 'urls', max: 20, appliesTo: ['saml'], why: 'Where Entra posts the SAML response. From the SP metadata (AssertionConsumerService Location) or the vendor SSO page.' },
  { key: 'signOnUrl', label: 'Sign-on URL', type: 'url', max: 500, appliesTo: ['saml', 'swa', 'bookmark'], why: 'SAML: optional, the vendor page that starts SP-initiated sign-in (My Apps tile). Password-based: the HTML sign-in page Entra fills. Linked: the URL the tile opens.' },
  { key: 'logoutUrl', label: 'Single logout URL', type: 'url', max: 500, appliesTo: ['saml'], why: 'Optional. The vendor SLO endpoint (SingleLogoutService in the SP metadata).' },
  { key: 'relayState', label: 'Relay state', type: 'text', max: 500, appliesTo: ['saml'], why: 'Optional. Default relay state after IdP-initiated sign-in.' },
  { key: 'redirectUris', label: 'Redirect URIs (exact, no wildcards)', type: 'urls', max: 20, appliesTo: ['oidc'], why: 'Entra refuses wildcard redirect URIs. List every real URI the application uses. For a SAML app staged as OpenID Connect: the callback / redirect URL from the vendor\'s OIDC settings.' },
];
const FIELD = Object.fromEntries(INPUT_FIELDS.map((f) => [f.key, f]));
const URL_SECRET = /[?&](client_secret|secret|token|access_token|password|pwd|api_key|apikey|sig|signature)=/i;
const looksSecret = (v) => /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(v) || (!/[\/:\s@]/.test(v) && v.length >= 32 && /[A-Z]/.test(v) && /[a-z]/.test(v) && /[0-9~._-]/.test(v));
function cleanUrl(v, { httpsOnly = true, allowSchemes = false } = {}) {
  const s = String(v).trim();
  if (!s) return { value: null };
  if (s.length > 500) return { error: 'longer than 500 characters' };
  if (s.includes('*')) return { error: 'wildcards are not accepted' };
  let u; try { u = new URL(s); } catch (e) { return { error: 'not a valid URL' }; }
  if (URL_SECRET.test(u.search)) return { error: 'the query string looks like it carries a secret; remove it — this page never stores secrets' };
  if (u.protocol === 'https:') return { value: s };
  if (u.protocol === 'http:' && (!httpsOnly || /^(localhost|127\.0\.0\.1)$/.test(u.hostname))) return { value: s };
  if (allowSchemes && !/^https?:$/.test(u.protocol)) return { value: s };
  return { error: 'must be https' };
}
/** Validate a {key: value|null} object; null clears a value. Returns {values, errors}. */
function sanitizeInputs(raw) {
  const values = {}; const errors = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { values, errors: [{ key: '*', error: 'values must be an object' }] };
  for (const [key, v] of Object.entries(raw)) {
    const f = FIELD[key];
    if (!f) { errors.push({ key, error: 'unknown input' }); continue; }
    if (v === null || v === '' || (Array.isArray(v) && !v.length)) { values[key] = null; continue; }
    if (f.type === 'text') {
      const s = String(v).trim().slice(0, f.max);
      if (looksSecret(s)) { errors.push({ key, error: 'looks like a secret or token; this page never stores secrets — paste it into the vendor field directly' }); continue; }
      if ((key === 'entityId') && /\s/.test(s)) { errors.push({ key, error: 'an entity id has no spaces' }); continue; }
      values[key] = s;
    } else if (f.type === 'choice') {
      const s = String(v).trim().toLowerCase();
      if (!f.choices.includes(s)) { errors.push({ key, error: 'must be one of ' + f.choices.join(', ') }); continue; }
      values[key] = s;
    } else if (f.type === 'url') {
      const r = cleanUrl(v, { httpsOnly: true });
      if (r.error) { errors.push({ key, error: r.error }); continue; }
      values[key] = r.value;
    } else if (f.type === 'urls') {
      const list = [].concat(v).map((x) => String(x).trim()).filter(Boolean);
      if (list.length > f.max) { errors.push({ key, error: 'at most ' + f.max + ' entries' }); continue; }
      const out = []; let bad = null;
      for (const x of list) { const r = cleanUrl(x, { httpsOnly: key !== 'redirectUris', allowSchemes: key === 'redirectUris' }); if (r.error) { bad = x + ': ' + r.error; break; } if (r.value && !out.includes(r.value)) out.push(r.value); }
      if (bad) { errors.push({ key, error: bad }); continue; }
      values[key] = out.length ? out : null;
    }
  }
  return { values, errors };
}
/** Merge stored inputs into a scanned model (only where the scan has nothing) and label each merged value. */
function applyInputs(model, inputs, owner) {
  if (!model || !model.identity) return model;
  model.identity.owner = owner || null;
  const v = (inputs && inputs.values) || {}; const meta = (inputs && inputs.meta) || {};
  model.inputSources = {};
  const src = (k) => { model.inputSources[k] = { by: (meta[k] && meta[k].by) || null, at: (meta[k] && meta[k].at) || null }; };
  if (v.adminUrl) { model.identity.adminUrl = v.adminUrl; src('adminUrl'); }
  model.identity.vendorOidc = v.vendorOidc || null; if (v.vendorOidc) src('vendorOidc');
  model.identity.protocolChoice = v.protocolChoice || null; if (v.protocolChoice) src('protocolChoice');
  if (model.saml) {
    const s = model.saml;
    if (!s.entityId && v.entityId) { s.entityId = v.entityId; src('entityId'); }
    if (!(s.acsUrls || []).length && Array.isArray(v.acsUrls) && v.acsUrls.length) { s.acsUrls = v.acsUrls.slice(); src('acsUrls'); }
    if (!s.relayState && v.relayState) { s.relayState = v.relayState; src('relayState'); }
    if (!(s.slo && s.slo.logoutUrl) && v.logoutUrl) { s.slo = Object.assign({}, s.slo || {}, { enabled: true, logoutUrl: v.logoutUrl }); src('logoutUrl'); }
  }
  if (!model.identity.loginUrl && v.signOnUrl) { model.identity.loginUrl = v.signOnUrl; src('signOnUrl'); }
  if (model.swa && !model.swa.url && v.signOnUrl) { model.swa.url = v.signOnUrl; src('signOnUrl'); }
  if (model.bookmark && !model.bookmark.url && v.signOnUrl && model.bookmark.target !== 'okta_hosted') { model.bookmark.url = v.signOnUrl; model.bookmark.host = hostOf(v.signOnUrl) || null; src('signOnUrl'); }
  if (model.oidc && Array.isArray(v.redirectUris) && v.redirectUris.length) {
    const o = model.oidc;
    const wild = o.wildcardRedirect === 'SUBDOMAIN' || (o.redirectUris || []).some((u) => u.includes('*'));
    if (wild || !(o.redirectUris || []).length) { o.redirectUrisOkta = (o.redirectUris || []).slice(); o.redirectUris = v.redirectUris.slice(); o.wildcardRedirect = null; src('redirectUris'); }
  }
  model.switchInputs = !model.oidc && model.saml && Array.isArray(v.redirectUris) && v.redirectUris.length ? { redirectUris: v.redirectUris.slice(), meta: { by: (meta.redirectUris && meta.redirectUris.by) || null, at: (meta.redirectUris && meta.redirectUris.at) || null } } : null; // used only for a SAML → OIDC switch
  model.vendorRepointed = meta.vendorRepointed || null;
  return model;
}
const dOnly = (x) => { try { return x ? new Date(x).toISOString().slice(0, 10) : '?'; } catch (e) { return String(x).slice(0, 10); } };

/** The inputs this app needs, each with need (required/recommended/optional), status and provenance. */
function inputsNeeded(m, proto, guide, extra = {}) {
  const t = m.auth.type; const P = proto.recommended; const src = m.inputSources || {}; const out = [];
  if (['unsupported', 'unknown', 'depends', 'none'].includes(P)) return out;
  const prov = (k) => src[k] ? { by: src[k].by, at: src[k].at } : {};
  const row = (key, need, present, value, source, more = {}) => { const f = FIELD[key]; out.push(Object.assign({ key, label: f.label, type: f.type, choices: f.choices || null, why: f.why, need, gate: null, status: present ? 'provided' : 'missing', value: value === undefined ? null : value, source: present ? source : null }, more)); };
  row('owner', t === 'saml' || t === 'oidc' ? 'required' : 'recommended', !!m.identity.owner, m.identity.owner || null, 'input', { gate: 'handoff' });
  const e = entraProto(m);
  if (t === 'saml') {
    const s = m.saml; const tpl = !!(proto.template && proto.template.id && !proto.nonGallery);
    const ev = oidcSupport(m, guide, m.saml && m.saml.entraTemplate);
    if (e === 'saml') {
      row('entityId', 'required', !!s.entityId, s.entityId || null, src.entityId ? 'input' : 'okta', Object.assign({ gate: 'push', hint: tpl ? `Pre-flight fails without it. Gallery template "${proto.template.displayName}" does not supply it — read it from the vendor SP metadata (EntityDescriptor entityID) or the vendor SSO settings page.` : 'Pre-flight fails without it. From the vendor SP metadata (EntityDescriptor entityID) or the vendor SSO settings page.' }, prov('entityId')));
      row('acsUrls', 'required', s.acsUrls.length > 0, s.acsUrls, src.acsUrls ? 'input' : 'okta', Object.assign({ gate: 'push', hint: 'Pre-flight fails without it. AssertionConsumerService Location(s) in the SP metadata.' }, prov('acsUrls')));
      row('signOnUrl', 'optional', !!m.identity.loginUrl, m.identity.loginUrl || null, src.signOnUrl ? 'input' : 'okta', prov('signOnUrl'));
      row('logoutUrl', 'optional', !!(s.slo && s.slo.logoutUrl), (s.slo && s.slo.logoutUrl) || null, src.logoutUrl ? 'input' : 'okta', prov('logoutUrl'));
      row('relayState', 'optional', !!s.relayState, s.relayState || null, src.relayState ? 'input' : 'okta', prov('relayState'));
    } else {
      const o = m.oidc;
      row('redirectUris', 'required', o.redirectUris.length > 0, o.redirectUris, 'input', Object.assign({ gate: 'push', hint: 'Staged as OpenID Connect while Okta uses SAML, so there is nothing to copy: the callback / redirect URL comes from the vendor\'s OpenID Connect (custom identity provider) settings' + (guide && guide.console ? ' — ' + guide.console.name + ' → ' + guide.console.path : '') + '.' }, prov('redirectUris')));
      row('signOnUrl', 'optional', !!m.identity.loginUrl, m.identity.loginUrl || null, src.signOnUrl ? 'input' : 'okta', prov('signOnUrl'));
      row('logoutUrl', 'optional', !!(s.slo && s.slo.logoutUrl), (s.slo && s.slo.logoutUrl) || null, src.logoutUrl ? 'input' : 'okta', Object.assign({ hint: 'Becomes the front-channel logout URL of the app registration.' }, prov('logoutUrl')));
    }
    row('vendorOidc', 'optional', !!m.identity.vendorOidc, m.identity.vendorOidc || null, 'input', Object.assign({ hint: ev.level === 'vendor_doc' ? `Vendor documentation (${guide.checkedAt}) lists OpenID Connect; the owner's answer is still recorded separately.` : ev.level === 'gallery' ? 'The Entra gallery entry for this vendor offers OpenID Connect; confirm with the owner that this application can use it.' : 'Ask the application owner or the vendor; the scan cannot see this. "Yes" makes OpenID Connect the preferred target.', guideSays: ev.level === 'vendor_doc' ? 'yes' : null }, prov('vendorOidc')));
    row('protocolChoice', 'optional', !!m.identity.protocolChoice, m.identity.protocolChoice || null, 'input', Object.assign({ hint: e === 'oidc' ? 'Staged as OpenID Connect (' + (proto.switch && proto.switch.chosen ? 'recorded choice' : ev.short) + '). Choose SAML to keep the vendor-side integration as it is.' : ev.available ? 'Kept on SAML by choice; OpenID Connect is available (' + ev.short + ').' : 'SAML today; choose OIDC only if you know the vendor supports it (no evidence is recorded).' }, prov('protocolChoice')));
  } else if (t === 'oidc') {
    const o = m.oidc; const wild = o.wildcardRedirect === 'SUBDOMAIN' || o.redirectUris.some((u) => u.includes('*')) || !o.redirectUris.length;
    row('redirectUris', wild ? 'required' : 'optional', !wild, o.redirectUris, src.redirectUris ? 'input' : 'okta', Object.assign({ gate: 'push', hint: wild ? 'Okta allows wildcards; Entra does not. List every exact URI.' + (o.redirectUris.length ? ' Okta has: ' + o.redirectUris.join(', ') : '') : 'From the Okta client; supply them only to override.', oktaValues: o.redirectUrisOkta || null }, prov('redirectUris')));
  }
  if (t === 'swa') row('signOnUrl', 'required', !!(m.swa && m.swa.url), (m.swa && m.swa.url) || null, src.signOnUrl ? 'input' : 'okta', Object.assign({ hint: 'The HTML sign-in page Entra password-based SSO fills (captured once in the portal).' }, prov('signOnUrl')));
  if (t === 'bookmark' && P === 'linked') row('signOnUrl', 'required', !!(m.bookmark && m.bookmark.url), (m.bookmark && m.bookmark.url) || null, src.signOnUrl ? 'input' : 'okta', Object.assign({ hint: 'The URL the linked tile opens in My Apps.' }, prov('signOnUrl')));
  if (t === 'saml' || t === 'oidc') {
    const gc = guide && guide.console ? guide.console : null;
    row('adminUrl', 'recommended', !!m.identity.adminUrl || !!gc, m.identity.adminUrl || (gc ? gc.url : null), m.identity.adminUrl ? 'input' : 'guide', Object.assign({ hint: gc && !m.identity.adminUrl ? `From the vendor guide: ${gc.name} → ${gc.path}` : 'The page in the vendor console where the identity-provider settings live.' }, prov('adminUrl')));
    const rec = extra.recorded || null;
    out.push({ key: 'twoIdp', label: 'Does the vendor accept two identity providers at once?', type: 'coexistence', choices: ['yes', 'no'], need: 'recommended', status: rec ? 'provided' : 'missing', value: rec ? (rec.supported ? 'yes' : 'no') : null, source: rec ? 'input' : null, by: rec ? rec.by : null, at: rec ? rec.at : null, note: rec ? rec.note : null, why: 'Decides coexistence (add Entra next to Okta, test, then retire Okta) versus a hard cutover with the owner.', route: 'coexistence' });
  }
  return out;
}
function inputsSummary(list) {
  const req = list.filter((x) => x.need === 'required'); const missing = req.filter((x) => x.status === 'missing');
  return { total: list.length, required: req.length, missing: missing.length, missingKeys: missing.map((x) => x.key), pushBlocking: list.filter((x) => x.gate === 'push' && x.status === 'missing').map((x) => x.key), recommendedMissing: list.filter((x) => x.need === 'recommended' && x.status === 'missing').map((x) => x.key) };
}

/** The protocol pill the queue and drawer show, from the recommendation and the OIDC evidence. */
function oidcEvidence(m, proto, guide) {
  const t = m.auth.type;
  if (t === 'oidc') return { level: 'current', pill: 'oidc', label: 'OIDC · preferred', detail: 'Already OpenID Connect against Okta; the Entra app registration keeps the protocol — only issuer, client id and secret change.' };
  if (t !== 'saml') return { level: null, pill: proto.recommended === 'linked' ? 'linked' : proto.recommended === 'password' ? 'password' : null, label: null, detail: null };
  const ev = oidcSupport(m, guide, m.saml && m.saml.entraTemplate);
  const EV = { owner: 'owner confirmed', vendor_doc: 'vendor documentation', gallery: 'Entra gallery' };
  if (proto.recommended === 'oidc') return { level: ev.level, pill: 'oidc', label: 'OIDC · preferred' + (proto.switch && proto.switch.chosen ? ' · chosen' : EV[ev.level] ? ' · ' + EV[ev.level] : ''), detail: `Staged as OpenID Connect although Okta uses SAML (${proto.switch && proto.switch.chosen ? 'recorded choice' : ev.short}). ${ev.detail} Keep SAML instead by recording "Target protocol in Entra: SAML" under Provide inputs.`, switched: true };
  if (proto.kept) return { level: ev.level, pill: 'saml-oidc', label: 'SAML · kept' + (ev.available ? ' (OIDC available)' : ''), detail: proto.reason };
  if (ev.level === 'owner_no') return { level: 'owner_no', pill: 'saml', label: 'SAML', detail: ev.detail };
  return { level: 'none', pill: 'saml-ask', label: 'SAML · ask owner about OIDC', detail: ev.detail };
}

/** The application (vendor) side: what it must give us, what it gets from Entra, how that gets entered, and that no vendor API is wired. */
function appSide(m, proto, guide) {
  const t = m.auth.type; const P = proto.recommended;
  if (t === 'bookmark') return { applicable: false, why: m.bookmark && m.bookmark.target === 'entra_launcher' ? 'The tile already opens Entra My Apps; there is no vendor configuration to change.' : 'A bookmark tile has no application-side SSO configuration; the vendor is not reconfigured.' };
  if (t === 'swa') return { applicable: false, why: 'Password-based SSO: the vendor is not reconfigured; each user enters their password once in My Apps.' };
  if (!['saml', 'oidc'].includes(t) || ['unsupported', 'unknown'].includes(P)) return { applicable: false, why: proto.reason };
  const tenant = process.env.ENTRA_TENANT_ID || null; const T = tenant || '<ENTRA_TENANT_ID not set on the server>';
  const link = m.identity.adminUrl ? { url: m.identity.adminUrl, path: null, source: 'input', label: 'Vendor admin console (recorded)' }
    : guide && guide.console ? { url: guide.console.url, path: guide.console.path, source: 'guide', label: guide.console.name }
    : m.identity.appUrl ? { url: m.identity.appUrl, path: null, source: 'okta', label: 'Application URL from Okta (not necessarily the admin console)' } : null;
  const s = m.saml, o = m.oidc; const src = m.inputSources || {}; const e = entraProto(m); const sw = !!(o && o.switched);
  const st = (present, key) => present ? (src[key] ? 'provided' : 'scanned') : 'missing';
  const needsFromApp = e === 'saml' ? [
    { key: 'entityId', label: 'Identifier (Entity ID)', value: s.entityId || null, status: st(!!s.entityId, 'entityId'), where: 'Vendor SSO settings or SP metadata entityID' },
    { key: 'acsUrls', label: 'Reply URL (ACS)', value: s.acsUrls, status: st(s.acsUrls.length > 0, 'acsUrls'), where: 'SP metadata AssertionConsumerService Location' },
    { key: 'signOnUrl', label: 'Sign-on URL', value: m.identity.loginUrl || null, status: st(!!m.identity.loginUrl, 'signOnUrl'), optional: true },
    { key: 'logoutUrl', label: 'Logout URL', value: (s.slo && s.slo.logoutUrl) || null, status: st(!!(s.slo && s.slo.logoutUrl), 'logoutUrl'), optional: true },
  ].concat(s.encryption && s.encryption.enabled ? [{ key: 'encryptionCert', label: 'Encryption certificate (.cer)', value: null, status: 'manual', where: 'From the vendor; uploaded under Token encryption in the Entra portal. Not collected by this page.' }] : []) : [
    { key: 'redirectUris', label: 'Redirect URIs', value: o.redirectUris, status: (o.redirectUris.some((u) => u.includes('*')) || !o.redirectUris.length) ? 'missing' : st(true, 'redirectUris'), where: sw ? 'The vendor\'s OpenID Connect (custom identity provider) settings: the callback / redirect URL it publishes. Record it under Provide inputs.' : 'The application\'s OIDC client configuration' },
    { key: 'postLogoutRedirectUris', label: 'Post-logout redirect URIs', value: o.postLogoutRedirectUris, status: o.postLogoutRedirectUris.length ? 'scanned' : 'missing', optional: true },
  ];
  const givesToApp = e === 'saml' ? [
    { key: 'issuer', label: 'Identity provider issuer / IdP Entity ID', value: `https://sts.windows.net/${T}/`, when: 'now' },
    { key: 'loginUrl', label: 'Sign-on (SSO) URL', value: `https://login.microsoftonline.com/${T}/saml2`, when: 'now' },
    { key: 'logoutUrl', label: 'Logout URL', value: `https://login.microsoftonline.com/${T}/saml2`, when: 'now' },
    { key: 'metadataUrl', label: 'Federation metadata URL', value: `https://login.microsoftonline.com/${T}/federationmetadata/2007-06/federationmetadata.xml?appid=<appId — filled in by the staging result>`, when: 'after staging' },
    { key: 'certificate', label: 'Signing certificate (Base64)', value: 'Download from the enterprise app → Single sign-on → SAML certificates, after staging.', when: 'after staging' },
  ] : [
    { key: 'issuer', label: 'Issuer / authority', value: `https://login.microsoftonline.com/${T}/v2.0`, when: 'now' },
    { key: 'discovery', label: 'OpenID configuration', value: `https://login.microsoftonline.com/${T}/v2.0/.well-known/openid-configuration`, when: 'now' },
    { key: 'clientId', label: 'Client ID', value: '<appId — filled in by the staging result>', when: 'after staging' },
  ].concat(o.secretRequired !== false ? [{ key: 'clientSecret', label: 'Client secret', value: 'Shown once, on the Application side step, to the technician who staged; never stored. Paste it straight into the vendor field.', when: 'after staging', secret: true }] : []);
  const apiPush = guide && guide.apiPush ? Object.assign({ available: false }, guide.apiPush) : { available: false, note: 'Not yet automated: no vendor API is connected on this page for writing SSO settings. The application side is done by the owner in the vendor console — or with the Claude in Chrome extension on the owner\'s signed-in tab (prompt below).' };
  return { applicable: true, protocol: P, owner: m.identity.owner || null, link, needsFromApp, givesToApp, apiPush, tenantKnown: !!tenant,
    switch: sw ? { from: 'saml', to: 'oidc', evidence: o.evidence || null, note: 'The application is reconfigured from SAML to OpenID Connect: its SAML identity-provider settings are replaced by an OIDC client configuration using the values below; its own entity id and ACS URL are no longer used.' } : null,
    prompt: vendorPrompt(m, P, link, needsFromApp, givesToApp),
    repointed: m.vendorRepointed || null,
    record: { label: 'Vendor repointed', note: 'Recorded by a person — history, not verification. Verify reads the Entra sign-in log; Verified needs the tested record.' } };
}
function vendorPrompt(m, P, link, needs, gives) {
  const where = link ? `${link.label || 'the vendor admin console'} (${link.url})${link.path ? ' → ' + link.path : ''}` : 'the vendor admin console (URL not recorded — record it under Provide inputs first)';
  const sw = !!(m.oidc && m.oidc.switched);
  const head = `Okta → Entra migration — ${m.identity.label} (Okta app ${m.identity.id}). Step: application owner ${sw ? 'switches the application from SAML to OpenID Connect against Entra' : 'repoints the application at Entra (' + String(P).toUpperCase() + ')'}.`;
  const ext = `Use the Claude in Chrome extension on my signed-in tab of ${where}. Do not use the built-in browser pane or open a new browser — only the extension on my tab carries my sign-in.`;
  const lines = [`Open ${where} and go to the single sign-on / SAML / OpenID Connect settings for this application. If you cannot find them, stop and ask me.`];
  if (P === 'saml') {
    lines.push('Replace the identity-provider values with these Entra values, exactly: ' + gives.filter((g) => g.when === 'now').map((g) => `${g.label} = ${g.value}`).join(' ; ') + '.');
    lines.push('Certificate: upload the Entra signing certificate file I downloaded (I will name the file) or paste the federation metadata URL I give you; if the vendor accepts neither, stop and ask me.');
    const sp = needs.filter((n) => ['entityId', 'acsUrls'].includes(n.key) && n.value && [].concat(n.value).length);
    if (sp.length) lines.push('Do not change the vendor\'s own service-provider identifiers: ' + sp.map((n) => `${n.label} = ${[].concat(n.value).join(', ')}`).join(' ; ') + '. If the console shows different values, stop and tell me.');
  } else {
    lines.push((sw ? 'Change the identity-provider type from SAML to OpenID Connect (add an OIDC provider if the console keeps both), then enter' : 'Enter') + ' these Entra values exactly: ' + gives.filter((g) => !g.secret).map((g) => `${g.label} = ${g.value}`).join(' ; ') + ' (I will paste the Client ID from the staging result).');
    lines.push('Client secret: leave that field to me. Stop, tell me which field it is, and I will paste the secret myself. Never ask me to paste it into this chat.');
    const r = needs.find((n) => n.key === 'redirectUris');
    if (r && r.value && r.value.length) lines.push('Redirect URIs stay as they are: ' + r.value.join(', ') + '. Do not add or remove any.');
  }
  lines.push('If the console allows more than one identity provider, add Entra next to Okta and do not delete the Okta entry. If it allows only one, stop before replacing it and ask me — that is the cutover.');
  lines.push('Before you press Save / Activate, show me the completed form and wait for my confirmation.');
  const verify = 'the vendor SSO page shows the Entra values above and reported a successful save; nothing else on the page changed.';
  return [head, ext, PROMPT_RULES, 'Do this:', lines.map((l, i) => `${i + 1}. ${l}`).join('\n'), 'Verify: ' + verify, 'Then report back: exactly what you changed, what you could not do and why. I will record it on the CorpIT migration page (App side → "Vendor repointed", then Validate); nothing is marked done by copying this prompt.'].join('\n');
}

/* ---- already migrated? twins (same base name) + where their links point ---- */
const TWIN_STOP = new Set(['sso', 'saml', 'oidc', 'oauth', 'wsfed', 'old', 'new', 'legacy', 'retired', 'deprecated', 'read', 'only', 'readonly', 'ro', 'dashboard', 'admin', 'online', 'web', 'portal', 'login', 'bookmark', 'tile', 'link', 'okta', 'entra', 'azure', 'microsoft', 'app', 'apps', 'application', 'the', 'and', 'of', 'for', 'inc', 'llc', 'v1', 'v2', 'via']);
function twinKey(label) {
  const toks = String(label || '').toLowerCase().replace(/^sso-/, '').split(/[^a-z0-9]+/).filter((t) => t && !TWIN_STOP.has(t));
  return toks.length ? toks.join(' ') : null;
}
function twinIndex(apps) {
  const by = new Map();
  for (const a of apps) { const k = twinKey(a.label); if (!k) continue; if (!by.has(k)) by.set(k, []); by.get(k).push(a); }
  return by;
}
const launcherOf = (url) => { const mm = String(url || '').match(/launcher\.myapps\.microsoft\.com\/api\/signin\/([0-9a-f-]{36})/i); return mm ? mm[1].toLowerCase() : null; };
async function entraByLauncher(ids) {
  const list = [...new Set(ids.filter(Boolean))];
  if (!list.length) return new Map();
  const [rows] = await pool.query(`SELECT entra_id, app_id, display_name, preferred_single_sign_on_mode, account_enabled FROM entra_apps WHERE app_id IN (?)`, [list]);
  return new Map(rows.map((r) => [String(r.app_id).toLowerCase(), r]));
}
const MIGRATED_LABEL = { evidence: 'Already migrated — evidence', likely: 'Likely migrated — confirm', inconclusive: 'Twin found — inconclusive', okta: 'Still signs in through Okta' };
/** app = {oktaId,label,name,status,signOnMode,url}; twins = same-key apps; probes = Map; entraByAppId = Map; cx = coexistenceFor(); facts = work-item facts */
function migratedFor(app, twins, probes, entraByAppId, cx, facts) {
  const why = []; let level = null; let twin = null; let probe = null; let probeTarget = null; let pwTile = false;
  const R = { okta: 0, inconclusive: 1, likely: 2, evidence: 3 };
  const set = (lvl) => { if (level === null || R[lvl] > R[level]) level = lvl; };
  const match = (facts && facts.match) || {};
  const eName = (e, id) => e ? `"${e.display_name}"${e.preferred_single_sign_on_mode ? ' (' + e.preferred_single_sign_on_mode + ', ' + (e.account_enabled ? 'enabled' : 'disabled') + ')' : ''}` : `Entra app ${id} (not in the Entra mirror)`;
  // a match is "confirmed" only when a person confirmed it; an identifier match is a suggestion until then
  const matchWord = match.decision === 'manual_confirmed' ? 'confirmed match' : 'suggested match (not confirmed yet)';
  const matchNote = (e) => !e || !match.entraId ? '' : e.entra_id === match.entraId ? ` — the same Entra app as the ${matchWord} on this work item` : ` — NOTE: the ${matchWord} on this work item is a different Entra app (${match.entraName || match.entraId}); check which is right`;
  const probeLine = (p, who) => { if (p.idp === 'entra') { set('evidence'); return `${who}: "Check where it points" (${dOnly(p.checkedAt)}) ${p.detail}.`; } if (p.idp === 'okta') { set('okta'); return `${who}: "Check where it points" (${dOnly(p.checkedAt)}) ${p.detail} — still Okta.`; } if (p.idp === 'vendor') { set('inconclusive'); return `${who}: "Check where it points" (${dOnly(p.checkedAt)}) ${p.detail}.`; } return `${who}: "Check where it points" (${dOnly(p.checkedAt)}) could not follow the link — ${p.detail}.`; };
  // 1. this app's own link (tiles)
  const ownLauncher = launcherOf(app.url);
  if (ownLauncher) { const e = entraByAppId.get(ownLauncher) || null; set('evidence'); why.push(`This Okta tile opens Entra My Apps for ${eName(e, ownLauncher)}${matchNote(e)}.`); }
  else if (app.url) { const p = probes.get(app.oktaId) || null; probeTarget = app.oktaId; if (p) { probe = p; why.push(probeLine(p, 'This tile')); } else if (/azure|entra|microsoft|myapps/i.test(app.url)) { set('likely'); why.push(`This tile links to ${app.url} — the URL names Entra/Azure; not followed yet.`); } else { set('inconclusive'); why.push(`This tile links to ${hostOf(app.url) || app.url} — the URL alone does not say which identity provider signs users in; not followed yet. Use "Check where it points".`); } }
  // 2. twins with the same base name
  for (const t of twins) {
    twin = twin || t;
    const tl = launcherOf(t.url); const tp = probes.get(t.oktaId) || null;
    if (tl) { const e = entraByAppId.get(tl) || null; set('evidence'); why.push(`Okta tile "${t.label}" (${t.oktaId}, ${t.status}) opens Entra My Apps for ${eName(e, tl)}${matchNote(e)}.`); }
    else if (tp) { probe = probe || tp; probeTarget = probeTarget || t.oktaId; why.push(probeLine(tp, `Okta tile "${t.label}" (${t.oktaId})`)); }
    else if (t.url) { probeTarget = probeTarget || t.oktaId; if (/azure|entra|microsoft|myapps/i.test(t.url)) { set('likely'); why.push(`Okta tile "${t.label}" (${t.oktaId}, ${t.status}) links to ${t.url} — the URL names Entra/Azure; not followed yet.`); } else { set('inconclusive'); why.push(`Okta tile "${t.label}" (${t.oktaId}, ${t.status}) links to ${hostOf(t.url) || t.url} — same name, but the URL alone does not say which identity provider signs users in. Use "Check where it points".`); } }
    else if (/\bold\b/i.test(t.label) && t.status === 'INACTIVE') { set('likely'); why.push(`"${t.label}" (${t.oktaId}) is an inactive twin marked OLD: this app looks like its replacement.`); }
    else { set('inconclusive'); why.push(`"${t.label}" (${t.oktaId}, ${String(t.signOnMode || '').toLowerCase().replace(/_/g, ' ')}, ${t.status}) shares the base name; no link to follow.`); }
  }
  if (/\bold\b/i.test(app.label) && app.status === 'INACTIVE') why.push('This app is inactive and named OLD: it is the retired side of the pair.');
  // 3. tenant sign-in evidence through the confirmed Entra app (from the coexistence signal)
  const tn = cx && cx.sources && cx.sources.tenant;
  if (tn && tn.entraSignIns && tn.entraSignIns.count > 0) {
    const ok = tn.oktaUsage || {};
    if (ok.count === 0) { set('evidence'); why.push(`${tn.entraSignIns.count} Entra sign-ins through "${tn.entraName}" in ${tn.entraSignIns.days} days and no Okta SSO sign-in in ${ok.days} days (checked ${dOnly(ok.checkedAt)}): users are on Entra.`); }
    else if (ok.count === null || ok.count === undefined) { set('likely'); why.push(`${tn.entraSignIns.count} Entra sign-ins through "${tn.entraName}" in ${tn.entraSignIns.days} days; Okta usage not checked yet — "Check Okta usage" tells a completed migration from coexistence.`); }
    else if (CX.PASSWORD_TILE.test(String(app.signOnMode || ''))) { set('likely'); pwTile = true; why.push(`${tn.entraSignIns.count} Entra sign-ins through "${tn.entraName}" and ${ok.count}${ok.capped ? '+' : ''} Okta launches of a ${String(app.signOnMode).toLowerCase().replace(/_/g, ' ')} tile in the window. That tile fills a vendor password, so its launches can be password sign-ins that bypass Entra: Entra is in use, but the migration is complete only if the vendor no longer accepts password sign-in.`); }
    else if (CX.NO_SSO.test(String(app.signOnMode || ''))) { set('evidence'); why.push(`${tn.entraSignIns.count} Entra sign-ins through "${tn.entraName}" and ${ok.count}${ok.capped ? '+' : ''} Okta tile launches in the window. The Okta app is a bookmark tile, not a federation: users still start from the Okta tile, then sign in through Entra. Entra is already the identity provider; the tile is not retired yet.`); }
    else why.push(`${tn.entraSignIns.count} Entra and ${ok.count}${ok.capped ? '+' : ''} Okta SSO sign-ins in the window: both identity providers are in use (coexistence, not a completed migration).`);
  }
  if (level === null && !why.length) return null;
  const next = level === 'evidence' ? 'Confirm the Entra app on the work item (Review match), record the tested sign-in, then retire the Okta app from the lifecycle action. Nothing is retired automatically.'
    : level === 'likely' && pwTile ? 'Ask the application owner whether the vendor still accepts password sign-in. If it does not, confirm the match, record the tested sign-in, then retire the tile; if it does, this is coexistence, not a completed migration.'
    : level === 'likely' ? 'Run "Check where it points" or "Check Okta usage" to turn this into evidence.'
    : level === 'inconclusive' ? 'Run "Check where it points" on the tile; if it lands on the vendor page, ask the owner which identity provider the vendor is configured for.'
    : level === 'okta' ? 'The link still sends users to Okta; this app is not migrated.' : null;
  return { level, label: level ? MIGRATED_LABEL[level] : null, why, next,
    twin: twin ? { oktaId: twin.oktaId, label: twin.label, status: twin.status, signOnMode: twin.signOnMode, url: twin.url || null } : null,
    twins: twins.map((t) => ({ oktaId: t.oktaId, label: t.label, status: t.status, signOnMode: t.signOnMode, url: t.url || null })),
    probe, probeTarget, canProbe: !!probeTarget };
}
const liteApp = (a) => ({ oktaId: a.okta_id, label: a.label, name: a.name, status: a.status, signOnMode: a.sign_on_mode, url: a.app_url || null });
/** "Marked as migrated" records (oem_app_migrated, active rows only). ids = null → all. */
async function loadMigratedMarks(ids) {
  if (Array.isArray(ids) && !ids.length) return new Map();
  const [rows] = await pool.query(`SELECT okta_id, entra_id, entra_name, note, sign_in_tested, marked_by, marked_at FROM oem_app_migrated WHERE cleared_at IS NULL${Array.isArray(ids) ? ' AND okta_id IN (?)' : ''}`, Array.isArray(ids) ? [ids] : []);
  return new Map(rows.map((r) => [r.okta_id, { entraId: r.entra_id, entraName: r.entra_name, note: r.note, signInTested: !!r.sign_in_tested, by: r.marked_by, at: r.marked_at }]));
}
/** Is this application already migrated, as far as the record shows? Verified/retired work item, a person's
    "marked as migrated" record, or evidence (a same-name tile opens Entra / a followed link lands on Entra).
    Any of these hides Stage in Entra: staging would create a second Entra application. Likely/inconclusive
    detections are cautions, not gates. */
function alreadyMigrated(as, extra = {}) {
  const ws = extra.workState || null; const manual = extra.manual || null; const mg = extra.migrated || as.migrated || null;
  if (ws === 'retired') return { kind: 'retired', label: 'Retired in Okta', detail: 'The work item is Retired: the Okta application has been retired after verification.' };
  if (ws === 'verified') return { kind: 'verified', label: 'Verified — sign-in through Entra recorded', detail: 'The work item is Verified: a tested sign-in through Entra is recorded.' };
  if (manual) return { kind: 'recorded', label: 'Migrated — recorded by ' + (manual.by || 'a person') + ' on ' + dOnly(manual.at) + (manual.signInTested ? ' (sign-in tested)' : ' (not verified)'), detail: 'Marked as migrated: ' + (manual.note || '') + (manual.entraName ? ' Entra app: ' + manual.entraName + '.' : ''), by: manual.by, at: manual.at, entraId: manual.entraId || null, entraName: manual.entraName || null, note: manual.note || null, signInTested: !!manual.signInTested };
  if (mg && mg.level === 'evidence') return { kind: 'evidence', label: 'Already migrated — evidence', detail: (mg.why || []).join(' ') };
  return null;
}
/** Close the push for an already-migrated application (on the assessment object, in place). */
function gateAlreadyMigrated(as, extra = {}) {
  const done = alreadyMigrated(as, extra);
  const mg = extra.migrated || as.migrated || null;
  as.alreadyMigrated = done;
  as.caution = !done && mg && (mg.level === 'likely' || mg.level === 'inconclusive') ? { level: mg.level, label: mg.label, detail: (mg.why || []).join(' ') } : null;
  if (done) { as.push.possible = false; as.push.blockedBy = []; as.push.handoffs = []; as.push.alreadyMigrated = done; as.push.reason = 'already migrated: ' + done.label; }
  return done;
}
/** For one app: the same "already migrated" computation the queue does, plus the URLs "Check where it
    points" may follow for it — its own tile URL and its twins', nothing else. */
async function migratedContext(oktaId, facts, cx) {
  const [apps] = await pool.query(`SELECT okta_id, name, label, status, sign_on_mode, JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.settings.app.url')) AS app_url FROM okta_apps WHERE seen_in_last_sync=1`);
  const lite = apps.map(liteApp); const me = lite.find((a) => a.oktaId === oktaId);
  if (!me) return { migrated: null, probeTargets: [] };
  const twins = (twinIndex(lite).get(twinKey(me.label)) || []).filter((a) => a.oktaId !== oktaId);
  const [probes, entra] = await Promise.all([LP.loadProbes([oktaId, ...twins.map((t) => t.oktaId)]), entraByLauncher([me, ...twins].map((a) => launcherOf(a.url)))]);
  return { migrated: migratedFor(me, twins, probes, entra, cx, facts),
    probeTargets: [me, ...twins].filter((a) => a.url).map((a) => ({ oktaId: a.oktaId, label: a.label, url: a.url, relation: a.oktaId === oktaId ? 'self' : 'twin', launcher: !!launcherOf(a.url), probe: probes.get(a.oktaId) || null })) };
}

/* Entra single sign-on methods (Microsoft Learn, checked 2026-09-10) and what this engine does for each.
   Graph v1.0 preferredSingleSignOnMode accepts only password, saml, notSupported, oidc — "linked" is portal-only. */
const SSO_METHODS = {
  checkedAt: '2026-09-10',
  sources: [
    { title: 'Plan a single sign-on deployment — single sign-on options (Microsoft Learn)', url: 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/plan-sso-deployment#single-sign-on-options' },
    { title: 'servicePrincipal resource type, Graph v1.0 — preferredSingleSignOnMode, loginUrl, samlSingleSignOnSettings', url: 'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0' },
  ],
  graphModes: ['password', 'saml', 'notSupported', 'oidc'],
  methods: [
    { key: 'oidc', entra: 'OpenID Connect and OAuth', okta: ['OPENID_CONNECT', 'SAML_2_0 — switch, when the vendor is evidenced to support OIDC'], push: 'auto', graph: 'App registration + service principal, redirect URIs, optional and group claims, client secret (addPassword), assignments — Graph v1.0.', inputs: ['owner', 'redirectUris (when Okta has a wildcard or none; always for a SAML → OIDC switch)', 'adminUrl (recommended)'], preferred: 'Preferred wherever the vendor is evidenced to support it (owner answer, vendor documentation or the Entra gallery), whatever Okta uses today; "Target protocol in Entra: SAML" under Provide inputs keeps SAML.', appSide: 'The vendor gets the Entra issuer, client id and the secret — shown once at staging; a new one can be issued from this page for the hand-off.', portalOnly: null },
    { key: 'saml', entra: 'SAML', okta: ['SAML_2_0'], push: 'auto', graph: 'Gallery template instantiate (or the non-gallery template), preferredSingleSignOnMode=saml, identifierUris, replyUrls, loginUrl, relayState, claims mapping, addTokenSigningCertificate, assignments — Graph v1.0.', inputs: ['owner', 'entityId + acsUrls when the Okta app object lacks them (OIN apps)', 'signOnUrl / logoutUrl / relayState (optional)', 'adminUrl (recommended)'], appSide: 'The vendor gets the Entra federation metadata URL or the signing certificate, the login/logout URLs and the issuer.', portalOnly: 'Token-encryption certificate upload (when the Okta app encrypts assertions).' },
    { key: 'password', entra: 'Password-based', okta: ['BROWSER_PLUGIN', 'AUTO_LOGIN'], push: 'auto+portal', graph: 'preferredSingleSignOnMode=password and loginUrl — Graph v1.0 (with approval on this page).', inputs: ['owner', 'signOnUrl (the HTML sign-in page)'], appSide: 'Nothing at the vendor; users re-enter their password once in My Apps — stored Okta passwords cannot be exported.', portalOnly: 'Sign-in form capture for a non-gallery app (My Apps Secure Sign-in Extension) — Claude prompt on the Entra tab.' },
    { key: 'linked', entra: 'Linked', okta: ['BOOKMARK (external URL)'], push: 'auto+portal', graph: 'homepage and loginUrl — Graph v1.0. Linked mode itself has no Graph value.', inputs: ['signOnUrl (the tile URL)'], appSide: 'None — a link does not authenticate.', portalOnly: 'Single sign-on → Linked in the portal — Claude prompt on the Entra tab.' },
    { key: 'disabled', entra: 'Disabled', okta: [], push: 'n/a', graph: 'preferredSingleSignOnMode=notSupported.', inputs: [], appSide: 'None.', portalOnly: null, note: 'For applications not ready for SSO; this engine never creates a disabled app.' },
    { key: 'header', entra: 'Header-based (Application Proxy)', okta: [], push: 'none', graph: 'Needs a private network connector and an Application Proxy application; not built here.', inputs: [], appSide: '—', portalOnly: 'All of it.', note: 'No Okta sign-on mode maps to it (Okta Access Gateway would).' },
    { key: 'iwa', entra: 'Integrated Windows Authentication (Application Proxy, KCD)', okta: [], push: 'none', graph: 'Application Proxy + Kerberos constrained delegation; not built here.', inputs: [], appSide: '—', portalOnly: 'All of it.', note: 'On-premises applications only.' },
    { key: 'wsfed', entra: 'WS-Federation (gallery templates only)', okta: ['WS_FEDERATION'], push: 'none', graph: 'Only through a gallery template that offers WS-Fed; otherwise the vendor must move to SAML.', inputs: [], appSide: '—', portalOnly: 'Template-specific.', note: 'No WS-Fed application in the current Okta sync.' },
    { key: 'unsupported', entra: 'No Entra application equivalent', okta: ['RADIUS_*', 'MFA_AS_SERVICE', 'SAML_1_1', 'Office 365 WS-Fed domain federation'], push: 'none', graph: '—', inputs: [], appSide: '—', portalOnly: null, note: 'RADIUS → NPS extension or SAML on the appliance; SAML 1.1 → the vendor must support SAML 2.0; domain federation is a domain-level cutover (Remaining Okta Dependencies).' },
  ],
};

/** roles = the WRITE credential's application roles: that is what gates every staging step. */
async function context() {
  const [w, r, okta] = await Promise.all([L.graphToken(false, 'write'), L.graphToken(false, 'read'), L.oktaIdentity()]);
  return { roles: w.roles || null, graphError: w.error || null, readRoles: r.roles || null, readError: r.error || null, okta,
           write: { configured: !!w.configured, name: w.name || null, appId: w.appId || null, error: w.error || null } };
}

async function latestMigrations() {
  const [rows] = await pool.query(`SELECT m.id, m.okta_id, m.status, m.protocol, m.readiness, m.created_at, m.finished_at, m.job_id FROM oem_migration m JOIN (SELECT okta_id, MAX(id) id FROM oem_migration GROUP BY okta_id) x ON x.id=m.id`);
  return new Map(rows.map((r) => [r.okta_id, r]));
}

/** Assess one app from its stored scan + the work-item facts + live roles. */
async function assessment(oktaId, ctx) {
  const scan = await loadScan(oktaId);
  if (!scan || !scan.model) return null;
  ctx = ctx || await context();
  const [[wi]] = await pool.query(`SELECT facts, state FROM oem_work_item WHERE item_key=?`, ['app:' + oktaId]);
  const facts = wi ? j(wi.facts, {}) : {};
  const a = assessApp(scan, { roles: ctx.roles, graphError: ctx.graphError, readRoles: ctx.readRoles, readError: ctx.readError, okta: ctx.okta, facts });
  a.workState = wi ? wi.state : null;
  // dual-IdP signal + the vendor guide (tenant evidence, vendor documentation, technician answer — each labelled)
  const [[scanRow]] = await pool.query(`SELECT coexistence, inputs FROM oem_app_scan WHERE okta_id=?`, [oktaId]);
  const ev = await CX.loadEvidence();
  const appRow = { oktaId, name: scan.model.identity.name, label: scan.model.identity.label, oktaStatus: scan.model.identity.status, signOnMode: scan.model.identity.signOnMode };
  const recorded = scanRow ? j(scanRow.coexistence, null) : null;
  a.coexistence = CX.coexistenceFor({ app: appRow, facts, recorded, evidence: ev });
  a.guide = VG.guideFor(appRow);
  // what a person must supply, what the app side needs and gets, and whether this app already looks migrated
  const inputs = scan.inputs || {};
  a.inputs = { values: inputs.values || {}, meta: inputs.meta || {}, fields: INPUT_FIELDS.filter((f) => f.appliesTo.includes(scan.model.auth.type) || f.appliesTo.includes(entraProto(scan.model))) };
  a.inputsNeeded = inputsNeeded(scan.model, a.protocol, a.guide, { recorded });
  a.inputsSummary = inputsSummary(a.inputsNeeded);
  a.protocol.oidcEvidence = oidcEvidence(scan.model, a.protocol, a.guide);
  a.appSide = appSide(scan.model, a.protocol, a.guide);
  a.vendorRepointed = (inputs.meta && inputs.meta.vendorRepointed) || null;
  const mc = await migratedContext(oktaId, facts, a.coexistence);
  a.migrated = mc.migrated; a.probeTargets = mc.probeTargets;
  a.migratedManual = (await loadMigratedMarks([oktaId])).get(oktaId) || null;
  gateAlreadyMigrated(a, { workState: a.workState, manual: a.migratedManual, migrated: a.migrated });
  return a;
}

/** The migration queue: every application-category Okta app with its readiness, automation, risk and status. */
async function queue({ includeInactive = true } = {}) {
  const ctx = await context();
  const [apps] = await pool.query(`SELECT a.okta_id, a.name, a.label, a.status, a.sign_on_mode, a.assigned_user_count, a.assigned_group_count, s.scanned_at, s.complete, s.errors, s.normalized, s.owner, s.coexistence, s.inputs, w.facts, w.state,
                                            JSON_UNQUOTE(JSON_EXTRACT(a.raw_json,'$._links.logo[0].href')) AS logo_href,
                                            JSON_UNQUOTE(JSON_EXTRACT(a.raw_json,'$.settings.app.url')) AS app_url
                                     FROM okta_apps a LEFT JOIN oem_app_scan s ON s.okta_id=a.okta_id LEFT JOIN oem_work_item w ON w.item_key=CONCAT('app:', a.okta_id)
                                    WHERE a.seen_in_last_sync=1 ${includeInactive ? '' : `AND a.status='ACTIVE'`}`);
  const [migs, evidence, [entraLogos], marks, usage, tests] = await Promise.all([latestMigrations(), CX.loadEvidence(), pool.query(`SELECT entra_id FROM entra_apps WHERE logo_url IS NOT NULL AND logo_url<>''`), loadMigratedMarks(null),
    USAGE ? USAGE.forQueue().catch((e) => ({ error: e.message, attach: () => ({ error: e.message }) })) : null, TSI ? TSI.latestMap() : new Map()]);
  const entraLogo = new Set(entraLogos.map((r) => r.entra_id));
  const OKTA_PLACEHOLDER = /\/assets\/img\/logos\/default\./;
  // "already migrated?" — twins by base name (the SSO- app and its plain bookmark), recorded link probes, launcher tiles → Entra apps
  const lite = apps.map(liteApp); const twins = twinIndex(lite);
  const [probes, entraByApp] = await Promise.all([LP.loadProbes(null), entraByLauncher(lite.map((x) => launcherOf(x.url)))]);
  const rows = [];
  for (const a of apps) {
    if (D.classifyOktaApp(a).category !== 'applications') continue;
    const facts = j(a.facts, {}) || {};
    const mig = migs.get(a.okta_id) || null;
    const appRow = { oktaId: a.okta_id, name: a.name, label: a.label, oktaStatus: a.status, signOnMode: a.sign_on_mode };
    const recorded = j(a.coexistence, null);
    const cx = CX.coexistenceFor({ app: appRow, facts, recorded, evidence });
    const inputs = j(a.inputs, null) || {};
    const mg = migratedFor(liteApp(a), (twins.get(twinKey(a.label)) || []).filter((t) => t.oktaId !== a.okta_id), probes, entraByApp, cx, facts);
    const cxRow = { level: cx.level, label: cx.label, rank: cx.rank, priority: cx.priority, strategy: cx.strategy, guide: cx.guide.available ? { key: cx.guide.key, multiIdp: cx.guide.multiIdp, status: cx.guide.status } : null, summary: cx.evidence[0] || null };
    const storedScanErrors = j(a.errors, []);
    const base = { oktaId: a.okta_id, label: a.label, name: a.name, oktaStatus: a.status, signOnMode: a.sign_on_mode, users: a.assigned_user_count, groups: a.assigned_group_count, owner: a.owner || null, workState: a.state || null, scannedAt: a.scanned_at || null, scanComplete: a.scanned_at ? migrationScanComplete({ complete: !!a.complete, errors: storedScanErrors }) : null, scanEvidenceComplete: a.scanned_at ? !!a.complete : null, migration: mig ? { id: mig.id, status: mig.status, at: mig.finished_at || mig.created_at, jobId: mig.job_id } : null, target: facts.match ? { decision: facts.match.decision, entraName: facts.match.entraName || null, entraId: facts.match.entraId || null } : null, coexistence: cxRow,
      migrated: mg ? { level: mg.level, label: mg.label, why: mg.why[0] || null, twin: mg.twin ? { oktaId: mg.twin.oktaId, label: mg.twin.label } : null, canProbe: mg.canProbe } : null,
      migratedManual: marks.get(a.okta_id) || null,
      usage: usage ? usage.attach({ oktaId: a.okta_id, oktaStatus: a.status, signOnMode: a.sign_on_mode, url: a.app_url }, facts) : null,
      testSignIn: tests.get(a.okta_id) || null,
      /* The Entra assignment shape, straight off the work item's own facts — the same numbers the matcher recorded.
         The page needs it to tell a pilot apart from a rollout: assignment required + NO group + at least one user
         means only named individuals can reach the application. Carried, never interpreted here; when discovery has
         not written facts.entra this stays null so the page reads unknown rather than "no groups". */
      entra: facts.entra ? { id: facts.entra.id || null, name: facts.entra.name || null,
        assignmentRequired: facts.entra.assignmentRequired === true, users: facts.entra.users, groups: facts.entra.groups,
        mirroredAt: facts.entra.mirroredAt || null } : null,
      logo: a.logo_href && !OKTA_PLACEHOLDER.test(a.logo_href) ? 'okta' : (facts.match && facts.match.entraId && entraLogo.has(facts.match.entraId) ? 'entra' : null) };
    const model = j(a.normalized, null);
    if (!model) {
      const doneU = alreadyMigrated({ migrated: mg, push: {} }, { workState: a.state || null, manual: marks.get(a.okta_id) || null, migrated: mg });
      rows.push(Object.assign(base, { assessed: false, protocol: null, readiness: null, classification: null, classLabel: 'Not scanned', risk: null, inputs: null, alreadyMigrated: doneU,
        action: doneU ? (doneU.kind === 'evidence' ? { code: 'confirm', label: 'Already migrated — evidence · confirm', stage: { entra: 'evidence', app: 'unknown' } } : { code: 'done', label: doneU.label, stage: { entra: doneU.entraId ? 'recorded' : (doneU.kind === 'recorded' ? 'unknown' : 'confirmed'), app: doneU.kind === 'recorded' ? (doneU.signInTested ? 'recorded' : 'unknown') : 'verified' }, recorded: doneU.kind === 'recorded' ? { by: doneU.by, at: doneU.at, note: doneU.note, entraId: doneU.entraId, entraName: doneU.entraName, signInTested: doneU.signInTested } : undefined }) : { code: 'scan', label: 'Scan' },
        push: { possible: false, blockedBy: [], reason: doneU ? 'already migrated: ' + doneU.label : 'not scanned', alreadyMigrated: doneU || undefined } })); continue; }
    applyInputs(model, inputs, a.owner);
    const as = assessApp({ model, complete: !!a.complete, errors: storedScanErrors, scannedAt: a.scanned_at }, { roles: ctx.roles, graphError: ctx.graphError, readRoles: ctx.readRoles, readError: ctx.readError, okta: ctx.okta, facts });
    const guide = VG.guideFor(appRow);
    const oe = oidcEvidence(model, as.protocol, guide);
    as.migrated = mg; gateAlreadyMigrated(as, { workState: a.state || null, manual: marks.get(a.okta_id) || null, migrated: mg });
    rows.push(Object.assign(base, {
      assessed: true, alreadyMigrated: as.alreadyMigrated, caution: as.caution,
      protocol: { current: model.auth.type, recommended: as.protocol.recommended, confidence: as.protocol.confidence, pill: oe.pill, pillLabel: oe.label, oidc: oe.level },
      readiness: { score: as.readiness.score, status: as.readiness.status, statusLabel: as.readiness.statusLabel },
      classification: as.classification, classLabel: as.classLabel, ownerAction: as.ownerAction.length > 0,
      automation: as.automation.counts, risk: as.risk, stops: as.stops.length, hardStops: as.stops.filter((s) => s.severity === 'stop').length,
      inputs: inputsSummary(inputsNeeded(model, as.protocol, guide, { recorded })),
      push: as.push,
      action: actionFor(as, mig, { workState: a.state || null, vendorRepointed: (inputs.meta && inputs.meta.vendorRepointed) || null, manual: marks.get(a.okta_id) || null, migrated: mg }),
    }));
  }
  // priority: applications that accept two IdPs first (they can be added to Entra and tested with Okta still live), then readiness
  rows.sort((x, y) => (y.coexistence.rank - x.coexistence.rank) || (y.readiness ? y.readiness.score : -1) - (x.readiness ? x.readiness.score : -1) || String(x.label).localeCompare(String(y.label)));
  return { generatedAt: nowIso(), roles: ctx.roles, graphError: ctx.graphError, write: ctx.write, okta: { login: ctx.okta.login, canWrite: ctx.okta.canWriteOkta }, rows,
    ordering: 'coexistence rank (accepts two IdPs first), then readiness score, then name',
    evidence: { days: evidence.days, entraMirror: evidence.mirror, oktaUsageChecked: evidence.okta.size } };
}

/** The one next action for a row. After staging the row is STAGED in Entra, not done: the Entra side was written and read
    back, the application side (owner) may still be pending; a recorded repoint is history; Verified needs the
    tested sign-in on the work item. `extra` = { workState, vendorRepointed }. */
function actionFor(as, mig, extra = {}) {
  const ws = extra.workState || null; const rp = extra.vendorRepointed || null; const migId = mig ? mig.id : null;
  if (ws === 'retired') return { code: 'done', label: 'Retired in Okta', stage: { entra: 'confirmed', app: 'verified' }, migrationId: migId };
  if (ws === 'verified') return { code: 'done', label: 'Verified — sign-in through Entra recorded', stage: { entra: 'confirmed', app: 'verified' }, migrationId: migId };
  const done = alreadyMigrated(as, extra);
  if (done && done.kind === 'recorded') return { code: 'done', label: done.label, stage: { entra: done.entraId ? 'recorded' : 'unknown', app: done.signInTested ? 'recorded' : 'unknown' }, migrationId: migId, recorded: { by: done.by, at: done.at, note: done.note, entraId: done.entraId, entraName: done.entraName, signInTested: done.signInTested }, note: 'Recorded by hand — history, not verification. Stage in Entra is hidden so nobody creates a second Entra application; clear the record under Already migrated if it is wrong. Record the tested sign-in on the work item to make it Verified.' };
  if (mig && ['running'].includes(mig.status)) return { code: 'follow', label: 'Running…', migrationId: mig.id };
  if (mig && (mig.status === 'succeeded' || mig.status === 'warnings')) {
    const ok = mig.status === 'succeeded'; const entra = ok ? 'confirmed' : 'warnings'; const appWork = as.ownerAction.length > 0;
    if (appWork && !rp) return { code: 'staged', label: ok ? 'Staged in Entra · application side pending' : 'Staged with warnings — review · application side pending', stage: { entra, app: 'pending' }, migrationId: mig.id,
      note: 'Application side still to do: ' + as.ownerAction.join('; ') + '. Record "Application repointed" on the Application side step when the owner has done it, then validate a sign-in.' };
    if (appWork && rp) return { code: 'validate', label: (ok ? 'Staged in Entra' : 'Staged with warnings') + ' · application repointed (recorded ' + dOnly(rp.at) + ') · validate sign-in', stage: { entra, app: 'recorded' }, migrationId: mig.id,
      note: 'Recorded by ' + (rp.by || 'a person') + (rp.note ? ': ' + rp.note : '') + ' — history, not verification. A tested sign-in through Entra is what turns this into Verified.' };
    return { code: 'validate', label: ok ? 'Staged in Entra · validate sign-in' : 'Staged with warnings — review · validate sign-in', stage: { entra, app: 'none' }, migrationId: mig.id };
  }
  if (mig && mig.status === 'failed') return { code: 'recover', label: 'Failed — review and roll back', migrationId: mig.id };
  if (done && done.kind === 'evidence') return { code: 'confirm', label: 'Already migrated — evidence · confirm', stage: { entra: 'evidence', app: 'unknown' }, migrationId: migId, note: done.detail + ' Stage in Entra is hidden: it would create a second Entra application. Mark as migrated (or confirm the match and record the tested sign-in).' };
  if (as.classification === 'unsupported') return { code: 'none', label: 'Not supported (see why)' };
  if (as.classification === 'manual') return { code: 'manual', label: as.protocol && as.protocol.switch && as.protocol.switch.shape === 'vendor_consent' ? 'Application side — vendor consent (not automated here)' : 'Manual migration — open plan', caution: as.caution || null };
  if (as.classification === 'blocked_info') return { code: 'fix', label: 'Provide missing information' };
  if (as.stops.some((s) => s.severity === 'stop')) return { code: 'resolve', label: 'Resolve blocker' };
  const caution = as.caution ? { level: as.caution.level, label: as.caution.label, detail: as.caution.detail } : null;
  if (as.push.possible && !as.push.blockedBy.length) return { code: 'migrate', label: 'Stage in Entra', caution, note: (as.push.handoffs || []).length ? (as.push.handoffs.length === 1 ? '1 step' : as.push.handoffs.length + ' steps') + ' handed off (needs ' + [...new Set(as.push.handoffs.map((h) => h.missing))].join(', ') + ')' : null };
  if (as.push.possible) return { code: 'preflight', label: 'Pre-flight (staging not yet enabled: needs ' + as.push.blockedBy[0] + ')', caution };
  return { code: 'plan', label: 'Open plan' };
}

/** The automation-coverage metric (spec §13), from the assessed queue. */
async function coverage() {
  const q = await queue({ includeInactive: false });
  const rows = q.rows;
  const scanned = rows.filter((r) => r.assessed);
  const by = (k) => scanned.filter((r) => r.classification === k).length;
  const stepTotals = scanned.reduce((a, r) => { a.total += r.automation.total; a.auto += r.automation.auto; a.approval += r.automation.approval; a.manual += r.automation.manual; a.unsupported += r.automation.unsupported; a.runnable += r.automation.runnableNow; return a; }, { total: 0, auto: 0, approval: 0, manual: 0, unsupported: 0, runnable: 0 });
  const automatable = by('fully') + by('mostly');
  return { write: q.write,
    generatedAt: q.generatedAt, roles: q.roles,
    apps: { active: rows.length, scanned: scanned.length, unscanned: rows.length - scanned.length },
    classification: { fully: by('fully'), mostly: by('mostly'), partially: by('partially'), manual: by('manual'), unsupported: by('unsupported'), blockedInfo: by('blocked_info') },
    appsAutomatable: { count: automatable, pct: scanned.length ? Math.round(100 * automatable / scanned.length) : null, basis: 'active applications whose Entra-side steps are all automatic (fully) or automatic plus the owner repointing the app (mostly), out of ' + scanned.length + ' scanned' },
    steps: Object.assign(stepTotals, { pctAutomatable: stepTotals.total ? Math.round(100 * (stepTotals.auto + stepTotals.approval) / stepTotals.total) : null, pctRunnableNow: stepTotals.total ? Math.round(100 * stepTotals.runnable / stepTotals.total) : null }),
    readiness: { ready: scanned.filter((r) => r.readiness.status === 'ready').length, review: scanned.filter((r) => r.readiness.status === 'review').length, manual: scanned.filter((r) => r.readiness.status === 'manual').length, blocked: scanned.filter((r) => r.readiness.status === 'blocked').length },
    coexistence: (() => { const by = (k) => rows.filter((r) => r.coexistence && r.coexistence.level === k).length; const c = { proven: by('proven'), entraActive: by('entra_active'), configured: by('configured'), recorded: by('recorded'), documented: by('documented'), single: by('single'), unknown: by('unknown') };
      c.priority = c.proven + c.entraActive + c.configured + c.recorded + c.documented;
      c.basis = 'active applications; tenant evidence = a confirmed or identifier-matched Entra app that is enabled with an SSO mode, plus mirrored Entra sign-ins (' + q.evidence.days + ' days) and, when checked, Okta System Log SSO events; vendor = documented support (not tenant-verified); recorded = technician answer';
      c.evidence = q.evidence; return c; })(),
    guides: { written: rows.filter((r) => r.coexistence && r.coexistence.guide).length, notWritten: rows.filter((r) => !(r.coexistence && r.coexistence.guide)).length, catalog: VG.list().length },
    push: { possibleNow: scanned.filter((r) => r.push.possible && !r.push.blockedBy.length).length, blockedByPermission: scanned.filter((r) => r.push.possible && r.push.blockedBy.length).length, blockedByConsent: scanned.filter((r) => r.push.possible && r.push.blockedBy.length).length /* alias, same number */, withHandoffs: scanned.filter((r) => r.push.possible && !r.push.blockedBy.length && (r.push.handoffs || []).length).length, missing: [...new Set(scanned.flatMap((r) => r.push.blockedBy))] },
  };
}

Object.assign(module.exports, { LANE, LANE_LABEL, annotateLanes, laneCounts, NON_GALLERY_TEMPLATE, recommendProtocol, policyMappingRows, assessApp, automationSteps, context, assessment, queue, coverage, latestMigrations,
  SSO_METHODS, INPUT_FIELDS, sanitizeInputs, applyInputs, inputsNeeded, inputsSummary, oidcEvidence, oidcSupport, entraProto, resolveTarget, appSide, twinKey, migratedFor, migratedContext, loadMigratedMarks, alreadyMigrated, gateAlreadyMigrated, actionFor });
