/**
 * oem-v2-model.js — OEM v2 domain model (DESIGN.md section 2).
 *
 * PURE: no database, no network, no environment. The only dependency is `crypto` (plan hashes).
 * Everything the routes, the store and the page fixtures agree on lives here: protocol
 * normalisation, per-protocol stage profiles, the migration plan and its hash, the public Entra
 * values, vendor instruction templates, verification check sets and verdicts, the Live-eligibility
 * predicate, the one dominant CTA per application, activity grouping, evidence dedupe and the
 * per-source status.
 *
 * Hard rule 2: nothing in this module ever produces a secret. `assertNoSecrets` refuses any config
 * carrying a secret-looking key, `entraValues` filters its own output through the same regex, and
 * vendor instructions carry only public values (URLs, entity ids, app ids, thumbprints).
 */
'use strict';

const crypto = require('crypto');

/* ------------------------------------------------------------------ secrets */

/** Keys that are never stored, displayed or logged (hard rule 2). */
const SECRET_KEY_RE = /secret|password|passwd|private_?key|cookie|mfa|otp|token/i;

/**
 * secrets-4: value patterns that are refused wherever free text is stored (notes, reasons, config values).
 * Deliberately narrow (fix-decisions): PEM private-key blocks, JWT shape, and key=value pairs whose key is a
 * credential name. NO high-entropy rule — SAML signing certificates, thumbprints and base64 metadata are
 * legitimate long tokens and must pass.
 */
const SECRET_TEXT_PATTERNS = [
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, what: 'a PEM private-key block' },
  { re: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, what: 'a JWT' },
  { re: /(?:^|[?&;,\s"'({\[])(?:client_secret|password|passwd|access_token|refresh_token|api_key|apikey)\s*[=:]\s*["']?[^\s&"',;)}\]]+/i, what: 'a credential value (key=value)' },
];

/** secrets-4: what in `str` looks like a secret value, or null. */
function secretTextHit(str) {
  if (str === null || str === undefined) return null;
  const s = String(str);
  if (!s) return null;
  for (const p of SECRET_TEXT_PATTERNS) if (p.re.test(s)) return p.what;
  return null;
}

/**
 * secrets-4: throws {status:400, error:'secrets are never stored', why} when a free-text input (note, reason,
 * attestation field) contains a PEM private key, a JWT or a credential key=value pair. Returns true otherwise.
 * `label` names the input in the message.
 */
function assertNoSecretText(str, label) {
  const hit = secretTextHit(str);
  if (!hit) return true;
  const err = new Error('secrets are never stored');
  err.status = 400; err.error = 'secrets are never stored';
  err.why = 'The ' + (label || 'text') + ' contains ' + hit + '. Client secrets, passwords, private keys and tokens are established outside CorpIT and are never stored here; remove it and try again.';
  throw err;
}

/**
 * Throws {status:400, error:'secrets are never stored', why} when `config` carries, at any depth,
 * a key matching SECRET_KEY_RE, or (secrets-4) a string VALUE that matches SECRET_TEXT_PATTERNS.
 * Arrays are walked; cycles are tolerated.
 */
function assertNoSecrets(config) {
  const seen = new Set();
  const walk = (v, path) => {
    if (typeof v === 'string') {
      const hit = secretTextHit(v);
      if (hit) {
        const err = new Error('secrets are never stored');
        err.status = 400; err.error = 'secrets are never stored';
        err.why = 'The value of "' + (path || 'input') + '" contains ' + hit + '. Client secrets, passwords, private keys and tokens are established outside CorpIT and are never stored here.';
        throw err;
      }
      return;
    }
    if (!v || typeof v !== 'object') return;
    if (seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) { v.forEach((x, i) => walk(x, path + '[' + i + ']')); return; }
    for (const k of Object.keys(v)) {
      if (SECRET_KEY_RE.test(k)) {
        const err = new Error('secrets are never stored');
        err.status = 400; err.error = 'secrets are never stored';
        err.why = 'The field "' + (path ? path + '.' : '') + k + '" looks like a secret. Client secrets, passwords, private keys, cookies, MFA codes and tokens are established outside CorpIT and are never stored here.';
        throw err;
      }
      walk(v[k], path ? path + '.' + k : k);
    }
  };
  walk(config, '');
  return true;
}

/** Deep copy of an object with every secret-looking key removed (defensive filter for outputs). */
function stripSecrets(v) {
  if (Array.isArray(v)) return v.map(stripSecrets);
  if (!v || typeof v !== 'object') return v;
  const out = {};
  for (const k of Object.keys(v)) { if (!SECRET_KEY_RE.test(k)) out[k] = stripSecrets(v[k]); }
  return out;
}

/* ---------------------------------------------------------------- protocols */

const PROTOCOLS = ['saml2', 'oidc', 'ws_fed', 'bookmark', 'swa_password', 'auto_login', 'header_based', 'scim_only', 'unknown_custom'];

// NOTE: bookmark / swa_password / auto_login labels and copy must never contain "SAML" (bug 6).
const PROTOCOL_LABEL = {
  saml2: 'SAML 2.0',
  oidc: 'OpenID Connect',
  ws_fed: 'WS-Federation',
  bookmark: 'Bookmark',
  swa_password: 'SWA (password)',
  auto_login: 'Auto-login',
  header_based: 'Header-based / custom',
  scim_only: 'SCIM provisioning only',
  unknown_custom: 'Unknown / custom',
};

const PROVISIONING_FEATURES = ['PUSH_NEW_USERS', 'IMPORT_NEW_USERS'];

/**
 * normalizeProtocol({signOnMode, name, features, settings}) -> one of PROTOCOLS.
 * Accepts a bare signOnMode string too. Never guesses: anything unrecognised is unknown_custom.
 */
function normalizeProtocol(app) {
  if (typeof app === 'string') app = { signOnMode: app };
  app = app || {};
  const mode = String(app.signOnMode || '').trim().toUpperCase();
  const features = Array.isArray(app.features) ? app.features.map((f) => String(f).toUpperCase()) : [];
  const name = String(app.name || '') + ' ' + String(app.label || '');
  if (!mode && features.some((f) => PROVISIONING_FEATURES.includes(f))) return 'scim_only';
  switch (mode) {
    case 'SAML_2_0': return 'saml2';
    case 'OPENID_CONNECT': return 'oidc';
    case 'WS_FEDERATION': return 'ws_fed';
    case 'BOOKMARK': return 'bookmark';
    case 'BROWSER_PLUGIN':
    case 'SECURE_PASSWORD_STORE':
    case 'BASIC_AUTH': return 'swa_password';
    case 'AUTO_LOGIN': return 'auto_login';
    default: break;
  }
  if (/header|iis|kerberos/i.test(name)) return 'header_based';
  return 'unknown_custom';
}

/* ----------------------------------------------------------- stage profiles */

const STAGE_KEYS = ['discover', 'match', 'configure_entra', 'vendor_setup', 'verify', 'live'];
const STAGE_LABEL = { discover: 'Discover', match: 'Match', configure_entra: 'Configure Entra', vendor_setup: 'Vendor setup', verify: 'Verify', live: 'Live approval' };

const NA = {
  bookmark_vendor: 'A bookmark has no vendor SSO side: it is a launcher, not an authenticator. Nothing to configure at the vendor.',
  swa_vendor: 'No vendor SSO side. The owner action is that users enter their credentials once in the My Apps browser extension; password material never migrates automatically.',
  header_configure: 'Header-based sign-on needs Entra application proxy, which is not automated from this page. Stop here and hand off to the owner and a technician with a discovery checklist.',
  header_after: 'Not reachable until the application proxy is configured outside this page.',
  unknown_configure: 'The sign-on method is not recognised. This page never guesses a protocol to unlock the wizard; complete the discovery checklist first.',
  unknown_after: 'Not reachable until the sign-on method is identified.',
};

const PROFILE_DEF = {
  saml2: { na: {}, why: { configure_entra: 'Enterprise application, identifier and reply URLs, NameID and claims, signing certificate, pilot assignment.', vendor_setup: 'The application owner enters the Entra Login URL and Entity ID and uploads the signing certificate or metadata.' },
    verification: ['entra_exists', 'entra_enabled', 'sso_mode', 'reply_or_redirect', 'identifier', 'assignments', 'signins_via_entra', 'okta_status'],
    rollback: 'Entra: disable (accountEnabled=false) or delete only the objects this revision created; the vendor keeps its Okta configuration until the owner removes it; Okta stays active until Retire Okta.', entraWrites: true },
  oidc: { na: {}, why: { configure_entra: 'App registration and service principal, redirect URIs, claims and scopes, pilot assignment. Client credentials are established outside CorpIT and never stored.', vendor_setup: 'The application owner enters the tenant/issuer, client ID and redirect URI in the vendor console and establishes credentials there.' },
    verification: ['entra_exists', 'entra_enabled', 'sso_mode', 'reply_or_redirect', 'identifier', 'assignments', 'signins_via_entra', 'okta_status'],
    rollback: 'Entra: disable or delete only the app registration and service principal this revision created; the vendor keeps its Okta configuration until the owner removes it; Okta stays active until Retire Okta.', entraWrites: true },
  ws_fed: { na: {}, why: { configure_entra: 'Enterprise application, realm and reply URL, claims, pilot assignment.', vendor_setup: 'The application owner enters the passive endpoint, realm and metadata in the vendor console.' },
    verification: ['entra_exists', 'entra_enabled', 'sso_mode', 'reply_or_redirect', 'identifier', 'assignments', 'signins_via_entra', 'okta_status'],
    rollback: 'Entra: disable or delete only the objects this revision created; the vendor keeps its Okta configuration until the owner removes it; Okta stays active until Retire Okta.', entraWrites: true },
  bookmark: { na: { vendor_setup: NA.bookmark_vendor }, why: { configure_entra: 'A linked (bookmark) application in Entra pointing at the same destination URL, plus pilot assignment.', verify: 'The destination URL loads and the sign-in system reached after the redirect is recorded. Claims and provisioning do not apply.' },
    verification: ['entra_exists', 'linked_url', 'assignments'],
    rollback: 'Remove the Entra bookmark; the Okta bookmark is untouched until Retire Okta. Retirement may keep a bookmark that points at Entra; the page says so explicitly.', entraWrites: true },
  swa_password: { na: { vendor_setup: NA.swa_vendor }, why: { configure_entra: 'A password-based single sign-on application in Entra with pilot assignment. This is a business decision: Entra password-based sign-on, vendor federation, or retire.', verify: 'Password-based mode is set, users are assigned and the browser extension is ready.' },
    verification: ['entra_exists', 'password_mode', 'assignments'],
    rollback: 'Remove the Entra password-based application; users keep their Okta credentials until Retire Okta. No password material is moved by this page.', entraWrites: true },
  auto_login: { na: { vendor_setup: NA.swa_vendor }, why: { configure_entra: 'A password-based single sign-on application in Entra with pilot assignment.', verify: 'Password-based mode is set, users are assigned and the browser extension is ready.' },
    verification: ['entra_exists', 'password_mode', 'assignments'],
    rollback: 'Remove the Entra password-based application; users keep their Okta credentials until Retire Okta. No password material is moved by this page.', entraWrites: true },
  header_based: { na: { configure_entra: NA.header_configure, vendor_setup: NA.header_after, verify: NA.header_after, live: NA.header_after }, why: {},
    verification: [], rollback: 'Nothing is written by this page for header-based applications; there is nothing to roll back.', entraWrites: false },
  scim_only: { na: {}, why: { configure_entra: 'Provisioning only: the Entra provisioning configuration for this application. There is no sign-on to configure.', vendor_setup: 'The application owner creates the SCIM endpoint and its credential in the vendor console and enters them in Entra; the credential is never stored here.', verify: 'The Entra provisioning job runs and reports its cycle.' },
    verification: ['entra_exists', 'entra_enabled', 'assignments', 'provisioning', 'okta_status'],
    rollback: 'Stop the Entra provisioning job; Okta provisioning stays untouched until Retire Okta.', entraWrites: true },
  unknown_custom: { na: { configure_entra: NA.unknown_configure, vendor_setup: NA.unknown_after, verify: NA.unknown_after, live: NA.unknown_after }, why: {},
    verification: [], rollback: 'Nothing is written by this page for an unrecognised sign-on method; there is nothing to roll back.', entraWrites: false },
};

/**
 * protocolProfile(protocol) -> { protocol, label, stages:[{key,label,applicable,why}], verification:[keys], rollback, entraWrites }.
 */
/* f14: an adopted revision (the Entra application was already configured and in use before this page touched it) has
   no Configure Entra write and no vendor step; verification drops the two checks that compare a planned value with Entra
   (there is no planned value — the configuration IS what Entra has). */
const ADOPT_STAGE = {
  configure_entra: 'Already configured in Entra. This revision adopts the existing configuration as-is; nothing is written.',
  vendor_setup: 'Not needed for an adopted configuration: verification checks that sign-ins already flow through Entra, which is the vendor trusting it.',
};
const ADOPT_DROPPED_CHECKS = ['reply_or_redirect', 'identifier'];
/* f15: an adopted revision is verified on what adoption relied on — the application still exists, is still enabled, still
   has the sign-on mode that was adopted, is still assigned, and Okta's status — whatever the base profile measures
   (the bookmark and password profiles measure none of enabled / mode / Okta status on their own). */
const ADOPT_ALWAYS_CHECKS = ['entra_exists', 'entra_enabled', 'sso_mode', 'assignments', 'okta_status'];
function protocolProfile(protocol, opts) {
  const p = PROTOCOLS.includes(protocol) ? protocol : 'unknown_custom';
  const d = PROFILE_DEF[p];
  const adopt = !!(opts && opts.adopt);
  const stages = STAGE_KEYS.map((key) => {
    const na = d.na[key];
    if (adopt && key === 'configure_entra') return { key, label: STAGE_LABEL[key], applicable: true, why: ADOPT_STAGE.configure_entra };
    if (adopt && key === 'vendor_setup') return { key, label: STAGE_LABEL[key], applicable: false, why: ADOPT_STAGE.vendor_setup };
    return { key, label: STAGE_LABEL[key], applicable: !na, why: na || d.why[key] || '' };
  });
  const verification = adopt ? CHECK_KEYS.filter((k) => !ADOPT_DROPPED_CHECKS.includes(k) && (ADOPT_ALWAYS_CHECKS.includes(k) || d.verification.includes(k))) : d.verification.slice();
  return { protocol: p, label: PROTOCOL_LABEL[p], stages, verification, rollback: adopt ? 'Nothing was written by this revision; there is nothing to roll back in Entra. Okta stays active until Retire Okta.' : d.rollback, entraWrites: adopt ? false : !!d.entraWrites, adopt };
}

/* ------------------------------------------------------------ plan + hash */

/** Deterministic JSON: object keys sorted at every depth; undefined -> null. */
function stableStringify(v) {
  if (v === undefined) return 'null';
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(v[k])).join(',') + '}';
}

function planHash(obj) { return crypto.createHash('sha256').update(stableStringify(obj)).digest('hex'); }

const S = (key, label, side, auto, detail) => ({ key, label, side, auto, detail });

function planSteps(protocol, ctx) {
  const c = ctx || {};
  const cfg = c.config || {};
  const sourceInventory = cfg._sourceInventory || {};
  if (protocol === 'saml2' && cfg.samlEndpointUpdate === true) return [
    S('adopt_target', 'Keep the prepared Entra application', 'entra', true, 'Recheck the selected application and the signing certificate already given to the vendor.'),
    S('redirect_uris', 'Apply the vendor Audience and ACS URLs', 'entra', true, 'Update only the Identifier and Reply URLs on this application.'),
    S('configure_saml', 'Apply the vendor relay state', 'entra', true, 'Keep the signing certificate, claims and assignments unchanged.'),
    S('verify_vendor_values', 'Verify the saved values', 'entra', true, 'Read back the URLs and relay state before testing sign-in.')
  ];
  const provisioning = sourceInventory.provisioning || {};
  const createNew = !!(c.createNew || cfg.createNew || !c.entraId);
  const appName = c.displayName || cfg.displayName || 'the destination application';
  const first = createNew
    ? S('create_app', 'Create enterprise application', 'entra', true, 'Create "' + appName + '" in Entra.')
    : S('adopt_app', 'Adopt the matched enterprise application', 'entra', true, 'Use the matched Entra service principal ' + (c.entraId || '') + '; nothing is created.');
  const pilotCount = [].concat(cfg.pilotUserUpns || [], cfg.pilotGroupIds || []).filter(Boolean).length;
  const pilot = S('assign_pilot', 'Assign isolated pilot', 'entra', true, 'Assign only ' + pilotCount + ' named pilot' + (pilotCount === 1 ? '' : 's') + ' to the assignment-required Entra application. Production groups and direct users wait until Live sign-off.');
  const rollout = S('expand_assignments', 'Expand production assignments', 'entra', true, 'After the pilot is verified and signed off Live, copy and live-verify the approved Okta groups and direct users on this same Entra application before any Okta tile assignment moves.');
  const retire = S('retire_okta', 'Retire Okta', 'platform', false, 'Only after Live sign-off: deactivate the Okta application (separate confirmation with its own preview and rollback).');
  const provisioningLane = provisioning.enabled ? [
    S('inventory_provisioning', 'Review Okta provisioning mappings', 'platform', true,
      (provisioning.inventoryComplete ? 'Inventory complete. ' : 'Inventory incomplete; rescan after granting the required Okta API reads. ') +
      Number(provisioning.outbound || 0) + ' outbound, ' + Number(provisioning.inbound || 0) + ' inbound and ' +
      Number(provisioning.groupPush || 0) + ' Group Push mapping(s) recorded.'),
    S('confirm_source_authority', 'Confirm the provisioning source of authority', 'owner', false,
      provisioning.specialistRequired
        ? 'Specialist review required: imports, profile mastering, password push or delegated authentication cannot be translated as ordinary outbound SCIM.'
        : 'Entra will become the outbound provisioning source after the isolated pilot succeeds.'),
    S('vendor_scim', 'Create a new vendor SCIM endpoint and credential', 'vendor', false,
      'The owner creates a credential for Entra. Okta credentials are never exported, reused or stored here.'),
    S('configure_provisioning', 'Configure Entra provisioning and attribute mappings', 'entra', false,
      'Enter the vendor credential directly in Entra, rebuild the recorded user and group mappings, and scope only an isolated pilot population.'),
    S('test_provisioning', 'Verify a provisioning pilot cycle', 'owner', false,
      'Require an Active Entra job with a successful export. Confirm create, update, deactivate and group membership behavior at the vendor.'),
    S('cutover_provisioning', 'Cut over provisioning without two writers', 'platform', false,
      'Stop Okta provisioning before expanding the Entra scope. Rollback stops Entra first, then resumes Okta with its assignments unchanged.'),
  ] : [];
  /* f14: adopted configuration — one step that changes nothing (auto === null: neither automatic nor manual), then the
     verification the owner takes part in, then retirement. Server-owned like createNew: the flag reaches here only from
     the store's cfg, which only the adopt route sets. */
  if (cfg.adopt === true) {
    const a = cfg.adopted || {};
    const users = a.users === undefined || a.users === null ? null : Number(a.users);
    return [
      S('adopt_existing', 'Keep the existing Entra configuration', 'entra', null, 'Keep "' + (a.displayName || appName) + '" exactly as it is in Entra today (' + (a.ssoModeLabel || PROTOCOL_LABEL[protocol] || protocol) + (users !== null ? ', ' + users + ' user' + (users === 1 ? '' : 's') + ' assigned' : '') + '). Nothing is written to Entra and nothing changes at the vendor.'),
      ...provisioningLane,
      S('test', 'Verify the existing sign-in', 'owner', false, 'Technician runs Test and verify against the configuration as it is; the owner confirms a user signs in through Entra.'),
      retire,
    ];
  }
  switch (protocol) {
    case 'saml2': return [
      first,
      S('configure_saml_urls', 'Configure Entity ID and Reply URL', 'entra', true, 'Identifier (Entity ID) and Reply URL (ACS) from the current Okta values or the draft.'),
      S('configure_claims', 'Copy NameID and attribute claims', 'entra', true, 'NameID format and attribute claims mirrored from Okta.'),
      S('signing_certificate', 'Provision the signing certificate', 'entra', true, 'Entra issues the SAML signing certificate; only its thumbprint and expiry are recorded.'),
      pilot,
      S('vendor_sso', 'Configure vendor SSO settings', 'vendor', false, 'The application owner enters the Entra Login URL and Entity ID and uploads the signing certificate or metadata in the vendor console.'),
      ...provisioningLane,
      S('test', 'Test sign-in and claims', 'owner', false, 'Technician runs Test and verify; the owner signs in through Entra and confirms the application worked.'),
      rollout,
      retire,
    ];
    case 'oidc': return [
      createNew ? S('create_registration', 'Create app registration and service principal', 'entra', true, 'Create the app registration "' + appName + '" and its service principal.') : first,
      S('redirect_uris', 'Configure redirect URIs and platform', 'entra', true, 'Redirect and post-logout URIs from the current Okta values or the draft.'),
      S('claims_scopes', 'Configure claims, scopes and consent', 'entra', true, 'Optional claims and API scopes mirrored from Okta; admin consent where needed.'),
      S('credentials', 'Establish client credentials outside CorpIT', 'owner', false, 'The owner creates the certificate or client credential in the vendor flow; nothing secret is stored or displayed here.'),
      pilot,
      S('vendor_oidc', 'Configure the vendor OIDC settings', 'vendor', false, 'The application owner enters the tenant/issuer, client ID and redirect URI in the vendor console.'),
      ...provisioningLane,
      S('test', 'Test sign-in and claims', 'owner', false, 'Technician runs Test and verify; the owner signs in through Entra and confirms the application worked.'),
      rollout,
      retire,
    ];
    case 'ws_fed': return [
      first,
      S('realm_reply', 'Configure realm and reply URL', 'entra', true, 'Realm (identifier) and reply URL from the current Okta values or the draft.'),
      S('configure_claims', 'Copy attribute claims', 'entra', true, 'Claims mirrored from Okta.'),
      pilot,
      S('vendor_wsfed', 'Configure the vendor WS-Federation settings', 'vendor', false, 'The application owner enters the passive endpoint, realm and metadata in the vendor console.'),
      ...provisioningLane,
      S('test', 'Test sign-in and claims', 'owner', false, 'Technician runs Test and verify; the owner signs in through Entra and confirms the application worked.'),
      rollout,
      retire,
    ];
    case 'bookmark': return [
      S('create_linked_app', 'Create a linked application', 'entra', true, 'A bookmark in Entra pointing at ' + (cfg.url || 'the same destination URL') + '. It launches the destination; it does not authenticate users.'),
      pilot,
      S('test', 'Open the bookmark and record where it lands', 'owner', false, 'The owner opens the bookmark from My Apps and confirms the destination loads and which sign-in system it reaches.'),
      rollout,
      S('retire_okta', 'Retire the Okta bookmark', 'platform', false, 'After Live sign-off: deactivate the Okta bookmark. The Entra bookmark keeps pointing at the same URL.'),
    ];
    case 'swa_password':
    case 'auto_login': return [
      S('create_password_app', 'Create a password-based sign-on application', 'entra', true, 'An Entra password-based sign-on application for ' + appName + '.'),
      pilot,
      S('owner_credentials', 'Users enter their credentials once', 'owner', false, 'Users enter their own credentials in the My Apps browser extension. Password material never migrates automatically.'),
      ...provisioningLane,
      S('test', 'Test the browser-extension sign-in', 'owner', false, 'The owner confirms a pilot user reaches the application through My Apps.'),
      rollout,
      retire,
    ];
    case 'scim_only': return [
      S('inventory_provisioning', 'Review Okta provisioning mappings', 'platform', true,
        (provisioning.inventoryComplete ? 'Inventory complete. ' : 'Inventory incomplete; rescan after granting the required Okta API reads. ') + Number(provisioning.outbound || 0) + ' outbound, ' + Number(provisioning.inbound || 0) + ' inbound and ' + Number(provisioning.groupPush || 0) + ' Group Push mapping(s) recorded.'),
      S('confirm_source_authority', 'Confirm the provisioning source of authority', 'owner', false,
        provisioning.specialistRequired ? 'Specialist review required before Entra provisioning can be configured.' : 'Entra becomes the outbound source only after the pilot succeeds.'),
      S('vendor_scim', 'Create a new vendor SCIM endpoint and credential', 'vendor', false, 'The owner creates a credential for Entra. Okta credentials are never exported, reused or stored here.'),
      S('configure_provisioning', 'Configure Entra provisioning and attribute mappings', 'entra', false, 'Enter the vendor credential directly in Entra and rebuild the recorded mappings for ' + appName + '.'),
      S('start_provisioning', 'Start provisioning for the pilot scope', 'entra', false, 'Start only after Test connection passes and the pilot users or groups are scoped.'),
      S('test', 'Confirm create, update and deactivate behavior', 'owner', false, 'Technician reads the provisioning job; the owner confirms the pilot records at the vendor.'),
      S('retire_okta', 'Cut over from Okta provisioning', 'platform', false, 'After Live sign-off: stop Okta provisioning before expanding Entra scope. Rollback stops Entra first and resumes Okta.'),
    ];
    case 'header_based': return [
      S('discovery_checklist', 'Complete the discovery checklist', 'owner', false, 'Record the header names, the upstream host and who owns the proxy. Entra application proxy is not automated from this page.'),
      S('handoff', 'Hand off to the owner and a technician', 'platform', false, 'No Entra write is performed by this page for header-based applications.'),
    ];
    default: return [
      S('discovery_checklist', 'Identify the sign-on method', 'owner', false, 'Record how users actually sign in; this page never guesses a protocol to unlock the wizard.'),
      S('handoff', 'Hand off to the owner and a technician', 'platform', false, 'No Entra write is performed until the method is identified.'),
    ];
  }
}

/**
 * planFor(protocol, ctx) -> { protocol, steps:[{key,label,side,auto,detail}], hash }
 * hash = sha256(stableStringify({protocol, entraId, config, steps: keys+labels})).
 */
function planFor(protocol, ctx) {
  const p = PROTOCOLS.includes(protocol) ? protocol : 'unknown_custom';
  const c = ctx || {};
  const steps = planSteps(p, c);
  const hash = planHash({ protocol: p, entraId: c.entraId || null, config: stripSecrets(c.config || {}), steps: steps.map((s) => ({ key: s.key, label: s.label })) });
  return { protocol: p, steps, hash };
}

/* ------------------------------------------------------------ entra values */

function arr(v) {
  if (Array.isArray(v)) return v.slice();
  if (typeof v === 'string' && v.trim()) { try { const j = JSON.parse(v); if (Array.isArray(j)) return j; } catch (e) { /* not JSON */ } return [v]; }
  return [];
}
function pick(o, keys, dflt) {
  for (const k of keys) if (o && o[k] !== undefined && o[k] !== null && o[k] !== '') return o[k];
  return dflt;
}

/**
 * entraValues(protocol, {tenantId, appId, spObjectId, mirrorRow, spExtras}) -> public values only.
 * The result is filtered through SECRET_KEY_RE; a secret key can never appear.
 */
function entraValues(protocol, ctx) {
  const c = ctx || {};
  const tenant = c.tenantId || '<tenant-id>';
  const appId = c.appId || pick(c.mirrorRow, ['app_id', 'appId'], null) || '<app-id>';
  const row = c.mirrorRow || {};
  const extras = c.spExtras || {};
  const spObjectId = c.spObjectId || pick(row, ['id', 'object_id', 'sp_object_id', 'entra_id'], null);
  const base = 'https://login.microsoftonline.com/' + tenant;
  let out;
  switch (protocol) {
    case 'saml2':
      out = {
        entityId: 'https://sts.windows.net/' + tenant + '/',
        loginUrl: base + '/saml2',
        logoutUrl: base + '/saml2',
        metadataUrl: base + '/federationmetadata/2007-06/federationmetadata.xml?appid=' + appId,
        certificateThumbprint: pick(extras, ['certificateThumbprint', 'thumbprint', 'signing_thumbprint'], null) || pick(row, ['certificate_thumbprint', 'thumbprint'], null),
        certificateExpires: pick(extras, ['certificateExpires', 'certificate_expires', 'signing_expires'], null) || pick(row, ['certificate_expires'], null),
        replyUrls: arr(pick(extras, ['replyUrls', 'reply_urls'], null) || pick(row, ['reply_urls', 'replyUrls'], null)),
        identifierUris: arr(pick(extras, ['identifierUris', 'identifier_uris'], null) || pick(row, ['identifier_uris', 'identifierUris'], null)),
        appId, spObjectId,
      };
      break;
    case 'oidc':
      out = {
        authority: base + '/v2.0',
        issuer: base + '/v2.0',
        clientId: appId,
        discoveryUrl: base + '/v2.0/.well-known/openid-configuration',
        redirectUris: arr(pick(extras, ['redirectUris', 'redirect_uris'], null) || pick(row, ['redirect_uris', 'redirectUris', 'reply_urls'], null)),
        tenantId: tenant, spObjectId,
      };
      break;
    case 'ws_fed':
      out = {
        passiveEndpoint: base + '/wsfed',
        metadataUrl: base + '/federationmetadata/2007-06/federationmetadata.xml?appid=' + appId,
        realm: arr(pick(extras, ['identifierUris', 'identifier_uris'], null) || pick(row, ['identifier_uris', 'identifierUris'], null))[0] || null,
        appId, spObjectId,
      };
      break;
    case 'bookmark':
      out = { myAppsUrl: 'https://myapps.microsoft.com/?tenantid=' + tenant, destinationUrl: pick(extras, ['linkedUrl', 'linked_url', 'url'], null) || pick(row, ['linked_url', 'homepage', 'url'], null), spObjectId };
      break;
    case 'swa_password':
    case 'auto_login':
      out = { myAppsUrl: 'https://myapps.microsoft.com/?tenantid=' + tenant, note: 'Users enter their own credentials once in the My Apps browser extension; nothing is stored here.', spObjectId };
      break;
    case 'scim_only':
      out = { note: 'Provisioning credentials are created at the vendor and entered in Entra by the owner; this page holds none of them.', appId, spObjectId };
      break;
    default:
      out = { note: 'No Entra values: this sign-on method is not configured from this page.' };
  }
  return stripSecrets(out);
}

/* -------------------------------------------------------- vendor templates */

const DISCLAIMER = 'These instructions are generated from the current Entra revision; nothing here changes the vendor. Vendor setup is done by the application owner and is only verified by the Test and verify step.';

const F = (label, valueKey) => ({ label, valueKey });

const SAML_FIELDS = [F('Login URL', 'loginUrl'), F('Entity ID (Issuer)', 'entityId'), F('Logout URL', 'logoutUrl'), F('Federation metadata URL', 'metadataUrl'), F('Signing certificate thumbprint', 'certificateThumbprint'), F('Reply URL (ACS) configured in Entra', 'replyUrls'), F('Identifier configured in Entra', 'identifierUris')];
const OIDC_FIELDS = [F('Authority (tenant)', 'authority'), F('Issuer', 'issuer'), F('Client ID (application ID)', 'clientId'), F('OpenID discovery URL', 'discoveryUrl'), F('Redirect URIs configured in Entra', 'redirectUris')];
const WSFED_FIELDS = [F('Passive endpoint', 'passiveEndpoint'), F('Federation metadata URL', 'metadataUrl'), F('Realm', 'realm')];
const SCIM_FIELDS = [F('Entra application ID', 'appId'), F('Service principal object ID', 'spObjectId')];

// Derived from oem-vendor-guides.js GUIDES[0] (adobe, checkedAt 2026-09-10). Copied so this module stays pure.
const ADOBE_STEPS = [
  { title: 'Open the directory', detail: 'Admin Console > Settings > Identity > Directories. Select the federated directory, then Edit.' },
  { title: 'Add the identity provider', detail: 'In the directory details panel select "Add new IdP", choose "Microsoft Azure Active Directory", then Next.' },
  { title: 'Sign in and consent (Entra Global Administrator)', detail: 'Sign in with the Entra Global Administrator account and select Accept at the permission prompt so Adobe can create its application in the tenant. Adobe notes this profile authenticates with OpenID Connect; confirm the Username field in the Admin Console matches the UPN field in Entra.' },
  { title: 'Check the new profile', detail: 'The directory details now list a second profile. The existing Okta profile stays "In use"; nothing has changed for users yet.' },
  { title: 'Test before activating', detail: 'On the new profile select Test. Sign in with two to three active users from the directory and confirm the username in the assertion matches the existing Admin Console usernames. Share the test link with another administrator to validate on a different machine.' },
  { title: 'Activate', detail: 'Select Activate on the new profile. It shows "In use"; the directory now runs the Entra OIDC profile alongside the Okta SAML profile (two profiles of different types).' },
  { title: 'Retire Okta later', detail: 'Only after Entra sign-ins are seen (this page\'s Verify step reads the Entra sign-in log): remove the Okta SAML profile in the same panel, then deactivate the Okta app from this page\'s lifecycle action.' },
  { title: 'SAML alternative (only when the login field is not the UPN)', detail: 'Entra admin center > Entra ID > Enterprise apps > New application > gallery "Adobe Identity Management (SAML)" > Single sign-on > SAML. Basic SAML Configuration: Sign on URL https://adobe.com; Identifier (Entity ID) = the Adobe value https://federatedid-na1.services.adobe.com/federated/saml/metadata/alias/<CUSTOM_ID>; Reply URL = the ACS .../federated/saml/SSO/alias/<id>. Download the Federation Metadata XML, assign users. In the Admin Console: Add new IdP > Other SAML Providers > upload the metadata > Save. Adobe warns: create a new SAML application instead of editing the existing one, to prevent authentication downtime; and because two SAML profiles cannot coexist, Activate on this path replaces the Okta profile (hard cutover, plan the owner window).' },
];

const VENDOR_TEMPLATES = [
  {
    key: 'adobe', version: '2026-09-10', protocol: 'oidc', altProtocols: ['saml2'], match: [/\badobe\b/i], vendor: 'Adobe Admin Console (Creative Cloud / Document Cloud / Experience Cloud for enterprise)',
    title: 'Adobe Admin Console: add Microsoft Entra ID as an identity provider', generic: false,
    console: { name: 'Adobe Admin Console', url: 'https://adminconsole.adobe.com', path: 'Settings > Identity > Directories > select the federated directory > Edit > Add new IdP' },
    prerequisites: [
      'System administrator role in the Adobe Admin Console.',
      'An existing federated directory (the one Okta signs users into today); this flow adds a profile to it.',
      'Entra: a Global Administrator to sign in and accept the consent prompt; Adobe creates "Adobe Identity Management (OIDC)" under Enterprise apps. The SAML alternative needs only Cloud Application Administrator or Application Administrator.',
      'Users (or the group) assigned to the new Entra application before testing.',
      'The Admin Console Username must equal the Entra UPN for the OIDC profile; otherwise use the "Other SAML Providers" path.',
    ],
    fields: OIDC_FIELDS,
    steps: ADOBE_STEPS,
    ownerActions: ['Sign in to the Adobe Admin Console as a System administrator.', 'Add the Microsoft Azure Active Directory profile and accept the Entra consent as a Global Administrator (an expanded-permission grant; the administrator clicks it).', 'Test the new profile with two to three active users before Activate.', 'Activate the profile, then return to CorpIT and mark vendor setup ready for test.'],
    verify: ['A federated user signs in at adobe.com through Entra; the Verify step reads the Entra sign-in log for the Adobe application.', 'The username in the assertion matches the existing Admin Console usernames.'],
    errors: ['Two SAML profiles cannot coexist: on the SAML path, Activate replaces the Okta profile (hard cutover).', 'A directory that signs in with a field other than the Entra UPN cannot use the OIDC profile.'],
    sources: [
      { title: 'Adobe Enterprise: Change your authentication provider (updated Aug 3, 2026)', url: 'https://helpx.adobe.com/business/enterprise/directories-domains-access/directory-trusting/change-authentication-provider.html' },
      { title: 'Adobe Enterprise: Authenticate your users with Microsoft Entra ID (Sep 1, 2025)', url: 'https://helpx.adobe.com/business/enterprise/identity-sso/integrate-with-microsoft-entra/sso-setup-azure.html' },
      { title: 'Microsoft Learn: Configure Adobe Identity Management (SAML) for single sign-on with Microsoft Entra ID (ms.date 2025-03-25)', url: 'https://learn.microsoft.com/en-us/entra/identity/saas-apps/adobe-identity-management-tutorial' },
      { title: 'Adobe Enterprise: Configure SAML directory in Admin Console', url: 'https://helpx.adobe.com/business/enterprise/directories-domains-access/directories-and-domains/create-directory-for-saml-identity-providers.html' },
    ],
  },
  {
    key: 'generic_saml2', version: '1', protocol: 'saml2', vendor: null, title: 'Generic SAML 2.0 instructions (no vendor template)', generic: true,
    console: null,
    prerequisites: ['An administrator role in the vendor console that can edit single sign-on settings.', 'The Entra application exists and pilot users are assigned.'],
    fields: SAML_FIELDS,
    steps: [
      { title: 'Open the vendor single sign-on settings', detail: 'Sign in to the vendor administration console and open its SAML / single sign-on configuration. Record the console URL and the exact field names you find so a vendor template can be written.' },
      { title: 'Create or edit the SAML configuration', detail: 'Prefer a new configuration next to the existing Okta one when the vendor allows more than one identity provider.' },
      { title: 'Enter the Entra Login URL and Entity ID', detail: 'Paste the Login URL (sign-in / SSO URL) and the Entity ID (issuer) from the values below.' },
      { title: 'Upload the Entra signing certificate or metadata', detail: 'Download the federation metadata from the link below (public) or the signing certificate, and upload it where the vendor asks for the identity provider certificate.' },
      { title: 'Save, then return to CorpIT', detail: 'Save the vendor configuration and mark vendor setup ready for test. Nothing is verified until the Test and verify step passes.' },
    ],
    ownerActions: ['Record the vendor console URL and the field names discovered.', 'Enter the Entra values exactly as shown, using the Copy buttons.', 'Save and return to CorpIT to mark vendor setup ready for test.'],
    verify: ['A pilot user signs in through Entra and the application loads.', 'NameID and the expected attribute claims appear in the Entra sign-in log.'],
    errors: ['Reply URL mismatch: the ACS URL the vendor posts to must match the Reply URL configured in Entra.', 'Audience mismatch: the vendor Entity ID must match the Identifier configured in Entra.'],
    sources: [],
  },
  {
    key: 'generic_oidc', version: '1', protocol: 'oidc', vendor: null, title: 'Generic OpenID Connect instructions (no vendor template)', generic: true,
    console: null,
    prerequisites: ['An administrator role in the vendor console that can edit OpenID Connect settings.', 'The Entra app registration and service principal exist and pilot users are assigned.'],
    fields: OIDC_FIELDS,
    steps: [
      { title: 'Open the vendor OpenID Connect settings', detail: 'Sign in to the vendor administration console and open its OpenID Connect / identity provider configuration. Record the console URL and field names.' },
      { title: 'Enter the tenant, issuer and client ID', detail: 'Paste the authority or issuer and the client ID from the values below; the vendor may also accept the discovery URL.' },
      { title: 'Confirm the redirect URI', detail: 'The redirect URI the vendor shows must match one of the redirect URIs configured in Entra; if it differs, edit the draft in CorpIT.' },
      { title: 'Establish the client credential outside CorpIT', detail: 'Create the client credential or certificate in the Entra admin center and enter it in the vendor console yourself. CorpIT never displays or stores it.' },
      { title: 'Save, then return to CorpIT', detail: 'Save the vendor configuration and mark vendor setup ready for test.' },
    ],
    ownerActions: ['Record the vendor console URL and the field names discovered.', 'Enter the Entra values exactly as shown.', 'Create the client credential in the Entra admin center and enter it at the vendor; do not paste it anywhere in CorpIT.', 'Save and return to CorpIT to mark vendor setup ready for test.'],
    verify: ['A pilot user signs in through Entra and the application loads.', 'The sign-in appears in the Entra sign-in log for this client ID.'],
    errors: ['Redirect URI mismatch (AADSTS50011): the vendor redirect URI must be registered in Entra.', 'Consent required: an administrator grants consent for the requested scopes.'],
    sources: [],
  },
  {
    key: 'generic_ws_fed', version: '1', protocol: 'ws_fed', vendor: null, title: 'Generic WS-Federation instructions (no vendor template)', generic: true,
    console: null,
    prerequisites: ['An administrator role in the vendor console that can edit federation settings.', 'The Entra application exists and pilot users are assigned.'],
    fields: WSFED_FIELDS,
    steps: [
      { title: 'Open the vendor federation settings', detail: 'Sign in to the vendor administration console and open its WS-Federation / claims-based identity provider configuration. Record the console URL and field names.' },
      { title: 'Enter the passive endpoint and realm', detail: 'Paste the passive endpoint and the realm from the values below, or import the federation metadata URL if the vendor accepts it.' },
      { title: 'Confirm the reply URL', detail: 'The reply URL the vendor expects must match the one configured in Entra.' },
      { title: 'Save, then return to CorpIT', detail: 'Save the vendor configuration and mark vendor setup ready for test.' },
    ],
    ownerActions: ['Record the vendor console URL and the field names discovered.', 'Enter the Entra values exactly as shown.', 'Save and return to CorpIT to mark vendor setup ready for test.'],
    verify: ['A pilot user signs in through Entra and the application loads.', 'The expected claims appear in the Entra sign-in log.'],
    errors: ['Realm mismatch: the vendor realm must equal the identifier configured in Entra.'],
    sources: [],
  },
  {
    key: 'generic_scim', version: '1', protocol: 'scim_only', vendor: null, title: 'Generic SCIM provisioning instructions (no vendor template)', generic: true,
    console: null,
    prerequisites: ['An administrator role in the vendor console that can manage SCIM / user provisioning.', 'The Entra application exists.'],
    fields: SCIM_FIELDS,
    steps: [
      { title: 'Open the vendor provisioning settings', detail: 'Sign in to the vendor administration console and open its SCIM / user provisioning configuration. Record the console URL and field names.' },
      { title: 'Create the SCIM endpoint and credential at the vendor', detail: 'Generate the SCIM base URL and its bearer credential in the vendor console.' },
      { title: 'Enter them in Entra yourself', detail: 'In the Entra admin center, open the application > Provisioning and enter the tenant URL and the credential there. CorpIT never displays or stores the credential.' },
      { title: 'Save, then return to CorpIT', detail: 'Save and mark vendor setup ready for test; the Test and verify step reads the Entra provisioning job.' },
    ],
    ownerActions: ['Record the vendor console URL and the field names discovered.', 'Create the SCIM endpoint and credential at the vendor and enter them in the Entra admin center; do not paste the credential anywhere in CorpIT.', 'Return to CorpIT to mark vendor setup ready for test.'],
    verify: ['The Entra provisioning job completes a cycle without errors.', 'Pilot users appear at the vendor.'],
    errors: ['Test connection fails: the SCIM base URL or credential entered in Entra is wrong; re-enter them in the Entra admin center.'],
    sources: [],
  },
];

const GENERIC_FOR = { saml2: 'generic_saml2', oidc: 'generic_oidc', ws_fed: 'generic_ws_fed', scim_only: 'generic_scim' };

function templateFor(protocol, vendorKey) {
  if (vendorKey) {
    const t = VENDOR_TEMPLATES.find((x) => x.key === vendorKey && (x.protocol === protocol || (x.altProtocols || []).includes(protocol)));
    if (t) return t;
  }
  return VENDOR_TEMPLATES.find((x) => x.key === GENERIC_FOR[protocol]) || null;
}

/**
 * vendorKeyFor({vendorKey, name, label, destinationName}) -> the key of the non-generic vendor template that names this
 * application, or null. An explicit vendorKey that names a template wins; otherwise the Okta name/label and the Entra
 * destination name are tried against each template's `match` patterns (an Okta catalog name is often an org-specific
 * slug such as auction_adobe_1, so slug equality misses the vendor).
 */
function vendorKeyFor(ctx) {
  const c = ctx || {};
  if (c.vendorKey && VENDOR_TEMPLATES.some((t) => t.key === c.vendorKey && !t.generic)) return c.vendorKey;
  const hay = [c.name, c.label, c.destinationName].filter(Boolean).map(String);
  if (!hay.length) return null;
  const t = VENDOR_TEMPLATES.find((x) => !x.generic && (x.match || []).some((re) => hay.some((s) => re.test(s))));
  return t ? t.key : null;
}

/** The federation protocols a technician may always pick by hand (Entra enterprise apps support both); everything else
 *  is offered only when Okta uses it or a vendor template documents it. */
const MANUAL_PROTOCOLS = ['oidc', 'saml2'];
const MANUAL_WHY = 'Not documented for this vendor in CorpIT: pick it only if you will test it with the vendor.';

/* ------------------------------------------------------------- gallery */
/* The Entra application gallery lists SAML and OpenID Connect as SEPARATE templates per product ("Adobe Identity
   Management" and "Adobe Identity Management (OIDC)"). galleryStem() normalises a template or application name to
   the product words: lower-case, parentheticals and the protocol/SSO words dropped, punctuation collapsed. A
   product is looked up by its first two stem words (one when the second is a noise word such as "admin" or "prod"),
   so "Zscaler ZIdentity" finds every "zscaler zidentity …" template and nothing else. Integrations ("… for Teams",
   add-ins, bots) are never counted as the product's own template. Nothing here invents a template: a match is a row
   read from the gallery mirror (oem_gallery_template). */
const GALLERY_STRIP = /\([^()]*\)|\b(?:openid connect|open id connect|openid|oidc|saml ?2(?:\.0)?|saml|single sign[- ]?on|sso|by microsoft)\b/gi;
const GALLERY_NOISE = new Set(['admin', 'prod', 'qa', 'ci', 'uat', 'dev', 'cloud', 'portal', 'dashboard', 'console', 'new', 'scim', 'app', 'phone', 'enterprise', 'online', 'read', 'workflows', 'workflow', 'non']);
const GALLERY_INTEGRATION = /\bfor (?:microsoft |ms )?(?:teams|intune|office ?365|outlook|onedrive|sharepoint|m365)\b|\bteams\b|add-? ?in|\bbot\b/i;
const GALLERY_GENERIC = new Set(['smart', 'schedule', 'scheduler', 'portfolio', 'verification', 'flow', 'ldap', 'jenkins']);
/* Okta `name` keys that are not product names (custom apps "acme_app_1", the generic templates). */
const GALLERY_SKIP_KEY = /^[a-z0-9]+_.+_[0-9]+$/;
const GALLERY_SKIP_NAMES = new Set(['oidc_client', 'template_saml_2_0', 'template_swa', 'bookmark', 'template_wsfed', 'template_basic_auth', 'template_sps']);
function galleryStem(name) {
  return String(name || '').toLowerCase().replace(GALLERY_STRIP, ' ').replace(/[^a-z0-9]+/g, ' ').trim().replace(/\s+/g, ' ');
}
/* galleryPrefix(name) -> the lookup key for a product name, or null when the name says nothing about a product. */
function galleryPrefix(name) {
  const raw = String(name || '').trim();
  if (!raw || GALLERY_SKIP_NAMES.has(raw.toLowerCase()) || GALLERY_SKIP_KEY.test(raw.toLowerCase())) return null;
  const w = galleryStem(raw).split(' ').filter(Boolean);
  if (!w.length) return null;
  if (w.length >= 2 && !GALLERY_NOISE.has(w[1]) && w[1].length >= 3) return w[0] + ' ' + w[1];
  if (GALLERY_GENERIC.has(w[0]) || GALLERY_NOISE.has(w[0]) || w[0].length < 3) return null;   // a lone 'admin' / 'portal' would match half the gallery
  return w[0];
}
/* galleryPrefixes(names) -> the distinct prefixes for a set of names (Okta name, Okta label, Entra destination name). */
function galleryPrefixes(names) {
  const out = [];
  for (const n of Array.isArray(names) ? names : [names]) { const p = galleryPrefix(n); if (p && out.indexOf(p) < 0) out.push(p); }
  return out;
}
/* galleryUnder(prefix, stem, displayName) -> true when a gallery row is this product's own template. */
function galleryUnder(prefix, stem, displayName) {
  if (!prefix || !stem) return false;
  if (stem !== prefix && stem.indexOf(prefix + ' ') !== 0) return false;
  return !GALLERY_INTEGRATION.test(String(displayName || ''));
}
/**
 * galleryPick(names, rows) -> {prefixes, oidc:[{id,name}], saml:[{id,name}]}
 * rows = gallery mirror rows {id, display_name|name, modes ('saml,oidc,password' or an array), stem?}. The product's own
 * templates split by the SSO mode they carry; a template that carries both modes lands in both lists.
 */
function galleryPick(names, rows) {
  const prefixes = galleryPrefixes(names);
  const oidc = [], saml = [];
  const seen = new Set();
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!r) continue;
    const name = r.display_name || r.displayName || r.name || '';
    const stem = r.stem || galleryStem(name);
    if (!prefixes.some((p) => galleryUnder(p, stem, name))) continue;
    const id = String(r.id || '');
    if (seen.has(id + '|' + name)) continue;
    seen.add(id + '|' + name);
    const modes = Array.isArray(r.modes) ? r.modes.map(String) : String(r.modes || '').split(/[,\s]+/);
    const m = modes.map((x) => x.toLowerCase()).filter(Boolean);
    if (m.includes('oidc')) oidc.push({ id, name });
    if (m.includes('saml')) saml.push({ id, name });
  }
  return { prefixes, oidc, saml };
}

/**
 * protocolOptions({oktaProtocol, signOnMode, vendorKey, destination, baseProtocol})
 *   -> {options:[{protocol,label,why,source,documented,primary}], primary, oidcAvailable, vendorKey}
 * The protocols a draft may be created with, in display order, each with a plain `why` and its source. OpenID Connect
 * is the primary (pre-selected) choice whenever it is documented for this destination or vendor, regardless of how Okta
 * signs users in today: a vendor template documents an OIDC path, or the confirmed Entra destination is an OIDC app
 * (preferredSingleSignOnMode 'oidc', or the gallery connector's name says OIDC/OpenID). The Okta protocol is always
 * offered. OIDC and SAML 2.0 are always pickable: when nothing documents them they are offered as a hand choice
 * (source 'manual', documented false) with MANUAL_WHY, so the technician can test with the vendor. A draft that forks
 * an existing revision keeps that revision's protocol as primary (an edit is not a switch); the rest is still offered.
 * Nothing here is a guess: every option names its source.
 */
function protocolOptions(ctx) {
  const c = ctx || {};
  const okta = PROTOCOLS.includes(c.oktaProtocol) ? c.oktaProtocol : normalizeProtocol(c.oktaProtocol || '');
  const t = c.vendorKey ? VENDOR_TEMPLATES.find((x) => x.key === c.vendorKey && !x.generic) || null : null;
  const vendorName = t ? String(t.vendor || t.key).replace(/\s*\(.*$/, '') : null;
  const vendorProtocols = t ? [t.protocol].concat(t.altProtocols || []) : [];
  const dest = c.destination || {};
  const destName = String(dest.name || '');
  const oidcWhy = [];
  if (vendorProtocols.includes('oidc')) oidcWhy.push(vendorName + ' documents an OpenID Connect path to Entra (vendor template ' + t.version + ')');
  if (dest.ssoMode === 'oidc') oidcWhy.push('the Entra destination is set to OpenID Connect');
  else if (/\b(oidc|openid)\b/i.test(destName)) oidcWhy.push('the Entra destination "' + destName + '" is the OpenID Connect connector');
  /* gallery-1: the Entra gallery is the third source of "OIDC is documented for this vendor" (SAML and OIDC are separate
     templates per product; see galleryPick). A template found there is read from the mirror, never guessed. */
  const gal = c.gallery && typeof c.gallery === 'object' ? c.gallery : {};
  const galOidc = Array.isArray(gal.oidc) ? gal.oidc.filter((t) => t && t.name) : [];
  const galSaml = Array.isArray(gal.saml) ? gal.saml.filter((t) => t && t.name) : [];
  if (galOidc.length) oidcWhy.push('the Entra gallery lists an OpenID Connect template for this vendor (' + galOidc[0].name + ')');
  const list = [];
  const add = (protocol, why, source) => {
    if (!PROTOCOLS.includes(protocol)) return;
    const o = list.find((x) => x.protocol === protocol);
    if (o) { if (why && o.why.indexOf(why) < 0) o.why += '; ' + why; return; }
    list.push({ protocol, label: PROTOCOL_LABEL[protocol], why: why || '', source, documented: source !== 'manual' });
  };
  if (oidcWhy.length) add('oidc', oidcWhy.join('; '), 'available');
  add(okta, 'how Okta signs users in today' + (c.signOnMode ? ' (' + c.signOnMode + ')' : ''), 'okta');
  if (dest.ssoMode === 'saml') add('saml2', 'the Entra destination is set to SAML', 'destination');
  for (const p of vendorProtocols) { if (p === 'oidc' && oidcWhy.length) continue; add(p, vendorName + ' documents ' + PROTOCOL_LABEL[p] + ' (vendor template ' + t.version + ')', 'vendor'); }
  if (galSaml.length) add('saml2', 'the Entra gallery lists a SAML template for this vendor (' + galSaml[0].name + ')', 'gallery');
  const base = PROTOCOLS.includes(c.baseProtocol) ? c.baseProtocol : null;
  if (base) add(base, 'the protocol of the revision this draft forks', 'revision');
  for (const p of MANUAL_PROTOCOLS) if (!list.some((o) => o.protocol === p)) add(p, MANUAL_WHY, 'manual');
  const primary = base || (oidcWhy.length ? 'oidc' : okta);
  return { options: list.map((o) => Object.assign({}, o, { primary: o.protocol === primary })), primary, oidcAvailable: oidcWhy.length > 0, vendorKey: t ? t.key : null, gallery: { oidc: galOidc.length, saml: galSaml.length } };
}

/**
 * vendorInstructions(protocol, {vendorKey, oktaName, oktaLabel, values, ownerEmail})
 * -> {templateKey, templateVersion, generic, title, fields:[{label,value}], steps, ownerActions, verify, disclaimer, ...}
 * For protocols with no vendor side (bookmark, swa_password, auto_login, header_based, unknown_custom) the result has
 * templateKey null, notApplicable true and a `why`; its text never contains "SAML" (bug 6).
 */
function vendorInstructions(protocol, ctx) {
  const c = ctx || {};
  const profile = protocolProfile(protocol, { adopt: c.adopt === true }); // f15: an adopted revision has no vendor step
  const vendorStage = profile.stages.find((s) => s.key === 'vendor_setup');
  const appLabel = c.oktaLabel || c.oktaName || 'this application';
  const values = stripSecrets(c.values || {});
  if (!vendorStage.applicable) {
    return {
      templateKey: null, templateVersion: null, generic: true, notApplicable: true, why: vendorStage.why, protocol: profile.protocol, vendor: null,
      title: 'No vendor setup for ' + appLabel + ' (' + PROTOCOL_LABEL[profile.protocol] + ')',
      console: null, prerequisites: [], fields: [], steps: [],
      ownerActions: profile.protocol === 'swa_password' || profile.protocol === 'auto_login'
        ? ['Users enter their own credentials once in the My Apps browser extension. No vendor configuration and no credential is handled by CorpIT.']
        : profile.protocol === 'bookmark'
          ? ['Nothing to do at the vendor: the bookmark launches the same destination URL from Entra My Apps.']
          : [],
      verify: [], errors: [], sources: [], metadataUrl: null, ownerEmail: c.ownerEmail || null, recordVendorConsole: false, disclaimer: DISCLAIMER,
    };
  }
  const t = templateFor(profile.protocol, c.vendorKey);
  if (!t) {
    return { templateKey: null, templateVersion: null, generic: true, notApplicable: false, why: null, protocol: profile.protocol, vendor: null, title: 'No instructions available for ' + PROTOCOL_LABEL[profile.protocol], console: null, prerequisites: [], fields: [], steps: [], ownerActions: [], verify: [], errors: [], sources: [], metadataUrl: null, ownerEmail: c.ownerEmail || null, recordVendorConsole: true, disclaimer: DISCLAIMER };
  }
  const fieldDefs = t.protocol === profile.protocol ? t.fields : (templateFor(profile.protocol, null) || { fields: [] }).fields;
  const fields = fieldDefs.map((f) => {
    let v = values[f.valueKey];
    if (Array.isArray(v)) v = v.join('\n');
    return { label: f.label, valueKey: f.valueKey, value: v === undefined || v === null || v === '' ? null : String(v) };
  });
  const title = t.generic ? t.title : t.title + ' (' + appLabel + ')';
  return {
    templateKey: t.key, templateVersion: t.version, generic: !!t.generic, notApplicable: false, why: null, protocol: profile.protocol, vendor: t.vendor || null, title,
    console: t.console || null, prerequisites: (t.prerequisites || []).slice(), fields,
    steps: t.steps.map((s) => ({ title: s.title, detail: s.detail })),
    ownerActions: (t.ownerActions || []).slice(), verify: (t.verify || []).slice(), errors: (t.errors || []).slice(), sources: (t.sources || []).slice(),
    metadataUrl: values.metadataUrl || null, ownerEmail: c.ownerEmail || null,
    recordVendorConsole: !!t.generic, disclaimer: DISCLAIMER,
  };
}

/* ------------------------------------------------------------ verification */

const CHECK_KEYS = ['entra_exists', 'entra_enabled', 'sso_mode', 'reply_or_redirect', 'identifier', 'assignments', 'provisioning', 'signins_via_entra', 'okta_status', 'linked_url', 'password_mode'];
const CHECK_LABEL = {
  entra_exists: 'Entra application exists',
  entra_enabled: 'Entra application is enabled',
  sso_mode: 'Single sign-on mode is configured',
  reply_or_redirect: 'Reply URL / redirect URI matches',
  identifier: 'Identifier / client ID matches',
  assignments: 'Pilot users are assigned',
  provisioning: 'Provisioning',
  signins_via_entra: 'Successful Entra sign-in',
  okta_status: 'Remaining Okta usage',
  linked_url: 'Destination URL reached',
  password_mode: 'Password-based sign-on mode',
};

/**
 * verificationChecks(protocol, {provisioning}) -> ordered [{key,label,applies}] over every CHECK_KEYS entry.
 * Provisioning is an independent lane: pass {provisioning:true} when the app is provisioned.
 */
function verificationChecks(protocol, opts) {
  const profile = protocolProfile(protocol, { adopt: !!(opts && opts.adopt) });
  const set = new Set(profile.verification);
  if (opts && opts.provisioning) set.add('provisioning');
  return CHECK_KEYS.map((key) => ({ key, label: CHECK_LABEL[key], applies: set.has(key) }));
}

/**
 * verdict(checks) -> 'pass' | 'fail' | 'inconclusive'. A check is {key, result|status, applies?}.
 * 'fail' when any applicable check failed; 'pass' when every applicable check is pass or not_applicable
 * (and at least one applicable check exists); otherwise 'inconclusive' (missing data is never a pass).
 */
function verdict(checks) {
  const list = Array.isArray(checks) ? checks.filter((c) => c && c.applies !== false) : [];
  if (!list.length) return 'inconclusive';
  let anyFail = false, allOk = true;
  for (const c of list) {
    const r = String(c.result || c.status || '').toLowerCase();
    if (r === 'fail') anyFail = true;
    else if (r !== 'pass' && r !== 'not_applicable') allOk = false;
  }
  if (anyFail) return 'fail';
  return allOk ? 'pass' : 'inconclusive';
}

/* --------------------------------------------------------- live eligibility */

function g(o, snake, camel) { if (!o) return undefined; return o[snake] !== undefined ? o[snake] : o[camel]; }
function lcId(v) { return v === null || v === undefined || v === '' ? null : String(v).toLowerCase(); }
function ts(v) { if (!v) return NaN; const t = new Date(v).getTime(); return isNaN(t) ? NaN : t; }

const STATE_LABEL = {
  draft: 'Draft', plan_approved: 'Plan approved', entra_configured: 'Entra configured', awaiting_vendor: 'Awaiting vendor setup',
  awaiting_verification: 'Awaiting verification', awaiting_live_approval: 'Awaiting Live approval', live: 'Live', superseded: 'Superseded',
  staged: 'Staged — waiting for a verified sign-in', complete: 'Complete — SSO verified',
};

/**
 * liveEligibility({revision, attempt, destination, actor, newerDraft}) -> {eligible, predicates:[{key,label,ok,detail}]}
 * Accepts snake_case (DB rows) and camelCase (store objects).
 */
function liveEligibility(ctx) {
  const c = ctx || {};
  const rev = c.revision || null, att = c.attempt || null, dest = c.destination || null, actor = c.actor || {};
  const newerDraft = c.newerDraft !== undefined ? !!c.newerDraft : !!(rev && g(rev, 'newer_draft', 'newerDraft'));
  const preds = [];
  const P = (key, label, ok, detail) => preds.push({ key, label, ok: !!ok, detail });

  const tomb = dest && (g(dest, 'tombstone', 'tombstone') || dest.state === 'invalidated');
  P('destination_confirmed', 'Destination is confirmed and exists in Entra', dest && dest.state === 'confirmed' && !tomb,
    !dest ? 'No destination.' : tomb ? 'The matched Entra application was deleted; resolve the destination first.' : dest.state === 'confirmed' ? 'Confirmed ' + (dest.name || dest.entraId || '') : 'Destination is ' + dest.state + ', not confirmed.');

  P('revision_state', 'Revision is awaiting Live approval', rev && rev.state === 'awaiting_live_approval',
    rev ? 'Revision ' + (rev.id || '') + ' is ' + (STATE_LABEL[rev.state] || rev.state) + '.' : 'No revision.');

  // authz-1: the confirmed destination must be the application the revision was planned and verified against.
  // A createNew revision passes once its entraId is bound (configure-entra records the created service principal).
  const revEntra = lcId(g(rev, 'entra_sp_id', 'entraId'));
  const destEntra = lcId(dest && (g(dest, 'entra_sp_id', 'entraId')));
  const revCfg = rev && rev.config && typeof rev.config === 'object' ? rev.config : null;
  const createNew = !!(rev && (g(rev, 'create_new', 'createNew') === true || (revCfg && revCfg.createNew === true)));
  P('destination_matches_revision', 'Confirmed destination is the application this revision was verified against',
    !!rev && !!revEntra && !!destEntra && destEntra === revEntra, // review-2: once a createNew revision is bound, the same equality applies
    !rev ? 'No revision.'
      : !revEntra ? (createNew ? 'The new Entra application has not been created yet; run Configure Entra first.' : 'The revision has no Entra destination bound.')
      : !destEntra ? 'No confirmed destination to compare with.'
      : destEntra === revEntra ? (createNew ? 'Revision is bound to the Entra application it created (' + revEntra + ').' : 'Destination ' + revEntra + ' matches the revision.')
      : 'The confirmed destination (' + destEntra + ') is not the application this revision was planned against (' + revEntra + '); create a new revision.');

  const attStatus = att ? String(att.status || '') : '';
  P('attempt_pass', 'Latest verification attempt passed', att && attStatus === 'pass',
    att ? 'Attempt #' + (att.id || g(att, 'attempt_id', 'attemptId') || '?') + (attStatus === 'fail' ? ' failed.' : attStatus === 'pass' ? ' passed.' : ' is ' + (attStatus || 'unknown') + '.') : 'No verification attempt yet.');

  const attRev = g(att, 'revision_id', 'revisionId');
  P('attempt_revision', 'Verification ran against this revision', att && rev && attRev !== undefined && String(attRev) === String(rev.id),
    att && rev ? (String(attRev) === String(rev.id) ? 'Attempt belongs to revision ' + rev.id + '.' : 'Attempt belongs to revision ' + attRev + ', not ' + rev.id + '.') : 'No attempt or revision.');

  const approvedHash = g(rev, 'plan_approved_hash', 'planApprovedHash');
  const attHash = g(att, 'plan_hash', 'planHash');
  P('attempt_hash', 'Evidence was generated against the approved plan', att && rev && !!approvedHash && attHash === approvedHash,
    !approvedHash ? 'Plan is not approved.' : att && attHash === approvedHash ? 'Attempt hash matches the approved plan.' : 'Attempt hash does not match the approved plan; run verification again.');

  const ownerAt = ts(g(rev, 'owner_confirmed_at', 'ownerConfirmedAt'));
  const finishedAt = ts(g(att, 'finished_at', 'finishedAt'));
  P('owner_confirmed', 'Application owner confirmed the vendor-side test after the attempt', !isNaN(ownerAt) && !isNaN(finishedAt) && ownerAt > finishedAt,
    isNaN(ownerAt) ? 'No owner confirmation.' : isNaN(finishedAt) ? 'Attempt has not finished.' : ownerAt > finishedAt ? 'Confirmed by ' + (g(rev, 'owner_confirmed_by', 'ownerConfirmedBy') || 'owner') + '.' : 'Owner confirmation predates the latest attempt; confirm again.');

  const planHashNow = g(rev, 'plan_hash', 'planHash');
  P('plan_unchanged', 'Plan unchanged since approval', rev && !!approvedHash && planHashNow === approvedHash,
    !approvedHash ? 'Plan is not approved.' : planHashNow === approvedHash ? 'Plan hash matches the approval.' : 'Plan changed since approval; approve it again.');

  P('no_newer_draft', 'No newer draft for this application', !newerDraft, newerDraft ? 'A newer draft exists; it supersedes this revision.' : 'This is the latest revision.');

  P('actor_can_sign_off', 'Signer has the Live sign-off role', actor.canSignOff && !actor.readOnly,
    actor.readOnly ? 'Read-only session.' : actor.canSignOff ? 'Signer may sign off.' : 'Signing off as Live needs the admin level.');

  return { eligible: preds.every((p) => p.ok), predicates: preds };
}

/* ------------------------------------------------------------ state + CTA */

/* f14: the Entra single sign-on modes this page can adopt as-is, and the protocol profile each one verifies under. */
const ADOPT_SSO_PROTOCOL = { saml: 'saml2', oidc: 'oidc', password: 'swa_password', linked: 'bookmark' };
/**
 * adoptable(destination) -> {ok, protocol, why}. An application is already migrated when its confirmed Entra destination is
 * enabled, has a single sign-on mode this page understands and has users or groups assigned: the page then offers to keep
 * that configuration as-is (no Entra write, no vendor step) and go straight to verification. Never for a deleted target,
 * and never when the mirror carries no assignment counts (unknown is not "in use").
 */
function adoptable(dest) {
  const d = dest || {};
  const no = (why, protocol) => ({ ok: false, protocol: protocol || null, why });
  if (d.state !== 'confirmed' || d.tombstone) return no(d.tombstone ? 'The matched Entra application was deleted.' : 'No confirmed destination.');
  if (d.enabled === false) return no('The Entra application is disabled (accountEnabled is false).');
  if (d.enabled !== true) return no('The enabled state of the Entra application is not in the mirror yet; refresh Entra applications first.'); // f15: unknown is not "enabled"
  const mode = String(d.ssoMode || '').toLowerCase();
  const protocol = ADOPT_SSO_PROTOCOL[mode] || null;
  if (!protocol) return no(mode ? 'Entra single sign-on mode "' + d.ssoMode + '" is not one this page can adopt.' : 'No single sign-on mode is set on the Entra application; it is not configured yet.');
  const users = d.users === null || d.users === undefined ? null : Number(d.users);
  const groups = d.groups === null || d.groups === undefined ? null : Number(d.groups);
  if (users === null && groups === null) return no('Assignment counts for the Entra application are not in the mirror yet; refresh Entra applications first.', protocol);
  if (!((users || 0) + (groups || 0) > 0)) return no('Nobody is assigned to the Entra application; it is not in use.', protocol);
  const plural = (v, w) => (v || 0) + ' ' + w + ((v || 0) === 1 ? '' : 's');
  return { ok: true, protocol, why: (d.name || d.entraId) + ' is ' + PROTOCOL_LABEL[protocol] + ' in Entra with ' + plural(users, 'user') + ' and ' + plural(groups, 'group') + ' assigned. Keep it as-is and verify it; no Entra write, no vendor step.' };
}

const CTA_LABELS = {
  adopt_existing: 'Verify the existing Entra setup',
  adopt_again: 'Re-read Entra and adopt again',
  plan_changes: 'Plan changes instead',
  resolve_destination: 'Resolve destination',
  choose_destination: 'Find the Entra app',
  create_entra_app: 'Create new Entra app',
  review_match: 'Review the suggested match',
  review_plan: 'Review plan',
  configure_entra: 'Configure Entra',
  vendor_instructions: 'View vendor instructions',
  verify: 'Test and verify',
  sign_off_live: 'Sign off as Live',
  retire_okta: 'Retire Okta',
  retired: 'Retired in Okta',
  review_retirement: 'Review for retirement',
  nothing_to_migrate: 'Nothing to migrate (inactive in Okta)',
  test_signin: 'Test the sign-in',
  check_signins: 'Check Entra sign-ins now',
  complete: 'Complete — SSO verified',
};

const CTA_TAB = { test_signin: 'verify', adopt_existing: 'verify', adopt_again: 'verify', resolve_destination: 'destination', choose_destination: 'destination', review_match: 'destination', review_plan: 'plan', configure_entra: 'configure', vendor_instructions: 'vendor', verify: 'verify', sign_off_live: 'verify', retire_okta: 'retire' };

function oktaIdOf(x) {
  return (x.okta && (x.okta.id || x.okta.oktaId)) || x.oktaId || (x.workItem && g(x.workItem, 'source_id', 'sourceId')) || (x.revision && g(x.revision, 'okta_app_id', 'oktaAppId')) || (x.destination && g(x.destination, 'okta_app_id', 'oktaAppId')) || '';
}

function cta(code, kind, x, extra) {
  const id = oktaIdOf(x);
  const tab = CTA_TAB[code];
  const href = id ? '#apps/' + id + (tab ? '/' + tab : '') : null;
  return Object.assign({ code, label: CTA_LABELS[code], kind, href, enabled: kind === 'primary', why: null }, extra || {});
}

/* conf-1: a suggestion is presented as "the suggested match" only when it is reliable — it matched on a sign-in endpoint
 * (reply URL / ACS / identifier URI / launcher link), scores at least RELIABLE_SCORE and is strictly ahead of any other
 * endpoint-backed candidate. Endpoint evidence outranks any name score — a name is never what makes a suggestion.
 * Anything weaker is "No reliable match found": the destination stays none, the sentence below says why, and the
 * technician picks from the candidates. Rejected and invalidated candidates never count. */
const RELIABLE_SCORE = 0.6;
function reliableSuggestion(cands) {
  const list = (Array.isArray(cands) ? cands : []).filter((c) => c && c.state !== 'rejected' && c.state !== 'invalidated' && c.state !== 'superseded')
    .map((c) => Object.assign({}, c, { score: Number(c.score) || 0, hostMatch: c.hostMatch === true }))
    .sort((a, b) => ((b.hostMatch ? 1 : 0) - (a.hostMatch ? 1 : 0)) || (b.score - a.score) || String(a.name || '').localeCompare(String(b.name || '')));
  const best = list[0] || null, next = list[1] || null;
  const pct = (c) => Math.round(Math.min(1, Math.max(0, c.score)) * 100) + '%';
  const nm = (c) => c.name || 'an unnamed Entra application';
  if (!best) return { ok: false, best: null, reason: 'no_candidates', why: 'No reliable match found — nothing in the Entra mirror resembles this application.' };
  if (!best.hostMatch) return { ok: false, best, reason: 'name_only', why: 'No reliable match found — the closest candidate, ' + nm(best) + ', matched on its name only (' + pct(best) + '), not on a sign-in endpoint.' };
  if (best.score < RELIABLE_SCORE) return { ok: false, best, reason: 'weak', why: 'No reliable match found — the closest candidate, ' + nm(best) + ', scored ' + pct(best) + '; below the ' + Math.round(RELIABLE_SCORE * 100) + '% bar.' };
  if (next && next.hostMatch && next.score >= best.score) return { ok: false, best, reason: 'tie', why: 'No reliable match found — ' + nm(best) + ' and ' + nm(next) + ' tie at ' + pct(best) + '; a person has to pick.' };
  return { ok: true, best, reason: 'reliable', why: null };
}

/**
 * appState(x) -> state key. x = {destination, revision, attempt, workItem, okta, profile, candidates, actor, liveEligibility, newerDraft}.
 */
function appState(x) {
  x = x || {};
  const dest = x.destination || { state: 'none' };
  const rev = x.revision && x.revision.state !== 'superseded' ? x.revision : null;
  const wi = x.workItem || {};
  const okta = x.okta || {};
  const disposition = wi.disposition || okta.disposition || null;
  const candidates = Array.isArray(x.candidates) ? x.candidates : (Array.isArray(dest.candidates) ? dest.candidates : []);
  let state;
  if (wi.state === 'retired' || (rev && rev.state === 'live' && g(rev, 'okta_retired_at', 'oktaRetiredAt'))) state = 'retired';
  else if (rev && rev.state === 'live') state = 'live';
  else if (disposition === 'retire' || disposition === 'exclude') state = 'not_migrating';
  else if (dest.state === 'invalidated' || dest.tombstone) state = 'destination_unresolved';
  else if (rev) state = rev.state;
  else if (dest.state === 'confirmed') state = 'match_confirmed_no_revision';
  // conf-1: the destination is the server's reliable pick (store.destinationFor); candidates alone never make a
  // suggestion — weak ones are "No reliable match found" and the technician picks from them.
  else if (dest.state === 'suggested' || dest.state === 'shortlisted') state = 'match_suggested';
  else state = 'no_destination';
  // An application deactivated in Okta has nobody signing in through it: nothing to migrate, whatever its disposition
  // says (a 'retire' disposition on an already-inactive app is not open work). Only retired and live outrank it.
  if (String(okta.status || '').toUpperCase() === 'INACTIVE' && state !== 'retired' && state !== 'live') state = 'nothing_to_migrate';
  // staged-1: the Entra export (oem_entra_export) is the list of applications already stood up in Entra. Until a
  // successful interactive Entra sign-in is seen the application is 'staged' (test it); the first verified sign-in
  // makes it 'complete' — SSO verification is the proof of completion. Only retired and live outrank it.
  const st = stagedStatus(x.staged);
  if (st && state !== 'retired' && state !== 'live') state = st;
  return state;
}

function stagedStatus(staged) {
  if (!staged || typeof staged !== 'object') return null;
  const s = String(staged.status || '').toLowerCase();
  return s === 'complete' || s === 'staged' ? s : null;
}

/* stagedWhy(staged) -> the plain sentence a Complete card carries: who signed in through Entra and when (evidence, not a claim). */
function stagedWhy(staged) {
  const s = staged || {};
  const who = s.completedUser || s.completed_user || null;
  const at = s.completedSigninAt || s.completed_signin_at || s.completedAt || s.completed_at || null;
  const name = s.name || s.displayName || s.display_name || 'the Entra application';
  return 'SSO verified: ' + (who ? who + ' signed in' : 'a successful sign-in') + ' through Entra to ' + name + (at ? ' on ' + String(at).replace('T', ' ').replace(/\.\d+Z$/, 'Z') : '') + '.';
}

function nextApplicableAfter(profile, stageKey) {
  const stages = profile && Array.isArray(profile.stages) ? profile.stages : protocolProfile('unknown_custom').stages;
  const i = stages.findIndex((s) => s.key === stageKey);
  for (let k = i + 1; k < stages.length; k++) if (stages[k].applicable) return stages[k].key;
  return null;
}

const STAGE_CTA = { vendor_setup: 'vendor_instructions', verify: 'verify', live: 'sign_off_live' };
/* f15: adopted-revision helpers for ctaFor. isAdopted reads the server-owned flag (top level, or under config as the store
   records it); adoptAgain offers a fresh adoption beside the verification controls once an attempt on an adopted revision
   did not pass (the Entra side drifted from what was adopted — re-reading it is the only way to record the new state). */
const isAdopted = (rev) => !!(rev && rev.state !== 'superseded' && (rev.adopt === true || (rev.config && rev.config.adopt === true)));
const ADOPT_RESUME_WHY = 'Adoption did not finish; run it again — nothing has been written to Entra.';
function adoptAgain(x) {
  const att = x.attempt || null;
  if (!isAdopted(x.revision) || !att || String(att.status || '').toLowerCase() === 'pass') return null;
  const id = oktaIdOf(x);
  return { code: 'adopt_again', label: CTA_LABELS.adopt_again, href: id ? '#apps/' + id + '/verify' : null };
}

/**
 * ctaFor(x) -> {state, cta:{code,label,kind,href,enabled,why}, secondary:[{code,label,href}]}.
 */
function ctaFor(x) {
  x = x || {};
  const state = appState(x);
  const profile = x.profile && x.profile.stages ? x.profile : protocolProfile(x.profile && x.profile.protocol ? x.profile.protocol : (x.okta && x.okta.protocol) || (x.revision && x.revision.protocol) || 'unknown_custom');
  const stageOf = (key) => profile.stages.find((s) => s.key === key) || { applicable: true, why: '' };
  const wi = x.workItem || {};
  const id = oktaIdOf(x);
  let out, secondary = [];
  switch (state) {
    case 'retired': out = cta('retired', 'done', x, { enabled: false, why: 'Retired in Okta.' }); break;
    /* staged-1: one primary — test the sign-in (the page reads the Entra sign-in log and completes it automatically);
       "check now" is the secondary so a technician who just signed in does not wait for the next scheduled read. */
    case 'staged': {
      const st = x.staged || {};
      out = cta('test_signin', 'primary', x, { why: 'Sign in to ' + (st.name || 'the application') + ' through Entra (My Apps or the vendor sign-in page). CorpIT reads the Entra sign-in log and marks the application Complete on the first successful sign-in; nothing else is required.' });
      secondary = [{ code: 'check_signins', label: CTA_LABELS.check_signins, href: out.href }];
      break;
    }
    case 'complete': out = cta('complete', 'done', x, { enabled: false, why: stagedWhy(x.staged) }); break;
    case 'nothing_to_migrate': out = cta('nothing_to_migrate', 'done', x, { enabled: false, why: 'The application is inactive in Okta; nobody signs in through it.' }); break;
    case 'not_migrating': out = cta('review_retirement', 'primary', x, { href: wi.key ? '#work/' + wi.key : (id ? '#apps/' + id : null) }); break;
    case 'destination_unresolved': out = cta('resolve_destination', 'primary', x); secondary = [{ code: 'create_entra_app', label: CTA_LABELS.create_entra_app, href: out.href }]; break;
    case 'no_destination': out = cta('choose_destination', 'primary', x, x.destination && x.destination.noReliable ? { why: String(x.destination.noReliable) } : null); secondary = [{ code: 'create_entra_app', label: CTA_LABELS.create_entra_app, href: out.href }]; break;
    case 'match_suggested': out = cta('review_match', 'primary', x); break;
    /* f14: a confirmed destination that is already configured and in use is adopted, not planned; the plan stays one
       click away as the secondary. A draft keeps Review plan first and offers the adoption beside it (the adopt route
       supersedes the draft). */
    case 'match_confirmed_no_revision': {
      const ad = adoptable(x.destination);
      if (ad.ok) { out = cta('adopt_existing', 'primary', x, { why: ad.why }); secondary = [{ code: 'review_plan', label: CTA_LABELS.plan_changes, href: id ? '#apps/' + id + '/plan' : null }]; }
      else out = cta('review_plan', 'primary', x);
      break;
    }
    case 'draft': {
      /* f15: an adopted revision only sits in draft when adoption stopped part-way (the route creates, approves and moves it
         in separate steps); the adopt route resumes it — there is nothing to review or configure. */
      if (isAdopted(x.revision)) { out = cta('adopt_existing', 'primary', x, { why: ADOPT_RESUME_WHY }); break; }
      out = cta('review_plan', 'primary', x);
      const ad = adoptable(x.destination);
      if (ad.ok) secondary = [{ code: 'adopt_existing', label: CTA_LABELS.adopt_existing, href: id ? '#apps/' + id + '/verify' : null }];
      break;
    }
    case 'plan_approved': {
      if (isAdopted(x.revision)) { out = cta('adopt_existing', 'primary', x, { why: ADOPT_RESUME_WHY }); break; } // f15: see 'draft'
      const st = stageOf('configure_entra');
      if (st.applicable) out = cta('configure_entra', 'primary', x);
      else {
        const next = nextApplicableAfter(profile, 'configure_entra');
        out = next && STAGE_CTA[next] ? cta(STAGE_CTA[next], 'primary', x) : cta('configure_entra', 'blocked', x, { enabled: false, why: st.why || 'Not automated from this page.' });
      }
      break;
    }
    case 'entra_configured':
    case 'awaiting_vendor': {
      if (isAdopted(x.revision)) { out = cta('adopt_existing', 'primary', x, { why: ADOPT_RESUME_WHY }); break; } // f15: see 'draft'
      const st = stageOf('vendor_setup');
      if (st.applicable) out = cta('vendor_instructions', 'primary', x);
      else {
        const next = nextApplicableAfter(profile, 'vendor_setup');
        out = next && STAGE_CTA[next] ? cta(STAGE_CTA[next], 'primary', x) : cta('verify', 'blocked', x, { enabled: false, why: st.why });
      }
      break;
    }
    case 'awaiting_verification': out = cta('verify', 'primary', x); if (adoptAgain(x)) secondary = [adoptAgain(x)]; break;
    case 'awaiting_live_approval': {
      if (adoptAgain(x)) secondary = [adoptAgain(x)];
      const le = x.liveEligibility && Array.isArray(x.liveEligibility.predicates) ? x.liveEligibility : liveEligibility({ revision: x.revision, attempt: x.attempt, destination: x.destination, actor: x.actor, newerDraft: x.newerDraft });
      if (le.eligible) out = cta('sign_off_live', 'primary', x);
      else {
        const first = le.predicates.find((p) => !p.ok);
        out = cta('sign_off_live', 'blocked', x, { enabled: false, why: first ? first.label + ': ' + first.detail : 'Not eligible.' });
      }
      break;
    }
    case 'live': {
      // tombstone-3: the Live revision points at an Entra application that no longer exists. State stays 'live'
      // (the revision record is immutable) but retiring Okta would strand every user, so the CTA is blocked.
      const dest = x.destination || {};
      const tomb = dest.tombstone && typeof dest.tombstone === 'object' ? dest.tombstone : null;
      if (tomb || dest.tombstone || dest.state === 'invalidated') {
        const name = (tomb && (tomb.name || tomb.displayName)) || dest.name || (tomb && tomb.entraId) || dest.entraId || 'the Entra application';
        const at = (tomb && (tomb.detectedAt || tomb.detected_at || tomb.deletedAt || tomb.deleted_at)) || dest.detectedAt || dest.detected_at || dest.tombstonedAt || null;
        out = cta('retire_okta', 'blocked', x, {
          enabled: false,
          why: 'The Live destination "' + name + '" was deleted from Entra' + (at ? ' (detected ' + at + ')' : '') + '. Users signing in through Entra have nowhere to go; restore or replace the Entra application before retiring Okta.',
        });
        secondary = [{ code: 'resolve_destination', label: CTA_LABELS.resolve_destination, href: id ? '#apps/' + id + '/destination' : null }];
      } else out = cta('retire_okta', 'primary', x);
      break;
    }
    default: out = cta('choose_destination', 'primary', x);
  }
  return { state, cta: out, secondary };
}

/* ------------------------------------------------------------- activity */

const CHILD_KINDS = new Set(['poll', 'step', 'job_step', 'job_poll', 'progress']);
const TWO_MIN = 2 * 60 * 1000, ONE_MIN = 60 * 1000;

function jobIdOf(r) { return r.parentJobId !== undefined ? r.parentJobId : (r.jobId !== undefined ? r.jobId : (r.ref && r.ref.jobId !== undefined ? r.ref.jobId : undefined)); }
function isChild(r) { return !!(r.parentJobId !== undefined || (CHILD_KINDS.has(String(r.kind)) && jobIdOf(r) !== undefined) || r.poll === true || r.step === true); }
/**
 * stateflow-2: rbac audit actions and v2 work events name the same step differently
 * ('oem_v2_plan_approve' vs 'plan_approved'). Aliases map the audit vocabulary onto the event vocabulary so the
 * 60 s echo-dedupe compares like with like. 'verify' maps to the 'verification' stem, which the includes-rule
 * matches against verification_pass / verification_fail / verification_inconclusive.
 */
const ACTION_ALIAS = {
  create_entra_app: 'revision_created', // review-2: the create-new-app audit row echoes the draft's revision_created event
  plan_approve: 'plan_approved',
  approve_plan: 'plan_approved',
  verify: 'verification',
  live: 'revision_live',
  go_live: 'revision_live',
  sign_off_live: 'revision_live',
  owner_confirm: 'owner_confirmed',
  vendor_ready: 'revision_awaiting_verification',
  configure_entra: 'entra_configure_started',
  entra_configure: 'entra_configure_started',
  revision_create: 'revision_created',
  create_draft: 'revision_created',
  revision_edit: 'revision_edited',
  update_draft: 'revision_edited',
  match_confirm: 'match_confirm',
  match_stage: 'match_stage',
  match_shortlist: 'match_stage',
  match_reject: 'match_reject',
  match_unreject: 'match_unreject',
  match_clear: 'match_clear',
  retire_okta: 'retire_okta_requested',
  live_override: 'live_override',
  // legacy work-queue audit rows (rbac_audit_log oem_work_* / oem_test_signin_*) echo these oem_work_event rows
  work_state: 'state_set',
  work_validate: 'validated',
  work_assign: 'assigned',
  work_unassign: 'unassigned',
  test_signin_check: 'test_signin_verified',
};
function normAction(s) {
  const base = String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/^oem_/, '').replace(/^v2_/, '');
  return ACTION_ALIAS[base] || base;
}
function actionOf(r) {
  if (r.action) return normAction(r.action);
  if (r.event) return normAction(r.event);
  if (r.kind === 'audit' && r.text) return normAction(String(r.text).split(' on ')[0]);
  return '';
}
function sameActor(a, b) { return !a || !b || String(a).toLowerCase() === String(b).toLowerCase(); }

/**
 * groupActivity(rows) -> rows ordered desc with `count` and `title`:
 *  - identical (kind,text,actor) within 2 minutes collapse into one row (count),
 *  - job step/poll rows collapse into their job row (ref.jobId / parentJobId) with count,
 *  - rbac audit rows that duplicate a work event (same action within 60 s) are dropped.
 */
function groupActivity(rows) {
  const input = (Array.isArray(rows) ? rows : []).filter(Boolean).map((r) => Object.assign({}, r));
  input.sort((a, b) => (ts(b.at) || 0) - (ts(a.at) || 0));

  // 1. job children -> parent job row
  const parents = new Map();
  for (const r of input) if (r.kind === 'job' && !isChild(r) && jobIdOf(r) !== undefined) { const k = String(jobIdOf(r)); if (!parents.has(k)) parents.set(k, r); }
  const orphans = new Map();
  const stage1 = [];
  for (const r of input) {
    if (!isChild(r)) { stage1.push(r); continue; }
    const k = String(jobIdOf(r));
    const p = parents.get(k);
    if (p) { p.count = (p.count || 1) + 1; p.children = (p.children || 0) + 1; continue; }
    const o = orphans.get(k);
    if (o) { o.count = (o.count || 1) + 1; o.children = (o.children || 0) + 1; continue; }
    r.count = r.count || 1; orphans.set(k, r); stage1.push(r);
  }

  // 2. audit rows duplicating a work event within 60 s
  const nonAudit = stage1.filter((r) => r.kind !== 'audit');
  /* an audit whose details name a job that has its own row is that job's start record, not a second event (codex F6):
     the job row already says who ran it and how it ended, so the echo is dropped whatever the actor or the delay */
  const jobIds = new Set(nonAudit.filter((w) => w.kind === 'job' && jobIdOf(w) !== undefined).map((w) => String(jobIdOf(w))));
  const stage2 = stage1.filter((r) => {
    if (r.kind !== 'audit') return true;
    if (r.jobRef !== undefined && r.jobRef !== null && jobIds.has(String(r.jobRef))) return false;
    const a = actionOf(r); if (!a) return true;
    const t = ts(r.at);
    return !nonAudit.some((w) => {
      const b = actionOf(w); if (!b) return false;
      const dup = a === b || (a.length >= 4 && b.length >= 4 && (a.includes(b) || b.includes(a)));
      return dup && sameActor(r.actor, w.actor) && Math.abs((ts(w.at) || 0) - (t || 0)) <= ONE_MIN;
    });
  });

  // 3. identical (kind, text, actor) within 2 minutes -> one row with count
  const out = [];
  const last = new Map();
  for (const r of stage2) {
    const key = [r.kind, r.text || r.title || '', r.actor || ''].join('|');
    const prev = last.get(key);
    if (prev && Math.abs((ts(prev.at) || 0) - (ts(r.at) || 0)) <= TWO_MIN) { prev.count = (prev.count || 1) + (r.count || 1); prev.dupes = (prev.dupes || 0) + 1; continue; }
    r.count = r.count || 1;
    if (!r.title) r.title = r.text || '';
    if (r.detail === undefined) r.detail = null;
    last.set(key, r); out.push(r);
  }
  return out;
}

/* ------------------------------------------------------------- evidence */

function normSentence(s) { return String(s).replace(/\s+/g, ' ').trim().replace(/[.!?]+$/, '').toLowerCase(); }

/**
 * dedupeEvidence(lines) -> unique sentences preserving first-seen order (bug 8).
 * Accepts an array (strings or {text}) or a single string, which is split into sentences and re-joined.
 */
function dedupeEvidence(lines) {
  const asString = typeof lines === 'string';
  const list = asString ? String(lines).split(/(?<=[.!?])\s+/) : (Array.isArray(lines) ? lines : []);
  const seen = new Set(); const out = [];
  for (const l of list) {
    if (l === null || l === undefined) continue;
    const text = typeof l === 'string' ? l : (l.text !== undefined ? String(l.text) : JSON.stringify(l));
    const k = normSentence(text);
    if (!k || seen.has(k)) continue;
    seen.add(k); out.push(l);
  }
  return asString ? out.map(String).join(' ') : out;
}

/* ---------------------------------------------------------- source status */

/**
 * sourceStatus({lastAttempt, lastSuccess, staleAfterMs, now}) -> 'running'|'ok'|'stale'|'partial'|'unknown'.
 * The status describes the DATA (SPEC 85: current / partial / stale / never measured); the attempt's verdict is the
 * last-attempt column's. A failed last attempt therefore leaves the status where the last success put it: 'ok'
 * inside the freshness window, 'stale' outside it, 'unknown' when nothing ever succeeded — never a fifth word.
 * 'ok' only ever comes from a successful attempt within the window. Unmeasured is 'unknown', never 'ok'.
 */
function sourceStatus(ctx) {
  const c = ctx || {};
  const la = c.lastAttempt || null, ls = c.lastSuccess || null;
  const now = c.now !== undefined ? ts(c.now) : Date.now();
  const staleAfter = c.staleAfterMs > 0 ? c.staleAfterMs : 0;
  const st = la ? String(la.status || '').toLowerCase() : '';
  if (st === 'running') return 'running';
  if (st === 'partial') return 'partial';
  if (!ls && st !== 'success') return 'unknown';
  const successAt = ls ? ts(ls.at || ls.finished_at || ls.finishedAt) : ts(la.at || la.finished_at || la.finishedAt);
  if (staleAfter && !isNaN(successAt) && now - successAt > staleAfter) return 'stale';
  if (staleAfter && isNaN(successAt)) return 'unknown';
  return 'ok';
}

module.exports = {
  SECRET_KEY_RE, assertNoSecrets, assertNoSecretText, secretTextHit, stripSecrets,
  PROTOCOLS, PROTOCOL_LABEL, normalizeProtocol,
  STAGE_KEYS, STAGE_LABEL, protocolProfile,
  stableStringify, planHash, planFor,
  entraValues,
  VENDOR_TEMPLATES, templateFor, vendorKeyFor, protocolOptions, MANUAL_PROTOCOLS, MANUAL_WHY, vendorInstructions, DISCLAIMER,
  galleryStem, galleryPrefix, galleryPrefixes, galleryPick,
  stagedStatus, stagedWhy,
  CHECK_KEYS, CHECK_LABEL, verificationChecks, verdict,
  liveEligibility,
  STATE_LABEL, CTA_LABELS, appState, ctaFor, adoptable, ADOPT_SSO_PROTOCOL, ADOPT_DROPPED_CHECKS, RELIABLE_SCORE, reliableSuggestion,
  normAction, ACTION_ALIAS, groupActivity, dedupeEvidence, sourceStatus,
};
