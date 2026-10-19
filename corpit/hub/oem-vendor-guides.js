/**
 * oem-vendor-guides.js — per-vendor "where to click" guides for adding Microsoft Entra ID as an
 * identity provider next to (or instead of) Okta, plus the vendor's documented multi-IdP support.
 *
 * Every guide is written from the vendor's own documentation and Microsoft Learn, fetched and read on
 * `checkedAt`; every source is listed with its URL. Nothing here is generated from memory: a vendor
 * without a fetched source has NO guide (status 'not_written') and contributes nothing to the
 * coexistence signal. Tenant facts (the Okta ACS/audience, the Entra apps that already exist) are
 * merged in by the caller — a guide never claims what this tenant has.
 *
 * Browser assistance: `browserAssist.verified.surface` names the Chrome-extension tools that exist in
 * the operator session (navigate, read_page, find, form_input, computer click/type, file_upload,
 * get_page_text). The extension never enters credentials, never solves CAPTCHAs, and asks before every
 * download, submit, consent or destructive click. `verified.console` says whether that vendor's console
 * has actually been driven from the extension in this tenant (none has, until an admin observes a run).
 *
 * multiIdp: 'yes' | 'no' | 'conditional' | 'unknown' — as the vendor documents it, not as this tenant runs.
 */
'use strict';

const SURFACE = 'Chrome extension tools present in the operator session: navigate, read_page, find, form_input, computer (click/type), file_upload, get_page_text. It never enters credentials or MFA, never solves CAPTCHAs, and asks before every download, form submit, consent grant or Save/Activate/Delete click.';
const CONSOLE_NOT_YET = 'Not yet driven from the extension in this tenant — the first run is done with the admin watching, one confirmed click at a time.';

const GUIDES = [
  {
    key: 'adobe',
    vendor: 'Adobe Admin Console (Creative Cloud / Document Cloud / Experience Cloud for enterprise)',
    matches: { names: ['auction_adobe_1', 'adobe', 'adobecc', 'adobe_creative_cloud', 'adobe_sign', 'adobesign'], labels: '^adobe\\b' },
    status: 'verified-docs', checkedAt: '2026-09-10',
    ssoSupport: {
      multiIdp: 'conditional',
      // how the vendor takes OpenID Connect: 'vendor_consent' = the vendor's own Entra integration (an Entra admin accepts a Microsoft consent from the
      // vendor console; no app registration is staged from this page), 'app_registration' = the vendor accepts a custom OIDC identity provider (issuer, client id, secret)
      oidcShape: 'vendor_consent',
      summary: 'Yes, with a type restriction. A federated directory holds up to two authentication profiles of different types at the same time: an "Other SAML Providers" profile (what Okta is today) can coexist with a "Microsoft Azure Active Directory" profile, which uses OpenID Connect. Two SAML profiles cannot coexist, and a Google (SAML) profile cannot coexist with Other SAML Providers. So the coexistence path from Okta to Entra is the OIDC profile; adding Entra as a second SAML profile replaces the Okta one at Activate.',
      protocols: ['SAML 2.0 ("Other SAML Providers" profile type)', 'OpenID Connect ("Microsoft Azure Active Directory" profile type — also the type that enables Microsoft Entra ID Sync)'],
      licensing: 'Federated ID needs an enterprise plan: Creative Cloud for enterprise, Document Cloud for enterprise or Experience Cloud (Adobe lists these as prerequisites). Teams plans have no federated directory.',
      recommended: { protocol: 'oidc', why: 'The OIDC ("Microsoft Azure Active Directory") profile is the only Entra profile type that can sit next to the existing Okta SAML profile, it is set up almost entirely inside the Adobe Admin Console (sign in as an Entra Global Administrator, accept the consent, done), and it is what Adobe requires for Entra ID Sync later. Use the SAML path only if the directory signs users in with a field other than the Entra UPN.' },
    },
    console: { name: 'Adobe Admin Console', url: 'https://adminconsole.adobe.com', path: 'Settings › Identity › Directories › select the federated directory › Edit › Add new IdP' },
    // Whether the vendor side could be written by API from this page. Honest default: nothing is wired, and
    // whether Adobe exposes an IdP-settings API was not checked — so it is "not yet automated", not "impossible".
    apiPush: { available: false, note: 'Not yet automated: no Adobe API is connected on this page for writing identity-provider settings (whether the User Management API covers directory IdP settings was not checked on 2026-09-10). The app side is done in the Admin Console by the owner — or with the Claude in Chrome extension on the owner\'s signed-in tab.' },
    prerequisites: [
      'System administrator role in the Adobe Admin Console.',
      'An existing federated directory (the one Okta signs users into today) — this flow adds a profile to it; it does not create a new directory.',
      'Entra: a Global Administrator to sign in and accept the consent prompt (Adobe creates an application in the tenant — it appears as "Adobe Identity Management (OIDC)" under Enterprise apps). The SAML alternative needs only Cloud Application Administrator or Application Administrator.',
      'Users (or the group) assigned to the new Entra application before testing.',
      'The Admin Console Username must equal the Entra UPN for the OIDC profile. If the directory\'s User Login Setting uses another field (for example email that differs from UPN), Adobe says to add the new IdP as "Other SAML Providers" instead.',
    ],
    collect: [
      'Which Admin Console directory holds the company domains, and the type of its current profile (expect "Other SAML Providers" for Okta).',
      'The directory\'s User Login Setting (UPN vs email) and 2–3 active federated users for the test.',
      'SAML path only: the Adobe Entity ID and ACS URL shown on the directory\'s Edit SAML Configuration screen (patterns: https://federatedid-na1.services.adobe.com/federated/saml/metadata/alias/<id> and …/federated/saml/SSO/alias/<id>; the Okta scan on this page holds the values Okta uses today).',
      'SAML path only: the Federation Metadata XML downloaded from the Entra enterprise application.',
    ],
    steps: [
      { title: 'Open the directory', detail: 'Admin Console › Settings › Identity › Directories. Select the federated directory, then Edit.' },
      { title: 'Add the identity provider', detail: 'In the directory details panel select "Add new IdP", choose "Microsoft Azure Active Directory", then Next.' },
      { title: 'Sign in and consent (Entra Global Administrator)', detail: 'Sign in with the Entra Global Administrator account and select Accept at the permission prompt so Adobe can create its application in the tenant. Adobe notes this profile authenticates with OpenID Connect; confirm the Username field in the Admin Console matches the UPN field in Entra.' },
      { title: 'Check the new profile', detail: 'The directory details now list a second profile. The existing Okta profile stays "In use"; nothing has changed for users yet.' },
      { title: 'Test before activating', detail: 'On the new profile select Test. Sign in with two to three active users from the directory and confirm the username in the assertion matches the existing Admin Console usernames. Share the test link with another administrator to validate on a different machine.' },
      { title: 'Activate', detail: 'Select Activate on the new profile. It shows "In use"; the directory now runs the Entra OIDC profile alongside the Okta SAML profile (two profiles of different types).' },
      { title: 'Retire Okta later', detail: 'Only after Entra sign-ins are seen (this page\'s Verify step reads the Entra sign-in log): remove the Okta SAML profile in the same panel, then deactivate the Okta app from this page\'s lifecycle action.' },
      { title: 'SAML alternative (only when the login field is not the UPN)', detail: 'Entra admin center › Entra ID › Enterprise apps › New application › gallery "Adobe Identity Management (SAML)" › Single sign-on › SAML. Basic SAML Configuration: Sign on URL https://adobe.com; Identifier (Entity ID) = the Adobe value https://federatedid-na1.services.adobe.com/federated/saml/metadata/alias/<CUSTOM_ID>; Reply URL = the ACS …/federated/saml/SSO/alias/<id>. Download the Federation Metadata XML, assign users. In the Admin Console: Add new IdP › Other SAML Providers › upload the metadata › Save. Adobe warns: create a new SAML application instead of editing the existing one, to prevent authentication downtime — and because two SAML profiles cannot coexist, Activate on this path replaces the Okta profile (hard cutover, plan the owner window).' },
    ],
    browserAssist: {
      claudeCan: [
        'Open adminconsole.adobe.com and entra.microsoft.com in the signed-in Chrome tab, follow the menu path and read which directory profile is "In use" (read_page / get_page_text).',
        'Fill the non-secret text fields on the Entra Basic SAML Configuration page (Identifier, Reply URL, Sign on URL) from the values recorded by the Okta scan (form_input), and read them back before the admin saves.',
        'Upload the Federation Metadata XML on the Adobe Edit SAML Configuration screen when the file is on this Mac (file_upload).',
        'Open the profile Test link and report the result page.',
      ],
      manual: [
        'Signing in to either console and any MFA prompt — the extension never enters credentials.',
        'The Entra Global Administrator consent prompt ("Accept") — an expanded-permission grant; the administrator clicks it.',
        'Save, Activate, Remove profile — irreversible controls; the extension asks and the administrator confirms each click (or clicks it themselves).',
        'Downloading the Federation Metadata XML — the extension asks first, naming the file and the source.',
      ],
      verified: { surface: SURFACE, console: CONSOLE_NOT_YET },
    },
    validation: {
      test: [
        '[vendor doc] Use the profile\'s Test link before Activate; sign in with two to three active users; confirm the assertion username format matches the existing usernames.',
        '[this page] After Activate, a federated user signs in at adobe.com; the Verify step reads the Entra sign-in log for the Adobe application and shows the sign-in (or says "none yet" — inconclusive, not a failure).',
      ],
      lockout: [
        '[platform guidance] Keep at least one Adobe System Administrator whose identity is not in the federated directory (an Adobe ID or Business ID) so the Admin Console stays reachable if federation breaks.',
        '[vendor doc] Do not edit the existing SAML profile; add a new profile and test it — the Okta profile keeps working until you remove it.',
        '[vendor doc] Do not withdraw or move domains during the test; domain trusts must be broken and re-established around any domain move.',
      ],
      undo: [
        'Before Activate: remove the untested profile from the directory details — users never saw it.',
        'After Activate: the previous profile is still listed; re-activate it, then remove the Entra profile. Users of the directory continue to sign in through whichever profile is "In use".',
        'Entra side: disable (accountEnabled = false) or delete the created enterprise application; this page\'s rollback deletes only objects it created itself.',
      ],
    },
    differences: [
      'Existing directory type: "Other SAML Providers" (Okta) + "Microsoft Azure Active Directory" (OIDC) coexist; a Google-type directory cannot coexist with Other SAML Providers.',
      'User Login Setting: a directory that signs in with a field other than the Entra UPN cannot use the OIDC profile — take the SAML path (hard cutover).',
      'Microsoft Entra ID Sync (formerly Azure Sync) is a separate, optional step on the directory\'s Sync tab; it requires the OIDC directory type and is not needed for SSO.',
      'Multiple directories: an organisation with several federated directories repeats this per directory; domains can be moved between directories after migration.',
    ],
    sources: [
      { title: 'Adobe Enterprise — Change your authentication provider (updated Aug 3, 2026)', url: 'https://helpx.adobe.com/business/enterprise/directories-domains-access/directory-trusting/change-authentication-provider.html' },
      { title: 'Adobe Enterprise — Authenticate your users with Microsoft Entra ID (Sep 1, 2025)', url: 'https://helpx.adobe.com/business/enterprise/identity-sso/integrate-with-microsoft-entra/sso-setup-azure.html' },
      { title: 'Microsoft Learn — Configure Adobe Identity Management (SAML) for single sign-on with Microsoft Entra ID (ms.date 2025-03-25)', url: 'https://learn.microsoft.com/en-us/entra/identity/saas-apps/adobe-identity-management-tutorial' },
      { title: 'Adobe Enterprise — Configure SAML directory in Admin Console', url: 'https://helpx.adobe.com/business/enterprise/directories-domains-access/directories-and-domains/create-directory-for-saml-identity-providers.html' },
    ],
  },
];

/* ------------------------------------------------------------------ lookup */

function norm(s) { return String(s || '').trim().toLowerCase(); }

/** The guide for an Okta app row ({name, label}) — by OIN key first, then by label pattern. */
function guideFor(app) {
  if (!app) return null;
  const name = norm(app.name), label = String(app.label || '');
  for (const g of GUIDES) {
    if (g.matches.names && g.matches.names.map(norm).includes(name)) return g;
  }
  for (const g of GUIDES) {
    if (g.matches.labels && new RegExp(g.matches.labels, 'i').test(label)) return g;
  }
  return null;
}

/** What the queue needs per row: is there a guide, and what does it say about two IdPs. */
function guideSummary(g) {
  if (!g) return { available: false, key: null, vendor: null, multiIdp: 'unknown', status: 'not_written' };
  return { available: true, key: g.key, vendor: g.vendor, multiIdp: g.ssoSupport.multiIdp, status: g.status, checkedAt: g.checkedAt, recommended: g.ssoSupport.recommended || null, summary: g.ssoSupport.summary, apiPush: g.apiPush || { available: false, note: 'Not yet automated: no vendor API is connected on this page.' } };
}

function list() { return GUIDES.map((g) => Object.assign(guideSummary(g), { console: g.console, sources: g.sources.length, steps: g.steps.length })); }

module.exports = { GUIDES, guideFor, guideSummary, list, SURFACE };
