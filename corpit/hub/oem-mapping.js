/**
 * oem-mapping.js — Okta -> Entra Conditional Access mapping catalog.
 *
 * Two kinds of content live here, and the UI labels them differently:
 *   FACTS   come from the live snapshot tables (oem_okta_*, oem_entra_*). Never hardcoded.
 *   JUDGMENT is the mapping analysis below: what an Okta construct becomes in Entra,
 *            where behaviour differs, and what must be true first.
 *
 * Automation labels are NOT hardcoded. Each mapping declares the Graph permissions its
 * actions need; capabilityFor() intersects that with the roles actually present on the
 * live app-only token, so a label can only claim automation we can really perform.
 * See no-fake-controls: an action we cannot execute renders blocked, with the reason.
 */
'use strict';

/** Graph application permissions this tenant's collector credential is known to need. */
const SCOPE = {
  READ_POLICY:  'Policy.Read.All',
  READ_DIR:     'Directory.Read.All',
  READ_AUDIT:   'AuditLog.Read.All',
  READ_REPORTS: 'Reports.Read.All',
  READ_AUTHMETH:'UserAuthenticationMethod.Read.All',
  WRITE_CA:     'Policy.ReadWrite.ConditionalAccess',
  WRITE_GROUP:  'Group.ReadWrite.All',
  WRITE_AUTHMETH_POLICY: 'Policy.ReadWrite.AuthenticationMethod',
  READ_DOMAIN:  'Domain.Read.All',
};

/** Work classes shown on the page. */
const CLASS = {
  AUTO:   'automate',   // Claude can do this now, with granted scopes
  MANUAL: 'manual',     // requires a human in the Entra admin center
  REVIEW: 'review',     // a decision or data gap must be settled first
};

/**
 * A migration step. `actions` are concrete things the page can run.
 * `requires` lists Graph scopes; if any are missing the action renders blocked.
 */
const MAPPINGS = [
  /* ---------------------------------------------------------------- phase 1 */
  {
    key: 'zone-parity',
    phase: 'prereq',
    order: 10,
    title: 'Okta network zones -> Entra named locations',
    oktaObject: { type: 'Network zones', name: 'OfficeIpZone, AWSIpZone, LegacyIpZone, BlockedIpZone, Unblock List, US Only, International Zone, TOR Block List' },
    entraObject: { type: 'Named locations', name: 'Office Locations, Zscaler SIPA IPs, AWS West-2, Blocked IP Zones, Unblock IP Zones, US Only Access Policy' },
    plain:
      'Every Okta rule that says "corporate network only" is really saying "source IP is inside OfficeIpZone". ' +
      'Entra has the same idea but calls it a named location, and it adds a second switch Okta does not have: ' +
      'a location can be marked Trusted. Policies that key off "trusted location" ignore a location that is not flagged. ' +
      'So the addresses have to match AND the trust flag has to be right, or the translated policy silently changes who gets in.',
    differences: [
      'Okta zones are either IP or DYNAMIC (country/ASN). Entra splits these into two object types: ipNamedLocation and countryNamedLocation. A single Okta dynamic zone that mixes country and ASN cannot be expressed as one Entra location.',
      'Entra ipNamedLocation carries isTrusted. Okta has no equivalent flag; an Okta zone is trusted only by virtue of a rule referencing it.',
      'Entra requires CIDR notation. Okta accepts single-IP ranges (a-b form), which have to be converted.',
      'Entra caps a named location at 2,000 ranges; Okta OfficeIpZone currently carries 168 entries across gateways and proxies, so it fits, but the Zscaler proxy list should live in its own location rather than being merged.',
    ],
    prerequisites: [
      'Decide whether the Zscaler egress ranges stay in a separate named location (they do today) or merge into Office Locations.',
      'Confirm the SIPA anchored egress IPs are the complete set. The parity table lists what is present in each system.',
    ],
    actions: [
      { id: 'zone-diff', label: 'Compute zone parity', cls: CLASS.AUTO, requires: [SCOPE.READ_POLICY],
        creates: 'A per-CIDR diff between each Okta zone and every Entra named location, including which side is missing and whether the Entra location is trusted.',
        why: 'A translated "corporate network only" policy is only as correct as the address list behind it.',
        verify: 'The parity table shows zero rows in the okta_only direction for OfficeIpZone.' },
      { id: 'zone-payload', label: 'Generate named-location payload', cls: CLASS.AUTO, requires: [SCOPE.READ_POLICY],
        creates: 'A Graph PATCH body for Office Locations adding the missing ranges, and a PATCH setting AWS West-2 isTrusted=true.',
        why: 'Hand-typing 12 CIDRs into the portal is where transcription errors happen.',
        verify: 'GET /identity/conditionalAccess/namedLocations returns the added ranges and isTrusted=true.' },
      { id: 'zone-apply', label: 'Apply to Entra', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'The named-location changes in the tenant.',
        why: 'Named locations are the foundation every network-scoped policy rests on.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access -> Named locations',
          steps: [
            'Open Named locations and select Office Locations.',
            'Paste each missing CIDR from the parity table into IP ranges, one per line.',
            'Leave "Mark as trusted location" checked, then Save.',
            'Select AWS West-2 and check "Mark as trusted location". Save.',
          ],
          confirm: 'Reopen each location and confirm the range count and the trusted flag. Then re-run Compute zone parity here; the okta_only rows should clear.',
        } },
    ],
  },

  {
    key: 'break-glass',
    noPayloadReason:
      'Break-glass accounts are user objects and a group, not a Conditional Access policy. There is no policy body to generate; the group has to exist before any policy can exclude it.',
    phase: 'prereq',
    order: 20,
    title: 'Break-glass accounts (none exist today)',
    oktaObject: { type: 'n/a', name: 'Okta admin access is governed by the Okta Admin Console policy' },
    entraObject: { type: 'Emergency access accounts', name: 'Excluded from every Conditional Access policy' },
    plain:
      'Conditional Access has no built-in escape hatch. A policy that blocks sign-in can lock out every administrator, ' +
      'including the person who wrote it. The standard control is two cloud-only accounts, excluded from all policies, ' +
      'with long random credentials held offline. This tenant has none, and 9 Global Admins, 4 of which are service accounts. ' +
      'No blocking policy should be enabled before these exist.',
    differences: [
      'Okta evaluates sign-on policies by priority and an earlier ALLOW short-circuits later rules, so a permissive high-priority policy acts as an informal escape hatch. Entra has no priority: all matching policies apply and any block wins.',
    ],
    prerequisites: ['Somewhere offline to store the credentials.', 'A monitoring rule that alerts on any break-glass sign-in.'],
    actions: [
      { id: 'bg-audit', label: 'Report current admin exposure', cls: CLASS.AUTO, requires: [SCOPE.READ_DIR, SCOPE.READ_AUDIT],
        creates: 'A list of directory role holders, which are service accounts by sign-in pattern, and which are excluded from existing CA policies.',
        why: 'Tells you who would actually be locked out, and who is already carrying a permanent exclusion.',
        verify: 'Cross-check the count against Entra admin center -> Roles and administrators.' },
      { id: 'bg-create', label: 'Create break-glass accounts', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_GROUP],
        creates: 'Two cloud-only Global Admin accounts and a group excluded from all CA policies.',
        why: 'Without this, enabling any block policy risks a tenant-wide lockout with no recovery path short of Microsoft support.',
        manual: {
          where: 'Entra admin center -> Identity -> Users -> All users -> New user',
          steps: [
            'Create two users on the onmicrosoft.com domain so they do not depend on Okta federation or AD Connect.',
            'Give each a 40+ character random password and store it offline, split between two custodians.',
            'Assign Global Administrator permanently (not PIM-eligible) so activation never depends on a working MFA path.',
            'Create a group named CA-BreakGlass-Exclude and add both accounts.',
            'Exclude that group from every Conditional Access policy, including the Microsoft-managed ones.',
            'Register a phishing-resistant method on each, and record the recovery procedure in the runbook.',
          ],
          confirm: 'Sign in with one account from a browser profile with no session, confirm no CA policy applied on the sign-in log entry, then confirm an alert fired.',
        } },
    ],
  },

  {
    key: 'mfa-claim',
    noPayloadReason:
      'The claim is carried by the federation settings on the Okta domain, changed with Set-MsolDomainFederationSettings or in the Okta admin console, not by a Conditional Access policy.',
    phase: 'prereq',
    order: 30,
    title: 'Okta does not pass its MFA claim to Entra',
    oktaObject: { type: 'Federation', name: 'auction.com is federated to Okta; Okta performs MFA' },
    entraObject: { type: 'Domain federation setting', name: 'federatedIdpMfaBehavior' },
    plain:
      'Okta does the MFA today, but Entra is not told about it. In a sample of 500 successful sign-ins, 497 were recorded as ' +
      'single-factor. That means a Conditional Access policy requiring MFA would treat almost every sign-in as not having met ' +
      'the requirement, and would challenge users a second time on top of Okta. This is the hidden blocker under every ' +
      'MFA-shaped mapping on this page, and it appears on no dashboard.',
    differences: [
      'Okta satisfies MFA inside its own session. Entra only believes MFA happened if the SAML/WS-Fed token carries the multipleauthn claim, or the domain is set to acceptIfMfaDoneByFederatedIdp.',
      'Until then, Entra-side MFA is additive rather than equivalent: users authenticate twice.',
    ],
    prerequisites: [
      'Okta must be configured to send the MFA claim for the Office 365 / Entra application.',
      'The domain must be set to federatedIdpMfaBehavior = acceptIfMfaDoneByFederatedIdp.',
      'Only 91 of 944 users covered by the registration report have any Entra MFA method registered; a registration drive is needed if Entra is to own MFA rather than trust Okta.',
    ],
    noEquivalentNote:
      'This has no Conditional Access setting at all. It is a federation property, changed with PowerShell or the Graph domain API, not in the Conditional Access blade.',
    actions: [
      { id: 'claim-measure', label: 'Measure the MFA claim rate', cls: CLASS.AUTO, requires: [SCOPE.READ_AUDIT],
        creates: 'The current split of singleFactorAuthentication vs multiFactorAuthentication across recent successful sign-ins, from the local sign-in mirror.',
        why: 'This is the gate. The number must move before any MFA policy is enforced, and it is directly measurable.',
        verify: 'Re-run after the federation change; multiFactorAuthentication should climb from near zero.' },
      { id: 'claim-read', label: 'Read current federation setting', cls: CLASS.MANUAL, requires: [SCOPE.READ_DOMAIN],
        creates: 'The live value of federatedIdpMfaBehavior for auction.com.',
        why: 'Confirms whether the setting is already correct before anyone changes Okta.',
        manual: {
          where: 'Not readable with the current credential. GET /domains/auction.com/federationConfiguration returns 403 because Domain.Read.All is not consented.',
          steps: [
            'Either grant Domain.Read.All to IT-Command-IdentityDiag and re-run this action,',
            'or read it interactively: Get-MgDomainFederationConfiguration -DomainId auction.com | Select FederatedIdpMfaBehavior',
          ],
          confirm: 'The value should read acceptIfMfaDoneByFederatedIdp once the change is made.',
        } },
      { id: 'claim-fix', label: 'Configure Okta to send the claim', cls: CLASS.MANUAL, requires: [],
        creates: 'An MFA claim in the token Okta issues to Entra, and the matching domain-side trust.',
        why: 'Without it, enforcing MFA in Entra double-prompts users and puts ~99% of sign-ins against an unmet requirement.',
        manual: {
          where: 'Okta admin console -> Applications -> Office 365 -> Sign On, then Entra via Graph or PowerShell',
          steps: [
            'In Okta, on the Office 365 app sign-on settings, enable the option that asserts MFA to the service provider so the token carries multipleauthn.',
            'In Entra, set the domain to accept it: Update-MgDomainFederationConfiguration -DomainId auction.com -FederatedIdpMfaBehavior acceptIfMfaDoneByFederatedIdp',
            'Do not enable any MFA-requiring CA policy until the measured claim rate has moved.',
          ],
          confirm: 'Run Measure the MFA claim rate again. Sign-ins should begin reporting multiFactorAuthentication.',
        } },
    ],
  },

  /* ---------------------------------------------------------------- phase 2 */
  {
    key: 'us-only',
    phase: 'translate',
    order: 40,
    title: 'US Only Sign On Policy -> block sign-in outside the United States',
    oktaObject: { type: 'OKTA_SIGN_ON', name: 'US Only Sign On Policy', policyId: '00pa6cyib8OuvV496357' },
    entraObject: { type: 'Conditional Access policy', name: 'CA-Geo-01 Block sign-in outside the United States' },
    plain:
      'Okta denies sign-in when the source IP is not in the "US Only" dynamic zone, for everyone. The Entra equivalent is a ' +
      'policy scoped to all users and all cloud apps, with the location condition set to any location except the US, granting Block. ' +
      'The shape is close to one-to-one, which makes this the safest first policy to translate.',
    differences: [
      'Okta resolves country from its own geo-IP database; Entra uses Microsoft\'s. They disagree at the edges, so a small number of sign-ins will be judged differently.',
      'Check includeUnknownCountriesAndRegions on the US Only Access Policy named location in the portal before enabling. If it is off, an address Microsoft cannot geolocate falls outside the location and gets blocked. Okta\'s dynamic zone treats unknown separately. The collector does not read that field, so this page cannot tell you which way it is set.',
      'A CA policy scoped to users does not govern service principals. Okta\'s sign-on policy likewise only covers the Everyone group, so both leave workload identities out, but for different reasons.',
      'Okta stops at the first matching rule by priority. Entra evaluates every policy and any Block wins, so an existing policy can combine with this one in ways Okta would not.',
    ],
    prerequisites: ['break-glass', 'zone-parity'],
    impact: { kind: 'signin-country', note: 'Counts successful sign-ins from outside the US in the local mirror, which are what this policy would have blocked.' },
    entraPayload: {
      displayName: 'CA-Geo-01 Block sign-in outside the United States',
      state: 'enabledForReportingButNotEnforced',
      conditions: {
        // The international group is excluded because Okta already exempts it: the International
        // Sign On Policy sits above the US-only DENY, which is why 42 users sign in from abroad
        // today without being blocked. Omitting it here would block all of them on day one.
        users: { includeUsers: ['All'], excludeGroups: ['<CA-BreakGlass-Exclude object id>', '<SaaS-OktaInternationalUsers>'] },
        applications: { includeApplications: ['All'] },
        clientAppTypes: ['all'],
        locations: { includeLocations: ['All'], excludeLocations: ['1e735520-db0c-4a3c-9d39-6e0256d3a259'] },
      },
      grantControls: { operator: 'OR', builtInControls: ['block'] },
    },
    actions: [
      { id: 'geo-preview', label: 'Preview policy + impact', cls: CLASS.AUTO, requires: [SCOPE.READ_POLICY, SCOPE.READ_AUDIT],
        creates: 'The exact Graph request body above, plus the count of recent successful sign-ins it would have blocked, broken down by country and user.',
        why: 'Report-only first, and a real impact number, is how you avoid discovering the blast radius from a help-desk queue.',
        verify: 'Read the payload and the affected-user list before anything is created.' },
      { id: 'geo-create', label: 'Create the policy', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'A new Conditional Access policy in report-only mode.',
        why: 'Report-only records what would have happened without affecting anyone.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access -> Policies -> New policy',
          steps: [
            'Name it CA-Geo-01 Block sign-in outside the United States.',
            'Users: include All users, exclude the CA-BreakGlass-Exclude group.',
            'Target resources: All cloud apps.',
            'Conditions -> Locations: include Any location, exclude the US Only Access Policy named location.',
            'Grant: Block access.',
            'Enable policy: set to Report-only, then Create.',
          ],
          confirm: 'Leave it in report-only for a full business week. In Sign-in logs -> Conditional Access, filter to this policy and confirm the only reportOnlyFailure entries are genuinely non-US. Then switch to On.',
        } },
    ],
  },

  {
    key: 'corp-network-only',
    phase: 'translate',
    order: 50,
    title: 'AllowFromCorporateNetworkOnly -> block outside trusted locations',
    oktaObject: { type: 'ACCESS_POLICY', name: 'AWS Single Sign-on, Slack, Zscaler ZPA/ZIA Admin, Office 365 (rule p2)' },
    entraObject: { type: 'Conditional Access policy', name: 'CA-Net-01 Require trusted location for privileged SaaS' },
    plain:
      'Four Okta app policies carry a rule named AllowFromCorporateNetworkOnly. Despite the name it is a DENY rule: it matches ' +
      'when the client is NOT in OfficeIpZone and blocks. The Entra equivalent scopes the same apps and blocks any location ' +
      'except the trusted named locations. This mapping is the reason the zone parity work has to come first, and it is where ' +
      'the SIPA anchored egress addresses matter.',
    differences: [
      'The Okta rule sits at priority 0 on each app policy, so it wins over the device-trust ALLOW rules beneath it. Off-network access is blocked even from a managed device. Rebuilding this in Entra as two separate policies changes that: Entra has no priority, so a Block always beats a Grant, which happens to preserve the behaviour here. Do not rely on that if you later soften the rule.',
      'Okta evaluates per application policy. Entra needs the app set listed explicitly on one policy, or one policy per app.',
      'Zscaler ZPA Admin and ZIA Admin are Okta-federated SaaS consoles, not Entra enterprise apps. Unless they are added to Entra as SAML apps, a CA policy cannot govern them at all.',
    ],
    prerequisites: ['zone-parity', 'break-glass'],
    entraPayload: {
      displayName: 'CA-Net-01 Require trusted location for privileged SaaS',
      state: 'enabledForReportingButNotEnforced',
      conditions: {
        users: { includeUsers: ['All'], excludeGroups: ['<CA-BreakGlass-Exclude object id>'] },
        // Deliberately not All cloud apps. The Okta rules live on four app
        // policies, so scoping this to everything would block far more than
        // the rules being migrated.
        applications: { includeApplications: ['<AWS Single Sign-on enterprise app id>', '<Slack enterprise app id>'] },
        clientAppTypes: ['all'],
        locations: {
          includeLocations: ['All'],
          // Excluded by object id, which works whether or not the location
          // carries the trusted flag. Trust matters only to an AllTrusted
          // include, which this body avoids for exactly that reason.
          excludeLocations: [
            'fa770870-91f5-462e-81f5-a1ef08a96a63',
            '08161496-4023-4da9-90db-e1658845740d',
            '527a6eab-0a98-45c3-a98f-465088a916b4',
          ],
        },
      },
      grantControls: { operator: 'OR', builtInControls: ['block'] },
    },
    noEquivalentNote:
      'Zscaler ZIA and ZPA admin consoles authenticate through Okta. Migrating their access policy to Entra requires re-federating those consoles to Entra first, which is a separate project.',
    actions: [
      { id: 'net-preview', label: 'Preview policy + impact', cls: CLASS.AUTO, requires: [SCOPE.READ_POLICY, SCOPE.READ_AUDIT],
        creates: 'A per-app payload plus the count of recent successful sign-ins from outside the trusted ranges.',
        why: 'Shows how much normal access happens off-network before you block it.',
        verify: 'Check the payload app list matches the four Okta policies.' },
      { id: 'net-create', label: 'Create the policy', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'A report-only CA policy blocking untrusted locations for the mapped apps.',
        why: 'Preserves the network boundary the Okta rules enforce today.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access -> Policies -> New policy',
          steps: [
            'Users: All users, excluding CA-BreakGlass-Exclude.',
            'Target resources: select the Entra enterprise applications that correspond to the Okta apps. AWS Single Sign-on and Slack exist as enterprise apps; the Zscaler consoles do not.',
            'Conditions -> Locations: include Any location, exclude Office Locations, Zscaler SIPA IPs and AWS West-2.',
            'Grant: Block access. Set Report-only, then Create.',
          ],
          confirm: 'Confirm in report-only that sign-ins through the SIPA anchored addresses are NOT flagged as would-be-blocked. If they are, the named location is still missing a range or the trusted flag.',
        } },
    ],
  },

  {
    key: 'mfa-all',
    phase: 'translate',
    order: 60,
    title: 'Okta default MFA -> require MFA for all users',
    oktaObject: { type: 'OKTA_SIGN_ON + ACCESS_POLICY', name: 'Default Policy rule "10hour Session", and the "Any two factors" app policy on 69 apps' },
    entraObject: { type: 'Conditional Access policy', name: '1. MFA for ALL for all apps from Anywhere (already exists, disabled)' },
    plain:
      'Okta requires a second factor for everyone through the Default Policy, and 69 applications sit on an "Any two factors" ' +
      'policy with a 12-hour re-authentication window. Entra already contains a policy that does exactly this, built and left ' +
      'disabled, with a 10-hour sign-in frequency that closely matches Okta. The right move is to enable that policy rather than ' +
      'build a new one. It is blocked until the MFA claim gap is closed.',
    differences: [
      'Okta\'s requirement is satisfied inside Okta. Entra\'s is satisfied only by an Entra-registered method or an accepted federated claim, so today the same policy would double-prompt.',
      'Okta factorPromptMode ALWAYS forces a factor on every sign-in. Entra\'s nearest equivalent is sign-in frequency everyTime, which is much more aggressive than the 10-hour value currently on the policy.',
      'The existing Entra policy excludes exactly one user. The Okta side exempts 31 through SaaS-MFA-Exclusion, so the exclusion sets do not currently agree.',
    ],
    prerequisites: ['mfa-claim', 'break-glass', 'mfa-exemption'],
    blockedBy: 'mfa-claim',
    // The policy exists already, so the body is a PATCH to it, not a create.
    entraPayloadMethod: 'PATCH',
    entraPayloadUrl:
      'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/664df08e-153e-4bfc-bc86-9a77dbbc8fea',
    entraPayload: {
      // Report-only, not enabled. Enabling is the separate manual decision and
      // it stays blocked until the claim gap closes.
      state: 'enabledForReportingButNotEnforced',
      conditions: {
        users: {
          includeUsers: ['All'],
          excludeGroups: ['<CA-BreakGlass-Exclude object id>', '<SaaS-MFA-Exclusion>'],
        },
      },
    },
    impact: { kind: 'mfa-claim', note: 'The share of sign-ins Entra currently considers single-factor is the population this policy would challenge.' },
    actions: [
      { id: 'mfaall-preview', label: 'Preview impact of enabling', cls: CLASS.AUTO, requires: [SCOPE.READ_AUDIT, SCOPE.READ_REPORTS],
        creates: 'The number of sign-ins and distinct users that would face a new MFA challenge, which service accounts and non-interactive flows are in scope, and which users have no Entra MFA method registered.',
        why: 'Named the three things that break last time this was considered: AD Connect, scripted password flows, and unregistered users.',
        verify: 'Compare against the existing policy exclusion list.' },
      { id: 'mfaall-enable', label: 'Enable the existing policy', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'Enforcement of policy 664df08e-153e-4bfc-bc86-9a77dbbc8fea.',
        why: 'The policy is already correct. Enabling beats authoring a duplicate.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access -> Policies -> "1. MFA for ALL for all apps from Anywhere"',
          steps: [
            'Do not enable until the measured MFA claim rate has moved off near-zero.',
            'Add the break-glass group and the AD Connect sync account to Exclude.',
            'Move the 31 members of the Okta SaaS-MFA-Exclusion group to a reviewed Entra exclusion group, or retire the exemptions.',
            'Set to Report-only first and leave it for a week.',
            'Only then set to On.',
          ],
          confirm: 'In report-only, confirm the sync account and any scripted flows show no would-be-block. Directory sync stopping is the failure this ordering prevents.',
        } },
    ],
  },

  {
    key: 'mfa-exemption',
    noPayloadReason:
      'An exemption is an excluded group on another policy, not a policy of its own. The body to change is the MFA policy body on the MFA for all step.',
    phase: 'translate',
    order: 70,
    title: 'MFA-Exemption policy -> there is no "exempt" policy in Entra',
    oktaObject: { type: 'OKTA_SIGN_ON', name: 'MFA-Exemption (priority 1)', policyId: '00p4h20zrwASq6i16356' },
    entraObject: { type: 'Policy exclusion', name: 'An excluded group on the MFA policy' },
    plain:
      'Okta expresses an exemption as its own policy: MFA-Exemption sits at priority 1, matches the SaaS-MFA-Exclusion group, and ' +
      'allows sign-in with no second factor. Because it is first, it wins for those members. Entra has no such construct. ' +
      'You cannot write a policy that grants an exception; you exclude the group from the policy that would otherwise apply. ' +
      'This is the single biggest structural difference between the two systems, and it changes how exemptions are audited.',
    differences: [
      'Okta: highest-priority match wins, so an ALLOW policy can override a stricter one. Entra: all policies apply and Block always wins, so the only way to exempt someone is exclusion.',
      'An Okta exemption is visible as a policy in the policy list. An Entra exclusion is a field inside another policy, which makes it much easier to lose track of. Keep exemptions in one named group so they can be reviewed.',
      'The Okta policy exempts everyone in the group from MFA on every application. An Entra exclusion is per-policy, so the same outcome needs the group excluded from each MFA-requiring policy.',
    ],
    reviewReason:
      '31 accounts are currently exempt from MFA, and the group is an APP_GROUP pushed from an application rather than a directory-managed group. Each member needs a reason to exist before the exemption is carried into Entra.',
    actions: [
      { id: 'exempt-enumerate', label: 'Enumerate and classify the exempt accounts', cls: CLASS.AUTO, requires: [SCOPE.READ_DIR, SCOPE.READ_AUDIT, SCOPE.READ_AUTHMETH],
        creates: 'The 31 members with, for each: whether an Entra MFA method is registered, recent interactive vs non-interactive sign-in counts, and whether the account holds a directory role.',
        why: 'Turns a group name into a decision list. Service accounts belong on certificate or workload-identity auth, not on a human MFA exemption.',
        verify: 'Spot-check two entries against Entra admin center -> Users.' },
      { id: 'exempt-group', label: 'Create the reviewed exclusion group', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_GROUP],
        creates: 'An Entra group holding only the exemptions that survived review.',
        why: 'Carrying all 31 across unreviewed would import the risk rather than migrate the control.',
        manual: {
          where: 'Entra admin center -> Identity -> Groups -> New group',
          steps: [
            'Create CA-MFA-Exempt-Reviewed as an assigned security group.',
            'Add only accounts with a written justification and an expiry date.',
            'Exclude that group from the MFA policy, not from every policy.',
            'Put a recurring access review on the group.',
          ],
          confirm: 'Group member count should be materially lower than 31. Any account still there should have an owner and a review date.',
        } },
    ],
  },

  {
    key: 'admin-console',
    noPayloadReason:
      'The Entra policy that covers this is Microsoft-managed and already enabled. Microsoft-managed policies cannot be authored or replaced through Graph, so there is nothing to generate.',
    phase: 'translate',
    order: 80,
    title: 'Okta Admin Console policy -> phishing-resistant MFA for admin roles',
    oktaObject: { type: 'ACCESS_POLICY', name: 'Okta Admin Console', policyId: 'rstuqosypn12oRuHt357' },
    entraObject: { type: 'Conditional Access policy', name: 'Microsoft-managed: MFA for admins accessing Microsoft Admin Portals (already enabled)' },
    plain:
      'The Okta Admin Console policy is the strongest thing in the Okta tenant: it requires two factors with a device-bound ' +
      'possession factor, and its catch-all denies everything else. Entra already enforces MFA on admin portals through a ' +
      'Microsoft-managed policy covering 14 roles. The upgrade that matches Okta\'s device-bound requirement is to add an ' +
      'authentication strength of Phishing-resistant MFA.',
    differences: [
      'The Microsoft-managed policy covers Microsoft admin portals only. Okta\'s covers the Okta console. Neither covers the other, so both must stay until Okta is retired.',
      'The Microsoft-managed policy carries 12 user exclusions. Those are 12 admins reaching admin portals without the requirement, and Microsoft-managed policies cannot be edited in place; you duplicate them into a custom policy to change the exclusion set.',
      'Phishing-resistant MFA in Entra means Windows Hello, FIDO2 or certificate-based auth. Okta\'s device-bound possession factor is Okta Verify or a YubiKey. The Okta webauthn authenticator is currently INACTIVE, so users do not have a FIDO2 credential to fall back on.',
    ],
    prerequisites: ['Enable FIDO2 in the Entra authentication methods policy and register at least the admin population before requiring it.'],
    actions: [
      { id: 'admin-audit', label: 'Report admin auth strength', cls: CLASS.AUTO, requires: [SCOPE.READ_DIR, SCOPE.READ_AUTHMETH, SCOPE.READ_POLICY],
        creates: 'Every directory role holder with their registered methods, flagging who could not satisfy phishing-resistant MFA today, plus the 12 exclusions on the managed policy.',
        why: 'Requiring a method nobody has registered locks out the administrators.',
        verify: 'Compare the flagged list against Entra admin center -> Authentication methods -> User registration details.' },
      { id: 'admin-strength', label: 'Require phishing-resistant MFA for admins', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'A custom CA policy on admin roles with authentication strength set to Phishing-resistant MFA.',
        why: 'Matches the device-bound requirement Okta already enforces on its own console.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access -> Policies -> New policy',
          steps: [
            'Users: select Directory roles and pick the privileged roles. Exclude the break-glass group.',
            'Target resources: All cloud apps, or Microsoft Admin Portals to mirror the managed policy.',
            'Grant: Require authentication strength -> Phishing-resistant MFA.',
            'Register FIDO2 keys or Windows Hello for every admin BEFORE switching from Report-only to On.',
          ],
          confirm: 'Each admin signs in and is challenged for the strong method. Confirm the break-glass accounts are excluded first.',
        } },
    ],
  },

  {
    key: 'device-trust',
    noPayloadReason:
      'Requiring a compliant or hybrid-joined device is a grant control inside another policy, not a policy of its own. It is added to the bodies on the network and MFA steps.',
    phase: 'translate',
    order: 90,
    title: 'Okta device trust -> require compliant or hybrid-joined device',
    oktaObject: { type: 'ACCESS_POLICY', name: 'Device Registered Managed / DeviceTrust rules on Office 365, AWS SSO, Slack' },
    entraObject: { type: 'Conditional Access grant', name: 'Require device to be marked as compliant, or hybrid Azure AD joined' },
    plain:
      'Okta allows access from a registered and managed device and denies a registered-but-unmanaged one, per platform. ' +
      'Entra expresses this as a grant control requiring a compliant or hybrid-joined device. The idea matches, but the ' +
      'underlying signal does not: Okta\'s "managed" comes from its device-trust integration, while Entra\'s "compliant" comes ' +
      'from an Intune compliance policy evaluation. A device can be one and not the other.',
    differences: [
      'Okta managed=true is asserted by the Okta Verify client via the device-trust connector. Entra compliant=true is Intune\'s verdict against a compliance policy. Migrating means the device population has to be enrolled and compliant in Intune, not merely managed.',
      'Okta rules are written per platform (Windows, macOS, iOS, Android) as separate rules. Entra takes a device-platform condition on one policy.',
      'The Okta macOS DeviceTrust rule on Office 365 is INACTIVE, so macOS is unprotected today. Do not carry that gap forward silently.',
      'Entra needs the device to be registered in Entra ID. Devices that only exist in Okta and Jamf will not satisfy the grant.',
    ],
    reviewReason:
      'Intune currently holds 850 device records against 1,598 directory users. Requiring a compliant device before enrollment covers the fleet would block legitimate access. The gap has to be measured per app and per platform first.',
    prerequisites: ['Intune enrollment coverage for the populations in scope.', 'Hybrid join or Entra registration for Windows devices still managed only by AD.'],
    actions: [
      { id: 'dev-coverage', label: 'Report device compliance coverage', cls: CLASS.AUTO, requires: [SCOPE.READ_DIR],
        creates: 'Enrolled and compliant device counts by platform against the user population, and the users with no compliant device at all.',
        why: 'The size of that last group is the size of the outage if this is enforced early.',
        verify: 'Compare with Intune admin center -> Devices -> Overview.' },
      { id: 'dev-policy', label: 'Require compliant device', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'A CA policy requiring a compliant or hybrid-joined device for the mapped apps.',
        why: 'Replaces the Okta device-trust rules once Intune coverage is sufficient.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access -> Policies -> New policy',
          steps: [
            'Start with one app and one platform, mirroring the narrowest Okta rule rather than all of them at once.',
            'Conditions -> Device platforms: select only the platform you are migrating.',
            'Grant: Require device to be marked as compliant, and Require hybrid Azure AD joined device, combined with Require one of the selected controls.',
            'Report-only until the coverage report shows the population is enrolled.',
            'Note the existing PILOT - Require Compliant Mac for O365 policy is self-cancelling: macOS appears in both the include and exclude platform lists, so it matches nothing. Fix or delete it rather than copying its shape.',
          ],
          confirm: 'A compliant device signs in cleanly; a non-compliant one is blocked in report-only. Check both before enforcing.',
        } },
    ],
  },

  {
    key: 'legacy-auth',
    noPayloadReason:
      'Block Legacy Authentication [ORG] already exists and is enforcing. Nothing needs creating; the work is reviewing its five excluded accounts.',
    phase: 'translate',
    order: 100,
    title: 'Okta legacy-client rules -> Block legacy authentication (already live)',
    oktaObject: { type: 'ACCESS_POLICY', name: 'Office 365 rules: Deny Legacy Client Authentication, Require Modern Authentication, Service Accounts without MFA' },
    entraObject: { type: 'Conditional Access policy', name: 'Block Legacy Authentication [ORG] (enabled and enforcing)' },
    plain:
      'Okta blocks ActiveSync for one group and allows it for four named service accounts. Entra already has a tenant-wide ' +
      'policy blocking legacy authentication, and it is enforcing. This mapping is essentially complete; what remains is ' +
      'reconciling the exemptions, because the two systems currently exempt different accounts.',
    differences: [
      'The Okta rules are scoped to the Office 365 app. The Entra policy covers all cloud apps, so it is broader.',
      'Okta exempts 4 named users for ActiveSync; Entra excludes 5 users, two of which are deleted objects. Neither list was derived from the other.',
      'A CA policy scoped to users does not cover service principals. Legacy sign-ins by workload identities are out of scope for both.',
    ],
    actions: [
      { id: 'legacy-verify', label: 'Verify enforcement and reconcile exemptions', cls: CLASS.AUTO, requires: [SCOPE.READ_POLICY, SCOPE.READ_AUDIT],
        creates: 'The live policy state and app scope, the current exclusion list with deleted objects flagged, and the Okta-exempt service accounts side by side.',
        why: 'This policy was enabled but inert for six years because its app scope was set to None. Reading state alone is not proof; the app scope has to be checked too.',
        verify: 'Policy state enabled, includeApplications All, and recent legacy sign-ins showing the policy applied.' },
      { id: 'legacy-exempt', label: 'Clean up the exclusion list', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'An exclusion list with the deleted objects removed and the real service accounts documented.',
        why: 'A stale exclusion is an unowned hole in an enforcing policy.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access -> "Block Legacy Authentication [ORG]" -> Users -> Exclude',
          steps: [
            'Remove the two exclusions that resolve to deleted objects.',
            'For each remaining exclusion, record why it needs legacy auth and when that ends.',
            'Move the four Okta-exempt ActiveSync accounts onto modern auth rather than adding them here.',
          ],
          confirm: 'Exclusion count drops and every remaining entry resolves to a live object with an owner.',
        } },
    ],
  },

  {
    key: 'session-lifetime',
    noPayloadReason:
      'Sign-in frequency and persistent browser are session controls added to an existing policy, not a policy of their own.',
    phase: 'translate',
    order: 110,
    title: 'Okta session timeouts -> sign-in frequency (no idle-timeout equivalent)',
    oktaObject: { type: 'OKTA_SIGN_ON', name: 'Session settings on every sign-on policy: 10 Hour Session, SaaS-SFTP-GSP, Default Policy' },
    entraObject: { type: 'Conditional Access session control', name: 'Sign-in frequency and Persistent browser session' },
    plain:
      'Okta controls sessions with two numbers: an idle timeout and an absolute lifetime. Entra Conditional Access only has the ' +
      'absolute one, expressed as sign-in frequency. There is no idle timeout in Conditional Access. This is the clearest case ' +
      'on this page of an Okta setting with no direct equivalent, and translating it always loses something.',
    differences: [
      'Okta maxSessionIdleMinutes has no Conditional Access equivalent. The nearest behaviour is Continuous Access Evaluation, which re-evaluates on token refresh and on critical events, not on user inactivity.',
      'Okta maxSessionLifetimeMinutes=0 means unlimited. Several policies here use 0, including MFA-Exemption and the Default Policy catch-all rule.',
      'Entra sign-in frequency has a practical floor of one hour and applies to first-party and SAML apps differently.',
      'The "Classic Migrated" app policy on 69 applications uses a re-authentication window of PT43800H, which is five years. In Entra there is no way to express that; the default rolling window is 90 days.',
    ],
    noEquivalentNote:
      'Idle timeout does not exist in Conditional Access. If an idle timeout is a requirement, it has to be enforced by the application or accepted as lost in the migration.',
    reviewReason:
      'Okta session settings differ per policy (120, 600, 720 and unlimited minutes). Consolidating them into one sign-in frequency is a policy decision, not a translation.',
    actions: [
      { id: 'session-table', label: 'Tabulate every Okta session setting', cls: CLASS.AUTO, requires: [],
        creates: 'Idle timeout, absolute lifetime and re-authentication window for every sign-on and app policy, with the Entra sign-in frequency each would become.',
        why: 'Makes the inconsistency visible so one target value can be chosen deliberately.',
        verify: 'Numbers match the Okta admin console policy pages.' },
      { id: 'session-apply', label: 'Set sign-in frequency', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'A sign-in frequency session control on the relevant policies.',
        why: 'Bounds session length in the absence of an idle timeout.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access -> the target policy -> Session',
          steps: [
            'Check Sign-in frequency and set a periodic value. The existing MFA policy already uses 10 hours, which is close to the Okta Default Policy idle timeout of 600 minutes.',
            'Consider Persistent browser session -> Never persistent for the privileged apps that Okta protects with short sessions.',
            'Do not attempt to reproduce PT43800H. Treat it as a defect to close, not a setting to migrate.',
          ],
          confirm: 'After the interval elapses, a user is re-prompted. Verify on one pilot account before applying broadly.',
        } },
    ],
  },

  {
    key: 'behaviors-risk',
    noPayloadReason:
      'Okta behaviour detection maps to Identity Protection risk policies, which are configured in their own portal blade and are not Conditional Access bodies.',
    phase: 'translate',
    order: 120,
    title: 'Okta behavior detection -> Entra Identity Protection risk policies',
    oktaObject: { type: 'Behaviors', name: 'New ASN, New City, New Country, New Device, New Geo-Location, New IP, New State, Velocity' },
    entraObject: { type: 'Conditional Access risk conditions', name: 'Sign-in risk and User risk' },
    plain:
      'Okta has eight behavior detections configured and active. None of them are referenced by any policy rule: every sign-on ' +
      'rule carries an empty behaviors list and a risk level of ANY. So the detection exists but changes nothing today. ' +
      'Entra has a genuinely different mechanism, Identity Protection, which scores risk with its own models and is already ' +
      'wired into one enabled policy for high-risk sign-ins.',
    differences: [
      'Okta behaviors are deterministic heuristics you reference from a rule. Entra risk is an ML score you cannot inspect or tune. The two are not equivalent and there is no mapping table between an Okta behavior and an Entra risk level.',
      'Entra risk-based Conditional Access requires Entra ID P2. The tenant has P2 with 6 seats enabled and only 2 consumed, so licensing needs checking before scoping a risk policy to everyone.',
      'Because the domain is federated and Okta does the authentication, Entra sees less signal per sign-in than it would if it owned the login, which weakens risk scoring until federation changes.',
    ],
    reviewReason:
      'The eight Okta behaviors are unused, so there is nothing to preserve functionally. The decision is whether to build the equivalent in Entra rather than to migrate anything.',
    actions: [
      { id: 'risk-report', label: 'Report configured-but-unused detections', cls: CLASS.AUTO, requires: [SCOPE.READ_POLICY],
        creates: 'Each Okta behavior with the count of policy rules referencing it, and the current Entra risk policy coverage and P2 seat consumption.',
        why: 'Shows there is no working control being lost, which changes this from a migration task to a new-build decision.',
        verify: 'Confirm in the Okta admin console that no sign-on rule lists a behavior.' },
    ],
  },

  {
    key: 'ldap-interface',
    noPayloadReason:
      'Entra has no LDAP endpoint, so there is no Conditional Access body that can express this. It needs a different answer entirely.',
    phase: 'translate',
    order: 130,
    title: 'Okta LDAP Interface -> no Entra equivalent',
    oktaObject: { type: 'ACCESS_POLICY', name: 'LDAP Interface Password-Only Policy', policyId: 'rst1oezqiekybkY5W358' },
    entraObject: { type: 'none', name: 'No Conditional Access equivalent exists' },
    plain:
      'Okta exposes an LDAP interface so legacy applications can bind with a username and password. Its policy is password-only ' +
      'with a five-year re-authentication window, and Conditional Access cannot govern it because Entra has no LDAP interface. ' +
      'Entra Domain Services is a separate paid product with different semantics, not a migration target for this.',
    differences: [
      'LDAP bind is not an OAuth or SAML flow, so no Conditional Access policy can evaluate it, in either tenant.',
      'This surface will keep working after Entra takes over Conditional Access, governed only by Okta. It is a permanent gap unless the consuming applications are moved.',
    ],
    noEquivalentNote:
      'There is nothing to create in Entra. The options are to inventory and retire the LDAP consumers, or to keep Okta running for this one surface and accept that it sits outside Conditional Access.',
    reviewReason: 'Which applications bind to the Okta LDAP interface is not recorded anywhere we can read. That inventory has to be gathered from the application owners.',
    actions: [
      { id: 'ldap-inventory', label: 'Report what is known', cls: CLASS.AUTO, requires: [],
        creates: 'The policy configuration and its assignment, with an explicit note that the consuming-application list is unavailable from the API.',
        why: 'Records the gap rather than leaving a blank on the migration plan.',
        verify: 'Nothing to verify in Entra. This item closes by gathering the consumer list off-system.' },
    ],
  },

  {
    key: 'password-policy',
    noPayloadReason:
      'Password complexity, history and lockout live in Entra password protection and the on-premises domain policy. Conditional Access has no say in them.',
    phase: 'translate',
    order: 140,
    title: 'Okta password policies -> not a Conditional Access concern',
    oktaObject: { type: 'PASSWORD', name: 'IT Admin Account Policy, Active Directory Policy, Default Policy' },
    entraObject: { type: 'Entra Password Protection / on-premises AD', name: 'Not Conditional Access' },
    plain:
      'Okta holds three password policies. None of them translate into Conditional Access, which governs access decisions rather ' +
      'than credential rules. Because auction.com is federated and passwords originate in Active Directory, the authoritative ' +
      'password policy stays in AD. Entra Password Protection can add banned-password enforcement on top.',
    differences: [
      'All three Okta policies set maxAgeDays to 0, meaning no expiry. That is current guidance, and matches the Entra recommendation, so nothing needs to change.',
      'Minimum length differs between policies: 12 characters on the Active Directory policy, 8 on the IT Admin and Default policies. The admin policy being weaker than the general AD policy is worth a look.',
      'Entra Password Protection needs proxy agents installed on domain controllers to enforce banned lists against on-premises password changes.',
    ],
    reviewReason: 'The IT Admin Account Policy allows an 8-character password for 12 privileged accounts while the AD policy requires 12 characters. That inversion should be settled regardless of the migration.',
    actions: [
      { id: 'pw-table', label: 'Tabulate password policies', cls: CLASS.AUTO, requires: [],
        creates: 'Complexity, age and history settings for each policy with its assigned group and member count.',
        why: 'Surfaces the admin-policy inversion and confirms no expiry is set anywhere.',
        verify: 'Compare against the AD Default Domain Policy, which is the real enforcement point for federated users.' },
    ],
  },

  /* ---------------------------------------------------------------- phase 3 */
  {
    key: 'dead-rules',
    noPayloadReason:
      'This step is a cleanup review on both tenants. It creates nothing.',
    phase: 'validate',
    order: 150,
    title: 'Rules that cannot match, on both sides',
    oktaObject: { type: 'Various', name: 'Unreachable Okta rules' },
    entraObject: { type: 'Various', name: 'Self-cancelling and inert Entra policies' },
    plain:
      'Both tenants contain policy that looks active in a list view but can never match a sign-in. These are worth clearing ' +
      'before the migration, because carrying them across doubles the confusion and because a policy that reads as protective ' +
      'while doing nothing is worse than no policy at all.',
    differences: [
      'Okta: the Default Policy contains a second rule named "Default Rule" beneath a rule that matches every sign-in from anywhere, so it is unreachable. The Okta Dashboard policy has the same shape: an allow-all rule at priority 0 leaves the two rules beneath it dead.',
      'Entra: PILOT - Require Compliant Mac for O365 lists macOS in both the include and exclude platform lists. Exclude wins, so the policy matches nothing. Test App Policy has the same defect across android and iOS.',
      'Entra: one of the two policies named "Block Global Admins - Claude M365 Connector" is scoped to includeUsers ["None"], the sentinel meaning no users, so it can never match. Both copies are disabled.',
      'This is the same class of defect as the app scope set to None that left Block Legacy Authentication inert for six years. It is not detectable by reading state alone.',
    ],
    actions: [
      { id: 'dead-scan', label: 'Scan both tenants for unmatched policy', cls: CLASS.AUTO, requires: [SCOPE.READ_POLICY],
        creates: 'Every Okta rule shadowed by an earlier catch-all, and every Entra policy whose conditions cannot be satisfied, with the reason for each.',
        why: 'Finds controls that report as configured while matching nothing.',
        verify: 'For an Entra policy, confirm it never appears in appliedConditionalAccessPolicies on recent sign-ins. Absence from that array means it was never evaluated, which is stronger evidence than reading the config.' },
      { id: 'dead-fix', label: 'Remove or repair', cls: CLASS.MANUAL, requires: [SCOPE.WRITE_CA],
        creates: 'A cleaned-up policy set on both sides.',
        why: 'Reduces the surface being migrated and removes false assurance.',
        manual: {
          where: 'Entra admin center -> Protection -> Conditional Access; Okta admin console -> Security -> Authentication policies',
          steps: [
            'For the two self-cancelling Entra policies, remove the platform from the exclude list, or delete the policy if it was only ever a test.',
            'Delete the duplicate Block Global Admins policy and keep one, correctly scoped.',
            'In Okta, delete the unreachable rules rather than leaving them for someone to mistake for active configuration.',
            'When you fix one of these, re-check the sibling checks computed the same way. Correcting the legacy-auth app scope on 2026-09-04 flipped a second control to a false pass.',
          ],
          confirm: 'Re-run the scan; the finding list should be empty.',
        } },
    ],
  },

  {
    key: 'validate',
    noPayloadReason:
      'Validation reads the tenant and the sign-in logs. It creates nothing.',
    phase: 'validate',
    order: 160,
    title: 'Validate the migration',
    oktaObject: { type: 'n/a', name: '' },
    entraObject: { type: 'Sign-in logs', name: 'appliedConditionalAccessPolicies' },
    plain:
      'A Conditional Access policy is proven by sign-in evidence, not by its configuration page. For each policy you enable, ' +
      'the check is that it appears in the applied-policies array on real sign-ins with the result you expect, and that the ' +
      'population you excluded is genuinely unaffected.',
    differences: [
      'A policy absent from appliedConditionalAccessPolicies was never evaluated. A policy present with result notApplied was evaluated and did not match. The difference matters when diagnosing an inert policy.',
      'The v1.0 sign-in feed returns interactive sign-ins only. Non-interactive sign-ins, which is where service accounts, printers and SMTP relays live, need the beta endpoint with a non-interactive event-type filter. Judging blast radius from interactive data alone understates it.',
    ],
    actions: [
      { id: 'val-applied', label: 'Check applied policies on real sign-ins', cls: CLASS.AUTO, requires: [SCOPE.READ_AUDIT],
        creates: 'For each enabled policy, the count of recent sign-ins where it applied, did not apply, or was absent entirely, split by interactive and non-interactive.',
        why: 'This is the only evidence that a policy is doing what its configuration claims.',
        verify: 'Every policy you enabled appears with a non-zero applied count.' },
      { id: 'val-report', label: 'Export the migration record', cls: CLASS.AUTO, requires: [SCOPE.READ_POLICY, SCOPE.READ_AUDIT],
        creates: 'A dated snapshot of both tenants, every mapping decision, what was applied, and what remains open.',
        why: 'Gives the change record something to point at, and the next person a starting point.',
        verify: 'The export opens and the counts match this page.' },
    ],
  },
];

/* ------------------------------------------------------------------ helpers */

/**
 * Decide what a step is actually labelled, given the scopes really present.
 * An action declared AUTO whose scopes are missing becomes blocked, and says why.
 */
function capabilityFor(action, grantedScopes) {
  const need = action.requires || [];
  const missing = need.filter((s) => !grantedScopes.includes(s));
  if (action.cls === CLASS.MANUAL) {
    return { cls: CLASS.MANUAL, runnable: false, missing,
             reason: missing.length
               ? 'Requires ' + missing.join(', ') + ', which is not consented to the collector app. This is a human step in the Entra admin center.'
               : 'This is a human step in the Entra admin center.' };
  }
  if (action.cls === CLASS.REVIEW) return { cls: CLASS.REVIEW, runnable: false, missing, reason: 'A decision is needed before this can proceed.' };
  if (missing.length) {
    return { cls: CLASS.MANUAL, runnable: false, missing, downgraded: true,
             reason: 'Would be automatic, but ' + missing.join(', ') + ' is not granted to the collector app.' };
  }
  return { cls: CLASS.AUTO, runnable: true, missing: [], reason: 'Runs here, read-only, with the scopes already consented.' };
}

/** Roll per-action capability up to a step-level label. */
function classifyStep(step, grantedScopes) {
  const caps = (step.actions || []).map((a) => capabilityFor(a, grantedScopes));
  const anyAuto = caps.some((c) => c.cls === CLASS.AUTO);
  const anyManual = caps.some((c) => c.cls === CLASS.MANUAL);
  let cls;
  if (step.reviewReason || step.blockedBy) cls = CLASS.REVIEW;
  else if (anyAuto && anyManual) cls = 'mixed';
  else if (anyAuto) cls = CLASS.AUTO;
  else cls = CLASS.MANUAL;
  return { cls, caps };
}

const PHASES = [
  { key: 'review',    title: 'Review Okta policies',      blurb: 'What is configured today, read live from Okta.' },
  { key: 'prereq',    title: 'Complete prerequisites',    blurb: 'Things that must be true before any policy is enabled.' },
  { key: 'translate', title: 'Inspect mappings and gaps', blurb: 'Each Okta construct, what it becomes in Entra, and where it does not translate.' },
  { key: 'validate',  title: 'Validate',                  blurb: 'Prove each policy from sign-in evidence, not configuration.' },
];

module.exports = { MAPPINGS, SCOPE, CLASS, PHASES, capabilityFor, classifyStep };
