/**
 * oem-sipa.js — Source IP Anchoring: how ZIA relays selected traffic through ZPA so it
 * egresses from our own public addresses, and what that means for the Entra migration.
 *
 * Facts here that come from the live tenant (segment ids, gateway attachments, which zone
 * or named location holds an address) are refreshed by the collector into oem_sipa_anchor.
 * The narrative and the recommendation are authored.
 */
'use strict';

/** The three anchored egress addresses. PTR/site/carrier confirmed by reverse DNS. */
const ANCHORS = [
  { ip: '64.58.136.121', label: 'SNA01 office egress', site: 'SNA01',
    ptr: 'wsip-64-58-136-121.oc.oc.cox.net', carrier: 'Cox Communications (Orange County)',
    connectorGroup: 'SNA01-Connector Group',
    oktaZones: ['OfficeIpZone', 'LegacyIpZone'],
    entraLocation: 'Office Locations', entraTrusted: true,
    entraCoveringRange: '64.58.136.112/28' },
  { ip: '64.58.136.122', label: 'SNA01 office egress', site: 'SNA01',
    ptr: 'wsip-64-58-136-122.oc.oc.cox.net', carrier: 'Cox Communications (Orange County)',
    connectorGroup: 'SNA01-Connector Group',
    oktaZones: ['OfficeIpZone', 'LegacyIpZone'],
    entraLocation: 'Office Locations', entraTrusted: true,
    entraCoveringRange: '64.58.136.112/28' },
  { ip: '34.223.75.130', label: 'AWS us-west-2 connector egress', site: 'AWS us-west-2',
    ptr: 'ec2-34-223-75-130.us-west-2.compute.amazonaws.com', carrier: 'Amazon AWS (Elastic IP)',
    connectorGroup: 'AWS-W2 App Connector Group',
    oktaZones: ['OfficeIpZone', 'AWSIpZone'],
    entraLocation: 'AWS West-2', entraTrusted: false,
    entraCoveringRange: '34.223.75.128/28' },
];

/** The relay path, in the order a packet actually traverses it. */
const RELAY_PATH = [
  { step: 1, node: 'Zscaler Client Connector', detail: 'Forwards the user\'s internet-bound traffic to the nearest ZIA service edge.' },
  { step: 2, node: 'ZIA forwarding / SIPA rule', detail: 'A ZIA rule matches the destination against a SIPA application segment. Matching traffic is handed to a ZPA gateway instead of egressing from the Zscaler cloud.' },
  { step: 3, node: 'SIPA Gateway (id 1473898)', detail: 'The ZIA-to-ZPA handoff object. Points at one ZPA server group.' },
  { step: 4, node: 'Server group 288258444836732930', detail: 'Dynamic Server Discovery Group. Selects an App Connector from the attached connector groups.' },
  { step: 5, node: 'App Connector', detail: 'SNA01-Connector Group or AWS-W2 App Connector Group, depending on which connector answers.' },
  { step: 6, node: 'Public egress', detail: 'Traffic leaves from the connector\'s own public address: 64.58.136.121/.122 at SNA01, 34.223.75.130 in AWS us-west-2.' },
  { step: 7, node: 'Identity provider', detail: 'Okta today, Entra after the migration. The IdP sees one of our addresses, not a Zscaler cloud address, which is what makes a trusted-location policy possible for remote users.' },
];

/**
 * Authored fallback only. /api/oem/sipa derives the segment's real id, destinations, gateway
 * and server groups from the live ZPA/ZIA read (or the mirror when live fails) and says which.
 */
const SEGMENT_TO_REUSE = {
  id: '288258444836732977',
  name: 'SIPA - Okta',
  destinations: ['10.9.168.9', '*.okta.com', 'app.slack.com'],
  gateway: 'SIPA Gateway',
  gatewayId: '1473898',
  serverGroup: '288258444836732930',
  renameTo: 'SIPA - Entra',
};

const NAMING_CONVENTION = {
  rule: 'SIPA - <identity provider or service>',
  why:
    'The convention already exists in the tenant and four segments follow it: SIPA - Okta, SIPA - Teleport, ' +
    'SIPA - GraphQL, SIPA - MLH. The prefix makes every anchored segment sort together and makes it obvious ' +
    'at a glance which segments exist to control egress identity rather than to publish an internal app.',
  conforming: ['SIPA - Okta', 'SIPA - Teleport', 'SIPA - GraphQL', 'SIPA - MLH'],
  nonConforming: [
    { name: 'SIPA Mauchly - Verify', shouldBe: 'SIPA - Mauchly Verify', note: 'Missing the separator, so it sorts away from the others.' },
    { name: 'SIPA Mauc RCA TEST', shouldBe: 'SIPA - Mauchly RCA (test)', note: 'Abbreviated and shouty; also attached to two different gateways, which is worth a look on its own.' },
  ],
};

/**
 * The recommendation. Reuse the segment that already anchors IdP traffic rather than
 * building a second one, and rename it at cutover.
 */
const RECOMMENDATION = {
  headline: 'Reuse SIPA - Okta. Do not create a new segment.',
  body: [
    'SIPA - Okta already does this job. It is attached to SIPA Gateway, which points at server group ' +
    '288258444836732930, which selects connectors in SNA01-Connector Group and AWS-W2 App Connector Group. ' +
    'Those connectors are what egress from 64.58.136.121, 64.58.136.122 and 34.223.75.130. The anchoring ' +
    'path Entra needs is the path Okta is already using.',

    'So the migration is a destination change inside one segment, not a new segment. Add the Entra sign-in ' +
    'destinations alongside the Okta ones. Both identity providers then anchor through the same connectors and ' +
    'present the same three addresses, which is exactly what you want while both are live: the Entra named ' +
    'location and the Okta network zone are describing the same egress points, so a policy on either side ' +
    'behaves the same way.',

    'At cutover, remove the Okta destinations and rename the segment SIPA - Entra. Renaming at the end rather ' +
    'than the start keeps the name truthful throughout: while it carries both, it is still the Okta segment ' +
    'doing double duty. A rename in ZPA does not change the segment id, so the gateway attachment and the ' +
    'server group binding survive it.',
  ],
  addDestinations: [
    'myapps.microsoft.com',
    'login.microsoftonline.com',
    'login.microsoft.com',
    'login.windows.net',
    '*.msftidentity.com',
    '*.msidentity.com',
    'device.login.microsoftonline.com',
    'autologon.microsoftazuread-sso.com',
  ],
  destinationNote:
    'Anchor the sign-in endpoints, not all of Microsoft 365. Putting *.office.com or the Exchange endpoints ' +
    'behind SIPA would push bulk mail and Teams media through the App Connectors, which is a throughput problem ' +
    'and not what the anchor is for. The policy decision keys off the sign-in address only.',
  cautions: [
    'The three addresses are the source of anchored traffic, not a destination. They do not go into the segment\'s ' +
    'address list. They go into the Entra named location that the Conditional Access policy trusts. Adding your own ' +
    'egress address as a destination inside the segment that produces it is how you build a routing loop.',
    'AWS West-2 is currently a named location with Mark as trusted OFF, so a policy keyed on trusted locations ' +
    'ignores 34.223.75.130 today. Any user whose traffic happens to anchor via the AWS connector would be treated ' +
    'as off-network. That is the one change that has to happen before a trusted-location policy is enabled.',
    'Two of the ranges in SIPA - Teleport, 173.164.151.184/29 and 50.216.28.240/29, are also in the set of ranges ' +
    'Okta trusts and Entra does not. Same root cause: they are anchored egress that only Okta was ever told about.',
  ],
  steps: [
    { n: 1, where: 'ZPA admin portal -> Application Management -> Application Segments -> SIPA - Okta',
      what: 'Add the Entra sign-in destinations listed above to the existing address list. Leave the Okta entries in place. Save.' },
    { n: 2, where: 'ZIA admin portal -> Policies -> Forwarding Control',
      what: 'Confirm the SIPA forwarding rule that matches this segment still matches after the destinations change, and that its ZPA gateway is SIPA Gateway.' },
    { n: 3, where: 'Verify from a client',
      what: 'On a machine running Client Connector, browse to the sign-in endpoint and confirm the source address seen by the IdP is one of the three anchors. The SIPA Mauchly - Verify segment exists for exactly this check and points at whatismyip.com.' },
    { n: 4, where: 'Entra admin center -> Protection -> Conditional Access -> Named locations',
      what: 'Confirm all three addresses fall inside a named location and that each of those locations is marked trusted. 34.223.75.130 is the one that currently is not.' },
    { n: 5, where: 'After Okta is retired',
      what: 'Remove *.okta.com and app.slack.com from the segment, then rename it SIPA - Entra. Re-verify step 3 afterwards; the id does not change, so nothing should need re-attaching.' },
  ],
};

module.exports = { ANCHORS, RELAY_PATH, SEGMENT_TO_REUSE, NAMING_CONVENTION, RECOMMENDATION };
