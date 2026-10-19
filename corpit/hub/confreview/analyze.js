'use strict';
/**
 * analyze.js — orchestrates a configuration review.
 *
 * Read-only by construction: it takes text, returns findings, and never touches a
 * device or writes the config anywhere. The caller is responsible for not storing
 * what it passes in.
 */
const core = require('./confreview');
const cisco = require('./rules-cisco');
const fortios = require('./rules-fortios');

/* What each engine actually looks at, so a clean result can say what was covered
   rather than just "no findings" — an empty list is only meaningful next to a
   statement of what was examined. */
const COVERAGE = {
  'cisco-iosxe': [
    'VTY and console transport, timeouts and access-class',
    'HTTP/HTTPS management server and Smart Install',
    'SSH version enforcement',
    'Enable secret and password storage type',
    'AAA and password-encryption',
    'SNMP communities, write access, ACL binding and v3',
    'Syslog destination and log timestamps',
    'NTP servers',
    'Login banner',
    'DTP negotiation, trunk allowed VLANs and native VLAN',
    'Spanning-tree mode and BPDU Guard defaults',
    'Access-list permissiveness',
    'Interface descriptions on live ports',
  ],
  fortios: [
    'Per-interface allowaccess (Telnet/HTTP/SSH/HTTPS) and WAN management exposure',
    'Admin accounts, trusted hosts and default account names',
    'Global admin timeout, strong-crypto and Telnet administration',
    'SNMP communities, default strings and v3 users',
    'NTP synchronisation',
    'Syslog destination',
    'Firewall policy permissiveness (any/any/any and any-service)',
    'Per-policy traffic logging',
    'Disabled, duplicate and shadowed policies with ordering analysis',
  ],
};

/* Areas no text-only review can settle. Stated explicitly so the reader knows the
   boundary of the result rather than assuming silence means clean. */
const NOT_EVALUATED = {
  'cisco-iosxe': [
    'Whether configured ACLs are actually applied to the right interfaces in the right direction',
    'Routing correctness, route redistribution loops and administrative distance conflicts — these need the topology, not one device',
    'Whether a redundant path genuinely exists (needs the peer device configs)',
    'Software version against current advisories',
    'Configuration backup schedule, which lives outside the device config',
  ],
  fortios: [
    'Whether address and service objects resolve to the ranges their names imply',
    'UTM profile contents (AV, IPS, web filter) referenced by policies',
    'VPN phase 1/2 proposals and pre-shared key strength',
    'Whether a policy is genuinely unused — that needs hit counters from the live device, not the config text',
    'HA cluster health and whether failover actually works',
  ],
  unknown: ['Everything — the platform could not be identified with confidence.'],
};

function summarise(findings) {
  const by = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { if (by[f.severity] != null) by[f.severity]++; });
  const conf = { confirmed: 0, likely: 0, possible: 0 };
  findings.forEach(f => { if (conf[f.confidence] != null) conf[f.confidence]++; });
  return { bySeverity: by, byConfidence: conf, total: findings.length };
}

/* Lines the parser could not classify — surfaced so "no findings" cannot be
   mistaken for "everything was understood". */
function unsupported(text, vendorId) {
  const ls = core.lines(text);
  const out = [];
  const skip = /^\s*(!|#|$)/;
  ls.forEach((l, i) => {
    if (skip.test(l)) return;
    const t = l.trim();
    if (vendorId === 'fortios') {
      if (!/^(config|edit|set|unset|next|end|purge|delete|rename|move|clone)\b/i.test(t))
        out.push({ line: i + 1, text: core.scrub(t.slice(0, 160)) });
    } else if (vendorId === 'cisco-iosxe' || vendorId === 'cisco-nxos') {
      // IOS is free-form; only flag things that clearly are not config
      if (/^[<>]|^\s*\^\s*$|Invalid input|% /i.test(t))
        out.push({ line: i + 1, text: core.scrub(t.slice(0, 160)) });
    }
  });
  return out.slice(0, 40);
}

function analyze(text, opts) {
  opts = opts || {};
  const raw = String(text || '');
  if (!raw.trim()) {
    return { ok: false, error: 'EMPTY', message: 'No configuration text was supplied.' };
  }
  // Always detect, even when the caller forces a platform: a forced platform that
  // disagrees with the evidence produces zero findings, and zero findings must
  // never be allowed to read as "clean" when it really means "wrong parser".
  const detected = core.detectVendor(raw);
  const vendor = opts.vendor && opts.vendor !== 'auto'
    ? { id: opts.vendor, name: opts.vendor, score: null, confident: true, forced: true }
    : detected;

  let res = { findings: [], complete: false };
  let engine = null;
  if (vendor.id === 'cisco-iosxe' || vendor.id === 'cisco-nxos') { res = cisco.run(raw); engine = 'cisco-iosxe'; }
  else if (vendor.id === 'fortios') { res = fortios.run(raw); engine = 'fortios'; }

  const findings = res.findings.slice().sort((a, b) =>
    core.sevRank(a.severity) - core.sevRank(b.severity) ||
    (a.line || 0) - (b.line || 0));

  const device = core.hostnameOf(raw, vendor.id);
  const ls = core.lines(raw);

  return {
    ok: true,
    reviewedAt: new Date().toISOString(),
    device: device || null,
    vendor: { id: vendor.id, name: vendor.name, confident: !!vendor.confident,
              forced: !!vendor.forced, score: vendor.score, runnerUp: vendor.runnerUp || null },
    engine,
    stats: { lines: ls.length, bytes: raw.length,
             looksComplete: !!res.complete, policies: (res.parsed || {}).policies || null },
    summary: summarise(findings),
    findings,
    coverage: COVERAGE[engine] || [],
    notEvaluated: NOT_EVALUATED[engine] || NOT_EVALUATED.unknown,
    unsupported: engine ? unsupported(raw, vendor.id) : [],
    notes: buildNotes(vendor, engine, res, findings, detected),
  };
}

function buildNotes(vendor, engine, res, findings, detected) {
  const n = [];
  if (vendor.forced && detected && detected.id !== 'unknown' && detected.id !== vendor.id) {
    n.push({ kind: 'blocker',
      text: `You selected ${vendor.id}, but this configuration looks like ${detected.name}. ` +
            `The ${vendor.id} rules do not understand ${detected.name} syntax, so a small number of ` +
            `findings — or none at all — means the wrong parser ran, NOT that the configuration is clean. ` +
            `Set the platform to "Detect automatically" and review again.` });
  }
  if (vendor.forced && !findings.length && detected && detected.id === 'unknown') {
    n.push({ kind: 'caution',
      text: `No findings were produced and the platform could not be independently confirmed from the text. ` +
            `Check that this really is a ${vendor.id} configuration before reading this as a clean result.` });
  }
  if (!engine) n.push({ kind: 'blocker',
    text: `The platform could not be identified${vendor.runnerUp ? '' : ''}, so no vendor rules were run. Paste a full \`show running-config\` (Cisco) or \`show full-configuration\` (FortiGate), or pick the platform manually.` });
  if (engine && !vendor.confident && !vendor.forced) n.push({ kind: 'caution',
    text: `Platform detection was not decisive (best match ${vendor.name}). Remediation commands are withheld where the platform is uncertain — confirm the platform and re-run.` });
  if (engine && !res.complete) n.push({ kind: 'caution',
    text: 'This looks like a partial configuration rather than a complete export. Checks that fire on the ABSENCE of a directive are reported at lower confidence, because the directive may simply be outside the excerpt.' });
  const mismatch = vendor.forced && detected && detected.id !== 'unknown' && detected.id !== vendor.id;
  if (engine && !findings.length && !mismatch) n.push({ kind: 'ok',
    text: 'No findings were raised by the checks that ran. See the completed-checks list for what was examined and the not-evaluated list for what this review cannot determine from config text alone.' });
  n.push({ kind: 'warn',
    text: 'This review is read-only and changed nothing. Validate every proposed change in a maintenance window and take a configuration backup before applying it — several remediations here affect management reachability and can lock you out if applied incorrectly.' });
  return n;
}

module.exports = { analyze, COVERAGE, NOT_EVALUATED };
