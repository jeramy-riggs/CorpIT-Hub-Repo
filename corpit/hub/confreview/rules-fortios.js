'use strict';
/**
 * rules-fortios.js — Fortinet FortiOS checks.
 *
 * Works from a `show full-configuration` style export. FortiOS config is a nested
 * `config X / edit Y / set k v / next / end` tree, so it is parsed properly rather
 * than line-matched: shadow and duplicate analysis needs real objects and real
 * ordering, and a regex over the text cannot give either.
 */
const { finding, lines } = require('./confreview');
const P = 'fortios';

/* ── parser: config/edit/set/next/end into a tree, keeping line numbers ──── */
function parse(text) {
  const ls = lines(text);
  const root = { path: [], children: [], entries: [], set: {}, line: 0 };
  const stack = [root];
  ls.forEach((raw, idx) => {
    const l = raw.trim();
    const top = stack[stack.length - 1];
    let m;
    if ((m = /^config\s+(.+)$/i.exec(l))) {
      const node = { kind: 'config', name: m[1].trim(), path: top.path.concat(m[1].trim()),
                     children: [], entries: [], set: {}, line: idx + 1 };
      top.children.push(node); stack.push(node);
    } else if ((m = /^edit\s+(.+)$/i.exec(l))) {
      const key = m[1].trim().replace(/^"|"$/g, '');
      const node = { kind: 'edit', name: key, path: top.path.concat('edit ' + key),
                     children: [], entries: [], set: {}, line: idx + 1, order: top.entries.length };
      top.entries.push(node); stack.push(node);
    } else if (/^(next|end)$/i.test(l)) {
      if (stack.length > 1) stack.pop();
    } else if ((m = /^set\s+(\S+)\s*(.*)$/i.exec(l))) {
      top.set[m[1]] = { value: m[2].trim(), line: idx + 1, raw: l };
    } else if ((m = /^unset\s+(\S+)/i.exec(l))) {
      top.set[m[1]] = { value: '', line: idx + 1, raw: l, unset: true };
    }
  });
  return root;
}
function findConfig(node, name) {
  const want = name.toLowerCase();
  const hit = [];
  (function walk(n) {
    if (n.kind === 'config' && n.name.toLowerCase() === want) hit.push(n);
    n.children.forEach(walk);
    n.entries.forEach(e => { e.children.forEach(walk); });
  })(node);
  return hit;
}
const val = (n, k) => (n.set[k] ? n.set[k].value.replace(/^"|"$/g, '') : null);
const listOf = (n, k) => {
  const v = val(n, k);
  if (!v) return [];
  return v.split(/\s+/).map(s => s.replace(/^"|"$/g, '')).filter(Boolean);
};
const isAny = arr => arr.length === 1 && /^(all|any)$/i.test(arr[0]);

function run(text) {
  const tree = parse(text);
  const out = [];
  const complete = /^\s*config system global/mi.test(text) && /^\s*end\s*$/mi.test(text);
  const absent = complete ? 'likely' : 'possible';

  /* ── interfaces: management exposure ─────────────────────────────────── */
  findConfig(tree, 'system interface').forEach(cfg => cfg.entries.forEach(ifc => {
    const allow = listOf(ifc, 'allowaccess').map(s => s.toLowerCase());
    const role = (val(ifc, 'role') || '').toLowerCase();
    const ip = val(ifc, 'ip') || '';
    const insecure = allow.filter(a => a === 'telnet' || a === 'http');
    if (insecure.length) out.push(finding({
      id: 'FOS-IF-INSECURE-MGMT', category: 'Insecure protocol', severity: 'critical',
      confidence: 'confirmed',
      title: `Interface ${ifc.name} accepts ${insecure.join(' and ').toUpperCase()} management`,
      problem: `\`set allowaccess\` on ${ifc.name} includes ${insecure.join(', ')}, which are unencrypted.`,
      impact: 'Administrative credentials and session content cross the network in clear text and can be captured or hijacked.',
      remediation: `config system interface\n edit "${ifc.name}"\n  set allowaccess ${allow.filter(a => a !== 'telnet' && a !== 'http').join(' ') || 'https ssh'}\n next\nend`,
      remediationPlatform: P, section: `system interface / ${ifc.name}`,
      line: (ifc.set.allowaccess || {}).line || ifc.line,
      evidence: (ifc.set.allowaccess || {}).raw }));

    // management reachable from a WAN-facing interface
    if (role === 'wan' && allow.some(a => ['https', 'ssh', 'http', 'telnet'].includes(a))) {
      out.push(finding({
        id: 'FOS-IF-WAN-MGMT', category: 'Exposed management interface', severity: 'critical',
        confidence: 'confirmed',
        title: `Management is reachable on WAN interface ${ifc.name}`,
        problem: `${ifc.name} has role WAN and permits ${allow.filter(a => ['https','ssh','http','telnet'].includes(a)).join(', ')}.`,
        impact: 'The administrative interface is exposed to the internet, where it will be found by automated scanning and subjected to credential attacks.',
        remediation: `config system interface\n edit "${ifc.name}"\n  set allowaccess ping\n next\nend\nRestrict administration to an internal interface or a VPN, and set trusted hosts on every admin account.`,
        remediationPlatform: P, section: `system interface / ${ifc.name}`,
        line: (ifc.set.allowaccess || {}).line || ifc.line,
        evidence: (ifc.set.allowaccess || {}).raw }));
    }
  }));

  /* ── admin accounts ──────────────────────────────────────────────────── */
  findConfig(tree, 'system admin').forEach(cfg => cfg.entries.forEach(a => {
    const trust = ['trusthost1','trusthost2','trusthost3','trusthost4']
      .map(k => val(a, k)).filter(Boolean);
    const open = trust.length === 0 || trust.some(t => /^0\.0\.0\.0\s+0\.0\.0\.0$/.test(t));
    if (open) out.push(finding({
      id: 'FOS-ADMIN-NOTRUST', category: 'Missing access control', severity: 'high',
      confidence: trust.length ? 'confirmed' : absent,
      title: `Admin account "${a.name}" is not restricted by trusted host`,
      problem: trust.length
        ? `Trusted hosts for "${a.name}" include 0.0.0.0/0, which matches every source.`
        : `No trusthost entries are defined for "${a.name}", so it may be used from any source that can reach the management service.`,
      impact: 'Administrative login is exposed to every reachable network rather than the management subnet, making credential attacks possible from anywhere.',
      remediation: `config system admin\n edit "${a.name}"\n  set trusthost1 <mgmt-subnet> <mask>\n next\nend`,
      remediationPlatform: P, section: `system admin / ${a.name}`, line: a.line }));
    if ((val(a, 'accprofile') || '') === 'super_admin' && a.name.toLowerCase() === 'admin') {
      out.push(finding({
        id: 'FOS-ADMIN-DEFAULTNAME', category: 'Default credential', severity: 'medium',
        confidence: 'confirmed', title: 'Default super-admin account name "admin" is in use',
        problem: 'The built-in account name `admin` with the `super_admin` profile is present.',
        impact: 'Half of a credential pair is known to any attacker, so brute force and spraying only need the password.',
        remediation: 'Create a named super-admin account per administrator, verify access, then remove or rename the default.',
        remediationPlatform: P, section: `system admin / ${a.name}`, line: a.line }));
    }
  }));

  /* ── global hardening ────────────────────────────────────────────────── */
  findConfig(tree, 'system global').forEach(g => {
    const timeout = parseInt(val(g, 'admintimeout') || '', 10);
    if (!isNaN(timeout) && timeout > 30) out.push(finding({
      id: 'FOS-ADMIN-TIMEOUT', category: 'Weak setting', severity: 'medium', confidence: 'confirmed',
      title: `Administrative idle timeout is ${timeout} minutes`,
      problem: '`set admintimeout` is longer than a typical 5–30 minute policy.',
      impact: 'An unattended administrative session stays authenticated far longer than necessary.',
      remediation: 'config system global\n set admintimeout 15\nend', remediationPlatform: P,
      section: 'system global', line: g.set.admintimeout.line, evidence: g.set.admintimeout.raw }));
    if ((val(g, 'strong-crypto') || '').toLowerCase() === 'disable') out.push(finding({
      id: 'FOS-WEAK-CRYPTO', category: 'Weak setting', severity: 'high', confidence: 'confirmed',
      title: 'Strong cryptography is disabled',
      problem: '`set strong-crypto disable` permits weak ciphers and hashes for administrative and SSL services.',
      impact: 'Management and VPN sessions may negotiate algorithms that are no longer considered safe.',
      remediation: 'config system global\n set strong-crypto enable\nend', remediationPlatform: P,
      section: 'system global', line: g.set['strong-crypto'].line, evidence: g.set['strong-crypto'].raw }));
    if ((val(g, 'admin-telnet') || '').toLowerCase() === 'enable') out.push(finding({
      id: 'FOS-ADMIN-TELNET', category: 'Insecure protocol', severity: 'critical', confidence: 'confirmed',
      title: 'Telnet administration is enabled globally',
      problem: '`set admin-telnet enable` is present.',
      impact: 'Administrative credentials traverse the network in clear text.',
      remediation: 'config system global\n set admin-telnet disable\nend', remediationPlatform: P,
      section: 'system global', line: g.set['admin-telnet'].line, evidence: g.set['admin-telnet'].raw }));
  });

  /* ── SNMP ────────────────────────────────────────────────────────────── */
  findConfig(tree, 'system snmp community').forEach(cfg => cfg.entries.forEach(c => {
    const name = val(c, 'name') || c.name;
    if (/^(public|private|community|default)$/i.test(name)) out.push(finding({
      id: 'FOS-SNMP-DEFAULT', category: 'Default credential', severity: 'high', confidence: 'confirmed',
      title: `Default SNMP community "${name}"`,
      problem: 'A well-known default community string is configured.',
      impact: 'Anyone who can reach UDP/161 can enumerate interfaces, routes, sessions and the device inventory.',
      remediation: `config system snmp community\n edit ${c.name}\n  set name "<long random string>"\n next\nend`,
      remediationPlatform: P, section: `system snmp community / ${c.name}`, line: c.line }));
  }));
  if (findConfig(tree, 'system snmp community').some(c => c.entries.length) &&
      !findConfig(tree, 'system snmp user').some(c => c.entries.length)) {
    out.push(finding({
      id: 'FOS-SNMP-V12', category: 'Insecure protocol', severity: 'medium', confidence: 'confirmed',
      title: 'SNMPv1/v2c configured with no SNMPv3 user',
      problem: 'Community-based SNMP is in use and no v3 user is defined.',
      impact: 'The community string crosses the network in clear text and can be replayed.',
      remediation: 'config system snmp user\n edit "<name>"\n  set security-level auth-priv\n  set auth-proto sha256\n  set priv-proto aes256\n next\nend',
      remediationPlatform: P }));
  }

  /* ── NTP + logging ───────────────────────────────────────────────────── */
  const ntp = findConfig(tree, 'system ntp')[0];
  if (complete && (!ntp || (val(ntp, 'ntpsync') || '').toLowerCase() === 'disable')) out.push(finding({
    id: 'FOS-NO-NTP', category: 'Missing NTP', severity: 'medium', confidence: absent,
    title: 'NTP synchronisation is not enabled',
    problem: ntp ? '`set ntpsync disable` is present.' : 'No `config system ntp` block is present.',
    impact: 'Log and session timestamps drift, breaking correlation with switches and identity logs, and certificate validation can fail.',
    remediation: 'config system ntp\n set ntpsync enable\n set server-mode disable\nend', remediationPlatform: P,
    section: 'system ntp', line: ntp ? ntp.line : null }));

  const hasSyslog = findConfig(tree, 'log syslogd setting')
    .some(s => (val(s, 'status') || '').toLowerCase() === 'enable');
  if (complete && !hasSyslog) out.push(finding({
    id: 'FOS-NO-SYSLOG', category: 'Missing logging', severity: 'medium', confidence: absent,
    title: 'No syslog destination is enabled',
    problem: 'No `config log syslogd setting` block has `set status enable`.',
    impact: 'Traffic and event logs stay on the unit and are lost on failure or rotation, leaving no durable record for an investigation.',
    remediation: 'config log syslogd setting\n set status enable\n set server "<collector-ip>"\nend', remediationPlatform: P }));

  /* ── firewall policy analysis ────────────────────────────────────────── */
  const polCfgs = findConfig(tree, 'firewall policy');
  const policies = [];
  polCfgs.forEach(cfg => cfg.entries.forEach(p => policies.push({
    id: p.name, line: p.line, node: p,
    name: val(p, 'name') || `policy-${p.name}`,
    srcintf: listOf(p, 'srcintf'), dstintf: listOf(p, 'dstintf'),
    srcaddr: listOf(p, 'srcaddr'), dstaddr: listOf(p, 'dstaddr'),
    service: listOf(p, 'service'),
    action: (val(p, 'action') || 'deny').toLowerCase(),
    status: (val(p, 'status') || 'enable').toLowerCase(),
    logtraffic: (val(p, 'logtraffic') || '').toLowerCase(),
    schedule: val(p, 'schedule'), nat: (val(p, 'nat') || '').toLowerCase(),
    comments: val(p, 'comments'),
  })));

  policies.forEach(p => {
    const anySrc = isAny(p.srcaddr), anyDst = isAny(p.dstaddr), anySvc = isAny(p.service);
    const wideOpen = p.action === 'accept' && anySrc && anyDst && anySvc;

    /* A disabled policy is not permitting anything right now. Reporting it as a
       critical exposure would be a false positive; the honest report is that it
       is disabled, plus what it WOULD allow if someone re-enabled it. */
    if (p.status === 'disable') {
      out.push(finding({
        id: 'FOS-POLICY-DISABLED', category: 'Unused rule',
        severity: wideOpen ? 'medium' : 'info', confidence: 'confirmed',
        title: `Policy ${p.id} is disabled${wideOpen ? ' and would permit any-to-any if re-enabled' : ''}`,
        problem: `"${p.name}" is present but has \`set status disable\`, so it is not evaluated.` +
          (wideOpen ? ' Its source, destination and service are all "all" with action accept.' : ''),
        impact: wideOpen
          ? 'It is currently inert, so it is not an active exposure. The risk is latent: anyone who re-enables it — during an incident, or by accident — instantly opens unrestricted access on this path.'
          : 'Disabled rules accumulate and obscure the effective policy. If it is no longer needed it should be removed; if it is a break-glass rule it should say so in its comment.',
        remediation: wideOpen
          ? `Either remove it, or narrow it now so re-enabling is safe:\nconfig firewall policy\n edit ${p.id}\n  set srcaddr "<specific source>"\n  set dstaddr "<specific destination>"\n  set service "<specific services>"\n  set comments "<why this exists>"\n next\nend`
          : `Remove the policy, or record why it is retained:\nconfig firewall policy\n edit ${p.id}\n  set comments "<why this is kept disabled>"\n next\nend`,
        remediationPlatform: P, section: `firewall policy / ${p.id}`, line: p.line }));
      return;   // the active-exposure checks below do not apply to a disabled rule
    }

    if (wideOpen) {
      /* Severity has to account for interface scope. A rule that is all/all/ALL
         between two SPECIFIC interfaces — the standard site-to-site tunnel or
         transit pattern — is broad, but it is not the same animal as one that is
         also unscoped by interface. Rating every such rule "critical" on a real
         firewall produces dozens of alerts and trains the reader to ignore them. */
      const srcAnyIf = p.srcintf.length === 0 || isAny(p.srcintf);
      const dstAnyIf = p.dstintf.length === 0 || isAny(p.dstintf);
      const openIfs = (srcAnyIf ? 1 : 0) + (dstAnyIf ? 1 : 0);
      const sev = openIfs === 2 ? 'critical' : openIfs === 1 ? 'high' : 'medium';
      const pair = `${p.srcintf.join(',') || 'any'} → ${p.dstintf.join(',') || 'any'}`;
      out.push(finding({
        id: 'FOS-POLICY-ANYANY', category: 'Overly permissive rule', severity: sev,
        confidence: 'confirmed',
        title: openIfs === 2
          ? `Policy ${p.id} permits any source to any destination on any service, from any interface`
          : `Policy ${p.id} permits all traffic between ${pair}`,
        problem: `"${p.name}" has srcaddr, dstaddr and service all set to "all" with action accept, on the interface pair ${pair}.`,
        impact: openIfs === 2
          ? 'The firewall enforces nothing on this path from anywhere. Any host that can reach the unit passes to any host and any port, which is effectively an open router.'
          : `Everything on ${p.srcintf.join(',') || 'the source side'} can reach everything on ${p.dstintf.join(',') || 'the destination side'} on every port. This is the usual shape of a site-to-site or transit rule, so it may be intended — but it means a compromise on either side moves laterally to the other without further obstacle, and nothing here limits the blast radius.`,
        remediation: `config firewall policy\n edit ${p.id}\n  set dstaddr "<the subnets or hosts actually required>"\n  set service "<the services actually required>"\n next\nend`,
        remediationPlatform: P, section: `firewall policy / ${p.id}`, line: p.line,
        extra: { interfacePair: pair, interfaceScoped: openIfs === 0 } }));
    }
    else if (p.action === 'accept' && anySvc && (anySrc || anyDst)) out.push(finding({
      id: 'FOS-POLICY-BROAD', category: 'Overly permissive rule', severity: 'high',
      confidence: 'confirmed',
      title: `Policy ${p.id} permits any service ${anySrc ? 'from any source' : 'to any destination'}`,
      problem: `"${p.name}" leaves ${[anySrc ? 'srcaddr' : null, anyDst ? 'dstaddr' : null, 'service'].filter(Boolean).join(' and ')} set to "all".`,
      impact: 'Far more reachability than the rule\'s intent, and it will mask more specific rules placed after it.',
      remediation: `config firewall policy\n edit ${p.id}\n  set service "<only the services required>"\n next\nend`,
      remediationPlatform: P, section: `firewall policy / ${p.id}`, line: p.line }));

    if (p.action === 'accept' && (p.logtraffic === 'disable' || p.logtraffic === '')) out.push(finding({
      id: 'FOS-POLICY-NOLOG', category: 'Missing logging', severity: 'medium',
      confidence: p.logtraffic === 'disable' ? 'confirmed' : 'possible',
      title: `Policy ${p.id} accepts traffic without logging`,
      problem: p.logtraffic === 'disable'
        ? `"${p.name}" has \`set logtraffic disable\`.`
        : `"${p.name}" does not set \`logtraffic\`; the effective default depends on firmware and may be "utm" rather than "all".`,
      impact: 'Traffic allowed by this rule leaves no record, so neither an investigation nor a rule-usage review can see what it carried.',
      remediation: `config firewall policy\n edit ${p.id}\n  set logtraffic all\n next\nend`,
      remediationPlatform: P, section: `firewall policy / ${p.id}`, line: p.line }));

  });

  /* duplicate and shadowed rules — needs ordering, which is why we parsed */
  const key = p => [p.srcintf.join('|'), p.dstintf.join('|'), p.srcaddr.join('|'),
                    p.dstaddr.join('|'), p.service.join('|'), p.action].join('::');
  const seen = new Map();
  policies.filter(p => p.status !== 'disable').forEach(p => {
    const k = key(p);
    if (seen.has(k)) {
      const first = seen.get(k);
      out.push(finding({
        id: 'FOS-POLICY-DUPLICATE', category: 'Duplicate rule', severity: 'low', confidence: 'confirmed',
        title: `Policy ${p.id} duplicates policy ${first.id}`,
        problem: `"${p.name}" has the same interfaces, addresses, service and action as "${first.name}" (policy ${first.id}), which sits earlier in the list.`,
        impact: 'The later rule can never match, because the earlier one already decides this traffic. It adds review burden and can mislead during a change.',
        remediation: `Confirm the two are genuinely equivalent, then remove the redundant one:\nconfig firewall policy\n delete ${p.id}\nend`,
        remediationPlatform: P, section: `firewall policy / ${p.id}`, line: p.line,
        extra: { shadowedBy: first.id } }));
    } else seen.set(k, p);
  });

  // a broad earlier ACCEPT that fully covers a later, narrower rule
  const covers = (a, b) => {
    const sub = (x, y) => isAny(x) || (y.length > 0 && y.every(v => x.includes(v)));
    return sub(a.srcintf, b.srcintf) && sub(a.dstintf, b.dstintf) &&
           sub(a.srcaddr, b.srcaddr) && sub(a.dstaddr, b.dstaddr) && sub(a.service, b.service);
  };
  const live = policies.filter(p => p.status !== 'disable');
  live.forEach((later, li) => {
    for (let ei = 0; ei < li; ei++) {
      const earlier = live[ei];
      if (key(earlier) === key(later)) continue;              // already reported as duplicate
      if (!covers(earlier, later)) continue;
      out.push(finding({
        id: 'FOS-POLICY-SHADOW', category: 'Shadowed rule', severity: 'medium', confidence: 'likely',
        title: `Policy ${later.id} is shadowed by policy ${earlier.id}`,
        problem: `"${earlier.name}" (policy ${earlier.id}) is evaluated first and its interfaces, addresses and services fully cover "${later.name}" (policy ${later.id}).`,
        impact: earlier.action === later.action
          ? 'The later rule never matches, so it is dead configuration that misleads anyone reading the policy.'
          : `The later rule never takes effect, so traffic you believe is ${later.action === 'accept' ? 'allowed' : 'blocked'} is actually ${earlier.action === 'accept' ? 'allowed' : 'blocked'} by the earlier rule. This is a genuine policy inversion.`,
        remediation: `Reorder so the more specific rule is evaluated first:\nconfig firewall policy\n move ${later.id} before ${earlier.id}\nend`,
        remediationPlatform: P, section: `firewall policy / ${later.id}`, line: later.line,
        extra: { shadowedBy: earlier.id } }));
      break;   // one shadow report per rule is enough to act on
    }
  });

  return { findings: out, complete, parsed: { policies: policies.length } };
}

module.exports = { run, parse };
