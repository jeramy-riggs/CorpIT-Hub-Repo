'use strict';
/**
 * rules-cisco.js — Cisco IOS / IOS-XE checks.
 *
 * Each rule reads the parsed config and returns zero or more findings. Rules that
 * fire on the ABSENCE of a directive carry confidence "likely" at best, because an
 * excerpt may simply not contain that section — see the note the analyzer attaches
 * when the config does not look like a complete `show running-config`.
 */
const { finding, lines, ciscoSections } = require('./confreview');

const P = 'cisco-iosxe';

/* Treat a config as complete enough to reason about absences only if it has the
   markers a full running-config always has. */
function looksComplete(text) {
  return /^\s*end\s*$/mi.test(text) &&
         /^\s*(hostname|version)\s+\S+/mi.test(text) &&
         /^\s*line con 0/mi.test(text);
}

function run(text) {
  const ls = lines(text);
  const sec = ciscoSections(ls);
  const out = [];
  const complete = looksComplete(text);
  const absent = complete ? 'likely' : 'possible';
  const has = re => re.test(text);
  const each = (re, fn) => ls.forEach((l, i) => { const m = re.exec(l); if (m) fn(l, i, m); });

  /* ── management plane ───────────────────────────────────────────────── */
  each(/^\s*transport input .*\btelnet\b/i, (l, i) => out.push(finding({
    id: 'IOS-TELNET-VTY', category: 'Insecure protocol', severity: 'critical',
    confidence: 'confirmed', title: 'Telnet accepted on VTY lines',
    problem: 'The VTY lines accept Telnet, which carries the session and its credentials in clear text.',
    impact: 'Anyone able to capture traffic on a transit segment can read the login and every command typed, giving full device control.',
    remediation: 'transport input ssh', remediationPlatform: P,
    section: sec[i], line: i + 1, evidence: l.trim() })));

  if (has(/^\s*ip http server\s*$/mi)) {
    const i = ls.findIndex(l => /^\s*ip http server\s*$/i.test(l));
    out.push(finding({
      id: 'IOS-HTTP', category: 'Exposed management interface', severity: 'high',
      confidence: 'confirmed', title: 'HTTP management server enabled',
      problem: 'The unencrypted web management server is running.',
      impact: 'Management credentials and session data traverse the network in clear text, and the web stack widens the attack surface on the control plane.',
      remediation: 'no ip http server\nip http secure-server', remediationPlatform: P,
      line: i + 1, evidence: ls[i].trim() }));
  }

  if (has(/^\s*vstack\b/mi) || (complete && !has(/^\s*no vstack\b/mi) && has(/^\s*hostname/mi) && has(/^\s*vstack/mi))) {
    const i = ls.findIndex(l => /^\s*vstack/i.test(l));
    if (i >= 0) out.push(finding({
      id: 'IOS-SMARTINSTALL', category: 'Exposed management interface', severity: 'critical',
      confidence: 'confirmed', title: 'Smart Install client enabled',
      problem: 'The Smart Install client (vstack) is active.',
      impact: 'Smart Install accepts unauthenticated commands on TCP/4786 and has been used to overwrite configs and images remotely. It is a remote takeover path.',
      remediation: 'no vstack', remediationPlatform: P,
      line: i + 1, evidence: ls[i].trim() }));
  }

  each(/^\s*ip ssh version\s+1\b/i, (l, i) => out.push(finding({
    id: 'IOS-SSHV1', category: 'Weak setting', severity: 'high', confidence: 'confirmed',
    title: 'SSH version 1 permitted',
    problem: 'SSH is pinned to protocol version 1, which has known cryptographic weaknesses.',
    impact: 'Sessions can be downgraded and are vulnerable to integrity and man-in-the-middle attacks.',
    remediation: 'ip ssh version 2', remediationPlatform: P,
    line: i + 1, evidence: l.trim() })));

  if (complete && has(/^\s*(line vty|transport input ssh)/mi) && !has(/^\s*ip ssh version 2\b/mi)) {
    out.push(finding({
      id: 'IOS-SSH-NOVER', category: 'Weak setting', severity: 'medium', confidence: absent,
      title: 'SSH version 2 not explicitly enforced',
      problem: 'No `ip ssh version 2` directive is present, so the device may negotiate SSHv1 if a client asks for it.',
      impact: 'A client can negotiate the weaker protocol version, undoing the protection SSH is there to provide.',
      remediation: 'ip ssh version 2', remediationPlatform: P }));
  }

  /* ── credentials + AAA ──────────────────────────────────────────────── */
  each(/^\s*enable password\b/i, (l, i) => out.push(finding({
    id: 'IOS-ENABLE-PASSWORD', category: 'Weak authentication', severity: 'high',
    confidence: 'confirmed', title: 'Privileged EXEC uses `enable password`, not `enable secret`',
    problem: '`enable password` is stored reversibly (clear text or Cisco type 7), unlike `enable secret`.',
    impact: 'Anyone who can read the config — a backup, a TFTP capture, a screen share — recovers the privileged password instantly.',
    remediation: 'no enable password\nenable secret <choose a new password>', remediationPlatform: P,
    line: i + 1, evidence: l.trim().replace(/(password\s+\S+\s+).*/i, '$1<redacted>') })));

  const t7 = [];
  each(/\bpassword\s+7\s+[0-9A-Fa-f]{4,}/i, (l, i) => t7.push({ l, i }));
  if (t7.length) out.push(finding({
    id: 'IOS-TYPE7', category: 'Weak authentication', severity: 'high', confidence: 'confirmed',
    title: 'Type 7 (reversible) passwords in the configuration',
    problem: `${t7.length} password${t7.length > 1 ? 's are' : ' is'} stored with Cisco type 7 encoding, which is a trivially reversible cipher, not a hash.`,
    impact: 'A reader of the config recovers the plaintext in seconds with freely available tools.',
    remediation: 'Replace each with a hashed form, e.g.\n  username <name> secret <password>\n  enable secret <password>\nThen confirm no `password 7` strings remain.',
    remediationPlatform: P, line: t7[0].i + 1, count: t7.length,
    evidence: t7[0].l.trim().replace(/(7\s+)[0-9A-Fa-f]+/, '$1<redacted>') }));

  each(/^\s*enable secret\s+5\s+/i, (l, i) => out.push(finding({
    id: 'IOS-SECRET-MD5', category: 'Weak authentication', severity: 'medium',
    confidence: 'confirmed', title: 'Enable secret uses the MD5 (type 5) hash',
    problem: 'Type 5 is salted MD5, which modern hardware brute-forces quickly.',
    impact: 'A captured config yields the privileged password to an offline cracking attempt.',
    remediation: 'enable algorithm-type sha256 secret <choose a new password>', remediationPlatform: P,
    line: i + 1, evidence: l.trim().replace(/(secret\s+5\s+)\S+/i, '$1<redacted>') })));

  if (complete && !has(/^\s*aaa new-model\b/mi)) out.push(finding({
    id: 'IOS-NO-AAA', category: 'Missing access control', severity: 'high', confidence: absent,
    title: 'AAA is not enabled',
    problem: '`aaa new-model` is absent, so the device falls back to local line passwords with no centralised authentication, authorisation or command accounting.',
    impact: 'No per-administrator identity, no central revocation when someone leaves, and no record of who ran which command.',
    remediation: 'aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local\naaa accounting commands 15 default start-stop group tacacs+',
    remediationPlatform: P }));

  if (complete && !has(/^\s*service password-encryption\b/mi)) out.push(finding({
    id: 'IOS-NO-PWENC', category: 'Weak authentication', severity: 'low', confidence: absent,
    title: '`service password-encryption` is not set',
    problem: 'Line and username passwords that are not hashed will be stored in clear text.',
    impact: 'Shoulder-surfing a config, or an unencrypted backup, exposes credentials. Note this only applies weak type 7 encoding — it is a hygiene control, not a substitute for `secret`.',
    remediation: 'service password-encryption', remediationPlatform: P }));

  /* ── SNMP ───────────────────────────────────────────────────────────── */
  each(/^\s*snmp-server community\s+(\S+)(.*)$/i, (l, i, m) => {
    const community = m[1], rest = m[2] || '';
    const weak = /^(public|private|cisco|community|snmp|admin|default)$/i.test(community);
    const rw = /\bRW\b/i.test(rest);
    const acl = /\b(RO|RW)\s+(\S+)/i.exec(rest);
    const redacted = l.trim().replace(community, weak ? community : '<redacted>');
    if (weak) out.push(finding({
      id: 'IOS-SNMP-DEFAULT', category: 'Default credential', severity: rw ? 'critical' : 'high',
      confidence: 'confirmed', title: `Default SNMP community string "${community}"${rw ? ' with WRITE access' : ''}`,
      problem: `The community string "${community}" is a well-known default${rw ? ' and it is configured read-write' : ''}.`,
      impact: rw
        ? 'Anyone who can reach the SNMP port can rewrite the configuration or pull it via TFTP — this is full device compromise.'
        : 'Anyone who can reach the SNMP port can enumerate interfaces, ARP, routes and the running topology.',
      remediation: `no snmp-server community ${community}\nsnmp-server community <long random string> RO <acl-number>`,
      remediationPlatform: P, line: i + 1, evidence: redacted }));
    else if (rw) out.push(finding({
      id: 'IOS-SNMP-RW', category: 'Weak setting', severity: 'high', confidence: 'confirmed',
      title: 'SNMP community configured read-write',
      problem: 'A read-write community allows configuration change over SNMP.',
      impact: 'Possession of the string permits writing the config or triggering a TFTP config transfer.',
      remediation: 'Prefer read-only, and restrict with an ACL:\n  snmp-server community <string> RO <acl-number>',
      remediationPlatform: P, line: i + 1, evidence: redacted }));
    if (!acl || !acl[2]) out.push(finding({
      id: 'IOS-SNMP-NOACL', category: 'Missing access control', severity: 'medium',
      confidence: 'confirmed', title: 'SNMP community has no access-list restriction',
      problem: 'The community is not bound to an access-list, so it answers any source that can reach UDP/161.',
      impact: 'Widens who can poll the device; combined with a guessable string it becomes an information-disclosure path.',
      remediation: 'snmp-server community <string> RO <acl-number>\naccess-list <acl-number> permit <management subnet>',
      remediationPlatform: P, line: i + 1, evidence: redacted }));
  });

  if (has(/^\s*snmp-server community/mi) && !has(/^\s*snmp-server group .* v3/mi)) out.push(finding({
    id: 'IOS-SNMP-V12', category: 'Insecure protocol', severity: 'medium', confidence: 'confirmed',
    title: 'SNMPv1/v2c in use with no SNMPv3 configured',
    problem: 'Community-based SNMP sends the community string in clear text and offers no integrity or encryption.',
    impact: 'The string can be captured passively and replayed from anywhere that can reach the device.',
    remediation: 'snmp-server group <grp> v3 priv\nsnmp-server user <user> <grp> v3 auth sha <auth-pass> priv aes 128 <priv-pass>',
    remediationPlatform: P }));

  /* ── logging, time, backup ──────────────────────────────────────────── */
  if (complete && !has(/^\s*logging (host|server)\s+\S+/mi)) out.push(finding({
    id: 'IOS-NO-SYSLOG', category: 'Missing logging', severity: 'medium', confidence: absent,
    title: 'No syslog destination configured',
    problem: 'No `logging host` is present, so log messages stay in a small local buffer that is lost on reload.',
    impact: 'No durable record for troubleshooting an outage or investigating an incident after the fact.',
    remediation: 'logging host <collector-ip>\nlogging trap informational', remediationPlatform: P }));

  if (complete && !has(/^\s*ntp server\s+\S+/mi)) out.push(finding({
    id: 'IOS-NO-NTP', category: 'Missing NTP', severity: 'medium', confidence: absent,
    title: 'No NTP server configured',
    problem: 'The device has no external time source.',
    impact: 'Log timestamps drift and cannot be correlated across devices, which undermines both troubleshooting and any incident timeline. Certificate validation can also fail.',
    remediation: 'ntp server <ntp-ip>\nntp server <ntp-ip-2>', remediationPlatform: P }));

  if (complete && !has(/^\s*service timestamps log\b/mi)) out.push(finding({
    id: 'IOS-NO-TIMESTAMP', category: 'Missing logging', severity: 'low', confidence: absent,
    title: 'Log messages are not timestamped',
    problem: '`service timestamps log datetime` is absent.',
    impact: 'Log lines cannot be placed on a timeline, making correlation with other devices impossible.',
    remediation: 'service timestamps log datetime msec localtime show-timezone', remediationPlatform: P }));

  /* ── line hygiene ───────────────────────────────────────────────────── */
  each(/^\s*exec-timeout\s+0\s+0\s*$/i, (l, i) => out.push(finding({
    id: 'IOS-EXEC-TIMEOUT', category: 'Weak setting', severity: 'medium', confidence: 'confirmed',
    title: 'Management session never times out',
    problem: `\`exec-timeout 0 0\` disables the idle timeout on ${sec[i] || 'a line'}.`,
    impact: 'An unattended or forgotten session stays privileged indefinitely, and a walk-up or hijacked terminal inherits it.',
    remediation: 'exec-timeout 10 0', remediationPlatform: P,
    section: sec[i], line: i + 1, evidence: l.trim() })));

  // VTY blocks with no access-class
  const vtyBlocks = [];
  ls.forEach((l, i) => { if (/^\s*line vty\b/i.test(l)) vtyBlocks.push(i); });
  vtyBlocks.forEach(start => {
    let end = start + 1;
    while (end < ls.length && (/^\s+\S/.test(ls[end]) || !ls[end].trim())) end++;
    const body = ls.slice(start, end).join('\n');
    if (!/access-class\s+\S+\s+in/i.test(body)) out.push(finding({
      id: 'IOS-VTY-NOACL', category: 'Missing access control', severity: 'high',
      confidence: 'confirmed', title: 'VTY lines accept connections from any source',
      problem: `\`${ls[start].trim()}\` has no inbound \`access-class\`, so management sessions are accepted from any reachable address.`,
      impact: 'The management plane is exposed to every segment that can route to the device, rather than to the management network only.',
      remediation: 'ip access-list standard MGMT\n permit <management subnet>\nline vty 0 15\n access-class MGMT in vrf-also',
      remediationPlatform: P, section: ls[start].trim(), line: start + 1, evidence: ls[start].trim() }));
  });

  if (complete && !has(/^\s*banner (login|motd)\b/mi)) out.push(finding({
    id: 'IOS-NO-BANNER', category: 'Operational', severity: 'info', confidence: absent,
    title: 'No login banner configured',
    problem: 'No login or MOTD banner is set.',
    impact: 'Many jurisdictions and audit regimes expect an explicit authorised-use notice before login.',
    remediation: 'banner login ^C\n<your approved authorised-use notice>\n^C', remediationPlatform: P }));

  /* ── switching: VLAN, trunk, spanning tree ──────────────────────────── */
  each(/^\s*switchport mode dynamic (auto|desirable)/i, (l, i) => out.push(finding({
    id: 'IOS-DTP', category: 'VLAN misconfiguration', severity: 'high', confidence: 'confirmed',
    title: 'Port negotiates trunking automatically (DTP)',
    problem: `${sec[i] || 'An interface'} is left in dynamic ${/auto/i.test(l) ? 'auto' : 'desirable'} mode, so it will form a trunk with any peer that asks.`,
    impact: 'A device plugged into this port can negotiate a trunk and reach every VLAN the switch carries — classic VLAN hopping.',
    remediation: 'switchport mode access\nswitchport nonegotiate', remediationPlatform: P,
    section: sec[i], line: i + 1, evidence: l.trim() })));

  // trunk without an allowed list
  const trunkIfs = [];
  ls.forEach((l, i) => { if (/^\s*switchport mode trunk\b/i.test(l)) trunkIfs.push(i); });
  trunkIfs.forEach(i => {
    const s = sec[i];
    const blockStart = ls.findIndex((l, k) => k <= i && l.trim() === s);
    let end = blockStart + 1;
    while (end < ls.length && (/^\s+\S/.test(ls[end]) || !ls[end].trim())) end++;
    const body = ls.slice(blockStart, end).join('\n');
    if (!/switchport trunk allowed vlan/i.test(body)) out.push(finding({
      id: 'IOS-TRUNK-ALLVLAN', category: 'VLAN misconfiguration', severity: 'medium',
      confidence: 'confirmed', title: 'Trunk carries every VLAN',
      problem: `${s || 'A trunk interface'} has no \`switchport trunk allowed vlan\`, so it forwards all VLANs by default.`,
      impact: 'Broadcast domains extend further than intended and a compromised segment gains reachability it should not have. It also widens spanning-tree scope.',
      remediation: 'switchport trunk allowed vlan <only the VLANs this link needs>',
      remediationPlatform: P, section: s, line: i + 1, evidence: ls[i].trim() }));
    if (/switchport trunk native vlan 1\b/i.test(body) || !/switchport trunk native vlan/i.test(body)) {
      out.push(finding({
        id: 'IOS-NATIVE-VLAN1', category: 'VLAN misconfiguration', severity: 'medium',
        confidence: /native vlan 1\b/i.test(body) ? 'confirmed' : 'likely',
        title: 'Trunk uses the default native VLAN (1)',
        problem: `${s || 'A trunk'} ${/native vlan 1\b/i.test(body) ? 'is set to native VLAN 1' : 'does not set a native VLAN, so it defaults to VLAN 1'}.`,
        impact: 'Untagged frames land in VLAN 1, which is also the default access VLAN — the basis of double-tagging VLAN hopping.',
        remediation: 'switchport trunk native vlan <unused vlan id>', remediationPlatform: P,
        section: s, line: i + 1, evidence: ls[i].trim() }));
    }
  });

  if (complete && !has(/^\s*spanning-tree portfast (edge )?bpduguard default/mi)) out.push(finding({
    id: 'IOS-NO-BPDUGUARD', category: 'Spanning-tree', severity: 'medium', confidence: absent,
    title: 'BPDU Guard is not enabled by default on edge ports',
    problem: '`spanning-tree portfast bpduguard default` is absent.',
    impact: 'A switch or a bridging device plugged into an access port can inject BPDUs, take over the root role and reshape or black-hole the topology.',
    remediation: 'spanning-tree portfast edge bpduguard default', remediationPlatform: P }));

  if (complete && has(/^\s*spanning-tree mode pvst\s*$/mi)) out.push(finding({
    id: 'IOS-STP-PVST', category: 'Spanning-tree', severity: 'low', confidence: 'confirmed',
    title: 'Classic PVST+ in use rather than Rapid PVST+',
    problem: 'The spanning-tree mode is legacy PVST+.',
    impact: 'Topology changes take tens of seconds to converge instead of a few, extending every link-failure outage.',
    remediation: 'spanning-tree mode rapid-pvst', remediationPlatform: P }));

  /* ── ACL hygiene ────────────────────────────────────────────────────── */
  each(/^\s*(?:access-list \d+\s+)?permit\s+ip\s+any\s+any\s*$/i, (l, i) => out.push(finding({
    id: 'IOS-ACL-ANYANY', category: 'Overly permissive rule', severity: 'medium',
    confidence: 'confirmed', title: 'Access-list permits all IP traffic',
    problem: `${sec[i] || 'An access-list'} contains an unrestricted \`permit ip any any\`.`,
    impact: 'If this list is applied for filtering it does nothing; if it is applied to management or a VTY it removes the restriction entirely.',
    remediation: 'Narrow the entry to the sources and destinations that are actually required, and keep an explicit deny at the end for visibility.',
    remediationPlatform: P, section: sec[i], line: i + 1, evidence: l.trim() })));

  /* ── interface hygiene ──────────────────────────────────────────────── */
  let noDesc = 0, firstNoDesc = null;
  ls.forEach((l, i) => {
    if (!/^interface\s+(Gigabit|TenGigabit|Twenty|Forty|Hundred|Ethernet)/i.test(l.trim())) return;
    let end = i + 1;
    while (end < ls.length && (/^\s+\S/.test(ls[end]) || !ls[end].trim())) end++;
    const body = ls.slice(i, end).join('\n');
    if (/^\s*shutdown\s*$/mi.test(body)) return;      // a disabled spare needs no description
    if (!/^\s*description\s+\S/mi.test(body)) { noDesc++; if (firstNoDesc == null) firstNoDesc = i; }
  });
  if (noDesc >= 5) out.push(finding({
    id: 'IOS-NO-DESC', category: 'Operational', severity: 'info', confidence: 'confirmed',
    title: `${noDesc} live interfaces have no description`,
    problem: 'Interfaces that are not shut down carry no description.',
    impact: 'Nobody can tell what is on a port without tracing the cable, which slows every change and every outage.',
    remediation: 'description <what is connected here>', remediationPlatform: P,
    line: firstNoDesc != null ? firstNoDesc + 1 : null, count: noDesc,
    evidence: firstNoDesc != null ? ls[firstNoDesc].trim() : null }));

  return { findings: out, complete };
}

module.exports = { run, looksComplete };
