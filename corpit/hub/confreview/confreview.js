'use strict';
/**
 * confreview.js — read-only configuration review for network switches and firewalls.
 *
 * This module NEVER writes to a device and NEVER persists a configuration. It is a
 * pure function of the text (or the collected objects) handed to it.
 *
 * Design rules that keep the output trustworthy:
 *   1. Every finding cites the exact line number and the line text it fired on, so a
 *      reader can verify it against their own config rather than trusting the tool.
 *   2. `confidence` separates what the config literally says ("confirmed") from what
 *      is inferred from an absence or from context ("likely"/"possible"). An absence
 *      is never "confirmed" — a config excerpt may simply not include that section.
 *   3. Remediation commands are tagged with the platform they are valid for and are
 *      withheld unless the detected platform matches. A Cisco command shown for a
 *      FortiGate is worse than no command at all.
 *   4. Anything the parser does not understand is reported back as an unsupported or
 *      unparsed construct rather than silently ignored, so "no findings" cannot be
 *      confused with "nothing was read".
 */

/* ── severity + confidence vocabularies ─────────────────────────────────── */
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const sevRank = s => { const i = SEV.indexOf(s); return i < 0 ? 99 : i; };

/* ── vendor detection ───────────────────────────────────────────────────────
   Scored rather than first-match: a config that mentions "interface" proves
   nothing, but "config system global" + "set vdom" is decisive. */
const VENDOR_SIGNS = [
  { id: 'fortios', name: 'Fortinet FortiOS', signs: [
      [/^\s*config system global\b/mi, 5], [/^\s*config firewall policy\b/mi, 5],
      [/^\s*set vdom\b/mi, 3], [/^\s*config vdom\b/mi, 3], [/\bnext\s*$/mi, 1],
      [/^\s*edit\s+"?\d+"?\s*$/mi, 1], [/#config-version=FG/mi, 6] ] },
  { id: 'cisco-iosxe', name: 'Cisco IOS / IOS-XE', signs: [
      [/^\s*version \d+\.\d+/mi, 2], [/^\s*service timestamps\b/mi, 3],
      [/^\s*line vty\b/mi, 3], [/^\s*switchport mode\b/mi, 3],
      [/^\s*spanning-tree mode\b/mi, 3], [/^\s*ip http server\b/mi, 2],
      [/^\s*boot system flash bootflash:.*iosxe/mi, 5], [/^\s*enable secret\b/mi, 2],
      [/^\s*hostname \S+/mi, 1], [/^\s*interface (Gigabit|TenGigabit|Twenty|Forty|Hundred)/mi, 3] ] },
  { id: 'cisco-nxos', name: 'Cisco NX-OS', signs: [
      [/^\s*feature \w+/mi, 5], [/^\s*vpc domain\b/mi, 4], [/^\s*interface Ethernet\d+\/\d+/mi, 3] ] },
  { id: 'arista-eos', name: 'Arista EOS', signs: [
      [/^\s*management api http-commands/mi, 5], [/^\s*interface Ethernet\d+$/mi, 2],
      [/^\s*daemon TerminAttr/mi, 5] ] },
  { id: 'juniper-junos', name: 'Juniper Junos', signs: [
      [/^\s*set (system|interfaces|security) /mi, 4], [/^\s*system \{/mi, 4],
      [/\bapply-groups\b/mi, 2] ] },
  { id: 'paloalto-panos', name: 'Palo Alto PAN-OS', signs: [
      [/^\s*set deviceconfig system/mi, 5], [/^\s*set rulebase security rules/mi, 5] ] },
];

function detectVendor(text) {
  const scores = VENDOR_SIGNS.map(v => ({
    id: v.id, name: v.name,
    score: v.signs.reduce((n, [re, w]) => n + (re.test(text) ? w : 0), 0),
  })).sort((a, b) => b.score - a.score);
  const top = scores[0], second = scores[1];
  if (!top || top.score < 3) {
    return { id: 'unknown', name: 'Unrecognised', score: top ? top.score : 0,
             confident: false, runnerUp: null };
  }
  return { id: top.id, name: top.name, score: top.score,
           // a clear winner means platform-specific remediation is safe to print
           confident: top.score >= 5 && top.score >= (second ? second.score * 1.6 : 0),
           runnerUp: second && second.score > 0 ? { id: second.id, score: second.score } : null };
}

/* ── shared helpers ─────────────────────────────────────────────────────── */
function lines(text) {
  return String(text).replace(/\r\n?/g, '\n').split('\n');
}
function hostnameOf(text, vendor) {
  let m;
  if (vendor === 'fortios') {
    m = /^\s*set hostname "?([^"\n]+)"?/mi.exec(text);
    if (m) return m[1].trim();
    m = /#config-version=\S+?-([A-Za-z0-9_-]+)-/i.exec(text);
    return m ? m[1] : null;
  }
  m = /^\s*hostname\s+(\S+)/mi.exec(text);
  if (m) return m[1];
  m = /^\s*set system host-name\s+(\S+)/mi.exec(text);
  return m ? m[1] : null;
}

/* Evidence is the one place raw config text leaves the server, so it is scrubbed
   here rather than in each rule — a rule author cannot forget a redaction that the
   constructor performs. */
const SECRET_PATTERNS = [
  // everything AFTER a secret keyword goes, not just the next token: forms like
  // `set psksecret ENC <blob>` would otherwise lose only the "ENC" marker.
  // The optional \d{1,2} is Cisco's encoding type (`password 7 <hash>`) and is
  // deliberately bounded — an unbounded \d+ swallows a numeric key such as
  // `ntp authentication-key 1 md5 0123456789` into the KEPT capture group.
  [/(\b(?:password|passwd|secret|psksecret|privatekey|passphrase|auth-pwd|priv-pwd|md5|key-string)\b\s+(?:\d{1,2}\s+)?)(?:ENC\s+)?\S.*$/gim, '$1<redacted>'],
  [/(\bcommunity\s+)(\S+)/gi, '$1<redacted>'],
  [/(\bkey\s+\d*\s*)(\S+)/gi, '$1<redacted>'],
  [/\$\d[a-z]?\$\S+/gi, '<redacted-hash>'],
];
function scrub(s) {
  if (!s) return s;
  let out = String(s);
  SECRET_PATTERNS.forEach(([re, rep]) => { out = out.replace(re, rep); });
  return out;
}

/* A finding is only ever built here, so the shape can never drift between rules. */
function finding(o) {
  return {
    id: o.id,
    category: o.category,
    severity: o.severity,
    confidence: o.confidence,           // confirmed | likely | possible
    title: o.title,
    problem: o.problem,
    impact: o.impact,
    remediation: o.remediation || null,
    remediationPlatform: o.remediationPlatform || null,
    section: o.section || null,
    line: o.line || null,               // 1-indexed
    evidence: scrub(o.evidence) || null,   // config text it fired on, secrets removed
    count: o.count || 1,
    extra: o.extra || null,
  };
}

/* ── section tracking for indentation-based configs ─────────────────────── */
function ciscoSections(ls) {
  // returns, per line index, the top-level block it belongs to (interface X, line vty…)
  const out = new Array(ls.length).fill(null);
  let cur = null;
  ls.forEach((l, i) => {
    if (/^\S/.test(l) && l.trim()) {
      cur = /^(interface|line|router|vlan|ip access-list|class-map|policy-map|banner)\b/i.test(l)
        ? l.trim() : null;
    } else if (!l.trim()) { /* keep section across blank lines inside a block */ }
    out[i] = cur;
  });
  return out;
}

module.exports = { SEV, sevRank, detectVendor, lines, hostnameOf, finding, ciscoSections, scrub };
