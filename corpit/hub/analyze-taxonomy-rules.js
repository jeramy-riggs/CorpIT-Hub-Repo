#!/usr/bin/env node
/**
 * analyze-taxonomy-rules.js — Phase 1 v2 (NO API KEY REQUIRED)
 * READ-ONLY deterministic clustering of sdops_request subjects.
 *
 * v2 changes:
 *   - System Notifications / Automated Alerts quarantined FIRST (machine noise
 *     kept out of real IT categories; nothing deleted, fully reversible).
 *   - Word-BOUNDARY matching (no more "word" matching inside "password").
 *   - Added AWS / Okta-app / Dayforce / SSPR / unlock rules.
 *   - Reports human vs automated split so you can gauge real classifiable volume.
 *
 * Outputs (same shape as before → Phase 2 unchanged):
 *   /home/ubuntu/taxonomy-proposal.json
 *   /home/ubuntu/taxonomy-proposal.md
 *
 * Usage (from /var/www/corpit-hub-api):
 *   node analyze-taxonomy-rules.js
 *   node analyze-taxonomy-rules.js --check
 */

'use strict';
const fs = require('fs');
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const CHECK_ONLY = process.argv.includes('--check');
const OUT_JSON = '/home/ubuntu/taxonomy-proposal.json';
const OUT_MD = '/home/ubuntu/taxonomy-proposal.md';

// ---------- DB config ----------
function resolveDbConfig() {
  const e = process.env;
  const user = e.DB_USER || e.MYSQL_USER;
  const password = e.DB_PASS || e.DB_PASSWORD || e.MYSQL_PASSWORD;
  const database = e.DB_NAME || e.MYSQL_DATABASE || 'corpit_hub';
  const host = e.DB_HOST || e.MYSQL_HOST || '127.0.0.1';
  if (!user) { console.error('[config] No DB_USER in .env'); process.exit(1); }
  const cfg = { user, password, database };
  if (e.DB_SOCKET) cfg.socketPath = e.DB_SOCKET; else cfg.host = host;
  return cfg;
}

function normalizeSubject(s) {
  return String(s || '')
    .replace(/^\s*((re|fw|fwd|aw)\s*:\s*)+/i, '')
    .replace(/#?\d{4,}/g, '#')
    .replace(/\b[\w.+-]+@[\w.-]+\b/g, '@user')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

// ---------- word-boundary term matcher ----------
// A "word char" here is [a-z0-9]; punctuation and brackets act as boundaries.
function termToRegex(term) {
  const esc = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  return new RegExp(`(?<![a-z0-9])${esc}(?![a-z0-9])`);
}

// ---------- AUTOMATED-ALERT quarantine (substring; distinctive machine strings) ----------
// Checked BEFORE the taxonomy rules. Ordered; first match wins.
const AUTOMATED = [
  { s: 'Room / AV Monitoring', any: ['zoom room is online', 'zoom room is offline', 'scheduling display', 'controller (', 'mauchly-', 'huddle room', 'board room) :'] },
  { s: 'Voicemail Notification', any: ['new voicemail from'] },
  { s: 'Security Tool Alert', any: ['darktrace', 'antigena', 'data loss prevention policies', 'securityscorecard'] },
  { s: 'App / Integration Alert', any: ['docusign: document delivery failed', 'flow has been suspended', 'your flow has been'] },
  // Generic external automated notifications (catch remaining [ext] [alert]/[update])
  { s: 'Other Automated Notification', any: ['[ext] [alert]', '[ext] [update]', '[alert]', '[update]'] },
];
function matchAutomated(norm) {
  for (const r of AUTOMATED) {
    if (r.any.some(t => norm.includes(t))) return { c: 'System Notifications', s: r.s };
  }
  return null;
}

// ---------- taxonomy RULES (word-boundary). First match wins; specific above general. ----------
const RULES = [
  // Identity & Access
  { c: 'Identity & Access', s: 'Password Reset', any: ['password reset', 'reset password', 'forgot password', 'change password', 'expired password', 'sspr', 'self service password', 'self-service password'] },
  { c: 'Identity & Access', s: 'Account Lockout', any: ['locked out', 'account lock', 'lockout', 'unlock account', 'unlock my', 'unlock', 'user locked'] },
  { c: 'Identity & Access', s: 'MFA / Authentication', any: ['mfa', 'multi-factor', 'multifactor', 'authenticator', 'okta verify', 'okta multifactor', 'okta mfa', '2fa', 'verification code', 'security method'] },
  { c: 'Identity & Access', s: 'Provisioning / Onboarding', any: ['new hire', 'onboard', 'new employee', 'new user', 'create account', 'account setup', 'setup account'] },
  { c: 'Identity & Access', s: 'Deprovisioning / Offboarding', any: ['offboard', 'terminate', 'termination', 'disable account', 'deactivate', 'separation', 'last day'] },
  { c: 'Identity & Access', s: 'Cloud / AWS Access', any: ['aws'] },
  { c: 'Identity & Access', s: 'SSO / Okta App Access', any: ['okta'] },
  { c: 'Identity & Access', s: 'Access Request / Permissions', any: ['access to', 'need access', 'request access', 'permission', 'permissions', 'add me to', 'group membership', 'security group', 'ad group', 'shared mailbox access', 'access needed', 'access request', 'wants to access', 'sftp', 'file transfer'] },

  // Email & Collaboration
  { c: 'Email & Collaboration', s: 'Outlook / Exchange', any: ['outlook', 'exchange', 'mailbox', 'distribution list', 'shared mailbox', 'calendar', 'archive'] },
  { c: 'Email & Collaboration', s: 'Teams', any: ['teams'] },
  { c: 'Email & Collaboration', s: 'SharePoint / OneDrive', any: ['sharepoint', 'onedrive', 'file share', 'shared drive'] },
  { c: 'Email & Collaboration', s: 'Spam / Phishing', any: ['spam', 'phishing', 'junk', 'quarantine'] },

  // Endpoint & Devices
  { c: 'Endpoint & Devices', s: 'Hardware / Laptop', any: ['laptop', 'desktop', 'monitor', 'keyboard', 'mouse', 'docking', 'dock', 'webcam', 'headset', 'battery', 'charger', 'hardware', 'memory upgrade'] },
  { c: 'Endpoint & Devices', s: 'Mobile Devices', any: ['iphone', 'ipad', 'android', 'mobile', 'cell phone', 'tablet'] },
  { c: 'Endpoint & Devices', s: 'Printing', any: ['print', 'printer', 'scanner', 'toner'] },
  { c: 'Endpoint & Devices', s: 'OS / Performance', any: ['blue screen', 'bsod', 'freeze', 'crash', 'reboot', 'restart system', 'wont boot'] },
  { c: 'Endpoint & Devices', s: 'MDM / Kandji', any: ['kandji', 'mdm', 'intune', 'company portal', 'comp portal'] },

  // Software & Applications
  { c: 'Software & Applications', s: 'Business Applications', any: ['salesforce', 'sap', 'quickbooks', 'adobe', 'docusign', 'zoom', 'dayforce', 'morpheus', 'workday'] },
  { c: 'Software & Applications', s: 'M365 Apps (Office)', any: ['excel', 'word', 'powerpoint', 'onenote', 'm365', 'o365', 'microsoft 365'] },
  { c: 'Software & Applications', s: 'Install / Update / License', any: ['install', 'reinstall', 'license', 'activation'] },

  // Network & Connectivity
  { c: 'Network & Connectivity', s: 'VPN / Zscaler', any: ['vpn', 'zscaler', 'zpa', 'zia', 'remote access', 'private access'] },
  { c: 'Network & Connectivity', s: 'Wi-Fi / LAN', any: ['wifi', 'wi-fi', 'wireless', 'ethernet', 'internet'] },
  { c: 'Network & Connectivity', s: 'Website / Firewall Block', any: ['blocked', 'firewall', 'proxy'] },

  // Telephony
  { c: 'Telephony', s: 'Vonage / VBC', any: ['vonage', 'vbc', 'vcc', 'call queue', 'softphone'] },
  { c: 'Telephony', s: 'Phone / Voicemail', any: ['phone', 'voicemail', 'extension', 'call quality', 'desk phone'] },

  // Security
  { c: 'Security', s: 'Malware / Incident', any: ['malware', 'virus', 'ransomware', 'compromised', 'breach', 'security incident', 'rapid7'] },
  { c: 'Security', s: 'Data / Encryption', any: ['bitlocker', 'filevault', 'encrypt', 'dlp'] },

  // Facilities & AV (human-reported, not the automated room alerts)
  { c: 'Facilities & AV', s: 'Conference Room / AV', any: ['conference room', 'projector', 'audio visual', 'meeting room', 'lobby tv', 'display'] },
];

const CATCHALL = { c: 'General / Other', s: 'Uncategorized' };

// Precompile
for (const r of RULES) { r._any = (r.any || []).map(termToRegex); r._all = (r.all || []).map(termToRegex); }

function classify(norm) {
  for (const r of RULES) {
    const anyHit = r._any.length === 0 || r._any.some(rx => rx.test(norm));
    const allHit = r._all.length === 0 || r._all.every(rx => rx.test(norm));
    if (anyHit && allHit) return { c: r.c, s: r.s };
  }
  return { c: CATCHALL.c, s: CATCHALL.s };
}

const STOPWORDS = new Set(('a an and the to for of in on at is are be with my me i you your it this that not no can cant cannot please help issue need request new re fw fwd get got has have unable working work user account ext'.split(/\s+/)));
function topTokens(subjects, limit = 25) {
  const freq = new Map();
  for (const s of subjects) for (const tok of s.split(/[^a-z0-9]+/)) {
    if (tok.length < 3 || STOPWORDS.has(tok)) continue;
    freq.set(tok, (freq.get(tok) || 0) + 1);
  }
  return [...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}

(async () => {
  const mysql = require('mysql2/promise');
  const cfg = resolveDbConfig();
  console.log(`[db] connecting as ${cfg.user}@${cfg.socketPath || cfg.host}/${cfg.database}`);
  const db = await mysql.createConnection(cfg);

  const [cols] = await db.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='sdops_request'`, [cfg.database]);
  const avail = new Set(cols.map(c => c.COLUMN_NAME.toLowerCase()));
  if (!avail.has('subject')) { console.error('[schema] no subject column'); process.exit(1); }
  console.log('[schema] category=' + (avail.has('category') ? 'category' : 'none'));

  const [[{ total }]] = await db.query('SELECT COUNT(*) AS total FROM sdops_request');
  console.log(`[data] ${total} requests`);
  if (CHECK_ONLY) { console.log('[check] OK — no API needed.'); await db.end(); return; }

  const [rows] = await db.query('SELECT subject FROM sdops_request');

  const tree = new Map();
  let automatedCount = 0, humanMatched = 0, humanTotal = 0;
  const add = (c, s, norm) => {
    if (!tree.has(c)) tree.set(c, new Map());
    const m = tree.get(c);
    if (!m.has(s)) m.set(s, { count: 0, subjects: [] });
    const cell = m.get(s); cell.count++;
    if (cell.subjects.length < 200) cell.subjects.push(norm);
  };

  for (const r of rows) {
    const norm = normalizeSubject(r.subject);
    if (!norm) continue;
    const auto = matchAutomated(norm);
    if (auto) { automatedCount++; add(auto.c, auto.s, norm); continue; }
    humanTotal++;
    const { c, s } = classify(norm);
    if (c !== CATCHALL.c) humanMatched++;
    add(c, s, norm);
  }

  const humanMatchPct = Math.round(humanMatched / humanTotal * 100);
  const autoPct = Math.round(automatedCount / rows.length * 100);
  console.log(`[split] automated notifications: ${automatedCount}/${rows.length} (${autoPct}%)`);
  console.log(`[split] human tickets: ${humanTotal}; of those, ${humanMatched} matched a specific rule (${humanMatchPct}%)`);

  const categories = [...tree.entries()]
    .map(([c, m]) => ({ c, total: [...m.values()].reduce((a, x) => a + x.count, 0), m }))
    .sort((a, b) => b.total - a.total)
    .map(({ c, m }) => ({
      name: c,
      description: c === 'System Notifications' ? 'Machine-generated alerts converted to tickets — quarantined for review; candidate for exclusion from classification.' : '',
      subcategories: [...m.entries()].sort((a, b) => b[1].count - a[1].count).map(([s, cell]) => ({
        name: s, description: '', est_share_pct: Math.round(cell.count / rows.length * 100),
        ticket_count: cell.count, example_subjects: cell.subjects.slice(0, 4),
      })),
    }));

  const otherSubjects = tree.get(CATCHALL.c)?.get(CATCHALL.s)?.subjects || [];
  const otherTokens = topTokens(otherSubjects);

  const out = {
    generated_at: new Date().toISOString(),
    model: 'rule-based-v2 (no API)',
    source: {
      table: 'sdops_request', total_requests: total,
      automated_notifications: automatedCount, automated_pct: autoPct,
      human_tickets: humanTotal, human_specific_match_pct: humanMatchPct,
    },
    status: 'PROPOSED — pending human approval',
    taxonomy: categories,
    notes: [
      'Rule-based v2, no AI. Confidence scoring deferred to Phase 3.',
      `Automated notifications: ${automatedCount} (${autoPct}% of all tickets) quarantined under "System Notifications".`,
      `Human tickets: ${humanTotal}; specific-rule match ${humanMatchPct}% (rest in General / Other).`,
      'DECISION PENDING: keep System Notifications as a real SDP category, or exclude these from classification entirely (cleaner reporting).',
      'To improve human coverage, add rules using the unmatched tokens below, then re-run.',
      'Top unmatched tokens (token:count): ' + otherTokens.map(([t, n]) => `${t}:${n}`).join(', '),
    ],
  };
  fs.writeFileSync(OUT_JSON, JSON.stringify(out, null, 2));

  const md = [];
  md.push('# Proposed SDP Taxonomy (rule-based v2)');
  md.push(`Generated ${out.generated_at} · ${total} tickets`);
  md.push(`\n**Split:** ${automatedCount} automated (${autoPct}%) · ${humanTotal} human · human specific-match ${humanMatchPct}%`);
  md.push('\n**Status: PROPOSED — review, then approve for Phase 2.**\n');
  for (const c of categories) {
    const ctot = c.subcategories.reduce((a, x) => a + x.ticket_count, 0);
    md.push(`## ${c.name}  _(${ctot} tickets)_`);
    if (c.description) md.push('_' + c.description + '_\n');
    md.push('| Subcategory | Tickets | Share | Example subjects |');
    md.push('|---|---|---|---|');
    for (const s of c.subcategories) md.push(`| ${s.name} | ${s.ticket_count} | ${s.est_share_pct}% | ${s.example_subjects.join('; ')} |`);
    md.push('');
  }
  md.push('## Design notes');
  out.notes.forEach(n => md.push(`- ${n}`));
  fs.writeFileSync(OUT_MD, md.join('\n'));

  console.log(`[done] wrote ${OUT_JSON} and ${OUT_MD}`);
  await db.end();
})().catch(e => { console.error('[fatal]', e.message); process.exit(1); });
