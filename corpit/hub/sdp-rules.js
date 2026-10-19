'use strict';
/**
 * sdp-rules.js — shared classifier core (single source of truth).
 * Used by classify-sim.js (Tier 1 simulation) and later the apply engine.
 * Rule-based, deterministic, word-boundary matching. No external deps.
 *
 * classify(subject) -> {
 *   category, subcategory, confidence (0..1), method, explanation, matchedCategories[]
 * }
 */

function normalizeSubject(s) {
  return String(s || '')
    .replace(/^\s*((re|fw|fwd|aw)\s*:\s*)+/i, '')
    .replace(/#?\d{4,}/g, '#')
    .replace(/\b[\w.+-]+@[\w.-]+\b/g, '@user')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function termToRegex(term) {
  const esc = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  return new RegExp(`(?<![a-z0-9])${esc}(e?s|ed|ing)?(?![a-z0-9])`);
}

// ---- automated-alert quarantine (substring; distinctive machine strings) ----
const AUTOMATED = [
  { s: 'Room / AV Monitoring', any: ['zoom room is online', 'zoom room is offline', 'scheduling display', 'controller (', 'mauchly-', 'huddle room', 'board room) :'] },
  { s: 'Voicemail Notification', any: ['new voicemail from'] },
  { s: 'Other Automated Notification', any: ['ups: self-test', 'self-test started by automatic timer', 'self-test passed'] },
  { s: 'Security Tool Alert', any: ['darktrace', 'antigena', 'data loss prevention policies', 'securityscorecard'] },
  { s: 'App / Integration Alert', any: ['docusign: document delivery failed', 'flow has been suspended', 'your flow has been'] },
  { s: 'Other Automated Notification', any: ['[ext] [alert]', '[ext] [update]', '[alert]', '[update]'] },
];
function matchAutomated(norm) {
  for (const r of AUTOMATED) if (r.any.some(t => norm.includes(t))) return r.s;
  return null;
}

// ---- taxonomy rules (word-boundary). First match wins; specific above general ----
const RULES = [
  { c: 'Identity & Access', s: 'Password Reset', any: ['password reset', 'reset password', 'forgot password', 'change password', 'expired password', 'sspr', 'self service password', 'self-service password', 'password changed'] },
  { c: 'Identity & Access', s: 'Account Lockout', any: ['locked out', 'account lock', 'lockout', 'unlock account', 'unlock my', 'unlock', 'user locked', 'log in', 'login', 'log into'] },
  { c: 'Identity & Access', s: 'MFA / Authentication', any: ['mfa', 'multi-factor', 'multifactor', 'multi factor', 'authenticator', 'okta verify', 'okta multifactor', 'okta mfa', '2fa', 'verification code', 'security method'] },
  { c: 'Identity & Access', s: 'Provisioning / Onboarding', any: ['new hire', 'onboard', 'new employee', 'new user', 'create account', 'account setup', 'setup account', 'welcome to auction', 'contingent worker', 'has been approved'] },
  { c: 'Identity & Access', s: 'Leave / Out-of-Office Administration', any: ['out of office', 'out of country', 'return from loa', 'return from leave'] },
  { c: 'Identity & Access', s: 'Deprovisioning / Offboarding', any: ['offboard', 'terminate', 'termination', 'disable account', 'deactivate', 'separation', 'last day', 'term -'] },
  { c: 'Identity & Access', s: 'Cloud / AWS Access', any: ['aws'] },
  { c: 'Identity & Access', s: 'SSO / Okta App Access', any: ['okta'] },
  { c: 'Identity & Access', s: 'Access Request / Permissions', any: ['access to', 'need access', 'request access', 'permission', 'permissions', 'add me to', 'group membership', 'security group', 'ad group', 'shared mailbox access', 'access needed', 'access request', 'wants to access', 'sftp', 'file transfer', 'access', 'winscp'] },

  { c: 'Email & Collaboration', s: 'Outlook / Exchange', any: ['outlook', 'exchange', 'mailbox', 'shared mailbox', 'calendar', 'archive'] },
  { c: 'Email & Collaboration', s: 'Distribution List / Shared Mailbox Administration', any: ['distro', 'distribution list', 'dl_', 'shared inbox', 'add to inbox', 'inbox access', 'group inbox'] },
  { c: 'Email & Collaboration', s: 'Teams', any: ['teams'] },
  { c: 'Email & Collaboration', s: 'SharePoint / OneDrive', any: ['sharepoint', 'onedrive', 'file share', 'shared drive'] },
  { c: 'Email & Collaboration', s: 'Spam / Phishing', any: ['spam', 'phishing', 'junk', 'quarantine'] },

  { c: 'Endpoint & Devices', s: 'Hardware / Laptop', any: ['laptop', 'desktop', 'monitor', 'keyboard', 'mouse', 'docking', 'dock', 'webcam', 'headset', 'battery', 'charger', 'hardware', 'memory upgrade', 'computer', 'web cam', 'cpu'] },
  { c: 'Endpoint & Devices', s: 'Mobile Devices', any: ['iphone', 'ipad', 'android', 'mobile', 'cell phone', 'tablet'] },
  { c: 'Endpoint & Devices', s: 'Printing', any: ['print', 'printer', 'scanner', 'toner'] },
  { c: 'Endpoint & Devices', s: 'OS / Performance', any: ['blue screen', 'bsod', 'freeze', 'crash', 'reboot', 'restart system', 'wont boot'] },
  { c: 'Endpoint & Devices', s: 'MDM / Kandji', any: ['kandji', 'mdm', 'intune', 'company portal', 'comp portal'] },
  { c: 'Endpoint & Devices', s: 'Mobile Carrier / Line Management', any: ['verizon', 'tmobile', 't-mobile', 'port over', 'line to disconnect', 'lines to cancel', 'international roaming', 'international cell'] },
  { c: 'Endpoint & Devices', s: 'Workstation Setup / Desk Move', any: ['desk move', 'desk set up', 'desk setup', 'work station', 'workstation set-up', 'workstation setup'] },

  { c: 'Software & Applications', s: 'Business Applications', any: ['salesforce', 'sap', 'quickbooks', 'adobe', 'docusign', 'zoom', 'dayforce', 'workday'] },
  { c: 'Software & Applications', s: 'AI Tools (Claude / Copilot)', any: ['claude', 'copilot', 'co-pilot', 'co pilot', 'chatgpt', 'chat gpt'] },
  { c: 'Software & Applications', s: 'Amazon Connect / Contact Center', any: ['amazon connect'] },
  { c: 'Software & Applications', s: 'Internal Business Apps (Morpheus / AuctionSync / SmartSale / Araya / Portfolio Interact)', any: ['morpheus', 'auctionsync', 'auction sync', 'smartsale', 'smart sale', 'araya', 'portfolio interact'] },
  { c: 'Software & Applications', s: 'Developer Tools (Okta SSO)', any: ['github', 'jira', 'linear', 'launchdarkly', 'launch darkly', 'datadog', 'kubernetes', 'k8s', 'dovetail', 'amplitude', 'confluence', 'atlassian'] },
  { c: 'Software & Applications', s: 'M365 Apps (Office)', any: ['excel', 'word', 'powerpoint', 'onenote', 'm365', 'o365', 'microsoft 365'] },
  { c: 'Software & Applications', s: 'Install / Update / License', any: ['install', 'reinstall', 'license', 'activation'] },

  { c: 'Network & Connectivity', s: 'VPN / Zscaler', any: ['vpn', 'zscaler', 'zpa', 'zia', 'remote access', 'private access'] },
  { c: 'Network & Connectivity', s: 'Wi-Fi / LAN', any: ['wifi', 'wi-fi', 'wireless', 'ethernet', 'internet'] },
  { c: 'Network & Connectivity', s: 'Website / Firewall Block', any: ['blocked', 'proxy'] },

  { c: 'Telephony', s: 'Vonage / VBC', any: ['vonage', 'vbc', 'vcc', 'call queue', 'softphone'] },
  { c: 'Telephony', s: 'Phone / Voicemail', any: ['phone', 'voicemail', 'extension', 'call quality', 'desk phone'] },

  { c: 'Security', s: 'Malware / Incident', any: ['malware', 'virus', 'ransomware', 'compromised', 'breach', 'security incident', 'rapid7'] },
  { c: 'Security', s: 'Data / Encryption', any: ['bitlocker', 'filevault', 'encrypt', 'dlp'] },

  { c: 'Facilities & AV', s: 'Conference Room / AV', any: ['conference room', 'projector', 'audio visual', 'meeting room', 'lobby tv', 'display'] },
];

// precompile
for (const r of RULES) r._any = r.any.map(termToRegex);

const CATCHALL = { c: 'General / Other', s: 'Uncategorized' };

// confidence tuning
const CONF = { automated: 0.97, single: 0.92, twoCat: 0.70, manyCat: 0.55, none: 0.0 };
const WEAK_TERMS = new Set(['tablet', 'phone', 'laptop', 'desktop', 'mobile', 'computer', 'cell phone']);

function classify(subjectRaw) {
  const norm = normalizeSubject(subjectRaw);
  if (!norm) return { category: CATCHALL.c, subcategory: CATCHALL.s, confidence: 0, method: 'rule-none', explanation: 'Empty subject.', matchedCategories: [] };

  const auto = matchAutomated(norm);
  if (auto) return {
    category: 'System Notifications', subcategory: auto, confidence: CONF.automated,
    method: 'rule-auto', explanation: `Automated machine-generated notification (${auto}).`, matchedCategories: ['System Notifications'],
  };

  // find winning rule + all categories that matched (for ambiguity)
  let winner = null, winnerTerms = [];
  const matchedCats = new Set();
  for (const r of RULES) {
    const hits = r.any.filter((_, i) => r._any[i].test(norm));
    if (hits.length) {
      const allWeak = hits.every(h => WEAK_TERMS.has(h));
      if (!winner) { winner = r; winnerTerms = hits; matchedCats.add(r.c); }
      else if (!allWeak) { matchedCats.add(r.c); }
    }
  }

  if (!winner) return {
    category: CATCHALL.c, subcategory: CATCHALL.s, confidence: CONF.none,
    method: 'rule-none', explanation: 'No taxonomy keywords matched — requires AI or manual review.', matchedCategories: [],
  };

  const nCats = matchedCats.size;
  const confidence = nCats === 1 ? CONF.single : nCats === 2 ? CONF.twoCat : CONF.manyCat;
  const competitors = [...matchedCats].filter(c => c !== winner.c);
  const explanation =
    `Matched ${winner.c} / ${winner.s} on: ${winnerTerms.map(t => `"${t}"`).join(', ')}.` +
    (competitors.length ? ` Competing categories also matched: ${competitors.join(', ')} — confidence reduced.` : ' No competing categories.');

  return { category: winner.c, subcategory: winner.s, confidence, method: 'rule', explanation, matchedCategories: [...matchedCats] };
}

module.exports = { normalizeSubject, classify, RULES, AUTOMATED, CATCHALL };
