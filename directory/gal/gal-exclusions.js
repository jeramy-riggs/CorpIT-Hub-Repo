// =============================================================================
// gal-exclusions.js - shared loader for the console-managed do-not-publish list.
//
// /var/lib/gal-directory/exclusions.json is written by the subadmin console
// (Directory Sync -> Who is published) and read by every job that builds the
// roster. It is a sync-side overlay ONLY: nothing here touches Active
// Directory, Entra or Exchange. The person keeps their numbers in AD and stays
// in Outlook's address book; they just stop being pushed to phones. Shape:
//
//   { "version": 1,
//     "rules": [
//       { "upn":    "ceo@auction.com",   // matched against upn AND mail, case-insensitive
//         "id":     "<graph object id>", // optional; when present it wins over upn
//         "mode":   "hide" | "no-mobile" | "no-phones",
//         "reason": "free text shown on the console",
//         "by":     "who added it", "at": "ISO timestamp" } ],
//     "policy": { "requireMobile": false } }   // directory-wide switches, optional
//
// Rules the engine enforces from this file:
//   * hide       the person is published to NO list; their cards are removed
//                from every recipient mailbox on the next run
//   * no-mobile  the card goes out without the mobile number (email, title,
//                desk phone still go)
//   * no-phones  the card goes out with no phone numbers at all
//   * two rules for one person: the stronger wins (hide > no-phones > no-mobile)
//   * policy.requireMobile  only people with a mobile number in Entra are
//                published; everyone else is held back with the reason
//                "no mobile number". Re-judged every run, so a number added
//                in AD brings the person back by itself. A person's OWN rule
//                outranks the policy ("publish them without their mobile" was
//                a deliberate choice to publish).
//   * a MISSING file means no exclusions; a MALFORMED file is fatal. A run
//     must never publish past a list it could not read. That includes a
//     policy key it does not recognise - a newer console may have written a
//     stricter rule than this engine knows how to keep.
// =============================================================================

const fs = require('fs');

// PATH-RELEASE-20260929: state dir via gal-paths.js (GAL_EXCLUSIONS_JSON still overrides). A missing
// FILE still means no exclusions; a missing state DIRECTORY throws at require time.
const EXCLUSIONS_JSON = require('./gal-paths').stateFile('exclusions.json', 'GAL_EXCLUSIONS_JSON');
const MODES = ['hide', 'no-phones', 'no-mobile'];          // strongest first
const RANK  = Object.fromEntries(MODES.map((m, i) => [m, i]));

// Directory-wide switches and the not-published reason each one stamps on a
// person it holds back. The console keys its counts on these exact strings.
const POLICY_REASON = { requireMobile: 'no mobile number' };
const defaultPolicy = () => Object.fromEntries(Object.keys(POLICY_REASON).map(k => [k, false]));

function parsePolicy(raw, path) {
  const policy = defaultPolicy();
  if (raw === undefined || raw === null) return policy;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`exclusions file "policy" is not an object (${path})`);
  for (const [k, v] of Object.entries(raw)) {
    if (!(k in policy)) throw new Error(`exclusions file has unknown policy "${k}" (${path})`);
    if (typeof v !== 'boolean') throw new Error(`exclusions file policy "${k}" must be true or false (${path})`);
    policy[k] = v;
  }
  return policy;
}

function loadExclusions(path = EXCLUSIONS_JSON) {
  let raw;
  try {
    raw = fs.readFileSync(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return index([], defaultPolicy());
    throw new Error(`exclusions file unreadable (${path}): ${err.message}`);
  }
  let doc;
  try { doc = JSON.parse(raw); } catch (err) {
    throw new Error(`exclusions file is not valid JSON (${path}): ${err.message}`);
  }
  const rules = doc && Array.isArray(doc.rules) ? doc.rules : null;
  if (!rules) throw new Error(`exclusions file has no "rules" array (${path})`);
  for (const r of rules) {
    if (!r || typeof r.upn !== 'string' || !r.upn.includes('@')) throw new Error(`exclusion rule without a usable upn: ${JSON.stringify(r)}`);
    if (!MODES.includes(r.mode)) throw new Error(`exclusion rule for ${r.upn} has unknown mode "${r.mode}"`);
  }
  return index(rules, parsePolicy(doc.policy, path));
}

// Lookup tables so matching a 2,000-user fetch costs nothing per user.
function index(rules, policy) {
  const byId = new Map(), byAddr = new Map();
  const put = (map, key, rule) => {
    if (!key) return;
    const k = String(key).toLowerCase();
    const have = map.get(k);
    if (!have || RANK[rule.mode] < RANK[have.mode]) map.set(k, rule);
  };
  for (const r of rules) {
    put(byId, r.id, r);
    put(byAddr, r.upn, r);
  }
  return {
    rules,
    size: rules.length,
    policy,
    // The matching rule for a Graph user object, or null.
    match(u) {
      if (!u) return null;
      const cands = [
        u.id && byId.get(String(u.id).toLowerCase()),
        u.userPrincipalName && byAddr.get(String(u.userPrincipalName).toLowerCase()),
        u.mail && byAddr.get(String(u.mail).toLowerCase())
      ].filter(Boolean);
      if (!cands.length) return null;
      return cands.reduce((a, b) => (RANK[b.mode] < RANK[a.mode] ? b : a));
    }
  };
}

// Apply a rule to a roster entry IN PLACE. The caller re-hashes afterwards so a
// newly hidden number turns into a PATCH on every phone that already has the card.
function applyExclusion(entry, rule) {
  if (!rule) return entry;
  if (rule.mode === 'no-mobile' || rule.mode === 'no-phones') entry.mobilePhone = null;
  if (rule.mode === 'no-phones') entry.businessPhones = [];
  entry.exclusion = rule.mode;
  return entry;
}

module.exports = { loadExclusions, applyExclusion, EXCLUSIONS_JSON, MODES, POLICY_REASON, defaultPolicy };
