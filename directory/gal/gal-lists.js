// =============================================================================
// gal-lists.js - shared list-config loader for the multi-list directory sync.
//
// /var/lib/gal-directory/lists.json (PATH-RELEASE-20260929; was /opt/gal-directory) is the authority on what gets published to
// whom. Shape:
//   [{ "id": "company",                     // slug, immutable, stamp key
//      "name": "Company Directory",         // shown on the console page
//      "category": "Company Directory",     // Contacts category on the cards
//      "source": { "type": "all" }          // who appears:
//              | { "type": "group", "group": "<graph group id>" }
//              | { "type": "upns",  "upns": ["a@x.com", ...] },
//      "recipients": ["upn", ...],          // who receives, managed on the page
//      "enabled": true }]
//
// Rules the engine enforces from this file:
//   * a card's stamp carries the list id - lists never touch each other's cards
//   * legacy stamps (pre-lists, 3-part) belong to the list id "company"
//   * a recipient in multiple lists gets ONE card per person (first list wins,
//     file order = priority)
//   * cards whose list id matches no enabled list are orphans and get cleaned
// =============================================================================

const fs = require('fs');

// PATH-RELEASE-20260929: state dir via gal-paths.js (GAL_LISTS_JSON still overrides).
const LISTS_JSON = require('./gal-paths').stateFile('lists.json', 'GAL_LISTS_JSON');

function loadLists() {
  const raw = JSON.parse(fs.readFileSync(LISTS_JSON, 'utf8'));
  if (!Array.isArray(raw) || !raw.length) throw new Error('lists.json is empty');
  const seen = new Set();
  for (const l of raw) {
    if (!l.id || !/^[a-z0-9-]{1,32}$/.test(l.id)) throw new Error(`bad list id: ${l.id}`);
    if (seen.has(l.id)) throw new Error(`duplicate list id: ${l.id}`);
    seen.add(l.id);
    if (!l.source || !['all', 'group', 'upns'].includes(l.source.type)) {
      throw new Error(`list ${l.id}: bad source`);
    }
    l.category = l.category || l.name || l.id;
    l.recipients = Array.isArray(l.recipients) ? l.recipients : [];
    l.enabled = l.enabled !== false;
  }
  return raw;
}

module.exports = { loadLists, LISTS_JSON };
