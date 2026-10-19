// One-shot: dump all directory groups for the console's type-ahead picker.
// Prints {ok, groups:[{id,name,mail,kind}]} - read-only.
try { require('dotenv').config(); } catch {
  try {
    for (const line of require('fs').readFileSync('.env', 'utf8').split('\n')) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line.trim());
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
    }
  } catch { /* env from caller */ }
}
const { graphFetchAllPages, GRAPH_BASE } = require('./gal-source');

function kindOf(g) {
  if ((g.groupTypes || []).includes('Unified')) return 'Microsoft 365';
  if (g.mailEnabled && g.securityEnabled)       return 'Mail-enabled security';
  if (g.mailEnabled)                            return 'Distribution';
  if (g.securityEnabled)                        return 'Security';
  return 'Group';
}

(async () => {
  const groups = await graphFetchAllPages(
    `${GRAPH_BASE}/groups?$select=id,displayName,mail,mailEnabled,securityEnabled,groupTypes&$top=999`);
  const out = groups
    .map(g => ({ id: g.id, name: g.displayName || '(unnamed)', mail: g.mail || null, kind: kindOf(g) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  console.log(JSON.stringify({ ok: true, count: out.length, groups: out }));
})().catch(e => {
  console.log(JSON.stringify({ ok: false, error: e.message.slice(0, 200) }));
  process.exit(1);
});
