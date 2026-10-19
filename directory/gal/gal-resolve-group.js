// One-shot: resolve a Graph group by object id or display name -> JSON.
// Usage: node gal-resolve-group.js "<name-or-guid>"
try { require('dotenv').config(); } catch {
  try {
    for (const line of require('fs').readFileSync('.env', 'utf8').split('\n')) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line.trim());
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
    }
  } catch { /* env from caller */ }
}
const { graphFetch, GRAPH_BASE } = require('./gal-source');

(async () => {
  const q = (process.argv[2] || '').trim();
  if (!q) throw new Error('no group given');

  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(q)) {
    const g = await graphFetch(`${GRAPH_BASE}/groups/${q}?$select=id,displayName`);
    console.log(JSON.stringify({ ok: true, id: g.id, name: g.displayName }));
    return;
  }
  const esc = q.replace(/'/g, "''");
  const r = await graphFetch(`${GRAPH_BASE}/groups?$filter=displayName eq '${encodeURIComponent(esc)}'&$select=id,displayName`);
  const hits = r.value || [];
  if (hits.length === 1) console.log(JSON.stringify({ ok: true, id: hits[0].id, name: hits[0].displayName }));
  else if (!hits.length)  console.log(JSON.stringify({ ok: false, error: `no group named "${q}"` }));
  else                    console.log(JSON.stringify({ ok: false, error: `${hits.length} groups named "${q}" - use the object id` }));
})().catch(e => { console.log(JSON.stringify({ ok: false, error: e.message.slice(0, 200) })); process.exit(1); });
