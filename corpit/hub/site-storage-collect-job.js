// site-storage-collect-job.js — nightly per-SITE SharePoint storage snapshot.
// One Graph call per site to read drive.quota.used. Upserts one row per (snap_date, site_id).
// Lightweight — runs in under a minute for ~250 sites. No drive walking, no file enumeration.
const mysql = require('mysql2/promise');

const TENANT_ID = process.env.SP_TENANT_ID, CLIENT_ID = process.env.SP_CLIENT_ID, CLIENT_SECRET = process.env.SP_CLIENT_SECRET;
const GRAPH = 'https://graph.microsoft.com/v1.0';

let _tok = null, _exp = 0;
async function token() {
  if (_tok && Date.now() < _exp - 60000) return _tok;
  const b = new URLSearchParams({ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET, scope: 'https://graph.microsoft.com/.default' });
  const r = await fetch(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`, { method: 'POST', body: b });
  const d = await r.json(); if (!d.access_token) throw new Error('token ' + JSON.stringify(d));
  _tok = d.access_token; _exp = Date.now() + (d.expires_in || 3600) * 1000; return _tok;
}
async function gget(u) {
  for (let a = 0; a < 6; a++) {
    const t = await token();
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 60000);
    try {
      const r = await fetch(u, { headers: { Authorization: 'Bearer ' + t }, signal: ctl.signal });
      if (r.status === 429 || r.status >= 500) {
        clearTimeout(timer);
        const w = parseInt(r.headers.get('retry-after') || '', 10) || Math.min(2 ** a, 30);
        await new Promise(s => setTimeout(s, w * 1000));
        continue;
      }
      if (r.status === 404) { clearTimeout(timer); return null; }
      if (!r.ok) { const txt = await r.text(); clearTimeout(timer); throw new Error(r.status + ' ' + u + ' ' + txt.slice(0, 200)); }
      const j = await r.json();
      clearTimeout(timer);
      return j;
    } catch (e) {
      clearTimeout(timer);
      if (a < 5) { console.log('[SITE-STORAGE] request retry (' + (e.name || e.message) + ')'); await new Promise(s => setTimeout(s, 2000)); continue; }
      throw e;
    }
  }
  throw new Error('retries ' + u);
}
function isSP(s) { try { const u = new URL(s.webUrl); return u.hostname.endsWith('.sharepoint.com') && !u.hostname.endsWith('-my.sharepoint.com') && !/^\/personal\//i.test(u.pathname); } catch { return false; } }

async function listSites() {
  const sites = [], seen = new Set(), add = s => { if (isSP(s) && !seen.has(s.id)) { seen.add(s.id); sites.push(s); } };
  try {
    let url = `${GRAPH}/sites/getAllSites?$select=id,displayName,name,webUrl&$top=100`;
    while (url) { const d = await gget(url); (d.value || []).forEach(add); url = d['@odata.nextLink'] || null; }
    if (sites.length) return sites;
  } catch (e) { console.log('[SITE-STORAGE] getAllSites failed, fallback search=*:', e.message); }
  let url = `${GRAPH}/sites?search=*&$select=id,displayName,name,webUrl&$top=100`;
  while (url) { const d = await gget(url); (d.value || []).forEach(add); url = d['@odata.nextLink'] || null; }
  return sites;
}

(async () => {
  const startedAt = Date.now();
  const snapDate = new Date().toISOString().slice(0, 10);
  console.log(`[SITE-STORAGE] ${new Date().toISOString()} starting snapshot ${snapDate}`);

  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'it_app',
    password: process.env.DB_PASSWORD || process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'corpit_hub',
    connectionLimit: 4
  });

  let sites = [];
  try {
    sites = await listSites();
    console.log(`[SITE-STORAGE] enumerated ${sites.length} SharePoint sites`);
  } catch (e) {
    console.error(`[SITE-STORAGE] FATAL enumerating sites: ${e.message}`);
    await pool.end(); process.exit(1);
  }

  let ok = 0, skipped = 0, errored = 0;
  for (let i = 0; i < sites.length; i++) {
    const s = sites[i];
    try {
      const d = await gget(`${GRAPH}/sites/${s.id}/drive?$select=quota`);
      if (!d || !d.quota) { skipped++; continue; }
      const used = Number(d.quota.used || 0);
      const total = d.quota.total != null ? Number(d.quota.total) : null;
      await pool.query(
        `INSERT INTO site_storage_snapshots (snap_date, site_id, site_name, web_url, used_bytes, quota_bytes)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE used_bytes=VALUES(used_bytes), quota_bytes=VALUES(quota_bytes), site_name=VALUES(site_name), web_url=VALUES(web_url)`,
        [snapDate, s.id, (s.displayName || s.name || '').slice(0, 500), (s.webUrl || '').slice(0, 1000), used, total]
      );
      ok++;
      if ((i + 1) % 50 === 0) console.log(`[SITE-STORAGE] ${i + 1}/${sites.length} sites processed`);
    } catch (e) {
      errored++;
      console.log(`[SITE-STORAGE] error site ${s.displayName || s.id}: ${e.message}`);
    }
  }

  const secs = Math.round((Date.now() - startedAt) / 1000);
  console.log(`[SITE-STORAGE] DONE — snapshot ${snapDate}: ${ok} ok, ${skipped} no-quota, ${errored} errors, ${sites.length} sites in ${secs}s`);
  await pool.end();
})().catch(e => { console.error('[SITE-STORAGE] FATAL', e); process.exit(1); });
