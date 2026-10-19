// storage-collect-job.js — nightly per-user SharePoint storage snapshot.
// Crawls all SharePoint sites/drives, sums file size by createdBy AND lastModifiedBy,
// upserts one row per (snap_date, principal, principal_type) into storage_snapshots.
// Hardened: timeout covers body read; per-drive page + wall-clock caps prevent hangs.
const mysql = require('mysql2/promise');

const TENANT_ID = process.env.SP_TENANT_ID, CLIENT_ID = process.env.SP_CLIENT_ID, CLIENT_SECRET = process.env.SP_CLIENT_SECRET;
const GRAPH = 'https://graph.microsoft.com/v1.0';
const DRIVE_MAX_PAGES = 2000, DRIVE_MAX_MS = 10 * 60 * 1000;

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
      if (!r.ok) { const txt = await r.text(); clearTimeout(timer); throw new Error(r.status + ' ' + u + ' ' + txt.slice(0, 200)); }
      const j = await r.json();
      clearTimeout(timer);
      return j;
    } catch (e) {
      clearTimeout(timer);
      if (a < 5) { console.log('[GROWTH-JOB] request retry (' + (e.name || e.message) + ')'); await new Promise(s => setTimeout(s, 2000)); continue; }
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
  } catch (e) { console.log('[GROWTH-JOB] getAllSites failed, fallback search=*:', e.message); }
  let url = `${GRAPH}/sites?search=*&$select=id,displayName,name,webUrl&$top=100`;
  while (url) { const d = await gget(url); (d.value || []).forEach(add); url = d['@odata.nextLink'] || null; }
  return sites;
}
async function listDrives(siteId) {
  const drives = []; let url = `${GRAPH}/sites/${siteId}/drives?$select=id,name&$top=100`;
  while (url) { const d = await gget(url); drives.push(...(d.value || [])); url = d['@odata.nextLink'] || null; }
  return drives;
}
function principalOf(idn) {
  const u = idn && idn.user;
  if (!u) return null;
  return (u.email || u.displayName || '').trim() || null;
}
function bump(map, key, bytes) {
  const k = key || '(unknown)';
  const e = map.get(k) || { bytes: 0, count: 0 };
  e.bytes += bytes; e.count += 1; map.set(k, e);
}
async function sumDrive(driveId, driveName, siteUrl, byCreator, byModifier) {
  const driveStart = Date.now();
  let pages = 0;
  let url = `${GRAPH}/drives/${driveId}/root/delta?$select=size,file,createdBy,lastModifiedBy`;
  while (url) {
    if (pages >= DRIVE_MAX_PAGES) { console.log(`[GROWTH-JOB] drive ${driveName} @ ${siteUrl} hit ${DRIVE_MAX_PAGES} pages, bailing partial`); break; }
    if (Date.now() - driveStart > DRIVE_MAX_MS) { console.log(`[GROWTH-JOB] drive ${driveName} @ ${siteUrl} hit ${DRIVE_MAX_MS/60000}min wall, bailing partial`); break; }
    pages++;
    const d = await gget(url);
    for (const it of (d.value || [])) {
      if (!it.file) continue;
      const sz = it.size || 0;
      bump(byCreator,  principalOf(it.createdBy),      sz);
      bump(byModifier, principalOf(it.lastModifiedBy), sz);
    }
    url = d['@odata.nextLink'] || null;
    if (pages % 100 === 0) console.log(`[GROWTH-JOB] drive ${driveName} page ${pages}, ${((Date.now()-driveStart)/1000)|0}s`);
  }
}

(async () => {
  const started = Date.now();
  const byCreator = new Map(), byModifier = new Map();
  const sites = await listSites();
  console.log(`[GROWTH-JOB] ${new Date().toISOString()} crawling ${sites.length} SharePoint sites, drive caps: ${DRIVE_MAX_PAGES}p / ${DRIVE_MAX_MS/60000}min`);
  let n = 0;
  for (const site of sites) {
    n++;
    try {
      const drives = await listDrives(site.id);
      for (const drv of drives) {
        try { await sumDrive(drv.id, drv.name || 'Documents', site.webUrl, byCreator, byModifier); }
        catch (e) { console.log(`[GROWTH-JOB] drive ${drv.name} @ ${site.webUrl}:`, e.message); }
      }
    } catch (e) { console.log(`[GROWTH-JOB] site ${site.webUrl}:`, e.message); }
    if (n % 25 === 0) { const rss = (process.memoryUsage().rss / 1048576) | 0; console.log(`[GROWTH-JOB] ${n}/${sites.length} sites, ${byCreator.size} creators / ${byModifier.size} modifiers, RSS ${rss}MB`); }
  }

  const snap = new Date().toISOString().slice(0, 10);
  const rows = [];
  for (const [p, e] of byCreator)  rows.push([snap, p, 'creator',  e.count, e.bytes]);
  for (const [p, e] of byModifier) rows.push([snap, p, 'modifier', e.count, e.bytes]);

  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });
  let written = 0;
  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500);
    await pool.query(
      `INSERT INTO storage_snapshots (snap_date, principal, principal_type, file_count, total_bytes)
       VALUES ? ON DUPLICATE KEY UPDATE file_count=VALUES(file_count), total_bytes=VALUES(total_bytes)`,
      [chunk]
    );
    written += chunk.length;
  }
  await pool.end();
  console.log(`[GROWTH-JOB] DONE — snapshot ${snap}: ${byCreator.size} creators / ${byModifier.size} modifiers, ${written} rows upserted, ${sites.length} sites in ${((Date.now() - started) / 1000) | 0}s`);
})().catch(e => { console.error('[GROWTH-JOB] FATAL', e); process.exit(1); });
