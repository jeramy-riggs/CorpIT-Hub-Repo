// dept-folder-walk-job.js — nightly walker: largest folder per department site.
// For each site in department_sites (or auto-seeded on first run):
//   - Recursively walk drive folders, tracking the biggest (by Graph-rolled-up folder.size).
//   - Resolve last_modified_by/at for the biggest folder. Folder metadata first;
//     if absent, fall back to the most-recently-modified child file inside it.
//   - Upsert one row per (snap_date, site_id) into department_site_folders.
// Caps: 500 pages per site, 5-minute wall clock per site. Bails partial cleanly.

const mysql = require('mysql2/promise');

const TENANT_ID = process.env.SP_TENANT_ID, CLIENT_ID = process.env.SP_CLIENT_ID, CLIENT_SECRET = process.env.SP_CLIENT_SECRET;
const GRAPH = 'https://graph.microsoft.com/v1.0';
const SITE_MAX_PAGES = 500;
const SITE_MAX_MS = 5 * 60 * 1000;

const SEED_PATTERNS = [
  'hr', 'humanresources', 'finance', 'fin', 'it', 'legal', 'marketing', 'mktg',
  'ops', 'operations', 'sales', 'accounting', 'acct', 'payroll', 'recruiting',
  'engineering', 'eng', 'product', 'prodeng', 'security', 'compliance', 'audit',
  'procurement', 'facilities', 'trusteeops', 'reo'
];

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
      if (a < 5) { console.log('[DEPT-WALK] request retry (' + (e.name || e.message) + ')'); await new Promise(s => setTimeout(s, 2000)); continue; }
      throw e;
    }
  }
  throw new Error('retries ' + u);
}

// F45: only walk Graph composite SharePoint site ids ("<tenant>.sharepoint.com,<guid>,<guid>"),
// never a OneDrive (-my) host or a path, so a bad manual department_sites row is never fetched.
// Same rule as POST /api/files/departments/sites in files-routes.js.
const SP_SITE_ID_RE = /^[a-z0-9-]+\.sharepoint\.com,[0-9a-f-]{36},[0-9a-f-]{36}$/i;
function validDeptSiteId(id) { const s = String(id == null ? '' : id); return SP_SITE_ID_RE.test(s) && !/-my\.sharepoint\.com,/i.test(s); }

function isSP(s) { try { const u = new URL(s.webUrl); return u.hostname.endsWith('.sharepoint.com') && !u.hostname.endsWith('-my.sharepoint.com') && !/^\/personal\//i.test(u.pathname); } catch { return false; } }

async function listSites() {
  const sites = [], seen = new Set(), add = s => { if (isSP(s) && !seen.has(s.id)) { seen.add(s.id); sites.push(s); } };
  try {
    let url = `${GRAPH}/sites/getAllSites?$select=id,displayName,name,webUrl&$top=100`;
    while (url) { const d = await gget(url); (d.value || []).forEach(add); url = d['@odata.nextLink'] || null; }
    if (sites.length) return sites;
  } catch (e) { console.log('[DEPT-WALK] getAllSites failed, fallback:', e.message); }
  let url = `${GRAPH}/sites?search=*&$select=id,displayName,name,webUrl&$top=100`;
  while (url) { const d = await gget(url); (d.value || []).forEach(add); url = d['@odata.nextLink'] || null; }
  return sites;
}

function matchesSeed(site) {
  try {
    const u = new URL(site.webUrl);
    const parts = u.pathname.toLowerCase().split('/').filter(Boolean);
    const idx = parts.indexOf('sites');
    if (idx === -1 || !parts[idx + 1]) return false;
    const slug = parts[idx + 1];
    return SEED_PATTERNS.some(p => slug.startsWith(p));
  } catch { return false; }
}

async function ensureSeed(pool, allSites) {
  const [[{ c }]] = await pool.query(`SELECT COUNT(*) AS c FROM department_sites`);
  if (c > 0) { console.log(`[DEPT-WALK] department_sites already has ${c} rows — skipping seed`); return; }
  const seed = allSites.filter(matchesSeed);
  console.log(`[DEPT-WALK] auto-seeding ${seed.length} department sites from ${allSites.length} total`);
  for (const s of seed) {
    await pool.query(
      `INSERT IGNORE INTO department_sites (site_id, site_name, web_url, department_name, is_department, source)
       VALUES (?, ?, ?, ?, 1, 'auto-seed')`,
      [s.id, (s.displayName || s.name || '').slice(0, 500), (s.webUrl || '').slice(0, 1000), (s.displayName || s.name || '').slice(0, 255)]
    );
  }
}

async function getPrimaryDrive(siteId) {
  const d = await gget(`${GRAPH}/sites/${siteId}/drive?$select=id,name`);
  return d || null;
}

async function walkSite(siteId, drive, startedAt) {
  let biggest = null;
  let pages = 0, bailed = false;
  const stack = [{ id: 'root', path: '' }];
  while (stack.length) {
    if (pages >= SITE_MAX_PAGES) { bailed = true; break; }
    if (Date.now() - startedAt > SITE_MAX_MS) { bailed = true; break; }
    const node = stack.pop();
    let url = `${GRAPH}/sites/${siteId}/drives/${drive.id}/items/${node.id}/children?$select=id,name,size,folder,webUrl,lastModifiedDateTime,lastModifiedBy&$top=200`;
    while (url) {
      if (pages >= SITE_MAX_PAGES) { bailed = true; break; }
      if (Date.now() - startedAt > SITE_MAX_MS) { bailed = true; break; }
      const d = await gget(url);
      if (!d) break;
      pages++;
      for (const item of d.value || []) {
        if (!item.folder) continue;
        const path = node.path + '/' + item.name;
        const size = Number(item.size || 0);
        if (!biggest || size > biggest.size) {
          biggest = {
            id: item.id, name: item.name, path, size,
            web_url: item.webUrl || null,
            last_modified_at: item.lastModifiedDateTime || null,
            last_modified_by: (item.lastModifiedBy && item.lastModifiedBy.user && (item.lastModifiedBy.user.email || item.lastModifiedBy.user.displayName)) || null,
            last_modified_source: 'folder'
          };
        }
        if (!biggest || size >= biggest.size / 2) {
          stack.push({ id: item.id, path });
        }
      }
      url = d['@odata.nextLink'] || null;
    }
    if (bailed) break;
  }
  return { biggest, pages, bailed };
}

async function resolveModFromChildFile(siteId, driveId, folderId) {
  const url = `${GRAPH}/sites/${siteId}/drives/${driveId}/items/${folderId}/children?$select=name,lastModifiedDateTime,lastModifiedBy,file&$orderby=lastModifiedDateTime desc&$top=1`;
  try {
    const d = await gget(url);
    const child = ((d && d.value) || []).find(c => c.file);
    if (!child) return null;
    return {
      last_modified_at: child.lastModifiedDateTime || null,
      last_modified_by: (child.lastModifiedBy && child.lastModifiedBy.user && (child.lastModifiedBy.user.email || child.lastModifiedBy.user.displayName)) || null
    };
  } catch (e) { console.log(`[DEPT-WALK] child-file mod lookup failed: ${e.message}`); return null; }
}

(async () => {
  const startedAt = Date.now();
  const snapDate = new Date().toISOString().slice(0, 10);
  console.log(`[DEPT-WALK] ${new Date().toISOString()} starting snapshot ${snapDate}`);

  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'it_app',
    password: process.env.DB_PASSWORD || process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'corpit_hub',
    connectionLimit: 4
  });

  let allSites = [];
  try { allSites = await listSites(); console.log(`[DEPT-WALK] enumerated ${allSites.length} SharePoint sites`); }
  catch (e) { console.error(`[DEPT-WALK] FATAL enumerating: ${e.message}`); await pool.end(); process.exit(1); }
  await ensureSeed(pool, allSites);

  const [deptRows] = await pool.query(`SELECT site_id, site_name, web_url FROM department_sites WHERE is_department=1 ORDER BY site_name`);
  console.log(`[DEPT-WALK] ${deptRows.length} department sites to walk`);

  let ok = 0, partial = 0, skipped = 0, errored = 0;
  for (let i = 0; i < deptRows.length; i++) {
    const ds = deptRows[i];
    const siteStart = Date.now();
    try {
      if (!validDeptSiteId(ds.site_id)) { skipped++; console.log(`[DEPT-WALK] invalid site_id for ${ds.site_name} (not a SharePoint site id) - skipped: ${JSON.stringify(String(ds.site_id).slice(0, 120))}`); continue; }
      const drive = await getPrimaryDrive(ds.site_id);
      if (!drive) { skipped++; console.log(`[DEPT-WALK] no drive for ${ds.site_name}`); continue; }
      const { biggest, pages, bailed } = await walkSite(ds.site_id, drive, siteStart);
      if (!biggest) { skipped++; console.log(`[DEPT-WALK] no folders in ${ds.site_name}`); continue; }

      let modBy = biggest.last_modified_by, modAt = biggest.last_modified_at, modSrc = biggest.last_modified_source;
      if (!modBy || !modAt) {
        const fb = await resolveModFromChildFile(ds.site_id, drive.id, biggest.id);
        if (fb) { modBy = fb.last_modified_by; modAt = fb.last_modified_at; modSrc = 'child-file'; }
      }

      await pool.query(
        `INSERT INTO department_site_folders
         (snap_date, site_id, site_name, folder_id, folder_path, folder_name, folder_size_bytes,
          last_modified_by, last_modified_at, last_modified_source, folder_web_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           folder_id=VALUES(folder_id), folder_path=VALUES(folder_path), folder_name=VALUES(folder_name),
           folder_size_bytes=VALUES(folder_size_bytes), last_modified_by=VALUES(last_modified_by),
           last_modified_at=VALUES(last_modified_at), last_modified_source=VALUES(last_modified_source),
           folder_web_url=VALUES(folder_web_url), site_name=VALUES(site_name)`,
        [snapDate, ds.site_id, ds.site_name, biggest.id, biggest.path.slice(0, 1500),
          biggest.name.slice(0, 500), biggest.size, modBy ? modBy.slice(0, 320) : null,
          modAt ? new Date(modAt).toISOString().slice(0, 19).replace('T', ' ') : null, modSrc,
          biggest.web_url ? biggest.web_url.slice(0, 1500) : null]
      );
      if (bailed) { partial++; console.log(`[DEPT-WALK] ${ds.site_name}: PARTIAL biggest=${biggest.name} (${(biggest.size/1099511627776).toFixed(2)}TB) pages=${pages}`); }
      else { ok++; console.log(`[DEPT-WALK] ${ds.site_name}: biggest=${biggest.name} (${(biggest.size/1099511627776).toFixed(2)}TB) pages=${pages}`); }
    } catch (e) {
      errored++;
      console.log(`[DEPT-WALK] error site ${ds.site_name}: ${e.message}`);
    }
  }

  const secs = Math.round((Date.now() - startedAt) / 1000);
  console.log(`[DEPT-WALK] DONE — snapshot ${snapDate}: ${ok} ok, ${partial} partial, ${skipped} skipped, ${errored} errors, ${deptRows.length} sites in ${secs}s`);
  await pool.end();
})().catch(e => { console.error('[DEPT-WALK] FATAL', e); process.exit(1); });
