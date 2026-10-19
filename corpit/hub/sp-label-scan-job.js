#!/usr/bin/env node
'use strict';
/**
 * sp-label-scan-job.js — tenant-wide Purview retention label scan.
 *
 * 1. Discovers every retention label in use via a Graph search aggregation on
 *    the ComplianceTag managed property.
 * 2. For each label, pages the listItem search (ComplianceTag:"<label>") and
 *    stores one row per labelled item with its site.
 *
 * Source is the SharePoint search index, so a label applied minutes ago may
 * not appear until the index catches up. Items the app cannot see in search
 * are not counted. Both limits are shown on the page.
 *
 * Results → corpit_hub.sp_label_scan_runs / sp_label_scan_items.
 * Run nightly from root cron (flock + corpit-cronwrap) and on demand from
 * POST /api/sharepoint-labels/refresh.
 */
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const mysql = require('mysql2/promise');

const TENANT_ID     = process.env.SP_TENANT_ID;
const CLIENT_ID     = process.env.SP_CLIENT_ID;
const CLIENT_SECRET = process.env.SP_CLIENT_SECRET;
const GRAPH     = 'https://graph.microsoft.com/v1.0';
const TOKEN_URL = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;
const REGION    = 'NAM';
const PAGE_SIZE = 500;
const MAX_ITEMS_PER_LABEL = 25000;   // hard stop; run is flagged truncated if hit
const MAX_LABELS = 100;
const STALE_RUN_MIN = 120;
const BACKOFFS_MS = [5000, 15000, 45000, 120000];

const ts  = () => new Date().toISOString();
const log = (...a) => console.log('[LABEL-SCAN]', ts(), ...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));

let _token = null, _exp = 0;
async function getToken() {
  if (_token && Date.now() < _exp - 60000) return _token;
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET, scope: 'https://graph.microsoft.com/.default' }),
  });
  const d = await r.json();
  if (!d.access_token) throw new Error('Token: ' + JSON.stringify(d).slice(0, 300));
  _token = d.access_token; _exp = Date.now() + d.expires_in * 1000;
  return _token;
}

async function search(request) {
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(GRAPH + '/search/query', {
      method: 'POST',
      headers: { Authorization: `Bearer ${await getToken()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ requests: [{ region: REGION, ...request }] }),
    });
    if (r.ok) {
      const d = await r.json();
      return (d.value && d.value[0] && d.value[0].hitsContainers && d.value[0].hitsContainers[0]) || {};
    }
    if ((r.status === 429 || r.status >= 500) && attempt < BACKOFFS_MS.length) {
      const ra = parseInt(r.headers.get('retry-after') || '0', 10);
      const wait = ra > 0 ? ra * 1000 + 500 : BACKOFFS_MS[attempt];
      log(`HTTP ${r.status} — retry in ${Math.round(wait / 1000)}s`);
      await sleep(wait); continue;
    }
    throw new Error(`search HTTP ${r.status}: ${(await r.text()).slice(0, 300)}`);
  }
}

async function discoverLabels() {
  const c = await search({
    entityTypes: ['listItem'], query: { queryString: 'ComplianceTag:*' }, size: 1,
    aggregations: [{ field: 'ComplianceTag', size: MAX_LABELS,
      bucketDefinition: { sortBy: 'count', isDescending: true, minimumCount: 1 } }],
  });
  const agg = (c.aggregations || []).find(a => a.field === 'ComplianceTag');
  return ((agg && agg.buckets) || []).map(b => ({ label: b.key, count: Number(b.count) || 0 }))
    .filter(b => b.label);
}

const FIELDS = ['complianceTag', 'spSiteURL', 'spWebUrl', 'siteTitle', 'siteId', 'path', 'title', 'fileName',
  'fileExtension', 'lastModifiedTime', 'modifiedBy', 'size', 'isDocument', 'relatedHubSites'];

async function graphGet(p) {
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(GRAPH + p, { headers: { Authorization: `Bearer ${await getToken()}` } });
    if (r.ok) return r.json();
    if ((r.status === 429 || r.status >= 500) && attempt < BACKOFFS_MS.length) {
      const ra = parseInt(r.headers.get('retry-after') || '0', 10);
      await sleep(ra > 0 ? ra * 1000 + 500 : BACKOFFS_MS[attempt]); continue;
    }
    const e = new Error(`GET ${p} HTTP ${r.status}`); e.status = r.status; throw e;
  }
}

const dec = u => { try { return decodeURI(String(u || '')); } catch { return String(u || ''); } };
const norm = u => dec(u).replace(/\/+$/, '').toLowerCase();

// Hub = first id in relatedHubSites (a hub site lists itself). Resolved to its
// site title/URL once per id; an id Graph cannot resolve is kept with no title.
const hubCache = new Map();
async function resolveHub(host, hubId) {
  if (!hubId) return null;
  if (!hubCache.has(hubId)) {
    let v = { id: hubId, title: null, url: null };
    try { const s = await graphGet(`/sites/${host},${hubId}?$select=displayName,webUrl`); v = { id: hubId, title: s.displayName || null, url: s.webUrl || null }; }
    catch (e) { log(`hub ${hubId} unresolved: ${e.message}`); }
    hubCache.set(hubId, v);
  }
  return hubCache.get(hubId);
}

// Lists of each web (site or subsite), longest URL first so the most specific
// list wins the prefix match against an item path.
const listCache = new Map();
async function listsFor(webUrl) {
  const key = norm(webUrl);
  if (!listCache.has(key)) {
    let lists = [];
    try {
      const u = new URL(dec(webUrl));
      const d = await graphGet(`/sites/${u.hostname}:${encodeURI(u.pathname.replace(/\/+$/, '') || '/')}:/lists?$select=displayName,webUrl&$top=500`);
      lists = (d.value || []).filter(l => l.webUrl).map(l => ({ name: l.displayName, url: dec(l.webUrl).replace(/\/+$/, '') }))
        .sort((a, b) => b.url.length - a.url.length);
    } catch (e) { log(`lists for ${webUrl} unavailable: ${e.message}`); }
    listCache.set(key, lists);
  }
  return listCache.get(key);
}

// A non-document hit whose path is a DispForm URL is a list item (a row in a
// list, or a non-file item in a library); any other non-document is a folder.
const isListItemPath = p => /\/DispForm\.aspx(\?|$)/i.test(dec(p));
function itemKind(r) { return r.is_document ? 'file' : isListItemPath(r.path) ? 'list_item' : 'folder'; }

// Library (or list) + folder for one item. folder_path is the item's containing
// folder within its library; for a labelled folder it is the folder itself, so
// the folder and the files inside it group together. List items sit at the
// list root (''). When Graph cannot list the web's libraries (OneDrive sites
// can return 423; Site Pages is not always listed), the library is taken from
// the URL segment instead — its URL name, which can differ from the display
// name ("Shared Documents" vs "Documents").
async function locate(r, kind) {
  const web = dec(r.web_url || r.site_url).replace(/\/+$/, '');
  const path = dec(r.path).split('?')[0];
  const lists = web ? await listsFor(web) : [];
  let lib = lists.find(l => path.toLowerCase() === l.url.toLowerCase() || path.toLowerCase().startsWith(l.url.toLowerCase() + '/'));
  if (!lib && web && path.toLowerCase().startsWith(web.toLowerCase() + '/')) {
    const segs = path.slice(web.length + 1).split('/');
    const n = segs[0].toLowerCase() === 'lists' && segs.length > 1 ? 2 : 1;
    lib = { name: segs[n - 1], url: web + '/' + segs.slice(0, n).join('/') };
  }
  if (!lib) return { library: null, library_url: null, folder_path: null };
  let rel = path.slice(lib.url.length).replace(/^\/+/, '');
  if (kind === 'list_item') rel = '';
  else if (kind === 'file') rel = rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '';
  return { library: lib.name, library_url: lib.url, folder_path: rel };
}

function kqlQuote(s) { return '"' + String(s).replace(/"/g, '') + '"'; }

function toDate(v) {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d) ? null : d;
}
const trunc = (v, n) => (v == null ? null : String(v).slice(0, n));

async function scanLabel(label) {
  const rows = []; const seen = new Set();
  let from = 0, total = null, truncated = false;
  while (true) {
    const c = await search({ entityTypes: ['listItem'], query: { queryString: 'ComplianceTag:' + kqlQuote(label) },
      fields: FIELDS, from, size: PAGE_SIZE });
    if (total == null) total = Number(c.total) || 0;
    const hits = c.hits || [];
    for (const h of hits) {
      const f = (h.resource && h.resource.fields) || {};
      // The KQL match is on the managed property; keep only exact label matches.
      if (f.complianceTag && f.complianceTag !== label) continue;
      const key = f.path || h.hitId;
      if (seen.has(key)) continue;
      seen.add(key);
      const isDoc = String(f.isDocument).toLowerCase() === 'true';
      rows.push({
        label, site_title: f.siteTitle, site_url: f.spSiteURL, site_id: f.siteId, web_url: f.spWebUrl,
        path: f.path, file_name: f.fileName || f.title, file_ext: (f.fileExtension || '').toLowerCase(),
        is_document: isDoc ? 1 : 0, size_bytes: Number(f.size) || null, modified_at: toDate(f.lastModifiedTime),
        modified_by: f.modifiedBy, hub_id: String(f.relatedHubSites || '').split(/[;,\s]+/).filter(Boolean)[0] || null,
      });
    }
    from += hits.length;
    if (!hits.length || !c.moreResultsAvailable) break;
    if (from >= MAX_ITEMS_PER_LABEL) { truncated = true; break; }
  }
  return { rows, total, truncated };
}

async function main() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    connectionLimit: 2, timezone: 'Z',
  });
  const batch = Date.now();
  try {
    // Cron (flock) and the on-demand route (hub user, no shared lock) can both
    // start this job, so exclusivity is by row: a scan takes minutes, so a
    // 'running' row younger than STALE_RUN_MIN is treated as live and this
    // start exits; older ones were killed and are reaped.
    const [reaped] = await pool.query(
      "UPDATE sp_label_scan_runs SET status='failed', finished_at=UTC_TIMESTAMP(), error='abandoned (process ended before finishing)' " +
      "WHERE status='running' AND started_at < UTC_TIMESTAMP() - INTERVAL ? MINUTE", [STALE_RUN_MIN]);
    if (reaped.affectedRows) log(`reaped ${reaped.affectedRows} abandoned run(s)`);
    const [live] = await pool.query("SELECT batch_id FROM sp_label_scan_runs WHERE status='running' LIMIT 1");
    if (live.length) { log(`batch ${live[0].batch_id} already running — exiting`); return; }
    await pool.query("INSERT INTO sp_label_scan_runs (batch_id, started_at, status) VALUES (?, UTC_TIMESTAMP(), 'running')", [batch]);
    log(`batch ${batch} started`);

    const labels = await discoverLabels();
    log(`labels found: ${labels.map(l => `${l.label} (${l.count})`).join(', ') || 'none'}`);
    let items = 0, anyTrunc = false;
    for (const l of labels) {
      const { rows, total, truncated } = await scanLabel(l.label);
      anyTrunc = anyTrunc || truncated;
      const vals = [];
      for (const r of rows) {
        let host = null; try { host = new URL(r.site_url).hostname; } catch {}
        const hub = host ? await resolveHub(host, r.hub_id) : null;
        const kind = itemKind(r);
        const loc = await locate(r, kind);
        vals.push([batch, trunc(r.label, 255), trunc(r.site_title, 255), trunc(r.site_url, 512), trunc(r.site_id, 64),
          trunc(r.web_url, 512), trunc(hub && hub.id, 64), trunc(hub && hub.title, 255), trunc(hub && hub.url, 512),
          trunc(loc.library, 255), trunc(loc.library_url, 1024), trunc(loc.folder_path, 1024),
          trunc(r.path, 1024), trunc(r.file_name, 512), trunc(r.file_ext, 32), r.is_document, r.size_bytes,
          r.modified_at, trunc(r.modified_by, 255), kind]);
      }
      for (let i = 0; i < vals.length; i += 500) {
        await pool.query(
          `INSERT INTO sp_label_scan_items (batch_id, label, site_title, site_url, site_id, web_url, hub_id, hub_title,
             hub_url, library, library_url, folder_path, path, file_name, file_ext, is_document, size_bytes,
             modified_at, modified_by, item_kind) VALUES ?`, [vals.slice(i, i + 500)]);
      }
      await pool.query(
        'INSERT INTO sp_label_scan_labels (batch_id, label, search_total, items_stored, truncated) VALUES (?,?,?,?,?)',
        [batch, l.label, total, rows.length, truncated ? 1 : 0]);
      items += rows.length;
      log(`${l.label}: ${rows.length} stored (search total ${total}${truncated ? ', TRUNCATED' : ''})`);
    }
    await pool.query(
      "UPDATE sp_label_scan_runs SET status='done', finished_at=UTC_TIMESTAMP(), labels_found=?, items_found=?, truncated=? WHERE batch_id=?",
      [labels.length, items, anyTrunc ? 1 : 0, batch]);
    // Keep the last 30 completed runs.
    const [old] = await pool.query(
      "SELECT batch_id FROM sp_label_scan_runs WHERE status='done' ORDER BY batch_id DESC LIMIT 1000 OFFSET 30");
    if (old.length) {
      const ids = old.map(r => r.batch_id);
      await pool.query('DELETE FROM sp_label_scan_items WHERE batch_id IN (?)', [ids]);
      await pool.query('DELETE FROM sp_label_scan_labels WHERE batch_id IN (?)', [ids]);
    }
    await pool.query(
      "DELETE i FROM sp_label_scan_items i JOIN sp_label_scan_runs r ON r.batch_id=i.batch_id WHERE r.status='failed'");
    log(`batch ${batch} done: ${labels.length} labels, ${items} items`);
  } catch (e) {
    log('FAILED', e.message);
    await pool.query("UPDATE sp_label_scan_runs SET status='failed', finished_at=UTC_TIMESTAMP(), error=? WHERE batch_id=?",
      [String(e.message).slice(0, 1000), batch]).catch(() => {});
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main();
