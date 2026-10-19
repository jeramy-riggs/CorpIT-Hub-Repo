'use strict';

const express = require('express');
const router  = express.Router();
// ---- RBAC enforcement (Slice 5: sharepoint-gov) ----
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
// ---------------------------------------------------------------------

// CORPIT-PRTG-GUARD 2026-09-06.  prtg01awsw2us.nrpi.local:5050 is shared with
// the ITAM deployment, which owns the SharePoint growth sensor and pushes it
// from its own 10:30 cron. Two hosts pushing the same channels to the same
// sensor would overwrite each other's readings and reset each other's alerting
// baseline. Exactly one host may push; this switch designates it. Fail closed:
// anything other than an explicit "1" means this host does not push.
const PRTG_ENABLED  = process.env.SP_PRTG_ENABLED === '1';

const TENANT_ID     = process.env.SP_TENANT_ID;
const CLIENT_ID     = process.env.SP_CLIENT_ID;
const CLIENT_SECRET = process.env.SP_CLIENT_SECRET;
const GRAPH         = 'https://graph.microsoft.com/v1.0';
const TOKEN_URL     = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;

// ── Seed data for enrichment (hub, ext_sharing, site name, dates) ────────
// The usage report lacks these fields; we merge from XLS-extracted seed.
const _seedIndex = new Map();
let _seedAsOf = null; // date of the seed file — hub/ext_sharing are only as fresh as this
let _seedMtimeMs = 0;
// Reloadable so the nightly sharepoint-seed-refresh-job.js takes effect without a
// restart: re-checked on every cache rebuild. A corrupt or missing file keeps the
// previous index (and the date only updates after a successful parse).
function loadSeedIndex() {
  try {
    const fs = require('fs');
    const _seedPath = require('path').join(__dirname, 'sharepoint-seed.json');
    const st = fs.statSync(_seedPath);
    if (st.mtimeMs === _seedMtimeMs) return; // unchanged since last load
    const _seedData = JSON.parse(fs.readFileSync(_seedPath, 'utf8'));
    _seedIndex.clear();
    for (const s of _seedData) {
      if (s.url) _seedIndex.set(s.url.toLowerCase().replace(/\/$/, ''), s);
    }
    _seedMtimeMs = st.mtimeMs;
    _seedAsOf = st.mtime.toISOString().slice(0, 10);
    console.log(`[SP] Seed index loaded: ${_seedIndex.size} sites for enrichment (as of ${_seedAsOf})`);
  } catch (e) {
    console.warn('[SP] Seed load failed — keeping previous seed index:', e.message);
  }
}
loadSeedIndex();

function mergeSeed(site) {
  const key = (site.url || '').toLowerCase().replace(/\/$/, '');
  const seed = _seedIndex.get(key);
  if (!seed) return site;
  return {
    ...site,
    name:         seed.name || site.name,
    hub:          seed.hub || site.hub,
    ext_sharing:  seed.ext_sharing || site.ext_sharing,
    teams:        seed.teams ?? site.teams,
    m365_group:   seed.m365_group ?? site.m365_group,
    date_created: seed.date_created || site.date_created,
    created_by:   seed.created_by || site.created_by,
  };
}

let _token = null, _tokenExpiry = 0;

async function getToken() {
  if (_token && Date.now() < _tokenExpiry - 60_000) return _token;
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default',
  });
  const res  = await fetch(TOKEN_URL, { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  const data = await res.json();
  if (!data.access_token) throw new Error(`Token error: ${JSON.stringify(data)}`);
  _token       = data.access_token;
  _tokenExpiry = Date.now() + data.expires_in * 1000;
  return _token;
}

async function gGet(path, token) {
  const url = path.startsWith('http') ? path : `${GRAPH}${path}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  const ct  = res.headers.get('content-type') || '';
  if (!res.ok) { const e = await res.text(); throw new Error(`Graph ${res.status} on ${path}: ${e.slice(0,300)}`); }
  if (ct.includes('text/csv') || ct.includes('text/plain') || ct.includes('octet-stream') || !ct.includes('json')) return { _csv: await res.text() };
  const text = await res.text();
  if (text.startsWith('Report') || text.startsWith('"Report')) return { _csv: text };
  try { return JSON.parse(text); } catch(e) { return { _csv: text }; }
}

function parseCSV(text) {
  const lines = text.replace(/\r\n/g,'\n').replace(/\r/g,'\n').trim().split('\n');
  if (lines.length < 2) return [];
  const headers = splitCSVLine(lines[0]);
  return lines.slice(1).map(line => {
    const cols = splitCSVLine(line);
    const obj = {};
    headers.forEach((h,i) => { obj[h.trim()] = (cols[i]||'').trim(); });
    return obj;
  }).filter(r => Object.values(r).some(v => v));
}

function splitCSVLine(line) {
  const cols = []; let cur = '', inQ = false;
  for (const ch of line) {
    if (ch === '"') { inQ = !inQ; }
    else if (ch === ',' && !inQ) { cols.push(cur); cur = ''; }
    else cur += ch;
  }
  cols.push(cur);
  return cols;
}

async function gGetAll(path, token) {
  const items = []; let next = path;
  while (next) {
    const res = await gGet(next, token);
    if (res.value) items.push(...res.value);
    next = res['@odata.nextLink'] || null;
  }
  return items;
}

function computeTier(lastActivity) {
  if (!lastActivity) return 'never';
  const d = Math.floor((Date.now() - new Date(lastActivity).getTime()) / 86_400_000);
  if (d >= 730) return 'critical';
  if (d >= 365) return 'high';
  if (d >= 180) return 'medium';
  if (d >= 90)  return 'watch';
  return 'active';
}

function daysInactive(lastActivity) {
  if (!lastActivity) return null;
  return Math.floor((Date.now() - new Date(lastActivity).getTime()) / 86_400_000);
}

function normSharing(cap) {
  if (!cap || cap === 'Disabled') return 'Off';
  return 'On';
}

// CorpIT port fix: upstream Graph/AAD error bodies (tenant id, client id,
// correlation ids, AADSTS codes) used to be returned to the browser verbatim.
// The full text still goes to the server log; the client gets the shape only.
function safeErr(e) {
  const m = String((e && e.message) || e || 'error');
  const graph = m.match(/^Graph (\d{3}) on ([^:]+):/);
  if (graph) return `Microsoft Graph returned ${graph[1]} for ${graph[2]}`;
  if (/token|AADSTS|client_secret|client_id/i.test(m)) return 'Microsoft Graph authentication failed';
  return m.slice(0, 200);
}

let _cache = null, _cacheExpiry = 0;
const CACHE_TTL = 6 * 60 * 60 * 1000;
let _refreshInflight = null;

async function fetchAllData(forceRefresh = false) {
  if (!forceRefresh && _cache && Date.now() < _cacheExpiry) return _cache;
  // Every SharePoint view calls this function. A cold cache used to start one
  // Graph site crawl per simultaneous request (including /sites and /summary).
  // Share the rebuild, then clear the promise on success or failure so retries
  // still work. A forced refresh joins an already running rebuild.
  if (_refreshInflight) return _refreshInflight;
  const pending = rebuildAllData();
  _refreshInflight = pending;
  try { return await pending; }
  finally { if (_refreshInflight === pending) _refreshInflight = null; }
}

async function rebuildAllData() {
  loadSeedIndex(); // pick up a refreshed sharepoint-seed.json without a restart
  const token = await getToken();

  // ── Step 1: Get all sites from Sites API (NOT subject to privacy toggle) ──
  // This gives us real IDs, URLs, and display names for every site.
  let allSiteData = [];
  try {
    console.log('[SP] Fetching sites from Sites search API…');
    allSiteData = await gGetAll('/sites/getAllSites?$select=id,webUrl,displayName,createdDateTime,lastModifiedDateTime&$top=500', token);
    console.log(`[SP] Sites API returned: ${allSiteData.length} sites`);
  } catch (e) {
    console.warn('[SP] getAllSites failed, trying search fallback:', e.message);
    try {
      allSiteData = await gGetAll('/sites?search=*&$select=id,webUrl,displayName,createdDateTime,lastModifiedDateTime&$top=500', token);
      console.log(`[SP] Sites search returned: ${allSiteData.length} sites`);
    } catch (e2) {
      console.error('[SP] Sites search also failed:', e2.message);
      // CorpIT port fix: do NOT fall through with an empty site list. Doing so
      // built a zeroed summary, cached it for CACHE_TTL, and let the dashboard
      // paint a green LIVE badge over a tenant it never actually read.
      throw new Error('SharePoint site list unavailable: ' + e2.message);
    }
  }
  if (!allSiteData.length) {
    // Same reasoning: a real tenant is never zero sites. Surface it.
    throw new Error('SharePoint site list came back empty - refusing to publish a zeroed tenant');
  }

  // ── Step 2: Build usage metrics index from the report ──
  // Key by Site Id (stable GUID) rather than Site URL. URL is blank in reports
  // when Microsoft's "Display concealed names" tenant setting is enabled.
  // Site Id is always populated and matches the middle segment of the Sites API composite id.
  let reportIndex = new Map(); // keyed by site collection GUID (lowercase)
  let reportRows = [];
  try {
    const rpt = await gGet(`/reports/getSharePointSiteUsageDetail(period='D180')`, token);
    if (rpt._csv) reportRows = parseCSV(rpt._csv);
    else if (Array.isArray(rpt.value)) reportRows = rpt.value;
    console.log(`[SP] Usage report rows: ${reportRows.length}`);

    for (const r of reportRows) {
      const siteId = (r['Site Id'] || '').toLowerCase();
      if (siteId) reportIndex.set(siteId, r);
    }
    console.log(`[SP] Report rows with Site Ids: ${reportIndex.size} of ${reportRows.length}`);
  } catch (e) { console.warn('[SP] Usage report failed (non-fatal):', e.message); }

  // ── Step 3: Build site objects from Sites API, enrich with report + seed ──
  const sites = allSiteData
    .filter(s => s.webUrl && !s.webUrl.includes('-my.sharepoint.com') && !s.webUrl.includes('/personal/'))
    .map(s => {
      const url = s.webUrl || '';

      // Sites API returns composite id: "hostname,siteCollectionId,webId".
      // Usage report's "Site Id" = the middle component (siteCollectionId GUID).
      const siteCollectionId = ((s.id || '').split(',')[1] || '').toLowerCase();
      const report = reportIndex.get(siteCollectionId);

      // Compute metrics from report if available, otherwise null
      const storageBytes = report ? parseInt(report['Storage Used (Byte)'] || 0) : 0;
      const lastAct      = report ? (report['Last Activity Date'] || null) : null;
      const fileCount    = report ? parseInt(report['File Count'] || 0) : 0;
      const activeFiles  = report ? parseInt(report['Active File Count'] || 0) : 0;
      const pageViews    = report ? parseInt(report['Page View Count'] || 0) : 0;
      const pageVisits   = report ? parseInt(report['Visited Page Count'] || 0) : 0;
      const template     = report ? (report['Root Web Template'] || '') : '';
      const ownerName    = report ? (report['Owner Display Name'] || '') : '';
      const ownerUPN     = report ? (report['Owner Principal Name'] || '') : '';

      return {
        id:            s.id || null,
        name:          s.displayName || '',
        url:           url,
        hub:           null,
        storage_gb:    parseFloat((storageBytes / 1_073_741_824).toFixed(2)),
        ext_sharing:   'Unknown',
        template,
        teams:         template === 'Group',
        last_activity: lastAct || null,
        date_created:  s.createdDateTime || null,
        days_inactive: daysInactive(lastAct),
        tier:          computeTier(lastAct),
        file_count:    fileCount,
        active_files:  activeFiles,
        page_views:    pageViews,
        page_visits:   pageVisits,
        admin:         ownerName || null,
        admin_upn:     ownerUPN || null,
        last_modified_by: null,
      };
    })
    .map(mergeSeed);

  // ── Step 2b: Fetch lastModifiedBy from each site's drive (batched, 10 concurrent) ──
  const BATCH = 10;
  const driveIndex = new Map();
  for (let i = 0; i < sites.length; i += BATCH) {
    const batch = sites.slice(i, i + BATCH);
    await Promise.all(batch.map(async site => {
      try {
        const rawSite = allSiteData.find(s => (s.webUrl || '') === site.url);
        if (!rawSite) return;
        const data = await gGet(`/sites/${rawSite.id}/drive/root/children?$orderby=lastModifiedDateTime desc&$top=1&$select=lastModifiedBy,name`, token);
        const items = data?.value;
        const name = items?.[0]?.lastModifiedBy?.user?.displayName || null;
        if (name) driveIndex.set(site.url, name);
      } catch (e) { /* non-fatal */ }
    }));
  }
  for (const site of sites) {
    if (driveIndex.has(site.url)) site.last_modified_by = driveIndex.get(site.url);
  }

  // Log merge results
  const withHub = sites.filter(s => s.hub);
  const withExt = sites.filter(s => s.ext_sharing !== 'Unknown');
  const withMetrics = sites.filter(s => s.storage_gb > 0 || s.file_count > 0);
  console.log(`[SP] After seed merge: ${withHub.length} with hub, ${withExt.length} with ext_sharing, ${withMetrics.length} with metrics`);

  // If usage report URLs were concealed (reportIndex empty) but seed has metrics, use seed
  if (reportIndex.size === 0 && _seedIndex && _seedIndex.size > 0) {
    console.log('[SP] Usage report concealed — supplementing metrics from seed data');
    for (const site of sites) {
      const seedKey = site.url.toLowerCase().replace(/\/$/, '');
      const seed = _seedIndex.get(seedKey);
      if (!seed) continue;
      // Only fill in metrics if site has none from the report
      if (site.storage_gb === 0 && seed.storage_gb)   site.storage_gb = seed.storage_gb;
      if (!site.last_activity && seed.last_activity)   site.last_activity = seed.last_activity;
      if (site.file_count === 0 && seed.file_count)    site.file_count = seed.file_count;
      if (site.active_files === 0 && seed.active_files) site.active_files = seed.active_files;
      if (site.page_views === 0 && seed.page_views)    site.page_views = seed.page_views;
      if (site.page_visits === 0 && seed.page_visits)  site.page_visits = seed.page_visits;
      if (!site.admin && seed.admin)                   site.admin = seed.admin;
      if (!site.admin_upn && seed.admin_upn)           site.admin_upn = seed.admin_upn;
      // Recompute tier from seed activity
      site.days_inactive = daysInactive(site.last_activity);
      site.tier = computeTier(site.last_activity);
    }
    const withMetrics2 = sites.filter(s => s.storage_gb > 0 || s.file_count > 0);
    console.log(`[SP] After seed metric supplement: ${withMetrics2.length} with metrics`);
  }

  const total_gb = parseFloat(sites.reduce((s,x) => s+x.storage_gb, 0).toFixed(2));
  const critical = sites.filter(s => s.tier==='critical'||s.tier==='never');
  const high     = sites.filter(s => s.tier==='high');
  const medium   = sites.filter(s => s.tier==='medium');
  const watch    = sites.filter(s => s.tier==='watch');
  const extOn    = sites.filter(s => s.ext_sharing==='On');
  const noHub    = sites.filter(s => !s.hub);

  const summary = {
    total_sites:       sites.length,
    total_gb,
    ext_on_count:      extOn.length,
    inactive_critical: critical.length,
    inactive_high:     high.length,
    inactive_medium:   medium.length,
    inactive_watch:    watch.length,
    no_hub_count:      noHub.length,
    no_hub_gb:         parseFloat(noHub.reduce((s,x) => s+x.storage_gb, 0).toFixed(2)),
    refreshed_at:      new Date().toISOString(),
    source:            'Microsoft Graph API · auctiondotcom tenant',
    seed_as_of:        _seedAsOf, // hub + ext_sharing enrichment date (not live via Graph)
  };

  const hubMap = {};
  for (const s of sites) {
    const h = s.hub || 'No Hub';
    if (!hubMap[h]) hubMap[h] = { hub: h, sites: 0, gb: 0 };
    hubMap[h].sites++;
    hubMap[h].gb += s.storage_gb;
  }
  const hubs = Object.values(hubMap)
    .map(h => ({ ...h, gb: parseFloat(h.gb.toFixed(2)) }))
    .sort((a,b) => b.gb - a.gb);

  summary.hubs = hubs;
  _cache      = { summary, sites, hubs };
  _cacheExpiry = Date.now() + CACHE_TTL;
  console.log(`[SP] cache built: ${sites.length} sites, ${total_gb} GB`);
  return _cache;
}

router.get('/summary', rbac.requirePage('sharepoint-gov','read'), async (req, res) => {
  try { const { summary } = await fetchAllData();
        res.json(Object.assign({}, summary, { prtg_enabled: PRTG_ENABLED })); }
  catch(e) { console.error('[SP] summary:', e.message); res.status(500).json({ error: safeErr(e) }); }
});

router.get('/sites', rbac.requirePage('sharepoint-gov','read'), async (req, res) => {
  try {
    const { sites } = await fetchAllData();
    const { tier, hub, ext } = req.query;
    let result = sites;
    // CorpIT port fix: a repeated query param arrives as an Array and threw on
    // .toLowerCase(), 500ing the route. Take the last value, as Express does elsewhere.
    const one = v => Array.isArray(v) ? String(v[v.length-1]) : (v == null ? v : String(v));
    const qTier = one(tier), qHub = one(hub), qExt = one(ext);
    if (qTier) result = result.filter(s => s.tier === qTier);
    if (qHub)  result = result.filter(s => (s.hub||'No Hub').toLowerCase() === qHub.toLowerCase());
    if (qExt)  result = result.filter(s => s.ext_sharing === (qExt==='on'?'On':'Off'));
    res.json(result);
  }
  catch(e) { console.error('[SP] sites:', e.message); res.status(500).json({ error: safeErr(e) }); }
});

router.get('/hubs', rbac.requirePage('sharepoint-gov','read'), async (req, res) => {
  try { const { hubs } = await fetchAllData(); res.json(hubs); }
  catch(e) { console.error('[SP] hubs:', e.message); res.status(500).json({ error: safeErr(e) }); }
});

router.get('/inactive', rbac.requirePage('sharepoint-gov','read'), async (req, res) => {
  try {
    const { sites } = await fetchAllData();
    res.json(sites.filter(s => ['critical','high','medium','watch','never'].includes(s.tier))
                  .sort((a,b) => (b.days_inactive||9999)-(a.days_inactive||9999)));
  }
  catch(e) { console.error('[SP] inactive:', e.message); res.status(500).json({ error: safeErr(e) }); }
});

router.get('/external-sharing', rbac.requirePage('sharepoint-gov','read'), async (req, res) => {
  try {
    const { sites } = await fetchAllData();
    res.json(sites.filter(s => s.ext_sharing==='On').sort((a,b) => b.storage_gb-a.storage_gb));
  }
  catch(e) { console.error('[SP] ext-sharing:', e.message); res.status(500).json({ error: safeErr(e) }); }
});

router.post('/refresh', rbac.requirePage('sharepoint-gov','admin'), async (req, res) => {
  try {
    _cache = null; _cacheExpiry = 0;
    const data = await fetchAllData(true);
    res.json({ ok: true, sites: data.sites.length, refreshed_at: data.summary.refreshed_at });
  }
  catch(e) { console.error('[SP] refresh:', e.message); res.status(500).json({ error: safeErr(e) }); }
});

// Live probe (60s cache): acquires a Graph token and hits a cheap SharePoint
// endpoint, so `ok` reflects real reachability instead of just config presence.
let _spHealth = { checkedAt: 0, ok: null, detail: null };

router.get('/health', rbac.requirePage('sharepoint-gov','read'), async (req, res) => {
  const configured = !!(TENANT_ID && CLIENT_ID && CLIENT_SECRET);
  const base = {
    configured,
    prtg_enabled: PRTG_ENABLED,
    cache_valid: !!(_cache && Date.now() < _cacheExpiry),
    cached_sites: _cache?.sites?.length || 0,
  };
  if (!configured) {
    return res.json(Object.assign({ ok: false, reason: 'unconfigured' }, base));
  }
  const now = Date.now();
  if (_spHealth.ok !== null && (now - _spHealth.checkedAt) < 60000) {
    return res.json(Object.assign({
      ok: _spHealth.ok, cached: true, checkedAt: _spHealth.checkedAt,
      probe: 'graph:/sites/root', error: _spHealth.ok ? undefined : _spHealth.detail,
    }, base));
  }
  try {
    const token = await getToken();
    await gGet('/sites/root?$select=id', token);
    _spHealth = { checkedAt: now, ok: true, detail: null };
    return res.json(Object.assign({
      ok: true, cached: false, checkedAt: now, probe: 'graph:/sites/root',
    }, base));
  } catch (e) {
    const detail = String(e && e.message || e).slice(0, 200);
    _spHealth = { checkedAt: now, ok: false, detail };
    console.error('[SP] health probe:', detail);
    return res.json(Object.assign({
      ok: false, cached: false, checkedAt: now, probe: 'graph:/sites/root',
      reason: 'probe_failed', error: detail,
    }, base));
  }
});

module.exports = router;
// Exported for direct in-process reuse by other routes on this same server
// (e.g. Licensing & Cost's SharePoint tile) -- same calculation, not a copy.
module.exports.fetchAllData = fetchAllData;

// ── PRTG Reset Baseline ───────────────────────────────────────────────────────
router.post('/prtg-reset', rbac.requirePage('sharepoint-gov','admin'), async (req, res) => {
  // CORPIT-PRTG-GUARD  Refuse before the re-snapshot, the push-state reset and
  // the push itself, so a blocked call leaves this host and PRTG untouched.
  if (!PRTG_ENABLED) {
    return res.status(409).json({
      ok: false,
      error: 'prtg_disabled',
      detail: 'PRTG push is disabled on this host. The prtg01awsw2us.nrpi.local:5050 '
            + 'SharePoint growth sensor is pushed by the ITAM deployment; resetting the '
            + 'baseline from here would overwrite its reading. To designate this host the '
            + 'pusher, set SP_PRTG_ENABLED=1 in /var/www/corpit-hub-api/.env and stop the '
            + 'ITAM cron first.',
    });
  }
  const mysql = require('mysql2/promise');
  const { pushToPrtg } = require('./prtg-helper');
  let conn;
  try {
    conn = await mysql.createConnection({
      host: 'localhost', user: 'root',
      socketPath: '/var/run/mysqld/mysqld.sock',
      database: 'corpit_hub',
    });

    // Re-snapshot current storage as new baseline
    const data = await fetchAllData(true);
    const sites = data.sites || [];
    const now = new Date();
    for (const s of sites) {
      const siteCollectionId = ((s.id || '').split(',')[1] || '').toLowerCase();
      if (!siteCollectionId) continue;
      await conn.execute(`
        INSERT INTO sharepoint_prtg_state (site_id, site_name, site_url, storage_gb, snapshot_taken_at)
        VALUES (?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          site_name=VALUES(site_name), site_url=VALUES(site_url),
          storage_gb=VALUES(storage_gb), snapshot_taken_at=VALUES(snapshot_taken_at)
      `, [siteCollectionId, s.displayName || s.webUrl, s.webUrl, (s.storageBytes||0)/1073741824, now]);
    }

    // Reset push state
    await conn.execute(`
      UPDATE sharepoint_prtg_push_state SET last_push_alert_count=-1, last_push_at=NOW(), last_push_status='reset' WHERE id=1
    `);

    // Push 0 to PRTG immediately → sensor goes green
    const result = await pushToPrtg(
      { host:'prtg01awsw2us.nrpi.local', port:5050, protocol:'http', token:process.env.PRTG_PUSH_TOKEN, timeoutMs:5000 },
      [
        { channel:'Sites Over Threshold', value:0 },
        { channel:'Total Sites Monitored', value:sites.length },
        { channel:'Growth Threshold %',   value:10 },
      ],
      `Baseline reset by ${req.user?.name || req.user?.email || 'admin'} — ${sites.length} sites re-snapshotted`
    );

    res.json({ ok: true, sites: sites.length, prtg: result });
  } catch (err) {
    console.error('[sp-prtg-reset]', err);
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    if (conn) await conn.end();
  }
});
