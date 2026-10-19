'use strict';
// sharepoint-seed-refresh-job.js — regenerate sharepoint-seed.json nightly.
// Source: the tenant-admin site's hidden aggregated site list
//   DO_NOT_DELETE_SPLIST_TENANTADMIN_AGGREGATED_SITECOLLECTIONS
// — the same data behind the SharePoint admin center's XLS export — read app-only
// via Graph (Sites.Read.All, already granted). No SharePoint-resource permission
// or certificate needed. CAVEAT: internal Microsoft list; if its shape ever
// changes this job fails validation and the previous seed stays in place.
// Deploy: /var/www/corpit-hub-api/sharepoint-seed-refresh-job.js
// Cron:   45 4 * * *  /usr/bin/node /var/www/corpit-hub-api/sharepoint-seed-refresh-job.js >> /var/log/sharepoint-seed-refresh.log 2>&1
// api-beta picks the new seed up on its next cache rebuild (mtime check) — no restart.
// Flags: --dry-run  fetch+map+validate, print summary, write nothing.

require('/var/www/corpit-hub-api/node_modules/dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const fs = require('fs');
const path = require('path');
const https = require('https');

const ADMIN_HOST = 'auctiondotcom-admin.sharepoint.com';
const SITE_PREFIX = 'https://auctiondotcom.sharepoint.com';
const SEED_PATH = '/var/www/corpit-hub-api/sharepoint-seed.json';
const MIN_SITES = 150;         // tenant runs ~213-250 site collections
const MIN_EXT_COVERAGE = 0.9;  // fraction of rows that must have On/Off
const KEEP_BAKS = 5;
const ZERO_GUID = '00000000-0000-0000-0000-000000000000';
const DRY = process.argv.includes('--dry-run');

const log = (m) => console.log(`[SEED-REFRESH] ${new Date().toISOString()} ${m}`);

function getToken() {
  return new Promise((resolve, reject) => {
    const body = `client_id=${process.env.SP_CLIENT_ID}&client_secret=${encodeURIComponent(process.env.SP_CLIENT_SECRET)}&grant_type=client_credentials&scope=${encodeURIComponent('https://graph.microsoft.com/.default')}`;
    const req = https.request({
      host: 'login.microsoftonline.com',
      path: `/${process.env.SP_TENANT_ID}/oauth2/v2.0/token`,
      method: 'POST', timeout: 30000,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(d);
          if (!j.access_token) return reject(new Error(`token: ${j.error || res.statusCode}`));
          resolve(j.access_token);
        } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('token timeout')));
    req.on('error', reject);
    req.write(body); req.end();
  });
}

function graphGet(token, apiPath) {
  return new Promise((resolve, reject) => {
    const req = https.get({
      host: 'graph.microsoft.com', path: apiPath, timeout: 60000,
      headers: { Authorization: `Bearer ${token}` },
    }, (res) => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error(`graph ${res.statusCode} on ${apiPath.slice(0, 80)}`));
        try { resolve(JSON.parse(d)); } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('graph timeout')));
    req.on('error', reject);
  });
}

const norm = (g) => String(g || '').replace(/[{}]/g, '').toLowerCase();
const dateOnly = (s) => (s ? String(s).slice(0, 10) : null);

// Same thresholds as sharepoint-governance.js computeTier()
function tierOf(lastActivity) {
  if (!lastActivity) return { days: null, tier: 'critical' };
  const days = Math.floor((Date.now() - new Date(lastActivity + 'T00:00:00Z').getTime()) / 86400000);
  const tier = days >= 730 ? 'critical' : days >= 365 ? 'high' : days >= 180 ? 'medium' : days >= 90 ? 'watch' : 'active';
  return { days, tier };
}

(async () => {
  const token = await getToken();
  const site = await graphGet(token, `/v1.0/sites/${ADMIN_HOST}`);
  const lists = await graphGet(token, `/v1.0/sites/${site.id}/lists?$select=id,name&$top=100`);
  // SharePoint truncates internal list names — match on the stable prefix.
  const agg = (lists.value || []).find(l => l.name.startsWith('DO_NOT_DELETE_SPLIST_TENANTADMIN_AGGREGATED_SITECO'));
  if (!agg) throw new Error('aggregated site list not found on admin site');

  let items = [];
  let next = `/v1.0/sites/${site.id}/lists/${agg.id}/items?expand=fields&$top=200`;
  while (next) {
    const r = await graphGet(token, next);
    items.push(...(r.value || []));
    next = r['@odata.nextLink'] ? r['@odata.nextLink'].replace('https://graph.microsoft.com', '') : null;
  }
  log(`fetched ${items.length} rows from ${agg.name}`);

  const rows = items.map(i => i.fields)
    .filter(f => f && f.SiteUrl && f.SiteUrl.startsWith(SITE_PREFIX) && !f.TimeDeleted);

  // Hub name resolution: a member site's HubSiteId equals the hub site's own SiteId.
  const titleBySiteId = new Map();
  for (const f of rows) if (f.SiteId) titleBySiteId.set(norm(f.SiteId), f.Title || null);

  const mapped = rows.map(f => {
    const hubId = norm(f.HubSiteId);
    const last = dateOnly(f.LastActivityOn);
    const { days, tier } = tierOf(last);
    return {
      name: f.Title || f.SiteUrl,
      url: String(f.SiteUrl).replace(/\/$/, ''),
      hub: hubId && hubId !== ZERO_GUID ? (titleBySiteId.get(hubId) || null) : null,
      storage_gb: f.StorageUsed ? parseFloat((Number(f.StorageUsed) / 1073741824).toFixed(2)) : 0,
      ext_sharing: f.ExternalSharing === 'On' ? 'On' : f.ExternalSharing === 'Off' ? 'Off' : 'Unknown',
      template: f.TemplateName || null,
      teams: String(f.TemplateName || '').startsWith('TEAMCHANNEL') || !!f.ChannelType,
      m365_group: !!(f.GroupId && norm(f.GroupId) !== ZERO_GUID),
      last_activity: last,
      date_created: dateOnly(f.TimeCreated),
      created_by: f.CreatedBy || null,
      days_inactive: days,
      tier,
      file_count: Number(f.NumOfFiles || 0),
      page_views: Number(f.PageViews || 0),
      page_visits: Number(f.PagesVisited || 0),
      active_files: Number(f.FileViewedOrEdited || 0),
      admin: f.SiteOwnerName || null,
      admin_upn: f.SiteOwnerEmail || null,
    };
  });

  // Dedupe by url, keep first occurrence.
  const seen = new Set(); const out = [];
  for (const s of mapped) { const k = s.url.toLowerCase(); if (!seen.has(k)) { seen.add(k); out.push(s); } }

  const extKnown = out.filter(s => s.ext_sharing !== 'Unknown').length;
  const extOn = out.filter(s => s.ext_sharing === 'On').length;
  const withHub = out.filter(s => s.hub).length;
  log(`mapped ${out.length} sites · ext known ${extKnown} (ON ${extOn}) · with hub ${withHub}`);

  if (out.length < MIN_SITES) throw new Error(`only ${out.length} sites (<${MIN_SITES}) — keeping old seed`);
  if (extKnown / out.length < MIN_EXT_COVERAGE) throw new Error(`ext_sharing coverage ${Math.round(extKnown / out.length * 100)}% (<${MIN_EXT_COVERAGE * 100}%) — keeping old seed`);
  if (withHub === 0) throw new Error('no hub assignments resolved — keeping old seed');

  if (DRY) {
    log('DRY RUN — nothing written. Sample hub site: ' + JSON.stringify(out.find(s => s.hub)));
    return;
  }

  // Backup current seed, prune old backups, atomic swap.
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  if (fs.existsSync(SEED_PATH)) fs.copyFileSync(SEED_PATH, `${SEED_PATH}.bak-${stamp}`);
  const dir = path.dirname(SEED_PATH);
  const baks = fs.readdirSync(dir).filter(n => n.startsWith('sharepoint-seed.json.bak-')).sort();
  while (baks.length > KEEP_BAKS) fs.unlinkSync(path.join(dir, baks.shift()));
  const tmp = SEED_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(out, null, 1));
  fs.renameSync(tmp, SEED_PATH);
  log(`seed replaced: ${out.length} sites written to ${SEED_PATH}`);
})().catch(e => { log('FAILED: ' + e.message); process.exit(1); });
