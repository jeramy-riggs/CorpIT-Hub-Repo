#!/usr/bin/env node
'use strict';
/**
 * dlp-search-sync.js  v3
 *
 * v3 changes:
 *   - drive_id and item_id stored as separate columns (no more parsing
 *     out of file_id, which broke when drive IDs contained underscores
 *     or spaces)
 *   - --sharing-only reads them directly
 *
 * Flags:
 *   --no-sharing     skip permissions enrichment (fast inventory)
 *   --sharing-only   only update sharing scope on existing GS_-prefixed rows
 */

require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const mysql = require('mysql2/promise');

const TENANT_ID     = process.env.SP_TENANT_ID;
const CLIENT_ID     = process.env.SP_CLIENT_ID;
const CLIENT_SECRET = process.env.SP_CLIENT_SECRET;
const SIT_GUID      = process.env.DLP_SIT_GUID || 'e3fc9a2b-10f9-4492-8e67-da265dbad5ac';

const GRAPH      = 'https://graph.microsoft.com/v1.0';
const TOKEN_URL  = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;
const PAGE_SIZE  = 500;
const MAX_PAGES  = 50;
const RESOLVE_CONCURRENCY = 2;
const MAX_RETRIES = 4;
const FALLBACK_BACKOFFS_MS = [5000, 15000, 45000, 120000];

const NO_SHARING   = process.argv.includes('--no-sharing');
const SHARING_ONLY = process.argv.includes('--sharing-only');

const ts  = () => new Date().toISOString();
const log = (...a) => console.log('[DLP-SYNC]', ts(), ...a);
const err = (...a) => console.error('[DLP-SYNC]', ts(), 'ERROR', ...a);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ---- Auth ----
let _token = null, _exp = 0;
async function getToken() {
  if (_token && Date.now() < _exp - 60000) return _token;
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default'
  });
  const r = await fetch(TOKEN_URL, {
    method: 'POST', body,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  const data = await r.json();
  if (!data.access_token) throw new Error('Token: ' + JSON.stringify(data));
  _token = data.access_token;
  _exp = Date.now() + (data.expires_in * 1000);
  return _token;
}

async function graphCall(method, path, body) {
  let attempt = 0;
  while (true) {
    const token = await getToken();
    const init = { method, headers: { Authorization: `Bearer ${token}` } };
    if (body) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const r = await fetch(GRAPH + path, init);
    if (r.ok) return r.json();

    if (r.status === 429) {
      const retryAfter = parseInt(r.headers.get('retry-after') || '0', 10);
      const waitMs = retryAfter > 0
        ? (retryAfter * 1000) + 500
        : FALLBACK_BACKOFFS_MS[Math.min(attempt, FALLBACK_BACKOFFS_MS.length - 1)];
      log(`Throttled (429) — sleeping ${Math.round(waitMs/1000)}s (attempt ${attempt+1}/${MAX_RETRIES})`);
      await sleep(waitMs);
      attempt++;
      if (attempt >= MAX_RETRIES) {
        const t = await r.text().catch(() => '');
        throw new Error(`Graph ${method} ${path}: 429 after ${MAX_RETRIES} retries — ${t.slice(0,200)}`);
      }
      continue;
    }

    if (r.status >= 500 && r.status < 600 && attempt < MAX_RETRIES) {
      const waitMs = FALLBACK_BACKOFFS_MS[Math.min(attempt, FALLBACK_BACKOFFS_MS.length - 1)];
      log(`5xx — backing off ${Math.round(waitMs/1000)}s`);
      await sleep(waitMs);
      attempt++;
      continue;
    }

    const t = await r.text().catch(() => '');
    const e = new Error(`Graph ${method} ${path}: ${r.status} ${t.slice(0,300)}`);
    e.status = r.status;
    throw e;
  }
}
const graphGet  = (p)    => graphCall('GET',  p);
const graphPost = (p, b) => graphCall('POST', p, b);

async function getRegion() {
  try {
    const root = await graphGet('/sites/root?$select=siteCollection');
    const code = root.siteCollection?.dataLocationCode;
    if (code) { log('Region:', code); return code; }
  } catch (e) {
    err('Region lookup failed, defaulting to NAM:', e.message);
  }
  return 'NAM';
}

async function searchAllMatches(region) {
  const hits = [];
  let from = 0, page = 0;
  const queryString = `SensitiveType:"${SIT_GUID}"`;
  log('Query:', queryString, '| region:', region);
  while (page < MAX_PAGES) {
    const body = {
      requests: [{
        entityTypes: ['driveItem'],
        query: { queryString },
        from, size: PAGE_SIZE,
        region,
        fields: [
          'name','webUrl','lastModifiedDateTime','createdDateTime',
          'parentReference','createdBy','lastModifiedBy','size','driveId'
        ]
      }]
    };
    const data = await graphPost('/search/query', body);
    const container = data.value?.[0]?.hitsContainers?.[0];
    if (!container) { log('No hitsContainer at page', page); break; }
    const got = container.hits || [];
    hits.push(...got);
    log(`Page ${page}: +${got.length} hits (total ${hits.length}/${container.total ?? '?'})`);
    if (!container.moreResultsAvailable || got.length === 0) break;
    from += got.length;
    page++;
  }
  if (page >= MAX_PAGES) err(`Hit MAX_PAGES (${MAX_PAGES}) — may be truncated`);
  return hits;
}

async function resolveSharing(driveId, itemId) {
  try {
    const data = await graphGet(`/drives/${encodeURIComponent(driveId)}/items/${encodeURIComponent(itemId)}/permissions?$top=200`);
    const perms = data.value || [];
    let scope = 'restricted';
    const links = [];
    for (const p of perms) {
      const scp = p.link?.scope;
      if (scp === 'anonymous') scope = 'anyone';
      else if (scp === 'organization' && scope !== 'anyone') scope = 'org';
      // F35: type + scope only. The link URL itself is the credential for an
      // 'anyone' link, and the dashboard never needs it.
      if (p.link) links.push({ type: p.link.type, scope: p.link.scope });
    }
    return { sharing_scope: scope, sharing_links: links };
  } catch (e) {
    if (e.status === 404) return { sharing_scope: 'unknown', sharing_links: [], _notFound: true };
    if (e.status === 400) return { sharing_scope: 'unknown', sharing_links: [], _invalid: true };
    err('resolveSharing failed for', driveId, itemId, '-', e.message);
    return { sharing_scope: 'unknown', sharing_links: [] };
  }
}

function buildAlertRow(hit) {
  const r = hit.resource || {};
  const pr = r.parentReference || {};
  const driveId = pr.driveId || r.driveId || null;
  const itemId  = r.id || hit.hitId || null;
  if (!driveId || !itemId) return null;

  const fileId = `GS_${driveId}_${itemId}`;
  const fileName = r.name || 'Unknown';
  const fileUrl  = r.webUrl || '';
  const siteUrl  = fileUrl.match(/(https:\/\/[^/]+\/sites\/[^/]+)/)?.[1] || '';
  const siteName = siteUrl.match(/\/sites\/([^/]+)/)?.[1]?.replace(/-/g,' ') || 'SharePoint';

  return {
    file_id: fileId,
    drive_id: driveId,
    item_id: itemId,
    file_name: fileName,
    file_path: fileUrl,
    site_url: siteUrl,
    site_name: siteName,
    owner: r.createdBy?.user?.email || r.createdBy?.user?.displayName || '—',
    modified_by: r.lastModifiedBy?.user?.email || r.lastModifiedBy?.user?.displayName || '—',
    modified_date: r.lastModifiedDateTime ? new Date(r.lastModifiedDateTime) : null,
    created_date: r.createdDateTime ? new Date(r.createdDateTime) : null,
    rule: 'rule_1',
    rule_label: 'Loan# Numeric/Alphanumeric',
    purview_policy: 'SP-DLP-LOAN-NUM-001',
    match_count: 1,
    severity: 'medium'
  };
}

async function upsertRow(pool, a) {
  await pool.query(
    `INSERT INTO dlp_alerts (
       file_id, drive_id, item_id, file_name, file_path, site_url, site_name,
       owner, modified_by, modified_date, created_date,
       rule, rule_label, purview_policy, match_count, severity,
       sharing_scope, sharing_links
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       drive_id       = VALUES(drive_id),
       item_id        = VALUES(item_id),
       file_name      = VALUES(file_name),
       file_path      = VALUES(file_path),
       site_url       = VALUES(site_url),
       site_name      = VALUES(site_name),
       owner          = VALUES(owner),
       modified_by    = VALUES(modified_by),
       modified_date  = VALUES(modified_date),
       rule           = VALUES(rule),
       rule_label     = VALUES(rule_label),
       purview_policy = VALUES(purview_policy),
       match_count    = VALUES(match_count),
       severity       = VALUES(severity),
       sharing_scope  = VALUES(sharing_scope),
       sharing_links  = VALUES(sharing_links),
       last_seen      = CURRENT_TIMESTAMP,
       status         = IF(status='resolved','resolved','active')`,
    [
      a.file_id, a.drive_id, a.item_id, a.file_name, a.file_path, a.site_url, a.site_name,
      a.owner, a.modified_by, a.modified_date, a.created_date,
      a.rule, a.rule_label, a.purview_policy, a.match_count, a.severity,
      a.sharing_scope || 'unknown', JSON.stringify(a.sharing_links || [])
    ]
  );
}

async function pMap(items, concurrency, fn, progressEvery = 100) {
  let i = 0, done = 0, notFound = 0, invalid = 0;
  const workers = Array(concurrency).fill(0).map(async () => {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      try {
        const r = await fn(items[idx], idx);
        if (r && r._notFound) notFound++;
        if (r && r._invalid)  invalid++;
      } catch (e) {
        err('pMap worker failed at', idx, '-', e.message);
      }
      done++;
      if (done % progressEvery === 0) {
        log(`Progress: ${done}/${items.length} (404s: ${notFound}, 400s: ${invalid})`);
      }
    }
  });
  await Promise.all(workers);
  log(`Final: ${done}/${items.length} processed — ${notFound} not found, ${invalid} invalid drive/item`);
}

async function runInventorySync(pool) {
  const runStart = new Date();
  log('=== Inventory sync start ===',
      NO_SHARING ? '(--no-sharing)' : '');

  const region = await getRegion();
  const hits   = await searchAllMatches(region);
  log(`Total hits returned: ${hits.length}`);

  const rows = hits.map(buildAlertRow).filter(Boolean);
  log(`Mapped to ${rows.length} valid rows`);

  let upserts = 0, failures = 0;

  if (NO_SHARING) {
    log(`UPSERTing ${rows.length} rows (no sharing)...`);
    for (const a of rows) {
      try { await upsertRow(pool, a); upserts++; }
      catch (e) { failures++; err('UPSERT failed', a.file_id, e.message); }
      if (upserts % 500 === 0) log(`UPSERTed ${upserts}/${rows.length}`);
    }
  } else {
    log(`Resolving sharing + UPSERTing ${rows.length} rows (concurrency=${RESOLVE_CONCURRENCY})...`);
    await pMap(rows, RESOLVE_CONCURRENCY, async (row) => {
      const s = await resolveSharing(row.drive_id, row.item_id);
      const enriched = { ...row, sharing_scope: s.sharing_scope, sharing_links: s.sharing_links };
      try { await upsertRow(pool, enriched); upserts++; }
      catch (e) { failures++; err('UPSERT failed', row.file_id, e.message); }
      return s;
    });
  }
  log(`Upserted ${upserts} rows (${failures} failures)`);

  const [result] = await pool.query(
    `UPDATE dlp_alerts
       SET status = 'removed'
     WHERE file_id LIKE 'GS\\_%'
       AND status = 'active'
       AND last_seen < ?`,
    [runStart]
  );
  log(`Marked ${result.affectedRows} files as removed`);
  log('=== Sync complete ===');
}

async function runSharingOnly(pool) {
  log('=== Sharing-only re-resolve start ===');
  const [rows] = await pool.query(
    `SELECT file_id, drive_id, item_id
       FROM dlp_alerts
      WHERE file_id LIKE 'GS\\_%'
        AND status = 'active'
        AND drive_id IS NOT NULL
        AND item_id IS NOT NULL
        AND sharing_scope = 'unknown'`
  );
  log(`Found ${rows.length} rows needing sharing-scope resolution`);
  if (rows.length === 0) {
    log('Nothing to do.');
    return;
  }

  let updated = 0, failures = 0;
  await pMap(rows, RESOLVE_CONCURRENCY, async (row) => {
    const s = await resolveSharing(row.drive_id, row.item_id);
    if (s.sharing_scope === 'unknown') return s; // skip update, keep unknown
    try {
      await pool.query(
        `UPDATE dlp_alerts SET sharing_scope = ?, sharing_links = ? WHERE file_id = ?`,
        [s.sharing_scope, JSON.stringify(s.sharing_links || []), row.file_id]
      );
      updated++;
    } catch (e) {
      failures++;
      err('UPDATE failed', row.file_id, e.message);
    }
    return s;
  });
  log(`Updated sharing on ${updated} rows (${failures} failures)`);
  log('=== Sharing re-resolve complete ===');
}

async function main() {
  if (!TENANT_ID || !CLIENT_ID || !CLIENT_SECRET) {
    throw new Error('Missing SP_TENANT_ID / SP_CLIENT_ID / SP_CLIENT_SECRET in .env');
  }
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME, connectionLimit: 5
  });
  try {
    if (SHARING_ONLY) await runSharingOnly(pool);
    else              await runInventorySync(pool);
    await pool.end();
    process.exit(0);
  } catch (e) {
    err('Sync failed:', e.message);
    err(e.stack);
    await pool.end().catch(() => {});
    process.exit(1);
  }
}

main();
