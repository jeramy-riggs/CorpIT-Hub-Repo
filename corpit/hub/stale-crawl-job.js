// stale-crawl-job.js — streams SharePoint files 7y+ into MySQL, collapsing any drive
// with >THRESHOLD stale files into one stale_drive_summary row.
// Hardened: timeout now covers body read; per-drive page + wall-clock caps bail on archive drives.
const mysql = require('mysql2/promise');
const extSummaryCache = require('./file-inventory-ext-cache');

const TENANT_ID = process.env.SP_TENANT_ID, CLIENT_ID = process.env.SP_CLIENT_ID, CLIENT_SECRET = process.env.SP_CLIENT_SECRET;
const GRAPH = 'https://graph.microsoft.com/v1.0', STALE_YEARS = 5, FLUSH = 1000, THRESHOLD = 10000;
const DRIVE_MAX_PAGES = 6000, DRIVE_MAX_MS = 45 * 60 * 1000;

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
      if (a < 5) { console.log('[STALE-JOB] request retry (' + (e.name || e.message) + ')'); await new Promise(s => setTimeout(s, 2000)); continue; }
      throw e;
    }
  }
  throw new Error('retries ' + u);
}
function isSP(s) { try { const u = new URL(s.webUrl); return u.hostname.endsWith('.sharepoint.com') && !u.hostname.endsWith('-my.sharepoint.com') && !/^\/personal\//i.test(u.pathname); } catch { return false; } }
async function listSites() {
  const sites = [], seen = new Set(), add = s => { if (isSP(s) && !seen.has(s.id)) { seen.add(s.id); sites.push(s); } };
  try { let url = `${GRAPH}/sites/getAllSites?$select=id,displayName,name,webUrl&$top=100`; while (url) { const d = await gget(url); (d.value || []).forEach(add); url = d['@odata.nextLink'] || null; } if (sites.length) return sites; }
  catch (e) { console.log('[STALE-JOB] getAllSites failed, fallback search=*:', e.message); }
  let url = `${GRAPH}/sites?search=*&$select=id,displayName,name,webUrl&$top=100`; while (url) { const d = await gget(url); (d.value || []).forEach(add); url = d['@odata.nextLink'] || null; }
  return sites;
}
async function listDrives(siteId) { const drives = []; let url = `${GRAPH}/sites/${siteId}/drives?$select=id,name&$top=100`; while (url) { const d = await gget(url); drives.push(...(d.value || [])); url = d['@odata.nextLink'] || null; } return drives; }

(async () => {
  const started = Date.now();
  const cutoff = new Date(); cutoff.setFullYear(cutoff.getFullYear() - STALE_YEARS); const cutoffISO = cutoff.toISOString();
  const d10 = new Date(); d10.setFullYear(d10.getFullYear() - 10); const d10t = d10.getTime();
  const d7 = new Date(); d7.setFullYear(d7.getFullYear() - 7); const d7t = d7.getTime();
  const d5 = new Date(); d5.setFullYear(d5.getFullYear() - 5); const d5t = d5.getTime();
  const pool = mysql.createPool({ host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10), user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME, waitForConnections: true, connectionLimit: 3, timezone: 'Z' });
  const batchId = Date.now();
  // A run row is closed only by the success path below or by the catch at the
  // end. NEITHER runs when the process is KILLED -- OOM, `timeout`, a reboot, a
  // systemd stop -- so a killed crawl leaves status='running' with NULL counters
  // forever. The 2026-08-28 run sat that way for 11 days; runningRun() in
  // files-routes.js reported "crawl in progress" for all of them, and
  // /inventory/summary read those NULLs as a measured zero.
  //
  // flock(1) makes the reaper exact rather than heuristic: the cron and every
  // documented manual invocation take an exclusive lock on
  // /run/stale-crawl-job.lock, so if THIS process is running, no other crawl is,
  // and every pre-existing 'running' row belongs to a process that is gone. No
  // age threshold is involved, so a legitimately long crawl can never be reaped.
  // This runs BEFORE our own row is inserted, so it can never touch it.
  for (const t of ['stale_crawl_runs', 'file_inventory_runs']) {
    try {
      const [r] = await pool.query(
        `UPDATE ${t} SET status='failed', finished_at=NOW() WHERE status='running'`);
      if (r.affectedRows) console.log(`[STALE-JOB] reaped ${r.affectedRows} abandoned ${t} row(s) from a killed crawl`);
    } catch (e) { console.log('[STALE-JOB] reap ' + t + ':', e.message); }
  }
  await pool.query("INSERT INTO stale_crawl_runs (batch_id, started_at, status) VALUES (?, NOW(), 'running')", [batchId]);
  await pool.query('INSERT INTO file_inventory_runs (batch_id, started_at, status) VALUES (?, NOW(), ?)', [batchId, 'running']).catch(()=>{});
  // SIGTERM/SIGINT are what `timeout`, systemd and Ctrl-C send; closing the row
  // here means an operator-stopped crawl is marked failed at once rather than
  // looking "in progress" until tomorrow's run reaps it. SIGKILL is uncatchable
  // by design -- that case is covered by the reaper above, not here.
  let _closing = false;
  const _onSignal = (sig) => {
    if (_closing) return; _closing = true;
    console.error(`[STALE-JOB] ${sig} — marking run ${batchId} failed`);
    pool.query("UPDATE stale_crawl_runs SET status='failed', finished_at=NOW() WHERE batch_id=?", [batchId])
      .then(() => pool.query("UPDATE file_inventory_runs SET status='failed', finished_at=NOW() WHERE batch_id=?", [batchId]))
      .catch(() => {})
      .finally(() => process.exit(1));
  };
  process.on('SIGTERM', () => _onSignal('SIGTERM'));
  process.on('SIGINT',  () => _onSignal('SIGINT'));
  await pool.query('DROP TABLE IF EXISTS file_inventory_staging').catch(e=>console.log('[INV] drop staging', e.message));
  await pool.query("CREATE TABLE file_inventory_staging (id BIGINT NOT NULL AUTO_INCREMENT, site_url VARCHAR(512), site_name VARCHAR(255), drive_name VARCHAR(255), file_name VARCHAR(512), file_path VARCHAR(1024), web_url VARCHAR(1024), owner VARCHAR(320), modified_by VARCHAR(320), modified_date DATETIME, created_date DATETIME, size BIGINT, ext VARCHAR(32), item_id VARCHAR(255), drive_id VARCHAR(255), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci").catch(e=>console.log('[INV] create staging', e.message));
  let invBuf = [], invCount = 0, invBytes = 0, partialDrives = 0;
  const invExtTotals = new Map();
  const INV_FLUSH = 2000;
  const invFlush = async () => { if (!invBuf.length) return; const rows = invBuf; invBuf = []; try { await pool.query('INSERT INTO file_inventory_staging (site_url,site_name,drive_name,file_name,file_path,web_url,owner,modified_by,modified_date,created_date,size,ext,item_id,drive_id) VALUES ?', [rows]); extSummaryCache.addInsertedRows(invExtTotals, rows); } catch (e) { console.log('[INV] flush err', e.message); } };

  let buf = [], totalCount = 0, totalBytes = 0;
  const flush = async () => { if (!buf.length) return; const rows = buf; buf = []; await pool.query(`INSERT INTO stale_files (batch_id,site_url,site_name,drive_name,file_name,file_path,web_url,owner,modified_by,modified_date,created_date,size) VALUES ?`, [rows]); };

  async function crawlDrive(drive, site) {
    const agg = { count: 0, bytes: 0, count10: 0, bytes10: 0, count5: 0, bytes5: 0, count7: 0, bytes7: 0, oldest: null, newest: null };
    let invDc = 0, invDb = 0;
    const driveStart = Date.now();
    let pages = 0, bailed = false;
    let url = `${GRAPH}/drives/${drive.id}/root/delta?$select=id,name,webUrl,size,file,createdDateTime,lastModifiedDateTime,createdBy,lastModifiedBy,parentReference`;
    while (url) {
      if (pages >= DRIVE_MAX_PAGES) { console.log(`[STALE-JOB] drive ${drive.name} @ ${site.webUrl} hit ${DRIVE_MAX_PAGES} pages, bailing partial (agg ${agg.count})`); bailed = true; break; }
      if (Date.now() - driveStart > DRIVE_MAX_MS) { console.log(`[STALE-JOB] drive ${drive.name} @ ${site.webUrl} hit ${DRIVE_MAX_MS/60000}min wall, bailing partial (agg ${agg.count})`); bailed = true; break; }
      pages++;
      const d = await gget(url);
      for (const it of (d.value || [])) {
        if (it.file) {
          const _sz = it.size || 0;
          const _pp = (it.parentReference?.path || '').replace(/^\/drives\/[^/]+\/root:?/, '') || '';
          const _dot = (it.name || '').lastIndexOf('.');
          const _ext = _dot > 0 ? it.name.slice(_dot + 1).toLowerCase().slice(0, 32) : '';
          invBuf.push([site.webUrl, (site.displayName || site.name || 'SharePoint'), (drive.name || 'Documents'), it.name, (_pp || '') + '/' + it.name, it.webUrl,
            it.createdBy?.user?.email || it.createdBy?.user?.displayName || '—', it.lastModifiedBy?.user?.email || it.lastModifiedBy?.user?.displayName || '—',
            it.lastModifiedDateTime ? new Date(it.lastModifiedDateTime) : null, it.createdDateTime ? new Date(it.createdDateTime) : null, _sz, _ext, it.id, drive.id]);
          invDc++; invDb += _sz; invCount++; invBytes += _sz;
          if (invBuf.length >= INV_FLUSH) await invFlush();
        }
        if (!it.file || !it.lastModifiedDateTime || it.lastModifiedDateTime >= cutoffISO) continue;
        const mt = new Date(it.lastModifiedDateTime); const sz = it.size || 0;
        agg.count++; agg.bytes += sz;
        if (mt.getTime() < d10t) { agg.count10++; agg.bytes10 += sz; }
        if (mt.getTime() < d5t) { agg.count5++; agg.bytes5 += sz; }
        if (mt.getTime() < d7t) { agg.count7++; agg.bytes7 += sz; }
        if (!agg.oldest || mt < agg.oldest) agg.oldest = mt;
        if (!agg.newest || mt > agg.newest) agg.newest = mt;
        if (agg.count <= THRESHOLD) {
          const p = (it.parentReference?.path || '').replace(/^\/drives\/[^/]+\/root:?/, '') || '';
          buf.push([batchId, site.webUrl, (site.displayName || site.name || 'SharePoint'), (drive.name || 'Documents'), it.name, (p || '') + '/' + it.name, it.webUrl,
            it.createdBy?.user?.email || it.createdBy?.user?.displayName || '—', it.lastModifiedBy?.user?.email || it.lastModifiedBy?.user?.displayName || '—',
            mt, it.createdDateTime ? new Date(it.createdDateTime) : null, sz]);
          if (buf.length >= FLUSH) await flush();
        }
      }
      url = d['@odata.nextLink'] || null;
      if (pages % 100 === 0) console.log(`[STALE-JOB] drive ${drive.name} page ${pages}, agg ${agg.count}, ${((Date.now()-driveStart)/1000)|0}s`);
    }
    await invFlush();
    if (bailed) partialDrives++;
    if (invDc > 0) { try { await pool.query('INSERT INTO file_inventory_drives (batch_id,site_url,site_name,drive_name,file_count,total_bytes,partial) VALUES (?,?,?,?,?,?,?)', [batchId, site.webUrl, (site.displayName || site.name || 'SharePoint'), (drive.name || 'Documents'), invDc, invDb, bailed ? 1 : 0]); } catch (e) { console.log('[INV] drive rollup', e.message); } }
    if (!agg.count) return;
    await flush();
    const collapsed = (agg.count > THRESHOLD || bailed) ? 1 : 0;
    await pool.query(
      `INSERT INTO stale_drive_summary (batch_id,site_url,site_name,drive_name,file_count,total_bytes,count_10,bytes_10,count_5,bytes_5,count_7,bytes_7,oldest_modified,newest_modified,collapsed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,


      [batchId, site.webUrl, (site.displayName || site.name || 'SharePoint'), (drive.name || 'Documents'), agg.count, agg.bytes, agg.count10, agg.bytes10, agg.count5, agg.bytes5, agg.count7, agg.bytes7, agg.oldest, agg.newest, collapsed]);
    if (collapsed) await pool.query("DELETE FROM stale_files WHERE batch_id=? AND site_url=? AND drive_name=?", [batchId, site.webUrl, (drive.name || 'Documents')]);
    totalCount += agg.count; totalBytes += agg.bytes;
  }

  try {
    const sites = await listSites();
    console.log(`[STALE-JOB] ${new Date().toISOString()} batch ${batchId}, crawling ${sites.length} sites, cutoff ${cutoffISO}, collapse>${THRESHOLD}, drive caps: ${DRIVE_MAX_PAGES}p / ${DRIVE_MAX_MS/60000}min`);
    let n = 0;
    for (const site of sites) {
      n++;
      try { const drives = await listDrives(site.id); for (const drv of drives) { try { await crawlDrive(drv, site); } catch (e) { console.log(`[STALE-JOB] drive ${drv.name} @ ${site.webUrl}:`, e.message); } } }
      catch (e) { console.log(`[STALE-JOB] site ${site.webUrl}:`, e.message); }
      if (n % 25 === 0) { const rss = (process.memoryUsage().rss / 1048576) | 0; console.log(`[STALE-JOB] ${n}/${sites.length} sites, ${totalCount} stale, RSS ${rss}MB`); }
    }
    await flush();
    await pool.query("UPDATE stale_crawl_runs SET status='done', finished_at=NOW(), file_count=?, total_bytes=?, sites_scanned=? WHERE batch_id=?", [totalCount, totalBytes, sites.length, batchId]);
    await pool.query("DELETE FROM stale_files WHERE batch_id<>?", [batchId]);
    await pool.query("DELETE FROM stale_drive_summary WHERE batch_id<>?", [batchId]);
    await pool.query("DELETE FROM stale_crawl_runs WHERE batch_id<>?", [batchId]);
    try {
      await invFlush();
      console.log('[INV] building indexes on ' + invCount + ' rows');
      await pool.query("ALTER TABLE file_inventory_staging ADD KEY ix_size (size), ADD KEY ix_modified (modified_date), ADD KEY ix_created (created_date), ADD KEY ix_site (site_url(191)), ADD KEY ix_site_size (site_url(191), size), ADD KEY ix_modby (modified_by(191)), ADD KEY ix_owner (owner(191)), ADD KEY ix_ext (ext), ADD KEY ix_item (item_id), ADD FULLTEXT KEY ft_name_path (file_name, file_path)");
      await pool.query('DROP TABLE IF EXISTS file_inventory_old');
      await pool.query('RENAME TABLE file_inventory TO file_inventory_old, file_inventory_staging TO file_inventory');
      try {
        const [[table]] = await pool.query(
          "SELECT DATE_FORMAT(CREATE_TIME, '%Y-%m-%d %H:%i:%s') AS generation FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='file_inventory'");
        if (!table?.generation) throw new Error('live table generation unavailable');
        await extSummaryCache.write(batchId, table.generation, extSummaryCache.topRows(invExtTotals));
      }
      catch (e) { console.log('[INV] extension snapshot unavailable; endpoint will use SQL fallback:', e.message); }
      await pool.query('DROP TABLE IF EXISTS file_inventory_old');
      await pool.query('DELETE FROM file_inventory_drives WHERE batch_id<>?', [batchId]);
      await pool.query("UPDATE file_inventory_runs SET status='done', finished_at=NOW(), file_count=?, total_bytes=?, sites_scanned=?, partial_drives=? WHERE batch_id=?", [invCount, invBytes, sites.length, partialDrives, batchId]);
      await pool.query('DELETE FROM file_inventory_runs WHERE batch_id<>?', [batchId]);
      console.log('[INV] DONE - ' + invCount + ' files (' + (invBytes / 1073741824).toFixed(1) + 'GB), ' + partialDrives + ' partial drives');
    } catch (e) { console.log('[INV] finalize FAILED (stale crawl unaffected):', e.message); }
    await pool.end();
    console.log(`[STALE-JOB] DONE — ${totalCount} stale files (${(totalBytes / 1073741824).toFixed(1)}GB) across ${sites.length} sites in ${((Date.now() - started) / 1000) | 0}s`);
  } catch (e) {
    console.error('[STALE-JOB] FATAL', e);
    // Both rows, not just the stale one: file_inventory_runs was left at
    // 'running' by this path too, which is how /inventory/summary came to
    // read NULL counters as a measured zero.
    try { await pool.query("UPDATE stale_crawl_runs SET status='failed', finished_at=NOW() WHERE batch_id=?", [batchId]); } catch {}
    try { await pool.query("UPDATE file_inventory_runs SET status='failed', finished_at=NOW() WHERE batch_id=?", [batchId]); } catch {}
    try { await pool.end(); } catch {}
    process.exit(1);
  }
})();
