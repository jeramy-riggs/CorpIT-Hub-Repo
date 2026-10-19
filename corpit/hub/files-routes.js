// files-routes.js — Stale Files (MySQL-backed) + Storage Growth. Mounted at /api/files.
const express = require('express');
const mysql   = require('mysql2/promise');
const path    = require('path');
const { spawn } = require('child_process');
const extSummaryCache = require('./file-inventory-ext-cache');
const router  = express.Router();

const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 5, timezone: 'Z',
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
const guard = rbac.requirePage('sharepoint-gov', 'read');
const guardAdmin = rbac.requirePage('sharepoint-gov', 'admin');

// ── stale files ────────────────────────────────────────────────────────────────
async function latestCompleteSnap() {
  const [rows] = await rbacPool.query(
    "SELECT snap_date, COUNT(*) c FROM site_storage_snapshots GROUP BY snap_date ORDER BY snap_date DESC LIMIT 2");
  if (!rows.length) return null;
  const fmt = d => new Date(d).toISOString().slice(0, 10);
  if (rows.length === 1) return fmt(rows[0].snap_date);
  const today = rows[0], prev = rows[1];
  const complete = Number(today.c) >= Math.floor(Number(prev.c) * 0.98);
  return fmt(complete ? today.snap_date : prev.snap_date);
}

async function latestBatch() {
  const [r] = await rbacPool.query("SELECT batch_id, started_at, finished_at, file_count, total_bytes, sites_scanned FROM stale_crawl_runs WHERE status='done' ORDER BY batch_id DESC LIMIT 1");
  return r[0] || null;
}
// The job reaps abandoned 'running' rows when it next starts, so a zombie
// normally lives at most one crawl interval. If the cron itself stops being
// scheduled there is no next start, and the row would claim "crawl in
// progress" indefinitely. Bound it here too: 26h matches maxAgeH on the
// file_inventory_runs feed in feed-freshness-routes.js, and the longest
// observed real crawl was 7h39m, so this cannot hide a live run.
const RUNNING_MAX_H = 26;
async function runningRun() {
  const [r] = await rbacPool.query(
    "SELECT batch_id, started_at, sites_scanned FROM stale_crawl_runs " +
    "WHERE status='running' AND started_at > NOW() - INTERVAL ? HOUR " +
    "ORDER BY batch_id DESC LIMIT 1", [RUNNING_MAX_H]);
  return r[0] || null;
}

router.get('/stale/summary', guard, async (req, res) => {
  try {
    const b = await latestBatch(), running = await runningRun();
    if (!b) return res.json({ status: running ? 'crawling' : 'empty', crawling: !!running, running: running || null, generated_at: null, count: 0 });
    const [[agg]] = await rbacPool.query(
      `SELECT COALESCE(SUM(file_count),0) c, COALESCE(SUM(total_bytes),0) bytes,
              COALESCE(SUM(count_10),0) c10, COALESCE(SUM(bytes_10),0) b10,
              COALESCE(SUM(count_7),0) c7, COALESCE(SUM(bytes_7),0) b7,
              COALESCE(SUM(count_5),0) c5, COALESCE(SUM(bytes_5),0) b5
       FROM stale_drive_summary WHERE batch_id=?`, [b.batch_id]);
    const [collapsed] = await rbacPool.query(
      `SELECT site_name, site_url, drive_name, file_count, total_bytes, oldest_modified, newest_modified
       FROM stale_drive_summary WHERE batch_id=? AND collapsed=1 ORDER BY file_count DESC`, [b.batch_id]);
    res.json({
      status: running ? 'refreshing' : 'ready', crawling: !!running, running: running || null,
      generated_at: b.finished_at, batch_id: b.batch_id, cutoff_years: 5,
      count: Number(agg.c), total_bytes: Number(agg.bytes),
      count_10: Number(agg.c10), bytes_10: Number(agg.b10),
      count_7: Number(agg.c7), bytes_7: Number(agg.b7),
      count_5: Number(agg.c5), bytes_5: Number(agg.b5),
      collapsed: collapsed.map(c => ({ site_name: c.site_name, site_url: c.site_url, drive_name: c.drive_name, file_count: Number(c.file_count), total_bytes: Number(c.total_bytes), oldest: c.oldest_modified, newest: c.newest_modified })),
    });
  } catch (e) { console.error('[STALE] summary', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/stale/cost/sites', guard, async (req, res) => {
  try {
    const preset = req.query.preset || '7'; // bytes_7_sites
    const b = await latestBatch();
    if (!b) return res.json({ status: 'empty', preset, rows: [] });
    let bytesCol, filesCol;
    if (preset === '10')     { bytesCol = 'SUM(bytes_10)'; filesCol = 'SUM(count_10)'; }
    else if (preset === '5') { bytesCol = 'SUM(bytes_5)'; filesCol = 'SUM(count_5)'; }
    else                     { bytesCol = 'SUM(bytes_7)'; filesCol = 'SUM(count_7)'; }
    const [rows] = await rbacPool.query(
      `SELECT site_name, site_url,
              ${filesCol} AS files,
              ${bytesCol} AS bytes
       FROM stale_drive_summary
       WHERE batch_id=?
       GROUP BY site_name, site_url
       HAVING bytes > 0
       ORDER BY bytes DESC`, [b.batch_id]);
    res.json({
      status: 'ready', preset, batch_id: b.batch_id,
      rows: rows.map(r => ({ site_name: r.site_name, site_url: r.site_url, files: Number(r.files), bytes: Number(r.bytes) }))
    });
  } catch (e) { console.error('[STALE] cost/sites', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/stale/cost', guard, async (req, res) => {
  try {
    const preset = req.query.preset || '7'; // '5' | '7' | '10'
    const b = await latestBatch();
    if (!b) return res.json({ status: 'empty', preset, bytes: 0, files: 0, preset_mode: true, count_7_preset: true });
    const [[agg]] = await rbacPool.query(
      `SELECT COALESCE(SUM(count_5),0) c5, COALESCE(SUM(bytes_5),0) b5,
              COALESCE(SUM(count_7),0) c7, COALESCE(SUM(bytes_7),0) b7,
              COALESCE(SUM(count_10),0) c10, COALESCE(SUM(bytes_10),0) b10
       FROM stale_drive_summary WHERE batch_id=?`, [b.batch_id]);
    let bytes, files;
    if (preset === '10')     { bytes = Number(agg.b10); files = Number(agg.c10); }
    else if (preset === '7') { bytes = Number(agg.b7);  files = Number(agg.c7);  }
    else                     { bytes = Number(agg.b5);  files = Number(agg.c5);  }
    res.json({ status: 'ready', preset, batch_id: b.batch_id, bytes, files, preset_mode: true, count_7_preset: true });
  } catch (e) { console.error('[STALE] cost', e.message); res.status(500).json({ error: e.message }); }
});


// Renewal Planning: all 3 presets in one payload
router.get('/stale/cost/all', guard, async (req, res) => {
  try {
    const b = await latestBatch();
    if (!b) return res.json({ status: 'empty', batch_id: null, presets: { '5': {bytes:0,files:0}, '7': {bytes:0,files:0}, '10': {bytes:0,files:0} } });
    const [[agg]] = await rbacPool.query(
      `SELECT COALESCE(SUM(count_5),0) c5, COALESCE(SUM(bytes_5),0) b5,
              COALESCE(SUM(count_7),0) c7, COALESCE(SUM(bytes_7),0) b7,
              COALESCE(SUM(count_10),0) c10, COALESCE(SUM(bytes_10),0) b10
       FROM stale_drive_summary WHERE batch_id=?`, [b.batch_id]);
    res.json({
      status: 'ready',
      batch_id: b.batch_id,
      presets: {
        '5':  { bytes: Number(agg.b5),  files: Number(agg.c5)  },
        '7':  { bytes: Number(agg.b7),  files: Number(agg.c7)  },
        '10': { bytes: Number(agg.b10), files: Number(agg.c10) }
      }
    });
  } catch (e) { console.error('[STALE] cost/all', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/stale/list', guard, async (req, res) => {
  try {
    const b = await latestBatch();
    if (!b) return res.json({ rows: [], total: 0, page: 1, pageSize: 100 });
    const page = Math.max(1, parseInt(req.query.page || '1', 10) || 1);
    const pageSize = Math.min(500, Math.max(10, parseInt(req.query.pageSize || '100', 10) || 100));
    const q = (req.query.search || '').trim();
    const params = [b.batch_id]; let where = 'batch_id=?';
    if (q) { where += ' AND (file_name LIKE ? OR site_name LIKE ? OR owner LIKE ? OR modified_by LIKE ? OR file_path LIKE ?)'; const like = '%' + q + '%'; params.push(like, like, like, like, like); }
    const _dOk = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
    const _from = _dOk(req.query.from) ? req.query.from : null, _to = _dOk(req.query.to) ? req.query.to : null;
    if (_from && _to)  { where += ' AND ((modified_date >= ? AND modified_date < ?) OR (created_date >= ? AND created_date < ?))'; params.push(_from, _to, _from, _to); }
    else if (_from)    { where += ' AND (modified_date >= ? OR created_date >= ?)'; params.push(_from, _from); }
    else if (_to)      { where += ' AND (modified_date < ? OR created_date < ?)'; params.push(_to, _to); }
    const [[cnt]] = await rbacPool.query(`SELECT COUNT(*) c FROM stale_files WHERE ${where}`, params);
    const SORT_WHITELIST = {
      modified_date: 'modified_date',
      created_date:  'created_date',
      size:          'size',
      file_name:     'file_name',
      site_name:     'site_name',
      owner:         'owner',
      modified_by:   'modified_by',
      file_path:     'file_path'
    };
    const sortByReq = String(req.query.sortBy || 'modified_date');
    const sortBy    = SORT_WHITELIST[sortByReq] || 'modified_date';
    const sortDir   = String(req.query.sortDir || 'asc').toLowerCase() === 'desc' ? 'DESC' : 'ASC';
    const [rows] = await rbacPool.query(
      `SELECT file_name,site_name,site_url,file_path,web_url,owner,modified_by,modified_date,created_date,size
       FROM stale_files WHERE ${where} ORDER BY ${sortBy} ${sortDir} LIMIT ? OFFSET ?`,
      [...params, pageSize, (page - 1) * pageSize]);
    res.json({ rows, total: Number(cnt.c), page, pageSize });
  } catch (e) { console.error('[STALE] list', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/stale/export', guard, async (req, res) => {
  try {
    const b = await latestBatch();
    if (!b) { res.status(404).send('no data'); return; }
    const q = (req.query.search || '').trim();
    const _dOk = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
    const _from = _dOk(req.query.from) ? req.query.from : null, _to = _dOk(req.query.to) ? req.query.to : null;
    const _params = [b.batch_id]; let _where = 'batch_id=?';
    if (q) { _where += ' AND (file_name LIKE ? OR site_name LIKE ? OR owner LIKE ? OR modified_by LIKE ? OR file_path LIKE ?)'; const like = '%' + q + '%'; _params.push(like, like, like, like, like); }
    if (_from && _to)  { _where += ' AND ((modified_date >= ? AND modified_date < ?) OR (created_date >= ? AND created_date < ?))'; _params.push(_from, _to, _from, _to); }
    else if (_from)    { _where += ' AND (modified_date >= ? OR created_date >= ?)'; _params.push(_from, _from); }
    else if (_to)      { _where += ' AND (modified_date < ? OR created_date < ?)'; _params.push(_to, _to); }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="stale-files-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.write('File Name,Site,Site URL,File Path,Owner,Last Modified By,Last Modified,Created,Size (bytes)\n');
    const csv = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
    const CH = 5000; let off = 0;
    for (;;) {
      const [rows] = await rbacPool.query(
        `SELECT file_name,site_name,site_url,file_path,owner,modified_by,modified_date,created_date,size
         FROM stale_files WHERE ${_where} ORDER BY modified_date ASC LIMIT ? OFFSET ?`, [..._params, CH, off]);
      if (!rows.length) break;
      for (const r of rows) res.write([csv(r.file_name), csv(r.site_name), csv(r.site_url), csv(r.file_path), csv(r.owner), csv(r.modified_by),
        r.modified_date ? new Date(r.modified_date).toISOString() : '', r.created_date ? new Date(r.created_date).toISOString() : '', r.size || 0].join(',') + '\n');
      off += CH; if (rows.length < CH) break;
    }
    res.end();
  } catch (e) { console.error('[STALE] export', e.message); res.status(500).end(); }
});

router.post('/stale/refresh', guardAdmin, async (req, res) => {
  try {
    const running = await runningRun();
    if (running) return res.json({ status: 'crawling', running });
    const child = spawn(process.execPath, ['--max-old-space-size=768', path.join(__dirname, 'stale-crawl-job.js')],
      { cwd: __dirname, env: process.env, detached: true, stdio: 'ignore' });
    child.unref();
    res.json({ status: 'started' });
  } catch (e) { console.error('[STALE] refresh', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/stale/health', async (req, res) => {
  try { const b = await latestBatch(), running = await runningRun(); res.json({ ok: true, crawling: !!running, count: b ? Number(b.file_count) : 0, generated_at: b ? b.finished_at : null }); }
  catch (e) { res.json({ ok: false, error: e.message }); }
});

// ── storage growth (exec reporting) ───────────────────────────────────────────
function periodDays(p) { return p === 'week' ? 7 : p === 'year' ? 365 : 30; }

router.get('/growth/summary', guard, async (req, res) => {
  const type = req.query.type === 'modifier' ? 'modifier' : 'creator';
  const period = ['week', 'month', 'year'].includes(req.query.period) ? req.query.period : 'month';
  try {
    const [series] = await rbacPool.query(
      `SELECT DATE_FORMAT(snap_date,'%Y-%m-%d') AS d, SUM(total_bytes) AS bytes, SUM(file_count) AS files
       FROM storage_snapshots WHERE principal_type=? GROUP BY snap_date ORDER BY snap_date`, [type]);
    if (!series.length) return res.json({ type, period, empty: true, series: [], latest: null, deltas: {}, leaderboard: [], share: [], all: [] });
    const latest = series[series.length - 1], latestDate = latest.d, curTotal = Number(latest.bytes);
    const totalAt = (daysAgo) => { const ref = new Date(latestDate); ref.setUTCDate(ref.getUTCDate() - daysAgo); const refStr = ref.toISOString().slice(0, 10); let best = null; for (const r of series) { if (r.d <= refStr) best = r; else break; } return best ? Number(best.bytes) : null; };
    const deltas = {};
    for (const [k, dd] of [['week', 7], ['month', 30], ['year', 365]]) { const prev = totalAt(dd); deltas[k] = prev == null ? null : { from: prev, to: curTotal, change: curTotal - prev }; }
    const [allLatest] = await rbacPool.query(
      `SELECT principal, total_bytes, file_count FROM storage_snapshots WHERE principal_type=? AND snap_date=? ORDER BY total_bytes DESC`, [type, latestDate]);
    const ref = new Date(latestDate); ref.setUTCDate(ref.getUTCDate() - periodDays(period));
    const [refRows] = await rbacPool.query(
      `SELECT principal, total_bytes FROM storage_snapshots WHERE principal_type=? AND snap_date=(SELECT MAX(snap_date) FROM storage_snapshots WHERE principal_type=? AND snap_date<=?)`,
      [type, type, ref.toISOString().slice(0, 10)]);
    const refMap = Object.fromEntries(refRows.map(r => [r.principal, Number(r.total_bytes)]));
    const leaderboard = allLatest.slice(0, 25).map(r => ({ principal: r.principal, total_bytes: Number(r.total_bytes), file_count: r.file_count, growth: (r.principal in refMap) ? Number(r.total_bytes) - refMap[r.principal] : null }));
    const top = allLatest.slice(0, 12).map(r => ({ principal: r.principal, bytes: Number(r.total_bytes) }));
    const othersBytes = allLatest.slice(12).reduce((s, r) => s + Number(r.total_bytes), 0);
    const share = othersBytes > 0 ? [...top, { principal: 'Others', bytes: othersBytes }] : top;
    res.json({ type, period, latest: { date: latestDate, total_bytes: curTotal, file_count: Number(latest.files), principals: allLatest.length },
      series: series.map(r => ({ date: r.d, bytes: Number(r.bytes), files: Number(r.files) })), deltas, leaderboard, share,
      all: allLatest.map(r => ({ principal: r.principal, total_bytes: Number(r.total_bytes), file_count: r.file_count })) });
  } catch (e) { console.error('[GROWTH] summary', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/growth/user', guard, async (req, res) => {
  const type = req.query.type === 'modifier' ? 'modifier' : 'creator';
  const principal = req.query.principal || '';
  if (!principal) return res.status(400).json({ error: 'principal required' });
  try {
    const [rows] = await rbacPool.query(
      `SELECT DATE_FORMAT(snap_date,'%Y-%m-%d') AS d, total_bytes, file_count FROM storage_snapshots WHERE principal_type=? AND principal=? ORDER BY snap_date`, [type, principal]);
    res.json({ type, principal, series: rows.map(r => ({ date: r.d, bytes: Number(r.total_bytes), files: r.file_count })) });
  } catch (e) { console.error('[GROWTH] user', e.message); res.status(500).json({ error: e.message }); }
});


// ── per-site storage (request capability #1) ──────────────────────────────────
router.get('/sites/storage', guard, async (req, res) => {
  try {
    const latestDate = await latestCompleteSnap();
    if (!latestDate) return res.json({ empty: true, latest_date: null, sites: [], total_bytes: 0 });
    const [rows] = await rbacPool.query(
      `SELECT site_id, site_name, web_url, used_bytes, quota_bytes
       FROM site_storage_snapshots WHERE snap_date=? ORDER BY used_bytes DESC`, [latestDate]);
    const total = rows.reduce((s, r) => s + Number(r.used_bytes), 0);
    res.json({
      latest_date: latestDate,
      total_bytes: total,
      sites: rows.map(r => ({
        site_id: r.site_id, site_name: r.site_name, web_url: r.web_url,
        used_bytes: Number(r.used_bytes), quota_bytes: r.quota_bytes == null ? null : Number(r.quota_bytes)
      }))
    });
  } catch (e) { console.error('[SITE-STORAGE] latest', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/sites/storage/trend', guard, async (req, res) => {
  try {
    const cap = await latestCompleteSnap();
    if (!cap) return res.json({ series: [] });
    const [rows] = await rbacPool.query(
      `SELECT DATE_FORMAT(snap_date,'%Y-%m-%d') AS date, SUM(used_bytes) AS bytes
       FROM site_storage_snapshots
       WHERE snap_date <= ?
       GROUP BY snap_date
       ORDER BY snap_date`, [cap]);
    res.json({ series: rows.map(r => ({ date: r.date, bytes: Number(r.bytes) })) });
  } catch (e) { console.error('[SITE-STORAGE] trend', e.message); res.status(500).json({ error: e.message }); }
});
// Authoritative tenant-total SharePoint storage (Graph getSharePointSiteUsageStorage — includes recycle bin + version history)

// Tenant pool composition: base + E3-license × per-license + SharePoint add-on.
// Reads live values from insight_sku (Rey's collect-tenant-insights job); falls back
// to hardcoded defaults if the SKU rows are missing.
router.get('/tenant/pool', guard, async (req, res) => {
  try {
    const [rows] = await rbacPool.query(
      `SELECT sku_part_number, consumed, enabled, DATE_FORMAT(collected_at,'%Y-%m-%dT%H:%i:%sZ') AS collected_at
       FROM insight_sku
       WHERE sku_part_number IN ('SPE_E3','SHAREPOINTSTORAGE')`);
    const map = Object.fromEntries(rows.map(r => [r.sku_part_number, r]));
    const e3 = map['SPE_E3'] || null;
    const stor = map['SHAREPOINTSTORAGE'] || null;
    // Freshest collected_at across the two rows
    const collectedAt = [e3, stor].filter(Boolean).map(r=>r.collected_at).sort().pop() || null;
    res.json({
      base_gb: 1024,
      per_license_gb: 10,
      licenses: {
        enabled:  e3 ? Number(e3.enabled)  : 781,
        consumed: e3 ? Number(e3.consumed) : 678
      },
      extra_storage_gb: stor ? Number(stor.enabled) : 20000,
      source: (e3 && stor) ? 'insight_sku' : 'fallback',
      collected_at: collectedAt
    });
  } catch (e) { console.error('[TENANT-POOL]', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/tenant/storage', guard, async (req, res) => {
  try {
    const [rows] = await rbacPool.query(
      `SELECT DATE_FORMAT(snap_date,'%Y-%m-%d') AS snap_date, used_bytes,
              DATE_FORMAT(report_date,'%Y-%m-%d') AS report_date, source
       FROM tenant_storage_snapshots ORDER BY snap_date DESC LIMIT 1`);
    if (!rows.length) return res.json({ used_bytes: null });
    res.json({ used_bytes: Number(rows[0].used_bytes), snap_date: rows[0].snap_date,
               report_date: rows[0].report_date, source: rows[0].source });
  } catch (e) { console.error('[TENANT-STORAGE]', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/sites/storage/quarterly', guard, async (req, res) => {
  // Returns TB-per-quarter aggregates. Optional ?site_id=... narrows to one site.
  const siteId = req.query.site_id || null;
  try {
    const params = []; let whereSite = '';
    if (siteId) { whereSite = 'AND site_id=?'; params.push(siteId); }
    // Per-quarter, pick the latest snap_date in that quarter.
    const [qrows] = await rbacPool.query(
      `SELECT y, q, MAX(snap_date) AS quarter_end_snap FROM (
         SELECT snap_date, YEAR(snap_date) AS y, QUARTER(snap_date) AS q
         FROM site_storage_snapshots
         WHERE 1=1 ${whereSite}
       ) t
       GROUP BY y, q
       ORDER BY y, q`, params);
    const series = [];
    for (const r of qrows) {
      const qParams = [r.quarter_end_snap]; let qWhere = '';
      if (siteId) { qWhere = 'AND site_id=?'; qParams.push(siteId); }
      const [sumRow] = await rbacPool.query(
        `SELECT SUM(used_bytes) AS bytes, COUNT(*) AS site_count
         FROM site_storage_snapshots WHERE snap_date=? ${qWhere}`, qParams);
      const bytes = Number(sumRow[0].bytes || 0);
      series.push({
        quarter: `${r.y}-Q${r.q}`,
        as_of: new Date(r.quarter_end_snap).toISOString().slice(0,10),
        bytes: bytes,
        tb: +(bytes / 1099511627776).toFixed(3),
        site_count: Number(sumRow[0].site_count || 0)
      });
    }
    res.json({ site_id: siteId, series });
  } catch (e) { console.error('[SITE-STORAGE] quarterly', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/sites/storage/:site_id/history', guard, async (req, res) => {
  try {
    const [rows] = await rbacPool.query(
      `SELECT DATE_FORMAT(snap_date,'%Y-%m-%d') AS d, site_name, web_url, used_bytes, quota_bytes
       FROM site_storage_snapshots WHERE site_id=? ORDER BY snap_date`, [req.params.site_id]);
    if (!rows.length) return res.json({ site_id: req.params.site_id, series: [] });
    res.json({
      site_id: req.params.site_id,
      site_name: rows[rows.length-1].site_name,
      web_url: rows[rows.length-1].web_url,
      series: rows.map(r => ({
        date: r.d,
        used_bytes: Number(r.used_bytes),
        quota_bytes: r.quota_bytes == null ? null : Number(r.quota_bytes)
      }))
    });
  } catch (e) { console.error('[SITE-STORAGE] history', e.message); res.status(500).json({ error: e.message }); }
});


// ── department site folders (request capability #2) ──────────────────────────
router.get('/departments/folders', guard, async (req, res) => {
  try {
    const [latestRow] = await rbacPool.query('SELECT MAX(snap_date) AS d FROM department_site_folders');
    const latestDate = latestRow[0] && latestRow[0].d ? new Date(latestRow[0].d).toISOString().slice(0,10) : null;
    if (!latestDate) return res.json({ empty: true, latest_date: null, folders: [] });
    const [rows] = await rbacPool.query(
      `SELECT f.site_id, f.site_name, d.department_name, d.web_url AS site_web_url, f.folder_name, f.folder_path,
              f.folder_size_bytes, f.last_modified_by, f.last_modified_at,
              f.last_modified_source, f.folder_web_url
         FROM department_site_folders f
         LEFT JOIN department_sites d ON d.site_id=f.site_id
        WHERE f.snap_date=?
        ORDER BY f.folder_size_bytes DESC`, [latestDate]);
    res.json({
      latest_date: latestDate,
      folders: rows.map(r => ({
        site_id: r.site_id, site_name: r.site_name, department_name: r.department_name,
        site_web_url: r.site_web_url,
        folder_name: r.folder_name, folder_path: r.folder_path,
        folder_size_bytes: Number(r.folder_size_bytes),
        last_modified_by: r.last_modified_by,
        last_modified_at: r.last_modified_at,
        last_modified_source: r.last_modified_source,
        folder_web_url: r.folder_web_url
      }))
    });
  } catch (e) { console.error('[DEPT] folders', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/departments/folders/:site_id/history', guard, async (req, res) => {
  try {
    const [rows] = await rbacPool.query(
      `SELECT DATE_FORMAT(snap_date,'%Y-%m-%d') AS d, folder_name, folder_path, folder_size_bytes,
              last_modified_by, last_modified_at, folder_web_url
         FROM department_site_folders WHERE site_id=? ORDER BY snap_date`, [req.params.site_id]);
    res.json({ site_id: req.params.site_id, series: rows.map(r => ({
      date: r.d, folder_name: r.folder_name, folder_path: r.folder_path,
      size_bytes: Number(r.folder_size_bytes),
      last_modified_by: r.last_modified_by, last_modified_at: r.last_modified_at,
      folder_web_url: r.folder_web_url
    })) });
  } catch (e) { console.error('[DEPT] history', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/departments/sites', guard, async (req, res) => {
  try {
    const [rows] = await rbacPool.query(
      `SELECT site_id, site_name, web_url, department_name, is_department, source, updated_at
         FROM department_sites ORDER BY is_department DESC, site_name`);
    res.json({ sites: rows });
  } catch (e) { console.error('[DEPT] sites', e.message); res.status(500).json({ error: e.message }); }
});

router.post('/departments/sites', guardAdmin, async (req, res) => {
  const { site_id, site_name, web_url, department_name } = req.body || {};
  if (!site_id || !site_name || !web_url) return res.status(400).json({ error: 'site_id, site_name, web_url required' });
  try {
    await rbacPool.query(
      `INSERT INTO department_sites (site_id, site_name, web_url, department_name, is_department, source)
       VALUES (?, ?, ?, ?, 1, 'manual')
       ON DUPLICATE KEY UPDATE is_department=1, department_name=VALUES(department_name), site_name=VALUES(site_name), web_url=VALUES(web_url), source='manual'`,
      [String(site_id).slice(0,255), String(site_name).slice(0,500), String(web_url).slice(0,1000), department_name ? String(department_name).slice(0,255) : null]
    );
    res.json({ ok: true });
  } catch (e) { console.error('[DEPT] add', e.message); res.status(500).json({ error: e.message }); }
});

router.delete('/departments/sites/:site_id', guardAdmin, async (req, res) => {
  try {
    await rbacPool.query('UPDATE department_sites SET is_department=0 WHERE site_id=?', [req.params.site_id]);
    res.json({ ok: true });
  } catch (e) { console.error('[DEPT] remove', e.message); res.status(500).json({ error: e.message }); }
});

// ── department drill-down: true site storage totals (added 2026-07) ───────────
router.get('/departments/site-storage', guard, async (req, res) => {
  try {
    const [sd] = await rbacPool.query('SELECT MAX(snap_date) AS d FROM site_storage_snapshots');
    const snap = sd[0] && sd[0].d ? new Date(sd[0].d).toISOString().slice(0,10) : null;
    if (!snap) return res.json({ empty: true, snap_date: null, rows: [] });
    const [fd] = await rbacPool.query('SELECT MAX(snap_date) AS d FROM department_site_folders');
    const fsnap = fd[0] && fd[0].d ? new Date(fd[0].d).toISOString().slice(0,10) : null;
    const [rows] = await rbacPool.query(
      `SELECT ss.site_id, ss.site_name, ds.department_name, ss.used_bytes, ss.quota_bytes,
              f.folder_name AS largest_folder, f.folder_size_bytes AS largest_bytes
         FROM site_storage_snapshots ss
         LEFT JOIN department_sites ds ON ds.site_id = ss.site_id
         LEFT JOIN department_site_folders f ON f.site_id = ss.site_id AND f.snap_date = ?
        WHERE ss.snap_date = ?
          AND ss.site_id IN (SELECT DISTINCT site_id FROM department_site_folders)
        ORDER BY ss.used_bytes DESC`, [fsnap, snap]);
    res.json({ snap_date: snap, rows: rows.map(r => ({
      site_id: r.site_id, site_name: r.site_name, department_name: r.department_name,
      used_bytes: Number(r.used_bytes), quota_bytes: r.quota_bytes == null ? null : Number(r.quota_bytes),
      largest_folder: r.largest_folder, largest_bytes: r.largest_bytes == null ? null : Number(r.largest_bytes)
    })) });
  } catch (e) { console.error('[DEPT] site-storage', e.message); res.status(500).json({ error: e.message }); }
});

// ── department drill-down: stale libraries 7y+ (added 2026-07) ────────────────
router.get('/departments/stale-libraries', guard, async (req, res) => {
  try {
    const [bd] = await rbacPool.query('SELECT MAX(batch_id) AS b FROM stale_drive_summary');
    const batch = bd[0] && bd[0].b ? bd[0].b : null;
    if (!batch) return res.json({ empty: true, batch_id: null, rows: [] });
    const [rows] = await rbacPool.query(
      `SELECT ds.department_name, sds.site_url, sds.site_name, sds.drive_name,
              sds.file_count, sds.total_bytes, sds.oldest_modified, sds.newest_modified
         FROM stale_drive_summary sds
         LEFT JOIN department_sites ds ON ds.web_url = sds.site_url
        WHERE sds.batch_id = ?
        ORDER BY sds.total_bytes DESC`, [batch]);
    res.json({ batch_id: String(batch), rows: rows.map(r => ({
      department_name: r.department_name, site_url: r.site_url, site_name: r.site_name,
      drive_name: r.drive_name, file_count: Number(r.file_count), total_bytes: Number(r.total_bytes),
      oldest_modified: r.oldest_modified, newest_modified: r.newest_modified,
      is_department: r.department_name != null
    })) });
  } catch (e) { console.error('[DEPT] stale-libraries', e.message); res.status(500).json({ error: e.message }); }
});

// ── department drill-down: stale files 7y+ (date filter + tenant-wide 2026-07) ─
router.get('/departments/stale-files', guard, async (req, res) => {
  try {
    const siteUrl = req.query.site_url ? String(req.query.site_url) : null;
    const dateOk = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
    const from = dateOk(req.query.from) ? req.query.from : null;
    const to   = dateOk(req.query.to)   ? req.query.to   : null;
    let limit = parseInt(req.query.limit, 10); if (!Number.isFinite(limit) || limit < 1) limit = 500; if (limit > 2000) limit = 2000;
    let offset = parseInt(req.query.offset, 10); if (!Number.isFinite(offset) || offset < 0) offset = 0;
    const [bd] = await rbacPool.query('SELECT MAX(batch_id) AS b FROM stale_files');
    const batch = bd[0] && bd[0].b ? bd[0].b : null;
    if (!batch) return res.json({ empty: true, batch_id: null, rows: [], total: 0 });
    const clauses = ['batch_id = ?']; const params = [batch];
    if (siteUrl) { clauses.push('site_url = ?'); params.push(siteUrl); }
    // "Either matches": in-range if EITHER modified_date OR created_date falls in [from, to)
    if (from && to)      { clauses.push('((modified_date >= ? AND modified_date < ?) OR (created_date >= ? AND created_date < ?))'); params.push(from, to, from, to); }
    else if (from)       { clauses.push('(modified_date >= ? OR created_date >= ?)'); params.push(from, from); }
    else if (to)         { clauses.push('(modified_date < ? OR created_date < ?)'); params.push(to, to); }
    const where = clauses.join(' AND ');
    const [cnt] = await rbacPool.query(`SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS b FROM stale_files WHERE ${where}`, params);
    const [rows] = await rbacPool.query(
      `SELECT site_name, site_url, file_name, file_path, web_url, drive_name, owner, modified_by, modified_date, created_date, size
         FROM stale_files WHERE ${where}
        ORDER BY size DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
    res.json({ batch_id: String(batch), total: Number(cnt[0].n), total_bytes: Number(cnt[0].b),
      limit, offset, site_url: siteUrl, from, to, rows: rows.map(r => ({
        site_name: r.site_name, site_url: r.site_url,
        file_name: r.file_name, file_path: r.file_path, web_url: r.web_url, drive_name: r.drive_name,
        owner: r.owner, modified_by: r.modified_by, modified_date: r.modified_date,
        created_date: r.created_date, size: Number(r.size)
      })) });
  } catch (e) { console.error('[DEPT] stale-files', e.message); res.status(500).json({ error: e.message }); }
});

// ── growth: per-user movers over a window (added 2026-07) ─────────────────────
router.get('/growth/movers', guard, async (req, res) => {
  const type = req.query.type === 'modifier' ? 'modifier' : 'creator';
  const window = ['week', 'month', 'year'].includes(req.query.window) ? req.query.window : 'month';
  const days = window === 'week' ? 7 : window === 'year' ? 365 : 30;
  try {
    const [ld] = await rbacPool.query('SELECT MAX(snap_date) AS d FROM storage_snapshots WHERE principal_type=?', [type]);
    const latestDate = ld[0] && ld[0].d ? new Date(ld[0].d).toISOString().slice(0, 10) : null;
    if (!latestDate) return res.json({ empty: true, type, window, latest_date: null, ref_date: null, has_baseline: false, rows: [] });
    const ref = new Date(latestDate); ref.setUTCDate(ref.getUTCDate() - days);
    const refStr = ref.toISOString().slice(0, 10);
    const [cur] = await rbacPool.query(
      'SELECT principal, total_bytes, file_count FROM storage_snapshots WHERE principal_type=? AND snap_date=? ORDER BY total_bytes DESC', [type, latestDate]);
    const [refRows] = await rbacPool.query(
      'SELECT principal, total_bytes FROM storage_snapshots WHERE principal_type=? AND snap_date=(SELECT MAX(snap_date) FROM storage_snapshots WHERE principal_type=? AND snap_date<=?)',
      [type, type, refStr]);
    const refMap = Object.fromEntries(refRows.map(r => [r.principal, Number(r.total_bytes)]));
    const rows = cur.map(r => {
      const now = Number(r.total_bytes);
      const has = r.principal in refMap;
      return { principal: r.principal, total_bytes: now, file_count: r.file_count,
               baseline_bytes: has ? refMap[r.principal] : null, change: has ? now - refMap[r.principal] : null, is_new: !has };
    }).sort((a, b) => {
      const ca = a.change == null ? a.total_bytes : a.change;
      const cb = b.change == null ? b.total_bytes : b.change;
      return cb - ca;
    });
    res.json({ type, window, latest_date: latestDate, ref_date: refStr, has_baseline: refRows.length > 0, rows });
  } catch (e) { console.error('[GROWTH] movers', e.message); res.status(500).json({ error: e.message }); }
});

// ── file inventory (Storage Explorer) — added 2026-07 ─────────────────────────
router.get('/inventory/summary', guard, async (req, res) => {
  try {
    const [runRows] = await rbacPool.query("SELECT batch_id, status, file_count, total_bytes, sites_scanned, partial_drives, finished_at FROM file_inventory_runs ORDER BY batch_id DESC LIMIT 1");
    const run = runRows[0];
    if (!run) return res.json({ empty: true, status: 'none' });
    // A crawl in flight has NULL counters. `Number(null || 0)` reported that
    // as a measured 0 -- "0 files, 0 B" -- which is the one answer this
    // endpoint must never invent. Null travels as null; the callers gate on
    // status==='done' and render '?'.
    const num = (v) => (v == null ? null : Number(v));
    res.json({ status: run.status, batch_id: String(run.batch_id),
      file_count: num(run.file_count), total_bytes: num(run.total_bytes),
      sites_scanned: num(run.sites_scanned), partial_drives: num(run.partial_drives),
      finished_at: run.finished_at });
  } catch (e) { console.error('[INV] summary', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/inventory/sites', guard, async (req, res) => {
  try {
    const [bRows] = await rbacPool.query("SELECT MAX(batch_id) AS bid FROM file_inventory_drives");
    const bid = bRows[0] && bRows[0].bid ? bRows[0].bid : null;
    if (!bid) return res.json({ rows: [] });
    const [rows] = await rbacPool.query(
      `SELECT site_url, MAX(site_name) site_name, SUM(file_count) file_count, SUM(total_bytes) total_bytes, MAX(partial) partial
         FROM file_inventory_drives WHERE batch_id=? GROUP BY site_url ORDER BY total_bytes DESC`, [bid]);
    res.json({ rows: rows.map(r => ({ site_url: r.site_url, site_name: r.site_name, file_count: Number(r.file_count), total_bytes: Number(r.total_bytes), partial: !!r.partial })) });
  } catch (e) { console.error('[INV] sites', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/inventory/libraries', guard, async (req, res) => {
  try {
    const site = req.query.site_url ? String(req.query.site_url) : null;
    if (!site) return res.status(400).json({ error: 'site_url required' });
    const [bRows] = await rbacPool.query("SELECT MAX(batch_id) AS bid FROM file_inventory_drives");
    const bid = bRows[0] && bRows[0].bid ? bRows[0].bid : null;
    if (!bid) return res.json({ rows: [] });
    const [rows] = await rbacPool.query(
      `SELECT drive_name, file_count, total_bytes, partial FROM file_inventory_drives WHERE batch_id=? AND site_url=? ORDER BY total_bytes DESC`, [bid, site]);
    res.json({ site_url: site, rows: rows.map(r => ({ drive_name: r.drive_name, file_count: Number(r.file_count), total_bytes: Number(r.total_bytes), partial: !!r.partial })) });
  } catch (e) { console.error('[INV] libraries', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/inventory/folders', guard, async (req, res) => {
  try {
    const site = req.query.site_url ? String(req.query.site_url) : null;
    if (!site) return res.status(400).json({ error: 'site_url required' });
    const drive = req.query.drive_name ? String(req.query.drive_name) : null;
    const prefix = req.query.prefix ? String(req.query.prefix) : '';
    const start = prefix.length + 1;
    const cl = ['site_url=?']; const p = [site];
    if (drive) { cl.push('drive_name=?'); p.push(drive); }
    if (prefix) { cl.push('file_path LIKE ?'); p.push(prefix + '/%'); }
    const expr = prefix ? 'SUBSTRING(file_path, ?)' : 'file_path';
    const sub = `SELECT size, SUBSTRING_INDEX(TRIM(LEADING '/' FROM ${expr}), '/', 1) seg, (TRIM(LEADING '/' FROM ${expr}) LIKE '%/%') more FROM file_inventory WHERE ${cl.join(' AND ')}`;
    const params = prefix ? [start, start, ...p] : [...p];
    const [rows] = await rbacPool.query(
      `SELECT seg AS name, SUM(size) total_bytes, COUNT(*) file_count, MAX(more) is_folder FROM (${sub}) t WHERE seg<>'' GROUP BY seg ORDER BY total_bytes DESC LIMIT 500`, params);
    res.json({ site_url: site, drive_name: drive, prefix, rows: rows.map(r => ({ name: r.name, total_bytes: Number(r.total_bytes), file_count: Number(r.file_count), is_folder: !!r.is_folder })) });
  } catch (e) { console.error('[INV] folders', e.message); res.status(500).json({ error: e.message }); }
});

function _invWhere(q) {
  const dOk = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
  const site = q.site_url ? String(q.site_url) : null;
  const drive = q.drive_name ? String(q.drive_name) : null;
  const prefix = q.prefix ? String(q.prefix) : null;
  const ext = q.ext ? String(q.ext).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 32) : null;
  const user = q.user ? String(q.user) : null;
  const userField = q.user_field === 'modified_by' ? 'modified_by' : (q.user_field === 'owner' ? 'owner' : null);
  const dateField = q.date_field === 'created' ? 'created_date' : 'modified_date';
  const from = dOk(q.from) ? q.from : null, to = dOk(q.to) ? q.to : null;
  const minSize = /^\d+$/.test(q.min_size || '') ? parseInt(q.min_size, 10) : null;
  const maxSize = /^\d+$/.test(q.max_size || '') ? parseInt(q.max_size, 10) : null;
  const search = (q.search || '').trim();
  const cl = [], p = [];
  if (site) { cl.push('site_url=?'); p.push(site); }
  if (drive) { cl.push('drive_name=?'); p.push(drive); }
  if (prefix) { cl.push('file_path LIKE ?'); p.push(prefix + '/%'); }
  if (ext) { cl.push('ext=?'); p.push(ext); }
  if (user && userField) { cl.push(userField + '=?'); p.push(user); }
  else if (user) { cl.push('(owner=? OR modified_by=?)'); p.push(user, user); }
  if (from && to) { cl.push(`(${dateField}>=? AND ${dateField}<?)`); p.push(from, to); }
  else if (from) { cl.push(`${dateField}>=?`); p.push(from); }
  else if (to) { cl.push(`${dateField}<?`); p.push(to); }
  if (minSize != null) { cl.push('size>=?'); p.push(minSize); }
  if (maxSize != null) { cl.push('size<=?'); p.push(maxSize); }
  if (search) { const bool = search.split(/\s+/).filter(Boolean).map(w => '+' + w.replace(/[+\-><()~*"@]/g, '') + '*').join(' '); if (bool) { cl.push('MATCH(file_name,file_path) AGAINST (? IN BOOLEAN MODE)'); p.push(bool); } }
  if (q.partial === '1') { cl.push('(site_url, drive_name) IN (SELECT site_url, drive_name FROM file_inventory_drives WHERE batch_id=(SELECT MAX(batch_id) FROM file_inventory_drives) AND partial=1)'); }
  return { where: cl.length ? ('WHERE ' + cl.join(' AND ')) : '', params: p };
}

router.get('/inventory/files', guard, async (req, res) => {
  try {
    let page = Math.max(1, parseInt(req.query.page || '1', 10) || 1);
    let pageSize = Math.min(500, Math.max(10, parseInt(req.query.pageSize || '100', 10) || 100));
    const SORT = { size: 'size', modified_date: 'modified_date', created_date: 'created_date', file_name: 'file_name', site_name: 'site_name', owner: 'owner', modified_by: 'modified_by' };
    const sortBy = SORT[String(req.query.sortBy || 'size')] || 'size';
    const sortDir = String(req.query.sortDir || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
    const { where, params } = _invWhere(req.query);
    // With no filters, COUNT+SUM scans all ~8.7M rows (~5s) — the runs rollup
    // already holds the exact totals once a crawl is done.
    let total, totalBytes;
    if (!where) {
      const [rr] = await rbacPool.query("SELECT status, file_count, total_bytes FROM file_inventory_runs ORDER BY batch_id DESC LIMIT 1");
      if (rr[0] && rr[0].status === 'done') { total = Number(rr[0].file_count || 0); totalBytes = Number(rr[0].total_bytes || 0); }
    }
    if (total === undefined) {
      const [cntRows] = await rbacPool.query(`SELECT COUNT(*) n, COALESCE(SUM(size),0) b FROM file_inventory ${where}`, params);
      total = Number(cntRows[0].n); totalBytes = Number(cntRows[0].b);
    }
    const [rows] = await rbacPool.query(
      `SELECT site_name,site_url,drive_name,file_name,file_path,web_url,owner,modified_by,modified_date,created_date,size,ext
         FROM file_inventory ${where} ORDER BY ${sortBy} ${sortDir} LIMIT ? OFFSET ?`, [...params, pageSize, (page - 1) * pageSize]);
    res.json({ total, total_bytes: totalBytes, page, pageSize, rows });
  } catch (e) { console.error('[INV] files', e.message); res.status(500).json({ error: e.message }); }
});

router.get('/inventory/export', guard, async (req, res) => {
  try {
    const { where, params } = _invWhere(req.query);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="inventory-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.write('Site,Library,File Name,Folder,File Path,Owner,Last Modified By,Modified,Created,Size (bytes),Ext,Web URL\n');
    const csv = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
    const CH = 5000; let off = 0;
    for (;;) {
      const [rows] = await rbacPool.query(
        `SELECT site_name,drive_name,file_name,file_path,owner,modified_by,modified_date,created_date,size,ext,web_url
           FROM file_inventory ${where} ORDER BY size DESC LIMIT ? OFFSET ?`, [...params, CH, off]);
      if (!rows.length) break;
      for (const r of rows) {
        const folder = (r.file_path || '').replace(/\/[^/]*$/, '') || '/';
        res.write([csv(r.site_name), csv(r.drive_name), csv(r.file_name), csv(folder), csv(r.file_path), csv(r.owner), csv(r.modified_by),
          r.modified_date ? new Date(r.modified_date).toISOString() : '', r.created_date ? new Date(r.created_date).toISOString() : '', r.size || 0, csv(r.ext), csv(r.web_url)].join(',') + '\n');
      }
      off += CH; if (rows.length < CH) break;
    }
    res.end();
  } catch (e) { console.error('[INV] export', e.message); res.status(500).end(); }
});
// ── file inventory: storage by file type (dashboard strip) ───────────────
// The crawler writes a small, table-generation-keyed snapshot after the inventory table
// swap. Its source is the rows successfully inserted into staging. Keep the SQL
// scan as a fallback for an absent/corrupt snapshot or the first deploy before
// the next crawl; dedupe those cold requests within this process.
let _extCache = null, _extInflight = null;
router.get('/inventory/by-ext', guard, async (req, res) => {
  try {
    // A running crawl still exposes the previous completed table. CREATE_TIME
    // changes at the atomic table swap, even if the crawler dies before it can
    // mark the run done. The run's status alone is not a safe cache key here.
    const [[table]] = await rbacPool.query(
      "SELECT DATE_FORMAT(CREATE_TIME, '%Y-%m-%d %H:%i:%s') AS generation FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='file_inventory'");
    const key = table?.generation || null;
    if (key && _extCache && _extCache.key === key) return res.json({ rows: _extCache.rows });
    if (key && _extInflight && _extInflight.key === key) return res.json({ rows: await _extInflight.p });
    const p = (async () => {
      if (key) {
        // The crawler publishes the snapshot immediately after RENAME TABLE.
        // Give that small cross-resource handoff 100 ms before starting the
        // expensive fallback scan; a crashed crawler still falls back to SQL.
        for (let attempt = 0; attempt <= 5; attempt++) {
          const saved = extSummaryCache.read(key);
          if (saved) return saved;
          if (attempt < 5) await new Promise(resolve => setTimeout(resolve, 20));
        }
      }
      const [rows] = await rbacPool.query("SELECT ext, COUNT(*) file_count, SUM(size) total_bytes FROM file_inventory WHERE ext<>'' GROUP BY ext ORDER BY total_bytes DESC LIMIT 12");
      const out = rows.map(r => ({ ext: r.ext, file_count: Number(r.file_count), total_bytes: Number(r.total_bytes) }));
      // Seed the durable cache on the first request after this code is deployed,
      // before the next nightly crawl. A swap during the query changes the key;
      // its own generation-specific file remains safe to ignore afterward.
      if (key) {
        try { await extSummaryCache.write('on-demand', key, out); }
        catch (e) { console.warn('[INV] by-ext snapshot write:', e.message); }
      }
      return out;
    })();
    _extInflight = { key, p };
    try {
      const out = await p;
      if (key && _extInflight?.p === p) _extCache = { key, rows: out };
      res.json({ rows: out });
    } finally { if (_extInflight?.p === p) _extInflight = null; }
  } catch (e) { console.error('[INV] by-ext', e.message); res.status(500).json({ error: e.message }); }
});

module.exports = router;
