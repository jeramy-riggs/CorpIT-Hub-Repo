// sp-label-routes.js — Retention label ("Tag Scan") results. Mounted at /api/sharepoint-labels.
// Data comes from sp-label-scan-job.js (nightly cron + POST /refresh).
const express = require('express');
const mysql   = require('mysql2/promise');
const path    = require('path');
const { spawn } = require('child_process');
const router  = express.Router();

const createRbac = require('./rbac-middleware');
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 3, timezone: 'Z',
});
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const guard = rbac.requirePage('sharepoint-gov', 'read');
const guardAdmin = rbac.requirePage('sharepoint-gov', 'admin');

// Matches STALE_RUN_MIN in the job: a 'running' row older than this was killed.
const RUNNING_MAX_MIN = 120;
const ITEM_CAP = 5000;

async function latestDone() {
  const [r] = await pool.query(
    "SELECT batch_id, started_at, finished_at, labels_found, items_found, truncated FROM sp_label_scan_runs WHERE status='done' ORDER BY batch_id DESC LIMIT 1");
  return r[0] || null;
}
async function runningRun() {
  const [r] = await pool.query(
    "SELECT batch_id, started_at FROM sp_label_scan_runs WHERE status='running' AND started_at > UTC_TIMESTAMP() - INTERVAL ? MINUTE ORDER BY batch_id DESC LIMIT 1",
    [RUNNING_MAX_MIN]);
  return r[0] || null;
}
async function lastFailure(afterBatch) {
  const [r] = await pool.query(
    "SELECT batch_id, started_at, finished_at, error FROM sp_label_scan_runs WHERE status='failed' AND batch_id > ? ORDER BY batch_id DESC LIMIT 1",
    [afterBatch || 0]);
  return r[0] || null;
}

router.get('/summary', guard, async (req, res) => {
  try {
    const run = await latestDone(), running = await runningRun();
    const failed = await lastFailure(run && run.batch_id);
    if (!run) return res.json({ run: null, running, failed, labels: [] });
    const [labels] = await pool.query(
      `SELECT l.label, l.search_total, l.items_stored, l.truncated,
              COUNT(DISTINCT i.site_url) sites, SUM(i.item_kind='folder' OR (i.item_kind IS NULL AND i.is_document=0)) folders
         FROM sp_label_scan_labels l
         LEFT JOIN sp_label_scan_items i ON i.batch_id=l.batch_id AND i.label=l.label
        WHERE l.batch_id=? GROUP BY l.label, l.search_total, l.items_stored, l.truncated
        ORDER BY l.items_stored DESC, l.label`, [run.batch_id]);
    const [[tot]] = await pool.query(
      'SELECT COUNT(DISTINCT site_url) sites FROM sp_label_scan_items WHERE batch_id=?', [run.batch_id]);
    res.json({ run: { ...run, sites: Number(tot.sites) || 0 }, running, failed,
      labels: labels.map(l => ({ ...l, sites: Number(l.sites) || 0, folders: Number(l.folders) || 0 })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/items', guard, async (req, res) => {
  try {
    const label = String(req.query.label || '');
    if (!label) return res.status(400).json({ error: 'label required' });
    const run = await latestDone();
    if (!run) return res.json({ run: null, label, sites: [], items: [], total: 0, capped: false });
    const [sites] = await pool.query(
      `SELECT site_title, site_url, MAX(hub_title) hub_title, MAX(hub_url) hub_url, COUNT(*) items,
              SUM(item_kind='folder' OR (item_kind IS NULL AND is_document=0)) folders, COALESCE(SUM(size_bytes),0) bytes, MAX(modified_at) last_modified
         FROM sp_label_scan_items WHERE batch_id=? AND label=?
        GROUP BY site_title, site_url ORDER BY items DESC, site_title`, [run.batch_id, label]);
    // Library › folder breakdown per site (folder_path '' = library root).
    const [folders] = await pool.query(
      `SELECT site_url, library, library_url, folder_path, COUNT(*) items, SUM(item_kind='folder' OR (item_kind IS NULL AND is_document=0)) folders,
              COALESCE(SUM(size_bytes),0) bytes, MAX(modified_at) last_modified
         FROM sp_label_scan_items WHERE batch_id=? AND label=?
        GROUP BY site_url, library, library_url, folder_path ORDER BY site_url, items DESC, library, folder_path`,
      [run.batch_id, label]);
    const [[cnt]] = await pool.query(
      'SELECT COUNT(*) c FROM sp_label_scan_items WHERE batch_id=? AND label=?', [run.batch_id, label]);
    const [items] = await pool.query(
      `SELECT label, site_title, site_url, hub_title, library, library_url, folder_path, item_kind, path, file_name, file_ext, is_document, size_bytes, modified_at, modified_by
         FROM sp_label_scan_items WHERE batch_id=? AND label=?
        ORDER BY site_title, path LIMIT ?`, [run.batch_id, label, ITEM_CAP]);
    const total = Number(cnt.c) || 0;
    res.json({ run: { batch_id: run.batch_id, finished_at: run.finished_at }, label,
      sites: sites.map(s => ({ ...s, items: Number(s.items), folders: Number(s.folders) || 0, bytes: Number(s.bytes) })),
      folders: folders.map(f => ({ ...f, items: Number(f.items), folders: Number(f.folders) || 0, bytes: Number(f.bytes) })),
      items, total, capped: total > items.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/refresh', guardAdmin, async (req, res) => {
  try {
    const running = await runningRun();
    if (running) return res.status(409).json({ error: 'A label scan is already running', running });
    const child = spawn(process.execPath, [path.join(__dirname, 'sp-label-scan-job.js')],
      { cwd: __dirname, env: process.env, detached: true, stdio: 'ignore' });
    child.unref();
    res.json({ ok: true, started: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
