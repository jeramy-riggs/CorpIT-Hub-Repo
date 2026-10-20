'use strict';
/**
 * gpo-audit.js
 * ─────────────────────────────────────────────────────────────────────
 * Express router mounted at /api/gpo by server.js.
 *
 * Endpoints:
 *   GET    /api/gpo/health                       — module health + DB ping
 *   POST   /api/gpo/upload                       — accept XML, parse, persist (multipart)
 *   GET    /api/gpo/uploads                      — upload history
 *   GET    /api/gpo/diff?from=&to=                — compare completed snapshots (read-only)
 *   GET    /api/gpo/inventory                    — list GPOs in the active upload
 *   GET    /api/gpo/gpo/:guid                    — single GPO detail (links, settings sample)
 *   GET    /api/gpo/findings                     — findings from the active upload (filterable)
 *   GET    /api/gpo/stats                        — summary counts for sidebar cards
 *   GET    /api/gpo/wmi-filters                  — WMI filters list
 *   POST   /api/gpo/uploads/:id/activate         — switch active snapshot to an earlier upload
 *   DELETE /api/gpo/uploads/:id                  — purge a non-active upload snapshot
 *
 * Database: corpit_hub (same pool pattern as other api-beta modules)
 * Uploads: written to ./tmp-uploads/, parsed, then deleted on success.
 * ─────────────────────────────────────────────────────────────────────
 */

const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const { parseGpoReport } = require('./gpo-parser');
const { analyze } = require('./gpo-conflict-engine');
const { buildRecommendations } = require('./gpo-recommendations');
const { createReadinessService } = require('./gpo-readiness');
const { snapshotId, compareSnapshots } = require('./gpo-snapshot-diff');

// ── BOM-aware XML reader ─────────────────────────────────────────────
// PowerShell's Get-GPOReport -ReportType Xml writes UTF-16 LE by default.
// We detect the BOM and decode accordingly.
function readXmlFile(path) {
  const buf = fs.readFileSync(path);
  if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
    return buf.subarray(2).toString('utf16le');
  }
  if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) {
    // UTF-16 BE — swap byte pairs, then decode as LE
    const swapped = Buffer.alloc(buf.length - 2);
    for (let i = 2; i < buf.length - 1; i += 2) {
      swapped[i - 2] = buf[i + 1];
      swapped[i - 1] = buf[i];
    }
    return swapped.toString('utf16le');
  }
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
    return buf.subarray(3).toString('utf8');
  }
  return buf.toString('utf8');
}

const router = express.Router();
// ---- RBAC enforcement (Slice 11: gpo-audit, super-admin only) ----
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

// ── DB pool ───────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME_BETA || 'corpit_hub',
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0
});

const readinessService = createReadinessService({ pool, getActiveUploadId });

// ── Upload handling ───────────────────────────────────────────────────
const UPLOAD_DIR = path.join(__dirname, 'tmp-uploads');
try { fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch (e) { /* ignore */ }

const MAX_FILE_SIZE = 50 * 1024 * 1024;  // 50 MB

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (req, file, cb) => {
    // Accept .xml by extension OR by mimetype
    const okExt = /\.xml$/i.test(file.originalname);
    const okMime = /xml/i.test(file.mimetype || '');
    if (!okExt && !okMime) return cb(new Error('Only .xml files are accepted'));
    cb(null, true);
  }
});

// ── Helpers ───────────────────────────────────────────────────────────
function badReq(res, msg, code = 'BAD_REQUEST') {
  return res.status(400).json({ ok: false, error: { code, message: msg } });
}
function serverErr(res, err, code = 'SERVER_ERROR') {
  console.error('[gpo-audit]', code, err && err.stack ? err.stack : err);
  return res.status(500).json({ ok: false, error: { code, message: err && err.message ? err.message : String(err) } });
}

async function getActiveUploadId(conn) {
  const [rows] = await conn.query('SELECT id FROM gpo_uploads WHERE is_active=1 ORDER BY id DESC LIMIT 1');
  return rows.length ? rows[0].id : null;
}

// ═══════════════════════════════════════════════════════════════════════
// GET /api/gpo/health
// ═══════════════════════════════════════════════════════════════════════
router.get('/health', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    try {
      await conn.query('SELECT 1');
      const [u] = await conn.query('SELECT COUNT(*) AS c FROM gpo_uploads');
      const activeId = await getActiveUploadId(conn);
      res.json({ ok: true, status: 'ok', db: 'connected', uploads: u[0].c, active_upload_id: activeId });
    } finally {
      conn.release();
    }
  } catch (e) {
    return serverErr(res, e, 'HEALTH_FAIL');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// POST /api/gpo/upload   (multipart: field "file")
// ═══════════════════════════════════════════════════════════════════════
router.post('/upload', rbac.requireSuperAdmin, upload.single('file'), async (req, res) => {
  const tmpPath = req.file && req.file.path;
  const originalName = req.file && req.file.originalname;
  const fileSize = req.file && req.file.size;
  const uploadedBy = (req.user && req.user.email) || null;   // session identity only; never the body

  if (!tmpPath) return badReq(res, 'No file received. Field name must be "file".');

  let conn;
  let uploadId = null;
  try {
    // ── Read file from disk ────────────────────────────
    const xmlString = readXmlFile(tmpPath);

    // ── Parse ──────────────────────────────────────────
    const parsed = parseGpoReport(xmlString);
    if (!parsed.gpos.length) throw new Error('Parser produced zero GPOs. Check the XML was generated by Get-GPOReport -All -ReportType Xml.');

    // ── Run conflict analysis ──────────────────────────
    const findings = analyze(parsed);

    // ── Persist ────────────────────────────────────────
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // Create upload row (inactive until finished)
    const [ins] = await conn.query(
      'INSERT INTO gpo_uploads (filename, file_size, gpo_count, finding_count, uploaded_by, parse_status, is_active) VALUES (?, ?, ?, ?, ?, ?, 0)',
      [originalName, fileSize, parsed.gpos.length, findings.length, uploadedBy, 'pending']
    );
    uploadId = ins.insertId;

    // Insert inventory rows
    for (const g of parsed.gpos) {
      await conn.query(
        `INSERT INTO gpo_inventory
         (upload_id, guid, name, domain, created_time, modified_time,
          user_enabled, computer_enabled,
          user_version_dir, user_version_sysvol, comp_version_dir, comp_version_sysvol,
          wmi_filter_name, security_trustees,
          setting_count_user, setting_count_computer, link_count, has_settings)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [uploadId, g.guid, g.name.slice(0, 512), g.domain, g.created_time, g.modified_time,
         g.user_enabled ? 1 : 0, g.computer_enabled ? 1 : 0,
         g.user_version_dir, g.user_version_sysvol, g.comp_version_dir, g.comp_version_sysvol,
         g.wmi_filter_name ? g.wmi_filter_name.slice(0, 255) : null,
         g.security_trustees,
         g.setting_count_user, g.setting_count_computer, g.links.length, g.has_settings ? 1 : 0]
      );
    }

    // Insert link rows
    for (const g of parsed.gpos) {
      for (const l of g.links) {
        await conn.query(
          'INSERT INTO gpo_links (upload_id, gpo_guid, som_name, som_path, link_enabled, enforced) VALUES (?,?,?,?,?,?)',
          [uploadId, g.guid, (l.som_name || '').slice(0, 512), (l.som_path || '').slice(0, 1024), l.link_enabled ? 1 : 0, l.enforced ? 1 : 0]
        );
      }
    }

    // Insert WMI filter rows
    for (const w of parsed.wmiFilters) {
      await conn.query(
        'INSERT INTO gpo_wmi_filters (upload_id, filter_name, query, description, used_by_count) VALUES (?,?,?,?,?)',
        [uploadId, w.filter_name.slice(0, 255), w.query, w.description, w.used_by_count]
      );
    }

    // Insert settings rows (batched for performance)
    const SETTING_BATCH = 500;
    const allSettings = [];
    for (const g of parsed.gpos) {
      for (const s of g.settings) {
        allSettings.push([uploadId, g.guid, s.scope, s.setting_type,
          (s.setting_key || '').slice(0, 512),
          s.setting_name ? s.setting_name.slice(0, 512) : null,
          s.setting_state ? s.setting_state.slice(0, 64) : null,
          s.setting_value || null,
          s.category_path ? s.category_path.slice(0, 1024) : null]);
      }
    }
    for (let i = 0; i < allSettings.length; i += SETTING_BATCH) {
      const chunk = allSettings.slice(i, i + SETTING_BATCH);
      if (!chunk.length) continue;
      await conn.query(
        `INSERT INTO gpo_settings (upload_id, gpo_guid, scope, setting_type, setting_key, setting_name, setting_state, setting_value, category_path) VALUES ${chunk.map(() => '(?,?,?,?,?,?,?,?,?)').join(',')}`,
        chunk.flat()
      );
    }

    // Insert findings  (Phase 1: setting_key column persists per-finding setting reference)
    for (const f of findings) {
      await conn.query(
        'INSERT INTO gpo_findings (upload_id, gpo_guid, severity, code, title, detail, related_guids, setting_key) VALUES (?,?,?,?,?,?,?,?)',
        [uploadId, f.gpo_guid, f.severity, f.code, f.title.slice(0, 255), f.detail, f.related_guids, f.setting_key || null]
      );
    }

    // Mark this upload active; deactivate all others
    await conn.query('UPDATE gpo_uploads SET is_active=0 WHERE id<>?', [uploadId]);
    await conn.query('UPDATE gpo_uploads SET is_active=1, parse_status=? WHERE id=?', ['ok', uploadId]);

    await conn.commit();

    // Cleanup tmp file
    try { fs.unlinkSync(tmpPath); } catch (e) { /* ignore */ }

    res.json({
      ok: true,
      data: {
        upload_id: uploadId,
        gpo_count: parsed.gpos.length,
        finding_count: findings.length,
        wmi_filter_count: parsed.wmiFilters.length,
        warnings: parsed.warnings || []
      }
    });
  } catch (e) {
    // Roll back transaction and mark error
    if (conn) {
      try { await conn.rollback(); } catch (_) { /* ignore */ }
    }
    // Try to record the failure (best-effort, in a fresh connection)
    if (uploadId !== null) {
      try {
        const c2 = await pool.getConnection();
        try {
          await c2.query('UPDATE gpo_uploads SET parse_status=?, parse_error=? WHERE id=?', ['error', String(e.message || e).slice(0, 1024), uploadId]);
        } finally { c2.release(); }
      } catch (_) { /* ignore */ }
    }
    try { if (tmpPath) fs.unlinkSync(tmpPath); } catch (_) { /* ignore */ }
    return serverErr(res, e, 'UPLOAD_PARSE_FAIL');
  } finally {
    if (conn) conn.release();
  }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /api/gpo/uploads
// ═══════════════════════════════════════════════════════════════════════
router.get('/uploads', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, filename, file_size, gpo_count, finding_count, uploaded_by, uploaded_at, parse_status, parse_error, is_active FROM gpo_uploads ORDER BY id DESC LIMIT 50');
    res.json({ ok: true, data: rows });
  } catch (e) { return serverErr(res, e); }
});

// Read-only comparison of any two completed snapshots, without activation.
router.get('/diff', rbac.requireSuperAdmin, async (req, res) => {
  const from = snapshotId(req.query.from), to = snapshotId(req.query.to);
  if (from === null || to === null) return badReq(res, 'from and to must be positive snapshot IDs');
  if (from === to) return badReq(res, 'Choose two different snapshots');
  let conn;
  try {
    conn = await pool.getConnection();
    return res.json({ ok: true, data: await compareSnapshots(conn, from, to) });
  } catch (e) {
    if (e.status === 404 || e.status === 409) {
      return res.status(e.status).json({ ok: false, error: { code: e.code, message: e.message } });
    }
    return serverErr(res, e, 'DIFF_FAIL');
  } finally { if (conn) conn.release(); }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /api/gpo/inventory
// ═══════════════════════════════════════════════════════════════════════
router.get('/inventory', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    try {
      const activeId = await getActiveUploadId(conn);
      if (!activeId) return res.json({ ok: true, data: [], upload_id: null });
      const [rows] = await conn.query(
        `SELECT i.id, i.guid, i.name, i.domain, i.created_time, i.modified_time,
                i.user_enabled, i.computer_enabled, i.wmi_filter_name,
                i.setting_count_user, i.setting_count_computer, i.link_count, i.has_settings,
                (SELECT COUNT(*) FROM gpo_links l WHERE l.upload_id=i.upload_id AND l.gpo_guid=i.guid AND l.link_enabled=1) AS enabled_link_count,
                (SELECT COUNT(*) FROM gpo_findings f WHERE f.upload_id=i.upload_id AND f.gpo_guid=i.guid) AS finding_count
         FROM gpo_inventory i
         WHERE i.upload_id=?
         ORDER BY i.name`,
        [activeId]
      );
      res.json({ ok: true, data: rows, upload_id: activeId });
    } finally { conn.release(); }
  } catch (e) { return serverErr(res, e); }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /api/gpo/gpo/:guid
// ═══════════════════════════════════════════════════════════════════════
router.get('/gpo/:guid', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const guid = (req.params.guid || '').toLowerCase().replace(/[{}]/g, '');
    if (!/^[a-f0-9-]{32,40}$/.test(guid)) return badReq(res, 'Invalid GUID format');
    const conn = await pool.getConnection();
    try {
      const activeId = await getActiveUploadId(conn);
      if (!activeId) return res.json({ ok: true, data: null });
      const [invRows] = await conn.query('SELECT * FROM gpo_inventory WHERE upload_id=? AND guid=?', [activeId, guid]);
      if (!invRows.length) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'GPO not in active upload' } });
      const [links] = await conn.query('SELECT som_name, som_path, link_enabled, enforced FROM gpo_links WHERE upload_id=? AND gpo_guid=?', [activeId, guid]);
      const [settingsSample] = await conn.query('SELECT scope, setting_type, setting_name, setting_state, setting_value, category_path FROM gpo_settings WHERE upload_id=? AND gpo_guid=? ORDER BY setting_type, category_path LIMIT 200', [activeId, guid]);
      const [findings] = await conn.query('SELECT severity, code, title, detail, related_guids FROM gpo_findings WHERE upload_id=? AND gpo_guid=? ORDER BY FIELD(severity,"critical","warn","info")', [activeId, guid]);
      res.json({ ok: true, data: { gpo: invRows[0], links, settings: settingsSample, findings } });
    } finally { conn.release(); }
  } catch (e) { return serverErr(res, e); }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /api/gpo/findings?severity=warn&code=UNLINKED&limit=500
// ═══════════════════════════════════════════════════════════════════════
router.get('/findings', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const sev = req.query.severity;
    const code = req.query.code;
    const limit = Math.min(parseInt(req.query.limit) || 500, 2000);
    const conn = await pool.getConnection();
    try {
      const activeId = await getActiveUploadId(conn);
      if (!activeId) return res.json({ ok: true, data: [], upload_id: null });
      const conds = ['f.upload_id=?'];
      const params = [activeId];
      if (sev && ['info','warn','critical'].includes(sev)) { conds.push('f.severity=?'); params.push(sev); }
      if (code && /^[A-Z_]+$/.test(code)) { conds.push('f.code=?'); params.push(code); }
      // The LIMIT decides how many rows travel, not how many exist. Count the
      // matching rows separately so the page can say "500 of 1369" instead of
      // presenting the cap as the total. conds only reference f.*, so the count
      // needs no join.
      const countParams = params.slice();
      params.push(limit);
      const [rows] = await conn.query(
        `SELECT f.id, f.gpo_guid, f.severity, f.code, f.title, f.detail, f.related_guids,
                i.name AS gpo_name
         FROM gpo_findings f
         LEFT JOIN gpo_inventory i ON i.upload_id=f.upload_id AND i.guid=f.gpo_guid
         WHERE ${conds.join(' AND ')}
         ORDER BY FIELD(f.severity,"critical","warn","info"), f.code, f.id
         LIMIT ?`,
        params
      );
      const [[cnt]] = await conn.query(
        `SELECT COUNT(*) AS total FROM gpo_findings f WHERE ${conds.join(' AND ')}`,
        countParams);
      res.json({ ok: true, data: rows, total: cnt.total,
                 truncated: rows.length < cnt.total, limit, upload_id: activeId });
    } finally { conn.release(); }
  } catch (e) { return serverErr(res, e); }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /api/gpo/stats
// ═══════════════════════════════════════════════════════════════════════
router.get('/stats', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    try {
      const activeId = await getActiveUploadId(conn);
      if (!activeId) return res.json({ ok: true, data: null });
      const [[totals]] = await conn.query(
        `SELECT
           COUNT(*) AS gpo_total,
           SUM(CASE WHEN link_count=0 THEN 1 ELSE 0 END) AS unlinked,
           SUM(CASE WHEN user_enabled=0 AND computer_enabled=0 THEN 1 ELSE 0 END) AS all_disabled,
           SUM(CASE WHEN has_settings=0 THEN 1 ELSE 0 END) AS empty_gpos,
           SUM(CASE WHEN modified_time IS NOT NULL AND modified_time < DATE_SUB(NOW(), INTERVAL 2 YEAR) THEN 1 ELSE 0 END) AS stale,
           SUM(CASE WHEN wmi_filter_name IS NOT NULL THEN 1 ELSE 0 END) AS with_wmi
         FROM gpo_inventory WHERE upload_id=?`, [activeId]);
      const [[findingCounts]] = await conn.query(
        `SELECT
           SUM(severity='critical') AS critical,
           SUM(severity='warn') AS warn,
           SUM(severity='info') AS info,
           COUNT(*) AS total
         FROM gpo_findings WHERE upload_id=?`, [activeId]);
      const [[conflictCount]] = await conn.query(
        `SELECT COUNT(*) AS c FROM gpo_findings WHERE upload_id=? AND code='SETTING_CONFLICT'`, [activeId]);
      const [[uploadMeta]] = await conn.query('SELECT filename, uploaded_at, uploaded_by FROM gpo_uploads WHERE id=?', [activeId]);
      res.json({
        ok: true,
        data: {
          upload_id: activeId,
          upload: uploadMeta,
          totals,
          findings: findingCounts,
          conflicts: conflictCount.c
        }
      });
    } finally { conn.release(); }
  } catch (e) { return serverErr(res, e); }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /api/gpo/wmi-filters
// ═══════════════════════════════════════════════════════════════════════
router.get('/wmi-filters', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    try {
      const activeId = await getActiveUploadId(conn);
      if (!activeId) return res.json({ ok: true, data: [], upload_id: null });
      const [rows] = await conn.query('SELECT filter_name, query, description, used_by_count FROM gpo_wmi_filters WHERE upload_id=? ORDER BY filter_name', [activeId]);
      res.json({ ok: true, data: rows, upload_id: activeId });
    } finally { conn.release(); }
  } catch (e) { return serverErr(res, e); }
});

// ═══════════════════════════════════════════════════════════════════════
// POST /api/gpo/uploads/:id/activate
// ═══════════════════════════════════════════════════════════════════════
// Complete snapshot-only readiness estimate; never contacts AD or Microsoft Graph.
router.get('/intune-readiness', rbac.requireSuperAdmin, async (req, res) => {
  try { res.json(await readinessService.read()); }
  catch (e) { return serverErr(res, e, 'READINESS_FAIL'); }
});

router.post('/uploads/:id/activate', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!Number.isFinite(id) || id < 1) return badReq(res, 'Invalid upload id');
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query('SELECT id, parse_status FROM gpo_uploads WHERE id=?', [id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Upload not found' } });
      if (rows[0].parse_status !== 'ok') return badReq(res, 'Cannot activate a failed upload', 'NOT_PARSED');
      await conn.query('UPDATE gpo_uploads SET is_active=0 WHERE id<>?', [id]);
      await conn.query('UPDATE gpo_uploads SET is_active=1 WHERE id=?', [id]);
      res.json({ ok: true, data: { activated: id } });
    } finally { conn.release(); }
  } catch (e) { return serverErr(res, e); }
});

// ═══════════════════════════════════════════════════════════════════════
// DELETE /api/gpo/uploads/:id
// ═══════════════════════════════════════════════════════════════════════
router.delete('/uploads/:id', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!Number.isFinite(id) || id < 1) return badReq(res, 'Invalid upload id');
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query('SELECT id, is_active FROM gpo_uploads WHERE id=?', [id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Upload not found' } });
      if (rows[0].is_active) return badReq(res, 'Cannot delete the active upload. Activate a different one first.', 'IS_ACTIVE');
      await conn.beginTransaction();
      try {
        await conn.query('DELETE FROM gpo_settings WHERE upload_id=?', [id]);
        await conn.query('DELETE FROM gpo_findings WHERE upload_id=?', [id]);
        await conn.query('DELETE FROM gpo_links WHERE upload_id=?', [id]);
        await conn.query('DELETE FROM gpo_wmi_filters WHERE upload_id=?', [id]);
        await conn.query('DELETE FROM gpo_inventory WHERE upload_id=?', [id]);
        await conn.query('DELETE FROM gpo_uploads WHERE id=?', [id]);
        await conn.commit();
      } catch (e) {
        await conn.rollback();
        throw e;
      }
      res.json({ ok: true, data: { deleted: id } });
    } finally { conn.release(); }
  } catch (e) { return serverErr(res, e); }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /api/gpo/recommendations
// Returns { aggregate, perFinding, summary } for the active snapshot
// ═══════════════════════════════════════════════════════════════════════
router.get('/recommendations', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    try {
      const activeId = await getActiveUploadId(conn);
      if (!activeId) return res.json({ ok: true, data: null });

      // Pull findings + inventory for the active upload
      const [findings] = await conn.query('SELECT id, gpo_guid, severity, code, title, detail, related_guids, setting_key FROM gpo_findings WHERE upload_id=?', [activeId]);
      const [inv] = await conn.query('SELECT guid, name, wmi_filter_name FROM gpo_inventory WHERE upload_id=?', [activeId]);

      const inventoryByGuid = {};
      for (const row of inv) inventoryByGuid[row.guid] = row;

      // Phase 1 enrichment: pre-fetch only the settings referenced by findings.
      // Cheap IN-list query bounded by the distinct setting_keys actually emitted.
      const settingKeys = [...new Set(findings.map(f => f.setting_key).filter(Boolean))];
      const settingsByKey = {};
      if (settingKeys.length > 0) {
        const placeholders = settingKeys.map(() => '?').join(',');
        const [settingRows] = await conn.query(
          `SELECT s.gpo_guid, s.scope, s.setting_type, s.setting_key, s.setting_name, s.setting_state, s.setting_value, s.category_path,
                  i.name AS gpo_name
           FROM gpo_settings s
           LEFT JOIN gpo_inventory i ON i.upload_id=s.upload_id AND i.guid=s.gpo_guid
           WHERE s.upload_id=? AND s.setting_key IN (${placeholders})`,
          [activeId, ...settingKeys]
        );
        for (const row of settingRows) {
          if (!settingsByKey[row.setting_key]) settingsByKey[row.setting_key] = [];
          settingsByKey[row.setting_key].push(row);
        }
      }

      const data = buildRecommendations(findings, inventoryByGuid, settingsByKey);
      res.json({ ok: true, data, upload_id: activeId });
    } finally { conn.release(); }
  } catch (e) { return serverErr(res, e); }
});

// ── Multer error handling wrapper ─────────────────────────────────────
router.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return badReq(res, `Upload error: ${err.message}`, err.code);
  }
  if (err) return badReq(res, err.message || String(err), 'UPLOAD_REJECTED');
  next();
});

// ── Phase 2 v1: Apply routes ──────────────────────────────────────────
// Adds Apply path for UNLINKED + EMPTY recommendations only.
// Other applyable codes (set_status / clear_wmi / remove_link) ship in v2
// once this pipeline has been exercised on the boring cases.
const crypto = require('crypto');
const { execFile } = require('child_process');
const path_p2 = require('path');

// v1 whitelist — finding codes that the apply pipeline can run today.
// SETTING_*, STALE, ENFORCED_OVERRIDE etc. require human canonical-picking.
const APPLYABLE_CODES_V1 = new Set(['UNLINKED', 'EMPTY']);

// Action map: each whitelisted code maps to ONE concrete actionType.
const CODE_TO_ACTION = {
  UNLINKED: 'remove_gpo',
  EMPTY:    'remove_gpo'
};

const PREVIEW_TTL_SECONDS = 60;

// Lightweight auth gate. Mirrors what the rest of the api-beta surface does:
// presence of the it_auth cookie. P1-SEC backlog upgrades this to real SSO.
function requireAuth(req, res, next) {
  const cookieHeader = req.headers.cookie || '';
  if (!/(?:^|;\s*)it_auth=/i.test(cookieHeader)) {
    return res.status(401).json({ ok: false, error: { code: 'AUTH_REQUIRED', message: 'Authentication required' } });
  }
  // Capture actor for audit log; falls back to a hash of the cookie if no header.
  const explicit = req.header('x-user-email') || req.header('x-user') || '';
  if (explicit) {
    req.gpo_actor = explicit.slice(0, 255);
  } else {
    const m = /(?:^|;\s*)it_auth=([^;]+)/i.exec(cookieHeader);
    const tok = m ? m[1] : '';
    req.gpo_actor = 'it_auth:' + crypto.createHash('sha256').update(tok).digest('hex').slice(0, 12);
  }
  next();
}

// Build the exact PowerShell that gpo-actions.py will run, for display in the
// preview UI. Kept in lockstep with gpo-actions.py _build_remove_gpo_script.
// If you change the PS over there, change it here too — there's a smoke test
// that compares the two for drift.
function buildPreviewCommand(actionType, gpoName, backupPath) {
  const safeName = String(gpoName).replace(/'/g, "''");
  const safePath = String(backupPath || 'C:\\GPOBackups').replace(/'/g, "''");
  if (actionType === 'remove_gpo') {
    return [
      "$ErrorActionPreference = 'Stop'",
      'try {',
      `    if (-not (Test-Path -LiteralPath '${safePath}')) {`,
      `        New-Item -ItemType Directory -Path '${safePath}' -Force | Out-Null`,
      '    }',
      `    $backup = Backup-GPO -Name '${safeName}' -Path '${safePath}' -Comment "IT Command apply tool — pre-remove backup $(Get-Date -Format yyyy-MM-dd-HHmmss)"`,
      `    Remove-GPO -Name '${safeName}' -Confirm:$false`,
      "    @{ success = $true; backupId = $backup.Id.ToString() } | ConvertTo-Json -Compress",
      '} catch {',
      "    @{ success = $false; errorMessage = $_.Exception.Message } | ConvertTo-Json -Compress",
      '    exit 1',
      '}'
    ].join('\n');
  }
  throw new Error(`Unsupported actionType for preview: ${actionType}`);
}

// POST /apply/preview ────────────────────────────────────────────────
// Body: { finding_id }
// Response: { ok, preview_token, expires_at, action_type, gpo:{name,guid}, command_text }
router.post('/apply/preview', rbac.requireSuperAdmin, requireAuth, async (req, res) => {
  const findingId = Number(req.body && req.body.finding_id);
  if (!Number.isInteger(findingId) || findingId <= 0) {
    return badReq(res, 'finding_id (positive integer) required');
  }

  let conn;
  try {
    conn = await pool.getConnection();
    const activeId = await getActiveUploadId(conn);
    if (!activeId) return badReq(res, 'No active upload');

    // Finding must belong to the active upload (prevents stale-id attacks)
    const [rows] = await conn.query(
      'SELECT id, gpo_guid, code FROM gpo_findings WHERE id=? AND upload_id=?',
      [findingId, activeId]
    );
    if (!rows.length) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Finding not found in active upload' } });
    const finding = rows[0];

    if (!APPLYABLE_CODES_V1.has(finding.code)) {
      return res.status(400).json({
        ok: false,
        error: { code: 'NOT_APPLYABLE', message: `Apply not supported for ${finding.code} in v1. Use the manual commands shown in the recommendation.` }
      });
    }

    const [gpoRows] = await conn.query('SELECT guid, name FROM gpo_inventory WHERE upload_id=? AND guid=?', [activeId, finding.gpo_guid]);
    if (!gpoRows.length) return res.status(404).json({ ok: false, error: { code: 'GPO_NOT_FOUND', message: 'GPO inventory row missing' } });
    const gpo = gpoRows[0];

    const actionType = CODE_TO_ACTION[finding.code];
    const commandText = buildPreviewCommand(actionType, gpo.name, 'C:\\GPOBackups');
    const previewToken = crypto.randomUUID();
    const expiresAtMs = Date.now() + PREVIEW_TTL_SECONDS * 1000;

    await conn.query(
      `INSERT INTO gpo_apply_audit
       (upload_id, finding_id, finding_code, gpo_guid, gpo_name, action_type, command, preview_token, status, actor, started_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NOW())`,
      [activeId, findingId, finding.code, gpo.guid, (gpo.name || '').slice(0, 512), actionType, commandText, previewToken, req.gpo_actor]
    );

    // Best-effort: mark stale tokens for this actor as expired (housekeeping; no transactional dependence)
    await conn.query(
      `UPDATE gpo_apply_audit SET status='expired'
       WHERE status='pending' AND started_at < (NOW() - INTERVAL ? SECOND)`,
      [PREVIEW_TTL_SECONDS]
    );

    res.json({
      ok: true,
      preview_token: previewToken,
      action_type:   actionType,
      finding_code:  finding.code,
      gpo:           { name: gpo.name, guid: gpo.guid },
      command_text:  commandText,
      expires_at:    new Date(expiresAtMs).toISOString(),
      ttl_seconds:   PREVIEW_TTL_SECONDS
    });
  } catch (e) { return serverErr(res, e, 'PREVIEW_FAIL'); }
  finally { if (conn) conn.release(); }
});

// POST /apply/execute ────────────────────────────────────────────────
// Body: { preview_token, confirmation_text }
// confirmation_text MUST match the GPO name (case-insensitive, trimmed).
// Response: { ok, success, exit_code, stdout, stderr, error, errorCode, backupId, audit_id }
router.post('/apply/execute', rbac.requireSuperAdmin, requireAuth, async (req, res) => {
  const token = (req.body && req.body.preview_token || '').trim();
  const confirmation = (req.body && req.body.confirmation_text || '').trim();
  if (!token) return badReq(res, 'preview_token required');
  if (!confirmation) return badReq(res, 'confirmation_text required (must match GPO name)');

  const winrmUser = process.env.WINRM_USER;
  const winrmPass = process.env.WINRM_PASS;
  if (!winrmUser || !winrmPass) {
    return res.status(500).json({ ok: false, error: { code: 'CONFIG', message: 'WinRM credentials not configured on server' } });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    const [rows] = await conn.query(
      `SELECT id, finding_id, finding_code, gpo_guid, gpo_name, action_type, command, status,
              TIMESTAMPDIFF(SECOND, started_at, NOW()) AS age_seconds
       FROM gpo_apply_audit WHERE preview_token=? LIMIT 1`,
      [token]
    );
    if (!rows.length) {
      return res.status(404).json({ ok: false, error: { code: 'TOKEN_NOT_FOUND', message: 'Preview token not found' } });
    }
    const auditRow = rows[0];

    if (auditRow.status !== 'pending') {
      return res.status(409).json({ ok: false, error: { code: 'TOKEN_NOT_PENDING', message: `Token already ${auditRow.status}` } });
    }
    if (auditRow.age_seconds > PREVIEW_TTL_SECONDS) {
      await conn.query("UPDATE gpo_apply_audit SET status='expired' WHERE id=?", [auditRow.id]);
      return res.status(410).json({ ok: false, error: { code: 'TOKEN_EXPIRED', message: `Preview expired (>${PREVIEW_TTL_SECONDS}s old). Re-preview.` } });
    }

    if (confirmation.toLowerCase() !== (auditRow.gpo_name || '').toLowerCase()) {
      return res.status(400).json({ ok: false, error: { code: 'CONFIRMATION_MISMATCH', message: 'confirmation_text must match the GPO name exactly' } });
    }

    // Spawn gpo-actions.py — same pattern as ad-provisioning.js manage-groups.py
    const scriptPath = path_p2.join(__dirname, 'gpo-actions.py');
    const payload = JSON.stringify({
      actionType: auditRow.action_type,
      gpoName:    auditRow.gpo_name,
      gpoGuid:    auditRow.gpo_guid,
      backupPath: 'C:\\GPOBackups'
    });

    const helperResult = await new Promise((resolve) => {
      const child = execFile('python3', [scriptPath], {
        env: { ...process.env, WINRM_USER: winrmUser, WINRM_PASS: winrmPass },
        timeout: 90000,
        maxBuffer: 1024 * 512
      }, (err, stdout, stderr) => {
        // Don't reject — gpo-actions.py exits 1 on PS failure but stdout still has structured JSON we want
        let parsed = null;
        try { parsed = JSON.parse((stdout || '').trim()); } catch (_) {}
        resolve({
          parsed,
          rawStdout: stdout || '',
          rawStderr: stderr || '',
          spawnError: err && !parsed ? String(err.message || err) : null
        });
      });
      child.stdin.write(payload);
      child.stdin.end();
    });

    const success    = !!(helperResult.parsed && helperResult.parsed.success);
    const exitCode   = helperResult.parsed ? (helperResult.parsed.exitCode ?? null) : null;
    const errorMsg   = helperResult.parsed ? helperResult.parsed.error : (helperResult.spawnError || 'Helper produced no parseable output');
    const errorCode  = helperResult.parsed ? helperResult.parsed.errorCode : 'powershell_error';
    const helperStdout = helperResult.parsed ? helperResult.parsed.stdout : helperResult.rawStdout;
    const helperStderr = helperResult.parsed ? helperResult.parsed.stderr : helperResult.rawStderr;

    await conn.query(
      `UPDATE gpo_apply_audit
       SET status=?, exit_code=?, stdout=?, stderr=?, completed_at=NOW()
       WHERE id=?`,
      [success ? 'success' : 'failed', exitCode, helperStdout, helperStderr, auditRow.id]
    );

    res.json({
      ok:         true,                 // request itself succeeded — the action may have failed
      success,                          // did the GPO actually get removed?
      audit_id:   auditRow.id,
      exit_code:  exitCode,
      backupId:   helperResult.parsed ? helperResult.parsed.backupId : null,
      error:      success ? null : errorMsg,
      errorCode:  success ? null : errorCode,
      stdout:     helperStdout,
      stderr:     helperStderr
    });
  } catch (e) { return serverErr(res, e, 'EXECUTE_FAIL'); }
  finally { if (conn) conn.release(); }
});

// GET /apply/audit ──────────────────────────────────────────────────
// Query: ?limit=50&offset=0
router.get('/apply/audit', rbac.requireSuperAdmin, requireAuth, async (req, res) => {
  const limit  = Math.max(1, Math.min(200, Number(req.query.limit)  || 50));
  const offset = Math.max(0, Number(req.query.offset) || 0);
  let conn;
  try {
    conn = await pool.getConnection();
    const [rows] = await conn.query(
      `SELECT id, upload_id, finding_id, finding_code, gpo_guid, gpo_name, action_type,
              status, exit_code, actor, started_at, completed_at,
              SUBSTRING(stderr, 1, 400) AS stderr_preview
       FROM gpo_apply_audit
       ORDER BY started_at DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    const [[{ total }]] = await conn.query('SELECT COUNT(*) AS total FROM gpo_apply_audit');
    res.json({ ok: true, total, limit, offset, rows });
  } catch (e) { return serverErr(res, e, 'AUDIT_FAIL'); }
  finally { if (conn) conn.release(); }
});
// ── End Phase 2 v1: Apply routes ──────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════
// POST /api/gpo/refresh  — one-click "Update from AD"
// Runs Get-GPOReport -All -ReportType Xml on the DC over WinRM (read-only),
// then ingests the XML through the SAME parse + persist path as /upload.
// ═══════════════════════════════════════════════════════════════════════

// Shared ingest — mirrors the persist logic of POST /upload, but from an
// in-memory XML string instead of a multipart file. Returns { upload_id, ... }.
async function ingestXmlString(xmlString, meta) {
  const parsed = parseGpoReport(xmlString);
  if (!parsed.gpos.length) throw new Error('Parser produced zero GPOs from the AD report.');
  const findings = analyze(parsed);

  const conn = await pool.getConnection();
  let uploadId = null;
  try {
    await conn.beginTransaction();

    const [ins] = await conn.query(
      'INSERT INTO gpo_uploads (filename, file_size, gpo_count, finding_count, uploaded_by, parse_status, is_active) VALUES (?, ?, ?, ?, ?, ?, 0)',
      [meta.filename, meta.fileSize || Buffer.byteLength(xmlString, 'utf8'), parsed.gpos.length, findings.length, meta.uploadedBy || null, 'pending']
    );
    uploadId = ins.insertId;

    for (const g of parsed.gpos) {
      await conn.query(
        `INSERT INTO gpo_inventory
         (upload_id, guid, name, domain, created_time, modified_time,
          user_enabled, computer_enabled,
          user_version_dir, user_version_sysvol, comp_version_dir, comp_version_sysvol,
          wmi_filter_name, security_trustees,
          setting_count_user, setting_count_computer, link_count, has_settings)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [uploadId, g.guid, g.name.slice(0, 512), g.domain, g.created_time, g.modified_time,
         g.user_enabled ? 1 : 0, g.computer_enabled ? 1 : 0,
         g.user_version_dir, g.user_version_sysvol, g.comp_version_dir, g.comp_version_sysvol,
         g.wmi_filter_name ? g.wmi_filter_name.slice(0, 255) : null,
         g.security_trustees,
         g.setting_count_user, g.setting_count_computer, g.links.length, g.has_settings ? 1 : 0]
      );
    }

    for (const g of parsed.gpos) {
      for (const l of g.links) {
        await conn.query(
          'INSERT INTO gpo_links (upload_id, gpo_guid, som_name, som_path, link_enabled, enforced) VALUES (?,?,?,?,?,?)',
          [uploadId, g.guid, (l.som_name || '').slice(0, 512), (l.som_path || '').slice(0, 1024), l.link_enabled ? 1 : 0, l.enforced ? 1 : 0]
        );
      }
    }

    for (const w of parsed.wmiFilters) {
      await conn.query(
        'INSERT INTO gpo_wmi_filters (upload_id, filter_name, query, description, used_by_count) VALUES (?,?,?,?,?)',
        [uploadId, w.filter_name.slice(0, 255), w.query, w.description, w.used_by_count]
      );
    }

    const SETTING_BATCH = 500;
    const allSettings = [];
    for (const g of parsed.gpos) {
      for (const s of g.settings) {
        allSettings.push([uploadId, g.guid, s.scope, s.setting_type,
          (s.setting_key || '').slice(0, 512),
          s.setting_name ? s.setting_name.slice(0, 512) : null,
          s.setting_state ? s.setting_state.slice(0, 64) : null,
          s.setting_value || null,
          s.category_path ? s.category_path.slice(0, 1024) : null]);
      }
    }
    for (let i = 0; i < allSettings.length; i += SETTING_BATCH) {
      const chunk = allSettings.slice(i, i + SETTING_BATCH);
      if (!chunk.length) continue;
      await conn.query(
        `INSERT INTO gpo_settings (upload_id, gpo_guid, scope, setting_type, setting_key, setting_name, setting_state, setting_value, category_path) VALUES ${chunk.map(() => '(?,?,?,?,?,?,?,?,?)').join(',')}`,
        chunk.flat()
      );
    }

    for (const f of findings) {
      await conn.query(
        'INSERT INTO gpo_findings (upload_id, gpo_guid, severity, code, title, detail, related_guids, setting_key) VALUES (?,?,?,?,?,?,?,?)',
        [uploadId, f.gpo_guid, f.severity, f.code, f.title.slice(0, 255), f.detail, f.related_guids, f.setting_key || null]
      );
    }

    await conn.query('UPDATE gpo_uploads SET is_active=0 WHERE id<>?', [uploadId]);
    await conn.query('UPDATE gpo_uploads SET is_active=1, parse_status=? WHERE id=?', ['ok', uploadId]);
    await conn.commit();

    return {
      upload_id: uploadId,
      gpo_count: parsed.gpos.length,
      finding_count: findings.length,
      wmi_filter_count: parsed.wmiFilters.length,
      warnings: parsed.warnings || []
    };
  } catch (e) {
    try { await conn.rollback(); } catch (_) { /* ignore */ }
    if (uploadId !== null) {
      try { await conn.query('UPDATE gpo_uploads SET parse_status=?, parse_error=? WHERE id=?', ['error', String(e.message || e).slice(0, 1024), uploadId]); } catch (_) { /* ignore */ }
    }
    throw e;
  } finally {
    conn.release();
  }
}

router.post('/refresh', rbac.requireSuperAdmin, requireAuth, async (req, res) => {
  const winrmUser = process.env.WINRM_USER;
  const winrmPass = process.env.WINRM_PASS;
  if (!winrmUser || !winrmPass) {
    return res.status(500).json({ ok: false, error: { code: 'CONFIG', message: 'WinRM credentials not configured on server' } });
  }
  const uploadedBy = (req.user && req.user.email) || req.gpo_actor || null;   // session identity only; never the body

  try {
    // 1) Pull the report XML from the DC over WinRM (read-only)
    const scriptPath = path_p2.join(__dirname, 'gpo-report.py');
    const helper = await new Promise((resolve) => {
      const child = execFile('python3', [scriptPath], {
        env: { ...process.env, WINRM_USER: winrmUser, WINRM_PASS: winrmPass },
        timeout: 180000,               // 3 min — large estates take a while
        maxBuffer: 96 * 1024 * 1024    // Get-GPOReport -All can be many MB
      }, (err, stdout, stderr) => resolve({ err, stdout: stdout || '', stderr: stderr || '' }));
    });

    const out = (helper.stdout || '').replace(/^﻿/, '').replace(/^\s+/, '');

    // Helper emits raw XML on success; JSON {error,errorCode} on failure.
    if (!out.startsWith('<')) {
      let msg = 'Get-GPOReport did not return a report';
      let code = 'winrm_error';
      try {
        const j = JSON.parse(out || helper.stderr || '{}');
        if (j.error) msg = j.error;
        if (j.errorCode) code = j.errorCode;
      } catch (_) {
        msg = (helper.stderr || out || msg).toString().slice(0, 800);
        if (helper.err && helper.err.killed) { code = 'timeout'; msg = 'WinRM report timed out (estate too large or DC slow)'; }
      }
      return res.status(502).json({ ok: false, error: { code, message: msg } });
    }

    // 2) Ingest via the shared persist path (creates + activates a snapshot)
    const stamp = new Date().toISOString().slice(0, 19).replace('T', '-').replace(/:/g, '');
    const data = await ingestXmlString(out, {
      filename: `ad-pull-${stamp}.xml`,
      fileSize: Buffer.byteLength(out, 'utf8'),
      uploadedBy
    });

    res.json({ ok: true, data });
  } catch (e) {
    return serverErr(res, e, 'REFRESH_FAIL');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// Intune conversion — Step 1: Analyze via Microsoft Group Policy analytics
// Uses the existing AZURE_* app (client-credentials, .default). Needs the
// DeviceManagementConfiguration.ReadWrite.All application permission consented.
// ═══════════════════════════════════════════════════════════════════════
const https = require('https');

function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const r = https.request(options, (resp) => {
      let data = '';
      resp.on('data', (c) => { data += c; });
      resp.on('end', () => resolve({ status: resp.statusCode, body: data }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

async function getGraphToken() {
  const form = new URLSearchParams({
    client_id: process.env.AZURE_CLIENT_ID,
    client_secret: process.env.AZURE_CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials'
  }).toString();
  const { status, body } = await httpsRequest({
    method: 'POST',
    host: 'login.microsoftonline.com',
    path: `/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/token`,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(form) }
  }, form);
  let j = {};
  try { j = JSON.parse(body || '{}'); } catch (_) {}
  if (status < 200 || status >= 300 || !j.access_token) {
    throw new Error('Graph token failed: ' + (j.error_description || j.error || ('HTTP ' + status)));
  }
  return j.access_token;
}

async function graphCall(method, apiPath, token, jsonBody) {
  const payload = jsonBody ? JSON.stringify(jsonBody) : null;
  const headers = { Authorization: 'Bearer ' + token };
  if (payload) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(payload); }
  const { status, body } = await httpsRequest({ method, host: 'graph.microsoft.com', path: apiPath, headers }, payload);
  let json = null;
  try { json = body ? JSON.parse(body) : null; } catch (_) {}
  return { status, json, raw: body };
}

// POST /api/gpo/intune/analyze  { guid }
// Pulls that GPO's XML from the DC, submits it to Microsoft Group Policy
// analytics (createMigrationReport), returns the supported/unsupported settings.
router.post('/intune/analyze', rbac.requireSuperAdmin, requireAuth, async (req, res) => {
  const guid = (req.body && req.body.guid || '').toLowerCase().replace(/[{}]/g, '');
  if (!/^[a-f0-9-]{32,40}$/.test(guid)) return badReq(res, 'Invalid GUID');

  const winrmUser = process.env.WINRM_USER;
  const winrmPass = process.env.WINRM_PASS;
  if (!winrmUser || !winrmPass) return res.status(500).json({ ok: false, error: { code: 'CONFIG', message: 'WinRM credentials not configured' } });
  if (!process.env.AZURE_CLIENT_ID || !process.env.AZURE_CLIENT_SECRET || !process.env.AZURE_TENANT_ID) {
    return res.status(500).json({ ok: false, error: { code: 'CONFIG', message: 'AZURE_* Graph credentials not configured' } });
  }

  let conn;
  try {
    // GPO name/domain for display + the OU DN the migration report wants
    conn = await pool.getConnection();
    const activeId = await getActiveUploadId(conn);
    const [rows] = await conn.query('SELECT name, domain FROM gpo_inventory WHERE upload_id=? AND guid=?', [activeId, guid]);
    const gpoName = rows.length ? rows[0].name : guid;
    const domain = rows.length ? rows[0].domain : null;
    conn.release(); conn = null;

    // 1) single-GPO XML via WinRM
    const scriptPath = path_p2.join(__dirname, 'gpo-report.py');
    const helper = await new Promise((resolve) => {
      execFile('python3', [scriptPath], {
        env: { ...process.env, WINRM_USER: winrmUser, WINRM_PASS: winrmPass, GPO_GUID: guid },
        timeout: 120000, maxBuffer: 32 * 1024 * 1024
      }, (err, stdout, stderr) => resolve({ err, stdout: stdout || '', stderr: stderr || '' }));
    });
    const xml = (helper.stdout || '').replace(/^﻿/, '').replace(/^\s+/, '');
    if (!xml.startsWith('<')) {
      let msg = 'Get-GPOReport (single GPO) failed', code = 'winrm_error';
      try { const j = JSON.parse(xml || helper.stderr || '{}'); if (j.error) msg = j.error; if (j.errorCode) code = j.errorCode; }
      catch (_) { msg = (helper.stderr || msg).toString().slice(0, 600); }
      return res.status(502).json({ ok: false, error: { code, message: msg } });
    }

    // 2) Graph token
    const token = await getGraphToken();

    // 3) createMigrationReport (Microsoft analyzes MDM support)
    const dn = domain
      ? 'OU=GPO,' + domain.split('.').map(p => 'DC=' + p).join(',')
      : 'OU=GPO,DC=domain';
    // Strip control chars that are illegal in XML 1.0 (some GPO reports embed a
    // raw 0x07 BEL etc. in setting values) — Microsoft's parser rejects them.
    // Keep tab (09), LF (0A), CR (0D).
    const cleanXml = xml.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
    // Microsoft decodes the content bytes as UTF-16 LE (== PowerShell's
    // [Text.Encoding]::Unicode.GetBytes) with NO BOM.
    const contentB64 = Buffer.from(cleanXml, 'utf16le').toString('base64');
    const create = await graphCall('POST', '/beta/deviceManagement/groupPolicyMigrationReports/createMigrationReport', token,
      { groupPolicyObjectFile: { ouDistinguishedName: dn, content: contentB64 } });
    if (create.status < 200 || create.status >= 300) {
      const gm = create.json && create.json.error && create.json.error.message;
      return res.status(502).json({ ok: false, error: { code: 'GRAPH', message: 'createMigrationReport failed: ' + (gm || ('HTTP ' + create.status)), detail: (create.raw || '').slice(0, 800) } });
    }
    const reportId = create.json && (create.json.id || create.json.value);
    if (!reportId) return res.status(502).json({ ok: false, error: { code: 'GRAPH', message: 'No migration report id returned', detail: (create.raw || '').slice(0, 800) } });

    // 4) poll for the expanded setting mappings
    let report = null, mappings = [];
    for (let i = 0; i < 8; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      const g = await graphCall('GET', `/beta/deviceManagement/groupPolicyMigrationReports/${encodeURIComponent(reportId)}?$expand=groupPolicySettingMappings`, token);
      if (g.status >= 200 && g.status < 300 && g.json) {
        report = g.json;
        mappings = g.json.groupPolicySettingMappings || [];
        if (mappings.length || report.totalSettingsCount != null) break;
      }
    }

    // Normalize defensively — beta field names vary
    const norm = (mappings || []).map((m) => {
      const status = m.mdmSupportState || m.settingMappingStatus || (m.isMdmSupported ? 'supported' : 'unsupported');
      return {
        name: m.settingName || m.adminTemplateSettingName || m.parentId || '(setting)',
        category: m.settingCategory || m.parentSettingCategory || '',
        supported: (m.isMdmSupported === true) || /^supported$/i.test(String(status)),
        status: String(status),
        csp: m.mdmCSPName || ''
      };
    });
    const supported = norm.filter((x) => x.supported).length;

    res.json({
      ok: true,
      data: {
        gpo: { guid, name: gpoName },
        reportId,
        total: report && report.totalSettingsCount != null ? report.totalSettingsCount : norm.length,
        supported: report && report.supportedSettingsCount != null ? report.supportedSettingsCount : supported,
        percent: report && report.supportedSettingsPercent != null ? report.supportedSettingsPercent : (norm.length ? Math.round(100 * supported / norm.length) : 0),
        mappings: norm
      }
    });
  } catch (e) {
    if (conn) conn.release();
    return serverErr(res, e, 'INTUNE_ANALYZE_FAIL');
  }
});

module.exports = router;
