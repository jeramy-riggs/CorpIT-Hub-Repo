'use strict';
/**
 * abm-routes.js
 * Express router — mounts Apple Business Manager endpoints at /api/abm/
 *
 * GET  /api/abm/health              — sync status, table counts
 * GET  /api/abm/devices             — list devices (filters: serial, family, status, mdm)
 * GET  /api/abm/devices/:serial     — single device with all warranty records
 * GET  /api/abm/mdm-servers         — list MDM servers with device counts
 * GET  /api/abm/reconciliation      — devices in ABM not found in Kandji or Intune
 * POST /api/abm/sync                — trigger manual full sync
 *
 * Authorization: gated on the 'it-inventory' page key -- reads at 'read',
 * the manual sync at 'admin'. The ITAM original carried the note "No
 * app-level auth (matches the convention of other api-beta routers)", so
 * every route here served the full Apple Business Manager inventory --
 * serial numbers, models, MDM assignment, reconciliation gaps -- to any
 * authenticated identity, including the 10 role-holders whose roles carry
 * default_access='none'. IT_Inventory_App.js is the only caller and its
 * users reach it-inventory through the same default_access ladder the rest
 * of that page already uses, so gating changes nothing for them.
 */

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { fullSync } = require('./apple-business-mgr');
const createRbac = require('./rbac-middleware');

const db = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
});

// Reuses the pool above rather than opening a second one to the same schema.
const rbac = createRbac(db);
router.use(rbac.loadCurrentUser);
const abmRead  = rbac.requirePage('it-inventory', 'read');
const abmAdmin = rbac.requirePage('it-inventory', 'admin');
// /api/abm/sync is in server.js's API_CRON set, so a valid x-cron-token caller
// reaches this router with no user session and abmAdmin alone would 403 it.
const abmAdminOrCron = (req, res, next) =>
  req.cronAuthorized ? next() : abmAdmin(req, res, next);

// Sync state — tracks last run + whether one is in flight (prevents overlap)
let syncInProgress = false;
let lastSyncResult = null;
let lastSyncStartedAt = null;

// ── Health ────────────────────────────────────────────────────────────────────
router.get('/health', abmRead, async (req, res) => {
  try {
    const [[devices]]  = await db.query(`SELECT COUNT(*) AS total, SUM(is_active=1) AS active FROM abm_devices`);
    const [[warranty]] = await db.query(`SELECT COUNT(*) AS total, SUM(is_active=1 AND status='ACTIVE') AS active FROM abm_warranty`);
    const [[servers]]  = await db.query(`SELECT COUNT(*) AS total, SUM(is_active=1) AS active FROM abm_mdm_servers`);
    const [[lastSync]] = await db.query(`SELECT MAX(last_synced_at) AS last_synced FROM abm_devices WHERE is_active=1`);
    res.json({
      status: 'ok',
      devices: { total: devices.total, active: devices.active },
      warranty_coverages: { total: warranty.total, active: warranty.active },
      mdm_servers: { total: servers.total, active: servers.active },
      last_device_sync: lastSync.last_synced,
      sync_in_progress: syncInProgress,
      last_sync_started_at: lastSyncStartedAt,
    });
  } catch (e) {
    res.status(500).json({ status: 'error', error: e.message });
  }
});

// ── Devices list ──────────────────────────────────────────────────────────────
router.get('/devices', abmRead, async (req, res) => {
  try {
    const where = ['d.is_active = 1'];
    const params = [];
    if (req.query.serial)  { where.push('d.serial_number = ?'); params.push(req.query.serial); }
    if (req.query.family)  { where.push('d.product_family = ?'); params.push(req.query.family); }
    if (req.query.status)  { where.push('d.status = ?'); params.push(req.query.status); }
    if (req.query.mdm)     { where.push('s.server_name = ?'); params.push(req.query.mdm); }
    const limit  = Math.min(parseInt(req.query.limit  || '500', 10), 5000);
    const offset =          parseInt(req.query.offset || '0',   10);
    const sql = `
      SELECT
        d.serial_number, d.device_model, d.product_family, d.product_type,
        d.color, d.status, d.order_date_time, d.added_to_org_date_time,
        d.imei_primary, d.eid,
        d.assigned_server_id, s.server_name AS mdm_server_name, s.server_type AS mdm_server_type,
        (SELECT COUNT(*) FROM abm_warranty w WHERE w.serial_number = d.serial_number AND w.is_active=1 AND w.status='ACTIVE') AS active_coverages,
        (SELECT MAX(end_date_time) FROM abm_warranty w WHERE w.serial_number = d.serial_number AND w.is_active=1 AND w.status='ACTIVE') AS coverage_ends
      FROM abm_devices d
      LEFT JOIN abm_mdm_servers s ON s.server_id = d.assigned_server_id
      WHERE ${where.join(' AND ')}
      ORDER BY d.serial_number
      LIMIT ? OFFSET ?
    `;
    params.push(limit, offset);
    const [rows] = await db.query(sql, params);
    res.json({ count: rows.length, limit, offset, devices: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Single device ─────────────────────────────────────────────────────────────
router.get('/devices/:serial', abmRead, async (req, res) => {
  try {
    const serial = req.params.serial;
    const [[device]] = await db.query(`
      SELECT d.*, s.server_name AS mdm_server_name, s.server_type AS mdm_server_type
      FROM abm_devices d
      LEFT JOIN abm_mdm_servers s ON s.server_id = d.assigned_server_id
      WHERE d.serial_number = ?
    `, [serial]);
    if (!device) return res.status(404).json({ error: 'Not found in ABM' });
    const [warranty] = await db.query(`
      SELECT * FROM abm_warranty
      WHERE serial_number = ? AND is_active = 1
      ORDER BY end_date_time DESC
    `, [serial]);
    res.json({ device, warranty });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── MDM servers ───────────────────────────────────────────────────────────────
router.get('/mdm-servers', abmRead, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT s.server_id, s.server_name, s.server_type,
             s.created_date_time, s.updated_date_time, s.is_active,
             (SELECT COUNT(*) FROM abm_devices d WHERE d.assigned_server_id = s.server_id AND d.is_active=1) AS device_count
      FROM abm_mdm_servers s
      ORDER BY device_count DESC, s.server_name
    `);
    res.json({ count: rows.length, servers: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Reconciliation: ABM devices not managed by Kandji or Intune ───────────────
// Managed = serial appears in any of:
//   corpit_hub.macbooks.serial         (Kandji Macs)
//   corpit_hub.intune_devices.serial_number  (Intune iPhones + 1 iPad)
//   it_inventory.ipad_devices.serial          (Kandji iPads — different DB)
router.get('/reconciliation', abmRead, async (req, res) => {
  try {
    const sql = `
      SELECT
        d.serial_number, d.device_model, d.product_family, d.color,
        d.status AS abm_status, d.order_date_time, d.added_to_org_date_time,
        s.server_name AS abm_assigned_server,
        CASE
          WHEN m.serial IS NOT NULL THEN 'kandji-mac'
          WHEN i.serial_number IS NOT NULL THEN 'intune'
          WHEN k.serial IS NOT NULL THEN 'kandji-ipad'
          ELSE 'UNMANAGED'
        END AS managed_in
      FROM abm_devices d
      LEFT JOIN abm_mdm_servers s ON s.server_id = d.assigned_server_id
      LEFT JOIN macbooks m ON m.serial COLLATE utf8mb4_unicode_ci = d.serial_number
      LEFT JOIN it_inventory.intune_devices i ON i.serial_number COLLATE utf8mb4_unicode_ci = d.serial_number
      LEFT JOIN it_inventory.ipad_devices k ON k.serial COLLATE utf8mb4_unicode_ci = d.serial_number
      WHERE d.is_active = 1
        AND m.serial IS NULL
        AND i.serial_number IS NULL
        AND k.serial IS NULL
      ORDER BY d.product_family, d.serial_number
    `;
    const [rows] = await db.query(sql);
    res.json({
      count: rows.length,
      description: 'Devices in ABM but not found in Kandji (macbooks/ipad_devices) or Intune (intune_devices)',
      devices: rows,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Manual sync trigger ───────────────────────────────────────────────────────
router.post('/sync', abmAdminOrCron, async (req, res) => {
  if (syncInProgress) {
    return res.status(409).json({
      error: 'Sync already in progress',
      started_at: lastSyncStartedAt,
    });
  }
  syncInProgress = true;
  lastSyncStartedAt = new Date().toISOString();
  // Respond immediately; sync runs in background
  res.json({
    status: 'started',
    started_at: lastSyncStartedAt,
    note: 'Sync runs in background. Poll /api/abm/health for completion.',
  });
  // Fire-and-forget background sync
  fullSync({ verbose: false })
    .then((result) => {
      lastSyncResult = { ok: true, finished_at: new Date().toISOString(), result };
    })
    .catch((err) => {
      lastSyncResult = { ok: false, finished_at: new Date().toISOString(), error: err.message };
    })
    .finally(() => {
      syncInProgress = false;
    });
});

// ── Last sync result (companion to POST /sync) ────────────────────────────────
router.get('/sync/last', abmRead, (req, res) => {
  res.json({
    in_progress: syncInProgress,
    started_at: lastSyncStartedAt,
    last_result: lastSyncResult,
  });
});

module.exports = router;
