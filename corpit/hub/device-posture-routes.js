// device-posture-routes.js — device security posture for the helpdesk landing
// page KPIs and the Asset Inventory app.
// Mount point: /api/device-posture  (beta API, port 3001)
//
//   GET /encryption  — Macs without FileVault + Windows without BitLocker
//   GET /patches     — missing patches by severity (ManageEngine Endpoint Central)
//
// Sources, and why each:
//   macbooks.filevault_enabled          — Kandji /devices/{id}/details, daily 04:00
//   sentinel_intune_device.is_encrypted — collect-intune.js, every 30 min. Preferred
//                                         over it_inventory.intune_devices.is_encrypted
//                                         because that one only refreshes when someone
//                                         runs the Intune Graph sync by hand.
//   me_missing_patch                    — collect-missing-patches.js, daily 03:40
//
// NOTE: `macbooks` MUST stay schema-qualified. This router's pool is on
// corpit_hub, which holds a stale 86-row copy of the same table name.
'use strict';
const express = require('express');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const router = express.Router();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});

const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

const PAGE_KEY = 'it-inventory';

// GET /api/device-posture/encryption
// Only Macs and Windows are counted: iOS and Android are encrypted at rest by
// the platform and would otherwise pad the number with devices nobody can act on.
router.get('/encryption', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [[mac]] = await pool.query(
      `SELECT COUNT(*)                                      AS total,
              SUM(filevault_enabled = 0)                    AS unencrypted,
              SUM(filevault_enabled IS NULL)                AS unknown,
              SUM(filevault_enabled = 1
                  AND filevault_prk_escrowed = 0)           AS noRecoveryKey,
              MAX(details_synced_at)                        AS collectedAt
         FROM it_inventory.macbooks`);
    const [[win]] = await pool.query(
      `SELECT COUNT(*)                     AS total,
              SUM(is_encrypted = 0)        AS unencrypted,
              SUM(is_encrypted IS NULL)    AS unknown,
              MAX(collected_at)            AS collectedAt
         FROM sentinel_intune_device
        WHERE os = 'Windows'`);
    const [macList] = await pool.query(
      `SELECT device_name AS deviceName, user_name AS user, model, os_version AS osVersion,
              checked_in AS lastCheckIn
         FROM it_inventory.macbooks
        WHERE filevault_enabled = 0
        ORDER BY user_name LIMIT 100`);
    const [winList] = await pool.query(
      `SELECT device_name AS deviceName, upn AS user, os_version AS osVersion,
              last_sync_dt AS lastCheckIn
         FROM sentinel_intune_device
        WHERE os = 'Windows' AND is_encrypted = 0
        ORDER BY upn LIMIT 100`);

    const n = (v) => Number(v || 0);
    res.json({
      mac: { total: n(mac.total), unencrypted: n(mac.unencrypted), unknown: n(mac.unknown),
             noRecoveryKey: n(mac.noRecoveryKey), collectedAt: mac.collectedAt || null },
      windows: { total: n(win.total), unencrypted: n(win.unencrypted), unknown: n(win.unknown),
                 collectedAt: win.collectedAt || null },
      unencryptedTotal: n(mac.unencrypted) + n(win.unencrypted),
      devices: { mac: macList, windows: winList },
    });
  } catch (err) {
    console.error('[device-posture/encryption]', err.message);
    res.status(500).json({ error: 'encryption query failed' });
  }
});

// GET /api/device-posture/patches
// `missing_count` is machines-still-missing-this-patch, so instances >> patches.
// The KPI uses `criticalPatches` (distinct Critical+Important patches outstanding)
// because that is the size of the remediation queue, not the blast radius.
router.get('/patches', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [bySeverity] = await pool.query(
      `SELECT severity_name AS severity, COUNT(*) AS patches,
              COALESCE(SUM(missing_count),0) AS instances
         FROM me_missing_patch
        WHERE missing_count > 0
        GROUP BY severity_name`);
    const [[crit]] = await pool.query(
      `SELECT COUNT(*) AS patches, COALESCE(SUM(missing_count),0) AS instances
         FROM me_missing_patch
        WHERE missing_count > 0 AND severity_name IN ('Critical','Important')`);
    const [[all]] = await pool.query(
      `SELECT COUNT(*) AS patches, COALESCE(SUM(missing_count),0) AS instances,
              MAX(collected_at) AS collectedAt
         FROM me_missing_patch WHERE missing_count > 0`);
    const [top] = await pool.query(
      `SELECT patch_id AS patchId, bulletin_id AS bulletinId, patch_name AS patchName,
              patch_description AS description, vendor_name AS vendor,
              severity_name AS severity, platform_name AS platform,
              missing_count AS missing, failed_count AS failed,
              reboot_required AS rebootRequired, released_dt AS releasedAt
         FROM me_missing_patch
        WHERE missing_count > 0
        ORDER BY FIELD(severity_name,'Critical','Important','Moderate','Low','Unrated'),
                 missing_count DESC
        LIMIT 50`);

    res.json({
      criticalPatches:   Number(crit.patches || 0),
      criticalInstances: Number(crit.instances || 0),
      totalPatches:      Number(all.patches || 0),
      totalInstances:    Number(all.instances || 0),
      bySeverity: bySeverity.reduce((a, r) => (a[r.severity || 'Unrated'] =
        { patches: Number(r.patches), instances: Number(r.instances) }, a), {}),
      top,
      collectedAt: all.collectedAt || null,
    });
  } catch (err) {
    console.error('[device-posture/patches]', err.message);
    res.status(500).json({ error: 'patches query failed' });
  }
});

module.exports = router;
