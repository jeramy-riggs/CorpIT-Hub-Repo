const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');

const pool = mysql.createPool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT) || 3306,
  database: 'it_inventory',
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  connectionLimit: 5,
  charset: 'utf8mb4',
});

// ── RBAC (2026-09-07) ────────────────────────────────────────
// These routes serve the IT Asset Console (IT_Inventory_App), so they gate on
// the same page key as the rest of that console. Until now this file carried no
// gate at all: server.js's blanket /api guard authenticates, but any signed-in
// identity -- including the reporting, outsideit and infosec roles, which
// resolve to NO access on it-inventory -- could read the full device cache.
// A SEPARATE pool is required here: rbac-middleware queries rbac_* unqualified
// and the pool above is on the it_inventory schema, not DB_NAME.
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
const needRead  = rbac.requirePage('it-inventory', 'read');
const needAdmin = rbac.requirePage('it-inventory', 'admin');
// The sync POSTs are in server.js's API_CRON set. A caller presenting a valid
// x-cron-token is authorized by the blanket and arrives here with NO user
// session, so a bare needAdmin would 403 a legitimate cron. Nothing schedules
// these today; gating without this branch would arm that failure for whoever
// does, and it would read as a bad token rather than a bad gate.
const needAdminOrCron = (req, res, next) =>
  req.cronAuthorized ? next() : needAdmin(req, res, next);

// ── Token cache ──────────────────────────────────────────────
let _token    = null;
let _tokenExp = 0;

async function getGraphToken() {
  if (_token && Date.now() < _tokenExp - 60_000) return _token;
  const url  = `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id:     process.env.AZURE_CLIENT_ID,
    client_secret: process.env.AZURE_CLIENT_SECRET,
    scope:         'https://graph.microsoft.com/.default',
    grant_type:    'client_credentials',
  });
  const res  = await fetch(url, { method: 'POST', body });
  const data = await res.json();
  if (!data.access_token) throw new Error('Graph token failed: ' + JSON.stringify(data));
  _token    = data.access_token;
  _tokenExp = Date.now() + (data.expires_in * 1000);
  return _token;
}

async function graphGet(url) {
  const token = await getGraphToken();
  const res   = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`Graph API ${res.status}: ${url}`);
  return res.json();
}

// ── Schema ───────────────────────────────────────────────────
// intune_graph_cache and intune_devices are created and altered by migrate.js at
// deploy time (schema/migrations.js), never by this module (CHG-ARCH-18). A table
// that does not satisfy schema/contract.js makes these routes answer 503.
const needSchema = require('./schema/readiness').requireSchema('intune');

// ── GET /api/intune-graph/map — serial+name keyed lookup ────
router.get('/map', needRead, needSchema, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM intune_graph_cache');
    const map = {};
    rows.forEach(r => {
      if (r.serial_number) map[r.serial_number.toLowerCase().trim()] = r;
      if (r.computer_name) map['name:' + r.computer_name.toLowerCase().trim()] = r;
    });
    res.json(map);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/intune-graph/status ─────────────────────────────
router.get('/status', needRead, needSchema, async (req, res) => {
  try {
    const [[row]] = await pool.query(
      'SELECT MAX(last_synced) as last_synced, COUNT(*) as total FROM intune_graph_cache'
    );
    res.json(row);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/intune-graph/sync — fetch all from Graph ──────
router.post('/sync', needAdminOrCron, needSchema, async (req, res) => {
  let syncStartTime = null;
  try {
    // Marker comes from MySQL, not `new Date()`: last_synced is datetime(0) so a
    // JS Date's milliseconds make every row written during the marker's own
    // second sort as older than it, and the prune below deletes rows this sync
    // just wrote. (Fixed 2026-08-15.)
    const [[mark]] = await pool.query('SELECT NOW() AS n');
    syncStartTime = mark.n;
    let url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,serialNumber,deviceName,osVersion,complianceState,enrolledDateTime,lastSyncDateTime,userPrincipalName,model,manufacturer,imei,phoneNumber,operatingSystem,isEncrypted&$top=999';
    let allDevices = [];

    // Paginate through all results
    while (url) {
      const data = await graphGet(url);
      allDevices = allDevices.concat(data.value || []);
      url = data['@odata.nextLink'] || null;
    }

    let synced = 0, errors = 0;
    for (const d of allDevices) {
      try {
        await pool.query(`
          INSERT INTO intune_graph_cache
            (device_id, serial_number, computer_name, display_name, os_version,
             compliance, enrolled_date, last_sync, user_upn, model, manufacturer, imei, phone_number, operating_system,
             is_encrypted)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            serial_number=VALUES(serial_number), computer_name=VALUES(computer_name),
            display_name=VALUES(display_name), os_version=VALUES(os_version),
            compliance=VALUES(compliance), enrolled_date=VALUES(enrolled_date),
            last_sync=VALUES(last_sync), user_upn=VALUES(user_upn),
            model=VALUES(model), manufacturer=VALUES(manufacturer),
            imei=VALUES(imei), phone_number=VALUES(phone_number), operating_system=VALUES(operating_system),
            is_encrypted=VALUES(is_encrypted), last_synced=NOW()
        `, [
          d.id,
          d.serialNumber || null,
          d.deviceName   || null,
          d.displayName  || d.deviceName || null,
          d.osVersion    || null,
          d.complianceState || null,
          d.enrolledDateTime || null,
          d.lastSyncDateTime || null,
          d.userPrincipalName || null,
          d.model        || null,
          d.manufacturer || null,
          d.imei         || null,
          d.phoneNumber  || null,
          d.operatingSystem || null,
          d.isEncrypted == null ? null : (d.isEncrypted ? 1 : 0),
        ]);
        synced++;
      } catch(e) { errors++; }
    }

    // Prune cache rows not touched in this sync (devices removed from Intune since last run)
    let pruned = 0;
    if (synced > 0 && allDevices.length > 0) {
      const [r] = await pool.query(
        'DELETE FROM intune_graph_cache WHERE last_synced < ?',
        [syncStartTime]
      );
      pruned = r.affectedRows;
    }

    res.json({ success: true, total: allDevices.length, synced, errors, pruned });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// ── POST /api/intune-graph/sync-to-devices — populate intune_devices from graph cache ──
router.post('/sync-to-devices', needAdminOrCron, needSchema, async (req, res) => {
  try {
    const [cacheRows] = await pool.query('SELECT * FROM intune_graph_cache');
    if (!cacheRows.length) {
      return res.json({ success: false, error: 'Graph cache is empty — run Intune Graph sync first' });
    }

    function deriveOS(model, manufacturer, operatingSystem) {
      if (operatingSystem) {
        const os = operatingSystem.toLowerCase();
        if (os === 'windows') return 'Windows';
        if (os === 'ios' || os === 'ipados') return 'iOS/iPadOS';
        if (os.includes('android')) return 'Android (Fully Managed)';
        return operatingSystem;
      }
      const m = (model || '').toLowerCase();
      const mfr = (manufacturer || '').toLowerCase();
      if (mfr === 'apple') return 'iOS/iPadOS';
      return 'Android (Fully Managed)';
    }

    function deriveCategory(model, manufacturer, operatingSystem) {
      const m = (model || '').toLowerCase();
      const mfr = (manufacturer || '').toLowerCase();
      const os = (operatingSystem || '').toLowerCase();
      if (mfr === 'apple' && m.includes('ipad')) return 'ipad';
      if (mfr === 'apple' && m.includes('iphone')) return 'iphone';
      if (mfr === 'apple') return 'iphone';
      if (os === 'windows') return 'windows';
      if (m.includes('tab') || m.includes('sm-t') || m.includes('sm-x')) return 'tablet';
      if (os.includes('android')) return 'mobile';
      return 'mobile';
    }

    // The ON DUPLICATE KEY upsert below needs UNIQUE(device_id); migrate.js step
    // inv-0005 guarantees it and needSchema refuses to run without it.

    let synced = 0, errors = 0;
    for (const d of cacheRows) {
      try {
        const os       = deriveOS(d.model, d.manufacturer, d.operating_system);
        const category = deriveCategory(d.model, d.manufacturer, d.operating_system);
        await pool.query(`
          INSERT INTO intune_devices
            (device_id, device_name, serial_number, imei, phone_number, os, os_version,
             compliance, primary_user_upn, primary_user_name, last_checkin,
             model, device_source, device_category, is_historical, is_encrypted)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'intune_graph', ?, 0, ?)
          ON DUPLICATE KEY UPDATE
            device_name=VALUES(device_name),
            serial_number=VALUES(serial_number),
            imei=VALUES(imei),
            phone_number=VALUES(phone_number),
            os=VALUES(os),
            os_version=VALUES(os_version),
            compliance=VALUES(compliance),
            primary_user_upn=VALUES(primary_user_upn),
            primary_user_name=VALUES(primary_user_name),
            last_checkin=VALUES(last_checkin),
            model=VALUES(model),
            device_source='intune_graph',
            device_category=VALUES(device_category),
            is_encrypted=VALUES(is_encrypted)
        `, [
          d.device_id,
          d.computer_name || d.display_name || null,
          d.serial_number || null,
          d.imei || null,
          d.phone_number || null,
          os,
          d.os_version || null,
          d.compliance || null,
          d.user_upn || null,
          d.display_name || null,
          d.last_sync || null,
          d.model || null,
          category,
          d.is_encrypted == null ? null : (d.is_encrypted ? 1 : 0),
        ]);
        synced++;
      } catch(e) { errors++; console.error('sync-to-devices error:', e.message); }
    }

    // ── Step 2: Add Live Auction tablets not in Intune as historical ──
    // Wipe existing historical tablets first to avoid duplicates
    // Prune: remove graph-sourced intune_devices rows whose device_id is no longer in cache
    let graphPruned = 0;
    if (synced > 0 && cacheRows.length > 0) {
      const [r] = await pool.query(
        "DELETE FROM intune_devices WHERE device_source = 'intune_graph' AND device_id NOT IN (SELECT device_id FROM intune_graph_cache)"
      );
      graphPruned = r.affectedRows;
    }

    await pool.query("DELETE FROM intune_devices WHERE is_historical = 1 AND device_source = 'live_auction'");
    const [laTablets] = await pool.query(`
      SELECT la.device_id1, la.imei, la.model, la.first_last, la.state, la.regional, la.active_inactive
      FROM live_auction_devices la
      LEFT JOIN intune_devices i ON la.imei = i.imei AND i.is_historical = 0
      WHERE i.id IS NULL AND la.imei IS NOT NULL AND la.imei != ''
    `);

    let historicalAdded = 0, historicalSkipped = 0;
    for (const la of laTablets) {
      try {
        await pool.query(`
          INSERT INTO intune_devices
            (device_name, imei, model, os, device_source, device_category,
             is_historical, la_device_id, la_state, la_regional, la_active)
          VALUES (?, ?, ?, 'Android (Fully Managed)', 'live_auction', 'tablet', 1, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            la_device_id=VALUES(la_device_id),
            la_state=VALUES(la_state),
            la_regional=VALUES(la_regional),
            la_active=VALUES(la_active)
        `, [
          la.first_last || la.device_id1 || '--',
          la.imei,
          la.model || '--',
          la.device_id1 || null,
          la.state || null,
          la.regional || null,
          la.active_inactive || null,
        ]);
        historicalAdded++;
      } catch(e) { historicalSkipped++; }
    }

    res.json({ success: true, total: cacheRows.length, synced, errors, graph_pruned: graphPruned, historical_tablets: { added: historicalAdded, skipped: historicalSkipped } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
