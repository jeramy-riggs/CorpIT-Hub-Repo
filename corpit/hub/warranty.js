const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');

// ── DB pool (reuse same creds, beta DB) ─────────────────────
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

async function getAccessToken() {
  if (_token && Date.now() < _tokenExp - 60_000) return _token;
  const params = new URLSearchParams({
    refresh_token: process.env.ME_REFRESH_TOKEN,
    client_id:     process.env.ME_CLIENT_ID,
    client_secret: process.env.ME_CLIENT_SECRET,
    grant_type:    'refresh_token',
  });
  const res  = await fetch('https://accounts.zoho.com/oauth/v2/token', { method:'POST', body:params });
  const data = await res.json();
  if (!data.access_token) throw new Error('Token refresh failed: ' + JSON.stringify(data));
  _token    = data.access_token;
  _tokenExp = Date.now() + (data.expires_in * 1000);
  return _token;
}

async function meGet(path) {
  const token = await getAccessToken();
  const url   = `${process.env.ME_BASE_URL}/api/1.4${path}`;
  const backoffs = [0, 3000, 8000, 20000];
  let lastErr;
  for (let i = 0; i < backoffs.length; i++) {
    if (backoffs[i] > 0) {
      const wait = backoffs[i] + Math.floor(Math.random() * 500);
      await new Promise(function (r) { setTimeout(r, wait); });
    }
    try {
      const res = await fetch(url, { headers: { Authorization: `Zoho-oauthtoken ${token}` } });
      if (!res.ok) throw new Error(`ME API ${res.status}: ${url}`);
      return await res.json();
    } catch (e) {
      lastErr = e;
      if (!/ME API 429/.test((e && e.message) || '')) throw e;
    }
  }
  throw lastErr;
}

// ── GET /api/warranty — read from cache ──────────────────────
router.get('/', needRead, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM warranty_cache ORDER BY computer_name ASC');
    res.json({ computers: rows, total: rows.length });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/warranty/status — last sync time ────────────────
router.get('/status', needRead, async (req, res) => {
  try {
    const [[row]] = await pool.query('SELECT MAX(last_synced) as last_synced, COUNT(*) as total FROM warranty_cache');
    res.json(row);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/warranty/sync — fetch all from ME, cache in DB ─
// The sync walks every ManageEngine computer one detail call at a time (minutes,
// well past nginx's 30 s proxy timeout), so it runs in the background and the
// page polls /sync/status. One run at a time.
const _warrantySync = { running: false, startedAt: null, finishedAt: null, result: null, error: null };
async function runWarrantySync() {
  try {
    // Step 1: get full computer list (paginated)
    let page = 1, allComputers = [], total = null;
    while (true) {
      const data = await meGet(`/som/computers?page=${page}&pagelimit=200`);
      const batch = data.message_response?.computers || [];
      allComputers = allComputers.concat(batch);
      total = data.message_response?.total || allComputers.length;
      if (allComputers.length >= total || batch.length === 0) break;
      page++;
    }

    // Step 2: for each computer, fetch warranty detail
    let synced = 0, errors = 0;
    for (const c of allComputers) {
      try {
        const detail = await meGet(`/inventory/compdetailssummary?resid=${c.resource_id}`);
        const hw = detail.message_response?.compdetailssummary?.computer_hardware_summary || {};
        const warrantyDate = (hw.warranty_expiry_date && hw.warranty_expiry_date !== '--')
          ? hw.warranty_expiry_date : null;

        await pool.query(`
          INSERT INTO warranty_cache
            (resource_id, computer_name, service_tag, device_model, device_manufacturer,
             device_type, os_name, logged_on_user, ip_address, warranty_expiry_date, agent_installed_on)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            computer_name=VALUES(computer_name), service_tag=VALUES(service_tag),
            device_model=VALUES(device_model), device_manufacturer=VALUES(device_manufacturer),
            device_type=VALUES(device_type), os_name=VALUES(os_name),
            logged_on_user=VALUES(logged_on_user), ip_address=VALUES(ip_address),
            warranty_expiry_date=VALUES(warranty_expiry_date), agent_installed_on=VALUES(agent_installed_on), last_synced=NOW()
        `, [
          String(c.resource_id),
          c.resource_name || c.full_name || '--',
          c['managedcomputerextn.service_tag'] || '--',
          hw.device_model || '--',
          hw.device_manufacturer || '--',
          hw.device_type || '--',
          c.os_name || '--',
          c['agent_logged_on_users'] || '--',
          c.ip_address || '--',
          warrantyDate,
          c.agent_installed_on || null,
        ]);
        synced++;
        // Small delay to avoid ME rate limits
        await new Promise(r => setTimeout(r, 150));
      } catch(e) {
        errors++;
      }
    }

    _warrantySync.result = { total: allComputers.length, synced, errors };
  } catch(e) {
    _warrantySync.error = e.message;
  } finally {
    _warrantySync.running = false;
    _warrantySync.finishedAt = new Date().toISOString();
  }
}

router.post('/sync', needAdminOrCron, (req, res) => {
  if (_warrantySync.running) {
    return res.status(202).json({ started: false, alreadyRunning: true, startedAt: _warrantySync.startedAt });
  }
  _warrantySync.running = true;
  _warrantySync.startedAt = new Date().toISOString();
  _warrantySync.finishedAt = null; _warrantySync.result = null; _warrantySync.error = null;
  runWarrantySync().catch(() => {});
  res.status(202).json({ started: true, alreadyRunning: false, startedAt: _warrantySync.startedAt });
});

router.get('/sync/status', needRead, (req, res) => {
  const state = _warrantySync.running ? 'running' : (_warrantySync.error ? 'failed' : (_warrantySync.result ? 'done' : 'idle'));
  res.json({ state, ..._warrantySync });
});

// GET /api/warranty/map — returns warranty keyed by service_tag for fast lookup
router.get("/map", needRead, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM warranty_cache");
    const map = {};
    rows.forEach(r => {
      if (r.service_tag && r.service_tag !== "--") {
        map[r.service_tag.toLowerCase().trim()] = r;
      }
      // also index by computer_name as fallback
      if (r.computer_name && r.computer_name !== "--") {
        map["name:" + r.computer_name.toLowerCase().trim()] = r;
      }
    });
    res.json(map);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
