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

// Status row lives in the beta schema; reference cross-schema explicitly.
const STATUS_TABLE = 'corpit_hub.me_patch_sync_status';

// timed fetch: aborts a stalled upstream call, but never clears the
// timer before res.json() finishes parsing the body.
async function fetchT(url, opts, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(function () { ctrl.abort(); }, ms || 20000);
  let res;
  try {
    res = await fetch(url, Object.assign({}, opts, { signal: ctrl.signal }));
    if (!res.ok) { clearTimeout(timer); throw new Error('ME API ' + res.status + ': ' + url); }
    const data = await res.json();
    clearTimeout(timer);
    return data;
  } catch (e) {
    clearTimeout(timer);
    if (e.name === 'AbortError') throw new Error('ME API timeout: ' + url);
    throw e;
  }
}

let _token    = null;
let _tokenExp = 0;
async function getAccessToken() {
  if (_token && Date.now() < _tokenExp - 60000) return _token;
  const params = new URLSearchParams({
    refresh_token: process.env.ME_REFRESH_TOKEN,
    client_id:     process.env.ME_CLIENT_ID,
    client_secret: process.env.ME_CLIENT_SECRET,
    grant_type:    'refresh_token',
  });
  const data = await fetchT('https://accounts.zoho.com/oauth/v2/token', { method: 'POST', body: params }, 15000);
  if (!data.access_token) throw new Error('Token refresh failed: ' + JSON.stringify(data));
  _token    = data.access_token;
  _tokenExp = Date.now() + (data.expires_in * 1000);
  return _token;
}
async function meGet(path) {
  const token = await getAccessToken();
  const url   = process.env.ME_BASE_URL + '/api/1.4' + path;
  const opts  = { headers: { Authorization: 'Zoho-oauthtoken ' + token } };
  const backoffs = [0, 3000, 8000, 20000];
  let lastErr;
  for (let i = 0; i < backoffs.length; i++) {
    if (backoffs[i] > 0) {
      const wait = backoffs[i] + Math.floor(Math.random() * 500);
      await new Promise(function (r) { setTimeout(r, wait); });
    }
    try {
      return await fetchT(url, opts, 20000);
    } catch (e) {
      lastErr = e;
      if (!/ME API 429/.test((e && e.message) || '')) throw e;
    }
  }
  throw lastErr;
}
async function mePost(path, body) {
  const token = await getAccessToken();
  const url   = process.env.ME_BASE_URL + '/api/1.4' + path;
  return fetchT(url, {
    method:  'POST',
    headers: { Authorization: 'Zoho-oauthtoken ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, 20000);
}

router.get('/scan-status/:resourceId', needRead, async (req, res) => {
  try {
    const { resourceId } = req.params;
    if (!resourceId || resourceId === 'null') {
      return res.status(400).json({ error: 'No resource_id — run a ME sync first' });
    }
    const data = await meGet('/patch/scandetails?resid=' + resourceId);
    const detail = data.message_response?.scandetails?.[0] || null;
    if (!detail) return res.json({ found: false, resourceId });
    const healthMap = { 0:'Unknown', 1:'Healthy', 2:'Vulnerable', 3:'Highly Vulnerable' };
    const scanMap   = { 226:'Failed', 227:'In Progress', 228:'Success', 229:'Not Scanned' };
    res.json({
      found:          true,
      resourceId,
      computerName:   detail['resource.name'] || '--',
      health:         healthMap[detail.resource_health_status] ?? 'Unknown',
      healthCode:     detail.resource_health_status,
      scanStatus:     scanMap[detail.scan_status] ?? 'Unknown',
      scanStatusCode: detail.scan_status,
      lastScanTime:   detail.last_scan_time ? new Date(detail.last_scan_time).toLocaleString('en-US') : '--',
      agentLive:      detail.computer_live_status === 1,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/scan', needAdminOrCron, async (req, res) => {
  try {
    const { resourceId } = req.body;
    if (!resourceId || resourceId === 'null') {
      return res.status(400).json({ error: 'resourceId is required' });
    }
    const data = await mePost('/patch/computers/scan', { resourceids: String(resourceId) });
    res.json({ success: true, resourceId, response: data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/cache', needRead, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM patch_health_cache');
    const map = {};
    rows.forEach(r => { map[r.resource_id] = r; });
    res.json({ success: true, total: rows.length, cache: map, lastSynced: rows[0]?.last_synced || null });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/sync-status', needRead, async (req, res) => {
  try {
    const [[row]] = await pool.query('SELECT MAX(last_synced) as last_synced, COUNT(*) as total FROM patch_health_cache');
    res.json({ last_synced: row.last_synced, total: row.total });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

let _syncRunning = false;

async function setStatus(fields) {
  const cols = ['state','started_at','finished_at','total','synced','errors','message'];
  const vals = cols.map(c => (c in fields ? fields[c] : null));
  try {
    await pool.query(
      'INSERT INTO ' + STATUS_TABLE + ' (id,state,started_at,finished_at,total,synced,errors,message) ' +
      'VALUES (1,?,?,?,?,?,?,?) ' +
      'ON DUPLICATE KEY UPDATE ' +
      'state=COALESCE(VALUES(state),state), ' +
      'started_at=COALESCE(VALUES(started_at),started_at), ' +
      'finished_at=VALUES(finished_at), ' +
      'total=COALESCE(VALUES(total),total), ' +
      'synced=COALESCE(VALUES(synced),synced), ' +
      'errors=COALESCE(VALUES(errors),errors), ' +
      'message=VALUES(message)',
      vals
    );
  } catch (e) { console.error('[me-patch] status write failed:', e.message); }
}

async function runSyncAll() {
  const started = new Date();
  await setStatus({ state: 'running', started_at: started, finished_at: null, total: 0, synced: 0, errors: 0, message: 'starting' });
  let synced = 0, errors = 0, total = 0;
  try {
    const [endpoints] = await pool.query(
      'SELECT resource_id, computer_name FROM endpoints WHERE resource_id IS NOT NULL'
    );
    total = endpoints.length;
    await setStatus({ total: total, message: 'processing ' + total + ' endpoints' });
    if (total === 0) {
      await setStatus({ state: 'idle', finished_at: new Date(), message: 'no endpoints with resource_id' });
      return;
    }
    const healthMap = { 0:'Unknown', 1:'Healthy', 2:'Vulnerable', 3:'Highly Vulnerable' };
    const scanMap   = { 226:'Failed', 227:'In Progress', 228:'Success', 229:'Not Scanned' };
    for (const ep of endpoints) {
      try {
        const data = await meGet('/patch/scandetails?resid=' + ep.resource_id);
        const detail = data.message_response?.scandetails?.[0] || null;
        if (!detail) { errors++; continue; }
        await pool.query(
          'INSERT INTO patch_health_cache ' +
          '(resource_id, computer_name, health, health_code, scan_status, last_scan_time, agent_live, last_synced) ' +
          'VALUES (?, ?, ?, ?, ?, ?, ?, NOW()) ' +
          'ON DUPLICATE KEY UPDATE ' +
          'computer_name=VALUES(computer_name), health=VALUES(health), health_code=VALUES(health_code), ' +
          'scan_status=VALUES(scan_status), last_scan_time=VALUES(last_scan_time), ' +
          'agent_live=VALUES(agent_live), last_synced=NOW()',
          [
            ep.resource_id,
            detail['resource.name'] || ep.computer_name || '--',
            healthMap[detail.resource_health_status] ?? 'Unknown',
            detail.resource_health_status,
            scanMap[detail.scan_status] ?? 'Unknown',
            detail.last_scan_time ? new Date(detail.last_scan_time).toLocaleString('en-US') : '--',
            detail.computer_live_status === 1 ? 1 : 0,
          ]
        );
        synced++;
        if (synced % 25 === 0) await setStatus({ synced: synced, errors: errors, message: synced + '/' + total });
        await new Promise(r => setTimeout(r, 600));
      } catch (e) {
        errors++;
        if (e.message && e.message.includes('429')) await new Promise(r => setTimeout(r, 5000));
      }
    }
    await setStatus({ state: 'ok', finished_at: new Date(), synced: synced, errors: errors, total: total, message: 'done: ' + synced + ' synced, ' + errors + ' errors' });
    console.log('[me-patch] sync-all done:', synced, 'synced,', errors, 'errors of', total);
  } catch (e) {
    await setStatus({ state: 'error', finished_at: new Date(), synced: synced, errors: errors, total: total, message: (e.message || '').slice(0, 480) });
    console.error('[me-patch] sync-all failed:', e.message);
  } finally {
    _syncRunning = false;
  }
}

router.post('/sync-all', needAdminOrCron, async (req, res) => {
  if (_syncRunning) {
    return res.status(202).json({ started: false, alreadyRunning: true, note: 'A sync is already in progress.' });
  }
  _syncRunning = true;
  setImmediate(runSyncAll);
  res.status(202).json({ started: true, note: 'Sync started in background. Poll GET /api/me-patch/sync-all/status.' });
});

router.get('/sync-all/status', needRead, async (req, res) => {
  try {
    const [[row]] = await pool.query('SELECT state, started_at, finished_at, total, synced, errors, message FROM ' + STATUS_TABLE + ' WHERE id=1');
    res.json(row || { state: 'never', message: 'no run recorded' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
