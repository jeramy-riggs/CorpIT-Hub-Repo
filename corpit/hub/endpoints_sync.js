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

// Status row lives in the beta schema; reference cross-schema explicitly.
const STATUS_TABLE = 'corpit_hub.endpoints_sync_status';

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
  if (_token && Date.now() < _tokenExp - 60_000) return _token;
  const params = new URLSearchParams({
    refresh_token: process.env.ME_REFRESH_TOKEN,
    client_id:     process.env.ME_CLIENT_ID,
    client_secret: process.env.ME_CLIENT_SECRET,
    grant_type:    'refresh_token',
  });
  const data = await fetchT('https://accounts.zoho.com/oauth/v2/token', { method:'POST', body:params }, 15000);
  if (!data.access_token) throw new Error('Token refresh failed: ' + JSON.stringify(data));
  _token    = data.access_token;
  _tokenExp = Date.now() + (data.expires_in * 1000);
  return _token;
}
async function meGet(path) {
  const token = await getAccessToken();
  const url   = `${process.env.ME_BASE_URL}/api/1.4${path}`;
  const opts  = { headers: { Authorization: `Zoho-oauthtoken ${token}` } };
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

const SERVER_TYPES = ['server'];
function isServer(deviceType) {
  if (!deviceType || deviceType === '--') return false;
  return SERVER_TYPES.some(t => deviceType.toLowerCase().includes(t));
}
function normalizeComputerType(deviceType) {
  if (!deviceType || deviceType === '--') return 'UNKNOWN';
  const dt = deviceType.toLowerCase();
  if (dt.includes('notebook') || dt.includes('laptop')) return 'LAPTOP';
  if (dt.includes('desktop'))   return 'DESKTOP';
  if (dt.includes('mini'))      return 'DESKTOP';
  if (dt.includes('virtual'))   return 'VIRTUAL';
  return deviceType.toUpperCase();
}

router.get('/status', async (req, res) => {
  try {
    const [[row]] = await pool.query(
      `SELECT MAX(updated_at) as last_synced, COUNT(*) as total FROM endpoints`
    );
    res.json(row);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── status row helpers ──
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
  } catch (e) { console.error('[endpoints-sync] status write failed:', e.message); }
}

// ── the worker (runs detached from the HTTP response) ──
async function runSync() {
  const started = new Date();
  await setStatus({ state:'running', started_at:started, finished_at:null, total:0, synced:0, errors:0, message:'fetching device list' });
  let synced = 0, skipped = 0, errors = 0, removed = 0;
  const errorSummary = {}; let rawSamples = 0;
  try {
    let page = 1, allComputers = [], total = null;
    while (true) {
      const data = await meGet(`/som/computers?page=${page}&pagelimit=200`);
      const batch = data.message_response?.computers || [];
      allComputers = allComputers.concat(batch);
      total = data.message_response?.total || allComputers.length;
      if (allComputers.length >= total || batch.length === 0) break;
      page++;
    }

    // Safety guard: never mass-delete on a suspiciously small response.
    if (allComputers.length < 75) {
      await setStatus({ state:'error', finished_at:new Date(), total:allComputers.length,
        message:'aborted — ME only returned ' + allComputers.length + ' devices, too few to safely delete stale records' });
      console.error('[endpoints-sync] aborted: only', allComputers.length, 'devices');
      return;
    }

    await setStatus({ total: allComputers.length, message: 'pruning stale + upserting ' + allComputers.length + ' devices' });

    const meNames = new Set(
      allComputers.map(c => (c.resource_name || c.full_name || '').toLowerCase().trim()).filter(Boolean)
    );

    const [existing] = await pool.query('SELECT id, computer_name FROM endpoints');
    for (const row of existing) {
      const name = (row.computer_name || '').toLowerCase().trim();
      if (!meNames.has(name)) {
        await pool.query('DELETE FROM endpoints WHERE id = ?', [row.id]);
        removed++;
      }
    }

    for (const c of allComputers) {
      try {
        const detail = await meGet(`/inventory/compdetailssummary?resid=${c.resource_id}`);
        const hw = detail.message_response?.compdetailssummary?.computer_hardware_summary || {};
        const cs = detail.message_response?.compdetailssummary?.computer_summary || {};
        const os = detail.message_response?.compdetailssummary?.computer_os_summary || {};
        const deviceType = hw.device_type || '--';

        if (isServer(deviceType)) {
          skipped++;
          await new Promise(r => setTimeout(r, 100));
          continue;
        }
        const agentStatus = c['managedcomputer.agent_status'];
        const remarks = c['remarks'] || '';
        if (agentStatus === 0 || remarks.includes('uninstall')) {
          skipped++;
          await new Promise(r => setTimeout(r, 100));
          continue;
        }

        const computerName  = c.resource_name || c.full_name || '--';
        const deviceModel   = hw.device_model || '--';
        const computerType  = normalizeComputerType(deviceType);
        const loggedOnUser  = c['agent_logged_on_users'] || '--';
        const firstLast     = cs.currently_logged_on_user || loggedOnUser || '--';
        const serviceTag    = (c['managedcomputerextn.service_tag'] || '--').replace(/%20/g, ' ');
        const osName        = os.os_name || c['os_name'] || c['os_platform_name'] || '--';
        const osVersion     = os.os_service_pack || c['os_version'] || '--';
        const resourceId    = c.resource_id_string || String(c.resource_id) || null;
        const lastAssetScan = c.agent_last_contact_time
          ? new Date(c.agent_last_contact_time).toLocaleDateString('en-US',
              { year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' })
          : '--';

        await pool.query(`
          INSERT INTO endpoints
            (computer_name, resource_id, device_model, computer_type, logged_on_user,
             first_last, user_source, last_asset_scan, service_tag, os_name, os_version)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            resource_id=VALUES(resource_id),
            device_model=VALUES(device_model),
            computer_type=VALUES(computer_type),
            logged_on_user=VALUES(logged_on_user),
            first_last=VALUES(first_last),
            last_asset_scan=VALUES(last_asset_scan),
            service_tag=VALUES(service_tag),
            os_name=VALUES(os_name),
            os_version=VALUES(os_version),
            updated_at=NOW()
        `, [computerName, resourceId, deviceModel, computerType, loggedOnUser,
            firstLast, 'me', lastAssetScan, serviceTag, osName, osVersion]);

        synced++;
        if (synced % 50 === 0) await setStatus({ synced: synced, errors: errors, message: synced + '/' + allComputers.length + ' (' + skipped + ' skipped, ' + removed + ' removed)' });
        await new Promise(r => setTimeout(r, 150));
      } catch(e) {
        errors++;
        const _msg = (e && e.message) || String(e);
        const _k = _msg.replace(/\d+/g,'N').slice(0,100);
        errorSummary[_k] = (errorSummary[_k]||0) + 1;
        if (rawSamples < 3) { rawSamples++; console.error('[endpoints-sync] sample err resid=' + (c && c.resource_id) + ' name=' + (c && c.resource_name) + ': ' + _msg.slice(0,220)); }
      }
    }

    await setStatus({ state:'ok', finished_at:new Date(), total:allComputers.length, synced:synced, errors:errors,
      message: 'done: ' + synced + ' synced, ' + skipped + ' skipped, ' + removed + ' removed, ' + errors + ' errors' });
    console.log('[endpoints-sync] done:', synced, 'synced,', skipped, 'skipped,', removed, 'removed,', errors, 'errors');
    if (errors > 0) {
      const _entries = Object.entries(errorSummary).sort((a,b)=>b[1]-a[1]).slice(0,10);
      console.error('[endpoints-sync] error summary (top ' + _entries.length + '/' + Object.keys(errorSummary).length + ' distinct):');
      for (const [k,n] of _entries) console.error('  ' + n + '  ' + k);
    }

  } catch(e) {
    await setStatus({ state:'error', finished_at:new Date(), synced:synced, errors:errors, message:(e.message||'').slice(0,480) });
    console.error('[endpoints-sync] failed:', e.message);
  } finally {
    _syncRunning = false;
  }
}

// ── POST /api/endpoints-sync/sync ───────────────────────────
// Returns immediately; sync runs in background. Guarded against overlap.
router.post('/sync', async (req, res) => {
  if (_syncRunning) {
    return res.status(202).json({ started: false, alreadyRunning: true, note: 'A sync is already in progress.' });
  }
  _syncRunning = true;
  setImmediate(runSync);
  res.status(202).json({ started: true, note: 'Sync started in background. Poll GET /api/endpoints-sync/sync/status.' });
});

// ── GET /api/endpoints-sync/sync/status ─────────────────────
router.get('/sync/status', async (req, res) => {
  try {
    const [[row]] = await pool.query('SELECT state, started_at, finished_at, total, synced, errors, message FROM ' + STATUS_TABLE + ' WHERE id=1');
    res.json(row || { state:'never', message:'no run recorded' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
