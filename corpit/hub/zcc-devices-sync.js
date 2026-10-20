#!/usr/bin/env node
// zcc-devices-sync.js — Sync ZCC device inventory to corpit_hub.zcc_devices
// CSV source: /zcc/papi/public/v1/downloadDevices (includes SerialNumber for Intune join).
// downloadDevices is a FULL-CSV EXPORT: one call returns the whole fleet.
// Runs every 4h via cron. Header-based column mapping (order-independent).

require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const { ziaAuth, httpsRequest } = require('/var/www/corpit-hub-api/zscaler-lookup');
const mysql = require('mysql2/promise');

const DRY_RUN = process.argv.includes('--dry-run');
const VERBOSE = process.argv.includes('--verbose');
const NO_PRUNE = process.argv.includes('--no-prune');      // upsert only, keep absent rows
const PLAN_PRUNE = process.argv.includes('--plan-prune');  // report what prune would remove; no writes

function log(msg) {
  const line = '[' + new Date().toISOString() + '] ' + msg + '\n';
  process.stdout.write(line);
}

// CSV parser — handles quoted fields with commas + escaped double-quotes ("")
function parseCSV(text) {
  const rows = [];
  let row = [], field = '', inQuotes = false, i = 0;
  const pushField = () => { row.push(field); field = ''; };
  const pushRow = () => { rows.push(row); row = []; };
  while (i < text.length) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQuotes = false; i++;
      } else { field += c; i++; }
    } else {
      if (c === '"') { inQuotes = true; i++; }
      else if (c === ',') { pushField(); i++; }
      else if (c === '\r') { i++; }
      else if (c === '\n') { pushField(); pushRow(); i++; }
      else { field += c; i++; }
    }
  }
  if (field.length || row.length) { pushField(); pushRow(); }
  return rows;
}

function parseGmtDate(s) {
  if (!s || !s.trim() || s === '---') return null;
  const iso = s.replace(' GMT', 'Z').replace(' ', 'T');
  const d = new Date(iso);
  return isNaN(d.getTime()) ? null : d;
}

// Field mapping: schema_column → CSV header (order-independent, resilient to header re-ordering)
const FIELD_MAP = {
  udid:                  'UDID',
  user_upn:              'User',
  owner:                 'Owner',
  hostname:              'Hostname',
  serial_number:         'SerialNumber',
  mac_address:           'Mac Address',
  device_type:           'Device type',
  device_model:          'Device model',
  manufacturer:          'Manufacturer',
  os_version:            'OS Version',
  zcc_version:           'Zscaler Client Connector Version',
  zdx_version:           'Zscaler Digital Experience Version',
  zdp_version:           'Zscaler Data Protection Version',
  tunnel_sdk_version:    'Active Tunnel SDK version',
  tunnel_version:        'Tunnel Version',
  policy_name:           'Policy Name',
  installation_type:     'Installation Type',
  device_state:          'Device State',
  trust_level:           'Device Trust Level',
  vpn_state:             'VPN State',
  zcc_revert_status:     'ZCC Revert Status',
  imprivata_user:        'Imprivata User',
  hardware_fingerprint:  'Device Hardware Fingerprint',
  config_download_count: 'Config Download Count',
  last_seen_zia:         'Last Seen Connected to ZIA',
  last_seen_zpa:         'Last Seen Connected to ZPA',
  last_seen_active:      'Last Seen with Client Connector Active',
  registration_ts:       'Registration TimeStamp',
  deregistration_ts:     'Last Deregistration TimeStamp',
  config_download_ts:    'Config Download TimeStamp'
};
const DATE_FIELDS = new Set(['last_seen_zia','last_seen_zpa','last_seen_active','registration_ts','deregistration_ts','config_download_ts']);
const INT_FIELDS = new Set(['config_download_count']);

async function fetchDevices(H) {
  // downloadDevices is a full-CSV export, NOT a paginated endpoint: it ignores
  // page/pageSize and returns the whole fleet on every call. The old pagination
  // loop here re-downloaded the identical CSV each "page" (732 rows >= its 500
  // exit threshold, so it never stopped), burned the endpoint's strict rate
  // budget, and died FATAL on 429 -- discarding everything already fetched.
  // One call fetches the entire fleet. (Fixed 2026-08-21.)
  const url = new URL('https://api.zsapi.net/zcc/papi/public/v1/downloadDevices');
  let r, tries = 0;
  while (true) {
    r = await httpsRequest(url, { method: 'GET', headers: H, timeoutMs: 120000 });
    if (r.status === 200) break;
    if (r.status === 429 && tries < 3) {
      tries++;
      const waitSec = 60 * tries;
      log('  429 rate-limited, waiting ' + waitSec + 's (retry ' + tries + '/3)');
      await new Promise(res => setTimeout(res, waitSec * 1000));
      continue;
    }
    throw new Error('downloadDevices HTTP ' + r.status);
  }
  const csv = typeof r.body === 'string' ? r.body : String(r.body);
  const rows = parseCSV(csv);
  if (rows.length < 2) throw new Error('downloadDevices returned no data rows');
  const header = rows[0];
  const headerIdx = {};
  header.forEach((h, i) => headerIdx[h] = i);
  // Validate every schema field maps to a real header
  for (const [col, hdr] of Object.entries(FIELD_MAP)) {
    if (headerIdx[hdr] === undefined) {
      throw new Error('CSV header missing expected column: "' + hdr + '" (for schema field ' + col + ')');
    }
  }
  log('CSV header validated (' + header.length + ' columns)');
  const dataRows = rows.slice(1).filter(r => r.length >= 5);
  log('parsed ' + dataRows.length + ' data rows from full-fleet CSV');
  return { rows: dataRows, headerIdx };
}

function mapRow(cols, headerIdx) {
  const rec = {};
  for (const [col, hdr] of Object.entries(FIELD_MAP)) {
    let v = cols[headerIdx[hdr]];
    if (v === undefined || v === null) { rec[col] = null; continue; }
    v = String(v).trim();
    if (!v) { rec[col] = null; continue; }
    if (DATE_FIELDS.has(col)) rec[col] = parseGmtDate(v);
    else if (INT_FIELDS.has(col)) { const n = parseInt(v, 10); rec[col] = Number.isFinite(n) ? n : null; }
    else rec[col] = v;
  }
  // raw_json captures the full CSV row keyed by header (future-proofs new fields)
  const rawObj = {};
  Object.keys(headerIdx).forEach(h => { rawObj[h] = cols[headerIdx[h]] || null; });
  rec.raw_json = JSON.stringify(rawObj);
  return rec;
}

async function upsert(pool, records) {
  const cols = [
    'udid','user_upn','owner','hostname','serial_number','mac_address','device_type','device_model',
    'manufacturer','os_version','zcc_version','zdx_version','zdp_version','tunnel_sdk_version',
    'tunnel_version','policy_name','installation_type','device_state','trust_level','vpn_state',
    'zcc_revert_status','imprivata_user','hardware_fingerprint','config_download_count',
    'last_seen_zia','last_seen_zpa','last_seen_active','registration_ts','deregistration_ts',
    'config_download_ts','raw_json'
  ];
  const colList = cols.map(c => '`' + c + '`').join(',');
  const placeholders = '(' + cols.map(() => '?').join(',') + ')';
  // updated_at is appended explicitly: it is not in `cols`, and even if it were,
  // MySQL skips ON UPDATE CURRENT_TIMESTAMP when an upsert changes nothing --
  // which is the normal case for a fleet whose devices did not move.
  const updateClause = cols.filter(c => c !== 'udid').map(c => '`' + c + '`=VALUES(`' + c + '`)').join(', ')
    + ', `updated_at`=CURRENT_TIMESTAMP';
  const CHUNK = 200;
  let affected = 0;
  for (let i = 0; i < records.length; i += CHUNK) {
    const chunk = records.slice(i, i + CHUNK);
    const sql = 'INSERT INTO zcc_devices (' + colList + ') VALUES ' + chunk.map(() => placeholders).join(',') + ' ON DUPLICATE KEY UPDATE ' + updateClause;
    const params = [];
    chunk.forEach(r => cols.forEach(c => params.push(r[c])));
    const [result] = await pool.query(sql, params);
    affected += result.affectedRows;
    if (VERBOSE) log('  chunk ' + i + '-' + (i + chunk.length) + ': affectedRows=' + result.affectedRows);
  }
  return affected;
}

// Remove devices ZCC no longer exports. downloadDevices returns the whole fleet (see
// fetchDevices), so a UDID missing from it is gone from ZCC. Without this the table kept
// every device ever seen, and /zcc/summary, version drift and the Intune cross-links
// counted them as live (116 such rows on 2026-10-15). Rows are copied to
// zcc_devices_removed before deletion; prune is skipped while that table is missing and
// refused when the export is too short to trust as the whole fleet.
const PRUNE_MIN_EXPORT = 500, PRUNE_MAX_SHARE = 0.25;
const ARCHIVE_COLS = Object.keys(FIELD_MAP).concat(['raw_json', 'first_seen_at', 'updated_at']);
async function prune(pool, seen, planOnly) {
  const [[arch]] = await pool.query("SELECT COUNT(*) n FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'zcc_devices_removed'");
  const [rows] = await pool.query('SELECT udid, device_state FROM zcc_devices');
  const gone = rows.filter(r => !seen.has(r.udid));
  const byState = {};
  gone.forEach(r => { byState[r.device_state] = (byState[r.device_state] || 0) + 1; });
  log('prune: ' + gone.length + ' of ' + rows.length + ' rows absent from the export ' + JSON.stringify(byState));
  if (!gone.length) return 0;
  if (seen.size < PRUNE_MIN_EXPORT || gone.length > rows.length * PRUNE_MAX_SHARE) {
    log('prune REFUSED: export has ' + seen.size + ' devices, ' + gone.length + ' rows absent -- too short to trust as the whole fleet; nothing removed');
    return 0;
  }
  if (!arch.n) { log('prune skipped: zcc_devices_removed table not present'); return 0; }
  if (planOnly) { log('prune PLAN only (--plan-prune): nothing removed'); return 0; }
  const cols = ARCHIVE_COLS.map(c => '`' + c + '`').join(',');
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (let i = 0; i < gone.length; i += 200) {
      const ids = gone.slice(i, i + 200).map(r => r.udid);
      await conn.query('REPLACE INTO zcc_devices_removed (' + cols + ', `removed_at`) SELECT ' + cols + ', CURRENT_TIMESTAMP FROM zcc_devices WHERE udid IN (?)', [ids]);
      await conn.query('DELETE FROM zcc_devices WHERE udid IN (?)', [ids]);
    }
    await conn.commit();
  } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
  log('prune: removed ' + gone.length + ' devices (archived in zcc_devices_removed)');
  return gone.length;
}

async function main() {
  const t0 = Date.now();
  log('ZCC devices sync starting' + (DRY_RUN ? ' (DRY-RUN)' : ''));
  const token = await ziaAuth();
  const H = { Authorization: 'Bearer ' + token, 'User-Agent': 'itam-zcc-sync' };
  const { rows, headerIdx } = await fetchDevices(H);
  log('total devices fetched: ' + rows.length);
  // Dedupe by UDID (last row wins) so repeated rows can never inflate the upsert.
  const byUdid = new Map();
  rows.forEach(r => { const rec = mapRow(r, headerIdx); if (rec.udid) byUdid.set(rec.udid, rec); });
  const records = Array.from(byUdid.values());
  log('prepared ' + records.length + ' unique records with valid UDID');
  if (DRY_RUN) {
    log('DRY-RUN — sample of first 2 records:');
    console.log(JSON.stringify(records.slice(0, 2), (k, v) => v instanceof Date ? v.toISOString() : v, 2));
    log('DRY-RUN complete (no DB writes)');
    return;
  }
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'corpit_hub',
    connectionLimit: 4
  });
  const seen = new Set(records.map(r => r.udid));
  if (PLAN_PRUNE) { await prune(pool, seen, true); await pool.end(); return; }
  const affected = await upsert(pool, records);
  log('upsert affectedRows total: ' + affected + ' (insert=1, update=2 per row)');
  if (NO_PRUNE) log('prune skipped (--no-prune)');
  else await prune(pool, seen, false);
  const [xlink] = await pool.query(
    'SELECT COUNT(*) AS zcc_total, ' +
    'SUM(CASE WHEN i.serial_number IS NOT NULL THEN 1 ELSE 0 END) AS intune_matched ' +
    'FROM zcc_devices z LEFT JOIN it_inventory.intune_devices i ON i.serial_number COLLATE utf8mb4_unicode_ci = z.serial_number ' +
    'WHERE z.serial_number IS NOT NULL AND z.serial_number != ""'
  );
  log('Intune cross-link: ' + xlink[0].intune_matched + '/' + xlink[0].zcc_total + ' devices matched by serial');
  const [tunnelDist] = await pool.query(
    'SELECT tunnel_version, COUNT(*) c FROM zcc_devices WHERE tunnel_version IS NOT NULL GROUP BY tunnel_version ORDER BY c DESC LIMIT 5'
  );
  log('Tunnel version distribution: ' + tunnelDist.map(r => r.tunnel_version + '=' + r.c).join(', '));
  const [zccVerDist] = await pool.query(
    'SELECT zcc_version, COUNT(*) c FROM zcc_devices WHERE zcc_version IS NOT NULL GROUP BY zcc_version ORDER BY c DESC LIMIT 5'
  );
  log('ZCC version distribution (top 5): ' + zccVerDist.map(r => r.zcc_version + '=' + r.c).join(', '));
  await pool.end();
  const dt = ((Date.now() - t0) / 1000).toFixed(1);
  log('ZCC sync complete in ' + dt + 's');
}

if (require.main === module) main().catch(e => { log('FATAL: ' + e.message + '\n' + (e.stack || '')); process.exit(1); });
module.exports = { prune, ARCHIVE_COLS };
