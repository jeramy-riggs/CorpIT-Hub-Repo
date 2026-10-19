// collect-missing-patches.js — ManageEngine Endpoint Central missing patches.
// Token/fetch pattern copied from endpoints_sync.js (2026-08-15).
//
// Feeds the "Critical patches" KPI on the helpdesk landing page and gives the
// Asset Inventory app per-patch detail it never had: patch_health_cache only
// carried an opaque health code per machine.
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');

const PAGE_LIMIT = 200;
const PAGE_CAP   = 50;

async function fetchT(url, opts, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms || 30000);
  try {
    const res = await fetch(url, Object.assign({}, opts, { signal: ctrl.signal }));
    if (!res.ok) throw new Error('ME API ' + res.status + ': ' + url);
    return await res.json();
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('ME API timeout: ' + url);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function getAccessToken() {
  const params = new URLSearchParams({
    refresh_token: process.env.ME_REFRESH_TOKEN,
    client_id:     process.env.ME_CLIENT_ID,
    client_secret: process.env.ME_CLIENT_SECRET,
    grant_type:    'refresh_token',
  });
  const data = await fetchT('https://accounts.zoho.com/oauth/v2/token',
    { method: 'POST', body: params }, 15000);
  if (!data.access_token) throw new Error('ME token fetch failed: ' + JSON.stringify(data));
  return data.access_token;
}

// "dc.common.CRITICAL" -> "Critical". The API also returns a friendlier
// `s.name`; prefer it and fall back to parsing the i18n key.
function severityName(p) {
  if (p['s.name']) return String(p['s.name']);
  const raw = String(p.severity_name || '').split('.').pop() || '';
  return raw ? raw.charAt(0).toUpperCase() + raw.slice(1).toLowerCase() : null;
}

const dtFromEpoch = (ms) => (ms ? new Date(Number(ms)).toISOString().slice(0, 19).replace('T', ' ') : null);

async function main() {
  const token = await getAccessToken();
  const pool = mysql.createPool({
    host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME, waitForConnections: true, connectionLimit: 3,
  });

  // Take the run marker from MySQL, not `new Date()`. A JS Date carries
  // milliseconds while `collected_at` is second-precision, so every row written
  // during the marker's own second compares as older than it and the prune below
  // deletes rows this very run just inserted.
  const [[{ syncStart }]] = await pool.query('SELECT NOW() AS syncStart');
  const all = [];
  for (let page = 1; page <= PAGE_CAP; page++) {
    const body = await fetchT(
      `${process.env.ME_BASE_URL}/api/1.4/patch/missingpatches?page=${page}&pagelimit=${PAGE_LIMIT}`,
      { headers: { Authorization: 'Bearer ' + token } }, 45000);
    const rows = body?.message_response?.missingpatches || [];
    all.push(...rows);
    if (rows.length < PAGE_LIMIT) break;
  }

  let upserted = 0;
  for (const p of all) {
    if (p.patch_id == null) continue;
    await pool.query(
      `INSERT INTO me_missing_patch
         (patch_id, bulletin_id, patch_name, patch_description, vendor_name, update_name,
          severity, severity_name, platform_name, missing_count, failed_count,
          reboot_required, released_dt)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         bulletin_id=VALUES(bulletin_id), patch_name=VALUES(patch_name),
         patch_description=VALUES(patch_description), vendor_name=VALUES(vendor_name),
         update_name=VALUES(update_name), severity=VALUES(severity),
         severity_name=VALUES(severity_name), platform_name=VALUES(platform_name),
         missing_count=VALUES(missing_count), failed_count=VALUES(failed_count),
         reboot_required=VALUES(reboot_required), released_dt=VALUES(released_dt),
         collected_at=NOW()`,
      [p.patch_id, p.bulletin_id || null, p.patch_name || null,
       (p.patch_description || '').slice(0, 1024) || null, p.vendor_name || null,
       p.update_name || null, p.severity == null ? null : Number(p.severity),
       severityName(p), p.platform_name || null,
       Number(p.missing || 0), Number(p.failed || 0),
       p.patch_noreboot == null ? null : (Number(p.patch_noreboot) ? 0 : 1),
       dtFromEpoch(p.patch_released_time)]
    );
    upserted++;
  }

  // Patches fully deployed since the last run stop appearing in the feed —
  // drop anything this run did not touch, but only if the run actually
  // returned data (never let an empty/failed page wipe the table).
  let pruned = 0;
  if (upserted > 0) {
    const [r] = await pool.query('DELETE FROM me_missing_patch WHERE collected_at < ?', [syncStart]);
    pruned = r.affectedRows;
  }

  const [[sum]] = await pool.query(
    `SELECT COUNT(*) AS patches, COALESCE(SUM(missing_count),0) AS instances
       FROM me_missing_patch WHERE severity_name IN ('Critical','Important')`);
  console.log(`missing patches: ${upserted} upserted, ${pruned} pruned; ` +
              `critical+important: ${sum.patches} patches / ${sum.instances} device-instances`);

  await pool.end();
}

main().then(() => { console.log('collect-missing-patches OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-missing-patches FAILED:', e.message); process.exit(1); });
