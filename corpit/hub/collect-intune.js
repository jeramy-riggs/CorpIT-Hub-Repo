// collect-intune.js — Intune managed devices mirror (pattern: collect-defender.js, 2026-07-20)
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');

async function getToken() {
  const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.ENTRA_CLIENT_ID,
      client_secret: process.env.ENTRA_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('token fetch failed: ' + JSON.stringify(j));
  return j.access_token;
}

const dt = (s) => (s && !String(s).startsWith('0001') ? new Date(s).toISOString().slice(0, 19).replace('T', ' ') : null);

async function main() {
  const token = await getToken();
  const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });

  let url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=500'
    + '&$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,enrolledDateTime';
  let total = 0, pages = 0;
  while (url && pages < 50) {
    const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error(`Graph ${r.status}: ${await r.text()}`);
    const j = await r.json();
    for (const d of j.value || []) {
      await pool.query(
        `INSERT INTO sentinel_intune_device
           (device_id, device_name, upn, os, os_version, compliance_state, is_encrypted, last_sync_dt, enrolled_dt, raw_json)
         VALUES (?,?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE device_name=VALUES(device_name), upn=VALUES(upn), os=VALUES(os),
           os_version=VALUES(os_version), compliance_state=VALUES(compliance_state),
           is_encrypted=VALUES(is_encrypted), last_sync_dt=VALUES(last_sync_dt),
           enrolled_dt=VALUES(enrolled_dt), raw_json=VALUES(raw_json),
           -- forces the row to count as changed so the column's ON UPDATE
           -- CURRENT_TIMESTAMP fires; otherwise an unchanged row leaves
           -- collected_at frozen and the freshness stamp reads stale even though
           -- the collector is running fine.
           collected_at=CURRENT_TIMESTAMP`,
        [d.id, d.deviceName, d.userPrincipalName, d.operatingSystem, d.osVersion,
         d.complianceState, d.isEncrypted ? 1 : 0, dt(d.lastSyncDateTime), dt(d.enrolledDateTime), JSON.stringify(d)]
      );
      total++;
    }
    url = j['@odata.nextLink'];
    pages++;
  }
  console.log(`intuneDevices: ${total} upserted (${pages} pages)`);
  await pool.end();
}

main().then(() => { console.log('collect-intune OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-intune FAILED:', e.message); process.exit(1); });
