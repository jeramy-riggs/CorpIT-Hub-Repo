// collect-purview.js — Purview sensitivity label taxonomy (beta informationProtection API)
// ENTRA_* creds + InformationProtectionPolicy.Read.All. Pattern: collect-defender.js.
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
  if (!j.access_token) throw new Error('token fetch failed: ' + JSON.stringify(j).slice(0, 200));
  return j.access_token;
}

async function main() {
  const token = await getToken();
  const r = await fetch('https://graph.microsoft.com/beta/informationProtection/policy/labels', {
    headers: { Authorization: 'Bearer ' + token },
  });
  if (!r.ok) throw new Error(`labels: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  const labels = (await r.json()).value || [];

  const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });
  const seen = [];
  for (const l of labels) {
    seen.push(l.id);
    await pool.query(
      `INSERT INTO sentinel_purview_label (label_id, name, is_active, sensitivity, parent_id, raw_json)
       VALUES (?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE name=VALUES(name), is_active=VALUES(is_active),
         sensitivity=VALUES(sensitivity), parent_id=VALUES(parent_id), raw_json=VALUES(raw_json)`,
      [l.id, l.name, l.isActive ? 1 : 0, l.sensitivity ?? null, l.parent?.id || null, JSON.stringify(l)]
    );
  }
  if (seen.length) {
    await pool.query(`DELETE FROM sentinel_purview_label WHERE label_id NOT IN (${seen.map(() => '?').join(',')})`, seen);
  }
  console.log(`purviewLabels: ${labels.length} upserted`);
  await pool.end();
}

main().then(() => { console.log('collect-purview OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-purview FAILED:', e.message); process.exit(1); });
