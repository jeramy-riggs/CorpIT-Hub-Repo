// collect-powerplatform.js — Power Platform environments + DLP policies (BAP admin API)
// PPADMIN_* creds (IT-Command-PowerPlatform-Admin SP). Pattern: collect-defender.js, 2026-07-20.
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');

async function getToken() {
  const r = await fetch(`https://login.microsoftonline.com/${process.env.PPADMIN_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.PPADMIN_CLIENT_ID,
      client_secret: process.env.PPADMIN_CLIENT_SECRET,
      scope: 'https://api.bap.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('token fetch failed: ' + JSON.stringify(j).slice(0, 200));
  return j.access_token;
}

const dt = (s) => (s ? new Date(s).toISOString().slice(0, 19).replace('T', ' ') : null);

async function main() {
  const token = await getToken();
  const H = { Authorization: 'Bearer ' + token };
  const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });

  // 1) environments
  let r = await fetch('https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01', { headers: H });
  if (!r.ok) throw new Error(`environments: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  const envs = (await r.json()).value || [];
  const seen = [];
  for (const e of envs) {
    const p = e.properties || {};
    seen.push(e.name);
    await pool.query(
      `INSERT INTO sentinel_pp_environment (env_id, display_name, sku, is_default, state, created_dt, raw_json)
       VALUES (?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), sku=VALUES(sku), is_default=VALUES(is_default),
         state=VALUES(state), created_dt=VALUES(created_dt), raw_json=VALUES(raw_json)`,
      [e.name, p.displayName, p.environmentSku, p.isDefault ? 1 : 0,
       p.states?.management?.id || null, dt(p.createdTime), JSON.stringify(e)]
    );
  }
  // remove environments deleted upstream
  if (seen.length) {
    await pool.query(`DELETE FROM sentinel_pp_environment WHERE env_id NOT IN (${seen.map(() => '?').join(',')})`, seen);
  }
  console.log(`ppEnvironments: ${envs.length} upserted`);

  // 2) DLP policies
  r = await fetch('https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v2/policies', { headers: H });
  if (!r.ok) throw new Error(`dlpPolicies: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  const pols = (await r.json()).value || [];
  await pool.query('DELETE FROM sentinel_pp_dlp_policy'); // full mirror, small table
  for (const p of pols) {
    await pool.query(
      `INSERT INTO sentinel_pp_dlp_policy (policy_id, display_name, env_type, raw_json) VALUES (?,?,?,?)`,
      [p.name || p.id, p.displayName, p.environmentType || null, JSON.stringify(p)]
    );
  }
  console.log(`ppDlpPolicies: ${pols.length} stored`);

  await pool.end();
}

main().then(() => { console.log('collect-powerplatform OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-powerplatform FAILED:', e.message); process.exit(1); });
