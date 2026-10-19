// backfill-entra-managers.js — pulls manager relationships from Graph and writes
// entra_users.manager_upn. Deliberately separate from entra-sync.js: confirmed that
// script's INSERT/ON DUPLICATE KEY UPDATE never references manager_upn, so this can
// run on its own schedule without any risk of the two overwriting each other.
//
// Feeds manager-notification logic downstream (AI Usage & Credits, etc.) — accuracy
// matters more than raw speed here, so we explicitly clear manager_upn to NULL when
// Graph reports no manager (reorg, offboarded manager, etc.) rather than leaving stale
// data in place.
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
  const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
  if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
}

async function getToken() {
  const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: process.env.ENTRA_CLIENT_ID,
      client_secret: process.env.ENTRA_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
    }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error('token acquisition failed: ' + JSON.stringify(j));
  return j.access_token;
}

async function fetchAllUsersWithManager(token) {
  const select = 'id,userPrincipalName,displayName';
  let url = `https://graph.microsoft.com/v1.0/users?$filter=userType eq 'Member'&$select=${select}&$expand=manager($select=userPrincipalName,displayName)&$top=999`;
  const rows = [];
  while (url) {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) throw new Error(`Graph fetch failed: HTTP ${r.status} ${await r.text()}`);
    const j = await r.json();
    rows.push(...(j.value || []));
    url = j['@odata.nextLink'] || null;
  }
  return rows;
}

async function main() {
  const token = await getToken();
  const users = await fetchAllUsersWithManager(token);
  console.log(`Fetched ${users.length} users from Graph.`);

  const pool = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });

  let updated = 0, cleared = 0, skipped = 0;
  for (const u of users) {
    const upn = u.userPrincipalName;
    if (!upn) { skipped++; continue; }
    const managerUpn = u.manager && u.manager.userPrincipalName ? u.manager.userPrincipalName : null;
    const [result] = await pool.query(
      `UPDATE entra_users SET manager_upn = ? WHERE user_principal_name = ?`,
      [managerUpn, upn]
    );
    if (result.affectedRows > 0) {
      if (managerUpn) updated++; else cleared++;
    } else {
      skipped++; // not in entra_users at all (e.g. filtered out by entra-sync's own criteria)
    }
  }
  console.log(`Manager set: ${updated} · Manager cleared (no manager in Graph): ${cleared} · Not found in entra_users: ${skipped}`);
  await pool.end();
}

main().catch((e) => { console.error('[backfill-entra-managers]', e.message); process.exit(1); });
