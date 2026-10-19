// collect-incidents.js — Defender XDR incidents (Graph /security/incidents).
// Pattern matches collect-defender.js (2026-08-15).
//
// NOTE ON CREDENTIALS: this uses AZURE_* (app "IT Inventory App-Graph"), not
// ENTRA_*. Only the AZURE_* app holds SecurityIncident.Read.All; the ENTRA_*
// app returns 403 on /security/incidents.
//
// NOTE ON $top: Graph silently returns an EMPTY value[] for $top > 50 on this
// endpoint (verified 2026-08-15: top=50 -> 15 rows, top=51 -> 0 rows). Never
// raise PAGE_SIZE above 50 — paging is via @odata.nextLink.
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');

const PAGE_SIZE = 50;
const PAGE_CAP  = 40;

async function getToken() {
  const r = await fetch(`https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.AZURE_CLIENT_ID,
      client_secret: process.env.AZURE_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('token fetch failed: ' + JSON.stringify(j));
  return j.access_token;
}

async function graphAll(url, token) {
  const out = [];
  let next = url, pages = 0;
  while (next && pages < PAGE_CAP) {
    const r = await fetch(next, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error(`Graph ${r.status} on ${next}: ${await r.text()}`);
    const j = await r.json();
    out.push(...(j.value || []));
    next = j['@odata.nextLink'];
    pages++;
  }
  return out;
}

const dt = (s) => (s ? new Date(s).toISOString().slice(0, 19).replace('T', ' ') : null);

async function main() {
  const token = await getToken();
  const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });

  const incidents = await graphAll(
    `https://graph.microsoft.com/v1.0/security/incidents?$top=${PAGE_SIZE}`, token);

  for (const i of incidents) {
    await pool.query(
      `INSERT INTO sentinel_incident
         (incident_id, display_name, status, severity, classification, determination,
          assigned_to, web_url, created_dt, last_update_dt, raw_json)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         display_name=VALUES(display_name), status=VALUES(status), severity=VALUES(severity),
         classification=VALUES(classification), determination=VALUES(determination),
         assigned_to=VALUES(assigned_to), web_url=VALUES(web_url),
         created_dt=VALUES(created_dt), last_update_dt=VALUES(last_update_dt),
         raw_json=VALUES(raw_json),
         -- forces the row to count as changed so the column's ON UPDATE
         -- CURRENT_TIMESTAMP fires; otherwise an unchanged incident leaves
         -- collected_at frozen and the freshness stamp reads stale even though
         -- the collector is running fine.
         collected_at=CURRENT_TIMESTAMP`,
      [String(i.id), i.displayName || null, i.status || null, i.severity || null,
       i.classification || null, i.determination || null,
       i.assignedTo || null, i.incidentWebUrl || null,
       dt(i.createdDateTime), dt(i.lastUpdateDateTime), JSON.stringify(i)]
    );
  }

  const active = incidents.filter(i => i.status === 'active' || i.status === 'inProgress').length;
  console.log(`incidents: ${incidents.length} upserted, ${active} active/inProgress`);

  await pool.end();
}

main().then(() => { console.log('collect-incidents OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-incidents FAILED:', e.message); process.exit(1); });
