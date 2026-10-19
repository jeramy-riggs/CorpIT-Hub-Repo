// collect-copilot-usage.js — pulls Graph's per-app Copilot activity report and upserts it.
// Run from /var/www/corpit-hub-api/ (needs its node_modules for mysql2). Cron candidate: e.g. `20 * * * *`.
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

// Load env the same way the other collectors in this directory do.
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

async function fetchAll(token) {
  let url = "https://graph.microsoft.com/beta/reports/getMicrosoft365CopilotUsageUserDetail(period='D7')?$format=application/json";
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

const nullIfBlank = (v) => (v ? v : null);

async function main() {
  const token = await getToken();
  const rows = await fetchAll(token);
  console.log(`Fetched ${rows.length} rows from Graph.`);

  const pool = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });

  let upserted = 0;
  for (const u of rows) {
    const email = (u.userPrincipalName || '').toLowerCase();
    if (!email) continue;
    await pool.query(
      `INSERT INTO copilot_app_usage
        (email, display_name, last_activity_date, chat_last_active, teams_last_active, word_last_active,
         excel_last_active, powerpoint_last_active, outlook_last_active, onenote_last_active, loop_last_active,
         report_refresh_date)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         display_name=VALUES(display_name), last_activity_date=VALUES(last_activity_date),
         chat_last_active=VALUES(chat_last_active), teams_last_active=VALUES(teams_last_active),
         word_last_active=VALUES(word_last_active), excel_last_active=VALUES(excel_last_active),
         powerpoint_last_active=VALUES(powerpoint_last_active), outlook_last_active=VALUES(outlook_last_active),
         onenote_last_active=VALUES(onenote_last_active), loop_last_active=VALUES(loop_last_active),
         report_refresh_date=VALUES(report_refresh_date)`,
      [
        email,
        u.displayName || null,
        nullIfBlank(u.lastActivityDate),
        nullIfBlank(u.copilotChatLastActivityDate),
        nullIfBlank(u.microsoftTeamsCopilotLastActivityDate),
        nullIfBlank(u.wordCopilotLastActivityDate),
        nullIfBlank(u.excelCopilotLastActivityDate),
        nullIfBlank(u.powerPointCopilotLastActivityDate),
        nullIfBlank(u.outlookCopilotLastActivityDate),
        nullIfBlank(u.oneNoteCopilotLastActivityDate),
        nullIfBlank(u.loopCopilotLastActivityDate),
        nullIfBlank(u.reportRefreshDate),
      ]
    );
    upserted++;
  }
  console.log(`Upserted ${upserted} rows into copilot_app_usage.`);
  await pool.end();
}

main().catch((e) => { console.error('[collect-copilot-usage]', e.message); process.exit(1); });
