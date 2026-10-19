// collect-m365-reports.js — Exchange mailbox usage + SharePoint site/user reports (Reports.Read.All)
// Pattern: collect-defender.js (2026-07-20). CSV endpoints, parsed by header name.
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

// minimal CSV parser with quoted-field support
function parseCsv(text) {
  const rows = [];
  let row = [], field = '', inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field.replace(/\r$/, '')); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field !== '' || row.length) { row.push(field.replace(/\r$/, '')); rows.push(row); }
  const header = rows.shift();
  return rows.filter((r) => r.length === header.length)
    .map((r) => Object.fromEntries(header.map((h, i) => [h.trim(), r[i]])));
}

async function fetchReport(name, token) {
  const r = await fetch(`https://graph.microsoft.com/v1.0/reports/${name}(period='D30')`, {
    headers: { Authorization: 'Bearer ' + token },
  });
  if (!r.ok) throw new Error(`${name}: Graph ${r.status} ${(await r.text()).slice(0, 200)}`);
  return parseCsv(await r.text());
}

const d = (s) => (s && s.trim() ? s.trim() : null);
const n = (s) => (s && s.trim() ? Number(s) : 0);

async function main() {
  const token = await getToken();
  const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });

  // 1) Mailbox usage
  const mbx = (await fetchReport('getMailboxUsageDetail', token)).filter((r) => r['Is Deleted'] !== 'True');
  for (const r of mbx) {
    await pool.query(
      `INSERT INTO sentinel_mailbox_usage
         (upn, display_name, last_activity_date, item_count, storage_used_b, prohibit_send_b, prohibit_send_receive_b, has_archive, report_date)
       VALUES (?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), last_activity_date=VALUES(last_activity_date),
         item_count=VALUES(item_count), storage_used_b=VALUES(storage_used_b), prohibit_send_b=VALUES(prohibit_send_b),
         prohibit_send_receive_b=VALUES(prohibit_send_receive_b), has_archive=VALUES(has_archive), report_date=VALUES(report_date),
           -- forces the row to count as changed so the column's ON UPDATE
           -- CURRENT_TIMESTAMP fires; otherwise an unchanged row leaves
           -- collected_at frozen and the freshness stamp reads stale even though
           -- the collector is running fine.
           collected_at=CURRENT_TIMESTAMP`,
      [r['User Principal Name'], r['Display Name'], d(r['Last Activity Date']), n(r['Item Count']),
       n(r['Storage Used (Byte)']), n(r['Prohibit Send Quota (Byte)']), n(r['Prohibit Send/Receive Quota (Byte)']),
       r['Has Archive'] === 'True' ? 1 : 0, d(r['Report Refresh Date'])]
    );
  }
  console.log(`mailboxUsage: ${mbx.length} upserted`);

  // 2) SharePoint site usage
  const sites = (await fetchReport('getSharePointSiteUsageDetail', token)).filter((r) => r['Is Deleted'] !== 'True');
  for (const r of sites) {
    await pool.query(
      `INSERT INTO sentinel_sp_site
         (site_id, site_url, owner_name, last_activity_date, file_count, active_file_count, storage_used_b, root_type, report_date)
       VALUES (?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE site_url=VALUES(site_url), owner_name=VALUES(owner_name),
         last_activity_date=VALUES(last_activity_date), file_count=VALUES(file_count),
         active_file_count=VALUES(active_file_count), storage_used_b=VALUES(storage_used_b),
         root_type=VALUES(root_type), report_date=VALUES(report_date),
           -- forces the row to count as changed so the column's ON UPDATE
           -- CURRENT_TIMESTAMP fires; otherwise an unchanged row leaves
           -- collected_at frozen and the freshness stamp reads stale even though
           -- the collector is running fine.
           collected_at=CURRENT_TIMESTAMP`,
      [r['Site Id'], r['Site URL'], r['Owner Display Name'], d(r['Last Activity Date']),
       n(r['File Count']), n(r['Active File Count']), n(r['Storage Used (Byte)']),
       r['Root Web Template'] || null, d(r['Report Refresh Date'])]
    );
  }
  console.log(`spSites: ${sites.length} upserted`);

  // 3) SharePoint user activity (external sharing signal)
  const act = (await fetchReport('getSharePointActivityUserDetail', token)).filter((r) => r['Is Deleted'] !== 'True');
  for (const r of act) {
    await pool.query(
      `INSERT INTO sentinel_sp_user_activity
         (upn, last_activity_date, viewed_edited_files, shared_internally, shared_externally, report_date)
       VALUES (?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE last_activity_date=VALUES(last_activity_date),
         viewed_edited_files=VALUES(viewed_edited_files), shared_internally=VALUES(shared_internally),
         shared_externally=VALUES(shared_externally), report_date=VALUES(report_date)`,
      [r['User Principal Name'], d(r['Last Activity Date']), n(r['Viewed Or Edited File Count']),
       n(r['Shared Internally File Count']), n(r['Shared Externally File Count']), d(r['Report Refresh Date'])]
    );
  }
  console.log(`spUserActivity: ${act.length} upserted`);

  // 4) Tenant-total SharePoint storage (authoritative — includes recycle bin + version history)
  {
    const rr = await fetch(`https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageStorage(period='D7')`,
      { headers: { Authorization: 'Bearer ' + token } });
    if (!rr.ok) throw new Error(`SiteUsageStorage: Graph ${rr.status} ${(await rr.text()).slice(0,200)}`);
    const trows = parseCsv(await rr.text()).filter((x) => (x['Site Type'] || '').trim() === 'All');
    trows.sort((a, b) => String(b['Report Date']).localeCompare(String(a['Report Date'])));
    const latest = trows[0];
    if (latest) {
      const used = n(latest['Storage Used (Byte)']);
      const rptDate = d(latest['Report Date']) || d(latest['Report Refresh Date']);
      await pool.query(
        `INSERT INTO tenant_storage_snapshots (snap_date, used_bytes, report_date, source)
         VALUES (CURDATE(), ?, ?, 'graph:getSharePointSiteUsageStorage D7')
         ON DUPLICATE KEY UPDATE used_bytes=VALUES(used_bytes), report_date=VALUES(report_date), source=VALUES(source)`,
        [used, rptDate]);
      console.log(`tenantStorage: ${used} bytes (report ${rptDate})`);
    } else { console.log('tenantStorage: no "All" row found'); }
  }


  await pool.end();
}

main().then(() => { console.log('collect-m365-reports OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-m365-reports FAILED:', e.message); process.exit(1); });
