// collect-tenant-insights.js — SKUs, per-user M365 activity, service principals, PP flows
// Daily. ENTRA_* (Graph) + PPADMIN_* (flow admin API). Pattern: collect-defender.js, 2026-07-23.
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const mysql = require('mysql2/promise');

async function tok(tenant, id, secret, scope) {
  const r = await fetch(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: id, client_secret: secret, scope, grant_type: 'client_credentials' }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('token failed for ' + scope + ': ' + JSON.stringify(j).slice(0, 150));
  return j.access_token;
}

function parseCsv(text) {
  const rows = [];
  let row = [], field = '', inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; } else field += c; }
    else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field.replace(/\r$/, '')); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field !== '' || row.length) { row.push(field.replace(/\r$/, '')); rows.push(row); }
  const header = rows.shift();
  return rows.filter((r) => r.length === header.length)
    .map((r) => Object.fromEntries(header.map((h, i) => [h.trim(), r[i]])));
}

const d = (s) => (s && String(s).trim() && !String(s).startsWith('0001') ? String(s).trim().slice(0, 10) : null);
const dt = (s) => (s ? new Date(s).toISOString().slice(0, 19).replace('T', ' ') : null);

async function main() {
  const g = await tok(process.env.ENTRA_TENANT_ID, process.env.ENTRA_CLIENT_ID, process.env.ENTRA_CLIENT_SECRET, 'https://graph.microsoft.com/.default');
  const GH = { Authorization: 'Bearer ' + g };
  const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });

  // 1) SKUs
  let r = await fetch('https://graph.microsoft.com/v1.0/subscribedSkus', { headers: GH });
  if (!r.ok) throw new Error('subscribedSkus ' + r.status);
  const skus = (await r.json()).value || [];
  for (const s of skus) {
    await pool.query(
      `INSERT INTO insight_sku (sku_id, sku_part_number, consumed, enabled, suspended, warning, raw_json)
       VALUES (?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE sku_part_number=VALUES(sku_part_number), consumed=VALUES(consumed),
         enabled=VALUES(enabled), suspended=VALUES(suspended), warning=VALUES(warning), raw_json=VALUES(raw_json)`,
      [s.skuId, s.skuPartNumber, s.consumedUnits, s.prepaidUnits?.enabled ?? 0,
       s.prepaidUnits?.suspended ?? 0, s.prepaidUnits?.warning ?? 0, JSON.stringify(s)]
    );
  }
  console.log(`skus: ${skus.length} upserted`);

  // 2) per-user activity (merge activations + per-service last-activity reports)
  const reports = {
    base: "getOffice365ActiveUserDetail(period='D30')",
    teams: "getTeamsUserActivityUserDetail(period='D30')",
  };
  const users = {};
  r = await fetch('https://graph.microsoft.com/v1.0/reports/' + reports.base, { headers: GH });
  if (!r.ok) throw new Error('activeUserDetail ' + r.status);
  for (const row of parseCsv(await r.text())) {
    if (row['Is Deleted'] === 'True') continue;
    users[row['User Principal Name']] = {
      licenses: row['Assigned Products'] || '',
      exchange_last: d(row['Exchange Last Activity Date']),
      onedrive_last: d(row['OneDrive Last Activity Date']),
      sharepoint_last: d(row['SharePoint Last Activity Date']),
      teams_last: d(row['Teams Last Activity Date']),
      report_date: d(row['Report Refresh Date']),
    };
  }
  r = await fetch('https://graph.microsoft.com/v1.0/reports/' + reports.teams, { headers: GH });
  if (r.ok) for (const row of parseCsv(await r.text())) {
    const u = users[row['User Principal Name']];
    if (u && d(row['Last Activity Date'])) u.teams_last = d(row['Last Activity Date']);
  }
  for (const [upn, u] of Object.entries(users)) {
    await pool.query(
      `INSERT INTO insight_user_activity (upn, licenses, exchange_last, onedrive_last, sharepoint_last, teams_last, report_date)
       VALUES (?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE licenses=VALUES(licenses), exchange_last=VALUES(exchange_last),
         onedrive_last=VALUES(onedrive_last), sharepoint_last=VALUES(sharepoint_last),
         teams_last=VALUES(teams_last), report_date=VALUES(report_date)`,
      [upn, u.licenses, u.exchange_last, u.onedrive_last, u.sharepoint_last, u.teams_last, u.report_date]
    );
  }
  console.log(`userActivity: ${Object.keys(users).length} upserted`);

  // 3) service principals (paged)
  let url = 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=999&$select=id,appId,displayName,publisherName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,createdDateTime';
  let spCount = 0, pages = 0;
  while (url && pages < 20) {
    const rr = await fetch(url, { headers: GH });
    if (!rr.ok) throw new Error('servicePrincipals ' + rr.status);
    const j = await rr.json();
    for (const sp of j.value || []) {
      await pool.query(
        `INSERT INTO insight_service_principal (sp_id, app_id, display_name, publisher, sp_type, account_enabled, app_owner_org, created_dt, raw_json)
         VALUES (?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), publisher=VALUES(publisher),
           sp_type=VALUES(sp_type), account_enabled=VALUES(account_enabled),
           app_owner_org=VALUES(app_owner_org), created_dt=VALUES(created_dt), raw_json=VALUES(raw_json)`,
        [sp.id, sp.appId, sp.displayName, sp.publisherName, sp.servicePrincipalType,
         sp.accountEnabled ? 1 : 0, sp.appOwnerOrganizationId || null, dt(sp.createdDateTime), JSON.stringify(sp)]
      );
      spCount++;
    }
    url = j['@odata.nextLink'];
    pages++;
  }
  console.log(`servicePrincipals: ${spCount} upserted (${pages} pages)`);

  // 3b) sign-in activity for all SPs (single report)
  try {
    let su = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999';
    let sPages = 0, sCount = 0;
    while (su && sPages < 10) {
      const rr = await fetch(su, { headers: GH });
      if (!rr.ok) { console.log('signInActivities: HTTP ' + rr.status + ' (skipped)'); break; }
      const j = await rr.json();
      for (const a of j.value || []) {
        const last = a.lastSignInActivity?.lastSignInDateTime || null;
        if (!last) continue;
        await pool.query(
          `UPDATE insight_service_principal SET last_signin_dt = ? WHERE app_id = ?`,
          [dt(last), a.appId]);
        sCount++;
      }
      su = j['@odata.nextLink']; sPages++;
    }
    console.log(`spSignInActivity: ${sCount} SPs updated`);
  } catch (e) { console.log('spSignInActivity failed:', e.message); }

  // 3c) consent grants for third-party SPs only
  const MS_ORG = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
  const [tps] = await pool.query(
    `SELECT sp_id FROM insight_service_principal
     WHERE sp_type = 'Application' AND app_owner_org IS NOT NULL
       AND app_owner_org NOT IN (?, ?)`, [MS_ORG, process.env.ENTRA_TENANT_ID || '']);
  let gCount = 0;
  for (const row of tps) {
    try {
      const [gr, ar] = await Promise.all([
        fetch(`https://graph.microsoft.com/v1.0/servicePrincipals/${row.sp_id}/oauth2PermissionGrants`, { headers: GH }).then((r) => r.ok ? r.json() : { value: [] }),
        fetch(`https://graph.microsoft.com/v1.0/servicePrincipals/${row.sp_id}/appRoleAssignments`, { headers: GH }).then((r) => r.ok ? r.json() : { value: [] }),
      ]);
      const grants = gr.value || [];
      const scopes = [...new Set(grants.flatMap((g) => String(g.scope || '').trim().split(/\s+/)))].filter(Boolean).join(' ');
      const admin = grants.some((g) => g.consentType === 'AllPrincipals');
      const userIds = [...new Set(grants.filter((g) => g.principalId).map((g) => g.principalId))];
      await pool.query(
        `UPDATE insight_service_principal SET delegated_scopes = ?, consent_type = ?, consented_by = ?, app_role_count = ? WHERE sp_id = ?`,
        [scopes || null, grants.length ? (admin ? 'admin' : 'user') : (ar.value?.length ? 'admin' : null),
         userIds.slice(0, 5).join(',') || null, (ar.value || []).length, row.sp_id]);
      gCount++;
    } catch (e) { /* per-SP failure tolerated */ }
  }
  console.log(`spConsent: ${gCount}/${tps.length} third-party SPs enriched`);

  // 4) flows across all PP environments
  const f = await tok(process.env.PPADMIN_TENANT_ID, process.env.PPADMIN_CLIENT_ID, process.env.PPADMIN_CLIENT_SECRET, 'https://service.flow.microsoft.com/.default');
  const [envs] = await pool.query('SELECT env_id FROM sentinel_pp_environment');
  let flowCount = 0;
  for (const e of envs) {
    const rr = await fetch(`https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/${e.env_id}/v2/flows?api-version=2016-11-01`,
      { headers: { Authorization: 'Bearer ' + f } });
    if (!rr.ok) { console.log(`flows[${e.env_id}]: HTTP ${rr.status} (skipped)`); continue; }
    for (const fl of (await rr.json()).value || []) {
      const p = fl.properties || {};
      await pool.query(
        `INSERT INTO insight_flow (flow_id, env_id, display_name, state, created_dt, modified_dt, owner_id, raw_json)
         VALUES (?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), state=VALUES(state),
           modified_dt=VALUES(modified_dt), raw_json=VALUES(raw_json)`,
        [fl.name, e.env_id, p.displayName, p.state, dt(p.createdTime), dt(p.lastModifiedTime),
         p.creator?.userId || null, JSON.stringify(fl).slice(0, 60000)]
      );
      flowCount++;
    }
  }
  console.log(`flows: ${flowCount} upserted across ${envs.length} environments`);

  await pool.end();
}

main().then(() => { console.log('collect-tenant-insights OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-tenant-insights FAILED:', e.message); process.exit(1); });
