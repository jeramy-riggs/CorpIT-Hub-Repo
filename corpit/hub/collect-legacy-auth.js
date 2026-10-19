#!/usr/bin/env node
/**
 * collect-legacy-auth.js — Tenant Sentinel collector
 * Pulls Entra sign-in logs for legacy authentication clients via Graph
 * (auditLogs/signIns, requires AuditLog.Read.All — ENTRA_* app already has it).
 *
 * Mirrors collect-lockouts.js: ENTRA_* env creds from /var/www/corpit-hub-api/.env,
 * upsert into sentinel_legacy_signin (duplicate-safe on Graph sign-in id).
 *
 * Env:
 *   LEGACY_LOOKBACK_HOURS  default 24 (use 720 for 30-day backfill)
 *
 * Cron: 25,55 * * * *  -> /home/ubuntu/collect-legacy-auth.log
 */
'use strict';
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const mysql = require('mysql2/promise');

const TENANT = process.env.ENTRA_TENANT_ID;
const CLIENT_ID = process.env.ENTRA_CLIENT_ID;
const CLIENT_SECRET = process.env.ENTRA_CLIENT_SECRET;
const LOOKBACK_HOURS = parseInt(process.env.LEGACY_LOOKBACK_HOURS || '24', 10);

// clientAppUsed values Microsoft classifies as legacy authentication
const LEGACY_CLIENTS = [
  'Exchange ActiveSync',
  'IMAP4',
  'POP3',
  'SMTP',
  'Authenticated SMTP',
  'Exchange Web Services',
  'MAPI Over HTTP',
  'Offline Address Book',
  'Outlook Anywhere (RPC over HTTP)',
  'Exchange Online PowerShell',
  'Autodiscover',
  'Reporting Web Services',
  'Other clients',
];

async function getToken() {
  const res = await fetch(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
  });
  if (!res.ok) throw new Error(`token ${res.status}: ${await res.text()}`);
  return (await res.json()).access_token;
}

async function fetchLegacySignIns(token, sinceIso) {
  const rows = [];
  for (const client of LEGACY_CLIENTS) {
    // one filtered query per legacy client keeps result sets small and server-side
    let url =
      'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=500&$filter=' +
      encodeURIComponent(`createdDateTime ge ${sinceIso} and clientAppUsed eq '${client}'`);
    while (url) {
      const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (res.status === 429) {
        const wait = parseInt(res.headers.get('retry-after') || '5', 10);
        await new Promise((r) => setTimeout(r, wait * 1000));
        continue;
      }
      if (!res.ok) throw new Error(`signIns(${client}) ${res.status}: ${await res.text()}`);
      const data = await res.json();
      rows.push(...(data.value || []));
      url = data['@odata.nextLink'] || null;
    }
  }
  return rows;
}

(async () => {
  const started = new Date();
  console.log(`[${started.toISOString()}] collect-legacy-auth start (lookback ${LOOKBACK_HOURS}h)`);

  const since = new Date(Date.now() - LOOKBACK_HOURS * 3600 * 1000).toISOString();
  const token = await getToken();
  const signins = await fetchLegacySignIns(token, since);
  console.log(`fetched ${signins.length} legacy sign-in events since ${since}`);

  const db = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });

  let upserts = 0;
  for (const s of signins) {
    await db.execute(
      `INSERT INTO sentinel_legacy_signin
         (id, created_at, upn, display_name, client_app, app_display_name,
          ip_address, country, error_code, raw_json)
       VALUES (?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE error_code = VALUES(error_code)`,
      [
        s.id,
        s.createdDateTime ? new Date(s.createdDateTime) : null,
        s.userPrincipalName || null,
        s.userDisplayName || null,
        s.clientAppUsed || null,
        s.appDisplayName || null,
        s.ipAddress || null,
        (s.location && s.location.countryOrRegion) || null,
        s.status ? s.status.errorCode : null,
        JSON.stringify(s),
      ]
    );
    upserts++;
  }
  await db.end();
  console.log(`[${new Date().toISOString()}] done — ${upserts} rows upserted`);
})().catch((e) => {
  console.error(`[${new Date().toISOString()}] FATAL`, e.message);
  process.exit(1);
});
