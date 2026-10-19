'use strict';
// SIGNIN-WATCH-BACKFILL v1.0 — historical pull for investigations
// Marker: SIGNIN-WATCH-BACKFILL
// Usage:
//   node signin-watch-backfill.js --upn=hsharp@auction.com [--days=90] [--source=okta|entra|both]
// Pulls as far back as each API retains (Okta ~90d, Entra ~30d), runs every
// sign-in through the trusted-network check, inserts violations idempotently
// (INSERT IGNORE on source+event id — safe to re-run, never duplicates).
// DOES NOT send alerts — historical rows land in the feed silently.
require('dotenv').config();
const mysql = require('mysql2/promise');
const { ipTrusted, normalizeOktaEvent, normalizeEntraEvent, fmtDateTimeSql } = require('/var/www/corpit-hub-api/signin-watch-lib.js');

const args = {};
for (const a of process.argv.slice(2)) { const m = a.match(/^--([^=]+)=(.*)$/); if (m) args[m[1]] = m[2]; }
const UPN = (args.upn || '').toLowerCase();
const DAYS = Math.min(parseInt(args.days || '90', 10), 365);
const SOURCE = args.source || 'both';
if (!UPN) { console.error('usage: node signin-watch-backfill.js --upn=user@auction.com [--days=90] [--source=okta|entra|both]'); process.exit(1); }
const { oktaFilterValue } = require('/var/www/corpit-hub-api/okta-lookup.js');
if (!oktaFilterValue(UPN)) { console.error('refusing --upn: not a plausible login/email (it is spliced into an Okta filter string)'); process.exit(1); }

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
});
const log = (...a) => console.log(new Date().toISOString(), '[backfill]', ...a);

async function entraToken() {
  const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: process.env.ENTRA_CLIENT_ID, client_secret: process.env.ENTRA_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' }),
    signal: AbortSignal.timeout(15000) });
  const j = await r.json();
  if (!j.access_token) throw new Error('entra token: ' + (j.error_description || j.error));
  return j.access_token;
}

async function insertQuiet(v) {
  const [r] = await pool.query(
    `INSERT IGNORE INTO signin_violations
       (upn, source, source_event_id, event_time, ip, geo_country, geo_city, result,
        failure_reason, app_name, client_app, user_agent, raw_json, alert_sent, alert_channels_hit)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'backfill: alerts suppressed')`,
    [v.upn, v.source, v.source_event_id, fmtDateTimeSql(v.event_time), v.ip,
     v.geo_country, v.geo_city, v.result, v.failure_reason,
     v.app_name ? String(v.app_name).slice(0, 200) : null,
     v.client_app ? String(v.client_app).slice(0, 200) : null,
     v.user_agent ? String(v.user_agent).slice(0, 500) : null,
     JSON.stringify(v.raw)]);
  return r.affectedRows > 0;
}

const OKTA_EVENT_RE = /^user\.(session\.start|authentication\.)/;

async function backfillOkta(nets, sinceIso) {
  // filter server-side by actor to keep volume sane over 90 days
  const filter = `actor.alternateId eq "${UPN}"`;
  let url = `${process.env.OKTA_BASE_URL}/api/v1/logs?since=${encodeURIComponent(sinceIso)}&filter=${encodeURIComponent(filter)}&sortOrder=ASCENDING&limit=1000`;
  let scanned = 0, matched = 0, violations = 0, pages = 0;
  while (url && pages < 100) {
    const r = await fetch(url, { headers: { Authorization: 'SSWS ' + process.env.OKTA_API_TOKEN }, signal: AbortSignal.timeout(90000) });
    if (r.status === 429) { const wait = parseInt(r.headers.get('x-rate-limit-reset') || '2', 10); log('okta 429, waiting'); await new Promise(s => setTimeout(s, 3000)); continue; }
    if (r.status !== 200) throw new Error('okta HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    const events = await r.json();
    if (!events.length) break;
    for (const ev of events) {
      scanned++;
      if (!OKTA_EVENT_RE.test(ev.eventType || '')) continue;
      matched++;
      const v = normalizeOktaEvent(ev);
      if (ipTrusted(v.ip, nets)) continue;
      if (await insertQuiet(v)) violations++;
    }
    pages++;
    const link = r.headers.get('link') || '';
    const m = link.match(/<([^>]+)>;\s*rel="next"/);
    url = m ? m[1] : null;
  }
  log(`okta: scanned=${scanned} auth-events=${matched} new-violations=${violations} pages=${pages}`);
  return violations;
}

async function backfillEntra(nets, sinceIso) {
  const token = await entraToken();
  const filter = `userPrincipalName eq '${UPN.replace(/'/g, "''")}' and createdDateTime gt ${sinceIso}`;
  let url = `https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=${encodeURIComponent(filter)}&$top=999`;
  let scanned = 0, violations = 0, pages = 0;
  while (url && pages < 100) {
    const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token }, signal: AbortSignal.timeout(90000) });
    if (r.status === 429) { log('entra 429, waiting'); await new Promise(s => setTimeout(s, 5000)); continue; }
    if (r.status !== 200) throw new Error('entra HTTP ' + r.status + ': ' + (await r.text()).slice(0, 300));
    const j = await r.json();
    for (const ev of (j.value || [])) {
      scanned++;
      const v = normalizeEntraEvent(ev);
      if (ipTrusted(v.ip, nets)) continue;
      if (await insertQuiet(v)) violations++;
    }
    url = j['@odata.nextLink'] || null;
    pages++;
  }
  log(`entra: scanned=${scanned} new-violations=${violations} pages=${pages}`);
  return violations;
}

(async () => {
  const since = new Date(Date.now() - DAYS * 86400000).toISOString();
  log(`backfilling ${UPN} since ${since} (${DAYS}d) source=${SOURCE}`);
  const [nets] = await pool.query('SELECT cidr, enabled FROM trusted_networks WHERE enabled = 1');
  log(`trusted networks loaded: ${nets.length}`);
  let total = 0;
  if (SOURCE === 'okta' || SOURCE === 'both') {
    try { total += await backfillOkta(nets, since); } catch (e) { console.error('[backfill] okta failed:', e.message); }
  }
  if (SOURCE === 'entra' || SOURCE === 'both') {
    try { total += await backfillEntra(nets, since); } catch (e) { console.error('[backfill] entra failed:', e.message); }
  }
  log(`DONE — ${total} new violation rows inserted (alerts suppressed)`);
  await pool.end();
})().catch(e => { console.error('[backfill] FAILED:', e.message); process.exit(1); });
