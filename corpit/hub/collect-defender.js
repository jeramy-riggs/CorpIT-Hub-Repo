// collect-defender.js — Secure Score + Identity Protection (risky users, risk detections)
// Pattern matches collect-legacy-auth.js (2026-07-20). ENTRA_* creds, mysql2 pool via env.
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');

const LOOKBACK_DAYS = parseInt(process.env.DEFENDER_LOOKBACK_DAYS || '30', 10);

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

async function graphAll(url, token, cap = 50) {
  const out = [];
  let next = url, pages = 0;
  while (next && pages < cap) {
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

  // 1) Secure Score — latest daily snapshots
  const scores = await graphAll('https://graph.microsoft.com/v1.0/security/secureScores?$top=30', token, 2);
  for (const s of scores) {
    await pool.query(
      `INSERT INTO sentinel_secure_score (score_date, current_score, max_score, raw_json)
       VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE current_score=VALUES(current_score),
       max_score=VALUES(max_score), raw_json=VALUES(raw_json),
           -- forces the row to count as changed so the column's ON UPDATE
           -- CURRENT_TIMESTAMP fires; otherwise an unchanged row leaves
           -- collected_at frozen and the freshness stamp reads stale even though
           -- the collector is running fine.
           collected_at=CURRENT_TIMESTAMP`,
      [dt(s.createdDateTime).slice(0, 10), s.currentScore, s.maxScore, JSON.stringify(s)]
    );
  }
  console.log(`secureScore: ${scores.length} snapshots upserted`);

  // 2) Risky users (all states — table is a mirror)
  const risky = await graphAll('https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$top=500', token);
  for (const u of risky) {
    await pool.query(
      `INSERT INTO sentinel_risky_user (risk_user_id, upn, display_name, risk_level, risk_state, risk_detail, last_updated_dt, raw_json)
       VALUES (?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE upn=VALUES(upn), display_name=VALUES(display_name),
       risk_level=VALUES(risk_level), risk_state=VALUES(risk_state), risk_detail=VALUES(risk_detail),
       last_updated_dt=VALUES(last_updated_dt), raw_json=VALUES(raw_json),
           -- forces the row to count as changed so the column's ON UPDATE
           -- CURRENT_TIMESTAMP fires; otherwise an unchanged row leaves
           -- collected_at frozen and the freshness stamp reads stale even though
           -- the collector is running fine.
           collected_at=CURRENT_TIMESTAMP`,
      [u.id, u.userPrincipalName, u.userDisplayName, u.riskLevel, u.riskState, u.riskDetail,
       dt(u.riskLastUpdatedDateTime), JSON.stringify(u)]
    );
  }
  console.log(`riskyUsers: ${risky.length} upserted`);

  // 3) Risk detections — lookback window
  const since = new Date(Date.now() - LOOKBACK_DAYS * 86400e3).toISOString();
  const dets = await graphAll(
    `https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=detectedDateTime ge ${since}&$top=500`,
    token
  );
  for (const d of dets) {
    const loc = [d.location?.city, d.location?.countryOrRegion].filter(Boolean).join(', ') || null;
    await pool.query(
      `INSERT INTO sentinel_risk_detection (detection_id, upn, risk_event_type, risk_level, risk_state, detected_dt, ip_address, location, raw_json)
       VALUES (?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE risk_level=VALUES(risk_level), risk_state=VALUES(risk_state), raw_json=VALUES(raw_json)`,
      [d.id, d.userPrincipalName, d.riskEventType, d.riskLevel, d.riskState,
       dt(d.detectedDateTime), d.ipAddress, loc, JSON.stringify(d)]
    );
  }
  console.log(`riskDetections: ${dets.length} upserted (lookback ${LOOKBACK_DAYS}d)`);

  await pool.end();
}

main().then(() => { console.log('collect-defender OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-defender FAILED:', e.message); process.exit(1); });
