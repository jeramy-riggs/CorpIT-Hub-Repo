// collect-lockouts.js
// Pulls Entra sign-in failures with errorCode 50053 (account locked) from
// Microsoft Graph and upserts into sdops_lockout. Duplicate-safe on id.
// Manual run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node collect-lockouts.js

const mysql = require('mysql2/promise');
const { ipTrustedType } = require('./signin-watch-lib');
const US_COUNTRY_VALUES = new Set(['us', 'usa', 'united states', 'united states of america']);
function isUsCountry(c) { return !!c && US_COUNTRY_VALUES.has(String(c).trim().toLowerCase()); }
const IMPOSSIBLE_TRAVEL_HOURS = parseInt(process.env.SIGNIN_WATCH_IMPOSSIBLE_TRAVEL_HOURS || '4', 10);

const LOOKBACK_HOURS = parseInt(process.env.LOCKOUT_LOOKBACK_HOURS || '24', 10);

async function getPool() {
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 5,
  });
}

async function getToken() {
  const res = await fetch(
    `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.ENTRA_CLIENT_ID,
        client_secret: process.env.ENTRA_CLIENT_SECRET,
        scope: 'https://graph.microsoft.com/.default',
        grant_type: 'client_credentials',
      }),
    }
  );
  const data = await res.json();
  if (!data.access_token) throw new Error('Token failure: ' + JSON.stringify(data));
  return data.access_token;
}

async function fetchLockouts(token) {
  const since = new Date(Date.now() - LOOKBACK_HOURS * 3600 * 1000)
    .toISOString().replace(/\.\d{3}Z$/, 'Z');
  const filter = encodeURIComponent(
    `status/errorCode eq 50053 and createdDateTime ge ${since}`
  );
  let url = `https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=${filter}&$top=100`;
  const rows = [];

  while (url) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`Graph ${res.status}: ${await res.text()}`);
    const data = await res.json();
    for (const s of data.value || []) {
      rows.push({
        id: s.id,
        createdAt: s.createdDateTime ? new Date(s.createdDateTime) : null,
        upn: s.userPrincipalName || '',
        displayName: s.userDisplayName || null,
        ip: s.ipAddress || null,
        country: s.location?.countryOrRegion || null,
        city: s.location?.city || null,
        appDisplayName: s.appDisplayName || null,
        clientApp: s.clientAppUsed || null,
        os: s.deviceDetail?.operatingSystem || null,
        isManaged: !!s.deviceDetail?.isManaged,
        riskState: s.riskState || 'none',
        raw: s,
      });
    }
    url = data['@odata.nextLink'] || null;
  }
  return rows;
}

async function upsert(pool, rows) {
  if (!rows.length) return 0;
  const [nets] = await pool.query('SELECT cidr, type, enabled FROM trusted_networks WHERE enabled = 1');

  const values = [];
  for (const r of rows) {
    const trustedType = ipTrustedType(r.ip, nets);
    const isTrustedIp = !!trustedType;
    const us = isUsCountry(r.country);
    const isOutOfCountry = !isTrustedIp && !!r.country && !us;

    let isImpossibleTravel = 0;
    if (!isTrustedIp && r.country && !us) {
      const [prior] = await pool.query(
        'SELECT id FROM sdops_lockout WHERE upn = ? AND country IS NOT NULL AND country != ? AND created_at >= (? - INTERVAL ? HOUR) AND created_at < ? LIMIT 1',
        [r.upn, r.country, r.createdAt, IMPOSSIBLE_TRAVEL_HOURS, r.createdAt]
      );
      if (prior.length) isImpossibleTravel = 1;
    }

    const hasRisk = r.riskState && r.riskState !== 'none';
    const isSuppressed = isTrustedIp
      ? 0
      : (r.isManaged && us && !isImpossibleTravel && !hasRisk) ? 1 : 0;

    values.push([
      r.id, r.createdAt, r.upn, r.displayName, r.ip, r.country, r.city,
      r.appDisplayName, r.clientApp, r.os, JSON.stringify(r.raw),
      r.isManaged ? 1 : 0, isTrustedIp ? 1 : 0, isOutOfCountry ? 1 : 0,
      isImpossibleTravel, r.riskState || null, isSuppressed,
    ]);
  }

  const sql = `
    INSERT INTO sdops_lockout
      (id, created_at, upn, display_name, ip, country, city,
       app_display_name, client_app, os, raw_json,
       is_managed, is_trusted_ip, is_out_of_country, is_impossible_travel, risk_state, is_suppressed)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      upn = VALUES(upn),
      display_name = VALUES(display_name),
      is_managed = VALUES(is_managed),
      is_trusted_ip = VALUES(is_trusted_ip),
      is_out_of_country = VALUES(is_out_of_country),
      is_impossible_travel = VALUES(is_impossible_travel),
      risk_state = VALUES(risk_state),
      is_suppressed = VALUES(is_suppressed)
  `;
  const [result] = await pool.query(sql, [values]);
  return result.affectedRows;
}

(async () => {
  const started = new Date();
  let pool;
  try {
    const token = await getToken();
    const rows = await fetchLockouts(token);
    pool = await getPool();
    const affected = await upsert(pool, rows);
    console.log(`[${started.toISOString()}] lockouts fetched=${rows.length} affected=${affected} lookback=${LOOKBACK_HOURS}h`);
  } catch (err) {
    console.error(`[${started.toISOString()}] ERROR: ${err.message}`);
    process.exitCode = 1;
  } finally {
    if (pool) await pool.end();
  }
})();
