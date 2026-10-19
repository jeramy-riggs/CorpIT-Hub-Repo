// collect-okta-users.js (v2)
// Pulls all Okta users (paginated) and upserts into okta_users.
// v2: also fetches DEPROVISIONED and SUSPENDED users, which the default
// /api/v1/users listing excludes — required for offboarding verification.
// Manual run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node collect-okta-users.js

const mysql = require('mysql2/promise');

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

function toDt(v) {
  return v ? new Date(v) : null;
}

async function fetchPage(startUrl, headers, rows, now) {
  let url = startUrl;
  while (url) {
    const res = await fetch(url, { headers });
    if (!res.ok) throw new Error(`Okta ${res.status}: ${await res.text()}`);
    const users = await res.json();
    for (const u of users) {
      rows.push([
        u.id,
        (u.profile && u.profile.login) || '',
        (u.profile && u.profile.email) || null,
        (u.profile && u.profile.firstName) || null,
        (u.profile && u.profile.lastName) || null,
        u.status || null,
        toDt(u.created),
        toDt(u.activated),
        toDt(u.statusChanged),
        toDt(u.lastLogin),
        now,
        JSON.stringify(u),
      ]);
    }
    const link = res.headers.get('link') || '';
    const m = link.split(',').map(s => s.trim()).find(s => s.endsWith('rel="next"'));
    url = m ? m.slice(m.indexOf('<') + 1, m.indexOf('>')) : null;
  }
}

async function fetchAllUsers() {
  const base = process.env.OKTA_BASE_URL.replace(/\/+$/, '');
  const headers = {
    Authorization: 'SSWS ' + process.env.OKTA_API_TOKEN,
    Accept: 'application/json',
  };
  const rows = [];
  const now = new Date();

  // Default listing (excludes DEPROVISIONED and SUSPENDED)
  await fetchPage(`${base}/api/v1/users?limit=200`, headers, rows, now);
  // Explicit passes for the excluded statuses
  const dep = encodeURIComponent('status eq "DEPROVISIONED"');
  await fetchPage(`${base}/api/v1/users?filter=${dep}&limit=200`, headers, rows, now);
  const sus = encodeURIComponent('status eq "SUSPENDED"');
  await fetchPage(`${base}/api/v1/users?filter=${sus}&limit=200`, headers, rows, now);

  return rows;
}

async function upsert(pool, rows) {
  if (!rows.length) return 0;
  const sql = `
    INSERT INTO okta_users
      (okta_id, login, email, first_name, last_name, status,
       created_at_okta, activated_at, status_changed_at, last_login,
       last_synced_at, raw_json)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      login = VALUES(login),
      email = VALUES(email),
      first_name = VALUES(first_name),
      last_name = VALUES(last_name),
      status = VALUES(status),
      activated_at = VALUES(activated_at),
      status_changed_at = VALUES(status_changed_at),
      last_login = VALUES(last_login),
      last_synced_at = VALUES(last_synced_at),
      raw_json = VALUES(raw_json)
  `;
  const [result] = await pool.query(sql, [rows]);
  return result.affectedRows;
}

(async () => {
  const started = new Date();
  let pool;
  try {
    const rows = await fetchAllUsers();
    pool = await getPool();
    const affected = await upsert(pool, rows);
    console.log(`[${started.toISOString()}] okta users fetched=${rows.length} affected=${affected}`);
  } catch (err) {
    console.error(`[${started.toISOString()}] ERROR: ${err.message}`);
    process.exitCode = 1;
  } finally {
    if (pool) await pool.end();
  }
})();
