#!/usr/bin/env node
// collect-password-resets.js
// Bulk-fetches pwdLastSet for every AD user via LDAP, diffs against the last
// known snapshot, and logs a genuine password-change event whenever it moves.
// First run for any UPN just establishes a baseline (no event logged) so we
// don't falsely report every employee as "just reset" on day one.
// Manual run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node collect-password-resets.js

'use strict';
const mysql = require('mysql2/promise');
const ldap = require('ldapjs');

function fileTimeToDate(fileTime) {
  if (!fileTime) return null;
  const val = BigInt(fileTime);
  if (val === 0n || val === 9223372036854775807n) return null;
  const epochDiff = 11644473600000n;
  const ms = val / 10000n - epochDiff;
  return new Date(Number(ms));
}

function fetchAllAdUsers() {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({
      url: process.env.LDAP_URL || 'ldap://10.9.64.80:389',
      timeout: 15000, connectTimeout: 15000,
      tlsOptions: { rejectUnauthorized: false },
    });
    client.on('error', (err) => reject(new Error('LDAP connection error: ' + err.message)));
    client.bind(process.env.LDAP_BIND_USER, process.env.LDAP_BIND_PASS, (err) => {
      if (err) { client.destroy(); return reject(new Error('LDAP bind failed: ' + err.message)); }
      const filter = '(&(objectCategory=person)(objectClass=user)(userPrincipalName=*))';
      const entries = [];
      client.search(process.env.LDAP_BASE_DN || 'DC=nrpi,DC=local',
        { filter, attributes: ['userPrincipalName', 'displayName', 'department', 'pwdLastSet'], scope: 'sub', sizeLimit: 5000, paged: true },
        (err, res) => {
          if (err) { client.unbind(); return reject(new Error('LDAP search error: ' + err.message)); }
          res.on('searchEntry', (entry) => {
            const attrs = {};
            (entry.attributes || []).forEach(a => { attrs[a.type] = a.values.length === 1 ? a.values[0] : a.values; });
            entries.push({
              upn: attrs.userPrincipalName || '',
              displayName: attrs.displayName || '',
              department: attrs.department || null,
              pwdLastSet: fileTimeToDate(attrs.pwdLastSet),
            });
          });
          res.on('error', (err) => { client.unbind(); reject(new Error('LDAP stream error: ' + err.message)); });
          res.on('end', () => { client.unbind(); resolve(entries); });
        });
    });
  });
}

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

(async () => {
  const started = new Date();
  let pool;
  // [CORPIT 2026-09-16] Tolerance for the DATETIME(0) vs AD-millisecond gap.
  // The snapshot column stores seconds; AD returns milliseconds. Without a
  // tolerance the two representations of the SAME instant compare unequal.
  // See the comparator below for the incident this closes.
  const PWD_CHANGE_TOLERANCE_MS = 2000;

  try {
    pool = await getPool();
    const users = await fetchAllAdUsers();
    const usersWithUpn = users.filter(u => u.upn);

    const [snapRows] = await pool.query('SELECT upn, pwd_last_set FROM sdops_password_snapshot');
    const snapMap = new Map(snapRows.map(r => [r.upn.toLowerCase(), r.pwd_last_set]));

    let newBaselines = 0, changed = 0, unchanged = 0;
    for (const u of usersWithUpn) {
      const key = u.upn.toLowerCase();
      const prior = snapMap.has(key) ? snapMap.get(key) : undefined;
      const current = u.pwdLastSet;

      if (prior === undefined) {
        // first time we've seen this account: establish baseline, no event
        newBaselines++;
      // [CORPIT 2026-09-16] Was: new Date(current).getTime() !== new Date(prior).getTime()
      // A strict inequality on epoch ms, comparing a second-precision value
      // from MySQL against a millisecond-precision value from AD. On the first
      // run against the ITAM-seeded baseline it reported 1,791 of 1,838
      // accounts as reset, including accounts whose two timestamps were
      // identical to the second, and accounts whose "new" value was EARLIER
      // than the old one. Only a forward jump past the representation gap is
      // a real change; equal or backward is an artifact, never an event.
      } else if (current && (!prior || (new Date(current).getTime() - new Date(prior).getTime()) > PWD_CHANGE_TOLERANCE_MS)) {
        changed++;
        await pool.query(
          'INSERT INTO sdops_password_reset_event (upn, display_name, department, old_pwd_last_set, new_pwd_last_set, detected_at) VALUES (?,?,?,?,?,?)',
          [u.upn, u.displayName || null, u.department || null, prior || null, current, started]
        );
        console.log('[collect-password-resets] DETECTED', u.upn, prior ? ('(' + prior + ' -> ' + current + ')') : ('(new baseline value: ' + current + ')'));
      } else {
        unchanged++;
      }

      await pool.query(
        'INSERT INTO sdops_password_snapshot (upn, pwd_last_set) VALUES (?,?) ON DUPLICATE KEY UPDATE pwd_last_set = VALUES(pwd_last_set)',
        [u.upn, current]
      );
    }

    const nowIso = new Date().toISOString();
    await pool.query("INSERT IGNORE INTO sdops_password_reset_meta (key_name, key_value) VALUES ('tracking_started_at', ?)", [nowIso]);
    await pool.query('INSERT INTO sdops_password_reset_meta (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)', ['ad_last_run_at', nowIso]);
    await pool.query('INSERT INTO sdops_password_reset_meta (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)', ['ad_last_error', '']);

    console.log(`[${started.toISOString()}] scanned=${usersWithUpn.length} newBaselines=${newBaselines} changed=${changed} unchanged=${unchanged}`);
  } catch (err) {
    console.error(`[${started.toISOString()}] ERROR: ${err.message}`);
    try {
      if (pool) await pool.query('INSERT INTO sdops_password_reset_meta (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)', ['ad_last_error', err.message.slice(0, 300)]);
    } catch (e2) {}
    process.exitCode = 1;
  } finally {
    if (pool) await pool.end();
  }
})();
