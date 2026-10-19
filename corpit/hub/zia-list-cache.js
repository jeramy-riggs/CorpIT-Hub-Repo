'use strict';
// zia-list-cache.js
// Nightly collector: fetches ZIA users, URL filtering rules, and firewall
// rules via OneAPI Bearer auth and writes them to the DB cache tables.
// Cron: 15 3 * * *
// Run manually: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) /usr/bin/node /var/www/corpit-hub-api/zia-list-cache.js

const mysql      = require('mysql2/promise');
const { ziaAuth, httpsRequest } = require('./zscaler-lookup');

const ZLIST_TIMEOUT = parseInt(process.env.ZSCALER_LIST_TIMEOUT_MS, 10) || 90000;
const ZIA_BASE     = process.env.ZIA_BASE_URL;

function log(msg) { console.log('[zia-list-cache] ' + new Date().toISOString() + ' ' + msg); }

// ── helpers ──────────────────────────────────────────────────────────────────

async function ziaGet(endpoint) {
  const url   = ZIA_BASE + '/' + endpoint;
  const token = await ziaAuth();
  const res   = await httpsRequest(url, {
    method: 'GET',
    headers: { Authorization: 'Bearer ' + token },
    timeoutMs: ZLIST_TIMEOUT
  });
  if (res.status === 401) {
    const newToken = await ziaAuth(true);
    return httpsRequest(url, {
      method: 'GET',
      headers: { Authorization: 'Bearer ' + newToken },
      timeoutMs: ZLIST_TIMEOUT
    });
  }
  return res;
}

function sleep(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }

// ── fetchers ─────────────────────────────────────────────────────────────────

async function fetchUsers() {
  const pageSize       = 100;
  const MAX_PAGES      = 50;
  const PAGE_DELAY_MS  = 1200;
  const MAX_429_RETRIES = 3;

  const allUsers = [];
  let page    = 1;
  let partial = false;

  while (page <= MAX_PAGES) {
    let attempt = 0;
    let r = null;

    while (attempt <= MAX_429_RETRIES) {
      r = await ziaGet('users?page=' + page + '&pageSize=' + pageSize);
      if (r.status !== 429) break;
      let wait = 2000 + (attempt * 2000);
      const ra = r.headers && (r.headers['retry-after'] || r.headers['Retry-After']);
      if (ra) { const s = parseInt(ra, 10); if (s > 0 && s < 60) wait = s * 1000; }
      log('zia/users 429 page ' + page + ', waiting ' + wait + 'ms');
      await sleep(wait);
      attempt++;
    }

    if (!r || r.status !== 200) {
      if (allUsers.length) {
        log('WARN zia/users partial — HTTP ' + (r && r.status) + ' on page ' + page);
        partial = true;
        break;
      }
      throw new Error('ZIA /users HTTP ' + (r && r.status) + ' on page ' + page);
    }

    const chunk = Array.isArray(r.body) ? r.body
                : (r.body && r.body.list ? r.body.list : []);
    if (!chunk.length) break;
    for (let i = 0; i < chunk.length; i++) allUsers.push(chunk[i]);
    if (chunk.length < pageSize) break;
    page++;
    if (page <= MAX_PAGES) await sleep(PAGE_DELAY_MS);
  }

  const users = allUsers.map(function(u) {
    return {
      id:                  u.id   || null,
      name:                u.name || null,
      email:               u.email || null,
      department:          u.department ? u.department.name : null,
      adminUser:           !!u.adminUser,
      pilotUser:           !!u.pilotUser,
      deleted:             !!u.deleted,
      disabled:            !!u.disabled,
      pwdLastModifiedTime: u.pwdLastModifiedTime || null
    };
  });

  return {
    success:   true,
    count:     users.length,
    users:     users,
    partial:   partial,
    queriedAt: new Date().toISOString()
  };
}

async function fetchUrlRules() {
  const r = await ziaGet('urlFilteringRules');
  if (r.status !== 200) throw new Error('ZIA urlFilteringRules HTTP ' + r.status);
  const rules = Array.isArray(r.body) ? r.body : [];
  return { rules: rules, count: rules.length };
}

async function fetchFwRules() {
  const r = await ziaGet('firewallFilteringRules');
  if (r.status !== 200) throw new Error('ZIA firewallFilteringRules HTTP ' + r.status);
  const rules = Array.isArray(r.body) ? r.body : [];
  return { rules: rules, count: rules.length };
}

// ── DB writers ───────────────────────────────────────────────────────────────

async function writeUsers(pool, payload) {
  // Keep only the latest row — truncate then insert
  await pool.query('TRUNCATE TABLE zia_users_cache');
  await pool.query(
    'INSERT INTO zia_users_cache (payload, is_partial, synced_at) VALUES (?, ?, NOW())',
    [JSON.stringify(payload), payload.partial ? 1 : 0]
  );
  log('zia_users_cache written: ' + payload.count + ' users, partial=' + payload.partial);
}

async function writeUrlRules(pool, payload) {
  await pool.query('TRUNCATE TABLE zia_url_rules_cache');
  await pool.query(
    'INSERT INTO zia_url_rules_cache (payload, synced_at) VALUES (?, NOW())',
    [JSON.stringify(payload)]
  );
  log('zia_url_rules_cache written: ' + payload.count + ' rules');
}

async function writeFwRules(pool, payload) {
  await pool.query('TRUNCATE TABLE zia_fw_rules_cache');
  await pool.query(
    'INSERT INTO zia_fw_rules_cache (payload, synced_at) VALUES (?, NOW())',
    [JSON.stringify(payload)]
  );
  log('zia_fw_rules_cache written: ' + payload.count + ' rules');
}

// ── main ─────────────────────────────────────────────────────────────────────

async function main() {
  const pool = mysql.createPool({
    host:             process.env.DB_HOST     || 'localhost',
    user:             process.env.DB_USER,
    password:         process.env.DB_PASSWORD,
    database:         process.env.DB_NAME     || 'corpit_hub',
    connectionLimit:  3,
    waitForConnections: true
  });

  let exitCode = 0;

  // Run all three fetches — fail independently so one bad fetch doesn't block others
  const tasks = [
    { name: 'users',     fetch: fetchUsers,    write: writeUsers },
    { name: 'url-rules', fetch: fetchUrlRules, write: writeUrlRules },
    { name: 'fw-rules',  fetch: fetchFwRules,  write: writeFwRules }
  ];

  for (const task of tasks) {
    try {
      log('starting ' + task.name);
      const payload = await task.fetch();
      await task.write(pool, payload);
      log('done ' + task.name);
    } catch (err) {
      log('ERROR ' + task.name + ': ' + err.message);
      exitCode = 1;
    }
  }

  await pool.end();
  log('finished — exitCode=' + exitCode);
  process.exit(exitCode);
}

main();
