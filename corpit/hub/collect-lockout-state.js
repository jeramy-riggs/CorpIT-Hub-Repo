#!/usr/bin/env node
// collect-lockout-state.js
// Runs live, authoritative lockout checks against AD (LDAP bit-filter on
// userAccountControl) and Okta (status eq "LOCKED_OUT"). Tracks open/close
// episodes in sdops_lockout_state. Does NOT infer lockout from failed-login
// events — only from each system's own authoritative locked state.
// Manual run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node collect-lockout-state.js

'use strict';
const mysql = require('mysql2/promise');
const ldap = require('ldapjs');
const axios = require('axios');

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

function fetchAdLocked() {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({
      url: process.env.LDAP_URL || 'ldap://10.9.64.80:389',
      timeout: 8000, connectTimeout: 8000,
      tlsOptions: { rejectUnauthorized: false },
    });
    client.on('error', (err) => reject(new Error('LDAP connection error: ' + err.message)));
    client.bind(process.env.LDAP_BIND_USER, process.env.LDAP_BIND_PASS, (err) => {
      if (err) { client.destroy(); return reject(new Error('LDAP bind failed: ' + err.message)); }
      const filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16))';
      const entries = [];
      client.search(process.env.LDAP_BASE_DN || 'DC=nrpi,DC=local',
        { filter, attributes: ['sAMAccountName', 'userPrincipalName', 'displayName', 'department'], scope: 'sub', sizeLimit: 300 },
        (err, res) => {
          if (err) { client.unbind(); return reject(new Error('LDAP search error: ' + err.message)); }
          res.on('searchEntry', (entry) => {
            const attrs = {};
            (entry.attributes || []).forEach(a => { attrs[a.type] = a.values.length === 1 ? a.values[0] : a.values; });
            entries.push({
              upn: attrs.userPrincipalName || attrs.sAMAccountName || '',
              displayName: attrs.displayName || '',
              department: attrs.department || null,
            });
          });
          res.on('error', (err) => { client.unbind(); reject(new Error('LDAP stream error: ' + err.message)); });
          res.on('end', () => { client.unbind(); resolve(entries); });
        });
    });
  });
}

async function fetchOktaLocked() {
  const filter = encodeURIComponent('status eq "LOCKED_OUT"');
  const url = process.env.OKTA_BASE_URL + '/api/v1/users?filter=' + filter + '&limit=200';
  const resp = await axios.get(url, { headers: { Authorization: 'SSWS ' + process.env.OKTA_API_TOKEN } });
  return (resp.data || []).map(u => ({
    upn: u.profile.login || '',
    displayName: ((u.profile.firstName || '') + ' ' + (u.profile.lastName || '')).trim(),
    department: u.profile.department || null,
  }));
}

async function resolveOktaEpisode(upn, lastSeenLockedAt) {
  const fallback = { resolutionMethod: 'unknown', resolvedBy: null, resolutionSource: 'OKTA' };
  try {
    // Use last_seen_locked_at as since; fall back to 30 min ago if null
    const since = lastSeenLockedAt
      ? new Date(lastSeenLockedAt).toISOString()
      : new Date(Date.now() - 30 * 60 * 1000).toISOString();
    const params = new URLSearchParams({ q: upn, since, limit: '50' });
    const resp = await axios.get(process.env.OKTA_BASE_URL + '/api/v1/logs?' + params.toString(), {
      headers: { Authorization: 'SSWS ' + process.env.OKTA_API_TOKEN },
      timeout: 8000,
    });
    const events = resp.data || [];
    // Search newest-first for an unlock event
    const unlockEvent = [...events].reverse().find(e =>
      e.eventType === 'user.account.unlock_by_admin' || e.eventType === 'user.account.unlock'
    );
    if (!unlockEvent) return fallback;
    const actor = unlockEvent.actor || {};
    const actorId = actor.alternateId || actor.id || '';
    if (unlockEvent.eventType === 'user.account.unlock_by_admin') {
      return { resolutionMethod: 'admin_unlock', resolvedBy: actorId, resolutionSource: 'OKTA' };
    }
    // user.account.unlock: distinguish auto-expired vs self-service
    const isSystem = actorId === 'system@okta.com' || actor.type === 'SystemPrincipal';
    if (isSystem) {
      return { resolutionMethod: 'auto_expired', resolvedBy: 'Okta System', resolutionSource: 'OKTA' };
    }
    return { resolutionMethod: 'self_service', resolvedBy: actorId, resolutionSource: 'OKTA' };
  } catch (e) {
    console.error('[collect-lockout-state] Okta resolve error for', upn, ':', e.message);
    return fallback;
  }
}

async function reconcileSource(pool, source, currentlyLocked) {
  const now = new Date();
  const lockedUpns = new Set(currentlyLocked.map(e => e.upn.toLowerCase()).filter(Boolean));

  // open or refresh episodes for everyone currently locked
  for (const e of currentlyLocked) {
    if (!e.upn) continue;
    const [existing] = await pool.query(
      'SELECT id FROM sdops_lockout_state WHERE upn = ? AND source = ? AND closed_at IS NULL LIMIT 1',
      [e.upn, source]
    );
    if (existing.length) {
      await pool.query(
        'UPDATE sdops_lockout_state SET last_seen_locked_at = ?, display_name = ?, department = ? WHERE id = ?',
        [now, e.displayName || null, e.department || null, existing[0].id]
      );
    } else {
      await pool.query(
        'INSERT INTO sdops_lockout_state (upn, source, display_name, department, opened_at, last_seen_locked_at) VALUES (?,?,?,?,?,?)',
        [e.upn, source, e.displayName || null, e.department || null, now, now]
      );
      console.log('[collect-lockout-state] OPENED', source, e.upn);
    }
  }

  // close episodes for anyone no longer in the currently-locked set
  const [openRows] = await pool.query(
    'SELECT id, upn, last_seen_locked_at AS lastSeenLockedAt FROM sdops_lockout_state WHERE source = ? AND closed_at IS NULL',
    [source]
  );
  for (const r of openRows) {
    if (!lockedUpns.has(String(r.upn).toLowerCase())) {
      const res = source === 'OKTA'
        ? await resolveOktaEpisode(r.upn, r.lastSeenLockedAt)
        : { resolutionMethod: 'unknown', resolvedBy: null, resolutionSource: 'AD' };
      await pool.query(
        'UPDATE sdops_lockout_state SET closed_at = ?, resolution_method = ?, resolved_by = ?, resolution_source = ? WHERE id = ?',
        [now, res.resolutionMethod, res.resolvedBy, res.resolutionSource, r.id]
      );
      console.log('[collect-lockout-state] CLOSED', source, r.upn, '|', res.resolutionMethod, res.resolvedBy || '');
    }
  }
}

(async () => {
  const started = new Date();
  let pool;
  try {
    pool = await getPool();

    let adLocked = [], adError = null;
    try { adLocked = await fetchAdLocked(); }
    catch (e) { adError = e.message; console.error('[collect-lockout-state] AD ERROR:', e.message); }

    let oktaLocked = [], oktaError = null;
    try { oktaLocked = await fetchOktaLocked(); }
    catch (e) { oktaError = e.message; console.error('[collect-lockout-state] OKTA ERROR:', e.message); }

    if (!adError) await reconcileSource(pool, 'AD', adLocked);
    if (!oktaError) await reconcileSource(pool, 'OKTA', oktaLocked);

    const nowIso = new Date().toISOString();
    // Set once, never overwritten — marks when authoritative AD/Okta tracking actually began,
    // so ticket-vs-episode comparisons can exclude tickets that predate this system.
    await pool.query("INSERT IGNORE INTO sdops_lockout_state_meta (key_name, key_value) VALUES ('tracking_started_at', ?)", [nowIso]);
    await pool.query('INSERT INTO sdops_lockout_state_meta (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)', ['ad_last_run_at', adError ? null : nowIso]);
    await pool.query('INSERT INTO sdops_lockout_state_meta (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)', ['ad_last_error', adError || '']);
    await pool.query('INSERT INTO sdops_lockout_state_meta (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)', ['okta_last_run_at', oktaError ? null : nowIso]);
    await pool.query('INSERT INTO sdops_lockout_state_meta (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)', ['okta_last_error', oktaError || '']);

    console.log(`[${started.toISOString()}] AD locked=${adLocked.length}${adError ? ' (ERROR: ' + adError + ')' : ''} | Okta locked=${oktaLocked.length}${oktaError ? ' (ERROR: ' + oktaError + ')' : ''}`);
  } catch (err) {
    console.error(`[${started.toISOString()}] FATAL: ${err.message}`);
    process.exitCode = 1;
  } finally {
    if (pool) await pool.end();
  }
})();
