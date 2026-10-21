'use strict';
const express = require('express');
const router = express.Router();
// F9/F10: Express 4 does not catch a rejected async handler, and server.js exits
// on unhandledRejection. Catch every promise a handler on this router returns
// (including routes added by the register() modules below) and answer 500 JSON.
['get', 'post', 'put', 'patch', 'delete'].forEach(function (m) {
  const orig = router[m].bind(router);
  router[m] = function () {
    const args = Array.prototype.map.call(arguments, function (fn) {
      if (typeof fn !== 'function' || fn.length > 3) return fn;
      return function (req, res, next) {
        const p = fn(req, res, next);
        if (p && typeof p.catch === 'function') p.catch(function (err) {
          console.error('[identity-routes] unhandled ' + req.method + ' ' + req.path + ':', err && err.message ? err.message : err);
          if (!res.headersSent) res.status(500).json({ error: 'Internal error' });
        });
        return p;
      };
    });
    return orig.apply(null, args);
  };
});
// Query/body values can be arrays or objects (?q[]=x); only a string is a value.
function str(v) { return typeof v === 'string' ? v : ''; }
const { execFile } = require('child_process');
const path = require('path');
const { lookupUser, searchUsers } = require('./identity-ldap');
const deviceModel = require('./identity-device-model');

let lookupZscalerUser = null;
const { enhanceRiskScore } = require('./enhance-risk');
try { ({ lookupZscalerUser } = require('./zscaler-lookup')); }
catch (e) { console.warn('[identity-routes] zscaler-lookup not found'); }

let lookupOktaUser = null;
try { ({ lookupOktaUser } = require('./okta-lookup')); }
catch (e) { console.warn('[identity-routes] okta-lookup not found'); }

let unlockAccount = null;
try {
  ({ unlockAccount } = require('./identity-actions'));
  console.log('[identity-routes] identity-actions loaded (unlock)');
} catch (e) {
  console.warn('[identity-routes] identity-actions not found, unlock disabled');
}

// ---- RBAC enforcement (Phase A) -------------------------------------
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
// ---------------------------------------------------------------------
const cache = new Map();
const CACHE_TTL = 60 * 1000;

function getCached(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { cache.delete(key); return null; }
  return entry.data;
}

function setCache(key, data) {
  cache.set(key, { ts: Date.now(), data });
  if (cache.size > 200) {
    [...cache.entries()].sort((a,b) => a[1].ts - b[1].ts).slice(0, 50).forEach(([k]) => cache.delete(k));
  }
}

// ── Measurement ladder (shared by every route in this file) ───────────────
// House rule: a source we could not query is NOT zero. Each source reports:
//   ok      queried, rows found
//   stale   queried, data older than its freshness budget
//   empty   queried, and the answer is genuinely nothing
//   unknown could NOT be queried (SQL/API failure) — render AMBER
//           ("… unavailable"), never a green "none" and never a red alarm.
// Callers must treat `count` as meaningless when status is 'unknown'.
function srcOk(label, count) {
  return { label: label, status: count > 0 ? 'ok' : 'empty', count: count };
}
function srcUnknown(label, err, where) {
  const msg = (err && err.message) ? err.message : String(err || 'unknown error');
  if (where) console.error('[identity-routes] ' + where + ':', msg);
  return { label: label, status: 'unknown', count: 0, error: msg };
}
// Roll a { key: state } map up into the two flags the front end renders from.
function srcSummary(sources) {
  const unavailable = Object.keys(sources)
    .filter(function (k) { return sources[k] && sources[k].status === 'unknown'; })
    .map(function (k) { return (sources[k] && sources[k].label) || k; });
  return { partial: unavailable.length > 0, unavailable: unavailable };
}

router.get('/search', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const q = str(req.query.q).trim();
  if (q.length < 2) return res.json([]);
  try {
    const results = await searchUsers(q);
    return res.json(results);
  } catch (err) {
    return res.status(500).json([]);
  }
});
router.get('/lookup', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const q = str(req.query.q).trim();
  if (!q) return res.status(400).json({ error: 'Query parameter "q" is required' });
  if (q.length > 256) return res.status(400).json({ error: 'Query too long' });

  const cached = getCached(q.toLowerCase());
  if (cached) return res.json({ ...cached, fromCache: true });

  try {
    const result = await lookupUser(q);
    if (!result) {
      return res.status(404).json({ error: 'User not found', identity: q, message: 'No account found in nrpi.local matching: ' + q });
    }

    result.actions = {
      canUnlock: !!unlockAccount,
      canResetPassword: !!(process.env.WINRM_USER && process.env.WINRM_PASS),
      canLockoutSource: !!(process.env.WINRM_USER && process.env.WINRM_PASS),
    };

    const searchEmail = result.email || result.upn || '';
    const enrichPromises = [];

    if (lookupZscalerUser && searchEmail) {
      enrichPromises.push(
        lookupZscalerUser(searchEmail, result.displayName)
          .then(r => { result.zscaler = r; })
          .catch(e => { result.zscaler = { zia: { status: 'error', error: e.message }, zpa: { status: 'error', error: e.message } }; })
      );
    }

    if (lookupOktaUser && searchEmail) {
      enrichPromises.push(
        lookupOktaUser(searchEmail)
          .then(r => { result.okta = r; })
          .catch(e => { result.okta = { status: 'error', error: e.message }; })
      );
    }

    await Promise.allSettled(enrichPromises);
    enhanceRiskScore(result);

    // groups-silent-zero: a lookup whose group reads were degraded is not
    // pinned for 60s -- the next request gets a fresh chance at the DC.
    if (!result.groupsUnavailable) setCache(q.toLowerCase(), result);
    return res.json(result);
  } catch (err) {
    console.error('[identity-routes] lookup error:', err.message);
    const isConn = /connection|ECONNREFUSED|ETIMEDOUT|bind/i.test(err.message);
    return res.status(isConn ? 503 : 500).json({ error: isConn ? 'AD connection failed' : 'Lookup failed', message: err.message, dc: process.env.LDAP_URL || 'ldap://10.9.64.80:389' });
  }
});

router.post('/unlock', rbac.requirePage('identity-diag','admin'), async (req, res) => {
  if (!unlockAccount) return res.status(501).json({ error: 'Unlock not available' });
  const identity = str(req.body && req.body.identity).trim();
  if (!identity) return res.status(400).json({ error: 'identity is required' });
  try {
    const result = await unlockAccount(identity);
    cache.clear();
    await rbac.audit(req, 'ad-unlock', identity.slice(0, 255), 'identity-diag', { success: result.success !== false, dn: result.dn || null });
    return res.json(result);
  } catch (err) {
    console.error('[identity-routes] unlock error:', err.message);
    await rbac.audit(req, 'ad-unlock-ERROR', identity.slice(0, 255), 'identity-diag', { error: String(err.message || err).slice(0, 300) });
    return res.status(500).json({ error: 'Unlock failed', message: err.message });
  }
});

// Identity whitelist shared by reset-password and lockout-source (CR-1): a
// sAMAccountName / UPN shape only, so nothing else can reach the PowerShell
// helpers. Anything else is a 400.
const LOCKOUT_IDENTITY_RE = /^[A-Za-z0-9._@\-]{1,64}$/;
// PowerShell treats U+2018-U+201B as single quotes as well as U+0027, and
// password-reset.py only doubles U+0027 -- a curly quote would terminate the
// quoted literal on the DC. Control characters have no business in a password.
const PASSWORD_LITERAL_BREAK_RE = /[\u2018-\u201b\u0000-\u001f\u007f]/;

// ── Password Reset (WinRM → DC, agent provides new password) ──
router.post('/reset-password', rbac.requirePage('identity-diag','admin'), (req, res) => {
  if (!process.env.WINRM_USER || !process.env.WINRM_PASS) {
    return res.status(500).json({ success: false, error: 'WINRM credentials not configured' });
  }
  const identity = (req.body && typeof req.body.identity === 'string' ? req.body.identity : '').trim();
  const newPassword = (req.body && typeof req.body.newPassword === 'string' ? req.body.newPassword : '').trim();
  const forceChange = (req.body && req.body.forceChange) ? '1' : '0';
  if (!identity) return res.status(400).json({ success: false, error: 'identity is required' });
  if (!LOCKOUT_IDENTITY_RE.test(identity)) return res.status(400).json({ success: false, error: 'identity may only contain letters, digits, . _ @ - (max 64 chars)' });
  if (!newPassword) return res.status(400).json({ success: false, error: 'newPassword is required' });
  if (newPassword.length < 8) return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
  if (PASSWORD_LITERAL_BREAK_RE.test(newPassword)) return res.status(400).json({ success: false, error: 'Password may not contain curly quotes or control characters' });

  const scriptPath = path.join(__dirname, 'password-reset.py');
  // pw-on-argv: target + new password travel in the child's environment, never
  // on argv -- /proc/<pid>/cmdline is world-readable (no hidepid), and execFile's
  // "Command failed: <argv>" error message used to be logged and returned.
  execFile('python3', [scriptPath], {
    timeout: 40000,
    env: { ...process.env, TARGET_USER: identity, NEW_PASSWORD: newPassword, FORCE_CHANGE: forceChange },
  }, async (err, stdout, stderr) => {
    const auditTarget = identity.slice(0, 255);
    if (err) {
      // err.message / err.cmd embed the full argv. Never log, return or audit
      // them; keep only exit code / timeout + stderr.
      const safeErr = err.killed ? 'Password reset timed out' : ('password-reset.py exited ' + (err.code != null ? err.code : 'abnormally'));
      console.error('[identity-routes] reset-password error:', safeErr, (stderr || '').trim().slice(0, 300));
      await rbac.audit(req, 'ad-reset-password-ERROR', auditTarget, 'identity-diag', { stage: 'execFile', error: safeErr, code: err.code != null ? err.code : null, killed: !!err.killed, forceChange: forceChange === '1' });
      return res.status(500).json({ success: false, error: 'Password reset failed: ' + safeErr });
    }
    try {
      const result = JSON.parse(stdout.trim());
      if (result.success) cache.clear();
      await rbac.audit(req, result.success ? 'ad-reset-password' : 'ad-reset-password-ERROR', auditTarget, 'identity-diag', { success: !!result.success, forceChange: forceChange === '1', error: result.success ? undefined : String(result.error || '').slice(0, 300) });
      return res.json(result);
    } catch (e) {
      await rbac.audit(req, 'ad-reset-password-ERROR', auditTarget, 'identity-diag', { stage: 'parse', error: 'Failed to parse response', forceChange: forceChange === '1' });
      return res.status(500).json({ success: false, error: 'Failed to parse response', raw: stdout });
    }
  });
});

// ── Lockout Source (WinRM → DC Event Log) ──
// CR-1: identity is whitelisted (LOCKOUT_IDENTITY_RE above) before it can
// reach the PowerShell helper, and is handed over via the environment
// (TARGET_USER) instead of argv. Anything else is a 400.
router.post('/lockout-source', rbac.requirePage('identity-diag','read'), (req, res) => {
  const identity = (req.body && typeof req.body.identity === 'string' ? req.body.identity : '').trim();
  if (!identity) return res.status(400).json({ error: 'identity is required' });
  if (!LOCKOUT_IDENTITY_RE.test(identity)) {
    return res.status(400).json({ error: 'identity may only contain letters, digits, . _ @ - (max 64 chars)' });
  }
  if (!process.env.WINRM_USER || !process.env.WINRM_PASS) {
    return res.status(500).json({ error: 'WINRM credentials not configured' });
  }
  const scriptPath = path.join(__dirname, 'lockout-source.py');
  execFile('python3', [scriptPath], {
    timeout: 40000,
    env: { ...process.env, TARGET_USER: identity },
  }, (err, stdout, stderr) => {
    if (err) {
      console.error('[identity-routes] lockout-source error:', err.message);
      if (err.killed) return res.status(504).json({ error: 'Query timed out' });
      return res.status(500).json({ error: 'Lockout source query failed', message: err.message });
    }
    try {
      const result = JSON.parse(stdout.trim());
      return res.json(result);
    } catch (e) {
      return res.status(500).json({ error: 'Failed to parse DC response', raw: stdout });
    }
  });
});



// ── Okta Auth Failures (System Log) ──
// GET /api/identity/okta-failures?q=optional_user&hours=24
router.get('/okta-failures', rbac.requirePage('identity-diag','read'), async (req, res) => {
  let oktaRequest, oktaFilterValue;
  try { ({ oktaRequest, oktaFilterValue } = require('./okta-lookup')); }
  catch (e) { return res.status(501).json({ error: 'okta-lookup module not available', failures: [] }); }

  if (!process.env.OKTA_BASE_URL || !process.env.OKTA_API_TOKEN) {
    return res.status(501).json({ error: 'Okta not configured', failures: [] });
  }

  const q = String(req.query.q || '').trim();
  // The value is spliced into a double-quoted System Log filter below; a `"`
  // or `\` would end the string and let the caller widen the query tenant-wide.
  if (q && !oktaFilterValue(q)) return res.status(400).json({ error: 'Invalid user identifier', failures: [] });
  const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 24, 1), 720);

  try {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
    // The System Log 'eq' operator is case-sensitive (see /okta-sessions above),
    // so resolve the caller's spelling to the exact profile login before it goes
    // into a filter. Left as typed when the user does not resolve, so a failed
    // attempt against a non-existent username still matches.
    let actorQ = q;
    if (q) {
      try {
        const _u = await oktaRequest('/api/v1/users/' + encodeURIComponent(q));
        if (_u.status === 200 && _u.body && _u.body.profile && _u.body.profile.login) actorQ = _u.body.profile.login;
      } catch (_e) {}
    }
    // Build filter: always FAILURE outcome, optionally scoped to a user.
    // The time window belongs in the since= query parameter, NOT inside the
    // filter expression. A `published gt "<iso>"` term in filter matches nothing
    // (HTTP 200, empty page), so this tool reported a confident zero for every
    // query -- org-wide and per-user -- while the log held 50 failures a day.
    let filter = 'outcome.result eq "FAILURE"';
    if (q) {
      filter = 'actor.alternateId eq "' + actorQ + '" and outcome.result eq "FAILURE"';
    }

    const logPath = '/api/v1/logs?since=' + encodeURIComponent(since) +
      '&filter=' + encodeURIComponent(filter) + '&sortOrder=DESCENDING&limit=50';
    const logRes = await oktaRequest(logPath);

    if (logRes.status !== 200) {
      return res.status(502).json({ error: 'Okta system log returned HTTP ' + logRes.status, failures: [] });
    }

    const events = Array.isArray(logRes.body) ? logRes.body : [];
    const failures = events.map(function(ev) {
      return {
        published: ev.published,
        user: ev.actor ? ev.actor.alternateId : '',
        displayName: ev.actor ? ev.actor.displayName : '',
        outcome: ev.outcome ? ev.outcome.result : 'FAILURE',
        reason: ev.outcome ? ev.outcome.reason : '',
        displayMessage: ev.displayMessage || '',
        eventType: ev.eventType || '',
        ipAddress: ev.client ? ev.client.ipAddress : '',
        userAgent: ev.client && ev.client.userAgent ? (ev.client.userAgent.browser || '') + ' / ' + (ev.client.userAgent.os || '') : '',
        city: ev.client && ev.client.geographicalContext ? ev.client.geographicalContext.city || '' : '',
        state: ev.client && ev.client.geographicalContext ? ev.client.geographicalContext.state || '' : '',
        country: ev.client && ev.client.geographicalContext ? ev.client.geographicalContext.country || '' : '',
      };
    });

    return res.json({ failures: failures, count: failures.length, since: since, filter: q || 'all users' });
  } catch (err) {
    console.error('[identity-routes] okta-failures error:', err.message);
    return res.status(500).json({ error: 'Okta system log query failed: ' + err.message, failures: [] });
  }
});
// ── Device Lookup (authoritative per-employee match; mirrors IT_Inventory_App) ──
// GET /api/identity/devices?q=username_or_email_or_name
// Resolves q -> a single employee (username + full name), then matches each
// device source by EXACT normalized owner key (NOT fuzzy LIKE). Sources & keys
// mirror IT_Inventory_App's itamDevicesForEmployee, PLUS Intune-managed Windows
// (which ManageEngine often has no owner for). iPhone/Tablet=Intune(upn),
// Mac=Kandji(username OR full name), Windows=ManageEngine(first_last/logged_on)
// + Intune(upn) deduped, iPad=ipad_devices(username), AWS=aws_workspaces(username).
async function deviceDiscovery(req, res) {
  const q = str(req.query.q).trim();
  if (!q || q.length > 256) return res.status(400).json({ error: 'A person query of 1–256 characters is required', devices: [] });

  // Lazy-init MySQL pool for device queries
  if (!router._devicePool) {
    try {
      const mysql = require('mysql2/promise');
      router._devicePool = mysql.createPool({
        host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
        database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
        waitForConnections: true, connectionLimit: 3, charset: 'utf8mb4',
      });
      console.log('[identity-routes] device DB pool created');
    } catch (e) {
      console.error('[identity-routes] device DB pool failed:', e.message);
      return res.status(500).json({ error: 'Database connection failed', devices: [] });
    }
  }
  const pool = router._devicePool;

  // Normalize an owner value to a comparable username key: lowercase, trim,
  // strip @auction.com suffix. Mirrors IT_Inventory_App's xu() for that domain.
  const norm = function (s) { return (s == null ? '' : String(s)).trim().toLowerCase().replace(/@auction\.com$/, ''); };
  const qKey = norm(q);
  const qLower = q.trim().toLowerCase();

  // Per-source measurement ledger. Every block below records ok / empty /
  // unknown, so a source whose SQL failed is never reported as "no devices".
  const sources = {};

  // 1) Resolve q -> a single employee so devices key off username + full name,
  //    not the raw search string. Prevents fuzzy false-positives (e.g. two Riggs).
  let resolved = null;
  try {
    const [emps] = await pool.query(
      "SELECT username, first_last FROM it_inventory.active_employees " +
      "WHERE LOWER(username)=? OR REPLACE(LOWER(business_email),'@auction.com','')=? OR LOWER(first_last)=? LIMIT 5",
      [qKey, qKey, qLower]
    );
    if (emps.length === 1) {
      resolved = emps[0];
    } else if (emps.length > 1) {
      resolved = emps.find(function (e) { return (e.username || '').toLowerCase() === qKey; }) || null;
    }
    sources.employeeDirectory = srcOk('Employee directory', resolved ? 1 : 0);
  } catch (e) { sources.employeeDirectory = srcUnknown('Employee directory', e, 'employee resolve error'); }

  // Fallback: no single employee match -> treat q itself as the username key.
  const username = resolved ? norm(resolved.username) : qKey;
  const fullName = resolved ? (resolved.first_last || '').trim().toLowerCase() : qLower;

  const devices = [];
  const sourceRecords = [];
  const winSeen = new Set();   // Windows machine keys (name/serial) already added, for dedup

  // iPhones & tablets — Intune (current only), keyed on primary_user_upn
  try {
    const [rows] = await pool.query(
      "SELECT id, device_id, device_name, model, os, os_version, serial_number, device_category, primary_user_upn, " +
      "       primary_user_name, compliance, last_checkin, ownership, phone_number, subscriber_carrier " +
      "  FROM it_inventory.intune_devices " +
      " WHERE device_category IN ('iphone','tablet') AND is_historical=0 " +
      "   AND REPLACE(LOWER(TRIM(primary_user_upn)),'@auction.com','')=? " +
      " ORDER BY last_checkin DESC",
      [username]
    );
    rows.forEach(function (r) {
      const device = {
        deviceName: r.device_name, model: r.model, os: r.os || (r.device_category === 'tablet' ? 'Android' : 'iOS'),
        osVersion: r.os_version, serial: r.serial_number, user: r.primary_user_upn || r.primary_user_name,
        compliance: r.compliance, lastCheckin: r.last_checkin, ownership: r.ownership, phone: r.phone_number,
        carrier: r.subscriber_carrier, source: 'Intune', type: r.device_category === 'tablet' ? 'Tablet' : 'iPhone',
      };
      sourceRecords.push(deviceModel.sourceRecord('intune', r.id, r.device_id, device));
      devices.push(device);
    });
    sources.intuneMobile = srcOk('Intune (iPhone / Tablet)', rows.length);
  } catch (e) { sources.intuneMobile = srcUnknown('Intune (iPhone / Tablet)', e, 'intune device query error'); }

  // MacBooks — Kandji (Kandji stores full names, so match username OR full name)
  try {
    const [rows] = await pool.query(
      "SELECT id, device_name, model, os_version, serial, blueprint, user_name, checked_in " +
      "  FROM it_inventory.macbooks " +
      " WHERE REPLACE(LOWER(TRIM(user_name)),'@auction.com','')=? OR LOWER(TRIM(user_name))=? " +
      " ORDER BY checked_in DESC",
      [username, fullName]
    );
    rows.forEach(function (r) {
      const device = {
        deviceName: r.device_name, model: r.model, os: 'macOS', osVersion: r.os_version, serial: r.serial,
        user: r.user_name, compliance: null, lastCheckin: r.checked_in, blueprint: r.blueprint,
        source: 'Kandji', type: 'MacBook',
      };
      sourceRecords.push(deviceModel.sourceRecord('kandji-mac', r.id, null, device));
      devices.push(device);
    });
    sources.kandjiMac = srcOk('Kandji (MacBook)', rows.length);
  } catch (e) { sources.kandjiMac = srcUnknown('Kandji (MacBook)', e, 'kandji device query error'); }

  // Windows (1/2) — ManageEngine endpoints (owner in first_last or logged_on_user)
  try {
    const [rows] = await pool.query(
      "SELECT id, resource_id, computer_name, device_model, os_name, os_version, service_tag, first_last, logged_on_user, last_asset_scan " +
      "  FROM it_inventory.endpoints " +
      " WHERE os_name LIKE '%Windows%' " +
      "   AND ( REPLACE(LOWER(TRIM(first_last)),'@auction.com','')=? " +
      "      OR REPLACE(LOWER(TRIM(logged_on_user)),'@auction.com','')=? ) " +
      " ORDER BY last_asset_scan DESC",
      [username, username]
    );
    rows.forEach(function (r) {
      if (r.computer_name) winSeen.add(String(r.computer_name).trim().toUpperCase());
      if (r.service_tag) winSeen.add(String(r.service_tag).trim().toUpperCase());
      const device = {
        deviceName: r.computer_name, model: r.device_model, os: r.os_name, osVersion: r.os_version,
        serial: r.service_tag, user: r.first_last || r.logged_on_user, compliance: null,
        lastCheckin: r.last_asset_scan, source: 'ManageEngine', type: 'Windows',
      };
      sourceRecords.push(deviceModel.sourceRecord('manageengine', r.id, r.resource_id, device));
      devices.push(device);
    });
    sources.manageEngineWindows = srcOk('ManageEngine (Windows)', rows.length);
  } catch (e) { sources.manageEngineWindows = srcUnknown('ManageEngine (Windows)', e, 'endpoints device query error'); }

  // Windows (2/2) — Intune-managed Windows (ownership via upn; ManageEngine often
  // has no owner for these). Dedup against the ManageEngine rows above by name/serial.
  try {
    const [rows] = await pool.query(
      "SELECT id, device_id, device_name, model, os, os_version, serial_number, primary_user_upn, compliance, last_checkin, ownership " +
      "  FROM it_inventory.intune_devices " +
      " WHERE device_category='windows' AND is_historical=0 " +
      "   AND REPLACE(LOWER(TRIM(primary_user_upn)),'@auction.com','')=? " +
      " ORDER BY last_checkin DESC",
      [username]
    );
    rows.forEach(function (r) {
      const nm = (r.device_name || '').trim().toUpperCase();
      const sn = (r.serial_number || '').trim().toUpperCase();
      const legacyDuplicate = (nm && winSeen.has(nm)) || (sn && winSeen.has(sn));
      const device = {
        deviceName: r.device_name, model: r.model, os: r.os || 'Windows', osVersion: r.os_version,
        serial: r.serial_number, user: r.primary_user_upn, compliance: r.compliance,
        lastCheckin: r.last_checkin, ownership: r.ownership, source: 'Intune', type: 'Windows',
      };
      sourceRecords.push(deviceModel.sourceRecord('intune', r.id, r.device_id, device));
      if (!legacyDuplicate) devices.push(device);
    });
    sources.intuneWindows = srcOk('Intune (Windows)', rows.length);
  } catch (e) { sources.intuneWindows = srcUnknown('Intune (Windows)', e, 'intune windows query error'); }

  // iPads — ipad_devices (Kandji-managed)
  try {
    const [rows] = await pool.query(
      "SELECT id, device_id, device_name, model, os_version, serial, user_name, checked_in, carrier " +
      "  FROM it_inventory.ipad_devices " +
      " WHERE REPLACE(LOWER(TRIM(user_name)),'@auction.com','')=? " +
      " ORDER BY checked_in DESC",
      [username]
    );
    rows.forEach(function (r) {
      const device = {
        deviceName: r.device_name, model: r.model, os: 'iPadOS', osVersion: r.os_version, serial: r.serial,
        user: r.user_name, compliance: null, lastCheckin: r.checked_in, carrier: r.carrier,
        source: 'Kandji', type: 'iPad',
      };
      sourceRecords.push(deviceModel.sourceRecord('kandji-ipad', r.id, r.device_id, device));
      devices.push(device);
    });
    sources.kandjiIpad = srcOk('Kandji (iPad)', rows.length);
  } catch (e) { sources.kandjiIpad = srcUnknown('Kandji (iPad)', e, 'ipad device query error'); }

  // AWS Workspaces — keyed on username
  try {
    const [rows] = await pool.query(
      "SELECT id, workspace_id, username, user_volume FROM it_inventory.aws_workspaces WHERE LOWER(TRIM(username))=?",
      [username]
    );
    rows.forEach(function (r) {
      const device = {
        deviceName: r.username, model: 'AWS Workspace', os: 'AWS', osVersion: null, serial: null,
        user: r.username, compliance: null, lastCheckin: null,
        detail: r.user_volume ? ('Vol ' + r.user_volume) : '', source: 'AWS', type: 'AWS Workspace',
      };
      sourceRecords.push(deviceModel.sourceRecord('aws', r.id, r.workspace_id, device));
      devices.push(device);
    });
    sources.awsWorkspaces = srcOk('AWS Workspaces', rows.length);
  } catch (e) { sources.awsWorkspaces = srcUnknown('AWS Workspaces', e, 'aws workspace query error'); }

  const groupingWarnings = await deviceModel.measureSerialMultiplicity(pool, sourceRecords);
  const deviceGroups = deviceModel.buildDeviceGroups(sourceRecords);
  const srcRoll = srcSummary(sources);
  const payload = {
    devices: devices,
    count: devices.length,
    deviceGroups,
    deviceGroupCount: deviceGroups.length,
    sourceRecordCount: sourceRecords.length,
    deviceSources: sources,
    groupingWarnings,
    resolvedUser: resolved ? { username: resolved.username, name: resolved.first_last } : null,
  };
  // Preserve the legacy conditional availability ladder. New deviceSources and
  // deviceGroups are additive; legacy devices/count keep their prior meaning.
  // No boolean is emitted: the generic renderer paints boolean true GREEN.
  if (srcRoll.partial) {
    payload.sources = sources;
    payload.unavailable = srcRoll.unavailable;
  }
  return res.json(payload);
}
router.get('/devices', rbac.requirePage('identity-diag','read'), deviceDiscovery);
require('./identity-device-detail').register(router,{rbac,discover:deviceDiscovery,
  zccList:q=>require('./zscaler-diag-routes').identityDeviceList(q),
  zdx:require('./zscaler-capabilities').zdx});
require('./identity-device-network').register(router,{rbac,discover:deviceDiscovery});
require('./identity-device-network-live').register(router,{rbac,discover:deviceDiscovery});

// ── Password Expiry (live LDAP query) ──
// GET /api/identity/password-expiry?days=30
router.get('/password-expiry', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const ldapMod = require('./ldap-secure'); // StartTLS before every bind

  const LDAP_URL       = process.env.LDAP_URL       || 'ldap://10.9.64.80:389';
  const LDAP_BASE_DN   = process.env.LDAP_BASE_DN   || 'DC=nrpi,DC=local';
  const LDAP_BIND_USER = process.env.LDAP_BIND_USER || '';
  const LDAP_BIND_PASS = process.env.LDAP_BIND_PASS || '';

  if (!LDAP_BIND_USER || !LDAP_BIND_PASS) {
    return res.status(501).json({ error: 'LDAP credentials not configured', users: [] });
  }

  function dateToFileTime(d) {
    var epochDiff = 11644473600000;
    return ((d.getTime() + epochDiff) * 10000).toString();
  }

  function fileTimeToDate(ft) {
    if (!ft) return null;
    var val = Number(ft);
    if (val === 0 || val >= 9223372036854775000) return null;
    var ms = val / 10000 - 11644473600000;
    return new Date(ms);
  }

  var client;
  try {
    // Connect + bind
    client = ldapMod.createClient({
      url: LDAP_URL, timeout: 15000, connectTimeout: 15000,
    });

    await new Promise(function(resolve, reject) {
      client.on('error', function(err) { reject(new Error('LDAP connection error: ' + err.message)); });
      client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, function(err) {
        if (err) { client.destroy(); reject(new Error('LDAP bind failed: ' + err.message)); }
        else resolve();
      });
    });

    // Get domain max password age
    var domainEntries = await new Promise(function(resolve, reject) {
      var entries = [];
      client.search(LDAP_BASE_DN, {
        filter: '(objectClass=domain)', attributes: ['maxPwdAge'], scope: 'base', sizeLimit: 1
      }, function(err, searchRes) {
        if (err) return reject(err);
        searchRes.on('searchEntry', function(entry) {
          var obj = {};
          entry.attributes.forEach(function(a) { obj[a.type] = a.values.length === 1 ? a.values[0] : a.values; });
          entries.push(obj);
        });
        searchRes.on('error', reject);
        searchRes.on('end', function() { resolve(entries); });
      });
    });

    if (!domainEntries.length || !domainEntries[0].maxPwdAge) {
      return res.status(500).json({ error: 'Could not read domain password policy', users: [] });
    }

    var maxPwdAgeMs = Math.abs(Number(BigInt(domainEntries[0].maxPwdAge)) / 10000);

    // Search for enabled users whose passwords expire (not "never expires" flag)
    // UAC bit 0x10000 = DONT_EXPIRE_PASSWORD, bit 0x2 = DISABLED
    // Filter: enabled users, password expires, password was set
    var filter = '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=65536))(pwdLastSet>=1))';

    var userEntries = await new Promise(function(resolve, reject) {
      var entries = [];
      client.search(LDAP_BASE_DN, {
        filter: filter,
        attributes: ['displayName','sAMAccountName','userPrincipalName','mail','pwdLastSet','department','title'],
        scope: 'sub',
        sizeLimit: 1000,
      }, function(err, searchRes) {
        if (err) return reject(err);
        searchRes.on('searchEntry', function(entry) {
          var obj = {};
          entry.attributes.forEach(function(a) { obj[a.type] = a.values.length === 1 ? a.values[0] : a.values; });
          entries.push(obj);
        });
        searchRes.on('error', reject);
        searchRes.on('end', function() { resolve(entries); });
      });
    });

    // Calculate expiry for each user and filter to within N days
    var now = Date.now();
    var cutoff = now + days * 86400000;
    var results = [];

    userEntries.forEach(function(u) {
      var pwdLastSet = fileTimeToDate(u.pwdLastSet);
      if (!pwdLastSet) return;
      var expiry = new Date(pwdLastSet.getTime() + maxPwdAgeMs);
      var expiryMs = expiry.getTime();
      // Include: already expired (negative days) up to N days from now
      if (expiryMs > cutoff) return; // too far out
      if (expiryMs < now - 90 * 86400000) return; // expired more than 90 days ago, skip ancient
      var daysLeft = Math.round((expiryMs - now) / 86400000);
      results.push({
        displayName: u.displayName || '',
        user: u.sAMAccountName || '',
        email: u.mail || u.userPrincipalName || '',
        department: u.department || '',
        title: u.title || '',
        expiryDate: expiry.toISOString().split('T')[0],
        daysLeft: daysLeft,
        pwdLastSet: pwdLastSet.toISOString(),
      });
    });

    // Sort: most urgent first (lowest/most negative daysLeft)
    results.sort(function(a, b) { return a.daysLeft - b.daysLeft; });

    return res.json({
      users: results,
      count: results.length,
      maxPwdAgeDays: Math.round(maxPwdAgeMs / 86400000),
      queriedAt: new Date().toISOString(),
    });

  } catch (err) {
    console.error('[identity-routes] password-expiry error:', err.message);
    return res.status(500).json({ error: 'LDAP query failed: ' + err.message, users: [] });
  } finally {
    if (client) try { client.unbind(); } catch (_) {}
  }
});

// GET /api/identity/stats  -> org-wide KPI counts for the landing dashboard
router.get('/stats', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const cacheKey = '__id_stats__';
  const cached = getCached(cacheKey);
  if (cached) return res.json({ ...cached, fromCache: true });

  const ldapMod = require('./ldap-secure'); // StartTLS before every bind
  const LDAP_URL       = process.env.LDAP_URL       || 'ldap://10.9.64.80:389';
  const LDAP_BASE_DN   = process.env.LDAP_BASE_DN   || 'DC=nrpi,DC=local';
  const LDAP_BIND_USER = process.env.LDAP_BIND_USER || '';
  const LDAP_BIND_PASS = process.env.LDAP_BIND_PASS || '';
  if (!LDAP_BIND_USER || !LDAP_BIND_PASS) {
    return res.status(501).json({ error: 'LDAP credentials not configured' });
  }

  let client;
  try {
    client = ldapMod.createClient({
      url: LDAP_URL, timeout: 20000, connectTimeout: 15000,
    });
    await new Promise(function(resolve, reject) {
      client.on('error', function(err) { reject(new Error('LDAP connection error: ' + err.message)); });
      client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, function(err) {
        if (err) { client.destroy(); reject(new Error('LDAP bind failed: ' + err.message)); }
        else resolve();
      });
    });

    function countFilter(filter) {
      return new Promise(function(resolve, reject) {
        var n = 0;
        client.search(LDAP_BASE_DN, {
          filter: filter, attributes: ['cn'], scope: 'sub',
          paged: { pageSize: 1000, pagePauseEnabled: false },
        }, function(err, sres) {
          if (err) return reject(err);
          sres.on('searchEntry', function() { n++; });
          sres.on('error', reject);
          sres.on('end', function() { resolve(n); });
        });
      });
    }

    // Enabled persons (UAC bit 0x2 = DISABLED must be absent)
    var activeIdentities = await countFilter('(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))');
    // Accounts carrying an active lockout timestamp (standard org-wide approximation)
    var lockedOut = await countFilter('(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))');

    var data = { activeIdentities: activeIdentities, lockedOut: lockedOut, queriedAt: new Date().toISOString() };
    setCache(cacheKey, data);
    return res.json(data);
  } catch (err) {
    console.error('[identity-routes] stats error:', err.message);
    return res.status(500).json({ error: 'LDAP query failed: ' + err.message });
  } finally {
    if (client) try { client.unbind(); } catch (_) {}
  }
});


// GET /api/identity/accounts?view=locked|all&q=&limit=
// ---------------------------------------------------------------------------
// Backs the console's persistent account list (Recent / Locked / All).
// /stats already counts these two populations with the same two filters but
// returns only integers, and /search refuses a query under two characters, so
// neither of those views had a feed. Read-only LDAP, same client/bind idiom as
// /stats above.
//
// 'locked' returns accounts carrying an ACTIVE LOCKOUT STAMP — the same
// approximation /stats counts. AD keeps lockoutTime set after the lockout
// duration has elapsed, so a stamped account may already be usable again; the
// row reports WHEN it was stamped and the caller resolves authoritative state
// by opening the account (lookup reads accountStatus.lockedOut). Nothing here
// claims an account is currently locked.
//
// Results are capped and the cap is REPORTED (truncated:true) rather than
// silently applied.
router.get('/accounts', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const view  = (str(req.query.view) || 'all').toLowerCase() === 'locked' ? 'locked' : 'all';
  const q     = String(req.query.q || '').trim().toLowerCase();
  const limit = Math.min(Math.max(parseInt(req.query.limit || '200', 10) || 200, 1), 1000);

  const cacheKey = '__id_accounts__' + view;
  let rows = getCached(cacheKey);

  if (!rows) {
    const ldapMod = require('./ldap-secure'); // StartTLS before every bind
    const LDAP_URL       = process.env.LDAP_URL       || 'ldap://10.9.64.80:389';
    const LDAP_BASE_DN   = process.env.LDAP_BASE_DN   || 'DC=nrpi,DC=local';
    const LDAP_BIND_USER = process.env.LDAP_BIND_USER || '';
    const LDAP_BIND_PASS = process.env.LDAP_BIND_PASS || '';
    if (!LDAP_BIND_USER || !LDAP_BIND_PASS) {
      return res.status(501).json({ error: 'LDAP credentials not configured', accounts: [] });
    }

    const filter = view === 'locked'
      ? '(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))'
      : '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName=*))';

    let client;
    try {
      client = ldapMod.createClient({
        url: LDAP_URL, timeout: 20000, connectTimeout: 15000,
      });
      await new Promise(function (resolve, reject) {
        client.on('error', function (err) { reject(new Error('LDAP connection error: ' + err.message)); });
        client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, function (err) {
          if (err) { client.destroy(); reject(new Error('LDAP bind failed: ' + err.message)); }
          else resolve();
        });
      });

      // Windows FILETIME (100ns ticks since 1601) -> ISO, or null when unset.
      // BigInt, not Number: lockoutTime runs past 2^53 and 0x7FFFFFFFFFFFFFFF is
      // the "never" sentinel. Same conversion identity-ldap.js uses.
      function fileTimeIso(v) {
        if (v == null || v === '') return null;
        let val;
        try { val = BigInt(String(v)); } catch (_) { return null; }
        if (val === 0n || val === 9223372036854775807n) return null;
        const ms = Number(val / 10000n - 11644473600000n);
        if (!isFinite(ms) || ms <= 0) return null;
        const d = new Date(ms);
        return isNaN(d.getTime()) ? null : d.toISOString();
      }

      rows = await new Promise(function (resolve, reject) {
        const out = [];
        client.search(LDAP_BASE_DN, {
          filter: filter,
          attributes: ['cn','displayName','sAMAccountName','userPrincipalName','mail',
                       'department','title','lockoutTime','badPwdCount','whenChanged'],
          scope: 'sub',
          paged: { pageSize: 1000, pagePauseEnabled: false },
        }, function (err, sres) {
          if (err) return reject(err);
          sres.on('searchEntry', function (entry) {
            // Same shape identity-ldap.js:parseEntry reads (ldapjs 3.x).
            const o = {};
            (entry.attributes || []).forEach(function (a) {
              o[a.type] = a.values.length === 1 ? a.values[0] : a.values;
            });
            if (!o.sAMAccountName) return;
            if (String(o.sAMAccountName).slice(-1) === '$') return;   // computer account
            out.push({
              displayName:  o.displayName || o.cn || o.sAMAccountName,
              samAccountName: o.sAMAccountName,
              upn:          o.userPrincipalName || '',
              email:        o.mail || '',
              department:   o.department || '',
              title:        o.title || '',
              lockoutTime:  fileTimeIso(o.lockoutTime),
              badPwdCount:  o.badPwdCount != null ? Number(o.badPwdCount) : null,
            });
          });
          sres.on('error', reject);
          sres.on('end', function () { resolve(out); });
        });
      });

      rows.sort(function (a, b) {
        if (view === 'locked') {
          const at = a.lockoutTime ? Date.parse(a.lockoutTime) : 0;
          const bt = b.lockoutTime ? Date.parse(b.lockoutTime) : 0;
          if (at !== bt) return bt - at;                       // most recent stamp first
        }
        return String(a.displayName).localeCompare(String(b.displayName), undefined, { sensitivity: 'base' });
      });
      setCache(cacheKey, rows);
    } catch (err) {
      console.error('[identity-routes] accounts error:', err.message);
      return res.status(500).json({ error: 'LDAP query failed: ' + err.message, accounts: [] });
    } finally {
      if (client) try { client.unbind(); } catch (_) {}
    }
  }

  let list = rows;
  if (q) {
    list = list.filter(function (r) {
      return String(r.displayName).toLowerCase().indexOf(q) >= 0
          || String(r.samAccountName).toLowerCase().indexOf(q) >= 0
          || String(r.email).toLowerCase().indexOf(q) >= 0
          || String(r.upn).toLowerCase().indexOf(q) >= 0
          || String(r.department).toLowerCase().indexOf(q) >= 0;
    });
  }
  const total = list.length;
  const truncated = total > limit;
  return res.json({
    view: view,
    accounts: list.slice(0, limit),
    count: Math.min(total, limit),
    total: total,
    truncated: truncated,
    queriedAt: new Date().toISOString(),
  });
});

// GET /api/identity/connector-health -> live probe of AD + Okta for the landing panel
router.get('/connector-health', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const out = [];

  // Active Directory: attempt a bind
  const ldapMod = require('./ldap-secure'); // StartTLS before every bind
  const LDAP_URL       = process.env.LDAP_URL       || 'ldap://10.9.64.80:389';
  const LDAP_BIND_USER = process.env.LDAP_BIND_USER || '';
  const LDAP_BIND_PASS = process.env.LDAP_BIND_PASS || '';
  await new Promise(function(resolve) {
    if (!LDAP_BIND_USER || !LDAP_BIND_PASS) { out.push({ name: 'Active Directory', status: 'unconfigured' }); return resolve(); }
    var c, done = false;
    function finish(st) { if (done) return; done = true; try { if (c) c.unbind(); } catch (_) {} out.push({ name: 'Active Directory', status: st }); resolve(); }
    try {
      c = ldapMod.createClient({ url: LDAP_URL, timeout: 8000, connectTimeout: 8000 });
      c.on('error', function() { finish('offline'); });
      c.bind(LDAP_BIND_USER, LDAP_BIND_PASS, function(err) { finish(err ? 'offline' : 'online'); });
    } catch (e) { finish('offline'); }
    setTimeout(function() { finish('offline'); }, 9000);
  });

  // Okta: lightweight authenticated call
  try {
    const { oktaRequest } = require('./okta-lookup');
    const r = await oktaRequest('/api/v1/users?limit=1');
    out.push({ name: 'Okta', status: (r && r.status >= 200 && r.status < 300) ? 'online' : 'degraded' });
  } catch (e) {
    out.push({ name: 'Okta', status: /not configured/i.test(e.message) ? 'unconfigured' : 'offline' });
  }

  return res.json({ connectors: out, queriedAt: new Date().toISOString() });
});

// GET /api/identity/entra-failures?hours=24 -> failed Entra ID sign-ins grouped by user
// Reads the entra_signin_logs table populated by entra-sync.js (no live Graph call).
router.get('/entra-failures', rbac.requirePage('identity-diag','read'), async (req, res) => {
  let hours = parseInt(req.query.hours, 10);
  if (!hours || hours < 1 || hours > 720) hours = 24;
  const cacheKey = '__entra_fail__' + hours;
  const cached = getCached(cacheKey);
  if (cached) return res.json({ ...cached, fromCache: true });

  try {
    const [rows] = await rbacPool.query(
      "SELECT COALESCE(user_display_name, user_principal_name) AS `User`, " +
      "  user_principal_name AS `UPN`, " +
      "  COUNT(*) AS `Failures`, " +
      "  MAX(created_at) AS `Last attempt`, " +
      "  GROUP_CONCAT(DISTINCT status_error_code ORDER BY status_error_code SEPARATOR ', ') AS `Error codes`, " +
      "  MAX(status_failure_reason) AS `Reason`, " +
      "  COUNT(DISTINCT ip_address) AS `IPs` " +
      "FROM corpit_hub.entra_signin_logs " +
      "WHERE status_error_code IS NOT NULL AND status_error_code <> 0 " +
      "  AND created_at >= (NOW() - INTERVAL ? HOUR) " +
      "GROUP BY user_principal_name, user_display_name " +
      "ORDER BY `Failures` DESC, `Last attempt` DESC " +
      "LIMIT 200",
      [hours]
    );
    const data = { failures: rows, hours: hours, queriedAt: new Date().toISOString() };
    setCache(cacheKey, data);
    return res.json(data);
  } catch (err) {
    console.error('[identity-routes] entra-failures error:', err.message);
    return res.status(500).json({ error: 'Query failed: ' + err.message, failures: [] });
  }
});


// GET /api/identity/okta-timeline?q=user@domain.com&hours=24
router.get('/okta-timeline', rbac.requirePage('identity-diag','read'), async (req, res) => {
  let oktaRequest, oktaFilterValue;
  try { ({ oktaRequest, oktaFilterValue } = require('./okta-lookup')); }
  catch (e) { return res.status(501).json({ error: 'okta-lookup module not available', events: [] }); }
  if (!process.env.OKTA_BASE_URL || !process.env.OKTA_API_TOKEN) {
    return res.status(501).json({ error: 'Okta not configured', events: [] });
  }
  let q = String(req.query.q || '').trim();
  if (!q) return res.status(400).json({ error: 'User identifier required (?q=email)', events: [] });
  if (!oktaFilterValue(q)) return res.status(400).json({ error: 'Invalid user identifier', events: [] });
  const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 24, 1), 720);
  try {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
    try { const _u = await oktaRequest('/api/v1/users/' + encodeURIComponent(q)); if (_u.status === 200 && _u.body && _u.body.profile) q = _u.body.profile.login || q; } catch(_e){}
    const filter = 'actor.alternateId eq "' + q + '"';
    const logPath = '/api/v1/logs?since=' + encodeURIComponent(since) + '&filter=' + encodeURIComponent(filter) + '&sortOrder=DESCENDING&limit=200';
    const logRes = await oktaRequest(logPath);
    if (logRes.status !== 200) {
      return res.status(502).json({ error: 'Okta system log returned HTTP ' + logRes.status, events: [] });
    }
    const raw = (Array.isArray(logRes.body) ? logRes.body : []).filter(function(ev){ return (ev.eventType || "").indexOf("rate_limit") < 0; });
    const events = raw.map(function(ev) {
      const type = ev.eventType || '';
      const outcome = ev.outcome ? ev.outcome.result : '';
      let category = 'other';
      if (type.indexOf('session.start') >= 0 || type.indexOf('authentication.sso') >= 0) {
        category = outcome === 'SUCCESS' ? 'login_success' : 'login_failure';
      } else if (type.indexOf('authentication.auth_via') >= 0 || type.indexOf('verify') >= 0) {
        category = outcome === 'SUCCESS' ? 'mfa_success' : 'mfa_failure';
      } else if (type.indexOf('mfa.factor') >= 0) {
        category = 'mfa_change';
      } else if (type.indexOf('credential.password') >= 0 || type.indexOf('password') >= 0) {
        category = 'password';
      } else if (type.indexOf('account.lock') >= 0) {
        category = 'lockout';
      } else if (type.indexOf('account.unlock') >= 0 || type.indexOf('unlock') >= 0) {
        category = 'unlock';
      } else if (type.indexOf('session.end') >= 0 || type.indexOf('logout') >= 0) {
        category = 'logout';
      } else if (type.indexOf('lifecycle') >= 0 || type.indexOf('suspend') >= 0 || type.indexOf('unsuspend') >= 0) {
        category = 'lifecycle';
      } else if (type.indexOf('app.') >= 0 || type.indexOf('application') >= 0) {
        category = 'app_access';
      } else if (outcome === 'FAILURE') {
        category = 'login_failure';
      }

      return {
        published: ev.published,
        eventType: type,
        category: category,
        outcome: outcome,
        reason: ev.outcome ? ev.outcome.reason || '' : '',
        displayMessage: ev.displayMessage || '',
        severity: ev.severity || 'INFO',
        ipAddress: ev.client ? ev.client.ipAddress : '',
        userAgent: ev.client && ev.client.userAgent
          ? (ev.client.userAgent.browser || '') + ' / ' + (ev.client.userAgent.os || '') : '',
        city: ev.client && ev.client.geographicalContext
          ? ev.client.geographicalContext.city || '' : '',
        state: ev.client && ev.client.geographicalContext
          ? ev.client.geographicalContext.state || '' : '',
        country: ev.client && ev.client.geographicalContext
          ? ev.client.geographicalContext.country || '' : '',
        target: ev.target && ev.target.length > 0
          ? ev.target[0].displayName || ev.target[0].alternateId || '' : '',
      };
    });

    const summary = {};
    events.forEach(function(e) { summary[e.category] = (summary[e.category] || 0) + 1; });

    return res.json({ events: events, count: events.length, since: since, user: q, summary: summary });
  } catch (err) {
    console.error('[identity-routes] okta-timeline error:', err.message);
    return res.status(500).json({ error: 'Okta timeline query failed: ' + err.message, events: [] });
  }
});

// GET /api/identity/okta-sessions?q=user@domain.com
router.get('/okta-sessions', rbac.requirePage('identity-diag','read'), async (req, res) => {
  let oktaRequest;
  try { ({ oktaRequest } = require('./okta-lookup')); }
  catch (e) { return res.status(501).json({ error: 'okta-lookup module not available', sessions: [] }); }
  if (!process.env.OKTA_BASE_URL || !process.env.OKTA_API_TOKEN) {
    return res.status(501).json({ error: 'Okta not configured', sessions: [] });
  }
  const q = str(req.query.q).trim();
  if (!q) return res.status(400).json({ error: 'User identifier required', sessions: [] });
  try {
    const userRes = await oktaRequest('/api/v1/users/' + encodeURIComponent(q));
    // Per-source measurement ledger (srcOk / srcUnknown / srcSummary, top of file).
    // Nothing is attached to a response unless a source is 'unknown' (fail-quiet).
    const sources = {};
    // Measured: Okta has no such user, so zero sessions is a real answer, not a
    // could-not-ask. Nothing is 'unknown', so this reply stays as it is today.
    if (userRes.status === 404) return res.json({ sessions: [], count: 0, user: q, error: 'User not found' });
    if (userRes.status !== 200) return res.status(502).json({ error: 'Okta HTTP ' + userRes.status, sessions: [] });
    const userId = userRes.body.id;
    const profile = userRes.body.profile || {};
    const displayName = (profile.firstName || '') + ' ' + (profile.lastName || '');
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    // The System Log 'eq' operator is CASE-SENSITIVE while /api/v1/users is not:
    // looking up "jriggs@auction.com" succeeds, but the log stores the actor as
    // "Jriggs@auction.com", so an alternateId filter built from whatever the
    // operator typed silently matched nothing and every account read as
    // "no sign-in events". actor.id is canonical and immune to casing.
    const filter = 'actor.id eq "' + userId + '"';
    const evtFilter = filter + ' and eventType eq "user.session.start"';
    const logRes = await oktaRequest('/api/v1/logs?since=' + encodeURIComponent(since) + '&filter=' + encodeURIComponent(evtFilter) + '&sortOrder=DESCENDING&limit=20');
    const sessions = [];
    if (logRes.status === 200 && Array.isArray(logRes.body)) {
      logRes.body.forEach(function(ev) {
        sessions.push({
          id: ev.uuid || '',
          published: ev.published,
          outcome: ev.outcome ? ev.outcome.result : '',
          ipAddress: ev.client ? ev.client.ipAddress : '',
          userAgent: ev.client && ev.client.userAgent ? (ev.client.userAgent.browser || '') + ' / ' + (ev.client.userAgent.os || '') : '',
          city: ev.client && ev.client.geographicalContext ? ev.client.geographicalContext.city || '' : '',
          state: ev.client && ev.client.geographicalContext ? ev.client.geographicalContext.state || '' : '',
          country: ev.client && ev.client.geographicalContext ? ev.client.geographicalContext.country || '' : '',
          amr: ev.authenticationContext ? ev.authenticationContext.authenticationProvider || '' : '',
        });
      });
      sources.oktaSystemLog = srcOk('Okta system log', sessions.length);
    } else {
      // Okta answered, but not with a usable log page (429 rate limit, 403,
      // 5xx, or a non-array body). We did NOT measure this user's sessions,
      // so say so instead of returning a confident zero.
      sources.oktaSystemLog = srcUnknown('Okta system log',
        new Error(logRes.status === 200 ? 'unexpected system-log response shape' : 'Okta HTTP ' + logRes.status),
        'okta-sessions system log unavailable');
    }
    const srcRoll = srcSummary(sources);
    const payload = { sessions: sessions, count: sessions.length, user: q, userId: userId, displayName: displayName, oktaStatus: userRes.body.status };
    // Fail-quiet: attach the ladder only when a source could not be measured.
    if (srcRoll.partial) { payload.sources = sources; payload.unavailable = srcRoll.unavailable; }
    return res.json(payload);
  } catch (err) {
    console.error('[identity-routes] okta-sessions error:', err.message);
    return res.status(500).json({ error: err.message, sessions: [] });
  }
});

// DELETE /api/identity/okta-sessions/clear?userId=xxx
router.delete('/okta-sessions/clear', rbac.requirePage('identity-diag','admin'), async (req, res) => {
  let oktaDelete;
  try { ({ oktaDelete } = require('./okta-lookup')); }
  catch (e) { return res.status(501).json({ error: 'okta-lookup module not available' }); }
  if (!oktaDelete) return res.status(501).json({ error: 'oktaDelete not available' });
  const userId = String(req.query.userId || '').trim();
  if (!userId) return res.status(400).json({ error: 'userId required' });
  // Audit target: the subject's Okta login, resolved server-side from the id
  // so the audit row never trusts a client-supplied name. Null if Okta will
  // not say; the id itself is always kept in details.
  let target = null;
  try {
    const { oktaRequest } = require('./okta-lookup');
    const u = await oktaRequest('/api/v1/users/' + encodeURIComponent(userId));
    if (u.status === 200 && u.body && u.body.profile && u.body.profile.login) target = String(u.body.profile.login).slice(0, 255);
  } catch (_e) {}
  try {
    const result = await oktaDelete('/api/v1/users/' + encodeURIComponent(userId) + '/sessions');
    if (result.status === 204 || result.status === 200) {
      console.log('[identity-routes] all sessions cleared for user:', userId);
      await rbac.audit(req, 'okta-sessions-clear', target, 'identity-diag', { oktaUserId: userId, httpStatus: result.status });
      return res.json({ success: true, message: 'All sessions cleared' });
    }
    await rbac.audit(req, 'okta-sessions-clear-ERROR', target, 'identity-diag', { oktaUserId: userId, httpStatus: result.status || null, error: 'Okta returned HTTP ' + result.status });
    return res.status(result.status || 500).json({ success: false, error: 'Okta returned HTTP ' + result.status, body: result.body });
  } catch (err) {
    console.error('[identity-routes] clear sessions error:', err.message);
    await rbac.audit(req, 'okta-sessions-clear-ERROR', target, 'identity-diag', { oktaUserId: userId, error: String(err.message || err).slice(0, 300) });
    return res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/identity/okta-group-apps?q=user@domain.com
router.get('/okta-group-apps', rbac.requirePage('identity-diag','read'), async (req, res) => {
  let oktaRequest;
  try { ({ oktaRequest } = require('./okta-lookup')); }
  catch (e) { return res.status(501).json({ error: 'okta-lookup module not available' }); }
  if (!process.env.OKTA_BASE_URL || !process.env.OKTA_API_TOKEN) {
    return res.status(501).json({ error: 'Okta not configured' });
  }
  const q = str(req.query.q).trim();
  if (!q) return res.status(400).json({ error: 'User identifier required' });
  try {
    // 1. Get user
    const userRes = await oktaRequest('/api/v1/users/' + encodeURIComponent(q));
    if (userRes.status !== 200) return res.status(404).json({ error: 'User not found in Okta' });
    const userId = userRes.body.id;
    const profile = userRes.body.profile || {};
    const oktaStatus = userRes.body.status;

    // Every sub-call below degrades to an empty array on a non-200. Without a
    // record of which ones failed, a throttled or unauthorised Okta produced a
    // successful 200 reporting zero accessible applications -- which the
    // offboarding audit reads as "application access removed". Same
    // `unavailable: []` convention as /devices and /okta-sessions.
    const unavailable = [];

    // 2. Get user's direct app assignments
    const appLinksRes = await oktaRequest('/api/v1/users/' + userId + '/appLinks');
    const appLinks = (appLinksRes.status === 200 && Array.isArray(appLinksRes.body)) ? appLinksRes.body : [];
    if (appLinksRes.status !== 200) unavailable.push('Direct app assignments could not be read (Okta /appLinks HTTP ' + appLinksRes.status + ')');

    // 3. Get user's groups
    const groupsRes = await oktaRequest('/api/v1/users/' + userId + '/groups');
    const allGroups = (groupsRes.status === 200 && Array.isArray(groupsRes.body)) ? groupsRes.body : [];
    if (groupsRes.status !== 200) unavailable.push('Group membership could not be read (Okta /groups HTTP ' + groupsRes.status + ') — no group-derived application access is listed below');

    // 4. Filter to meaningful groups (skip Everyone, built-in Okta groups)
    const skipGroups = ['everyone'];
    const meaningfulGroups = allGroups.filter(function(g) {
      const name = (g.profile && g.profile.name || '').toLowerCase();
      if (skipGroups.indexOf(name) >= 0) return false;
      if (g.type === 'BUILT_IN') return false;
      return true;
    });

    // 5. For each meaningful group (limit to 25 to avoid rate limits), get assigned apps
    const groupsToQuery = meaningfulGroups.slice(0, 25);
    const groupAppMap = [];
    const failedGroups = [];
    const batchSize = 5;
    for (let i = 0; i < groupsToQuery.length; i += batchSize) {
      const batch = groupsToQuery.slice(i, i + batchSize);
      const batchPromises = batch.map(function(g) {
        return oktaRequest('/api/v1/groups/' + g.id + '/apps')
          .then(function(r) {
            const apps = (r.status === 200 && Array.isArray(r.body)) ? r.body : [];
            if (r.status !== 200) failedGroups.push((g.profile && g.profile.name) || g.id);
            if (apps.length > 0) {
              groupAppMap.push({
                groupId: g.id,
                groupName: g.profile ? g.profile.name : 'Unknown',
                groupType: g.type || 'UNKNOWN',
                source: g.objectClass && g.objectClass.indexOf('okta:windows_security_principal') >= 0 ? 'AD Synced' :
                        g.type === 'APP_GROUP' ? 'App Group' : 'Okta Group',
                apps: apps.map(function(a) {
                  return {
                    appId: a.id,
                    name: a.label || a.name || 'Unknown',
                    status: a.status || 'UNKNOWN',
                    signOnMode: a.signOnMode || '',
                  };
                }),
                appCount: apps.length,
              });
            }
          })
          .catch(function(e) { failedGroups.push(((g.profile && g.profile.name) || g.id) + ': ' + e.message); });
      });
      await Promise.allSettled(batchPromises);
    }

    // 6. Build deduplicated app list with access sources
    const appAccessMap = {};
    // From direct appLinks
    appLinks.forEach(function(a) {
      const key = (a.label || a.appName || '').toLowerCase();
      if (!appAccessMap[key]) appAccessMap[key] = { name: a.label || a.appName, sources: [], status: 'ACTIVE' };
      appAccessMap[key].sources.push('Direct Assignment');
    });
    // From groups
    groupAppMap.forEach(function(g) {
      g.apps.forEach(function(a) {
        const key = (a.name || '').toLowerCase();
        if (!appAccessMap[key]) appAccessMap[key] = { name: a.name, sources: [], status: a.status };
        appAccessMap[key].sources.push(g.groupName + ' (' + g.source + ')');
      });
    });

    // Deduplicate sources
    Object.values(appAccessMap).forEach(function(a) {
      a.sources = [...new Set(a.sources)];
    });

    return res.json({
      user: q,
      oktaStatus: oktaStatus,
      displayName: (profile.firstName || '') + ' ' + (profile.lastName || ''),
      totalGroups: allGroups.length,
      meaningfulGroups: meaningfulGroups.length,
      queriedGroups: groupsToQuery.length,
      groupsWithApps: groupAppMap.length,
      groupAppMap: groupAppMap.sort(function(a, b) { return b.appCount - a.appCount; }),
      allAccessibleApps: Object.values(appAccessMap).sort(function(a, b) { return b.sources.length - a.sources.length; }),
      totalAccessibleApps: Object.keys(appAccessMap).length,
      directAppLinks: appLinks.length,
      failedGroups: failedGroups,
      // Genuine read failures only. The 25-group ceiling is already reported
      // separately as meaningfulGroups vs queriedGroups.
      unavailable: unavailable.concat(
        failedGroups.length ? [failedGroups.length + ' group(s) could not be expanded: ' + failedGroups.slice(0, 5).join(', ') + (failedGroups.length > 5 ? ', …' : '')] : []
      ),
    });
  } catch (err) {
    console.error('[identity-routes] okta-group-apps error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// Gated 2026-09-07: this reports the domain controller URL, the base DN and
// which integrations are loaded. That is infrastructure recon, not a
// liveness probe, and it binds to LDAP on every call.
router.get('/health', rbac.requirePage('identity-diag','read'), async (req, res) => {
  try {
    await lookupUser('krbtgt');
    return res.json({
      status: 'ok',
      dc: process.env.LDAP_URL || 'ldap://10.9.64.80:389',
      domain: process.env.LDAP_BASE_DN || 'DC=nrpi,DC=local',
      zscaler: lookupZscalerUser ? 'loaded' : 'not configured',
      okta: lookupOktaUser ? 'loaded' : 'not configured',
      actions: unlockAccount ? 'loaded' : 'not configured',
      winrm: process.env.WINRM_USER ? 'configured' : 'not configured',
      checkedAt: new Date().toISOString(),
    });
  } catch (err) {
    return res.status(503).json({ status: 'error', message: err.message });
  }
});

router.post('/cache/clear', rbac.requirePage('identity-diag','admin'), async (req, res) => {
  const size = cache.size;
  cache.clear();
  await rbac.audit(req, 'identity-cache-clear', null, 'identity-diag', { cleared: size });
  res.json({ cleared: size, message: 'Cleared ' + size + ' cached entries' });
});


// ── Password Spray Alerts (Entra / Okta / AD) ──
// Reads sdops_spray, returns windows whose activity is still within the
// configured detection window (default 60m). Populated by collect-spray.js.
router.get('/spray-alerts', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const windowMin = parseInt(process.env.SPRAY_WINDOW_MIN || '60', 10);
  const slowWindowMin = parseInt(process.env.SPRAY_SLOW_WINDOW_MIN || '1440', 10);
  const hoursParam = parseInt(req.query.hours, 10);
  const explicitRange = Number.isFinite(hoursParam) && hoursParam > 0;
  const rangeMin = explicitRange ? hoursParam * 60 : windowMin;
  const slowRangeMin = explicitRange ? rangeMin : slowWindowMin;
  if (!router._devicePool) {
    try {
      const mysql = require('mysql2/promise');
      router._devicePool = mysql.createPool({
        host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
        database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
        waitForConnections: true, connectionLimit: 3, charset: 'utf8mb4',
      });
    } catch (e) {
      return res.status(500).json({ error: 'Database connection failed', alerts: [] });
    }
  }
  try {
    const [rows] = await router._devicePool.query(
      `SELECT source, window_kind, src_ip, distinct_users, total_attempts, window_start, window_end,
              country, city, sample_users, first_seen, last_seen
         FROM sdops_spray
        WHERE (window_kind = 'fast' AND last_seen >= (NOW() - INTERVAL ? MINUTE))
           OR (window_kind = 'slow' AND last_seen >= (NOW() - INTERVAL ? MINUTE))
        ORDER BY distinct_users DESC, total_attempts DESC
        LIMIT 100`,
      [rangeMin, slowRangeMin]
    );
    const alerts = rows.map(function (r) {
      let users = [];
      try { users = typeof r.sample_users === 'string' ? JSON.parse(r.sample_users) : (r.sample_users || []); } catch (e) {}
      return {
        source: r.source,
        windowKind: r.window_kind,
        srcIp: r.src_ip,
        distinctUsers: r.distinct_users,
        totalAttempts: r.total_attempts,
        windowStart: r.window_start,
        windowEnd: r.window_end,
        country: r.country,
        city: r.city,
        sampleUsers: users,
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
      };
    });
    return res.json({ windowMinutes: windowMin, rangeMinutes: rangeMin, slowRangeMinutes: slowRangeMin, count: alerts.length, alerts: alerts });
  } catch (e) {
    console.error('[identity-routes] spray-alerts error:', e.message);
    return res.status(500).json({ error: 'Spray alert query failed', message: e.message, alerts: [] });
  }
});
// ── Password Spray Summary (count-only, for landing page badge) ──
router.get('/spray-summary', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const windowMin = parseInt(process.env.SPRAY_WINDOW_MIN || '60', 10);
  const slowWindowMin = parseInt(process.env.SPRAY_SLOW_WINDOW_MIN || '1440', 10);
  if (!router._devicePool) {
    try {
      const mysql = require('mysql2/promise');
      router._devicePool = mysql.createPool({
        host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
        database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
        waitForConnections: true, connectionLimit: 3, charset: 'utf8mb4',
      });
    } catch (e) {
      return res.status(500).json({ error: 'Database connection failed', count: 0 });
    }
  }
  try {
    const [rows] = await router._devicePool.query(
      `SELECT source, COUNT(*) AS c
         FROM sdops_spray
        WHERE (window_kind = 'fast' AND last_seen >= (NOW() - INTERVAL ? MINUTE))
           OR (window_kind = 'slow' AND last_seen >= (NOW() - INTERVAL ? MINUTE))
        GROUP BY source
        ORDER BY c DESC`,
      [windowMin, slowWindowMin]
    );
    let count = 0, topSource = null;
    for (const r of rows) { count += r.c; if (!topSource) topSource = r.source; }
    return res.json({ count: count, topSource: topSource });
  } catch (e) {
    console.error('[identity-routes] spray-summary error:', e.message);
    return res.status(500).json({ error: 'Spray summary query failed', count: 0 });
  }
});


// ── Password Spray Allowlist (known-benign egress IPs, e.g. Zscaler tunnel) ──
// GET is read; add/remove are admin (matches unlock/reset-password gating).
router.get('/spray-allowlist', rbac.requirePage('identity-diag','read'), async (req, res) => {
  if (!router._devicePool) {
    const mysql = require('mysql2/promise');
    router._devicePool = mysql.createPool({
      host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
      database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
      waitForConnections: true, connectionLimit: 3, charset: 'utf8mb4',
    });
  }
  try {
    const [rows] = await router._devicePool.query(
      'SELECT id, ip, label, note, added_by, added_at FROM sdops_spray_allowlist ORDER BY added_at DESC'
    );
    return res.json({ count: rows.length, entries: rows });
  } catch (e) {
    console.error('[identity-routes] spray-allowlist get error:', e.message);
    return res.status(500).json({ error: 'Allowlist query failed', entries: [] });
  }
});

router.post('/spray-allowlist', rbac.requirePage('identity-diag','admin'), async (req, res) => {
  if (!router._devicePool) {
    const mysql = require('mysql2/promise');
    router._devicePool = mysql.createPool({
      host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
      database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
      waitForConnections: true, connectionLimit: 3, charset: 'utf8mb4',
    });
  }
  const ip = str(req.body && req.body.ip).trim();
  const label = str(req.body && req.body.label).trim() || null;
  const note = str(req.body && req.body.note).trim() || null;
  // Basic IPv4/IPv6 sanity — reject anything that isn't plausibly an IP.
  if (!ip || !/^[0-9a-fA-F:.]{3,45}$/.test(ip)) {
    return res.status(400).json({ error: 'A valid IP address is required' });
  }
  const who = (req.rbac && req.rbac.user) || (req.user && (req.user.upn || req.user.email)) || 'unknown';
  try {
    await router._devicePool.query(
      `INSERT INTO sdops_spray_allowlist (ip, label, note, added_by)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE label = VALUES(label), note = VALUES(note), added_by = VALUES(added_by)`,
      [ip, label, note, who]
    );
    // Purge any already-flagged rows for this IP so the alert clears immediately.
    const [del] = await router._devicePool.query('DELETE FROM sdops_spray WHERE src_ip = ?', [ip]);
    await rbac.audit(req, 'spray-allowlist-add', null, 'identity-diag', { ip: ip, label: label, note: note, purgedFlagged: del.affectedRows || 0 });
    return res.json({ ok: true, ip: ip, purgedFlagged: del.affectedRows || 0 });
  } catch (e) {
    console.error('[identity-routes] spray-allowlist post error:', e.message);
    await rbac.audit(req, 'spray-allowlist-add-ERROR', null, 'identity-diag', { ip: ip, label: label, error: String(e.message || e).slice(0, 300) });
    return res.status(500).json({ error: 'Allowlist insert failed', message: e.message });
  }
});

router.delete('/spray-allowlist/:id', rbac.requirePage('identity-diag','admin'), async (req, res) => {
  if (!router._devicePool) {
    const mysql = require('mysql2/promise');
    router._devicePool = mysql.createPool({
      host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
      database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
      waitForConnections: true, connectionLimit: 3, charset: 'utf8mb4',
    });
  }
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });
  try {
    // Read the row first so the audit entry names the IP, not just the id.
    const [pre] = await router._devicePool.query('SELECT ip, label FROM sdops_spray_allowlist WHERE id = ?', [id]);
    const [r] = await router._devicePool.query('DELETE FROM sdops_spray_allowlist WHERE id = ?', [id]);
    await rbac.audit(req, 'spray-allowlist-delete', null, 'identity-diag', { id: id, ip: (pre[0] && pre[0].ip) || null, label: (pre[0] && pre[0].label) || null, removed: r.affectedRows || 0 });
    return res.json({ ok: true, removed: r.affectedRows || 0 });
  } catch (e) {
    console.error('[identity-routes] spray-allowlist delete error:', e.message);
    await rbac.audit(req, 'spray-allowlist-delete-ERROR', null, 'identity-diag', { id: id, error: String(e.message || e).slice(0, 300) });
    return res.status(500).json({ error: 'Allowlist delete failed', message: e.message });
  }
});

// ── Possible Compromise (sprayed user → subsequent successful auth) ──
// Louder tier than a flagged IP: a targeted account actually got in.
// ip_match=1 means the success also came from the flagged spray IP.
router.get('/compromise-alerts', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const windowMin = parseInt(process.env.SPRAY_WINDOW_MIN || '60', 10);
  const slowWindowMin = parseInt(process.env.SPRAY_SLOW_WINDOW_MIN || '1440', 10);
  const hoursParam = parseInt(req.query.hours, 10);
  const rangeMin = (Number.isFinite(hoursParam) && hoursParam > 0) ? hoursParam * 60 : slowWindowMin;
  if (!router._devicePool) {
    const mysql = require('mysql2/promise');
    router._devicePool = mysql.createPool({
      host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
      database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
      waitForConnections: true, connectionLimit: 3, charset: 'utf8mb4',
    });
  }
  try {
    const [rows] = await router._devicePool.query(
      `SELECT username, success_source, spray_source, spray_ip, spray_window_start,
              spray_window_kind, success_time, success_ip, success_country, success_city,
              ip_match, first_seen, last_seen
         FROM sdops_compromise
        WHERE last_seen >= (NOW() - INTERVAL ? MINUTE)
        ORDER BY ip_match DESC, success_time DESC
        LIMIT 200`,
      [rangeMin]
    );
    const alerts = rows.map(function (r) {
      return {
        username: r.username,
        successSource: r.success_source,
        spraySource: r.spray_source,
        sprayIp: r.spray_ip,
        sprayWindowStart: r.spray_window_start,
        sprayWindowKind: r.spray_window_kind,
        successTime: r.success_time,
        successIp: r.success_ip,
        successCountry: r.success_country,
        successCity: r.success_city,
        ipMatch: r.ip_match === 1,
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
      };
    });
    const ipMatches = alerts.filter(function (a) { return a.ipMatch; }).length;
    return res.json({ rangeMinutes: rangeMin, count: alerts.length, ipMatches: ipMatches, alerts: alerts });
  } catch (e) {
    console.error('[identity-routes] compromise-alerts error:', e.message);
    return res.status(500).json({ error: 'Compromise alert query failed', message: e.message, alerts: [] });
  }
});

// ── Portal Self-Lookup (no RBAC — returns only safe profile fields for form pre-fill) ──
// Used by accessportal.itam.nrpi.local to auto-populate the requester's own info.
// Accepts a work email / UPN / sAMAccountName. Returns minimal AD profile fields.
// Rate-limiting comes from the global middleware; nginx also restricts this
// location to the access portal vhost only.
// Gated 2026-09-07. This returns display name, email, department, title,
// manager and sAMAccountName for any identity the caller names -- a
// directory-enumeration primitive -- and was 1 of only 2 routes in this
// file without a gate, against 25 that have one. An omission, not a design.
router.get('/portal-lookup', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const q = str(req.query.q).trim();
  if (!q) return res.status(400).json({ error: 'Query parameter "q" is required' });
  if (q.length > 256) return res.status(400).json({ error: 'Query too long' });
  // Require it to look like an email/UPN or a short sAMAccountName (no arbitrary LDAP injection risk)
  const looksValid = /^[a-zA-Z0-9._\-+@]{2,128}$/.test(q);
  if (!looksValid) return res.status(400).json({ error: 'Invalid query format' });
  try {
    const result = await lookupUser(q);
    if (!result) return res.status(404).json({ error: 'User not found', identity: q });
    return res.json({
      name:        result.displayName  || '',
      email:       result.email        || result.upn || '',
      department:  result.department   || '',
      title:       result.title        || '',
      manager:     result.manager      || '',
      samAccount:  result.samAccountName || '',
    });
  } catch (err) {
    console.error('[identity-routes] portal-lookup error:', err.message);
    const isConn = /connection|ECONNREFUSED|ETIMEDOUT|bind/i.test(err.message);
    return res.status(isConn ? 503 : 500).json({ error: isConn ? 'AD connection failed' : 'Lookup failed' });
  }
});

// -- Force Replicate & Sync + Add-to-AD-group (identity-sync-routes) --
try {
  require('./identity-sync-routes').register(router, rbac, cache);
  console.log('[identity-routes] identity-sync-routes registered');
} catch (e) {
  console.error('[identity-routes] identity-sync-routes failed to register:', e.message);
}

module.exports = router;
