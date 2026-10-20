/**
 * housekeeping.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Express router for AD Housekeeping / Cleanup Dashboard
 *
 * Discovery (READ) → LDAP
 * Actions (WRITE)  → WinRM via housekeeping-actions.py
 * Audit             → MySQL housekeeping_audit table
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const express    = require('express');
const ldap       = require('ldapjs');
const { execFile } = require('child_process');
const path       = require('path');
const router     = express.Router();
// ---- RBAC enforcement (Slice 2: ad-housekeeping) ----
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
// ---------------------------------------------------------------------

// ─── Config ──────────────────────────────────────────────────────────────────
const LDAP_URL       = process.env.LDAP_URL       || 'ldap://10.9.64.80:389';
const LDAP_BASE_DN   = process.env.LDAP_BASE_DN   || 'DC=nrpi,DC=local';
const LDAP_BIND_USER = process.env.LDAP_BIND_USER || '';
const LDAP_BIND_PASS = process.env.LDAP_BIND_PASS || '';
const LDAP_TIMEOUT   = 15000;

const STALE_DAYS     = 90;
const PWD_STALE_DAYS = 180;

// OUs to exclude from stale-user scanning (kept for backward-compat;
// the new scan path uses classifyScope() below instead)
const EXCLUDED_OU_PATTERNS = [
  'service accounts',
  'disabled objects',
];

// ─── Scope classification ──────────────────────────────────────────────────
// Every flagged user gets a _scope tag. The frontend filters by scope at
// render time so service accounts no longer disappear silently — they just
// appear under the "Service & shared" scope tab instead of the primary view.
//
//   'users'           — /Accounts/Users (primary remediation focus)
//   'service-shared'  — service / specialty / SaaS service / test OUs,
//                       0365 shared mailboxes, .Conf_ named accounts
//   'other'           — admins, Users-Others, anything outside the above
//   'skip'            — Disabled Objects OU (graveyard, do not scan at all)
const SERVICE_SHARED_OUS = new Set([
  'SERVICE ACCOUNTS',
  'SAAS SERVICE ACCOUNTS',
  'SPECIALTY ACCOUNTS',
  'TEST OU',
  '0365 SHARED MAILBOXES',
]);
const SKIP_OUS = new Set(['DISABLED OBJS', 'DISABLED OBJECTS']);

function classifyScope(dn, displayName) {
  if (!dn) return 'other';
  const ous = dn.split(',')
    .map(s => s.trim())
    .filter(p => /^OU=/i.test(p))
    .map(p => p.substring(3).toUpperCase());
  if (ous.some(ou => SKIP_OUS.has(ou))) return 'skip';
  if (displayName && /^\.Conf_/i.test(displayName)) return 'service-shared';
  if (ous.some(ou => SERVICE_SHARED_OUS.has(ou))) return 'service-shared';
  if (ous[0] === 'USERS' && ous[1] === 'ACCOUNTS') return 'users';
  return 'other';
}

// ─── In-memory scan cache ──────────────────────────────────────────────────
// Shared across all clients of this PM2 process. First request triggers the
// LDAP work; subsequent requests within SCAN_CACHE_TTL_MS get the cached
// payload silently. ?force=1 bypasses. Action/revert/restore endpoints call
// cacheInvalidate() to ensure the next scan reflects the change.
const SCAN_CACHE_TTL_MS = 5 * 60 * 1000;
const scanCache = { users: null, groups: null, computers: null };

function cacheGet(kind) {
  const c = scanCache[kind];
  if (!c) return null;
  if (Date.now() - c.ts > SCAN_CACHE_TTL_MS) return null;
  return c;
}
function cacheSet(kind, payload) {
  scanCache[kind] = { ts: Date.now(), payload };
}
function cacheInvalidate() {
  scanCache.users = null;
  scanCache.groups = null;
  scanCache.computers = null;
}

// Disabled Objects OU (move target for cleanup)
const DISABLED_OU = process.env.HK_DISABLED_OU || 'OU=Disabled Objs,DC=NRPI,DC=LOCAL';

// Privileged groups to flag
const PRIVILEGED_GROUPS = [
  'domain admins', 'enterprise admins', 'schema admins',
  'administrators', 'account operators', 'backup operators',
  'server operators', 'dns admins',
];

// ─── LDAP Helpers ────────────────────────────────────────────────────────────

function parseEntry(entry) {
  const obj = {};
  entry.attributes.forEach(a => {
    if (a.type === 'objectSid') { obj.objectSid = a.buffers[0]; return; }   // binary: .values would decode it as text
    obj[a.type] = a.values.length === 1 ? a.values[0] : a.values;
  });
  return obj;
}

function createClient() {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({
      url: LDAP_URL, timeout: LDAP_TIMEOUT, connectTimeout: LDAP_TIMEOUT,
      tlsOptions: { rejectUnauthorized: false },
    });
    client.on('error', err => reject(new Error(`LDAP connection: ${err.message}`)));
    client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, err => {
      if (err) { client.destroy(); return reject(new Error(`LDAP bind: ${err.message}`)); }
      resolve(client);
    });
  });
}

function ldapSearch(client, base, filter, attributes, sizeLimit = 0, scope = 'sub') {
  return new Promise((resolve, reject) => {
    const entries = [];
    client.search(base, { filter, attributes, scope, sizeLimit, paged: { pageSize: 500 } }, (err, res) => {
      if (err) return reject(new Error(`LDAP search: ${err.message}`));
      res.on('searchEntry', entry => entries.push(parseEntry(entry)));
      res.on('error', err => {
        if (err.message && err.message.includes('Size Limit')) resolve(entries);
        else reject(new Error(`LDAP stream: ${err.message}`));
      });
      res.on('end', () => resolve(entries));
    });
  });
}

function closeClient(client) { try { client.unbind(); } catch (_) {} }

function cnFromDN(dn) {
  if (!dn) return dn;
  const m = dn.match(/^CN=([^,]+)/i);
  return m ? m[1] : dn;
}

function ouFromDN(dn) {
  if (!dn) return '';
  // Extract OU path: "CN=User,OU=Staff,OU=Accounts,DC=..." → "Staff/Accounts"
  const ous = [];
  const parts = dn.split(',');
  for (const p of parts) {
    if (p.trim().toUpperCase().startsWith('OU=')) {
      ous.push(p.trim().substring(3));
    }
  }
  return ous.join('/');
}

function fileTimeToDate(ft) {
  if (!ft) return null;
  const val = BigInt(ft);
  if (val === 0n || val === 9223372036854775807n) return null;
  const ms = val / 10000n - 11644473600000n;
  return new Date(Number(ms));
}

function dateToFileTime(date) {
  return ((BigInt(date.getTime()) + 11644473600000n) * 10000n).toString();
}

function daysSince(date) {
  if (!date) return null;
  return Math.floor((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24));
}

function isExcludedOU(dn) {
  if (!dn) return false;
  const lower = dn.toLowerCase();
  return EXCLUDED_OU_PATTERNS.some(p => lower.includes(p));
}

function isDisabled(uac) {
  return !!(parseInt(uac, 10) & 0x0002);
}

function getPrivilegedGroups(memberOf) {
  if (!memberOf) return [];
  const groups = Array.isArray(memberOf) ? memberOf : [memberOf];
  return groups
    .map(dn => cnFromDN(dn))
    .filter(name => PRIVILEGED_GROUPS.includes(name.toLowerCase()));
}

// ─── DB Helper (uses pool from parent server.js via req.app) ─────────────────

async function getPool(req) {
  // Try to get pool from app locals or create a basic one
  if (req.app.locals && req.app.locals.pool) return req.app.locals.pool;
  // Fallback: create our own connection
  const mysql = require('mysql2/promise');
  if (!module._hkPool) {
    module._hkPool = mysql.createPool({
      host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT) || 3306,
      database: process.env.DB_NAME || 'corpit_hub',
      user: process.env.DB_USER, password: process.env.DB_PASSWORD,
      waitForConnections: true, connectionLimit: 3, charset: 'utf8mb4',
    });
  }
  return module._hkPool;
}

// housekeeping_audit is created by migrate.js at deploy time (schema/migrations.js),
// never by this module (CHG-ARCH-18). Routes that use it refuse with 503 when it
// does not satisfy schema/contract.js.
const needSchema = require('./schema/readiness').requireSchema('housekeeping');

async function logAudit(pool, entry) {
  await pool.query(
    `INSERT INTO housekeeping_audit (action_type, object_type, object_name, object_dn, original_state, new_state, notes, performed_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [entry.action, entry.objectType, entry.objectName, entry.objectDN || null,
     JSON.stringify(entry.originalState || {}), JSON.stringify(entry.newState || {}),
     entry.notes || null, String(entry.performedBy || 'itam-api').slice(0, 100)]
  );
}

// ─── WinRM Action Helper ─────────────────────────────────────────────────────

function runAction(payload) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(__dirname, 'housekeeping-actions.py');
    const child = execFile('python3', [scriptPath], {
      env: { ...process.env, WINRM_USER: process.env.WINRM_USER, WINRM_PASS: process.env.WINRM_PASS },
      timeout: 60000, maxBuffer: 1024 * 512,
    }, (err, stdout, stderr) => {
      if (err && !stdout) return reject(new Error(stderr || err.message));
      try { resolve(JSON.parse(stdout.trim())); }
      catch (e) { reject(new Error(`Invalid response: ${stdout}`)); }
    });
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

// ─── Routes: Health ──────────────────────────────────────────────────────────

router.get('/health', async (req, res) => {
  let client;
  try {
    client = await createClient();
    closeClient(client);
    const pool = await getPool(req);
    await pool.query('SELECT 1 FROM housekeeping_audit LIMIT 1');   // read-only: reachable and present
    res.json({ status: 'ok', ldap: 'connected', audit_table: 'ready', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ─── Routes: Discovery ──────────────────────────────────────────────────────

router.get('/scan/users', rbac.requirePage('ad-housekeeping','read'), async (req, res) => {
  // 5-min cache check (unless ?force=1)
  if (req.query.force !== '1') {
    const hit = cacheGet('users');
    if (hit) return res.json({ ...hit.payload, cached: true, cachedAt: hit.ts });
  }

  let client;
  try {
    client = await createClient();

    const attrs = [
      'sAMAccountName', 'displayName', 'userAccountControl', 'lastLogonTimestamp',
      'pwdLastSet', 'accountExpires', 'memberOf', 'distinguishedName',
      'whenChanged', 'whenCreated', 'department', 'title', 'description', 'mail',
    ];

    // Fetch all user accounts
    const allUsers = await ldapSearch(client, LDAP_BASE_DN,
      '(&(objectCategory=person)(objectClass=user))', attrs, 0);

    closeClient(client);

    const staleUsers = [];
    const disabledUsers = [];
    const expiredAccounts = [];
    const passwordStale = [];
    const noGroupUsers = [];
    const privilegedRisk = [];
    const duplicateMap = {};

    for (const u of allUsers) {
      const dn = u.distinguishedName || '';
      const uac = parseInt(u.userAccountControl || '0', 10);
      const disabled = !!(uac & 0x0002);
      const sam = u.sAMAccountName || '';
      const display = u.displayName || sam;
      const _scope = classifyScope(dn, display);
      // Disabled-Objects OU is the graveyard — nothing to do there
      if (_scope === 'skip') continue;

      const lastLogon = fileTimeToDate(u.lastLogonTimestamp);
      const pwdSet = fileTimeToDate(u.pwdLastSet);
      const expires = fileTimeToDate(u.accountExpires);
      const memberOf = u.memberOf ? (Array.isArray(u.memberOf) ? u.memberOf : [u.memberOf]) : [];
      const groupNames = memberOf.map(d => cnFromDN(d));
      const privGroups = getPrivilegedGroups(u.memberOf);
      const ou = ouFromDN(dn);
      const lastLogonDays = daysSince(lastLogon);
      const pwdDays = daysSince(pwdSet);

      const base = {
        sam, display, dn, ou, _scope, disabled,
        lastLogon: lastLogon ? lastLogon.toISOString() : null,
        lastLogonDays, pwdLastSet: pwdSet ? pwdSet.toISOString() : null, pwdDays,
        expires: expires ? expires.toISOString() : null,
        groupCount: groupNames.length, groups: groupNames,
        privilegedGroups: privGroups,
        department: u.department || '', title: u.title || '', mail: u.mail || '',
        whenChanged: u.whenChanged || '', whenCreated: u.whenCreated || '',
      };

      // Disabled users — every scope, frontend filters
      if (disabled) {
        const dBase = { ...base };
        dBase.risk = privGroups.length > 0 ? 'high' : 'low';
        dBase.reason = 'Account is disabled' + (privGroups.length > 0 ? ' but still in privileged groups: ' + privGroups.join(', ') : '');
        disabledUsers.push(dBase);
      }

      // Enabled accounts — check for staleness etc.
      if (!disabled) {
        if (lastLogonDays !== null && lastLogonDays > STALE_DAYS) {
          const sBase = { ...base };
          sBase.risk = privGroups.length > 0 ? 'high' : 'medium';
          sBase.reason = `No logon in ${lastLogonDays} days` + (privGroups.length > 0 ? ' — in privileged groups: ' + privGroups.join(', ') : '');
          staleUsers.push(sBase);
        }
        if (pwdDays !== null && pwdDays > PWD_STALE_DAYS && !(uac & 0x10000)) {
          const pwdBase = { ...base };
          pwdBase.risk = 'medium';
          pwdBase.reason = `Password unchanged for ${pwdDays} days`;
          passwordStale.push(pwdBase);
        }
        if (groupNames.length <= 1) {
          const ngBase = { ...base };
          ngBase.risk = 'low';
          ngBase.reason = 'No security group memberships beyond Domain Users';
          noGroupUsers.push(ngBase);
        }
        if (expires && expires < new Date()) {
          const expBase = { ...base };
          expBase.risk = 'medium';
          expBase.reason = `Account expired on ${expires.toISOString().split('T')[0]} but still enabled`;
          expiredAccounts.push(expBase);
        }
      }

      // Privileged risk — already scope-independent; preserve current behavior
      if (privGroups.length > 0 && (disabled || (lastLogonDays !== null && lastLogonDays > STALE_DAYS))) {
        if (!privilegedRisk.find(p => p.sam === sam)) {
          const prBase = { ...base };
          prBase.risk = 'high';
          prBase.reason = (disabled ? 'Disabled' : `Stale (${lastLogonDays}d)`) + ' account in: ' + privGroups.join(', ');
          privilegedRisk.push(prBase);
        }
      }

      // Duplicate detection: group by normalized displayName
      if (display) {
        const key = display.toLowerCase().replace(/[^a-z]/g, '');
        if (!duplicateMap[key]) duplicateMap[key] = [];
        duplicateMap[key].push({ sam, display, dn, ou, disabled });
      }
    }

    const duplicates = Object.values(duplicateMap)
      .filter(arr => arr.length > 1)
      .map(arr => ({ names: arr, count: arr.length, risk: 'low', reason: 'Possible duplicate accounts' }));

    const payload = {
      staleUsers: { count: staleUsers.length, items: staleUsers },
      disabledUsers: { count: disabledUsers.length, items: disabledUsers },
      expiredAccounts: { count: expiredAccounts.length, items: expiredAccounts },
      passwordStale: { count: passwordStale.length, items: passwordStale },
      noGroupUsers: { count: noGroupUsers.length, items: noGroupUsers },
      privilegedRisk: { count: privilegedRisk.length, items: privilegedRisk },
      duplicates: { count: duplicates.length, items: duplicates },
      scannedAt: new Date().toISOString(),
      totalUsersScanned: allUsers.length,
    };
    cacheSet('users', payload);
    res.json({ ...payload, cached: false, cachedAt: scanCache.users.ts });
  } catch (err) {
    if (client) closeClient(client);
    console.error('[housekeeping] scan/users error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/scan/groups', rbac.requirePage('ad-housekeeping','read'), async (req, res) => {
  if (req.query.force !== '1') {
    const hit = cacheGet('groups');
    if (hit) return res.json({ ...hit.payload, cached: true, cachedAt: hit.ts });
  }
  let client;
  try {
    client = await createClient();

    // All security groups
    const allGroups = await ldapSearch(client, LDAP_BASE_DN,
      '(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))',
      ['cn', 'distinguishedName', 'description', 'member', 'whenChanged', 'managedBy', 'objectSid', 'isCriticalSystemObject'], 0);

    // A group whose members all hold it as their primary group (Domain Users, Domain Guests, ...) has an empty
    // `member` attribute, so collect the RIDs that some account uses as primaryGroupID.
    const primaryRids = new Set((await ldapSearch(client, LDAP_BASE_DN,
      '(&(objectClass=user)(primaryGroupID=*))', ['primaryGroupID'], 0)).map(u => Number(u.primaryGroupID)));

    closeClient(client);

    const emptyGroups = [];
    let systemSkipped = 0, primarySkipped = 0;
    for (const g of allGroups) {
      const name = g.cn || cnFromDN(g.distinguishedName);
      const members = g.member ? (Array.isArray(g.member) ? g.member : [g.member]) : [];

      if (members.length === 0) {
        // Built-in and other system groups are AD's own; they are not cleanup candidates.
        if (g.isCriticalSystemObject === 'TRUE' || /,CN=Builtin,/i.test(g.distinguishedName || '')) { systemSkipped++; continue; }
        const sid = Buffer.isBuffer(g.objectSid) && g.objectSid.length >= 4 ? g.objectSid : null;
        if (sid && primaryRids.has(sid.readUInt32LE(sid.length - 4))) { primarySkipped++; continue; }
        emptyGroups.push({
          name,
          dn: g.distinguishedName || '',
          ou: ouFromDN(g.distinguishedName),
          description: g.description || '',
          memberCount: 0,
          whenChanged: g.whenChanged || '',
          risk: 'low',
          reason: 'Security group has no members',
        });
      }
    }

    emptyGroups.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));

    const payload = {
      emptyGroups: { count: emptyGroups.length, items: emptyGroups },
      totalGroupsScanned: allGroups.length,
      skipped: { system: systemSkipped, primaryGroup: primarySkipped },
      scannedAt: new Date().toISOString(),
    };
    cacheSet('groups', payload);
    res.json({ ...payload, cached: false, cachedAt: scanCache.groups.ts });
  } catch (err) {
    if (client) closeClient(client);
    console.error('[housekeeping] scan/groups error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/scan/computers', rbac.requirePage('ad-housekeeping','read'), async (req, res) => {
  if (req.query.force !== '1') {
    const hit = cacheGet('computers');
    if (hit) return res.json({ ...hit.payload, cached: true, cachedAt: hit.ts });
  }
  let client;
  try {
    client = await createClient();

    const attrs = ['cn', 'distinguishedName', 'lastLogonTimestamp', 'operatingSystem',
                   'whenChanged', 'description', 'userAccountControl'];

    const allComputers = await ldapSearch(client, LDAP_BASE_DN,
      '(objectClass=computer)', attrs, 0);

    closeClient(client);

    const staleComputers = [];
    for (const c of allComputers) {
      const lastLogon = fileTimeToDate(c.lastLogonTimestamp);
      const lastLogonDays = daysSince(lastLogon);

      if (lastLogonDays !== null && lastLogonDays > STALE_DAYS) {
        staleComputers.push({
          name: c.cn || '',
          dn: c.distinguishedName || '',
          ou: ouFromDN(c.distinguishedName),
          os: c.operatingSystem || '',
          lastLogon: lastLogon ? lastLogon.toISOString() : null,
          lastLogonDays,
          whenChanged: c.whenChanged || '',
          description: c.description || '',
          disabled: c.userAccountControl ? !!(parseInt(c.userAccountControl, 10) & 0x0002) : false,
          risk: lastLogonDays > 180 ? 'medium' : 'low',
          reason: `No logon in ${lastLogonDays} days`,
        });
      }
    }

    staleComputers.sort((a, b) => (b.lastLogonDays || 0) - (a.lastLogonDays || 0));

    const payload = {
      staleComputers: { count: staleComputers.length, items: staleComputers },
      totalComputersScanned: allComputers.length,
      scannedAt: new Date().toISOString(),
    };
    cacheSet('computers', payload);
    res.json({ ...payload, cached: false, cachedAt: scanCache.computers.ts });
  } catch (err) {
    if (client) closeClient(client);
    console.error('[housekeeping] scan/computers error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/scan/summary', rbac.requirePage('ad-housekeeping','read'), async (req, res) => {
  // Lightweight summary — just counts. Frontend can call this first for the cards.
  // For now, redirect to the full scan. In future, cache results.
  res.json({ message: 'Use /scan/users, /scan/groups, /scan/computers for detailed results' });
});

// ─── Routes: Actions ─────────────────────────────────────────────────────────

router.post('/action', rbac.requirePage('ad-housekeeping','admin'), needSchema, async (req, res) => {
  const { action, objectName, objectDN, objectType, params } = req.body || {};

  if (!action || !objectName) {
    return res.status(400).json({ error: 'action and objectName are required' });
  }

  const validActions = ['disable-account', 'enable-account', 'move-to-disabled',
                        'remove-from-group', 'add-to-group'];
  if (!validActions.includes(action)) {
    return res.status(400).json({ error: `Invalid action. Valid: ${validActions.join(', ')}` });
  }

  if (!process.env.WINRM_USER || !process.env.WINRM_PASS) {
    return res.status(500).json({ error: 'WinRM credentials not configured' });
  }

  try {
    const pool = await getPool(req);

    const payload = {
      action,
      target: objectName,
      targetDN: objectDN || '',
      disabledOU: DISABLED_OU,
      ...(params || {}),
    };

    const result = await runAction(payload);

    // Log to audit table
    if (result.success) {
      await logAudit(pool, {
        action,
        objectType: objectType || 'unknown',
        objectName,
        objectDN: objectDN || '',
        originalState: result.originalState || {},
        newState: result.newState || {},
        notes: result.message || '',
        performedBy: who(req),
      });
      cacheInvalidate(); // AD just changed — next scan should be fresh
    }

    res.json(result);
  } catch (err) {
    console.error('[housekeeping] action error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Routes: Revert ──────────────────────────────────────────────────────────

router.post('/revert/:auditId', rbac.requirePage('ad-housekeeping','admin'), needSchema, async (req, res) => {
  const auditId = parseInt(req.params.auditId, 10);
  if (!auditId) return res.status(400).json({ error: 'Invalid audit ID' });

  try {
    const pool = await getPool(req);
    const [rows] = await pool.query('SELECT * FROM housekeeping_audit WHERE id = ?', [auditId]);

    if (rows.length === 0) return res.status(404).json({ error: 'Audit entry not found' });

    const entry = rows[0];
    if (entry.reverted) return res.status(400).json({ error: 'Already reverted' });

    const smbx = await revertSmbx(pool, entry);
    if (smbx) {
      if (smbx.success) {
        await pool.query('UPDATE housekeeping_audit SET reverted = 1, revert_at = NOW() WHERE id = ?', [auditId]);
        await logAudit(pool, { action: 'revert', objectType: entry.object_type, objectName: entry.object_name, objectDN: entry.object_dn,
          performedBy: who(req), originalState: { auditId, action: entry.action_type }, newState: {}, notes: `Reverted #${auditId} ${entry.action_type}: ${smbx.message || ''}` });
        cacheInvalidate(); smbxAdCache = null;
      }
      return res.json({ ...smbx, revertedAuditId: auditId });
    }

    // Determine revert action
    let revertPayload;
    switch (entry.action_type) {
      case 'disable-account':
        revertPayload = { action: 'enable-account', target: entry.object_name };
        break;
      case 'enable-account':
        revertPayload = { action: 'disable-account', target: entry.object_name };
        break;
      case 'move-to-disabled': {
        const orig = asObj(entry.original_state);
        if (!orig.originalOU) return res.status(400).json({ error: 'Original OU not recorded — cannot revert' });
        // By sAMAccountName: object_dn is the DN before the move, which no longer exists.
        revertPayload = { action: 'move-to-ou', target: entry.object_name, destinationOU: orig.originalOU };
        break;
      }
      case 'remove-from-group': {
        const orig2 = asObj(entry.original_state);
        revertPayload = { action: 'add-to-group', target: entry.object_name, groupName: orig2.groupName || '' };
        break;
      }
      default:
        return res.status(400).json({ error: `Cannot revert action type: ${entry.action_type}` });
    }

    const result = await runAction(revertPayload);

    if (result.success) {
      await pool.query('UPDATE housekeeping_audit SET reverted = 1, revert_at = NOW() WHERE id = ?', [auditId]);
      cacheInvalidate(); // AD just changed — next scan should be fresh
    }

    res.json({ ...result, revertedAuditId: auditId });
  } catch (err) {
    console.error('[housekeeping] revert error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Shared mailboxes ────────────────────────────────────────────────────────
// Snapshot: hk_shared_mailbox, written nightly by collect-shared-mailboxes.js (Exchange Online, read-only).
// Shared setting: hk_settings 'smbx.stale_days' (default 180), changed from the page, audited.
// Actions: on-prem AD for dirsynced mailboxes (housekeeping-actions.py), Exchange Online for the rest and for
// delegates / mailbox type (housekeeping-exo.ps1, needs an Exchange role on the app; errors are returned as-is).
// The slice ships in schema/contract.js. Until that file carries it, these routes answer 503 instead of
// requireSchema throwing here, which would take the whole hub down at require time.
const needSmbx = require('./schema/contract').SLICES.includes('shared-mailbox')
  ? require('./schema/readiness').requireSchema('shared-mailbox')
  : (req, res) => res.status(503).json({ error: 'SCHEMA_NOT_READY', slice: 'shared-mailbox', message: 'Shared mailbox tables are not in this server\'s schema contract yet.' });
const SMBX_STALE_DEFAULT = 180;
const SMBX_STALE_MIN = 7;
const SMBX_STALE_MAX = 3650;
const SMBX_REMOTE_SHARED = '34359738368';   // msExchRecipientTypeDetails of a RemoteSharedMailbox on-prem
const SMBX_REMOTE_USER = '2147483648';     // ... of a RemoteUserMailbox
const SMBX_AD_TYPES = { [SMBX_REMOTE_SHARED]: 'remote shared mailbox', [SMBX_REMOTE_USER]: 'remote user mailbox',
  '8589934592': 'remote room mailbox', '17179869184': 'remote equipment mailbox' };

function who(req) { return (req.user && req.user.email) || 'unknown'; }
// mysql2 hands JSON columns back already parsed; older rows or other drivers give text.
function asObj(v) {
  if (v == null) return {};
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch (_) { return {}; }
}
function ldapEsc(s) { return String(s).replace(/[\\*()\0]/g, c => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0')); }

async function getSetting(pool, key) {
  const [r] = await pool.query(
    "SELECT setting_value, updated_by, DATE_FORMAT(updated_at,'%Y-%m-%dT%H:%i:%sZ') updated_at FROM hk_settings WHERE setting_key = ?", [key]);
  return r[0] || null;
}
async function smbxStaleDays(pool) {
  const s = await getSetting(pool, 'smbx.stale_days');
  const n = s ? parseInt(s.setting_value, 10) : NaN;
  return { staleDays: Number.isInteger(n) ? n : SMBX_STALE_DEFAULT, isDefault: !s, updatedBy: s ? s.updated_by : null, updatedAt: s ? s.updated_at : null };
}

function runExo(payload) {
  return new Promise((resolve, reject) => {
    const child = execFile(process.env.SMBX_PWSH || 'pwsh',
      ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'housekeeping-exo.ps1')], {
        env: process.env, timeout: 180000, maxBuffer: 1024 * 512,
      }, (err, stdout, stderr) => {
        const line = String(stdout || '').trim().split('\n').reverse().find(l => l.trim().startsWith('{'));
        if (!line) return reject(new Error((stderr || (err && err.message) || 'no response from housekeeping-exo.ps1').toString().slice(0, 500)));
        try { resolve(JSON.parse(line)); } catch (e) { reject(new Error(`Invalid response: ${line.slice(0, 300)}`)); }
      });
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

// On-prem AD objects of the dirsynced shared mailboxes, keyed by lower-case mail and UPN. Cached like the scans.
let smbxAdCache = null;
async function smbxAdMap(force) {
  if (!force && smbxAdCache && Date.now() - smbxAdCache.ts < SCAN_CACHE_TTL_MS) return smbxAdCache.map;
  const client = await createClient();
  try {
    // Every mail-enabled user, not only RemoteSharedMailbox: a mailbox converted to shared in the cloud keeps
    // msExchRecipientTypeDetails = RemoteUserMailbox on-prem (14 of a 15-mailbox sample on 2026-10-14).
    const rows = await ldapSearch(client, LDAP_BASE_DN, '(&(objectClass=user)(msExchRecipientTypeDetails=*))',
      ['distinguishedName', 'sAMAccountName', 'userAccountControl', 'mail', 'userPrincipalName', 'msExchHideFromAddressLists', 'msExchRecipientTypeDetails'], 0);
    const map = {};
    for (const o of rows) {
      const v = { dn: o.distinguishedName, sam: o.sAMAccountName, disabled: isDisabled(o.userAccountControl || '0'),
        ou: ouFromDN(o.distinguishedName), hiddenAD: /^true$/i.test(String(o.msExchHideFromAddressLists || '')),
        inDisabledOU: classifyScope(o.distinguishedName, '') === 'skip', rtd: String(o.msExchRecipientTypeDetails || '') };
      const m = String(o.mail || '').toLowerCase(), u = String(o.userPrincipalName || '').toLowerCase();
      if (m) map[m] = v;
      if (u && !map[u]) map[u] = v;     // a mail match wins over another object's UPN
    }
    smbxAdCache = { ts: Date.now(), map };
    return map;
  } finally { closeClient(client); }
}
// The one AD object behind a mailbox, looked up fresh (not from the cache) right before an action.
async function smbxAdFind(m) {
  const client = await createClient();
  try {
    const keys = [m.primary_smtp, m.upn].filter(Boolean).map(ldapEsc);
    const f = '(&(objectClass=user)(|' + keys.map(k => `(mail=${k})(userPrincipalName=${k})(proxyAddresses=SMTP:${k})`).join('') + '))';
    const rows = await ldapSearch(client, LDAP_BASE_DN, f, ['distinguishedName', 'sAMAccountName', 'userAccountControl', 'msExchRecipientTypeDetails'], 0);
    if (rows.length !== 1) return { error: rows.length ? `${rows.length} AD objects match ${m.primary_smtp}; act on it in AD by hand` : `no AD object found for ${m.primary_smtp}` };
    const o = rows[0];
    return { dn: o.distinguishedName, sam: o.sAMAccountName, disabled: isDisabled(o.userAccountControl || '0'), rtd: String(o.msExchRecipientTypeDetails || '') };
  } finally { closeClient(client); }
}

function maxIso(...vals) {
  let best = null;
  for (const v of vals) if (v && (!best || v > best)) best = v;
  return best;
}

router.get('/shared-mailboxes', rbac.requirePage('ad-housekeeping', 'read'), needSmbx, async (req, res) => {
  try {
    const pool = await getPool(req);
    const st = await smbxStaleDays(pool);
    const metaRow = await getSetting(pool, 'smbx.collector');
    const collector = metaRow ? asObj(metaRow.setting_value) : null;
    const [rows] = await pool.query(`SELECT mailbox_guid, display_name, primary_smtp, upn, alias, is_dirsynced, hidden_gal,
        DATE_FORMAT(when_created,'%Y-%m-%dT%H:%i:%sZ') when_created, item_count, size_bytes,
        DATE_FORMAT(last_user_action,'%Y-%m-%dT%H:%i:%sZ') last_user_action, DATE_FORMAT(last_received,'%Y-%m-%dT%H:%i:%sZ') last_received,
        DATE_FORMAT(last_sent,'%Y-%m-%dT%H:%i:%sZ') last_sent, DATE_FORMAT(graph_last_activity,'%Y-%m-%d') graph_last_activity,
        recv_count, sent_count, trace_days, full_access, send_as, error, DATE_FORMAT(collected_at,'%Y-%m-%dT%H:%i:%sZ') collected_at
      FROM hk_shared_mailbox ORDER BY display_name`);
    let ad = {}, adError = null;
    try { ad = await smbxAdMap(req.query.force === '1'); } catch (e) { adError = e.message; }
    const cutoff = new Date(Date.now() - st.staleDays * 86400000).toISOString();
    const counts = { stale: 0, active: 0, unknown: 0 };
    const items = rows.map(r => {
      const graphIso = r.graph_last_activity ? r.graph_last_activity + 'T00:00:00Z' : null;
      const last = maxIso(r.last_received, r.last_sent, r.last_user_action, graphIso);
      // No dates at all because the collector could not read the mailbox is "unknown", not "stale".
      const status = (!last && r.error) ? 'unknown' : (!last || last < cutoff) ? 'stale' : 'active';
      counts[status]++;
      const a = r.is_dirsynced ? (ad[String(r.primary_smtp || '').toLowerCase()] || ad[String(r.upn || '').toLowerCase()] || null) : null;
      return {
        guid: r.mailbox_guid, name: r.display_name, smtp: r.primary_smtp, upn: r.upn, alias: r.alias,
        synced: !!r.is_dirsynced, hidden: !!r.hidden_gal, created: r.when_created, items: r.item_count, sizeBytes: r.size_bytes,
        lastUserAction: r.last_user_action, lastReceived: r.last_received, lastSent: r.last_sent, graphLastActivity: r.graph_last_activity,
        lastActivity: last, idleDays: last ? Math.floor((Date.now() - Date.parse(last)) / 86400000) : null,
        recv: r.recv_count, sent: r.sent_count, traceDays: r.trace_days,
        fullAccess: Array.isArray(asObj(r.full_access)) ? asObj(r.full_access) : [], sendAs: Array.isArray(asObj(r.send_as)) ? asObj(r.send_as) : [],
        error: r.error, status, collectedAt: r.collected_at,
        ad: a ? { dn: a.dn, sam: a.sam, disabled: a.disabled, ou: a.ou, inDisabledOU: a.inDisabledOU, type: SMBX_AD_TYPES[a.rtd] || (a.rtd ? 'other (' + a.rtd + ')' : 'unset') } : null,
      };
    });
    res.json({ staleDays: st.staleDays, staleDaysDefault: st.isDefault, collector, adError, total: items.length, counts, items });
  } catch (err) {
    console.error('[housekeeping] shared-mailboxes error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/settings', rbac.requirePage('ad-housekeeping', 'read'), needSmbx, async (req, res) => {
  try {
    const st = await smbxStaleDays(await getPool(req));
    res.json({ staleDays: st.staleDays, isDefault: st.isDefault, default: SMBX_STALE_DEFAULT, min: SMBX_STALE_MIN, max: SMBX_STALE_MAX,
      updatedBy: st.updatedBy, updatedAt: st.updatedAt });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.put('/settings', rbac.requirePage('ad-housekeeping', 'admin'), needSchema, needSmbx, async (req, res) => {
  const n = Number((req.body || {}).staleDays);
  if (!Number.isInteger(n) || n < SMBX_STALE_MIN || n > SMBX_STALE_MAX) {
    return res.status(400).json({ error: `staleDays must be a whole number from ${SMBX_STALE_MIN} to ${SMBX_STALE_MAX}` });
  }
  try {
    const pool = await getPool(req);
    const before = await smbxStaleDays(pool);
    if (before.staleDays === n && !before.isDefault) return res.json({ success: true, staleDays: n, unchanged: true });
    await pool.query(`INSERT INTO hk_settings (setting_key, setting_value, updated_by) VALUES ('smbx.stale_days', ?, ?)
      ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by)`, [String(n), who(req)]);
    await logAudit(pool, { action: 'setting-change', objectType: 'setting', objectName: 'smbx.stale_days', performedBy: who(req),
      originalState: { staleDays: before.staleDays, wasDefault: before.isDefault }, newState: { staleDays: n },
      notes: `Shared mailbox stale threshold ${before.staleDays} → ${n} days` });
    res.json({ success: true, staleDays: n });
  } catch (err) {
    console.error('[housekeeping] settings error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const SMBX_ACTIONS = ['smbx-hide-gal', 'smbx-remove-delegates', 'smbx-convert-user', 'smbx-delete', 'smbx-disable', 'smbx-move-disabled'];

router.post('/shared-mailboxes/action', rbac.requirePage('ad-housekeeping', 'admin'), needSchema, needSmbx, async (req, res) => {
  const { action, guid, confirm } = req.body || {};
  if (!SMBX_ACTIONS.includes(action)) return res.status(400).json({ error: `Invalid action. Valid: ${SMBX_ACTIONS.join(', ')}` });
  if (!guid) return res.status(400).json({ error: 'guid is required' });
  try {
    const pool = await getPool(req);
    const [rows] = await pool.query('SELECT mailbox_guid, display_name, primary_smtp, upn, is_dirsynced, full_access, send_as FROM hk_shared_mailbox WHERE mailbox_guid = ?', [guid]);
    if (!rows.length) return res.status(404).json({ error: 'mailbox not in the latest collection' });
    const m = rows[0];
    const synced = !!m.is_dirsynced;
    if (action === 'smbx-delete' && String(confirm || '').toLowerCase() !== String(m.primary_smtp || '').toLowerCase()) {
      return res.status(400).json({ error: 'type the mailbox address to confirm the delete' });
    }
    const needsAd = synced || action === 'smbx-disable' || action === 'smbx-move-disabled';
    if (needsAd && (!process.env.WINRM_USER || !process.env.WINRM_PASS)) return res.status(500).json({ error: 'WinRM credentials not configured' });
    let adObj = null;
    if (needsAd) {
      adObj = await smbxAdFind(m);
      if (adObj.error) return res.status(409).json({ error: adObj.error });
    }
    const base = { objectType: 'shared-mailbox', objectName: m.primary_smtp, objectDN: adObj ? adObj.dn : '', performedBy: who(req) };
    let result, audit = null;

    switch (action) {
      case 'smbx-hide-gal': {
        result = synced ? await runAction({ action: 'smbx-set-hide-gal', targetDN: adObj.dn, value: true })
                        : await runExo({ action: 'set-hidden', identity: guid, hidden: true });
        if (result.success) audit = { originalState: { guid, synced, [synced ? 'ad' : 'exo']: result.originalState || {} }, newState: result.newState };
        break;
      }
      case 'smbx-remove-delegates': {
        const fa = asObj(m.full_access), sa = asObj(m.send_as);
        if (!(fa.length || sa.length)) return res.status(400).json({ error: 'no delegates recorded for this mailbox' });
        result = await runExo({ action: 'remove-delegates', identity: guid, fullAccess: fa, sendAs: sa });
        if (result.success) audit = { originalState: { guid, ...(result.originalState || {}) }, newState: result.newState };
        break;
      }
      case 'smbx-convert-user': {
        // On-prem is either RemoteSharedMailbox (set it to RemoteUserMailbox too) or already RemoteUserMailbox
        // (cloud-only conversion earlier; nothing to change on-prem). Anything else is left to a person.
        const adToUser = synced && adObj.rtd === SMBX_REMOTE_SHARED;
        if (synced && !adToUser && adObj.rtd !== SMBX_REMOTE_USER) return res.status(409).json({ error: `on-prem object is neither a remote shared nor a remote user mailbox (msExchRecipientTypeDetails=${adObj.rtd || 'unset'})` });
        const exo = await runExo({ action: 'set-type', identity: guid, type: 'Regular' });
        if (!exo.success) { result = exo; break; }
        let adr = null;
        if (adToUser) adr = await runAction({ action: 'smbx-set-type-attrs', targetDN: adObj.dn, to: 'user' });
        result = { success: true, message: exo.message + (adr ? (adr.success ? '; ' + adr.message : '; ON-PREM STEP FAILED: ' + adr.error + ' (the next directory sync may set it back to shared)') : (synced ? '; on-prem object already a remote user mailbox' : '')) };
        if (adr && !adr.success) result.partial = true;
        audit = { originalState: { guid, synced, exo: exo.originalState || {}, ad: adr && adr.success ? adr.originalState : null }, newState: { type: 'Regular', adDone: !!(adr && adr.success) } };
        break;
      }
      case 'smbx-delete': {
        result = synced ? await runAction({ action: 'smbx-delete-object', targetDN: adObj.dn })
                        : await runExo({ action: 'remove-mailbox', identity: guid });
        if (result.success) audit = { originalState: { guid, synced, [synced ? 'ad' : 'exo']: result.originalState || {} }, newState: result.newState };
        break;
      }
      case 'smbx-disable': {
        if (adObj.disabled) return res.status(409).json({ error: 'AD account is already disabled' });
        result = await runAction({ action: 'disable-account', target: adObj.sam });
        if (result.success) audit = { action: 'disable-account', objectName: adObj.sam, originalState: result.originalState, newState: result.newState,
          notes: `${result.message || ''} (shared mailbox ${m.primary_smtp})` };
        break;
      }
      case 'smbx-move-disabled': {
        result = await runAction({ action: 'move-to-disabled', target: adObj.sam, disabledOU: DISABLED_OU });
        if (result.success) audit = { action: 'move-to-disabled', objectName: adObj.sam, originalState: result.originalState, newState: result.newState,
          notes: `${result.message || ''} (shared mailbox ${m.primary_smtp}; still in directory sync scope)` };
        break;
      }
    }
    if (result && result.success && audit) {
      await logAudit(pool, { action, ...base, notes: result.message || '', ...audit });
      cacheInvalidate(); smbxAdCache = null;
    }
    res.json(result);
  } catch (err) {
    console.error('[housekeeping] shared-mailboxes action error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Reverts of the shared-mailbox actions and the settings change; null when the type is not one of these.
async function revertSmbx(pool, entry) {
  const o = asObj(entry.original_state);
  switch (entry.action_type) {
    case 'setting-change': {
      if (entry.object_name !== 'smbx.stale_days') return { success: false, error: 'unknown setting' };
      if (o.wasDefault) await pool.query("DELETE FROM hk_settings WHERE setting_key = 'smbx.stale_days'");
      else await pool.query("UPDATE hk_settings SET setting_value = ? WHERE setting_key = 'smbx.stale_days'", [String(o.staleDays)]);
      return { success: true, message: `Stale threshold back to ${o.staleDays} days` };
    }
    case 'smbx-hide-gal':
      if (o.ad) {
        const v = o.ad.msExchHideFromAddressLists;
        return runAction({ action: 'smbx-set-hide-gal', targetDN: o.ad.DN || entry.object_dn, value: (v === true || v === false) ? v : null });
      }
      return runExo({ action: 'set-hidden', identity: o.guid, hidden: !!(o.exo && o.exo.hidden) });
    case 'smbx-remove-delegates':
      return runExo({ action: 'add-delegates', identity: o.guid, fullAccess: o.fullAccess || [], sendAs: o.sendAs || [] });
    case 'smbx-convert-user': {
      if (o.ad) {
        const r = await runAction({ action: 'smbx-set-type-attrs', targetDN: o.ad.DN || entry.object_dn, to: { RTD: o.ad.RTD, RRT: o.ad.RRT, RDT: o.ad.RDT } });
        if (!r.success) return r;
      }
      return runExo({ action: 'set-type', identity: o.guid, type: 'Shared' });
    }
    case 'smbx-delete':
      if (o.ad && o.ad.objectGUID) return runAction({ action: 'restore-object-guid', guid: o.ad.objectGUID });
      return { success: false, error: 'cloud-only mailbox: restore it from the Exchange admin center (soft-deleted mailboxes, 30 days)' };
    default:
      return null;
  }
}

// ─── Routes: Audit Log ───────────────────────────────────────────────────────

router.get('/audit-log', rbac.requirePage('ad-housekeeping','read'), needSchema, async (req, res) => {
  try {
    const pool = await getPool(req);
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const [rows] = await pool.query(
      'SELECT * FROM housekeeping_audit ORDER BY created_at DESC LIMIT ?', [limit]);
    res.json({ count: rows.length, entries: rows });
  } catch (err) {
    console.error('[housekeeping] audit-log error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Routes: Recycle Bin ─────────────────────────────────────────────────────

const recoveryLookup = require('./housekeeping-recycle-bin');
const readRecycleBin = recoveryLookup.createRecoveryReader({ ldap, createClient, closeClient, parseEntry, baseDN: LDAP_BASE_DN });
router.get('/recycle-bin', rbac.requirePage('ad-housekeeping','read'), async (req, res) => {
  try {
    res.json(await readRecycleBin());
  } catch (err) {
    console.error('[housekeeping] recycle-bin read error:', err.message);
    const failure = recoveryLookup.publicError(err);
    res.status(failure.status).json({ success: false, source: 'ldap', error: failure.message });
  }
});

router.post('/recycle-bin/restore', rbac.requirePage('ad-housekeeping','admin'), needSchema, async (req, res) => {
  const { objectDN, objectName } = req.body || {};
  if (!objectDN) return res.status(400).json({ error: 'objectDN is required' });

  try {
    const pool = await getPool(req);

    const result = await runAction({ action: 'restore-from-recycle-bin', targetDN: objectDN });

    if (result.success) {
      await logAudit(pool, {
        action: 'restore-from-recycle-bin',
        objectType: 'unknown',
        objectName: objectName || cnFromDN(objectDN),
        objectDN,
        originalState: { state: 'deleted' },
        newState: { state: 'restored' },
        notes: result.message || '',
        performedBy: who(req),
      });
      cacheInvalidate(); // AD just changed — next scan should be fresh
    }

    res.json(result);
  } catch (err) {
    console.error('[housekeeping] restore error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
