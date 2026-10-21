/**
 * ad-provisioning.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Express router for Active Directory group provisioning.
 *
 * READ  → LDAP (search users, list groups, get memberships)
 * WRITE → WinRM / PowerShell (add + remove user from groups)
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const express = require('express');
const ldapSecure = require('./ldap-secure'); // ldapjs client with StartTLS before every bind
const { execFile } = require('child_process');
const path    = require('path');
const router  = express.Router();
// ---- RBAC enforcement (Slice 10: user-provisioning) ----
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

const LDAP_URL       = process.env.LDAP_URL       || 'ldap://10.9.64.80:389';
const LDAP_BASE_DN   = process.env.LDAP_BASE_DN   || 'DC=nrpi,DC=local';
const LDAP_BIND_USER = process.env.LDAP_BIND_USER || '';
const LDAP_BIND_PASS = process.env.LDAP_BIND_PASS || '';
const LDAP_TIMEOUT   = 10000;

function parseEntry(entry) {
  const obj = {};
  entry.attributes.forEach(a => {
    obj[a.type] = a.values.length === 1 ? a.values[0] : a.values;
  });
  return obj;
}

function createClient() {
  return new Promise((resolve, reject) => {
    const client = ldapSecure.createClient({
      url: LDAP_URL, timeout: LDAP_TIMEOUT, connectTimeout: LDAP_TIMEOUT,
    });
    client.on('error', err => reject(new Error(`LDAP connection: ${err.message}`)));
    client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, err => {
      if (err) { client.destroy(); return reject(new Error(`LDAP bind: ${err.message}`)); }
      resolve(client);
    });
  });
}

function ldapSearch(client, base, filter, attributes, sizeLimit = 500, scope = 'sub') {
  return new Promise((resolve, reject) => {
    const entries = [];
    client.search(base, { filter, attributes, scope, sizeLimit, paged: { pageSize: 500 } }, (err, res) => {
      if (err) return reject(new Error(`LDAP search: ${err.message}`));
      res.on('searchEntry', entry => entries.push(parseEntry(entry)));
      res.on('error', err => { if (err.message && err.message.includes('Size Limit')) { resolve(entries); } else { reject(new Error(`LDAP stream: ${err.message}`)); } });
      res.on('end', () => resolve(entries));
    });
  });
}

function closeClient(client) { try { client.unbind(); } catch (_) {} }

function cnFromDN(dn) {
  if (!dn) return dn;
  const match = dn.match(/^CN=([^,]+)/i);
  return match ? match[1] : dn;
}

// ─── Routes ──────────────────────────────────────────────────────────────────

router.get('/health', async (req, res) => {
  let client;
  try {
    client = await createClient();
    closeClient(client);
    res.json({ status: 'ok', ldap: 'connected', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

router.get('/search-user', rbac.requirePage('user-provisioning','read'), async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q || q.length < 2) return res.status(400).json({ error: 'Query must be at least 2 characters' });
  let client;
  try {
    client = await createClient();
    const safeQ = q.replace(/[()\\*]/g, '');
    const filter = `(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*${safeQ}*)(displayName=*${safeQ}*)(cn=*${safeQ}*)))`;
    const results = await ldapSearch(client, LDAP_BASE_DN, filter,
      ['sAMAccountName', 'displayName', 'mail', 'title', 'department', 'distinguishedName', 'userAccountControl'], 20);
    const users = results.map(u => ({
      samAccountName: u.sAMAccountName || '', displayName: u.displayName || u.cn || u.sAMAccountName || '',
      mail: u.mail || '', title: u.title || '', department: u.department || '',
      dn: u.distinguishedName || '', enabled: u.userAccountControl ? !(parseInt(u.userAccountControl, 10) & 0x0002) : null,
    }));
    closeClient(client);
    res.json({ count: users.length, users });
  } catch (err) {
    if (client) closeClient(client);
    console.error('[ad-provisioning] search-user error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /search-group?q= — name-filtered AD security-group search for autocomplete
// (beta-user-projects new-project group picker). Mirrors /search-user; same RBAC,
// same LDAP-injection sanitize, same security-group filter as /groups. Added 2026-08-24.
router.get('/search-group', rbac.requirePage('user-provisioning','read'), async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q || q.length < 2) return res.status(400).json({ error: 'Query must be at least 2 characters' });
  let client;
  try {
    client = await createClient();
    const safeQ = q.replace(/[()\\*]/g, '');
    const filter = `(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648)(|(cn=*${safeQ}*)(sAMAccountName=*${safeQ}*)))`;
    const results = await ldapSearch(client, LDAP_BASE_DN, filter,
      ['cn', 'distinguishedName', 'description', 'groupType', 'managedBy'], 20);
    const groups = results.map(g => ({
      name: g.cn || cnFromDN(g.distinguishedName), dn: g.distinguishedName || '', description: g.description || '',
    })).sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
    closeClient(client);
    res.json({ count: groups.length, groups });
  } catch (err) {
    if (client) closeClient(client);
    console.error('[ad-provisioning] search-group error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/groups', rbac.requirePage('user-provisioning','read'), async (req, res) => {
  let client;
  try {
    client = await createClient();
    const baseDN = req.query.ou || LDAP_BASE_DN;
    const filter = '(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))';
    const results = await ldapSearch(client, baseDN, filter,
      ['cn', 'distinguishedName', 'description', 'groupType', 'managedBy'], 0);
    const groups = results.map(g => ({
      name: g.cn || cnFromDN(g.distinguishedName), dn: g.distinguishedName || '', description: g.description || '',
    })).sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
    closeClient(client);
    res.json({ count: groups.length, groups });
  } catch (err) {
    if (client) closeClient(client);
    console.error('[ad-provisioning] groups error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/user-groups/:samAccountName', rbac.requirePage('user-provisioning','read'), async (req, res) => {
  const sam = (req.params.samAccountName || '').trim();
  if (!sam) return res.status(400).json({ error: 'samAccountName is required' });
  let client;
  try {
    client = await createClient();
    const safeQ = sam.replace(/[()\\*]/g, '');
    const filter = `(&(objectCategory=person)(objectClass=user)(sAMAccountName=${safeQ}))`;
    const results = await ldapSearch(client, LDAP_BASE_DN, filter,
      ['sAMAccountName', 'displayName', 'memberOf', 'distinguishedName'], 1);
    if (results.length === 0) { closeClient(client); return res.status(404).json({ error: `User "${sam}" not found` }); }
    const user = results[0];
    let memberOf = user.memberOf || [];
    if (!Array.isArray(memberOf)) memberOf = [memberOf];
    const groups = memberOf.map(dn => ({ name: cnFromDN(dn), dn }))
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
    closeClient(client);
    res.json({ samAccountName: user.sAMAccountName, displayName: user.displayName || '', dn: user.distinguishedName || '', groupCount: groups.length, groups });
  } catch (err) {
    if (client) closeClient(client);
    console.error('[ad-provisioning] user-groups error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/provisioning/provision
 * Add AND/OR remove a user from AD security groups.
 *
 * Body: {
 *   samAccountName: "john.doe",
 *   addGroups: ["Group1", "Group2"],
 *   removeGroups: ["Group3"]
 * }
 */
router.post('/provision', rbac.requirePage('user-provisioning','admin'), async (req, res) => {
  const { samAccountName, addGroups, removeGroups } = req.body || {};

  if (!samAccountName || typeof samAccountName !== 'string') {
    return res.status(400).json({ error: 'samAccountName is required' });
  }

  const adds = Array.isArray(addGroups) ? addGroups : [];
  const removes = Array.isArray(removeGroups) ? removeGroups : [];

  if (adds.length === 0 && removes.length === 0) {
    return res.status(400).json({ error: 'No groups to add or remove' });
  }

  if (adds.length + removes.length > 50) {
    return res.status(400).json({ error: 'Maximum 50 group changes per request' });
  }

  const winrmUser = process.env.WINRM_USER;
  const winrmPass = process.env.WINRM_PASS;
  if (!winrmUser || !winrmPass) {
    return res.status(500).json({ error: 'WinRM credentials not configured on server' });
  }

  try {
    const scriptPath = path.join(__dirname, 'manage-groups.py');
    const payload = JSON.stringify({ samAccountName, addGroups: adds, removeGroups: removes });

    const result = await new Promise((resolve, reject) => {
      const child = execFile('python3', [scriptPath], {
        env: { ...process.env, WINRM_USER: winrmUser, WINRM_PASS: winrmPass },
        timeout: 90000,
        maxBuffer: 1024 * 512,
      }, (err, stdout, stderr) => {
        if (err && !stdout) return reject(new Error(stderr || err.message));
        try { resolve(JSON.parse(stdout.trim())); }
        catch (parseErr) { reject(new Error(`Invalid response: ${stdout}`)); }
      });
      child.stdin.write(payload);
      child.stdin.end();
    });

    const addedRes   = Array.isArray(result.added)   ? result.added   : [];
    const removedRes = Array.isArray(result.removed) ? result.removed : [];
    const totalAdds = addedRes.length;
    const totalRemoves = removedRes.length;
    console.log(`[ad-provisioning] ${samAccountName}: +${totalAdds} -${totalRemoves} groups`);
    // Audit (rbac_audit_log): one row per request summarising the change set.
    // Carries group identifiers + per-item outcome only -- never WINRM_USER/WINRM_PASS.
    const outcome = (x) => ({
      group: String((x && x.group) || '').slice(0, 256),
      ok: !!(x && x.success),
      message: String((x && x.message) || '').slice(0, 200),
    });
    const addOk = addedRes.filter(x => x && x.success).length;
    const remOk = removedRes.filter(x => x && x.success).length;
    const failed = (totalAdds - addOk) + (totalRemoves - remOk);
    const action = (result.success === false && !addOk && !remOk) ? 'ad-provision-FAILED'
                 : failed ? 'ad-provision-PARTIAL' : 'ad-provision';
    await rbac.audit(req, action, String(samAccountName).slice(0, 255), 'user-provisioning', {
      requested: { add: adds.map(g => String(g).slice(0, 256)), remove: removes.map(g => String(g).slice(0, 256)), count: adds.length + removes.length },
      added: addedRes.map(outcome),
      removed: removedRes.map(outcome),
      counts: { addOk, removeOk: remOk, failed },
      success: result.success !== false,
      error: result.error ? String(result.error).slice(0, 300) : undefined,
    });
    res.json(result);
  } catch (err) {
    console.error('[ad-provisioning] provision error:', err.message);
    await rbac.audit(req, 'ad-provision-ERROR', String(samAccountName).slice(0, 255), 'user-provisioning', {
      requested: { add: adds.map(g => String(g).slice(0, 256)), remove: removes.map(g => String(g).slice(0, 256)), count: adds.length + removes.length },
      error: String((err && err.message) || err).slice(0, 300),
    });
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
