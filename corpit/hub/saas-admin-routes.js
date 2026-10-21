// =====================================================================
// saas-admin-routes.js  (v1.2.0)
//
// IT Command SaaS Admin Console API. EVERY route requires super-admin.
// Mount (server.js):
//   const saasAdminRoutes = require('./saas-admin-routes');
//   app.use('/api/saas-admin', saasAdminRoutes);
//
// Surface:
//   Pages:  GET /pages · POST /pages · PATCH /pages/:key
//           (no DELETE - retire via status; keys stay valid for guards)
//   Roles:  GET /roles · POST /roles · PATCH /roles/:key
//           GET /roles/:key/exceptions · PUT /roles/:key/exceptions
//   Users:  GET /users · PATCH /users/:email (is_active)
//           POST /users/:email/invalidate   (kill switch -> AD re-resolve)
//           PUT /users/:email/overrides/:pageKey · DELETE same
//   Scan:   GET /discovery   (html files vs registry, guard keys vs registry)
//
// Every mutation writes rbac_audit_log.
// =====================================================================

'use strict';

const express = require('express');
const portalOwner = require('./portal-access-owner');
const fs      = require('fs');
const path    = require('path');
const mysql   = require('mysql2/promise');
const ldapSecure = require('./ldap-secure'); // ldapjs client with StartTLS before every bind
const createRbac = require('./rbac-middleware');

const router = express.Router();
router.use(express.json({ limit: '64kb' }));

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});

const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
router.use(rbac.requireSuperAdmin);

const WEB_ROOT   = '/var/www/html';
const ROUTE_DIRS = ['/var/www/corpit-hub-api', '/var/www/api'];

const VALID_ACCESS   = ['none', 'read', 'admin'];
const VALID_LEVELS   = ['read', 'admin', 'none'];
const VALID_STATUS   = ['active', 'beta', 'draft', 'retired'];
const VALID_POLICY   = ['matrix', 'authenticated'];
const VALID_CATEGORY = ['app', 'sop', 'admin'];
const KEY_RE         = /^[a-z0-9][a-z0-9-]{1,62}$/;

function bad(res, msg) { return res.status(400).json({ error: msg, code: 'BAD_REQUEST' }); }

// ---------------- Pages ------------------------------------------------

router.get('/pages', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT page_key, display_name, url_path, category, access_policy,
              status, nav_visible, display_order, description
         FROM rbac_pages ORDER BY category, display_order, page_key`
    );
    res.json({ pages: rows });
  } catch (e) {
    console.error('[saas-admin] pages list failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.post('/pages', async (req, res) => {
  const b = req.body || {};
  if (!KEY_RE.test(b.page_key || ''))              return bad(res, 'page_key: lowercase letters, digits, hyphens');
  if (!b.display_name)                             return bad(res, 'display_name required');
  if (!VALID_POLICY.includes(b.access_policy))     return bad(res, 'access_policy: matrix|authenticated');
  if (!VALID_STATUS.includes(b.status || 'draft')) return bad(res, 'status invalid');
  if (!VALID_CATEGORY.includes(b.category || 'app')) return bad(res, 'category: app|sop|admin');
  try {
    await pool.execute(
      `INSERT INTO rbac_pages
         (page_key, display_name, url_path, category, access_policy, status, nav_visible, description)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [b.page_key, b.display_name, b.url_path || null, b.category || 'app',
       b.access_policy, b.status || 'draft', b.nav_visible ? 1 : 0, b.description || null]
    );
    await rbac.audit(req, 'page_registered', null, b.page_key, { by: req.user.email, status: b.status || 'draft' });
    res.status(201).json({ ok: true });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'page_key already exists', code: 'DUPLICATE' });
    console.error('[saas-admin] page create failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.patch('/pages/:key', async (req, res) => {
  if (portalOwner.owns(req.params.key) && Object.hasOwn(req.body || {}, 'access_policy')) return portalOwner.reject(res);
  const key = req.params.key;
  const b = req.body || {};
  const sets = [], vals = [];
  if (b.display_name !== undefined) { sets.push('display_name = ?'); vals.push(b.display_name); }
  if (b.url_path !== undefined)     { sets.push('url_path = ?');     vals.push(b.url_path || null); }
  if (b.category !== undefined) {
    if (!VALID_CATEGORY.includes(b.category)) return bad(res, 'category invalid');
    sets.push('category = ?'); vals.push(b.category);
  }
  if (b.access_policy !== undefined) {
    if (!VALID_POLICY.includes(b.access_policy)) return bad(res, 'access_policy invalid');
    sets.push('access_policy = ?'); vals.push(b.access_policy);
  }
  if (b.status !== undefined) {
    if (!VALID_STATUS.includes(b.status)) return bad(res, 'status invalid');
    sets.push('status = ?'); vals.push(b.status);
  }
  if (b.nav_visible !== undefined) { sets.push('nav_visible = ?'); vals.push(b.nav_visible ? 1 : 0); }
  if (b.description !== undefined) { sets.push('description = ?'); vals.push(b.description || null); }
  if (b.display_order !== undefined) { sets.push('display_order = ?'); vals.push(parseInt(b.display_order, 10) || 100); }
  if (sets.length === 0) return bad(res, 'nothing to update');
  vals.push(key);
  try {
    const [r] = await pool.execute(`UPDATE rbac_pages SET ${sets.join(', ')} WHERE page_key = ?`, vals);
    if (r.affectedRows === 0) return res.status(404).json({ error: 'Unknown page', code: 'NOT_FOUND' });
    await rbac.audit(req, 'page_updated', null, key, { by: req.user.email, changes: b });
    res.json({ ok: true });
  } catch (e) {
    console.error('[saas-admin] page update failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ---------------- Roles ------------------------------------------------

router.get('/roles', async (req, res) => {
  try {
    const [roles] = await pool.query(
      `SELECT r.role_key, r.display_name, r.description, r.is_system,
              r.default_access, r.ad_group_dn,
              (SELECT COUNT(*) FROM rbac_user_roles ur WHERE ur.role_key = r.role_key) AS member_count
         FROM rbac_roles r ORDER BY r.role_key`
    );
    const [excs] = await pool.query(
      'SELECT role_key, page_key, access_level FROM rbac_role_pages ORDER BY role_key, page_key'
    );
    const excByRole = {};
    for (const e of excs) (excByRole[e.role_key] = excByRole[e.role_key] || []).push(e);
    res.json({ roles: roles.map(r => ({ ...r, exceptions: excByRole[r.role_key] || [] })) });
  } catch (e) {
    console.error('[saas-admin] roles list failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.post('/roles', async (req, res) => {
  const b = req.body || {};
  if (!KEY_RE.test(b.role_key || ''))          return bad(res, 'role_key: lowercase letters, digits, hyphens');
  if (!b.display_name)                         return bad(res, 'display_name required');
  if (!VALID_ACCESS.includes(b.default_access)) return bad(res, 'default_access: none|read|admin');
  try {
    await pool.execute(
      `INSERT INTO rbac_roles (role_key, display_name, description, is_system, default_access, ad_group_dn)
       VALUES (?, ?, ?, 0, ?, ?)`,
      [b.role_key, b.display_name, b.description || null, b.default_access, b.ad_group_dn || null]
    );
    await rbac.audit(req, 'role_created', null, null, { by: req.user.email, role_key: b.role_key, default_access: b.default_access });
    res.status(201).json({ ok: true });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'role_key already exists', code: 'DUPLICATE' });
    console.error('[saas-admin] role create failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.patch('/roles/:key', async (req, res) => {
  const key = req.params.key;
  const b = req.body || {};
  if (key === 'superadmin' && b.default_access !== undefined && b.default_access !== 'none') {
    return bad(res, 'superadmin default_access is fixed at none (bypass lives in code)');
  }
  const sets = [], vals = [];
  if (b.display_name !== undefined)   { sets.push('display_name = ?'); vals.push(b.display_name); }
  if (b.description !== undefined)    { sets.push('description = ?');  vals.push(b.description || null); }
  if (b.default_access !== undefined) {
    if (!VALID_ACCESS.includes(b.default_access)) return bad(res, 'default_access invalid');
    sets.push('default_access = ?'); vals.push(b.default_access);
  }
  if (b.ad_group_dn !== undefined)    { sets.push('ad_group_dn = ?');  vals.push(b.ad_group_dn || null); }
  if (sets.length === 0) return bad(res, 'nothing to update');
  vals.push(key);
  try {
    const [r] = await pool.execute(`UPDATE rbac_roles SET ${sets.join(', ')} WHERE role_key = ?`, vals);
    if (r.affectedRows === 0) return res.status(404).json({ error: 'Unknown role', code: 'NOT_FOUND' });
    await rbac.audit(req, 'role_updated', null, null, { by: req.user.email, role_key: key, changes: b });
    res.json({ ok: true });
  } catch (e) {
    console.error('[saas-admin] role update failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.put('/roles/:key/exceptions', async (req, res) => {
  // Body: { exceptions: [{page_key, access_level}, ...] } - full replacement.
  const key = req.params.key;
  const list = (req.body && req.body.exceptions) || null;
  if (!Array.isArray(list)) return bad(res, 'exceptions: array required');
  for (const e of list) {
    if (!KEY_RE.test(e.page_key || ''))          return bad(res, 'bad page_key in exceptions');
    if (!VALID_LEVELS.includes(e.access_level))  return bad(res, 'bad access_level in exceptions');
  }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [role] = await conn.query('SELECT role_key FROM rbac_roles WHERE role_key = ?', [key]);
    if (role.length === 0) { await conn.rollback(); conn.release(); return res.status(404).json({ error: 'Unknown role', code: 'NOT_FOUND' }); }
    const [current] = await conn.query('SELECT page_key,access_level FROM rbac_role_pages WHERE role_key = ?', [key]);
    if (!portalOwner.preserveRows(res,list,current)) { await conn.rollback(); conn.release(); return; }
    await conn.query("DELETE FROM rbac_role_pages WHERE role_key = ? AND page_key NOT IN ('accessportal','approver-portal')", [key]);
    if (list.some(e => !portalOwner.owns(e.page_key))) {
      await conn.query(
        'INSERT INTO rbac_role_pages (role_key, page_key, access_level) VALUES ?',
        [list.filter(e => !portalOwner.owns(e.page_key)).map(e => [key, e.page_key, e.access_level])]
      );
    }
    await conn.commit();
    conn.release();
    await rbac.audit(req, 'role_exceptions_replaced', null, null, { by: req.user.email, role_key: key, count: list.length });
    res.json({ ok: true, count: list.length });
  } catch (e) {
    try { await conn.rollback(); } catch (x) { /* ignore */ }
    conn.release();
    console.error('[saas-admin] exceptions update failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ---------------- Users ------------------------------------------------

router.get('/users', async (req, res) => {
  try {
    const [users] = await pool.query(
      `SELECT email, display_name, is_active, roles_resolved_at, roles_invalidated_at
         FROM rbac_users ORDER BY email`
    );
    const [roles] = await pool.query('SELECT email, role_key FROM rbac_user_roles');
    const [ovrs]  = await pool.query('SELECT email, page_key, access_level FROM rbac_user_page_access');
    const rByU = {}, oByU = {};
    for (const r of roles) (rByU[r.email] = rByU[r.email] || []).push(r.role_key);
    for (const o of ovrs)  (oByU[o.email] = oByU[o.email] || []).push({ page_key: o.page_key, access_level: o.access_level });
    res.json({
      users: users.map(u => ({
        ...u,
        roles: rByU[u.email] || [],
        overrides: oByU[u.email] || [],
      })),
    });
  } catch (e) {
    console.error('[saas-admin] users list failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.patch('/users/:email', async (req, res) => {
  const email = String(req.params.email || '').toLowerCase();
  const b = req.body || {};
  if (b.is_active === undefined) return bad(res, 'is_active required');
  try {
    const [r] = await pool.execute('UPDATE rbac_users SET is_active = ? WHERE email = ?', [b.is_active ? 1 : 0, email]);
    if (r.affectedRows === 0) return res.status(404).json({ error: 'Unknown user', code: 'NOT_FOUND' });
    await rbac.audit(req, b.is_active ? 'user_enabled' : 'user_disabled', email, null, { by: req.user.email });
    res.json({ ok: true });
  } catch (e) {
    console.error('[saas-admin] user update failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.post('/users/:email/invalidate', async (req, res) => {
  // Kill switch: forces AD re-resolution on the user's next request.
  const email = String(req.params.email || '').toLowerCase();
  try {
    const [r] = await pool.execute('UPDATE rbac_users SET roles_invalidated_at = NOW() WHERE email = ?', [email]);
    if (r.affectedRows === 0) return res.status(404).json({ error: 'Unknown user', code: 'NOT_FOUND' });
    await rbac.audit(req, 'user_roles_invalidated', email, null, { by: req.user.email });
    res.json({ ok: true });
  } catch (e) {
    console.error('[saas-admin] invalidate failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.put('/users/:email/overrides/:pageKey', async (req, res) => {
  if (portalOwner.owns(req.params.pageKey)) return portalOwner.reject(res);
  const email = String(req.params.email || '').toLowerCase();
  const pageKey = req.params.pageKey;
  const level = req.body && req.body.access_level;
  if (!VALID_LEVELS.includes(level)) return bad(res, 'access_level: read|admin|none');
  try {
    await pool.execute(
      `INSERT INTO rbac_user_page_access (email, page_key, access_level, granted_by)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE access_level = VALUES(access_level), granted_by = VALUES(granted_by)`,
      [email, pageKey, level, req.user.email]
    );
    await rbac.audit(req, 'override_set', email, pageKey, { by: req.user.email, level });
    res.json({ ok: true });
  } catch (e) {
    if (e.code === 'ER_NO_REFERENCED_ROW_2') return bad(res, 'user or page does not exist');
    console.error('[saas-admin] override set failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.delete('/users/:email/overrides/:pageKey', async (req, res) => {
  if (portalOwner.owns(req.params.pageKey)) return portalOwner.reject(res);
  const email = String(req.params.email || '').toLowerCase();
  const pageKey = req.params.pageKey;
  try {
    const [r] = await pool.execute(
      'DELETE FROM rbac_user_page_access WHERE email = ? AND page_key = ?', [email, pageKey]
    );
    if (r.affectedRows === 0) return res.status(404).json({ error: 'No such override', code: 'NOT_FOUND' });
    await rbac.audit(req, 'override_removed', email, pageKey, { by: req.user.email });
    res.json({ ok: true });
  } catch (e) {
    console.error('[saas-admin] override delete failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ---------------- Live AD membership ------------------------------------
// Queries the directory for the CURRENT members of every role-bound AD
// group. This is the live truth; the roles column is the snapshot from each
// user's last sign-in. Divergence usually just means "hasn't signed in yet."

function ldapMembersOf(groupDn) {
  return new Promise((resolve, reject) => {
    const client = ldapSecure.createClient({
      url: process.env.LDAP_URL,
      connectTimeout: 5000,
      timeout: 5000,
    });
    let settled = false;
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      try { client.unbind(() => {}); } catch (e) { /* ignore */ }
      try { client.destroy(); } catch (e) { /* ignore */ }
      err ? reject(err) : resolve(val);
    };
    client.on('error', (e) => done(e));
    client.bind(process.env.LDAP_BIND_USER, process.env.LDAP_BIND_PASS, (err) => {
      if (err) return done(err);
      const esc = String(groupDn).replace(/\\/g,'\\5c').replace(/\*/g,'\\2a').replace(/\(/g,'\\28').replace(/\)/g,'\\29');
      const results = [];
      client.search(process.env.LDAP_BASE_DN,
        { scope: 'sub', filter: '(&(objectClass=user)(memberOf=' + esc + '))', attributes: ['mail','displayName'] },
        (err2, res) => {
          if (err2) return done(err2);
          res.on('searchEntry', (entry) => {
            const obj = {};
            (entry.attributes || []).forEach((a) => {
              const vals = a.values || a.vals || [];
              obj[a.type] = vals.length === 1 ? vals[0] : vals.slice();
            });
            if (obj.mail) results.push({ email: String(obj.mail).toLowerCase(), displayName: obj.displayName || null });
          });
          res.on('error', (e) => done(e));
          res.on('end', () => done(null, results));
        });
    });
  });
}

router.get('/ad-membership', async (req, res) => {
  try {
    const [roles] = await pool.query(
      "SELECT role_key, ad_group_dn FROM rbac_roles WHERE ad_group_dn IS NOT NULL"
    );
    const byEmail = {};
    const errors = [];
    for (const r of roles) {
      try {
        const members = await ldapMembersOf(r.ad_group_dn);
        for (const m of members) {
          (byEmail[m.email] = byEmail[m.email] || []).push(r.role_key);
        }
      } catch (e) {
        errors.push({ role_key: r.role_key, error: e.message });
      }
    }
    res.json({ fetched_at: new Date().toISOString(), membership: byEmail, errors });
  } catch (e) {
    console.error('[saas-admin] ad-membership failed:', e.message);
    res.status(500).json({ error: 'Directory query failed', code: 'DIRECTORY_UNAVAILABLE' });
  }
});

// ---------------- Full AD sync -------------------------------------------
// Resolves EVERY role-bound group's membership from the directory and
// persists it, exactly as login-time resolution would - but for everyone at
// once. Users found in no group have their role rows cleared (authoritative
// model). rbac_users rows are created for members who have never signed in.
// Intended use: before an Entra cutover, or any time the console should
// reflect the directory without waiting for sign-ins.

router.post('/sync-ad', async (req, res) => {
  try {
    const [roles] = await pool.query(
      "SELECT role_key, ad_group_dn FROM rbac_roles WHERE ad_group_dn IS NOT NULL"
    );
    const byEmail = {};   // email -> { roles: [], displayName }
    const groupErrors = [];
    for (const r of roles) {
      try {
        const members = await ldapMembersOf(r.ad_group_dn);
        for (const m of members) {
          const rec = (byEmail[m.email] = byEmail[m.email] || { roles: [], displayName: m.displayName });
          rec.roles.push(r.role_key);
          if (!rec.displayName && m.displayName) rec.displayName = m.displayName;
        }
      } catch (e) {
        groupErrors.push({ role_key: r.role_key, error: e.message });
      }
    }
    if (groupErrors.length === roles.length && roles.length > 0) {
      return res.status(502).json({ error: 'Every group lookup failed - directory unreachable', code: 'DIRECTORY_UNAVAILABLE', errors: groupErrors });
    }

    const emails = Object.keys(byEmail);
    const conn = await pool.getConnection();
    let cleared = 0;
    try {
      await conn.beginTransaction();
      for (const email of emails) {
        await conn.query(
          `INSERT INTO rbac_users (email, display_name, is_active, roles_resolved_at)
             VALUES (?, ?, 1, NOW())
           ON DUPLICATE KEY UPDATE
             display_name      = COALESCE(VALUES(display_name), display_name),
             roles_resolved_at = NOW()`,
          [email, byEmail[email].displayName]
        );
        await conn.query('DELETE FROM rbac_user_roles WHERE email = ?', [email]);
        await conn.query(
          'INSERT INTO rbac_user_roles (email, role_key) VALUES ?',
          [byEmail[email].roles.map(rk => [email, rk])]
        );
      }
      // Authoritative: known users found in NO group lose their role rows.
      // Skipped when any group lookup failed, so a partial read never revokes.
      if (groupErrors.length === 0) {
        const [r2] = emails.length > 0
          ? await conn.query('DELETE FROM rbac_user_roles WHERE email NOT IN (?)', [emails])
          : await conn.query('DELETE FROM rbac_user_roles');
        cleared = r2.affectedRows;
      }
      await conn.commit();
    } catch (e) {
      try { await conn.rollback(); } catch (x) { /* ignore */ }
      conn.release();
      throw e;
    }
    conn.release();

    await rbac.audit(req, 'ad_full_sync', null, null, {
      by: req.user.email, users_synced: emails.length, role_rows_cleared: cleared, group_errors: groupErrors,
    });
    res.json({ ok: true, users_synced: emails.length, role_rows_cleared: cleared, errors: groupErrors });
  } catch (e) {
    console.error('[saas-admin] sync-ad failed:', e.message);
    res.status(500).json({ error: 'Sync failed', code: 'INTERNAL' });
  }
});

// ---------------- Discovery / drift ------------------------------------

router.get('/discovery', async (req, res) => {
  try {
    // 1. HTML files on disk
    let files = [];
    try {
      files = fs.readdirSync(WEB_ROOT)
        .filter(f => f.endsWith('.html'))
        .sort();
    } catch (e) {
      console.error('[saas-admin] web root scan failed:', e.message);
    }

    // 2. Registry
    const [pages] = await pool.query('SELECT page_key, url_path, status FROM rbac_pages');
    const registeredPaths = new Set(
      pages.filter(p => p.url_path).map(p => String(p.url_path).replace(/^\//, ''))
    );
    const registeredKeys = new Set(pages.map(p => p.page_key));

    const unregisteredFiles = files.filter(f => !registeredPaths.has(f));
    const missingFiles = pages
      .filter(p => p.url_path && p.status !== 'retired' && !files.includes(String(p.url_path).replace(/^\//, '')))
      .map(p => ({ page_key: p.page_key, url_path: p.url_path }));

    // 3. Guard keys in route files (both APIs), tolerant of ' and "
    const guardKeys = new Set();
    const guardRe = /requirePage\(\s*['"]([a-z0-9-]+)['"]/g;
    for (const dir of ROUTE_DIRS) {
      let names = [];
      try { names = fs.readdirSync(dir).filter(f => f.endsWith('.js')); } catch (e) { continue; }
      for (const name of names) {
        let src;
        try { src = fs.readFileSync(path.join(dir, name), 'utf8'); } catch (e) { continue; } // unreadable (root 0600) - skip
        let m;
        while ((m = guardRe.exec(src)) !== null) guardKeys.add(m[1]);
      }
    }

    const guardsWithoutRegistry = [...guardKeys].filter(k => !registeredKeys.has(k)).sort();
    const registryWithoutGuards = pages
      .filter(p => !guardKeys.has(p.page_key))
      .map(p => p.page_key)
      .sort();

    res.json({
      scanned_at: new Date().toISOString(),
      unregistered_files: unregisteredFiles,
      registry_missing_files: missingFiles,
      guards_without_registry: guardsWithoutRegistry,
      registry_without_guards: registryWithoutGuards,
      guard_keys_found: [...guardKeys].sort(),
    });
  } catch (e) {
    console.error('[saas-admin] discovery failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

module.exports = router;
