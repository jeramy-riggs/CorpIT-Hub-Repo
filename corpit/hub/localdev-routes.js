// =====================================================================
// localdev-routes.js  (v1.0.0)
//
// Sign-in and administration for local DEV/test accounts.
//
//   POST   /api/localdev/login              public, rate-limited
//   GET    /api/localdev/accounts           super-admin
//   POST   /api/localdev/accounts           super-admin
//   PATCH  /api/localdev/accounts/:email    super-admin
//   DELETE /api/localdev/accounts/:email    super-admin
//
// Every mutation and every sign-in (success or failure) writes rbac_audit_log.
// =====================================================================

'use strict';

const express = require('express');
const mysql   = require('mysql2/promise');
const localdev = require('./localdev-auth');
const createRbac = require('./rbac-middleware');

const router = express.Router();
router.use(express.json({ limit: '16kb' }));

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 4,
});

const rbac = createRbac(pool);

// The superadmin role can never be attached to a local account. The middleware
// strips it too, so this is the second of two independent guards.
const FORBIDDEN_ROLES = new Set(['superadmin']);

// ---------- brute-force guard (in-memory, per process) -----------------
const MAX_FAILS = 6;
const LOCK_MS   = 15 * 60 * 1000;
const fails = new Map();   // email -> { n, until }

function locked(email) {
  const f = fails.get(email);
  if (!f) return false;
  if (f.until && Date.now() < f.until) return true;
  if (f.until && Date.now() >= f.until) { fails.delete(email); return false; }
  return false;
}
function noteFail(email) {
  const f = fails.get(email) || { n: 0, until: 0 };
  f.n += 1;
  if (f.n >= MAX_FAILS) f.until = Date.now() + LOCK_MS;
  fails.set(email, f);
}
function clearFails(email) { fails.delete(email); }

// ---------- sign-in ----------------------------------------------------

router.post('/login', async (req, res) => {
  if (!localdev.isEnabled()) {
    return res.status(503).json({ error: 'DEV sign-in is not enabled on this server', code: 'LOCALDEV_OFF' });
  }
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  const password = String((req.body || {}).password || '');

  if (!localdev.isLocalName(email) || !password) {
    return res.status(400).json({ error: 'A @local sign-in name and password are required', code: 'BAD_REQUEST' });
  }
  if (locked(email)) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.', code: 'LOCKED' });
  }
  try {
    const [rows] = await pool.query(
      'SELECT email, display_name, password_hash, is_active FROM rbac_local_users WHERE email = ? LIMIT 1',
      [email]
    );
    // Same response shape and timing path whether the account is missing,
    // disabled, or the password is wrong - no account enumeration.
    const acct = rows[0];
    const ok = acct && acct.is_active
      ? await localdev.verifyPassword(password, acct.password_hash)
      : await localdev.verifyPassword(password, 'scrypt$16384$8$1$00$00');

    if (!acct || !acct.is_active || !ok) {
      noteFail(email);
      await rbac.audit({ user: { email }, headers: req.headers, socket: req.socket },
        'localdev_login_failed', email, null, { reason: !acct ? 'no_account' : (!acct.is_active ? 'disabled' : 'bad_password') });
      return res.status(401).json({ error: 'Sign-in failed', code: 'BAD_CREDENTIALS' });
    }

    clearFails(email);
    await pool.query('UPDATE rbac_local_users SET last_login_at = NOW() WHERE email = ?', [email]);
    const [rr] = await pool.query('SELECT role_key FROM rbac_user_roles WHERE email = ? ORDER BY role_key', [email]);
    const roles = rr.map(r => r.role_key).filter(r => !FORBIDDEN_ROLES.has(r));
    const token = localdev.mintToken(email, acct.display_name || email);

    await rbac.audit({ user: { email }, headers: req.headers, socket: req.socket },
      'localdev_login', email, null, { roles });

    require('./session-cookie').setSessionCookie(res, token, localdev.TTL_MS, req);
    res.json({ token, email, name: acct.display_name || email, roles, isLocalTest: true });
  } catch (e) {
    console.error('[localdev] login failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ---------- administration (super-admin only) --------------------------

router.use(rbac.loadCurrentUser);
router.use(rbac.requireSuperAdmin);

router.get('/accounts', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT l.email, l.display_name, l.is_active, l.note, l.created_by, l.created_at, l.last_login_at,
              GROUP_CONCAT(r.role_key ORDER BY r.role_key) AS roles
         FROM rbac_local_users l
         LEFT JOIN rbac_user_roles r ON r.email = l.email
        GROUP BY l.email
        ORDER BY l.email`
    );
    res.json({
      enabled: localdev.isEnabled(),
      accounts: rows.map(r => ({ ...r, roles: r.roles ? r.roles.split(',') : [] })),
    });
  } catch (e) {
    console.error('[localdev] list failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

async function setRoles(conn, email, roles) {
  await conn.query('DELETE FROM rbac_user_roles WHERE email = ?', [email]);
  const clean = (roles || []).filter(r => r && !FORBIDDEN_ROLES.has(r));
  if (clean.length) {
    await conn.query('INSERT INTO rbac_user_roles (email, role_key) VALUES ?',
      [clean.map(r => [email, r])]);
  }
  return clean;
}

router.post('/accounts', async (req, res) => {
  const b = req.body || {};
  const email = String(b.email || '').trim().toLowerCase();
  const password = String(b.password || '');
  if (!localdev.isLocalName(email)) {
    return res.status(400).json({ error: 'Sign-in name must look like test-tier1@local', code: 'BAD_NAME' });
  }
  if (password.length < 10) {
    return res.status(400).json({ error: 'Password must be at least 10 characters', code: 'WEAK_PASSWORD' });
  }
  const requested = Array.isArray(b.roles) ? b.roles : [];
  if (requested.some(r => FORBIDDEN_ROLES.has(r))) {
    return res.status(400).json({ error: 'A local account can never hold the superadmin role', code: 'FORBIDDEN_ROLE' });
  }
  const conn = await pool.getConnection();
  try {
    const hash = await localdev.hashPassword(password);
    await conn.beginTransaction();
    await conn.query(
      `INSERT INTO rbac_local_users (email, display_name, password_hash, is_active, note, created_by)
       VALUES (?,?,?,1,?,?)
       ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), password_hash=VALUES(password_hash),
                               is_active=1, note=VALUES(note)`,
      [email, b.displayName || email, hash, b.note || null, req.user.email]
    );
    // rbac_users row so per-user overrides (which FK to it) can target this account
    await conn.query(
      `INSERT INTO rbac_users (email, display_name, is_active, created_by)
       VALUES (?,?,1,?) ON DUPLICATE KEY UPDATE is_active=1`,
      [email, b.displayName || email, req.user.email]
    );
    const roles = await setRoles(conn, email, requested);
    await conn.commit();
    conn.release();
    await rbac.audit(req, 'localdev_account_created', email, null, { roles, by: req.user.email });
    res.json({ ok: true, email, roles });
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    conn.release();
    console.error('[localdev] create failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.patch('/accounts/:email', async (req, res) => {
  const email = String(req.params.email || '').trim().toLowerCase();
  const b = req.body || {};
  if (!localdev.isLocalName(email)) return res.status(400).json({ error: 'Not a local account', code: 'BAD_NAME' });
  if (Array.isArray(b.roles) && b.roles.some(r => FORBIDDEN_ROLES.has(r))) {
    return res.status(400).json({ error: 'A local account can never hold the superadmin role', code: 'FORBIDDEN_ROLE' });
  }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    if (typeof b.is_active === 'boolean') {
      await conn.query('UPDATE rbac_local_users SET is_active = ? WHERE email = ?', [b.is_active ? 1 : 0, email]);
    }
    if (b.password) {
      if (String(b.password).length < 10) {
        await conn.rollback(); conn.release();
        return res.status(400).json({ error: 'Password must be at least 10 characters', code: 'WEAK_PASSWORD' });
      }
      const hash = await localdev.hashPassword(String(b.password));
      await conn.query('UPDATE rbac_local_users SET password_hash = ? WHERE email = ?', [hash, email]);
    }
    let roles;
    if (Array.isArray(b.roles)) roles = await setRoles(conn, email, b.roles);
    await conn.commit();
    conn.release();
    await rbac.audit(req, 'localdev_account_updated', email, null,
      { is_active: b.is_active, roles, password_changed: !!b.password, by: req.user.email });
    res.json({ ok: true, email, roles });
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    conn.release();
    console.error('[localdev] update failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.delete('/accounts/:email', async (req, res) => {
  const email = String(req.params.email || '').trim().toLowerCase();
  if (!localdev.isLocalName(email)) return res.status(400).json({ error: 'Not a local account', code: 'BAD_NAME' });
  try {
    await pool.query('DELETE FROM rbac_user_roles WHERE email = ?', [email]);
    await pool.query('DELETE FROM rbac_local_users WHERE email = ?', [email]);
    await pool.query('DELETE FROM rbac_users WHERE email = ?', [email]);
    await rbac.audit(req, 'localdev_account_deleted', email, null, { by: req.user.email });
    res.json({ ok: true, email });
  } catch (e) {
    console.error('[localdev] delete failed:', e.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

module.exports = router;
