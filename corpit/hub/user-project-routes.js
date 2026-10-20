/**
 * user-project-routes.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Express router for the User Projects access tracker.
 *
 * Tracks POC/Project AD-group grants with optional auto-expiry. Adds and
 * removes happen through manage-groups.py (the same Python helper used by
 * ad-provisioning.js). Reads use LDAP. Reference-counting prevents removing
 * a user from a group if another active grant still keeps them in.
 *
 * Mounted at:  app.use('/api/user-project', require('./user-project-routes'))
 * RBAC page:   user-projects
 * ─────────────────────────────────────────────────────────────────────────────
 */

const express   = require('express');
const path      = require('path');
const { spawn } = require('child_process');
const ldap      = require('ldapjs');
const mysql     = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const router = express.Router();

// ─── DB pool + RBAC ──────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
// settingsfold W6 2026-10-12: PATCH /settings and POST /digest/send-test also write an
// rbac_audit_log row (page user-projects) so User activity shows them. The
// user_project_audit rows below are unchanged.
const SA = require('./settings-audit');

// ─── LDAP config ─────────────────────────────────────────────────────────────
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

function createLdapClient() {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({ url: LDAP_URL, timeout: LDAP_TIMEOUT, connectTimeout: LDAP_TIMEOUT });
    client.on('error', err => reject(new Error(`LDAP client error: ${err.message}`)));
    client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, err => {
      if (err) return reject(new Error(`LDAP bind: ${err.message}`));
      resolve(client);
    });
  });
}

function ldapSearch(client, base, filter, attributes, sizeLimit = 100, scope = 'sub') {
  return new Promise((resolve, reject) => {
    const entries = [];
    client.search(base, { filter, attributes, scope, sizeLimit, paged: { pageSize: 100 } }, (err, res) => {
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

function closeLdap(client) { try { client.unbind(); } catch (_) {} }

// ─── Audit helper ────────────────────────────────────────────────────────────
async function audit(conn, { project_id = null, grant_id = null, action, actor, details = null }) {
  try {
    await conn.query(
      'INSERT INTO user_project_audit (project_id, grant_id, action, actor, details) VALUES (?, ?, ?, ?, ?)',
      [project_id, grant_id, action, actor || 'system', details ? JSON.stringify(details) : null]
    );
  } catch (err) {
    console.error('[user-project] audit insert failed:', err.message);
  }
}

// ─── manage-groups.py wrapper ────────────────────────────────────────────────
function runManageGroups({ samAccountName, addGroups = [], removeGroups = [] }) {
  return new Promise((resolve, reject) => {
    if (!process.env.WINRM_USER || !process.env.WINRM_PASS) {
      return reject(new Error('WinRM credentials not configured on server'));
    }
    const scriptPath = path.join(__dirname, 'manage-groups.py');
    const payload    = JSON.stringify({ samAccountName, addGroups, removeGroups });
    const child = spawn('python3', [scriptPath], {
      env: { ...process.env, WINRM_USER: process.env.WINRM_USER, WINRM_PASS: process.env.WINRM_PASS },
      timeout: 90000,
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.on('error', err => reject(err));
    child.on('close', code => {
      if (code !== 0 && !stdout) return reject(new Error(stderr || `manage-groups.py exited ${code}`));
      try { resolve(JSON.parse(stdout.trim())); }
      catch (e) { reject(new Error(`manage-groups.py invalid JSON: ${stdout.slice(0, 200)}`)); }
    });
    child.stdin.write(payload);
    child.stdin.end();
  });
}

// ─── Helper: settings get/set ────────────────────────────────────────────────
async function getSetting(conn, key) {
  const [rows] = await conn.query('SELECT setting_value FROM user_project_settings WHERE setting_key=?', [key]);
  return rows.length ? rows[0].setting_value : null;
}
async function setSetting(conn, key, value, actor) {
  await conn.query(
    'INSERT INTO user_project_settings (setting_key, setting_value, updated_by) VALUES (?,?,?) ' +
    'ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value), updated_by=VALUES(updated_by)',
    [key, value, actor]
  );
}

// ─── Helper: actor (string used for granted_by/created_by/etc) ───────────────
function actor(req) {
  return (req.user && req.user.email) || 'unknown';
}

// ─── Validation helpers ──────────────────────────────────────────────────────
function isValidStatus(s)   { return ['active','paused','closed'].includes(s); }
function isValidMode(m)     { return ['auto','custom','permanent'].includes(m); }
function isValidDate(s)     { return /^\d{4}-\d{2}-\d{2}$/.test(s); }
function isValidDateTime(s) {
  if (!s) return false;
  const d = new Date(s);
  return !isNaN(d.getTime());
}

// ═════════════════════════════════════════════════════════════════════════════
// HEALTH
// ═════════════════════════════════════════════════════════════════════════════
router.get('/health', async (req, res) => {
  try {
    const [r] = await pool.query('SELECT COUNT(*) AS c FROM user_projects');
    res.json({ status: 'ok', projects: r[0].c, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// USERS — LDAP search-as-you-type
// ═════════════════════════════════════════════════════════════════════════════
router.get('/users/search', rbac.requirePage('user-projects','read'), async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q || q.length < 2) return res.status(400).json({ error: 'Query must be at least 2 characters' });
  let client;
  try {
    client = await createLdapClient();
    const safeQ = q.replace(/[()\\*\0]/g, '');
    const filter = `(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*${safeQ}*)(displayName=*${safeQ}*)(cn=*${safeQ}*)(mail=*${safeQ}*)))`;
    const results = await ldapSearch(client, LDAP_BASE_DN, filter,
      ['sAMAccountName','displayName','mail','title','department','distinguishedName','userAccountControl'], 20);
    const users = results.map(u => ({
      samAccountName: u.sAMAccountName || '',
      displayName:    u.displayName || u.cn || u.sAMAccountName || '',
      mail:           u.mail || '',
      title:          u.title || '',
      department:     u.department || '',
      dn:             u.distinguishedName || '',
      enabled:        u.userAccountControl ? !(parseInt(u.userAccountControl, 10) & 0x0002) : null,
    })).filter(u => u.samAccountName);
    closeLdap(client);
    res.json({ users, count: users.length });
  } catch (err) {
    if (client) closeLdap(client);
    res.status(500).json({ error: 'LDAP search failed', message: err.message });
  }
});

// LDAP lookup of a single user's current AD group memberships (sanity check on add)
router.get('/users/:sam/groups', rbac.requirePage('user-projects','read'), async (req, res) => {
  const sam = (req.params.sam || '').replace(/[()\\*\0]/g, '');
  if (!sam) return res.status(400).json({ error: 'Invalid sAMAccountName' });
  let client;
  try {
    client = await createLdapClient();
    const results = await ldapSearch(client, LDAP_BASE_DN,
      `(&(objectCategory=person)(objectClass=user)(sAMAccountName=${sam}))`,
      ['sAMAccountName','memberOf','displayName'], 1);
    closeLdap(client);
    if (!results.length) return res.status(404).json({ error: 'User not found' });
    const u = results[0];
    const memberOf = Array.isArray(u.memberOf) ? u.memberOf : (u.memberOf ? [u.memberOf] : []);
    const groups = memberOf.map(dn => {
      const m = dn.match(/^CN=([^,]+)/i);
      return m ? m[1] : dn;
    });
    res.json({ samAccountName: u.sAMAccountName, displayName: u.displayName || '', groups });
  } catch (err) {
    if (client) closeLdap(client);
    res.status(500).json({ error: 'LDAP lookup failed', message: err.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// PROJECTS — list / get / create / edit
// ═════════════════════════════════════════════════════════════════════════════
router.get('/projects', rbac.requirePage('user-projects','read'), async (req, res) => {
  try {
    const [projects] = await pool.query(
      `SELECT p.*,
              (SELECT COUNT(*) FROM user_project_groups g WHERE g.project_id = p.id) AS group_count,
              (SELECT COUNT(*) FROM user_project_grants gr WHERE gr.project_id = p.id AND gr.status='active') AS active_grants,
              -- The card beside active_grants renders an "All-time" grant count from
              -- p.total_grants, which this SELECT never produced: it read undefined and
              -- printed a hard 0 for every project. On an archived card, where the
              -- active count is hidden, that zero was the only number shown.
              (SELECT COUNT(*) FROM user_project_grants gr2 WHERE gr2.project_id = p.id) AS total_grants
       FROM user_projects p
       ORDER BY p.status='active' DESC, p.name ASC`
    );
    res.json({ projects });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/projects/:id', rbac.requirePage('user-projects','read'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid project id' });
  try {
    const [pRows] = await pool.query('SELECT * FROM user_projects WHERE id=?', [id]);
    if (!pRows.length) return res.status(404).json({ error: 'Project not found' });
    const [groups] = await pool.query(
      'SELECT id, ad_group_name, ad_group_dn, added_by, added_at FROM user_project_groups WHERE project_id=? ORDER BY ad_group_name',
      [id]
    );
    const [grants] = await pool.query(
      `SELECT * FROM user_project_grants WHERE project_id=? AND status='active' ORDER BY granted_at DESC`,
      [id]
    );
    res.json({ project: pRows[0], groups, active_grants: grants });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const { name, description, owner, status, start_date, planned_end_date, default_removal_mode, groups } = req.body || {};
  if (!name || typeof name !== 'string' || name.trim().length === 0 || name.length > 150) {
    return res.status(400).json({ error: 'Project name required (1-150 chars)' });
  }
  const s = status || 'active';
  if (!isValidStatus(s)) return res.status(400).json({ error: 'Invalid status' });
  const mode = default_removal_mode || 'auto';
  if (!isValidMode(mode)) return res.status(400).json({ error: 'Invalid default_removal_mode' });
  if (start_date && !isValidDate(start_date)) return res.status(400).json({ error: 'start_date must be YYYY-MM-DD' });
  if (planned_end_date && !isValidDate(planned_end_date)) return res.status(400).json({ error: 'planned_end_date must be YYYY-MM-DD' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [r] = await conn.query(
      `INSERT INTO user_projects (name, description, owner, status, start_date, planned_end_date, default_removal_mode, created_by, updated_by)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [name.trim(), description || null, owner || null, s, start_date || null, planned_end_date || null, mode, actor(req), actor(req)]
    );
    const projectId = r.insertId;

    if (Array.isArray(groups) && groups.length) {
      for (const g of groups) {
        if (typeof g !== 'string' || !g.trim()) continue;
        await conn.query(
          'INSERT IGNORE INTO user_project_groups (project_id, ad_group_name, added_by) VALUES (?,?,?)',
          [projectId, g.trim(), actor(req)]
        );
      }
    }
    await audit(conn, { project_id: projectId, action: 'project_created', actor: actor(req), details: { name, groups: groups || [] } });
    await conn.commit();

    const [created] = await pool.query('SELECT * FROM user_projects WHERE id=?', [projectId]);
    res.status(201).json({ project: created[0] });
  } catch (err) {
    await conn.rollback();
    if (err && err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'A project with that name already exists' });
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

router.patch('/projects/:id', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid project id' });
  const fields = [];
  const params = [];
  const allowed = { name:'string', description:'string', owner:'string', status:'status', start_date:'date',
                    planned_end_date:'date', default_removal_mode:'mode' };
  for (const [k, kind] of Object.entries(allowed)) {
    if (!(k in (req.body || {}))) continue;
    const v = req.body[k];
    if (kind === 'status' && v !== null && !isValidStatus(v)) return res.status(400).json({ error: `Invalid ${k}` });
    if (kind === 'mode'   && v !== null && !isValidMode(v))   return res.status(400).json({ error: `Invalid ${k}` });
    if (kind === 'date'   && v && !isValidDate(v))            return res.status(400).json({ error: `${k} must be YYYY-MM-DD` });
    fields.push(`${k} = ?`);
    params.push(v === '' ? null : v);
  }
  if (!fields.length) return res.status(400).json({ error: 'No editable fields supplied' });
  fields.push('updated_by = ?');
  params.push(actor(req));
  params.push(id);

  const conn = await pool.getConnection();
  try {
    const [existing] = await conn.query('SELECT * FROM user_projects WHERE id=?', [id]);
    if (!existing.length) return res.status(404).json({ error: 'Project not found' });
    await conn.query(`UPDATE user_projects SET ${fields.join(', ')} WHERE id=?`, params);
    await audit(conn, { project_id: id, action: 'project_edited', actor: actor(req), details: { changes: req.body } });
    const [updated] = await conn.query('SELECT * FROM user_projects WHERE id=?', [id]);
    res.json({ project: updated[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// ─── Project groups (link/unlink AD groups) ──────────────────────────────────
router.post('/projects/:id/groups', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { ad_group_name } = req.body || {};
  if (!id) return res.status(400).json({ error: 'Invalid project id' });
  if (!ad_group_name || typeof ad_group_name !== 'string' || !ad_group_name.trim())
    return res.status(400).json({ error: 'ad_group_name required' });

  // Sensitive-group blocklist
  try {
    const blRaw = await getSetting(pool, 'sensitive_group_blocklist');
    const bl = blRaw ? JSON.parse(blRaw) : [];
    if (Array.isArray(bl) && bl.some(b => b.toLowerCase() === ad_group_name.trim().toLowerCase())) {
      return res.status(403).json({ error: `Group "${ad_group_name}" is on the sensitive-group blocklist and cannot be added to a project.` });
    }
  } catch (_) { /* ignore parse errors, fail open */ }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [pRows] = await conn.query('SELECT id FROM user_projects WHERE id=?', [id]);
    if (!pRows.length) { await conn.rollback(); return res.status(404).json({ error: 'Project not found' }); }
    await conn.query(
      'INSERT IGNORE INTO user_project_groups (project_id, ad_group_name, added_by) VALUES (?,?,?)',
      [id, ad_group_name.trim(), actor(req)]
    );
    await audit(conn, { project_id: id, action: 'group_added', actor: actor(req), details: { ad_group_name } });
    await conn.commit();
    const [rows] = await pool.query('SELECT * FROM user_project_groups WHERE project_id=? ORDER BY ad_group_name', [id]);
    res.status(201).json({ groups: rows });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

router.delete('/projects/:id/groups/:gid', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const id  = parseInt(req.params.id, 10);
  const gid = parseInt(req.params.gid, 10);
  if (!id || !gid) return res.status(400).json({ error: 'Invalid ids' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [gRows] = await conn.query('SELECT * FROM user_project_groups WHERE id=? AND project_id=?', [gid, id]);
    if (!gRows.length) { await conn.rollback(); return res.status(404).json({ error: 'Group mapping not found' }); }
    // Check active grants that depend on this group
    const [activeUse] = await conn.query(
      `SELECT COUNT(*) AS c FROM user_project_grants WHERE project_id=? AND ad_group_name=? AND status='active'`,
      [id, gRows[0].ad_group_name]
    );
    if (activeUse[0].c > 0) {
      await conn.rollback();
      return res.status(409).json({ error: `Cannot unlink: ${activeUse[0].c} active grant(s) reference this group. Revoke them first.` });
    }
    await conn.query('DELETE FROM user_project_groups WHERE id=?', [gid]);
    await audit(conn, { project_id: id, action: 'group_removed', actor: actor(req), details: { ad_group_name: gRows[0].ad_group_name } });
    await conn.commit();
    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// GRANTS — list / create / extend / revoke
// ═════════════════════════════════════════════════════════════════════════════
router.get('/grants', rbac.requirePage('user-projects','read'), async (req, res) => {
  const status = req.query.status || 'active';
  if (!['active','expired','revoked','all'].includes(status))
    return res.status(400).json({ error: 'Invalid status filter' });
  try {
    let sql = `SELECT g.*, p.name AS project_name, p.status AS project_status
               FROM user_project_grants g JOIN user_projects p ON p.id = g.project_id`;
    const params = [];
    if (status !== 'all') { sql += ' WHERE g.status=?'; params.push(status); }
    sql += ' ORDER BY g.granted_at DESC LIMIT 2000';
    const [rows] = await pool.query(sql, params);
    res.json({ grants: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/grants', rbac.requirePage('user-projects','admin'), async (req, res) => {
  let { project_id, ad_group_name, user_sam, user_display_name, user_dept,
        removal_mode, expires_at, notes } = req.body || {};
  project_id = parseInt(project_id, 10);
  if (!project_id || !ad_group_name || !user_sam) {
    return res.status(400).json({ error: 'project_id, ad_group_name, and user_sam are required' });
  }
  user_sam = String(user_sam).trim();
  ad_group_name = String(ad_group_name).trim();
  removal_mode = removal_mode || 'auto';
  if (!isValidMode(removal_mode)) return res.status(400).json({ error: 'Invalid removal_mode' });
  if (removal_mode === 'permanent') expires_at = null;
  if (expires_at && !isValidDateTime(expires_at)) return res.status(400).json({ error: 'expires_at must be parseable datetime' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. project exists + group is attached
    const [pRows] = await conn.query('SELECT * FROM user_projects WHERE id=?', [project_id]);
    if (!pRows.length) { await conn.rollback(); return res.status(404).json({ error: 'Project not found' }); }
    const project = pRows[0];
    if (project.status === 'closed') {
      await conn.rollback(); return res.status(409).json({ error: 'Project is closed; cannot add new grants.' });
    }

    const [gRows] = await conn.query(
      'SELECT id FROM user_project_groups WHERE project_id=? AND ad_group_name=?',
      [project_id, ad_group_name]
    );
    if (!gRows.length) { await conn.rollback(); return res.status(400).json({ error: 'That group is not attached to this project.' }); }

    // 2. Resolve auto-mode expiry from POC end date (else permanent until POC sets one)
    let resolvedExpiresAt = expires_at || null;
    if (removal_mode === 'auto') {
      resolvedExpiresAt = project.planned_end_date
        ? new Date(project.planned_end_date + 'T23:59:59').toISOString().slice(0, 19).replace('T',' ')
        : null;
    } else if (removal_mode === 'custom') {
      if (!expires_at) { await conn.rollback(); return res.status(400).json({ error: 'expires_at required for custom mode' }); }
      resolvedExpiresAt = new Date(expires_at).toISOString().slice(0, 19).replace('T',' ');
    } else { // permanent
      resolvedExpiresAt = null;
    }

    // 3. Sensitive-group safety
    try {
      const blRaw = await getSetting(conn, 'sensitive_group_blocklist');
      const bl = blRaw ? JSON.parse(blRaw) : [];
      if (Array.isArray(bl) && bl.some(b => b.toLowerCase() === ad_group_name.toLowerCase())) {
        await conn.rollback();
        return res.status(403).json({ error: `Group "${ad_group_name}" is blocklisted.` });
      }
    } catch (_) {}

    // 4. Check existing grant for same project+group+user; longer-date-wins
    const [existing] = await conn.query(
      `SELECT * FROM user_project_grants WHERE project_id=? AND ad_group_name=? AND user_sam=?`,
      [project_id, ad_group_name, user_sam]
    );
    let grantId, adAction = null, adMessage = null;

    if (existing.length) {
      const ex = existing[0];
      if (ex.status === 'active') {
        // Compute new expiry: permanent beats everything; otherwise max(old, new)
        let nextExp = ex.expires_at;
        let modeFinal = ex.removal_mode;
        if (removal_mode === 'permanent' || ex.removal_mode === 'permanent') {
          nextExp = null; modeFinal = 'permanent';
        } else {
          const oldT = ex.expires_at ? new Date(ex.expires_at).getTime() : null;
          const newT = resolvedExpiresAt ? new Date(resolvedExpiresAt).getTime() : null;
          if (oldT == null && newT == null) { nextExp = null; }
          else if (oldT == null) { nextExp = ex.expires_at; modeFinal = ex.removal_mode; } // permanent stays permanent
          else if (newT == null) { nextExp = null; modeFinal = removal_mode; } // shouldn't hit
          else { nextExp = (newT > oldT) ? resolvedExpiresAt : ex.expires_at;
                 modeFinal = (newT > oldT) ? removal_mode : ex.removal_mode; }
        }
        await conn.query(
          `UPDATE user_project_grants SET removal_mode=?, expires_at=?, notes=?, granted_by=?, granted_at=CURRENT_TIMESTAMP WHERE id=?`,
          [modeFinal, nextExp, notes ?? ex.notes, actor(req), ex.id]
        );
        grantId = ex.id;
        await audit(conn, { project_id, grant_id: grantId, action: 'extended', actor: actor(req),
                            details: { old_expires_at: ex.expires_at, new_expires_at: nextExp, old_mode: ex.removal_mode, new_mode: modeFinal } });
        await conn.commit();
        const [g] = await pool.query('SELECT * FROM user_project_grants WHERE id=?', [grantId]);
        return res.json({ grant: g[0], ad_action: 'no_op_existing_active', message: 'Existing active grant updated (longer date wins).' });
      } else {
        // existing expired/revoked → reactivate by UPDATE
        await conn.query(
          `UPDATE user_project_grants SET status='active', removal_mode=?, expires_at=?, notes=?, granted_by=?, granted_at=CURRENT_TIMESTAMP,
                                          removed_by=NULL, removed_at=NULL, ad_action_on_remove=NULL
           WHERE id=?`,
          [removal_mode, resolvedExpiresAt, notes ?? null, actor(req), ex.id]
        );
        grantId = ex.id;
      }
    } else {
      const [r] = await conn.query(
        `INSERT INTO user_project_grants (project_id, ad_group_name, user_sam, user_display_name, user_dept,
                                           removal_mode, expires_at, status, notes, granted_by)
         VALUES (?,?,?,?,?,?,?, 'active', ?, ?)`,
        [project_id, ad_group_name, user_sam, user_display_name || null, user_dept || null,
         removal_mode, resolvedExpiresAt, notes || null, actor(req)]
      );
      grantId = r.insertId;
    }

    // 5. Reference-count: any OTHER active grant for this user+group?
    const [refs] = await conn.query(
      `SELECT COUNT(*) AS c FROM user_project_grants
       WHERE user_sam=? AND ad_group_name=? AND status='active' AND id<>?`,
      [user_sam, ad_group_name, grantId]
    );
    const alreadyTracked = refs[0].c > 0;

    // Commit DB state BEFORE WinRM, so failure of AD doesn't lose the row.
    await conn.commit();

    // 6. Trigger AD add (unless reference-counting says user is already in via another grant)
    if (alreadyTracked) {
      await pool.query(`UPDATE user_project_grants SET ad_action_on_add='skipped_already_member' WHERE id=?`, [grantId]);
      await audit(pool, { project_id, grant_id: grantId, action: 'ad_skip', actor: actor(req),
                          details: { reason: 'other active grant exists' } });
      adAction = 'skipped_already_member';
      adMessage = 'Tracked grant created. AD add skipped — another active grant keeps user in the group.';
    } else {
      try {
        const r = await runManageGroups({ samAccountName: user_sam, addGroups: [ad_group_name] });
        const addEntry = (r.added || []).find(x => x.group === ad_group_name);
        if (addEntry && addEntry.success) {
          if (/already a member/i.test(addEntry.message || '')) {
            adAction = 'skipped_already_member';
          } else {
            adAction = 'added';
          }
        } else {
          adAction = 'failed';
          adMessage = (addEntry && addEntry.message) || 'AD add reported failure';
        }
        await pool.query(`UPDATE user_project_grants SET ad_action_on_add=? WHERE id=?`, [adAction, grantId]);
        await audit(pool, { project_id, grant_id: grantId, action: 'ad_add', actor: actor(req),
                            details: { ad_group_name, user_sam, result: r } });
      } catch (err) {
        adAction = 'failed';
        adMessage = err.message;
        await pool.query(`UPDATE user_project_grants SET ad_action_on_add='failed' WHERE id=?`, [grantId]);
        await audit(pool, { project_id, grant_id: grantId, action: 'ad_add', actor: actor(req),
                            details: { ad_group_name, user_sam, error: err.message } });
      }
    }

    await audit(pool, { project_id, grant_id: grantId, action: 'created', actor: actor(req),
                        details: { ad_group_name, user_sam, removal_mode, expires_at: resolvedExpiresAt } });

    const [g] = await pool.query('SELECT * FROM user_project_grants WHERE id=?', [grantId]);
    res.status(201).json({ grant: g[0], ad_action: adAction, message: adMessage });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// EXTEND — push out expiry / flip to permanent
router.post('/grants/:id/extend', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  let { removal_mode, expires_at } = req.body || {};
  if (!id) return res.status(400).json({ error: 'Invalid grant id' });
  if (removal_mode && !isValidMode(removal_mode)) return res.status(400).json({ error: 'Invalid removal_mode' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query('SELECT * FROM user_project_grants WHERE id=?', [id]);
    if (!rows.length) { await conn.rollback(); return res.status(404).json({ error: 'Grant not found' }); }
    const ex = rows[0];
    if (ex.status !== 'active') { await conn.rollback(); return res.status(409).json({ error: 'Only active grants can be extended.' }); }

    let modeFinal = removal_mode || ex.removal_mode;
    let nextExp;
    if (modeFinal === 'permanent') nextExp = null;
    else if (expires_at) {
      if (!isValidDateTime(expires_at)) { await conn.rollback(); return res.status(400).json({ error: 'expires_at must be parseable datetime' }); }
      nextExp = new Date(expires_at).toISOString().slice(0, 19).replace('T',' ');
    } else if (modeFinal === 'auto') {
      const [p] = await conn.query('SELECT planned_end_date FROM user_projects WHERE id=?', [ex.project_id]);
      nextExp = p.length && p[0].planned_end_date
        ? new Date(p[0].planned_end_date + 'T23:59:59').toISOString().slice(0, 19).replace('T',' ')
        : null;
    } else {
      await conn.rollback();
      return res.status(400).json({ error: 'expires_at required when extending without changing mode to permanent/auto.' });
    }

    await conn.query(
      `UPDATE user_project_grants SET removal_mode=?, expires_at=?, granted_by=?, granted_at=CURRENT_TIMESTAMP WHERE id=?`,
      [modeFinal, nextExp, actor(req), id]
    );
    await audit(conn, { project_id: ex.project_id, grant_id: id, action: 'extended', actor: actor(req),
                        details: { old_expires_at: ex.expires_at, new_expires_at: nextExp, old_mode: ex.removal_mode, new_mode: modeFinal } });
    await conn.commit();
    const [g] = await pool.query('SELECT * FROM user_project_grants WHERE id=?', [id]);
    res.json({ grant: g[0] });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// REVOKE — manually remove now (reference-counted)
router.post('/grants/:id/revoke', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid grant id' });

  const conn = await pool.getConnection();
  let ex, otherCount;
  try {
    const [rows] = await conn.query('SELECT * FROM user_project_grants WHERE id=?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Grant not found' });
    ex = rows[0];
    if (ex.status !== 'active') return res.status(409).json({ error: 'Grant is not active.' });

    const [refs] = await conn.query(
      `SELECT COUNT(*) AS c FROM user_project_grants
       WHERE user_sam=? AND ad_group_name=? AND status='active' AND id<>?`,
      [ex.user_sam, ex.ad_group_name, id]
    );
    otherCount = refs[0].c;
  } finally {
    conn.release();
  }

  let adRemoveAction = null, adMessage = null;
  if (otherCount > 0) {
    adRemoveAction = 'skipped_other_active_grants';
    adMessage = `${otherCount} other active grant(s) keep user in the group; AD not changed.`;
    await audit(pool, { project_id: ex.project_id, grant_id: id, action: 'ad_skip', actor: actor(req),
                        details: { reason: 'other active grants', other_count: otherCount } });
  } else {
    try {
      const r = await runManageGroups({ samAccountName: ex.user_sam, removeGroups: [ex.ad_group_name] });
      const remEntry = (r.removed || []).find(x => x.group === ex.ad_group_name);
      adRemoveAction = (remEntry && remEntry.success) ? 'removed' : 'failed';
      adMessage = remEntry ? remEntry.message : 'no entry in result';
      await audit(pool, { project_id: ex.project_id, grant_id: id, action: 'ad_remove', actor: actor(req),
                          details: { ad_group_name: ex.ad_group_name, user_sam: ex.user_sam, result: r } });
    } catch (err) {
      adRemoveAction = 'failed';
      adMessage = err.message;
      await audit(pool, { project_id: ex.project_id, grant_id: id, action: 'ad_remove', actor: actor(req),
                          details: { ad_group_name: ex.ad_group_name, user_sam: ex.user_sam, error: err.message } });
    }
  }

  // 'manual_revoke' marker on the column for human readability;
  // 'removed/skipped/failed' captured in audit details.
  await pool.query(
    `UPDATE user_project_grants SET status='revoked', removed_by=?, removed_at=NOW(),
                                     ad_action_on_remove='manual_revoke' WHERE id=?`,
    [actor(req), id]
  );
  await audit(pool, { project_id: ex.project_id, grant_id: id, action: 'revoked', actor: actor(req),
                      details: { ad_remove_outcome: adRemoveAction, ad_message: adMessage } });

  const [g] = await pool.query('SELECT * FROM user_project_grants WHERE id=?', [id]);
  res.json({ grant: g[0], ad_action: adRemoveAction, message: adMessage });
});

// ═════════════════════════════════════════════════════════════════════════════
// HISTORY / AUDIT
// ═════════════════════════════════════════════════════════════════════════════
router.get('/projects/:id/history', rbac.requirePage('user-projects','read'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid project id' });
  try {
    const [rows] = await pool.query(
      `SELECT * FROM user_project_grants WHERE project_id=? AND status IN ('expired','revoked')
       ORDER BY removed_at DESC LIMIT 500`, [id]);
    res.json({ history: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/audit', rbac.requirePage('user-projects','read'), async (req, res) => {
  const projectId = req.query.project_id ? parseInt(req.query.project_id, 10) : null;
  const grantId   = req.query.grant_id ? parseInt(req.query.grant_id, 10) : null;
  const limit     = Math.min(parseInt(req.query.limit || '200', 10), 1000);
  try {
    let sql = 'SELECT * FROM user_project_audit WHERE 1=1';
    const params = [];
    if (projectId) { sql += ' AND project_id=?'; params.push(projectId); }
    if (grantId)   { sql += ' AND grant_id=?';   params.push(grantId); }
    sql += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);
    const [rows] = await pool.query(sql, params);
    res.json({ audit: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// SETTINGS
// ═════════════════════════════════════════════════════════════════════════════
router.get('/settings', rbac.requirePage('user-projects','read'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT setting_key, setting_value, updated_by, updated_at FROM user_project_settings');
    const out = {};
    for (const r of rows) out[r.setting_key] = { value: r.setting_value, updated_by: r.updated_by, updated_at: r.updated_at };
    res.json({ settings: out });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.patch('/settings', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const updates = req.body || {};
  const ALLOWED = ['digest_enabled','digest_day_of_week','digest_hour_local','digest_recipients','sensitive_group_blocklist','digest_sections'];
  const saKeys = Object.keys(updates).filter(k => ALLOWED.includes(k));
  const saBefore = saKeys.length ? await SA.byKey(pool, 'SELECT setting_key, setting_value FROM user_project_settings', [], 'setting_key', 'setting_value') : undefined;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const k of Object.keys(updates)) {
      if (!ALLOWED.includes(k)) continue;
      let v = updates[k];
      // Validate per-key
      if (k === 'digest_enabled') v = (v === true || v === 'true') ? 'true' : 'false';
      else if (k === 'digest_day_of_week') {
        const n = parseInt(v, 10); if (!(n >= 1 && n <= 7)) { await conn.rollback(); return res.status(400).json({ error: 'digest_day_of_week must be 1-7 (Mon=1)' }); }
        v = String(n);
      } else if (k === 'digest_hour_local') {
        const n = parseInt(v, 10); if (!(n >= 0 && n <= 23)) { await conn.rollback(); return res.status(400).json({ error: 'digest_hour_local must be 0-23' }); }
        v = String(n);
      } else if (k === 'digest_recipients' || k === 'sensitive_group_blocklist') {
        if (!Array.isArray(v)) { await conn.rollback(); return res.status(400).json({ error: `${k} must be an array` }); }
        v = JSON.stringify(v);
      }
      await setSetting(conn, k, v, actor(req));
    }
    await audit(conn, { action: 'settings_changed', actor: actor(req), details: { keys: Object.keys(updates) } });
    await conn.commit();
    const [rows] = await pool.query('SELECT setting_key, setting_value, updated_by, updated_at FROM user_project_settings');
    const out = {};
    for (const r of rows) out[r.setting_key] = { value: r.setting_value, updated_by: r.updated_by, updated_at: r.updated_at };
    if (saKeys.length) {
      const saAfter = {};
      for (const r of rows) saAfter[r.setting_key] = r.setting_value;
      await SA.record(rbac, req, 'user-projects', 'settings_saved', SA.entry({ what: 'digest_settings', op: 'update',
        before: saBefore, after: saAfter, keys: saKeys }));
    }
    res.json({ settings: out });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// ─── Bulk-create: project + group + N user grants in one shot ────────────────
router.post('/projects/bulk-create', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const { name, description, ad_group_name, users, expires_at, permanent } = req.body || {};

  // Validation
  if (!name || typeof name !== 'string' || !name.trim() || name.length > 150) {
    return res.status(400).json({ error: 'Project name required (1-150 chars)' });
  }
  if (!ad_group_name || typeof ad_group_name !== 'string' || !ad_group_name.trim()) {
    return res.status(400).json({ error: 'ad_group_name required' });
  }
  if (!Array.isArray(users) || users.length === 0) {
    return res.status(400).json({ error: 'At least one user required' });
  }
  if (users.length > 100) {
    return res.status(400).json({ error: 'Max 100 users per bulk-create' });
  }
  const isPermanent = permanent === true || permanent === 'true';
  if (!isPermanent) {
    if (!expires_at || !isValidDate(expires_at)) {
      return res.status(400).json({ error: 'expires_at (YYYY-MM-DD) required when not permanent' });
    }
  }

  // Normalize user list
  const cleanUsers = [];
  for (const u of users) {
    if (!u || typeof u !== 'object') continue;
    const sam = String(u.sam || u.samAccountName || '').trim();
    if (!sam) continue;
    cleanUsers.push({
      sam,
      display: u.display || u.displayName || null,
      dept: u.dept || u.department || null,
    });
  }
  if (!cleanUsers.length) return res.status(400).json({ error: 'No valid users in users[]' });

  // Sensitive group safety check
  const conn0 = await pool.getConnection();
  try {
    const blRaw = await getSetting(conn0, 'sensitive_group_blocklist');
    const bl = blRaw ? JSON.parse(blRaw) : [];
    if (Array.isArray(bl) && bl.some(b => b.toLowerCase() === ad_group_name.trim().toLowerCase())) {
      conn0.release();
      return res.status(403).json({ error: `Group "${ad_group_name}" is blocklisted.` });
    }
  } catch (_) {}
  conn0.release();

  const conn = await pool.getConnection();
  let projectId;
  let grantRows = [];
  try {
    await conn.beginTransaction();

    // 1. INSERT project
    const removalMode = isPermanent ? 'permanent' : 'auto';
    const plannedEnd = isPermanent ? null : expires_at;
    const resolvedExpiresAt = isPermanent ? null
      : new Date(expires_at + 'T23:59:59').toISOString().slice(0,19).replace('T',' ');

    const [pr] = await conn.query(
      `INSERT INTO user_projects (name, description, owner, status, start_date, planned_end_date, default_removal_mode, created_by, updated_by)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [name.trim(), description || null, null, 'active', null, plannedEnd, removalMode, actor(req), actor(req)]
    );
    projectId = pr.insertId;

    // 2. INSERT project_group link
    await conn.query(
      'INSERT INTO user_project_groups (project_id, ad_group_name, added_by) VALUES (?,?,?)',
      [projectId, ad_group_name.trim(), actor(req)]
    );

    // 3. INSERT a grant row per user
    for (const u of cleanUsers) {
      const [gr] = await conn.query(
        `INSERT INTO user_project_grants (project_id, ad_group_name, user_sam, user_display_name, user_dept,
                                           removal_mode, expires_at, status, notes, granted_by)
         VALUES (?,?,?,?,?,?,?, 'active', ?, ?)`,
        [projectId, ad_group_name.trim(), u.sam, u.display, u.dept,
         removalMode, resolvedExpiresAt, null, actor(req)]
      );
      grantRows.push({ grantId: gr.insertId, sam: u.sam, display: u.display });
    }

    await audit(conn, {
      project_id: projectId,
      action: 'project_created',
      actor: actor(req),
      details: { name, ad_group_name, user_count: cleanUsers.length, permanent: isPermanent, expires_at: resolvedExpiresAt }
    });

    await conn.commit();
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    conn.release();
    if (err && err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'A project with that name already exists' });
    return res.status(500).json({ error: err.message });
  }
  conn.release();

  // 4. WinRM AD adds (post-commit so DB is preserved even if AD fails)
  const adActions = [];
  for (const gr of grantRows) {
    // reference-count: other active grants for same user+group?
    let alreadyTracked = false;
    try {
      const [refs] = await pool.query(
        `SELECT COUNT(*) AS c FROM user_project_grants
         WHERE user_sam=? AND ad_group_name=? AND status='active' AND id<>?`,
        [gr.sam, ad_group_name.trim(), gr.grantId]
      );
      alreadyTracked = refs[0].c > 0;
    } catch (_) {}

    if (alreadyTracked) {
      await pool.query(`UPDATE user_project_grants SET ad_action_on_add='skipped_already_member' WHERE id=?`, [gr.grantId]);
      await audit(pool, { project_id: projectId, grant_id: gr.grantId, action: 'ad_skip', actor: actor(req),
                          details: { reason: 'other active grant exists' } });
      adActions.push({ user_sam: gr.sam, action: 'skipped_already_member', message: 'Another active grant covers this user' });
      continue;
    }

    try {
      const r = await runManageGroups({ samAccountName: gr.sam, addGroups: [ad_group_name.trim()] });
      const addEntry = (r.added || []).find(x => x.group === ad_group_name.trim());
      let act, msg = null;
      if (addEntry && addEntry.success) {
        act = /already a member/i.test(addEntry.message || '') ? 'skipped_already_member' : 'added';
      } else {
        act = 'failed';
        msg = (addEntry && addEntry.message) || 'AD add reported failure';
      }
      await pool.query(`UPDATE user_project_grants SET ad_action_on_add=? WHERE id=?`, [act, gr.grantId]);
      await audit(pool, { project_id: projectId, grant_id: gr.grantId, action: 'ad_add', actor: actor(req),
                          details: { ad_group_name, user_sam: gr.sam, result: r } });
      adActions.push({ user_sam: gr.sam, action: act, message: msg });
    } catch (err) {
      await pool.query(`UPDATE user_project_grants SET ad_action_on_add='failed' WHERE id=?`, [gr.grantId]);
      await audit(pool, { project_id: projectId, grant_id: gr.grantId, action: 'ad_add', actor: actor(req),
                          details: { ad_group_name, user_sam: gr.sam, error: err.message } });
      adActions.push({ user_sam: gr.sam, action: 'failed', message: err.message });
    }
  }

  const [created] = await pool.query('SELECT * FROM user_projects WHERE id=?', [projectId]);
  return res.status(201).json({
    project: created[0],
    ad_group_name: ad_group_name.trim(),
    grants_created: grantRows.length,
    ad_actions: adActions,
  });
});

// ═══════════════════════════════════════════════════════════════════
// PHASE2_MARKER_v1 — Add Members / Audit endpoints / Digest send-test
// ═══════════════════════════════════════════════════════════════════

// POST /projects/:id/add-members — add N users to existing project
// Inherits project's ad_group_name + removal_mode + expires_at
router.post('/projects/:id/add-members', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { users } = req.body || {};
  if (!id) return res.status(400).json({ error: 'Invalid project id' });
  if (!Array.isArray(users) || users.length === 0) return res.status(400).json({ error: 'users[] required' });
  if (users.length > 100) return res.status(400).json({ error: 'Max 100 users per add' });

  // clean users
  const cleanUsers = [];
  for (const u of users) {
    if (!u || typeof u !== 'object') continue;
    const sam = String(u.sam || u.samAccountName || '').trim();
    if (!sam) continue;
    cleanUsers.push({ sam, display: u.display || u.displayName || null, dept: u.dept || u.department || null });
  }
  if (!cleanUsers.length) return res.status(400).json({ error: 'No valid users' });

  const conn = await pool.getConnection();
  let project, groupName, resolvedExpiresAt, removalMode;
  const grantRows = [];
  try {
    await conn.beginTransaction();

    const [pRows] = await conn.query('SELECT * FROM user_projects WHERE id=?', [id]);
    if (!pRows.length) { await conn.rollback(); return res.status(404).json({ error: 'Project not found' }); }
    project = pRows[0];
    if (project.status === 'closed') {
      await conn.rollback(); return res.status(409).json({ error: 'Project is closed' });
    }

    // Find the (single) linked group for this project
    const [gRows] = await conn.query('SELECT ad_group_name FROM user_project_groups WHERE project_id=? ORDER BY id LIMIT 1', [id]);
    if (!gRows.length) { await conn.rollback(); return res.status(400).json({ error: 'Project has no AD group linked' }); }
    groupName = gRows[0].ad_group_name;

    removalMode = project.default_removal_mode || 'auto';
    resolvedExpiresAt = null;
    if (removalMode !== 'permanent' && project.planned_end_date) {
      resolvedExpiresAt = new Date(project.planned_end_date + 'T23:59:59').toISOString().slice(0,19).replace('T',' ');
    }

    for (const u of cleanUsers) {
      // Reactivate existing row if present, else insert
      const [existing] = await conn.query(
        `SELECT id, status FROM user_project_grants WHERE project_id=? AND ad_group_name=? AND user_sam=?`,
        [id, groupName, u.sam]
      );
      if (existing.length) {
        if (existing[0].status === 'active') {
          grantRows.push({ grantId: existing[0].id, sam: u.sam, display: u.display, reactivated: false, existing: true });
          continue;
        }
        await conn.query(
          `UPDATE user_project_grants SET status='active', removal_mode=?, expires_at=?, granted_by=?, granted_at=CURRENT_TIMESTAMP,
                                          removed_by=NULL, removed_at=NULL, ad_action_on_remove=NULL
           WHERE id=?`,
          [removalMode, resolvedExpiresAt, actor(req), existing[0].id]
        );
        grantRows.push({ grantId: existing[0].id, sam: u.sam, display: u.display, reactivated: true });
      } else {
        const [ins] = await conn.query(
          `INSERT INTO user_project_grants (project_id, ad_group_name, user_sam, user_display_name, user_dept,
                                            removal_mode, expires_at, status, granted_by)
           VALUES (?,?,?,?,?,?,?, 'active', ?)`,
          [id, groupName, u.sam, u.display, u.dept, removalMode, resolvedExpiresAt, actor(req)]
        );
        grantRows.push({ grantId: ins.insertId, sam: u.sam, display: u.display, reactivated: false });
      }
    }

    await audit(conn, { project_id: id, action: 'members_added', actor: actor(req),
                        details: { user_count: cleanUsers.length, ad_group_name: groupName } });
    await conn.commit();
  } catch (e) {
    try { await conn.rollback(); } catch(_){}
    conn.release();
    return res.status(500).json({ error: e.message });
  }
  conn.release();

  // WinRM adds
  const adActions = [];
  for (const gr of grantRows) {
    // reference-count check
    let alreadyTracked = false;
    try {
      const [refs] = await pool.query(
        `SELECT COUNT(*) AS c FROM user_project_grants
         WHERE user_sam=? AND ad_group_name=? AND status='active' AND id<>?`,
        [gr.sam, groupName, gr.grantId]
      );
      alreadyTracked = refs[0].c > 0;
    } catch(_){}

    if (alreadyTracked || gr.existing) {
      await pool.query(`UPDATE user_project_grants SET ad_action_on_add='skipped_already_member' WHERE id=?`, [gr.grantId]);
      await audit(pool, { project_id: id, grant_id: gr.grantId, action: 'ad_skip', actor: actor(req),
                          details: { reason: gr.existing ? 'grant already active in this project' : 'other active grant exists' } });
      adActions.push({ user_sam: gr.sam, action: 'skipped_already_member', message: null });
      continue;
    }

    try {
      const r = await runManageGroups({ samAccountName: gr.sam, addGroups: [groupName] });
      const addEntry = (r.added || []).find(x => x.group === groupName);
      let act, msg = null;
      if (addEntry && addEntry.success) {
        act = /already a member/i.test(addEntry.message || '') ? 'skipped_already_member' : 'added';
      } else {
        act = 'failed';
        msg = (addEntry && addEntry.message) || 'AD add reported failure';
      }
      await pool.query(`UPDATE user_project_grants SET ad_action_on_add=? WHERE id=?`, [act, gr.grantId]);
      await audit(pool, { project_id: id, grant_id: gr.grantId, action: 'ad_add', actor: actor(req),
                          details: { ad_group_name: groupName, user_sam: gr.sam, result: r } });
      adActions.push({ user_sam: gr.sam, action: act, message: msg });
    } catch (e) {
      await pool.query(`UPDATE user_project_grants SET ad_action_on_add='failed' WHERE id=?`, [gr.grantId]);
      await audit(pool, { project_id: id, grant_id: gr.grantId, action: 'ad_add', actor: actor(req),
                          details: { ad_group_name: groupName, user_sam: gr.sam, error: e.message } });
      adActions.push({ user_sam: gr.sam, action: 'failed', message: e.message });
    }
  }

  res.json({ project_id: id, ad_group_name: groupName, grants_created: grantRows.length, ad_actions: adActions });
});

// GET /audit/feed — global audit stream with project name joined
router.get('/audit/feed', rbac.requirePage('user-projects','read'), async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit || '100', 10), 500);
  const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);
  try {
    const [rows] = await pool.query(`
      SELECT a.id, a.created_at, a.action, a.actor, a.details, a.project_id, a.grant_id, p.name AS project_name
      FROM user_project_audit a
      LEFT JOIN user_projects p ON p.id = a.project_id
      ORDER BY a.id DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);
    res.json({ audit: rows, limit, offset });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PHASE3_MARKER_v1
// GET /audit/by-group — true audit: LDAP AD reality vs our grants
// Returns 3 buckets per preset group:
//   tracked : user is in AD AND in our active grants (with our metadata)
//   drift   : user is in AD but NOT in our grants (manual/external add)
//   stale   : user is in our active grants but NOT in AD (external removal)
router.get('/audit/by-group', rbac.requirePage('user-projects','read'), async (req, res) => {
  const PRESET = ['SaaS-ZIA-AI-Read', 'SaaS-ZIA-AI-RD', 'SaaS-ZIA-AI-Exec-Read', 'SaaS-ZIA-AI-RD-UploadAccess'];

  let ldapClient;
  try {
    // Pull all grants for preset groups in one query
    const [grantRows] = await pool.query(`
      SELECT g.id, g.ad_group_name, g.user_sam, g.user_display_name, g.user_dept, g.expires_at,
             g.granted_at, g.granted_by, g.project_id, p.name AS project_name
      FROM user_project_grants g
      LEFT JOIN user_projects p ON p.id = g.project_id
      WHERE g.status='active' AND g.ad_group_name IN (?,?,?,?)
      ORDER BY g.ad_group_name, g.user_sam
    `, PRESET);

    // Index grants by group -> lowercase sam
    const grantsByGroup = {};
    for (const g of PRESET) grantsByGroup[g] = {};
    for (const r of grantRows) {
      grantsByGroup[r.ad_group_name][String(r.user_sam).toLowerCase()] = r;
    }

    // Open LDAP once
    ldapClient = await createLdapClient();

    const buckets = {};
    const errors = {};

    for (const groupName of PRESET) {
      buckets[groupName] = { tracked: [], drift: [], stale: [] };

      // 1. Find the group and get its member DNs
      let memberDns = [];
      try {
        const groupResults = await ldapSearch(
          ldapClient,
          LDAP_BASE_DN,
          `(&(objectClass=group)(cn=${groupName.replace(/[()\\*\u0000]/g, '')}))`,
          ['distinguishedName', 'member'],
          5
        );
        if (!groupResults.length) {
          errors[groupName] = 'Group not found in AD';
          // Everything in grants is stale
          for (const sam of Object.keys(grantsByGroup[groupName])) {
            buckets[groupName].stale.push(grantsByGroup[groupName][sam]);
          }
          continue;
        }
        let m = groupResults[0].member || [];
        if (!Array.isArray(m)) m = [m];
        memberDns = m;
      } catch (e) {
        errors[groupName] = 'AD query failed: ' + e.message;
        continue;
      }

      if (!memberDns.length) {
        // AD group empty -> everything in grants is stale
        for (const sam of Object.keys(grantsByGroup[groupName])) {
          buckets[groupName].stale.push(grantsByGroup[groupName][sam]);
        }
        continue;
      }

      // 2. Resolve DNs to sAMAccountNames in one query (OR filter)
      const dnFilters = memberDns.map(dn => `(distinguishedName=${dn.replace(/[()\\*\u0000]/g, '')})`).join('');
      const memberResults = await ldapSearch(
        ldapClient,
        LDAP_BASE_DN,
        `(|${dnFilters})`,
        ['sAMAccountName', 'displayName', 'department', 'mail', 'distinguishedName', 'userAccountControl'],
        Math.max(memberDns.length, 100)
      );

      const adSet = new Set();
      const adDetails = {};
      for (const u of memberResults) {
        const sam = u.sAMAccountName;
        if (!sam) continue;
        const key = String(sam).toLowerCase();
        adSet.add(key);
        adDetails[key] = {
          user_sam: sam,
          user_display_name: u.displayName || '',
          user_dept: u.department || '',
          mail: u.mail || '',
          enabled: u.userAccountControl ? !(parseInt(u.userAccountControl, 10) & 0x0002) : null,
        };
      }

      const grantSet = new Set(Object.keys(grantsByGroup[groupName]));

      // Tracked: in both
      for (const key of adSet) {
        if (grantSet.has(key)) {
          buckets[groupName].tracked.push({
            ...grantsByGroup[groupName][key],
            ad_present: true,
            ad_enabled: adDetails[key].enabled,
          });
        }
      }
      // Drift: in AD, not in grants
      for (const key of adSet) {
        if (!grantSet.has(key)) {
          buckets[groupName].drift.push({
            ...adDetails[key],
            ad_group_name: groupName,
          });
        }
      }
      // Stale: in grants, not in AD
      for (const key of grantSet) {
        if (!adSet.has(key)) {
          buckets[groupName].stale.push({
            ...grantsByGroup[groupName][key],
            ad_present: false,
          });
        }
      }

      // Sort each bucket
      buckets[groupName].tracked.sort((a,b)=>String(a.user_sam).localeCompare(b.user_sam));
      buckets[groupName].drift.sort((a,b)=>String(a.user_sam).localeCompare(b.user_sam));
      buckets[groupName].stale.sort((a,b)=>String(a.user_sam).localeCompare(b.user_sam));
    }

    try { closeLdap(ldapClient); } catch (_) {}
    res.json({ groups: PRESET, buckets, errors });
  } catch (e) {
    try { if (ldapClient) closeLdap(ldapClient); } catch (_) {}
    res.status(500).json({ error: e.message });
  }
});

// POST /digest/send-test — trigger digest job with --test flag for current user
router.post('/digest/send-test', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const to = (req.body && req.body.to) ? String(req.body.to).trim() : actor(req);
  if (!to || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) {
    return res.status(400).json({ error: 'Invalid recipient email' });
  }
  const { spawn } = require('child_process');
  const child = spawn('node', [path.join(__dirname, 'user-project-digest-job.js'), '--test', to], {
    cwd: __dirname,
    env: process.env,
    detached: false,
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', d => stdout += d.toString());
  child.stderr.on('data', d => stderr += d.toString());
  const timeout = setTimeout(() => { try { child.kill('SIGKILL'); } catch(_){} }, 45000);
  child.on('close', code => {
    clearTimeout(timeout);
    SA.record(rbac, req, 'user-projects', code === 0 ? 'settings_test_sent' : 'settings_test_failed',
      SA.entry({ what: 'digest', op: 'test', subject: to, extra: { ok: code === 0, exit_code: code } }));
    if (code === 0) return res.json({ ok: true, to, stdout: stdout.slice(-2000) });
    return res.status(500).json({ ok: false, code, stdout: stdout.slice(-2000), stderr: stderr.slice(-2000) });
  });
  child.on('error', e => {
    clearTimeout(timeout);
    SA.record(rbac, req, 'user-projects', 'settings_test_failed',
      SA.entry({ what: 'digest', op: 'test', subject: to, extra: { ok: false, exit_code: null } }));
    res.status(500).json({ error: e.message });
  });
});

// POST /projects/:id/attach-grant — adopt an existing AD-drift user into a project
// No WinRM call: user is already in the group in AD.
router.post('/projects/:id/attach-grant', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const projectId = parseInt(req.params.id, 10);
  const { user_sam, user_display_name, user_dept, ad_group_name } = req.body || {};
  if (!projectId) return res.status(400).json({ error: 'Invalid project id' });
  if (!user_sam || typeof user_sam !== 'string' || !user_sam.trim()) return res.status(400).json({ error: 'user_sam required' });
  if (!ad_group_name || typeof ad_group_name !== 'string' || !ad_group_name.trim()) return res.status(400).json({ error: 'ad_group_name required' });

  const sam = user_sam.trim();
  const groupName = ad_group_name.trim();

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [pRows] = await conn.query('SELECT * FROM user_projects WHERE id=?', [projectId]);
    if (!pRows.length) { await conn.rollback(); return res.status(404).json({ error: 'Project not found' }); }
    const project = pRows[0];
    if (project.status === 'closed') { await conn.rollback(); return res.status(409).json({ error: 'Project is closed' }); }

    // Confirm this project actually uses that group
    const [gRows] = await conn.query('SELECT id FROM user_project_groups WHERE project_id=? AND ad_group_name=?', [projectId, groupName]);
    if (!gRows.length) { await conn.rollback(); return res.status(400).json({ error: 'Selected project does not use that AD group' }); }

    // Inherit removal_mode + expiry
    const removalMode = project.default_removal_mode || 'auto';
    let resolvedExpiresAt = null;
    if (removalMode !== 'permanent' && project.planned_end_date) {
      resolvedExpiresAt = new Date(project.planned_end_date + 'T23:59:59').toISOString().slice(0,19).replace('T',' ');
    }

    // Reactivate existing row or insert new
    const [existing] = await conn.query(
      `SELECT id, status FROM user_project_grants WHERE project_id=? AND ad_group_name=? AND user_sam=?`,
      [projectId, groupName, sam]
    );
    let grantId;
    if (existing.length) {
      if (existing[0].status === 'active') {
        await conn.rollback();
        return res.status(409).json({ error: 'This user already has an active grant on this project + group' });
      }
      await conn.query(
        `UPDATE user_project_grants SET status='active', removal_mode=?, expires_at=?, granted_by=?, granted_at=CURRENT_TIMESTAMP,
                                        removed_by=NULL, removed_at=NULL, ad_action_on_remove=NULL,
                                        ad_action_on_add='skipped_already_member',
                                        notes=COALESCE(notes,'')
         WHERE id=?`,
        [removalMode, resolvedExpiresAt, actor(req), existing[0].id]
      );
      grantId = existing[0].id;
    } else {
      const [ins] = await conn.query(
        `INSERT INTO user_project_grants (project_id, ad_group_name, user_sam, user_display_name, user_dept,
                                          removal_mode, expires_at, status, ad_action_on_add, notes, granted_by)
         VALUES (?,?,?,?,?,?,?, 'active', 'skipped_already_member', ?, ?)`,
        [projectId, groupName, sam, user_display_name || null, user_dept || null,
         removalMode, resolvedExpiresAt, 'Adopted from AD drift by ' + actor(req), actor(req)]
      );
      grantId = ins.insertId;
    }

    await audit(conn, {
      project_id: projectId, grant_id: grantId, action: 'drift_adopted',
      actor: actor(req),
      details: { ad_group_name: groupName, user_sam: sam, source: 'audit_by_group_ui' }
    });

    await conn.commit();
    res.json({ ok: true, grant_id: grantId, project_id: projectId, user_sam: sam, ad_group_name: groupName });
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

// PHASE4_MARKER_BE
// POST /projects/:id/archive — close project, revoke active grants, remove
// non-permanent users from AD with reference-counting. Permanent grants stay in AD.
router.post('/projects/:id/archive', rbac.requirePage('user-projects','admin'), async (req, res) => {
  const projectId = parseInt(req.params.id, 10);
  if (!projectId) return res.status(400).json({ error: 'Invalid project id' });

  const conn = await pool.getConnection();
  let project;
  let activeGrants = [];

  try {
    await conn.beginTransaction();
    const [pRows] = await conn.query('SELECT * FROM user_projects WHERE id=?', [projectId]);
    if (!pRows.length) { await conn.rollback(); return res.status(404).json({ error: 'Project not found' }); }
    project = pRows[0];
    if (project.status === 'closed') { await conn.rollback(); return res.status(409).json({ error: 'Project is already archived' }); }

    // Pull all active grants for this project
    const [grants] = await conn.query(
      `SELECT id, user_sam, user_display_name, ad_group_name, removal_mode FROM user_project_grants
       WHERE project_id=? AND status='active'`, [projectId]);
    activeGrants = grants;

    // Mark project as closed
    await conn.query(
      `UPDATE user_projects SET status='closed', updated_by=? WHERE id=?`,
      [actor(req), projectId]);

    // Audit the archive itself
    await audit(conn, {
      project_id: projectId,
      action: 'project_archived',
      actor: actor(req),
      details: { active_grants: activeGrants.length, project_removal_mode: project.default_removal_mode }
    });

    await conn.commit();
  } catch (e) {
    try { await conn.rollback(); } catch(_){}
    conn.release();
    return res.status(500).json({ error: e.message });
  }
  conn.release();

  // Process each grant post-commit so a WinRM failure doesn't lose the archive state
  const results = [];
  for (const g of activeGrants) {
    const isPermanent = g.removal_mode === 'permanent';

    if (isPermanent) {
      // Just mark as revoked in DB but leave AD alone
      await pool.query(
        `UPDATE user_project_grants
         SET status='revoked', removed_by=?, removed_at=CURRENT_TIMESTAMP,
             ad_action_on_remove='manual_revoke'
         WHERE id=?`,
        [actor(req), g.id]);
      await audit(pool, {
        project_id: projectId, grant_id: g.id, action: 'revoked', actor: actor(req),
        details: { reason: 'project_archived', ad_removal_skipped: true, mode: 'permanent' }
      });
      results.push({ user_sam: g.user_sam, action: 'kept_in_ad_permanent', message: 'Permanent grant — stayed in AD' });
      continue;
    }

    // Reference-count: any OTHER active grant for this user+group?
    let otherActive = 0;
    try {
      const [refs] = await pool.query(
        `SELECT COUNT(*) AS c FROM user_project_grants
         WHERE user_sam=? AND ad_group_name=? AND status='active' AND id<>?`,
        [g.user_sam, g.ad_group_name, g.id]);
      otherActive = refs[0].c;
    } catch(_){}

    if (otherActive > 0) {
      // Another project still keeps them in group; DB-only revoke, no WinRM
      await pool.query(
        `UPDATE user_project_grants
         SET status='revoked', removed_by=?, removed_at=CURRENT_TIMESTAMP,
             ad_action_on_remove='skipped_other_active_grants'
         WHERE id=?`,
        [actor(req), g.id]);
      await audit(pool, {
        project_id: projectId, grant_id: g.id, action: 'revoked', actor: actor(req),
        details: { reason: 'project_archived', ad_removal_skipped: true, other_active_grants: otherActive }
      });
      results.push({ user_sam: g.user_sam, action: 'skipped_other_active_grants', message: `Still active via ${otherActive} other project(s)` });
      continue;
    }

    // Full AD remove
    try {
      const r = await runManageGroups({ samAccountName: g.user_sam, removeGroups: [g.ad_group_name] });
      const rem = (r.removed || []).find(x => x.group === g.ad_group_name);
      const success = rem && rem.success;
      await pool.query(
        `UPDATE user_project_grants
         SET status='revoked', removed_by=?, removed_at=CURRENT_TIMESTAMP,
             ad_action_on_remove=?
         WHERE id=?`,
        [actor(req), success ? 'removed' : 'failed', g.id]);
      await audit(pool, {
        project_id: projectId, grant_id: g.id, action: 'ad_remove', actor: actor(req),
        details: { ad_group_name: g.ad_group_name, user_sam: g.user_sam, result: r, reason: 'project_archived' }
      });
      results.push({ user_sam: g.user_sam, action: success ? 'removed' : 'failed', message: rem ? rem.message : null });
    } catch (e) {
      await pool.query(
        `UPDATE user_project_grants
         SET status='revoked', removed_by=?, removed_at=CURRENT_TIMESTAMP,
             ad_action_on_remove='failed'
         WHERE id=?`,
        [actor(req), g.id]);
      await audit(pool, {
        project_id: projectId, grant_id: g.id, action: 'ad_remove', actor: actor(req),
        details: { ad_group_name: g.ad_group_name, user_sam: g.user_sam, error: e.message, reason: 'project_archived' }
      });
      results.push({ user_sam: g.user_sam, action: 'failed', message: e.message });
    }
  }

  res.json({
    project_id: projectId,
    status: 'closed',
    grants_processed: activeGrants.length,
    ad_actions: results,
  });
});

module.exports = router;
