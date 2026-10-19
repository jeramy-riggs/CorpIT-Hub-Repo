/**
 * Users Routes — user listing, search, detail, and filtered views.
 */
const express = require('express');
const router = express.Router();
const { getDb } = require('../db/database');
const logger = require('../utils/logger');

// GET /api/users — paginated user list with optional filters
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const { status, search, sort = 'display_name', order = 'ASC', page = 1, limit = 50 } = req.query;

    const allowedSorts = ['display_name', 'login', 'email', 'status', 'last_login', 'last_password_change', 'password_expiry_estimate', 'created'];
    const col = allowedSorts.includes(sort) ? sort : 'display_name';
    const dir = order.toUpperCase() === 'DESC' ? 'DESC' : 'ASC';
    const offset = (Math.max(1, parseInt(page)) - 1) * parseInt(limit);

    let where = [];
    let params = [];

    if (status) {
      where.push('status = ?');
      params.push(status);
    }
    if (search) {
      where.push("(login LIKE ? OR email LIKE ? OR display_name LIKE ?)");
      const s = `%${search}%`;
      params.push(s, s, s);
    }

    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const total = db.prepare(`SELECT COUNT(*) as c FROM users ${whereClause}`).get(...params).c;
    const rows = db.prepare(
      `SELECT id, login, email, display_name, status, last_login, last_password_change,
              password_expiry_estimate, locked_out, department, title, created
       FROM users ${whereClause}
       ORDER BY ${col} ${dir}
       LIMIT ? OFFSET ?`
    ).all(...params, parseInt(limit), offset);

    res.json({ total, page: parseInt(page), limit: parseInt(limit), users: rows });
  } catch (err) {
    logger.error(`Users list error: ${err.message}`);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

// GET /api/users/status-breakdown
router.get('/status-breakdown', (_req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare('SELECT status, COUNT(*) as count FROM users GROUP BY status ORDER BY count DESC').all();
    res.json(rows);
  } catch (err) {
    logger.error(`Status breakdown error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

// GET /api/users/:id
router.get('/:id', (req, res) => {
  try {
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Get their app assignments
    const apps = db.prepare(
      `SELECT a.app_id, ap.label, ap.logo_url, a.status, a.last_sync
       FROM app_assignments a
       JOIN applications ap ON ap.id = a.app_id
       WHERE a.user_id = ?`
    ).all(req.params.id);

    // Get recent logs
    const logs = db.prepare(
      `SELECT event_type, display_message, published, outcome, client_ip
       FROM system_logs WHERE actor_id = ? ORDER BY published DESC LIMIT 20`
    ).all(req.params.id);

    res.json({ ...user, apps, recentActivity: logs });
  } catch (err) {
    logger.error(`User detail error: ${err.message}`);
    res.status(500).json({ error: 'Failed to load user' });
  }
});

// GET /api/users/filter/inactive — active status but no login in 30+ days
router.get('/filter/inactive', (_req, res) => {
  try {
    const db = getDb();
    const threshold = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const rows = db.prepare(
      `SELECT id, login, email, display_name, last_login, department
       FROM users
       WHERE status = 'ACTIVE' AND (last_login IS NULL OR last_login < ?)
       ORDER BY last_login ASC
       LIMIT 100`
    ).all(threshold);
    res.json(rows);
  } catch (err) {
    logger.error(`Inactive filter error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

module.exports = router;
