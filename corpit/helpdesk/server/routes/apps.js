/**
 * Applications Routes — SSO app usage insights.
 */
const express = require('express');
const router = express.Router();
const { getDb } = require('../db/database');
const logger = require('../utils/logger');

const UNUSED_DAYS = parseInt(process.env.UNUSED_APP_THRESHOLD_DAYS || '90', 10);

// GET /api/apps — all apps with user counts
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const { search, sort = 'assigned_user_count', order = 'DESC' } = req.query;

    const allowedSorts = ['label', 'assigned_user_count', 'status', 'sign_on_mode', 'created'];
    const col = allowedSorts.includes(sort) ? sort : 'assigned_user_count';
    const dir = order.toUpperCase() === 'DESC' ? 'DESC' : 'ASC';

    let where = '';
    let params = [];
    if (search) {
      where = "WHERE (label LIKE ? OR name LIKE ?)";
      params.push(`%${search}%`, `%${search}%`);
    }

    const rows = db.prepare(
      `SELECT a.id, a.label, a.name, a.status, a.sign_on_mode, a.logo_url,
              a.assigned_user_count, a.created, a.last_updated,
              (SELECT COUNT(*) FROM app_assignments aa WHERE aa.app_id = a.id) as actual_user_count
       FROM applications a
       ${where}
       ORDER BY ${col} ${dir}`
    ).all(...params);

    res.json(rows);
  } catch (err) {
    logger.error(`Apps list error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

// GET /api/apps/usage-summary — most/least/unused apps
router.get('/usage-summary', (_req, res) => {
  try {
    const db = getDb();

    // Most used (by assigned users)
    const mostUsed = db.prepare(
      `SELECT id, label, logo_url, assigned_user_count, sign_on_mode
       FROM applications ORDER BY assigned_user_count DESC LIMIT 10`
    ).all();

    // Least used (> 0 users)
    const leastUsed = db.prepare(
      `SELECT id, label, logo_url, assigned_user_count, sign_on_mode
       FROM applications WHERE assigned_user_count > 0
       ORDER BY assigned_user_count ASC LIMIT 10`
    ).all();

    // Unused (0 assigned users)
    const unused = db.prepare(
      `SELECT id, label, logo_url, sign_on_mode, created
       FROM applications WHERE assigned_user_count = 0`
    ).all();

    // SSO app login activity from logs
    const since = new Date(Date.now() - UNUSED_DAYS * 86_400_000).toISOString();
    const appLoginActivity = db.prepare(
      `SELECT target_name as app_name, COUNT(*) as login_count,
              MAX(published) as last_access
       FROM system_logs
       WHERE event_type LIKE 'app.auth%' AND published > ?
       GROUP BY target_name
       ORDER BY login_count DESC`
    ).all(since);

    // Sign-on mode breakdown
    const signOnModes = db.prepare(
      `SELECT sign_on_mode, COUNT(*) as count FROM applications GROUP BY sign_on_mode ORDER BY count DESC`
    ).all();

    res.json({ mostUsed, leastUsed, unused, appLoginActivity, signOnModes });
  } catch (err) {
    logger.error(`App usage summary error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

// GET /api/apps/:id — app detail with assigned users
router.get('/:id', (req, res) => {
  try {
    const db = getDb();
    const app = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
    if (!app) return res.status(404).json({ error: 'Application not found' });

    const users = db.prepare(
      `SELECT aa.user_id, aa.user_login, aa.status, u.display_name, u.last_login
       FROM app_assignments aa
       LEFT JOIN users u ON u.id = aa.user_id
       WHERE aa.app_id = ?
       ORDER BY u.display_name ASC`
    ).all(req.params.id);

    res.json({ ...app, users });
  } catch (err) {
    logger.error(`App detail error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

module.exports = router;
