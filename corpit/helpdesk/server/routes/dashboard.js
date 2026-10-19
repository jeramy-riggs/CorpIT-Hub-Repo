/**
 * Dashboard Routes — summary cards, KPIs, and overview data.
 */
const express = require('express');
const router = express.Router();
const { getDb } = require('../db/database');
const logger = require('../utils/logger');

const UNUSED_DAYS = parseInt(process.env.UNUSED_APP_THRESHOLD_DAYS || '90', 10);
const PW_WARN_DAYS = parseInt(process.env.PASSWORD_EXPIRY_WARNING_DAYS || '14', 10);

// GET /api/dashboard/summary — top-level KPI cards
router.get('/summary', (_req, res) => {
  try {
    const db = getDb();
    const now = new Date().toISOString();
    const warnDate = new Date(Date.now() + PW_WARN_DAYS * 86_400_000).toISOString();

    const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
    const activeUsers = db.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'ACTIVE'").get().c;
    const lockedOut = db.prepare('SELECT COUNT(*) as c FROM users WHERE locked_out = 1').get().c;
    const suspended = db.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'SUSPENDED'").get().c;
    const deprovisioned = db.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'DEPROVISIONED'").get().c;
    const pwExpiringSoon = db.prepare(
      'SELECT COUNT(*) as c FROM users WHERE password_expiry_estimate IS NOT NULL AND password_expiry_estimate BETWEEN ? AND ?'
    ).get(now, warnDate).c;
    const pwExpired = db.prepare(
      'SELECT COUNT(*) as c FROM users WHERE password_expiry_estimate IS NOT NULL AND password_expiry_estimate < ?'
    ).get(now).c;
    const totalApps = db.prepare('SELECT COUNT(*) as c FROM applications').get().c;
    const neverLoggedIn = db.prepare("SELECT COUNT(*) as c FROM users WHERE last_login IS NULL AND status = 'ACTIVE'").get().c;

    // Inactive users (active status but no login in 30+ days)
    const inactiveThreshold = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const inactiveUsers = db.prepare(
      "SELECT COUNT(*) as c FROM users WHERE status = 'ACTIVE' AND (last_login IS NULL OR last_login < ?)"
    ).get(inactiveThreshold).c;

    // Failed logins in last 24h
    const since24h = new Date(Date.now() - 86_400_000).toISOString();
    const failedLogins24h = db.prepare(
      "SELECT COUNT(*) as c FROM system_logs WHERE event_type = 'user.session.start' AND outcome = 'FAILURE' AND published > ?"
    ).get(since24h).c;

    // Last sync info
    const lastSync = db.prepare(
      "SELECT completed_at FROM sync_status WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1"
    ).get();

    res.json({
      totalUsers, activeUsers, lockedOut, suspended, deprovisioned,
      pwExpiringSoon, pwExpired, totalApps, neverLoggedIn,
      inactiveUsers, failedLogins24h,
      lastSync: lastSync?.completed_at || null,
    });
  } catch (err) {
    logger.error(`Dashboard summary error: ${err.message}`);
    res.status(500).json({ error: 'Failed to load dashboard summary' });
  }
});

// GET /api/dashboard/recent-lockouts
router.get('/recent-lockouts', (_req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(
      "SELECT id, login, email, display_name, status_changed FROM users WHERE locked_out = 1 ORDER BY status_changed DESC LIMIT 25"
    ).all();
    res.json(rows);
  } catch (err) {
    logger.error(`Recent lockouts error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

// GET /api/dashboard/pw-expiring
router.get('/pw-expiring', (_req, res) => {
  try {
    const db = getDb();
    const now = new Date().toISOString();
    const warnDate = new Date(Date.now() + PW_WARN_DAYS * 86_400_000).toISOString();
    const rows = db.prepare(
      `SELECT id, login, email, display_name, last_password_change, password_expiry_estimate
       FROM users
       WHERE password_expiry_estimate IS NOT NULL AND password_expiry_estimate BETWEEN ? AND ?
       ORDER BY password_expiry_estimate ASC
       LIMIT 50`
    ).all(now, warnDate);
    res.json(rows);
  } catch (err) {
    logger.error(`PW expiring error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

// GET /api/dashboard/failed-logins
router.get('/failed-logins', (_req, res) => {
  try {
    const db = getDb();
    const since = new Date(Date.now() - 7 * 86_400_000).toISOString();
    const rows = db.prepare(
      `SELECT actor_login, client_ip, client_geo, published, display_message
       FROM system_logs
       WHERE event_type = 'user.session.start' AND outcome = 'FAILURE' AND published > ?
       ORDER BY published DESC
       LIMIT 100`
    ).all(since);
    res.json(rows);
  } catch (err) {
    logger.error(`Failed logins error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

// GET /api/dashboard/login-trend — daily login counts (last 7 days)
router.get('/login-trend', (_req, res) => {
  try {
    const db = getDb();
    const since = new Date(Date.now() - 7 * 86_400_000).toISOString();
    const rows = db.prepare(
      `SELECT DATE(published) as day,
              SUM(CASE WHEN outcome = 'SUCCESS' THEN 1 ELSE 0 END) as success,
              SUM(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END) as failure
       FROM system_logs
       WHERE event_type = 'user.session.start' AND published > ?
       GROUP BY DATE(published)
       ORDER BY day ASC`
    ).all(since);
    res.json(rows);
  } catch (err) {
    logger.error(`Login trend error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

// GET /api/dashboard/top-events — most frequent event types
router.get('/top-events', (_req, res) => {
  try {
    const db = getDb();
    const since = new Date(Date.now() - 7 * 86_400_000).toISOString();
    const rows = db.prepare(
      `SELECT event_type, COUNT(*) as count
       FROM system_logs WHERE published > ?
       GROUP BY event_type
       ORDER BY count DESC
       LIMIT 15`
    ).all(since);
    res.json(rows);
  } catch (err) {
    logger.error(`Top events error: ${err.message}`);
    res.status(500).json({ error: 'Failed' });
  }
});

module.exports = router;
