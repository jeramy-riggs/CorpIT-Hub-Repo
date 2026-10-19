const express = require('express');
const router = express.Router();
const { getDb } = require('../db/database');
const okta = require('../services/okta-client');
const { syncAll } = require('../services/sync-service');
const logger = require('../utils/logger');

// GET /api/health
router.get('/', (_req, res) => {
  const db = getDb();
  const lastSync = db.prepare(
    "SELECT * FROM sync_status WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1"
  ).get();
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const appCount = db.prepare('SELECT COUNT(*) as c FROM applications').get().c;

  res.json({
    status: 'ok',
    uptime: process.uptime(),
    cached: { users: userCount, applications: appCount },
    lastSync: lastSync || null,
  });
});

// GET /api/health/okta-test — verify Okta connectivity
router.get('/okta-test', async (_req, res) => {
  try {
    const org = await okta.testConnection();
    res.json({ connected: true, org: org.name, subdomain: org.subdomain });
  } catch (err) {
    logger.error(`Okta test failed: ${err.message}`);
    res.status(502).json({ connected: false, error: err.message });
  }
});

// POST /api/health/sync — trigger manual sync
router.post('/sync', async (_req, res) => {
  try {
    const results = await syncAll();
    res.json({ success: true, results });
  } catch (err) {
    logger.error(`Manual sync error: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/health/sync-history
router.get('/sync-history', (_req, res) => {
  const db = getDb();
  const rows = db.prepare(
    'SELECT * FROM sync_status ORDER BY id DESC LIMIT 30'
  ).all();
  res.json(rows);
});

module.exports = router;
