'use strict';
const express      = require('express');
const router       = express.Router();
const slackService = require('../services/slack-service');
const logger       = require('../utils/logger');

router.get('/status', (_req, res) => {
  res.json({
    enabled:    process.env.SLACK_ALERTS_ENABLED === 'true',
    configured: !!process.env.SLACK_WEBHOOK_URL,
  });
});

router.post('/test-lockout', async (_req, res) => {
  try {
    await slackService.alertUserLockout({ display_name: 'Test User', login: 'testuser@nrpi.local', email: 'testuser@nrpi.local', client_ip: '192.168.1.100' });
    res.json({ success: true, message: 'Test lockout alert sent to Slack' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/test-spike', async (_req, res) => {
  try {
    await slackService.alertFailedLoginSpike({ count: 15, windowMinutes: 15, topIPs: ['10.0.0.42 (8x)', '10.0.0.77 (4x)', '192.168.1.55 (3x)'] });
    res.json({ success: true, message: 'Test spike alert sent to Slack' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/test-sync-failure', async (_req, res) => {
  try {
    await slackService.alertSyncFailure({ syncType: 'Okta Users Sync', error: 'Connection timeout after 30000ms', lastSuccess: new Date(Date.now() - 3_600_000).toLocaleString() });
    res.json({ success: true, message: 'Test sync failure alert sent to Slack' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
