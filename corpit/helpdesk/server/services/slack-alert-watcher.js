'use strict';
const { getDb }    = require('../db/database');
const slackService = require('./slack-service');
const logger       = require('../utils/logger');

const POLL_INTERVAL_MS        = parseInt(process.env.SLACK_POLL_INTERVAL_MS       || '60000', 10);
const FAILED_LOGIN_WINDOW_MIN = parseInt(process.env.FAILED_LOGIN_WINDOW_MIN      || '15',    10);
const FAILED_LOGIN_THRESHOLD  = parseInt(process.env.FAILED_LOGIN_SPIKE_THRESHOLD || '10',    10);

const _alertedLockouts  = new Set();
let   _lastSpikeAlertAt = 0;
const SPIKE_COOLDOWN_MS = 30 * 60_000;

async function checkLockouts() {
  try {
    const db     = getDb();
    const locked = db.prepare(`SELECT id, login, email, display_name, status_changed FROM users WHERE locked_out = 1 ORDER BY status_changed DESC LIMIT 50`).all();
    for (const user of locked) {
      if (!_alertedLockouts.has(user.id)) {
        _alertedLockouts.add(user.id);
        const lastFailure = db.prepare(`SELECT client_ip FROM system_logs WHERE actor_id = ? AND event_type = 'user.session.start' AND outcome = 'FAILURE' ORDER BY published DESC LIMIT 1`).get(user.id);
        logger.info(`[Slack Watcher] Firing lockout alert for: ${user.login}`);
        await slackService.alertUserLockout({ ...user, client_ip: lastFailure?.client_ip || null });
      }
    }
    const lockedIds = new Set(locked.map(u => u.id));
    for (const id of _alertedLockouts) { if (!lockedIds.has(id)) _alertedLockouts.delete(id); }
  } catch (err) { logger.error(`[Slack Watcher] Lockout check error: ${err.message}`); }
}

async function checkFailedLoginSpike() {
  try {
    const now   = Date.now();
    const since = new Date(now - FAILED_LOGIN_WINDOW_MIN * 60_000).toISOString();
    const db    = getDb();
    const { count } = db.prepare(`SELECT COUNT(*) as count FROM system_logs WHERE event_type = 'user.session.start' AND outcome = 'FAILURE' AND published > ?`).get(since);
    if (count > FAILED_LOGIN_THRESHOLD) {
      if (now - _lastSpikeAlertAt < SPIKE_COOLDOWN_MS) return;
      _lastSpikeAlertAt = now;
      const topIPs = db.prepare(`SELECT client_ip, COUNT(*) as c FROM system_logs WHERE event_type = 'user.session.start' AND outcome = 'FAILURE' AND published > ? AND client_ip IS NOT NULL GROUP BY client_ip ORDER BY c DESC LIMIT 5`).all(since).map(r => `${r.client_ip} (${r.c}x)`);
      logger.info(`[Slack Watcher] Spike: ${count} failures in ${FAILED_LOGIN_WINDOW_MIN}m`);
      await slackService.alertFailedLoginSpike({ count, windowMinutes: FAILED_LOGIN_WINDOW_MIN, topIPs });
    }
  } catch (err) { logger.error(`[Slack Watcher] Spike check error: ${err.message}`); }
}

async function runChecks() {
  await checkLockouts();
  await checkFailedLoginSpike();
}

function startAlertWatcher() {
  if (process.env.SLACK_ALERTS_ENABLED !== 'true') { logger.info('[Slack Watcher] Disabled'); return; }
  logger.info(`[Slack Watcher] Started — polling every ${POLL_INTERVAL_MS / 1000}s`);
  runChecks();
  setInterval(runChecks, POLL_INTERVAL_MS);
}

module.exports = { startAlertWatcher };
