'use strict';
const fetch  = require('node-fetch');
const logger = require('../utils/logger');
const { SLACK_WEBHOOK_URL, SLACK_ALERTS_ENABLED = 'true', APP_BASE_URL = 'http://itam.nrpi.local' } = process.env;

async function postToSlack(payload) {
  if (SLACK_ALERTS_ENABLED !== 'true') { logger.info('[Slack] Disabled'); return; }
  if (!SLACK_WEBHOOK_URL) { logger.warn('[Slack] No webhook URL'); return; }
  try {
    const res = await fetch(SLACK_WEBHOOK_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (!res.ok) throw new Error(`Slack error ${res.status}: ${await res.text()}`);
    logger.info('[Slack] Alert posted successfully');
  } catch (err) { logger.error(`[Slack] Failed: ${err.message}`); }
}

async function alertUserLockout(user) {
  await postToSlack({
    text: `🔒 Account Locked Out: ${user.display_name || user.login}`,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: '🔒 Account Locked Out', emoji: true } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*User:*\n${user.display_name || user.login}` },
        { type: 'mrkdwn', text: `*Login:*\n${user.login}` },
        { type: 'mrkdwn', text: `*Email:*\n${user.email || '—'}` },
        { type: 'mrkdwn', text: `*Source IP:*\n${user.client_ip || 'Unknown'}` },
      ]},
      { type: 'section', text: { type: 'mrkdwn', text: `*Time:* ${new Date().toLocaleString('en-US', { timeZone: 'America/Los_Angeles' })}` } },
      { type: 'divider' },
      { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '🔓 Open HelpDesk Dashboard', emoji: true }, url: `${APP_BASE_URL}/helpdesk`, style: 'danger' }] },
    ],
  });
}

async function alertFailedLoginSpike(data) {
  await postToSlack({
    text: `🚨 Failed Login Spike: ${data.count} failures in ${data.windowMinutes} minutes`,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: '🚨 Failed Login Spike Detected', emoji: true } },
      { type: 'section', text: { type: 'mrkdwn', text: `*${data.count} failed login attempts* in the last *${data.windowMinutes} minutes*` } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*Failed Attempts:*\n${data.count}` },
        { type: 'mrkdwn', text: `*Time Window:*\nLast ${data.windowMinutes} minutes` },
        { type: 'mrkdwn', text: `*Top Source IPs:*\n${data.topIPs?.join('\n') || 'Unknown'}` },
        { type: 'mrkdwn', text: `*Threshold:*\n>${process.env.FAILED_LOGIN_SPIKE_THRESHOLD || 10} attempts` },
      ]},
      { type: 'section', text: { type: 'mrkdwn', text: `*Time:* ${new Date().toLocaleString('en-US', { timeZone: 'America/Los_Angeles' })}` } },
      { type: 'divider' },
      { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '🔍 View Failed Logins', emoji: true }, url: `${APP_BASE_URL}/helpdesk`, style: 'danger' }] },
    ],
  });
}

async function alertSyncFailure(data) {
  await postToSlack({
    text: `⚠️ Sync Failed: ${data.syncType}`,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: '⚠️ Sync Job Failed', emoji: true } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*Sync Job:*\n${data.syncType}` },
        { type: 'mrkdwn', text: `*Last Success:*\n${data.lastSuccess || 'Unknown'}` },
        { type: 'mrkdwn', text: `*Error:*\n${data.error || 'Unknown error'}` },
        { type: 'mrkdwn', text: `*Action:*\nManual re-sync may be required` },
      ]},
      { type: 'section', text: { type: 'mrkdwn', text: `*Time:* ${new Date().toLocaleString('en-US', { timeZone: 'America/Los_Angeles' })}` } },
      { type: 'divider' },
      { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '🔄 View Sync Status', emoji: true }, url: `${APP_BASE_URL}/helpdesk`, style: 'primary' }] },
    ],
  });
}

module.exports = { alertUserLockout, alertFailedLoginSpike, alertSyncFailure };
