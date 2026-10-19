#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// ai-report-send.js — Gen AI Security email report (v1.0)
// Cron hourly at :05. Sends when due per ai_report_config.
// Flags: --now (force send), --dry-run (render to /tmp, no send)
// Sender: Graph sendMail as itcommand@auction.com (AZURE_* creds)
// ═══════════════════════════════════════════════════════════════
'use strict';
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const mysql = require('mysql2/promise');
const Database = require('better-sqlite3');
const fs = require('fs');
const https = require('https');
const { ziaAuth, httpsRequest } = require('/var/www/corpit-hub-api/zscaler-lookup');

const FORCE = process.argv.includes('--now');
const DRY = process.argv.includes('--dry-run');
const AI_DB = process.env.AI_NSS_DB || '/var/www/corpit-hub-api/data/ai.db';
const SENDER_ADDR = 'itcommand@auction.com';
const SENDER_NAME = 'IT Command · Gen AI Security';
// Follows the host this runs on. Was pinned to itam.nrpi.local, which sent
// corpit recipients to the old deployment.
const HUB_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://corpit.nrpi.local').replace(/\/+$/, '');
const DASH_URL = HUB_ORIGIN + '/zscaler-command-center.html';

function log(m) { console.log('[' + new Date().toISOString() + '] ' + m); }

function postJson(urlStr, headers, bodyObj) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const payload = typeof bodyObj === 'string' ? bodyObj : JSON.stringify(bodyObj);
    const req = https.request({ host: u.host, path: u.pathname + u.search, method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }, headers), timeout: 30000 }, (r) => {
      let d = ''; r.on('data', c => d += c); r.on('end', () => resolve({ status: r.statusCode, body: d }));
    });
    req.on('error', reject); req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.write(payload); req.end();
  });
}
async function graphToken() {
  const T = process.env.AZURE_TENANT_ID, C = process.env.AZURE_CLIENT_ID, S = process.env.AZURE_CLIENT_SECRET;
  if (!T || !C || !S) throw new Error('AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET missing');
  const body = new URLSearchParams({ client_id: C, client_secret: S, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' }).toString();
  const r = await postJson('https://login.microsoftonline.com/' + T + '/oauth2/v2.0/token', { 'Content-Type': 'application/x-www-form-urlencoded' }, body);
  const j = JSON.parse(r.body);
  if (!j.access_token) throw new Error('graph token failed: ' + r.body.slice(0, 200));
  return j.access_token;
}
async function sendMail(token, toList, subject, html) {
  const payload = { message: { subject: subject, body: { contentType: 'HTML', content: html }, from: { emailAddress: { address: SENDER_ADDR, name: SENDER_NAME } }, toRecipients: toList.map(a => ({ emailAddress: { address: a } })) }, saveToSentItems: 'true' };
  const r = await postJson('https://graph.microsoft.com/v1.0/users/' + SENDER_ADDR + '/sendMail', { Authorization: 'Bearer ' + token }, payload);
  if (r.status !== 202) throw new Error('sendMail HTTP ' + r.status + ': ' + r.body.slice(0, 200));
}

// ── matcher (same as CC-AI-SHADOW, QA'd 24/24) ──
function aiNorm(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, ''); }
function isGoverned(app, norms) {
  const u = aiNorm(app); if (u.length < 3) return false;
  return norms.some(q => q.length >= 3 && (u.includes(q) || q.includes(u)));
}
async function getPolicyApps() {
  const tok = await ziaAuth();
  const r = await httpsRequest(new URL('https://api.zsapi.net/zia/api/v1/webApplicationRules/AI_ML'), { method: 'GET', headers: { Authorization: 'Bearer ' + tok, 'User-Agent': 'itam-ai-report' }, timeoutMs: 30000 });
  if (r.status !== 200) throw new Error('AI_ML rules HTTP ' + r.status);
  const rules = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
  const set = {};
  (rules || []).forEach(x => (x.applications || []).forEach(a => { set[a] = true; }));
  return Object.keys(set);
}

function collect(windowHours, policyNorms) {
  const db = new Database(AI_DB, { readonly: true, fileMustExist: true });
  const since = Date.now() - windowHours * 3600000;
  const kpi = db.prepare('SELECT COUNT(*) c, COUNT(DISTINCT user) u, COUNT(DISTINCT app) a, COUNT(DISTINCT host) s FROM ai_events WHERE ts>=?').get(since);
  const blocked = db.prepare("SELECT COUNT(*) c FROM ai_events WHERE ts>=? AND (action LIKE '%lock%' OR action LIKE '%eny%' OR action LIKE '%rop%')").get(since).c;
  const apps = db.prepare('SELECT app, COUNT(*) total, COUNT(DISTINCT user) users, COUNT(DISTINCT host) sites, MIN(ts) first_seen, MAX(ts) last_seen, ' +
    "SUM(CASE WHEN action LIKE '%lock%' OR action LIKE '%eny%' OR action LIKE '%rop%' THEN 1 ELSE 0 END) blocked " +
    'FROM ai_events WHERE ts>=? AND app IS NOT NULL AND length(app)>0 GROUP BY app ORDER BY total DESC').all(since);
  const topUsers = db.prepare('SELECT user, COUNT(*) total, COUNT(DISTINCT app) apps FROM ai_events WHERE ts>=? AND length(user)>0 GROUP BY user ORDER BY total DESC LIMIT 10').all(since);
  const unsanctioned = [], governed = [];
  apps.forEach(a => (isGoverned(a.app, policyNorms) ? governed : unsanctioned).push(a));
  // top users per unsanctioned app
  unsanctioned.forEach(a => {
    a.topUsers = db.prepare('SELECT user, COUNT(*) c FROM ai_events WHERE ts>=? AND app=? GROUP BY user ORDER BY c DESC LIMIT 5').all(since, a.app);
  });
  db.close();
  return { kpi, blocked, unsanctioned, governed, topUsers };
}

function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function fmtAgo(ms) { const d = Math.floor((Date.now() - ms) / 86400000); return d === 0 ? 'today' : d + 'd ago'; }
function renderHtml(d, windowHours, includeGoverned) {
  const days = Math.round(windowHours / 24);
  const td = 'padding:8px 10px;border-bottom:1px solid #e5e7eb;font-size:13px;';
  const th = 'padding:8px 10px;border-bottom:2px solid #d1d5db;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#6b7280;text-align:left;';
  let h = '<div style="font-family:Segoe UI,Arial,sans-serif;max-width:760px;margin:0 auto;color:#111827">';
  h += '<div style="background:#0A1628;color:#fff;padding:22px 26px;border-radius:10px 10px 0 0"><div style="font-size:19px;font-weight:700">Gen AI Security Report</div><div style="font-size:12px;color:#94a3b8;margin-top:4px">Auction.com · last ' + days + ' days · generated ' + new Date().toUTCString() + '</div></div>';
  h += '<div style="border:1px solid #e5e7eb;border-top:0;padding:20px 26px;border-radius:0 0 10px 10px">';
  // KPI row
  h += '<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:18px"><tr>';
  [['Transactions', d.kpi.c], ['Users', d.kpi.u], ['AI Apps', d.kpi.a], ['Blocked', d.blocked], ['Unsanctioned Apps', d.unsanctioned.length]].forEach(kv => {
    h += '<td style="padding:10px;text-align:center;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px"><div style="font-size:21px;font-weight:800">' + Number(kv[1]).toLocaleString() + '</div><div style="font-size:10.5px;color:#6b7280;text-transform:uppercase;letter-spacing:.5px">' + kv[0] + '</div></td><td style="width:8px"></td>';
  });
  h += '</tr></table>';
  // Unsanctioned — the headline
  h += '<div style="font-size:15px;font-weight:700;color:#b91c1c;margin:6px 0 8px">⚠ Unsanctioned AI — no policy rule covers these (' + d.unsanctioned.length + ')</div>';
  if (!d.unsanctioned.length) {
    h += '<div style="padding:12px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;font-size:13px;color:#166534">✔ Every AI application observed in the window is covered by an AI &amp; ML policy rule.</div>';
  } else {
    h += '<table width="100%" cellpadding="0" cellspacing="0"><tr><th style="' + th + '">Application</th><th style="' + th + '">Txns</th><th style="' + th + '">Users</th><th style="' + th + '">First seen</th><th style="' + th + '">Top users</th></tr>';
    d.unsanctioned.forEach(a => {
      h += '<tr><td style="' + td + '"><b>' + esc(a.app) + '</b>' + (a.blocked ? ' <span style="color:#b45309;font-size:11px">(' + a.blocked + ' blocked)</span>' : '') + '</td><td style="' + td + '">' + a.total.toLocaleString() + '</td><td style="' + td + '">' + a.users + '</td><td style="' + td + '">' + fmtAgo(a.first_seen) + '</td><td style="' + td + ';font-size:11.5px;color:#374151">' + a.topUsers.map(u => esc(u.user) + ' (' + u.c + ')').join('<br>') + '</td></tr>';
    });
    h += '</table>';
  }
  // Top users overall
  h += '<div style="font-size:14px;font-weight:700;margin:20px 0 8px">Top AI Users</div>';
  h += '<table width="100%" cellpadding="0" cellspacing="0"><tr><th style="' + th + '">User</th><th style="' + th + '">Transactions</th><th style="' + th + '">Apps</th></tr>';
  d.topUsers.forEach(u => { h += '<tr><td style="' + td + '">' + esc(u.user) + '</td><td style="' + td + '">' + u.total.toLocaleString() + '</td><td style="' + td + '">' + u.apps + '</td></tr>'; });
  h += '</table>';
  if (includeGoverned) {
    h += '<div style="font-size:14px;font-weight:700;margin:20px 0 8px">Governed AI Usage (covered by policy)</div>';
    h += '<table width="100%" cellpadding="0" cellspacing="0"><tr><th style="' + th + '">Application</th><th style="' + th + '">Txns</th><th style="' + th + '">Users</th></tr>';
    d.governed.slice(0, 12).forEach(a => { h += '<tr><td style="' + td + '">' + esc(a.app) + '</td><td style="' + td + '">' + a.total.toLocaleString() + '</td><td style="' + td + '">' + a.users + '</td></tr>'; });
    h += '</table>';
  }
  h += '<div style="margin-top:22px;font-size:11.5px;color:#6b7280">Live dashboard: <a href="' + DASH_URL + '">' + DASH_URL + '</a> · Gen AI Security → Usage. Configure this report from that page.</div>';
  h += '</div></div>';
  return h;
}

function isDue(cfg, now) {
  if (FORCE) return true;
  if (!cfg.enabled) return false;
  if (now.getUTCHours() !== cfg.send_hour_utc) return false;
  if (cfg.frequency === 'weekly' && now.getUTCDay() !== cfg.send_dow) return false;
  if (cfg.frequency === 'monthly' && now.getUTCDate() !== cfg.send_dom) return false;
  if (cfg.last_sent_at) {
    const last = new Date(cfg.last_sent_at).getTime();
    const minGap = cfg.frequency === 'daily' ? 20 : 20; // hours — one send per slot
    if (Date.now() - last < minGap * 3600000) return false;
  }
  return true;
}

async function main() {
  const pool = mysql.createPool({ host: process.env.DB_HOST || 'localhost', user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME || 'corpit_hub', connectionLimit: 2 });
  const [[cfg]] = await pool.query('SELECT * FROM ai_report_config WHERE id=1');
  if (!cfg) { log('no config row'); await pool.end(); return; }
  const now = new Date();
  if (!isDue(cfg, now)) { log('not due (enabled=' + cfg.enabled + ', freq=' + cfg.frequency + ')'); await pool.end(); return; }
  log('report due — collecting (window ' + cfg.window_hours + 'h)');
  let status = 'ok';
  try {
    const policyApps = await getPolicyApps();
    const norms = policyApps.map(aiNorm);
    const data = collect(cfg.window_hours, norms);
    const html = renderHtml(data, cfg.window_hours, !!cfg.include_governed);
    const subject = 'Gen AI Security Report — ' + data.unsanctioned.length + ' unsanctioned app' + (data.unsanctioned.length === 1 ? '' : 's') + ' · ' + Number(data.kpi.c).toLocaleString() + ' AI transactions';
    if (DRY) {
      fs.writeFileSync('/tmp/ai-report-preview.html', html);
      log('DRY RUN — wrote /tmp/ai-report-preview.html (' + html.length + ' bytes). subject: ' + subject);
    } else {
      const recipients = String(cfg.recipients || '').split(/[,;\s]+/).filter(Boolean);
      if (!recipients.length) throw new Error('no recipients configured');
      const tok = await graphToken();
      await sendMail(tok, recipients, subject, html);
      log('sent to ' + recipients.join(', '));
    }
  } catch (e) { status = 'error: ' + e.message.slice(0, 200); log('FAIL: ' + e.message); }
  if (!DRY) await pool.query('UPDATE ai_report_config SET last_sent_at=NOW(), last_status=? WHERE id=1', [status]);
  await pool.end();
  if (status !== 'ok') process.exit(1);
}
main().catch(e => { log('FATAL: ' + e.message); process.exit(1); });
