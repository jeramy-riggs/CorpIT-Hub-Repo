#!/usr/bin/env node
/**
 * user-project-digest-job.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Standalone cron job that emails the User Projects digest via Microsoft Graph
 * Mail.Send (Application permission, app 04ecee8f, AZURE_* env vars).
 *
 * Behavior:
 *   1. Reads user_project_settings for enabled / day / recipients / sections
 *   2. If digest_enabled != 'true' → exit silently
 *   3. If today's day-of-week != digest_day_of_week → exit silently
 *   4. If last_sent_at was within 20 hours → exit silently (safety)
 *   5. Builds HTML email with selected sections:
 *        - activity_7d      : last 7 days of audit feed
 *        - snapshot         : per-group current active members
 *        - expiring_14d     : grants expiring in next 14 days
 *        - recently_removed : grants expired/revoked in last 7 days
 *   6. Sends via Graph as CorpITOperationsHub <itcommand@auction.com>
 *   7. Updates digest_last_sent_at
 *
 * CLI flags:
 *   --test <recipient>   → force-send to one address, ignore day/enabled/last-sent
 *
 * Cron:
 *   0 9 * * * cd /var/www/corpit-hub-api && node user-project-digest-job.js >> /var/log/user-project-digest.log 2>&1
 * ─────────────────────────────────────────────────────────────────────────────
 */
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const mysql = require('mysql2/promise');
const mailGraph = require('./mail-graph');

// [CORPIT-QA 2026-09-07] Was: SENDER_ADDR = 'itcommand@auction.com', used as
// the /users/{id} path segment -- and the mail attribute is not an identifier Graph accepts in /users/{...},
// so this job could never have delivered a digest. Sender identity now
// comes from mail-graph.js (From: itcommand@auction.com, name CorpIT; the
// old 'CorpITOperationsHub' display name was a mangled leftover).
// User Projects now lives inside identity-diag.html (folded in 2026-09-04);
// beta-user-projects.html exists only on ITAM. No deep link to the projects
// view exists yet -- go() does not set location.hash.
const HUB_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://corpit.nrpi.local').replace(/\/+$/, '');

// AZURE_* credentials are read by mail-graph.js, not here.

function log(...a){ console.log(`[digest ${new Date().toISOString()}]`, ...a); }
function err(...a){ console.error(`[digest ${new Date().toISOString()}] ERROR`, ...a); }

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 3,
});

async function getSettings() {
  const [rows] = await pool.query('SELECT setting_key, setting_value FROM user_project_settings');
  const m = {};
  for (const r of rows) m[r.setting_key] = r.setting_value;
  return m;
}

async function sendMail(toList, subject, htmlBody) {
  // Throws on failure, as the axios.post it replaced did: the caller stamps
  // last_sent_at only after this returns, so a silent false would record a
  // digest that was never delivered.
  const r = await mailGraph.sendMail({
    to: toList, subject, html: htmlBody, saveToSentItems: true,
  });
  if (!r.ok) throw new Error('sendMail ' + r.reason + (r.status ? ' HTTP ' + r.status : ''));
}

/* ─── Data collectors ───────────────────────────────────────── */

async function collect_activity_7d() {
  const [rows] = await pool.query(`
    SELECT a.created_at, a.action, a.actor, a.details, p.name AS project_name
    FROM user_project_audit a
    LEFT JOIN user_projects p ON p.id = a.project_id
    WHERE a.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ORDER BY a.created_at DESC
    LIMIT 250
  `);
  return rows;
}

async function collect_snapshot() {
  const PRESET = ['SaaS-ZIA-AI-Read', 'SaaS-ZIA-AI-RD', 'SaaS-ZIA-AI-Exec-Read', 'SaaS-ZIA-AI-RD-UploadAccess'];
  const buckets = {};
  for (const g of PRESET) buckets[g] = [];
  const [rows] = await pool.query(`
    SELECT g.id, g.ad_group_name, g.user_sam, g.user_display_name, g.expires_at, g.granted_at, g.granted_by,
           p.name AS project_name
    FROM user_project_grants g
    LEFT JOIN user_projects p ON p.id = g.project_id
    WHERE g.status='active' AND g.ad_group_name IN (?, ?, ?, ?)
    ORDER BY g.ad_group_name, g.user_sam
  `, PRESET);
  for (const r of rows) {
    if (buckets[r.ad_group_name]) buckets[r.ad_group_name].push(r);
  }
  return buckets;
}

async function collect_expiring_14d() {
  const [rows] = await pool.query(`
    SELECT g.user_sam, g.user_display_name, g.ad_group_name, g.expires_at, p.name AS project_name
    FROM user_project_grants g
    LEFT JOIN user_projects p ON p.id = g.project_id
    WHERE g.status='active'
      AND g.expires_at IS NOT NULL
      AND g.expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 14 DAY)
    ORDER BY g.expires_at ASC
  `);
  return rows;
}

async function collect_recently_removed() {
  const [rows] = await pool.query(`
    SELECT g.user_sam, g.user_display_name, g.ad_group_name, g.status, g.removed_at, g.removed_by, p.name AS project_name
    FROM user_project_grants g
    LEFT JOIN user_projects p ON p.id = g.project_id
    WHERE g.status IN ('expired','revoked')
      AND g.removed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ORDER BY g.removed_at DESC
  `);
  return rows;
}

/* ─── HTML rendering ───────────────────────────────────────── */

function esc(s){ if(s==null)return ''; return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function fmtDT(s){ if(!s)return '—'; try{ return new Date(s).toLocaleString('en-US',{timeZone:'America/Los_Angeles'}); }catch(_){ return String(s); } }
function fmtD(s){ if(!s)return '—'; try{ return new Date(s).toLocaleDateString('en-US',{timeZone:'America/Los_Angeles'}); }catch(_){ return String(s); } }

function baseCSS() {
  return `
    body{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#0A1628;color:#EEF4FB;margin:0;padding:24px}
    .wrap{max-width:820px;margin:0 auto;background:#0F1F35;border:1px solid #1F3A5C;border-radius:10px;overflow:hidden}
    .head{padding:24px;border-bottom:1px solid #1F3A5C;background:linear-gradient(135deg,#0F1F35,#18304E)}
    .head h1{margin:0;font-size:20px;color:#EEF4FB}
    .head p{margin:4px 0 0;font-size:13px;color:#8FA3BE}
    .section{padding:20px 24px;border-bottom:1px solid #1F3A5C}
    .section:last-child{border-bottom:none}
    .section h2{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#38BDF8}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th{text-align:left;padding:8px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#8FA3BE;border-bottom:1px solid #1F3A5C;background:#18304E}
    td{padding:8px 10px;border-bottom:1px solid #1F3A5C;color:#EEF4FB;vertical-align:top}
    tr:last-child td{border-bottom:none}
    .chip{display:inline-block;padding:2px 8px;background:#18304E;border:1px solid #2D4D7A;border-radius:9px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#8FA3BE}
    .muted{color:#8FA3BE;font-size:12px}
    .empty{color:#5A6F8E;font-style:italic;font-size:12px;padding:8px 0}
    .group-block{margin-top:14px;padding:12px;background:#18304E;border-radius:6px;border-left:3px solid #0EA5E9}
    .group-block .gname{font-family:'JetBrains Mono',monospace;font-size:13px;color:#EEF4FB;font-weight:600}
    .group-block .gcount{font-size:11px;color:#8FA3BE;margin-left:8px}
    .foot{padding:16px 24px;font-size:11px;color:#5A6F8E;background:#0A1628;text-align:center}
    .foot a{color:#0EA5E9;text-decoration:none}
  `;
}

function renderActivity7d(rows) {
  if (!rows.length) return `<div class="empty">No activity in the last 7 days.</div>`;
  return `<table>
    <thead><tr><th>When</th><th>Project</th><th>Action</th><th>Actor</th></tr></thead>
    <tbody>
    ${rows.map(r=>`<tr>
      <td class="muted">${esc(fmtDT(r.created_at))}</td>
      <td>${esc(r.project_name||'—')}</td>
      <td><span class="chip">${esc(r.action)}</span></td>
      <td>${esc(r.actor)}</td>
    </tr>`).join('')}
    </tbody>
  </table>`;
}

function renderSnapshot(buckets) {
  const groups = Object.keys(buckets);
  return groups.map(g => {
    const members = buckets[g] || [];
    return `
      <div class="group-block">
        <div><span class="gname">${esc(g)}</span><span class="gcount">${members.length} active member${members.length===1?'':'s'}</span></div>
        ${members.length ? `
          <table style="margin-top:10px">
            <thead><tr><th>User</th><th>Project</th><th>Expires</th><th>Granted by</th></tr></thead>
            <tbody>
            ${members.map(m=>`<tr>
              <td>${esc(m.user_display_name||m.user_sam)}<div class="muted" style="font-family:'JetBrains Mono',monospace">${esc(m.user_sam)}</div></td>
              <td>${esc(m.project_name||'—')}</td>
              <td>${m.expires_at?esc(fmtD(m.expires_at)):'<span class="chip">Permanent</span>'}</td>
              <td class="muted">${esc(m.granted_by)}</td>
            </tr>`).join('')}
            </tbody>
          </table>
        ` : `<div class="empty" style="margin-top:6px">No active members.</div>`}
      </div>`;
  }).join('');
}

function renderExpiring14d(rows) {
  if (!rows.length) return `<div class="empty">Nothing expiring in the next 14 days.</div>`;
  return `<table>
    <thead><tr><th>User</th><th>Group</th><th>Project</th><th>Expires</th></tr></thead>
    <tbody>
    ${rows.map(r=>`<tr>
      <td>${esc(r.user_display_name||r.user_sam)}<div class="muted" style="font-family:'JetBrains Mono',monospace">${esc(r.user_sam)}</div></td>
      <td><span class="chip">${esc(r.ad_group_name)}</span></td>
      <td>${esc(r.project_name||'—')}</td>
      <td>${esc(fmtD(r.expires_at))}</td>
    </tr>`).join('')}
    </tbody>
  </table>`;
}

function renderRecentlyRemoved(rows) {
  if (!rows.length) return `<div class="empty">No removals in the last 7 days.</div>`;
  return `<table>
    <thead><tr><th>User</th><th>Group</th><th>Project</th><th>Status</th><th>When</th><th>By</th></tr></thead>
    <tbody>
    ${rows.map(r=>`<tr>
      <td>${esc(r.user_display_name||r.user_sam)}<div class="muted" style="font-family:'JetBrains Mono',monospace">${esc(r.user_sam)}</div></td>
      <td><span class="chip">${esc(r.ad_group_name)}</span></td>
      <td>${esc(r.project_name||'—')}</td>
      <td>${esc(r.status)}</td>
      <td class="muted">${esc(fmtDT(r.removed_at))}</td>
      <td class="muted">${esc(r.removed_by||'system')}</td>
    </tr>`).join('')}
    </tbody>
  </table>`;
}

async function buildEmailHTML(sections) {
  const parts = [];
  const today = new Date().toLocaleDateString('en-US', { timeZone:'America/Los_Angeles', weekday:'long', month:'long', day:'numeric', year:'numeric' });

  parts.push(`<!DOCTYPE html><html><head><meta charset="utf-8"/><style>${baseCSS()}</style></head><body>`);
  parts.push(`<div class="wrap">`);
  parts.push(`<div class="head"><h1>User Projects Digest</h1><p>${esc(today)}</p></div>`);

  if (sections.includes('activity_7d')) {
    const rows = await collect_activity_7d();
    parts.push(`<div class="section"><h2>Last 7 Days &middot; Activity Feed</h2>${renderActivity7d(rows)}</div>`);
  }
  if (sections.includes('snapshot')) {
    const buckets = await collect_snapshot();
    parts.push(`<div class="section"><h2>Current AD Group Snapshot</h2>${renderSnapshot(buckets)}</div>`);
  }
  if (sections.includes('expiring_14d')) {
    const rows = await collect_expiring_14d();
    parts.push(`<div class="section"><h2>Expiring in Next 14 Days</h2>${renderExpiring14d(rows)}</div>`);
  }
  if (sections.includes('recently_removed')) {
    const rows = await collect_recently_removed();
    parts.push(`<div class="section"><h2>Recently Removed (last 7 days)</h2>${renderRecentlyRemoved(rows)}</div>`);
  }

  parts.push(`<div class="foot">Sent by CorpITOperationsHub &middot; <a href="${HUB_ORIGIN}/identity-diag.html">User Projects</a></div>`);
  parts.push(`</div></body></html>`);
  return parts.join('\n');
}

/* ─── main ─────────────────────────────────────────────────── */

async function main() {
  const args = process.argv.slice(2);
  const testIdx = args.indexOf('--test');
  const isTest = testIdx >= 0;
  const testTo = isTest ? args[testIdx + 1] : null;
  if (isTest && !testTo) {
    err('--test requires an email address');
    process.exit(2);
  }

  const s = await getSettings();
  const enabled = String(s.digest_enabled || 'true') === 'true';
  const dow    = parseInt(s.digest_day_of_week || '2', 10); // 1=Mon
  let recipients = [];
  try { recipients = JSON.parse(s.digest_recipients || '[]'); } catch(_){}
  let sections = [];
  try { sections = JSON.parse(s.digest_sections || '["activity_7d","snapshot","expiring_14d","recently_removed"]'); } catch(_){
    sections = ['activity_7d','snapshot','expiring_14d','recently_removed'];
  }

  if (!isTest) {
    if (!enabled)          { log('digest_enabled=false → skip'); await pool.end(); return; }
    // JS: Sunday=0 ... Saturday=6. Settings: Mon=1 ... Sun=7.
    const now = new Date();
    const todayDow = ((now.getDay() + 6) % 7) + 1;
    if (todayDow !== dow) { log(`today dow=${todayDow}, configured=${dow} → skip`); await pool.end(); return; }
    // safety: skip if last sent within 20h
    if (s.digest_last_sent_at) {
      const last = new Date(s.digest_last_sent_at).getTime();
      const hrs = (Date.now() - last) / 3600000;
      if (hrs < 20) { log(`last sent ${hrs.toFixed(1)}h ago → skip (< 20h safety window)`); await pool.end(); return; }
    }
    if (!recipients.length) { log('no recipients configured → skip'); await pool.end(); return; }
  }

  const toList = isTest ? [testTo] : recipients;
  const subj = isTest
    ? '[TEST] User Projects Digest'
    : `User Projects Digest — ${new Date().toLocaleDateString('en-US',{timeZone:'America/Los_Angeles'})}`;

  log(`building HTML with sections=${JSON.stringify(sections)}`);
  const html = await buildEmailHTML(sections);

  log(`sending to ${JSON.stringify(toList)}…`);
  await sendMail(toList, subj, html);

  if (!isTest) {
    const conn = await pool.getConnection();
    try {
      await conn.query(
        `INSERT INTO user_project_settings (setting_key, setting_value, updated_by)
         VALUES ('digest_last_sent_at', NOW(), 'system')
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by='system'`
      );
    } finally { conn.release(); }
    log('digest_last_sent_at updated');
  }

  log('sent OK');
  await pool.end();
}

main().catch(async e => {
  err(e.stack || e.message || String(e));
  try { await pool.end(); } catch(_){}
  process.exit(1);
});
