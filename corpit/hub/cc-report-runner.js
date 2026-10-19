#!/usr/bin/env node
'use strict';
/* cc-report-runner.js — CC-V3 Report Center runner.
 * Spawned by api-beta (inherits its .env). Usage: node cc-report-runner.js --schedule <id>
 * Templates: dlp_weekly | connector_health | genai_summary | exec_summary
 * Mail: Graph app-only sendMail. Sender = CC_REPORT_SENDER (or AI_REPORT_SENDER) env.
 */
const path = require('path');
const APP = '/var/www/corpit-hub-api';
const HUB_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://corpit.nrpi.local').replace(/\/+$/, '');
const mysql = require(path.join(APP, 'node_modules', 'mysql2', 'promise'));
let ziaAuth, zpaAuth, httpsRequest;
try { ({ ziaAuth, zpaAuth, httpsRequest } = require(path.join(APP, 'zscaler-lookup'))); } catch (e) { console.error('zscaler-lookup load failed:', e.message); }
let PDFDocument; try { PDFDocument = require(path.join(APP, 'node_modules', 'pdfkit')); } catch (e) {}
let Database; try { Database = require(path.join(APP, 'node_modules', 'better-sqlite3')); } catch (e) {}

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 2
});

const argi = process.argv.indexOf('--schedule');
const SCHED_ID = argi > -1 ? parseInt(process.argv[argi + 1], 10) : null;

function jparse(b) { return typeof b === 'string' ? JSON.parse(b) : b; }

/* ── ZWA (Workflow Automation) direct auth — pattern verified live 2026-07-29 ── */
const ZWA_BASE = process.env.ZWA_BASE || ('https://api.' + (process.env.ZWA_CLOUD || 'us2') + '.zsworkflow.net');
async function zwaCount(days) {
  const kid = process.env.ZWA_KEY_ID, ks = process.env.ZWA_KEY_SECRET;
  if (!kid || !ks) throw new Error('ZWA keys missing');
  const tr = await httpsRequest(new URL(ZWA_BASE + '/v1/auth/api-key/token'),
    { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': 'itam-cc-report' } },
    JSON.stringify({ key_id: kid, key_secret: ks }));
  const tok = jparse(tr.body).token;
  const et = new Date(), st = new Date(Date.now() - days * 86400000);
  const sr = await httpsRequest(new URL(ZWA_BASE + '/dlp/v1/incidents/search'),
    { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + tok, 'User-Agent': 'itam-cc-report' } },
    JSON.stringify({ fields: [], timeRange: { startTime: st.toISOString(), endTime: et.toISOString() } }));
  const j = jparse(sr.body);
  return (j && j.cursor && j.cursor.totalElements) || 0;
}

async function ziaGetJson(p) {
  const token = await ziaAuth();
  const r = await httpsRequest(new URL(process.env.ZIA_BASE_URL + '/' + p),
    { method: 'GET', headers: { Authorization: 'Bearer ' + token }, timeoutMs: 60000 });
  return jparse(r.body);
}
async function zpaGetJson(p) {
  const token = await zpaAuth();
  const base = process.env.ZPA_BASE_URL;
  const r = await httpsRequest(new URL(base + '/' + p),
    { method: 'GET', headers: { Authorization: 'Bearer ' + token }, timeoutMs: 60000 });
  return jparse(r.body);
}
async function zpaListAll(p) {
  let out = [], page = 1;
  for (; page <= 20; page++) {
    const j = await zpaGetJson(p + '?page=' + page + '&pagesize=500');
    const list = (j && (j.list || j.items)) || (Array.isArray(j) ? j : []);
    out = out.concat(list);
    if (!list.length || list.length < 500) break;
  }
  return out;
}

async function tplDlpWeekly(win) {
  const days = Math.max(1, Math.round(win / 24));
  const [c7, c30, rulesResp] = await Promise.all([
    zwaCount(Math.min(days, 7)).catch(e => 'err: ' + e.message),
    zwaCount(30).catch(e => 'err: ' + e.message),
    ziaGetJson('webDlpRules').catch(e => [])
  ]);
  const rules = Array.isArray(rulesResp) ? rulesResp : [];
  const en = rules.filter(x => String(x.state || '').toUpperCase().indexOf('ENABLED') === 0);
  const dis = rules.filter(x => String(x.state || '').toUpperCase().indexOf('ENABLED') !== 0);
  const verified = (typeof c7 === 'number' && c7 > 0) || (typeof c30 === 'number' && c30 > 0);
  const sections = [
    { title: 'Incident volume (ZWA authoritative)', cols: ['Window', 'Incidents'], rows: [['Last ' + Math.min(days, 7) + 'd', String(c7)], ['Last 30d', String(c30)]] },
    { title: 'Pipeline coverage', cols: ['Metric', 'Value'], rows: [
      ['ZIA Web DLP rules (total)', String(rules.length)],
      ['Rules enabled', String(en.length)],
      ['Rules disabled', String(dis.length)],
      ['Forwarding to Workflow Automation', 'Global ZscalerDLP integration' + (verified ? ' - verified by delivery this period' : ' - no deliveries this period to verify')]
    ]},
    { title: 'Rules currently DISABLED (policy surface invisible to the incident store)', cols: ['Rule', 'Action', 'Severity'],
      rows: dis.slice(0, 60).map(x => [x.name || x.id, x.action || '', x.severity || '']) }
  ];
  return { title: 'DLP Weekly Summary', sections };
}

async function tplConnectorHealth() {
  const conns = await zpaListAll('connector');
  const on = conns.filter(c => String(c.ctrlChannelStatus || '').toUpperCase().includes('AUTHENTICATED'));
  const sections = [
    { title: 'Fleet', cols: ['Metric', 'Value'], rows: [
      ['Connectors total', String(conns.length)], ['Online', String(on.length)], ['Offline', String(conns.length - on.length)]
    ]},
    { title: 'Connectors', cols: ['Name', 'Status', 'Version', 'Expected', 'Last connect'],
      rows: conns.slice(0, 100).map(c => [c.name, c.ctrlChannelStatus || '', c.currentVersion || '', c.expectedVersion || '',
        c.lastBrokerConnectTime ? new Date(Number(c.lastBrokerConnectTime)).toUTCString() : '']) }
  ];
  return { title: 'ZPA Connector Health', sections };
}

function tplGenAI(win) {
  if (!Database) return { title: 'Gen AI Summary', sections: [{ title: 'Error', cols: ['Detail'], rows: [['better-sqlite3 unavailable']] }] };
  const AI_DB = process.env.AI_NSS_DB || '/var/www/corpit-hub-api/data/ai.db';
  let db;
  try { db = new Database(AI_DB, { readonly: true, fileMustExist: true }); }
  catch (e) { return { title: 'Gen AI Summary', sections: [{ title: 'Error', cols: ['Detail'], rows: [['ai.db not readable: ' + e.message]] }] }; }
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name);
    const t = tables.find(n => /event|log|tx|record/i.test(n)) || tables[0];
    if (!t) throw new Error('no tables in ai.db');
    const cols = db.prepare('PRAGMA table_info(`' + t + '`)').all().map(c => c.name);
    const tc = cols.find(c => /^(ts|time|timestamp|epoch|logtime|received)/i.test(c));
    const uc = cols.find(c => /^(user|login|email)/i.test(c));
    const ac = cols.find(c => /^(app|appname|application|cloudapp)/i.test(c));
    const sample = tc ? db.prepare('SELECT `' + tc + '` v FROM `' + t + '` ORDER BY rowid DESC LIMIT 1').get() : null;
    let cut = null;
    if (sample && sample.v != null) {
      const n = Number(sample.v);
      cut = isFinite(n) ? (n > 1e11 ? Date.now() - win * 3600000 : Math.floor((Date.now() - win * 3600000) / 1000))
                        : new Date(Date.now() - win * 3600000).toISOString();
    }
    const where = (tc && cut != null) ? ' WHERE `' + tc + '` >= ?' : '';
    const args = where ? [cut] : [];
    const total = db.prepare('SELECT COUNT(*) n FROM `' + t + '`' + where).get(...args).n;
    const users = uc ? db.prepare('SELECT COUNT(DISTINCT `' + uc + '`) n FROM `' + t + '`' + where).get(...args).n : '?';
    const topApps = ac ? db.prepare('SELECT `' + ac + '` a, COUNT(*) c FROM `' + t + '`' + where + ' GROUP BY `' + ac + '` ORDER BY c DESC LIMIT 15').all(...args) : [];
    db.close();
    return { title: 'Gen AI Usage Summary', sections: [
      { title: 'Volume (' + win + 'h)', cols: ['Metric', 'Value'], rows: [['AI transactions', String(total)], ['Distinct users', String(users)]] },
      { title: 'Top AI apps', cols: ['App', 'Transactions'], rows: topApps.map(r => [r.a, String(r.c)]) }
    ]};
  } catch (e) { try { db.close(); } catch (x) {} return { title: 'Gen AI Summary', sections: [{ title: 'Error', cols: ['Detail'], rows: [[e.message]] }] }; }
}

async function tplExec(win) {
  const [dlp, conn, ai] = await Promise.all([tplDlpWeekly(win), tplConnectorHealth(), Promise.resolve(tplGenAI(win))]);
  return { title: 'Executive Security Rollup', sections: []
    .concat(dlp.sections.slice(0, 2)).concat(ai.sections.slice(0, 1)).concat(conn.sections.slice(0, 1)) };
}

const TEMPLATES = { dlp_weekly: tplDlpWeekly, connector_health: () => tplConnectorHealth(), genai_summary: w => Promise.resolve(tplGenAI(w)), exec_summary: tplExec };

/* ── PDF render (mirrors CC-AI-PDF layout) ── */
function renderPdf(title, meta, sections) {
  return new Promise((resolve, reject) => {
    if (!PDFDocument) return reject(new Error('pdfkit not installed'));
    const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: 36, info: { Title: title } });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    const W = doc.page.width - 72;
    doc.rect(36, 36, W, 46).fill('#0A1628');
    doc.fill('#FFFFFF').font('Helvetica-Bold').fontSize(15).text(title, 48, 46);
    doc.fill('#94a3b8').font('Helvetica').fontSize(8.5).text('Auction.com · ' + meta + ' · generated ' + new Date().toUTCString(), 48, 66);
    doc.y = 96;
    const cell = v => { v = v == null ? '' : String(v); return v.length > 200 ? v.slice(0, 197) + '…' : v; };
    sections.forEach(sec => {
      const cols = (sec.cols || []).map(cell); const rows = (sec.rows || []).slice(0, 400);
      if (!cols.length) return;
      if (doc.y + 60 > doc.page.height - 40) { doc.addPage(); doc.y = 40; }
      doc.fill('#0A1628').font('Helvetica-Bold').fontSize(11).text(cell(sec.title || ''), 36, doc.y + 8);
      doc.moveDown(0.4);
      const wds = cols.map(() => W / cols.length);
      const row = (vals, head, zebra) => {
        if (doc.y + 14 > doc.page.height - 40) { doc.addPage(); doc.y = 40; }
        let x = 36; const y0 = doc.y;
        if (zebra) doc.rect(36, y0, W, 12).fill('#F1F5F9');
        doc.fill(head ? '#0EA5E9' : '#1e293b').font(head ? 'Helvetica-Bold' : 'Helvetica').fontSize(7.5);
        vals.forEach((v, i) => { doc.text(cell(v), x + 2, y0 + 2, { width: wds[i] - 4, height: 10, ellipsis: true }); x += wds[i]; });
        doc.y = y0 + 13;
      };
      row(cols, true, false);
      rows.forEach((r, i) => row(r, false, i % 2 === 1));
      doc.moveDown(0.6);
    });
    doc.end();
  });
}

/* ── Graph mail ── */
async function graphToken() {
  const T = process.env.AZURE_TENANT_ID || process.env.ENTRA_TENANT_ID;
  const C = process.env.AZURE_CLIENT_ID || process.env.ENTRA_CLIENT_ID;
  const S = process.env.AZURE_CLIENT_SECRET || process.env.ENTRA_CLIENT_SECRET;
  if (!T || !C || !S) throw new Error('AZURE_*/ENTRA_* creds missing');
  const body = 'client_id=' + C + '&client_secret=' + encodeURIComponent(S) + '&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&grant_type=client_credentials';
  const r = await httpsRequest(new URL('https://login.microsoftonline.com/' + T + '/oauth2/v2.0/token'),
    { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, body);
  const j = jparse(r.body); if (!j.access_token) throw new Error('graph token failed'); return j.access_token;
}
async function sendMail(recipients, subject, htmlBody, pdfBuf, fname) {
  const sender = process.env.CC_REPORT_SENDER || process.env.AI_REPORT_SENDER || process.env.REPORT_SENDER;
  if (!sender) throw new Error('CC_REPORT_SENDER env not set — cannot send');
  const tok = await graphToken();
  const msg = { message: {
    subject, body: { contentType: 'HTML', content: htmlBody },
    toRecipients: recipients.map(a => ({ emailAddress: { address: a.trim() } })).filter(x => x.emailAddress.address),
    attachments: [{ '@odata.type': '#microsoft.graph.fileAttachment', name: fname, contentType: 'application/pdf', contentBytes: pdfBuf.toString('base64') }]
  }, saveToSentItems: false };
  const r = await httpsRequest(new URL('https://graph.microsoft.com/v1.0/users/' + encodeURIComponent(sender) + '/sendMail'),
    { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, timeoutMs: 30000 }, JSON.stringify(msg));
  if (r.status >= 300) throw new Error('sendMail HTTP ' + r.status + ' ' + String(r.body).slice(0, 200));
}

async function main() {
  if (!SCHED_ID) { console.error('usage: node cc-report-runner.js --schedule <id>'); process.exit(1); }
  const [[sch]] = await pool.query('SELECT * FROM cc_report_schedules WHERE id=?', [SCHED_ID]);
  if (!sch) { console.error('schedule not found'); process.exit(1); }
  const rec = String(sch.recipients || '').split(/[;,\s]+/).filter(Boolean);
  let status = 'ok', detail = 'sent to ' + rec.length;
  try {
    const builder = TEMPLATES[sch.template_key];
    if (!builder) throw new Error('unknown template ' + sch.template_key);
    const rep = await builder(sch.window_hours || 168);
    const pdf = await renderPdf(rep.title, sch.label + ' · window ' + (sch.window_hours || 168) + 'h', rep.sections);
    const fname = sch.template_key + '-' + new Date().toISOString().slice(0, 10) + '.pdf';
    await sendMail(rec, '[IT Command] ' + rep.title + ' — ' + new Date().toISOString().slice(0, 10),
      '<p>Attached: <b>' + rep.title + '</b> (' + sch.label + ').</p><p>Drill into live data: <a href="' + HUB_ORIGIN + '/zscaler-command-center.html">Zscaler Command Center</a></p>', pdf, fname);
  } catch (e) { status = 'fail'; detail = e.message.slice(0, 480); }
  await pool.query('INSERT INTO cc_report_runs (schedule_id, template_key, triggered_by, recipients, status, detail) VALUES (?,?,?,?,?,?)',
    [SCHED_ID, sch.template_key, process.env.CC_RUN_BY || 'scheduler', rec.join(','), status, detail]);
  if (status === 'ok') await pool.query('UPDATE cc_report_schedules SET last_run=NOW() WHERE id=?', [SCHED_ID]);
  console.log('[cc-report-runner] ' + sch.template_key + ' → ' + status + ' (' + detail + ')');
  await pool.end();
  process.exit(status === 'ok' ? 0 : 2);
}
main().catch(e => { console.error(e); process.exit(1); });
