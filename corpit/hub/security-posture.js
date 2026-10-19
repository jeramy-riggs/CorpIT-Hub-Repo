'use strict';
// security-posture.js — non-destructive live checks + manual-status store that back
// the Server Health "Security" tab. All checks are READ-ONLY (fs stat/read, loopback
// HTTPS GET). Manual statuses (for code-level fixes) persist to a small JSON file.
// Score model: 100 - sum(points of every finding not marked/verified fixed).
const fs = require('fs');
const path = require('path');
const https = require('https');

const STORE = process.env.SECPOSTURE_STORE || '/var/www/corpit-hub-api/data/security-posture.json';
const WEB_ROOT = '/var/www/html';
const HELPDESK_BUILD = '/opt/helpdesk-dashboard/client/build';
// FU-36 (2026-09-08): this probe used to send Host/SNI 'itam.nrpi.local' — a leftover
// from the ITAM port. corpit has no such server block, so every probe landed on
// 00-default (`server_name _; return 404;`) instead of a real vhost. That made
// chkCsp report 'unknown' forever (masking a genuine report-only-CSP finding) and
// made chkSourceMaps pass unconditionally, since it treats 404 as "not served".
// Derived from ALLOWED_ORIGIN exactly like HUB_ORIGIN in the other modules.
const HUB_HOST = (process.env.ALLOWED_ORIGIN || 'https://corpit.nrpi.local')
  .replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim() || 'corpit.nrpi.local';

function loadStatus() {
  try { return JSON.parse(fs.readFileSync(STORE, 'utf8')); } catch (e) { return {}; }
}
function saveStatus(obj) {
  try {
    fs.mkdirSync(path.dirname(STORE), { recursive: true });
    fs.writeFileSync(STORE, JSON.stringify(obj, null, 2));
    return true;
  } catch (e) { return false; }
}

// ── fs helpers ──────────────────────────────────────────────────────────────
function walk(dir, out, depth) {
  out = out || [];
  if (depth == null) depth = 4;
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return out; }
  for (const e of ents) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (depth > 0) walk(p, out, depth - 1); }
    else out.push(p);
  }
  return out;
}
const DENY_EXT = /\.(bak|old|orig|save|swp|env|sql|dump)/i; // nginx denylist (unanchored)
function servedUnauth(rel) {
  if (/~$/.test(rel)) return false;        // nginx: ~$  -> 404
  if (DENY_EXT.test(rel)) return false;    // nginx: dot-blocked ext -> 404
  if (/\.html$/i.test(rel)) return false;  // .html is auth-gated (not static-served)
  return true;                             // else static handler serves it unauth
}
function httpsGet(pathname) {
  return new Promise(function (resolve) {
    const req = https.request({
      host: '127.0.0.1', port: 443, method: 'GET', path: pathname,
      servername: HUB_HOST, headers: { Host: HUB_HOST },
      rejectUnauthorized: false, timeout: 4000,
    }, function (r) {
      let b = '';
      r.on('data', d => { if (b.length < 2048) b += d; });
      r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, body: b }));
    });
    req.on('error', () => resolve({ status: 0, headers: {}, body: '' }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '' }); });
    req.end();
  });
}

// ── checks: each returns {state:'pass'|'fail'|'unknown', detail} ─────────────
async function chkImportKey() {
  const files = walk(WEB_ROOT, [], 2).filter(f => /\.js$/i.test(f));
  const re = /IMPORT_KEY\s*=\s*['"][0-9a-fA-F]{16,}['"]/;
  const hits = [];
  for (const f of files) {
    try { if (re.test(fs.readFileSync(f, 'utf8'))) hits.push(path.basename(f)); } catch (e) {}
  }
  return hits.length
    ? { state: 'fail', detail: 'Hardcoded key still in served JS: ' + hits.join(', ') }
    : { state: 'pass', detail: 'No hardcoded IMPORT_KEY in any served .js' };
}
async function chkServableBackups() {
  const files = walk(WEB_ROOT, [], 3);
  const hits = files.filter(f => {
    const rel = f.slice(WEB_ROOT.length);
    const base = path.basename(f);
    const looksBackup = /\.(html|js|css)\.[^/]+$/i.test(base) || /(^|\/)beta\//.test(rel);
    return looksBackup && servedUnauth(rel);
  });
  return hits.length
    ? { state: 'fail', detail: hits.length + ' backup/alt file(s) served unauth (e.g. ' + hits.slice(0, 3).map(h => path.basename(h)).join(', ') + ')' }
    : { state: 'pass', detail: 'No servable backup/alt source files under the web root' };
}
async function chkStaleBaks() {
  const n = walk(WEB_ROOT, [], 3).filter(f => /\.bak/i.test(path.basename(f)) || /~$/.test(f)).length;
  return n > 0
    ? { state: 'fail', detail: n + ' stale .bak/backup file(s) in the web root (404-blocked, but hygiene debt)' }
    : { state: 'pass', detail: 'No stale backup files in the web root' };
}
function readListeners() {
  const map = {};
  for (const fp of ['/proc/net/tcp', '/proc/net/tcp6']) {
    let lines;
    try { lines = fs.readFileSync(fp, 'utf8').split('\n'); } catch (e) { continue; }
    for (const ln of lines) {
      const c = ln.trim().split(/\s+/);
      if (c.length < 4 || !c[1] || c[1].indexOf(':') < 0) continue;
      if (c[3] !== '0A') continue; // LISTEN
      const parts = c[1].split(':');
      const port = parseInt(parts[1], 16);
      (map[port] = map[port] || []).push(parts[0].toUpperCase());
    }
  }
  return map;
}
async function chkReceivers() {
  const map = readListeners();
  const wildcard = new Set(['00000000', '00000000000000000000000000000000']);
  const exposed = [9600, 9601, 9602, 9603].filter(p => (map[p] || []).some(a => wildcard.has(a)));
  return exposed.length
    ? { state: 'fail', detail: 'Receiver port(s) bound to 0.0.0.0: ' + exposed.join(', ') + '. (A ufw-only fix is not auto-detected — bind to the mgmt IP, or mark fixed manually.)' }
    : { state: 'pass', detail: 'No receiver port bound to all interfaces' };
}
async function chkSourceMaps() {
  let mapRel = null;
  try {
    const jsDir = path.join(HELPDESK_BUILD, 'static', 'js');
    const f = fs.readdirSync(jsDir).find(n => /\.js\.map$/.test(n));
    if (f) mapRel = '/helpdesk/static/js/' + f;
  } catch (e) {}
  if (!mapRel) return { state: 'unknown', detail: 'No source-map file found to probe' };
  const r = await httpsGet(mapRel);
  if (r.status === 200) return { state: 'fail', detail: 'Source map served unauthenticated (HTTP 200)' };
  // FU-37 (2026-09-08): a 404 has two very different causes, and reporting both as
  // 'pass' produced a green control that could never go red. The helpdesk SPA was
  // never ported to corpit -- there is no /helpdesk route and no /var/www/html/helpdesk
  // -- so this probe 404s because the app is absent, not because the map is protected.
  // Say which. (Standing rule: a check that cannot fail is not a control.)
  if (r.status === 404 && !fs.existsSync(path.join(WEB_ROOT, 'helpdesk'))) {
    return { state: 'unknown', detail: 'Helpdesk SPA is not deployed on this host - nothing to protect (HTTP 404, no /helpdesk route)' };
  }
  if ([301, 302, 401, 403, 404].indexOf(r.status) >= 0) return { state: 'pass', detail: 'Source map not served unauth (HTTP ' + r.status + ')' };
  return { state: 'unknown', detail: 'Probe inconclusive (HTTP ' + r.status + ')' };
}
async function chkCsp() {
  const r = await httpsGet('/login.html');
  if (r.headers['content-security-policy']) return { state: 'pass', detail: 'Enforced CSP header present' };
  if (r.headers['content-security-policy-report-only']) return { state: 'fail', detail: 'CSP is Report-Only (not enforced)' };
  return { state: 'unknown', detail: 'No CSP header seen (HTTP ' + r.status + ')' };
}
async function chkHelpdeskDb() {
  try {
    const st = fs.statSync('/opt/helpdesk-dashboard/data/helpdesk.db');
    const mode = (st.mode & 0o777).toString(8);
    return (st.mode & 0o004)
      ? { state: 'fail', detail: 'helpdesk.db is world-readable (mode ' + mode + ')' }
      : { state: 'pass', detail: 'helpdesk.db not world-readable (mode ' + mode + ')' };
  } catch (e) { return { state: 'unknown', detail: 'helpdesk.db not found' }; }
}

// ── catalog (points sum to 25 -> current all-open score = 75) ────────────────
const FINDINGS = [
  { id: 'F1', points: 5,   sev: 'high',   cat: 'Secrets',          mode: 'auto',   check: chkImportKey,
    title: 'Live IMPORT_KEY served unauthenticated', fix: 'Rotate IMPORT_KEY, delete beta-IT_Inventory_App.js, retire the shared-key scheme.' },
  { id: 'F2', points: 4,   sev: 'high',   cat: 'XSS',              mode: 'manual',
    title: 'Stored/DOM XSS on identity-diag.html', fix: 'Escape " in attribute contexts (jsq) and route innerHTML through x().' },
  { id: 'F3', points: 3,   sev: 'high',   cat: 'XSS',              mode: 'manual',
    title: 'Stored/DOM XSS on ai-usage-credits.html', fix: 'Add an HTML escaper; escape name/email/manager/department before innerHTML.' },
  { id: 'F4', points: 2.5, sev: 'medium', cat: 'Network',          mode: 'auto',   check: chkReceivers,
    title: 'Log receivers 9600-9603 open to any host', fix: 'Bind to the mgmt interface or firewall the ports to the collector (10.20.10.85).' },
  { id: 'F5', points: 2,   sev: 'medium', cat: 'Content exposure', mode: 'auto',   check: chkServableBackups,
    title: 'Backup/alt files served unauthenticated', fix: 'Move backups out of the web root; deny non-.html backup suffixes.' },
  { id: 'F6', points: 2,   sev: 'medium', cat: 'Access control',   mode: 'manual',
    title: 'HelpDesk side-effect routes lack role checks', fix: 'Role-gate POST /api/health/sync + Slack test endpoints; add a sync concurrency lock.' },
  { id: 'F7', points: 1.5, sev: 'medium', cat: 'Content exposure', mode: 'auto',   check: chkSourceMaps,
    title: 'HelpDesk source maps served unauthenticated', fix: 'Add auth_request to /helpdesk/static/ or stop shipping .map to prod.' },
  { id: 'F8', points: 2,   sev: 'medium', cat: 'Access control',   mode: 'manual',
    title: 'api-beta sync/telemetry routes miss per-route authz', fix: 'Add requirePage guards; fix the netswitch factory signature to apply the gate.' },
  { id: 'F9', points: 1,   sev: 'low',    cat: 'Hardening',        mode: 'auto',   check: chkCsp,
    title: 'CSP is Report-Only (does not block XSS)', fix: 'Move to an enforced Content-Security-Policy after clearing inline-script violations.' },
  { id: 'F10', points: 1,  sev: 'low',    cat: 'Secrets',          mode: 'auto',   check: chkHelpdeskDb,
    title: 'HelpDesk PII cache world-readable', fix: 'chmod 640 helpdesk.db; rotate/relocate helpdesk .env secrets.' },
  { id: 'F11', points: 0.5, sev: 'low',   cat: 'XSS',              mode: 'manual',
    title: 'Escaping inconsistencies on enum/geoIP fields', fix: 'Escape command-center loc, cert-watchtower statusPill, sharepoint badges uniformly.' },
  { id: 'F12', points: 0.5, sev: 'info',  cat: 'Content exposure', mode: 'auto',   check: chkStaleBaks,
    title: 'Stale backup files in the web root', fix: 'Clear all .bak/backup copies out of /var/www/html.' },
];

async function computePosture() {
  const status = loadStatus();
  const items = [];
  let openPoints = 0;
  const maxPoints = FINDINGS.reduce((a, f) => a + f.points, 0);
  for (const f of FINDINGS) {
    let state, detail;
    if (f.mode === 'auto') {
      let r;
      try { r = await f.check(); } catch (e) { r = { state: 'unknown', detail: 'check error: ' + e.message }; }
      state = r.state === 'pass' ? 'fixed' : (r.state === 'unknown' ? 'unknown' : 'open');
      detail = r.detail;
    } else {
      const s = status[f.id] || {};
      state = s.status || 'open';        // open | in_progress | fixed
      detail = s.note || '';
    }
    const isOpen = state !== 'fixed';    // unknown / open / in_progress all still count
    if (isOpen) openPoints += f.points;
    const s = status[f.id] || {};
    items.push({
      id: f.id, title: f.title, severity: f.sev, category: f.cat, points: f.points,
      mode: f.mode, state: state, detail: detail, fix: f.fix,
      updatedBy: s.by || null, updatedAt: s.at || null,
    });
  }
  const score = Math.max(0, Math.round(100 - openPoints));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  const counts = { high: 0, medium: 0, low: 0, info: 0, openHigh: 0, fixed: 0 };
  for (const it of items) {
    counts[it.severity] = (counts[it.severity] || 0) + 1;
    if (it.state === 'fixed') counts.fixed++;
    else if (it.severity === 'high') counts.openHigh++;
  }
  return {
    score: score, grade: grade, maxPoints: maxPoints,
    openPoints: Math.round(openPoints * 10) / 10,
    remediatedPoints: Math.round((maxPoints - openPoints) * 10) / 10,
    total: items.length, counts: counts, items: items,
    generatedAt: new Date().toISOString(),
  };
}

const VALID_STATUS = ['open', 'in_progress', 'fixed'];
function setStatus(id, statusVal, note, who) {
  const f = FINDINGS.find(x => x.id === id);
  if (!f) return { ok: false, error: 'unknown finding id' };
  if (f.mode !== 'manual') return { ok: false, error: 'finding ' + id + ' is auto-checked and cannot be set manually' };
  if (VALID_STATUS.indexOf(statusVal) < 0) return { ok: false, error: 'invalid status' };
  const store = loadStatus();
  store[id] = { status: statusVal, note: String(note || '').slice(0, 500), by: who || 'unknown', at: new Date().toISOString() };
  if (!saveStatus(store)) return { ok: false, error: 'could not persist status' };
  return { ok: true, id: id, status: statusVal };
}

module.exports = { FINDINGS: FINDINGS, computePosture: computePosture, setStatus: setStatus };
