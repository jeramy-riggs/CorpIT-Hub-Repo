#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════
// ai-watch-job.js v1.0 — Gen AI Security watcher (cron: every 15 min)
// Location: /var/www/corpit-hub-api/ai-watch-job.js
//
// Does four things, read-only against ai.db, writes only to MySQL:
//   1. Auto-registers newly observed AI apps into ai_catalog (source=
//      'discovered', status='review') and stamps first/last_seen.
//   2. Alerts on brand-new apps that no catalog entry knew about.
//   3. Alerts on fresh activity by ai_watchlist subjects (open/monitoring).
//   4. Alerts on per-user volume spikes (>3x their 14-day daily baseline).
//
// Alerts POST {"text": "..."} to $AI_WATCH_WEBHOOK (works for both Teams
// and Slack incoming webhooks). If the env var is unset, alerts are
// logged to stdout only — the job still maintains the catalog.
// Dedupe state lives in ai_alert_state (high-water marks per alert key).
//
// Run (cron, as ubuntu):
//   */15 * * * * cd /var/www/corpit-hub-api && node -r dotenv/config ai-watch-job.js >> /var/log/ai-watch-job.log 2>&1
// Manual test:
//   cd /var/www/corpit-hub-api && node -r dotenv/config ai-watch-job.js --dry
// ═══════════════════════════════════════════════════════════════════
'use strict';

var DRY = process.argv.indexOf('--dry') >= 0;
var AI_DB = process.env.AI_NSS_DB || '/var/www/corpit-hub-api/data/ai.db';
var WEBHOOK = process.env.AI_WATCH_WEBHOOK || '';
var HUB_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://corpit.nrpi.local').replace(/\/+$/, '');
// The env override still wins; only the fallback host moves.
var CONSOLE_URL = process.env.AI_CONSOLE_URL || (HUB_ORIGIN + '/zscaler-command-center.html');
var WINDOW_MS = 30 * 60 * 1000;          // look-back for "new activity" (2x cron cadence)
var SPIKE_BASELINE_DAYS = 14;
var SPIKE_RATIO = 10;
var SPIKE_MIN_EVENTS = 100;
var MAX_SPIKE_ALERTS = 10;
var DIGEST_THRESHOLD = 15;
var EXCLUDE = new Set(['General Browsing','Unknown','Other','None','Miscellaneous']);               // ignore spikes below this absolute volume

var mysql = require('mysql2/promise');
var https = require('https');
var http = require('http');

function norm(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, ''); }
function log(m) { console.log('[' + new Date().toISOString() + '] ' + m); }

function post(text) {
  if (DRY || !WEBHOOK) { log((WEBHOOK ? '[dry] ' : '[no-webhook] ') + 'ALERT: ' + text); return Promise.resolve(); }
  return new Promise(function (resolve) {
    try {
      var u = new URL(WEBHOOK);
      var mod = u.protocol === 'http:' ? http : https;
      var body = JSON.stringify({ text: text });
      var rq = mod.request({ hostname: u.hostname, port: u.port || (u.protocol === 'http:' ? 80 : 443), path: u.pathname + u.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, timeout: 10000 },
        function (rs) { rs.resume(); rs.on('end', resolve); });
      rq.on('error', function (e) { log('webhook error: ' + e.message); resolve(); });
      rq.on('timeout', function () { rq.destroy(); log('webhook timeout'); resolve(); });
      rq.end(body);
    } catch (e) { log('webhook bad url: ' + e.message); resolve(); }
  });
}

async function main() {
  var Database;
  try { Database = require('better-sqlite3'); } catch (e) { log('FATAL: better-sqlite3 not installed'); process.exit(1); }
  var fs = require('fs');
  if (!fs.existsSync(AI_DB)) { log('ai.db not present — nothing to do'); return; }
  var db = new Database(AI_DB, { readonly: true, fileMustExist: true });

  var pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 2
  });

  async function getState(k) {
    var r = await pool.query('SELECT v FROM ai_alert_state WHERE k=?', [k]);
    return r[0][0] ? r[0][0].v : null;
  }
  async function setState(k, v) {
    if (DRY) return;
    await pool.query('INSERT INTO ai_alert_state (k, v) VALUES (?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)', [k, String(v)]);
  }

  var now = Date.now();
  var alerts = [];

  try {
    // ── 1. Catalog maintenance: register observed apps, stamp seen dates ──
    var catRows = (await pool.query('SELECT id, app_name, norm_key, aliases FROM ai_catalog'))[0];
    var knownKeys = [];
    catRows.forEach(function (r) {
      [r.norm_key].concat(String(r.aliases || '').split(/\n+/).map(norm)).forEach(function (k) { if (k && k.length >= 3) knownKeys.push({ key: k, id: r.id }); });
    });
    function knownIdOf(appNorm) {
      for (var i = 0; i < knownKeys.length; i++) {
        var k = knownKeys[i].key;
        if (appNorm === k || appNorm.indexOf(k) >= 0 || k.indexOf(appNorm) >= 0) return knownKeys[i].id;
      }
      return null;
    }

    var seen = db.prepare(
      "SELECT app, COUNT(*) c, COUNT(DISTINCT user) users, MIN(ts) fs, MAX(ts) ls " +
      "FROM ai_events WHERE ts>=? AND app IS NOT NULL AND length(app)>0 GROUP BY app"
    ).all(now - 7 * 86400000); // 7-day window keeps last_seen fresh without full scans

    var newApps = [];
    for (var i = 0; i < seen.length; i++) {
      var a = seen[i];
      if (EXCLUDE.has(a.app)) continue;
      var an = norm(a.app);
      if (an.length < 3) continue;
      var kid = knownIdOf(an);
      if (kid) {
        if (!DRY) await pool.query('UPDATE ai_catalog SET last_seen=FROM_UNIXTIME(?/1000), first_seen=COALESCE(first_seen, FROM_UNIXTIME(?/1000)) WHERE id=?', [a.ls, a.fs, kid]);
      } else {
        if (!DRY) await pool.query(
          'INSERT IGNORE INTO ai_catalog (app_name, norm_key, sanction_status, source, risk_note, first_seen, last_seen, created_by, updated_by) ' +
          'VALUES (?,?,\'review\',\'discovered\',\'Auto-registered: observed in Zscaler AI traffic, not previously in catalog.\', FROM_UNIXTIME(?/1000), FROM_UNIXTIME(?/1000), \'ai-watch-job\', \'ai-watch-job\')',
          [a.app, an, a.fs, a.ls]);
        newApps.push(a);
        knownKeys.push({ key: an, id: -1 });
      }
    }

    // ── 2. New-app alerts (dedupe on norm_key) ──
    for (var j = 0; j < newApps.length; j++) {
      var na = newApps[j];
      var dk = 'alerted_app:' + norm(na.app);
      if (await getState(dk)) continue;
      alerts.push('🆕 New AI app observed: "' + na.app + '" — ' + na.c + ' txns · ' + na.users + ' users (7d). Not in catalog; auto-registered as REVIEW. Investigate: ' + CONSOLE_URL + '?aiapp=' + encodeURIComponent(na.app));
      await setState(dk, new Date().toISOString());
    }

    // ── 3. Watchlist activity alerts (open/monitoring subjects, per-subject high-water) ──
    var wl = (await pool.query("SELECT id, subject, subject_type FROM ai_watchlist WHERE status IN ('open','monitoring')"))[0];
    for (var k = 0; k < wl.length; k++) {
      var w = wl[k];
      var col = w.subject_type === 'user' ? 'user' : (w.subject_type === 'app' ? 'app' : 'host');
      var hw = parseInt(await getState('wl_hw:' + w.id), 10) || (now - WINDOW_MS);
      var act = db.prepare('SELECT COUNT(*) c, MAX(ts) mx FROM ai_events WHERE ' + col + '=? AND ts>?').get(w.subject, hw);
      if (act && act.c > 0) {
        var link = w.subject_type === 'user'
          ? CONSOLE_URL + '?aiuser=' + encodeURIComponent(w.subject)
          : CONSOLE_URL + '?aiapp=' + encodeURIComponent(w.subject);
        alerts.push('👁 Watchlist activity: ' + w.subject_type + ' "' + w.subject + '" — ' + act.c + ' new AI events since last check. Investigate: ' + link);
        await setState('wl_hw:' + w.id, act.mx);
      }
    }

    // ── 4. Volume-spike alerts (daily dedupe per user) ──
    var today = new Date().toISOString().slice(0, 10);
    var spikeFired = 0;
    var spikes = db.prepare(
      "SELECT user, SUM(CASE WHEN ts>=? THEN 1 ELSE 0 END) recent, COUNT(*) base " +
      "FROM ai_events WHERE ts>=? AND user IS NOT NULL AND length(user)>0 GROUP BY user"
    ).all(now - 86400000, now - SPIKE_BASELINE_DAYS * 86400000);
    for (var m = 0; m < spikes.length; m++) {
      var s = spikes[m];
      var baselineDaily = (s.base - s.recent) / Math.max(SPIKE_BASELINE_DAYS - 1, 1);
      if (s.recent < SPIKE_MIN_EVENTS) continue;
      if (baselineDaily > 0 && s.recent >= baselineDaily * SPIKE_RATIO) {
        var sk = 'spike:' + today + ':' + s.user;
        if (await getState(sk)) continue;
        if (spikeFired >= MAX_SPIKE_ALERTS) continue;
        alerts.push('📈 AI volume spike: ' + s.user + ' — ' + s.recent + ' AI events in 24h vs ~' + Math.round(baselineDaily) + '/day baseline (' + (Math.round(s.recent / baselineDaily * 10) / 10) + '×). Investigate: ' + CONSOLE_URL + '?aiuser=' + encodeURIComponent(s.user));
        await setState(sk, '1'); spikeFired++;
      }
    }

    // ── Dispatch ──
    if (alerts.length > DIGEST_THRESHOLD) {
      var head = alerts.slice(0, 5).map(function (a) { return '- ' + a.split(' Investigate:')[0]; }).join('\n');
      await post('\ud83d\udce6 Gen AI watcher digest: ' + alerts.length + ' alerts this run (collapsed).\n' + head + '\n...and ' + (alerts.length - 5) + ' more - review in console: ' + CONSOLE_URL);
    } else {
      for (var n = 0; n < alerts.length; n++) await post(alerts[n]);
    }
    await setState('last_run', new Date().toISOString());
    log('done: ' + seen.length + ' apps stamped, ' + newApps.length + ' auto-registered, ' + alerts.length + ' alert(s)' + (DRY ? ' [DRY RUN — no writes]' : ''));
  } finally {
    try { db.close(); } catch (e) {}
    try { await pool.end(); } catch (e) {}
  }
}

main().catch(function (e) { log('FATAL: ' + (e && e.stack || e)); process.exit(1); });
