#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// ai-nss-receiver.js — ZIA NSS AI Web-Log receiver v2.0
// v2: AI class OR curated AI-domain match; captures user_agent;
//     tags each row with detection_source (ZS_CLASS | DOMAIN_MATCH).
// Env: AI_NSS_PORT/DB/RETAIN_DAYS/RAW/RAW_MAX/AI_ONLY as read below;
//   AI_NSS_IDLE_MS=43200000   close a stream that sent nothing for 12 h (0 = never); TCP keepalive is always on
// ═══════════════════════════════════════════════════════════════
'use strict';
const net = require('net');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { hostMatchesAI } = require('/var/www/corpit-hub-api/ai-domains.js');

const PORT = parseInt(process.env.AI_NSS_PORT, 10) || 9603;
const DB_PATH = process.env.AI_NSS_DB || '/var/www/corpit-hub-api/data/ai.db';
const RETAIN_DAYS = parseInt(process.env.AI_NSS_RETAIN_DAYS, 10) || 90;
const RAW = process.env.AI_NSS_RAW || '/var/log/itam/ai-nss-raw.log';
const RAW_MAX = parseInt(process.env.AI_NSS_RAW_MAX, 10) || 20;
const AI_ONLY = process.env.AI_NSS_AI_ONLY !== '0';

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = FULL');
if (db.pragma('synchronous', { simple: true }) !== 2) {
  db.close();
  throw new Error('SQLite writer requires synchronous=FULL');
}
// Table + indexes: idempotent create. Migration for detection_source/user_agent already ran.
db.exec(
  'CREATE TABLE IF NOT EXISTS ai_events (' +
  ' ts INTEGER NOT NULL, user TEXT, host TEXT, url TEXT, app TEXT, url_category TEXT,' +
  ' action TEXT, reason TEXT, device TEXT, department TEXT, location TEXT,' +
  ' client_ip TEXT, server_ip TEXT, req_method TEXT, resp_code TEXT,' +
  ' req_size INTEGER, resp_size INTEGER, raw TEXT,' +
  " detection_source TEXT DEFAULT 'ZS_CLASS', user_agent TEXT" +
  ');' +
  'CREATE INDEX IF NOT EXISTS ix_ai_ts     ON ai_events(ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ai_user   ON ai_events(user, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ai_app    ON ai_events(app, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ai_host   ON ai_events(host, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ai_dept   ON ai_events(department, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ai_action ON ai_events(action, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ai_source ON ai_events(detection_source, ts);' +
  'CREATE TABLE IF NOT EXISTS ai_seen_ids (' +
  ' record_id TEXT PRIMARY KEY, first_seen INTEGER NOT NULL' +
  ') WITHOUT ROWID;' +
  'CREATE INDEX IF NOT EXISTS ix_ai_seen_age ON ai_seen_ids(first_seen);'
);
const seen = db.prepare('INSERT OR IGNORE INTO ai_seen_ids (record_id, first_seen) VALUES (?, ?)');

const ins = db.prepare(
  'INSERT INTO ai_events (ts,user,host,url,app,url_category,action,reason,device,department,location,' +
  'client_ip,server_ip,req_method,resp_code,req_size,resp_size,raw,detection_source,user_agent)' +
  ' VALUES (@ts,@user,@host,@url,@app,@url_category,@action,@reason,@device,@department,@location,' +
  '@client_ip,@server_ip,@req_method,@resp_code,@req_size,@resp_size,@raw,@detection_source,@user_agent)'
);
const insMany = db.transaction(function (rows) {
  var inserted = 0;
  rows.forEach(function (r) {
    if (r.record_id && !seen.run(r.record_id, Date.now()).changes) return;
    var event = Object.assign({}, r); delete event.record_id;
    inserted += ins.run(event).changes;
  });
  return inserted;
});

function pickf(t) { for (var i = 1; i < arguments.length; i++) { var k = arguments[i]; if (t[k] !== undefined && t[k] !== null && t[k] !== '') return t[k]; } return null; }
function parseTs(t) {
  var raw = pickf(t, 'epochtime', 'datetime', 'time', 'LogTimestamp');
  if (raw) {
    var n = parseInt(raw, 10);
    if (!isNaN(n) && n > 0) return n < 1e11 ? n * 1000 : (n >= 1e14 ? Math.floor(n / 1000) : n);
    var ms = Date.parse(raw); if (!isNaN(ms)) return ms;
  }
  return Date.now();
}
function toInt(v) { var n = parseInt(v, 10); return isNaN(n) ? null : n; }
function eventId(t) {
  var value = pickf(t, 'recordid', 'record_id');
  if (typeof value === 'number' && !Number.isSafeInteger(value)) return null;
  var id = value == null ? '' : String(value);
  return /^\d{1,32}$/.test(id) && id !== '0' ? id : null;
}

function mapRecord(t, detSource) {
  return {
    ts: parseTs(t),
    user: pickf(t, 'user', 'login') || '',
    host: pickf(t, 'hostname', 'host', 'url', 'eurl') || '',
    url: pickf(t, 'url', 'eurl') || '',
    app: pickf(t, 'appname', 'appproto', 'app') || '',
    url_category: pickf(t, 'urlcategory', 'urlclass', 'urlsupercat') || '',
    action: pickf(t, 'action') || '',
    reason: pickf(t, 'reason') || '',
    device: pickf(t, 'device_hostname', 'devicename', 'device') || '',
    department: pickf(t, 'department', 'dept') || '',
    location: pickf(t, 'location', 'locationname') || '',
    client_ip: pickf(t, 'source_ip', 'cip', 'cintip') || '',
    server_ip: pickf(t, 'dest_ip', 'sip') || '',
    req_method: pickf(t, 'http_method', 'reqmethod', 'method') || '',
    resp_code: String(pickf(t, 'http_status_code', 'respcode') || ''),
    req_size: toInt(pickf(t, 'requestsize', 'reqsize', 'req_size', 'clientbytes')),
    resp_size: toInt(pickf(t, 'responsesize', 'respsize', 'resp_size', 'serverbytes')),
    user_agent: pickf(t, 'useragent', 'user_agent', 'ua') || '',
    record_id: eventId(t),
    raw: JSON.stringify(t).slice(0, 4000),
    detection_source: detSource || 'ZS_CLASS'
  };
}

let pending = [];
let stats = { lines: 0, bad: 0, inserted: 0, duplicates: 0, dropped: 0, matched_class: 0, matched_domain: 0, conns: 0, rawCaptured: 0 };
function flush() {
  if (!pending.length) return;
  var batch = pending; pending = [];
  try { var inserted = insMany(batch); stats.inserted += inserted; stats.duplicates += batch.length - inserted; }
  catch (e) { console.error('[ai-nss] insert error:', e.message); }
}
setInterval(flush, 2000).unref();

function captureRaw(line) {
  if (stats.rawCaptured >= RAW_MAX) return;
  try {
    fs.mkdirSync(path.dirname(RAW), { recursive: true });
    fs.appendFileSync(RAW, new Date().toISOString() + ' ' + line + '\n');
    stats.rawCaptured++;
    if (stats.rawCaptured === RAW_MAX) console.log('[ai-nss] raw capture complete (' + RAW_MAX + ' records) -> ' + RAW);
  } catch (e) { console.error('[ai-nss] raw capture error:', e.message); }
}

// Socket hygiene (CHG-ARCH-07, 2026-09-23). Node enables neither TCP keepalive nor an idle limit on
// accepted sockets, so a peer that vanished without FIN/RST (connector restart, NAT expiry) stayed
// "established" for ever: the previous lss process held 1,449 fds after 12 days against ~100 live
// streams. Keepalive (60 s idle, then the kernel's 9 probes x 75 s) reaps a dead peer in ~12 min;
// the idle limit closes a socket whose peer is alive but has sent nothing for IDLE_MS (0 = never).
const IDLE_MS = (function () { var v = parseInt(process.env.AI_NSS_IDLE_MS, 10); return isNaN(v) ? 12 * 3600000 : Math.max(0, v); })();
function guardSocket(sock, tag, peer) {
  sock.setKeepAlive(true, 60000);
  if (IDLE_MS > 0) sock.setTimeout(IDLE_MS, function () {
    console.log(tag + ' no data for ' + Math.round(IDLE_MS / 60000) + ' min, closing', peer);
    sock.destroy();
  });
}

const server = net.createServer(function (sock) {
  stats.conns++;
  var peer = sock.remoteAddress + ':' + sock.remotePort;
  console.log('[ai-nss] stream connected from', peer);
  guardSocket(sock, '[ai-nss]', peer);
  var buf = '';
  sock.on('data', function (chunk) {
    buf += chunk.toString('utf8');
    if (buf.length > 8 * 1024 * 1024) { console.error('[ai-nss] 8MB line guard tripped, dropping buffer'); buf = ''; return; }
    var idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      var line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
      if (!line) continue;
      stats.lines++;
      captureRaw(line);
      var jstart = line.indexOf('{');
      var payload = jstart >= 0 ? line.slice(jstart) : line;
      try {
        var o = JSON.parse(payload);
        if (o && o.event && typeof o.event === 'object') o = o.event;
        var ac = String(o.appclass || '');
        var host = String(o.hostname || o.host || o.url || o.eurl || '');
        var zsClass = /AI\s*&\s*ML/i.test(ac);
        var domain = hostMatchesAI(host);
        if (AI_ONLY && !zsClass && !domain) { stats.dropped++; continue; }
        if (zsClass) stats.matched_class++; else if (domain) stats.matched_domain++;
        pending.push(mapRecord(o, zsClass ? 'ZS_CLASS' : 'DOMAIN_MATCH'));
        if (pending.length >= 200) flush();
      } catch (e) { stats.bad++; if (stats.bad <= 5) console.error('[ai-nss] unparseable (first 200):', line.slice(0, 200)); }
    }
  });
  sock.on('error', function (e) { console.error('[ai-nss] socket error', peer, e.message); });
  sock.on('close', function () { flush(); console.log('[ai-nss] stream closed', peer); });
});
server.listen(PORT, '0.0.0.0', function () {
  console.log('[ai-nss] v2 listening on 0.0.0.0:' + PORT + ' -> ' + DB_PATH + ' (retain ' + RETAIN_DAYS + 'd, AI_ONLY=' + AI_ONLY + ')');
});

setInterval(function () {
  try {
    var cutoff = Date.now() - RETAIN_DAYS * 86400000;
    var r = db.prepare('DELETE FROM ai_events WHERE ts < ?').run(cutoff);
    if (r.changes) console.log('[ai-nss] pruned', r.changes, 'rows older than', RETAIN_DAYS, 'days');
    db.prepare('DELETE FROM ai_seen_ids WHERE first_seen < ?').run(Date.now() - 2 * 86400000);
  } catch (e) { console.error('[ai-nss] prune error:', e.message); }
}, 86400000).unref();
setInterval(function () { console.log('[ai-nss] stats:', JSON.stringify(stats)); }, 3600000).unref();

process.on('SIGINT', function () { flush(); db.close(); process.exit(0); });
process.on('SIGTERM', function () { flush(); db.close(); process.exit(0); });
