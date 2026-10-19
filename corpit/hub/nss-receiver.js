#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// nss-receiver.js — ZIA NSS Web-Log TCP receiver  (v1.0)
// Run under pm2:  pm2 start nss-receiver.js --name nss-receiver
//
// Receives ZIA NSS "Web Log" records (Custom JSON template, SYSLOG_TCP)
// on TCP 9602 and stores them in SQLite at /var/www/corpit-hub-api/data/nss.db.
// The NSS feed is source-filtered (Policy Action = SSL/handshake/inspection
// denials only), so volume is small — every record here is a user-facing
// SSL/inspection failure. We still raw-capture the first N records so the
// field mapping can be locked against real data before trusting it.
//
// Env (all optional):
//   NSS_PORT=9602
//   NSS_DB=/var/www/corpit-hub-api/data/nss.db
//   NSS_RETAIN_DAYS=90
//   NSS_RAW=/var/log/itam/nss-web-raw.log
//   NSS_RAW_MAX=20
//   NSS_IDLE_MS=43200000      close a stream that sent nothing for 12 h (0 = never); TCP keepalive is always on
// ═══════════════════════════════════════════════════════════════
'use strict';
const net = require('net');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const PORT = parseInt(process.env.NSS_PORT, 10) || 9602;
const DB_PATH = process.env.NSS_DB || '/var/www/corpit-hub-api/data/nss.db';
const RETAIN_DAYS = parseInt(process.env.NSS_RETAIN_DAYS, 10) || 90;
const RAW = process.env.NSS_RAW || '/var/log/itam/nss-web-raw.log';
const RAW_MAX = parseInt(process.env.NSS_RAW_MAX, 10) || 20;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = FULL');
if (db.pragma('synchronous', { simple: true }) !== 2) {
  db.close();
  throw new Error('SQLite writer requires synchronous=FULL');
}
db.exec(
  'CREATE TABLE IF NOT EXISTS ssl_events (' +
  ' ts INTEGER NOT NULL,' +          // epoch ms
  ' user TEXT,' +
  ' host TEXT,' +                    // hostname the user was reaching
  ' url TEXT,' +
  ' action TEXT,' +                  // policy action / reason (the SSL denial)
  ' reason TEXT,' +
  ' device TEXT,' +
  ' client_ip TEXT,' +
  ' server_ip TEXT,' +
  ' url_category TEXT,' +
  ' app TEXT,' +
  ' client_tls TEXT,' +
  ' server_tls TEXT,' +
  ' client_cipher TEXT,' +
  ' server_cipher TEXT,' +
  ' resp_code TEXT,' +
  ' raw TEXT' +
  ');' +
  'CREATE INDEX IF NOT EXISTS ix_ssl_ts ON ssl_events(ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ssl_user ON ssl_events(user, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ssl_host ON ssl_events(host, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ssl_action ON ssl_events(action, ts);' +
  'CREATE TABLE IF NOT EXISTS nss_seen_ids (' +
  ' record_id TEXT PRIMARY KEY, first_seen INTEGER NOT NULL' +
  ') WITHOUT ROWID;' +
  'CREATE INDEX IF NOT EXISTS ix_nss_seen_age ON nss_seen_ids(first_seen);'
);
// A separate, initially empty ID table avoids scanning or rebuilding the
// existing large event table. The ID and event insert share one transaction.
const seen = db.prepare('INSERT OR IGNORE INTO nss_seen_ids (record_id, first_seen) VALUES (?, ?)');
const ins = db.prepare(
  'INSERT INTO ssl_events (ts,user,host,url,action,reason,device,client_ip,server_ip,url_category,app,client_tls,server_tls,client_cipher,server_cipher,resp_code,raw)' +
  ' VALUES (@ts,@user,@host,@url,@action,@reason,@device,@client_ip,@server_ip,@url_category,@app,@client_tls,@server_tls,@client_cipher,@server_cipher,@resp_code,@raw)'
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
function eventId(t) {
  var value = pickf(t, 'recordid', 'record_id');
  if (typeof value === 'number' && !Number.isSafeInteger(value)) return null;
  var id = value == null ? '' : String(value);
  return /^\d{1,32}$/.test(id) && id !== '0' ? id : null;
}
// Field names follow feed #3's proven template; alternates included for safety.
function mapRecord(t) {
  return {
    ts: parseTs(t),
    user: pickf(t, 'user', 'login') || '',
    host: pickf(t, 'hostname', 'host', 'url', 'eurl') || '',
    url: pickf(t, 'url', 'eurl') || '',
    action: pickf(t, 'action', 'reason') || '',
    reason: pickf(t, 'reason', 'action') || '',
    device: pickf(t, 'device_hostname', 'devicename', 'device') || '',
    client_ip: pickf(t, 'source_ip', 'cip', 'cintip') || '',
    server_ip: pickf(t, 'dest_ip', 'sip') || '',
    url_category: pickf(t, 'urlcategory', 'urlclass', 'urlsupercat') || '',
    app: pickf(t, 'appname', 'appproto') || '',
    client_tls: pickf(t, 'client_ssl_version', 'clienttlsversion') || '',
    server_tls: pickf(t, 'server_ssl_version', 'srvtlsversion') || '',
    client_cipher: pickf(t, 'client_ssl_cipher', 'clientsslcipher') || '',
    server_cipher: pickf(t, 'server_ssl_cipher', 'srvsslcipher') || '',
    resp_code: String(pickf(t, 'http_status_code', 'respcode') || ''),
    record_id: eventId(t),
    raw: JSON.stringify(t).slice(0, 4000)
  };
}

let pending = [];
let stats = { lines: 0, bad: 0, inserted: 0, duplicates: 0, conns: 0, rawCaptured: 0 };
function flush() {
  if (!pending.length) return;
  var batch = pending; pending = [];
  try { var inserted = insMany(batch); stats.inserted += inserted; stats.duplicates += batch.length - inserted; }
  catch (e) { console.error('[nss] insert error:', e.message); }
}
setInterval(flush, 2000).unref();

function captureRaw(line) {
  if (stats.rawCaptured >= RAW_MAX) return;
  try {
    fs.mkdirSync(path.dirname(RAW), { recursive: true });
    fs.appendFileSync(RAW, new Date().toISOString() + ' ' + line + '\n');
    stats.rawCaptured++;
    if (stats.rawCaptured === RAW_MAX) console.log('[nss] raw capture complete (' + RAW_MAX + ' records) -> ' + RAW);
  } catch (e) { console.error('[nss] raw capture error:', e.message); }
}

// Socket hygiene (CHG-ARCH-07, 2026-09-23). Node enables neither TCP keepalive nor an idle limit on
// accepted sockets, so a peer that vanished without FIN/RST (connector restart, NAT expiry) stayed
// "established" for ever: the previous lss process held 1,449 fds after 12 days against ~100 live
// streams. Keepalive (60 s idle, then the kernel's 9 probes x 75 s) reaps a dead peer in ~12 min;
// the idle limit closes a socket whose peer is alive but has sent nothing for IDLE_MS (0 = never).
const IDLE_MS = (function () { var v = parseInt(process.env.NSS_IDLE_MS, 10); return isNaN(v) ? 12 * 3600000 : Math.max(0, v); })();
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
  console.log('[nss] stream connected from', peer);
  guardSocket(sock, '[nss]', peer);
  var buf = '';
  sock.on('data', function (chunk) {
    buf += chunk.toString('utf8');
    if (buf.length > 8 * 1024 * 1024) { console.error('[nss] 8MB line guard tripped, dropping buffer'); buf = ''; return; }
    var idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      var line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
      if (!line) continue;
      stats.lines++;
      captureRaw(line);
      // NSS syslog prefixes the JSON with a <PRI> + timestamp header; strip to first '{'.
      var jstart = line.indexOf('{');
      var payload = jstart >= 0 ? line.slice(jstart) : line;
      try {
        var o = JSON.parse(payload);
        if (o && o.event && typeof o.event === 'object') o = o.event;
        pending.push(mapRecord(o));
        if (pending.length >= 100) flush();
      } catch (e) { stats.bad++; if (stats.bad <= 5) console.error('[nss] unparseable (first 200):', line.slice(0, 200)); }
    }
  });
  sock.on('error', function (e) { console.error('[nss] socket error', peer, e.message); });
  sock.on('close', function () { flush(); console.log('[nss] stream closed', peer); });
});
server.listen(PORT, '0.0.0.0', function () {
  console.log('[nss] Web-Log SSL receiver listening on 0.0.0.0:' + PORT + ' -> ' + DB_PATH + ' (retain ' + RETAIN_DAYS + 'd, raw->' + RAW + ')');
});

// daily retention prune + hourly stats
setInterval(function () {
  try {
    var cutoff = Date.now() - RETAIN_DAYS * 86400000;
    var r = db.prepare('DELETE FROM ssl_events WHERE ts < ?').run(cutoff);
    if (r.changes) console.log('[nss] pruned', r.changes, 'rows older than', RETAIN_DAYS, 'days');
    db.prepare('DELETE FROM nss_seen_ids WHERE first_seen < ?').run(Date.now() - 2 * 86400000);
  } catch (e) { console.error('[nss] prune error:', e.message); }
}, 86400000).unref();
setInterval(function () { console.log('[nss] stats:', JSON.stringify(stats)); }, 3600000).unref();

process.on('SIGINT', function () { flush(); db.close(); process.exit(0); });
process.on('SIGTERM', function () { flush(); db.close(); process.exit(0); });
