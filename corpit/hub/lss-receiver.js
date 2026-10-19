#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// lss-receiver.js — ZPA LSS TCP receiver  (v2.1)
// Run under pm2:  pm2 restart lss-receiver   (or start --name lss-receiver)
//
// v1.0: User Activity JSON on TCP 9600 → conns table.
// v2.0 ADDS (fully additive; 9600 path unchanged):
//   • conns.internal_reason column (guarded ALTER; captures disconnect
//     reason separately from lifecycle status).
//   • Second listener on 9601 for the "App Connector Status" log type →
//     connector_health table. Field names for that template are NOT yet
//     confirmed, so we (a) raw-capture the first N records to a log file
//     for you to paste back, and (b) best-effort map common field names.
//     Nothing on 9601 can affect 9600 — separate server, separate try/catch.
//
// Env (all optional):
//   LSS_PORT=9600             User Activity listen port
//   LSS_STATUS_PORT=9601      App Connector Status listen port
//   LSS_DB=/var/www/corpit-hub-api/data/lss.db
//   LSS_RETAIN_DAYS=30
//   LSS_STATUS_RAW=/var/log/itam/lss-connstatus-raw.log   raw-capture path
//   LSS_STATUS_RAW_MAX=20     how many raw records to capture then stop
//   LSS_IDLE_MS=7200000       close a stream that sent nothing for this long (0 = never); TCP keepalive is always on
// ═══════════════════════════════════════════════════════════════
'use strict';
const net = require('net');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const PORT = parseInt(process.env.LSS_PORT, 10) || 9600;
const STATUS_PORT = parseInt(process.env.LSS_STATUS_PORT, 10) || 9601;
const DB_PATH = process.env.LSS_DB || '/var/www/corpit-hub-api/data/lss.db';
const RETAIN_DAYS = parseInt(process.env.LSS_RETAIN_DAYS, 10) || 30;
const STATUS_RAW = process.env.LSS_STATUS_RAW || '/var/log/itam/lss-connstatus-raw.log';
const STATUS_RAW_MAX = parseInt(process.env.LSS_STATUS_RAW_MAX, 10) || 20;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = FULL');
if (db.pragma('synchronous', { simple: true }) !== 2) {
  db.close();
  throw new Error('SQLite writer requires synchronous=FULL');
}
// Wait up to 5s for a lock instead of failing the whole batch instantly (2026-08-24).
db.pragma('busy_timeout = 5000');
db.exec(
  'CREATE TABLE IF NOT EXISTS conns (' +
  ' ts INTEGER NOT NULL,' +
  ' user TEXT,' +
  ' app TEXT,' +
  ' appgroup TEXT,' +
  ' connector TEXT,' +
  ' connector_ip TEXT,' +
  ' host TEXT,' +
  ' server_ip TEXT,' +
  ' client_ip TEXT,' +
  ' status TEXT,' +
  ' bytes_rx INTEGER DEFAULT 0,' +
  ' bytes_tx INTEGER DEFAULT 0,' +
  ' setup_ms INTEGER' +
  ');' +
  'CREATE INDEX IF NOT EXISTS ix_conns_ts ON conns(ts);' +
  'CREATE INDEX IF NOT EXISTS ix_conns_conn ON conns(connector, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_conns_app ON conns(app, ts);' +
  'CREATE INDEX IF NOT EXISTS ix_conns_user ON conns(user, ts);'
);

// v2.0: guarded ALTER — add internal_reason if not already present.
try {
  var cols = db.prepare('PRAGMA table_info(conns)').all().map(function (c) { return c.name; });
  if (cols.indexOf('internal_reason') === -1) {
    db.exec('ALTER TABLE conns ADD COLUMN internal_reason TEXT');
    console.log('[lss] migrated: added conns.internal_reason');
  }
} catch (e) { console.error('[lss] internal_reason migration skipped:', e.message); }

// v2.1 (2026-08-27): Diagnostics drill-down fields. The LSS User Activity
// stream already carries every one of these; v1/v2.0 simply dropped them on
// the floor. Guarded ALTERs — pre-existing rows keep NULL, so nothing that is
// already in the table changes and no existing query is affected.
var V21_COLS = [
  ['policy', 'TEXT'], ['client_zen', 'TEXT'], ['connector_zen', 'TEXT'],
  ['connection_id', 'TEXT'], ['session_id', 'TEXT'],
  ['service_port', 'INTEGER'], ['server_port', 'INTEGER'], ['ip_protocol', 'INTEGER'],
  ['platform', 'TEXT'], ['hostname', 'TEXT'], ['idp', 'TEXT'],
  ['client_city', 'TEXT'], ['client_country', 'TEXT'], ['policy_ms', 'INTEGER']
];
try {
  var v21have = db.prepare('PRAGMA table_info(conns)').all().map(function (c) { return c.name; });
  V21_COLS.forEach(function (c) {
    if (v21have.indexOf(c[0]) === -1) {
      db.exec('ALTER TABLE conns ADD COLUMN ' + c[0] + ' ' + c[1]);
      console.log('[lss] migrated: added conns.' + c[0]);
    }
  });
} catch (e) { console.error('[lss] v2.1 migration skipped:', e.message); }

// v2.0: App Connector Status table. Columns are our best guess; the raw
// blob is always stored so no data is lost if a field name differs.
db.exec(
  'CREATE TABLE IF NOT EXISTS connector_health (' +
  ' ts INTEGER NOT NULL,' +
  ' connector TEXT,' +
  ' connector_ip TEXT,' +
  ' group_name TEXT,' +
  ' cpu REAL,' +
  ' mem REAL,' +
  ' disk REAL,' +
  ' bytes_rx INTEGER,' +
  ' bytes_tx INTEGER,' +
  ' version TEXT,' +
  ' status TEXT,' +
  ' raw TEXT' +
  ');' +
  'CREATE INDEX IF NOT EXISTS ix_ch_ts ON connector_health(ts);' +
  'CREATE INDEX IF NOT EXISTS ix_ch_conn ON connector_health(connector, ts);'
);

const ins = db.prepare(
  'INSERT INTO conns (ts,user,app,appgroup,connector,connector_ip,host,server_ip,client_ip,status,internal_reason,bytes_rx,bytes_tx,setup_ms,' +
  ' policy,client_zen,connector_zen,connection_id,session_id,service_port,server_port,ip_protocol,platform,hostname,idp,client_city,client_country,policy_ms)' +
  ' VALUES (@ts,@user,@app,@appgroup,@connector,@connector_ip,@host,@server_ip,@client_ip,@status,@internal_reason,@bytes_rx,@bytes_tx,@setup_ms,' +
  ' @policy,@client_zen,@connector_zen,@connection_id,@session_id,@service_port,@server_port,@ip_protocol,@platform,@hostname,@idp,@client_city,@client_country,@policy_ms)'
);
const insMany = db.transaction(function (rows) { rows.forEach(function (r) { ins.run(r); }); });

const insCH = db.prepare(
  'INSERT INTO connector_health (ts,connector,connector_ip,group_name,cpu,mem,disk,bytes_rx,bytes_tx,version,status,raw)' +
  ' VALUES (@ts,@connector,@connector_ip,@group_name,@cpu,@mem,@disk,@bytes_rx,@bytes_tx,@version,@status,@raw)'
);
const insCHMany = db.transaction(function (rows) { rows.forEach(function (r) { insCH.run(r); }); });

function num(v) { var n = parseInt(v, 10); return isNaN(n) ? 0 : n; }
function fnum(v) { var n = parseFloat(v); return isNaN(n) ? null : n; }
function pickf(t) { for (var i = 1; i < arguments.length; i++) { var k = arguments[i]; if (t[k] !== undefined && t[k] !== null && t[k] !== '') return t[k]; } return null; }
function parseTs(t) {
  var raw = pickf(t, 'LogTimestamp', 'TimestampConnectionEnd', 'TimestampConnectionStart', 'Timestamp');
  if (raw) { var ms = Date.parse(raw); if (!isNaN(ms)) return ms; var n = parseInt(raw, 10); if (!isNaN(n) && n > 0) return n < 1e11 ? n * 1000 : (n >= 1e14 ? Math.floor(n / 1000) : n); }
  return Date.now();
}
function mapRecord(t) {
  return {
    ts: parseTs(t),
    user: pickf(t, 'Username', 'User') || '',
    app: pickf(t, 'Application', 'App') || '',
    appgroup: pickf(t, 'AppGroup') || '',
    connector: pickf(t, 'Connector') || '',
    connector_ip: pickf(t, 'ConnectorIP') || '',
    host: pickf(t, 'Host') || '',
    server_ip: pickf(t, 'ServerIP') || '',
    client_ip: pickf(t, 'ClientPublicIP', 'ClientPrivateIP') || '',
    status: pickf(t, 'ConnectionStatus') || '',
    internal_reason: pickf(t, 'InternalReason', 'InternalReasonCode') || '',
    bytes_rx: num(pickf(t, 'ZENTotalBytesRxClient', 'ZENBytesRxClient')),
    bytes_tx: num(pickf(t, 'ZENTotalBytesTxClient', 'ZENBytesTxClient')),
    setup_ms: num(pickf(t, 'ConnectionSetupTime', 'ServerSetupTime')),
    // ── v2.1 diagnostics fields ──
    policy: pickf(t, 'Policy', 'PolicyName') || '',
    client_zen: pickf(t, 'ClientZEN') || '',
    connector_zen: pickf(t, 'ConnectorZEN') || '',
    connection_id: pickf(t, 'ConnectionID') || '',
    session_id: pickf(t, 'SessionID') || '',
    service_port: num(pickf(t, 'ServicePort')),
    server_port: num(pickf(t, 'ServerPort')),
    ip_protocol: num(pickf(t, 'IPProtocol')),
    platform: pickf(t, 'Platform') || '',
    hostname: pickf(t, 'Hostname') || '',
    idp: pickf(t, 'Idp', 'IdP') || '',
    client_city: pickf(t, 'ClientCity') || '',
    client_country: pickf(t, 'ClientCountryCode') || '',
    policy_ms: num(pickf(t, 'PolicyProcessingTime'))
  };
}
// App Connector Status mapping confirmed from the live JSON feed on 2026-09-30.
function mapHealth(t) {
  return {
    ts: parseTs(t),
    connector: pickf(t, 'Connector', 'ConnectorName', 'Name') || '',
    connector_ip: pickf(t, 'ConnectorIP', 'PrivateIP', 'IP') || '',
    group_name: pickf(t, 'ConnectorGroup', 'AppConnectorGroup', 'GroupName') || '',
    cpu: fnum(pickf(t, 'CPUUtilization', 'CpuUtilization', 'CPU', 'Cpu')),
    mem: fnum(pickf(t, 'MemUtilization', 'MemoryUtilization', 'Memory', 'Mem')),
    disk: fnum(pickf(t, 'DiskUtilization', 'Disk')),
    bytes_rx: num(pickf(t, 'TotalBytesRx', 'BytesRx', 'BytesReceived', 'RxBytes')),
    bytes_tx: num(pickf(t, 'TotalBytesTx', 'BytesTx', 'BytesTransmitted', 'TxBytes')),
    version: pickf(t, 'Version', 'ConnectorVersion', 'SoftwareVersion') || '',
    status: pickf(t, 'SessionStatus', 'Status', 'ConnectorStatus', 'Health') || '',
    raw: JSON.stringify(t).slice(0, 4000)
  };
}

// ── 9600: User Activity (unchanged pipeline) ──
let pending = [];
let stats = { lines: 0, bad: 0, inserted: 0, conns: 0 };
function flush() {
  if (!pending.length) return;
  var batch = pending; pending = [];
  try { insMany(batch); stats.inserted += batch.length; }
  catch (e) {
    // Re-queue instead of dropping — a locked DB used to silently lose the whole
    // batch (2,146 batches lost by 2026-08-24). Cap the buffer and shed OLDEST
    // rows if the DB stays stuck (~20k rows is roughly 20 min of stream).
    pending = batch.concat(pending);
    if (pending.length > 20000) {
      var shed = pending.length - 20000;
      pending = pending.slice(shed);
      stats.shed = (stats.shed || 0) + shed;
      console.error('[lss] buffer cap hit, shed ' + shed + ' oldest rows (total shed ' + stats.shed + ')');
    }
    console.error('[lss] insert error (batch re-queued):', e.message);
  }
}
setInterval(flush, 1000).unref();
// WAL upkeep from the writer — the ONLY process that can truncate it. External
// checkpoints return busy while this process holds the write connection, which is
// how the WAL reached 7.3GB by 2026-08-24. Normal-case cost is <100ms/min; the
// busy_timeout above bounds the worst case at 5s.
setInterval(function () {
  try { db.pragma('wal_checkpoint(TRUNCATE)'); }
  catch (e) { console.error('[lss] wal_checkpoint error:', e.message); }
}, 60000).unref();

// Socket hygiene (CHG-ARCH-07, 2026-09-23). Node enables neither TCP keepalive nor an idle limit on
// accepted sockets, so a peer that vanished without FIN/RST (connector restart, NAT expiry) stayed
// "established" for ever: the previous lss process held 1,449 fds after 12 days against ~100 live
// streams. Keepalive (60 s idle, then the kernel's 9 probes x 75 s) reaps a dead peer in ~12 min;
// the idle limit closes a socket whose peer is alive but has sent nothing for IDLE_MS (0 = never).
const IDLE_MS = (function () { var v = parseInt(process.env.LSS_IDLE_MS, 10); return isNaN(v) ? 2 * 3600000 : Math.max(0, v); })();
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
  console.log('[lss] stream connected from', peer);
  guardSocket(sock, '[lss]', peer);
  var buf = '';
  sock.on('data', function (chunk) {
    buf += chunk.toString('utf8');
    if (buf.length > 8 * 1024 * 1024) { console.error('[lss] 8MB line guard tripped, dropping buffer'); buf = ''; return; }
    var idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      var line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
      if (!line) continue;
      stats.lines++;
      try {
        var o = JSON.parse(line);
        if (o && o.event && typeof o.event === 'object') o = o.event;
        pending.push(mapRecord(o));
        if (pending.length >= 200) flush();
      } catch (e) { stats.bad++; if (stats.bad <= 5) console.error('[lss] unparseable line (first 200 chars):', line.slice(0, 200)); }
    }
  });
  sock.on('error', function (e) { console.error('[lss] socket error', peer, e.message); });
  sock.on('close', function () { flush(); console.log('[lss] stream closed', peer); });
});
server.listen(PORT, '0.0.0.0', function () {
  console.log('[lss] User Activity listening on 0.0.0.0:' + PORT + ' -> ' + DB_PATH + ' (retain ' + RETAIN_DAYS + 'd)');
});

// ── 9601: App Connector Status (new; isolated) ──
let hPending = [];
let hStats = { lines: 0, bad: 0, inserted: 0, conns: 0, rawCaptured: 0 };
function hFlush() {
  if (!hPending.length) return;
  var batch = hPending; hPending = [];
  try { insCHMany(batch); hStats.inserted += batch.length; }
  catch (e) { console.error('[lss-ch] insert error:', e.message); }
}
setInterval(hFlush, 2000).unref();

function captureRaw(line) {
  if (hStats.rawCaptured >= STATUS_RAW_MAX) return;
  try {
    fs.mkdirSync(path.dirname(STATUS_RAW), { recursive: true });
    fs.appendFileSync(STATUS_RAW, new Date().toISOString() + ' ' + line + '\n');
    hStats.rawCaptured++;
    if (hStats.rawCaptured === STATUS_RAW_MAX) console.log('[lss-ch] raw capture complete (' + STATUS_RAW_MAX + ' records) -> ' + STATUS_RAW);
  } catch (e) { console.error('[lss-ch] raw capture error:', e.message); }
}

const statusServer = net.createServer(function (sock) {
  hStats.conns++;
  var peer = sock.remoteAddress + ':' + sock.remotePort;
  console.log('[lss-ch] status stream connected from', peer);
  guardSocket(sock, '[lss-ch]', peer);
  var buf = '';
  sock.on('data', function (chunk) {
    buf += chunk.toString('utf8');
    if (buf.length > 8 * 1024 * 1024) { console.error('[lss-ch] 8MB guard tripped'); buf = ''; return; }
    var idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      var line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
      if (!line) continue;
      hStats.lines++;
      captureRaw(line);
      try {
        var o = JSON.parse(line);
        if (o && o.event && typeof o.event === 'object') o = o.event;
        hPending.push(mapHealth(o));
        if (hPending.length >= 100) hFlush();
      } catch (e) { hStats.bad++; if (hStats.bad <= 5) console.error('[lss-ch] unparseable (first 200):', line.slice(0, 200)); }
    }
  });
  sock.on('error', function (e) { console.error('[lss-ch] socket error', peer, e.message); });
  sock.on('close', function () { hFlush(); console.log('[lss-ch] status stream closed', peer); });
});
statusServer.listen(STATUS_PORT, '0.0.0.0', function () {
  console.log('[lss-ch] App Connector Status listening on 0.0.0.0:' + STATUS_PORT + ' (raw->' + STATUS_RAW + ')');
});

// daily retention prune (both tables) + hourly stats
setInterval(function () {
  try {
    var cutoff = Date.now() - RETAIN_DAYS * 86400000;
    var r = db.prepare('DELETE FROM conns WHERE ts < ?').run(cutoff);
    var r2 = db.prepare('DELETE FROM connector_health WHERE ts < ?').run(cutoff);
    if (r.changes || r2.changes) console.log('[lss] pruned', r.changes, 'conns +', r2.changes, 'health older than', RETAIN_DAYS, 'd');
  } catch (e) { console.error('[lss] prune error:', e.message); }
}, 86400000).unref();
setInterval(function () {
  console.log('[lss] stats:', JSON.stringify(stats), '| ch:', JSON.stringify(hStats));
}, 3600000).unref();

process.on('SIGINT', function () { flush(); hFlush(); db.close(); process.exit(0); });
process.on('SIGTERM', function () { flush(); hFlush(); db.close(); process.exit(0); });
