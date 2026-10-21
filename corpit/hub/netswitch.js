'use strict';
/* ════════════════════════════════════════════════════════════════════
   /api/netswitch — Cisco switch fleet inventory (read-only)

   Serves the SNMP-polled switch cache for network-switches.html,
   network-health.html and device-trace.html. Data is produced out-of-band
   by /opt/corpit-netcollect (collect.py, fastpoll.py, healthscan.py,
   watchpoll.py, apmoves.py — SNMPv2c RO on corpit-net* systemd timers)
   into a SQLite cache. This route only READS that cache — it never talks
   to switches directly, so page loads are instant and never hit the
   network gear. The one exception is /locate, which spawns locate.py for
   a live per-port walk on demand.

   Cache: /var/www/corpit-hub-api/data/netfleet.db  (WAL; opened read-only here)

   Mount (server.js):  app.use('/api/netswitch',
                        require('./netswitch')({ requirePage: rbacGate.requirePage }));
   Behind the blanket /api auth gate (logged-in users), like /api/netdiag.
   ════════════════════════════════════════════════════════════════════ */

const express = require('express');
const path    = require('path');
const Database = require('better-sqlite3');
const offload  = require('./sqlite-offload');   // read-only SQLite off the event loop
const { attachIssueActivity } = require('./netswitch-activity');
const { execFile } = require('child_process');
const mysql = require('mysql2/promise');
let _assetPool = null;
function assetPool() {
  if (!_assetPool) _assetPool = mysql.createPool({
    host: process.env.DB_HOST, port: +process.env.DB_PORT || 3306,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: 'it_inventory', connectionLimit: 3, charset: 'utf8mb4' });
  return _assetPool;
}
// locate.py reads the SNMP community from /etc/corpit/netcollect.env itself:
// it is spawned here rather than by systemd, so no EnvironmentFile is in scope.
const LOCATE_PY = process.env.NET_LOCATE || '/opt/corpit-netcollect/locate.py';

const DB_PATH = process.env.NET_DB || '/var/www/corpit-hub-api/data/netfleet.db';

function openDbRW() {
  // watch list + claims are the one thing the UI writes. Their tables are created by
  // migrate.js at deploy time (schema/migrations.js), never here (CHG-ARCH-18);
  // fileMustExist because an empty file created here would hold none of them.
  const db = new Database(DB_PATH, { fileMustExist: true });
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = FULL');
  if (db.pragma('synchronous', { simple: true }) !== 2) {
    db.close();
    throw new Error('SQLite writer requires synchronous=FULL');
  }
  return db;
}

function openDb() {
  // readonly; fileMustExist so a missing cache surfaces as a clean 503
  return new Database(DB_PATH, { readonly: true, fileMustExist: true });
}

function parseDiag(rows) {
  for (const r of rows) {
    if (r && typeof r.diag === 'string') {
      try { r.diag = JSON.parse(r.diag); } catch (_) { r.diag = null; }
    }
  }
  return rows;
}

function readMeta(db) {
  const rows = db.prepare('SELECT k, v FROM net_meta').all();
  const m = {};
  for (const { k, v } of rows) m[k] = v;
  return {
    last_run:     m.last_run ? Number(m.last_run) : null,
    last_run_iso: m.last_run ? new Date(Number(m.last_run) * 1000).toISOString() : null,
    run_ms:       m.run_ms ? Number(m.run_ms) : null,
    device_count: m.device_count ? Number(m.device_count) : 0,
    reachable:    m.reachable ? Number(m.reachable) : 0,
    seeds:        m.seeds || '',
    community_ok: m.community_ok === '1',
    age_seconds:  m.last_run ? Math.round(Date.now() / 1000 - Number(m.last_run)) : null,
  };
}

module.exports = function buildNetswitchRouter(deps) {
  const router = express.Router();

  // [CORPIT-QA 2026-09-05] Honour the gate server.js passes (always
  //   { requirePage: rbacGate.requirePage }). Mirrors netdiag.js. Previously
  //   buildNetswitchRouter took no args, so all routes ran unguarded.
  const gate = deps && typeof deps.requirePage === 'function'
    ? deps.requirePage('network-diag')
    : (req, res, next) => next();
  router.use(gate);

  // /watch* and /claims* read and write the hub-owned tables in netfleet.db; they
  // answer 503 when those do not satisfy schema/contract.js (CHG-ARCH-18).
  router.use(['/watch', '/claims'], require('./schema/readiness').requireSchema('netfleet'));

  // The gate above is read-level. The four routes below mutate the cache, so
  // they take an admin gate as well: holding read on this page must not carry
  // authority to claim a port issue or pin a watch entry.
  const gateAdmin = deps && typeof deps.requirePage === 'function'
    ? deps.requirePage('network-diag', 'admin')
    : (req, res, next) => next();

  // GET /api/netswitch/fleet — full inventory + collector meta
  router.get('/fleet', (req, res) => {
    let db;
    try {
      db = openDb();
      const devices = db.prepare(
        `SELECT ip, name, site, model, serial, ios, uptime_days,
                if_total, if_up, core, location, reachable, ios_current, last_seen, error
           FROM net_switches
          ORDER BY site ASC, core DESC, name ASC`
      ).all();
      const meta = readMeta(db);
      res.json({ ok: true, meta, count: devices.length, devices });
    } catch (e) {
      if (e && e.code === 'SQLITE_CANTOPEN') {
        return res.status(503).json({ ok: false, error: 'CACHE_UNAVAILABLE',
          detail: 'switch cache not built yet — collector has not run' });
      }
      res.status(500).json({ ok: false, error: 'READ_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // GET /api/netswitch/health — collector freshness only (cheap)
  router.get('/health', (req, res) => {
    let db;
    try {
      db = openDb();
      const meta = readMeta(db);
      const stale = meta.age_seconds != null && meta.age_seconds > 1800; // >30min
      res.json({ ok: true, stale, meta });
    } catch (e) {
      res.status(503).json({ ok: false, error: 'CACHE_UNAVAILABLE', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // GET /api/netswitch/device/:ip — one device + recent port samples (sparkline)
  router.get('/device/:ip', (req, res) => {
    let db;
    try {
      db = openDb();
      const dev = db.prepare('SELECT * FROM net_switches WHERE ip = ?').get(req.params.ip);
      if (!dev) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
      const samples = db.prepare(
        'SELECT ts, if_up, if_total FROM net_samples WHERE ip = ? ORDER BY ts ASC'
      ).all(req.params.ip);
      res.json({ ok: true, device: dev, samples });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'READ_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // GET /api/netswitch/locate?q=<ip|mac> — find which switch/port/VLAN a device is on
  router.get('/locate', (req, res) => {
    const q = String(req.query.q || '').trim();
    if (!q) return res.status(400).json({ ok: false, error: 'BAD_INPUT', detail: 'q (IP or MAC) required' });
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$/.test(q))
      return res.status(400).json({ ok: false, error: 'BAD_INPUT', detail: 'q must be an IP, MAC, or device name' });
    execFile('python3', [LOCATE_PY, q], { timeout: 25000 }, (err, stdout, stderr) => {
      if (err) return res.status(504).json({ ok: false, error: 'LOCATE_FAILED',
        detail: String(stderr || err.message).slice(0, 300) });
      try { return res.json(JSON.parse(stdout)); }
      catch (e) { return res.status(500).json({ ok: false, error: 'BAD_OUTPUT', detail: e.message }); }
    });
  });

  // GET /api/netswitch/overview — Network Health panel: switches, port issues, scan meta
  router.get('/overview', (req, res) => {
    let db;
    try {
      db = openDb();
      const devices = db.prepare(
        `SELECT ip,name,site,model,serial,ios,uptime_days,if_total,if_up,core,location,
                reachable,ios_current,last_seen FROM net_switches ORDER BY site,core DESC,name`).all();
      let issues = [], scan = {}, counts = null;
      let scanError = false, activityError = false;
      try {
        // The list is paged. The counts are not: a caller rendering
        // issues.length as "all faults" would be short by whatever the cap cut.
        const ISSUE_LIMIT = 1000;
        issues = db.prepare(
          `SELECT switch,switch_ip,ifindex,port,descr,severity,kind,detail,diag,in_err,out_err,crc,out_disc,oper,ts
             FROM net_port_issues
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END,
                     crc DESC, in_err DESC LIMIT ?`).all(ISSUE_LIMIT);
        counts = { critical:0, warn:0, info:0, total:0,
                   returned:issues.length, limit:ISSUE_LIMIT, capped:false };
        for (const r of db.prepare(
               'SELECT severity, COUNT(*) n FROM net_port_issues GROUP BY severity').all()) {
          if (counts[r.severity] == null) counts[r.severity] = 0;
          counts[r.severity] += r.n;
          counts.total += r.n;
        }
        counts.capped = counts.total > issues.length;
        parseDiag(issues);
        // This is a sampled trend, not a live switch query. Keep it distinct
        // from the collector's severity, which uses lifetime counter values.
        const now = Math.floor(Date.now() / 1000);
        try {
          const samples = db.prepare(
            `SELECT s.switch_ip,s.ifindex,s.ts,s.oper,s.in_err,s.out_err,s.crc,s.out_disc
               FROM net_port_stats s
               JOIN net_port_issues i
                 ON i.switch_ip=s.switch_ip AND i.ifindex=s.ifindex
              WHERE s.ts >= ?`).all(now - 7200);
          attachIssueActivity(issues, samples, now);
        } catch (_) {
          // Older caches can lack history; retain findings and scan metadata.
          activityError = true;
          attachIssueActivity(issues, [], now);
        }
        const m = db.prepare('SELECT k,v FROM net_scan_meta').all();
        for (const {k,v} of m) scan[k] = /^\d+$/.test(v) ? Number(v) : v;
      } catch (_) { scanError = true; }
      const meta = readMeta(db);
      const up = devices.filter(d => d.reachable).length;
      const ports = devices.reduce((a,d)=>a+(d.if_total||0),0);
      const portsUp = devices.reduce((a,d)=>a+(d.if_up||0),0);
      res.json({ ok:true, meta,
        summary:{ switches:devices.length, switches_up:up, switches_down:devices.length-up,
                  ports, ports_up:portsUp,
                  sites:[...new Set(devices.map(d=>d.site).filter(Boolean))],
                  // from the table, not from the capped page above
                  critical:counts?counts.critical:issues.filter(i=>i.severity==='critical').length,
                  warn:counts?counts.warn:issues.filter(i=>i.severity==='warn').length,
                  info:counts?counts.info:issues.filter(i=>i.severity==='info').length,
                  scan_age: scan.last_scan ? Math.round(Date.now()/1000 - scan.last_scan) : null },
        scan, scan_error:scanError, activity_error:activityError, devices, issues, counts });
    } catch (e) {
      if (e && e.code === 'SQLITE_CANTOPEN')
        return res.status(503).json({ ok:false, error:'CACHE_UNAVAILABLE' });
      res.status(500).json({ ok:false, error:'READ_FAILED', detail:e.message });
    } finally { if (db) try { db.close(); } catch(_){} }
  });

  // GET /api/netswitch/fw-health — both FortiGates: status, resources, tunnels.
  // Proxies the existing /api/netdiag FortiGate readers so Network Health can
  // show firewall vitals without the page making six separate calls.
  router.get('/fw-health', async (req, res) => {
    const base = process.env.INTERNAL_API_BASE || 'http://127.0.0.1:3001';
    const auth = req.headers.authorization || '';
    const cookie = req.headers.cookie || '';
    const grab = async (fw, path) => {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 9000);
      try {
        const r = await fetch(`${base}/api/netdiag/fortigate/${path}?fw=${fw}`, {
          headers: { ...(auth ? { Authorization: auth } : {}), ...(cookie ? { Cookie: cookie } : {}) },
          signal: ctrl.signal });
        const j = await r.json().catch(() => null);
        // A probe that could not be read is an error object, not null: null used to
        // collapse 'the reader is down' into 'the firewall is down' (reachable:false).
        const pick = (v) => typeof v === 'string' ? v : (v && typeof v === 'object' ? (pick(v.message) || pick(v.detail) || pick(v.error) || JSON.stringify(v)) : (v == null ? '' : String(v)));
        if (!r.ok || !j || j.ok === false) return { __err: (j && (pick(j.detail) || pick(j.error))) || ('HTTP ' + r.status) };
        return j.data || j;
      } catch (e) { return { __err: e && e.name === 'AbortError' ? 'timed out after 9s' : ((e && e.message) || String(e)) }; } finally { clearTimeout(t); }
    };
    const sites = [
      { key: 'irvine', name: 'Irvine FortiGate', site: 'SNA01', host: '10.20.6.4' },
      { key: 'dallas', name: 'Dallas FortiGate', site: 'DFW02', host: '10.19.6.4' },
    ];
    const out = await Promise.all(sites.map(async s => {
      const probes = await Promise.all([
        grab(s.key, 'status'), grab(s.key, 'resources'), grab(s.key, 'tunnels')]);
      const errs = probes.filter(p => p && p.__err).map(p => p.__err);
      const [status, resources, tun] = probes.map(p => (p && p.__err) ? null : p);
      const tunnels = (tun && tun.tunnels) || [];
      const upT = tunnels.filter(t => /up|established/i.test(String(t.status || t.state || ''))).length;
      // reachable: true = answered; false = answered but empty; null = every probe failed
      // (reader down, no credentials, timeout) -- the page shows that as 'unknown'.
      return { ...s, reachable: (status || resources) ? true : (errs.length === 3 ? null : false),
        error: errs.length ? errs[0] : undefined,
        hostname: status && status.hostname, model: status && status.model,
        version: status && status.version, serial: status && status.serial,
        cpu: resources && resources.cpu, mem: resources && resources.mem,
        sessions: resources && resources.sessions,
        // null when the tunnel probe itself failed: 0/0 would read as 'no tunnels', which was not measured
        tunnels_total: tun ? tunnels.length : null, tunnels_up: tun ? upT : null,
        tunnels: tunnels.slice(0, 12) };
    }));
    res.json({ ok: true, firewalls: out });
  });

  /* Throughput is not a stored value — it is the slope between the two most
     recent counter samples fastpoll.py wrote for a port. Anything that would
     make that slope a lie (one sample only, a gap wider than an hour, or a
     counter that went backwards because the switch rebooted) yields no figure
     at all rather than a wrong one. */
  const RATE_WINDOW  = 3 * 3600;  // how far back to look for a pair of samples
  const RATE_MAX_DT  = 3600;      // samples further apart than this are not a rate
  const RATE_MAX_AGE = 2400;      // a rate older than this is history, not a reading
  function attachThroughput(db, ip, ports) {
    const now = Math.floor(Date.now() / 1000);
    let pairs;
    try {
      pairs = db.prepare(
        `SELECT ifindex, ts, in_oct, out_oct FROM net_port_stats
          WHERE switch_ip = ? AND ts >= ? AND in_oct IS NOT NULL AND out_oct IS NOT NULL
          ORDER BY ifindex, ts DESC`).all(ip, now - RATE_WINDOW);
    } catch (_) { return; }        // pre-migration DB: no octet columns, no rate
    const newest = new Map();
    for (const r of pairs) {
      const seen = newest.get(r.ifindex);
      if (!seen) newest.set(r.ifindex, [r]);
      else if (seen.length < 2) seen.push(r);
    }
    const rate = new Map();
    for (const [ifx, s] of newest) {
      if (s.length < 2) continue;
      // fastpoll stops sampling a port once it goes dark, so its last good pair
      // sits there indefinitely. Without an age check the API would keep serving
      // that frozen number as though the port were still passing traffic.
      if (now - s[0].ts > RATE_MAX_AGE) continue;
      const dt = s[0].ts - s[1].ts;                       // DESC, so [0] is newest
      if (dt <= 0 || dt > RATE_MAX_DT) continue;
      const din = s[0].in_oct - s[1].in_oct;
      const dout = s[0].out_oct - s[1].out_oct;
      if (din < 0 || dout < 0) continue;                  // counters reset
      // both directions are reported separately as well as combined: on a
      // full-duplex link they are independent capacity, so the sum alone can
      // read above the port's own speed and invites a bogus utilisation figure
      rate.set(ifx, { bps: Math.round((din + dout) * 8 / dt),
                      bps_in: Math.round(din * 8 / dt),
                      bps_out: Math.round(dout * 8 / dt),
                      bps_window: dt,                     // the REAL interval, not the cap
                      bps_age: now - s[0].ts });
    }
    for (const p of ports) {
      const v = rate.get(String(p.ifindex));
      if (v) Object.assign(p, v);
    }
  }

  /* GET /api/netswitch/trend?days=1|7|30
     Fleet-wide error history for the overview chart. net_port_stats already
     keeps 30 days of hourly counter snapshots, so this is a read of data that
     has been accumulating all along — nothing here is synthesised. Each bucket
     counts DISTINCT ports whose error counters rose during that hour, which is
     the number a NOC actually cares about ("how many ports went bad"), not a
     sum of counters that one flapping port can dominate.

     The aggregate is one SQL window statement run in a worker thread
     (sqlite-offload). It replaced a loop that pulled ~490k rows onto the main
     thread for 2.5s per view, during which nothing else in this process — the
     nginx auth gate included — was answered. Verified identical to that loop
     on 1/7/30-day windows before it shipped (2026-09-23). Days is clamped to
     the three buttons the page offers, so the 60s cache holds three entries. */
  const TREND_DAYS = [1, 7, 30];
  const trendSql = (bucket) => `
    WITH s AS (
      SELECT (ts / ${bucket}) * ${bucket} AS k,
             switch_ip || ':' || ifindex AS port,
             (in_err - LAG(in_err) OVER w) + (out_err - LAG(out_err) OVER w) + (crc - LAG(crc) OVER w) AS d,
             out_disc - LAG(out_disc) OVER w AS dd
        FROM net_port_stats
       WHERE ts >= ?
      WINDOW w AS (PARTITION BY switch_ip, ifindex ORDER BY ts))
    SELECT k AS ts,
           COUNT(DISTINCT CASE WHEN d  > 0 THEN port END) AS errors,
           COUNT(DISTINCT CASE WHEN dd > 0 THEN port END) AS discards
      FROM s WHERE d > 0 OR dd > 0
     GROUP BY k ORDER BY k`;

  router.get('/trend', async (req, res) => {
    const want = parseInt(req.query.days, 10);
    const days = TREND_DAYS.includes(want) ? want : 7;
    const bucket = days > 2 ? 21600 : 3600;          // 6h buckets for a week view
    const now = Math.floor(Date.now() / 1000);
    const since = now - days * 86400;
    const r = await offload.query(DB_PATH, [
      { sql: trendSql(bucket), params: [since] },
      { sql: 'SELECT COUNT(*) n FROM net_port_stats WHERE ts >= ?', params: [since], mode: 'get' },
    ], { cacheKey: 'netswitch:trend:' + days, cacheTtlMs: 60000, timeoutMs: 20000, label: 'Port-error trend' });
    if (!r.ok) {
      if (/no such table/i.test(r.error)) return res.json({ ok: true, days, series: [] });
      return res.status(r.status || 500).json({ ok: false, error: 'READ_FAILED', detail: r.error });
    }
    const got = new Map(r.results[0].map((b) => [b.ts, b]));
    // emit an unbroken series so the chart cannot imply a gap is a zero
    const out = [];
    const start = Math.floor(since / bucket) * bucket;
    const end = Math.floor(now / bucket) * bucket;
    for (let k = start; k <= end; k += bucket) {
      const b = got.get(k);
      out.push({ ts: k, errors: b ? b.errors : 0, discards: b ? b.discards : 0 });
    }
    res.json({ ok: true, days, bucket_seconds: bucket, samples: r.results[1].n, series: out,
               took_ms: r.tookMs, cached_at: r.cachedAt || null });
  });

  // ── drill-down: one switch, its ports, and what is plugged into them ──
  // GET /api/netswitch/switch/:ip
  router.get('/switch/:ip', (req, res) => {
    let db;
    try {
      db = openDb();
      const dev = db.prepare('SELECT * FROM net_switches WHERE ip = ?').get(req.params.ip);
      if (!dev) return res.status(404).json({ ok:false, error:'NOT_FOUND' });
      let ports = [];
      try {
        // duplex arrived after this table did. Ask the schema instead of naming
        // the column blind: a hard SELECT would throw on an un-migrated DB and
        // the catch below would silently return an EMPTY port list.
        const hasDuplex = db.prepare('PRAGMA table_info(net_ports)').all()
                            .some(c => c.name === 'duplex');
        ports = db.prepare(
          `SELECT p.ifindex,p.port,p.descr,p.oper,p.admin,p.speed,p.in_err,p.out_err,p.crc,
                  p.out_disc,p.mac_count, p.diag AS diag, i.severity AS severity` +
                  (hasDuplex ? ', p.duplex AS duplex' : '') + `
             FROM net_ports p
             LEFT JOIN net_port_issues i
                    ON i.switch_ip = p.switch_ip AND i.ifindex = p.ifindex
            WHERE p.switch_ip = ? ORDER BY p.port`).all(req.params.ip);
        parseDiag(ports);
        attachThroughput(db, req.params.ip, ports);
      } catch (_) {}
      let clients = 0;
      try { clients = db.prepare('SELECT COUNT(DISTINCT mac) c FROM net_cam WHERE switch_ip = ?')
                        .get(req.params.ip).c; } catch (_) {}
      res.json({ ok:true, device:dev, ports, clients });
    } catch (e) {
      res.status(500).json({ ok:false, error:'READ_FAILED', detail:e.message });
    } finally { if (db) try { db.close(); } catch(_){} }
  });

  // GET /api/netswitch/clients?switch_ip=&ifindex=   — devices seen on a switch / port
  router.get('/clients', (req, res) => {
    const sw = String(req.query.switch_ip || '').trim();
    const ifx = req.query.ifindex != null ? String(req.query.ifindex) : null;
    if (!sw) return res.status(400).json({ ok:false, error:'BAD_INPUT', detail:'switch_ip required' });
    let db;
    try {
      db = openDb();
      const args = ifx ? [sw, ifx] : [sw];
      const rows = db.prepare(
        `SELECT c.mac, c.port, c.vlan, c.ifindex, a.ip AS ip, s.first_seen, s.last_seen
           FROM net_cam c
           LEFT JOIN net_arp a ON a.mac = c.mac
           LEFT JOIN net_cam_seen s ON s.mac = c.mac AND s.switch_ip = c.switch_ip AND s.port = c.port
          WHERE c.switch_ip = ?` + (ifx ? ' AND c.ifindex = ?' : '') + `
          ORDER BY c.port, c.mac`).all(...args);
      res.json({ ok:true, count:rows.length, clients:rows });
    } catch (e) {
      if (/no such table/i.test(e.message))
        return res.json({ ok:true, count:0, clients:[], note:'CAM not collected yet' });
      res.status(500).json({ ok:false, error:'READ_FAILED', detail:e.message });
    } finally { if (db) try { db.close(); } catch(_){} }
  });

  // GET /api/netswitch/history?switch_ip=&ifindex=&hours=72  — counter series for a port
  router.get('/history', (req, res) => {
    const sw = String(req.query.switch_ip || '').trim();
    const ifx = String(req.query.ifindex || '').trim();
    const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 72, 1), 24 * 30);
    if (!sw || !ifx) return res.status(400).json({ ok:false, error:'BAD_INPUT',
      detail:'switch_ip and ifindex required' });
    let db;
    try {
      db = openDb();
      const since = Math.floor(Date.now()/1000) - hours*3600;
      const rows = db.prepare(
        `SELECT ts,oper,in_err,out_err,crc,out_disc FROM net_port_stats
          WHERE switch_ip=? AND ifindex=? AND ts>=? ORDER BY ts`).all(sw, ifx, since);
      // deltas make a rising counter readable
      const series = rows.map((r, i) => {
        const p = i ? rows[i-1] : null;
        return { ...r, d_in_err: p ? Math.max(0, r.in_err - p.in_err) : 0,
                       d_out_err: p ? Math.max(0, r.out_err - p.out_err) : 0,
                       d_crc: p ? Math.max(0, r.crc - p.crc) : 0 };
      });
      res.json({ ok:true, hours, count:series.length, series });
    } catch (e) {
      if (/no such table/i.test(e.message)) return res.json({ ok:true, hours, count:0, series:[] });
      res.status(500).json({ ok:false, error:'READ_FAILED', detail:e.message });
    } finally { if (db) try { db.close(); } catch(_){} }
  });

  // GET /api/netswitch/mac/:mac?hours=72 — where this device has been
  router.get('/mac/:mac', (req, res) => {
    const mac = String(req.params.mac || '').toLowerCase();
    const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 72, 1), 24 * 30);
    let db;
    try {
      db = openDb();
      const since = Math.floor(Date.now()/1000) - hours*3600;
      let places = [], ips = [];
      try {
        places = db.prepare(
          `SELECT s.switch_ip, w.name AS switch, s.port, s.vlan, s.first_seen, s.last_seen
             FROM net_cam_seen s LEFT JOIN net_switches w ON w.ip = s.switch_ip
            WHERE s.mac = ? AND s.last_seen >= ? ORDER BY s.last_seen DESC`).all(mac, since);
      } catch (_) {}
      try {
        ips = db.prepare(
          `SELECT ip, first_seen, last_seen FROM net_arp_seen
            WHERE mac = ? AND last_seen >= ? ORDER BY last_seen DESC`).all(mac, since);
      } catch (_) {}
      res.json({ ok:true, mac, hours, places, ips });
    } catch (e) {
      res.status(500).json({ ok:false, error:'READ_FAILED', detail:e.message });
    } finally { if (db) try { db.close(); } catch(_){} }
  });

  // ── watch list: pin a port / device / AP and sample it every few minutes ──
  const WATCH_KINDS = new Set(['port', 'device', 'ap']);

  // GET /api/netswitch/watch — everything pinned, newest sample + recent events
  router.get('/watch', (req, res) => {
    let db;
    try {
      db = openDbRW();
      const items = db.prepare('SELECT * FROM net_watch WHERE active=1 ORDER BY created_at DESC').all();
      const lastS = db.prepare('SELECT data, ts FROM net_watch_samples WHERE watch_id=? ORDER BY ts DESC LIMIT 1');
      const evs   = db.prepare('SELECT ts,severity,kind,message FROM net_watch_events WHERE watch_id=? ORDER BY ts DESC LIMIT 12');
      const cnt   = db.prepare('SELECT COUNT(*) c, MIN(ts) first FROM net_watch_samples WHERE watch_id=?');
      for (const it of items) {
        const s = lastS.get(it.id);
        it.last = s ? (() => { try { return JSON.parse(s.data); } catch (_) { return null; } })() : null;
        it.last_ts = s ? s.ts : null;
        it.events = evs.all(it.id);
        const c = cnt.get(it.id);
        it.samples = c.c; it.since = c.first;
        try { it.meta = it.meta ? JSON.parse(it.meta) : null; } catch (_) {}
      }
      res.json({ ok: true, count: items.length, items });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'READ_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // POST /api/netswitch/watch  { kind, ref, label, meta }
  router.post('/watch', gateAdmin, express.json(), (req, res) => {
    const b = req.body || {};
    const kind = String(b.kind || '').toLowerCase();
    const ref  = String(b.ref || '').trim();
    const REF_SHAPE = {
      port:   /^\d{1,3}(\.\d{1,3}){3}:\d{1,10}$/,          // <switch ip>:<ifindex>
      device: /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})$/,  // ip or mac
      ap:     /^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/            // meraki serial
    };
    if (!WATCH_KINDS.has(kind))
      return res.status(400).json({ ok: false, error: 'BAD_INPUT', detail: 'kind must be port, device or ap' });
    if (!ref || !REF_SHAPE[kind].test(ref))
      return res.status(400).json({ ok: false, error: 'BAD_INPUT',
        detail: kind === 'port' ? 'port ref must be <switch-ip>:<ifindex>'
              : kind === 'device' ? 'device ref must be an IP or MAC'
              : 'ap ref must be a serial' });
    let db;
    try {
      db = openDbRW();
      const who = (req.user && (req.user.email || req.user.upn || req.user.name)) || 'unknown';
      db.prepare(`INSERT INTO net_watch(kind,ref,label,meta,created_by,created_at,active)
                  VALUES(?,?,?,?,?,?,1)
                  ON CONFLICT(kind,ref) DO UPDATE SET active=1, label=excluded.label, meta=excluded.meta`)
        .run(kind, ref, String(b.label || ref).slice(0, 160),
             b.meta ? JSON.stringify(b.meta) : null, who, Math.floor(Date.now() / 1000));
      const row = db.prepare('SELECT * FROM net_watch WHERE kind=? AND ref=?').get(kind, ref);
      res.json({ ok: true, item: row });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'WRITE_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // DELETE /api/netswitch/watch/:id — unpin (history is kept)
  router.delete('/watch/:id', gateAdmin, (req, res) => {
    let db;
    try {
      db = openDbRW();
      db.prepare('UPDATE net_watch SET active=0 WHERE id=?').run(req.params.id);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'WRITE_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // GET /api/netswitch/watch/:id/history?hours=72 — dense samples + events
  router.get('/watch/:id/history', (req, res) => {
    const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 72, 1), 24 * 120);
    let db;
    try {
      db = openDbRW();
      const since = Math.floor(Date.now() / 1000) - hours * 3600;
      const rows = db.prepare('SELECT ts,data FROM net_watch_samples WHERE watch_id=? AND ts>=? ORDER BY ts')
                     .all(req.params.id, since);
      const samples = rows.map(r => { let d = null; try { d = JSON.parse(r.data); } catch (_) {} return { ts: r.ts, ...d }; });
      const events = db.prepare('SELECT ts,severity,kind,message FROM net_watch_events WHERE watch_id=? AND ts>=? ORDER BY ts DESC')
                       .all(req.params.id, since);
      res.json({ ok: true, hours, count: samples.length, samples, events });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'READ_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // GET /api/netswitch/resolve-asset?q=<device name|serial|hostname>
  // Macs are not in AD DNS, so a device name alone cannot be traced. Kandji does
  // know each Mac's MAC address — that is the stable key we can find on the
  // switch fabric. Intune/iPad inventory is checked the same way.
  router.get('/resolve-asset', async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (!q || q.length > 128)
      return res.status(400).json({ ok: false, error: 'BAD_INPUT', detail: 'q required' });
    try {
      const p = assetPool();
      const like = q;
      const [macs] = await p.query(
        `SELECT device_name, serial, local_hostname, mac_address, ip_address, user_name, 'kandji' AS src
           FROM macbooks
          WHERE device_name = ? OR serial = ? OR local_hostname = ?
          LIMIT 5`, [like, like, like]);
      const [ipads] = await p.query(
        `SELECT device_name, serial, NULL AS local_hostname, NULL AS mac_address, NULL AS ip_address,
                user_name, 'kandji-ipad' AS src
           FROM ipad_devices WHERE device_name = ? OR serial = ? LIMIT 5`, [like, like]);
      const [win] = await p.query(
        `SELECT device_name, serial_number AS serial, NULL AS local_hostname, NULL AS mac_address,
                NULL AS ip_address, primary_user_name AS user_name, 'intune' AS src
           FROM intune_devices WHERE device_name = ? OR serial_number = ? LIMIT 5`, [like, like]);
      let hits = [...macs, ...ipads, ...win];
      // nothing exact? try a contains match before giving up — people type partial names
      if (!hits.length) {
        const [m2] = await p.query(
          `SELECT device_name, serial, local_hostname, mac_address, ip_address, user_name, 'kandji' AS src
             FROM macbooks
            WHERE device_name LIKE CONCAT('%', ?, '%') OR local_hostname LIKE CONCAT('%', ?, '%')
            LIMIT 5`, [like, like]);
        const [w2] = await p.query(
          `SELECT device_name, serial_number AS serial, NULL AS local_hostname, NULL AS mac_address,
                  NULL AS ip_address, primary_user_name AS user_name, 'intune' AS src
             FROM intune_devices WHERE device_name LIKE CONCAT('%', ?, '%') LIMIT 5`, [like]);
        hits = [...m2, ...w2];
      }
      const best = hits.find(h => h.mac_address) || hits.find(h => h.ip_address) || hits[0] || null;
      res.json({ ok: true, query: q, count: hits.length, best, hits,
                 traceable: !!(best && (best.mac_address || best.ip_address)) });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'LOOKUP_FAILED', detail: e.message });
    }
  });

  // GET /api/netswitch/correlate?mac=&ip=
  // "Is it just this device, or is something shared broken?" Finds other devices
  // that sit on the same port / switch / VLAN and are currently faulting, so a
  // single user's complaint can be recognised as a shared cause.
  router.get('/correlate', (req, res) => {
    const mac = String(req.query.mac || '').toLowerCase().trim();
    const ip  = String(req.query.ip  || '').trim();
    if (!mac && !ip)
      return res.status(400).json({ ok: false, error: 'BAD_INPUT', detail: 'mac or ip required' });
    let db;
    try {
      db = openDb();
      let m = mac;
      if (!m && ip) {
        const r = db.prepare('SELECT mac FROM net_arp WHERE ip = ?').get(ip);
        m = r ? String(r.mac).toLowerCase() : '';
      }
      if (!m) return res.json({ ok: true, subject: null, peers: [], verdict: null,
                                note: 'device not currently in ARP, nothing to correlate' });

      // where the subject sits (prefer an edge port over an uplink)
      const spots = db.prepare(
        `SELECT c.switch_ip, c.switch, c.ifindex, c.port, c.vlan
           FROM net_cam c WHERE c.mac = ?`).all(m);
      const edge = spots.find(x => !/^(po|te|fo|hu|twe)/i.test(x.port || '')) || spots[0] || null;
      if (!edge) return res.json({ ok: true, subject: { mac: m }, peers: [], verdict: null,
                                   note: 'device not currently learned on a switch port' });

      const samePort = db.prepare(
        `SELECT c.mac, a.ip FROM net_cam c LEFT JOIN net_arp a ON a.mac = c.mac
          WHERE c.switch_ip = ? AND c.ifindex = ? AND c.mac != ?`).all(edge.switch_ip, edge.ifindex, m);

      const switchIssues = db.prepare(
        `SELECT port, descr, severity, kind, detail, diag, ifindex
           FROM net_port_issues
          WHERE switch_ip = ? AND severity IN ('critical','warn')
          ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END LIMIT 40`).all(edge.switch_ip);
      parseDiag(switchIssues);

      // which of those faulty ports actually have devices on them (real user impact)
      const impacted = [];
      const devOn = db.prepare(
        `SELECT c.mac, a.ip FROM net_cam c LEFT JOIN net_arp a ON a.mac = c.mac
          WHERE c.switch_ip = ? AND c.ifindex = ? LIMIT 6`);
      for (const it of switchIssues) {
        const devs = devOn.all(edge.switch_ip, it.ifindex);
        if (devs.length) impacted.push({ ...it, devices: devs });
      }

      const sameVlan = db.prepare(
        `SELECT DISTINCT i.switch, i.port, i.descr, i.severity, i.kind
           FROM net_port_issues i
           JOIN net_cam c ON c.switch_ip = i.switch_ip AND c.ifindex = i.ifindex
          WHERE c.vlan = ? AND i.severity IN ('critical','warn') AND i.switch_ip != ?
          LIMIT 20`).all(edge.vlan, edge.switch_ip);

      let watched = [];
      try {
        watched = db.prepare(
          `SELECT kind, ref, label FROM net_watch WHERE active=1`).all();
      } catch (_) {}

      // synthesise the headline
      let verdict = null;
      const kinds = {};
      for (const it of impacted) kinds[it.kind] = (kinds[it.kind] || 0) + 1;
      const topKind = Object.keys(kinds).sort((a, b) => kinds[b] - kinds[a])[0];
      const subjectFaulting = impacted.some(i => String(i.ifindex) === String(edge.ifindex));
      if (impacted.length >= 2 && topKind) {
        verdict = subjectFaulting ? {
          severity: impacted.some(i => i.severity === 'critical') ? 'critical' : 'warn',
          scope: 'switch', shared: true,
          title: `This is not just this device — ${impacted.length} ports on ${edge.switch} are faulting`,
          detail: `The same class of fault (${topKind}) appears on ${impacted.length} ports of this switch, ` +
                  `including this one. Look at the switch, its uplink, or a shared cabling path before ` +
                  `replacing anything on the desk.`
        } : {
          severity: 'warn', scope: 'switch', shared: false,
          title: `${impacted.length} other ports on ${edge.switch} are faulting`,
          detail: `This device's own port is clean, but neighbours on the same switch are not (mostly ${topKind}). ` +
                  `Worth knowing if the complaint is intermittent or shared.`
        };
      } else if (samePort.length && impacted.some(i => String(i.ifindex) === String(edge.ifindex))) {
        verdict = { severity: 'warn', scope: 'port',
          title: `Other devices share this port`,
          detail: `${samePort.length} other device(s) are learned on ${edge.port}. A fault here hits all of them.` };
      } else if (sameVlan.length >= 3) {
        verdict = { severity: 'warn', scope: 'vlan',
          title: `VLAN ${edge.vlan} has faults on other switches too`,
          detail: `${sameVlan.length} ports carrying this VLAN are faulting elsewhere — look at the VLAN path, not the endpoint.` };
      }

      res.json({ ok: true, subject: { mac: m, ip: ip || null, ...edge, faulting: subjectFaulting },
                 same_port: samePort, switch_issues: impacted, same_vlan: sameVlan,
                 watched, verdict });
    } catch (e) {
      if (/no such table/i.test(e.message))
        return res.json({ ok: true, subject: null, peers: [], verdict: null, note: 'not collected yet' });
      res.status(500).json({ ok: false, error: 'READ_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // ── Wi-Fi roaming map ────────────────────────────────────────────────
  // Meraki holds georeferenced floor plans and places every AP on them, so a
  // client's AP-association history can be drawn as an actual path through the
  // building instead of a list of AP names.
  const MERAKI_B = 'https://api.meraki.com/api/v1';
  function mkHeaders() { return { 'X-Cisco-Meraki-API-Key': process.env.MERAKI_API_KEY }; }
  async function mkGet(path) {
    const r = await fetch(MERAKI_B + path, { headers: mkHeaders() });
    if (!r.ok) throw new Error('Meraki ' + r.status + ' ' + path);
    return r.json();
  }
  // lat/lng -> 0..1 image coordinates.
  // Meraki floor plans are usually ROTATED, so the four corners do not form an
  // axis-aligned box — using only bottom-left/top-right puts APs off the image.
  // Solve the affine basis from the top-left origin instead:
  //   P - TL = x*(TR - TL) + y*(BL - TL)
  function toXY(lat, lng, fp) {
    const tl = fp.topLeftCorner, tr = fp.topRightCorner, bl = fp.bottomLeftCorner;
    if (!tl || !tr || !bl) {                       // fall back to the simple box
      const b = fp.bottomLeftCorner, t = fp.topRightCorner;
      if (!b || !t) return null;
      const dx = t.lng - b.lng, dy = t.lat - b.lat;
      if (!dx || !dy) return null;
      return { x: (lng - b.lng) / dx, y: 1 - (lat - b.lat) / dy };
    }
    const ux = tr.lng - tl.lng, uy = tr.lat - tl.lat;   // image +x
    const vx = bl.lng - tl.lng, vy = bl.lat - tl.lat;   // image +y (downward)
    const det = ux * vy - uy * vx;
    if (!det) return null;
    const px = lng - tl.lng, py = lat - tl.lat;
    return { x: (px * vy - py * vx) / det, y: (ux * py - uy * px) / det };
  }

  let _fpCache = { ts: 0, data: null };
  async function floorData() {
    if (_fpCache.data && Date.now() - _fpCache.ts < 10 * 60 * 1000) return _fpCache.data;
    const orgs = await mkGet('/organizations');
    const org = orgs[0];
    const nets = await mkGet(`/organizations/${org.id}/networks`);
    const out = [];
    for (const n of nets) {
      let plans = [];
      try { plans = await mkGet(`/networks/${n.id}/floorPlans`); } catch (_) { continue; }
      if (!plans.length) continue;
      let devs = [];
      try { devs = await mkGet(`/networks/${n.id}/devices`); } catch (_) {}
      const aps = devs.filter(d => /^MR|^CW/.test(d.model || ''));
      for (const fp of plans) {
        const on = aps.filter(a => a.floorPlanId === fp.floorPlanId && a.lat && a.lng)
          .map(a => ({ name: a.name || a.serial, serial: a.serial, model: a.model,
                       ...(toXY(a.lat, a.lng, fp) || {}) }))
          .filter(a => a.x != null);
        out.push({ network: n.name, networkId: n.id, floorPlanId: fp.floorPlanId,
                   name: fp.name, imageUrl: fp.imageUrl, aps: on });
      }
    }
    _fpCache = { ts: Date.now(), data: out };
    return out;
  }

  // GET /api/netswitch/floorplans — plans + AP positions (0..1 coordinates)
  router.get('/floorplans', async (req, res) => {
    try { res.json({ ok: true, floorplans: await floorData() }); }
    catch (e) { res.status(502).json({ ok: false, error: 'MERAKI_FAILED', detail: e.message }); }
  });

  // GET /api/netswitch/roam?mac=&hours=24 — the path a client took between APs
  router.get('/roam', async (req, res) => {
    const mac = String(req.query.mac || '').toLowerCase().trim();
    const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 24, 1), 24 * 7);
    if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac))
      return res.status(400).json({ ok: false, error: 'BAD_INPUT', detail: 'mac required' });
    try {
      const { getWifiConnectionHistory } = require('./meraki-lookup.js');
      const hist = await getWifiConnectionHistory(mac, hours);
      const events = (hist && hist.events) || [];
      const plans = await floorData();
      // index AP name -> {floor, x, y}
      const idx = {};
      plans.forEach(fp => fp.aps.forEach(a => { idx[a.name] = { floorPlanId: fp.floorPlanId, floor: fp.name, x: a.x, y: a.y }; }));
      // oldest -> newest, collapse repeats so the path is hops, not noise
      const ordered = events.slice().reverse();
      const path = [];
      for (const e of ordered) {
        const ap = e.ap && idx[e.ap];
        if (!ap) continue;
        const last = path[path.length - 1];
        if (last && last.ap === e.ap) { last.until = e.timestamp; last.events++; continue; }
        path.push({ ap: e.ap, ...ap, at: e.timestamp, until: e.timestamp, events: 1,
                    band: e.band || null, reason: e.reason || null });
      }
      const unplaced = [...new Set(events.map(e => e.ap).filter(a => a && !idx[a]))];
      res.json({ ok: true, mac, hours, hops: path.length, path,
                 floorplans: plans.map(f => ({ floorPlanId: f.floorPlanId, name: f.name,
                                               network: f.network, aps: f.aps })),
                 event_count: events.length, unplaced });
    } catch (e) {
      res.status(502).json({ ok: false, error: 'ROAM_FAILED', detail: e.message });
    }
  });

  // GET /api/netswitch/floorplan-image?id= — proxy the plan image (keeps the API key server-side)
  router.get('/floorplan-image', async (req, res) => {
    const id = String(req.query.id || '');
    try {
      const plans = await floorData();
      const fp = plans.find(p => p.floorPlanId === id);
      if (!fp || !fp.imageUrl) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
      const r = await fetch(fp.imageUrl, { headers: mkHeaders() });
      if (!r.ok) return res.status(502).json({ ok: false, error: 'IMAGE_FAILED', detail: 'HTTP ' + r.status });
      res.set('Content-Type', r.headers.get('content-type') || 'image/png');
      res.set('Cache-Control', 'private, max-age=3600');
      res.send(Buffer.from(await r.arrayBuffer()));
    } catch (e) {
      res.status(502).json({ ok: false, error: 'IMAGE_FAILED', detail: e.message });
    }
  });

  // ── Network Observatory ──────────────────────────────────────────────
  // One read for the whole live wireless picture: where each AP sits on its
  // floor plan, how many clients it is holding right now, who roamed in the
  // last hour, and any switch-port fault on an AP uplink. Live counts come
  // from Meraki, movements and faults from the local cache — so if Meraki is
  // down the cached half still renders and `degraded` names what is missing.
  // A count is never invented: if a network did not answer, the clients field
  // is omitted rather than reported as zero.
  let _liveCache = { ts: 0, key: '', data: null };
  async function liveClients(netIds) {
    const key = netIds.join(',');
    if (_liveCache.data && _liveCache.key === key && Date.now() - _liveCache.ts < 60 * 1000)
      return _liveCache.data;
    const out = { clients: [], ok: [], failed: [] };
    for (const id of netIds) {
      try {
        out.clients.push(...await mkGet(`/networks/${id}/clients?timespan=900&perPage=1000`));
        out.ok.push(id);
      } catch (e) { out.failed.push({ networkId: id, detail: e.message }); }
    }
    _liveCache = { ts: Date.now(), key, data: out };
    return out;
  }

  let _apStatusCache = { ts: 0, data: null };
  async function apStatuses() {
    if (_apStatusCache.data && Date.now() - _apStatusCache.ts < 5 * 60 * 1000) return _apStatusCache.data;
    const orgs = await mkGet('/organizations');
    const rows = await mkGet(`/organizations/${orgs[0].id}/devices/statuses?perPage=1000`);
    const by = {};
    for (const d of rows) if (d.serial && d.status) by[d.serial] = d.status;
    _apStatusCache = { ts: Date.now(), data: by };
    return by;
  }

  // GET /api/netswitch/observatory?floor=<floorPlanId> — the whole view in one call
  router.get('/observatory', async (req, res) => {
    const wantFloor = String(req.query.floor || '').trim();
    const now = Math.floor(Date.now() / 1000);
    const degraded = [];
    let db;
    try {
      // cached half: roams (apmoves.py) + AP-uplink port faults (healthscan.py)
      let movements = [], issues = [], moves15 = null, issuesOpen = null;
      try {
        db = openDb();
        try {
          movements = db.prepare(
            `SELECT mac, label, from_ap, to_ap, ssid, ts FROM net_ap_moves
              WHERE ts >= ? ORDER BY ts DESC LIMIT 200`).all(now - 3600);
          moves15 = db.prepare('SELECT COUNT(*) AS n FROM net_ap_moves WHERE ts >= ?').get(now - 900).n;
        } catch (_) { degraded.push('movements: collector has not run yet'); }
        try {
          issues = db.prepare(
            `SELECT switch, switch_ip, port, descr, severity, kind, detail, diag
               FROM net_port_issues WHERE descr LIKE '%WAP%'
              ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END,
                       crc DESC, in_err DESC LIMIT 20`).all();
          parseDiag(issues);
          issuesOpen = db.prepare(
            "SELECT COUNT(*) AS n FROM net_port_issues WHERE descr LIKE '%WAP%'").get().n;
        } catch (_) { degraded.push('issues: port scan has not run yet'); }
      } catch (e) {
        degraded.push('cache: ' + (e.code === 'SQLITE_CANTOPEN' ? 'netfleet.db not built yet' : e.message));
      }

      // live half: Meraki. AP coordinates come from floorData() — same affine.
      let plans = null;
      try { plans = await floorData(); }
      catch (e) { degraded.push('floorplans: ' + e.message); }
      const sel = (plans || []).filter(p => !wantFloor || p.floorPlanId === wantFloor);

      const okNets = new Set(), byAp = {};
      if (plans) {
        const live = await liveClients([...new Set(plans.map(p => p.networkId))]);
        for (const id of live.ok) okNets.add(id);
        for (const f of live.failed) degraded.push('clients ' + f.networkId + ': ' + f.detail);
        for (const c of live.clients) {
          const n = c.recentDeviceName;
          if (n) byAp[n] = (byAp[n] || 0) + 1;
        }
      } else {
        degraded.push('clients: skipped, floor plans unavailable');
      }

      let statuses = null;
      try { statuses = await apStatuses(); }
      catch (e) { degraded.push('device status: ' + e.message); }

      const floors = sel.map(p => ({
        floorPlanId: p.floorPlanId, name: p.name, network: p.network,
        ...(okNets.has(p.networkId)
              ? { clients: p.aps.reduce((a, ap) => a + (byAp[ap.name] || 0), 0) } : {}),
        ap_count: p.aps.length }));

      const aps = [];
      for (const p of sel) for (const a of p.aps) aps.push({
        name: a.name, serial: a.serial, x: a.x, y: a.y,
        ...(okNets.has(p.networkId) ? { clients: byAp[a.name] || 0 } : {}),
        ...(statuses && statuses[a.serial] ? { status: statuses[a.serial] } : {}),
        model: a.model, floorPlanId: p.floorPlanId });

      res.json({ ok: true, polled_at: now, floors, aps, movements, issues,
        summary: {
          ...(okNets.size ? { clients: floors.reduce((a, f) => a + (f.clients || 0), 0) } : {}),
          aps_total: aps.length,
          ...(statuses ? { aps_online: aps.filter(a => a.status === 'online').length } : {}),
          ...(moves15 != null ? { moves_15m: moves15 } : {}),
          ...(issuesOpen != null ? { issues_open: issuesOpen } : {}) },
        ...(degraded.length ? { degraded } : {}) });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'READ_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  // ── claims: who is working which fault ─────────────────────────────
  // Keyed by "<switch_ip>:<port>". When the hourly scan stops reporting the
  // fault, the claim auto-clears on the next read — that is the honest
  // "fixed" signal, and cleared-this-week is what the overview hero shows.
  const CLAIM_REF = /^\d{1,3}(\.\d{1,3}){3}:[A-Za-z0-9/.\-]{1,40}$/;
  router.get('/claims', (req, res) => {
    let db;
    try {
      db = openDbRW();
      const now = Math.floor(Date.now() / 1000);
      try {
        const open = new Set(db.prepare("SELECT switch_ip || ':' || port AS r FROM net_port_issues").all().map(x => x.r));
        const act = db.prepare('SELECT id, ref FROM net_claims WHERE cleared_at IS NULL').all();
        const mark = db.prepare('UPDATE net_claims SET cleared_at=? WHERE id=?');
        for (const c of act) if (!open.has(c.ref)) mark.run(now, c.id);
      } catch (_) { /* no issues table yet: skip auto-clear */ }
      const claims = db.prepare('SELECT * FROM net_claims WHERE cleared_at IS NULL ORDER BY claimed_at DESC').all();
      const week = db.prepare('SELECT COUNT(*) AS n FROM net_claims WHERE cleared_at >= ?').get(now - 7 * 86400);
      res.json({ ok: true, claims, cleared_week: (week && week.n) || 0 });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'READ_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  router.post('/claims', gateAdmin, express.json(), (req, res) => {
    const b = req.body || {};
    const ref = String(b.ref || '').trim();
    if (!CLAIM_REF.test(ref))
      return res.status(400).json({ ok: false, error: 'BAD_INPUT', detail: 'ref must be <switch-ip>:<port>' });
    let db;
    try {
      db = openDbRW();
      const who = (req.user && (req.user.email || req.user.upn || req.user.name)) || 'unknown';
      const cur = db.prepare('SELECT * FROM net_claims WHERE ref=? AND cleared_at IS NULL').get(ref);
      if (cur) return res.status(409).json({ ok: false, error: 'CLAIMED', by: cur.claimed_by, item: cur });
      db.prepare('INSERT INTO net_claims(ref,title,detail,claimed_by,claimed_at) VALUES(?,?,?,?,?)')
        .run(ref, String(b.title || '').slice(0, 160), String(b.detail || '').slice(0, 200),
             who, Math.floor(Date.now() / 1000));
      res.json({ ok: true, item: db.prepare('SELECT * FROM net_claims WHERE ref=? AND cleared_at IS NULL').get(ref) });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'WRITE_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  router.delete('/claims/:id', gateAdmin, (req, res) => {
    let db;
    try {
      db = openDbRW();
      db.prepare('DELETE FROM net_claims WHERE id=? AND cleared_at IS NULL').run(req.params.id);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'WRITE_FAILED', detail: e.message });
    } finally { if (db) try { db.close(); } catch (_) {} }
  });

  return router;
};
