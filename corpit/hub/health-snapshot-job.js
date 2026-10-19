// health-snapshot-job.js — nightly: capture one server-health row per day.
//
// 2026-08-21: this job used to fetch http://localhost:3001/api/system/health.
// When /api/system moved behind the RBAC gate (~2026-08-08) that call started
// returning {"ok":false,"error":"AUTH_REQUIRED"} — which is valid JSON, so
// JSON.parse succeeded, every metric read as undefined, and the job wrote a
// NULL row every night while still exiting 0. Two weeks of the Overview trend
// chart were plotting Number(null) === 0.
//
// It now reads the metrics directly from the kernel (no HTTP, no auth) and
// refuses to write a row it could not populate.
//
// Env: loaded from this directory's .env via dotenv below, so the job is
// self-sufficient under cron. Do NOT go back to `env $(cat .env | xargs)`:
// a single value containing a space silently truncates the whole set.
// Run: /usr/bin/node /var/www/corpit-hub-api/health-snapshot-job.js
require('dotenv').config({ path: __dirname + '/.env' });
const os = require('os');
const fs = require('fs');
const mysql = require('mysql2/promise');
const { execFile } = require('child_process');
const run = require('util').promisify(execFile);

function cpuLoadPct() {
  return Math.round((os.loadavg()[0] / os.cpus().length) * 1000) / 10;
}

// MemAvailable is the honest "how much can a new process actually get" number;
// os.freemem() excludes reclaimable page cache and reads far too pessimistic.
function memory() {
  var total = os.totalmem(), avail = null;
  try {
    var mi = fs.readFileSync('/proc/meminfo', 'utf8');
    var mt = mi.match(/^MemTotal:\s+(\d+) kB/m);
    var ma = mi.match(/^MemAvailable:\s+(\d+) kB/m);
    if (mt) total = parseInt(mt[1], 10) * 1024;
    if (ma) avail = parseInt(ma[1], 10) * 1024;
  } catch (e) {}
  if (avail == null) avail = os.freemem();
  var used = total - avail;
  return { totalBytes: total, availBytes: avail, usedPct: Math.round((used / total) * 1000) / 10 };
}

async function disk() {
  const { stdout } = await run('df', ['-B1', '--output=size,used,avail,pcent', '/']);
  const row = stdout.trim().split('\n').pop().trim().split(/\s+/);
  const total = parseInt(row[0], 10), used = parseInt(row[1], 10), avail = parseInt(row[2], 10);
  if (!total) throw new Error('df returned no usable size for /');
  return { totalBytes: total, usedBytes: used, availBytes: avail, usedPct: Math.round((used / total) * 1000) / 10 };
}

async function patches() {
  var upgradable = 0, security = 0, reboot = 0;
  try {
    const { stdout } = await run('bash', ['-lc', 'apt list --upgradable 2>/dev/null']);
    const lines = stdout.split('\n').filter(function (l) { return l && l.indexOf('Listing') !== 0; });
    upgradable = lines.length;
    security = lines.filter(function (l) { return l.indexOf('-security') !== -1; }).length;
  } catch (e) {}
  try { reboot = fs.existsSync('/var/run/reboot-required') ? 1 : 0; } catch (e) {}
  return { upgradable: upgradable, security: security, reboot: reboot };
}

(async function () {
  var mem, dsk, pat, cpuPct;
  try {
    cpuPct = cpuLoadPct();
    mem = memory();
    dsk = await disk();
    pat = await patches();
  } catch (e) {
    console.error('[snapshot] metric collection failed:', e.message);
    process.exit(1);
  }

  // Guard the exact failure that went unnoticed for two weeks: never persist a
  // row whose core metrics are missing — fail visibly instead.
  if (dsk.usedPct == null || isNaN(dsk.usedPct) || mem.usedPct == null || isNaN(mem.usedPct)) {
    console.error('[snapshot] refusing to write: core metrics unavailable',
      JSON.stringify({ disk: dsk.usedPct, mem: mem.usedPct }));
    process.exit(1);
  }

  var pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT) || 3306,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    connectionLimit: 1,
  });

  var now = new Date();
  var date = now.toISOString().slice(0, 10);

  try {
    await pool.query(
      'INSERT INTO corpit_hub.server_health_snapshots ' +
      '(snapshot_date, snapshot_at, cpu_load_pct, mem_used_pct, mem_total_bytes, ' +
      'disk_used_pct, disk_used_bytes, disk_total_bytes, disk_avail_bytes, ' +
      'patches_upgradable, patches_security, reboot_required) ' +
      'VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ' +
      'ON DUPLICATE KEY UPDATE snapshot_at=VALUES(snapshot_at), cpu_load_pct=VALUES(cpu_load_pct), ' +
      'mem_used_pct=VALUES(mem_used_pct), mem_total_bytes=VALUES(mem_total_bytes), ' +
      'disk_used_pct=VALUES(disk_used_pct), disk_used_bytes=VALUES(disk_used_bytes), ' +
      'disk_total_bytes=VALUES(disk_total_bytes), disk_avail_bytes=VALUES(disk_avail_bytes), ' +
      'patches_upgradable=VALUES(patches_upgradable), patches_security=VALUES(patches_security), ' +
      'reboot_required=VALUES(reboot_required)',
      [date, now, cpuPct, mem.usedPct, mem.totalBytes,
        dsk.usedPct, dsk.usedBytes, dsk.totalBytes, dsk.availBytes,
        pat.upgradable, pat.security, pat.reboot]);
    console.log('[snapshot] wrote', date, 'disk', dsk.usedPct + '%', 'mem', mem.usedPct + '%', 'cpu', cpuPct + '%');
  } catch (e) {
    console.error('[snapshot] db write failed:', e.message); process.exit(1);
  } finally {
    await pool.end();
  }
})();
