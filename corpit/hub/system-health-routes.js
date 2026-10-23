// System Health routes — self-host (corpit) CPU / RAM / Disk / Ubuntu patch status
// Mount: app.use('/api/system', require('./system-health-routes'));
const express = require('express');
const os = require('os');
const fs = require('fs');
const path = require('path');
const util = require('util');
const execP = util.promisify(require('child_process').exec);
const mysql = require('mysql2/promise');
const offload = require('./sqlite-offload');   // read-only SQLite off the event loop (CHG-ARCH-03b)
const { phasedPackages } = require('./apt-phasing');

const router = express.Router();

const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT) || 3306,
  database:           process.env.DB_NAME,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:    3,
  charset:            'utf8mb4',
});

const SNAP_TABLE = 'corpit_hub.server_health_snapshots';

// ── Access control ──────────────────────────────────────────────────────────
// These routes expose host telemetry, the crontab, backup filenames and the
// route table. They are gated server-side on a 'server-health' READ grant;
// hiding the nav tile was never the control. Super-admins bypass in
// requirePage itself.
const createRbac = require('./rbac-middleware');
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const needRead = rbac.requirePage('server-health', 'read');
router.use(needRead);

const THRESH = {
  cpu:  { warn: 70, down: 90 },
  mem:  { warn: 75, down: 90 },
  disk: { warn: 75, down: 90 },
};

function stateFor(pct, t) {
  if (pct >= t.down) return 'down';
  if (pct >= t.warn) return 'warn';
  return 'ok';
}

async function getMemory() {
  const { stdout } = await execP('free -b', { timeout: 5000 });
  const line = stdout.split('\n').find(function (l) { return l.indexOf('Mem:') === 0; });
  const parts = line.trim().split(/\s+/);
  const total = Number(parts[1]);
  const available = Number(parts[6]);
  const usedPct = Math.round(((total - available) / total) * 1000) / 10;
  return { totalBytes: total, availableBytes: available, usedPct: usedPct, state: stateFor(usedPct, THRESH.mem) };
}

async function getDisk() {
  const { stdout } = await execP('df -B1 /', { timeout: 5000 });
  const line = stdout.trim().split('\n')[1];
  const parts = line.trim().split(/\s+/);
  const totalBytes = Number(parts[1]);
  const usedBytes = Number(parts[2]);
  const availBytes = Number(parts[3]);
  const usedPct = Math.round((usedBytes / totalBytes) * 1000) / 10;
  return { mount: '/', totalBytes: totalBytes, usedBytes: usedBytes, availBytes: availBytes, usedPct: usedPct, state: stateFor(usedPct, THRESH.disk) };
}

// /proc/stat jiffy counters for core 'cpu' line. iowait is tracked separately
// from busy: time blocked on disk is NOT time spent computing.
function readProcStat() {
  var line = fs.readFileSync('/proc/stat', 'utf8').split('\n')[0];
  var p = line.trim().split(/\s+/).slice(1).map(Number);
  var user = p[0] || 0, nice = p[1] || 0, sys = p[2] || 0, idle = p[3] || 0,
      iowait = p[4] || 0, irq = p[5] || 0, soft = p[6] || 0, steal = p[7] || 0;
  return {
    total: user + nice + sys + idle + iowait + irq + soft + steal,
    idle: idle, iowait: iowait, steal: steal,
    busy: user + nice + sys + irq + soft,
  };
}

// Pressure Stall Information. 'full' = share of time EVERY task was stalled on
// this resource; the single most honest saturation signal the kernel exposes.
function readPressure(kind) {
  try {
    var txt = fs.readFileSync('/proc/pressure/' + kind, 'utf8');
    function avg(which, win) {
      var m = txt.match(new RegExp(which + '[^\\n]*avg' + win + '=([\\d.]+)'));
      return m ? parseFloat(m[1]) : null;
    }
    return { some10: avg('some', 10), some60: avg('some', 60), full10: avg('full', 10), full60: avg('full', 60) };
  } catch (e) { return null; }
}

// CPU utilisation is sampled on a background interval, NOT inside the request.
// Sampling during /health measured the apt subprocesses that /health itself
// spawns for the patch count, which reported ~84% busy on a fully idle box.
var _cpuSample = { prev: null, busyPct: null, iowaitPct: null, idlePct: null, stealPct: null };
(function startCpuSampler() {
  function tick() {
    try {
      var cur = readProcStat();
      if (_cpuSample.prev) {
        var dt = cur.total - _cpuSample.prev.total;
        if (dt > 0) {
          _cpuSample.busyPct = Math.round(((cur.busy - _cpuSample.prev.busy) / dt) * 1000) / 10;
          _cpuSample.iowaitPct = Math.round(((cur.iowait - _cpuSample.prev.iowait) / dt) * 1000) / 10;
          _cpuSample.idlePct = Math.round(((cur.idle - _cpuSample.prev.idle) / dt) * 1000) / 10;
          _cpuSample.stealPct = Math.round(((cur.steal - _cpuSample.prev.steal) / dt) * 1000) / 10;
        }
      }
      _cpuSample.prev = cur;
    } catch (e) {}
  }
  tick();
  var t = setInterval(tick, 5000);
  if (t.unref) t.unref();          // never hold the process open
})();

async function getCpu() {
  const cores = os.cpus().length;
  const load = os.loadavg();
  const loadPct = Math.round((load[0] / cores) * 1000) / 10;
  var busyPct = _cpuSample.busyPct, iowaitPct = _cpuSample.iowaitPct,
      idlePct = _cpuSample.idlePct, stealPct = _cpuSample.stealPct;
  // State follows real CPU consumption, not load average. Linux load counts
  // uninterruptible (D-state) tasks blocked on disk, so on a disk-bound host
  // loadPct reads like a CPU emergency while the CPU is idle.
  var state = busyPct != null ? stateFor(busyPct, THRESH.cpu) : stateFor(loadPct, THRESH.cpu);
  return {
    cores: cores, load1: load[0], load5: load[1], load15: load[2], loadPct: loadPct,
    busyPct: busyPct, iowaitPct: iowaitPct, idlePct: idlePct, stealPct: stealPct,
    pressure: readPressure('cpu'), state: state,
  };
}

// Disk saturation as its own first-class signal, so the UI can say "disk-bound"
// instead of blaming the CPU.
function getIo() {
  var pr = readPressure('io');
  var full = pr && pr.full10 != null ? pr.full10 : null;
  var state = full == null ? 'unknown' : (full >= 50 ? 'down' : full >= 20 ? 'warn' : 'ok');
  return { pressure: pr, stalledPct: full, state: state };
}

// The package counts come from two apt runs (about 2.2 s together on this host), and one
// console page load reaches getPatches() 3-4 times: /health, plus serverRows ->
// callLocal('/health') for /servers and for each /overview. So the counts are collected in
// the background and requests read the last result (decision G3, 2026-09-25): one run
// right after this module is required at hub start, then one every
// PATCH_REFRESH_MS. A request runs apt itself only as the fallback: when there is no good
// result yet, or the last good one is older than PATCH_COUNT_TTL_MS (the background runs
// have not succeeded for that long). Background and request runs share one in-flight
// run, so two apt runs never overlap. Both apt commands are async child processes.
// A run where either apt command failed never replaces the last good counts. While the
// most recent run has failed, callers get the last good counts marked ok:false,
// stale:true (G5); with no good run at all they get the failed run's own counts with
// ok:false, as before. collectedAt / ageSec (G4) are taken from the start of the run the
// served counts came from. The reboot-required reads and listsRefreshedAt in getPatches()
// stay per-request.
// After a package operation (the apt actions in system-actions-routes.js, unattended-upgrades,
// apt over ssh) dpkg rewrites /var/lib/dpkg/status and apt update renames new lists into
// /var/lib/apt/lists. When either mtime differs from the one read at the start of the last
// run, the next request starts a background run and is answered with the current counts
// without waiting for it (PERFORMANCE-PLAN item 1: "and after an approved package
// operation"). A run that fails does not make every later request start another: the key
// is recorded when a run starts, and the 15-min timer retries.
// The state and the timer live on globalThis, so a second evaluation of this module
// (require cache cleared, or a second path to the file) shares the same counts, run and
// timer instead of starting a second refresh loop.
var PATCH_COUNT_TTL_MS = 60 * 60 * 1000;   // fallback cap: good counts older than this make a request run apt
var PATCH_REFRESH_MS = 15 * 60 * 1000;     // background refresh interval
var PATCH_STATE = Symbol.for('corpit.system-health.patchCounts');
var _patch = globalThis[PATCH_STATE] || (globalThis[PATCH_STATE] = {
  good: null,    // last run where both apt commands succeeded: { upgradable, security, phased, phasedNames, ok, at }
  last: null,    // the most recent finished run, good or failed
  run: null,     // the run in progress, shared by every caller
  timer: null,   // the background refresh interval (one per process)
  key: null,     // aptStateKey() read at the start of the most recent run
});

function aptStateKey() {
  return ['/var/lib/dpkg/status', '/var/lib/apt/lists'].map(function (p) {
    try { return String(fs.statSync(p).mtimeMs); } catch (e) { return '-'; }
  }).join('|');
}

async function countPatchesUncached() {
  var upgradable = 0, security = 0, phased = 0, phasedNames = [], ok = true;
  var upgradableNames = new Set();
  try {
    const { stdout } = await execP('apt list --upgradable 2>/dev/null', { timeout: 15000 });
    const lines = stdout.split('\n').filter(function (l) { return l && l.indexOf('Listing') !== 0; });
    upgradable = lines.length;
    security = lines.filter(function (l) { return l.indexOf('-security') !== -1; }).length;
    upgradableNames = new Set(lines.map(function (l) { return l.split('/')[0]; }));
  } catch (e) { ok = false; }

  // Detect phased updates — Ubuntu holds these back intentionally; full-upgrade skips them.
  try {
    const { stdout } = await execP('apt-get -s full-upgrade 2>/dev/null', { timeout: 15000 });
    phasedNames = phasedPackages(stdout).filter(function (name) { return upgradableNames.has(name); });
    phased = phasedNames.length;
  } catch (e) { ok = false; }
  return { upgradable: upgradable, security: security, phased: phased, phasedNames: phasedNames, ok: ok };
}

// One apt run at a time: a caller that arrives while a run is in progress gets that run.
function refreshPatchCounts() {
  if (_patch.run) return _patch.run;
  var at = Date.now();
  _patch.key = aptStateKey();                      // read BEFORE the run: a change during it starts another
  var run = countPatchesUncached().then(function (r) {
    r.at = at;
    _patch.last = r;
    if (r.ok) _patch.good = r;
    return r;
  });
  _patch.run = run;
  function done() { if (_patch.run === run) _patch.run = null; }
  run.then(done, done);
  return run;
}

(function startPatchRefresh() {
  if (_patch.timer) return;                        // already running in this process
  function tick() { refreshPatchCounts().catch(function () {}); }
  _patch.timer = setInterval(tick, PATCH_REFRESH_MS);
  if (_patch.timer.unref) _patch.timer.unref();    // never hold the process open
  var warm = setTimeout(tick, 0);                  // warm once at hub start, after this require returns
  if (warm.unref) warm.unref();
})();

// Requests never wait for apt while good counts younger than the cap exist.
function countPatches() {
  var g = _patch.good;
  if (g && (Date.now() - g.at) < PATCH_COUNT_TTL_MS) {
    if (aptStateKey() !== _patch.key) refreshPatchCounts().catch(function () {});   // package state changed: refresh in the background
    return Promise.resolve(g);
  }
  return refreshPatchCounts();                     // fallback: no good counts yet, or older than the cap
}

async function getPatches() {
  var r = await countPatches();
  var good = _patch.good, last = _patch.last || r;
  var c = good || r;                               // the last good counts; the failed run's only if none
  var ok = !!(good && last.ok);
  var stale = !!(good && !last.ok);                // the most recent run failed: serving older good counts
  var upgradable = c.upgradable, security = c.security, phased = c.phased, phasedNames = c.phasedNames.slice();

  var actionable = Math.max(0, upgradable - phased);

  const rebootRequired = fs.existsSync('/var/run/reboot-required');
  var rebootPackages = [];
  if (rebootRequired && fs.existsSync('/var/run/reboot-required.pkgs')) {
    rebootPackages = fs.readFileSync('/var/run/reboot-required.pkgs', 'utf8').split('\n').filter(Boolean);
  }

  var listsRefreshedAt = null;
  try { listsRefreshedAt = fs.statSync('/var/lib/apt/lists').mtime; } catch (e) {}

  // State is "ok" if ALL remaining packages are just phased deferrals
  const state = (rebootRequired || security > 0) ? 'down' : (actionable > 0 ? 'warn' : 'ok');
  var out = { upgradable: upgradable, security: security, actionable: actionable, phased: phased, phasedNames: phasedNames, rebootRequired: rebootRequired, rebootPackages: rebootPackages, listsRefreshedAt: listsRefreshedAt, state: state,
    collectedAt: new Date(c.at).toISOString(), ageSec: Math.max(0, Math.floor((Date.now() - c.at) / 1000)), ok: ok };
  if (stale) out.stale = true;
  return out;
}

router.get('/health', async function (req, res) {
  try {
    const results = await Promise.all([
      getMemory().catch(function (e) { return { error: e.message, state: 'unknown' }; }),
      getDisk().catch(function (e) { return { error: e.message, state: 'unknown' }; }),
      getPatches().catch(function (e) { return { error: e.message, state: 'unknown' }; }),
      getCpu().catch(function (e) { return { error: e.message, state: 'unknown' }; }),
    ]);
    var cpu = results[3], io = getIo();
    // Name the actual bottleneck. Disk stall outranks CPU here because it is the
    // failure mode this host actually hits, and it is the one a load-average
    // reading misattributes to the CPU.
    var bottleneck = null;
    if (io.state === 'down') bottleneck = 'io';
    else if (cpu.state === 'down') bottleneck = 'cpu';
    else if (results[0].state === 'down') bottleneck = 'memory';
    else if (results[1].state === 'down') bottleneck = 'disk';
    else if (io.state === 'warn') bottleneck = 'io';
    else if (cpu.state === 'warn') bottleneck = 'cpu';
    res.json({
      timestamp: new Date().toISOString(),
      hostname: os.hostname(),
      uptimeSec: os.uptime(),
      cpu: cpu,
      io: io,
      memory: results[0],
      disk: results[1],
      patches: results[2],
      bottleneck: bottleneck,
    });
  } catch (e) {
    res.status(500).json({ status: 'error', message: e.message });
  }
});

// ─────────────────────────────────────────────────────────────
// Maintenance / housekeeping (read-only)
// ─────────────────────────────────────────────────────────────

// corpit (2026-09-06): the hub runs as the `corpit` service user with PM2_HOME set by
// /etc/corpit/ecosystem.config.js; pm2 resolves PM2_HOME before HOME, so the process
// environment is passed through untouched. The old ubuntu-home paths are unreadable here.
const PM2_BIN = fs.existsSync('/usr/lib/node_modules/pm2/bin/pm2')
  ? '/usr/lib/node_modules/pm2/bin/pm2' : 'pm2';

router.get('/pm2', async function (req, res) {
  try {
    const { stdout } = await execP(PM2_BIN + ' jlist', {
      timeout: 8000,
      env: process.env,
      maxBuffer: 4 * 1024 * 1024,
    });
    const raw = JSON.parse(stdout);
    const procs = raw.map(function (p) {
      const e = p.pm2_env || {};
      return {
        name: p.name, pmId: p.pm_id, status: e.status,
        uptimeMs: e.pm_uptime ? (Date.now() - e.pm_uptime) : null,
        restarts: e.restart_time, unstableRestarts: e.unstable_restarts,
        cpu: p.monit ? p.monit.cpu : null, memBytes: p.monit ? p.monit.memory : null,
        state: e.status === 'online' ? 'ok' : 'down',
      };
    });
    const worst = procs.some(function (p) { return p.state === 'down'; }) ? 'down' : 'ok';
    res.json({ timestamp: new Date().toISOString(), state: worst, processes: procs });
  } catch (e) {
    res.status(500).json({ state: 'unknown', error: e.message });
  }
});

router.get('/snapshots', async function (req, res) {
  const days = Math.min(parseInt(req.query.days) || 30, 365);
  try {
    const [rows] = await pool.query(
      'SELECT snapshot_date, cpu_load_pct, mem_used_pct, disk_used_pct, ' +
      'disk_used_bytes, disk_total_bytes, disk_avail_bytes ' +
      'FROM ' + SNAP_TABLE + ' WHERE snapshot_date >= (CURRENT_DATE - INTERVAL ? DAY) ' +
      'ORDER BY snapshot_date ASC', [days]);

    var forecast = { daysToFull: null, projectedFullDate: null, slopeBytesPerDay: null, note: null };
    if (rows.length >= 2) {
      var x0 = new Date(rows[0].snapshot_date).getTime();
      var pts = rows.map(function (r) {
        return { x: (new Date(r.snapshot_date).getTime() - x0) / 86400000, y: Number(r.disk_used_bytes) };
      });
      var n = pts.length, sx = 0, sy = 0, sxx = 0, sxy = 0;
      pts.forEach(function (p) { sx += p.x; sy += p.y; sxx += p.x * p.x; sxy += p.x * p.y; });
      var denom = (n * sxx - sx * sx);
      if (denom !== 0) {
        var slope = (n * sxy - sx * sy) / denom;
        var intercept = (sy - slope * sx) / n;
        forecast.slopeBytesPerDay = Math.round(slope);
        var total = Number(rows[rows.length - 1].disk_total_bytes);
        if (slope > 0) {
          var lastX = pts[pts.length - 1].x;
          var daysToFull = ((total - (slope * lastX + intercept)) / slope);
          if (daysToFull > 0 && isFinite(daysToFull)) {
            forecast.daysToFull = Math.round(daysToFull);
            var d = new Date(); d.setDate(d.getDate() + Math.round(daysToFull));
            forecast.projectedFullDate = d.toISOString().slice(0, 10);
          }
        } else { forecast.note = 'Disk usage flat or shrinking — no full-date projection.'; }
      }
    } else { forecast.note = 'Need at least 2 daily snapshots to forecast.'; }
    res.json({ timestamp: new Date().toISOString(), days: days, count: rows.length, snapshots: rows, forecast: forecast });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/backups', function (req, res) {
  function summarize(dir) {
    var out = { dir: dir, exists: false, files: [], latest: null };
    try {
      var names = fs.readdirSync(dir);
      out.exists = true;
      var stats = names.map(function (n) {
        try { var st = fs.statSync(path.join(dir, n)); return { name: n, sizeBytes: st.size, mtime: st.mtime }; }
        catch (e) { return null; }
      }).filter(Boolean).filter(function (f) { return !f.name.startsWith('.'); });
      stats.sort(function (a, b) { return b.mtime - a.mtime; });
      out.count = stats.length;
      out.totalBytes = stats.reduce(function (s, f) { return s + f.sizeBytes; }, 0);
      out.files = stats.slice(0, 10);
      out.latest = stats[0] || null;
    } catch (e) { out.error = e.message; }
    return out;
  }
  var nightly = summarize('/var/backups/corpit/nightly');
  var adhoc = summarize('/var/backups/corpit/adhoc');
  // corpit-db-backup.sh writes this after every run. A run where one schema failed still
  // leaves a fresh mtime in nightly/, so the status file is what turns that into a warn.
  var lastRun = null;
  try { lastRun = JSON.parse(fs.readFileSync('/var/backups/corpit/nightly-status.json', 'utf8')); } catch (e) { lastRun = null; }
  // The former 'home' card (/home/ubuntu/backups) was ad-hoc page copies, not database
  // backups, and is unreadable by the service user; dropped 2026-09-06.
  var state = 'unknown';
  if (nightly.latest) {
    var ageH = (Date.now() - new Date(nightly.latest.mtime).getTime()) / 3600000;
    state = ageH <= 26 ? 'ok' : (ageH <= 50 ? 'warn' : 'down');
    nightly.latestAgeHours = Math.round(ageH * 10) / 10;
  } else { state = 'warn'; }
  if (lastRun && lastRun.status !== 'ok' && state === 'ok') state = 'warn';
  var grandTotalBytes = (nightly.totalBytes || 0) + (adhoc.totalBytes || 0);
  res.json({ timestamp: new Date().toISOString(), state: state, grandTotalBytes: grandTotalBytes, nightly: nightly, adhoc: adhoc, lastRun: lastRun });
});

// ── Dynamic cron health: reads live ubuntu + root crontabs ──
function lastNonEmptyLine(file) {
  try {
    var buf = fs.readFileSync(file, 'utf8');
    var lines = buf.split('\n').filter(function (l) { return l.trim().length; });
    var last = lines[lines.length - 1] || '';
    return last.length > 200 ? last.slice(-200) : last;
  } catch (e) { return null; }
}

// Derive expected run interval (minutes) from cron minute+hour fields.
function cronIntervalMinutes(min, hour) {
  function stepOf(f) { var m = f.match(/^\*\/(\d+)$/); return m ? parseInt(m[1]) : null; }
  function listCount(f) { return f.split(',').length; }
  var mStep = stepOf(min);
  var mIsStar = (min === '*');
  var mCount = (!mStep && !mIsStar) ? listCount(min) : null; // single or list
  var hStep = stepOf(hour);
  var hIsStar = (hour === '*');
  var hCount = (!hStep && !hIsStar) ? listCount(hour) : null;

  if (hIsStar) {
    if (mStep) return mStep;                      // every mStep minutes
    if (mIsStar) return 1;                        // every minute
    if (mCount) return Math.max(1, Math.round(60 / mCount)); // mCount times/hour
  }
  var perHour = mStep ? Math.floor(60 / mStep) : (mIsStar ? 60 : (mCount || 1));
  if (hStep) {
    var hoursPerDay = Math.floor(24 / hStep);
    return Math.max(1, Math.round(1440 / (hoursPerDay * perHour)));
  }
  if (hCount) return Math.max(1, Math.round(1440 / (hCount * perHour))); // N times/day
  return 1440;
}

function friendlyName(cmd) {
  var nodeM = cmd.match(/node\s+(?:--\S+\s+)*(?:\S*\/)?([\w.-]+\.js)/);
  if (nodeM) return nodeM[1];
  var shM = cmd.match(/(?:\S*\/)?([\w.-]+\.sh)\b/);
  if (shM) return shM[1];
  var apiM = cmd.match(/\/api\/([\w-]+(?:\/[\w-]+)?)/);
  if (apiM) return apiM[1] + ' (api)';
  // run-parts drives a whole directory; name it by the directory, not by `cd`.
  var rp = cmd.match(/run-parts[^|;]*?(\/etc\/cron\.\w+)/);
  if (rp) return rp[1].replace('/etc/', '') + ' (run-parts)';
  // Otherwise take the first token that is an actual program, skipping shell
  // builtins, guards and wrappers — without this, `cd /x && …` names the job
  // "cd" and `command -v foo && foo` names it "command".
  var SKIP = /^(cd|env|test|command|sudo|nice|ionice|bash|sh|exec|then|else|fi|do|done|true|false|\[|\{)$/;
  var toks = cmd.split(/\s+/);
  for (var i = 0; i < toks.length; i++) {
    var t = toks[i];
    if (!t || t === '&&' || t === '||' || t === ';' || t === '-v') continue;
    if (t.indexOf('=') !== -1 && !/^\//.test(t)) continue;   // VAR=value prefixes
    if (/^-/.test(t)) continue;                              // flags
    // A path that is the operand of a `test`/`[` predicate is not the program:
    // `test -e /run/systemd/system || …` would otherwise be named "system".
    if (i > 0 && /^-[exfdrwsz]$/.test(toks[i - 1])) continue;
    var base = t.replace(/^.*\//, '');
    if (SKIP.test(base)) continue;
    if (base) return base;
  }
  return toks[0] || cmd;
}

// ── Cron field matching (supports *, */n, a-b, a,b, and a-b/n) ──
function cronFieldMatches(field, value, min, max) {
  if (field === '*') return true;
  return field.split(',').some(function (part) {
    var step = 1, range = part;
    var slash = part.indexOf('/');
    if (slash !== -1) { step = parseInt(part.slice(slash + 1), 10) || 1; range = part.slice(0, slash); }
    var lo, hi;
    if (range === '*') { lo = min; hi = max; }
    else if (range.indexOf('-') !== -1) {
      var bits = range.split('-'); lo = parseInt(bits[0], 10); hi = parseInt(bits[1], 10);
    } else { lo = hi = parseInt(range, 10); }
    if (isNaN(lo) || isNaN(hi)) return false;
    if (value < lo || value > hi) return false;
    return ((value - lo) % step) === 0;
  });
}

// Next fire time after `from`. Scans minute-by-minute; bails after 45 days so a
// nonsense expression cannot spin. Returns null if nothing matches in range.
function cronNextRun(f, from) {
  var d = new Date(from.getTime() + 60000 - (from.getTime() % 60000));
  var limit = 45 * 24 * 60;
  for (var i = 0; i < limit; i++) {
    var domOk = cronFieldMatches(f.dom, d.getDate(), 1, 31);
    var dowOk = cronFieldMatches(f.dow, d.getDay() === 0 && f.dow.indexOf('7') !== -1 ? 7 : d.getDay(), 0, 7);
    // POSIX: when both dom and dow are restricted, either matching fires the job.
    var dayOk = (f.dom === '*' || f.dow === '*') ? (domOk && dowOk) : (domOk || dowOk);
    if (dayOk
      && cronFieldMatches(f.mon, d.getMonth() + 1, 1, 12)
      && cronFieldMatches(f.hour, d.getHours(), 0, 23)
      && cronFieldMatches(f.min, d.getMinutes(), 0, 59)) return new Date(d);
    d = new Date(d.getTime() + 60000);
  }
  return null;
}

// Most recent fire time at or before `from` — used to date an observed run.
function cronPrevRun(f, from) {
  var d = new Date(from.getTime() - (from.getTime() % 60000));
  for (var i = 0; i < 45 * 24 * 60; i++) {
    var domOk = cronFieldMatches(f.dom, d.getDate(), 1, 31);
    var dowOk = cronFieldMatches(f.dow, d.getDay() === 0 && f.dow.indexOf('7') !== -1 ? 7 : d.getDay(), 0, 7);
    var dayOk = (f.dom === '*' || f.dow === '*') ? (domOk && dowOk) : (domOk || dowOk);
    if (dayOk
      && cronFieldMatches(f.mon, d.getMonth() + 1, 1, 12)
      && cronFieldMatches(f.hour, d.getHours(), 0, 23)
      && cronFieldMatches(f.min, d.getMinutes(), 0, 59)) return new Date(d);
    d = new Date(d.getTime() - 60000);
  }
  return null;
}

var DOW_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

// Plain-English rendering. Falls back to the raw expression rather than lying.
function humanSchedule(f) {
  function two(n) { return (n < 10 ? '0' : '') + n; }
  var everyMin = f.min.match(/^\*\/(\d+)$/);
  var everyHour = f.hour.match(/^\*\/(\d+)$/);
  var daily = (f.dom === '*' && f.mon === '*' && f.dow === '*');

  if (f.min === '*' && f.hour === '*') return 'every minute';
  if (everyMin && f.hour === '*') return 'every ' + everyMin[1] + ' min';
  if (f.hour === '*' && /^[\d,]+$/.test(f.min)) {
    var mins = f.min.split(',');
    return mins.length === 1 ? 'hourly at :' + two(+mins[0])
      : mins.length + '× per hour (:' + mins.map(function (m) { return two(+m); }).join(', :') + ')';
  }
  if (everyHour && /^\d+$/.test(f.min)) return 'every ' + everyHour[1] + 'h at :' + two(+f.min);
  if (/^\d+$/.test(f.min) && /^[\d,]+$/.test(f.hour)) {
    var times = f.hour.split(',').map(function (h) { return two(+h) + ':' + two(+f.min); }).join(', ');
    if (daily) return 'daily ' + times;
    if (f.dom === '*' && f.mon === '*' && f.dow !== '*' && /^\d$/.test(f.dow)) return DOW_NAMES[+f.dow] + ' ' + times;
    if (f.dow === '*' && f.mon === '*' && /^\d+$/.test(f.dom)) return 'day ' + f.dom + ' of month, ' + times;
    return times;
  }
  return [f.min, f.hour, f.dom, f.mon, f.dow].join(' ');
}

function parseCronLine(line, user, source, hasUserField) {
  var t = line.trim();
  if (!t || t[0] === '#') return null;
  if (/^[A-Z_]+\s*=/.test(t)) return null;               // SHELL=, PATH=, MAILTO=
  var re = hasUserField
    ? /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/
    : /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/;
  var m = t.match(re);
  if (!m) return null;
  var min = m[1], hour = m[2], dom = m[3], mon = m[4], dow = m[5];
  var cmd = hasUserField ? m[7] : m[6];
  if (hasUserField) user = m[6];
  // A leading @reboot/@daily style token never matches the 5-field regex, so
  // anything reaching here has real fields.
  var logM = cmd.match(/>>?\s*(\/\S+)/);
  var f = { min: min, hour: hour, dom: dom, mon: mon, dow: dow };
  return {
    user: user,
    source: source,
    fields: f,
    schedule: [min, hour, dom, mon, dow].join(' '),
    scheduleText: humanSchedule(f),
    name: friendlyName(cmd),
    command: cmd.length > 300 ? cmd.slice(0, 300) + '…' : cmd,
    niced: /\bnice\b|\bionice\b/.test(cmd),
    log: logM ? logM[1] : null,
    intervalMin: cronIntervalMinutes(min, hour),
  };
}

async function readCrontab(user) {
  try {
    // Exact command allowed by /etc/sudoers.d/corpit-cron-read (read-only, root|ubuntu).
    // -n: never wait on a password prompt if that entry is ever removed.
    const { stdout } = await execP('sudo -n /usr/bin/crontab -l -u ' + user, { timeout: 5000 });
    return stdout.split('\n');
  } catch (e) {
    // `crontab -l` exits non-zero both for "no crontab for <user>" -- benign,
    // the user simply has none -- and for a denied sudo read, which IS a gap in
    // what this page can see. stderr was previously discarded, so the two were
    // indistinguishable: returning [] for both let a total enumeration failure
    // render as a clean green panel. Only the denial returns null.
    if (/no crontab for/i.test(String((e && e.stderr) || ''))) return [];
    return null;
  }
}

function readFileLines(p) {
  try { return fs.readFileSync(p, 'utf8').split('\n'); } catch (e) { return []; }
}

// cronwrap (see /usr/local/bin/cronwrap) drops one JSON file per wrapped job.
var CRONWRAP_DIR = '/var/log/corpit/cronwrap';   // was /var/log/itam (never existed on this box)
function measuredRun(name) {
  try {
    return JSON.parse(fs.readFileSync(path.join(CRONWRAP_DIR, name + '.json'), 'utf8'));
  } catch (e) { return null; }
}

router.get('/cron', async function (req, res) {
  try {
    var lines = [];
    var counts = {};
    var unreadable = [];
    function add(arr, user, source, hasUserField) {
      if (arr === null) { unreadable.push(source); return; }
      var n = 0;
      arr.forEach(function (l) {
        var p = parseCronLine(l, user, source, hasUserField);
        if (p) { lines.push(p); n++; }
      });
      if (n) counts[source] = n;
    }

    add(await readCrontab('ubuntu'), 'ubuntu', 'crontab:ubuntu', false);
    add(await readCrontab('root'), 'root', 'crontab:root', false);
    add(readFileLines('/etc/crontab'), 'root', '/etc/crontab', true);

    var cronD = [];
    try { cronD = fs.readdirSync('/etc/cron.d'); } catch (e) {}
    cronD.filter(function (f) { return !/[.~]/.test(f); }).forEach(function (f) {
      add(readFileLines('/etc/cron.d/' + f), 'root', 'cron.d/' + f, true);
    });

    var now = new Date();
    var jobs = lines.map(function (j) {
      var next = cronNextRun(j.fields, now);
      var out = {
        name: j.name, user: j.user, source: j.source, schedule: j.schedule,
        scheduleText: j.scheduleText, command: j.command, niced: j.niced, log: j.log,
        fields: j.fields, maxAgeMin: j.intervalMin, intervalMin: j.intervalMin,
        exists: false, mtime: null, ageMin: null, lastLine: null, state: 'unknown',
        nextRun: next ? next.toISOString() : null,
        durationSec: null, durationSource: null, lastExit: null,
      };

      var meas = measuredRun(j.name);
      if (meas) {
        out.wrapped = true;
        if (meas.startedAt) out.lastStart = meas.startedAt;
        // A wrapper file with running:true is an in-flight run — it has a start
        // but no duration yet, so report elapsed rather than leaving it blank.
        if (meas.running) {
          out.running = true;
          if (meas.startedAt) out.elapsedSec = Math.round((Date.now() - new Date(meas.startedAt).getTime()) / 1000);
        } else if (meas.durationSec != null) {
          out.durationSec = meas.durationSec;
          out.durationSource = 'measured';
          out.lastExit = meas.exit;
          out.finishedAt = meas.finishedAt || null;
        }
      }

      // /dev/null is a discard, not a log. Stat-ing it returns the device node's
      // mtime (boot time), which made every such job read as permanently overdue.
      if (j.log === '/dev/null') { out.state = 'unknown'; out.note = 'output discarded (/dev/null)'; out.log = null; return out; }
      if (!j.log) { out.state = 'unknown'; out.note = 'no log redirect'; return out; }
      try {
        var st = fs.statSync(j.log);
        out.exists = true;
        out.mtime = st.mtime;
        out.ageMin = Math.round((Date.now() - st.mtime.getTime()) / 60000);
        var grace = Math.max(j.intervalMin * 1.5, j.intervalMin + 10);
        out.state = out.ageMin <= grace ? 'ok' : (out.ageMin <= j.intervalMin * 3 ? 'warn' : 'down');
        out.lastLine = lastNonEmptyLine(j.log);

        // No cronwrap data: infer duration from when the run was scheduled to
        // start vs. when its log was last written. Only meaningful for jobs that
        // run at most a few times a day, and always labelled 'observed'.
        if (out.durationSource == null && j.intervalMin >= 240) {
          var prev = cronPrevRun(j.fields, st.mtime);
          if (prev) {
            var secs = Math.round((st.mtime.getTime() - prev.getTime()) / 1000);
            // Reject anything filling ≥50% of the gap to the previous fire. If a
            // schedule was edited recently the log's last write belongs to the
            // OLD occurrence, and dating it against the new one yields absurd
            // spans (a retimed daily job measured 19h). Real daily jobs here top
            // out around 8h, so half the interval is a safe ceiling — and the
            // heavy jobs are cronwrap-measured anyway. Better no number than a
            // wrong one.
            // Hard 4h ceiling on top of the ratio test. Inference is only
            // trustworthy for short jobs; anything genuinely long-running here
            // is cronwrap-wrapped and reports a measured duration instead.
            if (secs >= 0 && secs < j.intervalMin * 60 * 0.5 && secs <= 4 * 3600) {
              out.durationSec = secs;
              out.durationSource = 'observed';
            }
          }
        }
      } catch (e) {
        // No log file is an absence of evidence, not evidence of failure: a job
        // installed after today's fire time has simply not reached its first
        // occurrence yet. Reporting 'down' asserted a crash nobody observed and
        // drove the top-line verdict to Critical.
        out.state = 'unknown'; out.error = 'no log yet (never run, or log deleted)';
      }
      return out;
    });

    jobs.sort(function (a, b) { return (a.nextRun || '').localeCompare(b.nextRun || ''); });

    var down = jobs.filter(function (j) { return j.state === 'down'; }).length;
    var warn = jobs.filter(function (j) { return j.state === 'warn'; }).length;
    // 'ok' has to mean "checked and healthy". If nothing could be enumerated --
    // every crontab read denied, no /etc/cron.d -- there is no evidence of
    // health to report, so say unknown rather than green.
    // A job we cannot see the result of is not a passing job. 'ok' is reserved
    // for jobs that actually reported.
    var unverified = jobs.filter(function (j) { return j.state === 'unknown'; }).length;
    var state = down ? 'down' : (warn ? 'warn' : ((jobs.length && !unverified) ? 'ok' : 'unknown'));
    if (!jobs.length && unreadable.length) state = 'unknown';
    res.json({
      timestamp: now.toISOString(), state: state, total: jobs.length,
      downCount: down, warnCount: warn, unverifiedCount: unverified,
      unreadableSources: unreadable,
      serverTz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
      tzOffsetMin: -now.getTimezoneOffset(),
      sources: counts,
      jobs: jobs,
    });
  } catch (e) {
    res.status(500).json({ state: 'unknown', error: e.message });
  }
});

router.get('/logrotate', async function (req, res) {
  try {
    var configs = [];
    try { configs = fs.readdirSync('/etc/logrotate.d'); } catch (e) {}
    var statusRaw = '';
    try { statusRaw = fs.readFileSync('/var/lib/logrotate/status', 'utf8'); } catch (e) {}
    var rotations = statusRaw.split('\n').map(function (l) {
      var m = l.match(/^"?([^"]+)"?\s+(\d{4}-\d{1,2}-\d{1,2})/);
      return m ? { file: m[1], lastRotated: m[2] } : null;
    }).filter(Boolean);
    // 'ok' was hardcoded, so a failed readdir + failed status read still
    // reported healthy. No evidence is not a pass.
    var lrState = (configs.length || rotations.length) ? 'ok' : 'unknown';
    res.json({ timestamp: new Date().toISOString(), state: lrState, configs: configs, rotations: rotations });
  } catch (e) {
    res.status(500).json({ state: 'unknown', error: e.message });
  }
});


// API Inventory — live route introspection
router.get('/api-inventory', async function (req, res) {
  try {
    var metaPath = path.join(__dirname, 'api-inventory-meta.json');
    var meta = {};
    var metaAvailable = false;
    try { meta = JSON.parse(fs.readFileSync(metaPath, 'utf8')); metaAvailable = true; } catch (e) {}

    var stack = req.app._router && req.app._router.stack ? req.app._router.stack : [];
    var modules = {};

    function extractPrefix(re) {
      var s = re.source;
      if (s.charAt(0) === '^') s = s.slice(1);
      var la = s.indexOf('(?=');
      if (la !== -1) s = s.slice(0, la);
      s = s.split('\\/').join('/');
      s = s.split('\\').join('');
      if (s.slice(-2) === '/?') s = s.slice(0, -2);
      if (s.charAt(s.length - 1) === '/') s = s.slice(0, -1);
      if (s.indexOf('(') !== -1 || s.indexOf('[') !== -1 || s.indexOf('*') !== -1) return null;
      if (s.charAt(0) !== '/') return null;
      return s;
    }

    stack.forEach(function (layer) {
      if (!layer.handle || !layer.handle.stack) return;
      var prefix = extractPrefix(layer.regexp);
      if (!prefix) return;

      layer.handle.stack.forEach(function (rl) {
        if (!rl.route) return;
        Object.keys(rl.route.methods).forEach(function (method) {
          if (!rl.route.methods[method]) return;
          var fullPath = prefix + (rl.route.path || '');
          if (!modules[prefix]) modules[prefix] = { prefix: prefix, routes: [] };
          var metaKey = method.toUpperCase() + ' ' + fullPath;
          modules[prefix].routes.push({
            method: method.toUpperCase(),
            path: fullPath,
            description: (meta[metaKey] && meta[metaKey].description) || '',
            // No metadata entry means this route's authorization is UNDOCUMENTED,
            // not that it is open. Defaulting to 'open' made every route match the
            // page's "No auth" filter whenever api-inventory-meta.json was absent,
            // which is exactly the list a reviewer would act on.
            rbac: (meta[metaKey] && meta[metaKey].rbac) || 'unknown'
          });
        });
      });
    });

    var result = Object.values(modules).sort(function (a, b) {
      return a.prefix.localeCompare(b.prefix);
    });

    var undocumented = result.reduce(function (n, m) {
      return n + m.routes.filter(function (r) { return r.rbac === 'unknown'; }).length;
    }, 0);
    res.json({
      timestamp: new Date().toISOString(),
      state: metaAvailable ? 'ok' : 'unknown',
      metaAvailable: metaAvailable,
      metaPath: metaPath,
      undocumented: undocumented,
      modules: result,
      total: result.reduce(function (n, m) { return n + m.routes.length; }, 0)
    });
  } catch (e) {
    res.status(500).json({ state: 'error', error: e.message });
  }
});

// ── Active SSH / login sessions (read-only) ──
router.get('/sessions', async function (req, res) {
  try {
    // 'who -H' columns: NAME LINE TIME ... (IP in parens at end if remote)
    const { stdout } = await execP('who 2>/dev/null || true', { timeout: 5000 });
    var sessions = stdout.split('\n').filter(function (l) { return l.trim().length; }).map(function (line) {
      var parts = line.trim().split(/\s+/);
      var user = parts[0] || '?';
      var tty  = parts[1] || '';
      // login date+time are parts[2]+parts[3]; IP is the last (…) token if present
      var since = (parts[2] || '') + ' ' + (parts[3] || '');
      var ip = 'local/console';
      var m = line.match(/\(([^)]+)\)\s*$/);
      if (m) { ip = m[1]; }
      else if (/^(pts|tty)/.test(tty) && parts.length >= 6) { ip = parts[parts.length - 1]; }
      return { user: user, tty: tty, since: since.trim(), ip: ip };
    });
    res.json({ timestamp: new Date().toISOString(), count: sessions.length, sessions: sessions });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// ─── GET /db-health — MySQL table stats + SQLite integrity ───────────────────
router.get('/db-health', async function (req, res) {
  var results = { mysql: [], sqlite: [], analyzedAt: new Date().toISOString() };
  // MySQL: table sizes + fragmentation
  try {
    var mysql = require('mysql2/promise');
    var pool = mysql.createPool({
      host:     process.env.DB_HOST     || 'localhost',
      port:     parseInt(process.env.DB_PORT || '3306', 10),
      user:     process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      connectionLimit: 2,
    });
    var [rows] = await pool.execute(
      `SELECT table_name,
              ROUND(data_length/1024/1024,2)    AS data_mb,
              ROUND(index_length/1024/1024,2)   AS index_mb,
              ROUND((data_length+index_length)/1024/1024,2) AS total_mb,
              ROUND(data_free/1024/1024,2)       AS free_mb,
              table_rows,
              engine,
              create_time,
              update_time
       FROM information_schema.tables
       WHERE table_schema = DATABASE()
       ORDER BY (data_length+index_length) DESC`
    );
    results.mysql = rows;
    await pool.end();
  } catch (e) {
    results.mysqlError = e.message;
  }
  // SQLite: size and free-list per file, integrity on request.
  // Every read runs in a worker thread (sqlite-offload). The size pragmas are
  // index-free and answer in milliseconds. PRAGMA integrity_check walks every
  // page (lss.db is 7.8GB) and used to run on the event loop, which froze the
  // auth gate for every vhost for the duration; it now runs off-thread with a
  // 20-minute budget and the verdict is kept for 12 hours, so a dashboard that
  // asks with ?integrity=1 twice pays once. ok is null until a check has run.
  var path  = require('path');
  var dbDir = path.join(__dirname, 'data');
  var dbs   = [];
  try { dbs = fs.readdirSync(dbDir).filter(function (f) { return /\.db$/.test(f); }).sort(); } catch (e) { dbs = []; }
  var runIntegrity = String(req.query.integrity || '') === '1';
  results.sqlite = await Promise.all(dbs.map(async function (dbName) {
    var dbPath = path.join(dbDir, dbName);
    var s = await offload.query(dbPath, [
      { sql: 'PRAGMA page_size', mode: 'get' }, { sql: 'PRAGMA page_count', mode: 'get' }, { sql: 'PRAGMA freelist_count', mode: 'get' }
    ], { cacheKey: 'dbh:size:' + dbName, cacheTtlMs: 30000, timeoutMs: 15000, label: dbName + ' size' });
    if (!s.ok) return { name: dbName, ok: false, integrity: s.error, totalMb: 0, freeMb: 0 };
    var pageSize = s.results[0].page_size || 0;
    var row = {
      name:      dbName,
      ok:        null,
      integrity: 'not_checked',
      totalMb:   Math.round(pageSize * (s.results[1].page_count || 0) / 1024 / 1024 * 10) / 10,
      freeMb:    Math.round(pageSize * (s.results[2].freelist_count || 0) / 1024 / 1024 * 10) / 10,
    };
    if (runIntegrity) {
      var ic = await offload.query(dbPath, [{ sql: 'PRAGMA integrity_check' }],
        { cacheKey: 'dbh:integrity:' + dbName, cacheTtlMs: 12 * 3600000, timeoutMs: 1200000, label: dbName + ' integrity check' });
      if (!ic.ok) { row.ok = false; row.integrity = ic.error; }
      else {
        var lines = ic.results[0].map(function (x) { return x.integrity_check; });
        row.ok = lines.length === 1 && lines[0] === 'ok';
        row.integrity = row.ok ? 'ok' : lines.join('\n');
        row.checkedAt = ic.cachedAt ? new Date(ic.cachedAt).toISOString() : results.analyzedAt;
      }
    }
    return row;
  }));
  res.json(results);
});

module.exports = router;

