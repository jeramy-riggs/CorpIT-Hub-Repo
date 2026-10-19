// system-actions-routes.js — maintenance ACTIONS for the Server Health page.
// Mount: app.use('/api/system', require('./system-actions-routes'));  (after system-health-routes)
// Pattern mirrors housekeeping.js / sharepoint-governance.js.
//
// RBAC: loadCurrentUser always runs (populates req.user for audit "who").
// Set ENFORCE_RBAC = true to require a 'server-health' admin grant on every action.
const express = require('express');
const os = require('os');
const fs = require('fs');
const path = require('path');
const util = require('util');
const { exec, spawn } = require('child_process');
const execP = util.promisify(exec);
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const router = express.Router();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 3,
  charset: 'utf8mb4',
});

const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

// ── RBAC gate switch (flip to true to enforce 'server-health' admin) ──
const ENFORCE_RBAC = true;
function needAdmin(req, res, next) {
  return ENFORCE_RBAC ? rbac.requirePage('server-health', 'admin')(req, res, next) : next();
}

// corpit (2026-09-06): the hub runs as the `corpit` service user. PM2_HOME comes from
// /etc/corpit/ecosystem.config.js and pm2 resolves it before HOME, so the environment
// is passed through untouched; the ubuntu-home paths this used are unreadable now.
const PM2_BIN = fs.existsSync('/usr/lib/node_modules/pm2/bin/pm2')
  ? '/usr/lib/node_modules/pm2/bin/pm2' : 'pm2';
const PM2_ENV = Object.assign({}, process.env);
const PM2_DUMP = path.join(process.env.PM2_HOME || path.join(os.homedir(), '.pm2'), 'dump.pm2');
const ALLOWED_PM2 = ['it-inventory-api', 'corpit-hub-api', 'corpit-gate-api'];  // corpit-gate-api: CHG-ARCH-21 B9
// Where detached actions and manual jobs write. Owned by the service user; /var/log/itam
// never existed on this box, so every fireDetached() silently failed to open its log.
const LOG_DIR = process.env.CORPIT_LOG_DIR || '/var/log/corpit';
// The service user has NO blanket sudo. Anything privileged needs an exact sudoers entry;
// ask sudo before firing a detached command so a refusal is reported as one, instead of a
// 'started' that never ran. `sudo -l <cmd>` exits 0 only when that exact command is allowed.
async function sudoAllows(cmd) {
  try { await execP('sudo -n -l ' + cmd, { timeout: 5000 }); return true; } catch (e) { return false; }
}
const NOT_PERMITTED = 'not permitted for the service user on this host (no sudoers entry for this command)';
// A refused `sudo -n` is a 403 with the same message as the preflighted routes, not a 500
// carrying sudo's prompt text; anything else that fails is still a 500 with its real error.
const SUDO_REFUSED = /a password is required|is not in the sudoers file|not allowed to execute|may not run sudo/;
function sendFail(res, e, extra) {
  const refused = SUDO_REFUSED.test((e && e.message) || '');
  return res.status(refused ? 403 : 500).json(Object.assign({ error: refused ? NOT_PERMITTED : (e && e.message) }, extra || {}));
}
const ENV_PREFIX = "cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs)";

// Whitelisted manual jobs (ME sync jobs intentionally excluded — they hang).
const JOBS = {
  'snapshot':             { label: 'Health snapshot',      script: 'health-snapshot-job.js',        long: false },
  'collect-requests':     { label: 'Collect requests',     script: 'collect-requests.js',           long: false },
  'collect-lockouts':     { label: 'Collect lockouts',     script: 'collect-lockouts.js',           long: false },
  'collect-spray':        { label: 'Collect spray',        script: 'collect-spray.js',              long: false },
  'collect-okta-users':   { label: 'Collect Okta users',   script: 'collect-okta-users.js',         long: false },
  'collect-email':        { label: 'Collect email activity',script: 'collect-email-activity.js',    long: false },
  'collect-legacy-auth':  { label: 'Collect legacy auth',  script: 'collect-legacy-auth.js',        long: false },
  'collect-defender':     { label: 'Collect Defender',     script: 'collect-defender.js',           long: false },
  'collect-intune':       { label: 'Collect Intune',       script: 'collect-intune.js',             long: false },
  'collect-m365':         { label: 'Collect M365 reports', script: 'collect-m365-reports.js',       long: false },
  'collect-powerplatform':{ label: 'Collect PowerPlatform',script: 'collect-powerplatform.js',      long: false },
  'storage-collect':      { label: 'Storage collect',      script: 'storage-collect-job.js',        long: true },
  'site-storage':         { label: 'Site storage collect', script: 'site-storage-collect-job.js',   long: true },
  'dept-walk':            { label: 'Dept folder walk',     script: 'dept-folder-walk-job.js',       long: true },
  'stale-crawl':          { label: 'Stale crawl',          script: 'stale-crawl-job.js',            long: true },
};

async function audit(req, action, target, params, result, detail) {
  try {
    const u = req.user || {};
    await pool.query(
      'INSERT INTO corpit_hub.server_action_audit (action, target, actor_email, actor_name, params, result, detail) VALUES (?,?,?,?,?,?,?)',
      [action, target || null, u.email || 'anonymous', u.displayName || null,
       params ? JSON.stringify(params) : null, result || null, detail ? String(detail).slice(0, 4000) : null]);
  } catch (e) { console.error('[actions] audit write failed:', e.message); }
}

function fireDetached(cmd, logFile) {
  try {
    const out = fs.openSync(logFile, 'a');
    const p = spawn('/usr/bin/setsid', ['bash', '-lc', cmd], { detached: true, stdio: ['ignore', out, out], env: PM2_ENV });
    p.unref();
    return true;
  } catch (e) { return false; }
}

// ─────────────── TIER 1 (no sudo) ───────────────

router.post('/pm2/restart', needAdmin, async function (req, res) {
  const name = String(req.body && req.body.name || '');
  if (ALLOWED_PM2.indexOf(name) === -1) {
    await audit(req, 'pm2_restart', name, null, 'rejected', 'name not in allowlist');
    return res.status(400).json({ error: 'process not allowed', allowed: ALLOWED_PM2 });
  }
  // Detached: restarting api-beta must not hang on killing our own process.
  const fired = fireDetached(PM2_BIN + ' restart ' + name, LOG_DIR + '/actions.log');
  await audit(req, 'pm2_restart', name, null, fired ? 'issued' : 'error', fired ? null : 'could not launch pm2 (log dir unwritable?)');
  if (!fired) return res.status(500).json({ status: 'error', error: 'restart not issued - could not launch pm2' });
  res.json({ status: 'issued', process: name, note: 'Restart issued; re-poll status in a few seconds.' });
});

router.post('/pm2/flush', needAdmin, async function (req, res) {
  const name = req.body && req.body.name;
  const target = (name && ALLOWED_PM2.indexOf(name) !== -1) ? name : 'all';
  try {
    const { stdout } = await execP(PM2_BIN + ' flush ' + (target === 'all' ? '' : target), { timeout: 8000, env: PM2_ENV });
    await audit(req, 'pm2_flush', target, null, 'success', null);
    res.json({ status: 'success', target: target, output: stdout.trim().slice(-400) });
  } catch (e) { await audit(req, 'pm2_flush', target, null, 'error', e.message); res.status(500).json({ error: e.message }); }
});

router.post('/pm2/save', needAdmin, async function (req, res) {
  try {
    const { stdout } = await execP(PM2_BIN + ' save', { timeout: 8000, env: PM2_ENV });
    await audit(req, 'pm2_save', null, null, 'success', null);
    res.json({ status: 'success', output: stdout.trim().slice(-400) });
  } catch (e) { await audit(req, 'pm2_save', null, null, 'error', e.message); res.status(500).json({ error: e.message }); }
});

router.post('/job/run', needAdmin, async function (req, res) {
  const key = String(req.body && req.body.job || '');
  const j = JOBS[key];
  if (!j) { await audit(req, 'job_run', key, null, 'rejected', 'unknown job'); return res.status(400).json({ error: 'unknown job', allowed: Object.keys(JOBS) }); }
  const logFile = LOG_DIR + '/manual-' + key + '.log';
  const ok = fireDetached(ENV_PREFIX + ' /usr/bin/node ' + j.script + ' >> ' + logFile + ' 2>&1', logFile);
  await audit(req, 'job_run', key, { long: j.long }, ok ? 'started' : 'error', null);
  res.json({ status: ok ? 'started' : 'error', job: j.label, long: j.long, log: logFile });
});

// ─────────────── TIER 2 (sudo) ───────────────

router.post('/apt/update', needAdmin, async function (req, res) {
  try {
    const { stdout } = await execP('sudo -n /usr/bin/apt-get update', { timeout: 90000 });
    await audit(req, 'apt_update', null, null, 'success', null);
    res.json({ status: 'success', output: stdout.trim().slice(-800) });
  } catch (e) { await audit(req, 'apt_update', null, null, 'error', e.message); sendFail(res, e, { output: (e.stdout || '').slice(-800) }); }
});

router.post('/apt/clean', needAdmin, async function (req, res) {
  try {
    const before = await execP("df -B1 --output=avail / | tail -1", { timeout: 5000 });
    const { stdout } = await execP('sudo -n /usr/bin/apt-get -y autoremove --purge && sudo -n /usr/bin/apt-get clean', { timeout: 120000 });
    const after = await execP("df -B1 --output=avail / | tail -1", { timeout: 5000 });
    const freed = Number(after.stdout.trim()) - Number(before.stdout.trim());
    await audit(req, 'apt_clean', null, null, 'success', 'freed=' + freed);
    res.json({ status: 'success', freedBytes: freed, output: stdout.trim().slice(-600) });
  } catch (e) { await audit(req, 'apt_clean', null, null, 'error', e.message); sendFail(res, e); }
});

router.post('/journal/vacuum', needAdmin, async function (req, res) {
  const days = Math.min(Math.max(parseInt(req.body && req.body.days) || 7, 1), 90);
  try {
    const { stdout, stderr } = await execP('sudo -n /usr/bin/journalctl --vacuum-time=' + days + 'd', { timeout: 30000 });
    await audit(req, 'journal_vacuum', String(days) + 'd', null, 'success', null);
    res.json({ status: 'success', output: (stderr || stdout).trim().slice(-600) });
  } catch (e) { await audit(req, 'journal_vacuum', null, null, 'error', e.message); sendFail(res, e); }
});

router.post('/logrotate/force', needAdmin, async function (req, res) {
  try {
    const { stdout } = await execP('sudo -n /usr/sbin/logrotate -f /etc/logrotate.conf', { timeout: 30000 });
    await audit(req, 'logrotate_force', null, null, 'success', null);
    res.json({ status: 'success', output: (stdout || '(no output)').trim().slice(-400) });
  } catch (e) { await audit(req, 'logrotate_force', null, null, 'error', e.message); sendFail(res, e); }
});

router.post('/backup/run', needAdmin, async function (req, res) {
  // corpit (2026-09-06): the nightly is a root-run systemd unit (corpit-db-backup.service).
  // The API only STARTS it, through a sudoers entry scoped to exactly that command, and
  // never runs mysqldump itself. --no-block returns at once; the Backups card shows the result.
  if (!fs.existsSync('/etc/systemd/system/corpit-db-backup.service')) {
    return res.status(404).json({ error: 'backup unit not installed' });
  }
  let ok = true, err = null;
  try { await execP('sudo -n /usr/bin/systemctl start --no-block corpit-db-backup.service', { timeout: 15000 }); }
  catch (e) { ok = false; err = e.message; }
  await audit(req, 'backup_run', null, null, ok ? 'started' : 'error', err);
  res.json({ status: ok ? 'started' : 'error', error: err, note: 'Backup running in background; re-poll Backups card.', log: '/var/log/corpit-backup.log' });
});

router.post('/apt/upgrade', needAdmin, async function (req, res) {
  if (String(req.body && req.body.confirm) !== os.hostname()) {
    await audit(req, 'apt_upgrade', null, null, 'rejected', 'confirm mismatch');
    return res.status(400).json({ error: 'confirmation required', expected: os.hostname() });
  }
  // env(1) form so a sudoers entry can match it exactly (a VAR=value prefix needs SETENV).
  const upgradeCmd = '/usr/bin/env DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -y full-upgrade';
  if (!(await sudoAllows(upgradeCmd))) {
    await audit(req, 'apt_upgrade', null, { confirmed: true }, 'rejected', NOT_PERMITTED);
    return res.status(403).json({ status: 'error', error: NOT_PERMITTED });
  }
  const upgradeLog = LOG_DIR + '/apt-upgrade.log';
  const ok = fireDetached('sudo -n ' + upgradeCmd, upgradeLog);
  await audit(req, 'apt_upgrade', null, { confirmed: true }, ok ? 'started' : 'error', ok ? null : 'could not launch (log dir unwritable?)');
  res.json({ status: ok ? 'started' : 'error', note: 'Upgrade running in background. May set reboot-required. Watch ' + upgradeLog + '.', log: upgradeLog });
});

// ─────────────── TIER 3 (reboot) ───────────────

router.get('/reboot/preflight', needAdmin, async function (req, res) {
  const checks = [];
  // 1. reboot flag
  const flag = fs.existsSync('/var/run/reboot-required');
  checks.push({ name: 'Reboot flag set', state: flag ? 'ok' : 'warn',
    detail: flag ? '/var/run/reboot-required present' : 'No reboot-required flag — reboot may be unnecessary' });
  // 2. active crawls (blocking)
  let crawlBusy = false, crawlDetail = 'none running';
  try {
    const { stdout } = await execP("pgrep -af 'stale-crawl-job[.]js|storage-collect-job[.]js|site-storage-collect-job[.]js|dept-folder-walk-job[.]js' || true", { timeout: 5000 });
    if (stdout.trim()) { crawlBusy = true; crawlDetail = stdout.trim().split('\n').length + ' crawl process(es) running'; }
  } catch (e) {}
  checks.push({ name: 'No active crawl', state: crawlBusy ? 'down' : 'ok', detail: crawlDetail });
  // 3. recent backup
  let backupOk = false, backupDetail = 'no nightly backup found';
  try {
    const files = fs.readdirSync('/var/backups/corpit/nightly').map(function (n) { return fs.statSync('/var/backups/corpit/nightly/' + n).mtime; });
    if (files.length) {
      const newest = new Date(Math.max.apply(null, files));
      const ageH = (Date.now() - newest.getTime()) / 3600000;
      backupOk = ageH <= 26;
      backupDetail = 'latest ' + Math.round(ageH) + 'h old';
    }
  } catch (e) {}
  checks.push({ name: 'Recent backup (<26h)', state: backupOk ? 'ok' : 'down', detail: backupDetail + (backupOk ? '' : ' — blocks reboot; use Prepare & reboot to make one') });
  // 4. pm2 process list persisted
  let pm2Warn = false, pm2Detail = 'dump.pm2 current';
  try {
    const dumpMtime = fs.statSync(PM2_DUMP).mtime.getTime();
    const { stdout } = await execP(PM2_BIN + ' jlist', { timeout: 8000, env: PM2_ENV, maxBuffer: 4 * 1024 * 1024 });
    const maxStart = Math.max.apply(null, JSON.parse(stdout).map(function (p) { return (p.pm2_env && p.pm2_env.pm_uptime) || 0; }));
    if (maxStart > dumpMtime) { pm2Warn = true; pm2Detail = 'a process restarted after last save — run pm2 save first or list will differ after reboot'; }
  } catch (e) { pm2Detail = 'could not verify (' + e.message + ')'; pm2Warn = true; }
  checks.push({ name: 'PM2 list saved', state: pm2Warn ? 'warn' : 'ok', detail: pm2Detail });
  // 5. disk sane
  let diskState = 'ok', diskDetail = '';
  try {
    const { stdout } = await execP('df -B1 /', { timeout: 5000 });
    const parts = stdout.trim().split('\n')[1].trim().split(/\s+/);
    const pct = Math.round((Number(parts[2]) / Number(parts[1])) * 100);
    diskDetail = pct + '% used';
    if (pct >= 95) diskState = 'warn';
  } catch (e) { diskDetail = 'unknown'; }
  checks.push({ name: 'Disk not full', state: diskState, detail: diskDetail });

  const blocking = checks.filter(function (c) { return c.state === 'down'; });
  res.json({
    timestamp: new Date().toISOString(),
    hostname: os.hostname(),
    ready: blocking.length === 0,
    blockingCount: blocking.length,
    warnCount: checks.filter(function (c) { return c.state === 'warn'; }).length,
    checks: checks,
    confirmWith: os.hostname(),
  });
});

router.post('/reboot', needAdmin, async function (req, res) {
  if (String(req.body && req.body.confirm) !== os.hostname()) {
    await audit(req, 'reboot', os.hostname(), null, 'rejected', 'confirm mismatch');
    return res.status(400).json({ error: 'confirmation required', expected: os.hostname() });
  }
  // Re-check blocking preflight (crawls) before committing.
  try {
    const { stdout } = await execP("pgrep -af 'stale-crawl-job[.]js|storage-collect-job[.]js|site-storage-collect-job[.]js|dept-folder-walk-job[.]js' || true", { timeout: 5000 });
    if (stdout.trim()) {
      await audit(req, 'reboot', os.hostname(), null, 'blocked', 'active crawl');
      return res.status(409).json({ error: 'active crawl running — reboot blocked', detail: stdout.trim() });
    }
  } catch (e) {}
  const who = (req.user && req.user.email) || 'anonymous';
  // Schedule with a 60s window so this can be cancelled. shutdown(8) returns as soon as
  // the timer is set, so run it inline and report its real exit instead of a detached
  // launch that could not tell a refused sudo from a scheduled reboot.
  try {
    await execP('sudo -n /usr/sbin/shutdown -r +1 "IT Command server-health reboot by ' + who.replace(/[^a-zA-Z0-9@._-]/g, '') + '"', { timeout: 10000 });
  } catch (e) {
    const refused = SUDO_REFUSED.test(e.message || '');
    await audit(req, 'reboot', os.hostname(), { confirmed: true }, refused ? 'rejected' : 'error', refused ? NOT_PERMITTED : e.message);
    return res.status(refused ? 403 : 500).json({ status: 'error', error: refused ? NOT_PERMITTED : 'failed to schedule reboot: ' + e.message });
  }
  await audit(req, 'reboot', os.hostname(), { confirmed: true }, 'scheduled', '+1 min by ' + who);
  res.json({ status: 'scheduled', when: '+1 minute', cancelWith: 'POST /api/system/reboot/cancel', by: who });
});

// ── Prepare & reboot: pm2 save + fresh backup, verify, then reboot ──
var _rebootPrep = { state: 'idle', step: null, message: null, ts: null };
function prep(state, step, message) { _rebootPrep = { state: state, step: step, message: message, ts: new Date().toISOString() }; }

async function crawlRunning() {
  try {
    const { stdout } = await execP("pgrep -af 'stale-crawl-job[.]js|storage-collect-job[.]js|site-storage-collect-job[.]js|dept-folder-walk-job[.]js' || true", { timeout: 5000 });
    return stdout.trim() ? stdout.trim() : null;
  } catch (e) { return null; }
}

router.post('/reboot/prepare-and-go', needAdmin, async function (req, res) {
  if (String(req.body && req.body.confirm) !== os.hostname()) {
    await audit(req, 'reboot_prepare', os.hostname(), null, 'rejected', 'confirm mismatch');
    return res.status(400).json({ error: 'confirmation required', expected: os.hostname() });
  }
  if (_rebootPrep.state === 'running') {
    return res.status(202).json({ started: false, alreadyRunning: true });
  }
  // Blocking check prep cannot fix: active crawl.
  const busy = await crawlRunning();
  if (busy) {
    await audit(req, 'reboot_prepare', os.hostname(), null, 'blocked', 'active crawl');
    return res.status(409).json({ error: 'active crawl running — reboot blocked', detail: busy });
  }
  const who = (req.user && req.user.email) || 'anonymous';
  const prepShutdownCmd = '/usr/sbin/shutdown -r +1 "IT Command prepared reboot by ' + who.replace(/[^a-zA-Z0-9@._-]/g, '') + '"';
  if (!(await sudoAllows(prepShutdownCmd))) {
    await audit(req, 'reboot_prepare', os.hostname(), { confirmed: true }, 'rejected', NOT_PERMITTED);
    return res.status(403).json({ status: 'error', error: NOT_PERMITTED });
  }
  prep('running', 'starting', 'Preparing to reboot…');
  await audit(req, 'reboot_prepare', os.hostname(), { confirmed: true }, 'started', 'by ' + who);
  res.status(202).json({ started: true, note: 'Preparing; poll GET /api/system/reboot/prep-status.' });

  // Background: pm2 save → backup (wait) → verify → reboot
  setImmediate(async function () {
    try {
      prep('running', 'pm2_save', 'Saving PM2 process list…');
      await execP(PM2_BIN + ' save', { timeout: 15000, env: PM2_ENV });

      prep('running', 'backup', 'Taking a fresh backup (this can take a minute)…');
      if (!fs.existsSync('/etc/systemd/system/corpit-db-backup.service')) throw new Error('backup unit not installed');
      await execP('sudo -n /usr/bin/systemctl start corpit-db-backup.service', { timeout: 600000, maxBuffer: 8 * 1024 * 1024 });

      // Verify a fresh nightly now exists (<26h).
      prep('running', 'verify', 'Verifying backup…');
      var fresh = false, detail = 'not found';
      try {
        var files = fs.readdirSync('/var/backups/corpit/nightly').map(function (n) { return fs.statSync('/var/backups/corpit/nightly/' + n).mtime; });
        if (files.length) {
          var ageH = (Date.now() - new Date(Math.max.apply(null, files)).getTime()) / 3600000;
          fresh = ageH <= 26; detail = Math.round(ageH * 10) / 10 + 'h old';
        }
      } catch (e) { detail = e.message; }
      if (!fresh) throw new Error('backup not fresh after run (' + detail + ')');

      // Re-check crawl one more time before committing.
      var busy2 = await crawlRunning();
      if (busy2) throw new Error('crawl started during prep — aborted');

      prep('running', 'reboot', 'All checks passed — scheduling reboot (+1 min).');
      await execP('sudo -n ' + prepShutdownCmd, { timeout: 10000 });
      await audit(req, 'reboot', os.hostname(), { prepared: true }, 'scheduled', '+1 min by ' + who);
      prep('reboot-scheduled', 'done', 'Reboot scheduled in 1 minute. Cancel window active.');
    } catch (e) {
      prep('aborted', 'error', 'Aborted: ' + e.message);
      await audit(req, 'reboot_prepare', os.hostname(), null, 'aborted', e.message);
    }
  });
});

router.get('/reboot/prep-status', needAdmin, function (req, res) {
  res.json(_rebootPrep);
});

router.post('/reboot/cancel', needAdmin, async function (req, res) {
  try {
    await execP('sudo -n /usr/sbin/shutdown -c', { timeout: 5000 });
    await audit(req, 'reboot_cancel', os.hostname(), null, 'success', null);
    res.json({ status: 'cancelled' });
  } catch (e) { await audit(req, 'reboot_cancel', null, null, 'error', e.message); sendFail(res, e); }
});

// ─────────────── DB maintenance ───────────────

router.post('/db/analyze', needAdmin, async function (req, res) {
  try {
    const [tables] = await pool.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
    );
    const names = tables.map(function (t) { return t.table_name || t.TABLE_NAME; });
    let analyzed = 0;
    for (const name of names) {
      await pool.query('ANALYZE TABLE `' + name.replace(/`/g, '') + '`');
      analyzed++;
    }
    await audit(req, 'db_analyze', 'corpit_hub', null, 'success', analyzed + ' tables');
    res.json({ status: 'success', detail: analyzed + ' tables analyzed' });
  } catch (e) {
    await audit(req, 'db_analyze', 'corpit_hub', null, 'error', e.message);
    res.status(500).json({ error: e.message });
  }
});

router.post('/db/optimize', needAdmin, async function (req, res) {
  if (String(req.body && req.body.confirm) !== os.hostname()) {
    await audit(req, 'db_optimize', 'corpit_hub', null, 'rejected', 'confirm mismatch');
    return res.status(400).json({ error: 'confirmation required', expected: os.hostname() });
  }
  // Run in background — table locks can take minutes on large DB
  const logFile = LOG_DIR + '/db-optimize.log';
  const envLine = "cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs)";
  const cmd = `node -e "
const mysql=require('mysql2/promise');
require('dotenv').config({path:'/var/www/corpit-hub-api/.env'});
(async()=>{
  const pool=mysql.createPool({host:process.env.DB_HOST,port:process.env.DB_PORT||3306,user:process.env.DB_USER,password:process.env.DB_PASSWORD,database:process.env.DB_NAME,connectionLimit:1});
  const [tables]=await pool.query(\"SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_type='BASE TABLE'\");
  for(const t of tables){
    const n=(t.table_name||t.TABLE_NAME).replace(/\`/g,'');
    console.log('OPTIMIZE TABLE '+n);
    await pool.query('OPTIMIZE TABLE \`'+n+'\`');
    console.log('done: '+n);
  }
  await pool.end();
  console.log('OPTIMIZE complete');
})().catch(e=>{console.error(e.message);process.exit(1);});
"`;
  const fired = fireDetached(cmd, logFile);
  await audit(req, 'db_optimize', 'corpit_hub', { confirmed: true }, fired ? 'started' : 'error', 'log: ' + logFile);
  if (!fired) return res.status(500).json({ error: 'failed to start optimize job' });
  res.json({ status: 'started', note: 'OPTIMIZE running in background. Re-poll db-health when done.', log: logFile });
});

// ─────────────── audit view ───────────────
router.get('/audit', needReadSH, async function (req, res) {
  const limit = Math.min(parseInt(req.query.limit) || 25, 100);
  try {
    const [rows] = await pool.query(
      'SELECT action, target, actor_email, result, detail, created_at FROM corpit_hub.server_action_audit ORDER BY id DESC LIMIT ?', [limit]);
    res.json({ count: rows.length, entries: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/actions/catalog', needReadSH, function (req, res) {
  res.json({ pm2: ALLOWED_PM2, jobs: Object.keys(JOBS).map(function (k) { return { key: k, label: JOBS[k].label, long: JOBS[k].long }; }), enforceRbac: ENFORCE_RBAC });
});

// ─── Upgrade result: tail of apt-upgrade log + running status ───
router.get('/apt/upgrade-status', needReadSH, async function (req, res) {
  var logFile = LOG_DIR + '/apt-upgrade.log';
  var result = { exists: false, running: false, tail: '', mtime: null, ageMin: null };
  // Check if apt-get upgrade is still running
  try {
    // The bracket class is load-bearing: execP runs this through `/bin/sh -c`,
    // so the wrapper shell's own cmdline contains the pattern text. `pgrep -af`
    // matches full command lines and excludes itself but NOT its parent, so a
    // plain 'apt-get.*full-upgrade' matches that shell and `running` is
    // permanently true. 'apt-ge[t]' cannot match its own literal source.
    var proc = await execP("pgrep -af 'apt-ge[t].*full-upgrade' 2>/dev/null || true", { timeout: 3000 });
    result.running = !!(proc.stdout && proc.stdout.trim());
  } catch (e) {}
  // Read tail of log
  try {
    var stat = fs.statSync(logFile);
    result.exists = true;
    result.mtime = stat.mtime;
    result.ageMin = Math.round((Date.now() - stat.mtime.getTime()) / 60000);
    var buf = fs.readFileSync(logFile, 'utf8');
    var lines = buf.split('\n');
    // Find the start of the LAST run (last "Reading package lists...")
    var lastRunStart = -1;
    for (var i = lines.length - 1; i >= 0; i--) {
      if (lines[i].indexOf('Reading package lists') !== -1) { lastRunStart = i; break; }
    }
    if (lastRunStart >= 0) {
      result.tail = lines.slice(lastRunStart).join('\n').trim();
    } else {
      result.tail = lines.slice(-30).join('\n').trim();
    }
    // Extract a quick summary from the last run
    var summaryMatch = result.tail.match(/(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded/);
    if (summaryMatch) {
      result.summary = { upgraded: parseInt(summaryMatch[1]), installed: parseInt(summaryMatch[2]), removed: parseInt(summaryMatch[3]), held: parseInt(summaryMatch[4]) };
    }
    // Check for phased deferral in output
    if (result.tail.indexOf('deferred due to phasing') !== -1) {
      result.phasedDeferral = true;
    }
  } catch (e) {
    result.error = e.code === 'ENOENT' ? 'No upgrade has been run yet.' : e.message;
  }
  res.json(result);
});

// ── Security posture (Server Health "Security" tab) ──────────────────────────
const secPosture = require('./security-posture');
function needReadSH(req, res, next) {
  return ENFORCE_RBAC ? rbac.requirePage('server-health', 'read')(req, res, next) : next();
}
router.get('/security-posture', needReadSH, async function (req, res) {
  try { res.json(await secPosture.computePosture()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
router.post('/security-posture/status', needAdmin, async function (req, res) {
  const id = String((req.body && req.body.id) || '');
  const st = String((req.body && req.body.status) || '');
  const note = (req.body && req.body.note) || '';
  const who = (req.user && (req.user.email || req.user.displayName)) || 'unknown';
  const r = secPosture.setStatus(id, st, note, who);
  if (!r.ok) return res.status(400).json(r);
  try { await audit(req, 'security_status', id, { status: st }, 'ok', note ? String(note).slice(0, 200) : null); } catch (e) {}
  res.json(r);
});

module.exports = router;

