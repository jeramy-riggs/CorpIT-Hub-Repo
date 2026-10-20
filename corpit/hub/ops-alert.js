#!/usr/bin/env node
'use strict';
// =====================================================================
// ops-alert.js  (v1.1.0, 2026-09-25)                    CORPIT-OPS-ALERT
//
// Emails operational failures on this host -- the nightly DB backup,
// Entra/Okta syncs (entra_sync_status) and every job run through
// /usr/local/bin/corpit-cronwrap -- to the addresses the admin console
// publishes in /etc/corpit/shared/ops-alerts.json (Administration > Settings >
// Alerts card, "Email ops failures to"). A missing or empty list mails nobody; the
// failure is still written to /var/log/corpit/ops-alert.log.
//
// Approved behaviour (DECISIONS-2026-09-25):
//   C1  Sender: the mail-graph.js defaults, itcommand@auction.com "CorpIT".
//   C2  One email when a job starts failing, a reminder once per UTC day
//       while it keeps failing, and a RECOVERED email when it succeeds.
//   C3  No burst cap.
//   C4  A sync whose latest run is 'partial' is emailed, PARTIAL in the subject.
//   C5  A sync run stuck in 'running' for longer than syncStaleHours (the
//       console setting alerts.sync_stale_hours) is emailed. Only runs that
//       started after launch count (<state>/launch.json, written at deploy).
//   C6  sync-watch runs every 15 min (corpit-ops-sync-watch.timer).
//   C7  No log tails in the email.
//
// Mail goes through mail-graph.js (Graph app-only sendMail; only 202 counts
// as sent). This host has no MTA and no SMTP relay; Graph is the only path.
// Sign-in alerts are NOT handled here, and alert_channels is not read.
//
// Always runs as `corpit`: cronwrap drops to it with setpriv, and the
// systemd units set User=corpit or use the same setpriv line.
//
// STREAKS (C2). While a key is failing, <state>/<key>.alerted holds
//   {key, job, source, result, kind, firstFailedAt, lastMailAt, mails}.
//   The marker is written only after Graph answers 202, so a send that
//   failed is retried on the next failure. A failure on a later UTC day
//   than lastMailAt sends the daily reminder. A success while the marker
//   exists sends RECOVERED and removes the marker (kept if the send
//   failed, so the next success retries).
//
// MODES
//   fail --key K --job J --source cron|sync|systemd [--kind failed|partial|stuck]
//        [--exit N | --result R] [--started T] [--duration S] [--detail TEXT] [--id N]
//   ok --key K [--detail TEXT]
//       The job succeeded. RECOVERED email if a streak marker exists.
//   systemd --unit U       OnFailure= handler (corpit-ops-alert@.service);
//                          key systemd.<U>; reads MONITOR_* from systemd.
//   systemd-ok --unit U    OnSuccess= handler (corpit-ops-recovered@.service).
//   sync-watch
//       Latest finished entra_sync_status row per job: 'failure' -> fail,
//       'partial' -> fail with PARTIAL (key sync.<job>); 'success' -> ok.
//       Runs 'running' since before now - syncStaleHours that started
//       after launch -> fail with STUCK (key sync-stuck.<job>.<id>); ok
//       once that run is no longer 'running'.
//   test
//       One test email to the published recipients.
//   --dry-run (any mode)
//       Sends nothing. Streak markers go to <state>/dry-run/ so real state
//       is never touched. The would-be email is printed to stdout.
//
// EXIT  0 done (sent, suppressed, cleared, or nothing to do)
//       1 unexpected error, or a streak marker could not be removed
//       2 usage   3 no recipients published   4 send failed
//       5 sync-watch could not read the database
//       6 sync-watch could not run the stuck check (launch.json missing or
//         invalid, or the published syncStaleHours is invalid)
// =====================================================================

require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const mail = require('./mail-graph');

// itam dev, settingsfold W3 2026-10-12: the console now publishes to
// /etc/corpit/shared/ (PATH-RELEASE-20260929), not /etc/corpit/.
const CONFIG_PATH   = '/etc/corpit/shared/ops-alerts.json';
const STATE_DIR     = '/var/lib/corpit/ops-alert';
const LAUNCH_PATH   = path.join(STATE_DIR, 'launch.json');
const LOG_PATH      = '/var/log/corpit/ops-alert.log';
const BACKUP_STATUS = '/var/backups/corpit/nightly-status.json';
const HOST          = os.hostname();
const WHERE_SET     = 'Recipients are set in the admin console (https://subadmin.nrpi.local/console#system/settings): Administration > Settings > Alerts card, "Email ops failures to".';

// Subject words per kind of failure: first email, then the daily reminder.
const KINDS = {
  failed:  { first: 'FAILED',  again: 'STILL FAILING' },
  partial: { first: 'PARTIAL', again: 'STILL PARTIAL' },
  stuck:   { first: 'STUCK',   again: 'STILL STUCK' },
};

const LATEST_SQL =
  `SELECT s.id, s.job, s.status, s.started_at, s.completed_at, s.error_message
     FROM entra_sync_status s
     JOIN (SELECT job, MAX(id) AS mid FROM entra_sync_status
            WHERE status <> 'running' GROUP BY job) m ON m.mid = s.id`;
const STUCK_SQL =
  `SELECT id, job, started_at FROM entra_sync_status
    WHERE status = 'running' AND started_at >= ?
      AND started_at < UTC_TIMESTAMP() - INTERVAL ? HOUR
    ORDER BY id`;
const ROWS_SQL = 'SELECT id, status FROM entra_sync_status WHERE id IN (?)';

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run') { out.dryRun = true; continue; }
    if (a.startsWith('--')) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) { out[a.slice(2)] = ''; continue; }
      out[a.slice(2)] = v; i++;
      continue;
    }
    out._.push(a);
  }
  return out;
}

function clip(s, n) {
  s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n - 3) + '...' : s;
}
function utcDay(ts) {
  const m = /^(\d{4}-\d{2}-\d{2})T/.exec(String(ts || ''));
  return m ? m[1] : '';
}

function log(rec) {
  const line = JSON.stringify(Object.assign({ ts: new Date().toISOString() }, rec));
  console.log(line);
  try { fs.appendFileSync(LOG_PATH, line + '\n', { mode: 0o640 }); } catch (e) { /* best effort */ }
}

function usage(msg) {
  console.error('ops-alert: ' + msg);
  console.error('usage: ops-alert.js fail|ok|systemd|systemd-ok|sync-watch|test [options] [--dry-run]');
  return 2;
}

function readConfig() {
  let doc;
  try { doc = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); }
  catch (e) {
    return { list: [], published: false, staleHours: null,
             why: e.code === 'ENOENT' ? 'not published' : 'unreadable (' + (e.code || e.message) + ')' };
  }
  const list = (Array.isArray(doc && doc.recipients) ? doc.recipients : [])
    .map(s => String(s).trim()).filter(Boolean);
  const h = doc ? doc.syncStaleHours : undefined;
  const staleHours = (Number.isInteger(h) && h >= 1 && h <= 720) ? h : null;
  return { list, published: true, staleHours, why: list.length ? '' : 'list is empty' };
}

function readLaunch() {
  let d;
  try { d = JSON.parse(fs.readFileSync(LAUNCH_PATH, 'utf8')); }
  catch (e) { return { error: 'launch.json ' + (e.code === 'ENOENT' ? 'missing' : 'unreadable (' + (e.code || e.message) + ')') }; }
  const at = String((d && d.launchedAt) || '');
  if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(at)) return { error: 'launch.json launchedAt is not "YYYY-MM-DD HH:MM:SS"' };
  return { at };
}

function stateDir(dry) { return dry ? path.join(STATE_DIR, 'dry-run') : STATE_DIR; }
function markerPath(key, dry) {
  const safe = String(key).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 200);
  return path.join(stateDir(dry), safe + '.alerted');
}
// null = no streak. An unreadable marker still means a streak exists: {}.
function readMarker(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')) || {}; }
  catch (e) { return e.code === 'ENOENT' ? null : {}; }
}
function writeMarker(p, rec) {
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o750 });
    fs.writeFileSync(p, JSON.stringify(rec) + '\n', { mode: 0o640 });
    return true;
  } catch (e) {
    log({ action: 'marker-write-failed', marker: p, error: e.code || e.message });
    return false;
  }
}
function removeMarker(p) {
  try { fs.unlinkSync(p); return true; }
  catch (e) {
    if (e.code === 'ENOENT') return true;
    log({ action: 'marker-remove-failed', marker: p, error: e.code || e.message });
    return false;
  }
}

async function send(subject, text, dry) {
  const r = readConfig();
  if (dry) return { ok: true, dry: true, to: r.list.length, why: r.why };
  if (!r.list.length) return { ok: false, reason: 'no-recipients', detail: r.why };
  const res = await mail.sendMail({ to: r.list, subject, text });
  return Object.assign({ to: r.list.length }, res);
}
function exitFor(r) { return r.ok ? 0 : (r.reason === 'no-recipients' ? 3 : 4); }
function outcome(r) { return r.ok ? (r.dry ? 'dry-run (would send)' : 'sent') : 'NOT-sent'; }

function bodyText(f) {
  const L = [f.lead, ''];
  L.push('Job:      ' + f.job);
  if (f.source) L.push('Source:   ' + f.source);
  if (f.result) L.push('Result:   ' + f.result);
  if (f.started)  L.push('Started:  ' + f.started);
  if (f.since)    L.push('Failing since: ' + f.since + ' (first email)');
  if (f.mails)    L.push('Emails so far: ' + f.mails);
  L.push('Reported: ' + new Date().toISOString());
  if (f.duration) L.push('Duration: ' + f.duration + 's');
  if (f.detail)   L.push('', 'Detail:   ' + f.detail);
  if (f.hints && f.hints.length) {
    L.push('', 'Where to look:');
    for (const h of f.hints) L.push('  ' + h);
  }
  L.push('', f.note);
  L.push('', '-- ops-alert.js on ' + HOST + '. ' + WHERE_SET);
  return L.join('\n');
}

function hints(source, job, a) {
  if (Array.isArray(a.where)) return a.where;
  if (source === 'sync') return [
    'SELECT * FROM corpit_hub.entra_sync_status WHERE id = ' + (a.id || '?') + ';',
    'syncs-worker logs: /var/lib/corpit/.pm2/logs/syncs-worker-*.log',
  ];
  return [
    'Run record: /var/log/corpit/cronwrap/' + job + '.json',
    "Cron line and its log: sudo crontab -l | grep -F 'corpit-cronwrap " + job + " '",
    "Not in root's crontab? It is a systemd timer: systemctl list-timers 'corpit-*'",
  ];
}

function leadFor(kind, source) {
  if (kind === 'partial') return 'A directory sync on ' + HOST + ' finished with status partial.';
  if (kind === 'stuck')   return 'A directory sync run on ' + HOST + ' has been in status running for too long.';
  return 'A scheduled operation on ' + HOST + ' failed' + (source === 'sync' ? ' (directory sync).' : '.');
}

async function cmdFail(a) {
  if (!a.key) return usage('fail needs --key');
  const dry  = !!a.dryRun;
  const key  = a.key;
  const job  = a.job || key;
  const kind = KINDS[a.kind] ? a.kind : 'failed';
  const mk   = markerPath(key, dry);
  const m    = readMarker(mk);
  const now  = new Date().toISOString();
  if (m) {
    const last = utcDay(m.lastMailAt);
    if (last && last >= now.slice(0, 10)) {
      log({ mode: 'fail', key, action: 'suppressed (already emailed today)',
            firstFailedAt: m.firstFailedAt, lastMailAt: m.lastMailAt, dry });
      return 0;
    }
  }
  const reminder = !!m;
  const since    = reminder ? (m.firstFailedAt || 'unknown') : now;
  const mails    = reminder ? (Number(m.mails) || 0) : 0;
  const source   = a.source || 'cron';
  const result   = (a.exit !== undefined && a.exit !== '') ? 'exit ' + a.exit : (a.result || 'failed');
  const subject  = '[CorpIT ops] ' + (reminder ? KINDS[kind].again : KINDS[kind].first) + ': ' +
                   job + ' (' + result + ')' + (reminder ? ' since ' + since : '') + ' on ' + HOST;
  const text = bodyText({
    lead: reminder ? 'Reminder: this is still failing on ' + HOST + '.' : leadFor(kind, source),
    job, source, result, started: a.started, duration: a.duration,
    since: reminder ? since : '', mails,
    detail: clip(a.detail, Number(a.detailMax) || 300), hints: hints(source, job, a),
    note: 'While this keeps failing you get one reminder a day (UTC). ' +
          'You get one more email when it succeeds again.',
  });
  const r = await send(subject, text, dry);
  if (r.ok) writeMarker(mk, { key, job, source, result, kind, firstFailedAt: since,
                              lastMailAt: now, mails: mails + 1, dry });
  log({ mode: 'fail', key, action: outcome(r) + (reminder ? ' (daily reminder)' : ''), to: r.to,
        why: r.why, reason: r.reason, status: r.status, detail: clip(r.detail, 200), subject, dry });
  if (dry) console.log('\n' + subject + '\n\n' + text + '\n');
  return exitFor(r);
}

async function cmdOk(a) {
  if (!a.key) return usage('ok needs --key');
  const dry = !!a.dryRun;
  const key = a.key;
  const mk  = markerPath(key, dry);
  const m   = readMarker(mk);
  if (!m) return 0;                                // no failure streak: nothing to say
  const job = m.job || a.job || key;
  const subject = '[CorpIT ops] RECOVERED: ' + job + ' on ' + HOST;
  const text = bodyText({
    lead: job + ' on ' + HOST + ' is working again.',
    job, source: m.source, result: 'succeeded' + (m.result ? ' (was: ' + m.result + ')' : ''),
    since: m.firstFailedAt || 'unknown', mails: Number(m.mails) || 0,
    detail: clip(a.detail, 300),
    note: 'No further email for this job unless it fails again.',
  });
  const r = await send(subject, text, dry);
  let cleared = false;
  if (r.ok || r.reason === 'no-recipients') cleared = removeMarker(mk);
  log({ mode: 'ok', key, action: outcome(r) + (cleared ? ', streak cleared' : ', streak kept'),
        to: r.to, why: r.why, reason: r.reason, status: r.status, detail: clip(r.detail, 200), subject, dry });
  if (dry) console.log('\n' + subject + '\n\n' + text + '\n');
  if ((r.ok || r.reason === 'no-recipients') && !cleared) return 1;
  return exitFor(r);
}

function systemdUnit(a) { return a.unit || process.env.MONITOR_UNIT || 'unknown-unit'; }

async function cmdSystemd(a) {
  const unit   = systemdUnit(a);
  const res    = process.env.MONITOR_SERVICE_RESULT || '';
  const code   = process.env.MONITOR_EXIT_CODE || '';
  const status = process.env.MONITOR_EXIT_STATUS || '';
  if (res === 'success') { log({ mode: 'systemd', unit, action: 'ignored (success)' }); return 0; }
  const result = [res && 'result=' + res, code && (code + (status ? ' ' + status : ''))]
    .filter(Boolean).join(', ') || 'failed';
  const where = ['journalctl -u ' + unit + ' -n 200 --no-pager'];
  let detail = '';
  if (unit === 'corpit-db-backup.service') {
    where.push('/var/log/corpit-backup.log', BACKUP_STATUS);
    try {
      const s = JSON.parse(fs.readFileSync(BACKUP_STATUS, 'utf8'));
      detail = 'nightly-status.json says status=' + s.status + ', finishedAt=' +
               (s.finishedAt || s.finished || '?') + (s.errors ? ', errors=' + s.errors : '') +
               ' (a finishedAt older than tonight means the script was killed before it wrote status)';
    } catch (e) { detail = 'nightly-status.json unreadable (' + (e.code || e.message) + ')'; }
  }
  return cmdFail({ key: 'systemd.' + unit, job: unit, source: 'systemd', result, detail,
                   detailMax: 500, where, dryRun: a.dryRun });
}

async function cmdSystemdOk(a) {
  const unit = systemdUnit(a);
  return cmdOk({ key: 'systemd.' + unit, dryRun: a.dryRun,
                 detail: unit + ' completed successfully at ' + new Date().toISOString() });
}

function openStuckMarkers(dry) {
  let names = [];
  try { names = fs.readdirSync(stateDir(dry)); } catch (e) { return []; }
  const out = [];
  for (const n of names) {
    const m = /^sync-stuck\.(.+)\.(\d+)\.alerted$/.exec(n);
    if (m) out.push({ key: 'sync-stuck.' + m[1] + '.' + m[2], job: m[1], id: m[2] });
  }
  return out;
}

async function cmdSyncWatch(a) {
  const dry = !!a.dryRun;
  const cfg = readConfig();
  const launch = readLaunch();
  // The stuck check needs both the threshold and the launch time. When the
  // settings were never published nobody can be mailed anyway, so that is a
  // skip, not an error; a published file without a valid threshold, or a
  // missing launch.json, is an error (exit 6) so the watcher shows as failed.
  let stuckSkip = '', stuckErr = false;
  if (!cfg.published)              stuckSkip = 'settings ' + cfg.why;
  else if (cfg.staleHours == null) { stuckSkip = 'published syncStaleHours is missing or invalid'; stuckErr = true; }
  else if (launch.error)           { stuckSkip = launch.error; stuckErr = true; }
  const hours = cfg.staleHours;

  const mysql = require('mysql2/promise');
  let conn, rows = [], stuck = [], ended = [];
  try {
    conn = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '3306', 10),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      connectTimeout: 10000,
      dateStrings: true,
    });
    [rows] = await conn.query(LATEST_SQL);
    if (!stuckSkip) {
      [stuck] = await conn.query(STUCK_SQL, [launch.at, hours]);
      const stuckIds = new Set(stuck.map(s => String(s.id)));
      const open = openStuckMarkers(dry).filter(x => !stuckIds.has(x.id));
      if (open.length) {
        const [st] = await conn.query(ROWS_SQL, [open.map(x => Number(x.id))]);
        const byId = new Map(st.map(r => [String(r.id), r.status]));
        for (const x of open) {
          const s = byId.get(x.id);
          if (s !== 'running') ended.push(Object.assign({ now: s || 'deleted' }, x));
        }
      }
    }
  } catch (e) {
    log({ mode: 'sync-watch', action: 'db-error', error: clip(e.code || e.message, 200), dry });
    return 5;
  } finally {
    if (conn) { try { await conn.end(); } catch (e) { /* ignore */ } }
  }

  let worst = 0, failing = 0, partial = 0, recovered = 0;
  for (const r of rows) {
    const key = 'sync.' + r.job;
    if (r.status === 'failure' || r.status === 'partial') {
      if (r.status === 'failure') failing++; else partial++;
      const c = await cmdFail({ key, job: 'sync:' + r.job, source: 'sync',
                                kind: r.status === 'partial' ? 'partial' : 'failed',
                                result: 'status=' + r.status, started: r.started_at,
                                detail: r.error_message, id: r.id, dryRun: a.dryRun });
      worst = Math.max(worst, c);
    } else if (r.status === 'success') {
      if (readMarker(markerPath(key, dry))) {
        recovered++;
        worst = Math.max(worst, await cmdOk({ key, dryRun: a.dryRun,
          detail: 'latest run id ' + r.id + ' finished with status success at ' + (r.completed_at || '?') + ' UTC' }));
      }
    }
  }
  for (const s of stuck) {
    const c = await cmdFail({ key: 'sync-stuck.' + s.job + '.' + s.id, job: 'sync:' + s.job,
                              source: 'sync', kind: 'stuck',
                              result: 'status=running for more than ' + hours + 'h',
                              started: s.started_at, id: s.id,
                              detail: 'run id ' + s.id + ' started ' + s.started_at +
                                      ' UTC and has not finished', dryRun: a.dryRun });
    worst = Math.max(worst, c);
  }
  for (const x of ended) {
    recovered++;
    worst = Math.max(worst, await cmdOk({ key: x.key, dryRun: a.dryRun,
      detail: 'run id ' + x.id + (x.now === 'deleted' ? ' no longer exists' : ' is now status ' + x.now) }));
  }
  if (stuckErr) worst = Math.max(worst, 6);
  log({ mode: 'sync-watch', action: 'checked', jobs: rows.length, failing, partial, stuck: stuck.length,
        recovered, stuckCheck: stuckSkip ? 'skipped: ' + stuckSkip : 'running > ' + hours + 'h since ' + launch.at,
        dry });
  return worst;
}

async function cmdTest(a) {
  const subject = '[CorpIT ops] TEST from ' + HOST;
  const text = 'Test email from ops-alert.js on ' + HOST + ' at ' + new Date().toISOString() + '.\n\n' +
    'Receiving this means backup, sync and scheduled-job failures on this host reach this address.\n' +
    WHERE_SET;
  const r = await send(subject, text, !!a.dryRun);
  log({ mode: 'test', action: outcome(r), to: r.to, why: r.why, reason: r.reason,
        status: r.status, detail: clip(r.detail, 200), dry: !!a.dryRun });
  return exitFor(r);
}

async function main() {
  const a = parseArgs(process.argv.slice(2));
  switch (a._[0]) {
    case 'fail':       return cmdFail(a);
    case 'ok':         return cmdOk(a);
    case 'systemd':    return cmdSystemd(a);
    case 'systemd-ok': return cmdSystemdOk(a);
    case 'sync-watch': return cmdSyncWatch(a);
    case 'test':       return cmdTest(a);
    default:           return usage('unknown mode ' + (a._[0] || '(none)'));
  }
}

main().then(
  code => process.exit(code || 0),
  e => { log({ action: 'crash', error: clip(e && e.stack || e, 400) }); process.exit(1); });
