'use strict';
// DARKTRACE-EMAIL 2026-10-14 — the /EMAIL puller. Runs in syncs-worker (startScheduler),
// never in the hub API's event loop. Read-only against Darktrace.
//
// Each run re-reads the last 7 days, so a message released since the last run stops
// counting as held:
//   emails/search  rcpt_rcpt_status = held        -> dt_email_message / dt_email_rcpt
//   emails/search  rcpt_rcpt_status = junk        -> same
//   emails/search  tag_severity     = critical    -> same, is_critical = 1
//   dash/threat_data (7 days)                     -> run row: threats_7d, inbound_7d
//   dash/data_loss                                -> dt_email_dlp      (replaced each run)
//   dash/user_anomaly                             -> dt_email_anomaly  (replaced each run)
//   system/audit/events (since the newest stored, 7 days on the first run) -> dt_email_audit
// One step failing does not stop the others; the run is then 'partial' and says which.
//
// Schedule: a 60 s tick checks dt_email_config (enabled, cadence_min) and the last run,
// so a Settings change applies without a restart. A MySQL named lock keeps two
// processes (or the A and B nodes) from running at once. Each run is recorded in
// dt_email_run and in the observability job registry (darktrace-email-sync.js).

const lib = require('./darktrace-email-lib');
const { withLock } = require('./sync-lock');
let obsJob = null;
try { obsJob = require('./obs-job'); } catch (e) { /* observability is optional */ }

const JOB = 'darktrace-email-sync.js';
const LOCK = 'corpit-darktrace-email-sync';
const DAY = 86400000;
const MAX_PAGES = 250;            // 5,000 messages per search per run
const TICK_MS = 60 * 1000;

const SEARCHES = [
  { key: 'held',     criteria: [{ apiFilter: 'rcpt_rcpt_status', operator: '=', value: 'held' }] },
  { key: 'junk',     criteria: [{ apiFilter: 'rcpt_rcpt_status', operator: '=', value: 'junk' }] },
  { key: 'critical', criteria: [{ apiFilter: 'tag_severity', operator: '=', value: 'critical' }] },
];

const clip = (v, n) => (v == null ? null : String(v).slice(0, n));
const int = v => (v == null || v === '' || !isFinite(Number(v)) ? null : Math.trunc(Number(v)));
const lower = v => (v == null ? null : String(v).trim().toLowerCase());
function msDate(ms) { const n = Number(ms); return isFinite(n) && n > 0 ? new Date(n) : null; }
function msgDate(m) {
  if (m.dtime_unix != null) {
    const n = Number(m.dtime_unix);
    if (isFinite(n) && n > 0) return new Date(n < 1e12 ? n * 1000 : n);
  }
  const d = m.dtime ? new Date(m.dtime) : null;
  return d && !isNaN(d) ? d : null;
}

async function storeMessages(p, runId, rows, criticalIds) {
  let rcpts = 0;
  for (const m of rows) {
    await p.query(
      `INSERT INTO dt_email_message (uuid, dtime, direction, from_email, from_name, subject, model_score,
         n_attachments, n_links, is_critical, seen_run_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE dtime=VALUES(dtime), direction=VALUES(direction), from_email=VALUES(from_email),
         from_name=VALUES(from_name), subject=VALUES(subject), model_score=VALUES(model_score),
         n_attachments=VALUES(n_attachments), n_links=VALUES(n_links),
         is_critical=GREATEST(is_critical, VALUES(is_critical)), seen_run_id=VALUES(seen_run_id)`,
      [clip(m.uuid, 64), msgDate(m), clip(m.direction, 16), clip(lower(m.header_from_email), 320),
       clip(m.header_from_personal, 255), clip(m.header_subject, 500), int(m.model_score),
       int(m.n_attachments), int(m.n_links), criticalIds.has(m.uuid) ? 1 : 0, runId]);
    for (const r of Array.isArray(m.rcpts) ? m.rcpts : []) {
      if (!r || !r.rcpt_to) continue;
      rcpts++;
      await p.query(
        `INSERT INTO dt_email_rcpt (uuid, rcpt_to, rcpt_status, action_status, actions, tags, is_group, seen_run_id)
         VALUES (?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE rcpt_status=VALUES(rcpt_status), action_status=VALUES(action_status),
           actions=VALUES(actions), tags=VALUES(tags), is_group=VALUES(is_group), seen_run_id=VALUES(seen_run_id)`,
        [clip(m.uuid, 64), clip(lower(r.rcpt_to), 320), clip(r.rcpt_status, 32), clip(r.action_status, 64),
         JSON.stringify(Array.isArray(r.rcpt_actions_taken) ? r.rcpt_actions_taken : []),
         JSON.stringify(Array.isArray(r.tags) ? r.tags : []), r.is_group_email ? 1 : 0, runId]);
    }
  }
  return rcpts;
}

// Replace a snapshot table in one transaction, so a reader never sees it half-empty.
async function replaceSnapshot(p, table, cols, rows, runId) {
  const conn = await p.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('DELETE FROM ' + table);
    for (const r of rows) {
      await conn.query('INSERT INTO ' + table + ' (' + cols.concat('run_id').join(', ') + ') VALUES (' +
        cols.concat('run_id').map(() => '?').join(',') + ')', cols.map(c => r[c]).concat(runId));
    }
    await conn.commit();
  } catch (e) { try { await conn.rollback(); } catch (_) { /* */ } throw e; }
  finally { conn.release(); }
}

// dash/data_loss and dash/user_anomaly are objects keyed by address.
function keyed(obj, keyName, fields) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new lib.DtError('expected an object keyed by address');
  return Object.keys(obj).map(k => {
    const v = obj[k] || {}, row = {};
    row[keyName] = clip(lower(k), 320);
    for (const f of fields) row[f] = (f === 'percentage') ? (isFinite(Number(v[f])) ? Number(v[f]) : null) : int(v[f]);
    return row;
  });
}

async function runOnce(opts) {
  const p = lib.pool();
  const cfg = (opts && opts.cfg) || await lib.loadConfig(p);
  if (!lib.configured(cfg)) throw new Error('not configured');
  const now = Date.now(), from = now - 7 * DAY;
  const [ins] = await p.query("INSERT INTO dt_email_run (started_at, state) VALUES (NOW(3), 'running')");
  const runId = ins.insertId;
  const out = { held_7d: null, junk_7d: null, critical_7d: null, threats_7d: null, inbound_7d: null,
                messages: 0, rcpts: 0, dlp: null, anomaly: null, audit_new: null, pages: 0, capped: [], errors: [] };
  const fail = (step, e) => out.errors.push(step + ': ' + ((e && e.message) || String(e)));

  // searches
  const found = {};
  for (const s of SEARCHES) {
    try {
      const r = await lib.searchAll(cfg, s.criteria, from, now, MAX_PAGES);
      found[s.key] = r.rows; out.pages += r.pages;
      if (r.capped) out.capped.push(s.key);
      out[s.key + '_7d'] = r.rows.length;
    } catch (e) { fail('search ' + s.key, e); }
  }
  try {
    const all = new Map();
    for (const k of Object.keys(found)) for (const m of found[k]) all.set(m.uuid, m);
    const crit = new Set((found.critical || []).map(m => m.uuid));
    out.messages = all.size;
    out.rcpts = await storeMessages(p, runId, [...all.values()], crit);
  } catch (e) { fail('store messages', e); }

  // dashboard numbers
  try {
    const t = await lib.get(cfg, 'dash/threat_data', { start: from, end: now, domains: '' });
    out.threats_7d = int(t && t.threats);
    out.inbound_7d = int(t && t.inbound);
  } catch (e) { fail('threat_data', e); }

  try {
    const rows = keyed(await lib.get(cfg, 'dash/data_loss'), 'sender', ['n_emails', 'n_attachments', 'n_rcpts', 'total_emails']);
    await replaceSnapshot(p, 'dt_email_dlp', ['sender', 'n_emails', 'n_attachments', 'n_rcpts', 'total_emails'], rows, runId);
    out.dlp = rows.length;
  } catch (e) { fail('data_loss', e); }

  try {
    const f = ['n_emails', 'n_attachments', 'n_links', 'n_last_period', 'n_last_week', 'percentage', 'total_emails'];
    const rows = keyed(await lib.get(cfg, 'dash/user_anomaly'), 'mailbox', f);
    await replaceSnapshot(p, 'dt_email_anomaly', ['mailbox'].concat(f), rows, runId);
    out.anomaly = rows.length;
  } catch (e) { fail('user_anomaly', e); }

  try {
    const [[last]] = await p.query('SELECT MAX(event_at) AS t FROM dt_email_audit');
    const since = last && last.t ? Math.max(new Date(last.t).getTime() - 3600000, from) : from;
    const ev = await lib.get(cfg, 'system/audit/events', { start: since, end: now });
    if (!Array.isArray(ev)) throw new lib.DtError('audit/events returned a ' + typeof ev + ', not a list');
    let n = 0;
    for (const e of ev) {
      if (!e || !e.uuid) continue;
      const [r] = await p.query(
        'INSERT IGNORE INTO dt_email_audit (uuid, event_at, event, account_id, tid, provider, run_id) VALUES (?,?,?,?,?,?,?)',
        [clip(e.uuid, 64), msDate(e.ms_ts), clip(e.event, 2000), clip(e.account_id, 320), clip(e.tid, 128), clip(e.provider, 64), runId]);
      n += r.affectedRows || 0;
    }
    out.audit_new = n;
  } catch (e) { fail('audit events', e); }

  // 8 steps: 3 searches, storing them, threat_data, data_loss, user_anomaly, audit events.
  const state = out.errors.length >= 8 ? 'failed' : (out.errors.length || out.capped.length) ? 'partial' : 'ok';
  const note = out.errors.concat(out.capped.map(k => 'search ' + k + ' stopped at ' + MAX_PAGES + ' pages')).join('; ');
  await p.query(
    `UPDATE dt_email_run SET finished_at=NOW(3), state=?, held_7d=?, junk_7d=?, critical_7d=?, threats_7d=?, inbound_7d=?,
       messages=?, rcpts=?, dlp_rows=?, anomaly_rows=?, audit_new=?, pages=?, note=? WHERE id=?`,
    [state, out.held_7d, out.junk_7d, out.critical_7d, out.threats_7d, out.inbound_7d, out.messages, out.rcpts,
     out.dlp, out.anomaly, out.audit_new, out.pages, note ? note.slice(0, 4000) : null, runId]);
  return Object.assign({ runId, state }, out);
}

// One locked run, recorded in the job registry. waitSec 0: if another process holds
// the lock, this one skips.
async function runLocked() {
  const p = lib.pool();
  const startedAt = new Date();
  const res = await withLock(LOCK, 0, async () => runOnce());
  if (res && res.skipped) return res;
  if (obsJob) await obsJob.record(p, JOB, { startedAt, finishedAt: new Date(), exitCode: res.state === 'failed' ? 1 : 0 });
  return res;
}

let timer = null, running = false;
async function tick() {
  if (running) return;
  running = true;
  try {
    const p = lib.pool();
    const cfg = await lib.loadConfig(p);
    if (!cfg || !(cfg.enabled === 1 || cfg.enabled === true) || !lib.configured(cfg)) return;
    // a run that died mid-way (process killed) is closed off, not left 'running' forever
    await p.query("UPDATE dt_email_run SET state='failed', finished_at=NOW(3), note='did not finish (process stopped mid-run)' " +
                  "WHERE state='running' AND started_at < NOW() - INTERVAL 2 HOUR");
    const cadence = Math.max(1, Number(cfg.cadence_min) || 30);
    const [[last]] = await p.query("SELECT started_at FROM dt_email_run ORDER BY id DESC LIMIT 1");
    if (last && Date.now() - new Date(last.started_at).getTime() < cadence * 60000) return;
    const r = await runLocked();
    if (r && !r.skipped) console.log('[darktrace-email] run ' + r.runId + ' ' + r.state + ' held=' + r.held_7d + ' junk=' + r.junk_7d +
      ' critical=' + r.critical_7d + ' threats=' + r.threats_7d + (r.errors.length ? ' errors=' + r.errors.join(' | ') : ''));
  } catch (e) {
    if (obsJob) { try { await obsJob.record(lib.pool(), JOB, { startedAt: new Date(), finishedAt: new Date(), exitCode: 1 }); } catch (_) { /* */ } }
    console.error('[darktrace-email] tick failed:', (e && e.message) || e);
  } finally { running = false; }
}

function startScheduler() {
  if (timer) return;
  timer = setInterval(tick, TICK_MS);
  timer.unref && timer.unref();
  setTimeout(tick, 90 * 1000).unref();
  console.log('[darktrace-email] scheduler started (checks every 60 s; cadence from dt_email_config)');
}

module.exports = { startScheduler, runOnce, runLocked, tick, JOB, MAX_PAGES };

// Manual run: sudo -u corpit node darktrace-email-sync.js --once
if (require.main === module) {
  require('dotenv').config();
  if (process.argv.includes('--once')) {
    runLocked().then(r => { console.log(JSON.stringify(r, null, 1)); process.exit(r && r.state === 'failed' ? 1 : 0); },
                     e => { console.error(e && e.message || e); process.exit(1); });
  } else { console.log('usage: node darktrace-email-sync.js --once'); process.exit(2); }
}
