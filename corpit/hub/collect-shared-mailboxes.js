// collect-shared-mailboxes.js — nightly snapshot of every Exchange Online shared mailbox into
// corpit_hub.hk_shared_mailbox, read by AD Management → Housekeeping → Shared Mailboxes.
//
//   node collect-shared-mailboxes.js                      collect (pwsh, read-only EXO) + write the DB
//   node collect-shared-mailboxes.js --json-out FILE      collect only; writes FILE, touches no database
//   node collect-shared-mailboxes.js --import FILE        write the DB from a FILE made by --json-out
//   options: --limit N (first N mailboxes, for a smoke run; never prunes) · --trace-days N (default 30, max 90)
//
// The EXO half is collect-shared-mailboxes.ps1 (GAL app certificate, Get-* cmdlets only). It needs to read
// SMBX_EXO_ENV (default /opt/gal-directory/.env) and the .pfx beside it, so it runs where those exist (corpit A/B).
// A full run takes roughly 2 h for ~800 mailboxes. Rows of mailboxes that no longer exist are pruned only after
// a complete, unlimited run. Graph "Last Activity Date" is copied from sentinel_mailbox_usage (collect-m365-reports.js).
require('dotenv').config({ path: __dirname + '/.env' });
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

function arg(name) { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : undefined; }
const JSON_OUT = arg('--json-out');
const IMPORT = arg('--import');
const LIMIT = parseInt(arg('--limit') || '0', 10) || 0;
const TRACE_DAYS = arg('--trace-days') !== undefined ? parseInt(arg('--trace-days'), 10) : 30;
const PWSH = process.env.SMBX_PWSH || 'pwsh';
const EXO_ENV = process.env.SMBX_EXO_ENV || '/opt/gal-directory/.env';

function collect(outFile) {
  return new Promise((resolve, reject) => {
    const a = ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'collect-shared-mailboxes.ps1'),
      '-Out', outFile, '-TraceDays', String(TRACE_DAYS), '-EnvFile', EXO_ENV];
    if (LIMIT) a.push('-Limit', String(LIMIT));
    const p = spawn(PWSH, a, { stdio: ['ignore', 'inherit', 'inherit'] });
    p.on('error', reject);
    p.on('exit', (code) => (code === 0 ? resolve() : reject(new Error('collect-shared-mailboxes.ps1 exited ' + code))));
  });
}

// ISO (UTC) → MySQL DATETIME text in UTC; null stays null.
function dt(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return isNaN(d) ? null : d.toISOString().slice(0, 19).replace('T', ' ');
}

async function importDoc(doc, limited) {
  const rows = Array.isArray(doc.mailboxes) ? doc.mailboxes : [];
  if (!rows.length) throw new Error('no mailboxes in the collection; nothing written');
  const runId = crypto.randomBytes(8).toString('hex');
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME || 'corpit_hub',
    charset: 'utf8mb4', timezone: 'Z',
  });
  try {
    // Graph Last Activity Date per UPN (a shared mailbox has no licence, so this report is the only Graph view of it).
    const graph = {};
    try {
      const [g] = await conn.query("SELECT LOWER(upn) upn, DATE_FORMAT(last_activity_date,'%Y-%m-%d') d FROM sentinel_mailbox_usage WHERE last_activity_date IS NOT NULL");
      for (const r of g) graph[r.upn] = r.d;
    } catch (e) { console.error('sentinel_mailbox_usage not read (Graph last activity left empty):', e.message); }

    await conn.beginTransaction();
    const sql = `INSERT INTO hk_shared_mailbox (mailbox_guid, display_name, primary_smtp, upn, alias, is_dirsynced, hidden_gal, when_created,
        item_count, size_bytes, last_user_action, last_received, last_sent, graph_last_activity, recv_count, sent_count, trace_days,
        full_access, send_as, error, run_id, collected_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), primary_smtp=VALUES(primary_smtp), upn=VALUES(upn), alias=VALUES(alias),
        is_dirsynced=VALUES(is_dirsynced), hidden_gal=VALUES(hidden_gal), when_created=VALUES(when_created), item_count=VALUES(item_count),
        size_bytes=VALUES(size_bytes), last_user_action=VALUES(last_user_action), last_received=VALUES(last_received), last_sent=VALUES(last_sent),
        graph_last_activity=VALUES(graph_last_activity), recv_count=VALUES(recv_count), sent_count=VALUES(sent_count), trace_days=VALUES(trace_days),
        full_access=VALUES(full_access), send_as=VALUES(send_as), error=VALUES(error), run_id=VALUES(run_id), collected_at=VALUES(collected_at)`;
    let n = 0;
    for (const m of rows) {
      if (!m.mailbox_guid) continue;
      await conn.query(sql, [m.mailbox_guid, m.display_name || null, m.primary_smtp || null, m.upn || null, m.alias || null,
        m.is_dirsynced ? 1 : 0, m.hidden_gal ? 1 : 0, dt(m.when_created), m.item_count ?? null, m.size_bytes ?? null,
        dt(m.last_user_action), dt(m.last_received), dt(m.last_sent), graph[String(m.upn || '').toLowerCase()] || null,
        m.recv_count ?? null, m.sent_count ?? null, doc.trace_days ?? null,
        JSON.stringify(m.full_access || []), JSON.stringify(m.send_as || []), m.error ? String(m.error).slice(0, 500) : null, runId, now]);
      n++;
    }
    let pruned = 0;
    if (!limited && doc.count === rows.length) {
      const [r] = await conn.query('DELETE FROM hk_shared_mailbox WHERE run_id <> ?', [runId]);
      pruned = r.affectedRows;
    }
    const meta = { run_id: runId, started: doc.started, finished: doc.finished, imported_at: now.replace(' ', 'T') + 'Z',
      count: n, errors: doc.errors || 0, trace_days: doc.trace_days ?? null, trace_error: doc.trace_error || null, pruned, limited: !!limited };
    await conn.query(`INSERT INTO hk_settings (setting_key, setting_value, updated_by) VALUES ('smbx.collector', ?, 'collector')
      ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value), updated_by=VALUES(updated_by)`, [JSON.stringify(meta)]);
    await conn.commit();
    console.log(`imported ${n} mailboxes (errors ${meta.errors}, pruned ${pruned}, trace ${meta.trace_days ?? 'n/a'}d${meta.trace_error ? ', trace failed' : ''})`);
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    throw e;
  } finally { await conn.end(); }
}

async function main() {
  if (!(TRACE_DAYS >= 0 && TRACE_DAYS <= 90)) throw new Error('--trace-days must be 0..90');
  if (IMPORT) {
    const doc = JSON.parse(fs.readFileSync(IMPORT, 'utf8'));
    return importDoc(doc, doc.limited || false);
  }
  if (JSON_OUT) {
    await collect(JSON_OUT);
    if (LIMIT) {        // a partial collection must never prune on --import
      const doc = JSON.parse(fs.readFileSync(JSON_OUT, 'utf8')); doc.limited = true;
      fs.writeFileSync(JSON_OUT, JSON.stringify(doc));
    }
    return;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'smbx-'));
  const file = path.join(dir, 'collect.json');
  try {
    await collect(file);
    await importDoc(JSON.parse(fs.readFileSync(file, 'utf8')), !!LIMIT);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

main().then(() => { console.log('collect-shared-mailboxes OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-shared-mailboxes FAILED:', e.message); process.exit(1); });
