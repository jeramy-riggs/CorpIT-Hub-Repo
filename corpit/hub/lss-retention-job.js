#!/usr/bin/env node
'use strict';
/* lss-retention-job.js — prune LSS sqlite to N days + VACUUM.
 * Usage:  node lss-retention-job.js --dry          (report only, default)
 *         node lss-retention-job.js --apply        (delete + vacuum)
 * Env:    LSS_DB (default /var/www/corpit-hub-api/data/lss.db), LSS_KEEP_DAYS (default 30)
 * Schema-agnostic: discovers each table's time column, samples it to detect
 * epoch-seconds vs epoch-ms vs ISO text, and prunes rows older than cutoff.
 */
const DB_PATH = process.env.LSS_DB || '/var/www/corpit-hub-api/data/lss.db';
const KEEP_DAYS = parseInt(process.env.LSS_KEEP_DAYS || '30', 10);
const APPLY = process.argv.includes('--apply');
const fs = require('fs');

let Database;
try { Database = require('/var/www/corpit-hub-api/node_modules/better-sqlite3'); }
catch (e) { try { Database = require('better-sqlite3'); } catch (e2) { console.error('better-sqlite3 not found'); process.exit(1); } }

if (!fs.existsSync(DB_PATH)) { console.error('DB not found:', DB_PATH); process.exit(1); }
const before = fs.statSync(DB_PATH).size;
const db = new Database(DB_PATH);
try {
  db.pragma('synchronous = EXTRA');
  if (db.pragma('synchronous', { simple: true }) !== 3) {
    throw new Error('SQLite writer requires synchronous=EXTRA');
  }
} catch (error) {
  db.close();
  throw error;
}
const cutoffMs = Date.now() - KEEP_DAYS * 86400000;
const TIME_RE = /^(ts|time|timestamp|epoch|logtime|log_time|datetime|received|received_at|event_time|eventtime|created|created_at)$/i;

const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all();
let totalDel = 0;
for (const t of tables) {
  const cols = db.prepare('PRAGMA table_info(' + JSON.stringify(t.name).replace(/"/g, '`') + ')').all();
  const tcol = cols.find(c => TIME_RE.test(c.name));
  if (!tcol) { console.log('[skip] ' + t.name + ' — no recognized time column'); continue; }
  const q = '`' + t.name.replace(/`/g, '') + '`', c = '`' + tcol.name.replace(/`/g, '') + '`';
  const sample = db.prepare('SELECT ' + c + ' AS v FROM ' + q + ' WHERE ' + c + ' IS NOT NULL ORDER BY rowid DESC LIMIT 1').get();
  if (!sample || sample.v == null) { console.log('[skip] ' + t.name + ' — empty'); continue; }
  let cutoff, mode;
  const v = sample.v;
  if (typeof v === 'number' || /^\d+(\.\d+)?$/.test(String(v))) {
    const n = Number(v);
    if (n > 1e14) { cutoff = cutoffMs * 1000; mode = 'epoch-us'; }
    else if (n > 1e11) { cutoff = cutoffMs; mode = 'epoch-ms'; }
    else { cutoff = Math.floor(cutoffMs / 1000); mode = 'epoch-s'; }
  } else {
    cutoff = new Date(cutoffMs).toISOString(); mode = 'iso-text';
  }
  const cnt = db.prepare('SELECT COUNT(*) AS n FROM ' + q + ' WHERE ' + c + ' < ?').get(cutoff).n;
  console.log('[' + (APPLY ? 'prune' : 'dry') + '] ' + t.name + '.' + tcol.name + ' (' + mode + '): ' + cnt + ' rows older than ' + KEEP_DAYS + 'd');
  if (APPLY && cnt > 0) {
    db.prepare('DELETE FROM ' + q + ' WHERE ' + c + ' < ?').run(cutoff);
    totalDel += cnt;
  }
}
if (APPLY) {
  console.log('deleted ' + totalDel + ' rows; running VACUUM…');
  db.exec('VACUUM');
  try {
    const cp = db.pragma('wal_checkpoint(TRUNCATE)');
    console.log('wal_checkpoint(TRUNCATE):', JSON.stringify(cp));
  } catch (e) {
    console.error('wal_checkpoint failed:', e.message);
  }
}
db.close();
const after = fs.statSync(DB_PATH).size;
console.log('size: ' + (before / 1048576).toFixed(1) + 'MB -> ' + (after / 1048576).toFixed(1) + 'MB' + (APPLY ? '' : ' (dry run — nothing changed)'));
