#!/usr/bin/env node
'use strict';
/* zpa-observed-access-job.js — nightly LSS → observed-access aggregate.
 *
 * Answers "who actually reaches this app segment", as opposed to the ZPA
 * policy model's "who is allowed to". Output is a small JSON file that
 * /api/zscaler/zpa/observed-access serves verbatim, so no request ever
 * touches lss.db (17M rows / ~5.6GB — a full scan runs ~2.5 minutes and
 * cold scans took the box down on 2026-08-14).
 *
 * Usage:  node zpa-observed-access-job.js [--days 14] [--top 10] [--out PATH] [--stdout]
 * Env:    LSS_DB, ZPA_OBS_DAYS, ZPA_OBS_TOP, ZPA_OBS_OUT
 *
 * LSS counting semantics — these are not interchangeable, get them wrong
 * and the numbers lie:
 *   - connection volume  = rows with status='open' only
 *   - presence/days-seen = ANY row. Machine tunnels open ONCE and then emit
 *     'active' for days, so counting opens alone sinks them to zero.
 *   - bytes              = rows with status='close' only (rx+tx are final there)
 *   - machine users match /^ZPA MACHINE@/ ; app '0' is receiver junk, dropped.
 *
 * Segments with no traffic are simply absent from byApp — the caller derives
 * "quiet" by differencing against the ZPA segment list, and "unmatched" by
 * the reverse. This job deliberately knows nothing about the policy model.
 */

const fs = require('fs');
const path = require('path');

function argVal(flag, dflt) {
  const i = process.argv.indexOf(flag);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : dflt;
}

const DB_PATH  = process.env.LSS_DB || '/var/www/corpit-hub-api/data/lss.db';
const DAYS     = Math.max(1, parseInt(argVal('--days', process.env.ZPA_OBS_DAYS || '14'), 10));
const TOP_N    = Math.max(1, parseInt(argVal('--top',  process.env.ZPA_OBS_TOP  || '10'), 10));
const OUT_PATH = argVal('--out', process.env.ZPA_OBS_OUT || '/var/www/corpit-hub-api/data/zpa-observed-access.json');
const TO_STDOUT = process.argv.includes('--stdout');
const DAY_MS = 86400000;

let Database;
try { Database = require('/var/www/corpit-hub-api/node_modules/better-sqlite3'); }
catch (e) {
  try { Database = require('better-sqlite3'); }
  catch (e2) { console.error('[zpa-obs] better-sqlite3 not found'); process.exit(1); }
}

if (!fs.existsSync(DB_PATH)) { console.error('[zpa-obs] DB not found: ' + DB_PATH); process.exit(1); }

const t0 = Date.now();
// Window is whole UTC days, inclusive of today-so-far, matching the Reach Map build.
const endDay   = Math.floor(t0 / DAY_MS);
const startDay = endDay - DAYS + 1;
const sinceMs  = startDay * DAY_MS;
const isoDay = d => new Date(d * DAY_MS).toISOString().slice(0, 10);

let db;
try { db = new Database(DB_PATH, { readonly: true, fileMustExist: true }); }
catch (e) { console.error('[zpa-obs] cannot open ' + DB_PATH + ': ' + e.message); process.exit(1); }
db.pragma('busy_timeout = 30000');

// One pass. GROUP BY app,user,day instead of COUNT(DISTINCT day) per group —
// the distinct-day rollup then happens in JS, which avoids sqlite's per-group
// dedupe sort and yields at most apps x users x DAYS rows (~48k here).
const SQL = `
  SELECT app,
         user,
         ts / ${DAY_MS}                                                          AS day,
         SUM(CASE WHEN status = 'open'  THEN 1 ELSE 0 END)                       AS o,
         SUM(CASE WHEN status = 'close'
                  THEN COALESCE(bytes_rx,0) + COALESCE(bytes_tx,0) ELSE 0 END)   AS b,
         MAX(ts)                                                                 AS lt,
         COUNT(*)                                                                AS n
    FROM conns
   WHERE ts >= ?
     AND app  IS NOT NULL AND app  <> '' AND app <> '0'
     AND user IS NOT NULL AND user <> ''
   GROUP BY app, user, day`;

const apps = new Map();   // app -> { users:Map, days:Set, o, b, n, lt }
let scanned = 0;

try {
  for (const r of db.prepare(SQL).iterate(sinceMs)) {
    scanned++;
    let a = apps.get(r.app);
    if (!a) { a = { users: new Map(), days: new Set(), o: 0, b: 0, n: 0, lt: 0 }; apps.set(r.app, a); }
    a.o += r.o; a.b += r.b; a.n += r.n;
    a.days.add(r.day);
    if (r.lt > a.lt) a.lt = r.lt;

    let u = a.users.get(r.user);
    if (!u) { u = { o: 0, b: 0, n: 0, lt: 0, days: 0 }; a.users.set(r.user, u); }
    u.o += r.o; u.b += r.b; u.n += r.n; u.days++;   // one row per (user,day) => days is just a count
    if (r.lt > u.lt) u.lt = r.lt;
  }
} catch (e) {
  console.error('[zpa-obs] query failed: ' + e.message);
  try { db.close(); } catch (x) {}
  process.exit(1);
}
try { db.close(); } catch (x) {}

const isMachine = u => /^ZPA MACHINE@/.test(u);
const allUsers = new Set();
const byApp = {};
let totalOpens = 0, totalBytes = 0, totalRows = 0;

for (const [name, a] of apps) {
  const entries = [...a.users.entries()];
  let machineUsers = 0;
  for (const [user] of entries) { allUsers.add(user); if (isMachine(user)) machineUsers++; }

  // Rank by presence first, then volume: a machine tunnel seen all 14 days
  // with 1 open outranks a human with 3 opens on one day.
  const top = entries
    .sort((x, y) => (y[1].days - x[1].days) || (y[1].o - x[1].o) || (y[1].n - x[1].n))
    .slice(0, TOP_N)
    .map(([user, u]) => ({
      user, o: u.o, days: u.days, lt: u.lt, b: u.b, m: isMachine(user),
    }));

  totalOpens += a.o; totalBytes += a.b; totalRows += a.n;
  byApp[name] = {
    u: entries.length,
    mu: machineUsers,
    o: a.o,
    b: a.b,
    days: a.days.size,
    lt: a.lt,
    top,
  };
}

let machineTotal = 0;
for (const u of allUsers) if (isMachine(u)) machineTotal++;

const out = {
  generatedAt: Date.now(),
  runtimeMs: Date.now() - t0,
  source: 'ZPA LSS user-activity feed (lss.db on itam), UTC days',
  db: DB_PATH,
  window: {
    startDay, endDay, days: DAYS,
    start: isoDay(startDay), end: isoDay(endDay),
    sinceMs, throughMs: Date.now(),
  },
  topN: TOP_N,
  totals: {
    apps: apps.size,
    users: allUsers.size,
    machineUsers: machineTotal,
    humanUsers: allUsers.size - machineTotal,
    opens: totalOpens,
    bytes: totalBytes,
    rows: totalRows,
    groupedRows: scanned,
  },
  byApp,
};

const json = JSON.stringify(out);
if (TO_STDOUT) { process.stdout.write(json + '\n'); process.exit(0); }

// Atomic replace so a reader never sees a half-written file.
try {
  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  const tmp = OUT_PATH + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, json);
  fs.renameSync(tmp, OUT_PATH);
} catch (e) {
  console.error('[zpa-obs] write failed: ' + e.message);
  process.exit(1);
}

console.log('[zpa-obs] ' + out.window.start + ' → ' + out.window.end +
  ' (' + DAYS + 'd): ' + apps.size + ' apps, ' + allUsers.size + ' users (' +
  machineTotal + ' machine), ' + totalOpens + ' opens, ' +
  (totalBytes / 1073741824).toFixed(1) + ' GB, ' + scanned + ' grouped rows in ' +
  ((Date.now() - t0) / 1000).toFixed(1) + 's → ' + OUT_PATH +
  ' (' + (json.length / 1024).toFixed(1) + ' KB)');
