#!/usr/bin/env node
/* ═══════════════════════════════════════════════════════════════════════════
   lss-query-worker.js — worker-thread owner of every lss.db read for the ZPA
   Connection Diagnostics view (CC-ZPADIAG).

   Why a worker at all: better-sqlite3 is synchronous. lss.db is ~9.5GB / 29M
   rows, and a filtered 30-day drill-down measured 27.9s — almost all of it
   random I/O, not row count. Run on the main thread that is 27.9s during which
   api-beta serves nothing at all, for every page on the site. Here it costs
   one thread and the event loop stays free.

   The parent sends { job, args }; this replies { ok, result } or { ok:false,
   error }. All SQL for the feature lives here so there is exactly one place
   that touches the file.
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';
const { parentPort, workerData } = require('worker_threads');
const Database = require('better-sqlite3');

const DB_PATH = workerData.dbPath;
const SCAN_BUDGET = workerData.scanBudget || 400000;

// Outcome buckets, derived from the LSS InternalReason code. Order matters:
// policy and re-auth are matched before the generic error patterns because
// their reason codes also contain SETUP_FAIL.
const BUCKET_SQL =
  "CASE" +
  " WHEN ir LIKE '%NO_POLICY_FOUND%' OR ir LIKE '%POLICY_BLOCK%' OR ir LIKE '%CLIENT_BLOCK%' THEN 'block'" +
  " WHEN ir LIKE '%SAML_EXPIRED%' OR ir LIKE '%REAUTH%' OR ir LIKE '%TIMEOUT_POLICY%' THEN 'reauth'" +
  " WHEN ir = 'OPEN_OR_ACTIVE_CONNECTION' OR ir LIKE 'BRK_MT_TERMINATED%' OR ir LIKE 'MT_CLOSED_%' THEN 'ok'" +
  " WHEN ir LIKE '%SETUP_FAIL%' OR ir LIKE '%SETUP_ERR%' OR ir LIKE '%TIMEOUT%'" +
  "   OR ir LIKE '%NOT_REACHABLE%' OR ir LIKE '%INVALID_DOMAIN%' OR ir LIKE '%_ERR_%' THEN 'error'" +
  " ELSE 'info' END";

const ROW_COLS = [
  'ts', 'connection_id', 'session_id', 'user', 'app', 'appgroup', 'policy',
  'client_zen', 'connector', 'connector_zen', 'connector_ip', 'host',
  'server_ip', 'server_port', 'service_port', 'ip_protocol', 'client_ip',
  'client_city', 'client_country', 'platform', 'hostname', 'idp', 'status',
  'internal_reason', 'policy_ms', 'setup_ms', 'bytes_rx', 'bytes_tx'
].join(', ') + ", COALESCE(internal_reason,'') ir";

const FACET_COLS = ['app', 'appgroup', 'user', 'policy', 'connector', 'client_zen', 'host', 'internal_reason'];

// One row per connection: the terminal record for each ConnectionID. Rows
// streamed before receiver v2.1 carry no connection_id, so they fall back to
// their own rowid and stay one row each rather than being merged.
function terminalSql(whereSql, cols) {
  return 'SELECT ' + cols + ' FROM (' +
    'SELECT c.*, ROW_NUMBER() OVER (' +
    "PARTITION BY COALESCE(NULLIF(c.connection_id, ''), 'r' || c.rowid) " +
    'ORDER BY c.ts DESC, c.rowid DESC) rn ' +
    'FROM conns c WHERE ' + whereSql + ') WHERE rn = 1';
}

// Pre-count so an oversized request is refused rather than started.
//
// The predicate counted here is NOT always the query's own WHERE. Counting the
// full filter set is only cheap when an index can serve it: `user=?`/`app=?`
// use covering indexes, but `host=?` or a LIKE falls back to
// `SEARCH c USING INDEX ix_conns_ts` — SQLite then reads every row in the
// window off a 9.5GB file to test the predicate. That made the guard cost
// exactly as much as the query it guarded AND report a tiny number, so it
// admitted the expensive request it existed to stop. For those filters the
// caller passes the bare `ts >= ?` window instead, which is the real scan size
// and is index-only (~0.7s at 30d).
function budgetCheck(db, whereSql, params, budget) {
  const cap = budget || SCAN_BUDGET;
  const n = db.prepare('SELECT COUNT(*) n FROM conns c WHERE ' + whereSql).get(params).n;
  if (n <= cap) return null;
  return {
    error: 'window too wide',
    estimatedRecords: n,
    budget: cap,
    guidance: 'This window matches ' + n.toLocaleString() + ' records, over the ' +
      cap.toLocaleString() + ' scan budget. Add a filter (app segment, user, ' +
      'connector…) or pick a shorter window.'
  };
}

const JOBS = {
  facets(db, a) {
    const over = budgetCheck(db, 'ts >= ?', [a.since]);
    if (over) return { over };
    const t0 = Date.now();
    const rows = db.prepare('SELECT ' + FACET_COLS.join(', ') + ', ts FROM conns WHERE ts >= ?').all(a.since);

    // counts[col][value] = { records, users:Set, lastTs }
    const counts = {};
    FACET_COLS.forEach(c => { counts[c] = Object.create(null); });
    for (const r of rows) {
      const u = r.user;
      for (const col of FACET_COLS) {
        const v = r[col];
        // "0" is Zscaler's null sentinel (no policy matched, no connector, no
        // IdP). Left in, it becomes a top-ranked dropdown entry literally named
        // "0" — the outcome counters already surface those connections.
        if (v === null || v === undefined || v === '' || v === '0' || v === 0) continue;
        let e = counts[col][v];
        if (!e) e = counts[col][v] = { records: 0, users: new Set(), lastTs: 0 };
        e.records++;
        if (u) e.users.add(u);
        if (r.ts > e.lastTs) e.lastTs = r.ts;
      }
    }
    const facet = (col, limit) => {
      const m = counts[col];
      return Object.keys(m)
        .map(k => ({ name: k, records: m[k].records, users: m[k].users.size, lastTs: m[k].lastTs }))
        .sort((x, y) => y.records - x.records)
        .slice(0, limit);
    };
    return {
      hours: a.hours, scanned: rows.length,
      apps: facet('app', 500), appgroups: facet('appgroup', 500), users: facet('user', 5000),
      policies: facet('policy', 200), connectors: facet('connector', 200),
      edges: facet('client_zen', 300), hosts: facet('host', 1000),
      reasons: facet('internal_reason', 60),
      tookMs: Date.now() - t0
    };
  },

  connections(db, a) {
    const over = budgetCheck(db, a.budgetWhere || a.where, a.budgetParams || a.params);
    if (over) return { over };
    const t0 = Date.now();

    // Counters cover every connection matching the filters, not just this page.
    const raw = db.prepare(
      'SELECT ' + BUCKET_SQL + ' bucket, COUNT(*) n FROM (' +
      terminalSql(a.where, "COALESCE(internal_reason,'') ir") + ') GROUP BY bucket'
    ).all(a.params);
    const counters = { total: 0, ok: 0, error: 0, block: 0, reauth: 0, info: 0 };
    raw.forEach(r => { counters[r.bucket] = r.n; counters.total += r.n; });

    let sql = 'SELECT *, ' + BUCKET_SQL + ' bucket FROM (' + terminalSql(a.where, ROW_COLS) + ')';
    const params = a.params.slice();
    if (a.outcome) { sql = 'SELECT * FROM (' + sql + ') WHERE bucket = ?'; params.push(a.outcome); }
    sql += ' ORDER BY ts DESC LIMIT ? OFFSET ?';
    params.push(a.limit, a.offset);
    const rows = db.prepare(sql).all(params);

    // How much of this page predates receiver v2.1, so the UI can say so rather
    // than render a blank Policy cell as though no policy had matched.
    const enriched = rows.filter(r => r.policy !== null && r.policy !== '').length;
    return { counters, rows, enrichedRows: enriched, tookMs: Date.now() - t0 };
  },

  connection(db, a) {
    // A connection's records span its own lifetime, not the whole browsing
    // window, so this is bounded by the clicked row's timestamp rather than by
    // `since`. Guarding it on the full window instead made the trail return
    // HTTP 400 for every window of 8h or more — the guard broke the drill-down
    // it was protecting, and told the operator to "add a filter" on an endpoint
    // that only accepts a cid.
    let lo = a.since, hi = Date.now();
    if (a.ts) {
      lo = a.ts - 3600000;        // an hour before the record we were shown
      hi = a.ts + 86400000;       // long-lived sessions still close within a day
    }
    const over = budgetCheck(db, 'ts >= ? AND ts <= ?', [lo, hi]);
    if (over) return { over };
    const rows = db.prepare(
      'SELECT * FROM conns WHERE connection_id = ? AND ts >= ? AND ts <= ? ORDER BY ts ASC LIMIT 200'
    ).all(a.cid, lo, hi);
    return { cid: a.cid, records: rows.length, rows, scopedFrom: lo, scopedTo: hi };
  }
};

let db;
try {
  db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
} catch (e) {
  parentPort.postMessage({ ok: false, error: 'LSS database not readable at ' + DB_PATH + ': ' + e.message });
  process.exit(0);
}

parentPort.on('message', (msg) => {
  try {
    const fn = JOBS[msg.job];
    if (!fn) return parentPort.postMessage({ id: msg.id, ok: false, error: 'unknown job ' + msg.job });
    parentPort.postMessage({ id: msg.id, ok: true, result: fn(db, msg.args) });
  } catch (e) {
    parentPort.postMessage({ id: msg.id, ok: false, error: e.message });
  }
});
parentPort.postMessage({ ready: true });
