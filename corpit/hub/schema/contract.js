'use strict';
/* ════════════════════════════════════════════════════════════════════
   Schema contract for the tables the hub's request-serving modules used to
   create or alter at load / request time (CHG-ARCH-18, review finding #8).

   The contract is what the CODE needs: every column a module reads or
   writes, the MySQL data type family, and the unique keys its upserts rely
   on. It is checked read-only (information_schema / PRAGMA), so the hub can
   verify it at startup without performing DDL. Changes are made only by
   migrate.js, at deploy time.

   Slices are per module so an incompatible table 503s the routes that use
   it instead of taking down the whole process (the auth gate lives here).
   ════════════════════════════════════════════════════════════════════ */

const path = require('path');

const DEFAULT_NET_DB = '/var/www/corpit-hub-api/data/netfleet.db';

// Resolved the same way the modules resolve them: intune_graph.js pins
// it_inventory, housekeeping.js uses DB_NAME || corpit_hub, netswitch.js uses
// NET_DB || the default path. SCHEMA_INVENTORY_DB exists for the scratch harness.
function names(env = process.env) {
  return {
    inventory: env.SCHEMA_INVENTORY_DB || 'it_inventory',
    hub:       env.DB_NAME || 'corpit_hub',
    netDb:     env.NET_DB || DEFAULT_NET_DB,
  };
}

const TABLES = [
  { slice: 'intune', store: 'mysql', db: 'inventory', table: 'intune_graph_cache',
    columns: {
      device_id: 'varchar', serial_number: 'varchar', imei: 'varchar', computer_name: 'varchar',
      display_name: 'varchar', os_version: 'varchar', compliance: 'varchar', enrolled_date: 'varchar',
      last_sync: 'varchar', user_upn: 'varchar', model: 'varchar', manufacturer: 'varchar',
      phone_number: 'varchar', operating_system: 'varchar', last_synced: 'datetime', is_encrypted: 'tinyint',
    },
    unique: [['device_id']] },                       // /sync upserts ON DUPLICATE KEY device_id
  { slice: 'intune', store: 'mysql', db: 'inventory', table: 'intune_devices',
    columns: {
      id: 'int', device_id: 'varchar', device_name: 'varchar', serial_number: 'varchar', imei: 'varchar',
      phone_number: 'varchar', os: 'varchar', os_version: 'varchar', compliance: 'varchar',
      primary_user_upn: 'varchar', primary_user_name: 'varchar', last_checkin: 'varchar', model: 'varchar',
      device_source: 'varchar', device_category: 'varchar', is_historical: 'tinyint', is_encrypted: 'tinyint',
      la_device_id: 'varchar', la_state: 'varchar', la_regional: 'varchar', la_active: 'varchar',
    },
    unique: [['device_id']] },                       // /sync-to-devices upserts ON DUPLICATE KEY device_id
  { slice: 'housekeeping', store: 'mysql', db: 'hub', table: 'housekeeping_audit',
    columns: {
      id: 'int', created_at: 'datetime', action_type: 'varchar', object_type: 'varchar',
      object_name: 'varchar', object_dn: 'text', original_state: 'json', new_state: 'json',
      performed_by: 'varchar', reverted: 'tinyint', revert_at: 'datetime', notes: 'text',
    },
    unique: [] },
  { slice: 'netfleet', store: 'sqlite', db: 'netDb', table: 'net_watch',
    columns: ['id', 'kind', 'ref', 'label', 'meta', 'created_by', 'created_at', 'active'],
    unique: [['kind', 'ref']] },                     // POST /watch: ON CONFLICT(kind,ref)
  { slice: 'netfleet', store: 'sqlite', db: 'netDb', table: 'net_watch_samples',
    columns: ['watch_id', 'ts', 'data'], unique: [] },
  { slice: 'netfleet', store: 'sqlite', db: 'netDb', table: 'net_watch_events',
    columns: ['id', 'watch_id', 'ts', 'severity', 'kind', 'message'], unique: [] },
  { slice: 'netfleet', store: 'sqlite', db: 'netDb', table: 'net_claims',
    columns: ['id', 'ref', 'title', 'detail', 'claimed_by', 'claimed_at', 'cleared_at'], unique: [] },
  // One-press access requests (access-request-routes.js): the dedupe ledger behind "Already requested #N".
  { slice: 'access-request', store: 'mysql', db: 'hub', table: 'access_requests',
    columns: {
      id: 'bigint', created_at: 'datetime', requester_email: 'varchar', requester_name: 'varchar', kind: 'varchar',
      target: 'varchar', need_key: 'varchar', need_text: 'varchar', path: 'varchar', reason: 'varchar',
      sdp_id: 'varchar', sdp_display_id: 'varchar', sdp_url: 'varchar',
    },
    unique: [] },
];

const SLICES = [...new Set(TABLES.map(t => t.slice))];

const sameCols = (a, b) => a.length === b.length && a.every((c, i) => c.toLowerCase() === String(b[i]).toLowerCase());

// ── MySQL: one information_schema read per kind, filtered in JS ──────────────
async function checkMysql(conn, n) {
  const wanted = TABLES.filter(t => t.store === 'mysql');
  const schemas = [...new Set(wanted.map(t => n[t.db]))];
  const tables  = [...new Set(wanted.map(t => t.table))];
  const [cols] = await conn.query(
    `SELECT TABLE_SCHEMA s, TABLE_NAME t, COLUMN_NAME c, DATA_TYPE d
       FROM information_schema.COLUMNS WHERE TABLE_SCHEMA IN (?) AND TABLE_NAME IN (?)`, [schemas, tables]);
  const [idx] = await conn.query(
    `SELECT TABLE_SCHEMA s, TABLE_NAME t, INDEX_NAME i, NON_UNIQUE nu, SEQ_IN_INDEX q, COLUMN_NAME c
       FROM information_schema.STATISTICS WHERE TABLE_SCHEMA IN (?) AND TABLE_NAME IN (?)
      ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX`, [schemas, tables]);
  const out = [];
  for (const t of wanted) {
    const s = n[t.db], fq = `${s}.${t.table}`;
    const have = new Map(cols.filter(r => r.s === s && r.t === t.table).map(r => [r.c.toLowerCase(), r.d.toLowerCase()]));
    if (!have.size) { out.push({ slice: t.slice, table: fq, problem: 'table missing' }); continue; }
    for (const [c, type] of Object.entries(t.columns)) {
      if (!have.has(c)) out.push({ slice: t.slice, table: fq, problem: `missing column ${c}` });
      else if (have.get(c) !== type) out.push({ slice: t.slice, table: fq, problem: `column ${c} is ${have.get(c)}, expected ${type}` });
    }
    const uniq = new Map();
    for (const r of idx.filter(r => r.s === s && r.t === t.table && Number(r.nu) === 0)) {
      if (!uniq.has(r.i)) uniq.set(r.i, []);
      uniq.get(r.i).push(r.c);
    }
    for (const u of t.unique) {
      if (![...uniq.values()].some(v => sameCols(v, u)))
        out.push({ slice: t.slice, table: fq, problem: `no unique key on (${u.join(', ')})` });
    }
  }
  return out;
}

// ── SQLite: read-only open; a missing file is 'unknown', never created ───────
function checkSqlite(n, Database) {
  const wanted = TABLES.filter(t => t.store === 'sqlite');
  const file = n.netDb, out = [];
  let db;
  try {
    db = new Database(file, { readonly: true, fileMustExist: true });
  } catch (e) {
    return { unreachable: `cannot open ${file} read-only: ${e.code || e.message}`, problems: [] };
  }
  try {
    for (const t of wanted) {
      const fq = `${path.basename(file)}:${t.table}`;
      const cols = db.prepare('SELECT name FROM pragma_table_info(?)').all(t.table).map(r => r.name.toLowerCase());
      if (!cols.length) { out.push({ slice: t.slice, table: fq, problem: 'table missing' }); continue; }
      for (const c of t.columns) if (!cols.includes(c)) out.push({ slice: t.slice, table: fq, problem: `missing column ${c}` });
      const uniq = db.prepare('SELECT name FROM pragma_index_list(?) WHERE "unique" = 1').all(t.table)
        .map(r => db.prepare('SELECT name FROM pragma_index_info(?) ORDER BY seqno').all(r.name).map(x => x.name));
      for (const u of t.unique)
        if (!uniq.some(v => sameCols(v, u))) out.push({ slice: t.slice, table: fq, problem: `no unique key on (${u.join(', ')})` });
    }
  } finally { db.close(); }
  return { unreachable: null, problems: out };
}

/**
 * Read-only contract check. Resolves to
 *   { ok, slices: { <slice>: { state: 'ok'|'incompatible'|'unknown', problems: [...] } } }
 * 'unknown' = the store could not be reached (connection refused, auth, the
 * SQLite file absent), which says nothing about the schema and is kept distinct
 * from 'incompatible'. Callers that must prove the contract treat it as failure.
 */
async function check({ mysqlConn, Database, env } = {}) {
  const n = names(env);
  const slices = Object.fromEntries(SLICES.map(s => [s, { state: 'ok', problems: [] }]));
  const mark = (list) => { for (const p of list) { slices[p.slice].state = 'incompatible'; slices[p.slice].problems.push(`${p.table}: ${p.problem}`); } };
  const mysqlSlices = [...new Set(TABLES.filter(t => t.store === 'mysql').map(t => t.slice))];
  try {
    mark(await checkMysql(mysqlConn, n));
  } catch (e) {
    for (const s of mysqlSlices) { slices[s] = { state: 'unknown', problems: [`mysql unreachable: ${e.code || e.message}`] }; }
  }
  const lite = checkSqlite(n, Database || require('better-sqlite3'));
  if (lite.unreachable) {
    for (const s of new Set(TABLES.filter(t => t.store === 'sqlite').map(t => t.slice))) slices[s] = { state: 'unknown', problems: [lite.unreachable] };
  } else mark(lite.problems);
  const ok = Object.values(slices).every(s => s.state === 'ok');
  return { ok, slices };
}

module.exports = { TABLES, SLICES, names, check, DEFAULT_NET_DB };
