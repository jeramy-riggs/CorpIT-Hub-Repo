#!/usr/bin/env node
'use strict';
/* ════════════════════════════════════════════════════════════════════
   Hub schema migrations (CHG-ARCH-18, review finding #8).

     sudo -u corpit node /var/www/corpit-hub-api/migrate.js status   read-only: recorded + what apply would do
     sudo -u corpit node /var/www/corpit-hub-api/migrate.js check    read-only: the contract the code needs
     sudo -u corpit node /var/www/corpit-hub-api/migrate.js apply    lock, run pending steps, prove the contract

   Run `apply` at deploy time BEFORE restarting corpit-hub-api; a non-zero exit
   means do not restart onto the new code. The hub itself performs no DDL: at
   startup it only checks the contract (schema/readiness.js) and 503s the routes
   of any module whose tables do not satisfy it.

   Exit codes: 0 ok · 1 usage / cannot connect · 2 contract not satisfied ·
               3 another migration holds the lock · 4 a step failed or a recorded
               step was edited.

   Runs as the service user, never root: opening netfleet.db read-write as
   root can leave root-owned -wal/-shm files the hub cannot open.
   ════════════════════════════════════════════════════════════════════ */

const path = require('path');
const os = require('os');
const crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const mysql = require('mysql2/promise');
const Database = require('better-sqlite3');
const contract = require('./schema/contract');
const STEPS = require('./schema/migrations');

const LOCK = process.env.MIGRATE_LOCK_NAME || 'corpit-hub.schema-migrate';
const EXIT = { OK: 0, USAGE: 1, CONTRACT: 2, LOCKED: 3, STEP: 4 };

const PRIV = 'the connecting MySQL identity lacks the privilege this DDL needs on that schema. ' +
  'Run migrate.js as the hub user (DB_USER from .env) or grant CREATE/ALTER/INDEX there.';
const HINTS = {
  ER_TABLEACCESS_DENIED_ERROR: PRIV, ER_DBACCESS_DENIED_ERROR: PRIV, ER_SPECIFIC_ACCESS_DENIED_ERROR: PRIV,
  ER_ACCESS_DENIED_ERROR: 'MySQL refused the login: check DB_USER / DB_PASSWORD in .env.',
  ER_LOCK_WAIT_TIMEOUT: 'waited lock_wait_timeout (10 s) for the table\'s metadata lock: a long transaction or query holds it. ' +
    'Find it in performance_schema.metadata_locks / SHOW PROCESSLIST, let it finish, re-run.',
  ER_BAD_FIELD_ERROR: 'a column this step positions against (AFTER ...) is missing: the table matches no shape this step knows. Inspect SHOW CREATE TABLE.',
  ER_TABLE_EXISTS_ERROR: 'the table appeared between the guard and the CREATE: something else created it. Re-run; the guard will record it as baseline.',
  ER_NO_SUCH_TABLE: 'the table is missing although an earlier step should have created it: the schema changed outside migrations.',
  ECONNREFUSED: 'MySQL is not reachable at DB_HOST:DB_PORT.',
  SQLITE_BUSY: 'netfleet.db stayed locked for 10 s (a collector writing). Re-run.',
  SQLITE_CANTOPEN: 'netfleet.db could not be opened read-write. The netcollect collector (corpit-netcollect.timer) creates it; ' +
    'it must exist and be writable by the user running migrate.js.',
  SQLITE_READONLY: 'netfleet.db is read-only for this user; run migrate.js as corpit.',
};

const out = (s = '') => process.stdout.write(s + '\n');
const q = mysql.escapeId;
const checksum = (step) => crypto.createHash('sha256').update(JSON.stringify(step)).digest('hex');
const target = (step, n) => step.store === 'sqlite' ? `${path.basename(n.netDb)}:${step.tables.join(',')}` : `${n[step.db]}.${step.table}`;

class StepError extends Error {
  constructor(message, { code, why, sql } = {}) { super(message); this.code = code; this.why = why; this.sql = sql; }
}

function connect() {
  return mysql.createConnection({
    host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT, 10) || 3306,
    socketPath: process.env.DB_SOCKET || undefined,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    connectTimeout: 10000, charset: 'utf8mb4', supportBigNumbers: true,
  });
}

// ── what the database looks like now (read-only) ────────────────────────────
async function tableExists(conn, schema, table) {
  const [r] = await conn.query('SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=?', [schema, table]);
  return r.length > 0;
}
async function columnsOf(conn, schema, table) {
  const [r] = await conn.query('SELECT COLUMN_NAME c FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=?', [schema, table]);
  return new Set(r.map(x => x.c.toLowerCase()));
}
async function indexesOf(conn, schema, table) {
  const [r] = await conn.query(
    `SELECT INDEX_NAME i, NON_UNIQUE nu, COLUMN_NAME c FROM information_schema.STATISTICS
      WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY INDEX_NAME, SEQ_IN_INDEX`, [schema, table]);
  const m = new Map();
  for (const x of r) {
    if (!m.has(x.i)) m.set(x.i, { unique: Number(x.nu) === 0, cols: [] });
    m.get(x.i).cols.push(x.c.toLowerCase());
  }
  return m;
}
function sqliteTables(file) {
  const db = new Database(file, { readonly: true, fileMustExist: true });
  try { return new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r => r.name)); }
  finally { db.close(); }
}

/** What applying `step` would do now: { action: 'baseline'|'apply', note, run?() } */
async function plan(conn, step, n) {
  if (step.store === 'sqlite') {
    let have;
    try { have = sqliteTables(n.netDb); }
    catch (e) { throw new StepError(`cannot open ${n.netDb}: ${e.message}`, { code: e.code || 'SQLITE_CANTOPEN' }); }
    const missing = step.tables.filter(t => !have.has(t));
    if (!missing.length) return { action: 'baseline', note: 'all tables already exist' };
    return { action: 'apply', note: `create ${missing.join(', ')}`, run: () => {
      const db = new Database(n.netDb, { fileMustExist: true, timeout: 10000 });
      try {
        db.pragma('synchronous = EXTRA');
        if (db.pragma('synchronous', { simple: true }) !== 3) {
          throw new Error('SQLite writer requires synchronous=EXTRA');
        }
        db.exec('BEGIN IMMEDIATE');
        try { db.exec(step.sql); db.exec('COMMIT'); }
        catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw Object.assign(e, { sql: step.sql }); }
      } finally { db.close(); }
    } };
  }
  const schema = n[step.db];
  const fq = `${q(schema)}.${q(step.table)}`;
  const exists = await tableExists(conn, schema, step.table);
  if (step.kind === 'create-table') {
    if (exists) return { action: 'baseline', note: 'table already exists' };
    return { action: 'apply', note: 'create table', sql: step.sql, schema };
  }
  if (!exists) throw new StepError(`${schema}.${step.table} does not exist`, { code: 'ER_NO_SUCH_TABLE' });
  if (step.kind === 'add-columns') {
    const have = await columnsOf(conn, schema, step.table);
    const add = step.columns.filter(([c]) => !have.has(c));
    if (!add.length) return { action: 'baseline', note: 'columns already present' };
    return { action: 'apply', note: `add ${add.map(([c]) => c).join(', ')}`, schema,
             sql: `ALTER TABLE ${fq} ` + add.map(([c, def]) => `ADD COLUMN ${q(c)} ${def}`).join(', ') };
  }
  if (step.kind === 'add-unique') {
    const idx = await indexesOf(conn, schema, step.table);
    const want = step.columns.map(c => c.toLowerCase());
    for (const [name, v] of idx)
      if (v.unique && v.cols.length === want.length && v.cols.every((c, i) => c === want[i]))
        return { action: 'baseline', note: `unique key ${name} already covers (${want.join(', ')})` };
    if (idx.has(step.index))
      throw new StepError(`an index named ${step.index} exists on ${schema}.${step.table} but is not UNIQUE (${want.join(', ')})`,
        { code: 'INDEX_NAME_TAKEN', why: 'drop or rename that index by hand, then re-run; this step will not replace an index it did not create.' });
    const cols = step.columns.map(q).join(', ');
    const [dups] = await conn.query(
      `SELECT ${cols}, COUNT(*) AS n FROM ${fq} WHERE ${step.columns.map(c => `${q(c)} IS NOT NULL`).join(' AND ')}
        GROUP BY ${cols} HAVING COUNT(*) > 1 ORDER BY n DESC LIMIT 5`);
    if (dups.length)
      throw new StepError(`${schema}.${step.table} has duplicate (${want.join(', ')}) values, so the unique key cannot be added`, {
        code: 'DUPLICATE_KEYS',
        why: `e.g. ${dups.map(d => `${want.map(c => d[c]).join('/')} x${d.n}`).join('; ')}. Resolve the duplicates (keep one row per value), then re-run.`,
        sql: `SELECT ${cols}, COUNT(*) n FROM ${fq} GROUP BY ${cols} HAVING n > 1` });
    return { action: 'apply', note: `add unique key ${step.index} (${want.join(', ')})`, schema,
             sql: `ALTER TABLE ${fq} ADD UNIQUE INDEX ${q(step.index)} (${cols})` };
  }
  throw new StepError(`unknown step kind ${step.kind}`, { code: 'BAD_STEP' });
}

async function recorded(conn, hub) {
  if (!(await tableExists(conn, hub, 'schema_migrations'))) return new Map();
  const [r] = await conn.query(`SELECT id, checksum, outcome, applied_at, applied_by FROM ${q(hub)}.schema_migrations`);
  return new Map(r.map(x => [x.id, x]));
}

function printContract(res) {
  for (const [s, v] of Object.entries(res.slices)) {
    out(`  contract ${s.padEnd(13)} ${v.state}`);
    for (const p of v.problems) out(`      - ${p}`);
  }
}

function explain(step, n, e) {
  out(`[migrate] FAILED at ${step.id} (${target(step, n)})`);
  out(`  error: ${e.code ? e.code + ': ' : ''}${e.message}`);
  const why = e.why || HINTS[e.code];
  if (why) out(`  why:   ${why}`);
  if (e.sql) out(`  sql:   ${String(e.sql).split('\n').join('\n         ')}`);
  out('  Steps after this one were not attempted; steps before it are recorded. Fix the cause and re-run apply.');
}

async function main(cmd) {
  if (!['status', 'check', 'apply'].includes(cmd)) {
    out('usage: node migrate.js status|check|apply'); return EXIT.USAGE;
  }
  if (cmd === 'apply' && process.getuid && process.getuid() === 0 && process.env.MIGRATE_ALLOW_ROOT !== '1') {
    out('[migrate] refusing to apply as root: run it as the service user (sudo -u corpit ...).'); return EXIT.USAGE;
  }
  const n = contract.names();
  let conn;
  try { conn = await connect(); }
  catch (e) { out(`[migrate] cannot connect to MySQL: ${e.code || ''} ${e.message}`); if (HINTS[e.code]) out(`  why:   ${HINTS[e.code]}`); return EXIT.USAGE; }
  try {
    out(`[migrate] ${cmd}  inventory=${n.inventory} hub=${n.hub} netfleet=${n.netDb}`);

    if (cmd === 'check') {
      const res = await contract.check({ mysqlConn: conn, Database });
      printContract(res);
      out(res.ok ? '[migrate] contract OK' : '[migrate] contract NOT satisfied: run `migrate.js apply`, or see the problems above');
      return res.ok ? EXIT.OK : EXIT.CONTRACT;
    }

    if (cmd === 'status') {
      const rec = await recorded(conn, n.hub);
      const creates = new Map();   // table an earlier pending step will create -> that step's id
      for (const step of STEPS) {
        const r = rec.get(step.id);
        let line;
        if (r) line = `recorded ${r.outcome} ${new Date(r.applied_at).toISOString()}${r.checksum !== checksum(step) ? '  ** DEFINITION CHANGED SINCE RECORDED **' : ''}`;
        else {
          const key = step.store === 'sqlite' ? null : `${n[step.db]}.${step.table}`;
          try {
            const p = await plan(conn, step, n);
            if (p.action === 'apply' && step.kind === 'create-table') creates.set(key, step.id);
            line = `pending: would ${p.action} (${p.note})`;
          } catch (e) {
            line = e.code === 'ER_NO_SUCH_TABLE' && creates.has(key)
              ? `pending: runs after ${creates.get(key)} creates the table`
              : `pending: would FAIL (${e.code || ''} ${e.message})`;
          }
        }
        out(`  ${step.id.padEnd(44)} ${line}`);
      }
      const res = await contract.check({ mysqlConn: conn, Database });
      printContract(res);
      return res.ok ? EXIT.OK : EXIT.CONTRACT;
    }

    // apply
    const [[lk]] = await conn.query('SELECT GET_LOCK(?, 0) AS got', [LOCK]);
    if (lk.got !== 1) {
      const [[who]] = await conn.query('SELECT IS_USED_LOCK(?) AS id', [LOCK]);
      out(`[migrate] another migration holds ${LOCK} (MySQL connection ${who.id}); nothing was changed. Re-run when it finishes.`);
      return EXIT.LOCKED;
    }
    try {
      await conn.query('SET SESSION lock_wait_timeout = 10');
      await conn.query(`CREATE TABLE IF NOT EXISTS ${q(n.hub)}.schema_migrations (
          id varchar(100) NOT NULL PRIMARY KEY,
          checksum char(64) NOT NULL,
          outcome varchar(16) NOT NULL,
          detail text,
          applied_by varchar(200),
          applied_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
          duration_ms int
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
      const rec = await recorded(conn, n.hub);
      const by = `${process.env.MIGRATE_BY ? process.env.MIGRATE_BY + ' ' : ''}${os.userInfo().username}@${os.hostname()}`;
      for (const step of STEPS) {
        const sum = checksum(step), r = rec.get(step.id);
        if (r) {
          if (r.checksum !== sum) {
            explain(step, n, new StepError(`step ${step.id} was recorded (${r.outcome}, ${new Date(r.applied_at).toISOString()}) with a different definition`, {
              code: 'STEP_EDITED', why: 'recorded steps are immutable. Revert the edit to schema/migrations.js and add a new step for the change.' }));
            return EXIT.STEP;
          }
          out(`  ${step.id.padEnd(44)} recorded (${r.outcome})`);
          continue;
        }
        const t0 = Date.now();
        let p;
        try {
          p = await plan(conn, step, n);
          if (p.action === 'apply') {
            if (p.run) p.run();
            else {
              try { await conn.query(`USE ${q(p.schema)}`); await conn.query(p.sql); }   // CREATE bodies are unqualified
              catch (e) { e.sql = p.sql; throw e; }
            }
          }
        } catch (e) { explain(step, n, e); return EXIT.STEP; }
        const ms = Date.now() - t0;
        await conn.query(`INSERT INTO ${q(n.hub)}.schema_migrations (id, checksum, outcome, detail, applied_by, duration_ms) VALUES (?,?,?,?,?,?)`,
          [step.id, sum, p.action === 'apply' ? 'applied' : 'baseline', p.note, by, ms]);
        out(`  ${step.id.padEnd(44)} ${p.action === 'apply' ? 'APPLIED ' : 'baseline'} ${p.note} (${ms} ms)`);
      }
      const res = await contract.check({ mysqlConn: conn, Database });
      printContract(res);
      if (!res.ok) {
        out('[migrate] every step is recorded but the contract is NOT satisfied: the schema changed outside migrations (or a store is unreachable).');
        out('  Fix the tables listed above by hand, or add a new step to schema/migrations.js. Do not restart onto code that needs them.');
        return EXIT.CONTRACT;
      }
      out('[migrate] OK');
      return EXIT.OK;
    } finally {
      await conn.query('SELECT RELEASE_LOCK(?)', [LOCK]).catch(() => {});
    }
  } catch (e) {
    out(`[migrate] error: ${e.code || ''} ${e.message}`);
    if (HINTS[e.code]) out(`  why:   ${HINTS[e.code]}`);
    return EXIT.USAGE;
  } finally {
    await conn.end().catch(() => {});
  }
}

if (require.main === module) main(process.argv[2]).then(code => process.exit(code));
module.exports = { main, EXIT };
