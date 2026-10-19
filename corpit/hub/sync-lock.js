// sync-lock.js — cross-process exclusion for the Entra/Okta sync jobs.
//
// The scheduler (syncs-worker), the hub API's manual triggers, OEM tooling and the
// okta-apps cron job load the same sync modules in separate processes, so a
// module-local flag cannot see a run in another process. A MySQL named lock can:
// one dedicated connection holds it for the life of the run, and the server drops
// it if that connection or process dies, so there is no stale lock to clean up.
//
// Rescan R4 (2026-09-24): when the server drops the lock while this process is still
// working, another process can take it, and both then write. So withLock hands fn a
// lease { name, signal }. The signal aborts (reason: a SyncLockLostError) when the lock
// connection emits 'error' or 'end', or when the ownership check finds the lock is not
// ours. That check runs every TIMING.checkMs on the lock connection
// (IS_USED_LOCK(name) must equal CONNECTION_ID()) and must answer within
// TIMING.checkTimeoutMs. fn stops itself by calling throwIfLost(signal) at its safe
// points (before each write phase / batch). If the lock was lost before fn returned,
// withLock rejects with the SyncLockLostError instead of returning fn's result.
// A lost lock is not released; its connection is destroyed. While the lock is held
// normally nothing else changes apart from the periodic check query.
'use strict';
const mysql = require('mysql2/promise');

// Production values. Exported so a test harness can shorten them.
const TIMING = { checkMs: 15000, checkTimeoutMs: 10000 };

class SyncLockLostError extends Error {
  constructor(name, why) {
    super(`sync lock ${name} lost (${why}); stopped before further writes`);
    this.name = 'SyncLockLostError';
    this.code = 'SYNC_LOCK_LOST';
    this.lock = name;
  }
}

// Throws the lease's SyncLockLostError once `signal` has aborted. No signal: no-op.
function throwIfLost(signal) {
  if (signal && signal.aborted) throw signal.reason;
}

async function connect() {
  const conn = await mysql.createConnection({
    host:     process.env.DB_HOST || 'localhost',
    port:     parseInt(process.env.DB_PORT || '3306', 10),
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  });
  // A dropped connection emits 'error'; unhandled, that would take the process down.
  conn.on('error', e => console.error('[sync-lock] lock connection error:', e.code || e.message));
  return conn;
}

// Resolves `p`, or rejects after `ms` with `msg`. The timer never keeps a process alive.
function bounded(p, ms, msg) {
  let t;
  const timeout = new Promise((_, reject) => { t = setTimeout(() => reject(new Error(msg)), ms); t.unref(); });
  return Promise.race([p, timeout]).finally(() => clearTimeout(t));
}

// Run fn(lease) while holding lock `name`.
//   waitSec 0  -> held elsewhere: skip, resolves { skipped: true, lock }
//   waitSec >0 -> queue behind the holder; still held after waitSec: throws
//   lock lost while fn runs -> lease.signal aborts; withLock rejects with SyncLockLostError
async function withLock(name, waitSec, fn) {
  const conn = await connect();
  let held = false, done = false, lost = false, timer = null;
  const ac = new AbortController();
  const lose = (why) => {
    if (!held || done || lost) return;
    lost = true;
    const err = new SyncLockLostError(name, why);
    console.error('[sync-lock] ' + err.message);
    ac.abort(err);
  };
  const onError = e => lose('lock connection error: ' + (e && (e.code || e.message)));
  const onEnd = () => lose('lock connection ended');
  const check = async () => {
    timer = null;
    if (done || lost) return;
    try {
      const [[r]] = await bounded(
        conn.query('SELECT IS_USED_LOCK(?) AS holder, CONNECTION_ID() AS me', [name]),
        TIMING.checkTimeoutMs, `no answer in ${TIMING.checkTimeoutMs} ms`);
      if (r.holder === null || r.holder === undefined) lose('the server shows it free');
      else if (String(r.holder) !== String(r.me)) lose(`now held by connection ${r.holder}, not this one (${r.me})`);
    } catch (e) {
      lose('ownership check failed: ' + (e && (e.code || e.message)));
    }
    if (!done && !lost) { timer = setTimeout(check, TIMING.checkMs); timer.unref(); }
  };
  try {
    const [[r]] = await conn.query('SELECT GET_LOCK(?, ?) AS got', [name, waitSec]);
    if (r.got !== 1) {
      if (waitSec === 0) return { skipped: true, lock: name };
      throw new Error(`${name} still held by another process after ${waitSec}s`);
    }
    held = true;
    conn.on('error', onError);
    conn.on('end', onEnd);
    timer = setTimeout(check, TIMING.checkMs); timer.unref();
    const result = await fn({ name, signal: ac.signal });
    // Lost before fn returned: its last writes may overlap a new holder, so do not report success.
    throwIfLost(ac.signal);
    return result;
  } finally {
    done = true;
    if (timer) clearTimeout(timer);
    let clean = !lost;
    if (held && !lost) {
      // Bounded: a connection that stops answering must not hold the caller here.
      clean = await bounded(conn.query('SELECT RELEASE_LOCK(?)', [name]), TIMING.checkTimeoutMs, `no answer in ${TIMING.checkTimeoutMs} ms`)
        .then(() => true, (e) => {
          console.error(`[sync-lock] ${name}: RELEASE_LOCK failed (${e.code || e.message}); destroying the connection, which frees the lock`);
          return false;
        });
    }
    if (clean) await conn.end().catch(() => conn.destroy());
    else conn.destroy();
    if (held) { conn.removeListener('error', onError); conn.removeListener('end', onEnd); }
  }
}

async function isHeld(name) {
  const conn = await connect();
  try {
    const [[r]] = await conn.query('SELECT IS_FREE_LOCK(?) AS free', [name]);
    return r.free === 0;
  } finally {
    await conn.end().catch(() => conn.destroy());
  }
}

module.exports = { withLock, isHeld, throwIfLost, SyncLockLostError, TIMING };
