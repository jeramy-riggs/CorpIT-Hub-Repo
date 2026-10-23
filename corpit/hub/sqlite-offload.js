'use strict';
/* ═══════════════════════════════════════════════════════════════════════════
   sqlite-offload.js — run read-only SQLite statements off the event loop.

   better-sqlite3 is synchronous. A two-second aggregate on the request path
   is two seconds during which this process answers nothing at all — including
   nginx's auth_request gate, which gives up at 2s and bounces every visitor on
   every vhost to sign-in. Measured before this module existed (2026-09-23):
   the ZPA traffic status COUNT(*) took 33.6s, the traffic summary ~4 minutes,
   the switch-port trend 2.5s. Any read that can take longer than a few
   milliseconds belongs here.

     query(dbPath, stmts, opts) → Promise<
         { ok: true,  results: [...], tookMs, cachedAt? }
       | { ok: false, status: 503|504|500, error }>

     stmts  [{ sql, params?, mode?: 'all' | 'get' }]
            Run in order on ONE connection in ONE worker thread, so an endpoint
            that needs five aggregates pays one thread start and one file open.
     opts   { timeoutMs, cacheKey, cacheTtlMs, label }

   Guarantees
     • SQL text is server code. Callers bind request input as params; the
       worker refuses any statement that is not read-only (belt) on a file it
       opened readonly (braces).
     • Never rejects. Every failure is { ok:false, status, error } so a route
       cannot forget a catch and leak a stack trace.
     • At most MAX_INFLIGHT threads run; up to MAX_QUEUE more callers wait in
       arrival order, each inside its own timeout, so a page that fans out six
       requests at once gets six answers instead of three answers and three
       503s. Beyond the queue the answer is an immediate 503.
     • A caller's timeout covers waiting and running together: a request that
       queued for most of its budget is not started only to be cancelled.
     • A slot is freed when the worker replies. A worker that timed out keeps
       its slot until the thread has actually exited: worker.terminate()
       cannot interrupt a native sqlite3_step loop, so releasing at timeout
       would let the cap admit more work than it bounds (same reasoning as
       lss-query-worker's runJob).
     • Identical concurrent requests share one promise; a success is then
       served from cache for cacheTtlMs. Failures are never cached.
     • resourceLimits caps the worker heap, so an oversized result set kills
       the thread and not the API.
   Results are shared between cached callers: treat them as immutable.
   ═══════════════════════════════════════════════════════════════════════════ */
const { Worker } = require('worker_threads');
const path = require('path');

const WORKER_PATH = path.join(__dirname, 'sqlite-offload-worker.js');
const MAX_INFLIGHT = intEnv('SQLITE_OFFLOAD_MAX_INFLIGHT', 3);
const MAX_QUEUE = intEnv('SQLITE_OFFLOAD_MAX_QUEUE', 16);
const DEFAULT_TIMEOUT_MS = intEnv('SQLITE_OFFLOAD_TIMEOUT_MS', 30000);
const WORKER_HEAP_MB = intEnv('SQLITE_OFFLOAD_HEAP_MB', 256);
const CACHE_MAX_ENTRIES = 256;
const MIN_START_BUDGET_MS = 250;   // less than this left after queueing: answer 504 without spawning a thread

let inFlight = 0;
const waiting = [];        // jobs admitted to the queue, oldest first
const cache = new Map();   // cacheKey → { promise } while running, { expiresAt, value } after

// '15s' above ten seconds, '0.3s' below it — a sub-second budget should not read as '0s'.
function secs(ms) { return (ms >= 10000 ? Math.round(ms / 1000) : Math.round(ms / 100) / 10) + 's'; }
function intEnv(name, fallback) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function run(dbPath, stmts, opts) {
  return new Promise((resolve) => {
    const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
    const job = { dbPath, stmts, opts, resolve, timeoutMs, deadline: Date.now() + timeoutMs, timer: null };
    if (inFlight < MAX_INFLIGHT) return start(job);
    if (waiting.length >= MAX_QUEUE) {
      return resolve({ ok: false, status: 503,
        error: 'Database queries are saturated (' + MAX_INFLIGHT + ' running, ' + MAX_QUEUE + ' waiting). Try again in a moment.' });
    }
    waiting.push(job);
    job.timer = setTimeout(() => {
      const i = waiting.indexOf(job);
      if (i >= 0) waiting.splice(i, 1);
      resolve({ ok: false, status: 504,
        error: (opts.label || 'Query') + ' waited ' + secs(timeoutMs) + ' for a database slot and was cancelled. Try again in a moment.' });
    }, timeoutMs);
  });
}

function pump() {
  while (inFlight < MAX_INFLIGHT && waiting.length) start(waiting.shift());
}

function start(job) {
  clearTimeout(job.timer);
  const { dbPath, stmts, opts, resolve } = job;
  const budgetMs = job.deadline - Date.now();
  if (budgetMs < MIN_START_BUDGET_MS) {
    resolve({ ok: false, status: 504,
      error: (opts.label || 'Query') + ' waited ' + secs(job.timeoutMs) + ' for a database slot and was cancelled. Try again in a moment.' });
    return;
  }
  inFlight++;
  let worker = null, done = false, released = false, timer = null;

  const release = () => { if (!released) { released = true; inFlight--; pump(); } };
  const finish = (v) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    if (worker) { try { worker.terminate(); } catch (_) { /* best effort; may not land */ } }
    resolve(v);
  };

  try {
    worker = new Worker(WORKER_PATH, {
      workerData: { dbPath, stmts },
      resourceLimits: { maxOldGenerationSizeMb: WORKER_HEAP_MB },
    });
  } catch (e) {
    release();
    return resolve({ ok: false, status: 503, error: 'query worker failed to start: ' + e.message });
  }
  timer = setTimeout(() => finish({ ok: false, status: 504,
    error: (opts.label || 'Query') + ' exceeded ' + secs(job.timeoutMs) +
           ' and was cancelled. Narrow the window and try again.' }), budgetMs);
  // The reply ends the SQL work, so the slot is freed here rather than when
  // the terminated worker finally exits. A timed-out worker keeps its slot
  // until exit: the native call cannot be interrupted and is still running.
  worker.on('message', (m) => { release(); finish(m && typeof m === 'object' ? m
    : { ok: false, status: 500, error: 'empty worker reply' }); });
  worker.on('error', (e) => { release(); finish({ ok: false, status: 500, error: e.message }); });
  worker.on('exit', (code) => { release(); finish({ ok: false, status: 500, error: 'query worker exited (' + code + ')' }); });
}

function query(dbPath, stmts, opts) {
  opts = opts || {};
  const key = opts.cacheKey;
  if (!key) return run(dbPath, stmts, opts);

  const now = Date.now();
  const hit = cache.get(key);
  if (hit) {
    if (hit.promise) return hit.promise;                       // cold miss: share the running query
    if (hit.expiresAt > now) return Promise.resolve(hit.value);
    if (hit.staleUntil > now) {
      // A costly report can be refreshed in the background. Keep the last
      // successful answer available while that query runs or times out.
      if (!hit.refreshPromise && (!hit.retryAt || hit.retryAt <= now)) {
        hit.refreshPromise = run(dbPath, stmts, opts).then((r) => {
          if (cache.get(key) !== hit) return r;                 // invalidated during refresh
          hit.refreshPromise = null;
          if (r.ok) {
            r.cachedAt = Date.now();
            cache.set(key, {
              expiresAt: r.cachedAt + opts.cacheTtlMs,
              staleUntil: r.cachedAt + opts.cacheTtlMs + (opts.staleTtlMs || 0),
              value: r,
            });
          } else {
            hit.retryAt = Date.now() + (opts.retryDelayMs || 30000);
            console.warn('[sqlite-offload] refresh failed:', opts.label || key, r.error);
          }
          return r;
        }).catch((e) => {
          if (cache.get(key) === hit) {
            hit.refreshPromise = null;
            hit.retryAt = Date.now() + (opts.retryDelayMs || 30000);
          }
          console.warn('[sqlite-offload] refresh failed:', opts.label || key, e.message);
          return { ok: false, status: 500, error: e.message };
        });
      }
      return Promise.resolve(Object.assign({}, hit.value, { stale: true }));
    }
    // Once the bounded stale period ends, callers must wait for a fresh
    // result. If a refresh is already running, share it.
    if (hit.refreshPromise) return hit.refreshPromise;
    cache.delete(key);
  }

  const p = run(dbPath, stmts, opts).then((r) => {
    if (r.ok && opts.cacheTtlMs > 0) {
      if (cache.size >= CACHE_MAX_ENTRIES) evictExpired();
      r.cachedAt = Date.now();
      cache.set(key, {
        expiresAt: r.cachedAt + opts.cacheTtlMs,
        staleUntil: r.cachedAt + opts.cacheTtlMs + (opts.staleTtlMs || 0),
        value: r,
      });
    } else {
      cache.delete(key);
    }
    return r;
  });
  cache.set(key, { promise: p });
  return p;
}

function evictExpired() {
  const now = Date.now();
  for (const [k, v] of cache) if (v.staleUntil && v.staleUntil <= now) cache.delete(k);
  if (cache.size >= CACHE_MAX_ENTRIES) cache.clear();          // bounded backstop
}

function invalidate(prefix) {
  for (const k of cache.keys()) if (!prefix || k.startsWith(prefix)) cache.delete(k);
}

function stats() {
  return { inFlight, waiting: waiting.length, maxInflight: MAX_INFLIGHT, maxQueue: MAX_QUEUE, cached: cache.size, timeoutMs: DEFAULT_TIMEOUT_MS };
}

module.exports = { query, invalidate, stats };
