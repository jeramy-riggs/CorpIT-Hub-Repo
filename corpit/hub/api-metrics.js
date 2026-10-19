// ─────────────────────────────────────────────────────────────────────────────
// api-metrics.js — in-process, per-module request/error counters.
//
// Exists so the Server Health dashboard can report a real error rate for the
// internal APIs registered in ITAM instead of guessing. Deliberately tiny:
// fixed-size ring of 1-minute buckets per '/api/<module>' prefix, no strings
// retained per request, no dependency, no disk. Counters reset on restart —
// the dashboard labels the window it is reporting.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

const WINDOW_MIN = 60;                 // rolling window, in 1-minute buckets
const MAX_PREFIXES = 200;              // hard cap; prevents unbounded growth

const buckets = new Map();             // prefix -> { at: [], total: [], err: [] }

function minuteIndex() { return Math.floor(Date.now() / 60000); }

function slot(prefix) {
  let b = buckets.get(prefix);
  if (!b) {
    if (buckets.size >= MAX_PREFIXES) return null;
    b = { minute: new Array(WINDOW_MIN).fill(-1), total: new Array(WINDOW_MIN).fill(0), err: new Array(WINDOW_MIN).fill(0), lastAt: 0 };
    buckets.set(prefix, b);
  }
  return b;
}

function prefixOf(url) {
  // '/api/system/vhosts?x=1' -> '/api/system'
  if (!url || url.slice(0, 5) !== '/api/') return null;
  const q = url.indexOf('?');
  const p = (q === -1 ? url : url.slice(0, q)).split('/');
  return p.length >= 3 && p[2] ? '/api/' + p[2] : null;
}

function middleware(req, res, next) {
  const prefix = prefixOf(req.originalUrl || req.url);
  if (!prefix) return next();
  res.on('finish', function () {
    const b = slot(prefix);
    if (!b) return;
    const m = minuteIndex();
    const i = m % WINDOW_MIN;
    if (b.minute[i] !== m) { b.minute[i] = m; b.total[i] = 0; b.err[i] = 0; }
    b.total[i]++;
    if (res.statusCode >= 500) b.err[i]++;
    b.lastAt = Date.now();
  });
  next();
}

// Returns { '/api/system': { requests, errors, errorRatePct, lastRequestAt } }
function snapshot() {
  const m = minuteIndex();
  const out = {};
  buckets.forEach(function (b, prefix) {
    let total = 0, err = 0;
    for (let i = 0; i < WINDOW_MIN; i++) {
      // Only count buckets inside the rolling window; a stale slot is a bucket
      // from a previous hour that has not been overwritten yet.
      if (b.minute[i] >= 0 && (m - b.minute[i]) < WINDOW_MIN) { total += b.total[i]; err += b.err[i]; }
    }
    out[prefix] = {
      requests: total,
      errors: err,
      errorRatePct: total ? Math.round((err / total) * 1000) / 10 : 0,
      lastRequestAt: b.lastAt ? new Date(b.lastAt).toISOString() : null,
    };
  });
  return { windowMin: WINDOW_MIN, prefixes: out };
}

module.exports = { middleware, snapshot, WINDOW_MIN };
