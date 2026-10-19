'use strict';
/* ════════════════════════════════════════════════════════════════════
   Startup schema readiness (CHG-ARCH-18). The hub performs no DDL: at boot
   it checks schema/contract.js read-only, and a module whose tables do not
   satisfy it answers 503 SCHEMA_NOT_READY instead of half-working. The rest
   of the process (the auth gate included) is unaffected.

     server.js:        require('./schema/readiness').start();   summary() -> /api/health
     module routers:   router.use(require('./schema/readiness').requireSchema('intune'))

   'incompatible' refuses every method with 503 SCHEMA_NOT_READY.
   'unknown' (a store unreachable at check time, or the check still running
   after WAIT_MS) depends on the method (rescan R5, 2026-09-24):
     GET / HEAD / OPTIONS pass through: the route surfaces its own DB error.
     Every other method is refused with 503 SCHEMA_UNVERIFIED + Retry-After.
     A write must not start against a store nobody has verified: housekeeping
     makes the AD change first and writes its audit row after.
   Anything not 'ok' is re-checked on demand, at most every 30 s. The retry
   that Retry-After asks for runs that re-check, so a transient failure heals
   without a restart.
   ════════════════════════════════════════════════════════════════════ */

const mysql = require('mysql2/promise');
const contract = require('./contract');

const RECHECK_MS = 30000;
const WAIT_MS = 5000;
const FIX = 'run `sudo -u corpit node /var/www/corpit-hub-api/migrate.js apply`, then restart corpit-hub-api';

let result = null;          // last contract.check() result
let checkedAt = 0;
let inflight = null;
let lastLogged = '';

async function runCheck() {
  let conn;
  try {
    conn = await mysql.createConnection({
      host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT, 10) || 3306,
      user: process.env.DB_USER, password: process.env.DB_PASSWORD,
      connectTimeout: 5000, charset: 'utf8mb4',
    });
  } catch (e) { conn = { query: () => Promise.reject(e) }; }    // -> mysql slices 'unknown'
  try {
    return await contract.check({ mysqlConn: conn });
  } finally {
    if (conn.end) conn.end().catch(() => {});
  }
}

function check() {
  if (!inflight) {
    inflight = runCheck()
      .then(r => { result = r; })
      .catch(e => { result = { ok: false, slices: Object.fromEntries(contract.SLICES.map(s => [s, { state: 'unknown', problems: [e.message] }])) }; })
      .finally(() => {
        checkedAt = Date.now();
        inflight = null;
        const line = Object.entries(result.slices).map(([s, v]) => `${s}=${v.state}`).join(' ');
        if (line !== lastLogged) {
          lastLogged = line;
          const probs = (st) => Object.values(result.slices).filter(v => v.state === st).flatMap(v => v.problems).join('; ');
          if (result.ok) console.log(`[schema] contract ok (${line})`);
          else if (summary() === 'incompatible')
            console.error(`[schema] contract NOT satisfied (${line}): ${probs('incompatible')} -- ${FIX}`);
          else    // unknown: a store was unreachable, which says nothing about the schema
            console.error(`[schema] contract could not be checked (${line}): ${probs('unknown')} -- reads on those routes pass through, writes answer 503 SCHEMA_UNVERIFIED; re-checked on demand every ${RECHECK_MS / 1000} s`);
        }
      });
  }
  return inflight;
}

function start() { return check(); }

function sliceState(slice) {
  if (!result) return { state: 'unknown', problems: ['not checked yet'] };
  return result.slices[slice] || { state: 'unknown', problems: [`no such slice ${slice}`] };
}

/** 'ok' | 'incompatible' | 'unknown' for /api/health (no detail: that route is public). */
function summary() {
  if (!result) return 'unknown';
  const states = Object.values(result.slices).map(v => v.state);
  if (states.includes('incompatible')) return 'incompatible';
  return states.every(s => s === 'ok') ? 'ok' : 'unknown';
}

// Wait (bounded) for an in-flight check, or start one if the last is stale.
async function settle() {
  const due = !result || Date.now() - checkedAt >= RECHECK_MS;
  const p = inflight || (due ? check() : null);
  if (p) await Promise.race([p, new Promise(r => setTimeout(r, WAIT_MS).unref())]);
}

// Methods that may run while a slice is 'unknown'. Everything else, including a
// request with no method, is treated as a write (fail closed).
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Seconds until a retry will find a fresh check: the in-flight one should have
// landed by then, or settle() will be allowed to start the next one.
function retryAfterSeconds() {
  const ms = inflight ? WAIT_MS : checkedAt + RECHECK_MS - Date.now();
  return Math.min(Math.ceil(RECHECK_MS / 1000), Math.max(1, Math.ceil(ms / 1000)));
}

function requireSchema(slice) {
  if (!contract.SLICES.includes(slice)) throw new Error(`requireSchema: unknown slice ${slice}`);
  return async (req, res, next) => {
    if (sliceState(slice).state !== 'ok') await settle();
    const s = sliceState(slice);
    if (s.state === 'incompatible')
      return res.status(503).json({ error: 'SCHEMA_NOT_READY', slice, problems: s.problems, fix: FIX });
    if (s.state !== 'ok' && !READ_METHODS.has(String(req.method || '').toUpperCase())) {
      const retryAfter = retryAfterSeconds();
      console.warn(`[schema] refused ${req.method} ${req.baseUrl || ''}${req.path || ''}: ${slice}=${s.state}, retry in ${retryAfter} s`);
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(503).json({
        error: 'SCHEMA_UNVERIFIED', slice, state: s.state, problems: s.problems, retryAfter,
        message: `The ${slice} tables could not be verified (store unreachable or check still running). Nothing was changed. Retry in ${retryAfter} s.`,
      });
    }
    next();
  };
}

module.exports = { start, check, summary, sliceState, requireSchema };
