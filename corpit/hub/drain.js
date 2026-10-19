'use strict';
// CHG-ARCH-20 (2026-09-24): drain in-flight requests on pm2 stop/restart.
// Review finding #6: the SIGINT/SIGTERM handlers exited 1.2 s after the signal whatever was
// still running, and app.listen's handle was thrown away, so nothing could stop accepting work.
// Sequence now: mark draining (health answers 503, responses carry Connection: close), stop
// accepting, wait for in-flight requests up to DRAIN_MS, close the pools handed to attach(),
// flush telemetry, exit 0. pm2 kill_timeout for these apps is 10000 (/etc/corpit/ecosystem.config.js);
// HARD_MS keeps the whole sequence inside it. A signal before attach() (still starting up) keeps
// the old behaviour: flush, exit within 1.2 s.
// Identical copies in /var/www/corpit-hub-api and /var/www/api (not a symlink, so each app's
// rollback is its own). Undo: rollback.sh in /var/backups/corpit-arch-fix-20260924/chg20-drain
const DRAIN_MS = 8000;       // agreed 2026-09-24: 8 s drain, pm2 kill_timeout 10 s
const POOL_MS = 500;
const FLUSH_MS = 1000;
const HARD_MS = 9500;        // from the signal; pm2 SIGKILLs at 10000

const st = { server: null, pools: [], draining: false, inflight: 0, t0: 0 };

function capped(p, ms) {
  return Promise.race([
    Promise.resolve(p).then(function () { return 'ok'; }, function () { return 'error'; }),
    new Promise(function (r) { setTimeout(r, ms, 'timeout').unref(); }),
  ]);
}

function flush() {
  try { return require('./obs-lib').flush(); } catch (e) { return Promise.resolve(); }
}

function attach(server, pools) {
  st.server = server;
  st.pools = (pools || []).filter(Boolean);
  server.on('request', function (req, res) {
    st.inflight++;
    res.on('close', function () {
      st.inflight--;
      if (st.draining) { try { server.closeIdleConnections(); } catch (e) {} }
    });
  });
  return server;
}

// Registered ahead of the routes. Only acts once draining has begun.
function middleware(req, res, next) {
  if (!st.draining) return next();
  res.set('Connection', 'close');
  if (req.path === '/api/health') return res.status(503).json({ status: 'draining' });
  return next();
}

function begin(sig, record) {
  const log = function (kind, msg) {
    try { if (record) record(kind, msg); else console.log('[drain] ' + kind + ' ' + msg); } catch (e) {}
  };
  if (st.draining) return;              // repeat signal: the first sequence is already running
  st.draining = true; st.t0 = Date.now();
  let done = false;
  const bye = function () { if (!done) { done = true; process.exit(0); } };
  if (!st.server) {                     // not listening yet: previous behaviour
    setTimeout(bye, 1200).unref();
    Promise.resolve(flush()).catch(function () {}).then(bye);
    return;
  }
  setTimeout(bye, HARD_MS);            // not unref'd: these two timers must fire even if nothing else is left
  const atSignal = st.inflight;
  let finishing = false;
  const finish = function (how) {
    if (finishing) return; finishing = true;
    const drainMs = Date.now() - st.t0, left = st.inflight;
    capped(Promise.all(st.pools.map(function (p) { return p.end(); })), POOL_MS).then(function (pools) {
      return capped(flush(), FLUSH_MS).then(function (fl) {
        log('DRAIN ' + how, 'in-flight at ' + sig + ' ' + atSignal + ', unfinished ' + left +
          ', drain ' + drainMs + 'ms, pools(' + st.pools.length + ') ' + pools + ', flush ' + fl);
      });
    }).then(bye, bye);
  };
  setTimeout(function () { finish('deadline'); }, DRAIN_MS);
  try { st.server.close(function () { finish('complete'); }); } catch (e) { finish('close-error'); }
  try { st.server.closeIdleConnections(); } catch (e) {}
}

module.exports = { attach: attach, middleware: middleware, begin: begin,
  DRAIN_MS: DRAIN_MS, HARD_MS: HARD_MS, _state: st };
