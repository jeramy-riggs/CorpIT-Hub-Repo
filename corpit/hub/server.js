require('dotenv').config();

// ── Crash logging (2026-08-25) ──────────────────────────────────────────────
// api-beta backs the auth gate for every ITAM page, so when it dies the whole
// site fails closed. pm2 restarts it, but pm2's logs carry no timestamps, which
// made a real outage impossible to date or diagnose. These handlers record WHEN
// and WHY to a dedicated timestamped log. They deliberately do NOT change which
// conditions are fatal — both cases already terminated the process by Node's
// default — so restart behaviour is unchanged; only visibility is added.
(function installCrashLogging(){
  const fs = require('fs');
  const os = require('os');
  // The hardcoded fallback used to be /home/ubuntu/.pm2/logs/api-beta-crash.log.
  // That path was right while these apps ran as `ubuntu`; they now run as the
  // `corpit` service user, and /home/ubuntu is 0750 ubuntu:ubuntu, so the
  // fallback is a path this process cannot write. It is not currently used --
  // pm2 supplies CRASH_LOG=/var/lib/corpit/.pm2/logs/corpit-hub-api-crash.log
  // from its env snapshot, and that sink is healthy -- but a fallback only ever
  // runs on the day something else broke, and this one would have failed
  // silently into the catch below. Point it somewhere the running user can
  // write: /var/log/corpit is corpit-owned and already covered by
  // /etc/logrotate.d/corpit-logs (weekly, rotate 4, create 0640 corpit corpit).
  //
  // Note for anyone reading logs here: the old /home/ubuntu file still exists,
  // is still named like a crash log, and is frozen at 2026-09-06 01:23 -- the
  // moment the service user changed. It is not the live sink. Check
  // `tr '\\0' '\\n' < /proc/<pid>/environ | grep CRASH_LOG` before believing it;
  // CRASH_LOG lives in pm2's dump.pm2, not in .env or the systemd unit.
  const LOG = process.env.CRASH_LOG || '/var/log/corpit/hub-api-lifecycle.log';
  let sinkDead = false;
  function record(kind, err, extra) {
    let line;
    try {
      line = [
        '[' + new Date().toISOString() + ']',
        kind,
        'pid=' + process.pid,
        'uptime=' + Math.round(process.uptime()) + 's',
        'rss=' + Math.round(process.memoryUsage().rss / 1048576) + 'MB',
        'host=' + os.hostname(),
        extra ? ('ctx=' + extra) : '',
        '\n  ' + ((err && (err.stack || err.message)) || String(err)),
        '\n'
      ].join(' ');
    } catch (e) { line = '[' + new Date().toISOString() + '] ' + kind + ' (unformattable)\n'; }
    try { fs.appendFileSync(LOG, line); } catch (e) {
      // Say it once. A recorder that cannot record must not fail quietly --
      // that is the exact defect this block exists to catch in others. The
      // stderr write below is the fallback, so records are never lost outright,
      // but the operator has to be told which sink went away.
      if (!sinkDead) {
        sinkDead = true;
        try {
          process.stderr.write('[' + new Date().toISOString() +
            '] LIFECYCLE LOG SINK UNWRITABLE ' + LOG + ' (' +
            ((e && e.code) || e) + ') -- records continue on stderr only\n');
        } catch (e2) {}
      }
    }
    try { process.stderr.write(line); } catch (e) {}
  }
  process.on('uncaughtException', function (err) {
    record('FATAL uncaughtException', err);
    process.exit(1);            // same as Node's default: die, let pm2 restart
  });
  process.on('unhandledRejection', function (reason) {
    record('FATAL unhandledRejection', reason);
    process.exit(1);            // matches Node's default for unhandled rejections
  });
  // OBS-CORE-10. This used to call process.exit(0) immediately. The buffer holds
  // up to one flush window, and a restart is exactly when the last few seconds of
  // requests are most worth having -- so every deploy silently discarded them,
  // uncounted. Flush, then exit; and exit anyway on a timer well inside pm2's
  // 1600 ms kill_timeout, because a stop must never wait on the recorder.
  // pm2 7 stops a process with SIGINT, not SIGTERM. This handler was registered
  // for SIGTERM only and has therefore NEVER run: the log holds 32 STARTUP lines
  // and zero orderly-stop lines. So the "orderly stop" record was itself a
  // control that could not do its job, and the buffer flush below would have
  // inherited exactly that. Register both signals and name the one received.
  // CHG-ARCH-20: the stop now drains in-flight requests (8 s), closes the main pool and flushes
  // (drain.js); a signal before the server is listening keeps the flush-then-exit-in-1.2 s path.
  ['SIGINT', 'SIGTERM'].forEach(function (sig) {
    process.on(sig, function () {
      record(sig + ' (orderly stop/restart)', 'n/a');
      require('./drain').begin(sig, record);
    });
  });
  record('STARTUP', 'process started', 'node=' + process.version);
})();

const express = require('express');
const mysql   = require('mysql2/promise');
const cors    = require('cors');
const rateLimit = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3001; // .env sets it; the fallback must never collide with it-inventory-api on :3000

// Registered FIRST -- ahead of express.json and the rate limiter -- because
// both of those answer requests themselves without calling next(). A 429 from
// the limiter and a 400 from a malformed body would otherwise never reach this
// middleware, and a rate-limit storm is this platform's own documented outage:
// a request log that cannot see a 429 is blind to the failure it most needs to
// catch. Nothing here reads req.body, and the actor is resolved inside
// res.on('finish') -- by which time auth has run -- so registering this early
// costs no attribution.
try { app.use(require('./obs-middleware').middleware); }
catch (e) { console.error('[startup] obs-middleware not loaded:', e.message); }
// CHG-ARCH-20: while draining, /api/health answers 503 and responses carry Connection: close.
app.use(require('./drain').middleware);
// The observability ingest is the ONE route with an operator-settable body cap
// ("Largest browser report accepted" in the console). It has to be mounted
// AHEAD of the global parser: body-parser sets req._body on the first parse, so
// a cap registered after this line would never see a body and the console
// setting would stay decorative. See obs-ingest-cap.js.
try { app.use('/api/observe/client', require('./obs-ingest-cap')); }
catch (e) { console.error('[startup] obs-ingest-cap not loaded:', e.message); }

// CHG-ARCH-13 (2026-09-23): one 50 MB cap on every route let any caller make the hub
// buffer 50 MB of JSON per request, and the caps individual routers declare for
// themselves were decorative: body-parser marks req._body on the first parse, so a
// parser registered later never sees a body. nginx already refuses more than 1 MB on
// /api/ (CHG-ARCH-09); the app now agrees with it, and the global parser steps aside
// for the routes and routers that own a parser, so THEIR limit is the one that
// applies. Per-route parsers of 256 KB or less elsewhere stay bounded by the 1 MB.
const OWN_BODY_ROUTES = new Set([
  'POST /api/sdops/calls/import',         // 15 MB  sdops-routes.js
  'POST /api/confreview/analyze',         //  8 MB  confreview-routes.js
  'POST /api/zscaler/zia/ai/export/pdf',  //  3 MB  zscaler-diag-routes.js
]);
const OWN_BODY_PREFIXES = [               // routers with a router.use(express.json(...)) of their own
  '/api/breakglass',                      //  4 KB
  '/api/localdev',                        // 16 KB
  '/api/saas-admin',                      // 64 KB
  '/api/department-access',               // 32 KB
  '/internal/department-principal',       // 16 KB
];
const jsonBody = express.json({ limit: '1mb' });
app.use(function (req, res, next) {
  if (OWN_BODY_ROUTES.has(req.method + ' ' + req.path)) return next();
  for (const p of OWN_BODY_PREFIXES) {
    if (req.path === p || req.path.startsWith(p + '/')) return next();
  }
  return jsonBody(req, res, next);
});
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.set('trust proxy', 1);
// nginx sets X-Real-IP on all 38 proxy blocks and overwrites any client-supplied value,
// so it is trustworthy; X-Forwarded-For is set on only 5 of them. Keying on X-Real-IP
// gives true per-client limiting everywhere instead of every user sharing one
// 127.0.0.1 bucket. (Fixed 2026-08-21.)
app.use(rateLimit({
  windowMs: 60_000,
  max: 500,
  standardHeaders: true,
  // Only nginx (loopback) is allowed to name the client. It sets X-Real-IP on all 38 proxy
  // blocks and overwrites any client-supplied value. Port 3001 is reachable off-box, so
  // honouring the header from a non-loopback peer would let a client mint a fresh bucket
  // per request and evade the limiter entirely.
  keyGenerator: (req) => {
    const peer = req.socket && req.socket.remoteAddress;
    const fromProxy = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
    return (fromProxy && req.headers['x-real-ip']) || req.ip;
  },
}));
// Per-module request / error counters for the Server Health dashboard.
// In-process, fixed-size, no I/O - see api-metrics.js.
try { app.use(require('./api-metrics').middleware); }
catch (e) { console.error('[startup] api-metrics not loaded:', e.message); }
// OBSERVABILITY layer 3: wrap the global fetch() that 56 modules in this tree
// use, so an upstream refusing us (a 429, an expired secret) is recorded rather
// than surfacing only as an inexplicably empty page.
try { require('./obs-dependency').install(); }
catch (e) { console.error('[startup] obs-dependency not installed:', e.message); }

const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT) || 3306,
  database:           process.env.DB_NAME,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:    10,
  charset:            'utf8mb4',
});

// The observability buffer flushes through this pool. Set as early as the pool
// exists so nothing recorded during startup is lost.
// initPool, not setPool(pool): the buffer flusher gets two connections of its
// own so it never queues behind application traffic -- and so that requiring
// obs-routes later cannot quietly move it onto the dashboard's pool, which is
// what used to happen.
let obsPool = null;
try {
  obsPool = require('./obs-lib').initPool();
} catch (e) {
  console.error('[startup] obs-lib pool not set:', e.message);
}

// The retention pruner runs from the HUB only. Both APIs share these tables via
// obs-lib, so starting it in both would have two processes deleting the same
// rows on the same schedule -- harmless but pointless, and it would make the
// job-run row ambiguous about which host actually pruned. Started here rather
// than inside obs-lib so that "who deletes rows" is answerable by reading a
// server file, not by inferring it from a library's side effects.
//
// Its own try/catch, and its own message: folding it into the one above meant a
// pruner that failed to start reported itself as "obs-lib pool not set", which
// is a different fault with a different fix.
try {
  if (obsPool) console.log('[startup] obs retention prune:',
    require('./obs-prune').start(obsPool) ? 'armed' : 'not armed');
} catch (e) {
  console.error('[startup] obs retention prune not started:', e.message);
}

// Apply the declared job registry from obs-jobs.json. Idempotent upsert, never
// deletes, never fatal: the API must boot even if its own telemetry config is
// broken. Logged either way, because a seeder that fails quietly leaves the
// observability page counting over a registry nobody knows is stale.
try {
  require('./obs-seed-jobs').seed(pool).then(function (r) {
    if (r.error) console.error('[startup] obs job registry:', r.error);
    console.log('[startup] obs job registry: ' + r.applied + '/' + r.declared + ' declared job(s) applied' +
      (r.unmanaged === null ? '; drift check did not run'
        : r.unmanaged.length ? '; ' + r.unmanaged.length + ' row(s) in the table are NOT in the manifest: ' + r.unmanaged.join(', ')
        : '') +
      ((r.clipped && r.clipped.length)
        ? '; note truncated for ' + r.clipped.join(', ') : ''));
  }).catch(function (e) { console.error('[startup] obs job registry failed:', e.message); });
} catch (e) { console.error('[startup] obs-seed-jobs not loaded:', e.message); }

// === ITAM-001 deny-by-default blanket (2026-08-08) ===
app.disable('x-powered-by');
const rbacGate = require('./rbac-middleware')(pool);
const API_PUBLIC = new Set([
  '/api/health',
  '/api/access-request/context',  // one-press access request: reads what the signed-in visitor was refused. Public
                                  // because the person the gate just refused must still be able to ask; the router
                                  // verifies the it_session cookie itself and answers 401 without one.
  '/api/access-request/file',     // files ONE Help Desk ticket. Self-authenticating plus a strict same-origin check.
  '/api/breakglass/status',
  '/api/breakglass/login',
  '/api/identity/portal-lookup',  // read-only AD profile lookup for access portal form pre-fill
  '/api/gate/check',              // nginx auth_request page gate — verifies the it_session
                                  // cookie by HMAC only. MUST stay public: routing it through
                                  // loadCurrentUser would make a directory hiccup lock out every
                                  // user except RBAC_SUPERADMINS (see gate-routes.js header).
  '/api/localdev/login',          // DEV sign-in — has its own rate limit, and is
                                  // inert unless LOCALDEV_ENABLED=1
  '/api/gate/refresh',            // re-issues a VALID it_session as the Domain cookie
                                  // (host-only -> .itam.nrpi.local migration for the
                                  // accessportal gate, 2026-08-24). Self-authenticating:
                                  // pure-HMAC verify inside, 401 otherwise — same posture
                                  // and same reason to stay public as /api/gate/check.
  '/api/gate/session-info',       // SESSION-WATCH 2026-09-04: reports the CALLER'S OWN
                                  // session lifetime (exp/iat/absolute cap) from its
                                  // it_session cookie. Public for the same reason as
                                  // /check: pure-HMAC verify inside, JSON 401 otherwise.
                                  // It must NOT go through loadCurrentUser - a directory
                                  // hiccup would 401 the countdown, and a countdown that
                                  // cannot measure is the failure this route exists to fix.
                                  // GET only, so the CSRF guard is not bypassed by it.
  '/api/gate/check-approver',     // tier-aware approver gate (session + tier2/superadmin).
                                  // Self-authenticating like /check; must bypass the RBAC
                                  // blanket so nginx auth_request can reach it.
  // [CORPIT-HUB-SSO] the sign-in front door. Public by necessity: these run
  // BEFORE the user has any credential, which is the whole point of them.
  // Each is self-authenticating -- /callback trusts nothing but a state+nonce it
  // minted itself plus a fully validated Entra id_token, and /accept trusts
  // nothing but a 60s audience-bound HMAC it can verify offline.
  '/api/auth/login',
  '/api/auth/callback',
  '/api/auth/accept',
  '/api/auth/status',
  '/api/auth/token',              // hands back the caller's OWN cookie token; 401 otherwise
  '/api/mpauth/login',            // MP-SIGNIN: My Profile's own sign-in, same reasoning as
  '/api/mpauth/callback',         // /api/auth/login + /callback above (mp-signin.js)
  '/api/gate/logout',             // clears the it_session cookie. Public by design: ending
                                  // your own session needs no credential, and it must work
                                  // even when the session is already invalid.
  '/api/gate/federated-logout',   // same teardown as /logout, then hands the browser to
                                  // Entra's logout endpoint so the Entra session ends too.
                                  // Public for the same reason and, more pointedly, because
                                  // its whole job is to run when the session should be gone:
                                  // gating it would make sign-out fail exactly when it has
                                  // already half-succeeded.
]);
// Internal cron/automation endpoints: allowed only with the shared CRON_TOKEN
// secret. Additive to the deny-by-default gate below; a missing/empty token or
// any path not in this set falls through to normal RBAC (fail-closed).
const API_CRON = new Set([
  '/api/endpoints-sync/sync',
  '/api/me-patch/sync-all',
  '/api/intune-crossref/sync',
  '/api/kandji-sync/sync',
  '/api/abm/sync',
  '/api/warranty/sync',
  '/api/intune-graph/sync',            // nightly full Graph refresh (added 2026-08-24)
  '/api/intune-graph/sync-to-devices', // step 2: push cache to intune_devices
]);
const CRON_TOKEN = process.env.CRON_TOKEN || '';
// Compared in constant time (CHG-ARCH-08): `===` on a secret returns at the
// first differing byte, which is measurable on the loopback path these
// endpoints exist for. See cron-token.js; an unset token disables the path.
const cronTokenOk = require('./cron-token')(CRON_TOKEN);
// M-1 (2026-09-06): the sync/action POSTs in API_CRON, plus /api/me-patch/scan
// (which forwards a caller-chosen resourceId to ManageEngine), are admin actions
// on the IT Inventory page -- every button that fires them lives in
// IT_Inventory_App.js -- yet until now any authenticated identity holding ZERO
// roles could fire them. A cron caller still passes above by x-cron-token; every
// other caller must hold 'it-inventory' admin, the same gate :3000 puts on that
// page's writes. Enforced here, at the blanket's choke point, for the same reason
// as the read-only clamp below: a per-route check rots the first time someone
// forgets one.
const API_SYNC_ADMIN = new Set([...API_CRON, '/api/me-patch/scan']);
const requireInventoryAdmin = rbacGate.requirePage('it-inventory', 'admin');
// Methods a read-only QA token may use. OPTIONS is included so CORS preflight
// still works; everything else falls through to the 403 below.
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
app.use('/api', function (req, res, next) {
  var p = req.originalUrl.split('?')[0].replace(/\/+$/, '') || '/';
  if (API_PUBLIC.has(p)) return next();
  // [CORPIT-QA 2026-09-07] Flag the request as cron-authorized. This next()s
  // straight into the router, so an in-module requirePage gate would then 403 a
  // valid cron caller -- there is no user session on this path. Modules that
  // gate their own sync POSTs branch on this flag rather than re-deriving the
  // token comparison, which would duplicate a secret check across N files.
  if (API_CRON.has(p) && cronTokenOk(req.get('x-cron-token'))) {
    req.cronAuthorized = true;
    return next();
  }
  return rbacGate.loadCurrentUser(req, res, function () {
    if (!req.user) {
      return res.status(401).json({ ok: false, error: 'AUTH_REQUIRED', detail: req.tokenError || 'NO_TOKEN' });
    }
    // ---------- CORPIT-CSRF (2026-09-02) ------------------------------------
    // loadCurrentUser now accepts the it_session cookie. A cookie is attached by
    // the browser automatically, so a cookie-authenticated state change is
    // forgeable from another origin; a bearer is not, because a cross-origin page
    // cannot read the token to set the header. So this guards ONLY the cookie
    // path -- every caller that works today keeps working unchanged.
    //
    // Do NOT lean on SameSite=Lax here. '.local' is not a public suffix, so the
    // browser treats subadmin/accessportal/directory/itam .nrpi.local as SAME-SITE
    // with corpit.nrpi.local and attaches the cookie to their cross-ORIGIN POSTs.
    // Lax blocks none of it. This check is therefore the load-bearing control, not
    // a belt-and-braces one, and it must compare ORIGIN (which differs on every one
    // of those hosts), never site. Placed at the same choke point as the read-only
    // clamp, for the same reason -- a per-route check rots the first time someone
    // forgets one.
    //
    // Two strengths, deliberately. A COOKIE-authenticated write must positively
    // prove same-origin: absent headers are refused, because a browser always
    // sends at least one of them and a non-browser client has no reason to
    // authenticate by cookie when it can send a bearer. A BEARER-authenticated
    // write is only refused when the browser explicitly says cross-site -- absent
    // headers pass, so curl, the QA harness and break-glass are untouched.
    //
    // The bearer arm matters for a second reason: step (3) is deferred, so
    // rbac-client.js still attaches a bearer to every fetch. Without it this guard
    // would ship completely unexercised and meet real traffic for the first time
    // only when the sessionStorage copy is finally removed.
    if (!READ_METHODS.has(req.method)) {
      var sfs = req.get('sec-fetch-site');          // sent by every current browser
      var org = req.get('origin');
      var verdict;
      if (sfs) {
        verdict = (sfs === 'same-origin') ? 'ok' : 'cross';
      } else if (org) {
        // ORIGIN-HOST-COMPARE
        // Compare HOST, not a rebuilt 'proto://host' string. X-Forwarded-Proto is set on
        // only 2 of the ~42 /api locations, so req.protocol is 'http' behind the proxy and
        // rebuilding the expected origin rejected legitimate same-origin requests (found
        // in QA, 2026-09-02). The platform is HTTPS-only -- port 80 301s to 443 -- so
        // requiring an https origin costs nothing and keeps the scheme check meaningful.
        var _oh = null;
        try { var _u = new URL(org); _oh = (_u.protocol === 'https:') ? _u.host.toLowerCase().replace(/:443$/, '') : null; } catch (e) { _oh = null; }
        var _hh = String(req.get('host') || '').toLowerCase().replace(/:443$/, '');
        verdict = (_oh && _oh === _hh) ? 'ok' : 'cross';
      } else {
        verdict = 'absent';
      }
      var csrfOk = (req.authVia === 'cookie') ? (verdict === 'ok') : (verdict !== 'cross');
      if (!csrfOk) {
        console.warn('[csrf-deny] ' + req.method + ' ' + p + ' via=' + req.authVia +
                     ' sec-fetch-site=' + (sfs || '-') + ' origin=' + (org || '-') +
                     ' user=' + (req.user && req.user.email));
        return res.status(403).json({ ok: false, error: 'CSRF_ORIGIN_REQUIRED',
          detail: 'A cookie-authenticated ' + req.method + ' must come from this origin. ' +
                  'Non-browser clients should send Authorization: Bearer instead.' });
      }
    }

    // Read-only QA tokens (2026-08-26). Enforced HERE, sharing the deny-by-default
    // blanket's choke point, so it covers every /api route including ones added
    // later — a per-route check would rot the first time someone forgot one.
    if (req.user.readOnly && !READ_METHODS.has(req.method)) {
      return res.status(403).json({ ok: false, error: 'READ_ONLY_TOKEN',
        detail: req.method + ' is not permitted with a read-only QA token.' });
    }
    // M-1: sync/action routes need 'it-inventory' admin. A cron-token caller never
    // reaches this line -- it passed above without a user -- so the cron path is
    // unchanged. 401/403 bodies come from requirePage, as on every other gated route.
    if (API_SYNC_ADMIN.has(p) && !READ_METHODS.has(req.method)) {
      return requireInventoryAdmin(req, res, next);
    }
    return next();
  });
});
// === end ITAM-001 blanket ===

// CORPIT-PLATFORM-VERSION (2026-09-02): single source of truth for the version
// shown in the sign-in footer. Read from /etc/corpit/VERSION with a 60s mtime-
// independent cache, so a deploy can bump the file WITHOUT restarting this
// process. Never throws: an unreadable or malformed file yields null and the
// footer then shows no version at all, rather than a stale or invented one.
// The strict semver test matters because this value is rendered on an
// anonymous page -- it is written with textContent, but validating server-side
// means a bad file can never put arbitrary text in front of a signed-out user.
const PLATFORM_VERSION_FILE = '/etc/corpit/VERSION';
let _pvCache = { at: 0, value: null };
function platformVersion() {
  const now = Date.now();
  if (_pvCache.at && (now - _pvCache.at) < 60000) return _pvCache.value;
  let v = null;
  try {
    const raw = require('fs').readFileSync(PLATFORM_VERSION_FILE, 'utf8').trim();
    if (/^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-[A-Za-z0-9.]{1,20})?$/.test(raw)) v = raw;
  } catch (e) { v = null; }
  _pvCache = { at: now, value: v };
  return v;
}

// CHG-ARCH-18: the hub performs no DDL. It checks the schema contract read-only at
// boot (schema/readiness.js) and reports it here; tables change only through
// migrate.js at deploy time. Detail stays in the log: this route is public.
const schemaReadiness = require('./schema/readiness');
schemaReadiness.start();

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', timestamp: new Date().toISOString(), version: platformVersion(), schema: schemaReadiness.summary() });
  } catch (e) {
    res.status(500).json({ status: 'error', message: e.message });
  }
});

async function auditLog(conn, tableName, recordId, action, oldVals, newVals) {
  try {
    await conn.execute(
      `INSERT INTO audit_log (table_name, record_id, action, old_values, new_values) VALUES (?, ?, ?, ?, ?)`,
      [tableName, recordId, action,
       oldVals ? JSON.stringify(oldVals) : null,
       newVals ? JSON.stringify(newVals) : null]
    );
  } catch (e) { console.error("[audit_log FAILED]", e.message, { tableName, recordId, action }); }
}

// [CORPIT-QA 2026-09-05] Removed the shadow inventory CRUD factory (const TABLES + the
// generated GET/POST/PUT/DELETE/import routes per table) and app.get('/api/dashboard').
// They duplicated the maintained copy in /var/www/api/server.js (:3000), which every
// served page reaches via nginx's /api/ catch-all. This :3001 copy had NO requirePage
// gate on its writes and its pool targets corpit_hub tables that diverge from the
// it_inventory tables the page uses. Reachable only via /hub-api/ (session-gated); no
// served page referenced it. auditLog() above is now unused; kept to minimise this diff.

const endpointsSyncRouter = require('./endpoints_sync');
app.use('/api/endpoints-sync', endpointsSyncRouter);

const intuneGraphRouter = require('./intune_graph');
app.use('/api/intune-graph', intuneGraphRouter);

const warrantyRouter = require('./warranty');
app.use('/api/warranty', warrantyRouter);

const kandjiSyncRouter = require('./kandji_sync');
app.use('/api/kandji-sync', kandjiSyncRouter);

const intuneCrossrefRouter = require('./intune_crossref');
app.use('/api/intune-crossref', intuneCrossrefRouter);

// Identity Diagnostic routes
const identityRoutes = require('./identity-routes');
app.use('/api/identity', identityRoutes);

const zscalerDiagRouter = require('./zscaler-diag-routes');
app.use('/api/zscaler', zscalerDiagRouter);
const zsnetRouter = require('./zsnet-routes');
app.use('/api/zsnet', zsnetRouter);

const spGovernance = require('./sharepoint-governance');
app.use('/api/sharepoint', spGovernance);
const dlpRoutes = require('./dlp-routes');
app.use('/api/dlp', dlpRoutes);
app.use('/api/files', require('./files-routes'));
app.use('/api/sharepoint-labels', require('./sp-label-routes'));
// [CORPIT-QA 2026-09-07] /api/tami unmounted. tami-routes.js proxies caller-
// supplied prompts to the Anthropic API on ANTHROPIC_API_KEY with NO page
// gate -- any authenticated identity could spend against it. It is dead
// code here: no served page, no nginx location and zero hits in the access
// logs reference it, and ANTHROPIC_API_KEY is not set on this host, so it
// answers 500 today. That last fact is why this is unmounted rather than
// gated: left in place it arms itself silently the day someone adds that
// variable for an unrelated reason. Gating it was rejected too -- there is
// no 'tami' row in rbac_pages, and an unlisted page key falls back to
// default_access, which would hand tier2 admin straight back. The file is
// retained on disk; restore by uncommenting this line AND adding a real
// rbac_pages row plus an in-module requirePage gate.
// app.use('/api/tami', require('./tami-routes'));
app.use('/api/user360', require('./user360-routes'));

const rapid7Router = require("./rapid7-lookup");
app.use("/api/rapid7", rapid7Router);

const provisioningRouter = require("./ad-provisioning");
app.use("/api/provisioning", provisioningRouter);

const userProjectRouter = require("./user-project-routes");
app.use("/api/user-project", userProjectRouter);

const housekeepingRouter = require("./housekeeping");
const fortinetRouter   = require("./fortinet-routes");
const merakiRouter     = require("./meraki-routes");
app.use("/api/housekeeping", housekeepingRouter);
app.use("/api/fortinet",    fortinetRouter);
app.use("/internal/department-principal", require("./department-access-routes").principal(pool));
app.use("/api/department-access", require("./department-access-routes")(pool));
app.use("/api/gate",        require("./gate-routes"));
app.use("/api/auth",        require("./oidc-auth"));      // [CORPIT-HUB-SSO] OIDC code+PKCE sign-in   // ITAM-01 page gate (pure crypto)
app.use("/api/mpauth",      require("./mp-signin"));      // MP-SIGNIN: My Profile sign-in (host-scoped session)

// Loopback-only Graph sendMail relay for the Access Portal (app.py on :8001).
// Ported from itam 2026-09-08. NOT under /api/ on purpose, so the /api blanket
// (deny-by-default, CSRF, read-only clamp) never applies to it. What keeps it
// off the vhosts is nginx: corpit's broad /hub-api/ proxy strips its prefix and
// used to forward /hub-api/internal/* here, so corpit.nrpi.local.conf refuses
// that path with a 404 (CHG-ARCH-05), and the relay itself refuses anything
// that arrived through a proxy hop (isLoopback: socket AND req.ip must be
// loopback). Holds no secret of its own - it reuses AZURE_*.
app.use("/internal/portal-mail", require("./portal-mail-relay"));
// Loopback-only directory lookup for the same portal: requester + manager
// (name/email/Entra id) for the public requester form. Reads the reporting tree
// My Profile already keeps (org-tree-lib), Graph only as the new-hire fallback.
// Same posture as the mail relay: /internal/*, X-Portal-Lookup-Key, audit log.
app.use("/internal/portal-lookup", require("./portal-lookup-relay")(pool));
// netdiag/netswitch build their gate from deps.requirePage; mounting them with NO
// deps silently degraded that gate to a pass-through next(), so any authenticated
// user reached /api/netdiag/resolve (the WinRM PowerShell sink). Wire it properly.
app.use("/api/netdiag",     require("./netdiag")({ requirePage: rbacGate.requirePage }));   // Network Diagnostics (FortiGate Irvine + Dallas)
app.use("/api/netswitch",   require("./netswitch")({ requirePage: rbacGate.requirePage }));   // Switch fleet inventory (SNMP RO cache)
app.use("/api/confreview",  require("./confreview-routes"));   // Read-only switch + firewall configuration review
app.use("/api/meraki",      merakiRouter);
const sdpRouter = require("./sdp-routes");
app.use("/api/sdp", sdpRouter);
// SIGNIN-WATCH mount (2026-08-10)
app.use("/api/signin-watch", require("./signin-watch-routes"));
const sdopsRouter = require('./sdops-routes');
app.use('/api/sdops', sdopsRouter);
const sentinelRouter = require('./sentinel-routes');
app.use('/api/sentinel', sentinelRouter);
// Okta -> Entra migration workspace. oem-work-routes (discovery, matching, work queue, jobs,
// Okta lifecycle) mounts first; oem-routes keeps the policy/SIPA/zone routes. Both under /api/oem.
app.use("/api/oem/v2", require("./oem-v2-routes"));
app.use('/api/oem/migrate', require('./oem-migrate-routes'));   // application migration engine (scan/assess/plan/push)
app.use('/api/oem/ca', require('./oem-ca-compare'));           // Conditional Access: read-only Okta rule ↔ Entra policy comparison
app.use('/api/oem/ca', require('./oem-ca-push'));              // Conditional Access: staged create/amend (draft → approve → push → verify → rollback)
app.use('/api/oem', require('./oem-work-routes'));
app.use('/api/oem', require('./oem-routes'));

const insightsRouter = require('./insights-routes');
app.use('/api/insights', insightsRouter);
app.use('/api/claude-analytics', require('./claude-analytics-routes'));
const mePatchRouter = require("./me-patch-actions");
app.use("/api/me-patch", mePatchRouter);

// Device security posture — encryption + missing patches (landing page KPIs)
app.use("/api/device-posture", require("./device-posture-routes"));

// Okta tenant view — user status, MFA factor enrolment and the application
// inventory, read from the corpit_hub mirrors. Read-only: no Okta API call and
// no write path. Gated on the helpdesk-okta page key.
app.use("/api/okta", require("./okta-routes"));

// Vendor service status (statuspage.io feeds, proxied server-side so the page stays
// CSP-clean under connect-src 'self'). Auth-only via the blanket /api gate above.
app.use("/api/service-status", require("./service-status-routes"));
// [CORPIT-QA 2026-09-07] /api/tenant-health unmounted. Its 5 probes had no page
// authorization and no consumer: nothing in /var/www/html references them, and
// the Operations Hub panel the module was written for was never built here.
// The routes are now gated on 'server-health' read inside the module, so
// remounting is just uncommenting this line. service-status-routes.js is in
// the same position (1 route, no consumer) but is left mounted for now -- it
// is reported, not changed, because it proxies only vendors' own public
// status pages and leaks nothing about this tenant.
// REMOUNTED 2026-09-08: the consumer now exists. The Operations Hub Environment
// status strip on /landing.html renders one row per probe, and the gate the
// 09-07 note asked for is already inside the module (server-health read, blanket).
app.use("/api/tenant-health", require("./tenant-health-routes"));   // per-tenant vendor probes (Okta, ZIA, Entra, Intune, IRU)

// Local conditions for the Operations Hub hero. Server-side so the page stays
// CSP-clean and no user IP reaches the vendor; returns ok:false rather than a
// fabricated reading when the upstream is unreachable. Auth-only, no page RBAC.
app.use("/api/weather", require("./weather-routes"));
const gpoAuditRouter = require("./gpo-audit");
app.use("/api/gpo", gpoAuditRouter);

const entraRouter = require("./entra-routes");
app.use("/api/entra", entraRouter);
const abmRouter = require("./abm-routes");
app.use("/api/abm", abmRouter);

// Profile photo proxy with disk cache (Microsoft Graph)
const photoRouter = require("./photo-route");
app.use("/api/photo", photoRouter);
app.use("/api/bugs", require("./bug-reports-routes"));
// MY-PROFILE (2026-09-05): self-scoped technician profile API. Sits behind the deny-by-default
// blanket above (loadCurrentUser + CSRF); the router only ever reads req.user.email.
app.use("/api/profile", require("./profile-routes"));
// ACCESS-REQUEST (2026-10-09): one-press "request access" for the site / page denial screens. Public in API_PUBLIC
// above; the router authenticates the it_session cookie itself. A load failure must not take the hub down.
try { app.use('/api/access-request', require('./access-request-routes').create({ pool })); }
catch (e) { console.error('[startup] FAILED to mount /api/access-request:', e.message); }

// RBAC Phase 1 (added 2026-05-05)
const rbacRoutes = require('./rbac-routes');
app.use('/api/rbac', rbacRoutes);

// Local DEV/test sign-in. Inert unless LOCALDEV_ENABLED=1 is set in .env —
// the module refuses to mint or verify a token without it.
try {
  app.use('/api/localdev', require('./localdev-routes'));
  console.log('[startup] /api/localdev mounted (enabled=' +
    (process.env.LOCALDEV_ENABLED === '1') + ')');
} catch (e) {
  console.error('[startup] /api/localdev FAILED to mount:', e.message);
}

// /api/backup-admin removed 2026-09-06: it wrapped ITAM's it-command-backup tool, which does
// not exist on this host (every call failed). The backup here is corpit-db-backup.timer; the
// console surface is system-health /backups + system-actions /backup/run.
try {
  const breakglassRoutes = require('./breakglass-routes');
  app.use('/api/breakglass', breakglassRoutes);
  console.log('[startup] /api/breakglass mounted');
} catch (e) {
  console.error('[startup] FAILED to mount /api/breakglass:', e.message);
}
try {
  const saasAdminRoutes = require('./saas-admin-routes');
  app.use('/api/saas-admin', saasAdminRoutes);
  console.log('[startup] /api/saas-admin mounted');
} catch (e) {
  console.error('[startup] FAILED to mount /api/saas-admin:', e.message);
}

// --- System Health (self-host CPU/RAM/Disk/Patch) ---
try {
  const systemHealthRoutes = require('./system-health-routes');
  app.use('/api/system', systemHealthRoutes);
  console.log('[startup] /api/system mounted');
} catch (e) {
  console.error('[startup] FAILED to mount /api/system:', e.message);
}

// --- System Actions (maintenance: pm2/apt/journal/backup/reboot) ---
try {
  const systemActionsRoutes = require('./system-actions-routes');
  app.use('/api/system', systemActionsRoutes);
  console.log('[startup] /api/system actions mounted');
} catch (e) {
  console.error('[startup] FAILED to mount system-actions:', e.message);
}

// --- Server Health & Maintenance dashboard (registry-driven host monitoring) ---
// Mounted last on /api/system so its paths resolve after the existing health
// and action routes. Read routes require a server-health 'read' grant; every
// mutation requires 'admin'.
try {
  const srvDashboardRoutes = require('./srv-dashboard-routes');
  app.use('/api/system', srvDashboardRoutes);
  console.log('[startup] /api/system dashboard mounted');
} catch (e) {
  console.error('[startup] FAILED to mount srv-dashboard:', e.message);
}

// --- A/B cluster health (Health Center page) -------------------------------
// Read-only summary of this node's DRBD/Pacemaker status file. Gated on the
// 'server-health' read grant, same as every other /api/system read.
try {
  app.use('/api/system', require('./ha-cluster-routes').router);
  console.log('[startup] /api/system cluster mounted');
} catch (e) {
  console.error('[startup] FAILED to mount /api/system cluster:', e.message);
}

// --- Access Portal journey log (Health Center page) ---------------------------
// Read-only relay to the portal backend's own 90-day journey log. Super-admins
// only, per route; each one-person lookup writes its own audit row.
try {
  app.use('/api/system/portal-journey', require('./portal-journey-routes').router);
  console.log('[startup] /api/system/portal-journey mounted');
} catch (e) {
  console.error('[startup] FAILED to mount /api/system/portal-journey:', e.message);
}

// --- Feed freshness ---------------------------------------------------------
// Reports, per collected feed, how old the newest row is against the cadence the
// feed is meant to keep. Mounted on its own path, NOT /api/system: that router
// gates every path beneath it on a 'server-health' read grant, and a user of
// Identity Diagnostics or SharePoint Governance needs to be able to learn that
// their own page's data has stopped advancing.
try {
  const feedFreshnessRoutes = require('./feed-freshness-routes');
  app.use('/api/feeds', feedFreshnessRoutes);
  console.log('[startup] /api/feeds mounted');
} catch (e) {
  console.error('[startup] FAILED to mount /api/feeds:', e.message);
}

// --- Observability -----------------------------------------------------------
// POST /api/observe/client is the browser beacon and needs only a session: every
// page must be able to report its own failure, including pages whose users have
// no grant on the dashboard. The GET panels aggregate across every page and user,
// so they require the 'observability' page grant, enforced inside the router.
try {
  app.use('/api/observe', require('./obs-routes'));
  console.log('[startup] /api/observe mounted');
} catch (e) {
  console.error('[startup] FAILED to mount /api/observe:', e.message);
}

// Scheduler ticks moved to the dedicated syncs-worker pm2 process
// (see /var/www/corpit-hub-api/syncs-worker.js) so heavy Entra/Okta syncs
// no longer block user-facing endpoints on this event loop.
// entra-sync and okta-sync are still required by other modules
// (entra-routes, photo-route, okta-sync <- entra-sync); only the
// scheduler ticks were relocated.
require("./okta-sync"); // ensure module is loadable (side-effect free)


// ---------- BODY ERRORS (CHG-ARCH-08) ----------------------------------------
// body-parser rejects an oversized, malformed or mis-encoded body by calling
// next(err). With no handler here, Express's default answered with an HTML page
// that -- NODE_ENV being unset -- carried the stack trace and this file's path.
// Every client of this API speaks JSON, so answer the way the deny blanket
// does, and leave anything that is not a body error to the default handler.
app.use(function (err, req, res, next) {
  if (err && err.type && err.status >= 400 && err.status < 500 && !res.headersSent) {
    return res.status(err.status).json({
      ok: false,
      error: err.type === 'entity.too.large' ? 'BODY_TOO_LARGE' : 'BAD_BODY',
      detail: err.message,
    });
  }
  return next(err);
});

// CHG-ARCH-20: keep the handle so a stop can stop accepting and drain (drain.js).
require('./drain').attach(app.listen(PORT, '127.0.0.1', () => {
  console.log(`corpit-hub-api listening on 127.0.0.1:${PORT}`);
}), [pool]);
