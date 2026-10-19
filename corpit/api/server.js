require('dotenv').config();
const express = require('express');
const mysql   = require('mysql2/promise');
const cors    = require('cors');
const rateLimit = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3000;

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

// OBS-CORE-10. This process had no SIGTERM handler at all, so pm2's stop went
// straight to Node's default exit and the recorder's buffer -- up to one flush
// window of requests -- was discarded on every restart without being counted.
// Exit on a timer regardless: a stop must never wait on the recorder, and pm2
// SIGKILLs at 1600 ms.
// Both signals: pm2 7 stops a process with SIGINT, so a SIGTERM-only handler
// never runs at all (proved on the hub API -- 32 startups, 0 stop records).
// CHG-ARCH-20: the stop now drains in-flight requests (8 s), closes pool + rbacPool and
// flushes (drain.js); a signal before the server is listening keeps the 1.2 s flush-then-exit.
['SIGINT', 'SIGTERM'].forEach(function (sig) {
  process.on(sig, function () { require('./drain').begin(sig, null); });
});
// CHG-ARCH-20: while draining, /api/health answers 503 and responses carry Connection: close.
app.use(require('./drain').middleware);
// ---------- BODY PARSING (CHG-ARCH-08, 2026-09-23) ---------------------------
// One 1 MB JSON parser for every route. Until now a single 50 MB parser sat
// here, ahead of loadCurrentUser and the deny blanket, so an anonymous POST to
// any /api/* path made this process buffer and JSON.parse up to 50 MB before it
// was told 401 -- and nginx passes 50m on /api/, so any browser could do it. A
// body over 1 MB is already an anomaly for a single inventory row. The two
// import routes take up to 50 MB, but only after their admin gate has passed
// (jsonImportBody, below), and the cert-watchtower check-in keeps the 5 MB
// parser it declares behind its bearer token -- a route-level parser is a no-op
// once a global one has run, so this skip is what makes that one effective. A
// body limit is part of a route's contract and belongs next to the route.
const IMPORT_PATH = /^\/api\/[^/]+\/import\/(append|bulk)$/;
const SELF_PARSED = new Set(['/api/agents/checkin']);
const jsonBody       = express.json({ limit: '1mb' });
const jsonImportBody = express.json({ limit: '50mb' });
app.use(function (req, res, next) {
  const p = req.path.replace(/\/+$/, '') || '/';
  if (IMPORT_PATH.test(p) || SELF_PARSED.has(p)) return next();
  return jsonBody(req, res, next);
});
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
// ---------- RATE-LIMIT-KEY (2026-09-04) ------------------------------------
// Was: rateLimit({...}) with no keyGenerator. It keys on req.ip, and since :3000
// listens on loopback behind nginx, req.ip is 127.0.0.1 for EVERY caller — so the
// 500/min quota was ONE GLOBAL BUCKET shared by the entire platform, not a
// per-user limit. Measured: request #501 got a 429. At ~11 API calls per page
// load that capped the WHOLE platform at ~45 page loads a minute, and no amount
// of CPU or RAM could raise it.
//
// Deliberately NOT fixed with app.set('trust proxy'): that makes Express derive
// req.ip from X-Forwarded-For, and nginx does not set that header on the /api/
// locations (only /hub-api/ does). Enabling it would have Express trust a header
// nothing overwrites, letting any caller send X-Forwarded-For: <anything> to mint
// a fresh bucket per fake value — evading the limit entirely.
//
// So: key on inputs the proxy actually controls.
//   u:<hash>  a signed-in user, from the it_session cookie (hashed, never raw).
//             Better than per-IP here because users arrive via ZPA and can share
//             an egress address.
//   i:<addr>  X-Real-IP, which nginx sets with proxy_set_header and therefore
//             REPLACES any client-supplied value, so it cannot be spoofed.
//   i:<req.ip> last resort.
// Prefixes keep user and IP buckets from ever colliding.
//
// max stays 500 — it now means 500/min PER CALLER, not 500/min for everyone.
const _rlCrypto = require('crypto');
function rateLimitKey(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)it_session=([^;]*)/);
  if (m && m[1]) {
    return 'u:' + _rlCrypto.createHash('sha256').update(m[1]).digest('hex').slice(0, 32);
  }
  const xri = req.headers['x-real-ip'];
  if (xri) return 'i:' + String(xri).split(',')[0].trim();
  return 'i:' + (req.ip || 'unknown');
}
app.use(rateLimit({
  windowMs: 60_000,
  max: 500,
  standardHeaders: true,
  keyGenerator: rateLimitKey,
  // No validate override: with a custom keyGenerator express-rate-limit 7.5.x never
  // inspects req.ip, and the key this used to pass (keyGeneratorIpFallback) is an
  // 8.x option — on 7.5.1 it only logged ERR_ERL_UNKNOWN_VALIDATION at every start.
}));

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

// ---- RBAC enforcement (Slice 1: IT Inventory) ----
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT) || 3306,
  database: 'corpit_hub',
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:    5,
});
// ---- observability (layers 3 and 4) ---------------------------------
// The three obs-* modules are SYMLINKS to /var/www/corpit-hub-api, the same
// arrangement as rbac-middleware.js above: one implementation, two processes.
// The consequence to remember is the one that has bitten this host before --
// editing an obs-* file and restarting ONLY corpit-hub-api leaves THIS process
// running the old code. Restart both:
//     corpit-pm2 restart corpit-hub-api it-inventory-api
//
// obs opens its own two connections to corpit_hub (initPool below) with the
// credentials this process already holds, so no new secret is introduced. It
// used to share rbacPool -- the 5-connection pool that authenticates EVERY
// request here. Sharing meant a slow obs INSERT was a slow sign-in, which is
// the observability system degrading the thing it observes.
//
// OBS_APP=core-api in this app's .env is what separates these rows from the hub
// API's on the dashboard. The actor hash uses RBAC_SESSION_SECRET, which both
// processes already share, so one person is one actor_key across both apps.
//
// The tunables come from the console (/etc/corpit/observability.json), read by
// obs-lib on a 30s poll -- so one console switch governs both processes.
try { require('./obs-lib').initPool(); }
catch (e) { console.error('[startup] obs-lib pool not set:', e.message); }
try { require('./obs-dependency').install(); }
catch (e) { console.error('[startup] obs-dependency not installed:', e.message); }
// ---------------------------------------------------------------------

const rbac = createRbac(rbacPool);
app.use(rbac.loadCurrentUser);
// ---------------------------------------------------------------------

// === ITAM-01 deny-by-default (ENFORCED) ===============================
// Mirrors the enforced blanket already live on api-beta (:3001 server.js:25-41).
// Anonymous /api access is DENIED, unconditionally: a request that is not on
// the API_PUBLIC allowlist, carries no valid bearer, and carries no valid
// it_session cookie gets 401. Enforced since 2026-08-24 (ITAM-RT-01).
// The ENFORCE_DENY flag that used to gate this was deleted 2026-09-03: it had
// been a hardcoded `true` for months, which made the last line of the blanket
// unreachable while this header still described the retired Stage-1 DRY-RUN
// ("never blocks — only logs"). A guard rail that misdescribes the posture is
// worse than no comment at all; anyone auditing auth read the opposite of the
// truth. loadCurrentUser (above) has already set req.user or null.
// Kept HERE in server.js, not in the symlinked rbac-middleware.js (shared
// with :3001). Machine paths that carry no user identity are allowlisted.
const API_PUBLIC = new Set([
  '/api/health',          // liveness probe
  '/api/agents/checkin',  // cert-watchtower agents: requireAgentToken bearer, no req.user
]);
// Core API auth must accept the SAME credential the page gate uses. Pages are gated on the signed
// it_session COOKIE (nginx auth_request -> api-beta gate-routes). loadCurrentUser above only reads
// the Authorization BEARER header, so a user with a valid session cookie but no live sessionStorage
// bearer 401s on every data call (observed 2026-08-24). So allow if req.user (bearer) OR a valid
// it_session cookie, verified with the exact pure-crypto verifiers the gate uses (HMAC over the
// shared RBAC_SESSION_SECRET; no DB/LDAP). Loaded defensively so a module hiccup can't crash :3000.
let _sessAuth = null, _bgAuth = null, _ldAuth = null;
try { _sessAuth = require('/var/www/corpit-hub-api/session-auth'); } catch (e) { console.warn('[rt01] session-auth load failed:', e.message); }
try { _bgAuth   = require('/var/www/corpit-hub-api/breakglass-auth'); } catch (e) { console.warn('[rt01] breakglass-auth load failed:', e.message); }
try { _ldAuth   = require('/var/www/corpit-hub-api/localdev-auth'); } catch (e) { console.warn('[rt01] localdev-auth load failed:', e.message); }
function _itSessionOk(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)it_session=([^;]*)/);
  if (!m) return false;
  const t = decodeURIComponent(m[1]);
  // AUDIT-IDENTITY (2026-09-03): keep the verified subject. Both verifiers already
  // return {ok, email, name}; this used to be thrown away, so a cookie-authenticated
  // request wrote audit rows with no actor. NOT req.user on purpose - that drives
  // rbac.requirePage(), and filling it from a cookie would change authorization
  // rather than logging. Read only by auditActor().
  try { if (_sessAuth) { const r = _sessAuth.verifySessionToken(t); if (r && r.ok) { req._sessionIdentity = r.email || null; return true; } } } catch (e) {}
  try { if (_bgAuth)   { const r = _bgAuth.verifySessionToken(t);   if (r && r.ok) { req._sessionIdentity = r.email || null; return true; } } } catch (e) {}
  // Read-only QA tokens (2026-08-26): remember the claim so the blanket below can
  // refuse mutations. localdev is currently OFF on :3000 (no LOCALDEV_ENABLED in
  // this .env), so this is inert today — it exists so that turning localdev on here
  // later cannot silently make "read-only" stop meaning read-only.
  try { if (_ldAuth)   { const r = _ldAuth.verifyToken(t);          if (r && r.ok) { req._roToken = !!r.readOnly; req._sessionIdentity = r.email || null; return true; } } } catch (e) {}
  return false;
}
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
function _roDenied(req, res) {
  return res.status(403).json({ ok: false, error: 'READ_ONLY_TOKEN',
    detail: req.method + ' is not permitted with a read-only QA token.' });
}
// ---------- CORPIT-CSRF (2026-09-02) --------------------------------------
// rbac-middleware.js (a SYMLINK to /var/www/corpit-hub-api/) now accepts the
// it_session cookie as a credential, and this process calls loadCurrentUser
// globally -- so cookie-authenticated writes became reachable here too, via the
// corpit vhost's `location /api/` catch-all. Same rule as :3001.
//
// Do NOT lean on SameSite=Lax: '.local' is not a public suffix, so every
// *.nrpi.local host is SAME-SITE with corpit and Lax attaches the cookie to
// their cross-ORIGIN writes. Compare ORIGIN, never site.
//
// Called from inside the ALLOW branches only. CSRF is about a request that would
// otherwise succeed; running it earlier would turn an anonymous POST's 401 into
// a 403 and diverge from :3001 for no benefit.
function _csrfDenied(req, res) {
  if (READ_METHODS.has(req.method)) return false;
  const sfs = req.get('sec-fetch-site');
  const org = req.get('origin');
  let verdict;
  if (sfs) verdict = (sfs === 'same-origin') ? 'ok' : 'cross';
  else if (org) {
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
  }
  else verdict = 'absent';
  // A cookie-authenticated write must PROVE same-origin (absent headers are
  // refused: a browser always sends one, and a non-browser client should be
  // using a bearer). A bearer-authenticated write is refused only on an explicit
  // cross-site claim, so agent check-ins, cron and curl are untouched.
  const byCookie = (req.authVia === 'cookie') || !req.headers.authorization;
  if (byCookie ? (verdict === 'ok') : (verdict !== 'cross')) return false;
  console.warn('[csrf-deny:3000] ' + req.method + ' ' + req.originalUrl.split('?')[0] +
               ' via=' + (req.authVia || '-') + ' sec-fetch-site=' + (sfs || '-') +
               ' origin=' + (org || '-'));
  res.status(403).json({ ok: false, error: 'CSRF_ORIGIN_REQUIRED',
    detail: 'A cookie-authenticated ' + req.method + ' must come from this origin. ' +
            'Non-browser clients should send Authorization: Bearer instead.' });
  return true;
}

app.use('/api', function (req, res, next) {
  const p = (req.originalUrl.split('?')[0]).replace(/\/+$/, '') || '/';
  if (API_PUBLIC.has(p)) return next();
  if (req.user) {
    if (_csrfDenied(req, res)) return;
    if (req.user.readOnly && !READ_METHODS.has(req.method)) return _roDenied(req, res);
    return next();
  }
  if (_itSessionOk(req)) {
    if (_csrfDenied(req, res)) return;
    if (req._roToken && !READ_METHODS.has(req.method)) return _roDenied(req, res);
    return next();
  }
  // Nothing authenticated this request: deny. There is deliberately no branch
  // here — the fall-through `return next()` that used to sit below was
  // unreachable (ENFORCE_DENY was a const true) and is gone with the flag.
  console.warn('[deny-enforce] ' + req.method + ' ' + p +
    ' hasBearer=' + (!!req.headers.authorization) +
    ' hasCookie=' + /(?:^|;\s*)it_session=/.test(req.headers.cookie || '') +
    ' ip=' + (auditIp(req) || '?'));   // CHG-ARCH-08: was req.ip, which is 127.0.0.1 behind nginx
  return res.status(401).json({ ok: false, error: 'AUTH_REQUIRED', detail: req.tokenError || 'NO_TOKEN' });
});
// === end ITAM-01 deny-by-default (ENFORCED) ===========================

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

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', timestamp: new Date().toISOString(), version: platformVersion() });
  } catch (e) {
    res.status(500).json({ status: 'error', message: e.message });
  }
});

// AUDIT-ACTOR (2026-09-03): the trail recorded WHAT changed and never WHO or from
// where — on the company's asset system of record. Both facts were already on the
// request and simply never written: req.user is populated by rbac.loadCurrentUser
// for every authenticated call, and nginx sets X-Real-IP on both /api/ proxy blocks.
//
// The richer INSERT is attempted FIRST and falls back to the original five-column
// INSERT when it fails, because those columns may not exist on this deployment yet.
// Until the operator applies the ALTER, every write takes the fallback path and the
// log is exactly what it was before — degraded, never broken:
//   ALTER TABLE audit_log
//     ADD COLUMN actor      VARCHAR(255) NULL AFTER action,
//     ADD COLUMN actor_ip   VARCHAR(45)  NULL AFTER actor,
//     ADD COLUMN user_agent VARCHAR(255) NULL AFTER actor_ip;
//
// Returns true only when a row was actually written, so a caller that must not let a
// mutation pass unlogged (import/bulk) can say so out loud.
function auditActor(req) {
  const u = (req && req.user) || null;
  if (u) {
    // The identity field varies by credential path in rbac-middleware, so take the
    // first that resolves.
    const id = u.email || u.user_email || u.upn || u.username || u.name || null;
    if (id) return id;
  }
  // Cookie-authenticated request: req.user is never set on that path (loadCurrentUser
  // reads only the bearer), so use the subject captured from the session token that
  // _itSessionOk already verified. See AUDIT-IDENTITY above.
  // null stays honest — never invent an actor.
  return (req && req._sessionIdentity) || null;
}

function auditIp(req) {
  if (!req) return null;
  // X-Real-IP is set with proxy_set_header on both /api/ locations, which REPLACES
  // any client-supplied value. req.ip is 127.0.0.1 here (no trust proxy is set, and
  // :3000 listens on loopback only), so it is the fallback, not the source.
  const xri = req.headers && req.headers['x-real-ip'];
  if (xri) return String(xri).split(',')[0].trim();
  return req.ip || (req.socket && req.socket.remoteAddress) || null;
}

async function auditLog(conn, tableName, recordId, action, oldVals, newVals, req) {
  const oldJson = oldVals ? JSON.stringify(oldVals) : null;
  const newJson = newVals ? JSON.stringify(newVals) : null;
  const actor   = auditActor(req);
  const actorIp = auditIp(req);
  const ua      = (req && typeof req.get === 'function' && req.get('user-agent'))
    ? String(req.get('user-agent')).slice(0, 255) : null;
  try {
    await conn.execute(
      `INSERT INTO audit_log (table_name, record_id, action, old_values, new_values, actor_email, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [tableName, recordId, action, oldJson, newJson, actor, actorIp, ua]
    );
    return true;
  } catch (e) {
    // Unknown column => the ALTER above has not been applied on this host yet. Fall
    // through to the original insert so the row is still written, but say so: a
    // missing actor column should be visible, not silent.
    console.warn("[audit_log actor columns unavailable]", e.code || e.message, "— using 5-column insert");
  }
  try {
    await conn.execute(
      `INSERT INTO audit_log (table_name, record_id, action, old_values, new_values) VALUES (?, ?, ?, ?, ?)`,
      [tableName, recordId, action, oldJson, newJson]
    );
    return true;
  } catch (e) { console.error("[audit_log FAILED]", e.message, { tableName, recordId, action, actor }); }
  return false;
}

const TABLES = {
  employees: {
    table: 'active_employees',
    columns: {
      'Worker ID':'worker_id','Status':'status','Employee Name':'employee_name',
      'First/Last':'first_last','Business Email':'business_email','Username':'username',
      'Job Name':'job_name','Business Title':'business_title','Manager Name':'manager_name',
      'Functional Leader':'functional_leader','Department':'department','Pay Class':'pay_class',
      'Location Name':'location_name','Work Assignment Is Virtual':'is_virtual','Hire Date':'hire_date',
      'Desktop/Laptop':'device_laptop','MacBook':'device_macbook','AWS Workspace':'device_aws',
      'iPhone':'device_iphone','Tablet':'device_tablet','iPad':'device_ipad',
    }
  },
  terms: {
    table: 'terminated_employees',
    columns: {
      'Worker ID':'worker_id','Status':'status','Employee Name':'employee_name',
      'First/Last':'first_last','Business Email':'business_email','Job Name':'job_name',
      'Department':'department','Location Name':'location_name','Pay Class':'pay_class',
      'Termination Date':'termination_date','Functional Leader':'functional_leader',
      'Is Termination Reason':'is_termination_reason',
    }
  },
  intune: {
    table: 'intune_devices',
    columns: {
      'Device ID':'device_id','Device name':'device_name','Ownership':'ownership',
      'Compliance':'compliance','OS':'os','OS version':'os_version',
      'Primary user UPN':'primary_user_upn','Last check-in':'last_checkin','Model':'model',
      'Serial number':'serial_number','Phone number':'phone_number',
      'Primary user display name':'primary_user_name','Subscriber carrier':'subscriber_carrier',
      'device_source':'device_source','device_category':'device_category','IMEI':'imei',
      'is_historical':'is_historical','la_device_id':'la_device_id','la_state':'la_state','la_regional':'la_regional','la_active':'la_active','Carrier':'carrier',
    }
  },
  macbooks: {
    table: 'macbooks',
    columns: {
      'Device Name':'device_name','Model':'model','Chip':'chip','OS Version':'os_version',
      'Serial':'serial','Blueprint':'blueprint','User':'user_name','Checked In':'checked_in',
    }
  },
  endpoints: {
    table: 'endpoints',
    columns: {
      'Computer Name':'computer_name','Device Model':'device_model','Computer Type':'computer_type',
      'Currently Logged on Users':'logged_on_user','First/Last':'first_last',
      'Last Successful Asset Scan':'last_asset_scan','Service Tag':'service_tag','OS Name':'os_name','OS Version':'os_version',
    }
  },
  liveauction: {
    table: 'live_auction_devices',
    columns: {
      'Device Type':'device_type','Device ID1':'device_id1','Phone number':'phone_number',
      'IMEI':'imei','Tmobile':'carrier_tmobile','Verizon':'carrier_verizon',
      'Assigned To':'assigned_to','First/Last':'first_last','Employee Active':'employee_active',
      'Employee Termed':'employee_termed','Model':'model','EID':'eid','State':'state',
      'Regional':'regional','Active/Inactive':'active_inactive','OS':'os',
    }
  },
  tmobile: {
    table: 'tmobile_lines',
    columns: {
      'Phone Number':'line','User':'first_last_name','Email':'email_address',
      'Department':'cost_center','Device':'device_type','Status':'line_status',
      'IMEI':'imei','Intune Registered':'intune_registered',
      'Intune Compliance':'intune_compliance',
    }
  },
  verizon: {
    table: 'verizon_lines',
    columns: {
      'Phone number':'phone_number','Username':'username','Department':'department',
      'Functional Leader':'functional_leader','Equipment Model':'equipment_model','IMEI':'imei',
      'Service Status':'service_status','Device Type':'device_type',
    }
  },
  ipads: {
    table: 'ipad_devices',
    columns: {
      'Device ID':'device_id','Device Name':'device_name','Model':'model',
      'OS Version':'os_version','Serial':'serial','Blueprint':'blueprint',
      'User':'user_name','Checked In':'checked_in',
      'Is Missing':'is_missing','MDM Enabled':'mdm_enabled',
    }
  },
  aws: {
    table: 'aws_workspaces',
    columns: {
      'WorkSpace ID':'workspace_id','Username':'username','First/Last':'first_last',
      'Compute':'compute','Root volume':'root_volume','User volume':'user_volume',
      'Operating system':'operating_system','Standby enabled':'standby_enabled',
      'Running mode':'running_mode','Protocol':'protocol','Status':'status',
    }
  },
};

// ROW-CAP + REVERSED-COLMAP helpers (2026-09-03) ------------------------------
// clampRowLimit / clampRowOffset: the list route below defaulted to `limit = 2000`
// with no upper bound, so `?limit=999999` was honoured and any table that outgrew
// 2000 rows was silently truncated to the 2000 NEWEST ids — ORDER BY id DESC drops
// the OLDEST, which is exactly the terminated employees and aged endpoints the
// Lifecycle and Warranty pages exist to surface. The default is deliberately
// UNCHANGED: every current caller sends no limit at all and must keep getting the
// same page. What changes is that the value is bounded and the true total is
// reported in X-Total-Count, so a truncated response is DETECTABLE. A silent cap
// at any number has the same failure mode.
const DEFAULT_ROW_LIMIT = 2000;
const MAX_ROW_LIMIT     = 20000;   // a bound on abuse, not a page size
function clampRowLimit(v) {
  // A duplicated query param arrives as an array; take the last, never parseInt an array.
  const n = parseInt(Array.isArray(v) ? v[v.length - 1] : v, 10);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_ROW_LIMIT;
  return Math.min(n, MAX_ROW_LIMIT);
}
function clampRowOffset(v) {
  const n = parseInt(Array.isArray(v) ? v[v.length - 1] : v, 10);
  if (!Number.isFinite(n) || n < 0) return 0;
  return n;
}

// reversedColMap: dbToApp runs once per ROW and used to rebuild the reversed
// (db column -> app key) map on every one of them — for intune that is a 22-entry
// map rebuilt 1100 times for a single GET, on the :3000 process the rest of the
// platform shares. The colMap objects live in TABLES and never change, so the
// reversal is memoised against the colMap ITSELF: dbToApp's signature is untouched
// and every existing caller gets it for free. Behaviour is identical; only the
// allocation count changes.
const _reversedColMaps = new WeakMap();
function reversedColMap(colMap) {
  let reversed = _reversedColMaps.get(colMap);
  if (!reversed) {
    reversed = Object.fromEntries(Object.entries(colMap).map(([k,v]) => [v,k]));
    _reversedColMaps.set(colMap, reversed);
  }
  return reversed;
}

function dbToApp(row, colMap) {
  const reversed = reversedColMap(colMap);
  const out = {};
  for (const [dbCol, val] of Object.entries(row)) {
    if (dbCol === 'id' || dbCol === 'created_at' || dbCol === 'updated_at') continue;
    out[reversed[dbCol] || dbCol] = val;
  }
  out._id = row.id;
  return out;
}

function appToDb(body, colMap) {
  const out = {};
  for (const [appKey, dbCol] of Object.entries(colMap)) {
    if (body[appKey] !== undefined) out[dbCol] = body[appKey] ?? null;
  }
  return out;
}

for (const [routeName, cfg] of Object.entries(TABLES)) {
  const { table, columns } = cfg;

  app.get(`/api/${routeName}`, async (req, res) => {
    try {
      // ROW-CAP (2026-09-03): the page fetches every table with a bare GET, so what
      // this route returns IS "the fleet" to every badge, stat card, dollar total and
      // CSV export downstream — and before this a truncated response looked exactly
      // like a complete one. The limit is now clamped (clampRowLimit) and the true
      // row count for the SAME WHERE clause is returned in the X-Total-Count header,
      // so a caller can tell it received a page rather than the table. The body stays
      // a BARE JSON ARRAY on purpose: every caller does res.json() and expects an
      // array, so changing the shape would break all of them.
      const { search, limit, offset } = req.query;
      const lim = clampRowLimit(limit);
      const off = clampRowOffset(offset);
      let where = '';
      const params = [];
      if (search) {
        const cols = Object.values(columns);
        where = ' WHERE ' + cols.map(c => `${c} LIKE ?`).join(' OR ');
        params.push(...cols.map(() => `%${search}%`));
      }
      const [[totals]] = await pool.query(`SELECT COUNT(*) AS total FROM ${table}${where}`, params);
      const sql = `SELECT * FROM ${table}${where} ORDER BY id DESC LIMIT ? OFFSET ?`;
      const [rows] = await pool.query(sql, params.concat([lim, off]));
      res.set('X-Total-Count', String(totals.total));
      res.json(rows.map(r => dbToApp(r, columns)));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get(`/api/${routeName}/:id`, async (req, res) => {
    try {
      const [rows] = await pool.query(`SELECT * FROM ${table} WHERE id = ?`, [req.params.id]);
      if (!rows.length) return res.status(404).json({ error: 'Not found' });
      res.json(dbToApp(rows[0], columns));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post(`/api/${routeName}`, rbac.requirePage('it-inventory','admin'), async (req, res) => {
    try {
      const dbRow = appToDb(req.body, columns);
      if (!Object.keys(dbRow).length) return res.status(400).json({ error: 'No valid fields' });
      const cols = Object.keys(dbRow).join(', ');
      const placeholders = Object.keys(dbRow).map(() => '?').join(', ');
      const [result] = await pool.execute(`INSERT INTO ${table} (${cols}) VALUES (${placeholders})`, Object.values(dbRow));
      const conn = await pool.getConnection();
      await auditLog(conn, table, result.insertId, 'INSERT', null, dbRow, req);
      conn.release();
      res.status(201).json({ id: result.insertId, ...req.body });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.put(`/api/${routeName}/:id`, rbac.requirePage('it-inventory','admin'), async (req, res) => {
    try {
      const [existing] = await pool.query(`SELECT * FROM ${table} WHERE id = ?`, [req.params.id]);
      if (!existing.length) return res.status(404).json({ error: 'Not found' });
      const dbRow = appToDb(req.body, columns);
      if (!Object.keys(dbRow).length) return res.status(400).json({ error: 'No valid fields' });
      const setClause = Object.keys(dbRow).map(c => `${c} = ?`).join(', ');
      await pool.execute(`UPDATE ${table} SET ${setClause} WHERE id = ?`, [...Object.values(dbRow), req.params.id]);
      const conn = await pool.getConnection();
      await auditLog(conn, table, req.params.id, 'UPDATE', existing[0], dbRow, req);
      conn.release();
      res.json({ id: req.params.id, ...req.body });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.delete(`/api/${routeName}/:id`, rbac.requirePage('it-inventory','admin'), async (req, res) => {
    try {
      const [existing] = await pool.query(`SELECT * FROM ${table} WHERE id = ?`, [req.params.id]);
      if (!existing.length) return res.status(404).json({ error: 'Not found' });
      await pool.execute(`DELETE FROM ${table} WHERE id = ?`, [req.params.id]);
      const conn = await pool.getConnection();
      await auditLog(conn, table, req.params.id, 'DELETE', existing[0], null, req);
      conn.release();
      res.json({ deleted: true, id: req.params.id });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post(`/api/${routeName}/import/append`, rbac.requirePage('it-inventory','admin'), jsonImportBody, async (req, res) => {
    const records = req.body;
    if (!Array.isArray(records)) return res.status(400).json({ error: 'Expected array' });
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      let inserted = 0;
      for (const record of records) {
        const dbRow = appToDb(record, columns);
        if (!Object.keys(dbRow).length) continue;
        const cols = Object.keys(dbRow).join(', ');
        const ph = Object.keys(dbRow).map(() => '?').join(', ');
        await conn.execute(`INSERT INTO ${table} (${cols}) VALUES (${ph})`, Object.values(dbRow));
        inserted++;
      }
      await conn.commit();
      res.json({ imported: inserted, table });
    } catch (e) {
      await conn.rollback();
      res.status(500).json({ error: e.message });
    } finally { conn.release(); }
  });

  app.post(`/api/${routeName}/import/bulk`, rbac.requirePage('it-inventory','admin'), jsonImportBody, async (req, res) => {
    // CORPIT-BULK-GUARDS 2026-09-03 — two stale guards removed, one kept.
    //
    // REMOVED, guard 1: an origin check against a hardcoded 'https://itam.nrpi.local'.
    // The hostname was baked into this source file, so it could never pass on corpit
    // and would break again on the next host. Origin is now checked by _csrfDenied()
    // in the /api blanket above, which compares the Origin HOST to the REQUEST HOST —
    // derived per-request, so it cannot go stale when the app moves. Verified live:
    // a write carrying Origin: https://evil.example.com is refused 403.
    //
    // REMOVED, guard 2: a required it_auth=granted_2024 cookie. ACCEPT_LEGACY has been
    // false since 2026-08-24 (ITAM-RT-02) and gate-routes only ever CLEARS that cookie,
    // so nothing issues it — the check could only pass for a browser still holding a
    // retired value that was itself published in ~15 world-readable .bak files. It was
    // not adding authentication, only breaking bulk import.
    //
    // This route is NOT unguarded. Four independent layers still apply:
    //   1. nginx  location ~* ^/api/[^/]+/import/bulk$  ->  auth_request /_gate
    //   2. the in-process deny-by-default blanket (unconditional, above)
    //   3. rbac.requirePage('it-inventory','admin') on this very route
    //   4. _csrfDenied() origin/host comparison
    // Guard 3 below (minimum 10 records) is KEPT — this handler runs
    // DELETE FROM <table> before re-inserting, so it is a real wipe guard.
    const records = req.body;
    if (!Array.isArray(records)) return res.status(400).json({ error: 'Expected array' });
    // Guard 3: refuse suspiciously small payloads to prevent accidental wipes.
    // The bulk handler issues DELETE FROM ${table} for non-upsert tables,
    // so an empty or tiny payload would wipe the table.
    if (records.length < 10) {
      return res.status(400).json({ error: 'Payload too small — minimum 10 records required for bulk import' });
    }
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      // BULK SEMANTICS — READ BEFORE CHANGING (2026-09-03)
      // For every table EXCEPT the two upsert tables below this route is REPLACE,
      // not merge: it runs an unfiltered DELETE FROM <table> and then re-inserts
      // only what the uploaded file contained. The UI calls the button "Import", so
      // a user with a partial spreadsheet destroys every row that is not in their
      // file. The two upsert tables merge on the primary key and delete nothing.
      // The default is deliberately NOT changed here — apiBulkImport
      // (IT_Inventory_App.js) sends no mode flag, so flipping it would silently
      // change what every existing import does. The real fix is an explicit
      // mode: 'replace'|'upsert' from the client, tracked separately. What this
      // change adds is the forensic record: the destroyed row count is captured and
      // written to audit_log below.
      const upsertTables = ['active_employees', 'terminated_employees'];
      const useUpsert = upsertTables.includes(table);
      let deleted = 0;
      if (!useUpsert) {
        // affectedRows, not a second COUNT(*): the number reported must be what THIS
        // statement destroyed inside THIS transaction.
        const [delResult] = await conn.execute(`DELETE FROM ${table}`);
        deleted = delResult.affectedRows || 0;
      }
      let inserted = 0;
      for (const record of records) {
        const dbRow = appToDb(record, columns);
        if (!Object.keys(dbRow).length) continue;
        const cols = Object.keys(dbRow).join(', ');
        const ph = Object.keys(dbRow).map(() => '?').join(', ');
        if (useUpsert) {
          const updates = Object.keys(dbRow).map(c => `${c} = VALUES(${c})`).join(', ');
          await conn.execute(
            `INSERT INTO ${table} (${cols}) VALUES (${ph}) ON DUPLICATE KEY UPDATE ${updates}`,
            Object.values(dbRow)
          );
        } else {
          await conn.execute(`INSERT INTO ${table} (${cols}) VALUES (${ph})`, Object.values(dbRow));
        }
        inserted++;
      }
      // BULK-AUDIT (2026-09-03): this is the single most destructive operation in the
      // app — it can DELETE thousands of rows — and it was the ONLY mutation with no
      // forensic record at all. Written on the transaction's OWN connection and
      // BEFORE the commit, so the audit row lands atomically with the import: if the
      // import rolls back, the claim that it happened rolls back with it. record_id
      // is 0 because a bulk run is not one row.
      const bulkAudited = await auditLog(conn, table, 0, 'BULK_IMPORT',
        { rows_deleted: deleted },
        { rows_inserted: inserted, records_received: records.length,
          mode: useUpsert ? 'upsert' : 'replace' },
        req);
      if (!bulkAudited) {
        // audit_log refused the row (e.g. `action` too narrow for 'BULK_IMPORT').
        // Never fail the import over the log — but never let a wipe pass in silence.
        console.error('[bulk-import NO AUDIT ROW]', { table: table, deleted: deleted,
          inserted: inserted, received: records.length,
          actor: auditActor(req), ip: auditIp(req) });
      }
      await conn.commit();
      res.json({ imported: inserted, table });
    } catch (e) {
      await conn.rollback();
      res.status(500).json({ error: e.message });
    } finally { conn.release(); }
  });
}

app.get('/api/dashboard', async (req, res) => {
  try {
    const [[empRow]]     = await pool.query('SELECT COUNT(*) as c FROM active_employees');
    const [[termsRow]]   = await pool.query('SELECT COUNT(*) as c FROM terminated_employees');
    const [[intuneRow]]  = await pool.query('SELECT COUNT(*) as c FROM intune_devices');
    const [[compRow]]    = await pool.query("SELECT COUNT(*) as c FROM intune_devices WHERE compliance = 'Compliant'");
    const [[nonCompRow]] = await pool.query("SELECT COUNT(*) as c FROM intune_devices WHERE compliance = 'Noncompliant'");
    const [[macRow]]     = await pool.query('SELECT COUNT(*) as c FROM macbooks');
    const [[laRow]]      = await pool.query('SELECT COUNT(*) as c FROM live_auction_devices');
    const [[tmRow]]      = await pool.query('SELECT COUNT(*) as c FROM tmobile_lines');
    const [[vzRow]]      = await pool.query('SELECT COUNT(*) as c FROM verizon_lines');
    const [[awsRow]]     = await pool.query('SELECT COUNT(*) as c FROM aws_workspaces');
    const [[laptopRow]]  = await pool.query("SELECT COUNT(*) as c FROM active_employees WHERE device_laptop IS NOT NULL AND device_laptop != ''");
    const [[iphoneRow]]  = await pool.query("SELECT COUNT(*) as c FROM intune_devices WHERE device_category = 'iphone' AND is_historical = 0");
    res.json({
      activeEmployees: empRow.c, terminated: termsRow.c, intuneDevices: intuneRow.c,
      compliant: compRow.c, nonCompliant: nonCompRow.c, macbooks: macRow.c,
      liveAuction: laRow.c, tmobileLines: tmRow.c, verizonLines: vzRow.c,
      awsWorkspaces: awsRow.c, laptops: laptopRow.c, iphones: iphoneRow.c,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Dedicated filtered routes for device categories
app.get('/api/tablets', async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM intune_devices WHERE device_category='tablet' AND is_historical=0 ORDER BY id DESC");
    const cols = TABLES.intune.columns;
    res.json(rows.map(r => { const o={}; Object.entries(cols).forEach(([k,v])=>{o[k]=r[v]??null;}); o['device_category']=r.device_category; o['is_historical']=r.is_historical; o['la_device_id']=r.la_device_id; o['la_state']=r.la_state; o['la_regional']=r.la_regional; o['la_active']=r.la_active; o['_id']=r.id; return o; }));
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/tablets-historical', async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM intune_devices WHERE device_category='tablet' AND is_historical=1 ORDER BY id DESC");
    const cols = TABLES.intune.columns;
    res.json(rows.map(r => { const o={}; Object.entries(cols).forEach(([k,v])=>{o[k]=r[v]??null;}); o['device_category']=r.device_category; o['is_historical']=r.is_historical; o['la_device_id']=r.la_device_id; o['la_state']=r.la_state; o['la_regional']=r.la_regional; o['la_active']=r.la_active; o['_id']=r.id; return o; }));
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/mobile-historical', async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM intune_devices WHERE device_category='iphone' AND is_historical=1 ORDER BY id DESC");
    const cols = TABLES.intune.columns;
    res.json(rows.map(r => { const o={}; Object.entries(cols).forEach(([k,v])=>{o[k]=r[v]??null;}); o['device_category']=r.device_category; o['is_historical']=r.is_historical; o['_id']=r.id; return o; }));
  } catch(e) { res.status(500).json({error:e.message}); }
});

// Cert Watchtower routes (Phase 1)
const createCertRouter = require('./cert-watchtower-routes');
app.use('/', createCertRouter(pool, rbac));

// Cert Watchtower agent routes (Phase 2)
const createAgentRouter = require('./cert-watchtower-agent-routes');
app.use('/', createAgentRouter(pool, rbac));

// Cert Watchtower PRTG routes (Phase 2.5)
const createPrtgRouter = require('./cert-watchtower-prtg-routes');
const createIntuneRouter = require('./cert-watchtower-intune-routes');
app.use('/', createIntuneRouter(pool, rbac));
app.use('/', createPrtgRouter(pool, rbac));



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
  console.log(`IT Inventory API running on port ${PORT}`);
}), [pool, rbacPool]);
