// tenant-health-routes.js — "is this vendor working FOR US, right now" probes.
//
// Distinct from service-status-routes.js, which proxies vendors' public status
// pages (what the vendor says about itself, globally). These endpoints make a
// real authenticated call against OUR tenant, so they catch the cases a status
// page never shows: an expired API token, a revoked grant, our own org being
// throttled, a connector that stopped checking in.
//
// UNMOUNTED 2026-09-07 (see server.js). The Operations Hub status panel this
// was written for does not exist on corpit: landing.html fetches only
// /api/profile/pins, /api/profile/recent, /landing/landing.json and a weather
// forecast, and nothing in /var/www/html references /api/tenant-health at all.
// The original note read "auth-only, no page RBAC — this feeds the Operations
// Hub status panel that every signed-in tech sees". That premise does not hold
// here, and "every signed-in tech" is not the population that reaches this: the
// 3 'outsideit' users hold a valid session and, by name, are not techs.
//
// Every route is now gated on 'server-health' read -- the existing key for
// platform status, already used by srv-dashboard-routes.js -- so that IF the
// panel is ever built, remounting is a one-line change against authorization
// that is already correct, instead of a route going live ungated. Do NOT
// invent a 'tenant-health' page key to gate it more precisely: there is no such
// row in rbac_pages, and an unlisted key falls back to default_access, which
// hands tier2 admin straight back. That is the trap /api/tami was removed for.
//
// Each route is independently fetchable so the landing page can paint rows as
// they land instead of blocking on the slowest vendor, and each caches for 60s
// (a vendor error for 10s) so ten techs with the hub open do not become ten
// times the vendor calls. Callers that miss while a refresh is running share it.

const express = require('express');
const router  = express.Router();

const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 3,
  queueLimit: 0,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
// Blanket, not per-route: a per-route check rots the first time someone adds a
// probe and forgets one, which is exactly how this module ended up ungated.
router.use(rbac.requirePage('server-health', 'read'));

const TTL_MS       = 60 * 1000;
const ERROR_TTL_MS = 10 * 1000;   // G18: a vendor error result (see vendorError) expires sooner
const TIMEOUT_MS   = 7000;

// ---- tiny cache -----------------------------------------------------------
// G18 (CHG-P25-G18, 2026-09-25): a caller that misses while a refresh for the
// same key is already running waits on that refresh instead of starting its
// own vendor call. A result the probe marked with vendorError() (the vendor
// answered with a non-success HTTP status) is kept for ERROR_TTL_MS; every
// other result for TTL_MS as before. A refresh that throws or rejects is not
// cached: everyone waiting on it gets the rejection, and the next call starts
// a new refresh.
const _cache = {};
const _inflight = {};
const _vendorErrors = new WeakSet();
function vendorError(payload) { _vendorErrors.add(payload); return payload; }
function cached(key, fn) {
  const hit = _cache[key];
  if (hit && (Date.now() - hit.at) < hit.ttl) {
    return Promise.resolve(Object.assign({}, hit.payload, { cached: true }));
  }
  if (!_inflight[key]) {
    const p = fn().then(payload => {
      _cache[key] = { at: Date.now(), ttl: _vendorErrors.has(payload) ? ERROR_TTL_MS : TTL_MS, payload };
      return payload;
    });
    const done = () => { if (_inflight[key] === p) delete _inflight[key]; };
    p.then(done, done);
    _inflight[key] = p;
  }
  return _inflight[key].then(payload => Object.assign({}, payload, { cached: false }));
}

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label + ' timed out after ' + ms + 'ms')), ms)),
  ]);
}

async function getJson(url, headers) {
  const r = await withTimeout(fetch(url, { headers: headers || {} }), TIMEOUT_MS, url);
  const text = await r.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (e) { /* non-JSON */ }
  return { status: r.status, ok: r.ok, body, raw: text };
}

// state vocabulary shared by every route below, so the page has one contract:
//   ok | warn | bad | unconfigured   (+ a human `text` and a `detail` tooltip)
const S = (state, text, detail, extra) =>
  Object.assign({ state, text, detail, checkedAt: new Date().toISOString() }, extra || {});

// ---- Microsoft Graph token (shared by entra + intune) ----------------------
let _graphTok = { at: 0, token: null };
async function graphToken() {
  if (_graphTok.token && (Date.now() - _graphTok.at) < 45 * 60 * 1000) return _graphTok.token;
  const t = process.env.AZURE_TENANT_ID, c = process.env.AZURE_CLIENT_ID, s = process.env.AZURE_CLIENT_SECRET;
  if (!t || !c || !s) throw new Error('AZURE_* credentials not configured');
  const body = new URLSearchParams({
    client_id: c, client_secret: s,
    scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials',
  });
  const r = await withTimeout(
    fetch('https://login.microsoftonline.com/' + t + '/oauth2/v2.0/token', { method: 'POST', body }),
    TIMEOUT_MS, 'graph token');
  const j = await r.json();
  if (!j.access_token) throw new Error('token endpoint returned no access_token');
  _graphTok = { at: Date.now(), token: j.access_token };
  return j.access_token;
}

// ===========================================================================
// GET /okta — authenticated call against our Okta org.
// Okta publishes no machine-readable public status feed (status.okta.com/api/v2
// returns 401), so the API is both the preferred and the only route.
// ===========================================================================
router.get('/okta', async (req, res) => {
  try {
    const payload = await cached('okta', async () => {
      const base = process.env.OKTA_BASE_URL, tok = process.env.OKTA_API_TOKEN;
      if (!base || !tok) return S('unconfigured', 'Not configured', 'OKTA_BASE_URL / OKTA_API_TOKEN not set.');
      const b = (base.startsWith('http') ? base : 'https://' + base).replace(/\/$/, '');
      const t0 = Date.now();
      const r = await getJson(b + '/api/v1/org', { Authorization: 'SSWS ' + tok, Accept: 'application/json' });
      const ms = Date.now() - t0;
      if (r.status === 200) {
        const org = (r.body && (r.body.companyName || r.body.subdomain)) || 'org';
        const st  = r.body && r.body.status;
        return S('ok', 'Operational',
          'Okta org API answered in ' + ms + 'ms (' + org + (st ? ' · ' + st : '') + ').',
          { responseMs: ms, org: org });
      }
      if (r.status === 401 || r.status === 403) {
        return vendorError(S('bad', 'Auth failed',
          'Okta rejected our API token (HTTP ' + r.status + ') — the token is expired, revoked or lacks scope. ' +
          'This is our credential, not an Okta outage.', { httpStatus: r.status }));
      }
      if (r.status === 429) {
        return vendorError(S('warn', 'Rate limited', 'Okta returned HTTP 429 for our org.', { httpStatus: 429 }));
      }
      return vendorError(S('bad', 'Degraded', 'Okta org API returned HTTP ' + r.status + '.', { httpStatus: r.status }));
    });
    res.json(payload);
  } catch (e) {
    res.json(S('bad', 'Unreachable', 'Could not reach the Okta API: ' + e.message));
  }
});

// ===========================================================================
// GET /zia — Zscaler Internet Access, via the ZIdentity OneAPI token path that
// the Command Center already uses. trust.zscaler.com is not a statuspage.io
// feed (404), so again the API is the only real option.
// ===========================================================================
router.get('/zia', async (req, res) => {
  try {
    const payload = await cached('zia', async () => {
      let z;
      try { z = require('./zscaler-lookup'); }
      catch (e) { return S('unconfigured', 'Not configured', 'zscaler-lookup module unavailable.'); }
      if (!process.env.ZSCALER_CLIENT_ID || !process.env.ZSCALER_CLIENT_SECRET) {
        return S('unconfigured', 'Not configured', 'ZSCALER_CLIENT_ID / _SECRET not set.');
      }
      const t0 = Date.now();
      await withTimeout(z.ziaAuth(), TIMEOUT_MS, 'ZIA auth');
      const ms = Date.now() - t0;
      return S('ok', 'Operational',
        'ZIA authenticated against our tenant in ' + ms + 'ms (ZIdentity OneAPI).',
        { responseMs: ms });
    });
    res.json(payload);
  } catch (e) {
    const m = String(e.message || '');
    const auth = /401|403|invalid_client|unauthorized/i.test(m);
    res.json(S(auth ? 'bad' : 'bad', auth ? 'Auth failed' : 'Unreachable',
      'ZIA probe failed: ' + m.slice(0, 200)));
  }
});

// ===========================================================================
// GET /entra — LAYERED, by design.
//   1. Microsoft Service Health for our tenant (what MS says about our
//      services). Needs the ServiceHealth.Read.All app role; it is NOT granted
//      today, so this arm 403s.
//   2. Fallback: a real Graph call against our tenant (/organization), which
//      answers "is Entra serving us right now".
// The moment someone grants ServiceHealth.Read.All + admin consent, arm 1
// starts succeeding and this upgrades itself with no code change.
// ===========================================================================
router.get('/entra', async (req, res) => {
  try {
    const payload = await cached('entra', async () => {
      const tok = await graphToken();
      const H = { Authorization: 'Bearer ' + tok };

      // --- arm 1: Microsoft's own service health ---
      const sh = await getJson('https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/healthOverviews', H);
      if (sh.status === 200 && sh.body && Array.isArray(sh.body.value)) {
        const all = sh.body.value;
        // We care about the identity-adjacent workloads on this row.
        const WANT = ['Microsoft Entra', 'Azure Active Directory', 'Identity Service'];
        const mine = all.filter(w => WANT.some(n => (w.service || '').toLowerCase().includes(n.toLowerCase())));
        const pool = mine.length ? mine : all;
        const bad  = pool.filter(w => /serviceDegradation|serviceInterruption|extendedRecovery/i.test(w.status || ''));
        const advisory = pool.filter(w => /investigating|restoringService|verifyingService/i.test(w.status || ''));
        const names = s => s.map(w => w.service + ' (' + w.status + ')').join(', ');
        if (bad.length)      return S('bad',  'Service issue',  'Microsoft reports: ' + names(bad) + '.',        { mode: 'servicehealth', workloads: pool.length });
        if (advisory.length) return S('warn', 'Advisory',       'Microsoft reports: ' + names(advisory) + '.',   { mode: 'servicehealth', workloads: pool.length });
        return S('ok', 'Operational',
          'Microsoft reports all ' + pool.length + ' identity workload(s) healthy for our tenant.',
          { mode: 'servicehealth', workloads: pool.length });
      }

      // --- arm 2: live tenant probe ---
      const t0 = Date.now();
      const org = await getJson('https://graph.microsoft.com/v1.0/organization', H);
      const ms  = Date.now() - t0;
      const why = sh.status === 403
        ? 'Microsoft Service Health needs the ServiceHealth.Read.All app role (not granted), so this is a live Graph reachability check instead.'
        : 'Service Health returned HTTP ' + sh.status + '; using a live Graph reachability check instead.';
      if (org.status === 200) {
        const name = (org.body && org.body.value && org.body.value[0] && org.body.value[0].displayName) || 'tenant';
        return S('ok', 'Operational',
          'Graph answered for ' + name + ' in ' + ms + 'ms. ' + why,
          { mode: 'probe', degradedSource: sh.status, responseMs: ms });
      }
      if (org.status === 401 || org.status === 403) {
        return vendorError(S('bad', 'Auth failed',
          'Graph rejected our app credentials (HTTP ' + org.status + '). ' + why, { mode: 'probe' }));
      }
      return vendorError(S('bad', 'Degraded', 'Graph /organization returned HTTP ' + org.status + '. ' + why, { mode: 'probe' }));
    });
    res.json(payload);
  } catch (e) {
    res.json(S('bad', 'Unreachable', 'Entra probe failed: ' + String(e.message).slice(0, 200)));
  }
});

// ===========================================================================
// GET /intune — device management health straight from Graph, replacing the
// old disk-encryption-count reading. managedDeviceOverview is a single cheap
// call that reports enrolment totals and per-OS breakdown for our tenant.
// ===========================================================================
router.get('/intune', async (req, res) => {
  try {
    const payload = await cached('intune', async () => {
      const tok = await graphToken();
      const H = { Authorization: 'Bearer ' + tok };
      const ov = await getJson('https://graph.microsoft.com/v1.0/deviceManagement/managedDeviceOverview', H);
      if (ov.status === 403 || ov.status === 401) {
        return vendorError(S('bad', 'Auth failed',
          'Graph rejected the device-management read (HTTP ' + ov.status + ').'));
      }
      if (ov.status !== 200 || !ov.body) {
        return vendorError(S('bad', 'Degraded', 'Intune overview returned HTTP ' + ov.status + '.'));
      }
      const b = ov.body;
      const enrolled = b.enrolledDeviceCount || 0;
      const mdm      = (b.mdmEnrolledCount != null) ? b.mdmEnrolledCount : null;
      const dual     = (b.dualEnrolledDeviceCount != null) ? b.dualEnrolledDeviceCount : null;
      // Non-compliant count is a second, still-cheap call and is the number a
      // tech actually acts on.
      // Graph rejects $count on managedDevices (HTTP 400), so page the filtered
      // list and count ids. $top maxes at 1000; a nextLink means we undercounted,
      // which we say out loud rather than reporting a confidently wrong number.
      let nonCompliant = null, ncCapped = false;
      const nc = await getJson(
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices" +
        "?$filter=complianceState eq 'noncompliant'&$select=id&$top=999", H);
      if (nc.status === 200 && nc.body && Array.isArray(nc.body.value)) {
        nonCompliant = nc.body.value.length;
        ncCapped = !!nc.body['@odata.nextLink'];
      }

      const bits = [enrolled + ' device(s) enrolled'];
      if (mdm != null)  bits.push(mdm + ' MDM');
      if (dual != null && dual > 0) bits.push(dual + ' dual-enrolled');
      if (nonCompliant != null) bits.push(nonCompliant + (ncCapped ? '+' : '') + ' non-compliant');
      const detail = 'Intune (Graph) · ' + bits.join(' · ') + '.';

      if (enrolled === 0) return S('bad', 'No devices', 'Intune reports zero enrolled devices. ' + detail, { enrolled: 0 });
      if (nonCompliant && nonCompliant > 0) {
        return S('warn', 'Needs review', detail, { enrolled, nonCompliant, nonCompliantCapped: ncCapped });
      }
      return S('ok', 'Operational', detail, { enrolled, nonCompliant });
    });
    res.json(payload);
  } catch (e) {
    res.json(S('bad', 'Unreachable', 'Intune probe failed: ' + String(e.message).slice(0, 200)));
  }
});

// ===========================================================================
// GET /kandji — IRU (Kandji's new name). Authenticated call against our
// tenant; the vendor's public page is separately proxied by
// /api/service-status (status.kandji.io), so the row can show both.
// ===========================================================================
// /iru is the current name; /kandji stays as an alias so anything already
// pointing at the old name keeps working.
router.get(['/iru', '/kandji'], async (req, res) => {
  try {
    const payload = await cached('kandji', async () => {
      const base = process.env.KANDJI_BASE_URL, tok = process.env.KANDJI_TOKEN;
      if (!base || !tok) return S('unconfigured', 'Not configured', 'KANDJI_BASE_URL / KANDJI_TOKEN not set.');
      const b = base.replace(/\/$/, '');
      const t0 = Date.now();
      const r = await getJson(b + '/api/v1/devices?limit=1', { Authorization: 'Bearer ' + tok, Accept: 'application/json' });
      const ms = Date.now() - t0;
      if (r.status === 200) {
        // The list endpoint returns an array; a count header is not guaranteed,
        // so report reachability plus whatever total we can see cheaply.
        let total = null;
        if (Array.isArray(r.body)) total = null;               // page only
        else if (r.body && typeof r.body.count === 'number') total = r.body.count;
        return S('ok', 'Operational',
          'IRU (Kandji) API answered in ' + ms + 'ms' + (total != null ? ' · ' + total + ' devices' : '') + '.',
          { responseMs: ms, devices: total });
      }
      if (r.status === 401 || r.status === 403) {
        return vendorError(S('bad', 'Auth failed',
          'IRU rejected our API token (HTTP ' + r.status + ') — expired, revoked or out of scope.', { httpStatus: r.status }));
      }
      if (r.status === 429) return vendorError(S('warn', 'Rate limited', 'IRU returned HTTP 429.', { httpStatus: 429 }));
      return vendorError(S('bad', 'Degraded', 'IRU API returned HTTP ' + r.status + '.', { httpStatus: r.status }));
    });
    res.json(payload);
  } catch (e) {
    res.json(S('bad', 'Unreachable', 'Could not reach the IRU (Kandji) API: ' + String(e.message).slice(0, 200)));
  }
});

module.exports = router;
