// ─────────────────────────────────────────────────────────────────────────────
// srv-dashboard.test.js — tests for the Server Health & Maintenance dashboard.
//
//   cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) \
//     node --test srv-dashboard.test.js
//
// Two layers:
//   * unit    — the probe library's pure logic, including the scope rule that
//               keeps this feature from becoming a scanner.
//   * contract— the live API on localhost:3001, exercised with the localdev
//               test account. These assert the access gates and the response
//               shapes the page depends on.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const probe = require('./srv-probe-lib');

const BASE = process.env.TEST_BASE || 'http://localhost:3001';
const TEST_EMAIL = process.env.TEST_EMAIL || 'test-tier2@local';
const TEST_PASSWORD = process.env.TEST_PASSWORD || '';

// ── helpers ─────────────────────────────────────────────────────────────────
function req(method, path, opts) {
  opts = opts || {};
  return new Promise(function (resolve, reject) {
    const u = new URL(BASE + path);
    const r = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: method,
      headers: Object.assign(
        { 'Content-Type': 'application/json' },
        opts.token ? { Authorization: 'Bearer ' + opts.token } : {}),
      timeout: 30000,
    }, function (res) {
      let body = '';
      res.on('data', function (c) { body += c; });
      res.on('end', function () {
        let json = null;
        try { json = JSON.parse(body); } catch (e) { /* non-JSON */ }
        resolve({ status: res.statusCode, body: json, raw: body });
      });
    });
    r.on('timeout', function () { r.destroy(); reject(new Error('timeout on ' + path)); });
    r.on('error', reject);
    if (opts.body) r.write(JSON.stringify(opts.body));
    r.end();
  });
}

let TOKEN = null;
async function token() {
  if (TOKEN) return TOKEN;
  if (!TEST_PASSWORD) return null;
  const r = await req('POST', '/api/localdev/login', { body: { email: TEST_EMAIL, password: TEST_PASSWORD } });
  TOKEN = r.body && r.body.token;
  return TOKEN;
}

// A throwaway origin so redirect behaviour can be exercised without touching
// anything real.
function stubServer(handler) {
  return new Promise(function (resolve) {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', function () { resolve({ server: s, port: s.address().port }); });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// UNIT — certificate name matching
// ═══════════════════════════════════════════════════════════════════════════
test('nameMatches: exact host', function () {
  assert.equal(probe.nameMatches('itam.nrpi.local', 'itam.nrpi.local'), true);
  assert.equal(probe.nameMatches('itam.nrpi.local', 'other.nrpi.local'), false);
});

test('nameMatches: case and trailing dot are not a mismatch', function () {
  assert.equal(probe.nameMatches('ITAM.NRPI.local', 'itam.nrpi.local.'), true);
});

test('nameMatches: a wildcard covers one label only', function () {
  assert.equal(probe.nameMatches('app.nrpi.local', '*.nrpi.local'), true);
  assert.equal(probe.nameMatches('a.b.nrpi.local', '*.nrpi.local'), false,
    'a wildcard must not span a dot');
  assert.equal(probe.nameMatches('nrpi.local', '*.nrpi.local'), false,
    'a wildcard must not match the bare domain');
});

test('nameMatches: missing input is never a match', function () {
  assert.equal(probe.nameMatches('', 'itam.nrpi.local'), false);
  assert.equal(probe.nameMatches('itam.nrpi.local', null), false);
});

// ═══════════════════════════════════════════════════════════════════════════
// UNIT — error sanitisation
// ═══════════════════════════════════════════════════════════════════════════
test('sanitizeError: known codes become plain language', function () {
  const e = new Error('connect ECONNREFUSED 10.9.58.141:443');
  e.code = 'ECONNREFUSED';
  assert.deepEqual(probe.sanitizeError(e), { code: 'ECONNREFUSED', message: 'Connection refused' });
});

test('sanitizeError: an unknown failure keeps no raw payload', function () {
  const e = new Error('boom <script>alert(1)</script> /etc/secret/path?token=abc');
  const s = probe.sanitizeError(e);
  assert.equal(/[<>?]/.test(s.message), false, 'markup and query strings are stripped');
  assert.ok(s.message.length <= 180);
});

test('sanitizeError: nothing in, nothing out', function () {
  assert.equal(probe.sanitizeError(null), null);
});

// ═══════════════════════════════════════════════════════════════════════════
// UNIT — the scope rule. This is the test that matters most: the redirect
// follower must never contact a host that is not in the registry.
// ═══════════════════════════════════════════════════════════════════════════
test('followChain: a redirect to an unregistered host is recorded, not visited', async function () {
  // Both stubs run locally, but they answer to DIFFERENT host names, and only
  // one of those names is in the registry allow-set. That is the real-world
  // shape: a registered vhost redirecting somewhere ITAM does not manage.
  let offScopeHits = 0;
  const off = await stubServer(function (rq, rs) { offScopeHits++; rs.end('should never be reached'); });
  const on = await stubServer(function (rq, rs) {
    rs.writeHead(302, { Location: 'http://localhost:' + off.port + '/elsewhere' });
    rs.end();
  });
  try {
    const allowed = new Set(['127.0.0.1']);          // 'localhost' is NOT registered
    const r = await probe.followChain('http://127.0.0.1:' + on.port + '/', allowed, 3000);
    assert.equal(offScopeHits, 0, 'the unregistered destination must not be requested');
    assert.equal(r.hops, 0, 'the hop is refused');
    assert.equal(r.loop, false);
    assert.ok(/localhost:/.test(String(r.redirectTo)),
      'the destination is still reported to the operator');
  } finally { off.server.close(); on.server.close(); }
});

test('followChain: a redirect INTO another registered host is allowed', async function () {
  let secondHits = 0;
  const second = await stubServer(function (rq, rs) { secondHits++; rs.writeHead(200); rs.end('ok'); });
  const first = await stubServer(function (rq, rs) {
    rs.writeHead(302, { Location: 'http://localhost:' + second.port + '/' });
    rs.end();
  });
  try {
    const allowed = new Set(['127.0.0.1', 'localhost']);   // both registered
    const r = await probe.followChain('http://127.0.0.1:' + first.port + '/', allowed, 3000);
    assert.equal(secondHits, 1, 'a hop between two registered hosts is followed');
    assert.equal(r.hops, 1);
    assert.equal(r.result.status, 200);
  } finally { second.server.close(); first.server.close(); }
});

test('followChain: an empty allow-set stops at the first redirect', async function () {
  let offScopeHits = 0;
  const off = await stubServer(function (rq, rs) { offScopeHits++; rs.end('nope'); });
  const on = await stubServer(function (rq, rs) {
    rs.writeHead(301, { Location: 'http://127.0.0.1:' + off.port + '/elsewhere' });
    rs.end();
  });
  try {
    const r = await probe.followChain('http://127.0.0.1:' + on.port + '/', new Set(), 3000);
    assert.equal(offScopeHits, 0, 'the out-of-scope destination must not be requested');
    assert.equal(r.hops, 0, 'no hop is taken');
    assert.ok(String(r.redirectTo).indexOf(String(off.port)) !== -1,
      'the destination is still reported so an operator can see it');
  } finally { off.server.close(); on.server.close(); }
});

test('followChain: a self-referential redirect is reported as a loop', async function () {
  const s = await stubServer(function (rq, rs) {
    rs.writeHead(302, { Location: '/' });
    rs.end();
  });
  try {
    const r = await probe.followChain('http://127.0.0.1:' + s.port + '/', new Set(['127.0.0.1']), 3000);
    assert.equal(r.loop, true);
  } finally { s.server.close(); }
});

test('followChain: a normal 200 is not a redirect', async function () {
  const s = await stubServer(function (rq, rs) { rs.writeHead(200); rs.end('ok'); });
  try {
    const r = await probe.followChain('http://127.0.0.1:' + s.port + '/', new Set(['127.0.0.1']), 3000);
    assert.equal(r.loop, false);
    assert.equal(r.hops, 0);
    assert.equal(r.result.status, 200);
  } finally { s.server.close(); }
});

// ═══════════════════════════════════════════════════════════════════════════
// UNIT — probeVhost end to end against a stub
// ═══════════════════════════════════════════════════════════════════════════
const TH = { vhost_response_ms: { warn: 1500, crit: 5000 }, cert_days_left: { warn: 30, crit: 7 } };

test('probeVhost: a plain 200 on an HTTP vhost is healthy but flagged for no TLS', async function () {
  const s = await stubServer(function (rq, rs) { rs.writeHead(200); rs.end('ok'); });
  try {
    const r = await probe.probeVhost({
      id: 1, fqdn: '127.0.0.1', port: s.port, probe_path: '/', expect_https: 0,
      expected_status: 200, status: 'active',
    }, new Set(['127.0.0.1']), TH);
    assert.equal(r.dns_state, 'ok');
    assert.equal(r.last_status, 200);
    assert.equal(r.state, 'healthy');
    assert.ok(r.flags.indexOf('no-https') !== -1);
  } finally { s.server.close(); }
});

test('probeVhost: an unexpected status downgrades the state', async function () {
  const s = await stubServer(function (rq, rs) { rs.writeHead(503); rs.end('down'); });
  try {
    const r = await probe.probeVhost({
      id: 1, fqdn: '127.0.0.1', port: s.port, probe_path: '/', expect_https: 0,
      expected_status: 200, status: 'active',
    }, new Set(['127.0.0.1']), TH);
    assert.equal(r.state, 'critical');
    assert.ok(r.flags.indexOf('unexpected-status') !== -1);
    assert.ok(/503/.test(r.error_message));
  } finally { s.server.close(); }
});

test('probeVhost: a name that does not resolve reports offline, not healthy', async function () {
  const r = await probe.probeVhost({
    id: 1, fqdn: 'no-such-host.invalid', port: 443, probe_path: '/', expect_https: 1,
    expected_status: 200, status: 'active',
  }, new Set(['no-such-host.invalid']), TH);
  assert.equal(r.state, 'offline');
  assert.equal(r.dns_state, 'nxdomain');
  assert.equal(r.cert_state, 'unknown');
});

test('probeVhost: a vhost in maintenance is never reported as failing', async function () {
  const s = await stubServer(function (rq, rs) { rs.writeHead(500); rs.end('x'); });
  try {
    const r = await probe.probeVhost({
      id: 1, fqdn: '127.0.0.1', port: s.port, probe_path: '/', expect_https: 0,
      expected_status: 200, status: 'maintenance',
    }, new Set(['127.0.0.1']), TH);
    assert.equal(r.state, 'maintenance');
  } finally { s.server.close(); }
});

test('probeVhost: a loopback answer on the local host is not called a repoint', async function () {
  const s = await stubServer(function (rq, rs) { rs.writeHead(200); rs.end('ok'); });
  try {
    const r = await probe.probeVhost({
      id: 1, fqdn: '127.0.0.1', port: s.port, probe_path: '/', expect_https: 0,
      expected_status: 200, status: 'active', expected_ip: '10.9.58.141',
    }, new Set(['127.0.0.1']), TH);
    assert.ok(r.flags.indexOf('dns-loopback') !== -1, 'reported as a loopback answer');
    assert.equal(r.flags.indexOf('dns-unexpected-target'), -1, 'not raised as a DNS change');
    assert.equal(r.state, 'healthy');
  } finally { s.server.close(); }
});

// ═══════════════════════════════════════════════════════════════════════════
// CONTRACT — access control
// ═══════════════════════════════════════════════════════════════════════════
const GATED = ['/overview', '/servers', '/vhosts', '/jobs', '/apis', '/findings',
  '/thresholds', '/maintenance', '/vhost-config-audit',
  '/health', '/cron', '/backups', '/pm2', '/db-health', '/api-inventory'];

test('every dashboard endpoint refuses an unauthenticated caller', async function () {
  for (const p of GATED) {
    const r = await req('GET', '/api/system' + p);
    assert.ok(r.status === 401 || r.status === 403,
      p + ' answered ' + r.status + ' without a token — it must not');
  }
});

test('an admin-only route refuses an unauthenticated caller', async function (t) {
  const r = await req('POST', '/api/system/vhosts', { body: { fqdn: 'x.example.test' } });
  assert.ok(r.status === 401 || r.status === 403, 'POST /vhosts answered ' + r.status);
});

// ═══════════════════════════════════════════════════════════════════════════
// CONTRACT — shapes the page depends on. Skipped without a test password.
// ═══════════════════════════════════════════════════════════════════════════
test('authenticated read endpoints return their documented shape', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('set TEST_PASSWORD to run the authenticated contract tests');

  const ov = await req('GET', '/api/system/overview', { token: tok });
  assert.equal(ov.status, 200);
  assert.ok(['healthy', 'warning', 'critical', 'offline', 'maintenance', 'unknown'].indexOf(ov.body.overall) !== -1,
    'overall uses the shared status vocabulary');
  assert.ok(Array.isArray(ov.body.reasons));
  assert.ok(Array.isArray(ov.body.unavailable), 'unavailable sources are always listed, even when empty');
  assert.ok(ov.body.counts && typeof ov.body.counts === 'object');
  assert.equal('healthPercent' in ov.body, false, 'no unexplained health percentage is published');

  const sv = await req('GET', '/api/system/servers', { token: tok });
  assert.equal(sv.status, 200);
  assert.ok(Array.isArray(sv.body.servers));
  sv.body.servers.forEach(function (s) {
    assert.ok(['healthy', 'warning', 'critical', 'offline', 'maintenance', 'unknown'].indexOf(s.health) !== -1);
    if (!s.isLocal && s.monitorMode === 'none') {
      assert.equal(s.cpu, null, 'a host with no collector must not report utilisation');
      assert.equal(s.memory, null);
    }
  });

  const vh = await req('GET', '/api/system/vhosts', { token: tok });
  assert.equal(vh.status, 200);
  assert.ok(Array.isArray(vh.body.vhosts));

  const jb = await req('GET', '/api/system/jobs', { token: tok });
  assert.equal(jb.status, 200);
  assert.ok(jb.body.counts && typeof jb.body.counts.total === 'number');

  const ap = await req('GET', '/api/system/apis', { token: tok });
  assert.equal(ap.status, 200);
  assert.ok(Array.isArray(ap.body.internal) && Array.isArray(ap.body.external));
});

test('a failing health source degrades that source only', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');
  const ov = await req('GET', '/api/system/overview', { token: tok });
  assert.equal(ov.status, 200, 'the overview still answers 200 regardless of source failures');
  ov.body.unavailable.forEach(function (u) {
    assert.ok(u.source && u.error, 'each unavailable source names itself and its error');
    assert.ok(u.error.length <= 200, 'the error is truncated, not a raw stack');
  });
});

test('no response carries a credential', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');
  const secrets = [process.env.AZURE_CLIENT_SECRET, process.env.OKTA_API_TOKEN,
    process.env.KANDJI_TOKEN, process.env.ZSCALER_CLIENT_SECRET, process.env.DB_PASSWORD]
    .filter(function (v) { return v && v.length > 6; });
  const paths = ['/overview', '/servers', '/vhosts', '/apis', '/findings', '/jobs',
    '/apis/intune/identity', '/apis/entra/identity', '/apis/okta/identity'];
  for (const p of paths) {
    const r = await req('GET', '/api/system' + p, { token: tok });
    for (const sec of secrets) {
      assert.equal(r.raw.indexOf(sec), -1, p + ' leaked a credential value');
    }
    assert.equal(/-----BEGIN [A-Z ]*PRIVATE KEY/.test(r.raw), false, p + ' leaked a private key');
    assert.equal(/eyJ[A-Za-z0-9_-]{20,}\./.test(r.raw), false, p + ' leaked a bearer token');
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// CONTRACT — input validation. A registry that accepts anything is a scanner.
// ═══════════════════════════════════════════════════════════════════════════
test('the registry rejects malformed input', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');

  const bad = [
    { label: 'a URL instead of a host name', body: { fqdn: 'http://evil.example.com/path' } },
    { label: 'a host name with a space', body: { fqdn: 'not a host' } },
    { label: 'an empty host name', body: { fqdn: '' } },
    { label: 'an out-of-range port', body: { fqdn: 'a.test.local', port: 99999 } },
    { label: 'a probe path that is not a path', body: { fqdn: 'a.test.local', probe_path: 'no-leading-slash' } },
    { label: 'a probe path containing a space', body: { fqdn: 'a.test.local', probe_path: '/a b' } },
    { label: 'an expected address that is not an address', body: { fqdn: 'a.test.local', expected_ip: 'evil.example.com' } },
    { label: 'an out-of-range HTTP status', body: { fqdn: 'a.test.local', expected_status: 9000 } },
    { label: 'an invalid exposure value', body: { fqdn: 'a.test.local', exposure: 'everywhere' } },
  ];
  for (const c of bad) {
    const r = await req('POST', '/api/system/vhosts', { token: tok, body: c.body });
    assert.equal(r.status, 400, c.label + ' should be rejected, got ' + r.status);
    assert.ok(r.body && r.body.error, c.label + ' should return an explanation');
  }
});

test('the registry refuses targets that are not ITAM inventory', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');
  const blocked = [
    { label: 'cloud instance metadata', body: { fqdn: '169.254.169.254' } },
    { label: 'link-local by name', body: { fqdn: 'metadata.google.internal' } },
    { label: 'link-local as an expected address', body: { fqdn: 'ok.test.local', expected_ip: '169.254.169.254' } },
  ];
  for (const c of blocked) {
    const r = await req('POST', '/api/system/vhosts', { token: tok, body: c.body });
    assert.equal(r.status, 400, c.label + ' should be refused, got ' + r.status);
    assert.ok(/outside the ITAM inventory/.test(r.body.error || ''), c.label + ' should say why');
  }
  const sr = await req('POST', '/api/system/servers', { token: tok, body: { hostname: '169.254.169.254' } });
  assert.equal(sr.status, 400, 'server registration is guarded the same way');
});

test('thresholds reject unknown keys and non-numeric values', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');
  let r = await req('PUT', '/api/system/thresholds', {
    token: tok, body: { thresholds: { not_a_real_threshold: { warn: 1, crit: 2 } } } });
  assert.equal(r.status, 400);
  r = await req('PUT', '/api/system/thresholds', {
    token: tok, body: { thresholds: { cpu_used_pct: { warn: 'high', crit: 'higher' } } } });
  assert.equal(r.status, 400);
});

test('a recheck can only target a registered record', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');
  const r = await req('POST', '/api/system/vhosts/99999999/check', { token: tok });
  assert.equal(r.status, 404, 'an unknown id must not probe anything');
  // There is deliberately no route that accepts a host name, so there is no
  // "check this arbitrary target" path to test against.
});

test('the local host cannot be retired out of the registry', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');
  const list = await req('GET', '/api/system/servers', { token: tok });
  const local = (list.body.servers || []).filter(function (s) { return s.isLocal; })[0];
  if (!local) return t.skip('no local server registered');
  const r = await req('DELETE', '/api/system/servers/' + local.id, { token: tok });
  assert.equal(r.status, 400);
});

// ═══════════════════════════════════════════════════════════════════════════
// CONTRACT — full registry lifecycle, cleaned up after itself
// ═══════════════════════════════════════════════════════════════════════════
test('a virtual host can be registered, checked and retired', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');

  // A fixed name, not a timestamped one. Retiring is a status change rather
  // than a delete (history stays attributable), so a per-run name would leave a
  // new retired row behind on every run. Reusing one name caps that at a single
  // row for the life of the box.
  const fqdn = 'selftest.invalid';
  let id;
  const created = await req('POST', '/api/system/vhosts', {
    token: tok,
    body: { fqdn: fqdn, friendly_name: 'Automated test record', exposure: 'internal',
      expect_https: false, probe_path: '/', expected_status: 200 },
  });
  if (created.status === 409) {
    // Left retired by an earlier run — find it and bring it back.
    const all = await req('GET', '/api/system/vhosts?include=retired', { token: tok });
    const existing = (all.body.vhosts || []).filter(function (v) { return v.fqdn === fqdn; })[0];
    assert.ok(existing, 'a duplicate was reported but the record could not be found');
    id = existing.id;
    const back = await req('PUT', '/api/system/vhosts/' + id, {
      token: tok, body: { status: 'active', monitoring_enabled: true } });
    assert.equal(back.status, 200);
  } else {
    assert.equal(created.status, 200, created.raw);
    id = created.body.id;
  }
  assert.ok(id);

  try {
    // A duplicate registration is refused rather than silently creating a twin.
    const dup = await req('POST', '/api/system/vhosts', {
      token: tok, body: { fqdn: fqdn, probe_path: '/' } });
    assert.equal(dup.status, 409);

    // .invalid never resolves, by RFC. The check must say offline, not healthy.
    const chk = await req('POST', '/api/system/vhosts/' + id + '/check', { token: tok });
    assert.equal(chk.status, 200);
    assert.equal(chk.body.result.state, 'offline');
    assert.equal(chk.body.result.dns_state, 'nxdomain');

    const detail = await req('GET', '/api/system/vhosts/' + id, { token: tok });
    assert.equal(detail.status, 200);
    assert.equal(detail.body.vhost.state, 'offline');
    assert.ok(detail.body.history.length >= 1, 'the check is retained as history');
  } finally {
    const del = await req('DELETE', '/api/system/vhosts/' + id, { token: tok });
    assert.equal(del.status, 200, 'cleanup failed — a test record was left registered');
  }
});

test('a retired record leaves the monitored set', async function (t) {
  const tok = await token();
  if (!tok) return t.skip('needs TEST_PASSWORD');
  const list = await req('GET', '/api/system/vhosts', { token: tok });
  const leftovers = (list.body.vhosts || []).filter(function (v) { return /^selftest\./.test(v.fqdn); });
  assert.equal(leftovers.length, 0, 'test records must not survive: ' +
    leftovers.map(function (v) { return v.fqdn; }).join(', '));
});
