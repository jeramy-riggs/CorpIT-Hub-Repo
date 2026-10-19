'use strict';
// node --test access-request-routes.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const mod = require('./access-request-routes');

// ---- fakes ------------------------------------------------------------------------------------------------------
const POLICY = {
  superadmin_groups: ['SaaS-ITH-SA'],
  default: { mode: 'superadmin' },
  sites: {
    'reporting.nrpi.local': { mode: 'groups', groups: ['SaaS-Reporting-Users', 'SaaS-Reporting-Admins'], label: 'Reporting' },
    'open.nrpi.local': { mode: 'authenticated', label: 'Open' },
  },
};

function fakeSiteAccess(policy) {
  return {
    POLICY_PATH: '/nonexistent',
    normHost: function (h) { return String(h || '').replace(/:\d+$/, '').replace(/\.$/, '').toLowerCase(); },
    decide: function (host, email, groups) {
      const site = policy.sites[host] || policy.default;
      if (site.mode === 'authenticated') return { allow: true, reason: 'authenticated', mode: site.mode };
      if (groups == null) return { allow: false, reason: 'session-predates-policy', mode: site.mode };
      const want = site.mode === 'groups' ? site.groups : policy.superadmin_groups;
      const have = groups.map(function (g) { return g.toLowerCase(); });
      const hit = want.some(function (g) { return have.indexOf(g.toLowerCase()) !== -1; });
      if (hit) return { allow: true, reason: 'group-match', mode: site.mode };
      return { allow: false, reason: site.mode === 'groups' ? 'not-in-allowed-group' : 'superadmin-only', mode: site.mode };
    },
  };
}

function fakeSession(table) {
  return {
    verifySessionToken: function (tok) { return table[tok] || { ok: false }; },
  };
}

// An in-memory stand-in for the three things the router asks the pool for.
function fakePool(opts) {
  opts = opts || {};
  const state = {
    ledger: [], audit: [], locks: new Set(), lockCalls: 0, releases: 0,
    pages: opts.pages || [{ page_key: 'itam-settings', display_name: 'ITAM Settings', access_policy: 'matrix' },
                           { page_key: 'rbac-admin', display_name: 'Access Admin', access_policy: 'matrix' }],
    roles: opts.roles || [
      { role_key: 'tier1', display_name: 'Tier 1', ad_group_dn: 'CN=SaaS-ITH-T1,OU=G,DC=x', default_access: 'read' },
      { role_key: 'tier2', display_name: 'Tier 2', ad_group_dn: 'CN=SaaS-ITH-T2,OU=G,DC=x', default_access: 'admin' },
      { role_key: 'nogroup', display_name: 'Legacy', ad_group_dn: null, default_access: 'admin' },
    ],
    rolePages: opts.rolePages || [{ role_key: 'tier1', page_key: 'itam-settings', access_level: 'none' }],
    userRoles: opts.userRoles || [],
    insertFails: !!opts.insertFails,
    nextId: 1,
  };
  function run(sql, params) {
    sql = sql.replace(/\s+/g, ' ').trim();
    if (/^SELECT page_key, display_name, access_policy FROM rbac_pages/.test(sql)) {
      return [state.pages.filter(function (p) { return p.page_key === params[0]; })];
    }
    if (/^SELECT role_key FROM rbac_user_roles/.test(sql)) return [state.userRoles.map(function (r) { return { role_key: r }; })];
    if (/^SELECT role_key, display_name, ad_group_dn, default_access FROM rbac_roles/.test(sql)) {
      return [state.roles.filter(function (r) { return r.ad_group_dn; })];
    }
    if (/^SELECT role_key, access_level FROM rbac_role_pages/.test(sql)) {
      return [state.rolePages.filter(function (r) { return r.page_key === params[0]; })];
    }
    if (/^SELECT id, created_at, sdp_id, sdp_display_id FROM access_requests/.test(sql)) {
      const rows = state.ledger.filter(function (r) {
        return r.requester_email === params[0] && r.kind === params[1] && r.target === params[2] && r.need_key === params[3];
      });
      return [rows.slice(-1)];
    }
    if (/^SELECT COUNT\(\*\) AS n FROM access_requests/.test(sql)) {
      return [[{ n: state.ledger.filter(function (r) { return r.requester_email === params[0]; }).length }]];
    }
    if (/^SELECT GET_LOCK/.test(sql)) {
      state.lockCalls++;
      if (state.locks.has(params[0])) return [[{ got: 0 }]];
      state.locks.add(params[0]); return [[{ got: 1 }]];
    }
    if (/^SELECT RELEASE_LOCK/.test(sql)) { state.releases++; state.locks.delete(params[0]); return [[{ r: 1 }]]; }
    if (/^INSERT INTO access_requests/.test(sql)) {
      if (state.insertFails) throw new Error('db down');
      state.ledger.push({
        id: state.nextId++, created_at: new Date(), requester_email: params[0], requester_name: params[1], kind: params[2],
        target: params[3], need_key: params[4], need_text: params[5], path: params[6], reason: params[7],
        sdp_id: params[8], sdp_display_id: params[9], sdp_url: params[10],
      });
      return [{}];
    }
    if (/^INSERT INTO rbac_audit_log/.test(sql)) { state.audit.push({ action: params[1], details: params[4] && JSON.parse(params[4]) }); return [{}]; }
    throw new Error('unexpected SQL in test: ' + sql);
  }
  const pool = {
    query: async function (sql, p) { return run(sql, p || []); },
    execute: async function (sql, p) { return run(sql, p || []); },
    getConnection: async function () { return { query: pool.query, release: function () {} }; },
  };
  return { pool, state };
}

const SESS = {
  good: { ok: true, email: 'Pat.Lee@Example.com', name: 'Pat Lee', groups: ['Some-Other-Group'] },
  member: { ok: true, email: 'sam@example.com', name: 'Sam', groups: ['saas-reporting-users'] },
  stale: { ok: true, email: 'old@example.com', name: 'Old', groups: undefined },
  sa: { ok: true, email: 'root@example.com', name: 'Root', groups: ['SaaS-ITH-SA'] },
  expired: { ok: false, expired: true },
};

async function boot(over) {
  over = over || {};
  const fp = fakePool(over.pool);
  const tickets = [];
  const dep = {
    pool: fp.pool,
    sessionAuth: fakeSession(SESS_TABLE),
    siteAccess: fakeSiteAccess(over.policy || POLICY),
    getPolicy: function () { return over.policy || POLICY; },
    createTicket: over.createTicket || (async function (a) { tickets.push(a); return { id: '9000' + tickets.length, display_id: String(1000 + tickets.length), url: 'https://sdp/x' }; }),
    getRequestById: over.getRequestById || (async function () { return { id: '1', display_id: '1', status: 'Open' }; }),
    effectiveLevel: over.effectiveLevel || (async function (email, roles, pageKey) {
      if (pageKey === 'rbac-admin') return 'none';
      let lvl = 'none';
      const rank = { none: 0, read: 1, admin: 2 };
      fp.state.roles.forEach(function (r) {
        if (roles.indexOf(r.role_key) === -1) return;
        const exc = fp.state.rolePages.find(function (x) { return x.role_key === r.role_key && x.page_key === pageKey; });
        const eff = exc ? exc.access_level : r.default_access;
        if (rank[eff] > rank[lvl]) lvl = eff;
      });
      return lvl;
    }),
    dryRun: over.dryRun || function () { return false; },
    now: function () { return new Date('2026-10-09T18:00:00Z'); },
  };
  const app = express();
  app.use(express.json());
  app.set('trust proxy', false);
  app.use('/api/access-request', mod.create(dep));
  const server = await new Promise(function (r) { const s = app.listen(0, '127.0.0.1', function () { r(s); }); });
  const port = server.address().port;
  function call(method, path, o) {
    o = o || {};
    return new Promise(function (resolve, reject) {
      const headers = Object.assign({ host: o.host || 'reporting.nrpi.local' }, o.headers || {});
      if (o.cookie) headers.cookie = o.cookie;
      let data = null;
      if (o.body) { data = JSON.stringify(o.body); headers['content-type'] = 'application/json'; headers['content-length'] = Buffer.byteLength(data); }
      const req = http.request({ host: '127.0.0.1', port, method, path, headers }, function (res) {
        let buf = ''; res.on('data', function (c) { buf += c; });
        res.on('end', function () { let j = null; try { j = JSON.parse(buf); } catch (e) { /* not json */ } resolve({ status: res.statusCode, json: j, headers: res.headers }); });
      });
      req.on('error', reject); if (data) req.write(data); req.end();
    });
  }
  return { call, fp, tickets, close: function () { server.close(); } };
}
const SESS_TABLE = { good: SESS.good, member: SESS.member, stale: SESS.stale, sa: SESS.sa, expired: SESS.expired };
const SAME = { 'sec-fetch-site': 'same-origin' };

// ---- pure helpers -----------------------------------------------------------------------------------------------
test('groupNameOf pulls the CN out of a DN and leaves plain names alone', function () {
  assert.equal(mod.groupNameOf('CN=SaaS-ITH-T1,OU=Groups,DC=corp,DC=local'), 'SaaS-ITH-T1');
  assert.equal(mod.groupNameOf('CN=Smith\\, Team,OU=G'), 'Smith, Team');
  assert.equal(mod.groupNameOf('Plain-Group'), 'Plain-Group');
});

test('siteNeed: groups mode lists the groups; other modes fall to the super-admin groups; empty policy falls back', function () {
  assert.deepEqual(mod.siteNeed(POLICY, 'reporting.nrpi.local').groups, ['SaaS-Reporting-Users', 'SaaS-Reporting-Admins']);
  assert.deepEqual(mod.siteNeed(POLICY, 'nowhere.nrpi.local').groups, ['SaaS-ITH-SA']);
  assert.deepEqual(mod.siteNeed(null, 'x').groups, ['SaaS-ITH-SA']);
});

test('buildTicket escapes everything it did not write itself', function () {
  const t = mod.buildTicket({
    kind: 'site', target: { label: '<b>Evil</b>', host: 'a.nrpi.local', key: 'a.nrpi.local' },
    need: { groups: ['G<1>', 'G2'] }, refusal: 'no',
  }, { email: 'x@y.z', name: '"><script>' }, '/p?<x>', new Date('2026-10-09T00:00:00Z'));
  assert.ok(!/<script>/.test(t.description));
  assert.ok(t.description.indexOf('&lt;script&gt;') !== -1);
  assert.ok(t.description.indexOf('G&lt;1&gt;') !== -1);
  assert.ok(t.subject.length <= 250);
});

// ---- context ----------------------------------------------------------------------------------------------------
test('context: no cookie is 401 SIGN_IN_REQUIRED, expired cookie is SESSION_EXPIRED', async function () {
  const a = await boot();
  try {
    let r = await a.call('GET', '/api/access-request/context?kind=site');
    assert.equal(r.status, 401); assert.equal(r.json.error, 'SIGN_IN_REQUIRED');
    r = await a.call('GET', '/api/access-request/context?kind=site', { cookie: 'it_session=expired' });
    assert.equal(r.status, 401); assert.equal(r.json.error, 'SESSION_EXPIRED');
  } finally { a.close(); }
});

test('context (site): a person outside the groups gets ready + the group names; response is no-store', async function () {
  const a = await boot();
  try {
    const r = await a.call('GET', '/api/access-request/context?kind=site', { cookie: 'it_session=good' });
    assert.equal(r.status, 200);
    assert.equal(r.json.state, 'ready');
    assert.deepEqual(r.json.need.groups, ['SaaS-Reporting-Users', 'SaaS-Reporting-Admins']);
    assert.equal(r.json.need.any_of, true);
    assert.equal(r.json.target.label, 'Reporting');
    assert.equal(r.json.user.email, 'pat.lee@example.com');
    assert.match(r.headers['cache-control'], /no-store/);
    assert.equal(r.json.dry_run, false);
  } finally { a.close(); }
});

test('context (site): someone who is allowed is told so; a pre-policy token is told to sign in again', async function () {
  const a = await boot();
  try {
    let r = await a.call('GET', '/api/access-request/context?kind=site', { cookie: 'it_session=member' });
    assert.equal(r.json.state, 'allowed');
    r = await a.call('GET', '/api/access-request/context?kind=site', { cookie: 'it_session=stale' });
    assert.equal(r.json.state, 'stale-session');
    assert.equal(r.json.need, undefined);
  } finally { a.close(); }
});

test('context (site): the host comes from the Host header, never from the query string', async function () {
  const a = await boot();
  try {
    const r = await a.call('GET', '/api/access-request/context?kind=site&host=open.nrpi.local', { cookie: 'it_session=good' });
    assert.equal(r.json.target.key, 'reporting.nrpi.local');
    const bad = await a.call('GET', '/api/access-request/context?kind=site', { cookie: 'it_session=good', host: 'bad host!' });
    assert.equal(bad.status, 400);
  } finally { a.close(); }
});

test('context (site): a policy with no usable group is reported unavailable, not as a button that files nothing', async function () {
  const a = await boot({ policy: { superadmin_groups: [], default: { mode: 'groups', groups: [] }, sites: { 'reporting.nrpi.local': { mode: 'groups', groups: [], label: 'R' } } } });
  try {
    const r = await a.call('GET', '/api/access-request/context?kind=site', { cookie: 'it_session=good' });
    // superadmin_groups empty falls back to SaaS-ITH-SA only for non-groups modes; a groups-mode site with no groups has none
    assert.equal(r.json.state, 'unavailable');
  } finally { a.close(); }
});

test('context (app): closest-fit group first, roles without an AD group never offered, ticket not created', async function () {
  const a = await boot();
  try {
    const r = await a.call('GET', '/api/access-request/context?kind=app&page=itam-settings&level=read', { cookie: 'it_session=good' });
    assert.equal(r.json.state, 'ready');
    // tier1 has an explicit "none" for this page, so only tier2 grants read; the AD-less role is skipped
    assert.deepEqual(r.json.need.groups, ['SaaS-ITH-T2']);
    assert.equal(r.json.target.label, 'ITAM Settings');
    assert.equal(a.tickets.length, 0);
  } finally { a.close(); }
});

test('context (app): validates page + level; unknown page is 404', async function () {
  const a = await boot();
  try {
    assert.equal((await a.call('GET', '/api/access-request/context?kind=app&page=../x', { cookie: 'it_session=good' })).json.error, 'BAD_PAGE');
    assert.equal((await a.call('GET', '/api/access-request/context?kind=app&page=itam-settings&level=none', { cookie: 'it_session=good' })).json.error, 'BAD_LEVEL');
    const r = await a.call('GET', '/api/access-request/context?kind=app&page=no-such-page', { cookie: 'it_session=good' });
    assert.equal(r.status, 404); assert.equal(r.json.error, 'UNKNOWN_PAGE');
  } finally { a.close(); }
});

test('context (app): already holding the level = allowed; a super-admin role = allowed; hard-excluded page asks for the super-admin group', async function () {
  const a = await boot({ pool: { userRoles: ['tier2'] } });
  try {
    let r = await a.call('GET', '/api/access-request/context?kind=app&page=itam-settings&level=admin', { cookie: 'it_session=good' });
    assert.equal(r.json.state, 'allowed');
    r = await a.call('GET', '/api/access-request/context?kind=app&page=rbac-admin&level=read', { cookie: 'it_session=good' });
    assert.equal(r.json.state, 'ready');
    assert.deepEqual(r.json.need.groups, ['SaaS-ITH-SA']);
  } finally { a.close(); }
  const b = await boot({ pool: { userRoles: ['superadmin'] } });
  try {
    const r = await b.call('GET', '/api/access-request/context?kind=app&page=rbac-admin&level=admin', { cookie: 'it_session=good' });
    assert.equal(r.json.state, 'allowed');
  } finally { b.close(); }
});

test('context (app): holding read but needing admin says so', async function () {
  const a = await boot({ pool: { userRoles: ['tier1'], rolePages: [] } });
  try {
    const r = await a.call('GET', '/api/access-request/context?kind=app&page=itam-settings&level=admin', { cookie: 'it_session=good' });
    assert.equal(r.json.state, 'ready');
    assert.match(r.json.refusal, /not at the level/);
    assert.deepEqual(r.json.need.groups, ['SaaS-ITH-T2']);
  } finally { a.close(); }
});

// ---- file -------------------------------------------------------------------------------------------------------
test('file: refuses without a positive same-origin signal', async function () {
  const a = await boot();
  try {
    let r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', body: { kind: 'site' } });
    assert.equal(r.status, 403); assert.equal(r.json.error, 'CSRF_ORIGIN_REQUIRED');
    r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', body: { kind: 'site' }, headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(r.status, 403);
    r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', body: { kind: 'site' }, headers: { origin: 'http://reporting.nrpi.local' } });
    assert.equal(r.status, 403);
    r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', body: { kind: 'site' }, headers: { origin: 'https://evil.example' } });
    assert.equal(r.status, 403);
    assert.equal(a.tickets.length, 0);
  } finally { a.close(); }
});

test('file: no session is 401 and nothing is filed', async function () {
  const a = await boot();
  try {
    const r = await a.call('POST', '/api/access-request/file', { body: { kind: 'site' }, headers: SAME });
    assert.equal(r.status, 401); assert.equal(a.tickets.length, 0);
  } finally { a.close(); }
});

test('file (site): files ONE ticket built server-side from the verified session; the body cannot supply identity or text', async function () {
  const a = await boot();
  try {
    const r = await a.call('POST', '/api/access-request/file', {
      cookie: 'it_session=good', headers: Object.assign({ origin: 'https://reporting.nrpi.local' }, {}),
      body: { kind: 'site', path: '/dashboards/q3?x=1', requesterEmail: 'boss@example.com', group: 'SaaS-ITH-SA', description: 'pwned', subject: 'pwned' },
    });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.equal(r.json.state, 'filed');
    assert.equal(r.json.ticket.display_id, '1001');
    assert.equal(a.tickets.length, 1);
    const t = a.tickets[0];
    assert.equal(t.requesterEmail, 'pat.lee@example.com');
    assert.equal(t.requesterName, 'Pat Lee');
    assert.equal(t.category, 'Identity & Access');
    assert.equal(t.subcategory, 'Access Request / Permissions');
    assert.match(t.subject, /Reporting \(reporting\.nrpi\.local\).*SaaS-Reporting-Users/);
    assert.match(t.description, /SaaS-Reporting-Users/);
    assert.match(t.description, /SaaS-Reporting-Admins/);
    assert.match(t.description, /any one/);
    assert.match(t.description, /\/dashboards\/q3</);              // pathname kept, query dropped
    assert.ok(t.description.indexOf('x=1') === -1);
    assert.ok(t.description.indexOf('pwned') === -1);
    assert.ok(t.description.indexOf('SaaS-ITH-SA') === -1);
    assert.equal(a.fp.state.ledger.length, 1);
    assert.equal(a.fp.state.ledger[0].requester_email, 'pat.lee@example.com');
    assert.ok(a.fp.state.audit.some(function (x) { return x.action === 'access_request_filed'; }));
    assert.equal(a.fp.state.releases, 1);
  } finally { a.close(); }
});

test('file: pressing again while the ticket is open files nothing and returns the existing number', async function () {
  const a = await boot();
  try {
    const opts = { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } };
    const first = await a.call('POST', '/api/access-request/file', opts);
    const second = await a.call('POST', '/api/access-request/file', opts);
    assert.equal(first.json.state, 'filed');
    assert.equal(second.json.state, 'already');
    assert.equal(second.json.ticket.display_id, first.json.ticket.display_id);
    assert.equal(a.tickets.length, 1);
    // the context endpoint now reports the same thing, so the page opens on "already requested"
    const ctx = await a.call('GET', '/api/access-request/context?kind=site', { cookie: 'it_session=good' });
    assert.equal(ctx.json.state, 'already');
    assert.equal(ctx.json.ticket.display_id, first.json.ticket.display_id);
    assert.equal(ctx.json.ticket.status, 'Open');
    assert.equal(JSON.stringify(ctx.json).indexOf('sdp/x'), -1);   // the SDP link is not exposed
  } finally { a.close(); }
});

test('file: a closed earlier ticket does not block a new request', async function () {
  let status = 'Open';
  const a = await boot({ getRequestById: async function () { return { id: '1', status: status }; } });
  try {
    const opts = { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } };
    await a.call('POST', '/api/access-request/file', opts);
    status = 'Closed';
    const r = await a.call('POST', '/api/access-request/file', opts);
    assert.equal(r.json.state, 'filed');
    assert.equal(a.tickets.length, 2);
  } finally { a.close(); }
});

test('file: a ticket SDP no longer has (404 -> null) is not open; an SDP outage is treated as still open (no duplicate)', async function () {
  let mode = 'gone';
  const a = await boot({ getRequestById: async function () { if (mode === 'gone') return null; throw new Error('SDP 503'); } });
  try {
    const opts = { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } };
    await a.call('POST', '/api/access-request/file', opts);
    let r = await a.call('POST', '/api/access-request/file', opts);
    assert.equal(r.json.state, 'filed'); assert.equal(a.tickets.length, 2);
    mode = 'down';
    r = await a.call('POST', '/api/access-request/file', opts);
    assert.equal(r.json.state, 'already');
    assert.equal(r.json.ticket.verified, false);
    assert.equal(r.json.ticket.status, null);
    assert.equal(a.tickets.length, 2);
  } finally { a.close(); }
});

test('file: a ticket older than the window no longer counts', async function () {
  const a = await boot();
  try {
    const opts = { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } };
    await a.call('POST', '/api/access-request/file', opts);
    a.fp.state.ledger.length = 0;     // the SQL window (created_at > now - 45d) is the database's job; an empty result is "not open"
    const r = await a.call('POST', '/api/access-request/file', opts);
    assert.equal(r.json.state, 'filed');
  } finally { a.close(); }
});

test('file: SDP failure is an honest 502 with no ledger row and no success shape', async function () {
  const a = await boot({ createTicket: async function () { throw new Error('SDP 500'); } });
  try {
    const r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } });
    assert.equal(r.status, 502); assert.equal(r.json.error, 'FILING_FAILED');
    assert.equal(r.json.state, undefined); assert.equal(r.json.ticket, undefined);
    assert.equal(a.fp.state.ledger.length, 0);
    assert.ok(a.fp.state.audit.some(function (x) { return x.action === 'access_request_failed'; }));
    assert.equal(a.fp.state.releases, 1);
  } finally { a.close(); }
});

test('file: SDP answering without an id is a failure, not a success', async function () {
  const a = await boot({ createTicket: async function () { return {}; } });
  try {
    const r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } });
    assert.equal(r.status, 502);
    assert.equal(a.fp.state.ledger.length, 0);
  } finally { a.close(); }
});

test('file: ledger insert failing AFTER the ticket exists still tells the truth (filed) and keeps the lock tidy', async function () {
  const a = await boot({ pool: { insertFails: true } });
  try {
    const r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } });
    assert.equal(r.status, 200); assert.equal(r.json.state, 'filed');
    assert.equal(a.tickets.length, 1);
    assert.equal(a.fp.state.releases, 1);
  } finally { a.close(); }
});

test('file: a lock held by a concurrent press is a 503 BUSY, never a second ticket', async function () {
  const a = await boot();
  try {
    // pre-hold the exact lock the route will ask for by running one request with the pool pausing inside createTicket
    let release; const hold = new Promise(function (r) { release = r; });
    a.fp.state.locks.clear();
    const slow = await boot({ createTicket: async function () { await hold; return { id: '77', display_id: '77' }; } });
    const opts = { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } };
    const p1 = slow.call('POST', '/api/access-request/file', opts);
    await new Promise(function (r) { setTimeout(r, 80); });
    // the fake lock answers instantly (no 5 s wait), so the second press sees got=0
    const p2 = await slow.call('POST', '/api/access-request/file', opts);
    assert.equal(p2.status, 503); assert.equal(p2.json.error, 'BUSY');
    release();
    const r1 = await p1;
    assert.equal(r1.json.state, 'filed');
    assert.equal(slow.fp.state.ledger.length, 1);
    slow.close();
  } finally { a.close(); }
});

test('file: a person cannot cause more than 5 new tickets an hour', async function () {
  const a = await boot();
  try {
    for (let i = 0; i < 5; i++) {
      a.fp.state.ledger.push({ requester_email: 'pat.lee@example.com', kind: 'site', target: 'other' + i, need_key: 'k' + i, created_at: new Date(), sdp_id: 'x', sdp_display_id: 'x' });
    }
    const r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } });
    assert.equal(r.status, 429); assert.equal(r.json.error, 'TOO_MANY_REQUESTS');
    assert.equal(a.tickets.length, 0);
  } finally { a.close(); }
});

test('file: already-allowed and stale-session people are told so and nothing is filed', async function () {
  const a = await boot();
  try {
    let r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=member', headers: SAME, body: { kind: 'site' } });
    assert.equal(r.json.state, 'allowed');
    r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=stale', headers: SAME, body: { kind: 'site' } });
    assert.equal(r.json.state, 'stale-session');
    assert.equal(a.tickets.length, 0);
  } finally { a.close(); }
});

test('file (app): the ticket names the page, the level and the groups that grant it', async function () {
  const a = await boot();
  try {
    const r = await a.call('POST', '/api/access-request/file', {
      cookie: 'it_session=good', headers: SAME, body: { kind: 'app', page: 'itam-settings', level: 'admin' } });
    assert.equal(r.json.state, 'filed');
    const t = a.tickets[0];
    assert.match(t.subject, /ITAM Settings \(admin access\).*SaaS-ITH-T2/);
    assert.match(t.description, /page key itam-settings/);
    assert.match(t.description, /SaaS-ITH-T2/);
    assert.ok(a.fp.state.audit.some(function (x) { return x.action === 'access_request_filed'; }));
  } finally { a.close(); }
});

test('dry run: nothing reaches SDP or the ledger, the audit says so, and the answer is labelled', async function () {
  const a = await boot({ dryRun: function () { return true; } });
  try {
    const ctx = await a.call('GET', '/api/access-request/context?kind=site', { cookie: 'it_session=good' });
    assert.equal(ctx.json.dry_run, true);
    const r = await a.call('POST', '/api/access-request/file', { cookie: 'it_session=good', headers: SAME, body: { kind: 'site' } });
    assert.equal(r.json.state, 'filed'); assert.equal(r.json.dry_run, true);
    assert.equal(r.json.ticket.display_id, 'PRACTICE');
    assert.equal(a.tickets.length, 0); assert.equal(a.fp.state.ledger.length, 0);
    assert.ok(a.fp.state.audit.some(function (x) { return x.action === 'access_request_dryrun'; }));
  } finally { a.close(); }
});

test('sessionOf: tries every it_session value and decodes them', function () {
  const sa = { verifySessionToken: function (t) { return t === 'second' ? { ok: true, email: 'A@B.C', name: null, groups: [] } : { ok: false }; } };
  const s = mod.sessionOf({ headers: { cookie: 'a=1; it_session=first; it_session=sec%6Fnd', host: 'h' } }, sa);
  assert.equal(s.ok, true); assert.equal(s.email, 'a@b.c');
  assert.equal(mod.sessionOf({ headers: {} }, sa).ok, false);
});
