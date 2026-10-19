'use strict';
// MP-SIGNIN (2026-10-07): host-scoped sessions + My Profile sign-in helpers.
// Run: node --test mp-signin.test.js   (needs no network, no directory, no real secret)

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'mp-signin-test-'));
process.env.RBAC_SESSION_SECRET = 'test-secret-' + crypto.randomBytes(16).toString('hex');
process.env.SESSION_REVOKE_FILE = path.join(TMP, 'revoked-sessions.json');
process.env.MP_SIGNIN_CONFIG = path.join(TMP, 'myprofile-signin.json');
process.env.MP_SIGNIN_TEST_EXPORTS = '1';

const test = require('node:test');
const assert = require('node:assert');
const sessionAuth = require('./session-auth');
const adGroups = require('./ad-groups');
const mp = require('./mp-signin');

const MP = 'myprofile.nrpi.local';

function b64urlDecode(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Buffer.from(s, 'base64'); }
function b64url(b) { return Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function payloadOf(tok) { return JSON.parse(b64urlDecode(tok.split('.')[0]).toString('utf8')); }
function masterSign(payloadObj) {
  const raw = JSON.stringify(payloadObj);
  return b64url(raw) + '.' + b64url(crypto.createHmac('sha256', process.env.RBAC_SESSION_SECRET).update(raw).digest());
}

test('scoped token verifies only on its own host', function () {
  const t = sessionAuth.mintSessionToken('a.user@auction.com', 'A User', ['g1'], { scope: MP });
  assert.ok(t);
  assert.strictEqual(payloadOf(t).scp, MP);
  const ok = sessionAuth.verifySessionToken(t, { host: MP });
  assert.strictEqual(ok.ok, true);
  assert.strictEqual(ok.scope, MP);
  assert.deepStrictEqual(ok.groups, ['g1']);
  assert.strictEqual(sessionAuth.verifySessionToken(t, { host: 'MyProfile.nrpi.local:443' }).ok, true);
  assert.deepStrictEqual(sessionAuth.verifySessionToken(t, { host: 'corpit.nrpi.local' }), { ok: false });
  assert.deepStrictEqual(sessionAuth.verifySessionToken(t), { ok: false });              // no host = refused
  assert.deepStrictEqual(sessionAuth.verifySessionToken(t, { host: '' }), { ok: false });
});

test('scoped token fails under the master key (old verifiers reject it)', function () {
  const t = sessionAuth.mintSessionToken('a.user@auction.com', 'A User', null, { scope: MP });
  const [body, sig] = t.split('.');
  const masterSig = crypto.createHmac('sha256', process.env.RBAC_SESSION_SECRET).update(b64urlDecode(body)).digest();
  assert.notStrictEqual(b64url(masterSig), sig);
});

test('scope cannot be added to or stripped from a token', function () {
  const plain = sessionAuth.mintSessionToken('b@auction.com', 'B', null);
  const p = payloadOf(plain);
  // add scp to a platform token, keep its master signature
  const forgedAdd = b64url(JSON.stringify(Object.assign({}, p, { scp: MP }))) + '.' + plain.split('.')[1];
  assert.strictEqual(sessionAuth.verifySessionToken(forgedAdd, { host: MP }).ok, false);
  // strip scp from a scoped token, keep its derived signature
  const scoped = sessionAuth.mintSessionToken('b@auction.com', 'B', null, { scope: MP });
  const sp = payloadOf(scoped); delete sp.scp;
  const forgedStrip = b64url(JSON.stringify(sp)) + '.' + scoped.split('.')[1];
  assert.strictEqual(sessionAuth.verifySessionToken(forgedStrip, { host: 'corpit.nrpi.local' }).ok, false);
  // master-signed payload claiming a scope: wrong key for that scope
  const masterScoped = masterSign(Object.assign({}, p, { scp: MP }));
  assert.strictEqual(sessionAuth.verifySessionToken(masterScoped, { host: MP }).ok, false);
  // malformed scp values
  for (const bad of ['', 1, null, ['x']]) {
    assert.strictEqual(sessionAuth.verifySessionToken(masterSign(Object.assign({}, p, { scp: bad })), { host: MP }).ok, false);
  }
});

test('platform tokens are unchanged: no scp, any host, scope null', function () {
  const t = sessionAuth.mintSessionToken('c@auction.com', 'C', ['x']);
  assert.ok(!('scp' in payloadOf(t)));
  for (const h of [undefined, 'corpit.nrpi.local', MP]) {
    const r = sessionAuth.verifySessionToken(t, h === undefined ? undefined : { host: h });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.scope, null);
  }
});

test('asking for an empty scope never yields a platform token', function () {
  assert.strictEqual(sessionAuth.mintSessionToken('d@auction.com', 'D', null, { scope: '' }), null);
  assert.strictEqual(sessionAuth.mintSessionToken('d@auction.com', 'D', null, { scope: '  ' }), null);
});

test('renewal carries the scope and the cap anchor', function () {
  const t = sessionAuth.mintSessionToken('e@auction.com', 'E', ['g'], { scope: MP });
  const prior = sessionAuth.verifySessionToken(t, { host: MP });
  const again = sessionAuth.mintSessionToken(prior.email, prior.name, prior.groups,
                                             { ait: prior.absAit, scope: prior.scope || undefined });
  const r = sessionAuth.verifySessionToken(again, { host: MP });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.scope, MP);
  assert.strictEqual(r.absAit, prior.absAit);
  assert.strictEqual(sessionAuth.verifySessionToken(again, { host: 'corpit.nrpi.local' }).ok, false);
});

test('logout revokes a scoped token only when given its host', function () {
  const t = sessionAuth.mintSessionToken('f@auction.com', 'F', null, { scope: MP });
  assert.strictEqual(sessionAuth.revokeTokenForLogout(t, { host: MP }), true);
  assert.strictEqual(sessionAuth.verifySessionToken(t, { host: MP }).revoked, true);
});

test('accountExpires parsing', function () {
  const f = adGroups._t.accountExpiresMs;
  assert.strictEqual(f('0'), null);
  assert.strictEqual(f('9223372036854775807'), null);
  assert.strictEqual(f(undefined), null);
  assert.ok(Number.isNaN(f('abc')));
  // 2020-01-01T00:00:00Z as FILETIME
  assert.strictEqual(f('132223104000000000'), Date.UTC(2020, 0, 1));
});

test('return target stays on this host', function () {
  const rp = mp._t.returnPath, O = 'https://' + MP;
  assert.strictEqual(rp('/', O), '/');
  assert.strictEqual(rp('/my-profile.html?tab=ai', O), '/my-profile.html?tab=ai');
  assert.strictEqual(rp(O + '/x', O), '/x');
  assert.strictEqual(rp('https://corpit.nrpi.local/x', O), '/');
  assert.strictEqual(rp('http://' + MP + '/x', O), '/');
  assert.strictEqual(rp('//evil.example/x', O), '/');
  assert.strictEqual(rp('/\t/evil.example', O), '/');
  assert.strictEqual(rp('/\\evil.example', O), '/');
  assert.strictEqual(rp('/..//evil.example', O), '/');
  assert.strictEqual(rp('javascript:alert(1)', O), '/');
  assert.strictEqual(rp('', O), '/');
});

test('transaction cookie: round-trips, rejects tampering and expiry', function () {
  const sealed = mp._t.sealTx({ state: 's', ts: Date.now() });
  assert.strictEqual(mp._t.openTx(sealed).state, 's');
  const [body, sig] = sealed.split('.');
  const evil = b64url(JSON.stringify({ state: 'x', ts: Date.now() }));
  assert.strictEqual(mp._t.openTx(evil + '.' + sig), null);
  assert.strictEqual(mp._t.openTx(body), null);
  assert.strictEqual(mp._t.openTx(mp._t.sealTx({ state: 's', ts: Date.now() - 11 * 60 * 1000 })), null);
  // an oidc-auth-style transaction (sealed with the master key) is not accepted here
  const masterSealed = body + '.' + b64url(crypto.createHmac('sha256', process.env.RBAC_SESSION_SECRET).update(body).digest());
  assert.strictEqual(mp._t.openTx(masterSealed), null);
});

test('config: absent or incomplete = shut; valid = parsed', function () {
  const file = process.env.MP_SIGNIN_CONFIG;
  try { fs.unlinkSync(file); } catch (e) {}
  assert.strictEqual(mp._t.config(), null);
  fs.writeFileSync(file, JSON.stringify({ tenant_id: 'not-a-guid', client_id: 'x', client_secret: 's', hosts: [MP] }));
  assert.strictEqual(mp._t.config(), null);
  const good = { tenant_id: 'ED594306-0406-4bba-b9b0-05b769fd1508', client_id: 'b6eb3715-c953-46eb-9dc6-47fd6416516f',
                 client_secret: 'x', hosts: ['MyProfile.nrpi.local.'] };
  // a different size guarantees the mtime+size cache key changes
  fs.writeFileSync(file, JSON.stringify(good) + '\n');
  const c = mp._t.config();
  assert.ok(c);
  assert.deepStrictEqual(c.hosts, [MP]);
  assert.strictEqual(c.tenant, 'ed594306-0406-4bba-b9b0-05b769fd1508');
});

test('host comes from Host, never X-Forwarded-Host', function () {
  assert.strictEqual(mp._t.hostOf({ headers: { host: 'MyProfile.nrpi.local:443', 'x-forwarded-host': 'corpit.nrpi.local' } }), MP);
});

test.after(function () { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (e) {} });
