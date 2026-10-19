// cron-token.test.js -- unit tests for the constant-time X-Cron-Token check.
//
//   cd /var/www/corpit-hub-api && node --test cron-token.test.js
//
// Pure logic, no .env and no network: the module only needs node's crypto.
const test = require('node:test');
const assert = require('node:assert/strict');
const make = require('./cron-token');

const SECRET = 'a'.repeat(31) + 'b' + 'c'.repeat(32);   // 64 chars, like the real token

test('accepts exactly the configured secret', () => {
  assert.equal(make(SECRET)(SECRET), true);
});

test('rejects a same-length token that differs in one byte', () => {
  const ok = make(SECRET);
  assert.equal(ok('a'.repeat(32) + 'c'.repeat(32)), false);
  assert.equal(ok(SECRET.slice(0, 63) + 'd'), false);
});

test('rejects a prefix, a superset and the empty string without throwing', () => {
  const ok = make(SECRET);
  assert.equal(ok(SECRET.slice(0, 40)), false);
  assert.equal(ok(SECRET + 'x'), false);
  assert.equal(ok(''), false);
});

test('rejects non-string headers', () => {
  const ok = make(SECRET);
  assert.equal(ok(undefined), false);
  assert.equal(ok(null), false);
  assert.equal(ok(['x']), false);
  assert.equal(ok(42), false);
});

test('an unset or empty secret disables the path entirely', () => {
  for (const s of ['', undefined, null]) {
    const ok = make(s);
    assert.equal(ok(''), false);
    assert.equal(ok('anything'), false);
  }
});
