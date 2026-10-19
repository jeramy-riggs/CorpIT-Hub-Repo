'use strict';
// cron-token.js -- constant-time check of the X-Cron-Token header (CHG-ARCH-08, 2026-09-23).
//
// The internal sync endpoints in server.js's API_CRON set accept a shared secret
// instead of a session. Comparing that secret with `===` returns at the first
// byte that differs, so the time a request takes leaks how much of the token the
// caller has right -- measurable on the loopback path these endpoints exist for.
// Both sides are hashed to a fixed 32 bytes first, so the comparison takes the
// same time for any input length and never throws on a length mismatch.
//
//   const cronTokenOk = require('./cron-token')(process.env.CRON_TOKEN);
//   if (cronTokenOk(req.get('x-cron-token'))) { ... }
//
// An empty or unset secret disables the path: cronTokenOk() is then always false.
const crypto = require('crypto');

function digest(s) { return crypto.createHash('sha256').update(String(s), 'utf8').digest(); }

module.exports = function makeCronTokenCheck(secret) {
  const expected = (typeof secret === 'string' && secret !== '') ? digest(secret) : null;
  return function cronTokenOk(given) {
    if (!expected || typeof given !== 'string' || given === '') return false;
    return crypto.timingSafeEqual(digest(given), expected);
  };
};
