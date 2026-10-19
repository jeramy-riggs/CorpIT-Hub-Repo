'use strict';
// Request-local correlation only. Never a session token or an identity supplied by a client.
const {AsyncLocalStorage} = require('async_hooks');
const {randomUUID} = require('crypto');
const storage = new AsyncLocalStorage();
function run(req, res, next) {
  const requestId = randomUUID();
  req.activityRequestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  return storage.run({requestId, req}, next);
}
function current() { return storage.getStore() || {}; }
module.exports = {run, current};
