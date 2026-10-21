'use strict';
// ldap-secure.js — the one way hub code makes an ldapjs client.
//
// Why: every directory call binds with the service account password, and the
// hub talks to the DC by IP on ldap://...:389. A plain ldapjs client sends that
// bind in cleartext. This wrapper guarantees the password only ever goes over a
// verified TLS channel:
//
//   ldap://  -> StartTLS on the same connection, then the bind. The first
//               bind() on a socket runs client.starttls() first (ldapjs queues
//               it until 'connect'); the real bind is only sent after the TLS
//               handshake has completed and the peer cert verified.
//   ldaps:// -> native TLS, same tlsOptions.
//
// TLS is always verified against the NRPI CA chain with the name in
// LDAP_TLS_NAME (default 'nrpi.local' — the domain name every DC cert carries
// in its SAN, since we connect by IP). Callers' tlsOptions (e.g. the old
// rejectUnauthorized:false) are ignored.
//
// Fail closed: if the CA cannot be read, or StartTLS is refused, times out or
// fails verification, bind() calls back with the error, the client is
// destroyed, and no bind request is ever written to the socket. There is no
// plaintext fallback.

const fs   = require('fs');
const path = require('path');
const tls  = require('tls');
const ldap = require('ldapjs');

const CA_PATH  = process.env.LDAP_TLS_CA || path.join(__dirname, 'certs', 'nrpi-ca-chain.pem');
const TLS_NAME = process.env.LDAP_TLS_NAME || 'nrpi.local';

// Read the CA once, at load. A failure is remembered and reported on every bind.
let CA = null;
let caError = null;
try {
  CA = fs.readFileSync(CA_PATH);
  if (!CA.length) throw new Error('empty file');
} catch (e) {
  CA = null;
  caError = new Error(`[ldap-secure] cannot read LDAP CA ${CA_PATH}: ${e.message} — refusing to bind`);
  console.error(caError.message);
}

const TLS_OPTIONS = Object.freeze({
  ca: CA || undefined,
  minVersion: 'TLSv1.2',
  // Connections are by IP, so verify the cert against the domain name instead.
  checkServerIdentity: (_host, cert) => tls.checkServerIdentity(TLS_NAME, cert),
});

const noop = () => {};

function isTls(sock) {
  return !!(sock && sock.encrypted === true && sock.authorized === true);
}

function allLdaps(url) {
  const urls = [].concat(url || []);
  return urls.length > 0 && urls.every(u => /^ldaps:\/\//i.test(String(u)));
}

// Tear the client down after a failed upgrade. A failed StartTLS can leave
// client._socket pointing at a dead TLS socket with no 'error' listener, so a
// later write (the caller's unbind) would otherwise throw an unhandled error.
function abandon(client) {
  for (const s of [client._socket, client._socket && client._socket._parent]) {
    if (s && typeof s.on === 'function') s.on('error', noop);
  }
  try { client.destroy(); } catch (e) { /* ignore */ }
}

function createClient(opts) {
  const o = Object.assign({}, opts);
  // bindDN/bindCredentials make ldapjs auto-bind in its 'setup' hook, which
  // would bypass the StartTLS gate below.
  delete o.bindDN;
  delete o.bindCredentials;
  o.tlsOptions = Object.assign({}, TLS_OPTIONS);

  const client = ldap.createClient(o);
  const nativeTls = allLdaps(o.url);
  const handshakeMs = (parseInt(o.connectTimeout, 10) || 10000) + (parseInt(o.timeout, 10) || 10000);
  const realBind = client.bind.bind(client);
  let failed = null;    // sticky error once an upgrade has failed
  let waiters = null;   // binds waiting on an in-flight StartTLS

  function upgrade(done) {
    if (isTls(client._socket)) return done(null);
    if (waiters) { waiters.push(done); return; }
    waiters = [done];

    let finished = false;
    const finish = (err) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      client.removeListener('connectError', finish);
      if (!err && !isTls(client._socket)) err = new Error('[ldap-secure] StartTLS completed without a verified TLS socket');
      if (err) {
        failed = err;
        abandon(client);
      }
      const list = waiters;
      waiters = null;
      for (const w of list) w(err || null);
    };
    // Same routing ldapjs gives bind(): a connect failure reaches the callback.
    client.on('connectError', finish);
    const timer = setTimeout(() => finish(new Error('[ldap-secure] StartTLS timed out')), handshakeMs);
    try {
      client.starttls(Object.assign({}, TLS_OPTIONS), [], (err) => finish(err || null));
    } catch (e) {
      finish(e);
    }
  }

  client.bind = function secureBind(name, credentials, controls, callback) {
    if (typeof controls === 'function') { callback = controls; controls = []; }
    if (typeof callback !== 'function') throw new TypeError('callback (function) required');
    if (caError) return void process.nextTick(callback, caError);
    if (failed) return void process.nextTick(callback, failed);
    // ldaps://: the socket is TLS (verified with TLS_OPTIONS) before anything is sent.
    if (nativeTls) return realBind(name, credentials, controls, callback);
    upgrade((err) => {
      if (err) return callback(err);
      return realBind(name, credentials, controls, callback);
    });
    return true;
  };

  return client;
}

module.exports = { createClient, TLS_NAME, CA_PATH };
