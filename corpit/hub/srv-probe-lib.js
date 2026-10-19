// ─────────────────────────────────────────────────────────────────────────────
// srv-probe-lib.js — virtual-host / subdomain probing for the Server Health
// dashboard.
//
// SCOPE RULE (enforced here, not just by convention): this module only ever
// contacts an FQDN that was handed to it from the srv_vhost registry. It does
// no discovery, no enumeration, and it does NOT follow a redirect unless the
// redirect target's hostname is itself a registered vhost. A redirect pointing
// anywhere else is recorded as a destination string and left unvisited.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const tls = require('tls');
const net = require('net');

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_HOPS = 5;

// Error text can carry paths, IPs of unrelated infrastructure, or raw response
// bodies. Keep the shape of the failure, drop everything else.
function sanitizeError(err) {
  if (!err) return null;
  const code = err.code || err.errno || null;
  const known = {
    ENOTFOUND:            'DNS name did not resolve',
    EAI_AGAIN:            'DNS lookup failed (temporary)',
    ECONNREFUSED:         'Connection refused',
    ECONNRESET:           'Connection reset by peer',
    EHOSTUNREACH:         'Host unreachable',
    ENETUNREACH:          'Network unreachable',
    ETIMEDOUT:            'Connection timed out',
    ESOCKETTIMEDOUT:      'Response timed out',
    CERT_HAS_EXPIRED:     'TLS certificate has expired',
    DEPTH_ZERO_SELF_SIGNED_CERT: 'TLS certificate is self-signed',
    SELF_SIGNED_CERT_IN_CHAIN:   'TLS chain contains a self-signed certificate',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'TLS chain is incomplete',
    ERR_TLS_CERT_ALTNAME_INVALID:    'TLS certificate name does not match the host',
  };
  if (code && known[code]) return { code: String(code), message: known[code] };
  if (err.message === 'timeout') return { code: 'ETIMEDOUT', message: 'Request timed out' };
  // Unknown failure: keep a short, character-restricted summary only.
  const msg = String(err.message || 'Request failed')
    .replace(/[^\w .,:()\-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 180);
  return { code: code ? String(code).slice(0, 64) : 'ERROR', message: msg || 'Request failed' };
}

function hostFromUrl(u) {
  try { return new URL(u).hostname.toLowerCase(); } catch (e) { return null; }
}

// RFC 6125-ish: exact match, or a single leading wildcard label.
function nameMatches(host, name) {
  if (!host || !name) return false;
  host = String(host).toLowerCase().replace(/\.$/, '');
  name = String(name).toLowerCase().replace(/\.$/, '');
  if (name === host) return true;
  if (name.startsWith('*.')) {
    const suffix = name.slice(1);            // ".example.com"
    if (!host.endsWith(suffix)) return false;
    return host.slice(0, host.length - suffix.length).indexOf('.') === -1;
  }
  return false;
}

function certNames(cert) {
  const names = [];
  if (cert && cert.subject && cert.subject.CN) names.push(cert.subject.CN);
  if (cert && cert.subjectaltname) {
    String(cert.subjectaltname).split(',').forEach(function (p) {
      const t = p.trim();
      if (t.slice(0, 4) === 'DNS:') names.push(t.slice(4));
    });
  }
  return names;
}

async function resolveDns(fqdn) {
  // A literal address needs no lookup and must not be treated as a DNS failure.
  if (net.isIP(fqdn)) return { state: 'ok', ip: fqdn, all: [fqdn] };
  try {
    const addrs = await dns.lookup(fqdn, { all: true });
    if (!addrs || !addrs.length) return { state: 'no-address', ip: null, all: [] };
    return { state: 'ok', ip: addrs[0].address, all: addrs.map(function (a) { return a.address; }) };
  } catch (e) {
    const s = sanitizeError(e);
    return { state: s && s.code === 'ENOTFOUND' ? 'nxdomain' : 'error', ip: null, all: [], error: s };
  }
}

// TLS handshake only — no HTTP request. Returns the presented leaf certificate.
// rejectUnauthorized is deliberately false: this estate runs an internal CA and
// a self-signed origin cert, and the point is to REPORT chain/name problems,
// not to refuse to look at them.
function inspectTls(fqdn, port, timeoutMs) {
  return new Promise(function (resolve) {
    let done = false;
    const finish = function (v) { if (!done) { done = true; resolve(v); } };
    let socket;
    try {
      socket = tls.connect({
        host: fqdn, port: port, servername: net.isIP(fqdn) ? undefined : fqdn,
        rejectUnauthorized: false, timeout: timeoutMs,
      }, function () {
        const cert = socket.getPeerCertificate(false) || {};
        const names = certNames(cert);
        const notAfter = cert.valid_to ? new Date(cert.valid_to) : null;
        const daysLeft = notAfter && !isNaN(notAfter) ? Math.floor((notAfter - Date.now()) / 86400000) : null;
        const issuerCn  = (cert.issuer  && cert.issuer.CN)  || null;
        const subjectCn = (cert.subject && cert.subject.CN) || null;
        const selfSigned = !!(issuerCn && subjectCn && issuerCn === subjectCn);
        finish({
          present: !!cert.valid_to,
          issuer: issuerCn, subject: subjectCn, names: names,
          notAfter: notAfter && !isNaN(notAfter) ? notAfter : null,
          daysLeft: daysLeft,
          nameMatch: names.length ? names.some(function (n) { return nameMatches(fqdn, n); }) : null,
          selfSigned: selfSigned,
          authorized: socket.authorized === true,
          authError: socket.authorized ? null : (socket.authorizationError ? String(socket.authorizationError).slice(0, 120) : null),
          error: null,
        });
        socket.end();
      });
      socket.on('timeout', function () { socket.destroy(); finish({ present: false, error: { code: 'ETIMEDOUT', message: 'TLS handshake timed out' } }); });
      socket.on('error', function (e) { finish({ present: false, error: sanitizeError(e) }); });
    } catch (e) {
      finish({ present: false, error: sanitizeError(e) });
    }
  });
}

// One HTTP(S) request, no redirect following. Caller owns the hop loop so the
// registry check can gate every hop.
function requestOnce(urlStr, timeoutMs) {
  return new Promise(function (resolve) {
    let u;
    try { u = new URL(urlStr); } catch (e) { return resolve({ error: { code: 'EBADURL', message: 'Invalid URL' } }); }
    const mod = u.protocol === 'https:' ? https : http;
    const started = Date.now();
    let done = false;
    const finish = function (v) { if (!done) { done = true; resolve(v); } };

    const req = mod.request({
      protocol: u.protocol, hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: (u.pathname || '/') + (u.search || ''),
      method: 'GET',
      servername: net.isIP(u.hostname) ? undefined : u.hostname,
      rejectUnauthorized: false,
      headers: { 'User-Agent': 'CorpIT-ServerHealth/1.0 (registry probe)', 'Accept': '*/*', 'Connection': 'close' },
      timeout: timeoutMs,
    }, function (res) {
      // Status line and headers are all we need; drain and drop the body so a
      // large page cannot hold the socket or the heap.
      res.resume();
      res.on('end', function () {
        finish({
          status: res.statusCode,
          location: res.headers.location || null,
          ms: Date.now() - started,
          error: null,
        });
      });
      res.on('error', function (e) { finish({ status: res.statusCode, ms: Date.now() - started, error: sanitizeError(e) }); });
    });
    req.on('timeout', function () { req.destroy(); finish({ error: { code: 'ETIMEDOUT', message: 'Request timed out' }, ms: Date.now() - started }); });
    req.on('error', function (e) { finish({ error: sanitizeError(e), ms: Date.now() - started }); });
    req.end();
  });
}

// Walk redirects, but only into hosts that are themselves registered.
// `allowedHosts` is a Set of lowercase FQDNs from srv_vhost.
async function followChain(startUrl, allowedHosts, timeoutMs) {
  const seen = [];
  let url = startUrl;
  let hops = 0;
  let last = null;
  let loop = false;
  let stoppedOffScope = null;

  while (hops <= MAX_HOPS) {
    if (seen.indexOf(url) !== -1) { loop = true; break; }
    seen.push(url);
    last = await requestOnce(url, timeoutMs);
    if (last.error) break;
    const isRedirect = last.status >= 300 && last.status < 400 && last.location;
    if (!isRedirect) break;

    let next;
    try { next = new URL(last.location, url).toString(); } catch (e) { break; }
    const nextHost = hostFromUrl(next);
    if (!nextHost || !allowedHosts.has(nextHost)) {
      // Out-of-scope destination: record it, do not request it.
      stoppedOffScope = next;
      break;
    }
    url = next;
    hops++;
  }

  // A same-host redirect that keeps pointing back at itself is a loop even if
  // the URL string differs by a query token; MAX_HOPS exhaustion counts too.
  if (!loop && hops > MAX_HOPS) loop = true;
  if (!loop && hops >= MAX_HOPS && last && last.status >= 300 && last.status < 400) loop = true;

  return {
    finalUrl: url,
    hops: hops,
    loop: loop,
    result: last,
    redirectTo: stoppedOffScope || (last && last.location) || (hops > 0 ? url : null),
    chain: seen,
  };
}

/**
 * Probe one registered vhost.
 * @param {object} vh    row from srv_vhost
 * @param {Set}    allowedHosts lowercase FQDNs of every registered vhost
 * @param {object} th    thresholds { vhost_response_ms:{warn,crit}, cert_days_left:{warn,crit} }
 */
async function probeVhost(vh, allowedHosts, th, opts) {
  opts = opts || {};
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const fqdn = String(vh.fqdn).toLowerCase();
  const port = vh.port || 443;
  const path = vh.probe_path || '/';

  const out = {
    vhost_id: vh.id, state: 'unknown', dns_state: 'unknown', resolved_ip: null,
    http_status: null, https_status: null, last_status: null, response_ms: null,
    redirect_to: null, redirect_hops: null, redirect_loop: 0,
    tls_issuer: null, tls_subject: null, tls_not_after: null, tls_days_left: null,
    tls_name_match: null, tls_self_signed: null, cert_state: 'unknown',
    https_available: null, http_available: null,
    error_code: null, error_message: null,
    flags: [],
  };

  // 1. DNS
  const d = await resolveDns(fqdn);
  out.dns_state = d.state;
  out.resolved_ip = d.ip;
  out.resolved_all = d.all || [];
  if (d.state !== 'ok') {
    out.state = 'offline';
    out.cert_state = 'unknown';
    out.error_code = (d.error && d.error.code) || 'DNS';
    out.error_message = (d.error && d.error.message) || (d.state === 'nxdomain' ? 'DNS name did not resolve' : 'DNS returned no address');
    out.flags.push(d.state === 'nxdomain' ? 'dns-nxdomain' : 'dns-no-address');
    return out;
  }
  // Prefer the address CorpIT expects when the name legitimately resolves to
  // several — otherwise whichever entry the resolver happened to return first
  // (on this host, usually the /etc/hosts loopback line) reads as a repoint.
  if (vh.expected_ip && d.all.indexOf(vh.expected_ip) !== -1) {
    out.resolved_ip = vh.expected_ip;
    if (d.all.length > 1) out.flags.push('dns-multiple-addresses');
  } else if (vh.expected_ip) {
    var loopbackOnly = d.all.length > 0 && d.all.every(function (a) {
      return a === '127.0.0.1' || a === '::1' || a.indexOf('127.') === 0;
    });
    // A probe running on the host itself answering from /etc/hosts is not a
    // DNS change; it is the local resolver short-circuiting. Say that, and do
    // not raise it as a warning.
    if (loopbackOnly) out.flags.push('dns-loopback');
    else out.flags.push('dns-unexpected-target');
  }

  // 2. TLS (only when the vhost is expected to serve HTTPS)
  if (vh.expect_https) {
    const t = await inspectTls(fqdn, port, timeoutMs);
    if (t.present) {
      out.tls_issuer = t.issuer; out.tls_subject = t.subject;
      out.tls_not_after = t.notAfter; out.tls_days_left = t.daysLeft;
      out.tls_name_match = t.nameMatch === null ? null : (t.nameMatch ? 1 : 0);
      out.tls_self_signed = t.selfSigned ? 1 : 0;
      if (t.daysLeft != null && t.daysLeft < 0)                        { out.cert_state = 'expired'; out.flags.push('cert-expired'); }
      else if (t.nameMatch === false)                                  { out.cert_state = 'mismatch'; out.flags.push('cert-name-mismatch'); }
      else if (t.daysLeft != null && t.daysLeft <= th.cert_days_left.crit) { out.cert_state = 'critical'; out.flags.push('cert-expiring'); }
      else if (t.daysLeft != null && t.daysLeft <= th.cert_days_left.warn) { out.cert_state = 'warning'; out.flags.push('cert-expiring'); }
      else                                                              { out.cert_state = 'ok'; }
    } else {
      out.cert_state = 'none';
      out.flags.push('tls-handshake-failed');
      if (t.error) { out.error_code = t.error.code; out.error_message = t.error.message; }
    }
  } else {
    out.cert_state = 'none';
  }

  // 3. HTTPS request chain
  const scheme = vh.expect_https ? 'https' : 'http';
  const base = scheme + '://' + fqdn + (port === (vh.expect_https ? 443 : 80) ? '' : ':' + port) + path;
  const chain = await followChain(base, allowedHosts, timeoutMs);
  const r = chain.result || {};
  out.response_ms = r.ms != null ? r.ms : null;
  out.redirect_hops = chain.hops;
  out.redirect_loop = chain.loop ? 1 : 0;
  out.redirect_to = chain.redirectTo;
  if (chain.loop) out.flags.push('redirect-loop');

  if (r.error) {
    if (vh.expect_https) out.https_available = 0; else out.http_available = 0;
    out.error_code = out.error_code || r.error.code;
    out.error_message = out.error_message || r.error.message;
    out.state = 'offline';
    out.flags.push('unavailable');
    return out;
  }

  out.last_status = r.status;
  if (vh.expect_https) { out.https_status = r.status; out.https_available = 1; }
  else                 { out.http_status  = r.status; out.http_available  = 1; }

  // 4. Plain-HTTP reachability, recorded separately. On an HTTPS vhost this is
  //    informational: it tells the operator whether :80 answers at all.
  if (vh.expect_https) {
    const plain = await requestOnce('http://' + fqdn + path, Math.min(timeoutMs, 5000));
    out.http_available = plain.error ? 0 : 1;
    out.http_status = plain.error ? null : plain.status;
  } else {
    out.https_available = null;
    out.flags.push('no-https');
  }

  // 5. State
  const expected = vh.expected_status || 200;
  const okStatus = r.status === expected || (r.status >= 200 && r.status < 400 && expected === 200);
  if (!okStatus) {
    out.flags.push('unexpected-status');
    out.state = r.status >= 500 ? 'critical' : 'warning';
    out.error_message = out.error_message || ('HTTP ' + r.status + ' (expected ' + expected + ')');
  } else {
    out.state = 'healthy';
  }
  if (out.response_ms != null && out.response_ms >= th.vhost_response_ms.crit) { out.state = 'critical'; out.flags.push('slow-response'); }
  else if (out.response_ms != null && out.response_ms >= th.vhost_response_ms.warn && out.state === 'healthy') { out.state = 'warning'; out.flags.push('slow-response'); }

  if (out.cert_state === 'expired' || out.cert_state === 'mismatch') out.state = 'critical';
  else if (out.cert_state === 'critical' && out.state !== 'critical') out.state = 'critical';
  else if (out.cert_state === 'warning' && out.state === 'healthy') out.state = 'warning';
  if (out.redirect_loop) out.state = 'critical';
  if (out.flags.indexOf('dns-unexpected-target') !== -1 && out.state === 'healthy') out.state = 'warning';
  if (out.flags.indexOf('tls-handshake-failed') !== -1) out.state = 'critical';

  if (vh.status === 'maintenance') out.state = 'maintenance';

  return out;
}

module.exports = {
  probeVhost, resolveDns, inspectTls, requestOnce, followChain,
  sanitizeError, nameMatches, DEFAULT_TIMEOUT_MS,
};
