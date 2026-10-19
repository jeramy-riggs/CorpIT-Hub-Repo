'use strict';
const https = require('https');
// Layer 3. This module's httpsRequest() is the ONLY way anything in this tree
// talks to Zscaler -- 11 modules import it -- and it is raw https.request, so
// the global-fetch wrapper in obs-dependency.js never sees it. obs_dependency
// held zero zscaler rows for exactly that reason: the vendor most likely to
// fail was the one vendor layer 3 was blind to. Wrapping this one function
// covers all 11 callers without touching any of them.
const obsDep = require('./obs-dependency');

// (legacy ZIA key obfuscation removed — ZIdentity OneAPI OAuth2)

function httpsRequest(url, options, body) {
  return new Promise((resolve, reject) => {
    // -- instrumentation prelude ------------------------------------------
    // Nothing here may change the request. Every value is derived from what
    // the caller already passed, note() can only be reached once, and
    // obsDep.record() is obs.safe()-wrapped so it cannot throw into this
    // promise. If the URL will not parse we simply make the call untracked --
    // an unobserved request is better than a broken one.
    const started = process.hrtime.bigint();
    let host = null, path = null;
    try {
      const u = (url instanceof URL) ? url : new URL(String(url));
      host = u.hostname;
      path = u.pathname + (u.search || '');
    } catch (e) { /* untracked */ }
    const method = (options && options.method) || 'GET';
    let recorded = false;
    // One record per request, whichever way it ends. The timeout path calls
    // req.destroy(), which can also surface on 'error', and a bare 'error'
    // after a resolve is possible on a half-closed socket -- without this flag
    // a single timed-out call would appear twice, once as a timeout and once
    // as a socket error, and the failure count would overstate itself.
    function note(status, ok, err) {
      if (recorded || !host) return;
      recorded = true;
      // Duration here is time-to-BODY-COMPLETE, not time-to-headers as in
      // obs-dependency's fetch wrapper: that wrapper refuses to touch the body
      // because doing so would change behaviour, while this function already
      // reads it to completion, so measuring the whole thing costs nothing and
      // is what the caller actually waited for. Worth knowing before comparing
      // this vendor's duration column against a fetch-wrapped one.
      obsDep.record({
        host: host, path: path, method: method,
        operation: (options && options.obsOperation) || '',
        status: status, ok: ok, err: err,
        durationMs: Number(process.hrtime.bigint() - started) / 1e6,
      });
    }

    const req = https.request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        // Recorded from the STATUS, not from whether the body parsed. A 200
        // carrying unparseable text still resolves below and is still a
        // successful call to the vendor; a 401 with a perfect JSON body is
        // still a refusal. Conflating the two is how a stale secret reads as
        // "Zscaler answered fine, the page just had no data".
        note(res.statusCode, res.statusCode >= 200 && res.statusCode < 400, null);
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: data ? JSON.parse(data) : null, cookies: res.headers['set-cookie'] || [] });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, body: data, cookies: res.headers['set-cookie'] || [] });
        }
      });
    });
    req.on('error', (err) => {
      // status stays NULL: no response at all is a different fact from a bad
      // response, and the dashboard renders them differently.
      note(null, false, (err && (err.code || err.message)) || 'request failed');
      reject(err);
    });
    req.setTimeout((options && options.timeoutMs) || 15000, () => {
      note(null, false, 'ETIMEDOUT');
      req.destroy(); reject(new Error("Request timed out"));
    });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

// ── ZIdentity OneAPI shared OAuth2 token (ZIA + ZPA) ──
let oneapiToken = { token: null, expiresAt: 0 };

async function oneapiAuth(force) {
  const clientId = process.env.ZSCALER_CLIENT_ID;
  const clientSecret = process.env.ZSCALER_CLIENT_SECRET;
  const vanity = process.env.ZSCALER_VANITY_DOMAIN;
  if (!clientId || !clientSecret || !vanity) throw new Error('ZIdentity credentials not configured');
  if (!force && oneapiToken.token && Date.now() < oneapiToken.expiresAt) return oneapiToken.token;
  const url = new URL('https://' + vanity + '/oauth2/v1/token');
  const body = 'grant_type=client_credentials'
    + '&client_id=' + encodeURIComponent(clientId)
    + '&client_secret=' + encodeURIComponent(clientSecret)
    + '&audience=' + encodeURIComponent('https://api.zscaler.com');
  const res = await httpsRequest(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, body);
  if (res.status !== 200) throw new Error('ZIdentity auth failed: HTTP ' + res.status);
  const token = res.body && res.body.access_token ? res.body.access_token : null;
  if (!token) throw new Error('ZIdentity auth: no access_token');
  const ttlMs = res.body.expires_in ? Math.max(60, res.body.expires_in - 300) * 1000 : 50 * 60 * 1000;
  oneapiToken = { token, expiresAt: Date.now() + ttlMs };
  console.log('[zscaler] ZIdentity OneAPI token acquired');
  return token;
}

// ZIA auth now returns a Bearer token (callers build the header)
async function ziaAuth(force) {
  return oneapiAuth(force);
}

async function ziaUserLookup(email, displayName) {
  try {
    const token = await ziaAuth();
    const baseUrl = process.env.ZIA_BASE_URL;

    // ZIA search only works with name= param, not search= or email=
    const searchName = displayName || email.split('@')[0];
    const searchUrl = new URL(baseUrl + '/users');
    searchUrl.searchParams.set('name', searchName);
    searchUrl.searchParams.set('page', '1');
    searchUrl.searchParams.set('pageSize', '10');

    const res = await httpsRequest(searchUrl, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
    if (res.status === 401 || res.status === 403) {
      const newToken = await ziaAuth(true);
      const retry = await httpsRequest(searchUrl, { method: 'GET', headers: { Authorization: 'Bearer ' + newToken } });
      if (retry.status !== 200) return { status: 'error', error: 'HTTP ' + retry.status };
      return parseZiaUsers(retry.body, email, displayName);
    }
    if (res.status !== 200) return { status: 'error', error: 'HTTP ' + res.status };
    return parseZiaUsers(res.body, email, displayName);
  } catch (err) {
    console.error('[zscaler] ZIA lookup error:', err.message);
    return { status: 'error', error: err.message };
  }
}

function parseZiaUsers(body, searchEmail, searchName) {
  let users = Array.isArray(body) ? body : (body && body.list ? body.list : []);
  if (!users.length) return { status: 'not_found' };
  const email = (searchEmail || '').toLowerCase();
  const name = (searchName || '').toLowerCase();

  // Priority 1: exact email match
  var match = users.find(function(u) { return (u.email || '').toLowerCase() === email; });
  // Priority 2: exact name match
  if (!match && name) match = users.find(function(u) { return (u.name || '').toLowerCase() === name; });
  // Priority 3: email username match
  if (!match) {
    var username = email.split('@')[0];
    match = users.find(function(u) { return (u.email || '').toLowerCase().split('@')[0] === username; });
  }
  if (!match) return { status: 'not_found' };

  return {
    status: 'found',
    name: match.name || null,
    email: match.email || null,
    department: match.department ? match.department.name : null,
    groups: (match.groups || []).map(function(g) { return g.name; }),
    isEnabled: !match.disabled,
    id: match.id || null,
    adminUser: !!match.adminUser,
    pilotUser: !!match.pilotUser,
    deleted: !!match.deleted,
    pwdLastModifiedTime: match.pwdLastModifiedTime || null
  };
}

// ZPA auth now returns the shared OneAPI Bearer token
async function zpaAuth() {
  return oneapiAuth();
}

async function zpaConnectivityCheck() {
  try {
    const token = await zpaAuth();
    const customerId = process.env.ZPA_CUSTOMER_ID;
    if (!customerId) return { status: 'error', error: 'ZPA_CUSTOMER_ID not configured' };
    const url = new URL('https://api.zsapi.net/zpa/mgmtconfig/v2/admin/customers/' + customerId + '/idp');
    url.searchParams.set('page', '1');
    url.searchParams.set('pageSize', '1');
    const res = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
    if (res.status === 200) {
      return { status: 'connected', idpCount: res.body && res.body.totalCount ? parseInt(res.body.totalCount) : 0 };
    }
    return { status: 'error', error: 'HTTP ' + res.status };
  } catch (err) {
    console.error('[zscaler] ZPA connectivity check error:', err.message);
    return { status: 'error', error: err.message };
  }
}

async function lookupZscalerUser(email, displayName) {
  const result = { zia: { status: 'unconfigured' }, zpa: { status: 'unconfigured' } };
  const promises = [];
  if (process.env.ZSCALER_CLIENT_ID && process.env.ZSCALER_CLIENT_SECRET) {
    promises.push(ziaUserLookup(email, displayName).then(function(r) { result.zia = r; }).catch(function(e) { result.zia = { status: 'error', error: e.message }; }));
  }
  if (process.env.ZSCALER_CLIENT_ID && process.env.ZSCALER_CLIENT_SECRET) {
    promises.push(zpaConnectivityCheck().then(function(r) { result.zpa = r; }).catch(function(e) { result.zpa = { status: 'error', error: e.message }; }));
  }
  await Promise.allSettled(promises);
  return result;
}

module.exports = { lookupZscalerUser, ziaAuth, zpaAuth, httpsRequest };
