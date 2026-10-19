'use strict';
const https = require('https');

function oktaRequest(path) {
  const baseUrl = process.env.OKTA_BASE_URL;
  const token = process.env.OKTA_API_TOKEN;
  if (!baseUrl || !token) return Promise.reject(new Error('Okta credentials not configured'));

  return new Promise((resolve, reject) => {
    const url = new URL(baseUrl + path);
    const req = https.request(url, {
      method: 'GET',
      headers: { 'Authorization': 'SSWS ' + token, 'Accept': 'application/json' },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null }); }
        catch (e) { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Okta request timed out')); });
    req.end();
  });
}

function oktaDelete(path) {
  const baseUrl = process.env.OKTA_BASE_URL;
  const token = process.env.OKTA_API_TOKEN;
  if (!baseUrl || !token) return Promise.reject(new Error('Okta credentials not configured'));

  return new Promise((resolve, reject) => {
    const url = new URL(baseUrl + path);
    const req = https.request(url, {
      method: 'DELETE',
      headers: { 'Authorization': 'SSWS ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json' },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null }); }
        catch (e) { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Okta request timed out')); });
    req.end();
  });
}

// Okta filter/search values are double-quoted SCIM strings. A `"` or `\`
// inside the value ends the string and lets the caller append their own terms
// (`x" or outcome.result eq "SUCCESS`), turning a per-user System Log query
// into a tenant-wide one. encodeURIComponent does not help: Okta URL-decodes
// before it parses the expression. Accept only what a login / email / sAM can
// look like; return null otherwise so the caller can answer 400 or skip.
const OKTA_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._'+\-]{0,99}(@[A-Za-z0-9][A-Za-z0-9.\-]{0,253})?$/;
function oktaFilterValue(v) {
  const s = String(v == null ? '' : v).trim();
  return OKTA_ID_RE.test(s) ? s : null;
}

async function lookupOktaUser(email) {
  if (!process.env.OKTA_BASE_URL || !process.env.OKTA_API_TOKEN) {
    return { status: 'unconfigured' };
  }

  try {
    // Step 1: Find user by email/login
    const userRes = await oktaRequest('/api/v1/users/' + encodeURIComponent(email));
    if (userRes.status === 404) {
      // Try searching by login
      const safeEmail = oktaFilterValue(email);
      if (!safeEmail) return { status: 'not_found' };
      const searchRes = await oktaRequest('/api/v1/users?search=profile.email+eq+%22' + encodeURIComponent(safeEmail) + '%22&limit=1');
      if (searchRes.status === 200 && Array.isArray(searchRes.body) && searchRes.body.length > 0) {
        return await buildOktaResult(searchRes.body[0]);
      }
      return { status: 'not_found' };
    }
    if (userRes.status !== 200) {
      return { status: 'error', error: 'HTTP ' + userRes.status };
    }
    return await buildOktaResult(userRes.body);
  } catch (err) {
    console.error('[okta] lookup error:', err.message);
    return { status: 'error', error: err.message };
  }
}

async function buildOktaResult(user) {
  const userId = user.id;
  const profile = user.profile || {};
  const statusMap = {
    'ACTIVE': 'Active',
    'STAGED': 'Staged',
    'PROVISIONED': 'Provisioned',
    'DEPROVISIONED': 'Deprovisioned',
    'SUSPENDED': 'Suspended',
    'RECOVERY': 'Recovery',
    'LOCKED_OUT': 'Locked Out',
    'PASSWORD_EXPIRED': 'Password Expired',
  };

  var result = {
    status: 'found',
    oktaId: userId,
    oktaStatus: statusMap[user.status] || user.status,
    oktaStatusRaw: user.status,
    login: profile.login || null,
    email: profile.email || null,
    firstName: profile.firstName || null,
    lastName: profile.lastName || null,
    displayName: (profile.firstName || '') + ' ' + (profile.lastName || ''),
    lastLogin: user.lastLogin || null,
    lastUpdated: user.lastUpdated || null,
    created: user.created || null,
    passwordChanged: user.passwordChanged || null,
    mfa: [],
    mfaStatus: 'unknown',
    appCount: 0,
    // appCount is seeded to 0 and only overwritten on a 200. Without a
    // companion status the caller cannot tell "Okta reported no apps" from
    // "Okta declined the appLinks call", and every degraded lookup rendered as
    // a confident zero. Mirrors mfaStatus: unknown -> ok | error.
    // (activeSessions was removed 2026-09-10: Okta has no GET
    // /api/v1/users/{id}/sessions -- it answers 405 E0000022 -- so the count
    // could never be measured. Sign-in history lives in /okta-sessions.)
    appsStatus: 'unknown',
  };

  var promises = [];

  // MFA Factors
  promises.push(
    oktaRequest('/api/v1/users/' + userId + '/factors')
      .then(function(r) {
        if (r.status === 200 && Array.isArray(r.body)) {
          result.mfaStatus = 'ok';
          result.mfa = r.body
            .filter(function(f) { return f.status === 'ACTIVE'; })
            .map(function(f) {
              var label = f.factorType;
              if (f.factorType === 'push' || f.provider === 'OKTA' && f.factorType === 'push') label = 'Okta Verify Push';
              else if (f.factorType === 'token:software:totp' && f.provider === 'OKTA') label = 'Okta Verify TOTP';
              else if (f.factorType === 'token:software:totp' && f.provider === 'GOOGLE') label = 'Google Auth';
              else if (f.factorType === 'sms') label = 'SMS';
              else if (f.factorType === 'call') label = 'Voice Call';
              else if (f.factorType === 'email') label = 'Email';
              else if (f.factorType === 'webauthn') label = 'Security Key';
              else if (f.factorType === 'token:hotp') label = 'Hardware Token';
              else if (f.factorType === 'signed_nonce') label = 'Okta FastPass';
              else label = f.factorType + ' (' + f.provider + ')';
              return { type: f.factorType, provider: f.provider, label: label, status: f.status };
            });
        }
      })
      .catch(function(e) { console.error('[okta] factors error:', e.message); })
  );

  // Assigned Apps
  promises.push(
    oktaRequest('/api/v1/users/' + userId + '/appLinks')
      .then(function(r) {
        if (r.status === 200 && Array.isArray(r.body)) {
          result.appsStatus = 'ok';
          result.appCount = r.body.length;
          result.apps = r.body.slice(0, 10).map(function(a) { return a.label || a.appName; });
        } else {
          result.appsStatus = 'error';
          result.appsError = 'Okta /appLinks HTTP ' + r.status;
        }
      })
      .catch(function(e) {
        result.appsStatus = 'error';
        result.appsError = e.message;
        console.error('[okta] apps error:', e.message);
      })
  );

  await Promise.allSettled(promises);
  return result;
}

module.exports = { lookupOktaUser, oktaRequest, oktaDelete, oktaFilterValue };
