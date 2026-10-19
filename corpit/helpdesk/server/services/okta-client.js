/**
 * Okta API Client
 * Supports both API Token and OAuth 2.0 (private_key_jwt) auth.
 * Handles pagination automatically.
 */
const fetch = require('node-fetch');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

const ORG_URL = (process.env.OKTA_ORG_URL || '').replace(/\/+$/, '');
const AUTH_METHOD = process.env.OKTA_AUTH_METHOD || 'token';

let oauthAccessToken = null;
let oauthTokenExpiry = 0;

// ── Token Auth Header ───────────────────────────────────────
function getTokenHeaders() {
  return {
    Authorization: `SSWS ${process.env.OKTA_API_TOKEN}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };
}

// ── OAuth 2.0 Private Key JWT ───────────────────────────────
async function getOAuthToken() {
  if (oauthAccessToken && Date.now() < oauthTokenExpiry - 60_000) {
    return oauthAccessToken;
  }

  const clientId = process.env.OKTA_CLIENT_ID;
  const keyPath = process.env.OKTA_PRIVATE_KEY_PATH;
  const keyId = process.env.OKTA_KEY_ID;

  if (!clientId || !keyPath) {
    throw new Error('OKTA_CLIENT_ID and OKTA_PRIVATE_KEY_PATH are required for OAuth auth.');
  }

  const privateKey = fs.readFileSync(keyPath, 'utf8');
  const now = Math.floor(Date.now() / 1000);

  const assertion = jwt.sign(
    {
      iss: clientId,
      sub: clientId,
      aud: `${ORG_URL}/oauth2/v1/token`,
      iat: now,
      exp: now + 300,
    },
    privateKey,
    { algorithm: 'RS256', header: { kid: keyId } }
  );

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'okta.users.read okta.apps.read okta.logs.read okta.groups.read',
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: assertion,
  });

  const res = await fetch(`${ORG_URL}/oauth2/v1/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OAuth token request failed (${res.status}): ${text}`);
  }

  const data = await res.json();
  oauthAccessToken = data.access_token;
  oauthTokenExpiry = Date.now() + data.expires_in * 1000;
  logger.info('OAuth access token obtained');
  return oauthAccessToken;
}

async function getOAuthHeaders() {
  const token = await getOAuthToken();
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };
}

// ── Unified Request Helper ──────────────────────────────────
async function getHeaders() {
  if (AUTH_METHOD === 'oauth') return getOAuthHeaders();
  return getTokenHeaders();
}

async function oktaFetch(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${ORG_URL}${endpoint}`;
  const headers = await getHeaders();
  const res = await fetch(url, { ...options, headers: { ...headers, ...options.headers } });
  if (res.status === 429) {
    const retryAfter = parseInt(res.headers.get('x-rate-limit-reset') || '1', 10);
    const waitMs = Math.max((retryAfter * 1000) - Date.now(), 1000);
    logger.warn(`Rate limited. Waiting ${Math.round(waitMs / 1000)}s…`);
    await new Promise(r => setTimeout(r, waitMs));
    return oktaFetch(endpoint, options);
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Okta API ${res.status} on ${url}: ${text}`);
  }
  const data = await res.json();
  return { data, headers: res.headers };
}

// ── Paginated Fetch ─────────────────────────────────────────
async function oktaFetchAll(endpoint, limit = 200) {
  const separator = endpoint.includes('?') ? '&' : '?';
  let url = `${endpoint}${separator}limit=${limit}`;
  let all = [];
  let page = 0;

  while (url) {
    const { data, headers } = await oktaFetch(url);
    all = all.concat(data);
    page++;
    logger.debug(`Fetched page ${page} from ${endpoint} (${data.length} items)`);

    // Parse Link header for next page
    const link = headers.get('link') || '';
    const nextMatch = link.match(/<([^>]+)>;\s*rel="next"/);
    url = nextMatch ? nextMatch[1] : null;
  }

  return all;
}

// ── Domain-specific Fetchers ────────────────────────────────

async function fetchUsers() {
  logger.info('Fetching all users from Okta…');
  return oktaFetchAll('/api/v1/users');
}

async function fetchApplications() {
  logger.info('Fetching all applications from Okta…');
  return oktaFetchAll('/api/v1/apps');
}

async function fetchAppUsers(appId) {
  return oktaFetchAll(`/api/v1/apps/${appId}/users`);
}

async function fetchSystemLogs(since, until) {
  const params = new URLSearchParams({ since, until, sortOrder: 'DESCENDING' });
  logger.info(`Fetching system logs ${since} → ${until}`);
  return oktaFetchAll(`/api/v1/logs?${params.toString()}`);
}

async function fetchGroups() {
  return oktaFetchAll('/api/v1/groups');
}

async function testConnection() {
  const { data } = await oktaFetch('/api/v1/org');
  return data;
}

module.exports = {
  fetchUsers, fetchApplications, fetchAppUsers,
  fetchSystemLogs, fetchGroups, testConnection,
};
