// ═══════════════════════════════════════════════════════════════════════
// rapid7-lookup.js — Rapid7 InsightIDR integration for Identity Diagnostics
// Mount point: /api/rapid7/  (beta API, port 3001)
// ═══════════════════════════════════════════════════════════════════════
//
// Endpoints:
//   GET /api/rapid7/health              — Validate API key & connectivity
//   GET /api/rapid7/accounts?username=  — Search IDR accounts by sAMAccountName
//   GET /api/rapid7/investigations?status=OPEN&days=30  — List investigations
//   GET /api/rapid7/auth-activity?username=&hours=24    — Recent auth events
//
// Required .env vars:
//   RAPID7_API_KEY   — Command Platform API key (User or Org key)
//   RAPID7_REGION    — Region code from your Rapid7 URL (default: us)
//
// Uses Node built-in https module — no npm dependencies required.
// ═══════════════════════════════════════════════════════════════════════

const express = require('express');
const https   = require('https');
const router  = express.Router();
// ---- RBAC enforcement (Slice 8: rapid7 routes — identity-diag + live-presence) ----
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
// ---------------------------------------------------------------------

// ─── Configuration ───────────────────────────────────────────────────

const API_KEY  = process.env.RAPID7_API_KEY;
const REGION   = process.env.RAPID7_REGION || 'us';
const API_HOST = `${REGION}.api.insight.rapid7.com`;
const TIMEOUT  = 20000;

// Async polling config — Rapid7 log queries run asynchronously
const POLL_MAX_RETRIES = 8;
const POLL_INTERVAL_MS = 3000;

// ─── HTTP helper (built-in https, no axios needed) ───────────────────

function r7request(method, path, body) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: API_HOST,
      port:     443,
      path,
      method,
      headers: {
        'X-Api-Key':    API_KEY,
        'Content-Type': 'application/json',
        'Accept':       'application/json'
      },
      timeout: TIMEOUT
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 400) {
            const err = new Error(parsed.message || `HTTP ${res.statusCode}`);
            err.status = res.statusCode;
            err.body   = parsed;
            reject(err);
          } else {
            resolve(parsed);
          }
        } catch (e) {
          if (res.statusCode >= 400) {
            const err = new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`);
            err.status = res.statusCode;
            reject(err);
          } else {
            resolve({ raw: data });
          }
        }
      });
    });

    req.on('error',   reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

// Helper to make requests using a full URL (for polling continuation links)
function r7requestUrl(fullUrl) {
  return new Promise((resolve, reject) => {
    const url = new URL(fullUrl);
    const options = {
      hostname: url.hostname,
      port:     443,
      path:     url.pathname + url.search,
      method:   'GET',
      headers: {
        'X-Api-Key':    API_KEY,
        'Accept':       'application/json'
      },
      timeout: TIMEOUT
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve({ raw: data });
        }
      });
    });

    req.on('error',   reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Poll timeout')); });
    req.end();
  });
}

// ─── Logset ID cache ─────────────────────────────────────────────────

let logsetCache     = null;
let logsetCacheTime = 0;
const CACHE_TTL     = 3600000; // 1 hour

async function getLogsetIds() {
  const now = Date.now();
  if (logsetCache && (now - logsetCacheTime) < CACHE_TTL) {
    return logsetCache;
  }

  console.log('[Rapid7] Fetching logset inventory...');
  const data = await r7request('GET', '/log_search/management/logsets');

  logsetCache = {};
  for (const ls of (data.logsets || [])) {
    logsetCache[ls.name] = {
      id:   ls.id,
      logs: (ls.logs_info || []).map(l => ({ id: l.id, name: l.name }))
    };
  }
  logsetCacheTime = now;
  console.log(`[Rapid7] Cached ${Object.keys(logsetCache).length} logsets`);
  return logsetCache;
}


// ═══════════════════════════════════════════════════════════════════════
//  1. HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════════

router.get('/health', async (req, res) => {
  if (!API_KEY) {
    return res.json({ status: 'error', region: REGION, message: 'RAPID7_API_KEY not configured in .env' });
  }

  try {
    const data = await r7request('GET', '/validate');
    res.json({ status: 'ok', region: REGION, host: API_HOST, message: data.message || 'Authorized' });
  } catch (err) {
    res.json({ status: 'error', region: REGION, host: API_HOST, message: err.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════
//  2. ACCOUNT SEARCH
// ═══════════════════════════════════════════════════════════════════════

router.get('/accounts', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: 'username query parameter is required' });
  if (!API_KEY)  return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });

  try {
    const data = await r7request('POST', '/idr/v1/accounts/_search', {
      search: [{ field: 'name', operator: 'EQUALS', value: username }]
    });

    const accounts = data.data || [];
    const metadata = data.metadata || {};

    const userRrns = [...new Set(
      accounts.filter(a => a.user && a.user.rrn).map(a => a.user.rrn)
    )];

    res.json({
      success:  true,
      username,
      total:    metadata.total_data || accounts.length,
      accounts: accounts.map(a => ({
        rrn:         a.rrn,
        name:        a.name,
        domain:      a.domain || null,
        authService: a.authentication_service || 'UNKNOWN',
        disabled:    a.disabled || false,
        user: a.user ? { rrn: a.user.rrn, name: a.user.name } : null
      })),
      userRrns
    });
  } catch (err) {
    console.error('[Rapid7] Account search error:', err.message);
    res.status(err.status || 500).json({ error: 'Rapid7 account search failed', detail: err.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════
//  3. INVESTIGATIONS
// ═══════════════════════════════════════════════════════════════════════

router.get('/investigations', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const { status, days, size } = req.query;
  if (!API_KEY) return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });

  try {
    const pageSize  = Math.min(parseInt(size) || 20, 50);
    const daysBack  = parseInt(days) || 30;
    const startTime = new Date(Date.now() - daysBack * 86400000).toISOString();

    let qs = `?size=${pageSize}&index=0&start_time=${encodeURIComponent(startTime)}`;
    if (status) qs += `&statuses=${status.toUpperCase()}`;

    const data           = await r7request('GET', `/idr/v2/investigations${qs}`);
    const investigations = data.data || [];
    const metadata       = data.metadata || {};

    res.json({
      success:      true,
      daysBack,
      statusFilter: status || 'ALL',
      total:        metadata.total_data || investigations.length,
      page:         metadata.index || 0,
      totalPages:   metadata.total_pages || 1,
      investigations: investigations.map(inv => ({
        id:              inv.id || null,
        rrn:             inv.rrn || null,
        title:           inv.title,
        source:          inv.source,
        status:          inv.status,
        priority:        inv.priority,
        disposition:     inv.disposition,
        assignee:        inv.assignee || null,
        responsibility:  inv.responsibility || null,
        createdTime:     inv.created_time,
        lastAccessed:    inv.last_accessed,
        firstAlertTime:  inv.first_alert_time,
        latestAlertTime: inv.latest_alert_time
      }))
    });
  } catch (err) {
    console.error('[Rapid7] Investigations error:', err.message);
    res.status(err.status || 500).json({ error: 'Rapid7 investigations query failed', detail: err.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════
//  4. AUTH ACTIVITY (Log Search)
// ═══════════════════════════════════════════════════════════════════════
// Rapid7 log events use email-format usernames in fields like
// "user" and "account" (e.g. jriggs@auction.com). We use a
// case-insensitive regex match to find events for a given username
// across all authentication logsets.
//
// The Log Search API is asynchronous — queries return progress=0
// initially and must be polled via continuation URL until events
// are returned or progress reaches 100%.

router.get('/auth-activity', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const { username, hours } = req.query;
  if (!username) return res.status(400).json({ error: 'username query parameter is required' });
  if (!API_KEY)  return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });

  try {
    const logsets = await getLogsetIds();

    const targets = ['Asset Authentication', 'Ingress Authentication', 'SSO Authentication']
      .filter(name => logsets[name])
      .map(name => ({ name, id: logsets[name].id }));

    if (targets.length === 0) {
      return res.status(404).json({
        error: 'No authentication logsets found',
        available: Object.keys(logsets)
      });
    }

    const hoursBack = parseInt(hours) || 24;
    const now  = Date.now();
    const from = now - (hoursBack * 3600000);

    // Use case-insensitive regex to match username in any field
    // This catches both sAMAccountName (jriggs) and email (jriggs@auction.com)
    const leql = `where(/${username}/i)`;

    const results = await Promise.all(targets.map(ls => queryLogset(ls, leql, from, now)));

    // Combine events, parse message JSON, sort newest first
    let allEvents = [];
    for (const r of results) {
      for (const e of r.events) {
        // Parse the message JSON to extract structured fields
        let parsed = {};
        try {
          if (typeof e.message === 'string' && e.message.startsWith('{')) {
            parsed = JSON.parse(e.message);
          }
        } catch (_) { /* leave parsed empty */ }

        allEvents.push({
          logset:      r.logset,
          timestamp:   e.timestamp,
          user:        parsed.user || parsed.account || null,
          sourceIp:    parsed.source_ip || null,
          service:     parsed.service || null,
          ssoProvider: parsed.sso_provider || null,
          geoCity:     parsed.geoip_city || null,
          geoCountry:  parsed.geoip_country_code || null,
          geoRegion:   parsed.geoip_region || null,
          geoOrg:      parsed.geoip_organization || null,
          rawMessage:  e.message
        });
      }
    }
    allEvents.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    allEvents = allEvents.slice(0, 50);

    res.json({
      success:     true,
      username,
      hoursBack,
      totalEvents: allEvents.length,
      logsets: results.map(r => ({ name: r.logset, eventCount: r.events.length, error: r.error || null })),
      events: allEvents
    });
  } catch (err) {
    console.error('[Rapid7] Auth activity error:', err.message);
    res.status(err.status || 500).json({ error: 'Rapid7 auth activity query failed', detail: err.message });
  }
});


// ─── Log Search helper with async polling ────────────────────────────
// Rapid7's Log Search API is async. The initial request returns
// progress=0 and a continuation URL. We poll that URL until
// events appear or we hit the retry limit.

async function queryLogset(ls, leql, from, to) {
  try {
    const encodedLeql = encodeURIComponent(leql);
    const qs = `?query=${encodedLeql}&from=${from}&to=${to}&per_page=25`;
    let data   = await r7request('GET', `/log_search/query/logsets/${ls.id}${qs}`);
    let events = data.events || [];

    // Poll if query is still processing
    let retries = 0;
    while (retries < POLL_MAX_RETRIES) {
      // If we got events, we're done
      if (events.length > 0) break;

      // If progress is 100+ or missing (completed), we're done
      const progress = data.progress;
      if (progress === undefined || progress === null || progress >= 100) break;

      // Find continuation URL
      const selfLink = (data.links || []).find(l => l.rel === 'Self');
      if (!selfLink || !selfLink.href) break;

      retries++;
      await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));

      // Poll continuation — append per_page if not already in URL
      let pollUrl = selfLink.href;
      if (!pollUrl.includes('per_page')) {
        pollUrl += (pollUrl.includes('?') ? '&' : '?') + 'per_page=25';
      }

      data = await r7requestUrl(pollUrl);
      events = events.concat(data.events || []);
    }

    return { logset: ls.name, events };
  } catch (err) {
    console.error(`[Rapid7] Log query failed for ${ls.name}:`, err.message);
    return { logset: ls.name, events: [], error: err.message };
  }
}




// ═══════════════════════════════════════════════════════════════════════
//  5. DEVICE LOOKUP (two-step: AD Auth → Host-to-IP)
// ═══════════════════════════════════════════════════════════════════════
// GET /api/rapid7/device-lookup?username=jriggs&hours=24
//
// Step 1: Searches Asset Authentication logs for the username to find
//         which devices (hostnames) they authenticated to.
// Step 2: Cross-references those hostnames in Host-to-IP Observations
//         to get local IP addresses and MAC addresses.

router.get('/device-lookup', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const { username, hours } = req.query;
  if (!username) return res.status(400).json({ error: 'username query parameter is required' });
  if (!API_KEY)  return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });

  try {
    const logsets = await getLogsetIds();
    const hoursBack = parseInt(hours) || 24;
    const now  = Date.now();
    const from = now - (hoursBack * 3600000);

    // Step 1: Search Asset Authentication for the user's device logins
    const aaId = logsets['Asset Authentication'] ? logsets['Asset Authentication'].id : null;
    if (!aaId) {
      return res.status(404).json({ error: 'Asset Authentication logset not found' });
    }

    const leql = `where(/${username}/i)`;
    const aaResult = await queryLogset(
      { name: 'Asset Authentication', id: aaId },
      leql, from, now
    );

    // Extract unique device hostnames and IPs from auth events
    const deviceMap = {}; // hostname → { ips, accounts, lastSeen, eventCodes }
    for (const event of aaResult.events) {
      let parsed = {};
      try {
        if (typeof event.message === 'string' && event.message.startsWith('{')) {
          parsed = JSON.parse(event.message);
        }
      } catch (_) { continue; }

      const host = parsed.destination_asset || parsed.source_asset;
      if (!host) continue;

      const shortHost = host.split('.')[0].toLowerCase();
      if (!deviceMap[shortHost]) {
        deviceMap[shortHost] = {
          hostname: host,
          ips: new Set(),
          accounts: new Set(),
          lastSeen: null,
          eventCodes: new Set(),
          results: new Set()
        };
      }

      const entry = deviceMap[shortHost];
      if (parsed.destination_asset_address) entry.ips.add(parsed.destination_asset_address);
      if (parsed.source_asset_address) entry.ips.add(parsed.source_asset_address);
      if (parsed.destination_account) entry.accounts.add(parsed.destination_account);
      if (parsed.windows_event_code) entry.eventCodes.add(parsed.windows_event_code);
      if (parsed.result) entry.results.add(parsed.result);

      const ts = parsed.timestamp || event.timestamp;
      if (ts && (!entry.lastSeen || ts > entry.lastSeen)) {
        entry.lastSeen = ts;
      }
    }

    // Step 2: Cross-reference hostnames in Host-to-IP Observations
    const hipId = logsets['Host To IP Observations'] ? logsets['Host To IP Observations'].id : null;
    const devices = [];

    for (const [shortHost, info] of Object.entries(deviceMap)) {
      const device = {
        hostname:   info.hostname,
        shortName:  shortHost,
        ipsFromAD:  [...info.ips],
        accounts:   [...info.accounts],
        lastSeen:   info.lastSeen,
        eventCodes: [...info.eventCodes],
        results:    [...info.results],
        localIp:    null,
        mac:        null,
        hipTimestamp: null,
        allIps:     []
      };

      // Query Host-to-IP for this device
      if (hipId) {
        try {
          const hipLeql = `where(/${shortHost}/i)`;
          const hipResult = await queryLogset(
            { name: 'Host-to-IP', id: hipId },
            hipLeql, from, now
          );

          if (hipResult.events.length > 0) {
            // Take the most recent event
            let latest = null;
            for (const he of hipResult.events) {
              let hp = {};
              try {
                if (typeof he.message === 'string' && he.message.startsWith('{')) {
                  hp = JSON.parse(he.message);
                }
              } catch (_) { continue; }

              if (!latest || (hp.timestamp && hp.timestamp > (latest.timestamp || ''))) {
                latest = hp;
              }
            }

            if (latest) {
              device.localIp = latest.ip || null;
              device.mac = latest.client_mac || null;
              device.hipTimestamp = latest.timestamp || null;
              if (latest.source_json && latest.source_json.ipv4_addresses) {
                device.allIps = latest.source_json.ipv4_addresses;
              }
            }
          }
        } catch (hipErr) {
          console.error(`[Rapid7] Host-to-IP lookup failed for ${shortHost}:`, hipErr.message);
        }
      }

      devices.push(device);
    }

    // Sort by lastSeen (most recent first)
    devices.sort((a, b) => {
      if (!a.lastSeen) return 1;
      if (!b.lastSeen) return -1;
      return b.lastSeen.localeCompare(a.lastSeen);
    });

    res.json({
      success:  true,
      username,
      hoursBack,
      totalDevices: devices.length,
      totalAuthEvents: aaResult.events.length,
      hipAvailable: !!hipId,
      devices
    });

  } catch (err) {
    console.error('[Rapid7] Device lookup error:', err.message);
    res.status(err.status || 500).json({
      error: 'Rapid7 device lookup failed',
      detail: err.message
    });
  }
});



// ═══════════════════════════════════════════════════════════════════════
//  6. NETWORK & VPN ACTIVITY
// ═══════════════════════════════════════════════════════════════════════
// GET /api/rapid7/network-activity?username=jriggs&hours=24
//
// Queries Ingress Authentication for VPN/ZPA sessions and
// Firewall Activity for network events tied to a user.
// Returns source IPs, geo, ISP, connection type, and service info.

router.get('/network-activity', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const { username, hours } = req.query;
  if (!username) return res.status(400).json({ error: 'username query parameter is required' });
  if (!API_KEY)  return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });

  try {
    const logsets = await getLogsetIds();
    const hoursBack = parseInt(hours) || 24;
    const now  = Date.now();
    const from = now - (hoursBack * 3600000);
    const leql = `where(/${username}/i)`;

    // Query Ingress Auth (VPN/ZPA/Okta sessions) and Firewall Activity
    const targets = [
      { name: 'Ingress Authentication', id: logsets['Ingress Authentication']?.id },
      { name: 'Firewall Activity', id: logsets['Firewall Activity']?.id }
    ].filter(t => t.id);

    const results = await Promise.all(targets.map(ls => queryLogset(ls, leql, from, now)));

    // Parse and deduplicate sessions
    const sessions = [];
    const seenIps = new Set();

    for (const r of results) {
      for (const e of r.events) {
        let parsed = {};
        try {
          if (typeof e.message === 'string' && e.message.startsWith('{')) {
            parsed = JSON.parse(e.message);
          }
        } catch (_) { continue; }

        const sourceIp = parsed.source_ip || parsed.source_address || null;
        const ts = parsed.timestamp || null;

        // For Ingress Auth — rich session data
        if (r.logset === 'Ingress Authentication' && sourceIp) {
          const sessionKey = sourceIp + '|' + (parsed.service || '') + '|' + (ts || '').substring(0, 13);
          if (!seenIps.has(sessionKey)) {
            seenIps.add(sessionKey);
            sessions.push({
              type:           'vpn',
              timestamp:      ts,
              user:           parsed.user || null,
              account:        parsed.account || null,
              sourceIp:       sourceIp,
              service:        parsed.service || null,
              result:         parsed.result || null,
              geoCity:        parsed.geoip_city || null,
              geoRegion:      parsed.geoip_region || null,
              geoCountry:     parsed.geoip_country_code || null,
              geoOrg:         parsed.geoip_organization || null,
              connectionType: parsed.geoip_connection_type || null
            });
          }
        }

        // For Firewall — connection data
        if (r.logset === 'Firewall Activity' && sourceIp) {
          sessions.push({
            type:        'firewall',
            timestamp:   ts,
            sourceIp:    sourceIp,
            sourcePort:  parsed.source_port || null,
            destIp:      parsed.destination_address || null,
            destPort:    parsed.destination_port || null,
            protocol:    parsed.transport_protocol || null,
            status:      parsed.connection_status || null,
            direction:   parsed.direction || null,
            bytesIn:     parsed.incoming_bytes || null,
            bytesOut:    parsed.outgoing_bytes || null,
            geoCountry:  parsed.geoip_country_code || null,
            geoOrg:      parsed.geoip_organization || null
          });
        }
      }
    }

    // Sort newest first
    sessions.sort((a, b) => {
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      return b.timestamp.localeCompare(a.timestamp);
    });

    // Summarize unique locations
    const locations = {};
    sessions.filter(s => s.type === 'vpn').forEach(s => {
      const key = s.sourceIp || 'unknown';
      if (!locations[key]) {
        locations[key] = {
          ip: s.sourceIp,
          city: s.geoCity,
          region: s.geoRegion,
          country: s.geoCountry,
          org: s.geoOrg,
          connectionType: s.connectionType,
          lastSeen: s.timestamp,
          count: 0
        };
      }
      locations[key].count++;
      if (s.timestamp > locations[key].lastSeen) {
        locations[key].lastSeen = s.timestamp;
      }
    });

    res.json({
      success: true,
      username,
      hoursBack,
      totalSessions: sessions.length,
      vpnSessions: sessions.filter(s => s.type === 'vpn').length,
      firewallEvents: sessions.filter(s => s.type === 'firewall').length,
      locations: Object.values(locations),
      sessions: sessions.slice(0, 30)
    });

  } catch (err) {
    console.error('[Rapid7] Network activity error:', err.message);
    res.status(err.status || 500).json({
      error: 'Rapid7 network activity query failed',
      detail: err.message
    });
  }
});



// ═══════════════════════════════════════════════════════════════════════
//  7. LIVE OFFICE PRESENCE
// ═══════════════════════════════════════════════════════════════════════
// GET /api/rapid7/live-presence?minutes=60&webMinutes=30
//
// Merges ZPA Ingress Auth (sparse — long-token users rarely re-auth)
// with ZIA Web Proxy (continuous — any browsing activity creates events).
// Enriches each user's location from a 7-day Ingress Auth history cache,
// matching on their CURRENT WAN IP so multi-ISP/load-balanced setups
// resolve to the correct ISP per session.

const OFFICE_IPS = {
  '64.58.136.122': 'Irvine HQ',
  '64.58.136.121': 'Irvine HQ'
  // Add more: '<wan ip>': '<office label>'
};

const LIVE_PRESENCE_WEB_LOGSET_ID = '54414c09-670a-47c7-9e2d-8e38d4c94f09';
let livePresenceCache = { data: null, expiresAt: 0 };
const LIVE_PRESENCE_CACHE_MS = 30 * 1000;

let locationCache = { data: {}, lastBuildTs: 0, buildingPromise: null, stats: null };
const LOCATION_CACHE_TTL_MS = 60 * 60 * 1000;
const LOCATION_CACHE_BUILD_TIMEOUT_MS = 60 * 1000;

async function buildLocationCache(days) {
  const N_DAYS = days || 7;
  const logsets = await getLogsetIds();
  const iaId = logsets['Ingress Authentication'] && logsets['Ingress Authentication'].id;
  if (!iaId) throw new Error('Ingress Authentication logset not found');

  const now = Date.now();
  const from = now - (N_DAYS * 24 * 60 * 60 * 1000);

  console.log('[Rapid7] Building location cache from last ' + N_DAYS + 'd of Ingress Auth...');
  const t0 = Date.now();

  const result = await queryLogset(
    { name: 'Ingress Auth (history)', id: iaId },
    'where(/Zscaler|ZPA|vpn|ASA/i)',
    from, now
  );

  const cache = {};
  let ipCount = 0;
  let skipped = 0;

  const events = result.events || [];
  for (const e of events) {
    let p = {};
    try {
      if (typeof e.message === 'string' && e.message.startsWith('{')) {
        p = JSON.parse(e.message);
      }
    } catch (_) { skipped++; continue; }

    const sourceIp = p.source_ip || null;
    if (!sourceIp) { skipped++; continue; }

    const user = p.user || p.account || null;
    if (!user || user === 'unknown') { skipped++; continue; }
    if (String(user).toLowerCase().indexOf('machine@') !== -1) { skipped++; continue; }

    const timestamp = p.timestamp || e.timestamp || '';
    const key = String(user).toLowerCase();

    const enrichment = {
      city:           p.geoip_city || 'Unknown',
      region:         p.geoip_region || '',
      country:        p.geoip_country_code || '',
      org:            p.geoip_organization || 'Unknown ISP',
      connectionType: p.geoip_connection_type || 'Unknown',
      lastSeenTs:     timestamp
    };

    if (!cache[key]) {
      cache[key] = { displayName: user, lastAuthTs: timestamp, knownIps: {} };
    }
    const entry = cache[key];
    if (!entry.knownIps[sourceIp]) {
      entry.knownIps[sourceIp] = enrichment;
      ipCount++;
    } else if (timestamp > entry.knownIps[sourceIp].lastSeenTs) {
      entry.knownIps[sourceIp] = enrichment;
    }
    if (timestamp > entry.lastAuthTs) entry.lastAuthTs = timestamp;
  }

  const userCount = Object.keys(cache).length;
  const elapsed = Math.round((Date.now() - t0) / 1000);
  console.log('[Rapid7] Location cache built: ' + userCount + ' users, ' + ipCount +
              ' unique IPs, ' + events.length + ' events, ' + skipped +
              ' skipped, ' + elapsed + 's');

  return {
    data: cache,
    stats: {
      userCount:    userCount,
      ipCount:      ipCount,
      eventsParsed: events.length,
      skipped:      skipped,
      elapsedSec:   elapsed,
      historyDays:  N_DAYS,
      builtAt:      new Date().toISOString()
    }
  };
}

async function ensureLocationCache() {
  const age = Date.now() - locationCache.lastBuildTs;
  if (locationCache.lastBuildTs && age < LOCATION_CACHE_TTL_MS) return;

  if (!locationCache.buildingPromise) {
    const buildTimeout = new Promise(function(_, reject) {
      setTimeout(function(){
        reject(new Error('location cache build timeout (' + (LOCATION_CACHE_BUILD_TIMEOUT_MS/1000) + 's)'));
      }, LOCATION_CACHE_BUILD_TIMEOUT_MS);
    });
    locationCache.buildingPromise = Promise.race([buildLocationCache(), buildTimeout])
      .then(function(fresh){
        locationCache.data = fresh.data;
        locationCache.stats = fresh.stats;
        locationCache.lastBuildTs = Date.now();
      })
      .catch(function(err){
        console.error('[Rapid7] location cache build failed:', err.message);
        locationCache.lastBuildTs = Date.now();
      })
      .finally(function(){
        locationCache.buildingPromise = null;
      });
  }

  if (locationCache.lastBuildTs === 0) {
    await locationCache.buildingPromise;
  }
}

function resolveLocation(u, cacheData) {
  const wanIp = u.wanIp;

  if (OFFICE_IPS[wanIp]) {
    return {
      city:           OFFICE_IPS[wanIp],
      region:         '',
      country:        '',
      org:            'Office Network',
      connectionType: 'Corporate',
      isOffice:       true,
      isApprox:       false
    };
  }

  if (u.inlineEnrichment) {
    return Object.assign({}, u.inlineEnrichment, { isOffice: false, isApprox: false });
  }

  const key = u.name.toLowerCase();
  const entry = cacheData[key];
  if (entry) {
    if (entry.knownIps[wanIp]) {
      return Object.assign({}, entry.knownIps[wanIp], { isOffice: false, isApprox: false });
    }
    const ips = Object.keys(entry.knownIps);
    if (ips.length) {
      ips.sort(function(a, b) {
        return String(entry.knownIps[b].lastSeenTs).localeCompare(String(entry.knownIps[a].lastSeenTs));
      });
      return Object.assign({}, entry.knownIps[ips[0]], { isOffice: false, isApprox: true });
    }
  }

  return {
    city:           'Unknown',
    region:         '',
    country:        '',
    org:            'Unknown ISP',
    connectionType: 'Unknown',
    isOffice:       false,
    isApprox:       false
  };
}

router.get('/live-presence', rbac.requirePage('live-presence','read'), async (req, res) => {
  if (!API_KEY) return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });

  if (livePresenceCache.data && Date.now() < livePresenceCache.expiresAt && !req.query.fresh) {
    return res.json(Object.assign({}, livePresenceCache.data, { fromCache: true }));
  }

  try {
    await ensureLocationCache();

    const logsets = await getLogsetIds();
    const minutes    = parseInt(req.query.minutes, 10)    || 60;
    const webMinutes = parseInt(req.query.webMinutes, 10) || 30;
    const now        = Date.now();
    const authFrom   = now - (minutes * 60000);
    const webFrom    = now - (webMinutes * 60000);

    const iaId = logsets['Ingress Authentication'] ? logsets['Ingress Authentication'].id : null;
    if (!iaId) return res.status(404).json({ error: 'Ingress Authentication logset not found' });

    const authPromise = queryLogset(
      { name: 'Ingress Auth', id: iaId },
      'where(/Zscaler|ZPA|vpn|ASA/i)',
      authFrom, now
    ).then(function(r){ return { events: r.events || [], error: null }; })
     .catch(function(e){ return { events: [], error: e.message }; });

    const webPromise = queryLogset(
      { name: 'Web Proxy', id: LIVE_PRESENCE_WEB_LOGSET_ID },
      'where(/./)',
      webFrom, now
    ).then(function(r){ return { events: r.events || [], error: null }; })
     .catch(function(e){ return { events: [], error: e.message }; });

    const results = await Promise.all([authPromise, webPromise]);
    const authResult = results[0];
    const webResult  = results[1];

    function parseEvent(e, source) {
      let p = {};
      try {
        if (typeof e.message === 'string' && e.message.startsWith('{')) {
          p = JSON.parse(e.message);
        }
      } catch (_) { return null; }

      let wanIp = null;
      let email = null;
      let inlineEnrichment = null;

      if (source === 'zpa-auth') {
        wanIp = p.source_ip || null;
        if (p.geoip_city || p.geoip_organization) {
          inlineEnrichment = {
            city:           p.geoip_city || 'Unknown',
            region:         p.geoip_region || '',
            country:        p.geoip_country_code || '',
            org:            p.geoip_organization || 'Unknown ISP',
            connectionType: p.geoip_connection_type || 'Unknown',
            lastSeenTs:     p.timestamp || ''
          };
        }
      } else {
        const ext = (p.source_json && p.source_json.extension) || {};
        wanIp = ext.srcPostNAT || null;
        email = ext.usrName || null;
      }

      if (!wanIp) return null;

      const user = p.user || p.account || null;
      if (!user || user === 'unknown') return null;
      if (String(user).toLowerCase().indexOf('machine@') !== -1) return null;

      const timestamp = p.timestamp || e.timestamp || '';

      return {
        user:             String(user),
        email:            email,
        wanIp:            String(wanIp),
        timestamp:        String(timestamp),
        service:          p.service || (source === 'zpa-auth' ? 'ZPA' : 'ZIA Web'),
        source:           source,
        inlineEnrichment: inlineEnrichment
      };
    }

    const users = {};
    function mergeUser(rec) {
      const key = rec.user.toLowerCase();
      if (!users[key]) {
        users[key] = {
          name:             rec.user,
          email:            rec.email,
          sources:          {},
          wanIp:            rec.wanIp,
          lastSeen:         rec.timestamp,
          service:          rec.service,
          inlineEnrichment: rec.inlineEnrichment,
          sessionCount:     0
        };
      }
      const u = users[key];
      u.sessionCount++;
      u.sources[rec.source] = true;
      if (rec.email && !u.email) u.email = rec.email;
      if (rec.timestamp && rec.timestamp > u.lastSeen) {
        u.lastSeen = rec.timestamp;
        u.wanIp    = rec.wanIp;
        u.service  = rec.service;
        if (rec.inlineEnrichment) u.inlineEnrichment = rec.inlineEnrichment;
      }
    }

    authResult.events.forEach(function(e){ const r = parseEvent(e, 'zpa-auth'); if (r) mergeUser(r); });
    webResult.events.forEach( function(e){ const r = parseEvent(e, 'zia-web');  if (r) mergeUser(r); });

    const locMap = {};
    Object.keys(users).forEach(function(k) {
      const u = users[k];
      const loc = resolveLocation(u, locationCache.data);
      const groupKey = loc.city + '|' + loc.org + (loc.isOffice ? '|office' : '');

      if (!locMap[groupKey]) {
        locMap[groupKey] = {
          city:           loc.city,
          region:         loc.region,
          country:        loc.country,
          org:            loc.org,
          connectionType: loc.connectionType,
          isOffice:       loc.isOffice,
          users:          [],
          ips:            {}
        };
      }
      locMap[groupKey].users.push({
        name:         u.name,
        sourceIp:     u.wanIp,
        service:      u.service,
        lastSeen:     u.lastSeen,
        sessionCount: u.sessionCount,
        sources:      Object.keys(u.sources).sort(),
        isApprox:     loc.isApprox
      });
      locMap[groupKey].ips[u.wanIp] = true;
    });

    const locArray = Object.keys(locMap).map(function(k) {
      const loc = locMap[k];
      return {
        city:           loc.city,
        region:         loc.region,
        country:        loc.country,
        org:            loc.org,
        connectionType: loc.connectionType,
        isOffice:       loc.isOffice,
        userCount:      loc.users.length,
        ipCount:        Object.keys(loc.ips).length,
        sessionCount:   loc.users.reduce(function(s,x){ return s + x.sessionCount; }, 0),
        users:          loc.users.sort(function(a,b){ return String(b.lastSeen).localeCompare(String(a.lastSeen)); })
      };
    });

    locArray.sort(function(a,b) {
      if (a.isOffice !== b.isOffice) return a.isOffice ? -1 : 1;
      return b.userCount - a.userCount;
    });

    const payload = {
      success:            true,
      authMinutes:        minutes,
      webMinutes:         webMinutes,
      queriedAt:          new Date().toISOString(),
      totalUsers:         Object.keys(users).length,
      totalLocations:     locArray.length,
      totalSessions:      authResult.events.length + webResult.events.length,
      authEvents:         authResult.events.length,
      webEvents:          webResult.events.length,
      sourceErrors:       { auth: authResult.error, web: webResult.error },
      locationCacheStats: locationCache.stats,
      locationCacheAge:   locationCache.lastBuildTs ? Math.round((Date.now() - locationCache.lastBuildTs) / 1000) : null,
      locations:          locArray
    };

    livePresenceCache = { data: payload, expiresAt: Date.now() + LIVE_PRESENCE_CACHE_MS };
    res.json(Object.assign({}, payload, { fromCache: false }));

  } catch (err) {
    console.error('[Rapid7] Live presence error:', err.message);
    res.status(err.status || 500).json({
      error:  'Rapid7 live presence query failed',
      detail: err.message
    });
  }
});


router.get('/live-presence-debug', rbac.requirePage('live-presence','admin'), async (req, res) => {
  if (!API_KEY) return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });
  try {
    const source = (req.query.source || 'web').toLowerCase();
    const limit  = Math.min(parseInt(req.query.limit, 10) || 3, 10);
    const now    = Date.now();
    const from   = now - (15 * 60000);

    let logsetId, leql, name;
    if (source === 'auth') {
      const logsets = await getLogsetIds();
      logsetId = logsets['Ingress Authentication'] && logsets['Ingress Authentication'].id;
      leql     = 'where(/Zscaler|ZPA|vpn|ASA/i)';
      name     = 'Ingress Auth';
    } else {
      logsetId = LIVE_PRESENCE_WEB_LOGSET_ID;
      leql     = 'where(/./)';
      name     = 'Web Proxy';
    }
    if (!logsetId) return res.status(404).json({ error: 'logset not resolved for source=' + source });

    const result = await queryLogset({ name: name, id: logsetId }, leql, from, now);
    const sampled = (result.events || []).slice(0, limit).map(function(e) {
      let parsed = null;
      try {
        if (typeof e.message === 'string' && e.message.startsWith('{')) {
          parsed = JSON.parse(e.message);
        }
      } catch (_) {}
      return { raw_message: e.message, parsed: parsed, meta_timestamp: e.timestamp };
    });

    res.json({ success: true, source: source, totalInWindow: (result.events || []).length, returned: sampled.length, events: sampled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


router.get('/location-cache-stats', rbac.requirePage('live-presence','admin'), async (req, res) => {
  try {
    const ageSec = locationCache.lastBuildTs ? Math.round((Date.now() - locationCache.lastBuildTs) / 1000) : null;
    const data = locationCache.data || {};
    const keys = Object.keys(data);
    const usersWithMultipleIps = keys.filter(function(k){ return Object.keys(data[k].knownIps).length > 1; }).length;
    const sample = keys.slice(0, 10).map(function(k) {
      const entry = data[k];
      const ips = Object.keys(entry.knownIps).map(function(ip) {
        const en = entry.knownIps[ip];
        return { ip: ip, org: en.org, city: en.city, connectionType: en.connectionType, lastSeen: en.lastSeenTs };
      });
      return { name: entry.displayName, lastAuthTs: entry.lastAuthTs, ipCount: ips.length, ips: ips };
    });
    res.json({
      success:              true,
      ageSec:               ageSec,
      ttlSec:               Math.round(LOCATION_CACHE_TTL_MS / 1000),
      stats:                locationCache.stats,
      totalUsers:           keys.length,
      usersWithMultipleIps: usersWithMultipleIps,
      sampleUsers:          sample
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ────────────────────────────────────────────────────────────────
// Zscaler Web Failures (Web Proxy Activity logset via NSS-for-Web v2)
// ────────────────────────────────────────────────────────────────
const WEB_PROXY_LOGSET_ID = '54414c09-670a-47c7-9e2d-8e38d4c94f09';

router.get('/web-failures', rbac.requirePage('identity-diag','read'), async (req, res) => {
  try {
    const name = (req.query.name || '').trim();
    const limit = Math.min(parseInt(req.query.limit, 10) || 10, 100);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const blockedOnly = req.query.blocked_only !== 'false';
    const hours = Math.min(parseInt(req.query.hours, 10) || 24, 168);

    if (!name || name.length < 3) {
      return res.status(400).json({ error: 'name parameter required (min 3 chars)' });
    }

    // LEQL injection protection: escape regex special chars in name
    const safeName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const blockedClause = blockedOnly ? ' AND is_blocked=/true/i' : '';
    const leql = `where(user=/${safeName}/i${blockedClause})`;

    const now = Date.now();
    const from = now - hours * 60 * 60 * 1000;

    const result = await queryLogset(
      { name: 'Web Proxy Activity', id: WEB_PROXY_LOGSET_ID },
      leql, from, now
    );

    if (result.error) {
      return res.status(500).json({ error: result.error });
    }

    // Parse events, sort desc by timestamp
    const parsed = (result.events || [])
      .map(ev => {
        try {
          const m = typeof ev.message === 'string' ? JSON.parse(ev.message) : ev.message;
          return {
            timestamp: m.timestamp || ev.timestamp,
            user: m.user || '',
            url: m.url || '',
            url_host: m.url_host || '',
            top_private_domain: m.top_private_domain || '',
            is_blocked: String(m.is_blocked || '').toLowerCase() === 'true',
            http_method: m.http_method || '',
            source_ip: m.source_ip || '',
            destination_ip: m.destination_ip || '',
            geoip_country_code: m.geoip_country_code || '',
            geoip_city: m.geoip_city || '',
            user_agent: m.user_agent || '',
            entry_id: m.entry_id || ''
          };
        } catch (e) { return null; }
      })
      .filter(x => x !== null)
      .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));

    // Detect name-collision: count distinct user variants
    const userCounts = {};
    for (const ev of parsed) {
      const u = ev.user || '(blank)';
      userCounts[u] = (userCounts[u] || 0) + 1;
    }
    const userVariants = Object.keys(userCounts)
      .map(u => ({ user: u, count: userCounts[u] }))
      .sort((a, b) => b.count - a.count);

    // Apply offset/limit for pagination
    const page = parsed.slice(offset, offset + limit);
    const hasMore = parsed.length > offset + limit;

    res.json({
      success: true,
      name: name,
      blockedOnly: blockedOnly,
      hours: hours,
      totalFound: parsed.length,
      returned: page.length,
      offset: offset,
      limit: limit,
      hasMore: hasMore,
      events: page,
      userVariants: userVariants,
      multipleVariants: userVariants.length > 1
    });
  } catch (err) {
    console.error('[Rapid7] web-failures error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════
// Web Activity (Zscaler Command Center) — added 2026-07-29
// GET /api/rapid7/web-activity?q=<user-or-domain>&hours=24&max=500
//
// Differences vs /web-failures:
//  • FULL-TEXT LEQL match — catches the email in source_json.extension.usrName
//    (the `user` field in this feed often holds a display name, so
//    user=/email/i misses; this is why /web-failures returned 0 for emails)
//  • Works for DOMAINS too — pass a domain to find every user who hit it
//  • Polls the async log search to completion and follows Next links
//  • Passes through EVERY scalar field the feed carries (fields{}), so the
//    UI can filter on category/app/action/status without backend rework
//  • RBAC: zscaler-diag page (not identity-diag) — Command Center users
// ════════════════════════════════════════════════════════════════════
router.get('/web-activity', rbac.requirePage('zscaler-diag', 'read'), async (req, res) => {
  try {
    const q = ((req.query.q || req.query.name) || '').trim();
    const hours = Math.min(parseInt(req.query.hours, 10) || 24, 168);
    const maxEvents = Math.min(parseInt(req.query.max, 10) || 500, 1000);
    if (!q || q.length < 3) return res.status(400).json({ error: 'q parameter required (min 3 chars)' });
    if (!API_KEY) return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });

    const safe = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const leql = `where(/${safe}/i)`;
    const now = Date.now(), from = now - hours * 3600000;

    // Query with big pages; poll while in progress; follow Next when complete
    const qs = `?query=${encodeURIComponent(leql)}&from=${from}&to=${now}&per_page=300`;
    let data = await r7request('GET', `/log_search/query/logsets/${WEB_PROXY_LOGSET_ID}${qs}`);
    let events = data.events || [];
    let guard = 0;
    while (guard < 14 && events.length < maxEvents) {
      const links = data.links || [];
      const progress = data.progress;
      let nextUrl = null;
      if (progress !== undefined && progress !== null && progress < 100) {
        const self = links.find(l => l.rel === 'Self');
        nextUrl = self && self.href;
        if (nextUrl) await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
      } else {
        const nxt = links.find(l => l.rel === 'Next');
        nextUrl = nxt && nxt.href;
      }
      if (!nextUrl) break;
      guard++;
      if (!nextUrl.includes('per_page')) nextUrl += (nextUrl.includes('?') ? '&' : '?') + 'per_page=300';
      data = await r7requestUrl(nextUrl);
      events = events.concat(data.events || []);
    }
    const truncated = events.length > maxEvents;
    events = events.slice(0, maxEvents);

    const out = [];
    const variants = {};
    for (const ev of events) {
      let m = {};
      try { m = typeof ev.message === 'string' ? JSON.parse(ev.message) : (ev.message || {}); } catch (_) { continue; }
      const ext = (m.source_json && m.source_json.extension) || {};
      const fields = {};
      const collect = function (obj) {
        for (const k in obj) {
          const v = obj[k];
          if (v === null || v === undefined) continue;
          const t = typeof v;
          if (t === 'string' || t === 'number' || t === 'boolean') {
            const s = String(v);
            if (s.length <= 300) fields[k] = v;
          }
        }
      };
      collect(m); collect(ext);
      const user = ext.usrName || m.user || m.account || '';
      variants[user || '(blank)'] = (variants[user || '(blank)'] || 0) + 1;
      out.push({
        timestamp: m.timestamp || ev.timestamp,
        user: user,
        display_user: m.user || null,
        url: m.url || ext.request || '',
        url_host: m.url_host || ext.dhost || '',
        top_private_domain: m.top_private_domain || '',
        is_blocked: String(m.is_blocked || '').toLowerCase() === 'true' || /block|denied/i.test(String(ext.act || m.action || '')),
        action: ext.act || m.action || null,
        reason: ext.reason || m.reason || null,
        category: ext.cat || m.url_category || m.urlcategory || ext.urlcategory || ext.urlClass || null,
        app: ext.app || m.appname || ext.appname || null,
        http_method: m.http_method || ext.requestMethod || '',
        status: m.http_status || ext.outcome || ext.status || null,
        source_ip: m.source_ip || ext.src || '',
        destination_ip: m.destination_ip || ext.dst || '',
        geoip_city: m.geoip_city || '',
        geoip_country_code: m.geoip_country_code || '',
        user_agent: String(m.user_agent || ext.requestClientApplication || '').slice(0, 160),
        fields: fields
      });
    }
    out.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
    const userVariants = Object.keys(variants).map(u => ({ user: u, count: variants[u] })).sort((a, b) => b.count - a.count);

    res.json({
      success: true,
      q: q,
      hours: hours,
      totalFound: out.length,
      truncated: truncated,
      pollRounds: guard,
      events: out,
      userVariants: userVariants,
      multipleVariants: userVariants.length > 1
    });
  } catch (err) {
    console.error('[Rapid7] web-activity error:', err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════
//  IP CROSS-REFERENCE — find which users appear in auth logs for a given IP
// ═══════════════════════════════════════════════════════════════════════
// GET /api/rapid7/ip-xref?ip=1.2.3.4&hours=720&subnet=1
//
// Searches Asset Authentication, Ingress Authentication, SSO Authentication
// logsets for any events containing the IP address. Returns unique usernames
// found, with event counts. If subnet=1, also matches the /24 (IPv4) or
// first 4 hextets (IPv6) to catch rotating-IP campaigns.
//
// Used by Sign-In Watch to determine if a violation's attacker IP has
// appeared against other users in Rapid7 auth logs.

router.get('/ip-xref', rbac.requirePage('identity-diag', 'read'), async (req, res) => {
  const { ip, hours, subnet } = req.query;
  if (!ip) return res.status(400).json({ error: 'ip query parameter is required' });
  if (!API_KEY) return res.status(500).json({ error: 'RAPID7_API_KEY not configured' });

  try {
    const logsets = await getLogsetIds();
    const targets = ['Asset Authentication', 'Ingress Authentication', 'SSO Authentication']
      .filter(name => logsets[name])
      .map(name => ({ name, id: logsets[name].id }));

    if (targets.length === 0) {
      return res.status(404).json({ error: 'No authentication logsets found' });
    }

    const hoursBack = Math.min(parseInt(hours) || 720, 2160); // default 30d, max 90d
    const now  = Date.now();
    const from = now - (hoursBack * 3600000);

    // Build search term: exact IP, or subnet prefix for rotating-IP campaigns
    let searchTerm = ip;
    if (subnet === '1') {
      if (ip.includes(':')) {
        // IPv6: match first 4 hextets
        searchTerm = ip.split(':').slice(0, 4).join(':');
      } else {
        // IPv4: match /24
        searchTerm = ip.split('.').slice(0, 3).join('.') + '.';
      }
    }

    // IPs contain only digits, dots, colons — just escape dots for regex
    const escapedTerm = searchTerm.split('.').join('[.]');
    const leql = 'where(/' + escapedTerm + '/i)';

    const results = await Promise.all(targets.map(ls => queryLogset(ls, leql, from, now)));

    // Extract unique usernames from all matching events
    const userMap = new Map(); // username → { count, logsets, lastSeen, ips }
    for (const r of results) {
      for (const e of r.events) {
        let parsed = {};
        try {
          if (typeof e.message === 'string' && e.message.startsWith('{')) {
            parsed = JSON.parse(e.message);
          }
        } catch (_) {}

        const user = parsed.user || parsed.account || parsed.username || null;
        const eventIp = parsed.source_ip || parsed.ip_address || null;

        if (!user) continue;
        const key = String(user).toLowerCase();
        if (!userMap.has(key)) {
          userMap.set(key, { username: user, count: 0, logsets: new Set(), ips: new Set(), lastSeen: null });
        }
        const entry = userMap.get(key);
        entry.count++;
        entry.logsets.add(r.logset);
        if (eventIp) entry.ips.add(eventIp);
        if (!entry.lastSeen || e.timestamp > entry.lastSeen) entry.lastSeen = e.timestamp;
      }
    }

    const users = [...userMap.values()].map(u => ({
      username: u.username,
      count: u.count,
      logsets: [...u.logsets],
      unique_ips: u.ips.size,
      last_seen: u.lastSeen ? new Date(u.lastSeen).toISOString() : null,
    })).sort((a, b) => b.count - a.count);

    res.json({
      ok: true,
      query_ip: ip,
      search_term: searchTerm,
      subnet_mode: subnet === '1',
      hours_back: hoursBack,
      total_events: results.reduce((s, r) => s + r.events.length, 0),
      unique_users: users.length,
      users,
      logsets: results.map(r => ({ name: r.logset, events: r.events.length, error: r.error || null })),
    });
  } catch (err) {
    console.error('[Rapid7] IP xref error:', err.message);
    res.status(err.status || 500).json({ error: 'Rapid7 IP xref failed', detail: err.message });
  }
});

module.exports = router;
