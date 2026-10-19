'use strict';
const express = require('express');
const router = express.Router();
const offload = require('./sqlite-offload');   // read-only SQLite off the event loop (CHG-ARCH-03)
// ---- RBAC enforcement (Slice 6: zscaler-diag) ----
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
const aiCatLib = require('./ai-catalog-lib'); aiCatLib.init(rbacPool); aiCatLib.refresh().catch(function () {}); // AI catalog cache warm (CC-AICAT)
router.use(rbac.loadCurrentUser);
// ---------------------------------------------------------------------

// Import auth helpers from existing zscaler-lookup module
let ziaAuth, zpaAuth, httpsRequest;
const ZLIST_TIMEOUT = parseInt(process.env.ZSCALER_LIST_TIMEOUT_MS, 10) || 60000;
try {
  ({ ziaAuth, zpaAuth, httpsRequest } = require('./zscaler-lookup'));
  console.log('[zscaler-diag] auth helpers loaded');
} catch (e) {
  console.warn('[zscaler-diag] zscaler-lookup not available:', e.message);
}

// ── Helper: authenticated ZIA GET ──
async function ziaGet(path) {
  if (!ziaAuth) throw new Error('ZIA auth not available');
  const token = await ziaAuth();
  const url = new URL(process.env.ZIA_BASE_URL + '/' + path);
  const res = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token }, timeoutMs: ZLIST_TIMEOUT });
  if (res.status === 401 || res.status === 403) {
    const newToken = await ziaAuth(true);
    const retry = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + newToken }, timeoutMs: ZLIST_TIMEOUT });
    return retry;
  }
  return res;
}

// ── Helper: authenticated ZIA POST ──
async function ziaPost(path, body) {
  if (!ziaAuth) throw new Error('ZIA auth not available');
  const token = await ziaAuth();
  const url = new URL(process.env.ZIA_BASE_URL + '/' + path);
  const res = await httpsRequest(url, { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' } }, JSON.stringify(body));
  if (res.status === 401 || res.status === 403) {
    const newToken = await ziaAuth(true);
    const retry = await httpsRequest(url, { method: 'POST', headers: { Authorization: 'Bearer ' + newToken, 'Content-Type': 'application/json' } }, JSON.stringify(body));
    return retry;
  }
  return res;
}

// ── Helper: authenticated ZPA GET ──
async function zpaGet(path) {
  if (!zpaAuth) throw new Error('ZPA auth not available');
  const token = await zpaAuth();
  const cid = process.env.ZPA_CUSTOMER_ID;
  if (!cid) throw new Error('ZPA_CUSTOMER_ID not configured');
  const url = new URL('https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/' + cid + '/' + path);
  const res = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
  return res;
}

// ═══════════════════════════════════════════════
// ZIA ROUTES
// ═══════════════════════════════════════════════

// ── 1. URL Category Lookup ──
// POST /api/zscaler/zia/url-lookup   body: { urls: ["example.com"] }
router.post('/zia/url-lookup', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  const urls = req.body && req.body.urls;
  if (!urls || !Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({ error: 'urls array is required' });
  }
  if (urls.length > 100) {
    return res.status(400).json({ error: 'Max 100 URLs per request' });
  }
  try {
    const result = await ziaPost('urlLookup', urls);
    if (result.status !== 200) {
      return res.status(502).json({ error: 'ZIA returned HTTP ' + result.status, raw: typeof result.body === 'string' ? result.body.slice(0, 200) : null });
    }
    return res.json({ results: result.body, count: Array.isArray(result.body) ? result.body.length : 0 });
  } catch (err) {
    console.error('[zscaler-diag] url-lookup error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── 2. URL Filtering Rules ──
router.get('/zia/url-filtering-rules', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  const forceLive = req.query.live === '1';
  try {
    const pool = getZiaCachePool(router);
    if (!forceLive) {
      const [rows] = await pool.query('SELECT payload, synced_at FROM zia_url_rules_cache ORDER BY id DESC LIMIT 1');
      if (rows.length) {
        const data = JSON.parse(rows[0].payload);
        return res.json(Object.assign({}, data, { fromCache: true, synced_at: rows[0].synced_at }));
      }
    }
    // Live fetch (cache miss or ?live=1)
    const result = await ziaGet('urlFilteringRules');
    if (result.status !== 200) return res.status(502).json({ error: 'ZIA returned HTTP ' + result.status });
    const rules   = Array.isArray(result.body) ? result.body : [];
    const payload = { rules: rules, count: rules.length };
    // Refresh cache
    try {
      await pool.query('TRUNCATE TABLE zia_url_rules_cache');
      await pool.query('INSERT INTO zia_url_rules_cache (payload, synced_at) VALUES (?, NOW())', [JSON.stringify(payload)]);
    } catch (cacheErr) { console.warn('[zscaler-diag] url-rules cache write failed:', cacheErr.message); }
    return res.json(Object.assign({}, payload, { fromCache: false, synced_at: new Date().toISOString() }));
  } catch (err) {
    console.error('[zscaler-diag] url-filtering-rules error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── 3. Security Policy ──
router.get('/zia/security', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  try {
    const result = await ziaGet('security');
    if (result.status !== 200) {
      return res.status(502).json({ error: 'ZIA returned HTTP ' + result.status });
    }
    return res.json({ policy: result.body });
  } catch (err) {
    console.error('[zscaler-diag] security error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── 4. DLP Dictionaries ──
router.get('/zia/dlp-dictionaries', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  try {
    const result = await ziaGet('dlpDictionaries');
    if (result.status !== 200) {
      return res.status(502).json({ error: 'ZIA returned HTTP ' + result.status });
    }
    var dicts = Array.isArray(result.body) ? result.body : [];
    return res.json({ dictionaries: dicts, count: dicts.length });
  } catch (err) {
    console.error('[zscaler-diag] dlp-dictionaries error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════
// ZPA ROUTES
// ═══════════════════════════════════════════════

// ── 5. App Connector Groups ──
router.get('/zpa/connector-groups', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  try {
    const result = await zpaFetchCached('connectorGroups', 'appConnectorGroup');
    return res.json({ groups: result.data, count: result.data.length, totalCount: result.data.length, fromCache: result.fromCache });
  } catch (err) {
    console.error('[zscaler-diag] connector-groups error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── 6. Application Segments ──
router.get('/zpa/applications', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  try {
    const result = await zpaFetchCached('applications', 'application');
    return res.json({ applications: result.data, count: result.data.length, totalCount: result.data.length, fromCache: result.fromCache });
  } catch (err) {
    console.error('[zscaler-diag] applications error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── 7. Access Policies ──
router.get('/zpa/access-policies', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  try {
    const result = await zpaFetchCached('accessPolicies', 'policySet/rules/policyType/ACCESS_POLICY');
    return res.json({ policies: result.data, count: result.data.length, fromCache: result.fromCache });
  } catch (err) {
    console.error('[zscaler-diag] access-policies error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── 8. Server Groups ──
router.get('/zpa/server-groups', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  try {
    const result = await zpaFetchCached('serverGroups', 'serverGroup');
    return res.json({ groups: result.data, count: result.data.length, totalCount: result.data.length, fromCache: result.fromCache });
  } catch (err) {
    console.error('[zscaler-diag] server-groups error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── ZPA User Access Cross-Reference ──
// GET /api/zscaler/zpa/user-access?q=user@email.com
router.get('/zpa/user-access', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q) return res.status(400).json({ error: 'Query parameter "q" (email) is required' });

  try {
    // 1. Fetch all access policies
    // 1. Fetch access policies, app segments, segment groups (cached & paginated)
    const [policyResult, appResult, segResult] = await Promise.all([
      zpaFetchCached('accessPolicies', 'policySet/rules/policyType/ACCESS_POLICY'),
      zpaFetchCached('applications',   'application'),
      zpaFetchCached('segmentGroups',  'segmentGroup'),
    ]);
    var allRules = policyResult.data;
    var allApps  = appResult.data;
    var allSegs  = segResult.data;

    // 2. Build lookup maps
    var appMap = {};
    allApps.forEach(function(a) { appMap[a.id] = a; });
    var segMap = {};
    allSegs.forEach(function(s) { segMap[s.id] = s; });

    // 4. For each rule, determine if user matches
    var matchedPolicies = [];

    allRules.forEach(function(rule) {
      var conditions = rule.conditions || [];
      var hasScimUserCondition = false;
      var userMatches = false;
      var appOperands = [];
      var otherConditions = [];

      conditions.forEach(function(cond) {
        var operands = cond.operands || [];

        // Check if this condition block contains SCIM userName checks
        var scimUserOps = operands.filter(function(op) {
          return op.objectType === 'SCIM' && op.name === 'userName';
        });

        if (scimUserOps.length > 0) {
          hasScimUserCondition = true;
          // OR logic — any match means user qualifies
          var matched = scimUserOps.some(function(op) {
            return (op.rhs || '').toLowerCase() === q;
          });
          if (matched) userMatches = true;
        }

        // Check for SCIM_GROUP conditions (group-based access)
        var scimGroupOps = operands.filter(function(op) {
          return op.objectType === 'SCIM_GROUP';
        });
        if (scimGroupOps.length > 0) {
          hasScimUserCondition = true;
          // We can't resolve group membership here, but flag it
          otherConditions.push({
            type: 'SCIM_GROUP',
            groups: scimGroupOps.map(function(op) { return op.name || op.rhs; })
          });
        }

        // Collect APP and APP_GROUP operands
        operands.forEach(function(op) {
          if (op.objectType === 'APP' || op.objectType === 'APP_GROUP') {
            appOperands.push({
              type: op.objectType,
              id: op.rhs,
              name: op.name || null
            });
          }
          if (op.objectType === 'CLIENT_TYPE') {
            otherConditions.push({ type: 'CLIENT_TYPE', value: op.rhs || op.name });
          }
          if (op.objectType === 'POSTURE') {
            otherConditions.push({ type: 'POSTURE', name: op.name || op.lhs });
          }
          if (op.objectType === 'PLATFORM') {
            otherConditions.push({ type: 'PLATFORM', value: op.lhs });
          }
        });
      });

      // Policy applies if:
      //   a) No SCIM user condition at all (applies to everyone), OR
      //   b) Has SCIM user condition and user matched
      var applies = !hasScimUserCondition || userMatches;
      var matchReason = !hasScimUserCondition ? 'No user restriction (applies to all users)' : 'Direct SCIM user match';

      if (!applies) return;

      // Resolve app details
      var accessibleApps = [];
      appOperands.forEach(function(op) {
        if (op.type === 'APP') {
          var app = appMap[op.id];
          accessibleApps.push({
            name: op.name || (app ? app.name : op.id),
            type: 'App Segment',
            domainNames: app ? (app.domainNames || []) : [],
            tcpPorts: app ? (app.tcpPortRanges || []) : [],
            enabled: app ? app.enabled : null
          });
        } else if (op.type === 'APP_GROUP') {
          var seg = segMap[op.id];
          var segName = op.name || (seg ? seg.name : op.id);
          // Find all apps in this segment group
          var segApps = allApps.filter(function(a) {
            return a.segmentGroupId === op.id || a.segmentGroupName === segName;
          });
          if (segApps.length > 0) {
            segApps.forEach(function(a) {
              accessibleApps.push({
                name: a.name,
                type: 'Via: ' + segName,
                domainNames: a.domainNames || [],
                tcpPorts: a.tcpPortRanges || [],
                enabled: a.enabled
              });
            });
          } else {
            // No individual apps resolved — show the group itself
            accessibleApps.push({
              name: segName,
              type: 'Segment Group',
              domainNames: [],
              tcpPorts: [],
              enabled: seg ? seg.enabled : null
            });
          }
        }
      });

      matchedPolicies.push({
        policyName: rule.name || 'Unnamed',
        action: rule.action || 'UNKNOWN',
        matchReason: matchReason,
        order: rule.ruleOrder || rule.order || null,
        otherConditions: otherConditions,
        apps: accessibleApps,
        appCount: accessibleApps.length
      });
    });

    // Deduplicate apps across policies
    var allAccessible = {};
    matchedPolicies.forEach(function(p) {
      if (p.action !== 'ALLOW') return;
      p.apps.forEach(function(a) {
        if (!allAccessible[a.name]) allAccessible[a.name] = a;
      });
    });

    return res.json({
      user: q,
      matchedPolicies: matchedPolicies,
      policyCount: matchedPolicies.length,
      uniqueApps: Object.values(allAccessible),
      uniqueAppCount: Object.keys(allAccessible).length,
      totalPoliciesChecked: allRules.length
    });

  } catch (err) {
    console.error('[zscaler-diag] user-access error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Health Check ──
router.get('/health', async (req, res) => {
  var status = { zia: 'unconfigured', zpa: 'unconfigured' };
  if (process.env.ZSCALER_CLIENT_ID && process.env.ZSCALER_CLIENT_SECRET) {
    try { await ziaAuth(); status.zia = 'connected'; } catch (e) { status.zia = 'error: ' + e.message; }
  }
  if (process.env.ZSCALER_CLIENT_ID && process.env.ZSCALER_CLIENT_SECRET) {
    try { await zpaAuth(); status.zpa = 'connected'; } catch (e) { status.zpa = 'error: ' + e.message; }
  }
  res.json({ status: status, checkedAt: new Date().toISOString() });
});

// ═══════════════════════════════════════════════════════════════════════
// APP SEGMENT LOOKUP (Phase B — hostname/IP → app segment cross-reference)
// ═══════════════════════════════════════════════════════════════════════

// ── Module-level cache for ZPA config data ──
// 5-minute TTL. App segments and policies rarely change within a
// help-desk session; caching means one round-trip per 5 min, not per lookup.
const ZPA_CACHE_TTL_MS = 5 * 60 * 1000;
const zpaCache = {
  applications:    { data: null, expiresAt: 0 },
  segmentGroups:   { data: null, expiresAt: 0 },
  accessPolicies:  { data: null, expiresAt: 0 },
  connectorGroups: { data: null, expiresAt: 0 },
  serverGroups:    { data: null, expiresAt: 0 },
};

async function zpaFetchCached(key, zpaPath) {
  const now = Date.now();
  if (zpaCache[key].data && now < zpaCache[key].expiresAt) {
    return { data: zpaCache[key].data, fromCache: true };
  }

  // ZPA hard-caps page size at 20 regardless of what we request. Paginate
  // using the server-reported totalPages rather than guessing by short-page.
  const MAX_PAGES = 100;    // safety cap — 100 * 20 = 2000 items
  const PAGE_SIZE = 20;     // ZPA's actual limit; asking for more is ignored
  // Strip any page/pageSize the caller passed
  const cleanPath = zpaPath
    .replace(/[?&](page|pageSize)=\d+/g, '')
    .replace(/\?&/, '?')
    .replace(/\?$/, '');
  const joiner = cleanPath.indexOf('?') >= 0 ? '&' : '?';

  const allItems = [];
  let page = 1;
  let totalPages = 1;  // assume 1 until the first response tells us otherwise

  while (page <= MAX_PAGES) {
    const pagedPath = cleanPath + joiner + 'page=' + page + '&pageSize=' + PAGE_SIZE;
    const res = await zpaGet(pagedPath);
    if (res.status !== 200) {
      throw new Error('ZPA ' + pagedPath + ' returned HTTP ' + res.status);
    }
    const body = res.body || {};
    const list = Array.isArray(body.list) ? body.list : (Array.isArray(body) ? body : []);
    allItems.push.apply(allItems, list);

    // Server reports totalPages — use it authoritatively
    if (body.totalPages !== undefined) {
      const tp = parseInt(body.totalPages, 10);
      if (!isNaN(tp)) totalPages = tp;
    }
    // Safety: if server returned nothing, stop even if page < totalPages
    if (list.length === 0) break;
    if (page >= totalPages) break;
    page++;
  }

  if (page > MAX_PAGES) {
    console.warn('[zscaler-diag] zpaFetchCached ' + key + ' hit MAX_PAGES cap');
  }

  zpaCache[key] = { data: allItems, expiresAt: now + ZPA_CACHE_TTL_MS };
  return { data: allItems, fromCache: false };
}

// ── Input normalization ──
// Accepts: FQDN, FQDN:port, scheme://FQDN/path, IPv4, IPv4/CIDR
// Returns: { target, type: 'ipv4'|'fqdn'|'unknown' }
function normalizeTarget(raw) {
  let s = (raw || '').trim().toLowerCase();
  if (!s) return { target: '', type: 'unknown' };
  // Strip scheme
  s = s.replace(/^[a-z]+:\/\//, '');
  // Strip path
  const slashIdx = s.indexOf('/');
  if (slashIdx >= 0) s = s.slice(0, slashIdx);
  // Strip port (but leave IPv6 brackets alone if present — not supporting v6 today)
  if (s.indexOf('[') < 0) {
    const colonIdx = s.lastIndexOf(':');
    if (colonIdx > 0) {
      const portPart = s.slice(colonIdx + 1);
      if (/^\d+$/.test(portPart)) s = s.slice(0, colonIdx);
    }
  }
  const isIPv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s);
  return { target: s, type: isIPv4 ? 'ipv4' : (s.length > 0 ? 'fqdn' : 'unknown') };
}

// ── IPv4 utilities (pure, no network calls) ──
function ipv4ToLong(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const n0 = parseInt(parts[0], 10), n1 = parseInt(parts[1], 10),
        n2 = parseInt(parts[2], 10), n3 = parseInt(parts[3], 10);
  if ([n0,n1,n2,n3].some(x => isNaN(x) || x < 0 || x > 255)) return null;
  // Use multiplication instead of shift to avoid JS 32-bit sign issues
  return (n0 * 16777216) + (n1 * 65536) + (n2 * 256) + n3;
}
function ipv4InCIDR(ip, cidrStr) {
  const parts = cidrStr.split('/');
  if (parts.length !== 2) return false;
  const network = ipv4ToLong(parts[0].trim());
  const prefix = parseInt(parts[1].trim(), 10);
  const ipLong = ipv4ToLong(ip);
  if (network === null || ipLong === null || isNaN(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - prefix)) >>> 0);
  return (ipLong & mask) === (network & mask);
}
function ipv4InRange(ip, startStr, endStr) {
  const ipLong = ipv4ToLong(ip);
  const startLong = ipv4ToLong(startStr.trim());
  const endLong = ipv4ToLong(endStr.trim());
  if (ipLong === null || startLong === null || endLong === null) return false;
  return ipLong >= startLong && ipLong <= endLong;
}

// ── Match one target against one domainNames[] entry ──
// Returns: { match: bool, matchType: string, matchedPattern: string } or null
function tryMatchPattern(normalized, pattern) {
  const target = normalized.target;
  const p = (pattern || '').trim().toLowerCase();
  if (!p) return null;

  if (normalized.type === 'fqdn') {
    if (target === p) return { match: true, matchType: 'exact', matchedPattern: pattern };
    if (p.indexOf('*.') === 0) {
      const suffix = p.slice(1); // leading dot kept
      if (target.endsWith(suffix) && target.length > suffix.length) {
        return { match: true, matchType: 'wildcard', matchedPattern: pattern };
      }
    }
    // FQDN input might also match a raw IP entry if DNS resolves to it —
    // we don't resolve DNS server-side (that would add latency and complexity).
    // Flag this case so UI can suggest the user also try the IP.
    return null;
  }

  if (normalized.type === 'ipv4') {
    if (target === p) return { match: true, matchType: 'exact-ip', matchedPattern: pattern };
    if (p.indexOf('/') > 0 && ipv4InCIDR(target, p)) {
      return { match: true, matchType: 'cidr', matchedPattern: pattern };
    }
    // Range syntax "10.0.0.1-10.0.0.100" (rare in ZPA but handle gracefully)
    if (p.indexOf('-') > 0) {
      const rangeParts = p.split('-');
      if (rangeParts.length === 2 && ipv4InRange(target, rangeParts[0], rangeParts[1])) {
        return { match: true, matchType: 'range', matchedPattern: pattern };
      }
    }
    // IP target could also match an FQDN pattern if ZPA resolves it —
    // not checked here (would require DNS; out of scope).
    return null;
  }

  return null;
}

// ── Main endpoint ──
// GET /api/zscaler/zpa/app-segment-lookup?q=<target>&user=<email>
router.get('/zpa/app-segment-lookup', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  const raw = (req.query.q || '').trim();
  const user = (req.query.user || '').trim().toLowerCase();

  if (!raw) return res.status(400).json({ error: 'Query parameter "q" (hostname or IP) is required' });

  const normalized = normalizeTarget(raw);
  if (normalized.type === 'unknown' || !normalized.target) {
    return res.status(400).json({ error: 'Could not parse "' + raw + '" as a hostname or IPv4 address' });
  }

  try {
    // Fetch all three datasets (cached where possible)
    const [appsResult, segGroupsResult, policiesResult] = await Promise.all([
      zpaFetchCached('applications',   'application?page=1&pageSize=500'),
      zpaFetchCached('segmentGroups',  'segmentGroup?page=1&pageSize=500'),
      zpaFetchCached('accessPolicies', 'policySet/rules/policyType/ACCESS_POLICY'),
    ]);
    const allApps = appsResult.data;
    const allSegGroups = segGroupsResult.data;
    const allPolicies = policiesResult.data;

    // Build segment group ID → name map
    const segGroupById = {};
    allSegGroups.forEach(function(g) { segGroupById[g.id] = g; });

    // Match each app segment's domainNames[] against the target
    const matchedSegments = [];
    allApps.forEach(function(app) {
      const domains = app.domainNames || [];
      for (let i = 0; i < domains.length; i++) {
        const m = tryMatchPattern(normalized, domains[i]);
        if (m && m.match) {
          const serverGroups = (app.serverGroups || []).map(function(sg) {
            return { id: sg.id, name: sg.name, enabled: sg.enabled, dynamicDiscovery: sg.dynamicDiscovery };
          });
          matchedSegments.push({
            id: app.id,
            name: app.name,
            enabled: app.enabled,
            description: app.description || null,
            bypassType: app.bypassType || 'NEVER',
            ipAnchored: !!app.ipAnchored,
            segmentGroupId: app.segmentGroupId || null,
            segmentGroupName: app.segmentGroupName || (segGroupById[app.segmentGroupId] ? segGroupById[app.segmentGroupId].name : null),
            segmentGroupEnabled: app.segmentGroupId && segGroupById[app.segmentGroupId] ? segGroupById[app.segmentGroupId].enabled : null,
            tcpPortRanges: app.tcpPortRanges || [],
            udpPortRanges: app.udpPortRanges || [],
            serverGroups: serverGroups,
            domainNames: domains,
            matchType: m.matchType,
            matchedPattern: m.matchedPattern,
          });
          break; // one match per segment is enough
        }
      }
    });

    // Find all access policies that gate any matched segment
    // (via APP operand referring to segment.id, or APP_GROUP operand referring to segment.segmentGroupId)
    const matchedSegmentIds = new Set(matchedSegments.map(function(s) { return s.id; }));
    const matchedSegGroupIds = new Set(matchedSegments.map(function(s) { return s.segmentGroupId; }).filter(Boolean));

    const gatingPolicies = [];
    allPolicies.forEach(function(rule) {
      const conditions = rule.conditions || [];
      const gatesVia = [];
      const otherConditions = [];

      conditions.forEach(function(cond) {
        (cond.operands || []).forEach(function(op) {
          if (op.objectType === 'APP' && matchedSegmentIds.has(op.rhs)) {
            gatesVia.push({ type: 'APP', id: op.rhs, name: op.name || null });
          } else if (op.objectType === 'APP_GROUP' && matchedSegGroupIds.has(op.rhs)) {
            gatesVia.push({ type: 'APP_GROUP', id: op.rhs, name: op.name || null });
          } else if (op.objectType === 'SCIM' && op.name === 'userName') {
            otherConditions.push({ type: 'SCIM_USER', email: op.rhs, idpId: op.idpId });
          } else if (op.objectType === 'SCIM_GROUP') {
            otherConditions.push({ type: 'SCIM_GROUP', groupName: op.name || op.rhs, idpId: op.idpId });
          } else if (op.objectType === 'POSTURE') {
            otherConditions.push({ type: 'POSTURE', profileName: op.name, expected: op.rhs });
          } else if (op.objectType === 'PLATFORM') {
            otherConditions.push({ type: 'PLATFORM', platform: op.lhs, allowed: op.rhs === 'true' });
          } else if (op.objectType === 'CLIENT_TYPE') {
            otherConditions.push({ type: 'CLIENT_TYPE', value: op.rhs || op.name });
          }
        });
      });

      if (gatesVia.length > 0) {
        gatingPolicies.push({
          id: rule.id,
          name: rule.name || 'Unnamed',
          description: rule.description || null,
          action: rule.action || 'UNKNOWN',
          ruleOrder: rule.ruleOrder || rule.order || null,
          gatesVia: gatesVia,
          otherConditions: otherConditions,
        });
      }
    });

    // Sort by ruleOrder (numeric, lower = higher priority)
    gatingPolicies.sort(function(a, b) {
      const ao = parseInt(a.ruleOrder, 10); const bo = parseInt(b.ruleOrder, 10);
      if (isNaN(ao) && isNaN(bo)) return 0;
      if (isNaN(ao)) return 1;
      if (isNaN(bo)) return -1;
      return ao - bo;
    });

    // ── Optional user verdict ──
    let userVerdict = null;
    if (user) {
      userVerdict = evaluateUserVerdict(user, gatingPolicies);
      // Annotate each gating policy with per-user applicability
      gatingPolicies.forEach(function(p) {
        p.appliesToUser = policyAppliesToUser(user, p);
      });
    }

    // ── Suggestions on no match ──
    // When the input doesn't match any segment, look for domainNames that
    // CONTAIN the target as a substring — catches typos and FQDN/IP confusion.
    let suggestions = [];
    if (matchedSegments.length === 0 && normalized.target.length >= 3) {
      const needle = normalized.target;
      const hits = [];
      allApps.forEach(function(app) {
        (app.domainNames || []).forEach(function(d) {
          const dLc = (d || '').toLowerCase();
          if (dLc.indexOf(needle) >= 0 || needle.indexOf(dLc) >= 0) {
            hits.push({
              segmentName: app.name,
              segmentId: app.id,
              matchedDomain: d,
              segmentGroupName: app.segmentGroupName || null,
            });
          }
        });
      });
      // Dedupe by segmentId + domain, cap at 5
      const seen = new Set();
      suggestions = hits.filter(function(h) {
        const k = h.segmentId + '|' + h.matchedDomain;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      }).slice(0, 5);
    }

    return res.json({
      target: normalized.target,
      targetType: normalized.type,
      originalQuery: raw,
      matchedSegmentCount: matchedSegments.length,
      matchedSegments: matchedSegments,
      gatingPolicyCount: gatingPolicies.length,
      gatingPolicies: gatingPolicies,
      userVerdict: userVerdict,
      suggestions: suggestions,
      cacheStatus: {
        applications:   appsResult.fromCache ? 'cached' : 'fresh',
        segmentGroups:  segGroupsResult.fromCache ? 'cached' : 'fresh',
        accessPolicies: policiesResult.fromCache ? 'cached' : 'fresh',
      },
      totalCounts: {
        applications:   allApps.length,
        segmentGroups:  allSegGroups.length,
        accessPolicies: allPolicies.length,
      },
    });

  } catch (err) {
    console.error('[zscaler-diag] app-segment-lookup error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── User verdict evaluation ──
// Given a user email and a list of gating policies (ordered by rule priority),
// walk the rules in order and return the first one that conclusively ALLOWs or
// DENYs the user. Flag indeterminate cases (SCIM_GROUP conditions we can't
// resolve here) as "uncertain".

// Helper: determine if a single policy applies to a given user.
// Returns: 'yes' | 'no' | 'uncertain'
function policyAppliesToUser(userEmail, policy) {
  const emailLc = (userEmail || '').toLowerCase();
  const conds = policy.otherConditions || [];
  const scimUserConds = conds.filter(function(c) { return c.type === 'SCIM_USER'; });
  const scimGroupConds = conds.filter(function(c) { return c.type === 'SCIM_GROUP'; });

  if (scimUserConds.length > 0) {
    const match = scimUserConds.some(function(c) { return (c.email || '').toLowerCase() === emailLc; });
    return match ? 'yes' : 'no';
  }
  if (scimGroupConds.length > 0) {
    // Can't resolve without SCIM group membership lookup
    return 'uncertain';
  }
  // No user/group condition — applies to everyone
  return 'yes';
}
function evaluateUserVerdict(userEmail, gatingPolicies) {
  const emailLc = userEmail.toLowerCase();
  let firstAllowing = null;
  let firstDenying = null;
  let uncertainPolicies = [];

  for (let i = 0; i < gatingPolicies.length; i++) {
    const policy = gatingPolicies[i];
    const conds = policy.otherConditions || [];
    const scimUserConds = conds.filter(function(c) { return c.type === 'SCIM_USER'; });
    const scimGroupConds = conds.filter(function(c) { return c.type === 'SCIM_GROUP'; });

    let appliesToUser = null; // true / false / null(uncertain)

    if (scimUserConds.length > 0) {
      // Explicit user list — deterministic
      const match = scimUserConds.some(function(c) { return (c.email || '').toLowerCase() === emailLc; });
      appliesToUser = match;
    } else if (scimGroupConds.length > 0) {
      // Group condition — we can't resolve membership without a SCIM user lookup.
      // Mark as uncertain and move on.
      appliesToUser = null;
      uncertainPolicies.push({
        policyName: policy.name,
        action: policy.action,
        groups: scimGroupConds.map(function(c) { return c.groupName; }),
      });
    } else {
      // No user/group condition — applies to everyone
      appliesToUser = true;
    }

    if (appliesToUser === true) {
      if (policy.action === 'ALLOW' && !firstAllowing) firstAllowing = policy;
      if (policy.action === 'DENY'  && !firstDenying)  firstDenying  = policy;
      // In ZPA, first matching rule wins. So if this rule applies deterministically,
      // we can stop — but only if it's the highest-priority one we'd trust.
      // For now, collect all and let the UI explain.
    }
  }

  // Determine verdict — first-match-wins by rule order
  let canAccess = null;
  let verdictText = null;
  let decidingPolicy = null;

  if (firstAllowing && firstDenying) {
    const ao = parseInt(firstAllowing.ruleOrder, 10);
    const dO = parseInt(firstDenying.ruleOrder, 10);
    if (!isNaN(ao) && !isNaN(dO)) {
      if (ao < dO) { canAccess = true;  decidingPolicy = firstAllowing; verdictText = 'ALLOWED by higher-priority rule.'; }
      else         { canAccess = false; decidingPolicy = firstDenying;  verdictText = 'DENIED by higher-priority rule.'; }
    } else {
      canAccess = null; verdictText = 'Conflicting rules — inspect manually.';
    }
  } else if (firstAllowing) {
    canAccess = true;  decidingPolicy = firstAllowing; verdictText = 'Explicitly ALLOWED.';
  } else if (firstDenying) {
    canAccess = false; decidingPolicy = firstDenying;  verdictText = 'Explicitly DENIED.';
  } else if (uncertainPolicies.length > 0) {
    canAccess = null; verdictText = 'Depends on group membership — check Okta/SCIM for the groups listed below.';
  } else {
    canAccess = false; verdictText = 'No gating rule grants this user access.';
  }

  return {
    user: userEmail,
    canAccess: canAccess,
    verdictText: verdictText,
    decidingPolicy: decidingPolicy ? { name: decidingPolicy.name, action: decidingPolicy.action, ruleOrder: decidingPolicy.ruleOrder } : null,
    uncertainPolicies: uncertainPolicies,
  };
}

// ── Tenant info (for topbar badge) ──
// Returns IdP name + ZIA cloud. Cached 1 hour since IdP config rarely changes.
let tenantInfoCache = { data: null, expiresAt: 0 };
router.get('/zpa/tenant-info', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  try {
    if (tenantInfoCache.data && Date.now() < tenantInfoCache.expiresAt) {
      return res.json(Object.assign({}, tenantInfoCache.data, { fromCache: true }));
    }
    // Derive ZIA cloud from base URL (e.g. https://zsapi.zscalertwo.net/api/v1 → zscalertwo.net)
    let ziaCloud = null;
    try {
      const u = new URL(process.env.ZIA_BASE_URL || '');
      ziaCloud = u.hostname.replace(/^zsapi\./, '');
    } catch (e) { /* ignore */ }

    // Fetch primary IdP via v2 endpoint
    const token = await zpaAuth();
    const cid = process.env.ZPA_CUSTOMER_ID;
    const url = new URL('https://api.zsapi.net/zpa/mgmtconfig/v2/admin/customers/' + cid + '/idp?page=1&pageSize=5');
    const result = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
    let primaryIdp = null, idpCount = 0, scimEnabled = false;
    if (result.status === 200 && result.body && Array.isArray(result.body.list)) {
      const list = result.body.list;
      idpCount = list.length;
      const enabled = list.filter(function(i) { return i.enabled; });
      const primary = enabled.length > 0 ? enabled[0] : (list[0] || null);
      if (primary) {
        primaryIdp = primary.name;
        scimEnabled = !!primary.scimEnabled;
      }
    }
    const info = {
      primaryIdp: primaryIdp,
      idpCount: idpCount,
      scimEnabled: scimEnabled,
      ziaCloud: ziaCloud,
      zpaCloud: 'zscaler.com',   // all Zscaler tenants hit the same ZPA config endpoint
    };
    tenantInfoCache = { data: info, expiresAt: Date.now() + 60 * 60 * 1000 };
    return res.json(Object.assign({}, info, { fromCache: false }));
  } catch (err) {
    console.error('[zscaler-diag] tenant-info error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Cache-clear endpoint (for admins / debugging) ──
// ── ZIA Users (bulk list, cached) ──────────────────────────
// GET /api/zscaler/zia/users
// Returns minimal ZIA user records for client-side enrichment
// (e.g. ADMIN/PILOT/DELETED badges on live-presence.html).
//
// Rate limiting: ZIA /users is capped at ~1 req/sec. We pace
// pagination with a 1.2s sleep and honor Retry-After on 429.
// If a mid-fetch failure occurs AFTER we've collected some pages,
// we return partial results flagged { partial: true } and DO NOT
// cache them. Full successful fetches are cached for 10 minutes.
let ziaUsersCache = { data: null, expiresAt: 0 };
const ZIA_USERS_CACHE_MS = 10 * 60 * 1000;

router.get('/zia/users', rbac.requirePage('zscaler-diag','read'), async (req, res) => {
  const forceLive = req.query.live === '1';
  try {
    // 1. In-memory cache (10 min) — still honoured when not forcing live
    if (!forceLive && ziaUsersCache.data && Date.now() < ziaUsersCache.expiresAt) {
      return res.json(Object.assign({}, ziaUsersCache.data, { fromCache: true, synced_at: ziaUsersCache.data.queriedAt }));
    }
    // 2. DB cache
    if (!forceLive) {
      try {
        const pool = getZiaCachePool(router);
        const [rows] = await pool.query('SELECT payload, is_partial, synced_at FROM zia_users_cache ORDER BY id DESC LIMIT 1');
        if (rows.length && !rows[0].is_partial) {
          const data = JSON.parse(rows[0].payload);
          // Warm in-memory cache from DB so subsequent hits are instant
          ziaUsersCache = { data: data, expiresAt: Date.now() + ZIA_USERS_CACHE_MS };
          return res.json(Object.assign({}, data, { fromCache: true, synced_at: rows[0].synced_at }));
        }
      } catch (dbErr) { console.warn('[zscaler-diag] zia/users DB cache read failed:', dbErr.message); }
    }
    // 3. Live fetch

    const pageSize = 100;
    const MAX_PAGES = 50;              // safety cap: up to 5000 users
    const PAGE_DELAY_MS = 1200;        // pace to ~0.83 req/sec
    const MAX_429_RETRIES = 3;
    const sleep = function(ms) { return new Promise(function(r){ setTimeout(r, ms); }); };

    const allUsers = [];
    let page = 1;
    let partial = false;

    while (page <= MAX_PAGES) {
      // Fetch one page, retrying on 429
      let attempt = 0;
      let r = null;
      while (attempt <= MAX_429_RETRIES) {
        r = await ziaGet('users?page=' + page + '&pageSize=' + pageSize);
        if (r.status !== 429) break;

        let wait = 5000;
        const ra = r.headers && (r.headers['retry-after'] || r.headers['Retry-After']);
        if (ra) {
          const raSec = parseInt(ra, 10);
          if (raSec > 0 && raSec < 60) wait = raSec * 1000;
        } else {
          wait = 2000 + (attempt * 2000);   // 2s, 4s, 6s
        }
        console.warn('[zscaler-diag] zia/users 429 page ' + page + ', waiting ' + wait + 'ms (attempt ' + (attempt + 1) + ')');
        await sleep(wait);
        attempt++;
      }

      if (!r || r.status !== 200) {
        // If we've already collected data, return partial rather than fail hard
        if (allUsers.length) {
          console.warn('[zscaler-diag] zia/users partial result — HTTP ' + (r && r.status) + ' on page ' + page);
          partial = true;
          break;
        }
        return res.status(502).json({ error: 'ZIA /users HTTP ' + (r && r.status), page: page });
      }

      const chunk = Array.isArray(r.body) ? r.body : (r.body && r.body.list ? r.body.list : []);
      if (!chunk.length) break;
      for (let i = 0; i < chunk.length; i++) allUsers.push(chunk[i]);
      if (chunk.length < pageSize) break;   // last page
      page++;

      // Pace before next page
      if (page <= MAX_PAGES) await sleep(PAGE_DELAY_MS);
    }

    const users = allUsers.map(function(u) {
      return {
        id:                  u.id || null,
        name:                u.name || null,
        email:               u.email || null,
        department:          u.department ? u.department.name : null,
        adminUser:           !!u.adminUser,
        pilotUser:           !!u.pilotUser,
        deleted:             !!u.deleted,
        disabled:            !!u.disabled,
        pwdLastModifiedTime: u.pwdLastModifiedTime || null
      };
    });

    const payload = {
      success:   true,
      count:     users.length,
      users:     users,
      partial:   partial,
      queriedAt: new Date().toISOString()
    };

    // Only cache FULL fetches — a partial could mislead the UI for 10 minutes
    if (!partial) {
      ziaUsersCache = { data: payload, expiresAt: Date.now() + ZIA_USERS_CACHE_MS };
    }

    return res.json(Object.assign({}, payload, { fromCache: false }));

  } catch (err) {
    console.error('[zscaler-diag] zia/users error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});


// POST /api/zscaler/zpa/cache/clear
router.post('/zpa/cache/clear', rbac.requirePage('zscaler-diag','admin'), (req, res) => {
  zpaCache.applications    = { data: null, expiresAt: 0 };
  zpaCache.segmentGroups   = { data: null, expiresAt: 0 };
  zpaCache.accessPolicies  = { data: null, expiresAt: 0 };
  zpaCache.connectorGroups = { data: null, expiresAt: 0 };
  zpaCache.serverGroups    = { data: null, expiresAt: 0 };
  res.json({ ok: true, clearedAt: new Date().toISOString() });
});

// ═══════════════════════════════════════════════════════════════════════
// ENHANCED SERVICES (v2) — added 2026-07-29
// ZIA deep-policy, SaaS/CASB, ZDX, ZCC, ZINS, ZEASM.
// Reuses the shared OneAPI bearer token (ziaAuth() and zpaAuth() return the
// same token post-ZIdentity migration). Every route fails SOFT: any upstream
// or path issue returns JSON {error}, and the front-end renders a clean
// "not wired yet" card instead of breaking. Paths marked "verify" are
// best-guess and easy to correct once confirmed against the live tenant.
// ═══════════════════════════════════════════════════════════════════════
const requireRead = rbac.requirePage('zscaler-diag', 'read');
const requireAdmin = rbac.requirePage('zscaler-diag', 'admin');

// ── Live Status: presence summary (helpdesk landing page tile) ──
router.get('/presence-summary', requireRead, async (req, res) => {
  try {
    if (!router._presencePool) {
      const mysql = require('mysql2/promise');
      router._presencePool = mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || 'corpit_hub',
        connectionLimit: 3,
        waitForConnections: true
      });
    }
    const [rows] = await router._presencePool.query(
      "SELECT SUM(device_count) AS total, MAX(updated_at) AS updated_at FROM zdx_presence_geo WHERE geo_type='country'"
    );
    const total = rows[0] && rows[0].total != null ? Number(rows[0].total) : null;
    return res.json({ total: total, updated_at: rows[0] ? rows[0].updated_at : null });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── Live Status: connector health (OneAPI token check, 60s in-memory cache) ──
let _connHealthCache = { checkedAt: 0, ok: null };
router.get('/connector-health', requireRead, async (req, res) => {
  const now = Date.now();
  if (_connHealthCache.ok !== null && (now - _connHealthCache.checkedAt) < 60000) {
    return res.json({ ok: _connHealthCache.ok, cached: true, checkedAt: _connHealthCache.checkedAt });
  }
  try {
    await ziaAuth();
    _connHealthCache = { checkedAt: now, ok: true };
    return res.json({ ok: true, cached: false, checkedAt: now });
  } catch (e) {
    _connHealthCache = { checkedAt: now, ok: false };
    return res.json({ ok: false, cached: false, checkedAt: now, error: e.message });
  }
});
const ONEAPI_HOST = 'https://api.zsapi.net';

// Generic OneAPI GET against any service base path, using the shared token.
async function oneapiGet(pathAfterHost) {
  if (!ziaAuth) throw new Error('OneAPI auth not available');
  const token = await ziaAuth();
  const url = new URL(ONEAPI_HOST + pathAfterHost);
  let res = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token }, timeoutMs: ZLIST_TIMEOUT });
  if (res.status === 401 || res.status === 403) {
    const t2 = await ziaAuth(true);
    res = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + t2 }, timeoutMs: ZLIST_TIMEOUT });
  }
  return res;
}

// Normalize the many shapes upstreams return into a plain array.
function asList(body) {
  if (Array.isArray(body)) return body;
  if (body && Array.isArray(body.list)) return body.list;
  if (body && Array.isArray(body.devices)) return body.devices;
  if (body && Array.isArray(body.items)) return body.items;
  return [];
}

// ── ZIA: Cloud Firewall Rules ── (base = ZIA_BASE_URL; high confidence)
router.get('/zia/firewall-rules', requireRead, async (req, res) => {
  const forceLive = req.query.live === '1';
  try {
    const pool = getZiaCachePool(router);
    if (!forceLive) {
      const [rows] = await pool.query('SELECT payload, synced_at FROM zia_fw_rules_cache ORDER BY id DESC LIMIT 1');
      if (rows.length) {
        const data = JSON.parse(rows[0].payload);
        return res.json(Object.assign({}, data, { fromCache: true, synced_at: rows[0].synced_at }));
      }
    }
    // Live fetch (cache miss or ?live=1)
    const r = await ziaGet('firewallFilteringRules');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA firewallFilteringRules HTTP ' + r.status });
    const rules   = Array.isArray(r.body) ? r.body : [];
    const payload = { rules: rules, count: rules.length };
    // Refresh cache
    try {
      await pool.query('TRUNCATE TABLE zia_fw_rules_cache');
      await pool.query('INSERT INTO zia_fw_rules_cache (payload, synced_at) VALUES (?, NOW())', [JSON.stringify(payload)]);
    } catch (cacheErr) { console.warn('[zscaler-diag] fw-rules cache write failed:', cacheErr.message); }
    return res.json(Object.assign({}, payload, { fromCache: false, synced_at: new Date().toISOString() }));
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZIA: Cloud App Control / discovered cloud apps ──
// verify: cloudApplications/lite returns the cloud-app catalog ZIA recognises.
// Cloud App Control *rules* live under webApplicationRules/{ruleType}.
router.get('/zia/cloud-app-control', requireRead, async (req, res) => {
  try {
    const r = await ziaGet('cloudApplications/lite');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA cloudApplications/lite HTTP ' + r.status, hint: 'verify endpoint at help.zscaler.com/zia' });
    const apps = Array.isArray(r.body) ? r.body : [];
    return res.json({ apps: apps, count: apps.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZIA: Shadow IT (discovered SaaS) ──
// First pass reuses the cloud-app catalog. TODO: the full Shadow IT report is
// a POST with a time range — wire that when we want usage/volume numbers.
router.get('/zia/shadow-it', requireRead, async (req, res) => {
  try {
    const r = await ziaGet('cloudApplications/lite');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA cloudApplications/lite HTTP ' + r.status });
    const apps = Array.isArray(r.body) ? r.body : [];
    return res.json({ apps: apps, count: apps.length, note: 'catalog view — full Shadow IT report (POST w/ time range) TODO' });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── Device-list snapshots (CHG-PERF-ITEM2; approved G13/G14/G15, 2026-09-25) ──
// Only the UNFILTERED /zdx/devices and /zcc/devices lists are kept, in memory, one slot per route:
// ZDX presence for 2 min, ZCC enrollment for 15 min, counted from the start of the vendor fetch.
// Callers that arrive while that route's vendor fetch is running share it (one in-flight call).
// A list is kept only when every vendor page answered HTTP 200. Vendor errors (502), exceptions
// (500), error-cut partial lists and ZCC 404s reach the callers that shared that fetch exactly as
// before and are never kept. Filtered per-user lookups (ZDX emails= or q=, ZCC q=: identity-diag,
// signin-watch, the command-center search) always go to the vendor and never touch the slot.
const DEVLIST_MAX_AGE_MS = { zdx: 2 * 60 * 1000, zcc: 15 * 60 * 1000 };
const devListState = { zdx: { at: 0, out: null, inflight: null }, zcc: { at: 0, out: null, inflight: null } };
function devListShared(route, fetchList) {
  const s = devListState[route];
  const age = Date.now() - s.at;
  if (s.out && age >= 0 && age < DEVLIST_MAX_AGE_MS[route]) return Promise.resolve(s.out);
  if (s.inflight) return s.inflight;
  const startedAt = Date.now();
  s.inflight = fetchList().then(function (out) {
    s.inflight = null;
    if (out.clean) { s.out = out; s.at = startedAt; }
    return out;
  }, function (e) { s.inflight = null; throw e; });
  return s.inflight;
}

// ZDX device list for the last 2h. Returns { status, body, clean }; clean = every vendor page answered 200.
async function zdxDeviceList(emails, q) {
  const now = Math.floor(Date.now() / 1000);
  const from = now - 2 * 60 * 60;            // last 2h = ZDX "active" window
  let base = '/zdx/v1/devices?from=' + from + '&to=' + now;
  if (emails) base += '&emails=' + encodeURIComponent(emails);
  else if (q)  base += '&q=' + encodeURIComponent(q);
  const MAX_PAGES = 25;
  const all = [];
  let offset = null, page = 0, more = false;
  let truncated = false, truncReason = null, vendorErr = false;
  while (page < MAX_PAGES) {
    const r = await oneapiGet(base + (offset ? '&offset=' + encodeURIComponent(offset) : ''));
    if (r.status !== 200) {
      // A partial list still beats a hard failure, but (as ZCC does) say that it is partial (G16).
      if (all.length) {
        truncated = true; vendorErr = true;
        truncReason = 'ZDX /devices returned HTTP ' + r.status + ' on page ' + (page + 1) +
          ' - there are more devices than the ' + all.length + ' listed here';
        break;
      }
      return { status: 502, clean: false, body: { error: 'ZDX /devices HTTP ' + r.status, hint: 'confirm ZDX entitlement + /zdx/v1 base' } };
    }
    const chunk = asList(r.body);
    all.push.apply(all, chunk);
    offset = r.body && (r.body.next_offset || r.body.nextOffset) || null;
    page++;
    more = !!offset && chunk.length > 0;
    if (!more) break;
  }
  // Stopping at the page ceiling while ZDX still hands back a next_offset is a cut-off, not an end (G16).
  if (!truncated && more) {
    truncated = true;
    truncReason = 'reached the ' + MAX_PAGES + '-page ceiling (' + all.length +
      ' devices) - ZDX reported more beyond it';
  }
  return { status: 200, clean: !vendorErr,
           body: { devices: all, count: all.length, filtered: !!emails, window: { from: from, to: now }, pagesFetched: page,
                   truncated: truncated, truncatedReason: truncReason } };
}

// ── ZDX: Device health & presence ── (base /zdx/v1; paginated via next_offset)
router.get('/zdx/devices', requireRead, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    // ZDX /devices has NO free-text 'q' filter — passing one is silently ignored and
    // the FULL fleet comes back. 'emails' is the real per-user filter. Verified live
    // 2026-08-15: q=<user> -> 97 rows (whole fleet), emails=<user> -> 1 row.
    // Route an email-shaped q to emails so existing callers get the scoped answer.
    const emails = (req.query.emails || (q.indexOf('@') > -1 ? q : '')).trim();
    // Only the unfiltered list (no emails, no q) is shared and kept; every other call goes to ZDX.
    const out = (emails || q) ? await zdxDeviceList(emails, q)
                              : await devListShared('zdx', function () { return zdxDeviceList('', ''); });
    return res.status(out.status).json(out.body);
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZDX: Presence Map ── (reads cached zdx_presence_geo, populated by zdx-presence-sync.js)
router.get('/zdx/presence-map', requireRead, async (req, res) => {
  try {
    if (!router._presencePool) {
      const mysql = require('mysql2/promise');
      router._presencePool = mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || 'corpit_hub',
        connectionLimit: 3,
        waitForConnections: true
      });
    }
    const [rows] = await router._presencePool.query(
      'SELECT geo_id, geo_type, name, parent_geo_id, country_code, state_name, ' +
      'latitude, longitude, device_count, updated_at ' +
      'FROM zdx_presence_geo ORDER BY geo_type, device_count DESC'
    );
    const countries = rows.filter(r => r.geo_type === 'country');
    const states    = rows.filter(r => r.geo_type === 'state');
    const cities    = rows.filter(r => r.geo_type === 'city');
    const updatedAt = rows.length ? rows.reduce((m, r) => (r.updated_at > m ? r.updated_at : m), rows[0].updated_at) : null;
    return res.json({
      countries: countries,
      states:    states,
      cities:    cities,
      count: { countries: countries.length, states: states.length, cities: cities.length, total: rows.length },
      updated_at: updatedAt,
      note: 'device_count is placeholder (1 per city); accurate counts arrive with Phase 5 ISP crawl'
    });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZDX: Device Geo/ISP ── (reads cached zdx_device_geo; populated by zdx-isp-crawl.js nightly)
router.get('/zdx/device-geo', requireRead, async (req, res) => {
  try {
    if (!router._presencePool) {
      const mysql = require('mysql2/promise');
      router._presencePool = mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER, password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || 'corpit_hub',
        connectionLimit: 3
      });
    }
    const [rows] = await router._presencePool.query(
      "SELECT z.device_id, z.userid, z.device_name, z.first_public_ip, z.city, z.region, " +
      "z.country_code, z.isp, z.asn, z.crawl_status, z.crawled_at, " +
      "i.serial_number AS asset_serial, i.primary_user_upn AS asset_upn " +
      "FROM zdx_device_geo z " +
      "LEFT JOIN it_inventory.intune_devices i ON SUBSTRING_INDEX(z.device_name,'(',1) = i.device_name " +
      "WHERE z.crawl_status='ok'"
    );
    return res.json({ devices: rows, count: rows.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

router.get("/asset/by-user", requireRead, async (req, res) => {
  try {
    const upn = (req.query.upn || "").trim();
    if (!upn) return res.status(400).json({ error: "upn required" });
    if (!router._presencePool) {
      const mysql = require("mysql2/promise");
      router._presencePool = mysql.createPool({
        host: process.env.DB_HOST || "localhost",
        user: process.env.DB_USER, password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || "corpit_hub",
        connectionLimit: 3
      });
    }
    const [rows] = await router._presencePool.query(
      "SELECT device_name, serial_number, model, os, os_version, compliance, ownership, " +
      "device_category, last_checkin FROM it_inventory.intune_devices " +
      "WHERE LOWER(primary_user_upn)=LOWER(?) AND (is_historical IS NULL OR is_historical=0) " +
      "ORDER BY device_category, device_name",
      [upn]
    );
    return res.json({ upn: upn, devices: rows, count: rows.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZIA: Web DLP Rules ── (the actual DLP policy — actions, severities, engines per rule)
router.get('/zia/web-dlp-rules', requireRead, async (req, res) => {
  try {
    const r = await ziaGet('webDlpRules');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA webDlpRules HTTP ' + r.status });
    const rules = Array.isArray(r.body) ? r.body : [];
    return res.json({ rules: rules, count: rules.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZIA: DLP Engines ──
router.get('/zia/dlp-engines', requireRead, async (req, res) => {
  try {
    const r = await ziaGet('dlpEngines');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA dlpEngines HTTP ' + r.status });
    const engines = Array.isArray(r.body) ? r.body : [];
    return res.json({ engines: engines, count: engines.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// The OneAPI POST helper used to be declared TWICE in this file, here and again
// below, with the same name at the same scope. Function declarations hoist, so
// the later one silently overwrote this one and every call resolved to it --
// this copy had been unreachable since the day the second was added. It was not
// identical, either: it guarded `bodyObj || {}` and the live one did not, so
// reading this code told you about a safety net that was not actually in place.
// Removed. The `|| {}` guard has been moved onto the surviving definition, so
// nothing is lost by the deletion rather than merely nothing being lost given
// today's three callers.

// ── ZWA: DLP incidents (Workflow Automation) — SEPARATE API KEY ──
// Auth flow (from official zscaler-sdk-python zwa/legacy.py):
//   1. POST https://api.{cloud}.zsworkflow.net/v1/auth/api-key/token  {key_id, key_secret} → {token}
//   2. Bearer that token → POST {base}/zwa/dlp/v1/incidents/search
//      body: { fields: [], timeRange: { startTime: ISO, endTime: ISO } }
// Env: ZWA_KEY_ID, ZWA_KEY_SECRET, optional ZWA_CLOUD (default us2) / ZWA_BASE.
const ZWA_BASE = process.env.ZWA_BASE || ('https://api.' + (process.env.ZWA_CLOUD || 'us2') + '.zsworkflow.net');
let zwaTok = { token: null, expiresAt: 0 };
async function zwaToken(force) {
  if (!force && zwaTok.token && Date.now() < zwaTok.expiresAt) return zwaTok.token;
  const kid = process.env.ZWA_KEY_ID, sec = process.env.ZWA_KEY_SECRET;
  if (!kid || !sec) { const e = new Error('ZWA_KEY_ID / ZWA_KEY_SECRET not set in .env'); e.code = 'NOKEYS'; throw e; }
  const r = await httpsRequest(new URL(ZWA_BASE + '/v1/auth/api-key/token'),
    { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': 'itam-command-center/2.0', 'Accept': 'application/json' } },
    JSON.stringify({ key_id: kid, key_secret: sec }));
  const tok = r.body && r.body.token;
  if (r.status !== 200 || !tok) throw new Error('ZWA token HTTP ' + r.status + ': ' + (typeof r.body === 'string' ? r.body.slice(0, 150) : JSON.stringify(r.body || {}).slice(0, 150)));
  zwaTok = { token: tok, expiresAt: Date.now() + 25 * 60 * 1000 };
  return tok;
}
router.get('/zwa/incidents', requireRead, async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days, 10) || 7, 365);
    const et = new Date(), st = new Date(Date.now() - days * 86400000);
    let t;
    try { t = await zwaToken(); }
    catch (e) {
      if (e.code === 'NOKEYS') return res.status(501).json({ error: e.message, hint: 'Add ZWA_KEY_ID / ZWA_KEY_SECRET to /var/www/corpit-hub-api/.env and pm2 restart api-beta.' });
      return res.status(502).json({ error: e.message });
    }
    /* NOTE: direct key-auth host uses NO /zwa prefix — the /zwa/... form is the
       OneAPI-gateway path and CloudFront 403s it here (verified live 2026-07-29). */
    const doSearch = function (tok) {
      return httpsRequest(new URL(ZWA_BASE + '/dlp/v1/incidents/search'),
        { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', 'User-Agent': 'itam-command-center/2.0', 'Accept': 'application/json' } },
        JSON.stringify({ fields: [], timeRange: { startTime: st.toISOString(), endTime: et.toISOString() } }));
    };
    let r = await doSearch(t);
    if (r.status === 401) { t = await zwaToken(true); r = await doSearch(t); }
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA incidents/search HTTP ' + r.status, upstreamBody: typeof r.body === 'string' ? r.body.slice(0, 300) : r.body });
    let list = asList(r.body);
    const b = r.body || {};
    if (!list.length) { const keys = ['incidents', 'data', 'content', 'records']; for (let i = 0; i < keys.length; i++) { if (Array.isArray(b[keys[i]])) { list = b[keys[i]]; break; } } }
    return res.json({ incidents: list, count: list.length, window: { from: st.toISOString(), to: et.toISOString() }, raw: list.length ? undefined : b });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZWA: authenticated GET helper ──
async function zwaGet(path) {
  let t = await zwaToken();
  const mk = function (tok) {
    return httpsRequest(new URL(ZWA_BASE + path),
      { method: 'GET', headers: { Authorization: 'Bearer ' + tok, 'User-Agent': 'itam-command-center/2.0', 'Accept': 'application/json' } });
  };
  let r = await mk(t);
  if (r.status === 401) { t = await zwaToken(true); r = await mk(t); }
  return r;
}

// ── ZWA: full incident record — details + triggers + history + tickets + evidence ──
// (evidence returns a URL to the XML with the actual data that triggered the match)
router.get('/zwa/incident/:id/full', requireRead, async (req, res) => {
  try {
    const rawId = String(req.params.id || '').trim();
    if (!rawId) return res.status(400).json({ error: 'incident id required' });
    const id = encodeURIComponent(rawId);
    const paths = {
      details: '/dlp/v1/incidents/' + id,
      triggers: '/dlp/v1/incidents/' + id + '/triggers',
      history: '/dlp/v1/incidents/' + id + '/change-history',
      tickets: '/dlp/v1/incidents/' + id + '/tickets',
      evidence: '/dlp/v1/incidents/' + id + '/evidence'
    };
    const out = {};
    await Promise.all(Object.keys(paths).map(async function (k) {
      try {
        const r = await zwaGet(paths[k]);
        out[k] = { status: r.status, data: (typeof r.body === 'string' ? r.body.slice(0, 300) : r.body) };
      } catch (e) { out[k] = { status: 0, data: e.message }; }
    }));
    return res.json(out);
  } catch (e) {
    if (e.code === 'NOKEYS') return res.status(501).json({ error: e.message });
    return res.status(500).json({ error: e.message });
  }
});

// ── ZWA: audit log — activity inside Workflow Automation (works even with 0 incidents) ──
router.get('/zwa/audit', requireRead, async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days, 10) || 7, 365);
    const et = new Date(), st = new Date(Date.now() - days * 86400000);
    let t = await zwaToken();
    const mk = function (tok) {
      return httpsRequest(new URL(ZWA_BASE + '/dlp/v1/customer/audit'),
        { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', 'User-Agent': 'itam-command-center/2.0', 'Accept': 'application/json' } },
        JSON.stringify({ fields: [], timeRange: { startTime: st.toISOString(), endTime: et.toISOString() } }));
    };
    let r = await mk(t);
    if (r.status === 401) { t = await zwaToken(true); r = await mk(t); }
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA audit HTTP ' + r.status, upstreamBody: typeof r.body === 'string' ? r.body.slice(0, 300) : r.body });
    let list = asList(r.body);
    const b = r.body || {};
    if (!list.length) { const keys = ['logs', 'auditLogs', 'data', 'records', 'content']; for (let i = 0; i < keys.length; i++) { if (Array.isArray(b[keys[i]])) { list = b[keys[i]]; break; } } }
    return res.json({ logs: list, count: list.length, window: { from: st.toISOString(), to: et.toISOString() }, raw: list.length ? undefined : b });
  } catch (e) {
    if (e.code === 'NOKEYS') return res.status(501).json({ error: e.message });
    return res.status(500).json({ error: e.message });
  }
});

// ── ZCC: Device OTP bundle ── (on-demand, 15min cache; returns 7 OTPs per device)
router.get('/zcc/otp/:udid', requireAdmin, async (req, res) => {
  const udid = String(req.params.udid || '').trim();
  if (!udid) return res.status(400).json({ error: 'udid required' });
  // A device OTP unlocks/uninstalls the Zscaler client on that machine: admin only, every read audited.
  try { if (typeof rbac.audit === 'function') await rbac.audit(req, 'zcc_otp_view', null, 'zscaler-diag', { udid }); } catch (e) {}
  try {
    if (!router._presencePool) {
      const mysql = require('mysql2/promise');
      router._presencePool = mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER, password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || 'corpit_hub',
        connectionLimit: 3
      });
    }
    // Check cache (15 min TTL)
    const [cached] = await router._presencePool.query(
      "SELECT * FROM zcc_device_otp WHERE udid=? AND fetched_at > NOW() - INTERVAL 15 MINUTE",
      [udid]
    );
    if (cached.length) {
      return res.json({
        udid,
        cached: true, fetched_at: cached[0].fetched_at,
        logoutOtp: cached[0].logout_otp, uninstallOtp: cached[0].uninstall_otp,
        exitOtp: cached[0].exit_otp, ziaDisableOtp: cached[0].zia_disable_otp,
        zpaDisableOtp: cached[0].zpa_disable_otp, zdxDisableOtp: cached[0].zdx_disable_otp,
        zdpDisableOtp: cached[0].zdp_disable_otp
      });
    }
    // Fresh fetch from ZCC portal via OneAPI
    const r = await oneapiGet('/zcc/papi/public/v1/getOtp?udid=' + encodeURIComponent(udid));
    if (r.status === 429) return res.status(429).json({ error: 'ZCC portal rate-limited; try again in ~15 min' });
    if (r.status !== 200) return res.status(502).json({ error: 'ZCC getOtp HTTP ' + r.status });
    const o = r.body || {};
    await router._presencePool.query(
      "REPLACE INTO zcc_device_otp (udid,logout_otp,uninstall_otp,exit_otp,zia_disable_otp,zpa_disable_otp,zdx_disable_otp,zdp_disable_otp,fetched_at) VALUES (?,?,?,?,?,?,?,?,NOW())",
      [udid, o.logoutOtp||null, o.uninstallOtp||null, o.exitOtp||null, o.ziaDisableOtp||null, o.zpaDisableOtp||null, o.zdxDisableOtp||null, o.zdpDisableOtp||null]
    );
    return res.json({ udid, cached: false, ...o });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ZCC enrolled-device list. Returns { status, body, clean }; clean = every vendor page answered 200
// (a 404 still ends the list exactly as before, but such a list is never kept by the snapshot cache).
async function zccDeviceList(q) {
  const PAGE_SIZE = 500, MAX_PAGES = 30;      // up to 15k devices
  const all = [];
  let page = 1;
  let truncated = false, truncReason = null, clean = true;
  while (page <= MAX_PAGES) {
    let path = '/zcc/papi/public/v1/getDevices?page=' + page + '&pageSize=' + PAGE_SIZE;
    if (q) path += '&username=' + encodeURIComponent(q);
    const r = await oneapiGet(path);
    // ZCC answers 404 (not an empty 200) when the username owns no devices.
    // Treating that as an error made the caller's 'not enrolled' state unreachable.
    if (r.status === 404) { clean = false; break; }
    if (r.status !== 200) {
      // A partial fleet still beats a hard failure, but the caller has to be
      // able to tell the two apart. Without a marker a mid-pagination 429
      // renders as a confident, SMALLER fleet -- 500 of 743 devices reported
      // as though 500 were all of them.
      if (all.length) {
        truncated = true; clean = false;
        truncReason = 'ZCC getDevices returned HTTP ' + r.status + ' on page ' + page +
          ' - the fleet is larger than the ' + all.length + ' devices listed here';
        break;
      }
      return { status: 502, clean: false, body: { error: 'ZCC getDevices HTTP ' + r.status, hint: 'confirm ZCC entitlement + /zcc/papi/public/v1 base' } };
    }
    const chunk = asList(r.body);
    all.push.apply(all, chunk);
    if (chunk.length < PAGE_SIZE) break;      // last page
    page++;
  }
  // Hitting the page ceiling with a full last page is also a cut-off, not an end.
  if (!truncated && page > MAX_PAGES) {
    truncated = true;
    truncReason = 'reached the ' + MAX_PAGES + '-page ceiling (' + all.length +
      ' devices) - there may be more beyond it';
  }
  return { status: 200, clean: clean,
           body: { devices: all, count: all.length, pagesFetched: page,
                   truncated: truncated, truncatedReason: truncReason } };
}

// ── ZCC: Enrolled devices ── (base /zcc/papi/public/v1; paginated — fleets exceed one page)
router.get('/zcc/devices', requireRead, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    // Only the unfiltered fleet (no q) is shared and kept; a q= (per-user) lookup always goes to ZCC.
    const out = q ? await zccDeviceList(q)
                  : await devListShared('zcc', function () { return zccDeviceList(''); });
    return res.status(out.status).json(out.body);
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZEASM: External attack-surface findings ── (verify base path)
router.get('/easm/findings', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zeasm/v1/findings');
    if (r.status !== 200) return res.status(502).json({ error: 'ZEASM /findings HTTP ' + r.status, hint: 'confirm ZEASM entitlement + /zeasm base path' });
    const findings = asList(r.body);
    return res.json({ findings: findings, count: findings.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZDX: Application health scores ── (probe-verified 200)
router.get('/zdx/apps', requireRead, async (req, res) => {
  try {
    const now = Math.floor(Date.now() / 1000);
    const from = now - 2 * 60 * 60;
    const r = await oneapiGet('/zdx/v1/apps?from=' + from + '&to=' + now);
    if (r.status !== 200) return res.status(502).json({ error: 'ZDX /apps HTTP ' + r.status });
    const apps = asList(r.body);
    return res.json({ apps: apps, count: apps.length, window: { from: from, to: now } });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZDX: Departments ── (probe-verified 200)
router.get('/zdx/departments', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zdx/v1/administration/departments');
    if (r.status !== 200) return res.status(502).json({ error: 'ZDX /departments HTTP ' + r.status });
    const depts = asList(r.body);
    return res.json({ departments: depts, count: depts.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── OneAPI POST helper (ZINS GraphQL) ──
// The single OneAPI POST helper (a duplicate declaration above was removed).
async function oneapiPost(pathAfterHost, bodyObj) {
  if (!ziaAuth) throw new Error('OneAPI auth not available');
  const token = await ziaAuth();
  const url = new URL(ONEAPI_HOST + pathAfterHost);
  // `|| {}` matters: JSON.stringify(undefined) returns the VALUE undefined, not
  // a string, and httpsRequest's `if (body)` then writes no body at all -- so a
  // caller that omitted the argument would POST an empty request and get back a
  // vendor error about malformed input, pointing nowhere near the real cause.
  const payload = JSON.stringify(bodyObj || {});
  const H = (t) => ({ Authorization: 'Bearer ' + t, 'Content-Type': 'application/json' });
  let res = await httpsRequest(url, { method: 'POST', headers: H(token) }, payload);
  if (res.status === 401 || res.status === 403) {
    const t2 = await ziaAuth(true);
    res = await httpsRequest(url, { method: 'POST', headers: H(t2) }, payload);
  }
  return res;
}
function gqlBody(res) {
  let b = res.body;
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = null; } }
  return (b && b.data) || null;
}
// ── ZINS: Shadow IT apps (verified live: SHADOW_IT.apps GraphQL) ──
router.get('/zins/shadow-it', requireRead, async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days, 10) || 7, 90);
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
    const endTime = Date.now(), startTime = endTime - days * 86400000;
    const query = 'query ShadowITApps($startTime: Long!, $endTime: Long!, $limit: Int) { SHADOW_IT { apps(start_time: $startTime, end_time: $endTime) { entries(limit: $limit) { application application_category risk_index computed_risk_index sanctioned_state data_consumed data_uploaded data_downloaded authenticated_users last_access_time } } } }';
    const r = await oneapiPost('/zins/graphql', { query: query, variables: { startTime: startTime, endTime: endTime, limit: limit }, operationName: 'ShadowITApps' });
    if (r.status !== 200) return res.status(502).json({ error: 'ZINS graphql HTTP ' + r.status });
    const d = gqlBody(r);
    const list = (d && d.SHADOW_IT && d.SHADOW_IT.apps && Array.isArray(d.SHADOW_IT.apps.entries)) ? d.SHADOW_IT.apps.entries : [];
    return res.json({ days: days, apps: list, count: list.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ── ZINS: CASB SaaS app report (SAAS_SECURITY.casb_app GraphQL) ──
router.get('/zins/casb', requireRead, async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days, 10) || 7, 90);
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
    const endTime = Date.now(), startTime = endTime - days * 86400000;
    const query = 'query CasbAppReport($startTime: Long!, $endTime: Long!, $limit: Int) { SAAS_SECURITY { casb_app(start_time: $startTime, end_time: $endTime) { obfuscated entries(limit: $limit) { name total } } } }';
    const r = await oneapiPost('/zins/graphql', { query: query, variables: { startTime: startTime, endTime: endTime, limit: limit }, operationName: 'CasbAppReport' });
    if (r.status !== 200) return res.status(502).json({ error: 'ZINS graphql HTTP ' + r.status });
    const d = gqlBody(r);
    const node = (d && d.SAAS_SECURITY && d.SAAS_SECURITY.casb_app) || {};
    const list = Array.isArray(node.entries) ? node.entries : [];
    return res.json({ days: days, obfuscated: node.obfuscated === true, apps: list, count: list.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ── ZINS: overview rollup (top shadow-IT apps by data consumed) ──
router.get('/zins/summary', requireRead, async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days, 10) || 7, 90);
    const endTime = Date.now(), startTime = endTime - days * 86400000;
    const query = 'query ShadowITApps($startTime: Long!, $endTime: Long!, $limit: Int) { SHADOW_IT { apps(start_time: $startTime, end_time: $endTime) { entries(limit: $limit) { application risk_index sanctioned_state data_consumed } } } }';
    const r = await oneapiPost('/zins/graphql', { query: query, variables: { startTime: startTime, endTime: endTime, limit: 200 }, operationName: 'ShadowITApps' });
    if (r.status !== 200) return res.status(502).json({ error: 'ZINS graphql HTTP ' + r.status });
    const d = gqlBody(r);
    const list = (d && d.SHADOW_IT && d.SHADOW_IT.apps && Array.isArray(d.SHADOW_IT.apps.entries)) ? d.SHADOW_IT.apps.entries : [];
    const top = list.slice().sort((a, b) => (b.data_consumed || 0) - (a.data_consumed || 0)).slice(0, 5);
    const highRisk = list.filter((a) => (a.computed_risk_index || a.risk_index || 0) >= 4).length;
    return res.json({ days: days, totalApps: list.length, highRiskApps: highRisk, topByData: top });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ── ZID: ZIdentity users (verified live: /ziam/admin/api/v1/users) ──
router.get('/zid/users', requireRead, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const offset = parseInt(req.query.offset, 10) || 0;
    const r = await oneapiGet('/ziam/admin/api/v1/users?pagesize=' + limit + '&pageoffset=' + offset);
    if (r.status !== 200) return res.status(502).json({ error: 'ZID /users HTTP ' + r.status });
    let b = r.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
    let users = Array.isArray(b.records) ? b.records : [];
    const q = String(req.query.q || '').trim().toLowerCase();
    if (q) users = users.filter((u) => JSON.stringify([u.loginName, u.displayName, u.primaryEmail]).toLowerCase().includes(q));
    return res.json({ total: b.totalRecord || users.length, pageOffset: b.pageOffset || 0, pageSize: b.pageSize || limit, users: users });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ── ZID: ZIdentity groups ──
router.get('/zid/groups', requireRead, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const offset = parseInt(req.query.offset, 10) || 0;
    const r = await oneapiGet('/ziam/admin/api/v1/groups?pagesize=' + limit + '&pageoffset=' + offset);
    if (r.status !== 200) return res.status(502).json({ error: 'ZID /groups HTTP ' + r.status });
    let b = r.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
    let groups = Array.isArray(b.records) ? b.records : [];
    const q = String(req.query.q || '').trim().toLowerCase();
    if (q) groups = groups.filter((g) => JSON.stringify([g.name, g.displayName, g.description]).toLowerCase().includes(q));
    return res.json({ total: b.totalRecord || groups.length, pageOffset: b.pageOffset || 0, pageSize: b.pageSize || limit, groups: groups });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ── ZIA cache DB pool (lazy) ──────────────────────────────────────────────
function getZiaCachePool(router) {
  if (!router._ziaCachePool) {
    const mysql = require('mysql2/promise');
    router._ziaCachePool = mysql.createPool({
      host:             process.env.DB_HOST || 'localhost',
      user:             process.env.DB_USER,
      password:         process.env.DB_PASSWORD,
      database:         process.env.DB_NAME || 'corpit_hub',
      connectionLimit:  3,
      waitForConnections: true
    });
  }
  return router._ziaCachePool;
}

module.exports = router;

// ═══════════════════════════════════════════════════════════════
// CC-CONNECTOR-MONITOR routes v2.6.1 — appended for Command Center
// App Connector health monitor + "apps served" mapping.
// v2.6.1: /connector needs a ZPA role grant this API client lacks
// (403 access.denied). Fallback: appConnectorGroup embeds each
// group's connectors with health data nested in assistantVersion —
// flatten that instead. If the grant is later added in ZIdentity,
// the primary path takes over automatically.
// Uses existing module-scope helpers: zpaGet(), requireRead, router.
// ═══════════════════════════════════════════════════════════════

// Paginate any ZPA list endpoint. ZPA hard-caps pageSize at 20 and
// reports totalPages authoritatively (same pattern as zpaFetchCached).
async function ccZpaListAll(path) {
  var all = [];
  var page = 1, totalPages = 1;
  var joiner = path.indexOf('?') >= 0 ? '&' : '?';
  while (page <= 100) {
    var r = await zpaGet(path + joiner + 'page=' + page + '&pageSize=20');
    if (r.status !== 200) {
      var err = new Error('ZPA ' + path.split('?')[0] + ' HTTP ' + r.status);
      err.zpaStatus = r.status;
      throw err;
    }
    var b = r.body || {};
    var list = Array.isArray(b.list) ? b.list : (Array.isArray(b) ? b : []);
    all.push.apply(all, list);
    if (b.totalPages !== undefined) {
      var tp = parseInt(b.totalPages, 10);
      if (!isNaN(tp)) totalPages = tp;
    }
    if (!list.length || page >= totalPages) break;
    page++;
  }
  return all;
}

// Normalize ZPA timestamps to epoch-milliseconds. ZPA mixes units:
// seconds (10 digits), ms (13), and microseconds (16, e.g.
// lastBrokerConnectTime "1784527226041503").
function ccZpaMs(v) {
  if (v === null || v === undefined || v === '') return null;
  var n = typeof v === 'number' ? v : parseInt(String(v), 10);
  if (isNaN(n) || n <= 0) return null;
  if (n >= 1e14) return Math.floor(n / 1000);  // microseconds → ms
  if (n >= 1e11) return n;                     // already ms
  return n * 1000;                             // seconds → ms
}

// Flatten one embedded group connector: hoist assistantVersion fields
// (expectedVersion/currentVersion/lastBroker*/applicationStartTime/
// platform/privateIp/publicIp if present) up to the top level without
// clobbering top-level values, then normalize broker timestamps and
// derive a synthetic ctrlChannelStatus from connect vs disconnect.
function ccFlattenGroupConnector(c, groupName) {
  var out = {};
  Object.keys(c).forEach(function (k) { if (k !== 'assistantVersion') out[k] = c[k]; });
  var av = c.assistantVersion || {};
  Object.keys(av).forEach(function (k) {
    if (out[k] === undefined || out[k] === null || out[k] === '') out[k] = av[k];
  });
  out.appConnectorGroupName = out.appConnectorGroupName || groupName;
  var conn = ccZpaMs(out.lastBrokerConnectTime);
  var disc = ccZpaMs(out.lastBrokerDisconnectTime);
  if (conn) out.lastBrokerConnectTime = conn;
  if (disc) out.lastBrokerDisconnectTime = disc;
  if (!out.ctrlChannelStatus && !out.controlChannelStatus) {
    var isConn = !!conn && (!disc || conn > disc);
    out.ctrlChannelStatus = out.enabled && isConn ? 'ZPN_STATUS_AUTHENTICATED' : 'ZPN_STATUS_DISCONNECTED';
    out.statusDerived = 'from broker connect/disconnect times (group-embedded data; /connector grant missing)';
  }
  return out;
}

function ccConnSummary(conns) {
  var up = 0, down = 0, disabled = 0, drift = 0;
  var groups = {};
  conns.forEach(function (c) {
    var st = String(c.ctrlChannelStatus || c.controlChannelStatus || '');
    var isUp = c.enabled && /AUTHENTICATED/i.test(st);
    if (!c.enabled) disabled++;
    else if (isUp) up++;
    else down++;
    if (c.expectedVersion && c.currentVersion && c.expectedVersion !== c.currentVersion) drift++;
    groups[c.appConnectorGroupName || 'Ungrouped'] = true;
  });
  return { total: conns.length, up: up, down: down, disabled: disabled, drift: drift, groups: Object.keys(groups).length };
}

// GET /api/zscaler/zpa/connectors — every App Connector with health status
router.get('/zpa/connectors', requireRead, async (req, res) => {
  try {
    var conns, source = 'connector';
    try {
      conns = await ccZpaListAll('connector');
      conns = conns.map(function (c) {
        var m = ccZpaMs(c.lastBrokerConnectTime); if (m) c.lastBrokerConnectTime = m;
        var d = ccZpaMs(c.lastBrokerDisconnectTime); if (d) c.lastBrokerDisconnectTime = d;
        return c;
      });
    } catch (e) {
      // This API client has no /connector grant, so 403 is the steady state
      // and appConnectorGroup is in practice the primary source. Gating the
      // fallback on 403/401 meant any OTHER primary failure -- a connect-stage
      // stall surfaces here as "Request timed out" -- became a hard 500 on a
      // page whose data was sitting one fast call away. Fall back on any
      // primary failure and record in `source` which kind it was. If the
      // second read fails too the error still propagates and the page says so.
      var denied = (e.zpaStatus === 403 || e.zpaStatus === 401);
      source = denied
        ? 'appConnectorGroup (fallback — /connector grant missing)'
        : 'appConnectorGroup (fallback — /connector read failed: ' + e.message + ')';
      var groups = await ccZpaListAll('appConnectorGroup');
      conns = [];
      groups.forEach(function (g) {
        (g.connectors || []).forEach(function (c) {
          conns.push(ccFlattenGroupConnector(c, g.name));
        });
      });
    }
    return res.json({ connectors: conns, count: conns.length, source: source, summary: ccConnSummary(conns) });
  } catch (e) {
    console.error('[zscaler-diag] zpa/connectors error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// GET /api/zscaler/zpa/connector-apps — which app segments ride each
// connector group (via server groups). This is the "what's in use" map:
// the public ZPA API does not expose per-connector live throughput, so
// we show what each group serves instead.
router.get('/zpa/connector-apps', requireRead, async (req, res) => {
  try {
    var sgs = await ccZpaListAll('serverGroup');
    var byGroup = {}; // connectorGroupId -> {id,name,apps:{},serverGroups:[]}
    sgs.forEach(function (sg) {
      var apps = (sg.applications || []).map(function (a) { return a.name || String(a.id || ''); }).filter(Boolean);
      (sg.appConnectorGroups || []).forEach(function (cg) {
        var key = String(cg.id || cg.name || '?');
        if (!byGroup[key]) byGroup[key] = { id: cg.id || null, name: cg.name || key, apps: {}, serverGroups: [] };
        byGroup[key].serverGroups.push(sg.name || String(sg.id || ''));
        apps.forEach(function (a) { byGroup[key].apps[a] = true; });
      });
    });
    var out = Object.keys(byGroup).map(function (k) {
      var g = byGroup[k];
      return { id: g.id, name: g.name, apps: Object.keys(g.apps).sort(), serverGroups: g.serverGroups };
    });
    return res.json({ groups: out, count: out.length });
  } catch (e) {
    console.error('[zscaler-diag] zpa/connector-apps error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});
// ═══ end CC-CONNECTOR-MONITOR v2.6.1 ═══

// ═══════════════════════════════════════════════════════════════
// CC-ROUTES-TRAFFIC v2.7 — appended for Command Center
// (1) /zpa/topology     — app → server group → connector group →
//     connector path map with health + risk scoring (config-side).
// (2) /zpa/traffic/*    — bandwidth/apps/users from the local LSS
//     receiver database (lss-receiver.js, pm2 app "lss-receiver").
//     Lazy-loads better-sqlite3: if not installed or no data yet,
//     /traffic/status says so instead of crashing api-beta.
// Reuses module-scope helpers from earlier appends: zpaGet(),
// requireRead, router, ccZpaListAll(), ccFlattenGroupConnector(),
// ccConnSummary(), zpaFetchCached().
// ═══════════════════════════════════════════════════════════════

async function ccGetAllConnectors() {
  try {
    var conns = await ccZpaListAll('connector');
    return conns;
  } catch (e) {
    // Same reasoning as /zpa/connectors above: fall back on any primary
    // failure, not only on the missing grant. A failure of the fallback
    // itself still throws to the caller.
    var groups = await ccZpaListAll('appConnectorGroup');
    var out = [];
    groups.forEach(function (g) {
      (g.connectors || []).forEach(function (c) { out.push(ccFlattenGroupConnector(c, g.name)); });
    });
    return out;
  }
}
function ccUp(c) { return !!c.enabled && /AUTHENTICATED/i.test(String(c.ctrlChannelStatus || c.controlChannelStatus || '')); }

// GET /api/zscaler/zpa/topology — full path map + risk
router.get('/zpa/topology', requireRead, async (req, res) => {
  try {
    var results = await Promise.all([
      ccZpaListAll('serverGroup'),
      ccGetAllConnectors(),
      zpaFetchCached('applications', 'application')
    ]);
    var sgs = results[0], conns = results[1], appsFull = results[2].data || [];

    // connector group name -> connectors
    var cgConns = {};
    conns.forEach(function (c) {
      var g = c.appConnectorGroupName || 'Ungrouped';
      if (!cgConns[g]) cgConns[g] = [];
      cgConns[g].push({ name: c.name, up: ccUp(c), enabled: !!c.enabled });
    });

    // app id -> {serverGroups, connectorGroups}
    var appPaths = {};
    sgs.forEach(function (sg) {
      var cgs = (sg.appConnectorGroups || []).map(function (cg) { return cg.name || String(cg.id || '?'); });
      (sg.applications || []).forEach(function (a) {
        var id = String(a.id || a.name);
        if (!appPaths[id]) appPaths[id] = { name: a.name || id, serverGroups: {}, connectorGroups: {} };
        appPaths[id].serverGroups[sg.name || String(sg.id)] = true;
        cgs.forEach(function (g) { appPaths[id].connectorGroups[g] = true; });
      });
    });

    // enrich from full app segment list (domains, enabled) + risk score
    var appMeta = {};
    appsFull.forEach(function (a) { appMeta[String(a.id)] = a; });
    var apps = Object.keys(appPaths).map(function (id) {
      var p = appPaths[id];
      var meta = appMeta[id] || {};
      var cgList = Object.keys(p.connectorGroups).sort();
      var upConns = 0, totConns = 0, upGroups = 0;
      var cgDetail = cgList.map(function (g) {
        var list = cgConns[g] || [];
        var up = list.filter(function (x) { return x.up; }).length;
        upConns += up; totConns += list.length;
        if (up > 0) upGroups++;
        return { name: g, up: up, total: list.length };
      });
      var risk = 'ok';
      if (upConns === 0) risk = 'no-path';
      else if (upConns === 1) risk = 'single-connector';
      else if (upGroups === 1) risk = 'single-group';
      return {
        id: id, name: p.name,
        enabled: meta.enabled !== undefined ? !!meta.enabled : true,
        domains: (meta.domainNames || []).slice(0, 8),
        serverGroups: Object.keys(p.serverGroups).sort(),
        connectorGroups: cgDetail,
        upConnectors: upConns, totalConnectors: totConns,
        risk: risk
      };
    }).sort(function (a, b) {
      var rank = { 'no-path': 0, 'single-connector': 1, 'single-group': 2, 'ok': 3 };
      return (rank[a.risk] - rank[b.risk]) || String(a.name).localeCompare(String(b.name));
    });

    // blast radius: per connector group, apps that lose ALL paths if it dies
    var blast = Object.keys(cgConns).sort().map(function (g) {
      var lost = apps.filter(function (a) {
        var upHere = a.connectorGroups.some(function (x) { return x.name === g && x.up > 0; });
        var upElsewhere = a.connectorGroups.some(function (x) { return x.name !== g && x.up > 0; });
        return upHere && !upElsewhere;
      }).map(function (a) { return a.name; });
      var list = cgConns[g];
      return { group: g, up: list.filter(function (x) { return x.up; }).length, total: list.length, appsLostIfDown: lost };
    });

    var atRisk = apps.filter(function (a) { return a.risk !== 'ok'; }).length;
    var noPath = apps.filter(function (a) { return a.risk === 'no-path'; }).length;
    return res.json({
      apps: apps, blast: blast,
      summary: { apps: apps.length, atRisk: atRisk, noPath: noPath, connectors: conns.length, connectorsUp: conns.filter(ccUp).length, groups: Object.keys(cgConns).length }
    });
  } catch (e) {
    console.error('[zscaler-diag] zpa/topology error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// ── LSS traffic (local receiver DB) ──
// Every lss.db read below runs in a worker thread (sqlite-offload); this module
// holds no SQLite connection of its own. Windows are 1/8/24h. The 7-day option
// the page still offers is refused with the reason: a week is ~10M session
// records and every cut of it measured 20s to 2.5min (2026-09-23), far past
// the page's 20s budget. An hourly rollup kept by the receiver is the fix.
var LSS_DB_PATH = process.env.LSS_DB || '/var/www/corpit-hub-api/data/lss.db';
var LSS_MAX_HOURS = 24;
function dbMissing(dbPath, reason) { return require('fs').existsSync(dbPath) ? null : reason; }
function lssMissing() { return dbMissing(LSS_DB_PATH, 'LSS database not found at ' + LSS_DB_PATH + ' — receiver not running or no data yet'); }
function lssWindowRefused(hours, what) {
  return 'The ' + hours + 'h ' + what + ' is not available on this host: it would scan every session record for the week ' +
         '(about 10 million rows, several minutes). Choose 24h or shorter.';
}
// A failed worker run is already { status, error }; nothing else is ever sent.
function offloadFail(res, r) { return res.status(r.status || 500).json({ error: r.error }); }
// Express 4 drops a rejected async handler on the floor and the request hangs;
// this answers it instead. The worker never rejects, so this only ever catches
// a bug in the response-shaping code.
function guarded(fn) {
  return function (req, res) {
    Promise.resolve(fn(req, res)).catch(function (e) { if (!res.headersSent) res.status(500).json({ error: e.message }); });
  };
}

// GET /api/zscaler/zpa/traffic/status
// Both reads run in a worker thread (sqlite-offload) and are cached 30s.
// COUNT(*) walks the smallest index of conns — 15.6M entries, measured 33.6s on
// the main thread on 2026-09-23. nginx's auth gate gives up at 2s, so every
// Command Center load was bouncing every visitor on every vhost to sign-in.
// conns is a rowid table the receiver only appends to and the retention job
// trims from the oldest end, so MAX(rowid)-MIN(rowid)+1 is the record count to
// within the rows a retention pass is deleting at that instant. The connector
// count is a loose index scan (recursive CTE stepping MIN(connector) > last):
// a handful of index seeks instead of a 20s walk of ix_conns_conn.
var LSS_DISTINCT_CONNECTORS =
  'WITH RECURSIVE d(c) AS (SELECT MIN(connector) FROM conns UNION ALL ' +
  'SELECT (SELECT MIN(connector) FROM conns WHERE connector > d.c) FROM d WHERE d.c IS NOT NULL) ' +
  'SELECT COUNT(*) v FROM d WHERE c IS NOT NULL';
router.get('/zpa/traffic/status', requireRead, async function (req, res) {
  var r = await offload.query(LSS_DB_PATH, [
    { sql: 'SELECT MIN(rowid) v FROM conns', mode: 'get' },
    { sql: 'SELECT MAX(rowid) v FROM conns', mode: 'get' },
    { sql: 'SELECT MIN(ts) v FROM conns', mode: 'get' },
    { sql: 'SELECT MAX(ts) v FROM conns', mode: 'get' },
    { sql: LSS_DISTINCT_CONNECTORS, mode: 'get' }
  ], { cacheKey: 'lss:status', cacheTtlMs: 30000, timeoutMs: 15000, label: 'LSS status' });
  if (!r.ok) return res.json({ streaming: false, reason: r.error });
  var v = r.results.map(function (x) { return x ? x.v : null; });
  var records = v[1] ? (v[1] - (v[0] || 1) + 1) : 0;
  return res.json({ streaming: records > 0, records: records, firstTs: v[2], lastTs: v[3], connectors: v[4] || 0, db: LSS_DB_PATH });
});

// GET /api/zscaler/zpa/traffic/summary?hours=1|8|24
// Five aggregates over the window, run on one connection in one worker thread
// (sqlite-offload), cached 60s per window. Every statement names ix_conns_ts:
// left to itself the planner pairs GROUP BY connector/app/user with the index
// on that column and walks all 15.6M entries to skip a sort — 46s for a
// ONE-hour window versus 64ms through the ts index (measured 2026-09-23).
// Cold cost after the fix: 1h ≈ 0.3s, 8h ≈ 4s, 24h ≈ 9s. A 7-day window would
// scan ~9.8M records (≈2.5 min, far past the page's 20s budget), so it is
// refused with the reason rather than started; an hourly rollup maintained by
// the receiver is the fix for that window.
var SUMMARY_TOP = 25;
function summaryStmts(hours) {
  var since = Date.now() - hours * 3600000;
  var bucketMs = hours <= 26 ? 3600000 : 6 * 3600000;
  var agg = 'COUNT(*) sessions, SUM(bytes_rx) rx, SUM(bytes_tx) tx';
  var src = ' FROM conns INDEXED BY ix_conns_ts WHERE ts >= ?';
  var byVolume = ' ORDER BY (SUM(bytes_rx) + SUM(bytes_tx)) DESC';
  return { bucketMs: bucketMs, stmts: [
    { sql: 'SELECT connector, ' + agg + ', COUNT(DISTINCT user) users' + src + ' GROUP BY connector' + byVolume, params: [since] },
    { sql: 'SELECT app, ' + agg + ', COUNT(DISTINCT user) users' + src + ' GROUP BY app' + byVolume + ' LIMIT ' + SUMMARY_TOP, params: [since] },
    { sql: 'SELECT user, ' + agg + ', COUNT(DISTINCT app) apps' + src + ' GROUP BY user' + byVolume + ' LIMIT ' + SUMMARY_TOP, params: [since] },
    { sql: 'SELECT (ts / ' + bucketMs + ') b, ' + agg + src + ' GROUP BY b ORDER BY b', params: [since] },
    { sql: 'SELECT ' + agg + ', COUNT(DISTINCT user) users, COUNT(DISTINCT app) apps' + src, params: [since], mode: 'get' }
  ] };
}
router.get('/zpa/traffic/summary', requireRead, async function (req, res) {
  var hours = t2Hours(req);
  if (hours > LSS_MAX_HOURS) return res.status(400).json({ error: lssWindowRefused(hours, 'traffic summary') });
  var q = summaryStmts(hours);
  var r = await offload.query(LSS_DB_PATH, q.stmts, { cacheKey: 'lss:summary:' + hours, cacheTtlMs: 60000, timeoutMs: 60000, label: 'ZPA traffic summary (' + hours + 'h)' });
  if (!r.ok) return res.status(r.status || 500).json({ error: r.error });
  var t = r.results;
  return res.json({
    hours: hours, totals: t[4], byConnector: t[0], byApp: t[1], byUser: t[2],
    timeline: t[3].map(function (x) { return { t: x.b * q.bucketMs, sessions: x.sessions, rx: x.rx || 0, tx: x.tx || 0 }; }),
    bucketMs: q.bucketMs, tookMs: r.tookMs, cachedAt: r.cachedAt || null
  });
});
// ═══ end CC-ROUTES-TRAFFIC v2.7 ═══

// CC-CONNECTOR-DETAIL v2.9 — per-connector bandwidth + apps + users (from lss.db)
// GET /api/zscaler/zpa/connector/detail?connector=<name>&hours=<1|8|24>
// Four aggregates on one worker connection, cached 60s per connector+window.
// Each reads through ix_conns_conn (connector = ? AND ts >= ?): 0.6-0.9s at
// 24h; at 168h each one measured 22-31s, so the week is refused like the summary.
router.get('/zpa/connector/detail', requireRead, guarded(async function (req, res) {
  var connector = String(req.query.connector || '').trim();
  if (!connector) return res.status(400).json({ error: 'connector query param required' });
  var hours = t2Hours(req);
  if (hours > LSS_MAX_HOURS) return res.status(400).json({ error: lssWindowRefused(hours, 'connector detail') });
  var missing = lssMissing(); if (missing) return res.status(503).json({ error: missing });
  var since = Date.now() - hours * 3600000;
  var bucketMs = 3600000;   // hourly; the 6h bucket only ever applied to the refused 7-day window
  var src = ' FROM conns INDEXED BY ix_conns_conn WHERE connector = ? AND ts >= ?';
  var byVolume = ' ORDER BY (SUM(bytes_rx) + SUM(bytes_tx)) DESC LIMIT 50';
  var r = await offload.query(LSS_DB_PATH, [
    { sql: 'SELECT COUNT(*) sessions, SUM(bytes_rx) rx, SUM(bytes_tx) tx, COUNT(DISTINCT user) users, COUNT(DISTINCT app) apps, MAX(ts) lastTs' + src, params: [connector, since], mode: 'get' },
    { sql: 'SELECT app, COUNT(*) sessions, SUM(bytes_rx) rx, SUM(bytes_tx) tx, COUNT(DISTINCT user) users, MAX(ts) lastTs' + src + ' GROUP BY app' + byVolume, params: [connector, since] },
    { sql: 'SELECT user, COUNT(*) sessions, SUM(bytes_rx) rx, SUM(bytes_tx) tx, COUNT(DISTINCT app) apps, MAX(ts) lastTs' + src + ' GROUP BY user' + byVolume, params: [connector, since] },
    { sql: 'SELECT (ts / ' + bucketMs + ') b, COUNT(*) sessions, SUM(bytes_rx) rx, SUM(bytes_tx) tx' + src + ' GROUP BY b ORDER BY b', params: [connector, since] }
  ], { cacheKey: 'lss:cdetail:' + hours + ':' + connector, cacheTtlMs: 60000, timeoutMs: 60000, label: 'Connector detail (' + hours + 'h)' });
  if (!r.ok) return offloadFail(res, r);
  var t = r.results;
  return res.json({
    connector: connector, hours: hours, bucketMs: bucketMs,
    totals: t[0] || { sessions: 0, rx: 0, tx: 0, users: 0, apps: 0, lastTs: null },
    byApp: t[1], byUser: t[2],
    timeline: t[3].map(function (x) { return { t: x.b * bucketMs, sessions: x.sessions, rx: x.rx || 0, tx: x.tx || 0 }; }),
    tookMs: r.tookMs, cachedAt: r.cachedAt || null
  });
}));
// ═══ end CC-CONNECTOR-DETAIL v2.9 ═══

// CC-ROUTES-TRAFFIC2 v3.0 — extra LSS cuts + connector-health reader
// Every statement names ix_conns_ts: without sqlite_stat1 the planner pairs a
// GROUP BY column with the index on that column and walks all 15.6M entries
// (fan-out at 1h: 59s unforced vs 56ms through the ts index, 2026-09-23).
// Cold cost at 24h: backends 4.7s, clients 2.4s, sessions 2.8s, latency 6.5s.
function t2Hours(req){ var a=[1,8,24,168]; var h=parseInt(req.query.hours,10)||24; return a.indexOf(h)===-1?24:h; }
function t2Opts(route, hours) {
  return { cacheKey: 'lss:' + route + ':' + hours, cacheTtlMs: 60000, timeoutMs: 60000, label: 'ZPA ' + route + ' (' + hours + 'h)' };
}
// Answers the request when the window is refused or the file is missing and
// returns 0; otherwise the window in hours.
function t2Window(req, res, what) {
  var hours = t2Hours(req);
  if (hours > LSS_MAX_HOURS) { res.status(400).json({ error: lssWindowRefused(hours, what) }); return 0; }
  var missing = lssMissing(); if (missing) { res.status(503).json({ error: missing }); return 0; }
  return hours;
}

// GET /zpa/traffic/latency?hours= — connection setup_ms percentiles per connector + per app
// Percentiles come out of SQL window functions, so the worker hands back 50
// rows instead of the 1.6M setup_ms values a 24h window holds (the previous
// version copied every row into JS and sorted there: 6s of transfer alone).
// p50/p95 pick the value at floor(q*(n-1)) of the sorted run, exactly as the JS
// did. The two cuts are separate workers because each is a full pass over the
// window; in parallel a cold 24h answers in ~6.5s instead of ~13s.
function latencySql(col) {
  return 'WITH r AS (SELECT ' + col + ' k, setup_ms v, ROW_NUMBER() OVER (PARTITION BY ' + col + ' ORDER BY setup_ms) rn, ' +
    'COUNT(*) OVER (PARTITION BY ' + col + ') n, SUM(setup_ms) OVER (PARTITION BY ' + col + ') sm ' +
    'FROM conns INDEXED BY ix_conns_ts WHERE ts >= ? AND setup_ms > 0 AND ' + col + ' IS NOT NULL AND ' + col + " != '') " +
    'SELECT k AS "key", n, MAX(CASE WHEN rn = 1 + CAST(0.5 * (n - 1) AS INTEGER) THEN v END) p50, ' +
    'MAX(CASE WHEN rn = 1 + CAST(0.95 * (n - 1) AS INTEGER) THEN v END) p95, MAX(v) max, ' +
    'CAST(ROUND(sm * 1.0 / n) AS INTEGER) avg FROM r GROUP BY k ORDER BY p95 DESC LIMIT 50';
}
router.get('/zpa/traffic/latency', requireRead, guarded(async function (req, res) {
  var hours = t2Window(req, res, 'latency cut'); if (!hours) return;
  var since = Date.now() - hours * 3600000;
  var both = await Promise.all(['connector', 'app'].map(function (col) {
    return offload.query(LSS_DB_PATH, [{ sql: latencySql(col), params: [since] }], t2Opts('latency-' + col, hours));
  }));
  var failed = both.filter(function (r) { return !r.ok; })[0];
  if (failed) return offloadFail(res, failed);
  return res.json({ hours: hours, byConnector: both[0].results[0], byApp: both[1].results[0], unit: 'ms',
    tookMs: both[0].tookMs + both[1].tookMs, cachedAt: both[0].cachedAt || null });
}));

// GET /zpa/traffic/backends?hours= — host + server_ip targets per app segment
router.get('/zpa/traffic/backends', requireRead, guarded(async function (req, res) {
  var hours = t2Window(req, res, 'backend cut'); if (!hours) return;
  var since = Date.now() - hours * 3600000;
  var r = await offload.query(LSS_DB_PATH, [
    { sql: 'SELECT host, app, COUNT(*) sessions, COUNT(DISTINCT server_ip) server_ips, COUNT(DISTINCT user) users, ' +
           'SUM(bytes_rx) rx, SUM(bytes_tx) tx, MAX(ts) lastTs ' +
           "FROM conns INDEXED BY ix_conns_ts WHERE ts >= ? AND host IS NOT NULL AND host != '' GROUP BY host, app " +
           'ORDER BY (SUM(bytes_rx) + SUM(bytes_tx)) DESC LIMIT 200', params: [since] },
    // Fan-out check: apps a single segment reaches across many server IPs (possible drift / LB)
    { sql: 'SELECT app, COUNT(DISTINCT server_ip) server_ips, COUNT(DISTINCT host) hosts, COUNT(*) sessions ' +
           "FROM conns INDEXED BY ix_conns_ts WHERE ts >= ? AND server_ip IS NOT NULL AND server_ip != '' GROUP BY app " +
           'HAVING server_ips > 1 ORDER BY server_ips DESC LIMIT 50', params: [since] }
  ], t2Opts('backends', hours));
  if (!r.ok) return offloadFail(res, r);
  return res.json({ hours: hours, byHost: r.results[0], fanout: r.results[1], tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// GET /zpa/traffic/clients?hours= — top client public IPs; opportunistic geo from zdx_ip_geo (MySQL)
router.get('/zpa/traffic/clients', requireRead, guarded(async function (req, res) {
  var hours = t2Window(req, res, 'client cut'); if (!hours) return;
  var since = Date.now() - hours * 3600000;
  var r = await offload.query(LSS_DB_PATH, [
    { sql: 'SELECT client_ip, COUNT(*) sessions, COUNT(DISTINCT user) users, COUNT(DISTINCT app) apps, ' +
           'SUM(bytes_rx) rx, SUM(bytes_tx) tx, MAX(ts) lastTs ' +
           "FROM conns INDEXED BY ix_conns_ts WHERE ts >= ? AND client_ip IS NOT NULL AND client_ip != '' GROUP BY client_ip " +
           'ORDER BY (SUM(bytes_rx) + SUM(bytes_tx)) DESC LIMIT 100', params: [since] }
  ], t2Opts('clients', hours));
  if (!r.ok) return offloadFail(res, r);
  // Cached results are shared between callers: enrich a copy.
  var rows = r.results[0].map(function (x) { return Object.assign({}, x); });
  // Geo already cached from the ZDX ISP crawl — zero new API calls, best-effort.
  try {
    var ips = rows.map(function (x) { return x.client_ip; }).filter(Boolean);
    if (ips.length) {
      var pool = getZiaCachePool(router);
      var ph = ips.map(function () { return '?'; }).join(',');
      var geoRows = (await pool.query('SELECT ip, city, region, country_code, isp, is_zscaler FROM zdx_ip_geo WHERE ip IN (' + ph + ')', ips))[0];
      var gmap = {}; geoRows.forEach(function (g) { gmap[g.ip] = g; });
      rows.forEach(function (x) {
        var g = gmap[x.client_ip];
        if (g) { x.city = g.city; x.region = g.region; x.country_code = g.country_code; x.isp = g.isp; x.is_zscaler = g.is_zscaler; }
      });
    }
  } catch (e) { /* geo is best-effort; return rows without it */ }
  return res.json({ hours: hours, clients: rows, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// GET /zpa/traffic/sessions?hours= — concurrency/state timeline (open/active/close counts)
router.get('/zpa/traffic/sessions', requireRead, guarded(async function (req, res) {
  var hours = t2Window(req, res, 'session timeline'); if (!hours) return;
  var since = Date.now() - hours * 3600000;
  var bucketMs = 3600000;
  var r = await offload.query(LSS_DB_PATH, [
    { sql: 'SELECT (ts / ' + bucketMs + ') b, status, COUNT(*) n FROM conns INDEXED BY ix_conns_ts WHERE ts >= ? GROUP BY b, status ORDER BY b', params: [since] },
    { sql: 'SELECT status, COUNT(*) n FROM conns INDEXED BY ix_conns_ts WHERE ts >= ? GROUP BY status', params: [since] }
  ], t2Opts('sessions', hours));
  if (!r.ok) return offloadFail(res, r);
  var buckets = {};
  r.results[0].forEach(function (x) { var t = x.b * bucketMs; (buckets[t] = buckets[t] || { t: t, open: 0, active: 0, close: 0 })[x.status] = x.n; });
  var timeline = Object.keys(buckets).map(function (k) { return buckets[k]; }).sort(function (a, b) { return a.t - b.t; });
  return res.json({ hours: hours, bucketMs: bucketMs, timeline: timeline, byState: r.results[1], tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// GET /zpa/connector-health?hours= — App Connector Status metrics (Phase 2 feed)
// Reads connector_health if lss-receiver v2.0 is populating it (port 9601).
// Answers streaming:false with a setup hint until records arrive. All four
// windows stay available: the table is small (it is empty today) and indexed
// on ts. Cached 30s per window.
router.get('/zpa/connector-health', requireRead, guarded(async function (req, res) {
  var missing = lssMissing(); if (missing) return res.json({ streaming: false, reason: missing });
  var hours = t2Hours(req); var since = Date.now() - hours * 3600000;
  var r = await offload.query(LSS_DB_PATH, [
    { sql: 'SELECT COUNT(*) n, MAX(ts) lastTs FROM connector_health INDEXED BY ix_ch_ts WHERE ts >= ?', params: [since], mode: 'get' },
    // Latest sample per connector + window peaks.
    { sql: 'SELECT connector, ts, cpu, mem, disk, bytes_tx, bytes_rx, raw FROM connector_health ch1 ' +
           'WHERE ts = (SELECT MAX(ts) FROM connector_health ch2 WHERE ch2.connector = ch1.connector) ' +
           'GROUP BY connector ORDER BY connector' },
    { sql: 'SELECT connector, MAX(cpu) cpuMax, MAX(mem) memMax, MAX(disk) diskMax, COUNT(*) samples ' +
           'FROM connector_health INDEXED BY ix_ch_ts WHERE ts >= ? GROUP BY connector', params: [since] }
  ], { cacheKey: 'lss:chealth:' + hours, cacheTtlMs: 30000, timeoutMs: 30000, label: 'Connector health (' + hours + 'h)' });
  if (!r.ok) {
    if (/no such table/i.test(r.error)) return res.json({ streaming: false, reason: 'connector_health table not present — configure ZPA App Connector Status LSS → itam:9601 and restart lss-receiver' });
    return res.json({ streaming: false, reason: r.error });
  }
  var cnt = r.results[0] || { n: 0, lastTs: null };
  if (!cnt.n) return res.json({ streaming: false, reason: 'connector_health table empty for window — no App Connector Status records yet' });
  var pmap = {}; r.results[2].forEach(function (p) { pmap[p.connector] = p; });
  var latest = r.results[1].map(function (l) {
    var p = pmap[l.connector] || {};
    return Object.assign({}, l, { cpuMax: p.cpuMax, memMax: p.memMax, diskMax: p.diskMax, samples: p.samples });
  });
  return res.json({ streaming: true, hours: hours, records: cnt.n, lastTs: cnt.lastTs, connectors: latest, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));
// ═══ end CC-ROUTES-TRAFFIC2 v3.0 ═══

// CC-NSS-SSL v3.1 — ZIA NSS SSL/inspection-error analytics (nss.db, ssl_events)
// Every read runs in a worker thread and names ix_ssl_ts: the by-user and
// by-site rollups were being planned as full scans of ix_ssl_user/ix_ssl_host
// (1.5s each at 24h vs 60ms through the ts index, 2026-09-23). Status is cached
// 30s, the summary 60s per window; the detail drill is not cached.
var NSS_DB_PATH = process.env.NSS_DB || '/var/www/corpit-hub-api/data/nss.db';
var NSS_MISSING = 'nss.db not present — NSS feed not configured yet';
function nssHours(req) { var a = [1, 8, 24, 168, 720]; var h = parseInt(req.query.hours, 10) || 24; return a.indexOf(h) === -1 ? 24 : h; }

// GET /zscaler/nss/ssl/status — feed liveness + quick counts (for the Overview KPI)
router.get('/nss/ssl/status', requireRead, guarded(async function (req, res) {
  var missing = dbMissing(NSS_DB_PATH, NSS_MISSING); if (missing) return res.json({ streaming: false, reason: missing });
  var since = Date.now() - 24 * 3600000;
  var r = await offload.query(NSS_DB_PATH, [
    { sql: 'SELECT COUNT(*) events, COUNT(DISTINCT user) users, COUNT(DISTINCT host) sites, MAX(ts) lastTs FROM ssl_events INDEXED BY ix_ssl_ts WHERE ts >= ?', params: [since], mode: 'get' }
  ], { cacheKey: 'nss:status', cacheTtlMs: 30000, timeoutMs: 15000, label: 'NSS SSL status' });
  if (!r.ok) return res.json({ streaming: false, reason: r.error });
  var row = r.results[0] || {};
  return res.json({ streaming: (row.events || 0) > 0, hours: 24, events: row.events || 0, users: row.users || 0, sites: row.sites || 0, lastTs: row.lastTs || null });
}));

// GET /zscaler/nss/ssl/summary?hours= — KPI totals + rollups by reason / user / site
router.get('/nss/ssl/summary', requireRead, guarded(async function (req, res) {
  var missing = dbMissing(NSS_DB_PATH, NSS_MISSING); if (missing) return res.status(503).json({ error: missing });
  var hours = nssHours(req); var since = Date.now() - hours * 3600000;
  var bucketMs = hours <= 24 ? 3600000 : 6 * 3600000;   // hourly (<=24h) or 6h buckets for the trend
  var src = ' FROM ssl_events INDEXED BY ix_ssl_ts WHERE ts >= ?';
  var r = await offload.query(NSS_DB_PATH, [
    { sql: 'SELECT COUNT(*) events, COUNT(DISTINCT user) users, COUNT(DISTINCT host) sites, COUNT(DISTINCT reason) reasons, MAX(ts) lastTs' + src, params: [since], mode: 'get' },
    { sql: 'SELECT reason, COUNT(*) c, COUNT(DISTINCT user) users, COUNT(DISTINCT host) sites' + src + ' GROUP BY reason ORDER BY c DESC', params: [since] },
    { sql: 'SELECT user, COUNT(*) c, COUNT(DISTINCT host) sites, MAX(ts) lastTs' + src + " AND user != '' GROUP BY user ORDER BY c DESC LIMIT 100", params: [since] },
    { sql: 'SELECT host, COUNT(*) c, COUNT(DISTINCT user) users, MAX(ts) lastTs' + src + " AND host != '' GROUP BY host ORDER BY c DESC LIMIT 100", params: [since] },
    { sql: 'SELECT url_category, COUNT(*) c' + src + " AND url_category != '' GROUP BY url_category ORDER BY c DESC LIMIT 30", params: [since] },
    { sql: 'SELECT (ts / ' + bucketMs + ') b, COUNT(*) c' + src + ' GROUP BY b ORDER BY b', params: [since] }
  ], { cacheKey: 'nss:summary:' + hours, cacheTtlMs: 60000, timeoutMs: 60000, label: 'NSS SSL summary (' + hours + 'h)' });
  if (!r.ok) return offloadFail(res, r);
  var t = r.results;
  return res.json({ hours: hours, bucketMs: bucketMs, totals: t[0], byReason: t[1], byUser: t[2], bySite: t[3], byCategory: t[4],
    timeline: t[5].map(function (x) { return { t: x.b * bucketMs, c: x.c }; }), tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// GET /zscaler/nss/ssl/detail?hours=&user=&host=&reason= — drill to raw events
router.get('/nss/ssl/detail', requireRead, guarded(async function (req, res) {
  var missing = dbMissing(NSS_DB_PATH, NSS_MISSING); if (missing) return res.status(503).json({ error: missing });
  var hours = nssHours(req); var since = Date.now() - hours * 3600000;
  var where = ['ts >= ?']; var args = [since];
  if (req.query.user)   { where.push('user = ?');   args.push(String(req.query.user)); }
  if (req.query.host)   { where.push('host = ?');   args.push(String(req.query.host)); }
  if (req.query.reason) { where.push('reason = ?'); args.push(String(req.query.reason)); }
  var r = await offload.query(NSS_DB_PATH, [
    { sql: 'SELECT ts,user,host,url,reason,action,device,client_ip,server_ip,url_category,app,client_tls,server_tls,client_cipher,server_cipher,resp_code ' +
           'FROM ssl_events WHERE ' + where.join(' AND ') + ' ORDER BY ts DESC LIMIT 500', params: args }
  ], { timeoutMs: 30000, label: 'NSS SSL detail (' + hours + 'h)' });
  if (!r.ok) return offloadFail(res, r);
  return res.json({ hours: hours, count: r.results[0].length, events: r.results[0] });
}));
// ═══ end CC-NSS-SSL v3.1 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-PHASE1A v1.0 — ZCC DB-backed summaries + ZTW + ZPA expansions
// Deployed 2026-08-06. Rollback: restore from /var/backups/itam/*.pre-phase1a.*
// Depends on: zcc_devices table (see zcc-devices-sync.js cron)
// ═══════════════════════════════════════════════════════════════════
const p1aPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'corpit_hub',
  waitForConnections: true, connectionLimit: 4
});

// ── /zcc/summary — fleet aggregations from zcc_devices ──
router.get('/zcc/summary', requireRead, async (req, res) => {
  try {
    const [[cnt]] = await p1aPool.query(
      'SELECT COUNT(*) total, ' +
      'SUM(CASE WHEN device_state="Registered" THEN 1 ELSE 0 END) registered, ' +
      'SUM(CASE WHEN device_state="Removed" OR deregistration_ts IS NOT NULL THEN 1 ELSE 0 END) deregistered, ' +
      'SUM(CASE WHEN last_seen_active >= NOW() - INTERVAL 24 HOUR THEN 1 ELSE 0 END) active_24h, ' +
      'SUM(CASE WHEN last_seen_active < NOW() - INTERVAL 30 DAY THEN 1 ELSE 0 END) stale_30d ' +
      'FROM zcc_devices'
    );
    const [tunnel]  = await p1aPool.query('SELECT tunnel_version, COUNT(*) c FROM zcc_devices WHERE tunnel_version IS NOT NULL GROUP BY tunnel_version ORDER BY c DESC');
    const [zccVer]  = await p1aPool.query('SELECT zcc_version, COUNT(*) c FROM zcc_devices WHERE zcc_version IS NOT NULL GROUP BY zcc_version ORDER BY c DESC LIMIT 15');
    const [zdxVer]  = await p1aPool.query('SELECT zdx_version, COUNT(*) c FROM zcc_devices WHERE zdx_version IS NOT NULL GROUP BY zdx_version ORDER BY c DESC LIMIT 15');
    const [osType]  = await p1aPool.query('SELECT device_type, COUNT(*) c FROM zcc_devices WHERE device_type IS NOT NULL GROUP BY device_type ORDER BY c DESC');
    const [byPol]   = await p1aPool.query('SELECT policy_name, COUNT(*) c FROM zcc_devices WHERE policy_name IS NOT NULL GROUP BY policy_name ORDER BY c DESC LIMIT 20');
    const [[xlink]] = await p1aPool.query(
      'SELECT COUNT(*) zcc_total, ' +
      'SUM(CASE WHEN i.serial_number IS NOT NULL THEN 1 ELSE 0 END) intune_matched ' +
      'FROM zcc_devices z LEFT JOIN it_inventory.intune_devices i ON i.serial_number COLLATE utf8mb4_unicode_ci = z.serial_number ' +
      'WHERE z.serial_number IS NOT NULL AND z.serial_number != ""'
    );
    const [[fresh]] = await p1aPool.query('SELECT MAX(updated_at) last_sync FROM zcc_devices');
    return res.json({
      totals: cnt, tunnelDist: tunnel, zccVersionDist: zccVer, zdxVersionDist: zdxVer,
      osDist: osType, policyDist: byPol, intuneCrosslink: xlink, lastSync: fresh.last_sync
    });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── ZCC agent-version comparison — SHARED by every drift render path ──
// There is no trustworthy "latest ZCC build" source available to this platform:
// the ZCC API exposes no latest-version endpoint, the app profiles
// (/zcc/papi/public/v1/web/policy/listByCompany) carry no target-version field,
// getCompanyInfo's "version" is the ADMIN PORTAL version (not a client build),
// and no config value pins one. The previous code used the MOST COMMON installed
// build as "latest", which is not the same thing: it marked the single largest
// cohort up-to-date by definition (280 Windows devices on 4.9.0.412 while 4.9.0.448
// and 4.9.0.455 were already deployed) and flagged every device on ANOTHER
// platform's newest build as outdated. ZCC ships a separate version line per
// platform (Windows / macOS / iOS / Android), so one global "latest" is wrong by
// construction. What we CAN measure is the newest build observed in our own fleet,
// per platform — so that is what we compare against, and that is what we say.
// Vendor-latest stays explicitly 'unknown' (amber "?"), never a green number.
function zccVerKey(v) {
  // Drop the architecture suffix ("(64-bit)") — not part of the version. Any other
  // parenthesised number IS a build number (iOS/macOS ship "4.5.1 (37)").
  var nums = String(v == null ? '' : v).replace(/\(\s*\d+\s*-\s*bit\s*\)/gi, ' ').match(/\d+/g);
  return nums ? nums.map(Number) : [];
}
function zccVerCmp(a, b) {
  var A = zccVerKey(a), B = zccVerKey(b), n = Math.max(A.length, B.length);
  for (var i = 0; i < n; i++) {
    var x = A[i] || 0, y = B[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
// rows: [{ device_type, zcc_version, c }] -> { platformKey: newestObservedVersion }
function zccNewestObserved(rows) {
  var out = {};
  (rows || []).forEach(function (r) {
    if (!r || !r.zcc_version) return;
    var p = r.device_type == null ? '' : String(r.device_type);
    if (out[p] === undefined || zccVerCmp(r.zcc_version, out[p]) > 0) out[p] = r.zcc_version;
  });
  return out;
}

// ── /zcc/drift — agent-version drift audit (per-platform, fleet-observed baseline) ──
router.get('/zcc/drift', requireRead, async (req, res) => {
  try {
    const [byPlatform] = await p1aPool.query(
      'SELECT device_type, zcc_version, COUNT(*) c FROM zcc_devices WHERE zcc_version IS NOT NULL GROUP BY device_type, zcc_version ORDER BY c DESC'
    );
    const [zcc] = await p1aPool.query(
      'SELECT zcc_version, COUNT(*) c FROM zcc_devices WHERE zcc_version IS NOT NULL GROUP BY zcc_version ORDER BY c DESC'
    );
    const newest = zccNewestObserved(byPlatform);
    const platforms = Object.keys(newest);
    const platTotal = {};
    byPlatform.forEach(function (r) {
      var p = r.device_type == null ? '' : String(r.device_type);
      platTotal[p] = (platTotal[p] || 0) + (Number(r.c) || 0);
    });
    const reference = platforms.map(function (p) {
      return { platform: p || null, newestObserved: newest[p], devices: platTotal[p] || 0 };
    }).sort(function (a, b) { return b.devices - a.devices; });
    // Measured and genuinely empty is still not "everyone is current": with no
    // versions in the table there is no baseline, so drift is unknown, not zero.
    if (!platforms.length) {
      return res.json({
        referenceBasis: 'fleet-newest-observed-per-platform',
        latestVersion: null, latestVersionStatus: 'unknown',
        vendorLatestVersion: null, vendorLatestStatus: 'unknown',
        vendorLatestReason: 'no ZCC API endpoint or config value publishes the vendor-latest build',
        driftStatus: 'unknown',
        driftReason: 'zcc_devices holds no agent versions — the ZCC sync has not populated the table',
        reference: [], byPlatform: byPlatform, distribution: zcc,
        outdatedDevices: [], outdatedCount: null, returned: 0, truncated: false
      });
    }
    // Exclude every build that TIES its platform's newest on the numeric key, not
    // just the one string we happened to pick. zccVerKey drops the architecture
    // suffix, so "4.9.0.455 (64-bit)" and "4.9.0.455 (32-bit)" are the same build;
    // excluding by exact string would leave the other architecture reported as
    // drifted against a numerically identical baseline — a false alarm on a fleet
    // that is fully current. Every platform's newest ties itself, so past the
    // !platforms.length guard `current` always has at least one pair per platform
    // and the join can never dangle.
    const current = [];
    platforms.forEach(function (p) {
      const seen = {};
      byPlatform.forEach(function (r) {
        const rp = r.device_type == null ? '' : String(r.device_type);
        if (rp !== p || !r.zcc_version || seen[r.zcc_version]) return;
        if (zccVerCmp(r.zcc_version, newest[p]) === 0) { seen[r.zcc_version] = 1; current.push([p, r.zcc_version]); }
      });
    });
    const where = 'zcc_version IS NOT NULL AND ' +
      current.map(function () { return 'NOT (device_type <=> ? AND zcc_version = ?)'; }).join(' AND ');
    const args = [];
    current.forEach(function (pv) { args.push(pv[0] === '' ? null : pv[0], pv[1]); });
    // Count separately: outdatedDevices is a capped page, so its length is a page
    // size, not the population. Reporting the page size as the total under-reports.
    const [[tot]] = await p1aPool.query('SELECT COUNT(*) c FROM zcc_devices WHERE ' + where, args);
    const [outdated] = await p1aPool.query(
      'SELECT udid, user_upn, hostname, device_type, zcc_version, zdx_version, last_seen_active ' +
      'FROM zcc_devices WHERE ' + where + ' ORDER BY last_seen_active DESC LIMIT 500',
      args
    );
    outdated.forEach(function (d) {
      d.newestObservedForPlatform = newest[d.device_type == null ? '' : String(d.device_type)] || null;
    });
    const total = Number(tot && tot.c) || 0;
    return res.json({
      referenceBasis: 'fleet-newest-observed-per-platform',
      // Not measurable: no vendor source exists. Render this as an amber "?",
      // never as a version and never as green.
      latestVersion: null, latestVersionStatus: 'unknown',
      vendorLatestVersion: null, vendorLatestStatus: 'unknown',
      vendorLatestReason: 'no ZCC API endpoint or config value publishes the vendor-latest build',
      driftStatus: 'ok',
      reference: reference, byPlatform: byPlatform, distribution: zcc,
      outdatedDevices: outdated, outdatedCount: total,
      returned: outdated.length, truncated: total > outdated.length
    });
  } catch (e) {
    // Could not measure. Keep the 500 so the page paints its "unavailable" card,
    // and carry the unknown in the body too, for consumers that ignore the status
    // code. Never fall through to an empty list — that reads as "0 devices drifted".
    return res.status(500).json({
      error: e.message, driftStatus: 'unknown', driftReason: 'drift query failed: ' + e.message,
      latestVersion: null, latestVersionStatus: 'unknown',
      vendorLatestVersion: null, vendorLatestStatus: 'unknown',
      outdatedCount: null, returned: 0, truncated: false
    });
  }
});

// ── /zcc/dereg — deregistered device audit ──
router.get('/zcc/dereg', requireRead, async (req, res) => {
  try {
    const [rows] = await p1aPool.query(
      'SELECT udid, user_upn, hostname, device_type, serial_number, ' +
      'registration_ts, deregistration_ts, last_seen_active, policy_name ' +
      'FROM zcc_devices WHERE deregistration_ts IS NOT NULL ' +
      'ORDER BY deregistration_ts DESC LIMIT 500'
    );
    return res.json({ deregistered: rows, count: rows.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zcc/orphans — devices in one system but not the other ──
router.get('/zcc/orphans', requireRead, async (req, res) => {
  try {
    const [zccOnly] = await p1aPool.query(
      'SELECT z.udid, z.user_upn, z.hostname, z.serial_number, z.device_type, z.last_seen_active ' +
      'FROM zcc_devices z LEFT JOIN it_inventory.intune_devices i ON i.serial_number COLLATE utf8mb4_unicode_ci = z.serial_number ' +
      'WHERE z.serial_number IS NOT NULL AND z.serial_number != "" AND i.serial_number IS NULL ' +
      'ORDER BY z.last_seen_active DESC LIMIT 300'
    );
    const [intuneOnly] = await p1aPool.query(
      'SELECT i.id, i.device_name, i.serial_number ' +
      'FROM it_inventory.intune_devices i LEFT JOIN zcc_devices z ON z.serial_number = i.serial_number COLLATE utf8mb4_unicode_ci ' +
      'WHERE i.serial_number IS NOT NULL AND i.serial_number != "" AND z.serial_number IS NULL ' +
      'LIMIT 300'
    );
    return res.json({ zccOnly: zccOnly, zccOnlyCount: zccOnly.length, intuneOnly: intuneOnly, intuneOnlyCount: intuneOnly.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zcc/device/:udid — single device with Intune cross-link ──
router.get('/zcc/device/:udid', requireRead, async (req, res) => {
  try {
    const [rows] = await p1aPool.query(
      'SELECT z.*, i.id intune_id, i.device_name intune_device_name ' +
      'FROM zcc_devices z LEFT JOIN it_inventory.intune_devices i ON i.serial_number COLLATE utf8mb4_unicode_ci = z.serial_number ' +
      'WHERE z.udid = ? LIMIT 1',
      [req.params.udid]
    );
    if (!rows.length) return res.status(404).json({ error: 'device not found' });
    return res.json(rows[0]);
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /ztw/ip-dest-groups — Cloud Connector destination groups ──
router.get('/ztw/ip-dest-groups', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/ztw/api/v1/ipDestinationGroups?pageSize=500');
    if (r.status !== 200) return res.status(502).json({ error: 'ZTW ipDestinationGroups HTTP ' + r.status });
    const groups = asList(r.body);
    return res.json({ groups: groups, count: groups.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /ztw/ip-source-groups — Cloud Connector source groups ──
router.get('/ztw/ip-source-groups', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/ztw/api/v1/ipSourceGroups?pageSize=500');
    if (r.status !== 200) return res.status(502).json({ error: 'ZTW ipSourceGroups HTTP ' + r.status });
    const groups = asList(r.body);
    return res.json({ groups: groups, count: groups.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zpa/access-rules — ZPA ACCESS_POLICY rules w/ conditions ──
router.get('/zpa/access-rules', requireRead, async (req, res) => {
  try {
    const cid = process.env.ZPA_CUSTOMER_ID;
    if (!cid) return res.status(500).json({ error: 'ZPA_CUSTOMER_ID not set' });
    const all = [];
    let page = 1;
    const MAX_PAGES = 10;
    while (page <= MAX_PAGES) {
      const r = await oneapiGet('/zpa/mgmtconfig/v1/admin/customers/' + cid + '/policySet/rules/policyType/ACCESS_POLICY?page=' + page + '&pagesize=100');
      if (r.status !== 200) { if (all.length) break; return res.status(502).json({ error: 'ZPA access rules HTTP ' + r.status }); }
      const body = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
      const chunk = (body && body.list) ? body.list : [];
      all.push.apply(all, chunk);
      if (chunk.length < 100) break;
      page++;
    }
    return res.json({ rules: all, count: all.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ═══ end CC-PHASE1A v1.0 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-DLP-DEEP v1.0 — ZIA DLP expansion + ZWA client-side aggregations
// Deployed 2026-08-06. Rollback: restore pre-dlp-deep backup.
// ═══════════════════════════════════════════════════════════════════

// ── /zia/dlp-notification-templates — 5 templates ──
router.get('/zia/dlp-notification-templates', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/dlpNotificationTemplates');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA notif-templates HTTP ' + r.status });
    const templates = asList(r.body);
    return res.json({ templates: templates, count: templates.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/dlp-edm-schemas — Exact Data Match schemas ──
router.get('/zia/dlp-edm-schemas', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/dlpExactDataMatchSchemas');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA EDM HTTP ' + r.status });
    const schemas = asList(r.body);
    return res.json({ schemas: schemas, count: schemas.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/dlp-idm-profiles — Indexed Doc Match profiles ──
router.get('/zia/dlp-idm-profiles', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/idmprofile');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA IDM HTTP ' + r.status });
    const profiles = asList(r.body);
    return res.json({ profiles: profiles, count: profiles.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/icap-servers ──
router.get('/zia/icap-servers', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/icapServers');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA ICAP HTTP ' + r.status });
    const servers = asList(r.body);
    return res.json({ servers: servers, count: servers.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/incident-receivers ──
router.get('/zia/incident-receivers', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/incidentReceiverServers');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA incident-receivers HTTP ' + r.status });
    const receivers = asList(r.body);
    return res.json({ receivers: receivers, count: receivers.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/file-type-rules ──
router.get('/zia/file-type-rules', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/fileTypeRules');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA file-type-rules HTTP ' + r.status });
    const rules = asList(r.body);
    return res.json({ rules: rules, count: rules.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/org-info ──
router.get('/zia/org-info', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/orgInformation');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA org-info HTTP ' + r.status });
    const body = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
    const org = Array.isArray(body) ? body[0] : body;
    return res.json({ org: org });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/dlp-dictionaries-predef — 204 predefined dicts (lite endpoint) ──
router.get('/zia/dlp-dictionaries-predef', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/dlpDictionaries/lite');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA predef HTTP ' + r.status });
    const dictionaries = asList(r.body);
    return res.json({ dictionaries: dictionaries, count: dictionaries.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zwa/statistics — client-side aggregation from /incidents/search ──
router.get('/zwa/statistics', requireRead, async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days, 10) || 30, 365);
    const et = new Date(), st = new Date(Date.now() - days * 86400000);
    let t;
    try { t = await zwaToken(); }
    catch (e) { if (e.code === 'NOKEYS') return res.status(501).json({ error: e.message }); throw e; }
    const doSearch = function (tok) {
      return httpsRequest(new URL(ZWA_BASE + '/dlp/v1/incidents/search'),
        { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': 'itam-command-center/2.0' } },
        JSON.stringify({ timeRange: { startTime: st.toISOString(), endTime: et.toISOString() } }));
    };
    let r = await doSearch(t);
    if (r.status === 401) { t = await zwaToken(true); r = await doSearch(t); }
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA stats search HTTP ' + r.status });
    const b = r.body || {};
    let list = Array.isArray(b.data) ? b.data : (Array.isArray(b.incidents) ? b.incidents : asList(b));
    function agg(fn) {
      const m = {};
      list.forEach(i => { const k = fn(i) || 'unknown'; m[k] = (m[k] || 0) + 1; });
      return Object.keys(m).map(k => ({ key: k, count: m[k] })).sort((a, b) => b.count - a.count);
    }
    return res.json({
      total: list.length,
      window: { from: st.toISOString(), to: et.toISOString(), days },
      bySeverity:    agg(i => i.severity),
      byStatus:      agg(i => i.status),
      byPriority:    agg(i => i.priority),
      bySourceType:  agg(i => i.sourceType),
      byEngine:      agg(i => (i.matchingPolicies && i.matchingPolicies.engines && i.matchingPolicies.engines[0]) ? i.matchingPolicies.engines[0].name : null),
      byRule:        agg(i => (i.matchingPolicies && i.matchingPolicies.rules && i.matchingPolicies.rules[0]) ? i.matchingPolicies.rules[0].name : null),
      byUser:        agg(i => i.userInfo && i.userInfo.email),
      byDepartment:  agg(i => i.userInfo && i.userInfo.department),
      byApp:         agg(i => i.applicationInfo && i.applicationInfo.hostnameOrApplication),
      byProtocol:    agg(i => i.protocol)
    });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zwa/timeline — daily buckets by severity ──
router.get('/zwa/timeline', requireRead, async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days, 10) || 30, 365);
    const et = new Date(), st = new Date(Date.now() - days * 86400000);
    let t;
    try { t = await zwaToken(); }
    catch (e) { if (e.code === 'NOKEYS') return res.status(501).json({ error: e.message }); throw e; }
    const doSearch = function (tok) {
      return httpsRequest(new URL(ZWA_BASE + '/dlp/v1/incidents/search'),
        { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': 'itam-command-center/2.0' } },
        JSON.stringify({ timeRange: { startTime: st.toISOString(), endTime: et.toISOString() } }));
    };
    let r = await doSearch(t);
    if (r.status === 401) { t = await zwaToken(true); r = await doSearch(t); }
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA timeline HTTP ' + r.status });
    const b = r.body || {};
    let list = Array.isArray(b.data) ? b.data : (Array.isArray(b.incidents) ? b.incidents : asList(b));
    const buckets = {};
    list.forEach(i => {
      const d = i.createdAt ? String(i.createdAt).slice(0, 10) : null;
      if (!d) return;
      if (!buckets[d]) buckets[d] = { date: d, total: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      buckets[d].total++;
      const s = String(i.severity || '').toUpperCase();
      if (buckets[d][s] !== undefined) buckets[d][s]++;
    });
    return res.json({
      total: list.length,
      window: { from: st.toISOString(), to: et.toISOString(), days },
      timeline: Object.values(buckets).sort((a, b) => a.date.localeCompare(b.date))
    });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ═══ end CC-DLP-DEEP v1.0 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-DLP-EVIDENCE v1.0 — incident evidence / triggers / tickets / tx lookup
// S3 attachment streaming pending infosec bucket access (see backlog).
// ═══════════════════════════════════════════════════════════════════

// ── /zwa/incident/:id/evidence — file meta + evidenceURL ──
router.get('/zwa/incident/:id/evidence', requireRead, async (req, res) => {
  try {
    const id = encodeURIComponent(String(req.params.id || '').trim());
    if (!id) return res.status(400).json({ error: 'incident id required' });
    const r = await zwaGet('/dlp/v1/incidents/' + id + '/evidence');
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA evidence HTTP ' + r.status });
    const body = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
    return res.json(body);
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zwa/incident/:id/triggers — actual matched strings per dictionary ──
router.get('/zwa/incident/:id/triggers', requireRead, async (req, res) => {
  try {
    const id = encodeURIComponent(String(req.params.id || '').trim());
    if (!id) return res.status(400).json({ error: 'incident id required' });
    const r = await zwaGet('/dlp/v1/incidents/' + id + '/triggers');
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA triggers HTTP ' + r.status });
    const body = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
    return res.json({ triggers: body });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zwa/incident/:id/tickets ──
router.get('/zwa/incident/:id/tickets', requireRead, async (req, res) => {
  try {
    const id = encodeURIComponent(String(req.params.id || '').trim());
    if (!id) return res.status(400).json({ error: 'incident id required' });
    const r = await zwaGet('/dlp/v1/incidents/' + id + '/tickets');
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA tickets HTTP ' + r.status });
    const body = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
    return res.json({ tickets: (body && body.tickets) || [], cursor: body && body.cursor });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zwa/transaction/:txid — find incident(s) by ZIA transaction id ──
router.get('/zwa/transaction/:txid', requireRead, async (req, res) => {
  try {
    const tx = encodeURIComponent(String(req.params.txid || '').trim());
    if (!tx) return res.status(400).json({ error: 'transaction id required' });
    const r = await zwaGet('/dlp/v1/incidents/transactions/' + tx);
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA tx lookup HTTP ' + r.status });
    const body = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
    return res.json({ incidents: (body && body.incidents) || [], cursor: body && body.cursor });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ═══ end CC-DLP-EVIDENCE v1.0 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-GENAI v1.0 — Gen AI Security posture (ZIA AI_ML app-control rules)
// ═══════════════════════════════════════════════════════════════════
router.get('/zia/genai-rules', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/webApplicationRules/AI_ML');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA AI_ML rules HTTP ' + r.status });
    const rules = asList(r.body);
    // Summary aggregation
    const summary = { total: rules.length, allow: 0, deny: 0, isolate: 0, caution: 0, promptCapture: 0, enabled: 0, appsGoverned: {} };
    rules.forEach(x => {
      const acts = (x.actions || []).join(',');
      if (/ALLOW/.test(acts)) summary.allow++;
      if (/DENY|BLOCK/.test(acts)) summary.deny++;
      if (/ISOLATE/.test(acts)) summary.isolate++;
      if (/CAUTION/.test(acts)) summary.caution++;
      if (x.promptCaptureEnabled) summary.promptCapture++;
      if (x.state === 'ENABLED') summary.enabled++;
      (x.applications || []).forEach(a => { summary.appsGoverned[a] = (summary.appsGoverned[a] || 0) + 1; });
    });
    summary.distinctApps = Object.keys(summary.appsGoverned).length;
    // sort by order for a proper policy stack
    rules.sort((a, b) => (parseInt(a.order, 10) || 0) - (parseInt(b.order, 10) || 0));
    return res.json({ rules: rules, count: rules.length, summary: summary });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/genai-apps — full AI/ML app catalog (filter broken server-side; return all) ──
router.get('/zia/genai-apps', requireRead, async (req, res) => {
  try {
    const r = await oneapiGet('/zia/api/v1/cloudApplications/lite?pageSize=1000');
    if (r.status !== 200) return res.status(502).json({ error: 'ZIA cloudApps HTTP ' + r.status });
    const apps = asList(r.body);
    return res.json({ apps: apps, count: apps.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ═══ end CC-GENAI v1.0 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-AI-USAGE v1.0 — Gen AI usage analytics (ai.db, ai_events)
// Fed by ai-nss-receiver (NSS-AI-ITAM feed, AI & ML Apps class).
// ═══════════════════════════════════════════════════════════════════
var AI_DB_PATH = process.env.AI_NSS_DB || '/var/www/corpit-hub-api/data/ai.db';
var AI_MISSING = 'ai.db not present — AI NSS feed not configured yet';
// Every ai.db read below runs in a worker thread (sqlite-offload). Windows up
// to 30 days are served; the page offers 24h/7d/30d. Longer windows are refused
// with the reason: the 30-day cuts already take 3-7s each cold (2026-09-23) and
// every hour past that adds a straight-line scan. Results are cached 60s for
// windows up to a day and 5 min beyond, keyed by route and window.
var AI_MAX_HOURS = 720;
function aiHours(req) {
  var h = parseInt(req.query.hours, 10);
  if (!isNaN(h) && h > 0) return Math.min(h, 8760);
  var d = parseInt(req.query.days, 10);
  if (!isNaN(d) && d > 0) return Math.min(d * 24, 8760);
  return 168; // default 7d
}
// Answers the request when the window is refused or the file is missing and
// returns 0; otherwise the window in hours.
function aiWindow(req, res) {
  var hours = aiHours(req);
  if (hours > AI_MAX_HOURS) {
    res.status(400).json({ error: 'The ' + hours + 'h AI usage window is not available on this host: it would scan every ' +
      'AI event for the period (' + Math.round(hours / 24) + ' days). Choose 30 days or shorter.' });
    return 0;
  }
  var missing = dbMissing(AI_DB_PATH, AI_MISSING); if (missing) { res.status(503).json({ error: missing }); return 0; }
  return hours;
}
function aiOpts(route, hours, extra) {
  return { cacheKey: 'ai:' + route + ':' + hours + (extra ? ':' + extra : ''), cacheTtlMs: hours <= 24 ? 60000 : 300000,
           timeoutMs: 60000, label: 'AI ' + route + ' (' + hours + 'h)' };
}
function aiIsAllowed(a) { return /allow/i.test(a || ''); }
function aiIsBlocked(a) { return /block|deny|drop/i.test(a || ''); }
function aiIsIsolated(a) { return /isolat/i.test(a || ''); }
// The GROUP BY cuts name ix_ai_ts: without sqlite_stat1 the planner pairs the
// GROUP BY column with the index on that column and walks all 2M entries.
var AI_SRC = ' FROM ai_events INDEXED BY ix_ai_ts WHERE ts >= ?';
var AI_BLOCKED = "SUM(CASE WHEN action LIKE '%lock%' OR action LIKE '%eny%' OR action LIKE '%rop%' THEN 1 ELSE 0 END)";
// Loose index scan: step through the distinct values of a column with one
// index seek each (a recursive CTE on MIN(col) > last), then probe the
// column's (col, ts) index for the window. 3ms for the distinct-user count
// against 400ms-12s for COUNT(DISTINCT user) over the window.
function aiDistinct(col) {
  return 'WITH RECURSIVE d(k) AS (SELECT MIN(' + col + ') FROM ai_events UNION ALL ' +
         'SELECT (SELECT MIN(' + col + ') FROM ai_events WHERE ' + col + ' > d.k) FROM d WHERE d.k IS NOT NULL) ';
}
function aiDistinctInWindow(col, ix) {
  return aiDistinct(col) + 'SELECT COUNT(*) v FROM d WHERE k IS NOT NULL AND EXISTS ' +
         '(SELECT 1 FROM ai_events INDEXED BY ' + ix + ' WHERE ' + col + ' = d.k AND ts >= ?)';
}

// ── /zia/ai/status — overview probe (KPIs) ──
// COUNT(*) is a covering walk of ix_ai_ts; users/apps/actions come from loose
// scans of their own indexes. Distinct hosts (thousands of values, so no loose
// scan) reads ix_ai_ts up to a day and the covering (host, ts) index beyond,
// whichever measured faster at that window (0.4s vs 3.7s at 24h, 2.3s vs 4.5s at 30d).
router.get('/zia/ai/status', requireRead, guarded(async function (req, res) {
  var hours = aiHours(req);
  if (hours > AI_MAX_HOURS) return res.status(400).json({ error: 'The ' + hours + 'h AI usage window is not available on this host. Choose 30 days or shorter.' });
  var missing = dbMissing(AI_DB_PATH, AI_MISSING); if (missing) return res.json({ streaming: false, reason: missing });
  var since = Date.now() - hours * 3600000;
  var r = await offload.query(AI_DB_PATH, [
    { sql: 'SELECT COUNT(*) c' + AI_SRC, params: [since], mode: 'get' },
    { sql: aiDistinctInWindow('user', 'ix_ai_user'), params: [since], mode: 'get' },
    { sql: aiDistinctInWindow('app', 'ix_ai_app'), params: [since], mode: 'get' },
    { sql: 'SELECT COUNT(DISTINCT host) s FROM ai_events INDEXED BY ' + (hours <= 24 ? 'ix_ai_ts' : 'ix_ai_host') + ' WHERE ts >= ?', params: [since], mode: 'get' },
    { sql: aiDistinct('action') + 'SELECT k action, (SELECT COUNT(*) FROM ai_events INDEXED BY ix_ai_action WHERE action = d.k AND ts >= ?) c FROM d WHERE k IS NOT NULL', params: [since] }
  ], aiOpts('status', hours));
  if (!r.ok) return res.json({ streaming: false, reason: r.error });
  var t = r.results, allowed = 0, blocked = 0, isolated = 0;
  t[4].forEach(function (x) { if (aiIsBlocked(x.action)) blocked += x.c; else if (aiIsIsolated(x.action)) isolated += x.c; else if (aiIsAllowed(x.action)) allowed += x.c; });
  return res.json({ streaming: true, hours: hours, transactions: t[0].c, users: t[1].v, apps: t[2].v, sites: t[3].s,
    allowed: allowed, blocked: blocked, isolated: isolated, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /zia/ai/top-apps — per-app usage w/ allowed/blocked/isolated ──
router.get('/zia/ai/top-apps', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var r = await offload.query(AI_DB_PATH, [
    { sql: 'SELECT app, COUNT(*) total, COUNT(DISTINCT user) users, ' +
           "SUM(CASE WHEN action LIKE '%llow%' THEN 1 ELSE 0 END) allowed, " + AI_BLOCKED + ' blocked, ' +
           "SUM(CASE WHEN action LIKE '%solat%' THEN 1 ELSE 0 END) isolated" +
           AI_SRC + ' AND app IS NOT NULL AND length(app) > 0 GROUP BY app ORDER BY total DESC LIMIT 50', params: [Date.now() - hours * 3600000] }
  ], aiOpts('top-apps', hours));
  if (!r.ok) return offloadFail(res, r);
  return res.json({ hours: hours, apps: r.results[0], count: r.results[0].length, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /zia/ai/top-users ──
router.get('/zia/ai/top-users', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var r = await offload.query(AI_DB_PATH, [
    { sql: 'SELECT user, COUNT(*) total, COUNT(DISTINCT app) apps, COUNT(DISTINCT host) sites, SUM(COALESCE(req_size, 0)) up_bytes, ' +
           AI_BLOCKED + ' blocked, MAX(ts) last_seen' +
           AI_SRC + ' AND user IS NOT NULL AND length(user) > 0 GROUP BY user ORDER BY total DESC LIMIT 100', params: [Date.now() - hours * 3600000] }
  ], aiOpts('top-users', hours));
  if (!r.ok) return offloadFail(res, r);
  return res.json({ hours: hours, users: r.results[0], count: r.results[0].length, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /zia/ai/top-sites — all AI hostnames in use ──
router.get('/zia/ai/top-sites', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var r = await offload.query(AI_DB_PATH, [
    { sql: 'SELECT host, app, COUNT(*) total, COUNT(DISTINCT user) users, ' + AI_BLOCKED + ' blocked' +
           AI_SRC + ' AND host IS NOT NULL AND length(host) > 0 GROUP BY host ORDER BY total DESC LIMIT 100', params: [Date.now() - hours * 3600000] }
  ], aiOpts('top-sites', hours));
  if (!r.ok) return offloadFail(res, r);
  return res.json({ hours: hours, sites: r.results[0], count: r.results[0].length, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /zia/ai/by-dept ──
router.get('/zia/ai/by-dept', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var r = await offload.query(AI_DB_PATH, [
    { sql: "SELECT COALESCE(NULLIF(department, ''), '(unknown)') dept, COUNT(*) total, COUNT(DISTINCT user) users, COUNT(DISTINCT app) apps" +
           AI_SRC + ' GROUP BY dept ORDER BY total DESC LIMIT 40', params: [Date.now() - hours * 3600000] }
  ], aiOpts('by-dept', hours));
  if (!r.ok) return offloadFail(res, r);
  return res.json({ hours: hours, departments: r.results[0], count: r.results[0].length, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /zia/ai/trends — hourly (<=48h) or daily buckets per top app ──
router.get('/zia/ai/trends', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var since = Date.now() - hours * 3600000;
  var bucket = hours <= 48 ? 3600000 : 86400000;
  var r = await offload.query(AI_DB_PATH, [
    { sql: 'SELECT (ts / ' + bucket + ') b, app, COUNT(*) c' + AI_SRC + ' AND app IS NOT NULL AND length(app) > 0 GROUP BY b, app', params: [since] },
    { sql: 'SELECT app, COUNT(*) c' + AI_SRC + ' AND app IS NOT NULL AND length(app) > 0 GROUP BY app ORDER BY c DESC LIMIT 6', params: [since] }
  ], aiOpts('trends', hours));
  if (!r.ok) return offloadFail(res, r);
  var topApps = r.results[1].map(function (x) { return x.app; });
  var buckets = {};
  r.results[0].forEach(function (x) {
    var t = x.b * bucket;
    if (!buckets[t]) { buckets[t] = { ts: t }; topApps.forEach(function (a) { buckets[t][a] = 0; }); }
    if (topApps.indexOf(x.app) >= 0) buckets[t][x.app] = x.c;
  });
  return res.json({ hours: hours, bucketMs: bucket, apps: topApps,
    series: Object.values(buckets).sort(function (a, b) { return a.ts - b.ts; }), tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /zia/ai/detail — drill to raw events (not cached; filters are free-form) ──
// LIKE wildcards in the action filter are escaped so a caller cannot widen
// the match beyond a substring.
function likeEscape(s) { return String(s).replace(/[\\%_]/g, '\\$&'); }
router.get('/zia/ai/detail', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var where = ['ts >= ?']; var args = [Date.now() - hours * 3600000];
  if (req.query.user)   { where.push('user = ?'); args.push(String(req.query.user)); }
  if (req.query.app)    { where.push('app = ?');  args.push(String(req.query.app)); }
  if (req.query.host)   { where.push('host = ?'); args.push(String(req.query.host)); }
  if (req.query.action) { where.push("action LIKE ? ESCAPE '\\'"); args.push('%' + likeEscape(req.query.action) + '%'); }
  var r = await offload.query(AI_DB_PATH, [
    { sql: 'SELECT ts,user,app,host,url,url_category,action,reason,device,department,client_ip,req_method,resp_code,req_size ' +
           'FROM ai_events WHERE ' + where.join(' AND ') + ' ORDER BY ts DESC LIMIT 500', params: args }
  ], { timeoutMs: 30000, label: 'AI detail (' + hours + 'h)' });
  if (!r.ok) return offloadFail(res, r);
  return res.json({ hours: hours, count: r.results[0].length, events: r.results[0] });
}));
// ═══ end CC-AI-USAGE v1.1 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-AI-SHADOW v1.0 — unsanctioned AI detection
// usage apps (ai_events) MINUS policy-governed apps (ZIA AI_ML rules).
// Matcher QA'd 24/24 against live tenant names.
// ═══════════════════════════════════════════════════════════════════
function aiNorm(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, ''); }
function aiIsGoverned(usageApp, policyNorms) {
  var u = aiNorm(usageApp);
  if (u.length < 3) return false;
  for (var i = 0; i < policyNorms.length; i++) {
    var q = policyNorms[i];
    if (q.length < 3) continue;
    if (u.indexOf(q) >= 0 || q.indexOf(u) >= 0) return true;
  }
  return false;
}
var aiPolicyCache = { norms: null, apps: null, exp: 0 };
async function aiGetPolicyApps() {
  if (aiPolicyCache.norms && Date.now() < aiPolicyCache.exp) return aiPolicyCache;
  var r = await oneapiGet('/zia/api/v1/webApplicationRules/AI_ML');
  if (r.status !== 200) throw new Error('AI_ML rules HTTP ' + r.status);
  var rules = asList(r.body);
  var set = {};
  rules.forEach(function (x) { (x.applications || []).forEach(function (a) { set[a] = true; }); });
  var apps = Object.keys(set);
  aiPolicyCache = { apps: apps, norms: apps.map(aiNorm), exp: Date.now() + 15 * 60 * 1000 };
  return aiPolicyCache;
}

// ── /zia/ai/unsanctioned — shadow AI apps + who is using them ──
// The per-app rollup and the top-5 users per app (a window function, one pass)
// run in one worker while the ZIA policy list is fetched; a policy failure is
// answered as 502 (upstream), not 500. Cached results are shared, so the
// per-app decoration is built on copies.
router.get('/zia/ai/unsanctioned', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var since = Date.now() - hours * 3600000;
  var work = await Promise.all([
    offload.query(AI_DB_PATH, [
      { sql: 'SELECT app, COUNT(*) total, COUNT(DISTINCT user) users, COUNT(DISTINCT host) sites, ' + AI_BLOCKED + ' blocked, ' +
             'MIN(ts) first_seen, MAX(ts) last_seen' + AI_SRC + ' AND app IS NOT NULL AND length(app) > 0 GROUP BY app ORDER BY total DESC', params: [since] },
      { sql: 'SELECT app, user, c FROM (SELECT app, user, COUNT(*) c, ROW_NUMBER() OVER (PARTITION BY app ORDER BY COUNT(*) DESC, user) rn' +
             AI_SRC + ' AND app IS NOT NULL AND length(app) > 0 GROUP BY app, user) WHERE rn <= 5 ORDER BY app, c DESC', params: [since] }
    ], aiOpts('unsanctioned', hours)),
    aiGetPolicyApps().then(function (pol) { return { ok: true, pol: pol }; }, function (e) { return { ok: false, error: e.message }; })
  ]);
  var r = work[0], p = work[1];
  if (!r.ok) return offloadFail(res, r);
  if (!p.ok) return res.status(502).json({ error: 'ZIA AI_ML policy unavailable: ' + p.error });
  var uMap = {};
  r.results[1].forEach(function (x) { (uMap[x.app] = uMap[x.app] || []).push({ user: x.user, count: x.c }); });
  var unsanctioned = [], governed = [];
  r.results[0].forEach(function (a) {
    if (aiIsGoverned(a.app, p.pol.norms)) { governed.push({ app: a.app, total: a.total, users: a.users }); return; }
    var cs = aiCatLib.sanctionOfSync(a.app);
    unsanctioned.push(Object.assign({}, a, { topUsers: uMap[a.app] || [], catalog_status: cs ? cs.status : null }));
  });
  return res.json({
    hours: hours, policyApps: p.pol.apps.length,
    unsanctioned: unsanctioned, unsanctionedCount: unsanctioned.length,
    governed: governed, governedCount: governed.length,
    tookMs: r.tookMs, cachedAt: r.cachedAt || null
  });
}));
// ═══ end CC-AI-SHADOW v1.1 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-AI-REPORT-CFG v1.0 — Gen AI report scheduling API
// ═══════════════════════════════════════════════════════════════════
const requireWrite = rbac.requirePage('zscaler-diag', 'admin');
const { spawn } = require('child_process');

router.get('/zia/ai/report-config', requireRead, async function (req, res) {
  try {
    const [[cfg]] = await rbacPool.query('SELECT * FROM ai_report_config WHERE id=1');
    if (!cfg) return res.status(404).json({ error: 'no config row (seed the ai_report_config table)' });
    return res.json(cfg);
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

router.post('/zia/ai/report-config', requireWrite, express.json(), async function (req, res) {
  try {
    const b = req.body || {};
    const allowed = ['enabled', 'recipients', 'frequency', 'send_hour_utc', 'send_dow', 'send_dom', 'window_hours', 'include_governed'];
    const fields = [], vals = [];
    for (const k of allowed) if (b[k] !== undefined) { fields.push('`' + k + '`=?'); vals.push(b[k]); }
    if (!fields.length) return res.status(400).json({ error: 'no valid fields provided' });
    fields.push('updated_by=?'); vals.push((req.user && (req.user.email || req.user.upn)) || 'unknown');
    vals.push(1);
    await rbacPool.query('UPDATE ai_report_config SET ' + fields.join(', ') + ' WHERE id=?', vals);
    const [[cfg]] = await rbacPool.query('SELECT * FROM ai_report_config WHERE id=1');
    return res.json(cfg);
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

router.post('/zia/ai/report-send', requireWrite, function (req, res) {
  const proc = spawn('/usr/bin/node', ['/var/www/corpit-hub-api/ai-report-send.js', '--now'], { cwd: '/var/www/corpit-hub-api', detached: true, stdio: 'ignore' });
  proc.unref();
  return res.json({ triggered: true, pid: proc.pid });
});
// ═══ end CC-AI-REPORT-CFG v1.0 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-AI-EXT v1.0 — Extended AI intelligence:
//   shadow-domains · dlp-crossref · anomalies · clients · oauth-grants
// ═══════════════════════════════════════════════════════════════════
const { hostMatchesAI: aiExtHostMatch } = require('/var/www/corpit-hub-api/ai-domains.js');

// ── /zia/ai/shadow-domains — apps caught by DOMAIN_MATCH only ──
// Both cuts read ix_ai_source (detection_source, ts); the top-5 users per host
// is one window-function pass instead of a second query over the host list.
router.get('/zia/ai/shadow-domains', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var since = Date.now() - hours * 3600000;
  var src = " FROM ai_events INDEXED BY ix_ai_source WHERE detection_source = 'DOMAIN_MATCH' AND ts >= ?";
  var r = await offload.query(AI_DB_PATH, [
    { sql: 'SELECT host, app, url_category, COUNT(*) total, COUNT(DISTINCT user) users, MIN(ts) first_seen, MAX(ts) last_seen, ' + AI_BLOCKED + ' blocked' +
           src + ' AND length(host) > 0 GROUP BY host ORDER BY total DESC LIMIT 100', params: [since] },
    { sql: 'SELECT host, user, c FROM (SELECT host, user, COUNT(*) c, ROW_NUMBER() OVER (PARTITION BY host ORDER BY COUNT(*) DESC, user) rn' +
           src + ' AND length(host) > 0 AND length(user) > 0 GROUP BY host, user) WHERE rn <= 5 ORDER BY host, c DESC', params: [since] }
  ], aiOpts('shadow-domains', hours));
  if (!r.ok) return offloadFail(res, r);
  var uMap = {};
  r.results[1].forEach(function (x) { (uMap[x.host] = uMap[x.host] || []).push({ user: x.user, count: x.c }); });
  var hosts = r.results[0].map(function (h) { return Object.assign({}, h, { topUsers: uMap[h.host] || [] }); });
  return res.json({ hours: hours, hosts: hosts, count: hosts.length, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /zia/ai/dlp-crossref — DLP incidents involving AI apps ──
router.get('/zia/ai/dlp-crossref', requireRead, async function (req, res) {
  try {
    var days = Math.min(parseInt(req.query.days, 10) || 30, 365);
    var et = new Date(), st = new Date(Date.now() - days * 86400000);
    var t;
    try { t = await zwaToken(); }
    catch (e) { if (e.code === 'NOKEYS') return res.status(501).json({ error: e.message }); throw e; }
    var doSearch = function (tok) {
      return httpsRequest(new URL(ZWA_BASE + '/dlp/v1/incidents/search'),
        { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': 'itam-command-center/2.0' } },
        JSON.stringify({ timeRange: { startTime: st.toISOString(), endTime: et.toISOString() } }));
    };
    var r = await doSearch(t);
    if (r.status === 401) { t = await zwaToken(true); r = await doSearch(t); }
    if (r.status !== 200) return res.status(502).json({ error: 'ZWA search HTTP ' + r.status });
    var b = r.body || {};
    var list = Array.isArray(b.data) ? b.data : (Array.isArray(b.incidents) ? b.incidents : asList(b));
    // AI-only cross-ref: incidents touching AI apps/domains
    function mapInc(i) {
      return {
        id: i.id || i.internalId, txId: i.transactionId, createdAt: i.createdAt,
        user: i.userInfo && i.userInfo.email, department: i.userInfo && i.userInfo.department,
        app: i.applicationInfo && (i.applicationInfo.hostnameOrApplication || i.applicationInfo.name),
        url: i.applicationInfo && i.applicationInfo.url,
        severity: i.severity, status: i.status,
        dictionaries: (i.matchingPolicies && i.matchingPolicies.dictionaries || []).map(function (d) { return d.name; }),
        rules: (i.matchingPolicies && i.matchingPolicies.rules || []).map(function (d) { return d.name; })
      };
    }
    function agg(src, fn) {
      var m = {};
      src.forEach(function (i) { var k = fn(i) || '(unknown)'; m[k] = (m[k] || 0) + 1; });
      return Object.keys(m).map(function (k) { return { key: k, count: m[k] }; }).sort(function (a, b) { return b.count - a.count; });
    }
    var pol = await aiGetPolicyApps();
    var aiIncidents = list.filter(function (i) {
      var appInfo = i.applicationInfo || {};
      var host = appInfo.url || appInfo.hostnameOrApplication || '';
      var appName = appInfo.name || appInfo.hostnameOrApplication || '';
      return aiExtHostMatch(host) || (appName && aiIsGoverned(appName, pol.norms));
    });
    return res.json({
      days: days,
      total_incidents: list.length,
      ai_incidents_count: aiIncidents.length,
      by_user: agg(aiIncidents, function (i) { return i.userInfo && i.userInfo.email; }),
      by_ai_app: agg(aiIncidents, function (i) { return i.applicationInfo && (i.applicationInfo.hostnameOrApplication || i.applicationInfo.name); }),
      by_dictionary: agg(aiIncidents, function (i) { return i.matchingPolicies && i.matchingPolicies.dictionaries && i.matchingPolicies.dictionaries[0] && i.matchingPolicies.dictionaries[0].name; }),
      by_severity: agg(aiIncidents, function (i) { return i.severity; }),
      incidents: aiIncidents.slice(0, 100).map(mapInc)
    });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});

// ── /zia/ai/anomalies — first-time users, spikes, off-hours, new apps ──
// Five statements in one worker, cached 5 min per window. The volume-spike
// baseline is one grouped query over the baseline period instead of a COUNT
// per user in the window (396 round trips at 30d). Windows past 30 days are
// refused: the baseline is 3x the window and the five passes already take
// ~15s cold at 30 days (2026-09-23).
var AI_ANOMALY_MAX_DAYS = 30;
router.get('/zia/ai/anomalies', requireRead, guarded(async function (req, res) {
  var days = parseInt(req.query.days, 10) || 7;
  if (days > AI_ANOMALY_MAX_DAYS) return res.status(400).json({ error: 'The ' + days + '-day anomaly window is not available on this host: it scans three times the window for a baseline. Choose 30 days or shorter.' });
  if (days < 1) days = 7;
  var missing = dbMissing(AI_DB_PATH, AI_MISSING); if (missing) return res.status(503).json({ error: missing });
  var now = Date.now(), winSince = now - days * 86400000, baseSince = now - days * 3 * 86400000;
  var r = await offload.query(AI_DB_PATH, [
    // First-time users: appear in window, never in baseline
    { sql: 'SELECT user, COUNT(*) c, COUNT(DISTINCT app) apps, MIN(ts) first_seen' + AI_SRC + ' AND length(user) > 0 AND user NOT IN ' +
           '(SELECT DISTINCT user FROM ai_events INDEXED BY ix_ai_ts WHERE ts < ? AND ts >= ? AND length(user) > 0) GROUP BY user ORDER BY c DESC LIMIT 50', params: [winSince, winSince, baseSince] },
    // Volume spikes: window count vs baseline daily average, per user
    { sql: 'SELECT user, COUNT(*) c' + AI_SRC + ' AND length(user) > 0 GROUP BY user', params: [winSince] },
    { sql: 'SELECT user, COUNT(*) c' + AI_SRC + ' AND ts < ? AND length(user) > 0 GROUP BY user', params: [baseSince, winSince] },
    // Off-hours (before 6am or after 10pm UTC, or a weekend — approximate regardless of TZ)
    { sql: 'SELECT user, COUNT(*) total, SUM(CASE WHEN CAST(strftime(\'%H\', ts / 1000, \'unixepoch\') AS INTEGER) < 6 ' +
           'OR CAST(strftime(\'%H\', ts / 1000, \'unixepoch\') AS INTEGER) >= 22 ' +
           'OR CAST(strftime(\'%w\', ts / 1000, \'unixepoch\') AS INTEGER) IN (0, 6) THEN 1 ELSE 0 END) offhours' +
           AI_SRC + ' AND length(user) > 0 GROUP BY user HAVING offhours > 5 AND (offhours * 100 / total) > 30 ORDER BY offhours DESC LIMIT 30', params: [winSince] },
    // New apps: first seen in the window
    { sql: 'SELECT app, MIN(ts) first_seen, COUNT(*) c, COUNT(DISTINCT user) users' + AI_SRC + ' AND length(app) > 0 AND app NOT IN ' +
           '(SELECT DISTINCT app FROM ai_events INDEXED BY ix_ai_ts WHERE ts < ? AND ts >= ? AND length(app) > 0) GROUP BY app ORDER BY c DESC LIMIT 30', params: [winSince, winSince, baseSince] }
  ], { cacheKey: 'ai:anomalies:' + days, cacheTtlMs: 300000, timeoutMs: 60000, label: 'AI anomalies (' + days + 'd)' });
  if (!r.ok) return offloadFail(res, r);
  var base = {}; r.results[2].forEach(function (x) { base[x.user] = x.c; });
  var basePeriodDays = days * 2, spikes = [];
  r.results[1].forEach(function (w) {
    var baseDaily = (base[w.user] || 0) / basePeriodDays, winDaily = w.c / days;
    if (baseDaily > 0 && winDaily > baseDaily * 3 && w.c > 20) {
      spikes.push({ user: w.user, window_count: w.c, window_daily: Math.round(winDaily), baseline_daily: Math.round(baseDaily * 10) / 10, ratio: Math.round(winDaily / baseDaily * 10) / 10 });
    }
  });
  spikes.sort(function (a, b) { return b.ratio - a.ratio; });
  return res.json({ days: days, first_time_users: r.results[0], volume_spikes: spikes.slice(0, 30), off_hours_users: r.results[3], new_apps: r.results[4],
    tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /zia/ai/clients — UA-based AI client detection ──
// One grouped pass (user_agent, user, app) through ix_ai_ts; the signature
// match stays in JS because the catalog patterns are regular expressions.
router.get('/zia/ai/clients', requireRead, guarded(async function (req, res) {
  var hours = aiWindow(req, res); if (!hours) return;
  var sigs = aiCatLib.uaSigsSync(); // catalog-backed UA signatures (ai_catalog.ua_patterns), legacy fallback inside lib
  var r = await offload.query(AI_DB_PATH, [
    { sql: 'SELECT user_agent, user, app, COUNT(*) c' + AI_SRC + ' AND length(user_agent) > 0 GROUP BY user_agent, user, app', params: [Date.now() - hours * 3600000] }
  ], aiOpts('clients', hours));
  if (!r.ok) return offloadFail(res, r);
  var byClient = {}, samples = {};
  r.results[0].forEach(function (x) {
    var matched = null;
    for (var i = 0; i < sigs.length; i++) { if (sigs[i].re.test(x.user_agent)) { matched = sigs[i].name; break; } }
    if (!matched) return;
    var c = byClient[matched] = byClient[matched] || { client: matched, total: 0, users: {}, apps: {} };
    c.total += x.c;
    if (x.user) c.users[x.user] = (c.users[x.user] || 0) + x.c;
    if (x.app) c.apps[x.app] = (c.apps[x.app] || 0) + x.c;
    if (!samples[matched]) samples[matched] = x.user_agent;
  });
  var clients = Object.values(byClient).map(function (c) {
    return {
      client: c.client, total: c.total, ua_sample: samples[c.client],
      user_count: Object.keys(c.users).length,
      top_users: Object.keys(c.users).map(function (u) { return { user: u, c: c.users[u] }; }).sort(function (a, b) { return b.c - a.c; }).slice(0, 5),
      top_apps: Object.keys(c.apps).map(function (a) { return { app: a, c: c.apps[a] }; }).sort(function (a, b) { return b.c - a.c; }).slice(0, 5)
    };
  }).sort(function (a, b) { return b.total - a.total; });
  return res.json({ hours: hours, clients: clients, count: clients.length, tookMs: r.tookMs, cachedAt: r.cachedAt || null });
}));

// ── /entra/ai-oauth-grants — Enterprise-app grants to AI vendors ──
function graphTokenAiExt() {
  var T = process.env.AZURE_TENANT_ID || process.env.ENTRA_TENANT_ID;
  var C = process.env.AZURE_CLIENT_ID || process.env.ENTRA_CLIENT_ID;
  var S = process.env.AZURE_CLIENT_SECRET || process.env.ENTRA_CLIENT_SECRET;
  if (!T || !C || !S) return Promise.reject(new Error('AZURE_*/ENTRA_* creds missing'));
  var body = 'client_id=' + C + '&client_secret=' + encodeURIComponent(S) + '&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&grant_type=client_credentials';
  return httpsRequest(new URL('https://login.microsoftonline.com/' + T + '/oauth2/v2.0/token'),
    { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, body)
    .then(function (r) { var j = typeof r.body === 'string' ? JSON.parse(r.body) : r.body; if (!j.access_token) throw new Error('graph token failed'); return j.access_token; });
}
function graphGet(tok, path) {
  return httpsRequest(new URL('https://graph.microsoft.com/v1.0' + path),
    { method: 'GET', headers: { Authorization: 'Bearer ' + tok, Accept: 'application/json' }, timeoutMs: 30000 })
    .then(function (r) { return typeof r.body === 'string' ? JSON.parse(r.body) : r.body; });
}
// AI vendor keyword matchers for servicePrincipal displayName/publisher
function isAiSp(sp) {
  var s = ((sp.displayName || '') + ' ' + (sp.publisherName || '') + ' ' + (sp.appDisplayName || '')).toLowerCase();
  return !!aiCatLib.matchSpTextSync(s); // catalog-backed (ai_catalog), legacy keyword fallback inside lib
}
router.get('/entra/ai-oauth-grants', requireRead, async function (req, res) {
  try {
    var tok = await graphTokenAiExt();
    // Page through servicePrincipals, filter AI
    var aiSps = {}; var next = "/servicePrincipals?$select=id,displayName,publisherName,appDisplayName,appId&$top=999";
    var pages = 0, MAX = 10;
    while (next && pages < MAX) {
      var j = await graphGet(tok, next);
      (j.value || []).forEach(function (sp) { if (isAiSp(sp)) aiSps[sp.id] = sp; });
      next = j['@odata.nextLink'] ? j['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null;
      pages++;
    }
    var aiSpIds = Object.keys(aiSps);
    // Now grants
    var grants = []; var gNext = "/oauth2PermissionGrants?$top=999"; var gPages = 0;
    while (gNext && gPages < MAX) {
      var gj = await graphGet(tok, gNext);
      (gj.value || []).forEach(function (g) { if (aiSps[g.clientId]) grants.push(g); });
      gNext = gj['@odata.nextLink'] ? gj['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null;
      gPages++;
    }
    // Resolve principalId → user email (batch — collect unique)
    var userIds = {}; grants.forEach(function (g) { if (g.principalId) userIds[g.principalId] = true; });
    var userMap = {};
    var ids = Object.keys(userIds).slice(0, 200);
    for (var i = 0; i < ids.length; i += 20) {
      var chunk = ids.slice(i, i + 20);
      try {
        var ur = await httpsRequest(new URL('https://graph.microsoft.com/v1.0/directoryObjects/getByIds'),
          { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' } },
          JSON.stringify({ ids: chunk, types: ['user'] }));
        var uj = typeof ur.body === 'string' ? JSON.parse(ur.body) : ur.body;
        (uj.value || []).forEach(function (u) { userMap[u.id] = u.userPrincipalName || u.mail || u.displayName; });
      } catch (e) { /* skip failed lookups */ }
    }
    var result = grants.map(function (g) {
      var sp = aiSps[g.clientId] || {};
      return {
        grantId: g.id, appName: sp.displayName, publisher: sp.publisherName, appId: sp.appId,
        principalId: g.principalId, user: userMap[g.principalId] || g.principalId, consentType: g.consentType,
        scope: g.scope, expiryTime: g.expiryTime, startTime: g.startTime
      };
    }).sort(function (a, b) { return (a.appName || '').localeCompare(b.appName || ''); });
    return res.json({ ai_service_principals: aiSpIds.length, grants: result, count: result.length });
  } catch (e) { return res.status(500).json({ error: e.message }); }
});
// ═══ end CC-AI-EXT v1.0 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-AI-PDF v1.0 — Gen AI tab export → PDF (pdfkit, generic sections)
// POST /zia/ai/export/pdf  body: {title, meta, sections:[{title,cols[],rows[[]]}]}
// Client sends the same section data used for CSV; server just renders.
// ═══════════════════════════════════════════════════════════════════
router.post('/zia/ai/export/pdf', requireRead, express.json({ limit: '3mb' }), function (req, res) {
  var PDFDocument;
  try { PDFDocument = require('pdfkit'); }
  catch (e) { return res.status(501).json({ error: 'pdfkit not installed' }); }
  try {
    var b = req.body || {};
    var sections = Array.isArray(b.sections) ? b.sections.slice(0, 12) : [];
    if (!sections.length) return res.status(400).json({ error: 'no sections' });
    var title = String(b.title || 'Gen AI Security').slice(0, 120);
    var meta = String(b.meta || '').slice(0, 200);

    var doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: 36, info: { Title: title } });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="' + title.replace(/[^A-Za-z0-9_-]+/g, '-').toLowerCase() + '.pdf"');
    doc.pipe(res);

    var W = doc.page.width - 72; // usable width
    // header band
    doc.rect(36, 36, W, 46).fill('#0A1628');
    doc.fill('#FFFFFF').font('Helvetica-Bold').fontSize(15).text(title, 48, 46);
    doc.fill('#94a3b8').font('Helvetica').fontSize(8.5).text('Auction.com · ' + meta + ' · generated ' + new Date().toUTCString(), 48, 66);
    doc.y = 96;

    function cell(v) { v = v == null ? '' : String(v); return v.length > 300 ? v.slice(0, 297) + '…' : v; }
    function ensureRoom(need) { if (doc.y + need > doc.page.height - 40) { doc.addPage(); doc.y = 40; } }

    sections.forEach(function (sec) {
      var cols = (sec.cols || []).slice(0, 12).map(cell);
      var rows = (sec.rows || []).slice(0, 500);
      if (!cols.length) return;
      ensureRoom(50);
      doc.fill('#0A1628').font('Helvetica-Bold').fontSize(11).text(cell(sec.title || ''), 36, doc.y + 6);
      doc.moveDown(0.4);
      // column widths: proportional to header+sample content length, min 40
      var weights = cols.map(function (c, i) {
        var m = c.length;
        rows.slice(0, 20).forEach(function (r) { var L = String(r[i] == null ? '' : r[i]).length; if (L > m) m = L; });
        return Math.min(Math.max(m, 6), 60);
      });
      var tw = weights.reduce(function (a, x) { return a + x; }, 0);
      var widths = weights.map(function (x) { return Math.max(40, x / tw * W); });
      var sw = widths.reduce(function (a, x) { return a + x; }, 0);
      if (sw > W) { var k = W / sw; widths = widths.map(function (x) { return x * k; }); }

      function drawRow(vals, isHead, zebra) {
        var pad = 3, x = 36, y0 = doc.y;
        doc.font(isHead ? 'Helvetica-Bold' : 'Helvetica').fontSize(isHead ? 7.5 : 7.5);
        var h = 10;
        vals.forEach(function (v, i) {
          var hh = doc.heightOfString(cell(v), { width: widths[i] - pad * 2 });
          if (hh + pad * 2 > h) h = hh + pad * 2;
        });
        h = Math.min(h, 60);
        ensureRoom(h + 2);
        y0 = doc.y;
        if (isHead) { doc.rect(36, y0, sw, h).fill('#E2E8F0'); }
        else if (zebra) { doc.rect(36, y0, sw, h).fill('#F8FAFC'); }
        doc.fill(isHead ? '#0A1628' : '#111827');
        vals.forEach(function (v, i) {
          doc.text(cell(v), x + pad, y0 + pad, { width: widths[i] - pad * 2, height: h - pad, ellipsis: true });
          x += widths[i];
        });
        doc.moveTo(36, y0 + h).lineTo(36 + sw, y0 + h).strokeColor('#D1D5DB').lineWidth(0.5).stroke();
        doc.y = y0 + h;
      }
      drawRow(cols, true, false);
      rows.forEach(function (r, ri) { drawRow(cols.map(function (_, i) { return r[i]; }), false, ri % 2 === 1); });
      doc.y += 14;
    });
    doc.end();
  } catch (e) {
    if (!res.headersSent) return res.status(500).json({ error: e.message });
    try { res.end(); } catch (x) {}
  }
});
// ═══ end CC-AI-PDF v1.0 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-V3-CORE v1.0 — Saved Views · ZCC Installer Versions · Diagnostics ·
// Report Center (schedules/runs/run-now + in-process scheduler)
// Appended after module.exports — same router object, routes still register.
// ═══════════════════════════════════════════════════════════════════
(function () {
  const fsV3 = require('fs');
  const cpV3 = require('child_process');
  const v3Read = rbac.requirePage('zscaler-diag', 'read');
  const v3Admin = rbac.requirePage('zscaler-diag', 'admin');
  const v3User = req => (req.user && (req.user.email || req.user.upn)) || 'unknown';

  /* ── Saved Views ── */
  router.get('/cc/views', v3Read, async (req, res) => {
    try {
      const [rows] = await rbacPool.query(
        'SELECT id, owner_email, name, view_key, qs, shared, created_at FROM cc_saved_views WHERE owner_email=? OR shared=1 ORDER BY created_at DESC LIMIT 200',
        [v3User(req)]);
      res.json({ views: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  router.post('/cc/views', v3Read, express.json(), async (req, res) => {
    try {
      const b = req.body || {};
      if (!b.name || !b.view_key) return res.status(400).json({ error: 'name and view_key required' });
      await rbacPool.query('INSERT INTO cc_saved_views (owner_email, name, view_key, qs, shared) VALUES (?,?,?,?,?)',
        [v3User(req), String(b.name).slice(0, 120), String(b.view_key).slice(0, 60), String(b.qs || '').slice(0, 2000), b.shared ? 1 : 0]);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  router.delete('/cc/views/:id', v3Read, async (req, res) => {
    try {
      const [r] = await rbacPool.query('DELETE FROM cc_saved_views WHERE id=? AND owner_email=?', [req.params.id, v3User(req)]);
      res.json({ ok: true, deleted: r.affectedRows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  /* ── ZCC installer versions ── */
  router.get('/zcc/app-versions', v3Read, async (req, res) => {
    try {
      const [rows] = await rbacPool.query('SELECT platform, version, download_url, notes, source, updated_by, updated_at FROM zcc_app_versions ORDER BY platform');
      res.json({ versions: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  router.post('/zcc/app-versions', v3Admin, express.json(), async (req, res) => {
    try {
      const b = req.body || {};
      if (!b.platform || !b.version || !b.download_url) return res.status(400).json({ error: 'platform, version, download_url required' });
      await rbacPool.query(
        'INSERT INTO zcc_app_versions (platform, version, download_url, notes, source, updated_by) VALUES (?,?,?,?,?,?) ' +
        'ON DUPLICATE KEY UPDATE version=VALUES(version), download_url=VALUES(download_url), notes=VALUES(notes), source=VALUES(source), updated_by=VALUES(updated_by)',
        [String(b.platform).toLowerCase().slice(0, 20), String(b.version).slice(0, 60), String(b.download_url).slice(0, 1000),
         String(b.notes || '').slice(0, 300), 'manual', v3User(req)]);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  /* ── Diagnostics ── */
  function v3Exec(cmd, args) {
    return new Promise(resolve => {
      try {
        cpV3.execFile(cmd, args, { timeout: 8000, maxBuffer: 4 * 1024 * 1024 }, (err, so) => resolve(err ? null : String(so)));
      } catch (e) { resolve(null); }
    });
  }
  async function v3Pm2() {
    const cands = ['pm2', '/usr/local/bin/pm2', '/home/ubuntu/.npm-global/bin/pm2', '/usr/bin/pm2'];
    for (const c of cands) {
      const out = await v3Exec(c, ['jlist']);
      if (out) { try { const j = JSON.parse(out); if (Array.isArray(j)) return j; } catch (e) {} }
    }
    return null;
  }
  router.get('/cc/diagnostics', v3Read, async (req, res) => {
    const out = { at: new Date().toISOString() };
    try {
      const dbs = [
        { name: 'lss.db', path: process.env.LSS_DB || '/var/www/corpit-hub-api/data/lss.db' },
        { name: 'nss.db', path: process.env.NSS_DB || '/var/www/corpit-hub-api/data/nss.db' },
        { name: 'ai.db', path: process.env.AI_NSS_DB || '/var/www/corpit-hub-api/data/ai.db' }
      ];
      out.sqlite = dbs.map(d => {
        try { const s = fsV3.statSync(d.path); return { name: d.name, mb: +(s.size / 1048576).toFixed(1), lastWrite: s.mtime.toISOString() }; }
        catch (e) { return { name: d.name, error: 'not found' }; }
      });
    } catch (e) { out.sqlite = { error: e.message }; }
    try {
      const df = await v3Exec('df', ['-k', '/']);
      if (df) {
        const L = df.trim().split('\n').pop().split(/\s+/);
        out.disk = { totalGB: +(L[1] / 1048576).toFixed(1), usedGB: +(L[2] / 1048576).toFixed(1), availGB: +(L[3] / 1048576).toFixed(1), usePct: L[4] };
      }
    } catch (e) {}
    try {
      const pm2 = await v3Pm2();
      if (pm2) out.pm2 = pm2.map(p => ({
        name: p.name, status: p.pm2_env && p.pm2_env.status, restarts: p.pm2_env && p.pm2_env.restart_time,
        uptimeMs: p.pm2_env && p.pm2_env.pm_uptime ? Date.now() - p.pm2_env.pm_uptime : null,
        memMB: p.monit ? +(p.monit.memory / 1048576).toFixed(1) : null, cpu: p.monit ? p.monit.cpu : null
      }));
      else out.pm2 = { error: 'pm2 jlist unavailable from service context' };
    } catch (e) { out.pm2 = { error: e.message }; }
    try {
      const [rows] = await rbacPool.query(
        "SELECT table_schema s, ROUND(SUM(data_length+index_length)/1048576,1) mb FROM information_schema.tables WHERE table_schema IN ('it_inventory','corpit_hub') GROUP BY table_schema");
      out.mysql = rows;
    } catch (e) { out.mysql = { error: e.message }; }
    try {
      const m = process.memoryUsage();
      out.apiBeta = { heapMB: +(m.heapUsed / 1048576).toFixed(1), rssMB: +(m.rss / 1048576).toFixed(1), uptimeH: +(process.uptime() / 3600).toFixed(1), node: process.version };
    } catch (e) {}
    res.json(out);
  });

  /* ── Report Center ── */
  const V3_TEMPLATES = [
    { key: 'dlp_weekly', label: 'DLP Weekly Summary', desc: 'ZWA incident volume + rule-forwarding coverage + gap list' },
    { key: 'genai_summary', label: 'Gen AI Usage Summary', desc: 'AI transaction volume, distinct users, top apps (ai.db)' },
    { key: 'connector_health', label: 'ZPA Connector Health', desc: 'Fleet status, versions, drift, last heartbeat' },
    { key: 'exec_summary', label: 'Executive Security Rollup', desc: 'DLP + Gen AI + connector posture, one PDF' }
  ];
  router.get('/cc/report/templates', v3Read, (req, res) => res.json({ templates: V3_TEMPLATES }));

  router.get('/cc/report/schedules', v3Read, async (req, res) => {
    try { const [rows] = await rbacPool.query('SELECT * FROM cc_report_schedules ORDER BY id'); res.json({ schedules: rows }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });
  router.post('/cc/report/schedules', v3Admin, express.json(), async (req, res) => {
    try {
      const b = req.body || {};
      if (!b.template_key || !b.recipients) return res.status(400).json({ error: 'template_key and recipients required' });
      if (b.id) {
        await rbacPool.query(
          'UPDATE cc_report_schedules SET template_key=?, label=?, recipients=?, cadence=?, send_hour_utc=?, send_dow=?, send_dom=?, window_hours=?, enabled=? WHERE id=?',
          [b.template_key, String(b.label || b.template_key).slice(0, 160), String(b.recipients).slice(0, 2000),
           b.cadence || 'weekly', +b.send_hour_utc || 14, +b.send_dow || 1, +b.send_dom || 1, +b.window_hours || 168, b.enabled ? 1 : 0, +b.id]);
      } else {
        await rbacPool.query(
          'INSERT INTO cc_report_schedules (template_key, label, recipients, cadence, send_hour_utc, send_dow, send_dom, window_hours, enabled, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)',
          [b.template_key, String(b.label || b.template_key).slice(0, 160), String(b.recipients).slice(0, 2000),
           b.cadence || 'weekly', +b.send_hour_utc || 14, +b.send_dow || 1, +b.send_dom || 1, +b.window_hours || 168,
           b.enabled === false ? 0 : 1, v3User(req)]);
      }
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  router.delete('/cc/report/schedules/:id', v3Admin, async (req, res) => {
    try { await rbacPool.query('DELETE FROM cc_report_schedules WHERE id=?', [req.params.id]); res.json({ ok: true }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });
  router.get('/cc/report/runs', v3Read, async (req, res) => {
    try { const [rows] = await rbacPool.query('SELECT * FROM cc_report_runs ORDER BY ran_at DESC LIMIT 100'); res.json({ runs: rows }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  function v3SpawnRunner(schedId, by) {
    const env = Object.assign({}, process.env, { CC_RUN_BY: by || 'scheduler' });
    const p = cpV3.spawn('/usr/bin/node', ['/var/www/corpit-hub-api/cc-report-runner.js', '--schedule', String(schedId)],
      { cwd: '/var/www/corpit-hub-api', detached: true, stdio: 'ignore', env });
    p.unref();
    return p.pid;
  }
  router.post('/cc/report/run-now/:id', v3Admin, (req, res) => {
    try { res.json({ triggered: true, pid: v3SpawnRunner(req.params.id, v3User(req)) }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  /* ── In-process scheduler: every 5 min, fire due schedules ── */
  if (!global.__CCV3_SCHED) {
    global.__CCV3_SCHED = setInterval(async function () {
      try {
        const now = new Date();
        const [rows] = await rbacPool.query('SELECT * FROM cc_report_schedules WHERE enabled=1');
        for (const s of rows) {
          if (now.getUTCHours() !== s.send_hour_utc) continue;
          if (s.cadence === 'weekly' && now.getUTCDay() !== s.send_dow) continue;
          if (s.cadence === 'monthly' && now.getUTCDate() !== s.send_dom) continue;
          const minGapH = s.cadence === 'daily' ? 20 : s.cadence === 'weekly' ? 144 : 648;
          if (s.last_run && (now - new Date(s.last_run)) < minGapH * 3600000) continue;
          console.log('[cc-v3-sched] firing schedule ' + s.id + ' (' + s.template_key + ')');
          v3SpawnRunner(s.id, 'scheduler');
        }
      } catch (e) { console.warn('[cc-v3-sched]', e.message); }
    }, 5 * 60 * 1000);
    if (global.__CCV3_SCHED.unref) global.__CCV3_SCHED.unref();
  }
  console.log('[zscaler-diag] CC-V3-CORE v1.0 routes registered');
})();
// ═══ end CC-V3-CORE v1.0 ═══

// ═══════════════════════════════════════════════════════════════════
// CC-AICAT v1.0 — AI Catalog · Watchlist · Investigation · Feed Health
// Appended after CC-V3-CORE — same router object, routes still register.
// Uses module-scope: router, rbac, rbacPool, express, aiOpen, aiHours,
// aiNorm, aiIsGoverned, aiGetPolicyApps, oneapiGet, asList, httpsRequest,
// zwaToken, ZWA_BASE, aiExtHostMatch, graphTokenAiExt, graphGet, isAiSp.
// ═══════════════════════════════════════════════════════════════════
(function () {
  var aiCatRead = rbac.requirePage('zscaler-diag', 'read');
  var aiCatAdmin = rbac.requirePage('zscaler-diag', 'admin');
  var aiCatJson = express.json({ limit: '1mb' });
  var aiCatMod = require('./ai-catalog-lib');
  function aiWho(req) { return (req.user && (req.user.email || req.user.upn)) || 'unknown'; }
  function aiBlockedSql() { return "SUM(CASE WHEN action LIKE '%lock%' OR action LIKE '%eny%' OR action LIKE '%rop%' THEN 1 ELSE 0 END)"; }

  /* ── Catalog ── */
  router.get('/zia/ai/catalog', aiCatRead, async function (req, res) {
    try {
      var out = await rbacPool.query('SELECT * FROM ai_catalog ORDER BY retired, app_name');
      res.json({ rows: out[0], count: out[0].length, live_cache: aiCatMod.fromDb() });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  router.post('/zia/ai/catalog', aiCatAdmin, aiCatJson, async function (req, res) {
    try {
      var b = req.body || {};
      var who = aiWho(req);
      var st = ['sanctioned', 'unsanctioned', 'review', 'blocked'].indexOf(b.sanction_status) >= 0 ? b.sanction_status : 'review';
      if (b.id) {
        await rbacPool.query(
          'UPDATE ai_catalog SET sanction_status=?, category=COALESCE(?,category), risk_note=COALESCE(?,risk_note), aliases=COALESCE(?,aliases), domains=COALESCE(?,domains), ua_patterns=COALESCE(?,ua_patterns), retired=COALESCE(?,retired), updated_by=? WHERE id=?',
          [st, b.category || null, b.risk_note || null, b.aliases || null, b.domains || null, b.ua_patterns || null, (b.retired === 0 || b.retired === 1) ? b.retired : null, who, parseInt(b.id, 10)]);
      } else {
        if (!b.app_name || String(b.app_name).trim().length < 2) return res.status(400).json({ error: 'app_name required' });
        var nk = aiCatMod.norm(b.app_name);
        if (nk.length < 3) return res.status(400).json({ error: 'app_name too short after normalization' });
        await rbacPool.query(
          'INSERT INTO ai_catalog (app_name, norm_key, aliases, domains, ua_patterns, category, sanction_status, risk_note, source, created_by, updated_by) VALUES (?,?,?,?,?,?,?,?,\'manual\',?,?) ' +
          'ON DUPLICATE KEY UPDATE sanction_status=VALUES(sanction_status), risk_note=COALESCE(VALUES(risk_note),risk_note), retired=0, updated_by=VALUES(updated_by)',
          [String(b.app_name).trim(), nk, b.aliases || null, b.domains || null, b.ua_patterns || null, b.category || null, st, b.risk_note || null, who, who]);
      }
      await aiCatMod.refresh();
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Import apps referenced by live ZIA AI_ML policy rules as source='zscaler'.
  // ?probe=1 returns a cloudApplications/lite sample so the full-catalog import
  // can be schema-mapped later without guessing field names.
  router.post('/zia/ai/catalog/import-zscaler', aiCatAdmin, aiCatJson, async function (req, res) {
    try {
      if (req.query.probe) {
        var pr = await oneapiGet('/zia/api/v1/cloudApplications/lite?pageSize=5');
        return res.json({ status: pr.status, sample: asList(pr.body).slice(0, 3) });
      }
      var pol = await aiGetPolicyApps();
      var who = aiWho(req);
      var added = 0, seen = 0;
      for (var i = 0; i < pol.apps.length; i++) {
        var name = pol.apps[i];
        var nk = aiCatMod.norm(name);
        if (nk.length < 3) continue;
        seen++;
        var r = await rbacPool.query(
          'INSERT IGNORE INTO ai_catalog (app_name, norm_key, category, sanction_status, source, risk_note, created_by, updated_by) VALUES (?,?,?,\'sanctioned\',\'zscaler\',\'Imported: referenced by a live ZIA AI_ML policy rule.\',?,?)',
          [name, nk, 'zscaler-policy', who, who]);
        if (r[0] && r[0].affectedRows) added++;
      }
      await rbacPool.query('INSERT INTO ai_alert_state (k, v) VALUES (\'last_zscaler_import\', ?) ON DUPLICATE KEY UPDATE v=VALUES(v)', [new Date().toISOString()]);
      await aiCatMod.refresh();
      res.json({ ok: true, policy_apps: seen, added: added });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  /* ── Watchlist ── */
  router.get('/zia/ai/watchlist', aiCatRead, async function (req, res) {
    try {
      var out = await rbacPool.query('SELECT * FROM ai_watchlist ORDER BY FIELD(status,\'open\',\'monitoring\',\'closed\'), updated_at DESC LIMIT 300');
      res.json({ rows: out[0], count: out[0].length });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  router.post('/zia/ai/watchlist', aiCatAdmin, aiCatJson, async function (req, res) {
    try {
      var b = req.body || {};
      var who = aiWho(req);
      if (b.id) {
        var st = ['open', 'monitoring', 'closed'].indexOf(b.status) >= 0 ? b.status : null;
        await rbacPool.query(
          'UPDATE ai_watchlist SET status=COALESCE(?,status), assignee=COALESCE(?,assignee), notes=COALESCE(?,notes), updated_by=?, closed_at=IF(COALESCE(?,status)=\'closed\', COALESCE(closed_at, NOW()), NULL) WHERE id=?',
          [st, b.assignee || null, (typeof b.notes === 'string') ? b.notes : null, who, st, parseInt(b.id, 10)]);
        return res.json({ ok: true });
      }
      var ty = ['user', 'app', 'host'].indexOf(b.subject_type) >= 0 ? b.subject_type : null;
      var subj = String(b.subject || '').trim();
      if (!ty || !subj) return res.status(400).json({ error: 'subject and subject_type (user|app|host) required' });
      await rbacPool.query(
        'INSERT INTO ai_watchlist (subject, subject_type, status, notes, created_by, updated_by) VALUES (?,?,\'open\',?,?,?) ' +
        'ON DUPLICATE KEY UPDATE status=\'open\', closed_at=NULL, notes=COALESCE(VALUES(notes),notes), updated_by=VALUES(updated_by)',
        [subj, ty, (typeof b.notes === 'string') ? b.notes : null, who, who]);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  /* ── Feed health (ai.db liveness — stale-data guard for the whole workspace) ── */
  // Three index-only reads in a worker, cached 30s: this is polled by every
  // AI workspace tab.
  router.get('/zia/ai/feed-health', aiCatRead, guarded(async function (req, res) {
    var missing = dbMissing(AI_DB_PATH, AI_MISSING); if (missing) return res.json({ ok: false, reason: missing });
    var now = Date.now();
    var r = await offload.query(AI_DB_PATH, [
      { sql: 'SELECT MAX(ts) t FROM ai_events', mode: 'get' },
      { sql: 'SELECT COUNT(*) c' + AI_SRC, params: [now - 3600000], mode: 'get' },
      { sql: 'SELECT COUNT(*) c' + AI_SRC, params: [now - 86400000], mode: 'get' }
    ], { cacheKey: 'ai:feed-health', cacheTtlMs: 30000, timeoutMs: 15000, label: 'AI feed health' });
    if (!r.ok) return res.json({ ok: false, reason: r.error });
    var sz = 0;
    try { sz = require('fs').statSync(AI_DB_PATH).size; } catch (e) {}
    var lastTs = (r.results[0] && r.results[0].t) || 0;
    var lagMin = lastTs ? Math.round((now - lastTs) / 60000) : null;
    res.json({
      ok: true, last_event_ts: lastTs, lag_minutes: lagMin,
      events_1h: r.results[1].c, events_24h: r.results[2].c, db_bytes: sz,
      state: lagMin == null ? 'empty' : (lagMin <= 15 ? 'live' : (lagMin <= 60 ? 'slow' : 'stale')),
      catalog_live: aiCatMod.fromDb()
    });
  }));

  /* ── Cached Entra OAuth grants (mirrors /entra/ai-oauth-grants, 15-min TTL)
        so the per-user investigation doesn't re-page Graph on every open. ── */
  var aiGrantsCache = { data: null, exp: 0, err: null };
  async function aiGrantsCached() {
    if (aiGrantsCache.data && Date.now() < aiGrantsCache.exp) return aiGrantsCache.data;
    try {
      var tok = await graphTokenAiExt();
      var aiSps = {}; var next = "/servicePrincipals?$select=id,displayName,publisherName,appDisplayName,appId&$top=999";
      var pages = 0, MAX = 10;
      while (next && pages < MAX) {
        var j = await graphGet(tok, next);
        (j.value || []).forEach(function (sp) { if (isAiSp(sp)) aiSps[sp.id] = sp; });
        next = j['@odata.nextLink'] ? j['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null;
        pages++;
      }
      var grants = []; var gNext = "/oauth2PermissionGrants?$top=999"; var gPages = 0;
      while (gNext && gPages < MAX) {
        var gj = await graphGet(tok, gNext);
        (gj.value || []).forEach(function (g) { if (aiSps[g.clientId]) grants.push(g); });
        gNext = gj['@odata.nextLink'] ? gj['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null;
        gPages++;
      }
      var userIds = {}; grants.forEach(function (g) { if (g.principalId) userIds[g.principalId] = true; });
      var userMap = {};
      var ids = Object.keys(userIds).slice(0, 200);
      for (var i = 0; i < ids.length; i += 20) {
        var chunk = ids.slice(i, i + 20);
        try {
          var ur = await httpsRequest(new URL('https://graph.microsoft.com/v1.0/directoryObjects/getByIds'),
            { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' } },
            JSON.stringify({ ids: chunk, types: ['user'] }));
          var uj = typeof ur.body === 'string' ? JSON.parse(ur.body) : ur.body;
          (uj.value || []).forEach(function (u) { userMap[u.id] = u.userPrincipalName || u.mail || u.displayName; });
        } catch (e) { /* skip failed lookups */ }
      }
      var result = grants.map(function (g) {
        var sp = aiSps[g.clientId] || {};
        return { appName: sp.displayName, publisher: sp.publisherName, user: userMap[g.principalId] || g.principalId, consentType: g.consentType, scope: g.scope };
      });
      aiGrantsCache = { data: result, exp: Date.now() + 15 * 60 * 1000, err: null };
      return result;
    } catch (e) {
      aiGrantsCache.err = e.message;
      if (aiGrantsCache.data) return aiGrantsCache.data; // stale better than nothing
      throw e;
    }
  }

  /* ── Investigation composite — one call assembles the whole evidence pack ── */
  router.get('/zia/ai/investigate', aiCatRead, async function (req, res) {
    var user = String(req.query.user || '').trim();
    if (!user) return res.status(400).json({ error: 'user required' });
    var hours = aiWindow(req, res); if (!hours) return;
    var out = { user: user, hours: hours };
    // Six reads on one worker connection through ix_ai_user (user, ts); not
    // cached, an investigation wants the live picture.
    var since = Date.now() - hours * 3600000;
    var src = ' FROM ai_events INDEXED BY ix_ai_user WHERE user = ? AND ts >= ?';
    var r = await offload.query(AI_DB_PATH, [
      { sql: 'SELECT COUNT(*) total, COUNT(DISTINCT app) apps, COUNT(DISTINCT host) hosts, ' + aiBlockedSql() + ' blocked, ' +
             'SUM(COALESCE(req_size, 0)) up_bytes, MIN(ts) first_seen, MAX(ts) last_seen' + src, params: [user, since], mode: 'get' },
      { sql: "SELECT department FROM ai_events INDEXED BY ix_ai_user WHERE user = ? AND length(COALESCE(department, '')) > 0 ORDER BY ts DESC LIMIT 1", params: [user], mode: 'get' },
      { sql: "SELECT location FROM ai_events INDEXED BY ix_ai_user WHERE user = ? AND length(COALESCE(location, '')) > 0 ORDER BY ts DESC LIMIT 1", params: [user], mode: 'get' },
      { sql: 'SELECT app, COUNT(*) c, ' + aiBlockedSql() + ' blocked, SUM(COALESCE(req_size, 0)) bytes, MIN(ts) first_seen, MAX(ts) last_seen' + src +
             ' AND app IS NOT NULL AND length(app) > 0 GROUP BY app ORDER BY c DESC', params: [user, since] },
      { sql: 'SELECT host, COUNT(*) c, ' + aiBlockedSql() + ' blocked, SUM(COALESCE(req_size, 0)) bytes, MAX(detection_source) detection_source' + src +
             " AND length(COALESCE(host, '')) > 0 GROUP BY host ORDER BY c DESC LIMIT 30", params: [user, since] },
      { sql: 'SELECT ts, app, host, url, action, url_category, req_method, req_size, user_agent, device, client_ip, detection_source' + src +
             ' ORDER BY ts DESC LIMIT 300', params: [user, since] }
    ], { timeoutMs: 30000, label: 'AI investigate' });
    if (!r.ok) return res.status(r.status || 500).json({ error: 'ai.db: ' + r.error });
    out.summary = r.results[0] || {};
    out.summary.department = r.results[1] ? r.results[1].department : null;
    out.summary.location = r.results[2] ? r.results[2].location : null;
    out.apps = r.results[3]; out.hosts = r.results[4]; out.events = r.results[5];

    // Sanction status + governance per app
    try {
      var pol = null;
      try { pol = await aiGetPolicyApps(); } catch (e) { pol = null; }
      out.apps.forEach(function (a) {
        var s = aiCatMod.sanctionOfSync(a.app);
        a.catalog_status = s ? s.status : null;
        a.governed = pol ? aiIsGoverned(a.app, pol.norms) : null;
      });
    } catch (e) { /* enrichment optional */ }

    // Desktop clients seen for this user
    try {
      var sigs = aiCatMod.uaSigsSync();
      var seen = {};
      out.events.forEach(function (e) {
        if (!e.user_agent) return;
        for (var i = 0; i < sigs.length; i++) { if (sigs[i].re.test(e.user_agent)) { seen[sigs[i].name] = (seen[sigs[i].name] || 0) + 1; break; } }
      });
      out.clients = Object.keys(seen).map(function (k) { return { client: k, c: seen[k] }; }).sort(function (a, b) { return b.c - a.c; });
    } catch (e) { out.clients = []; }

    // Watch status
    try {
      var wr = await rbacPool.query('SELECT * FROM ai_watchlist WHERE subject_type=\'user\' AND subject=? LIMIT 1', [user]);
      out.watch = wr[0][0] || null;
    } catch (e) { out.watch = null; }

    // Entra OAuth grants for this user (cached fetch, graceful)
    try {
      var grants = await aiGrantsCached();
      var lu = user.toLowerCase();
      out.oauth = { grants: grants.filter(function (g) { return String(g.user || '').toLowerCase() === lu; }), cached: true };
    } catch (e) { out.oauth = { error: e.message }; }

    // DLP × AI incidents for this user (ZWA, graceful; window capped at 30d)
    try {
      var days = Math.min(Math.max(1, Math.round(aiHours(req) / 24)), 30);
      var et = new Date(), st2 = new Date(Date.now() - days * 86400000);
      var t = await zwaToken();
      var doSearch = function (tok) {
        return httpsRequest(new URL(ZWA_BASE + '/dlp/v1/incidents/search'),
          { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': 'itam-command-center/3.0' } },
          JSON.stringify({ timeRange: { startTime: st2.toISOString(), endTime: et.toISOString() } }));
      };
      var r2 = await doSearch(t);
      if (r2.status === 401) { t = await zwaToken(true); r2 = await doSearch(t); }
      if (r2.status !== 200) { out.dlp = { error: 'ZWA HTTP ' + r2.status }; }
      else {
        var b2 = r2.body || {};
        var list = Array.isArray(b2.data) ? b2.data : (Array.isArray(b2.incidents) ? b2.incidents : asList(b2));
        var lu2 = user.toLowerCase();
        var mine = list.filter(function (i) { return String((i.userInfo && i.userInfo.email) || '').toLowerCase() === lu2; });
        var polN = null; try { polN = await aiGetPolicyApps(); } catch (e) { polN = { norms: [] }; }
        var mineAi = mine.filter(function (i) {
          var ap = i.applicationInfo || {};
          var host = ap.url || ap.hostnameOrApplication || '';
          var nm = ap.name || ap.hostnameOrApplication || '';
          return aiExtHostMatch(host) || (nm && aiIsGoverned(nm, polN.norms)) || !!aiCatMod.sanctionOfSync(nm);
        });
        out.dlp = {
          days: days, user_incidents: mine.length, ai_incidents: mineAi.length,
          incidents: mineAi.slice(0, 25).map(function (i) {
            return {
              createdAt: i.createdAt, severity: i.severity, status: i.status,
              app: i.applicationInfo && (i.applicationInfo.hostnameOrApplication || i.applicationInfo.name),
              dictionaries: (i.matchingPolicies && i.matchingPolicies.dictionaries || []).map(function (d) { return d.name; }),
              rules: (i.matchingPolicies && i.matchingPolicies.rules || []).map(function (d) { return d.name; })
            };
          })
        };
      }
    } catch (e) { out.dlp = { error: (e.code === 'NOKEYS') ? 'ZWA keys not configured' : e.message }; }

    return res.json(out);
  });

  console.log('[zscaler-diag] CC-AICAT v1.0 routes registered (catalog/watchlist/investigate/feed-health)');
})();
// ═══ end CC-AICAT v1.0 ═══

// ═══ CC-ZPA-OBSERVED-ACCESS v1.0 ═══
// "Who actually reaches this segment", to sit beside the policy model's
// "who is allowed to". Served entirely from the precomputed aggregate that
// zpa-observed-access-job.js writes nightly — a request must NEVER scan
// lss.db (17M rows / ~5.6GB, ~53s per pass, and cold scans took the box
// down on 2026-08-14).
(function () {
  const fsOA = require('fs');
  const OA_PATH = process.env.ZPA_OBS_OUT || '/var/www/corpit-hub-api/data/zpa-observed-access.json';
  const OA_STALE_HOURS = parseInt(process.env.ZPA_OBS_STALE_HOURS || '36', 10);
  let oaCache = { mtimeMs: 0, data: null };

  function oaLoad() {
    let st;
    try { st = fsOA.statSync(OA_PATH); }
    catch (e) {
      return { err: 'no aggregate yet at ' + OA_PATH + ' — zpa-observed-access-job.js has not run' };
    }
    if (oaCache.data && oaCache.mtimeMs === st.mtimeMs) return { data: oaCache.data, st };
    try {
      const data = JSON.parse(fsOA.readFileSync(OA_PATH, 'utf8'));
      oaCache = { mtimeMs: st.mtimeMs, data };
      return { data, st };
    } catch (e) {
      return { err: 'aggregate unreadable: ' + e.message };
    }
  }

  // GET /api/zscaler/zpa/observed-access[?app=NAME][&top=N]
  router.get('/zpa/observed-access', requireRead, function (req, res) {
    const h = oaLoad();
    // Degrade to an empty-but-valid payload rather than an error: the caller
    // renders the policy half regardless, and a spinner that never resolves
    // is worse than a visible "no data yet" (see CC Attack Surface, CC-audit).
    if (h.err) {
      return res.json({
        available: false, reason: h.err,
        window: null, totals: null, byApp: {},
      });
    }
    const d = h.data;
    const ageMs = Date.now() - (d.generatedAt || h.st.mtimeMs);
    const base = {
      available: true,
      generatedAt: d.generatedAt,
      ageHours: +(ageMs / 3600000).toFixed(1),
      stale: ageMs > OA_STALE_HOURS * 3600000,
      source: d.source,
      window: d.window,
      topN: d.topN,
      totals: d.totals,
    };

    const one = req.query.app;
    if (one) {
      const hit = d.byApp[one];
      return res.json(Object.assign(base, {
        app: one,
        found: !!hit,
        activity: hit || null,
      }));
    }

    // Optional narrowing of the per-segment user list; the file is built at
    // topN=10, so this can only shrink it.
    const top = parseInt(req.query.top, 10);
    let byApp = d.byApp;
    if (top > 0 && top < (d.topN || 10)) {
      byApp = {};
      for (const k of Object.keys(d.byApp)) {
        byApp[k] = Object.assign({}, d.byApp[k], { top: d.byApp[k].top.slice(0, top) });
      }
    }
    return res.json(Object.assign(base, { apps: Object.keys(byApp).length, byApp }));
  });

  // POST /api/zscaler/zpa/observed-access/refresh — detached rebuild.
  // Deliberately does not await: the scan is ~53s and would block the event
  // loop for every other route on this process.
  router.post('/zpa/observed-access/refresh', rbac.requirePage('zscaler-diag', 'admin'), function (req, res) {
    const { spawn } = require('child_process');
    try {
      const days = String(Math.max(1, Math.min(parseInt(req.query.days, 10) || 14, 90)));
      const child = spawn('nice', [
        '-n', '19', 'ionice', '-c3',
        process.execPath, '/var/www/corpit-hub-api/zpa-observed-access-job.js',
        '--days', days,
      ], { cwd: '/var/www/corpit-hub-api', detached: true, stdio: 'ignore' });
      child.unref();
      return res.json({ ok: true, started: true, days: +days, note: 'rebuild runs detached, ~1 min; re-GET observed-access for the new generatedAt' });
    } catch (e) {
      return res.status(500).json({ ok: false, error: e.message });
    }
  });

  console.log('[zscaler-diag] CC-ZPA-OBSERVED-ACCESS v1.0 routes registered (observed-access, refresh)');
})();
// ═══ end CC-ZPA-OBSERVED-ACCESS v1.0 ═══

// ═══════════════════════════════════════════════════════════════════════════
// CC-ZPADIAG v1.1 — ZPA Connection Diagnostics drill-down (from lss.db)
// Mirrors the ZPA admin portal's Diagnostics view: outcome counters plus a
// per-connection record table, filterable by app segment and/or username.
//
//   GET /zpa/diag/facets       dropdown sources (app segments, users, ...)
//   GET /zpa/diag/connections  counters + paged connection rows
//   GET /zpa/diag/connection   the full record trail for one ConnectionID
//
// v1.1: every lss.db read moved into lss-query-worker.js (a worker thread).
// better-sqlite3 is synchronous and this table is ~9.5GB / 29M rows — a
// filtered 30-day drill-down measured 27.9s, which on the main thread is 27.9s
// of api-beta serving nothing at all, for every page on the site. The worker
// also owns the scan-budget pre-count that refuses oversized windows outright.
//
// Read-only throughout: the worker opens lss.db with readonly:true.
//
// Field availability: Policy / Service Edge / ports / device fields arrive with
// lss-receiver v2.1 (2026-08-27). Rows streamed before that are still listed,
// but report those columns as null so the UI can label them rather than render
// a blank that reads as "no policy matched".
// ═══════════════════════════════════════════════════════════════════════════
(function () {
  var WorkerThreads;
  try { WorkerThreads = require('worker_threads'); }
  catch (e) { console.error('[zscaler-diag] CC-ZPADIAG disabled — worker_threads unavailable:', e.message); return; }

  var WORKER_PATH = require('path').join(__dirname, 'lss-query-worker.js');
  var SCAN_BUDGET = parseInt(process.env.ZPADIAG_SCAN_BUDGET, 10) || 400000;
  var JOB_TIMEOUT_MS = parseInt(process.env.ZPADIAG_TIMEOUT_MS, 10) || 60000;
  var MAX_INFLIGHT = parseInt(process.env.ZPADIAG_MAX_INFLIGHT, 10) || 3;
  var inFlight = 0;

  // One worker per request. The pooled alternative buys ~40ms of startup back
  // on jobs that run for seconds, and costs stuck-slot and respawn-loop bugs.
  function runJob(job, args) {
    return new Promise(function (resolve) {
      if (inFlight >= MAX_INFLIGHT) {
        return resolve({ ok: false, status: 429, error: 'Diagnostics queries are saturated (' + MAX_INFLIGHT + ' running). Try again in a moment.' });
      }
      inFlight++;
      var w = null, done = false, timer = null, released = false;
      // Releasing the slot and answering the client are two different events.
      // terminate() cannot interrupt better-sqlite3: it is parked in a native
      // sqlite3_step loop and V8 termination only lands when the isolate
      // re-enters JS. So a timed-out worker keeps doing random I/O over a 9.5GB
      // file. Decrementing inFlight at timeout would let MAX_INFLIGHT admit a
      // replacement while the old thread is still running, and the cap would
      // stop bounding anything. The slot is therefore held until 'exit'.
      function release() {
        if (released) return;
        released = true;
        inFlight--;
      }
      function finish(v) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (w) { try { w.terminate(); } catch (e) {} }   // best effort; may not land
        resolve(v);
      }
      try {
        w = new WorkerThreads.Worker(WORKER_PATH, { workerData: { dbPath: LSS_DB_PATH, scanBudget: SCAN_BUDGET } });
      } catch (e) { release(); return resolve({ ok: false, status: 503, error: e.message }); }
      timer = setTimeout(function () {
        finish({ ok: false, status: 504, error: 'Query exceeded ' + Math.round(JOB_TIMEOUT_MS / 1000) + 's and was cancelled. Narrow the window or add a filter.' });
      }, JOB_TIMEOUT_MS);
      w.on('message', function (m) {
        if (m && m.ready) { w.postMessage({ id: 1, job: job, args: args }); return; }
        finish(m || { ok: false, error: 'empty worker reply' });
      });
      w.on('error', function (e) { release(); finish({ ok: false, status: 500, error: e.message }); });
      w.on('exit', function (c) {
        release();   // the thread is genuinely gone — only now is the slot free
        finish({ ok: false, status: 500, error: 'worker exited (' + c + ')' });
      });
    });
  }

  // Shared reply handling: worker refusals become 400s carrying their guidance.
  function reply(res, r, extra) {
    if (!r.ok) return res.status(r.status || 500).json({ error: r.error });
    if (r.result && r.result.over) return res.status(400).json(Object.assign(r.result.over, extra || {}));
    return res.json(Object.assign({}, r.result, extra || {}));
  }

  // Windows the UI offers, in hours. Anything else clamps to 2h — the default
  // the ZPA portal's own Diagnostics view opens with.
  var WINDOWS = [1, 2, 8, 24, 72, 168, 720];
  function winHours(req) {
    var h = parseInt(req.query.hours, 10);
    return WINDOWS.indexOf(h) === -1 ? 2 : h;
  }

  // Only these columns have an index that can serve an equality filter
  // (ix_conns_user / ix_conns_app / ix_conns_conn). Everything else degrades to
  // a scan of the ts window, which changes how the request must be budgeted.
  var INDEXED_FILTERS = { user: 1, app: 1, connector: 1 };

  // Equality filters the caller may set: query param -> column.
  var EQ_FILTERS = {
    user: 'user', app: 'app', appgroup: 'appgroup', host: 'host',
    policy: 'policy', connector: 'connector', edge: 'client_zen',
    status: 'status', reason: 'internal_reason', platform: 'platform',
    hostname: 'hostname', client_ip: 'client_ip', server_ip: 'server_ip'
  };

  function buildWhere(req) {
    var hours = winHours(req);
    var since = Date.now() - hours * 3600000;
    var where = ['ts >= ?'], params = [since], active = [], allIndexed = true;
    Object.keys(EQ_FILTERS).forEach(function (k) {
      var v = req.query[k];
      if (v === undefined || v === null || String(v).trim() === '') return;
      where.push('c.' + EQ_FILTERS[k] + ' = ?');
      params.push(String(v).trim());
      active.push(k);
      if (!INDEXED_FILTERS[k]) allIndexed = false;
    });
    // Free-text contains-match over the fields an operator would actually type.
    var q = String(req.query.q || '').trim();
    if (q) {
      where.push('(c.user LIKE ? OR c.app LIKE ? OR c.host LIKE ? OR c.hostname LIKE ? OR c.client_ip LIKE ? OR c.server_ip LIKE ?)');
      for (var i = 0; i < 6; i++) params.push('%' + q + '%');
      active.push('q');
      allIndexed = false;   // no index serves a leading-wildcard LIKE
    }
    return {
      sql: where.join(' AND '), params: params, hours: hours, since: since, active: active,
      // What to budget against: the real scan size. With only index-served
      // filters that is the filtered count; otherwise it is the whole window.
      budgetWhere: allIndexed ? where.join(' AND ') : 'ts >= ?',
      budgetParams: allIndexed ? params : [since],
      allIndexed: allIndexed
    };
  }

  // ── GET /zpa/diag/facets?hours=24 ──
  // Populates the searchable dropdowns. Counts come from the same window the
  // table uses, so an empty dropdown genuinely means "no traffic in window".
  // Cached briefly: the dropdowns barely move between refreshes, and the scan
  // behind them is the most expensive thing this feature does.
  var facetCache = {};
  var FACET_TTL_MS = 60000;

  router.get('/zpa/diag/facets', requireRead, async function (req, res) {
    var hours = winHours(req);
    var hit = facetCache[hours];
    if (hit && Date.now() - hit.at < FACET_TTL_MS) {
      return res.json(Object.assign({}, hit.payload, { cached: true, ageMs: Date.now() - hit.at }));
    }
    var r = await runJob('facets', { hours: hours, since: Date.now() - hours * 3600000 });
    if (r.ok && r.result && !r.result.over) facetCache[hours] = { at: Date.now(), payload: r.result };
    return reply(res, r);
  });

  // ── GET /zpa/diag/connections ──
  // Filters: user, app, appgroup, host, policy, connector, edge, status,
  //          reason, platform, hostname, client_ip, server_ip, q, outcome
  // Paging:  hours, limit (<=500), offset
  router.get('/zpa/diag/connections', requireRead, async function (req, res) {
    var w = buildWhere(req);
    var limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
    var offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    var outcome = String(req.query.outcome || '').trim();
    var r = await runJob('connections', {
      where: w.sql, params: w.params, outcome: outcome, limit: limit, offset: offset,
      budgetWhere: w.budgetWhere, budgetParams: w.budgetParams
    });
    var extra = { hours: w.hours, since: w.since, filters: w.active, outcome: outcome || null, limit: limit, offset: offset };
    if (r.ok && r.result && r.result.counters) {
      extra.matched = outcome ? (r.result.counters[outcome] || 0) : r.result.counters.total;
    }
    return reply(res, r, extra);
  });

  // ── GET /zpa/diag/connection?cid=<ConnectionID>&hours=24 ──
  // The full open -> active -> close record trail behind one table row.
  router.get('/zpa/diag/connection', requireRead, async function (req, res) {
    var cid = String(req.query.cid || '').trim();
    if (!cid) return res.status(400).json({ error: 'cid query param required' });
    var hours = winHours(req);
    // ts is the clicked row's timestamp; it bounds the scan to that one
    // connection's lifetime instead of the whole browsing window.
    var ts = parseInt(req.query.ts, 10);
    var r = await runJob('connection', {
      cid: cid,
      since: Date.now() - hours * 3600000,
      ts: (!isNaN(ts) && ts > 0) ? ts : null
    });
    return reply(res, r, { hours: hours });
  });

  console.log('[zscaler-diag] CC-ZPADIAG v1.1 routes registered (worker-backed: diag/facets, diag/connections, diag/connection)');
})();
// ═══ end CC-ZPADIAG v1.1 ═══

// ═══════════════════════════════════════════════════════════════════════════
// CC-ZFULL v1.0 — full-surface read coverage for ZPA / ZIA / ZCC
// Added 2026-08-27. Everything here is READ-ONLY; the API client is bound to
// read-only roles on ZPA and ZIA (see the ZIdentity API-client Resources tab),
// so a write route would 403 anyway. Write support is deliberately deferred
// until there is a preview + confirm + audit path to put behind it.
//
// Every endpoint below was probed live before being written — all 41 returned
// 200 under the current role. Endpoints that 403 for us (ZPA service edges,
// provisioning keys, PRA portals/console) are intentionally ABSENT rather than
// shipped as controls that cannot work.
//
// Shape: { items, count, fromCache, fetchedAt } for lists,
//        { item,  fromCache, fetchedAt }        for singleton config objects.
// ═══════════════════════════════════════════════════════════════════════════
(function () {
  var ZF_TTL_MS = parseInt(process.env.ZFULL_CACHE_MS, 10) || 300000;   // 5 min
  var zfCache = Object.create(null);

  function zfGet(key) {
    var e = zfCache[key];
    if (!e) return null;
    if (Date.now() - e.at > ZF_TTL_MS) { delete zfCache[key]; return null; }
    return e;
  }
  function zfPut(key, payload) { zfCache[key] = { at: Date.now(), payload: payload }; return payload; }

  var CID = function () { return process.env.ZPA_CUSTOMER_ID; };
  function zpaPath(ver, tail) { return '/zpa/mgmtconfig/' + ver + '/admin/customers/' + CID() + '/' + tail; }

  // ── the table ────────────────────────────────────────────────────────────
  // kind: 'list' -> array (or {list:[]}) response;  'object' -> singleton config
  var ZFULL = [
    // ZPA · identity & trust
    { route: 'zpa/posture-profiles',    path: function () { return zpaPath('v2', 'posture'); },          kind: 'list' },
    { route: 'zpa/trusted-networks',    path: function () { return zpaPath('v2', 'network'); },          kind: 'list' },
    { route: 'zpa/saml-attributes',     path: function () { return zpaPath('v2', 'samlAttribute'); },    kind: 'list' },
    { route: 'zpa/idps',                path: function () { return zpaPath('v2', 'idp'); },              kind: 'list' },
    { route: 'zpa/ba-certificates',     path: function () { return zpaPath('v1', 'certificate'); },      kind: 'list' },
    { route: 'zpa/service-edge-groups', path: function () { return zpaPath('v1', 'serviceEdgeGroup'); }, kind: 'list' },
    { route: 'zpa/isolation-profiles',  path: function () { return zpaPath('v1', 'isolation/profiles'); },kind: 'list' },
    { route: 'zpa/inspection-profiles', path: function () { return zpaPath('v1', 'inspectionProfile'); },kind: 'list' },

    // ZIA · threat & inspection
    { route: 'zia/ips-rules',            path: '/zia/api/v1/firewallIpsRules',    kind: 'list' },
    { route: 'zia/dns-rules',            path: '/zia/api/v1/firewallDnsRules',    kind: 'list' },
    { route: 'zia/ssl-inspection-rules', path: '/zia/api/v1/sslInspectionRules',  kind: 'list' },
    { route: 'zia/sandbox-rules',        path: '/zia/api/v1/sandboxRules',        kind: 'list' },
    { route: 'zia/atp-settings',         path: '/zia/api/v1/cyberThreatProtection/advancedThreatSettings', kind: 'object' },

    // ZIA · policy objects
    { route: 'zia/url-categories',        path: '/zia/api/v1/urlCategories?includeOnlyUrlKeywordCounts=true', kind: 'list' },
    { route: 'zia/network-services',      path: '/zia/api/v1/networkServices',          kind: 'list' },
    { route: 'zia/network-service-groups',path: '/zia/api/v1/networkServiceGroups',     kind: 'list' },
    { route: 'zia/network-applications',  path: '/zia/api/v1/networkApplications',      kind: 'list' },
    { route: 'zia/network-app-groups',    path: '/zia/api/v1/networkApplicationGroups', kind: 'list' },
    { route: 'zia/time-intervals',        path: '/zia/api/v1/timeIntervals',            kind: 'list' },
    { route: 'zia/rule-labels',           path: '/zia/api/v1/ruleLabels',               kind: 'list' },
    { route: 'zia/device-groups',         path: '/zia/api/v1/deviceGroups',             kind: 'list' },
    { route: 'zia/workload-groups',       path: '/zia/api/v1/workloadGroups',           kind: 'list' },

    // ZIA · infrastructure
    { route: 'zia/locations',         path: '/zia/api/v1/locations',        kind: 'list' },
    { route: 'zia/location-groups',   path: '/zia/api/v1/locations/groups', kind: 'list' },
    { route: 'zia/gre-tunnels',       path: '/zia/api/v1/greTunnels',       kind: 'list' },
    { route: 'zia/static-ips',        path: '/zia/api/v1/staticIP',         kind: 'list' },
    { route: 'zia/vpn-credentials',   path: '/zia/api/v1/vpnCredentials',   kind: 'list' },
    { route: 'zia/activation-status', path: '/zia/api/v1/status',           kind: 'object' },

    // ZCC
    { route: 'zcc/web-policies',   path: '/zcc/papi/public/v1/web/policy/listByCompany', kind: 'list' },
    { route: 'zcc/device-cleanup', path: '/zcc/papi/public/v1/getDeviceCleanupInfo',     kind: 'object' },
    { route: 'zcc/admin-sync',     path: '/zcc/papi/public/v1/getAdminUsersSyncInfo',    kind: 'object' },
    { route: 'zcc/company-info',   path: '/zcc/papi/public/v1/getCompanyInfo',           kind: 'object' }
  ];

  ZFULL.forEach(function (spec) {
    router.get('/' + spec.route, requireRead, async function (req, res) {
      var key = spec.route;
      if (!req.query.refresh) {
        var hit = zfGet(key);
        if (hit) return res.json(Object.assign({}, hit.payload, { fromCache: true, ageMs: Date.now() - hit.at }));
      }
      try {
        var path = typeof spec.path === 'function' ? spec.path() : spec.path;
        var r = await oneapiGet(path);
        if (r.status !== 200) {
          return res.status(502).json({ error: spec.route + ' upstream HTTP ' + r.status, upstreamStatus: r.status });
        }
        var body = typeof r.body === 'string' ? (function () { try { return JSON.parse(r.body); } catch (e) { return null; } })() : r.body;
        var payload;
        if (spec.kind === 'list') {
          var items = asList(body);
          payload = { items: items, count: items.length, fetchedAt: Date.now() };
        } else {
          // A 200 with a null body is a real answer: the object is not configured
          // in this tenant (ZPA isolation is the live example). Say so.
          payload = { item: body || null, configured: body !== null && body !== undefined, fetchedAt: Date.now() };
        }
        zfPut(key, payload);
        return res.json(Object.assign({}, payload, { fromCache: false }));
      } catch (e) {
        return res.status(500).json({ error: e.message });
      }
    });
  });

  // ── ZPA policy engine ────────────────────────────────────────────────────
  // The eight policy types, each fetched as { set header, rules }. The set
  // endpoint returns only the header — rules live at policySet/rules/policyType
  // and are paginated, which is why the two are fetched separately.
  var POLICY_TYPES = [
    { type: 'ACCESS_POLICY',           label: 'Access' },
    { type: 'TIMEOUT_POLICY',          label: 'Timeout / Re-auth' },
    { type: 'CLIENT_FORWARDING_POLICY',label: 'Client Forwarding' },
    { type: 'ISOLATION_POLICY',        label: 'Isolation' },
    { type: 'INSPECTION_POLICY',       label: 'App Protection' },
    { type: 'CREDENTIAL_POLICY',       label: 'Credential' },
    { type: 'CAPABILITIES_POLICY',     label: 'Capabilities' },
    { type: 'REDIRECTION_POLICY',      label: 'Redirection' }
  ];
  var POLICY_BY_TYPE = {};
  POLICY_TYPES.forEach(function (p) { POLICY_BY_TYPE[p.type] = p; });

  async function fetchRules(type) {
    var all = [], page = 1, MAX_PAGES = 20;
    while (page <= MAX_PAGES) {
      var r = await oneapiGet(zpaPath('v1', 'policySet/rules/policyType/' + type) + '?page=' + page + '&pagesize=100');
      if (r.status !== 200) { if (all.length) break; throw new Error('rules HTTP ' + r.status); }
      var b = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
      var chunk = (b && b.list) || [];
      all.push.apply(all, chunk);
      if (chunk.length < 100) break;
      page++;
    }
    return all;
  }

  // GET /zpa/policy/overview — every policy type with its rule count, for tabs.
  router.get('/zpa/policy/overview', requireRead, async function (req, res) {
    var key = 'zpa/policy/overview';
    if (!req.query.refresh) {
      var hit = zfGet(key);
      if (hit) return res.json(Object.assign({}, hit.payload, { fromCache: true, ageMs: Date.now() - hit.at }));
    }
    try {
      var out = await Promise.all(POLICY_TYPES.map(async function (p) {
        var row = { type: p.type, label: p.label };
        try {
          var sr = await oneapiGet(zpaPath('v1', 'policySet/policyType/' + p.type));
          // Check status FIRST. Without it a 429/500 body parses into a truthy
          // object and gets reported — and cached — as "this policy type is
          // provisioned", which is a factual claim about the tenant drawn from
          // an error response.
          if (sr.status !== 200) {
            row.setError = 'upstream HTTP ' + sr.status;
            row.provisioned = null;
          } else {
            var sb = typeof sr.body === 'string' ? (function () { try { return JSON.parse(sr.body); } catch (e) { return null; } })() : sr.body;
            // A 200 with a null body means this policy type is not provisioned.
            row.provisioned = !!sb;
            if (sb) { row.setId = sb.id; row.setName = sb.name; row.enabled = sb.enabled; row.description = sb.description; }
          }
        } catch (e) { row.setError = e.message; row.provisioned = null; }
        try { row.ruleCount = (await fetchRules(p.type)).length; }
        catch (e) { row.ruleCount = null; row.rulesError = e.message; }
        return row;
      }));
      var payload = { policies: out, fetchedAt: Date.now() };
      // Only cache a clean sweep — caching a partial failure would pin a wrong
      // picture of the tenant for the full TTL.
      var clean = out.every(function (r) { return !r.setError && !r.rulesError; });
      payload.partial = !clean;
      if (clean) zfPut(key, payload);
      return res.json(Object.assign({}, payload, { fromCache: false }));
    } catch (e) { return res.status(500).json({ error: e.message }); }
  });

  // GET /zpa/policy/rules?type=ACCESS_POLICY — full rules for one type.
  router.get('/zpa/policy/rules', requireRead, async function (req, res) {
    var type = String(req.query.type || 'ACCESS_POLICY').trim().toUpperCase();
    if (!POLICY_BY_TYPE[type]) {
      return res.status(400).json({ error: 'unknown policy type', allowed: Object.keys(POLICY_BY_TYPE) });
    }
    var key = 'zpa/policy/rules:' + type;
    if (!req.query.refresh) {
      var hit = zfGet(key);
      if (hit) return res.json(Object.assign({}, hit.payload, { fromCache: true, ageMs: Date.now() - hit.at }));
    }
    try {
      var rules = await fetchRules(type);
      var payload = { type: type, label: POLICY_BY_TYPE[type].label, items: rules, count: rules.length, fetchedAt: Date.now() };
      zfPut(key, payload);
      return res.json(Object.assign({}, payload, { fromCache: false }));
    } catch (e) { return res.status(502).json({ error: e.message }); }
  });

  console.log('[zscaler-diag] CC-ZFULL v1.0 routes registered (' + (ZFULL.length + 2) + ' read endpoints across ZPA/ZIA/ZCC)');
})();
// ═══ end CC-ZFULL v1.0 ═══
