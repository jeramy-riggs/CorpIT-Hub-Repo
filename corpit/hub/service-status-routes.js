// service-status-routes.js — vendor service status, proxied server-side.
//
// Why a proxy instead of fetching statuspage.io from the browser: the site CSP is
// `connect-src 'self' https://login.microsoftonline.com`. It is Report-Only today, so a
// direct browser fetch would work now and break silently the moment CSP is enforced.
// Serving the feeds from 'self' is CSP-clean either way, keeps one outbound path instead
// of one per client, and lets us cache.
//
// Mounted at /api/service-status, which sits behind server.js's blanket /api auth gate
// (auth-only, no page RBAC — vendor status is not sensitive).

const express = require('express');
const router = express.Router();

// Statuspage.io-compatible feeds. Verified reachable from this host 2026-08-18.
// NOTE: use the VBC page (uc.vonagestatus.com), NOT vonageapi.statuspage.io — the latter
// is the developer SMS/Voice API platform, whose global indicator goes amber for regional
// SMS maintenance (Europe/APAC) that has nothing to do with our phone system.
const FEEDS = [
  { key: 'vonage', label: 'Vonage',  host: 'uc.vonagestatus.com',
    url: 'https://vonagebusiness.statuspage.io/api/v2/summary.json' },
  { key: 'meraki', label: 'Meraki',  host: 'status.meraki.net',
    url: 'https://status.meraki.net/api/v2/summary.json' },
  { key: 'kandji', label: 'Kandji',  host: 'status.kandji.io',
    url: 'https://status.kandji.io/api/v2/summary.json' },
];

const TTL_MS     = 60 * 1000;
const TIMEOUT_MS = 6000;

let _cache = { at: 0, payload: null };

// statuspage leaf component states, worst-first
const COMPONENT_RANK = {
  major_outage: 3,
  partial_outage: 2,
  degraded_performance: 1,
  under_maintenance: 1,
  operational: 0,
};

function classify(summary) {
  const indicator = (summary.status && summary.status.indicator) || 'unknown';
  const description = (summary.status && summary.status.description) || '';

  // Container rows (group: true) restate their children — counting them double-reports.
  const leaves = (summary.components || []).filter(c => !c.group);
  const degraded = leaves.filter(c => c.status && c.status !== 'operational');

  // impact:'none' entries are notices (e.g. "scheduled maintenance next Tuesday").
  // Rapid7 had one of these sitting open while every component was operational, so
  // treating any open incident as a problem would have shown a false warning.
  const incidents = (summary.incidents || [])
    .filter(i => i.impact && i.impact !== 'none');

  const worstComponent = degraded.reduce(
    (w, c) => Math.max(w, COMPONENT_RANK[c.status] || 0), 0);
  const criticalIncident = incidents.some(
    i => i.impact === 'critical' || i.impact === 'major');

  let state, text;
  if (indicator === 'critical' || indicator === 'major' || worstComponent === 3 || criticalIncident) {
    state = 'bad';
    text = worstComponent === 3 ? 'Major outage' : (indicator === 'critical' ? 'Critical' : 'Outage');
  } else if (worstComponent === 2) {
    state = 'warn'; text = 'Partial outage';
  } else if (indicator === 'maintenance' || degraded.some(c => c.status === 'under_maintenance')) {
    state = 'warn'; text = 'Maintenance';
  } else if (indicator === 'minor' || worstComponent === 1 || incidents.length) {
    state = 'warn'; text = 'Degraded';
  } else if (indicator === 'none') {
    state = 'ok'; text = 'Operational';
  } else {
    state = 'unknown'; text = 'Unknown';
  }

  return {
    state,
    text,
    indicator,
    description,
    components: leaves.length,
    degraded: degraded.map(c => c.name),
    incidents: incidents.map(i => ({ name: i.name, impact: i.impact, status: i.status })),
  };
}

async function fetchFeed(feed) {
  try {
    const res = await fetch(feed.url, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      return { key: feed.key, label: feed.label, source: feed.host,
               state: 'unknown', text: 'Unavailable', error: 'HTTP ' + res.status };
    }
    const body = await res.json();
    return Object.assign(
      { key: feed.key, label: feed.label, source: feed.host },
      classify(body));
  } catch (e) {
    const msg = e && e.name === 'TimeoutError' ? 'timeout' : String(e && e.message || e).slice(0, 120);
    return { key: feed.key, label: feed.label, source: feed.host,
             state: 'unknown', text: 'Unavailable', error: msg };
  }
}

router.get('/', async (req, res) => {
  const now = Date.now();
  if (_cache.payload && (now - _cache.at) < TTL_MS && req.query.live !== '1') {
    return res.json(Object.assign({}, _cache.payload, { cached: true }));
  }
  const results = await Promise.all(FEEDS.map(fetchFeed));
  const services = {};
  results.forEach(r => { services[r.key] = r; });

  const payload = {
    ok: true,
    checkedAt: new Date(now).toISOString(),
    cached: false,
    ttlSeconds: TTL_MS / 1000,
    services,
  };
  _cache = { at: now, payload };
  res.json(payload);
});

module.exports = router;
