// weather-routes.js — office conditions for the Operations Hub hero, proxied server-side.
//
// History: landing.html used to call api.open-meteo.com straight from the browser.
// That was removed 2026-09-08 (see the QA note in landing.html) for two reasons, and
// this module exists to bring the readout back without either of them:
//
//   1. Third-party egress from an internal console. Every load sent the signed-in
//      user's IP and an internal Referer to a vendor nobody reviewed, and the site
//      CSP is `connect-src 'self' https://login.microsoftonline.com` — Report-Only
//      today, so the browser call worked but would have died silently the moment CSP
//      is enforced. One outbound call from this host, cached, is CSP-clean and leaks
//      no user identity. Same reasoning as service-status-routes.js.
//   2. A fabricated fallback. The old catch() was empty, so a blocked call left a
//      hardcoded "73°F • Sunny" on screen as though it had been measured. This route
//      never invents a reading: a failure returns { ok:false, reason } and the page
//      renders the location alone.
//
// 2026-09-09: a second office. Jeramy asked for Plano alongside Irvine, so SITES is
// now a list. open-meteo takes comma-separated coordinates and answers with one array
// element per site, which keeps this to the SAME single outbound call point 1 above
// is about — adding an office does not add a request, and does not add a round of
// egress review. The response still carries the old single-site fields at the top
// level (they mirror the first site) so a page that has not been redeployed keeps
// rendering one office instead of breaking.
//
// Mounted at /api/weather, behind server.js's blanket /api auth gate (auth-only, no
// page RBAC — the weather in Irvine is not tenant data).

const express = require('express');
const router  = express.Router();

// "Label|lat|lon" entries separated by ';'. Overridable so a third office does not
// need a code change, the way the single LAT/LON pair was before it.
const DEFAULT_SITES = 'Irvine, CA|33.6846|-117.8265;Plano, TX|33.0198|-96.6989';

function parseSites(spec) {
  const out = [];
  String(spec || '').split(';').forEach(function (row) {
    const p = row.split('|').map(function (x) { return x.trim(); });
    if (p.length < 3 || !p[0]) return;
    const lat = Number(p[1]), lon = Number(p[2]);
    if (!isFinite(lat) || !isFinite(lon)) return;
    out.push({ label: p[0], lat: lat, lon: lon });
  });
  return out;
}

let SITES = parseSites(process.env.WEATHER_SITES || DEFAULT_SITES);
if (!SITES.length) SITES = parseSites(DEFAULT_SITES);

// The pre-2026-09-09 env vars named one site. Honour them as an override of the
// first entry so an existing deployment's configuration keeps meaning what it meant.
if (process.env.WEATHER_LAT && process.env.WEATHER_LON) {
  SITES[0] = {
    label: process.env.WEATHER_LABEL || SITES[0].label,
    lat:   Number(process.env.WEATHER_LAT),
    lon:   Number(process.env.WEATHER_LON),
  };
}

const TTL_MS     = 10 * 60 * 1000;   // conditions do not move faster than this
const TIMEOUT_MS = 6000;

let _cache = { at: 0, payload: null };

// WMO code -> short label + a glyph key the page maps to its own icon set.
// Kept deliberately coarse: the hero shows one word, not a forecast.
const WMO = {
  0:  ['Clear', 'sun'],
  1:  ['Mostly clear', 'sun'],
  2:  ['Partly cloudy', 'cloud-sun'],
  3:  ['Overcast', 'cloud'],
  45: ['Fog', 'fog'],       48: ['Fog', 'fog'],
  51: ['Drizzle', 'rain'],  53: ['Drizzle', 'rain'],  55: ['Drizzle', 'rain'],
  56: ['Freezing drizzle', 'rain'], 57: ['Freezing drizzle', 'rain'],
  61: ['Rain', 'rain'],     63: ['Rain', 'rain'],     65: ['Heavy rain', 'rain'],
  66: ['Freezing rain', 'rain'], 67: ['Freezing rain', 'rain'],
  71: ['Snow', 'snow'],     73: ['Snow', 'snow'],     75: ['Heavy snow', 'snow'],
  77: ['Snow grains', 'snow'],
  80: ['Showers', 'rain'],  81: ['Showers', 'rain'],  82: ['Heavy showers', 'rain'],
  85: ['Snow showers', 'snow'], 86: ['Snow showers', 'snow'],
  95: ['Thunderstorm', 'storm'], 96: ['Thunderstorm', 'storm'], 99: ['Thunderstorm', 'storm'],
};

function withTimeout(p, ms, label) {
  return Promise.race([
    p,
    new Promise(function (_, rej) {
      setTimeout(function () { rej(new Error(label + ' timed out after ' + ms + 'ms')); }, ms);
    }),
  ]);
}

// A site we could not read reports itself unreadable. It never borrows another
// site's reading, and never falls back to a made-up one.
function unread(site, reason) {
  return { label: site.label, ok: false, reason: reason };
}

function readSite(site, entry) {
  const c = entry && entry.current;
  if (!c || typeof c.temperature_2m !== 'number') {
    return unread(site, 'upstream returned no current reading');
  }
  const code = Number(c.weather_code);
  const meta = WMO[code] || ['Unknown', 'cloud'];
  return {
    label: site.label,
    ok: true,
    tempF: Math.round(c.temperature_2m),
    code: code,
    text: meta[0],
    icon: (meta[1] === 'sun' && c.is_day === 0) ? 'moon' : meta[1],
    isDay: c.is_day !== 0,
    observedAt: c.time || null,
  };
}

// The page reads `sites`; everything else here is the pre-two-office shape, kept
// so an older landing.html still renders the first office rather than nothing.
function envelope(sites) {
  const first = sites[0] || {};
  const anyOk = sites.some(function (s) { return s.ok; });
  return Object.assign({}, first, {
    ok: anyOk && first.ok !== false,
    sites: sites,
    source: 'open-meteo',
  });
}

router.get('/', async (req, res) => {
  const hit = _cache.payload;
  if (hit && (Date.now() - _cache.at) < TTL_MS) {
    return res.json(Object.assign({}, hit, { cached: true }));
  }
  const url = 'https://api.open-meteo.com/v1/forecast'
    + '?latitude='  + encodeURIComponent(SITES.map(function (s) { return s.lat; }).join(','))
    + '&longitude=' + encodeURIComponent(SITES.map(function (s) { return s.lon; }).join(','))
    + '&current=temperature_2m,weather_code,is_day'
    + '&temperature_unit=fahrenheit'
    + '&timezone=auto';
  try {
    const r = await withTimeout(fetch(url, { headers: { Accept: 'application/json' } }), TIMEOUT_MS, 'open-meteo');
    if (!r.ok) {
      // No cached value to fall back on and no reading to report. Say so, per site.
      const why = 'upstream HTTP ' + r.status;
      return res.json(Object.assign(envelope(SITES.map(function (s) { return unread(s, why); })),
                                    { ok: false, reason: why }));
    }
    const j = await r.json();
    // One coordinate answers with an object; several answer with an array. Both,
    // because SITES is configurable and may legitimately hold a single office.
    const rows = Array.isArray(j) ? j : [j];
    const sites = SITES.map(function (s, i) { return readSite(s, rows[i]); });
    if (!sites.some(function (s) { return s.ok; })) {
      return res.json(Object.assign(envelope(sites),
                                    { ok: false, reason: 'upstream returned no current reading' }));
    }
    const payload = envelope(sites);
    _cache = { at: Date.now(), payload: payload };
    res.json(Object.assign({}, payload, { cached: false }));
  } catch (e) {
    const why = String(e.message).slice(0, 160);
    res.json(Object.assign(envelope(SITES.map(function (s) { return unread(s, why); })),
                           { ok: false, reason: why }));
  }
});

module.exports = router;
