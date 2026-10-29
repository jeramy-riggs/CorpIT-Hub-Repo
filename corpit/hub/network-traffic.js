'use strict';

// Read-only correlation for Network Operations. Each upstream keeps its own
// grain and freshness; the response never presents proxy log bytes as the
// complete contents of a FortiGate tunnel.
const https = require('https');
const net = require('net');
const Database = require('better-sqlite3');
const { fgtGet } = require('./netdiag');
const { merakiGet, NETWORKS } = require('./meraki-lookup');

const SITES = {
  SNA01: { name: 'Irvine', fw: 'irvine', wan: 'port2', inside: 'port1',
    prefix: '10.20.', remotePrefixes: ['10.20.250.', '10.20.251.'], network: NETWORKS.SNA01.id },
  DFW02: { name: 'Plano', fw: 'dallas', wan: 'port1', inside: 'port2',
    prefix: '10.19.', remotePrefixes: [], network: NETWORKS.DFW02.id },
};
const LOGSET = '54414c09-670a-47c7-9e2d-8e38d4c94f09';
const DB_PATH = process.env.NET_DB || '/var/www/corpit-hub-api/data/netfleet.db';
const livePrevious = new Map();
const liveMeasured = new Map();
const historyCache = new Map();
const topUsersCache = new Map();
const pinnedCache = new Map();

function siteOf(req, res) {
  const site = String(req.query.site || 'SNA01').toUpperCase();
  if (!SITES[site]) {
    res.status(400).json({ ok: false, detail: 'Choose Irvine or Plano.' });
    return null;
  }
  return { code: site, ...SITES[site] };
}
function roundedMbps(bytes, seconds) { return Math.round(bytes * 8 / seconds / 1e6 * 10) / 10; }
function responseError(e) { return e && e.message ? e.message : String(e); }
function officeIp(site, ip) {
  return net.isIPv4(ip) && ip.startsWith(site.prefix) &&
    !site.remotePrefixes.some(prefix => ip.startsWith(prefix));
}
function officeSource(site, ip) {
  if (ip) return `source_ip="${ip}"`;
  return [`source_ip STARTS-WITH "${site.prefix}"`,
    ...site.remotePrefixes.map(prefix => `source_ip NOT STARTS-WITH "${prefix}"`)].join(' AND ');
}
function settle(name, result) {
  return result.status === 'fulfilled'
    ? { ok: true, data: result.value }
    : { ok: false, error: responseError(result.reason), source: name,
      ...(result.reason && result.reason.pending ? { pending: true } : {}) };
}

async function live(req, res) {
  const site = siteOf(req, res); if (!site) return;
  try {
    const raw = await fgtGet(site.fw, 'api/v2/monitor/system/interface');
    const list = Array.isArray(raw.results) ? raw.results :
      Object.entries(raw.results || {}).map(([name, value]) => ({ name, ...value }));
    const port = list.find(p => p.name === site.wan);
    if (!port) throw new Error('WAN interface was not returned by the FortiGate.');
    const now = Date.now(), rx = Number(port.rx_bytes), tx = Number(port.tx_bytes);
    const speedMbps = Number(port.speed) || null;
    const previous = livePrevious.get(site.code);
    let downMbps = null, upMbps = null, intervalSeconds = null, sampledAt = now;
    if (previous && Number.isFinite(rx) && Number.isFinite(tx)) {
      intervalSeconds = (now - previous.at) / 1000;
      if (intervalSeconds >= 2 && intervalSeconds <= 90 && rx >= previous.rx && tx >= previous.tx) {
        downMbps = roundedMbps(rx - previous.rx, intervalSeconds);
        upMbps = roundedMbps(tx - previous.tx, intervalSeconds);
        liveMeasured.set(site.code, { at: now, downMbps, upMbps, intervalSeconds });
      }
    }
    // Viewers polling just after another viewer can reuse the last valid delta.
    // Keep its original sample time so the UI never presents an old rate as new.
    if (downMbps == null && previous && intervalSeconds >= 0 && intervalSeconds < 2 &&
        rx >= previous.rx && tx >= previous.tx) {
      const measured = liveMeasured.get(site.code);
      if (measured && now - measured.at <= 30000) {
        ({ downMbps, upMbps, intervalSeconds } = measured);
        sampledAt = measured.at;
      }
    }
    // A second viewer arriving milliseconds later must not erase the baseline
    // before anyone has a valid two-sample rate.
    if (Number.isFinite(rx) && Number.isFinite(tx) &&
        (!previous || intervalSeconds >= 2 || rx < previous.rx || tx < previous.tx))
      livePrevious.set(site.code, { at: now, rx, tx });
    res.json({ ok: true, site: site.code, name: site.name, sampledAt,
      interface: site.wan, alias: port.alias || '', speedMbps, downMbps, upMbps,
      intervalSeconds, state: downMbps == null ? 'warming' : 'measured' });
  } catch (e) { res.status(502).json({ ok: false, detail: responseError(e) }); }
}

function windowOf(req, res) {
  const now = Date.now();
  let end = req.query.to ? Date.parse(String(req.query.to)) : now;
  let start = req.query.from ? Date.parse(String(req.query.from)) : now - 24 * 3600000;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end > now + 60000 ||
      end - start < 2 * 3600000 || end - start > 7 * 86400000) {
    res.status(400).json({ ok: false, detail: 'Choose a past interval from 2 hours to 7 days.' });
    return null;
  }
  return { from: start, to: end };
}

async function fortiHistory(site, window, sourceIp, destinationIp) {
  const query = { device: 'disk', report_by: 'destination', sort_by: 'bytes',
    start: Math.floor(window.from / 1000), end: Math.floor(window.to / 1000) };
  query.filter = JSON.stringify({ dstintf: [site.wan], srcintf: [site.inside],
    ...(sourceIp ? { srcip: [sourceIp] } : {}),
    ...(destinationIp ? { dstip: [destinationIp] } : {}) });
  const [dest, source] = await Promise.all([
    fgtGet(site.fw, 'api/v2/monitor/fortiview/historical-statistics', query),
    sourceIp ? Promise.resolve(null) : fgtGet(site.fw, 'api/v2/monitor/fortiview/historical-statistics',
      { ...query, report_by: 'source' }),
  ]);
  const results = dest.results || {}, graph = results.summary && results.summary.graph || [];
  const details = (results.details || []).filter(d => d.dstintf === site.wan);
  return { grain: 'FortiView logged bytes from office inside interface; graph resolution varies with interval',
    sampledAt: Date.now(), graph: graph.map(p => ({ ts: Number(p.time) * 1000,
      downBytes: Number(p.rcvdbyte) || 0, upBytes: Number(p.sentbyte) || 0 })),
    destinations: details.slice(0, 30).map(d => ({ ip: d.dstip, interface: d.dstintf,
      downBytes: Number(d.rcvdbyte) || 0, upBytes: Number(d.sentbyte) || 0,
      sessions: Number(d.sessions) || 0 })),
    sources: source && (source.results?.details || []).slice(0, 30).map(d => ({
      ip: d.srcip, downBytes: Number(d.rcvdbyte) || 0,
      upBytes: Number(d.sentbyte) || 0, sessions: Number(d.sessions) || 0 })) || [] };
}

function streamingApplication(row) {
  const app = String(row.application || '').trim();
  const host = String(row.destination || '').toLowerCase();
  let category = null, signal = 'Meraki application';
  if (/^(riverside(?:\.fm)?|zoom webinars?|webex webinars?|gotowebinar|on24|livestorm|bigmarker)$/i.test(app)) category = 'webinars';
  else if (/^(zoom meetings|ms teams video|ms teams audio|ms teams app sharing|google meet|skype|wi-fi calling|statistical conference video|statistical conference audio|real-time transport protocol video)$/i.test(app)) category = 'meetings';
  else if (/^microsoft teams$/i.test(app)) { category = 'meetings'; signal = 'general Teams application; call unconfirmed'; }
  else if (/^(instagram|facebook|tiktok|snapchat|twitter|linkedin|reddit|pinterest|threads)$/i.test(app)) { category = 'social'; signal = 'social app; media use unconfirmed'; }
  else if (/^(youtube|youtube tv|youtube music|netflix(?: video)?|hulu(?: video)?|disney\+|disney plus|prime video|amazon prime video|hbo max|peacock(?: tv)?|paramount\+|paramount plus|apple tv\+?|discovery\+|discovery plus|espn\+|fubo(?:tv)?|sling tv|twitch(?:\.tv)?|vimeo|spotify|itunes-audio|apple music|pandora|amazon music|soundcloud)$/i.test(app)) category = 'streaming';
  else if (/^itunes$/i.test(app)) { category = 'streaming'; signal = 'general iTunes application; audio unconfirmed'; }
  else if (/(?:^|\.)(?:riverside\.fm|riverside\.com|gotowebinar\.com|on24\.com|livestorm\.co|bigmarker\.com)$/.test(host)) { category = 'webinars'; signal = 'webinar service destination; stream unconfirmed'; }
  else if (/(?:^|\.)(?:instagram\.com|facebook\.com|fbcdn\.net|tiktok\.com|tiktokv\.us|snapchat\.com|linkedin\.com|reddit\.com|x\.com|twitter\.com|pinterest\.com|threads\.net)$/.test(host)) { category = 'social'; signal = 'social destination; media use unconfirmed'; }
  else if (/(?:^|\.)live-video\.net$/.test(host)) { category = 'streaming'; signal = 'shared Amazon IVS live-video CDN; service unconfirmed'; }
  else if (/(?:^|\.)(?:googlevideo\.com|amazonvideo\.com|nflxvideo\.net|vimeocdn\.com)$/.test(host)) { category = 'streaming'; signal = 'media destination; service variant unconfirmed'; }
  else if (/(?:^|\.)(?:youtube\.com|hulu\.com|netflix\.com|disneyplus\.com|primevideo\.com|hbomax\.com|peacocktv\.com|paramountplus\.com|discoveryplus\.com|fubo\.tv|sling\.com|twitch\.tv|vimeo\.com|spotifycdn\.com|scdn\.co|pandora\.com|soundcloud\.com)$/.test(host) || /^(?:music\.apple\.com|music\.amazon\.com)$/.test(host)) { category = 'streaming'; signal = 'service destination; playback unconfirmed'; }
  else if (/(?:^|\.)(?:teams\.microsoft\.com|meet\.google\.com|zoom\.us|webex\.com)$/.test(host)) { category = 'meetings'; signal = 'meeting service destination; call unconfirmed'; }
  if (!category) return null;
  return { category, signal };
}
function streamingDomain(domain) {
  const name = String(domain || '').toLowerCase();
  if (name === 'live-video.net')
    return { category: 'streaming', signal: 'shared Amazon IVS live-video CDN; service unconfirmed' };
  if (/^(riverside\.fm|riverside\.com|gotowebinar\.com|on24\.com|livestorm\.co|bigmarker\.com)$/.test(name))
    return { category: 'webinars', signal: 'webinar service domain; stream unconfirmed' };
  if (/^(zoom\.us|zoom\.com|webex\.com|vonage\.com|skype\.com)$/.test(name))
    return { category: 'meetings', signal: 'meeting service domain; call unconfirmed' };
  if (/^(instagram\.com|facebook\.com|fbcdn\.net|tiktok\.com|tiktokv\.us|snapchat\.com|linkedin\.com|reddit\.com|x\.com|twitter\.com|pinterest\.com|threads\.net)$/.test(name))
    return { category: 'social', signal: name === 'fbcdn.net' ?
      'shared social CDN; service and media unconfirmed' : 'social site; media use unconfirmed' };
  if (/^(youtube\.com|netflix\.com|nflxvideo\.net|vimeo\.com|vimeocdn\.com|twitch\.tv|hulu\.com|googlevideo\.com|disneyplus\.com|primevideo\.com|amazonvideo\.com|hbomax\.com|peacocktv\.com|paramountplus\.com|discoveryplus\.com|fubo\.tv|sling\.com)$/.test(name))
    return { category: 'streaming', signal: /googlevideo|nflxvideo|vimeocdn|amazonvideo/.test(name) ?
      'media CDN; service variant unconfirmed' : 'service domain; playback unconfirmed' };
  if (/^(spotify\.com|spotifycdn\.com|scdn\.co|pandora\.com|soundcloud\.com)$/.test(name))
    return { category: 'streaming', signal: /spotifycdn|scdn/.test(name) ?
      'service CDN; audio stream unconfirmed' : 'service domain; playback unconfirmed' };
  return null;
}

async function merakiHistory(site, window) {
  const t0 = encodeURIComponent(new Date(window.from).toISOString());
  const t1 = encodeURIComponent(new Date(window.to).toISOString());
  const r = await merakiGet(`/networks/${site.network}/traffic?t0=${t0}&t1=${t1}&deviceType=wireless`,
    { maxBytes: 4 * 1024 * 1024 });
  if (r.status !== 200 || !Array.isArray(r.body)) throw new Error(`Meraki HTTP ${r.status}`);
  const rows = r.body.sort((a, b) => (Number(b.recv) + Number(b.sent)) -
    (Number(a.recv) + Number(a.sent)));
  const convert = d => ({
      application: d.application || 'Unknown', destination: d.destination || null,
      protocol: d.protocol || null, port: d.port || null,
      downKb: Number(d.recv) || 0, upKb: Number(d.sent) || 0,
      clients: Number(d.numClients) || 0 });
  return { scope: 'Wi-Fi only; app categories may overlap or describe encrypted tunnels',
    totalEntries: rows.length,
    entries: rows.slice(0, 30).map(convert),
    streaming: rows.map(d => ({ ...convert(d),
      ...(streamingApplication(d) || { category: 'other',
        signal: 'unclassified Meraki label; inner service unknown' }) })) };
}

function rapidGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'X-Api-Key': process.env.RAPID7_API_KEY,
      Accept: 'application/json' }, timeout: 20000 }, response => {
      let body = '';
      response.on('data', c => { body += c; if (body.length > 2 * 1024 * 1024) req.destroy(new Error('Rapid7 response too large')); });
      response.on('end', () => {
        let data; try { data = JSON.parse(body); } catch { return reject(new Error('Rapid7 returned invalid JSON')); }
        if (response.statusCode >= 400) return reject(new Error(data.message || `Rapid7 HTTP ${response.statusCode}`));
        resolve(data);
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Rapid7 timed out')));
  });
}
async function rapidQuery(query, window, attempts = 8, extra = '') {
  if (!process.env.RAPID7_API_KEY) throw new Error('Rapid7 API is not configured.');
  const host = `${process.env.RAPID7_REGION || 'us'}.api.insight.rapid7.com`;
  let url = `https://${host}/log_search/query/logsets/${LOGSET}?query=${encodeURIComponent(query)}` +
    `&from=${window.from}&to=${window.to}${extra}`;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const data = await rapidGet(url);
    const next = (data.links || []).find(link => link.rel === 'Self');
    if (!next || data.progress >= 100) return data;
    const parsed = new URL(next.href);
    if (parsed.hostname !== host || parsed.protocol !== 'https:') throw new Error('Rapid7 continuation host changed.');
    url = next.href;
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
  throw new Error('Rapid7 query did not finish in time.');
}
// Newest office-source proxy event in the last 24 h. An empty window can then say whether
// the feed is lagging or the office was quiet. One event, newest first: about 2 s.
const latestCache = new Map();
async function latestProxyEvent(site, sourceIp) {
  const key = site.code + ':' + (sourceIp || ''), hit = latestCache.get(key);
  if (hit && Date.now() - hit.at < 60000) return hit.ts;
  const to = Date.now();
  const data = await rapidQuery(`where(${officeSource(site, sourceIp)})`, { from: to - 86400000, to }, 10,
    '&per_page=1&most_recent_first=true');
  const ts = Number(data.events?.[0]?.timestamp) || null;
  if (latestCache.size > 30) latestCache.clear();
  latestCache.set(key, { at: Date.now(), ts });
  return ts;
}
function latestOrNull(site, sourceIp) {
  let timer;
  return Promise.race([latestProxyEvent(site, sourceIp),
    new Promise(resolve => { timer = setTimeout(() => resolve(null), 8000); })])
    .catch(() => null).finally(() => clearTimeout(timer));
}
async function webHistory(site, window, sourceIp, attempts) {
  const where = `where(${officeSource(site, sourceIp)})`;
  const [data, usersData, hostsData] = await Promise.all([
    rapidQuery(`${where} groupby(top_private_domain) calculate(sum:incoming_bytes) sort(desc) limit(200)`, window, attempts),
    rapidQuery(`${where} groupby(user) calculate(sum:incoming_bytes) sort(desc) limit(20)`, window, attempts),
    rapidQuery(`${where} groupby(url_host) calculate(sum:incoming_bytes) sort(desc) limit(30)`, window, attempts),
  ]);
  const statistics = data.statistics || {};
  const groupedDomains = (statistics.groups || []).map(row => { const [domain, value] = Object.entries(row)[0] || [];
    return { domain, downBytes: Number(value?.sum) || 0 }; });
  return { scope: 'Office DHCP source IPs in observed Zscaler web proxy logs; may omit tunnel applications and media',
    matchedEvents: data.search_stats?.events_matched ?? null,
    domains: groupedDomains.slice(0, 25),
    hosts: (hostsData.statistics?.groups || []).map(row => { const [host, value] = Object.entries(row)[0] || [];
      return { host, downBytes: Number(value?.sum) || 0 }; }).filter(row => row.host).slice(0, 25),
    streamingDomains: groupedDomains.map(d => ({ ...d,
      ...(streamingDomain(d.domain) || { category: 'other',
        signal: 'other ranked proxy site; purpose unconfirmed' }) })),
    users: (usersData.statistics?.groups || []).map(row => { const [user, value] = Object.entries(row)[0] || [];
      return { user, downBytes: Number(value?.sum) || 0 }; }) };
}

// Long proxy windows can outlast the page's 20 s request timeout. The Rapid7 run keeps going
// after the response so a refresh picks it up, and the last good result for the same
// rolling window is shown, labelled with its age, instead of a blank ranking.
const webRunning = new Map();
const webLastGood = new Map();
function webKey(site, window, sourceIp) {
  const rolling = Date.now() - window.to < 120000;
  return `${site.code}:${sourceIp}:${Math.round((window.to - window.from) / 60000)}:` +
    (rolling ? 'now' : Math.round(window.to / 60000));
}
async function webHistoryShared(site, window, sourceIp) {
  const key = webKey(site, window, sourceIp);
  const recent = webLastGood.get(key);
  if (recent && Date.now() - recent.at < 120000) return recent.data;
  let run = webRunning.get(key);
  if (!run) {
    run = webHistory(site, window, sourceIp, 50).then(data => {
      if (webLastGood.size > 30) webLastGood.clear();
      webLastGood.set(key, { at: Date.now(), from: window.from, to: window.to, data });
      return data;
    }).finally(() => webRunning.delete(key));
    run.catch(() => {});
    webRunning.set(key, run);
  }
  let timer;
  const wait = new Promise((_, reject) => { timer = setTimeout(() => {
    const e = new Error('Rapid7 is still running this query. Refresh evidence in about 30 seconds.');
    e.pending = true; reject(e); }, 15000); });
  try { return await Promise.race([run, wait]); }
  catch (e) {
    const last = webLastGood.get(key);
    if (last && Date.now() - last.at < 30 * 60000)
      return { ...last.data, carried: { at: last.at, from: last.from, to: last.to, reason: responseError(e) } };
    throw e;
  } finally { clearTimeout(timer); }
}

// Pinned services on the Traffic view. Fixed server-side so the query never takes caller text.
// riverside.com carries Riverside media and signalling (Riverside IT firewall guide);
// live-video.net is Amazon IVS playback, shared by Riverside, Twitch and others.
const PINNED = [
  { key: 'zoom', domains: ['zoom.us', 'zoom.com'] },
  { key: 'teams', hosts: ['teams.microsoft.com'] },
  { key: 'riverside', domains: ['riverside.fm', 'riverside.com'] },
  { key: 'ivs', domains: ['live-video.net'] },
  { key: 'vonage', domains: ['vonage.com'] },
];
function pairGroups(data) {
  return (data.statistics?.groups || []).map(row => {
    const [label, value] = Object.entries(row)[0] || [];
    const text = String(label || '').replace(/^\[|\]$/g, '');
    const cut = text.indexOf(', ');
    return cut < 0 ? null : { name: text.slice(0, cut).toLowerCase(), user: text.slice(cut + 2),
      downBytes: Number(value?.sum) || 0 };
  }).filter(Boolean);
}
// The user panels poll every 60 s. Their Rapid7 runs also keep going past the 15 s reply and
// fill the cache when done, so a busy Rapid7 (a long proxy window running) delays the next
// check instead of failing every one.
const panelRunning = new Map();
async function panelRun(key, build) {
  let run = panelRunning.get(key);
  if (!run) {
    run = build().finally(() => panelRunning.delete(key));
    run.catch(() => {});
    panelRunning.set(key, run);
  }
  let timer;
  const wait = new Promise((_, reject) => { timer = setTimeout(() => {
    const e = new Error('Rapid7 is busy with this query; the next check picks up the result.');
    e.pending = true; reject(e); }, 15000); });
  try { return await Promise.race([run, wait]); } finally { clearTimeout(timer); }
}

async function pinnedUsers(req, res) {
  const site = siteOf(req, res); if (!site) return;
  const now = Date.now();
  const to = req.query.to ? Date.parse(String(req.query.to)) : now;
  const from = req.query.from ? Date.parse(String(req.query.from)) : to - 30 * 60000;
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from || to > now + 60000 ||
      to - from < 5 * 60000 || to - from > 7 * 86400000)
    return res.status(400).json({ ok: false, detail: 'Choose a past interval from 5 minutes to 7 days.' });
  const sourceIp = String(req.query.ip || '').trim();
  if (sourceIp && !officeIp(site, sourceIp))
    return res.status(400).json({ ok: false, detail: 'Source must be an on-prem office IPv4 address for this site.' });
  const key = webKey(site, { from, to }, sourceIp);
  const hit = pinnedCache.get(key);
  if (hit && Date.now() - hit.at < 45000) return res.json(hit.body);
  try { res.json(await panelRun('pin:' + key, async () => {
    const source = officeSource(site, sourceIp), window = { from, to };
    const domains = PINNED.flatMap(p => p.domains || []), hosts = PINNED.flatMap(p => p.hosts || []);
    const anyOf = (field, list) => list.map(v => `${field}="${v}"`).join(' OR ');
    const tail = ' calculate(sum:incoming_bytes) sort(desc) limit(200)';
    const [byDomain, byHost, latestEventAt] = await Promise.all([
      rapidQuery(`where((${anyOf('top_private_domain', domains)}) AND ${source}) groupby(top_private_domain, user)${tail}`, window, 50),
      hosts.length ? rapidQuery(`where((${anyOf('url_host', hosts)}) AND ${source}) groupby(url_host, user)${tail}`, window, 50)
        : Promise.resolve({}),
      latestOrNull(site, sourceIp),
    ]);
    const rows = [...pairGroups(byDomain), ...pairGroups(byHost)];
    const services = PINNED.map(p => {
      const names = [...(p.domains || []), ...(p.hosts || [])];
      const users = new Map();
      for (const r of rows) if (names.includes(r.name) && r.user)
        users.set(r.user, (users.get(r.user) || 0) + r.downBytes);
      return { key: p.key, names, users: [...users].map(([user, downBytes]) => ({ user, downBytes }))
        .sort((a, b) => b.downBytes - a.downBytes).slice(0, 25) };
    });
    const body = { ok: true, site: site.code, from, to, generatedAt: Date.now(), sourceIp: sourceIp || null,
      scope: 'On-prem office source IPs in observed Zscaler web proxy logs; partial and can lag a few minutes',
      matchedEvents: (byDomain.search_stats?.events_matched ?? 0) + (byHost.search_stats?.events_matched ?? 0),
      latestEventAt, services };
    if (pinnedCache.size > 30) pinnedCache.clear();
    pinnedCache.set(key, { at: Date.now(), body });
    return body;
  })); } catch (e) { res.status(502).json({ ok: false, detail: responseError(e) }); }
}

async function topUsers(req, res) {
  const site = siteOf(req, res); if (!site) return;
  const window = windowOf(req, res); if (!window) return;
  const sourceIp = String(req.query.ip || '').trim();
  if (sourceIp && !officeIp(site, sourceIp))
    return res.status(400).json({ ok: false, detail: 'Source must be an on-prem office IPv4 address for this site.' });
  const key = webKey(site, window, sourceIp);
  const hit = topUsersCache.get(key);
  if (hit && Date.now() - hit.at < 45000) return res.json(hit.body);
  try { res.json(await panelRun('top:' + key, async () => {
    const where = `where(${officeSource(site, sourceIp)})`;
    const data = await rapidQuery(`${where} groupby(user) calculate(sum:incoming_bytes) sort(desc) limit(20)`, window, 50);
    const body = { ok: true, site: site.code, from: window.from, to: window.to,
      generatedAt: Date.now(), sourceIp: sourceIp || null,
      scope: 'On-prem office source IPs in observed Zscaler web proxy logs; partial user ranking',
      matchedEvents: data.search_stats?.events_matched ?? null,
      users: (data.statistics?.groups || []).map(row => { const [user, value] = Object.entries(row)[0] || [];
        return { user, downBytes: Number(value?.sum) || 0 }; }) };
    if (topUsersCache.size > 30) topUsersCache.clear();
    topUsersCache.set(key, { at: Date.now(), body });
    return body;
  })); } catch (e) { res.status(502).json({ ok: false, detail: responseError(e) }); }
}

async function userSites(req, res) {
  const site = siteOf(req, res); if (!site) return;
  const window = windowOf(req, res); if (!window) return;
  const user = String(req.query.user || '').trim();
  const sourceIp = String(req.query.ip || '').trim();
  if (user.length < 2 || user.length > 100 || !/^[\p{L}\p{N} ._@'-]+$/u.test(user))
    return res.status(400).json({ ok: false, detail: 'Choose a user from the observed list.' });
  if (sourceIp && !officeIp(site, sourceIp))
    return res.status(400).json({ ok: false, detail: 'Source must be an on-prem office IPv4 address for this site.' });
  try {
    const escaped = user.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const source = officeSource(site, sourceIp);
    const q = `where(user="${escaped}" AND ${source}) ` +
      'groupby(top_private_domain) calculate(sum:incoming_bytes) sort(desc) limit(20)';
    const data = await rapidQuery(q, window);
    res.json({ ok: true, user, site: site.code, from: window.from, to: window.to,
      sourceIp: sourceIp || null,
      scope: 'On-prem office source IPs in observed Zscaler web proxy logs only',
      domains: (data.statistics?.groups || []).map(row => { const [domain, value] = Object.entries(row)[0] || [];
        return { domain, downBytes: Number(value?.sum) || 0 }; }) });
  } catch (e) { res.status(502).json({ ok: false, detail: responseError(e) }); }
}

async function domainUsers(req, res) {
  const site = siteOf(req, res); if (!site) return;
  const window = windowOf(req, res); if (!window) return;
  const domain = String(req.query.domain || '').trim().toLowerCase();
  const field = String(req.query.field || 'domain').trim().toLowerCase();
  const sourceIp = String(req.query.ip || '').trim();
  if (domain.length < 2 || domain.length > 100 || !/^[a-z0-9.-]+$/.test(domain))
    return res.status(400).json({ ok: false, detail: 'Enter a site or domain name.' });
  if (!['domain', 'host'].includes(field))
    return res.status(400).json({ ok: false, detail: 'Choose domain or exact host.' });
  if (sourceIp && !officeIp(site, sourceIp))
    return res.status(400).json({ ok: false, detail: 'Source must be an on-prem office IPv4 address for this site.' });
  try {
    const source = officeSource(site, sourceIp);
    const match = field === 'host' ? `url_host="${domain}"` :
      `top_private_domain ICONTAINS "${domain}"`;
    const query = `where(${match} AND ${source}) ` +
      'groupby(user) calculate(sum:incoming_bytes) sort(desc) limit(20)';
    const data = await rapidQuery(query, window);
    res.json({ ok: true, domain, field, site: site.code, from: window.from, to: window.to,
      sourceIp: sourceIp || null,
      scope: 'On-prem office source IPs in observed Zscaler web proxy logs only',
      matchedEvents: data.search_stats?.events_matched ?? null,
      users: (data.statistics?.groups || []).map(row => { const [user, value] = Object.entries(row)[0] || [];
        return { user, downBytes: Number(value?.sum) || 0 }; }) });
  } catch (e) { res.status(502).json({ ok: false, detail: responseError(e) }); }
}

function switchHistory(site) {
  const db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
  try {
    const latest = db.prepare(`SELECT MAX(s.ts) ts FROM net_port_stats s
      JOIN net_switches d ON d.ip=s.switch_ip WHERE d.site=?`).get(site.code)?.ts || null;
    const ageSeconds = latest ? Math.floor(Date.now() / 1000) - latest : null;
    if (ageSeconds == null || ageSeconds > 1800) return {
      state: 'stale', lastSampleAt: latest && latest * 1000, ageSeconds, ports: [] };
    const rows = db.prepare(`SELECT s.switch_ip,s.ifindex,s.ts,s.in_oct,s.out_oct,
        p.switch,p.port,p.descr,p.speed,d.core FROM net_port_stats s
      JOIN net_switches d ON d.ip=s.switch_ip
      JOIN net_ports p ON p.switch_ip=s.switch_ip AND p.ifindex=s.ifindex
      WHERE d.site=? AND s.ts>=? AND s.in_oct IS NOT NULL AND s.out_oct IS NOT NULL
      ORDER BY s.switch_ip,s.ifindex,s.ts DESC`).all(site.code, latest - 1800);
    const pairs = new Map();
    for (const row of rows) { const key = row.switch_ip + ':' + row.ifindex;
      const pair = pairs.get(key) || []; if (pair.length < 2) pair.push(row); pairs.set(key, pair); }
    const ports = [];
    for (const pair of pairs.values()) { if (pair.length < 2) continue;
      const [a, b] = pair, seconds = a.ts - b.ts, down = a.in_oct - b.in_oct, up = a.out_oct - b.out_oct;
      // netfast runs every 15 min and its run times drift ±15 s; allow one late run, not a missed one.
      if (seconds < 2 || seconds > 1200 || down < 0 || up < 0) continue;
      ports.push({ switchIp: a.switch_ip, switch: a.switch, ifindex: a.ifindex,
        port: a.port, description: a.descr, speedMbps: Number(a.speed) || null,
        core: !!a.core, sampledAt: a.ts * 1000, downMbps: roundedMbps(down, seconds),
        upMbps: roundedMbps(up, seconds) });
    }
    ports.sort((a, b) => (b.downMbps + b.upMbps) - (a.downMbps + a.upMbps));
    if (!ports.length) return { state: 'unpaired', lastSampleAt: latest * 1000, ageSeconds, ports: [],
      reason: 'Recent samples could not be paired into port rates' };
    return { state: 'measured', lastSampleAt: latest * 1000, ageSeconds, ports: ports.slice(0, 12),
      note: 'Per-port rates can duplicate traffic across the switch path; do not add them.' };
  } finally { db.close(); }
}

async function access(req, res) {
  const site = siteOf(req, res); if (!site) return;
  const [switches, wifi] = await Promise.allSettled([
    Promise.resolve().then(() => switchHistory(site)),
    merakiGet(`/networks/${site.network}/clients?timespan=300&perPage=1000`,
      { maxBytes: 5 * 1024 * 1024 }).then(r => {
      if (r.status !== 200 || !Array.isArray(r.body)) throw new Error(`Meraki HTTP ${r.status}`);
      const clients = r.body.filter(c => c.recentDeviceConnection === 'Wireless')
        .map(c => {
          const recvKb = Number(c.usage?.recv) || 0, sentKb = Number(c.usage?.sent) || 0;
          return { user: c.user || null, device: c.description || c.dhcpHostname || null,
            ip: c.ip || null, mac: c.mac || null, ap: c.recentDeviceName || null,
            ssid: c.ssid || null, lastSeen: c.lastSeen || null, recvKb, sentKb,
            downMbps: roundedMbps(recvKb * 1000, 300), upMbps: roundedMbps(sentKb * 1000, 300) };
        }).sort((a, b) => (b.recvKb + b.sentKb) - (a.recvKb + a.sentKb));
      return { windowSeconds: 300, updatedAtMostSeconds: 300, totalClients: clients.length,
        truncated: !!r.hasMore, clients: clients.slice(0, 10),
        note: 'Estimated average from Meraki client usage, treated as kilobytes; recent AP is not a historical attachment.' };
    }),
  ]);
  res.json({ ok: true, site: site.code, name: site.name, checkedAt: Date.now(),
    switches: settle('Switch SNMP', switches), wifi: settle('Meraki clients', wifi) });
}

async function history(req, res) {
  const site = siteOf(req, res); if (!site) return;
  const window = windowOf(req, res); if (!window) return;
  const sourceIp = String(req.query.ip || '').trim();
  const destinationIp = String(req.query.dest || '').trim();
  if (sourceIp && !officeIp(site, sourceIp))
    return res.status(400).json({ ok: false, detail: 'Source must be an on-prem office IPv4 address for this site.' });
  if (destinationIp && !net.isIPv4(destinationIp))
    return res.status(400).json({ ok: false, detail: 'Destination must be an IPv4 address.' });
  const key = `${site.code}:${window.from}:${window.to}:${sourceIp}:${destinationIp}`;
  const hit = historyCache.get(key);
  if (hit && Date.now() - hit.at < 60000) return res.json(hit.body);
  const [forti, meraki, web, switches] = await Promise.allSettled([
    fortiHistory(site, window, sourceIp, destinationIp), merakiHistory(site, window),
    webHistoryShared(site, window, sourceIp), Promise.resolve().then(() => switchHistory(site)),
  ]);
  const body = { ok: true, site: site.code, name: site.name, from: window.from, to: window.to,
    sourceIp: sourceIp || null, destinationIp: destinationIp || null, generatedAt: Date.now(),
    forti: settle('FortiGate', forti), meraki: settle('Meraki', meraki),
    web: settle('Rapid7 web proxy', web), switches: settle('Switch SNMP', switches) };
  // an empty proxy window says how current the feed is (lag vs. a quiet office)
  if (body.web.ok && !body.web.data.matchedEvents)
    body.web.data = { ...body.web.data, latestEventAt: await latestOrNull(site, sourceIp) };
  // A failed or carried-over proxy result is not cached, so Refresh evidence retries it.
  if (body.web.ok && !body.web.data.carried) {
    if (historyCache.size > 30) historyCache.clear();
    historyCache.set(key, { at: Date.now(), body });
  }
  res.json(body);
}

async function resolve(req, res) {
  const site = siteOf(req, res); if (!site) return;
  const q = String(req.query.q || '').trim();
  if (q.length < 2 || q.length > 80 || !/^[\w.@ :+-]+$/.test(q))
    return res.status(400).json({ ok: false, detail: 'Enter a user, device, MAC, IP, switch, or port.' });
  const needle = q.toLowerCase(), macHex = needle.replace(/[^0-9a-f]/g, '');
  const macNeedle = macHex.length === 12 ? macHex.match(/.{2}/g).join(':') : needle;
  const matches = [];
  try {
    const r = await merakiGet(`/networks/${site.network}/clients?timespan=86400&perPage=1000`,
      { maxBytes: 5 * 1024 * 1024 });
    if (r.status === 200 && Array.isArray(r.body)) for (const c of r.body) {
      const fields = [c.ip, c.mac, c.user, c.description, c.dhcpHostname];
      if (fields.some(v => String(v || '').toLowerCase().includes(needle)) ||
          String(c.mac || '').toLowerCase() === macNeedle) matches.push({
        kind: 'client', ip: c.ip || null, mac: c.mac || null, user: c.user || null,
        label: c.description || c.dhcpHostname || c.ip || c.mac,
        attachment: c.recentDeviceName || null,
        observedAt: c.lastSeen ? Number(c.lastSeen) * 1000 : null,
        source: 'Meraki client, last 24h' });
    }
  } catch (_) { /* switch cache and identity search remain usable */ }
  if (q.length >= 3 && !net.isIPv4(q) && !/^[0-9a-f:.-]{12,17}$/i.test(q)) {
    try {
      const window = { from: Date.now() - 86400000, to: Date.now() };
      const leql = `where(user ICONTAINS "${q}" AND ${officeSource(site)}) ` +
        'groupby(source_ip) calculate(sum:incoming_bytes) sort(desc) limit(10)';
      const data = await rapidQuery(leql, window);
      for (const row of data.statistics?.groups || []) {
        const [ip, value] = Object.entries(row)[0] || [];
        if (!officeIp(site, ip)) continue;
        matches.push({ kind: 'proxy-user', ip, label: `${q} · ${ip}`,
          downBytes: Number(value?.sum) || 0, source: 'Recent web proxy user match' });
      }
    } catch (_) { /* other sources still return */ }
  }
  try {
    const db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
    try {
      const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
      const macLike = '%' + macNeedle.replace(/[\\%_]/g, '\\$&') + '%';
      const devices = db.prepare(`SELECT ip,name,last_seen FROM net_switches
        WHERE site=? AND (name LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\') LIMIT 10`)
        .all(site.code, like, like);
      for (const device of devices) matches.push({ kind: 'switch', ip: null,
        switchIp: device.ip, switch: device.name, label: device.name + ' · ' + device.ip,
        observedAt: device.last_seen ? Number(device.last_seen) * 1000 : null,
        source: 'Switch inventory' });
      const rows = db.prepare(`SELECT d.ip switch_ip,d.name switch_name,d.site,p.port,p.descr,p.ifindex,
          c.mac,a.ip client_ip,MAX(COALESCE(c.ts,0),COALESCE(a.ts,0)) observed
        FROM net_switches d LEFT JOIN net_ports p ON p.switch_ip=d.ip
        LEFT JOIN net_cam c ON c.switch_ip=p.switch_ip AND c.ifindex=p.ifindex
        LEFT JOIN net_arp a ON a.mac=c.mac
        WHERE d.site=? AND (p.port LIKE ? ESCAPE '\\' OR p.descr LIKE ? ESCAPE '\\'
          OR c.mac LIKE ? ESCAPE '\\' OR a.ip LIKE ? ESCAPE '\\'
          OR CAST(c.vlan AS TEXT) LIKE ? ESCAPE '\\')
        LIMIT 20`).all(site.code, like, like, macLike, like, like);
      for (const row of rows) { const observedAt = row.observed ? row.observed * 1000 : null;
        const fresh = observedAt && Date.now() - observedAt <= 30 * 60000;
        // A MAC is learned on every port-channel/uplink between it and the core, so only
        // an access port (or the AP port of a Wi-Fi client) is where the device attaches.
        const role = !row.port || /^po/i.test(row.port) || /up-?link|down-?link|trunk/i.test(row.descr || '')
          ? 'transit' : /\bw?ap\d*\b|wap/i.test(row.descr || '') ? 'ap' : 'direct';
        matches.push({ kind: 'switch', role, ip: fresh ? row.client_ip || null : null,
        lastKnownIp: fresh ? null : row.client_ip || null, stale: !fresh,
        mac: row.mac || null, switchIp: row.switch_ip, switch: row.switch_name,
        port: row.port, ifindex: row.ifindex, label: [row.switch_name, row.port, row.descr].filter(Boolean).join(' · '),
        observedAt, source: 'Switch SNMP cache' }); }
    } finally { db.close(); }
  } catch (_) { /* show Meraki matches even if the switch cache is unavailable */ }
  // Identity names may not occur in Meraki; use the existing Investigate view for deeper lookup.
  res.json({ ok: true, query: q, site: site.code, matches: matches.slice(0, 30),
    searched: ['Meraki recent clients', 'web proxy user', 'switch SNMP cache'],
    note: 'Switch matches are historical when the SNMP collector is stale. Verify identity in Investigate.' });
}

module.exports = { live, history, topUsers, pinnedUsers, access, resolve, userSites, domainUsers, _roundedMbps: roundedMbps };
