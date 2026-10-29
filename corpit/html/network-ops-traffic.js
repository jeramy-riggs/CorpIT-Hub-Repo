window.NetworkOpsModules = window.NetworkOpsModules || {};
window.NetworkOpsModules.traffic = function (ctx) {
  'use strict';
  const root = ctx.root, E = ctx.chrome.esc;
  const $ = id => root.querySelector('#' + id);
  let active = true, timer = null, warmTimer = null, historyTimer = null, accessTimer = null, lastKey = '';
  let webRetryTimer = null, webRetries = 0;
  let topCheckAt = 0, topRequest = false, topDataKey = '';
  let accessCheckAt = 0, accessRequest = false, accessSite = '';
  let graph = [], selected = 0, chartGeometry = null, focusAnchor = null, drilling = false;
  let userRequest = 0, domainRequest = 0, streamRequest = 0;
  let selectedGroup = null;
  let pinTimer = null, pinRequest = false, pinData = null, pinKey = '', pinCheckAt = 0, pinFailed = '';
  const timeZone = site => site === 'DFW02' ? 'America/Chicago' : 'America/Los_Angeles';
  const time = (ms, site, options = {}) => new Intl.DateTimeFormat('en-US', {
    timeZone: timeZone(site), month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
    ...options,
  }).format(new Date(ms));
  function zonedMidnight(site, now) {
    const zone = timeZone(site), parts = ms => Object.fromEntries(new Intl.DateTimeFormat('en-US', {
      timeZone: zone, year: 'numeric', month: 'numeric', day: 'numeric',
      hour: 'numeric', minute: 'numeric', hourCycle: 'h23',
    }).formatToParts(new Date(ms)).filter(p => p.type !== 'literal').map(p => [p.type, Number(p.value)]));
    const today = parts(now), target = Date.UTC(today.year, today.month - 1, today.day);
    let guess = target;
    for (let i = 0; i < 2; i++) { const local = parts(guess);
      guess += target - Date.UTC(local.year, local.month - 1, local.day, local.hour, local.minute); }
    return guess;
  }
  const bytes = n => { n = Number(n) || 0; return n >= 1e12 ? (n / 1e12).toFixed(2) + ' TB' :
    n >= 1e9 ? (n / 1e9).toFixed(2) + ' GB' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' MB' :
    n >= 1e3 ? (n / 1e3).toFixed(0) + ' KB' : n + ' B'; };
  const empty = (title, detail) => '<div class="nempty"><b>' + E(title) + '</b>' + E(detail) + '</div>';
  const qs = object => new URLSearchParams(object).toString();
  const serviceGroups = [
    { key: 'streaming', title: 'Streaming', detail: 'TV, video, and music. A site visit or shared media CDN does not establish playback.' },
    { key: 'meetings', title: 'Meetings', detail: 'Calls and collaboration. A general Teams or meeting site label does not establish an active call.' },
    { key: 'webinars', title: 'Webinars', detail: 'Riverside and dedicated webinar platforms. Ordinary Zoom and Teams meetings stay in Meetings.' },
    { key: 'social', title: 'Social media', detail: 'App and site use. A social classification does not establish video or audio streaming.' },
    { key: 'other', title: 'Other', detail: 'Remaining application rows and proxy sites, including generic tunnels. Their inner service or purpose is unconfirmed.' },
  ];
  const services = [
    { group: 'streaming', name: 'Hulu', query: 'hulu.com', app: /^hulu(?: video)?$/i, domains: ['hulu.com'] },
    { group: 'streaming', name: 'Netflix', query: 'netflix.com', app: /^netflix(?: video)?$/i, domains: ['netflix.com', 'nflxvideo.net'] },
    { group: 'streaming', name: 'Disney+', query: 'disneyplus.com', app: /^disney(?:\+| plus)$/i, domains: ['disneyplus.com'] },
    { group: 'streaming', name: 'Prime Video', query: 'primevideo.com', app: /^(?:amazon )?prime video$/i,
      domains: ['primevideo.com'] },
    { group: 'streaming', name: 'HBO Max', query: 'hbomax.com', app: /^hbo max$/i,
      domains: ['hbomax.com'] },
    { group: 'streaming', name: 'Peacock', query: 'peacocktv.com', app: /^peacock(?: tv)?$/i, domains: ['peacocktv.com'] },
    { group: 'streaming', name: 'Paramount+', query: 'paramountplus.com', app: /^paramount(?:\+| plus)$/i,
      domains: ['paramountplus.com'] },
    { group: 'streaming', name: 'Apple TV', query: 'tv.apple.com', field: 'host', app: /^apple tv\+?$/i,
      domains: [] },
    { group: 'streaming', name: 'YouTube TV', query: 'tv.youtube.com', field: 'host', app: /^youtube tv$/i,
      domains: [] },
    { group: 'streaming', name: 'YouTube', query: 'youtube.com', app: /^youtube$/i,
      domains: ['youtube.com', 'googlevideo.com'] },
    { group: 'streaming', name: 'Discovery+', query: 'discoveryplus.com', app: /^discovery(?:\+| plus)$/i,
      domains: ['discoveryplus.com'] },
    { group: 'streaming', name: 'Fubo', query: 'fubo.tv', app: /^fubo(?:tv)?$/i, domains: ['fubo.tv'] },
    { group: 'streaming', name: 'Sling TV', query: 'watch.sling.com', field: 'host', app: /^sling tv$/i,
      domains: ['sling.com'] },
    { group: 'streaming', name: 'Amazon IVS live video', query: 'live-video.net', app: /^amazon ivs$/i, domains: ['live-video.net'] },
    { group: 'streaming', name: 'Twitch', query: 'twitch.tv', app: /^twitch(?:\.tv)?$/i, domains: ['twitch.tv'] },
    { group: 'streaming', name: 'Vimeo', query: 'vimeo.com', app: /^vimeo$/i,
      domains: ['vimeo.com', 'vimeocdn.com'] },
    { group: 'streaming', name: 'Spotify', query: 'spotify.com', app: /^spotify$/i,
      domains: ['spotify.com', 'spotifycdn.com', 'scdn.co'] },
    { group: 'streaming', name: 'Apple Music', query: 'music.apple.com', field: 'host', app: /^apple music$/i, domains: [] },
    { group: 'streaming', name: 'YouTube Music', query: 'music.youtube.com', field: 'host', app: /^youtube music$/i, domains: [] },
    { group: 'streaming', name: 'Amazon Music', query: 'music.amazon.com', field: 'host', app: /^amazon music$/i, domains: [] },
    { group: 'streaming', name: 'Pandora', query: 'pandora.com', app: /^pandora$/i, domains: ['pandora.com'] },
    { group: 'streaming', name: 'SoundCloud', query: 'soundcloud.com', app: /^soundcloud$/i, domains: ['soundcloud.com'] },
    { group: 'meetings', name: 'Zoom', query: 'zoom.us', app: /^zoom meetings$/i, domains: ['zoom.us', 'zoom.com'] },
    { group: 'meetings', name: 'Teams', query: 'teams.microsoft.com', field: 'host', app: /^(?:microsoft teams|ms teams (?:video|audio|app sharing))$/i, domains: [] },
    { group: 'meetings', name: 'Google Meet', query: 'meet.google.com', field: 'host', app: /^google meet$/i, domains: [] },
    { group: 'meetings', name: 'Webex', query: 'webex.com', app: /^webex(?: meetings)?$/i, domains: ['webex.com'] },
    { group: 'meetings', name: 'Skype', query: 'skype.com', app: /^skype$/i, domains: ['skype.com'] },
    { group: 'meetings', name: 'Vonage', query: 'vonage.com', app: /^vonage$/i, domains: ['vonage.com'] },
    { group: 'webinars', name: 'Riverside', query: 'riverside', app: /^riverside(?:\.fm)?$/i, domains: ['riverside.fm', 'riverside.com'] },
    { group: 'webinars', name: 'GoTo Webinar', query: 'gotowebinar.com', app: /^gotowebinar$/i, domains: ['gotowebinar.com'] },
    { group: 'webinars', name: 'ON24', query: 'on24.com', app: /^on24$/i, domains: ['on24.com'] },
    { group: 'webinars', name: 'Livestorm', query: 'livestorm.co', app: /^livestorm$/i, domains: ['livestorm.co'] },
    { group: 'webinars', name: 'BigMarker', query: 'bigmarker.com', app: /^bigmarker$/i, domains: ['bigmarker.com'] },
    { group: 'social', name: 'Instagram', query: 'instagram.com', app: /^instagram$/i, domains: ['instagram.com'] },
    { group: 'social', name: 'Facebook', query: 'facebook.com', app: /^facebook$/i, domains: ['facebook.com'] },
    { group: 'social', name: 'TikTok', query: 'tiktok.com', app: /^tiktok$/i, domains: ['tiktok.com', 'tiktokv.us'] },
    { group: 'social', name: 'Snapchat', query: 'snapchat.com', app: /^snapchat$/i, domains: ['snapchat.com'] },
    { group: 'social', name: 'X / Twitter', query: 'x.com', app: /^twitter$/i, domains: ['x.com', 'twitter.com'] },
    { group: 'social', name: 'LinkedIn', query: 'linkedin.com', app: /^linkedin$/i, domains: ['linkedin.com'] },
    { group: 'social', name: 'Reddit', query: 'reddit.com', app: /^reddit$/i, domains: ['reddit.com'] },
    { group: 'social', name: 'Pinterest', query: 'pinterest.com', app: /^pinterest$/i, domains: ['pinterest.com'] },
    { group: 'social', name: 'Threads', query: 'threads.net', app: /^threads$/i, domains: ['threads.net'] },
  ];
  const criticalServices = [
    { key: 'zoom', name: 'Zoom', query: 'zoom.us', field: 'domain', app: /^zoom meetings$/i,
      domains: ['zoom.us', 'zoom.com'] },
    { key: 'teams', name: 'Teams', query: 'teams.microsoft.com', field: 'host',
      app: /^(?:microsoft teams|ms teams (?:video|audio|app sharing))$/i, domains: [] },
    { key: 'riverside', name: 'Riverside', query: 'riverside', field: 'domain', app: /^riverside(?:\.fm)?$/i,
      domains: ['riverside.fm', 'riverside.com'], split: 'Media and recordings bypass Zscaler from',
      splitHosts: 'riverside.com, app.riverside.com and assets.riverside.fm', splitBytes: 'sign-in and control traffic' },
    { key: 'ivs', name: 'live-video.net', query: 'live-video.net', field: 'domain', app: /^amazon ivs$/i,
      domains: ['live-video.net'], note: 'Amazon IVS · shared CDN', split: 'HLS video bypasses Zscaler from',
      splitHosts: 'player.stats.live-video.net', splitBytes: 'player statistics' },
    { key: 'vonage', name: 'Vonage', query: 'vonage.com', field: 'domain', app: /^vonage$/i,
      domains: ['vonage.com'] },
  ];

  // Zscaler PAC USBased_RS v2 sends Riverside media and *.hls.live-video.net DIRECT from this time.
  const SPLIT_AT = Date.parse('2026-10-29T16:29:00Z');
  function windowBounds(state) {
    if (state.trafficFrom && state.trafficTo) {
      const from = Date.parse(state.trafficFrom), to = Date.parse(state.trafficTo);
      if (Number.isFinite(from) && Number.isFinite(to)) return { from, to };
    }
    const to = Date.now();
    const from = state.trafficWindow === '7d' ? to - 7 * 86400000 :
      state.trafficWindow === '24h' ? to - 86400000 : zonedMidnight(state.site, to);
    // Meraki traffic analysis requires a two-hour lookback.
    return { from: Math.min(from, to - 2 * 3600000), to };
  }
  function keyOf(state) { return [state.site, state.trafficWindow, state.trafficFrom,
    state.trafficTo, state.trafficIp, state.trafficDest].join('|'); }
  function setFocus(patch) { ctx.filters(patch); return loadHistory(); }
  function setStatus(message) { $('tr-source-status').textContent = message; }
  function setGauge(id, value, speed) {
    const gauge = $(id + '-gauge'), output = $(id);
    const measured = Number.isFinite(value) && value >= 0;
    const capacity = Number.isFinite(speed) && speed > 0;
    output.textContent = measured ? value.toFixed(1) : '—';
    const ratio = capacity && measured ? Math.max(0, Math.min(1, value / speed)) : 0;
    gauge.style.setProperty('--gauge-angle', (-90 + 180 * ratio).toFixed(1) + 'deg');
    gauge.classList.toggle('traffic-unknown', !capacity || !measured);
    gauge.classList.toggle('traffic-warn', capacity && measured && ratio >= .7 && ratio < .9);
    gauge.classList.toggle('traffic-hot', capacity && measured && ratio >= .9);
    gauge.querySelectorAll('[data-tr-tick]').forEach(tick => {
      tick.textContent = capacity ? Math.round(speed * Number(tick.dataset.trTick) / 100).toLocaleString() : '—';
    });
    const status = !measured ? 'Sampling live rate' : !capacity ? 'Link speed unknown' :
      ratio >= 1 ? 'At or above link speed' : ratio >= .9 ? 'Near capacity' :
      ratio >= .7 ? 'High use' : 'Within capacity';
    $(id + '-status').textContent = status;
    gauge.setAttribute('aria-label', !measured ? 'WAN rate is warming up; inspect logged traffic' :
      value.toFixed(1) + ' megabits per second' +
      (capacity ? ', ' + Math.round(value / speed * 100) + ' percent of ' +
        speed.toLocaleString() + ' megabits per second link, ' + status.toLowerCase() : '') +
      '; inspect logged traffic');
    $(id + '-meta').textContent = !measured ? 'Waiting for two counter samples' :
      (capacity ? speed.toLocaleString() + ' Mbps link capacity · ' +
        Math.round(value / speed * 100) + '% used' : 'Live counter delta; link speed unavailable');
  }
  async function readLive() {
    const site = ctx.state().site;
    try {
      const d = await ctx.json('/api/netswitch/traffic/live?' + qs({ site }), { fresh: true });
      if (!active || site !== ctx.state().site) return;
      setGauge('tr-down', d.downMbps, d.speedMbps);
      setGauge('tr-up', d.upMbps, d.speedMbps);
      $('tr-meter-time').textContent = d.state === 'warming' ? 'Taking a second counter sample…' :
        d.name + ' · ' + d.interface + ' · ' + Math.round(d.intervalSeconds) + 's sample at ' +
        time(d.sampledAt, site);
      if (d.state === 'warming' && !warmTimer) warmTimer = setTimeout(() => {
        warmTimer = null; if (active) readLive();
      }, 3500);
    } catch (e) {
      if (active) { setGauge('tr-down', null, null); setGauge('tr-up', null, null);
        $('tr-meter-time').textContent = 'WAN counter unavailable: ' + e.message; }
    }
  }
  function startMeter() { stopMeter(); active = true; readLive(); timer = setInterval(readLive, 15000); }
  function stopMeter() { if (timer) clearInterval(timer); if (warmTimer) clearTimeout(warmTimer);
    timer = null; warmTimer = null; }
  function topRefreshStatus(failed = false) {
    const label = $('tr-user-refreshed');
    if (!label) return;
    label.textContent = failed ? (topCheckAt ? 'Update delayed · last good check ' +
      time(topCheckAt, ctx.state().site) : 'Proxy query delayed · retrying automatically') :
      'Auto updates every 60s' + (topCheckAt ? ' · checked ' +
        time(topCheckAt, ctx.state().site) : ' · checking now');
    label.classList.toggle('traffic-refresh-delayed', failed);
  }
  async function refreshTopUsers() {
    if (!active || topRequest || document.hidden) return;
    const state = ctx.state(), key = keyOf(state), window = windowBounds(state);
    topRequest = true;
    try {
      const d = await ctx.json('/api/netswitch/traffic/top-users?' + qs({ site: state.site,
        from: new Date(window.from).toISOString(), to: new Date(window.to).toISOString(),
        ...(state.trafficIp ? { ip: state.trafficIp } : {}) }), { fresh: true });
      if (!active || key !== keyOf(ctx.state()) || key !== lastKey) return;
      renderTopUserRates({ ok: true, data: d }, state, window);
      topCheckAt = Date.now();
      topRefreshStatus();
    } catch (e) {
      if (active && key === keyOf(ctx.state())) {
        if (! $('tr-capacity-users').querySelector('[data-tr-rate-user]'))
          $('tr-capacity-users').innerHTML = empty('User rates unavailable',
            e.message + ' Automatic retry in 60 seconds.');
        topRefreshStatus(true);
      }
    } finally { topRequest = false; }
  }
  function startTopRefresh() {
    stopTopRefresh();
    historyTimer = setInterval(refreshTopUsers, 60000);
    topRefreshStatus();
  }
  function stopTopRefresh() { if (historyTimer) clearInterval(historyTimer); historyTimer = null; }
  document.addEventListener('visibilitychange', () => {
    if (active && !document.hidden && Date.now() - topCheckAt >= 60000) refreshTopUsers();
    if (active && !document.hidden && Date.now() - accessCheckAt >= 120000) loadAccess();
  });

  function renderAccess(d, site) {
    const switchPart = d.switches, wifiPart = d.wifi;
    const switchTarget = $('tr-access-switches'), wifiTarget = $('tr-access-wifi');
    const switchData = switchPart.ok && switchPart.data;
    const ports = (switchData?.ports || []).filter(p => !/span|mirror|monitor/i.test(p.description || '')).slice(0, 5);
    switchTarget.innerHTML = !switchPart.ok ? empty('Switch rates unavailable', switchPart.error) :
      switchData.state === 'stale' ? empty('Switch samples are stale',
        switchData.lastSampleAt ? 'Last sample ' + time(switchData.lastSampleAt, site) : 'No recent counters.') :
      ports.length ? ports.map(p => row(p.switch + ' · ' + p.port,
        [p.description, time(p.sampledAt, site)].filter(Boolean).join(' · '),
        p.downMbps.toFixed(1) + ' in / ' + p.upMbps.toFixed(1) + ' out Mbps',
        'data-tr-access-switch="' + E(p.switchIp) + '" data-tr-access-port="' + E(p.ifindex) +
        '" data-tr-access-port-name="' + E(p.port) + '"')).join('') :
        empty('No paired switch counters', 'Two recent SNMP samples are needed per port.');
    switchTarget.querySelectorAll('[data-tr-access-switch]').forEach(b => b.onclick = () =>
      ctx.navigate({ view: 'switches', site, switch: b.dataset.trAccessSwitch,
        port: b.dataset.trAccessPort, portName: b.dataset.trAccessPortName, panel: 'port' }));
    const clients = (wifiPart.ok && wifiPart.data.clients || []).slice(0, 5);
    wifiTarget.innerHTML = !wifiPart.ok ? empty('Wi-Fi usage unavailable', wifiPart.error) :
      clients.length ? clients.map(c => {
        const label = c.user || c.device || c.ip || c.mac || 'Unidentified client';
        return row(label, [c.ap || 'AP unknown', c.ip, c.device && c.device !== label ? c.device : null]
          .filter(Boolean).join(' · '), c.downMbps.toFixed(1) + ' ↓ / ' + c.upMbps.toFixed(1) + ' ↑ Mbps',
          'data-tr-access-client="' + E(c.mac || c.ip || '') + '"');
      }).join('') : empty('No recent Wi-Fi clients', 'Meraki returned no client usage in the last five minutes.');
    wifiTarget.querySelectorAll('[data-tr-access-client]').forEach(b => b.onclick = () =>
      ctx.search(b.dataset.trAccessClient));
    $('tr-access-time').textContent = 'Checked ' + time(d.checkedAt, site) +
      ' · Meraki client data can update as slowly as every 5 min';
  }
  async function loadAccess() {
    if (!active || accessRequest || document.hidden) return;
    const site = ctx.state().site;
    if (site !== accessSite) {
      accessSite = site;
      $('tr-access-switches').innerHTML = empty('Loading switch rates', 'Reading recent SNMP counter pairs…');
      $('tr-access-wifi').innerHTML = empty('Loading Wi-Fi clients', 'Reading recent Meraki usage…');
    }
    accessRequest = true;
    try {
      const d = await ctx.json('/api/netswitch/traffic/access?' + qs({ site }), { fresh: true });
      if (!active || site !== ctx.state().site) return;
      renderAccess(d, site);
      accessCheckAt = Date.now();
    } catch (e) {
      if (active && site === ctx.state().site) $('tr-access-time').textContent =
        'Access rates unavailable · ' + e.message;
    } finally { accessRequest = false; }
  }
  function startAccess() { stopAccess(); loadAccess(); accessTimer = setInterval(loadAccess, 120000); }
  function stopAccess() { if (accessTimer) clearInterval(accessTimer); accessTimer = null; }

  function row(label, sub, amount, attrs = '') {
    const tag = attrs ? 'button' : 'div';
    return '<' + tag + ' class="traffic-row" ' + (attrs ? 'type="button" ' + attrs : '') + '><span class="traffic-row-main">' +
      '<b>' + E(label) + '</b><small>' + E(sub || '') + '</small></span>' +
      '<strong>' + E(amount) + '</strong></' + tag + '>';
  }
  function clearChartInteraction() {
    const el = $('tr-chart');
    graph = []; chartGeometry = null; focusAnchor = null;
    el.onclick = el.onpointermove = el.onpointerleave = el.onkeydown = null;
    el.removeAttribute('tabindex'); el.removeAttribute('aria-describedby');
    el.setAttribute('role', 'img');
    el.setAttribute('aria-label', 'FortiGate traffic timeline unavailable');
    $('tr-chart-detail').replaceChildren();
  }
  function chartPoints(data) {
    graph = (data || []).filter(p => Number.isFinite(p.ts)).sort((a, b) => a.ts - b.ts);
    const el = $('tr-chart');
    if (!graph.length) { clearChartInteraction();
      el.innerHTML = empty('No FortiView history', 'No logged traffic buckets were returned for this interval.'); return; }
    selected = focusAnchor == null ? graph.length - 1 : graph.reduce((best, p, i) =>
      Math.abs(p.ts - focusAnchor) < Math.abs(graph[best].ts - focusAnchor) ? i : best, 0);
    focusAnchor = null;
    const all = graph.map(p => Math.max(p.downBytes, p.upBytes) / 1e9);
    const max = Math.max(1, ...all), W = 1000, H = 260, left = 52, right = 15, top = 16, bottom = 35;
    const width = W - left - right, height = H - top - bottom;
    const x = i => left + i * width / Math.max(1, graph.length - 1);
    const y = n => top + height - (n / max) * height;
    chartGeometry = { W, H, left, right, top, bottom, x, y };
    const path = field => graph.map((p, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ',' +
      y((Number(p[field]) || 0) / 1e9).toFixed(1)).join(' ');
    let svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" aria-hidden="true">';
    for (const fraction of [0, .5, 1]) { const yy = y(max * fraction);
      svg += '<line class="traffic-grid" x1="' + left + '" y1="' + yy + '" x2="' + (W - right) +
        '" y2="' + yy + '"></line><text class="traffic-axis" x="' + (left - 8) + '" y="' +
        (yy + 4) + '" text-anchor="end">' + (max * fraction).toFixed(max < 10 ? 1 : 0) + '</text>'; }
    svg += '<path class="traffic-line traffic-download" pathLength="1" d="' + path('downBytes') + '"></path>' +
      '<path class="traffic-line traffic-upload" pathLength="1" d="' + path('upBytes') + '"></path>' +
      '<text class="traffic-axis" x="' + left + '" y="' + (H - 5) + '">' +
      E(time(graph[0].ts, ctx.state().site)) + '</text><text class="traffic-axis" x="' +
      (W - right) + '" y="' + (H - 5) + '" text-anchor="end">' +
      E(time(graph[graph.length - 1].ts, ctx.state().site)) + '</text>' +
      '<line class="traffic-cursor" x1="0" x2="0" y1="' + top + '" y2="' +
      (H - bottom) + '"></line><circle class="traffic-cursor-dot down" r="5"></circle>' +
      '<circle class="traffic-cursor-dot up" r="4"></circle></svg>';
    el.innerHTML = svg + '<div class="traffic-chart-tip" hidden></div>';
    el.setAttribute('role', 'button'); el.tabIndex = 0;
    el.setAttribute('aria-describedby', 'tr-chart-note');
    $('tr-graph-grain').textContent = graph.length > 1 ?
      Math.round((graph[1].ts - graph[0].ts) / 60000) + ' min buckets · GB per bucket' : 'GB per bucket';
    $('tr-chart-detail').innerHTML = '<span class="traffic-legend"><i class="down"></i> Download <i class="up"></i> Upload</span>' +
      '<label>Inspect bucket <input type="range" id="tr-point" min="0" max="' + (graph.length - 1) +
      '" value="' + selected + '"></label><span id="tr-point-label"></span>' +
      '<button class="nbtn" type="button" id="tr-focus-time">Drill into 2 hours</button>' +
      (ctx.state().trafficFrom ? '<button class="nbtn" type="button" id="tr-clear-time">Clear time focus</button>' : '');
    $('tr-point').oninput = e => { selected = Number(e.target.value); showPoint(); };
    $('tr-focus-time').onclick = () => focusTime(true);
    if ($('tr-clear-time')) $('tr-clear-time').onclick = () => setFocus({ trafficFrom: '', trafficTo: '' });
    const indexAt = clientX => { const rect = el.getBoundingClientRect();
      const px = (clientX - rect.left) / rect.width * W;
      return Math.max(0, Math.min(graph.length - 1,
        Math.round((px - left) / width * (graph.length - 1)))); };
    const inPlot = clientY => { const rect = el.getBoundingClientRect();
      const py = (clientY - rect.top) / rect.height * H;
      return py >= top - 4 && py <= H - bottom + 4; };
    el.onpointermove = event => { if (!inPlot(event.clientY)) { el.querySelector('.traffic-chart-tip').hidden = true; return; }
      const index = indexAt(event.clientX);
      if (index !== selected) { selected = index; $('tr-point').value = String(index); showPoint(); }
      el.querySelector('.traffic-chart-tip').hidden = false; };
    el.onpointerleave = () => { const tip = el.querySelector('.traffic-chart-tip'); if (tip) tip.hidden = true; };
    el.onclick = event => { if (!inPlot(event.clientY)) return;
      selected = indexAt(event.clientX); $('tr-point').value = String(selected); showPoint(); focusTime(true); };
    el.onkeydown = event => { const step = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0;
      if (step) { event.preventDefault(); selected = Math.max(0, Math.min(graph.length - 1, selected + step));
        $('tr-point').value = String(selected); showPoint(); }
      else if (event.key === 'Home' || event.key === 'End') { event.preventDefault();
        selected = event.key === 'Home' ? 0 : graph.length - 1;
        $('tr-point').value = String(selected); showPoint(); }
      else if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); focusTime(true); } };
    showPoint();
  }
  function showPoint() { const p = graph[selected]; if (!p) return;
    $('tr-point-label').textContent = time(p.ts, ctx.state().site) + ' · ' +
      bytes(p.downBytes) + ' down · ' + bytes(p.upBytes) + ' up';
    const el = $('tr-chart'), g = chartGeometry;
    if (!g) return;
    const xx = g.x(selected), downY = g.y(p.downBytes / 1e9), upY = g.y(p.upBytes / 1e9);
    const cursor = el.querySelector('.traffic-cursor');
    cursor.setAttribute('x1', xx); cursor.setAttribute('x2', xx);
    const down = el.querySelector('.traffic-cursor-dot.down'), up = el.querySelector('.traffic-cursor-dot.up');
    down.setAttribute('cx', xx); down.setAttribute('cy', downY);
    up.setAttribute('cx', xx); up.setAttribute('cy', upY);
    const tip = el.querySelector('.traffic-chart-tip');
    tip.textContent = time(p.ts, ctx.state().site) + ' · ' + bytes(p.downBytes) +
      ' down · ' + bytes(p.upBytes) + ' up · Click to drill';
    tip.style.left = Math.max(105, Math.min(el.clientWidth - 105, xx / g.W * el.clientWidth)) + 'px';
    el.setAttribute('aria-label', 'FortiGate logged traffic. ' +
      time(p.ts, ctx.state().site) + ', ' + bytes(p.downBytes) + ' download, ' +
      bytes(p.upBytes) + ' upload. Press Enter to drill into two hours.'); }
  async function focusTime(reveal = false) { const p = graph[selected]; if (!p || drilling) return;
    drilling = true; focusAnchor = p.ts;
    const to = Math.min(Date.now(), p.ts + 3600000), from = to - 2 * 3600000;
    try { const loaded = await setFocus({ trafficFrom: new Date(from).toISOString(),
      trafficTo: new Date(to).toISOString() });
      if (loaded && reveal) $('tr-users-card').scrollIntoView({ block: 'start', behavior:
        matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    } finally { drilling = false; } }

  function renderForti(part) {
    if (!part.ok) { clearChartInteraction(); $('tr-chart').innerHTML = empty('Firewall history unavailable', part.error);
      $('tr-dest').innerHTML = empty('No firewall destinations', part.error);
      $('tr-sources').innerHTML = empty('No source ranking', part.error); return; }
    const data = part.data;
    chartPoints(data.graph);
    const destinations = data.destinations || [];
    $('tr-dest').innerHTML = destinations.length ? destinations.slice(0, 12).map(d =>
      row(d.ip, d.interface + ' · ' + d.sessions.toLocaleString() + ' sessions',
        bytes(d.downBytes + d.upBytes), 'data-tr-dest="' + E(d.ip) + '"')).join('') :
      empty('No WAN destinations', 'No matching destination records were returned.');
    $('tr-sources').innerHTML = data.sources?.length ? data.sources.slice(0, 12).map(d =>
      row(d.ip || 'Unknown', d.sessions.toLocaleString() + ' sessions',
        bytes(d.downBytes + d.upBytes), 'data-tr-ip="' + E(d.ip || '') + '"')).join('') :
      empty('No source ranking', ctx.state().trafficIp ? 'Source IP filter is active.' : 'No source records were returned.');
    root.querySelectorAll('[data-tr-dest]').forEach(b => b.onclick = () => setFocus({ trafficDest: b.dataset.trDest }));
    root.querySelectorAll('#tr-sources [data-tr-ip]').forEach(b => b.onclick = () => setFocus({ trafficIp: b.dataset.trIp }));
  }
  function renderMeraki(part) {
    $('tr-meraki').innerHTML = !part.ok ? empty('Meraki unavailable', part.error) :
      part.data.entries?.length ? part.data.entries.slice(0, 12).map(d => row(d.application,
        [d.destination, d.protocol && d.port && d.protocol + '/' + d.port,
          d.clients + ' clients'].filter(Boolean).join(' · '),
        (d.downKb + d.upKb).toLocaleString() + ' kb')).join('') :
      empty('No Wi-Fi classifications', 'No application entries in this window.');
  }
  // newest office proxy event, shown when a window comes back empty
  function latestNote(at) {
    const ip = ctx.state().trafficIp, from = ip ? 'from ' + ip : 'office';
    return at ? 'Latest ' + (ip ? 'proxy event ' + from : 'office proxy event') + ': ' + time(at, ctx.state().site) + '.' :
      'No ' + (ip ? 'proxy events ' + from : 'office proxy events') + ' in the last 24 hours.';
  }
  function renderWeb(part) {
    const carried = part.ok && part.data.carried;
    const quiet = part.ok && !part.data.matchedEvents && 'latestEventAt' in part.data ? ' ' + latestNote(part.data.latestEventAt) : '';
    $('tr-web').innerHTML = !part.ok ? empty('Proxy logs unavailable', part.error) :
      '<p class="traffic-count">' + E(part.data.matchedEvents == null ? 'Event count unavailable' :
        part.data.matchedEvents.toLocaleString() + ' office-source log events' + quiet) + '</p>' +
      (carried ? '<p class="traffic-note traffic-carried">' + E('Showing the proxy result from ' +
        time(carried.at, ctx.state().site) + ' for this window. ' + carried.reason) + '</p>' : '') +
      (part.data.domains?.length ? rankedRows(part.data.domains, d => row(d.domain || 'Unknown domain',
        'Observed download', bytes(d.downBytes)), 'sites') :
        empty('No matching domains', 'The proxy feed may not cover this traffic.')) +
      '<details class="traffic-more traffic-hosts"><summary>Exact website hosts in observed Zscaler traffic</summary>' +
      '<p class="traffic-note">Select a host to see its recorded users. This is partial web-log evidence, not every site inside the tunnel.</p>' +
      (part.data.hosts?.length ? rankedRows(part.data.hosts, h => row(h.host,
        'Observed download · inspect users', bytes(h.downBytes), 'data-tr-host="' + E(h.host) + '"'), 'hosts') :
        empty('No exact hosts', 'The proxy feed did not return host detail for this window.')) + '</details>';
    $('tr-users').innerHTML = !part.ok ? empty('User ranking unavailable', part.error) :
      part.data.users?.length ? rankedRows(part.data.users, d =>
        row(d.user || 'Unidentified', 'Observed proxy download', bytes(d.downBytes),
          'data-tr-user="' + E(d.user || '') + '"'), 'users') :
        empty('No observed users', 'The proxy feed may not cover this interval or source.' + quiet);
    $('tr-user-sites').innerHTML = empty('Select a user', 'See the sites recorded for that user in this window.');
    root.querySelectorAll('[data-tr-user]').forEach(b => b.onclick = () => loadUserSites(b.dataset.trUser));
    root.querySelectorAll('[data-tr-host]').forEach(b => b.onclick = () => {
      $('tr-domain').value = b.dataset.trHost;
      $('tr-domain-field').value = 'host';
      searchDomain(null, b.dataset.trHost, 'host');
    });
  }
  function renderTopUserRates(part, state, window) {
    const target = $('tr-capacity-users');
    if (!part.ok) { target.innerHTML = empty('Checking proxy users',
      part.error + ' Trying the user-only query.'); return; }
    const seconds = (window.to - window.from) / 1000;
    const users = (part.data.users || []).filter(u => u.user && Number(u.downBytes) > 0).slice(0, 5);
    const maxBytes = Math.max(1, ...users.map(u => Number(u.downBytes)));
    target.innerHTML = users.length ? users.map(u => {
      const mbps = Number(u.downBytes) * 8 / seconds / 1e6;
      const rate = mbps < 0.1 ? '&lt;0.1' : mbps.toFixed(1);
      const share = Math.max(2, Math.round(Number(u.downBytes) / maxBytes * 100));
      return '<button class="traffic-user-rate" type="button" style="--rate-share:' + share + '%" data-tr-rate-user="' + E(u.user) + '">' +
        '<span class="traffic-user-rate-name"><b>' + E(u.user) + '</b><small>' +
        E(bytes(u.downBytes)) + ' observed</small></span><strong>' + rate +
        '<small>Mbps</small></strong></button>';
    }).join('') : empty('No observed users', 'The proxy feed did not return user bytes in this window.');
    topDataKey = keyOf(state);
    $('tr-capacity-scope').textContent = 'On-prem office source IPs · partial Zscaler web logs · selected-window average' +
      (state.trafficDest ? ' · firewall destination focus does not narrow this list.' :
        ' · not total WAN user speed.');
    target.querySelectorAll('[data-tr-rate-user]').forEach(b => b.onclick = () => {
      loadUserSites(b.dataset.trRateUser);
      $('tr-users-card').scrollIntoView({ block: 'center', behavior:
        matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    });
  }
  function rankedRows(items, render, label) {
    const rows = items.slice(0, 12).map(render);
    return rows.slice(0, 5).join('') + (rows.length > 5 ?
      '<details class="traffic-more"><summary>Show ' + (rows.length - 5) +
      ' more ' + E(label) + '</summary>' + rows.slice(5).join('') + '</details>' : '');
  }
  function qualityItem(name, state, detail, tone) {
    return '<div class="traffic-quality-row"><span class="traffic-quality-dot ' + E(tone) + '"></span>' +
      '<div><b>' + E(name) + '</b><small>' + E(state + ' · ' + detail) + '</small></div></div>';
  }
  function renderBrief(d, state) {
    const forti = d.forti.ok && d.forti.data.destinations?.[0];
    const user = d.web.ok && d.web.data.users?.[0];
    const domain = d.web.ok && d.web.data.domains?.[0];
    $('tr-brief-dest').textContent = forti?.ip || 'Unavailable';
    $('tr-brief-dest-volume').textContent = forti ?
      bytes(forti.downBytes + forti.upBytes) + ' office-sourced WAN bytes' : 'No matching firewall destination';
    $('tr-brief-user').textContent = user?.user || 'Unavailable';
    $('tr-brief-user-volume').textContent = user ? bytes(user.downBytes) + ' observed download' :
      'No proxy user in this window';
    $('tr-brief-domain').textContent = domain?.domain || 'Unavailable';
    $('tr-brief-domain-volume').textContent = domain ? bytes(domain.downBytes) + ' observed download' :
      'No proxy site in this window';
    $('tr-brief-scope').textContent = state.trafficDest ?
      'Destination focus applies to the firewall. Proxy user and site rankings remain site-wide; Meraki remains Wi-Fi-wide.' :
      state.trafficIp ? 'Source focus applies to the firewall and proxy rankings. Meraki remains Wi-Fi-wide.' :
      'Office-inside firewall bytes, office-source proxy downloads, and local AP application units have different scopes; do not add them.';
    const switchData = d.switches.ok && d.switches.data;
    const buckets = d.forti.ok ? d.forti.data.graph || [] : [];
    $('tr-quality').innerHTML =
      qualityItem('Firewall', d.forti.ok ? 'Available' : 'Unavailable',
        d.forti.ok ? buckets.length + ' office-inside WAN buckets' +
          (buckets.length ? '; last ' + time(buckets[buckets.length - 1].ts, state.site) : '') :
          d.forti.error, d.forti.ok ? 'good' : 'bad') +
      qualityItem('Meraki', d.meraki.ok ? 'Available' : 'Unavailable',
        d.meraki.ok ? (d.meraki.data.totalEntries ?? d.meraki.data.entries?.length ?? 0) +
          ' local AP Wi-Fi records; overlapping categories' : d.meraki.error,
        d.meraki.ok ? 'good' : 'bad') +
      qualityItem('Zscaler proxy', !d.web.ok ? 'Unavailable' : d.web.data.carried ? 'Earlier result' : 'Partial',
        d.web.ok ? (d.web.data.matchedEvents?.toLocaleString() || 'Unknown count') +
          ' office-source events' + (d.web.data.carried ? ' from the query at ' +
            time(d.web.data.carried.at, state.site) + '; the latest did not finish' :
            '; user and site rankings are limited') : d.web.error,
        d.web.ok ? 'warn' : 'bad') +
      (d.web.ok ? qualityItem('Proxy timing', 'Provisional',
        'recent closed windows can change as logs arrive', 'warn') : '') +
      qualityItem('Switch SNMP', switchData?.state === 'measured' ? 'Available' :
        switchData?.state === 'stale' ? 'Stale' : 'Unavailable',
        switchData?.state === 'stale' && switchData.lastSampleAt ?
          'last sample ' + time(switchData.lastSampleAt, state.site, { year: 'numeric' }) :
          switchData?.state === 'measured' ? 'fresh paired port counters' :
          switchData?.reason || d.switches.error || 'No usable samples',
        switchData?.state === 'measured' ? 'good' : 'warn');
  }
  function renderCritical(d) {
    const apps = d.meraki.ok ? d.meraki.data.streaming || [] : [];
    const sites = d.web.ok ? d.web.data.streamingDomains || [] : [];
    $('tr-critical-apps').innerHTML = criticalServices.map((service, index) => {
      const appRows = apps.filter(row => service.app.test(row.application || ''));
      const siteRows = sites.filter(row => service.domains.includes(row.domain));
      const clients = Math.max(0, ...appRows.map(row => Number(row.clients) || 0));
      const siteBytes = siteRows.reduce((n, row) => n + (Number(row.downBytes) || 0), 0);
      const signal = appRows.length && siteRows.length ? 'Wi-Fi app and proxy site signal' :
        appRows.length ? 'Wi-Fi app signal' : siteRows.length ? 'Proxy site signal' :
        !d.meraki.ok && !d.web.ok ? 'Sources unavailable' : 'No ranked signal';
      const detail = [appRows.length ? 'Wi-Fi: ' + clients + (clients === 1 ? ' client' : ' clients') + ' (Meraki)' :
          d.meraki.ok ? 'Wi-Fi: no app rows' : '',
        siteRows.length ? 'Proxy: ' + bytes(siteBytes) + ' download' : ''].filter(Boolean).join(' · ') ||
        'Open a focused site check';
      return '<div class="traffic-critical-item"><button type="button" class="traffic-critical-tile' +
        (appRows.length || siteRows.length ? ' observed' : '') +
        '" data-tr-critical="' + index + '"><b>' + E(service.name) + '</b>' +
        (service.note ? '<em>' + E(service.note) + '</em>' : '') + '<span>' +
        E(signal) + '</span><small>' + E(detail) + '</small></button>' +
        '<div class="traffic-pin-users" data-tr-pin="' + E(service.key) + '" aria-live="polite"></div></div>';
    }).join('');
    renderPinned();
    $('tr-critical-apps').querySelectorAll('[data-tr-critical]').forEach(button => button.onclick = () => {
      const service = criticalServices[Number(button.dataset.trCritical)];
      $('tr-stream-query').value = service.query;
      $('tr-stream-field').value = service.field;
      lookupStreaming(service.query, service.field);
      $('tr-stream-card').scrollIntoView({ block: 'start', behavior:
        matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    });
  }
  function pinWindow(state) {
    if (state.trafficFrom && state.trafficTo) return { ...windowBounds(state), focused: true };
    const to = Date.now(); return { from: to - 30 * 60000, to, focused: false };
  }
  function renderPinned() {
    const state = ctx.state(), window = pinWindow(state);
    const label = $('tr-pin-status');
    if (label) {
      label.textContent = (window.focused ? 'Users in the focused window' : 'Users active in the last 30 min') +
        ' · office proxy logs, can lag a few minutes · ' +
        (pinData && pinKey === keyOf(state) && 'latestEventAt' in pinData ? (pinData.latestEventAt ?
          'latest proxy event ' + time(pinData.latestEventAt, state.site) : 'no proxy events in 24 h') + ' · ' : '') + (pinFailed ? (pinCheckAt ? 'update delayed · last good check ' +
        time(pinCheckAt, state.site) : 'proxy query delayed · retrying') : pinCheckAt ? 'auto updates every 60s · checked ' +
        time(pinCheckAt, state.site) : 'checking now');
      label.classList.toggle('traffic-refresh-delayed', !!pinFailed);
    }
    root.querySelectorAll('[data-tr-pin]').forEach(box => {
      const found = pinData && pinKey === keyOf(state) ? (pinData.services || []).find(x => x.key === box.dataset.trPin) : null;
      if (!found) { box.innerHTML = '<p class="traffic-pin-empty">' + E(pinFailed && !pinData ? 'Users unavailable' : 'Reading users…') + '</p>'; return; }
      const service = criticalServices.find(x => x.key === box.dataset.trPin);
      const split = service && service.split && window.to > SPLIT_AT ? '<p class="traffic-pin-split">' +
        E(service.split + ' ' + time(SPLIT_AT, state.site) + '. Users still show from ' + service.splitHosts +
          '; sizes after that are ' + service.splitBytes + ', not video.') + '</p>' : '';
      if (!found.users.length) { box.innerHTML = '<p class="traffic-pin-empty">No users in proxy logs</p>' + split; return; }
      const shown = found.users.slice(0, 6);
      box.innerHTML = '<p class="traffic-pin-count">' + found.users.length + (found.users.length === 1 ? ' user' : ' users') +
        (found.users.length === 25 ? '+' : '') + '</p><ul>' + shown.map(u => '<li><button type="button" data-tr-pin-user="' +
        E(u.user) + '" title="Show sites recorded for ' + E(u.user) + '"><span>' + E(u.user) + '</span><small>' +
        E(bytes(u.downBytes)) + '</small></button></li>').join('') + '</ul>' +
        (found.users.length > shown.length ? '<p class="traffic-pin-more">+' + (found.users.length - shown.length) +
          ' more · open the tile for the full list</p>' : '') + split;
      box.querySelectorAll('[data-tr-pin-user]').forEach(b => b.onclick = () => {
        loadUserSites(b.dataset.trPinUser);
        $('tr-users-card').scrollIntoView({ block: 'center', behavior:
          matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
      });
    });
  }
  async function loadPinned() {
    if (!active || pinRequest || document.hidden) return;
    const state = ctx.state(), key = keyOf(state), window = pinWindow(state);
    pinRequest = true;
    try {
      const d = await ctx.json('/api/netswitch/traffic/pinned-users?' + qs({ site: state.site,
        from: new Date(window.from).toISOString(), to: new Date(window.to).toISOString(),
        ...(state.trafficIp ? { ip: state.trafficIp } : {}) }), { fresh: true });
      if (!active || key !== keyOf(ctx.state())) return;
      pinData = d; pinKey = key; pinCheckAt = Date.now(); pinFailed = '';
    } catch (e) {
      if (key === keyOf(ctx.state())) pinFailed = e.message || 'failed';
    } finally { pinRequest = false; if (active) renderPinned(); }
  }
  function startPinned() { stopPinned(); loadPinned(); pinTimer = setInterval(loadPinned, 60000); }
  function stopPinned() { if (pinTimer) clearInterval(pinTimer); pinTimer = null; }
  function renderStreaming(d) {
    const apps = d.meraki.ok ? d.meraki.data.streaming || [] : [];
    const sites = d.web.ok ? d.web.data.streamingDomains || [] : [];
    const evidence = group => ({ apps: apps.filter(x => x.category === group.key),
      sites: sites.filter(x => x.category === group.key) });
    const cards = serviceGroups.map(group => {
      const found = evidence(group);
      const namedApps = found.apps.filter(x => group.key === 'other' || group.key === 'social' ||
        x.signal === 'Meraki application');
      const examples = [...namedApps.slice(0, 3).map(x => x.application),
        ...found.sites.slice(0, 3).map(x => x.domain),
        ...found.apps.slice(0, 3).map(x => x.destination)].filter(Boolean);
      const sample = [...new Set(examples)].slice(0, 3).join(' · ') ||
        (group.key === 'webinars' ? 'No ranked signal; check Riverside.fm' :
          'No named signal in ranked data');
      const open = selectedGroup === group.key;
      const count = found.apps.length + ' Wi-Fi ' + (found.apps.length === 1 ? 'row' : 'rows') +
        ' · ' + found.sites.length + ' proxy ' + (found.sites.length === 1 ? 'site' : 'sites');
      return '<button type="button" class="traffic-category-card' + (open ? ' selected' : '') +
        '" data-tr-group="' + E(group.key) + '" aria-expanded="' + open +
        '" aria-controls="tr-category-detail"><span class="traffic-category-card-top"><b>' +
        E(group.title) + '</b><span>' + (open ? 'Close' : 'Inspect') + '</span></span><strong>' +
        E(count) +
        '</strong><small>' + E(sample) + '</small></button>';
    }).join('');
    let detail = '';
    const group = serviceGroups.find(x => x.key === selectedGroup);
    if (group) {
      const found = evidence(group);
      const options = services.map((service, index) => service.group === group.key ?
        '<option value="' + index + '">' + E(service.name) + '</option>' : '').join('');
      detail = '<section class="traffic-category-detail" id="tr-category-detail" aria-label="' +
        E(group.title + ' details') + '"><div class="traffic-category-head"><div><h3>' +
        E(group.title) + '</h3><p class="traffic-note">' + E(group.detail) + '</p></div></div>' +
        (options ? '<form id="tr-category-service-form" class="traffic-category-service-form"><label for="tr-group-service">Check a service</label><select id="tr-group-service" class="op-input">' +
          options + '</select><button class="nbtn" type="submit">Check users</button></form>' :
          '<p class="traffic-note">Use the custom site or host lookup below to inspect a specific service.</p>') +
        '<div class="traffic-category-evidence"><div><h4>Wi-Fi classifications' +
        (found.apps.length > 12 ? ' <small>Top 12 of ' + found.apps.length + '</small>' : '') + '</h4>' +
        (!d.meraki.ok ? empty('Meraki unavailable', d.meraki.error) : found.apps.length ?
          rankedRows(found.apps, x => row(x.application,
            [x.destination, x.clients + (x.clients === 1 ? ' client' : ' clients'),
              x.signal].filter(Boolean).join(' · '),
            (x.downKb + x.upKb).toLocaleString() + ' kb'), 'apps') :
          empty('No named app in this window', 'Generic tunnels do not identify the service.')) +
        '</div><div><h4>Observed proxy sites' +
        (found.sites.length > 12 ? ' <small>Top 12 of ' + found.sites.length + '</small>' : '') + '</h4>' +
        (!d.web.ok ? empty('Proxy unavailable', d.web.error) : found.sites.length ?
          rankedRows(found.sites, x => row(x.domain, x.signal, bytes(x.downBytes),
            'data-tr-stream-domain="' + E(x.domain) + '"'), 'sites') :
          empty('No ranked site match', 'Only the largest 200 proxy domains are checked here.')) +
        '</div></div></section>';
    }
    $('tr-category-groups').innerHTML = '<div class="traffic-category-list">' + cards +
      '</div>' + (detail || '<div id="tr-category-detail" hidden></div>');
    root.querySelectorAll('[data-tr-group]').forEach(b => b.onclick = () => {
      selectedGroup = selectedGroup === b.dataset.trGroup ? null : b.dataset.trGroup;
      renderStreaming(d);
    });
    const serviceForm = $('tr-category-service-form');
    if (serviceForm) serviceForm.onsubmit = event => { event.preventDefault();
      const service = services[Number($('tr-group-service').value)];
      if (service) lookupStreaming(service.query, service.field || 'domain', true);
    };
    $('tr-stream-status').textContent = apps.length + ' Wi-Fi rows · ' + sites.length + ' proxy sites';
    root.querySelectorAll('[data-tr-stream-domain]').forEach(b => b.onclick = () =>
      lookupStreaming(b.dataset.trStreamDomain, 'domain', true));
  }
  async function lookupStreaming(query, field, reveal = false) {
    query = String(query || '').trim().toLowerCase();
    if (query.length < 2) return;
    field = field === 'host' ? 'host' : 'domain';
    $('tr-stream-query').value = query; $('tr-stream-field').value = field;
    const seq = ++streamRequest, state = ctx.state(), window = windowBounds(state);
    $('tr-stream-results').innerHTML = empty('Checking ' + query,
      'Reading observed proxy users for this ' + (field === 'host' ? 'exact host' : 'site family') + '…');
    try {
      const d = await ctx.json('/api/netswitch/traffic/domain-users?' + qs({ site: state.site,
        from: new Date(window.from).toISOString(), to: new Date(window.to).toISOString(),
        domain: query, field, ...(state.trafficIp ? { ip: state.trafficIp } : {}) }), { fresh: true });
      if (seq !== streamRequest || !active) return;
      const count = d.matchedEvents == null ? 'Event count unavailable' :
        d.matchedEvents.toLocaleString() + ' matched events';
      $('tr-stream-results').innerHTML = '<div class="traffic-stream-result"><h4>' + E(query) +
        ' · ' + (field === 'host' ? 'exact host' : 'site family') + '</h4><p class="traffic-note">' +
        E(count + ' · office source IPs · partial proxy coverage' + (state.trafficIp ? ' · source ' + state.trafficIp :
          state.trafficDest ? ' · site-wide under destination focus' : '')) + '</p>' +
        (d.users?.length ? rankedRows(d.users, x => row(x.user || 'Unidentified',
          'Observed download', bytes(x.downBytes),
          'data-tr-stream-user="' + E(x.user || '') + '"'), 'users') :
          empty('No proxy records returned', 'This does not prove the service was unused.')) + '</div>';
      root.querySelectorAll('[data-tr-stream-user]').forEach(b => b.onclick = () => {
        loadUserSites(b.dataset.trStreamUser);
        $('tr-users-card').scrollIntoView({ block: 'center', behavior:
          matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
      });
      if (reveal) $('tr-stream-results').scrollIntoView({ block: 'nearest', behavior:
        matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    } catch (e) { if (seq === streamRequest) $('tr-stream-results').innerHTML =
      empty('Streaming lookup unavailable', e.message); }
  }
  async function loadUserSites(user) {
    if (!user) return;
    const seq = ++userRequest, state = ctx.state(), window = windowBounds(state);
    $('tr-user-sites').innerHTML = empty('Loading ' + user, 'Reading observed proxy domains…');
    try {
      const d = await ctx.json('/api/netswitch/traffic/user-sites?' + qs({ site: state.site,
        from: new Date(window.from).toISOString(), to: new Date(window.to).toISOString(), user,
        ...(state.trafficIp ? { ip: state.trafficIp } : {}) }), { fresh: true });
      if (seq !== userRequest) return;
      $('tr-user-sites').innerHTML = '<h3>' + E(user) + ' · observed sites</h3>' +
        (state.trafficIp ? '<p class="traffic-note">Source ' + E(state.trafficIp) + '</p>' : '') +
        (d.domains?.length ? d.domains.map(x => row(x.domain || 'Unknown domain',
          'Observed download', bytes(x.downBytes))).join('') :
          empty('No domains returned', 'The web proxy feed has no site breakdown for this user.'));
    } catch (e) { if (seq === userRequest) $('tr-user-sites').innerHTML = empty('Site lookup unavailable', e.message); }
  }
  function renderSwitch(part) {
    if (!part.ok) { $('tr-switches').innerHTML = empty('Switch cache unavailable', part.error); return; }
    const d = part.data;
    if (d.state === 'stale') { $('tr-switches').innerHTML = empty('Switch samples are stale',
      d.lastSampleAt ? 'Last sample ' + time(d.lastSampleAt, ctx.state().site) + '. No live switch rate is shown.' :
        'The collector has no samples for this site.'); return; }
    $('tr-switches').innerHTML = d.ports?.length ? d.ports.map(p => row(p.switch + ' · ' + p.port,
      [p.description, p.core ? 'core' : null, time(p.sampledAt, ctx.state().site)].filter(Boolean).join(' · '),
      p.downMbps.toFixed(1) + ' in / ' + p.upMbps.toFixed(1) + ' out Mbps',
      'data-tr-switch="' + E(p.switchIp) + '" data-tr-port="' + E(p.ifindex) +
      '" data-tr-port-name="' + E(p.port) + '"')).join('') :
      empty('No paired switch samples', 'Two fresh octet counter samples are needed per port.');
    root.querySelectorAll('[data-tr-switch]').forEach(b => b.onclick = () => ctx.navigate({ view: 'switches',
      site: ctx.state().site, switch: b.dataset.trSwitch, port: b.dataset.trPort,
      portName: b.dataset.trPortName, panel: 'port' }));
  }
  async function loadHistory() {
    const state = ctx.state(), key = keyOf(state), window = windowBounds(state);
    if (key !== lastKey) { topCheckAt = 0; webRetries = 0; }
    lastKey = key;
    ++userRequest; ++domainRequest; ++streamRequest;
    $('tr-domain-results').replaceChildren();
    $('tr-stream-results').replaceChildren();
    $('tr-window').value = state.trafficFrom && state.trafficTo ? 'focus' : state.trafficWindow;
    $('tr-reset').hidden = !state.trafficFrom && !state.trafficIp && !state.trafficDest;
    $('tr-window-note').textContent = time(window.from, state.site) + ' – ' + time(window.to, state.site) +
      (state.trafficIp ? ' · source ' + state.trafficIp : '') +
      (state.trafficDest ? ' · destination ' + state.trafficDest : '');
    setStatus('Loading source comparison…');
    try {
      const d = await ctx.json('/api/netswitch/traffic/history?' + qs({ site: state.site,
        from: new Date(window.from).toISOString(), to: new Date(window.to).toISOString(),
        ...(state.trafficIp ? { ip: state.trafficIp } : {}),
        ...(state.trafficDest ? { dest: state.trafficDest } : {}) }), { fresh: true });
      if (key !== lastKey) return false;
      renderForti(d.forti); renderMeraki(d.meraki); renderWeb(d.web);
      if (d.web.ok || topDataKey !== key || !$('tr-capacity-users').querySelector('[data-tr-rate-user]'))
        renderTopUserRates(d.web, state, window);
      renderSwitch(d.switches);
      if (d.web.ok) topCheckAt = Date.now();
      topRefreshStatus(!d.web.ok);
      if (!d.web.ok) refreshTopUsers();
      renderBrief(d, state); renderStreaming(d); renderCritical(d);
      const streamQuery = $('tr-stream-query').value;
      if (streamQuery) lookupStreaming(streamQuery, $('tr-stream-field').value);
      $('tr-heading').textContent = 'On-prem traffic at ' + d.name;
      const currentSwitch = d.switches.ok && d.switches.data?.state === 'measured';
      const freshCount = [d.forti, d.meraki, d.web].filter(p => p.ok).length + (currentSwitch ? 1 : 0);
      setStatus(freshCount + ' feeds returned' + (d.switches.ok && !currentSwitch ?
        (d.switches.data?.state === 'stale' ? ' · switch stale' : ' · no switch rates') : '') +
        (d.web.ok ? (d.web.data.carried ? ' · proxy from ' + time(d.web.data.carried.at, state.site) :
          ' · proxy partial') : ''));
      // Rapid7 keeps running a long query after the hub answers; read it once more when it should be done.
      clearTimeout(webRetryTimer);
      if (d.web.ok && !d.web.data.carried) webRetries = 0;
      else if ((d.web.pending || d.web.ok) && webRetries < 3) {
        webRetries++;
        webRetryTimer = setTimeout(() => { if (key === lastKey && !document.hidden) loadHistory(); }, 30000);
      }
      ctx.chrome.stamp('Traffic evidence · ' + time(d.generatedAt, state.site), freshCount < 4);
      ctx.chrome.vitals([{ k: 'Site', v: d.name }, { k: 'Usable layers', v: freshCount + '/4' },
        { k: 'Window', v: state.trafficFrom ? '2 hours' : state.trafficWindow === '7d' ? '7 days' : state.trafficWindow === '24h' ? '24 hours' : 'Today' }]);
      return true;
    } catch (e) {
      if (key === lastKey) { setStatus('Traffic evidence unavailable'); clearChartInteraction();
        $('tr-chart').innerHTML = empty('Traffic evidence unavailable', e.message);
        topRefreshStatus(true); refreshTopUsers(); }
      return false;
    }
  }
  async function search(event) {
    event.preventDefault(); const q = $('tr-query').value.trim(); if (q.length < 2) return;
    $('tr-search-results').innerHTML = empty('Searching', 'Checking recent Wi-Fi, web proxy, and switch records…');
    try {
      const d = await ctx.json('/api/netswitch/traffic/resolve?' + qs({ site: ctx.state().site, q }), { fresh: true });
      const seen = new Set(), matches = (d.matches || []).filter(m => {
        const key = [m.kind, m.ip, m.mac, m.switchIp, m.port].join('|');
        if (seen.has(key)) return false; seen.add(key); return true; });
      // uplinks and port-channels that learned the MAC are transit evidence, not extra connections
      const shown = matches.slice(0, 20), transit = shown.filter(m => m.role === 'transit');
      const where = { direct: 'direct attachment', ap: 'AP port · Wi-Fi client behind this AP', transit: 'transit uplink' };
      const line = m => row(m.label || m.ip || m.mac,
          [where[m.role], m.ip, m.lastKnownIp ? 'last known IP ' + m.lastKnownIp : null, m.mac, m.user,
            m.source, m.stale ? 'stale' : null,
            m.observedAt ? 'observed ' + time(m.observedAt, ctx.state().site) : null]
            .filter(Boolean).join(' · '), m.ip ? 'View traffic' : 'Inspect',
          'data-tr-result="' + matches.indexOf(m) + '"');
      const primary = shown.filter(m => m.role !== 'transit');
      $('tr-search-results').innerHTML = '<div class="traffic-search-results"><h3>' +
        E(primary.length + (primary.length === 1 ? ' matching path' : ' matching paths') +
          (transit.length ? ' · ' + transit.length + ' transit ' + (transit.length === 1 ? 'uplink' : 'uplinks') : '')) + '</h3>' +
        (shown.length ? primary.map(line).join('') +
          (transit.length ? '<details><summary>' + E(transit.length + (transit.length === 1 ? ' uplink also learned' : ' uplinks also learned') +
            ' this MAC on the way to the core. They are not separate connections.') + '</summary>' +
            transit.map(line).join('') + '</details>' : '') :
          '<p>No direct path found in recent clients or the switch cache.</p>') +
        '<button class="nbtn" type="button" id="tr-deep-search">Investigate identity and device</button></div>';
      root.querySelectorAll('[data-tr-result]').forEach(b => b.onclick = () => {
        const m = matches[Number(b.dataset.trResult)];
        if (m.ip) setFocus({ trafficIp: m.ip, trafficDest: '' });
        else if (m.switchIp) ctx.navigate({ view: 'switches', site: ctx.state().site,
          switch: m.switchIp, ...(m.ifindex ? { port: m.ifindex, portName: m.port, panel: 'port' } : {}) });
        else ctx.search(q);
      });
      $('tr-deep-search').onclick = () => ctx.search(q);
    } catch (e) { $('tr-search-results').innerHTML = empty('Search unavailable', e.message); }
  }

  async function searchDomain(event, selectedHost, selectedField) {
    event?.preventDefault(); const domain = (selectedHost || $('tr-domain').value).trim();
    if (domain.length < 2) return;
    const field = selectedField || $('tr-domain-field').value;
    const seq = ++domainRequest;
    const state = ctx.state(), window = windowBounds(state);
    $('tr-domain-results').innerHTML = empty('Searching ' + domain, 'Checking the observed proxy feed…');
    try {
      const d = await ctx.json('/api/netswitch/traffic/domain-users?' + qs({ site: state.site,
        from: new Date(window.from).toISOString(), to: new Date(window.to).toISOString(), domain, field,
        ...(state.trafficIp ? { ip: state.trafficIp } : {}) }), { fresh: true });
      if (seq !== domainRequest) return;
      $('tr-domain-results').innerHTML = '<div class="traffic-domain-result"><h3>' + E(domain) +
        ' · observed users</h3><p class="traffic-note">' +
        (state.trafficIp ? 'Source ' + E(state.trafficIp) + ' · ' : '') + E(d.matchedEvents == null ?
          'Event count unavailable' : d.matchedEvents.toLocaleString() + ' matched log events') +
        ' · ' + E(field === 'host' ? 'exact host' : 'site family') + ' · office source IPs · partial proxy coverage</p>' + (d.users?.length ? d.users.map(u => row(u.user ||
          'Unidentified', 'Observed download', bytes(u.downBytes), 'data-tr-domain-user="' +
          E(u.user || '') + '"')).join('') : empty('No records found',
          'A missing domain in this feed does not prove the site was unused.')) + '</div>';
      root.querySelectorAll('[data-tr-domain-user]').forEach(b => b.onclick = () => loadUserSites(b.dataset.trDomainUser));
    } catch (e) { if (seq === domainRequest) $('tr-domain-results').innerHTML =
      empty('Site lookup unavailable', e.message); }
  }

  $('tr-search-form').addEventListener('submit', search);
  $('tr-domain-form').addEventListener('submit', searchDomain);
  $('tr-stream-form').addEventListener('submit', e => { e.preventDefault();
    lookupStreaming($('tr-stream-query').value, $('tr-stream-field').value); });
  $('tr-window').onchange = e => setFocus({ trafficWindow: e.target.value,
    trafficFrom: '', trafficTo: '' });
  $('tr-refresh').onclick = () => { readLive(); loadHistory(); };
  $('tr-reset').onclick = () => setFocus({ trafficFrom: '', trafficTo: '', trafficIp: '', trafficDest: '' });
  root.querySelectorAll('[data-tr-section]').forEach(b => b.onclick = () => {
    const target = $(b.dataset.trSection);
    if (target) target.scrollIntoView({ block: 'start', behavior:
      matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  });
  root.querySelectorAll('[data-tr-jump]').forEach(b => b.onclick = () =>
    $('tr-timeline').scrollIntoView({ block: 'center', behavior:
      matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }));
  const ready = loadHistory().then(ok => { startMeter(); startTopRefresh(); startAccess(); startPinned(); return ok; });
  return { ready, refresh: loadHistory, activate(state) {
    active = true;
    if (!timer) startMeter();
    if (!historyTimer) startTopRefresh();
    if (!accessTimer) startAccess();
    else if (state.site !== accessSite) loadAccess();
    if (keyOf(state) !== lastKey) loadHistory();
    if (!pinTimer || pinKey !== keyOf(state)) startPinned();
  }, deactivate() { active = false; clearTimeout(webRetryTimer); stopMeter(); stopTopRefresh(); stopAccess(); stopPinned(); ++userRequest; ++domainRequest; ++streamRequest; }, capture() { return {}; } };
};
