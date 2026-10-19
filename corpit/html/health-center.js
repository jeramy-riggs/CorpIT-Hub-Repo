/* health-center.js — one page for the service status and health signals that were
   spread over Server Health, the landing page probes, Network Health, Observability,
   the tenant checks, the security queues and the A/B cluster, plus the settings
   that drive them.

   Reads (all existing hub APIs except /api/system/cluster, added with this page):
     /api/system/servers, /api/system/pm2, /api/system/overview, /api/system/cluster,
     /api/tenant-health/<tenant>, /api/zscaler/zpa/connector-health,
     /api/identity/connector-health, /api/sdp/changes/health, /api/service-status,
     /api/netswitch/overview, /api/netswitch/fw-health, /api/meraki/noc,
     /api/feeds/freshness, /api/observe/summary, /api/sentinel/incidents,
     /api/identity/spray-alerts, /api/system/security-posture
   Writes (Settings tab, admin only, existing Server Health endpoints):
     PUT /api/system/thresholds, POST/DELETE /api/system/maintenance

   Access: super-admins only. The page asks /api/rbac/me first and fetches and
   shows nothing until that says super-admin. /api/system/cluster enforces the
   same rule on the server; every other source keeps the gate it already had.

   Rules this page keeps:
   - Worst state wins; states are never averaged.
   - `unknown` is its own state. A source that cannot be reached, answers an
     error, is older than its freshness limit, or is not permitted is drawn as
     "Not reporting" and is never drawn as healthy.
   - A write is only called saved after the value has been read back.
   - Host pages run a strict CSP: no inline handlers, text goes in via textContent. */
(function () {
  'use strict';

  var PAGE_KEY = 'server-health';          // RBAC page key every /api/system route is gated on
  var TIMEOUT_MS = 25000;
  var REFRESH_MS = 60000;
  var STALE = {
    tenant: 600,                           // tenant-health answers are cached 60 s
    vendor: 600,                           // service-status answers are cached 60 s
    net: 1800,                             // netswitch.js /health: collector older than 30 min is stale
    wifi: 600,                             // meraki-routes.js caches the NOC answer 30 s
    obsBeat: 1800                          // obs heartbeat job writes every 10 min; three missed beats = not reporting
  };

  /* ═══ small helpers ═══════════════════════════════════════════════════ */
  function $(id) { return document.getElementById(id); }

  function h(tag, props, kids) {
    var n = document.createElement(tag);
    if (props) Object.keys(props).forEach(function (k) {
      var v = props[k];
      if (v == null || v === false) return;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'on') Object.keys(v).forEach(function (ev) { n.addEventListener(ev, v[ev]); });
      else if (k === 'value') n.value = v;
      else n.setAttribute(k, v === true ? '' : String(v));
    });
    (kids || []).forEach(function (c) {
      if (c == null || c === false) return;
      n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  // Phone width: each row becomes a labelled block (CSS), so the label comes from the header cell.
  function stack(table, twoCol) {
    var heads = [].map.call(table.querySelectorAll('thead th'), function (t) { return t.textContent; });
    [].forEach.call(table.querySelectorAll('tbody tr'), function (tr) {
      [].forEach.call(tr.children, function (td, i) { if (i > 0 && heads[i]) td.setAttribute('data-label', heads[i]); });
    });
    table.classList.add('hc-stack');
    if (twoCol) table.classList.add('cols2');
    return table;
  }

  function num(v) { if (v == null || v === '') { return null; } var n = Number(v); return isFinite(n) ? n : null; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function pct(v) { var n = num(v); return n == null ? null : (Math.round(n * 10) / 10) + '%'; }
  function dur(sec) {
    var s = num(sec); if (s == null || s < 0) return null;
    if (s < 90) return Math.round(s) + ' s';
    if (s < 5400) return Math.round(s / 60) + ' min';
    if (s < 172800) return Math.round(s / 3600) + ' h';
    return Math.round(s / 86400) + ' d';
  }
  function ageSec(iso) {
    var t = Date.parse(iso);
    return isFinite(t) ? Math.max(0, Math.round((Date.now() - t) / 1000)) : null;
  }
  function when(v) {
    var d = new Date(v);
    return isNaN(d.getTime()) ? '' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }
  function hostOk(s) { return typeof s === 'string' && /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(s); }

  /* ═══ state vocabulary ════════════════════════════════════════════════ */
  /* bad > warn > maint > unknown > ok, the same order Server Health uses
     (critical, offline, warning, maintenance, unknown, healthy). */
  var RANK = { bad: 0, warn: 1, maint: 2, unknown: 3, ok: 4 };
  var LABEL = { bad: 'Needs attention', warn: 'Needs review', maint: 'Maintenance', unknown: 'Not reporting', ok: 'Operational' };
  var FROM_SYS = { healthy: 'ok', warning: 'warn', critical: 'bad', offline: 'bad', down: 'bad', maintenance: 'maint', unknown: 'unknown' };
  var FROM_TEN = { ok: 'ok', warn: 'warn', bad: 'bad', unknown: 'unknown', unconfigured: 'unknown' };
  /* An unrecognised word is `unknown`, never `ok`. */
  function fromSys(s) { return FROM_SYS[s] || 'unknown'; }
  function fromTen(s) { return FROM_TEN[s] || 'unknown'; }
  function worse(a, b) { return RANK[a] <= RANK[b] ? a : b; }

  function row(key, name, state, detail, extra) {
    var r = { key: key, name: name, state: state, detail: detail || '' };
    if (extra) Object.keys(extra).forEach(function (k) { r[k] = extra[k]; });
    return r;
  }

  /* ═══ network ═════════════════════════════════════════════════════════ */
  function getJSON(url) {
    var ctl = ('AbortController' in window) ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, TIMEOUT_MS);
    return fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        clearTimeout(timer);
        if (r.status === 401) return { s: 'auth' };
        if (r.status === 403) return { s: 'denied' };
        if (!r.ok) return { s: 'error', code: r.status };
        return r.json().then(function (d) { return { s: 'ok', data: d }; },
          function () { return { s: 'error', msg: 'The source did not return JSON.' }; });
      })
      .catch(function (e) {
        clearTimeout(timer);
        return { s: 'error', msg: e && e.name === 'AbortError' ? 'No answer within ' + (TIMEOUT_MS / 1000) + ' s.' : 'Could not reach the source.' };
      });
  }
  function send(method, url, body) {
    var ctl = ('AbortController' in window) ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, TIMEOUT_MS);
    return fetch(url, {
      method: method, credentials: 'same-origin', signal: ctl ? ctl.signal : undefined,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) {
      clearTimeout(timer);
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) {
          var e = new Error(j && j.error ? j.error
            : r.status === 401 ? 'Your session has expired. Reload the page to sign in again.'
            : r.status === 403 ? 'Your account does not have access to change this.'
            : 'The change failed (HTTP ' + r.status + ').');
          e.status = r.status; throw e;
        }
        return j;
      });
    }, function (e) {
      clearTimeout(timer);
      throw new Error(e && e.name === 'AbortError' ? 'No answer within ' + (TIMEOUT_MS / 1000) + ' s.' : 'Could not reach the server.');
    });
  }

  /* ═══ STATUS: probes ══════════════════════════════════════════════════
     A probe is one fetch. Its read() turns the payload into one or more rows. */

  /* -- Hosts & platform ---------------------------------------------- */
  function readServers(d) {
    var list = d && Array.isArray(d.servers) ? d.servers : null;
    if (!list) return [row('servers', 'Servers', 'unknown', 'The response had no server list.')];
    if (!list.length) return [row('servers', 'Servers', 'unknown', 'No servers are registered.')];
    return list.map(function (s, i) {
      var st = fromSys(s && s.health);
      if (!s || s.monitoringEnabled === false) st = 'unknown';
      var bits = [];
      var cpu = s.cpu && pct(s.cpu.busyPct), mem = s.memory && pct(s.memory.usedPct), dsk = s.disk && pct(s.disk.usedPct);
      bits.push(cpu ? 'CPU ' + cpu : 'CPU not reported');
      bits.push(mem ? 'memory ' + mem : 'memory not reported');
      bits.push(dsk ? 'disk ' + dsk : 'disk not reported');
      var up = dur(s.uptimeSec); if (up) bits.push('up ' + up);
      if (s.pendingReboot) bits.push('reboot pending');
      if (s.backup && num(s.backup.latestAgeHours) != null) bits.push('newest backup ' + Math.round(s.backup.latestAgeHours) + ' h old');
      var lead = s.monitoringEnabled === false ? 'Monitoring is turned off. ' : (s.health === 'critical' || s.health === 'offline' ? (s.health === 'offline' ? 'Offline. ' : 'Critical. ') : '');
      return row('servers:' + (s.id != null ? s.id : i), String(s.friendlyName || s.hostname || 'Server'), st, lead + bits.join(' · '));
    });
  }

  function countsRow(key, name, c, calc) {
    if (!c || typeof c !== 'object') return row(key, name, 'unknown', 'Not in the response.');
    var r = calc(c);
    return row(key, name, r.state, r.detail);
  }
  function parts(pairs) {
    return pairs.filter(function (p) { return num(p[1]); }).map(function (p) { return p[1] + ' ' + p[0]; }).join(' · ');
  }
  function readOverview(d) {
    var c = d && d.counts;
    if (!c || typeof c !== 'object') return [row('overview', 'Platform overview', 'unknown', 'The response had no counts.')];
    var out = [];

    out.push(countsRow('overview:vhosts', 'Virtual hosts', c.vhosts, function (v) {
      var st = (v.critical || v.offline) ? 'bad' : v.warning ? 'warn' : v.maintenance ? 'maint' : v.unknown ? 'unknown' : v.total ? 'ok' : 'unknown';
      return { state: st, detail: parts([['healthy', v.healthy], ['warning', v.warning], ['critical', v.critical], ['offline', v.offline], ['in maintenance', v.maintenance], ['not reporting', v.unknown]]) || 'None registered.' };
    }));
    out.push(countsRow('overview:jobs', 'Scheduled jobs', c.jobs, function (j) {
      var st = (j.failed || j.stuck) ? 'bad' : j.delayed ? 'warn' : j.unknown ? 'unknown' : j.total ? 'ok' : 'unknown';
      return { state: st, detail: parts([['healthy', j.healthy], ['running', j.running], ['delayed', j.delayed], ['stuck', j.stuck], ['failed', j.failed], ['not confirmed running', j.unknown]]) || 'None registered.' };
    }));
    out.push(countsRow('overview:apis', 'APIs and integrations', c.apis, function (a) {
      var st = a.externalDown ? 'bad' : (a.externalDegraded || a.internalDegraded) ? 'warn' : a.externalUnknown ? 'unknown' : 'ok';
      var det = [];
      det.push(plural(num(a.internalActive) || 0, 'internal API') + ' active');
      var ext = parts([['degraded', a.externalDegraded], ['down', a.externalDown], ['not measured', a.externalUnknown]]);
      det.push(plural(num(a.externalTotal) || 0, 'external integration') + (ext ? ' (' + ext + ')' : ''));
      if (num(a.internalDegraded)) det.push(plural(a.internalDegraded, 'internal API') + ' erroring');
      return { state: st, detail: det.join(' · ') };
    }));

    var b = c.backups;
    if (!b) out.push(row('overview:backups', 'Nightly backup', 'unknown', 'Not in the response.'));
    else {
      var bs = fromSys(b.state);
      var bd = bs === 'ok' ? 'Newest nightly backup is within its limit.' : bs === 'warn' ? 'Newest nightly backup is ageing.' : bs === 'bad' ? 'Newest nightly backup is overdue.' : 'Backup age could not be determined.';
      if (num(b.failures)) bd += ' ' + plural(b.failures, 'failure') + ' recorded.';
      out.push(row('overview:backups', 'Nightly backup', bs, bd));
    }

    var k = c.certificates;
    if (!k) out.push(row('overview:certs', 'Certificates', 'unknown', 'Not in the response.'));
    else {
      var ks = (k.expired || k.mismatched) ? 'bad' : k.expiringSoon ? 'warn' : 'ok';
      var kd = parts([['expired', k.expired], ['not matching their host', k.mismatched], ['expiring soon', k.expiringSoon]]);
      if (k.soonest && num(k.soonest.tls_days_left) != null && hostOk(k.soonest.fqdn)) kd = (kd ? kd + ' · ' : '') + 'next to expire: ' + k.soonest.fqdn + ' in ' + plural(k.soonest.tls_days_left, 'day');
      out.push(row('overview:certs', 'Certificates', ks, kd || 'No certificate is close to expiry.'));
    }

    var f = c.findings;
    if (!f) out.push(row('overview:findings', 'Open findings', 'unknown', 'Not in the response.'));
    else out.push(row('overview:findings', 'Open findings', f.critical ? 'bad' : f.warning ? 'warn' : 'ok',
      parts([['critical', f.critical], ['warning', f.warning], ['info', f.info]]) || 'No open findings.'));

    var m = c.maintenance;
    if (!m) out.push(row('overview:maint', 'Maintenance', 'unknown', 'Not in the response.'));
    else out.push(row('overview:maint', 'Maintenance', m.active ? 'maint' : m.overdue ? 'warn' : 'ok',
      parts([['in progress', m.active], ['overdue', m.overdue], ['upcoming', m.upcoming]]) || 'Nothing scheduled.'));

    if (d.unavailable && d.unavailable.length) {
      out.push(row('overview:unavail', 'Overview sections', 'unknown',
        plural(d.unavailable.length, 'section') + ' could not be computed: ' +
        d.unavailable.map(function (u) { return String((u && u.source) || 'unknown').slice(0, 40); }).join(', ') + '.'));
    }
    return out;
  }

  /* -- A/B cluster --------------------------------------------------- */
  function readCluster(d) {
    if (!d || typeof d !== 'object') return [row('cluster', 'A/B cluster', 'unknown', 'The response was empty.')];
    var st = fromSys(d.state);
    var reasons = (Array.isArray(d.reasons) ? d.reasons : []).map(function (r) { return r && r.text; }).filter(Boolean);
    var facts = [];
    function fact(k, v) { if (v != null && v !== '') facts.push([k, String(v)]); }
    fact('Seen from', d.node);
    var age = dur(d.ageSeconds); if (age) fact('Feed age', age + ' old');
    var dr = d.drbd;
    if (dr) {
      fact('DRBD role', dr.role ? dr.role + (dr.peerRole ? ' (peer ' + dr.peerRole + ')' : '') : null);
      fact('Connection', dr.connection);
      fact('Disks', (dr.disk || dr.peerDisk) ? (dr.disk || '?') + ' / ' + (dr.peerDisk || '?') : null);
      if (num(dr.oosKiB) != null) fact('Out of sync', dr.oosKiB + ' KiB');
    }
    var pm = d.pacemaker;
    if (pm) {
      if (Array.isArray(pm.nodes)) fact('Nodes online', pm.nodes.filter(function (n) { return n.online; }).length + ' of ' + pm.nodes.length);
      if (Array.isArray(pm.promoted)) fact('DRBD primary on', pm.promoted.join(', ') || 'no node');
      fact('Cluster manager lead', pm.dc);
      if (Array.isArray(pm.resources)) fact('Resources', pm.resources.length + ' (' + pm.resources.filter(function (r) { return r.failed; }).length + ' failed)');
      fact('Fencing', pm.stonithEnabled === false ? 'off' : 'on');
    }
    if (d.lastDecision) fact('Last handler decision', [d.lastDecision.mode, d.lastDecision.outcome].filter(Boolean).join(': '));
    return [row('cluster', 'DRBD and Pacemaker', st,
      reasons.length ? reasons.join('. ') + '.' : 'No faults found in DRBD or Pacemaker.', { facts: facts })];
  }

  /* -- tenants and endpoints ----------------------------------------- */
  function freshness(iso, limit) {
    var a = ageSec(iso);
    if (a == null) return 'No check time was reported, so it cannot be shown as healthy.';
    if (a > limit) return 'Last checked ' + dur(a) + ' ago, older than the ' + dur(limit) + ' limit.';
    return null;
  }
  function readTenant(p) {
    return function (d) {
      if (!d || typeof d !== 'object') return [row(p.id, p.name, 'unknown', 'The response was empty.')];
      var st = fromTen(d.state);
      var detail = String(d.detail || d.text || '');
      if (d.state === 'unconfigured') detail = detail || 'This check is not configured.';
      if (st === 'ok') {
        var stale = freshness(d.checkedAt, STALE.tenant);
        if (stale) { st = 'unknown'; detail = stale; }
      }
      return [row(p.id, p.name, st, detail)];
    };
  }
  function readZpa(d) {
    var p = { id: 'zpa', name: 'Zscaler ZPA connectors' };
    if (!d || typeof d !== 'object') return [row(p.id, p.name, 'unknown', 'The response was empty.')];
    if (d.streaming === false) return [row(p.id, p.name, 'unknown', String(d.reason || 'No connector telemetry in the window.'))];
    var c = Array.isArray(d.connectors) ? d.connectors : [];
    if (!c.length) return [row(p.id, p.name, 'unknown', 'Streaming is on but no connector records came back.')];
    var hot = c.filter(function (x) { return Number(x.cpuMax) >= 90 || Number(x.memMax) >= 90 || Number(x.diskMax) >= 90; });
    if (hot.length) return [row(p.id, p.name, 'warn', plural(hot.length, 'connector') + ' of ' + c.length + ' peaked at 90% or more CPU, memory or disk.')];
    return [row(p.id, p.name, 'ok', plural(c.length, 'connector') + ' reporting, all under 90%.')];
  }

  /* -- vendor status pages ------------------------------------------- */
  function readVendors(d) {
    if (!d || typeof d !== 'object' || d.ok === false || !d.services || typeof d.services !== 'object') {
      return [row('vendors', 'Vendor status pages', 'unknown', 'The status-page checker returned no services.')];
    }
    var stale = freshness(d.checkedAt, STALE.vendor);
    return Object.keys(d.services).map(function (k) {
      var s = d.services[k] || {};
      var st = fromTen(s.state), det = [];
      if (s.description) det.push(String(s.description));
      var inc = Array.isArray(s.incidents) ? s.incidents.length : 0, deg = Array.isArray(s.degraded) ? s.degraded.length : 0;
      if (inc) det.push(plural(inc, 'active incident'));
      if (deg) det.push(plural(deg, 'component') + ' degraded');
      if (st === 'ok' && stale) { st = 'unknown'; det = [stale]; }
      return row('vendors:' + k, String(s.label || k), st, det.join(' · '), { href: hostOk(s.source) ? 'https://' + s.source : null, linkText: 'Status page' });
    });
  }

  /* -- network ------------------------------------------------------- */
  /* Same rule as the landing page's Network tile, plus the collector freshness
     rule from netswitch.js. */
  function readNet(d) {
    if (!d || typeof d !== 'object' || d.ok === false) return [row('net', 'Switch fleet', 'unknown', String((d && d.detail) || 'The switch cache is not available.'))];
    var c = d.counts || d.summary || {}, sm = d.summary || {};
    var crit = num(c.critical) || 0, warn = num(c.warn) || 0, down = num(sm.switches_down) || 0;
    var st = (crit || down) ? 'bad' : warn ? 'warn' : 'ok';
    var det = [];
    if (num(sm.switches) != null) det.push((num(sm.switches_up) != null ? sm.switches_up + ' of ' : '') + plural(sm.switches, 'switch', 'switches') + ' up');
    if (down) det.push(down + ' unreachable');
    if (crit) det.push(plural(crit, 'critical issue'));
    if (warn) det.push(plural(warn, 'warning'));
    if (!crit && !warn && !down) det.push('no critical or warning issues');
    var a = d.meta ? num(d.meta.age_seconds) : null;
    if (a == null) {
      if (st === 'ok') { st = 'unknown'; det = ['The collector did not report when it last ran.']; }
    } else if (a > STALE.net) {
      var note = 'collector last ran ' + dur(a) + ' ago (limit ' + dur(STALE.net) + ')';
      if (st === 'ok') { st = 'unknown'; det = [note.charAt(0).toUpperCase() + note.slice(1) + '.']; } else det.push(note);
    }
    return [row('net', 'Switch fleet', st, det.join(' · '))];
  }

  /* Same reading as the NOC page: reachable null = could not be read, false = no data.
     Backup tunnels sit idle (phase 2 down) by design, so only a primary tunnel that is
     not up counts against a firewall. */
  function readFirewalls(d) {
    var list = d && Array.isArray(d.firewalls) ? d.firewalls : null;
    if (!list || !list.length) return [row('fw', 'Firewalls', 'unknown', 'The response had no firewall list.')];
    return list.map(function (f, i) {
      var name = String(f.name || f.hostname || 'Firewall');
      var key = 'fw:' + (f.key || i);
      if (f.reachable === null || f.reachable === undefined) return row(key, name, 'unknown', 'The firewall could not be read.');
      if (f.reachable === false) return row(key, name, 'bad', 'The firewall did not answer.');
      var tun = Array.isArray(f.tunnels) ? f.tunnels : [];
      var pri = tun.filter(function (t) { return t && t.role === 'primary'; });
      var priDown = pri.filter(function (t) { return t.status !== 'up'; });
      var bak = tun.filter(function (t) { return t && t.role === 'backup'; });
      var bakDown = bak.filter(function (t) { return t.phase1 !== 'up'; });
      var st = priDown.length ? 'bad' : bakDown.length ? 'warn' : 'ok';
      var det = [];
      if (pri.length) det.push(pri.length - priDown.length + ' of ' + plural(pri.length, 'primary tunnel') + ' up');
      if (priDown.length) det.push('down: ' + priDown.map(function (t) { return String(t.remote || '?'); }).join(', '));
      if (bak.length) det.push(bakDown.length ? plural(bakDown.length, 'backup tunnel') + ' not negotiated' : plural(bak.length, 'backup tunnel') + ' on standby');
      if (!tun.length) det.push('no tunnels reported');
      if (num(f.cpu) != null) det.push('CPU ' + f.cpu + '%');
      if (num(f.mem) != null) det.push('memory ' + f.mem + '%');
      if (num(f.sessions) != null) det.push(f.sessions + ' sessions');
      return row(key, name, st, det.join(' · '));
    });
  }

  function readWifi(d) {
    var name = 'Wi-Fi access points';
    if (!d || d.success === false || !d.summary) return [row('wifi', name, 'unknown', String((d && d.error) || 'Meraki returned no access-point summary.'))];
    var s = d.summary, total = num(s.totalAps), on = num(s.totalOnline), off = num(s.totalOffline) || 0;
    if (total == null || on == null) return [row('wifi', name, 'unknown', 'The access-point counts were not in the response.')];
    var st = total && !on ? 'bad' : off ? 'warn' : total ? 'ok' : 'unknown';
    var det = [on + ' of ' + total + ' online'];
    if (off) det.push(off + ' offline');
    var sites = d.sites && typeof d.sites === 'object' ? d.sites : {};
    Object.keys(sites).forEach(function (k) {
      var x = sites[k] || {};
      if (num(x.offlineCount)) det.push(String(x.name || k) + ': ' + x.offlineCount + ' offline');
    });
    if (num(s.totalClients) != null) det.push(plural(s.totalClients, 'client'));
    var stale = freshness(d.fetchedAt, STALE.wifi);
    if (st === 'ok' && stale) { st = 'unknown'; det = [stale]; }
    return [row('wifi', name, st, det.join(' · '))];
  }

  /* -- identity and service desk ------------------------------------- */
  /* Okta already has its own tenant check, so only the AD bind is taken from here. */
  function readConnectors(d) {
    var list = d && Array.isArray(d.connectors) ? d.connectors : null;
    var ad = list && list.filter(function (c) { return c && c.name === 'Active Directory'; })[0];
    if (!ad) return [row('ad', 'Active Directory', 'unknown', 'The connector check did not report Active Directory.')];
    var st = { online: 'ok', degraded: 'warn', offline: 'bad' }[ad.status] || 'unknown';
    var det = { online: 'A directory bind succeeded.', degraded: 'The directory answered but the check was not clean.',
      offline: 'The directory bind failed or timed out.', unconfigured: 'The bind account is not configured on this host.' }[ad.status] || 'Unrecognised connector status.';
    return [row('ad', 'Active Directory', st, det)];
  }

  function readSdp(d) {
    if (!d || d.success !== true) return [row('sdp', 'Service Desk (changes)', 'unknown', String((d && d.error) || 'The change module did not answer.'))];
    if (d.reachable === false) return [row('sdp', 'Service Desk (changes)', 'bad', 'The Service Desk change module is unreachable.')];
    if (d.reachable !== true) return [row('sdp', 'Service Desk (changes)', 'unknown', 'Reachability was not reported.')];
    return [row('sdp', 'Service Desk (changes)', 'ok', 'The change module answered.')];
  }

  /* -- data feeds and jobs ------------------------------------------- */
  /* Feeds: the hub's own freshness registry. A failing or abandoned producer is a
     fault; a stale or empty table needs review; a feed it could not measure is
     not reporting. */
  function readFeeds(d) {
    var list = d && Array.isArray(d.feeds) ? d.feeds : null;
    if (!list || !list.length) return [row('feeds', 'Data feeds', 'unknown', 'The freshness registry returned no feeds.')];
    var failing = list.filter(function (f) { return f.producerFailing || f.producerAbandoned; });
    var late = list.filter(function (f) { return f.state === 'stale' || f.state === 'empty'; });
    var unk = list.filter(function (f) { return f.state !== 'ok' && f.state !== 'stale' && f.state !== 'empty'; });
    var st = failing.length ? 'bad' : late.length ? 'warn' : unk.length ? 'unknown' : 'ok';
    var det = [];
    if (failing.length) det.push(plural(failing.length, 'collector') + ' failing');
    if (late.length) det.push(late.length + ' of ' + list.length + ' out of date');
    if (unk.length) det.push(unk.length + ' not measured');
    if (!det.length) det.push('All ' + list.length + ' feeds are within their limits.');
    var facts = list.filter(function (f) { return f.state !== 'ok' || f.producerFailing || f.producerAbandoned; })
      .sort(function (a, b) {
        var ra = num(a.ageHours) != null && num(a.maxAgeHours) ? a.ageHours / a.maxAgeHours : -1;
        var rb = num(b.ageHours) != null && num(b.maxAgeHours) ? b.ageHours / b.maxAgeHours : -1;
        return rb - ra;
      }).slice(0, 8).map(function (f) {
        var v = f.producerFailing ? 'collector failing' : f.producerAbandoned ? 'collector hung' :
          f.state === 'empty' ? 'no rows' :
          num(f.ageHours) != null ? Math.round(f.ageHours) + ' h old (limit ' + f.maxAgeHours + ' h)' : 'not measured';
        return [String(f.label || f.key), v];
      });
    return [row('feeds', 'Data feeds', st, det.join(' · '), { facts: facts })];
  }

  /* Observability: the same tiles and the same colours as observability.html. */
  function readObserve(d) {
    if (!d || d.state === 'unknown' || d.ok === false) return [row('obs', 'Observability', 'unknown', String((d && (d.detail || d.error)) || 'The summary could not be measured.'))];
    var out = [];
    var deg = 0, err = 0, warnFail = 0;
    (Array.isArray(d.client) ? d.client : []).forEach(function (c) {
      if (c.kind === 'degraded') { deg += num(c.n) || 0; return; }
      if (c.severity === 'error') { err += num(c.n) || 0; return; }
      if (c.kind === 'fetch_fail' || c.kind === 'resource_fail') warnFail += num(c.n) || 0;
    });
    var hrs = num(d.hours) || 24, win = ' in the last ' + hrs + ' h';

    var j = d.jobs || {};
    if (j.state !== 'measured') out.push(row('obs:jobs', 'Job registry', 'unknown', j.state === 'empty' ? 'No jobs are declared, so there is nothing to measure.' : 'The job registry could not be read.'));
    else {
      var jc = j.counts || {};
      var jbad = (num(jc.failing) || 0) + (num(jc.overdue) || 0) + (num(jc['never-ran']) || 0) + (num(jc.unknown) || 0);
      var juns = num(jc['not-scheduled']) || 0, und = j.undeclared;
      out.push(row('obs:jobs', 'Job registry', jbad ? 'bad' : (juns || und === null || und) ? 'warn' : 'ok',
        (parts([['failing', jc.failing], ['overdue', jc.overdue], ['never ran', jc['never-ran']], ['unknown outcome', jc.unknown], ['deployed but not scheduled', jc['not-scheduled']], ['ok', jc.ok]]) || 'no runs counted') +
        ' · ' + plural(num(j.declared) || 0, 'job') + ' declared' + (j.host && hostOk(j.host) ? ' on ' + j.host : '') +
        (und === null ? ' · undeclared jobs not measured' : und ? ' · ' + und + ' running undeclared' : '')));
    }

    var dep = d.dependencies || {};
    out.push(row('obs:deps', 'Upstream calls', num(dep.failed) ? 'bad' : 'ok',
      (num(dep.failed) || 0) + ' failed of ' + (num(dep.total) || 0) + ' calls to ' + plural(num(dep.vendors) || 0, 'vendor') + win + '.'));

    var rq = d.requests || {}, ab = num(rq.aborted) || 0;
    out.push(row('obs:5xx', 'Server errors', num(rq.e5) ? 'bad' : (num(rq.e4) || ab) ? 'warn' : 'ok',
      plural(num(rq.e5) || 0, 'server error') + ' · ' + plural(num(rq.e4) || 0, 'client error') + (ab ? ' · ' + ab + ' never completed' : '') + win + ' (sampled log, not total traffic).'));

    out.push(row('obs:browser', 'Browser failures', err ? 'bad' : warnFail ? 'warn' : 'ok',
      err + warnFail ? err + ' error-level · ' + warnFail + ' warn or info (4xx calls, optional assets)' + win + '.' : 'No uncaught errors, failed calls or dead assets' + win + '.'));
    out.push(row('obs:degraded', 'Degraded renders', deg ? 'warn' : 'ok',
      deg ? plural(deg, 'page') + ' told a user it did not know' + win + '.' : 'No page reported an unknown state' + win + '.'));

    var p = d.pipeline || {}, drop = 0;
    Object.keys(p.buffers || {}).forEach(function (k) { drop += num(p.buffers[k] && p.buffers[k].dropped) || 0; });
    drop += (num(p.ingestDropped) || 0);
    var hb = ageSec(p.lastHeartbeatAt);
    var cst = p.enabled === false ? 'unknown' : p.lastError ? 'bad' : drop ? 'warn' : (hb == null || hb > STALE.obsBeat) ? 'unknown' : 'ok';
    var cdet = p.enabled === false ? 'Recording is switched off, so every figure above is incomplete.' :
      p.lastError ? 'Last write error: ' + String(p.lastError).slice(0, 120) + '. Figures above may be undercounts.' :
      drop ? plural(drop, 'event') + ' dropped from the buffers, so figures above are undercounts.' :
      hb == null ? 'The collector did not report a heartbeat.' :
      hb > STALE.obsBeat ? 'Last heartbeat ' + dur(hb) + ' ago, older than the ' + dur(STALE.obsBeat) + ' limit.' :
      'Recording, nothing dropped, heartbeat ' + dur(hb) + ' ago.';
    out.push(row('obs:self', 'Observability collector', cst, cdet));
    return out;
  }

  /* -- application services ------------------------------------------ */
  function readPm2(d) {
    var list = d && Array.isArray(d.processes) ? d.processes : null;
    if (!list || !list.length) return [row('pm2', 'App services', 'unknown', String((d && d.error) || 'No process list came back.'))];
    var down = list.filter(function (p) { return p.status !== 'online'; });
    var flappy = list.filter(function (p) { return p.status === 'online' && num(p.unstableRestarts); });
    var st = down.length ? 'bad' : flappy.length ? 'warn' : 'ok';
    var det = [list.length - down.length + ' of ' + plural(list.length, 'process', 'processes') + ' online'];
    if (down.length) det.push('not online: ' + down.map(function (p) { return String(p.name) + ' (' + String(p.status || '?') + ')'; }).join(', '));
    if (flappy.length) det.push('restarting: ' + flappy.map(function (p) { return String(p.name); }).join(', '));
    var facts = list.map(function (p) {
      return [String(p.name), String(p.status || '?') + (dur(num(p.uptimeMs) / 1000) ? ' · up ' + dur(num(p.uptimeMs) / 1000) : '') + ' · ' + plural(num(p.restarts) || 0, 'restart')];
    });
    return [row('pm2', 'App services', st, det.join(' · '), { facts: facts })];
  }

  /* -- security signals ----------------------------------------------- */
  /* These count open work. A zero from a feed that is out of date is not an
     all-clear, so each row names the feed it depends on (see applyFeedTrust). */
  function readIncidents(d) {
    var name = 'Defender incidents';
    if (!d || num(d.windowOpen) == null) return [row('inc', name, 'unknown', 'The incident count was not in the response.', { feed: 'sentinel_incident' })];
    var days = num(d.windowDays) || 30;
    return [row('inc', name, d.windowOpen ? 'warn' : 'ok',
      plural(d.windowOpen, 'incident') + ' opened in the last ' + days + ' days' + (num(d.openTotal) != null ? ' · ' + d.openTotal + ' open in total' : '') + '.',
      { feed: 'sentinel_incident' })];
  }
  function readSpray(d) {
    var name = 'Password-spray alerts';
    if (!d || num(d.count) == null) return [row('spray', name, 'unknown', 'The alert count was not in the response.', { feed: 'sdops_spray' })];
    var mins = num(d.windowMinutes) || 60;
    return [row('spray', name, d.count ? 'bad' : 'ok',
      d.count ? plural(d.count, 'source') + ' flagged in the last ' + dur(mins * 60) + '.' : 'No spray pattern in the last ' + dur(mins * 60) + '.',
      { feed: 'sdops_spray' })];
  }
  function readPosture(d) {
    var name = 'Platform security review';
    var c = d && d.counts;
    if (!c || num(d.score) == null) return [row('posture', name, 'unknown', 'The review score was not in the response.')];
    var items = Array.isArray(d.items) ? d.items : [];
    var open = items.filter(function (i) { return i && i.state !== 'fixed'; }).length;
    return [row('posture', name, num(c.openHigh) ? 'warn' : 'ok',
      'Score ' + d.score + (d.grade ? ' (' + d.grade + ')' : '') + ' · ' + plural(num(c.openHigh) || 0, 'high-severity item') + ' open · ' + open + ' of ' + plural(items.length, 'item') + ' open.')];
  }

  /* A count drawn from a collected table is only as good as that table. When the
     feed behind an "ok" row is not ok, the row says it cannot report. Never the
     other way round: a fault from an old feed still shows as a fault. */
  function applyFeedTrust(r) {
    if (!r.feed || r.state !== 'ok') return r;
    var fd = RAW.feeds;
    if (!fd || !Array.isArray(fd.feeds)) return Object.assign({}, r, { state: 'unknown', detail: r.detail + ' The freshness of its source could not be checked.' });
    var f = fd.feeds.filter(function (x) { return x.key === r.feed; })[0];
    if (!f) return Object.assign({}, r, { state: 'unknown', detail: r.detail + ' Its source feed is not in the freshness registry.' });
    if (f.state === 'ok' && !f.producerFailing && !f.producerAbandoned) return r;
    var why = num(f.ageHours) != null ? 'is ' + Math.round(f.ageHours) + ' h old (limit ' + f.maxAgeHours + ' h)' : 'could not be measured';
    return Object.assign({}, r, { state: 'unknown', detail: r.detail + ' Not trusted: its source, ' + String(f.label || f.key) + ', ' + why + '.' });
  }

  var CARDS = [
    { id: 'platform', title: 'Hosts and platform', sub: 'Servers, virtual hosts, jobs, integrations, backups, certificates',
      link: { href: '/server-health.html', text: 'Server Health workspace' } },
    { id: 'cluster', title: 'A/B cluster', sub: 'As seen by the node that answered this page',
      link: { href: 'https://backup.nrpi.local/availability/', text: 'Availability page (super admins)' } },
    { id: 'tenants', title: 'Tenants and endpoints', sub: 'Identity, directory, device management, secure access and the Service Desk' },
    { id: 'vendors', title: 'Vendor status pages', sub: 'Published by Vonage, Meraki and Kandji' },
    { id: 'network', title: 'Network', sub: 'Switches, firewalls and Wi-Fi',
      link: { href: '/network-health.html', text: 'Network Health' } },
    { id: 'data', title: 'Data feeds and jobs', sub: 'Whether the collectors behind every page are keeping their data current',
      link: { href: '/observability.html', text: 'Observability' } },
    { id: 'security', title: 'Security signals', sub: 'Open work from Defender, sign-in monitoring and the platform security review',
      link: { href: '/signin-watch.html', text: 'Sign-In Watch' } }
  ];
  function tenant(id, name, href) {
    var p = { id: id, name: name };
    return { id: id, card: 'tenants', name: name, url: '/api/tenant-health/' + id, href: href, read: readTenant(p) };
  }
  var PROBES = [
    { id: 'servers', card: 'platform', name: 'Servers', url: '/api/system/servers', read: readServers },
    { id: 'pm2', card: 'platform', name: 'App services', url: '/api/system/pm2', href: '/server-health.html', read: readPm2 },
    { id: 'overview', card: 'platform', name: 'Platform overview', url: '/api/system/overview', read: readOverview },
    { id: 'cluster', card: 'cluster', name: 'A/B cluster', url: '/api/system/cluster', read: readCluster },
    tenant('entra', 'Entra ID', '/tenant-sentinel.html'),
    tenant('okta', 'Okta', '/okta-dashboard.html'),
    tenant('intune', 'Endpoints (Intune)', '/IT_Inventory_App.html'),
    tenant('zia', 'Zscaler ZIA', null),
    tenant('iru', 'Iru (Kandji)', null),
    { id: 'zpa', card: 'tenants', name: 'Zscaler ZPA connectors', url: '/api/zscaler/zpa/connector-health', href: '/zscaler-command-center.html', read: readZpa },
    { id: 'ad', card: 'tenants', name: 'Active Directory', url: '/api/identity/connector-health', href: '/ad-management.html', read: readConnectors },
    { id: 'sdp', card: 'tenants', name: 'Service Desk (changes)', url: '/api/sdp/changes/health', href: '/service-desk-portal.html', read: readSdp },
    { id: 'vendors', card: 'vendors', name: 'Vendor status pages', url: '/api/service-status', read: readVendors },
    { id: 'net', card: 'network', name: 'Switch fleet', url: '/api/netswitch/overview', read: readNet },
    { id: 'fw', card: 'network', name: 'Firewalls', url: '/api/netswitch/fw-health', href: '/network-health.html', read: readFirewalls },
    { id: 'wifi', card: 'network', name: 'Wi-Fi access points', url: '/api/meraki/noc', href: '/network-health.html', read: readWifi },
    { id: 'feeds', card: 'data', name: 'Data feeds', url: '/api/feeds/freshness', read: readFeeds },
    { id: 'obs', card: 'data', name: 'Observability', url: '/api/observe/summary?hours=24', href: '/observability.html', read: readObserve },
    { id: 'inc', card: 'security', name: 'Defender incidents', url: '/api/sentinel/incidents?windowDays=30', href: 'https://security.microsoft.com/incidents', read: readIncidents },
    { id: 'spray', card: 'security', name: 'Password-spray alerts', url: '/api/identity/spray-alerts', href: '/signin-watch.html', read: readSpray },
    { id: 'posture', card: 'security', name: 'Platform security review', url: '/api/system/security-posture', href: '/server-health.html', read: readPosture }
  ];

  /* ═══ STATUS: state + render ══════════════════════════════════════════ */
  var RESULTS = {};            // probe id -> { rows, at }
  var RAW = {};                // probe id -> last payload, null when that answer failed (applyFeedTrust reads feeds)
  var gen = 0;                 // a response from an older refresh is dropped
  var pendingN = 0;
  var lastDone = null;

  function failRows(p, res) {
    var why, text;
    if (res.s === 'auth') { why = 'Sign-in required. Reload the page to sign in again.'; text = 'Sign-in required'; }
    else if (res.s === 'denied') { why = 'Your account does not have access to this source.'; text = 'No access'; }
    else { why = res.msg || ('The source answered HTTP ' + res.code + '.'); }
    return [row(p.id, p.name, 'unknown', why, { text: text, href: p.href })];
  }
  function safeRead(p, data) {
    try {
      var rows = p.read(data);
      return rows.map(function (r) { if (p.href && !r.href) r.href = p.href; return r; });
    } catch (e) {
      return [row(p.id, p.name, 'unknown', 'The response could not be read.', { href: p.href })];
    }
  }

  function refresh() {
    var g = ++gen, inflight = {};
    pendingN = PROBES.length;
    $('hc-refresh').disabled = true;
    $('hc-refresh').textContent = 'Refreshing…';
    PROBES.forEach(function (p) {
      var pr = inflight[p.url] || (inflight[p.url] = getJSON(p.url));
      pr.then(function (res) {
        if (g !== gen) return;
        RAW[p.id] = res.s === 'ok' ? res.data : null;
        RESULTS[p.id] = { rows: res.s === 'ok' ? safeRead(p, res.data) : failRows(p, res), at: Date.now() };
        pendingN--;
        if (pendingN === 0) { lastDone = new Date(); $('hc-refresh').disabled = false; $('hc-refresh').textContent = 'Refresh'; }
        renderStatus();
      });
    });
    renderStatus();
  }

  function renderStatus() {
    var all = [];
    var host = $('hc-cards');
    clear(host);
    CARDS.forEach(function (c) {
      var body = h('div', { class: 'hc-card-b' });
      PROBES.filter(function (p) { return p.card === c.id; }).forEach(function (p) {
        var res = RESULTS[p.id];
        if (!res) { body.appendChild(rowEl({ name: p.name, state: 'pending', detail: 'Checking…' })); return; }
        res.rows.map(applyFeedTrust).forEach(function (r) { r.cardTitle = c.title; all.push(r); body.appendChild(rowEl(r)); });
      });
      var head = h('div', { class: 'hc-card-h' }, [h('h2', { text: c.title }), h('span', { class: 'hc-card-sub', text: c.sub })]);
      if (c.link) head.appendChild(h('a', { class: 'hc-card-link', href: c.link.href, text: c.link.text }));
      host.appendChild(h('section', { class: 'hc-card' }, [head, body]));
    });
    renderVerdict(all);
  }

  function rowEl(r) {
    var chipCls = r.state === 'pending' ? 's-pending' : 's-' + r.state;
    var chipTxt = r.state === 'pending' ? 'Checking' : (r.text || LABEL[r.state]);
    var head = h('div', { class: 'hc-row-h' }, [
      h('span', { class: 'hc-row-name', text: r.name }),
      h('span', { class: 'hc-chip ' + chipCls, text: chipTxt })
    ]);
    if (r.href) {
      var ext = /^https?:/.test(r.href);
      head.appendChild(h('a', { class: 'hc-row-link', href: r.href, text: r.linkText || 'Open', target: ext ? '_blank' : null, rel: ext ? 'noopener noreferrer' : null }));
    }
    var el = h('div', { class: 'hc-row' }, [head]);
    if (r.detail) el.appendChild(h('p', { class: 'hc-row-detail', text: r.detail }));
    if (r.facts && r.facts.length) {
      var dl = h('dl', { class: 'hc-facts' });
      r.facts.forEach(function (f) { dl.appendChild(h('div', { class: 'hc-fact' }, [h('dt', { text: f[0] }), h('dd', { text: f[1] })])); });
      el.appendChild(dl);
    }
    return el;
  }

  function renderVerdict(rows) {
    var box = $('hc-verdict'), head = $('hc-v-head'), sub = $('hc-v-sub'), list = $('hc-reasons');
    clear(list);
    var firstLoad = PROBES.some(function (p) { return !RESULTS[p.id]; });
    if (firstLoad) {
      box.className = 'hc-verdict is-pending';
      head.textContent = 'Checking…';
      sub.textContent = (PROBES.length - pendingN) + ' of ' + PROBES.length + ' sources have answered.';
      list.hidden = true;
      return;
    }
    var n = { bad: 0, warn: 0, maint: 0, unknown: 0, ok: 0 }, worst = 'ok';
    rows.forEach(function (r) { n[r.state]++; worst = worse(worst, r.state); });
    var total = rows.length;
    box.className = 'hc-verdict is-' + worst;
    head.textContent =
      worst === 'bad' ? plural(n.bad, 'check') + ' need' + (n.bad === 1 ? 's' : '') + ' attention' :
      worst === 'warn' ? plural(n.warn, 'check') + ' need' + (n.warn === 1 ? 's' : '') + ' review' :
      worst === 'maint' ? 'Maintenance in progress' :
      worst === 'unknown' ? plural(n.unknown, 'check') + ' not reporting' :
      'All systems operational';
    var bits = [(total - n.unknown) + ' of ' + total + ' checks reporting'];
    if (worst !== 'ok') bits.push(n.ok + ' operational');
    if (n.bad && worst !== 'bad') bits.push(n.bad + ' need attention');
    if (n.warn && worst !== 'warn') bits.push(n.warn + ' need review');
    if (n.maint && worst !== 'maint') bits.push(n.maint + ' in maintenance');
    if (n.unknown && worst !== 'unknown') bits.push(n.unknown + ' not reporting');
    sub.textContent = bits.join(' · ');

    var bad = rows.filter(function (r) { return r.state !== 'ok'; })
      .sort(function (a, b) { return RANK[a.state] - RANK[b.state]; });
    bad.slice(0, 12).forEach(function (r) {
      list.appendChild(h('li', null, [
        h('span', { class: 'hc-chip s-' + r.state, text: r.text || LABEL[r.state] }),
        h('span', null, [h('b', { text: r.name }), h('span', { class: 'where', text: ' · ' + r.cardTitle }),
          r.detail ? ' — ' + r.detail : ''])
      ]));
    });
    if (bad.length > 12) list.appendChild(h('li', null, [h('span', { class: 'where', text: '+ ' + (bad.length - 12) + ' more below' })]));
    list.hidden = !bad.length;
    $('hc-updated').textContent = lastDone ? 'Updated ' + lastDone.toLocaleTimeString() : '';
  }

  /* ═══ SETTINGS ════════════════════════════════════════════════════════ */
  var ADMIN = false, VERIFIED = false, settingsLoaded = false;
  var THR = null, THR_ORIG = null;

  function setMsg(node, kind, text) {
    node.className = 'hc-msg' + (kind ? ' ' + kind : '');
    node.textContent = text || '';
  }
  function whoCanEdit() {
    var note = $('hc-set-note');
    if (!VERIFIED) { note.className = 'hc-note bad'; note.textContent = 'Your access could not be confirmed, so editing is turned off. Reload the page to try again.'; note.hidden = false; }
    else if (!ADMIN) { note.className = 'hc-note'; note.textContent = 'You can read these settings. Changing them needs admin access to Server Health.'; note.hidden = false; }
    else note.hidden = true;
  }

  /* -- thresholds ---------------------------------------------------- */
  function validNum(s) {
    var t = String(s).trim();
    if (t === '') return null;
    var n = Number(t);
    return (isFinite(n) && n >= 0 && n <= 1e9) ? n : null;
  }
  function loadThresholds() {
    var box = $('hc-thr');
    getJSON('/api/system/thresholds').then(function (res) {
      if (res.s !== 'ok' || !res.data || !res.data.thresholds) {
        clear(box);
        box.appendChild(h('div', { class: 'hc-note bad', text: res.s === 'denied' ? 'Your account does not have access to the thresholds.' : res.s === 'auth' ? 'Sign-in required. Reload the page.' : 'The thresholds could not be loaded right now.' }));
        return;
      }
      THR = res.data.thresholds;
      THR_ORIG = {};
      Object.keys(THR).forEach(function (k) { THR_ORIG[k] = { warn: num(THR[k].warn), crit: num(THR[k].crit) }; });
      renderThresholds();
    });
  }
  function renderThresholds(keepMsg) {
    var box = $('hc-thr');
    clear(box);
    var keys = Object.keys(THR).sort();
    if (!keys.length) { box.appendChild(h('div', { class: 'hc-skel', text: 'No thresholds are defined.' })); return; }
    var inputs = {}, save = null, reset = null;
    var msg = h('span', { class: 'hc-msg', id: 'hc-thr-msg', role: 'status' });
    var tbody = h('tbody');
    function onEdit() { if (save) updateDirty(keys, inputs, tbody, save, reset, msg); }
    keys.forEach(function (k) {
      var t = THR[k], tr = h('tr');
      function cell(field) {
        var v = num(t[field]);
        if (!ADMIN) return h('td', { class: 'num u-mono', text: v == null ? '—' : String(v) });
        var inp = h('input', { class: 'hc-in narrow u-mono', type: 'number', min: '0', max: '1000000000', step: 'any',
          inputmode: 'decimal', value: v == null ? '' : String(v), 'aria-label': k + ' ' + (field === 'warn' ? 'warning' : 'critical') + ' threshold' });
        inp.addEventListener('input', onEdit);
        inputs[k + '.' + field] = inp;
        return h('td', { class: 'num' }, [inp]);
      }
      tr.appendChild(h('td', null, [h('div', { class: 'key', text: k }), h('div', { class: 'desc', text: t.description || '' })]));
      tr.appendChild(cell('warn'));
      tr.appendChild(cell('crit'));
      tr.appendChild(h('td', { text: t.unit || '' }));
      tr.appendChild(h('td', { class: 'desc', text: t.updatedAt ? when(t.updatedAt) + (t.updatedBy ? ' by ' + t.updatedBy : '') : 'Default value' }));
      tr.dataset.key = k;
      tbody.appendChild(tr);
    });
    var table = h('table', { class: 'hc-table' }, [
      h('thead', null, [h('tr', null, [h('th', { text: 'Setting' }), h('th', { text: 'Warning at' }), h('th', { text: 'Critical at' }), h('th', { text: 'Unit' }), h('th', { text: 'Last changed' })])]),
      tbody
    ]);
    box.appendChild(h('div', { class: 'hc-tw' }, [stack(table, true)]));

    if (ADMIN) {
      save =h('button', { type: 'button', class: 'hc-btn pri', id: 'hc-thr-save', text: 'Save changes', disabled: true });
      reset = h('button', { type: 'button', class: 'hc-btn', id: 'hc-thr-reset', text: 'Discard edits', disabled: true });
      box.appendChild(h('div', { class: 'hc-actions' }, [save, reset, msg]));
      save.addEventListener('click', function () { saveThresholds(inputs, save, reset, msg); });
      reset.addEventListener('click', function () { renderThresholds(); });
    } else {
      box.appendChild(h('div', { class: 'hc-actions' }, [msg]));
    }
    if (keepMsg) setMsg(msg, keepMsg.kind, keepMsg.text);
  }
  function dirtyKeys(keys, inputs) {
    var out = [], invalid = false;
    keys.forEach(function (k) {
      var w = validNum(inputs[k + '.warn'].value), c = validNum(inputs[k + '.crit'].value);
      inputs[k + '.warn'].classList.toggle('invalid', w == null);
      inputs[k + '.crit'].classList.toggle('invalid', c == null);
      if (w == null || c == null) { invalid = true; out.push({ key: k, bad: true }); return; }
      if (w !== THR_ORIG[k].warn || c !== THR_ORIG[k].crit) out.push({ key: k, warn: w, crit: c });
    });
    return { list: out, invalid: invalid };
  }
  function updateDirty(keys, inputs, tbody, save, reset, msg) {
    var d = dirtyKeys(keys, inputs);
    var dirtySet = {};
    d.list.forEach(function (x) { dirtySet[x.key] = true; });
    Array.prototype.forEach.call(tbody.children, function (tr) { tr.classList.toggle('dirty', !!dirtySet[tr.dataset.key]); });
    save.disabled = !d.list.length || d.invalid;
    reset.disabled = !d.list.length;
    if (d.invalid) setMsg(msg, 'bad', 'Each value must be a number from 0 to 1,000,000,000.');
    else if (d.list.length) setMsg(msg, '', plural(d.list.length, 'setting') + ' changed, not saved yet.');
    else setMsg(msg, '', '');
  }
  function saveThresholds(inputs, save, reset, msg) {
    var keys = Object.keys(THR).sort();
    var d = dirtyKeys(keys, inputs);
    if (d.invalid || !d.list.length) return;
    var body = { thresholds: {} };
    d.list.forEach(function (x) { body.thresholds[x.key] = { warn: x.warn, crit: x.crit }; });
    save.disabled = true; reset.disabled = true;
    setMsg(msg, '', 'Saving…');
    send('PUT', '/api/system/thresholds', body).then(function () {
      return getJSON('/api/system/thresholds');
    }).then(function (res) {
      if (res.s !== 'ok' || !res.data || !res.data.thresholds) throw new Error('The change was sent but the server did not answer the read-back, so it is not confirmed. Reload the page and check.');
      var wrong = d.list.filter(function (x) {
        var t = res.data.thresholds[x.key];
        return !t || num(t.warn) !== x.warn || num(t.crit) !== x.crit;
      });
      if (wrong.length) throw new Error('The server answered OK but ' + wrong.map(function (x) { return x.key; }).join(', ') + ' did not read back with the new value. Reload the page and check.');
      THR = res.data.thresholds; THR_ORIG = {};
      Object.keys(THR).forEach(function (k) { THR_ORIG[k] = { warn: num(THR[k].warn), crit: num(THR[k].crit) }; });
      renderThresholds({ kind: 'ok', text: 'Saved, and read back from the server (' + plural(d.list.length, 'setting') + ').' });
      refresh();
    }).catch(function (e) {
      save.disabled = false; reset.disabled = false;
      setMsg(msg, 'bad', e.message);
    });
  }

  /* -- maintenance --------------------------------------------------- */
  var KINDS = [['task', 'Task'], ['window', 'Maintenance window']];
  var TARGETS = [['global', 'The whole estate'], ['server', 'A server'], ['vhost', 'A virtual host'], ['job', 'A scheduled job'], ['api', 'An API'], ['service', 'A service']];
  var TARGET_LABEL = {}; TARGETS.forEach(function (t) { TARGET_LABEL[t[0]] = t[1]; });

  function loadMaint(keepMsg) {
    var box = $('hc-mnt');
    getJSON('/api/system/maintenance').then(function (res) {
      clear(box);
      if (res.s !== 'ok' || !res.data || !Array.isArray(res.data.items)) {
        box.appendChild(h('div', { class: 'hc-note bad', text: res.s === 'denied' ? 'Your account does not have access to maintenance items.' : res.s === 'auth' ? 'Sign-in required. Reload the page.' : 'Maintenance items could not be loaded right now.' }));
        return;
      }
      renderMaint(box, res.data.items, keepMsg);
    });
  }
  function renderMaint(box, items, keepMsg) {
    var msg = h('span', { class: 'hc-msg', role: 'status' });
    if (keepMsg) setMsg(msg, keepMsg.kind, keepMsg.text);
    if (!items.length) box.appendChild(h('div', { class: 'hc-skel', text: 'Nothing is scheduled.' }));
    else {
      var tbody = h('tbody');
      items.forEach(function (m) {
        var target = (TARGET_LABEL[m.itemType] || m.itemType || '') + ((m.itemLabel || m.itemRef) ? ': ' + (m.itemLabel || m.itemRef) : '');
        var span = m.startsAt ? when(m.startsAt) + (m.endsAt ? ' to ' + when(m.endsAt) : '') : (m.dueAt ? 'Due ' + when(m.dueAt) : '');
        var status = h('td');
        if (m.overdue) status.appendChild(h('span', { class: 'hc-chip s-warn', text: 'Overdue' }));
        else if (m.active) status.appendChild(h('span', { class: 'hc-chip s-maint', text: 'In progress' }));
        else status.appendChild(document.createTextNode(m.upcoming ? 'Upcoming' : String(m.status || '').replace('_', ' ')));
        var act = h('td');
        if (ADMIN) act.appendChild(h('button', { type: 'button', class: 'hc-btn small danger', text: 'Cancel', 'aria-label': 'Cancel ' + (m.title || 'item'),
          on: { click: function () { cancelMaint(m, msg); } } }));
        tbody.appendChild(h('tr', null, [
          h('td', null, [h('div', { text: m.title || '(untitled)' }), m.detail ? h('div', { class: 'desc', text: m.detail }) : null]),
          h('td', { text: m.kind === 'window' ? 'Window' : 'Task' }),
          h('td', { text: target }),
          h('td', { text: span }),
          status,
          h('td', { text: m.ownerEmail || '' }),
          act
        ]));
      });
      box.appendChild(h('div', { class: 'hc-tw' }, [stack(h('table', { class: 'hc-table' }, [
        h('thead', null, [h('tr', null, ['Title', 'Kind', 'Applies to', 'When', 'Status', 'Owner', ''].map(function (t) { return h('th', { text: t }); }))]),
        tbody
      ]), true)]));
    }
    box.appendChild(h('div', { class: 'hc-actions' }, [msg]));
    if (ADMIN) box.appendChild(maintForm(msg));
  }

  function opt(pair, sel) { return h('option', { value: pair[0], text: pair[1], selected: sel === pair[0] ? true : null }); }
  function field(label, ctl, full) {
    var id = ctl.id;
    return h('div', { class: full ? 'full' : null }, [h('label', { for: id, text: label }), ctl]);
  }
  function maintForm(listMsg) {
    var f = h('form', { class: 'hc-form', novalidate: true, id: 'hc-mnt-form' });
    var title = h('input', { class: 'hc-in', id: 'hm-title', type: 'text', maxlength: '255', required: true });
    var kind = h('select', { class: 'hc-sel', id: 'hm-kind' }, KINDS.map(function (k) { return opt(k, 'task'); }));
    var type = h('select', { class: 'hc-sel', id: 'hm-type' }, TARGETS.map(function (k) { return opt(k, 'global'); }));
    var ref = h('input', { class: 'hc-in', id: 'hm-ref', type: 'text', maxlength: '255', placeholder: 'Server or host ID, or job name' });
    var starts = h('input', { class: 'hc-in', id: 'hm-starts', type: 'datetime-local' });
    var ends = h('input', { class: 'hc-in', id: 'hm-ends', type: 'datetime-local' });
    var due = h('input', { class: 'hc-in', id: 'hm-due', type: 'datetime-local' });
    var owner = h('input', { class: 'hc-in', id: 'hm-owner', type: 'email', maxlength: '255' });
    var detail = h('textarea', { class: 'hc-ta', id: 'hm-detail', maxlength: '2000' });
    var msg = h('span', { class: 'hc-msg', role: 'status' });
    var btn = h('button', { type: 'submit', class: 'hc-btn pri', text: 'Add' });
    f.appendChild(h('h3', { text: 'Add a maintenance window or task' }));
    f.appendChild(field('Title', title)); f.appendChild(field('Kind', kind)); f.appendChild(field('Applies to', type)); f.appendChild(field('Item reference', ref));
    f.appendChild(field('Window starts', starts)); f.appendChild(field('Window ends', ends)); f.appendChild(field('Due', due)); f.appendChild(field('Owner e-mail', owner));
    f.appendChild(field('Detail', detail, true));
    f.appendChild(h('div', { class: 'hc-actions full' }, [btn, msg]));

    f.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var t = title.value.trim();
      if (!t) { setMsg(msg, 'bad', 'A title is required.'); return; }
      var body = { title: t, kind: kind.value, item_type: type.value, status: 'scheduled' };
      function dt(inp, name) {
        if (!inp.value) return true;
        var d = new Date(inp.value);
        if (isNaN(d.getTime())) { setMsg(msg, 'bad', 'Check the ' + name + ' date.'); return false; }
        return d.toISOString();
      }
      var s = dt(starts, 'start'), e = dt(ends, 'end'), u = dt(due, 'due');
      if (s === false || e === false || u === false) return;
      if (s !== true) body.starts_at = s;
      if (e !== true) body.ends_at = e;
      if (u !== true) body.due_at = u;
      if (kind.value === 'window') {
        if (s === true || e === true) { setMsg(msg, 'bad', 'A maintenance window needs a start and an end.'); return; }
        if (Date.parse(e) <= Date.parse(s)) { setMsg(msg, 'bad', 'The window must end after it starts.'); return; }
      }
      if (ref.value.trim()) body.item_ref = ref.value.trim();
      if (owner.value.trim()) body.owner_email = owner.value.trim();
      if (detail.value.trim()) body.detail = detail.value.trim();
      btn.disabled = true; setMsg(msg, '', 'Adding…');
      send('POST', '/api/system/maintenance', body).then(function (r) {
        if (!r || !r.ok) throw new Error('The server did not confirm the new item.');
        loadMaint({ kind: 'ok', text: 'Added "' + t + '".' });
        refresh();
      }).catch(function (err) { btn.disabled = false; setMsg(msg, 'bad', err.message); });
    });
    return f;
  }
  function cancelMaint(m, msg) {
    if (!window.confirm('Cancel "' + (m.title || 'this item') + '"?')) return;
    setMsg(msg, '', 'Cancelling…');
    send('DELETE', '/api/system/maintenance/' + encodeURIComponent(m.id)).then(function () {
      loadMaint({ kind: 'ok', text: 'Cancelled "' + (m.title || 'item') + '".' });
      refresh();
    }).catch(function (e) { setMsg(msg, 'bad', e.message); });
  }

  /* -- where each setting lives -------------------------------------- */
  /* Audited 2026-09-30 against the hub, the console and the host files. */
  var WHERE = [
    ['Alert thresholds: CPU, memory, disk, backup age, certificate days, job staleness, virtual-host latency, API error rate',
      'This page, Settings tab (also the Server Health workspace). Saved in the Server Health database; who changed a value is recorded.', 'Yes'],
    ['Maintenance windows and tasks',
      'This page, Settings tab (also the Server Health workspace). Saved in the Server Health database.', 'Yes'],
    ['Server and virtual-host registry: add, edit, retire',
      'Server Health workspace.', 'No'],
    ['Findings: acknowledge and reopen',
      'Server Health workspace.', 'No'],
    ['Tenant checks (Entra, Okta, Intune, ZIA, Iru): cache time and timeout',
      'Hub code, tenant-health-routes.js: answers cached 60 s, failures 10 s, 7 s timeout. A code change that goes out through a release.', 'No'],
    ['Vendor status pages (Vonage, Meraki, Kandji)',
      'Hub code, service-status-routes.js: answers cached 60 s, 6 s timeout. A code change that goes out through a release.', 'No'],
    ['A/B cluster status feed',
      'Each node writes it every 15 s from a systemd timer; this page calls it not reporting after 90 s (ha-cluster-routes.js).', 'No'],
    ['A/B cluster alert delivery',
      'A config file on the backup host, /etc/corpit-ha-alert/delivery.json.', 'No'],
    ['Scheduled-job list and expected intervals',
      'obs-jobs.json in the hub folder, applied by obs-seed-jobs.js.', 'No'],
    ['Switch fleet rule and freshness',
      'The critical and warning rule mirrors the landing page Network tile. The 30-minute freshness limit is in the hub code, netswitch.js.', 'No'],
    ['Firewall list and tunnel roles (primary or backup)',
      'Hub code, netswitch.js fw-health. A primary tunnel that is not up needs attention; idle backup tunnels are normal.', 'No'],
    ['Data feed list and the age each feed may reach',
      'Hub code, feed-freshness-routes.js (the FEEDS registry). A code change that goes out through a release.', 'No'],
    ['Observability recording: on or off, sample rate, retention',
      'A config file on each node, /etc/corpit/shared/observability.json. The colours on this page are the Observability page\'s own.', 'No'],
    ['Password-spray detection window',
      'Hub environment, SPRAY_WINDOW_MIN and SPRAY_SLOW_WINDOW_MIN.', 'No'],
    ['Platform security review items: mark fixed or open',
      'Server Health workspace.', 'No'],
    ['Admin center: its own service, housekeeping and backup copies',
      'Admin center (subadmin.nrpi.local). It runs outside the hub, so this page cannot read it; use the Admin center System page.', 'No'],
    ['Alerts for the signals on this page',
      'None exist. Crossing a threshold changes what these pages show; it does not send a message. Sign-In Watch is the only job wired to alert delivery.', 'n/a']
  ];
  function renderWhere() {
    var tbody = h('tbody');
    WHERE.forEach(function (w) {
      tbody.appendChild(h('tr', null, [
        h('td', { text: w[0] }), h('td', { text: w[1] }),
        h('td', null, [h('span', { class: w[2] === 'Yes' ? 'hc-yes' : 'hc-no', text: w[2] })])
      ]));
    });
    var box = $('hc-where');
    clear(box);
    box.appendChild(h('div', { class: 'hc-tw' }, [stack(h('table', { class: 'hc-table' }, [
      h('thead', null, [h('tr', null, [h('th', { text: 'Setting' }), h('th', { text: 'Where it is changed' }), h('th', { text: 'On this page' })])]),
      tbody
    ]), false)]));
  }

  function loadSettings() {
    if (settingsLoaded) return;
    settingsLoaded = true;
    renderWhere();
    var rb = window.itRbac;
    var ready = rb && typeof rb.ready === 'function' ? Promise.resolve(rb.ready()).catch(function () { return null; }) : Promise.resolve(null);
    ready.then(function () {
      try {
        VERIFIED = !!(rb && rb.isVerified && rb.isVerified());
        ADMIN = VERIFIED && !!rb.canAdmin(PAGE_KEY);
      } catch (e) { VERIFIED = false; ADMIN = false; }
      whoCanEdit();
      loadThresholds();
      loadMaint();
    });
  }

  /* ═══ portal journeys ═════════════════════════════════════════════════ */
  /* The Access Portal's own journey log (journey.db beside portal.db on the node
     that runs the portal backend), relayed read-only by /api/system/portal-journey.
     A log that cannot be read is said so in words and is never drawn as zeros.
     Every value from the log is page- or server-recorded text: textContent only. */
  var J_API = '/api/system/portal-journey';
  var J_TIMEOUT_MS = 45000;                  // the hub waits 30 s for the summary
  var jLoaded = false, jBusy = false, jPersonBusy = false;
  var J_TYPES = { aia: 'AI Use Case Intake', oca: 'Out-of-Country Access', wua: 'Website / URL Access',
    paa: 'Privileged / Admin Access', ser: 'Security Exception Request', sir: 'IT Security Incident Form' };
  var J_PAGES = { home: 'the home page', aiachoose: 'the AI Use Case Intake chooser', form: 'a request form',
    cla: 'the Claude acknowledgment', confirm: 'the confirmation page', signin: 'the sign-in page',
    'signin-redirect': 'sign-in (leaving for Microsoft)' };
  var J_IDSRC = { entra: 'signed in with Microsoft', discarded: 'signed in, then chose "Not me"', typed: 'typed in / directory lookup' };
  var J_KEYS = { sw: 'screen w', sh: 'screen h', dpr: 'pixel ratio', nav: 'navigation', size: 'page bytes',
    lm: 'page modified', lsc: 'saved settings on this browser', cla: 'saved settings say Claude form live',
    path: 'path', c2: 'card 2', c2vis: 'card 2 on screen', c2top: 'card 2 top px', stacked: 'stacked',
    cards: 'cards', enabled: 'silent sign-in on', on: 'silent sign-in on', next: 'return to',
    src: 'eligibility source', emp: 'employment source', matched: 'matched', via: 'came from',
    c2shown: 'card 2 shown', c2en: 'card 2 usable', c2seen: 'card 2 on screen', fte: 'page: eligible',
    idv: 'page: signed in', lookup: 'used directory lookup', fte_srv: 'server: eligible',
    stamp: 'page stamp', src_error: 'eligibility check error', rev: 'page', form: 'form', had: 'had a sign-in' };

  function jGet(url) {
    var ctl = ('AbortController' in window) ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, J_TIMEOUT_MS);
    return fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        clearTimeout(timer);
        return r.json().catch(function () { return null; }).then(function (j) {
          if (r.ok && j && j.ok && j.data) return { ok: true, data: j.data };
          return { ok: false, msg: j && j.error ? j.error
            : r.status === 401 ? 'Your session has expired. Reload the page to sign in again.'
            : r.status === 403 ? 'Your account does not have access to the journey log.'
            : 'The journey log did not answer (HTTP ' + r.status + ').' };
        });
      }, function (e) {
        clearTimeout(timer);
        return { ok: false, msg: e && e.name === 'AbortError' ? 'No answer within ' + (J_TIMEOUT_MS / 1000) + ' s.' : 'Could not reach the hub API.' };
      });
  }

  function jN(v) { var n = num(v); return n == null ? '—' : n.toLocaleString(); }
  function jBytes(v) {
    var n = num(v); if (n == null) return '—';
    return n < 1048576 ? Math.round(n / 1024) + ' KB' : (Math.round(n / 104857.6) / 10) + ' MB';
  }
  function jTime(ts) {
    var d = new Date(ts);
    return isNaN(d.getTime()) ? String(ts || '') : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  function jType(t) { return J_TYPES[t] || t || 'unknown form'; }
  function jPage(p) { return J_PAGES[p] || p || 'an unknown page'; }
  function jUa(ua) {
    ua = String(ua || ''); if (!ua) return 'browser not recorded';
    var m, b = 'Unknown browser', os = '';
    if ((m = /Edg\/(\d+)/.exec(ua))) b = 'Edge ' + m[1];
    else if ((m = /Firefox\/(\d+)/.exec(ua))) b = 'Firefox ' + m[1];
    else if ((m = /HeadlessChrome\/(\d+)/.exec(ua))) b = 'Headless Chrome ' + m[1] + ' (automated test)';
    else if ((m = /Chrome\/(\d+)/.exec(ua))) b = 'Chrome ' + m[1];
    else if ((m = /Version\/(\d+)[^ ]* .*Safari/.exec(ua))) b = 'Safari ' + m[1];
    if (/iPhone|iPad/.test(ua)) os = 'iOS'; else if (/Android/.test(ua)) os = 'Android';
    else if (/Windows/.test(ua)) os = 'Windows'; else if (/Mac OS X|Macintosh/.test(ua)) os = 'macOS';
    else if (/Linux/.test(ua)) os = 'Linux';
    return b + (os ? ' on ' + os : '');
  }
  function jRest(d, skip) {
    return Object.keys(d || {}).filter(function (k) { return skip.indexOf(k) === -1; }).map(function (k) {
      var v = d[k];
      return (J_KEYS[k] || k) + ' ' + (v === true ? 'yes' : v === false ? 'no' : v === null ? '—' : String(v));
    }).join(' · ');
  }
  /* One event in plain words, plus whatever else it carried. */
  function jSay(e) {
    var d = e.data || {}, t;
    switch (e.event) {
      case 'load':
        t = 'Opened the page' + (d.intake ? ' from the ' + jType(d.intake) + ' link' : '') + ', window ' + (d.w || '?') + ' × ' + (d.h || '?')
          + (d.zoom && d.zoom !== 1 ? ', zoom ' + Math.round(d.zoom * 100) + '%' : '') + (d.cached ? ', page from browser cache' : '');
        return [t, jRest(d, ['w', 'h', 'zoom', 'cached', 'intake', 'ua'])];
      case 'identity':
        if (d.failed) return ['The page could not check who this is', ''];
        t = 'Page: ' + (d.verified ? 'signed in, card 2 ' + (d.fte ? 'allowed' : 'not allowed') : 'not signed in')
          + (d.leaving ? ', leaving for silent sign-in' : '');
        return [t, jRest(d, ['verified', 'fte', 'leaving'])];
      case 'whoami':
        t = d.verified ? 'Server: signed in as ' + (e.email || '?') + ', ' + (d.fte ? 'eligible' : 'not eligible') + ' for card 2'
          + (d.blocked ? ' (blocked)' : '') : 'Server: not signed in' + (d.discarded ? ' (chose "Not me" earlier)' : '');
        return [t, jRest(d, ['verified', 'fte', 'blocked', 'discarded'])];
      case 'whoami_failed': return ['The identity check failed in the browser (network or server error)', ''];
      case 'signin_start': return ['Sign-in started (' + (d.mode === 'silent' ? 'silent' : 'Microsoft sign-in page') + ')', jRest(d, ['mode'])];
      case 'signin_result':
        t = 'Sign-in came back: ' + (d.result || '?') + (d.aadsts ? ' ' + d.aadsts : '') + (d.error && !d.aadsts ? ' (' + d.error + ')' : '');
        return [t, jRest(d, ['result', 'aadsts', 'error'])];
      case 'view':
        if (d.page !== 'aiachoose') return ['Saw ' + jPage(d.page), jRest(d, ['page'])];
        t = 'Saw the AI Use Case Intake chooser: ' + (d.cards != null ? plural(d.cards, 'card') + ', ' : '')
          + (d.c2 === 'enabled' ? 'card 2 usable' + (d.c2vis ? ' and on screen' : ' but below the fold')
            : d.c2 === 'disabled' ? 'card 2 greyed out' : 'no card 2')
          + (d.stacked ? ', cards stacked' : '');
        return [t, jRest(d, ['page', 'cards', 'c2', 'c2vis', 'stacked'])];
      case 'card2_seen':
        return ['Card 2 came on screen' + (d.c2 === 'disabled' ? ' greyed out' : '') + (d.ms != null ? ' after ' + (d.ms / 1000).toFixed(1) + ' s' : ''), jRest(d, ['c2', 'ms'])];
      case 'click':
        t = 'Clicked ' + (d.fn === 'other' ? 'a control' : d.fn || '?') + (d.arg ? ' (' + (J_TYPES[d.arg] || d.arg) + ')' : '') + (d.page ? ' on ' + jPage(d.page) : '');
        return [t, ''];
      case 'form_start': return ['Started the ' + jType(d.type) + ' form' + (d.via ? ' (from ' + d.via + ')' : ''), ''];
      case 'step': return [jType(d.type) + ' form, step ' + (d.n != null ? d.n : '?'), ''];
      case 'cla_open': return ['Opened the Claude acknowledgment (card 2)' + (d.via ? ' from ' + d.via : ''), ''];
      case 'lookup': return ['Directory lookup: ' + (d.offline ? 'directory unavailable' : d.found ? 'found' : 'not found'), ''];
      case 'dir_offline': return ['Directory unavailable; the form switched to offline mode', ''];
      case 'submit_ok': return ['Page showed the confirmation for ' + (d.id || jType(d.type)), ''];
      case 'submit_fail': return ['Submit failed on the page: ' + (d.msg || '?'), d.type ? jType(d.type) : ''];
      case 'submit':
        t = 'Filed ' + jType(d.type) + (d.id ? ' ' + d.id : '') + ', ' + (J_IDSRC[e.idsrc] || e.idsrc || 'identity source unknown');
        return [t, jRest(d, ['type', 'id'])];
      case 'ack':
        return [d.already ? 'Claude acknowledgment was already on file' : 'Claude acknowledgment recorded' + (d.id ? ' ' + d.id : '') + (d.sample ? ' (sample, form not live)' : ''),
          jRest(d, ['already', 'id', 'sample'])];
      case 'ack_refused': return ['Claude acknowledgment refused: ' + (d.blocked ? 'blocked' : 'not eligible'), jRest(d, ['blocked'])];
      case 'ack_ok': return ['Page: acknowledgment accepted' + (d.already ? ' (already on file)' : ''), ''];
      case 'ack_fail': return ['Acknowledgment failed on the page: ' + (d.msg || '?'), ''];
      case 'resize': return ['Resized the window to ' + (d.w || '?') + ' × ' + (d.h || '?'), ''];
      case 'jserr':
        return ['Page script error: ' + (d.msg || '?'), d.src ? d.src + (d.line ? ':' + d.line + (d.col ? ':' + d.col : '') : '') : ''];
      case 'leave': return ['Left the page from ' + jPage(d.page) + (d.ms != null ? ' after ' + (dur(d.ms / 1000) || '?') : ''), ''];
      case 'forget': return ['Sign-in cleared ("Not me")', jRest(d, [])];
    }
    return [e.event, jRest(d, [])];
  }

  function jCard(title, sub, kids, wide) {
    return h('div', { class: 'hc-card' + (wide ? ' wide' : '') }, [
      h('div', { class: 'hc-card-h' }, [h('h2', { text: title }), sub ? h('span', { class: 'hc-card-sub', text: sub }) : null]),
      h('div', { class: 'hc-card-b' }, kids)
    ]);
  }
  function jFacts(pairs) {
    var dl = h('dl', { class: 'hc-facts' });
    pairs.forEach(function (p) { if (p) dl.appendChild(h('div', { class: 'hc-fact' }, [h('dt', { text: p[0] }), h('dd', { text: p[1] })])); });
    return dl;
  }
  // [{k, n}] → a two-column table, or a line saying there were none.
  function jCounts(title, rows, none, label) {
    var kids = [h('h3', { class: 'hc-j-h3', text: title })];
    if (!rows || !rows.length) { kids.push(h('p', { class: 'hc-msg', text: none })); return h('div', null, kids); }
    var tb = h('tbody');
    rows.forEach(function (r) { tb.appendChild(h('tr', null, [h('td', { text: label ? label(r.k) : r.k }), h('td', { class: 'num', text: jN(r.n) })])); });
    kids.push(h('div', { class: 'hc-tw' }, [h('table', { class: 'hc-table hc-j-small' }, [
      h('thead', null, [h('tr', null, [h('th', { text: 'What' }), h('th', { class: 'num', text: 'Count' })])]), tb])]));
    return h('div', null, kids);
  }
  function jObjRows(o) { return Object.keys(o || {}).map(function (k) { return { k: k, n: o[k] }; }).sort(function (a, b) { return b.n - a.n; }); }
  function jSignin(k) {
    var p = String(k).split(':');
    if (p[0] === 'start') return 'Started (' + (p[1] === 'silent' ? 'silent' : 'Microsoft sign-in page') + ')';
    return 'Came back: ' + p.join(' ');
  }

  function jRenderHead(d) {
    var box = $('hc-j-head'), s = d.store || {};
    clear(box);
    if (s.full) box.appendChild(h('p', { class: 'hc-note bad', text: 'The journey log reached its size limit (' + jBytes(s.max_bytes) + '). New events are being dropped until the 90-day purge frees space.' }));
    if (s.error) box.appendChild(h('p', { class: 'hc-note bad', text: 'The journey log writer reported an error: ' + s.error }));
    if (num(s.dropped) > 0) box.appendChild(h('p', { class: 'hc-note bad', text: plural(num(s.dropped), 'event') + ' could not be written since the portal backend last started (queue or file full). Counts below are missing those.' }));
    if (d.empty) {
      box.appendChild(h('p', { class: 'hc-note', text: 'Nothing has been recorded on this node yet. The log file is created with the first page event after this logging went live.' }));
    } else {
      if (d.truncated) box.appendChild(h('p', { class: 'hc-note', text: 'This window holds more than 300,000 events; the counts cover the first 300,000. Pick a shorter window for complete counts.' }));
      box.appendChild(jFacts([
        ['Events in window', jN(d.events)], ['Visits', jN(d.visits)], ['People', jN(d.people)],
        ['Page loads', jN(d.loads && d.loads.count)]
      ]));
    }
    box.appendChild(h('h3', { class: 'hc-j-h3', text: 'The log itself' }));
    box.appendChild(jFacts([
      d.empty ? null : ['Events kept', jN(s.rows)],
      d.empty ? null : ['Oldest event', s.oldest ? when(s.oldest) : '—'],
      ['File size', jBytes(s.bytes)], ['Kept for', (s.keep_days || 90) + ' days'],
      ['Last purge', s.last_purge ? when(s.last_purge) : 'not yet'],
      ['Written*', jN(s.written)], ['Dropped*', jN(s.dropped)], ['Page posts refused*', jN(s.rejected)],
      ['Purged*', jN(s.purged)], ['Waiting to write', jN(s.queue)]
    ]));
    box.appendChild(h('p', { class: 'hc-foot', text: '* since the portal backend last started. Refused posts are page posts that failed the origin, size or rate checks.' }));
  }

  function jRenderFlags(d) {
    var box = $('hc-j-flags');
    clear(box);
    var aia = (d.submits || []).filter(function (r) { return /^aia /.test(r.k); }).reduce(function (a, r) { return a + (num(r.n) || 0); }, 0);
    var flags = d.flags || [];
    if (!flags.length) {
      box.appendChild(h('p', { class: 'hc-note ok', text: d.empty ? 'Nothing recorded yet.'
        : plural(aia, 'AI Use Case Intake') + ' filed in this window; none flagged.' }));
      return;
    }
    box.appendChild(h('p', { class: 'hc-msg', text: plural(flags.length, 'flagged intake') + ' of ' + plural(aia, 'AI Use Case Intake') + ' filed in this window' + (flags.length >= 200 ? ' (newest 200 shown)' : '') + '. Newest first.' }));
    var tb = h('tbody');
    flags.forEach(function (f) {
      tb.appendChild(h('tr', null, [
        h('td', { text: when(f.ts) }),
        h('td', { text: f.email || '—' }),
        h('td', { class: 'key', text: (f.id || '—') + (f.via ? ' · from ' + f.via : '') }),
        h('td', { text: f.reason }),
        h('td', null, [f.email ? h('button', { type: 'button', class: 'hc-btn small', text: 'Show journey',
          on: { click: function () { $('hc-j-email').value = f.email; jPerson(true); } } }) : null])
      ]));
    });
    box.appendChild(h('div', { class: 'hc-tw' }, [stack(h('table', { class: 'hc-table' }, [
      h('thead', null, [h('tr', null, [h('th', { text: 'Filed' }), h('th', { text: 'Person' }), h('th', { text: 'Request' }), h('th', { text: 'Why it is flagged' }), h('th', { text: '' })])]),
      tb]))]));
  }

  function jRenderSummary(d) {
    var box = $('hc-j-sum');
    clear(box);
    if (d.empty) return;
    var L = d.loads || {}, I = d.identity || {}, C = d.chooser || {}, A = d.acks || {}, W = L.width || {};
    box.appendChild(jCard('Page loads', 'Window width when the page opened.', [
      jFacts([['Loads', jN(L.count)], ['From browser cache', jN(L.cached)],
        ['Under 600 px', jN(W['<600'] || 0)], ['600–859 px', jN(W['600-859'] || 0)],
        ['860–1199 px', jN(W['860-1199'] || 0)], ['1200 px and up', jN(W['1200+'] || 0)],
        W.unknown ? ['Width unknown', jN(W.unknown)] : null]),
      jCounts('Page version', L.rev, 'None recorded.'),
      jCounts('How the page was opened', jObjRows(L.nav), 'None recorded.')
    ]));
    box.appendChild(jCard('Who the server saw', 'One identity check per page load, so these count checks, not people.', [
      jFacts([['Signed in', jN(I.verified)], ['Not signed in', jN(I.unverified)],
        ['Eligible for card 2', jN(I.eligible)], ['Not eligible', jN(I.not_eligible)], ['Blocked', jN(I.blocked)]]),
      jCounts('Eligibility source', jObjRows(I.elig_source), 'None recorded.'),
      jCounts('Employment source', jObjRows(I.emp_source), 'None recorded.')
    ]));
    box.appendChild(jCard('AI Use Case Intake chooser', 'The two-card screen.', [
      jFacts([['Times shown', jN(C.views)], ['Visits shown it', jN(C.visits)],
        ['Card 2 greyed out', jN(C.c2_disabled)], ['Card 2 below the fold', jN(C.c2_below_fold)],
        ['Shown stacked', jN(C.stacked)], ['Visits: card 2 usable on screen', jN(C.c2_seen_visits)],
        ['Visits: card 2 never usable on screen', jN(C.c2_never_seen_visits)]])
    ]));
    box.appendChild(jCard('Sign-in', 'Silent and Microsoft sign-in starts, and how they came back.', [
      jCounts('Sign-in', d.signin, 'No sign-ins in this window.', jSignin)
    ]));
    box.appendChild(jCard('Requests filed', 'Form, where the page says it came from, and the identity source.', [
      jCounts('Requests', d.submits, 'No requests filed in this window.'),
      jFacts([['Acknowledgments recorded', jN(A['new'])], ['Already on file', jN(A.already)], ['Refused', jN(A.refused)]])
    ]));
    box.appendChild(jCard('Page errors', 'Script errors and failed submits as the page saw them.', [
      jCounts('Script errors', d.js_errors, 'No script errors in this window.'),
      jCounts('Failed submits', d.form_failures, 'No failed submits in this window.')
    ]));
  }

  function jLoad() {
    if (jBusy) return;
    jBusy = true;
    jLoaded = true;
    var btn = $('hc-j-refresh'), hours = $('hc-j-hours').value;
    btn.disabled = true;
    $('hc-j-updated').textContent = 'Loading…';
    jGet(J_API + '/summary?hours=' + encodeURIComponent(hours)).then(function (r) {
      jBusy = false;
      btn.disabled = false;
      if (!r.ok) {
        $('hc-j-updated').textContent = '';
        clear($('hc-j-head')); clear($('hc-j-flags')); clear($('hc-j-sum'));
        $('hc-j-head').appendChild(h('p', { class: 'hc-note bad', text: r.msg }));
        $('hc-j-flags').appendChild(h('p', { class: 'hc-msg', text: 'Not available: the journey log could not be read.' }));
        return;
      }
      $('hc-j-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
      jRenderHead(r.data);
      jRenderFlags(r.data);
      jRenderSummary(r.data);
    });
  }

  function jVisit(g, open) {
    var flags = g.flags || [];
    var det = h('details', { class: 'hc-j-visit' });
    det.open = !!open || flags.length > 0;
    var head = h('summary', null, [
      h('span', { class: 'hc-j-when', text: when(g.first) + (g.last && g.last !== g.first ? ' – ' + jTime(g.last) : '') }),
      h('span', { class: 'hc-j-meta', text: (g.visit ? jUa(g.ua) + (g.w ? ' · ' + g.w + ' px wide' : '') + ' · visit ' + g.visit.slice(0, 8)
        : 'Server records without a page visit') + ' · ' + plural(g.events.length, 'event') }),
      flags.length ? h('span', { class: 'hc-chip s-warn', text: 'Possible wrong form' }) : null
    ]);
    det.appendChild(head);
    if (g.ua) head.title = g.ua;
    flags.forEach(function (f) {
      det.appendChild(h('p', { class: 'hc-note bad', text: (f.id || 'An AI Use Case Intake') + ': ' + f.reason }));
    });
    var tb = h('tbody');
    g.events.forEach(function (e) {
      var said = jSay(e);
      var hit = e.event === 'submit' && flags.some(function (f) { return f.id && f.id === (e.data || {}).id; });
      tb.appendChild(h('tr', { class: (e.origin === 'server' ? 'hc-j-srv' : '') + (hit ? ' hc-j-hit' : '') }, [
        h('td', { class: 'u-mono', text: jTime(e.ts) }),
        h('td', { text: e.origin === 'server' ? 'Server' : 'Page' }),
        h('td', null, [h('div', { text: said[0] }), said[1] ? h('div', { class: 'hc-j-det', text: said[1] }) : null])
      ]));
    });
    det.appendChild(h('div', { class: 'hc-tw' }, [stack(h('table', { class: 'hc-table hc-j-small hc-j-tl' }, [
      h('thead', null, [h('tr', null, [h('th', { text: 'Time' }), h('th', { text: 'From' }), h('th', { text: 'What happened' })])]),
      tb]))]));
    return det;
  }

  function jPerson(scroll) {
    if (jPersonBusy) return;
    var input = $('hc-j-email'), box = $('hc-j-person');
    var email = String(input.value || '').trim().toLowerCase();
    clear(box);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      input.classList.add('invalid');
      box.appendChild(h('p', { class: 'hc-msg bad', text: 'Enter a full email address.' }));
      return;
    }
    input.classList.remove('invalid');
    jPersonBusy = true;
    var days = $('hc-j-days').value;
    box.appendChild(h('div', { class: 'hc-skel', text: 'Looking up ' + email + '…' }));
    if (scroll) $('hc-j-pform').scrollIntoView({ behavior: 'smooth', block: 'start' });
    jGet(J_API + '/person?email=' + encodeURIComponent(email) + '&days=' + encodeURIComponent(days)).then(function (r) {
      jPersonBusy = false;
      clear(box);
      if (!r.ok) { box.appendChild(h('p', { class: 'hc-note bad', text: r.msg })); return; }
      var d = r.data, visits = d.visits || [];
      if (!visits.length) {
        box.appendChild(h('p', { class: 'hc-note', text: 'Nothing recorded for ' + d.email + ' in the last ' + plural(d.days, 'day') + '. The log only holds visits since this logging went live, and keeps ' + (d.keep_days || 90) + ' days.' }));
        return;
      }
      if (d.truncated) box.appendChild(h('p', { class: 'hc-note', text: 'More than 5,000 events: the oldest are shown, the newest are cut off. Pick fewer days to see the latest.' }));
      var nflag = visits.reduce(function (a, g) { return a + (g.flags || []).length; }, 0);
      box.appendChild(h('p', { class: 'hc-msg', text: d.email + ': ' + plural(visits.length, 'visit') + ' in the last ' + plural(d.days, 'day') + ', newest first'
        + (nflag ? '; ' + plural(nflag, 'possible wrong form') : '') + '.' }));
      visits.forEach(function (g, i) { box.appendChild(jVisit(g, i === 0)); });
    });
  }

  function loadJourneys() {
    if (!jLoaded) jLoad();
  }
  function wireJourneys() {
    $('hc-j-refresh').addEventListener('click', jLoad);
    $('hc-j-hours').addEventListener('change', jLoad);
    $('hc-j-pform').addEventListener('submit', function (e) { e.preventDefault(); jPerson(false); });
  }

  /* ═══ tabs ════════════════════════════════════════════════════════════ */
  var TABS = ['status', 'settings', 'journeys'];
  function showTab(name, focus) {
    if (TABS.indexOf(name) === -1) name = 'status';
    TABS.forEach(function (t) {
      var on = t === name;
      var btn = $('hc-tab-' + t);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
      btn.tabIndex = on ? 0 : -1;
      $('hc-panel-' + t).hidden = !on;
      if (on && focus) btn.focus();
    });
    try { history.replaceState(null, '', name === 'status' ? location.pathname + location.search : '#' + name); } catch (e) { /* file:// and sandboxes */ }
    if (name === 'settings') loadSettings();
    if (name === 'journeys') loadJourneys();
    if (name === 'status' && lastDone && Date.now() - lastDone.getTime() > REFRESH_MS) refresh();
  }
  function wireTabs() {
    TABS.forEach(function (t, i) {
      var btn = $('hc-tab-' + t);
      btn.addEventListener('click', function () { showTab(t); });
      btn.addEventListener('keydown', function (e) {
        var next = e.key === 'ArrowRight' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' ? (i + TABS.length - 1) % TABS.length : e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : -1;
        if (next >= 0) { e.preventDefault(); showTab(TABS[next], true); }
      });
    });
    window.addEventListener('hashchange', function () { showTab(location.hash.replace('#', '')); });
  }

  /* ═══ access gate ═════════════════════════════════════════════════════ */
  /* Hide first, ask second: the tabs and panels start hidden and open only on an
     affirmative super-admin answer. "Could not ask" is its own message, so a
     failed permission lookup is never worded as "you are not allowed". */
  function gateShow(title, text, action) {
    $('hc-gate-h').textContent = title;
    $('hc-gate-p').textContent = text;
    var box = $('hc-gate-a');
    clear(box);
    if (action) box.appendChild(action);
  }
  function gateCheck() {
    var rb = window.itRbac;
    var ready = rb && typeof rb.ready === 'function' ? Promise.resolve(rb.ready()).catch(function () { return null; }) : Promise.resolve(null);
    return ready.then(function () {
      var state = '', me = null;
      try { state = rb && rb.state ? rb.state() : ''; me = state === 'ok' ? rb.me() : null; } catch (e) { state = ''; me = null; }
      if (state === 'unauthenticated') {
        gateShow('Session required', 'Your session is not active. Sign in, then return here.',
          h('a', { href: '/login.html?return=' + encodeURIComponent(location.pathname), text: 'Sign in' }));
        return false;
      }
      if (state !== 'ok' || !(me && me.email)) {          // an answer with no identity in it is not an answer
        gateShow('Access check did not complete', 'The permission service did not answer, so this page cannot confirm who you are. This is not a sign-out. Retry; if it keeps happening the hub API is unavailable.',
          h('button', { type: 'button', class: 'hc-btn', text: 'Retry', on: { click: function () { location.reload(); } } }));
        return false;
      }
      if (me.isSuperAdmin !== true) {
        gateShow('Super-admin only', 'Health Center is available to super-admins only. Your account does not have that level. Ask a platform owner if you need it.');
        return false;
      }
      return true;
    });
  }

  /* ═══ boot ════════════════════════════════════════════════════════════ */
  function boot() {
    gateCheck().then(function (ok) {
      if (!ok) return;
      $('hc-gate').hidden = true;
      $('hc-tabs').hidden = false;
      $('hc-main').hidden = false;
      start();
    });
  }
  function start() {
    wireTabs();
    wireJourneys();
    $('hc-refresh').addEventListener('click', refresh);
    showTab(location.hash.replace('#', ''));
    refresh();
    setInterval(function () {
      if (document.hidden || $('hc-panel-status').hidden || pendingN > 0) return;
      refresh();
    }, REFRESH_MS);
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden && !$('hc-panel-status').hidden && pendingN === 0 && lastDone && Date.now() - lastDone.getTime() > REFRESH_MS) refresh();
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
