'use strict';
/* ════════════════════════════════════════════════════════════════════
   /api/netdiag — Network Diagnostics backend (P1)
   Reads FortiGate REST monitor APIs on Irvine + Dallas and returns
   responses shaped exactly for beta-network-diag.html.

   Env (in /var/www/corpit-hub-api/.env):
     FORTIGATE_HOST / FORTIGATE_API_TOKEN                → fw=irvine
     FORTIGATE_DALLAS_HOST / FORTIGATE_DALLAS_API_TOKEN → fw=dallas

   TLS: FortiGate mgmt is reached by IP; certs are NRPI-CA issued with
   CN=nrpi.local. Every request uses the shared verifying agent from
   ./fortigate-tls (NRPI CA + name check + optional SHA-256 pin).

   Mount (in the api-beta entry file):
     const buildNetdiag = require('./netdiag');
     app.use('/api/netdiag', buildNetdiag({ requirePage }));  // rbac optional
   ════════════════════════════════════════════════════════════════════ */

const express = require('express');
const https = require('https');
const { URL } = require('url');
const net = require('net');
const { agent: fortigateAgent } = require('./fortigate-tls');

const FW = {
  irvine: { host: process.env.FORTIGATE_HOST, token: process.env.FORTIGATE_API_TOKEN },
  dallas: { host: process.env.FORTIGATE_DALLAS_HOST, token: process.env.FORTIGATE_DALLAS_API_TOKEN },
};

const FGT_TIMEOUT_MS = 10000;

// P2 correlation: reverse an IP to a device via DHCP (WinRM), then hand the
// hostname to user360 for the full identity + device picture.
const { execFile } = require('child_process');
const path = require('path');
const DHCP_SERVERS = { primary: '10.20.10.52', secondary: '10.9.65.56' };
const INTERNAL_API_BASE = process.env.INTERNAL_API_BASE || 'http://127.0.0.1:3001';
const RESOLVE_TIMEOUT_MS = 12000;

function dhcpByIp(ip, server) {
  return new Promise(resolve => {
    // CR-2: ip is interpolated into a PowerShell script that runs on the DHCP server
    // (dhcp-lookup.py). Only a dotted-quad IPv4 literal may ever reach the spawn.
    if (!net.isIPv4(ip)) return resolve(null);
    const script = path.join(__dirname, 'dhcp-lookup.py');
    execFile('python3', [script, '--ip', ip, '--server', server], { timeout: 30000 }, (err, stdout) => {
      if (err) return resolve(null);
      try { const j = JSON.parse(stdout); resolve(j && !j.error ? j : null); }
      catch { resolve(null); }
    });
  });
}
async function dhcpResolve(ip) {
  // Query both DHCP servers concurrently and prefer the primary's answer. Probing them
  // sequentially cost ~5s on every IP trace (~2.4s each) even when neither had a lease.
  // (Fixed 2026-08-21.)
  const [primary, secondary] = await Promise.all([
    dhcpByIp(ip, DHCP_SERVERS.primary),
    dhcpByIp(ip, DHCP_SERVERS.secondary),
  ]);
  return primary || secondary;
}
async function user360(q, cred) {
  const _fetch = global.fetch;
  if (!_fetch) throw new Error('global fetch unavailable (Node < 18)');
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), RESOLVE_TIMEOUT_MS);
  try {
    const r = await _fetch(`${INTERNAL_API_BASE}/api/user360/${encodeURIComponent(q)}`, {
      headers: { ...(cred.authorization ? { Authorization: cred.authorization } : {}), ...(cred.cookie ? { Cookie: cred.cookie } : {}) }, signal: ctrl.signal,
    });
    const text = await r.text();
    let body; try { body = text ? JSON.parse(text) : null; } catch { body = null; }
    if (!r.ok) { const e = new Error(`user360 ${r.status}`); e.status = r.status; e.body = body; throw e; }
    return body;
  } finally { clearTimeout(timer); }
}

/* ── low-level FortiGate GET ─────────────────────────────────────── */
function fgtGet(fw, apiPath, query, options = {}) {
  return new Promise((resolve, reject) => {
    const cfg = FW[fw];
    if (!cfg || !cfg.host || !cfg.token) {
      const e = new Error(`firewall "${fw}" is not configured (missing env)`);
      e.statusCode = 400;
      return reject(e);
    }
    let u;
    try {
      u = new URL(apiPath, cfg.host.endsWith('/') ? cfg.host : cfg.host + '/');
    } catch (err) {
      return reject(new Error(`bad FORTIGATE host for "${fw}"`));
    }
    if (query) Object.keys(query).forEach(k => { if (query[k] != null) u.searchParams.set(k, query[k]); });

    const req = https.request({
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      method: 'GET',
      headers: { Authorization: `Bearer ${cfg.token}`, Accept: 'application/json' },
      // Verified against the NRPI CA (F13/F14) — see fortigate-tls.js.
      agent: fortigateAgent,
      timeout: FGT_TIMEOUT_MS,
    }, res => {
      let body = '', bytes = 0;
      res.on('data', c => {
        bytes += c.length;
        if (Number.isSafeInteger(options.maxBytes) && options.maxBytes > 0 && bytes > options.maxBytes) {
          const error = new Error('FortiGate response exceeded the read limit');
          reject(error); req.destroy(error);
          return;
        }
        body += c;
      });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode === 401 || res.statusCode === 403) {
          const e = new Error(`FortiGate ${fw} rejected the API token (HTTP ${res.statusCode}) — check trusted-host + key`);
          e.statusCode = 502;
          return reject(e);
        }
        if (res.statusCode >= 400) {
          const e = new Error(`FortiGate ${fw} HTTP ${res.statusCode} on ${u.pathname}`);
          e.statusCode = 502;
          return reject(e);
        }
        try { resolve(JSON.parse(body)); }
        catch (err) { reject(new Error(`FortiGate ${fw} returned non-JSON on ${u.pathname}`)); }
      });
    });
    req.on('timeout', () => { req.destroy(new Error(`FortiGate ${fw} timed out after ${FGT_TIMEOUT_MS}ms`)); });
    req.on('error', reject);
    req.end();
  });
}

const results = r => (r && (Array.isArray(r.results) ? r.results : r.results != null ? r.results : r)) || [];

/* ── helpers ─────────────────────────────────────────────────────── */
function humanBytes(n) {
  n = Number(n) || 0;
  if (n >= 1e12) return (n / 1e12).toFixed(1) + 'T';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}
function ago(epochSec) {
  if (!epochSec) return null;
  const s = Math.max(0, Math.floor(Date.now() / 1000 - epochSec));
  if (s < 90) return s + 's ago';
  if (s < 5400) return Math.round(s / 60) + ' min ago';
  if (s < 172800) return Math.round(s / 3600) + ' hours ago';
  return Math.round(s / 86400) + ' days ago';
}
// FortiOS monitor vpn/ipsec creation_time is RELATIVE (seconds since the
// tunnel established), not an epoch — format it as an uptime duration.
function upFor(sec) {
  sec = Number(sec) || 0;
  if (sec <= 0) return null;
  if (sec < 90) return 'up ' + sec + 's';
  if (sec < 5400) return 'up ' + Math.round(sec / 60) + ' min';
  if (sec < 172800) return 'up ' + Math.round(sec / 3600) + ' hours';
  return 'up ' + Math.round(sec / 86400) + ' days';
}
const sendOk = (res, data) => res.json({ ok: true, data });
const sendErr = (res, err) => res.status((err && err.statusCode) || 502).json({ ok: false, error: { message: (err && err.message) || 'upstream error' } });

/* ── mappers: FortiOS monitor payload → frontend shape ───────────── */

// Backup/on-demand tunnels are named or commented with these markers.
const BACKUP_RE = /(^|[^a-z])(bu|backup)([^a-z]|$)/i;
function isBackup(t) {
  return BACKUP_RE.test(t.name || '') || BACKUP_RE.test(t.comments || '');
}

function mapTunnels(raw, fw) {
  const localFallback = (FW[fw] && FW[fw].host || '').replace(/^https?:\/\//, '') || '—';
  return results(raw).map(t => {
    const proxies = Array.isArray(t.proxyid) ? t.proxyid : [];
    const p2up = proxies.some(p => p.status === 'up');
    const traffic = (Number(t.incoming_bytes) || 0) + (Number(t.outgoing_bytes) || 0);
    const backup = isBackup(t);

    // Selectors: FortiOS returns 0.0.0.0/0 for route-based (VTI) tunnels,
    // where the real scoping lives on the static route — label it plainly
    // instead of showing a meaningless wildcard pair.
    const rawSel = proxies.map(p =>
      `${(p.proxy_src && p.proxy_src[0] && (p.proxy_src[0].subnet || p.proxy_src[0].name)) || '?'} <> ${(p.proxy_dst && p.proxy_dst[0] && (p.proxy_dst[0].subnet || p.proxy_dst[0].name)) || '?'}`
    ).join(', ');
    const allWildcard = proxies.length > 0 && proxies.every(p =>
      p.proxy_src && p.proxy_src[0] && /^0\.0\.0\.0/.test(p.proxy_src[0].subnet || '') &&
      p.proxy_dst && p.proxy_dst[0] && /^0\.0\.0\.0/.test(p.proxy_dst[0].subnet || ''));
    const selectors = allWildcard ? 'route-based (VTI) — scoped by static route' : (rawSel || '—');

    // Verdict:
    //   up   → phase-2 SA established (active tunnel)
    //   idle → backup/on-demand tunnel, down with no traffic (healthy resting state)
    //   down → a tunnel that should be carrying traffic but isn't
    let status;
    if (p2up) status = 'up';
    else if (backup && traffic === 0) status = 'idle';
    else status = 'down';

    const expires = proxies.filter(p => p.status === 'up' && p.expire != null).map(p => Number(p.expire));

    return {
      remote: t.name || 'tunnel',
      remotePeer: t.rgwy || t['remote-gw'] || t.tun_id || '—',
      local: t.lgwy || t['local-gw'] || localFallback,
      role: backup ? 'backup' : 'primary',
      phase1: status === 'down' ? 'down' : 'up',
      phase2: p2up ? 'up' : 'down',
      status,
      reason: status === 'down' ? 'phase-2 SA is down and no traffic is flowing on a primary tunnel' : undefined,
      ike: t['wizard-type'] || t.wizard_type || undefined,
      selectors,
      comments: t.comments || undefined,
      pfs: undefined,
      rekey: expires.length ? Math.min.apply(null, expires) : null,
      pin: humanBytes(t.incoming_bytes),
      pout: humanBytes(t.outgoing_bytes),
      dpd: t.connection_count > 0 ? `${t.connection_count} connection(s)` : (backup ? 'on-demand / failover' : undefined),
      lastChange: upFor(t.creation_time),
    };
  });
}

async function getRoutes(fw) {
  const raw = await fgtGet(fw, 'api/v2/monitor/router/ipv4');
  const routes = results(raw).map(r => ({
    dest: r.ip_mask || r.dst || '—',
    via: r.gateway && r.gateway !== '0.0.0.0' ? r.gateway : 'connected',
    iface: r.interface || '—',
    type: r.type || '—',
    status: 'ok',
  }));

  // Dynamic routing — discovered through the API, never assumed.
  let dynamic = null;
  try {
    const bgp = results(await fgtGet(fw, 'api/v2/monitor/router/bgp/neighbors'));
    if (bgp.length) {
      dynamic = {
        protocol: 'BGP',
        neighbors: bgp.map(n => ({
          peer: n.neighbor_ip || n.ip || '—',
          state: n.state || (n.is_established ? 'Established' : 'Idle'),
          prefixes: (n.received_prefixes != null ? n.received_prefixes : n.prefixes_received != null ? n.prefixes_received : '—') + ' rx',
          uptime: n.uptime != null ? String(n.uptime) : '—',
        })),
      };
    }
  } catch (e) { /* endpoint absent or BGP not running — fine */ }
  if (!dynamic) {
    try {
      const ospf = results(await fgtGet(fw, 'api/v2/monitor/router/ospf/neighbors'));
      if (ospf.length) {
        dynamic = {
          protocol: 'OSPF',
          neighbors: ospf.map(n => ({
            peer: n.neighbor_ip || n.router_id || '—',
            state: n.state || '—',
            prefixes: '—',
            uptime: '—',
          })),
        };
      }
    } catch (e) { /* fine */ }
  }
  return { routes, dynamic };
}

function mapInterfaces(raw) {
  const arr = results(raw);
  const list = Array.isArray(arr) ? arr : Object.keys(arr).map(k => Object.assign({ name: k }, arr[k]));
  return list
    .filter(i => i.name && !/^(ssl\.|l2t\.|naf\.)/.test(i.name))
    .map(i => {
      const speedNum = Number(i.speed) || 0;
      return {
        name: i.name,
        role: (i.alias || i.type || '—').replace(/^\(|\)$/g, ''),
        state: i.link ? 'up' : 'down',
        speed: i.link ? `${speedNum >= 1000 ? (speedNum / 1000) + ' Gbps' : speedNum + ' Mbps'} / ${i.duplex === 1 || i.duplex === 'full' ? 'full' : i.duplex === 0 || i.duplex === 'half' ? 'half' : '—'}` : '—',
        errs: (Number(i.tx_errors) || 0) + (Number(i.rx_errors) || 0),
        drops: (Number(i.tx_drops) || 0) + (Number(i.rx_drops) || 0),
        // Utilization needs two samples to compute; not available from one
        // monitor read. 0 keeps the bar honest until we add sampling.
        util: 0,
        rx: humanBytes(i.rx_bytes),
        tx: humanBytes(i.tx_bytes),
      };
    });
}

async function getPolicies(fw) {
  const [cmdb, mon] = await Promise.all([
    fgtGet(fw, 'api/v2/cmdb/firewall/policy'),
    fgtGet(fw, 'api/v2/monitor/firewall/policy'),
  ]);
  const stats = {};
  results(mon).forEach(p => { stats[p.policyid] = p; });
  const names = a => (Array.isArray(a) ? a.map(x => x.name).join(',') : '—') || 'any';
  return results(cmdb).map(p => {
    const st = stats[p.policyid] || {};
    return {
      seq: p.policyid,
      name: p.name || `policy-${p.policyid}`,
      src: names(p.srcaddr),
      dst: names(p.dstaddr),
      svc: names(p.service),
      action: (p.action || 'deny').toUpperCase() === 'ACCEPT' ? 'ACCEPT' : 'DENY',
      hits: Number(st.hit_count != null ? st.hit_count : st.packets) || 0,
      bytes: humanBytes(st.bytes),
      last: st.last_used ? ago(st.last_used) : '—',
    };
  });
}

function mapSessions(raw) {
  const arr = results(raw);
  const list = Array.isArray(arr) ? arr : (arr.details || []);
  return list.map(s => {
    const proto = (s.proto || (s.protocol === 6 ? 'tcp' : s.protocol === 17 ? 'udp' : s.protocol) || '?');
    const dport = s.dport != null ? s.dport : s.dst_port;
    const nat = (s.natsaddr || s.natip)
      ? `SNAT ${s.natsaddr || s.natip}${s.natsport ? ':' + s.natsport : ''}`
      : (s.nat === 'snat' ? 'SNAT' : 'none');
    return {
      src: `${s.saddr || s.src || '—'}:${s.sport != null ? s.sport : ''}`,
      dst: `${s.daddr || s.dst || '—'}:${dport != null ? dport : ''}`,
      proto: `${proto}/${dport != null ? dport : ''}`,
      policy: s.policyid != null ? String(s.policyid) : '—',
      nat: nat,
      egress: s.dstintf || s['dst-intf'] || '—',
      exp: (s.expiry != null ? s.expiry : s.expire != null ? s.expire : s.duration != null ? s.duration : '—') + 's',
    };
  });
}

/* ── router ──────────────────────────────────────────────────────── */
module.exports = function buildNetdiagRouter(deps) {
  const router = express.Router();
  const gate = deps && typeof deps.requirePage === 'function'
    ? deps.requirePage('network-diag')
    : (req, res, next) => next();
  router.use(gate);

  const fwOf = req => {
    const fw = String(req.query.fw || 'irvine').toLowerCase();
    return FW[fw] ? fw : null;
  };
  const guard = (req, res) => {
    const fw = fwOf(req);
    if (!fw) { res.status(400).json({ ok: false, error: { message: 'unknown fw — use fw=irvine|dallas' } }); return null; }
    return fw;
  };

  router.get('/fortigate/status', async (req, res) => {
    const fw = guard(req, res); if (!fw) return;
    try {
      const r = await fgtGet(fw, 'api/v2/monitor/system/status');
      const d = r.results || {};
      sendOk(res, { hostname: d.hostname, model: d.model_number || d.model, version: r.version, serial: r.serial });
    } catch (e) { sendErr(res, e); }
  });

  router.get('/fortigate/tunnels', async (req, res) => {
    const fw = guard(req, res); if (!fw) return;
    try {
      const raw = await fgtGet(fw, 'api/v2/monitor/vpn/ipsec');
      sendOk(res, { tunnels: mapTunnels(raw, fw) });
    } catch (e) { sendErr(res, e); }
  });

  router.get('/fortigate/routes', async (req, res) => {
    const fw = guard(req, res); if (!fw) return;
    try { sendOk(res, await getRoutes(fw)); }
    catch (e) { sendErr(res, e); }
  });

  router.get('/fortigate/interfaces', async (req, res) => {
    const fw = guard(req, res); if (!fw) return;
    try {
      const raw = await fgtGet(fw, 'api/v2/monitor/system/interface', { include_vlan: 'true' });
      sendOk(res, { interfaces: mapInterfaces(raw) });
    } catch (e) { sendErr(res, e); }
  });

  router.get('/fortigate/resources', async (req, res) => {
    const fw = guard(req, res); if (!fw) return;
    try {
      const raw = await fgtGet(fw, 'api/v2/monitor/system/resource/usage');
      const d = results(raw);
      const pick = k => {
        const v = d[k];
        if (Array.isArray(v) && v.length) return Number(v[0].current) || 0;
        return Number(v && v.current) || 0;
      };
      sendOk(res, { cpu: pick('cpu'), mem: pick('mem'), disk: pick('disk'), sessions: pick('session') });
    } catch (e) { sendErr(res, e); }
  });

  router.get('/fortigate/policies', async (req, res) => {
    const fw = guard(req, res); if (!fw) return;
    try { sendOk(res, { policies: await getPolicies(fw) }); }
    catch (e) { sendErr(res, e); }
  });

  router.get('/fortigate/sessions', async (req, res) => {
    const fw = guard(req, res); if (!fw) return;
    try {
      const raw = await fgtGet(fw, 'api/v2/monitor/firewall/session', {
        count: Math.min(Number(req.query.count) || 100, 500),
        summary: 'false',
        ip_version: 'ipv4',
      });
      sendOk(res, { sessions: mapSessions(raw), total: (raw.results && raw.results.total) || undefined });
    } catch (e) { sendErr(res, e); }
  });

  // Single-IP query for the Query Console: best-matching live session.
  router.get('/fortigate/session', async (req, res) => {
    const fw = guard(req, res); if (!fw) return;
    const ip = String(req.query.ip || '').trim();
    if (!ip) return res.status(400).json({ ok: false, error: { message: 'ip required' } });
    try {
      const raw = await fgtGet(fw, 'api/v2/monitor/firewall/session', {
        count: 200, summary: 'false', ip_version: 'ipv4',
      });
      const all = results(raw);
      const list = Array.isArray(all) ? all : (all.details || []);
      const hit = list.find(s => s.saddr === ip || s.daddr === ip);
      if (!hit) return sendOk(res, null);
      const s = mapSessions([hit])[0];
      sendOk(res, {
        src: s.src, dst: s.dst, proto: s.proto,
        policy: s.policy, nat: s.nat,
        tunnel: s.egress, iface: s.egress,
        expires: s.exp, status: 'ok',
        because: `Traffic from this host is matching policy ${s.policy} and egressing via ${s.egress}.`,
      });
    } catch (e) { sendErr(res, e); }
  });

  // ── P2 correlation: user <-> identity <-> device <-> network path ──
  router.get('/resolve', async (req, res) => {
    const by = String(req.query.by || 'user').toLowerCase();
    const q = String(req.query.q || '').trim();
    const auth = { authorization: req.headers.authorization || '', cookie: req.headers.cookie || '' };
    if (!q) return res.status(400).json({ ok: false, error: { message: 'q required' } });
    // CR-2: anything other than by=user takes the IP path below, whose q feeds
    // dhcp-lookup.py (WinRM PowerShell). Reject unknown modes and require a strict
    // IPv4 literal for by=ip BEFORE any upstream call.
    if (by !== 'user' && by !== 'ip') return res.status(400).json({ ok: false, error: { message: 'by must be user|ip' } });
    if (by === 'ip' && !net.isIPv4(q)) return res.status(400).json({ ok: false, error: { message: 'q must be an IPv4 address when by=ip' } });

    try {
      if (by === 'user') {
        const u360 = await user360(q, auth);
        return sendOk(res, { by, query: q, network: null, user360: u360 });
      }

      // by === 'ip': live FortiGate session for context + DHCP reverse -> user360
      const fw = fwOf(req) || 'irvine';
      let network = null;
      try {
        const raw = await fgtGet(fw, 'api/v2/monitor/firewall/session', { count: 200, summary: 'false', ip_version: 'ipv4' });
        const all = results(raw); const list = Array.isArray(all) ? all : (all.details || []);
        const hit = list.find(s => s.saddr === q || s.daddr === q);
        if (hit) network = Object.assign({ fw }, mapSessions([hit])[0]);
      } catch (e) { /* session context is best-effort */ }

      const lease = await dhcpResolve(q);
      let u360 = null, resolvedFrom = null;
      if (lease && lease.hostname) {
        resolvedFrom = lease.hostname;
        // DHCP returns an FQDN (WARVID-07.NRPI.LOCAL) but user360 matches the AD short
        // name (sAMAccountName WARVID-07$), so the full name always 404d. (Fixed 2026-08-21.)
        const shortName = String(lease.hostname).split('.')[0];
        try { u360 = await user360(shortName, auth); } catch (e) { u360 = { _error: e.message }; }
      }
      return sendOk(res, {
        by, query: q, network,
        dhcp: lease || null,
        resolvedFrom,
        user360: u360,
        note: lease ? undefined : 'No DHCP lease found for this IP — identity resolution needs a current lease.',
      });
    } catch (e) {
      return res.status(e.status === 404 ? 404 : 502).json({ ok: false, error: { message: e.message, upstream: e.body || undefined } });
    }
  });

  return router;
};

// Shared transport for explicit selected-device read-only checks; legacy routes are unchanged.
module.exports.fgtGet = fgtGet;
