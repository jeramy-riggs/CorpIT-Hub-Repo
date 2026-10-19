'use strict';
// SW-LIB v1.0.0 — shared helpers for signin-watch (poller + routes)
// Marker: SIGNIN-WATCH-LIB

// ---- IP / CIDR matching (IPv4 + IPv6) -------------------------------
function ipToBigInt(ip) {
  if (!ip) return null;
  ip = String(ip).trim();
  // strip port forms like "1.2.3.4:443" (IPv4 only)
  if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(ip)) ip = ip.split(':')[0];
  if (ip.includes('.') && !ip.includes(':')) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return null;
    return { v: 4, n: BigInt(parts[0]) * 16777216n + BigInt(parts[1]) * 65536n + BigInt(parts[2]) * 256n + BigInt(parts[3]) };
  }
  if (ip.includes(':')) {
    // IPv4-mapped ::ffff:1.2.3.4
    const m4 = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (m4) return ipToBigInt(m4[1]);
    let head = ip, tail = '';
    if (ip.includes('::')) {
      const seg = ip.split('::');
      if (seg.length !== 2) return null;
      head = seg[0]; tail = seg[1];
    }
    const h = head ? head.split(':') : [];
    const t = tail ? tail.split(':') : [];
    const fill = 8 - h.length - t.length;
    if (fill < 0 && ip.includes('::')) return null;
    const groups = ip.includes('::') ? [...h, ...Array(fill).fill('0'), ...t] : h;
    if (groups.length !== 8) return null;
    let n = 0n;
    for (const g of groups) {
      if (!/^[0-9a-f]{0,4}$/i.test(g)) return null;
      n = (n << 16n) + BigInt(parseInt(g || '0', 16));
    }
    return { v: 6, n };
  }
  return null;
}

function ipInCidr(ip, cidr) {
  const parsedIp = ipToBigInt(ip);
  if (!parsedIp) return false;
  let base = cidr, bits = null;
  if (cidr.includes('/')) { const s = cidr.split('/'); base = s[0]; bits = parseInt(s[1], 10); }
  const parsedBase = ipToBigInt(base);
  if (!parsedBase || parsedBase.v !== parsedIp.v) return false;
  const maxBits = parsedIp.v === 4 ? 32 : 128;
  if (bits === null || isNaN(bits)) bits = maxBits;         // bare IP = /32 or /128
  if (bits < 0 || bits > maxBits) return false;
  const shift = BigInt(maxBits - bits);
  return (parsedIp.n >> shift) === (parsedBase.n >> shift);
}

function ipTrusted(ip, networks) {
  if (!ip) return false;
  for (const net of networks) {
    if (net.enabled && ipInCidr(ip, net.cidr)) return true;
  }
  return false;
}

// Like ipTrusted, but returns the TYPE of the first matching enabled network
// ('zscaler' | 'office-plano' | 'office-irvine' | 'other') or null if untrusted.
function ipTrustedType(ip, networks) {
  if (!ip) return null;
  for (const net of networks) {
    if (net.enabled && ipInCidr(ip, net.cidr)) return net.type || 'other';
  }
  return null;
}

function validCidr(cidr) {
  if (!cidr || typeof cidr !== 'string') return false;
  let base = cidr, bits = null;
  if (cidr.includes('/')) { const s = cidr.split('/'); if (s.length !== 2) return false; base = s[0]; bits = parseInt(s[1], 10); }
  const p = ipToBigInt(base);
  if (!p) return false;
  const maxBits = p.v === 4 ? 32 : 128;
  if (bits !== null && (isNaN(bits) || bits < 0 || bits > maxBits)) return false;
  return true;
}

// ---- Event normalization --------------------------------------------
// Okta System Log event -> violation-shape (before trusted check)
function normalizeOktaEvent(ev) {
  const actor = ev.actor || {};
  const client = ev.client || {};
  const geo = (client.geographicalContext) || {};
  const outcome = ev.outcome || {};
  let result = 'unknown';
  if (outcome.result === 'SUCCESS') result = 'success';
  else if (outcome.result === 'FAILURE' || outcome.result === 'DENY') result = 'failure';
  return {
    upn: (actor.alternateId || '').toLowerCase(),
    source: 'okta',
    source_event_id: ev.uuid,
    event_time: ev.published ? new Date(ev.published) : new Date(),
    ip: client.ipAddress || null,
    geo_country: geo.country || null,
    geo_city: geo.city || null,
    result,
    failure_reason: outcome.reason || null,
    app_name: ev.eventType || null,
    client_app: (client.userAgent && client.userAgent.browser) || null,
    user_agent: (client.userAgent && client.userAgent.rawUserAgent) || null,
    raw: ev,
  };
}

// Entra signIn resource -> violation-shape
function normalizeEntraEvent(ev) {
  const st = ev.status || {};
  const loc = ev.location || {};
  let result = 'unknown';
  if (st.errorCode === 0) result = 'success';
  else if (typeof st.errorCode === 'number') result = 'failure';
  return {
    upn: (ev.userPrincipalName || '').toLowerCase(),
    source: 'entra',
    source_event_id: ev.id,
    event_time: ev.createdDateTime ? new Date(ev.createdDateTime) : new Date(),
    ip: ev.ipAddress || null,
    geo_country: loc.countryOrRegion || null,
    geo_city: loc.city || null,
    result,
    failure_reason: st.errorCode ? `${st.errorCode}: ${st.failureReason || ''}`.slice(0, 500) : null,
    app_name: ev.appDisplayName || null,
    client_app: ev.clientAppUsed || null,
    user_agent: null,
    raw: ev,
  };
}

function fmtDateTimeSql(d) {
  // JS Date -> 'YYYY-MM-DD HH:MM:SS' (UTC)
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

module.exports = { ipToBigInt, ipInCidr, ipTrusted, ipTrustedType, validCidr, normalizeOktaEvent, normalizeEntraEvent, fmtDateTimeSql };
