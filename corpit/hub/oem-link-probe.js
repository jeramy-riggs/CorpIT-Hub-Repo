/**
 * oem-link-probe.js — "Check where it points": follow an Okta tile's URL from the server and record
 * which identity provider it lands on. The answer is evidence for "already migrated" (lands on Entra),
 * "still on Okta" (lands on Okta) or inconclusive (the vendor's own page — a sign-in there may bounce to
 * either IdP in a browser; this probe cannot tell).
 *
 * Guard rails: http/https only; the host must resolve to public addresses (no loopback, private, link-local,
 * CGNAT, multicast, .local/.internal); at most 6 hops; 8 s per hop; GET with no cookies or credentials;
 * at most 64 KB of a final HTML body is read, only to spot an IdP hostname or a <meta http-equiv=refresh>.
 * Nothing is written to any vendor; nothing here proves a sign-in works — Verify reads the sign-in log.
 */
'use strict';
const dns = require('dns').promises;
const net = require('net');
const L = require('./oem-lib');
const { pool, j, nowIso } = L;

const MAX_HOPS = 6, HOP_MS = 8000, BODY_BYTES = 65536;
const UA = 'corpit-okta-entra-migration link probe (GET, no credentials; follows redirects only)';
const REDIRECT = new Set([301, 302, 303, 307, 308]);

const IDP = [
  { idp: 'entra', re: /(^|\.)(login\.microsoftonline\.com|login\.microsoft\.com|login\.windows\.net|myapps\.microsoft\.com|myapplications\.microsoft\.com|login\.microsoftonline\.us|account\.activedirectory\.windowsazure\.com)$/i, label: 'Microsoft Entra ID' },
  { idp: 'okta', re: /(^|\.)(okta\.com|okta-emea\.com|oktapreview\.com|okta-gov\.com)$/i, label: 'Okta' },
  { idp: 'other_idp', re: /(^|\.)(accounts\.google\.com|onelogin\.com|pingone\.com|pingidentity\.com|auth0\.com|duosecurity\.com|jumpcloud\.com)$/i, label: 'another identity provider' },
];
const OKTA_BASE_HOST = (() => { try { return process.env.OKTA_BASE_URL ? new URL(process.env.OKTA_BASE_URL).hostname.toLowerCase() : null; } catch (e) { return null; } })();

/** Which IdP a hostname belongs to: {idp, label} or null (vendor / unknown). */
function classifyHost(host) {
  const h = String(host || '').toLowerCase();
  if (!h) return null;
  if (OKTA_BASE_HOST && h === OKTA_BASE_HOST) return { idp: 'okta', label: 'Okta (this org\'s Okta domain)' };
  for (const k of IDP) if (k.re.test(h)) return { idp: k.idp, label: k.label };
  return null;
}

/* ------------------------------------------------------------- address guard */
function privateV4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
  return p[0] === 0 || p[0] === 10 || p[0] === 127 || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || (p[0] === 169 && p[1] === 254)
    || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 192 && p[1] === 0 && (p[2] === 0 || p[2] === 2)) || (p[0] === 198 && (p[1] === 18 || p[1] === 19))
    || p[0] >= 224;
}
function privateV6(ip) {
  const a = ip.toLowerCase();
  if (a === '::' || a === '::1') return true;
  const m4 = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); if (m4) return privateV4(m4[1]);
  return /^f[cd]/.test(a) || /^fe[89ab]/.test(a) || /^fec/.test(a) || /^ff/.test(a);
}
function privateIp(ip) { const v = net.isIP(ip); return v === 4 ? privateV4(ip) : v === 6 ? privateV6(ip) : true; }

async function hostAllowed(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return { ok: false, why: 'no host' };
  if (h === 'localhost' || /\.(local|internal|localdomain|home|lan|corp)$/.test(h) || /(^|\.)nrpi\.local$/.test(h)) return { ok: false, why: `"${h}" is an internal name; the probe follows public hosts only` };
  if (net.isIP(h)) return privateIp(h) ? { ok: false, why: `${h} is not a public address` } : { ok: true };
  let addrs;
  try { addrs = await dns.lookup(h, { all: true }); } catch (e) { return { ok: false, why: `${h} does not resolve (${e.code || e.message})` }; }
  if (!addrs.length) return { ok: false, why: `${h} does not resolve` };
  const bad = addrs.find((a) => privateIp(a.address));
  if (bad) return { ok: false, why: `${h} resolves to ${bad.address}, which is not a public address` };
  return { ok: true };
}

/* ----------------------------------------------------------------- follow */
async function readHead(r) {
  const ct = String(r.headers.get('content-type') || '');
  if (!/text\/html|application\/xhtml/i.test(ct) || !r.body) { try { await r.body?.cancel(); } catch (e) { /* ignore */ } return ''; }
  const reader = r.body.getReader(); const chunks = []; let n = 0;
  try {
    while (n < BODY_BYTES) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); n += value.length; }
  } catch (e) { /* partial body is fine */ }
  try { await reader.cancel(); } catch (e) { /* ignore */ }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8', 0, Math.min(n, BODY_BYTES));
}
function metaRefresh(html, base) {
  const m = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']\s*\d+\s*;\s*url\s*=\s*([^"'>\s]+)/i) || html.match(/<meta[^>]+content\s*=\s*["']\s*\d+\s*;\s*url\s*=\s*([^"'>\s]+)["'][^>]*http-equiv\s*=\s*["']?refresh/i);
  if (!m) return null;
  try { return new URL(m[1].replace(/&amp;/g, '&'), base).href; } catch (e) { return null; }
}
function mentions(html) {
  const out = [];
  for (const k of IDP) { const re = new RegExp(k.re.source.replace(/^\(\^\|\\\.\)/, '(^|[^a-z0-9-])'), 'i'); if (re.test(html)) out.push(k.idp); }
  return out;
}

/** Follow one URL. Never throws; the result's idp is 'blocked' or 'error' when it could not be followed. */
async function follow(startUrl) {
  const hops = []; let cur = String(startUrl || '').trim(); let idpHit = null; let finalUrl = null; let mention = [];
  for (let i = 0; i < MAX_HOPS; i++) {
    let u; try { u = new URL(cur); } catch (e) { return { idp: 'error', hops, finalUrl: cur || null, detail: 'not a valid URL', mentions: [] }; }
    if (!/^https?:$/.test(u.protocol)) return { idp: 'blocked', hops, finalUrl: cur, detail: `only http/https URLs are followed (got ${u.protocol})`, mentions: [] };
    // a known IdP host is trusted by name (public SaaS); every other host must resolve to public addresses
    const cls = classifyHost(u.hostname);
    if (!cls) { const guard = await hostAllowed(u.hostname); if (!guard.ok) return { idp: 'blocked', hops, finalUrl: cur, detail: guard.why, mentions: [] }; }
    if (cls && !idpHit) idpHit = { hop: i, host: u.hostname, ...cls };
    let r;
    try { r = await fetch(cur, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(HOP_MS), headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml,*/*;q=0.8', 'accept-language': 'en' } }); }
    catch (e) { hops.push({ url: cur, status: null, location: null, error: String(e && (e.cause && e.cause.code || e.name || e.message) || e).slice(0, 120) }); return { idp: idpHit ? idpHit.idp : 'error', idpHit, hops, finalUrl: cur, detail: `could not fetch ${u.hostname}: ${hops[hops.length - 1].error}`, mentions: [] }; }
    const hop = { url: cur, status: r.status, location: null };
    if (REDIRECT.has(r.status)) {
      const loc = r.headers.get('location');
      try { await r.body?.cancel(); } catch (e) { /* ignore */ }
      if (!loc) { hops.push(hop); finalUrl = cur; break; }
      try { hop.location = new URL(loc, cur).href; } catch (e) { hop.location = loc; hops.push(hop); return { idp: idpHit ? idpHit.idp : 'error', idpHit, hops, finalUrl: cur, detail: 'redirect to an invalid location', mentions: [] }; }
      hops.push(hop); cur = hop.location; finalUrl = cur;
      if (i === MAX_HOPS - 1) return { idp: idpHit ? idpHit.idp : 'error', idpHit, hops, finalUrl, detail: `more than ${MAX_HOPS} redirects; stopped`, mentions: [] };
      continue;
    }
    // a final answer (2xx/4xx/5xx): look once for a meta refresh and for IdP hostnames in the page
    const html = r.status >= 200 && r.status < 500 ? await readHead(r) : '';
    hops.push(hop); finalUrl = cur;
    const refresh = html ? metaRefresh(html, cur) : null;
    if (refresh && i < MAX_HOPS - 1) { hop.location = refresh; hop.via = 'meta refresh'; cur = refresh; finalUrl = cur; continue; }
    mention = html ? mentions(html) : [];
    break;
  }
  const last = hops[hops.length - 1] || null;
  let idp, detail;
  const fh = (() => { try { return new URL(finalUrl).hostname; } catch (e) { return null; } })();
  const finalCls = classifyHost(fh);
  if (finalCls) { idp = finalCls.idp; detail = `lands on ${fh} (${finalCls.label})${hops.length > 1 ? ' after ' + (hops.length - 1) + ' redirect' + (hops.length > 2 ? 's' : '') : ''}`; }
  else if (idpHit) { idp = idpHit.idp; detail = `passes through ${idpHit.host} (${idpHit.label}) and ends on ${fh || '?'}`; }
  else if (last && last.status && last.status >= 500) { idp = 'error'; detail = `${fh || '?'} answered HTTP ${last.status}`; }
  else if (!last || last.status === null) { idp = 'error'; detail = 'no answer'; }
  else { idp = 'vendor'; detail = `lands on ${fh || '?'} (HTTP ${last.status}) — the vendor's own page; a sign-in from there may still go to either IdP` + (mention.length ? `. The page mentions ${mention.map((m) => IDP.find((k) => k.idp === m).label).join(' and ')} (weak hint, not evidence)` : ''); }
  return { idp, idpHit, hops, finalUrl, detail, mentions: mention };
}

/* ------------------------------------------------------------------ store */
async function probe(oktaId, url, actor) {
  const started = nowIso();
  const r = await follow(url);
  const row = { oktaId, url, finalUrl: r.finalUrl || null, idp: r.idp, hops: r.hops, detail: String(r.detail || '').slice(0, 500), mentions: r.mentions || [], checkedAt: started, checkedBy: actor || null };
  await pool.query(`INSERT INTO oem_link_probe (okta_id, url, final_url, idp, hops, detail, checked_at, checked_by) VALUES (?,?,?,?,?,?,?,?)
                    ON DUPLICATE KEY UPDATE url=VALUES(url), final_url=VALUES(final_url), idp=VALUES(idp), hops=VALUES(hops), detail=VALUES(detail), checked_at=VALUES(checked_at), checked_by=VALUES(checked_by)`,
    [oktaId, String(url).slice(0, 2048), row.finalUrl ? String(row.finalUrl).slice(0, 2048) : null, row.idp, JSON.stringify({ hops: row.hops, mentions: row.mentions }), row.detail, new Date(started), row.checkedBy]);
  return row;
}

function rowOut(r) {
  if (!r) return null;
  const h = j(r.hops, {}) || {};
  return { oktaId: r.okta_id, url: r.url, finalUrl: r.final_url, idp: r.idp, hops: Array.isArray(h) ? h : (h.hops || []), mentions: Array.isArray(h) ? [] : (h.mentions || []), detail: r.detail, checkedAt: r.checked_at, checkedBy: r.checked_by };
}
/** Map okta_id → probe for the given ids (or all when ids is null). */
async function loadProbes(ids = null) {
  const [rows] = ids && ids.length ? await pool.query(`SELECT * FROM oem_link_probe WHERE okta_id IN (?)`, [ids]) : ids ? [[]] : await pool.query(`SELECT * FROM oem_link_probe`);
  return new Map(rows.map((r) => [r.okta_id, rowOut(r)]));
}

module.exports = { probe, follow, loadProbes, classifyHost, hostAllowed, MAX_HOPS, HOP_MS };
