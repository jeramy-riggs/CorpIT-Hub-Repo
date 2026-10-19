/**
 * oem-net.js — IPv4 interval maths for zone/named-location parity.
 *
 * Comparing CIDR strings directly over-reports: the same address space written two ways
 * looks like a gap. Everything here reduces an address list to sorted numeric intervals
 * and asks a coverage question instead, which is the question that actually matters:
 * "is this address space trusted on the other side, by whatever route".
 */
'use strict';

function ipToInt(ip) {
  const p = String(ip).trim().split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) {
    const v = Number(o);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** Accepts "a.b.c.d", "a.b.c.d/nn" and Okta's "a.b.c.d-e.f.g.h" range form. */
function toInterval(entry) {
  const s = String(entry || '').trim();
  if (!s) return null;
  if (s.includes('/')) {
    const [ip, bitsRaw] = s.split('/');
    const start = ipToInt(ip);
    const bits = Number(bitsRaw);
    if (start === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
    const size = bits === 0 ? 4294967296 : Math.pow(2, 32 - bits);
    const masked = bits === 0 ? 0 : Math.floor(start / size) * size;
    return [masked, masked + size - 1];
  }
  if (s.includes('-')) {
    const [a, b] = s.split('-');
    const lo = ipToInt(a); const hi = ipToInt(b);
    if (lo === null || hi === null || hi < lo) return null;
    return [lo, hi];
  }
  const one = ipToInt(s);
  return one === null ? null : [one, one];
}

/** Merge overlapping/adjacent intervals so coverage tests are cheap and exact. */
function normalize(entries) {
  const iv = (entries || []).map(toInterval).filter(Boolean).sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const [lo, hi] of iv) {
    const last = out[out.length - 1];
    if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else out.push([lo, hi]);
  }
  return out;
}

/** Portions of `subject` not covered by `cover`. Empty array means fully covered. */
function uncovered(subject, cover) {
  const gaps = [];
  for (let [lo, hi] of subject) {
    let cur = lo;
    for (const [clo, chi] of cover) {
      if (chi < cur) continue;
      if (clo > hi) break;
      if (clo > cur) gaps.push([cur, Math.min(hi, clo - 1)]);
      cur = Math.max(cur, chi + 1);
      if (cur > hi) break;
    }
    if (cur <= hi) gaps.push([cur, hi]);
  }
  return gaps;
}

function contains(intervals, ip) {
  const n = ipToInt(ip);
  if (n === null) return false;
  return intervals.some(([lo, hi]) => n >= lo && n <= hi);
}

/** Render an interval as the shortest list of CIDRs that exactly covers it. */
function toCidrs([lo, hi]) {
  const out = [];
  let cur = lo;
  while (cur <= hi) {
    let bits = 32;
    while (bits > 0) {
      const size = Math.pow(2, 32 - (bits - 1));
      if (cur % size !== 0 || cur + size - 1 > hi) break;
      bits--;
    }
    const size = Math.pow(2, 32 - bits);
    out.push(intToIp(cur) + (bits === 32 ? '/32' : '/' + bits));
    cur += size;
    if (out.length > 512) break;
  }
  return out;
}

function count(intervals) {
  return intervals.reduce((n, [lo, hi]) => n + (hi - lo + 1), 0);
}

module.exports = { ipToInt, intToIp, toInterval, normalize, uncovered, contains, toCidrs, count };
