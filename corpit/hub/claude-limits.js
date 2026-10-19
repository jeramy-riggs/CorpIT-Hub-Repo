/**
 * claude-limits.js — shared, pure helpers for the Spend Limits / Members data.
 * No DB, no HTTP: the collector and both route files require this so the parsing and
 * the "is this live?" decision exist in exactly one place.
 *
 * Facts this encodes (Spend Limits API + User management reference, read 2026-09-01):
 *  - Amounts are decimal STRINGS in minor units (cents). `amount` null = no limit for
 *    that period (unlimited); "0" = included usage only. Never parseFloat for storage.
 *  - One row per (member, period). Only `monthly` exists today; treat as an open set.
 *  - `source.type` is an OPEN set: user | seat_tier | rbac_group | organization |
 *    organization_service | <future>. Unknown values fall through, never throw.
 *  - `period_to_date_spend` reads "0" when the reading is temporarily unavailable.
 *  - The per-member "organization" default is NOT the org-wide monthly budget shown
 *    on the page (that is a billing setting with no API). Keep the two apart.
 */
'use strict';

const FRESH_HOURS = 36;   // a pull older than this is stale: the page falls back to CSV limits

/** Timestamp → epoch ms. A bare 'YYYY-MM-DD HH:MM:SS' (what MySQL hands back for a DATETIME,
 *  and what the collector writes) is UTC by contract here — Node would otherwise parse it
 *  as LOCAL time, so freshness would drift by the server's UTC offset. NaN when unparseable. */
function parseTs(v) {
  if (v == null || v === '') return NaN;
  if (v instanceof Date) return v.getTime();
  const str = String(v);
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(str)) return Date.parse(str.replace(' ', 'T') + 'Z');
  return Date.parse(str);
}

/** ISO 8601 → 'YYYY-MM-DD HH:MM:SS' (UTC) for MySQL DATETIME; null-safe. */
function toSql(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

/** Normalise one GET /spend_limits/effective row into the claude_spend_limit shape. */
function parseEffectiveRow(x, fetchedAt) {
  const a = x.actor || {}, src = x.source || {}, scope = x.scope || {};
  const sourceRef = src.seat_tier || src.rbac_group_id || src.service
    || (src.type === 'user' ? (src.user_id || null) : null) || null;
  return {
    user_id: scope.user_id || a.user_id || null,
    period: x.period || 'monthly',
    email: (a.email_address || '').toLowerCase() || null,
    display_name: a.name || null,
    deleted: a.deleted ? 1 : 0,
    amount_cents: x.amount == null ? null : String(x.amount),
    currency: x.currency || 'USD',
    source_type: src.type || '',
    source_ref: sourceRef,
    spend_limit_id: x.spend_limit_id || null,
    ptd_spend_cents: x.period_to_date_spend == null ? '0' : String(x.period_to_date_spend),
    fetched_at: fetchedAt,
  };
}

/** Normalise one GET /spend_limit_increase_requests row into the claude_limit_request shape. */
function parseRequestRow(r, fetchedAt) {
  const a = r.actor || {}, ss = r.spend_summary || null, rb = r.resolved_by || null;
  let resolvedBy = null;
  if (rb) resolvedBy = rb.type === 'scoped_api_key_actor'
    ? 'api-key:' + (rb.scoped_api_key_id || '')
    : ((rb.email_address || rb.name || rb.user_id || '') || null);
  return {
    id: r.id,
    user_id: a.user_id || null,
    email: (a.email_address || '').toLowerCase() || null,
    display_name: a.name || null,
    status: r.status || 'pending',
    period: r.period || 'monthly',
    created_at: toSql(r.created_at),
    resolved_at: toSql(r.resolved_at),
    resolved_by: resolvedBy,
    current_limit_cents: ss && ss.amount != null ? String(ss.amount) : null,
    current_source_type: ss && ss.source ? (ss.source.type || '') : null,
    ptd_spend_cents: ss && ss.period_to_date_spend != null ? String(ss.period_to_date_spend) : null,
    fetched_at: fetchedAt,
  };
}

/** Normalise one GET /organizations/users row into the claude_member shape. */
function parseMemberRow(u, fetchedAt) {
  return {
    user_id: u.id || null,
    email: (u.email || '').toLowerCase() || null,
    display_name: u.name || null,
    role: u.role || null,
    added_at: toSql(u.added_at),
    fetched_at: fetchedAt,
  };
}

/** Is a stored pull fresh enough to be presented as live? */
function isFresh(fetchedAt, now = Date.now(), hours = FRESH_HOURS) {
  if (!fetchedAt) return false;
  const t = parseTs(fetchedAt);
  if (isNaN(t)) return false;
  return (now - t) <= hours * 3600e3;
}

/** newest fetched_at across rows (Date or string), or null */
function newestFetchedAt(rows) {
  let best = null;
  for (const r of rows || []) {
    const t = r ? parseTs(r.fetched_at) : NaN;
    if (!isNaN(t) && (best == null || t > best)) best = t;
  }
  return best == null ? null : new Date(best).toISOString();
}

/** cents (string/number) → dollars rounded to cents; null stays null */
const cents = (v) => (v == null ? null : Math.round(Number(v)) / 100);

/**
 * Per-email limit view from claude_spend_limit rows (monthly period only).
 *  customLimit    = amount when the source is a per-user override
 *  groupLimit     = amount when inherited from an rbac_group or seat_tier
 *  effectiveLimit = amount whatever the source (null = unlimited)
 *  defaultLimit   = most common inherited (non-user) amount = the org's effective per-member default
 */
function buildLimitMaps(rows) {
  const byEmail = {}; const inherited = {}; let n = 0;
  for (const r of rows || []) {
    if ((r.period || 'monthly') !== 'monthly') continue;
    const amt = cents(r.amount_cents);
    const st = r.source_type || '';
    const rec = {
      userId: r.user_id || null,
      effectiveLimit: amt,
      unlimited: r.amount_cents == null,
      customLimit: st === 'user' ? amt : null,
      groupLimit: (st === 'rbac_group' || st === 'seat_tier') ? amt : null,
      sourceType: st,
      sourceRef: r.source_ref || null,
      ptdSpend: cents(r.ptd_spend_cents),
      // "0" is a real cap (included usage only) and the docs say to treat it as at-limit
      includedOnly: r.amount_cents != null && amt === 0,
      label: sourceLabel(st, r.amount_cents == null, r.amount_cents != null && amt === 0),
    };
    if (r.email) byEmail[r.email] = rec;
    if (st !== 'user' && amt != null) { const k = st + '|' + amt; inherited[k] = (inherited[k] || 0) + 1; }
    n++;
  }
  let defaultLimit = null, defaultSource = null, best = 0;
  for (const k of Object.keys(inherited)) {
    if (inherited[k] > best) { best = inherited[k]; const i = k.indexOf('|'); defaultSource = k.slice(0, i); defaultLimit = Number(k.slice(i + 1)); }
  }
  return { byEmail, defaultLimit, defaultSource, asOf: newestFetchedAt(rows), count: n };
}

/** Human label for a source type. Open set: unknown values render verbatim. */
function sourceLabel(st, unlimited, includedOnly) {
  if (includedOnly) return 'Included usage only';
  if (unlimited) return 'No limit';
  const known = { user: 'Custom limit', rbac_group: 'Group limit', seat_tier: 'Seat-tier default',
                  organization: 'Org default', organization_service: 'Service default' };
  return known[st] || (st ? String(st).replace(/_/g, ' ') : 'No limit');
}

module.exports = { FRESH_HOURS, parseTs, toSql, parseEffectiveRow, parseRequestRow, parseMemberRow,
                   isFresh, newestFetchedAt, cents, buildLimitMaps, sourceLabel };
