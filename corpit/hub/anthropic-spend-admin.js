'use strict';
// =====================================================================
// anthropic-spend-admin.js  (2026-09-25)
//
// The one place CorpIT Hub WRITES to the Anthropic Spend Limits API. The
// collector only reads; this module sets a person's monthly cap when a
// My Profile limit approval completes, and puts it back when the monthly
// reset runs.
//
// Facts this encodes (Spend Limits API reference, read 2026-09-25):
//   - Amounts are decimal STRINGS in minor units (cents). amount null = no cap.
//   - POST /v1/organizations/spend_limits is an upsert keyed on scope+period.
//   - DELETE /v1/organizations/spend_limits/{id} removes a per-user override;
//     the person falls back to whatever they inherit (seat tier, group, org).
//   - Setting a limit directly does NOT resolve a pending claude.ai increase
//     request. When one is pending, approving it writes the same override AND
//     resolves it, so the person is not left with a stale "pending" in Claude.
//   - Writes need write:spend_limits. The key the Hub already reads spend with
//     (ANTHROPIC_ANALYTICS_KEY in .env) was created with read AND write, so no
//     second key is needed (checked 2026-09-25: DELETE of an unknown id answers
//     404, not 403). ANTHROPIC_ADMIN_KEY, if it is ever set, is used first.
//   - 60 requests/minute per organisation, shared with the hourly collector.
//
// Nothing here throws on an HTTP answer: every call resolves to
// { ok, status, data, error }, so a caller cannot mistake a refusal for a write.
// The key is never logged, returned or put in an error message.
// =====================================================================

const API = 'https://api.anthropic.com';
const VERSION = '2023-06-01';
const TIMEOUT_MS = 20000;

function key() { return process.env.ANTHROPIC_ADMIN_KEY || process.env.ANTHROPIC_ANALYTICS_KEY || ''; }
function adminKeyInstalled() { return !!process.env.ANTHROPIC_ADMIN_KEY; }

async function call(method, path, body) {
  const k = key();
  if (!k) return { ok: false, status: 0, data: null, error: 'No Anthropic Admin API key is configured on this host.' };
  if (typeof fetch !== 'function') return { ok: false, status: 0, data: null, error: 'fetch is not available in this Node runtime.' };
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const init = { method, signal: ctl.signal, headers: { 'x-api-key': k, 'anthropic-version': VERSION, 'user-agent': 'corpit-hub-limit-approvals/1.0' } };
    if (body !== undefined) { init.headers['content-type'] = 'application/json'; init.body = JSON.stringify(body); }
    const r = await fetch(API + path, init);
    const text = await r.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
    if (r.ok) return { ok: true, status: r.status, data, error: null };
    return { ok: false, status: r.status, data, error: describe(r.status, data, text) };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: e.name === 'AbortError' ? 'Anthropic did not answer within 20 s.' : ('Could not reach Anthropic: ' + e.message) };
  } finally { clearTimeout(t); }
}

function describe(status, data, text) {
  const msg = data && data.error && (data.error.message || data.error.type);
  if (status === 401) return 'Anthropic rejected the API key (401).';
  if (status === 403) {
    return 'The Anthropic key on this host is not allowed to change spend limits (403'
      + (msg ? ': ' + String(msg).slice(0, 160) : '') + '). Check that the key still has write access to spend limits.';
  }
  if (status === 404) return 'Anthropic answered 404' + (msg ? ': ' + String(msg).slice(0, 160) : '') + '.';
  if (status === 429) return 'Anthropic rate-limited the call (429). Try again in a minute.';
  return 'Anthropic answered HTTP ' + status + (msg ? ': ' + String(msg).slice(0, 200) : (text ? ': ' + String(text).slice(0, 120) : '')) + '.';
}

/** cents as a Number, or null for "no cap". Accepts the API's decimal strings. */
function centsOf(v) { if (v == null || v === '') return null; const n = Number(v); return Number.isFinite(n) ? Math.round(n) : null; }

/** The person's effective monthly limit, live. { ok, row:{amountCents, sourceType, spendLimitId, ptdCents}|null } */
async function effective(userId) {
  const r = await call('GET', '/v1/organizations/spend_limits/effective?limit=10&user_ids%5B%5D=' + encodeURIComponent(userId));
  if (!r.ok) return r;
  const rows = (r.data && Array.isArray(r.data.data)) ? r.data.data : [];
  const mine = rows.find((x) => {
    const sc = x.scope || {}, a = x.actor || {};
    return (sc.user_id || a.user_id) === userId && (x.period || 'monthly') === 'monthly';
  }) || null;
  if (!mine) return { ok: true, status: r.status, row: null };
  return {
    ok: true, status: r.status,
    row: {
      amountCents: centsOf(mine.amount),
      unlimited: mine.amount == null,
      sourceType: (mine.source && mine.source.type) || '',
      spendLimitId: mine.spend_limit_id || null,
      ptdCents: centsOf(mine.period_to_date_spend) || 0,
    },
  };
}

/** Pending claude.ai increase requests from this person, newest first. */
async function pendingRequests(userId) {
  const r = await call('GET', '/v1/organizations/spend_limit_increase_requests?limit=20&status%5B%5D=pending&actor_ids%5B%5D=' + encodeURIComponent(userId));
  if (!r.ok) return r;
  const rows = (r.data && Array.isArray(r.data.data)) ? r.data.data : [];
  const mine = rows.filter((x) => x && x.status === 'pending' && ((x.actor && x.actor.user_id) === userId));
  mine.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
  return { ok: true, status: r.status, rows: mine };
}

/** Upsert a per-user monthly override. */
function setUserLimit(userId, cents) {
  return call('POST', '/v1/organizations/spend_limits',
    { scope: { type: 'user', user_id: userId }, amount: String(Math.round(cents)), period: 'monthly' });
}

/** Approve a pending increase request at this amount. We send our own email, so Anthropic's is suppressed. */
function approveRequest(requestId, cents) {
  return call('POST', '/v1/organizations/spend_limit_increase_requests/' + encodeURIComponent(requestId) + '/approve',
    { amount: String(Math.round(cents)), suppress_notification: true });
}

/** Remove a per-user override; the person falls back to what they inherit. */
function deleteLimit(spendLimitId) {
  return call('DELETE', '/v1/organizations/spend_limits/' + encodeURIComponent(spendLimitId));
}

module.exports = { adminKeyInstalled, effective, pendingRequests, setUserLimit, approveRequest, deleteLimit, centsOf, _call: call };
