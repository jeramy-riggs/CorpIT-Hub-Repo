'use strict';
// =====================================================================
// mail-graph.js  (v1.0.0)
//
// The single Microsoft Graph mail path for CorpIT Hub.
//
// WHY THIS MODULE EXISTS
// ----------------------
// Every Graph sender ported from ITAM addressed the service mailbox by its
// `mail` attribute:
//
//     POST /v1.0/users/itcommand@auction.com/sendMail
//
// Graph resolves /users/{...} by userPrincipalName or object id ONLY -- it
// does not look at the `mail` attribute. The CorpIT mailbox has
//
//     mail = itcommand@auction.com
//     upn  = itcommand@auctiondotcom.onmicrosoft.com
//     id   = 4c91ab01-6554-4d7a-9228-a09e6c809216
//
// so that call returned 404 Request_ResourceNotFound and NO Graph mail was
// ever delivered from this host -- including break-glass security alerts.
// (ITAM's one working sender, portal-mail-relay.js, uses the UPN. Its other
// three senders carry the same bug. Fixed here, in CorpIT only; ITAM is
// read-only.)
//
// The address recipients SEE is unchanged: itcommand@auction.com is still the
// From: header. Only the path identifier is corrected.
//
// This module never reports success it did not get: Graph answers sendMail
// with 202 Accepted, and anything else is returned as a failure with a
// reason, so a caller cannot stamp "notified" on a send that did not happen.
// =====================================================================

const TENANT = () => process.env.AZURE_TENANT_ID;
const CLIENT = () => process.env.AZURE_CLIENT_ID;
const SECRET = () => process.env.AZURE_CLIENT_SECRET;

// What recipients see.
const FROM_ADDRESS = () => process.env.CORPIT_MAIL_FROM      || 'itcommand@auction.com';
const FROM_NAME    = () => process.env.CORPIT_MAIL_FROM_NAME || 'CorpIT';
// What Graph accepts in the URL path. MUST be a UPN or an object id.
const MAILBOX_ID   = () => process.env.CORPIT_MAIL_MAILBOX   || 'itcommand@auctiondotcom.onmicrosoft.com';

function configured() { return !!(TENANT() && CLIENT() && SECRET() && typeof fetch === 'function'); }

// ── token ────────────────────────────────────────────────────────────
let _tok = { exp: 0, v: null };
async function token() {
  if (_tok.v && Date.now() < _tok.exp) return _tok.v;
  if (!configured()) return null;
  try {
    const r = await fetch(`https://login.microsoftonline.com/${TENANT()}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT(), client_secret: SECRET(),
        scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials',
      }),
    });
    const j = await r.json();
    if (!j.access_token) return null;
    const ttl = Math.max(60, Number(j.expires_in || 3600) - 60);
    _tok = { exp: Date.now() + ttl * 1000, v: j.access_token };
    return _tok.v;
  } catch (e) { return null; }
}

// ── sender mailbox ───────────────────────────────────────────────────
let _box = { exp: 0, v: null };
function cacheBox(id) { _box = { exp: Date.now() + 3600e3, v: id }; return id; }

// Resolve the mailbox to an object id Graph will accept in /users/{id}.
// Two steps, so a UPN change cannot silently stop delivery the way the
// mail-attribute bug did:
//   1. the configured identifier (a UPN or an object id)
//   2. a directory lookup by the `mail` attribute
// Returns null when it cannot be resolved -- never a guess.
async function senderMailbox(tok, mailboxOverride) {
  const over = mailboxOverride != null && String(mailboxOverride).trim() !== '';
  if (!over && _box.v && Date.now() < _box.exp) return _box.v;
  const t = tok || await token();
  if (!t) return null;
  const H = { Authorization: 'Bearer ' + t };
  try {
    const want = over ? String(mailboxOverride).trim() : MAILBOX_ID();
    let r = await fetch(
      `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(want)}?$select=id`, { headers: H });
    if (r.ok) { const d = await r.json(); if (d && d.id) return over ? d.id : cacheBox(d.id); }
    // Mail-attribute fallback only applies to the default sender; an overridden
    // mailbox is passed as a UPN and resolves directly above.
    if (!over) {
      const addr = String(FROM_ADDRESS()).replace(/'/g, "''");   // OData quote escape
      r = await fetch('https://graph.microsoft.com/v1.0/users?$select=id&$top=1&$filter=' +
        encodeURIComponent(`mail eq '${addr}'`), { headers: H });
      if (r.ok) {
        const d = await r.json();
        if (d && Array.isArray(d.value) && d.value[0] && d.value[0].id) {
          console.warn('[mail-graph] %s did not resolve; fell back to a mail-attribute lookup', want);
          return cacheBox(d.value[0].id);
        }
      }
    }
  } catch (e) { console.error('[mail-graph] senderMailbox:', e.message); }
  return null;
}

// ── send ─────────────────────────────────────────────────────────────
// Resolves to { ok:true, status:202 } or { ok:false, reason, status? }.
// Never throws, never rejects -- callers that need an exception raise their
// own from the returned reason, so each keeps its own error semantics.
async function sendMail({ to, subject, html, text, saveToSentItems = false, from, fromName, mailbox }) {
  if (!configured()) return { ok: false, reason: 'not-configured' };
  const list = (Array.isArray(to) ? to : [to]).map(a => String(a || '').trim()).filter(Boolean);
  if (!list.length) return { ok: false, reason: 'no-recipient' };
  const t = await token();
  if (!t) return { ok: false, reason: 'no-token' };
  const box = await senderMailbox(t, mailbox);
  if (!box) return { ok: false, reason: 'sender-unresolved' };
  try {
    const r = await fetch(
      `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(box)}/sendMail`,
      { method: 'POST',
        headers: { Authorization: 'Bearer ' + t, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: {
            subject: String(subject == null ? '' : subject),
            body: html ? { contentType: 'HTML', content: html }
                       : { contentType: 'Text', content: String(text == null ? '' : text) },
            from: { emailAddress: { address: (from || FROM_ADDRESS()), name: (fromName || FROM_NAME()) } },
            toRecipients: list.map(a => ({ emailAddress: { address: a } })),
          },
          saveToSentItems: !!saveToSentItems,
        }) });
    // Graph answers 202 Accepted. Anything else is a failure.
    if (r.status === 202) return { ok: true, status: 202 };
    let detail = '';
    try { detail = (await r.text()).slice(0, 300); } catch (e) {}
    console.error('[mail-graph] sendMail HTTP %s %s', r.status, detail);
    return { ok: false, reason: 'http', status: r.status, detail };
  } catch (e) {
    console.error('[mail-graph] sendMail:', e.message);
    return { ok: false, reason: 'exception', detail: e.message };
  }
}

module.exports = { configured, token, senderMailbox, sendMail, fromAddress: FROM_ADDRESS };
