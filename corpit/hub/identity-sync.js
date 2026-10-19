'use strict';
/*
 * identity-sync.js — Entra (Graph) sync status for the identity-diag
 * "Force Replicate & Sync" modal, plus the server-side debounce guard for the
 * tenant-wide AAD Connect delta trigger.
 *
 * AD-layer status/replication and the AAD Connect trigger live in sync-actions.py
 * (WinRM). Okta-layer status is already present in the main /lookup response, so
 * the modal renders it client-side; there is no on-demand Okta import API.
 */

let _token = null, _tokenExp = 0;
async function getGraphToken() {
  if (_token && Date.now() < _tokenExp - 60_000) return _token;
  const url = `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: process.env.AZURE_CLIENT_ID,
    client_secret: process.env.AZURE_CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials',
  });
  const res = await fetch(url, { method: 'POST', body });
  const data = await res.json();
  if (!data.access_token) throw new Error('Graph token failed');
  _token = data.access_token;
  _tokenExp = Date.now() + (data.expires_in * 1000);
  return _token;
}

async function graphGet(path) {
  const token = await getGraphToken();
  const res = await fetch('https://graph.microsoft.com/v1.0' + path, {
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    const e = new Error('Graph ' + res.status);
    e.status = res.status; e.body = body.slice(0, 300);
    throw e;
  }
  return res.json();
}

/**
 * Per-user Entra sync state. `upn` should be the user's UPN or primary email.
 * Returns onPremises sync flags + last dirsync timestamp for that object, plus
 * the tenant's org-wide last dirsync time for context.
 */
async function entraUserStatus(upn) {
  const out = { configured: !!(process.env.AZURE_CLIENT_ID && process.env.AZURE_CLIENT_SECRET) };
  if (!out.configured) return { ...out, error: 'Graph not configured' };
  if (!upn) return { ...out, error: 'no UPN/email for this user' };
  try {
    const sel = 'id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesSamAccountName';
    const u = await graphGet('/users/' + encodeURIComponent(upn) + '?$select=' + encodeURIComponent(sel));
    out.found = true;
    out.userPrincipalName = u.userPrincipalName;
    out.accountEnabled = u.accountEnabled;
    out.onPremisesSyncEnabled = u.onPremisesSyncEnabled;
    out.onPremisesLastSyncDateTime = u.onPremisesLastSyncDateTime;
    out.onPremisesSamAccountName = u.onPremisesSamAccountName;
  } catch (e) {
    if (e.status === 404) { out.found = false; out.error = 'user not found in Entra'; }
    else out.error = e.message + (e.body ? ' — ' + e.body : '');
  }
  try {
    const org = await graphGet('/organization?$select=onPremisesSyncEnabled,onPremisesLastSyncDateTime');
    const o = (org.value || [])[0] || {};
    out.orgLastSync = o.onPremisesLastSyncDateTime;
    out.orgSyncEnabled = o.onPremisesSyncEnabled;
  } catch (e) { /* org context is best-effort */ }
  return out;
}

// ── Debounce for the tenant-wide AAD Connect delta trigger ──────────────────
// The cycle is global and already runs on a schedule; this stops a row of clicks
// from stacking Start-ADSyncSyncCycle calls (which would just error anyway).
const ENTRA_DELTA_MIN_INTERVAL_MS = 5 * 60 * 1000;
let _lastEntraDelta = 0;
function entraDeltaGate() {
  const since = Date.now() - _lastEntraDelta;
  if (_lastEntraDelta && since < ENTRA_DELTA_MIN_INTERVAL_MS) {
    return { allowed: false, waitSec: Math.ceil((ENTRA_DELTA_MIN_INTERVAL_MS - since) / 1000) };
  }
  return { allowed: true };
}
function markEntraDelta() { _lastEntraDelta = Date.now(); }

module.exports = { entraUserStatus, entraDeltaGate, markEntraDelta };
