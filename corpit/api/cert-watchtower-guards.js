// =============================================================================
// Cert Watchtower — shared guards (hotfix-bundle3 2026-10-21, F6/F19/F20/F21/F32)
// File: /var/www/api/cert-watchtower-guards.js
//
// One place for the checks that more than one Cert Watchtower file must agree
// on, so they cannot drift apart:
//   - CORPIT_SECRET_CONFIG_KEYS / corpitRedactConfig: cert_config rows that
//     hold a live credential (used by cert-watchtower-routes.js and
//     cert-watchtower-prtg-routes.js).
//   - WinRM scan-target policy: which hosts, transports and cert-store lists
//     the server will send the shared WinRM service credential to (used by
//     cert-watchtower-agent-routes.js and cert-watchtower-winrm-scan.js).
//     The Python helpers repeat the same checks (defense in depth).
//
// No dependencies.
// =============================================================================

// === CORPIT-SECRET-CONFIG (2026-09-06, shared 2026-10-21) ====================
// Config rows that hold a live credential. These must never reach a browser:
// each has an admin-gated path of its own for the rare case an operator needs
// the value. Callers get "<key>_set" instead so the UI can still render state.
// prtg_auth_token / prtg_push_url are legacy Phase 2 rows that may still hold
// a value; prtg_summary_sensor_token is the live PRTG push key.
const CORPIT_SECRET_CONFIG_KEYS = [
  'agent_enrollment_token',
  'prtg_summary_sensor_token',
  'prtg_auth_token',
  'prtg_push_url'
];

function corpitRedactConfig(config) {
  const out = Object.assign({}, config || {});
  for (const k of CORPIT_SECRET_CONFIG_KEYS) {
    if (Object.prototype.hasOwnProperty.call(out, k)) {
      out[k + '_set'] = !!(out[k] !== null && out[k] !== undefined && String(out[k]) !== '');
      delete out[k];
    }
  }
  return out;
}
// === end CORPIT-SECRET-CONFIG ================================================

// === WinRM scan-target policy ================================================
// 'basic' is refused: it sends the domain service credential as a reusable
// header (cleartext over http). ntlm/kerberos/credssp over http stay allowed
// because WinRM encrypts the message payload for them.
const WINRM_TRANSPORTS = ['ntlm', 'kerberos', 'credssp'];

// Domain-joined names (*.nrpi.local) or 10.0.0.0/8 only.
const WINRM_HOST_NAME_RE = /^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+nrpi\.local$/i;
const WINRM_HOST_IPV4_RE = /^10\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// Comma-separated LocalMachine\<Store> / CurrentUser\<Store> list.
const SCAN_STORE_ITEM = '(?:LocalMachine|CurrentUser)\\\\[A-Za-z0-9 _-]+';
const SCAN_STORES_RE = new RegExp(`^\\s*${SCAN_STORE_ITEM}\\s*(?:,\\s*${SCAN_STORE_ITEM}\\s*)*$`, 'i');

function isAllowedWinrmHost(s) {
  if (typeof s !== 'string') return false;
  const t = s.trim();
  if (t.length === 0 || t.length > 255) return false;
  if (WINRM_HOST_NAME_RE.test(t)) return true;
  const m = WINRM_HOST_IPV4_RE.exec(t);
  return !!m && m.slice(1).every(o => Number(o) <= 255);
}

function isAllowedWinrmTransport(v) {
  return WINRM_TRANSPORTS.includes(v);
}

function isValidScanStores(v) {
  return typeof v === 'string' && v.length <= 512 && SCAN_STORES_RE.test(v);
}

// Check a cert_agents row (or the same shape) before any credential is sent.
// Returns null when allowed, otherwise a short reason string.
function winrmTargetRefusal(target) {
  const host = (target && (target.target_host || target.fqdn)) || '';
  if (!isAllowedWinrmHost(host)) return 'target host must be *.nrpi.local or a 10.x address';
  const transport = (target && target.winrm_transport) || 'ntlm';
  if (!isAllowedWinrmTransport(transport)) return `winrm_transport '${transport}' is not allowed`;
  if (target && target.scan_stores && !isValidScanStores(target.scan_stores)) return 'scan_stores invalid';
  return null;
}
// === end WinRM scan-target policy ============================================

module.exports = {
  CORPIT_SECRET_CONFIG_KEYS,
  corpitRedactConfig,
  WINRM_TRANSPORTS,
  isAllowedWinrmHost,
  isAllowedWinrmTransport,
  isValidScanStores,
  winrmTargetRefusal
};
