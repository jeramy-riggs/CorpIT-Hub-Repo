'use strict';
/* ════════════════════════════════════════════════════════════════════
   fortigate-tls.js — one verifying https.Agent for every FortiGate REST
   call (netdiag.js, fortinet-lookup.js, fortinet-routes.js).  F13/F14.

   The FGTs are reached by IP (Irvine 10.20.6.4, Dallas 10.19.6.4). Both
   mgmt certs are CN=nrpi.local issued by NRPI-PKI04AWSW2US-CA:
     Irvine  SAN = IP:10.20.6.4, DNS:sna01-fw01.nrpi.local (no nrpi.local)
     Dallas  no SAN extension
   Node's default identity check never falls back to CN once a SAN exists,
   so the name check here passes when FORTIGATE_TLS_NAME (default
   'nrpi.local') matches a SAN DNS entry (Node's rules) OR equals the
   subject CN exactly. Chain must still validate against the NRPI CA.

   CA: /var/www/corpit-hub-api/certs/nrpi-ca-chain.pem (FORTIGATE_CA_FILE
   overrides). Fail closed: if it cannot be read every request through
   this agent errors — there is no fallback to unverified TLS.

   Optional pin: FORTIGATE_CERT_SHA256 = comma list of SHA-256 cert
   fingerprints (colon-hex or plain hex, any case). When set, the peer
   cert must be in the list; unset = CA + name only. Values as of
   2026-10-21 (re-pin on renewal):
     Irvine 4E:00:77:E9:7C:EE:97:9E:CF:E2:83:CD:F3:DA:89:5F:32:AA:07:FA:50:C4:27:35:CC:1D:34:06:AC:75:5A:58  (to 2027-09-16)
     Dallas 47:8C:B2:E6:C4:68:33:01:8D:D5:E0:C5:17:E1:21:39:BD:18:B5:3A:CF:08:14:6C:8B:84:E2:6A:FC:8C:1E:7B  (to 2028-04-12)
   ════════════════════════════════════════════════════════════════════ */

const fs = require('fs');
const https = require('https');
const tls = require('tls');

const CA_FILE = process.env.FORTIGATE_CA_FILE || '/var/www/corpit-hub-api/certs/nrpi-ca-chain.pem';

function normFp(s) { return String(s || '').replace(/[^0-9a-f]/gi, '').toUpperCase(); }

function checkFortigateIdentity(host, cert) {
  const name = String(process.env.FORTIGATE_TLS_NAME || 'nrpi.local').trim().toLowerCase();
  const cn = cert && cert.subject && typeof cert.subject.CN === 'string' ? cert.subject.CN.toLowerCase() : '';
  if (tls.checkServerIdentity(name, cert) !== undefined && cn !== name) {
    const e = new Error(`FortiGate cert for ${host} does not match expected name "${name}" (CN=${cn || '-'})`);
    e.code = 'ERR_FORTIGATE_TLS_NAME';
    return e;
  }
  const pins = String(process.env.FORTIGATE_CERT_SHA256 || '').split(',').map(normFp).filter(Boolean);
  if (pins.length && !pins.includes(normFp(cert && cert.fingerprint256))) {
    const e = new Error(`FortiGate cert for ${host} fingerprint ${cert && cert.fingerprint256} is not in FORTIGATE_CERT_SHA256`);
    e.code = 'ERR_FORTIGATE_TLS_PIN';
    return e;
  }
  return undefined;
}

let agent;
try {
  const ca = fs.readFileSync(CA_FILE);
  agent = new https.Agent({
    keepAlive: true,
    ca,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    checkServerIdentity: checkFortigateIdentity,
  });
} catch (err) {
  const msg = `FortiGate TLS CA unreadable (${CA_FILE}): ${err.message} — FortiGate calls disabled`;
  console.error('[fortigate-tls] ' + msg);
  agent = new https.Agent({ keepAlive: false });
  agent.createConnection = function (options, cb) {
    const e = new Error(msg);
    e.code = 'ERR_FORTIGATE_TLS_CA';
    process.nextTick(() => cb(e));
  };
}

module.exports = { agent, checkFortigateIdentity, CA_FILE };
