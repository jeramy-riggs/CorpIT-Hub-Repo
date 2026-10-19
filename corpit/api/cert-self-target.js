'use strict';
// Keep owner-local certificate inspection off the client-IP-preserving NLB.
// SNI remains the caller's original hostname in cert-watchtower-routes.js.
const os = require('node:os');
const nodes = new Set(['ip-10-9-58-207', 'ip-10-9-59-25']);
const names = new Set(['corpit', 'subadmin', 'accessportal', 'directory', 'myprofile', 'reporting', 'itam'].map(x => x + '.nrpi.local'));
module.exports = function certificateConnectHost(hostname, port, node = os.hostname()) {
  const normalized = String(hostname).toLowerCase().replace(/\.$/, '');
  return nodes.has(node) && Number(port) === 443 && names.has(normalized) ? '127.0.0.1' : hostname;
};
