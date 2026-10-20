'use strict';
const http = require('node:http');

// Fixed loopback destination only. Both the cookie and original Host are
// necessary for host-scoped sessions. Node fetch ignores a custom Host header;
// http.request preserves it. No redirects are followed and no credentials log.
function requestRapid7Xref(params, headers) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      hostname: '127.0.0.1', port: 3001, method: 'GET',
      path: `/api/rapid7/ip-xref?${params}`,
      headers: {
        Authorization: headers.authorization || '',
        Cookie: headers.cookie || '',
        Host: headers.host,
      },
      signal: AbortSignal.timeout(30000),
    }, response => {
      const chunks = [];
      let bytes = 0;
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 2 * 1024 * 1024) {
          request.destroy(new Error('Rapid7 response exceeds size limit'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolve({ ok: response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode, data });
        } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.end();
  });
}
module.exports = { requestRapid7Xref };
