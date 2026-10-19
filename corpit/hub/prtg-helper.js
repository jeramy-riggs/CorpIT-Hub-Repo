'use strict';
// prtg-helper.js — lightweight PRTG HTTP Push helper for api-beta
// Ported from cert-watchtower-prtg-helper.js. No DB, no .env, no logging.
// Caller owns retry/backoff and result handling.

const VERSION = '1.0.0';

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Build a PRTG XML payload.
 * @param {Array<{channel:string, value:number, unit?:string, customUnit?:string, float?:boolean}>} channels
 * @param {string} statusText
 * @returns {string}
 */
function buildPrtgXml(channels, statusText) {
  const results = channels.map(c => {
    let block = `<result><channel>${escapeXml(c.channel)}</channel><value>${c.value}</value>`;
    if (c.customUnit) block += `<customunit>${escapeXml(c.customUnit)}</customunit>`;
    else if (c.unit)  block += `<unit>${escapeXml(c.unit)}</unit>`;
    if (c.float)      block += `<float>1</float>`;
    block += `</result>`;
    return block;
  }).join('\n  ');

  return `<?xml version="1.0" encoding="UTF-8"?>\n<prtg>\n  ${results}\n  <text>${escapeXml(statusText)}</text>\n</prtg>`;
}

/**
 * Parse PRTG's JSON response body.
 * @param {string} rawBody
 * @returns {{ status: string, matchingSensors: number, raw: string }}
 */
function parsePrtgResponse(rawBody) {
  try {
    const obj = JSON.parse(rawBody);
    return {
      status:          obj.status || 'Unknown',
      matchingSensors: parseInt(obj['Matching Sensors'] ?? obj.matchingSensors ?? -1, 10),
      raw:             rawBody,
    };
  } catch {
    return { status: 'ParseError', matchingSensors: -1, raw: rawBody };
  }
}

/**
 * Push a payload to PRTG.
 * @param {{host:string, port:number, token:string, protocol?:string, verifySsl?:boolean, timeoutMs?:number}} cfg
 * @param {Array} channels
 * @param {string} statusText
 * @returns {Promise<{ok:boolean, status:string, matchingSensors:number, raw:string, error?:string}>}
 */
async function pushToPrtg(cfg, channels, statusText) {
  const protocol = cfg.protocol || 'http';
  const url      = `${protocol}://${cfg.host}:${cfg.port}/${cfg.token}`;
  const xml      = buildPrtgXml(channels, statusText);
  const timeout  = cfg.timeoutMs || 5000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'text/xml' },
      body:    xml,
      signal:  controller.signal,
    });
    clearTimeout(timer);

    const rawBody = await res.text();
    const parsed  = parsePrtgResponse(rawBody);

    if (parsed.matchingSensors === 0) {
      return { ok: false, status: 'mismatch', ...parsed };
    }
    return { ok: parsed.status === 'Ok', status: parsed.status === 'Ok' ? 'ok' : 'error', ...parsed };

  } catch (err) {
    clearTimeout(timer);
    const isTimeout = err.name === 'AbortError';
    return { ok: false, status: isTimeout ? 'timeout' : 'error', matchingSensors: -1, raw: '', error: err.message };
  }
}

module.exports = { pushToPrtg, buildPrtgXml, parsePrtgResponse, VERSION };
