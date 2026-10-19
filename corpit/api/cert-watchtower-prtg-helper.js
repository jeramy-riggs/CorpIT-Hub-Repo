/**
 * cert-watchtower-prtg-helper.js
 *
 * Standalone helper for pushing data to PRTG HTTP Push Data Advanced sensors.
 *
 * Design contract:
 *   - No DB reads or writes
 *   - No filesystem reads (no .env loading)
 *   - No retry / backoff (caller's responsibility)
 *   - No logging to /var/log/ (returns structured result; caller decides what to log)
 *   - No PRTG sensor creation (manual create model — option A1)
 *
 * Exports:
 *   pushToPrtg(opts) -> Promise<Result>
 *   buildPrtgXml(channels, statusText) -> string         (exported for tests)
 *   parsePrtgResponse(rawBody) -> ParsedResponse         (exported for tests)
 *
 * CLI:
 *   node cert-watchtower-prtg-helper.js test-push --host=H --port=P --token=T \
 *        --value=42 [--channel=Name] [--text="status text"] [--protocol=http|https] \
 *        [--insecure] [--timeout=5000]
 */

'use strict';

const PROTOCOLS = new Set(['http', 'https']);
const VERSION = '0.1.0';

/* -------------------------------------------------------------------------- */
/*  XML escaping                                                              */
/* -------------------------------------------------------------------------- */

function xmlEscape(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/* -------------------------------------------------------------------------- */
/*  Input validation                                                          */
/* -------------------------------------------------------------------------- */

function validateChannel(ch, idx) {
  if (!ch || typeof ch !== 'object') {
    throw new Error(`channels[${idx}]: must be an object`);
  }
  if (typeof ch.name !== 'string' || ch.name.trim() === '') {
    throw new Error(`channels[${idx}]: 'name' must be a non-empty string`);
  }
  if (ch.name.length > 200) {
    throw new Error(`channels[${idx}]: 'name' too long (>200 chars)`);
  }
  if (!Number.isFinite(Number(ch.value))) {
    throw new Error(`channels[${idx}] '${ch.name}': 'value' must be a finite number, got ${typeof ch.value}`);
  }
}

function validateOpts(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new Error('pushToPrtg: opts object required');
  }
  const { host, port, protocol = 'http', token, channels, timeoutMs = 5000 } = opts;

  if (typeof host !== 'string' || host.trim() === '') {
    throw new Error('pushToPrtg: host required (non-empty string)');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`pushToPrtg: port must be integer 1-65535, got ${port}`);
  }
  if (!PROTOCOLS.has(protocol)) {
    throw new Error(`pushToPrtg: protocol must be 'http' or 'https', got '${protocol}'`);
  }
  if (typeof token !== 'string' || token.trim() === '') {
    throw new Error('pushToPrtg: token required (non-empty string)');
  }
  // PRTG identtokens are GUIDs by default; allow flexibility but reject obvious junk
  if (token.length > 256 || /[\s\/?#]/.test(token)) {
    throw new Error('pushToPrtg: token contains invalid characters or is too long');
  }
  if (!Array.isArray(channels) || channels.length === 0) {
    throw new Error('pushToPrtg: channels must be a non-empty array');
  }
  if (channels.length > 50) {
    throw new Error(`pushToPrtg: too many channels (${channels.length}); PRTG limit is around 50`);
  }
  channels.forEach(validateChannel);

  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) {
    throw new Error(`pushToPrtg: timeoutMs must be integer 100-60000, got ${timeoutMs}`);
  }
}

/* -------------------------------------------------------------------------- */
/*  XML payload builder                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Build the PRTG XML payload from a channels array.
 *
 * channels: [
 *   { name: "Days Until Expiry", value: 30 },
 *   { name: "Cert Status", value: 1 },
 *   { name: "Handshake Time", value: 142 }
 * ]
 *
 * Optional per-channel fields (passed through verbatim if PRTG-recognised):
 *   - unit         : "Custom" | "TimeResponse" | "BytesBandwidth" | etc.
 *   - customUnit   : string (only used when unit==="Custom")
 *   - float        : 0 | 1   (1 if value is a float)
 *   - decimalMode  : "Auto" | "All" | "Custom"
 *   - mode         : "Absolute" | "Difference"
 *   - showChart    : 0 | 1
 *   - showTable    : 0 | 1
 *
 * NOTE: thresholds (warning/error limits) are intentionally NOT pushed inline.
 * Per the agreed design (Q1), thresholds live in the PRTG sensor template so
 * NOC sees them in the PRTG UI without code-side drift.
 */
function buildPrtgXml(channels, statusText) {
  const parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<prtg>'];

  for (const ch of channels) {
    parts.push('<result>');
    parts.push(`<channel>${xmlEscape(ch.name)}</channel>`);
    parts.push(`<value>${xmlEscape(ch.value)}</value>`);

    if (ch.unit) {
      parts.push(`<unit>${xmlEscape(ch.unit)}</unit>`);
      if (ch.unit === 'Custom' && ch.customUnit) {
        parts.push(`<customunit>${xmlEscape(ch.customUnit)}</customunit>`);
      }
    }
    if (ch.float === 0 || ch.float === 1) {
      parts.push(`<float>${ch.float}</float>`);
    }
    if (ch.decimalMode) {
      parts.push(`<decimalmode>${xmlEscape(ch.decimalMode)}</decimalmode>`);
    }
    if (ch.mode) {
      parts.push(`<mode>${xmlEscape(ch.mode)}</mode>`);
    }
    if (ch.showChart === 0 || ch.showChart === 1) {
      parts.push(`<showchart>${ch.showChart}</showchart>`);
    }
    if (ch.showTable === 0 || ch.showTable === 1) {
      parts.push(`<showtable>${ch.showTable}</showtable>`);
    }

    parts.push('</result>');
  }

  if (statusText !== undefined && statusText !== null && String(statusText).trim() !== '') {
    // PRTG only honours <text> at the top level; truncate to PRTG's ~2000 char limit
    const trimmed = String(statusText).slice(0, 2000);
    parts.push(`<text>${xmlEscape(trimmed)}</text>`);
  }

  parts.push('</prtg>');
  return parts.join('');
}

/* -------------------------------------------------------------------------- */
/*  Response parsing                                                          */
/* -------------------------------------------------------------------------- */

/**
 * PRTG's HTTP Push Data Advanced returns JSON like:
 *   {"status":"Ok","Matching Sensors":"1"}
 *   {"status":"Ok","Matching Sensors":"0"}   (token doesn't match anything)
 *
 * On older PRTG versions or error cases, the body may be plain text or HTML.
 * Parse defensively.
 */
function parsePrtgResponse(rawBody) {
  const out = { status: null, matchingSensors: null, parseError: null };
  if (!rawBody || typeof rawBody !== 'string') return out;

  const trimmed = rawBody.trim();
  if (trimmed === '') return out;

  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed === 'object') {
      out.status = parsed.status || null;
      // PRTG uses the literal key "Matching Sensors" with a space
      const ms = parsed['Matching Sensors'];
      if (ms !== undefined && ms !== null) {
        const n = parseInt(ms, 10);
        out.matchingSensors = Number.isFinite(n) ? n : null;
      }
    }
  } catch (err) {
    out.parseError = err.message;
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/*  Main: push                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Push channels to a PRTG HTTP Push Data Advanced sensor.
 *
 * @param {Object}   opts
 * @param {string}   opts.host         — PRTG probe push hostname (e.g. "prtg01awsw2us.nrpi.local")
 * @param {number}   opts.port         — PRTG probe push port (e.g. 5050)
 * @param {string}   opts.protocol     — "http" or "https" (default "http")
 * @param {string}   opts.token        — PRTG sensor identtoken (GUID)
 * @param {Array}    opts.channels     — array of { name, value, ...optional }
 * @param {string=}  opts.statusText   — optional PRTG sensor status message
 * @param {boolean=} opts.verifyTls    — if false (default), skip TLS cert verification (HTTPS only)
 * @param {number=}  opts.timeoutMs    — request timeout, default 5000
 *
 * @returns {Promise<{
 *   ok: boolean,
 *   httpStatus: number|null,
 *   matchingSensors: number|null,
 *   prtgStatus: string|null,
 *   body: string|null,
 *   error: string|null,
 *   durationMs: number,
 *   url: string
 * }>}
 */
async function pushToPrtg(opts) {
  const t0 = Date.now();

  // Validate first — caller bugs should fail fast, not as network errors
  try {
    validateOpts(opts);
  } catch (err) {
    return {
      ok: false,
      httpStatus: null,
      matchingSensors: null,
      prtgStatus: null,
      body: null,
      error: `validation: ${err.message}`,
      durationMs: Date.now() - t0,
      url: null
    };
  }

  const {
    host, port, protocol = 'http', token, channels,
    statusText, verifyTls = false, timeoutMs = 5000
  } = opts;

  // PRTG ignores trailing slashes; build URL deterministically
  const url = `${protocol}://${host}:${port}/${encodeURIComponent(token)}`;

  let xmlBody;
  try {
    xmlBody = buildPrtgXml(channels, statusText);
  } catch (err) {
    return {
      ok: false,
      httpStatus: null,
      matchingSensors: null,
      prtgStatus: null,
      body: null,
      error: `xml-build: ${err.message}`,
      durationMs: Date.now() - t0,
      url
    };
  }

  // For HTTPS with verifyTls=false we need to override the global default.
  // Node's built-in fetch doesn't expose an 'agent' option until 18.x+ via
  // undici dispatcher. The clean Node-20 approach: set NODE_TLS_REJECT_UNAUTHORIZED
  // in scope, but that's process-global. Better: use a custom Agent only when needed.
  let dispatcher;
  if (protocol === 'https' && verifyTls === false) {
    try {
      // Lazy-load undici only when we actually need it
      const { Agent } = require('undici');
      dispatcher = new Agent({ connect: { rejectUnauthorized: false } });
    } catch (err) {
      // undici should be bundled with Node 20; if it's not, fall through and let
      // fetch use its default (which will reject self-signed certs)
    }
  }

  const fetchOpts = {
    method: 'POST',
    headers: { 'Content-Type': 'text/xml; charset=utf-8' },
    body: xmlBody,
    signal: AbortSignal.timeout(timeoutMs)
  };
  if (dispatcher) fetchOpts.dispatcher = dispatcher;

  let res, bodyText;
  try {
    res = await fetch(url, fetchOpts);
    bodyText = await res.text();
  } catch (err) {
    // AbortSignal.timeout fires a TimeoutError (DOMException name="TimeoutError")
    const isTimeout = err && (err.name === 'TimeoutError' || err.code === 'UND_ERR_HEADERS_TIMEOUT');
    return {
      ok: false,
      httpStatus: null,
      matchingSensors: null,
      prtgStatus: null,
      body: null,
      error: `${isTimeout ? 'timeout' : 'network'}: ${err && err.message ? err.message : String(err)}`,
      durationMs: Date.now() - t0,
      url
    };
  }

  const parsed = parsePrtgResponse(bodyText);

  // PRTG returns HTTP 200 even when the token matches no sensor — that's why
  // we also check matchingSensors. ok = HTTP 2xx AND ≥1 matching sensor.
  const httpOk = res.status >= 200 && res.status < 300;
  const sensorMatched = parsed.matchingSensors !== null
    ? parsed.matchingSensors >= 1
    : null;  // unknown — older PRTG, or non-JSON body

  let ok, error = null;
  if (!httpOk) {
    ok = false;
    error = `http: status ${res.status}`;
  } else if (sensorMatched === false) {
    ok = false;
    error = 'sensor-mismatch: PRTG returned 0 matching sensors (token wrong, sensor deleted, or paused)';
  } else {
    ok = true;
  }

  return {
    ok,
    httpStatus: res.status,
    matchingSensors: parsed.matchingSensors,
    prtgStatus: parsed.status,
    body: bodyText,
    error,
    durationMs: Date.now() - t0,
    url
  };
}

/* -------------------------------------------------------------------------- */
/*  CLI                                                                       */
/* -------------------------------------------------------------------------- */

function parseArgs(argv) {
  const args = {};
  for (const a of argv) {
    const m = a.match(/^--([^=]+)(?:=(.*))?$/);
    if (!m) continue;
    args[m[1]] = m[2] === undefined ? true : m[2];
  }
  return args;
}

async function cliMain() {
  const [, , cmd, ...rest] = process.argv;

  if (!cmd || cmd === '--help' || cmd === '-h') {
    process.stdout.write(
      `cert-watchtower-prtg-helper v${VERSION}\n\n` +
      `Usage:\n` +
      `  node cert-watchtower-prtg-helper.js test-push \\\n` +
      `      --host=HOST --port=PORT --token=GUID \\\n` +
      `      --value=NUMBER [--channel=NAME] [--text="status"] \\\n` +
      `      [--protocol=http|https] [--insecure] [--timeout=5000]\n\n` +
      `Examples:\n` +
      `  node cert-watchtower-prtg-helper.js test-push \\\n` +
      `      --host=prtg01awsw2us.nrpi.local --port=5050 \\\n` +
      `      --token=08BBBD60-145C-4866-98E0-542BDA6A9F52 \\\n` +
      `      --value=77 --text="CLI test"\n`
    );
    process.exit(cmd ? 0 : 1);
  }

  if (cmd !== 'test-push') {
    process.stderr.write(`Unknown command: ${cmd}\nRun with --help for usage.\n`);
    process.exit(2);
  }

  const args = parseArgs(rest);
  const required = ['host', 'port', 'token', 'value'];
  for (const k of required) {
    if (args[k] === undefined) {
      process.stderr.write(`Missing required: --${k}\n`);
      process.exit(2);
    }
  }

  const port = parseInt(args.port, 10);
  const value = Number(args.value);
  if (!Number.isFinite(value)) {
    process.stderr.write(`--value must be a number, got '${args.value}'\n`);
    process.exit(2);
  }
  const timeoutMs = args.timeout ? parseInt(args.timeout, 10) : 5000;

  const result = await pushToPrtg({
    host: args.host,
    port,
    protocol: args.protocol || 'http',
    token: args.token,
    channels: [
      { name: args.channel || 'Test Value', value }
    ],
    statusText: args.text,
    verifyTls: args.insecure ? false : true,
    timeoutMs
  });

  // Pretty-print result; exit 0 on ok, 1 on failure
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exit(result.ok ? 0 : 1);
}

/* -------------------------------------------------------------------------- */
/*  Exports / entrypoint                                                      */
/* -------------------------------------------------------------------------- */

module.exports = {
  pushToPrtg,
  buildPrtgXml,
  parsePrtgResponse,
  VERSION
};

// Run CLI only when invoked directly (not when require()d)
if (require.main === module) {
  cliMain().catch((err) => {
    process.stderr.write(`fatal: ${err && err.stack ? err.stack : err}\n`);
    process.exit(99);
  });
}
