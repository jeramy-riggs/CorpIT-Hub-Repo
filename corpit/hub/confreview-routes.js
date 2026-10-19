'use strict';
/**
 * confreview-routes.js — mounts the configuration review at /api/confreview/
 *
 *   POST /api/confreview/analyze   { text, vendor? }  — review pasted/uploaded config
 *   GET  /api/confreview/collect?fw=irvine|dallas     — pull live config and review it
 *   GET  /api/confreview/checks                       — what the engine looks at
 *
 * Read-only in every sense: it never writes to a device, and it never stores a
 * configuration. Uploaded text lives in the request body for the duration of the
 * call and is discarded; collected text is held in a local variable and never
 * written to disk or returned to the browser. Only findings leave this module, and
 * their evidence lines are scrubbed of secrets by confreview.finding().
 */
const express = require('express');
const https = require('https');
const router = express.Router();

const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME, waitForConnections: true, connectionLimit: 5,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);

const { analyze, COVERAGE, NOT_EVALUATED } = require('./confreview/analyze');

const MAX_BYTES = 8 * 1024 * 1024;      // a full chassis config is ~1MB; 8 is generous
const FW = {
  irvine: { host: process.env.FORTIGATE_HOST, token: process.env.FORTIGATE_API_TOKEN,
            label: 'Irvine FortiGate', site: 'SNA01' },
  dallas: { host: process.env.FORTIGATE_DALLAS_HOST, token: process.env.FORTIGATE_DALLAS_API_TOKEN,
            label: 'Dallas FortiGate', site: 'DFW02' },
};

/* ── POST /analyze — uploaded or pasted config ───────────────────────────── */
router.post('/analyze', rbac.requirePage('network-diag', 'read'),
  express.json({ limit: MAX_BYTES }), (req, res) => {
    const body = req.body || {};
    const text = typeof body.text === 'string' ? body.text : '';
    if (!text.trim()) {
      return res.status(400).json({ ok: false, error: 'EMPTY',
        message: 'No configuration text was supplied.' });
    }
    if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) {
      return res.status(413).json({ ok: false, error: 'TOO_LARGE',
        message: `Configuration exceeds the ${MAX_BYTES / 1024 / 1024} MB limit.` });
    }
    try {
      const result = analyze(text, { vendor: body.vendor });
      result.source = { kind: 'upload', name: (body.name || '').slice(0, 120) || null };
      return res.json(result);
      // `text` goes out of scope here. Nothing is written anywhere.
    } catch (e) {
      return res.status(500).json({ ok: false, error: 'ANALYZE_FAILED', message: e.message });
    }
  });

/* ── GET /collect — pull the live firewall config and review it ───────────── */
function fetchConfig(cfg) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL('api/v2/monitor/system/config/backup?scope=global',
                      cfg.host.endsWith('/') ? cfg.host : cfg.host + '/'); }
    catch (e) { return reject(new Error('bad FORTIGATE host')); }
    const rq = https.request({
      hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: 'GET',
      headers: { Authorization: `Bearer ${cfg.token}` },
      // self-signed cert on a management address — relaxed for THIS request only
      agent: new https.Agent({ rejectUnauthorized: false }), timeout: 30000,
    }, r => {
      let d = '';
      r.on('data', c => { d += c; if (d.length > MAX_BYTES) { rq.destroy(); reject(new Error('config exceeds size limit')); } });
      r.on('end', () => {
        if (r.statusCode === 200) return resolve(d);
        // 401/403 here is almost always the API token's profile, not the network:
        // reading a full config needs more than the read-only monitor scope the
        // dashboard endpoints get by with. Say so, rather than "HTTP 403".
        const why = (r.statusCode === 403 || r.statusCode === 401)
          ? `the firewall refused the request (HTTP ${r.statusCode}). Reading a full configuration needs an API token whose admin profile grants read access to System > Configuration; the token that powers the dashboards may only have monitor scope.`
          : `the firewall returned HTTP ${r.statusCode}.`;
        reject(Object.assign(new Error(why), { statusCode: 502 }));
      });
    });
    rq.on('error', e => reject(e));
    rq.on('timeout', () => { rq.destroy(); reject(new Error('firewall timed out')); });
    rq.end();
  });
}

// Collecting a live device config is a privileged action, so it needs admin,
// not the read level the upload path uses.
router.get('/collect', rbac.requirePage('network-diag', 'admin'), async (req, res) => {
  const key = String(req.query.fw || 'irvine').toLowerCase();
  const cfg = FW[key];
  if (!cfg) return res.status(400).json({ ok: false, error: 'BAD_FW',
    message: `Unknown firewall "${key}". Expected one of: ${Object.keys(FW).join(', ')}.` });
  if (!cfg.host || !cfg.token) return res.status(400).json({ ok: false, error: 'NOT_CONFIGURED',
    message: `${cfg.label} has no host or API token configured on this server.` });
  try {
    const text = await fetchConfig(cfg);
    const result = analyze(text);
    result.source = { kind: 'collected', name: cfg.label, site: cfg.site,
                      fetchedBytes: Buffer.byteLength(text, 'utf8') };
    result.notes.unshift({ kind: 'info',
      text: `Configuration was read live from ${cfg.label} and analysed in memory. It was not saved on this server and the config text itself is not returned to the browser — only the findings below.` });
    return res.json(result);
  } catch (e) {
    return res.status(e.statusCode || 502).json({ ok: false, error: 'COLLECT_FAILED',
      message: `Could not read the configuration from ${cfg.label} — ${e.message}`,
      hint: 'You can still review this device by exporting its configuration and pasting it into the box on the left.' });
  }
});

/* ── GET /checks — what this engine covers, for the UI to show up front ──── */
router.get('/checks', rbac.requirePage('network-diag', 'read'), (req, res) => {
  res.json({ ok: true, coverage: COVERAGE, notEvaluated: NOT_EVALUATED,
    firewalls: Object.keys(FW).filter(k => FW[k].host && FW[k].token)
      .map(k => ({ key: k, label: FW[k].label, site: FW[k].site })),
    limits: { maxBytes: MAX_BYTES } });
});

module.exports = router;
