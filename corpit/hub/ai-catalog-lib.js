// ═══════════════════════════════════════════════════════════════════
// ai-catalog-lib.js v1.1 — shared AI app catalog for Gen AI Security v3
// Location: /var/www/corpit-hub-api/ai-catalog-lib.js
//
// Backs the Gen AI detection matchers with the ai_catalog MySQL table.
// The cache refreshes in the background (5-min TTL); all matchers are
// SYNCHRONOUS so existing call sites (isAiSp, UA sig scan) keep their
// signatures. If the DB is unreachable or the table is empty, matchers
// fall back to the frozen LEGACY_* constants (the exact pre-v3 hardcoded
// lists), so detection never goes dark.
//
// API:
//   init(pool)                 -> wire the mysql2/promise pool (once)
//   refresh()                  -> Promise; force reload now
//   matchSpTextSync(text)      -> catalog row | null   (Entra SP matching)
//   uaSigsSync()               -> [{name, re, row?}]   (desktop client sigs)
//   sanctionOfSync(appName)    -> {status, row} | null
//   catalogSync()              -> active rows ([] until first load)
//   fromDb()                   -> bool (true = live DB cache in use)
//   norm(s)                    -> normalization used for keys
// ═══════════════════════════════════════════════════════════════════
'use strict';

var _pool = null;
var _cache = { rows: [], normKeys: [], sigs: [], byNorm: {}, exp: 0, fromDb: false };
var _loading = false;
var TTL_MS = 5 * 60 * 1000;

// ── Frozen legacy fallbacks (pre-v3 hardcoded lists, verbatim) ──
var LEGACY_KEYS = ['openai','chatgpt','anthropic','claude','gemini','copilot','grammarly','perplexity','cursor','codeium','windsurf','cohere','mistral','huggingface','notion ai','otter','fireflies','tldv','fathom','grok','poe.com','character.ai','midjourney','runway','elevenlabs','synthesia','heygen','ollama','glean','harvey','writer','jasper'];
var LEGACY_SIGS = [
  { name: 'Claude Desktop', re: /Claude\/[\d.]+/i },
  { name: 'ChatGPT Desktop', re: /ChatGPT\/[\d.]+|OpenAI\/Desktop/i },
  { name: 'Cursor', re: /Cursor\/[\d.]+|cursor-ide/i },
  { name: 'Ollama', re: /Ollama/i },
  { name: 'LM Studio', re: /LMStudio|LM-Studio/i },
  { name: 'Continue.dev', re: /Continue\/[\d.]+|continue-dev/i },
  { name: 'Cline', re: /Cline\/|cline-vscode/i },
  { name: 'Windsurf', re: /Windsurf\/[\d.]+|windsurf-editor/i },
  { name: 'Aider', re: /aider\/[\d.]+/i },
  { name: 'Perplexity Desktop', re: /Perplexity\/[\d.]+/i },
  { name: 'MCP Client', re: /modelcontextprotocol|mcp-client|Claude-Code/i },
  { name: 'Grammarly App', re: /Grammarly\/[\d.]+/i },
  { name: 'Merlin Extension', re: /merlin/i },
  { name: 'Sider Extension', re: /sider/i },
  { name: 'Monica Extension', re: /monica/i }
];

function norm(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, ''); }

function init(pool) { _pool = pool; }

function refresh() {
  if (!_pool) return Promise.resolve(_cache);
  _loading = true;
  return _pool.query(
    'SELECT id, app_name, norm_key, aliases, domains, ua_patterns, category, sanction_status, risk_note, source, retired FROM ai_catalog WHERE retired=0'
  ).then(function (out) {
    var rows = out[0] || [];
    if (!rows.length) { _cache.exp = Date.now() + TTL_MS; _cache.fromDb = false; return _cache; }
    var normKeys = [], sigs = [], byNorm = {};
    rows.forEach(function (r) {
      var keys = [r.norm_key].concat(String(r.aliases || '').split(/\n+/).map(norm));
      keys.forEach(function (k) {
        if (!k || k.length < 3) return;
        normKeys.push({ key: k, row: r });
        byNorm[k] = r;
      });
      String(r.ua_patterns || '').split(/\n+/).forEach(function (p) {
        p = p.trim();
        if (!p) return;
        try { sigs.push({ name: r.app_name, re: new RegExp(p, 'i'), row: r }); }
        catch (e) { /* bad regex stored in DB — skip, never crash */ }
      });
    });
    _cache = { rows: rows, normKeys: normKeys, sigs: sigs, byNorm: byNorm, exp: Date.now() + TTL_MS, fromDb: true };
    return _cache;
  }).catch(function () {
    // DB down / table missing — keep last good cache, retry after TTL
    _cache.exp = Date.now() + TTL_MS;
    return _cache;
  }).finally(function () { _loading = false; });
}

function _kick() { if (Date.now() >= _cache.exp && !_loading) refresh(); }

function matchSpTextSync(text) {
  _kick();
  var s = String(text || '').toLowerCase();
  if (_cache.fromDb) {
    var stripped = norm(s);
    for (var i = 0; i < _cache.normKeys.length; i++) {
      var k = _cache.normKeys[i].key;
      if (s.indexOf(k) >= 0 || stripped.indexOf(k) >= 0) return _cache.normKeys[i].row;
    }
    return null;
  }
  for (var j = 0; j < LEGACY_KEYS.length; j++) {
    if (s.indexOf(LEGACY_KEYS[j]) >= 0) return { app_name: LEGACY_KEYS[j], sanction_status: 'review', source: 'legacy' };
  }
  return null;
}

function uaSigsSync() {
  _kick();
  return (_cache.fromDb && _cache.sigs.length) ? _cache.sigs : LEGACY_SIGS;
}

function sanctionOfSync(appName) {
  _kick();
  if (!_cache.fromDb) return null;
  var n = norm(appName);
  if (!n || n.length < 3) return null;
  if (_cache.byNorm[n]) return { status: _cache.byNorm[n].sanction_status, row: _cache.byNorm[n] };
  for (var i = 0; i < _cache.normKeys.length; i++) {
    var k = _cache.normKeys[i].key;
    if (n.indexOf(k) >= 0 || k.indexOf(n) >= 0) return { status: _cache.normKeys[i].row.sanction_status, row: _cache.normKeys[i].row };
  }
  return null;
}

function catalogSync() { _kick(); return _cache.rows; }
function fromDb() { return _cache.fromDb; }

module.exports = {
  init: init, refresh: refresh,
  matchSpTextSync: matchSpTextSync, uaSigsSync: uaSigsSync, sanctionOfSync: sanctionOfSync,
  catalogSync: catalogSync, fromDb: fromDb, norm: norm,
  LEGACY_KEYS: LEGACY_KEYS, LEGACY_SIGS: LEGACY_SIGS
};
