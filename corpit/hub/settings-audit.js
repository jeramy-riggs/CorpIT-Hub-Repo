'use strict';
// settings-audit.js — settingsfold W6 (2026-10-12)
// One row shape for the rbac_audit_log entries that settings save routes write,
// so a save made from the subadmin Settings tabs shows up in User activity
// (hub user-activity.js, source "Access audit": actor_email exact match).
//
// Installed as two identical copies: /var/www/corpit-hub-api/settings-audit.js
// (hub :3001) and /var/www/api/settings-audit.js (it-inventory-api :3000, the
// cert-watchtower routes). No requires, no state.
//
// Rules this file enforces:
//   * never throws and never rejects: an audit gap must not break or change a save;
//   * secret values are never written. A key that is in the caller's secret list,
//     or whose name looks like a credential (SECRET_RE), is recorded only as
//     "(set)", "(changed)" or "(cleared)";
//   * other values are clipped to 200 characters;
//   * if a before/after read failed, the row says so (changes_unavailable) and
//     lists the field names only. It never guesses an old value.

const SECRET_RE = /(token|secret|password|passwd|pwd|api[_-]?key|private[_-]?key|webhook|credential|bearer|cookie|config_json|mention_config)/i;
const CLIP = 200;

function isSecret(key, secretKeys) {
  return (Array.isArray(secretKeys) && secretKeys.indexOf(key) >= 0) || SECRET_RE.test(String(key));
}
function empty(v) { return v === null || v === undefined || v === ''; }
function text(v) {
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch (e) { return String(v); } }
  return String(v);
}
function same(a, b) {
  if (empty(a) && empty(b)) return true;
  if (empty(a) || empty(b)) return false;
  if (typeof a !== 'object' && typeof b !== 'object' && a !== true && b !== true && a !== false && b !== false) {
    const na = Number(a), nb = Number(b);
    if (String(a).trim() !== '' && String(b).trim() !== '' && Number.isFinite(na) && Number.isFinite(nb)) return na === nb;
  }
  return text(a) === text(b);
}
function clipValue(v) {
  if (v === undefined || v === null) return null;
  if (Buffer.isBuffer(v)) return '(binary)';
  if (typeof v === 'number' || typeof v === 'boolean') return v;
  const s = text(v);
  return s.length > CLIP ? s.slice(0, CLIP) + '…' : s;
}

// { key: {from, to} } for the keys whose value differs. Secret keys: "(set)" /
// "(changed)" / "(cleared)" only.
function changes(before, after, keys, secretKeys) {
  const b = before || {}, a = after || {};
  const ks = keys || Array.from(new Set(Object.keys(b).concat(Object.keys(a))));
  const out = {};
  for (const k of ks) {
    const x = b[k], y = a[k];
    if (same(x, y)) continue;
    if (isSecret(k, secretKeys)) out[k] = empty(y) ? '(cleared)' : empty(x) ? '(set)' : '(changed)';
    else out[k] = { from: clipValue(x), to: clipValue(y) };
  }
  return out;
}

// First row, null when there is no row, undefined when the read failed.
async function snap(pool, sql, params) {
  try {
    const r = await pool.query(sql, params || []);
    const rows = r && r[0];
    return Array.isArray(rows) && rows.length ? rows[0] : null;
  } catch (e) { return undefined; }
}

// {key: row-or-value} from a key/value table; undefined when the read failed.
async function byKey(pool, sql, params, keyCol, valCol) {
  try {
    const r = await pool.query(sql, params || []);
    const out = {};
    for (const row of (r && r[0]) || []) out[row[keyCol]] = valCol ? row[valCol] : row;
    return out;
  } catch (e) { return undefined; }
}

// Build the details object.
//   what      the settings area ("watchlist", "channel", "thresholds", ...)
//   op        create|update|delete|pause|resume|test; omitted => derived from before
//   id, subject   row id and its natural key (upn, cidr, subject) — never a secret
//   before/after  snapshots (null = no row, undefined = read failed)
//   keys      field names to compare;  secretKeys  extra secret field names
//   extra     extra non-secret facts (rows, partial, ok, ...)
function entry(o) {
  const d = { what: o.what };
  if (o.op) d.op = o.op;
  else d.op = o.before === null ? 'create' : (o.before ? 'update' : 'upsert');
  if (o.id !== undefined && o.id !== null) d.id = o.id;
  if (o.subject !== undefined && o.subject !== null) d.subject = clipValue(String(o.subject));
  if (o.keys) {
    d.fields = o.keys.slice(0, 50);
    if (o.before === undefined || o.after === undefined) d.changes_unavailable = 'before/after read failed';
    else d.changes = changes(o.before, o.after, o.keys, o.secretKeys);
  }
  if (o.extra) for (const k of Object.keys(o.extra)) if (o.extra[k] !== undefined) d[k] = o.extra[k];
  return d;
}

function routeOf(req) {
  try { return String(req.method) + ' ' + (req.baseUrl || '') + ((req.route && req.route.path) || req.path || ''); }
  catch (e) { return null; }
}

// rbac.audit(req, action, target_email, target_page_key, details) — swallowed.
async function record(rbac, req, page, action, detail) {
  try {
    if (!rbac || typeof rbac.audit !== 'function') return;
    const d = Object.assign({ route: routeOf(req) }, detail || {});
    await rbac.audit(req, action, null, page, d);
  } catch (e) {
    try { console.error('[settings-audit] ' + action + ' on ' + page + ' not recorded:', e && e.message); } catch (_) { /* */ }
  }
}

module.exports = { SECRET_RE, isSecret, changes, snap, byKey, entry, record };
