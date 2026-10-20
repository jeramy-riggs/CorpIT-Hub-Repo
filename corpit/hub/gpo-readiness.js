'use strict';

// Snapshot-only estimate; no Graph/Intune calls or directory changes.
function classifySetting(s) {
  const normalize = value => String(value || '').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_/-]+/g, ' ').toLowerCase();
  const path = normalize(s.category_path), type = normalize(s.setting_type), name = normalize(s.setting_name);
  const hay = path + ' ' + type + ' ' + name;
  // The collector stores Administrative Templates as admin_template; category paths omit that prefix.
  if (/^admin(?:istrative)? templates?$/.test(type) || /administrative templates|admx/.test(path))
    return { tier: 'ready', reason: 'Settings Catalog candidate — verify exact Microsoft mapping' };
  if (/folder redirection/.test(hay)) return { tier: 'no', reason: 'Review OneDrive Known Folder Move as an alternative' };
  if (/software installation|software settings/.test(hay) || /\bmsi\b/.test(hay)) return { tier: 'no', reason: 'Review Intune app deployment as an alternative' };
  if (/drive ?map|mapped drive|network drive/.test(hay)) return { tier: 'no', reason: 'Drive maps need a separately reviewed alternative' };
  if (/scheduled task/.test(hay)) return { tier: 'no', reason: 'Scheduled tasks need a separately reviewed alternative' };
  if (/script/.test(type + ' ' + path)) return { tier: 'no', reason: 'Review platform scripts or remediations as an alternative' };
  if (/printer/.test(type + ' ' + path)) return { tier: 'no', reason: 'Review Universal Print or another printer deployment approach' };
  if (/user rights assignment/.test(hay)) return { tier: 'partial', reason: 'User rights candidate — verify supported rights, principals and scope' };
  if (/security options|account polic|password|account lockout|\baudit\b|windows firewall|system services/.test(hay)) return { tier: 'ready', reason: 'Security policy candidate — verify CSP, scope and value' };
  if (/preferences/.test(type + ' ' + path)) return { tier: 'partial', reason: 'Group Policy Preference — verify an alternative' };
  if (/internet explorer|control panel/.test(hay)) return { tier: 'partial', reason: 'Legacy setting — review a supported replacement' };
  return { tier: 'review', reason: 'Unrecognized — manual review' };
}

function rollupGpo(g, settings) {
  const counts = { ready: 0, partial: 0, no: 0, review: 0 };
  const blockers = new Set();
  settings.forEach(s => { const c = classifySetting(s); counts[c.tier]++; if (c.tier === 'no') blockers.add(c.reason); });
  const total = settings.length;
  const readiness = total ? Math.round(100 * (counts.ready + 0.5 * counts.partial) / total) : 0;
  const hasBlocker = counts.no > 0;
  let rating = readiness >= 85 ? 'ready' : readiness >= 60 ? 'mostly' : readiness >= 30 ? 'partial' : 'stays';
  if (hasBlocker && (rating === 'ready' || rating === 'mostly')) rating = 'partial';
  if (total === 0) rating = 'stays';
  return { name: g.name, guid: g.guid, total, counts, readiness, rating, blockers: [...blockers] };
}

function summarizeIntune(results) {
  const summary = { ready: 0, mostly: 0, partial: 0, stays: 0, totalSettings: 0, portableSettings: 0 };
  results.forEach(r => { summary[r.rating]++; summary.totalSettings += r.total; summary.portableSettings += r.counts.ready + 0.5 * r.counts.partial; });
  summary.readyPct = summary.totalSettings ? Math.round(100 * summary.portableSettings / summary.totalSettings) : 0;
  return { gpos: results, summary };
}

function buildReadiness(inventory, settings) {
  const grouped = new Map();
  const key = value => String(value || '').toLowerCase().replace(/[{}]/g, '');
  for (const row of settings) {
    const id = key(row.gpo_guid);
    if (!grouped.has(id)) grouped.set(id, []);
    grouped.get(id).push(row);
  }
  return { ...summarizeIntune(inventory.map(g => { const rows = grouped.get(key(g.guid)) || []; return { ...rollupGpo(g, rows), settings: rows.map(s => ({ ...s, ...classifySetting(s) })) }; })),
    source: 'snapshot', estimated: true, complete: true };
}
function createReadinessService({ pool, getActiveUploadId, now = Date.now, ttlMs = 300000 }) {
  const cache = new Map(), pending = new Map();
  return { async read() {
    const conn = await pool.getConnection();
    try {
      const id = await getActiveUploadId(conn);
      if (!id) return { ok: true, data: null, upload_id: null };
      const saved = cache.get(id);
      if (saved && saved.expires > now()) return saved.value;
      if (pending.has(id)) return await pending.get(id);
      const work = (async () => {
        const [inventory] = await conn.query('SELECT guid, name FROM gpo_inventory WHERE upload_id=? ORDER BY name', [id]);
        // Read every classified field; the detail endpoint's 200-setting sample is unsuitable here.
        const [settings] = await conn.query('SELECT gpo_guid, scope, setting_type, setting_name, setting_state, setting_value, category_path FROM gpo_settings WHERE upload_id=?', [id]);
        const value = { ok: true, data: buildReadiness(inventory, settings), upload_id: id };
        cache.set(id, { value, expires: now() + ttlMs });
        while (cache.size > 3) cache.delete(cache.keys().next().value);
        return value;
      })();
      pending.set(id, work);
      try { return await work; } finally { if (pending.get(id) === work) pending.delete(id); }
    } finally { conn.release(); }
  }};
}
module.exports = { classifySetting, rollupGpo, summarizeIntune, buildReadiness, createReadinessService };
