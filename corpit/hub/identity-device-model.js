'use strict';

// Stage 1 is read-only. Source identifiers survive grouping; nothing is persisted.
const SOURCE_TABLES = Object.freeze({
  intune: { table: 'intune_devices', serial: 'serial_number', current: ' AND is_historical=0' },
  'kandji-mac': { table: 'macbooks', serial: 'serial', current: '' },
  manageengine: { table: 'endpoints', serial: 'service_tag', current: '' },
  'kandji-ipad': { table: 'ipad_devices', serial: 'serial', current: '' },
});

function text(v) { return v == null ? '' : String(v).trim(); }
function modelText(v) {
  const value = text(v);
  return /^(?:[-—–]+|unknown|none|null|n\/?a|not (?:applicable|available|specified))?$/i.test(value) ? null : value;
}
function serialKey(v) {
  const s = text(v).toUpperCase();
  if (!s || /^(?:[-—]+|0+|UNKNOWN|NONE|NULL|N\/?A|NOT (?:APPLICABLE|AVAILABLE|SPECIFIED)|DEFAULT STRING|SYSTEM SERIAL NUMBER|TO BE FILLED.*)$/i.test(s)) return '';
  return s;
}
function family(r) {
  const s = text(r.os || r.type).toLowerCase();
  if (/windows/.test(s)) return 'windows';
  if (/mac|osx/.test(s)) return 'mac';
  if (/ipad/.test(s) || r.type === 'iPad') return 'ipad';
  if (/ios|iphone/.test(s)) return 'ios';
  if (/android/.test(s)) return 'android';
  return '';
}
function sourceRecord(sourceKey, rowId, nativeId, device) {
  const native = text(nativeId), row = text(rowId);
  const recordKey = native ? sourceKey + ':native:' + native : row ? sourceKey + ':row:' + row : null;
  return Object.assign({}, device, {
    sourceRef: { sourceKey, rowId: row || null, nativeId: native || null, recordKey },
    // Global serial uniqueness is measured separately, never assumed from one user's list.
    serialMultiplicity: null,
  });
}

async function measureSerialMultiplicity(pool, records) {
  const warnings = [];
  for (const [sourceKey, cfg] of Object.entries(SOURCE_TABLES)) {
    const set = records.filter(r => r.sourceRef.sourceKey === sourceKey);
    const serials = [...new Set(set.map(r => serialKey(r.serial)).filter(Boolean))];
    if (!serials.length) continue;
    try {
      const [counts] = await pool.query(
        'SELECT UPPER(TRIM(' + cfg.serial + ')) AS serial_key, COUNT(*) AS matches FROM it_inventory.' + cfg.table +
        ' WHERE UPPER(TRIM(' + cfg.serial + ')) IN (?)' + cfg.current + ' GROUP BY UPPER(TRIM(' + cfg.serial + '))', [serials]);
      const map = new Map(counts.map(r => [serialKey(r.serial_key), Number(r.matches)]));
      set.forEach(r => { const k = serialKey(r.serial); if (k) r.serialMultiplicity = map.get(k) ?? null; });
    } catch (_) { warnings.push(sourceKey + ': serial uniqueness could not be checked; records remain separate'); }
  }
  return warnings;
}

function buildDeviceGroups(records) {
  const buckets = new Map(), used = new Set(), groups = [];
  records.forEach((r, i) => {
    const sn = serialKey(r.serial), f = family(r);
    if (sn && f) { const k = f + '\u0000' + sn; if (!buckets.has(k)) buckets.set(k, []); buckets.get(k).push(i); }
  });
  function make(indices, status, basis) {
    const rows = indices.map(i => records[i]);
    const refs = rows.map(r => r.sourceRef).sort((a,b) => String(a.recordKey).localeCompare(String(b.recordKey)));
    const preferred = rows.find(r => r.sourceRef.sourceKey === 'manageengine') || rows[0];
    // Only borrow model evidence within this already verified device group.
    // Keep source records untouched and prefer a real ManageEngine model when present.
    const model = modelText(preferred.model) || rows.map(r => modelText(r.model)).find(Boolean) || null;
    const key = refs.find(r => r.recordKey);
    groups.push({ deviceKey: key ? key.recordKey : null, deviceName: preferred.deviceName || preferred.serial || 'Unnamed device',
      model, type: preferred.type || null, serial: preferred.serial || null,
      sourceRefs: refs, records: rows, match: { status, basis } });
    indices.forEach(i => used.add(i));
  }
  for (const indices of buckets.values()) {
    if (indices.length < 2) continue;
    const rows = indices.map(i => records[i]);
    const differentSources = new Set(rows.map(r => r.sourceRef.sourceKey)).size === rows.length;
    const unique = rows.every(r => r.serialMultiplicity === 1 && r.sourceRef.recordKey);
    if (differentSources && unique) make(indices, 'confirmed', 'unique-serial-and-platform');
  }
  records.forEach((r,i) => {
    if (used.has(i)) return;
    const sn = serialKey(r.serial), f = family(r), peers = sn && f ? buckets.get(f + '\u0000' + sn) || [] : [];
    const duplicate = r.serialMultiplicity > 1 || peers.some(j => j !== i && records[j].sourceRef.sourceKey === r.sourceRef.sourceKey);
    make([i], duplicate ? 'ambiguous' : (sn && r.serialMultiplicity == null && r.sourceRef.sourceKey !== 'aws' ? 'unverified' : 'single-source'),
      duplicate ? 'duplicate-serial-kept-separate' : (peers.length > 1 ? 'match-not-confirmed' : 'source-record'));
  });
  return groups;
}

module.exports = { sourceRecord, serialKey, family, measureSerialMultiplicity, buildDeviceGroups };
