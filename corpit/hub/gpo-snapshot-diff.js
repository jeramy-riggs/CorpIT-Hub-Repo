'use strict';

// Read-only snapshot comparison. Database row IDs change on every import;
// compare GPO GUIDs and semantic finding identities instead.
const guid = value => String(value || '').toLowerCase().replace(/[{}]/g, '');
const stable = value => JSON.stringify(value, (_, item) =>
  item && !Array.isArray(item) && typeof item === 'object'
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);

function snapshotId(value) {
  if (typeof value !== 'string' || !/^[1-9]\d{0,9}$/.test(value) || Number(value) > 4294967295) return null;
  return Number(value);
}

function findingKey(row) {
  let related = [];
  try { related = typeof row.related_guids === 'string' ? JSON.parse(row.related_guids) : row.related_guids; } catch (_) {}
  related = Array.isArray(related) ? [...new Set(related.map(guid))].sort() : [];
  // Cross-GPO findings may choose a different first GPO after reordering an XML.
  const owners = related.length ? related : [guid(row.gpo_guid)];
  const subject = row.setting_key || (owners.some(Boolean) ? '' : `${row.title || ''}\n${row.detail || ''}`);
  return stable([row.code, row.severity, owners, subject]);
}

function subtractFindings(left, right) {
  const remaining = new Map();
  for (const row of right) {
    const key = findingKey(row);
    remaining.set(key, (remaining.get(key) || 0) + 1);
  }
  return left.filter(row => {
    const key = findingKey(row), count = remaining.get(key) || 0;
    if (!count) return true;
    remaining.set(key, count - 1);
    return false;
  });
}

function signature(row) {
  const { id, upload_id, guid: ignoredGuid, gpo_guid, ...content } = row;
  // Trustees are stored as a JSON array, whose order is not significant.
  if (typeof content.security_trustees === 'string') {
    try {
      const parsed = JSON.parse(content.security_trustees);
      if (Array.isArray(parsed)) content.security_trustees = parsed.map(stable).sort();
    } catch (_) {}
  }
  return stable(content);
}

function groupContent(rows) {
  const result = new Map();
  for (const row of rows) {
    const key = guid(row.gpo_guid);
    if (!result.has(key)) result.set(key, []);
    result.get(key).push(signature(row));
  }
  return new Map([...result].map(([key, values]) => [key, stable(values.sort())]));
}

function compareRows(from, to) {
  const before = new Map(from.inventory.map(row => [guid(row.guid), row]));
  const after = new Map(to.inventory.map(row => [guid(row.guid), row]));
  const beforeLinks = groupContent(from.links), afterLinks = groupContent(to.links);
  const beforeSettings = groupContent(from.settings), afterSettings = groupContent(to.settings);
  const changedGPOs = [];
  for (const [key, row] of after) {
    const old = before.get(key);
    if (!old) continue;
    const changed = [];
    if (signature(old) !== signature(row)) changed.push('metadata');
    if ((beforeLinks.get(key) || '[]') !== (afterLinks.get(key) || '[]')) changed.push('links');
    if ((beforeSettings.get(key) || '[]') !== (afterSettings.get(key) || '[]')) changed.push('settings');
    if (changed.length) changedGPOs.push({ ...row, changed });
  }
  const sort = rows => rows.sort((a, b) =>
    String(a.name || a.title || '').localeCompare(String(b.name || b.title || '')) || stable(a).localeCompare(stable(b)));
  return {
    addedGPOs: sort([...after].filter(([key]) => !before.has(key)).map(([, row]) => row)),
    removedGPOs: sort([...before].filter(([key]) => !after.has(key)).map(([, row]) => row)),
    changedGPOs: sort(changedGPOs),
    newFindings: sort(subtractFindings(to.findings, from.findings)),
    resolvedFindings: sort(subtractFindings(from.findings, to.findings)),
  };
}

async function compareSnapshots(conn, fromId, toId) {
  // Keep all reads consistent even if an upload is removed concurrently.
  await conn.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  await conn.query('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
  try {
    const [uploads] = await conn.query(
      'SELECT id, filename, uploaded_at, parse_status FROM gpo_uploads WHERE id IN (?, ?)', [fromId, toId]);
    const from = uploads.find(row => row.id === fromId), to = uploads.find(row => row.id === toId);
    if (!from || !to) {
      const error = new Error('One or both snapshots were not found');
      error.status = 404; error.code = 'SNAPSHOT_NOT_FOUND'; throw error;
    }
    if (from.parse_status !== 'ok' || to.parse_status !== 'ok') {
      const error = new Error('Both snapshots must have completed parsing');
      error.status = 409; error.code = 'SNAPSHOT_NOT_READY'; throw error;
    }
    async function read(id) {
      const [inventory] = await conn.query('SELECT * FROM gpo_inventory WHERE upload_id=?', [id]);
      const [findings] = await conn.query(
        `SELECT f.gpo_guid, f.severity, f.code, f.title, f.detail, f.related_guids, f.setting_key,
                i.name AS gpo_name FROM gpo_findings f
         LEFT JOIN gpo_inventory i ON i.upload_id=f.upload_id AND i.guid=f.gpo_guid WHERE f.upload_id=?`, [id]);
      const [links] = await conn.query('SELECT * FROM gpo_links WHERE upload_id=?', [id]);
      const [settings] = await conn.query('SELECT * FROM gpo_settings WHERE upload_id=?', [id]);
      return { inventory, findings, links, settings };
    }
    const before = await read(fromId), after = await read(toId);
    const result = { from, to, ...compareRows(before, after) };
    await conn.commit();
    return result;
  } catch (error) {
    await conn.rollback();
    throw error;
  }
}

module.exports = { snapshotId, compareRows, compareSnapshots };
