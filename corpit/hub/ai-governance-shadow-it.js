'use strict';
const crypto = require('node:crypto');
const MAX_BYTES = 16 * 1024 * 1024, MAX_ROWS = 25000, MAX_COLUMNS = 200;
function invalid(code) { const e = new Error('Shadow IT report validation failed'); e.code = code; throw e; }
const key = s => String(s || '').replace(/^\uFEFF/, '').toLowerCase().replace(/[^a-z0-9]/g, '');
// RFC 4180 quoting, including embedded newlines. Never persist the source CSV.
function csv(text, { vendorMetadataQuotes = false } = {}) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_BYTES) invalid('SHADOW_SIZE');
  if (/[\u0000\uFFFD]/.test(text)) invalid('SHADOW_ENCODING');
  const rows = []; let row = [], field = '', quoted = false, closed = false, vendorColumns = null;
  function column() { row.push(field); field = ''; closed = false; if (row.length > MAX_COLUMNS) invalid('SHADOW_COLUMNS'); }
  function record() { column();
    // ZIA's exporter emits bare quotes inside unused metadata (e.g. DNS CAA
    // policy descriptions). Permit those only in non-retained columns after
    // identifying the header. Retained application/metric fields stay strict.
    if (vendorMetadataQuotes && !vendorColumns) { const m = mapping(row); if (m.name !== undefined && (m.users !== undefined || m.transactions !== undefined || m.data_consumed !== undefined)) { const retained = new Set(Object.values(m)); vendorColumns = new Set(row.map((_,i)=>i).filter(i=>!retained.has(i))); } }
    if (row.some(x => x.trim())) rows.push(row); row = []; if (rows.length > MAX_ROWS + 40) invalid('SHADOW_ROWS'); }
  text = text.replace(/^\uFEFF/, '');
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else {
      let next = i + 1; while (text[next] === ' ' || text[next] === '\t') next++;
      if (vendorColumns?.has(row.length) && next < text.length && ![',','\r','\n'].includes(text[next])) field += c;
      else { quoted = false; closed = true; }
    } } else field += c; }
    else if (c === ',') column();
    else if (c === '\r' || c === '\n') { if (c === '\r' && text[i + 1] === '\n') i++; record(); }
    else if (c === '"') { if (field || closed) invalid('SHADOW_QUOTES'); quoted = true; }
    else { if (closed) { if (c !== ' ' && c !== '\t') invalid('SHADOW_QUOTES'); } else field += c; }
    if (field.length > 32768) invalid('SHADOW_FIELD');
  }
  if (quoted) invalid('SHADOW_TRUNCATED');
  if (field || row.length || closed) record();
  return rows;
}
const aliases = {
  name: ['application', 'applicationname', 'cloudapplication', 'cloudapplicationname', 'appname'],
  source_id: ['applicationid', 'cloudapplicationid', 'app', 'appcode', 'applicationcode'],
  category: ['category', 'applicationcategory', 'cloudapplicationcategory'],
  users: ['users', 'totalusers', 'uniqueusers', 'numberofusers', 'usercount'],
  transactions: ['transactions', 'totaltransactions', 'numberoftransactions', 'transactioncount', 'totalrequests', 'requests'],
  data_consumed: ['dataconsumed', 'totaldataconsumed', 'totaldata', 'datatransferred', 'totaltraffic', 'totalbytes'],
  upload: ['upload', 'uploaded', 'datauploaded', 'uploadbytes', 'bytesuploaded'],
  download: ['download', 'downloaded', 'datadownloaded', 'downloadbytes', 'bytesdownloaded'],
  risk: ['risk', 'riskindex', 'riskscore', 'cloudapplicationriskindex', 'applicationriskindex'],
  sanction: ['sanctionstatus', 'sanctionedstatus', 'sanctionedstate', 'applicationstatus', 'status'],
  last_used: ['lastused', 'lastaccessed', 'lastaccesstime', 'lastaccessedtime']
};
function mapping(header) {
  const columns = header.map(key), result = {};
  for (const [name, options] of Object.entries(aliases)) {
    const indices = columns.map((v, i) => {
      if (['users','transactions'].includes(name) && /%|percent|percentage/i.test(header[i])) return -1;
      const withoutUnit = ['data_consumed','upload','download'].includes(name) ? v.replace(/(?:bytes|kb|mb|gb|tb)$/, '') : v;
      return options.includes(v) || options.includes(withoutUnit) ? i : -1;
    }).filter(i => i >= 0);
    if (indices.length > 1) invalid('SHADOW_AMBIGUOUS_HEADER');
    if (indices.length) result[name] = indices[0];
  }
  return result;
}
function count(s) {
  s = String(s || '').trim(); if (!s || /^(n\/?a|unknown|--?|null)$/i.test(s)) return null;
  if (!/^(\d+|\d{1,3}(,\d{3})+)$/.test(s)) invalid('SHADOW_NUMBER');
  const n = Number(s.replace(/,/g, '')); if (!Number.isSafeInteger(n) || n < 0) invalid('SHADOW_NUMBER'); return n;
}
function parse(text, checkedAt, duration = 'LAST_7_DAYS') {
  if (!Number.isFinite(Date.parse(checkedAt))) invalid('SHADOW_DATE');
  const records = csv(text, { vendorMetadataQuotes: true }); let start = -1, map;
  for (let i = 0; i < Math.min(records.length, 35); i++) {
    const m = mapping(records[i]);
    if (m.name !== undefined && (m.users !== undefined || m.transactions !== undefined || m.data_consumed !== undefined)) { start = i; map = m; break; }
  }
  if (start < 0) invalid('SHADOW_HEADER');
  const headers = records[start], rows = [], seen = new Map();
  for (const record of records.slice(start + 1)) {
    if (record.length !== headers.length) invalid('SHADOW_ROW_SHAPE');
    const get = name => map[name] === undefined ? '' : record[map[name]].trim();
    const traffic = field => { const value = get(field); if (!value) return null; const unit = map[field] === undefined ? null : headers[map[field]].match(/(?:\(|\b)(bytes|KB|MB|GB|TB)(?:\)|\b)/i) || (key(headers[map[field]]).endsWith('bytes') ? ['bytes','bytes'] : null); return unit && /^[0-9,.]+$/.test(value) ? value + ' ' + (unit[1].toLowerCase()==='bytes'?'bytes':unit[1].toUpperCase()) : value; };
    const name = get('name'); if (!name || name.length > 255) invalid('SHADOW_NAME');
    const row = { name, source_id: get('source_id') || null, category: get('category') || null,
      users: count(get('users')), transactions: count(get('transactions')),
      data_consumed: traffic('data_consumed'), upload: traffic('upload'), download: traffic('download'),
      risk: get('risk') || null, sanction: get('sanction') || null, last_used: get('last_used') || null,
      evidence_kind: 'application_usage_aggregate' };
    for (const [k, v] of Object.entries(row)) if (typeof v === 'string' && v.length > (k === 'name' ? 255 : 500)) invalid('SHADOW_FIELD');
    const id = row.source_id ? 'id:' + row.source_id : 'name:' + name.toLowerCase() + '\0' + (row.category || '');
    if (seen.has(id)) { if (JSON.stringify(seen.get(id)) !== JSON.stringify(row)) invalid('SHADOW_DUPLICATE'); continue; }
    seen.set(id, row); rows.push(row);
  }
  if (rows.length > MAX_ROWS) invalid('SHADOW_ROWS');
  const periodKeys = new Set(['time','timerange','timeperiod','daterange','reportperiod','starttime','endtime','startdate','enddate','from','to']);
  const reportedPeriod = records.slice(0,start).filter(r=>periodKeys.has(key(r[0]))).slice(0,10).map(r=>({label:r[0].slice(0,80),value:r.slice(1).join(' ').slice(0,500)}));
  return { schema_version: 1, checked_at: checkedAt, window: { duration, requested_at: checkedAt, as_reported: reportedPeriod }, rows,
    source_row_count: records.length - start - 1, row_count: rows.length,
    report_sha256: crypto.createHash('sha256').update(text).digest('hex'),
    fields: Object.keys(map), retained: false,
    note: 'Application aggregates from the requested report window. User counts can overlap across applications. Traffic units and vendor risk/sanction labels are retained as reported. This is not evidence of a licensed seat, access grant, AI-feature use or governance approval.' };
}
function retain(current, previous) {
  if (current.shadow_it?.schema_version === 1) return current;
  if (previous?.shadow_it?.schema_version !== 1) return current;
  return { ...current, shadow_it: { ...previous.shadow_it, retained: true, last_attempt_at: current.checked_at } };
}
function decorate(usage, catalog, definitions, match) {
  if (!usage) return null;
  const names = new Set((definitions || []).map(x => key(x.name)));
  return { ...usage, rows: (usage.rows || []).map(x => {
    const matched = match(x, catalog);
    return { ...x, catalog_id: matched?.id || null,
      ai_relevant: !!matched || names.has(key(x.name)) || /(?:\bAI\b|artificial intelligence|machine learning|generative)/i.test(x.category || '') };
  }) };
}
module.exports = { csv, parse, retain, decorate, MAX_BYTES, MAX_ROWS };
