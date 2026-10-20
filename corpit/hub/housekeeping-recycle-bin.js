'use strict';

// Read-only discovery. No WinRM, shell execution, LDAP mutation, or caller-supplied filter.
const SHOW_DELETED = '1.2.840.113556.1.4.417';
const LDAP_PAGE_SIZE = 500;
const MAX_RECORDS = 50000;
const PAGED_RESULTS = '1.2.840.113556.1.4.319';
const ATTRIBUTES = ['name', 'msDS-LastKnownRDN', 'objectClass', 'distinguishedName',
  'lastKnownParent', 'whenChanged', 'isDeleted', 'isRecycled'];

function attributes(row) {
  return Object.fromEntries(Object.entries(row).map(([name, value]) => [name.toLowerCase(), value]));
}
function one(value) { return Array.isArray(value) ? value[0] : value; }
function text(value) { return String(one(value) ?? ''); }
function isTrue(value) { return text(value).toLowerCase() === 'true'; }
function date(value) {
  let raw = text(value);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(raw);
  if (m) raw = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${(m[7] || '').padEnd(3, '0').slice(0, 3)}Z`;
  const ms = raw ? Date.parse(raw) : NaN;
  return Number.isFinite(ms) ? new Date(ms).toISOString() : '';
}
function normalize(row) {
  const r = attributes(row);
  if (!isTrue(r.isdeleted) || isTrue(r.isrecycled) || !text(r.distinguishedname)) return null;
  const classes = Array.isArray(r.objectclass) ? r.objectclass : [r.objectclass];
  if (classes.some(c => String(c).toLowerCase() === 'container')) return null;
  return {
    name: text(r['msds-lastknownrdn'] || r.name).replace(/(?:\n|\\0a)DEL:[\s\S]*$/i, ''),
    objectClass: String(classes[classes.length - 1] || 'unknown'),
    dn: text(r.distinguishedname),
    whenChanged: date(r.whenchanged),
    lastKnownParent: text(r.lastknownparent),
  };
}
function search(client, base, options, controls, parseEntry, timeoutMs, maxRecords = MAX_RECORDS) {
  return new Promise((resolve, reject) => {
    const entries = [];
    let settled = false;
    const timer = setTimeout(() => finish(new Error('Recovery directory lookup timed out. Try again.')), timeoutMs);
    function finish(err, limited = false) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err); else resolve({ entries, limited });
    }
    try {
      client.search(base, options, controls, (err, result) => {
        if (settled) return;
        if (err) return finish(err);
        result.on('searchEntry', entry => {
          if (settled) return;
          try {
            if (entries.length >= maxRecords) {
              const error = new Error('Recovery lookup exceeded its safety limit. No partial results were returned.');error.code = 'RESULT_LIMIT';finish(error);return;
            }
            entries.push(parseEntry(entry));
          } catch (error) { finish(error); }
        });
        result.on('error', error => {
          finish(error);
        });
        result.on('end', response => {
          const status = Number(response && response.status || 0);
          if (status) {
            const error = new Error('Recovery directory search failed.');error.code = status;return finish(error);
          }
          finish(null);
        });
      });
    } catch (err) { finish(err); }
  });
}
function createRecoveryReader({ ldap, createClient, closeClient, parseEntry, baseDN, timeoutMs = 15000, scanTimeoutMs = 25000, maxRecords = MAX_RECORDS }) {
  return async function readRecycleBin() {
    let client;
    try {
      client = await createClient();
      const root = await search(client, '', { scope: 'base', filter: '(objectClass=*)', attributes: ['supportedControl'], sizeLimit: 1, timeLimit: 10 }, [], parseEntry, timeoutMs);
      const supported = attributes(root.entries[0] || {}).supportedcontrol || [];
      if (![SHOW_DELETED, PAGED_RESULTS].every(control => (Array.isArray(supported) ? supported : [supported]).includes(control))) {
        const error = new Error('The directory does not support the controls required for a complete deleted-object lookup.');error.code = 'UNSUPPORTED_CONTROL';throw error;
      }
      const controls = [new ldap.Control({ type: SHOW_DELETED, criticality: true })];
      const base = 'CN=Deleted Objects,' + baseDN;
      // Confirm container visibility first; never silently fall back to a normal search.
      const container = await search(client, base, { scope: 'base', filter: '(objectClass=*)', attributes: ['distinguishedName'], sizeLimit: 1, timeLimit: 10 }, controls, parseEntry, timeoutMs);
      if (!container.entries.length) {
        const error = new Error('The current directory account cannot see the Deleted Objects container.');error.code = 'CONTAINER_UNAVAILABLE';throw error;
      }
      const result = await search(client, base, {
        scope: 'one', filter: '(&(isDeleted=TRUE)(!(isRecycled=TRUE))(!(objectClass=container)))',
        attributes: ATTRIBUTES, sizeLimit: 0, timeLimit: 10, paged: { pageSize: LDAP_PAGE_SIZE },
      }, controls, parseEntry, scanTimeoutMs, maxRecords);
      const rows = result.entries.map(normalize).filter(Boolean);
      const compare = new Intl.Collator('en', { numeric: true, sensitivity: 'base' }).compare;
      rows.sort((a, b) => compare(a.name, b.name) || compare(a.dn, b.dn));
      return { success: true, count: rows.length, items: rows, source: 'ldap', readOnly: true,
        complete: true, limit: null, truncated: false };
    } finally {
      if (client) {
        // Destroy also cancels any timed-out outstanding search; no directory changes occur.
        try { if (typeof client.destroy === 'function') client.destroy(); else closeClient(client); } catch (_) {}
      }
    }
  };
}
function publicError(error) {
  if (error.code === 'RESULT_LIMIT') return { status: 503, message: error.message };
  if (Number(error.code) === 4 || error.name === 'SizeLimitExceededError' || error.name === 'PagedError') return { status: 503, message: 'The directory returned an incomplete lookup. No partial results were shown. Try again.' };
  if (Number(error.code) === 50) return { status: 403, message: 'The current directory account does not have permission to read deleted objects.' };
  if (Number(error.code) === 32 || error.code === 'CONTAINER_UNAVAILABLE') return { status: 503, message: 'The Deleted Objects container is unavailable to the current directory account.' };
  if (error.code === 'UNSUPPORTED_CONTROL') return { status: 503, message: error.message };
  return { status: 503, message: 'Recovery lookup could not read the directory. Check connectivity and the existing account permissions, then try again.' };
}
module.exports = { createRecoveryReader, normalize, publicError, SHOW_DELETED, LDAP_PAGE_SIZE, PAGED_RESULTS, MAX_RECORDS };
