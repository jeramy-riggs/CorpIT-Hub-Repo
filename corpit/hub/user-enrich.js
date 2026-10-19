/**
 * user-enrich.js — resolve Meraki client identity from local Intune + Kandji data
 *
 * Input:  array of Meraki client objects (from /networks/:id/clients)
 * Output: same array, with .user field replaced by real user name where resolvable
 *
 * Matching strategy:
 *   - Windows (Meraki.user ends in .NRPI.LOCAL or contains a dot): strip domain,
 *     match against it_inventory.intune_devices.device_name, return primary_user_name.
 *   - Apple/Mac (Meraki.description is 8-14 alphanumeric uppercase): match against
 *     it_inventory.macbooks.serial OR device_name, return user_name.
 *   - Otherwise: leave client.user unchanged.
 *
 * Cache: 5-minute in-memory Map. Keyed by hostname|serial lookup value.
 * Failure: any DB error is logged; original client.user is preserved.
 */

const mysql = require('mysql2/promise');

// Shared pool — same credentials as server.js (it_app has ALL PRIVILEGES on it_inventory)
const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT) || 3306,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  // NOTE: no `database` — we query fully-qualified (`it_inventory.intune_devices`)
  waitForConnections: true,
  connectionLimit:    5,
  charset:            'utf8mb4',
});

// In-memory cache: key → { value: string|null, expires: epochMs }
const CACHE_TTL_MS = 5 * 60 * 1000;
const cache = new Map();

function cacheGet(key) {
  const entry = cache.get(key);
  if (!entry) return undefined;              // miss
  if (entry.expires < Date.now()) {
    cache.delete(key);
    return undefined;                         // expired
  }
  return entry.value;                         // may be null (negative cache)
}

function cacheSet(key, value) {
  cache.set(key, { value, expires: Date.now() + CACHE_TTL_MS });
}

// Periodic cleanup — runs every 5 min, prevents unbounded Map growth
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of cache) if (v.expires < now) cache.delete(k);
}, CACHE_TTL_MS).unref(); // unref so this timer doesn't keep node alive on shutdown

/**
 * Classify a Meraki client and extract its lookup key.
 * Returns { type: 'windows' | 'mac' | null, key: string | null }
 */
function classifyClient(c) {
  const user = (c.user || '').trim();
  const desc = (c.description || '').trim();

  // Windows path: Meraki reports AD hostname via 802.1X machine auth
  // Format we observed: "1YFJN94.NRPI.LOCAL" — contains a dot, ends with LOCAL
  if (user && user.toUpperCase().endsWith('.NRPI.LOCAL')) {
    const hostname = user.split('.')[0].toUpperCase();
    if (hostname.length >= 3) return { type: 'windows', key: hostname };
  }

  // Mac path: Meraki description is the Mac's hostname, which defaults to the serial.
  // Real Kandji serials match /^[A-Z0-9]{8,14}$/ (verified 137/137 on this fleet).
  // Requires uppercase + alphanumeric only so we don't hit UUIDs like "271529af-..."
  if (desc && /^[A-Z0-9]{8,14}$/.test(desc)) {
    return { type: 'mac', key: desc };
  }

  return { type: null, key: null };
}

async function lookupWindows(hostnames) {
  if (hostnames.length === 0) return new Map();
  const placeholders = hostnames.map(() => '?').join(',');
  const sql = `
    SELECT UPPER(device_name) AS key_name, primary_user_upn AS display
    FROM it_inventory.intune_devices
    WHERE device_name IN (${placeholders})
      AND primary_user_upn IS NOT NULL
      AND primary_user_upn <> ''
  `;
  const [rows] = await pool.query(sql, hostnames);
  const map = new Map();
  for (const r of rows) map.set(r.key_name, r.display);
  return map;
}

async function lookupMac(serials) {
  if (serials.length === 0) return new Map();
  const placeholders = serials.map(() => '?').join(',');
  // Match on serial OR device_name (Kandji stores serial in both for many rows)
  const sql = `
    SELECT UPPER(serial) AS key_serial, UPPER(device_name) AS key_devname, user_name AS display
    FROM it_inventory.macbooks
    WHERE (serial IN (${placeholders}) OR device_name IN (${placeholders}))
      AND user_name IS NOT NULL
      AND user_name <> ''
      AND user_name <> '--'
  `;
  // Parameters used twice — once for serial, once for device_name
  const [rows] = await pool.query(sql, [...serials, ...serials]);
  const map = new Map();
  for (const r of rows) {
    if (r.key_serial)  map.set(r.key_serial,  r.display);
    if (r.key_devname) map.set(r.key_devname, r.display);
  }
  return map;
}

/**
 * Enrich a list of Meraki clients in place (also returns the array for chaining).
 * Wraps ALL DB work in try/catch: if anything errors, original data is returned unchanged.
 */
async function enrichClients(clients) {
  if (!Array.isArray(clients) || clients.length === 0) return clients;

  // Step 1: classify and separate into lookup buckets
  const windowsKeys = new Set();
  const macKeys     = new Set();
  const clientMeta  = []; // parallel array: { index, type, key }

  clients.forEach((c, i) => {
    const { type, key } = classifyClient(c);
    clientMeta.push({ index: i, type, key });
    if (type === 'windows') windowsKeys.add(key);
    else if (type === 'mac') macKeys.add(key);
  });

  // Step 2: check cache, collect remaining keys to query
  const resolved = new Map(); // fullKey → userName (null means "definitively unknown")
  const toQueryWin = [];
  const toQueryMac = [];

  for (const k of windowsKeys) {
    const cached = cacheGet(`win|${k}`);
    if (cached !== undefined) resolved.set(`win|${k}`, cached);
    else toQueryWin.push(k);
  }
  for (const k of macKeys) {
    const cached = cacheGet(`mac|${k}`);
    if (cached !== undefined) resolved.set(`mac|${k}`, cached);
    else toQueryMac.push(k);
  }

  // Step 3: query DB for uncached keys (both in parallel)
  try {
    const [winResults, macResults] = await Promise.all([
      lookupWindows(toQueryWin),
      lookupMac(toQueryMac),
    ]);

    // Populate resolved map + cache (including negative cache for misses)
    for (const k of toQueryWin) {
      const name = winResults.get(k) || null;
      resolved.set(`win|${k}`, name);
      cacheSet(`win|${k}`, name);
    }
    for (const k of toQueryMac) {
      const name = macResults.get(k) || null;
      resolved.set(`mac|${k}`, name);
      cacheSet(`mac|${k}`, name);
    }
  } catch (err) {
    console.error('[user-enrich] DB lookup failed, returning clients unenriched:', err.message);
    return clients;
  }

  // Step 4: overwrite client.user where we found a real name
  for (const meta of clientMeta) {
    if (!meta.type || !meta.key) continue;
    const fullKey = `${meta.type === 'windows' ? 'win' : 'mac'}|${meta.key}`;
    const name = resolved.get(fullKey);
    if (name) clients[meta.index].user = name;
  }

  return clients;
}

module.exports = { enrichClients };
