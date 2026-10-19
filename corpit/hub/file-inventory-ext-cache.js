// Small, batch-keyed snapshot for the Storage Explorer file-type strip.
// The crawler writes it from rows successfully inserted into staging; requests
// use it only when its table generation matches the live inventory table.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// data/ is the existing DRBD-backed mount, so a failover keeps this snapshot.
const CACHE_DIR = path.join(__dirname, 'data');

function cacheFile(generation) {
  if (typeof generation !== 'string' ||
      !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(generation)) return null;
  // A separate tiny file per table generation prevents an old in-flight SQL
  // fallback from overwriting the new crawl's snapshot after an atomic swap.
  return path.join(CACHE_DIR, `file-inventory-by-ext-${generation.replace(/\D/g, '')}.json`);
}

function addInsertedRows(totals, rows) {
  for (const row of rows) {
    const ext = row[11]; // file_inventory_staging INSERT column order
    if (!ext) continue;
    const prev = totals.get(ext) || { ext, file_count: 0, total_bytes: 0 };
    prev.file_count += 1;
    prev.total_bytes += Number(row[10]) || 0; // size
    totals.set(ext, prev);
  }
}

function topRows(totals) {
  return [...totals.values()]
    .sort((a, b) => b.total_bytes - a.total_bytes || a.ext.localeCompare(b.ext))
    .slice(0, 12);
}

function read(generation, file = cacheFile(generation)) {
  if (!file) return null;
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data.generation !== generation || !Array.isArray(data.rows)) return null;
    if (!data.rows.every(r => typeof r.ext === 'string' &&
        Number.isFinite(r.file_count) && r.file_count >= 0 &&
        Number.isFinite(r.total_bytes) && r.total_bytes >= 0)) return null;
    return data.rows;
  } catch (_) { return null; } // absent/corrupt cache: the SQL fallback is authoritative
}

async function write(batchId, generation, rows, file = cacheFile(generation)) {
  if (!file) throw new Error('invalid inventory table generation');
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    await fs.promises.writeFile(tmp, JSON.stringify({ batch_id: String(batchId), generation, rows }) + '\n');
    // The crawler may run as root while the API runs as corpit; aggregated
    // extension counts contain no personal data and must be readable by both.
    await fs.promises.chmod(tmp, 0o644);
    await fs.promises.rename(tmp, file);
  } catch (e) {
    await fs.promises.unlink(tmp).catch(() => {});
    throw e;
  }
}

module.exports = { addInsertedRows, topRows, read, write, cacheFile };
