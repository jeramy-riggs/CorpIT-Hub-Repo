#!/usr/bin/env node
/*
 * version-crawl-job.js — SharePoint file version-history storage crawler (Phase B)
 *
 * Walks file_inventory (size DESC), for each file with item_id+drive_id calls
 * Graph /drives/{driveId}/items/{itemId}/versions via $batch (20/req), computes
 * extra storage consumed by non-current versions, and upserts into file_versions.
 *
 * Checkpointed via file_versions.checked_at (resumable). Re-checks rows older
 * than RECHECK_DAYS. Hard-stops before the 16:00 stale-crawl cron.
 *
 * Launch (detached, survives SSH drop + PM2 restart):
 *   cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) \
 *     setsid nohup /usr/bin/node --max-old-space-size=1024 version-crawl-job.js \
 *     >> /home/ubuntu/version-crawl.log 2>&1 < /dev/null &
 *   disown
 */

const mysql = require('mysql2/promise');

// ── Config ──────────────────────────────────────────────────────────────────
const GRAPH = 'https://graph.microsoft.com/v1.0';
const BATCH_SIZE = 20;            // Graph $batch hard max
const SELECT_CHUNK = 500;         // rows pulled from DB per loop
const RECHECK_DAYS = 7;
const INTER_BATCH_MS = 150;       // gentle pacing between batches
const HARD_STOP_UTC_HOUR = 15;    // stop at 15:30 UTC (before 16:00 stale-crawl)
const HARD_STOP_UTC_MIN = 30;
const TOKEN_URL = tid => `https://login.microsoftonline.com/${tid}/oauth2/v2.0/token`;

const {
  SP_TENANT_ID, SP_CLIENT_ID, SP_CLIENT_SECRET,
  DB_USER, DB_PASSWORD, DB_NAME = 'corpit_hub'
} = process.env;

if (!SP_TENANT_ID || !SP_CLIENT_ID || !SP_CLIENT_SECRET) {
  console.error('[VER] missing SP_* env vars'); process.exit(1);
}

// ── Token (client credentials, auto-refresh) ─────────────────────────────────
let _tok = null, _tokExp = 0;
async function token() {
  if (_tok && Date.now() < _tokExp - 60000) return _tok;
  const body = new URLSearchParams({
    client_id: SP_CLIENT_ID, client_secret: SP_CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials'
  });
  const r = await fetch(TOKEN_URL(SP_TENANT_ID), { method: 'POST', body });
  if (!r.ok) throw new Error(`token ${r.status}: ${await r.text()}`);
  const j = await r.json();
  _tok = j.access_token; _tokExp = Date.now() + (j.expires_in * 1000);
  return _tok;
}

// ── Hard stop check ──────────────────────────────────────────────────────────
function pastHardStop() {
  const now = new Date();
  const h = now.getUTCHours(), m = now.getUTCMinutes();
  return h > HARD_STOP_UTC_HOUR || (h === HARD_STOP_UTC_HOUR && m >= HARD_STOP_UTC_MIN);
}

// ── Graph $batch for a chunk of files ────────────────────────────────────────
async function fetchVersionsBatch(files) {
  const tk = await token();
  const requests = files.map((f, i) => ({
    id: String(i),
    method: 'GET',
    // $select keeps payload small; size is what we need
    url: `/drives/${f.drive_id}/items/${f.item_id}/versions?$select=id,size`
  }));
  const r = await fetch(`${GRAPH}/$batch`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${tk}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests })
  });
  if (r.status === 429) {
    const ra = parseInt(r.headers.get('retry-after') || '10', 10);
    console.log(`[VER] 429 on $batch, sleeping ${ra}s`);
    await sleep(ra * 1000);
    return fetchVersionsBatch(files); // retry same chunk
  }
  if (!r.ok) throw new Error(`$batch ${r.status}: ${(await r.text()).slice(0, 300)}`);
  const j = await r.json();
  const out = new Map(); // index -> {count, extraBytes, currentSize}
  for (const resp of (j.responses || [])) {
    const idx = parseInt(resp.id, 10);
    const f = files[idx];
    if (resp.status === 429) { out.set(idx, { retry: true }); continue; }
    if (resp.status >= 400) { out.set(idx, { count: null, extraBytes: null, err: resp.status }); continue; }
    const versions = (resp.body && resp.body.value) || [];
    const count = versions.length;
    // extra = sum(all version sizes) - current file size; current file size is f.size
    const sumAll = versions.reduce((s, v) => s + (Number(v.size) || 0), 0);
    const extra = Math.max(0, sumAll - Number(f.size || 0));
    out.set(idx, { count, extraBytes: extra });
  }
  return out;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── Main ─────────────────────────────────────────────────────────────────────
(async () => {
  const pool = await mysql.createPool({
    host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
    user: DB_USER, password: DB_PASSWORD, database: DB_NAME,
    waitForConnections: true, connectionLimit: 4
  });

  let totalChecked = 0, totalWithHistory = 0, totalExtraBytes = 0, errCount = 0;
  const startedAt = new Date();
  console.log(`[VER] ${startedAt.toISOString()} version-crawl starting (recheck>${RECHECK_DAYS}d, hardstop ${HARD_STOP_UTC_HOUR}:${HARD_STOP_UTC_MIN} UTC)`);

  try {
    while (true) {
      if (pastHardStop()) { console.log('[VER] hard stop reached, exiting cleanly'); break; }

      // Pull next chunk: largest files, with graph ids, not-yet-checked or stale
      const [rows] = await pool.query(
        `SELECT fi.item_id, fi.drive_id, fi.size
           FROM file_inventory fi
           LEFT JOIN file_versions fv ON fv.item_id = fi.item_id
          WHERE fi.item_id IS NOT NULL AND fi.drive_id IS NOT NULL AND fi.size > 0
            AND (fv.checked_at IS NULL OR fv.checked_at < (NOW() - INTERVAL ? DAY))
          ORDER BY fi.size DESC
          LIMIT ?`, [RECHECK_DAYS, SELECT_CHUNK]);

      if (!rows.length) { console.log('[VER] no more files to check — fill complete'); break; }

      // De-dup by item_id within chunk (same file can appear once; defensive)
      const seen = new Set();
      const files = rows.filter(r => { if (seen.has(r.item_id)) return false; seen.add(r.item_id); return true; });

      for (let i = 0; i < files.length; i += BATCH_SIZE) {
        if (pastHardStop()) { console.log('[VER] hard stop mid-chunk, exiting'); await pool.end(); process.exit(0); }
        const slice = files.slice(i, i + BATCH_SIZE);
        let results;
        try {
          results = await fetchVersionsBatch(slice);
        } catch (e) {
          console.log(`[VER] batch error: ${e.message}`);
          errCount += slice.length;
          await sleep(2000);
          continue;
        }

        // Build upsert rows
        const upserts = [];
        for (let k = 0; k < slice.length; k++) {
          const f = slice[k];
          const res = results.get(k);
          if (!res || res.retry) continue; // skip; will re-select next pass
          if (res.count === null) { errCount++; continue; }
          totalChecked++;
          if (res.count > 1) { totalWithHistory++; totalExtraBytes += res.extraBytes; }
          // Skip-but-mark: even 1-version files get checked_at set so we don't re-hit them
          upserts.push([f.item_id, f.drive_id, res.count, res.extraBytes, new Date()]);
        }

        if (upserts.length) {
          await pool.query(
            `INSERT INTO file_versions (item_id, drive_id, version_count, version_bytes, checked_at)
             VALUES ? ON DUPLICATE KEY UPDATE
               drive_id=VALUES(drive_id), version_count=VALUES(version_count),
               version_bytes=VALUES(version_bytes), checked_at=VALUES(checked_at)`, [upserts]);
        }

        if (totalChecked % 1000 < BATCH_SIZE) {
          console.log(`[VER] checked ${totalChecked}, w/history ${totalWithHistory}, extra ${(totalExtraBytes/1073741824).toFixed(1)}GB, err ${errCount}`);
        }
        await sleep(INTER_BATCH_MS);
      }
    }
  } catch (e) {
    console.log(`[VER] FATAL: ${e.message}`);
  } finally {
    console.log(`[VER] DONE — checked ${totalChecked}, w/history ${totalWithHistory}, total extra ${(totalExtraBytes/1073741824).toFixed(1)}GB, errors ${errCount}, elapsed ${Math.round((Date.now()-startedAt)/1000)}s`);
    await pool.end();
  }
})();
