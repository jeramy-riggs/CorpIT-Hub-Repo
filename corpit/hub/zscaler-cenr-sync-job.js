'use strict';
// ZSCALER-CENR-SYNC v1.0 — keeps trusted_networks 'zscaler' rows in step with
// Zscaler's published CENR list for zscalertwo.net.
// Marker: SIGNIN-WATCH-CENR-SYNC
// Safe: only touches rows with note='CENR auto-import'. Manual rows untouched.
// New ranges -> inserted enabled. Ranges gone from CENR -> disabled (not deleted,
// so history and any violation context survive; re-appearing ranges re-enable).
// Run via cron (root, like other jobs) — see install notes.
require('dotenv').config();
const mysql = require('mysql2/promise');

const CENR_URL = 'https://config.zscaler.com/api/zscalertwo.net/cenr/json';
const MARK = 'CENR auto-import';

(async () => {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  });
  const log = (...a) => console.log(new Date().toISOString(), '[cenr-sync]', ...a);

  const r = await fetch(CENR_URL, { signal: AbortSignal.timeout(30000) });
  if (r.status !== 200) throw new Error('CENR HTTP ' + r.status);
  const j = await r.json();
  const cloud = j['zscalertwo.net'] || {};
  const live = new Map();   // range -> city
  for (const contKey of Object.keys(cloud)) {
    for (const cityKey of Object.keys(cloud[contKey])) {
      const city = cityKey.replace(/^city\s*:\s*/, '');
      for (const e of cloud[contKey][cityKey]) {
        const range = (e.range || '').trim();
        if (range && !live.has(range)) live.set(range, city);
      }
    }
  }
  if (live.size < 100) throw new Error(`CENR sanity check failed: only ${live.size} ranges — refusing to sync`);
  log(`CENR live ranges: ${live.size}`);

  const [rows] = await pool.query(
    `SELECT id, cidr, enabled FROM trusted_networks WHERE type = 'zscaler' AND note = ?`, [MARK]);
  const db = new Map(rows.map(x => [x.cidr, x]));

  let added = 0, reEnabled = 0, disabled = 0;
  for (const [range, city] of live) {
    const ex = db.get(range);
    if (!ex) {
      await pool.query(
        `INSERT IGNORE INTO trusted_networks (label, cidr, type, note, created_by, enabled)
         VALUES (?, ?, 'zscaler', ?, 'cenr-sync', 1)`,
        [('ZS ' + city).slice(0, 120), range, MARK]);
      added++;
    } else if (!ex.enabled) {
      await pool.query(`UPDATE trusted_networks SET enabled = 1 WHERE id = ?`, [ex.id]);
      reEnabled++;
    }
  }
  for (const [cidr, ex] of db) {
    if (!live.has(cidr) && ex.enabled) {
      await pool.query(`UPDATE trusted_networks SET enabled = 0 WHERE id = ?`, [ex.id]);
      disabled++;
    }
  }
  log(`added=${added} re-enabled=${reEnabled} disabled=${disabled}`);

  await pool.query(
    `INSERT INTO signin_watch_state (key_name, key_value) VALUES ('cenr_last_sync', ?)
     ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)`,
    [JSON.stringify({ at: new Date().toISOString(), live: live.size, added, reEnabled, disabled })]);
  await pool.end();
})().catch(e => { console.error('[cenr-sync] FAILED:', e.message); process.exit(1); });
