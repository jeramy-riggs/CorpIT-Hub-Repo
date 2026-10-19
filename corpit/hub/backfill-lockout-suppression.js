#!/usr/bin/env node
'use strict';
const mysql = require('mysql2/promise');
const { ipTrustedType } = require('/var/www/corpit-hub-api/signin-watch-lib.js');

const US_COUNTRY_VALUES = new Set(['us', 'usa', 'united states', 'united states of america']);
function isUsCountry(c) { return !!c && US_COUNTRY_VALUES.has(String(c).trim().toLowerCase()); }
const IMPOSSIBLE_TRAVEL_HOURS = parseInt(process.env.SIGNIN_WATCH_IMPOSSIBLE_TRAVEL_HOURS || '4', 10);

async function main() {
  const pool = await mysql.createPool({
    host: process.env.DB_HOST, port: process.env.DB_PORT,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME
  });

  const [nets] = await pool.query('SELECT cidr, type, enabled FROM trusted_networks WHERE enabled = 1');
  const [rows] = await pool.query('SELECT id, upn, ip, country, created_at, raw_json FROM sdops_lockout ORDER BY created_at ASC');
  console.log('[scope]', rows.length, 'total lockout rows to backfill');

  let updated = 0;
  for (const r of rows) {
    let raw;
    try { raw = typeof r.raw_json === 'string' ? JSON.parse(r.raw_json) : r.raw_json; } catch (e) { raw = {}; }
    const isManaged = !!(raw.deviceDetail && raw.deviceDetail.isManaged);
    const riskState = raw.riskState || 'none';

    const trustedType = ipTrustedType(r.ip, nets);
    const isTrustedIp = !!trustedType;
    const us = isUsCountry(r.country);
    const isOutOfCountry = !isTrustedIp && !!r.country && !us;

    let isImpossibleTravel = 0;
    if (!isTrustedIp && r.country && !us) {
      const [prior] = await pool.query(
        'SELECT id FROM sdops_lockout WHERE upn = ? AND country IS NOT NULL AND country != ? AND created_at >= (? - INTERVAL ? HOUR) AND created_at < ? LIMIT 1',
        [r.upn, r.country, r.created_at, IMPOSSIBLE_TRAVEL_HOURS, r.created_at]
      );
      if (prior.length) isImpossibleTravel = 1;
    }

    const hasRisk = riskState && riskState !== 'none';
    const isSuppressed = isTrustedIp
      ? 0
      : (isManaged && us && !isImpossibleTravel && !hasRisk) ? 1 : 0;

    await pool.query(
      'UPDATE sdops_lockout SET is_managed=?, is_trusted_ip=?, is_out_of_country=?, is_impossible_travel=?, risk_state=?, is_suppressed=? WHERE id=?',
      [isManaged ? 1 : 0, isTrustedIp ? 1 : 0, isOutOfCountry ? 1 : 0, isImpossibleTravel, riskState, isSuppressed, r.id]
    );
    updated++;
    if (updated % 200 === 0) console.log('  ...', updated, '/', rows.length);
  }
  console.log('[done] backfilled', updated, 'rows');
  await pool.end();
}

main().catch(e => { console.error('[error]', e.message); process.exit(1); });
