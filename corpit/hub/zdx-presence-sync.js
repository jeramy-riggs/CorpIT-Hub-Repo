// zdx-presence-sync.js — Rebuild zdx_presence_geo from real device attributions in zdx_device_geo.
// Zero ZDX API calls; pure SQL rollup. Runs whenever zdx_device_geo updates (post ISP crawl).

const mysql = require('mysql2/promise');

async function main() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'corpit_hub',
    connectionLimit: 3
  });

  // City-level rollup — use device-attributed city + coords from zdx_device_geo
  const [cityRows] = await pool.query(`
    SELECT
      CONCAT(COALESCE(city,'?'),'|',COALESCE(region,'?'),'|',country_code) AS geo_id,
      city AS name, region AS state_name, country_code,
      AVG(latitude) AS latitude, AVG(longitude) AS longitude,
      COUNT(*) AS device_count
    FROM zdx_device_geo
    WHERE crawl_status='ok' AND city IS NOT NULL AND country_code IS NOT NULL
      AND latitude IS NOT NULL AND longitude IS NOT NULL
    GROUP BY city, region, country_code
  `);

  // State-level rollup
  const [stateRows] = await pool.query(`
    SELECT
      CONCAT('state|',region,'|',country_code) AS geo_id,
      region AS name, region AS state_name, country_code,
      NULL AS latitude, NULL AS longitude,
      COUNT(*) AS device_count
    FROM zdx_device_geo
    WHERE crawl_status='ok' AND region IS NOT NULL AND country_code IS NOT NULL
    GROUP BY region, country_code
  `);

  // Country-level rollup — join geo_centroids for lat/lon
  const [countryRows] = await pool.query(`
    SELECT
      CONCAT('country|',dg.country_code) AS geo_id,
      COALESCE(gc.name, dg.country_code) AS name,
      NULL AS state_name, dg.country_code,
      gc.latitude, gc.longitude,
      COUNT(*) AS device_count
    FROM zdx_device_geo dg
    LEFT JOIN geo_centroids gc ON gc.kind='country' AND gc.code=dg.country_code
    WHERE dg.crawl_status='ok' AND dg.country_code IS NOT NULL
    GROUP BY dg.country_code, gc.name, gc.latitude, gc.longitude
  `);

  // Attach state coords from geo_centroids (US only for now)
  for (const s of stateRows) {
    const [c] = await pool.query(
      "SELECT latitude, longitude FROM geo_centroids WHERE kind='us_state' AND name=?",
      [s.state_name]
    );
    if (c.length) { s.latitude = c[0].latitude; s.longitude = c[0].longitude; }
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('TRUNCATE TABLE zdx_presence_geo');
    const rows = [];
    for (const r of cityRows) rows.push([r.geo_id.slice(0,64), 'city', r.name, null, r.country_code, r.state_name, r.latitude, r.longitude, r.device_count]);
    for (const r of stateRows) rows.push([r.geo_id.slice(0,64), 'state', r.name, null, r.country_code, r.state_name, r.latitude, r.longitude, r.device_count]);
    for (const r of countryRows) rows.push([r.geo_id.slice(0,64), 'country', r.name, null, r.country_code, r.state_name, r.latitude, r.longitude, r.device_count]);
    if (rows.length) {
      await conn.query(
        'INSERT INTO zdx_presence_geo (geo_id, geo_type, name, parent_geo_id, country_code, state_name, latitude, longitude, device_count) VALUES ?',
        [rows]
      );
    }
    await conn.commit();
    console.log('Sync complete: city=' + cityRows.length, 'state=' + stateRows.length, 'country=' + countryRows.length, 'total=' + rows.length);
  } catch (e) { await conn.rollback(); throw e; }
  finally { conn.release(); }
  await pool.end();
}

main().catch(e => { console.error('ERR:', e.message); process.exit(1); });
