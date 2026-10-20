'use strict';
// Historical geo rows remain available. Current presence uses observations from
// the last 24 hours and retains their source times instead of rollup build time.
const mysql = require('mysql2/promise');
const { evidenceCutoff, failure } = require('./zdx-evidence');
async function refreshPresence(pool, now = new Date()) {
  const cutoff = evidenceCutoff(now), conn = await pool.getConnection();
  let active = false;
  try {
    await conn.beginTransaction(); active = true;
    const bounds = [cutoff.oldest,cutoff.newest];
    const [cities] = await conn.query(`SELECT CONCAT(city,'|',COALESCE(region,'?'),'|',country_code) AS geo_id,
      city AS name,region AS state_name,country_code,AVG(latitude) AS latitude,AVG(longitude) AS longitude,
      COUNT(*) AS device_count,MIN(crawled_at) AS evidence_at FROM zdx_device_geo
      WHERE crawl_status='ok' AND city IS NOT NULL AND country_code IS NOT NULL
        AND latitude IS NOT NULL AND longitude IS NOT NULL AND crawled_at BETWEEN ? AND ?
      GROUP BY city,region,country_code`,bounds);
    const [states] = await conn.query(`SELECT CONCAT('state|',region,'|',country_code) AS geo_id,
      region AS name,region AS state_name,country_code,COUNT(*) AS device_count,MIN(crawled_at) AS evidence_at
      FROM zdx_device_geo WHERE crawl_status='ok' AND region IS NOT NULL AND country_code IS NOT NULL
        AND crawled_at BETWEEN ? AND ? GROUP BY region,country_code`,bounds);
    const [countries] = await conn.query(`SELECT CONCAT('country|',dg.country_code) AS geo_id,
      COALESCE(gc.name,dg.country_code) AS name,dg.country_code,gc.latitude,gc.longitude,
      COUNT(*) AS device_count,MIN(dg.crawled_at) AS evidence_at FROM zdx_device_geo dg
      LEFT JOIN geo_centroids gc ON gc.kind='country' AND gc.code=dg.country_code
      WHERE dg.crawl_status='ok' AND dg.country_code IS NOT NULL AND dg.crawled_at BETWEEN ? AND ?
      GROUP BY dg.country_code,gc.name,gc.latitude,gc.longitude`,bounds);
    if (!countries.length) throw failure('ZDX_NO_EVIDENCE','No recent successful device observations; previous presence retained');
    for (const state of states) {
      const [centroids] = await conn.query("SELECT latitude,longitude FROM geo_centroids WHERE kind='us_state' AND name=?",[state.state_name]);
      if (centroids.length) Object.assign(state,centroids[0]);
    }
    const rows = [];
    for (const [kind,items] of [['city',cities],['state',states],['country',countries]]) {
      for (const row of items) {
        if (!row.evidence_at || !Number.isFinite(new Date(row.evidence_at).getTime())) throw failure('ZDX_TIME','Invalid source timestamp; previous presence retained');
        rows.push([row.geo_id,kind,row.name,null,row.country_code,row.state_name || null,
          row.latitude ?? null,row.longitude ?? null,row.device_count,row.evidence_at]);
      }
    }
    // InnoDB DELETE/INSERT rolls back together. Never silently truncate geography keys.
    await conn.query('DELETE FROM zdx_presence_geo');
    await conn.query('INSERT INTO zdx_presence_geo (geo_id,geo_type,name,parent_geo_id,country_code,state_name,latitude,longitude,device_count,updated_at) VALUES ?',[rows]);
    await conn.commit(); active = false;
    return { cities:cities.length,states:states.length,countries:countries.length,total:rows.length };
  } catch (error) { if (active) await conn.rollback(); throw error; }
  finally { conn.release(); }
}
async function main() {
  require('dotenv').config({path:'/var/www/corpit-hub-api/.env',quiet:true});
  const pool = mysql.createPool({host:process.env.DB_HOST || 'localhost',user:process.env.DB_USER,
    password:process.env.DB_PASSWORD,database:process.env.DB_NAME || 'corpit_hub',connectionLimit:3,timezone:'Z'});
  try { console.log('Presence evidence saved:',JSON.stringify(await refreshPresence(pool))); }
  finally { await pool.end(); }
}
if (require.main === module) main().catch(error => { console.error('ERR:',error.code || 'ZDX_ROLLUP',error.message); process.exitCode = 1; });
module.exports = { refreshPresence, main };
