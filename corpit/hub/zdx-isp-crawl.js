// zdx-isp-crawl.js — Nightly ZDX cloudpath crawl → first public hop → ip-api.com lookup → cache
// Runs at 03:00 via cron. Read-only to ZDX; writes to zdx_ip_geo, zdx_device_geo, zdx_user_isp.

const mysql = require('mysql2/promise');
const http = require('http');
const { ziaAuth, httpsRequest } = require('/var/www/corpit-hub-api/zscaler-lookup');
const HOST = 'https://api.zsapi.net';
const IP_API_HOST = 'ip-api.com';
const IP_API_FIELDS = 'status,country,countryCode,regionName,city,lat,lon,isp,org,as,query';

async function zget(p) {
  const t = await ziaAuth();
  return httpsRequest(new URL(HOST + p), { method: 'GET', headers: { Authorization: 'Bearer ' + t } });
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (ip.startsWith('127.') || ip === '') return true;
  if (ip.startsWith('169.254.')) return true;
  if (ip.startsWith('192.0.0.')) return true;
  if (ip.startsWith('172.')) {
    const s = parseInt(ip.split('.')[1], 10);
    if (s >= 16 && s <= 31) return true;
  }
  if (ip.startsWith('100.')) {
    const s = parseInt(ip.split('.')[1], 10);
    if (s >= 64 && s <= 127) return true; // CGNAT
  }
  return false;
}

function ipApiLookup(ip) {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { hostname: IP_API_HOST, path: '/json/' + encodeURIComponent(ip) + '?fields=' + IP_API_FIELDS, timeout: 10000 },
      res => {
        let buf = '';
        res.on('data', c => buf += c);
        res.on('end', () => {
          try { resolve(JSON.parse(buf)); } catch (e) { reject(e); }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

async function getOrLookupIp(pool, ip) {
  const [cached] = await pool.query(
    'SELECT * FROM zdx_ip_geo WHERE ip=? AND cached_at > NOW() - INTERVAL 30 DAY', [ip]
  );
  if (cached.length) return cached[0];
  await sleep(1500);
  try {
    const r = await ipApiLookup(ip);
    if (r.status !== 'success') throw new Error(r.message || 'ip-api fail');
    const asnMatch = (r.as || '').match(/^(AS\d+)/);
    const asn = asnMatch ? asnMatch[1] : null;
    const isZ = /zscaler/i.test(r.isp || '') || /zscaler/i.test(r.org || '');
    const row = {
      ip, country_code: r.countryCode || null, country_name: r.country || null,
      region: r.regionName || null, city: r.city || null,
      latitude: r.lat || null, longitude: r.lon || null,
      isp: r.isp || null, org: r.org || null, asn,
      is_zscaler: isZ ? 1 : 0, lookup_status: 'ok'
    };
    await pool.query(
      'REPLACE INTO zdx_ip_geo (ip,country_code,country_name,region,city,latitude,longitude,isp,org,asn,is_zscaler,lookup_status,cached_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW())',
      [row.ip,row.country_code,row.country_name,row.region,row.city,row.latitude,row.longitude,row.isp,row.org,row.asn,row.is_zscaler,row.lookup_status]
    );
    return row;
  } catch (e) {
    console.warn('IP lookup failed', ip, e.message);
    await pool.query(
      'REPLACE INTO zdx_ip_geo (ip,lookup_status,cached_at) VALUES (?,?,NOW())',
      [ip, 'fail']
    );
    return { ip, lookup_status: 'fail' };
  }
}

async function crawlDeviceForPublicIp(device, apps, W) {
  for (const app of apps) {
    try {
      const pr = await zget('/zdx/v1/devices/' + device.id + '/apps/' + app.id + '/cloudpath-probes?' + W);
      const probes = (pr.body?.probes || pr.body?.items || pr.body || []);
      const p0 = Array.isArray(probes) ? probes[0] : null;
      if (!p0 || p0.id == null) { await sleep(120); continue; }
      const cp = await zget('/zdx/v1/devices/' + device.id + '/apps/' + app.id + '/cloudpath-probes/' + p0.id + '/cloudpath?' + W);
      const traces = cp.body || [];
      const latest = Array.isArray(traces) ? traces[traces.length - 1] : traces;
      const legs = latest?.cloudpath || [];
      const clientLeg = legs.find(l => l.src === 'client' && l.dst === 'zen') || legs[0];
      const hops = clientLeg?.hops || [];
      const firstPublic = hops.find(h => !isPrivateIp(h.ip));
      await sleep(120);
      if (firstPublic && firstPublic.ip) return { ip: firstPublic.ip, appName: app.name };
    } catch (e) { /* try next app */ }
  }
  return null;
}

async function main() {
  const args = process.argv.slice(2);
  const limitFlag = args.find(a => a.startsWith('--limit='));
  const LIMIT = limitFlag ? parseInt(limitFlag.split('=')[1], 10) : 0;

  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'corpit_hub',
    connectionLimit: 4
  });

  const now = Math.floor(Date.now() / 1000), from = now - 2 * 3600;
  const W = 'from=' + from + '&to=' + now;

  console.log('fetching apps + devices...');
  const appsR = await zget('/zdx/v1/apps?' + W);
  const apps = Array.isArray(appsR.body) ? appsR.body : (appsR.body?.apps || []);
  const devR = await zget('/zdx/v1/devices?' + W);
  let devs = devR.body?.devices || devR.body?.items || devR.body || [];
  devs = devs.filter(d => /Mac|Windows|Latitude|MacBook|Precision|OptiPlex|ThinkPad/i.test(d.name || ''));
  if (LIMIT > 0) devs = devs.slice(0, LIMIT);
  console.log('crawling', devs.length, 'desktops using', apps.length, 'apps');

  let ok = 0, noPub = 0, err = 0;
  for (let i = 0; i < devs.length; i++) {
    const d = devs[i];
    try {
      const result = await crawlDeviceForPublicIp(d, apps, W);
      if (!result) {
        await pool.query(
          'REPLACE INTO zdx_device_geo (device_id,userid,device_name,crawl_status,crawled_at) VALUES (?,?,?,?,NOW())',
          [d.id, d.userid || null, (d.name || '').slice(0, 254), 'no_public_hop']
        );
        noPub++;
        if ((i+1) % 20 === 0) console.log('  progress', (i+1) + '/' + devs.length, 'ok=' + ok, 'no_pub=' + noPub, 'err=' + err);
        continue;
      }
      const geo = await getOrLookupIp(pool, result.ip);
      await pool.query(
        'REPLACE INTO zdx_device_geo (device_id,userid,device_name,first_public_ip,city,region,country_code,latitude,longitude,isp,asn,crawl_status,crawled_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW())',
        [d.id, d.userid || null, (d.name || '').slice(0, 254), result.ip,
         geo.city || null, geo.region || null, geo.country_code || null,
         geo.latitude || null, geo.longitude || null,
         geo.isp || null, geo.asn || null,
         geo.lookup_status === 'ok' ? 'ok' : 'error']
      );
      ok++;
    } catch (e) {
      console.warn('device', d.id, 'error:', e.message);
      err++;
    }
    if ((i+1) % 20 === 0) console.log('  progress', (i+1) + '/' + devs.length, 'ok=' + ok, 'no_pub=' + noPub, 'err=' + err);
  }

  console.log('rolling up per-user ISPs...');
  await pool.query('DELETE FROM zdx_user_isp');
  await pool.query(
    `INSERT INTO zdx_user_isp (userid, home_isp, home_city, home_country, device_count, updated_at)
     SELECT userid,
       SUBSTRING_INDEX(GROUP_CONCAT(isp ORDER BY isp), ',', 1) AS home_isp,
       SUBSTRING_INDEX(GROUP_CONCAT(city ORDER BY city), ',', 1) AS home_city,
       SUBSTRING_INDEX(GROUP_CONCAT(country_code ORDER BY country_code), ',', 1),
       COUNT(*), NOW()
     FROM zdx_device_geo
     WHERE userid IS NOT NULL AND isp IS NOT NULL AND crawl_status='ok'
     GROUP BY userid`
  );

  console.log('DONE. ok=' + ok, 'no_public_hop=' + noPub, 'error=' + err);
  await pool.end();
}

main().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
