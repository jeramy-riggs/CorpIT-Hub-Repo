// zdx-isp-crawl.js — Nightly ZDX cloudpath crawl → first public hop → ip-api.com lookup → cache
// Runs at 03:00 via cron. Read-only to ZDX; writes to zdx_ip_geo, zdx_device_geo, zdx_user_isp.

'use strict';
const mysql = require('mysql2/promise');
const { failure,readList,fetchList,evidenceCutoff,replaceUserIsp } = require('./zdx-evidence');
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
  return new Promise((resolve,reject)=>{
    let timer;
    const finish=(error,result)=>{clearTimeout(timer);error ? reject(error) : resolve(result);};
    const req=http.get({hostname:IP_API_HOST,path:'/json/'+encodeURIComponent(ip)+'?fields='+IP_API_FIELDS},res=>{
      let buf='';
      if(res.statusCode!==200){res.resume();return finish(failure('ZDX_GEO','Geolocation read unavailable'));}
      res.on('data',chunk=>{buf+=chunk;if(buf.length>65536)req.destroy(failure('ZDX_GEO','Geolocation response exceeded limit'));});
      res.on('error',error=>finish(error));
      res.on('end',()=>{try{finish(null,JSON.parse(buf));}catch(error){finish(error);}});
    });
    timer=setTimeout(()=>req.destroy(failure('ZDX_GEO','Geolocation read timed out')),10000);
    req.on('error',error=>finish(error));
  });
}

async function getOrLookupIp(pool, ip) {
  const [cached] = await pool.query('SELECT * FROM zdx_ip_geo WHERE ip=? AND cached_at > UTC_TIMESTAMP() - INTERVAL 30 DAY AND lookup_status=\'ok\'',[ip]);
  if (cached.length) return { row:cached[0],cached:true };
  await sleep(1500);
  let result;
  try { result = await ipApiLookup(ip); }
  catch { throw failure('ZDX_GEO','Geolocation read failed; previous evidence retained'); }
  if (result.status !== 'success' || !Number.isFinite(result.lat) || !Number.isFinite(result.lon)) throw failure('ZDX_GEO','Geolocation returned invalid data; previous evidence retained');
  const asn = (result.as || '').match(/^(AS\d+)/);
  return { cached:false,row:{ip,country_code:result.countryCode || null,country_name:result.country || null,
    region:result.regionName || null,city:result.city || null,latitude:result.lat,longitude:result.lon,
    isp:result.isp || null,org:result.org || null,asn:asn ? asn[1] : null,
    is_zscaler:/zscaler/i.test((result.isp || '')+' '+(result.org || '')) ? 1 : 0,lookup_status:'ok'} };
}

async function crawlDeviceForPublicIp(device, apps, window, get = zget) {
  for (const app of apps) {
    const probes = readList(await get('/zdx/v1/devices/'+encodeURIComponent(device.id)+'/apps/'+encodeURIComponent(app.id)+'/cloudpath-probes?'+window),['probes','items'],'ZDX cloudpath probes');
    if (!probes.length) continue;
    const probe = probes[0];
    if (probe.id == null) throw failure('ZDX_SHAPE','Cloudpath probe has no ID; previous evidence retained');
    const traceResponse = await get('/zdx/v1/devices/'+encodeURIComponent(device.id)+'/apps/'+encodeURIComponent(app.id)+'/cloudpath-probes/'+encodeURIComponent(probe.id)+'/cloudpath?'+window);
    if (traceResponse && traceResponse.body && !Array.isArray(traceResponse.body) && Array.isArray(traceResponse.body.cloudpath)) traceResponse.body = [traceResponse.body];
    const traces = readList(traceResponse,['items','traces'],'ZDX cloudpath');
    if (!traces.length) continue;
    const latest = traces[traces.length-1];
    if (!Array.isArray(latest.cloudpath) || latest.cloudpath.some(x=>!x || typeof x!=='object')) throw failure('ZDX_SHAPE','Cloudpath legs are invalid; previous evidence retained');
    const leg = latest.cloudpath.find(x=>x.src==='client' && x.dst==='zen') || latest.cloudpath[0];
    if (!leg) continue;
    if (!Array.isArray(leg.hops) || leg.hops.some(x=>!x || typeof x!=='object')) throw failure('ZDX_SHAPE','Cloudpath hops are invalid; previous evidence retained');
    const first = leg.hops.find(h=>typeof h.ip==='string' && !isPrivateIp(h.ip));
    await sleep(120);
    if (first) return {ip:first.ip,appName:app.name};
  }
  return null;
}

async function collect({pool,get=zget,lookup=getOrLookupIp,crawl=crawlDeviceForPublicIp,now=new Date(),dryRun=false,limit=0} = {}) {
  const cutoff = evidenceCutoff(now), observedAt = cutoff.newest;
  const end = Math.floor(observedAt.getTime()/1000), window='from='+(end-7200)+'&to='+end;
  const apps = await fetchList(get,'/zdx/v1/apps?'+window,['apps','items']);
  const devices = await fetchList(get,'/zdx/v1/devices?'+window,['devices','items']);
  if (apps.some(x=>x.id==null) || devices.some(x=>x.id==null)) throw failure('ZDX_SHAPE','ZDX application/device has no ID; previous evidence retained');
  const unique = new Map();
  for (const device of devices) {
    const id=String(device.id);
    if (unique.has(id)) throw failure('ZDX_PARTIAL','Duplicate device across ZDX pages; previous evidence retained');
    unique.set(id,device);
  }
  let desktops = Array.from(unique.values()).filter(d=>/Mac|Windows|Latitude|MacBook|Precision|OptiPlex|ThinkPad/i.test(d.name || ''));
  if (limit && !dryRun) throw failure('ZDX_PARTIAL','Limited collection cannot publish a complete rollup; use --dry-run');
  if (limit) desktops=desktops.slice(0,limit);
  if (dryRun) return {dryRun:true,apps:apps.length,desktops:desktops.length,databaseWrites:0};
  if (!apps.length || !desktops.length) throw failure('ZDX_NO_EVIDENCE','No current apps/desktops to collect; previous evidence retained');
  const geoRows=[],ipRows=new Map();
  for (const device of desktops) {
    // Any denied, malformed or failed sub-read aborts the whole publication.
    const result=await crawl(device,apps,window,get);
    if (!result) continue; // No new positive attribution: retain prior evidence/date.
    const geo=await lookup(pool,result.ip), row=geo.row;
    if (!row || row.lookup_status!=='ok' || !row.country_code || !row.isp) throw failure('ZDX_GEO','Incomplete geolocation evidence; previous evidence retained');
    if (!geo.cached) ipRows.set(result.ip,row);
    geoRows.push([device.id,device.userid || null,(device.name || '').slice(0,254),result.ip,
      row.city || null,row.region || null,row.country_code,row.latitude ?? null,row.longitude ?? null,
      row.isp,row.asn || null,'ok',observedAt]);
  }
  if (!geoRows.length) throw failure('ZDX_NO_EVIDENCE','No successful current geo observations; previous evidence retained');
  const conn=await pool.getConnection(); let active=false;
  try {
    await conn.beginTransaction(); active=true;
    for (const row of ipRows.values()) await conn.query(
      'REPLACE INTO zdx_ip_geo (ip,country_code,country_name,region,city,latitude,longitude,isp,org,asn,is_zscaler,lookup_status,cached_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [row.ip,row.country_code,row.country_name,row.region,row.city,row.latitude,row.longitude,row.isp,row.org,row.asn,row.is_zscaler,row.lookup_status,observedAt]);
    for (const row of geoRows) await conn.query(
      'REPLACE INTO zdx_device_geo (device_id,userid,device_name,first_public_ip,city,region,country_code,latitude,longitude,isp,asn,crawl_status,crawled_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',row);
    await replaceUserIsp(conn,cutoff);
    await conn.commit(); active=false;
    return {observedDevices:geoRows.length,eligibleDevices:desktops.length,unresolvedDevices:desktops.length-geoRows.length,evidenceAt:observedAt.toISOString()};
  } catch(error) { if(active) await conn.rollback(); throw error; }
  finally { conn.release(); }
}

async function main() {
  require('dotenv').config({path:'/var/www/corpit-hub-api/.env',quiet:true});
  const args=process.argv.slice(2), limited=args.find(x=>x.startsWith('--limit='));
  const limit=limited ? Number(limited.split('=')[1]) : 0;
  if (!Number.isInteger(limit) || limit<0) throw failure('ZDX_ARGS','--limit must be a non-negative integer');
  const dryRun=args.includes('--dry-run') || args.includes('--check-access');
  // No database connection or geolocation read in preflight mode.
  let pool;
  try {
    if(!dryRun) pool=mysql.createPool({host:process.env.DB_HOST || 'localhost',user:process.env.DB_USER,
      password:process.env.DB_PASSWORD,database:process.env.DB_NAME || 'corpit_hub',connectionLimit:4,timezone:'Z'});
    console.log('ZDX collection:',JSON.stringify(await collect({pool,dryRun,limit})));
  } finally { if(pool) await pool.end(); }
}
if(require.main===module) main().catch(error=>{console.error('FATAL:',error.code || 'ZDX_COLLECTION',error.code ? error.message : 'Collection failed; previous evidence retained');process.exitCode=1;});
module.exports={collect,crawlDeviceForPublicIp,getOrLookupIp,main};
