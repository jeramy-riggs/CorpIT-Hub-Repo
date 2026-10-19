const { ziaAuth, httpsRequest } = require('/var/www/corpit-hub-api/zscaler-lookup');
const HOST = 'https://api.zsapi.net';
async function get(p) {
  const t = await ziaAuth();
  return httpsRequest(new URL(HOST + p), { method: 'GET', headers: { Authorization: 'Bearer ' + t } });
}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (ip.startsWith('127.') || ip === '') return true;
  if (ip.startsWith('169.254.')) return true;
  // 172.16.0.0 - 172.31.255.255
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}
(async () => {
  const now = Math.floor(Date.now()/1000), from = now - 2*3600, W = 'from='+from+'&to='+now;
  const apps = (await get('/zdx/v1/apps?'+W)).body || [];
  const app = Array.isArray(apps) ? apps[0] : (apps.apps||apps.items||[])[0];
  if (!app) { console.log('no apps'); return; }

  const listResp = await get('/zdx/v1/devices?'+W);
  const devs = (listResp.body?.devices || listResp.body?.items || listResp.body || []);
  // Diverse sample: skip Android, pick 10 spread across the list
  const desktops = devs.filter(d => /Mac|Windows|Latitude|MacBook/i.test(d.name||''));
  const sample = [];
  const step = Math.max(1, Math.floor(desktops.length / 10));
  for (let i = 0; i < desktops.length && sample.length < 10; i += step) sample.push(desktops[i]);
  console.log('sampling', sample.length, 'desktops across', devs.length, 'total, app:', app.name);

  const results = [];
  for (const d of sample) {
    try {
      const probesResp = await get('/zdx/v1/devices/'+d.id+'/apps/'+app.id+'/cloudpath-probes?'+W);
      const probes = (probesResp.body?.probes || probesResp.body?.items || probesResp.body || []);
      const p0 = Array.isArray(probes) ? probes[0] : null;
      if (!p0 || p0.id == null) { console.log(d.id, '(NO PROBES)'); results.push({id:d.id,name:d.name,firstPublicIp:null,reason:'no probes'}); await sleep(120); continue; }
      const cpResp = await get('/zdx/v1/devices/'+d.id+'/apps/'+app.id+'/cloudpath-probes/'+p0.id+'/cloudpath?'+W);
      const traces = cpResp.body || [];
      const latest = Array.isArray(traces) ? traces[traces.length-1] : traces;
      const legs = latest?.cloudpath || [];
      const clientLeg = legs.find(l => l.src === 'client' && l.dst === 'zen') || legs[0];
      const hops = clientLeg?.hops || [];
      const firstPublic = hops.find(h => !isPrivateIp(h.ip));
      results.push({
        id: d.id,
        name: d.name.slice(0, 40),
        totalHops: hops.length,
        firstPublicIp: firstPublic?.ip || null,
        firstPublicHopIndex: firstPublic ? hops.indexOf(firstPublic) : -1,
        allIps: hops.map(h => h.ip).filter(Boolean).slice(0, 8)
      });
      await sleep(150);
    } catch(e) { results.push({id:d.id,name:d.name,error:e.message}); }
  }
  console.log('\n=== Results ===');
  for (const r of results) {
    console.log('\ndevice', r.id, '('+r.name+')');
    console.log('  first public IP:', r.firstPublicIp || 'NONE', '@ hop', r.firstPublicHopIndex);
    console.log('  full hop chain:', r.allIps.join(' -> '));
  }
  const withPublic = results.filter(r => r.firstPublicIp).length;
  console.log('\n=== Summary ===');
  console.log('extracted first public IP:', withPublic + '/' + results.length);
})().catch(e => { console.error('ERR:', e.message); process.exit(1); });
