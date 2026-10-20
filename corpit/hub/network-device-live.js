'use strict';
// Bounded read-only providers. No user lookup, DNS fallback or vendor mutation.
const {execFile}=require('child_process');
const path=require('path');
const {macAddress}=require('./identity-device-network');
const stamp=v=>{const d=new Date(typeof v==='number'?v*1000:v);return v!=null && Number.isFinite(d.getTime())?d.toISOString():null;};
const section=(status,records=[],reason='')=>({status,records,reason});
function runJson(script,args,timeout=40000,exec=execFile){
  return new Promise(resolve=>exec('python3',[path.join(__dirname,script),...args],{timeout,maxBuffer:1024*1024,env:process.env},(err,out)=>{
    if(err)return resolve({status:'unavailable',reason:err.killed?'The read timed out.':'The read could not complete.'});
    try{resolve(JSON.parse(out));}catch(_){resolve({status:'unavailable',reason:'The provider returned an invalid response.'});}
  }));
}
function hostMatch(actual,wanted){const a=String(actual||'').toLowerCase().replace(/\.$/,''),w=String(wanted||'').toLowerCase().replace(/\.$/,'');return w.includes('.')?a===w:a.split('.')[0]===w;}
async function dhcp(query,{run=runJson,timeoutMs=23000}={}){
  const sources=await Promise.all(['10.20.10.52','10.9.65.56'].map(async server=>{
    const data=await run('dhcp-lookup.py',['--exact',query.mac?'--mac':'--device',query.mac||query.hostname,'--server',server],Math.max(1,Math.min(23000,timeoutMs)));
    if(data.status!=='ok' || !Array.isArray(data.leases))return {server,status:'unavailable',records:[],code:data.code||null,reason:'Exact DHCP read unavailable'+(data.code?' ('+data.code+')':'')+'; this is not a no-lease result.'};
    const valid=data.leases.filter(r=>['Active','ActiveReservation'].includes(r.state) && (query.mac?macAddress(r.mac)===query.mac:hostMatch(r.hostname,query.hostname)));
    const invalid=data.leases.length!==valid.length;
    return {server,status:invalid || valid.length>100?'partial':valid.length?'ok':'empty',records:valid.slice(0,100).map(r=>({ip:r.ip,mac:macAddress(r.mac),hostname:r.hostname,scope:r.scope,state:r.state,expiresAt:stamp(r.expiresAt),server})),reason:invalid?'Mismatched or inactive rows were withheld.':valid.length>100?'Results capped at 100 per DHCP server.':''};
  }));
  const records=sources.flatMap(s=>s.records),failed=sources.some(s=>s.status==='unavailable'||s.status==='partial');
  return {...section(failed?(records.length?'partial':sources.every(s=>s.status==='unavailable')?'unavailable':'partial'):records.length?'ok':'empty',records),sources,
    basis:query.mac?'Exact selected MAC':'Exact selected inventory hostname; a hostname lease alone does not prove hardware identity',
    reason:'All returned exact active matches remain visible. Failover duplicates and conflicting leases are not resolved by choosing the first result.'};
}
function measurementEvidence(value,fields){
  const sampleCount=value.records.length,measurementCount=value.records.filter(row=>fields.some(key=>typeof row[key]==='number' && Number.isFinite(row[key]))).length;
  return {...value,sampleCount,measurementCount,coverageStatus:value.status,
    status:measurementCount?value.status:'no_measurements',
    reason:value.reason+(measurementCount?'':' No measurements in the returned samples.')};
}
async function meraki(mac,{get,config,now=Date.now()}={}){
  const api=config||require('./meraki-lookup'),transport=get||api.merakiGet,deadline=Date.now()+35000;
  get=(p)=>{const remaining=deadline-Date.now();if(remaining<=0)throw Error('Meraki deadline');return transport(p,{timeoutMs:Math.min(10000,remaining)});};
  let search;try{search=await get('/organizations/'+api.ORG_ID+'/clients/search?mac='+encodeURIComponent(mac)+'&perPage=5');}catch(_){return section('unavailable',[],'Meraki search unavailable.');}
  if(search.status===204)return section('empty',[],'No Meraki record returned. This does not establish offline state.');
  const body=search.body;
  if(search.status!==200 || !body || !Array.isArray(body.records))return section('unavailable',[],'Meraki search HTTP '+search.status+' failed or returned an invalid shape.');
  if(macAddress(body.mac)!==mac)return section('unavailable',[],'Meraki did not verify the exact selected MAC; response withheld.');
  const allowed=new Map(Object.values(api.NETWORKS).map(n=>[n.id,n]));
  const networks=[...new Set(body.records.map(r=>r.network?.id).filter(Boolean))],records=[];
  let partial=!!search.hasMore || networks.length>4;
  for(const id of networks.slice(0,4)){
    if(!allowed.has(id)){partial=true;records.push({networkId:id,status:'not_supported',reason:'Network is outside the configured site list.'});continue;}
    const n=allowed.get(id),r={networkId:id,site:n.name,status:'ok',client:null,events:section('not_included'),signal:section('not_included'),latency:section('not_included')};
    try{
      const detail=await get('/networks/'+encodeURIComponent(id)+'/clients/'+encodeURIComponent(body.clientId||mac));
      if(detail.status!==200 || macAddress(detail.body?.mac)!==mac){r.status='unavailable';r.reason='Client detail did not verify the exact MAC.';partial=true;records.push(r);continue;}
      const c=detail.body;r.client={mac,clientId:c.id||body.clientId,ip:c.ip,ssid:c.ssid,vlan:c.vlan??null,status:c.status,firstSeen:stamp(c.firstSeen),lastSeen:stamp(c.lastSeen),apName:c.recentDeviceName,apSerial:c.recentDeviceSerial,connection:c.recentDeviceConnection};
      const base='/networks/'+encodeURIComponent(id);
      const reads=await Promise.allSettled([
        get(base+'/events?productType=wireless&clientMac='+encodeURIComponent(mac)+'&perPage=1000'),
        get(base+'/wireless/signalQualityHistory?clientId='+encodeURIComponent(c.id||body.clientId||mac)+'&timespan=3600&resolution=300'),
        get(base+'/wireless/latencyHistory?clientId='+encodeURIComponent(c.id||body.clientId||mac)+'&timespan=3600&resolution=300')
      ]);
      reads.forEach((out,index)=>{
        const key=['events','signal','latency'][index];
        if(out.status!=='fulfilled' || out.value.status!==200){r[key]=section('unavailable',[],'Optional Meraki evidence could not be read.');partial=true;return;}
        const v=out.value.body,all=index===0?v?.events:v;
        if(!Array.isArray(all)){r[key]=section('unavailable',[],'Unexpected Meraki evidence shape.');partial=true;return;}
        const rows=all.filter(e=>{const t=Date.parse(index===0?e.occurredAt:e.endTs||e.startTs);return Number.isFinite(t)&&t>=now-3600000&&t<=now+300000 && (index!==0 || macAddress(e.clientMac)===mac || (!e.clientMac && (macAddress(e.clientId)===mac || e.clientId===(c.id||body.clientId))));}).sort((a,b)=>Date.parse(index===0?b.occurredAt:b.endTs||b.startTs)-Date.parse(index===0?a.occurredAt:a.endTs||a.startTs));
        r[key]=section(index===0?'partial':out.value.hasMore || rows.length>50?'partial':rows.length?'ok':'empty',rows.slice(0,50).map(e=>index===0?{occurredAt:stamp(e.occurredAt),type:e.type,description:e.description,apName:e.deviceName,apSerial:e.deviceSerial}:index===1?{startTs:stamp(e.startTs),endTs:stamp(e.endTs),rssi:e.rssi??null,snr:e.snr??null}:{startTs:stamp(e.startTs),endTs:stamp(e.endTs),avgLatencyMs:e.avgLatencyMs??null}),index===0?'Last hour within one returned page (up to 1000 provider events, 50 displayed). Older pages and unverified client events were not followed.':'Last hour; at most 50 returned samples.');
        if(index>0)r[key]=measurementEvidence(r[key],index===1?['rssi','snr']:['avgLatencyMs']);
        if(index===0 || r[key].status==='partial' || r[key].coverageStatus==='partial')partial=true;
      });
    }catch(_){r.status='unavailable';r.reason='Meraki client evidence unavailable.';partial=true;}
    records.push(r);
  }
  return {...section(partial?'partial':records.length?'ok':'empty',records,'Vendor-reported status and last-seen are observations, not independent proof of current connection. Multiple networks remain separate.'),window:{since:new Date(now-3600000).toISOString(),through:new Date(now).toISOString()},pageLimited:!!search.hasMore};
}
async function firewall(ip,fw,{get}={}){
  // Native monitor parameters, not generic filter= (ignored on some FortiOS versions).
  if(!require('net').isIPv4(ip) || !['irvine','dallas'].includes(fw))return section('unavailable',[],'Choose a verified DHCP IPv4 address and configured firewall.');
  get=get||require('./netdiag').fgtGet;
  const limit=50;
  const directions=await Promise.all(['source','destination'].map(async direction=>{
    try{
      const raw=await get(fw,'api/v2/monitor/firewall/session',{count:limit+1,summary:'false',ip_version:'ipv4',[direction]:ip},{maxBytes:1024*1024});
      if(raw?.status!=='success' || (raw.http_status!=null && raw.http_status!==200))throw Error('Monitor read rejected');
      const payload=raw.results,list=Array.isArray(payload)?payload:payload?.details;
      if(!Array.isArray(list))throw Error('Invalid session shape');
      const address=row=>direction==='source'?(row?.saddr||row?.src):(row?.daddr||row?.dst);
      // Fail closed if a native filter is ignored; never fall back to a global sample.
      if(list.some(row=>address(row)!==ip))return {direction,status:'unavailable',records:[],reason:'The firewall did not verify the exact '+direction+' IP filter; response withheld.'};
      const truncated=list.length>limit || raw.limit_reached===true || payload?.limit_reached===true || raw.hasMore===true || payload?.hasMore===true || Number(payload?.total)>list.length;
      return {direction,status:truncated?'partial':list.length?'ok':'empty',records:list.slice(0,limit),truncated,
        reason:truncated?'Matching sessions exceed this directional read limit.':''};
    }catch(_){return {direction,status:'unavailable',records:[],reason:'The '+direction+' IP-filtered monitor read could not complete.'};}
  }));
  const unique=new Map();
  for(const source of directions)for(const row of source.records){
    const src=row.saddr||row.src,dst=row.daddr||row.dst;
    const identity=JSON.stringify([row.session_id??row.id??null,row.vf??row.vdom??null,src,row.sport??row.src_port??null,dst,row.dport??row.dst_port??null,row.proto??row.protocol??null,row.policyid??row.policy_id??null,row.snaddr??null,row.snport??null,row.srcintf??null,row.dstintf??row['dst-intf']??null]);
    if(!unique.has(identity))unique.set(identity,{sourceIp:src,sourcePort:row.sport??row.src_port??null,destinationIp:dst,destinationPort:row.dport??row.dst_port??null,protocol:row.proto??row.protocol??null,policy:row.policyid??row.policy_id??null,egress:row.dstintf||row['dst-intf']||null,direction:src===ip&&dst===ip?'both':src===ip?'source':'destination'});
  }
  const records=[...unique.values()],complete=directions.every(d=>['ok','empty'].includes(d.status));
  const status=complete?(records.length?'ok':'empty'):directions.every(d=>d.status==='unavailable')?'unavailable':'partial';
  return {...section(status,records,'Exact source and destination IP monitor reads on the explicitly selected firewall. No matching records returned does not establish policy denial or offline state. Firewall visibility and IP ownership remain separate from device identity.'),firewall:fw,ip,
    sources:directions.map(({records,...source})=>({...source,matchingReturned:records.length})),
    scope:{mode:'exact-ip',complete,perDirectionLimit:limit,matchingReturned:records.length,matchingLimit:limit*2}};
}
async function probe(kind,target,{run=runJson}={}){
  const args=[kind,'--ip',target.ip||target.switch_ip];
  if(kind==='switch')args.push('--mac',target.mac,'--vlan',String(target.vlan),'--ifindex',String(target.ifindex));
  return run('identity-network-probe.py',args,15000);
}
module.exports={dhcp,meraki,firewall,probe,hostMatch,runJson,stamp};
