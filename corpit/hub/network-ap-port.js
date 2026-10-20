'use strict';
// Explicit current-AP discovery. GETs and exact SNMP reads only; no cache writes.
const net=require('net');
const {macAddress}=require('./identity-device-network');
const stamp=v=>require('./network-device-live').stamp(v);
function privateIp(v){if(!net.isIPv4(v))return false;const a=v.split('.').map(Number);return a[0]===10||a[0]===172&&a[1]>=16&&a[1]<=31||a[0]===192&&a[1]===168;}
function systemName(v){return typeof v==='string'&&/^[a-z0-9._-]{1,253}$/i.test(v)?v.toLowerCase().replace(/\.$/,''):'';}
function sameSystem(a,b){a=systemName(a);b=systemName(b);return !!a&&!!b&&(a===b||(!a.includes('.')||!b.includes('.'))&&a.split('.')[0]===b.split('.')[0]);}
function portName(v){return typeof v==='string'?v.trim().toLowerCase().replace(/^tengigabitethernet/,'te').replace(/^twentyfivegige/,'twe').replace(/^gigabitethernet/,'gi').replace(/^fastethernet/,'fa').replace(/^fortygigabitethernet/,'fo').replace(/^hundredgige/,'hu').replace(/^ethernet/,'eth'):'';}
function validPort(v){return /^(?:te|twe|gi|fa|fo|hu|eth)\d+(?:\/\d+){0,3}$/.test(portName(v));}
const vlanNumber=v=>v!==null&&v!==''&&Number.isInteger(Number(v))&&Number(v)>=1&&Number(v)<=4094?Number(v):null;
async function knownSwitch(ip,site,{query}={}){
  query=query||((statements,options)=>require('./sqlite-offload').query(process.env.NET_DB||'/var/www/corpit-hub-api/data/netfleet.db',statements,options));
  const out=await query([{sql:'SELECT ip,name,site FROM net_switches WHERE ip=? LIMIT 2',params:[ip]}],{timeoutMs:5000,label:'Selected AP neighbor scope'});
  const rows=out?.ok&&out.results?.[0];return Array.isArray(rows)&&rows.length===1&&rows[0].ip===ip&&rows[0].site===site?rows[0]:null;
}
function neighborCandidates(ports,clientVlan){
  if(!ports||typeof ports!=='object'||Array.isArray(ports)||Object.keys(ports).length>8)return {status:'unavailable',reason:'AP neighbor data is missing or exceeds the bounded port scope.'};
  const candidates=[];
  for(const [sourcePort,row] of Object.entries(ports)){
    const entries=[];
    for(const protocol of ['cdp','lldp']){
      const n=row?.[protocol];if(!n)continue;
      const ip=n.managementAddress||n.address,name=protocol==='cdp'?n.deviceId:n.systemName;
      const vlan=vlanNumber(clientVlan)||vlanNumber(protocol==='cdp'?n.nativeVlan:n.portVlan);
      if(!privateIp(ip)||!systemName(name)||!validPort(n.portId)||!vlan)return {status:'unavailable',reason:'AP neighbor lacks a supported private switch address, system name, physical port or VLAN candidate.'};
      entries.push({switch_ip:ip,switch:name,port:n.portId,vlan,sourcePort,protocol,vlanBasis:vlanNumber(clientVlan)?'Meraki client VLAN':'AP port native VLAN candidate; requires exact client-MAC verification'});
    }
    if(entries.length===2&&(entries[0].switch_ip!==entries[1].switch_ip||!sameSystem(entries[0].switch,entries[1].switch)||portName(entries[0].port)!==portName(entries[1].port)||entries[0].vlan!==entries[1].vlan))return {status:'ambiguous',reason:'AP LLDP and CDP neighbors disagree; no switch was probed.'};
    if(entries.length)candidates.push({...entries[0],protocol:entries.map(e=>e.protocol.toUpperCase()).join(' + ')});
  }
  if(candidates.length!==1)return {status:candidates.length?'ambiguous':'empty',reason:candidates.length?'Multiple AP-facing ports were reported; no switch was chosen.':'No usable AP wired neighbor was returned.'};
  return {status:'ok',candidate:candidates[0]};
}
async function currentApPort(target,{get,config,scopeSwitch=knownSwitch,run,now=Date.now}={}){
  const api=config||require('./meraki-lookup'),transport=get||api.merakiGet;
  run=run||require('./network-device-live').runJson;
  const started=now(),deadline=Date.now()+35000;
  const evidence={status:'unavailable',mac:target.mac,ip:target.ip,discoveredAt:new Date(started).toISOString(),client:null,ap:null,neighbor:null,verification:null,
    reason:'',note:'AP-facing switch port, not a direct wired connection to the laptop. Reads are point-in-time observations. Counters are cumulative totals, not error rates.'};
  const fail=(status,reason)=>Object.assign(evidence,{status,reason});
  const remaining=()=>{const ms=deadline-Date.now();if(ms<=0)throw Error('Read deadline');return ms;};
  const read=async path=>{const r=await transport(path,{timeoutMs:Math.min(8000,remaining())});if(r?.status!==200||r.hasMore)throw Error('Incomplete Meraki read');return r.body;};
  const fresh=c=>macAddress(c?.mac)===target.mac&&c.ip===target.ip&&c.status==='Online'&&String(c.recentDeviceConnection).toLowerCase()==='wireless'&&/^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){2}$/.test(c.recentDeviceSerial||'')&&Number.isFinite(Date.parse(stamp(c.lastSeen)))&&Date.parse(stamp(c.lastSeen))>=now()-300000&&Date.parse(stamp(c.lastSeen))<=now()+30000;
  if(macAddress(target.mac)!==target.mac||!privateIp(target.ip))return fail('unavailable','A verified selected MAC and fresh DHCP IPv4 address are required.');
  try{
    const search=await read('/organizations/'+api.ORG_ID+'/clients/search?mac='+encodeURIComponent(target.mac)+'&perPage=5');
    if(macAddress(search?.mac)!==target.mac||!Array.isArray(search.records))return fail('unavailable','Meraki search did not verify the selected MAC.');
    const networks=[...new Set(search.records.map(r=>r.network?.id).filter(Boolean))],configured=new Map(Object.values(api.NETWORKS).map(n=>[n.id,n]));
    if(!networks.length)return fail('empty','No Meraki client network was returned; no switch was probed.');
    if(networks.length>4||networks.some(id=>!configured.has(id)))return fail('unavailable','Meraki network coverage is incomplete or outside configured sites; no switch was probed.');
    const matches=[];
    for(const id of networks){
      const path='/networks/'+encodeURIComponent(id)+'/clients/'+encodeURIComponent(target.mac),c=await read(path);
      if(macAddress(c?.mac)!==target.mac)return fail('unavailable','Meraki client detail did not verify the selected MAC.');
      if(fresh(c))matches.push({c,id,path,site:configured.get(id)});
    }
    if(matches.length!==1)return fail(matches.length?'ambiguous':'unavailable',matches.length?'Multiple current wireless client matches; no AP was chosen.':'No recent Online wireless client matched the fresh DHCP IP; no switch was probed.');
    const {c,id,path,site}=matches[0];
    evidence.client={mac:target.mac,ip:c.ip,networkId:id,site:site.name,status:c.status,ssid:c.ssid,lastSeen:stamp(c.lastSeen)};
    const serial=c.recentDeviceSerial,ap=await read('/devices/'+encodeURIComponent(serial));
    if(ap?.serial!==serial||ap.networkId!==id||!/^(?:MR|CW9)/.test(ap.model||''))return fail('unavailable','The current AP identity and network could not be verified.');
    evidence.ap={serial,name:ap.name||c.recentDeviceName,networkId:id};
    const adjacency=neighborCandidates((await read('/devices/'+encodeURIComponent(serial)+'/lldpCdp'))?.ports,c.vlan);
    if(adjacency.status!=='ok')return fail(adjacency.status,adjacency.reason);
    const n=adjacency.candidate;
    const known=await scopeSwitch(n.switch_ip,site.site);
    if(!known||!sameSystem(known.name,n.switch))return fail('unavailable','AP neighbor is not a recognized switch in this configured site; no SNMP read was attempted.');
    evidence.neighbor={...n,scopeBasis:'Known switch inventory (target scope only; current port is not taken from the cache)'};
    const result=await run('identity-network-probe.py',['ap-switch','--ip',n.switch_ip,'--mac',target.mac,'--vlan',String(n.vlan),'--expected-port',n.port,'--expected-system',n.switch],Math.min(18000,remaining()));
    evidence.verification=result;
    if(!['ok','partial'].includes(result?.status))return fail(['empty','changed','ambiguous'].includes(result?.status)?result.status:'unavailable',result?.reason||'The live MAC and AP port were not verified.');
    // Defense in depth: never render health that did not verify this exact discovered path.
    if(result.mac!==target.mac||result.switchIp!==n.switch_ip||result.vlan!==n.vlan||!result.pathVerified||!sameSystem(result.systemName,n.switch)||portName(result.values?.port)!==portName(n.port)){
      evidence.verification=null;return fail('unavailable','SNMP result did not verify the exact discovered MAC, switch and AP port; health withheld.');
    }
    // Detect a client roam/IP change while the switch was being read.
    const after=await read(path);
    if(!fresh(after)||after.recentDeviceSerial!==serial||vlanNumber(after.vlan)!==vlanNumber(c.vlan)){
      evidence.verification=null;return fail('changed','Client AP, IP, VLAN or freshness changed during verification; port health withheld. Run the check again.');
    }
    evidence.client.recheckedAt=new Date(now()).toISOString();
    return fail(result.status==='ok'?'verified':'partial','Current AP neighbor and exact selected-MAC switch port verified. Missing health fields remain unknown.');
  }catch(_){evidence.verification=null;return fail('unavailable','Current AP port read was unavailable, incomplete or timed out; no cached port fallback was used.');}
}
module.exports={currentApPort,neighborCandidates,knownSwitch,sameSystem,portName};
