'use strict';

// Reads the existing netfleet snapshot through its read-only worker. No network I/O.
const DB_PATH = process.env.NET_DB || '/var/www/corpit-hub-api/data/netfleet.db';
const iso = value => {const d=new Date(Number(value)*1000);return value!=null && Number(value)>0 && Number.isFinite(d.getTime()) ? d.toISOString() : null;};
const section = (status, records=[], reason='') => ({status,records,reason,source:'Stored network cache'});
function portRole(port, description) {
  return /^(?:po|port-channel|te|twe|fo|hu)/i.test(String(port || '')) || /uplink/i.test(String(description || '')) ? 'uplink' : 'edge_candidate';
}
async function readCachedNetwork({mac=null,ip=null,days=7,query,now=Date.now(),dbPath=DB_PATH}) {
  query = query || ((stmts,opts)=>require('./sqlite-offload').query(dbPath,stmts,opts));
  const result={mode:'cached',readAt:new Date(now).toISOString(),snapshotAt:null,historyWindow:null,
    locations:section('not_selected'),bindings:section('not_selected'),portHealth:section('not_selected'),
    issues:section('not_selected'),locationHistory:section('not_selected'),portHistory:section('not_selected'),
    locationAssessment:'unavailable',limitations:[]};
  const deadline=Date.now()+10000;
  const invoke=(statements,label)=>{
    const remaining=deadline-Date.now();
    return remaining<=0?Promise.resolve({ok:false,status:504}):query(statements,{timeoutMs:Math.min(7000,remaining),label:'Selected device '+label});
  };
  let schema;
  try {schema=await invoke([{sql:"SELECT name FROM sqlite_master WHERE type='table'"}],'cache schema');}
  catch (_) {schema={ok:false};}
  if(!schema.ok){
    for(const key of ['locations','bindings','portHealth','issues','locationHistory','portHistory'])result[key]=section('unavailable',[],'Network snapshot could not be read.');
    result.limitations.push('Network cache unavailable; no active diagnostic was attempted.');return result;
  }
  const tables=new Set(schema.results[0].map(r=>r.name));
  async function rows(tablesNeeded,sql,params,label,cap=200) {
    if(tablesNeeded.some(t=>!tables.has(t)))return section('unavailable',[],'Required cache tables have not been collected.');
    let out;
    try {out=await invoke([{sql,params}],label);}catch(_){out={ok:false};}
    if(!out.ok)return section('unavailable',[],'This part of the network cache could not be read.');
    const records=out.results[0] || [],truncated=records.length>cap;
    return {...section(truncated?'partial':records.length?'ok':'empty',records.slice(0,cap)),truncated,limit:cap};
  }
  const meta=await rows(['net_meta'],"SELECT k,v FROM net_meta WHERE k='last_run'",[],'snapshot date',1);
  const snapshot=Number(meta.records[0]?.v);
  const end=Number.isFinite(snapshot) && snapshot>0 && snapshot*1000<=now+300000 ? snapshot : Math.floor(now/1000);
  result.snapshotAt=Number.isFinite(snapshot) && snapshot>0 ? iso(snapshot) : null;
  result.historyWindow={days,since:iso(end-days*86400),through:iso(end),basis:result.snapshotAt && end===snapshot?'cache snapshot':'request time; cache date unavailable'};
  if(!result.snapshotAt || end!==snapshot)result.limitations.push('A usable snapshot date was not available; history uses the stated request-time window.');
  const since=end-days*86400;
  result.bindings=await rows(['net_arp'],
    'SELECT ip,mac,core,ts FROM net_arp WHERE '+(mac?'mac=?':'ip=?')+' ORDER BY ts DESC LIMIT 201',[mac || ip],'ARP bindings');
  result.bindings.records=result.bindings.records.map(r=>({...r,observedAt:iso(r.ts),association:mac?'exact-selected-mac':'unverified-ip-only'}));
  if(!mac){
    for(const key of ['locations','portHealth','issues','locationHistory','portHistory'])result[key]=section('not_associated',[],'An IP observation alone does not verify a hardware MAC.');
    result.locationAssessment='unverified_ip';
    result.limitations.push('IP addresses can be reassigned. Cached ARP bindings are candidates and were not followed to a switch port.');return result;
  }
  const locations=await rows(['net_cam'],
    'SELECT switch_ip,switch,ifindex,port,vlan,ts FROM net_cam WHERE mac=? ORDER BY switch_ip,ifindex,vlan LIMIT 201',[mac],'CAM locations');
  result.locations={...locations,records:locations.records.map(r=>({...r,role:portRole(r.port),observedAt:iso(r.ts),basis:'Exact MAC in stored CAM table; port role is a naming heuristic'}))};
  const health=await rows(['net_ports','net_cam'],
    'SELECT p.switch_ip,p.ifindex,p.port,p.descr,p.oper,p.admin,p.speed,p.duplex,p.in_err,p.out_err,p.crc,p.out_disc,p.ts FROM net_ports p WHERE EXISTS (SELECT 1 FROM net_cam c WHERE c.mac=? AND c.switch_ip=p.switch_ip AND c.ifindex=p.ifindex) ORDER BY p.switch_ip,p.ifindex LIMIT 201',[mac],'port health');
  result.portHealth={...health,records:health.records.map(r=>({...r,role:portRole(r.port,r.descr),observedAt:iso(r.ts)}))};
  // Description can identify an uplink even when its port name cannot.
  result.locations.records=result.locations.records.map(r=>{
    const h=result.portHealth.records.find(p=>p.switch_ip===r.switch_ip && Number(p.ifindex)===Number(r.ifindex));
    return {...r,role:portRole(r.port,h?.descr)};
  });
  const candidates=new Set(result.locations.records.filter(r=>r.role==='edge_candidate').map(r=>r.switch_ip+':'+r.ifindex));
  result.locationAssessment=locations.status==='unavailable'?'unavailable':!locations.records.length?'no_cached_location':!candidates.size?'uplinks_only':candidates.size===1?'one_edge_candidate':'multiple_edge_candidates';
  result.issues=await rows(['net_port_issues','net_cam'],
    'SELECT i.switch_ip,i.switch,i.ifindex,i.port,i.descr,i.severity,i.kind,i.detail,i.in_err,i.out_err,i.crc,i.out_disc,i.oper,i.ts FROM net_port_issues i WHERE EXISTS (SELECT 1 FROM net_cam c WHERE c.mac=? AND c.switch_ip=i.switch_ip AND c.ifindex=i.ifindex) ORDER BY i.ts DESC LIMIT 201',[mac],'matching-port issues');
  result.issues.records=result.issues.records.map(r=>({...r,observedAt:iso(r.ts)}));
  result.locationHistory=await rows(['net_cam_seen'],
    'SELECT switch_ip,port,vlan,first_seen,last_seen FROM net_cam_seen WHERE mac=? AND last_seen>=? AND first_seen<=? ORDER BY last_seen DESC LIMIT 201',[mac,since,end],'location history');
  result.locationHistory.records=result.locationHistory.records.map(r=>({...r,firstSeenAt:iso(r.first_seen),lastSeenAt:iso(r.last_seen),basis:'Historical CAM observation'}));
  result.portHistory=await rows(['net_port_stats','net_cam'],
    'SELECT p.switch_ip,p.ifindex,p.ts,p.oper,p.in_err,p.out_err,p.crc,p.out_disc FROM net_port_stats p WHERE p.ts>=? AND p.ts<=? AND EXISTS (SELECT 1 FROM net_cam c WHERE c.mac=? AND c.switch_ip=p.switch_ip AND c.ifindex=p.ifindex) ORDER BY p.ts DESC LIMIT 501',[since,end,mac],'port history',500);
  result.portHistory.records=result.portHistory.records.map(r=>({...r,observedAt:iso(r.ts)}));
  result.portHistory.reason='Latest 500 matching samples at most, across all observed ports; counters are recorded totals, not calculated rates.';
  result.limitations.push('These are stored observations, not a live path or online/offline determination.');
  if(result.locationAssessment==='uplinks_only')result.limitations.push('Only uplink-pattern observations were found. No endpoint edge port is established.');
  if(candidates.size>1)result.limitations.push('Several edge-port candidates exist; no port was selected automatically.');
  if(candidates.size===1)result.limitations.push('The edge port is a candidate based on its name/description, not a confirmed physical connection.');
  for(const key of ['locations','bindings','portHealth','issues','locationHistory','portHistory']){
    if(result[key].status==='unavailable')result.limitations.push(key+': unavailable');
    if(result[key].truncated)result.limitations.push(key+': results capped at '+result[key].limit);
  }
  return result;
}
module.exports={readCachedNetwork,portRole};
