'use strict';
// Supplemental reads never add peers to, or reclassify, the history assessment.
const history=require('./network-device-history'),{macAddress}=require('./identity-device-network');
const categories=['backgroundTraffic','bestEffortTraffic','videoTraffic','voiceTraffic'];
const labels=['Background','Best effort','Video','Voice'];
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0;
const text=v=>typeof v==='string'?v.slice(0,256):null;
const same=(r,w)=>r.startTs===w.start&&r.endTs===w.end;
function intervalWindow(target,now=Date.now()){
 const w=history.historyWindow(target,now);
 if(Date.parse(w.end)-Date.parse(w.start)!==300000||Date.parse(w.start)%300000)throw {status:400,message:'Choose one complete five-minute history interval.'};
 return w;
}
function sampleSupport(response,mac){
 const records=categories.map((category,i)=>({category,label:labels[i],sampleCount:null,averageMs:null,status:'unavailable'}));
 const out={status:'unavailable',sampleCount:null,support:'unknown',records,scope:'Selected client / network / band / exact interval; statistics cannot be pinned to an AP serial.',reason:'Latency sample counts unavailable; no confidence inferred.'};
 if(response.status!==200||response.hasMore||macAddress(response.body?.mac)!==mac||!response.body.latencyStats||typeof response.body.latencyStats!=='object')return out;
 for(const row of records){
  const v=response.body.latencyStats[row.category],d=v?.rawDistribution;
  if(!d||typeof d!=='object'||Array.isArray(d)||!Object.keys(d).length||Object.keys(d).length>128)continue;
  const entries=Object.entries(d);if(entries.some(([k,n])=>!/^\d{1,8}$/.test(k)||!Number.isSafeInteger(n)||n<0))continue;
  const count=entries.reduce((n,[,v])=>n+v,0);if(!Number.isSafeInteger(count))continue;
  row.sampleCount=count;row.averageMs=count&&finite(v.avg)?v.avg:null;row.status=count?'measured':'no_samples';
 }
 const valid=records.filter(r=>r.sampleCount!==null);
 out.status=valid.length===4?'ok':valid.length?'partial':'unavailable';
 const total=valid.reduce((n,r)=>n+r.sampleCount,0);
 if(valid.length===4&&Number.isSafeInteger(total)){
  out.sampleCount=total;out.support=total===0?'no_samples':total===1?'single_sample':'multiple_samples';
  out.reason=total===0?'No latency samples reported; zero averages in empty categories are not measurements.':total===1?'Sparse evidence: one latency sample. This does not establish a sustained five-minute delay or a cause.':'Multiple latency samples reported. Sample count alone does not establish causation or statistical confidence.';
 }else {if(valid.length===4)out.status='partial';out.reason='Some category counts are unavailable or malformed. A complete total and confidence are unknown.';}
 return out;
}
function transitions(events,mac,clientId,apSerial,w,direction='arrival'){
 const during=events.filter(e=>e.clientMac===mac&&(!e.clientId||e.clientId===clientId)&&e.occurredAt>=w.start&&e.occurredAt<w.end);
 const result=[];
 for(const joined of during.filter(e=>e.kind==='connect'&&e.apSerial)){
  const left=during.filter(e=>e.kind==='disconnect'&&e.apSerial&&e.apSerial!==joined.apSerial&&Math.abs(Date.parse(e.occurredAt)-Date.parse(joined.occurredAt))<=5000&&((joined.apSerial===apSerial&&direction!=='departure')||(e.apSerial===apSerial&&direction!=='arrival'))).sort((a,b)=>Math.abs(Date.parse(a.occurredAt)-Date.parse(joined.occurredAt))-Math.abs(Date.parse(b.occurredAt)-Date.parse(joined.occurredAt))||a.occurredAt.localeCompare(b.occurredAt))[0];
  if(left){const arriving=joined.apSerial===apSerial;result.push({direction:arriving?'arrival':'departure',joinedAt:joined.occurredAt,leftAt:left.occurredAt,fromAp:left.apSerial,toAp:joined.apSerial,band:(arriving?joined.band:left.band)||null,basis:arriving?'Same verified peer associated here and disconnected from another AP within five seconds. Event order can overlap; continuous presence is not established.':'Same verified peer disconnected here and associated with another AP within five seconds. Event order can overlap; continuous presence is not established.'});}
 }
 return [...new Map(result.map(r=>[JSON.stringify(r),r])).values()].slice(0,20);
}
let active=0;
async function collectIntervalContext(target,options={}){
 if(active>=2)throw {status:429,message:'Two interval context reads are already running. Retry shortly.'};
 active++;try{return await collect(target,options);}finally{active--;}
}
async function collect(target,{get,config,now=Date.now(),budgetMs=32000,maxRequests=24,peerCandidate=null}={}){
 const api=config||require('./meraki-lookup'),transport=get||api.merakiGet,w=intervalWindow(target,now),site=api.NETWORKS[target.site];
 if(macAddress(target.mac)!==target.mac||!Object.hasOwn(api.NETWORKS,target.site)||!site||!['2.4','5','6'].includes(target.band))throw {status:400,message:'Choose a verified source MAC, configured site and band.'};
 const deadline=Date.now()+Math.min(32000,budgetMs),calls=[];let requests=0,peak=0,reading=0;
 async function read(path){
  if(requests>=Math.min(24,maxRequests)||Date.now()>=deadline)return {status:'budget'};
  requests++;reading++;peak=Math.max(peak,reading);
  try{const r=await transport(path,{timeoutMs:Math.max(1,Math.min(6500,deadline-Date.now())),pagination:true,maxBytes:3*1024*1024});calls.push({status:r.status});return r;}
  catch(_){calls.push({status:'unavailable'});return {status:'unavailable'};}finally{reading--;}
 }
 const base='/networks/'+encodeURIComponent(site.id),unavailable=reason=>({status:'unavailable',scope:{mac:target.mac,site:target.site,networkId:site.id,band:target.band},window:w,reason,requestCount:requests,assessmentChanged:false,...(peerCandidate?{requestedPeer:{mac:peerCandidate.mac,clientId:peerCandidate.clientId}}:{})});
 const search=await read('/organizations/'+encodeURIComponent(api.ORG_ID)+'/clients/search?mac='+encodeURIComponent(target.mac)+'&perPage=5');
 if(search.status!==200||macAddress(search.body?.mac)!==target.mac||!Array.isArray(search.body.records)||!search.body.records.some(r=>r.network?.id===site.id))return unavailable('Exact selected-MAC/site discovery unavailable.');
 const client=await read(base+'/clients/'+encodeURIComponent(target.mac)),c=client.body;
 if(client.status!==200||macAddress(c?.mac)!==target.mac||typeof c.id!=='string'||!c.id||String(c.recentDeviceConnection).toLowerCase()!=='wireless'||!/^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){2}$/.test(c.recentDeviceSerial||''))return unavailable('Selected MAC/native client and reported wireless AP could not be verified.');
 const ap=await read('/devices/'+encodeURIComponent(c.recentDeviceSerial));
 if(ap.status!==200||ap.body?.serial!==c.recentDeviceSerial||ap.body.networkId!==site.id)return unavailable('Reported AP/network identity unavailable.');
 const scope={mac:target.mac,clientId:c.id,site:target.site,networkId:site.id,band:target.band,apSerial:c.recentDeviceSerial,apName:text(ap.body.name)};
 if(peerCandidate&&(scope.apSerial!==peerCandidate.apSerial||scope.networkId!==peerCandidate.networkId||peerCandidate.selectedClientId&&scope.clientId!==peerCandidate.selectedClientId))throw {status:409,message:'The selected native client, AP or network changed. Read interval context again.'};
 const params={t0:w.start,t1:w.end,resolution:'300',autoResolution:'false',deviceSerial:scope.apSerial,clientId:c.id,band:target.band};
 const selected={};let supportResponse;
 const jobs=[['latency',async()=>history.measurements(await read(base+'/wireless/latencyHistory?'+new URLSearchParams(params)),['avgLatencyMs'],w)],['signal',async()=>history.measurements(await read(base+'/wireless/signalQualityHistory?'+new URLSearchParams(params)),['rssi','snr'],w)],['usage',async()=>history.measurements(await read(base+'/wireless/usageHistory?'+new URLSearchParams(params)),['totalKbps','sentKbps','receivedKbps'],w)],['support',async()=>{supportResponse=await read(base+'/wireless/clients/'+encodeURIComponent(c.id)+'/latencyStats?'+new URLSearchParams({t0:w.start,t1:w.end,band:target.band}));return sampleSupport(supportResponse,target.mac);}]];
 for(let i=0;i<jobs.length;i+=2)await Promise.all(jobs.slice(i,i+2).map(async([key,fn])=>{selected[key]=await fn();}));
 const [apEvents,clientEvents]=await Promise.all([history.eventLog(read,site.id,{deviceSerial:scope.apSerial},w),history.eventLog(read,site.id,{clientMac:target.mac},w)]);
 const all=apEvents.records.filter(e=>e.clientMac&&e.clientMac!==target.mac&&e.clientId&&e.clientId!==c.id&&e.occurredAt>=w.start&&e.occurredAt<w.end&&['connect','disconnect'].includes(e.kind));
 const candidateMap=new Map();
 for(const event of all){const old=candidateMap.get(event.clientMac);if(old){if(old.clientId!==event.clientId)old.conflict=true;}else candidateMap.set(event.clientMac,{mac:event.clientMac,clientId:event.clientId,conflict:false});}
 const ids=new Map();for(const p of candidateMap.values()){if(!ids.has(p.clientId))ids.set(p.clientId,[]);ids.get(p.clientId).push(p);}
 for(const peers of ids.values())if(peers.length>1)peers.forEach(p=>{p.conflict=true;});
 const candidates=[...candidateMap.values()].sort((a,b)=>a.mac.localeCompare(b.mac)),peers=[];
 async function peer(p){
  if(p.conflict)return {...p,status:'unavailable',reason:'Conflicting event identities; independent peer context withheld.'};
  const r=await read(base+'/clients/'+encodeURIComponent(p.mac));
  if(r.status!==200||macAddress(r.body?.mac)!==p.mac||r.body.id!==p.clientId)return {...p,status:'unavailable',reason:'Event peer MAC/native ID could not be verified.'};
  const [latency,events]=await Promise.all([read(base+'/wireless/latencyHistory?'+new URLSearchParams({...params,clientId:p.clientId})).then(r=>history.measurements(r,['avgLatencyMs'],w)),history.eventLog(read,site.id,{clientMac:p.mac},w)]);
  const changes=transitions(events.records,p.mac,p.clientId,scope.apSerial,w,'both');
  return {...p,status:latency.status==='unavailable'||latency.status==='partial'||events.status!=='ok'?'partial':'ok',latency,events,transitions:changes,context:changes.some(t=>t.direction==='arrival')?'AP transition observed':changes.length?'Departure from selected AP observed':events.records.some(e=>e.kind==='connect'&&e.apSerial===scope.apSerial&&e.occurredAt>=w.start&&e.occurredAt<w.end)?'Association observed; previous AP not established':events.coverage.complete?'No AP transition established in returned events':'AP transition unknown; event coverage incomplete',matchingLatencyMs:latency.records.find(r=>same(r,w))?.avgLatencyMs??null,comparisonEffect:'Context only. No peer is added to or removed from the original assessment.'};
 }
 // The browser selects only a server-issued reference; rediscover membership before inspection.
 let chosen=candidates.slice(0,2);
 if(peerCandidate){
  const candidate=candidates.slice(2).find(p=>p.mac===peerCandidate.mac&&p.clientId===peerCandidate.clientId&&!p.conflict);
  if(!candidate)throw {status:409,message:'This excluded candidate could not be reverified for the interval. Read interval context again.'};
  chosen=[candidate];
 }
 // Sequential candidates keep each peer's metric/event pair at two concurrent reads.
 for(const p of chosen)peers.push(await peer(p));
 // Finish every chosen peer's base reads before optional history can spend the remainder.
 // AP inventory is identical for this verified network during this request; share its read.
 let apInventory;
 async function historicalRead(path){
  if(path===base+'/devices'){if(!apInventory)apInventory=read(path);return apInventory;}
  return read(path);
 }
 for(const p of peers){
  if(!p.events||p.events.coverage.complete)continue;
  p.historicalEvents=await require('./network-historical-events').readHistoricalEvents(historicalRead,scope,p,w);
  if(p.historicalEvents.reassociations.length)p.context='Previous AP reported by client connectivity';
  else if(!p.transitions.length){const gap=require('./network-historical-events').roamingGap(p.historicalEvents,scope,w);if(gap){p.roamingGap=gap;p.context=gap.label;}}
 }

 const candidateCount=peerCandidate?1:candidates.length,peerLimit=peerCandidate?1:2;
 const excludedCandidates=(peerCandidate?[]:candidates.slice(2)).map((p,i)=>({...p,status:'not_read',identityVerified:false,selectionRank:i+3,reason:'Not read: two-peer context limit reached. Event-derived MAC/native ID has not been independently verified.'+(p.conflict?' Conflicting event identities also require review.':'')}));
 const support=selected.support;delete selected.support;
 const partial=[...Object.values(selected),support,apEvents,clientEvents,...peers].some(s=>['unavailable','partial'].includes(s.status))||(!peerCandidate&&candidates.length>2);
 return {status:partial?'partial':'ok',...(peerCandidate?{requestedPeer:{mac:peerCandidate.mac,clientId:peerCandidate.clientId}}:{}),scope,window:w,selected,sampleConfidence:support,peerRoaming:{status:apEvents.status==='unavailable'?'unavailable':candidateCount>peerLimit||peers.some(p=>p.status!=='ok')?'partial':'ok',candidateCount,readCount:peers.length,limit:peerLimit,truncated:candidateCount>peerLimit,excludedCount:excludedCandidates.length,excludedCandidates,peers,selectionBasis:peerCandidate?'One explicitly requested excluded candidate, reverified against selected-AP interval events. Context only; original peer selection is unchanged.':'Up to two independent peers with association/disassociation events inside this interval, ordered by MAC. Events alone are not measured latency.'},apEvents,clientEvents,assessmentChanged:false,requestCount:requests,limits:{maxRequests:Math.min(24,maxRequests),budgetMs:Math.min(32000,budgetMs),maxConcurrentReads:2,peakConcurrentReads:peak,maxPeerContexts:peerLimit,maxEventPagesPerScope:3,maxHistoricalEventPagesPerPeer:3},limitations:[support.scope,'Sample count is measurement support, not a probability or root-cause confidence score. Voice is a traffic category, not proof of a voice call.','Only exact AP/band time-series measurements describe this AP. Client statistics and AP transitions cannot substitute for independent interval peers.','An arrival or departure requires a verified same-peer association and disassociation on different APs within five seconds, both inside the interval, with one event on the selected AP. Band and missing coverage remain explicit.','Current AP scope is reverified at read time. It is not a continuous historical association trace.','Missing signal, usage or events do not prove idle, sleep, power saving, a client fault or a radio reset.','Incomplete legacy peer logs can receive a time-bounded client connectivity fallback after the initial peer base reads, or on explicit excluded-peer inspection, within the same total budget. Its coverage and reported reassociations remain separate from legacy coverage and paired transitions.','Existing history classifications and thresholds are unchanged.']};
}
module.exports={collectIntervalContext,intervalWindow,sampleSupport,transitions};
