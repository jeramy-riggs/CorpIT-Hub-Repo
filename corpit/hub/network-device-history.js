'use strict';
// Passive, bounded history reads. No DHCP, probes, device tools or vendor writes.
const {macAddress}=require('./identity-device-network');
const bands=['2.4','5','6'];
const peerEvidence=require('./network-peer-evidence');
const stamp=v=>{const n=typeof v==='number'?v*1000:Date.parse(v);return Number.isFinite(n)?new Date(n).toISOString():null;};
const numeric=v=>typeof v==='number'&&Number.isFinite(v)?v:null;
const safe=v=>typeof v==='string'?v.slice(0,256):null;
function historyWindow(input,now=Date.now()){
 const end=input.end==null?now:Date.parse(input.end),start=input.start==null?end-3600000:Date.parse(input.start);
 if(!Number.isFinite(start)||!Number.isFinite(end)||Math.min(now,end)<=start||end-start>21600000||start<now-7*86400000||end>now+30000)throw {status:400,message:'Choose a valid history interval up to six hours within the last seven days, ending no later than now.'};
 return {start:new Date(start).toISOString(),end:new Date(Math.min(now,end)).toISOString(),contextStart:new Date(start-900000).toISOString(),contextEnd:new Date(Math.min(now,end+900000)).toISOString(),resolutionSeconds:300};
}
function eventKind(type){
 if(type==='dfs_event')return 'dfs';
 if(['auto_rf_channel_change','sunray_auto_rf_channel_change','ai_rrm_lite_auto_rf_channel_change'].includes(type))return 'channel_change';
 if(type==='boot')return 'boot';if(type==='carrier_event')return 'uplink';if(type==='events_dropped2')return 'dropped_events';if(type==='afc_response')return 'afc';
 if(/disassociation|deauth/.test(type))return 'disconnect';if(/association|fast_roam/.test(type))return 'connect';
 if(/^(noise_avoid_|channel_scan|spectrum_scan|auto_tx_|auto_rx_|sunray_auto_|ai_rrm_lite_auto_)/.test(type))return 'rf';
 return 'other';
}
function eventBand(e){
 const d=e.eventData||{},b=String(d.band||'').replace(/\s*GHz$/i,'');
 if(bands.includes(b))return b;
 if(e.type==='afc_response')return '6';
 if(String(d.radio)==='0')return '2.4';if(String(d.radio)==='1')return '5';return null;
}
function normalizeEvent(e){
 const data={};for(const k of ['radio','band','channel','old_channel','new_channel','reason','status','request_type','ssid','ssid_number'])if(['string','number','boolean'].includes(typeof e.eventData?.[k]))data[k]=String(e.eventData[k]).slice(0,256);
 return {occurredAt:stamp(e.occurredAt),type:safe(e.type),description:safe(e.description),kind:eventKind(e.type||''),band:eventBand(e),apSerial:safe(e.deviceSerial),clientMac:macAddress(e.clientMac),clientId:safe(e.clientId),data};
}
function olderLink(link,path,filter){
 if(!link)return null;
 const u=new URL(link,'https://api.meraki.com');
 if(u.origin!=='https://api.meraki.com'||u.pathname!=='/api/v1'+path||u.username||u.password||u.hash)throw Error('Pagination scope');
 const allowed=new Set(['productType','deviceSerial','clientMac','perPage','startingAfter','endingBefore']);
 if([...u.searchParams.keys()].some(k=>!allowed.has(k))||[...u.searchParams.keys()].some(k=>u.searchParams.getAll(k).length!==1)||u.searchParams.get('productType')!=='wireless'||u.searchParams.get('perPage')!=='1000')throw Error('Pagination parameters');
 for(const [k,v] of Object.entries(filter))if(u.searchParams.get(k)!==v)throw Error('Pagination identity');
 for(const k of ['deviceSerial','clientMac'])if(!(k in filter)&&u.searchParams.has(k))throw Error('Pagination changed filter');
 return u.pathname.slice('/api/v1'.length)+u.search;
}
async function eventLog(read,networkId,filter,window){
 const path='/networks/'+encodeURIComponent(networkId)+'/events',scope=filter.deviceSerial?'ap':'client';
 let next=path+'?'+new URLSearchParams({productType:'wireless',...filter,perPage:'1000'}),records=[],ranges=[],pages=0,reason='',complete=false,cut=false;
 const seen=new Set();
 for(let i=0;i<3&&next;i++){
  if(seen.has(next)){reason='Provider repeated a pagination cursor.';break;}seen.add(next);
  const r=await read(next);if(r.status!==200||!Array.isArray(r.body?.events)||r.body.events.length>1000){reason='Event read unavailable or malformed.';complete=false;break;}
  pages++;
  const raw=r.body.events;
  if(raw.some(e=>!e||e.networkId!==networkId||!stamp(e.occurredAt)||typeof e.type!=='string'||(scope==='ap'?e.deviceSerial!==filter.deviceSerial:macAddress(e.clientMac)!==filter.clientMac&&e.clientId!==filter.clientMac))){reason='Event identity or timestamp mismatch; this page was withheld.';break;}
  if(r.body.message){reason='Provider supplied an event-log warning.';}
  const a=stamp(r.body.pageStartAt),b=stamp(r.body.pageEndAt);
  if(a&&b&&a<=b)ranges.push({start:a,end:b});
  records.push(...raw.map(normalizeEvent).filter(e=>e.occurredAt&&e.occurredAt>=window.contextStart&&e.occurredAt<window.contextEnd));
  const ordered=ranges.slice().sort((a,b)=>a.start.localeCompare(b.start));let through=null;
  for(const range of ordered){if(through===null){if(range.start<=window.contextStart)through=range.end;}else if(range.start<=through&&range.end>through)through=range.end;}
  complete=!!through&&through>=window.contextEnd&&!reason;
  if(complete)break;
  try{next=olderLink(r.pagination?.prev,path,filter);}catch(_){reason='Pagination left the verified event scope.';break;}
  if(!next){reason=reason||'Provider page bounds do not establish full event-window coverage.';break;}
 }
 if(!complete&&!reason)reason='Event page or time budget reached before coverage was established.';
 const unique=new Map(records.map(e=>[JSON.stringify(e),e]));records=[...unique.values()].sort((a,b)=>a.occurredAt.localeCompare(b.occurredAt));
 if(records.length>1500){records=records.slice(0,1500);complete=false;cut=true;reason='Displayed event rows capped at 1500.';}
 return {status:complete?'ok':pages?'partial':'unavailable',records,coverage:{complete,pages,ranges,truncated:cut},reason};
}
function measurements(r,fields,window){
 if(r.status!==200||!Array.isArray(r.body)||r.body.length>1000)return {status:'unavailable',records:[],measurementCount:0,reason:'History read unavailable, malformed or oversized.'};
 let malformed=false;
 let records=r.body.flatMap(row=>{
  const start=stamp(row?.startTs),end=stamp(row?.endTs);if(!start||!end||end<=start){malformed=true;return [];}
  if(end<=window.start||start>=window.end)return [];
  return [{startTs:start,endTs:end,...Object.fromEntries(fields.map(k=>{let n=numeric(row[k]);if(n!=null&&k!=='rssi'&&k!=='snr'&&(n<0||k.startsWith('utilization')&&n>100)){n=null;malformed=true;}return [k,n];}))}];
 }).sort((a,b)=>a.startTs.localeCompare(b.startTs));
 const invalid=new Set();for(let i=1;i<records.length;i++)if(records[i].startTs<records[i-1].endTs){invalid.add(i-1);invalid.add(i);malformed=true;}records=records.filter((_,i)=>!invalid.has(i));
 const measurementCount=records.filter(x=>fields.some(k=>x[k]!=null)).length;
 const duration=x=>Math.max(0,Math.min(Date.parse(x.endTs),Date.parse(window.end))-Math.max(Date.parse(x.startTs),Date.parse(window.start)))/1000;
 const requestedSeconds=(Date.parse(window.end)-Date.parse(window.start))/1000,returnedSeconds=records.reduce((n,x)=>n+duration(x),0),measuredSeconds=records.filter(x=>fields.some(k=>x[k]!=null)).reduce((n,x)=>n+duration(x),0);
 return {status:malformed||r.hasMore?'partial':measurementCount?'ok':'no_measurements',records,measurementCount,sampleCount:records.length,coverage:{requestedSeconds,returnedSeconds,measuredSeconds,unmeasuredSeconds:Math.max(0,requestedSeconds-measuredSeconds)},reason:malformed?'Invalid or overlapping intervals withheld.':r.hasMore?'Provider returned a partial history.':measurementCount?'Only returned measured intervals establish coverage.':'No measurements in returned intervals; missing is not zero.'};
}
async function collectBoundedHistory(target,{get,config,now=Date.now(),budgetMs=42000,maxRequests=60,wait=ms=>new Promise(r=>setTimeout(r,ms))}={}){
 const api=config||require('./meraki-lookup'),transport=get||api.merakiGet,window=historyWindow(target,now),site=api.NETWORKS[target.site];
 if(macAddress(target.mac)!==target.mac||!Object.hasOwn(api.NETWORKS,target.site)||!site||!bands.includes(target.band))throw {status:400,message:'Choose a verified MAC, configured site and radio band.'};
 const deadline=Date.now()+Math.min(42000,budgetMs);let requests=0,rateLimited=false;
 const read=async path=>{
  if(requests>=Math.min(60,maxRequests)||Date.now()>=deadline)return {status:'budget'};
  requests++;
  try{
   const r=await transport(path,{timeoutMs:Math.max(1,Math.min(6500,deadline-Date.now())),pagination:true,maxBytes:3*1024*1024});
   if(r.status===429){rateLimited=true;const seconds=Number(r.pagination?.retryAfter);if(Number.isFinite(seconds)&&seconds>=0&&seconds<=2&&Date.now()+seconds*1000+1000<deadline){await wait(seconds*1000);return read(path);}}
   return r;
  }catch(_){return {status:'unavailable'};}
 };
 const base='/networks/'+encodeURIComponent(site.id),empty=(reason)=>({status:'unavailable',scope:{mac:target.mac,site:target.site,networkId:site.id,band:target.band},window,reason,requestCount:requests});
 const search=await read('/organizations/'+encodeURIComponent(api.ORG_ID)+'/clients/search?mac='+encodeURIComponent(target.mac)+'&perPage=5');
 if(search.status!==200||macAddress(search.body?.mac)!==target.mac||!Array.isArray(search.body.records))return empty('Exact selected-MAC Meraki discovery unavailable.');
 if(!search.body.records.some(r=>r.network?.id===site.id))return empty('No selected-MAC record was established in the chosen site; no other site was selected.');
 const detail=await read(base+'/clients/'+encodeURIComponent(target.mac)),c=detail.body;
 if(detail.status!==200||macAddress(c?.mac)!==target.mac||!c.id||String(c.recentDeviceConnection).toLowerCase()!=='wireless'||!/^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){2}$/.test(c.recentDeviceSerial||''))return empty('Selected MAC and reported wireless AP could not be verified.');
 const ap=await read('/devices/'+encodeURIComponent(c.recentDeviceSerial));
 if(ap.status!==200||ap.body?.serial!==c.recentDeviceSerial||ap.body?.networkId!==site.id)return empty('Reported AP/network identity could not be verified.');
 const scope={mac:target.mac,clientId:c.id,site:target.site,networkId:site.id,apSerial:ap.body.serial,apName:safe(ap.body.name),band:target.band,reportedSsid:safe(c.ssid),reportedIp:safe(c.ip),lastSeen:stamp(c.lastSeen),apBasis:'Presently reported AP; historical metrics are filtered to this AP and band. Current association is not a continuous historical trace.'};
 const range={t0:window.start,t1:window.end,resolution:'300',autoResolution:'false'},apRange={...range,deviceSerial:scope.apSerial};
 const metric=(name,params,fields)=>read(base+'/wireless/'+name+'?'+new URLSearchParams(params)).then(r=>measurements(r,fields,window));
 const series={};
 // At most two simultaneous requests, including event pagination.
 const [apEvents,clientEvents]=await Promise.all([eventLog(read,site.id,{deviceSerial:scope.apSerial},window),eventLog(read,site.id,{clientMac:target.mac},window)]);
 const jobs=[['selected',()=>metric('latencyHistory',{...apRange,clientId:c.id,band:target.band},['avgLatencyMs'])],['signal',()=>metric('signalQualityHistory',{...apRange,clientId:c.id,band:target.band},['rssi','snr'])],['utilization',()=>metric('channelUtilizationHistory',{...apRange,resolution:'600',band:target.band},['utilizationTotal','utilization80211','utilizationNon80211'])],['usage',()=>metric('usageHistory',{...apRange,clientId:c.id,band:target.band},['totalKbps','sentKbps','receivedKbps'])],...bands.map(b=>['ap'+b,()=>metric('latencyHistory',{...apRange,band:b},['avgLatencyMs'])])];
 for(let i=0;i<jobs.length;i+=2)await Promise.all(jobs.slice(i,i+2).map(async([key,fn])=>{series[key]=await fn();}));
 const [catalog,roster]=await Promise.all([read(base+'/events/eventTypes'),read('/devices/'+encodeURIComponent(scope.apSerial)+'/clients?t0='+encodeURIComponent(window.start))]);
 const candidates=roster.status===200&&Array.isArray(roster.body)&&roster.body.length<=1000?roster.body:[];
 // Identity and overlap, never latency magnitude or current SSID, determine priority.
 const eligible=[...new Map(candidates.filter(x=>x&&macAddress(x.mac)&&macAddress(x.mac)!==target.mac&&typeof x.id==='string'&&x.id&&x.id!==c.id).map(x=>[macAddress(x.mac),x])).values()];
 const ids=new Set(),independent=eligible.filter(x=>{if(ids.has(x.id))return false;ids.add(x.id);return true;});
 const selectedIntervals=new Set(series.selected.records.filter(x=>numeric(x.avgLatencyMs)!==null).map(x=>x.startTs+'|'+x.endTs));
 const overlapCount=s=>s.records.filter(x=>numeric(x.avgLatencyMs)!==null&&selectedIntervals.has(x.startTs+'|'+x.endTs)).length;
 const initialScreeningLimit=8,screeningLimit=16,comparisonLimit=3,screened=[];let screeningStop='';
 const highMs=require('./network-device-assessment').RULES.highLatencyMs;
 const measuredSelected=series.selected.records;
 const verified=()=>screened.filter(p=>p.clientId);
 const coverage=()=>peerEvidence.coverage(measuredSelected,verified(),target.band,highMs);
 const gaps=()=>coverage().filter(r=>r.elevated&&r.missingPeers>0);
 async function screen(candidate,phase,requestedWindow){
  const mac=macAddress(candidate.mac),d=await read(base+'/clients/'+encodeURIComponent(mac));
  if(d.status!==200||macAddress(d.body?.mac)!==mac||d.body.id!==candidate.id)return {mac,status:'unavailable',reason:'Peer detail identity not verified.',series:{},overlapCount:0,phase,requestedWindow};
  const peer={mac,clientId:d.body.id,reportedSsid:safe(d.body.ssid),ssidBasis:'Current reported SSID only; historical SSID not established.',series:{},status:'ok',phase,requestedWindow};
  const params={...apRange,t0:requestedWindow.start,t1:requestedWindow.end,clientId:peer.clientId,band:target.band};
  peer.series[target.band]=measurements(await read(base+'/wireless/latencyHistory?'+new URLSearchParams(params)),['avgLatencyMs'],requestedWindow);
  peer.overlapCount=overlapCount(peer.series[target.band]);
  if(['unavailable','partial'].includes(peer.series[target.band].status))peer.status='partial';
  peer.associationBasis='Only non-null AP- and band-filtered measurement intervals are eligible comparisons; roster membership alone is insufficient.';return peer;
 }
 async function screenPhase(candidates,phase,requestedWindow,stopWhenCovered){
  let position=0;
  while(position<candidates.length){
   if(stopWhenCovered&&!gaps().length)break;
   const reserve=Math.min(comparisonLimit,independent.length)*(bands.length-1);
   const slots=Math.min(2,candidates.length-position,Math.floor((Math.min(60,maxRequests)-requests-reserve)/2));
   if(slots<=0){screeningStop='Request budget reserved for comparison bands.';break;}
   if(Date.now()>=deadline){screeningStop='History time budget reached during candidate screening.';break;}
   const batch=candidates.slice(position,position+slots);position+=slots;
   screened.push(...await Promise.all(batch.map(c=>screen(c,phase,requestedWindow))));
  }
 }
 await screenPhase(independent.slice(0,initialScreeningLimit),'initial',{start:window.start,end:window.end},false);
 const initialCoverage=coverage(),initialGaps=gaps(),followupWindow=initialGaps.length?{start:initialGaps[0].startTs,end:initialGaps[initialGaps.length-1].endTs}:null;
 if(initialGaps.length&&!screeningStop&&screened.length>=Math.min(initialScreeningLimit,independent.length))await screenPhase(independent.slice(initialScreeningLimit,screeningLimit),'followup',followupWindow,true);
 const peers=peerEvidence.chooseCrossBand(measuredSelected,screened,target.band,comparisonLimit,highMs);
 for(const peer of peers){
  if(!peer.clientId)continue;
  await Promise.all(bands.filter(b=>b!==target.band).map(async b=>{peer.series[b]=await metric('latencyHistory',{...apRange,clientId:peer.clientId,band:b},['avgLatencyMs']);}));
  if(Object.values(peer.series).some(x=>['unavailable','partial'].includes(x.status)))peer.status='partial';
 }
 const rosterValid=roster.status===200&&Array.isArray(roster.body)&&roster.body.length<=1000;
 const screeningComplete=rosterValid&&!roster.hasMore&&screened.length===independent.length&&!screened.some(p=>!p.clientId||['unavailable','partial'].includes(p.series[target.band].status));
 const selectedPeers=new Set(peers.map(p=>p.mac));
 const sameBandRecords=verified().map(p=>({...p,series:{[target.band]:p.series[target.band]}}));
 const intervalCoverage=coverage().map(r=>{const initialPeerCount=initialCoverage.find(x=>x.startTs===r.startTs&&x.endTs===r.endTs)?.peerCount||0;return {...r,initialPeerCount,stage:initialPeerCount>=2?'initial':r.peerCount>=2?'followup':'insufficient'};}),remainingGaps=gaps();
 const followup={initialMissingIntervals:initialGaps.length,remainingMissingIntervals:remainingGaps.length,filledIntervals:initialGaps.filter(r=>!remainingGaps.some(x=>x.startTs===r.startTs&&x.endTs===r.endTs)).length,candidatesRead:screened.filter(p=>p.phase==='followup').length,window:followupWindow,reason:!initialGaps.length?'Initial screened evidence supplies two peers for each measured elevated interval.':remainingGaps.length?'Some elevated intervals still lack two measured peers; missing data remains unknown.':'Additional measured evidence filled the initial peer gaps.'};
 const out={status:'ok',scope,window,series,apEvents,clientEvents,peers:{status:!rosterValid?'unavailable':!screeningComplete||independent.length>comparisonLimit||peers.some(p=>p.status!=='ok')?'partial':'ok',candidateCount:independent.length,screenedCount:screened.length,screeningLimit,screeningComplete,screeningStop:screeningStop||(!rosterValid?'Peer roster unavailable or malformed.':roster.hasMore?'Peer roster was page-limited.':independent.length>screened.length?(screened.length>=screeningLimit?'Candidate screening limit reached.':'Further candidates were not needed to fill measured elevated-interval gaps.'):''),initialScreeningLimit,sameBandRecords,verifiedCount:sameBandRecords.length,intervalCoverage,followup,selectionBasis:'Every verified screened same-band measurement informs its matching interval. The cross-band cohort prioritizes two-peer coverage of elevated intervals. Exact boundaries must match. Peer latency magnitude and current SSID do not affect selection.',screening:screened.map(p=>({mac:p.mac,status:p.clientId?p.series[target.band].status:p.status,overlappingMeasuredIntervals:p.overlapCount,selected:selectedPeers.has(p.mac),usedForSameBand:!!p.clientId&&p.overlapCount>0,phase:p.phase,requestedWindow:p.requestedWindow,reason:p.reason||p.series[target.band]?.reason||''})),sampledCount:peers.length,limit:comparisonLimit,truncated:!!roster.hasMore||independent.length>comparisonLimit||screened.length<independent.length,records:peers},capabilities:{catalogStatus:catalog.status===200&&Array.isArray(catalog.body)&&catalog.body.every(x=>x&&typeof x.type==='string')?'ok':'unavailable',eventTypes:catalog.status===200&&Array.isArray(catalog.body)?catalog.body.slice(0,300).filter(x=>x&&typeof x.type==='string').map(x=>({type:safe(x.type),description:safe(x.description)})):[],radioResetHistory:'unavailable',spikeRetryHistory:'unavailable'},requestCount:requests,rateLimited,limits:{maxRequests:Math.min(60,maxRequests),maxEventPagesPerScope:3,maxPeers:3,maxSameBandPeers:screeningLimit,maxPeerCandidates:screeningLimit,maxConcurrentReads:2,budgetMs:Math.min(42000,budgetMs)},limitations:[scope.apBasis,'The first eight candidates are screened, then up to eight more only while elevated intervals lack two measured peers. All verified same-band readings are retained; three clients receive cross-band detail. Unread candidates and unmeasured bands remain unknown. This is not an exhaustive AP census. Historical SSID membership is not established.','AP aggregates include the selected client and are not independent peer evidence.','Null or absent samples are unknown. Utilization uses 10-minute intervals; latency uses five-minute intervals.','Retry history and radio-only reset history are unavailable; packet loss and retry rate are different measurements.','Current DHCP, switch-port, firewall and DEV probe observations cannot establish a historical cause.','Power state is unobserved; activity correlation does not prove power saving.']};
 if(search.hasMore)out.limitations.push('MAC discovery was page-limited; only the explicitly chosen site was read.');
 if(rateLimited)out.limitations.push('Provider rate limiting occurred; inspect each section for coverage.');
 if(apEvents.status!=='ok'||clientEvents.status!=='ok'||Object.values(series).some(s=>s.status==='unavailable'||s.status==='partial')||out.peers.status!=='ok'||out.capabilities.catalogStatus!=='ok')out.status='partial';
 out.analysis=require('./network-device-assessment').assess(out);
 return out;
}
let active=0;
async function collectHistory(target,options){
 if(active>=2)throw {status:429,message:'Two network history analyses are already running. Retry shortly.'};
 active++;try{return await collectBoundedHistory(target,options);}finally{active--;}
}
module.exports={collectHistory,historyWindow,eventLog,olderLink,normalizeEvent,eventKind,eventBand,measurements};
