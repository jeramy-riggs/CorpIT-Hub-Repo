'use strict';
// Native-client, time-bounded fallback for incomplete legacy network event paging.
const {macAddress}=require('./identity-device-network');
const serial=v=>typeof v==='string'&&/^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){2}$/.test(v);
const stamp=v=>{const n=typeof v==='string'?Date.parse(v):NaN;return Number.isFinite(n)?new Date(n).toISOString():null;};
const safe=v=>typeof v==='string'?v.slice(0,256):null;
const types=new Set(['assoc','auth','connection','deauth','dhcp','disassoc','dns','roam','sticky']);
function nextLink(link,path,window){
 if(!link)return null;
 const u=new URL(link,'https://api.meraki.com'),allowed=new Set(['t0','t1','perPage','sortOrder','startingAfter','endingBefore']);
 if(u.origin!=='https://api.meraki.com'||u.username||u.password||u.hash||u.pathname!=='/api/v1'+path)throw Error('Historical event pagination scope');
 if([...u.searchParams.keys()].some(k=>!allowed.has(k)||u.searchParams.getAll(k).length!==1)||u.searchParams.get('t0')!==window.contextStart||u.searchParams.get('t1')!==window.contextEnd||u.searchParams.get('perPage')!=='1000'||u.searchParams.get('sortOrder')!=='ascending'||u.searchParams.has('startingAfter')&&u.searchParams.has('endingBefore'))throw Error('Historical event pagination parameters');
 return u.pathname.slice('/api/v1'.length)+u.search;
}
function normalize(row,peer){
 const data={};for(const k of ['reason','reassoc'])if(['string','number'].includes(typeof row.eventData?.[k]))data[k]=String(row.eventData[k]).slice(0,256);
 const previous=macAddress(row.eventData?.roamApMac);if(previous)data.roamApMac=previous;
 return {occurredAt:stamp(row.occurredAt),type:row.type,subtype:safe(row.subtype),description:'Client connectivity · '+row.type+(row.subtype?' · '+safe(row.subtype):''),kind:row.type==='assoc'&&row.subtype==='success'?'connect':['disassoc','deauth'].includes(row.type)?'disconnect':'other',apSerial:row.deviceSerial,clientMac:peer.mac,clientId:peer.clientId,band:['2.4','5','6'].includes(row.band)?row.band:null,data,source:'client_connectivity'};
}
function reportedReassociations(records,devices,peer,scope,window){
 if(devices.status!==200||devices.hasMore||!Array.isArray(devices.body)||devices.body.length>1000)return [];
 return records.filter(e=>e.type==='connection'&&e.subtype==='success'&&e.data.reassoc==='1'&&e.data.roamApMac&&e.apSerial===scope.apSerial&&e.occurredAt>=window.start&&e.occurredAt<window.end).flatMap(e=>{
  const matches=devices.body.filter(d=>macAddress(d.mac)===e.data.roamApMac);
  if(matches.length!==1)return [];const previous=matches[0];
  if(!serial(previous.serial)||previous.serial===scope.apSerial||previous.networkId!==scope.networkId||!/^(MR|CW)/.test(previous.model||''))return [];
  return [{occurredAt:e.occurredAt,fromAp:previous.serial,fromApName:safe(previous.name),fromApMac:e.data.roamApMac,toAp:scope.apSerial,toApName:scope.apName||null,band:e.band,clientMac:peer.mac,clientId:peer.clientId,source:'client_connectivity',basis:'Successful client connectivity event reports reassoc=1 and a previous AP MAC, matched uniquely to current AP inventory in this network. This is a vendor-reported reassociation, not a paired disconnect/association or proof of continuous presence.'}];
 });
}
// Other-AP context never becomes a selected-AP arrival/departure or a paired transition.
function otherApReassociations(records,devices,peer,scope,window){
 if(devices.status!==200||devices.hasMore||!Array.isArray(devices.body)||devices.body.length>1000)return [];
 const valid=d=>d&&serial(d.serial)&&d.networkId===scope.networkId&&/^(MR|CW)/.test(d.model||'');
 return records.filter(e=>e.clientMac===peer.mac&&e.clientId===peer.clientId&&e.type==='connection'&&e.subtype==='success'&&e.data.reassoc==='1'&&e.data.roamApMac&&e.apSerial!==scope.apSerial&&e.occurredAt>=window.start&&e.occurredAt<window.end).flatMap(e=>{
  const from=devices.body.filter(d=>macAddress(d.mac)===e.data.roamApMac),to=devices.body.filter(d=>d.serial===e.apSerial);
  if(from.length!==1||to.length!==1||!valid(from[0])||!valid(to[0])||from[0].serial===scope.apSerial||from[0].serial===to[0].serial)return [];
  return [{occurredAt:e.occurredAt,fromAp:from[0].serial,fromApName:safe(from[0].name),fromApMac:e.data.roamApMac,toAp:to[0].serial,toApName:safe(to[0].name),band:e.band,clientMac:peer.mac,clientId:peer.clientId,source:'client_connectivity',basis:'Successful client connectivity event reports reassoc=1 and a previous AP MAC. Both APs were verified uniquely in current inventory in this network and differ from the selected AP. Other-AP context only; not a selected-AP transition, paired disconnect/association or proof of continuous presence.'}];
 });
}
function roamingGap(historical,scope,window){
 if(!historical.coverage?.complete||['unavailable','partial'].includes(historical.apMapping?.status)||historical.reassociations?.length)return null;
 const during=(historical.records||[]).filter(e=>e.occurredAt>=window.start&&e.occurredAt<window.end),here=during.filter(e=>e.apSerial===scope.apSerial);
 if(here.some(e=>e.type==='assoc'&&e.subtype==='success'||e.type==='connection'&&e.subtype==='success'))return {code:'previous_ap_not_reported',label:'Association here; previous AP not reported',detail:'Returned interval events show association on the selected AP without a verified previous-AP reference. This does not establish an AP change.'};
 if(historical.otherApReassociations?.length)return {code:'other_ap_reassociations',label:'Roaming reported between other APs',detail:'Verified successful reassociations in this interval involve other APs. They do not establish an arrival at or departure from the selected AP.'};
 if(here.some(e=>['disassoc','deauth'].includes(e.type)))return {code:'destination_not_confirmed',label:'Disconnect here; destination not confirmed',detail:'The selected AP logged a disconnect in this interval. No matched destination is established by the returned connectivity source or the existing paired-transition evidence.'};
 return null;
}
async function readHistoricalEvents(read,scope,peer,window){
 const path='/networks/'+encodeURIComponent(scope.networkId)+'/wireless/clients/'+encodeURIComponent(peer.clientId)+'/connectivityEvents',params={t0:window.contextStart,t1:window.contextEnd,perPage:'1000',sortOrder:'ascending'},seen=new Set(),records=[];
 let next=path+'?'+new URLSearchParams(params),pages=0,complete=false,reason='',truncated=false;
 for(let i=0;i<3&&next;i++){
  if(seen.has(next)){reason='Provider repeated a historical event cursor.';break;}seen.add(next);
  const r=await read(next);
  if(r.status!==200||!Array.isArray(r.body)||r.body.length>1000){reason='Time-bounded client connectivity read unavailable or malformed.';break;}
  pages++;
  if(r.body.some(e=>!e||!stamp(e.occurredAt)||!types.has(e.type)||!serial(e.deviceSerial)||e.networkId!=null&&e.networkId!==scope.networkId||e.clientMac!=null&&macAddress(e.clientMac)!==peer.mac||e.clientId!=null&&e.clientId!==peer.clientId||stamp(e.occurredAt)<window.contextStart||stamp(e.occurredAt)>=window.contextEnd)){reason='Historical event identity, time or AP mismatch; this page was withheld.';break;}
  records.push(...r.body.map(e=>normalize(e,peer)));
  if(records.length>1500){records.length=1500;truncated=true;reason='Historical event rows capped at 1500.';break;}
  try{next=nextLink(r.pagination?.next,path,window);}catch(_){reason='Historical event pagination left the verified client or time window.';break;}
  if(!next){if(r.hasMore||r.body.length===1000)reason='Terminal historical event coverage could not be established.';else complete=true;break;}
 }
 if(!complete&&!reason)reason='Historical event page or request budget reached before coverage was established.';
 const unique=[...new Map(records.map(e=>[JSON.stringify(e),e])).values()].sort((a,b)=>a.occurredAt.localeCompare(b.occurredAt));
 const candidates=unique.filter(e=>e.type==='connection'&&e.subtype==='success'&&e.data.reassoc==='1'&&e.data.roamApMac&&e.occurredAt>=window.start&&e.occurredAt<window.end);
 let mapping={status:'not_needed',reason:'No successful reassociation reference in the chosen interval.'},reassociations=[],otherReassociations=[];
 if(candidates.length){const devices=await read('/networks/'+encodeURIComponent(scope.networkId)+'/devices');reassociations=reportedReassociations(unique,devices,peer,scope,window);otherReassociations=otherApReassociations(unique,devices,peer,scope,window);const mapped=reassociations.length+otherReassociations.length;mapping={status:mapped===candidates.length?'ok':mapped?'partial':'unavailable',reason:mapped===candidates.length?'Reassociation references matched to verified APs in current network inventory.':'Some reassociation references could not be mapped uniquely to verified APs in this network.'};}
 return {status:complete?'ok':pages?'partial':'unavailable',records:unique,coverage:{complete,pages,truncated,requestedStart:window.contextStart,requestedEnd:window.contextEnd,basis:'Exact native-client endpoint with t0/t1; all returned pages consumed using verified provider links. Coverage applies to this source only.'},reason,apMapping:mapping,reassociations,otherApReassociations:otherReassociations,source:'Meraki time-bounded client connectivity events',scope:{mac:peer.mac,clientId:peer.clientId,networkId:scope.networkId,band:'All bands; each event retains its reported band.'}};
}
module.exports={readHistoricalEvents,nextLink,reportedReassociations,otherApReassociations,roamingGap,normalize};
