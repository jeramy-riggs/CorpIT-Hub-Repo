'use strict';
// Deterministic evidence rules, never a root-cause or power-state assertion.
const peerEvidence=require('./network-peer-evidence');
const RULES=Object.freeze({highLatencyMs:100,stablePeerMs:50,minIndependentPeers:2});
const finite=v=>typeof v==='number'&&Number.isFinite(v);
const ms=s=>Date.parse(s);
const rows=s=>s?.records||[];
const overlap=(a,b)=>ms(a.startTs)<ms(b.endTs)&&ms(b.startTs)<ms(a.endTs);
const exact=(a,b)=>a.startTs===b.startTs&&a.endTs===b.endTs;
function assess(h){
 const highMs=RULES.highLatencyMs,stableMs=RULES.stablePeerMs,band=h.scope.band,findings=[],timeline=[],catalog=new Set(h.capabilities.eventTypes.map(x=>x.type));
 const selected=rows(h.series.selected),apEvents=rows(h.apEvents),clientEvents=rows(h.clientEvents),peers=peerEvidence.combinePeers(h.peers.records,h.peers.sameBandRecords||[],h.scope.mac,band,h.scope.clientId);
 const allEvents=[...new Map([...apEvents,...clientEvents].map(e=>[JSON.stringify(e),e])).values()];
 const selectedEvents=allEvents.filter(e=>!e.clientMac||e.clientMac===h.scope.mac||e.clientId===h.scope.clientId);
 let clientPattern=0,radioPattern=0,apPattern=0,rfPattern=0,uncertain=0;
 const counts={measured:selected.filter(x=>finite(x.avgLatencyMs)).length,missing:selected.filter(x=>!finite(x.avgLatencyMs)).length,flagged:0};
 for(const sample of selected){
  if(!finite(sample.avgLatencyMs))continue;
  const flagged=sample.avgLatencyMs>=highMs;
  const same=[],other=[];
  for(const p of peers){
   for(const [b,s] of Object.entries(p.series||{})){
    const r=rows(s).find(x=>exact(x,sample)&&finite(x.avgLatencyMs));
    if(r)(b===band?same:other).push({mac:p.mac,band:b,latencyMs:r.avgLatencyMs,reportedSsid:p.reportedSsid,ssidBasis:'Current only; historical SSID unknown'});
   }
  }
  const sameBad=same.filter(p=>p.latencyMs>=highMs),sameStable=same.filter(p=>p.latencyMs<stableMs),otherBad=other.filter(p=>p.latencyMs>=highMs);
  const during=selectedEvents.filter(e=>ms(e.occurredAt)>=ms(sample.startTs)&&ms(e.occurredAt)<ms(sample.endTs));
  const nearby=selectedEvents.filter(e=>!during.includes(e)&&ms(e.occurredAt)>=ms(sample.startTs)-900000&&ms(e.occurredAt)<ms(sample.endTs)+900000);
  const apDuring=during.filter(e=>e.apSerial===h.scope.apSerial),applicable=apDuring.filter(e=>!e.band||e.band===band);
  const utilization=rows(h.series.utilization).filter(x=>overlap(x,sample));
  const usage=rows(h.series.usage).filter(x=>exact(x,sample));
  let pattern='below_threshold';
  if(flagged){
   counts.flagged++;
   const independentBad=new Set([...sameBad,...otherBad].map(x=>x.mac));
   if(sameBad.length&&otherBad.length&&independentBad.size>=2&&applicable.some(e=>['boot','uplink'].includes(e.kind))){pattern='ap_or_uplink_suspected';apPattern++;}
   else if(sameBad.length>=2){pattern='shared_radio_path_suspected';radioPattern++;}
   else if(sameStable.length>=2&&!sameBad.length){pattern='selected_client_pattern';clientPattern++;}
   else{pattern='client_or_radio_unresolved';uncertain++;}
   if(utilization.some(x=>finite(x.utilizationTotal)&&x.utilizationTotal>=70||finite(x.utilizationNon80211)&&x.utilizationNon80211>=10)){rfPattern++;}
  }
  timeline.push({startTs:sample.startTs,endTs:sample.endTs,latencyMs:sample.avgLatencyMs,flagged,pattern,sameBandPeers:same,otherBandPeers:other,events:during,nearbyEvents:nearby,utilization,usage,apBandLatencyMs:rows(h.series['ap'+band]).find(x=>exact(x,sample))?.avgLatencyMs??null});
 }
 const add=(id,title,detail,evidence,next)=>findings.push({id,title,detail,evidence,next});
 if(apPattern)add('ap_path','AP or shared uplink issue suspected','Independent clients across bands deteriorated together and an AP boot/uplink event overlapped. Timing supports investigation, not causation.',{intervals:apPattern},'Review the correlated AP/uplink event and obtain time-matched switch evidence.');
 if(radioPattern)add('radio','Shared radio path issue suspected','At least two independent same-band peers also showed elevated latency in matching intervals. Shared SSID or upstream causes remain possible.',{intervals:radioPattern},'Compare SSIDs and other bands during the same intervals.');
 if(clientPattern)add('client','Selected-client pattern observed','At least two independent same-band peers stayed below the stable threshold while this client was elevated. Historical SSID differences are unknown; a client fault is not proven.',{intervals:clientPattern},'Compare client activity and an observed awake period, or inspect the client driver when access is available.');
 if(uncertain)add('unresolved','Client or radio path unresolved','Comparable same-band peers were missing, mixed or insufficient. A healthy different-band client cannot establish a client-only fault.',{intervals:uncertain},'Obtain overlapping same-band peer measurements during a spike.');
 if(!counts.measured)add('missing','Insufficient latency measurements','No selected-client AP/band latency measurements were returned. Missing data does not establish a healthy or offline device.',counts,'Check the selected site, AP scope, band and history coverage.');
 else if(!counts.flagged)add('no_flags','No measured interval crossed the review threshold','This applies only to measured returned intervals, not to missing intervals or unobserved brief spikes.',counts,'Use the incident window reported by the user and inspect missing coverage.');
 if(rfPattern)add('rf','RF conditions overlap elevated latency','Utilization or non-Wi-Fi utilization crossed the stated review threshold in overlapping ten-minute samples. This does not measure retries or establish a cause.',{intervals:rfPattern},'Inspect the overlapping utilization intervals and obtain spike-specific retry evidence if available.');
 const flagged=timeline.filter(x=>x.flagged),correlations=[];
 for(const t of flagged)for(const e of t.events)if(['dfs','channel_change','boot','uplink','disconnect','connect','rf'].includes(e.kind))correlations.push({startTs:t.startTs,endTs:t.endTs,event:e,appliesToSelectedScope:e.apSerial===h.scope.apSerial&&(!e.band||e.band===band),bandKnown:!!e.band,relationship:'Occurred during the measurement interval; causation not established.'});
 const types=['dfs_event','auto_rf_channel_change','sunray_auto_rf_channel_change','ai_rrm_lite_auto_rf_channel_change','boot'];
 const logCoverage=h.apEvents.coverage?.complete&&types.every(x=>catalog.has(x))&&!apEvents.some(e=>e.kind==='dropped_events');
 const relevant=correlations.filter(x=>x.appliesToSelectedScope&&['dfs','channel_change','boot'].includes(x.event.kind));
 if(relevant.length)add('events','AP events overlap elevated latency','Review the event timestamps and affected band. Unknown band is explicitly retained; overlap alone does not prove an explanation.',{matches:relevant.length},'Open the correlated event details and compare affected clients.');
 else if(flagged.length)add('no_events',logCoverage?'No logged DFS, channel change or AP boot overlapped flagged intervals':'No matching AP event was established; event coverage is incomplete',logCoverage?'The retrieved AP log covers the investigation window and the required event types are exposed. Unlogged radio-only resets remain possible.':'Do not interpret missing pages, catalog access or dropped-event warnings as proof that no event occurred.',{complete:!!logCoverage,flaggedIntervals:flagged.length},logCoverage?'Continue with same-band client comparison.':'Review provider coverage and retry the bounded history read.');
 add('limits','Power saving and radio-only resets remain unconfirmed','Traffic, latency, packet loss and retry rate have different meanings. Current firewall, DHCP, port and DEV probe results do not explain a historical spike.',{radioResetHistory:'unavailable',retryHistory:'unavailable',powerState:'unobserved'},'Keep current checks separate; obtain observed client power state or retained vendor radio diagnostics if needed.');
 const groups=peers.map(p=>{const measured={};for(const [b,s]of Object.entries(p.series||{}))measured[b]=rows(s).filter(x=>finite(x.avgLatencyMs)&&selected.some(y=>finite(y.avgLatencyMs)&&exact(x,y))).length;return {mac:p.mac,reportedSsid:p.reportedSsid,status:p.status,crossBandEnriched:p.crossBandEnriched,overlappingMeasuredIntervals:measured,sameBand:measured[band]||0,ssidBasis:'Present-time SSID only; no historical SSID classification.'};});
 return {version:1,rules:{highLatencyMs:highMs,stablePeerMs:stableMs,minIndependentPeers:2,nearbyMinutes:15,highUtilizationPct:70,highNonWifiPct:10,note:'Review thresholds, not vendor SLAs or root-cause probabilities.'},counts,findings,timeline,correlations,peerGroups:groups,verdict:apPattern?'AP or shared uplink issue suspected':radioPattern?'Shared radio path issue suspected':clientPattern&&!uncertain?'Selected-client pattern observed':counts.flagged?'Client or radio path unresolved':counts.measured?'No measured interval crossed the review threshold':'Insufficient evidence'};
}
module.exports={assess,RULES};
