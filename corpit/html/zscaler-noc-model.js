/* Pure, bounded projection of the existing read APIs. No identities, OTPs,
   credentials, database paths or arbitrary upstream bodies are retained. */
(function(){'use strict';
var definitions=[
 {id:'zia',name:'ZIA policy API',url:'/api/zscaler/zia/firewall-rules',view:'urllookup',kind:'configuration'},
 {id:'zpa',name:'ZPA connectors',url:'/api/zscaler/zpa/connectors',view:'connectors',kind:'configuration'},
 {id:'zcc',name:'ZCC device API',url:'/api/zscaler/zcc/devices',view:'zcc',kind:'inventory'},
 {id:'zdx',name:'ZDX applications',url:'/api/zscaler/zdx/apps',view:'zdxapps',kind:'experience',window:'Last 2 hours'},
 {id:'zwa',name:'ZWA DLP incidents',url:'/api/zscaler/zwa/incidents?days=1',view:'dlpinc',kind:'incidents',window:'Last 24 hours'},
 {id:'groups',name:'Configured application paths',url:'/api/zscaler/zpa/connector-apps',view:'noc-resilience',kind:'configuration'},
 {id:'snapshot',name:'ZCC inventory snapshot',url:'/api/zscaler/zcc/summary',view:'zcc',kind:'snapshot'},
 {id:'feeds',name:'Collector freshness',url:'/api/feeds/freshness?page=zscaler-command-center',view:'noc-coverage',kind:'collection'},
 {id:'lss',name:'ZPA session log coverage',url:'/api/zscaler/zpa/traffic/status',view:'routes',kind:'events'},
 {id:'nss',name:'ZIA inspection log coverage',url:'/api/zscaler/nss/ssl/status',view:'sslerr',kind:'events'},
 {id:'activation',name:'ZIA activation status',url:'/api/zscaler/zia/activation-status',view:'noc-policy',kind:'configuration'},
 {id:'ssl',name:'SSL inspection policy',url:'/api/zscaler/zia/ssl-inspection-rules',view:'noc-policy',kind:'configuration'},
 {id:'posture',name:'ZPA posture profiles',url:'/api/zscaler/zpa/posture-profiles',view:'noc-policy',kind:'configuration'},
 {id:'trust',name:'ZPA trusted networks',url:'/api/zscaler/zpa/trusted-networks',view:'noc-policy',kind:'configuration'},
 {id:'certs',name:'ZPA browser-access certificates',url:'/api/zscaler/zpa/ba-certificates',view:'noc-policy',kind:'configuration'}
];
function num(v){if(v==null||v===''||typeof v==='boolean')return null;var n=Number(v);return Number.isFinite(n)?n:null;}
function text(v){return typeof v==='string'?v.slice(0,220):null;}
function ts(v){if(v==null||v==='')return null;var n=num(v);if(n!=null){if(n>=1e14)n/=1000;else if(n<1e11)n*=1000;return n>0?n:null;}var t=Date.parse(String(v).replace(' ','T'));return Number.isFinite(t)?t:null;}
function list(v,cap){return Array.isArray(v)&&v.length<=cap&&v.every(function(x){return x&&typeof x==='object'&&!Array.isArray(x);});}
function pick(o,keys){var result={};keys.forEach(function(k){var x=o&&o[k];if(typeof x==='string')result[k]=text(x);else if(typeof x==='number')result[k]=num(x);else if(typeof x==='boolean'||x===null)result[k]=x;});return result;}
function connectorState(c){var s=String(c.ctrlChannelStatus||c.controlChannelStatus||'').toUpperCase();if(c.enabled===false)return 'disabled';if(c.enabled!==true)return 'unknown';if(['ZPN_STATUS_AUTHENTICATED','AUTHENTICATED'].includes(s))return 'connected';if(['ZPN_STATUS_DISCONNECTED','DISCONNECTED','ZPN_STATUS_NOT_ENROLLED'].includes(s))return 'disconnected';return 'unknown';}
function project(id,d){
 if(!d||typeof d!=='object'||Array.isArray(d)||d.ok===false||d.error)return null;
 if(id==='zia'){if(!list(d.rules,10000))return null;return {count:d.rules.length,fromCache:d.fromCache===true,fetchedAt:ts(d.synced_at)};}
 if(id==='zpa'){
  if(!list(d.connectors,2000))return null;
  var conns=d.connectors.map(function(c){var r=pick(c,['id','name','enabled','appConnectorGroupName','currentVersion','expectedVersion','ctrlChannelStatus','controlChannelStatus','statusDerived','lastBrokerConnectTime','lastBrokerDisconnectTime']);r.state=connectorState(c);return r;});
  return {connectors:conns,source:d.source==='connector'?'Connector API':/fallback|appConnectorGroup/.test(String(d.source||''))?'App connector groups (fallback)':'Source not reported',fallback:/fallback|appConnectorGroup/.test(String(d.source||'')),partial:d.truncated===true};
 }
 if(id==='groups'){if(!list(d.groups,2000))return null;return {groups:d.groups.map(function(g){return {id:g.id==null?null:String(g.id).slice(0,80),name:text(g.name),apps:Array.isArray(g.apps)?g.apps.filter(function(a){return typeof a==='string';}).slice(0,2000).map(text):[],serverGroups:Array.isArray(g.serverGroups)?g.serverGroups.filter(function(a){return typeof a==='string';}).slice(0,200).map(text):[]};})};}
 if(id==='zcc'){if(!list(d.devices,15000))return null;return {count:d.devices.length,partial:d.truncated===true,pages:num(d.pagesFetched)};}
 if(id==='zdx'){if(!list(d.apps,3000))return null;return {apps:d.apps.slice(0,200).map(function(a){return {id:a.id==null?null:String(a.id).slice(0,80),name:text(a.name),score:num(a.score)};}),window:{from:ts(d.window&&(d.window.fromUnixSec||d.window.from)),to:ts(d.window&&(d.window.toUnixSec||d.window.to))},partial:d.truncated===true||d.apps.length>200,returnedCount:d.apps.length};}
 if(id==='zwa'){if(!list(d.incidents,20000)&&num(d.count)==null)return null;return {count:num(d.count)==null?d.incidents.length:num(d.count),partial:d.truncated===true};}
 if(id==='snapshot'){if(!d.totals||typeof d.totals!=='object')return null;return {totals:pick(d.totals,['total','registered','deregistered','active_24h','stale_30d']),lastSync:ts(d.lastSync),osDist:list(d.osDist,100)?d.osDist.map(function(r){return pick(r,['device_type','c']);}):[]};}
 if(id==='feeds'){if(!list(d.feeds,200))return null;return {feeds:d.feeds.map(function(f){var r=pick(f,['key','label','state','ageHours','maxAgeH','collector','producerFailing','producerAbandoned','producerOverdue','freshnessBasis','sourceOldestAt','sourceNewestAt','storedUpdatedAt','reason','collectionMode','scheduled']);r.lastRun=pick(f.lastRun,['exitCode','ageHours','startAgeHours']);return r;})};}
 if(id==='lss'||id==='nss'){if(d.reason)return {unavailable:true,note:/no such table|table not present/i.test(String(d.reason))?'Log store schema not present on this server':/not found|not present|ENOENT/i.test(String(d.reason))?'Log store not present on this server':'Log store read failed'};return {streaming:d.streaming===true,events:num(d.events),lastTs:ts(d.lastTs),windowHours:num(d.hours)};}
 if(id==='activation')return {configured:d.configured!==false&&d.item!=null,status:typeof d.item==='string'?text(d.item):text(d.item&&d.item.status),fetchedAt:ts(d.fetchedAt),fromCache:d.fromCache===true};
 if(['ssl','posture','trust','certs'].includes(id)){if(!list(d.items,10000))return null;return {count:d.items.length,fetchedAt:ts(d.fetchedAt),fromCache:d.fromCache===true,items:id==='certs'?d.items.slice(0,100).map(function(c){return pick(c,['name','expirationTime','expiryTime','validTo']);}):undefined};}
 return null;
}
function response(id,r,now){var def=definitions.find(function(d){return d.id===id;});if(!def)return null;var d=r&&r.data,received=r&&r.receivedAt||now;
 var upstream=num(d&&d.upstreamStatus),match=String(d&&d.error||'').match(/HTTP\s+(\d{3})/i);if(upstream==null&&match)upstream=Number(match[1]);
 var state=d&&d.code==='ZDX_API_NOT_INCLUDED'?'not_included':!r?'unknown':r.status===401?'auth':r.status===403?'denied':r.status===408?'timeout':!r.ok?upstream===403?'denied':'error':'ok';
 var data=state==='ok'?project(id,d):null;if(state==='ok'&&!data)state='unknown';if(state==='ok'&&data.partial)state='partial';
 var note=state==='not_included'?'ZDX Standard: API telemetry is not collected. ZCC inventory/check-in remains available.':null;if(state==='ok'&&data.unavailable){note=data.note;data=null;state='error';}
 return {id:id,name:def.name,view:def.view,url:def.url,kind:def.kind,window:def.window||'Point-in-time / source-defined',state:state,status:num(r&&r.status),upstreamStatus:upstream,receivedAt:received,responseTimeMs:num(r&&r.elapsedMs),note:note,data:data};
}
function fresh(r,now){return !!r&&Number.isFinite(r.receivedAt)&&r.receivedAt<=now+30000&&now-r.receivedAt<=150000;}
function usable(r,now){return fresh(r,now)&&['ok','partial'].includes(r.state)&&!!r.data;}
function snapshotState(r,now){if(!usable(r,now))return 'unknown';var last=r.data.lastSync;return last==null?'unknown':last>now+30000?'unknown':now-last>86400000?'stale':'ok';}
function eventState(r,now){if(!usable(r,now))return 'unknown';var d=r.data;if(d.lastTs==null||d.lastTs>now+30000)return 'unknown';if(now-d.lastTs>900000)return 'stale';return d.streaming?'recent':'unknown';}
function collectionState(r,now){if(!usable(r,now)||!r.data.fetchedAt)return 'unknown';return r.data.fetchedAt>now+30000?'unknown':now-r.data.fetchedAt>86400000?'stale':'ok';}
function groups(sources,now){var c=sources.zpa,g=sources.groups;if(!usable(c,now))return [];var map=Object.create(null);c.data.connectors.forEach(function(x){var name=x.appConnectorGroupName||'Ungrouped';if(!map[name])map[name]={name:name,connected:0,enabled:0,disabled:0,unknown:0,drift:0,apps:null,fallback:c.data.fallback};var m=map[name];if(x.state==='disabled')m.disabled++;else if(x.enabled===true)m.enabled++;if(x.state==='connected')m.connected++;if(x.state==='unknown')m.unknown++;if(x.expectedVersion&&x.currentVersion&&x.expectedVersion!==x.currentVersion)m.drift++;});
 if(usable(g,now))g.data.groups.forEach(function(x){if(map[x.name])map[x.name].apps=x.apps;});return Object.keys(map).sort().map(function(k){return map[k];});}
function issues(sources,now){var out=[];definitions.forEach(function(d){var r=sources[d.id];if(!r||r.state==='pending'||r.state==='not_included')return;if(!fresh(r,now))out.push({id:d.id,title:d.name+' refresh stale',detail:'Last API response is no longer current',severity:'warn',view:'noc-coverage'});else if(!['ok','partial'].includes(r.state))out.push({id:d.id,title:d.name+' unavailable',detail:r.state==='denied'?'Read denied'+(r.upstreamStatus?' by upstream HTTP '+r.upstreamStatus:''):r.state==='auth'?'Console sign-in required':r.state==='timeout'?'Response timed out':r.state==='pending'?'Collection pending':r.note||'Source data could not be confirmed',severity:'warn',view:'noc-coverage'});else if(r.state==='partial')out.push({id:d.id,title:d.name+' is partial',detail:'Counts apply only to returned records',severity:'warn',view:'noc-coverage'});});
 definitions.forEach(function(d){var r=sources[d.id];if(usable(r,now)&&r.data.fetchedAt&&collectionState(r,now)==='stale')out.push({id:d.id,title:d.name+' snapshot is older than 24 hours',detail:'A recent API read returned older configuration; verify the collector or source cache',severity:'warn',view:'noc-coverage'});});
 groups(sources,now).forEach(function(g){if(g.enabled&&g.connected<g.enabled)out.push({id:'zpa',title:g.name+' connection evidence needs review',detail:g.connected+' of '+g.enabled+' enabled connectors report connected',severity:g.unknown?'warn':'bad',view:'noc-resilience',group:g.name});else if(g.enabled===1)out.push({id:'zpa',title:g.name+' has one enabled connector',detail:'Review intended redundancy · configured dependency, not a verified outage',severity:'warn',view:'noc-resilience',group:g.name});if(g.drift)out.push({id:'zpa',title:g.name+' version mismatch',detail:g.drift+' connector versions differ from expected',severity:'warn',view:'connectors'});});
 var feeds=sources.feeds;if(usable(feeds,now))feeds.data.feeds.forEach(function(f){if(f.state!=='not_included'&&(f.state!=='ok'||f.producerFailing||f.producerOverdue||f.producerAbandoned))out.push({id:'feeds',title:(f.label||f.key)+' collector needs review',detail:f.state==='stale'?'Last collection '+Math.round(num(f.ageHours)||0)+' hours ago':f.producerFailing?'Collector last failed':f.producerOverdue?'Collector overdue':f.producerAbandoned?'Collector outcome not recorded':'Collection '+(f.state||'unknown'),severity:'warn',view:'noc-coverage'});});
 ['lss','nss'].forEach(function(id){var r=sources[id];if(usable(r,now)&&eventState(r,now)!=='recent')out.push({id:id,title:r.name+' not confirmed current',detail:'Historical rows and a successful request do not establish ongoing ingestion',severity:'warn',view:'noc-coverage'});});
 if(usable(sources.snapshot,now)&&snapshotState(sources.snapshot,now)==='unknown')out.push({id:'snapshot',title:'ZCC check-in snapshot freshness unconfirmed',detail:'Collection time is missing or invalid; current check-in coverage is unknown',severity:'warn',view:'noc-coverage'});
 if(snapshotState(sources.snapshot,now)==='stale')out.push({id:'snapshot',title:'ZCC cached check-in coverage is stale',detail:'The 24-hour check-in count cannot establish current activity',severity:'warn',view:'noc-coverage'});
 var a=sources.activation;if(usable(a,now)&&a.data.status&&/pending|notactive|inactive/i.test(a.data.status))out.push({id:'activation',title:'ZIA configuration has pending activation',detail:'Read-only review; no activation is executed here',severity:'warn',view:'noc-policy'});
 return out.sort(function(a,b){return (a.severity==='bad'?0:1)-(b.severity==='bad'?0:1);});
}
window.ZscalerNocModel={definitions:definitions,num:num,time:ts,project:project,response:response,fresh:fresh,usable:usable,snapshotState:snapshotState,eventState:eventState,collectionState:collectionState,groups:groups,issues:issues,connectorState:connectorState};
})();
