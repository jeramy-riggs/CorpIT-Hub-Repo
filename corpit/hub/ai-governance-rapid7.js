'use strict';
const https=require('https'),crypto=require('crypto'),fs=require('fs');
const norm=v=>String(v||'').toLowerCase().replace(/[^a-z0-9]/g,'');
const FAMILIES=['Web Proxy Activity','SSO Authentication','Cloud Service Activity','DNS Query'];
const split=v=>String(v||'').split(/\r?\n|\\n|,/).map(x=>x.trim()).filter(Boolean);
const text=(v,max=255)=>typeof v==='string'||typeof v==='number'?String(v).slice(0,max):'';
const at=(obj,path)=>path.split('.').reduce((o,k)=>o&&o[k],obj);
const pick=(obj,keys,max=255)=>{for(const k of keys){const v=text(at(obj,k),max);if(v)return v;}return '';};
const iso=v=>{if(v==null||v==='')return null;let d;if(typeof v==='number')d=new Date(v<1e12?v*1000:v);else d=new Date(/^\d{10,13}$/.test(String(v))?Number(v)*(String(v).length===10?1000:1):v);return Number.isFinite(d.getTime())?d.toISOString():null;};
function host(v){if(!v)return '';try{const s=String(v).trim();const u=new URL(/^[a-z]+:\/\//i.test(s)?s:'https://'+s);const h=u.hostname.toLowerCase().replace(/\.$/,'');return /^[a-z0-9.-]+$/.test(h)&&h.includes('.')&&!/^[0-9.]+$/.test(h)?h:'';}catch{return '';}}
function client({env=process.env,sleep=ms=>new Promise(r=>setTimeout(r,ms)),now=Date.now,request}={}){
 const region=env.RAPID7_REGION||'us';if(!/^[a-z][a-z0-9-]{0,15}$/.test(region))throw new Error('Invalid Rapid7 region');
 const origin='https://'+region+'.api.insight.rapid7.com';let queue=Promise.resolve(),last=0,count=0,rateRemaining=null;
 const raw=request||function(url,{timeoutMs=15000,signal}={}){return new Promise((resolve,reject)=>{
  const req=https.get(url,{signal,headers:{'X-Api-Key':env.RAPID7_API_KEY,Accept:'application/json'}},res=>{let body='',bytes=0;res.on('data',d=>{bytes+=d.length;if(bytes>12*1024*1024)req.destroy(new Error('Response limit exceeded'));else body+=d;});res.on('end',()=>{let data;try{data=JSON.parse(body);}catch{data=null;}resolve({status:res.statusCode,headers:res.headers,body:data});});res.on('error',reject);res.on('aborted',()=>reject(new Error('Rapid7 response interrupted')));});req.setTimeout(timeoutMs,()=>req.destroy(new Error('Rapid7 request timed out')));req.on('error',reject);
 });};
 function target(path){const u=new URL(path,origin);if(u.origin!==origin||u.username||u.password||!(u.pathname==='/log_search/management/logsets'||u.pathname.startsWith('/log_search/query/')))throw new Error('Rejected Rapid7 continuation target');return u;}
 async function get(path,{deadline=Infinity,requestCeiling=Infinity}={}){
  if(!env.RAPID7_API_KEY&&!request)throw new Error('Rapid7 credentials are not configured');const u=target(path);
  const run=async()=>{
   const budget=()=>{if(count>=requestCeiling&&count<LIMITS.maxRequests)throw Object.assign(new Error('Requests reserved for remaining focused checks'),{code:'RESERVED_BUDGET'});if(count>=LIMITS.maxRequests||now()>=deadline)throw Object.assign(new Error('Rapid7 request/time budget reached'),{code:'BUDGET'});};budget();
   const delay=600-(now()-last);if(delay>0){if(now()+delay>=deadline)throw Object.assign(new Error('Rapid7 time budget reached'),{code:'BUDGET'});await sleep(delay);}
   async function send(){budget();count++;last=now();const timeoutMs=Math.max(1,Math.min(15000,deadline-now())),controller=new AbortController();let timer,r;
    try{r=await Promise.race([raw(u,{timeoutMs,signal:controller.signal}),new Promise((resolve,reject)=>{timer=setTimeout(()=>{const error=Object.assign(new Error('Rapid7 request timed out at absolute deadline'),{code:'RAPID7_TIMEOUT'});reject(error);controller.abort(error);},timeoutMs);})]);}finally{clearTimeout(timer);}
    const remaining=Number(r.headers?.['x-ratelimit-remaining']);if(Number.isFinite(remaining))rateRemaining=remaining;return r;}
   let r=await send();if(r.status===429){
    const n=Number(r.headers?.['retry-after']??r.headers?.['x-ratelimit-reset']??3),wait=Math.max(600,Number.isFinite(n)&&n>=0?n*1000:3000);
    if(wait>30000||now()+wait>=deadline)throw Object.assign(new Error('Rapid7 rate limit; previous evidence remains available'),{status:429});
    await sleep(wait);r=await send();
   }
   if(r.status!==200&&r.status!==202)throw Object.assign(new Error('Rapid7 HTTP '+r.status),{status:r.status});if(!r.body||typeof r.body!=='object')throw new Error('Unexpected Rapid7 response');return r.body;
  };const p=queue.then(run,run);queue=p.catch(()=>{});return p;
 }
 return {get,origin,sleep,now,stats:()=>({requests:count,rate_remaining:rateRemaining})};
}
const rawEventKey=e=>JSON.stringify([e.log_id||e.logId||e.log?.id||'',e.id||e.sequence_number_str||crypto.createHash('sha256').update(JSON.stringify(e)).digest('hex')]);
async function query(api,logset,leql,from,to,{maxEvents=2000,maxPages=10,maxPolls=20,perPage=500,deadline=Infinity,mostRecentFirst=false,stopWhen=null,emptyLowProgressPolls=0,emptyStagnantPolls=0,requestCeiling=Infinity}={}){
 const clock=api.now||Date.now,initial='/log_search/query/logsets/'+encodeURIComponent(logset.id)+'?'+new URLSearchParams({query:leql,from:String(from),to:String(to),per_page:String(Math.min(500,perPage,maxEvents)),...(mostRecentFirst?{most_recent_first:'true'}:{})});
 let path=initial,events=[],polls=0,pagePolls=0,pages=1,completed=false,partial=false,reason='',lastProgress=null,emptyLowProgressStall=false,emptyProgressStall=false,stableEmptyPolls=0;const seen=new Set(),pageStarts=new Set([initial]);
 while(path){
  if(clock()>=deadline){partial=true;reason='Query time budget reached';break;}
  if(api.stats&&api.stats().requests>=requestCeiling){partial=true;reason='Requests reserved for remaining focused checks';break;}
  let d;try{d=await api.get(path,{deadline,requestCeiling});}catch(e){if(!events.length)throw e;partial=true;reason=e.code==='RESERVED_BUDGET'?'Requests reserved for remaining focused checks':e.status?'Query continuation unavailable (HTTP '+e.status+')':'Query continuation unavailable or budget reached';break;}
  if(!Array.isArray(d.events)&&!(d.progress!=null&&Number.isFinite(Number(d.progress))))throw new Error('Unexpected Rapid7 event response');
  const added=[],previousLength=events.length;for(const e of d.events||[]){const key=rawEventKey(e);if(!seen.has(key)){seen.add(key);events.push(e);added.push(e);}}
  const progress=d.progress==null?null:Number(d.progress),running=progress!=null&&progress<100,links=d.links||[],next=links.find(l=>String(l.rel).toLowerCase()==='next');stableEmptyPolls=running&&!events.length&&progress===lastProgress?stableEmptyPolls+1:0;lastProgress=progress;
  if(stopWhen&&added.length&&stopWhen(added.slice(0,Math.max(0,maxEvents-previousLength)))){partial=true;reason='Normalized observation sample cap reached';break;}
  if(events.length>=maxEvents){completed=!running&&!next?.href;partial=!completed||events.length>maxEvents;reason=partial?'Event cap reached':'';break;}
  if(running){
   if(emptyStagnantPolls>0&&!events.length&&stableEmptyPolls>=emptyStagnantPolls){partial=true;emptyProgressStall=true;reason='Empty stalled-progress query stopped for bounded retry';break;}
   if(emptyLowProgressPolls>0&&!events.length&&progress<=5&&pagePolls>=emptyLowProgressPolls){partial=true;emptyLowProgressStall=true;reason='Empty low-progress query stopped for bounded retry';break;}
   const self=links.find(l=>String(l.rel).toLowerCase()==='self');if(!self?.href){partial=true;reason='Continuation missing while query running';break;}
   if(pagePolls>=maxPolls){partial=true;reason='Query still running at per-page poll limit';break;}
   if(clock()+1500>=deadline){partial=true;reason='Query time budget reached';break;}
   pagePolls++;polls++;await api.sleep(1500);path=self.href;
  }else if(next?.href){
   if(pages>=maxPages){partial=true;reason='Page cap reached';break;}
   if(pageStarts.has(next.href)){partial=true;reason='Repeated next-page continuation';break;}
   pageStarts.add(next.href);pages++;pagePolls=0;path=next.href;
  }else{completed=true;break;}
 }
 return {events:events.slice(0,maxEvents),partial,completed,reason,progress:lastProgress,polls,pages,...(emptyLowProgressStall?{empty_low_progress_stall:true}:{}),...(emptyProgressStall?{empty_progress_stall:true}:{})};
}


function vocabulary(catalog,definitions=[]){const names=new Map(),domains=[];for(const a of catalog){for(const n of [a.app_name,...split(a.aliases)]){const key=norm(n);if(!names.has(key))names.set(key,[]);names.get(key).push(a);}for(const d of split(a.domains)){const h=host(d.replace(/^\*\./,''));if(h)domains.push({domain:h,app:a,domain_count:split(a.domains).length});}}
 const zNames=new Map();for(const z of definitions){for(const n of [z.name,z.code]){const k=norm(n);if(k)zNames.set(k,z);}}return {catalog,names,domains,zNames};}
const realId=a=>!a.reference_only&&Number.isSafeInteger(Number(a.id))&&Number(a.id)>0;
function matchName(name,v){
 const n=norm(name);if(!n)return null;
 const allowed=a=>!(n.includes('githubcopilot')&&norm(a.app_name)==='microsoftcopilot');
 const exact=v.catalog.filter(a=>norm(a.app_name)===n&&allowed(a)),aliases=(v.names.get(n)||[]).filter(allowed);
 // Reference vocabulary describes capabilities; it must not compete with real inventory IDs.
 for(const pool of [exact.filter(realId),aliases.filter(realId)])if(pool.length){const ids=new Set(pool.map(a=>Number(a.id)));return ids.size===1?pool[0]:null;}
 for(const pool of [exact.filter(a=>!realId(a)),aliases.filter(a=>!realId(a))])if(pool.length)return new Set(pool.map(a=>norm(a.app_name))).size===1?pool[0]:null;
 return null;
}
function matchDomain(domain,v){const candidates=v.domains.filter(x=>!(norm(x.app.app_name)==='microsoftcopilot'&&(domain==='githubcopilot.com'||domain.endsWith('.githubcopilot.com')))&&(domain===x.domain||domain.endsWith('.'+x.domain))).sort((a,b)=>b.domain.length-a.domain.length||a.domain_count-b.domain_count);if(!candidates.length)return null;const best=candidates[0],ties=candidates.filter(x=>x.domain.length===best.domain.length&&x.domain_count===best.domain_count);return new Set(ties.map(x=>x.app.id)).size===1?best.app:null;}
function originOf(message,logName){const vendor=pick(message,['source_json.device_vendor','source_json.deviceVendor','source_json.vendor','device_vendor','vendor','event_source','source_json.event_source','source_json.product']);const s=(vendor+' '+logName).toLowerCase();if(/zscaler/.test(s))return 'Zscaler';if(/okta/.test(s))return 'Okta';if(/umbrella/.test(s))return 'Cisco Umbrella';if(/fortigate|fortinet/.test(s))return 'Fortinet';if(/cloudtrail/.test(s))return 'AWS CloudTrail';if(/box\.com/.test(s))return 'Box';if(/entra|azure\s*ad|office\s*365|microsoft\s*365/.test(s))return 'Microsoft Entra / M365';return vendor?text(vendor,100):'Original source not established';}
function normalize(event,ls,v){let m;try{m=typeof event.message==='string'?JSON.parse(event.message):event.message||{};}catch{return {skip:'unparsed'};}if(!m||typeof m!=='object')return {skip:'unparsed'};
 const logId=text(event.log_id||event.logId||event.log&&event.log.id||m.log_id,190),log=(ls.logs_info||[]).find(x=>String(x.id)===logId),logName=text(log&&log.name||'',190),origin=originOf(m,logName);
 let rawApp=pick(m,APP_FIELDS);const cloudService=pick(m,['source_json.eventSource']);if(/^(bedrock|bedrock-agent|bedrock-runtime)\.amazonaws\.com$/i.test(cloudService))rawApp='Amazon Bedrock';
 const domain=host(pick(m,DOMAIN_FIELDS))||host(rawApp)||(/^(bedrock|bedrock-agent|bedrock-runtime)\.amazonaws\.com$/i.test(cloudService)?cloudService:'');
 const rawZ=v.zNames.get(norm(rawApp)),app=matchName(rawZ?rawZ.name:rawApp,v)||matchDomain(domain,v),z=rawZ||(app?v.zNames.get(norm(app.app_name)):null);const aiCategory=pick(m,['category','url_category','source_json.extension.cat','source_json.category']);const aiSignal=/generative\s*ai|artificial\s*intelligence|ai\s*[&_/-]\s*ml/i.test(aiCategory);
 if(!app&&!z&&!/^bedrock(?:-agent|-runtime)?\.amazonaws\.com$/i.test(cloudService)&&!(aiSignal&&rawApp&&!/^(unknown|web\s*browsing|general)$/i.test(rawApp)))return {skip:'unmatched'};
 const occurred=iso(pick(m,['timestamp','time','event_time','source_json.published','source_json.timestamp']))||iso(event.timestamp);if(!occurred)return {skip:'missing_time'};
 const family=ls.name==='SSO Authentication'?'sso_authentication':ls.name==='Cloud Service Activity'?'cloud_activity':ls.name==='DNS Query'?'dns_query':'web_request';
 const identity=pick(m,['source_json.extension.usrName','account','user','source_user','user_name','username','source_json.actor.alternateId','source_json.userPrincipalName','source_json.user','actor.user.email_addr','actor.user.name'],190);
 const result=pick(m,['result','outcome','action','source_json.outcome.result','source_json.extension.act','source_json.action'],80),blocked=String(at(m,'is_blocked')||'').toLowerCase()==='true'||/block|denied|deny|fail/i.test(result);
 const sourceId=text(event.id,190)||pick(m,['source_json.extension.recordid','source_json.uuid','source_json.eventID','entry_id'],190)||text(event.sequence_number_str,190)||null;
 const name=text(app?app.app_name:z?z.name:rawApp,190),key=z?'z:'+z.code:app&&app.id?'catalog:'+app.id:'observed:'+crypto.createHash('sha256').update(norm(name)).digest('hex').slice(0,40);const fp=crypto.createHash('sha256').update(JSON.stringify(sourceId?[ls.id,logId,sourceId]:[ls.id,logId,occurred,identity,domain,rawApp,result])).digest('hex');
 return {fingerprint:fp,candidate_key:key,catalog_id:app?app.id:null,app_name:name,domain:domain||null,user_identity:identity||null,occurred_at:occurred,event_time_basis:pick(m,['timestamp','time','event_time','source_json.published','source_json.timestamp'])?'source_event_time':'Rapid7 event timestamp',logset_id:String(ls.id),logset_name:ls.name,log_id:logId||null,log_name:logName||null,source_event_id:sourceId,collector:'Rapid7 InsightIDR',original_source:origin,evidence_kind:family,result:result||null,blocked,raw_app_label:rawApp||null,raw_category:aiCategory||null,zscaler_code:z?z.code:null,zscaler_label:z?z.name:origin==='Zscaler'?rawApp||name:null,zscaler_category:z?z.parent:origin==='Zscaler'?aiCategory||null:null,match_basis:app?(app.reference_only?'Official vendor reference name; feature use not established':'Catalog name/domain match'):z?'Zscaler definition match':'AI-category signal; review required'};
}
// A unanimous concrete link for the same source application can fill an earlier
// empty link. Genuine conflicts remain unresolved and visible for review.
function groupLinks(observations){const links=new Map();for(const o of observations){let ids=links.get(o.candidate_key);if(!ids){ids=new Set();links.set(o.candidate_key,ids);}if(Number.isSafeInteger(Number(o.catalog_id))&&Number(o.catalog_id)>0)ids.add(Number(o.catalog_id));}return links;}
function reconcileGroups(observations){const links=groupLinks(observations);return observations.map(o=>{const ids=links.get(o.candidate_key);return !o.catalog_id&&ids.size===1?{...o,catalog_id:[...ids][0],match_basis:'Consistent catalog match within source application'}:{...o};});}
function aggregate(observations){
 const map=new Map(),links=groupLinks(observations);
 for(const o of observations){const occurred=iso(o.occurred_at);let a=map.get(o.candidate_key);
  if(!a){a={code:o.candidate_key,name:o.app_name,catalog_id:null,evidence_kind:'observed_activity',collector:'Rapid7 InsightIDR',origins:[],logsets:[],log_names:[],domains:[],source_refs:[],origin_counts:{},event_count:0,blocked_count:0,first_observed:occurred,last_observed:occurred,zscaler_code:o.zscaler_code||null,zscaler_label:o.zscaler_label||null,zscaler_category:o.zscaler_category||null,match_basis:o.match_basis};map.set(o.candidate_key,a);}
  if(!a.zscaler_label&&o.zscaler_label)a.zscaler_label=o.zscaler_label;
  if(!a.zscaler_code&&o.zscaler_code)a.zscaler_code=o.zscaler_code;
  if(!a.zscaler_category&&o.zscaler_category)a.zscaler_category=o.zscaler_category;
  if(o.catalog_id&&o.match_basis)a.match_basis=o.match_basis;
  a.event_count++;a.origin_counts[o.original_source]=(a.origin_counts[o.original_source]||0)+1;
  let ref=a.source_refs.find(r=>r.logset_id===o.logset_id&&r.log_id===o.log_id&&r.original_source===o.original_source);
  if(!ref){ref={logset_id:o.logset_id,logset_name:o.logset_name,log_id:o.log_id,log_name:o.log_name,original_source:o.original_source,evidence_kind:o.evidence_kind,count:0};a.source_refs.push(ref);}ref.count++;
  if(o.blocked)a.blocked_count++;
  for(const [key,value] of [['origins',o.original_source],['logsets',o.logset_name],['log_names',o.log_name],['domains',o.domain]])if(value&&!a[key].includes(value))a[key].push(value);
  if(occurred<a.first_observed)a.first_observed=occurred;if(occurred>a.last_observed)a.last_observed=occurred;
 }
 for(const a of map.values()){const ids=[...links.get(a.code)].sort((x,y)=>x-y);if(ids.length===1)a.catalog_id=ids[0];else if(ids.length>1){a.catalog_conflicts=ids;a.match_basis='Conflicting inventory records; review required';}}
 return [...map.values()].sort((a,b)=>b.event_count-a.event_count);
}
function makeQuery(catalog){const escape=s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),terms=new Set(['generative ai','artificial intelligence','AI & ML','claude','chatgpt','copilot','openai','anthropic','gemini','perplexity','bedrock','cursor','grammarly','dovetail','zoom','darktrace','amplitude','loopio']);for(const a of catalog)for(const d of split(a.domains)){const h=host(d);if(h)terms.add(h);}const batches=[[]];let length=0,count=0,partial=false;for(const t of terms){const e=escape(t);if(e.length>680||count>=180){partial=true;continue;}if(length+e.length+1>680){if(batches.length>=4){partial=true;break;}batches.push([]);length=0;}batches[batches.length-1].push(e);length+=e.length+1;count++;}const queries=batches.filter(b=>b.length).map(b=>'where(/'+b.join('|')+'/i)');return {leql:queries[0],queries,term_count:count,vocabulary_limited:partial};}
const APP_FIELDS=Object.freeze(['application','app','application_name','app_name','source_json.extension.app','source_json.extension.appname','source_json.appDisplayName','source_json.target.application.name','source_json.application','source_json.app','target.application.name','source_json.service','source_json.app_name','service']);
const DOMAIN_FIELDS=Object.freeze(['url_host','top_private_domain','source_json.extension.dhost','source_json.extension.request','source_json.request','query','query_name','dns_query','dns_question','source_json.query','source_json.query_name','domain','url']);
const LIMITS=Object.freeze({maxRequests:240,totalMs:300000,broadFamilyMs:30000,broadRawPerFamily:2000,broadNormalizedPerFamily:400,focusApps:24,focusMinObservations:30,focusRawPerQuery:100,focusNormalizedPerApp:30,focusQueryMs:20000,maxObservations:2000,maxPollsPerPage:20,maxPagesPerQuery:10});
const CLOUD_DISCOVERY=Object.freeze({nativeRaw:200,nativeNormalized:200,nativeMs:8000,broadPageSize:250,recoveryMs:6000,recoveryRaw:400});
const CLOUD_NATIVE_QUERY='where(source_json.eventSource IIN ["bedrock.amazonaws.com","bedrock-agent.amazonaws.com","bedrock-runtime.amazonaws.com"])';
// A bounded, cycle-scoped operator request reserves existing slots, never new
// capacity. Keep the request independent of observed candidates: an empty check
// must not silently lose its requested place because it produced no activity.
function readFocusRequest(){try{return JSON.parse(fs.readFileSync(__dirname+'/ai-governance-rapid7-priority.json','utf8'));}catch(e){return e.code==='ENOENT'?null:{invalid:true};}}
function requestedChecks(request,when){
 if(!request)return {status:'none',targets:[]};
 const cycle=Date.parse(request.cycle),items=request.targets;
 if(!Number.isFinite(cycle)||cycle%3600000!==0||typeof request.id!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(request.id)||!Array.isArray(items)||!items.length||items.length>LIMITS.focusApps||items.some(x=>!x||typeof x!=='object'||!Number.isSafeInteger(x.catalog_id)||x.catalog_id<=0||!FAMILIES.includes(x.family))||new Set(items.map(x=>x.catalog_id)).size!==items.length)return {status:'invalid',targets:[]};
 const status=when<cycle?'pending':when>=cycle+300000?'expired':'active';
 return {id:request.id,cycle:new Date(cycle).toISOString(),expires_at:new Date(cycle+300000).toISOString(),status,targets:status==='active'?items.map(x=>({catalog_id:x.catalog_id,family:x.family})):[]};
}
function focusHistory(catalog,previous,request,when){
 const allowed=new Set(catalog.filter(realId).map(a=>Number(a.id))),records=new Map();
 const add=row=>{const id=Number(row?.catalog_id),at=Date.parse(row?.last_attempted_collection_at);if(!allowed.has(id)||!Number.isFinite(at)||at>when||typeof row?.run_id!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(row.run_id))return;
  if(!records.has(id)||Date.parse(records.get(id).last_attempted_collection_at)<at)records.set(id,{catalog_id:id,last_attempted_collection_at:new Date(at).toISOString(),run_id:row.run_id});};
 if(request?.coverage_history_seed?.version===1&&Array.isArray(request.coverage_history_seed.apps))for(const r of request.coverage_history_seed.apps)add(r);
 if(previous?.focus_history?.version===1&&Array.isArray(previous.focus_history.apps))for(const r of previous.focus_history.apps)add(r);
 for(const c of previous?.application_checks||[])if(c.queries_attempted>0)add({catalog_id:c.catalog_id,last_attempted_collection_at:previous.checked_at,run_id:previous.run_id});
 return [...records.values()].sort((a,b)=>a.catalog_id-b.catalog_id);
}
function focusedPlan(catalog,previous,observed,when,request=null){
 const focusVocabulary=vocabulary(catalog);
 const counts=new Map();for(const o of observed){const id=Number(o.catalog_id);if(Number.isSafeInteger(id)&&id>0)counts.set(id,(counts.get(id)||0)+1);}
 const prior=new Set((previous?.candidates||[]).map(x=>Number(x.catalog_id))),referenceNames=new Set(catalog.filter(x=>x.reference_only).map(x=>norm(x.app_name)));
 const apps=[...new Map(catalog.filter(realId).map(a=>[Number(a.id),a])).values()].filter(a=>(counts.get(Number(a.id))||0)<LIMITS.focusMinObservations).sort((a,b)=>Number(a.id)-Number(b.id));
 const requestState=requestedChecks(request,when),allApps=[...new Map(catalog.filter(realId).map(a=>[Number(a.id),a])).values()],requested=requestState.targets.map(t=>({app:allApps.find(a=>Number(a.id)===t.catalog_id),family:t.family})).filter(t=>t.app),requestedIds=new Set(requested.map(t=>Number(t.app.id)));
 const normalApps=apps.filter(a=>!requestedIds.has(Number(a.id)));
 const thin=normalApps.filter(a=>counts.has(Number(a.id))).sort((a,b)=>counts.get(Number(a.id))-counts.get(Number(b.id))||Number(a.id)-Number(b.id));
 const reference=normalApps.filter(a=>!counts.has(Number(a.id))&&referenceNames.has(norm(a.app_name))).sort((a,b)=>String(a.app_name).localeCompare(String(b.app_name)));
 const priorApps=normalApps.filter(a=>!thin.includes(a)&&!reference.includes(a)&&prior.has(Number(a.id))),other=normalApps.filter(a=>!thin.includes(a)&&!reference.includes(a)&&!prior.has(Number(a.id)));
 const slots=Math.max(0,LIMITS.focusApps-requested.length-thin.length-reference.length),priorSlots=Math.min(priorApps.length,other.length?Math.ceil(slots/2):slots),otherSlots=Math.min(other.length,slots-priorSlots);
 const rotate=(rows,size)=>{const offset=rows.length?(Math.floor(when/3600000)*Math.max(1,size))%rows.length:0;return rows.slice(offset).concat(rows.slice(0,offset));};
 const history=focusHistory(catalog,previous,request,when),lastAttempt=new Map(history.map(r=>[r.catalog_id,r])),age=a=>Date.parse(lastAttempt.get(Number(a.id))?.last_attempted_collection_at)||0;
 const fair=history.length>0,rotating=fair?[...priorApps,...other].sort((a,b)=>age(a)-age(b)||Number(a.id)-Number(b.id)).slice(0,slots):[...rotate(priorApps,priorSlots).slice(0,priorSlots),...rotate(other,otherSlots).slice(0,otherSlots)];
 const chosen=[...requested.map(t=>t.app),...thin,...reference,...rotating];
 const selected=chosen.slice(0,LIMITS.focusApps).map(a=>{
  // A shared alias/domain can resolve to another concrete inventory entry.
  // Do not spend this app's bounded query sample on that other entry's traffic.
  // Normalization remains authoritative; this only narrows query vocabulary.
  const entries=[];let excludedTerms=0;
  for(const value of new Set([a.app_name,...split(a.aliases)].map(x=>String(x||'').trim()).filter(x=>x.length>=3))){
   if(Number(matchName(value,focusVocabulary)?.id)===Number(a.id))entries.push({kind:'name',value});else excludedTerms++;
  }
  for(const d of split(a.domains)){const value=host(d.replace(/^\*\./,''));if(!value)continue;
   if(Number(matchDomain(value,focusVocabulary)?.id)===Number(a.id))entries.push({kind:'domain',value});else excludedTerms++;
  }
  const batches=[[]];let length=0,limited=false;
  for(const item of entries){const size=JSON.stringify(item.value).length+1;if(size>680){limited=true;continue;}if(length+size>680){if(batches.length>=2){limited=true;break;}batches.push([]);length=0;}batches[batches.length-1].push(item);length+=size;}
  const queries=batches.filter(x=>x.length).map(batch=>{
   const names=batch.filter(x=>x.kind==='name').map(x=>JSON.stringify(x.value)),domains=batch.filter(x=>x.kind==='domain').map(x=>x.value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'));
   const clauses=[];if(names.length)clauses.push(APP_FIELDS.join(',')+' IIN ['+names.join(',')+']');
   if(domains.length)clauses.push(DOMAIN_FIELDS.join(',')+'=/(^|:\\/\\/|\\.)('+domains.join('|')+')([\\/:?#]|$)/i');
   return 'where('+clauses.join(' OR ')+')';
  });
  // Exact hosts must already have positive evidence for this entry and still
  // resolve to it under the current most-specific domain ownership rules.
  const hosts=[...new Set([...observed.filter(o=>Number(o.catalog_id)===Number(a.id)).map(o=>o.domain),...(previous?.candidates||[]).filter(o=>Number(o.catalog_id)===Number(a.id)).flatMap(o=>o.domains||[])].map(host).filter(h=>h&&Number(matchDomain(h,focusVocabulary)?.id)===Number(a.id)))].sort();
  const hostBatches=[[]];let hostSize=0;for(const h of hosts){const size=JSON.stringify(h).length+1;if(size>680)continue;if(hostSize+size>680){if(hostBatches.length>=2)break;hostBatches.push([]);hostSize=0;}hostBatches.at(-1).push(h);hostSize+=size;}
  const nativeHostQueries=hostBatches.filter(x=>x.length).map(x=>'where(url_host IIN ['+x.map(JSON.stringify).join(',')+'])');
  const nativeQueries=batches.map(batch=>batch.filter(x=>x.kind==='name').map(x=>JSON.stringify(x.value))).filter(names=>names.length).map(names=>'where(source_json.extension.appname IIN ['+names.join(',')+'])');const nativeSsoQueries=batches.map(batch=>batch.filter(x=>x.kind==='name').map(x=>JSON.stringify(x.value))).filter(names=>names.length).map(names=>'where(service IIN ['+names.join(',')+'])');const broadCount=counts.get(Number(a.id))||0;return {catalog_id:Number(a.id),name:a.app_name,queries,native_queries:nativeQueries,native_host_queries:nativeHostQueries,native_sso_queries:nativeSsoQueries,native_cloud_queries:nativeSsoQueries,excluded_term_count:excludedTerms,broad_observation_count:broadCount,coverage_last_attempted_collection_at:lastAttempt.get(Number(a.id))?.last_attempted_collection_at||null,coverage_history_basis:fair?'Recorded collector attempts; history may be incomplete':null,requested_family:requested.find(t=>Number(t.app.id)===Number(a.id))?.family||null,selection_reason:requestedIds.has(Number(a.id))?'Requested cycle recheck · '+requested.find(t=>Number(t.app.id)===Number(a.id)).family:broadCount?'Broad sample below '+LIMITS.focusMinObservations+' observations':fair?'No broad observations; '+(lastAttempt.has(Number(a.id))?'oldest recorded attempt '+lastAttempt.get(Number(a.id)).last_attempted_collection_at:'no recorded focused attempt'):'No observations in broad sample',vocabulary_limited:limited||!queries.length};
 });const eligible=new Set([...apps.map(a=>Number(a.id)),...requestedIds]).size;return {selected,eligible,history,fair,omitted:Math.max(0,eligible-selected.length),request:{...requestState,selected:requested.map(t=>({catalog_id:Number(t.app.id),family:t.family})),unavailable:requestState.targets.filter(t=>!requestedIds.has(t.catalog_id))}};
}
async function collect({api,catalog,definitions=[],previous=null,hours=24,onProgress=()=>{},runId=crypto.randomUUID(),focusRequest=readFocusRequest()}){
 const started=api.now(),checked_at=new Date(started).toISOString(),to=started,from=to-hours*3600000,deadline=started+LIMITS.totalMs,v=vocabulary(catalog,definitions),q=makeQuery(catalog),sources=[],observations=[],seen=new Set();
 const d=await api.get('/log_search/management/logsets',{deadline});if(!Array.isArray(d.logsets))throw new Error('Unexpected Rapid7 logset inventory');
 const families=FAMILIES.map(name=>({ls:d.logsets.find(x=>x.name===name),name,status:null,count:0,queried_events:0,partial:false,completed:true,skipped:{},queries_attempted:0,queries_completed:0,polls:0,pages:0,notes:new Set()}));
 function consume(result,f,{target=null,cap=Infinity}={}){
  f.queried_events+=result.events.length;f.polls+=result.polls;f.pages+=result.pages;f.partial||=result.partial;f.completed&&=result.completed;if(result.reason)f.notes.add(result.reason);let accepted=0;
  for(const e of result.events){const n=normalize(e,f.ls,v);if(n.skip){f.skipped[n.skip]=(f.skipped[n.skip]||0)+1;continue;}if(target&&Number(n.catalog_id)!==target){f.skipped.focus_other_match=(f.skipped.focus_other_match||0)+1;continue;}if(seen.has(n.fingerprint))continue;
   if(accepted>=cap||observations.length>=LIMITS.maxObservations){f.partial=true;f.notes.add('Normalized observation sample cap reached');continue;}
   seen.add(n.fingerprint);observations.push(n);f.count++;accepted++;
  }return accepted;
 }
 async function search(f,leql,options){f.queries_attempted++;try{const {windowFrom=from,windowTo=to,...queryOptions}=options;const r=await query(api,f.ls,leql,windowFrom,windowTo,queryOptions);f.status=200;if(r.completed&&!r.partial)f.queries_completed++;return r;}catch(e){f.last_query_error=e.status?'Query unavailable (HTTP '+e.status+')':e.code==='RESERVED_BUDGET'?'Requests reserved for remaining focused checks':e.code==='BUDGET'?'Request/time budget reached':/timed out/.test(e.message)?'Rapid7 request timed out':'Query unavailable';f.partial=true;f.completed=false;f.notes.add(e.code==='RESERVED_BUDGET'?'Requests reserved for remaining focused checks':e.status?'Query unavailable (HTTP '+e.status+')':'Query unavailable or request/time budget reached');if(f.status!==200||[401,403].includes(e.status))f.status=e.status||null;return null;}}
 for(const f of families){
  if(!f.ls){f.partial=true;f.completed=false;f.notes.add('Log set not available to current credentials');continue;}
  onProgress(f.name+' · discovery');const familyDeadline=Math.min(deadline,api.now()+LIMITS.broadFamilyMs),cloud=f.name==='Cloud Service Activity',web=f.name==='Web Proxy Activity',webIncomplete=[];let raw=0,accepted=0,broadIncomplete=false;
  const plans=[...(cloud?[{name:'Native cloud service fields',leql:CLOUD_NATIVE_QUERY,native:true}]:[]),...q.queries.map((leql,i)=>({name:'Broad discovery batch '+(i+1),leql}))];if(cloud||web)f.discovery_checks=[];
  for(const [index,plan] of plans.entries()){
   if(raw>=LIMITS.broadRawPerFamily||api.now()>=familyDeadline){f.partial=true;f.completed=false;f.notes.add('Discovery event/time budget reached; focused inventory checks reserved separately');break;}
   if(cloud&&!plan.native&&raw>=LIMITS.broadRawPerFamily-CLOUD_DISCOVERY.recoveryRaw){f.partial=true;f.completed=false;broadIncomplete=true;f.notes.add('Broad Cloud raw budget reached; remaining raw capacity reserved for native recovery');break;}
   if((cloud||web)&&accepted>=LIMITS.broadNormalizedPerFamily){f.partial=true;f.completed=false;f.notes.add('Discovery normalized sample cap reached; remaining batches not read');break;}
   const cap=Math.max(0,Math.min(LIMITS.broadNormalizedPerFamily-accepted,plan.native?CLOUD_DISCOVERY.nativeNormalized:Infinity)),queryStarted=api.now(),queryDeadline=web?Math.min(familyDeadline,queryStarted+Math.max(1,Math.floor((familyDeadline-6000-queryStarted)/(plans.length-index)))):!cloud?familyDeadline:Math.min(familyDeadline,queryStarted+(plan.native?CLOUD_DISCOVERY.nativeMs:Math.max(1,Math.floor((familyDeadline-CLOUD_DISCOVERY.recoveryMs-queryStarted)/(plans.length-index))))),pending=new Set();
   const stopWhen=(web||cloud&&!plan.native)?events=>{for(const e of events){const n=normalize(e,f.ls,v);if(!n.skip&&!seen.has(n.fingerprint))pending.add(n.fingerprint);}return pending.size>=cap;}:null;
   const result=await search(f,plan.leql,{maxEvents:Math.max(0,Math.min(LIMITS.broadRawPerFamily-raw-(cloud&&!plan.native?CLOUD_DISCOVERY.recoveryRaw:0),plan.native?CLOUD_DISCOVERY.nativeRaw:Infinity)),maxPages:LIMITS.maxPagesPerQuery,maxPolls:LIMITS.maxPollsPerPage,perPage:cloud&&!plan.native?CLOUD_DISCOVERY.broadPageSize:500,mostRecentFirst:!!plan.native,deadline:queryDeadline,stopWhen});
   if(cloud&&!plan.native&&(!result||result.partial||!result.completed))broadIncomplete=true;
   if(web&&(!result||result.partial||!result.completed))webIncomplete.push(plan);
   let added=0;if(result){raw+=result.events.length;added=consume(result,f,{cap});accepted+=added;}
   if(cloud||web)f.discovery_checks.push({name:plan.name,duration_ms:Math.max(0,api.now()-queryStarted),returned:result?.events.length||0,accepted:added,completed:!!result?.completed,partial:!result||result.partial,reason:result?.reason||(!result?f.last_query_error:'Query completed'),progress:result?.progress??null,polls:result?.polls||0,pages:result?.pages||0});
   if(!result&&[401,403].includes(f.status))break;
  }
  // Reissue only incomplete original Web predicates over the same full window.
  // Both initial batches and retries share the unchanged family/raw/sample caps.
  if(web&&webIncomplete.length&&accepted<LIMITS.broadNormalizedPerFamily&&raw<LIMITS.broadRawPerFamily&&api.now()<familyDeadline&&![401,403].includes(f.status)){
   const recoveryDeadline=Math.min(familyDeadline,api.now()+6000);
   for(const [index,plan] of webIncomplete.entries()){
    if(accepted>=LIMITS.broadNormalizedPerFamily||raw>=LIMITS.broadRawPerFamily||api.now()>=recoveryDeadline||[401,403].includes(f.status))break;
    const queryStarted=api.now(),cap=LIMITS.broadNormalizedPerFamily-accepted,pending=new Set(),stopWhen=events=>{for(const e of events){const n=normalize(e,f.ls,v);if(!n.skip&&!seen.has(n.fingerprint))pending.add(n.fingerprint);}return pending.size>=cap;};
    const result=await search(f,plan.leql,{maxEvents:LIMITS.broadRawPerFamily-raw,maxPages:LIMITS.maxPagesPerQuery,maxPolls:LIMITS.maxPollsPerPage,perPage:500,deadline:Math.min(recoveryDeadline,queryStarted+Math.max(1,Math.floor((recoveryDeadline-queryStarted)/(webIncomplete.length-index)))),stopWhen});
    let added=0;if(result){raw+=result.events.length;added=consume(result,f,{cap});accepted+=added;}
    f.discovery_checks.push({name:plan.name+' · original full-window retry',duration_ms:Math.max(0,api.now()-queryStarted),returned:result?.events.length||0,accepted:added,completed:!!result?.completed,partial:!result||result.partial,reason:result?.reason||(!result?f.last_query_error:'Query completed'),progress:result?.progress??null,polls:result?.polls||0,pages:result?.pages||0});
   }
   f.partial=true;f.completed=false;f.notes.add('Web discovery retries retain bounded evidence; earlier incomplete searches remain audited');
  }
  // Preserve broad discovery's reserved share before recovering known native
  // service evidence. This fills only unused sample slots; it never turns an
  // incomplete broad search into a complete discovery claim.
  if(cloud&&broadIncomplete&&accepted<LIMITS.broadNormalizedPerFamily&&raw<LIMITS.broadRawPerFamily&&api.now()<familyDeadline&&![401,403].includes(f.status)){
   const queryStarted=api.now(),cap=LIMITS.broadNormalizedPerFamily-accepted,pending=new Set(),stopWhen=events=>{for(const e of events){const n=normalize(e,f.ls,v);if(!n.skip&&!seen.has(n.fingerprint))pending.add(n.fingerprint);}return pending.size>=cap;};
   const result=await search(f,CLOUD_NATIVE_QUERY,{maxEvents:Math.min(CLOUD_DISCOVERY.recoveryRaw,LIMITS.broadRawPerFamily-raw),maxPages:LIMITS.maxPagesPerQuery,maxPolls:LIMITS.maxPollsPerPage,perPage:200,mostRecentFirst:true,deadline:Math.min(familyDeadline,queryStarted+CLOUD_DISCOVERY.recoveryMs),stopWhen});
   let added=0;if(result){raw+=result.events.length;added=consume(result,f,{cap});accepted+=added;}
   f.discovery_checks.push({name:'Native cloud service recovery',duration_ms:Math.max(0,api.now()-queryStarted),returned:result?.events.length||0,accepted:added,completed:!!result?.completed,partial:!result||result.partial,reason:result?.reason||f.last_query_error||'Query unavailable',progress:result?.progress??null,polls:result?.polls||0,pages:result?.pages||0});
   f.partial=true;f.completed=false;f.notes.add('Broad Cloud discovery remains incomplete after bounded native-service recovery');
  }
  if(q.vocabulary_limited){f.partial=true;f.notes.add('Broad discovery vocabulary limit reached');}
 }
 const broadFingerprints=new Set(observations.map(x=>x.fingerprint)),focus=focusedPlan(catalog,previous,reconcileGroups(observations),started,focusRequest),checks=[],acceptedById=new Map();
 for(const target of focus.selected){const check={catalog_id:target.catalog_id,name:target.name,broad_observation_count:target.broad_observation_count,selection_broad_observation_count:target.broad_observation_count,selection_reason:target.selection_reason,coverage_last_attempted_collection_at:target.coverage_last_attempted_collection_at,coverage_history_basis:target.coverage_history_basis,excluded_term_count:target.excluded_term_count,queries_planned:families.length*target.queries.length,queries_attempted:0,queries_completed:0,partial:target.vocabulary_limited,requested_family:target.requested_family,families:[]};checks.push(check);}
 // Run every explicitly requested family before other focused work. A Web cap
 // on an earlier family must not suppress the requested SSO/DNS/Cloud check.
 const work=focus.selected.flatMap(target=>families.map(f=>({target,f}))),ordered=[...work.filter(w=>w.f.name===w.target.requested_family),...work.filter(w=>w.f.name!==w.target.requested_family)];
 for(const [workIndex,{target,f}] of ordered.entries()){
  onProgress(('Focused inventory check · '+target.name+' · '+f.name).slice(0,100));const check=checks.find(c=>c.catalog_id===target.catalog_id);let accepted=acceptedById.get(target.catalog_id)||0;
  {let attempted=0,completed=0;const outcomes=[],web=f.name==='Web Proxy Activity',sso=f.name==='SSO Authentication',cloud=f.name==='Cloud Service Activity',dns=f.name==='DNS Query',nativeQueries=web?target.native_queries:sso?target.native_sso_queries:cloud?target.native_cloud_queries:[],familyDeadline=Math.min(deadline,api.now()+LIMITS.focusQueryMs),primaryDeadline=Math.min(familyDeadline,api.now()+12000);let incompleteMain=false;const fullWindowDone=new Set(),remainingMain=new Set(target.queries);
   async function attempt(leql,strategy,queryDeadline,{windowFrom=from,windowTo=to,perPage=30,emptyLowProgressPolls=0,emptyStagnantPolls=0}={}){
    if(!f.ls||[401,403].includes(f.status)||api.now()>=queryDeadline||accepted>=LIMITS.focusNormalizedPerApp){check.partial=true;return null;}
    const requestStart=api.stats?.().requests;let requestCeiling=Infinity;
    let webRecoveryReserved=0;
    if(Number.isFinite(requestStart)){
     const available=family=>family.ls&&![401,403].includes(family.status);
     const share=family=>family.name==='Cloud Service Activity'?3:2;let future=remainingMain.size*share(f);
     future+=ordered.slice(workIndex+1).filter(w=>available(w.f)).reduce((n,w)=>n+share(w.f)*w.target.queries.length,0);
     const recoveryCeiling=future>0?Math.max(requestStart,LIMITS.maxRequests-future):LIMITS.maxRequests;
     if(strategy==='Application/domain fields'){
      // A small positive Web sample already warrants recovery. Do not let a
      // slow main spend the last two requests in this family's available share
      // and thereby disable the native recovery that the share could fund.
      // Later originals keep their exact existing reservation; no capacity is
      // borrowed. When fewer than four requests are free, keep normal mains.
      const spare=recoveryCeiling-requestStart;
      if(web&&target.broad_observation_count>0&&target.broad_observation_count<LIMITS.focusMinObservations&&(target.native_host_queries.length||nativeQueries.length)&&spare>=4){requestCeiling=recoveryCeiling-2;webRecoveryReserved=2;}
     }else requestCeiling=future>0?recoveryCeiling:Infinity;
     if(strategy!=='Application/domain fields'&&requestStart>=requestCeiling){check.partial=true;f.partial=true;f.completed=false;f.notes.add('Requests reserved for remaining focused checks');outcomes.push({strategy,page_size:perPage,attempted:false,requests_used:0,duration_ms:0,returned:0,accepted:0,completed:false,partial:true,reason:'Requests reserved for remaining focused checks'});return null;}
    }
    const queryStarted=api.now(),pending=new Set(),stopWhen=events=>{for(const e of events){const n=normalize(e,f.ls,v);if(!n.skip&&Number(n.catalog_id)===target.catalog_id&&!seen.has(n.fingerprint))pending.add(n.fingerprint);}return pending.size>=LIMITS.focusNormalizedPerApp-accepted;};attempted++;check.queries_attempted++;const r=await search(f,leql,{maxEvents:LIMITS.focusRawPerQuery,maxPages:LIMITS.maxPagesPerQuery,maxPolls:LIMITS.maxPollsPerPage,perPage,mostRecentFirst:true,deadline:queryDeadline,windowFrom,windowTo,stopWhen,emptyLowProgressPolls,emptyStagnantPolls,requestCeiling});
    if(webRecoveryReserved&&r?.reason==='Requests reserved for remaining focused checks')r.reason='Web main request share reached; native recovery and later original checks reserved';
    if(r){if(windowFrom===from&&windowTo===to&&r.completed&&!r.partial&&target.queries.includes(leql))fullWindowDone.add(leql);const added=consume(r,f,{target:target.catalog_id,cap:Math.max(0,LIMITS.focusNormalizedPerApp-accepted)});accepted+=added;outcomes.push({strategy,page_size:perPage,...(webRecoveryReserved?{native_recovery_requests_reserved:webRecoveryReserved,main_request_ceiling:requestCeiling}:{}),...(Number.isFinite(requestStart)?{requests_used:api.stats().requests-requestStart}:{}),...(r.empty_low_progress_stall?{empty_low_progress_stall:true}:{}),...(r.empty_progress_stall?{empty_progress_stall:true}:{}),...(windowFrom!==from?{query_window:{from:new Date(windowFrom).toISOString(),to:new Date(windowTo).toISOString()}}:{}),duration_ms:Math.max(0,api.now()-queryStarted),returned:r.events.length,accepted:added,completed:r.completed,partial:r.partial,reason:r.reason||'Query completed',progress:r.progress,polls:r.polls,pages:r.pages});if(r.completed&&!r.partial){completed++;check.queries_completed++;}else check.partial=true;}else {check.partial=true;outcomes.push({strategy,page_size:perPage,...(windowFrom!==from?{query_window:{from:new Date(windowFrom).toISOString(),to:new Date(windowTo).toISOString()}}:{}),duration_ms:Math.max(0,api.now()-queryStarted),returned:0,accepted:0,completed:false,partial:true,reason:f.last_query_error||'Query unavailable'});}return r;
   }
   for(const leql of target.queries){remainingMain.delete(leql);const r=await attempt(leql,'Application/domain fields',primaryDeadline,{emptyLowProgressPolls:(web||cloud)?2:0,emptyStagnantPolls:(sso||dns)?2:0});if(!r||r.partial||!r.completed)incompleteMain=true;
    if(((web||cloud)&&r?.empty_low_progress_stall||(sso||dns)&&r?.empty_progress_stall)&&accepted<LIMITS.focusNormalizedPerApp&&![401,403].includes(f.status)&&primaryDeadline-api.now()>1000){
     check.queries_planned++;await attempt(leql,'Early full-window stalled-query retry',primaryDeadline);
    }
   }
   // Completed main queries already cover the native-label subset. Retry only
   // incomplete Web/SSO/Cloud checks with room for more unique observations, and share
   // the original twenty-second budget rather than extending collection time.
   const eligible=()=>incompleteMain&&!target.queries.every(leql=>fullWindowDone.has(leql))&&accepted<LIMITS.focusNormalizedPerApp&&f.ls&&![401,403].includes(f.status)&&api.now()<familyDeadline;
   if(web&&eligible()&&target.native_host_queries.length){
    check.queries_planned+=target.native_host_queries.length;
    const hostDeadline=Math.min(familyDeadline,api.now()+Math.min(3000,Math.max(1,Math.floor((familyDeadline-api.now())/(nativeQueries.length?2:1)))));
    const incompleteHosts=[];
    for(const leql of target.native_host_queries){const r=await attempt(leql,'Native observed-host fallback',hostDeadline);if(!r||r.partial||!r.completed)incompleteHosts.push(leql);}
    if(eligible()&&incompleteHosts.length&&familyDeadline-api.now()>1000){
     check.queries_planned+=incompleteHosts.length;
     const retryDeadline=nativeQueries.length?Math.max(api.now(),familyDeadline-2500):familyDeadline;
     for(const leql of incompleteHosts)await attempt(leql,'Native observed-host retry',retryDeadline);
    }
   }
   const recentCloud=cloud&&incompleteMain&&to-from>3600000;
   if((web||sso||cloud)&&eligible()&&nativeQueries.length){
    check.queries_planned+=nativeQueries.length;
    const nativeDeadline=(recentCloud||sso)?Math.min(familyDeadline,Math.max(api.now(),familyDeadline-4000)):familyDeadline;
    for(const leql of nativeQueries)await attempt(leql,cloud?'Native Cloud service fallback':sso?'Native SSO service fallback':'Native application-label fallback',nativeDeadline);
   }
   if(recentCloud&&eligible()&&familyDeadline-api.now()>1000){
    check.queries_planned+=target.queries.length;
    for(const leql of target.queries)await attempt(leql,'Recent-hour application/domain retry',familyDeadline,{windowFrom:Math.max(from,to-3600000)});
   }
   if(eligible()&&familyDeadline-api.now()>1000){
    const remaining=target.queries.filter(leql=>!fullWindowDone.has(leql));check.queries_planned+=remaining.length;
    for(const leql of remaining)await attempt(leql,'Full-window smaller-page retry',familyDeadline,{perPage:10});
   }
   const fullWindowCompleted=target.queries.length>0&&target.queries.every(leql=>fullWindowDone.has(leql));
   check.families.push({name:f.name,attempted,completed,outcomes,full_window_completed:fullWindowCompleted,full_window_recovered:incompleteMain&&fullWindowCompleted,note:!attempted?(accepted>=LIMITS.focusNormalizedPerApp?'Application sample cap reached':api.now()>=deadline?'Collection time budget reached':!f.ls?'Log set unavailable':'Not attempted under source/request limits'):undefined});
  }
  acceptedById.set(target.catalog_id,accepted);
 }
 for(const target of focus.selected){const check=checks.find(c=>c.catalog_id===target.catalog_id),accepted=acceptedById.get(target.catalog_id)||0;
  check.observation_count=observations.filter(x=>Number(x.catalog_id)===target.catalog_id).length;
  check.focused_observation_count=accepted;
  if(accepted>=LIMITS.focusNormalizedPerApp)check.partial=true;
  if(check.queries_attempted<check.queries_planned)check.partial=true;
  // Only terminal reads of every original predicate at its original full
  // window can restore focused coverage. Native/recent subsets never do.
  check.full_window_completed=!target.vocabulary_limited&&check.families.every(f=>f.full_window_completed);
  check.full_window_recovered=check.full_window_completed&&check.families.some(f=>f.full_window_recovered);
  if(check.full_window_completed&&accepted<LIMITS.focusNormalizedPerApp&&observations.length<LIMITS.maxObservations)check.partial=false;
  check.status=accepted?'Observed':check.observation_count?(check.partial?'Observed in broad sample; focused check incomplete':'Observed in broad sample; no additional focused records'):check.partial?'Not established; check incomplete':'No matching records returned by completed focused queries';if(check.full_window_recovered&&!check.partial)check.status=accepted?'Observed; original full-window focused queries completed after retry':'Original full-window focused queries completed after retry; no matching records';
 }
 for(const f of families){if(api.now()>=deadline){f.partial=true;f.notes.add('Collection time budget reached');}const {ls,notes,last_query_error,...record}=f;record.count=record.status===200?record.count:null;record.note=[...notes].map(x=>x+'.').join(' ')+' Discovery and focused name/alias/domain queries are bounded. Results overlap and observations are deduplicated. No returned record does not establish absence or complete activity coverage.';sources.push(record);}
 const reconciled=reconcileGroups(observations),candidates=aggregate(reconciled);
 // A focused observation can provide the first concrete link for an earlier
 // broad row in the same unanimous source group. Summarize after that linking
 // step, retaining the selection-time count so eligibility stays auditable.
 for(const check of checks){const rows=reconciled.filter(x=>Number(x.catalog_id)===check.catalog_id);check.observation_count=rows.length;check.broad_observation_count=rows.filter(x=>broadFingerprints.has(x.fingerprint)).length;check.broad_linked_after_selection=Math.max(0,check.broad_observation_count-check.selection_broad_observation_count);}
 // Retain real attempts even when they returned no activity. Merely selected
 // checks skipped by a shared budget do not advance the coverage queue.
 const savedHistory=new Map(focus.history.map(r=>[r.catalog_id,r]));for(const c of checks)if(c.queries_attempted>0)savedHistory.set(c.catalog_id,{catalog_id:c.catalog_id,last_attempted_collection_at:checked_at,run_id:runId});
 return {snapshot:{focus_history:{version:1,time_basis:'Source collection start timestamp; only checks with actual query attempts are recorded',basis:'Recorded focused attempts; an attempt is not completion, activity or entitlement',apps:[...savedHistory.values()].sort((a,b)=>a.catalog_id-b.catalog_id)},run_id:runId,checked_at,completed_at:new Date(api.now()).toISOString(),window:{from:new Date(from).toISOString(),to:new Date(to).toISOString(),hours},sources,candidates,application_checks:checks,query_scope:{focused_rotation:{strategy:focus.fair?'Least recently attempted absent apps':'Hour-offset bootstrap without recorded history',known_attempted_apps:focus.history.length,history_after_collection:savedHistory.size,policy:'Explicit cycle requests, small positive samples and reference-backed apps retain priority within the existing ceiling. Remaining absent slots prefer no recorded focused attempt, then oldest recorded attempt, with catalog ID ties. Saved history retains zero-result attempts; selected checks with no actual query attempt do not advance. History can be incomplete and does not establish absence, effective access or complete coverage.'},requested_checks:{...focus.request,policy:'Explicit cycle rechecks reserve existing focused slots and run each requested family first. They expire five minutes after the scheduled cycle starts. Remaining small positive samples retain count/ID priority. All existing limits, ownership and recovery rules remain in force; unavailable or incomplete checks remain unknown.'},strategy:'Bounded discovery plus structured focused checks for missing or small broad samples',focused_fields:'Exact case-insensitive application names/aliases and configured host/URL fields; message mentions excluded',web_discovery:{primaryShareMs:24000,recoveryMs:6000,perPage:500,policy:'Broad Web batches share the first twenty-four seconds; incomplete original predicates may be reissued once over the same original full window using up to six remaining seconds. All attempts share the unchanged thirty-second family, 2000-raw and 400-normalized discovery caps. Paging stops when the unique normalized sample fills. Earlier failures remain audited; capped, unread or incomplete searches remain unknown.'},cloud_discovery:{...CLOUD_DISCOVERY,policy:'Recognized Bedrock service fields sampled first; broad discovery uses smaller pages with six seconds and up to 400 raw records reserved for native-service recovery after an incomplete broad search. Recovery fills only unused sample slots within the same family limits. Other cloud services, unqueried batches and incomplete broad searches remain unknown.'},focused_cloud_retry:{primaryMs:12000,totalMs:20000,earlyMainRetry:true,emptyLowProgressPolls:2,emptyLowProgressMax:5,field:'service',recentWindowMs:3600000,recentReservedMs:4000,policy:'An empty Cloud main at no more than five percent progress after two polls may reissue its identical original full-window predicate once within the same twelve-second main share. Higher progress or any returned records suppress this early restart. Incomplete focused Cloud searches use an exact owned service subset, reserving up to four seconds for an application/domain retry over the most recent hour when the source window is longer. All attempts share the original twenty-second family budget and thirty-additional-record app cap. Smaller thirty-record pages stop when enough unique target records are found. Completed main searches are not retried. Native and recent-hour subsets do not complete an unfinished full-window search.'},focused_dns_retry:{primaryMs:12000,totalMs:20000,earlyMainRetry:true,emptyStagnantPolls:2,policy:'An empty focused DNS main with unchanged progress across two polls may reissue its identical original full-window predicate once within the same twelve-second main share. Advancing progress or any returned records suppress this early retry. Existing original-window smaller-page recovery shares the same twenty-second family deadline; incomplete checks remain unknown.'},focused_sso_retry:{primaryMs:12000,totalMs:20000,originalReservedMs:4000,earlyMainRetry:true,emptyStagnantPolls:2,field:'service',policy:'An empty SSO main with unchanged progress across two polls may reissue its original full-window predicate once inside the same twelve-second main share. Advancing progress or returned records suppress this early retry. Incomplete focused SSO searches can retry exact owned application names in the normalized service field within the same twenty-second SSO budget. The native service subset reserves up to four remaining seconds for the original full-window smaller-page retry within the same twenty-second deadline. Completed main searches are not retried. Native service results are a subset; incomplete broader application-field searches remain unknown.'},focused_web_retry:{primaryMs:12000,totalMs:20000,earlyMainRetry:true,emptyLowProgressPolls:2,emptyLowProgressMax:5,hostRetry:true,hostInitialMs:3000,nativeReservedMs:2500,field:'source_json.extension.appname',hostField:'url_host',policy:'An empty Web main query at no more than five percent progress after two polls may restart once at the same full window within the original twelve-second main share. Positive records or higher progress do not trigger this early retry; repeated stalls still leave coverage unknown. Incomplete Web checks first retry exact previously observed hostnames that still resolve to this inventory entry, conditionally retry an incomplete exact-host search once before owned native application labels when time and capacity remain. The first host attempt uses at most three seconds; a retry reserves 2.5 seconds for existing native-label recovery when configured. The retry uses the same positively owned hosts, original time window and thirty-record pages; duplicate fingerprints and other-app matches are rejected. The fallbacks share the original twenty-second family budget; thirty-record pages stop at the remaining unique target sample. Other inventory entries and duplicate fingerprints are rejected. Completed main queries are not retried; subset results leave broader coverage unknown.'},focused_full_window_retry:{primaryMs:12000,totalMs:20000,perPage:10,policy:'Incomplete focused main searches may retry their original predicates over the original full window with ten-record pages using only remaining family time. All attempts share the original twenty-second family budget, request/record caps and thirty-additional-record app cap. Focused coverage is restored only when every original predicate completes at the original full window; earlier timeouts remain in diagnostics. Native and recent-hour subset results never restore broader coverage. Empty focused Cloud mains at no more than five percent progress after two polls may reissue the identical original query once within the same twelve-second main share; higher progress or populated responses suppress this early retry. Empty focused DNS mains whose progress stays unchanged across two polls may reissue the identical original query once within the same twelve-second main share; advancing or populated responses suppress this early retry. Focused SSO native-service subsets reserve up to four remaining seconds for original full-window recovery inside the same twenty-second family budget.'},focused_request_reservation:{requestsPerRemainingMain:2,cloudRequestsPerRemainingMain:3,thinWebRecoveryRequests:2,thinWebMinimumSpare:4,policy:'Small positive Web samples preserve two requests for native recovery inside their available main share when at least four requests remain after reserving later original checks. Main and recovery keep the same family deadline, sample caps and global limits. Optional recovery attempts reserve two requests (three for Cloud) for each still-unstarted original query in later selected checks. Original main queries retain priority; reservations are best effort, not guaranteed completion. Shared global time/request/record limits still apply; exhausted or reserved attempts remain unknown.'},focused_order:'Newest first',focused_vocabulary:'Aliases and domains must resolve to the selected inventory entry; terms belonging to another entry are excluded',...LIMITS,term_count:q.term_count,query_batches_per_logset:q.queries.length,max_regex_characters:680,vocabulary_limited:q.vocabulary_limited,focus_eligible:focus.eligible,focus_selected:focus.selected.length,focus_omitted:focus.omitted,client:api.stats?api.stats():null},observation_count:reconciled.length,note:'Activity observations are not entitlements, grant dates, AI-feature enablement or governance approval. Apps below the broad-sample threshold remain eligible for focused checks. Cycle-scoped requested families are checked first within existing slots; otherwise small positive samples are checked first, ordered by observation count, followed by missing reference-backed apps and absent apps ordered by recorded attempt age when history is available. Recorded attempts are not enterprise-wide coverage; missing history is unknown. Focused checks add only deduplicated new observations within existing bounds. Unchecked or incomplete checks remain unknown. No raw message, full URL, prompt, response, IP or device payload is retained.'},observations:reconciled};
}


module.exports={APP_FIELDS,DOMAIN_FIELDS,client,query,vocabulary,normalize,makeQuery,collect,host,matchName,originOf,reconcileGroups,aggregate,focusedPlan,focusHistory,requestedChecks,LIMITS};
