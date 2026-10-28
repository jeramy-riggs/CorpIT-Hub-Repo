'use strict';
// AI USE-CASE ENRICHMENT 2026-10-20. Proposes workbook values for use cases from the sources
// configured on this hub, one row per field with its provenance (source system, record ID,
// date observed, confidence, match method). Values reach a use case only when a reviewer
// decides, or when a low-risk authoritative fact (AUTO below) fills a blank field.
// Never proposed: the InfoSec / Legal review section (risk tier, client approval, reviewer,
// review date, follow-up, disclosure window). Evidence limits stay explicit: Zscaler shows
// observation, not approval; Entra / Okta show assignment, not active use; Rapid7 shows
// telemetry, not purpose; vendor documentation shows availability, not configuration.
// Apps and use cases stay separate: a possible new app is routed to the existing Sources
// import flow, a possible new use case is a draft candidate until a reviewer creates it.
const crypto=require('node:crypto');
const model=require('./ai-governance-use-case-model');
const M=require('./ai-governance-maintenance');
const sourcesModule=require('./ai-governance-sources-routes');
const Z=require('./ai-governance-zscaler');
const shadow=require('./ai-governance-shadow-it');
const SYSTEM='system:use-case-enrichment',LOCK='corpit_aigov_uc_enrich';
const FIELDS=new Map(model.fields.map(f=>[f.key,f]));
const REQUIRED=model.fields.filter(f=>f.required).map(f=>f.key);
// Filled automatically only into a blank field, from a Verified / Confirmed source, when no
// other proposal for the field disagrees. 'mon' is the SIEM log-source status the spec lists
// as low-risk; 'siem' (whether the use case is fully logged) still needs a reviewer.
const AUTO=new Set(['dept','vendor','sso','intake','systems','mon','notes']);
const PROTECTED=new Set(['window','tier','capprov','revby','revdate','followup']);
// An app's sign-on setup says nothing about API, MCP, SDK or self-hosted use.
const NON_SSO_ACCESS=new Set(['API','MCP','SDK / library','In-house hosted model']);
const CONFIDENCE={verified:'Verified',confirmed:'Confirmed',inferred:'Inferred',needs_review:'Needs Review',unknown:'Unknown'};
const RANK={verified:0,confirmed:1,inferred:2,needs_review:3,unknown:4};
const STATE={complete:'Complete',prefilled:'Prefilled – awaiting review',conflicting:'Conflicting',unknown:'Unknown',missing:'Missing',not_applicable:'Not applicable'};
const LIVE=new Set(['open','matched']),KEPT=new Set(['accepted','auto_accepted','merged','matched']);
const FEDERATED={Entra:new Set(['saml','oidc']),Okta:new Set(['SAML_2_0','SAML_1_1','OPENID_CONNECT','WS_FEDERATION'])};
const SOURCES=[
 {key:'governance',name:'CorpIT AI Governance records',proves:'Vendor, owner, purpose and SSO status recorded by governance editors on the linked application',limit:'Application level: a use case may differ. A reported SSO status is not verified.'},
 {key:'identity_live',name:'Microsoft Entra and Okta app configuration (live read)',proves:'Federated sign-on mode and Entra app owners for app instances already linked to the catalog',limit:'Sign-on setup of the app, not that every user or API path uses it. The app owner is not necessarily the use-case technical owner.'},
 {key:'identity_access',name:'Entra and Okta assignments (hourly snapshot)',proves:'Accounts assigned through groups, direct assignment, licences or Okta',limit:'Assignment, not active use. Evidence only; no field is filled from it.'},
 {key:'rapid7',name:'Rapid7 InsightIDR activity (hourly snapshot)',proves:'Which SIEM log sources carry events for an app, with first and last observed times',limit:'Telemetry, not purpose or approval. Zscaler events carried by Rapid7 are not independent confirmation.'},
 {key:'zscaler',name:'Zscaler AI definitions and Shadow IT usage (hourly snapshot)',proves:'Observed users and transactions per app, and AI policy rules that name it',limit:'Observation, not approval. The Zscaler sanction tag is not a governance decision. Evidence only.'},
 {key:'entra',name:'Entra enterprise applications (hourly snapshot)',proves:'Enterprise apps present in the tenant',limit:'Presence does not prove use, licensing or an AI feature. Unmatched apps go to the Governance Queue; nothing is created automatically.'},
 {key:'vendor',name:'Official vendor capability references',proves:'Embedded AI feature names with dated vendor links',limit:'Vendor documentation shows availability, not that the feature is licensed, enabled or used. Evidence only.'},
 {key:'intake',name:'Access Portal AI intake (reviewer lookup)',proves:'Available request fields, status and source evidence after an authorized read',limit:'Search and confirm in Portal lookup. Submitted answers are proposals, not verified configuration; the requester is not assumed to be the business owner.'}
];
const NOT_USED=[
 {key:'portal_sync',name:'Access Portal ↔ AI Governance sync'},
 {key:'sdp',name:'ServiceDesk Plus',status:'not_used',note:'Connected for release change records only. No AI request records are read from it.'},
 {key:'forms',name:'Microsoft Forms / SharePoint intake lists',status:'not_configured'},
 {key:'ticketing',name:'ServiceNow / Jira',status:'not_configured'},
 {key:'procurement',name:'Procurement and contract records',status:'not_configured'},
 {key:'defender',name:'Microsoft Defender for Cloud Apps',status:'not_configured'},
 {key:'purview',name:'Microsoft Purview',status:'not_configured'},
 {key:'other_siem',name:'Other SIEM APIs',status:'not_configured'}
];
function fail(message,status=400){throw Object.assign(new Error(message),{status});}
const blank=v=>!String(v??'').trim();
const low=v=>String(v??'').trim().toLowerCase();
const same=(a,b)=>low(a)===low(b);
const parse=v=>v==null?null:typeof v==='string'?JSON.parse(v):v;
const iso=v=>M.stamp(v)?.toISOString()||null;
const sqlTime=v=>{const d=M.stamp(v);return d?d.toISOString().slice(0,19).replace('T',' '):null;};
const yes=v=>v===true||['true','yes','on','1'].includes(low(v));
const cut=(v,n)=>{const s=String(v??'');return s.length>n?s.slice(0,n-1)+'…':s;};
const uniq=a=>[...new Set(a.filter(Boolean))];
function fingerprint(target,field,source,record,value){return crypto.createHash('sha256').update([target,field,source,record,low(value)].join('\u0001')).digest('hex');}
// Workbook spelling of a proposed value, or the reason it cannot be proposed.
function clean(field,value){
 if(field==='name'||PROTECTED.has(field)||!FIELDS.has(field))return {problem:'not a proposable field'};
 if(blank(value))return {problem:'blank'};
 const r=model.check({name:'-',[field]:String(value).trim()});
 return r.problems.length?{problem:r.problems[0]}:{value:r.profile[field]};
}
function unknownValue(f){if(!f.allowed)return 'Unknown';return ['Unknown','Unsure','TBD'].find(x=>f.allowed.includes(x))||null;}
function fieldState(value,open){
 const vals=uniq(open.map(p=>low(p.proposed_value)));
 if(vals.length>1||(!blank(value)&&vals.some(v=>v!==low(value))))return 'conflicting';
 if(blank(value))return vals.length?'prefilled':'missing';
 if(['n/a','not applicable'].includes(low(value)))return 'not_applicable';
 if(['unknown','unsure','tbd'].includes(low(value)))return 'unknown';
 return 'complete';
}
// Summary: the workbook's 28 Summary formulas over the saved (approved) values.
const eq=(k,v)=>r=>same(r.p[k],v);
const SUMMARY=[
 ['Volume','Use cases recorded',r=>!blank(r.p.name)],
 ['Volume','Rows with required fields still blank',r=>Number(r.calc.required_blank)>0],
 ...['Production','Pilot / POC','In development','Retired'].map(v=>['By status',v,eq('status',v)]),
 ...FIELDS.get('cat').allowed.map(v=>['By category',v,eq('cat',v)]),
 ['Risk indicators','Processes NPI',eq('npi','Yes')],
 ['Risk indicators','Processes client data',eq('client','Yes')],
 ['Risk indicators','Processes consumer (SmartSale) data',eq('consumer','Yes')],
 ['Risk indicators','Output reaches external parties',eq('ext','Yes')],
 ['Risk indicators','Agentic',eq('agentic','Yes')],
 ['Risk indicators','Fully automated (no human review)',eq('oversight','Fully automated')],
 ['Risk indicators','Public / consumer instance',eq('instance','Public / consumer')],
 ['Risk indicators','Data sent to or retained by a third party',eq('third','Yes')],
 ['Risk indicators','Vendor training status Unknown or Not prohibited',r=>same(r.p.training,'Unknown')||same(r.p.training,'Not prohibited')],
 ['Risk indicators','Auto-flag: Review for High',r=>r.calc.auto_flag==='Review for High'],
 ['Control gaps','Not using Okta / SSO',r=>same(r.p.sso,'No')||same(r.p.sso,'Partial')],
 ['Control gaps','Logs not fully sent to SIEM (No, Partial, Unknown)',r=>['no','partial','unknown'].includes(low(r.p.siem))],
 ['Control gaps','No intake form submitted',eq('intake','No')],
 ...['Low','Medium','High'].map(v=>['InfoSec review status','Risk tier: '+v,eq('tier',v)]),
 ['InfoSec review status','Recorded but no risk tier assigned',null]
];
function summary(rows){
 const names=rows.filter(r=>!blank(r.p.name)).length,tiers=rows.filter(r=>!blank(r.p.tier)).length;
 return SUMMARY.map(([group,label,test])=>({group,label,count:test?rows.filter(test).length:names-tiers}));
}

// ---- Sources -------------------------------------------------------------------------
function snapshotState(snap,config,now=Date.now()){
 if(!config)return {status:'not_configured'};
 if(!config.enabled)return {status:'paused',checked_at:iso(snap?.checked_at)};
 if(!snap)return {status:'no_data'};
 const at=M.stamp(snap.checked_at),limit=Math.max(60,Number(config.interval_minutes)||60)*2*60000;
 const status=config.last_status==='failed'?'failed':!at||now-at>limit?'stale':config.last_status==='partial'?'partial':'current';
 return {status,checked_at:at?.toISOString()||null,last_status:config.last_status||null};
}
// Bounded live reads of app instances already linked to the catalog by the hourly identity
// snapshot. Own allowlist: only one service principal (and its owners) or one Okta app.
async function identityLive(instances,{fetchImpl=fetch,getToken=()=>require('./entra-sync').getAccessToken(),oktaOrigin=process.env.OKTA_BASE_URL,oktaToken=process.env.OKTA_API_TOKEN,budgetMs=25000,now=Date.now}={}){
 const deadline=now()+budgetMs,results=[],errors=[];let token=null,tokenError=null,requests=0;
 const ENTRA=/^\/v1\.0\/servicePrincipals\/[0-9a-f-]{36}(\/owners)?$/,OKTA=/^\/api\/v1\/apps\/[A-Za-z0-9]{1,64}$/;
 async function get(provider,path){
  if(now()>=deadline)throw Object.assign(new Error('time budget reached'),{code:'budget'});
  const origin=provider==='Entra'?'https://graph.microsoft.com':oktaOrigin;
  const u=new URL(path,origin),base=new URL(origin);
  if(u.protocol!=='https:'||u.origin!==base.origin||u.username||u.password||!(provider==='Entra'?ENTRA:OKTA).test(u.pathname))throw Object.assign(new Error('rejected path'),{code:'rejected'});
  requests++;
  const r=await fetchImpl(u,{method:'GET',redirect:'error',headers:{Authorization:provider==='Entra'?'Bearer '+token:'SSWS '+oktaToken,Accept:'application/json'},signal:AbortSignal.timeout(Math.max(1,Math.min(8000,deadline-now())))});
  if(!r.ok)throw Object.assign(new Error('HTTP '+r.status),{code:'http_'+r.status});
  return r.json();
 }
 const list=[...instances.values()].slice(0,40),entra=list.filter(x=>x.provider==='Entra'),okta=list.filter(x=>x.provider==='Okta');
 if(entra.length){try{token=await getToken();if(!token)throw new Error('no token');}catch{tokenError='Microsoft Graph credentials are not available';}}
 const one=async x=>{
  try{
   if(x.provider==='Entra'){
    if(tokenError)return errors.push({provider:'Entra',id:x.id,error:tokenError});
    if(!/^[0-9a-f-]{36}$/.test(x.id))return errors.push({provider:'Entra',id:x.id,error:'not a service principal ID'});
    const sp=await get('Entra','/v1.0/servicePrincipals/'+x.id+'?$select=id,appId,displayName,preferredSingleSignOnMode,servicePrincipalType,accountEnabled');
    let owners=null;try{const o=await get('Entra','/v1.0/servicePrincipals/'+x.id+'/owners?$select=id,displayName,userPrincipalName');owners=(o.value||[]).filter(v=>v['@odata.type']==='#microsoft.graph.user').map(v=>String(v.displayName||v.userPrincipalName||'').trim()).filter(Boolean);}catch(e){errors.push({provider:'Entra',id:x.id,error:'owners: '+(e.code||'request failed')});}
    results.push({...x,name:sp.displayName||x.name,mode:sp.preferredSingleSignOnMode||null,enabled:sp.accountEnabled!==false,owners,app_id:sp.appId||null});
   }else{
    if(!oktaOrigin||!oktaToken)return errors.push({provider:'Okta',id:x.id,error:'Okta API is not configured'});
    const a=await get('Okta','/api/v1/apps/'+encodeURIComponent(x.id));
    results.push({...x,name:a.label||x.name,mode:a.signOnMode||null,enabled:a.status==='ACTIVE',owners:null,okta_name:a.name||null});
   }
  }catch(e){errors.push({provider:x.provider,id:x.id,error:e.code||(/Timeout|Abort/.test(e.name)?'timeout':'request failed')});}
 };
 for(let i=0;i<list.length;i+=4)await Promise.all(list.slice(i,i+4).map(one));
 const status=!list.length?'current':!results.length?'failed':errors.length||instances.size>list.length?'partial':'current';
 return {results,errors,requests,status,checked_at:new Date().toISOString(),instances:instances.size,read:list.length};
}

// ---- Facts --------------------------------------------------------------------------------
// One fact = one field value from one source record. App-level facts are copied onto every
// use case and open draft of that app; each copy keeps the source record ID.
function governanceFacts(a){
 const out=[],at=iso(a.gov_updated_at),rec='ai_governance_app:'+a.id,sys='CorpIT AI Governance – application record';
 const add=(field,value,confidence,method,extra={})=>out.push({field,value,source_value:value,source_key:'governance',source_system:sys,source_record_id:rec,observed_at:at,confidence,match_method:method,...extra});
 if(!blank(a.vendor))add('vendor',a.vendor,'confirmed','Vendor recorded on the linked application by a governance editor');
 if(!blank(a.owner))add('bowner',a.owner,'inferred','Owner of the linked application; the use-case business owner may differ');
 if(!blank(a.business_purpose))add('what',a.business_purpose,'inferred','Purpose of the linked application; this use case may be narrower');
 const acct=parse(a.corporate_account)||{},map={configured:['Yes','confirmed','SSO recorded as configured on the corporate account'],not_applicable:['N/A','confirmed','SSO recorded as not applicable on the corporate account'],reported:['Yes','needs_review','SSO reported by a person; not verified against Entra or Okta']}[acct.sso_status];
 if(map)out.push({field:'sso',value:map[0],source_value:'sso_status: '+acct.sso_status+(acct.sso_provider?' ('+acct.sso_provider+')':''),source_key:'governance',source_system:'CorpIT AI Governance – corporate account record',source_record_id:'ai_governance_account:'+a.id,observed_at:iso(acct.verified_on)||iso(a.account_updated_at),confidence:map[1],match_method:map[2],evidence_note:cut(acct.sso_note||'',1000)||null,evidence_url:acct.sso_evidence_url||null});
 const risk=parse(a.risk_profile)||{};
 for(const [k,v] of Object.entries(risk)){
  if(k==='name'||k==='cat'||PROTECTED.has(k)||!FIELDS.has(k)||typeof v!=='string'||blank(v)||['unknown','unsure','tbd'].includes(low(v)))continue;
  out.push({field:k,value:v,source_value:v,source_key:'governance',source_system:'CorpIT AI Governance – application assessment',source_record_id:'ai_governance_risk:'+a.id,observed_at:iso(a.risk_updated_at),confidence:k==='vendor'||k==='sso'?'confirmed':'inferred',match_method:'Application-level assessment; this use case may differ'});
 }
 return out;
}
function identityFacts(r){
 const out=[],rec=(r.provider==='Entra'?'servicePrincipal:':'okta_app:')+r.id,sys=r.provider==='Entra'?'Microsoft Entra – enterprise application':'Okta – application';
 if(r.enabled&&FEDERATED[r.provider].has(r.mode))out.push({field:'sso',value:'Yes',source_value:(r.provider==='Entra'?'preferredSingleSignOnMode: ':'signOnMode: ')+r.mode,source_key:'identity_live',source_system:sys,source_record_id:rec,observed_at:r.checked_at,confidence:'verified',match_method:'Federated sign-on configured on app instance “'+cut(r.name,80)+'”, linked to this catalog app by the identity snapshot',evidence_note:'Sign-on setup of the app, not proof that every user or API path uses it.'});
 if(r.owners&&r.owners.length)out.push({field:'towner',value:cut(r.owners.join('; '),255),source_value:r.owners.join('; '),source_key:'identity_live',source_system:sys+' owners',source_record_id:rec,observed_at:r.checked_at,confidence:'inferred',match_method:'Owner of Entra app “'+cut(r.name,80)+'”; the use-case technical owner may differ'});
 return out;
}
function rapid7Facts(x,checked){
 const out=[],refs=Array.isArray(x.source_refs)?x.source_refs:[],origins=Object.keys(x.origin_counts||{}),rec='rapid7:'+x.code,at=iso(x.last_observed)||iso(checked);
 const logs=uniq(refs.map(r=>r.log_name?r.log_name+(r.logset_name?' ('+r.logset_name+')':''):null)).sort();
 if(logs.length)out.push({field:'mon',value:cut('Rapid7 InsightIDR receives events for this app from: '+logs.join('; '),4000),source_value:logs.join('; '),source_key:'rapid7',source_system:'Rapid7 InsightIDR – log search',source_record_id:rec,observed_at:at,confidence:'verified',match_method:'App matched by '+cut(x.match_basis||'catalog name',120),evidence_note:'Telemetry about access to the app; it does not show purpose or approval.'});
 const own=origins.filter(o=>o!=='Zscaler');
 if(own.length)out.push({field:'siem',value:'Partial',source_value:'Log origins in Rapid7: '+origins.join(', '),source_key:'rapid7',source_system:'Rapid7 InsightIDR – log search',source_record_id:rec,observed_at:at,confidence:'inferred',match_method:'The platform’s own log ('+own.join(', ')+') reaches the SIEM; whether this use case is fully logged is not established'});
 if(origins.includes('AWS CloudTrail'))out.push({field:'host',value:'AWS',source_value:'Log origin: AWS CloudTrail',source_key:'rapid7',source_system:'Rapid7 InsightIDR – log search',source_record_id:rec,observed_at:at,confidence:'inferred',match_method:'Platform activity is logged by AWS CloudTrail'});
 return out;
}
// Legacy intake adapter, retained for older callers. It maps only source values
// that are actually present. The enrichment run no longer invokes it.
function intakeFacts(row,origin){
 const b=M.intake(row,origin);if(!b||!b.eligible)return null;
 const d=row.details&&typeof row.details==='object'?row.details:{},sub=row.submitter&&typeof row.submitter==='object'?row.submitter:{},out=[];
 const base={source_key:'intake',source_system:'Access Portal – AI use-case intake',source_record_id:b.id,observed_at:iso(row.updated_at),evidence_url:b.source_url};
 const add=(field,value,sourceField)=>{if(!blank(value))out.push({...base,field,value:String(value).trim(),source_value:String(value).trim(),confidence:'needs_review',match_method:'Source field '+sourceField+' on '+b.id,evidence_note:'Source field: '+sourceField});};
 const text=v=>typeof v==='string'?v.trim():'';
 add('dept',text(sub.dept),'submitter.dept');
 add('what',text(d.use_case),'details.use_case');
 add('vendor',text(d.tool_vendor),'details.tool_vendor');
 add('systems',uniq([text(d.adc_systems),text(d.client_systems)]).join('; '),'details.adc_systems / details.client_systems');
 add('notes',text(d.notes),'details.notes');
 out.push({...base,field:'intake',value:'Yes',source_value:b.id,confidence:'needs_review',match_method:'Existing request '+b.id,evidence_note:'Source field: id'});
 const tool=b.app_name||'(tool not named)',dept=b.department||'(department unknown)';
 return {basic:b,facts:out,name:cut(tool+' – '+dept+' – '+b.id,255),detail:{request_id:b.id,app_name:b.app_name,vendor:b.vendor,requester:b.requester,department:b.department,status:b.status,updated_at:b.updated_at,source_url:b.source_url,review_process:text(d.review_process).slice(0,2000)||null,issues:b.issues}};
}

// ---- Run -----------------------------------------------------------------------------------
async function load(c){
 const [ucs]=await c.query('SELECT u.id,u.catalog_id,u.profile,u.revision,c.app_name FROM ai_governance_use_case u LEFT JOIN ai_catalog c ON c.id=u.catalog_id ORDER BY u.id');
 const [apps]=await c.query('SELECT c.id,c.app_name,c.aliases,c.retired,g.vendor,g.owner,g.business_purpose,g.updated_at AS gov_updated_at,ac.profile AS corporate_account,ac.updated_at AS account_updated_at,r.profile AS risk_profile,r.updated_at AS risk_updated_at FROM ai_catalog c LEFT JOIN ai_governance_app g ON g.catalog_id=c.id LEFT JOIN ai_governance_account ac ON ac.catalog_id=c.id LEFT JOIN ai_governance_risk r ON r.catalog_id=c.id');
 const [snaps]=await c.query("SELECT source_key,payload,checked_at FROM ai_governance_source WHERE source_key IN ('entra','identity_access','rapid7','zscaler')");
 const [config]=await c.query('SELECT source_key,enabled,interval_minutes,last_success_at,last_status FROM ai_governance_refresh_config');
 const [cands]=await c.query('SELECT * FROM ai_governance_uc_candidate');
 let portalSync=null;try{const [p]=await c.query('SELECT enabled,last_pull_at,last_pull_status FROM ai_governance_portal_sync WHERE id=1');portalSync=p[0]||null;}catch{}
 return {ucs:ucs.map(u=>({...u,profile:model.parsed(u.profile)})),apps,snap:new Map(snaps.map(s=>[s.source_key,{payload:parse(s.payload)||{},checked_at:s.checked_at}])),config:new Map(config.map(x=>[x.source_key,x])),cands,portalSync};
}
function sourceStates(d,run){
 const at=k=>d.snap.get(k),cfg=k=>d.config.get(k);
 const live={governance:{status:'current',checked_at:new Date().toISOString()},
  identity_access:snapshotState(at('identity_access'),cfg('entra')),entra:snapshotState(at('entra'),cfg('entra')),rapid7:snapshotState(at('rapid7'),cfg('rapid7')),zscaler:snapshotState(at('zscaler'),cfg('zscaler')),
  vendor:{status:'current',checked_at:null,note:'Curated list, reviewed manually'}};
 const ran=new Map(((run&&parse(run.sources))||[]).map(s=>[s.key,s]));
 const list=SOURCES.map(s=>{if(s.key==='intake')return {...s,configured:true,status:'lookup_only',checked_at:null,note:'Use Portal lookup for a live read and reviewer confirmation; enrichment runs do not read or apply Portal values.'};const r=ran.get(s.key)||{};const base=live[s.key]||{status:r.status||'not_run',checked_at:r.checked_at||null};return {...s,configured:base.status!=='not_configured',...r,...base,...(s.key==='identity_live'?{status:r.status||'not_run',checked_at:r.checked_at||null}:{})};});
 const ps=d.portalSync;
 return [...list,...NOT_USED.map(s=>s.key==='portal_sync'?{...s,configured:!!ps,status:!ps?'not_configured':ps.enabled?'not_used':'off',note:!ps?'Off until a super admin saves the Portal token in subadmin Settings.':'Portal summary sync is separate from the reviewer-led use-case lookup.'}:{...s,configured:s.status==='not_used',note:s.note||'Not configured on this hub. Nothing is read from it.'})];
}
async function run(pool,{trigger='manual',actor=SYSTEM,cookie=null,intakeClient=null,intakeAllowed=false,identity={}}={}){
 const lock=await pool.getConnection();
 try{
  const [[l]]=await lock.query('SELECT GET_LOCK(?,0) AS ok',[LOCK]);
  if(!l||l.ok!==1)return {skipped:true};
  try{return await locked(pool,{trigger,actor,cookie,intakeClient,intakeAllowed,identity});}
  finally{await lock.query('SELECT RELEASE_LOCK(?)',[LOCK]).catch(()=>{});}
 }finally{lock.release();}
}
async function locked(pool,{trigger,actor,cookie,intakeClient,intakeAllowed,identity}){
 const runId=crypto.randomUUID(),started=new Date();
 await pool.query("UPDATE ai_governance_uc_enrich_run SET status='abandoned',completed_at=UTC_TIMESTAMP() WHERE status='running' AND started_at<UTC_TIMESTAMP()-INTERVAL 15 MINUTE");
 await pool.query("INSERT INTO ai_governance_uc_enrich_run(id,trigger_kind,actor,status,started_at) VALUES(?,?,?,'running',?)",[runId,trigger,actor,sqlTime(started)]);
 try{
  const d=await load(pool),facts=[],evidence=new Map(),skipped=[],srcStatus=new Map(),ok=new Set(['governance']);
  const live=d.apps.filter(a=>!a.retired),appById=new Map(d.apps.map(a=>[a.id,a]));
  const ev=(id,source,text,at)=>{if(!evidence.has(id))evidence.set(id,[]);evidence.get(id).push({source,text:cut(text,600),observed_at:iso(at)});};
  // Targets: use cases, and open drafts once their app is known.
  const byApp=new Map(),push=(id,t)=>{if(!byApp.has(id))byApp.set(id,[]);byApp.get(id).push(t);};
  for(const u of d.ucs)if(u.catalog_id)push(u.catalog_id,{uc:u.id});
  const candByKey=new Map(d.cands.map(x=>[x.source_key+'\u0001'+x.source_record_id,x]));
  // Portal values enter only through the reviewer-led lookup and confirmation route.
  // A broad enrichment run must never associate a request or apply Portal values.
  const intake=[];
  srcStatus.set('intake',{status:'lookup_only',note:'Use Portal lookup to read a request and confirm its match. Portal fields are proposals only.'});
  const ucByRequest=new Map();
  for(const u of d.ucs)for(const m of String((u.profile.notes||'')+' '+(u.profile.name||'')).matchAll(/\bAIA-\d{4}-\d{5}\b/g))if(!ucByRequest.has(m[0]))ucByRequest.set(m[0],u.id);
  const candidates=[];
  for(const x of intake){
   const old=candByKey.get('intake\u0001'+x.basic.id),hits=M.match(x.basic.app_name,live),catalog_id=old&&old.catalog_id||(hits.length===1?hits[0].id:null);
   const decided=old&&['created','linked'].includes(old.status)&&old.use_case_id?old.use_case_id:null;
   const auto_link=!decided&&(!old||old.status==='open')?ucByRequest.get(x.basic.id)||null:null;
   candidates.push({kind:'intake',source_key:'intake',source_system:'Access Portal – AI use-case intake',source_record_id:x.basic.id,name:x.name,catalog_id,match_status:hits.length===1?'matched':hits.length>1?'ambiguous':'unmatched',detail:x.detail,observed_at:x.basic.updated_at,auto_link,old,facts:x.facts,use_case_id:decided||auto_link});
  }
  // Snapshots.
  const ia=d.snap.get('identity_access')?.payload||{},instances=new Map(),users=new Map();
  for(const a of ia.apps||[])if(a.catalog_id){ev(a.catalog_id,'identity_access',a.provider+': '+(a.user_count||0)+' account(s) assigned across '+(a.active_instances||0)+' active instance(s) (group '+(a.group_membership_users||0)+', direct '+(a.direct_assignment_users||0)+', licence '+(a.license_assigned_users||0)+', Okta '+(a.okta_assignment_users||0)+'). Assignment, not active use.',a.checked_at);users.set(a.catalog_id,(users.get(a.catalog_id)||0)+(Number(a.user_count)||0));}
  if(ia.licensing&&ia.licensing.catalog_id)ev(ia.licensing.catalog_id,'identity_access','Microsoft licence '+ia.licensing.sku+': '+ia.licensing.distinct_assigned_users+' user(s) assigned. Licence assignment, not active use.',ia.checked_at);
  for(const u of ia.users||[])for(const e of u.evidence||[])if(u.catalog_id&&e.instance_id&&e.instance_active!==false){const k=u.provider+':'+e.instance_id;if(!instances.has(k))instances.set(k,{provider:u.provider,id:String(e.instance_id),name:e.instance_name||'',catalog_id:u.catalog_id});}
  const r7=d.snap.get('rapid7'),events=new Map();
  for(const x of r7?.payload?.candidates||[])if(x.catalog_id){events.set(x.catalog_id,(events.get(x.catalog_id)||0)+(Number(x.event_count)||0));
   const oc=Object.entries(x.origin_counts||{}).map(([k,v])=>k+' '+v).join(', ');
   ev(x.catalog_id,'rapid7','Rapid7: '+(x.event_count||0)+' event(s) '+(iso(x.first_observed)||'').slice(0,10)+' to '+(iso(x.last_observed)||'').slice(0,10)+(oc?' ('+oc+')':'')+'. Telemetry, not purpose or approval.',x.last_observed);}
  const zs=d.snap.get('zscaler'),catalogLite=live.map(a=>({id:a.id,app_name:a.app_name,aliases:a.aliases}));
  const usage=zs?shadow.decorate(zs.payload.shadow_it,catalogLite,zs.payload.candidates,Z.match):null;
  for(const row of usage?.rows||[])if(row.catalog_id)ev(row.catalog_id,'zscaler','Zscaler Shadow IT ('+(usage.window?.duration||'report window')+'): '+(row.users??'?')+' user(s), '+(row.transactions??'?')+' transaction(s). Sanction tag “'+(row.sanction||'none')+'” is a Zscaler label, not a governance decision.',usage.checked_at);
  for(const x of zs?.payload?.candidates||[]){const a=Z.match(x,catalogLite);if(a&&(x.rules||[]).length)ev(a.id,'zscaler','Zscaler AI policy rules naming “'+x.name+'”: '+x.rules.map(r=>r.name+' ('+r.state+', '+(r.actions||[]).join('/')+')').join('; ')+'. Policy reference, not approval.',x.definition_checked_at||zs.payload.checked_at);}
  for(const x of sourcesModule.references){const a=sourcesModule.match(x.name,x.aliases||[],catalogLite);if(a)ev(a.id,'vendor','Vendor documentation: '+x.vendor+' '+x.capability_name+' (checked '+x.verified_at+'). Availability, not licensing or enablement.',x.verified_at+'T00:00:00Z');}
  for(const k of ['identity_access','rapid7','zscaler','entra']){const s=snapshotState(d.snap.get(k),d.config.get(k==='identity_access'?'entra':k));srcStatus.set(k,{...s,records:k==='identity_access'?(ia.apps||[]).length:k==='rapid7'?(r7?.payload?.candidates||[]).length:k==='zscaler'?(usage?.rows||[]).length:(d.snap.get('entra')?.payload?.candidates||[]).length});if(['current','stale'].includes(s.status))ok.add(k);}
  srcStatus.set('vendor',{status:'current',records:sourcesModule.references.length});
  // Observed drafts: an app with assignments or activity but no use case yet.
  const withUc=new Set(d.ucs.map(u=>u.catalog_id));
  for(const a of live){
   if(withUc.has(a.id))continue;const u=users.get(a.id)||0,e=events.get(a.id)||0;if(!u&&!e)continue;
   const seen=[u&&'Entra/Okta assignment',e&&'Rapid7 activity'].filter(Boolean).join(' and ');
   candidates.push({kind:'observed',source_key:'observed',source_system:seen,source_record_id:'catalog:'+a.id,name:cut(a.app_name+' – (department unknown) – observed in '+seen,255),catalog_id:a.id,match_status:'matched',detail:{app_name:a.app_name,assigned_accounts:u,rapid7_events:e,note:'Telemetry and assignments show an app is in use somewhere. They do not show who owns the use or what it is for.'},observed_at:null,old:candByKey.get('observed\u0001catalog:'+a.id),facts:[]});
  }
  // Candidate rows (dismissed / created stay as decided).
  const cRows=[];
  for(const x of candidates){
   const status=x.auto_link?'linked':x.old?x.old.status==='covered'?'open':x.old.status:'open';
   const detail=JSON.stringify(x.detail);
   if(x.old){await pool.query('UPDATE ai_governance_uc_candidate SET name=?,source_system=?,catalog_id=COALESCE(catalog_id,?),match_status=?,detail=?,status=?,use_case_id=COALESCE(use_case_id,?),reviewer=IF(?,?,reviewer),reviewed_at=IF(?,UTC_TIMESTAMP(),reviewed_at),observed_at=?,run_id=? WHERE id=?',[x.name,x.source_system,x.catalog_id,x.match_status,detail,status,x.auto_link,!!x.auto_link,SYSTEM,!!x.auto_link,sqlTime(x.observed_at),runId,x.old.id]);cRows.push({...x,id:x.old.id,status,use_case_id:x.old.use_case_id||x.auto_link||null});}
   else{const [r]=await pool.query('INSERT INTO ai_governance_uc_candidate(kind,source_key,source_system,source_record_id,name,catalog_id,match_status,detail,status,use_case_id,reviewer,reviewed_at,observed_at,run_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[x.kind,x.source_key,x.source_system,x.source_record_id,x.name,x.catalog_id,x.match_status,detail,status,x.auto_link,x.auto_link?SYSTEM:null,x.auto_link?sqlTime(new Date()):null,sqlTime(x.observed_at),runId]);cRows.push({...x,id:r.insertId,status,use_case_id:x.auto_link});}
  }
  // Observed drafts whose app now has a use case are covered.
  for(const c of d.cands)if(c.kind==='observed'&&c.status==='open'&&withUc.has(c.catalog_id))await pool.query("UPDATE ai_governance_uc_candidate SET status='covered',run_id=? WHERE id=?",[runId,c.id]);
  for(const c of cRows)if(c.status==='open'&&c.catalog_id)push(c.catalog_id,{cand:c.id});
  // Live identity reads for apps that have a target.
  const wanted=new Map([...instances].filter(([,x])=>byApp.has(x.catalog_id)));
  const il=await identityLive(wanted,identity);
  srcStatus.set('identity_live',{status:il.status,checked_at:il.checked_at,records:il.results.length,requests:il.requests,instances:il.instances,read:il.read,errors:il.errors.slice(0,20)});
  // Only a complete read withdraws earlier live proposals; a timeout must not erase them.
  if(il.status==='current')ok.add('identity_live');
  for(const r of il.results)ev(r.catalog_id,'identity_live',r.provider+' app “'+r.name+'” ('+r.id+'): sign-on mode '+(r.mode||'not set')+(r.enabled?'':' — disabled')+(r.owners?', owners: '+(r.owners.join('; ')||'none'):'')+'.',r.checked_at);
  // Facts per target.
  const targetFacts=(t,list)=>{for(const f of list)facts.push({...f,uc:t.uc||null,cand:t.cand||null});};
  for(const [appId,targets] of byApp){
   const a=appById.get(appId);if(!a)continue;
   const list=[...governanceFacts(a),...il.results.filter(r=>r.catalog_id===appId).flatMap(r=>identityFacts({...r,checked_at:il.checked_at})),...(r7?.payload?.candidates||[]).filter(x=>x.catalog_id===appId).flatMap(x=>rapid7Facts(x,r7.checked_at))];
   for(const t of targets)targetFacts(t,list);
  }
  for(const c of cRows){if(c.kind!=='intake'||c.status==='dismissed')continue;const t=c.use_case_id?{uc:c.use_case_id}:c.status==='open'?{cand:c.id}:null;if(t)targetFacts(t,c.facts);}
  // Store proposals.
  const profiles=new Map(d.ucs.map(u=>[u.id,u.profile]));
  const [existing]=await pool.query('SELECT id,use_case_id,candidate_id,field_key,proposed_value,source_key,fingerprint,status FROM ai_governance_uc_proposal');
  const byFp=new Map(existing.map(p=>[p.fingerprint,p])),seen=new Set(),counts={facts:0,inserted:0,refreshed:0,withdrawn:0,auto_accepted:0,skipped:0};
  for(const f of facts){
   const v=clean(f.field,f.value);if(v.problem){counts.skipped++;if(skipped.length<50)skipped.push({source:f.source_key,record:f.source_record_id,field:f.field,reason:v.problem});continue;}
   counts.facts++;const target=f.uc?'uc:'+f.uc:'cand:'+f.cand,fp=fingerprint(target,f.field,f.source_key,f.source_record_id,v.value);
   if(seen.has(fp))continue;seen.add(fp);
   const status=f.uc&&same(profiles.get(f.uc)?.[f.field],v.value)?'matched':'open',old=byFp.get(fp);
   const cols=[cut(f.source_value??'',4000)||null,f.source_system,cut(f.source_record_id,255),sqlTime(f.observed_at),f.confidence,cut(f.match_method,255),f.evidence_note?cut(f.evidence_note,1000):null,f.evidence_url?cut(f.evidence_url,1000):null,runId];
   if(old){if(['open','matched','withdrawn'].includes(old.status)){await pool.query('UPDATE ai_governance_uc_proposal SET source_value=?,source_system=?,source_record_id=?,observed_at=?,confidence=?,match_method=?,evidence_note=?,evidence_url=?,run_id=?,status=? WHERE id=?',[...cols,status,old.id]);counts.refreshed++;}}
   else{await pool.query('INSERT INTO ai_governance_uc_proposal(use_case_id,candidate_id,field_key,proposed_value,source_value,source_system,source_record_id,observed_at,confidence,match_method,evidence_note,evidence_url,run_id,status,source_key,fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[f.uc,f.cand,f.field,v.value,...cols,status,f.source_key,fp]);counts.inserted++;}
  }
  // A source that answered but no longer gives a value withdraws it; others keep theirs.
  for(const p of existing){
   if(!LIVE.has(p.status)||seen.has(p.fingerprint))continue;
   if(ok.has(p.source_key)){await pool.query("UPDATE ai_governance_uc_proposal SET status='withdrawn',run_id=? WHERE id=? AND status IN ('open','matched')",[runId,p.id]);counts.withdrawn++;}
   else if(p.use_case_id){const st=same(profiles.get(p.use_case_id)?.[p.field_key],p.proposed_value)?'matched':'open';if(st!==p.status)await pool.query('UPDATE ai_governance_uc_proposal SET status=? WHERE id=? AND status IN (\'open\',\'matched\')',[st,p.id]);}
  }
  counts.auto_accepted=await autoAccept(pool,runId,actor);
  const sources=SOURCES.map(s=>({key:s.key,name:s.name,...(srcStatus.get(s.key)||{status:s.key==='governance'?'current':'not_run'})}));
  const entraSnap=d.snap.get('entra')?.payload||{},unmatched={
   entra:(entraSnap.candidates||[]).filter(x=>!sourcesModule.match(x.name,x.aliases||[],catalogLite)).map(x=>({name:x.name,code:x.code,observed_at:x.observed_at,source:'Entra'})),
   rapid7:(r7?.payload?.candidates||[]).filter(x=>!x.catalog_id).map(x=>({name:x.name,code:x.code,observed_at:x.last_observed,events:x.event_count,source:'Rapid7'})),
   zscaler:(usage?.rows||[]).filter(x=>!x.catalog_id&&x.ai_relevant&&Number(x.users)>0).map(x=>({name:x.name,code:x.source_id,users:x.users,category:x.category,source:'Zscaler'}))};
  const summaryCounts={...counts,use_cases:d.ucs.length,candidates:{intake:cRows.filter(c=>c.kind==='intake').length,observed:cRows.filter(c=>c.kind==='observed').length,open:cRows.filter(c=>c.status==='open').length},skipped_detail:skipped,
   evidence:Object.fromEntries([...evidence].map(([k,v])=>[k,v.slice(0,40)])),unmatched:Object.fromEntries(Object.entries(unmatched).map(([k,v])=>[k,{count:v.length,items:v.slice(0,200)}]))};
  await pool.query("UPDATE ai_governance_uc_enrich_run SET status='completed',completed_at=UTC_TIMESTAMP(),sources=?,counts=? WHERE id=?",[JSON.stringify(sources),JSON.stringify(summaryCounts),runId]);
  return {id:runId,status:'completed',sources,counts:{...counts,candidates:summaryCounts.candidates}};
 }catch(e){
  await pool.query("UPDATE ai_governance_uc_enrich_run SET status='failed',completed_at=UTC_TIMESTAMP(),error=? WHERE id=?",[cut(e.message||e.code||'failed',1000),runId]).catch(()=>{});
  throw e;
 }
}
// Low-risk authoritative facts fill blank fields only, one transaction per use case.
async function autoAccept(pool,runId,actor){
 const [open]=await pool.query("SELECT * FROM ai_governance_uc_proposal WHERE status='open' AND use_case_id IS NOT NULL AND source_key NOT IN ('intake','intake_lookup') AND field_key IN (?)",[[...AUTO]]);
 const groups=new Map();for(const p of open){const k=p.use_case_id+'\u0001'+p.field_key;if(!groups.has(k))groups.set(k,[]);groups.get(k).push(p);}
 const [conflicts]=await pool.query("SELECT use_case_id,field_key,proposed_value FROM ai_governance_uc_proposal WHERE status='open' AND use_case_id IS NOT NULL");
 const plan=new Map();
 for(const [k,list] of groups){
  const [ucId,field]=[list[0].use_case_id,list[0].field_key];
  if(uniq(conflicts.filter(p=>p.use_case_id===ucId&&p.field_key===field).map(p=>low(p.proposed_value))).length!==1)continue;
  const best=list.filter(p=>['verified','confirmed'].includes(p.confidence)).sort((a,b)=>RANK[a.confidence]-RANK[b.confidence]||a.id-b.id)[0];
  if(!best)continue;if(!plan.has(ucId))plan.set(ucId,[]);plan.get(ucId).push({best,list});
 }
 let n=0;
 for(const [ucId,items] of plan){
  const c=await pool.getConnection();
  try{
   await c.beginTransaction();
   const [rows]=await c.query('SELECT id,catalog_id,profile,revision FROM ai_governance_use_case WHERE id=? FOR UPDATE',[ucId]);const u=rows[0];
   if(!u){await c.rollback();continue;}
   const profile=model.parsed(u.profile),applied=[];
   for(const {best,list} of items){
    const [still]=await c.query("SELECT id FROM ai_governance_uc_proposal WHERE id=? AND status='open' FOR UPDATE",[best.id]);
    if(!still.length||!blank(profile[best.field_key]))continue;
    if(best.field_key==='sso'&&NON_SSO_ACCESS.has(profile.access))continue;
    profile[best.field_key]=best.proposed_value;applied.push({best,list});
   }
   if(!applied.length){await c.rollback();continue;}
   const before=model.parsed(u.profile);
   await c.query('UPDATE ai_governance_use_case SET profile=?,revision=revision+1,updated_by=? WHERE id=?',[JSON.stringify(profile),SYSTEM,ucId]);
   for(const {best,list} of applied){
    await c.query("UPDATE ai_governance_uc_proposal SET status='auto_accepted',decided_value=?,reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?",[best.proposed_value,SYSTEM,best.id]);
    const rest=list.filter(p=>p.id!==best.id).map(p=>p.id);if(rest.length)await c.query("UPDATE ai_governance_uc_proposal SET status='matched' WHERE id IN (?) AND status='open'",[rest]);
    await c.query('INSERT INTO ai_governance_audit(actor,action,catalog_id,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?)',[SYSTEM,'use_case_proposal_auto_accepted',u.catalog_id,ucId,JSON.stringify({ref:model.ref(ucId),field:best.field_key,value:before[best.field_key]||'',revision:u.revision}),JSON.stringify({ref:model.ref(ucId),proposal_id:best.id,field:best.field_key,label:FIELDS.get(best.field_key).label,value:best.proposed_value,source_system:best.source_system,source_record_id:best.source_record_id,observed_at:iso(best.observed_at),confidence:CONFIDENCE[best.confidence],match_method:best.match_method,revision:u.revision+1,run_id:runId,run_by:actor,rule:'Blank field, Verified or Confirmed source, no conflicting proposal'})]);
    n++;
   }
   await c.commit();
  }catch(e){await c.rollback();throw e;}finally{c.release();}
 }
 return n;
}
let lastFailure=0;
async function scheduled(pool,options={}){
 if(Date.now()-lastFailure<15*60000)return null;
 try{
  const [r]=await pool.query("SELECT started_at FROM ai_governance_uc_enrich_run WHERE trigger_kind='scheduled' AND status IN ('completed','running') ORDER BY started_at DESC LIMIT 1");
  if(r.length&&Date.now()-M.stamp(r[0].started_at)<60*60000)return null;
  return await run(pool,{trigger:'scheduled',actor:SYSTEM,...options});
 }catch(e){lastFailure=Date.now();throw e;}
}

// ---- Decisions -----------------------------------------------------------------------------
const ACTIONS={accept:['accepted','use_case_proposal_accepted'],keep:['kept','use_case_proposal_kept'],merge:['merged','use_case_proposal_merged'],unknown:['unknown','use_case_proposal_marked_unknown'],reject:['rejected','use_case_proposal_rejected']};
async function audit(c,who,action,catalogId,entityId,before,after){await c.query('INSERT INTO ai_governance_audit(actor,action,catalog_id,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?)',[who,action,catalogId,entityId,before?JSON.stringify(before):null,JSON.stringify(after||{})]);}
const provenance=p=>({proposal_id:p.id,proposed_value:p.proposed_value,source_value:p.source_value,source_system:p.source_system,source_record_id:p.source_record_id,observed_at:iso(p.observed_at),confidence:CONFIDENCE[p.confidence],match_method:p.match_method,evidence_note:p.evidence_note,evidence_url:p.evidence_url});
async function decide(pool,who,body){
 const list=body&&Array.isArray(body.decisions)?body.decisions:null;
 if(!list||!list.length)fail('Choose at least one proposal');
 if(list.length>500)fail('Decide up to 500 proposals at a time');
 const want=new Map();
 for(const d of list){const n=Number(d&&d.id);if(!Number.isSafeInteger(n)||n<1)fail('Invalid proposal ID');if(want.has(n))fail('A proposal is listed twice');if(!ACTIONS[d.action])fail('Choose Accept, Keep existing, Merge, Mark Unknown or Reject');want.set(n,d);}
 const c=await pool.getConnection();
 try{
  await c.beginTransaction();
  const [rows]=await c.query('SELECT * FROM ai_governance_uc_proposal WHERE id IN (?) ORDER BY id FOR UPDATE',[[...want.keys()]]);
  if(rows.length!==want.size)fail('A proposal was not found. Reload the review.',409);
  for(const p of rows){if(p.status!=='open')fail('A proposal was already decided. Reload the review.',409);if(!p.use_case_id)fail('Create or link the draft use case before deciding its proposals');if(PROTECTED.has(p.field_key))fail('InfoSec / Legal review fields are not decided here');}
  const ucIds=uniq(rows.map(p=>p.use_case_id));
  const [ucs]=await c.query('SELECT id,catalog_id,profile,revision FROM ai_governance_use_case WHERE id IN (?) FOR UPDATE',[ucIds]);
  const byUc=new Map(ucs.map(u=>[u.id,{...u,profile:model.parsed(u.profile),before:model.parsed(u.profile),changed:new Map()}]));
  if(body.bulk===true){
   if(rows.some(p=>want.get(p.id).action!=='accept'))fail('Bulk review accepts proposals only');
   if(new Set(rows.map(p=>[p.source_key,p.field_key,p.confidence].join('|'))).size!==1)fail('Bulk accept needs proposals with the same source, field and confidence');
   const [others]=await c.query("SELECT use_case_id,proposed_value FROM ai_governance_uc_proposal WHERE status='open' AND field_key=? AND use_case_id IN (?)",[rows[0].field_key,ucIds]);
   for(const p of rows){const u=byUc.get(p.use_case_id);if(!blank(u.profile[p.field_key])||others.some(o=>o.use_case_id===p.use_case_id&&!same(o.proposed_value,p.proposed_value)))fail(model.ref(p.use_case_id)+' has conflicting evidence for this field. Review it on its own.');}
  }
  const decided=[];
  for(const p of rows){
   const d=want.get(p.id),u=byUc.get(p.use_case_id),f=FIELDS.get(p.field_key);
   if(!u)fail('Use case not found',404);
   const current=String(u.before[p.field_key]||'');let value=null;
   if(d.action==='accept')value=p.proposed_value;
   else if(d.action==='merge'){if(typeof d.value!=='string'||blank(d.value))fail('Enter the merged value for '+f.label);value=d.value;}
   else if(d.action==='unknown'){value=unknownValue(f);if(!value)fail(f.label+' has no Unknown choice in the workbook. Reject the proposal or merge a value.');}
   if(value!==null){
    if(typeof d.expected!=='string'||d.expected.trim()!==current.trim())fail(model.ref(u.id)+' changed. Reload the review.',409);
    if(u.changed.has(p.field_key))fail('Two decisions change '+f.label+' on '+model.ref(u.id));
    const v=clean(p.field_key,value);if(v.problem)fail(f.label+': '+v.problem);value=v.value;
    u.changed.set(p.field_key,value);u.profile[p.field_key]=value;
   }
   const [status,action]=ACTIONS[d.action];
   await c.query('UPDATE ai_governance_uc_proposal SET status=?,decided_value=?,reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?',[status,value??(d.action==='keep'?current:null),who,p.id]);
   decided.push({p,u,action,value,current});
  }
  for(const u of byUc.values()){
   if(!u.changed.size)continue;
   await c.query('UPDATE ai_governance_use_case SET profile=?,revision=revision+1,updated_by=? WHERE id=?',[JSON.stringify(u.profile),who,u.id]);
   for(const [field,value] of u.changed)await c.query("UPDATE ai_governance_uc_proposal SET status=IF(LOWER(TRIM(proposed_value))=LOWER(TRIM(?)),'matched','superseded'),decided_value=IF(LOWER(TRIM(proposed_value))=LOWER(TRIM(?)),NULL,?),reviewer=IF(LOWER(TRIM(proposed_value))=LOWER(TRIM(?)),NULL,?),reviewed_at=IF(LOWER(TRIM(proposed_value))=LOWER(TRIM(?)),NULL,UTC_TIMESTAMP()) WHERE use_case_id=? AND field_key=? AND status='open'",[value,value,value,value,who,value,u.id,field]);
  }
  for(const {p,u,action,value,current} of decided)await audit(c,who,action,u.catalog_id,u.id,{ref:model.ref(u.id),field:p.field_key,value:current,revision:u.revision},{ref:model.ref(u.id),field:p.field_key,label:FIELDS.get(p.field_key).label,value:value??current,...provenance(p),bulk:body.bulk===true,revision:u.changed.size?u.revision+1:u.revision});
  await c.commit();
  return {decided:decided.length,use_cases:[...byUc.values()].map(u=>({id:u.id,ref:model.ref(u.id),revision:u.changed.size?u.revision+1:u.revision}))};
 }catch(e){await c.rollback();throw e;}finally{c.release();}
}
// Draft candidates: create a use case (owner and purpose confirmed by the reviewer), link to
// an existing one, or dismiss. Proposals follow the draft to the use case.
async function candidateAction(pool,who,candId,body){
 const b=body||{},action=b.action;
 if(!['create','link','dismiss'].includes(action))fail('Choose Create, Link or Dismiss');
 const c=await pool.getConnection();
 try{
  await c.beginTransaction();
  const [cr]=await c.query('SELECT * FROM ai_governance_uc_candidate WHERE id=? FOR UPDATE',[candId]),cand=cr[0];
  if(!cand)fail('Draft not found',404);
  if(cand.status!=='open')fail('This draft was already decided. Reload the review.',409);
  const [props]=await c.query("SELECT * FROM ai_governance_uc_proposal WHERE candidate_id=? AND status='open' AND use_case_id IS NULL FOR UPDATE",[candId]);
  const info={id:cand.id,kind:cand.kind,name:cand.name,source_system:cand.source_system,source_record_id:cand.source_record_id};
  if(action==='dismiss'){
   await c.query("UPDATE ai_governance_uc_candidate SET status='dismissed',reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?",[who,candId]);
   if(props.length)await c.query("UPDATE ai_governance_uc_proposal SET status='withdrawn',reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id IN (?)",[who,props.map(p=>p.id)]);
   await audit(c,who,'use_case_candidate_dismissed',cand.catalog_id,null,null,{candidate:info,proposals_withdrawn:props.length,note:'Draft dismissed. No use case was created.'});
   await c.commit();return {status:'dismissed'};
  }
  const move=async(ucId,keep)=>{let moved=0;for(const p of props){if(keep.has(p.id))continue;const fp=fingerprint('uc:'+ucId,p.field_key,p.source_key,p.source_record_id,p.proposed_value);const [dup]=await c.query('SELECT id FROM ai_governance_uc_proposal WHERE fingerprint=?',[fp]);if(dup.length)await c.query("UPDATE ai_governance_uc_proposal SET status='superseded',reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?",[who,p.id]);else{await c.query('UPDATE ai_governance_uc_proposal SET use_case_id=?,fingerprint=? WHERE id=?',[ucId,fp,p.id]);moved++;}}return moved;};
  if(action==='link'){
   const n=Number(b.use_case_id);if(!Number.isSafeInteger(n)||n<1)fail('Choose the use case to link');
   const [u]=await c.query('SELECT id,catalog_id FROM ai_governance_use_case WHERE id=? FOR UPDATE',[n]);if(!u.length)fail('Use case not found',404);
   const moved=await move(n,new Set());
   await c.query("UPDATE ai_governance_uc_candidate SET status='linked',use_case_id=?,reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?",[n,who,candId]);
   await audit(c,who,'use_case_candidate_linked',u[0].catalog_id,n,null,{ref:model.ref(n),candidate:info,proposals_moved:moved,note:'Draft evidence linked to an existing use case. Proposals still need review.'});
   await c.commit();return {status:'linked',use_case_id:n,ref:model.ref(n)};
  }
  if(b.confirmed!==true)fail('Confirm the business owner and purpose before creating the use case');
  const appN=Number(b.catalog_id);if(!Number.isSafeInteger(appN)||appN<1)fail('Choose the catalog application this use case belongs to');
  const [app]=await c.query('SELECT id FROM ai_catalog WHERE id=? AND retired=0 FOR SHARE',[appN]);if(!app.length)fail('Choose a current catalog application');
  const typed={name:String(b.name??cand.name),bowner:String(b.bowner??''),what:String(b.what??'')};
  if(blank(typed.bowner))fail('Enter the business owner');if(blank(typed.what))fail('Enter what it does / the business process it supports');
  const profile=model.validate(typed),accepted=[],keep=new Set();
  const groups=new Map();for(const p of props){if(!groups.has(p.field_key))groups.set(p.field_key,[]);groups.get(p.field_key).push(p);}
  for(const [field,list] of groups){
   if(field==='bowner'||field==='what'){for(const p of list)if(same(p.proposed_value,profile[field])){accepted.push({p,value:profile[field]});keep.add(p.id);}else{keep.add(p.id);await c.query("UPDATE ai_governance_uc_proposal SET status='superseded',decided_value=?,reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?",[profile[field],who,p.id]);}continue;}
   if(!AUTO.has(field)||list.some(p=>['intake','intake_lookup'].includes(p.source_key))||uniq(list.map(p=>low(p.proposed_value))).length!==1)continue;
   const best=list.filter(p=>['verified','confirmed'].includes(p.confidence)).sort((a,b)=>RANK[a.confidence]-RANK[b.confidence]||a.id-b.id)[0];if(!best)continue;
   profile[field]=best.proposed_value;accepted.push({p:best,value:best.proposed_value});keep.add(best.id);
   for(const p of list)if(p.id!==best.id){keep.add(p.id);await c.query("UPDATE ai_governance_uc_proposal SET status='matched' WHERE id=?",[p.id]);}
  }
  const full=model.validate({...Object.fromEntries(model.fields.map(f=>[f.key,''])),...profile});
  const [x]=await c.query('INSERT INTO ai_governance_use_case(catalog_id,profile,created_by,updated_by) VALUES(?,?,?,?)',[appN,JSON.stringify(full),who,who]),ucId=x.insertId;
  for(const {p,value} of accepted){const fp=fingerprint('uc:'+ucId,p.field_key,p.source_key,p.source_record_id,p.proposed_value);await c.query("UPDATE ai_governance_uc_proposal SET use_case_id=?,fingerprint=?,status='accepted',decided_value=?,reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?",[ucId,fp,value,who,p.id]);}
  for(const p of props)if(keep.has(p.id)&&!accepted.some(a=>a.p.id===p.id)){const fp=fingerprint('uc:'+ucId,p.field_key,p.source_key,p.source_record_id,p.proposed_value);await c.query('UPDATE ai_governance_uc_proposal SET use_case_id=?,fingerprint=? WHERE id=?',[ucId,fp,p.id]);}
  const moved=await move(ucId,keep);
  await c.query("UPDATE ai_governance_uc_candidate SET status='created',use_case_id=?,catalog_id=?,reviewer=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?",[ucId,appN,who,candId]);
  await audit(c,who,'use_case_candidate_created',appN,ucId,null,{ref:model.ref(ucId),catalog_id:appN,profile:full,revision:1,candidate:info,owner_and_purpose_confirmed:true,proposals_moved:moved,note:'Created from a draft. It does not approve the application or grant access.'});
  for(const {p,value} of accepted)await audit(c,who,'use_case_proposal_accepted',appN,ucId,{ref:model.ref(ucId),field:p.field_key,value:'',revision:0},{ref:model.ref(ucId),field:p.field_key,label:FIELDS.get(p.field_key).label,value,...provenance(p),revision:1,via:'draft created'});
  await c.commit();
  return {status:'created',use_case_id:ucId,ref:model.ref(ucId)};
 }catch(e){await c.rollback();throw e;}finally{c.release();}
}

// ---- Views ---------------------------------------------------------------------------------
async function view(pool,{editor=false}={}){
 const d=await load(pool);
 const [props]=await pool.query("SELECT * FROM ai_governance_uc_proposal WHERE status IN ('open','matched') OR reviewed_at>UTC_TIMESTAMP()-INTERVAL 30 DAY ORDER BY id");
 const [runs]=await pool.query('SELECT * FROM ai_governance_uc_enrich_run ORDER BY started_at DESC LIMIT 10');
 const lastDone=runs.find(r=>r.status==='completed')||null,counts=parse(lastDone?.counts)||{};
 const open=props.filter(p=>p.status==='open'),openBy=new Map();
 for(const p of open)if(p.use_case_id){const k=p.use_case_id+'\u0001'+p.field_key;if(!openBy.has(k))openBy.set(k,[]);openBy.get(k).push(p);}
 const rows=d.ucs.map(u=>{
  const states={};for(const f of model.fields)states[f.key]=fieldState(u.profile[f.key],openBy.get(u.id+'\u0001'+f.key)||[]);
  const done=REQUIRED.filter(k=>['complete','not_applicable'].includes(states[k])).length;
  return {id:u.id,ref:model.ref(u.id),catalog_id:u.catalog_id,app_name:u.app_name,revision:u.revision,profile:u.profile,calc:model.calc(u.profile),states,
   completeness:{complete:done,total:REQUIRED.length,pct:Math.round(done/REQUIRED.length*100)},
   counts:Object.fromEntries(Object.keys(STATE).map(s=>[s,REQUIRED.filter(k=>states[k]===s).length])),open:open.filter(p=>p.use_case_id===u.id).length};
 });
 const apps=[...new Set(rows.map(r=>r.catalog_id))].map(id=>{const list=rows.filter(r=>r.catalog_id===id),done=list.reduce((n,r)=>n+r.completeness.complete,0);return {catalog_id:id,app_name:list[0].app_name,use_cases:list.length,pct:Math.round(done/(list.length*REQUIRED.length)*100)};}).sort((a,b)=>String(a.app_name).localeCompare(String(b.app_name)));
 const cands=d.cands.filter(c=>c.status==='open').map(c=>({id:c.id,kind:c.kind,name:c.name,source_system:c.source_system,source_record_id:c.source_record_id,catalog_id:c.catalog_id,match_status:c.match_status,detail:parse(c.detail),observed_at:iso(c.observed_at),open:open.filter(p=>p.candidate_id===c.id&&!p.use_case_id).length}));
 const sources=sourceStates(d,lastDone),unmatched=counts.unmatched||{};
 const [portalReads]=await pool.query("SELECT created_at FROM ai_governance_audit WHERE action IN ('use_case_portal_lookup','use_case_portal_match_confirmed') ORDER BY id DESC LIMIT 1");
 const portalSource=sources.find(s=>s.key==='intake');if(portalSource)portalSource.checked_at=iso(portalReads[0]?.created_at);
 // Governance Queue: the spec's eleven items.
 const fieldItems=state=>rows.flatMap(r=>model.fields.filter(f=>(state!=='missing'||f.required)&&r.states[f.key]===state).map(f=>({use_case_id:r.id,ref:r.ref,name:r.profile.name,field:f.key,label:f.label})));
 const trigger=r=>{const hits=[];for(const [k,v] of [['npi','Yes'],['client','Yes'],['consumer','Yes'],['ext','Yes'],['oversight','Fully automated']]){const now=same(r.profile[k],v),prop=(openBy.get(r.id+'\u0001'+k)||[]).some(p=>same(p.proposed_value,v));if(now||prop)hits.push(FIELDS.get(k).label+(now?'':' (proposed)'));}return hits;};
 const linkedIntake=new Set(d.cands.filter(c=>c.kind==='intake'&&c.use_case_id).map(c=>c.use_case_id));
 const queue=[
  {key:'prefilled',label:'Prefilled, awaiting review',items:fieldItems('prefilled'),tab:'review'},
  {key:'missing',label:'Required fields missing',items:fieldItems('missing'),tab:'review'},
  {key:'conflicting',label:'Conflicting evidence',items:fieldItems('conflicting'),tab:'review'},
  {key:'unmatched_apps',label:'Apps seen in sources but not in the catalog',count:['entra','rapid7','zscaler'].reduce((n,k)=>n+(unmatched[k]?.count||0),0),items:['entra','rapid7','zscaler'].flatMap(k=>(unmatched[k]?.items||[]).slice(0,60)),href:'#sources',note:'Add or match these in Sources. A new app is a discovery candidate, not a use case, and needs approval.'},
  {key:'unmatched_intake',label:'Approved intake not yet a use case',items:cands.filter(c=>c.kind==='intake').map(c=>({candidate_id:c.id,name:c.name,match_status:c.match_status})),tab:'review'},
  {key:'owners',label:'Missing business owner, technical owner or purpose',items:rows.filter(r=>['bowner','towner','what'].some(k=>!['complete','not_applicable'].includes(r.states[k]))).map(r=>({use_case_id:r.id,ref:r.ref,name:r.profile.name,detail:['bowner','towner','what'].filter(k=>!['complete','not_applicable'].includes(r.states[k])).map(k=>FIELDS.get(k).label).join(', ')})),tab:'review'},
  {key:'high_risk',label:'Possible high-risk trigger',items:rows.map(r=>({r,hits:trigger(r)})).filter(x=>x.hits.length).map(({r,hits})=>({use_case_id:r.id,ref:r.ref,name:r.profile.name,detail:hits.join(', ')})),tab:'review',note:'InfoSec / Legal assign the risk tier. Nothing here sets it.'},
  {key:'risk_tier',label:'No risk tier assigned',items:rows.filter(r=>blank(r.profile.tier)).map(r=>({use_case_id:r.id,ref:r.ref,name:r.profile.name})),tab:'inventory',note:'Assigned by InfoSec / Legal only.'},
  {key:'intake_evidence',label:'No intake evidence',items:rows.filter(r=>!same(r.profile.intake,'Yes')&&!linkedIntake.has(r.id)).map(r=>({use_case_id:r.id,ref:r.ref,name:r.profile.name,detail:'Intake form submitted: '+(r.profile.intake||'blank')})),tab:'review'},
  {key:'stale',label:'Stale sources',items:sources.filter(s=>s.status==='stale').map(s=>({source:s.key,name:s.name,detail:'Last checked '+(s.checked_at||'never')})),tab:'sources'},
  {key:'failed',label:'Source failures',items:sources.filter(s=>s.status==='failed').map(s=>({source:s.key,name:s.name,detail:s.error||'Last attempt failed'})),tab:'sources'}
 ].map(q=>({...q,count:q.count??q.items.length,items:editor?q.items.slice(0,200):[]}));
 const field=f=>({key:f.key,label:f.label,required:!!f.required,allowed:f.allowed||null,kind:f.kind,auto:AUTO.has(f.key),protected:PROTECTED.has(f.key),unknown_value:unknownValue(f)});
 const pub=p=>({id:p.id,use_case_id:p.use_case_id,candidate_id:p.candidate_id,field:p.field_key,value:p.proposed_value,source_value:p.source_value,source_key:p.source_key,source_system:p.source_system,source_record_id:p.source_record_id,observed_at:iso(p.observed_at),confidence:p.confidence,confidence_label:CONFIDENCE[p.confidence],match_method:p.match_method,evidence_note:p.evidence_note,evidence_url:p.evidence_url,status:p.status,decided_value:p.decided_value,reviewer:p.reviewer,reviewed_at:iso(p.reviewed_at),auto:AUTO.has(p.field_key)&&!['intake','intake_lookup'].includes(p.source_key)});
 return {can_edit:editor,received_at:new Date().toISOString(),fields:model.fields.map(field),states:STATE,confidence:CONFIDENCE,
  policy:{auto:[...AUTO],protected:[...PROTECTED],non_sso_access:[...NON_SSO_ACCESS],note:'Access Portal values always wait for a reviewer. Other sources auto-fill only Verified or Confirmed values into blanks when no source disagrees. Risk tier and the InfoSec / Legal review section are never proposed.'},
  run:lastDone?{id:lastDone.id,trigger:lastDone.trigger_kind,actor:lastDone.actor,started_at:iso(lastDone.started_at),completed_at:iso(lastDone.completed_at),counts:{...counts,evidence:undefined,unmatched:undefined}}:null,
  runs:runs.map(r=>({id:r.id,trigger:r.trigger_kind,actor:r.actor,status:r.status,started_at:iso(r.started_at),completed_at:iso(r.completed_at),error:r.error})),
  sources,summary:summary(rows.map(r=>({p:r.profile,calc:r.calc}))),queue,apps,
  use_cases:rows.map(r=>editor?r:{id:r.id,ref:r.ref,catalog_id:r.catalog_id,app_name:r.app_name,completeness:r.completeness,counts:r.counts}),
  proposals:editor?props.map(pub):[],candidates:editor?cands:[],evidence:editor?(counts.evidence||{}):{},
  note:'Proposals are not inventory data until a reviewer accepts them. They do not approve an application, grant access or set a risk tier.'};
}
// Export: where each saved value came from, for values that still equal the decided value.
async function evidenceRefs(pool){
 const [rows]=await pool.query("SELECT p.use_case_id,p.field_key,p.proposed_value,p.decided_value,p.status,p.source_system,p.source_record_id,p.observed_at,p.confidence,u.profile FROM ai_governance_uc_proposal p JOIN ai_governance_use_case u ON u.id=p.use_case_id WHERE p.status IN ('accepted','auto_accepted','merged','matched') ORDER BY FIELD(p.status,'auto_accepted','accepted','merged','matched'),p.id");
 const out=new Map(),done=new Set();
 for(const r of rows){
  const profile=model.parsed(r.profile),value=r.status==='matched'?r.proposed_value:r.decided_value,k=r.use_case_id+'\u0001'+r.field_key;
  if(done.has(k)||blank(value)||!same(profile[r.field_key],value))continue;done.add(k);
  const line=FIELDS.get(r.field_key).label+': '+r.source_system+' '+r.source_record_id+' ('+((iso(r.observed_at)||'').slice(0,10)||'date not recorded')+', '+CONFIDENCE[r.confidence]+(r.status==='merged'?', merged by reviewer':r.status==='auto_accepted'?', auto-filled':r.status==='matched'?', agrees with saved value':', accepted')+')';
  out.set(r.use_case_id,cut([out.get(r.use_case_id),line].filter(Boolean).join('\n'),4000));
 }
 return out;
}
async function auditTrail(pool){
 const [rows]=await pool.query("SELECT a.id,a.actor,a.action,a.catalog_id,a.entity_id,a.before_json,a.after_json,a.created_at,c.app_name FROM ai_governance_audit a LEFT JOIN ai_catalog c ON c.id=a.catalog_id WHERE a.action LIKE 'use\\_case\\_%' ORDER BY a.id DESC LIMIT 300");
 return rows.map(r=>({...r,before_json:parse(r.before_json),after_json:parse(r.after_json),created_at:iso(r.created_at)}));
}
module.exports={FEDERATED,run,scheduled,decide,candidateAction,view,evidenceRefs,auditTrail,summary,fieldState,intakeFacts,governanceFacts,identityFacts,rapid7Facts,identityLive,clean,fingerprint,AUTO,PROTECTED,REQUIRED,SUMMARY,SYSTEM};
