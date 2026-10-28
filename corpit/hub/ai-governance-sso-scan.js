'use strict';
// AI SSO SCAN 2026-10-28: hourly read of the sign-on mode of every Entra / Okta app instance the
// identity snapshot links to a catalog app. An enabled SAML / OIDC / WS-Fed instance, or an Entra app
// with tenant-wide openid consent, fills the risk
// assessment's "Okta / SSO used?" with Yes, whatever the account record says. Name-only Okta
// matches are not used here; the account form's "Check now" still shows those.
const E=require('./ai-governance-use-case-enrich');
const KEY='sso_scan',SYSTEM='system:ai-governance-sso-scan',HOUR=60*60000;
let lastFailure=0;
// Third-party OIDC apps ("Sign in with Microsoft") have no SSO mode in Entra; tenant-wide admin
// consent to the openid scope plus a group assignment is the sign-in evidence for those.
async function entraConsent(ids,{getToken=()=>require('./entra-sync').getAccessToken(),fetchImpl=fetch,budgetMs=30000}={}){
 const out=new Map(),errors=[],deadline=Date.now()+budgetMs;if(!ids.length)return {out,errors};
 let token;try{token=await getToken();}catch{return {out,errors:ids.map(id=>({provider:'Entra',id,error:'consent: no token'}))};}
 for(const id of ids){
  if(!/^[0-9a-f-]{36}$/.test(id)||Date.now()>=deadline){errors.push({provider:'Entra',id,error:'consent: '+(Date.now()>=deadline?'time budget reached':'not a service principal ID')});continue;}
  try{const get=async path=>{const r=await fetchImpl('https://graph.microsoft.com/v1.0/servicePrincipals/'+id+path,{redirect:'error',headers:{Authorization:'Bearer '+token,Accept:'application/json'},signal:AbortSignal.timeout(8000)});if(!r.ok)throw new Error('HTTP '+r.status);return (await r.json()).value||[];};
   const consented=(await get('/oauth2PermissionGrants')).some(g=>g.consentType==='AllPrincipals'&&String(g.scope||'').split(/\s+/).includes('openid'));
   // Consent alone lets anyone sign in; it counts only once a group is assigned to the app.
   out.set(id,consented&&(await get('/appRoleAssignedTo?$select=principalType&$top=999')).some(a=>a.principalType==='Group'));
  }catch(e){errors.push({provider:'Entra',id,error:'consent: '+(e.message||'request failed')});}
 }
 return {out,errors};
}
const parsed=v=>!v?{}:typeof v==='string'?JSON.parse(v):v;
function linkedInstances(ia){
 const out=new Map();
 for(const u of ia.users||[])for(const e of u.evidence||[])if(u.catalog_id&&e.instance_id&&e.instance_active!==false){const k=u.provider+':'+e.instance_id;if(!out.has(k))out.set(k,{provider:u.provider,id:String(e.instance_id),name:e.instance_name||'',catalog_id:u.catalog_id});}
 return out;
}
async function run(pool,{live=E.identityLive,consent=entraConsent,budgetMs=60000,identity=null}={}){
 const [rows]=await pool.query("SELECT source_key,payload FROM ai_governance_source WHERE source_key IN ('identity_access',?)",[KEY]);
 const get=k=>parsed(rows.find(r=>r.source_key===k)?.payload);
 const ia=identity||get('identity_access'),prev=get(KEY),all=linkedInstances(ia),list=[...all.values()];
 const results=[],errors=[];let requests=0;
 // identityLive reads 40 instances per call.
 for(let i=0;i<list.length;i+=40){const r=await live(new Map(list.slice(i,i+40).map(x=>[x.provider+':'+x.id,x])),{budgetMs});results.push(...r.results);errors.push(...r.errors);requests+=r.requests;}
 const c=await consent(results.filter(r=>r.provider==='Entra'&&r.enabled&&!r.mode).map(r=>r.id));errors.push(...c.errors);
 for(const r of results)if(c.out.get(r.id)){r.mode='OIDC admin consent';r.consented=true;}
 const fresh=new Set(results.map(r=>r.provider+':'+r.id));
 // A failed read keeps the last known result for that instance rather than dropping it.
 const kept=(prev.results||[]).filter(r=>all.has(r.provider+':'+r.id)&&!fresh.has(r.provider+':'+r.id)&&errors.some(e=>e.provider===r.provider&&String(e.id)===String(r.id))).map(r=>({...r,retained:true}));
 const out=[...results.map(r=>({catalog_id:r.catalog_id,provider:r.provider,id:r.id,name:r.name,mode:r.mode,enabled:r.enabled,federated:!!(r.enabled&&(r.consented||E.FEDERATED[r.provider]?.has(r.mode))),checked_at:r.checked_at||new Date().toISOString()})),...kept];
 const payload={schema_version:1,checked_at:new Date().toISOString(),identity_checked_at:ia.checked_at||null,instances:list.length,read:results.length,requests,status:!list.length?'current':!results.length?'failed':errors.length?'partial':'current',results:out,errors:errors.slice(0,50),note:'Sign-on setup of linked app instances. Not proof that every user or API path signs in through it.'};
 await pool.query('INSERT INTO ai_governance_source(source_key,payload,checked_by) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),checked_by=VALUES(checked_by),checked_at=CURRENT_TIMESTAMP',[KEY,JSON.stringify(payload),SYSTEM]);
 return payload;
}
// Hourly, and also right after each identity refresh, so a newly linked app instance is read within one tick.
async function scheduled(pool,options={}){
 if(Date.now()-lastFailure<15*60000)return null;
 try{
  const [r]=await pool.query("SELECT source_key,checked_at FROM ai_governance_source WHERE source_key IN ('identity_access',?)",[KEY]);
  const scan=r.find(x=>x.source_key===KEY),ia=r.find(x=>x.source_key==='identity_access');
  const newIdentity=ia&&scan&&new Date(ia.checked_at)>new Date(scan.checked_at);
  if(scan&&!newIdentity&&Date.now()-new Date(scan.checked_at).getTime()<HOUR)return null;
  return await run(pool,options);
 }catch(e){lastFailure=Date.now();throw e;}
}
// catalog_id -> enabled federated instances, for the risk assessment.
async function federatedByApp(pool){
 const [r]=await pool.query('SELECT payload FROM ai_governance_source WHERE source_key=?',[KEY]);
 const p=parsed(r[0]?.payload),out=new Map();
 for(const x of p.results||[])if(x.federated){if(!out.has(x.catalog_id))out.set(x.catalog_id,[]);out.get(x.catalog_id).push(x);}
 return out;
}
module.exports={KEY,run,scheduled,federatedByApp,linkedInstances};
