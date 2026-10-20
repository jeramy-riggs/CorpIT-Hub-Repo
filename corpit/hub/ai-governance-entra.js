'use strict';
// A governance-only Graph read. Does not run the broader identity sync or write
// its shared caches. Uses the existing app credentials and granted permissions.
const norm=v=>String(v||'').toLowerCase().replace(/[^a-z0-9]/g,'');
function snapshot(rows,catalog,refs,checked_at=new Date().toISOString(),partial=false){
 const match=require('./ai-governance-sources-routes').match;
 const candidates=[];
 for(const r of rows){
  const ref=refs.find(x=>[x.name,...x.aliases].some(n=>norm(n)===norm(r.display_name))),existing=match(r.display_name,[],catalog);
  if(!ref&&!existing&&!/chatgpt|anthropic|claude|gemini|copilot|perplexity|bedrock|cursor|grammarly|dovetail|zoom|darktrace|amplitude|loopio|adobe.*acrobat/i.test(r.display_name))continue;
  candidates.push({code:r.entra_id,name:r.display_name,vendor:r.publisher_name,aliases:[],catalog_id:existing?existing.id:null,evidence_kind:'enterprise_app_presence',url:'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/'+encodeURIComponent(r.entra_id),capability_name:ref?ref.capability_name:null,suggested_category:ref?ref.suggested_category:null,capability_url:ref?ref.url:null,observed_at:checked_at,match_basis:ref?'Exact vendor reference name':existing?'Exact inventory name/alias':'Name signal only; classification requires review'});
 }
 return {checked_at,origin:'Microsoft Graph',sources:[{name:'Entra enterprise applications (Microsoft Graph)',status:200,count:candidates.length,scanned:rows.length,partial,oldest_cache:null,newest_cache:null,note:'Direct read of service principals with existing application permissions. Presence does not establish assignment, license, AI-feature use or approval.'}],candidates};
}
function client({fetchImpl=fetch,getToken=()=>require('./entra-sync').getAccessToken(),sleep=ms=>new Promise(r=>setTimeout(r,ms))}={}){
 return {async get(path){const u=new URL(path,'https://graph.microsoft.com');if(u.origin!=='https://graph.microsoft.com'||u.username||u.password||u.pathname!=='/v1.0/servicePrincipals')throw new Error('Rejected Graph continuation');
 const token=await getToken();for(let i=0;i<2;i++){
 const r=await fetchImpl(u,{redirect:'error',headers:{Authorization:'Bearer '+token,Accept:'application/json'},signal:AbortSignal.timeout(20000)});
 if(r.status===429&&i===0){const seconds=Number(r.headers.get('retry-after')||3);if(!Number.isFinite(seconds)||seconds>15)throw new Error('Graph rate limit; retry later');await sleep(Math.max(1,seconds)*1000);continue;}
 if(!r.ok)throw Object.assign(new Error('Microsoft Graph HTTP '+r.status),{status:r.status});const d=await r.json();if(!Array.isArray(d.value))throw new Error('Unexpected Graph response');return d;
 }throw new Error('Graph read did not complete');}};
}
async function collect({catalog,refs,api=client(),now=Date.now}){
 const rows=[],seen=new Set(),deadline=now()+120000;let path='/v1.0/servicePrincipals?$select=id,displayName,publisherName&$top=100',pages=0;
 while(path){if(++pages>100||now()>deadline)throw new Error('Entra collection exceeded its page/time budget; previous evidence retained');
 const d=await api.get(path);for(const x of d.value){if(!x.id||typeof x.displayName!=='string')throw new Error('Unexpected Graph application record');if(!seen.has(x.id)){seen.add(x.id);rows.push({entra_id:x.id,display_name:x.displayName,publisher_name:x.publisherName||null});}}path=d['@odata.nextLink']||null;
 }
 return snapshot(rows,catalog,refs,new Date(now()).toISOString());
}
module.exports={client,collect,snapshot};
