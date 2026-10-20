'use strict';
// Identity reads only. Rows are stored in a separate, permission-gated snapshot.
const {target,oktaNext}=require('./ai-governance-access-transport');
async function collect({catalog,runId,fetchImpl=fetch,getToken=()=>require('./entra-sync').getAccessToken(),oktaOrigin=process.env.OKTA_BASE_URL,oktaToken=process.env.OKTA_API_TOKEN,now=Date.now}){
 const started=now(),deadline=started+180000,maxRequests=150,maxRows=10000,checked_at=new Date(started).toISOString();let requests=0,token;
 const checks=[],users=new Map(),profiles=new Map(),groups=new Map(),instances=[],blocked=new Map(),match=require('./ai-governance-sources-routes').match;
 async function read(provider,path,{single=false}={}){
  const rows=[],visited=new Set();let next=path,status=null,reason='complete',pages=0;
  while(next){
   if(blocked.has(provider)){status=blocked.get(provider);reason='provider_read_denied';break;}
   if(now()>=deadline||requests>=maxRequests){reason='collection_budget';break;}
   if(visited.has(next)){reason='pagination_loop';break;}visited.add(next);
   try{const url=target(provider,next,oktaOrigin);requests++;
    const r=await fetchImpl(url,{method:'GET',redirect:'error',headers:{Authorization:provider==='Entra'?'Bearer '+token:'SSWS '+oktaToken,Accept:'application/json'},signal:AbortSignal.timeout(Math.max(1,Math.min(12000,deadline-now())))});status=r.status;
    if(!r.ok){if(status===401||status===403)blocked.set(provider,status);reason='http_'+status;break;}const d=await r.json(),page=single?[d]:provider==='Entra'?d.value:d;
    if(!Array.isArray(page)){reason='unexpected_response';break;}pages++;
    const left=maxRows-rows.length;rows.push(...page.slice(0,left));next=single?null:provider==='Entra'?d['@odata.nextLink']||null:oktaNext(r.headers.get('link'));
    if(page.length>left||(rows.length>=maxRows&&next)){reason='row_cap';break;}
   }catch(e){reason=/Timeout|Abort/.test(e.name)?'request_timeout':'request_failed';break;}
  }
  return {rows,complete:reason==='complete',status,stop_reason:reason,pages};
 }
 const meta=x=>({complete:x.complete,status:x.status,stop_reason:x.stop_reason,pages:x.pages,rows:x.rows.length});
 const check=(provider,kind,r,app=null)=>{const m={provider,kind,...meta(r),...(app?{catalog_id:app.id}: {})};checks.push(m);return m;};
 function person(app,provider,id){if(!id)return null;const key=app.id+'|'+provider+'|'+id;let u=users.get(key);if(!u){u={catalog_id:Number(app.id),provider,provider_user_id:id,display_name:null,user_identity:null,account_enabled:null,evidence:[]};users.set(key,u);}return u;}
 function add(app,provider,id,evidence,profile){const u=person(app,provider,id);if(!u)return;if(profile){if(profile.displayName)u.display_name=profile.displayName;if(profile.userPrincipalName)u.user_identity=profile.userPrincipalName;if(typeof profile.accountEnabled==='boolean')u.account_enabled=profile.accountEnabled;}
  const key=JSON.stringify(evidence);if(!u.evidence.some(x=>JSON.stringify(x)===key))u.evidence.push(evidence);
 }
 try{token=await getToken();}catch{checks.push({provider:'Entra',kind:'authentication',complete:false,status:null,stop_reason:'authentication_failed',rows:0,pages:0});}
 const e=token?await read('Entra','/v1.0/servicePrincipals?$select=id,displayName,accountEnabled,appRoleAssignmentRequired,appRoles&$top=999'):{rows:[],complete:false,status:null,stop_reason:'authentication_failed',pages:0};check('Entra','applications',e);
 const o=oktaOrigin&&oktaToken?await read('Okta','/api/v1/apps?limit=200'):{rows:[],complete:false,status:null,stop_reason:'not_configured',pages:0};check('Okta','applications',o);
 for(const sp of e.rows){const app=match(sp.displayName,[],catalog);if(!app)continue;
  const active=sp.accountEnabled===true,inst={catalog_id:Number(app.id),provider:'Entra',id:sp.id,name:sp.displayName,active,assignment_required:sp.appRoleAssignmentRequired};instances.push(inst);
  const a=await read('Entra','/v1.0/servicePrincipals/'+encodeURIComponent(sp.id)+'/appRoleAssignedTo?$select=id,principalId,principalType,appRoleId,createdDateTime&$top=999');check('Entra','app_assignments',a,app);
  for(const row of a.rows){const role=(sp.appRoles||[]).find(x=>x.id===row.appRoleId),basis={instance_id:sp.id,instance_name:sp.displayName,instance_active:active,assignment_required:sp.appRoleAssignmentRequired,source_record_id:row.id,assignment_date:row.createdDateTime||null,role:row.appRoleId==='00000000-0000-0000-0000-000000000000'?'Default app access':role?.displayName||'Role not resolved',role_id:row.appRoleId||null};
   if(row.principalType==='User')add(app,'Entra',row.principalId,{...basis,kind:'direct_app_assignment',date_meaning:'Directory app-role assignment created; original vendor grant date unknown.'});
   if(row.principalType==='Group'){
    if(!groups.has(row.principalId))groups.set(row.principalId,await read('Entra','/v1.0/groups/'+encodeURIComponent(row.principalId)+'/members/microsoft.graph.user?$select=id,displayName,userPrincipalName,accountEnabled&$top=999'));
    const g=groups.get(row.principalId);check('Entra','direct_group_members',g,app);
    for(const member of g.rows){profiles.set(member.id,member);add(app,'Entra',member.id,{...basis,kind:'assigned_group_membership',group_id:row.principalId,date_meaning:'Group-to-app assignment created; individual grant date unknown.'},member);}
   }
  }
 }
 for(const appInstance of o.rows){const app=match(appInstance.label,[],catalog);if(!app)continue;const active=appInstance.status==='ACTIVE';instances.push({catalog_id:Number(app.id),provider:'Okta',id:appInstance.id,name:appInstance.label,active,status:appInstance.status});
  const a=await read('Okta','/api/v1/apps/'+encodeURIComponent(appInstance.id)+'/users?limit=500');check('Okta','app_users',a,app);
  for(const row of a.rows){const p=row.profile||{},identity=p.login||p.userName||p.email||null;add(app,'Okta',row.id,{kind:'okta_app_assignment',instance_id:appInstance.id,instance_name:appInstance.label,instance_active:active,source_record_id:row.id,scope:row.scope||'Unknown',provisioning_status:row.status||'Unknown',assignment_date:row.created||null,date_meaning:'Okta app-user assignment created; original vendor grant date unknown.',role:'Vendor role not established'});const u=person(app,'Okta',row.id);if(u){u.user_identity=identity;u.display_name=[p.firstName,p.lastName].filter(Boolean).join(' ')||null;}}
 }
 let licensing=null;
 if(token){const s=await read('Entra','/v1.0/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,consumedUnits');check('Entra','subscribed_skus',s);const sku=s.rows.find(x=>x.skuPartNumber==='Microsoft_365_Copilot'),app=match('Microsoft Copilot',[],catalog);
  if(sku&&app){const a=await read('Entra','/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses,licenseAssignmentStates&$filter='+encodeURIComponent('assignedLicenses/any(x:x/skuId eq '+sku.skuId+')')+'&$top=999');check('Entra','copilot_license_users',a,app);const ids=new Set();
   for(const row of a.rows){if(!(row.assignedLicenses||[]).some(x=>x.skuId===sku.skuId))continue;ids.add(row.id);profiles.set(row.id,row);const states=(row.licenseAssignmentStates||[]).filter(x=>x.skuId===sku.skuId);for(const state of states.length?states:[{}])add(app,'Entra',row.id,{kind:'license_assignment',sku:sku.skuPartNumber,sku_id:sku.skuId,state:state.state||'Not returned',assigned_by_group:state.assignedByGroup||null,assignment_date:state.lastUpdatedDateTime||null,date_meaning:'License assignment state last updated; original grant date unknown.',role:'Microsoft 365 Copilot license',instance_active:true},row);}
   licensing={catalog_id:Number(app.id),sku:sku.skuPartNumber,consumed_units:sku.consumedUnits,distinct_assigned_users:ids.size,complete:a.complete,consumed_matches_users:a.complete?sku.consumedUnits===ids.size:null};
  }
 }
 // Resolve only named direct assignees not already described by membership/license reads.
 for(const u of users.values())if(u.provider==='Entra'){
  if(!profiles.has(u.provider_user_id)){const r=await read('Entra','/v1.0/users/'+encodeURIComponent(u.provider_user_id)+'?$select=id,displayName,userPrincipalName,accountEnabled',{single:true});check('Entra','user_profile',r);profiles.set(u.provider_user_id,r.rows[0]||{});}
  const p=profiles.get(u.provider_user_id);u.display_name=p.displayName||u.display_name;u.user_identity=p.userPrincipalName||u.user_identity;if(typeof p.accountEnabled==='boolean')u.account_enabled=p.accountEnabled;
 }
 const oktaProfiles=new Map();for(const u of users.values())if(u.provider==='Okta'){
  if(!oktaProfiles.has(u.provider_user_id)){const r=await read('Okta','/api/v1/users/'+encodeURIComponent(u.provider_user_id),{single:true});check('Okta','user_profile',r);oktaProfiles.set(u.provider_user_id,r.rows[0]||{});}
  const record=oktaProfiles.get(u.provider_user_id),p=record.profile||{};u.user_identity=p.login||p.email||u.user_identity;u.display_name=[p.firstName,p.lastName].filter(Boolean).join(' ')||u.display_name;u.account_status=record.status||'Unknown';u.account_enabled=record.status==='ACTIVE'?true:['DEPROVISIONED','SUSPENDED'].includes(record.status)?false:null;
 }
 const rows=[...users.values()].sort((a,b)=>a.catalog_id-b.catalog_id||a.provider.localeCompare(b.provider)||a.provider_user_id.localeCompare(b.provider_user_id));
 const apps=[];for(const key of new Set([...instances.map(x=>x.catalog_id+'|'+x.provider),...rows.map(x=>x.catalog_id+'|'+x.provider)])){const [id,provider]=key.split('|'),people=rows.filter(x=>x.catalog_id===Number(id)&&x.provider===provider),appInstances=instances.filter(x=>x.catalog_id===Number(id)&&x.provider===provider),represented=people.filter(x=>x.evidence.some(e=>e.instance_active));
  const count=kind=>represented.filter(x=>x.evidence.some(e=>e.instance_active&&e.kind===kind)).length;
  apps.push({catalog_id:Number(id),provider,user_count:represented.length,direct_assignment_users:count('direct_app_assignment'),group_membership_users:count('assigned_group_membership'),okta_assignment_users:count('okta_app_assignment'),license_assigned_users:count('license_assignment'),disabled_user_accounts:represented.filter(x=>x.account_enabled===false).length,account_status_unknown:represented.filter(x=>x.account_enabled==null).length,inactive_only_users:people.length-represented.length,all_instance_users:people.length,active_instances:appInstances.filter(x=>x.active).length,inactive_instances:appInstances.filter(x=>!x.active).length,instance_assignment_required:appInstances.filter(x=>x.active).map(x=>x.assignment_required).filter(x=>typeof x==='boolean'),checked_at,run_id:runId});
 }
 const sources=['Entra','Okta'].map(provider=>{const c=checks.filter(x=>x.provider===provider);return {name:provider==='Entra'?'Microsoft Entra access evidence':'Okta app assignments',provider,status:c.some(x=>x.status===200)?200:c.find(x=>x.status)?.status||null,partial:!c.length||c.some(x=>!x.complete),count:apps.filter(x=>x.provider===provider).length,note:'Distinct accounts per app/provider; active app instances only. Assignment, membership and license counts overlap and must not be added. Cross-provider unique people are unknown.'};});
 return {schema_version:1,checked_at,completed_at:new Date(now()).toISOString(),run_id:runId,status:sources.some(x=>x.partial)?'partial':'completed',duration_ms:now()-started,requests,limits:{duration_ms:180000,requests:maxRequests,rows_per_endpoint:maxRows},sources,checks,apps,users:rows,licensing,note:'Directory and license evidence only. No access provisioned. AI enablement, vendor seats, business purpose, original grant dates and governance approval are not inferred. Users deduplicate per catalog app/provider ID across instances, membership and licensing; cross-provider identities remain separate.'};
}
function retained(next,previous){if(next.status==='completed'||!previous)return {...next,retained:false,last_attempt:{run_id:next.run_id,checked_at:next.checked_at,status:next.status,sources:next.sources}};return {...previous,retained:true,last_attempt:{run_id:next.run_id,checked_at:next.checked_at,status:next.status,sources:next.sources,checks:next.checks}};}
function summary(d){if(!d)return {schema_version:1,checked_at:null,apps:[],sources:[],status:'not_collected'};const {users,...safe}=d;return safe;}
module.exports={collect,retained,summary};
