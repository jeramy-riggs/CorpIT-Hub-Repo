(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.AIGovernanceUsageModel=api;})(typeof window==='object'?window:this,function(){'use strict';
 const norm=v=>String(v??'').normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu,'');
 const count=v=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0?v:null;
 const timestamp=v=>{if(v==null||v==='')return null;const n=typeof v==='number'?v:Date.parse(v);return Number.isFinite(n)&&n>0?n:null;};
 function match(name,apps){const key=norm(name);if(!key)return {id:null,state:'Unmatched'};let rows=apps.filter(a=>norm(a.app_name)===key);if(!rows.length)rows=apps.filter(a=>(Array.isArray(a.aliases)?a.aliases:String(a.aliases||'').split(/\r?\n/)).some(x=>norm(x)===key));return rows.length===1?{id:Number(rows[0].id),state:'Matched'}:{id:null,state:rows.length?'Ambiguous':'Unmatched'};}
 function feed(result,now=Date.now()){const d=result?.data;if(!result?.ok||d?.ok!==true)return {state:'Unavailable',last:null,note:result?.error||'Feed health unavailable'};const last=timestamp(d.last_event_ts);if(!last||last>now+300000)return {state:'Unknown',last:null,note:'No valid last-event time returned'};const age=Math.max(0,(now-last)/60000);return {state:age<=15?'Recent events':age<=60?'Slow / quiet':'Stale',last,note:'Last event age: '+Math.round(age)+' minutes. This is event recency, not a complete ingestion heartbeat.'};}
 function build({apps=[],top,status,health,shadow,hours=168,now=Date.now()}){
  const freshness=feed(health,now),validTop=top?.ok&&top.data?.hours===hours&&Array.isArray(top.data.apps),validStatus=status?.ok&&status.data?.streaming===true&&status.data?.hours===hours;
  const rows=validTop?top.data.apps.slice(0,50).filter(r=>typeof r.app==='string'&&r.app.trim()).map(r=>({name:r.app,...match(r.app,apps),total:count(r.total),users:count(r.users),allowed:count(r.allowed),blocked:count(r.blocked),isolated:count(r.isolated)})):[];
  const summary={};for(const k of ['transactions','users','apps','allowed','blocked','isolated'])summary[k]=validStatus?count(status.data[k]):null;
  const report=shadow&&Array.isArray(shadow.rows)?shadow:null;
  const reportRows=report?report.rows.filter(r=>r.ai_relevant||r.catalog_id).map(r=>({...r,users:count(r.users),transactions:count(r.transactions),id:apps.some(a=>Number(a.id)===Number(r.catalog_id))?Number(r.catalog_id):null})):[];
  return {hours,received_at:now,feed:freshness,summary,rows,top_available:!!validTop,top_error:validTop?'':top?.error||'Application usage response unavailable or incomplete',status_available:!!validStatus,status_error:validStatus?'':status?.error||'Usage totals unavailable or incomplete',top_cached_at:validTop?timestamp(top.data.cachedAt):null,status_cached_at:validStatus?timestamp(status.data.cachedAt):null,top_capped:rows.length===50,shadow:report,reportRows};
 }
 function details(result,name,hours,now=Date.now()){
  if(!result?.ok||result.data?.hours!==hours||!Array.isArray(result.data.events))throw new Error(result?.error||'Application activity response is incomplete');
  const rows=result.data.events.slice(0,500),since=now-hours*3600000,people=new Map();let unidentified=0,ignored=0,valid=0;
  for(const e of rows){const ts=timestamp(e.ts);if(e.app!==name||!ts||ts<since||ts>now+300000){ignored++;continue;}valid++;
   const user=typeof e.user==='string'?e.user.trim():'';if(!user||/^(unknown|anonymous|n\/a|none|-)$/i.test(user)){unidentified++;continue;}
   let p=people.get(user);if(!p){p={user,total:0,allowed:0,blocked:0,isolated:0,other:0,first_seen:ts,last_seen:ts,departments:new Set()};people.set(user,p);}p.total++;p.first_seen=Math.min(p.first_seen,ts);p.last_seen=Math.max(p.last_seen,ts);
   const action=String(e.action||'');if(/block|deny|drop/i.test(action))p.blocked++;else if(/isolat/i.test(action))p.isolated++;else if(/allow/i.test(action))p.allowed++;else p.other++;
   if(typeof e.department==='string'&&e.department.trim())p.departments.add(e.department.trim());
  }
  return {people:[...people.values()].map(p=>({...p,departments:[...p.departments]})).sort((a,b)=>b.total-a.total),returned:rows.length,valid,unidentified,ignored,capped:rows.length===500};
 }
 return {norm,count,timestamp,match,feed,build,details};
});
