'use strict';
// AI AUTO-ADD 2026-10-28: hourly. A known AI app (curated vendor reference or Entra AI candidate) that is
// not in the inventory is added for review once the Zscaler Shadow IT report shows traffic for it
// (e.g. "Dovetail Intelligence Platform" -> Dovetail). Generic "AI & ML" traffic rows are left to
// ai-watch-job: names like "Anthropic AI" / "OpenAI" would duplicate Claude / ChatGPT here.
// A retired inventory record is never re-added.
const S=require('./ai-governance-sources-routes');
const KEY='auto_add',SYSTEM='system:ai-governance-auto-add',HOUR=60*60000;
let lastFailure=0;
const norm=v=>String(v||'').toLowerCase().replace(/[^a-z0-9]/g,'');
const parsed=v=>!v?{}:typeof v==='string'?JSON.parse(v):v;
// Traffic name equals the app name or an alias, or starts with it as whole words ("Dovetail Intelligence Platform").
function trafficFor(names,rows){
 const words=names.map(n=>String(n||'').trim().toLowerCase()).filter(n=>norm(n).length>=4);
 return rows.filter(r=>((r.users||0)>0||(r.transactions||0)>0)&&words.some(n=>{const t=String(r.name||'').trim().toLowerCase();return norm(t)===norm(n)||t.startsWith(n+' ');}));
}
function plan(zscaler,entra,catalog,refs=S.references){
 const rows=zscaler?.shadow_it?.rows||[],out=[],taken=new Set();
 const candidates=[...refs.map(x=>({...x,source_key:'vendor'})),...(entra?.candidates||[]).map(x=>({...x,source_key:'entra',url:x.url}))];
 for(const x of candidates){
  const names=[x.name,...(x.aliases||[])];
  if(taken.has(norm(x.name))||S.match(x.name,x.aliases||[],catalog))continue;
  const traffic=trafficFor(names,rows);if(!traffic.length)continue;
  // Traffic already linked to another inventory record (via its aliases) is not new.
  if(traffic.some(r=>S.match(r.name,[],catalog)))continue;
  taken.add(norm(x.name));out.push({candidate:x,traffic,also:candidates.filter(y=>y!==x&&norm(y.name)===norm(x.name))});
 }
 return out;
}
async function run(pool){
 const [src]=await pool.query("SELECT source_key,payload FROM ai_governance_source WHERE source_key IN ('zscaler','entra')");
 const get=k=>parsed(src.find(r=>r.source_key===k)?.payload);
 const zscaler=get('zscaler'),entra=get('entra');
 // Retired records count as known, so a retired app is not added back.
 const [catalog]=await pool.query('SELECT id,app_name,aliases,retired FROM ai_catalog');
 const added=[];
 for(const {candidate:x,traffic,also} of plan(zscaler,entra,catalog)){
  const users=Math.max(...traffic.map(r=>r.users||0)),transactions=traffic.reduce((n,r)=>n+(r.transactions||0),0);
  const aliases=[...new Set([...(x.aliases||[]),...traffic.map(r=>r.name)].filter(a=>norm(a)!==norm(x.name)))];
  const c=await pool.getConnection();
  try{
   await c.beginTransaction();
   const [dupe]=await c.query('SELECT id FROM ai_catalog WHERE norm_key=? FOR UPDATE',[norm(x.name)]);
   if(dupe.length){await c.rollback();continue;}
   const note=('Auto-added: Zscaler shows traffic as "'+traffic.map(r=>r.name).join('", "')+'" ('+users+' users, '+transactions+' transactions, last 7 days). Not yet reviewed or approved.').slice(0,500);
   const [ins]=await c.query("INSERT INTO ai_catalog(app_name,norm_key,aliases,sanction_status,source,risk_note,created_by,updated_by) VALUES(?,?,?,'review','discovered',?,?,?)",[x.name,norm(x.name),aliases.join('\n')||null,note,SYSTEM,SYSTEM]);
   for(const e of [x,...also]){
    await c.query('INSERT IGNORE INTO ai_governance_evidence SET ?',{catalog_id:ins.insertId,source_key:e.source_key,source_record_id:e.code,evidence_kind:e.evidence_kind,source_url:e.url||null,capability_name:e.capability_name||null,suggested_category:e.suggested_category||null,observed_at:e.observed_at?new Date(e.observed_at):new Date(e.verified_at+'T00:00:00Z'),attached_by:SYSTEM});
   }
   const after={name:x.name,aliases,traffic:traffic.map(r=>({name:r.name,source_id:r.source_id,users:r.users,transactions:r.transactions,category:r.category})),evidence:[x,...also].map(e=>e.source_key+':'+e.code),shadow_it_checked_at:zscaler.shadow_it?.checked_at||zscaler.checked_at||null};
   await c.query('INSERT INTO ai_governance_audit(actor,action,catalog_id,entity_id,after_json) VALUES(?,?,?,?,?)',[SYSTEM,'application_auto_added',ins.insertId,ins.insertId,JSON.stringify(after)]);
   await c.commit();added.push({id:ins.insertId,...after});
  }catch(e){await c.rollback().catch(()=>{});throw e;}finally{c.release();}
 }
 await pool.query('INSERT INTO ai_governance_source(source_key,payload,checked_by) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),checked_by=VALUES(checked_by),checked_at=CURRENT_TIMESTAMP',[KEY,JSON.stringify({schema_version:1,checked_at:new Date().toISOString(),added}),SYSTEM]);
 return added;
}
async function scheduled(pool){
 if(Date.now()-lastFailure<15*60000)return null;
 try{
  const [r]=await pool.query('SELECT checked_at FROM ai_governance_source WHERE source_key=?',[KEY]);
  if(r.length&&Date.now()-new Date(r[0].checked_at).getTime()<HOUR)return null;
  return await run(pool);
 }catch(e){lastFailure=Date.now();throw e;}
}
module.exports={KEY,run,scheduled,plan,trafficFor};
