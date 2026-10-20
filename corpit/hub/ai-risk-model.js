'use strict';
// Field definitions are captured from the existing portal workbook contract.
const fields = require('./ai-risk-fields.json');
const baseKeys = new Set(['name','what','cat','bowner','vendor','sso']);
const editable = fields.filter(f => !baseKeys.has(f.key));
function fail(message, status=400) { throw Object.assign(new Error(message), {status}); }
function parsed(v) { if (!v) return {}; return typeof v==='string' ? JSON.parse(v) : v; }
function validDate(v) { return /^\d{4}-\d{2}-\d{2}$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString().slice(0,10)===v; }
function validate(body) {
  if (!body || typeof body!=='object' || Array.isArray(body)) fail('An assessment object is required');
  const out={};
  for (const f of editable.concat([{key:'basis',label:'Assessment rationale',kind:'long'}, {key:'evidence_url',label:'Assessment evidence URL',kind:'url'}])) {
    const raw=body[f.key];
    if (raw!=null && typeof raw!=='string') fail(f.label+' must be text');
    const v=String(raw||'').trim();
    if (v.length>(f.kind==='long'?4000:f.kind==='url'?2000:255)) fail(f.label+' is too long');
    if (v && f.allowed && !f.allowed.includes(v)) fail('Unsupported '+f.label);
    if (v && f.kind==='date' && !validDate(v)) fail('Invalid '+f.label);
    out[f.key]=v;
  }
  if (out.evidence_url) {
    let u; try { u=new URL(out.evidence_url); } catch { fail('Use an HTTPS assessment evidence URL'); }
    if (u.protocol!=='https:' || u.username || u.password) fail('Use an HTTPS evidence URL without credentials');
  }
  if (out.tier && (!out.revby || !out.revdate || !out.basis || !out.evidence_url)) fail('A risk tier requires reviewer, review date, rationale and evidence URL');
  if (out.revdate && out.revdate>new Date().toISOString().slice(0,10)) fail('Review date cannot be in the future');
  return out;
}
function assessment(app, now=new Date()) {
  const p=parsed(app.risk_profile), account=parsed(app.corporate_account);
  const data={...p,name:app.app_name||'',what:app.business_purpose||'',cat:app.category||'',bowner:app.owner||'',vendor:app.vendor||'',
    sso:account.sso_status==='configured'?'Yes':account.sso_status==='reported'?'Partial':account.sso_status==='not_applicable'?'N/A':''};
  const conditional=new Set();
  if (data.agentic==='Yes') conditional.add('agtools');
  if (data.client==='Yes') conditional.add('clients');
  if (data.third==='Yes') conditional.add('training');
  if (['API','MCP','SDK / library'].includes(data.access) || data.agentic==='Yes') conditional.add('keys');
  const coverage=fields.map(f=>{
    const v=String(data[f.key]||'').trim();
    const unknown=/^(unknown|unsure|tbd|unclassified|not verified)$/i.test(v);
    const state=!v?'missing':unknown || (f.key==='sso'&&v==='Partial')?'partial':'available';
    const controlGap=(f.key==='siem'&&['No','Partial','Unknown'].includes(v))||(f.key==='sso'&&['No','Partial'].includes(v))||(f.key==='training'&&data.third==='Yes'&&['Unknown','Not prohibited'].includes(v));
    return {control_gap:controlGap,key:f.key,label:f.label,section:f.section,required:!!f.required||conditional.has(f.key),state,value:v,
      source:baseKeys.has(f.key)?f.key==='sso'?'Corporate account record':'Application catalog':'Risk assessment'};
  });
  const required=coverage.filter(f=>f.required), complete=required.filter(f=>f.state==='available').length;
  const triggers=[];
  for (const [key,label] of [['npi','NPI'],['client','Client data'],['consumer','Consumer data'],['ext','External output']]) if(data[key]==='Yes')triggers.push(label);
  if(data.oversight==='Fully automated')triggers.push('Fully automated');
  if(data.agentic==='Yes')triggers.push('Agent tools / permissions');
  if(data.instance==='Public / consumer')triggers.push('Public / consumer instance');
  let next='';
  if(data.tier && validDate(data.revdate||'')) {
    if(data.tier==='Low') next='On material change';
    else {const [y,m,d]=data.revdate.split('-').map(Number),month=m-1+(data.tier==='High'?3:12);const date=new Date(Date.UTC(y,month,1));const last=new Date(Date.UTC(date.getUTCFullYear(),date.getUTCMonth()+1,0)).getUTCDate();date.setUTCDate(Math.min(d,last));next=date.toISOString().slice(0,10);}
  }
  const reviewed=!!(data.tier&&data.revby&&data.revdate&&data.basis&&data.evidence_url);
  return {profile:p,revision:Number(app.risk_revision)||0,updated_at:app.risk_updated_at||null,updated_by:app.risk_updated_by||null,
    coverage,required_total:required.length,required_complete:complete,required_gaps:required.length-complete,
    missing:coverage.filter(f=>f.state==='missing').length,partial:coverage.filter(f=>f.state==='partial').length,
    control_gaps:coverage.filter(f=>f.control_gap).map(f=>({key:f.key,label:f.label,value:f.value})),triggers,tier:reviewed?data.tier:null,review_status:reviewed?'Recorded':Object.values(p).some(Boolean)?'In progress':'Unassessed',
    next_review:next,overdue:/^\d{4}-\d{2}-\d{2}$/.test(next)&&next<now.toISOString().slice(0,10)};
}
module.exports={fields,editable,validate,assessment,parsed};
