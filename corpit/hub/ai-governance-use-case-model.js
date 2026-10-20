'use strict';
// AI USE-CASE INVENTORY 2026-10-20. One record per use case from the InfoSec / Legal
// "AI/ML Use Inventory" workbook. The fields are the workbook's own columns (the same
// definitions as the app-level assessment, ai-risk-fields.json), stored as one JSON profile.
// Required (*) columns may be blank: the workbook itself counts them in "Required fields
// still blank" (AK). Only the name is needed to keep a record.
const fields=require('./ai-risk-fields.json');
const KEYS=new Set(fields.map(f=>f.key));
// Workbook columns: A = ID, B..AS = fields in order, with the three calculated columns
// (AK, AM, AR) at their template positions.
const CALC={AK:{key:'required_blank',label:'Required fields still blank'},AM:{key:'auto_flag',label:'Auto-flag: high-risk trigger present'},AR:{key:'next_review',label:'Next review due'}};
function letter(n){let s='';for(n++;n>0;n=Math.floor((n-1)/26))s=String.fromCharCode(65+(n-1)%26)+s;return s;}
const COLUMNS=[{col:'A',key:'id',label:'ID (InfoSec assigns)'}];
for(let i=1,f=0;f<fields.length||COLUMNS.length<45;i++){const col=letter(i);if(CALC[col])COLUMNS.push({col,...CALC[col],calculated:true});else COLUMNS.push({col,key:fields[f].key,label:fields[f].label,field:fields[f++]});}
const HEADERS=COLUMNS.map(c=>c.label+(c.field&&c.field.required?' *':''));
const MAX={text:255,long:4000};
const squash=v=>String(v).replace(/\s+/g,' ').trim();
function validDate(v){return /^\d{4}-\d{2}-\d{2}$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,10)===v;}
// Returns {profile, problems}. Select values match the workbook list ignoring case and
// spacing and are stored in the list's spelling.
function check(body){
  const problems=[],profile={};
  if(!body||typeof body!=='object'||Array.isArray(body))return {profile,problems:['A use-case object is required']};
  for(const k of Object.keys(body))if(!KEYS.has(k))problems.push('Unknown field '+String(k).slice(0,40));
  for(const f of fields){
    const raw=body[f.key];
    if(raw!=null&&typeof raw!=='string'){problems.push(f.label+' must be text');continue;}
    let v=String(raw||'').trim();
    if(v.length>(f.kind==='long'?MAX.long:MAX.text)){problems.push(f.label+' is longer than '+(f.kind==='long'?MAX.long:MAX.text)+' characters');continue;}
    if(v&&f.allowed){const hit=f.allowed.find(a=>squash(a).toLowerCase()===squash(v).toLowerCase());if(!hit){problems.push(f.label+': "'+v.slice(0,60)+'" is not one of the workbook choices');continue;}v=hit;}
    if(v&&f.kind==='date'&&!validDate(v)){problems.push(f.label+': "'+v.slice(0,30)+'" is not a date (YYYY-MM-DD)');continue;}
    profile[f.key]=v;
  }
  if(profile.name==='')problems.push('Name of AI/ML use or system is required');
  return {profile,problems};
}
function validate(body){const r=check(body);if(r.problems.length)throw Object.assign(new Error(r.problems[0]),{status:400,problems:r.problems});return r.profile;}
function parsed(v){if(!v)return {};return typeof v==='string'?JSON.parse(v):v;}
// The workbook's own formulas: AK counts blank required columns, AM flags the high-risk
// triggers, AR adds 3 / 12 months to the review date by tier (EDATE: clamp to month end).
function edate(day,months){const [y,m,d]=day.split('-').map(Number);const t=new Date(Date.UTC(y,m-1+months,1));const last=new Date(Date.UTC(t.getUTCFullYear(),t.getUTCMonth()+1,0)).getUTCDate();t.setUTCDate(Math.min(d,last));return t.toISOString().slice(0,10);}
function calc(p){
  if(!p.name)return {required_blank:'',auto_flag:'',next_review:''};
  const required_blank=fields.filter(f=>f.required&&!String(p[f.key]||'').trim()).length;
  const auto_flag=p.npi==='Yes'||p.client==='Yes'||p.consumer==='Yes'||p.ext==='Yes'||p.oversight==='Fully automated'?'Review for High':'-';
  let next_review='';
  if(p.tier&&validDate(p.revdate||''))next_review=p.tier==='High'?edate(p.revdate,3):p.tier==='Medium'?edate(p.revdate,12):'On material change';
  return {required_blank,auto_flag,next_review};
}
const ref=n=>'UC-'+String(n).padStart(4,'0');
const refId=v=>{const m=/^UC-0*(\d{1,9})$/i.exec(String(v||'').trim());return m?Number(m[1]):null;};
module.exports={fields,COLUMNS,HEADERS,check,validate,parsed,calc,ref,refId,validDate};
