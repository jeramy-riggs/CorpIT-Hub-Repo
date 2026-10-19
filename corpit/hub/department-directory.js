'use strict';
const ldap=require('ldapjs');
const norm=dn=>String(dn||'').trim().toLowerCase().replace(/\s*,\s*/g,',');
const esc=v=>String(v).replace(/\\/g,'\\5c').replace(/\*/g,'\\2a').replace(/\(/g,'\\28').replace(/\)/g,'\\29').replace(/\0/g,'\\00');
const EMAIL=/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
function fail(message,status=400){const e=new Error(message);e.status=status;throw e;}
async function connect(){
  return new Promise((resolve,reject)=>{
    const c=ldap.createClient({url:process.env.LDAP_URL,connectTimeout:5000,timeout:5000});
    let bound=false;
    c.on('error',e=>{if(!bound){c.destroy();reject(e);}});
    c.bind(process.env.LDAP_BIND_USER,process.env.LDAP_BIND_PASS,e=>{if(e){c.destroy();reject(e);}else{bound=true;resolve(c);}});
  });
}
function search(c,base,filter,attributes,scope='sub'){
  return new Promise((resolve,reject)=>{
    const rows=[];
    c.search(base,{scope,filter,attributes,sizeLimit:1000,timeLimit:5},(e,r)=>{
      if(e)return reject(e);
      r.on('searchEntry',entry=>{const o={dn:entry.dn.toString()};for(const a of entry.attributes||[]) {const vals=a.values||a.vals||[];o[a.type.toLowerCase()]=vals.length===1?vals[0]:vals;}rows.push(o);});
      r.on('error',reject);r.on('end',r=>r.status?reject(new Error('Directory search did not complete')):resolve(rows));
    });
  });
}
const attrs=['cn','displayName','mail','userPrincipalName','member','memberOf','groupType','userAccountControl','adminCount'];
const array=v=>v==null?[]:Array.isArray(v)?v:[v];
async function user(c,email){
  if(!EMAIL.test(email))fail('Enter a valid company email');
  const rows=await search(c,process.env.LDAP_BASE_DN,`(&(objectCategory=person)(objectClass=user)(|(mail=${esc(email)})(userPrincipalName=${esc(email)})))`,attrs);
  if(rows.length!==1)fail(rows.length?'Directory identity is ambiguous':'Person not found in AD',404);
  const u=rows[0];if((Number(u.useraccountcontrol)||0)&2)fail('This AD account is disabled',403);
  if(String(u.mail||u.userprincipalname||'').toLowerCase()!==email)fail('Use the person’s primary email address');
  return u;
}
async function group(c,dn){
  if(typeof dn!=='string'||dn.length>1500||!norm(dn).endsWith(','+norm(process.env.LDAP_BASE_DN)))fail('Select a group in this directory');
  const rows=await search(c,dn,'(objectClass=group)',attrs,'base');
  if(rows.length!==1||!(Number(rows[0].grouptype)&0x80000000))fail('Select an AD security group');
  return rows[0];
}
async function writableGroup(pool,c,role){
  if(typeof role!=='string'||! /^[a-z0-9][a-z0-9-]{0,63}$/.test(role))fail('Choose a mapped department group');
  const [rows]=await pool.query('SELECT role_key,ad_group_dn FROM rbac_roles WHERE role_key=?',[role]);
  if(rows.length!==1||!rows[0].ad_group_dn)fail('Choose a mapped department group');
  const g=await group(c,rows[0].ad_group_dn);
  if (Number(g.admincount) === 1 || !/^SaaS-ITH-(MGR|HR|LGL|SEC|CLO|CTO|CEO)$/i.test(String(g.cn))) fail('AD membership editing is limited to dedicated CorpIT approval groups. This group can still receive an app policy.',403);
  if(!/^(approver-|portal-dept-)/.test(role))fail('Platform groups cannot be edited from department access',403);
  // The same AD group can map to several roles. Any extra platform role protects it.
  const [uses]=await pool.query('SELECT role_key,default_access,ad_group_dn FROM rbac_roles WHERE ad_group_dn IS NOT NULL');
  const related=uses.filter(r=>norm(r.ad_group_dn)===norm(g.dn));
  if(related.some(r=>! /^(approver-|portal-dept-)/.test(r.role_key)||r.default_access!=='none'))fail('This group also grants platform privileges. Use an app-only override.',403);
  const keys=related.map(r=>r.role_key);
  const [other]=await pool.query("SELECT role_key,page_key,access_level FROM rbac_role_pages WHERE role_key IN (?) AND page_key NOT IN ('approver-portal','accessportal') AND access_level <> 'none'",[keys]);
  g.other_resources=other;
  return g;
}
async function modify(c,dn,userDn,action){
  const change=new ldap.Change({operation:action==='add'?'add':'delete',modification:new ldap.Attribute({type:'member',values:[userDn]})});
  await new Promise((resolve,reject)=>c.modify(dn,change,e=>e?reject(e):resolve()));
}
async function withDirectory(fn){let c;try{c=await connect();return await fn(c);}finally{if(c){try{c.unbind(()=>{});}catch(e){c.destroy();}}}}
module.exports={norm,esc,EMAIL,fail,search,user,group,writableGroup,modify,withDirectory,array,attrs};
