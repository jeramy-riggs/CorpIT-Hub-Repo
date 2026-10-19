'use strict';
const express=require('express');
const crypto=require('crypto');
const D=require('./department-directory');
const {resolveRoles}=require('./rbac-ad-resolver');
const {evaluate}=require('./portal-access');
const impactHash=g=>crypto.createHash('sha256').update(JSON.stringify((g.other_resources||[]).map(r=>[r.role_key,r.page_key,r.access_level]).sort())).digest('hex');
const cn=dn=>String(dn||'').replace(/^CN=/i,'').split(/(?<!\\),/)[0].replace(/\\,/g,',');
module.exports=function(pool){
  const router=express.Router();
  const rbac=require('./rbac-middleware')(pool);
  router.use(express.json({limit:'32kb'}));
  router.use((req,res,next)=>{req.portalStrictDirectory=true;rbac.loadCurrentUser(req,res,next).catch(next);});
  router.use(rbac.requireSuperAdmin);
  router.use((req,res,next)=>{
    res.set('Cache-Control','no-store');
    if(!['GET','HEAD'].includes(req.method)) {
      const origin=req.get('origin');
      if(origin && origin!=='https://'+req.get('host'))return res.status(403).json({error:'Use this app to make changes'});
    }
    next();
  });
  const wrap=fn=>async(req,res)=>{try{await fn(req,res);}catch(e){console.error('[department-access]',e.name,e.message);res.status(e.status||502).json({error:e.status?e.message:(e.code===50?'The directory account cannot change this group. An AD administrator must delegate membership rights.':'Directory operation failed. No success has been assumed; refresh the person’s access before retrying.')});}};
  // Unlike the platform convenience audit, writes here fail closed before AD mutation.
  const audit=(req,action,email,details)=>pool.execute('INSERT INTO rbac_audit_log (actor_email,action,target_email,target_page_key,details,ip_address,user_agent) VALUES (?,?,?,?,?,?,?)',
    [req.user.email,action,email||null,'approver-portal',JSON.stringify(details),null,String(req.get('user-agent')||'').slice(0,500)]);
  router.get('/groups',wrap(async(req,res)=>{
    const q=String(req.query.q||'').trim();if(q.length<2||q.length>80)D.fail('Enter at least two characters of a security group name');
    const rows=await D.withDirectory(c=>D.search(c,process.env.LDAP_BASE_DN,`(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648)(cn=*${D.esc(q)}*))`,['cn','groupType']));
    res.json({groups:rows.slice(0,100).map(g=>({dn:g.dn,name:g.cn})),truncated:rows.length>100});
  }));
  router.get('/mappings',wrap(async(req,res)=>{
    const [roles]=await pool.query('SELECT role_key,display_name,ad_group_dn,default_access FROM rbac_roles WHERE ad_group_dn IS NOT NULL ORDER BY display_name');
    res.json({roles:roles.map(r=>({...r,membership_editable:/^(approver-|portal-dept-)/.test(r.role_key)&&r.default_access==='none'}))});
  }));
  router.post('/mappings',wrap(async(req,res)=>{
    const dn=req.body.dn;
    const group=await D.withDirectory(c=>D.group(c,dn));
    const [all]=await pool.query('SELECT role_key,display_name,ad_group_dn FROM rbac_roles WHERE ad_group_dn IS NOT NULL');
    const found=all.find(r=>D.norm(r.ad_group_dn)===D.norm(group.dn));
    if(found)return res.json({role:found,existing:true});
    const role='portal-dept-'+crypto.createHash('sha256').update(D.norm(group.dn)).digest('hex').slice(0,16);
    const conn=await pool.getConnection();
    try{
      await conn.beginTransaction();
      await conn.execute("INSERT INTO rbac_roles(role_key,display_name,description,is_system,default_access,ad_group_dn) VALUES(?,?,?,0,'none',?)",[role,String(group.cn).slice(0,100),'Approval Portal group; department grants are managed in Approval Access.',group.dn]);
      // No standalone page grant: a saved approval policy supplies entry.
      await conn.execute('UPDATE rbac_users SET roles_resolved_at=NULL,roles_invalidated_at=NOW()');
      await conn.execute('INSERT INTO rbac_audit_log(actor_email,action,target_page_key,details) VALUES(?,?,?,?)',[req.user.email,'portal.group_mapped','approver-portal',JSON.stringify({role,dn:group.dn})]);
      await conn.commit();
    }catch(e){await conn.rollback();throw e;}finally{conn.release();}
    res.status(201).json({role:{role_key:role,display_name:group.cn,ad_group_dn:group.dn}});
  }));
  router.get('/members',wrap(async(req,res)=>{
    const role=String(req.query.role||'');
    const result=await D.withDirectory(async c=>{
      const [rows]=await pool.query('SELECT ad_group_dn FROM rbac_roles WHERE role_key=?',[role]);
      if(rows.length!==1||!rows[0].ad_group_dn)D.fail('Choose a mapped group');
      const g=await D.group(c,rows[0].ad_group_dn);
      // memberOf evaluates direct membership, matching the shared RBAC resolver.
      const members=await D.search(c,process.env.LDAP_BASE_DN,`(&(objectCategory=person)(objectClass=user)(memberOf=${D.esc(g.dn)}))`,D.attrs);
      let writable=true,restriction='',impact=[];try{const target=await D.writableGroup(pool,c,role);impact=target.other_resources||[];}catch(e){if(!e.status)throw e;writable=false;restriction=e.message;}
      return {group:{name:g.cn,dn:g.dn,role_key:role},writable,restriction,other_resources:impact,impact_hash:impactHash({other_resources:impact}),
        members:members.map(u=>({email:String(u.mail||u.userprincipalname||'').toLowerCase(),name:u.displayname||u.cn,enabled:!((Number(u.useraccountcontrol)||0)&2)})),
        nested_count:Math.max(0,D.array(g.member).length-members.length)};
    });
    res.json(result);
  }));
  const busy=new Set();
  router.post('/memberships',wrap(async(req,res)=>{
    const {role,action}=req.body;const email=String(req.body.email||'').trim().toLowerCase();
    const reason=String(req.body.reason||'').trim();
    if(!['add','remove'].includes(action)||!reason||reason.length>1000)D.fail('Choose Add or Remove and enter a reason (up to 1000 characters)');
    if(typeof req.body.expected_member!=='boolean')D.fail('Refresh membership before saving');
    const key=role+':'+email;if(busy.has(key))D.fail('A membership update is already running for this person',409);busy.add(key);
    let changed=false;
    try{
      const outcome=await D.withDirectory(async c=>{
        const g=await D.writableGroup(pool,c,role),u=await D.user(c,email);
        if(g.other_resources?.length && req.body.expected_impact_hash!==impactHash(g))D.fail('Review the other application permissions for this group before saving.',409);
        const member=D.array(u.memberof).some(d=>D.norm(d)===D.norm(g.dn));
        if(member!==req.body.expected_member)D.fail('Membership changed. Refresh and review before saving.',409);
        if(member===(action==='add'))return {changed:false,member,role,email};
        await audit(req,'portal.ad_membership_requested',email,{role,group:g.dn,action,reason,before:member,other_resources:g.other_resources||[]});
        // Mark stale before and after modifying AD. A failed refresh never leaves a
        // previously cached department grant authoritative at the approval gate.
        await pool.execute('UPDATE rbac_users SET roles_resolved_at=NULL,roles_invalidated_at=NOW() WHERE email=?',[email]);
        try{await D.modify(c,g.dn,u.dn,action);changed=true;}
        catch(e){await audit(req,'portal.ad_membership_failed',email,{role,action,reason,code:e.code||e.name});throw e;}
        await pool.execute('UPDATE rbac_users SET roles_resolved_at=NULL,roles_invalidated_at=NOW() WHERE email=?',[email]);
        const refreshed=await resolveRoles(pool,email);
        if(!refreshed.ok && action==='remove'){
          const [related]=await pool.query('SELECT role_key,ad_group_dn FROM rbac_roles WHERE ad_group_dn IS NOT NULL');
          const keys=related.filter(r=>D.norm(r.ad_group_dn)===D.norm(g.dn)).map(r=>r.role_key);
          await pool.query('DELETE FROM rbac_user_roles WHERE email=? AND role_key IN (?)',[email,keys]);
        }
        await audit(req,'portal.ad_membership_changed',email,{role,group:g.dn,action,reason,before:member,after:action==='add',refresh_ok:refreshed.ok});
        return {changed:true,member:action==='add',role,email,refresh_ok:refreshed.ok,
          warning:refreshed.ok?null:'AD membership changed; app role refresh is pending. Retry Refresh access.'};
      });
      res.json(outcome);
    }catch(e){
      if(changed){console.error('[department-access] AD changed; follow-up failed',email,e.message);return res.status(200).json({changed:true,member:action==='add',email,role,refresh_ok:false,warning:'AD membership changed, but follow-up verification or audit failed. Refresh access and check the recorded change before retrying.'});}
      throw e;
    }finally{busy.delete(key);}
  }));
  router.post('/entry-rule',wrap(async(req,res)=>{
    const email=String(req.body.email||'').trim().toLowerCase(),level=req.body.level,reason=String(req.body.reason||'').trim();
    if(!['inherit','read','admin','none'].includes(level)||!reason||reason.length>1000)D.fail('Choose an entry rule and enter a reason');
    const u=await D.withDirectory(c=>D.user(c,email));
    const conn=await pool.getConnection();
    try{
      await conn.beginTransaction();
      const [before]=await conn.query("SELECT access_level FROM rbac_user_page_access WHERE email=? AND page_key='approver-portal' FOR UPDATE",[email]);
      const previous=before[0]?.access_level||'inherit';
      if(req.body.expected_level!==previous)D.fail('The entry rule changed. Check access and retry.',409);
      // An existing global account disable is never cleared by a portal grant.
      await conn.execute('INSERT INTO rbac_users(email,display_name,is_active) VALUES(?,?,1) ON DUPLICATE KEY UPDATE email=VALUES(email)',[email,u.displayname||email]);
      if(level==='inherit')await conn.execute("DELETE FROM rbac_user_page_access WHERE email=? AND page_key='approver-portal'",[email]);
      else await conn.execute("INSERT INTO rbac_user_page_access(email,page_key,access_level,granted_by) VALUES(?,'approver-portal',?,?) ON DUPLICATE KEY UPDATE access_level=VALUES(access_level),granted_by=VALUES(granted_by),granted_at=NOW()",[email,level,req.user.email]);
      await conn.execute('INSERT INTO rbac_audit_log(actor_email,action,target_email,target_page_key,details) VALUES(?,?,?,?,?)',[req.user.email,'portal.entry_rule_changed',email,'approver-portal',JSON.stringify({before:previous,after:level,reason})]);
      await conn.commit();
    }catch(e){await conn.rollback();throw e;}finally{conn.release();}
    res.json(await preview(email));
  }));
  async function preview(email){
    const u=await D.withDirectory(c=>D.user(c,email));
    const [maps]=await pool.query('SELECT role_key,ad_group_dn FROM rbac_roles WHERE ad_group_dn IS NOT NULL');
    const memberships=D.array(u.memberof);
    const roles=maps.filter(r=>memberships.some(d=>D.norm(d)===D.norm(r.ad_group_dn))).map(r=>r.role_key);
    const [rows]=await pool.query('SELECT is_active,roles_resolved_at,roles_invalidated_at FROM rbac_users WHERE email=?',[email]);
    const isEnv=(process.env.RBAC_SUPERADMINS||'').toLowerCase().split(',').map(x=>x.trim()).includes(email);
    const active=!rows.length||!!rows[0].is_active||isEnv;
    const subject={email,roles,isActive:active,isSuperAdmin:active&&(isEnv||roles.includes('superadmin'))};
    const result=await evaluate(pool,rbac,subject,memberships.map(cn));
    const [entry]=await pool.query("SELECT access_level FROM rbac_user_page_access WHERE email=? AND page_key='approver-portal'",[email]);
    return {email,name:u.displayname||email,roles,entry_override:entry[0]?.access_level||'inherit',account_active:active,roles_resolved_at:rows[0]?.roles_resolved_at||null,
      directory_checked_at:new Date().toISOString(),...result,
      authentication_note:'Corporate sign-in is required. Entra application assignment is not checked by this directory connection.'};
  }
  router.get('/preview',wrap(async(req,res)=>res.json(await preview(String(req.query.email||'').trim().toLowerCase()))));
  router.post('/refresh',wrap(async(req,res)=>{
    const email=String(req.body.email||'').trim().toLowerCase();
    await D.withDirectory(c=>D.user(c,email));
    const [rows]=await pool.query('SELECT is_active FROM rbac_users WHERE email=?',[email]);
    if(rows.length&&!rows[0].is_active)D.fail('Account is disabled in CorpIT',403);
    const result=await resolveRoles(pool,email);if(!result.ok)D.fail(result.message||'Directory refresh failed',502);
    await audit(req,'portal.access_refreshed',email,{roles:result.roles});
    res.json(await preview(email));
  }));
  return router;
};
// Service-to-service validation; never mounted under the browser API prefix.
module.exports.principal=function(pool){
  const router=express.Router();router.use(express.json({limit:'16kb'}));
  router.post('/',async(req,res)=>{
    const key=process.env.PORTAL_LOOKUP_KEY||'',sent=String(req.get('X-Portal-Lookup-Key')||'');
    if(!['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress)||!key||Buffer.byteLength(sent)!==Buffer.byteLength(key)||!crypto.timingSafeEqual(Buffer.from(sent),Buffer.from(key)))return res.sendStatus(403);
    try{
      const keys=req.body.keys;
      if(!Array.isArray(keys)||!keys.length||keys.length>20||keys.some(k=>typeof k!=='string'||!/^[a-z0-9][a-z0-9-]{0,63}$/.test(k)))return res.status(400).json({error:'Choose a mapped AD group'});
      const [rows]=await pool.query('SELECT role_key,ad_group_dn FROM rbac_roles WHERE role_key IN (?)',[keys]);
      if(keys.some(k=>!rows.some(r=>r.role_key===k&&r.ad_group_dn)))return res.status(400).json({error:'Map a directory security group before saving this policy'});
      await D.withDirectory(async c=>{for(const r of rows)await D.group(c,r.ad_group_dn);});
      res.json({ok:true});
    }catch(e){res.status(e.status||502).json({error:e.status?e.message:'Directory validation is unavailable. Retry before saving.'});}
  });return router;
};
