'use strict';
// Shared by the protected portal gate and the in-app effective-access preview.
const http = require('http');
const siteAccess = require('./site-access');
function portalScope(email, roles) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ email, roles });
    const req = http.request({host:'127.0.0.1', port:8001, path:'/internal/approval-access', method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),
        'X-Portal-Lookup-Key':process.env.PORTAL_LOOKUP_KEY || ''}}, res => {
      let data=''; res.on('data', c => {data+=c; if(data.length>1024*1024)req.destroy(new Error('Portal response too large'));});
      res.on('end', () => {try {const j=JSON.parse(data); if(res.statusCode!==200 || !j.ok)throw new Error('Portal policy unavailable'); resolve(j.data);} catch(e){reject(e);}});
    });
    req.setTimeout(4000, () => req.destroy(new Error('Portal policy timed out')));
    req.on('error',reject); req.end(body);
  });
}
async function evaluate(pool, rbac, user, groups) {
  const scope=await portalScope(user.email, user.roles);
  const site=siteAccess.decide('accessportal.nrpi.local', user.email, groups);
  // Environment recovery / AD super-admins have explicitly reported oversight.
  if(user.isSuperAdmin) return {allowed:true,level:'admin',tier:'superadmin',site,scope,recovery:true};
  if(!user.isActive) return {allowed:false,reason:'account-disabled',site,scope};
  if(!site.allow) return {allowed:false,reason:'site-'+site.reason,site,scope};
  const [overrides]=await pool.query('SELECT access_level FROM rbac_user_page_access WHERE email=? AND page_key=? LIMIT 1',[user.email,'approver-portal']);
  if(overrides.length && overrides[0].access_level==='none')return {allowed:false,reason:'explicit-page-block',site,scope};
  if(scope.blocked)return {allowed:false,reason:'portal-block',site,scope};
  const level=await rbac.effectiveLevelForPage(user.email,user.roles,'approver-portal','matrix',false);
  const allowed=level!=='none' || scope.admitted;
  return {allowed,level:level==='admin'?'admin':'read',tier:user.roles.includes('tier2')?'tier2':'granted',
    reason:allowed?(scope.admitted?'approval-grant':'page-grant'):'no-grant',site,scope};
}
module.exports={portalScope,evaluate};
