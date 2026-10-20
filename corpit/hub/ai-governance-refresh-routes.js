'use strict';
module.exports=function({router,refresh,admin,wrap,actor,rbac}){
 const identity=rbac.requirePage('identity-diag','read'),zscaler=rbac.requirePage('zscaler-diag','read');
 const sourceRead=(req,res,next)=>{const key=req.params.source;if(key==='entra')return identity(req,res,next);if(key==='zscaler')return zscaler(req,res,next);if(key==='rapid7')return identity(req,res,()=>zscaler(req,res,next));next();};
 router.get('/refresh-status',wrap(async(req,res)=>res.json(await refresh.status())));
 router.put('/refresh-schedule/:source',admin,sourceRead,wrap(async(req,res)=>{await refresh.configure(req.params.source,req.body.enabled,Number(req.body.interval_minutes),actor(req));res.json({ok:true,...await refresh.status()});}));
};
