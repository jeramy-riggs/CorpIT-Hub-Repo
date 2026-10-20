'use strict';
const https=require('node:https'),fs=require('node:fs');
const allowed=new Set(['https://dev-accessportal.nrpi.local','https://accessportal.nrpi.local']);
module.exports=function create({origin=process.env.AI_GOVERNANCE_INTAKE_ORIGIN||(process.env.DEV_SERVER==='1'?'https://dev-accessportal.nrpi.local':'https://accessportal.nrpi.local'),caPath=process.env.AI_GOVERNANCE_INTAKE_CA,request=https.request,readFile=fs.readFileSync}={}){
 if(!allowed.has(origin))throw new Error('Intake origin must be the existing Access Portal');
 if(process.env.DEV_SERVER==='1'&&origin!=='https://dev-accessportal.nrpi.local')throw new Error('DEV governance may read only DEV Access Portal');
 if(process.env.DEV_SERVER!=='1'&&origin==='https://dev-accessportal.nrpi.local')throw new Error('Production governance may not read DEV Access Portal');
 const error=(message,status=502)=>Object.assign(new Error(message),{status});
 // CA FALLBACK 2026-10-20: prod A/B have no /etc/ssl/certs copy, so the hub carries the same public NRPI chain in
 // certs/; it then follows every release and failover. An explicit AI_GOVERNANCE_INTAKE_CA is still the only path tried.
 const caPaths=caPath?[caPath]:['/etc/ssl/certs/nrpi-ca-chain.pem',require('node:path').join(__dirname,'certs','nrpi-ca-chain.pem')];
 return {origin,read(cookie){
  const session=String(cookie||'').split(';').map(x=>x.trim()).filter(x=>/^it_session=/.test(x)).join('; ');
  if(!session)return Promise.reject(error('Access Portal source access is required. Open Access Portal to check your access.',424));
  let ca;for(const p of caPaths){try{ca=readFile(p);break;}catch{}}if(!ca)return Promise.reject(error('The configured corporate CA bundle is unavailable'));
  return new Promise((resolve,reject)=>{
   const req=request(new URL('/api/portal/requests?type=aia&archived=all',origin),{method:'GET',ca,rejectUnauthorized:true,timeout:12000,headers:{Accept:'application/json',Cookie:session}},res=>{
    if(res.statusCode!==200){res.resume();return reject(error([401,403].includes(res.statusCode)?'Access Portal did not authorize this source read. Open Access Portal to check source access. Your AI Governance session remains valid.':res.statusCode>=300&&res.statusCode<400?'Access Portal requires its own source sign-in. Open Access Portal to check source access; no redirect or credentials were forwarded.':'Access Portal intake read failed',[401,403].includes(res.statusCode)||res.statusCode>=300&&res.statusCode<400?424:502));}
    let size=0;const chunks=[];res.on('data',chunk=>{size+=chunk.length;if(size>8*1024*1024){req.destroy();reject(error('Intake response exceeded its bounded read limit'));}else chunks.push(chunk);});
    res.on('error',()=>reject(error('Intake response was interrupted')));res.on('end',()=>{try{const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(body.ok!==true||!Array.isArray(body.data)||body.data.length>2000)throw new Error();resolve({rows:body.data,checked_at:new Date().toISOString()});}catch{reject(error('Intake response is incomplete or exceeds 2,000 records; no enrichment was applied'));}});
   });
   req.on('timeout',()=>{req.destroy();reject(error('Access Portal intake read timed out'));});req.on('error',()=>reject(error('Access Portal could not be read with verified TLS')));req.end();
  });
 }};
};
