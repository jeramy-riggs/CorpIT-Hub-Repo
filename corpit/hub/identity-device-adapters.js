'use strict';
// Explicit read of the selected Intune enrollment; never a hostname search or device action.
const model=require('./identity-device-model'),detail=require('./identity-device-detail');
const text=v=>v==null?'':String(v).trim();
const cache=new Map(),inflight=new Set(),TTL=15*60*1000;
const uuid=v=>/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text(v));
function reference(group){
  const refs=group.records.filter(r=>r.sourceRef.sourceKey==='intune' && model.family(r)==='windows').map(r=>r.sourceRef);
  return refs.length===1 && uuid(refs[0].nativeId) && detail.serialAssociationAllowed(group)?refs[0]:null;
}
function matches(group,person,d){
  const ref=reference(group),aliases=new Set(group.records.map(r=>text(r.user).toLowerCase()).filter(v=>v.includes('@')));
  if(person?.username)aliases.add(text(person.username).toLowerCase()+'@auction.com');
  return !!ref && text(d.id).toLowerCase()===text(ref.nativeId).toLowerCase() && model.serialKey(d.serialNumber)===model.serialKey(group.serial) && model.family({os:d.operatingSystem})==='windows' && aliases.has(text(d.userPrincipalName).toLowerCase());
}
function cached(group,person,now=Date.now()){
  const ref=reference(group),v=ref&&cache.get(ref.nativeId.toLowerCase());
  if(!v)return null;
  if(v.expires<=now){cache.delete(ref.nativeId.toLowerCase());return null;}
  return matches(group,person,v.device)?{...v,device:{...v.device}}:null;
}
// Failures carry a code so discover() can say whether a retry can help (B1 2026-10-17: a 404 read as "retry when ready").
const fail=(code,message,http)=>Object.assign(Error(message),{code,http});
async function graphDevice(id,{fetchImpl=fetch,env=process.env}={}){
  if(!uuid(id))throw fail('INVALID_ENROLLMENT','Invalid enrollment');
  if(!env.AZURE_TENANT_ID||!env.AZURE_CLIENT_ID||!env.AZURE_CLIENT_SECRET)throw fail('NOT_CONFIGURED','Not configured');
  const signal=AbortSignal.timeout(15000);
  const tokenResponse=await fetchImpl('https://login.microsoftonline.com/'+encodeURIComponent(env.AZURE_TENANT_ID)+'/oauth2/v2.0/token',{method:'POST',body:new URLSearchParams({client_id:env.AZURE_CLIENT_ID,client_secret:env.AZURE_CLIENT_SECRET,scope:'https://graph.microsoft.com/.default',grant_type:'client_credentials'}),signal});
  if(!tokenResponse.ok)throw fail('TOKEN_UNAVAILABLE','Token unavailable',tokenResponse.status);
  const token=await tokenResponse.json();if(!token.access_token)throw fail('TOKEN_UNAVAILABLE','Token unavailable');
  const response=await fetchImpl('https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/'+encodeURIComponent(id)+'?$select=id,serialNumber,userPrincipalName,operatingSystem,wiFiMacAddress,ethernetMacAddress,lastSyncDateTime',{headers:{Authorization:'Bearer '+token.access_token,Accept:'application/json'},signal});
  if(!response.ok)throw fail(response.status===404?'ENROLLMENT_NOT_FOUND':response.status===401||response.status===403?'READ_FORBIDDEN':'READ_UNAVAILABLE','Managed adapter read unavailable',response.status);
  const d=await response.json();
  return Object.fromEntries(['id','serialNumber','userPrincipalName','operatingSystem','wiFiMacAddress','ethernetMacAddress','lastSyncDateTime'].map(k=>[k,d[k]??null]));
}
const FAILURES={
  ENROLLMENT_NOT_FOUND:'Intune no longer has this enrollment; it was removed or the device was re-enrolled. The inventory record is out of date, so retrying will not help. Refresh inventory, then select the device again.',
  READ_FORBIDDEN:'Intune refused the managed device read for this server\'s Graph app. Retrying will not help until its permissions are fixed.',
  NOT_CONFIGURED:'Intune reads are not configured on this server. Retrying will not help until the Graph app settings are added.',
  TOKEN_UNAVAILABLE:'Microsoft sign-in for the Intune read failed. Retry later; if it keeps failing, check the Graph app credentials.',
  EDEVGUARD:'The DEV egress guard blocked the Intune read. This is a DEV server limit, not a device problem.',
  TIMEOUT:'Intune did not answer within 15 seconds. Existing inventory sources remain available; retry discovery when ready.'
};
function failure(e){
  const code=e?.code==='EDEVGUARD'||e?.cause?.code==='EDEVGUARD'?'EDEVGUARD':e?.name==='TimeoutError'||e?.name==='AbortError'?'TIMEOUT':FAILURES[e?.code]?e.code:'READ_UNAVAILABLE';
  return {status:'unavailable',code,reason:FAILURES[code]||'Managed adapters could not be read. Existing inventory sources remain available; retry discovery when ready.'};
}
async function discover(group,person,{read=graphDevice,now=Date.now()}={}){
  const ref=reference(group);if(!ref)return {status:'not_associated',reason:'A unique current Windows Intune enrollment and unambiguous inventory serial are required.'};
  const key=ref.nativeId.toLowerCase();
  if(inflight.has(key))return {status:'busy',reason:'Adapter discovery is already running for this enrollment.'};
  inflight.add(key);cache.delete(key);
  try{
    const device=await read(ref.nativeId);
    if(!matches(group,person,device))return {status:'not_associated',reason:'Intune device ID, serial, Windows platform and owner did not all match the selected inventory. No adapters were added.'};
    const value={device,readAt:new Date(now).toISOString(),expires:now+TTL};
    for(const [k,v] of cache)if(v.expires<=now)cache.delete(k);
    while(cache.size>=300)cache.delete(cache.keys().next().value);
    cache.set(key,value);
    return {status:device.wiFiMacAddress||device.ethernetMacAddress?'ok':'empty',readAt:value.readAt,expiresAt:new Date(value.expires).toISOString(),reason:'Selected Intune enrollment verified by device ID, serial, platform and owner. Choose an adapter; current connection is verified separately by Meraki or exact DHCP.'};
  }catch(e){return failure(e);}
  finally{inflight.delete(key);}
}
module.exports={reference,matches,cached,discover,graphDevice};
