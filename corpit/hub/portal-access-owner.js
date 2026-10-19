'use strict';
// Global matrix editors may edit other apps without replacing portal-owned rows.
const keys=['accessportal','approver-portal'];
const url='https://accessportal.nrpi.local/approver.html';
const owns=key=>keys.includes(key);
function reject(res) {return res.status(409).json({code:'PORTAL_ACCESS_MANAGED_IN_APP',error:'Manage Approval Portal access in Administrator > Approval Access.',owner_url:url});}
function preserve(res, proposed, current) {
  for(const key of keys) {
    if(Object.hasOwn(proposed,key) && proposed[key]!==current[key]) {reject(res);return false;}
  }
  for(const key of keys) {
    if(Object.hasOwn(current,key))proposed[key]=current[key];else delete proposed[key];
  }
  return true;
}
function preserveRows(res, proposed, current) {
  const map=Object.fromEntries(proposed.map(r=>[r.page_key,r.access_level]));
  if(!preserve(res,map,Object.fromEntries(current.map(r=>[r.page_key,r.access_level]))))return false;
  proposed.splice(0,proposed.length,...Object.entries(map).map(([page_key,access_level])=>({page_key,access_level})));
  return true;
}
module.exports={keys,url,owns,reject,preserve,preserveRows};
