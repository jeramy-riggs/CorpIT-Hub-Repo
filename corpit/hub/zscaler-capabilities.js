'use strict';
// Confirmed tenant subscription. This is a product capability, not an outage
// or a request to buy an upgrade. ZCC inventory remains independently available.
const zdx = Object.freeze({plan:'Standard',api:false,state:'not_included',
  reason:'ZDX API access is not included in the current Standard subscription. This workspace uses ZCC enrollment and check-in data; experience scores, live presence and ISP/location telemetry are not collected.'});
function unavailable(){return {code:'ZDX_API_NOT_INCLUDED',state:'not_included',error:zdx.reason,plan:zdx.plan,available:false};}
function blocked(url){return url.hostname==='api.zsapi.net'&&/^\/zdx\//.test(url.pathname)&&!zdx.api;}
module.exports={zdx,unavailable,blocked};
