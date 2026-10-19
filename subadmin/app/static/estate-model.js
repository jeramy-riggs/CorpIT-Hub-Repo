(function(root){
  'use strict';
  function health(v){v=String(v||'unknown').toLowerCase();return ({ok:'healthy',normal:'healthy',warn:'warning',down:'critical',offline:'critical'})[v]||(['healthy','warning','critical','maintenance'].includes(v)?v:'unknown');}
  function normalise(kind,rows){return rows.map(function(r){
    var id=kind==='service'?(r.key||r.name):r.id;
    if(id==null) return null;
    return {id:String(id),kind:kind,name:r.friendlyName||r.name||r.hostname||r.fqdn||String(id),
      subtitle:r.hostname||r.fqdn||r.endpointCategory||r.domain||r.category||'',
      state:health(kind==='server'?r.health:r.state),checked:r.lastCheckIn||r.lastCheckedAt||r.lastCheckAt||null,
      raw:r};
  }).filter(Boolean);}
  function records(sources){
    return normalise('server',(sources.servers||{}).servers||[])
      .concat(normalise('webapp',(sources.vhosts||{}).vhosts||[]))
      .concat(normalise('service',(sources.apis||{}).external||[]))
      .concat(normalise('service',((sources.apis||{}).internal||[]).map(function(r){return Object.assign({},r,{key:'internal:'+r.name});})));
  }
  function matches(r,q,kind,filter){return (!kind||r.kind===kind)&&(!q||(r.name+' '+r.subtitle).toLowerCase().includes(q.toLowerCase()))&&(filter==='attention'?['warning','critical'].includes(r.state):filter==='all'||!filter?true:r.state===filter);}
  function summary(rows){return rows.reduce(function(n,r){n.total++;n[r.state]=(n[r.state]||0)+1;return n;},{total:0,healthy:0,warning:0,critical:0,unknown:0,maintenance:0});}
  function route(r,tab){return '#resource/'+r.kind+'/'+encodeURIComponent(r.id)+'/'+(tab||'health');}
  function sort(rows,key,direction){var rank={critical:0,warning:1,unknown:2,maintenance:3,healthy:4};return rows.slice().sort(function(a,b){var x=key==='state'?rank[a.state]:key==='checked'?(Date.parse(a.checked)||0):String(a[key]||'').toLowerCase(),y=key==='state'?rank[b.state]:key==='checked'?(Date.parse(b.checked)||0):String(b[key]||'').toLowerCase();return (x<y?-1:x>y?1:0)*(direction==='desc'?-1:1);});}
  var api={sort:sort,health:health,normalise:normalise,records:records,matches:matches,summary:summary,route:route};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.EstateModel=api;
})(typeof window!=='undefined'?window:globalThis);
