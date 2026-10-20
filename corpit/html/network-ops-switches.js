window.NetworkOpsModules=window.NetworkOpsModules||{};
window.NetworkOpsModules.switches=function(ctx){
'use strict';
var NOC=ctx.chrome,workspace=ctx;

NOC.act('<button class="nbtn" id="os-nRefresh">'+NOC.icon('refresh')+'Refresh</button>');
var esc=NOC.esc, ago=NOC.ago;
var S={devices:[],meta:{},site:'ALL',q:'',sel:null,ports:{},condition:'all',busy:false};

async function jget(u){return ctx.json(u);}
function isUplink(p){return /^(Te|Twe|Fo|Hu|Fi)/i.test(String(p.port||''))||(p.speed||0)>=10000;}

function visible(){
  var q=S.q;
  return S.devices.filter(function(d){
    if(S.site!=='ALL'&&d.site!==S.site)return false;
    if(S.condition==='offline'&&d.reachable)return false;
    if(S.condition==='offstd'&&(d.ios_current==null||d.ios_current))return false;
    if(S.condition==='core'&&!d.core)return false;
    if(!q)return true;
    return [d.name,d.ip,d.model,d.serial,d.site,d.ios].join(' ').toLowerCase().indexOf(q)>-1;
  }).sort(function(a,b){
    return String(a.site||'').localeCompare(String(b.site||''))||
           String(a.name||'').localeCompare(String(b.name||''));});
}

function renderKpis(){
  var d=ctx.scopeDevices(S.devices);
  var up=d.filter(function(x){return x.reachable;}).length;
  var pu=d.reduce(function(n,x){return n+(x.if_up||0);},0);
  var pt=d.reduce(function(n,x){return n+(x.if_total||0);},0);
  var sites=Object.keys(d.reduce(function(a,x){a[x.site]=1;return a;},{})).length;
  // ios_current arrives as a SQLite integer (0/1), never a boolean, so the
  // old `=== false` test matched nothing. null = the collector never read a
  // version off that switch: unknown, which is neither current nor behind.
  var offStd=d.filter(function(x){return x.ios_current!=null && !x.ios_current;}).length;
  var stdUnk=d.filter(function(x){return x.ios_current==null;}).length;
  var stdBuild=(d.filter(function(x){return x.ios_current==1;})[0]||{}).ios||'';
  var core=d.filter(function(x){return x.core;}).length;
  var K=function(o){return '<div class="c2"><div class="nkpi'+(o.tone?' '+o.tone:'')+'">'+
    '<span class="k">'+esc(o.k)+'</span><span class="v">'+o.v+'</span>'+
    (o.s?'<span class="s">'+esc(o.s)+'</span>':'')+
    (o.meter!=null?'<span class="nmeter"><i class="'+(o.mt||'')+'" style="width:'+o.meter+'%"></i></span>':'')+
    '</div></div>';};
  document.getElementById('os-kpis').innerHTML=
    K({k:'Switches',v:up+'<small>/'+d.length+'</small>',tone:up<d.length?'bad':'good',
       s:up<d.length?(d.length-up)+' not responding':'all responding',
       meter:d.length?Math.round(up/d.length*100):0,mt:up<d.length?'bad':'good'})+
    K({k:'Ports active',v:pu.toLocaleString()+'<small>/'+pt.toLocaleString()+'</small>',
       s:pt?Math.round(pu/pt*100)+'% in use':'',meter:pt?Math.round(pu/pt*100):0})+
    K({k:'Sites',v:sites,tone:'info',s:'with switching'})+
    K({k:'Core',v:core,s:'core / distribution'})+
    K({k:'Access',v:d.length-core,s:'access switches'})+
    K({k:'Off standard build',v:offStd,
       tone:offStd?'warn':(stdUnk?'info':'good'),
       s:offStd?((stdBuild?'not on '+stdBuild:'off the standard build')+
                 (stdUnk?' · '+stdUnk+' unknown':''))
              :(stdUnk?stdUnk+' version not read'
                     :(stdBuild?'all on '+stdBuild:'all on the standard build'))});
}

function renderRows(){
  var rows=visible();document.getElementById('os-switchExport').disabled=!rows.length;
  if(!rows.filter(function(d){return d.ip===S.sel;}).length) S.sel=rows.length?rows[0].ip:null;

  var sites=Object.keys(S.devices.reduce(function(a,x){a[x.site]=1;return a;},{})).sort();
  document.getElementById('os-siteSeg').innerHTML=
    ['ALL'].concat(sites).map(function(s){
      var n=s==='ALL'?S.devices.length:S.devices.filter(function(x){return x.site===s;}).length;
      return '<button data-s="'+esc(s)+'" aria-pressed="'+(S.site===s)+'">'+
        (s==='ALL'?'All':esc(s))+' '+n+'</button>';}).join('');
  document.querySelectorAll('#os-siteSeg [data-s]').forEach(function(b){
    b.addEventListener('click',function(){ctx.navigate({site:b.dataset.s,switch:'',port:''});});});

  var el=document.getElementById('os-rows');
  if(!rows.length){
    el.innerHTML='<div class="nempty">'+NOC.icon('switchd')+'<b>No switches match</b>'+
      'Try a different site or clear the filter.</div>';
  }else{
    el.innerHTML='<table class="nt">'+
      '<colgroup><col class="wide"><col style="width:92px"><col style="width:112px">'+
      '<col style="width:92px"><col style="width:104px"><col style="width:84px"></colgroup>'+
      '<thead><tr>'+
      '<th data-key="n">Switch</th><th data-key="site">Site</th><th data-key="m">Model</th>'+
      '<th data-key="ios">IOS-XE</th><th data-key="p" data-type="num" class="num">Ports</th>'+
      '<th data-key="st">State</th></tr></thead><tbody>'+
      rows.map(function(d){
        var pct=d.if_total?Math.round(d.if_up/d.if_total*100):0;
        return '<tr class="click" data-ip="'+esc(d.ip)+'" aria-selected="'+(S.sel===d.ip)+'">'+
          '<td class="grow"><button class="fbtn" type="button" aria-label="Show '+esc(d.name)+'">'+
            '<span class="t">'+esc(d.name)+(d.core?' <span class="sev info">core</span>':'')+'</span>'+
            '<span class="s">'+esc(d.ip)+'</span></button></td>'+
          '<td class="mono">'+esc(d.site||'')+'</td>'+
          '<td class="mono">'+esc(d.model||'')+'</td>'+
          '<td class="mono">'+esc(d.ios||'—')+
            (d.ios_current!=null&&!d.ios_current?' <span class="sev warn">off std</span>':'')+'</td>'+
          '<td class="num" data-sort="'+(d.if_up||0)+'">'+(d.if_up||0)+'/'+(d.if_total||0)+'</td>'+
          '<td>'+(d.reachable?'<span class="sev ok">up</span>':'<span class="sev crit">no reply</span>')+'</td>'+
          '</tr>';}).join('')+'</tbody></table>';
    NOC.sortable(el.querySelector('table'));
    el.querySelectorAll('tr.click').forEach(function(tr){
      var go=function(){select(tr.dataset.ip);};
      tr.addEventListener('click',go);
      var fb=tr.querySelector('.fbtn');
      if(fb)fb.addEventListener('click',function(e){e.stopPropagation();go();});
    });
  }
  ctx.filters({site:S.site,switch:S.sel||'',condition:S.condition,switchSearch:S.q});
  var up=ctx.scopeDevices(S.devices).filter(function(d){return d.reachable;}).length;
  var pu=ctx.scopeDevices(S.devices).reduce(function(n,d){return n+(d.if_up||0);},0);
  document.getElementById('os-foot').innerHTML=
    '<span><b>'+rows.length+'</b> shown</span><span><b>'+up+'/'+ctx.scopeDevices(S.devices).length+'</b> responding</span>'+
    '<span><b>'+pu.toLocaleString()+'</b> ports up</span>'+
    '<span style="margin-left:auto;color:var(--o-faint)">Pick a switch to load its front panel</span>';
}

function select(ip){ S.sel=ip;ctx.filters({switch:ip});renderRows();renderDetail();renderPanel();ctx.selectSwitch(ip); }

function renderDetail(){
  var el=document.getElementById('os-detail');
  var d=S.devices.filter(function(x){return x.ip===S.sel;})[0];
  if(!d){el.innerHTML='<div class="nempty">'+NOC.icon('switchd')+
    '<b>No switch selected</b>Pick one from the inventory.</div>';return;}
  var pct=d.if_total?Math.round(d.if_up/d.if_total*100):0;
  var c=S.ports[d.ip];
  el.innerHTML='<div class="swid" style="margin-bottom:12px">'+
      '<span><span class="nm">'+esc(d.name)+'</span><br>'+
      '<span class="ip">'+esc(d.ip)+'</span></span></div>'+
    '<dl class="dl">'+
      '<dt>State</dt><dd>'+(d.reachable
        ?'<span class="sev ok">responding</span>':'<span class="sev crit">no reply</span>')+
        ' <span style="color:var(--o-faint);font-size:11.5px">'+esc(ago(S.meta.age_seconds))+'</span></dd>'+
      '<dt>Role</dt><dd>'+(d.core?'Core / distribution':'Access')+'</dd>'+
      '<dt>Model</dt><dd class="mono">'+esc(d.model||'—')+'</dd>'+
      (d.serial?'<dt>Serial</dt><dd class="mono">'+esc(d.serial)+'</dd>':'')+
      '<dt>Software</dt><dd>IOS-XE <b>'+esc(d.ios||'—')+'</b>'+
        (d.ios_current!=null&&!d.ios_current?' <span class="sev warn">off standard build</span>':
         (d.ios_current==null?' <span class="sev info">build not read</span>':''))+'</dd>'+
      '<dt>Ports</dt><dd>'+(d.if_up||0)+' of '+(d.if_total||0)+' active'+
        '<span class="nmeter"><i style="width:'+pct+'%"></i></span></dd>'+
      (c&&!c.err?'<dt>Devices</dt><dd><b>'+c.clients+'</b> learned on this switch</dd>':'')+
    '</dl>';
}

/* ── the faceplate, kept exactly as it was and given the whole width ────── */
function renderPanel(){
  var d=S.devices.filter(function(x){return x.ip===S.sel;})[0];
  var host=document.getElementById('os-panel');
  var title=document.getElementById('os-panelTitle');
  if(!d){host.innerHTML='<div class="nempty">'+NOC.icon('switchd')+
    '<b>No switch selected</b></div>';return;}
  title.textContent=d.name+' · front panel';
  document.getElementById('os-panelTools').innerHTML=
    '<span class="sev '+(d.reachable?'ok':'crit')+'">'+(d.reachable?'responding':'no reply')+'</span>'+
    '<span style="font-family:var(--n-mono);font-size:11px;color:var(--o-faint)">'+esc(d.model||'')+'</span>';

  var draw=function(){
    if(S.sel!==d.ip)return;
    var c=S.ports[d.ip];
    if(!c)return;
    if(c.err){host.innerHTML='<div class="nempty">'+NOC.icon('switchd')+
      '<b>Port detail unavailable</b>'+esc(c.err)+' <button class="nbtn" data-port-retry>Retry port detail</button></div>';host.querySelector('[data-port-retry]').onclick=function(){delete S.ports[d.ip];renderPanel();};return;}
    host.innerHTML='';
    ITPanel.render(host,{kind:'switch',title:d.model||d.name,sub:d.ip,sysOk:!!d.reachable,
      ports:c.ports,onSelect:function(p){ITDrill.portDetail(d.ip,d.name,p.id,p.label);}});
    var withDev=c.ports.filter(function(p){return (p.mac_count||0)>0;}).length;
    var errP=c.ports.filter(function(p){return (p.crc||0)+(p.in_err||0)+(p.out_err||0)>0;}).length;
    var upl=c.ports.filter(isUplink).length;
    host.insertAdjacentHTML('beforeend','<div class="panelmeta">'+
      '<span><b>'+c.clients+'</b> devices learned</span>'+
      '<span><b>'+withDev+'</b> ports with a device</span>'+
      '<span><b>'+upl+'</b> uplinks</span>'+
      (errP?'<span style="color:var(--o-slow)"><b>'+errP+'</b> ports counting errors</span>'
           :'<span>no ports counting errors</span>')+
      '<span style="margin-left:auto;color:var(--o-faint)">Click any port for history and what is plugged in</span>'+
      '</div>'+
      (c.ports.some(function(p){return p.duplex;})?'':
        '<div class="pnote">Duplex and live throughput arrive with the next collector pass; '+
        'until a port reports them, those two indicators are left off rather than guessed.</div>'));
    renderPortFinder(d,c,host);renderDetail();
  };
  if(S.ports[d.ip]){draw();return;}
  host.innerHTML='<div class="nskel" style="height:120px;border-radius:12px"></div>';
  jget('/api/netswitch/switch/'+encodeURIComponent(d.ip))
    .then(function(j){S.ports[d.ip]={ports:j.ports||[],clients:j.clients||0};})
    .catch(function(e){S.ports[d.ip]={ports:[],clients:0,err:e.message};})
    .then(draw);
}

/* Locate a port without changing the existing switch faceplate. */
var portFind={q:'',condition:'all'};
function matchingPorts(ports,q,condition){
 q=String(q||'').toLowerCase().trim();
 return ports.filter(function(p){
  if(q&&![p.port,p.alias,p.description,p.descr,p.ifindex].join(' ').toLowerCase().includes(q))return false;
  if(condition==='errors'&&!((p.crc||0)+(p.in_err||0)+(p.out_err||0)>0))return false;
  if(condition==='devices'&&!(p.mac_count>0))return false;
  if(condition==='up'&&p.oper!=='up')return false;
  if(condition==='down'&&p.oper==='up')return false;
  if(condition==='uplinks'&&!isUplink(p))return false;
  return true;
 });
}
function renderPortFinder(d,c,host){
 portFind.q=ctx.state().portSearch||'';portFind.condition=ctx.state().portCondition||'all';
 var box=document.createElement('section');box.className='ops-port-finder';
 box.innerHTML='<div class="op-tools"><label>Find a port <input class="op-input" id="os-portFind" type="search" placeholder="Port or description" aria-controls="portFindResults"></label><label>Show <select class="op-input" id="os-portFindCondition"><option value="all">All ports</option><option value="errors">Counting errors</option><option value="devices">Learned devices</option><option value="up">Link up</option><option value="down">Link down</option><option value="uplinks">Uplinks</option></select></label><button class="nbtn" id="os-portFindReset">Reset port filters</button><button class="nbtn" id="os-portExport">Export ports CSV</button></div><div id="os-portFindResults" aria-live="polite"></div>';
 host.appendChild(box);var q=box.querySelector('#os-portFind'),condition=box.querySelector('#os-portFindCondition'),results=box.querySelector('#os-portFindResults');q.value=portFind.q;condition.value=portFind.condition;
 function draw(){
  ctx.filters({portSearch:portFind.q,portCondition:portFind.condition});
  var rows=matchingPorts(c.ports,portFind.q,portFind.condition),active=portFind.q||portFind.condition!=='all';
  box.querySelector('#os-portExport').disabled=!rows.length;
  results.innerHTML='<p>'+rows.length+' of '+c.ports.length+' ports'+(active?' match':' · choose a filter or use the faceplate above')+'</p>'+(active?(rows.length?'<div class="ops-port-matches">'+rows.map(function(p){return '<button class="nbtn" data-find-ifx="'+esc(p.ifindex)+'" data-find-port="'+esc(p.port)+'">'+esc(p.port)+' · '+esc(p.alias||p.description||p.descr||'No description')+' · '+esc(p.oper||'unknown')+(p.mac_count?' · '+p.mac_count+' learned':'')+'</button>';}).join('')+'</div>':'<p>No matching ports. Clear the filters to see all ports.</p>'):'');
  results.querySelectorAll('[data-find-ifx]').forEach(function(b){b.onclick=function(){window.NetworkOps.openPort(d.ip,d.name,b.dataset.findIfx,b.dataset.findPort);};});
 }
 q.oninput=function(){portFind.q=q.value;draw();};condition.onchange=function(){portFind.condition=condition.value;draw();};
 box.querySelector('#os-portFindReset').onclick=function(){portFind.q='';portFind.condition='all';q.value='';condition.value='all';draw();q.focus();};
 box.querySelector('#os-portExport').onclick=function(){OpsPolish.csv(d.name+'-ports.csv',['Switch','Switch IP','Port','Description','Link','Speed Mbps','Learned devices','CRC','Input errors','Output errors'],matchingPorts(c.ports,portFind.q,portFind.condition).map(function(p){return[d.name,d.ip,p.port,p.alias||p.description||p.descr||'',p.oper,p.speed,p.mac_count,p.crc,p.in_err,p.out_err];}));};
 draw();
}

document.getElementById('os-q').addEventListener('input',function(e){
  S.q=e.target.value.trim().toLowerCase();renderRows();renderDetail();renderPanel();});

function renderScopeVitals(){var s=ctx.summarize(S.devices),issues=ctx.scopeIssues(S.overview?.issues||[],S.devices),counts=S.overview?.counts,all=ctx.state().site==='ALL',critical=all&&counts?.critical!=null?counts.critical:issues.filter(function(i){return i.severity==='critical';}).length,total=all&&counts?.total!=null?counts.total:issues.length;NOC.vitals([{k:'Scan',v:ago(S.meta.age_seconds)},{k:'Switches',v:s.switches_up+'/'+s.switches,cls:s.switches_down?'bad':'good'},{k:'Ports up',v:s.ports_up},{k:'Sites',v:new Set(ctx.scopeDevices(S.devices).map(function(d){return d.site;})).size},{k:'Faults · loaded scope',v:total,cls:critical?'bad':total?'warn':'good'}]);NOC.badge('health',critical||total,critical?'bad':'warn');}
async function load(){
  if(S.busy)return;S.busy=true;document.getElementById('os-nRefresh').disabled=true;
  S.ports={};
  try{
    var ov=await jget('/api/netswitch/overview');
    if(!ov||ov.ok===false)throw new Error((ov&&ov.detail)||'unavailable');
    S.devices=ov.devices||[]; S.meta=ov.meta||{};S.overview=ov;ctx.inventory(ov);
    var s=ov.summary||{};
    var crit=(ov.issues||[]).filter(function(i){return i.severity==='critical';}).length;
    NOC.badge('health',crit||(ov.issues||[]).length,crit?'bad':'warn');
    renderScopeVitals();
    NOC.stamp('scanned '+ago(S.meta.age_seconds),(S.meta.age_seconds||0)>7200);
    S.site=ctx.state().site;S.sel=ctx.state().switch||S.sel;
    renderKpis(); renderRows(); renderDetail(); renderPanel();return true;
  }catch(e){
    var m=(e.code===401)?'Your session expired. <a href="/login.html">Sign in</a>.':esc(e.message);
    document.getElementById('os-kpis').innerHTML='<div class="c12"><div class="ncard"><div class="ncb">'+
      '<div class="nempty">'+NOC.icon('switchd')+'<b>Couldn’t load the fabric</b>'+m+'</div></div></div></div>';
    return false;
  }finally{S.busy=false;document.getElementById('os-nRefresh').disabled=false;}
}
document.getElementById('os-switchCondition').onchange=function(e){S.condition=e.target.value;renderRows();renderDetail();renderPanel();};
document.getElementById('os-switchReset').onclick=function(){S.site=ctx.state().site;S.q='';S.condition='all';document.getElementById('os-q').value='';document.getElementById('os-switchCondition').value='all';renderRows();renderDetail();renderPanel();};
document.getElementById('os-switchExport').onclick=function(){OpsPolish.csv('switch-inventory.csv',['Switch','Site','IP','Model','Serial','IOS-XE','Ports up','Ports total','Responding','Standard build'],visible().map(d=>[d.name,d.site,d.ip,d.model,d.serial,d.ios,d.if_up,d.if_total,d.reachable?'Yes':'No',d.ios_current==null?'Unknown':d.ios_current?'Yes':'No']));};
document.getElementById('os-nRefresh').addEventListener('click',load);
S.site=ctx.state().site;S.sel=ctx.state().switch||null;S.q=ctx.state().switchSearch;S.condition=ctx.state().condition;var ready=load();
return {ready:ready,refresh:load,activate:function(st){S.site=st.site;S.condition=st.condition;S.q=st.switchSearch;S.sel=st.switch||S.sel;document.getElementById('os-q').value=S.q;document.getElementById('os-switchCondition').value=S.condition;renderScopeVitals();renderKpis();renderRows();renderDetail();renderPanel();},deactivate:function(){},capture:function(){return{switch:S.sel||'',condition:S.condition,switchSearch:S.q};}};

};
