window.NetworkOpsModules=window.NetworkOpsModules||{};
window.NetworkOpsModules.overview=function(ctx){
'use strict';
var NOC=ctx.chrome,workspace=ctx;

NOC.act('<button class="nbtn rel icon" id="oh-nAlerts" aria-label="Faults needing action">'+
  NOC.icon('bell')+'<span class="badge" id="oh-alertN" hidden>0</span></button>'+
  '<button class="nbtn" id="oh-nRefresh">'+NOC.icon('refresh')+'Refresh</button>');

var esc=NOC.esc, ago=NOC.ago;
var S={issues:[],devices:[],counts:null,sum:{},meta:{},noc:null,claims:{},cleared:0,
       filter:'all',range:7,fw:null,watch:[],q:'',busy:false};

async function jget(u){return ctx.json(u);}
/* ── issue helpers: the diagnosis is authored by the collector, not here ── */
var KIND={crc:'Physical layer',errors:'Port errors',inerr:'Port errors',outerr:'Port errors',
          discards:'Congestion',halfduplex:'Duplex',duplex:'Duplex',flapping:'Flapping',
          unplugged:'Unplugged',down:'Link down'};
function diagOf(i){try{return typeof i.diag==='string'?JSON.parse(i.diag):(i.diag||{});}catch(e){return {};}}
function titleOf(i){return diagOf(i).title||KIND[i.kind]||'Port issue';}
function causeOf(i){
  var d=diagOf(i),c=d.cause||i.detail||'',t=d.title||'';
  if(t&&c.indexOf(t)===0)c=c.slice(t.length).replace(/^[\s—–:-]+/,'');
  return c;}
function refOf(i){return i.switch_ip+':'+i.port;}
function ini(n){n=String(n||'').split('@')[0];var w=n.split(/[._\- ]+/).filter(Boolean);
  return ((w[0]||'?')[0]+(w[1]?w[1][0]:'')).toUpperCase();}

/* ── KPI strip ──────────────────────────────────────────────────────────── */
function kpi(o){
  return '<div class="'+(o.span||'c2')+'">'+
    '<'+(o.href?'button':'div')+' class="nkpi'+(o.tone?' '+o.tone:'')+'"'+
      (o.href?' data-go="'+esc(o.href)+'"':'')+'>'+
    '<span class="k">'+(o.icon?NOC.icon(o.icon):'')+esc(o.k)+'</span>'+
    '<span class="v">'+o.v+'</span>'+
    (o.s?'<span class="s">'+o.s+'</span>':'')+
    (o.meter!=null?'<span class="nmeter"><i class="'+(o.mtone||'')+'" style="width:'+
      Math.max(0,Math.min(100,o.meter))+'%"></i></span>':'')+
    '</'+(o.href?'button':'div')+'></div>';
}
function renderKpis(){
  var s=scopeSummary(), n=(S.noc&&S.noc.summary)||{};
  var crit=sevTotal('critical');
  var warn=sevTotal('warn');
  var pPct=s.ports?Math.round(s.ports_up/s.ports*100):0;
  var swPct=s.switches?Math.round(s.switches_up/s.switches*100):0;
  var apTot=(n.totalOnline||0)+(n.totalOffline||0);
  document.getElementById('oh-kpis').innerHTML=
    kpi({k:'Critical',v:crit,tone:crit?'bad':'good',icon:'pulse',
         s:crit?'needs action now':'nothing critical',href:'critical'})+
    kpi({k:'Warnings',v:warn,tone:warn?'warn':'good',
         s:warn?'watch these':'all clear',href:'warn'})+
    kpi({k:'Switches',v:s.switches_up+'<small>/'+s.switches+'</small>',
         tone:s.switches_down?'bad':'good',s:s.switches_down?s.switches_down+' not responding':'all responding',
         meter:swPct,mtone:s.switches_down?'bad':'good'})+
    kpi({k:'Ports active',v:Number(s.ports_up||0).toLocaleString()+'<small>/'+
         Number(s.ports||0).toLocaleString()+'</small>',s:pPct+'% of the fabric in use',
         meter:pPct,mtone:''})+
    kpi({k:'APs · fleet',v:apTot?(n.totalOnline+'<small>/'+apTot+'</small>'):'—',
         tone:n.totalOffline?'warn':'good',
         s:apTot?(n.totalOffline?n.totalOffline+' offline':'all online'):'Meraki unavailable',
         meter:apTot?Math.round(n.totalOnline/apTot*100):null,mtone:n.totalOffline?'warn':'good'})+
    kpi({k:'Clients · fleet',v:n.totalClients!=null?Number(n.totalClients).toLocaleString():'—',
         tone:'info',s:'fleet · last reported'});
  document.querySelectorAll('#oh-kpis [data-go]').forEach(function(b){
    b.addEventListener('click',function(){S.q='';document.getElementById('oh-faultSearch').value='';S.filter=b.dataset.go;renderFaults();
      document.getElementById('oh-faults').scrollIntoView({block:'center',behavior:'smooth'});});});
}

/* ── vitals strip ───────────────────────────────────────────────────────── */
function renderVitals(){
  var s=scopeSummary(),n=(S.noc&&S.noc.summary)||{};
  var crit=sevTotal('critical'), open=queueTotal();
  NOC.vitals([
    {k:'Scan',v:ago(S.meta.age_seconds||s.scan_age)},
    {k:'Switches',v:s.switches_up+'/'+s.switches,cls:s.switches_down?'bad':'good'},
    {k:'Ports up',v:Number(s.ports_up||0).toLocaleString()},
    {k:'APs · fleet',v:(n.totalOnline!=null?n.totalOnline+'/'+((n.totalOnline||0)+(n.totalOffline||0)):'—'),
     cls:n.totalOffline?'warn':'good'},
    {k:'Clients · fleet',v:n.totalClients!=null?Number(n.totalClients).toLocaleString():'—'},
    {k:'Open faults',v:open.toLocaleString(),cls:crit?'bad':(open?'warn':'good')},
    {k:'Cleared 7d · fleet',v:S.cleared||0,cls:'good'}
  ]);
  NOC.badge('health',crit||open,crit?'bad':'warn');
  var a=document.getElementById('oh-alertN');
  if(a){ if(crit){a.hidden=false;a.textContent=crit;} else a.hidden=true; }
  NOC.stamp('scanned '+ago(S.meta.age_seconds||s.scan_age),(S.meta.age_seconds||0)>7200);
}

/* ── fault queue ────────────────────────────────────────────────────────── */
var SEV={critical:'crit',warn:'warn',info:'info'};
// How many faults of this severity EXIST -- not how many arrived in the page.
function sevTotal(k){
  if(ctx.state().site==='ALL'&&S.counts&&S.counts[k]!=null)return S.counts[k];
  return scopedIssues().filter(function(i){return i.severity===k;}).length;
}
function queueTotal(){
  return ctx.state().site==='ALL'&&S.counts&&S.counts.total!=null?S.counts.total:scopedIssues().length;
}
function faultRows(){var q=S.q.trim().toLowerCase();return scopedIssues().filter(function(i){return (S.filter==='all'||i.severity===S.filter)&&(!q||[i.switch,i.switch_ip,i.port,i.descr,titleOf(i),causeOf(i)].join(' ').toLowerCase().includes(q));});}
function renderFaults(){
  var all=scopedIssues(), f=S.filter;
  ctx.filters({severity:S.filter,faultSearch:S.q});
  var severityRows=(f==='all')?all:all.filter(function(i){return i.severity===f;});
  var list=faultRows();document.getElementById('oh-fExport').disabled=!list.length;
  var cnt=sevTotal;
  document.getElementById('oh-fFilter').innerHTML=
    [['all','All',queueTotal()],['critical','Critical',cnt('critical')],
     ['warn','Warnings',cnt('warn')],['info','Info',cnt('info')]]
    .filter(function(x){return x[0]==='all'||x[2];})
    .map(function(x){return '<button data-f="'+x[0]+'" aria-pressed="'+(f===x[0])+'">'+
      x[1]+' '+x[2]+'</button>';}).join('');
  document.querySelectorAll('#oh-fFilter [data-f]').forEach(function(b){
    b.addEventListener('click',function(){S.filter=b.dataset.f;renderFaults();});});

  var el=document.getElementById('oh-faults');
  // The tabs above count the queue; this list is what the server sent. When
  // those differ the reader is looking at a slice, and has to be told which.
  var shownFor=(f==='all')?queueTotal():cnt(f);
  var capNote=(shownFor>severityRows.length)
    ? '<div class="pnote">Loaded '+severityRows.length.toLocaleString()+' of '+
      shownFor.toLocaleString()+' — the server returns the most severe first. '+
      'Narrow by switch or severity to reach the rest.</div>'
    : '';
  if(!list.length&&S.q.trim()){
    el.innerHTML='<div class="nempty"><b>No faults match this search</b>Clear the search or use Reset filters.</div>';
  }else if(!list.length){
    el.innerHTML='<div class="nempty">'+NOC.icon('pulse')+
      '<b>'+(shownFor?'None of these arrived in this page':
             (f==='all'?'No open faults':'Nothing at this severity'))+'</b>'+
      (shownFor?shownFor.toLocaleString()+' fault'+(shownFor===1?'':'s')+
                ' of this severity are open, but none were in the slice the '+
                'server returned. Narrow by switch to reach them.'
              :(f==='all'?'Every port the last scan touched came back clean.'
                        :'Try another filter to see the rest of the queue.'))+'</div>';
  }else{
    var rows=list.slice().sort(function(a,b){
      var o={critical:0,warn:1,info:2};
      return (o[a.severity]-o[b.severity])||String(a.switch).localeCompare(String(b.switch));
    }).map(function(i){
      var ref=refOf(i), c=S.claims[ref];
      return '<tr class="click" data-ref="'+esc(ref)+'" data-ifx="'+esc(i.ifindex||'')+
        '" data-sw="'+esc(i.switch||'')+'" data-ip="'+esc(i.switch_ip||'')+
        '" data-pt="'+esc(i.port||'')+'">'+
        '<td data-sort="'+({critical:0,warn:1,info:2}[i.severity])+'">'+
          '<span class="sev '+(SEV[i.severity]||'')+'">'+esc(i.severity||'')+'</span></td>'+
        /* a real button inside the cell, not role="button" on the <tr>: the row
           stays a row for screen readers, and the fault is still tab-reachable */
        '<td class="grow"><button class="fbtn" type="button" '+
          'aria-label="Open '+esc(titleOf(i))+' on '+esc(i.switch||'')+' '+esc(i.port||'')+'">'+
          '<span class="t">'+esc(titleOf(i))+'</span>'+
          '<span class="s">'+esc(causeOf(i))+'</span></button></td>'+
        '<td class="mono">'+esc(i.switch||'')+'</td>'+
        '<td class="mono">'+esc(i.port||'')+'</td>'+
        '<td class="grow"><span class="s" title="'+esc(i.descr||'')+'">'+esc(i.descr||'—')+'</span></td>'+
        '<td>'+(c?'<button class="owner" data-cid="'+c.id+'" title="Claimed by '+esc(c.claimed_by)+
            ' — click to release">'+esc(ini(c.claimed_by))+'</button>'
          :'<button class="claim" data-cref="'+esc(ref)+'" data-ctitle="'+esc(titleOf(i))+
            '">Claim</button>')+'</td>'+
        '</tr>';
    }).join('');
    el.innerHTML='<table class="nt">'+
      '<colgroup><col style="width:88px"><col class="wide"><col style="width:150px">'+
      '<col style="width:88px"><col class="mid"><col style="width:74px"></colgroup>'+
      '<thead><tr>'+
      '<th data-key="sev" data-type="num">Sev</th><th data-key="t">Fault</th>'+
      '<th data-key="sw">Switch</th><th data-key="p">Port</th>'+
      '<th data-key="d">Description</th><th>Owner</th></tr></thead><tbody>'+rows+'</tbody></table>'+capNote;
    NOC.sortable(el.querySelector('table'));
    el.querySelectorAll('tr.click').forEach(function(tr){
      var open=function(){ITDrill.portDetail(tr.dataset.ip,tr.dataset.sw,tr.dataset.ifx,tr.dataset.pt);};
      tr.addEventListener('click',function(e){
        if(e.target.closest('.claim,.owner,.fbtn'))return;   // those handle themselves
        open();
      });
      var fb=tr.querySelector('.fbtn');
      if(fb) fb.addEventListener('click',function(e){e.stopPropagation();open();});
    });
    el.querySelectorAll('.claim').forEach(function(b){
      b.addEventListener('click',function(){claim(b.dataset.cref,b.dataset.ctitle);});});
    el.querySelectorAll('.owner').forEach(function(b){
      b.addEventListener('click',function(){release(b.dataset.cid);});});
  }
  var crit=cnt('critical');
  document.getElementById('oh-fFoot').innerHTML=
    '<span><b>'+list.length+'</b> shown</span>'+
    '<span><b>'+crit+'</b> critical</span>'+
    '<span><b>'+(S.cleared||0)+'</b> cleared this week</span>'+
    '<span style="margin-left:auto;color:var(--o-faint)">Click a row for port history and evidence</span>';
}

var pendingClaims=new Set();
async function claim(ref,title){
 if(pendingClaims.has(ref))return;pendingClaims.add(ref);var buttons=[...ctx.root.querySelectorAll('[data-cref]')].filter(function(b){return b.dataset.cref===ref;});buttons.forEach(function(b){b.disabled=true;});
 try{await ctx.write('/api/netswitch/claims','POST',{ref:ref,title:title});await reloadClaims();ctx.notify('Issue claimed.');}catch(e){ctx.notify('Could not claim this issue: '+e.message);}finally{pendingClaims.delete(ref);buttons.forEach(function(b){b.disabled=false;});}
}
async function release(id){
 if(pendingClaims.has(id)||!confirm('Release this issue so someone else can pick it up?'))return;pendingClaims.add(id);
 try{await ctx.write('/api/netswitch/claims/'+id,'DELETE');await reloadClaims();ctx.notify('Issue released.');}catch(e){ctx.notify('Could not release this issue: '+e.message);}finally{pendingClaims.delete(id);}
}
async function reloadClaims(){
  try{
    var cl=await jget('/api/netswitch/claims');
    S.claims={}; S.cleared=0;
    if(cl&&cl.ok){(cl.claims||[]).forEach(function(c){S.claims[c.ref]=c;});
      S.cleared=cl.cleared_week||0;}
  }catch(e){throw Error('The action completed, but ownership could not be refreshed. Try Refresh.');}
  renderFaults(); renderVitals();
}

/* ── sites ──────────────────────────────────────────────────────────────── */
function renderSites(){
  var by={};
  S.devices.forEach(function(d){
    var s=by[d.site]||(by[d.site]={site:d.site,sw:0,up:0,pu:0,pt:0,faults:0});
    s.sw++; if(d.reachable)s.up++; s.pu+=d.if_up||0; s.pt+=d.if_total||0;
  });
  S.issues.forEach(function(i){
    var d=S.devices.filter(function(x){return x.ip===i.switch_ip;})[0];
    if(d&&by[d.site])by[d.site].faults++;
  });
  var list=Object.keys(by).sort().map(function(k){return by[k];});
  document.getElementById('oh-siteN').textContent=list.length+' sites';
  document.getElementById('oh-sites').innerHTML=list.map(function(s){
    var pct=s.pt?Math.round(s.pu/s.pt*100):0;
    var tone=(s.up<s.sw)?'bad':(s.faults?'warn':'ok');
    return '<a class="nrow" href="/network-switches.html?site='+encodeURIComponent(s.site)+'">'+
      '<span class="ic '+tone+'">'+NOC.icon('pin')+'</span>'+
      '<span class="bd"><span class="t">'+esc(s.site)+'</span>'+
      '<span class="s">'+s.up+'/'+s.sw+' switches · '+s.pu.toLocaleString()+' ports up</span>'+
      '<span class="nmeter" style="margin-top:5px"><i class="'+(tone==='bad'?'bad':'')+
        '" style="width:'+pct+'%"></i></span></span>'+
      '<span class="rt">'+(s.faults?'<span class="sev warn">'+s.faults+'</span>':
        '<span class="sev ok">ok</span>')+'</span></a>';
  }).join('')||'<div class="nempty"><b>No switches</b>Nothing in the inventory yet.</div>';
}

/* ── trend ──────────────────────────────────────────────────────────────── */
async function renderTrend(){
  document.getElementById('oh-tRange').innerHTML=[[1,'24h'],[3,'3d'],[7,'7d'],[30,'30d']]
    .map(function(x){return '<button data-r="'+x[0]+'" aria-pressed="'+(S.range===x[0])+'">'+
      x[1]+'</button>';}).join('');
  document.querySelectorAll('#oh-tRange [data-r]').forEach(function(b){
    b.addEventListener('click',function(){ctx.navigate({range:Number(b.dataset.r)*24});});});
  var request=++trendRequest;
  var el=document.getElementById('oh-trend');
  el.innerHTML='<div class="nskel" style="height:118px"></div>';
  try{
    var days=S.range===1?1:S.range<=7?7:30;
    var d=await jget('/api/netswitch/trend?days='+days);
    if(request!==trendRequest)return;
    var ser=((d&&d.series)||[]).filter(function(p){return p.ts>=Date.now()/1000-S.range*86400;});
    var fmt=function(ts){
      var dt=new Date(ts*1000);
      return S.range<=1?String(dt.getHours()).padStart(2,'0')+':00'
        :(dt.getMonth()+1)+'/'+dt.getDate();};
    NOC.area(el,ser.map(function(p){return {t:fmt(p.ts),v:p.errors};}),
      {tone:'bad',unit:'ports',label:'Ports whose error counters rose',
       emptyHint:'The collector keeps 30 days of counters; this fills in as it samples.'});
    var tot=ser.reduce(function(a,p){return a+p.errors;},0);
    var peak=ser.reduce(function(a,p){return Math.max(a,p.errors);},0);
    document.getElementById('oh-tFoot').innerHTML=
      '<span>Each point counts <b>distinct ports</b> whose error counters rose in that window</span>'+
      '<span style="margin-left:auto"><b>'+peak+'</b> peak · <b>'+tot+'</b> total</span>';
  }catch(e){
    if(request!==trendRequest)return;
    el.innerHTML='<div class="nempty"><b>Trend unavailable</b>'+esc(e.message)+'</div>';
  }
}

/* ── firewalls + wireless + watch ───────────────────────────────────────── */
async function renderFw(){
  var el=document.getElementById('oh-fw');
  try{
    var d=await jget('/api/netswitch/fw-health');
    if(!d||d.ok===false)throw new Error((d&&(d.detail||d.error))||'firewall reader unavailable');
    var fws=(d&&d.firewalls)||[];
    if(!fws.length)throw new Error('no firewalls reported');
    el.innerHTML=fws.map(function(f){
      if(f.reachable===null){ try{ if(window.ITObserve&&typeof ITObserve.degraded==='function') ITObserve.degraded('fw:'+f.key,'Firewall "'+f.name+'" could not be read',f.error||'all probes failed'); }catch(_){} }
      return '<div style="margin-bottom:12px">'+
        '<div style="display:flex;align-items:center;gap:7px">'+
        '<span class="sev '+(f.reachable===null?'info':f.reachable?'ok':'crit')+'"'+(f.error?' title="'+esc(typeof f.error==='string'?f.error:JSON.stringify(f.error))+'"':'')+'>'+(f.reachable===null?'unknown':f.reachable?'up':'no data')+'</span>'+
        '<b style="font-size:12.5px">'+esc(f.name)+'</b>'+
        '<span class="s" style="font-family:var(--n-mono);font-size:10.5px;color:var(--o-faint);margin-left:auto">'+
          esc(f.host)+'</span></div>'+
        '<div class="fwgauge">'+
          '<div class="fwg"><div class="k">CPU</div><div class="v">'+(f.cpu!=null?f.cpu+'%':'—')+
            '</div><span class="nmeter"><i class="'+(f.cpu>80?'bad':f.cpu>60?'warn':'')+
            '" style="width:'+(f.cpu||0)+'%"></i></span></div>'+
          '<div class="fwg"><div class="k">Memory</div><div class="v">'+(f.mem!=null?f.mem+'%':'—')+
            '</div><span class="nmeter"><i class="'+(f.mem>85?'bad':f.mem>70?'warn':'')+
            '" style="width:'+(f.mem||0)+'%"></i></span></div>'+
          '<div class="fwg"><div class="k">Sessions</div><div class="v">'+
            (f.sessions!=null?Number(f.sessions).toLocaleString():'—')+'</div></div>'+
          '<div class="fwg"><div class="k">Tunnels</div><div class="v'+
            (f.tunnels_total!=null&&f.tunnels_up<f.tunnels_total?'" style="color:var(--o-slow)':'"')+'>'+
            (f.tunnels_total==null?'\u2014':f.tunnels_up+'/'+f.tunnels_total)+'</div></div>'+
        '</div></div>';
    }).join('');
  }catch(e){
    el.innerHTML='<div class="nempty">'+NOC.icon('shield')+'<b>Firewall data unavailable</b>'+
      esc(e.message)+'</div>';
    try{ if(window.ITObserve&&typeof ITObserve.degraded==='function') ITObserve.degraded('fw','Firewall data unavailable',e.message); }catch(_){}
  }
}
function renderWifi(){
  var n=(S.noc&&S.noc.summary)||{};
  var el=document.getElementById('oh-wifi');
  if(n.totalAps==null){
    el.innerHTML='<div class="nempty">'+NOC.icon('wifi')+'<b>Meraki unavailable</b>'+
      'The wireless summary could not be read.</div>';return;}
  var apTot=(n.totalOnline||0)+(n.totalOffline||0);
  el.innerHTML='<div class="fwgauge" style="margin-top:0">'+
    '<div class="fwg"><div class="k">Access points</div><div class="v">'+n.totalOnline+
      ' <span style="font-size:12px;color:var(--o-faint)">/ '+apTot+'</span></div>'+
      '<span class="nmeter"><i class="'+(n.totalOffline?'warn':'good')+'" style="width:'+
      (apTot?Math.round(n.totalOnline/apTot*100):0)+'%"></i></span></div>'+
    '<div class="fwg"><div class="k">Clients</div><div class="v">'+
      Number(n.totalClients||0).toLocaleString()+'</div></div>'+
    '<div class="fwg"><div class="k">Offline</div><div class="v" style="color:'+
      (n.totalOffline?'var(--o-slow)':'var(--o-sig)')+'">'+(n.totalOffline||0)+'</div></div>'+
    '<div class="fwg"><div class="k">Avg clients / AP</div><div class="v">'+
      (n.totalOnline?Math.round((n.totalClients||0)/n.totalOnline*10)/10:'—')+'</div></div>'+
  '</div>';
}
async function renderWatch(){
  var el=document.getElementById('oh-watch');
  try{
    var d=await jget('/api/netswitch/watch');
    var items=(d&&d.items)||[];
    document.getElementById('oh-watchN').textContent=items.length||'none';
    if(!items.length){
      el.innerHTML='<div class="nempty">'+NOC.icon('pin')+'<b>Nothing on watch</b>'+
        'Open any port or device and choose <b>Watch this</b> — watched items are sampled '+
        'every 5 minutes and kept for 120 days.</div>';return;}
    el.innerHTML='<div class="nlist">'+items.map(function(it){
      var last=it.last||{}, dg=last.diag||null, sev=dg&&dg.severity;
      var tone=sev==='critical'?'bad':(sev==='warn'?'warn':'ok');
      var state=it.kind==='port'
        ? (last.oper?('link '+last.oper):'no sample yet')+(last.speed?' · '+last.speed+' Mbps':'')
        : (it.kind==='device'?((last.reach||{}).alive?'responding':'no reply'):'—');
      return '<button class="nrow" data-w="'+esc(it.ref||'')+'">'+
        '<span class="ic '+tone+'">'+NOC.icon(it.kind==='ap'?'wifi':'switchd')+'</span>'+
        '<span class="bd"><span class="t">'+esc(it.label||it.ref||'')+'</span>'+
        '<span class="s">'+esc(state)+'</span></span>'+
        '<span class="rt">'+esc(it.kind||'')+'</span></button>';
    }).join('')+'</div>';
    el.querySelectorAll('[data-w]').forEach(function(b){b.onclick=function(){ctx.watch(items.find(function(it){return it.ref===b.dataset.w;}));};});
  }catch(e){
    el.innerHTML='<div class="nempty"><b>Watch list unavailable</b>'+esc(e.message)+'</div>';
  }
}

/* ── CSV export of exactly what is on screen ────────────────────────────── */
document.getElementById('oh-fExport').addEventListener('click',function(){
  var list=faultRows();
  var q=OpsPolish.csvCell;
  var csv=['severity,fault,switch,switch_ip,port,description,detail,owner'].concat(
    list.map(function(i){var c=S.claims[refOf(i)];
      return [i.severity,titleOf(i),i.switch,i.switch_ip,i.port,i.descr,causeOf(i),
              c?c.claimed_by:''].map(q).join(',');})).join('\n');
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));
  a.download='nrpi-faults.csv'; a.click(); URL.revokeObjectURL(a.href);
});

/* ── load ───────────────────────────────────────────────────────────────── */
var trendRequest=0;
function scopedIssues(){return ctx.scopeIssues(S.issues,S.devices);}
function scopeSummary(){return ctx.state().site==='ALL'?S.sum:ctx.summarize(S.devices);}
async function load(){
  if(S.busy)return;S.busy=true;document.getElementById('oh-nRefresh').disabled=true;
  try{
    var res=await Promise.all([
      jget('/api/netswitch/overview'),
      jget('/api/meraki/noc').catch(function(){return null;}),
      jget('/api/netswitch/claims').catch(function(){return null;})]);
    var ov=res[0], noc=res[1], cl=res[2];
    if(!ov||ov.ok===false)throw new Error((ov&&ov.detail)||'overview unavailable');
    S.issues=ov.issues||[]; S.devices=ov.devices||[];
    // counts are read from the table; ov.issues is a capped page of it
    S.counts=ov.counts||null;
    S.sum=ov.summary||{}; S.meta=ov.meta||{}; S.noc=noc;
    S.claims={}; S.cleared=0;
    if(cl&&cl.ok){(cl.claims||[]).forEach(function(c){S.claims[c.ref]=c;});
      S.cleared=cl.cleared_week||0;}
    ctx.inventory(ov);renderVitals(); renderKpis(); renderFaults(); renderSites(); renderWifi();
    renderTrend(); renderFw(); renderWatch();return true;
  }catch(e){
    var m=(e.code===401)?'Your session expired. <a href="/login.html">Sign in</a> to continue.':esc(e.message);
    document.getElementById('oh-kpis').innerHTML=
      '<div class="c12"><div class="ncard"><div class="ncb"><div class="nempty">'+
      NOC.icon('pulse')+'<b>Couldn’t load network health</b>'+m+'</div></div></div></div>';
    return false;
  }finally{S.busy=false;document.getElementById('oh-nRefresh').disabled=false;}
}
document.getElementById('oh-faultSearch').addEventListener('input',function(e){S.q=e.target.value;renderFaults();});
document.getElementById('oh-faultReset').onclick=function(){S.q='';S.filter='all';document.getElementById('oh-faultSearch').value='';renderFaults();};
document.getElementById('oh-nRefresh').addEventListener('click',load);
document.getElementById('oh-nAlerts').addEventListener('click',function(){
  S.filter='critical'; renderFaults();
  document.getElementById('oh-faults').scrollIntoView({block:'center',behavior:'smooth'});});
S.filter=ctx.state().severity;S.q=ctx.state().faultSearch;S.range=ctx.state().range/24;var ready=load();
return {ready:ready,refresh:load,activate:function(st){var changed=S.range!==st.range/24;S.range=st.range/24;S.filter=st.severity;S.q=st.faultSearch;document.getElementById('oh-faultSearch').value=S.q;renderVitals();renderKpis();renderFaults();if(changed)renderTrend();},deactivate:function(){},capture:function(){return{severity:S.filter,faultSearch:S.q};}};

};
