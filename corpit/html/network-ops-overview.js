window.NetworkOpsModules=window.NetworkOpsModules||{};
window.NetworkOpsModules.overview=function(ctx){
'use strict';
var NOC=ctx.chrome,workspace=ctx;

NOC.act('<button class="nbtn rel icon" id="oh-nAlerts" aria-label="Review port findings">'+
  NOC.icon('bell')+'<span class="badge" id="oh-alertN" hidden>0</span></button>'+
  '<button class="nbtn" id="oh-nRefresh">'+NOC.icon('refresh')+'Refresh</button>');

var esc=NOC.esc, ago=NOC.ago;
var S={issues:[],devices:[],counts:null,sum:{},meta:{},scan:{},scanError:false,activityError:false,noc:null,claims:{},cleared:0,
       filter:'all',range:7,fw:null,watch:[],q:'',busy:false};
function revealFindings(){
  var details=document.getElementById('oh-findings');
  details.open=true;
  document.getElementById('oh-faults').scrollTop=0;
  details.scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});
}
document.getElementById('oh-fqIcon').textContent='Port findings';
document.getElementById('oh-faultSearch').setAttribute('aria-label','Search port findings');
document.getElementById('oh-faultSearch').setAttribute('placeholder','Search switch, IP, port, finding or description…');

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
function secondsSince(ts){return ts?Math.max(0,Math.floor(Date.now()/1000)-ts):null;}
function activityRank(i){return ({rising:0,link_changed:1,link_down:2,stable:3,link_steady:3,
  link_up:4,reset:5,insufficient:6,stale:7,not_tracked:8,unavailable:9})[i.activity&&i.activity.state]??9;}
function activityCell(i){
  var a=i.activity||{},state=a.state||'unavailable';
  var elapsed=a.window_seconds?Math.round(a.window_seconds/60)+'m sampled':'';
  var link=a.latest_oper?'link '+a.latest_oper:'';
  var changes=a.link_changes?String(a.link_changes)+' link changes':'';
  var when=a.last_ts?'last '+ago(secondsSince(a.last_ts)):'';
  var detail=[elapsed,link,changes,when].filter(Boolean).join(' · ');
  if(state==='rising'){
    var parts=[];
    if(a.d_crc>0)parts.push('+'+Number(a.d_crc).toLocaleString()+' CRC');
    if(a.d_out_disc>0)parts.push('+'+Number(a.d_out_disc).toLocaleString()+(a.d_out_disc==1?' discard':' discards'));
    if(a.d_in_err>0&&!(a.d_crc>0))parts.push('+'+Number(a.d_in_err).toLocaleString()+(a.d_in_err==1?' input error':' input errors'));
    if(a.d_out_err>0)parts.push('+'+Number(a.d_out_err).toLocaleString()+(a.d_out_err==1?' output error':' output errors'));
    return '<b>'+esc(parts.join(' · ')||'Counters rose')+'</b><span class="s">'+esc(detail)+'</span>';
  }
  var label={stable:'Finding counter unchanged',link_changed:'Link changed',link_down:'Still down',
             link_steady:'No link change',link_up:'Link now up',not_tracked:'Change not sampled',
             reset:'Counter reset',insufficient:'Need another sample',
             stale:'Sample stale',unavailable:'No samples'}[state]||'No samples';
  var other=[];
  if(state==='stable'){
    if(a.finding_counter!=='crc'&&a.d_crc>0)other.push('+'+Number(a.d_crc).toLocaleString()+' other CRC');
    if(a.finding_counter!=='out_disc'&&a.d_out_disc>0)other.push('+'+Number(a.d_out_disc).toLocaleString()+(a.d_out_disc==1?' other discard':' other discards'));
    if(a.finding_counter!=='in_err'&&a.finding_counter!=='crc'&&a.d_in_err>0)other.push('+'+Number(a.d_in_err).toLocaleString()+(a.d_in_err==1?' other input error':' other input errors'));
    if(a.finding_counter!=='out_err'&&a.d_out_err>0)other.push('+'+Number(a.d_out_err).toLocaleString()+(a.d_out_err==1?' other output error':' other output errors'));
  }
  return '<span>'+esc(label)+'</span><span class="s">'+esc(other.concat(detail?[detail]:[]).join(' · '))+'</span>';
}
function ini(n){n=String(n||'').split('@')[0];var w=n.split(/[._\- ]+/).filter(Boolean);
  return ((w[0]||'?')[0]+(w[1]?w[1][0]:'')).toUpperCase();}

/* ── fleet health ───────────────────────────────────────────────────────── */
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
  var pollAge=S.meta.last_run?secondsSince(S.meta.last_run):s.scan_age;
  var pollStale=pollAge==null||pollAge>7200;
  var pPct=s.ports?Math.round(s.ports_up/s.ports*100):0;
  var swPct=s.switches?Math.round(s.switches_up/s.switches*100):0;
  var apTot=(n.totalOnline||0)+(n.totalOffline||0);
  document.getElementById('oh-kpis').innerHTML=
    kpi({span:'c3',k:'Switches',v:s.switches_up+'<small>/'+s.switches+'</small>',
         tone:pollStale?'warn':s.switches_down?'bad':'good',
         s:pollStale?'last poll '+(pollAge!=null?ago(pollAge):'unavailable'):
           s.switches_down?s.switches_down+' not responding':'all responding',
         meter:swPct,mtone:pollStale?'warn':s.switches_down?'bad':'good'})+
    kpi({span:'c3',k:'Interfaces up',v:Number(s.ports_up||0).toLocaleString()+'<small>/'+
         Number(s.ports||0).toLocaleString()+'</small>',s:pPct+'% active at last poll; unused may be down',
         meter:pPct,mtone:''})+
    kpi({span:'c3',k:'Access points · fleet',v:apTot?(n.totalOnline+'<small>/'+apTot+'</small>'):'—',
         tone:n.totalOffline?'warn':'good',
         s:apTot?(n.totalOffline?n.totalOffline+' offline':'all online'):'Meraki unavailable',
         meter:apTot?Math.round(n.totalOnline/apTot*100):null,mtone:n.totalOffline?'warn':'good'})+
    kpi({span:'c3',k:'Clients seen · 5 min · fleet',v:n.totalClients!=null?Number(n.totalClients).toLocaleString():'—',
         tone:'info',s:'includes recently offline clients'});
}

function renderFreshness(){
  var inventoryAge=S.meta.last_run?secondsSince(S.meta.last_run):scopeSummary().scan_age;
  var findingAge=secondsSince(S.scan.last_scan);
  var inventoryStale=inventoryAge==null||inventoryAge>7200;
  var findingStale=findingAge==null||findingAge>7200||S.scanError;
  var el=document.getElementById('oh-freshness');
  el.classList.toggle('stale',inventoryStale||findingStale);
  var inventory='Inventory '+esc(inventoryAge!=null?ago(inventoryAge):'unavailable');
  var findings='finding scan '+esc(findingAge!=null?ago(findingAge):'unavailable');
  el.innerHTML=inventoryStale&&findingStale
    ? '<b>Switch evidence needs fresh collection</b><span>'+inventory+' · '+findings+
      '. Switch totals and port findings are last-known; verify a port before treating a finding as current.</span>'
    : inventoryStale
      ? '<b>Switch inventory needs a fresh poll</b><span>'+inventory+' · '+findings+
        '. Switch response and interface counts are last-known.</span>'
      : findingStale
        ? '<b>Port findings need a fresh scan</b><span>'+inventory+' · '+findings+
          '. Switch totals reflect the recent poll; finding severity remains historical. Verify a port before acting.</span>'
        : '<b>Switch evidence is recent</b><span>'+inventory+' · '+findings+'.</span>';
}

/* ── vitals strip ───────────────────────────────────────────────────────── */
function renderVitals(){
  var s=scopeSummary(),n=(S.noc&&S.noc.summary)||{};
  var crit=sevTotal('critical'), open=queueTotal();
  var inventoryAge=S.meta.last_run?secondsSince(S.meta.last_run):s.scan_age;
  var findingAge=secondsSince(S.scan.last_scan);
  NOC.vitals([
    {k:'Inventory poll',v:ago(inventoryAge)},
    {k:'Finding scan',v:ago(findingAge),cls:findingAge>7200?'warn':''},
    {k:'Switches',v:s.switches_up+'/'+s.switches,cls:s.switches_down?'bad':'good'},
    {k:'Interfaces up',v:Number(s.ports_up||0).toLocaleString()},
    {k:'APs · fleet',v:(n.totalOnline!=null?n.totalOnline+'/'+((n.totalOnline||0)+(n.totalOffline||0)):'—'),
     cls:n.totalOffline?'warn':'good'},
    {k:'Clients seen 5m · fleet',v:n.totalClients!=null?Number(n.totalClients).toLocaleString():'—'},
    {k:'Port findings',v:S.scanError?'—':open.toLocaleString(),cls:crit?'bad':(open||S.scanError?'warn':'good')},
    {k:'Cleared 7d · fleet',v:S.cleared||0,cls:'good'}
  ]);
  NOC.badge('health',crit||open,crit?'bad':'warn');
  var a=document.getElementById('oh-alertN');
  if(a){ if(crit){a.hidden=false;a.textContent=crit;} else a.hidden=true; }
  NOC.stamp('inventory polled '+ago(inventoryAge),(inventoryAge||0)>7200);
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
  var scrollKey=JSON.stringify([ctx.state().site,S.filter,S.q]);
  var resetScroll=S.faultScrollKey!==scrollKey;
  S.faultScrollKey=scrollKey;
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
  var findingAge=secondsSince(S.scan.last_scan);
  document.getElementById('oh-findings-summary-copy').textContent=
    (S.scanError?'Finding scan unavailable':queueTotal().toLocaleString()+' findings at last scan')+
    ' · '+(findingAge!=null?ago(findingAge):'scan time unavailable');
  var note='<div class="pnote">Finding scan '+esc(findingAge!=null?ago(findingAge):'unavailable')+
    '. Severity may use accumulated counters; recent change needs fresh samples. Open a port to verify impact.'+
    (S.scanError?' Finding data could not be read.':'')+
    (S.activityError?' Counter history could not be read.':'')+'</div>';
  // The tabs above count the queue; this list is what the server sent. When
  // those differ the reader is looking at a slice, and has to be told which.
  var shownFor=(f==='all')?queueTotal():cnt(f);
  var capNote=(shownFor>severityRows.length)
    ? '<div class="pnote">Loaded '+severityRows.length.toLocaleString()+' of '+
      shownFor.toLocaleString()+' — the server returns the most severe first. '+
      'Narrow by switch or severity to reach the rest.</div>'
    : '';
  if(!list.length&&S.q.trim()&&!S.scanError){
    el.innerHTML=note+'<div class="nempty"><b>No findings match this search</b>Clear the search or use Reset filters.</div>';
  }else if(!list.length){
    el.innerHTML=note+'<div class="nempty">'+NOC.icon('pulse')+
      '<b>'+(S.scanError?'Findings unavailable':shownFor?'None of these arrived in this page':
             (f==='all'?'No port findings':'Nothing at this severity'))+'</b>'+
      (S.scanError?'The last finding scan could not be loaded. Try Refresh.':shownFor?shownFor.toLocaleString()+' finding'+(shownFor===1?'':'s')+
                ' of this severity exist, but none were in the slice the '+
                'server returned. Narrow by switch to reach them.'
              :(f==='all'?'Every port the last scan touched came back clean.'
                        :'Try another filter to see the rest of the queue.'))+'</div>';
  }else{
    var rows=list.slice().sort(function(a,b){
      var o={critical:0,warn:1,info:2};
      return (o[a.severity]-o[b.severity])||(activityRank(a)-activityRank(b))||
        String(a.switch).localeCompare(String(b.switch));
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
        '<td data-sort="'+activityRank(i)+'" class="grow">'+activityCell(i)+'</td>'+
        '<td class="grow"><span class="s" title="'+esc(i.descr||'')+'">'+esc(i.descr||'—')+'</span></td>'+
        '<td>'+(c?'<button class="owner" data-cid="'+c.id+'" title="Claimed by '+esc(c.claimed_by)+
            ' — click to release">'+esc(ini(c.claimed_by))+'</button>'
          :'<button class="claim" data-cref="'+esc(ref)+'" data-ctitle="'+esc(titleOf(i))+
            '">Claim</button>')+'</td>'+
        '</tr>';
    }).join('');
    el.innerHTML=note+'<table class="nt">'+
      '<colgroup><col style="width:88px"><col class="wide"><col style="width:150px">'+
      '<col style="width:88px"><col style="width:180px"><col class="mid"><col style="width:74px"></colgroup>'+
      '<thead><tr>'+
      '<th data-key="sev" data-type="num">Sev</th><th data-key="t">Finding</th>'+
      '<th data-key="sw">Switch</th><th data-key="p">Port</th>'+
      '<th data-key="a" data-type="num">Recent change</th>'+
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
    '<span><b>'+crit+'</b> critical at last scan</span>'+
    '<span><b>'+(S.cleared||0)+'</b> cleared this week</span>'+
    '<span style="margin-left:auto;color:var(--o-faint)">Click a row for port history and evidence</span>';
  if(resetScroll)el.scrollTop=0;
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
  var by={},siteScope=ctx.state().site,deviceSite={};
  S.devices.forEach(function(d){
    deviceSite[d.ip]=d.site;
    if(siteScope!=='ALL'&&d.site!==siteScope)return;
    var s=by[d.site]||(by[d.site]={site:d.site,sw:0,up:0,pu:0,pt:0,faults:0,critical:0});
    s.sw++; if(d.reachable)s.up++; s.pu+=d.if_up||0; s.pt+=d.if_total||0;
  });
  S.issues.forEach(function(i){
    var site=deviceSite[i.switch_ip],s=by[site];
    if(s){s.faults++;if(i.severity==='critical')s.critical++;}
  });
  var list=Object.keys(by).sort().map(function(k){return by[k];});
  document.getElementById('oh-siteN').textContent=list.length+' site'+(list.length===1?'':'s');
  document.getElementById('oh-sites').innerHTML=list.length?'<div class="overview-site-list">'+list.map(function(s){
    var pct=s.pt?Math.round(s.pu/s.pt*100):0;
    var label=({SNA01:'Irvine',DFW02:'Plano'})[s.site]||s.site;
    var tone=s.up<s.sw?'crit':s.critical?'warn':'ok';
    return '<a class="overview-site" href="/network-switches.html?site='+encodeURIComponent(s.site)+'">'+
      '<span class="overview-site-head"><strong>'+esc(label)+' <small>'+esc(s.site)+'</small></strong>'+
      '<span class="sev '+tone+'">'+(S.scanError?'Findings unavailable':s.critical?
        s.critical+' critical at scan':s.faults?s.faults+' finding'+(s.faults===1?'':'s')+' at scan':'No findings at scan')+'</span></span>'+
      '<span class="overview-site-facts"><span>'+s.up+'/'+s.sw+' switches responded</span>'+
      '<span>'+s.pu.toLocaleString()+'/'+s.pt.toLocaleString()+' interfaces up</span></span>'+
      '<span class="nmeter"><i style="width:'+pct+'%"></i></span></a>';
  }).join('')+'</div>':'<div class="nempty"><b>No switches</b>Nothing in the inventory yet.</div>';
}

function renderAttention(){
  var el=document.getElementById('oh-attention');
  if(S.scanError){
    el.innerHTML='<div class="nempty"><b>Finding scan unavailable</b>Check the switch source before reviewing priorities.</div>';
    return;
  }
  var critical=scopedIssues().filter(function(i){return i.severity==='critical';})
    .sort(function(a,b){return activityRank(a)-activityRank(b);});
  var count=sevTotal('critical'),warnings=sevTotal('warn');
  var rising=critical.filter(function(i){return i.activity&&i.activity.state==='rising';}).length;
  var top=critical.length?critical.slice(0,3):scopedIssues().filter(function(i){return i.severity==='warn';}).slice(0,3);
  el.innerHTML='<div class="nh-attention-grid"><div class="nh-attention-totals">'+
    '<button type="button" class="nh-critical-total" data-filter="critical" aria-label="Review '+count+' critical findings">'+
    '<strong>'+count.toLocaleString()+'</strong><span>critical finding'+(count===1?'':'s')+'</span></button>'+
    '<p class="nh-rising">'+(count?(rising?rising+' with rising counters':'No rising counters verified'):'No critical findings at last scan')+'</p>'+
    '<button type="button" class="nh-warning-total" data-filter="warn" aria-label="Review '+warnings+' warnings">'+
    '<strong>'+warnings.toLocaleString()+'</strong><span>warning'+(warnings===1?'':'s')+'</span><i aria-hidden="true">›</i></button></div>'+
    '<div class="nh-investigate"><div class="nh-investigate-heading"><b>Investigate first</b><small>Last scan</small></div>'+
    (top.length?'<div class="overview-attention-list">'+top.map(function(i){
      return '<button type="button" class="overview-attention-row" data-ip="'+esc(i.switch_ip||'')+
        '" data-sw="'+esc(i.switch||'')+'" data-ifx="'+esc(i.ifindex||'')+'" data-pt="'+esc(i.port||'')+'">'+
        '<span class="sev '+(SEV[i.severity]||'info')+'">'+esc(i.severity||'info')+'</span>'+
        '<span><b>'+esc(titleOf(i))+'</b><small>'+esc(i.switch||'')+' · '+esc(i.port||'')+
        ' · '+esc((i.activity&&i.activity.state)==='rising'?'rising':
          (i.activity&&i.activity.state)==='stable'?'counter unchanged':'not recently verified')+
        '</small></span></button>';
    }).join('')+'</div>':'<p class="nh-no-findings">No findings need review in this scope.</p>')+
    '<button type="button" class="nbtn overview-review" id="oh-review">Review full queue</button></div></div>';
  el.querySelectorAll('.overview-attention-row').forEach(function(b){
    b.onclick=function(){ITDrill.portDetail(b.dataset.ip,b.dataset.sw,b.dataset.ifx,b.dataset.pt);};
  });
  el.querySelectorAll('[data-filter]').forEach(function(b){
    b.onclick=function(){S.q='';document.getElementById('oh-faultSearch').value='';S.filter=b.dataset.filter;
      renderFaults();revealFindings();};
  });
  document.getElementById('oh-review').onclick=function(){S.q='';S.filter='all';
    document.getElementById('oh-faultSearch').value='';renderFaults();revealFindings();};
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
  var pollAge=S.meta.last_run?secondsSince(S.meta.last_run):scopeSummary().scan_age;
  if(pollAge==null||pollAge>7200){
    el.innerHTML='<div class="overview-trend-stale"><b>Recent switch trend cannot be verified</b>'+
      '<span>Last inventory poll '+esc(pollAge!=null?ago(pollAge):'unavailable')+
      '. A flat line would not show whether ports stayed healthy while collection was stale.</span></div>';
    document.getElementById('oh-tFoot').innerHTML='<span>Trend resumes when current switch samples are available.</span>';
    return;
  }
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
    var tot=ser.reduce(function(a,p){return a+p.errors;},0);
    var peak=ser.reduce(function(a,p){return Math.max(a,p.errors);},0);
    if(!ser.length){
      el.innerHTML='<div class="overview-trend-stale"><b>No counter trend samples in this window</b>'+
        '<span>The collector has no points to compare for the selected range.</span></div>';
    }else if(!peak){
      el.innerHTML='<div class="overview-trend-stale overview-trend-quiet"><b>No rising ports in the recorded trend buckets</b>'+
        '<span>This does not revalidate findings from the last severity scan.</span></div>';
    }else{
      NOC.area(el,ser.map(function(p){return {t:fmt(p.ts),v:p.errors};}),
        {tone:'bad',unit:'ports',label:'Ports whose error counters rose',
         emptyHint:'The collector keeps 30 days of counters; this fills in as it samples.'});
    }
    document.getElementById('oh-tFoot').innerHTML=
      '<span>Each point counts <b>distinct ports</b> whose error counters rose'+
        (secondsSince(S.scan.last_scan)>7200?'; finding severity last scanned '+esc(ago(secondsSince(S.scan.last_scan))):'')+
        '</span>'+
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
      var tunnelWarn=f.tunnels_total!=null&&f.tunnels_up<f.tunnels_total;
      var meter=function(value,limit,warning){
        return '<span class="nmeter"><i class="'+(value>limit?'bad':value>warning?'warn':'')+
          '" style="width:'+Math.max(0,Math.min(100,Number(value)||0))+'%"></i></span>';
      };
      return '<div class="overview-fw">'+
        '<div class="overview-fw-head"><b>'+esc(f.name)+'</b>'+
        '<span class="sev '+(f.reachable===null?'info':f.reachable?'ok':'crit')+'"'+
          (f.error?' title="'+esc(typeof f.error==='string'?f.error:JSON.stringify(f.error))+'"':'')+'>'+
          (f.reachable===null?'unknown':f.reachable?'responding':'no data')+'</span>'+
        '<small>'+esc(f.host)+'</small></div>'+
        '<div class="fwgauge">'+
          '<div class="fwg"><div class="k">CPU</div><div class="v">'+(f.cpu!=null?f.cpu+'%':'—')+
            '</div>'+meter(f.cpu,80,60)+'</div>'+
          '<div class="fwg"><div class="k">Memory</div><div class="v">'+(f.mem!=null?f.mem+'%':'—')+
            '</div>'+meter(f.mem,85,70)+'</div>'+
          '<div class="fwg"><div class="k">Sessions</div><div class="v">'+
            (f.sessions!=null?Number(f.sessions).toLocaleString():'—')+'</div></div>'+
          '<div class="fwg"><div class="k">Tunnels</div><div class="v'+(tunnelWarn?' warn':'')+'">'+
            (f.tunnels_total==null?'—':esc(f.tunnels_up)+'/'+esc(f.tunnels_total))+'</div></div>'+
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
    '<div class="fwg"><div class="k">Clients seen (5m)</div><div class="v">'+
      Number(n.totalClients||0).toLocaleString()+'</div></div>'+
    '<div class="fwg"><div class="k">Offline</div><div class="v" style="color:'+
      (n.totalOffline?'var(--o-slow)':'var(--o-sig)')+'">'+(n.totalOffline||0)+'</div></div>'+
    '<div class="fwg"><div class="k">Avg seen / AP</div><div class="v">'+
      (n.totalOnline?Math.round((n.totalClients||0)/n.totalOnline*10)/10:'—')+'</div></div>'+
  '</div>';
}
async function renderWatch(){
  var el=document.getElementById('oh-watch'),card=document.getElementById('oh-watch-card');
  try{
    var d=await jget('/api/netswitch/watch');
    if(!d||d.ok===false)throw new Error((d&&(d.detail||d.error))||'watch list unavailable');
    var items=(d&&d.items)||[];
    document.getElementById('oh-watchN').textContent=items.length||'none';
    card.hidden=!items.length;
    card.parentElement.classList.toggle('watch-empty',!items.length);
    if(!items.length){
      el.replaceChildren();return;}
    // Unwatch follows the server gate (DELETE /watch needs network-diag admin)
    var R=window.itRbac, admin=!R||!R.canAdmin||R.canAdmin('network-diag');
    el.innerHTML='<div class="nlist">'+items.map(function(it){
      var last=it.last||{}, dg=last.diag||null, sev=dg&&dg.severity;
      var tone=sev==='critical'?'bad':(sev==='warn'?'warn':'ok');
      var reach=last.reach;
      var state=it.kind==='port'
        ? (last.oper?('link '+last.oper):'no sample yet')+(last.speed?' · '+last.speed+' Mbps':'')
        : (it.kind==='device'?(!reach?'no sample yet':reach.alive?'responding':
            (dg&&dg.key==='icmp_blocked'?'present, no ping reply':'no reply')):'—');
      // the sample time keeps an old result from reading as current beside a fresh trace
      if(it.last_ts) state+=' · sampled '+ago(secondsSince(it.last_ts));
      return '<div style="display:flex;align-items:center;gap:6px"><button class="nrow" style="flex:1;min-width:0" data-w="'+esc(it.ref||'')+'"'+
        (dg&&dg.title?' title="'+esc(dg.title+(dg.cause?' — '+dg.cause:''))+'"':'')+'>'+
        '<span class="ic '+tone+'">'+NOC.icon(it.kind==='ap'?'wifi':'switchd')+'</span>'+
        '<span class="bd"><span class="t">'+esc(it.label||it.ref||'')+'</span>'+
        '<span class="s">'+esc(state)+'</span></span>'+
        '<span class="rt">'+esc(it.kind||'')+'</span></button>'+
        (admin?'<button class="nbtn" data-unw="'+esc(it.id)+'" aria-label="Stop watching '+esc(it.label||it.ref||'')+'">Unwatch</button>':'')+
        '</div>';
    }).join('')+'</div>';
    el.querySelectorAll('[data-w]').forEach(function(b){b.onclick=function(){ctx.watch(items.find(function(it){return it.ref===b.dataset.w;}));};});
    el.querySelectorAll('[data-unw]').forEach(function(b){b.onclick=async function(){
      b.disabled=true;
      try{await ctx.write('/api/netswitch/watch/'+encodeURIComponent(b.dataset.unw),'DELETE');
        await ctx.watchChanged();await renderWatch();ctx.notify('Removed from the watch list. Its sample history is kept.');}
      catch(e){b.disabled=false;ctx.notify('Could not unwatch: '+e.message);}
    };});
  }catch(e){
    card.hidden=false;card.parentElement.classList.remove('watch-empty');
    el.innerHTML='<div class="nempty"><b>Watch list unavailable</b>'+esc(e.message)+'</div>';
  }
}

/* ── CSV export of exactly what is on screen ────────────────────────────── */
document.getElementById('oh-fExport').addEventListener('click',function(){
  var list=faultRows();
  var q=OpsPolish.csvCell;
  var csv=['severity,finding,switch,switch_ip,port,description,detail,owner,finding_scan_time,activity,finding_counter,first_sample_time,last_sample_time,delta_input_errors,delta_output_errors,delta_crc,delta_discards,link_at_latest_sample,link_changes'].concat(
    list.map(function(i){var c=S.claims[refOf(i)];
      var a=i.activity||{};
      return [i.severity,titleOf(i),i.switch,i.switch_ip,i.port,i.descr,causeOf(i),
              c?c.claimed_by:'',S.scan.last_scan?new Date(S.scan.last_scan*1000).toISOString():'',
              a.state||'unavailable',a.finding_counter||'',a.first_ts?new Date(a.first_ts*1000).toISOString():'',
              a.last_ts?new Date(a.last_ts*1000).toISOString():'',a.d_in_err,a.d_out_err,a.d_crc,a.d_out_disc,
              a.latest_oper||'',a.link_changes].map(q).join(',');})).join('\n');
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));
  a.download='nrpi-port-findings.csv'; a.click(); URL.revokeObjectURL(a.href);
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
    S.sum=ov.summary||{}; S.meta=ov.meta||{}; S.scan=ov.scan||{};
    S.scanError=!!ov.scan_error; S.activityError=!!ov.activity_error; S.noc=noc; S.loadedAt=Date.now();
    S.claims={}; S.cleared=0;
    if(cl&&cl.ok){(cl.claims||[]).forEach(function(c){S.claims[c.ref]=c;});
      S.cleared=cl.cleared_week||0;}
    ctx.inventory(ov);renderVitals(); renderKpis(); renderFreshness(); renderSites(); renderAttention(); renderFaults(); renderWifi();
    renderTrend(); renderFw(); renderWatch();return true;
  }catch(e){
    var m=(e.code===401)?'Your session expired. <a href="/login.html">Sign in</a> to continue.':esc(e.message);
    document.getElementById('oh-kpis').innerHTML=
      '<div class="c12"><div class="ncard"><div class="ncb"><div class="nempty">'+
      NOC.icon('pulse')+'<b>Couldn’t load network health</b>'+m+'</div></div></div></div>';
    document.getElementById('oh-freshness').textContent='Switch evidence unavailable; the source could not be read.';
    ['oh-sites','oh-attention','oh-fw','oh-wifi','oh-trend','oh-watch'].forEach(function(id){
      document.getElementById(id).innerHTML='<div class="nempty"><b>Source unavailable</b>Refresh after the network source returns.</div>';
    });
    document.getElementById('oh-watch-card').hidden=false;
    document.getElementById('oh-watch-card').parentElement.classList.remove('watch-empty');
    return false;
  }finally{S.busy=false;document.getElementById('oh-nRefresh').disabled=false;}
}
document.getElementById('oh-faultSearch').addEventListener('input',function(e){S.q=e.target.value;renderFaults();});
document.getElementById('oh-faultReset').onclick=function(){S.q='';S.filter='all';document.getElementById('oh-faultSearch').value='';renderFaults();};
document.getElementById('oh-nRefresh').addEventListener('click',load);
document.getElementById('oh-nAlerts').addEventListener('click',function(){
  S.filter='critical'; renderFaults();
  revealFindings();});
document.getElementById('oh-findings').addEventListener('toggle',function(){
  document.getElementById('oh-findings-toggle').textContent=this.open?'Hide findings':'Review findings';
});
S.filter=ctx.state().severity;S.q=ctx.state().faultSearch;S.range=ctx.state().range/24;
document.getElementById('oh-findings').open=(S.filter!=='all'||!!S.q);
var ready=load();
return {ready:ready,refresh:load,activate:function(st){var changed=S.range!==st.range/24;S.range=st.range/24;S.filter=st.severity;S.q=st.faultSearch;document.getElementById('oh-faultSearch').value=S.q;
  if(S.filter!=='all'||S.q)document.getElementById('oh-findings').open=true;
  renderVitals();renderKpis();renderFreshness();renderAttention();renderSites();renderFaults();if(changed)renderTrend();
  // Switching views keeps the last snapshot; re-read it once it is over a minute old so Overview matches Switches.
  if(!S.busy&&(!S.loadedAt||Date.now()-S.loadedAt>60000))load();},deactivate:function(){},capture:function(){return{severity:S.filter,faultSearch:S.q};}};

};
