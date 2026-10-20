window.NetworkOpsModules=window.NetworkOpsModules||{};
window.NetworkOpsModules.investigate=function(ctx){
'use strict';
var NOC=ctx.chrome,workspace=ctx;

/* shared IT Command chrome: header, workspace switcher, nav drawer */
var P={
 dev:'<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
 port:'<path d="M6 9V6a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v3"/><path d="M4 9h16v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/><path d="M9 13h.01M12 13h.01M15 13h.01"/>',
 sw:'<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 11h.01M6 13.5h.01"/><path d="M18 12h-5"/>',
 router:'<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01"/><path d="M12 13V8m0 0-2.5 2M12 8l2.5 2"/><path d="M16 8a4 4 0 0 0-8 0"/>',
 shield:'<path d="M12 3 5 6v5c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6z"/>',
 globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18"/>',
 wifi:'<path d="M2 8.5a16 16 0 0 1 20 0M5 12a11 11 0 0 1 14 0M8.5 15.5a6 6 0 0 1 7 0"/><path d="M12 19h.01"/>',
 user:'<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
 heart:'<path d="M3 12h4l2 5 4-10 2 5h6"/>',
 ping:'<circle cx="12" cy="12" r="2.5"/><path d="M7.8 7.8a6 6 0 0 0 0 8.4M4.9 4.9a10 10 0 0 0 0 14.2M16.2 7.8a6 6 0 0 1 0 8.4M19.1 4.9a10 10 0 0 1 0 14.2"/>',
 check:'<path d="m5 12 5 5L20 6"/>', alert:'<path d="M12 3 2 20h20z"/><path d="M12 9v5M12 17.5h.01"/>',
 x:'<path d="M6 6l12 12M18 6 6 18"/>', copy:'<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
 ext:'<path d="M14 4h6v6M20 4l-9 9M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"/>',
 search:'<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>'
};
function ic(k,c){return '<svg class="'+(c||'')+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+(P[k]||'')+'</svg>';}
var esc=function(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});};
var enc=encodeURIComponent;
var IPRE=/^\d{1,3}(\.\d{1,3}){3}$/;
function macHex(q){return q.replace(/[^0-9a-fA-F]/g,'');}
function classify(q){q=q.trim();if(IPRE.test(q))return'ip';if(macHex(q).length===12&&/^[0-9a-fA-F.:-]+$/.test(q))return'mac';return'id';}
var TL={ip:'IP address',mac:'MAC address',id:'user / device'};
async function jget(u){return ctx.json(u);}
function apn(m){return (m&&(m.apName||m.recentDeviceName))||'';}
// user360 nests identity per source (ad / entra / okta); flatten it for the cards
function personOf(i){if(!i)return null;var a=i.ad||{},en=i.entra||{},ok=i.okta||{};
  var p={displayName:i.displayName||a.displayName||en.display_name||ok.displayName||'',
    email:i.email||a.email||en.mail||ok.email||'',upn:i.upn||a.upn||en.user_principal_name||ok.login||'',
    department:i.department||a.department||en.department||'',jobTitle:i.jobTitle||i.title||a.title||en.job_title||'',
    manager:i.manager||a.manager||''};
  return (p.displayName||p.email||p.upn)?p:null;}
function seen(t){var d=t?new Date(t):null;return d&&!isNaN(d)?d.toLocaleString([], {month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}):'';}
function fwSite(n){if(!n)return null;
  if(n.indexOf('SNA01')===0)return{site:'SNA01 · Irvine',fw:'Irvine FortiGate',host:'10.20.6.4'};
  if(n.indexOf('DFW02')===0)return{site:'DFW02 · Plano TX',fw:'Plano FortiGate',host:'10.19.6.4'};return null;}
function dur(s){if(s==null)return'—';var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return d?d+'d '+h+'h':(h?h+'h '+m+'m':m+'m');}
function tAgo(ts){if(!ts)return'';var d=new Date(ts),f=Math.round((Date.now()-d)/60000);
  if(f<1)return'now';if(f<60)return f+'m ago';if(f<1440)return Math.round(f/60)+'h ago';return d.toLocaleDateString();}

NOC.act('<button class="nbtn" id="ot-go">Trace</button>');
var out=document.getElementById('ot-out'), qin=document.getElementById('nQ'),
    tchip=document.getElementById('ot-tchip'), qList=document.getElementById('ot-qList');

var RK='dtrace.recent';
function recents(){try{var r=JSON.parse(localStorage.getItem(RK)||'[]');return Array.isArray(r)?r.filter(x=>typeof x==='string').slice(0,6):[];}catch(e){return[];}}
function saveR(r){try{localStorage.setItem(RK,JSON.stringify(r));}catch(e){}}
function pushR(q){var r=recents().filter(function(x){return x!==q;});r.unshift(q);saveR(r.slice(0,6));}
function delR(q){saveR(recents().filter(function(x){return x!==q;}));drawHint();}
/* the left queue owns recents now — same store, same delR(); drawHint()
   just paints into #ot-qList instead of the old strip under the search box. */
var QI={ip:'globe',mac:'port',id:'user'};
var EXAMPLES=['10.20.21.51','14:50:51:69:43:6a'];
var CURAS='',CURQ=null;                 // the term showing in the pane, marked in the list
function drawHint(){
  var t=qin.value.trim();
  if(t){tchip.hidden=false;tchip.textContent=TL[classify(t)];}else tchip.hidden=true;
  if(!qList)return;
  var a=document.activeElement,                       // keep the keyboard's place
      fq=(a&&qList.contains(a)&&a.dataset)?(a.dataset.q||null):null;
  var r=recents();
  var rn=document.getElementById('ot-recN');
  if(rn){rn.textContent=r.length||'none';rn.className='sev'+(r.length?' info':'');}
  var h = r.length
    ? r.map(function(x){
        return '<div class="qrowx"><button class="nrow" data-q="'+esc(x)+'" aria-current="'+(CURQ===x)+'">'+
          '<span class="ic">'+ic(QI[classify(x)])+'</span><span class="bd">'+
          '<span class="t">'+esc(x)+'</span><span class="s">'+esc(TL[classify(x)])+'</span></span></button>'+
          '<button class="qx" data-del="'+esc(x)+'" title="Remove from recent" aria-label="Remove '+
          esc(x)+' from recent">'+ic('x')+'</button></div>';}).join('')
    : '<div class="nempty">'+ic('search')+'<b>Nothing traced yet</b>Try '+
      EXAMPLES.map(function(x){return '<button class="qex" data-q="'+esc(x)+
        '" aria-label="Trace '+esc(x)+'">'+esc(x)+'</button>';}).join(' or ')+'.</div>';
  qList.innerHTML=h;
  if(fq)[].slice.call(qList.querySelectorAll('[data-q]')).forEach(function(b){
    if(b.dataset.q===fq)b.focus();});
}
qList.addEventListener('click',function(e){
  var d=e.target.closest('[data-del]'); if(d){e.stopPropagation();delR(d.dataset.del);return;}
  var r=e.target.closest('[data-q]'); if(r){window.NetworkOps.trace(r.dataset.q);}});
/* arrow keys walk the list, same as network-health */
qList.addEventListener('keydown',function(e){
  if(e.key!=='ArrowDown'&&e.key!=='ArrowUp')return;
  var rows=[].slice.call(qList.querySelectorAll('.nrow'));
  var at=rows.indexOf(document.activeElement); if(at<0)return;
  e.preventDefault();
  var nxt=rows[at+(e.key==='ArrowDown'?1:-1)]; if(nxt){nxt.focus();nxt.click();}});
qin.addEventListener('input',drawHint);

document.getElementById('ot-go').addEventListener('click',function(){window.NetworkOps.trace(qin.value);});
out.addEventListener('keydown',function(e){
  if(e.key!=='Enter'&&e.key!==' ')return;
  var t=e.target.closest('[role="button"]'); if(!t)return;
  e.preventDefault(); t.click();});
out.addEventListener('click',async function(e){
  var b=e.target.closest('[data-copy]'); if(!b)return;
  try{await navigator.clipboard.writeText(b.dataset.copy);b.classList.add('ok');b.innerHTML=ic('check');
    setTimeout(function(){b.classList.remove('ok');b.innerHTML=ic('copy');},1100);}catch(_){}});

function card(t,i,tg,body,foot){return '<section class="u-card u-fade"><header>'+ic(i,'ci')+'<h2>'+t+'</h2>'+
  (tg?'<span class="tag">'+tg+'</span>':'')+'</header>'+body+(foot||'')+'</section>';}
function tag(c,t){return '<span class="u-tag '+c+'">'+t+'</span>';}
function kv(k,v){return (v||v===0)?'<div class="u-kv"><span class="k">'+k+'</span><span class="v">'+v+'</span></div>':'';}
function cp(v){return '<button class="cp" data-copy="'+esc(v)+'" title="Copy">'+ic('copy')+'</button>';}
function n(v,badAt){if(v==null)return'—';var c=(badAt&&v>=badAt)?'txt-bad':(v>0?'txt-warn':'txt-good');
  return '<span class="'+c+'">'+Number(v).toLocaleString()+'</span>';}

var RUNSEQ=0;
// The shared sidebar footer ships a literal “connecting…” that only
// NOC.stamp() clears. This page traces on demand instead of polling, so
// without these calls it claims a pending connection on every load, forever.
function traceStamp(q,err){
  if(err)NOC.stamp('trace failed \u00b7 '+q,true);
  else NOC.stamp('traced '+q,false);
}
function run(){
  var q=qin.value.trim(); if(!q){qin.focus();return;}
  qin.removeAttribute('aria-invalid');
  if(IPRE.test(q)&&!q.split('.').every(n=>Number(n)<=255)){qin.setAttribute('aria-invalid','true');document.getElementById('ot-traceMessage').textContent='Enter a valid IPv4 address (each part must be 0–255).';qin.focus();return;}
  document.getElementById('ot-traceMessage').textContent='';
  ctx.beginTrace(q,'');ROAM.mac=null;ROAM.data=null;++roamRequest;CURAS='';
  var seq=++RUNSEQ; rStop();
  CURQ=q; pushR(q); drawHint();
  ctx.filters({q:q,as:''});
  var kind=classify(q);
  out.innerHTML='<section class="u-card"><div class="u-skel" style="margin:16px;width:55%;height:20px"></div>'+
    '<div class="u-skel" style="margin:0 16px 16px;width:75%"></div></section>';
  NOC.stamp('tracing '+q+'\u2026',false);
  (kind==='id'?runId(q,seq):runNet(q,kind,{seq:seq})).then(function(){
    if(seq===RUNSEQ)traceStamp(q,null);
  }).catch(function(e){
    if(seq!==RUNSEQ)return;
    traceStamp(q,e);
    var m=(e.code===401)?'Your session expired. <a href="/login.html">Sign in</a> to keep tracing.':esc(e.message);
    out.innerHTML='<div class="u-note bad">'+ic('alert')+'<div><b>Couldn’t complete the trace.</b><br>'+m+'</div></div>';});
}

function verdict(loc,mer){
  var r=loc.reachability,e=loc.edge,h=e&&e.health,wl=mer&&mer.found;
  var nm=(loc.hostname&&loc.hostname.split('.')[0])||loc.ip||loc.mac||'Device';
  if(r&&r.device&&r.device.present===false&&!wl)return{l:'bad',t:nm+' is not responding',
    d:'Nothing answers for <b>'+esc(loc.ip||'')+'</b> — no ping, no TCP, and nothing seen on the network recently.'};
  if(h&&h.oper&&h.oper!=='up')return wl
    ?{l:'bad',t:'The uplink behind '+nm+'’s access point is down',
      d:'<b>'+esc(apn(mer)||'Its access point')+'</b> hangs off port <b>'+esc(e.port)+'</b> on '+esc(e.switch)+', which reports <b>'+esc(h.oper)+'</b> (admin '+esc(h.admin)+'). The laptop is fine — the AP’s cable run is the problem.'}
    :{l:'bad',t:nm+'’s switch port is down',
      d:'Port <b>'+esc(e.port)+'</b> on '+esc(e.switch)+' reports <b>'+esc(h.oper)+'</b> (admin '+esc(h.admin)+').'};
  if(wl&&mer.status&&mer.status!=='Online'){
    var ls=seen(mer.lastSeen), where=(mer.ssid?' on <b>'+esc(mer.ssid)+'</b>':'')+(apn(mer)?' via '+esc(apn(mer)):'');
    var rd=r&&r.device;
    if(rd&&rd.present!==false&&(rd.icmp||rd.evidence))return{l:'good',t:nm+(rd.icmp?' is online':' is on the network'),
      d:(rd.icmp?'It answers on <b>'+esc(loc.ip||mer.ip||'')+'</b> ('+rd.rtt_ms+' ms)':'It was seen on the network ('+esc(rd.evidence)+')')+
        '. Meraki lists it as <b>'+esc(mer.status)+'</b> on Wi-Fi'+(ls?' (last seen '+ls+where+')':'')+', so it may be wired or between Wi-Fi sessions.'};
    return{l:'warn',t:nm+' was last seen on Wi-Fi',
      d:'Meraki lists it as <b>'+esc(mer.status)+'</b>'+(ls?'; last seen '+ls:'')+where+'.'};}
  var pIss=[],oIss=[];
  if(h){if(h.in_err>0)pIss.push(h.in_err.toLocaleString()+' input errors');
        if(h.out_err>0)pIss.push(h.out_err.toLocaleString()+' output errors');
        if(h.crc>0)pIss.push(h.crc.toLocaleString()+' CRC errors');
        if(h.duplex==='half')pIss.push('a half-duplex mismatch');}
  if(r&&r.gateway&&!r.gateway.alive)oIss.push('an unreachable gateway');
  var rssi=wl&&mer.signalQuality&&mer.signalQuality.rssi;
  if(rssi!=null&&rssi<-72)oIss.push('a weak Wi-Fi signal ('+rssi+' dBm)');
  if(pIss.length||oIss.length){
    function j(a){return a.length>1?a.slice(0,-1).join(', ')+' and '+a.slice(-1):a[0];}
    var src=wl?'its access point’s uplink ('+esc((e&&e.switch)||'')+' '+esc((e&&e.port)||'')+') is showing '
              :'its switch port is showing ';
    var d=pIss.length?('Reachable, but '+src+j(pIss)+(oIss.length?' — plus '+j(oIss):'')+'.')
                     :('Reachable, but showing '+j(oIss)+'.');
    return{l:'warn',t:nm+' is online, with issues',d:d};}
  if(wl)return{l:'good',t:nm+' is online over Wi-Fi',
    d:'Connected to <b>'+esc(mer.ssid)+'</b> on '+esc(apn(mer)||'an access point')+(rssi!=null?' at <b>'+rssi+' dBm</b>':'')+'.'};
  if(e&&h)return{l:'good',t:nm+' is online',
    d:'Wired to <b>'+esc(e.switch)+' '+esc(e.port)+'</b>'+(e.vlan!=null?' on VLAN '+e.vlan:'')+
      ' — link up'+(h.speed_mbps?' at '+h.speed_mbps+' Mbps':'')+
      (h.duplex?', '+esc(h.duplex)+' duplex':'')+', no errors.'};
  // u = unmeasured. Amber headline (worth attention), but nothing about this
  // device's experience was actually sampled -- see the path node below.
  if(loc.error)return{l:'warn',u:true,t:nm+' could not be traced',d:esc(loc.error)+'.'};
  return{l:'info',t:nm+' located',d:'Resolved, but not currently in a switch CAM table or on Wi-Fi.'};
}

/* shared-fault alert: is this one device, or is something common broken? */
function corrAlert(c){
  if(!c||!c.verdict)return '';
  var v=c.verdict, imp=(c.switch_issues||[]).filter(function(x){return (x.devices||[]).length;});
  var peers=imp.slice(0,6).map(function(x){
    var who=(x.devices||[]).map(function(d){return d.ip||d.mac;}).filter(Boolean).slice(0,3).join(', ');
    return '<div class="u-row"><span class="u-dot '+(x.severity==='critical'?'bad':'warn')+'"></span>'+
      '<div class="main"><div class="t u-mono">'+esc(x.port)+' <span style="font-family:var(--u-font)">'+esc(x.descr||'')+'</span></div>'+
      '<div class="s">'+esc((x.diag&&x.diag.title)||x.kind||'')+(who?' · '+esc(who):'')+'</div></div></div>';}).join('');
  var sp=(c.same_port||[]).length;
  return '<div class="u-note '+(v.severity==='critical'?'bad':'warn')+'" style="margin-bottom:14px;display:block">'+
    '<div style="display:flex;gap:11px;align-items:flex-start">'+ic('alert')+
    '<div><b>'+esc(v.title)+'</b><br><span class="txt-2">'+esc(v.detail)+'</span>'+
    (sp?'<br><span class="txt-2">'+sp+' other device'+(sp>1?'s share':' shares')+' this exact port.</span>':'')+
    '</div></div>'+
    (peers?'<div style="margin-top:11px;border-top:1px solid var(--u-hair)">'+peers+'</div>':'')+
    '</div>';
}

function pathHtml(loc,mer,fwi,xp){
  var e=loc.edge,h=e&&e.health,r=loc.reachability,wl=mer&&mer.found;
  var dev=r&&r.device,gw=r&&r.gateway,N=[];
  N.push({role:'Device',val:(loc.hostname&&loc.hostname.split('.')[0])||loc.ip||loc.mac||'Device',
    sub:dev?(dev.icmp?dev.rtt_ms+' ms':(dev.present!==false?(dev.evidence||'seen on network'):'no response')):'',
    st:dev?(dev.present!==false?'':'bad'):''});
  if(wl){
    var rs=mer.signalQuality&&mer.signalQuality.rssi;
    N.push({role:'Wireless',val:apn(mer)||'Access point',
      sub:(rs!=null?rs+' dBm \u00b7 ':'')+(mer.ssid||''),st:(rs!=null&&rs<-72)?'warn':''});
  }
  if(e){
    var iss=[]; if(h){if(h.crc>0)iss.push(h.crc.toLocaleString()+' CRC');
      if(h.in_err>0)iss.push(h.in_err.toLocaleString()+' in-err');
      if(h.out_err>0)iss.push(h.out_err.toLocaleString()+' out-err');}
    N.push({role:wl?'AP uplink':'Access port',val:e.port,
      sub:e.switch+(iss.length?' \u00b7 '+iss.join(' \u00b7 '):''),
      st:h?(h.oper!=='up'?'bad':(iss.length?'warn':'')):''});
  } else if(!wl){
    N.push({role:'Access port',val:'not in CAM',sub:'',st:'dim'});
  }
  var up=(loc.locations||[]).filter(function(x){return x.role==='uplink';})[0];
  N.push({role:'Core',val:up?up.switch:'distribution',sub:up?(up.port+' \u00b7 trunk'):'',st:''});
  N.push({role:'Gateway',val:gw?gw.ip:(e?'VLAN '+e.vlan:'\u2014'),
    sub:gw?(gw.alive?gw.rtt_ms+' ms':'no reply'):'',st:gw?(gw.alive?'':'bad'):''});
  N.push({role:'Firewall',val:fwi?fwi.fw.split(' ')[0]:'Firewall',sub:fwi?fwi.host:'',st:''});
  if(xp) N.push({role:'Experience',val:xp.label||'This device',sub:xp.sub||'',
    st:xp.level==='bad'?'bad':(xp.level==='warn'?'warn':'')});
  return '<section class="u-card u-fade"><header>'+ic('ping','ci')+'<h2>Connectivity path</h2></header>'+
    '<div class="pathcard"><div class="path">'+
    N.map(function(x){return '<div class="pnode '+(x.st||'')+'">'+
      '<div class="role">'+esc(x.role)+'</div><div class="val">'+esc(x.val)+'</div>'+
      (x.sub?'<div class="sub">'+esc(x.sub)+'</div>':'')+'</div>';}).join('')+
    '</div></div></section>';
}

/* ── signal field renderer: the pretty heat map ─────────────────────────
   A continuous RF-style field instead of blobs: every pixel takes the
   strongest AP's gaussian falloff, colored on the classic survey ramp
   (blue weak → cyan → green → yellow → orange → red strong).            */
var HEAT_STOPS=[            // t, r,g,b, alpha
  [0.00,  59,130,246, 0.00],
  [0.10,  59,130,246, 0.16],
  [0.26,   6,182,212, 0.26],
  [0.44,  34,197, 94, 0.34],
  [0.62, 250,204, 21, 0.42],
  [0.80, 249,115, 22, 0.46],
  [0.93, 239, 68, 68, 0.52],
  [1.00, 254,202,202, 0.58]];
function heatColor(t){
  for(var k=1;k<HEAT_STOPS.length;k++){
    if(t<=HEAT_STOPS[k][0]){
      var a=HEAT_STOPS[k-1],c=HEAT_STOPS[k],f=(t-a[0])/(c[0]-a[0]||1);
      return [a[1]+(c[1]-a[1])*f, a[2]+(c[2]-a[2])*f, a[3]+(c[3]-a[3])*f, a[4]+(c[4]-a[4])*f];
    }}
  var e=HEAT_STOPS[HEAT_STOPS.length-1]; return [e[1],e[2],e[3],e[4]];
}
function renderHeatCanvas(el, aps, used){
  var cv=el.querySelector('.heatc'); if(!cv||!aps||!aps.length) return;
  var W=300,H=225; cv.width=W; cv.height=H;
  var ctx=cv.getContext('2d'), img=ctx.createImageData(W,H), px=img.data;
  var pts=aps.map(function(a){return {x:a.x,y:a.y,s:used[a.name]?0.14:0.10,boost:used[a.name]?1.0:0.8};});
  for(var y=0;y<H;y++){
    var ny=(y+0.5)/H;
    for(var x=0;x<W;x++){
      var nx=(x+0.5)/W, best=0, second=0;
      for(var i=0;i<pts.length;i++){
        var p=pts[i], dx=nx-p.x, dy=ny-p.y;
        var v=p.boost*Math.exp(-(dx*dx+dy*dy)/(2*p.s*p.s));
        if(v>best){second=best;best=v;} else if(v>second){second=v;}
      }
      var t=Math.min(1, best+second*0.28);
      if(t<0.045) continue;
      var c=heatColor(t), o=(y*W+x)*4;
      px[o]=c[0]; px[o+1]=c[1]; px[o+2]=c[2]; px[o+3]=Math.round(c[3]*255);
    }
  }
  ctx.putImageData(img,0,0);
}

/* ── playback: walk the path and show what the client saw at each hop ── */
/* Replay recorded AP associations. Travel between APs is illustrative, not a measured walking path. */
var RPLAY={frame:null,i:0,loop:false,stops:[],el:null,playing:false,phase:'dwell',elapsed:0,progress:0,position:null,speed:1};
var rSpriteOk=true; // The inline vector avatar has no image or network dependency.
var replayMotion=window.matchMedia('(prefers-reduced-motion: reduce)');
function rPerson(){return '<ellipse class="rp-shadow" cx="18" cy="49" rx="9" ry="2"/>'+
 '<g class="rp-person"><g class="rp-leg rp-leg-back"><path d="M16 30 L13 40 L10 47"/><path class="rp-shoe" d="M10 47h-3"/></g>'+
 '<g class="rp-leg rp-leg-front"><path d="M20 30 L23 39 L23 47"/><path class="rp-shoe" d="M23 47h4"/></g>'+
 '<path class="rp-arm-back" d="M12 19 L7 27 L11 31"/>'+
 '<path class="rp-shirt" d="M12 17 Q18 13 24 17 L26 30 Q18 34 10 30Z"/>'+
 '<circle class="rp-head" cx="18" cy="9" r="6"/><path class="rp-hair" d="M12 9 Q10 1 18 2 Q25 2 24 8 L21 5 Q16 8 12 6Z"/>'+
 '<path class="rp-arm-front" d="M24 19 L28 26 L24 30"/>'+
 '<g class="rp-laptop" transform="rotate(-8 27 28)"><rect x="21" y="23" width="12" height="8" rx="1.5"/><path d="M20 32h14"/></g></g>';}
function rAvatar(){return '<svg class="rperson-svg" viewBox="0 0 36 52" aria-hidden="true">'+rPerson()+'</svg>';}
function rIcon(playing){
 var b=RPLAY.el&&RPLAY.el.querySelector('#ot-rPlayBtn');if(b){b.setAttribute('aria-pressed',String(!!playing));b.setAttribute('aria-label',playing?'Pause replay':'Play replay');}
 return playing?'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 5h4v14H6zM14 5h4v14h-4z"/></svg>':'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>';
}
function rWalking(on){if(!RPLAY.el)return;RPLAY.el.querySelectorAll('#rWalker,.r-person').forEach(function(w){w.classList.toggle('walking',!!on&&!replayMotion.matches);});}
function rStop(){
 if(RPLAY.frame!=null)cancelAnimationFrame(RPLAY.frame);RPLAY.frame=null;RPLAY.playing=false;rWalking(false);
 var b=RPLAY.el&&RPLAY.el.querySelector('#ot-rPlayBtn');if(b)b.innerHTML=rIcon(false);
}
function rBindPlayback(stops,el){
 rStop();RPLAY.stops=stops;RPLAY.el=el;RPLAY.i=0;RPLAY.speed=speedGet();RPLAY.phase='dwell';RPLAY.elapsed=0;RPLAY.progress=0;RPLAY.position=stops[0]||null;
 var btn=el.querySelector('#ot-rPlayBtn'),scrub=el.querySelector('#ot-rScrub'),loopBtn=el.querySelector('#ot-rLoopBtn'),prev=el.querySelector('#ot-rPrev'),next=el.querySelector('#ot-rNext'),position=el.querySelector('#ot-rPosition');
 if(!btn||!scrub)return;var follow=el.querySelector('#ot-rFollow');if(follow)follow.disabled=replayMotion.matches;btn.disabled=stops.length<2;loopBtn.disabled=stops.length<2;loopBtn.setAttribute('aria-pressed',String(RPLAY.loop));
 var speed=el.querySelector('#ot-rSpd');
 function applySpeed(){speed.querySelectorAll('button').forEach(function(b){b.setAttribute('aria-pressed',String(+b.dataset.spd===RPLAY.speed));});el.querySelector('.rmap').style.setProperty('--r-gait',(0.5/RPLAY.speed)+'s');}
 speed.innerHTML=[[0.25,'¼×'],[0.5,'½×'],[1,'1×'],[2,'2×']].map(function(v){return '<button data-spd="'+v[0]+'" aria-label="Playback speed '+v[1]+'">'+v[1]+'</button>';}).join('');
 speed.querySelectorAll('button').forEach(function(b){b.onclick=function(){RPLAY.speed=+b.dataset.spd;speedSet(RPLAY.speed);applySpeed();};});applySpeed();
 var svg=el.querySelector('.rmap .rstage > svg'),walker=document.createElementNS('http://www.w3.org/2000/svg','g');walker.id='rWalker';walker.setAttribute('aria-hidden','true');walker.innerHTML='<g class="r-facing"><g transform="scale(.14)"><g transform="translate(-18 -49)">'+rPerson()+'</g></g></g>';svg.appendChild(walker);
 function drawPoint(p,moving){
  RPLAY.position=p;walker.style.transform='translate('+(p.x*100)+'px,'+(p.y*100)+'px)';
  var movingTo=stops[Math.min(RPLAY.i+1,stops.length-1)],facing=moving&&movingTo.x<p.x?-1:1;
  if(moving){walker.querySelector('.r-facing').setAttribute('transform','scale('+facing+' 1)');var person=el.querySelector('.r-person');if(person)person.classList.toggle('facing-left',facing<0);}
  ['.rtravel3','.rtravel-shadow'].forEach(function(sel){var node=el.querySelector(sel);if(node)node.style.transform='translate3d('+(p.x*100)+'%,'+(p.y*100)+'%,0)';});
  var stage=el.querySelector('.rmap.r3d .rstage');if(stage)stage.style.transform=!replayMotion.matches&&followOn()&&RPLAY.playing?stageFollow(p.x,p.y):stageBase();
  rWalking(moving);
  var trail=svg.querySelector('.leg');if(trail){var points=stops.slice(0,RPLAY.i+1);if(moving)points=points.concat([p]);trail.setAttribute('points',points.map(function(q){return(q.x*100)+','+(q.y*100);}).join(' '));}
 }
 function showStop(){
  var p=stops[RPLAY.i];if(!p)return;scrub.value=String(RPLAY.i);scrub.setAttribute('aria-valuetext','Stop '+(RPLAY.i+1)+' of '+stops.length+', '+p.ap+', '+String(p.at).slice(11,16));position.textContent=(RPLAY.i+1)+' / '+stops.length;prev.disabled=RPLAY.i===0;next.disabled=RPLAY.i===stops.length-1;
  el.querySelector('#ot-rNowT').textContent=String(p.at).slice(11,16);
  var seconds=p.at&&p.until?Math.max(0,Math.round((new Date(p.until)-new Date(p.at))/1000)):0,dwell=seconds>=3600?Math.round(seconds/3600)+'h':seconds>=60?Math.round(seconds/60)+'m':seconds?seconds+'s':'—',bad=/poor|low ack|fail|deauth|timeout/i.test(p.reason||'');
  el.querySelector('#ot-rNow').innerHTML='<div><div class="l">Access point</div><div class="v">'+esc(p.ap)+'</div></div><div><div class="l">Band</div><div class="v">'+(p.band?esc(p.band)+' GHz':'—')+'</div></div><div><div class="l">Dwell</div><div class="v">'+dwell+'</div></div><div><div class="l">Associations</div><div class="v">'+(p.events||1)+'</div></div>'+(p.reason?'<div style="grid-column:1/-1"><div class="l">Last event</div><div class="v '+(bad?'txt-warn':'')+'">'+esc(p.reason)+'</div></div>':'');
  el.querySelectorAll('.rtag').forEach(function(tag){tag.classList.toggle('alert',bad&&tag.dataset.ap===p.ap);tag.classList.toggle('current',tag.dataset.ap===p.ap);});
  var call=el.querySelector('.rcall');call.classList.toggle('on',bad);if(bad)call.innerHTML='<b>'+ic('alert')+'Handoff issue</b><div>'+esc(p.ap)+'</div><div>'+esc(p.reason||'')+'</div>';
 }
 function jump(i){rStop();RPLAY.i=Math.max(0,Math.min(stops.length-1,i));RPLAY.phase='dwell';RPLAY.progress=0;RPLAY.elapsed=0;drawPoint(stops[RPLAY.i],false);showStop();}
 scrub.oninput=function(){jump(+scrub.value);};prev.onclick=function(){jump(RPLAY.i-1);};next.onclick=function(){jump(RPLAY.i+1);};loopBtn.onclick=function(){RPLAY.loop=!RPLAY.loop;loopBtn.setAttribute('aria-pressed',String(RPLAY.loop));};
 var last=null;
 function tick(now){
  if(!RPLAY.playing)return;var dt=last==null?0:Math.max(0,now-last);last=now;RPLAY.elapsed+=dt*RPLAY.speed;
  if(RPLAY.phase==='dwell'){
   var bad=/poor|low ack|fail|deauth|timeout/i.test(stops[RPLAY.i].reason||''),hold=bad?2400:700;
   if(RPLAY.elapsed>=hold){
    if(RPLAY.i>=stops.length-1){if(!RPLAY.loop){rStop();return;}jump(0);RPLAY.playing=true;btn.innerHTML=rIcon(true);last=now;}
    else{RPLAY.phase='travel';RPLAY.elapsed=0;}
   }
  }else{
   var progress=replayMotion.matches?1:Math.min(1,RPLAY.elapsed/240),a=stops[RPLAY.i],b=stops[RPLAY.i+1];RPLAY.progress=progress;drawPoint({x:a.x+(b.x-a.x)*progress,y:a.y+(b.y-a.y)*progress},progress<1);
   if(progress>=1){RPLAY.i++;RPLAY.phase='dwell';RPLAY.elapsed=0;RPLAY.progress=0;drawPoint(stops[RPLAY.i],false);showStop();}
  }
  if(RPLAY.playing)RPLAY.frame=requestAnimationFrame(tick);
 }
 btn.onclick=function(){if(RPLAY.playing){rStop();return;}if(RPLAY.i===stops.length-1)jump(0);RPLAY.playing=true;last=null;btn.innerHTML=rIcon(true);RPLAY.frame=requestAnimationFrame(tick);};
 jump(0);
}
document.addEventListener('visibilitychange',function(){if(document.hidden)rStop();});
replayMotion.addEventListener('change',function(){rStop();if(RPLAY.el){var follow=RPLAY.el.querySelector('#ot-rFollow');if(follow)follow.disabled=replayMotion.matches;}});

/* ── Wi-Fi travel map: where this client went, AP to AP ───────────────── */
var ROAM={hours:Math.min(ctx.state().range,168), floor:null, data:null, heat:true},roamRequest=0;
/* per-floor rotation, quarter-turns counter-clockwise; the diagonal HQ floors
   read far better turned 90° left, so they default to 1 */
var SKINS={g_591097451092378945:'/floorskin-g_591097451092378945.webp'};
function skinOn(){try{return localStorage.getItem('dtrace.mapskin')!=='0';}catch(e){return true;}}
function skinSet(v){try{localStorage.setItem('dtrace.mapskin',v?'1':'0');}catch(e){}}
function map3dOn(){try{return localStorage.getItem('dtrace.map3d')!=='0';}catch(e){return true;}}
function map3dSet(v){try{localStorage.setItem('dtrace.map3d',v?'1':'0');}catch(e){}}
function followOn(){try{return localStorage.getItem('dtrace.mapfollow')!=='0';}catch(e){return true;}}
function followSet(v){try{localStorage.setItem('dtrace.mapfollow',v?'1':'0');}catch(e){}}
var R3D_TILT=55, R3D_ZOOM=1.75, R3D_SCALE=1.12;
function speedGet(){try{var v=parseFloat(localStorage.getItem('dtrace.mapspeed'));
  return [.25,.5,1,2].includes(v)?v:1;}catch(e){return 1;}}
function speedSet(v){try{localStorage.setItem('dtrace.mapspeed',String(v));}catch(e){}}
function stageBase(){return 'translateY(-50%) rotateX('+R3D_TILT+'deg) scale('+R3D_SCALE+')';}
function stageFollow(px,py){return 'translateY(-50%) rotateX('+R3D_TILT+'deg) scale('+R3D_ZOOM+
  ') translate('+((0.5-px)*100).toFixed(2)+'%,'+((0.65-py)*100).toFixed(2)+'%)';}
function openPoster(){
  var dark=true;
  try{var t=document.documentElement.getAttribute('data-theme');
    dark=t?(t==='dark'):window.matchMedia('(prefers-color-scheme: dark)').matches;}catch(e){}
  var b=document.createElement('figure'); b.className='artbox';
  b.innerHTML='<img src="'+(dark?'/wifi-poster-dark.webp':'/wifi-poster-light.webp')+'" alt="Illustrated Wi-Fi heat map of the HQ first floor">'+
    '<figcaption>HQ 1st floor, as art — the live map above is the truth. Click anywhere to close.</figcaption>';
  function close_(){b.remove();document.removeEventListener('keydown',onKey);}
  function onKey(e){if(e.key==='Escape')close_();}
  b.addEventListener('click',close_); document.addEventListener('keydown',onKey);
  ctx.root.appendChild(b);
}
var ROT_DEFAULT={g_591097451092378945:1, g_591097451092378946:1};
function rotGet(fid){
  try{var o=JSON.parse(localStorage.getItem('dtrace.maprot')||'{}');
      return (fid in o)?o[fid]:(ROT_DEFAULT[fid]||0);}catch(e){return ROT_DEFAULT[fid]||0;}
}
function rotSet(fid,n){
  try{var o=JSON.parse(localStorage.getItem('dtrace.maprot')||'{}');o[fid]=((n%4)+4)%4;
      localStorage.setItem('dtrace.maprot',JSON.stringify(o));}catch(e){}
}
function rotPt(x,y,n){ for(var i=0;i<n;i++){var t=x; x=y; y=1-t;} return {x:x,y:y}; }
async function roamMap(mac, mountId){
  rStop();ROAM.mac=mac;var request=++roamRequest,runToken=RUNSEQ;
  var el=document.getElementById(mountId); if(!el) return;
  el.innerHTML='<section class="u-card"><header>'+ic('wifi','ci')+'<h2>Travel map</h2></header>'+
    '<div class="u-skel" style="margin:16px;height:180px"></div></section>';
  try{
    var d=await jget('/api/netswitch/roam?mac='+enc(mac)+'&hours='+ROAM.hours);
    if(request!==roamRequest||runToken!==RUNSEQ)return;
    ROAM.data=d;
    if(!d.ok||!d.path||!d.path.length){
      el.innerHTML='<section class="u-card"><header>'+ic('wifi','ci')+'<h2>Travel map</h2></header>'+
        '<div class="u-empty">No access-point history for this client in the last '+ROAM.hours+'h.'+
        (d.unplaced&&d.unplaced.length?'<br><span class="txt-3">APs not placed on a floor plan: '+esc(d.unplaced.join(', '))+'</span>':'')+
        '</div></section>'; return;}
    // group the path by floor; default to the floor with the most stops
    var byFloor={};
    d.path.forEach(function(p){ (byFloor[p.floorPlanId]=byFloor[p.floorPlanId]||[]).push(p); });
    var floors=Object.keys(byFloor).sort(function(a,b){return byFloor[b].length-byFloor[a].length;});
    if(!ROAM.floor||!byFloor[ROAM.floor]) ROAM.floor=floors[0];
    var fp0=(d.floorplans||[]).filter(function(f){return f.floorPlanId===ROAM.floor;})[0]||{aps:[]};
    var rotN=rotGet(ROAM.floor);
    var fp={aps:(fp0.aps||[]).map(function(a){var r=rotPt(a.x,a.y,rotN);
      return {name:a.name,serial:a.serial,x:r.x,y:r.y};})};
    var stops=(byFloor[ROAM.floor]||[]).map(function(p){var r=rotPt(p.x,p.y,rotN);
      var q={}; for(var k in p) q[k]=p[k]; q.x=r.x; q.y=r.y; return q;});
    var used={}; stops.forEach(function(p){used[p.ap]=1;});

    // full route drawn faint; playback lights it up progressively. No time labels
    // on the plan itself — dozens of them were unreadable; time lives in the scrubber.
    var pts=stops.map(function(p){return (p.x*100).toFixed(2)+','+(p.y*100).toFixed(2);}).join(' ');
    var svg='<svg viewBox="0 0 100 100" preserveAspectRatio="none">'+
      '<defs>'+
        '<radialGradient id="ot-rgUsed"><stop offset="0%" stop-color="#f5c84c" stop-opacity=".55"/>'+
          '<stop offset="45%" stop-color="#7ed957" stop-opacity=".35"/>'+
          '<stop offset="100%" stop-color="#2bb3a3" stop-opacity="0"/></radialGradient>'+
        '<radialGradient id="ot-rgIdle"><stop offset="0%" stop-color="#7ed957" stop-opacity=".30"/>'+
          '<stop offset="55%" stop-color="#2bb3a3" stop-opacity=".18"/>'+
          '<stop offset="100%" stop-color="#2bb3a3" stop-opacity="0"/></radialGradient>'+
      '</defs>'+
      '';
    (fp.aps||[]).forEach(function(a){
      var u=!!used[a.name], short=a.name.replace(/^SNA01-|^DFW02-/,'');
      svg+='<circle class="apdot'+(u?' used':'')+'" cx="'+(a.x*100).toFixed(2)+'" cy="'+(a.y*100).toFixed(2)+'" r="'+(u?1.1:0.8)+'"/>';
      svg+='<text class="aplab'+(u?' used':'')+'" text-anchor="middle" x="'+(a.x*100).toFixed(2)+'" y="'+(a.y*100+2.6).toFixed(2)+'">'+esc(short)+'</text>';
    });
    for(var si=1;si<stops.length;si++){
      var A=stops[si-1],B=stops[si];
      var bd=/deauth|fail|timeout/i.test(B.reason||''), sl=/poor|low ack/i.test(B.reason||'');
      var tc=bd?'var(--u-sig-fault)':(sl?'var(--u-sig-slow)':'var(--u-sig-clean)');
      var tw=(0.45+Math.min(B.events||1,4)*0.22).toFixed(2);
      svg+='<line class="trail" x1="'+(A.x*100).toFixed(2)+'" y1="'+(A.y*100).toFixed(2)+
        '" x2="'+(B.x*100).toFixed(2)+'" y2="'+(B.y*100).toFixed(2)+'" stroke="'+tc+
        '" stroke-width="'+tw+'" stroke-dasharray="1.7 1.5" stroke-linecap="round"/>'+
        '<circle class="bead" cx="'+((A.x+B.x)*50).toFixed(2)+'" cy="'+((A.y+B.y)*50).toFixed(2)+'" r="0.5"/>';
    }
    svg+='<polyline class="leg" points=""/>';
    // one marker per distinct AP visit (not per event) — sized by dwell count
    var seen={};
    stops.forEach(function(p,i){
      var k=p.ap, first=(i===0), last=(i===stops.length-1);
      if(seen[k]&&!first&&!last) return; seen[k]=1;
      var cls=first?'first':(last?'last':'');
      svg+='<circle class="stop '+cls+'" cx="'+(p.x*100).toFixed(2)+'" cy="'+(p.y*100).toFixed(2)+'" r="'+(first||last?1.5:1.0)+'"/>';
    });
    svg+='</svg>';

    var trouble={}; stops.forEach(function(p){
      if(/poor|low ack|fail|deauth|timeout/i.test(p.reason||'')) trouble[p.ap]=1;});
    var tags3=fp.aps.map(function(a){
      return '<div class="rtag'+(used[a.name]?' used':'')+(trouble[a.name]?' warn':'')+
        '" data-ap="'+esc(a.name)+'" style="left:'+(a.x*100).toFixed(2)+
        '%;top:'+(a.y*100).toFixed(2)+'%">'+(trouble[a.name]?'&#9888; ':'')+
        esc(String(a.name).replace(/^[A-Z]{3}\d+-/,''))+'</div>';}).join('');
    var floorBtns=floors.map(function(f){
      var nm=((d.floorplans||[]).filter(function(x){return x.floorPlanId===f;})[0]||{}).name||f;
      return '<button data-floor="'+esc(f)+'" aria-pressed="'+(f===ROAM.floor)+'">'+esc(nm)+' <span class="txt-3">'+byFloor[f].length+'</span></button>';}).join('');
    var hourBtns=[[24,'1d'],[48,'2d'],[72,'3d'],[168,'7d']].map(function(x){
      return '<button data-rh="'+x[0]+'" aria-pressed="'+(ROAM.hours===x[0])+'">'+x[1]+'</button>';}).join('');

    el.innerHTML='<section class="u-card u-fade"><header>'+ic('wifi','ci')+'<h2>Travel map</h2>'+
      '<span class="tag">'+tag('', d.hops+' hops · '+d.event_count+' events')+'</span></header>'+
      '<div class="rbar"><div class="u-seg">'+floorBtns+'</div><div class="u-seg">'+hourBtns+'</div>'+
      '<button class="u-btn" id="ot-rHeat" aria-pressed="'+(ROAM.heat!==false)+'">Coverage</button>'+
      '<button class="u-btn" id="ot-rRot" title="Rotate the plan 90° left">⟲ Rotate</button>'+
      (SKINS[ROAM.floor]?'<button class="u-btn" id="ot-rSkin" aria-pressed="'+skinOn()+'" title="Illustrated floor instead of the CAD plan">Styled floor</button>':'')+
      '<button class="u-btn" id="ot-r3d" aria-pressed="'+map3dOn()+'" title="Tilted diorama view">3D</button>'+
      '<button class="u-btn" id="ot-rFollow" aria-pressed="'+followOn()+'" title="Camera follows the walker during playback"'+(map3dOn()?'':' style="display:none"')+'>Follow</button>'+
      '<button class="u-btn" id="ot-rArt" title="The office as art — just for fun">✨ Poster</button></div>'+
      '<div class="rmap roam-replay'+(map3dOn()?' r3d':'')+(map3dOn()&&!rSpriteOk?' nospr':'')+'"><div class="rstage"><img id="ot-rFloorImg" alt="" ><canvas class="heatc"'+(ROAM.heat===false?' style="display:none"':'')+'></canvas>'+svg+
      '<div class="rtravel-shadow"><span></span></div><div class="rtravel3"><div class="r-person">'+rAvatar()+'</div></div>'+tags3+'<div class="rping"></div></div><div class="rcall"></div></div>'+
      '<div class="rplay">'+
        '<button class="pb" id="ot-rPlayBtn" aria-label="Play replay" aria-pressed="false">'+
          '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></button>'+
        '<button class="pb" id="ot-rPrev" aria-label="Previous access-point event">‹</button><button class="pb" id="ot-rNext" aria-label="Next access-point event">›</button><span class="now" id="ot-rPosition"></span><input type="range" id="ot-rScrub" min="0" max="'+Math.max(0,stops.length-1)+'" value="0" step="1" aria-label="Travel replay position">'+
        '<span class="now" id="ot-rNowT"></span>'+
        '<button class="pb" id="ot-rLoopBtn" aria-label="Loop playback" aria-pressed="'+(RPLAY.loop?'true':'false')+'" title="Loop playback">'+
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 2l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 22l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg></button>'+
      '<span class="rspd" id="ot-rSpd" role="group" aria-label="Playback speed"></span>'+
      '</div><div class="rnow" id="ot-rNow"></div>'+
      '<div class="rlegend"><span class="heatscale" title="signal: weak to strong"></span>'+
      '<span><i style="background:var(--u-sig-clean)"></i>clean handoff</span>'+
      '<span><i style="background:var(--u-sig-slow)"></i>slow roam</span>'+
      '<span><i style="background:var(--u-sig-fault)"></i>drop / deauth</span>'+
      '<span class="txt-3">AP associations · route is illustrative, not a measured walking path</span></div>'+
      '</section>';
    // the plan image needs the auth token, which only fetch() carries — load it as a blob
    (async function(){
      try{
        var useSkin=SKINS[ROAM.floor]&&skinOn();
        var ir=await fetch(useSkin?SKINS[ROAM.floor]:('/api/netswitch/floorplan-image?id='+enc(ROAM.floor)),{credentials:'include'});
        if(!ir.ok) return;
        var bl=await ir.blob();
        var bmp=await createImageBitmap(bl);
        if(request!==roamRequest||runToken!==RUNSEQ){bmp.close();return;}
        var w=bmp.width,h=bmp.height,cw=w,ch=h;
        if(rotN%2===1){cw=h;ch=w;}
        var oc=document.createElement('canvas'); oc.width=cw; oc.height=ch;
        var octx=oc.getContext('2d');
        octx.translate(cw/2,ch/2); octx.rotate(-Math.PI/2*rotN);  // CCW
        octx.drawImage(bmp,-w/2,-h/2);bmp.close();
        var im=el.querySelector('#ot-rFloorImg'), box=el.querySelector('.rmap'),
            stg=el.querySelector('.rstage'), is3=box&&box.classList.contains('r3d');
        if(im){im.src=oc.toDataURL('image/png'); if(useSkin) im.classList.add('skin');}
        if(box){box.style.aspectRatio=cw+' / '+(is3?Math.round(ch*0.62):ch);
          box.style.maxWidth='min('+Math.round((is3?680:560)*cw/ch)+'px, calc(100% - 28px))';}
        if(stg&&is3){
          stg.style.top='50%'; stg.style.height='auto'; stg.style.aspectRatio=cw+' / '+ch;
          if(!stg.style.transform) stg.style.transform=stageBase();}
      }catch(e){}
    })();
    renderHeatCanvas(el, fp.aps||[], used);
    var rb=el.querySelector('#ot-rRot');
    if(rb) rb.addEventListener('click',function(){rotSet(ROAM.floor,rotGet(ROAM.floor)+1);rStop();roamMap(mac,mountId);});
    var hb=el.querySelector('#ot-rHeat');
    if(hb) hb.addEventListener('click',function(){
      ROAM.heat=(ROAM.heat===false); hb.setAttribute('aria-pressed',ROAM.heat!==false);
      var g=el.querySelector('.rmap .heatc'); if(g) g.style.display=(ROAM.heat===false)?'none':'';});
    var sb=el.querySelector('#ot-rSkin');
    if(sb) sb.addEventListener('click',function(){skinSet(!skinOn());rStop();roamMap(mac,mountId);});
    var ab=el.querySelector('#ot-rArt');
    if(ab) ab.addEventListener('click',openPoster);
    var db=el.querySelector('#ot-r3d');
    if(db) db.addEventListener('click',function(){map3dSet(!map3dOn());rStop();roamMap(mac,mountId);});
    var fb=el.querySelector('#ot-rFollow');
    if(fb) fb.addEventListener('click',function(){followSet(!followOn());
      fb.setAttribute('aria-pressed',followOn());
      var sg=el.querySelector('.rmap.r3d .rstage');
      if(sg) sg.style.transform=!replayMotion.matches&&followOn()&&RPLAY.position
        ?stageFollow(RPLAY.position.x,RPLAY.position.y):stageBase();});
    el.querySelectorAll('[data-floor]').forEach(function(btn){
      btn.addEventListener('click',function(){ROAM.floor=btn.dataset.floor;rStop();roamMap(mac,mountId);});});
    el.querySelectorAll('[data-rh]').forEach(function(btn){
      btn.addEventListener('click',function(){ROAM.floor=null;ctx.navigate({range:Number(btn.dataset.rh)});});});
    rBindPlayback(stops, el);
  }catch(e){
    if(request!==roamRequest||runToken!==RUNSEQ)return;
    el.innerHTML='<section class="u-card"><div class="u-note bad" style="margin:14px">'+ic('alert')+
      '<div>Travel map unavailable: '+esc(e.message)+'</div></div></section>';
  }
}

async function runNet(q,kind,ctx){
  ctx=ctx||{};
  var loc=ctx.loc||await jget('/api/netswitch/locate?q='+enc(q));
  var ip=loc.ip||(kind==='ip'?q:null), mac=loc.mac||(kind==='mac'?q:null), host=loc.hostname||null;
  var pr=await Promise.all([
    ip?jget('/api/netdiag/resolve?by=ip&q='+enc(ip)).catch(function(){return{ok:false};}):Promise.resolve(null),
    mac?jget('/api/meraki/client?mac='+enc(mac)).catch(function(){return null;}):Promise.resolve(null),
    (mac||ip)?jget('/api/netswitch/correlate?'+(mac?'mac='+enc(mac):'ip='+enc(ip))).catch(function(){return null;}):Promise.resolve(null)]);
  var resolve=pr[0], mer=pr[1], corr=pr[2], wifi=null;
  if(mer&&mer.found&&mac){try{wifi=await jget('/api/meraki/wifi-events?mac='+enc(mac)+'&hours=24');}catch(e){}}
  var person=personOf(resolve&&resolve.user360&&resolve.user360.identity), owner=null;
  if(!person&&host){try{var u=await jget('/api/user360/'+enc(host.split('.')[0]));
    if(u&&u.ok!==false)person=personOf(u.identity);}catch(e){}}
  if(ctx.asset&&ctx.asset.user_name&&ctx.asset.user_name!=='--')owner={name:ctx.asset.user_name,src:String(ctx.asset.src||'inventory').replace(/^./,function(c){return c.toUpperCase();})};
  if(!person&&owner){try{var uo=await jget('/api/user360/'+enc(owner.name));
    if(uo&&uo.ok!==false){person=personOf(uo.identity);if(person)person.via=owner.src;}}catch(e){}}

  var e=loc.edge,h=e&&e.health,fwS=resolve&&resolve.network,dhcp=resolve&&resolve.dhcp;
  var wl=mer&&mer.found, ipD=ip||(wl&&mer.ip)||mac;
  var site=(e&&e.switch)||(wl&&apn(mer))||'', fwi=fwSite(site);
  var v=verdict(loc,mer), r=loc.reachability&&loc.reachability.device;
  var vic={good:'check',warn:'alert',bad:'x',info:'search'}[v.l];

  // pin target: MAC is the stable key, fall back to IP
  var wref = mac || ip;
  var wlabel = (ctx.asset&&ctx.asset.device_name) || ctx.searched ||
               (host&&!/^ip-\d/.test(host)?host.split('.')[0]:'') || wref;
  if(ctx.asset&&ctx.asset.user_name&&ctx.asset.user_name!=='--') wlabel += ' · '+ctx.asset.user_name;
  var facts=[];
  if(ipD)facts.push('<span class="fact">'+ic('dev')+esc(ipD)+cp(ipD)+'</span>');
  if(mac)facts.push('<span class="fact">'+ic('port')+esc(mac)+cp(mac)+'</span>');
  if(host)facts.push('<span class="fact">'+ic('globe')+esc(host)+cp(host)+'</span>');

  var resolvedNote='';
  if(ctx.searched&&ctx.asset){
    resolvedNote='<div class="d" style="margin-top:6px;color:var(--u-text-3)">Resolved <b>'+esc(ctx.searched)+
      '</b> via '+esc(ctx.asset.src||'inventory')+(ctx.asset.user_name&&ctx.asset.user_name!=='--'?' · '+esc(ctx.asset.user_name):'')+'</div>';
  }
  var html='<div class="verdict '+v.l+' u-fade"><div class="vi">'+ic(vic)+'</div><div class="vm">'+
    '<h2>'+esc(v.t)+'</h2><div class="d">'+v.d+'</div>'+resolvedNote+
    (facts.length?'<div class="facts">'+facts.join('')+'</div>':'')+
    (wref?'<div style="margin-top:12px"><button class="u-btn" id="ot-watchBtn" data-ref="'+esc(wref)+'" data-label="'+esc(wlabel)+'">'+
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'+
      '<path d="M12 17v5"/><path d="M9 10.8V4h6v6.8l2 3.2H7z"/></svg>Watch this device</button>'+
      '<span class="txt-3" style="font-size:11.5px;margin-left:9px">samples every 5 min · kept 120 days</span></div>':'')+
    '</div>'+
    (r?'<div class="live"><span class="u-dot '+(r.present!==false?'':'bad')+'"></span>'+
       (r.icmp?'live · '+r.rtt_ms+' ms':(r.present!==false?esc(r.evidence||'on the network'):'no response'))+'</div>':'')+
    '</div>'+corrAlert(corr)+pathHtml(loc,mer,fwi,{label:(person&&(person.displayName||person.name))||(host?host.split('.')[0]:null)||ipD,sub:(v.u?'not measured':({good:'healthy',warn:'issues found',bad:'impacted',info:'no live data'}[v.l]||'—')),level:(v.u?'info':v.l)})+'<div class="split" style="margin-top:14px"><div class="stack">';

  /* main column */
  if(wl){
    var rssi=mer.signalQuality&&mer.signalQuality.rssi, snr=mer.signalQuality&&mer.signalQuality.snr;
    var q5=rssi==null?0:rssi>=-60?5:rssi>=-67?4:rssi>=-72?3:rssi>=-80?2:1;
    var sc=q5>=4?'':(q5===3?'w':'b');
    var bars=[10,16,22,27,32].map(function(hh,i){return '<i class="'+(i<q5?'on '+sc:'')+'" style="height:'+hh+'px"></i>';}).join('');
    html+=card('Wireless','wifi',tag(mer.status==='Online'?'good':'',esc(mer.status||'—')),
      '<div class="sig"><div class="bars">'+bars+'</div><div><div class="v '+(sc==='b'?'txt-bad':(sc==='w'?'txt-warn':'txt-good'))+'">'+
        (rssi!=null?rssi+' dBm':'—')+'</div><div class="s">signal'+(snr!=null?' · SNR '+snr:'')+' · '+
        (['','very weak','weak','fair','good','excellent'][q5]||'')+'</div></div></div>'+
      (mer.status!=='Online'?kv('Last seen',esc(seen(mer.lastSeen))):'')+kv('SSID',esc(mer.ssid))+kv('Access point',esc(apn(mer)))+kv('Site',esc(mer.site||site))+
      kv('Manufacturer',esc(mer.manufacturer))+kv('Meraki IP',mer.ip?esc(mer.ip)+cp(mer.ip):''));
    if(wifi&&wifi.found&&wifi.events&&wifi.events.length){
      var bad=wifi.events.filter(function(x){return /poor|low ack|fail/i.test(x.reason||'');}).length;
      html+=card('Wi-Fi connection history','ping',tag(bad?'warn':'',(wifi.eventCount||wifi.events.length)+' · 24h'),
        '<div>'+wifi.events.slice(0,7).map(function(x){
          var dc=x.type==='disconnect', b=/poor|low ack|fail|deauth|timeout|roam/i.test(x.reason||'');
          return '<div class="ev '+(dc?(b?'bad':'dc'):'cn')+'"><span class="d"></span><div class="b">'+
            '<div class="r1"><span class="u-tag '+(dc?'warn':'good')+'">'+esc(x.type)+'</span>'+esc(x.ap||'')+
            (x.band?' · '+esc(x.band)+' GHz':'')+'</div>'+
            (x.reason||x.details?'<div class="r2 '+(b?'bad':'')+'">'+esc(x.reason||x.details)+'</div>':'')+
            '</div><span class="t">'+esc(tAgo(x.timestamp))+'</span></div>';}).join('')+'</div>');
    }
  }
  if(e&&h){
    var util=h.util_pct!=null?h.util_pct:0;
    var st=h.oper!=='up'?tag('bad','link '+esc(h.oper)):((h.in_err>0||h.out_err>0||h.crc>0)?tag('warn','errors'):tag('good','Healthy'));
    html+=card(wl?'AP uplink port':'Switch port health','heart',st,
      kv('Link','<span class="'+(h.oper==='up'?'txt-good':'txt-bad')+'">'+esc(h.oper)+'</span> · admin '+esc(h.admin))+
      kv('Speed / duplex',(h.speed_mbps?h.speed_mbps+' Mbps':'—')+' · <span class="'+(h.duplex==='half'?'txt-warn':'')+'">'+esc(h.duplex||'—')+'</span>')+
      kv('Throughput',h.in_mbps!=null?'<span class="u-mono">&darr; '+h.in_mbps+' &nbsp; &uarr; '+h.out_mbps+'</span> <span class="txt-3">Mbps</span>':'')+
      (h.util_pct!=null?'<div class="u-kv"><span class="k">Utilization</span><span class="v" style="display:flex;align-items:center;gap:9px">'+
        '<span class="u-meter" style="flex:1;max-width:150px"><i style="width:'+Math.min(util,100)+'%"></i></span><span class="u-mono">'+util+'%</span></span></div>':'')+
      kv('Input errors','<span class="u-mono">'+n(h.in_err,100)+'</span>')+
      kv('Output errors','<span class="u-mono">'+n(h.out_err,100)+'</span>')+
      kv('CRC / FCS','<span class="u-mono">'+n(h.crc,1)+'</span>')+
      kv('Discards in / out','<span class="u-mono">'+Number(h.in_disc||0).toLocaleString()+' / <span class="'+(h.out_disc>100000?'txt-warn':'')+'">'+Number(h.out_disc||0).toLocaleString()+'</span></span>')+
      (h.poe_status?kv('PoE',esc(h.poe_status)+(h.poe_watts?' · '+h.poe_watts+' W':'')):'')+
      kv('Link up for',dur(h.last_change_sec)));
  }
  if(e){
    var others=(loc.locations||[]).filter(function(x){return x!==e;});
    html+=card('Switch attachment','sw',tag('',esc(e.switch)),
      kv('Edge switch',esc(e.switch))+
      kv('Port','<span class="u-mono">'+esc(e.port)+'</span> '+tag('good','Edge'))+
      kv('Description',esc(e.port_desc||'—'))+kv('VLAN','<span class="u-mono">'+esc(e.vlan)+'</span>')+
      kv('Switch IP','<span class="u-mono">'+esc(e.switch_ip)+'</span>'+cp(e.switch_ip))+
      (wl?kv('','<span class="txt-3">This port is the AP uplink — the device connects over Wi-Fi.</span>'):'')+
      (others.length?'<div class="u-kv"><span class="k">Uplink path</span><span class="v" style="padding:0"><div class="u-tw"><table class="u-table"><tbody>'+
        others.map(function(x){return '<tr><td>'+esc(x.switch)+'</td><td class="u-mono">'+esc(x.port)+'</td><td>VLAN '+x.vlan+'</td><td>'+tag('info',x.role)+'</td></tr>';}).join('')+
        '</tbody></table></div></span></div>':''));
  }else if(!wl){
    html+=card('Switch attachment','sw',tag('','—'),
      '<div class="u-empty">'+(loc.error?esc(loc.error):'Not found in any switch CAM table — the device may be offline.')+'</div>');
  }

  html+='</div><div class="stack">';
  /* rail */
  if(loc.reachability){var d=loc.reachability.device,g=loc.reachability.gateway;
    html+=card('Reachability','ping',
      tag(d&&d.present!==false?(d.alive?'good':'warn'):'bad',
          d&&d.present!==false?(d.alive?'live':'quiet'):'no response'),
      kv('Device',d?('<span class="'+(d.present!==false?'txt-good':'txt-bad')+'">'+
        (d.present!==false?'on the network':'not responding')+'</span>'+
        (d.evidence?' · '+esc(d.evidence):'')):'—')+
      kv('Ping',d?(d.icmp?'<span class="txt-good">replies</span>'+(d.rtt_ms!=null?' · '+d.rtt_ms+' ms':''):
        '<span class="txt-3">no reply — most endpoints block ICMP, so this alone is not a fault</span>'):'')+
      (g?kv('Gateway','<span class="u-mono">'+esc(g.ip)+'</span> — <span class="'+(g.alive?'txt-good':'txt-bad')+'">'+(g.alive?'reachable':'no reply')+'</span>'+(g.rtt_ms!=null?' · '+g.rtt_ms+' ms':'')):''));}
  var fwB,fwT;
  if(fwS){fwT=tag('good','live session');
    fwB=kv('Action','<span class="u-mono">'+esc(fwS.action||'')+'</span>')+kv('Policy',esc(fwS.policyName||fwS.policyid||''))+
        kv('Destination','<span class="u-mono">'+esc(fwS.daddr||'')+'</span>')+kv('Service','<span class="u-mono">'+esc(fwS.service||fwS.proto||'')+'</span>')+
        kv('Firewall',esc(fwS.fw||(fwi&&fwi.fw)||''));}
  else if(fwi){fwT=tag('','by site');
    fwB=kv('Serving firewall',esc(fwi.fw))+kv('Management','<span class="u-mono">'+esc(fwi.host)+'</span>'+cp(fwi.host))+kv('Site',esc(fwi.site))+
        '<div class="u-kv"><span class="v"><a href="/network-health.html#fw">Firewall vitals '+ic('ext')+'</a></span></div>';}
  else{fwT=null;fwB='<div class="u-empty">No firewall context.</div>';}
  html+=card('Firewall path','shield',fwT,fwB);
  var idB,idT;
  if(person){idT=tag('good','matched');
    idB=(person.via?kv('Matched by',esc(person.via)+' assigned user'):'')+kv('Name',esc(person.displayName||person.name||''))+
        kv('Email',(person.email||person.upn)?'<span class="u-mono">'+esc(person.email||person.upn)+'</span>'+cp(person.email||person.upn):'')+
        kv('Department',esc(person.department||''))+kv('Title',esc(person.jobTitle||person.title||''));}
  else if(owner){idT=tag('','from '+esc(owner.src));
    idB=kv('Assigned user',esc(owner.name))+kv('Source',esc(owner.src))+
        '<div class="u-empty">No directory account matched this name.</div>';}
  else{idT=host?tag('','host only'):null;
    idB=(host?kv('Hostname','<span class="u-mono">'+esc(host)+'</span>'+cp(host))+kv('Resolved by','reverse DNS (PTR)'):'')+
        (dhcp&&dhcp.hostname?kv('DHCP host','<span class="u-mono">'+esc(dhcp.hostname)+'</span>'):'')+
        '<div class="u-empty">'+(host?'No person is linked to this host in identity.':'No identity resolved.')+'</div>';}
  html+=card('Identity','user',idT,idB);
  html+='</div></div>';
  if(mac) html+='<div id="ot-roamMount" style="margin-top:14px"></div>';
  if(ctx.seq&&ctx.seq!==RUNSEQ)return;
  out.innerHTML=html;
  workspace.evidence({query:q,ip:ip,mac:mac,edge:e,person:person,site:site,seq:workspace.state().q});
  if(mac) roamMap(mac,'ot-roamMount');
  var wb=document.getElementById('ot-watchBtn');
  if(wb) wb.addEventListener('click',async function(){
    if(wb.dataset.done){workspace.navigate({view:'overview',section:'watch'});return;}
    wb.disabled=true;
    try{
      var r=await fetch('/api/netswitch/watch',{method:'POST',credentials:'include',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({kind:'device',ref:wb.dataset.ref,label:wb.dataset.label,
                             meta:{hostname:host||null,ip:ip||null,site:site||null}})});
      var j=await r.json().catch(function(){return{ok:false};});
      if(!r.ok||!j.ok) throw new Error(j.detail||'could not pin');
      wb.classList.add('pri');
      wb.innerHTML='Watching — see the Watch list';
      wb.disabled=false;
      wb.dataset.done='1';workspace.watchChanged();
    }catch(e){ wb.disabled=false; wb.innerHTML='Could not watch: '+esc(e.message); }
  });
}

async function runId(q,seq){
  var u=null;
  try{ u=await jget('/api/user360/'+enc(q)); }catch(e){ u=null; }
  // user360 can answer ok:true with an EMPTY identity for serials/device names —
  // only treat it as a person when there is actually a person in it
  var _real=!!personOf(u&&u.identity);
  var _devs=(u&&u.devices&&(u.devices.devices||u.devices.items||u.devices))||[];
  if(!u||u.ok===false||(!_real&&(!Array.isArray(_devs)||!_devs.length))){
    // not a person — it may still be a device name or serial we hold in inventory
    try{
      var a=await jget('/api/netswitch/resolve-asset?q='+enc(q));
      if(a&&a.best) return resolveAndTrace(q,seq);
    }catch(e){}
    // in no inventory — printers, copiers and other domain gear exist only in DNS.
    // locate resolves a bare name through the DNS suffixes; trace it when it resolves.
    var dnsTried=/^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/.test(q), dnsFailed=false;
    if(dnsTried){
      var dl=null;
      try{ dl=await jget('/api/netswitch/locate?q='+enc(q)); }catch(e){ if(e&&e.code===401)throw e; dl=null;
        dnsFailed=!!(e&&(e.name==='TypeError'||/took too long|Request failed/i.test(e.message||''))); }
      if(seq&&seq!==RUNSEQ)return;
      if(dl&&dl.ip) return runNet(q,'host',{searched:q,seq:seq,loc:dl});
    }
    if(seq&&seq!==RUNSEQ)return;
    out.innerHTML='<div class="u-note">'+ic('search')+'<div><b>No match for “'+esc(q)+'”.</b><br>'+
      '<span class="txt-2">Checked identity, Kandji, Intune'+(!dnsTried?' (not a DNS name, so DNS was not checked)':dnsFailed?'; the DNS lookup did not finish, so try again':' and DNS')+' — nothing matches. Try an IP, MAC, username, email, device name or serial.</span></div></div>';return;}
  var p=personOf(u.identity)||{}, dv=(u.devices&&(u.devices.devices||u.devices.items||u.devices))||[];
  var list=Array.isArray(dv)?dv:[];
  var nm=p.displayName||p.name||q;
  var html='<div class="verdict info u-fade"><div class="vi">'+ic('user')+'</div><div class="vm"><h2>'+esc(nm)+'</h2>'+
    '<div class="d">'+(list.length?'Found <b>'+list.length+'</b> managed device'+(list.length>1?'s':'')+'. Search a device’s <b>IP</b> or <b>MAC</b> to trace its live path.':'No managed devices on record.')+'</div>'+
    ((p.email||p.upn)?'<div class="facts"><span class="fact">'+ic('user')+esc(p.email||p.upn)+cp(p.email||p.upn)+'</span></div>':'')+
    '</div></div><div class="split"><div class="stack">';
  html+=card('Devices','dev',tag('',String(list.length)),
    list.length?'<div class="u-list">'+list.map(function(d){
      var nm=d.deviceName||d.name||'';
      return '<div class="u-row'+(nm?' click':'')+'"'+(nm?' data-dev="'+esc(nm)+'" role="button" tabindex="0" aria-label="Trace '+esc(nm)+'"':'')+'>'+
        '<span class="ico">'+ic('dev')+'</span>'+
        '<div class="main"><div class="t">'+esc(nm||'device')+
        ' <span class="txt-3">'+esc(d.os||'')+' '+esc(d.osVersion||'')+'</span></div>'+
        '<div class="s">'+esc(d.model||'')+(d.serial?' · <span class="u-mono">'+esc(d.serial)+'</span>':'')+'</div></div>'+
        (nm?'<div class="side txt-3">trace</div>'+ic('chev','chev'):'')+'</div>';}).join('')+'</div>'
      :'<div class="u-empty">No managed devices found.</div>');
  html+='</div><div class="stack">'+card('Identity','user',tag('good','matched'),
    kv('Name',esc(p.displayName||p.name||''))+kv('Email',(p.email||p.upn)?'<span class="u-mono">'+esc(p.email||p.upn)+'</span>':'')+
    kv('Department',esc(p.department||''))+kv('Title',esc(p.jobTitle||p.title||''))+kv('Manager',esc(p.manager||'')))+
    '</div></div>';
  if(seq&&seq!==RUNSEQ)return;
  out.innerHTML=html;
  out.querySelectorAll('[data-dev]').forEach(function(el){
    el.addEventListener('click',function(){window.NetworkOps.trace(el.dataset.dev,'device');});});
}


/* Resolve anything that is not obviously an IP/MAC into something traceable.
   Order matters: asset inventory knows Macs (which have no DNS record), DNS
   knows domain-joined Windows, and only then do we give up. */
async function resolveAndTrace(name,seq){
  var asset=null;
  try{ asset=await jget('/api/netswitch/resolve-asset?q='+enc(name)); }catch(e){}
  var best=asset&&asset.best;
  if(best&&best.mac_address) return runNet(best.mac_address,'mac',{asset:best,searched:name,seq:seq});
  if(best&&best.ip_address)  return runNet(best.ip_address,'ip',{asset:best,searched:name,seq:seq});
  // no inventory record with a network identity — try DNS by name
  return runNet(name,'host',{asset:best,searched:name,seq:seq});
}
/* trace a device by its inventory name */
function traceDevice(name){
  ctx.beginTrace(name,'device');ROAM.mac=null;ROAM.data=null;++roamRequest;CURAS='device';
  var seq=++RUNSEQ; rStop();
  qin.value=name; CURQ=name; pushR(name); drawHint();
  ctx.filters({q:name,as:'device'});
  out.innerHTML='<section class="u-card"><div class="u-skel" style="margin:16px;width:55%;height:20px"></div>'+
    '<div class="u-skel" style="margin:0 16px 16px;width:75%"></div></section>';
  NOC.stamp('tracing '+name+'\u2026',false);
  resolveAndTrace(name,seq).then(function(){
    if(seq===RUNSEQ)traceStamp(name,null);
  }).catch(function(e){
    if(seq!==RUNSEQ)return;
    traceStamp(name,e);
    var m=(e.code===401)?'Your session expired. <a href="/login.html">Sign in</a>.':esc(e.message);
    out.innerHTML='<div class="u-note bad">'+ic('alert')+'<div><b>Couldn’t trace '+esc(name)+'.</b><br>'+m+'</div></div>';});
}

function intro(){
  out.innerHTML='<div class="intro u-fade"><div><h2>Find any device, see its whole path</h2>'+
    '<p>One lookup ties together the firewall, the switch it plugs into, its Wi-Fi and who owns it — so you can tell in seconds whether a device is on, where it connects, and what’s wrong.</p>'+
    '<div class="caps">'+
      '<div class="cap">'+ic('port')+'<b>Where it plugs in</b><span>The exact switch, port and VLAN — or the Wi-Fi access point and SSID.</span></div>'+
      '<div class="cap">'+ic('heart')+'<b>Live health</b><span>Link speed, errors, PoE, signal, and a live ping to the device and its gateway.</span></div>'+
      '<div class="cap">'+ic('user')+'<b>Who and how it exits</b><span>The owner from identity, and the firewall path out to the internet.</span></div>'+
    '</div></div>'+
    '<figure class="ihero" aria-hidden="true"><img src="/office-hero.webp" alt="" width="1100" height="614" loading="lazy"></figure></div>';
}
document.getElementById('ot-traceClear').onclick=function(){++RUNSEQ;rStop();CURQ=null;qin.value='';qin.removeAttribute('aria-invalid');drawHint();intro();ctx.clearEvidence();ROAM.mac=null;ROAM.data=null;++roamRequest;ctx.filters({q:'',as:'',originSwitch:'',originPort:'',originPortName:'',panel:'',port:'',portName:''});document.getElementById('ot-traceMessage').textContent='Trace cleared. Recent searches are retained.';NOC.stamp('on demand · nothing traced yet',false);qin.focus();};
  document.getElementById('ot-traceCopy').onclick=function(){ctx.copy();};

 drawHint();intro();NOC.stamp('on demand · nothing traced yet',false);
 return {ready:Promise.resolve(),activate:function(st){
   var oldHours=ROAM.hours;ROAM.hours=Math.min(st.range,168);
   if(oldHours!==ROAM.hours&&ROAM.mac&&CURQ===st.q&&!out.querySelector('.u-skel'))roamMap(ROAM.mac,'ot-roamMount');
   if(st.q&&(CURQ!==st.q||CURAS!==st.as||out.querySelector('.u-skel'))){qin.value=st.q;drawHint();if(st.as==='device')traceDevice(st.q);else run();}
   else if(!st.q&&CURQ){++RUNSEQ;rStop();CURQ=null;intro();drawHint();}
 },query:function(){return CURQ;},search:function(q,as){qin.value=q;drawHint();if(as==='device')traceDevice(q);else run();},deactivate:function(){++RUNSEQ;rStop();ctx.root.querySelector('.artbox')?.click();},refresh:function(){if(CURQ){if(ctx.state().as==='device')traceDevice(CURQ);else run();}},capture:function(){return{};}};

};
