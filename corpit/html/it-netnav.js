/* ══════════════════════════════════════════════════════════════════════
   it-netnav.js — shared UniFi-style sidebar for the IT Command network
   pages. Renders into <aside class="u-rail" id="uRail"> and marks the
   current page from document.body.dataset.page.

   Usage:
     <body class="u" data-page="health">
       <div class="u-app">
         <aside class="u-rail" id="uRail"></aside>
         <div class="u-main"> … </div>
       </div>
       <script src="/it-netnav.js"></script>

   Badge counts:  ITNetNav.count('health', 6, true)   // true = red
   ══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  var I = {
    net:   '<path d="M2 15h20v6H2z"/><path d="M6 18h.01M10 18h.01"/><path d="M12 15v-4"/><path d="M8 3h8v8H8z"/>',
    health:'<path d="M3 12h4l2.5 6 4-13L16 12h5"/>',
    switch:'<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 11h.01M6 13.5h.01"/><path d="M18 12h-5"/>',
    trace: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
    shield:'<path d="M12 3 5 6v5c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6z"/>',
    wifi:  '<path d="M2 8.5a16 16 0 0 1 20 0M5 12a11 11 0 0 1 14 0M8.5 15.5a6 6 0 0 1 7 0"/><path d="M12 19h.01"/>',
    home:  '<path d="M3 11 12 4l9 7"/><path d="M5.5 10v10h13V10"/>',
    pin:   '<path d="M12 17v5"/><path d="M9 10.8V4h6v6.8l2 3.2H7z"/>',
    obs:   '<circle cx="12" cy="12" r="2"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>'+
           '<path d="M5.6 5.6 7.8 7.8M16.2 16.2l2.2 2.2M18.4 5.6l-2.2 2.2M7.8 16.2l-2.2 2.2"/>',
    menu:  '<path d="M3 6h18M3 12h18M3 18h18"/>'
  };
  function svg(k) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
           'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (I[k] || '') + '</svg>';
  }

  var NAV = [
    { g: 'Monitor', items: [
      { k: 'obs',      l: 'Observatory',    i: 'obs',    href: '/network-observatory.html' },
      { k: 'health',   l: 'Network Health', i: 'health', href: '/network-health.html' },
      { k: 'switches', l: 'Switches',       i: 'switch', href: '/network-switches.html' },
      { k: 'wifi',     l: 'Wi-Fi',          i: 'wifi',   href: '/network-health.html#wifi' },
      { k: 'firewall', l: 'Firewalls',      i: 'shield', href: '/network-health.html#firewalls' }
    ]},
    { g: 'Troubleshoot', items: [
      { k: 'trace',    l: 'Device Trace',   i: 'trace',  href: '/device-trace.html' },
      { k: 'watch',    l: 'Watch list',     i: 'pin',    href: '/network-health.html#watch' }
    ]}
  ];

  function render() {
    var rail = document.getElementById('uRail');
    if (!rail) return;
    var cur = (document.body.dataset.page || '').toLowerCase();

    var html =
      '<div class="u-brand">' +
        '<span class="mark">' + svg('net') + '</span>' +
        '<span><b>IT Command</b><span>Network</span></span>' +
        '<button class="u-burger" id="uBurger" aria-label="Toggle navigation" aria-expanded="false">' + svg('menu') + '</button>' +
      '</div><nav class="u-nav">';

    NAV.forEach(function (grp) {
      html += '<div class="u-navlabel">' + grp.g + '</div>';
      grp.items.forEach(function (it) {
        html += '<a href="' + it.href + '" data-nav="' + it.k + '"' +
                (it.k === cur ? ' class="on" aria-current="page"' : '') + '>' +
                svg(it.i) + '<span>' + it.l + '</span>' +
                '<span class="n" data-count="' + it.k + '" hidden></span></a>';
      });
    });

    html += '<div class="u-navlabel">Elsewhere</div>' +
            '<a href="/landing.html">' + svg('home') + '<span>Operations Hub</span></a>' +
            '</nav><div class="u-railfoot">Polled from corpit · read-only</div>';

    rail.innerHTML = html;

    var b = document.getElementById('uBurger');
    if (b) b.addEventListener('click', function () {
      var open = rail.classList.toggle('open');
      b.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  /* ── shared detail drawer ──────────────────────────────────────────
     Any list row on any page opens one the same way:
       ITDrawer.open({ icon:'<svg…>', title:'SNA01-WAP09',
                       subtitle:'access point · SNA01', body:'<html>' })
     ITDrawer.loading(...) shows a skeleton while data arrives.        */
  var _d = null, _s = null;
  function build() {
    if (_d) return;
    _s = document.createElement('div'); _s.className = 'u-scrim';
    _d = document.createElement('aside');
    _d.className = 'u-drawer'; _d.setAttribute('role', 'dialog');
    _d.setAttribute('aria-modal', 'true'); _d.setAttribute('aria-hidden', 'true');
    _d.innerHTML = '<header><span class="di" id="uDIcon"></span>' +
      '<span class="dt"><h2 id="uDTitle"></h2><span class="ds" id="uDSub"></span></span>' +
      '<button class="dx" id="uDClose" aria-label="Close">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round">' +
      '<path d="M6 6l12 12M18 6 6 18"/></svg></button></header>' +
      '<div class="dbody" id="uDBody"></div>';
    document.body.appendChild(_s); document.body.appendChild(_d);
    _s.addEventListener('click', close);
    _d.querySelector('#uDClose').addEventListener('click', close);
    document.addEventListener('keydown', function (e) {
      if (!_d.classList.contains('on')) return;
      if (e.key === 'Escape') return close();
      if (e.key !== 'Tab') return;                 // minimal focus trap (aria-modal)
      var f = _d.querySelectorAll('button:not([disabled]),[href],input,select,textarea,[tabindex]:not([tabindex="-1"])');
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1], a = document.activeElement;
      if (!_d.contains(a)) { e.preventDefault(); first.focus(); }
      else if (e.shiftKey && a === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && a === last) { e.preventDefault(); first.focus(); }
    });
  }
  var _ret = null;
  function open(o) {
    build();
    if (!_d.classList.contains('on')) _ret = document.activeElement;
    _d.querySelector('#uDIcon').innerHTML = o.icon || '';
    _d.querySelector('#uDTitle').textContent = o.title || '';
    _d.querySelector('#uDSub').textContent = o.subtitle || '';
    _d.querySelector('#uDBody').innerHTML = o.body || '';
    _d.classList.add('on'); _s.classList.add('on');
    _d.setAttribute('aria-hidden', 'false');
    _d.querySelector('#uDClose').focus();
  }
  function setBody(html) { build(); _d.querySelector('#uDBody').innerHTML = html; }
  function loading(o) {
    open(Object.assign({}, o, { body:
      '<div class="u-skel" style="margin:16px;width:60%"></div>' +
      '<div class="u-skel" style="margin:0 16px 10px;width:80%"></div>' +
      '<div class="u-skel" style="margin:0 16px;width:45%"></div>' }));
  }
  function close() {
    if (!_d) return;
    _d.classList.remove('on'); _s.classList.remove('on');
    _d.setAttribute('aria-hidden', 'true');
    if (_ret && _ret.focus && document.contains(_ret)) { try { _ret.focus(); } catch (_) {} }
    _ret = null;
  }
  var _timer=null;
  function live(fn, secs){                       // re-run fn while the drawer is open
    stopLive();
    _timer=setInterval(function(){
      if(!_d || !_d.classList.contains('on')) return stopLive();
      var b=_d.querySelector('#uDBody');
      if(b && b.contains(document.activeElement)) return; // keyboard user mid-drawer: skip, next tick catches up
      try{ fn(); }catch(_){}
    }, (secs||60)*1000);
  }
  function stopLive(){ if(_timer){ clearInterval(_timer); _timer=null; } }
  var _origClose = close;
  close = function(){ stopLive(); _origClose(); };
  window.ITDrawer = { open: open, close: close, body: setBody, loading: loading,
                      live: live, stopLive: stopLive };


  /* ── shared drill-down ────────────────────────────────────────────
     Identical behaviour on every page/tab:
       ITDrill.switchDetail(ip, name)      switch -> ports -> devices
       ITDrill.portDetail(ip,name,ifx,pt)  port -> devices + history
       ITDrill.apDetail(ap, siteName)      access point -> clients
     Rows that represent a device link through to Device Trace.        */
  var G = {
    dev:'<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    port:'<path d="M6 9V6a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v3"/><path d="M4 9h16v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/>',
    chev:'<path d="M9 6l6 6-6 6"/>', alert:'<path d="M12 3 2 20h20z"/><path d="M12 9v5M12 17.5h.01"/>'
  };
  function g(k,cls){return '<svg class="'+(cls||'')+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">'+(G[k]||I[k]||'')+'</svg>';}
  function E(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function KV(k,v){return (v||v===0)?'<div class="u-kv"><span class="k">'+k+'</span><span class="v">'+v+'</span></div>':'';}
  function when(ts){if(!ts)return'';var m=Math.round((Date.now()/1000-ts)/60);
    if(m<2)return'just now';if(m<60)return m+'m ago';if(m<2880)return Math.round(m/60)+'h ago';
    return new Date(ts*1000).toLocaleDateString();}
  async function J(u){var r=await fetch(u,{credentials:'include'});
    if(r.status===401)throw Object.assign(new Error('Your session expired — sign in again.'),{code:401});
    var j=await r.json().catch(function(){return{ok:false};});
    if(!j||j.ok===false)throw new Error(j&&j.detail||'unavailable');return j;}
  function err(e){ITDrawer.body('<div class="u-note bad" style="margin:16px">'+g('alert')+'<div>'+E(e.message)+'</div></div>');}
  function devRows(list,empty){
    if(!list||!list.length)return '<div class="u-empty">'+(empty||'Nothing connected right now.')+'</div>';
    return '<div class="u-list">'+list.map(function(c){
      var q=c.ip||c.mac;
      return '<div class="u-row click" role="button" tabindex="0" data-trace="'+E(q)+'"><span class="ico">'+g('dev')+'</span>'+
        '<div class="main"><div class="t u-mono">'+E(c.ip||c.mac)+'</div>'+
        '<div class="s u-mono">'+E(c.mac||'')+(c.vlan?' · VLAN '+c.vlan:'')+(c.port?' · '+E(c.port):'')+'</div></div>'+
        '<div class="side">'+E(when(c.last_seen))+'</div>'+g('chev','chev')+'</div>';}).join('')+'</div>';
  }
  function wireTrace(){
    document.querySelectorAll('.u-drawer [data-trace]').forEach(function(el){
      var go=function(ev){ev.stopPropagation();
        location.href='/device-trace.html?q='+encodeURIComponent(el.dataset.trace);};
      el.addEventListener('click',go);
      el.addEventListener('keydown',function(ev){
        if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();go(ev);}});});
  }
  var HRS = 72;
  async function switchDetail(ip,name){
    ITDrawer.loading({icon:g('switch'),title:name,subtitle:ip+' · switch'});
    try{
      var r=await Promise.all([J('/api/netswitch/switch/'+encodeURIComponent(ip)),
                               J('/api/netswitch/clients?switch_ip='+encodeURIComponent(ip))]);
      var d=r[0],dev=d.device||{},ports=d.ports||[],clients=(r[1]&&r[1].clients)||[];
      var up=ports.filter(function(p){return p.oper==='up';}).length;
      var body='<div class="dsec">Switch</div>'+
        KV('Model','<span class="u-mono">'+E(dev.model||'')+'</span>')+
        KV('Serial','<span class="u-mono">'+E(dev.serial||'')+'</span>')+
        KV('IOS-XE','<span class="u-mono">'+E(dev.ios||'')+'</span>')+
        KV('Location',E(dev.location||''))+
        KV('Ports up',up+' of '+ports.length)+
        KV('Devices connected',String(clients.length))+
        '<div class="dsec">Ports</div>';
      body += ports.length ? '<div class="u-list">'+ports.map(function(p){
          var bad=(p.crc>0)||(p.in_err>=50)||(p.out_err>=50);
          return '<div class="u-row click" role="button" tabindex="0" data-ifx="'+E(p.ifindex)+'" data-pt="'+E(p.port)+'">'+
            '<span class="u-dot '+(p.oper==='up'?(bad?'warn':''):'off')+'"></span>'+
            '<div class="main"><div class="t u-mono">'+E(p.port)+
              (p.mac_count?' <span class="u-tag">'+p.mac_count+' device'+(p.mac_count>1?'s':'')+'</span>':'')+
              (bad?' <span class="u-tag warn">errors</span>':'')+'</div>'+
              (p.descr?'<div class="s">'+E(p.descr)+'</div>':'')+'</div>'+
            '<div class="side">'+(p.oper==='up'?(p.speed?p.speed+'M':'up'):E(p.oper||'—'))+'</div>'+
            g('chev','chev')+'</div>';}).join('')+'</div>'
        : '<div class="u-empty">Port detail arrives on the next hourly scan.</div>';
      ITDrawer.body(body);
      document.querySelectorAll('.u-drawer [data-ifx]').forEach(function(el){
        var go=function(){portDetail(ip,name,el.dataset.ifx,el.dataset.pt);};
        el.addEventListener('click',go);
        el.addEventListener('keydown',function(ev){
          if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();go();}});});
    }catch(e){err(e);}
  }
  async function portDetail(ip,name,ifx,pt){
    ITDrawer.loading({icon:g('port'),title:pt,subtitle:name+' · '+ip});
    try{
      var r=await Promise.all([
        J('/api/netswitch/clients?switch_ip='+encodeURIComponent(ip)+'&ifindex='+encodeURIComponent(ifx)),
        J('/api/netswitch/history?switch_ip='+encodeURIComponent(ip)+'&ifindex='+encodeURIComponent(ifx)+'&hours='+HRS),
        J('/api/netswitch/switch/'+encodeURIComponent(ip)).catch(function(){return{ports:[]};})]);
      var clients=(r[0]&&r[0].clients)||[], hist=(r[1]&&r[1].series)||[];
      var pinfo=(r[2]&&r[2].ports||[]).filter(function(x){return String(x.ifindex)===String(ifx);})[0];
      var body=(pinfo&&pinfo.diag?diagBlock(pinfo.diag):'')+
        '<div class="dsec">Connected devices</div>'+devRows(clients,'No devices learned on this port.');
      body+='<div class="dsec">History</div><div style="padding:0 16px 4px"><div class="u-seg" id="uHrs">'+
        [[24,'1d'],[48,'2d'],[72,'3d'],[120,'5d'],[168,'7d'],[720,'30d']].map(function(x){
          return '<button data-h="'+x[0]+'" aria-pressed="'+(HRS===x[0])+'">'+x[1]+'</button>';}).join('')+'</div></div>';
      if(!hist.length) body+='<div class="u-empty">No samples in this window yet — history builds up hourly.</div>';
      else{
        var mx=1; hist.forEach(function(h){mx=Math.max(mx,h.d_crc+h.d_in_err+h.d_out_err);});
        body+='<div style="padding:10px 16px"><div style="display:flex;align-items:flex-end;gap:2px;height:50px">'+
          hist.map(function(h){var v=h.d_crc+h.d_in_err+h.d_out_err;
            var px=Math.max(3,Math.round(v/mx*48));
            var c=v>0?'var(--u-bad)':(h.oper==='up'?'var(--u-good)':'var(--u-surface-3)');
            return '<i title="'+new Date(h.ts*1000).toLocaleString()+' · +'+v+' errors" style="flex:1;min-width:2px;height:'+px+'px;background:'+c+';border-radius:1px"></i>';}).join('')+
          '</div><div style="display:flex;justify-content:space-between;font-size:10px;color:var(--u-muted);margin-top:6px">'+
          '<span>'+E(when(hist[0].ts))+'</span><span>now</span></div>'+
          '<div style="font-size:11.5px;color:var(--u-text-3);margin-top:7px">Each bar is a sample — 15&nbsp;min for the last 7 days, hourly before that. Red means new errors appeared in that window.</div></div>';
      }
      body += window.ITWatch ? ITWatch.pinBtn('port', ip+':'+ifx, pt+' · '+name, {switch:name, port:pt, switch_ip:ip}) : '';
      ITDrawer.body(body); wireTrace(); if(window.ITWatch) ITWatch.wirePins();
      document.querySelectorAll('#uHrs button').forEach(function(b){
        b.addEventListener('click',function(){HRS=+b.dataset.h;portDetail(ip,name,ifx,pt);});});
      // keep it as current as the data allows: re-pull every 60s while open
      ITDrawer.live(function(){ portDetail(ip,name,ifx,pt); }, 60);
    }catch(e){err(e);}
  }
  function apDetail(ap,site){
    ap=ap||{}; var cl=ap.clients||[];
    var on=String(ap.status||'').toLowerCase()==='online';
    var body='<div class="dsec">Access point</div>'+
      KV('Model','<span class="u-mono">'+E(ap.model||'')+'</span>')+
      KV('Serial','<span class="u-mono">'+E(ap.serial||'')+'</span>')+
      KV('Status',on?'<span class="txt-good">Online</span>':'<span class="txt-bad">'+E(ap.status||'offline')+'</span>')+
      KV('LAN IP',ap.lanIp?'<span class="u-mono">'+E(ap.lanIp)+'</span>':'')+
      KV('Site',E(site||''))+KV('Clients',String(cl.length))+
      '<div class="dsec">Connected clients</div>';
    body += cl.length ? '<div class="u-list">'+cl.map(function(c){
        return '<div class="u-row click" role="button" tabindex="0" data-trace="'+E(c.ip||c.mac)+'"><span class="ico">'+g('dev')+'</span>'+
          '<div class="main"><div class="t">'+E(c.description||c.ip||c.mac)+'</div>'+
          '<div class="s u-mono">'+E(c.mac||'')+(c.ip?' · '+E(c.ip):'')+(c.ssid?' · '+E(c.ssid):'')+'</div></div>'+
          '<div class="side">'+E(c.manufacturer||'')+'</div>'+g('chev','chev')+'</div>';}).join('')+'</div>'
      : '<div class="u-empty">No clients on this access point right now.</div>';
    if(ap.serial && window.ITWatch) body += ITWatch.pinBtn('ap', ap.serial, ap.name||ap.serial, {site:site});
    ITDrawer.open({icon:g('wifi'),title:ap.name||ap.serial||'Access point',
      subtitle:(site||'')+' · '+cl.length+' client'+(cl.length===1?'':'s'),body:body});
    wireTrace(); if(window.ITWatch) ITWatch.wirePins();
  }
  function diagBlock(d){
    if(!d) return '';
    var sev=d.severity||'info';
    var ico=(sev==='ok')?'<path d="m5 12 5 5L20 6"/>':'<path d="M12 3 2 20h20z"/><path d="M12 9v5M12 17.5h.01"/>';
    return '<div class="u-diag '+sev+'"><div class="h">'+
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'+ico+'</svg>'+
      E(d.title||'')+(d.confidence?'<span class="cf">'+E(d.confidence)+' confidence</span>':'')+'</div>'+
      (d.cause?'<div class="cause">'+E(d.cause)+'</div>':'')+
      (d.action?'<div class="act"><b>Do this:</b><span>'+E(d.action)+'</span></div>':'')+
      ((d.evidence&&d.evidence.length)?'<div class="ev">'+d.evidence.map(function(x){return '<span>'+E(x)+'</span>';}).join('')+'</div>':'')+
      '</div>';
  }
  window.ITDiag = { block: diagBlock };

  /* ── watch list: pin anything, sample it every 5 minutes, keep 120 days ── */
  var PIN='<path d="M12 17v5"/><path d="M9 10.8V4h6v6.8l2 3.2H7z"/>';
  function pinBtn(kind,ref,label,meta){
    return '<button class="u-btn" data-pin="'+E(kind)+'" data-ref="'+E(ref)+'" data-label="'+E(label||ref)+'"'+
      (meta?" data-meta='"+JSON.stringify(meta).replace(/'/g,"&#39;")+"'":'')+
      ' style="margin:12px 16px">'+
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'+PIN+'</svg>'+
      'Watch this</button>';
  }
  async function pin(kind,ref,label,meta){
    var r=await fetch('/api/netswitch/watch',{method:'POST',credentials:'include',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({kind:kind,ref:ref,label:label,meta:meta||null})});
    var j=await r.json().catch(function(){return{ok:false};});
    if(!j.ok) throw new Error(j.detail||'could not pin');
    return j.item;
  }
  function wirePins(){
    document.querySelectorAll('.u-drawer [data-pin]').forEach(function(el){
      el.addEventListener('click',async function(){
        el.disabled=true;
        try{
          var meta=null; try{meta=el.dataset.meta?JSON.parse(el.dataset.meta):null;}catch(_){}
          await pin(el.dataset.pin,el.dataset.ref,el.dataset.label,meta);
          el.innerHTML='Watching — sampling every 5 min';
          el.classList.add('pri');
        }catch(e){ el.disabled=false; el.innerHTML='Could not pin: '+E(e.message); }
      });});
  }
  window.ITWatch = { pinBtn: pinBtn, pin: pin, wirePins: wirePins };

  window.ITDrill = { switchDetail: switchDetail, portDetail: portDetail, apDetail: apDetail,
                     devRows: devRows, wireTrace: wireTrace,
                     setHours: function(h){HRS=h;}, hours: function(){return HRS;} };

  window.ITNetNav = {
    count: function (key, n, bad) {
      var el = document.querySelector('[data-count="' + key + '"]');
      if (!el) return;
      if (!n) { el.hidden = true; return; }
      el.hidden = false;
      el.textContent = n > 99 ? '99+' : n;
      el.className = 'n' + (bad ? ' bad' : '');
    }
  };

  /* ═══ ITCmd — the shared command-center chrome ══════════════════════
     One call gives every page in the suite an identical header, workspace
     switcher and nav drawer, so the look can never drift page to page.

     The switcher lives IN the header rather than in a separate band or a
     second icon rail: two navigations for four pages is duplicated chrome,
     and on an incident page every pixel above the first row of data is a
     pixel the tech has to scroll past.

     Page contract:
       <body class="u cmd" data-page="health">
       <aside class="u-rail" id="uRail"></aside>
       <div class="owrap">
         <header class="ohead" id="uCmdHead"></header>
         ... .oshell > main.omain
     ITCmd.mount({title, sub, alertTarget}) fills the header and wires it.
     ITCmd.act(html) injects page controls into the header action slot.
     ITCmd.badge(n) sets the count on the header's alert button.          */
  var WORK = [
    { k:'health',   href:'/network-health.html',      l:'Network health', i:'health' },
    { k:'observatory', href:'/network-observatory.html', l:'Live building', i:'obs' },
    { k:'switches', href:'/network-switches.html',    l:'Switch fabric',  i:'switch' },
    { k:'trace',    href:'/device-trace.html',        l:'Device trace',   i:'trace' }
  ];
  var LOGO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="5.5" cy="12" r="2.4"/><circle cx="17.5" cy="5.5" r="2.4"/>' +
    '<circle cx="17.5" cy="18.5" r="2.4"/><path d="M7.7 10.9 15.3 6.6M7.7 13.1l7.6 4.3"/></svg>';
  var ALERT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M12 3.5 2.5 19.5h19z"/><path d="M12 10v4.2M12 17.2h.01"/></svg>';

  function navOpen(o) {
    var rail = document.getElementById('uRail'),
        sc = document.getElementById('oScrim'),
        b = document.getElementById('oMenu');
    if (!rail) return;
    rail.classList.toggle('open', o);
    if (sc) sc.hidden = !o;
    if (b) b.setAttribute('aria-expanded', String(o));
  }

  /* Rows and sortable headers are click-wired by the pages; give them real
     keyboard operation. A <tr> cannot honestly take role="button" (it stays a
     row for assistive tech), so it gets focus + Enter/Space + a label. */
  function keyboardize(root) {
    (root || document).querySelectorAll(
      'tr.rowlink:not([data-kbd]),[data-sw]:not([data-kbd]),thead th[data-k]:not([data-kbd])'
    ).forEach(function (el) {
      el.dataset.kbd = '1';
      if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
      if (el.tagName === 'TH') {
        el.setAttribute('role', 'button');
        if (!el.getAttribute('aria-label'))
          el.setAttribute('aria-label', 'Sort by ' + (el.textContent || '').trim());
      } else if (!el.getAttribute('aria-label')) {
        /* name the row by its first cell, not by every cell run together */
        var cell = el.querySelector('td,.t,.main .t');
        var name = ((cell || el).textContent || '').trim().replace(/\s+/g, ' ').slice(0, 60);
        el.setAttribute('aria-label', 'Open details for ' + name);
      }
    });
  }

  window.ITCmd = {
    mount: function (o) {
      o = o || {};
      var cur = (document.body.dataset.page || '').toLowerCase();
      var head = document.getElementById('uCmdHead');
      if (head) {
        head.innerHTML =
          '<div class="ologo" aria-hidden="true">' + LOGO + '</div>' +
          '<div class="tt"><b>' + (o.title || 'IT Command') + '</b>' +
            '<span>' + (o.sub || '') + '</span></div>' +
          '<div class="sp"></div>' +
          '<div class="hact" id="uCmdAct"></div>' +
          '<button class="oalert" id="oAlert" aria-label="Go to items needing attention">' +
            ALERT + '<span class="bdg" id="railBdg" hidden></span></button>' +
          '<button class="oburger" id="oMenu" aria-label="Open navigation" aria-expanded="false">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
            'stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>' +
          '<nav class="oswitch" aria-label="Network workspaces">' +
            WORK.map(function (w) {
              return '<a href="' + w.href + '"' +
                (w.k === cur ? ' aria-current="page"' : '') + '>' + svg(w.i) +
                '<span>' + w.l + '</span></a>';
            }).join('') +
          '</nav>';
      }
      if (!document.getElementById('oScrim')) {
        var sc = document.createElement('button');
        sc.className = 'oscrim'; sc.id = 'oScrim'; sc.hidden = true;
        sc.setAttribute('aria-label', 'Close menu');
        document.body.appendChild(sc);
        sc.addEventListener('click', function () { navOpen(false); });
      }
      var mb = document.getElementById('oMenu');
      if (mb) mb.addEventListener('click', function () {
        var r = document.getElementById('uRail');
        navOpen(!(r && r.classList.contains('open')));
      });
      document.addEventListener('keydown', function (e) { if (e.key === 'Escape') navOpen(false); });
      var al = document.getElementById('oAlert');
      if (al) al.addEventListener('click', function () {
        var t = document.querySelector(o.alertTarget || '#nowCard, .attn, #colA');
        if (t) t.scrollIntoView({ behavior: 'smooth', block: 'center' });
      });

      /* keyboard-operable rows, kept working as pages re-render */
      var main = document.querySelector('.omain') || document.body;
      keyboardize(main);
      var pending = false;
      new MutationObserver(function () {
        if (pending) return;
        pending = true;
        requestAnimationFrame(function () { pending = false; keyboardize(main); });
      }).observe(main, { childList: true, subtree: true });
      main.addEventListener('keydown', function (e) {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        var el = e.target.closest('tr.rowlink,[data-sw],thead th[data-k]');
        if (!el) return;
        e.preventDefault();
        el.click();
      });
      return this;
    },
    act: function (html) {
      var el = document.getElementById('uCmdAct');
      if (el) el.innerHTML = html;
      return el;
    },
    /* move a page's site banner into the header as a compact chip */
    chip: function (sel) {
      var el = document.querySelector(sel || '#oSite'), act = document.getElementById('uCmdAct');
      if (el && act) act.insertBefore(el, act.firstChild);
      return el;
    },
    badge: function (n) {
      var b = document.getElementById('railBdg');
      if (!b) return;
      if (!n) { b.hidden = true; return; }
      b.hidden = false; b.textContent = n > 99 ? '99+' : n;
    },
    nav: navOpen
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', render);
  else render();
})();
