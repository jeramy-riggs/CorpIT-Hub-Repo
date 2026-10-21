/* it-noc.js — shared chrome for the NOC console.
   Builds the sidebar, top bar and vitals strip so all four pages are the same
   application rather than four pages that look alike, and supplies the small
   chart + table helpers the dashboards need. No dependencies.

   NOC.mount({page,title,sub})   render the shell
   NOC.vitals([{k,v,cls,s}])     the always-visible strip under the top bar
   NOC.badge('health', 6, 'bad') live count on a nav item
   NOC.stamp(text, stale)        freshness line in the sidebar footer
   NOC.act(html)                 extra buttons in the top bar
   NOC.area(el, pts, opts)       filled line chart from real samples
   NOC.sortable(table)           click-to-sort with aria-sort, keyboard included
*/
(function(){
  'use strict';
  var E=function(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});};
  function svg(p,c){return '<svg class="'+(c||'')+'" viewBox="0 0 24 24" fill="none" '+
    'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" '+
    'aria-hidden="true">'+p+'</svg>';}

  var I={
    grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    pulse:'<path d="M3 12h4l2.5 6 4-13L16 12h5"/>',
    switchd:'<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 11h.01M6 13.5h.01M18 12h-5"/>',
    building:'<path d="M3 21h18M5 21V5a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v16M15 21V11h4a2 2 0 0 1 2 2v8"/><path d="M9 7h2M9 11h2M9 15h2"/>',
    search:'<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
    bell:'<path d="M18 8a6 6 0 1 0-12 0c0 7-3 8-3 8h18s-3-1-3-8"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
    refresh:'<path d="M20 12a8 8 0 1 1-2.5-5.8"/><path d="M20 4v4h-4"/>',
    menu:'<path d="M3 6h18M3 12h18M3 18h18"/>',
    logo:'<circle cx="12" cy="12" r="2.4"/><path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8"/>',
    pin:'<path d="M12 21s7-6.3 7-11a7 7 0 1 0-14 0c0 4.7 7 11 7 11Z"/><circle cx="12" cy="10" r="2.5"/>',
    shield:'<path d="M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z"/>',
    wifi:'<path d="M2.5 9a15 15 0 0 1 19 0M6 12.5a10 10 0 0 1 12 0M9.5 16a5 5 0 0 1 5 0"/><circle cx="12" cy="19.5" r="1"/>'
  };

  /* one place that knows the workspaces, so a rename lands everywhere */
  var NAV=[
    {group:'Operations', items:[
      {k:'health', l:'Overview', href:'/network-health.html', i:'grid'}
    ]},
    {group:'Network', items:[
      {k:'fabric', l:'Switches', href:'/network-switches.html', i:'switchd'},
      {k:'building', l:'Live building', href:'/network-observatory.html', i:'building'}
    ]},
    {group:'Investigate', items:[
      {k:'trace', l:'Investigate', href:'/device-trace.html', i:'search'},
      {k:'confreview', l:'Config review', href:'/config-review.html', i:'shield'}
    ]}
  ];

  var MOUNTED=null;

  function mount(o){
    o=o||{}; MOUNTED=o;
    // 'cmd' carries the --o-* palette from it-command.css, 'noc' the console
    // shell. Both are in the markup already; adding them here keeps mount()
    // usable on a page that forgot one.
    document.body.classList.add('cmd','noc');
    var side='<aside class="nside" id="nSide">'+
      '<div class="nbrand"><span class="mk">'+svg(I.logo)+'</span>'+
        '<span><b>CorpIT</b><span>Network operations</span></span></div>'+
      '<nav class="nnav" aria-label="Workspaces">'+
        NAV.map(function(g){
          return '<div class="ngroup">'+E(g.group)+'</div>'+
            g.items.map(function(it){
              return '<a class="nitem" href="'+it.href+'" data-nav="'+it.k+'"'+
                (it.k===o.page?' aria-current="page"':'')+'>'+svg(I[it.i])+
                '<span class="lbl">'+E(it.l)+'</span>'+
                '<span class="n" data-badge="'+it.k+'" hidden></span></a>';
            }).join('');
        }).join('')+
      '</nav>'+
      '<div class="nfoot"><span class="dot" id="nDot"></span><span id="nStamp">connecting…</span></div>'+
    '</aside>';

    var top='<div class="nmain"><header class="ntop">'+
      '<button class="nburger" id="nBurger" aria-label="Open navigation" aria-expanded="false">'+svg(I.menu)+'</button>'+
      '<div class="ncrumb"><h1>'+E(o.title||'')+'</h1>'+
        (o.sub?'<span class="sub">'+E(o.sub)+'</span>':'')+'</div>'+
      '<div class="nsearch">'+svg(I.search)+
        '<input id="nQ" type="search" placeholder="Trace a user, device, IP or MAC…" '+
        'aria-label="Trace a user, device, IP or MAC" autocomplete="off">'+
        '<kbd>/</kbd></div>'+
      '<div class="act" id="nAct"></div>'+
    '</header>'+
    '<div class="nvit" id="nVit" aria-label="Live vitals"></div>'+
    '<main class="nbody" id="nBody"></main></div>';

    var shell=document.createElement('div');
    shell.className='nshell';
    shell.innerHTML=side+top;
    // keep whatever the page already had and move it into the body
    var kept=document.getElementById('nocContent');
    document.body.insertBefore(shell, document.body.firstChild);
    document.body.insertAdjacentHTML('beforeend','<div class="nscrim" id="nScrim"></div>');
    if(kept) document.getElementById('nBody').appendChild(kept);

    // search is a real destination, not decoration: it hands off to Device Trace
    var q=document.getElementById('nQ');
    q.addEventListener('keydown',function(e){
      if(e.key!=='Enter')return;
      var v=q.value.trim(); if(!v)return;
      if(window.NetworkOps)window.NetworkOps.search(v);
    });
    document.addEventListener('keydown',function(e){
      if(e.key!=='/'||e.metaKey||e.ctrlKey||e.altKey)return;
      var t=e.target,tag=(t.tagName||'').toLowerCase();
      if(tag==='input'||tag==='textarea'||t.isContentEditable)return;
      e.preventDefault(); q.focus(); q.select();
    });

    var bg=document.getElementById('nBurger'), sc=document.getElementById('nScrim');
    function nav(open){
      document.body.classList.toggle('nav-open',open);
      bg.setAttribute('aria-expanded',open?'true':'false');
    }
    bg.addEventListener('click',function(){nav(!document.body.classList.contains('nav-open'));});
    sc.addEventListener('click',function(){nav(false);});
    document.addEventListener('keydown',function(e){
      if(e.key==='Escape'&&document.body.classList.contains('nav-open'))nav(false);});
    return document.getElementById('nBody');
  }

  function act(html){var el=document.getElementById('nAct'); if(el)el.innerHTML=html; return el;}

  function vitals(list){
    var el=document.getElementById('nVit'); if(!el)return;
    el.innerHTML=(list||[]).map(function(v){
      return '<div class="nv"><span class="k">'+E(v.k)+'</span>'+
        '<span class="v'+(v.cls?' '+v.cls:'')+'">'+E(v.v)+'</span>'+
        (v.s?'<span class="s">'+E(v.s)+'</span>':'')+'</div>';
    }).join('');
  }

  function badge(key,n,cls){
    var el=document.querySelector('[data-badge="'+key+'"]'); if(!el)return;
    if(!n){el.hidden=true;return;}
    el.hidden=false; el.textContent=n; el.className='n'+(cls?' '+cls:'');
  }

  function stamp(text,stale){
    var s=document.getElementById('nStamp'), d=document.getElementById('nDot');
    if(s)s.textContent=text;
    if(d)d.className='dot'+(stale?' stale':'');
  }

  /* ── charts ────────────────────────────────────────────────────────────
     Small, honest and dependency-free. Points come from real samples; a run
     of zeros is drawn as zeros, and an empty series draws nothing at all
     rather than a flat line that looks like "no faults". */
  function area(el,pts,o){
    if(!el)return;
    o=o||{};
    var vals=(pts||[]).map(function(p){return +p.v||0;});
    if(!vals.length){
      el.innerHTML='<div class="nempty">'+svg(I.pulse)+'<b>No history yet</b>'+
        E(o.emptyHint||'Samples appear once the collector has run twice.')+'</div>';
      return;
    }
    var W=o.w||560, H=o.h||118, PL=30, PR=6, PT=8, PB=17;
    var max=Math.max.apply(null,vals.concat([o.min||1]));
    var iw=W-PL-PR, ih=H-PT-PB, n=vals.length;
    var X=function(i){return PL+(n<2?iw/2:i*iw/(n-1));};
    var Y=function(v){return PT+ih-(v/max)*ih;};
    var d='',ar='';
    vals.forEach(function(v,i){d+=(i?'L':'M')+X(i).toFixed(1)+' '+Y(v).toFixed(1);});
    ar='M'+X(0).toFixed(1)+' '+(PT+ih)+d.slice(1)+'L'+X(n-1).toFixed(1)+' '+(PT+ih)+'Z';
    var cls=o.tone?' '+o.tone:'';
    var s='<svg class="nchart" viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" '+
      'role="img" aria-label="'+E(o.label||'trend')+'">';
    [0,.5,1].forEach(function(f){
      var y=PT+ih*f;
      s+='<line class="grid" x1="'+PL+'" y1="'+y.toFixed(1)+'" x2="'+(W-PR)+'" y2="'+y.toFixed(1)+'"/>';
      s+='<text class="axis" x="'+(PL-5)+'" y="'+(y+3).toFixed(1)+'" text-anchor="end">'+
         Math.round(max*(1-f))+'</text>';
    });
    s+='<path class="ar'+cls+'" d="'+ar+'"/><path class="ln'+cls+'" d="'+d+'"/>';
    // end point marker: where the fleet is right now
    s+='<circle class="pt" cx="'+X(n-1).toFixed(1)+'" cy="'+Y(vals[n-1]).toFixed(1)+'" r="3"/>';
    if(pts[0].t) s+='<text class="axis" x="'+PL+'" y="'+(H-4)+'">'+E(pts[0].t)+'</text>';
    if(pts[n-1].t) s+='<text class="axis" x="'+(W-PR)+'" y="'+(H-4)+'" text-anchor="end">'+
      E(pts[n-1].t)+'</text>';
    // one hover band per sample, so every point is reachable by pointer and tooltip
    var bw=iw/Math.max(1,n-1);
    pts.forEach(function(p,i){
      s+='<rect class="hit" x="'+(X(i)-bw/2).toFixed(1)+'" y="'+PT+'" width="'+bw.toFixed(1)+
         '" height="'+ih+'"><title>'+E((p.t?p.t+' — ':'')+p.v+' '+(o.unit||''))+'</title></rect>';
    });
    el.innerHTML=s+'</svg>';
  }

  /* ── sortable tables ──────────────────────────────────────────────────── */
  function sortable(table){
    if(!table||table.dataset.sortable)return;
    table.dataset.sortable='1';
    var ths=[].slice.call(table.querySelectorAll('thead th[data-key]'));
    ths.forEach(function(th){
      th.classList.add('srt');
      th.tabIndex=0;
      th.setAttribute('role','columnheader');
      if(!th.querySelector('.ar')) th.insertAdjacentHTML('beforeend','<span class="ar">▲</span>');
      var go=function(){
        var asc=th.getAttribute('aria-sort')!=='ascending';
        ths.forEach(function(o){o.removeAttribute('aria-sort');
          var a=o.querySelector('.ar'); if(a)a.textContent='▲';});
        th.setAttribute('aria-sort',asc?'ascending':'descending');
        th.querySelector('.ar').textContent=asc?'▲':'▼';
        var tb=table.tBodies[0];
        var rows=[].slice.call(tb.rows);
        var i=ths.indexOf(th)+ (th.cellIndex-ths.indexOf(th)); // real column index
        i=th.cellIndex;
        var num=th.dataset.type==='num';
        rows.sort(function(a,b){
          var x=(a.cells[i]||{}).dataset||{}, y=(b.cells[i]||{}).dataset||{};
          var av=x.sort!=null?x.sort:(a.cells[i]||{}).textContent||'';
          var bv=y.sort!=null?y.sort:(b.cells[i]||{}).textContent||'';
          if(num){av=parseFloat(String(av).replace(/[^0-9.\-]/g,''))||0;
                  bv=parseFloat(String(bv).replace(/[^0-9.\-]/g,''))||0;
                  return asc?av-bv:bv-av;}
          return asc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
        });
        rows.forEach(function(r){tb.appendChild(r);});
      };
      th.addEventListener('click',go);
      th.addEventListener('keydown',function(e){
        if(e.key==='Enter'||e.key===' '){e.preventDefault();go();}});
    });
  }

  function ago(s){
    if(s==null)return '—';
    if(s<90)return s+'s ago';
    if(s<5400)return Math.round(s/60)+'m ago';
    if(s<172800)return Math.round(s/3600)+'h ago';
    return Math.round(s/86400)+'d ago';
  }

  window.NOC={mount:mount,act:act,vitals:vitals,badge:badge,stamp:stamp,
              area:area,sortable:sortable,icon:function(k,c){return svg(I[k]||'',c);},
              I:I,ago:ago,esc:E};
})();
