(function(){
  var KEY='portal_theme', MAXEL=3000, runs=0, MAXRUNS=20, busy=false;
  function mode(){return document.documentElement.getAttribute('data-theme')==='dark'?'dark':'light';}
  function scope(){return document.getElementById('apv4-root')||document.body;}
  function vis(el){if(!el)return false;var r=el.getBoundingClientRect();return r.width>0&&r.height>0;}

  var BG={'#f3f4f6':'#0B1925','#f9fafb':'#142533','#ffffff':'#142533','#fff':'#142533',
          '#f8f9fa':'#142533','#e5e7eb':'#1C2E3D','#f1f5f9':'#142533'};
  var FG={'#111827':'#EBF1F6','#374151':'#C2CCD4','#4b5563':'#AEB9C2','#6b7280':'#93A1AB',
          '#9ca3af':'#86939D','#1f2937':'#D6DEE5'};
  var BD={'#e5e7eb':'#2A3D4D','#d1d5db':'#3C5060','#f3f4f6':'#25384A','#e2e8f0':'#2A3D4D'};
  function swap(p,h){var v=h.toLowerCase();
    if(p.indexOf('background')===0)return BG[v]||null;
    if(p==='color')return FG[v]||null;
    if(p.indexOf('border')>-1)return BD[v]||null;return null;}
  function darken(s){return s.replace(/([a-z-]+)\s*:\s*([^;]+)/gi,function(m,p,val){
    var hx=val.match(/#[0-9a-fA-F]{3,6}\b/); if(!hx)return m;
    var h6=hx[0]; if(h6.length===4) h6='#'+h6[1]+h6[1]+h6[2]+h6[2]+h6[3]+h6[3];
    var r=swap(p.trim().toLowerCase(),h6); return r?m.replace(hx[0],r):m;});}

  function skin(on){
    if(busy)return 0; busy=true; var hit=0;
    try{
      var root=scope(), els=root.querySelectorAll('[style]');
      var n=Math.min(els.length,MAXEL);
      for(var i=0;i<n;i++){
        var el=els[i], s=el.getAttribute('style')||'';
        if(s.indexOf('auction-hq-banner')>-1) continue;
        if(on){
          var d=darken(s);
          if(d!==s){ if(!el.hasAttribute('data-pt-orig'))el.setAttribute('data-pt-orig',s);
                     el.setAttribute('style',d); hit++; }
        }else if(el.hasAttribute('data-pt-orig')){
          el.setAttribute('style',el.getAttribute('data-pt-orig'));
          el.removeAttribute('data-pt-orig'); hit++;
        }
      }
    }catch(e){console.warn('[portal-theme]',e);} finally{busy=false;}
    return hit;
  }

  function paint(m){
    document.documentElement.setAttribute('data-theme',m);   /* always explicit */
    try{localStorage.setItem(KEY,m);}catch(e){}
    if(typeof window.applyTheme==='function'){try{window.applyTheme(m==='dark');}catch(e){}}
    skin(m==='dark');
    var f=document.querySelectorAll('.pt-toggle');
    for(var i=0;i<f.length;i++)f[i].textContent=m==='dark'?'\u2600':'\u263D';
  }
  window.portalToggleTheme=function(){runs=0;paint(mode()==='dark'?'light':'dark');};

  /* index.html owns a native toggle even when hidden in form view — never duplicate it */
  function hasNative(){
    /* approver.html carries a DEAD theme-btn-pub in v1 markup, so it needs ours.
       index.html has a real one (hidden in form view) — never duplicate it. */
    if(/approver\.html$/i.test(location.pathname)) return false;
    return !!(document.getElementById('theme-btn-pub')||document.getElementById('theme-btn-ap'));
  }

  function place(b){
    var so=null, els=document.querySelectorAll('button,a');
    for(var i=0;i<els.length;i++){
      if((els[i].textContent||'').trim().toLowerCase()!=='sign out') continue;
      if(els[i].getBoundingClientRect().width>0){ so=els[i]; break; }
    }
    if(!so) return false;
    var sr=so.getBoundingClientRect(), left=sr.left;
    /* walk left through the header cluster (avatar, username) so we don't overlap it */
    var sib=so.previousElementSibling;
    while(sib){
      var r=sib.getBoundingClientRect();
      if(r.width>0 && Math.abs(r.top-sr.top)<32 && r.left>sr.left-240) left=Math.min(left,r.left);
      sib=sib.previousElementSibling;
    }
    b.style.top=Math.round(sr.top+sr.height/2-21)+'px';
    b.style.right=Math.round(window.innerWidth-left+14)+'px';
    b.style.bottom='auto';
    return true;
  }
  function mount(){
    if(hasNative()) return;
    var b=document.querySelector('.pt-toggle');
    if(!b){
      b=document.createElement('button');
      b.className='pt-toggle pt-fixed'; b.type='button'; b.title='Toggle dark or light mode';
      b.onclick=window.portalToggleTheme;
      b.textContent = mode()==='dark' ? '\u2600' : '\u263D';
      document.body.appendChild(b);
    }
    place(b);
  }
  window.addEventListener('resize',function(){
    var b=document.querySelector('.pt-toggle'); if(b) place(b);
  });

  function boot(){
    var saved='light';
    try{var v=localStorage.getItem(KEY); if(v==='dark'||v==='light')saved=v;}catch(e){}
    paint(saved); mount();
    var iv=setInterval(function(){
      if(++runs>MAXRUNS){clearInterval(iv);
        console.log('[portal-theme] settled —',mode(),'| toggles:',document.querySelectorAll('.pt-toggle').length,
                    '| native:',hasNative(),'| scope:',scope().id||'body');
        return;}
      mount(); if(mode()==='dark') skin(true);
    },700);
  }
  window.addEventListener('storage',function(e){
    if(e.key===KEY&&(e.newValue==='dark'||e.newValue==='light')){runs=0;paint(e.newValue);}
  });
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);else boot();
})();
