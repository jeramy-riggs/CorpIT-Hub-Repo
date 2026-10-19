/* it-panel.js — front-panel port maps for switches, firewalls and access points.
   Every light on these panels is driven by a real polled value. Nothing is
   decorative: if a signal is not collected, the indicator is not drawn.

   Signals and where they come from
     link / port up / port down   ifOperStatus            (net_ports.oper)
     administratively disabled    ifAdminStatus           (net_ports.admin)
     speed  100M / 1G / 2.5G /10G ifHighSpeed             (net_ports.speed)
     errors                       CRC + in/out errors     (net_ports.crc/in_err/out_err)
     alerts                       the hourly diagnosis    (net_port_issues.severity)
     devices on the port          CAM table               (net_ports.mac_count)
     duplex                       dot3StatsDuplexStatus   (switch: NOT YET COLLECTED)
                                  FortiGate monitor API   (firewall: live)
     throughput (LED pulse rate)  ifHCIn/OutOctets deltas (NOT YET COLLECTED)

   The last two are absent on switch ports today, so the duplex glyph and the
   pulse are simply not rendered there. They light up on their own the moment
   the collector supplies the fields — no page change needed.

   Usage:  ITPanel.render(el, {kind:'switch', device:{...}, ports:[...],
                              onSelect:function(port){...}})
*/
(function(){
  'use strict';

  var E=function(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});};

  /* ── geometry (SVG user units; the panel scales to its container) ──────── */
  var CH=24, COLG=5, ROWG=8, NUMH=13, PAD=15, GRPG=11, UPG=26;
  var CW=32, CWD=32;   // cage width; a panel may widen it for named interfaces
  /* the silkscreen block sizes itself to its longest line — a clipped device
     name is the kind of thing that quietly makes a panel look broken. Measure
     with the real font rather than guessing an average character width. */
  var _cx=null;
  function textW(s,font){
    if(!s)return 0;
    if(!_cx){try{_cx=document.createElement('canvas').getContext('2d');}catch(e){_cx=false;}}
    if(!_cx)return String(s).length*7.4;
    _cx.font=font; return _cx.measureText(String(s)).width;
  }
  /* a named bay gets its label trimmed to the cell, never bled into its
     neighbour. Trim the MIDDLE: interface names differ at the tail
     (internal1/2/3), so a plain head-trim renders three identical bays.
     The full name stays in the tooltip and the aria-label. */
  function fit(s,maxW,font){
    s=String(s==null?'':s);
    if(textW(s,font)<=maxW)return s;
    for(var n=s.length-1;n>=2;n--){
      var head=Math.ceil(n/2), tail=n-head;
      var c=s.slice(0,head)+'\u2026'+(tail?s.slice(s.length-tail):'');
      if(textW(c,font)<=maxW)return c;
    }
    return s.slice(-1);
  }
  function silkW(o){
    var sans=getComputedStyle(document.body).fontFamily||'system-ui';
    return Math.ceil(Math.max(76,
      textW(o.title,'700 13px '+sans)+4,
      textW(o.sub,'500 10.5px ui-monospace,monospace')+4,
      o.sysOk!=null?86:0));
  }

  /* ── normalise one port from whatever the API gave us ─────────────────────
     Returns a shape the renderer understands. `duplex` and `bps` stay null
     when the source has no such field — that is what keeps the panel honest. */
  function normSwitch(p){
    var errs=(p.crc||0)+(p.in_err||0)+(p.out_err||0);
    var up=p.oper==='up';
    var admDown=String(p.admin||'').toLowerCase()==='down';
    var sev=p.severity||(p.diag&&p.diag.severity)||null;
    return {
      id:String(p.ifindex), num:portNum(p.port), label:p.port, descr:p.descr||'',
      state: admDown?'disabled':(up?'up':'down'),
      sev: up?(sev==='critical'?'critical':(sev==='warn'||errs>0?'warn':null)):null,
      speed: up?(p.speed||null):null,
      duplex: p.duplex||null,          // not collected yet on switches
      bps: (p.bps!=null?p.bps:null),   // not collected yet on switches
      bps_in:(p.bps_in!=null?p.bps_in:null), bps_out:(p.bps_out!=null?p.bps_out:null),
      window:(p.bps_window||null),   // seconds the rate was actually averaged over
      errs: errs, discards:p.out_disc||0, macs:p.mac_count||0,
      uplink: isUplink(p.port,p.speed), raw:p
    };
  }
  function normFw(i){
    var errs=(i.errs!=null?i.errs:(Number(i.rx_errors)||0)+(Number(i.tx_errors)||0));
    var up=/^up$/i.test(String(i.state||i.link||''))||i.link===true;
    var sp=null, dx=null;
    // mapInterfaces() hands back a display string: "1 Gbps / full"
    var m=/([\d.]+)\s*(Gbps|Mbps)/i.exec(String(i.speed||''));
    if(m) sp=Math.round(parseFloat(m[1])*(/g/i.test(m[2])?1000:1));
    if(/\bfull\b/i.test(String(i.speed||''))) dx='full';
    else if(/\bhalf\b/i.test(String(i.speed||''))) dx='half';
    return { id:i.name, num:null, label:i.name, descr:i.role||'',
      state: up?'up':'down', sev: up&&errs>0?'warn':null,
      speed: up?sp:null, duplex: up?dx:null, bps:(i.bps!=null?i.bps:null),
      errs:errs, discards:i.drops||0, macs:0, uplink:false, raw:i };
  }

  function portNum(name){var m=/(\d+)\s*$/.exec(String(name||''));return m?m[1]:'';}
  function isUplink(name,speed){
    return /^(Te|Twe|Fo|Hu|Fi)/i.test(String(name||''))||(speed||0)>=10000;
  }
  function speedTag(mbps){
    if(!mbps)return '';
    if(mbps>=100000)return '100G'; if(mbps>=40000)return '40G';
    if(mbps>=25000)return '25G';   if(mbps>=10000)return '10G';
    if(mbps>=5000)return '5G';     if(mbps>=2500)return '2.5G';
    if(mbps>=1000)return (mbps/1000)+'G';
    return String(mbps);
  }
  function speedClass(mbps){
    if(!mbps)return '';
    if(mbps>=10000)return 'sp10g'; if(mbps>=2500)return 'sp25';
    if(mbps>=1000)return 'sp1g';   return 'sp100';
  }
  /* LED colour follows the worst true thing about the port */
  function ledClass(p){
    if(p.state==='disabled')return 'led-off';
    if(p.state!=='up')return 'led-down';
    if(p.sev==='critical')return 'led-alert';
    if(p.sev==='warn')return 'led-warn';
    return 'led-up';
  }
  /* Pulse period from real throughput. Only ever called when bps is a number. */
  function pulse(bps){
    if(bps==null)return null;
    if(bps<8000)return null;                       // effectively idle — steady light
    var s=Math.max(0.09,Math.min(1.1,1.1-Math.log10(bps/8000)*0.24));
    return s.toFixed(2)+'s';
  }
  function mins(s){
    if(!s)return '';
    if(s<90)return s+' seconds';
    var m=Math.round(s/60);
    return m<90?m+' minutes':Math.round(s/3600)+' hours';
  }
  function human(bps){
    if(bps==null)return null;
    var u=['bps','kbps','Mbps','Gbps'],i=0,v=bps;
    while(v>=1000&&i<u.length-1){v/=1000;i++;}
    return (v<10?v.toFixed(1):Math.round(v))+' '+u[i];
  }

  function tip(p){
    var t=[p.label+(p.descr?' — '+p.descr:'')];
    t.push(p.state==='disabled'?'administratively shut down'
         : p.state==='up'?('link up'+(p.speed?' · '+speedTag(p.speed)+(p.speed<1000?' Mbps':''):'')
                           +(p.duplex?' · '+p.duplex+' duplex':''))
         : 'link down');
    if(p.bps!=null){
      // never present an average as though it were an instantaneous reading, and
      // keep the two directions separate — summed, they can exceed the line rate
      t.push('throughput '+human(p.bps)+(p.window?' averaged over '+mins(p.window):'')+
        (p.bps_in!=null?' (in '+human(p.bps_in)+', out '+human(p.bps_out)+')':''));
    }
    if(p.errs) t.push(p.errs.toLocaleString()+' errors');
    if(p.discards) t.push(p.discards.toLocaleString()+' discards');
    if(p.macs) t.push(p.macs+' device'+(p.macs>1?'s':'')+' learned');
    return t.join(' · ');
  }

  /* ── one RJ45 cage ─────────────────────────────────────────────────────── */
  function cage(p,x,y,row){
    var cls='fpport '+ledClass(p)+(p.state==='up'?' live':'')+(p.uplink?' up-link':'');
    var per=p.state==='up'?pulse(p.bps):null;
    var g='<g class="'+cls+'" role="button" tabindex="0" data-pid="'+E(p.id)+'"'+
      (per?' style="--fpr:'+per+'"':'')+
      ' aria-label="'+E(tip(p))+'"><title>'+E(tip(p))+'</title>';
    // number silkscreened outside the row, the way it is on the real faceplate
    var wide=(p.num==null||p.num==='');
    var lbl=wide?fit(p.label,CW+COLG-2,'600 8px ui-monospace,monospace')
                :String(p.num);
    g+='<text class="fpnum'+(wide?' wide':'')+'" x="'+(x+CW/2)+'" y="'+
       (row?y+CH+10:y-4)+'">'+E(lbl)+'</text>';
    // the cage: a rounded body with the RJ45 latch notch cut into the top
    g+='<path class="fpcage" d="'+cagePath(x,y,row)+'"/>';
    // status LED
    var ly=row?y+CH-8:y+4, dy=row?y+11:y+17;     // keep LED and glyph clear of the latch cut
    g+='<rect class="fpled" x="'+(x+4)+'" y="'+ly+'" width="8" height="4" rx="1.6"/>';
    if(per) g+='<rect class="fpact" x="'+(x+4)+'" y="'+ly+'" width="8" height="4" rx="1.6"/>';
    // speed, printed in the cage so it reads without a hover
    if(p.speed) g+='<text class="fpsp '+speedClass(p.speed)+'" x="'+(x+CW-4)+'" y="'+(ly+5)+'">'+
      E(speedTag(p.speed))+'</text>';
    // duplex glyph — drawn only when the source actually reports it
    if(p.duplex) g+='<text class="fpdx'+(p.duplex==='half'?' half':'')+'" x="'+(x+CW/2)+'" y="'+
      dy+'">'+(p.duplex==='half'?'→':'⇄')+'</text>';
    else if(p.state==='up') g+='<rect class="fpbar" x="'+(x+7)+'" y="'+(dy-4)+'" width="'+(CW-14)+'" height="2.5" rx="1.2"/>';
    if(p.state==='disabled') g+='<path class="fpx" d="M'+(x+9)+' '+(dy-9)+'l'+(CW-18)+' 8M'+
      (x+CW-9)+' '+(dy-9)+'l-'+(CW-18)+' 8"/>';
    g+='<rect class="fphit" x="'+x+'" y="'+y+'" width="'+CW+'" height="'+CH+'" rx="3"/>';
    return g+'</g>';
  }
  /* row 0 sits latch-down and row 1 latch-up, the way stacked RJ45 jacks are
     actually mounted — it is the cue that says "this is the front of a box" */
  function cagePath(x,y,row){
    var w=CW,h=CH,r=2.5,nw=9,nh=4;                 // nw/nh = the latch notch
    var l=x,t=y,rt=x+w,b=y+h,cx=x+w/2;
    if(row) return 'M'+(l+r)+' '+t+'H'+(cx-nw/2)+'v'+nh+'h'+nw+'v-'+nh+'H'+(rt-r)+
           'a'+r+' '+r+' 0 0 1 '+r+' '+r+'V'+(b-r)+
           'a'+r+' '+r+' 0 0 1 -'+r+' '+r+'H'+(l+r)+
           'a'+r+' '+r+' 0 0 1 -'+r+' -'+r+'V'+(t+r)+
           'a'+r+' '+r+' 0 0 1 '+r+' -'+r+'Z';
    return 'M'+(l+r)+' '+t+'H'+(rt-r)+
           'a'+r+' '+r+' 0 0 1 '+r+' '+r+'V'+(b-r)+
           'a'+r+' '+r+' 0 0 1 -'+r+' '+r+'H'+(cx+nw/2)+'v-'+nh+'h-'+nw+'v'+nh+'H'+(l+r)+
           'a'+r+' '+r+' 0 0 1 -'+r+' -'+r+'V'+(t+r)+
           'a'+r+' '+r+' 0 0 1 '+r+' -'+r+'Z';
  }

  /* ── the chassis ───────────────────────────────────────────────────────── */
  function faceplate(o){
    var ports=o.ports||[];
    var main=ports.filter(function(p){return !p.uplink;});
    var upl =ports.filter(function(p){return  p.uplink;});
    var rows=o.rows===1?1:2;
    var cols=Math.ceil(main.length/rows), ucols=Math.ceil(upl.length/rows);
    var colPitch=CW+COLG, rowPitch=CH+ROWG+NUMH;
    CW=o.cw||CWD;
    var SILK=silkW(o), x0=PAD+SILK+PAD;

    var gg=o.group===false?0:Math.floor(Math.max(0,cols-1)/6)*GRPG;
    var w=x0+cols*colPitch-COLG+gg+(upl.length?UPG+ucols*colPitch-COLG:0)+PAD;
    var h=PAD+NUMH+CH+(rows>1?ROWG+NUMH+CH:0)+PAD;

    // never scale below 1:1 — a squeezed faceplate stops being readable, so the
    // wrapper scrolls instead. Upscaling on a wide pane is free (it is vector).
    var s='<svg class="fp" viewBox="0 0 '+Math.round(w)+' '+Math.round(h)+'" '+
      'style="min-width:'+Math.round(w)+'px" '+
      'preserveAspectRatio="xMinYMid meet" role="group" aria-label="'+E(o.title||'Front panel')+'">';
    s+='<defs><linearGradient id="fpb" x1="0" y1="0" x2="0" y2="1">'+
       '<stop offset="0" class="fpb1"/><stop offset="1" class="fpb2"/></linearGradient></defs>';
    s+='<rect class="fpbez" x="0.5" y="0.5" width="'+(w-1)+'" height="'+(h-1)+'" rx="9" fill="url(#fpb)"/>';
    s+='<rect class="fpvent" x="'+PAD+'" y="'+(h-PAD+2)+'" width="0" height="0"/>';

    // silkscreen: device identity + the one system LED we can actually verify
    var sy=PAD+NUMH+2;
    s+='<text class="fpsilk1" x="'+PAD+'" y="'+(sy+11)+'">'+E(o.title||'')+'</text>';
    if(o.sub) s+='<text class="fpsilk2" x="'+PAD+'" y="'+(sy+26)+'">'+E(o.sub)+'</text>';
    if(o.sysOk!=null){
      s+='<rect class="fpled '+(o.sysOk?'led-up':'led-alert')+'" x="'+PAD+'" y="'+(sy+38)+'" width="9" height="4.5" rx="1.8"/>';
      s+='<text class="fpsilk3" x="'+(PAD+14)+'" y="'+(sy+43)+'">'+(o.sysOk?'RESPONDING':'NO REPLY')+'</text>';
    }

    var i,p,col,row,x,y;
    for(i=0;i<main.length;i++){
      p=main[i]; col=Math.floor(i/rows); row=rows>1?(i%rows):0;
      x=x0+col*colPitch+(o.group===false?0:Math.floor(col/6)*GRPG);
      y=PAD+NUMH+row*rowPitch;
      s+=cage(p,x,y,row);
    }
    if(upl.length){
      var ux=x0+cols*colPitch-COLG+gg+UPG;
      s+='<line class="fpdiv" x1="'+(ux-UPG/2)+'" y1="'+(PAD+4)+'" x2="'+(ux-UPG/2)+'" y2="'+(h-PAD-4)+'"/>';
      var lx=ux-UPG/2;
      s+='<text class="fpsilk3 fprot" transform="rotate(-90 '+lx+' '+(h/2)+')" x="'+lx+
         '" y="'+(h/2)+'">UPLINKS</text>';
      for(i=0;i<upl.length;i++){
        p=upl[i]; col=Math.floor(i/rows); row=rows>1?(i%rows):0;
        x=ux+col*colPitch; y=PAD+NUMH+row*rowPitch;
        s+=cage(p,x,y,row);
      }
    }
    return s+'</svg>';
  }

  /* ── legend: only the states actually present on this panel ────────────── */
  function legend(ports){
    var has={}, any=false;
    ports.forEach(function(p){
      has[ledClass(p)]=true;
      if(p.speed)has['s_'+speedClass(p.speed)]=true;
      if(p.duplex)has['d_'+p.duplex]=true;
      if(p.bps!=null&&pulse(p.bps)){has.pulse=true;if(p.window)has.win=p.window;}
      if(p.macs)has.macs=true; if(p.errs)has.err=true;
    });
    var L=[['led-up','Link up'],['led-warn','Errors counting'],['led-alert','Alert raised'],
           ['led-down','No link'],['led-off','Shut down']];
    var h='<div class="fplg">';
    L.forEach(function(x){ if(!has[x[0]])return; any=true;
      h+='<span class="fplgi"><i class="fpdot '+x[0]+'"></i>'+x[1]+'</span>';});
    if(has.pulse){any=true;h+='<span class="fplgi"><i class="fpdot led-up fpblink"></i>Pulsing with traffic'+
      (has.win?' ('+mins(has.win)+' average)':'')+'</span>';}
    ['sp100','sp1g','sp25','sp10g'].forEach(function(c){
      if(!has['s_'+c])return; any=true;
      var n={sp100:'100 Mb',sp1g:'1 Gig',sp25:'2.5 Gig',sp10g:'10 Gig+'}[c];
      h+='<span class="fplgi"><b class="fpsw '+c+'">'+n+'</b></span>';});
    if(has.d_full){any=true;h+='<span class="fplgi"><i class="fpgl">⇄</i>Full duplex</span>';}
    if(has.d_half){any=true;h+='<span class="fplgi"><i class="fpgl half">→</i>Half duplex</span>';}
    return any?h+'</div>':'';
  }

  /* mark the wrapper only when it actually overflows, and clear the hint once
     the reader has scrolled to the end */
  function edgeFade(w){
    if(!w)return;
    var sync=function(){
      var over=w.scrollWidth-w.clientWidth>4;
      w.classList.toggle('fpscroll',over);
      w.classList.toggle('at-end',over&&w.scrollLeft>=w.scrollWidth-w.clientWidth-4);
    };
    w.addEventListener('scroll',sync,{passive:true});
    if(window.ResizeObserver) new ResizeObserver(sync).observe(w);
    requestAnimationFrame(sync);
  }

  function render(el,o){
    if(!el)return;
    o=o||{};
    var norm=o.kind==='firewall'?normFw:normSwitch;
    var ports=(o.ports||[]).map(norm);
    if(o.sortNumeric!==false) ports.sort(function(a,b){
      return (parseInt(a.num,10)||0)-(parseInt(b.num,10)||0)||
             String(a.label).localeCompare(String(b.label));});
    if(!ports.length){
      el.innerHTML='<div class="u-empty">No interface detail from the last poll.</div>';return;}
    el.innerHTML='<div class="fpwrap">'+faceplate({title:o.title,sub:o.sub,sysOk:o.sysOk,
      ports:ports,rows:o.rows,cw:o.cw,group:o.group})+'</div>'+legend(ports);
    edgeFade(el.querySelector('.fpwrap'));
    var by={}; ports.forEach(function(p){by[p.id]=p;});
    el.querySelectorAll('[data-pid]').forEach(function(g){
      var p=by[g.dataset.pid];
      var go=function(){ if(o.onSelect)o.onSelect(p); };
      g.addEventListener('click',go);
      g.addEventListener('keydown',function(e){
        if(e.key==='Enter'||e.key===' '){e.preventDefault();go();}});
    });
    return ports;
  }

  /* ── status plate ────────────────────────────────────────────────────────
     Some devices have no ports to draw. An access point reports a status, a
     client count and the state of its uplink — three real signals and nothing
     else, since no per-radio telemetry is collected. Rather than invent a port
     map for it, the plate shows exactly those signals in the same language:
     one labelled LED per signal, plus an optional load bar.

       ITPanel.plate(el,{title,sub,leds:[{k,v,state}],meter:{k,v,max,cap}}) */
  function plate(el,o){
    if(!el)return;
    o=o||{}; var leds=o.leds||[];
    var W=Math.max(300,88+leds.length*112+(o.meter?150:0)), H=84;
    var SW=silkW({title:o.title,sub:o.sub,sysOk:null});
    W=Math.max(W,PAD+SW+PAD+leds.length*112+(o.meter?150:0)+PAD);
    var s='<svg class="fp" viewBox="0 0 '+W+' '+H+'" style="min-width:'+Math.min(W,560)+'px" '+
      'preserveAspectRatio="xMinYMid meet" role="group" aria-label="'+E(o.title||'Device')+' status plate">';
    s+='<defs><linearGradient id="fpb2" x1="0" y1="0" x2="0" y2="1">'+
       '<stop offset="0" class="fpb1"/><stop offset="1" class="fpb2"/></linearGradient></defs>';
    s+='<rect class="fpbez" x="0.5" y="0.5" width="'+(W-1)+'" height="'+(H-1)+'" rx="9" fill="url(#fpb2)"/>';
    s+='<text class="fpsilk1" x="'+PAD+'" y="'+(PAD+16)+'">'+E(o.title||'')+'</text>';
    if(o.sub) s+='<text class="fpsilk2" x="'+PAD+'" y="'+(PAD+33)+'">'+E(o.sub)+'</text>';
    var x=PAD+SW+PAD;
    leds.forEach(function(L){
      var cls={good:'led-up',warn:'led-warn',bad:'led-alert',off:'led-down',none:'led-off'}[L.state]||'led-down';
      s+='<g class="fpport '+cls+'"><title>'+E(L.k+': '+L.v)+'</title>'+
         '<rect class="fpled" x="'+x+'" y="'+(PAD+8)+'" width="13" height="6" rx="2.4"/>'+
         '<text class="fpsilk3" x="'+(x+19)+'" y="'+(PAD+13)+'">'+E(String(L.k).toUpperCase())+'</text>'+
         '<text class="fpval" x="'+x+'" y="'+(PAD+37)+'">'+E(L.v)+'</text></g>';
      x+=112;
    });
    if(o.meter){
      var m=o.meter, cap=m.cap||m.max||1, pctv=Math.max(0,Math.min(1,(m.v||0)/cap));
      s+='<text class="fpsilk3" x="'+x+'" y="'+(PAD+13)+'">'+E(String(m.k).toUpperCase())+'</text>';
      s+='<rect class="fpmb" x="'+x+'" y="'+(PAD+21)+'" width="122" height="7" rx="3.5"/>';
      s+='<rect class="fpmf" x="'+x+'" y="'+(PAD+21)+'" width="'+(122*pctv).toFixed(1)+'" height="7" rx="3.5"/>';
      s+='<text class="fpval" x="'+x+'" y="'+(PAD+45)+'">'+E(m.v)+(m.unit?' '+E(m.unit):'')+'</text>';
    }
    el.innerHTML='<div class="fpwrap">'+s+'</svg></div>';
    edgeFade(el.querySelector('.fpwrap'));
  }

  window.ITPanel={render:render,plate:plate,speedTag:speedTag,human:human};
})();
