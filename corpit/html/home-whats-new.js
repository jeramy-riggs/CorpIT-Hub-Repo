/* A finite, permission-aware trailer. The only persistent writes are local viewing preferences. */
(function () {
 'use strict';
 var tile=document.getElementById('home-whats-new');if(!tile)return;
 var scenes=Array.from(tile.querySelectorAll('.hwt-scene'));
 var chapters=Array.from(tile.querySelectorAll('[data-hwt-chapter]'));
 var play=tile.querySelector('[data-hwt-play]'),label=tile.querySelector('[data-hwt-play-label]'),icon=tile.querySelector('[data-hwt-play-icon]');
 var prev=tile.querySelector('[data-hwt-prev]'),next=tile.querySelector('[data-hwt-next]'),replay=tile.querySelector('[data-hwt-replay]');
 var dismiss=document.getElementById('home-whats-new-dismiss'),restore=document.getElementById('home-whats-new-restore');
 var position=tile.querySelector('[data-hwt-position]'),note=tile.querySelector('[data-hwt-motion-note]'),message=tile.querySelector('[data-hwt-message]'),globalStatus=document.getElementById('home-whats-new-status');
 var reduced=matchMedia('(prefers-reduced-motion: reduce)'),ease=getComputedStyle(tile).getPropertyValue('--ease-out').trim()||'cubic-bezier(.23,1,.32,1)';
 var ready=false,inView=false,playing=false,ended=false,current=0,elapsed=0,last=0,raf=0;
 var allowed=[],motion=new Set(),flight=[],storageKey=null,firstRun=false;
 var duration=5200;
 function read(key){try{return key&&localStorage.getItem(key);}catch(_){return null;}}
 function write(key,value){if(!key)return;try{if(value===null)localStorage.removeItem(key);else localStorage.setItem(key,value);}catch(_){}}
 function canSee(scene){
  if(scene.dataset.workspace==='intune'){
   if(location.hostname!=='dev-corpit.nrpi.local')return false;
   var rb=window.itRbac,me=rb&&rb.state()==='ok'?rb.me():null;
   return !!(me&&me.email&&(me.isSuperAdmin===true||(me.isActive===true&&Array.isArray(me.roles)&&me.roles.indexOf('tier2')!==-1)));
  }
  return !!(window.itRbac&&itRbac.canAccess(scene.dataset.rbacPage));
 }
 function run(node,frames,options){
  if(!node||typeof node.animate!=='function')return null;
  var a=node.animate(frames,Object.assign({duration:700,easing:ease},options));motion.add(a);
  a.finished.then(function(){motion.delete(a);},function(){motion.delete(a);});return a;
 }
 function cancelMotion(){motion.forEach(function(a){a.cancel();});motion.clear();flight=[];}
 function announce(text){message.textContent=text;}
 function updateControls(){
  play.disabled=reduced.matches;
  label.textContent=reduced.matches?'Static preview':playing?'Pause trailer':ended?'Replay trailer':'Play trailer';
  play.setAttribute('aria-label',label.textContent);icon.textContent=playing?'Ⅱ':'▶';
  position.textContent=allowed.length?'Scene '+(current+1)+' of '+allowed.length+' · '+allowed[current].querySelector('.hwt-app').textContent:'';
  note.textContent=reduced.matches?'Reduced motion · choose a workspace':ended?'Your next stop is one click away.':playing?'Now playing · previews, not live readings':'Choose a scene, or play the trailer';
 }
 function setProgress(){var active=allowed[current];if(!active)return;var b=chapters.find(function(x){return x.dataset.hwtChapter===active.dataset.workspace;});if(b)b.querySelector('i').style.transform='scaleX('+Math.min(1,elapsed/duration)+')';}
 function show(index,animateIt,cinematic){
  cancelMotion();current=Math.max(0,Math.min(allowed.length-1,index));elapsed=0;ended=false;
  scenes.forEach(function(s){s.hidden=s!==allowed[current];});
  chapters.forEach(function(b){var selected=allowed[current]&&b.dataset.hwtChapter===allowed[current].dataset.workspace;b.setAttribute('aria-pressed',String(!!selected));b.querySelector('i').style.transform='scaleX(0)';});
  updateControls();if(!allowed.length)return;
  var scene=allowed[current];
  if(animateIt&&!reduced.matches){
   var dir=current%2?-1:1;
   run(scene.querySelector('.hwt-copy'),[{transform:'translateX('+(-dir*22)+'px)',opacity:0},{transform:'translateX(0)',opacity:1}],{duration:500});
   var camera=run(scene.querySelector('.hwt-camera'),cinematic?[
    {transform:'translate3d('+dir*100+'px,14px,-180px) rotateY('+(-dir*13)+'deg) scale(.94)',opacity:0,easing:ease},
    {transform:'translate3d(0,0,0) rotateY(0deg) scale(1)',opacity:1,offset:.25},
    {transform:'translate3d('+(-dir*12)+'px,-3px,45px) rotateY('+dir*3+'deg) scale(1.045)',opacity:1,offset:.82,easing:ease},
    {transform:'translate3d('+(-dir*82)+'px,8px,-120px) rotateY('+dir*12+'deg) scale(.95)',opacity:0}
    ]:[{transform:'translate3d('+dir*85+'px,8px,-120px) rotateY('+(-dir*10)+'deg) scale(.95)',opacity:0},{transform:'translate3d(0,0,0) rotateY(0deg) scale(1)',opacity:1}],{duration:cinematic?duration:900,easing:cinematic?'linear':ease,fill:cinematic?'both':'none'});
   if(camera&&cinematic){camera.pause();flight.push(camera);}
   scene.querySelectorAll('.hwt-frame').forEach(function(frame,i){
    var dest=getComputedStyle(frame).transform;
    run(frame,[{transform:'translate3d('+dir*(80+i*24)+'px,'+(18+i*12)+'px,-150px) rotateY('+(-dir*18)+'deg) scale(.94)',opacity:0},{transform:dest,opacity:i===0?.7:1}],{duration:900,delay:i*70,fill:'backwards'});
    run(frame.querySelector('.hwt-glint'),[{transform:'translateX(-60%)',opacity:0},{opacity:.65,offset:.4},{transform:'translateX(60%)',opacity:0}],{duration:1100,delay:650+i*70});
   });
   run(scene.querySelector('.hwt-orbit'),[{transform:'rotate(-16deg) scale(.92)',opacity:.2},{transform:'rotate(8deg) scale(1.06)',opacity:1}],{duration:2400});
  }else if(animateIt&&reduced.matches){run(scene,[{opacity:.8},{opacity:1}],{duration:120});}
  setProgress();
 }
 function holdFrame(){motion.forEach(function(a){a.pause();});setProgress();}
 function stop(why){
  if(!playing)return;
  playing=false;if(raf)cancelAnimationFrame(raf);raf=0;last=0;holdFrame();updateControls();
  if(why)announce(why);
 }
 function tick(now){
  if(!playing)return;
  if(last)elapsed+=Math.min(now-last,100);last=now;
  flight.forEach(function(a){a.currentTime=elapsed;});setProgress();
  if(elapsed>=duration){
   if(current===allowed.length-1){elapsed=duration;ended=true;stop();cancelMotion();updateControls();announce('Trailer complete. Choose a workspace or replay.');return;}
   show(current+1,true,true);
  }
  raf=requestAnimationFrame(tick);
 }
 function start(restart){
  if(!ready||tile.hidden||!allowed.length||reduced.matches)return;
  if(restart||ended){show(0,true,true);}else if(!motion.size){var saved=elapsed;show(current,true,true);elapsed=saved;}
  motion.forEach(function(a){if(flight.indexOf(a)<0&&typeof a.play==='function')a.play();});
  playing=true;last=0;firstRun=false;updateControls();
  if(raf)cancelAnimationFrame(raf);raf=requestAnimationFrame(tick);
 }
 function choose(index,animateIt){firstRun=false;stop();show(index,animateIt);announce(allowed.length?allowed[current].querySelector('.hwt-app').textContent+' selected.':'');}
 function visibleScenes(){
  var previous=allowed[current]&&allowed[current].dataset.workspace;
  allowed=scenes.filter(canSee);
  chapters.forEach(function(b){b.hidden=!allowed.some(function(s){return s.dataset.workspace===b.dataset.hwtChapter;});});
  var found=allowed.findIndex(function(s){return s.dataset.workspace===previous;});show(found<0?0:found,false);
  var any=allowed.length>0;tile.hidden=!any||read(storageKey)==='dismissed';restore.hidden=!any||!tile.hidden;restore.setAttribute('aria-expanded',String(!tile.hidden));
 }
 function initialize(){
  var rb=window.itRbac,me=rb&&(rb.realMe?rb.realMe():rb.me());
  var identity=me&&(me.email||me.upn||me.userPrincipalName||me.sub||me.id||me.username);
  if(identity){storageKey='corpit:home:trailer:2026-10-19-v1:'+encodeURIComponent(String(identity).toLowerCase());}
  // Autoplay once per page launch, including returning visitors.
  visibleScenes();ready=true;tile.removeAttribute('data-hw-pending');firstRun=true;if(firstRun&&inView&&!document.hidden&&!reduced.matches)start(true);
 }
 play.addEventListener('click',function(){if(playing){stop('Trailer paused.');return;}if(reduced.matches){choose((current+1)%allowed.length,false);return;}start(ended);});
 play.disabled=reduced.matches;
 prev.addEventListener('click',function(e){choose((current-1+allowed.length)%allowed.length,e.detail>0);});
 next.addEventListener('click',function(e){choose((current+1)%allowed.length,e.detail>0);});
 replay.addEventListener('click',function(){if(reduced.matches){choose(0,false);return;}stop();start(true);});
 chapters.forEach(function(b){b.addEventListener('click',function(e){var i=allowed.findIndex(function(s){return s.dataset.workspace===b.dataset.hwtChapter;});if(i>=0)choose(i,e.detail>0);});});
 dismiss.addEventListener('click',function(){stop();cancelMotion();firstRun=false;write(storageKey,'dismissed');tile.hidden=true;restore.hidden=false;restore.setAttribute('aria-expanded','false');restore.focus({preventScroll:true});globalStatus.textContent='What’s new dismissed. Show it again anytime.';});
 restore.addEventListener('click',function(){write(storageKey,null);tile.hidden=false;restore.hidden=true;restore.setAttribute('aria-expanded','true');show(0,false);dismiss.focus({preventScroll:true});tile.scrollIntoView({block:'nearest',behavior:'auto'});globalStatus.textContent='What’s new shown. Play the trailer or choose a workspace.';});
 tile.addEventListener('focusin',function(e){if(e.target.closest('.hwt-links,.hwt-chapters'))stop('Trailer paused so you can explore.');});
 tile.addEventListener('pointerover',function(e){if(e.target.closest('.hwt-links'))stop();});
 tile.addEventListener('keydown',function(e){if(e.key==='Escape'){stop('Trailer paused.');}if(e.key==='ArrowRight'&&e.target.closest('.hwt-chapters')){e.preventDefault();choose((current+1)%allowed.length,false);chapters.find(function(b){return b.dataset.hwtChapter===allowed[current].dataset.workspace;}).focus();}if(e.key==='ArrowLeft'&&e.target.closest('.hwt-chapters')){e.preventDefault();choose((current-1+allowed.length)%allowed.length,false);chapters.find(function(b){return b.dataset.hwtChapter===allowed[current].dataset.workspace;}).focus();}});
 document.addEventListener('visibilitychange',function(){if(document.hidden)stop();});
 if(reduced.addEventListener)reduced.addEventListener('change',function(){stop();cancelMotion();updateControls();});
 scenes.forEach(function(scene){scene.querySelectorAll('img').forEach(function(image){function unavailable(){image.closest('.hwt-frame').hidden=true;scene.querySelector('.hwt-caption').textContent='Preview unavailable · open the workspace to explore';}image.addEventListener('error',unavailable);if(image.complete&&image.naturalWidth===0)unavailable();});});
 if('IntersectionObserver' in window){new IntersectionObserver(function(entries){inView=entries.some(function(e){return e.isIntersecting;});if(!inView)stop();else if(ready&&firstRun&&!tile.hidden&&!document.hidden&&!reduced.matches)start(true);},{threshold:.35}).observe(tile);}
 if('MutationObserver' in window){
  var guardObserver=new MutationObserver(function(){
   if(!ready)return;
   var nextAllowed=scenes.filter(canSee);
   if(nextAllowed.map(function(s){return s.dataset.workspace;}).join(',')!==allowed.map(function(s){return s.dataset.workspace;}).join(',')){
    stop();cancelMotion();firstRun=false;visibleScenes();
   }
  });
  scenes.forEach(function(scene){guardObserver.observe(scene,{attributes:true,attributeFilter:['data-rbac-applied','style']});});
 }
 if(window.itRbac&&itRbac.ready)itRbac.ready().then(initialize).catch(function(){tile.hidden=true;restore.hidden=true;tile.removeAttribute('data-hw-pending');});else{tile.hidden=true;restore.hidden=true;tile.removeAttribute('data-hw-pending');}
})();
