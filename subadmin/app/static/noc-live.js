/* Interactive NOC feedback uses the verified health-frame protocol only. */
(function() {
  'use strict';
  var strip = document.querySelector('.noc-live-strip');
  if (!strip) return;
  var labels = {bad:'Critical',warn:'Needs review',unknown:'Unknown',maint:'Maintenance',ok:'Healthy'};
  var states = ['bad','warn','unknown','maint','ok'];
  var reduced = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : {matches:false};
  var baseline = null, latest = null, history = [], notices = new Map(), completedAt = null;
  var requestTimer = null, suppressMotion = false, connected = false;
  var live = document.getElementById('noc-live-status'), age = document.getElementById('noc-live-age');
  var progress = strip.querySelector('[role=progressbar]'), bar = document.getElementById('noc-mix-bar');
  var list = document.getElementById('noc-change-list'), count = document.getElementById('noc-changes-count');
  var inspect = document.getElementById('noc-filter-changed'), announcement = document.getElementById('noc-change-announcement');
  var animations = new Map();
  function emit(name, detail) { document.dispatchEvent(new CustomEvent(name, {detail:detail})); }
  function canMove() { return !reduced.matches && !suppressMotion && !document.hidden && document.body.dataset.hybridModule==='health'; }
  function cue(element, frames, duration) {
    if (!element || !canMove() || !element.animate) return;
    var old = animations.get(element); if (old) old.cancel();
    var easing = getComputedStyle(document.documentElement).getPropertyValue('--ease-out').trim() || 'cubic-bezier(0.23, 1, 0.32, 1)';
    var animation = element.animate(frames, {duration:duration, easing:easing});
    animations.set(element, animation);
    animation.finished.then(function(){if(animations.get(element)===animation)animations.delete(element);},function(){});
  }
  function stopMotion() { animations.forEach(function(a){a.cancel();}); animations.clear(); }
  if (reduced.addEventListener) reduced.addEventListener('change', function(){if(reduced.matches)stopMotion();});
  document.addEventListener('visibilitychange', function(){if(document.hidden)stopMotion();});
  function filter(state) { emit('noc-health-filter', {state:state}); }
  var mixButtons = {};
  var legend = document.createElement('div'); legend.className='noc-mix-legend'; bar.after(legend);
  states.forEach(function(state){
    var b=document.createElement('button'); b.type='button'; b.className='noc-mix-segment '+state;
    b.hidden=true;b.dataset.state=state; b.addEventListener('click',function(){filter(state);}); bar.append(b);
    var l=document.createElement('button'); l.type='button'; l.className='noc-mix-key '+state;
    l.disabled=true;l.append(document.createElement('i'),document.createElement('span'));l.querySelector('span').textContent=labels[state]+' —'; l.firstChild.setAttribute('aria-hidden','true');
    l.addEventListener('click',function(){filter(state);}); legend.append(l); mixButtons[state]={segment:b,key:l};
  });
  function selection() {
    var state=document.getElementById('hybrid-check-state').value;
    states.forEach(function(s){mixButtons[s].key.setAttribute('aria-pressed',String(s===state));mixButtons[s].segment.setAttribute('aria-pressed',String(s===state));});
  }
  function paintMix(snapshot) {
    var totals={bad:0,warn:0,unknown:0,maint:0,ok:0};snapshot.rows.forEach(function(r){totals[r.state]++;});
    states.forEach(function(s){
      var pair=mixButtons[s],n=totals[s],share=snapshot.rows.length?n/snapshot.rows.length*100:0;
      pair.segment.style.flexBasis='0';pair.segment.style.flexGrow=String(n);pair.segment.hidden=!n;
      pair.segment.setAttribute('aria-label',labels[s]+': '+n+' of '+snapshot.rows.length+' checks. Filter these checks.');
      pair.segment.title=labels[s]+': '+n+' ('+Math.round(share)+'%)';
      pair.key.querySelector('span').textContent=labels[s]+' '+n;pair.key.disabled=!n;
    });
    document.getElementById('noc-mix-scope').textContent=snapshot.rows.length+' reported checks'+(snapshot.pending?' · refresh in progress':'');
    selection();
  }
  function ageLabel() {
    if (!completedAt || document.hidden) return;
    var seconds=Math.max(0,Math.floor((Date.now()-completedAt)/1000));
    age.textContent='Snapshot received '+(seconds<60?seconds+'s':Math.floor(seconds/60)+'m')+' ago';
    age.title='Time since a completed snapshot arrived in this tab. Check source timestamps for collection freshness.';
  }
  function busy(value, text) {
    strip.classList.toggle('is-refreshing',value); strip.classList.toggle('motion-muted',suppressMotion);
    strip.setAttribute('aria-busy',String(value)); live.textContent=text;
  }
  function markRows() {
    document.querySelectorAll('[data-check-id]').forEach(function(row){
      var record=notices.get(row.dataset.checkId),note=row.querySelector('.noc-change-note');
      if (!record || !latest) { if(note)note.remove(); return; }
      if(!note){note=document.createElement('span');note.className='noc-change-note';row.firstChild.append(note);}
      note.textContent='Changed: '+record.from+' → '+record.to;
    });
    selection();
  }
  function paintHistory() {
    var active=document.activeElement,focusKey=active&&active.dataset&&active.dataset.nocChange;
    count.textContent=String(history.length); list.replaceChildren();
    var activeIds = new Set(latest?latest.rows.map(function(r){return r.id;}):[]);
    inspect.disabled=!history.some(function(r){return activeIds.has(r.id);}) || !connected;
    if (!history.length) { var empty=document.createElement('li');empty.textContent=baseline?'No status changes since the first completed snapshot.':'No completed comparison yet. Watching for status changes.';list.append(empty);return; }
    history.forEach(function(record){
      var item=document.createElement('li'),button=document.createElement('button');button.type='button';button.className='noc-change-link';
      button.disabled=!connected||!activeIds.has(record.id);button.textContent=record.name;button.setAttribute('aria-label','Open current evidence for '+record.name);
      button.dataset.nocChange=record.id+'|'+record.at+'|'+record.from+'|'+record.to;
      button.addEventListener('click',function(e){emit('noc-evidence-request',{id:record.id,trigger:button,animate:e.detail>0});});
      var state=document.createElement('span');state.textContent=record.from+' → '+record.to;
      var time=document.createElement('time');time.dateTime=new Date(record.at).toISOString();time.textContent=new Date(record.at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
      item.append(button,state,time);list.append(item);
    });
    if(focusKey&&!active.isConnected){var restore=Array.from(list.querySelectorAll('[data-noc-change]')).find(function(b){return b.dataset.nocChange===focusKey&&!b.disabled;});if(restore)restore.focus({preventScroll:true});}
  }
  function complete(snapshot) {
    var now=Date.now(), map=new Map(snapshot.rows.map(function(r){return [r.id,r];})), changes=[];
    if (baseline) {
      map.forEach(function(r,id){var previous=baseline.get(id);if(previous&&previous.state!==r.state)changes.push({id:id,name:r.name,from:labels[previous.state],to:labels[r.state],state:r.state,at:now});});
      baseline.forEach(function(r,id){if(!map.has(id))changes.push({id:id,name:r.name,from:labels[r.state],to:'Not in snapshot',at:now});});
    }
    baseline=map;completedAt=now;ageLabel();
    changes.forEach(function(change){notices.set(change.id,change);});
    if(changes.length){
      history=changes.concat(history).slice(0,12);
      announcement.textContent=changes.length+' status change'+(changes.length===1?'':'s')+' observed in the completed refresh.';
      var retained=new Set(history.map(function(r){return r.id;}));notices.forEach(function(_,id){if(!retained.has(id))notices.delete(id);});
      document.querySelectorAll('.noc-metric').forEach(function(metric){if(changes.some(function(r){return r.state===metric.dataset.nocState;}))cue(metric.querySelector('b'),[{opacity:0.45},{opacity:1}],240);});
      cue(count,[{opacity:0.45},{opacity:1}],240);
    }
    emit('noc-health-changes',{ids:Array.from(new Set(history.map(function(r){return r.id;}))).filter(function(id){return map.has(id);})});
    paintHistory();markRows();
  }
  function receive(snapshot) {
    clearTimeout(requestTimer);requestTimer=null;connected=true;latest=snapshot;
    strip.classList.remove('is-unavailable');paintMix(snapshot);
    progress.hidden=!snapshot.pending;
    if(snapshot.pending){
      var answered=snapshot.sourceCount-snapshot.pending,percent=snapshot.sourceCount?answered/snapshot.sourceCount*100:0;
      progress.setAttribute('aria-valuenow',String(Math.round(percent)));progress.setAttribute('aria-valuetext',answered+' of '+snapshot.sourceCount+' sources answered');
      progress.querySelector('i').style.transform='scaleX('+(percent/100)+')';
      busy(true,'Refreshing · '+answered+' of '+snapshot.sourceCount+' sources answered');
    }else{
      busy(false,'Snapshot received · '+snapshot.sourceCount+' sources answered');complete(snapshot);suppressMotion=false;strip.classList.remove('motion-muted');
    }
  }
  function unavailable() {
    clearTimeout(requestTimer);requestTimer=null;stopMotion();connected=false;latest=null;baseline=null;completedAt=null;notices.clear();
    busy(false,'Health snapshot unavailable');strip.classList.add('is-unavailable');progress.hidden=true;age.textContent='';
    states.forEach(function(s){mixButtons[s].segment.hidden=true;mixButtons[s].key.disabled=true;mixButtons[s].key.querySelector('span').textContent=labels[s]+' —';});
    document.getElementById('noc-mix-scope').textContent='Coverage unknown';paintHistory();
  }
  document.addEventListener('noc-health-snapshot',function(e){receive(e.detail);});
  document.addEventListener('noc-health-unavailable',unavailable);
  document.addEventListener('noc-checks-painted',markRows);
  document.addEventListener('noc-refresh-request',function(e){
    suppressMotion=!(e.detail&&e.detail.animate);busy(true,'Refresh requested · waiting for sources');progress.hidden=true;
    clearTimeout(requestTimer);requestTimer=setTimeout(function(){busy(false,'Refresh response not yet received. Retry when ready.');document.getElementById('hybrid-refresh').disabled=false;suppressMotion=false;},15000);
  });
  document.addEventListener('noc-evidence-open',function(e){if(e.detail&&e.detail.animate)cue(document.getElementById('hybrid-evidence'),[{opacity:0.4,transform:'translateX(8px)'},{opacity:1,transform:'translateX(0)'}],200);});
  inspect.addEventListener('click',function(){filter('changed');});
  window.addEventListener('console-route',stopMotion);
  var clock=setInterval(ageLabel,15000);window.addEventListener('pagehide',function(){clearInterval(clock);clearTimeout(requestTimer);stopMotion();});
  if(window.NOC_HEALTH_SNAPSHOT)receive(window.NOC_HEALTH_SNAPSHOT);
  else if(!document.getElementById('health-workspace'))unavailable();
})();
