/* Native dialogs, real screenshots, and interruptible onboarding motion. */
(function () {
  'use strict';
  if (location.hostname !== 'dev-myprofile.nrpi.local') return;
  var dialog = document.querySelector('dialog[data-workspace-tour]');
  var trigger = document.getElementById('workspace-whats-new-link');
  var content = document.getElementById('workspace-whats-new-content');
  if (!dialog || !trigger || !content || typeof dialog.showModal !== 'function') return;
  var config;
  try { config = JSON.parse(content.textContent); } catch (_) { return; }
  dialog.querySelectorAll('img[data-cwn-preview-src]').forEach(function (image) { image.src = image.getAttribute('data-cwn-preview-src'); });
  var total = Array.isArray(config.steps) ? config.steps.length : 0;
  if (!total) return;
  var entrySearch = location.search;
  var screen = dialog.querySelector('.cwn-screen');
  var title = screen.querySelector('.cwn-title');
  var description = screen.querySelector('.cwn-description');
  var lesson = screen.querySelector('[data-cwn-lesson]');
  var topics = screen.querySelector('[data-cwn-topic]');
  var progress = screen.querySelector('[data-cwn-progress]');
  var stage = screen.querySelector('.cwn-stage');
  var note = screen.querySelector('.cwn-welcome-note');
  var preview = screen.querySelector('.cwn-preview');
  var shot = preview.querySelector('.cwn-shot');
  var imageStatus = preview.querySelector('[data-cwn-image-status]');
  var image = shot.querySelector('img');
  var focuses = shot.querySelector('.cwn-focuses');
  var track = dialog.querySelector('.cwn-track');
  var indicator = track.querySelector('.cwn-indicator');
  if (total !== 3) {
    track.querySelectorAll('span').forEach(function (node) { node.remove(); });
    for (var i = 0; i < total; i++) track.insertBefore(document.createElement('span'), indicator);
    track.style.width = (total * 36) + 'px';
  }
  var next = dialog.querySelector('[data-cwn-next]');
  var nextLabel = next.querySelector('span');
  var back = dialog.querySelector('[data-cwn-back]');
  var later = dialog.querySelector('[data-cwn-later]');
  var motionMedia = window.matchMedia('(prefers-reduced-motion: reduce)');
  var reduced = { get matches() { return motionMedia.matches || document.documentElement.getAttribute('data-reduce-motion') !== 'off'; }, addEventListener: function (name, callback) { motionMedia.addEventListener(name, callback); } };
  trigger.style.removeProperty('display');
  trigger.hidden = false;
  var ease = getComputedStyle(dialog).getPropertyValue('--cwn-ease').trim() || 'cubic-bezier(.23,1,.32,1)';
  var animations = new Set();
  var step = -1, epoch = 0, closing = false, returnFocus;

  // Account state is authoritative. Old, unscoped browser flags may belong to
  // another technician, so they are deliberately neither read nor imported.
  var guideOpened = false, savePromise;
  var syncNotice = document.createElement('span');
  syncNotice.setAttribute('role', 'status');
  syncNotice.hidden = true;
  trigger.after(syncNotice);
  function syncError(message, retry) {
    syncNotice.replaceChildren(document.createTextNode(message + ' '));
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'cwn-trigger';
    button.textContent = 'Retry guide sync';
    button.addEventListener('click', retry);
    syncNotice.appendChild(button);
    syncNotice.hidden = false;
    dialog.dataset.guideAccountState = 'error';
  }
  function accountRequest(method, path) {
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 8000);
    // Deliberately omit view-as headers/query: this is always the real caller's
    // onboarding preference, even while inspecting somebody else's profile.
    return fetch('/api/profile/guides' + path, {
      method: method, credentials: 'same-origin', cache: 'no-store',
      signal: controller.signal, keepalive: method === 'PUT'
    }).then(function (response) {
      if (!response.ok) throw new Error('Guide sync unavailable');
      return response.json();
    }).finally(function () { clearTimeout(timeout); });
  }
  function rememberDismissal() {
    if (savePromise) return savePromise;
    syncNotice.hidden = true;
    dialog.dataset.guideAccountState = 'saving';
    savePromise = accountRequest('PUT', '/' + encodeURIComponent(dialog.dataset.workspaceTour)).then(function (result) {
      if (!result.ok || result.dismissed !== true) throw new Error('Guide sync unavailable');
      dialog.dataset.guideAccountState = 'dismissed';
    }).catch(function () {
      syncError('Guide closed; dismissal has not synced to your account.', rememberDismissal);
    }).finally(function () { savePromise = null; });
    return savePromise;
  }

  function motionAllowed(event) {
    return !reduced.matches && typeof screen.animate === 'function' && (!event || event.detail > 0);
  }
  function animate(node, frames, options) {
    var animation = node.animate(frames, Object.assign({ duration: 250, easing: ease }, options));
    animations.add(animation);
    animation.finished.then(function () { animations.delete(animation); }, function () { animations.delete(animation); });
    return animation;
  }
  function cancelMotion() {
    epoch++;
    animations.forEach(function (animation) { animation.cancel(); });
    animations.clear();
    dialog.querySelectorAll('.cwn-ghost').forEach(function (ghost) { ghost.remove(); });
    image.onload = null;
  }
  // The browser may retain the previous decoded image while a new src loads.
  // Optional training markup keeps that image hidden until the current read ends.
  function updateImageStatus() {
    if (!imageStatus || preview.hidden || !image.complete) return;
    var loaded = image.naturalWidth > 0;
    shot.hidden = !loaded;
    imageStatus.hidden = loaded;
    imageStatus.textContent = loaded ? '' : 'Screenshot unavailable. The guidance for this topic is still available.';
  }
  if (imageStatus) {
    image.addEventListener('load', updateImageStatus);
    image.addEventListener('error', updateImageStatus);
  }
  function render() {
    var welcome = step < 0;
    progress.textContent = welcome ? (config.training ? 'Training guide' : 'A quick tour') : 'Step ' + (step + 1) + ' of ' + total;
    title.textContent = welcome ? config.title : config.steps[step].title;
    description.textContent = welcome ? config.description : config.steps[step].description;
    if (topics) topics.value = String(step);
    if (lesson) {
      lesson.hidden = welcome;
      var actions = lesson.querySelector('[data-cwn-actions]');
      actions.replaceChildren();
      if (!welcome) {
        (config.steps[step].actions || []).forEach(function (text) {
          var item = document.createElement('li'); item.textContent = text; actions.appendChild(item);
        });
        lesson.querySelector('[data-cwn-meaning]').textContent = config.steps[step].meaning || '';
      }
    }
    stage.hidden = !welcome;
    note.hidden = !welcome;
    preview.hidden = welcome;
    later.hidden = !welcome;
    back.hidden = welcome;
    track.hidden = welcome;
    nextLabel.textContent = welcome ? (config.guide ? 'Show me how' : 'Take a quick tour') : step === total - 1 ? 'Got it' : 'Next';
    indicator.style.transform = 'translateX(' + Math.max(0, step) * 36 + 'px)';
    focuses.replaceChildren();
    if (!welcome) {
      var item = config.steps[step];
      if (imageStatus) {
        shot.hidden = true;
        imageStatus.hidden = false;
        imageStatus.textContent = 'Loading screenshot…';
      }
      image.src = item.image;
      updateImageStatus();
      image.alt = item.alt;
      item.focus.forEach(function (rect) {
        var frame = document.createElement('div');
        frame.className = 'cwn-focus';
        frame.style.cssText = 'left:' + rect[0] + '%;top:' + rect[1] + '%;width:' + rect[2] + '%;height:' + rect[3] + '%';
        var ring = document.createElement('span');
        ring.className = 'cwn-focus-ring';
        frame.appendChild(ring);
        focuses.appendChild(frame);
      });
    }
  }
  function screenshotMotion() {
    var generation = epoch;
    function reveal() {
      if (generation !== epoch || !dialog.open || step < 0 || reduced.matches) return;
      animate(shot, [{ transform: 'scale(1.035)', opacity: .6 }, { transform: 'scale(1)', opacity: 1 }], { duration: 280 });
      focuses.querySelectorAll('.cwn-focus').forEach(function (frame, index) {
        animate(frame, [{ clipPath: 'inset(0 100% 0 0)', opacity: .3 }, { clipPath: 'inset(0 0 0 0)', opacity: 1 }], { duration: 650, delay: 120 + index * 80, fill: 'backwards' });
        animate(frame.firstChild, [{ transform: 'scale(1)', opacity: .6 }, { transform: 'scale(1.055)', opacity: 0 }], { duration: 750, delay: 450 + index * 80, iterations: 2 });
      });
    }
    if (image.complete && image.naturalWidth) reveal();
    else image.onload = reveal;
  }
  function welcomeMotion() {
    var flow = stage.querySelector('.cwn-ai-flow');
    if (flow) {
      animate(flow.querySelector('.cwn-ai-orbit'), [{ transform: 'translate(-50%,-50%) scale(.5)', opacity: 0 }, { opacity: .55, offset: .25 }, { transform: 'translate(-50%,-50%) scale(1.18)', opacity: 0 }], { duration: 1200 });
      flow.querySelectorAll('.cwn-ai-node').forEach(function (node, index) {
        animate(node, [{ transform: 'translateY(22px) rotateX(55deg) scale(.8)', opacity: 0 }, { transform: 'translateY(0) rotateX(0) scale(1)', opacity: 1 }], { duration: 650, delay: 240 + index * 130, fill: 'backwards' });
      });
      flow.querySelectorAll('.cwn-ai-wire').forEach(function (wire, index) {
        animate(wire, [{ transform: 'scaleX(0)', opacity: 0 }, { transform: 'scaleX(1)', opacity: 1 }], { duration: 650, delay: 400 + index * 180, fill: 'backwards' });
        animate(wire.querySelector('em'), [{ transform: 'translateX(-100%)', opacity: 0 }, { opacity: 1, offset: .25 }, { transform: 'translateX(500%)', opacity: 0 }], { duration: 1000, delay: 600 + index * 180 });
      });
    }
    stage.querySelectorAll('.cwn-mini').forEach(function (card, index) {
      var destination = getComputedStyle(card).transform;
      animate(card, [
        { transform: 'translate(0,34px) rotate(0deg) scale(.84)', opacity: 0 },
        { transform: destination, opacity: 1 }
      ], { duration: 650, delay: 80 + index * 80, fill: 'backwards' });
      animate(card.querySelector('.cwn-mini-sheen'), [
        { transform: 'translateX(-100%)', opacity: 0 },
        { opacity: .7, offset: .4 },
        { transform: 'translateX(100%)', opacity: 0 }
      ], { duration: 1000, delay: 400 + index * 80 });
    });
    animate(screen.querySelector('.cwn-emblem'), [
      { transform: 'rotate(-50deg) scale(.85)', opacity: 0 },
      { transform: 'rotate(0deg) scale(1)', opacity: 1 }
    ], { duration: 650 });
  }
  function go(destination, event) {
    if (config.guide) resetDepth();
    if (closing) return;
    var useMotion = motionAllowed(event), direction = destination > step ? 1 : -1;
    cancelMotion();
    var ghost;
    if (useMotion) {
      ghost = screen.cloneNode(true);
      ghost.classList.add('cwn-ghost');
      ghost.setAttribute('aria-hidden', 'true');
      ghost.inert = true;
      ghost.querySelectorAll('[id],[aria-live]').forEach(function (node) { node.removeAttribute('id'); node.removeAttribute('aria-live'); });
      screen.parentNode.appendChild(ghost);
    }
    step = destination;
    dialog.toggleAttribute('data-instant', !useMotion);
    render();
    if (config.training) dialog.scrollTop = 0;
    title.focus({ preventScroll: true });
    if (!useMotion) return;
    var outgoing = animate(ghost, [
      { transform: 'translateX(0) scale(1)', opacity: 1 },
      { transform: 'translateX(' + -direction * 28 + 'px) scale(.985)', opacity: 0 }
    ], { duration: 180 });
    outgoing.finished.then(function () { ghost.remove(); }, function () { ghost.remove(); });
    animate(screen, [
      { transform: 'translateX(' + direction * 28 + 'px)', opacity: 0 },
      { transform: 'translateX(0)', opacity: 1 }
    ], { duration: 250 });
    if (step < 0) welcomeMotion(); else screenshotMotion();
  }
  function open(event, startStep) {
    if (dialog.open) return;
    guideOpened = true;
    cancelMotion();
    returnFocus = document.activeElement;
    closing = false;
    step = startStep === 0 ? 0 : -1;
    dialog.removeAttribute('data-exiting');
    dialog.toggleAttribute('data-instant', !motionAllowed(event));
    render();
    dialog.showModal();
    if (config.training) dialog.scrollTop = 0;
    next.focus({ preventScroll: true });
    if (!motionAllowed(event)) return;
    animate(dialog, [
      { transform: 'translateY(18px) scale(.95)', opacity: 0 },
      { transform: 'translateY(0) scale(1)', opacity: 1 }
    ], { duration: 250 });
    [screen.querySelector('.cwn-progress'), title, description, note].forEach(function (node, index) {
      animate(node, [{ transform: 'translateY(8px)', opacity: 0 }, { transform: 'translateY(0)', opacity: 1 }], { duration: 250, delay: index * 50, fill: 'backwards' });
    });
    // Fade the footer in place: translating its bottom edge creates a transient scrollbar.
    animate(dialog.querySelector('.cwn-footer'), [{ opacity: 0 }, { opacity: 1 }], { duration: 250, delay: 200, fill: 'backwards' });
    if (step < 0) welcomeMotion(); else screenshotMotion();
  }
  function finishClose() {
    cancelMotion();
    dialog.close();
  }
  function close(event) {
    if (!dialog.open || closing) return;
    rememberDismissal();
    if (!motionAllowed(event)) { finishClose(); return; }
    if (closing) return;
    cancelMotion();
    closing = true;
    dialog.setAttribute('data-exiting', '');
    var exit = animate(dialog, [
      { transform: 'translateY(0) scale(1)', opacity: 1 },
      { transform: 'translateY(12px) scale(.97)', opacity: 0 }
    ], { duration: 180 });
    exit.finished.then(finishClose, function () {});
  }
  if (topics) topics.addEventListener('change', function (event) {
    var destination = Number(topics.value);
    if (Number.isInteger(destination) && destination >= -1 && destination < total) go(destination, event);
  });
  trigger.addEventListener('click', function (event) { event.preventDefault(); open(event); });
  next.addEventListener('click', function (event) { if (step === total - 1) close(event); else go(step + 1, event); });
  back.addEventListener('click', function (event) { go(Math.max(-1, step - 1), event); });
  later.addEventListener('click', close);
  dialog.querySelector('[data-cwn-close]').addEventListener('click', close);
  dialog.addEventListener('cancel', function (event) { event.preventDefault(); close(event); });
  dialog.addEventListener('close', function () {
    closing = false;
    dialog.removeAttribute('data-exiting');
    var target = returnFocus && returnFocus !== document.body && returnFocus.isConnected ? returnFocus : trigger;
    target.focus({ preventScroll: true });
  });
  dialog.addEventListener('keydown', function (event) {
    event.stopPropagation();
    if (event.key !== 'Tab') return;
    var buttons = Array.prototype.filter.call(dialog.querySelectorAll('button'), function (button) { return !button.disabled && button.getClientRects().length > 0; });
    var first = buttons[0], last = buttons[buttons.length - 1];
    if (event.shiftKey && (document.activeElement === first || document.activeElement === title)) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });
  function preferenceChanged() {
    if (!reduced.matches) return;
    var wasClosing = closing;
    cancelMotion();
    dialog.setAttribute('data-instant', '');
    if (wasClosing) finishClose();
  }
  if (reduced.addEventListener) reduced.addEventListener('change', preferenceChanged);
  // AI's welcome has pointer-driven depth on the decorative screenshot stage.
  var depthFrame = 0, depthPoint;
  var finePointer = matchMedia('(hover:hover) and (pointer:fine)');
  function resetDepth() {
    if (depthFrame) cancelAnimationFrame(depthFrame);
    depthFrame = 0;
    stage.style.transform = '';
  }
  dialog.addEventListener('pointermove', function (event) {
    if (!config.guide || step >= 0 || closing || reduced.matches || !finePointer.matches || event.pointerType === 'touch') return;
    depthPoint = { x: event.clientX, y: event.clientY };
    if (depthFrame) return;
    depthFrame = requestAnimationFrame(function () {
      depthFrame = 0;
      var rect = dialog.getBoundingClientRect();
      var x = Math.max(-1, Math.min(1, (depthPoint.x - rect.left - rect.width / 2) / (rect.width / 2)));
      var y = Math.max(-1, Math.min(1, (depthPoint.y - rect.top - rect.height / 2) / (rect.height / 2)));
      stage.style.transform = 'perspective(900px) rotateX(' + (-y * 4) + 'deg) rotateY(' + (x * 6) + 'deg)';
    });
  });
  dialog.addEventListener('pointerleave', resetDepth);
  dialog.addEventListener('keydown', resetDepth);
  dialog.addEventListener('close', resetDepth);
  if (reduced.addEventListener) reduced.addEventListener('change', function () { if (reduced.matches) resetDepth(); });
  function maybeWelcome() {
    if (config.triggerBefore) {
      var anchor = document.querySelector(config.triggerBefore);
      if (!anchor) return;
      anchor.before(trigger);
      trigger.hidden = false;
    }
    if (config.rbacPage && (!window.itRbac || !itRbac.canAccess(config.rbacPage))) return;
    var params = new URLSearchParams(entrySearch);
    if (params.get('tour') === dialog.dataset.workspaceTour) {
      if (document.querySelector('.idm-overlay.show, .modal-backdrop.show, #modal-backdrop.open, #import-backdrop.open, dialog[open], #iv360-backdrop.open')) return;
      open(undefined, config.guide ? -1 : 0);
      // Preserve filters the workspace may have added while loading.
      params = new URLSearchParams(location.search);
      params.delete('tour');
      var search = params.toString();
      history.replaceState(history.state, '', location.pathname + (search ? '?' + search : '') + location.hash);
      return;
    }
    syncNotice.hidden = true;
    dialog.dataset.guideAccountState = 'loading';
    accountRequest('GET', '').then(function (result) {
      if (!result.dismissed || typeof result.dismissed !== 'object') throw new Error('Guide sync unavailable');
      var seen = result.dismissed[dialog.dataset.workspaceTour] === true;
      // A manual replay or dismissal while the read was in flight wins.
      if (guideOpened) return;
      dialog.dataset.guideAccountState = seen ? 'dismissed' : 'unseen';
      if (seen) return;
      if (document.querySelector('.idm-overlay.show, .modal-backdrop.show, #modal-backdrop.open, #import-backdrop.open, dialog[open], #iv360-backdrop.open')) return;
      open();
    }).catch(function () {
      if (!guideOpened) syncError('Guide status is unavailable. You can still open How to use.', maybeWelcome);
    });
  }
  var started = false;
  function ready() {
    if (started || !document.documentElement.hasAttribute('data-reduce-motion')) return;
    started = true;
    maybeWelcome();
  }
  var prefObserver = new MutationObserver(function () { preferenceChanged(); if (reduced.matches) resetDepth(); ready(); });
  prefObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-reduce-motion'] });
  if (document.readyState === 'complete') ready();
  else window.addEventListener('load', ready, { once: true });
})();
