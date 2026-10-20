/* Screenshot-led introduction. No account data, API calls or backend changes. */
(function () {
  'use strict';
  var dialog = document.getElementById('identity-whats-new');
  var trigger = document.getElementById('identity-whats-new-link');
  if (!dialog || !trigger || typeof dialog.showModal !== 'function') return;
  var seenKey = 'corpit:identity:whats-new:2026-10-18-v1';
  var step = -1;
  var returnFocus;
  var title = dialog.querySelector('.iwn-title');
  var description = dialog.querySelector('.iwn-description');
  var progress = dialog.querySelector('.iwn-progress');
  var preview = dialog.querySelector('.iwn-preview');
  var image = preview.querySelector('img');
  var note = dialog.querySelector('.iwn-welcome-note');
  var dots = dialog.querySelector('.iwn-dots');
  var back = dialog.querySelector('[data-iwn-back]');
  var next = dialog.querySelector('[data-iwn-next]');
  var later = dialog.querySelector('[data-iwn-later]');
  var steps = [
    {
      title: 'Find the person',
      description: 'Search by name, username or email. People you look up appear in Recent, so you can return to them quickly.',
      image: 'find-person.webp',
      alt: 'DEV account search beside the Accounts panel, with the search field and Recent tab highlighted.'
    },
    {
      title: 'Start with the issue',
      description: 'Choose Can’t sign in, Device issue, Missing access or Offboarding review. Pick a task first, or look up the person and continue from there.',
      image: 'choose-task.webp',
      alt: 'DEV task shortcuts: Can’t sign in, Device issue, Missing access and Offboarding review.'
    },
    {
      title: 'Explore the workspace',
      description: 'Use the left navigation to move between Devices, Sign-ins, Security and Group access. Available tools follow your access permissions.',
      image: 'explore-workspace.webp',
      alt: 'DEV Identity support page with the left workspace navigation highlighted.'
    }
  ];
  function render(moveFocus) {
    var welcome = step < 0;
    progress.textContent = welcome ? 'A quick tour' : 'Step ' + (step + 1) + ' of 3';
    title.textContent = welcome ? 'What’s new in Identity support' : steps[step].title;
    description.textContent = welcome
      ? 'Find people, investigate device issues, and review access from one workspace. Take a quick look at where to start.'
      : steps[step].description;
    preview.hidden = welcome;
    note.hidden = !welcome;
    back.hidden = welcome;
    later.hidden = !welcome;
    dots.hidden = welcome;
    next.textContent = welcome ? 'Take a quick tour' : step === 2 ? 'Got it' : 'Next';
    if (!welcome) {
      image.src = '/assets/identity-whats-new/' + steps[step].image + '?v=20261018a';
      image.alt = steps[step].alt;
      Array.prototype.forEach.call(dots.children, function (dot, i) {
        dot.className = i === step ? 'current' : '';
      });
    }
    if (moveFocus) title.focus({ preventScroll: true });
  }
  function open() {
    if (dialog.open) return;
    returnFocus = document.activeElement;
    step = -1;
    render(false);
    dialog.showModal();
    next.focus({ preventScroll: true });
  }
  function close() { dialog.close(); }
  trigger.addEventListener('click', function (event) { event.preventDefault(); open(); });
  next.addEventListener('click', function () {
    if (step === 2) { close(); return; }
    step++;
    render(true);
  });
  back.addEventListener('click', function () { step = Math.max(-1, step - 1); render(true); });
  later.addEventListener('click', close);
  dialog.querySelector('[data-iwn-close]').addEventListener('click', close);
  dialog.addEventListener('close', function () {
    try { localStorage.setItem(seenKey, 'seen'); } catch (_) { /* Storage may be unavailable. */ }
    var target = returnFocus && returnFocus !== document.body && returnFocus.isConnected ? returnFocus : trigger;
    target.focus({ preventScroll: true });
  });
  /* Keep existing page shortcuts from acting on the workspace behind the dialog. */
  dialog.addEventListener('keydown', function (event) {
    event.stopPropagation();
    if (event.key !== 'Tab') return;
    var buttons = Array.prototype.filter.call(dialog.querySelectorAll('button'), function (button) {
      return !button.disabled && button.getClientRects().length > 0;
    });
    var first = buttons[0], last = buttons[buttons.length - 1];
    if (event.shiftKey && (document.activeElement === first || document.activeElement === title)) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus();
    }
  });
  function maybeWelcome() {
    try { if (localStorage.getItem(seenKey)) return; } catch (_) {}
    // Preserve direct links into a person's record or another tool.
    if (location.search || (location.hash && location.hash !== '#overview')) return;
    if (document.querySelector('.idm-overlay.show, .modal-backdrop.show, dialog[open]')) return;
    open();
  }
  if (document.readyState === 'complete') maybeWelcome();
  else window.addEventListener('load', maybeWelcome, { once: true });
})();
