/* On-demand page guidance. Tours explain visible controls; they never operate them. */
(function () {
  'use strict';
  var trigger = document.getElementById('noc-help');
  if (!trigger || typeof HTMLDialogElement === 'undefined') return;
  var dialog = document.createElement('dialog');
  dialog.id = 'noc-guide';
  dialog.className = 'noc-guide';
  dialog.setAttribute('aria-labelledby', 'noc-guide-title');
  dialog.setAttribute('aria-describedby', 'noc-guide-copy');
  dialog.innerHTML = '<div class="noc-guide-ring" aria-hidden="true" hidden></div><section class="noc-guide-card">' +
    '<header><span class="noc-guide-kicker">PAGE GUIDE</span><button type="button" class="noc-guide-close" aria-label="Close page guide">×</button></header>' +
    '<div class="noc-guide-reading" aria-live="polite" aria-atomic="true"><h2 id="noc-guide-title"></h2><p id="noc-guide-copy"></p></div>' +
    '<div class="noc-guide-topics"></div><div class="noc-guide-tip"></div>' +
    '<footer><button type="button" class="btn" data-guide-back>Back</button><span class="noc-guide-progress"></span><button type="button" class="btn pri" data-guide-next>Walk me through</button></footer></section>';
  document.body.append(dialog);
  var card = dialog.querySelector('.noc-guide-card'), ring = dialog.querySelector('.noc-guide-ring');
  var title = dialog.querySelector('h2'), copy = dialog.querySelector('#noc-guide-copy');
  var topics = dialog.querySelector('.noc-guide-topics'), tip = dialog.querySelector('.noc-guide-tip');
  var back = dialog.querySelector('[data-guide-back]'), next = dialog.querySelector('[data-guide-next]');
  var progress = dialog.querySelector('.noc-guide-progress'), kicker = dialog.querySelector('.noc-guide-kicker');
  var current, steps = [], index = -1, returnFocus, startScroll, frameScroll, selectedTarget;
  function step(target, heading, body) { return {target: target, title: heading, body: body}; }
  var shell = [
    step('#nav', 'Move between workspaces', 'The main rail groups the console into diagnostics, access, services, operations and settings. The links underneath change to match the workspace you are viewing.'),
    step('#cmdk-open', 'Jump straight to a destination', 'Search for a service, person or setting here. You can also press ⌘K on Mac or Ctrl+K on Windows to open search.')
  ];
  var stateTopic = ['What do the health states mean?', 'Critical means the source reports a failure. Needs review means it reports a warning. Unknown means usable evidence is missing or unavailable; it does not establish health. Healthy reflects the latest source result. Maintenance identifies a known maintenance condition.'];
  var freshnessTopic = ['How recent is this evidence?', 'Check the reported time and the source details before acting. A refresh asks the workspace for newer results; it does not repair a service. A stale or missing result can need investigation even when the underlying system is running.'];
  var saveTopic = ['What happens when I save?', 'An unsaved change is a draft. Save sends it to the owning service, which checks your permissions and returns the result. Read the confirmation or refusal: some settings are stored before they take effect, and some recovery settings record a desired state. Keep a draft until the save is confirmed.'];
  var ownershipTopic = ['Which access system owns this?', 'Console permissions, Hub page grants, site admission and Access Portal approvals have different owners. Follow the page’s ownership notes and handoffs. Access shown here is evidence; a review or a proposed change does not automatically grant or remove access.'];
  var releaseTopic = ['How does development relate to production?', 'The DEV badge identifies development. Editing this console’s development files does not publish them to production. Production releases go through Launch Pad preparation, sign-off and launch. Operational controls may show production evidence, so read their target and confirmation before using them.'];
  function config() {
    var hash = location.hash.slice(1) || 'overview', module = document.body.dataset.hybridModule;
    var name = document.getElementById('noc-current').textContent || 'this workspace';
    var c = {name: name, intro: 'Use the workspace links to choose a task, inspect its evidence and follow the control that owns the change.', topics: [freshnessTopic, ownershipTopic, releaseTopic], steps: [step('[data-view]:not([hidden]) h2', 'Start with the page’s purpose', 'The heading and description explain the task in this workspace. Read the source and ownership notes before using a control.')]};
    if (hash === 'overview' || hash.startsWith('overview/')) {
      c.intro = 'Use the server console to inspect environment health, resources, runtime services, databases, backups, users and logs. Every number must have a real source; missing collectors remain Unknown.';
      c.topics = [stateTopic, freshnessTopic, ['Why are some metrics not measured?', 'The current sources do not establish online people, independent remote-node metrics or full request distributions. Sampled request logs cannot establish p95, total traffic or an overall error percentage. Coverage names each missing collector.']];
      c.steps = [step('#server-environment', 'Confirm the observed environment', 'Development reads its own sources. Production cluster evidence represents the responding node; remote registration alone is not deep monitoring.'), step('#noc-workspace-nav', 'Choose an investigation view', 'The workspace links open Servers, Performance, Services, Databases, Backups, Users, Logs and Coverage. Settings and controlled repair tools retain their existing permissions.'), step('#server-content', 'Read current evidence and gaps', 'Dials show reported utilization. Graphs contain completed observations since this tab opened, with gaps for missing data. Logs identify their source cap and window.'), step('#server-help', 'Understand the measurement', 'Explain this page describes the current view, including sampling limits and which values are not measured.'), step('#server-refresh', 'Request newer source evidence', 'Refresh asks the existing health service for another read-only snapshot. Opening a view never runs an integrity scan, schedules jobs or changes permissions.')];
    } else if (hash.indexOf('health/') === 0) {
      var section = hash.split('/')[1];
      c.topics = [stateTopic, freshnessTopic, saveTopic];
      if (section === 'settings') {
        c.intro = 'Set the limits that turn host, job and integration evidence into warnings or critical checks. Maintenance windows identify planned work. Read the owning service’s apply notes before saving.';
        c.steps = [step('@health #hc-thr', 'Understand the alert limits', 'Thresholds decide when a reading becomes warning or critical. Check the units and ordering of the values. The Server Health service decides whether you can save.'), step('@health #hc-mnt', 'Identify planned maintenance', 'A window in progress marks affected items as Maintenance. Read the target and timing before recording a window or task.'), step('@health #hc-panel-settings .hc-card:last-child', 'Find other settings by owner', 'The settings directory links to the existing owners of service configuration. Each editor keeps its permissions and audit trail.')];
      } else if (section === 'journeys') {
        c.intro = 'Find a person’s recorded activity by exact email or UPN and a time window. Inspect the timeline alongside each source’s coverage; missing activity is not proof that nothing happened.';
        c.topics = [freshnessTopic, ['What is recorded?', 'This workspace combines the available activity sources. Access Portal recording excludes form contents and keystrokes and is retained for 90 days. Read each source’s coverage notes; every person lookup is audited under your name.'], ['What does missing activity mean?', 'An unavailable source or a gap in recording is different from an empty result. Check the selected time window and the source coverage before drawing a conclusion about someone’s activity.']];
        c.steps = [step('@health #hc-j-pform', 'Choose the person and window', 'Enter the exact email or UPN, choose the time window and select Find activity. This guide does not perform a lookup or submit the form.'), step('@health #hc-j-person', 'Read the timeline with coverage', 'The result identifies available and unavailable sources. Read event evidence and coverage together; absence of a recorded event does not establish that the action never happened.'), step('@health .hc-activity-summary', 'Inspect Portal recording', 'Expand Portal collection overview to inspect the recording summary and possible form-routing findings. These are observations for investigation.')];
      } else {
        c.intro = 'Inspect the complete health snapshot, filter the checks and read each source’s evidence and timestamp before acting.';
        c.steps = [step('@health #hc-verdict', 'Understand the overall verdict', 'The verdict summarizes the reporting sources. Why this verdict explains the checks behind it. Not reporting is never treated as healthy.'), step('@health .hc-check-toolbar', 'Find the check', 'Search by source, name or evidence, and narrow by state. Needs attention includes failures, warnings and missing evidence.'), step('@health #hc-cards .hc-card', 'Read the source evidence', 'A check’s details and report time explain its state. Open the owning workspace when you need deeper evidence or an operational control.'), step('@health #hc-refresh', 'Refresh the snapshot', 'Refresh asks for newer evidence. It does not repair a fault, run a maintenance action or establish health for a source that cannot report.')];
      }
    } else if (hash === 'system/settings') {
      c.intro = 'Choose a setting group, read the field’s Details and edit only what you intend to change. Review the result after Save settings.';
      c.topics = [saveTopic, ['Does Save apply just this section?', 'Save settings submits the complete console form, including the groups currently hidden from view. Switching groups keeps your edits. Review all drafts before saving, and read any message saying a setting is stored but not yet in force.'], releaseTopic];
      c.steps = [step('.console-settings-workbench nav', 'Choose a setting group', 'These groups organize sign-in, sessions, housekeeping, alerts and other console behavior. Switching the visible group keeps the complete form and your drafts intact.'), step('[data-settings-panel]:not([hidden])', 'Read the field details', 'Each field has Details explaining its meaning, limits or when it takes effect. A blank secret field keeps the existing secret unless the page explicitly says otherwise.'), step('.settings-save', 'Review and save deliberately', 'The draft count shows changed controls. Save settings submits all groups together. Read the result to distinguish a saved setting from one that has taken effect.')];
    } else if (hash === 'settings' || hash === 'settings/directory') {
      c.intro = 'This directory helps you find the setting and the service that owns it. Some settings open an editor here; others take you to the owning workspace.';
      c.topics = [saveTopic, ['Why do some settings open another page?', 'The directory brings destinations together without changing who owns them. Its notes say whether a setting is editable here, managed in another tool or controlled through a release. Your permission to save is still checked by the owning service.'], releaseTopic];
      c.steps = [step('.settings-toolbar', 'Find the setting', 'Search by a task or setting name, such as thresholds, notifications or access. The group filter narrows the directory.'), step('#settings-categories', 'Browse by purpose', 'Categories group related settings. All settings returns to the full directory.'), step('.settings-entry', 'Read the ownership note', 'Each entry describes what it controls and where it can be changed. Follow its link to the editor or owning workspace.'), step('[data-tabs=settings]', 'Open an integrated editor', 'Available editors appear as tabs. Temporarily unavailable editors have a retry path. A missing tab can reflect your permissions or an endpoint that is not available.')];
    } else if (hash.indexOf('settings/') === 0) {
      c.intro = 'These controls read and save through the owning service. Change a field, review its meaning and save its editor. Neighboring unsaved editors remain drafts.';
      c.topics = [saveTopic, ['Why is an editor unavailable?', 'A temporary service failure shows an explanation and Reload. A denied or absent endpoint is not shown as an available editor. The owning service checks access again on save, even if you can read its settings.'], hash === 'settings/backup' ? ['What do the recovery controls promise?', 'Read the delivery and desired-state notes. Replication and failover preferences do not by themselves start replication or a switch. Revision checks prevent a save from silently overwriting a newer admin change.'] : freshnessTopic];
      c.steps = [step('[data-tabs=settings]', 'Choose the right editor', 'Each tab belongs to a service. Changing tabs keeps your unsaved work for this session; leaving or reloading the console can require discarding a draft.'), step('.sf:not(.is-loading) .sf-lede', 'Read the ownership and apply notes', 'The introduction explains the service, permissions and when changes take effect. Reload reads the service again and asks before discarding drafts.'), step('[data-sf-body] .card-h', 'Inspect a group of controls', 'Related settings are grouped into editors. Read the field notes, units and limits before making a change.'), step('[data-sf-body] .sf-foot', 'Save one editor and check the result', 'Save becomes available when an editor changes. Its submitted controls pause while saving. Read the returned result; unsaved changes in other editors stay as drafts.')];
    } else if (hash === 'system/updates') {
      c.intro = 'Review package and reboot evidence for each host. Choose an action only after checking the target, serving node and any release or HA restrictions.';
      c.topics = [freshnessTopic, ['Does opening this page install anything?', 'No. Reading the summary does not install updates or reboot a host. The action controls describe their exact target and required confirmations. Check for updates asks the updates service to refresh its evidence.'], releaseTopic];
      c.steps = [step('[data-upd-nodes]', 'Read each host’s update evidence', 'Separate host cards show pending packages, kernel state, reboot requirements and which node is serving web. Confirm the host before choosing an action.'), step('[data-updates-panel] .card:nth-of-type(3)', 'Follow the controlled actions', 'Install and reboot are separate decisions. Their descriptions explain downtime and safety checks. The walkthrough does not click these controls.'), step('#noc-workspace-nav', 'Return to related operations', 'Use the operations links for server status, audit history and other maintenance evidence.')];
    } else if (hash === 'iam/access') {
      c.intro = 'Select a Hub role to review page permissions, or check one person’s inherited access and exceptions. Edit permissions enables drafts; Review changes shows their exact scope before Save.';
      c.topics = [['What does inherited mean?', 'Inherited follows the role’s default, or the highest permission from a person’s roles. An explicit page permission or personal exception overrides that default. Signed-in pages allow at least Read. Protected pages and super-admin rules are enforced separately by the Hub.'], ['When does access change?', 'Drafts change only this preview. Save reviewed changes sends the full merged grant set to the Hub’s existing API, which checks super-admin authority and audits each transaction. Existing sessions may retain access until they refresh.'], ownershipTopic];
      c.steps = [step('.ac-views', 'Choose the access question', 'Roles & permissions reviews one role. People & exceptions checks one person. Audit log shows recorded events. Compare all roles opens the optional matrix.'), step('[data-ac-pane]:not([hidden]) #ac-role-list, [data-ac-pane]:not([hidden]) #ac-plist, [data-ac-pane]:not([hidden]) #ac-audit', 'Find your subject', 'Search for a role, person or recorded event. The role list includes membership counts; drafts survive switching roles.'), step('[data-ac-pane]:not([hidden]) #ac-role-summary, [data-ac-pane]:not([hidden]) #ac-pdet', 'Read defaults and effective access', 'The summary explains inherited access. Effective access shows the result and the reason, including protected pages and signed-in minimum permissions.'), step('[data-ac-edit]', 'Edit, review and save', 'Enable editing deliberately. Changed fields stay in a draft. Review changes lists every change, including drafts in other roles or a person. Saving requires explicit acknowledgment and the Hub’s super-admin authorization.')];
    } else if (module === 'people') {
      c.intro = 'Choose a site, group or person, inspect their access path and follow the owning system to review a change.';
      c.topics = [ownershipTopic, ['Does recording a review change access?', 'A review records a decision or evidence. A proposal plans a change. Actual enforcement belongs to the named access service and its explicit controls; check the page’s result before assuming a grant was changed.'], freshnessTopic];
      c.steps = [step('[data-view]:not([hidden]) h2', 'Choose the access question', 'The page title tells you whether you are reviewing site admission, groups, people or page grants. These are different parts of the access path.'), step('.agw-board, #access-registry, [data-access-control], .directory-toolbar', 'Select and inspect', 'Use the list and filters to find the site, group or person. Open the details to examine ownership, membership and enforcement evidence.'), step('#noc-workspace-nav', 'Follow the owning workspace', 'The contextual links lead to related access tools. Permission to read this page does not grant permission to write in those tools.')];
    } else if (module === 'resources') {
      c.intro = 'Find a service or resource, inspect its health and last check, then open its details or owning tool.';
      c.topics = [stateTopic, freshnessTopic, ['What does Manage registrations do?', 'Registration controls describe which resources the platform monitors. Registration is different from fixing a running service. Follow the owning tool and review its scope before changing monitoring configuration.']];
      c.steps = [step('#resource-list-query, #workspace-query, [data-view]:not([hidden]) h2', 'Find the resource', 'Use the search and workspace links to narrow the estate to the service or resource you need.'), step('.ledger-table, #resource-content, .ledger-catalog', 'Read health alongside freshness', 'A state summarizes the latest evidence. Inspect the last-check time and details so a stale or unknown result is not mistaken for a current answer.'), step('#resource-manage, #resource-tabs, #noc-workspace-nav', 'Open the control that owns the task', 'Details and owning workspaces provide the next action. Read their scope and permission notes before changing configuration.')];
    } else if (module === 'operations') {
      c.intro = 'Use operations to inspect host evidence and reach the control that owns a maintenance task. Read the target and impact before running an action.';
      c.topics = [freshnessTopic, ['Where should I run a maintenance action?', 'Use the named owning control. Quick actions take you to the appropriate task; the full workspace contains more host tools. An action can have a different scope from the evidence you are currently viewing. Read the target and any confirmation carefully.'], releaseTopic];
      c.steps = [step('[data-view]:not([hidden]) h2', 'Start with the task and evidence', 'The heading and description show the operational task. Review host or finding evidence before choosing an action.'), step('#noc-workspace-nav', 'Choose a maintenance destination', 'Use these links for updates, cleanup, changes, audit history and the full host workspace. They organize distinct tools and permissions.'), step('[data-view]:not([hidden]) .card, #advanced-workspace', 'Check target and impact', 'Read which host, service or record a control affects. Reboots, releases and recovery operations have their own confirmations; this guide does not run them.')];
    }
    c.steps = shell.concat(c.steps);
    return c;
  }
  function visible(el) { return !!el && !el.closest('[hidden]') && el.getClientRects().length > 0; }
  function targetFor(selector) {
    if (selector.indexOf('@health ') === 0) {
      var frame = document.getElementById('health-workspace');
      try { return visible(frame) && frame.contentDocument ? Array.from(frame.contentDocument.querySelectorAll(selector.slice(8))).find(visible) : null; }
      catch (e) { return null; }
    }
    return Array.from(document.querySelectorAll(selector)).find(visible);
  }
  function locate() {
    if (index < 0 || !dialog.open) return;
    selectedTarget = targetFor(steps[index].target);
    ring.hidden = !selectedTarget;
    dialog.classList.toggle('has-target', !!selectedTarget);
    card.style.top = ''; card.style.bottom = ''; card.style.left = ''; card.style.right = '';
    if (!selectedTarget) return;
    var r = selectedTarget.getBoundingClientRect(), pad = 5;
    if (selectedTarget.ownerDocument !== document) {
      var frameRect = document.getElementById('health-workspace').getBoundingClientRect();
      r = {left:r.left+frameRect.left,top:r.top+frameRect.top,right:r.right+frameRect.left,bottom:r.bottom+frameRect.top};
    }
    var left = Math.max(4, r.left - pad), top = Math.max(4, r.top - pad);
    var right = Math.min(innerWidth - 4, r.right + pad), bottom = Math.min(innerHeight - 4, r.bottom + pad);
    ring.hidden = right <= left || bottom <= top;
    dialog.classList.toggle('has-target', !ring.hidden);
    ring.style.left = left + 'px'; ring.style.top = top + 'px';
    ring.style.width = Math.max(0, right - left) + 'px'; ring.style.height = Math.max(0, bottom - top) + 'px';
    // Keep the reading card away from the outlined control when there is room.
    if (innerWidth > 700) {
      var cardRect = card.getBoundingClientRect();
      if (right > cardRect.left && left < cardRect.right && bottom > cardRect.top && top < cardRect.bottom) {
        if (bottom < innerHeight / 2) { card.style.top = ''; card.style.bottom = '24px'; }
        else if (left > innerWidth / 2) { card.style.right = 'auto'; card.style.left = '24px'; }
        else { card.style.bottom = 'auto'; card.style.top = '24px'; }
      }
    }
  }
  function renderHome(topic) {
    index = -1; ring.hidden = true; dialog.classList.remove('is-tour', 'has-target');
    title.textContent = topic ? topic[0] : current.name;
    copy.textContent = topic ? topic[1] : current.intro;
    kicker.textContent = 'PAGE GUIDE'; progress.textContent = '';
    back.hidden = !topic; back.textContent = 'Page overview';
    next.textContent = 'Walk me through'; next.disabled = !steps.length;
    topics.replaceChildren();
    if (!topic) current.topics.forEach(function(item) {
      var b = document.createElement('button'); b.type = 'button'; b.className = 'noc-guide-topic'; b.textContent = item[0];
      b.addEventListener('click', function() { renderHome(item); next.focus(); }); topics.append(b);
    });
    topics.hidden = !!topic;
    tip.textContent = 'Walkthroughs explain the controls on this page. You can close the guide at any time.';
    tip.hidden = false;
  }
  function showStep(n) {
    index = n; dialog.classList.add('is-tour'); topics.hidden = true; tip.hidden = true;
    title.textContent = steps[n].title; copy.textContent = steps[n].body;
    kicker.textContent = current.name + ' · WALKTHROUGH'; progress.textContent = (n + 1) + ' of ' + steps.length;
    back.hidden = false; back.textContent = n ? 'Back' : 'Overview';
    next.textContent = n === steps.length - 1 ? 'Done' : 'Next';
    var target = targetFor(steps[n].target);
    if (target) {
      target.scrollIntoView({block: innerWidth <= 700 ? 'start' : 'center', behavior: 'instant'});
      if (innerWidth <= 700 && target.ownerDocument === document && !target.closest('.hybrid-header, .noc-rail')) window.scrollBy(0, -100);
    }
    locate();
  }
  function cleanup() {
    ring.hidden = true; dialog.classList.remove('is-tour', 'has-target'); index = -1; selectedTarget = null;
    if (frameScroll) { try { frameScroll.window.scrollTo(frameScroll.x, frameScroll.y); } catch(e) {} }
    if (startScroll) window.scrollTo(startScroll.x, startScroll.y);
    var restore = visible(returnFocus) ? returnFocus : trigger;
    restore.focus({preventScroll: true});
  }
  function close() { if (dialog.open) dialog.close(); }
  function open(topic) {
    if (dialog.open) return;
    current = config(); steps = current.steps.filter(function(s) { return !!targetFor(s.target); });
    returnFocus = document.activeElement; startScroll = {x: scrollX, y: scrollY};
    frameScroll = null;
    try { var health = document.getElementById('health-workspace'); if (health && visible(health)) frameScroll = {window:health.contentWindow,x:health.contentWindow.scrollX,y:health.contentWindow.scrollY}; } catch(e) {}
    renderHome(topic); dialog.showModal(); next.focus();
  }
  trigger.addEventListener('click', function() { open(); });
  dialog.querySelector('.noc-guide-close').addEventListener('click', close);
  dialog.addEventListener('close', cleanup);
  dialog.addEventListener('click', function(e) { if (e.target === dialog && index < 0) close(); });
  back.addEventListener('click', function() { if (index <= 0) renderHome(); else showStep(index - 1); next.focus(); });
  next.addEventListener('click', function() { if (index === steps.length - 1 && index >= 0) close(); else showStep(index + 1); });
  dialog.addEventListener('keydown', function(e) {
    if (index < 0) return;
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault(); e.stopPropagation();
      if (e.key === 'ArrowRight') next.click(); else back.click();
    }
  });
  window.addEventListener('resize', function() { if (index >= 0 && dialog.open) showStep(index); });
  window.addEventListener('scroll', locate, {passive: true, capture: true});
  var frame = document.getElementById('health-workspace');
  if (frame) frame.addEventListener('load', function() { try { frame.contentWindow.addEventListener('scroll', locate, {passive:true}); } catch(e) {} });
  function sync() {
    close();
    var page = Array.from(document.querySelectorAll('#noc-main [data-view]')).find(visible);
    if (!page) return;
    var helper = page.querySelector(':scope > .noc-page-helper');
    if (!helper) {
      helper = document.createElement('details'); helper.className = 'noc-page-helper';
      var summary = document.createElement('summary'); summary.textContent = 'How to use this page'; helper.append(summary);
      var body = document.createElement('div'); body.className = 'noc-page-helper-body';
      body.append(document.createElement('p'));
      var walk = document.createElement('button'); walk.type = 'button'; walk.className = 'btn sm'; walk.textContent = 'Open page guide';
      walk.addEventListener('click', function() { open(); }); body.append(walk); helper.append(body);
      var heading = page.querySelector(':scope > .page-h, :scope > .ledger-heading, :scope > .hybrid-health-layout > .page-h');
      if (heading && heading.parentElement === page) heading.after(helper); else page.prepend(helper);
    }
    helper.querySelector('p').textContent = config().intro;
  }
  // Route changes close the guide and update help without navigating or touching drafts.
  window.addEventListener('console-route', sync);
  window.addEventListener('hashchange', sync);
  sync();
})();
