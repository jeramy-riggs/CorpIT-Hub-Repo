/* Entry point. Intune Health's existing access gate owns authorization. */
(function () {
  'use strict';
  if (location.hostname !== 'dev-corpit.nrpi.local' && location.hostname !== 'corpit.nrpi.local') return;
  var workspace = document.getElementById('ps-work');
  var trigger = document.getElementById('workspace-whats-new-link');
  var dialog = document.getElementById('workspace-whats-new');
  if (!workspace || !trigger || !dialog) return;
  var initialized = false;

  function sync() {
    // Wait for the page's actual role check, including its tier2 access rule.
    // Do not replace that rule with a generic page entitlement or fetch identity again.
    if (workspace.hidden) {
      trigger.hidden = true;
      if (dialog.open) dialog.close();
      return;
    }
    if (initialized) return;
    initialized = true;
    var engine = document.createElement('script');
    engine.src = '/workspace-whats-new.js?v=20261019-account-guides2';
    engine.onload = function () { trigger.hidden = workspace.hidden; };
    document.body.appendChild(engine);
  }

  new MutationObserver(sync).observe(workspace, { attributes: true, attributeFilter: ['hidden'] });
  sync();
})();
