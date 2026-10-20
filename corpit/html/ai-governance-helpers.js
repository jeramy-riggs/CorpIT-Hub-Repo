/* Small contextual explanations. No API calls, storage or record changes. */
(function () {
  'use strict';
  const HELP = {
    'Governance Dashboard': ['Start with the overview', 'Use the links under the summary counts to open inventory, review work, approved applications or data quality. The dashboard summarizes recorded evidence; it does not approve applications or grant access.'],
    'AI Inventory': ['Using AI Inventory', 'This is the master list of known AI platforms and AI-enabled applications. Select an application to review its owner, business purpose, classification and evidence. Inclusion in the inventory does not establish active use or approval.'],
    'Governance Queue': ['Working through the queue', 'Use Work focus or search to find the next item to review, then follow its action links. Each application has one row with all its review reasons. Intake requests and approvals are viewed in Access Portal. Approved applications can remain here when information or assessments need follow-up.'],
    'Application Reviews': ['Reviewing an application', 'Review the owner, purpose, evidence and assessment gaps before recording an approval decision. Record a rationale and any conditions. A decision does not provision access or change Zscaler policy, and approval does not remove outstanding gaps.'],
    'Approved Applications': ['What approved means', 'Only applications with a recorded Approved governance decision appear here. Review the decision evidence, owner and conditions before relying on that approval. Observed use or a vendor sanction label is not governance approval.'],
    'Usage & Activity': ['Reading usage evidence', 'Select a time window and application, then open observed users for activity detail. Allowed requests and blocked attempts are different signals. Check the last source event and report dates.'],
    'Intake Requests': ['Reading Portal requests', 'Access Portal is the intake and approval system. Use Open Access Portal queue to view pending requests, approvals and history in a new tab. Intake records and counts are not imported here. Use the Portal to submit or decide a request; requester and requested access are not confirmed ownership or actual access.'],
    'Access Registry': ['Understanding recorded access', 'Review account arrangements, SSO verification and recorded user or project grants here. Observed activity does not establish a license or access grant. Adding a governance record does not provision or revoke access in the owning system.'],
    'Risk Assessments': ['Completing an assessment', 'Select an application and review its data handling, exposure questions, controls and evidence. Save a draft when answers are incomplete. A final tier requires reviewer details, a review date, rationale and HTTPS evidence; the automatic checks do not assign that tier.'],
    'App Coverage Gaps': ['Finding missing information', 'This view measures answers in saved application assessments. Use the field counts to find affected applications, then review the missing or uncertain answers. A recorded answer shows completeness; it does not prove that a control is effective.'],
    'Discovery': ['Reviewing discovery candidates', 'Treat these records as leads for review. Check the source evidence and match a candidate to the correct inventory application before acting. Discovery does not establish approval, active AI-feature use or a license entitlement.'],
    'Audit Trail': ['Following the audit history', 'Use the recorded actor, action, application and timestamp to understand what changed. Governance and project events describe their own actions; an event date is not necessarily the original access-grant date. The view is limited to the returned history.'],
    'Classification & Sources': ['Classifications and evidence sources', 'Review category definitions, discovery mappings, vendor references and source collection status here. Categories describe the application; a source match provides evidence, not an approval. Collection time and the period covered by a report can differ.'],
    'Executive Reports': ['Preparing a governance report', 'Choose the report scope, check source warnings, then download the relevant CSV or Legal brief. Inventory and access are current recorded snapshots; date filters apply to request submissions and audit events. Partial or bounded source reads do not establish complete enterprise coverage.'],
    'User Projects': ['Infrastructure project records', 'Use project mappings, AD groups and grant relationships to investigate how applications relate to infrastructure access. Project-level evidence is separate from the application approval decision and business ownership.'],
    'Inventory Health': ['Improving inventory quality', 'Filter the maintenance queue to find missing metadata, overdue reviews or aging records. Complete the application information and review schedule in the linked record. The quality percentage measures completeness, not security risk.'],
    'Portal Approval Queue': ['Opening the approval queue', 'Use Open Access Portal queue to view requests, decisions and approval history directly in Access Portal. Opens in a new tab; no intake records are imported into AI Governance.'],
    'Metadata complete': ['How completeness is measured', 'The score covers six recorded dimensions: owner, purpose, decision, evidence, review schedule and access/account information. Missing information lowers the score. A high completeness score does not mean low risk or complete discovery.'],
    'Governance Decisions': ['Reading decision counts', 'These are current recorded application dispositions: Approved, Under Review, Restricted and Rejected. Unreviewed means no final decision is recorded. Follow a count to see the matching applications; historical approval transitions are shown separately in trends.'],
    'High-Risk Review Required': ['A review signal, not an assigned tier', 'This flags recorded exposure indicators with an incomplete, overdue or open-control assessment. Open the application to review the saved answers and evidence. Zero flags does not establish low risk when assessment answers are missing.'],
    'AI Classification Distribution': ['How applications are grouped', 'Counts use saved categories and recorded AI types. Embedded AI can overlap another category, so counts may not add up to the inventory total. Unknown categories remain visible until a reviewer records a classification.'],
    'Applications by Department': ['Where department counts come from', 'These groups use the department saved in the application assessment. Requester details, observed-user departments and owner names are not substituted automatically. Unknown department means the application needs that information reviewed.'],
    'Last 30 days': ['Understanding governance trends', 'The charts use recorded dates and audited approval transitions across 30 UTC calendar dates. Quality and overdue history accumulate as daily observations. Missing days are not backfilled, and one baseline does not yet establish a trend.'],
    'Source coverage': ['Checking evidence freshness', 'Check the last successful collection and any partial or unavailable status before drawing conclusions. A successful read or recent event does not prove complete feed coverage. Source collection dates, event times and vendor report periods are separate.'],
    'Automatic risk checks': ['How automatic checks help', 'The checks use saved answers to flag follow-up and calculate the review schedule. They do not assign a final risk tier. Unknown answers remain gaps; review the evidence and record the final assessment separately.'],
  };

  for (const [key, value] of Object.entries(window.AIGovernanceFieldGuide || {})) HELP['field:' + key] = value;
  HELP['Application lifecycle'] = ['Understanding lifecycle', 'Production, pilot, development and retired describe the saved assessment lifecycle. They are separate from governance approval and observed usage. Unknown answers remain visible.'];
  HELP['Risk indicators & control gaps'] = ['Reading recorded signals', 'Counts use saved application assessments in the report scope. A signal prompts review and does not assign a tier. Missing or uncertain answers are shown separately; a zero signal count does not establish safety or effective controls.'];
  HELP['Assigned risk tiers'] = ['Reading assigned tiers', 'Only completed assessments supply a tier here. InfoSec / Legal record the reviewer, review date, rationale and evidence. High reviews are due after 3 months, Medium after 12 months, and Low on material change.'];
  HELP['Risk Assessments'][1] += ' Use Unknown or Unsure when you do not know. Keep separate use-case reviews in Access Portal; one tool can support several uses with different risks.';
  HELP['AI Inventory'][1] += ' Include in-house AI, embedded SaaS features, coding assistants and AI in development or pilot, as well as production.';
  let active = null, nextId = 0, pending = false, frame = 0;
  const records = new WeakMap();
  const canHover = () => typeof matchMedia !== 'function' || matchMedia('(hover: hover)').matches;

  function close(record = active) {
    if (!record) return;
    clearTimeout(record.timer);
    record.pinned = false;
    if (record.native && record.pop.matches(':popover-open')) record.pop.hidePopover();
    record.pop.hidden = true;
    record.button.setAttribute('aria-expanded', 'false');
    if (active === record) active = null;
  }

  function open(record) {
    clearTimeout(record.timer);
    if (active !== record) close();
    active = record;
    record.pop.hidden = false;
    if (record.native && !record.pop.matches(':popover-open')) record.pop.showPopover();
    record.button.setAttribute('aria-expanded', 'true');
    const anchor = record.button.getBoundingClientRect(), box = record.pop.getBoundingClientRect();
    const left = Math.max(16, Math.min(anchor.left, innerWidth - box.width - 16));
    const below = anchor.bottom + 9;
    const top = below + box.height <= innerHeight - 16 ? below : Math.max(16, anchor.top - box.height - 9);
    record.pop.style.left = left + 'px';
    record.pop.style.top = top + 'px';
  }

  function dismissAfterPointerLeave(record) {
    clearTimeout(record.timer);
    record.timer = setTimeout(() => {
      if (!record.pinned && !record.button.matches(':hover') && !record.pop.matches(':hover') && document.activeElement !== record.button) close(record);
    }, 120);
  }

  function attach(heading, key, field = false) {
    let record = records.get(heading);
    if (!record) {
      const wrapper = document.createElement('div');
      wrapper.className = field ? 'ai-help-field' + (heading.classList.contains('sai-full') ? ' sai-full' : '') : 'ai-help-heading' + (heading.tagName === 'H1' ? ' ai-help-page-title' : '');
      heading.before(wrapper);
      wrapper.append(heading);
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'ai-help-trigger';
      button.textContent = '?';
      button.setAttribute('aria-expanded', 'false');
      const pop = document.createElement('div');
      pop.className = 'ai-help-popover';
      pop.id = 'ai-governance-help-' + (++nextId);
      pop.setAttribute('popover', 'auto');
      pop.setAttribute('role', 'tooltip');
      pop.hidden = true;
      const title = document.createElement('h3');
      title.className = 'ai-help-title';
      const text = document.createElement('p');
      text.id = pop.id + '-text';
      pop.append(title, text);
      button.setAttribute('aria-controls', pop.id);
      button.setAttribute('popovertarget', pop.id);
      button.setAttribute('aria-describedby', text.id);
      wrapper.append(button, pop);
      record = { button, pop, title, text, native: typeof pop.showPopover === 'function', pinned: false, timer: null, key: null };
      records.set(heading, record);
      button.addEventListener('click', event => {
        event.preventDefault();
        event.stopPropagation();
        if (record.pinned && active === record) close(record);
        else { open(record); record.pinned = true; }
      });
      button.addEventListener('pointerenter', () => { if (canHover()) open(record); });
      button.addEventListener('pointerleave', () => dismissAfterPointerLeave(record));
      button.addEventListener('focus', () => open(record));
      button.addEventListener('blur', () => { if (!record.pinned) close(record); });
      pop.addEventListener('pointerenter', () => clearTimeout(record.timer));
      pop.addEventListener('pointerleave', () => dismissAfterPointerLeave(record));
      pop.addEventListener('toggle', event => {
        if (event.newState === 'closed' && active === record) close(record);
      });
    }
    if (record.key !== key) {
      if (active === record) close(record);
      record.key = key;
      record.button.setAttribute('aria-label', 'Help: ' + (field ? HELP[key][0] : key));
      record.title.textContent = HELP[key][0];
      record.text.textContent = HELP[key][1];
    }
  }

  function scan() {
    pending = false;
    frame = 0;
    const seen = new Set();
    for (const heading of document.querySelectorAll('#title, #workspace h2, dialog h2, dialog h3')) {
      if (heading.closest('.ai-help-popover, a, button, label')) continue;
      const key = heading.textContent.trim();
      if (!HELP[key] || seen.has(key)) continue;
      seen.add(key);
      attach(heading, key);
    }
    for (const label of document.querySelectorAll('dialog label[data-ai-help-field]')) {
      const key = 'field:' + label.dataset.aiHelpField;
      if (HELP[key]) attach(label, key, true);
    }
    if (active && !active.button.isConnected) close();
  }

  function schedule() {
    if (!pending) { pending = true; frame = requestAnimationFrame(scan); }
  }

  function start() {
    scan();
    const observer = new MutationObserver(schedule);
    const observe = () => observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    observe();
    window.addEventListener('pagehide', () => {
      observer.disconnect();
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
      pending = false;
      close();
    });
    window.addEventListener('pageshow', () => { observe(); schedule(); });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && active) {
        event.preventDefault();
        event.stopPropagation();
        close();
      }
    }, { capture: true });
    document.addEventListener('pointerdown', event => {
      if (active && !active.button.contains(event.target) && !active.pop.contains(event.target)) close();
    });
    document.addEventListener('scroll', () => close(), { capture: true, passive: true });
    window.addEventListener('resize', () => close(), { passive: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
