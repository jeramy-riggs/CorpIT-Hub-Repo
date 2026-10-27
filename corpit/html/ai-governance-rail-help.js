/* Context help for the AI Governance rail. It does not change navigation. */
(function () {
  'use strict';
  const HELP = {
    dashboard: 'Overview of known applications, review work, recorded approvals, metadata quality, risk signals and recent trends. Switch off Compact to show every navigation view.',
    inventory: 'Search the known AI application catalog. Review classification, owner, purpose and governance status. Switch off Compact for Account and SSO filters, filter scope and source details.',
    'use-cases': 'Use-case records, Portal request lookup, review queue, summary, enrichment sources and audit trail. A use-case review is separate from application approval.',
    usage: 'Zscaler NSS and Shadow IT observations: requests, reported identities, application activity, source dates and coverage limits.',
    attention: 'Application follow-up for owner and purpose gaps, assessments and governance decisions. Portal intake approvals stay in Access Portal.',
    'approved-sites': 'Applications with a recorded Approved governance decision, with assessment details, observed activity and decision evidence where available.',
    requests: 'Open Access Portal for AI intake, approval progress and request history. Portal records are not imported into this workspace.',
    access: 'Directory and license evidence, linked project grants and other recorded access by application. Assignment alone does not prove current vendor access.',
    risk: 'Application assessment answers, risk indicators, control gaps, review status and any risk tier recorded by a reviewer.',
    coverage: 'Field-level missing, partial or uncertain assessment answers and control follow-up, with links to affected applications.',
    discovery: 'Review candidate applications, Shadow IT evidence, source details and missing classification or governance information.',
    audit: 'Search returned Governance and User Projects events, including decisions, reviews, evidence changes and collection activity.',
    sources: 'Legal AI categories, source refresh status, coverage and diagnostics, discovery mappings and embedded-AI references.',
    reports: 'Legal and InfoSec report scope, governance and risk measures, owner and purpose review, inventory health and exports.',
    projects: 'Project register with status, application mappings where recorded, grants and activity. Recorded grants do not verify current access.'
  };
  let pop, popTitle, popText, active, pinned = false;
  function hide() {
    if (active) active.querySelector('.ai-rail-help')?.removeAttribute('data-open');
    active = null;
    pinned = false;
    if (pop) pop.hidden = true;
  }
  function show(btn, hold = false) {
    const text = HELP[btn.dataset.view];
    if (!text || !pop) return;
    if (active && active !== btn) active.querySelector('.ai-rail-help')?.removeAttribute('data-open');
    active = btn;
    pinned = hold;
    const marker = btn.querySelector('.ai-rail-help');
    if (marker) marker.setAttribute('data-open', '');
    popTitle.textContent = btn.querySelector('.nav-text')?.childNodes[0]?.textContent?.trim() || 'About this view';
    popText.textContent = text;
    pop.hidden = false;
    const r = btn.getBoundingClientRect();
    const w = pop.offsetWidth, h = pop.offsetHeight;
    const left = r.right + 12 + w <= innerWidth - 12 ? r.right + 12 : Math.max(12, r.left - w - 12);
    pop.style.left = left + 'px';
    pop.style.top = Math.max(12, Math.min(r.top + (r.height - h) / 2, innerHeight - h - 12)) + 'px';
  }
  function mount() {
    const nav = document.getElementById('navigation');
    if (!nav || document.getElementById('ai-rail-help')) return;
    pop = document.createElement('div');
    pop.id = 'ai-rail-help';
    pop.className = 'ai-rail-help-pop';
    pop.setAttribute('role', 'tooltip');
    pop.hidden = true;
    popTitle = document.createElement('strong');
    popText = document.createElement('span');
    pop.append(popTitle, popText);
    document.body.appendChild(pop);
    nav.querySelectorAll('button[data-view]').forEach(btn => {
      const text = HELP[btn.dataset.view];
      if (!text) return;
      const desc = document.createElement('span');
      desc.id = 'ai-rail-help-' + btn.dataset.view;
      desc.hidden = true;
      desc.textContent = text;
      btn.appendChild(desc);
      btn.setAttribute('aria-describedby', desc.id);
      btn.removeAttribute('title');
      const marker = document.createElement('span');
      marker.className = 'ai-rail-help';
      marker.setAttribute('aria-hidden', 'true');
      marker.textContent = '?';
      marker.addEventListener('pointerenter', () => show(btn));
      marker.addEventListener('pointerleave', () => { if (!pinned && !btn.matches(':focus-visible')) hide(); });
      marker.addEventListener('click', event => {
        event.preventDefault();
        event.stopPropagation();
        if (active === btn && pinned) hide();
        else show(btn, true);
      });
      btn.appendChild(marker);
      btn.addEventListener('focus', () => { if (btn.matches(':focus-visible')) show(btn); });
      btn.addEventListener('blur', () => { if (!pinned) hide(); });
    });
    nav.addEventListener('click', event => { if (!event.target.closest('.ai-rail-help')) hide(); });
    addEventListener('scroll', hide, true);
    addEventListener('resize', hide);
    addEventListener('keydown', event => { if (event.key === 'Escape') hide(); });
    document.addEventListener('pointerdown', event => {
      if (pinned && !event.target.closest('.ai-rail-help')) hide();
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
