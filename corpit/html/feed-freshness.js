/* Feed freshness banner.
 *
 * A page opts in with a data attribute on its own script tag:
 *   <script src="/feed-freshness.js" data-page="identity-diag" defer></script>
 *
 * It asks /api/feeds/freshness which feeds back that page, and if any of them is
 * stale, empty or unmeasurable it puts a banner at the top of the document saying
 * so. The point is that a page must not render "no results in the last 24 hours"
 * as an all-clear when the underlying collector has not run since the host was
 * seeded -- zero rows from a dead feed and zero rows from a quiet network look
 * identical in every widget on these dashboards.
 *
 * If the freshness call itself fails, no banner is shown. That is deliberate: with
 * no measurement the page has no basis to claim the data is stale, and none to
 * claim it is current either. It makes no claim at all.
 */
(function () {
  'use strict';

  var self = document.currentScript;
  var page = self && self.getAttribute('data-page');
  if (!page) return;

  var STATE_TEXT = {
    stale:   'has not updated',
    empty:   'has never collected any data on this host',
    unknown: 'could not be checked',
  };
  // Used when state is 'ok' but the collector is not: the sentence has to
  // describe the JOB, not the age, or it reads as a contradiction. One line per
  // fault -- "last failed" is untrue of a job that succeeded and then stopped
  // running, and untrue of one that died without reporting anything at all.
  function producerText(f) {
    if (f.producerFailing)   return 'is current, but its collector last failed';
    if (f.producerAbandoned)
      return midflight(f) ? 'is current, but its collector did not finish'
                          : 'is current, but its collector has not completed a run in days';
    return 'is current, but its collector is overdue';
  }

  function ago(hours) {
    if (hours == null) return '';
    if (hours < 1)  return Math.round(hours * 60) + ' min';
    if (hours < 48) return Math.round(hours) + ' hours';
    return Math.round(hours / 24) + ' days';
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // Three producer faults, each a separate fact, each able to be true while the
  // rows still look current. Every site below asks this one question, so the
  // next signal added to the API is one edit here rather than five conditionals
  // scattered through render() -- which is how producerAbandoned shipped in the
  // payload and stayed invisible on the page.
  function producerBad(f) {
    return !!(f.producerFailing || f.producerAbandoned || f.producerOverdue);
  }

  // What is actually being claimed about the table. A failed or abandoned run
  // may have written only part of it; an overdue one wrote all of it and then
  // stopped, so "incomplete" would be the wrong accusation.
  // Past this, an abandoned run is not a write in progress. The API declares a
  // run stuck after 12h; double it, so a job killed overnight is still read as
  // a possible partial write while one killed last week is not.
  var ABANDONED_MIDFLIGHT_H = 24;

  function midflight(f) {
    if (!f.producerAbandoned) return false;
    var h = f.lastRun && f.lastRun.startAgeHours;
    return h == null || h <= ABANDONED_MIDFLIGHT_H;
  }

  function producerWord(f) {
    // 'incomplete' is a claim about the ROWS, and only a run that could still
    // have been writing when it died supports it. A long-dead run supports a
    // claim about the JOB instead.
    if (f.producerFailing) return 'may be incomplete';
    if (f.producerAbandoned) return midflight(f) ? 'may be incomplete' : 'may be behind';
    return 'may be behind';
  }

  function producerWhy(f) {
    var who = f.collector ? esc(f.collector) : 'its collector';
    if (f.producerFailing)
      return 'the rows are current, but ' + who + ' last exited ' +
             (f.lastRun && f.lastRun.exitCode != null ? esc(String(f.lastRun.exitCode)) : 'non-zero') +
             ', so this table may be only partly rebuilt';
    if (f.producerAbandoned)
      return midflight(f)
        ? 'the rows are current, but ' + who + ' started ' +
          ago(f.lastRun && f.lastRun.startAgeHours) +
          ' ago and never recorded an outcome, so this table may be only partly rebuilt'
        // Deliberately does not claim the rows are wrong. Something refreshed
        // them after that run died; the run log cannot say what, and neither
        // can this banner.
        : 'the rows are current, but ' + who + ' has not recorded a completed run in ' +
          ago(f.lastRun && f.lastRun.startAgeHours) +
          ' -- its last run was killed before it finished, so whatever has ' +
          'refreshed this table since is unrecorded';
    return 'the rows are current, but ' + who + ' last succeeded ' +
           ago(f.lastRun && f.lastRun.ageHours) + ' ago and is expected at least every ' +
           ago(f.producerOverdueBy && f.producerOverdueBy.expectedWithinHours) +
           ', so nothing collected since then is shown';
  }

  function render(data) {
    // Two different faults, both worth showing: the data is old, or the job that
    // writes it last failed. The second can happen while the data still looks
    // current, because a half-finished run leaves fresh rows behind it.
    var bad = (data.feeds || []).filter(function (f) {
      return f.state !== 'not_included' && (f.state !== 'ok' || producerBad(f));
    });
    if (!bad.length) return;

    // Tell the observability collector that this page is about to show a user a
    // degraded state. One report per feed, at the moment the banner is decided,
    // so "how often does anyone actually SEE this" becomes a countable number
    // instead of something only discoverable by opening the page yourself.
    if (window.ITObserve && window.ITObserve.degraded) {
      bad.forEach(function (f) {
        window.ITObserve.degraded('feed:' + f.key,
          f.label + ' ' + (f.state === 'ok' && producerBad(f)
            ? producerText(f) : (STATE_TEXT[f.state] || f.state)),
          'state=' + f.state + (f.ageHours != null ? ' ageHours=' + Math.round(f.ageHours) : '') +
          ' collector=' + (f.collector || 'unknown') +
          // Which fault fired, so a degraded report is diagnosable without
          // reopening the page it was reported from.
          (f.producerFailing   ? ' producer=failing'   : '') +
          (f.producerAbandoned ? ' producer=abandoned' : '') +
          (f.producerOverdue   ? ' producer=overdue'   : ''));
      });
    }

    // An overdue-only banner must not say "did not finish": that run finished,
    // and finished successfully. Computed once here, read twice below.
    var allOk = bad.every(function (f) { return f.state === 'ok'; });
    // Whether ANY flagged feed could be holding a half-written table. Only this
    // licenses the header to say what is shown may be part of the picture.
    var suspectRows = bad.some(function (f) { return f.producerFailing || midflight(f); });
    var allOverdue = allOk && bad.every(function (f) {
      return f.producerOverdue && !f.producerFailing && !f.producerAbandoned;
    });

    var wrap = document.createElement('div');
    wrap.id = 'feed-freshness-banner';
    wrap.setAttribute('role', 'status');
    // Fixed to the bottom, deliberately. These five pages use five different body
    // layouts -- flex row, height:100% app shells, plain block -- and a banner
    // inserted into the flow becomes a flex item on at least one of them (measured
    // on identity-diag: it turned into a 3088px-tall column beside the sidebar).
    // position:fixed takes it out of flow entirely, so no page's layout can
    // stretch it, and the bottom edge is chosen over the top because none of
    // these pages pin their toolbar, so a top bar would cover page controls.
    wrap.style.cssText = [
      'box-sizing:border-box', 'position:fixed', 'left:0', 'right:0', 'bottom:0',
      'max-height:40vh', 'overflow:auto',
      'padding:10px 16px',
      'background:#3a2a08', 'color:#f5d98b',
      'border-top:1px solid #6b4d10', 'border-left:4px solid #d99a00',
      'box-shadow:0 -2px 12px rgba(0,0,0,.35)',
      'font:13px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif',
      'z-index:99999',
    ].join(';');

    var items = bad.map(function (f) {
      if(f.collectionMode==='manual_test')return '<li>'+esc(f.label)+' is a DEV test snapshot; recurring collection is intentionally not enabled here. '+esc(f.newest?'Source date: '+f.newest+'.':'No source date recorded.')+' Live collection belongs in production.</li>';
      var age = f.state === 'stale' ? ' for ' + ago(f.ageHours) : '';
      if (f.state === 'ok' && producerBad(f)) age = '';
      // What each state actually measures, and nothing beyond it.
      //
      // The else branch used to read "<collector> is not scheduled on this
      // host" for BOTH 'stale' and 'empty'. Neither state measures that.
      // 'stale' means the newest row is old -- equally produced by a scheduled
      // collector failing every run, by an upstream refusing (a stale API
      // secret did exactly this to Zscaler), or by a failing DB write. 'empty'
      // means the table has no rows -- equally produced by a brand-new table or
      // by a collector that runs and stores nothing. Naming one specific cause
      // sends whoever reads it to check the crontab, where they find the entry
      // present and the banner apparently wrong.
      //
      // It also rendered "( is not scheduled on this host)" with no subject
      // whenever collector was null.
      var owner = f.collector ? esc(f.collector) + ' is what populates it' : '';
      var why;
      if (f.state === 'ok' && producerBad(f))
        // The rows are current. The job that writes them is not, and which way
        // it is not decides the sentence.
        why = producerWhy(f);
      else if (f.state === 'unknown') why = 'the freshness check for this feed did not complete';
      else if (f.state === 'empty')   why = 'no rows at all on this host' + (owner ? '; ' + owner : '');
      else                            why = 'nothing has written to it since' + (owner ? '; ' + owner : '');
      // A feed flagged only because its collector failed still has state 'ok'.
      // Leading the sentence with the word "ok" and then explaining why it is
      // not fine reads as a contradiction, so the producer case says what is
      // actually being claimed: the table may be short of rows.
      var word = (f.state === 'ok' && producerBad(f))
        ? producerWord(f)
        : (STATE_TEXT[f.state] || f.state);
      return '<li style="margin:2px 0"><b>' + esc(f.label) + '</b> ' +
             esc(word) + age +
             ' <span style="opacity:.72">(' + why + ')</span></li>';
    }).join('');

    wrap.innerHTML =
      '<div style="display:flex;gap:12px;align-items:flex-start">' +
        '<span aria-hidden="true" style="font-size:15px;line-height:1.2">&#9888;</span>' +
        '<div style="flex:1;min-width:0">' +
          '<b>' + (!allOk ? 'Some data on this page is not current.'
             : suspectRows ? 'A collector behind this page is not finishing.'
             : allOverdue  ? 'A collector behind this page has not run on schedule.'
             : 'A collector behind this page is not completing runs.') + '</b> ' +
          // The two faults need two sentences. "Stopped advancing" is false for a
          // feed whose rows are current and whose collector is the thing failing.
          (allOk
            ? (suspectRows
              ? 'Its rows are current, but the run that rebuilds them did not finish, ' +
                'so what is shown below may be only part of the picture.'
              : allOverdue
              ? 'Its rows are current as of the last run, but that run is overdue, ' +
                'so anything collected since then is missing from what is shown below.'
              // Neither claim fits a run that died days ago while rows kept
              // arriving: the table is not half-written, and it is not simply
              // waiting on a late run. Say only what the run log supports.
              : 'Its rows are current, but the collector that maintains them has not ' +
                'completed a run, so what has been refreshing them is unrecorded.')
            : 'Counts, charts and “no results” states below are drawn from feeds that ' +
              'have stopped advancing, so an empty panel here does not mean nothing is happening.') +
          '<ul style="margin:6px 0 0;padding-left:18px">' + items + '</ul>' +
        '</div>' +
        '<button type="button" aria-label="Dismiss" ' +
          'style="background:none;border:0;color:inherit;cursor:pointer;font-size:17px;line-height:1;padding:0 2px;opacity:.7">&times;</button>' +
      '</div>';

    wrap.querySelector('button').addEventListener('click', function () { wrap.remove(); });

    document.body.appendChild(wrap);
  }

  function go() {
    fetch('/api/feeds/freshness?page=' + encodeURIComponent(page), { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d && d.feeds) render(d); })
      .catch(function () { /* no measurement -> no claim */ });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go);
  else go();
})();
