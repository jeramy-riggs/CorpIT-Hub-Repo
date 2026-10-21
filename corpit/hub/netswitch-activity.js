'use strict';

// Keep counter activity separate from the collector's severity. Severity is
// based on accumulated SNMP counters; activity describes observed changes.
const WINDOW_SECONDS = 3600;
const STALE_SECONDS = 1800;
const COUNTERS = ['in_err', 'out_err', 'crc', 'out_disc'];
const FINDING_COUNTER = { crc: 'crc', discards: 'out_disc', inerr: 'in_err',
  outerr: 'out_err', errors: 'in_err' };

function attachIssueActivity(issues, samples, nowSeconds = Math.floor(Date.now() / 1000)) {
  const byPort = new Map();
  for (const sample of samples) {
    const key = sample.switch_ip + ':' + sample.ifindex;
    if (!byPort.has(key)) byPort.set(key, []);
    byPort.get(key).push(sample);
  }

  for (const issue of issues) {
    const rows = byPort.get(issue.switch_ip + ':' + issue.ifindex) || [];
    rows.sort((a, b) => a.ts - b.ts);
    const latest = rows[rows.length - 1];
    if (!latest) {
      issue.activity = { state: 'unavailable', samples: 0 };
      continue;
    }

    const windowRows = rows.filter(row => row.ts >= latest.ts - WINDOW_SECONDS);
    const first = windowRows[0];
    const activity = {
      state: 'insufficient',
      samples: windowRows.length,
      first_ts: first.ts,
      last_ts: latest.ts,
      window_seconds: latest.ts - first.ts,
      latest_oper: latest.oper,
      link_changes: 0,
      finding_counter: FINDING_COUNTER[issue.kind] || null,
      d_in_err: null,
      d_out_err: null,
      d_crc: null,
      d_out_disc: null,
    };
    for (let n = 1; n < windowRows.length; n++) {
      if (windowRows[n - 1].oper !== windowRows[n].oper) activity.link_changes++;
    }

    if (nowSeconds - latest.ts > STALE_SECONDS) {
      activity.state = 'stale';
    } else if (!activity.finding_counter) {
      if (issue.kind === 'down' || issue.kind === 'unplugged') {
        activity.state = latest.oper === 'up' ? 'link_up' : 'link_down';
      } else if (issue.kind === 'flapping') {
        activity.state = activity.link_changes ? 'link_changed' : 'link_steady';
      } else {
        activity.state = 'not_tracked';
      }
    } else if (windowRows.length >= 2) {
      const delta = Object.fromEntries(COUNTERS.map(key => [key, 0]));
      let reset = false;
      for (let n = 1; n < windowRows.length; n++) {
        const before = windowRows[n - 1];
        const after = windowRows[n];
        for (const key of COUNTERS) {
          if (!Number.isSafeInteger(before[key]) || !Number.isSafeInteger(after[key]) ||
              after[key] < before[key]) {
            reset = true;
            break;
          }
          delta[key] += after[key] - before[key];
        }
        if (reset) break;
      }
      if (reset) {
        activity.state = 'reset';
      } else {
        for (const key of COUNTERS) activity['d_' + key] = delta[key];
        activity.state = delta[activity.finding_counter] > 0 ? 'rising' : 'stable';
      }
    }
    issue.activity = activity;
  }
  return issues;
}

module.exports = { attachIssueActivity, WINDOW_SECONDS, STALE_SECONDS };
