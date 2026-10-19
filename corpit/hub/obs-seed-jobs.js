// ---------------------------------------------------------------------------
// obs-seed-jobs.js - applies obs-jobs.json to the obs_job registry. 2026-09-07
//
// The registry decides what the observability page is capable of noticing. Until
// this file existed its 22 rows had been typed at a mysql prompt: there was no
// writer anywhere in the build, so the only supported way to declare a new
// collector was for someone to know that, and to remember. A registry that is
// hard to add to is a registry that silently goes stale, and a stale registry
// makes "7 jobs need attention" a number computed over an unknown fraction of
// the jobs that exist. Declaring a job is now an edit to a file in the deploy
// tree, which is reviewable, diffable and rolls back with everything else.
//
// Rules:
//   * Upsert by jobName. Re-running is a no-op, so this is safe at every start.
//   * NEVER delete. A registry row that is not in the manifest is reported, not
//     removed - it may be a hand-declared job someone still depends on, and
//     deleting it would take its history off the page without telling anyone.
//   * Never fatal. The API must start even if the manifest is unreadable; it
//     says so in the log rather than failing to boot over telemetry config.
// ---------------------------------------------------------------------------
'use strict';

const fs = require('fs');
const path = require('path');

const MANIFEST = path.join(__dirname, 'obs-jobs.json');

function intOr(v, dflt) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : dflt;
}

// The note is documentation shown to a person, so damaging it silently is the
// same failure as any other silently-wrong reading on these pages. NOTE_MAX is a
// runaway guard, not a formatting decision, and hitting it is reported.
const NOTE_MAX = 4000;
function clipNote(jobName, notes, out) {
  const s = String(notes);
  if (s.length <= NOTE_MAX) return s;
  out.clipped.push(jobName + ' (' + s.length + ' chars)');
  return s.slice(0, NOTE_MAX);
}

async function seed(pool) {
  const out = { applied: 0, declared: 0, unmanaged: [], clipped: [], error: null };
  if (!pool) { out.error = 'no pool'; return out; }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  } catch (e) {
    out.error = 'manifest unreadable: ' + (e.code || e.message);
    return out;
  }
  const jobs = Array.isArray(manifest && manifest.jobs) ? manifest.jobs : null;
  if (!jobs) { out.error = 'manifest has no jobs array'; return out; }
  out.declared = jobs.length;

  for (const j of jobs) {
    if (!j || !j.jobName) continue;
    try {
      await pool.query(
        'INSERT INTO obs_job (job_name, label, script, owner_page, cadence_min, grace_min, ' +
        'enabled, scheduled, schedule_src, notes) VALUES (?,?,?,?,?,?,?,?,?,?) ' +
        'ON DUPLICATE KEY UPDATE label=VALUES(label), script=VALUES(script), ' +
        'owner_page=VALUES(owner_page), cadence_min=VALUES(cadence_min), ' +
        'grace_min=VALUES(grace_min), enabled=VALUES(enabled), scheduled=VALUES(scheduled), ' +
        'schedule_src=VALUES(schedule_src), notes=VALUES(notes)',
        [String(j.jobName).slice(0, 191), String(j.label || j.jobName).slice(0, 160),
         j.script ? String(j.script).slice(0, 191) : null,
         j.ownerPage ? String(j.ownerPage).slice(0, 64) : null,
         intOr(j.cadenceMin, 1440), intOr(j.graceMin, 30),
         j.enabled === false ? 0 : 1, j.scheduled === true ? 1 : 0,
         j.scheduleSrc ? String(j.scheduleSrc).slice(0, 191) : null,
         j.notes ? clipNote(j.jobName, j.notes, out) : null]
      );
      out.applied++;
    } catch (e) {
      // One malformed entry must not stop the rest, and must not be silent.
      out.error = out.error || ('row ' + j.jobName + ': ' + (e.code || e.message));
    }
  }

  // Drift the other way: rows in the table that the manifest does not declare.
  try {
    const names = new Set(jobs.map(function (j) { return j.jobName; }));
    const rows = (await pool.query('SELECT job_name FROM obs_job'))[0];
    out.unmanaged = rows.map(function (r) { return r.job_name; })
                        .filter(function (n) { return !names.has(n); });
  } catch (e) { out.unmanaged = null; }   // null: not measured, not "none"

  return out;
}

module.exports = { seed, MANIFEST };
