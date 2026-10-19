// ---------------------------------------------------------------------------
// obs-job.js - layer 2: did the work that feeds these pages actually run?
//                                                                   2026-09-06
// srv_job_run already stores job OUTCOMES, and vhost-health-job.js writes to it.
// It cannot answer the question that has now caused three separate incidents,
// because the answer is an absence:
//
//   Cert Watchtower's cron died on 2026-05-08. srv_job_run simply stopped
//   gaining rows. Nothing asked "where is the row that should be here?", so the
//   page reported ok/142d for four months while the certificate really had 21
//   days left.
//
// A table of outcomes can only describe jobs that ran. A job that was deployed
// and never scheduled has no row at all - and 37 collectors on this host are in
// exactly that state. So the registry (obs_job) declares what is SUPPOSED to
// run and how often, and the resolver joins it against srv_job_run. The join is
// what turns an absence into a reportable state.
//
// The state ladder is the same one used for feeds, for the same reason - there
// must be a rung for "could not measure", and it must never be painted green:
//
//   ok            scheduled, ran inside its cadence, and the last run SUCCEEDED
//   failing       ran inside its cadence, but the last run FAILED
//   overdue       scheduled, but the newest run is older than cadence + grace
//   never-ran     declared and scheduled, and has NEVER produced a run row
//   not-scheduled declared, deployed, but nothing on this host invokes it
//   disabled      deliberately switched off; an operator decision, not a fault
//   unknown       the join itself failed. NOT ok, NOT overdue.
//
// The COLLECTION as a whole gets the same treatment, because the registry is
// hand-maintained and an empty one is the easy false all-clear: the join runs,
// finds nothing to join against, and every count is legitimately zero. So
// resolve() reports state 'empty' rather than 'measured' when nothing is
// declared, and carries `declared` so a caller that only receives the counts
// (the summary strip does) can still tell zero-problems from zero-jobs.
//
// `scheduled` is a DECLARATION, checked by hand against crontab and systemd on
// the date in schedule_src, not something this process measures - the API runs
// as `corpit` and cannot read root's crontab. The dashboard says so rather than
// implying it was measured. What IS measured is whether runs are arriving.
// ---------------------------------------------------------------------------
'use strict';

const obs = require('./obs-lib');

// Outcomes go to the EXISTING table. A second job-outcome table would create
// exactly the duplicate-implementation problem the port is meant to remove.
const RUN_TABLE = 'srv_job_run';

// The machine this process is running on. A run row is only evidence about the
// host that produced it, and this table was seeded from ITAM's - see the note in
// vhost-health-job.js. Every write stamps it; the resolver below refuses to treat
// another host's row, or an unstamped one, as proof that a job ran here.
const HOST = require('os').hostname();

// Written directly rather than through the buffer: a job records one row at the
// end of its life and then the process exits, so a 5-second flush timer would
// lose it. This is the one place where a synchronous-ish write is correct.
async function record(pool, jobName, r) {
  if (!pool || !jobName) return;
  const started = r && r.startedAt ? obs.nowSql(r.startedAt) : null;
  const finished = r && r.finishedAt ? obs.nowSql(r.finishedAt) : obs.nowSql();
  const dur = (started && finished)
    ? Math.max(0, Math.round((new Date(finished) - new Date(started)) / 1000))
    : null;
  const state = (r && r.state) || (r && r.exitCode === 0 ? 'success' : 'failed');
  try {
    await pool.query(
      'INSERT INTO `' + RUN_TABLE + '` (job_name, started_at, finished_at, duration_sec, exit_code, state, host) ' +
      'VALUES (?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE ' +
      'finished_at=VALUES(finished_at), duration_sec=VALUES(duration_sec), ' +
      'exit_code=VALUES(exit_code), state=VALUES(state), host=VALUES(host)',
      [obs.clip(jobName, 191), started, finished, dur,
       (r && Number.isFinite(r.exitCode)) ? r.exitCode : null, state, HOST]
    );
  } catch (e) { /* rule 1: never break the job you are observing */ }
}

// Convenience for a collector: obsJob.wrap(pool, 'name', async () => {...})
// Records a 'running' row up front so that a job which HANGS is distinguishable
// from one that was never invoked - without it, both look identical.
async function wrap(pool, jobName, fn) {
  const startedAt = new Date();
  await record(pool, jobName, { startedAt: startedAt, finishedAt: startedAt, state: 'running' });
  try {
    const out = await fn();
    await record(pool, jobName, { startedAt: startedAt, finishedAt: new Date(), exitCode: 0, state: 'success' });
    return out;
  } catch (e) {
    await record(pool, jobName, { startedAt: startedAt, finishedAt: new Date(), exitCode: 1, state: 'failed' });
    throw e;
  }
}

// -- the resolver -----------------------------------------------------------
async function resolve(pool) {
  const out = { scannedAt: new Date().toISOString(), jobs: [], counts: {} };
  let jobs, runs;
  try {
    jobs = (await pool.query('SELECT * FROM obs_job'))[0];
  } catch (e) {
    // The registry itself is unreadable. Report that, do not report "all clear".
    return Object.assign(out, { state: 'unknown', error: e.code || e.message, jobs: [] });
  }
  try {
    // Both halves of the join are filtered to THIS host. Filtering only the outer
    // half would pick another host's newest run as the target timestamp and then
    // match nothing, silently turning a healthy job into 'never-ran'.
    runs = (await pool.query(
      'SELECT r.job_name, r.started_at, r.finished_at, r.duration_sec, r.state, r.exit_code ' +
      'FROM ' + RUN_TABLE + ' r ' +
      'JOIN (SELECT job_name, MAX(COALESCE(finished_at, started_at, observed_at)) AS t ' +
      '      FROM ' + RUN_TABLE + ' WHERE host = ? GROUP BY job_name) m ' +
      '  ON m.job_name = r.job_name ' +
      ' AND COALESCE(r.finished_at, r.started_at, r.observed_at) = m.t ' +
      'WHERE r.host = ?', [HOST, HOST]
    ))[0];
  } catch (e) {
    return Object.assign(out, { state: 'unknown', error: e.code || e.message, jobs: [] });
  }

  // Rows for a job name that this host did not write - another machine's, or one
  // written before the host column existed. They are NOT evidence that the job
  // ran here, and they are not discarded either: a reader looking at 'never-ran'
  // deserves to know that rows under that name exist and where they came from.
  // null means the question could not be asked, which is not the same as zero.
  let unattr = null;
  try {
    unattr = new Map((await pool.query(
      'SELECT job_name, COUNT(*) AS n, MAX(COALESCE(finished_at, started_at, observed_at)) AS newest ' +
      'FROM ' + RUN_TABLE + ' WHERE host IS NULL OR host <> ? GROUP BY job_name', [HOST]
    ))[0].map(function (r) { return [r.job_name, r]; }));
  } catch (e) { unattr = null; }

  // Job names that have produced runs ON THIS HOST but that nobody declared. The
  // registry is hand-maintained, so the failure mode is a job that exists and is
  // simply absent from it - invisible to every count on the page. Reporting the
  // gap is the only thing that keeps 'N need attention' from being a number
  // computed over an unknown fraction of reality.
  try {
    out.undeclared = (await pool.query(
      'SELECT r.job_name, COUNT(*) AS runs, ' +
      '       MAX(COALESCE(r.finished_at, r.started_at, r.observed_at)) AS newest ' +
      'FROM ' + RUN_TABLE + ' r LEFT JOIN obs_job j ON j.job_name = r.job_name ' +
      'WHERE r.host = ? AND j.job_name IS NULL GROUP BY r.job_name ORDER BY newest DESC', [HOST]
    ))[0].map(function (r) {
      return { jobName: r.job_name, runs: r.runs,
               newestRunAt: r.newest ? new Date(r.newest).toISOString() : null };
    });
  } catch (e) { out.undeclared = null; }

  const last = new Map();
  runs.forEach(function (r) { last.set(r.job_name, r); });
  const now = Date.now();

  out.jobs = jobs.map(function (j) {
    const r = last.get(j.job_name) || null;
    const lastAt = r ? (r.finished_at || r.started_at) : null;
    const ageMin = lastAt ? Math.round((now - new Date(lastAt).getTime()) / 60000) : null;
    const dueMin = (j.cadence_min || 0) + (j.grace_min || 0);

    let state;
    if (!j.enabled)             state = 'disabled';
    else if (!j.scheduled)      state = 'not-scheduled';
    else if (!r)                state = 'never-ran';
    else if (ageMin > dueMin)   state = 'overdue';
    else if (r.state === 'failed') state = 'failing';
    else if (r.state === 'running') state = 'running';
    // srv_job_run.state is enum('success','failed','running','unknown') and
    // DEFAULTS to 'unknown'. vhost-health-job.js actively writes it whenever a
    // cronwrap record has no exit code -- a truncated write, a wrapper killed
    // before it could record the outcome, or any legacy seed row. The ladder
    // had no branch for it and fell into the terminal `else state = 'ok'`, so
    // the one outcome that means "the run happened and nobody knows how it
    // went" was painted green. The header of this file declares 'unknown' a
    // required rung that must never be green; this is that rung.
    else if (r.state !== 'success') state = 'unknown';
    else                        state = 'ok';

    return {
      jobName: j.job_name, label: j.label, script: j.script, page: j.owner_page,
      cadenceMin: j.cadence_min, graceMin: j.grace_min,
      enabled: !!j.enabled, scheduled: !!j.scheduled, scheduleSrc: j.schedule_src,
      notes: j.notes,
      lastRunAt: lastAt ? new Date(lastAt).toISOString() : null,
      lastRunState: r ? r.state : null,
      lastDurationSec: r ? r.duration_sec : null,
      ageMinutes: ageMin,
      overdueByMinutes: (ageMin != null && ageMin > dueMin) ? (ageMin - dueMin) : null,
      state: state,
      unattributedRuns: unattr === null ? null : (unattr.get(j.job_name) || { n: 0 }).n,
      unattributedNewestAt: (function () {
        if (unattr === null) return null;
        const u = unattr.get(j.job_name);
        return (u && u.newest) ? new Date(u.newest).toISOString() : null;
      })(),
    };
  });

  out.jobs.sort(function (a, b) {
    const rank = { failing: 0, overdue: 1, unknown: 2, 'never-ran': 3, 'not-scheduled': 4,
                   running: 5, ok: 6, disabled: 7 };
    return (rank[a.state] - rank[b.state]) || a.jobName.localeCompare(b.jobName);
  });
  out.jobs.forEach(function (j) { out.counts[j.state] = (out.counts[j.state] || 0) + 1; });
  // How many jobs anyone has DECLARED. Not how many exist on the host - nothing
  // here measures that, and a guessed count would be exactly the invented number
  // this module exists to prevent. It is the denominator a reader needs to know
  // that '0 failing' was computed over a registry someone has to maintain.
  out.declared = jobs.length;
  out.host = HOST;
  out.unattributedMeasured = unattr !== null;
  out.state = jobs.length ? 'measured' : 'empty';
  return out;
}

module.exports = { record, wrap, resolve, RUN_TABLE };
