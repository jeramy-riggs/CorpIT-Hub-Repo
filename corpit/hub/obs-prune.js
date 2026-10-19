// ---------------------------------------------------------------------------
// obs-prune.js - layer 0: keep the observability tables from becoming the
//                outage.                                            2026-09-07
//
// Nothing in this build deleted a row. obs_request, obs_dependency,
// obs_client_event and srv_job_run only ever grew, and obs_dependency grows
// fastest because it is NOT sampled - every outbound call to every vendor is a
// row. On an idle host with nobody using it yet that was already ~400 rows an
// hour, and the whole point of the port is that people are about to start using
// it. A telemetry table that fills the disk takes down the application it was
// installed to observe, which is the one failure this build must not cause.
//
// Retention is an operator decision, so it lives in the console like every
// other setting (obs.retention_days, obs.job_run_retention_days) and arrives
// here through the same published file as the rest of the tunables.
//
// Deletes are batched and bounded. One unbounded DELETE over a table that has
// been growing for months is a long lock on the table the flusher is writing
// to; MAX_BATCHES caps a single pass so a first run after a long gap makes
// steady progress over several hours instead of stalling everything once.
//
// Every table here now has a leading index on the column this ranges over, and
// two of them did not before: obs_client_event was indexed on occurred_at (the
// browser clock, see below) and srv_job_run only on (job_name, observed_at),
// which a bare observed_at range cannot use. Both got one:
//   ALTER TABLE obs_client_event ADD KEY ix_oce_received (received_at);
//   ALTER TABLE srv_job_run      ADD KEY ix_srv_job_run_observed (observed_at);
// Additive and reversible with DROP INDEX. Without them each pass is a full
// table scan of the exact table that is growing, which gets slower precisely as
// it gets more important.
//
// It runs through obs-job.wrap, so it is visible on the dashboard as a job with
// real state. A prune that starts failing is exactly as interesting as a
// collector that starts failing, and it should not need a different place to
// look.
// ---------------------------------------------------------------------------
'use strict';

const obs = require('./obs-lib');
const obsJob = require('./obs-job');

const JOB = 'obs-retention-prune';
const BATCH = 5000;
const MAX_BATCHES = 40;          // per table, per pass: 200k rows is plenty of headroom
const EVERY_MS = 3600000;        // hourly
const FIRST_MS = 120000;         // let the process finish booting first

// Which column carries the time each table is aged by. obs_client_event is the
// one that matters: occurred_at comes from the BROWSER's clock. A machine with
// a clock set forward would write rows that never aged out, and a retention
// policy that a client can opt out of is not a retention policy. received_at is
// this server's own timestamp, so it is the only defensible basis.
const TABLES = [
  { table: 'obs_request',      column: 'at' },
  { table: 'obs_dependency',   column: 'at' },
  { table: 'obs_client_event', column: 'received_at' },
];
const JOB_RUNS = { table: obsJob.RUN_TABLE, column: 'observed_at' };

let timer = null;

async function pruneOne(pool, spec, days) {
  const out = { table: spec.table, deleted: 0, capped: false, error: null };
  const sql = 'DELETE FROM `' + spec.table + '` WHERE `' + spec.column +
              '` < NOW() - INTERVAL ? DAY LIMIT ' + BATCH;
  for (let i = 0; i < MAX_BATCHES; i++) {
    let r;
    try {
      r = (await pool.query(sql, [days]))[0];
    } catch (e) {
      out.error = e.code || e.message;
      return out;
    }
    const n = r && r.affectedRows ? r.affectedRows : 0;
    out.deleted += n;
    if (n < BATCH) return out;          // caught up
  }
  // Still more to delete than one pass allows. Reported, not hidden: an
  // operator who lowers retention from 90 days to 7 should be able to see that
  // it is working through the backlog rather than wonder why the table is still
  // large an hour later.
  out.capped = true;
  return out;
}

async function runOnce(pool) {
  const days = Math.max(1, Math.round(obs.CFG.retentionDays));
  const jobDays = Math.max(1, Math.round(obs.CFG.jobRunRetentionDays));
  const results = [];
  for (const spec of TABLES) results.push(await pruneOne(pool, spec, days));
  results.push(await pruneOne(pool, JOB_RUNS, jobDays));

  const failed = results.filter(function (r) { return r.error; });
  if (failed.length) {
    // Thrown so obs-job.wrap records the run as failed. A prune that cannot
    // delete is the beginning of the disk problem it exists to prevent, and it
    // must not be recorded as a success.
    const e = new Error('prune failed: ' + failed.map(function (r) {
      return r.table + ': ' + r.error;
    }).join('; '));
    e.results = results;
    throw e;
  }
  return results;
}

function start(pool) {
  if (timer || !pool) return false;
  const tick = function () {
    if (!obs.CFG.enabled) return;   // the emergency stop stops this too
    obsJob.wrap(pool, JOB, function () { return runOnce(pool); })
      .catch(function (e) { console.error('[obs-prune]', e.message); });
  };
  setTimeout(tick, FIRST_MS).unref();
  timer = setInterval(tick, EVERY_MS);
  if (timer.unref) timer.unref();
  return true;
}

module.exports = { start, runOnce, pruneOne, JOB, TABLES, JOB_RUNS, BATCH, MAX_BATCHES };
