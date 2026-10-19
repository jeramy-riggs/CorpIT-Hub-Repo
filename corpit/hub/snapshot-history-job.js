/**
 * snapshot-history-job.js — Phase 1.1
 * Writes today's score, module scores, and per-finding status/affected to
 * sentinel_score_history / sentinel_finding_history using the SAME
 * computeFindings()/score() logic the live dashboard uses (imported from
 * sentinel-routes.js, not duplicated) — the snapshot can never drift from
 * what users see. Idempotent: safe to re-run same day (ON DUPLICATE KEY UPDATE).
 * Cron: once daily, end of day.
 */
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');
const sentinel = require('./sentinel-routes');

const pool = mysql.createPool({
  host: process.env.DB_HOST, user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 2,
});

async function main() {
  const findings = await sentinel.computeFindings();
  const { score, grade, crit, moduleScores } = sentinel.score(findings);
  const today = new Date().toISOString().slice(0, 10);

  await pool.query(
    `INSERT INTO sentinel_score_history (snapshot_date, score, grade, crit_count, module_scores)
     VALUES (?,?,?,?,?)
     ON DUPLICATE KEY UPDATE score=VALUES(score), grade=VALUES(grade),
       crit_count=VALUES(crit_count), module_scores=VALUES(module_scores), generated_at=CURRENT_TIMESTAMP`,
    [today, score, grade, crit, JSON.stringify(moduleScores)]
  );

  for (const f of findings) {
    await pool.query(
      `INSERT INTO sentinel_finding_history (snapshot_date, finding_id, severity, module, status, affected)
       VALUES (?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE status=VALUES(status), affected=VALUES(affected)`,
      [today, f.id, f.sev, f.module, f.status, f.affected]
    );
  }

  console.log(`[snapshot-history] ${today}: score=${score} grade=${grade} crit=${crit} findings=${findings.length}`);
  await pool.end();
}

main()
  .then(() => process.exit(0))
  .catch((err) => { console.error('[snapshot-history] FAILED', err.message); process.exit(1); });
