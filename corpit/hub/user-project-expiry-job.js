/**
 * user-project-expiry-job.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Nightly job: expire overdue grants + close overdue projects.
 *
 * Grant expiry  — auto grants where expires_at < NOW() and status='active'
 * Project close — projects where planned_end_date < TODAY(), status='active',
 *                 default_removal_mode='auto'
 *
 * Flags:
 *   --dry   Print what would happen, make no changes (default)
 *   --apply Perform AD removal + DB updates
 *
 * Cron (ubuntu): 0 1 * * * node /var/www/corpit-hub-api/user-project-expiry-job.js --apply >> /home/ubuntu/user-project-expiry.log 2>&1
 * ─────────────────────────────────────────────────────────────────────────────
 */
'use strict';
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const path      = require('path');
const { spawn } = require('child_process');
const mysql     = require('mysql2/promise');

const DRY = !process.argv.includes('--apply');
if (DRY) console.log('[expiry-job] DRY RUN — pass --apply to commit changes');

const pool = mysql.createPool({
  host:               process.env.DB_HOST || 'localhost',
  port:               parseInt(process.env.DB_PORT || '3306', 10),
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  database:           process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit:    5,
});

// ─── AD helper (same impl as user-project-routes.js) ─────────────────────────
function runManageGroups({ samAccountName, addGroups = [], removeGroups = [] }) {
  return new Promise((resolve, reject) => {
    if (!process.env.WINRM_USER || !process.env.WINRM_PASS) {
      return reject(new Error('WinRM credentials not configured'));
    }
    const scriptPath = path.join(__dirname, 'manage-groups.py');
    const payload    = JSON.stringify({ samAccountName, addGroups, removeGroups });
    const child = spawn('python3', [scriptPath], {
      env: { ...process.env },
      timeout: 90000,
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.on('error', err => reject(err));
    child.on('close', code => {
      if (code !== 0 && !stdout) return reject(new Error(stderr || `manage-groups.py exited ${code}`));
      try { resolve(JSON.parse(stdout.trim())); }
      catch (e) { reject(new Error(`manage-groups.py invalid JSON: ${stdout.slice(0, 200)}`)); }
    });
    child.stdin.write(payload);
    child.stdin.end();
  });
}

// ─── Audit helper ─────────────────────────────────────────────────────────────
async function audit(conn, { project_id, grant_id = null, action, details = {} }) {
  await conn.execute(
    `INSERT INTO user_project_audit (project_id, grant_id, action, actor, details, created_at)
     VALUES (?, ?, ?, 'expiry-job', ?, NOW())`,
    [project_id, grant_id, action, JSON.stringify(details)]
  );
}

// ─── Expire grants ────────────────────────────────────────────────────────────
async function expireGrants() {
  const [grants] = await pool.execute(
    `SELECT g.*, p.name AS project_name
     FROM user_project_grants g
     JOIN user_projects p ON p.id = g.project_id
     WHERE g.status = 'active'
       AND g.removal_mode = 'auto'
       AND g.expires_at < NOW()`
  );

  console.log(`[expiry-job] ${grants.length} grant(s) to expire`);

  let expired = 0, skipped = 0, failed = 0;

  for (const g of grants) {
    // Check if another active grant keeps this user in the same AD group
    const [refs] = await pool.execute(
      `SELECT COUNT(*) AS c FROM user_project_grants
       WHERE user_sam = ? AND ad_group_name = ? AND status = 'active' AND id <> ?`,
      [g.user_sam, g.ad_group_name, g.id]
    );
    const otherCount = refs[0].c;

    let adAction = null;

    if (DRY) {
      console.log(`  [DRY] grant #${g.id} ${g.user_sam} → ${g.ad_group_name} | other_grants=${otherCount}`);
      continue;
    }

    const conn = await pool.getConnection();
    try {
      if (otherCount > 0) {
        adAction = 'skipped_other_active_grants';
        await audit(conn, {
          project_id: g.project_id, grant_id: g.id, action: 'ad_skip',
          details: { reason: 'other active grants', other_count: otherCount }
        });
      } else {
        try {
          const r = await runManageGroups({ samAccountName: g.user_sam, removeGroups: [g.ad_group_name] });
          const entry = (r.removed || []).find(x => x.group === g.ad_group_name);
          adAction = (entry && entry.success) ? 'removed' : 'failed';
          await audit(conn, {
            project_id: g.project_id, grant_id: g.id, action: 'ad_remove',
            details: { ad_group_name: g.ad_group_name, user_sam: g.user_sam, result: r }
          });
        } catch (err) {
          adAction = 'failed';
          failed++;
          await audit(conn, {
            project_id: g.project_id, grant_id: g.id, action: 'ad_remove',
            details: { ad_group_name: g.ad_group_name, user_sam: g.user_sam, error: err.message }
          });
        }
      }

      await conn.execute(
        `UPDATE user_project_grants
         SET status = 'expired', removed_by = 'expiry-job', removed_at = NOW(),
             ad_action_on_remove = ?
         WHERE id = ?`,
        [adAction, g.id]
      );
      await audit(conn, {
        project_id: g.project_id, grant_id: g.id, action: 'expired',
        details: { ad_action: adAction, expires_at: g.expires_at }
      });

      if (adAction === 'skipped_other_active_grants') skipped++;
      else if (adAction === 'removed') expired++;

      console.log(`  grant #${g.id} ${g.user_sam} → ${g.ad_group_name} | ${adAction}`);
    } finally {
      conn.release();
    }
  }

  if (!DRY) console.log(`[expiry-job] grants: ${expired} removed, ${skipped} skipped (other grants), ${failed} failed`);
}

// ─── Close overdue projects ───────────────────────────────────────────────────
async function closeProjects() {
  const [projects] = await pool.execute(
    `SELECT id, name, planned_end_date
     FROM user_projects
     WHERE status = 'active'
       AND default_removal_mode = 'auto'
       AND planned_end_date < CURDATE()`
  );

  console.log(`[expiry-job] ${projects.length} project(s) to close`);

  for (const p of projects) {
    if (DRY) {
      console.log(`  [DRY] project #${p.id} "${p.name}" planned_end=${p.planned_end_date}`);
      continue;
    }
    await pool.execute(
      `UPDATE user_projects SET status = 'closed', updated_by = 'expiry-job', updated_at = NOW() WHERE id = ?`,
      [p.id]
    );
    const conn = await pool.getConnection();
    try {
      await audit(conn, {
        project_id: p.id, action: 'project_closed',
        details: { reason: 'auto-expiry', planned_end_date: p.planned_end_date }
      });
    } finally {
      conn.release();
    }
    console.log(`  project #${p.id} "${p.name}" → closed`);
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
(async () => {
  const start = Date.now();
  console.log(`[expiry-job] start ${new Date().toISOString()}`);
  try {
    await expireGrants();
    await closeProjects();
  } catch (err) {
    console.error('[expiry-job] fatal:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
  console.log(`[expiry-job] done in ${((Date.now() - start) / 1000).toFixed(1)}s`);
})();
