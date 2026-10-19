// collapse-stale.js — one-time: build stale_drive_summary from the latest done batch,
// then remove individual rows for drives over the threshold. No re-crawl needed.
//   cd /var/www/corpit-hub-api && env $(cat .env|grep -v '^#'|grep -v '^$'|xargs) node collapse-stale.js
const mysql = require('mysql2/promise');
const THRESHOLD = 10000;

(async () => {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3, timezone: 'Z',
  });
  const [[run]] = await pool.query("SELECT batch_id FROM stale_crawl_runs WHERE status='done' ORDER BY batch_id DESC LIMIT 1");
  if (!run) { console.log('No done batch to collapse.'); await pool.end(); return; }
  const bid = run.batch_id;
  const d10 = new Date(); d10.setFullYear(d10.getFullYear() - 10);

  await pool.query("DELETE FROM stale_drive_summary WHERE batch_id=?", [bid]);
  await pool.query(
    `INSERT INTO stale_drive_summary (batch_id, site_url, site_name, drive_name, file_count, total_bytes, count_10, bytes_10, oldest_modified, newest_modified, collapsed)
     SELECT batch_id, site_url, MAX(site_name), drive_name, COUNT(*), COALESCE(SUM(size),0),
            COALESCE(SUM(modified_date < ?),0), COALESCE(SUM(CASE WHEN modified_date < ? THEN size ELSE 0 END),0),
            MIN(modified_date), MAX(modified_date), (COUNT(*) > ?)
     FROM stale_files WHERE batch_id=? GROUP BY site_url, drive_name`,
    [d10, d10, THRESHOLD, bid]);

  const [[c]] = await pool.query("SELECT COUNT(*) n FROM stale_drive_summary WHERE batch_id=? AND collapsed=1", [bid]);
  const [del] = await pool.query(
    `DELETE FROM stale_files WHERE batch_id=? AND (site_url, drive_name) IN
       (SELECT site_url, drive_name FROM stale_drive_summary WHERE batch_id=? AND collapsed=1)`, [bid, bid]);
  console.log(`Collapsed ${c.n} archive drive(s); removed ${del.affectedRows} individual rows. Done.`);
  await pool.end();
})().catch(e => { console.error('FATAL', e); process.exit(1); });
