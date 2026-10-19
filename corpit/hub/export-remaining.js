const mysql = require('mysql2/promise');
(async () => {
  const pool = await mysql.createPool({ host: process.env.DB_HOST, port: process.env.DB_PORT, user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME });
  const IRV = '259065000000222001', PLA = '259065000000391179', REM = '259065000005353177';
  const HINTS = ['mineola','atlanta','las vegas','redwood','chicago','phoenix','new york','belmont','newport','san mateo'];
  const [rows] = await pool.query(
    'SELECT r.id, r.subject, r.status, r.site AS current_site, r.site_id, ' +
    'COALESCE(e1.office_location, e2.office_location) AS office ' +
    'FROM sdops_request r ' +
    'LEFT JOIN entra_users e1 ON LOWER(e1.mail) = LOWER(r.requester_email) ' +
    'LEFT JOIN entra_users e2 ON LOWER(e2.user_principal_name) = LOWER(r.requester_email) ' +
    'WHERE r.gone = 0'
  );
  const out = [];
  for (const r of rows) {
    const off = (r.office || '').toLowerCase().trim();
    let targetId = null, targetName = null;
    const isNA = (off === '') || (off === 'n/a') || (off === 'na');
    if (isNA === false) {
      if (off.indexOf('remote') !== -1) { targetId = REM; targetName = 'Remote'; }
      else if (off.indexOf('irvine') !== -1 || off.indexOf('mauchly') !== -1) { targetId = IRV; targetName = 'Irvine Location'; }
      else if (off.indexOf('plano') !== -1) { targetId = PLA; targetName = 'Plano Location'; }
      else {
        for (const h of HINTS) { if (off.indexOf(h) !== -1) { targetId = REM; targetName = 'Remote'; break; } }
      }
    }
    if (targetId === null) { continue; }
    if (String(r.site_id) === targetId) { continue; }
    r.targetName = targetName;
    out.push(r);
  }
  console.log('total needing correction:', out.length);
  const fs = require('fs');
  const esc = (s) => '"' + String(s || '').replace(/"/g, '""') + '"';
  const lines = ['RequestID,Subject,Status,CurrentSite,TargetSite,EntraOffice'];
  for (const r of out) {
    lines.push([r.id, esc(r.subject), r.status, esc(r.current_site), esc(r.targetName), esc(r.office)].join(','));
  }
  fs.writeFileSync('/home/ubuntu/site-correction-needed.csv', lines.join('\n'));
  console.log('written to /home/ubuntu/site-correction-needed.csv');
  await pool.end();
})();
