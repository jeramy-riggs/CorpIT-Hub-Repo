// /var/www/corpit-hub-api/bug-reports-routes.js
// Mount in server.js:  app.use('/api/bugs', require('./bug-reports-routes'));
//
// Ported from ITAM 2026-09-07. Corrections applied here and NOT on ITAM:
//
//   1. Reporter identity came from x-remote-* request headers with a fallback
//      to req.body.reporter_username / reporter_email. Both are caller-supplied
//      on a route that writes an audit row and, on close, sends mail to that
//      address from it-command@auction.com. Identity now comes only from
//      req.user, which the platform gate in server.js has already established.
//   2. Ticket numbers were COUNT(*)+1. Two concurrent submits computed the same
//      number and the second lost its report to a duplicate-key 500 (the column
//      is UNIQUE); a deleted row also made the next submit reuse a number that
//      had already been issued. Now MAX(suffix)+1 with a retry on collision,
//      and the date comes from the DB (CURDATE) so it agrees with created_at
//      instead of being a UTC day off.
//   3. Uploads were stored under the caller's own filename, so evil.html kept
//      its extension and /admin/:id/screenshot served it back as text/html on
//      this origin - stored XSS against a super-admin. The name is now
//      generated and the extension comes from the validated image type.
//   4. multer's own errors (file too large, wrong type) bypassed the route's
//      try/catch and reached Express's default handler, which answers with HTML.
//      The page does r.json() on that and showed the user
//      "Unexpected token '<'" instead of "file too large". Handled below.
//   5. err.message went to the browser on every 500, leaking SQL and paths.
//      Errors are logged server-side and answered generically.
//   6. The screenshot purge on close sat INSIDE `if (isClosing &&
//      report.reporter_email)`, so a report from an identity with no mail
//      address kept its screenshot forever. Purge is gated on closing only.
//   7. fs.unlink was fire-and-forget and screenshot_deleted_at was stamped
//      regardless, so a failed delete was recorded as a completed one.
//   8. PATCH answered {success:true} whether or not the reporter was actually
//      notified. SMTP_HOST is unset on this host, so getMailer() returns null
//      and NOBODY has ever been emailed - while the form promised "you'll get
//      an email when it's fixed". The response now names what happened, GET
//      /capabilities publishes it, and the pages say only what is true.
//   9. POST /changelog/:app_key answered {success:true} for an app_key that
//      does not exist: the INSERT succeeded, the UPDATE matched no row, and
//      the caller was told the version had been bumped.
//  10. GET /admin/:id was SELECT *, returning screenshot_path (a server
//      filesystem path) to the browser. Explicit column list instead.
//  11. /admin/list capped at 200 and reported rows.length as the count, so a
//      truncated list read as a complete one. It now reports matched vs
//      returned and the page says when it is showing a page of a larger set.

const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const mysql   = require('mysql2/promise');
const nodemailer = require('nodemailer');
const rateLimit  = require('express-rate-limit');

const router = express.Router();

// ---- DB pool (corpit_hub) ---------------------------------------------------
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '',
  database: 'corpit_hub',
  waitForConnections: true,
  connectionLimit: 10,
});

// ---- RBAC -------------------------------------------------------------------
// server.js already runs a deny-by-default gate over all of /api on this port,
// so req.user is populated before anything here runs. loadCurrentUser stays so
// the module is correct if it is ever mounted somewhere without that blanket.
const createRbac = require('./rbac-middleware');
// reuseIdentity:false (G19): this stays a full re-check that queries the
// database, never a reuse of the identity the blanket already loaded.
const rbac = createRbac(pool, { reuseIdentity: false });
router.use(rbac.loadCurrentUser);

// ---- Screenshot upload config -----------------------------------------------
// Outside the web root by design: nginx serves /var/www/html, so nothing here
// is reachable except through the super-admin route below.
const UPLOAD_DIR = '/var/www/uploads/bug-reports';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
// The stored extension is chosen from THIS map, never from the caller's
// filename, so the file can only ever be served back as an image.
const IMAGE_EXT = {
  'image/png':  '.png',
  'image/jpeg': '.jpg',
  'image/gif':  '.gif',
  'image/webp': '.webp',
};
const EXT_TYPE = { '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp' };

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = IMAGE_EXT[String(file.mimetype).toLowerCase()] || '.bin';
    cb(null, crypto.randomBytes(16).toString('hex') + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
  fileFilter: (req, file, cb) => {
    const ok = Object.prototype.hasOwnProperty.call(IMAGE_EXT, String(file.mimetype).toLowerCase());
    cb(ok ? null : new Error('Only PNG, JPG, GIF, or WebP images are accepted.'), ok);
  },
});

// A public write that touches the DB and the disk. The global limiter is
// 500/min across every API on this port, which is no limit at all for this.
const submitLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  message: { error: 'Too many bug reports from this client. Wait a minute and try again.' },
  keyGenerator: (req) => {
    const peer = req.socket && req.socket.remoteAddress;
    const fromProxy = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
    return (fromProxy && req.headers['x-real-ip']) || req.ip;
  },
});

// ---- Helpers ----------------------------------------------------------------
const STATUSES     = ['new', 'in_progress', 'resolved', 'closed', 'wont_fix', 'duplicate'];
const CLOSING      = ['resolved', 'closed', 'wont_fix', 'duplicate'];
const SEVERITIES   = ['low', 'medium', 'high', 'critical'];
// The enum on app_changelog.change_type, read from the column itself so the
// two cannot drift. The literal is the fallback and is the enum as of
// 2026-09-07; the previous list ('feature','fix','improvement','breaking')
// shared exactly one value with the column, so every other valid type was
// rejected with a 400 naming types MySQL could not store.
const CHANGE_TYPES_FALLBACK = ['added', 'changed', 'fixed', 'removed', 'security', 'deprecated'];
let _changeTypes = null;
async function changeTypes() {
  if (_changeTypes) return _changeTypes;
  try {
    const [rows] = await pool.query(
      'SELECT COLUMN_TYPE AS t FROM information_schema.COLUMNS ' +
      "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'app_changelog' " +
      "AND COLUMN_NAME = 'change_type'");
    const t = rows && rows[0] && rows[0].t;
    const m = t && String(t).match(/^enum\((.*)\)$/i);
    if (m) {
      const parsed = m[1].split(',').map(v => v.trim().replace(/^'|'$/g, ''));
      if (parsed.length) { _changeTypes = parsed; return _changeTypes; }
    }
  } catch (e) {
    console.error('[bug-reports] could not read change_type enum, using fallback:', e.message);
  }
  _changeTypes = CHANGE_TYPES_FALLBACK;
  return _changeTypes;
}

// Never send err.message to the browser: it carries SQL text, column names and
// filesystem paths. Log it with an id the operator can grep for.
function fail(res, code, err, tag) {
  const ref = crypto.randomBytes(4).toString('hex');
  console.error('[bug-reports] ' + tag + ' ref=' + ref + ':', err);
  return res.status(code).json({ error: 'Server error. Reference ' + ref + '.', ref });
}

// Identity comes from the session the platform gate established. It is NOT
// read from request headers or the POST body: both are caller-supplied, and
// this value is written to an audit row and used as a mail destination.
function reporterOf(req) {
  const u = req.user;
  if (!u || !u.email) return null;
  return {
    username:    u.email,
    email:       u.email,
    displayName: u.displayName || null,
  };
}

function getMailer() {
  if (!process.env.SMTP_HOST) return null;
  return nodemailer.createTransport({
    host:   process.env.SMTP_HOST,
    port:   Number(process.env.SMTP_PORT || 25),
    secure: process.env.SMTP_SECURE === 'true',
    auth:   process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
}

function slackNotify(text) {
  if (!process.env.SLACK_WEBHOOK_URL) return;
  try {
    const https = require('https');
    const payload = JSON.stringify({ text });
    const url = new URL(process.env.SLACK_WEBHOOK_URL);
    const req = https.request({
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, () => {});
    req.on('error', () => {});
    req.write(payload); req.end();
  } catch (_) {}
}

// BUG-YYYYMMDD-NNNN. The date is the DB's, so it agrees with created_at.
// The suffix is MAX+1 rather than COUNT+1 so a deleted row cannot make the
// next submit reuse a number that was already issued, and the caller retries
// on the UNIQUE index if two submits race.
async function nextTicketNumber(conn) {
  const [[{ ymd }]] = await conn.query("SELECT DATE_FORMAT(CURDATE(), '%Y%m%d') AS ymd");
  const [[{ hi }]]  = await conn.query(
    "SELECT COALESCE(MAX(CAST(SUBSTRING_INDEX(ticket_number, '-', -1) AS UNSIGNED)), 0) AS hi " +
    'FROM bug_reports WHERE ticket_number LIKE ?',
    ['BUG-' + ymd + '-%']
  );
  return 'BUG-' + ymd + '-' + String(Number(hi) + 1).padStart(4, '0');
}

// =============================================================================
// What this service can actually do right now.
// The form used to promise "you'll get an email when it's fixed" unconditionally.
// SMTP is configured by environment, so the promise is only true on a host where
// SMTP_HOST is set; the pages read this and say the true thing either way.
// =============================================================================
router.get('/capabilities', (req, res) => {
  res.json({
    notify_reporter: process.env.SMTP_HOST ? 'email' : 'none',
    slack_notify:    process.env.SLACK_WEBHOOK_URL ? 'on' : 'off',
    max_upload_mb:   MAX_UPLOAD_BYTES / (1024 * 1024),
    accepted_types:  Object.keys(IMAGE_EXT),
  });
});

// =============================================================================
// Who am I (for the reporter line on the bug form)
// =============================================================================
router.get('/whoami', (req, res) => {
  const r = reporterOf(req);
  if (!r) return res.status(401).json({ error: 'Not authenticated' });
  res.json(r);
});

// =============================================================================
// Submit a bug report (with optional screenshot)
// =============================================================================
router.post('/submit', submitLimiter, upload.single('screenshot'), async (req, res) => {
  const reporter = reporterOf(req);
  if (!reporter) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const { app_name, app_version, title, description, steps_to_reproduce, page_url } = req.body;
  const severity = SEVERITIES.includes(req.body.severity) ? req.body.severity : 'medium';
  if (!app_name || !title || !description) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'App, title and description are required.' });
  }

  const conn = await pool.getConnection();
  try {
    let ticket = null;
    let inserted = null;
    // The UNIQUE index on ticket_number is the real arbiter. Recompute and
    // retry rather than trusting a read that another submit can invalidate
    // between the SELECT and the INSERT.
    for (let attempt = 0; attempt < 5 && !inserted; attempt++) {
      ticket = await nextTicketNumber(conn);
      try {
        const [result] = await conn.query(
          `INSERT INTO bug_reports
             (ticket_number, reporter_username, reporter_email, reporter_display_name,
              app_name, app_version, severity, title, description, steps_to_reproduce,
              browser_info, page_url, screenshot_path, screenshot_original_name, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')`,
          [
            ticket, reporter.username, reporter.email, reporter.displayName,
            app_name, app_version || null, severity, title, description, steps_to_reproduce || null,
            req.headers['user-agent'] || null, page_url || null,
            req.file ? req.file.path : null,
            req.file ? req.file.originalname : null,
          ]
        );
        inserted = result;
      } catch (e) {
        if (e && e.code === 'ER_DUP_ENTRY' && attempt < 4) continue;
        throw e;
      }
    }

    slackNotify(`:bug: New bug report *${ticket}*\n*App:* ${app_name}\n*Severity:* ${severity}\n*Reporter:* ${reporter.username}\n*Title:* ${title}`);

    const willEmail = !!process.env.SMTP_HOST;
    res.json({
      success: true,
      ticket_number: ticket,
      id: inserted.insertId,
      notify_reporter: willEmail ? 'email' : 'none',
      message: willEmail
        ? `Logged as ${ticket}. You will be emailed at ${reporter.email} when it is resolved.`
        : `Logged as ${ticket}. Email notification is not configured on this server, so check back here or ask IT for the status.`,
    });
  } catch (err) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return fail(res, 500, err, 'submit');
  } finally {
    conn.release();
  }
});

// =============================================================================
// ADMIN: list reports
// =============================================================================
router.get('/admin/list', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const { status, app_name } = req.query;
    // A cap presented as a total reads as "this is everything". Clamp it,
    // count what actually matched, and let the caller see the difference.
    let limit = Number(req.query.limit || 200);
    if (!Number.isFinite(limit) || limit < 1) limit = 200;
    limit = Math.min(limit, 1000);

    const where = []; const params = [];
    if (status)   { where.push('status = ?');   params.push(status); }
    if (app_name) { where.push('app_name = ?'); params.push(app_name); }
    const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

    const [[{ matched }]] = await pool.query(
      `SELECT COUNT(*) AS matched FROM bug_reports ${whereSql}`, params
    );
    const [rows] = await pool.query(
      `SELECT id, ticket_number, reporter_username, reporter_email, reporter_display_name,
              app_name, app_version, severity, title, status,
              (screenshot_path IS NOT NULL AND screenshot_deleted_at IS NULL) AS has_screenshot,
              screenshot_deleted_at, created_at, updated_at, resolved_at, user_notified_at
       FROM bug_reports
       ${whereSql}
       ORDER BY FIELD(status,'new','in_progress','resolved','closed','wont_fix','duplicate'),
                created_at DESC
       LIMIT ?`,
      params.concat([limit])
    );
    res.json({ reports: rows, returned: rows.length, matched: Number(matched), limit });
  } catch (err) {
    return fail(res, 500, err, 'admin/list');
  }
});

// =============================================================================
// ADMIN: single report detail
// =============================================================================
router.get('/admin/:id', rbac.requireSuperAdmin, async (req, res) => {
  try {
    // Explicit columns: SELECT * handed the browser screenshot_path, a server
    // filesystem path the page has no use for.
    const [rows] = await pool.query(
      `SELECT id, ticket_number, reporter_username, reporter_email, reporter_display_name,
              app_name, app_version, severity, title, description, steps_to_reproduce,
              browser_info, page_url, screenshot_original_name, screenshot_deleted_at,
              (screenshot_path IS NOT NULL AND screenshot_deleted_at IS NULL) AS has_screenshot,
              status, admin_notes, resolution_notes, resolved_by, resolved_at,
              user_notified_at, created_at, updated_at
       FROM bug_reports WHERE id = ?`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (err) {
    return fail(res, 500, err, 'admin/detail');
  }
});

// =============================================================================
// ADMIN: serve screenshot
// =============================================================================
router.get('/admin/:id/screenshot', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT screenshot_path, screenshot_deleted_at FROM bug_reports WHERE id = ?',
      [req.params.id]
    );
    if (!rows.length || !rows[0].screenshot_path) return res.status(404).json({ error: 'No screenshot' });
    if (rows[0].screenshot_deleted_at) return res.status(410).json({ error: 'Screenshot purged after resolution' });

    // Serve by basename out of UPLOAD_DIR, and name the type explicitly rather
    // than letting the extension decide it. Rows written before the generated
    // filename landed could still carry an arbitrary extension.
    const base = path.basename(rows[0].screenshot_path);
    const type = EXT_TYPE[path.extname(base).toLowerCase()];
    if (!type) return res.status(415).json({ error: 'Stored file is not a supported image type' });
    res.set('Content-Type', type);
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Content-Security-Policy', "default-src 'none'; sandbox");
    res.sendFile(base, { root: UPLOAD_DIR, dotfiles: 'deny' }, (err) => {
      if (err && !res.headersSent) res.status(404).json({ error: 'No screenshot' });
    });
  } catch (err) {
    return fail(res, 500, err, 'admin/screenshot');
  }
});

// =============================================================================
// ADMIN: update report. Closing notifies the reporter and purges the screenshot.
// =============================================================================
router.patch('/admin/:id', rbac.requireSuperAdmin, express.json(), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { admin_notes, resolution_notes } = req.body;
    const status   = req.body.status;
    const severity = req.body.severity;
    if (status   && !STATUSES.includes(status))     return res.status(400).json({ error: 'Unknown status' });
    if (severity && !SEVERITIES.includes(severity)) return res.status(400).json({ error: 'Unknown severity' });

    const actor = (req.user && req.user.email) || 'unknown';

    const [existing] = await conn.query('SELECT * FROM bug_reports WHERE id = ?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Not found' });
    const report = existing[0];

    const updates = []; const params = [];
    if (status)                               { updates.push('status = ?');           params.push(status); }
    if (typeof admin_notes === 'string')      { updates.push('admin_notes = ?');      params.push(admin_notes); }
    if (typeof resolution_notes === 'string') { updates.push('resolution_notes = ?'); params.push(resolution_notes); }
    if (severity)                             { updates.push('severity = ?');         params.push(severity); }

    const isClosing = CLOSING.includes(status) && !report.resolved_at;
    if (isClosing) {
      updates.push('resolved_by = ?', 'resolved_at = NOW()');
      params.push(actor);
    }
    if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });

    params.push(req.params.id);
    await conn.query(`UPDATE bug_reports SET ${updates.join(', ')} WHERE id = ?`, params);

    // ---- notify ------------------------------------------------------------
    // 'skipped' is the honest answer when the ticket was not closed by this
    // request. Every other value says what was actually attempted, so the
    // console can stop claiming an email was sent when none was.
    let notified = 'skipped';
    if (isClosing) {
      const mailer = getMailer();
      if (!report.reporter_email)   notified = 'no-address';
      else if (!mailer)             notified = 'not-configured';
      else {
        const subject = `[CorpIT Hub] Your bug report ${report.ticket_number} has been ${status}`;
        const resolutionText = resolution_notes || report.resolution_notes || '(no additional notes)';
        const body =
`Hi ${report.reporter_display_name || report.reporter_username},

Your bug report has been ${status}.

Ticket:      ${report.ticket_number}
App:         ${report.app_name}
Title:       ${report.title}
Resolution:  ${resolutionText}

Thanks for helping us improve CorpIT Hub.

— IT Operations`;
        try {
          await mailer.sendMail({
            from: process.env.SMTP_FROM || 'it-command@auction.com',
            to: report.reporter_email, subject, text: body,
          });
          await conn.query('UPDATE bug_reports SET user_notified_at = NOW() WHERE id = ?', [req.params.id]);
          notified = 'sent';
        } catch (mailErr) {
          console.error('[bug-reports] mail error:', mailErr);
          notified = 'failed';
        }
      }

      // Purge is a retention rule about the screenshot. It used to sit inside
      // the mail branch, so a report from an identity with no mail address kept
      // its screenshot for ever.
      if (report.screenshot_path && !report.screenshot_deleted_at) {
        try {
          await fs.promises.unlink(report.screenshot_path);
          await conn.query('UPDATE bug_reports SET screenshot_deleted_at = NOW() WHERE id = ?', [req.params.id]);
        } catch (unlinkErr) {
          if (unlinkErr && unlinkErr.code === 'ENOENT') {
            // Already gone from disk; the row should say so.
            await conn.query('UPDATE bug_reports SET screenshot_deleted_at = NOW() WHERE id = ?', [req.params.id]);
          } else {
            // Do NOT stamp screenshot_deleted_at: the file is still there.
            console.error('[bug-reports] screenshot purge failed for id ' + req.params.id + ':', unlinkErr);
          }
        }
      }
    }

    res.json({ success: true, notified });
  } catch (err) {
    return fail(res, 500, err, 'admin/patch');
  } finally {
    conn.release();
  }
});

// =============================================================================
// Changelog feed (all apps + entries, one payload for the master page)
// =============================================================================
router.get('/changelog', async (req, res) => {
  try {
    const [apps]    = await pool.query(
      'SELECT app_key, app_name, app_url, current_version, description, category FROM app_registry WHERE is_active = 1 ORDER BY category, app_name'
    );
    const [entries] = await pool.query(
      'SELECT app_key, version, change_type, description, released_at, released_by, is_major FROM app_changelog ORDER BY released_at DESC, id DESC'
    );
    res.json({ apps, entries });
  } catch (err) {
    return fail(res, 500, err, 'changelog');
  }
});

router.get('/changelog/:app_key', async (req, res) => {
  try {
    const [app] = await pool.query(
      'SELECT app_key, app_name, app_url, current_version, description, category, is_active FROM app_registry WHERE app_key = ?',
      [req.params.app_key]
    );
    if (!app.length) return res.status(404).json({ error: 'App not found' });
    const [entries] = await pool.query(
      'SELECT version, change_type, description, released_at, is_major FROM app_changelog WHERE app_key = ? ORDER BY released_at DESC, id DESC',
      [req.params.app_key]
    );
    res.json({ app: app[0], entries });
  } catch (err) {
    return fail(res, 500, err, 'changelog/app');
  }
});

// =============================================================================
// ADMIN: add a changelog entry (also bumps current_version)
// =============================================================================
router.post('/changelog/:app_key', rbac.requireSuperAdmin, express.json(), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { version, change_type, description, released_at, is_major } = req.body;
    if (!version || !change_type || !description) {
      return res.status(400).json({ error: 'version, change_type, and description are required' });
    }
    const types = await changeTypes();
    if (!types.includes(change_type)) {
      return res.status(400).json({ error: 'change_type must be one of: ' + types.join(', ') });
    }
    // Previously the INSERT ran, the UPDATE matched nothing, and the caller was
    // told the version had been bumped on an app that does not exist.
    const [app] = await conn.query('SELECT app_key FROM app_registry WHERE app_key = ?', [req.params.app_key]);
    if (!app.length) return res.status(404).json({ error: 'App not found: ' + req.params.app_key });

    await conn.query(
      `INSERT INTO app_changelog (app_key, version, change_type, description, released_at, is_major)
       VALUES (?, ?, ?, ?, COALESCE(?, CURDATE()), ?)`,
      [req.params.app_key, version, change_type, description, released_at || null, is_major ? 1 : 0]
    );
    await conn.query('UPDATE app_registry SET current_version = ? WHERE app_key = ?', [version, req.params.app_key]);
    res.json({ success: true, app_key: req.params.app_key, current_version: version });
  } catch (err) {
    return fail(res, 500, err, 'changelog/add');
  } finally {
    conn.release();
  }
});

// -----------------------------------------------------------------------------
// multer's errors do not reach a route's try/catch. Without this they fell to
// Express's default handler, which answers with an HTML page; the browser then
// failed on r.json() and showed the user a JSON parse error instead of
// "that file is too large".
// -----------------------------------------------------------------------------
router.use(function (err, req, res, next) {
  if (!err) return next();
  if (err instanceof multer.MulterError) {
    const msg = err.code === 'LIMIT_FILE_SIZE'
      ? 'Screenshot is larger than ' + (MAX_UPLOAD_BYTES / (1024 * 1024)) + ' MB.'
      : err.code === 'LIMIT_FILE_COUNT' || err.code === 'LIMIT_UNEXPECTED_FILE'
        ? 'Attach at most one screenshot.'
        : 'Upload rejected (' + err.code + ').';
    return res.status(400).json({ error: msg });
  }
  if (/PNG, JPG, GIF, or WebP/.test(String(err.message || ''))) {
    return res.status(400).json({ error: err.message });
  }
  return fail(res, 500, err, 'router');
});

module.exports = router;
