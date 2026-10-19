// ─────────────────────────────────────────────────────────────────────────────
// vhost-health-job.js — probes every REGISTERED, monitoring-enabled virtual
// host in srv_vhost, writes srv_vhost_check + srv_vhost_current, samples
// cronwrap job runs into srv_job_run, and synthesises srv_finding rows.
//
// Registry-only by construction: the FQDN list comes from srv_vhost and the
// redirect follower is handed that same list as its allow-set. Nothing else is
// ever contacted. Run from cron:
//   */10 * * * * /usr/bin/node /var/www/corpit-hub-api/vhost-health-job.js
// DB_* comes from this directory's .env via dotenv below -- never from
// `env $(cat .env | xargs)`, which drops everything after a value with a space.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

require('dotenv').config({ path: __dirname + '/.env' });

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const probe = require('./srv-probe-lib');

const CRONWRAP_DIR = '/var/log/corpit/cronwrap';
// Which machine a run happened on. srv_job_run had no such column, and this
// database was seeded from ITAM's - so 956 of its rows describe jobs that ran on
// ITAM in August and were indistinguishable from this host's own. Two DECLARED
// jobs resolve their "last run" against those rows today. Unstamped, a seeded row
// with a recent timestamp would paint a job green here that has never run here
// once, which is the Cert Watchtower failure exactly. Rows written before this
// column existed stay NULL and are reported as unattributed, not as evidence.
const HOST = require('os').hostname();
const CHECK_RETENTION_DAYS = 30;
const CONCURRENCY = 4;

function pool() {
  return mysql.createPool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT) || 3306,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    connectionLimit: 2,
    charset: 'utf8mb4',
  });
}

async function loadThresholds(db) {
  const fallback = {
    vhost_response_ms: { warn: 1500, crit: 5000 },
    cert_days_left:    { warn: 30,   crit: 7 },
  };
  try {
    const [rows] = await db.query('SELECT threshold_key, warn_value, crit_value FROM srv_threshold');
    const t = {};
    rows.forEach(function (r) { t[r.threshold_key] = { warn: Number(r.warn_value), crit: Number(r.crit_value) }; });
    return Object.assign(fallback, t);
  } catch (e) { return fallback; }
}

// Bounded fan-out: probes are network-bound and the box also serves the app.
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = new Array(Math.min(limit, items.length)).fill(0).map(async function () {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      try { out[idx] = await fn(items[idx], idx); }
      catch (e) { out[idx] = { __error: e.message }; }
    }
  });
  await Promise.all(workers);
  return out;
}

// ── findings ────────────────────────────────────────────────────────────────
// Each finding carries a stable fingerprint so a recurring condition updates
// one row (preserving first_seen_at and any acknowledgement) instead of
// producing a new alert every ten minutes.
function fp(parts) { return parts.filter(Boolean).join('|').slice(0, 191); }

async function upsertFinding(db, f) {
  await db.query(
    'INSERT INTO srv_finding (fingerprint, severity, confidence, item_type, item_ref, item_label, ' +
    'title, detail, probable_cause, impact, recommendation, evidence, status) ' +
    'VALUES (?,?,?,?,?,?,?,?,?,?,?,?, "open") ' +
    'ON DUPLICATE KEY UPDATE severity=VALUES(severity), confidence=VALUES(confidence), ' +
    'item_label=VALUES(item_label), title=VALUES(title), detail=VALUES(detail), ' +
    'probable_cause=VALUES(probable_cause), impact=VALUES(impact), ' +
    'recommendation=VALUES(recommendation), evidence=VALUES(evidence), ' +
    'last_seen_at=CURRENT_TIMESTAMP, resolved_at=NULL, ' +
    // An acknowledged finding that is still firing stays acknowledged; a
    // resolved one that fires again reopens.
    'status=IF(status="resolved","open",status)',
    [f.fingerprint, f.severity, f.confidence || 'confirmed', f.item_type, f.item_ref,
      f.item_label || null, f.title, f.detail || null, f.probable_cause || null,
      f.impact || null, f.recommendation || null, JSON.stringify(f.evidence || {})]
  );
}

// Anything this run did NOT re-raise, within the families this job owns, is
// no longer true — close it rather than leaving a stale alert on the board.
async function closeStale(db, family, liveFingerprints) {
  const live = liveFingerprints.length ? liveFingerprints : ['__none__'];
  const marks = live.map(function () { return '?'; }).join(',');
  await db.query(
    'UPDATE srv_finding SET status="resolved", resolved_at=CURRENT_TIMESTAMP ' +
    'WHERE status<>"resolved" AND fingerprint LIKE ? AND fingerprint NOT IN (' + marks + ')',
    [family + '|%'].concat(live)
  );
}

function vhostFindings(vh, r) {
  const list = [];
  const ref = String(vh.id);
  const label = vh.fqdn;
  const base = { item_type: 'vhost', item_ref: ref, item_label: label };
  const ev = { fqdn: vh.fqdn, resolved_ip: r.resolved_ip, status: r.last_status, response_ms: r.response_ms };

  if (r.flags.indexOf('dns-nxdomain') !== -1 || r.flags.indexOf('dns-no-address') !== -1) {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'dns', ref]), severity: 'critical', confidence: 'confirmed',
      title: 'Registered subdomain does not resolve',
      detail: vh.fqdn + ' is registered in CorpIT but DNS returned no address.',
      probable_cause: 'The DNS record was removed, or the name is shadowed by a container record in the zone.',
      impact: 'Every application and API served from this host name is unreachable by name.',
      recommendation: 'Confirm the A record exists in the nrpi.local zone and that no same-label container is shadowing it.',
      evidence: ev,
    }));
  }
  if (r.flags.indexOf('dns-unexpected-target') !== -1) {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'dnstarget', ref]), severity: 'warning', confidence: 'confirmed',
      title: 'DNS resolves to an unexpected address',
      detail: vh.fqdn + ' resolves to ' + r.resolved_ip + '; CorpIT has ' + vh.expected_ip + ' on record.',
      probable_cause: 'The record was repointed, or the expected address on the CorpIT record is out of date.',
      impact: 'Traffic may be reaching a different host than the one CorpIT has on record for this name.',
      recommendation: 'Confirm which address is correct, then fix either the DNS record or the CorpIT registration.',
      evidence: ev,
    }));
  }
  if (r.flags.indexOf('unavailable') !== -1) {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'down', ref]), severity: 'critical', confidence: 'confirmed',
      title: 'Website is unavailable',
      detail: vh.fqdn + ' did not answer: ' + (r.error_message || 'no response') + '.',
      probable_cause: r.error_code === 'ECONNREFUSED'
        ? 'Nothing is listening on the port — the web server or its listener is likely stopped.'
        : (r.error_code === 'ETIMEDOUT' ? 'The connection timed out; a firewall rule or an overloaded host would both look like this.' : null),
      impact: 'The application on this host name is down for all users.',
      recommendation: 'Check the web server on ' + (vh.server_hostname || 'its host') + ' and the listener for ' + vh.binding + '.',
      evidence: ev,
    }));
  }
  if (r.flags.indexOf('redirect-loop') !== -1) {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'loop', ref]), severity: 'critical', confidence: 'confirmed',
      title: 'Redirect loop', detail: vh.fqdn + ' redirects back to itself and never reaches a final response.',
      probable_cause: 'An HTTP-to-HTTPS rule and a canonical-host rule are likely bouncing the request between each other.',
      impact: 'Browsers abort the request; the site is effectively down.',
      recommendation: 'Review the redirect rules in ' + (vh.binding || 'the vhost configuration') + '.',
      evidence: Object.assign({ hops: r.redirect_hops, redirect_to: r.redirect_to }, ev),
    }));
  }
  if (r.flags.indexOf('unexpected-status') !== -1) {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'status', ref]), severity: r.last_status >= 500 ? 'critical' : 'warning', confidence: 'confirmed',
      title: 'Unexpected HTTP status',
      detail: vh.fqdn + vh.probe_path + ' returned HTTP ' + r.last_status + '; CorpIT expects ' + vh.expected_status + '.',
      probable_cause: r.last_status >= 500 ? 'The application behind this vhost is erroring rather than the web server failing.'
        : (r.last_status === 401 || r.last_status === 403 ? 'The probe path sits behind an auth gate.' : null),
      impact: r.last_status >= 500 ? 'Users see an error page instead of the application.' : 'The monitored path may not represent real availability.',
      recommendation: r.last_status === 401 || r.last_status === 403
        ? 'Point the probe path at an unauthenticated health path, or set the expected status to ' + r.last_status + '.'
        : 'Check the application log on the hosting server for this vhost.',
      evidence: ev,
    }));
  }
  if (r.flags.indexOf('slow-response') !== -1) {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'slow', ref]), severity: 'warning', confidence: 'confirmed',
      title: 'Excessive response time',
      detail: vh.fqdn + ' answered in ' + r.response_ms + ' ms.',
      probable_cause: 'Slow upstream, database contention, or a saturated host.',
      impact: 'Pages feel unresponsive; long requests can queue behind each other.',
      recommendation: 'Compare against the hosting server’s CPU / IO pressure for the same window.',
      evidence: ev,
    }));
  }
  if (r.cert_state === 'expired') {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'certexp', ref]), severity: 'critical', confidence: 'confirmed',
      title: 'TLS certificate has expired',
      detail: 'The certificate served for ' + vh.fqdn + ' expired ' + Math.abs(r.tls_days_left) + ' day(s) ago.',
      impact: 'Browsers and API clients refuse the connection.',
      recommendation: 'Reissue and install the certificate, then reload the web server.',
      evidence: { issuer: r.tls_issuer, not_after: r.tls_not_after },
    }));
  } else if (r.cert_state === 'mismatch') {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'certname', ref]), severity: 'critical', confidence: 'confirmed',
      title: 'Certificate hostname mismatch',
      detail: 'The certificate served for ' + vh.fqdn + ' does not carry that name (CN ' + (r.tls_subject || 'unknown') + ').',
      probable_cause: 'The default vhost’s certificate is answering because SNI is not matching this server block.',
      impact: 'Clients see a certificate warning and may refuse to connect.',
      recommendation: 'Confirm the server block for ' + vh.fqdn + ' names its own certificate, and that the name is in the SAN list.',
      evidence: { subject: r.tls_subject, issuer: r.tls_issuer },
    }));
  } else if (r.cert_state === 'critical' || r.cert_state === 'warning') {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'certsoon', ref]), severity: r.cert_state === 'critical' ? 'critical' : 'warning', confidence: 'confirmed',
      title: 'TLS certificate expires soon',
      detail: 'The certificate for ' + vh.fqdn + ' has ' + r.tls_days_left + ' day(s) left.',
      impact: 'Once it lapses, every client of this host name fails to connect.',
      recommendation: 'Schedule the reissue now; renewal here is manual.',
      evidence: { issuer: r.tls_issuer, not_after: r.tls_not_after, days_left: r.tls_days_left },
    }));
  }
  if (r.flags.indexOf('tls-handshake-failed') !== -1) {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'tls', ref]), severity: 'critical', confidence: 'confirmed',
      title: 'TLS handshake failed',
      detail: vh.fqdn + ':' + vh.port + ' did not complete a TLS handshake — ' + (r.error_message || 'no certificate presented') + '.',
      probable_cause: 'Nothing is listening on the TLS port, or the binding presents no certificate.',
      impact: 'HTTPS is unavailable for this host name.',
      recommendation: 'Check the listener and certificate paths in ' + (vh.binding || 'the vhost configuration') + '.',
      evidence: ev,
    }));
  }
  if (r.flags.indexOf('no-https') !== -1) {
    list.push(Object.assign({}, base, {
      fingerprint: fp(['vhost', 'nohttps', ref]), severity: 'warning', confidence: 'confirmed',
      title: 'Missing HTTPS',
      detail: vh.fqdn + ' is registered as plain HTTP only.',
      impact: 'Traffic to this host name is not encrypted in transit.',
      recommendation: 'Add a TLS binding and set “expect HTTPS” on the CorpIT record.',
      evidence: ev,
    }));
  }
  return list;
}

// ── job-run sampling ────────────────────────────────────────────────────────
async function sampleJobRuns(db) {
  let files = [];
  try { files = fs.readdirSync(CRONWRAP_DIR).filter(function (f) { return /\.json$/.test(f); }); }
  catch (e) { return 0; }
  let n = 0;
  for (const f of files) {
    let j;
    try { j = JSON.parse(fs.readFileSync(path.join(CRONWRAP_DIR, f), 'utf8')); } catch (e) { continue; }
    if (!j || !j.startedAt) continue;
    const name = f.replace(/\.json$/, '');
    const state = j.running ? 'running' : (j.exit === 0 ? 'success' : (j.exit == null ? 'unknown' : 'failed'));
    try {
      await db.query(
        'INSERT INTO srv_job_run (job_name, started_at, finished_at, duration_sec, exit_code, state, host) ' +
        'VALUES (?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE finished_at=VALUES(finished_at), ' +
        'duration_sec=VALUES(duration_sec), exit_code=VALUES(exit_code), state=VALUES(state), ' +
        'host=VALUES(host)',
        [name.slice(0, 191), new Date(j.startedAt), j.finishedAt ? new Date(j.finishedAt) : null,
          j.durationSec != null ? j.durationSec : null, j.exit != null ? j.exit : null, state, HOST]
      );
      n++;
    } catch (e) { /* one bad wrapper file must not stop the rest */ }
  }

  // In-flight markers (<job>.run). A hung job shows as 'running' with a
  // started_at that keeps ageing, which is a different and more useful fact
  // than 'overdue'. The one marker deliberately skipped is our own: this
  // process is itself running under cronwrap, so its marker is always present
  // and always fresh, and recording it would pin this job at 'running' forever
  // -- which is exactly the bug this branch was added to fix.
  //
  // started_at is part of the unique key, so the row written here is the same
  // row the completed record updates on the next pass: 'running' becomes
  // 'success' or 'failed' rather than accumulating a second row.
  let markers = [];
  try { markers = fs.readdirSync(CRONWRAP_DIR).filter(function (f) { return /\.run$/.test(f); }); }
  catch (e) { markers = []; }
  const selfJob = process.env.CRONWRAP_JOB || '';
  for (const f of markers) {
    const name = f.replace(/\.run$/, '');
    if (name === selfJob) continue;
    let m;
    try { m = JSON.parse(fs.readFileSync(path.join(CRONWRAP_DIR, f), 'utf8')); } catch (e) { continue; }
    if (!m || !m.startedAt) continue;
    try {
      await db.query(
        'INSERT INTO srv_job_run (job_name, started_at, finished_at, duration_sec, exit_code, state, host) ' +
        'VALUES (?,?,NULL,NULL,NULL,?,?) ON DUPLICATE KEY UPDATE state=VALUES(state), host=VALUES(host)',
        [name.slice(0, 191), new Date(m.startedAt), 'running', HOST]
      );
      n++;
    } catch (e) { /* one bad marker must not stop the rest */ }
  }
  return n;
}

// ── main ────────────────────────────────────────────────────────────────────
(async function () {
  const db = pool();
  const started = Date.now();
  try {
    const th = await loadThresholds(db);

    const [vhosts] = await db.query(
      'SELECT v.*, s.hostname AS server_hostname FROM srv_vhost v ' +
      'LEFT JOIN srv_server s ON s.id = v.server_id ' +
      'WHERE v.status <> "retired" AND v.monitoring_enabled = 1'
    );
    // The allow-set for redirect following is every registered FQDN, including
    // ones with monitoring paused — a redirect INTO a known host is in scope.
    const [allFqdn] = await db.query('SELECT fqdn FROM srv_vhost');
    const allowed = new Set(allFqdn.map(function (r) { return String(r.fqdn).toLowerCase(); }));

    console.log('[vhost-health] probing ' + vhosts.length + ' registered vhost(s)');

    const results = await mapLimit(vhosts, CONCURRENCY, async function (vh) {
      const r = await probe.probeVhost(vh, allowed, th);
      return { vh: vh, r: r };
    });

    const liveFp = [];
    for (const item of results) {
      if (!item || item.__error) { console.error('[vhost-health] probe error:', item && item.__error); continue; }
      const vh = item.vh, r = item.r;

      const [ins] = await db.query(
        'INSERT INTO srv_vhost_check (vhost_id, state, dns_state, resolved_ip, http_status, https_status, ' +
        'last_status, response_ms, redirect_to, redirect_hops, redirect_loop, tls_issuer, tls_subject, ' +
        'tls_not_after, tls_days_left, tls_name_match, tls_self_signed, cert_state, https_available, ' +
        'http_available, error_code, error_message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        [vh.id, r.state, r.dns_state, r.resolved_ip, r.http_status, r.https_status, r.last_status,
          r.response_ms, r.redirect_to, r.redirect_hops, r.redirect_loop, r.tls_issuer, r.tls_subject,
          r.tls_not_after, r.tls_days_left, r.tls_name_match, r.tls_self_signed, r.cert_state,
          r.https_available, r.http_available, r.error_code, r.error_message]
      );

      const healthy = r.state === 'healthy';
      await db.query(
        'INSERT INTO srv_vhost_current (vhost_id, last_check_id, state, dns_state, resolved_ip, last_status, ' +
        'response_ms, redirect_to, redirect_loop, tls_issuer, tls_not_after, tls_days_left, tls_name_match, ' +
        'cert_state, https_available, http_available, error_message, checked_at, ok_since, failing_since) ' +
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,' +
        (healthy ? 'CURRENT_TIMESTAMP' : 'NULL') + ',' + (healthy ? 'NULL' : 'CURRENT_TIMESTAMP') + ') ' +
        'ON DUPLICATE KEY UPDATE last_check_id=VALUES(last_check_id), state=VALUES(state), ' +
        'dns_state=VALUES(dns_state), resolved_ip=VALUES(resolved_ip), last_status=VALUES(last_status), ' +
        'response_ms=VALUES(response_ms), redirect_to=VALUES(redirect_to), redirect_loop=VALUES(redirect_loop), ' +
        'tls_issuer=VALUES(tls_issuer), tls_not_after=VALUES(tls_not_after), tls_days_left=VALUES(tls_days_left), ' +
        'tls_name_match=VALUES(tls_name_match), cert_state=VALUES(cert_state), ' +
        'https_available=VALUES(https_available), http_available=VALUES(http_available), ' +
        'error_message=VALUES(error_message), checked_at=CURRENT_TIMESTAMP, ' +
        // Keep the moment the condition STARTED, not the moment we last saw it.
        'ok_since=' + (healthy ? 'COALESCE(ok_since, CURRENT_TIMESTAMP)' : 'NULL') + ', ' +
        'failing_since=' + (healthy ? 'NULL' : 'COALESCE(failing_since, CURRENT_TIMESTAMP)'),
        [vh.id, ins.insertId, r.state, r.dns_state, r.resolved_ip, r.last_status, r.response_ms,
          r.redirect_to, r.redirect_loop, r.tls_issuer, r.tls_not_after, r.tls_days_left,
          r.tls_name_match, r.cert_state, r.https_available, r.http_available, r.error_message]
      );

      for (const f of vhostFindings(vh, r)) { await upsertFinding(db, f); liveFp.push(f.fingerprint); }
      console.log('[vhost-health] ' + vh.fqdn + ' -> ' + r.state + (r.last_status ? ' HTTP ' + r.last_status : '') +
        (r.response_ms != null ? ' ' + r.response_ms + 'ms' : '') + (r.flags.length ? ' [' + r.flags.join(',') + ']' : ''));
    }

    await closeStale(db, 'vhost', liveFp);

    const n = await sampleJobRuns(db);
    console.log('[vhost-health] sampled ' + n + ' job run(s)');

    const [del] = await db.query(
      'DELETE FROM srv_vhost_check WHERE checked_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [CHECK_RETENTION_DAYS]);
    if (del.affectedRows) console.log('[vhost-health] pruned ' + del.affectedRows + ' old check row(s)');

    console.log('[vhost-health] done in ' + Math.round((Date.now() - started) / 1000) + 's');
  } catch (e) {
    console.error('[vhost-health] FAILED:', e.message);
    process.exitCode = 1;
  } finally {
    await db.end();
  }
})();
