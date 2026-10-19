#!/usr/bin/env node
/**
 * spend-alert-digest-job.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Emails each manager the direct reports of theirs who are at or past the
 * configured share of their monthly Claude spend limit — the same list the
 * "Approaching their Claude limit" card shows on My Profile → AI tools & usage.
 *
 * SHIPS DISABLED. digest_enabled is a console setting that defaults to false, and
 * with it false this job sends nothing, to anybody, ever. That is deliberate:
 * the in-app card went live first, and mail to managers only starts once
 * somebody has read a preview and turned it on. --preview and --dry-run work
 * while it is off, precisely so that reading can happen.
 *
 * Every figure comes from spend-alert-lib, the same module the page and the
 * ticket route use. The three surfaces cannot drift because none of them owns
 * the arithmetic.
 *
 * Routing: a person alerts their DIRECT manager, and every DIRECTOR above that
 * manager, because a director is accountable for the whole subtree and sees it on
 * the same page. A skip-level entry says whose report it actually is, so a director
 * does not open a conversation the person's own manager is already having.
 *
 * Deduping (ai_alert_state, key spend_digest:<manager>): a manager is mailed
 * when the set of alerting people changes or somebody's state worsens; when
 * nothing has changed they are mailed at most weekly. A daily mail repeating
 * yesterday's unchanged list is how a digest teaches people to filter it.
 *
 * CLI:
 *   --preview [manager-email]  build the HTML, send nothing, write it to a file
 *   --dry-run                  log who would be mailed and why, send nothing
 *   --test <addr> [--as <mgr>] send one real email to <addr> (ignores enabled/hour/dedupe)
 *
 * Cron (hourly; the job itself checks digest_hour):
 *   7 * * * * cd /var/www/corpit-hub-api && node spend-alert-digest-job.js >> /var/log/claude-spend-digest.log 2>&1
 * ─────────────────────────────────────────────────────────────────────────────
 */
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const fs = require('fs');
const mysql = require('mysql2/promise');
const mailGraph = require('./mail-graph');
const spendAlert = require('./spend-alert-lib');
const aiTools = require('./ai-tools-lib');

const HUB_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://corpit.nrpi.local').replace(/\/+$/, '');
const TEAM_URL = HUB_ORIGIN + '/my-profile.html#claude/team';
const QUIET_DAYS = 7;   // an unchanged list is re-sent at most this often

// Alerts send from Enterprise Approvals, not itcommand@ (per-call override; other
// mail-graph callers keep their own sender). Env can retarget without a code change.
const ALERT_FROM      = process.env.SPEND_ALERT_FROM      || 'EnterpriseApprovals@auction.com';
const ALERT_FROM_NAME = process.env.SPEND_ALERT_FROM_NAME || 'Enterprise Approvals';
const ALERT_MAILBOX   = process.env.SPEND_ALERT_MAILBOX   || 'EnterpriseApprovals@auctiondotcom.onmicrosoft.com';
const ALERT_SENDER    = { from: ALERT_FROM, fromName: ALERT_FROM_NAME, mailbox: ALERT_MAILBOX };

function log(...a) { console.log(`[spend-digest ${new Date().toISOString()}]`, ...a); }
function err(...a) { console.error(`[spend-digest ${new Date().toISOString()}] ERROR`, ...a); }

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 3,
});

/* ─── period ───────────────────────────────────────────────────────────────
 * The digest only ever speaks about the month in progress, so the period is
 * built here rather than read from the report's coverage: same convention
 * (daysElapsed = UTC day of month), no dependency on the cost feed, which this
 * job does not read at all. */
function currentPeriod() {
  const now = new Date();
  const y = now.getUTCFullYear(), m = now.getUTCMonth();
  const month = y + '-' + String(m + 1).padStart(2, '0');
  const daysInMonth = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  return {
    month,
    label: new Date(Date.UTC(y, m, 1)).toLocaleDateString('en-US', { timeZone: 'UTC', month: 'long', year: 'numeric' }),
    isCurrent: true,
    daysInMonth,
    daysElapsed: now.getUTCDate(),
  };
}

/* ─── data ─────────────────────────────────────────────────────────────────
 * One pass over everybody who has a monthly limit, then one pass over the ancestor
 * edges above them. Shaped into the member form spend-alert-lib expects, so the
 * maths below is the same maths the card runs.
 *
 * org_reporting_edge holds (manager, member, depth) for EVERY ancestor, not just
 * the immediate one, so a director's subtree is an indexed read rather than a walk. */
async function loadPeople() {
  const [rows] = await pool.query(`
    SELECT LOWER(l.email)                              AS email,
           COALESCE(p.display_name, l.display_name, l.email) AS name,
           p.job_title                                 AS title,
           l.amount_cents, l.ptd_spend_cents, l.source_type, l.currency, l.fetched_at,
           LOWER(p.manager_email)                      AS manager_email,
           COALESCE(mp.display_name, p.manager_email)  AS manager_name
    FROM claude_spend_limit l
    JOIN org_reporting_person p  ON LOWER(p.email)  = LOWER(l.email)
    LEFT JOIN org_reporting_person mp ON LOWER(mp.email) = LOWER(p.manager_email)
    WHERE l.period = 'monthly' AND l.deleted = 0
      AND p.manager_email IS NOT NULL AND p.manager_email <> ''
  `);
  const newest = rows.reduce((a, r) => (r.fetched_at && (!a || r.fetched_at > a) ? r.fetched_at : a), null);
  // mysql2 hands DATETIME back as a Date. String()ing that yields "Wed Sep 09 2026 ..."
  // — not an ISO stamp — so a slice for "YYYY-MM-DD HH:MM" quietly drops the clock time.
  const asOf = newest ? new Date(newest).toISOString().replace('T', ' ').slice(0, 16) : null;
  const people = new Map();
  for (const r of rows) {
    people.set(r.email, {
      email: r.email,
      name: r.name,
      title: r.title || null,
      managerEmail: r.manager_email,
      managerName: r.manager_name,
      claudeLimit: {
        amount: r.amount_cents == null ? null : Number(r.amount_cents) / 100,
        currency: r.currency || 'USD',
        basis: r.source_type === 'user' ? 'individual' : 'plan default',
        sourceType: r.source_type || null,
        periodToDateSpend: Number(r.ptd_spend_cents) / 100,
        asOf,
      },
    });
  }
  return { people, asOf };
}

/**
 * Everyone who should be told about somebody, and who.
 *
 * A manager gets depth-1 only. A director gets their whole subtree — the same
 * population the team page already shows them. Whether a viewer is a director is
 * AD's answer (manages_managers), not an inference from the edge table, so it
 * matches what the page decides for the same person.
 */
async function loadViewers(people) {
  const emails = [...people.keys()];
  if (!emails.length) return new Map();
  const [edges] = await pool.query(
    'SELECT LOWER(manager_email) AS manager_email, LOWER(member_email) AS member_email, depth '
    + 'FROM org_reporting_edge WHERE member_email IN (?)', [emails]);
  const mgrEmails = [...new Set(edges.map((e) => e.manager_email))];
  if (!mgrEmails.length) return new Map();
  const [mgrs] = await pool.query(
    'SELECT LOWER(email) AS email, display_name, manages_managers, direct_reports, in_hr '
    + 'FROM org_reporting_person WHERE email IN (?)', [mgrEmails]);
  const meta = new Map(mgrs.map((m) => [m.email, m]));
  const viewers = new Map();
  for (const e of edges) {
    const p = people.get(e.member_email);
    if (!p) continue;
    const m = meta.get(e.manager_email);
    if (!m) continue;
    // The AD tree tops out in placeholder accounts — "BOD Board of Director" is a
    // node, not a person with a mailbox. HR is the roster of actual employees, so
    // only somebody HR knows about is a viewer. Today that drops exactly one
    // account, and it is that placeholder.
    if (Number(m.in_hr) !== 1) continue;
    const depth = Number(e.depth) || 1;
    const isDirector = Number(m.manages_managers) === 1;
    // A manager who is not a director hears about their own reports only.
    if (depth > 1 && !isDirector) continue;
    if (!viewers.has(e.manager_email)) {
      viewers.set(e.manager_email, {
        email: e.manager_email,
        name: m.display_name || e.manager_email,
        isDirector,
        members: [],
      });
    }
    viewers.get(e.manager_email).members.push(Object.assign({}, p, { depth, direct: depth === 1 }));
  }
  return viewers;
}

/** Every manager's own chosen threshold, in one read. */
async function loadManagerThresholds() {
  const out = new Map();
  try {
    const [rows] = await pool.query('SELECT LOWER(manager_email) AS email, threshold, email_alert FROM ai_spend_alert_manager');
    for (const r of rows) out.set(r.email, { threshold: r.threshold == null ? null : Number(r.threshold), emailAlert: Number(r.email_alert) === 1 });
  } catch (_) { /* table absent = nobody has chosen one */ }
  return out;
}

/** Tickets already raised this period, so the mail says "requested" instead of nagging. */
async function loadTickets(period) {
  const [rows] = await pool.query(
    'SELECT LOWER(subject_email) AS email, sdp_display_id, sdp_url, recommended, status, created_at ' +
    "FROM claude_limit_increase_ticket WHERE period = ? AND status <> 'failed'", [period]);
  const m = new Map();
  for (const r of rows) m.set(r.email, r);
  return m;
}

/* ─── dedupe ───────────────────────────────────────────────────────────── */
function fingerprint(period, alerts, threshold) {
  // The threshold is part of the fingerprint: a manager who lowers their own
  // number is asking to be told about the people it just added, not to wait a week.
  return period + '|th' + threshold + '|' + alerts.map((a) => a.email + ':' + a.state).sort().join(',');
}

async function lastSent(manager) {
  const [rows] = await pool.query('SELECT v FROM ai_alert_state WHERE k = ?', ['spend_digest:' + manager]);
  if (!rows.length) return null;
  try { return JSON.parse(rows[0].v); } catch (_) { return null; }
}

async function recordSent(manager, fp) {
  await pool.query(
    'INSERT INTO ai_alert_state (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)',
    ['spend_digest:' + manager, JSON.stringify({ fp, sentAt: new Date().toISOString() })]
  );
}

/** Why this manager is (or is not) getting mail. Returned as a string either way. */
function sendDecision(prev, fp) {
  if (!prev || prev.fp !== fp) return { send: true, why: prev ? 'list changed' : 'first alert' };
  const age = (Date.now() - new Date(prev.sentAt).getTime()) / 86400000;
  if (age >= QUIET_DAYS) return { send: true, why: `unchanged but ${age.toFixed(1)}d since last` };
  return { send: false, why: `unchanged, mailed ${age.toFixed(1)}d ago` };
}

/* ─── HTML ─────────────────────────────────────────────────────────────── */
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const money = (n) => '$' + Number(n || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

function baseCSS() {
  return `
    body{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#0A1628;color:#EEF4FB;margin:0;padding:24px}
    .wrap{max-width:820px;margin:0 auto;background:#0F1F35;border:1px solid #1F3A5C;border-radius:10px;overflow:hidden}
    .head{padding:24px;border-bottom:1px solid #1F3A5C;background:linear-gradient(135deg,#0F1F35,#18304E)}
    .head h1{margin:0;font-size:20px;color:#EEF4FB}
    .head p{margin:6px 0 0;font-size:13px;color:#8FA3BE}
    .section{padding:20px 24px;border-bottom:1px solid #1F3A5C}
    .section:last-child{border-bottom:none}
    .person{padding:14px 0;border-bottom:1px solid #1F3A5C}
    .person:last-child{border-bottom:none}
    .pname{font-size:15px;color:#EEF4FB;font-weight:600}
    .ptitle{font-size:12px;color:#8FA3BE;margin-left:8px}
    .figure{font-family:'JetBrains Mono',monospace;font-size:14px;margin:6px 0}
    .near{color:#FBBF24}
    .over{color:#F87171}
    .rec{display:inline-block;margin-top:8px;padding:8px 12px;background:#18304E;border-left:3px solid #0EA5E9;border-radius:4px;font-size:13px;color:#EEF4FB}
    .rec b{font-family:'JetBrains Mono',monospace}
    .why{font-size:13px;color:#C7D6E8;margin:6px 0 0}
    .meta{font-size:11px;color:#5A6F8E;margin-top:6px}
    .via{display:inline-block;margin-left:8px;padding:2px 8px;background:#18304E;border:1px solid #2D4D7A;border-radius:9px;font-size:11px;color:#8FA3BE}
    .filed{font-size:12px;color:#34D399;margin-top:6px}
    .cta{display:inline-block;margin-top:6px;padding:9px 16px;background:#0EA5E9;color:#04121F !important;border-radius:5px;font-size:13px;font-weight:600;text-decoration:none}
    .foot{padding:16px 24px;font-size:11px;color:#5A6F8E;background:#0A1628;text-align:center;line-height:1.6}
    .foot a{color:#0EA5E9;text-decoration:none}
    .banner{padding:12px 24px;background:#3B2A0B;color:#FBBF24;font-size:12px;border-bottom:1px solid #1F3A5C}
  `;
}

function renderPerson(a, ticket) {
  const cls = a.state === 'over' ? 'over' : 'near';
  const p = [];
  p.push(`<div class="person">`);
  p.push(`<div><span class="pname">${esc(a.name)}</span>${a.title ? `<span class="ptitle">${esc(a.title)}</span>` : ''}`
    + (a.direct ? '' : `<span class="via">reports to ${esc(a.reportsTo || 'someone below you')}</span>`)
    + `</div>`);
  if (a.state === 'included-only') {
    p.push(`<div class="figure over">${money(a.ptdSpend)} spent — no paid allowance</div>`);
    p.push(`<div class="why">Their limit is set to included usage only, so anything they run beyond the plan allowance has nowhere to go.</div>`);
  } else {
    p.push(`<div class="figure ${cls}">${money(a.ptdSpend)} of ${money(a.limit)} &middot; ${a.pct}%</div>`);
    const r = a.recommendation || {};
    if (r.needed) {
      p.push(`<div class="why">${esc(r.note)}</div>`);
      p.push(`<div class="rec">Recommended for ${esc(a.periodLabel)}: <b>${money(r.amount)}</b></div>`);
    } else if (a.state === 'over') {
      p.push(`<div class="why">Already past the limit for this month.</div>`);
    } else {
      p.push(`<div class="why">At this rate the month still closes inside the limit — worth a look, not necessarily an increase.</div>`);
    }
  }
  p.push(`<div class="meta">Day ${a.daysElapsed} of ${a.daysInMonth} &middot; ${esc(a.basis || 'limit')} &middot; figures from ${esc(a.asOf || 'an unknown time')} UTC</div>`);
  if (ticket) {
    const link = ticket.sdp_url ? `<a href="${esc(ticket.sdp_url)}" style="color:#34D399">${esc(ticket.sdp_display_id || 'the ticket')}</a>` : esc(ticket.sdp_display_id || '');
    p.push(`<div class="filed">Increase already requested${link ? ' — ' + link : ''}${ticket.recommended ? ' for ' + money(ticket.recommended) : ''}.</div>`);
  }
  p.push(`</div>`);
  return p.join('\n');
}

function buildHTML(manager, alerts, period, threshold, tickets, banner) {
  const n = alerts.length;
  const parts = [];
  parts.push(`<!DOCTYPE html><html><head><meta charset="utf-8"/><style>${baseCSS()}</style></head><body><div class="wrap">`);
  if (banner) parts.push(`<div class="banner">${esc(banner)}</div>`);
  const directs = alerts.filter((a) => a.direct).length;
  const below = n - directs;
  // Say exactly who these people are. "3 of your direct reports" over a list that
  // is really one report and two skip-levels is the kind of wrong that gets a
  // manager asking somebody else's report about their spending.
  const whoLine = below === 0
    ? (n === 1 ? 'One of your direct reports is' : n + ' of your direct reports are')
    : directs === 0
      ? (n === 1 ? 'One person in your organisation is' : n + ' people in your organisation are')
      : directs + ' of your direct reports and ' + below
        + (below === 1 ? ' person further down are' : ' people further down are');
  parts.push(`<div class="head"><h1>Claude spend — ${esc(period.label)}</h1>`);
  parts.push(`<p>${whoLine} at or past ${threshold}% of their monthly Claude limit.</p></div>`);
  parts.push(`<div class="section">`);
  for (const a of alerts) parts.push(renderPerson(a, tickets.get(a.email)));
  parts.push(`</div>`);
  parts.push(`<div class="section"><a class="cta" href="${TEAM_URL}">Review and request an increase</a>`);
  parts.push(`<div class="meta">Requesting an increase opens a Service Desk ticket in your name with the figures above.</div></div>`);
  parts.push(`<div class="foot">Sent to ${esc(manager.name || manager.email)} because these people are in your reporting line in Active Directory.<br/>`);
  parts.push(`Limits and spend come from the Claude Admin API, refreshed hourly. Your alert threshold is ${threshold}%, which you can change on the page above.<br/>`);
  parts.push(`<a href="${TEAM_URL}">CorpIT Hub — AI tools &amp; usage</a></div>`);
  parts.push(`</div></body></html>`);
  return parts.join('\n');
}

/* ─── main ─────────────────────────────────────────────────────────────── */
async function main() {
  const args = process.argv.slice(2);
  const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true) : null; };
  const preview = flag('--preview');
  const dryRun = args.includes('--dry-run');
  const testTo = flag('--test');
  const testAs = flag('--as');
  if (testTo === true) { err('--test requires an email address'); process.exit(2); }

  const cfg = await aiTools.spendAlertConfig();
  const period = currentPeriod();
  log(`config: threshold=${cfg.threshold}% digestEnabled=${cfg.digestEnabled} digestHour=${cfg.digestHour} (${cfg.source})`
    + (cfg.published && !cfg.published.threshold
        ? ' — threshold is this job\'s built-in default; the console has never published one' : ''));
  if (cfg.source === 'unknown') {
    // The published file exists but could not be read. Carrying on would send mail
    // under a default nobody chose, so this stops instead.
    err(`cannot read ${cfg.path}: ${cfg.error}. Refusing to run on a threshold nobody set.`);
    await pool.end();
    process.exit(1);
  }

  const live = !preview && !dryRun && !testTo;
  if (live) {
    // No global gate here: a manager who switched their own alerts on is mailed
    // even when the console default is off. digestEnabled remains an admin
    // force-all, applied per-manager in the send loop below.
    const hour = new Date().getUTCHours();
    if (hour !== cfg.digestHour) { log(`hour ${hour} UTC != digest_hour ${cfg.digestHour} → skip`); await pool.end(); return; }
  }

  const { people, asOf } = await loadPeople();
  const viewers = await loadViewers(people);
  const ownThresholds = await loadManagerThresholds();
  const tickets = await loadTickets(period.month);
  log(`${people.size} people with a monthly limit; ${viewers.size} managers and directors above them; feed as of ${asOf}`);

  // Every viewer's list, computed by the shared library on the viewer's own number.
  const digests = [];
  for (const g of viewers.values()) {
    const pref = ownThresholds.get(g.email) || {};
    const eff = spendAlert.effectiveThreshold(pref.threshold, cfg.threshold);
    const alerts = spendAlert.alertsFor(g.members, period, eff.threshold, { includeIndirect: g.isDirector });
    if (!alerts.length) continue;
    for (const a of alerts) a.periodLabel = period.label;
    digests.push({ manager: g, alerts, threshold: eff.threshold, thresholdSource: eff.source,
                   optedIn: pref.emailAlert === true,
                   fp: fingerprint(period.month, alerts, eff.threshold) });
  }
  digests.sort((a, b) => b.alerts.length - a.alerts.length);
  log(`${digests.length} managers/directors have at least one person at or past their threshold`);

  if (preview) {
    const want = typeof preview === 'string' ? preview.toLowerCase() : null;
    const chosen = want ? digests.filter((d) => d.manager.email === want) : digests;
    if (!chosen.length) { log(want ? `no alerts for ${want}` : 'no alerts anywhere — nothing to preview'); await pool.end(); return; }
    for (const d of chosen) {
      const html = buildHTML(d.manager, d.alerts, period, d.threshold, tickets,
        'PREVIEW — this message was not sent to anyone.');
      const path = '/tmp/spend-digest-' + d.manager.email.replace(/[^a-z0-9]+/gi, '_') + '.html';
      fs.writeFileSync(path, html);
      log(`preview → ${path}  (${d.manager.name} <${d.manager.email}>, ${d.manager.isDirector ? 'director' : 'manager'}, `
        + `threshold ${d.threshold}% ${d.thresholdSource}, ${d.alerts.length}: `
        + `${d.alerts.map((a) => a.name + ' ' + a.pct + '%' + (a.direct ? '' : ' [via ' + a.reportsTo + ']')).join(', ')})`);
    }
    await pool.end();
    return;
  }

  if (dryRun) {
    for (const d of digests) {
      const gate = d.optedIn || cfg.digestEnabled;
      const dec = gate ? sendDecision(await lastSent(d.manager.email), d.fp)
        : { send: false, why: 'manager has not switched email alerts on' };
      log(`${dec.send ? 'WOULD SEND' : 'would skip'} → ${d.manager.email} @${d.threshold}% (${dec.why}): `
        + `${d.alerts.map((a) => a.name + ' ' + a.state + ' ' + a.pct + '%' + (a.direct ? '' : ' [via ' + a.reportsTo + ']')).join(', ')}`);
    }
    await pool.end();
    return;
  }

  if (testTo) {
    const want = typeof testAs === 'string' ? testAs.toLowerCase() : null;
    const d = want ? digests.find((x) => x.manager.email === want) : digests[0];
    if (!d) { err(want ? `no alerts for ${want}` : 'no alerts anywhere — nothing to send'); await pool.end(); process.exit(3); }
    const html = buildHTML(d.manager, d.alerts, period, d.threshold, tickets,
      `TEST — this is the message ${d.manager.name} <${d.manager.email}> would receive. They were not sent it.`);
    const r = await mailGraph.sendMail({ to: [testTo], subject: `[TEST] Claude spend — ${d.alerts.length} of your reports near their limit`, html, saveToSentItems: true, ...ALERT_SENDER });
    if (!r.ok) { err('sendMail ' + r.reason + (r.status ? ' HTTP ' + r.status : '')); await pool.end(); process.exit(1); }
    log(`test digest for ${d.manager.email} sent to ${testTo}`);
    await pool.end();
    return;
  }

  let sent = 0, skipped = 0;
  for (const d of digests) {
    if (!d.optedIn && !cfg.digestEnabled) { skipped++; log(`skip ${d.manager.email}: email alerts off for this manager`); continue; }
    const dec = sendDecision(await lastSent(d.manager.email), d.fp);
    if (!dec.send) { skipped++; log(`skip ${d.manager.email}: ${dec.why}`); continue; }
    const html = buildHTML(d.manager, d.alerts, period, d.threshold, tickets, null);
    const subj = d.alerts.length === 1
      ? `Claude spend — ${d.alerts[0].name} is at ${d.alerts[0].pct}% of their monthly limit`
      : `Claude spend — ${d.alerts.length} people in your org are near their monthly limit`;
    const r = await mailGraph.sendMail({ to: [d.manager.email], subject: subj, html, saveToSentItems: true, ...ALERT_SENDER });
    if (!r.ok) { err(`send to ${d.manager.email} failed: ${r.reason}${r.status ? ' HTTP ' + r.status : ''}`); continue; }
    // Recorded only after a successful send, so a failed one is retried next run
    // rather than being remembered as delivered.
    await recordSent(d.manager.email, d.fp);
    sent++;
    log(`sent → ${d.manager.email} (${dec.why})`);
  }
  log(`done: ${sent} sent, ${skipped} skipped`);
  await pool.end();
}

main().catch(async (e) => {
  err(e.stack || e.message || String(e));
  try { await pool.end(); } catch (_) {}
  process.exit(1);
});
