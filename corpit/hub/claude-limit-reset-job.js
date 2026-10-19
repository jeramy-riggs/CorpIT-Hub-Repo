#!/usr/bin/env node
'use strict';
// =====================================================================
// claude-limit-reset-job.js  (2026-09-25)
//
// Undoes My Profile Claude limit raises on the 1st of the month: every raise
// applied in an earlier month (UTC) goes back to the cap the person had before
// it. A person who had their own admin-set cap gets that cap back; a person who
// had none loses the per-user override and falls back to what they inherit
// (the default). Caps that nobody raised here are never touched.
//
// A raise is only undone if the account still shows exactly what My Profile set.
// If somebody changed it since (in the Claude console, or another tool), it is
// left alone and listed as skipped.
//
// Each run that resets or skips anybody files ONE Service Desk ticket listing
// everyone, closes it, and mails each person whose limit was put back. Runs
// hourly from root cron (at :00, so the 1st starts clean), so a missed or failed
// hour catches up on the next one; rows are marked one at a time, so nothing is
// ever reset twice.
//
// A reset Anthropic refuses (or that cannot be read back) is retried every hour,
// for as long as it takes (Jeramy 2026-09-25). If it is still not done 6 hours into
// the month it is reported ONCE, on an OPEN ticket; later runs add each result to
// that ticket instead of filing new ones, and close it when every reset on it is
// finished. Nobody is reset while an approval for them is being applied (a row in
// 'applying' that moved in the last 10 minutes): they are left to the next hour, so
// the two writes cannot cross.
//
//   node claude-limit-reset-job.js          do it
//   node claude-limit-reset-job.js --dry    show what it would do; no writes, no ticket, no mail
//
// Runs even when approvals are switched off in the console: the switch stops new
// raises, not the promise that raises end on the 1st.
//
// Stage U (2026-09-26), before the resets, when the approvals module has them:
//  - wrapStopped: a decision (approved, denied, withdrawn) whose step stopped after
//    the final status, before its ticket was closed or its mail went, is finished
//    here once it has not moved for 10 minutes (ticket noted and closed, mail sent
//    once). Only decisions since stage U and in the last 3 days.
//  - recordLanded: in the first 6 hours of a month, a raise from an earlier month
//    marked failed (or stopped while applying) whose write DID land in Anthropic is
//    recorded as applied, so it is reset below with the rest.
// Either one failing, or Anthropic not answering for a landed-write check, makes the
// run exit 1 (tried again next hour); the resets still run.
// =====================================================================

require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const mysql = require('mysql2/promise');
const anthropic = require('./anthropic-spend-admin');
const approvals = require('./claude-limit-approvals');
const mailGraph = require('./mail-graph');
let sdp = null;
try { sdp = require('./sdp-lookup'); } catch (e) { console.warn('[limit-reset] sdp-lookup unavailable:', e.message); }

const DRY = process.argv.includes('--dry');
const GAP_MS = 1500;     // the Spend Limits API allows 60/min for the whole org, shared with the collector
const RETRY_HOURS = 6;   // a reset still not done this long into the month is reported (once) on an open ticket
const SDP_MS = 45000, MAIL_MS = 30000;
const { money, monthName, mailHtml, SENDER, TICKET_FALLBACK, STALE_S } = approvals;
const within = approvals._within;

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 2,
});
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const sqlNow = () => new Date().toISOString().slice(0, 19).replace('T', ' ');
const log = (...a) => console.log(new Date().toISOString(), '[limit-reset]', ...a);
const jsonCol = (v) => { if (v == null) return null; if (typeof v === 'object') return v; try { return JSON.parse(v); } catch (e) { return null; } };
const sdpErr = (e) => (sdp && sdp.sdpErrorText ? sdp.sdpErrorText(e) : e.message);
const who = (r) => (r.requester_name || r.requester_email) + ' <' + r.requester_email + '>  request #' + r.id;
const resetTicketOf = (r) => (jsonCol(r.tickets) || []).filter(t => t.action === 'reset').pop() || null;

async function mark(id, state, detail) {
  if (DRY) return;
  await pool.query('UPDATE claude_limit_approval SET reset_state = ?, reset_at = ?, reset_detail = ? WHERE id = ? AND reset_state IS NULL',
    [state, sqlNow(), String(detail || '').slice(0, 500), id]);
}

/* A reset that will be tried again next hour: the row stays due, with the latest reason. */
async function note(id, detail) {
  if (DRY) return;
  const d = String(detail || '').slice(0, 500);
  await pool.query('UPDATE claude_limit_approval SET reset_detail = ? WHERE id = ? AND reset_state IS NULL AND NOT (reset_detail <=> ?)', [d, id, d]);
}

async function addTicket(id, t) {
  await pool.query("UPDATE claude_limit_approval SET tickets = JSON_ARRAY_APPEND(COALESCE(tickets, JSON_ARRAY()), '$', CAST(? AS JSON)) WHERE id = ?",
    [JSON.stringify({ action: 'reset', id: t.id, display: t.display, url: t.url, closed: !!t.closed }), id]);
}

async function userIdFor(r) {
  if (r.anthropic_user_id) return r.anthropic_user_id;
  const [[m]] = await pool.query("SELECT user_id FROM claude_spend_limit WHERE period = 'monthly' AND LOWER(email) = ? LIMIT 1", [r.requester_email]);
  return m ? m.user_id : null;
}

/* An approval for this person being applied right now (moved in the last STALE_S). Its
 * write and a reset must not cross, so the reset waits for the next hour. */
async function busy(r) {
  const [[b]] = await pool.query(
    `SELECT id FROM claude_limit_approval WHERE requester_email = ? AND status = 'applying' AND updated_at > NOW() - INTERVAL ${STALE_S} SECOND LIMIT 1`, [r.requester_email]);
  return b ? b.id : null;
}
const BUSY = (id) => ({ outcome: 'later', busy: true, detail: 'Request #' + id + ' for this person is being applied right now; left to the next hour.' });

/* One row. Returns { outcome: reset|skipped|failed|later, detail } */
async function resetOne(r) {
  const applied = Number(r.applied_cents);
  const back = r.prior_override_cents == null ? null : Number(r.prior_override_cents);
  const backText = back == null ? 'the inherited default' + (r.prior_amount_cents != null ? ' (' + money(Number(r.prior_amount_cents)) + ' when raised)' : '') : money(back) + ' (their own cap)';
  const isBack = (x) => (back == null ? x.sourceType !== 'user' : (x.amountCents === back && x.sourceType === 'user'));
  const uid = await userIdFor(r);
  if (!uid) return { outcome: 'skipped', detail: 'No Claude account on record any more; nothing to reset.' };
  let b = await busy(r);
  if (b) return BUSY(b);
  const cur = await anthropic.effective(uid);
  if (!cur.ok) return { outcome: 'later', detail: 'Could not read the current limit: ' + cur.error };
  const c = cur.row;
  // Tried before (an earlier hour could not finish): if the cap is already where the reset
  // puts it (that write landed, or IT set it by hand), it is done and nothing is written.
  if (r.reset_detail != null && c && isBack(c)) {
    return { outcome: 'reset', detail: 'Already back to ' + (c.unlimited ? 'no cap' : money(c.amountCents)) + ' (' + (back == null ? 'no override, inherits ' + (c.sourceType || '?') : 'their own cap') + '); nothing written.', nowCents: c.amountCents };
  }
  if (!c || c.unlimited || c.amountCents !== applied || c.sourceType !== 'user') {
    return { outcome: 'skipped', detail: 'Changed outside My Profile since the raise (now ' + (c ? (c.unlimited ? 'no cap' : money(c.amountCents)) + ', ' + (c.sourceType || '?') : 'no limit row') + '); left as it is.' };
  }
  if (DRY) return { outcome: 'reset', detail: 'Would put ' + money(applied) + ' back to ' + backText + '.' };
  b = await busy(r);
  if (b) return BUSY(b);
  const w = back == null ? await anthropic.deleteLimit(c.spendLimitId) : await anthropic.setUserLimit(uid, back);
  // Nothing was written, so it is safe to try again next hour, for as long as it takes.
  if (!w.ok) return { outcome: 'later', detail: 'Anthropic refused the reset: ' + w.error };
  await sleep(GAP_MS);
  const after = await anthropic.effective(uid);
  // Sent but not confirmed: next hour reads it again and finds it landed (above) or writes it again.
  if (!after.ok || !after.row) return { outcome: 'later', detail: 'Reset sent but not read back: ' + (after.error || 'no row') };
  const a = after.row;
  if (!isBack(a)) return { outcome: 'failed', detail: 'Reset sent but Anthropic now shows ' + (a.unlimited ? 'no cap' : money(a.amountCents)) + ' (' + (a.sourceType || '?') + '), expected ' + backText + '.' };
  return { outcome: 'reset', detail: money(applied) + ' back to ' + (a.unlimited ? 'no cap' : money(a.amountCents)) + ' (' + (back == null ? 'override removed, inherits ' + (a.sourceType || '?') : 'their own cap') + ').', nowCents: a.amountCents };
}

// RESET / SKIPPED / FAILED / SUPERSEDED / NOT APPLICABLE / RETRYING, then the person
const tag = (s) => String(s).toUpperCase().replace(/_/g, ' ').padEnd(10) + ' ';
const line = (d) => tag(d.outcome) + who(d.row) + '  ' + d.detail;

async function main() {
  const now = new Date(), month = now.toISOString().slice(0, 7);
  const late = now - Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1) >= RETRY_HOURS * 3600e3;
  // Stage U: finish stopped wrap-ups, and record landed writes before the due query sees them.
  let pre = true, landedLater = 0;
  const U = { pool, sdp, mailGraph };
  if (typeof approvals.wrapStopped === 'function') {
    try { await approvals.wrapStopped(U, { dry: DRY, log }); }
    catch (e) { pre = false; log('error in the wrap-up check: ' + e.message); }
  }
  if (typeof approvals.recordLanded === 'function') {
    try { const L = await approvals.recordLanded(U, { dry: DRY, now, log }); landedLater = (L && L.later) || 0; }
    catch (e) { pre = false; log('error in the landed-write check: ' + e.message); }
  }
  const clean = pre && !landedLater;
  const [rows] = await pool.query(
    `SELECT id, requester_email, requester_name, manager_email, applied_cents, applied_at, anthropic_user_id,
            prior_source, prior_override_cents, prior_amount_cents, notified, tickets, reset_detail
       FROM claude_limit_approval
      WHERE status = 'approved' AND reset_state IS NULL AND applied_cents IS NOT NULL
        AND DATE_FORMAT(applied_at, '%Y-%m') < ?
      ORDER BY applied_at ASC LIMIT 200`, [month]);
  // Reset tickets left open by earlier runs; each closes once every reset on it is finished.
  const [onTickets] = await pool.query(
    `SELECT id, requester_email, requester_name, reset_state, reset_detail, tickets FROM claude_limit_approval
      WHERE JSON_SEARCH(tickets, 'one', 'reset', NULL, '$[*].action') IS NOT NULL`);
  const openIds = new Set();
  for (const x of onTickets) for (const t of jsonCol(x.tickets) || []) if (t.action === 'reset' && !t.closed) openIds.add(t.id);
  if (!rows.length && !openIds.size) { log('nothing due' + (DRY ? ' (dry)' : '')); return clean ? 0 : 1; }
  if (rows.length) log(rows.length + ' raise(s) due for reset' + (DRY ? ' (dry run: no writes)' : ''));

  const done = [], reports = [], follow = new Map();   // follow: old ticket id -> finished rows on it
  let retrying = 0;
  for (const r of rows) {
    let o;
    try { o = await resetOne(r); } catch (e) { o = { outcome: 'later', detail: 'error: ' + e.message }; }
    log('#' + r.id, r.requester_email, o.outcome, '-', o.detail);
    const d = Object.assign({ row: r, old: resetTicketOf(r) }, o);
    if (o.outcome === 'later') {                          // stays due; next hour tries again
      if (o.busy) continue;
      retrying++;
      await note(r.id, o.detail);
      if (late && !d.old) reports.push(d);                // reported once; later hours do not file again
      await sleep(GAP_MS);
      continue;
    }
    await mark(r.id, o.outcome, o.detail);
    if (d.old) { if (!follow.has(d.old.id)) follow.set(d.old.id, []); follow.get(d.old.id).push(d); openIds.add(d.old.id); }
    else done.push(d);
    await sleep(GAP_MS);
  }
  if (DRY) { log('(dry run: no writes) ' + done.length + ' would finish, ' + retrying + ' would retry, ' + openIds.size + ' open reset ticket(s) not touched'); return clean ? 0 : 1; }

  let ok = true;
  // One ticket for this run's first results and new reports. Closed unless something failed
  // or is still not done, in which case it stays open for IT and later hours add to it.
  let ticket = null;
  if (done.length || reports.length) {
    const failed = done.filter(d => d.outcome === 'failed').length, nReset = done.filter(d => d.outcome === 'reset').length;
    const lines = ['Monthly reset of Claude spend limits raised in CorpIT Hub -> My Profile (' + monthName(month) + ').', '',
      'Only limits raised through My Profile are reset, each back to the cap the person had before the raise.', ''];
    for (const d of done) lines.push(line(d));
    if (reports.length) {
      lines.push('', 'NOT DONE YET: these resets have not gone through since the 1st. The job tries again every hour and adds the result here;',
        'this ticket closes once all are finished. Setting the cap by hand in the Claude admin console also counts: the next hour sees it.');
      for (const d of reports) lines.push(tag('retrying') + who(d.row) + '  ' + d.detail);
    }
    const hold = failed || reports.length;
    if (sdp && sdp.createTicket) {
      try {
        const t = await within(SDP_MS, sdp.createTicket({ subject: '[Claude spend] Monthly limit reset ' + month + ': ' + nReset + ' reset' + (failed ? ', ' + failed + ' FAILED' : '') + (reports.length ? ', ' + reports.length + ' NOT DONE YET' : ''),
          description: lines.join('\n'), requesterEmail: TICKET_FALLBACK.email, requesterName: TICKET_FALLBACK.name }), 'SDP');
        ticket = { id: String(t.id), display: String(t.display_id), url: t.url, closed: false };
        if (!hold) {
          let c;
          try { c = await within(SDP_MS, sdp.closeTicket(ticket.id, 'Monthly Claude limit reset completed: ' + nReset + ' person(s) put back to their prior cap.'), 'SDP'); }
          catch (e) { c = { ok: false, error: sdpErr(e) }; }
          ticket.closed = !!c.ok;
          if (!c.ok) { ok = false; log('ticket', ticket.display, 'NOT closed:', c.error); }
        } else log('ticket', ticket.display, 'left OPEN:', failed, 'failed,', reports.length, 'not done yet');
      } catch (e) { ok = false; log('reset ticket NOT filed:', sdpErr(e)); }
    } else { ok = false; log('reset ticket NOT filed: sdp-lookup unavailable'); }
    if (ticket) {
      for (const d of done) {
        await pool.query('UPDATE claude_limit_approval SET reset_detail = CONCAT(LEFT(reset_detail, 460), ?) WHERE id = ?', [' [' + ticket.display + ']', d.row.id]);
        await addTicket(d.row.id, ticket);
      }
      for (const d of reports) await addTicket(d.row.id, ticket);
    }
  }

  // Tickets from earlier runs: add what finished this hour, and close each one whose resets
  // are all finished (reset, skipped, or replaced by a newer raise) with none failed.
  const tix = new Map();
  for (const id of openIds) {
    const [on] = await pool.query(
      `SELECT id, requester_email, requester_name, reset_state, reset_detail, tickets FROM claude_limit_approval
        WHERE JSON_SEARCH(tickets, 'one', ?, NULL, '$[*].id') IS NOT NULL`, [id]);
    const mine = on.filter(x => (jsonCol(x.tickets) || []).some(t => t.action === 'reset' && t.id === id));
    const t = mine.map(x => (jsonCol(x.tickets) || []).filter(y => y.action === 'reset' && y.id === id).pop()).find(Boolean);
    if (!t || !mine.length || (ticket && id === ticket.id)) continue;
    tix.set(id, t);
    const fin = follow.get(id) || [];
    const closable = mine.every(x => x.reset_state != null) && !mine.some(x => x.reset_state === 'failed');
    const lines = fin.map(line);
    if (closable) for (const x of mine) if (!fin.some(d => d.row.id === x.id)) lines.push(tag(x.reset_state) + who(x) + '  ' + (x.reset_detail || ''));
    if (lines.length) {
      try { await within(SDP_MS, sdp.addNoteToTicket(id, (closable ? 'All resets on this ticket are finished.' : 'Update from the hourly reset:') + '\n' + lines.join('\n'), false), 'SDP'); }
      catch (e) { ok = false; log('ticket', t.display, 'note NOT added:', sdpErr(e)); }
    }
    for (const d of fin) await pool.query('UPDATE claude_limit_approval SET reset_detail = CONCAT(LEFT(reset_detail, 460), ?) WHERE id = ?', [' [' + t.display + ']', d.row.id]);
    if (!closable) { log('ticket', t.display, 'stays OPEN'); continue; }
    let c;
    try { c = await within(SDP_MS, sdp.closeTicket(id, 'Monthly Claude limit reset finished: every reset on this ticket is done.'), 'SDP'); }
    catch (e) { c = { ok: false, error: sdpErr(e) }; }
    if (!c.ok) { ok = false; log('ticket', t.display, 'NOT closed:', c.error); continue; }
    for (const x of mine) {
      const list = (jsonCol(x.tickets) || []).map(y => (y.action === 'reset' && y.id === id ? Object.assign({}, y, { closed: true }) : y));
      await pool.query('UPDATE claude_limit_approval SET tickets = ? WHERE id = ?', [JSON.stringify(list), x.id]);
    }
    log('ticket', t.display, 'closed');
  }

  // Mail each person whose limit was put back.
  const reset = done.filter(d => d.outcome === 'reset').map(d => Object.assign({ t: ticket }, d));
  for (const [id, fin] of follow) for (const d of fin) if (d.outcome === 'reset') reset.push(Object.assign({ t: tix.get(id) || d.old }, d));
  for (const d of reset) {
    const r = d.row;
    const nowText = d.nowCents == null ? 'the standard limit' : money(d.nowCents);
    let res;
    try {
      res = await within(MAIL_MS, mailGraph.sendMail(Object.assign({ to: [r.requester_email], saveToSentItems: true,
        subject: 'Your Claude monthly limit is back to ' + nowText,
        html: mailHtml('Your Claude limit was reset for the new month', [
          'Your Claude monthly spend limit is back to <b>' + nowText + '</b>. The ' + money(Number(r.applied_cents)) + ' limit raised in My Profile last month has ended, as it does on the 1st.',
          'If you need more again this month, request it in My Profile.' + (d.t ? ' Logged on Service Desk ticket ' + d.t.display + '.' : ''),
        ], 'Open My Profile') }, SENDER)), 'Mail');
    } catch (e) { res = { ok: false, reason: e.message }; }
    const n = jsonCol(r.notified) || [];
    n.push({ event: 'reset', to: r.requester_email, ok: !!res.ok, reason: res.ok ? null : (res.reason || 'failed'), at: sqlNow() });
    await pool.query('UPDATE claude_limit_approval SET notified = ? WHERE id = ?', [JSON.stringify(n.slice(-40)), r.id]);
    if (!res.ok) log('mail to', r.requester_email, 'NOT sent:', res.reason);
  }
  const all = done.concat([].concat(...follow.values()));
  log('done:', all.filter(d => d.outcome === 'reset').length, 'reset,', all.filter(d => d.outcome !== 'reset').length, 'skipped/failed,', retrying, 'still retrying,',
    'ticket', ticket ? ticket.display + (ticket.closed ? ' closed' : ' OPEN') : 'none');
  return (clean && ok && !retrying && all.every(d => d.outcome !== 'failed')) ? 0 : 1;
}

main().then(code => pool.end().then(() => process.exit(code)))
  .catch(e => { console.error('[limit-reset] fatal:', e.message); pool.end().finally(() => process.exit(2)); });
