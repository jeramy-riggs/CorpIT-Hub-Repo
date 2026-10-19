/**
 * oem-usage.js — per-application sign-in USAGE, Entra and Okta side by side, for the migration page.
 * Removable: delete this file and the two `try { require('./oem-usage') }` hooks (oem-migrate.js queue(),
 * oem-migrate-routes.js) and every row simply has no `usage` block.
 *
 * What is counted: DISTINCT USERS who signed in SUCCESSFULLY — never events, never assignment counts —
 * in the same labelled window on both sides (last 7 and last 30 days), with the last successful sign-in
 * and the freshness of each source. The two platform counts are never added together.
 *   Entra — entra_signin_logs, the platform's mirror of interactive Entra sign-ins, by the application's
 *           client appId (the sign-in row's appId; a SAML/OIDC enterprise app signs in as itself).
 *   Okta  — oem_okta_usage, the cached Okta System Log read for the app (user.authentication.sso events
 *           naming the app as target, newest 100). Distinct users come from the stored events, so a read
 *           capped at 100 events is "partial coverage" and a row stored before the read kept every event
 *           (5 sample rows) says "re-check to collect users". Bookmark tile launches are not sign-ins and
 *           are not in that read at all.
 *   Overlap — where both platforms name the person by the same address (Okta login = Entra UPN,
 *           case-insensitive): seen on both, still Okta-only. Unavailable when either side is unavailable.
 *   People  — the single-application read (forApp, used by the panel) also NAMES the distinct users behind each
 *           count, newest sign-in first, capped at 200 with the remainder reported as `truncated`. The queue
 *           never carries them. Each entry says whether the other platform still sees that person. The list is
 *           exactly the count it sits under: same window, same source, same successes-only rule — so it is
 *           evidence, not a second measurement. A list is `available:false` with the same reason as its count.
 *           Each entry carries `events` (30 days) and `events7`/`in7` (last 7), so the page can narrow the SAME
 *           list to the 7-day window and land on exactly `users7` people — never a recount.
 * Missing, unreadable, stale or partial data reads as null with a reason — never as zero.
 */
'use strict';
const L = require('./oem-lib');
const { pool, j, nowIso } = L;

const WINDOWS = [7, 30];
const STALE_MS = 6 * 3600 * 1000;            // Entra mirror newer than this = fresh; older = say so
const OKTA_STALE_MS = 24 * 3600 * 1000;      // an Okta read older than a day is shown with its age and a re-check hint
const CONFIRMED = new Set(['manual_confirmed', 'auto_high']);
const BOOKMARK = /^BOOKMARK$/i;
/* Why a bookmark does NOT retire with the migration, said in the destination's own terms. A tile only
   retires with it when it opens the CONFIRMED Entra application (see `retirable` below). */
const B_DEST_WHY = {
  other_entra_app: 'The tile opens a DIFFERENT Entra application from the one confirmed for it — that is a duplicate integration to sort out, not a retirement.',
  entra_launcher_unconfirmed: 'The tile opens an Entra launcher, but no Entra application is confirmed for it yet — confirm the match first.',
  vendor_url: 'The tile points straight at the vendor, not at the confirmed Entra application. Who signs the user in there is not visible from Okta, so the tile cannot be called retired on this evidence.',
  unverified: 'The tile has no URL recorded, so there is nothing to compare with the Entra application.'
};
const hostOf = (u) => { try { return new URL(String(u)).hostname.toLowerCase(); } catch (e) { return null; } };
const launcherOf = (url) => { const mm = String(url || '').match(/launcher\.myapps\.microsoft\.com\/api\/signin\/([0-9a-f-]{36})/i); return mm ? mm[1].toLowerCase() : null; };
const addr = (s) => { const v = String(s || '').trim().toLowerCase(); return v.includes('@') ? v : null; };

/** One pass over the mirror (30 days, successes only, grouped by app+user) and one over the Okta cache.
    Memoised for 60 s: the group-by costs ~0.9 s and the queue is fetched on every view; checkedAt says when it was read. */
let memo = { at: 0, value: null, pending: null };
async function loadUsage({ fresh = false } = {}) {
  if (!fresh && memo.value && Date.now() - memo.at < 60000) return memo.value;
  if (!fresh && memo.pending) return memo.pending;
  memo.pending = loadUsageNow().then((v) => { memo = { at: Date.now(), value: v, pending: null }; return v; }, (e) => { memo.pending = null; throw e; });
  return memo.pending;
}
async function loadUsageNow() {
  const out = { checkedAt: nowIso(), windows: WINDOWS,
    entra: { ok: false, newest: null, oldest: null, total: 0, error: null, byApp: new Map() },
    okta: new Map() };
  try {
    const [[span]] = await pool.query(`SELECT MIN(created_at) oldest, MAX(created_at) newest, COUNT(*) total FROM entra_signin_logs`);
    const total = span ? Number(span.total || 0) : 0;
    out.entra.newest = span ? span.newest : null; out.entra.oldest = span ? span.oldest : null; out.entra.total = total;
    out.entra.ok = total > 0; if (!out.entra.ok) out.entra.error = 'the Entra sign-in mirror is empty';
    if (out.entra.ok) {
      const [rows] = await pool.query(`SELECT app_id, LOWER(user_principal_name) upn, MAX(created_at) last, COUNT(*) events, SUM(created_at > NOW() - INTERVAL 7 DAY) in7
                                         FROM entra_signin_logs WHERE outcome='SUCCESS' AND created_at > NOW() - INTERVAL 30 DAY AND app_id IS NOT NULL AND user_principal_name IS NOT NULL
                                        GROUP BY app_id, LOWER(user_principal_name)`);
      /* One row per app+user already — keep the people, not only how many there were: the panel names them as the
         evidence that the application is being used through Entra. ~3.8k rows tenant-wide, so this costs nothing. */
      for (const r of rows) {
        const k = String(r.app_id).toLowerCase();
        let e = out.entra.byApp.get(k);
        if (!e) { e = { users30: new Set(), users7: new Set(), last: null, people: new Map() }; out.entra.byApp.set(k, e); }
        e.users30.add(r.upn); if (Number(r.in7) > 0) e.users7.add(r.upn);
        e.people.set(r.upn, { upn: r.upn, last: r.last, events: Number(r.events || 0), events7: Number(r.in7 || 0), in7: Number(r.in7 || 0) > 0 });
        if (!e.last || new Date(r.last) > new Date(e.last)) e.last = r.last;
      }
    }
  } catch (e) { out.entra = { ok: false, newest: null, oldest: null, total: 0, error: 'sign-in mirror not readable: ' + e.message, byApp: new Map() }; }
  try {
    const [u] = await pool.query(`SELECT okta_id, days, since, count, last_at, sample, error, checked_at, checked_by FROM oem_okta_usage`);
    for (const r of u) out.okta.set(r.okta_id, { days: r.days, since: r.since, count: r.count === null || r.count === undefined ? null : Number(r.count), last: r.last_at, events: j(r.sample, []) || [], error: r.error, checkedAt: r.checked_at, checkedBy: r.checked_by });
  } catch (e) { /* table absent until 004 runs: Okta usage reads as not checked */ }
  return out;
}

/** Distinct successful users in the Okta cache for one window, from the stored events. */
function oktaUsers(row, days) {
  const since = Date.now() - days * 86400000;
  const since7 = Date.now() - 7 * 86400000;
  const users = new Set(); const people = new Map(); let unnamed = 0;
  for (const e of row.events || []) {
    if (!e || !e.published || new Date(e.published).getTime() < since) continue;
    if (e.outcome && String(e.outcome).toUpperCase() !== 'SUCCESS') continue;
    const a = addr(e.actor);
    if (!a) { unnamed++; continue; }
    users.add(a);
    const recent = new Date(e.published).getTime() >= since7 ? 1 : 0;
    const prev = people.get(a);
    if (!prev) people.set(a, { upn: a, last: e.published, events: 1, events7: recent, in7: recent > 0 });
    else { prev.events++; prev.events7 += recent; prev.in7 = prev.events7 > 0; if (new Date(e.published) > new Date(prev.last)) prev.last = e.published; }
  }
  return { users, people, unnamed };
}

/** The named people behind a count, newest first, capped so one busy application cannot bloat the response.
    The entries are COPIES: the source map lives in the memoised 30-day load, shared by every caller, and the
    per-application read stamps `alsoOkta`/`alsoEntra` onto what it gets back. Two Okta apps can point at the
    same Entra application, so handing out the shared objects would let one app's comparison show up on another. */
const PEOPLE_CAP = 200;
function peopleList(map, cap) {
  const all = Array.from(map.values()).map((r) => Object.assign({}, r)).sort((a, b) => new Date(b.last) - new Date(a.last));
  const shown = all.slice(0, cap || PEOPLE_CAP);
  return { list: shown, total: all.length, truncated: all.length - shown.length };
}

/**
 * The side-by-side usage block for one application row.
 * app: { oktaId, signOnMode, oktaStatus, url }   facts: the work item's facts (match + entra)
 */
function usageFor(app, facts, U, opts) {
  const withPeople = !!(opts && opts.people);   // the queue only needs counts; the panel names the people
  const match = (facts && facts.match) || {}; const entra = (facts && facts.entra) || null;
  const confirmed = CONFIRMED.has(match.decision) && entra && entra.appId ? String(entra.appId).toLowerCase() : null;
  const out = { window: { days: 30, label: 'Last 30 days', options: WINDOWS.slice() }, checkedAt: U.checkedAt,
    basis: 'Distinct users with a successful sign-in in the window — not events, not assignments. Counts are per platform and are not added together.',
    entra: null, okta: null, overlap: null, bookmark: null, signal: null };

  /* Entra side: needs a confirmed Entra application, the mirror, and coverage of the window */
  const mirrorAge = U.entra.newest ? Date.now() - new Date(U.entra.newest).getTime() : null;
  const coverageDays = U.entra.oldest ? Math.floor((Date.now() - new Date(U.entra.oldest).getTime()) / 86400000) : 0;
  if (!confirmed) out.entra = { available: false, reason: 'No confirmed Entra application yet — confirm the match first.', users7: null, users30: null, last: null };
  else if (!U.entra.ok) out.entra = { available: false, reason: U.entra.error || 'Entra sign-in mirror not available', users7: null, users30: null, last: null };
  else {
    const e = U.entra.byApp.get(confirmed) || null;
    out.entra = { available: true, appId: confirmed, name: entra.name || null, users7: e ? e.users7.size : 0, users30: e ? e.users30.size : 0, last: e ? e.last : null,
      newest: U.entra.newest, stale: mirrorAge !== null && mirrorAge > STALE_MS, coverage: coverageDays >= 30 ? 'full' : 'partial', coverageDays,
      basis: 'interactive sign-ins mirrored from Entra (entra_signin_logs) by the application\'s client appId; successes only',
      note: e ? null : 'No successful sign-ins observed in this window' };
    if (out.entra.coverage === 'partial') out.entra.coverageNote = 'The mirror covers ' + coverageDays + ' day' + (coverageDays === 1 ? '' : 's') + ', less than the 30-day window.';
    if (withPeople) {
      const pl = e ? peopleList(e.people) : { list: [], total: 0, truncated: 0 };
      out.entra.people = { available: true, days: 30, list: pl.list, total: pl.total, truncated: pl.truncated,
        basis: 'Each person signed in successfully through Entra to this application at least once in the last 30 days (entra_signin_logs, matched on the application\'s client appId). "Events" is how many successful sign-ins that person made in the window.',
        note: pl.total ? null : 'No successful Entra sign-ins in the last 30 days — nobody to list.' };
      if (out.entra.coverage === 'partial') out.entra.people.coverageNote = out.entra.coverageNote;
    }
  }
  if (withPeople && !out.entra.people) out.entra.people = { available: false, reason: out.entra.reason, list: [], total: null, truncated: 0 };

  /* Okta side: the cached System Log read, distinct users from the stored events */
  const o = U.okta.get(app.oktaId) || null;
  if (!o) out.okta = { available: false, checked: false, reason: 'Not checked yet — run "Check Okta usage" (one Okta System Log read).', users7: null, users30: null, last: null };
  else if (o.error) out.okta = { available: false, checked: true, reason: 'Last Okta read failed: ' + o.error, checkedAt: o.checkedAt, users7: null, users30: null, last: null };
  else {
    const full = Array.isArray(o.events) && (o.count === null || o.events.length >= Math.min(o.count, 100));
    const u30 = oktaUsers(o, 30), u7 = oktaUsers(o, 7);
    const oktaAge = o.checkedAt ? Date.now() - new Date(o.checkedAt).getTime() : null;
    out.okta = { available: full, checked: true, checkedAt: o.checkedAt, checkedBy: o.checkedBy || null, events: o.count, last: o.last,
      users7: full ? u7.users.size : null, users30: full ? u30.users.size : null,
      capped: o.count !== null && o.count >= 100, stale: oktaAge !== null && oktaAge > OKTA_STALE_MS, unnamed: u30.unnamed,
      basis: 'Okta System Log user.authentication.sso events naming this app as target (newest 100), read on demand and cached; successes only',
      reason: full ? null : 'The stored read kept only ' + (o.events ? o.events.length : 0) + ' sample events — re-check Okta usage to collect users.' };
    if (full && o.count !== null && o.count >= 100) out.okta.coverage = 'partial', out.okta.coverageNote = 'The Okta read stops at 100 events, so the user count is a floor for the window.';
    else if (full) out.okta.coverage = 'full';
    if (full && o.count === 0) out.okta.note = 'No successful sign-ins observed in this window';
    if (BOOKMARK.test(String(app.signOnMode || ''))) out.okta.limitation = 'Bookmark tile: Okta does not authenticate users to this app. Any events Okta logs for the tile record tile activity; they cannot be separated from Okta-authenticated sign-ins, so treat this count as tile activity.';
    if (withPeople) {
      if (!full) out.okta.people = { available: false, reason: out.okta.reason, list: [], total: null, truncated: 0 };
      else {
        const pl = peopleList(u30.people);
        out.okta.people = { available: true, days: 30, list: pl.list, total: pl.total, truncated: pl.truncated,
          basis: 'Each person appears in the cached Okta System Log read for this application (user.authentication.sso, successes only) in the last 30 days. "Events" is how many of the stored events are theirs.',
          note: pl.total ? null : 'No successful Okta sign-ins in the stored read — nobody to list.' };
        if (out.okta.capped) out.okta.people.coverageNote = 'The Okta read stops at 100 events, so this list is a floor: people whose sign-ins fall outside the newest 100 events are missing.';
        if (u30.unnamed > 0) out.okta.people.unnamedNote = u30.unnamed + ' event' + (u30.unnamed === 1 ? '' : 's') + ' named no address and could not be attributed to a person.';
        if (out.okta.limitation) out.okta.people.limitation = out.okta.limitation;
      }
    }
  }
  if (withPeople && !out.okta.people) out.okta.people = { available: false, reason: out.okta.reason, list: [], total: null, truncated: 0 };

  /* Overlap: both sides identify the person by address */
  if (out.entra.available && out.okta.available) {
    const e = U.entra.byApp.get(confirmed); const eu = e ? e.users30 : new Set();
    const ou = oktaUsers(o, 30).users;
    let both = 0; for (const u of ou) if (eu.has(u)) both++;
    out.overlap = { available: true, days: 30, both, oktaOnly: ou.size - both, entraOnly: eu.size - both,
      basis: 'same address on both platforms (Okta login = Entra user principal name), last 30 days',
      partial: out.okta.unnamed > 0 || out.okta.capped || out.entra.coverage === 'partial' };
    if (out.okta.unnamed > 0) out.overlap.note = out.okta.unnamed + ' Okta event' + (out.okta.unnamed === 1 ? '' : 's') + ' named no address and could not be correlated.';
    /* On a named list, say per person whether the other platform still sees them — a user on both sides is not
       finished migrating, and that is the thing the list is read for. */
    if (withPeople && out.entra.people && out.entra.people.available) for (const r of out.entra.people.list) r.alsoOkta = ou.has(r.upn);
    if (withPeople && out.okta.people && out.okta.people.available) for (const r of out.okta.people.list) r.alsoEntra = eu.has(r.upn);
  } else out.overlap = { available: false, reason: !out.entra.available ? out.entra.reason : out.okta.reason };

  /* Bookmark detection: an Okta tile that points at the Entra destination */
  if (BOOKMARK.test(String(app.signOnMode || ''))) {
    const launcher = launcherOf(app.url); const host = hostOf(app.url);
    const b = { isBookmark: true, url: app.url || null, destination: 'unverified', evidence: [] };
    b.evidence.push('Okta application type: Bookmark (a link; it does not authenticate users)');
    if (launcher && confirmed && launcher === confirmed) { b.destination = 'entra_launcher'; b.evidence.push('The tile URL is the Entra My Apps launcher for the confirmed Entra application (appId matches).'); }
    else if (launcher && confirmed) { b.destination = 'other_entra_app'; b.evidence.push('The tile URL is an Entra launcher for a different application (appId ' + launcher + ') — possible duplicate integration; check the match.'); }
    else if (launcher) { b.destination = 'entra_launcher_unconfirmed'; b.evidence.push('The tile URL is an Entra launcher (appId ' + launcher + ') but no Entra application is confirmed for this tile yet.'); }
    else if (host && entra && confirmed) {
      const hosts = [entra.loginUrl, ...(entra.replyUrls || [])].map(hostOf).filter(Boolean);
      if (hosts.includes(host)) { b.destination = 'entra_app_host'; b.evidence.push('The tile URL host (' + host + ') matches the confirmed Entra application\'s sign-on address.'); }
      else { b.destination = 'vendor_url'; b.evidence.push('The tile points at ' + host + '; the confirmed Entra application\'s addresses do not include that host — the vendor may sign users in through Entra or through something else; not verified.'); }
    } else if (host) { b.destination = 'vendor_url'; b.evidence.push('The tile points at ' + host + '; no confirmed Entra application to compare it with.'); }
    else b.evidence.push('The tile has no URL recorded.');
    if (out.entra.available) b.evidence.push(out.entra.users30 > 0 ? out.entra.users30 + ' distinct user' + (out.entra.users30 === 1 ? '' : 's') + ' signed in through Entra in the last 30 days.' : 'No Entra sign-ins observed for the confirmed application in the last 30 days.');
    else b.evidence.push('Entra sign-ins: ' + out.entra.reason);
    if (out.okta.available) b.evidence.push(out.okta.users30 > 0 ? out.okta.users30 + ' user' + (out.okta.users30 === 1 ? '' : 's') + ' with Okta-side events for the tile in the last 30 days — tile activity, not Okta-authenticated sign-ins (Okta cannot distinguish the two for a bookmark).' : 'No Okta-side events for the tile in the last 30 days.');
    else b.evidence.push('Okta-side tile activity: ' + (out.okta.reason || 'not available') + ' (a bookmark never authenticates through Okta; any events are tile activity).');
    /* Does this tile retire WITH the migration? A bookmark authenticates nobody — it is a link. When it
       opens the confirmed Entra application and people are actually signing in there, the Okta side has
       nothing left to decommission: the tile is a shortcut into Entra, and leaving it is not a second
       sign-in path. Recorded as a named verdict so the page and POST /work/:key/state read ONE derivation
       (the route re-derives it server-side; a client may not assert it). */
    const dstOk = b.destination === 'entra_launcher' || b.destination === 'entra_app_host';
    const blockers = [];
    if (!dstOk) blockers.push(B_DEST_WHY[b.destination] || 'The tile does not point at the confirmed Entra application.');
    if (!out.entra.available) blockers.push('Entra sign-ins cannot be read, so nobody can be shown using the destination: ' + out.entra.reason);
    else if (!(out.entra.users30 > 0)) blockers.push('No successful Entra sign-in for the confirmed application in the last 30 days. A tile nobody has used through Entra is not evidence that the move happened.');
    b.retirable = { ok: blockers.length === 0, blockers,
      basis: blockers.length ? null :
        'The Okta tile is a bookmark that opens ' + (b.destination === 'entra_launcher' ? 'the Entra My Apps launcher for' : 'the sign-on address of') +
        ' ' + (entra && entra.name ? entra.name : 'the confirmed Entra application') + ', and ' + out.entra.users30 + ' user' + (out.entra.users30 === 1 ? '' : 's') +
        ' signed in through Entra in the last 30 days. A bookmark never authenticates anyone, so there is no Okta sign-in path left to retire.' };
    out.bookmark = b;
  }

  /* The review signal (a signal to review, never proof) */
  const eu30 = out.entra.available ? out.entra.users30 : null; const ou30 = out.okta.available ? out.okta.users30 : null;
  const bmatch = out.bookmark && (out.bookmark.destination === 'entra_launcher' || out.bookmark.destination === 'entra_app_host');
  if (bmatch && eu30 > 0) out.signal = { code: 'bookmark_handoff', label: 'Likely migrated — Okta bookmark points to the Entra destination', tone: 'ok', why: 'A confidently matched bookmark points at the confirmed Entra application and Entra sign-ins were observed in the window. Review signal — confirm the match and record a tested sign-in to make it verified.' };
  else if (eu30 > 0 && ou30 > 0) out.signal = { code: 'both_active', label: 'Both sign-in paths active', tone: 'warn', why: eu30 + ' Entra user' + (eu30 === 1 ? '' : 's') + ' and ' + ou30 + ' Okta user' + (ou30 === 1 ? '' : 's') + ' signed in during the last 30 days.' };
  else if (eu30 > 0 && ou30 === 0) out.signal = { code: 'entra_active', label: 'Entra usage observed', tone: 'ok', why: eu30 + ' Entra user' + (eu30 === 1 ? '' : 's') + ' in the last 30 days; no Okta-authenticated sign-in in the same window.' };
  else if (eu30 > 0 && ou30 === null) out.signal = { code: 'entra_active', label: 'Entra usage observed', tone: 'ok', why: eu30 + ' Entra user' + (eu30 === 1 ? '' : 's') + ' in the last 30 days; Okta usage ' + (out.okta.checked ? 'partial — re-check to compare' : 'not checked yet') + '.' };
  else if (ou30 > 0 && (eu30 === 0 || eu30 === null)) out.signal = { code: 'okta_active', label: 'Okta usage still observed', tone: 'warn', why: ou30 + ' Okta user' + (ou30 === 1 ? '' : 's') + ' in the last 30 days' + (eu30 === 0 ? '; no Entra sign-in observed.' : '; Entra side ' + (out.entra.reason || 'not available') + '.') };
  else if (eu30 === 0 && ou30 === 0) out.signal = { code: 'none_observed', label: 'No successful sign-ins observed on either platform in this window', tone: 'unknown', why: 'Neither platform recorded a successful sign-in in the last 30 days.' };
  else out.signal = { code: 'insufficient', label: 'Insufficient usage data', tone: 'unknown', why: [out.entra.available ? null : 'Entra: ' + out.entra.reason, out.okta.available ? null : 'Okta: ' + out.okta.reason].filter(Boolean).join(' ') };
  return out;
}

/** Row-level attach for the queue: one loadUsage() per request, usageFor() per row. */
async function forQueue() { const U = await loadUsage(); return { U, attach: (app, facts) => usageFor(app, facts, U) }; }
async function forApp(oktaId) {
  const [[a]] = await pool.query(`SELECT a.okta_id, a.status, a.sign_on_mode, JSON_UNQUOTE(JSON_EXTRACT(a.raw_json,'$.settings.app.url')) AS app_url, w.facts FROM okta_apps a LEFT JOIN oem_work_item w ON w.item_key=CONCAT('app:', a.okta_id) WHERE a.okta_id=?`, [oktaId]);
  if (!a) return null;
  const U = await loadUsage({ fresh: true });
  return usageFor({ oktaId: a.okta_id, oktaStatus: a.status, signOnMode: a.sign_on_mode, url: a.app_url }, j(a.facts, {}) || {}, U, { people: true });
}

module.exports = { loadUsage, usageFor, forQueue, forApp, WINDOWS };
