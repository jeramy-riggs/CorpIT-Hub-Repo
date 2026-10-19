'use strict';
// ALERT-DISPATCH v1.4.0 (risk-detection cards + MS correlation fact) — pluggable violation alert delivery
// Marker: SIGNIN-WATCH-DISPATCH
// Drivers keyed by alert_channels.type. Each driver: async send(config, payload) -> {ok, detail}
// payload: { upn, source, event_time(Date), ip, geo_country, geo_city, result,
//            failure_reason, app_name, client_app, test(bool) }

// Every one of these is rendered into something a human opens during an
// incident -- a Teams card, an email, an SDP ticket. Copied from ITAM they
// still named ITAM, so an alert raised BY corpit sent the responder to the
// other deployment. ALLOWED_ORIGIN is the canonical origin already configured
// for this host.
const HUB_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://corpit.nrpi.local').replace(/\/+$/, '');
const DASH_URL = HUB_ORIGIN + '/signin-watch.html';
const IDENTITY_URL = HUB_ORIGIN + '/identity-diag.html';
const INVESTIGATE_URL = HUB_ORIGIN + '/signin-watch.html';

// SDP driver support (v1.1.0)
let sdpLookup;
try { sdpLookup = require('./sdp-lookup'); } catch (e) { /* not available */ }

function cardColor(result) {
  return result === 'success' ? 'Attention' : (result === 'failure' ? 'Warning' : 'Default');
}

function buildTeamsCard(p, mentionConfig) {
  const when = p.event_time instanceof Date ? p.event_time.toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : String(p.event_time);
  const vipPrefix = (p.tier === 'vip') ? '🔴 VIP · ' : '';
  const title = p.test
    ? '🔧 Sign-In Watch — test alert'
    : p.kind === 'risk_detection'
    ? vipPrefix + (p.risk_event_type === 'leakedCredentials'
        ? '🔑 Sign-In Watch — password found in breach dump'
        : '⚠️ Sign-In Watch — Microsoft risk detection: ' + (p.risk_event_type || 'unknown'))
    : vipPrefix + (p.result === 'success'
        ? '🚨 Sign-In Watch — SUCCESSFUL sign-in from untrusted network'
        : '⚠️ Sign-In Watch — sign-in attempt from untrusted network');
  const facts = [
    { title: 'User', value: p.upn || '—' },
    { title: 'Source', value: (p.source || '—').toUpperCase() },
    { title: 'Result', value: (p.result || 'unknown').toUpperCase() },
    { title: 'Time', value: when },
    { title: 'IP', value: p.ip || '—' },
    { title: 'Location', value: [p.geo_city, p.geo_country].filter(Boolean).join(', ') || '—' },
    { title: 'App', value: p.app_name || '—' },
  ];
  if (p.failure_reason) facts.push({ title: 'Reason', value: String(p.failure_reason).slice(0, 200) });
  if (p.geo_asn || p.geo_isp) facts.push({ title: 'ASN / ISP', value: [p.geo_asn, p.geo_isp].filter(Boolean).join(' · ').slice(0, 100) });
  if (p.ca_status && p.ca_status !== 'null') facts.push({ title: 'CA policy', value: p.ca_status === 'notApplied' ? '⚠️ Not applied' : p.ca_status });
  if (p.client_app) facts.push({ title: 'Client type', value: p.client_app + (/IMAP|POP|SMTP|ActiveSync/i.test(p.client_app) ? ' ⚠️ LEGACY AUTH' : '') });
  if (p.tier === 'vip') facts.unshift({ title: 'Tier', value: '🔴 VIP — high priority' });
  // employee status from snapshot
  if (p.snapshot && p.snapshot.employee) {
    const emp = p.snapshot.employee;
    facts.push({ title: 'Employee', value: emp.status === 'terminated' ? '🔴 TERMINATED' + (emp.termination_date ? ' ' + emp.termination_date : '') : 'Active' });
  }
  // violation ID for deep-link
  if (p.violation_id) facts.push({ title: 'Violation #', value: String(p.violation_id) });

  // ── enriched fields ──
  // Employee status (highest priority context — goes near top)
  if (p.snapshot && p.snapshot.employee) {
    const emp = p.snapshot.employee;
    const empVal = emp.status === 'terminated'
      ? '🔴 TERMINATED' + (emp.termination_date ? ' · ' + emp.termination_date : '')
      : '🟢 Active';
    facts.splice(1, 0, { title: 'Employee', value: empVal });
  }

  // VIP flag (right after employee)
  if (p.tier === 'vip') facts.splice(2, 0, { title: 'Priority', value: '🔴 VIP — escalate immediately' });

  // v1.3.0: linked SDP ticket (violation ticket or account pause ticket)
  if (p.ticket_display) {
    facts.splice(1, 0, { title: 'Ticket', value: '🎫 SDP #' + p.ticket_display + (p.repush ? ' — tracking this activity' : '') });
  }

  // v1.4.0: risk-detection payloads replace sign-in facts with detection facts
  if (p.kind === 'risk_detection') {
    facts.length = 0;
    facts.push(
      { title: 'User', value: p.upn || '—' },
      { title: 'Detection', value: (p.risk_event_type || '—') + ' (' + (p.risk_level || '?') + ')' },
      { title: 'Detail', value: p.risk_detail || '—' },
      { title: 'Time', value: when },
      { title: 'IP', value: p.ip || '—' },
      { title: 'Location', value: [p.geo_city, p.geo_country].filter(Boolean).join(', ') || '—' },
      { title: 'Action', value: p.risk_event_type === 'leakedCredentials' ? 'Reset the password NOW — it is in a public dump' : 'Review in Entra Identity Protection' }
    );
    if (p.tier === 'vip') facts.splice(1, 0, { title: 'Priority', value: '🔴 VIP — escalate immediately' });
  }

  // v1.4.0: two engines agree — Microsoft flagged the same window
  if (p.ms_risk_match) {
    facts.splice(1, 0, { title: 'Corroborated', value: '⚠️ Microsoft also flagged: ' + (p.ms_risk_match.type || '?') + ' (' + (p.ms_risk_match.level || '?') + ')' + (p.ms_risk_match.ip_match ? ' — same IP' : '') });
  }

  // Resource targeted
  const resource = p.resource || (p.snapshot && p.snapshot.resource);
  if (resource && resource !== 'null') facts.push({ title: 'Resource', value: String(resource).slice(0, 80) });

  // Device posture
  const devManaged = p.device_managed != null ? p.device_managed : (p.snapshot && p.snapshot.device_managed);
  const devId = p.device_id || (p.snapshot && p.snapshot.device_id);
  const devParts = [];
  if (devManaged === false || devManaged === 'false' || devManaged === 0) devParts.push('⚠️ Unmanaged');
  if (!devId || devId === '' || devId === 'null') devParts.push('No device ID');
  if (devParts.length) facts.push({ title: 'Device', value: devParts.join(' · ') });

  // ASN / ISP (attacker infrastructure)
  if (p.geo_asn || p.geo_isp) {
    facts.push({ title: 'ASN / ISP', value: [p.geo_asn, p.geo_isp].filter(Boolean).join(' · ').slice(0, 100) });
  }

  // Subnet cluster
  if (p.snapshot && p.snapshot.subnet_cluster_size > 1) {
    facts.push({ title: 'Subnet', value: p.snapshot.subnet_cluster_size + ' IPs in same subnet — sustained campaign' });
  }

  // Failure streak
  if (p.__failure_streak != null && p.__failure_streak > 0) {
    facts.push({ title: 'Failure streak', value: String(p.__failure_streak) + ' consecutive failures' });
  }

  // findings from auto-investigation snapshot
  const bodyBlocks = [
    { type: 'TextBlock', size: 'Medium', weight: 'Bolder', color: cardColor(p.result), text: (p.tier === 'vip' ? '🔴 VIP · ' : '') + (p.test ? '🔧 Sign-In Watch — test alert' : (p.result === 'success' ? '🚨 SUCCESSFUL sign-in from untrusted network' : '⚠️ Sign-in attempt from untrusted network')), wrap: true },
  ];
  if (p.snapshot && Array.isArray(p.snapshot.findings) && p.snapshot.findings.length) {
    bodyBlocks.push({ type: 'TextBlock', text: '**Findings:** ' + p.snapshot.findings.join(' · '), wrap: true, color: 'Warning', spacing: 'Small' });
  }
  bodyBlocks.push({ type: 'FactSet', facts });

  // @mentions (from channel mention_config: { "mentions": [{"id":"upn@domain","name":"Name"}] })
  const msteams = { width: 'Full' };
  let mentionText = '';
  if (mentionConfig && Array.isArray(mentionConfig.mentions) && mentionConfig.mentions.length) {
    msteams.entities = mentionConfig.mentions.map(m => ({
      type: 'mention',
      text: '<at>' + (m.name || m.id) + '</at>',
      mentioned: { id: m.id, name: m.name || m.id },
    }));
    mentionText = mentionConfig.mentions.map(m => '<at>' + (m.name || m.id) + '</at>').join(' ');
    bodyBlocks.unshift({ type: 'TextBlock', text: mentionText, wrap: true });
  }

  return {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      contentUrl: null,
      content: {
        $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
        type: 'AdaptiveCard',
        version: '1.4',
        msteams,
        body: bodyBlocks,
        actions: [
          { type: 'Action.OpenUrl', title: 'Open Sign-In Watch', url: DASH_URL },
          { type: 'Action.OpenUrl', title: 'User in Identity Diag', url: IDENTITY_URL + '?q=' + encodeURIComponent(p.upn || '') },
          { type: 'Action.OpenUrl', title: 'Investigate', url: INVESTIGATE_URL + '?violation=' + (p.violation_id || '') },
        ].concat(p.ticket_url ? [{ type: 'Action.OpenUrl', title: 'Open Ticket', url: p.ticket_url }] : []),
      },
    }],
  };
}

const drivers = {
  // config_json: { "webhook_url": "https://prod-XX.westus.logic.azure.com/workflows/..." }
  async teams(config, payload) {
    if (!config || !config.webhook_url) return { ok: false, detail: 'missing webhook_url in config_json' };
    // Power Automate "Post card in a chat or channel" expects just the card content object,
    // not the full {"type":"message","attachments":[...]} wrapper.
    const card = buildTeamsCard(payload, payload.__mention_config);
    const cardContent = card.attachments[0].content;
    const r = await fetch(config.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cardContent),
      signal: AbortSignal.timeout(10000),
    });
    const ok = r.status >= 200 && r.status < 300;
    return { ok, detail: 'HTTP ' + r.status };
  },

  // config_json: { "url": "https://...", "headers": {..} } — generic JSON POST, future use
  async webhook(config, payload) {
    if (!config || !config.url) return { ok: false, detail: 'missing url in config_json' };
    const r = await fetch(config.url, {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, config.headers || {}),
      body: JSON.stringify({ event: 'signin_watch_violation', payload: Object.assign({}, payload, { raw: undefined }) }),
      signal: AbortSignal.timeout(10000),
    });
    const ok = r.status >= 200 && r.status < 300;
    return { ok, detail: 'HTTP ' + r.status };
  },
  // SDP: auto-create a ticket per violation (v1.1.0)
  async sdp(config, payload) {
    if (!sdpLookup || !sdpLookup.createTicket) return { ok: false, detail: 'sdp-lookup module not available' };
    if (payload.test) return { ok: true, detail: 'SDP test: would create ticket (skipped)' };
    try {
      const geo = [payload.geo_city, payload.geo_country].filter(Boolean).join(', ') || 'Unknown';
      const ticket = await sdpLookup.createTicket({
        subject: '[Sign-In Watch] ' + (payload.result === 'success' ? 'SUCCESSFUL' : 'Attempted') + ' sign-in — ' + (payload.upn || '?') + ' from ' + geo,
        description: [
          'Sign-In Watch automated alert',
          'User: ' + (payload.upn || '—'),
          'Source: ' + ((payload.source || '').toUpperCase()),
          'Result: ' + ((payload.result || 'unknown').toUpperCase()),
          'Time: ' + (payload.event_time instanceof Date ? payload.event_time.toISOString() : String(payload.event_time)),
          'IP: ' + (payload.ip || '—'),
          'Location: ' + geo,
          'App: ' + (payload.app_name || '—'),
          payload.failure_reason ? 'Reason: ' + String(payload.failure_reason).slice(0, 200) : null,
          '',
          'Dashboard: ' + DASH_URL,
        ].filter(Boolean).join('\n'),
        requesterEmail: config.requester_email || 'itcommand@auction.com',
        requesterName: config.requester_name || 'IT Command',
      });
      return { ok: true, detail: 'ticket #' + ticket.id };
    } catch (e) {
      return { ok: false, detail: e.message };
    }
  },

  // slack / email: drivers not yet implemented — channel rows can exist but will report unsupported.
};

function parseConfig(row) {
  if (row.config_json == null) return {};
  if (typeof row.config_json === 'object') return row.config_json;   // mysql2 JSON column
  try { return JSON.parse(row.config_json); } catch (e) { return {}; }
}

function channelMatches(row, payload) {
  if (!row.enabled) return false;
  if (payload.test) return true;
  // tier filter: channel can target vip-only, standard-only, or all
  const tier = payload.tier || 'standard';
  if (row.tier_filter === 'vip' && tier !== 'vip') return false;
  if (row.tier_filter === 'standard' && tier !== 'standard') return false;
  // v1.4.0: risk detections aren't sign-ins — tier-filtered but not fire_on-gated
  if (payload.kind === 'risk_detection') return true;
  // fire_on filter
  if (row.fire_on === 'all') return true;
  return row.fire_on === payload.result;
}

/**
 * Send a violation (or test) payload to all matching enabled channels.
 * Returns { sent: [names], failed: [{name, detail}] }.
 * Never throws.
 */
async function dispatch(pool, payload) {
  const out = { sent: [], failed: [] };
  let rows;
  try {
    [rows] = await pool.query('SELECT * FROM alert_channels WHERE enabled = 1');
  } catch (e) {
    out.failed.push({ name: '(db)', detail: e.message });
    return out;
  }
  // fetch failure streak once for this dispatch cycle
  if (!payload.__streak_fetched && payload.upn) {
    payload.__streak_fetched = true;
    try {
      const [[s]] = await pool.query(
        `SELECT COUNT(*) AS n FROM signin_violations
         WHERE upn = ? AND result = 'failure'
         AND event_time > COALESCE(
           (SELECT event_time FROM signin_violations WHERE result = 'success' AND upn = ? ORDER BY event_time DESC LIMIT 1),
           '2000-01-01'
         )`,
        [payload.upn, payload.upn]);
      payload.__failure_streak = s.n;
    } catch (e) { payload.__failure_streak = null; }
  }

  for (const row of rows) {
    if (!channelMatches(row, payload)) continue;
    const driver = drivers[row.type];
    if (!driver) { out.failed.push({ name: row.name, detail: 'driver not implemented: ' + row.type }); continue; }
    // attach this channel's mention config to the payload (teams driver reads it)
    let mc = null;
    if (row.mention_config) { try { mc = typeof row.mention_config === 'object' ? row.mention_config : JSON.parse(row.mention_config); } catch (e) {} }
    payload.__mention_config = mc;
    try {
      const res = await driver(parseConfig(row), payload);
      if (res.ok) out.sent.push(row.name);
      else out.failed.push({ name: row.name, detail: res.detail });
    } catch (e) {
      out.failed.push({ name: row.name, detail: e.message });
    }
  }
  return out;
}

/**
 * Fire a test payload at ONE channel by id (used by the console's test button).
 */
async function testChannel(pool, channelId, actorEmail) {
  const [rows] = await pool.query('SELECT * FROM alert_channels WHERE id = ?', [channelId]);
  if (!rows.length) return { ok: false, detail: 'channel not found' };
  const row = rows[0];
  const driver = drivers[row.type];
  if (!driver) return { ok: false, detail: 'driver not implemented: ' + row.type };
  const payload = {
    test: true, upn: actorEmail || 'test@auction.com', source: 'okta', result: 'failure',
    event_time: new Date(), ip: '203.0.113.10', geo_country: 'Testland', geo_city: 'Console',
    app_name: 'Sign-In Watch test', client_app: null, failure_reason: 'This is a test alert.',
  };
  let res;
  try { res = await driver(parseConfig(row), payload); }
  catch (e) { res = { ok: false, detail: e.message }; }
  try {
    await pool.query('UPDATE alert_channels SET last_test_at = NOW(), last_test_result = ? WHERE id = ?',
      [(res.ok ? 'OK ' : 'FAIL ') + String(res.detail).slice(0, 100), channelId]);
  } catch (e) { /* non-fatal */ }
  return res;
}

module.exports = { dispatch, testChannel, drivers };
