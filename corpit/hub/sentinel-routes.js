/**
 * sentinel-routes.js — Tenant Sentinel (Phase 1: live modules only)
 * Requires/rbac pattern confirmed to match sdops-routes.js exactly (2026-07-17).
 * Register in server.js next to the sdops mount:
 *   const sentinelRouter = require('./sentinel-routes');
 *   app.use('/api/sentinel', sentinelRouter);
 */
'use strict';
const express = require('express');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const router = express.Router();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});

const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const db = pool; // db.query(...) below matches pool.query(...)

const PAGE_KEY = 'tenant-sentinel';

// Okta statuses considered "active" — keep in sync with sdops-routes.js
const OKTA_ACTIVE = `('ACTIVE','PASSWORD_EXPIRED','RECOVERY','LOCKED_OUT')`;
// Exclude conference rooms / placeholder objects — same convention as sdops
const REAL_PERSON = `u.display_name NOT LIKE '.%'`;

/* ------------------------------------------------------------------ */
/* raw data endpoints (drill-down)                                     */
/* ------------------------------------------------------------------ */

// GET /api/sentinel/legacy-auth?days=30
router.get('/legacy-auth', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const days = Math.min(parseInt(req.query.days || '30', 10), 365);
  try {
    const [rows] = await db.query(
      `SELECT id, created_at AS createdAt, upn, display_name AS displayName,
              client_app AS clientApp, app_display_name AS appDisplayName,
              ip_address AS ip, country, error_code AS errorCode
         FROM sentinel_legacy_signin
        WHERE created_at >= NOW() - INTERVAL ? DAY
        ORDER BY created_at DESC LIMIT 2000`,
      [days]
    );
    res.json({ data: rows, total: rows.length });
  } catch (e) {
    console.error('[sentinel] legacy-auth', e.message);
    res.status(500).json({ error: 'query failed' });
  }
});

/* ------------------------------------------------------------------ */
/* findings engine                                                     */
/* ------------------------------------------------------------------ */

async function q(sql, params = []) {
  const [rows] = await db.query(sql, params);
  return rows;
}

function winName(os, ver) {
  if (os !== 'Windows' || !ver) return `${os} ${ver || ''}`.trim();
  const build = parseInt(String(ver).split('.')[2] || '0', 10);
  return `${build >= 22000 ? 'Windows 11' : 'Windows 10'} (build ${build})`;
}

async function computeFindings() {
  const findings = [];

  /* ---- IAM-LEG-002: legacy auth activity (30d) ---- */
  const leg = await q(
    `SELECT upn, client_app, COUNT(*) c
       FROM sentinel_legacy_signin
      WHERE created_at >= NOW() - INTERVAL 30 DAY
      GROUP BY upn, client_app ORDER BY c DESC`
  );
  const legTotal = leg.reduce((a, r) => a + r.c, 0);
  const legUsers = new Set(leg.map((r) => r.upn)).size;
  findings.push({
    id: 'IAM-LEG-002', sev: 'high', module: 'Identity',
    title: 'Legacy authentication activity observed',
    affected: legUsers,
    status: legTotal > 0 ? 'fail' : 'pass',
    fw: ['CIS 1.2.2', 'NIST PR.AC', 'ZT-Identity'],
    issue: `${legTotal} sign-ins via legacy protocols (IMAP/POP/SMTP-AUTH/EAS/EWS) in the last 30 days across ${legUsers} accounts.`,
    impact: 'Legacy protocols cannot enforce MFA and are the leading vector for account takeover via password spray.',
    risk: 'Each legacy sign-in bypasses MFA entirely. A Conditional Access block for "Other clients" is the fix.',
    steps: [
      'Create a report-only CA policy targeting legacy authentication clients.',
      'Review the accounts below and migrate legitimate legacy usage (scanners, shared mailboxes) to modern auth or app passwords behind named locations.',
      'Switch the policy to enforce (block).',
    ],
    evidence: { legacySignIns30d: legTotal, distinctUsers: legUsers, topClients: [...new Set(leg.slice(0, 5).map((r) => r.client_app))] },
    affectedList: leg.slice(0, 8).map((r) => ({ n: r.upn || '(unknown)', d: `${r.client_app}, ${r.c} sign-ins` })),
    ref: 'CIS §1.2 · MS Learn: Block legacy authentication', diff: 'low', rr: 81,
  });

  /* ---- IAM-SPRAY-003: lockout volume / password-spray traffic (7d) ---- */
  const lck = await q(
    `SELECT upn, COUNT(*) c FROM sdops_lockout
      WHERE created_at >= NOW() - INTERVAL 7 DAY
      GROUP BY upn ORDER BY c DESC`
  );
  const lckTotal = lck.reduce((a, r) => a + r.c, 0);
  findings.push({
    id: 'IAM-SPRAY-003', sev: 'critical', module: 'Identity',
    title: 'Account lockout volume consistent with password-spray activity',
    affected: lck.length,
    status: lckTotal > 50 ? 'fail' : lckTotal > 10 ? 'partial' : 'pass',
    fw: ['NIST DE.CM', 'ZT-Identity', 'CIS 1.x'],
    issue: `${lckTotal} lockout events (Entra errorCode 50053) across ${lck.length} accounts in the last 7 days.`,
    impact: 'Sustained spray traffic indicates active credential attack; a single weak/reused password yields a foothold.',
    risk: 'Attack tooling (Azure PowerShell/CLI, legacy mail clients) has been observed in prior analysis; CA policies to block legacy auth and non-admin access to admin portals are pending.',
    steps: [
      'Escalate to security (bundle with existing spray-campaign findings).',
      'CA: block legacy authentication tenant-wide.',
      'CA: block Windows Azure Service Management API / Admin Portals for non-admins.',
      'Consider geo-based CA for countries with no business presence.',
    ],
    evidence: { lockouts7d: lckTotal, uniqueUsers: lck.length },
    affectedList: lck.slice(0, 8).map((r) => ({ n: r.upn || '(unknown)', d: `${r.c} lockouts / 7d` })),
    ref: 'MS Learn: Conditional Access — block legacy auth', diff: 'medium', rr: 90,
  });

  /* ---- HYG-DIS-011: disabled in Entra but active in Okta ---- */
  const dis = await q(
    `SELECT u.user_principal_name upn, u.display_name dn, o.status oktaStatus, o.last_login lastLogin
       FROM entra_users u
       JOIN okta_users o ON o.login = u.user_principal_name
      WHERE u.account_enabled = 0 AND o.status IN ${OKTA_ACTIVE} AND ${REAL_PERSON}
      ORDER BY o.last_login DESC`
  );
  findings.push({
    id: 'HYG-DIS-011', sev: 'high', module: 'Accounts',
    title: 'Accounts disabled in Entra but still active in Okta',
    affected: dis.length,
    status: dis.length > 0 ? 'fail' : 'pass',
    fw: ['NIST PR.AC', 'ISO A.5.18', 'ZT-Identity'],
    issue: `${dis.length} accounts are disabled in Entra ID yet remain in an active state in Okta.`,
    impact: 'Okta-federated apps may still be reachable by identities the org considers offboarded/disabled.',
    risk: 'Access persists through the IdP the deprovisioning process missed — a direct offboarding-control gap.',
    steps: [
      'Deactivate the listed Okta accounts.',
      'Add Okta deactivation to the offboarding checklist / automate via SCIM or workflow.',
    ],
    evidence: { disabledEntraActiveOkta: dis.length },
    affectedList: dis.slice(0, 10).map((r) => ({ n: r.upn, d: `Okta ${r.oktaStatus}, last login ${r.lastLogin ? String(r.lastLogin).slice(0, 10) : 'never'}` })),
    ref: 'Okta lifecycle management docs', diff: 'trivial', rr: 74,
  });

  /* ---- OFF-GAP-020: terminated (90d) but active in Okta ---- */
  const term = await q(
    `SELECT u.user_principal_name upn, u.display_name dn, o.status oktaStatus,
            MAX(a.activity_date_time) termTs
       FROM entra_audit_logs a
       JOIN entra_users u ON u.entra_id = JSON_UNQUOTE(JSON_EXTRACT(a.target_resources_json, '$[0].id'))
       JOIN okta_users o ON o.login = u.user_principal_name
      WHERE a.activity_display_name = 'Disable account' AND a.result = 'success'
        AND a.activity_date_time >= NOW() - INTERVAL 90 DAY
        AND u.account_enabled = 0  -- still disabled today; re-enabled accounts (LOA returns, rehires) are not offboarding gaps
        AND o.status IN ${OKTA_ACTIVE}
      GROUP BY u.user_principal_name, u.display_name, o.status`
  );
  findings.push({
    id: 'OFF-GAP-020', sev: 'critical', module: 'Offboarding',
    title: 'Terminated employees still active in Okta',
    affected: term.length,
    status: term.length > 0 ? 'fail' : 'pass',
    fw: ['NIST PR.AC-4', 'ISO A.5.18', 'SOX ITGC'],
    issue: `${term.length} accounts disabled in Entra within the last 90 days (and still disabled today) remain active in Okta. Accounts re-enabled since (LOA returns, rehires) are excluded.`,
    impact: 'Terminated users retaining SSO access is a top audit finding and insider-risk exposure.',
    risk: 'Any Okta-federated app remains reachable post-termination until the Okta identity is deactivated.',
    steps: ['Deactivate the listed Okta accounts immediately.', 'Automate Okta deactivation on Entra disable.'],
    evidence: { terminated90dActiveOkta: term.length },
    affectedList: term.slice(0, 10).map((r) => ({ n: r.upn, d: `disabled ${String(r.termTs).slice(0, 10)}, Okta ${r.oktaStatus}` })),
    ref: 'Offboarding gap check (Terminations module)', diff: 'trivial', rr: 95,
  });

  /* ---- HYG-STALE-010: enabled accounts with no Okta login > 90d ---- */
  const stale = await q(
    `SELECT u.user_principal_name upn, o.last_login lastLogin
       FROM entra_users u
       JOIN okta_users o ON o.login = u.user_principal_name
      WHERE u.account_enabled = 1 AND o.status IN ${OKTA_ACTIVE} AND ${REAL_PERSON}
        AND (u.department IS NOT NULL AND u.department <> 'N-A' OR u.manager_upn IS NOT NULL)
        AND o.last_login IS NOT NULL AND o.last_login < NOW() - INTERVAL 90 DAY
      ORDER BY o.last_login ASC`
  );
  findings.push({
    id: 'HYG-STALE-010', sev: 'medium', module: 'Accounts',
    title: 'Enabled accounts with no sign-in for 90+ days',
    affected: stale.length,
    status: stale.length > 0 ? 'partial' : 'pass',
    fw: ['CIS 1.x', 'NIST PR.AC', 'ISO A.5.16'],
    issue: `${stale.length} enabled employee accounts have not signed in to Okta in over 90 days.`,
    impact: 'Dormant enabled accounts widen the attack surface with no business benefit.',
    risk: 'Stale accounts are preferred spray/phish targets — activity on them goes unnoticed.',
    steps: ['Review with HR/managers whether these are leaves, contractors, or missed offboarding.', 'Disable confirmed-dormant accounts.'],
    evidence: { staleEnabledAccounts: stale.length },
    affectedList: stale.slice(0, 10).map((r) => ({ n: r.upn, d: `last login ${String(r.lastLogin).slice(0, 10)}` })),
    ref: 'CIS account hygiene guidance', diff: 'low', rr: 55,
  });

  /* ---- DEF-RISKY-030: Identity Protection risky users ---- */
  const rsk = await q(
    `SELECT risk_level, COUNT(*) c FROM sentinel_risky_user
      WHERE risk_state IN ('atRisk','confirmedCompromised') GROUP BY risk_level`
  );
  const rc = { high: 0, medium: 0, low: 0 };
  for (const r of rsk) if (rc[r.risk_level] !== undefined) rc[r.risk_level] = r.c;
  const rskTotal = rc.high + rc.medium; // low-risk excluded as MS-noise; still shown in evidence
  const rskTop = await q(
    `SELECT upn, risk_level, risk_state, last_updated_dt FROM sentinel_risky_user
      WHERE risk_state IN ('atRisk','confirmedCompromised') AND risk_level IN ('high','medium')
      ORDER BY FIELD(risk_level,'high','medium'), last_updated_dt DESC LIMIT 8`
  );
  findings.push({
    id: 'DEF-RISKY-030', sev: rc.high > 0 ? 'high' : 'medium', module: 'Defender',
    title: 'Users flagged at-risk by Identity Protection with no remediation',
    affected: rskTotal,
    status: rc.high > 0 ? 'fail' : rskTotal > 0 ? 'partial' : 'pass',
    fw: ['NIST DE.CM', 'ZT-Identity', 'CIS 1.x'],
    issue: `${rskTotal} users are in an unremediated at-risk state at high/medium risk (${rc.high} high, ${rc.medium} medium; plus ${rc.low} low-risk not counted).`,
    impact: 'At-risk users have exhibited signals (leaked credentials, anomalous sign-ins) that Microsoft correlates with account compromise.',
    risk: 'Without risk-based CA policies or manual triage, flagged accounts remain usable by an attacker until someone notices.',
    steps: [
      'Triage high-risk users first: confirm compromise or dismiss with justification.',
      'Require secure password reset for confirmed cases.',
      'Deploy risk-based Conditional Access (block or require MFA on high sign-in/user risk) so this self-remediates.',
    ],
    evidence: { atRiskUsers: rskTotal, high: rc.high, medium: rc.medium, low: rc.low },
    affectedList: rskTop.map((r) => ({ n: r.upn, d: `${r.risk_level} · ${r.risk_state}` })),
    ref: 'MS Learn: Investigate risky users · risk-based CA', diff: 'medium', rr: 85,
  });

  /* ---- DEF-SCORE-031: Microsoft Secure Score ---- */
  const ss = await q(
    `SELECT current_score, max_score FROM sentinel_secure_score ORDER BY score_date DESC LIMIT 1`
  );
  const ssPct = ss.length ? Math.round((ss[0].current_score / ss[0].max_score) * 100) : null;
  findings.push({
    id: 'DEF-SCORE-031', sev: 'medium', module: 'Defender',
    title: 'Microsoft Secure Score below 80% target',
    affected: 1,
    status: ssPct === null ? 'pass' : ssPct >= 80 ? 'pass' : ssPct >= 65 ? 'partial' : 'fail',
    fw: ['CIS benchmark', 'NIST ID.RA'],
    issue: ssPct === null ? 'No Secure Score data collected yet.'
      : `Tenant Secure Score is ${ss[0].current_score}/${ss[0].max_score} (${ssPct}%).`,
    impact: 'Secure Score aggregates Microsoft-recommended hardening across identity, apps and devices; a low score means known controls are unimplemented.',
    risk: 'Each unimplemented improvement action is a documented, attacker-known gap.',
    steps: [
      'Review top improvement actions in Microsoft 365 Defender portal (sorted by points).',
      'Prioritize identity actions (MFA coverage, legacy auth, risk policies) — they overlap with existing critical findings here.',
    ],
    evidence: ss.length ? { currentScore: Number(ss[0].current_score), maxScore: Number(ss[0].max_score), percent: ssPct } : {},
    affectedList: [],
    ref: 'MS Learn: Microsoft Secure Score', diff: 'medium', rr: 70,
  });

  /* ---- DEF-DETECT-032: recent risk detections (30d) ---- */
  const det = await q(
    `SELECT upn, risk_event_type, risk_level, detected_dt, location FROM sentinel_risk_detection
      WHERE detected_dt >= NOW() - INTERVAL 30 DAY ORDER BY detected_dt DESC`
  );
  findings.push({
    id: 'DEF-DETECT-032', sev: 'low', module: 'Defender',
    title: 'Sign-in risk detections in the last 30 days',
    affected: new Set(det.map((d) => d.upn)).size,
    status: det.some((d) => d.risk_level === 'high') ? 'fail' : det.length > 0 ? 'partial' : 'pass',
    fw: ['NIST DE.AE', 'ZT-Identity'],
    issue: `${det.length} risk detections (unfamiliar sign-in properties, atypical travel, etc.) across ${new Set(det.map((d) => d.upn)).size} users in 30 days.`,
    impact: 'Individual low-risk detections are common noise, but clusters on one account indicate targeting.',
    risk: 'Detections feed user risk; unreviewed detections accumulate into at-risk users (see DEF-RISKY-030).',
    steps: ['Spot-check detections against the affected users for expected travel/devices.', 'Covered longer-term by risk-based CA.'],
    evidence: { detections30d: det.length },
    affectedList: det.slice(0, 8).map((d) => ({ n: d.upn, d: `${d.risk_event_type} · ${d.risk_level} · ${String(d.detected_dt).slice(0, 10)}` })),
    ref: 'MS Learn: Risk detections', diff: 'low', rr: 40,
  });

  /* ---- INT-COMP-040: noncompliant managed devices ---- */
  const nc = await q(
    `SELECT device_name, upn, os, os_version, last_sync_dt FROM sentinel_intune_device
      WHERE compliance_state = 'noncompliant' ORDER BY last_sync_dt DESC`
  );
  const [grace] = await q(`SELECT COUNT(*) c FROM sentinel_intune_device WHERE compliance_state = 'inGracePeriod'`);
  const [devTotal] = await q(`SELECT COUNT(*) c FROM sentinel_intune_device`);
  findings.push({
    id: 'INT-COMP-040', sev: 'high', module: 'Intune',
    title: 'Managed devices failing compliance policy',
    affected: nc.length,
    status: nc.length > Math.round(devTotal.c * 0.05) ? 'fail' : nc.length > 0 ? 'partial' : 'pass',
    fw: ['CIS device mgmt', 'NIST PR.IP', 'ZT-Device'],
    issue: `${nc.length} of ${devTotal.c} managed devices are noncompliant (plus ${grace.c} in grace period).`,
    impact: 'Noncompliant devices may lack passcodes, patches or jailbreak protection while retaining corporate access.',
    risk: 'If CA does not require device compliance, these devices access mail/data with unenforced baselines.',
    steps: [
      'Review top noncompliance reasons in Intune (settings grid).',
      'Notify owners of long-noncompliant devices; retire/wipe abandoned ones.',
      'Verify CA policies require compliant device for corporate apps.',
    ],
    evidence: { noncompliant: nc.length, inGracePeriod: grace.c, totalManaged: devTotal.c },
    affectedList: nc.slice(0, 8).map((d) => ({ n: d.device_name, d: `${d.upn || '(no user)'} · ${winName(d.os, d.os_version)}` })),
    ref: 'MS Learn: Intune compliance policies', diff: 'medium', rr: 75,
  });

  /* ---- INT-ENC-041: unencrypted devices ---- */
  // isEncrypted from Graph is known to lag; a device that is compliant AND recently
  // synced has passed Intune's own encryption evaluation, so exclude those (false positives).
  const unenc = await q(
    `SELECT device_name, upn, os, os_version FROM sentinel_intune_device
      WHERE is_encrypted = 0 AND compliance_state <> 'unknown'
        AND NOT (compliance_state = 'compliant' AND last_sync_dt >= NOW() - INTERVAL 14 DAY)
      ORDER BY os, device_name`
  );
  findings.push({
    id: 'INT-ENC-041', sev: 'high', module: 'Intune',
    title: 'Managed devices without disk encryption',
    affected: unenc.length,
    status: unenc.length > 0 ? 'fail' : 'pass',
    fw: ['CIS 2.x', 'NIST PR.DS', 'ISO A.8.24'],
    issue: `${unenc.length} devices report unencrypted to Intune and are not confirmed compliant (recently-synced compliant devices are excluded as known false positives in the Graph isEncrypted field).`,
    impact: 'A lost or stolen unencrypted laptop exposes all local corporate data with no mitigations.',
    risk: 'Unencrypted endpoints are a direct data-breach and disclosure-obligation risk.',
    steps: ['Check each device in Intune admin center > Devices > Monitor > Encryption report.', 'Verify BitLocker recovery keys are escrowed to Entra ID.', 'Re-sync or re-enroll devices whose encryption state will not refresh.'],
    evidence: { unencryptedDevices: unenc.length },
    affectedList: unenc.slice(0, 8).map((d) => ({ n: d.device_name, d: `${d.upn || '(no user)'} · ${winName(d.os, d.os_version)}` })),
    ref: 'MS Learn: Intune disk encryption policy', diff: 'low', rr: 88,
  });

  /* ---- INT-STALE-042: stale device sync (30d+) ---- */
  const dstale = await q(
    `SELECT device_name, upn, os, last_sync_dt FROM sentinel_intune_device
      WHERE last_sync_dt < NOW() - INTERVAL 30 DAY ORDER BY last_sync_dt ASC`
  );
  findings.push({
    id: 'INT-STALE-042', sev: 'medium', module: 'Intune',
    title: 'Managed devices not syncing for 30+ days',
    affected: dstale.length,
    status: dstale.length > 0 ? 'partial' : 'pass',
    fw: ['CIS device mgmt', 'NIST PR.MA'],
    issue: `${dstale.length} devices have not checked in to Intune for over 30 days.`,
    impact: 'Stale devices no longer receive policy, patches or remote wipe — management in name only.',
    risk: 'Their compliance state is frozen at last sync and cannot be trusted.',
    steps: ['Contact owners of recently-stale devices.', 'Set an Intune cleanup rule to auto-retire devices stale 90+ days.'],
    evidence: { staleDevices30d: dstale.length },
    affectedList: dstale.slice(0, 8).map((d) => ({ n: d.device_name, d: `${d.upn || '(no user)'} · last sync ${String(d.last_sync_dt).slice(0, 10)}` })),
    ref: 'MS Learn: Intune device cleanup rules', diff: 'low', rr: 50,
  });

  /* ---- EXO-QUOTA-050: mailboxes near send quota ---- */
  const nq = await q(
    `SELECT upn, display_name, storage_used_b, prohibit_send_b FROM sentinel_mailbox_usage
      WHERE prohibit_send_b > 0 AND storage_used_b > prohibit_send_b * 0.9
      ORDER BY storage_used_b / prohibit_send_b DESC`
  );
  findings.push({
    id: 'EXO-QUOTA-050', sev: 'medium', module: 'Exchange',
    title: 'Mailboxes at 90%+ of send quota',
    affected: nq.length,
    status: nq.length > 0 ? 'partial' : 'pass',
    fw: ['Operational hygiene'],
    issue: `${nq.length} mailboxes are above 90% of their prohibit-send quota.`,
    impact: 'These users will abruptly lose the ability to send mail, generating urgent helpdesk tickets.',
    risk: 'Predictable outage — cheap to prevent, disruptive to ignore.',
    steps: ['Enable archive mailboxes for the accounts below.', 'Apply retention/MRM policies to auto-archive.'],
    evidence: { mailboxesOver90Pct: nq.length },
    affectedList: nq.slice(0, 8).map((r) => ({ n: r.upn, d: `${Math.round(r.storage_used_b / r.prohibit_send_b * 100)}% of quota` })),
    ref: 'MS Learn: Exchange Online mailbox quotas', diff: 'low', rr: 45,
  });

  /* ---- EXO-INACT-051: enabled employees with inactive mailboxes (90d) ---- */
  const im = await q(
    `SELECT m.upn, m.display_name, m.last_activity_date FROM sentinel_mailbox_usage m
      JOIN entra_users u ON u.user_principal_name = m.upn
     WHERE u.account_enabled = 1 AND u.display_name NOT LIKE '.%'
       AND (u.department IS NOT NULL AND u.department <> 'N-A' OR u.manager_upn IS NOT NULL)
       AND (m.last_activity_date IS NULL OR m.last_activity_date < CURDATE() - INTERVAL 90 DAY)
     ORDER BY m.last_activity_date ASC`
  );
  findings.push({
    id: 'EXO-INACT-051', sev: 'medium', module: 'Exchange',
    title: 'Enabled employees with mailboxes inactive 90+ days',
    affected: im.length,
    status: im.length > 0 ? 'partial' : 'pass',
    fw: ['CIS 1.x', 'License hygiene'],
    issue: `${im.length} enabled employee accounts show no mailbox activity in 90+ days.`,
    impact: 'Correlates with the stale-account finding: unused licensed mailboxes cost money and widen attack surface.',
    risk: 'Unwatched mailboxes are ideal for silent forwarding rules and BEC persistence.',
    steps: ['Cross-check against HYG-STALE-010 account list.', 'Reclaim licenses for confirmed-dormant users.'],
    evidence: { inactiveMailboxes90d: im.length },
    affectedList: im.slice(0, 8).map((r) => ({ n: r.upn, d: `last activity ${r.last_activity_date ? String(r.last_activity_date).slice(0, 10) : 'never'}` })),
    ref: 'M365 usage reports', diff: 'low', rr: 50,
  });

  /* ---- SP-STALE-060: stale SharePoint sites (180d) ---- */
  // Tier thresholds (730/365/180/90 days) aligned to the authoritative
  // SharePoint Governance dashboard's computeTier() -- reused here rather
  // than an independent 180-day cutoff, per the consistency review.
  const ss2 = await q(
    `SELECT site_url, owner_name, last_activity_date, file_count, active_file_count, root_type, storage_used_b,
            CASE
              WHEN last_activity_date IS NULL THEN NULL
              ELSE DATEDIFF(CURDATE(), last_activity_date)
            END AS days_inactive
       FROM sentinel_sp_site
      WHERE last_activity_date IS NULL OR last_activity_date < CURDATE() - INTERVAL 180 DAY
      ORDER BY storage_used_b DESC`
  );
  const [spTotal] = await q(`SELECT COUNT(*) c FROM sentinel_sp_site`);
  const spCritical = ss2.filter((r) => r.days_inactive == null || r.days_inactive >= 730);
  const spHigh = ss2.filter((r) => r.days_inactive != null && r.days_inactive >= 365 && r.days_inactive < 730);
  const spMedium = ss2.filter((r) => r.days_inactive != null && r.days_inactive >= 180 && r.days_inactive < 365);
  const spSev = spCritical.length > 0 ? 'high' : spHigh.length > 0 ? 'high' : 'medium';
  findings.push({
    id: 'SP-STALE-060', sev: spSev, module: 'SharePoint',
    title: 'SharePoint sites inactive 180+ days',
    affected: ss2.length,
    status: ss2.length > Math.round(spTotal.c * 0.25) ? 'fail' : ss2.length > 0 ? 'partial' : 'pass',
    fw: ['ISO A.5.9', 'Data lifecycle'],
    issue: `${ss2.length} of ${spTotal.c} SharePoint sites have had no activity in over 180 days -- ${spCritical.length} never active or inactive 2+ years (critical), ${spHigh.length} inactive 1-2 years (high), ${spMedium.length} inactive 180-364 days (medium).`,
    impact: 'Abandoned sites accumulate stale permissions and unowned data nobody reviews.',
    risk: 'Orphaned content is invisible to owners but fully visible to anyone with lingering access.',
    steps: ['Run a site lifecycle review; archive or delete confirmed-dead sites.', 'Enable site inactivity policies in SharePoint admin.'],
    evidence: { staleSites180d: ss2.length, totalSites: spTotal.c, criticalCount: spCritical.length, highCount: spHigh.length, mediumCount: spMedium.length },
    affectedList: ss2.slice(0, 8).map((r) => ({ n: r.site_url || r.owner_name || '(unnamed)', d: `last active ${r.last_activity_date ? String(r.last_activity_date).slice(0, 10) : 'never'} · ${r.file_count} files (${r.active_file_count || 0} active)${r.root_type ? ' · ' + r.root_type : ''}` })),
    ref: 'SharePoint Governance dashboard thresholds (730/365/180/90 days); site population from Microsoft\'s getSharePointSiteUsageDetail (D30) report, which may differ slightly from SharePoint Governance\'s live getAllSites tenant directory count (a different Graph scope: usage-reported sites vs. every site that currently exists) -- both are real Microsoft-sourced figures, not a discrepancy to reconcile away.', diff: 'medium', rr: 55,
  });

  /* ---- SP-EXT-061: external file sharing (30d) ---- */
  const ext = await q(
    `SELECT upn, shared_externally FROM sentinel_sp_user_activity
      WHERE shared_externally > 0 ORDER BY shared_externally DESC`
  );
  const extFiles = ext.reduce((a, r) => a + Number(r.shared_externally), 0);
  findings.push({
    id: 'SP-EXT-061', sev: 'high', module: 'SharePoint',
    title: 'Files shared externally from SharePoint/OneDrive',
    affected: ext.length,
    status: extFiles > 100 ? 'fail' : extFiles > 0 ? 'partial' : 'pass',
    fw: ['NIST PR.DS', 'ZT-Data', 'ISO A.8.3'],
    issue: extFiles === 0 ? 'No external file sharing detected in the last 30 days.'
      : `${extFiles} files shared externally by ${ext.length} users in the last 30 days.`,
    impact: 'External shares are the primary data-egress channel from M365; volume needs monitoring.',
    risk: 'Unreviewed external shares persist after projects end and after employees leave.',
    steps: ['Review external sharing settings per site.', 'Consider expiration policies on external links.'],
    evidence: { externalSharers: ext.length, externalFiles30d: extFiles },
    affectedList: ext.slice(0, 8).map((r) => ({ n: r.upn, d: `${r.shared_externally} files shared externally` })),
    ref: 'MS Learn: SharePoint external sharing', diff: 'medium', rr: 78,
  });

  /* ---- PP-DLP-070: environments without DLP coverage ---- */
  const [dlpCount] = await q(`SELECT COUNT(*) c FROM sentinel_pp_dlp_policy`);
  const ppEnvs = await q(`SELECT display_name, sku, is_default, created_dt FROM sentinel_pp_environment ORDER BY is_default DESC, created_dt`);
  findings.push({
    id: 'PP-DLP-070', sev: 'high', module: 'Power Platform',
    title: 'No data loss prevention policies for Power Platform',
    affected: dlpCount.c === 0 ? ppEnvs.length : 0,
    status: dlpCount.c === 0 ? 'fail' : 'pass',
    fw: ['NIST PR.DS', 'ZT-Data', 'CIS app governance'],
    issue: dlpCount.c === 0
      ? `0 DLP policies exist across ${ppEnvs.length} Power Platform environments, including the tenant Default environment.`
      : `${dlpCount.c} DLP policies in place.`,
    impact: 'Without DLP policies, any licensed user can build Power Automate flows or Power Apps connecting corporate data (SharePoint, Outlook, Dataverse) to hundreds of third-party connectors — Dropbox, Gmail, social media, arbitrary HTTP endpoints.',
    risk: 'The Default environment is open to every licensed user by design; unmanaged connector use is a silent, sanctioned-looking data-exfiltration path.',
    steps: [
      'Create a tenant-wide DLP policy in the Power Platform admin center: classify business connectors (SharePoint, Teams, Dataverse) vs blocked/non-business (social, personal storage, HTTP).',
      'Apply strictest classification to the Default environment.',
      'Review existing flows/apps for violations after the policy lands (report available in admin center).',
    ],
    evidence: { dlpPolicies: dlpCount.c, environments: ppEnvs.length },
    affectedList: ppEnvs.slice(0, 8).map((e) => ({ n: e.display_name, d: `${e.sku}${e.is_default ? ' · DEFAULT — open to all users' : ''}` })),
    ref: 'MS Learn: Power Platform data loss prevention policies', diff: 'medium', rr: 82,
  });

  /* ---- PP-ENV-071: environment hygiene (trials/sprawl) ---- */
  const trials = await q(`SELECT display_name, sku, created_dt FROM sentinel_pp_environment WHERE sku IN ('Trial') ORDER BY created_dt`);
  findings.push({
    id: 'PP-ENV-071', sev: 'low', module: 'Power Platform',
    title: 'Trial and unmanaged environments present',
    affected: trials.length,
    status: trials.length > 0 ? 'partial' : 'pass',
    fw: ['App governance'],
    issue: `${trials.length} trial environments exist; trials sit outside normal governance and lifecycle.`,
    impact: 'Trial environments are created by individual users, often forgotten, and can hold real data.',
    risk: 'Ungoverned environments accumulate data and connections nobody reviews.',
    steps: ['Review trial environments and delete unused ones.', 'Restrict trial environment creation to admins in Power Platform settings.'],
    evidence: { trialEnvironments: trials.length },
    affectedList: trials.map((e) => ({ n: e.display_name, d: `created ${String(e.created_dt).slice(0, 10)}` })),
    ref: 'MS Learn: Control environment creation', diff: 'trivial', rr: 35,
  });

  /* ---- PUR-LBL-080: sensitivity label posture ---- */
  const lbls = await q(`SELECT name, is_active FROM sentinel_purview_label ORDER BY sensitivity DESC`);
  const activeLbls = lbls.filter((l) => l.is_active);
  const testLbls = activeLbls.filter((l) => /test|expire/i.test(l.name));
  findings.push({
    id: 'PUR-LBL-080', sev: 'medium', module: 'Purview',
    title: activeLbls.length === 0 ? 'No sensitivity labels published' : 'Test labels active in production taxonomy',
    affected: activeLbls.length === 0 ? 1 : testLbls.length,
    status: activeLbls.length === 0 ? 'fail' : testLbls.length > 0 ? 'partial' : 'pass',
    fw: ['NIST PR.DS', 'ISO A.5.12', 'ZT-Data'],
    issue: activeLbls.length === 0
      ? 'No active sensitivity labels are published to the tenant.'
      : `${activeLbls.length} active labels published; ${testLbls.length} appear to be test labels (${testLbls.map((l) => l.name).join(', ')}) alongside the production ADC taxonomy.`,
    impact: 'Sensitivity labels are the foundation for data classification, encryption and DLP in M365. Test labels in the user-facing picker cause misclassification and undermine the taxonomy.',
    risk: 'Users offered "Test Internal Email Encryption" next to ADC-Restricted will mislabel documents; encrypted-and-expiring test labels can silently destroy access to real content.',
    steps: [
      'Remove or deactivate test labels from the published policy (keep them in a test-scoped policy if needed).',
      'Verify the ADC-Public/Confidential/Restricted taxonomy matches the data classification standard.',
      'Phase 2: evaluate auto-labeling policies and label analytics for adoption measurement.',
    ],
    evidence: { activeLabels: activeLbls.length, testLabels: testLbls.length, taxonomy: activeLbls.map((l) => l.name) },
    affectedList: testLbls.map((l) => ({ n: l.name, d: 'active test label in production' })),
    ref: 'MS Learn: sensitivity labels', diff: 'low', rr: 48,
  });

  return findings;
}

function score(findings) {
  // Per-module scoring: each live module scores 0-100 from its own findings;
  // overall = average across modules. Any critical fail forces "At Risk".
  const W = { critical: 40, high: 25, medium: 12, low: 5 };
  const byMod = {};
  for (const f of findings) (byMod[f.module] = byMod[f.module] || []).push(f);
  const moduleScores = {};
  for (const [m, fs] of Object.entries(byMod)) {
    let s = 100;
    for (const f of fs) {
      if (f.status === 'fail') s -= W[f.sev];
      else if (f.status === 'partial') s -= Math.round(W[f.sev] / 2);
    }
    moduleScores[m] = Math.max(0, s);
  }
  const vals = Object.values(moduleScores);
  const s = vals.length ? Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) : 100;
  const crit = findings.filter((f) => f.sev === 'critical' && f.status === 'fail').length;
  let grade = s >= 85 ? 'Good' : s >= 70 ? 'Fair' : 'At Risk';
  if (crit > 0) grade = 'At Risk';
  return { score: s, grade, crit, moduleScores };
}

// GET /api/sentinel/overview — single payload driving the whole dashboard
router.get('/overview', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const findings = await computeFindings();
    const { score: s, grade, crit, moduleScores } = score(findings);

    // per-finding score impact: how much the overall score rises if this finding passed
    for (const f of findings) {
      if (f.status === 'pass') { f.scoreImpact = 0; continue; }
      const hypo = findings.map((x) => x === f ? { ...x, status: 'pass' } : x);
      f.scoreImpact = score(hypo).score - s;
    }

    // 14-day legacy-auth trend
    const trendRows = await q(
      `SELECT DATE(created_at) d, COUNT(*) c FROM sentinel_legacy_signin
        WHERE created_at >= NOW() - INTERVAL 14 DAY GROUP BY DATE(created_at) ORDER BY d`
    );

    // tiles
    const [lck7] = await q(`SELECT COUNT(*) c FROM sdops_lockout WHERE created_at >= NOW() - INTERVAL 7 DAY`);
    const legF = findings.find((f) => f.id === 'IAM-LEG-002');
    const disF = findings.find((f) => f.id === 'HYG-DIS-011');
    const gapF = findings.find((f) => f.id === 'OFF-GAP-020');

    res.json({
      generatedAt: new Date().toISOString(),
      score: s, grade, crit, moduleScores,
      severity: ['critical', 'high', 'medium', 'low'].reduce((o, k) => {
        o[k] = findings.filter((f) => f.sev === k && f.status !== 'pass').length; return o;
      }, {}),
      // Three of these four carried a fixed colour, so a zero was drawn in the
      // same red or amber as a hundred -- "Lockouts (7d): 0" rendered critical.
      // Only the offboarding tile tested its own value. Each now has a rung for
      // "none", which is the whole point of a coloured tile.
      // feeds: the /api/feeds registry keys whose freshness decides this number,
      // named here rather than in the page so the mapping cannot drift from the
      // queries above. windowH is how far back the number looks (null = a
      // point-in-time state, not a window): when a backing feed is older than
      // windowH the window lies entirely inside the gap, so a zero is guaranteed
      // rather than measured, and the page must not paint it as an all-clear.
      tiles: [
        { l: 'Legacy auth sign-ins (30d)', n: String(legF.evidence.legacySignIns30d), pct: Math.min(100, legF.evidence.legacySignIns30d), c: legF.evidence.legacySignIns30d > 0 ? '--high' : '--pass',
          feeds: ['sentinel_legacy_signin'], windowH: 720 },
        { l: 'Lockouts (7d)', n: String(lck7.c), pct: Math.min(100, Math.round(lck7.c / 10)), c: lck7.c > 0 ? '--crit' : '--pass',
          feeds: ['sdops_lockout'], windowH: 168 },
        { l: 'Entra-disabled / Okta-active', n: String(disF.affected), pct: Math.min(100, disF.affected * 10), c: disF.affected > 0 ? '--med' : '--pass',
          feeds: ['entra_users', 'okta_users'], windowH: null },
        { l: 'Offboarding gaps (90d)', n: String(gapF.affected), pct: Math.min(100, gapF.affected * 20), c: gapF.affected > 0 ? '--crit' : '--pass',
          feeds: ['entra_users', 'okta_users'], windowH: 2160 },
      ],
      trend: { labels: trendRows.map((r) => String(r.d).slice(5, 10)), data: trendRows.map((r) => r.c) },
      modulesAvailable: ['Identity', 'Accounts', 'Offboarding', 'Defender', 'Intune', 'Exchange', 'SharePoint', 'Power Platform', 'Purview'],
      modulesPending: [],
      findings,
    });
  } catch (e) {
    console.error('[sentinel] overview', e.message);
    res.status(500).json({ error: 'overview failed' });
  }
});


// ---------- Defender XDR incidents (added 2026-08-15) ----------
// Fed by collect-incidents.js. `windowDays` scopes the headline count the same
// way the landing page's other KPIs are scoped (locked today, certs <30d) —
// without it the count is dominated by months-old unresolved informational
// incidents and is permanently red.
router.get('/incidents', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const windowDays = Math.min(Math.max(parseInt(req.query.windowDays || '30', 10), 1), 365);
  try {
    const OPEN = "status IN ('active','inProgress')";
    const [[win]] = await pool.query(
      `SELECT COUNT(*) AS total,
              SUM(severity IN ('high','medium')) AS actionable
         FROM sentinel_incident
        WHERE ${OPEN} AND created_dt >= DATE_SUB(NOW(), INTERVAL ? DAY)`, [windowDays]);
    const [[all]] = await pool.query(
      `SELECT COUNT(*) AS openTotal,
              SUM(severity IN ('high','medium')) AS openActionable
         FROM sentinel_incident WHERE ${OPEN}`);
    const [bySeverity] = await pool.query(
      `SELECT severity, COUNT(*) AS n FROM sentinel_incident
        WHERE ${OPEN} GROUP BY severity`);
    const [recent] = await pool.query(
      `SELECT incident_id AS id, display_name AS displayName, status, severity,
              assigned_to AS assignedTo, web_url AS webUrl,
              created_dt AS createdAt, last_update_dt AS lastUpdatedAt
         FROM sentinel_incident WHERE ${OPEN}
        ORDER BY FIELD(severity,'high','medium','low','informational'), created_dt DESC
        LIMIT 50`);
    const [[fresh]] = await pool.query(
      `SELECT MAX(collected_at) AS collectedAt FROM sentinel_incident`);
    res.json({
      windowDays,
      windowOpen: Number(win.total || 0),
      windowActionable: Number(win.actionable || 0),
      openTotal: Number(all.openTotal || 0),
      openActionable: Number(all.openActionable || 0),
      bySeverity: bySeverity.reduce((a, r) => (a[r.severity || 'unknown'] = Number(r.n), a), {}),
      recent,
      collectedAt: fresh.collectedAt || null,
    });
  } catch (err) {
    console.error('[sentinel/incidents]', err.message);
    res.status(500).json({ error: 'incidents query failed' });
  }
});

// ---------- Defender / Identity Protection (added 2026-07-20) ----------
router.get('/defender', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [[score]] = await pool.query(
      `SELECT score_date, current_score AS currentScore, max_score AS maxScore
       FROM sentinel_secure_score ORDER BY score_date DESC LIMIT 1`);
    const [trend] = await pool.query(
      `SELECT score_date AS d, current_score AS s, max_score AS m
       FROM sentinel_secure_score ORDER BY score_date ASC`);
    const [riskyUsers] = await pool.query(
      `SELECT upn, display_name AS displayName, risk_level AS riskLevel,
              risk_state AS riskState, risk_detail AS riskDetail, last_updated_dt AS lastUpdated
       FROM sentinel_risky_user WHERE risk_state IN ('atRisk','confirmedCompromised')
       ORDER BY FIELD(risk_level,'high','medium','low'), last_updated_dt DESC`);
    const [detections] = await pool.query(
      `SELECT upn, risk_event_type AS eventType, risk_level AS riskLevel,
              risk_state AS riskState, detected_dt AS detectedAt, ip_address AS ip, location
       FROM sentinel_risk_detection ORDER BY detected_dt DESC LIMIT 200`);
    const counts = { high:0, medium:0, low:0 };
    for (const u of riskyUsers) if (counts[u.riskLevel] !== undefined) counts[u.riskLevel]++;
    res.json({ secureScore: score || null, scoreTrend: trend, riskyUsers,
               riskyCounts: counts, riskyTotal: riskyUsers.length, detections });
  } catch (err) {
    console.error('[sentinel/defender]', err.message);
    res.status(500).json({ error: 'defender query failed' });
  }
});

// ---------- Fix Tracking (added 2026-07-22) ----------
router.get('/status', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT finding_id, status, owner, notes, updated_by, updated_at FROM sentinel_finding_status`);
    res.json({ statuses: rows });
  } catch (err) {
    console.error('[sentinel/status:get]', err.message);
    res.status(500).json({ error: 'status query failed' });
  }
});

router.post('/status/:findingId', require('express').json(), rbac.requirePage(PAGE_KEY, 'admin'), async (req, res) => {
  const { findingId } = req.params;
  const { status, owner, notes } = req.body || {};
  const valid = ['open', 'in_progress', 'risk_accepted', 'resolved'];
  if (!valid.includes(status)) return res.status(400).json({ error: 'invalid status' });
  const ownerStr = owner == null ? null : String(owner).trim();
  if (ownerStr && !/^[^\s<>"']{1,255}$/.test(ownerStr)) return res.status(400).json({ error: 'invalid owner (one token, max 255 chars, no quotes or angle brackets)' });
  const notesStr = notes == null ? null : String(notes);
  if (notesStr && notesStr.length > 4000) return res.status(400).json({ error: 'notes too long (max 4000 chars)' });
  if (!/^[A-Z]{2,4}-[A-Z]{2,8}-\d{3}$/.test(findingId)) return res.status(400).json({ error: 'invalid finding id' });
  try {
    await db.query(
      `INSERT INTO sentinel_finding_status (finding_id, status, owner, notes, updated_by)
       VALUES (?,?,?,?,?)
       ON DUPLICATE KEY UPDATE status=VALUES(status), owner=VALUES(owner),
         notes=VALUES(notes), updated_by=VALUES(updated_by)`,
      [findingId, status, ownerStr || null, notesStr || null, req.user?.email || 'unknown']);
    res.json({ ok: true });
  } catch (err) {
    console.error('[sentinel/status:post]', err.message);
    res.status(500).json({ error: 'status update failed' });
  }
});

// ---------- Data Freshness (Phase 1.2, added 2026-09-01) ----------
// SOURCES lists every table this platform's findings/reports actually read.
// expectedMinutes comes only from verified crontab entries — sources without
// a confirmed schedule show age only, no breach flag (honesty over completeness).
const FRESHNESS_SOURCES = [
  { key: 'legacy_signin',   label: 'Legacy sign-ins',        table: 'sentinel_legacy_signin',   col: 'created_at',    expectedMinutes: null, tier: 'event-only', usedBy: ['IAM-LEG-002'] },
  { key: 'lockouts',        label: 'Account lockouts',       table: 'sdops_lockout',             col: 'created_at',    expectedMinutes: null, tier: 'event-only', usedBy: ['IAM-SPRAY-003'] },
  { key: 'risky_users',     label: 'Risky users (Defender)', table: 'sentinel_risky_user',       col: 'collected_at',  expectedMinutes: 1440, tier: 'timestamp', usedBy: ['DEF-RISKY-030'] },
  { key: 'risk_detections', label: 'Risk detections',        table: 'sentinel_risk_detection',   col: 'collected_at',  expectedMinutes: 1440, tier: 'timestamp', usedBy: ['DEF-DETECT-032'] },
  { key: 'secure_score',    label: 'Microsoft Secure Score', table: 'sentinel_secure_score',     col: 'collected_at',  expectedMinutes: 1440, tier: 'timestamp', usedBy: ['DEF-SCORE-031'] },
  { key: 'intune_device',   label: 'Intune devices',         table: 'sentinel_intune_device',    col: 'collected_at',   expectedMinutes: 1440,tier: 'timestamp', usedBy: ['INT-COMP-040','INT-ENC-041','INT-STALE-042'] },
  { key: 'mailbox_usage',   label: 'Mailbox usage',          table: 'sentinel_mailbox_usage',    col: 'collected_at',   expectedMinutes: 720, tier: 'timestamp', usedBy: ['EXO-QUOTA-050','EXO-INACT-051'] },
  { key: 'sp_site',         label: 'SharePoint sites',        table: 'sentinel_sp_site',          col: 'collected_at',   expectedMinutes: 720, tier: 'timestamp', usedBy: ['SP-STALE-060'] },
  { key: 'sp_user_activity',label: 'SharePoint sharing activity', table: 'sentinel_sp_user_activity', col: 'collected_at', expectedMinutes: 720, tier: 'timestamp', usedBy: ['SP-EXT-061'] },
  { key: 'pp_environment',  label: 'Power Platform environments', table: 'sentinel_pp_environment', col: 'collected_at', expectedMinutes: 720, tier: 'timestamp', usedBy: ['PP-ENV-071'] },
  { key: 'pp_dlp',          label: 'Power Platform DLP policies', table: 'sentinel_pp_dlp_policy', col: null,           expectedMinutes: 720, tier: 'count-only', usedBy: ['PP-DLP-070'] },
  { key: 'purview_label',   label: 'Purview sensitivity labels', table: 'sentinel_purview_label', col: null,           expectedMinutes: 720, tier: 'count-only', usedBy: ['PUR-LBL-080'] },
  { key: 'incidents',       label: 'Defender incidents',     table: 'sentinel_incident',          col: 'collected_at',   expectedMinutes: 1440,tier: 'timestamp', usedBy: ['Dashboard incidents'] },
  { key: 'insight_sku',     label: 'Licensing (SKUs)',        table: 'insight_sku',                col: 'collected_at',   expectedMinutes: 1440, tier: 'timestamp', usedBy: ['Licensing & Cost'] },
  { key: 'insight_activity',label: 'Workload activity',       table: 'insight_user_activity',       col: 'collected_at',   expectedMinutes: 1440, tier: 'timestamp', usedBy: ['Workload Activity','Licensing holders'] },
  { key: 'insight_sp',      label: 'App consent (service principals)', table: 'insight_service_principal', col: 'collected_at', expectedMinutes: 1440, tier: 'timestamp', usedBy: ['App & Automation'] },
  { key: 'insight_flow',    label: 'Power Automate flows',    table: 'insight_flow',               col: 'collected_at',   expectedMinutes: 1440, tier: 'timestamp', usedBy: ['App & Automation'] },
  { key: 'okta_users',      label: 'Okta users',              table: 'okta_users',                  col: 'last_synced_at', expectedMinutes: 1440, tier: 'timestamp', usedBy: ['HYG-DIS-011','HYG-STALE-010','OFF-GAP-020'] },
  { key: 'okta_factors',    label: 'Okta MFA factors',        table: 'okta_user_factors',      col: 'last_synced_at', expectedMinutes: 1440, tier: 'timestamp', usedBy: ['User 360 MFA','Privileged access MFA'] },
  { key: 'okta_entra_migration', label: 'Okta to Entra CA snapshot', table: 'oem_okta_policy', col: 'collected_at', expectedMinutes: 1440, tier: 'timestamp', usedBy: ['okta-entra-migration'] },
  { key: 'priv_roles',      label: 'Entra directory roles',   table: 'priv_role_assignment',   col: 'collected_at',   expectedMinutes: 1440, tier: 'timestamp', usedBy: ['PRIV-GA-090','Privileged access'] },
  { key: 'entra_users',     label: 'Entra ID users',          table: null,                          col: null,             expectedMinutes: null, tier: 'run-log-entra', usedBy: ['Nearly every finding'] },
];

router.get('/freshness', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const results = [];
    for (const s of FRESHNESS_SOURCES) {
      let lastAt = null, count = null;
      try {
        if (s.tier === 'count-only') {
          const [row] = await q(`SELECT COUNT(*) c FROM ${s.table}`);
          count = row.c;
        } else if (s.col) {
          const [row] = await q(`SELECT MAX(${s.col}) m, COUNT(*) c FROM ${s.table}`);
          lastAt = row.m; count = row.c;
        }
      } catch (e) { /* table/col mismatch surfaces as unknown below, not a crash */ }
      const ageMinutes = lastAt ? Math.round((Date.now() - new Date(lastAt).getTime()) / 60000) : null;
      const stale = s.expectedMinutes != null && ageMinutes != null ? ageMinutes > s.expectedMinutes * 2 : null;
      results.push({
        key: s.key, label: s.label, usedBy: s.usedBy, tier: s.tier,
        lastCollectedAt: lastAt, ageMinutes, expectedMinutes: s.expectedMinutes,
        stale, rowCount: count,
      });
    }
    // entra-sync: real run-log signal (status enum + error), no verified cadence to flag breach against
    const entraRuns = await q(
      `SELECT job, status, started_at, completed_at, records_fetched, records_upserted, error_message
       FROM entra_sync_status ORDER BY started_at DESC LIMIT 200`);
    const byJob = {};
    for (const r of entraRuns) if (!byJob[r.job]) byJob[r.job] = r; // most recent per job (query is DESC)
    const entraStatus = Object.values(byJob).map((r) => ({
      job: r.job, status: r.status, startedAt: r.started_at, completedAt: r.completed_at,
      recordsFetched: r.records_fetched, recordsUpserted: r.records_upserted,
      error: r.error_message || null,
    }));
    const ix = results.findIndex((r) => r.key === 'entra_users');
    if (ix >= 0) results[ix] = { ...results[ix], entraJobs: entraStatus };

    const entraReliability = await q(
      `SELECT job, COUNT(*) total, SUM(status='success') successes, MAX(started_at) lastRun
       FROM entra_sync_status WHERE started_at >= NOW() - INTERVAL 24 HOUR GROUP BY job ORDER BY job`);
    const sdopsReliability = await q(
      `SELECT module, COUNT(*) total, SUM(status='ok') successes, MAX(started_at) lastRun
       FROM sdops_collector_run WHERE started_at >= NOW() - INTERVAL 24 HOUR GROUP BY module ORDER BY module`);
    const withRate = (rows, nameKey) => rows.map((r) => ({
      name: r[nameKey], total: r.total, successes: r.successes,
      rate: r.total ? Math.round((r.successes / r.total) * 100) : null,
      lastRun: r.lastRun,
    }));

    res.json({
      generatedAt: new Date().toISOString(),
      note: 'Sources marked tier "timestamp" show ingestion age (real collector-run signal). "event-only" sources have no ingestion timestamp in the schema — age reflects the most recent event from Microsoft, not collector health, and no stale flag is shown. Only entra-sync (tier "run-log-entra") has verified run-level status.',
      sources: results,
      reliability: {
        windowHours: 24,
        note: 'Success rate exists only for sources with a real run log (entra-sync, and the two SDOps collectors below). No run log exists for defender, intune, m365-reports, purview, powerplatform, or tenant-insights collectors — their reliability cannot be measured, only their ingestion age (above).',
        entra: withRate(entraReliability, 'job'),
        sdops: withRate(sdopsReliability, 'module'),
      },
    });
  } catch (err) {
    console.error('[sentinel/freshness]', err.message);
    res.status(500).json({ error: 'freshness query failed' });
  }
});

// ---------- Privileged Access — "Who Has the Keys?" (Phase 2.2, added 2026-09-01) ----------
router.get('/history', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const days = Math.min(Math.max(parseInt(req.query.days || '30', 10), 1), 365);
  try {
    const rows = await q(
      `SELECT snapshot_date, score, grade, crit_count FROM sentinel_score_history
        WHERE snapshot_date >= CURDATE() - INTERVAL ? DAY ORDER BY snapshot_date ASC`, [days]);
    res.json({
      days, points: rows.length,
      // Zero rows because the snapshot job has never run here is not the same
      // as zero rows because history just began. Say which.
      note: rows.length === 0
        ? 'No daily snapshots have been recorded on this host yet — the trend fills in once snapshot-history-job.js runs.'
        : rows.length < 3 ? 'History just started — the trend line will fill in as daily snapshots accumulate.' : null,
      history: rows.map((r) => ({ date: String(r.snapshot_date).slice(0, 10), score: r.score, grade: r.grade, crit: r.crit_count })),
    });
  } catch (err) {
    console.error('[sentinel/history]', err.message);
    res.status(500).json({ error: 'history query failed' });
  }
});

router.get('/tenant-changes', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const days = Math.min(Math.max(parseInt(req.query.days || '30', 10), 1), 90);
  try {
    // observedTo: same reason as /signin-analytics -- a relative window over a
    // feed that has stopped advancing is not the window the caller asked for.
    const [[total]] = await pool.query(
      `SELECT COUNT(*) c, MAX(activity_date_time) observedTo
         FROM entra_audit_logs WHERE activity_date_time >= NOW() - INTERVAL ? DAY`, [days]);
    const byCategory = await q(
      `SELECT COALESCE(category, 'Uncategorized') category, COUNT(*) c FROM entra_audit_logs
        WHERE activity_date_time >= NOW() - INTERVAL ? DAY GROUP BY category ORDER BY c DESC`, [days]);
    const byActivity = await q(
      `SELECT activity_display_name activity, category, COUNT(*) c FROM entra_audit_logs
        WHERE activity_date_time >= NOW() - INTERVAL ? DAY
        GROUP BY activity_display_name, category ORDER BY c DESC LIMIT 15`, [days]);
    const byInitiator = await q(
      `SELECT COALESCE(initiated_by_user_upn, initiated_by_app_name, 'unknown') initiator,
              initiated_by_app_name IS NOT NULL AS isApp, COUNT(*) c
         FROM entra_audit_logs WHERE activity_date_time >= NOW() - INTERVAL ? DAY
        GROUP BY initiator, isApp ORDER BY c DESC LIMIT 15`, [days]);
    const recent = await q(
      `SELECT activity_date_time dt, activity_display_name activity, category, result,
              COALESCE(initiated_by_user_upn, initiated_by_app_name, 'unknown') initiator,
              initiated_by_app_name IS NOT NULL AS isApp,
              JSON_UNQUOTE(JSON_EXTRACT(target_resources_json, '$[0].displayName')) targetName
         FROM entra_audit_logs WHERE activity_date_time >= NOW() - INTERVAL ? DAY
        ORDER BY activity_date_time DESC LIMIT 500`, [days]);
    res.json({ days, total: total.c, observedTo: total.observedTo || null,
               byCategory, byActivity, byInitiator, recent });
  } catch (err) {
    console.error('[sentinel/tenant-changes]', err.message);
    res.status(500).json({ error: 'tenant-changes query failed' });
  }
});

router.get('/user360', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const upn = (req.query.upn || '').trim().toLowerCase();
  if (!upn) return res.status(400).json({ error: 'upn query parameter is required' });
  try {
    const [u] = await q(
      `SELECT entra_id, display_name, user_principal_name upn, department, job_title,
              manager_upn, account_enabled, last_login
         FROM entra_users WHERE LOWER(user_principal_name) = ?`, [upn]);
    if (!u) return res.status(404).json({ error: 'user not found' });

    let managerName = null;
    if (u.manager_upn) {
      const [m] = await q(`SELECT display_name FROM entra_users WHERE user_principal_name = ?`, [u.manager_upn]);
      managerName = m ? m.display_name : u.manager_upn;
    }

    const roles = await q(
      `SELECT ra.role_name, COALESCE(pt.privilege_tier, 2) AS tier, ra.eligibility
         FROM priv_role_assignment ra LEFT JOIN priv_role_tier pt ON pt.role_name = ra.role_name
        WHERE ra.member_entra_id = ? AND ra.member_type = 'user'`, [u.entra_id]);

    const [okta] = await q(`SELECT okta_id, status FROM okta_users WHERE LOWER(login) = ?`, [upn]);
    // If the factor table has never been collected, every user reads back as
    // "no active factor" -- an unmeasured state rendering as a measured
    // finding. Carry the distinction to the client instead.
    const [[factorCov]] = await pool.query('SELECT COUNT(*) c FROM okta_user_factors');
    const mfaMeasured = factorCov.c > 0;
    let mfa = { measured: mfaMeasured, hasActiveFactor: mfaMeasured ? false : null, factorTypes: [] };
    if (okta && mfaMeasured) {
      const factors = await q(`SELECT factor_type FROM okta_user_factors WHERE okta_id = ? AND status = 'ACTIVE'`, [okta.okta_id]);
      mfa = { measured: true, hasActiveFactor: factors.length > 0, factorTypes: factors.map((f) => f.factor_type) };
    }

    const [activity] = await q(
      `SELECT licenses, exchange_last, onedrive_last, sharepoint_last, teams_last
         FROM insight_user_activity WHERE LOWER(upn) = ?`, [upn]);

    const [copilot] = await q(
      `SELECT chat_last_active, teams_last_active, word_last_active, excel_last_active,
              powerpoint_last_active, outlook_last_active, onenote_last_active, loop_last_active
         FROM copilot_app_usage WHERE LOWER(email) = ?`, [upn]);

    const findings = await computeFindings();
    const dnLower = (u.display_name || '').toLowerCase();
    const related = findings.filter((f) => (f.affectedList || []).some((a) =>
      (a.n || '').toLowerCase() === upn || (a.n || '').toLowerCase() === dnLower));

    res.json({
      identity: { ...u, managerName },
      roles, mfa,
      activity: activity || null,
      copilot: copilot || null,
      relatedFindings: related.map((f) => ({ id: f.id, title: f.title, sev: f.sev, module: f.module, status: f.status })),
    });
  } catch (err) {
    console.error('[sentinel/user360]', err.message);
    res.status(500).json({ error: 'user360 query failed' });
  }
});

router.get('/search', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const term = (req.query.q || '').trim();
  if (term.length < 2) return res.json({ privilegedAccounts: [], recentActivity: [] });
  const like = '%' + term + '%';
  try {
    const privilegedAccounts = await q(
      `SELECT DISTINCT u.user_principal_name upn, u.display_name dn, ra.role_name
         FROM priv_role_assignment ra
         JOIN entra_users u ON u.entra_id = ra.member_entra_id
        WHERE ra.member_type = 'user' AND (u.display_name LIKE ? OR u.user_principal_name LIKE ?)
        LIMIT 8`, [like, like]);
    const recentActivity = await q(
      `SELECT DISTINCT COALESCE(initiated_by_user_upn, initiated_by_app_name) initiator,
              initiated_by_app_name IS NOT NULL AS isApp
         FROM entra_audit_logs
        WHERE activity_date_time >= NOW() - INTERVAL 30 DAY
          AND (initiated_by_user_upn LIKE ? OR initiated_by_app_name LIKE ?)
        LIMIT 8`, [like, like]);
    const privUpns = new Set(privilegedAccounts.map((p) => p.upn));
    const employeeCandidates = await q(
      `SELECT user_principal_name upn, display_name dn, department
         FROM entra_users
        WHERE account_enabled = 1 AND display_name NOT LIKE '.%'
          AND (display_name LIKE ? OR user_principal_name LIKE ?)
        LIMIT 15`, [like, like]);
    const employees = employeeCandidates.filter((e) => !privUpns.has(e.upn)).slice(0, 8);
    res.json({ privilegedAccounts, recentActivity, employees });
  } catch (err) {
    console.error('[sentinel/search]', err.message);
    res.status(500).json({ error: 'search failed' });
  }
});

router.get('/signin-analytics', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const days = Math.min(Math.max(parseInt(req.query.days || '30', 10), 1), 90);
  try {
    // [CORPIT-QA 2026-09-07] Also select the span actually observed. The window
    // is relative (NOW() - INTERVAL n DAY) but the feed is not guaranteed to be
    // current, so "last 30 days" can silently mean "the 19 days that ended when
    // the collector stopped". The caller needs the real span to label the number.
    const [[totals]] = await pool.query(
      `SELECT COUNT(*) total, SUM(outcome='FAILURE') failures,
              SUM(conditional_access_status='notApplied') caNotApplied,
              MIN(created_at) observedFrom, MAX(created_at) observedTo
         FROM entra_signin_logs WHERE created_at >= NOW() - INTERVAL ? DAY`, [days]);
    const byDay = await q(
      `SELECT DATE(created_at) d, COUNT(*) total, SUM(outcome='FAILURE') failures
         FROM entra_signin_logs WHERE created_at >= NOW() - INTERVAL ? DAY
        GROUP BY DATE(created_at) ORDER BY d ASC`, [days]);
    const topFailures = await q(
      `SELECT status_failure_reason reason, COUNT(*) c FROM entra_signin_logs
        WHERE outcome='FAILURE' AND created_at >= NOW() - INTERVAL ? DAY AND status_failure_reason IS NOT NULL
        GROUP BY status_failure_reason ORDER BY c DESC LIMIT 10`, [days]);
    const byCountry = await q(
      `SELECT location_country country, COUNT(*) c FROM entra_signin_logs
        WHERE created_at >= NOW() - INTERVAL ? DAY AND location_country IS NOT NULL
        GROUP BY location_country ORDER BY c DESC LIMIT 12`, [days]);
    res.json({
      days,
      // A rate over zero rows is not 0% -- it is unmeasured. Returning a literal
      // 0 here made a dead feed read as "0% failures / 0% without CA", i.e. the
      // most reassuring value the tile can show. null forces the caller to say so.
      totals: { total: totals.total, failures: totals.failures,
                failureRate: totals.total ? Math.round((totals.failures / totals.total) * 100) : null,
                caNotAppliedRate: totals.total ? Math.round((totals.caNotApplied / totals.total) * 100) : null,
                observedFrom: totals.observedFrom || null,
                observedTo: totals.observedTo || null },
      byDay: byDay.map((r) => ({ date: String(r.d).slice(0, 10), total: r.total, failures: r.failures })),
      topFailures, byCountry,
    });
  } catch (err) {
    console.error('[sentinel/signin-analytics]', err.message);
    res.status(500).json({ error: 'signin-analytics query failed' });
  }
});

router.get('/priv-access', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    // Weak factors are sms/call/email/question; anything else (push,
    // signed_nonce, TOTP, webauthn) counts as strong.
    const rows = await q(
      `SELECT ra.role_name, COALESCE(pt.privilege_tier, 2) AS tier, pt.role_name IS NULL AS unclassified,
              ra.eligibility, ra.member_type, ra.member_entra_id,
              COALESCE(u.display_name, sp.display_name) dn,
              COALESCE(u.user_principal_name, sp.display_name) upn,
              COALESCE(u.account_enabled, sp.account_enabled) account_enabled,
              COALESCE(u.last_login, sp.last_signin_dt) last_login,
              sp.app_id, sp.publisher,
              COALESCE(SUM(f.factor_type IS NOT NULL
                       AND f.factor_type NOT IN ('sms','call','email','question')), 0) > 0 AS hasStrongMfa,
              COALESCE(SUM(f.factor_type IS NOT NULL), 0) > 0
                AND COALESCE(SUM(f.factor_type IS NOT NULL
                       AND f.factor_type NOT IN ('sms','call','email','question')), 0) = 0 AS hasSmsOnly
         FROM priv_role_assignment ra
         LEFT JOIN priv_role_tier pt ON pt.role_name = ra.role_name
         LEFT JOIN entra_users u ON u.entra_id = ra.member_entra_id AND ra.member_type = 'user'
         -- Service principals hold directory roles too, and one of them holds
         -- Global Administrator here. They were returned unresolved (no name,
         -- no upn) and the page then dropped them, so an app with GA never
         -- appeared on the page that exists to list who holds GA.
         LEFT JOIN insight_service_principal sp
                ON sp.sp_id = ra.member_entra_id AND ra.member_type = 'servicePrincipal'
         LEFT JOIN okta_users o ON o.login = u.user_principal_name AND o.status != 'DEPROVISIONED'
         LEFT JOIN okta_user_factors f ON f.okta_id = o.okta_id AND f.status = 'ACTIVE'
        GROUP BY ra.role_name, pt.privilege_tier, ra.eligibility, ra.member_type, ra.member_entra_id,
                 u.display_name, u.user_principal_name, u.account_enabled, u.last_login,
                 sp.display_name, sp.account_enabled, sp.last_signin_dt, sp.app_id, sp.publisher
        ORDER BY tier ASC, ra.role_name`);
    const byTier = { 0: 0, 1: 0, 2: 0, 3: 0 };
    const seen = new Set();
    for (const r of rows) { if (!seen.has(r.member_entra_id)) { byTier[r.tier] = (byTier[r.tier] || 0) + 1; seen.add(r.member_entra_id); } }
    const [[privCov]] = await pool.query(
      'SELECT COUNT(*) c, MAX(collected_at) lastAt FROM priv_role_assignment');
    const [[privMfaCov]] = await pool.query(
      'SELECT COUNT(*) c, MAX(last_synced_at) lastAt FROM okta_user_factors');
    // A role with no priv_role_tier row falls to tier 2 via COALESCE. That is a
    // default, not a classification, and 14 roles currently take it -- including
    // Directory Synchronization Accounts. The per-row 'unclassified role' chip
    // discloses it one row at a time; the tier tallies do not, so say it here.
    const [[unclass]] = await pool.query(
      `SELECT COUNT(DISTINCT ra.role_name) roles, COUNT(DISTINCT ra.member_entra_id) members
         FROM priv_role_assignment ra
         LEFT JOIN priv_role_tier pt ON pt.role_name = ra.role_name
        WHERE pt.role_name IS NULL`);
    const gaTrend = await q(
      `SELECT snapshot_date, affected FROM sentinel_finding_history
        WHERE finding_id = 'PRIV-GA-090' ORDER BY snapshot_date ASC LIMIT 90`);

    res.json({
      generatedAt: new Date().toISOString(),
      coverage: {
        // entra was the literal true: the page claimed directory roles were
        // collected even on a host where the collector had never run. Both
        // this and the MFA flag are now read from the tables themselves.
        entra: privCov.c > 0, entraCollectedAt: privCov.lastAt,
        mfaMeasured: privMfaCov.c > 0, mfaCollectedAt: privMfaCov.lastAt,
        pim: rows.some((r) => r.eligibility === 'eligible'),
        unclassifiedRoles: unclass.roles, unclassifiedMembers: unclass.members,
        okta: false, azureRbac: false,
        note: (privCov.c > 0
          ? 'Entra directory roles: collected.'
          : 'Entra directory roles: NOT collected on this host yet — run collect-priv-roles.js.')
          + (unclass.roles
              ? `  ${unclass.roles} role${unclass.roles === 1 ? '' : 's'} (${unclass.members} account${unclass.members === 1 ? '' : 's'}) have no privilege-tier classification and are counted at tier 2 by default \u2014 a default, not an assessment.`
              : '')
          + '  MFA status: from Okta (this tenant\'s real authentication system), not Entra. PIM eligibility: collected. Okta admin roles and Azure RBAC role assignments are not collected — out of scope for this report today.',
      },
      gaTrend: gaTrend.map((r) => ({ date: String(r.snapshot_date).slice(0, 10), count: r.affected })),
      byTier,
      principals: {
        users: new Set(rows.filter((r) => r.member_type === 'user').map((r) => r.member_entra_id)).size,
        servicePrincipals: new Set(rows.filter((r) => r.member_type === 'servicePrincipal').map((r) => r.member_entra_id)).size,
        other: new Set(rows.filter((r) => r.member_type !== 'user' && r.member_type !== 'servicePrincipal').map((r) => r.member_entra_id)).size,
      },
      assignments: rows.map((r) => ({
        ...r,
        hasStrongMfa: r.member_type !== 'user' ? undefined : (privMfaCov.c > 0 ? !!r.hasStrongMfa : null),
        hasSmsOnly: r.member_type !== 'user' ? undefined : (privMfaCov.c > 0 ? !!r.hasSmsOnly : null),
      })),
    });
  } catch (err) {
    console.error('[sentinel/priv-access]', err.message);
    res.status(500).json({ error: 'priv-access query failed' });
  }
});

router.computeFindings = computeFindings;
router.score = score;

module.exports = router;
