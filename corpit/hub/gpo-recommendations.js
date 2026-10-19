'use strict';
/**
 * gpo-recommendations.js  (Phase 1 enriched)
 * ─────────────────────────────────────────────────────────────────────
 * Converts findings into prescriptive remediation recommendations.
 *
 * Phase 1 enrichment over the original module:
 *   - Accepts a settingsByKey map (keyed by gpo_settings.setting_key)
 *     so per-finding recs can show exact policyPath / current value /
 *     per-GPO state for setting-level findings.
 *   - Each rec output now carries (in addition to existing fields):
 *       setting           — { policyPath, settingName, scope, settingType } | null
 *       affectedGPOs      — [{ name, guid, currentState, currentValue }] | null
 *       whyItMatters      — short business/security framing
 *       whereToFix        — { gpmc:{console,steps}, intune?:{csp,note}|null }
 *       applyable         — boolean (can the page Apply this in Phase 2?)
 *       applyAction       — 'remove_gpo' | 'remove_link' | 'set_status'
 *                          | 'clear_wmi' | null
 *
 * Backwards-compatible: if settingsByKey is undefined the new fields are
 * still emitted (with `setting:null` and `affectedGPOs:null`) so the
 * frontend can render everything else uniformly.
 *
 * Principles preserved from the original:
 *   1. Every destructive action is preceded by a Backup-GPO command
 *   2. Remove-* commands default to -WhatIf (dry-run)
 *   3. Risk ratings explicit: Low | Medium | High
 *   4. Tool never writes to AD here — recommendations are advisory only.
 *      Apply path is added in a separate Phase 2 module.
 * ─────────────────────────────────────────────────────────────────────
 */

// Priority levels: 1=Critical, 2=High, 3=Medium, 4=Informational
const CODE_META = {
  SETTING_CONFLICT:   { priority: 1, category: 'Resolve policy conflicts', effortMin: 15, impact: 'Eliminates unpredictable policy application across machines.' },
  WMI_MISSING:        { priority: 1, category: 'Fix broken WMI filters',   effortMin: 10, impact: 'GPO is silently not applying — restore intended behaviour.' },
  UNLINKED:           { priority: 2, category: 'Remove unlinked GPOs',     effortMin:  5, impact: 'Reduces AD clutter and replication overhead.' },
  EMPTY:              { priority: 2, category: 'Remove empty GPOs',        effortMin:  3, impact: 'Eliminates zero-value GPOs from the environment.' },
  LINK_DISABLED:      { priority: 2, category: 'Clean up disabled links',  effortMin:  5, impact: 'Reduces confusion from dormant links.' },
  STALE:              { priority: 3, category: 'Review stale GPOs',        effortMin: 10, impact: 'Confirms policies still reflect intent.' },
  ALL_DISABLED:       { priority: 3, category: 'Decide on fully-disabled GPOs', effortMin: 5, impact: 'Removes GPOs that apply nothing.' },
  DUPLICATE_SETTING:  { priority: 3, category: 'Consolidate duplicate settings', effortMin: 10, impact: 'Single source of truth per setting.' },
  ENFORCED_OVERRIDE:  { priority: 3, category: 'Audit Enforced links',     effortMin:  8, impact: 'Confirms each Enforced flag is still warranted.' },
  SETTING_OVERLAP:    { priority: 4, category: 'Review setting overlap',   effortMin:  5, impact: 'Housekeeping — informational.' },
  WMI_DUPLICATE:      { priority: 4, category: 'Consolidate WMI filters',  effortMin: 10, impact: 'Simplifies filter management.' }
};

// ── Command block helper ──────────────────────────────────────────────
function cmd(text, lang = 'powershell') {
  return { lang, text };
}

// ── Pretty GPMC path (turn parser's category_path into human form) ────
// Parser stores e.g. "Windows Components/Data Collection and Preview Builds"
// or "Security/Account" — we normalize separators and prefix scope.
function prettyGpmcPath(scope, settingType, categoryPath, settingName) {
  if (!categoryPath) return settingName || '';
  const scopeLabel = scope === 'computer' ? 'Computer Configuration' : 'User Configuration';
  let mid = '';
  if (settingType === 'admin_template')   mid = 'Policies\\Administrative Templates';
  else if (settingType === 'security')    mid = 'Policies\\Windows Settings\\Security Settings';
  else if (settingType === 'pref_registry') mid = 'Preferences\\Windows Settings\\Registry';
  else if (settingType === 'pref_other')  mid = 'Preferences';
  const tail = String(categoryPath).replace(/\//g, '\\');
  const fullPath = [scopeLabel, mid, tail].filter(Boolean).join('\\');
  return settingName ? `${fullPath}\\${settingName}` : fullPath;
}

// ── Standard GPMC navigation steps for editing a GPO at a setting ─────
function gpmcStepsForSetting(gpoName, scope, settingType, categoryPath, settingName) {
  const scopeLabel = scope === 'computer' ? 'Computer Configuration' : 'User Configuration';
  const steps = [
    'Open Group Policy Management Console (GPMC) — gpmc.msc on a DC or RSAT-equipped workstation.',
    'Forest → Domains → nrpi.local → Group Policy Objects.',
    `Right-click "${gpoName}" → Edit. The Group Policy Management Editor opens.`,
    `Navigate: ${scopeLabel} → ${settingType === 'admin_template' ? 'Policies → Administrative Templates' : settingType === 'security' ? 'Policies → Windows Settings → Security Settings' : 'Preferences'} → ${categoryPath || '(see policy path above)'}.`,
    `Locate "${settingName}" → double-click → set to Not configured (or the agreed canonical value).`,
    'OK to save, then close the editor.',
    'On a representative client: gpupdate /force, then gpresult /h C:\\Temp\\out.html to verify the change took effect.'
  ];
  return { console: 'Group Policy Management Console (gpmc.msc)', steps };
}

// ── Standard GPMC navigation steps for managing a GPO itself ──────────
function gpmcStepsForGpo(gpoName, action) {
  const base = [
    'Open Group Policy Management Console (GPMC) — gpmc.msc on a DC or RSAT-equipped workstation.',
    'Forest → Domains → nrpi.local → Group Policy Objects.'
  ];
  switch (action) {
    case 'remove':
      return { console: 'GPMC', steps: [...base, `Right-click "${gpoName}" → Back Up… (save to C:\\GPOBackups).`, `Right-click "${gpoName}" → Delete → Yes.`] };
    case 'manage_links':
      return { console: 'GPMC', steps: [...base, `Right-click "${gpoName}" → Scope tab shows linked OUs.`, 'Right-click each link in the OU tree → Link Enabled (toggle) or Delete Link.'] };
    case 'set_status':
      return { console: 'GPMC', steps: [...base, `Right-click "${gpoName}" → GPO Status → choose: All Settings Enabled / User Settings Disabled / Computer Settings Disabled / All Settings Disabled.`] };
    case 'manage_wmi':
      return { console: 'GPMC', steps: [...base, `Right-click "${gpoName}" → Scope tab → WMI Filtering section → click the dropdown to clear or change filter.`, 'Filters themselves are managed under Forest → Domains → nrpi.local → WMI Filters.'] };
    case 'manage_enforced':
      return { console: 'GPMC', steps: [...base, `Find each OU/domain link of "${gpoName}" in the tree.`, 'Right-click the link → Enforced (toggle off if no longer needed).'] };
    default:
      return { console: 'GPMC', steps: base };
  }
}

// ── Build setting block + affectedGPOs from settingsByKey lookup ──────
function buildSettingBlock(finding, settingsByKey) {
  if (!finding.setting_key || !settingsByKey) return { setting: null, affectedGPOs: null };
  const occurrences = settingsByKey[finding.setting_key];
  if (!Array.isArray(occurrences) || occurrences.length === 0) return { setting: null, affectedGPOs: null };
  const first = occurrences[0];
  return {
    setting: {
      policyPath: prettyGpmcPath(first.scope, first.setting_type, first.category_path, first.setting_name),
      settingName: first.setting_name,
      scope: first.scope,
      settingType: first.setting_type,
      rawCategoryPath: first.category_path,
      settingKey: finding.setting_key
    },
    affectedGPOs: occurrences.map(o => ({
      name: o.gpo_name || '(unknown)',
      guid: o.gpo_guid,
      currentState: o.setting_state || '',
      currentValue: o.setting_value || ''
    }))
  };
}

// ── Per-code recommendation builders ──────────────────────────────────
const BUILDERS = {

  UNLINKED: ({ gpo }) => ({
    title: `Delete unlinked GPO: ${gpo.name}`,
    summary: `This GPO is not linked to any site, domain, or OU. It applies to nothing and is a candidate for removal.`,
    whyItMatters: 'Unlinked GPOs accumulate in AD over time. They consume SYSVOL replication bandwidth, slow GPMC, and create cognitive load when troubleshooting policy. Removing them after backup is a clean, reversible operation.',
    whereToFix: { gpmc: gpmcStepsForGpo(gpo.name, 'remove'), intune: null },
    investigation: [
      cmd(`Get-GPO -Name "${gpo.name}" | Select-Object DisplayName, Owner, CreationTime, ModificationTime, User, Computer`),
      `Check GPMC audit history for who last modified this GPO and when it was last linked.`,
      `Review the GPO in GPMC for any settings worth preserving before removal.`
    ],
    backup: [ cmd(`Backup-GPO -Name "${gpo.name}" -Path "C:\\GPOBackups" -Comment "Unlinked cleanup — pre-delete backup"`) ],
    action: [
      cmd(`# DRY RUN — shows what would be removed`),
      cmd(`Remove-GPO -Name "${gpo.name}" -WhatIf`),
      cmd(`# Remove -WhatIf once satisfied to execute:`),
      cmd(`Remove-GPO -Name "${gpo.name}"`)
    ],
    risk: 'Low',
    riskDetail: 'The GPO applies nothing today, so removing it has no policy impact. The backup preserves recovery capability.',
    saferAlternative: 'Move the GPO to a "Staging for Deletion" OU or add "[ARCHIVED]" to the name and leave it for 30–90 days before removing.',
    applyable: true,
    applyAction: 'remove_gpo'
  }),

  ALL_DISABLED: ({ gpo }) => ({
    title: `Resolve fully-disabled GPO: ${gpo.name}`,
    summary: `Both User and Computer configuration sections are disabled. Even where linked, this GPO will not apply anything.`,
    whyItMatters: 'A GPO with both sections disabled is dead weight — it shows up everywhere a GPMC operator looks but does nothing. Decide whether to re-enable the section you actually need or remove the GPO entirely.',
    whereToFix: { gpmc: gpmcStepsForGpo(gpo.name, 'set_status'), intune: null },
    investigation: [
      cmd(`Get-GPO -Name "${gpo.name}" | Select-Object DisplayName, GpoStatus, User, Computer`),
      `If it was disabled as a temporary measure, check if the business reason still applies.`,
      `If intended to be fully disabled permanently, consider removing the GPO entirely.`
    ],
    backup: [ cmd(`Backup-GPO -Name "${gpo.name}" -Path "C:\\GPOBackups" -Comment "Fully-disabled GPO — pre-change backup"`) ],
    action: [
      cmd(`# Option A — re-enable the section you actually need:`),
      cmd(`(Get-GPO -Name "${gpo.name}").GpoStatus = "UserSettingsEnabled"   # or "ComputerSettingsEnabled" or "AllSettingsEnabled"`),
      cmd(``),
      cmd(`# Option B — remove the GPO entirely (dry run):`),
      cmd(`Remove-GPO -Name "${gpo.name}" -WhatIf`)
    ],
    risk: 'Low',
    riskDetail: 'GPO currently applies nothing, so neither option has immediate operational impact.',
    saferAlternative: 'Leave disabled and add a comment explaining why via Set-GPO -Name "..." -Description "..."',
    applyable: true,
    applyAction: 'set_status'
  }),

  EMPTY: ({ gpo }) => ({
    title: `Remove empty GPO: ${gpo.name}`,
    summary: `This GPO contains no settings. It may be a forgotten placeholder or a pre-created skeleton.`,
    whyItMatters: 'Empty GPOs are a frequent source of "why is this here?" tickets. Like unlinked GPOs they cost SYSVOL replication and clutter, while delivering zero policy value. Safe to remove after backup.',
    whereToFix: { gpmc: gpmcStepsForGpo(gpo.name, 'remove'), intune: null },
    investigation: [
      `Open GPMC → locate the GPO → verify both Computer and User configuration trees are empty.`,
      cmd(`Get-GPO -Name "${gpo.name}" | Select-Object DisplayName, Description, CreationTime`),
      `Check the Description field for any note indicating it's a planned or placeholder GPO.`
    ],
    backup: [ cmd(`Backup-GPO -Name "${gpo.name}" -Path "C:\\GPOBackups" -Comment "Empty GPO — pre-delete backup"`) ],
    action: [
      cmd(`Remove-GPO -Name "${gpo.name}" -WhatIf`),
      cmd(`# Remove -WhatIf once confirmed safe:`),
      cmd(`Remove-GPO -Name "${gpo.name}"`)
    ],
    risk: 'Low',
    riskDetail: 'No settings present, so no policies are lost on removal.',
    saferAlternative: 'Rename with "[EMPTY - review]" prefix and revisit in 30 days.',
    applyable: true,
    applyAction: 'remove_gpo'
  }),

  STALE: ({ gpo }) => ({
    title: `Review stale GPO: ${gpo.name}`,
    summary: `This GPO has not been modified in 2+ years. It may still be valuable, but long-untouched policies often contain assumptions no longer true.`,
    whyItMatters: 'Stale GPOs frequently encode obsolete security baselines, references to retired servers, or workarounds for fixed bugs. A 2-year+ untouched GPO may be the only thing standing between your environment and a clean baseline — or it may be enforcing a policy nobody remembers.',
    whereToFix: { gpmc: gpmcStepsForGpo(gpo.name, 'remove'), intune: null },
    investigation: [
      cmd(`Get-GPO -Name "${gpo.name}" | Select-Object DisplayName, ModificationTime, User, Computer`),
      cmd(`Get-GPOReport -Name "${gpo.name}" -ReportType Html -Path "C:\\GPOReports\\${gpo.name.replace(/[^a-zA-Z0-9]/g, '_')}.html"`),
      `Compare the HTML report against current security baselines and business intent.`,
      `Confirm linked OUs still contain objects the GPO was designed for.`
    ],
    backup: [ cmd(`Backup-GPO -Name "${gpo.name}" -Path "C:\\GPOBackups" -Comment "Stale review backup"`) ],
    action: [
      cmd(`# If still valid, document the review:`),
      cmd(`Set-GPO -Name "${gpo.name}" -Description "Reviewed $(Get-Date -Format yyyy-MM-dd) — still in use. Owner: <name>"`),
      cmd(``),
      cmd(`# If obsolete, back up then remove:`),
      cmd(`Remove-GPO -Name "${gpo.name}" -WhatIf`)
    ],
    risk: 'Medium',
    riskDetail: 'The GPO may still actively apply policies to production users/computers. Always review settings and linked OUs before removing.',
    saferAlternative: 'Disable the user or computer section temporarily as a canary — if nobody complains in 2 weeks, the GPO is likely safe to remove.',
    applyable: false,
    applyAction: null
  }),

  LINK_DISABLED: ({ gpo }) => ({
    title: `Clean up disabled links: ${gpo.name}`,
    summary: `This GPO is linked to one or more OUs, but every link is disabled. The GPO does not apply anywhere.`,
    whyItMatters: 'Disabled links are usually the residue of a temporary change (testing, freeze, planned migration) that nobody cleaned up. They confuse anyone troubleshooting policy because the GPO appears "linked" in reports while applying nothing.',
    whereToFix: { gpmc: gpmcStepsForGpo(gpo.name, 'manage_links'), intune: null },
    investigation: [
      cmd(`Get-GPO -Name "${gpo.name}" | Select-Object DisplayName`),
      `Open GPMC → find each linked OU → review whether the link was disabled intentionally (e.g., testing freeze) or forgotten.`,
      `If the disabled links were a temporary measure, decide whether to re-enable or unlink.`
    ],
    backup: [ cmd(`Backup-GPO -Name "${gpo.name}" -Path "C:\\GPOBackups"`) ],
    action: [
      cmd(`# Option A — re-enable a link (replace OU DN):`),
      cmd(`Set-GPLink -Name "${gpo.name}" -Target "OU=TargetOU,DC=example,DC=local" -LinkEnabled Yes`),
      cmd(``),
      cmd(`# Option B — remove the link entirely (dry run first):`),
      cmd(`Remove-GPLink -Name "${gpo.name}" -Target "OU=TargetOU,DC=example,DC=local" -WhatIf`)
    ],
    risk: 'Low',
    riskDetail: 'Since no links are currently active, unlinking changes nothing operationally.',
    saferAlternative: 'Leave disabled links in place as historical markers. Only clean up if administrative clutter is a concern.',
    applyable: true,
    applyAction: 'remove_link'
  }),

  WMI_MISSING: ({ gpo }) => ({
    title: `CRITICAL: ${gpo.name} references missing WMI filter "${gpo.wmi_filter_name || '(unknown)'}"`,
    summary: `This GPO references a WMI filter that no longer exists. A missing filter evaluates as FALSE, so the GPO silently does not apply. If the GPO was meant to apply, users are currently not receiving its policies.`,
    whyItMatters: 'Missing WMI filters are silent failures. Nothing in the event log on the target machine clearly indicates the GPO is being skipped — it just isn\'t there. If the GPO is enforcing security policies (firewall, BitLocker, AppLocker), those policies are inactive on every targeted machine right now.',
    whereToFix: { gpmc: gpmcStepsForGpo(gpo.name, 'manage_wmi'), intune: null },
    investigation: [
      cmd(`Get-GPO -Name "${gpo.name}" | Select-Object DisplayName, WmiFilter`),
      `Check GPMC → WMI Filters node → confirm "${gpo.wmi_filter_name || '(unknown)'}" is actually missing vs. renamed.`,
      `Review the GPO's original intent — was it meant to apply to all linked OUs, or only to a subset matching the filter?`,
      `Check AD replication health — a filter that exists on one DC but not another can cause this false alarm.`
    ],
    backup: [ cmd(`Backup-GPO -Name "${gpo.name}" -Path "C:\\GPOBackups" -Comment "Pre WMI fix"`) ],
    action: [
      cmd(`# Option A — clear the reference (GPO applies to all linked objects):`),
      cmd(`Set-GPO -Name "${gpo.name}" -WmiFilter $null`),
      cmd(``),
      cmd(`# Option B — recreate the WMI filter with the original query.`),
      cmd(`#   Do this in GPMC (Group Policy Management → WMI Filters → New)`),
      cmd(`#   Then re-attach via GPMC → ${gpo.name} → Scope tab → WMI Filtering dropdown.`)
    ],
    risk: 'High',
    riskDetail: 'Clearing the WMI filter will cause the GPO to apply to EVERY object in its linked OUs. If the filter was restricting to (say) Windows 10 only, removing it will apply the GPO to servers too.',
    saferAlternative: 'Recreate the WMI filter before changing GPO assignment. Only clear the reference after confirming all linked objects should receive the policy.',
    applyable: true,
    applyAction: 'clear_wmi'
  }),

  SETTING_OVERLAP: ({ finding, settingBlock }) => ({
    title: `Review setting overlap: ${(settingBlock.setting && settingBlock.setting.settingName) || finding.title.replace(/^Setting "/, '').replace(/" touched.*/, '')}`,
    summary: `Multiple GPOs define the same setting with the same value. Not harmful, but a single source of truth is cleaner.`,
    whyItMatters: 'Same value in multiple GPOs is harmless today but tomorrow\'s problem: when somebody changes one of the copies, the policy becomes a conflict. Designating one canonical owner prevents this drift.',
    whereToFix: { gpmc: settingBlock.setting ? gpmcStepsForSetting('<each non-canonical GPO>', settingBlock.setting.scope, settingBlock.setting.settingType, settingBlock.setting.rawCategoryPath, settingBlock.setting.settingName) : { console: 'GPMC', steps: ['Open GPMC and edit each non-canonical GPO to set this setting to Not configured.'] }, intune: null },
    investigation: [
      `${finding.detail || ''}`,
      `Decide which GPO is the canonical owner of this setting (usually the one with the broadest appropriate scope, like domain-level baseline).`
    ],
    backup: [ cmd(`# Back up every GPO involved before editing:`), cmd(`Backup-GPO -All -Path "C:\\GPOBackups" -Comment "Pre setting-overlap cleanup"`) ],
    action: [
      `Open GPMC → edit each non-canonical GPO → locate the duplicate setting → right-click → "Not configured" or delete.`,
      `Leave the setting defined only in the canonical (owning) GPO.`
    ],
    risk: 'Low',
    riskDetail: 'Same value everywhere, so consolidation changes nothing about effective policy.',
    saferAlternative: 'Add a comment on each GPO indicating which one owns the setting, rather than consolidating.',
    applyable: false,
    applyAction: null
  }),

  SETTING_CONFLICT: ({ finding, settingBlock }) => ({
    title: `CRITICAL: conflicting values — ${(settingBlock.setting && settingBlock.setting.settingName) || finding.title.replace(/^Conflicting values for "/, '').replace(/" across.*/, '')}`,
    summary: `Two or more GPOs set the same policy to different values. The effective value depends on LSDOU processing order + link order + Enforced flags. This leads to unpredictable configuration across machines.`,
    whyItMatters: 'Conflicting GPO settings are the #1 cause of "works on my machine but not theirs" policy support tickets. Two users in different OUs can see different values for the exact same policy. Until you pick a canonical owner and make every other GPO say "Not configured", the effective value drifts every time link order changes.',
    whereToFix: { gpmc: settingBlock.setting ? gpmcStepsForSetting('<each non-canonical GPO>', settingBlock.setting.scope, settingBlock.setting.settingType, settingBlock.setting.rawCategoryPath, settingBlock.setting.settingName) : { console: 'GPMC', steps: ['Open GPMC and edit non-canonical GPOs to clear this setting.'] }, intune: null },
    investigation: [
      `${finding.detail || ''}`,
      cmd(`# On an affected user's workstation, run as that user:`),
      cmd(`gpresult /h C:\\Temp\\gpresult.html`),
      cmd(`# Opens a report showing which GPO actually "won" each setting for this user.`),
      `Compare findings across multiple users in different OUs — the winner may differ.`,
      `Decide: do you want ONE GPO to own this setting, or different values for different scopes (OU-specific overrides)?`
    ],
    backup: [ cmd(`Backup-GPO -All -Path "C:\\GPOBackups" -Comment "Pre setting-conflict resolution"`) ],
    action: [
      `Strategy 1 (recommended): Pick one canonical GPO. Edit all others in GPMC and set the conflicting setting to "Not configured".`,
      `Strategy 2: Adjust link order if conflicts are scope-intentional.`,
      cmd(`Set-GPLink -Name "<winning-GPO>" -Target "OU=...,DC=..." -Order 1`),
      `Strategy 3: Use Enforced on the authoritative GPO — ONLY if you intend to override Block Inheritance below it.`,
      cmd(`Set-GPLink -Name "<authoritative-GPO>" -Target "OU=...,DC=..." -Enforced Yes`)
    ],
    risk: 'High',
    riskDetail: 'Changing a conflicting setting in the wrong direction can tighten or loosen security posture unintentionally. Use gpresult to confirm current effective state before acting.',
    saferAlternative: 'Document the conflict and the intended winner in each GPO\'s Description field. Schedule a formal consolidation during a change window.',
    applyable: false,
    applyAction: null
  }),

  DUPLICATE_SETTING: ({ finding, settingBlock }) => ({
    title: `Consolidate duplicate setting${settingBlock.setting ? ': ' + settingBlock.setting.settingName : ''}`,
    summary: finding.detail || `Multiple GPOs define the same setting with identical values.`,
    whyItMatters: 'Like SETTING_OVERLAP, identical duplicates are stable today but invite drift. Consolidating to a single owning GPO simplifies future changes — touch one place, not three.',
    whereToFix: { gpmc: settingBlock.setting ? gpmcStepsForSetting('<each duplicate GPO>', settingBlock.setting.scope, settingBlock.setting.settingType, settingBlock.setting.rawCategoryPath, settingBlock.setting.settingName) : { console: 'GPMC', steps: ['Open GPMC and edit each non-canonical GPO to clear the duplicate setting.'] }, intune: null },
    investigation: [
      `Confirm the GPOs are linked to overlapping scopes (same OUs or parent/child OUs).`,
      `If they're linked to completely different OU subtrees, the duplication may be intentional (defense in depth).`
    ],
    backup: [ cmd(`Backup-GPO -All -Path "C:\\GPOBackups" -Comment "Pre duplicate-setting consolidation"`) ],
    action: [
      `Keep the setting in the most specific (deepest scope) GPO that needs it.`,
      `Remove it from the broader-scoped GPOs by editing in GPMC → "Not configured".`
    ],
    risk: 'Low',
    riskDetail: 'Identical values — no change in effective policy.',
    saferAlternative: 'Leave as-is unless you\'re actively simplifying your GPO footprint.',
    applyable: false,
    applyAction: null
  }),

  ENFORCED_OVERRIDE: ({ finding, gpo }) => ({
    title: `Audit Enforced flag: ${gpo.name}`,
    summary: `This GPO has Enforced=true on one or more links. Enforced GPOs bypass Block Inheritance on child OUs, which can be legitimate (security baselines) or accidental (copy-paste).`,
    whyItMatters: 'Enforced is the GP equivalent of "ignore everything else and apply this." It\'s appropriate for top-down security baselines you genuinely want to override OU-level Block Inheritance. It\'s a problem when someone enabled it years ago, doesn\'t remember why, and now it overrides legitimate exceptions.',
    whereToFix: { gpmc: gpmcStepsForGpo(gpo.name, 'manage_enforced'), intune: null },
    investigation: [
      `${finding.detail || ''}`,
      cmd(`Get-GPInheritance -Target "<OU DN>"  # for each linked OU, review the GpoLinks collection`),
      `Confirm the Enforced flag is intentional and documented.`,
      `Check if any child OUs have "Block Inheritance" set — if yes, Enforced is actively overriding them.`
    ],
    backup: [ cmd(`Backup-GPO -Name "${gpo.name}" -Path "C:\\GPOBackups"`) ],
    action: [
      cmd(`# If Enforced is no longer needed, remove it (replace target OU):`),
      cmd(`Set-GPLink -Name "${gpo.name}" -Target "OU=...,DC=..." -Enforced No`),
      cmd(``),
      cmd(`# If Enforced is intentional, document the reason:`),
      cmd(`Set-GPO -Name "${gpo.name}" -Description "Enforced by design: <reason>. Reviewed $(Get-Date -Format yyyy-MM-dd)."`)
    ],
    risk: 'Medium',
    riskDetail: 'Removing Enforced can allow child OUs with Block Inheritance to stop receiving this GPO. Verify no downstream OU is relying on the override.',
    saferAlternative: 'Document the reason for Enforced in the GPO Description instead of changing the flag.',
    applyable: false,
    applyAction: null
  }),

  WMI_DUPLICATE: ({ finding }) => ({
    title: `Consolidate duplicate WMI filters`,
    summary: finding.detail || `Multiple WMI filters have identical queries.`,
    whyItMatters: 'Duplicate WMI filters with identical queries do the same job under different names. Consolidating to one canonical filter reduces filter-management overhead and removes a category of "is this the right filter?" mistakes.',
    whereToFix: { gpmc: { console: 'GPMC', steps: [
      'Open GPMC. Navigate to Forest → Domains → nrpi.local → WMI Filters.',
      'Identify which duplicate is the canonical one (clearest name, best description, longest history).',
      'For every GPO using a non-canonical duplicate, right-click the GPO → Scope tab → WMI Filtering dropdown → select the canonical filter.',
      'Once no GPO references the duplicates, right-click each → Delete.'
    ] }, intune: null },
    investigation: [
      `GPMC → WMI Filters → review each filter mentioned in the finding for differences in name/description.`,
      `List all GPOs using each duplicate filter — each must be reassigned to the single canonical filter before deleting the others.`
    ],
    backup: [ cmd(`# No backup of WMI filters needed — they're recreatable. But back up affected GPOs:`), cmd(`Backup-GPO -All -Path "C:\\GPOBackups" -Comment "Pre WMI filter consolidation"`) ],
    action: [
      `In GPMC, pick one filter as canonical.`,
      `For every GPO using a non-canonical duplicate, right-click the GPO → WMI Filter → select the canonical one.`,
      `Delete the now-orphaned duplicate filters in GPMC.`
    ],
    risk: 'Low',
    riskDetail: 'Identical queries mean effective filtering doesn\'t change.',
    saferAlternative: 'Leave duplicates in place and add notes to each filter\'s description explaining the intent.',
    applyable: false,
    applyAction: null
  })
};

// ── Public API ────────────────────────────────────────────────────────
function buildRecommendations(findings, inventoryByGuid, settingsByKey) {
  const perFinding = [];
  const byCode = {};

  // Defensive default — older callers pass only two args
  const _settingsByKey = settingsByKey || {};

  for (const f of findings) {
    byCode[f.code] = (byCode[f.code] || 0) + 1;
    const builder = BUILDERS[f.code];
    if (!builder) continue;
    const gpo = inventoryByGuid[f.gpo_guid] || { name: '(no GPO)', guid: null, wmi_filter_name: null };
    const settingBlock = buildSettingBlock(f, _settingsByKey);
    try {
      const rec = builder({ finding: f, gpo, settingBlock });
      const meta = CODE_META[f.code] || { priority: 5 };
      perFinding.push({
        finding_id: f.id,
        gpo_guid: f.gpo_guid,
        gpo_name: gpo.name,
        code: f.code,
        severity: f.severity,
        priority: meta.priority,
        // setting + affectedGPOs are merged from settingBlock; rec may pass them through too
        setting: settingBlock.setting,
        affectedGPOs: settingBlock.affectedGPOs,
        ...rec
      });
    } catch (e) {
      console.error('[gpo-recommendations] builder failed for', f.code, e.message);
    }
  }

  // Sort: priority ASC, then severity (critical > warn > info), then GPO name
  const sevRank = { critical: 0, warn: 1, info: 2 };
  perFinding.sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    const as = sevRank[a.severity] ?? 3, bs = sevRank[b.severity] ?? 3;
    if (as !== bs) return as - bs;
    return (a.gpo_name || '').localeCompare(b.gpo_name || '');
  });

  // Aggregate: group codes into priority categories
  const aggMap = {};
  for (const [code, count] of Object.entries(byCode)) {
    const meta = CODE_META[code];
    if (!meta) continue;
    if (!aggMap[meta.category]) {
      aggMap[meta.category] = { category: meta.category, priority: meta.priority, count: 0, effortMin: 0, impact: meta.impact, codes: [] };
    }
    aggMap[meta.category].count += count;
    aggMap[meta.category].effortMin += count * meta.effortMin;
    aggMap[meta.category].codes.push(code);
  }
  const aggregate = Object.values(aggMap).sort((a, b) => a.priority - b.priority || b.count - a.count);

  return {
    aggregate,
    perFinding,
    summary: {
      total_findings: findings.length,
      total_recommendations: perFinding.length,
      by_priority: {
        1: perFinding.filter(r => r.priority === 1).length,
        2: perFinding.filter(r => r.priority === 2).length,
        3: perFinding.filter(r => r.priority === 3).length,
        4: perFinding.filter(r => r.priority === 4).length
      }
    }
  };
}

module.exports = { buildRecommendations };
