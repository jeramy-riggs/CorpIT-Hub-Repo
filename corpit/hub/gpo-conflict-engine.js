'use strict';
/**
 * gpo-conflict-engine.js
 * ─────────────────────────────────────────────────────────────────────
 * Cross-GPO analysis. Reads parsed GPOs + settings and produces findings.
 *
 * Finding codes:
 *   Per-GPO (single-GPO observations):
 *     UNLINKED          — GPO has zero links
 *     ALL_DISABLED      — both User and Computer sections disabled
 *     EMPTY             — no settings at all
 *     STALE             — not modified in 2+ years
 *     LINK_DISABLED     — GPO linked but every link is disabled
 *     WMI_MISSING       — GPO references a WMI filter name not found in the report
 *
 *   Cross-GPO (multi-GPO observations):
 *     SETTING_OVERLAP   — same setting defined in 2+ GPOs (info)
 *     SETTING_CONFLICT  — same setting, DIFFERENT values in 2+ GPOs (warn)
 *     DUPLICATE_SETTING — same setting, IDENTICAL values in 2+ GPOs (info)
 *     ENFORCED_OVERRIDE — GPO uses Enforced=true (warn — bypasses Block Inheritance)
 *     WMI_DUPLICATE     — two WMI filter names have identical queries (info)
 * ─────────────────────────────────────────────────────────────────────
 */

const STALE_YEARS = 2;

// Phase 1.6: OU-overlap helpers. Two GPOs "overlap in scope" if any pair of
// their enabled link paths share a tree relationship -- same path, or one is
// an ancestor of the other (case-insensitive). Disjoint paths mean the GPOs
// apply to non-overlapping computer populations, so disagreeing values are
// not actually a conflict.
function pathsOverlap(pathsA, pathsB) {
  for (const a of pathsA) {
    const aLow = (a || '').toLowerCase();
    if (!aLow) continue;
    for (const b of pathsB) {
      const bLow = (b || '').toLowerCase();
      if (!bLow) continue;
      if (aLow === bLow) return true;
      if (aLow.startsWith(bLow + '/') || bLow.startsWith(aLow + '/')) return true;
    }
  }
  return false;
}

function hasOverlappingDisagreement(occurrences) {
  const sigGroups = new Map();
  for (const o of occurrences) {
    const sig = `${o.state}::${o.value}`;
    if (!sigGroups.has(sig)) sigGroups.set(sig, []);
    sigGroups.get(sig).push(o);
  }
  const sigs = [...sigGroups.keys()];
  if (sigs.length < 2) return false;
  for (let i = 0; i < sigs.length; i++) {
    for (let j = i + 1; j < sigs.length; j++) {
      for (const oa of sigGroups.get(sigs[i])) {
        for (const ob of sigGroups.get(sigs[j])) {
          if (pathsOverlap(oa.link_paths || [], ob.link_paths || [])) return true;
        }
      }
    }
  }
  return false;
}

function analyze(parsed) {
  const { gpos, wmiFilters } = parsed;
  const findings = [];
  const now = new Date();

  // Build a quick name lookup for WMI filters
  const wmiByName = new Map();
  for (const w of wmiFilters) wmiByName.set(w.filter_name, w);

  // ═══ Per-GPO findings ═══
  for (const g of gpos) {
    // UNLINKED
    if (!g.links || g.links.length === 0) {
      findings.push({
        gpo_guid: g.guid,
        severity: 'warn',
        code: 'UNLINKED',
        title: `${g.name} is not linked anywhere`,
        detail: 'This GPO applies to nothing. Candidate for deletion or archival.',
        related_guids: null
      });
    } else {
      // LINK_DISABLED — every link disabled
      const anyEnabled = g.links.some(l => l.link_enabled);
      if (!anyEnabled) {
        findings.push({
          gpo_guid: g.guid,
          severity: 'warn',
          code: 'LINK_DISABLED',
          title: `${g.name} has links but all are disabled`,
          detail: `Links found: ${g.links.length}. None are currently enabled. Either enable a link or unlink.`,
          related_guids: null
        });
      }
      // ENFORCED_OVERRIDE — any link is enforced
      const enforcedLinks = g.links.filter(l => l.enforced);
      if (enforcedLinks.length > 0) {
        findings.push({
          gpo_guid: g.guid,
          severity: 'warn',
          code: 'ENFORCED_OVERRIDE',
          title: `${g.name} is Enforced on ${enforcedLinks.length} link(s)`,
          detail: `Enforced links bypass Block Inheritance. SOMs: ${enforcedLinks.map(l => l.som_path).join('; ')}`,
          related_guids: null
        });
      }
    }

    // ALL_DISABLED
    if (!g.user_enabled && !g.computer_enabled) {
      findings.push({
        gpo_guid: g.guid,
        severity: 'warn',
        code: 'ALL_DISABLED',
        title: `${g.name} has both User and Computer sections disabled`,
        detail: 'This GPO will not apply anything even where linked. Candidate for cleanup.',
        related_guids: null
      });
    }

    // EMPTY
    if (!g.has_settings) {
      findings.push({
        gpo_guid: g.guid,
        severity: 'info',
        code: 'EMPTY',
        title: `${g.name} contains no settings`,
        detail: 'No Administrative Template, Security, or Preferences settings detected. May be a placeholder.',
        related_guids: null
      });
    }

    // STALE
    if (g.modified_time) {
      const mod = new Date(g.modified_time);
      if (!isNaN(mod.getTime())) {
        const yearsOld = (now - mod) / (1000 * 60 * 60 * 24 * 365.25);
        if (yearsOld >= STALE_YEARS) {
          findings.push({
            gpo_guid: g.guid,
            severity: 'info',
            code: 'STALE',
            title: `${g.name} has not been modified in ${yearsOld.toFixed(1)} years`,
            detail: `Last modified: ${g.modified_time}. Review whether its settings are still relevant.`,
            related_guids: null
          });
        }
      }
    }

    // WMI_MISSING
    if (g.wmi_filter_name && !wmiByName.has(g.wmi_filter_name)) {
      findings.push({
        gpo_guid: g.guid,
        severity: 'warn',
        code: 'WMI_MISSING',
        title: `${g.name} references WMI filter "${g.wmi_filter_name}" which was not found`,
        detail: 'The referenced WMI filter is not present in the report. It may have been deleted without updating the GPO, which means the filter evaluates as false and the GPO silently stops applying.',
        related_guids: null
      });
    }
  }

  // ═══ Cross-GPO: setting overlap / conflict / duplicate ═══
  // Group all settings by setting_key
  const byKey = new Map();  // setting_key -> [{guid, name, value, state}, ...]
  for (const g of gpos) {
    if (!g.settings) continue;
    // Phase 1.5: capture whether this GPO actually applies to anything.
    const isActive = !!(g.links && g.links.some(l => l.link_enabled));
    const linkPaths = (g.links || []).filter(l => l.link_enabled).map(l => l.som_path || l.som_name || '');
    for (const s of g.settings) {
      if (!byKey.has(s.setting_key)) byKey.set(s.setting_key, []);
      byKey.get(s.setting_key).push({
        guid: g.guid,
        gpo_name: g.name,
        value: s.setting_value || '',
        state: s.setting_state || '',
        setting_name: s.setting_name,
        scope: s.scope,
        type: s.setting_type,
        is_active: isActive,
        link_paths: linkPaths
      });
    }
  }

  for (const [key, allOccurrences] of byKey.entries()) {
    // Phase 1.5: only consider GPOs with at least one enabled link.
    const occurrences = allOccurrences.filter(o => o.is_active);
    if (occurrences.length < 2) continue;  // single-GPO — nothing cross-cutting

    // Skip pref_other noise — we only flagged "present" so overlap isn't meaningful
    if (occurrences[0].type === 'pref_other') continue;

    // Build a signature per occurrence: state + value
    const sigs = occurrences.map(o => `${o.state}::${o.value}`);
    const uniqueSigs = new Set(sigs);
    const gpoNames = occurrences.map(o => o.gpo_name);
    const gpoGuids = occurrences.map(o => o.guid);
    const firstOccurrence = occurrences[0];

    if (uniqueSigs.size === 1) {
      // All identical — DUPLICATE_SETTING
      findings.push({
        gpo_guid: firstOccurrence.guid,
        severity: 'info',
        code: 'DUPLICATE_SETTING',
        setting_key: key,
        title: `Duplicate setting "${firstOccurrence.setting_name}" in ${occurrences.length} GPOs`,
        detail: `The ${firstOccurrence.scope} setting "${firstOccurrence.setting_name}" is defined identically in: ${gpoNames.join(' | ')}. Consider consolidating.`,
        related_guids: JSON.stringify(gpoGuids)
      });
    } else {
      // Different values — SETTING_CONFLICT + SETTING_OVERLAP
      // Phase 1.6: only emit conflict findings if disagreeing GPOs share OU scope.
      // Disjoint-OU disagreement is an intentional defense-in-depth split, not a real conflict.
      if (!hasOverlappingDisagreement(occurrences)) continue;
      findings.push({
        gpo_guid: firstOccurrence.guid,
        severity: 'warn',
        code: 'SETTING_CONFLICT',
        setting_key: key,
        title: `Conflicting values for "${firstOccurrence.setting_name}" across ${occurrences.length} GPOs`,
        detail: `The ${firstOccurrence.scope} setting "${firstOccurrence.setting_name}" has different values across: ${occurrences.map(o => `[${o.gpo_name}] state=${o.state} value=${(o.value || '').slice(0, 80)}`).join(' || ')}. The winner depends on processing order (LSDOU + link order + Enforced).`,
        related_guids: JSON.stringify(gpoGuids)
      });
      // Also emit SETTING_OVERLAP as a lower-priority informational finding
      findings.push({
        gpo_guid: firstOccurrence.guid,
        severity: 'info',
        code: 'SETTING_OVERLAP',
        setting_key: key,
        title: `Setting "${firstOccurrence.setting_name}" touched by ${occurrences.length} GPOs`,
        detail: `${gpoNames.join(' | ')}`,
        related_guids: JSON.stringify(gpoGuids)
      });
    }
  }

  // ═══ WMI filter duplicates ═══
  const byQuery = new Map();
  for (const w of wmiFilters) {
    const q = (w.query || '').replace(/\s+/g, ' ').trim();
    if (!q) continue;
    if (!byQuery.has(q)) byQuery.set(q, []);
    byQuery.get(q).push(w.filter_name);
  }
  for (const [q, names] of byQuery.entries()) {
    if (names.length > 1) {
      findings.push({
        gpo_guid: null,
        severity: 'info',
        code: 'WMI_DUPLICATE',
        title: `Duplicate WMI filter query used by ${names.length} filter names`,
        detail: `Filters with identical query: ${names.join(' | ')}. Candidate for consolidation. Query: ${q.slice(0, 200)}`,
        related_guids: null
      });
    }
  }

  return findings;
}

module.exports = { analyze };
