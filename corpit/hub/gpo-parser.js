'use strict';
/**
 * gpo-parser.js
 * ─────────────────────────────────────────────────────────────────────
 * Parses the XML output of `Get-GPOReport -All -ReportType Xml` into a
 * normalized structure suitable for storage and cross-GPO analysis.
 *
 * Handles:
 *   - GPO metadata (name, GUID, created/modified, enabled sections)
 *   - OU / domain / site links
 *   - WMI filter references
 *   - Security filtering (trustees with Apply)
 *   - Administrative Template policies (registry.pol)
 *   - Security Settings (account, password, audit, user rights)
 *   - Group Policy Preferences Registry
 *   - Non-registry Preferences (flagged as "present" only — not deep-compared)
 *
 * Security note: XXE prevention is enforced by the caller disabling DTD
 * and entity expansion in fast-xml-parser options.
 * ─────────────────────────────────────────────────────────────────────
 */

const { XMLParser } = require('fast-xml-parser');

// ── Parser options — locked down against XXE, namespace-stripped ──────
const PARSER_OPTIONS = {
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  allowBooleanAttributes: true,
  parseTagValue: false,          // keep raw strings, we convert explicitly
  parseAttributeValue: false,
  trimValues: true,
  removeNSPrefix: true,          // strips q1:, q2: etc. — critical for sane traversal
  processEntities: false,        // disable entity expansion (XXE defense)
  stopNodes: [],
  isArray: () => false           // we handle array coercion manually
};

// ── Helpers ───────────────────────────────────────────────────────────
function arr(x) {
  if (x === undefined || x === null) return [];
  return Array.isArray(x) ? x : [x];
}

function bool(x) {
  if (x === true || x === 'true' || x === '1' || x === 1) return true;
  return false;
}

function str(x) {
  if (x === undefined || x === null) return null;
  if (typeof x === 'object' && x['#text'] !== undefined) return String(x['#text']).trim();
  return String(x).trim();
}

function toDate(x) {
  const s = str(x);
  if (!s) return null;
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  // MySQL DATETIME format: YYYY-MM-DD HH:MM:SS
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

function safeStringify(x) {
  try {
    return JSON.stringify(x);
  } catch (e) {
    return String(x);
  }
}

// ── Main entry point ──────────────────────────────────────────────────
function parseGpoReport(xmlString) {
  if (typeof xmlString !== 'string' || xmlString.length === 0) {
    throw new Error('parseGpoReport: empty or non-string input');
  }
  // Strip BOM + leading whitespace
  const cleaned = xmlString.replace(/^\uFEFF/, '').replace(/^\s+/, '');
  if (!cleaned.startsWith('<?xml') && !cleaned.startsWith('<')) {
    throw new Error('parseGpoReport: input does not look like XML');
  }
  // Quick XXE pre-flight: reject if DOCTYPE with ENTITY is present
  if (/<!DOCTYPE[^>]*\bENTITY\b/i.test(cleaned)) {
    throw new Error('parseGpoReport: DOCTYPE with ENTITY declarations rejected (XXE defense)');
  }

  const parser = new XMLParser(PARSER_OPTIONS);
  const doc = parser.parse(cleaned);

  // Locate the GPO element(s). Get-GPOReport produces one of:
  //   <GPO>...</GPO>                              (single report, no wrapper)
  //   <report><GPO>...</GPO><GPO>...</GPO></report>   (some RSAT versions)
  //   <GPOs><GPO>...</GPO></GPOs>                     (rare)
  let gpoNodes;
  if (doc.GPO) {
    gpoNodes = arr(doc.GPO);
  } else if (doc.report && doc.report.GPO) {
    gpoNodes = arr(doc.report.GPO);
  } else if (doc.GPOs && doc.GPOs.GPO) {
    gpoNodes = arr(doc.GPOs.GPO);
  } else {
    // Final fallback — walk one level deep
    const firstKey = Object.keys(doc)[0];
    if (firstKey && doc[firstKey] && doc[firstKey].GPO) {
      gpoNodes = arr(doc[firstKey].GPO);
    } else {
      throw new Error('parseGpoReport: no <GPO> elements found. Confirm the XML was produced by Get-GPOReport -All -ReportType Xml.');
    }
  }

  const gpos = [];
  const wmiFilterMap = new Map();  // filter_name -> {query, description, used_by_count}
  const warnings = [];

  for (const gpoNode of gpoNodes) {
    try {
      gpos.push(parseOneGpo(gpoNode, wmiFilterMap));
    } catch (e) {
      warnings.push({
        gpo_name: str(gpoNode.Name) || '<unknown>',
        error: e.message
      });
    }
  }

  const wmiFilters = [];
  for (const [name, info] of wmiFilterMap.entries()) {
    wmiFilters.push({ filter_name: name, query: info.query, description: info.description, used_by_count: info.used_by_count });
  }

  return { gpos, wmiFilters, warnings };
}

// ── Parse a single <GPO> element ──────────────────────────────────────
function parseOneGpo(n, wmiFilterMap) {
  // Identifier is usually <Identifier><Identifier>{GUID}</Identifier><Domain>...</Domain></Identifier>
  let guid = null;
  let domain = null;
  if (n.Identifier) {
    guid = str(n.Identifier.Identifier) || str(n.Identifier);
    domain = str(n.Identifier.Domain);
  }
  if (!guid) {
    throw new Error('GPO node missing Identifier/guid');
  }
  // Normalize GUID (strip braces)
  guid = guid.replace(/[{}]/g, '').toLowerCase();

  const name = str(n.Name) || '(unnamed)';

  // Enabled sections
  const userEnabled = bool(n.User && n.User.Enabled);
  const computerEnabled = bool(n.Computer && n.Computer.Enabled);

  // Version info
  const userVersionDir = parseInt(str(n.User && n.User.VersionDirectory)) || 0;
  const userVersionSysvol = parseInt(str(n.User && n.User.VersionSysvol)) || 0;
  const compVersionDir = parseInt(str(n.Computer && n.Computer.VersionDirectory)) || 0;
  const compVersionSysvol = parseInt(str(n.Computer && n.Computer.VersionSysvol)) || 0;

  // WMI filter
  let wmiFilterName = null;
  if (n.FilterName) {
    wmiFilterName = str(n.FilterName);
  } else if (n.WMIFilter) {
    wmiFilterName = str(n.WMIFilter.Name) || str(n.WMIFilter);
  }
  if (wmiFilterName) {
    const existing = wmiFilterMap.get(wmiFilterName) || {
      query: str(n.FilterQuery) || (n.WMIFilter && str(n.WMIFilter.Query)) || null,
      description: str(n.FilterDescription) || null,
      used_by_count: 0
    };
    existing.used_by_count += 1;
    wmiFilterMap.set(wmiFilterName, existing);
  }

  // Security trustees (who has Apply Group Policy)
  const trustees = [];
  const secDescriptor = n.SecurityDescriptor;
  if (secDescriptor && secDescriptor.Permissions) {
    const perms = arr(secDescriptor.Permissions.TrusteePermissions);
    for (const p of perms) {
      if (!p) continue;
      const trusteeName = str(p.Trustee && p.Trustee.Name) || str(p.Trustee && p.Trustee.SID);
      const standard = p.Standard && str(p.Standard.GPOGroupedAccessEnum);
      // "Apply Group Policy" shows up as "Read, Apply Group Policy" or similar
      if (trusteeName && standard && /Apply/i.test(standard)) {
        trustees.push(trusteeName);
      }
    }
  }

  // Links
  const links = [];
  const linksToArr = arr(n.LinksTo);
  for (const l of linksToArr) {
    if (!l) continue;
    links.push({
      som_name: str(l.SOMName) || '',
      som_path: str(l.SOMPath) || '',
      link_enabled: bool(l.Enabled),
      enforced: bool(l.NoOverride)
    });
  }

  // Settings — dive into Computer and User ExtensionData
  const settings = [];
  collectSettings(n.Computer, 'computer', settings);
  collectSettings(n.User, 'user', settings);

  const settingCountComputer = settings.filter(s => s.scope === 'computer').length;
  const settingCountUser = settings.filter(s => s.scope === 'user').length;
  const hasSettings = settings.length > 0;

  return {
    guid,
    name,
    domain,
    created_time: toDate(n.CreatedTime),
    modified_time: toDate(n.ModifiedTime),
    user_enabled: userEnabled,
    computer_enabled: computerEnabled,
    user_version_dir: userVersionDir,
    user_version_sysvol: userVersionSysvol,
    comp_version_dir: compVersionDir,
    comp_version_sysvol: compVersionSysvol,
    wmi_filter_name: wmiFilterName,
    security_trustees: trustees.join(', ') || null,
    setting_count_user: settingCountUser,
    setting_count_computer: settingCountComputer,
    has_settings: hasSettings,
    links,
    settings
  };
}

// ── Collect settings from a Computer or User node ─────────────────────
function collectSettings(node, scope, out) {
  if (!node || !node.ExtensionData) return;
  const extensions = arr(node.ExtensionData);
  for (const ext of extensions) {
    if (!ext || !ext.Extension) continue;
    const extNode = ext.Extension;
    const extType = str(ext.Name) || '';   // e.g., "Registry", "Security", "Folders"

    // ─ Administrative Template policies (most common) ──
    // Contains <Policy> elements with Name, State, Category, and value descriptions
    if (extNode.Policy) {
      for (const p of arr(extNode.Policy)) {
        if (!p) continue;
        const polName = str(p.Name);
        const polState = str(p.State) || 'Unknown';
        const category = str(p.Category);
        if (!polName) continue;
        // Canonical key: scope + category + name (stable across GPOs)
        const key = `AdminTemplate|${scope}|${category || ''}|${polName}`;
        // Value snapshot: JSON of sub-settings (DropDownList, EditText, Numeric, CheckBox)
        const valueSnapshot = extractPolicyValue(p);
        out.push({
          scope,
          setting_type: 'admin_template',
          setting_key: key,
          setting_name: polName,
          setting_state: polState,
          setting_value: valueSnapshot,
          category_path: category || null
        });
      }
    }

    // ─ Security Settings ───────────────────────────────
    // Shapes vary: Account, Audit, EventAudit, UserRightsAssignment, SystemAccess, etc.
    for (const secKey of ['Account', 'Audit', 'EventAudit', 'UserRightsAssignment', 'SystemAccess', 'RegistryValue']) {
      if (extNode[secKey]) {
        for (const s of arr(extNode[secKey])) {
          if (!s) continue;
          const sName = str(s.Name) || str(s.KeyName) || secKey;
          const sValue = extractSecurityValue(s);
          out.push({
            scope,
            setting_type: 'security',
            setting_key: `Security|${scope}|${secKey}|${sName}`,
            setting_name: sName,
            setting_state: null,
            setting_value: sValue,
            category_path: `Security/${secKey}`
          });
        }
      }
    }

    // ─ Group Policy Preferences Registry ───────────────
    // Look for Registry items with Properties sub-elements
    if (extNode.RegistrySettings || extType === 'Registry') {
      const regRoot = extNode.RegistrySettings || extNode;
      for (const r of arr(regRoot.Registry)) {
        if (!r) continue;
        const props = r.Properties || {};
        const hive = props['@_hive'] || str(r.hive);
        const regKey = props['@_key'] || str(r.key);
        const regName = props['@_name'] || str(r.name) || '(Default)';
        const regValue = props['@_value'] || str(r.value) || '';
        const regType = props['@_type'] || str(r.type) || '';
        const action = props['@_action'] || 'U';  // U=Update, C=Create, R=Replace, D=Delete
        if (!regKey) continue;
        out.push({
          scope,
          setting_type: 'pref_registry',
          setting_key: `PrefReg|${scope}|${hive || ''}\\${regKey}|${regName}`,
          setting_name: `${hive || ''}\\${regKey}\\${regName}`,
          setting_state: action,
          setting_value: `${regType}:${regValue}`,
          category_path: 'Preferences/Registry'
        });
      }
    }

    // ─ Non-registry preferences — flag as present only ─
    // Files, Drive Maps, Scheduled Tasks, Services, Shortcuts, etc.
    for (const prefKey of ['Files', 'DriveMapSettings', 'ScheduledTasks', 'NTServices', 'Shortcuts', 'Folders', 'FolderRedirection', 'EnvironmentVariables', 'PrinterSettings']) {
      if (extNode[prefKey]) {
        const items = arr(extNode[prefKey][Object.keys(extNode[prefKey])[0]] || extNode[prefKey]);
        out.push({
          scope,
          setting_type: 'pref_other',
          setting_key: `PrefOther|${scope}|${prefKey}`,
          setting_name: prefKey,
          setting_state: 'Present',
          setting_value: `items:${items.length}`,
          category_path: `Preferences/${prefKey}`
        });
      }
    }
  }
}

// ── Extract a canonical value string from an Administrative Template policy ──
function extractPolicyValue(p) {
  const parts = [];
  // DropDownList
  for (const dd of arr(p.DropDownList)) {
    if (!dd) continue;
    const ddName = str(dd.Name);
    const ddVal = str(dd.Value && dd.Value.Name) || str(dd.Value);
    if (ddName || ddVal) parts.push(`DD[${ddName || ''}]=${ddVal || ''}`);
  }
  // EditText
  for (const et of arr(p.EditText)) {
    if (!et) continue;
    parts.push(`ET[${str(et.Name) || ''}]=${str(et.Value) || ''}`);
  }
  // Numeric
  for (const num of arr(p.Numeric)) {
    if (!num) continue;
    parts.push(`NUM[${str(num.Name) || ''}]=${str(num.Value) || ''}`);
  }
  // CheckBox
  for (const cb of arr(p.CheckBox)) {
    if (!cb) continue;
    parts.push(`CB[${str(cb.Name) || ''}]=${str(cb.State) || ''}`);
  }
  // ListBox
  for (const lb of arr(p.ListBox)) {
    if (!lb) continue;
    const vals = arr(lb.Value && lb.Value.Element).map(e => str(e && e.Data) || str(e)).filter(Boolean);
    parts.push(`LB[${str(lb.Name) || ''}]=[${vals.join(',')}]`);
  }
  // MultiText
  for (const mt of arr(p.MultiText)) {
    if (!mt) continue;
    const vals = arr(mt.Value && mt.Value.string).map(s => str(s)).filter(Boolean);
    parts.push(`MT[${str(mt.Name) || ''}]=[${vals.join(',')}]`);
  }
  return parts.length ? parts.join('; ') : (str(p.State) || '');
}

// ── Extract a canonical value string from a Security Setting ──────────
function extractSecurityValue(s) {
  if (s.SettingNumber !== undefined) return String(str(s.SettingNumber));
  if (s.SettingBoolean !== undefined) return String(str(s.SettingBoolean));
  if (s.SettingString !== undefined) return str(s.SettingString);
  if (s.SettingStrings !== undefined) {
    const arrVals = arr(s.SettingStrings.string).map(x => str(x)).filter(Boolean);
    return arrVals.join(',');
  }
  if (s.Member !== undefined) {
    const members = arr(s.Member).map(m => str(m.Name) || str(m.SID) || str(m)).filter(Boolean);
    return `Members:[${members.join(',')}]`;
  }
  if (s.SuccessAttempts !== undefined || s.FailureAttempts !== undefined) {
    return `S:${str(s.SuccessAttempts) || '0'}/F:${str(s.FailureAttempts) || '0'}`;
  }
  // Fallback: stringify
  return safeStringify(s).slice(0, 512);
}

module.exports = { parseGpoReport };
