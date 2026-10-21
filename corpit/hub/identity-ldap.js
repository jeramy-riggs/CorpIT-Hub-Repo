'use strict';

const ldapSecure = require('./ldap-secure'); // ldapjs client with StartTLS before every bind

const LDAP_URL        = process.env.LDAP_URL        || 'ldap://10.9.64.80:389';
const LDAP_BASE_DN    = process.env.LDAP_BASE_DN    || 'DC=nrpi,DC=local';
const LDAP_BIND_USER  = process.env.LDAP_BIND_USER  || 'itjeramy.riggs@nrpi.local';
const LDAP_BIND_PASS  = process.env.LDAP_BIND_PASS  || '';
const LDAP_TIMEOUT_MS = 8000;

const UAC = {
  ACCOUNTDISABLE:       0x0002,
  LOCKOUT:              0x0010,
  DONT_EXPIRE_PASSWORD: 0x10000,
  PASSWORD_EXPIRED:     0x800000,
  PASSWD_NOTREQD:       0x0020,
  PASSWD_CANT_CHANGE:   0x0040,
};

const USER_ATTRS = [
  'cn','displayName','sAMAccountName','userPrincipalName','mail',
  'userAccountControl','lockoutTime','badPwdCount','badPasswordTime',
  'pwdLastSet','accountExpires','lastLogonTimestamp','lastLogon',
  'distinguishedName','department','title','description','manager',
  'physicalDeliveryOfficeName','telephoneNumber','mobile',
  'memberOf','whenCreated','whenChanged','objectGUID',
  'msDS-UserPasswordExpiryTimeComputed','logonWorkstation',
  'homeDirectory','profilePath','scriptPath','employeeID',
];

const PRIVILEGED_GROUPS = [
  'domain admins','enterprise admins','schema admins',
  'administrators','account operators','backup operators',
  'print operators','server operators','group policy creator owners',
  'dns admins','dhcp administrators',
];

// ── Key fix: build a plain object from entry.attributes ──────────────────────
// entry.object is undefined in this ldapjs version — must parse attributes array
function parseEntry(entry) {
  const obj = {};
  entry.attributes.forEach(a => {
    obj[a.type] = a.values.length === 1 ? a.values[0] : a.values;
  });
  return obj;
}

function fileTimeToDate(fileTime) {
  if (!fileTime) return null;
  const val = BigInt(fileTime);
  if (val === 0n || val === 9223372036854775807n) return null;
  const epochDiff = 11644473600000n;
  const ms = val / 10000n - epochDiff;
  return new Date(Number(ms));
}

function decodeUAC(uacVal) {
  const uac = parseInt(uacVal, 10) || 0;
  return {
    raw:                  uac,
    enabled:              !(uac & UAC.ACCOUNTDISABLE),
    lockedOut:            !!(uac & UAC.LOCKOUT),
    passwordExpired:      !!(uac & UAC.PASSWORD_EXPIRED),
    passwordNeverExpires: !!(uac & UAC.DONT_EXPIRE_PASSWORD),
    passwordNotRequired:  !!(uac & UAC.PASSWD_NOTREQD),
    cantChangePassword:   !!(uac & UAC.PASSWD_CANT_CHANGE),
  };
}

function createClient() {
  return new Promise((resolve, reject) => {
    const client = ldapSecure.createClient({
      url:            LDAP_URL,
      timeout:        LDAP_TIMEOUT_MS,
      connectTimeout: LDAP_TIMEOUT_MS,
    });
    client.on('error', (err) => reject(new Error(`LDAP connection error: ${err.message}`)));
    client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, (err) => {
      if (err) { client.destroy(); return reject(new Error(`LDAP bind failed: ${err.message}`)); }
      resolve(client);
    });
  });
}

function ldapSearch(client, base, filter, attributes, scope = 'sub') {
  return new Promise((resolve, reject) => {
    const entries = [];
    client.search(base, { filter, attributes, scope, sizeLimit: 300 }, (err, res) => {
      if (err) return reject(new Error(`LDAP search error: ${err.message}`));
      res.on('searchEntry', (entry) => entries.push(parseEntry(entry)));
      res.on('error',       (err)   => reject(new Error(`LDAP stream error: ${err.message}`)));
      res.on('end',         ()      => resolve(entries));
    });
  });
}

function closeClient(client) {
  try { client.unbind(); } catch (_) {}
}

// RFC 4515 filter-value escaping. Backslash is replaced FIRST so the
// backslashes the later replacements introduce are not re-escaped.
// Same helper as ad-groups.js:33 and rbac-ad-resolver.js:94.
function escapeFilterValue(v) {
  return String(v)
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

async function getDomainPolicy(client) {
  try {
    const r = await ldapSearch(client, LDAP_BASE_DN,
      '(objectClass=domain)',
      ['maxPwdAge','lockoutThreshold','lockoutDuration','minPwdLength'],
      'base');
    if (r.length > 0) {
      const d = r[0];
      return {
        maxPwdAge:              d.maxPwdAge || null,
        lockoutThreshold:       parseInt(d.lockoutThreshold, 10) || 0,
        lockoutDurationMinutes: d.lockoutDuration
          ? Math.abs(Number(BigInt(d.lockoutDuration)) / 600000000) : null,
        minPwdLength: parseInt(d.minPwdLength, 10) || 0,
      };
    }
  } catch (e) { console.warn('[identity-ldap] domain policy:', e.message); }
  return {};
}

async function resolveGroupsRecursive(client, groupDNs, seen = new Set(), failed = []) {
  const groups = [];
  for (const dn of groupDNs) {
    if (seen.has(dn)) continue;
    seen.add(dn);
    try {
      const r = await ldapSearch(client, dn,
        '(objectClass=group)',
        ['cn','distinguishedName','memberOf','description'], 'base');
      if (r.length > 0) {
        const g = r[0];
        const name = g.cn || dn.split(',')[0].replace('CN=','');
        groups.push({
          name,
          dn:           g.distinguishedName || dn,
          description:  g.description || null,
          isPrivileged: PRIVILEGED_GROUPS.includes(name.toLowerCase()),
        });
        const parents = g.memberOf
          ? (Array.isArray(g.memberOf) ? g.memberOf : [g.memberOf]) : [];
        if (parents.length > 0) {
          const nested = await resolveGroupsRecursive(client, parents, seen, failed);
          groups.push(...nested);
        }
      } else {
        failed.push({ dn, error: 'no entry returned' });
      }
    } catch (e) { failed.push({ dn, error: e.message }); }
  }
  return groups;
}

function buildRootCause(risks, data) {
  const findings = [];

  if (risks.some(r => r.code === 'ACCOUNT_LOCKED')) {
    findings.push({
      priority: 1,
      title: 'Account is locked out',
      detail: data.lockoutTime
        ? `Locked at ${data.lockoutTime.toLocaleString()}. Bad password count: ${data.badPwdCount}.`
        : `Bad password count: ${data.badPwdCount}.`,
      remediation: [
        'Unlock: Right-click user in ADUC → Unlock Account',
        'PowerShell on a DC: Unlock-ADAccount -Identity <sam>',
        'Root cause: check Event ID 4740 on adcoredc16009.NRPI.LOCAL — CallerComputerName shows source device',
      ],
    });
  }

  if (risks.some(r => r.code === 'PASSWORD_EXPIRED' || r.code === 'PASSWORD_PAST_EXPIRY')) {
    findings.push({
      priority: 2,
      title: 'Password is expired — most likely root cause of repeated lockouts',
      detail: `Password last set: ${data.pwdLastSet ? data.pwdLastSet.toLocaleString() : 'unknown'}. All devices with saved credentials will begin locking the account.`,
      remediation: [
        'Reset in ADUC: right-click user → Reset Password',
        'After reset: update ALL devices — phone, tablet, laptop, Outlook, VPN, mapped drives simultaneously',
      ],
    });
  }

  if (risks.some(r => r.code === 'PASSWORD_EXPIRING_SOON')) {
    findings.push({
      priority: 3,
      title: `Password expiring in ${data.expiresInDays} day(s)`,
      detail: 'Upcoming expiry causes lockout waves as devices fail to refresh after the change.',
      remediation: [
        'Notify user to change password now',
        'After change: update all devices simultaneously to avoid lockouts',
      ],
    });
  }

  if (data.badPwdCount > 0 && risks.some(r => r.code === 'HIGH_BAD_PASSWORD_COUNT' || r.code === 'RECENT_BAD_PASSWORD')) {
    findings.push({
      priority: 4,
      title: `${data.badPwdCount} bad password attempt(s) — stale credential source likely`,
      detail: data.badPasswordTime
        ? `Last bad password: ${data.badPasswordTime.toLocaleString()}.`
        : 'Repeated authentication failures detected.',
      remediation: [
        'Check Windows Credential Manager: run → control keymgr.dll',
        'Check mapped drives: net use (in cmd)',
        'Check mobile device email profile (iOS: Settings → Mail → Account)',
        'Check scheduled tasks and Windows services running as this user',
        'For exact source device: check Event ID 4740 on adcoredc16009.NRPI.LOCAL',
      ],
    });
  }

  if (risks.some(r => r.code === 'PRIVILEGED_ACCOUNT')) {
    findings.push({
      priority: 5,
      title: 'Privileged account — elevated security risk',
      detail: 'This account holds privileged AD group membership. Lockouts on privileged accounts are higher severity.',
      remediation: [
        'Verify admin group membership is still required',
        'Consider a separate named admin account for day-to-day use',
      ],
    });
  }

  if (findings.length === 0) {
    findings.push({
      priority: 99,
      title: 'No significant issues detected',
      detail: 'Account appears healthy. Password current, no lockout active, no elevated bad-password count.',
      remediation: [],
    });
  }

  return findings.sort((a, b) => a.priority - b.priority);
}

async function lookupUser(identity) {
  if (!identity || !identity.trim()) throw new Error('Identity is required');

  const client = await createClient();

  try {
    const escaped = escapeFilterValue(identity);
    const filter = `(|` +
      `(sAMAccountName=${escaped})` +
      `(userPrincipalName=${escaped})` +
      `(mail=${escaped})` +
      `(displayName=${escaped})` +
      `(cn=${escaped})` +
    `)`;

    const results = await ldapSearch(client, LDAP_BASE_DN, filter, USER_ATTRS);
    if (results.length === 0) return null;

    const entry = results.find(r =>
      r.sAMAccountName?.toLowerCase() === identity.toLowerCase()
    ) || results[0];

    const policy = await getDomainPolicy(client);
    const uac    = decodeUAC(entry.userAccountControl);

    const lockoutTime     = fileTimeToDate(entry.lockoutTime);
    const badPasswordTime = fileTimeToDate(entry.badPasswordTime);
    const pwdLastSet      = fileTimeToDate(entry.pwdLastSet);
    const lastLogon       = fileTimeToDate(entry.lastLogonTimestamp || entry.lastLogon);
    const whenCreated     = entry.whenCreated ? new Date(entry.whenCreated) : null;
    const whenChanged     = entry.whenChanged ? new Date(entry.whenChanged) : null;
    const accountExpires  = fileTimeToDate(entry.accountExpires);

    let passwordExpiry   = null;
    let pwdExpiresInDays = null;
    if (!uac.passwordNeverExpires && pwdLastSet && policy.maxPwdAge) {
      const ageMs    = Math.abs(Number(BigInt(policy.maxPwdAge)) / 10000);
      passwordExpiry = new Date(pwdLastSet.getTime() + ageMs);
      pwdExpiresInDays = Math.round((passwordExpiry - new Date()) / 86400000);
    }

    const ouLocation = (entry.distinguishedName || '').split(',').slice(1).join(',');

    const rawGroups = entry.memberOf
      ? (Array.isArray(entry.memberOf) ? entry.memberOf : [entry.memberOf]) : [];
    // A group DN the DC would not answer for is NOT "no group". Same ladder as
    // identity-routes.js srcUnknown: the count becomes null and the reason
    // travels with it, so the console renders "unknown" instead of 0.
    const groupSeen = new Set(), groupReadFailures = [];
    const groups           = await resolveGroupsRecursive(client, rawGroups, groupSeen, groupReadFailures);
    const privilegedGroups = groups.filter(g => g.isPrivileged);
    const groupsUnavailable = groupReadFailures.length > 0;
    const groupsError = groupsUnavailable
      ? `${groupReadFailures.length} of ${groupSeen.size} AD group lookups failed (${String(groupReadFailures[0].error || '').slice(0, 160)})`
      : null;
    if (groupsUnavailable) console.warn('[identity-ldap] group resolution degraded for', entry.sAMAccountName, '-', groupsError);

    let managerName = null;
    if (entry.manager) {
      try {
        const mgr = await ldapSearch(client, entry.manager,
          '(objectClass=*)', ['displayName','sAMAccountName'], 'base');
        if (mgr.length > 0) managerName = mgr[0].displayName || mgr[0].sAMAccountName;
      } catch (_) {}
    }

    const now   = new Date();
    const risks = [];

    if (!uac.enabled)
      risks.push({ level:'critical', code:'ACCOUNT_DISABLED',        message:'Account is disabled in AD' });
    if (uac.lockedOut || (lockoutTime && lockoutTime > new Date(0)))
      risks.push({ level:'critical', code:'ACCOUNT_LOCKED',          message:'Account is currently locked out' });
    if (uac.passwordExpired)
      risks.push({ level:'critical', code:'PASSWORD_EXPIRED',        message:'Password has expired' });
    if (pwdExpiresInDays !== null && pwdExpiresInDays < 0)
      risks.push({ level:'critical', code:'PASSWORD_PAST_EXPIRY',    message:`Password expired ${Math.abs(pwdExpiresInDays)} day(s) ago` });
    if (pwdExpiresInDays !== null && pwdExpiresInDays >= 0 && pwdExpiresInDays <= 7)
      risks.push({ level:'warning',  code:'PASSWORD_EXPIRING_SOON',  message:`Password expires in ${pwdExpiresInDays} day(s)` });
    if (parseInt(entry.badPwdCount, 10) > 3)
      risks.push({ level:'warning',  code:'HIGH_BAD_PASSWORD_COUNT', message:`${entry.badPwdCount} bad password attempts recorded` });
    if (privilegedGroups.length > 0)
      risks.push({ level:'critical', code:'PRIVILEGED_ACCOUNT',      message:`Member of: ${privilegedGroups.map(g=>g.name).join(', ')}` });
    if (badPasswordTime && (now - badPasswordTime) < 3600000)
      risks.push({ level:'warning',  code:'RECENT_BAD_PASSWORD',     message:'Bad password attempt within the last hour' });
    if (!lastLogon || (now - lastLogon) > 90 * 86400000)
      risks.push({ level:'warning',  code:'STALE_LOGON',             message: lastLogon ? 'No logon in 90+ days' : 'No logon recorded' });

    const scoreMap = {
      ACCOUNT_DISABLED:40, ACCOUNT_LOCKED:35, PASSWORD_EXPIRED:30,
      PASSWORD_PAST_EXPIRY:30, PRIVILEGED_ACCOUNT:25,
      RECENT_BAD_PASSWORD:20, HIGH_BAD_PASSWORD_COUNT:15,
      PASSWORD_EXPIRING_SOON:10, STALE_LOGON:10,
    };
    const riskScore    = Math.min(risks.reduce((s,r) => s+(scoreMap[r.code]||5),0), 100);
    const riskCategory = riskScore>=60?'CRITICAL':riskScore>=35?'HIGH':
                         riskScore>=15?'MEDIUM'  :riskScore>=1 ?'LOW':'CLEAN';

    const rootCause = buildRootCause(risks, {
      badPwdCount: parseInt(entry.badPwdCount,10)||0,
      badPasswordTime, lockoutTime, passwordExpiry,
      pwdLastSet, expiresInDays: pwdExpiresInDays,
    });

    return {
      displayName:    entry.displayName       || null,
      samAccountName: entry.sAMAccountName    || null,
      upn:            entry.userPrincipalName || null,
      email:          entry.mail              || null,
      department:     entry.department        || null,
      title:          entry.title             || null,
      office:         entry.physicalDeliveryOfficeName || null,
      phone:          entry.telephoneNumber   || null,
      mobile:         entry.mobile            || null,
      manager:        managerName,
      description:    entry.description       || null,
      distinguishedName: entry.distinguishedName || null,
      ouLocation,
      accountStatus: {
        enabled:        uac.enabled,
        lockedOut:      uac.lockedOut || !!(lockoutTime && lockoutTime > new Date(0)),
        lockoutTime,
        badPwdCount:    parseInt(entry.badPwdCount,10)||0,
        badPasswordTime,
        accountExpires,
        accountExpired: accountExpires ? accountExpires < now : false,
      },
      password: {
        // fileTimeToDate() collapses "attribute absent", "0" and the
        // never-expires sentinel to null, so lastSet:null alone cannot say
        // whether the password must be changed at next sign-in or simply
        // could not be read. AD encodes "must change" as pwdLastSet == 0,
        // and after an admin reset that is the single most actionable fact
        // about the account -- without this the console can only show a dash.
        mustChange:   String(entry.pwdLastSet) === '0',
        lastSet:      pwdLastSet,
        expiry:       passwordExpiry,
        expiresInDays: pwdExpiresInDays,
        expired:      uac.passwordExpired,
        neverExpires: uac.passwordNeverExpires,
        notRequired:  uac.passwordNotRequired,
        cantChange:   uac.cantChangePassword,
      },
      lastLogon,
      whenCreated,
      whenChanged,
      groups,                                   // what WAS read (may be a floor)
      privilegedGroups,                         // subset of `groups` -- also a floor when degraded
      groupCount:   groupsUnavailable ? null : groups.length,
      groupsResolved: groups.length,            // always numeric
      groupsUnavailable,                        // true = at least one group read failed
      groupsError,                              // reason string, null when clean
      domainPolicy: policy,
      risks,
      riskScore,
      riskCategory,
      rootCause,
      queriedAt: new Date().toISOString(),
      dc: LDAP_URL,
    };

  } finally {
    closeClient(client);
  }
}

async function searchUsers(prefix) {
  if (!prefix || prefix.trim().length < 2) return [];
  const client = await createClient();
  try {
    const esc = escapeFilterValue(prefix.trim());
    const filter = '(|' +
      '(sAMAccountName=' + esc + '*)' +
      '(displayName=' + esc + '*)' +
      '(sn=' + esc + '*)' +
      '(givenName=' + esc + '*)' +
      '(mail=' + esc + '*)' +
      '(userPrincipalName=' + esc + '*)' +
      ')';
    const results = await ldapSearch(client, LDAP_BASE_DN, filter,
      ['sAMAccountName','displayName','mail','userPrincipalName'], 'sub');
    return results.slice(0, 15).map(r => ({
      sam:         r.sAMAccountName  || '',
      displayName: r.displayName     || '',
      email:       r.mail            || r.userPrincipalName || '',
    }));
  } finally {
    closeClient(client);
  }
}
module.exports = { lookupUser, searchUsers, escapeFilterValue };
