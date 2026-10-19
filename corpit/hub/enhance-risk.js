'use strict';

function enhanceRiskScore(result) {
  if (!result || !result.risks) return;
  var newRisks = [];
  var okta = result.okta || {};
  var zscaler = result.zscaler || {};
  var zia = zscaler.zia || {};

  // Okta signals
  if (okta.status === 'found') {
    // A failed Okta /factors call leaves mfa as an empty array, which is
    // byte-identical to genuine zero enrolment. "Could not measure" is a
    // distinct state: it raises no risk signal and adds nothing to the score.
    // Only an EMPTY unmeasured list is suppressed - if factors actually came
    // back, trust the data over the flag and keep scoring it.
    var mfaList = Array.isArray(okta.mfa) ? okta.mfa : null;
    var mfaUnmeasured = !mfaList || (okta.mfaStatus === 'unknown' && mfaList.length === 0);
    if (mfaUnmeasured) {
      okta.mfaStatus = 'unknown';
    } else if (mfaList.length === 0) {
      newRisks.push({ level: 'critical', code: 'NO_MFA', message: 'No MFA factors enrolled in Okta' });
    } else {      var types = okta.mfa.map(function(f) { return f.type || f.factorType || ''; });
      var hasSmsOnly = types.every(function(t) { return t === 'sms' || t === 'call' || t === 'email'; });
      if (hasSmsOnly) {
        newRisks.push({ level: 'warning', code: 'WEAK_MFA', message: 'Only SMS/voice/email MFA — no push or hardware key' });
      }
    }
    if (okta.oktaStatusRaw === 'LOCKED_OUT') {
      newRisks.push({ level: 'critical', code: 'OKTA_LOCKED', message: 'Okta account is locked out' });
    } else if (okta.oktaStatusRaw === 'SUSPENDED') {
      newRisks.push({ level: 'critical', code: 'OKTA_SUSPENDED', message: 'Okta account is suspended' });
    } else if (okta.oktaStatusRaw === 'DEPROVISIONED') {
      newRisks.push({ level: 'critical', code: 'OKTA_DEPROVISIONED', message: 'Okta account is deprovisioned' });
    } else if (okta.oktaStatusRaw === 'PASSWORD_EXPIRED') {
      newRisks.push({ level: 'warning', code: 'OKTA_PWD_EXPIRED', message: 'Okta password is expired' });
    }
    if (okta.lastLogin) {
      var daysSinceLogin = (Date.now() - new Date(okta.lastLogin).getTime()) / 86400000;
      if (daysSinceLogin > 30) {
        newRisks.push({ level: 'warning', code: 'OKTA_STALE_LOGIN', message: 'No Okta login in ' + Math.round(daysSinceLogin) + ' days' });
      }
    }
  } else if (okta.status === 'not_found' && result.accountStatus && result.accountStatus.enabled) {
    newRisks.push({ level: 'warning', code: 'NO_OKTA_ACCOUNT', message: 'Active AD account but no Okta profile found' });
  }

  // Zscaler signals
  if (zia.status === 'not_found' && result.accountStatus && result.accountStatus.enabled) {
    newRisks.push({ level: 'warning', code: 'NO_ZIA', message: 'Not provisioned in Zscaler ZIA — no web security' });
  } else if (zia.status === 'found' && zia.isEnabled === false) {
    newRisks.push({ level: 'warning', code: 'ZIA_DISABLED', message: 'Zscaler ZIA account is disabled' });
  }

  if (newRisks.length === 0) return;

  // Merge risks
  result.risks = result.risks.concat(newRisks);

  // Add rootCause findings
  var findingMap = {
    NO_MFA: { priority: 2, title: 'No MFA enrolled in Okta — critical security gap',
      detail: 'This user has no multi-factor authentication configured. Account is vulnerable to credential compromise.',
      remediation: ['Enroll MFA: Okta Admin > Users > Select User > More Actions > Reset Multifactor',
        'Require MFA via authentication policy if not already enforced',
        'Consider Okta FastPass or FIDO2 hardware key for strongest protection'] },
    WEAK_MFA: { priority: 4, title: 'Weak MFA — SMS/email only',
      detail: 'User relies on SMS, voice, or email as MFA. These are vulnerable to SIM-swap and interception attacks.',
      remediation: ['Enroll Okta Verify Push or FIDO2 hardware key', 'Consider blocking SMS MFA in authentication policy'] },
    OKTA_LOCKED: { priority: 1, title: 'Okta account is locked out',
      detail: 'The user cannot authenticate to any Okta-protected application.',
      remediation: ['Okta Admin > Users > Select User > Unlock', 'Check Okta system log for lockout cause',
        'Verify AD account is also not locked (dual lockout)'] },
    OKTA_SUSPENDED: { priority: 1, title: 'Okta account is suspended',
      detail: 'Account has been administratively suspended. User cannot access any Okta apps.',
      remediation: ['Okta Admin > Users > Select User > Unsuspend', 'Verify suspension was intentional before unsuspending'] },
    OKTA_DEPROVISIONED: { priority: 1, title: 'Okta account is deprovisioned',
      detail: 'Account has been deprovisioned. All app assignments removed.',
      remediation: ['If this was a mistake, reactivate in Okta Admin > Users', 'Check HR/termination workflows'] },
    NO_OKTA_ACCOUNT: { priority: 4, title: 'Active AD account with no Okta profile',
      detail: 'User exists in AD but not in Okta. They cannot access SSO-protected applications.',
      remediation: ['Check if user should be provisioned to Okta', 'If using AD-to-Okta sync, verify sync group membership',
        'May be a service account or legacy account — verify with manager'] },
    NO_ZIA: { priority: 5, title: 'Not provisioned in Zscaler ZIA',
      detail: 'User has no Zscaler Internet Access profile. Web traffic is not being filtered or inspected.',
      remediation: ['Add user to ZIA via admin portal or SCIM provisioning', 'Verify Zscaler Client Connector is installed on their device',
        'Check if user is in an excluded group intentionally'] },
    ZIA_DISABLED: { priority: 5, title: 'Zscaler ZIA account is disabled',
      detail: 'User exists in ZIA but is disabled. Web security policies are not being enforced.',
      remediation: ['Re-enable in ZIA admin portal', 'Check if this was done intentionally during troubleshooting'] },
  };

  var newFindings = [];
  newRisks.forEach(function(r) {
    if (findingMap[r.code]) newFindings.push(findingMap[r.code]);
  });

  if (newFindings.length > 0 && result.rootCause) {
    result.rootCause = result.rootCause.filter(function(f) { return f.priority !== 99; });
    result.rootCause = result.rootCause.concat(newFindings).sort(function(a, b) { return a.priority - b.priority; });
  }

  // Recalculate score
  var scoreMap = {
    ACCOUNT_DISABLED: 40, ACCOUNT_LOCKED: 35, PASSWORD_EXPIRED: 30,
    PASSWORD_PAST_EXPIRY: 30, PRIVILEGED_ACCOUNT: 25,
    RECENT_BAD_PASSWORD: 20, HIGH_BAD_PASSWORD_COUNT: 15,
    PASSWORD_EXPIRING_SOON: 10, STALE_LOGON: 10,
    NO_MFA: 25, WEAK_MFA: 10, OKTA_LOCKED: 30, OKTA_SUSPENDED: 35,
    OKTA_DEPROVISIONED: 40, OKTA_PWD_EXPIRED: 15, OKTA_STALE_LOGIN: 10,
    NO_OKTA_ACCOUNT: 15, NO_ZIA: 15, ZIA_DISABLED: 15,
  };
  // An entry standing for an unmeasured input must never add points — an
  // upstream API outage must not manufacture a CRITICAL score.
  result.riskScore = Math.min(result.risks.reduce(function(s, r) {
    if (!r || r.level === 'unknown' || r.measured === false) return s;
    return s + (scoreMap[r.code] || 5);
  }, 0), 100);
  result.riskCategory = result.riskScore >= 60 ? 'CRITICAL' : result.riskScore >= 35 ? 'HIGH' :
                        result.riskScore >= 15 ? 'MEDIUM' : result.riskScore >= 1 ? 'LOW' : 'CLEAN';
}

module.exports = { enhanceRiskScore };
