'use strict';
const { X509Certificate } = require('crypto');
const guid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s || ''));
const thumb = (s) => String(s || '').replace(/[:\s]/g, '').toUpperCase();

/* Graph returns both Sign (private) and Verify (public) credentials. Only the
   preferred, valid public X.509 certificate can leave this helper. */
function publicCertificate(sp, now = Date.now()) {
  const preferred = thumb(sp && sp.preferredTokenSigningKeyThumbprint);
  if (!preferred) return null;
  for (const k of (sp.keyCredentials || [])) {
    if (k.usage !== 'Verify' || k.type !== 'AsymmetricX509Cert' || !k.key) continue;
    try {
      const cert = new X509Certificate(Buffer.from(k.key, 'base64'));
      if (thumb(cert.fingerprint) !== preferred || Date.parse(cert.validFrom) > now || Date.parse(cert.validTo) <= now) continue;
      return { certificatePem: cert.toString(), certificateThumbprint: preferred, certificateExpires: new Date(cert.validTo).toISOString() };
    } catch (_) { /* Invalid or non-certificate public data is unavailable. */ }
  }
  return null;
}

async function readHandoff({ revision: rev, destination: d, tenantId, graphGet }) {
  const unavailable = (why) => ({ available: false, why, values: {}, metadataUrl: null });
  if (!rev || rev.protocol !== 'saml2') return null;
  if (!d || d.tombstone || d.state === 'invalidated') return unavailable('The Entra destination was deleted. Resolve the destination before continuing SAML setup.');
  if (rev.state === 'superseded' || d.state !== 'confirmed' || !rev.entraId || rev.entraId !== d.entraId) return unavailable('Prepare and confirm the Entra destination first.');
  if (!guid(tenantId)) return unavailable('The Entra tenant identifier is unavailable. Ask an administrator to check the connection.');
  let r;
  try { r = await graphGet('/v1.0/servicePrincipals/' + encodeURIComponent(rev.entraId) + '?$select=id,appId,preferredSingleSignOnMode,preferredTokenSigningKeyThumbprint,keyCredentials'); }
  catch (_) { return unavailable('Could not read Entra. Retry to load the current signing certificate.'); }
  if (r.status !== 200 || !r.body || r.body.id !== rev.entraId) return unavailable(r.status === 404 ? 'The Entra application no longer exists. Resolve the destination first.' : 'Could not read Entra. Retry to load the current signing certificate.');
  const sp = r.body;
  if (!guid(sp.appId) || sp.preferredSingleSignOnMode !== 'saml') return unavailable('Configure SAML on the Entra application first. An isolated shell does not have a signing certificate.');
  const cert = publicCertificate(sp);
  if (!cert) return unavailable('No current preferred signing certificate is available. Complete the Entra SAML configuration, then retry.');
  const base = 'https://login.microsoftonline.com/' + tenantId;
  return { available: true, why: null, values: Object.assign({ entityId: 'https://sts.windows.net/' + tenantId + '/', loginUrl: base + '/saml2' }, cert),
    metadataUrl: base + '/federationmetadata/2007-06/federationmetadata.xml?appid=' + sp.appId, entraId: sp.id, appId: sp.appId };
}

function validateVendorValues(cfg) {
  const c = cfg || {};
  const entity = String(c.entityId || '').trim();
  if (!entity || entity.length > 500 || /[<>\s]/.test(entity) || /\{\{|placeholder\.invalid/.test(entity)) return 'Enter the real Audience URL supplied by the vendor.';
  const urls = c.replyUrls;
  if (!Array.isArray(urls) || urls.length < 1 || urls.length > 20) return 'Enter the ACS URL supplied by the vendor.';
  for (const s of urls) {
    try { const u = new URL(s); if (u.protocol !== 'https:' || u.username || u.password || u.hash || u.hostname === 'placeholder.invalid' || /[<>*\s]/.test(s) || s.length > 500) return 'ACS URLs must be complete HTTPS URLs without placeholders.'; }
    catch (_) { return 'Enter a valid HTTPS ACS URL.'; }
  }
  if (String(c.relayState || '').length > 500) return 'Relay state must be 500 characters or fewer.';
  if (!/^[0-9A-F]{40}$/i.test(String(c.samlHandoffThumbprint || ''))) return 'Reload the Entra signing certificate before saving vendor values.';
  return null;
}
module.exports = { publicCertificate, readHandoff, validateVendorValues };
