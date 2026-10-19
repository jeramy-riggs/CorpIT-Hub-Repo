// session-cookie.js — sets the it_session gate cookie. (ITAM-01)
//
// The signed token already minted by each login path is ALSO placed in an HttpOnly
// cookie so nginx's auth_request can verify it. JS never needs to read this cookie —
// the frontend keeps using the sessionStorage copy for its Authorization header — so
// HttpOnly costs nothing and takes the token out of reach of XSS.
//
// Domain=.itam.nrpi.local (2026-08-24, Approver Portal gate): the accessportal
// subdomain's /_gate needs the cookie too. Browsers treat a host-only cookie and a
// Domain= cookie of the same name as TWO separate cookies and send the older one
// first, so every set/clear below also clears the pre-rollout host-only variant —
// otherwise a stale host-only token would wedge the gate in a login loop.
'use strict';

const NAME   = 'it_session';
// SESSION_COOKIE_DOMAIN (2026-08-28): a Domain= for a domain this host is NOT under is
// silently DISCARDED by the browser, so a clone on another host mints a session (200) whose
// cookie never sticks -> gate 401 -> login loop. Env-driven so each host sets one it can own.
// Empty string = host-only cookie. Default preserves the original itam behaviour.
const DOMAIN = (process.env.SESSION_COOKIE_DOMAIN !== undefined)
  ? String(process.env.SESSION_COOKIE_DOMAIN).trim()
  : '.itam.nrpi.local';
// secure: vhosts are HTTPS-only (port 80 301s to 443).
// sameSite lax: survives the Entra SSO top-level redirect back to us.
const BASE = { httpOnly: true, secure: true, sameSite: 'lax', path: '/' };

// A Domain= the current host does not sit under is silently discarded by the
// browser (see the header note). One API now answers for corpit, accessportal,
// subadmin and directory, so the configured DOMAIN is only correct for some of
// them -- resolve it per request and fall back to a host-only cookie, which is
// what the multi-vhost design wants anyway: every host holds only its own session.
function cookieDomainFor(req) {
  if (!DOMAIN) return '';
  if (!req) return DOMAIN;               // legacy callers: unchanged behaviour
  const raw = req.headers['x-forwarded-host'] || req.headers.host || '';
  const host = String(raw).split(',')[0].trim().split(':')[0].toLowerCase();
  const base = DOMAIN.replace(/^\./, '').toLowerCase();
  if (!host) return DOMAIN;
  return (host === base || host.endsWith('.' + base)) ? DOMAIN : '';
}

function setSessionCookie(res, token, ttlMs, req) {
  if (!token) return;
  res.clearCookie(NAME, { ...BASE }); // pre-rollout host-only variant
  const opts = { ...BASE, maxAge: ttlMs };
  const d = cookieDomainFor(req);
  if (d) opts.domain = d;
  res.cookie(NAME, token, opts);
}

function clearSessionCookie(res, req) {
  res.clearCookie(NAME, { ...BASE }); // pre-rollout host-only variant
  const d = cookieDomainFor(req);
  if (d) res.clearCookie(NAME, { ...BASE, domain: d });
}

module.exports = { NAME, setSessionCookie, clearSessionCookie, cookieDomainFor };
