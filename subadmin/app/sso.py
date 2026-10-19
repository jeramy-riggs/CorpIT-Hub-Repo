"""
Entra ID single sign-on for the CORPIT admin console.

Two halves, deliberately kept apart:

  Authentication  - OpenID Connect authorization-code flow with PKCE against a
                    dedicated confidential app registration. The code/token
                    exchange happens server-side over TLS with the client
                    secret, so no access or ID token is ever handed to the
                    browser. The ID token is fully validated: RS256 signature
                    against the tenant JWKS, plus issuer, audience, tenant,
                    nonce and expiry.

  Authorization   - NOT taken from the token. Group membership is read from
                    on-prem AD over LDAP against the SaaS-ITH-* role and approver
                    groups the platform already uses, so roles keep one source
                    of truth. The practical consequence is that this app
                    registration needs NO admin-consented Graph permissions -
                    only openid/profile/email, which is default user consent.

Default-deny: a directory account with none of the mapped groups gets no
console access at all, even though Entra authenticated it successfully.
"""

import base64
import hashlib
import json
import secrets
import ssl
import threading
import time
import urllib.parse
import urllib.request

import jwt
from jwt import PyJWKClient

# --------------------------------------------------------------------------
# Role model
#
# Ranked most-privileged first; a user in several groups gets the highest.
# Anything not listed here is denied - adding a group to the console is a
# deliberate edit, never a side effect of someone joining a group in AD.
# --------------------------------------------------------------------------
ROLE_RANK = ["platform-owner", "operator", "security", "viewer"]

# Every role and approver group follows the SaaS-ITH-<ROLE> convention (IT Hub,
# 2026-10-08; the approver groups moved onto it the same day), so sign-in reads one prefix.
GROUP_PREFIXES = ("saas-ith-",)

GROUP_ROLE_MAP = {
    "saas-ith-sa": "platform-owner",
    "saas-ith-hd": "operator",
    "saas-ith-sec": "security",
    "saas-ith-ro": "viewer",
}

# Roles that may perform any write at all. Read-only roles get the whole
# console but every action is disabled, the same way estate scope behaves.
WRITE_ROLES = {"platform-owner", "operator"}

_JWKS_LOCK = threading.Lock()
_JWKS_CLIENT = {"url": None, "client": None}


class SSOError(Exception):
    """Anything that should end the sign-in attempt with a clean message."""


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def sso_config(cfg):
    """Read the sso block out of config.json. Returns None when not configured."""
    s = (cfg or {}).get("sso") or {}
    if not s.get("enabled"):
        return None
    missing = [k for k in ("tenant_id", "client_id", "client_secret", "redirect_uri")
               if not s.get(k)]
    if missing:
        raise SSOError("sso config incomplete, missing: " + ", ".join(missing))
    return s


def authority(tenant_id):
    return "https://login.microsoftonline.com/%s" % tenant_id


def _jwks(tenant_id):
    url = authority(tenant_id) + "/discovery/v2.0/keys"
    with _JWKS_LOCK:
        if _JWKS_CLIENT["url"] != url:
            # PyJWKClient caches signing keys internally and refetches on a
            # miss, which is what handles Entra's key rollover.
            _JWKS_CLIENT["url"] = url
            _JWKS_CLIENT["client"] = PyJWKClient(url, cache_keys=True, lifespan=3600)
        return _JWKS_CLIENT["client"]


# --------------------------------------------------------------------------
# Authorization-code + PKCE
# --------------------------------------------------------------------------
def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def begin_login(s, next_path="/"):
    """Build the authorize URL. Returns (url, pending) - store pending in the session."""
    verifier = _b64url(secrets.token_bytes(64))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    pending = {
        "state": secrets.token_urlsafe(32),
        "nonce": secrets.token_urlsafe(32),
        "verifier": verifier,
        "next": next_path if next_path.startswith("/") and not next_path.startswith("//") else "/",
        "ts": int(time.time()),
    }
    q = {
        "client_id": s["client_id"],
        "response_type": "code",
        "redirect_uri": s["redirect_uri"],
        "response_mode": "query",
        "scope": "openid profile email",
        "state": pending["state"],
        "nonce": pending["nonce"],
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": s.get("prompt", "select_account"),
    }
    url = authority(s["tenant_id"]) + "/oauth2/v2.0/authorize?" + urllib.parse.urlencode(q)
    return url, pending


def _post_form(url, fields, timeout=15):
    body = urllib.parse.urlencode(fields).encode("ascii")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode("utf-8"))
        except Exception:
            payload = {}
        raise SSOError("token endpoint %s: %s" % (
            e.code, payload.get("error_description") or payload.get("error") or "request failed"))
    except Exception as e:
        raise SSOError("could not reach the token endpoint: %s" % e)


def complete_login(s, pending, args):
    """Validate the callback and return the verified ID-token claims."""
    if not pending:
        raise SSOError("no sign-in was in progress - start again from the console")
    if int(time.time()) - int(pending.get("ts", 0)) > 600:
        raise SSOError("sign-in took too long, please try again")

    if args.get("error"):
        raise SSOError(args.get("error_description") or args.get("error"))

    state = args.get("state") or ""
    if not secrets.compare_digest(state, pending.get("state", "")):
        raise SSOError("state mismatch - sign-in was not started from this console")

    code = args.get("code")
    if not code:
        raise SSOError("no authorization code returned")

    tok = _post_form(authority(s["tenant_id"]) + "/oauth2/v2.0/token", {
        "client_id": s["client_id"],
        "client_secret": s["client_secret"],
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": s["redirect_uri"],
        "code_verifier": pending["verifier"],
        "scope": "openid profile email",
    })
    id_token = tok.get("id_token")
    if not id_token:
        raise SSOError("no id_token in the token response")

    signing_key = _jwks(s["tenant_id"]).get_signing_key_from_jwt(id_token)
    try:
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=s["client_id"],
            issuer="https://login.microsoftonline.com/%s/v2.0" % s["tenant_id"],
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            leeway=120,
        )
    except jwt.PyJWTError as e:
        raise SSOError("id_token rejected: %s" % e)

    # Belt and braces on top of the issuer check: pin the tenant explicitly so a
    # token minted in another tenant can never satisfy this app.
    if claims.get("tid") != s["tenant_id"]:
        raise SSOError("token came from the wrong tenant")
    if not secrets.compare_digest(str(claims.get("nonce") or ""), pending.get("nonce", "")):
        raise SSOError("nonce mismatch - possible replay")

    return claims


def identity_from_claims(claims):
    """The UPN/email we look up in AD, plus a display name."""
    upn = (claims.get("preferred_username") or claims.get("upn")
           or claims.get("email") or "").strip()
    if not upn:
        raise SSOError("Entra returned no username for this account")
    return {
        "upn": upn.lower(),
        "upn_raw": upn,
        "name": claims.get("name") or upn,
        "oid": claims.get("oid") or "",
    }


# --------------------------------------------------------------------------
# Authorization - AD group membership over LDAP
# --------------------------------------------------------------------------
def _escape_filter(v):
    out = []
    for ch in v:
        if ch in "\\*()\0":
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def group_cn(dn):
    """CN=SaaS-ITH-HD,OU=... -> saas-ith-hd"""
    head = str(dn).split(",", 1)[0].strip()
    if head.lower().startswith("cn="):
        head = head[3:]
    return head.strip().lower()


def ad_groups_for(ldap_cfg, upn):
    """Return the user's SaaS-ITH-* group CNs, lowercased. Raises on LDAP failure."""
    import ldap3

    server = ldap3.Server(ldap_cfg["url"], get_info=None, connect_timeout=10)
    conn = ldap3.Connection(
        server, user=ldap_cfg["bind_user"], password=ldap_cfg["bind_pass"],
        auto_bind=False, receive_timeout=15, raise_exceptions=False,
    )
    if not conn.bind():
        raise SSOError("directory bind failed: %s" % (conn.result or {}).get("description"))
    try:
        u = _escape_filter(upn)
        # UPNs in this directory are mixed case (Jriggs@, Mbaig@); LDAP matching
        # on these attributes is case-insensitive, and mail is checked too
        # because Entra's preferred_username is not always the on-prem UPN.
        flt = ("(&(objectCategory=person)(objectClass=user)"
               "(|(userPrincipalName=%s)(mail=%s)))" % (u, u))
        ok = conn.search(ldap_cfg["base_dn"], flt, attributes=["memberOf", "userAccountControl", "cn"])
        if not ok or not conn.entries:
            raise SSOError("no directory account found for %s" % upn)
        e = conn.entries[0]

        uac = 0
        try:
            uac = int(e.userAccountControl.value or 0)
        except Exception:
            uac = 0
        if uac & 0x2:  # ACCOUNTDISABLE
            raise SSOError("directory account for %s is disabled" % upn)

        member_of = e.memberOf.values if "memberOf" in e else []
        return sorted({group_cn(d) for d in member_of if any(p in str(d).lower() for p in GROUP_PREFIXES)})
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def role_for_groups(groups, role_map=None):
    """Highest-ranked mapped role, or None when the user matches nothing (default-deny)."""
    m = role_map or GROUP_ROLE_MAP
    roles = {m[g] for g in groups if g in m}
    for r in ROLE_RANK:
        if r in roles:
            return r
    return None


def authorize(ldap_cfg, ident, owners, role_map=None):
    """Resolve a verified identity into a console session dict, or raise SSOError."""
    groups = ad_groups_for(ldap_cfg, ident["upn"])
    role = role_for_groups(groups, role_map)
    if not role:
        raise SSOError(
            "%s signed in successfully but is not in any group that grants console "
            "access. Ask the platform owner to add you to a SaaS-ITH role group."
            % ident["upn_raw"])

    owner_set = {o.strip().lower() for o in (owners or []) if o and o.strip()}
    # Prod-write is an explicit allowlist on top of the role. SaaS-ITH-SA
    # currently holds two people, but the platform decision is that production
    # writes are the named owner's alone until that is widened deliberately.
    is_owner = ident["upn"] in owner_set and role == "platform-owner"

    return {
        "user": ident["upn_raw"],
        "upn": ident["upn"],
        "name": ident["name"],
        "oid": ident["oid"],
        "auth": "entra",
        "role": role,
        "groups": groups,
        "can_write": role in WRITE_ROLES,
        "can_write_prod": is_owner,
        "issued": int(time.time()),
    }


def logout_url(s, post_logout="/"):
    return authority(s["tenant_id"]) + "/oauth2/v2.0/logout?" + urllib.parse.urlencode(
        {"post_logout_redirect_uri": urllib.parse.urljoin(s["redirect_uri"], post_logout)})
