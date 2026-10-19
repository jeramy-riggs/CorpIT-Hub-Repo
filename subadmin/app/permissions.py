"""Console capability permissions, granted to Active Directory security groups.

Before this, who could do what was decided by decorators in app.py: nearly every
action was `@login_required`, which meant any account that could open the console
could also delete a production vhost. Changing that meant editing code.

Now every privileged action is a named capability, and a capability is granted to
AD security groups from the console's Identity & Access section. Group membership
is already resolved at sign-in and carried in the session, so a check here is a
set intersection - no directory round trip on the request path.

Three properties are deliberate:

* **Default deny.** A capability with no groups is owner-only. A policy file that
  is missing, unreadable or corrupt yields the built-in defaults, which are the
  tightest sensible set - never "allow everything".
* **The platform owner always holds every capability.** This is the ladder guard:
  no combination of edits on the page can lock every administrator out of the
  console. It is why `permissions.manage` is not editable.
* **Grants name groups, not people.** There is no per-user list to drift out of
  step with the directory; removing someone from the AD group removes their
  access at their next sign-in.

Because groups are read at sign-in, a change here reaches anyone already signed in
only when they sign in again. The page says so.
"""
import json
import os
import tempfile

# Only groups the sign-in path actually resolves can ever match. sso.ad_groups_for
# returns the user's `saas-ith-*` group CNs, lowercased, and nothing else -
# so offering any other group name in the console would be offering a control that
# silently never fires.
# str.startswith accepts the tuple. SaaS-ITH-* covers the role groups and, since
# 2026-10-08, the approver groups too (IT Hub convention).
GROUP_PREFIX = ("saas-ith-",)

OWNER_ROLE = "platform-owner"


class Capability:
    def __init__(self, key, label, group, help, default=(), danger=False,
                 editable=True):
        self.key = key
        self.label = label
        self.group = group
        self.help = help
        self.default = tuple(default)
        self.danger = danger
        self.editable = editable


# Grouped the way the console is: the section a capability belongs to.
CAPABILITIES = [
    Capability(
        "subdomain.create", "Create a subdomain", "Subdomains",
        "Provisions the certificate, CSR and nginx vhost, and pushes the DNS record. "
        "Creates a real, resolvable name on the estate.",
        default=("saas-ith-hd",)),
    Capability(
        "subdomain.dns", "Push DNS", "Subdomains",
        "Creates or re-verifies the A record on all three domain controllers. Safe to "
        "re-run; the helper refuses to repoint a name that already points elsewhere.",
        default=("saas-ith-hd",)),
    Capability(
        "subdomain.cert", "Deploy a certificate", "Subdomains",
        "Installs a CA-signed certificate and reloads nginx. Verified against the "
        "site's private key before anything changes.",
        default=("saas-ith-hd",)),
    Capability(
        "subdomain.delete", "Remove a subdomain", "Subdomains",
        "Deletes the vhost and certificate. The DNS record is left pointing at a host "
        "that no longer answers for it. Not reversible from the console.",
        danger=True),
    Capability(
        "subdomain.access", "Change who may open a site", "Subdomains",
        "Rewrites the access policy the sign-in gate enforces for a site. This is the "
        "control that decides who can see a site at all.",
        danger=True),
    Capability(
        "change.request", "Raise a change for approval", "Change control",
        "Sends a change out for approval. Refused while any preflight check is "
        "failing, so it cannot be used to route around the validation gate.",
        default=("saas-ith-hd",)),
    Capability(
        "change.approve", "Approve or reject a change", "Change control",
        "Records a decision against one approval slot. Two approvals release a "
        "change to the deploy stage; one rejection returns it to preflight.",
        danger=True),
    Capability(
        "links.manage", "Manage the link directory", "Link directory",
        "Adds, edits, reorders, hides and removes entries, and rebuilds the published "
        "static hub page.",
        default=("saas-ith-hd",)),
    Capability(
        "landing.manage", "Edit the CorpIT home page", "CorpIT Hub",
        "Adds, edits, hides and reorders the links and sections on the CorpIT Hub home "
        "page, picks their icons, and publishes the result. Every save goes live right away.",
        default=("saas-ith-hd",)),
    Capability(
        "directory.sync", "Start a directory sync", "Directory Sync",
        "Kicks a manual sync. Holds a lock, so a second run is refused rather than "
        "started twice.",
        default=("saas-ith-hd",)),
    Capability(
        "directory.manage", "Manage lists, recipients and who is held back", "Directory Sync",
        "Creates, enables, disables and deletes address lists, changes who receives "
        "them, and holds people back from the directory (left out, or published without "
        "their numbers). Removing a recipient cleans that list's contacts out of their "
        "mailbox on the next sync. Nothing here changes Active Directory or Exchange.",
        danger=True, default=("saas-ith-hd",)),
    Capability(
        "housekeeping.run", "Run cleanup", "System",
        "Deletes aged backup files and ages out routine audit rows, within the "
        "retention set under Housekeeping. The list shown before the button is the "
        "list that gets deleted.",
        danger=True),
    Capability(
        "settings.manage", "Change platform settings", "System",
        "The settings registry, including the sign-in configuration. Granting this is "
        "close to granting ownership - a change here decides how everyone signs in.",
        danger=True),
    Capability(
        "permissions.manage", "Change these permissions", "System",
        "Reserved to the platform owner and not editable. If this could be delegated or "
        "removed, one bad edit could lock every administrator out of the console with no "
        "way back in.",
        danger=True, editable=False),
    Capability(
        "access.propose", "Record an access-governance proposal", "Identity & Access",
        "Records a reviewed plan for an AD group without changing Active Directory. "
        "The proposal remains draft evidence until a separately controlled process applies it.",
        default=("saas-ith-hd",)),
]

BY_KEY = {c.key: c for c in CAPABILITIES}
CAP_GROUPS = list(dict.fromkeys(c.group for c in CAPABILITIES))


def defaults():
    return {c.key: list(c.default) for c in CAPABILITIES}


def normalise(raw):
    """Coerce whatever is on disk into {known capability: [known-shaped group]}.

    Unknown keys are dropped rather than carried, and every group name is
    lowercased and prefix-checked, so a hand-edited file cannot introduce a grant
    the console would not have offered.
    """
    out = defaults()
    if not isinstance(raw, dict):
        return out
    for key, groups in raw.items():
        cap = BY_KEY.get(key)
        if cap is None or not cap.editable:
            continue
        if not isinstance(groups, list):
            continue
        clean, seen = [], set()
        for g in groups:
            g = str(g).strip().lower()
            if g and g.startswith(GROUP_PREFIX) and g not in seen:
                seen.add(g)
                clean.append(g)
        out[key] = clean
    return out


def load(path):
    """The policy on disk, or the built-in defaults. Never raises: a missing or
    unreadable policy must fall back to the tight defaults, not to nothing."""
    try:
        with open(path, encoding="utf-8") as fh:
            return normalise(json.load(fh))
    except (OSError, json.JSONDecodeError, ValueError):
        return defaults()


def save(path, policy):
    """Write atomically at 0600, same discipline as config.json."""
    policy = normalise(policy)
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".permissions.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(policy, fh, indent=2, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return policy


def session_groups(sess):
    """The AD groups on this session, lowercased. Empty for a local account."""
    ctx = sess.get("sso") or {}
    return {str(g).strip().lower() for g in (ctx.get("groups") or []) if str(g).strip()}


def allowed(policy, cap_key, sess, is_owner):
    """May this session use this capability?

    The owner check comes first and is unconditional - that is the ladder guard.
    Everything else is a set intersection against the grant, and an unknown
    capability is denied rather than allowed.
    """
    if is_owner:
        return True
    cap = BY_KEY.get(cap_key)
    if cap is None or not cap.editable:
        return False
    granted = set(policy.get(cap_key) or ())
    if not granted:
        return False
    return bool(granted & session_groups(sess))


def diff(before, after):
    """[(capability label, added, removed)] for the audit log."""
    out = []
    for cap in CAPABILITIES:
        b, a = set(before.get(cap.key) or ()), set(after.get(cap.key) or ())
        if b != a:
            out.append((cap.label, sorted(a - b), sorted(b - a)))
    return out
