"""Read-only Active Directory access registry and local change proposals.

Active Directory remains authoritative.  This module reads group evidence over
LDAP and records proposed work in SubAdmin's SQLite database; it never writes to
the directory.
"""
import json
import re
import sqlite3
import time
from datetime import datetime, timezone


GROUP_PREFIX = ("saas-ith-",)  # role groups and approver groups (IT Hub convention); str.startswith takes the tuple
GROUP_NAME = re.compile(r"^SaaS-ITH-[A-Za-z0-9][A-Za-z0-9 &_.-]{1,79}$", re.I)
PROPOSAL_ACTIONS = {
    "create": "Create a role group",
    "change": "Change an existing group",
    "review": "Review and attest access",
    "retire": "Retire a group",
}
REVIEW_CYCLES = {
    "monthly": "Monthly",
    "quarterly": "Quarterly",
    "semiannual": "Twice a year",
    "annual": "Annual",
}
_CACHE = {"ts": 0.0, "data": None, "error": None}
_TTL = 120.0


def init(db_path):
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """CREATE TABLE IF NOT EXISTS access_governance_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft',
                action TEXT NOT NULL,
                group_name TEXT NOT NULL,
                purpose TEXT NOT NULL,
                business_owner TEXT NOT NULL,
                technical_owner TEXT NOT NULL,
                review_cycle TEXT NOT NULL,
                resources_json TEXT NOT NULL DEFAULT '[]',
                notes TEXT NOT NULL DEFAULT ''
            )"""
        )
        con.commit()
    finally:
        con.close()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _cn(value):
    text = str(value or "").strip()
    head = text.split(",", 1)[0]
    return head[3:].replace("\\,", ",").strip() if head.lower().startswith("cn=") else text


def _group_scope(group_type):
    try:
        value = int(group_type or 0) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return "unknown", False
    scope = "universal" if value & 0x8 else "domain local" if value & 0x4 else "global" if value & 0x2 else "unknown"
    return scope, bool(value & 0x80000000)


def _changed_at(value):
    text = str(value or "").strip()
    match = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", text)
    if match:
        year, month, day, hour, minute, _second = match.groups()
        return "%s-%s-%s %s:%s UTC" % (year, month, day, hour, minute)
    return text[:19].replace("T", " ") if text else "unknown"


def _directory_read(ldap_cfg):
    import ldap3

    server = ldap3.Server(ldap_cfg["url"], get_info=None, connect_timeout=8)
    conn = ldap3.Connection(
        server, user=ldap_cfg["bind_user"], password=ldap_cfg["bind_pass"],
        auto_bind=False, receive_timeout=15, raise_exceptions=False,
    )
    if not conn.bind():
        raise RuntimeError("directory bind failed")
    try:
        ok = conn.search(
            ldap_cfg["base_dn"],
            "(&(objectCategory=group)(cn=SaaS-ITH-*))",
            attributes=["cn", "description", "managedBy", "member", "whenChanged",
                        "groupType", "distinguishedName"],
            size_limit=250,
        )
        if not ok:
            raise RuntimeError("directory group search failed")
        out = []
        for entry in conn.entries:
            raw = entry.entry_attributes_as_dict
            name = str((raw.get("cn") or [""])[0]).strip()
            if not name:
                continue
            members = sorted(str(v).strip().lower() for v in (raw.get("member") or []) if str(v).strip())
            scope, security = _group_scope((raw.get("groupType") or [0])[0])
            changed = (raw.get("whenChanged") or [None])[0]
            out.append({
                "key": name.lower(),
                "name": name,
                "description": str((raw.get("description") or [""])[0]).strip(),
                "owner": _cn((raw.get("managedBy") or [""])[0]),
                "members": members,
                "member_count": len(members),
                "scope": scope,
                "security": security,
                "changed": _changed_at(changed),
            })
        return sorted(out, key=lambda row: row["name"].lower())
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def directory_groups(ldap_cfg, now=None):
    stamp = time.time() if now is None else float(now)
    if _CACHE["data"] is not None and stamp - _CACHE["ts"] < _TTL:
        return _CACHE["data"], _CACHE["error"]
    try:
        data = _directory_read(ldap_cfg)
        _CACHE.update(ts=stamp, data=data, error=None)
    except Exception as exc:
        # A failed refresh must never replace the last known good evidence.
        if _CACHE["data"] is None:
            _CACHE.update(ts=stamp, data=[], error=str(exc)[:180])
        else:
            _CACHE.update(ts=stamp, error=str(exc)[:180])
    return _CACHE["data"], _CACHE["error"]


def assemble(groups, role_map, permission_policy, capabilities, policy_rows):
    """Join AD records to every enforcement reference SubAdmin already knows."""
    by_key = {g["key"]: dict(g) for g in groups}
    referenced = set(role_map)
    cap_labels = {c.key: c.label for c in capabilities}
    cap_refs = {}
    for cap_key, granted in permission_policy.items():
        for group in granted or []:
            key = str(group).strip().lower()
            referenced.add(key)
            cap_refs.setdefault(key, []).append(cap_labels.get(cap_key, cap_key))
    site_refs = {}
    for fqdn, rule in policy_rows:
        if rule.get("mode") != "groups":
            continue
        for group in rule.get("groups") or []:
            key = str(group).strip().lower()
            referenced.add(key)
            site_refs.setdefault(key, []).append(fqdn)

    # A referenced group missing from AD is still a registry record, because
    # the broken reference is the most important evidence on the page.
    for key in sorted(referenced):
        if key.startswith(GROUP_PREFIX) and key not in by_key:
            by_key[key] = {
                "key": key, "name": key, "description": "", "owner": "",
                "members": [], "member_count": None, "scope": "unknown",
                "security": None, "changed": "unknown", "missing": True,
            }

    member_sets = {}
    for row in by_key.values():
        signature = tuple(row.get("members") or [])
        if signature:
            member_sets.setdefault(signature, []).append(row["key"])

    registry = []
    findings = []
    for key, row in by_key.items():
        row = dict(row)
        row["role"] = role_map.get(key)
        row["capabilities"] = sorted(cap_refs.get(key, []))
        row["sites"] = sorted(site_refs.get(key, []))
        row["referenced"] = key in referenced
        row["duplicates"] = [k for k in member_sets.get(tuple(row.get("members") or []), []) if k != key]
        issues = []
        if row.get("missing"):
            issues.append(("critical", "Referenced by policy but not found in AD"))
        else:
            if row.get("security") is False:
                issues.append(("critical", "Group is not security-enabled"))
            if not row.get("owner"):
                issues.append(("warning", "No AD managedBy owner"))
            if not row.get("description"):
                issues.append(("warning", "No AD purpose description"))
            if row.get("member_count") == 0 and row["referenced"]:
                issues.append(("warning", "Referenced group has no direct members"))
            if row["duplicates"]:
                issues.append(("review", "Same direct membership as %s" % ", ".join(row["duplicates"])))
            if not row["referenced"]:
                issues.append(("review", "No SubAdmin role, capability, or site reference"))
        row["issues"] = issues
        row["level"] = ("critical" if any(level == "critical" for level, _ in issues)
                        else "warning" if any(level == "warning" for level, _ in issues)
                        else "review" if issues else "healthy")
        registry.append(row)
        for level, message in issues:
            findings.append({"level": level, "group": row["name"], "message": message})

    order = {"critical": 0, "warning": 1, "review": 2, "healthy": 3}
    registry.sort(key=lambda row: (order[row["level"]], row["name"].lower()))
    findings.sort(key=lambda item: (order.get(item["level"], 9), item["group"].lower(), item["message"]))
    return registry, findings


def proposals(conn, limit=20):
    rows = conn.execute(
        "SELECT * FROM access_governance_proposals ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["resources"] = json.loads(item.pop("resources_json"))
        except (TypeError, ValueError):
            item["resources"] = []
        item["action_label"] = PROPOSAL_ACTIONS.get(item["action"], item["action"])
        item["review_label"] = REVIEW_CYCLES.get(item["review_cycle"], item["review_cycle"])
        out.append(item)
    return out


def validate_proposal(form):
    action = str(form.get("action") or "").strip().lower()
    group_name = str(form.get("group_name") or "").strip()
    purpose = str(form.get("purpose") or "").strip()
    business_owner = str(form.get("business_owner") or "").strip()
    technical_owner = str(form.get("technical_owner") or "").strip()
    review_cycle = str(form.get("review_cycle") or "").strip().lower()
    resources = [part.strip() for part in str(form.get("resources") or "").splitlines() if part.strip()]
    notes = str(form.get("notes") or "").strip()
    errors = []
    if action not in PROPOSAL_ACTIONS:
        errors.append("Choose a proposal type.")
    if not GROUP_NAME.fullmatch(group_name):
        errors.append("Group name must start with SaaS-ITH- and use the approved naming characters.")
    if len(purpose) < 12:
        errors.append("Describe the business purpose in at least 12 characters.")
    if not business_owner:
        errors.append("Name the business owner.")
    if not technical_owner:
        errors.append("Name the technical owner.")
    if review_cycle not in REVIEW_CYCLES:
        errors.append("Choose a review cycle.")
    if not resources:
        errors.append("List at least one intended site, page, or console capability.")
    return ({
        "action": action, "group_name": group_name, "purpose": purpose[:500],
        "business_owner": business_owner[:160], "technical_owner": technical_owner[:160],
        "review_cycle": review_cycle, "resources": resources[:50], "notes": notes[:2000],
    }, errors)


def save_proposal(conn, user, data):
    cur = conn.execute(
        """INSERT INTO access_governance_proposals
           (created_at,created_by,status,action,group_name,purpose,business_owner,
            technical_owner,review_cycle,resources_json,notes)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (_now(), user, "draft", data["action"], data["group_name"], data["purpose"],
         data["business_owner"], data["technical_owner"], data["review_cycle"],
         json.dumps(data["resources"], ensure_ascii=True), data["notes"]),
    )
    conn.commit()
    return cur.lastrowid


def build(A, ctx):
    try:
        ldap_cfg = A._ldap_cfg()
        groups, directory_error = directory_groups(ldap_cfg)
    except Exception as exc:
        groups, directory_error = [], str(exc)[:180]
    registry, findings = assemble(
        groups, A.sso_mod.GROUP_ROLE_MAP, ctx["policy"], A.permissions.CAPABILITIES,
        ctx["policy_rows"],
    )
    ctx.update(
        access_registry=registry,
        access_findings=findings,
        access_directory_error=directory_error,
        access_summary={
            "groups": len(registry),
            "attention": sum(1 for row in registry if row["level"] in ("critical", "warning")),
            "unowned": sum(1 for row in registry if not row.get("owner") and not row.get("missing")),
            "unreferenced": sum(1 for row in registry if not row.get("referenced")),
        },
        access_proposals=proposals(A.db()),
        access_proposal_actions=PROPOSAL_ACTIONS,
        access_review_cycles=REVIEW_CYCLES,
    )
