"""Directory access policy: which directory groups grant which ServiceOps
access level, who may sign in at all, and how a user's groups are resolved
(direct memberOf, nested AD groups, or an OpenLDAP-style group search).

Login (app.ldap_authenticate), the scheduled sync (ldap_sync.sync_directory)
and the administrator's "check a user" tool all use these helpers, so a
mapping always means the same thing everywhere.
"""
import json

from ldap3 import SUBTREE
from ldap3.utils.conv import escape_filter_chars

from serviceops_core.identity import normalized_directory_groups

# Access levels an administrator may map a directory group to. Platform
# administrator (superadmin) is deliberately not offered: it spans every
# organization on the installation and is granted only by hand.
ACCESS_LEVELS = ("requester", "agent", "manager", "admin")
ACCESS_LEVEL_LABELS = {
    "requester": "Requester (regular access)",
    "agent": "Agent",
    "manager": "Manager",
    "admin": "Administrator",
}
# AD's LDAP_MATCHING_RULE_IN_CHAIN: matches every group the user belongs to,
# directly or through any depth of nested groups.
AD_IN_CHAIN_RULE = "1.2.840.113556.1.4.1941"
MAX_RESOLVED_GROUPS = 1000


def role_mappings():
    """The configured {directory group: access level} mappings."""
    import app as core_app
    try:
        mappings = json.loads(core_app.setting_value("LDAP_ROLE_MAPPINGS", "{}"))
    except (TypeError, json.JSONDecodeError):
        return {}
    return {str(group): role for group, role in mappings.items()} if isinstance(mappings, dict) else {}


def matched_access_groups(groups, mappings=None):
    """The configured mappings this user's groups match, as {group: role}."""
    mappings = role_mappings() if mappings is None else mappings
    normalized = normalized_directory_groups(groups)
    return {
        group: role for group, role in mappings.items()
        if str(group).strip().casefold() in normalized
    }


def mapped_groups(groups, tenant_id=None):
    """The active ServiceOps groups whose AD/LDAP mappings these directory
    groups match."""
    from app import DirectoryGroupMapping, SupportGroup
    aliases = normalized_directory_groups(groups)
    if not aliases:
        return []
    query = DirectoryGroupMapping.query.join(SupportGroup).filter(
        DirectoryGroupMapping.active.is_(True), SupportGroup.active.is_(True),
    )
    if tenant_id is not None:
        query = query.filter(SupportGroup.tenant_id == tenant_id)
    found = {}
    for mapping in query:
        if mapping.directory_group.strip().casefold() in aliases:
            found[mapping.support_group.id] = mapping.support_group
    return sorted(found.values(), key=lambda group: group.name)


def sign_in_allowed(groups, tenant_id=None):
    """With LDAP_REQUIRE_ACCESS_GROUP on, only directory users in an AD/LDAP
    group mapped to a ServiceOps group (or to an LDAP_ROLE_MAPPINGS level)
    may sign in; otherwise every directory user may, with the default access."""
    import app as core_app
    if not core_app.setting_bool("LDAP_REQUIRE_ACCESS_GROUP", False):
        return True
    return bool(matched_access_groups(groups) or mapped_groups(groups, tenant_id))


def resolve_groups(connection, user_dn, username, member_of):
    """Every group DN the user belongs to: the entry's own memberOf, plus
    nested AD groups (LDAP_NESTED_GROUPS) and groups found by
    LDAP_GROUP_SEARCH_FILTER for directories without memberOf. A failed
    lookup keeps the direct groups rather than failing the sign-in."""
    import app as core_app
    groups = [str(group) for group in (member_of or [])]
    base_dn = core_app.setting_value("LDAP_GROUP_BASE_DN", "") or core_app.setting_value("LDAP_BASE_DN", "")
    filters = []
    if user_dn and core_app.setting_bool("LDAP_NESTED_GROUPS", False):
        filters.append(f"(member:{AD_IN_CHAIN_RULE}:={escape_filter_chars(user_dn)})")
    template = core_app.setting_value("LDAP_GROUP_SEARCH_FILTER", "").strip()
    if template:
        filters.append(
            template.replace("{dn}", escape_filter_chars(user_dn or ""))
            .replace("{username}", escape_filter_chars(username or ""))
        )
    for search_filter in filters:
        try:
            found = connection.search(
                base_dn, search_filter, search_scope=SUBTREE, attributes=[],
                size_limit=MAX_RESOLVED_GROUPS,
            )
        except Exception as error:  # noqa: BLE001 - keep the direct groups
            core_app.current_app.logger.warning("LDAP group lookup failed: %s", type(error).__name__)
            continue
        if found:
            groups.extend(entry.entry_dn for entry in connection.entries)
    seen, unique = set(), []
    for group in groups:
        key = group.strip().casefold()
        if key and key not in seen:
            seen.add(key)
            unique.append(group.strip())
    return unique


def server_uris(raw):
    """LDAP_SERVER_URI may list several servers (space or comma separated),
    tried in order, so sign-in survives one domain controller being down."""
    return [uri for uri in raw.replace(",", " ").split() if uri]


def check_user(username):
    """What sign-in would grant `username`, without signing them in: the
    directory entry found, its resolved groups, the access mappings it
    matches, the resulting access level and teams, and whether sign-in is
    allowed. Reads the directory with the service account only."""
    import app as core_app
    from app import current_user

    local_part = core_app.ldap_login_local_part(username)
    _server, service = core_app.ldap_server_and_service_connection()
    try:
        search_filter = core_app.setting_value(
            "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
        ).replace("{username}", escape_filter_chars(local_part))
        service.search(
            core_app.setting_value("LDAP_BASE_DN", ""), search_filter, search_scope=SUBTREE,
            attributes=["memberOf", "displayName", "userAccountControl"], size_limit=2,
        )
        entries = list(service.entries)
        if len(entries) != 1:
            return {"username": local_part, "found": False, "matches": len(entries)}
        entry = entries[0]
        values = entry.entry_attributes_as_dict
        groups = resolve_groups(service, entry.entry_dn, local_part, values.get("memberOf", []))
    finally:
        service.unbind()
    matched = matched_access_groups(groups)
    roles = set(core_app.mapped_roles(groups, "LDAP_ROLE_MAPPINGS"))
    teams = []
    for group in mapped_groups(groups, current_user.tenant_id):
        group_roles = core_app.group_access_roles(group)
        roles.update(group_roles)
        teams.append(group.name + (f" ({', '.join(group_roles)})" if group_roles else ""))
    control = (values.get("userAccountControl") or [None])[0]
    try:
        disabled = bool(int(control) & 2)
    except (TypeError, ValueError):
        disabled = False
    return {
        "username": local_part,
        "found": True,
        "dn": entry.entry_dn,
        "name": (values.get("displayName") or [local_part])[0],
        "groups": [group[:120] for group in groups[:25]],
        "group_count": len(groups),
        "matched": matched,
        "access_level": max(roles, key=lambda role: core_app.ROLE_RANK.get(role, -1)),
        "roles": sorted(roles, key=lambda role: -core_app.ROLE_RANK.get(role, -1)),
        "teams": teams,
        "allowed": sign_in_allowed(groups, current_user.tenant_id) and not disabled,
        "disabled": disabled,
    }
