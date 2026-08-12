"""Pure identity/directory logic shared by app.py's LDAP and role-mapping
code -- no Flask, database, or network dependency, matching the bounded-
interface pattern already established by serviceops_core.security. Anything
here that needs a live setting value, an LDAP connection, or the database
stays a thin wrapper in app.py that calls into this module.
"""
from serviceops_models import ROLE_RANK


def ldap_login_local_part(username):
    """Strip a UPN suffix (user@company.com) or down-level domain prefix
    (CORP\\user) so any of the three Windows login forms a user might type
    still resolve to the same bare account name. Returns the input
    unchanged if it carries neither form.
    """
    if "\\" in username:
        return username.split("\\", 1)[1]
    if "@" in username:
        return username.split("@", 1)[0]
    return username


def ldap_domain_suffix_from_base_dn(base_dn):
    """Best-effort UPN-style domain suffix derived from an LDAP base DN's
    DC= components (e.g. "DC=corp,DC=example,DC=com" -> "corp.example.com").
    Display-only -- a real UPN suffix can differ from the base DN's domain
    components -- so this never affects what ldap_authenticate() actually
    accepts, only the login form's placeholder text.
    """
    domain_parts = [
        part.split("=", 1)[1].strip()
        for part in base_dn.split(",")
        if part.strip().upper().startswith("DC=") and part.split("=", 1)[1].strip()
    ]
    return ".".join(domain_parts)


def normalized_directory_groups(groups):
    """Return case-insensitive full-DN and first-CN aliases for AD
    memberships, so a mapping configured against either form matches."""
    normalized = set()
    for value in groups or []:
        group = str(value).strip()
        if not group:
            continue
        normalized.add(group.casefold())
        first_rdn = group.split(",", 1)[0].strip()
        if first_rdn.casefold().startswith("cn="):
            normalized.add(first_rdn[3:].strip().casefold())
    return normalized


def match_directory_role_mappings(groups, mappings, configured_default, default="requester"):
    """Map directory/realm groups to every ServiceOps role they grant,
    without trusting user input. Returns {role: matched_group_or_None} --
    a user can match more than one configured group mapping and so hold
    more than one role at once (e.g. a "gg_admins" group granting admin
    alongside a "gg_managers" group granting manager). Falls back to
    `configured_default` (a single entry with no matched group) when
    nothing matched.

    `mappings` is the already-parsed {directory_group: role} dict (the
    caller owns fetching/parsing the setting's raw JSON); `configured_default`
    is the caller's already-fetched fallback-role setting value.
    """
    normalized = normalized_directory_groups(groups)
    matched = {}
    for group, role in mappings.items():
        if role in ROLE_RANK and str(group).strip().casefold() in normalized:
            matched[role] = str(group).strip()
    if matched:
        return matched
    return {configured_default if configured_default in ROLE_RANK else default: None}
