"""Where a ticket's devices physically sit.

Collects the rack-mounted configuration items linked to a ticket (the same
rack, U position and face the CMDB already stores, from NetBox or manual
entry) and decides whether the ticket's assignment group is a Data Center
team, whose tickets open on the Affected CIs tab with the rack view.
"""
from serviceops_core.ci_class_policy import ci_class_read_allowed

DATA_CENTER_GROUP_TYPE = "Data Center"
_ROLE_ORDER = {"Primary CI": 0, "Affected CI": 1}


def is_data_center_group(group):
    return bool(group) and group.group_type == DATA_CENTER_GROUP_TYPE


def rack_label(ci):
    """"B4-12 · Tokyo DC1 · U22, front", or "" for a CI with no rack."""
    if not ci or not ci.rack_id or not ci.rack:
        return ""
    parts = [ci.rack.name]
    if ci.rack.site:
        parts.append(ci.rack.site)
    if ci.rack_position is not None:
        position = int(ci.rack_position) if ci.rack_position == int(ci.rack_position) else ci.rack_position
        parts.append(f"U{position}" + (f", {ci.rack_face}" if ci.rack_face else ""))
    return " · ".join(parts)


def rack_mounted_cis(ci_links, tenant_id, role, extra_ci=None):
    """The linked CIs that have a rack placement and whose class `role` may
    read, primary CI first, each CI once. `extra_ci` is a CI shown on the
    form but not linked through TaskCI (a change's governance CI)."""
    ordered = sorted(ci_links, key=lambda link: _ROLE_ORDER.get(link.relationship_role, 2))
    candidates = ([extra_ci] if extra_ci else []) + [link.ci for link in ordered]
    seen, mounted = set(), []
    for ci in candidates:
        if not ci or ci.id in seen or not ci.rack_id or not ci.rack:
            continue
        seen.add(ci.id)
        if ci_class_read_allowed(tenant_id, ci.ci_class, role):
            mounted.append(ci)
    return mounted
