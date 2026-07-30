"""Generic, schema-agnostic LDAP/AD directory synchronization.

This module populates ServiceOps profile fields (title, department, division,
employee_id, employee_type), the manager reporting chain (User.manager_id),
and AD-group-driven team membership (GroupMember / DirectoryManagedMembership)
from an existing LDAP/AD directory, using the same bind, StartTLS, and
attribute-matching conventions already used by interactive LDAP login
(app.ldap_authenticate).

It intentionally does not:
  * create new ServiceOps users (only already-provisioned LDAP identities are
    updated — see ``ldap_authenticate``/``provision_external_user``),
  * run on a schedule (manual trigger only; see app.py's admin route),
  * mutate approval-resolution logic (Approval/CCB code is unchanged; it
    merely benefits from the more complete User/GroupMember data this
    produces).

Attribute names are entirely admin-configurable via the LDAP_ATTR_MAP
setting so this works against AD or OpenLDAP schemas without any
hard-coded company-specific attribute, OU, or domain assumptions.
"""
import json
from ldap3 import SUBTREE

DEFAULT_ATTR_MAP = {
    "title": "title",
    "department": "department",
    "division": "division",
    "employee_id": "employeeID",
    "employee_type": "employeeType",
    "manager": "manager",
    "email": "mail",
    "display_name": "displayName",
    "username": "sAMAccountName",
}

# ServiceOps User columns populated from directory attributes (excludes
# "manager", "email", "display_name", "username" which are handled separately).
PROFILE_FIELDS = ("title", "department", "division", "employee_id", "employee_type")


class DirectorySyncError(RuntimeError):
    """Raised for conditions that must abort the whole sync (e.g. bad tenant)."""


def _attr_map():
    import app as core_app
    try:
        mapping = json.loads(core_app.setting_value("LDAP_ATTR_MAP", "{}"))
    except (json.JSONDecodeError, TypeError):
        mapping = {}
    merged = dict(DEFAULT_ATTR_MAP)
    if isinstance(mapping, dict):
        merged.update({k: v for k, v in mapping.items() if isinstance(v, str) and v})
    return merged


def _first(values_dict, attr_name):
    values = values_dict.get(attr_name)
    if not values:
        return None
    value = values[0] if isinstance(values, list) else values
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def sync_directory(tenant_id, dry_run=False):
    """Synchronize directory-sourced profile fields, manager chain, and
    AD-group team membership for every LDAP-provisioned user in ``tenant_id``.

    Fails closed: a missing/invalid tenant_id raises DirectorySyncError rather
    than silently defaulting to any particular tenant.
    """
    import app as core_app
    from app import db

    if not tenant_id or not isinstance(tenant_id, int):
        raise DirectorySyncError("A valid integer tenant_id is required; refusing to sync.")
    tenant = db.session.get(core_app.Tenant, tenant_id)
    if not tenant or not tenant.active:
        raise DirectorySyncError(f"Tenant {tenant_id} does not exist or is inactive; refusing to sync.")
    if not core_app.setting_bool("LDAP_ENABLED"):
        raise DirectorySyncError("LDAP is not enabled; refusing to sync.")

    summary = {
        "tenant_id": tenant_id,
        "dry_run": bool(dry_run),
        "directory_entries": 0,
        "users_updated": 0,
        "managers_resolved": 0,
        "memberships_added": 0,
        "memberships_removed": 0,
        "users_unmatched": 0,
        "errors": [],
    }

    server, service = core_app.ldap_server_and_service_connection()
    try:
        attr_map = _attr_map()
        wanted_attrs = sorted(set(attr_map.values()) | {"memberOf", "distinguishedName"})
        search_filter = core_app.setting_value(
            "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
        ).replace("{username}", "*")
        base_dn = core_app.setting_value("LDAP_BASE_DN", "")
        if not service.search(base_dn, search_filter, search_scope=SUBTREE, attributes=wanted_attrs):
            summary["errors"].append("Directory search returned no results or failed.")
            return summary
        entries = list(service.entries)
    finally:
        try:
            service.unbind()
        except Exception:
            pass

    summary["directory_entries"] = len(entries)

    # Tenant-scoped DN -> User map, built the same way ldap_authenticate
    # identifies an existing ServiceOps user from an LDAP entry: via the
    # ExternalIdentity row created at first LDAP login (provider="ldap",
    # subject=<entry DN>). Only already-provisioned users are touched.
    identities = (
        core_app.ExternalIdentity.query
        .filter_by(provider="ldap")
        .join(core_app.User, core_app.ExternalIdentity.user_id == core_app.User.id)
        .filter(core_app.User.tenant_id == tenant_id)
        .all()
    )
    dn_to_user = {identity.subject.strip().casefold(): identity.user for identity in identities}

    for entry in entries:
        entry_dn = getattr(entry, "entry_dn", None) or ""
        values = entry.entry_attributes_as_dict
        user = dn_to_user.get(entry_dn.strip().casefold())
        if not user:
            summary["users_unmatched"] += 1
            continue
        if user.tenant_id != tenant_id:
            # Defense in depth: never mutate another tenant's user even if the
            # identity map above were somehow built incorrectly.
            summary["errors"].append(f"Skipped user outside tenant scope: {entry_dn}")
            continue

        try:
            changed = False
            for field in PROFILE_FIELDS:
                ldap_attr = attr_map.get(field)
                if not ldap_attr:
                    continue
                value = _first(values, ldap_attr)
                if value is None:
                    # Sparse directory entry: never null out existing data.
                    continue
                if getattr(user, field, None) != value:
                    setattr(user, field, value)
                    changed = True

            manager_dn = _first(values, attr_map.get("manager", "manager"))
            if manager_dn:
                manager_user = dn_to_user.get(manager_dn.strip().casefold())
                if manager_user and manager_user.id != user.id:
                    if user.manager_id != manager_user.id:
                        user.manager_id = manager_user.id
                        changed = True
                    summary["managers_resolved"] += 1
                # Manager DN out of scope/filter: leave manager_id unchanged,
                # do not error the whole sync.

            if changed:
                summary["users_updated"] += 1

            groups = values.get("memberOf") or []
            before_ids = {
                m.group_id for m in core_app.DirectoryManagedMembership.query
                .filter_by(user_id=user.id).all()
            }
            core_app.sync_directory_team_memberships(user, groups)
            db.session.flush()
            after_ids = {
                m.group_id for m in core_app.DirectoryManagedMembership.query
                .filter_by(user_id=user.id).all()
            }
            summary["memberships_added"] += len(after_ids - before_ids)
            summary["memberships_removed"] += len(before_ids - after_ids)
        except Exception as error:  # noqa: BLE001 - isolate one bad entry from the whole sync
            summary["errors"].append(f"{entry_dn or '(unknown dn)'}: {type(error).__name__}")

    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()

    return summary
