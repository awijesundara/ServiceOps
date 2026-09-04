"""Generic, schema-agnostic LDAP/AD directory synchronization.

This module populates ServiceOps profile fields (title, department, division,
employee_id, employee_type), the manager reporting chain (User.manager_id),
and AD-group-driven team membership (GroupMember / DirectoryManagedMembership)
from an existing LDAP/AD directory, using the same bind, StartTLS, and
attribute-matching conventions already used by interactive LDAP login
(app.ldap_authenticate).

By default it updates already-provisioned identities and pre-provisions only
missing managers.  An administrator can explicitly request ``provision_all``
to create an LDAP-backed ServiceOps profile for every valid directory entry.
Scheduled/background synchronization never enables this mode: bulk account
creation is an intentional, audited administrator action.
  * run on a schedule (manual trigger only; see app.py's admin route),
  * mutate approval-resolution logic (Approval/CCB code is unchanged; it
    merely benefits from the more complete User/GroupMember data this
    produces).

Attribute names are entirely admin-configurable via the LDAP_ATTR_MAP
setting so this works against AD or OpenLDAP schemas without any
hard-coded company-specific attribute, OU, or domain assumptions.
"""
import json
import re
import uuid
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from ldap3 import SUBTREE
from ldap3.utils.dn import parse_dn

DEFAULT_ATTR_MAP = {
    "title": "title",
    "department": "department",
    "division": "division",
    "employee_id": "employeeID",
    "employee_type": "employeeType",
    "business_phone": "telephoneNumber",
    "mobile_phone": "mobile",
    "location": "physicalDeliveryOfficeName",
    "manager": "manager",
    "email": "mail",
    "display_name": "displayName",
    "username": "sAMAccountName",
    "team_name": "teamName",
    "user_principal_name": "userPrincipalName",
    "given_name": "givenName",
    "surname": "sn",
    "common_name": "cn",
    "directory_created_at": "whenCreated",
    "directory_changed_at": "whenChanged",
    "last_logon_at": "lastLogonTimestamp",
    "password_last_set_at": "pwdLastSet",
    "account_expires_at": "accountExpires",
    "account_control": "userAccountControl",
    "bad_password_count": "badPwdCount",
    "logon_count": "logonCount",
    "primary_group_id": "primaryGroupID",
    "object_guid": "objectGUID",
    "uid_number": "uidNumber",
    "gid_number": "gidNumber",
    "unix_home_directory": "unixHomeDirectory",
    "login_shell": "loginShell",
    "country_code": "countryCode",
}

# ServiceOps User columns populated from directory attributes (excludes
# "manager", "email", "display_name", "username" which are handled separately).
PROFILE_FIELDS = (
    "title", "department", "division", "employee_id", "employee_type",
    "business_phone", "mobile_phone", "location",
)

DIRECTORY_DETAIL_FIELDS = (
    "user_principal_name", "given_name", "surname", "common_name",
    "team_name", "directory_created_at", "directory_changed_at",
    "last_logon_at", "password_last_set_at", "account_expires_at",
    "bad_password_count", "logon_count", "primary_group_id", "object_guid",
    "uid_number", "gid_number", "unix_home_directory", "login_shell",
    "country_code",
)


def _as_scalar(value):
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return value


def _safe_text(value, limit=500):
    value = _as_scalar(value)
    if value is None or isinstance(value, (bytes, bytearray)):
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _directory_time(value):
    """Normalize AD FILETIME/generalized-time values without exposing raw counters."""
    value = _as_scalar(value)
    if value in (None, "", 0, "0", 9223372036854775807, "9223372036854775807"):
        return None
    if isinstance(value, datetime):
        timestamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc).isoformat()
    text = str(value).strip()
    if re.fullmatch(r"\d{14}(?:\.\d+)?Z", text):
        try:
            return datetime.strptime(text.split(".")[0], "%Y%m%d%H%M%S").replace(
                tzinfo=timezone.utc
            ).isoformat()
        except ValueError:
            return None
    try:
        ticks = int(text)
        if ticks <= 0:
            return None
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=ticks // 10
        )).isoformat()
    except (ValueError, OverflowError):
        return None


def _friendly_group_name(value):
    text = _safe_text(value, 500)
    if not text:
        return None
    try:
        parts = parse_dn(text, escape=True)
        for attribute, name, _separator in parts:
            if attribute.casefold() == "cn":
                return str(name).strip()[:160]
    except (ValueError, TypeError):
        pass
    return text[:160] if "," not in text else None


def directory_profile_payload(values, groups, attr_map=None):
    """Build the allow-listed, display-safe profile snapshot stored by ServiceOps."""
    attr_map = attr_map or _attr_map()
    payload = {}
    time_fields = {
        "directory_created_at", "directory_changed_at", "last_logon_at",
        "password_last_set_at", "account_expires_at",
    }
    for field in DIRECTORY_DETAIL_FIELDS:
        raw = values.get(attr_map.get(field, ""))
        if field in time_fields:
            value = _directory_time(raw)
        elif field == "object_guid":
            scalar = _as_scalar(raw)
            if isinstance(scalar, (bytes, bytearray)) and len(scalar) == 16:
                value = str(uuid.UUID(bytes_le=bytes(scalar)))
            else:
                value = _safe_text(scalar, 80)
        else:
            value = _safe_text(raw)
        if value is not None:
            payload[field] = value
    control_raw = _safe_text(values.get(attr_map.get("account_control", "userAccountControl")), 20)
    if control_raw:
        try:
            control = int(control_raw)
        except ValueError:
            control = None
        if control is not None:
            payload.update({
                "account_enabled": not bool(control & 0x0002),
                "account_locked": bool(control & 0x0010),
                "password_not_required": bool(control & 0x0020),
                "password_never_expires": bool(control & 0x10000),
                "smartcard_required": bool(control & 0x40000),
            })
    friendly_groups = sorted({
        name for name in (_friendly_group_name(group) for group in (groups or [])) if name
    }, key=str.casefold)
    return payload, friendly_groups


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


def sync_directory(tenant_id, dry_run=False, provision_all=False):
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
        "users_provisioned": 0,
        "users_updated": 0,
        "managers_resolved": 0,
        "managers_provisioned": 0,
        "self_manager_skipped": 0,
        "self_manager_users": [],
        "memberships_added": 0,
        "memberships_removed": 0,
        "teams_created": 0,
        "team_managers_inferred": 0,
        "directory_profiles_updated": 0,
        "accounts_deactivated": 0,
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
        entries = []
        for record in service.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=wanted_attrs,
            paged_size=500,
            generator=True,
        ):
            if record.get("type") != "searchResEntry":
                continue
            dn = str(record.get("dn") or "").strip()
            attrs = record.get("attributes") or {}
            entries.append((dn, attrs))
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

    # Every directory entry this search returned, keyed by its own DN --
    # lets a manager DN that resolves to no ServiceOps user yet still be
    # provisioned below, as long as that manager is themselves a real
    # directory entry this search found (never fabricated).
    dn_to_entry = {}
    for entry_dn_raw, entry_values in entries:
        entry_dn = (entry_dn_raw or "").strip().casefold()
        if entry_dn:
            dn_to_entry[entry_dn] = entry_values

    if provision_all:
        for entry_dn_raw, entry_values in entries:
            entry_dn = (entry_dn_raw or "").strip()
            key = entry_dn.casefold()
            if not entry_dn or key in dn_to_user:
                continue
            username = _first(entry_values, attr_map.get("username", "sAMAccountName"))
            if not username:
                summary["errors"].append(
                    f"{entry_dn or '(unknown dn)'}: missing mapped username; profile not provisioned"
                )
                continue
            email = _first(entry_values, attr_map.get("email", "mail"))
            display_name = (
                _first(entry_values, attr_map.get("display_name", "displayName")) or username
            )
            groups = entry_values.get("memberOf") or []
            roles = core_app.mapped_roles(groups, "LDAP_ROLE_MAPPINGS")
            profile, friendly_groups = directory_profile_payload(entry_values, groups, attr_map)
            profile_attrs = {
                field: _first(entry_values, attr_map.get(field, field))
                for field in PROFILE_FIELDS
                if _first(entry_values, attr_map.get(field, field))
            }
            profile_attrs["team_name"] = profile.get("team_name")
            try:
                transaction = nullcontext() if dry_run else db.session.begin_nested()
                with transaction:
                    user = core_app.provision_external_user(
                        "ldap", entry_dn, username, display_name, email, roles,
                        groups=groups, profile_attrs=profile_attrs,
                        directory_profile=profile,
                        directory_group_names=friendly_groups,
                    )
                    if user.tenant_id != tenant_id:
                        raise DirectorySyncError(
                            "directory identity collided with an account outside this tenant"
                        )
                    db.session.flush()
                    dn_to_user[key] = user
                    summary["users_provisioned"] += 1
            except Exception as error:  # noqa: BLE001 - isolate a malformed/colliding entry
                summary["errors"].append(f"{entry_dn}: {type(error).__name__}")

    def _resolve_or_provision_manager(manager_dn, _resolving=None):
        """Return the ServiceOps User for `manager_dn`, provisioning a normal
        LDAP-identity user record for them (role/groups resolved the usual
        way) if the directory search above found them but they've never
        logged into ServiceOps. `_resolving` guards against an (unlikely but
        directory-data-driven, not code-controlled) manager cycle."""
        key = manager_dn.strip().casefold()
        existing = dn_to_user.get(key)
        if existing:
            return existing
        entry_values = dn_to_entry.get(key)
        if not entry_values:
            return None
        _resolving = _resolving or set()
        if key in _resolving:
            summary["errors"].append(f"Manager reporting cycle detected at: {manager_dn}")
            return None
        _resolving.add(key)
        manager_username = _first(entry_values, attr_map.get("username", "sAMAccountName"))
        if not manager_username:
            return None
        manager_email = _first(entry_values, attr_map.get("email", "mail"))
        manager_name = _first(entry_values, attr_map.get("display_name", "displayName")) or manager_username
        manager_groups = entry_values.get("memberOf") or []
        manager_roles = core_app.mapped_roles(manager_groups, "LDAP_ROLE_MAPPINGS")
        manager_directory_profile, manager_group_names = directory_profile_payload(
            entry_values, manager_groups, attr_map
        )
        manager_profile_attrs = {
            field: _first(entry_values, attr_map.get(field, field))
            for field in PROFILE_FIELDS
            if _first(entry_values, attr_map.get(field, field))
        }
        manager_profile_attrs["team_name"] = manager_directory_profile.get("team_name")
        provisioned = core_app.provision_external_user(
            "ldap", manager_dn, manager_username, manager_name, manager_email,
            manager_roles, groups=manager_groups, profile_attrs=manager_profile_attrs,
            directory_profile=manager_directory_profile,
            directory_group_names=manager_group_names,
        )
        if provisioned.tenant_id != tenant_id:
            # provision_external_user() can adopt an existing local/other-tenant
            # account by email/username collision -- never wire a cross-tenant
            # user into this tenant's reporting chain.
            summary["errors"].append(
                f"Manager {manager_dn} resolved to a user outside this tenant; skipped."
            )
            return None
        db.session.flush()
        dn_to_user[key] = provisioned
        summary["managers_provisioned"] += 1
        return provisioned

    for entry_dn, values in entries:
        entry_dn = entry_dn or ""
        user = dn_to_user.get(entry_dn.strip().casefold())
        if not user:
            summary["users_unmatched"] += 1
            continue
        if user.tenant_id != tenant_id:
            # Defense in depth: never mutate another tenant's user even if the
            # identity map above were somehow built incorrectly.
            summary["errors"].append(f"Skipped user outside tenant scope: {entry_dn}")
            continue

        counters_before = {
            key: summary[key] for key in (
                "users_updated", "managers_resolved", "managers_provisioned",
                "self_manager_skipped", "memberships_added", "memberships_removed",
                "teams_created", "directory_profiles_updated", "accounts_deactivated",
            )
        }
        try:
            transaction = nullcontext() if dry_run else db.session.begin_nested()
            with transaction:
                changed = False
                groups = values.get("memberOf") or []
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
                    manager_user = _resolve_or_provision_manager(manager_dn)
                    if manager_user and manager_user.id == user.id:
                        summary["self_manager_skipped"] += 1
                        summary["self_manager_users"].append(user.username)
                        summary["errors"].append(
                            f"Self-manager record skipped for {user.username}: directory manager points to own DN."
                        )
                    elif manager_user:
                        if user.manager_id != manager_user.id:
                            user.manager_id = manager_user.id
                            changed = True
                        summary["managers_resolved"] += 1

                if changed:
                    summary["users_updated"] += 1

                directory_profile, friendly_groups = directory_profile_payload(values, groups, attr_map)
                core_app.apply_directory_profile(user, directory_profile, friendly_groups)
                summary["directory_profiles_updated"] += 1
                if (
                    core_app.setting_bool("LDAP_SYNC_ACCOUNT_STATUS", True)
                    and directory_profile.get("account_enabled") is False
                    and user.active
                ):
                    user.active = False
                    user.auth_version += 1
                    core_app.UserSession.query.filter_by(
                        user_id=user.id, revoked_at=None
                    ).update({"revoked_at": core_app.now()})
                    summary["accounts_deactivated"] += 1

                before_ids = {
                    m.group_id for m in core_app.DirectoryManagedMembership.query
                    .filter_by(user_id=user.id, tenant_id=user.tenant_id).all()
                }
                created_team = core_app.sync_directory_team_memberships(
                    user, groups, declared_team=directory_profile.get("team_name")
                )
                if created_team:
                    summary["teams_created"] += 1
                db.session.flush()
                after_ids = {
                    m.group_id for m in core_app.DirectoryManagedMembership.query
                    .filter_by(user_id=user.id, tenant_id=user.tenant_id).all()
                }
                summary["memberships_added"] += len(after_ids - before_ids)
                summary["memberships_removed"] += len(before_ids - after_ids)
        except Exception as error:  # noqa: BLE001 - isolate one bad entry from the whole sync
            for key, value in counters_before.items():
                summary[key] = value
            summary["errors"].append(f"{entry_dn or '(unknown dn)'}: {type(error).__name__}")

    # Direct-report relationships are also an auditable source of manager
    # authority. Reconcile after every manager link is known so processing
    # order cannot cause the grant to flap.
    affected_users = {user.id: user for user in dn_to_user.values()}
    for user in affected_users.values():
        core_app.sync_implied_role_grants(user)
        summary["team_managers_inferred"] += core_app.reconcile_directory_team_managers(user)

    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()

    # Keep response bounded/deterministic for admin UI + logs.
    summary["self_manager_users"] = sorted(set(summary["self_manager_users"]))

    return summary
