"""Per-(tenant, CI class, role) CMDB permission policy.

DB-backed and tenant-scoped, unlike security.py's deliberately file-based,
no-DB role/action policy -- kept as a separate module so security.py's
existing no-app-context unit tests stay untouched. See CiClassPermission
in serviceops_models.py for the full opt-in semantics, which are
deliberately asymmetric between read and create/update/delete:

- Read defaults OPEN for an unmanaged class (no rows at all): visible to
  every role that could see CMDB before this table existed. Only once an
  administrator adds at least one row for a class does it become
  "managed" for read, at which point a role needs an explicit
  can_read=True row or its CIs are filtered from CMDB lists/exports/
  topology for that class.
- Create/update/delete default CLOSED for agent/manager, regardless of
  whether the class is "managed" for read: an agent/manager row (or its
  absence) is checked directly, independent of read-management state, so
  shipping this feature never grants new write capability to anyone until
  an administrator explicitly checks a box. admin/superadmin always pass
  every check -- this table only ever grants agent/manager capability
  they didn't have, never restricts admin's pre-existing full access.
"""

_CRUD_COLUMNS = {"create": "can_create", "update": "can_update", "delete": "can_delete"}


def ci_class_read_allowed(tenant_id, ci_class, role):
    """True if `role` may see CIs of `ci_class` for `tenant_id`."""
    from serviceops_models import CiClassPermission

    if role == "superadmin":
        return True
    rows = CiClassPermission.query.filter_by(tenant_id=tenant_id, ci_class=ci_class).all()
    if not rows:
        return True
    return any(row.role == role and row.can_read for row in rows)


def ci_class_action_allowed(tenant_id, ci_class, role, action):
    """True if `role` may perform `action` ("create"/"update"/"delete")
    against CIs of `ci_class` for `tenant_id`. Unlike read, this always
    defaults to False for agent/manager absent an explicit grant -- see
    module docstring."""
    from serviceops_models import CiClassPermission

    if role in ("admin", "superadmin"):
        return True
    column = _CRUD_COLUMNS.get(action)
    if column is None:
        raise ValueError(f"Unknown CI class action: {action}")
    row = CiClassPermission.query.filter_by(tenant_id=tenant_id, ci_class=ci_class, role=role).first()
    return bool(row and getattr(row, column))


def managed_ci_classes(tenant_id):
    """ci_class values currently under granular read control for a tenant."""
    from serviceops_models import CiClassPermission, db

    return {
        row[0] for row in db.session.query(CiClassPermission.ci_class)
        .filter_by(tenant_id=tenant_id).distinct().all()
    }


def restrict_ci_query_to_readable_classes(query, tenant_id, role):
    """Applied to a ConfigurationItem query before pagination/aggregation.
    No-ops (returns the query unchanged) when nothing is managed -- the
    zero-behavior-change fast path for tenants that never configure this."""
    from serviceops_models import ConfigurationItem

    managed = managed_ci_classes(tenant_id)
    if not managed:
        return query
    denied = [c for c in managed if not ci_class_read_allowed(tenant_id, c, role)]
    return query.filter(~ConfigurationItem.ci_class.in_(denied)) if denied else query
