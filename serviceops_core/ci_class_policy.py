"""Per-(tenant, CI class, role) CMDB read-visibility policy.

DB-backed and tenant-scoped, unlike security.py's deliberately file-based,
no-DB role/action policy -- kept as a separate module so security.py's
existing no-app-context unit tests stay untouched. See CiClassPermission
in serviceops_models.py for the opt-in/deny-once-managed semantics this
implements: a CI class with no configured rows is visible to every role
that can see CMDB at all (unchanged default); only once an administrator
adds at least one row for a class does that class become "managed," at
which point any role without an explicit can_read=True row for it is
filtered out of CMDB lists/exports/topology for that class.

Deliberately narrower than a full per-class CRUD matrix: create/update/
delete on CMDB stay governed solely by the existing @roles("admin") gate
on the CI mutation routes, unaffected by this module.
"""


def ci_class_read_allowed(tenant_id, ci_class, role):
    """True if `role` may see CIs of `ci_class` for `tenant_id`."""
    from serviceops_models import CiClassPermission

    if role == "superadmin":
        return True
    rows = CiClassPermission.query.filter_by(tenant_id=tenant_id, ci_class=ci_class).all()
    if not rows:
        return True
    return any(row.role == role and row.can_read for row in rows)


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
