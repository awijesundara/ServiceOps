"""Helpers and constants shared by the route modules in serviceops_core/web/.

Hoisted verbatim from app.create_app(), where they were closures.
"""
import hashlib
import os
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import abort, current_app, g, redirect, request, url_for
from flask_login import current_user
from sqlalchemy import func
from werkzeug.utils import secure_filename

import app as core
from app import (
    align_tz,
    APP_VERSION,
    apply_filter_conditions,
    ATTACHMENT_ALLOWED_TYPES,
    audit,
    client_sysops_group,
    current_storage,
    DOMAIN_CONFIG,
    effective_role_has_action,
    local_device_artwork,
    require_api_scope,
    role_at_least,
    service_availability_pct,
    setting_int,
    tenant_query,
    tenant_ticket_categories,
    UNCATEGORISED,
    user_can_view_catalog_request,
    user_in_group,
    validate_attachment_upload,
    visible_enterprise_record_query,
    visible_ticket_query,
)
from serviceops_core.ci_class_policy import restrict_ci_query_to_readable_classes
from serviceops_models import (
    Audit,
    CatalogTask,
    ChangeOwnership,
    ChangePostImplementationReview,
    ClientTicket,
    ClientView,
    ConfigurationItem,
    db,
    EnterpriseRecord,
    FileAttachment,
    GroupMember,
    KpiSnapshot,
    now,
    OperationalTask,
    PlatformSetting,
    ServiceOffering,
    ServiceOutage,
    SLADefinition,
    SupportGroup,
    TaskHistory,
    TaskSLA,
    Ticket,
    TicketAssignmentGroup,
    User,
)


TICKET_STATE_OPTIONS = ["New", "In Progress", "Pending", "Resolved", "Closed", "Cancelled"]


TERMINAL_TICKET_STATES = ["Resolved", "Closed", "Cancelled"]


TERMINAL_TASK_STATES = ["Closed Complete", "Closed Incomplete", "Closed Skipped", "Cancelled"]


CLIENT_VIEW_SORT_COLUMNS = {
    "updated": ClientTicket.updated_at, "created": ClientTicket.created_at,
    "priority": ClientTicket.priority, "status": ClientTicket.status,
}


GUIDED_TOUR_ROLES = ("requester", "agent", "manager", "admin")


# requester/agent/manager/admin are editable; superadmin is never
# overridable (always implicitly granted everywhere, per this app's
# existing convention -- see RolePolicyOverride's docstring).
EDITABLE_POLICY_ROLES = ("requester", "agent", "manager", "admin")


# Every admin panel route is gated by @roles("admin")/@roles("superadmin")
# -- a hardcoded role-membership check that runs before, and completely
# independently of, this action-based policy system. Granting a
# non-admin role one of these three admin-tier actions here can
# therefore never open panel access for them (confirmed: every route
# checking these actions is also @roles("admin")-gated, except the
# CMDB Discovery routes, which check security_administer alone -- so
# that one exception is deliberately still left editable for agent/
# manager below). Hiding the other, structurally pointless checkboxes
# for non-admin roles avoids silently configuring something that can
# never take effect, with no error or explanation, the way it
# previously did.
ADMIN_PANEL_GATED_ACTIONS = {"administer", "platform_administer"}


# A full audit (every effective_role_has_action()/@require_action call
# site in app.py, both decorator and inline) found these actions are
# never checked anywhere, for any role, browser or REST API -- real
# authorization for the operations they'd nominally cover (ticket
# delete, approval decisions, task close/reopen, etc.) happens through
# entirely separate, hardcoded @roles(...) + team-membership checks
# that don't consult this policy at all. Toggling these here is a
# structural no-op for every role, not a role-specific gap like
# ADMIN_PANEL_GATED_ACTIONS above -- shown as fixed/informational
# rather than editable, so this page never again promises control it
# can't deliver. "create" is a partial case (checked for REST API v1
# clients, not the browser UI) and is called out separately in the
# page copy rather than lumped in here, since it does have real effect
# for one surface.
UNENFORCED_ACTIONS = {
    "delete", "purge", "approve", "accept", "close", "reopen",
    "delegate", "relate", "discover", "read",
}


# Structured facts written by agentless discovery (serviceops_core/
# network_discovery.py's reconcile_facts_into_cmdb) -- rendered as their
# own read-only panels/tables on the CI form (see ci_form.html), never as
# editable "Additional imported fields" rows, since a raw Python list-of-
# dicts str()'d into a text input is unreadable (the exact "[{'index':
# '1', ...}]" wall of text an administrator flagged from a live scan).
CI_DISCOVERY_ATTRIBUTE_KEYS = {
    "sys_descr", "sys_object_id", "sys_uptime", "interfaces",
    "lldp_neighbors", "discovered_via", "discovered_at",
}


# requester is deliberately excluded: no CMDB route (read or write) has
# ever let requester through, so a requester column would be an inert
# checkbox that can never take effect -- the same footgun avoided
# elsewhere in this feature. admin's create/update/delete are always
# implicitly allowed (see ci_class_action_allowed) and rendered as an
# "Always" badge in the template rather than a checkbox that would be
# equally inert; admin's Read column stays a real, restrictable checkbox.
CI_CLASS_PERMISSION_ROLES = ("agent", "manager", "admin")


CI_CLASS_PERMISSION_CRUD_ROLES = ("agent", "manager")


ITIL_ADMIN_SECTIONS = {
    "ticket-defaults": ("Ticket defaults", "Initial priority for new tickets and parent/child incident state sync."),
    "catalog": ("Catalog and fulfillment routing", "Service catalog items and which team fulfills each one by default."),
    "team-aliases": ("Team name aliases", "Historical/imported team name spellings that safely merge into one canonical team."),
    "team-managers": ("Team managers", "The named manager who holds change-approval authority for each team."),
    "executive-approval": ("Executive approval (CEO)", "The named user required to approve every Normal/Emergency change."),
    "governance-groups": ("Governance groups", "Review accountable groups, their type, manager, and current membership."),
    "change-approval-policy": ("Change approval policy", "Which CMDB environment names require Change Control Board approval."),
    "ccb": ("Change Control Board approvers", "Users granted CCB voting authority for non-standard changes."),
    "change-freeze": ("Change freeze windows", "Blocks Standard/Normal change scheduling and approval during active windows."),
    "service-offerings": ("Service offerings", "Map services to their supporting configuration items."),
    "ticket-categories": ("Ticket categories", "The category/subcategory taxonomy offered on the ticket form, and which service offering each subcategory suggests."),
    "sla": ("SLA definitions and business calendars", "Business schedules and SLA target durations by priority."),
}


def usertime_filter(value, fmt="%b %d, %H:%M"):
    if value is None:
        return ""
    tz_name = getattr(current_user, "timezone", None) if current_user.is_authenticated else None
    try:
        tz = ZoneInfo(tz_name) if tz_name else ZoneInfo("UTC")
    except (ZoneInfoNotFoundError, ValueError):
        tz = ZoneInfo("UTC")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(tz).strftime(fmt)


def _recovery_set_status():
    """Single source of truth for backup/RPO freshness -- read by both
    /metrics and system_health(), which previously computed this
    independently and could silently drift apart."""
    last_backup_row = db.session.get(PlatformSetting, "LAST_BACKUP_AT")
    last_backup_at = None
    if last_backup_row and last_backup_row.value:
        try:
            last_backup_at = datetime.fromisoformat(last_backup_row.value)
        except ValueError:
            pass
    backup_rpo_hours = setting_int("BACKUP_RPO_HOURS", int(os.getenv("BACKUP_RPO_HOURS", "24")))
    backup_age_seconds = -1
    if last_backup_at:
        backup_age_seconds = max(0, (now() - align_tz(last_backup_at, now())).total_seconds())
    backup_healthy = bool(
        last_backup_at is not None and backup_age_seconds <= backup_rpo_hours * 3600
    )
    return last_backup_at, backup_healthy, backup_rpo_hours, backup_age_seconds


def mobile_only():
    if g.api_client.client_kind != "mobile":
        abort(403, description="A mobile user session is required.")


def scim_user_document(user):
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(user.id), "externalId": user.employee_id,
        "userName": user.username, "displayName": user.name,
        "active": user.active,
        "emails": [{"value": user.email, "primary": True}],
        "meta": {"resourceType": "User", "created": user.created_at.isoformat(),
                 "location": url_for("scim_user", user_id=user.id, _external=True)},
    }


def require_scim_admin():
    require_api_scope("users:provision")
    if not effective_role_has_action(g.api_user.role, "security_administer", tenant_id=g.api_user.tenant_id):
        abort(403, description="The SCIM client must act as a security administrator.")


def visible_tickets():
    return visible_ticket_query(current_user)


def ticket_filter_field_spec():
    return {
        "number": {"label": "Number", "type": "text", "column": Ticket.number},
        "title": {"label": "Short description", "type": "text", "column": Ticket.title},
        "priority": {"label": "Priority", "type": "choice", "column": Ticket.priority,
                    "options": [(p, p) for p in ["P1", "P2", "P3", "P4"]]},
        "state": {"label": "State", "type": "choice", "column": Ticket.state,
                  "options": [(s, s) for s in TICKET_STATE_OPTIONS]},
        "category": {"label": "Category", "type": "choice", "column": Ticket.category,
                    "options": [(c.name, c.name) for c in tenant_ticket_categories(current_user.tenant_id)]},
        "opened": {"label": "Opened", "type": "date", "column": Ticket.created_at},
        "updated": {"label": "Updated", "type": "date", "column": Ticket.updated_at},
    }


def ticket_group_filter_handler(kind):
    """Assignment group lives on TicketAssignmentGroup (incidents) or
    ChangeOwnership (changes), not a plain Ticket column, so it needs a
    subquery instead of the generic column-based filter path."""
    link_model = ChangeOwnership if kind == "change" else TicketAssignmentGroup

    def handler(query, op, value):
        if op == "eq" and value:
            try:
                group_id_value = int(value)
            except ValueError:
                return query
            return query.filter(Ticket.id.in_(
                db.session.query(link_model.ticket_id).filter(link_model.group_id == group_id_value)
            ))
        if op == "ne" and value:
            try:
                group_id_value = int(value)
            except ValueError:
                return query
            return query.filter(~Ticket.id.in_(
                db.session.query(link_model.ticket_id).filter(link_model.group_id == group_id_value)
            ))
        if op == "is_empty":
            return query.filter(~Ticket.id.in_(db.session.query(link_model.ticket_id)))
        if op == "is_not_empty":
            return query.filter(Ticket.id.in_(db.session.query(link_model.ticket_id)))
        return query
    return handler


def ticket_list_query(kind, q="", conditions=None):
    """Shared filtering for the ticket list view and its CSV export, so
    both stay consistent: free-text search plus the generic filter
    condition list (see apply_filter_conditions)."""
    query = visible_tickets().filter_by(kind=kind).filter(Ticket.deleted_at.is_(None))
    if q:
        query = query.filter(db.or_(Ticket.number.ilike(f"%{q}%"), Ticket.title.ilike(f"%{q}%")))
    query = apply_filter_conditions(
        query, conditions or [], ticket_filter_field_spec(),
        extra_handlers={"group": ticket_group_filter_handler(kind)},
    )
    return query


def manager_portal_groups():
    if role_at_least(current_user.effective_role, "admin"):
        return tenant_query(SupportGroup).filter(
            SupportGroup.group_type == "IT Fulfillment",
            SupportGroup.active.is_(True),
        ).order_by(SupportGroup.name).all()
    return tenant_query(SupportGroup).filter(
        SupportGroup.group_type == "IT Fulfillment",
        SupportGroup.active.is_(True),
        SupportGroup.manager_id == current_user.id,
    ).order_by(SupportGroup.name).all()


def manager_portal_context():
    """Team and per-member workload/SLA snapshot for the manager portal,
    shared by the HTML view and the CSV export so both stay consistent."""
    groups = manager_portal_groups()
    group_ids = [group.id for group in groups]
    memberships = GroupMember.query.filter(
        GroupMember.group_id.in_(group_ids)
    ).options(db.joinedload(GroupMember.user)).all() if group_ids else []
    member_ids = sorted({m.user_id for m in memberships})

    open_ticket_rows = Ticket.query.filter(
        Ticket.assignee_id.in_(member_ids),
        Ticket.state.notin_(TERMINAL_TICKET_STATES),
    ).with_entities(Ticket.id, Ticket.assignee_id, Ticket.kind).all() if member_ids else []
    open_ticket_ids_by_member = defaultdict(list)
    open_incidents_by_member = Counter()
    open_changes_by_member = Counter()
    for ticket_id, assignee_id, kind in open_ticket_rows:
        open_ticket_ids_by_member[assignee_id].append(ticket_id)
        if kind == "incident":
            open_incidents_by_member[assignee_id] += 1
        elif kind == "change":
            open_changes_by_member[assignee_id] += 1

    thirty_days_ago = now() - timedelta(days=30)
    resolved_30d_by_member = Counter()
    if member_ids:
        for assignee_id, count in db.session.query(
            Ticket.assignee_id, func.count(Ticket.id)
        ).filter(
            Ticket.assignee_id.in_(member_ids),
            Ticket.state.in_(TERMINAL_TICKET_STATES),
            func.coalesce(Ticket.resolved_at, Ticket.updated_at) >= thirty_days_ago,
        ).group_by(Ticket.assignee_id).all():
            resolved_30d_by_member[assignee_id] = count

    open_tasks_by_member = Counter()
    if member_ids:
        for model in (OperationalTask, CatalogTask):
            for assignee_id, count in db.session.query(
                model.assignee_id, func.count(model.id)
            ).filter(
                model.assignee_id.in_(member_ids),
                model.state.notin_(TERMINAL_TASK_STATES),
            ).group_by(model.assignee_id).all():
                open_tasks_by_member[assignee_id] += count

    sla_at_risk_hours = setting_int("SLA_AT_RISK_HOURS", 4)
    breach_horizon = now() + timedelta(hours=sla_at_risk_hours)
    all_open_ticket_ids = [row[0] for row in open_ticket_rows]
    sla_breached_by_member = Counter()
    sla_at_risk_by_member = Counter()
    if all_open_ticket_ids:
        ticket_to_member = {
            ticket_id: assignee_id for ticket_id, assignee_id, _ in open_ticket_rows
        }
        sla_rows = TaskSLA.query.filter(
            TaskSLA.target_type == "ticket",
            TaskSLA.target_id.in_(all_open_ticket_ids),
            TaskSLA.stage == "In Progress",
        ).all()
        for row in sla_rows:
            assignee_id = ticket_to_member.get(row.target_id)
            if assignee_id is None:
                continue
            if row.breached:
                sla_breached_by_member[assignee_id] += 1
            else:
                breach_at = row.breach_at if row.breach_at.tzinfo else row.breach_at.replace(tzinfo=timezone.utc)
                if breach_at <= breach_horizon:
                    sla_at_risk_by_member[assignee_id] += 1

    team_rows = []
    member_rows_by_group = {}
    for group in groups:
        group_members = sorted(
            (m for m in memberships if m.group_id == group.id),
            key=lambda m: m.user.name,
        )
        member_rows = []
        for membership in group_members:
            user = membership.user
            member_rows.append({
                "user": user,
                "role_in_group": membership.role,
                "status": "Active" if user.active else "Inactive",
                "open_incidents": open_incidents_by_member.get(user.id, 0),
                "open_changes": open_changes_by_member.get(user.id, 0),
                "open_tasks": open_tasks_by_member.get(user.id, 0),
                "resolved_30d": resolved_30d_by_member.get(user.id, 0),
                "sla_breached": sla_breached_by_member.get(user.id, 0),
                "sla_at_risk": sla_at_risk_by_member.get(user.id, 0),
            })
        member_rows_by_group[group.id] = member_rows
        team_rows.append({
            "group": group,
            "open_incidents": sum(row["open_incidents"] for row in member_rows),
            "open_changes": sum(row["open_changes"] for row in member_rows),
            "open_tasks": sum(row["open_tasks"] for row in member_rows),
            "sla_breached": sum(row["sla_breached"] for row in member_rows),
            "member_count": len(member_rows),
        })
    return team_rows, member_rows_by_group


def client_workspace_context():
    group = client_sysops_group(current_user.tenant_id)
    user_ids = set()
    if group:
        user_ids.update(member.user_id for member in group.members if member.user.active)
        if group.manager and group.manager.active:
            user_ids.add(group.manager_id)
    if current_user.id not in user_ids and role_at_least(current_user.effective_role, "admin"):
        user_ids.add(current_user.id)
    agents = tenant_query(User).filter(User.id.in_(user_ids), User.active.is_(True)).order_by(User.name).all() if user_ids else []
    return group, agents


def client_ticket_filter_field_spec():
    return {
        "number": {"label": "Number", "type": "text", "column": ClientTicket.number},
        "subject": {"label": "Subject", "type": "text", "column": ClientTicket.subject},
        "status": {"label": "Status", "type": "choice", "column": ClientTicket.status,
                   "options": [(s, s) for s in ["New", "Open", "Pending", "On-hold", "Solved", "Closed"]]},
        "priority": {"label": "Priority", "type": "choice", "column": ClientTicket.priority,
                     "options": [(p, p) for p in ["Low", "Normal", "High", "Urgent"]]},
        "ticket_type": {"label": "Type", "type": "choice", "column": ClientTicket.ticket_type,
                        "options": [(t, t) for t in ["Question", "Incident", "Problem", "Task"]]},
        "channel": {"label": "Channel", "type": "choice", "column": ClientTicket.channel,
                    "options": [(c, c) for c in ["Web", "Email", "Phone", "Chat"]]},
        "tags": {"label": "Tags", "type": "text", "column": ClientTicket.tags},
        "created": {"label": "Opened", "type": "date", "column": ClientTicket.created_at},
        "updated": {"label": "Updated", "type": "date", "column": ClientTicket.updated_at},
    }


def visible_client_views(user):
    return ClientView.query.filter(
        ClientView.tenant_id == user.tenant_id,
        db.or_(ClientView.created_by_id == user.id, ClientView.shared.is_(True)),
    ).order_by(ClientView.name).all()


def _infrastructure_rows():
    return [
        ("Deployment profile", current_app.config.get("DEPLOYMENT_PROFILE") or "Default profile", "Docker environment / Helm values"),
        ("Database", current_app.config["SQLALCHEMY_DATABASE_URI"].split("@")[-1], "DATABASE_URL / Kubernetes Secret"),
        ("Upload storage", current_app.config.get("UPLOAD_FOLDER") or "Not configured", "Docker volume / Kubernetes PVC"),
        ("Application replicas", os.getenv("REPLICA_COUNT") or "1 (local Compose default)", "Docker Compose / Helm"),
        ("Ingress and TLS", os.getenv("PUBLIC_BASE_URL") or "Managed outside ServiceOps", "Reverse proxy / Kubernetes Ingress"),
    ]


def audit_filter_field_spec():
    # "action"/"target" stay free-text (contains/starts_with/eq) rather
    # than a "choice" list of every distinct action string ever
    # written -- those are ad-hoc per call site throughout this file,
    # not a fixed enum, and a hardcoded option list would silently go
    # stale exactly like the hardcoded-action-list problem this
    # codebase has already had to fix elsewhere. "user_id" and
    # "authentication_provider" are genuinely bounded sets, so those
    # are real choice fields.
    users = User.query.filter_by(tenant_id=core.tenant_context_id()).order_by(User.name).all()
    return {
        "action": {"label": "Action", "type": "text", "column": Audit.action},
        "target": {"label": "Target", "type": "text", "column": Audit.target},
        "user_id": {"label": "User", "type": "choice", "column": Audit.user_id,
                    "options": [(str(u.id), f"{u.name} ({u.username})") for u in users]},
        "source_ip": {"label": "Source IP", "type": "text", "column": Audit.source_ip},
        "created_at": {"label": "Time", "type": "date", "column": Audit.created_at},
    }


def cmdb_filter_field_spec():
    support_groups = SupportGroup.query.filter_by(
        tenant_id=core.tenant_context_id()
    ).order_by(SupportGroup.name).all()
    return {
        "name": {"label": "Name", "type": "text", "column": ConfigurationItem.name},
        "ci_class": {"label": "Class", "type": "text", "column": ConfigurationItem.ci_class},
        "environment": {"label": "Environment", "type": "choice", "column": ConfigurationItem.environment,
                        "options": [(v, v) for v in ["Production", "Staging", "Development", "Test"]]},
        "operational_status": {"label": "Status", "type": "choice", "column": ConfigurationItem.operational_status,
                               "options": [(v, v) for v in ["Operational", "Degraded", "Down", "Maintenance", "Retired"]]},
        "lifecycle_state": {"label": "Lifecycle", "type": "choice", "column": ConfigurationItem.lifecycle_state,
                            "options": [(v, v) for v in ["Planned", "In Use", "Maintenance", "Retired", "Disposed"]]},
        "business_criticality": {"label": "Criticality", "type": "choice", "column": ConfigurationItem.business_criticality,
                                 "options": [(v, v) for v in ["Critical", "High", "Medium", "Low"]]},
        "location": {"label": "Location", "type": "text", "column": ConfigurationItem.location},
        "support_group_id": {"label": "Owning team", "type": "choice", "column": ConfigurationItem.support_group_id,
                             "options": [(str(g.id), g.name) for g in support_groups]},
    }


def _ci_attributes_from_form(existing_attributes=None):
    """Merges the editable free-form attribute rows with whatever
    discovery-structured keys (see CI_DISCOVERY_ATTRIBUTE_KEYS) the CI
    already has -- those never appear as editable rows, so without this
    merge saving the form would silently wipe discovered interfaces/LLDP
    data every time an admin edits an unrelated field."""
    keys = request.form.getlist("attr_key")
    values = request.form.getlist("attr_value")
    attributes = {
        key: value for key, value in (
            (k.strip(), v.strip()) for k, v in zip(keys, values)
        ) if key and key not in CI_DISCOVERY_ATTRIBUTE_KEYS and value
    }
    if existing_attributes:
        for key in CI_DISCOVERY_ATTRIBUTE_KEYS:
            if key in existing_attributes:
                attributes[key] = existing_attributes[key]
    return attributes


def _ci_duplicate_of(name, serial_number, exclude_id=None):
    """Hostname and serial number are each supposed to identify exactly
    one physical/virtual asset, so a second CI with the same name or
    serial within a tenant is almost always a mistake (a re-created
    record, a copy-pasted form) rather than a legitimate second CI.
    Returns the existing CI it collides with, or None."""
    query = tenant_query(ConfigurationItem)
    if exclude_id:
        query = query.filter(ConfigurationItem.id != exclude_id)
    conditions = [func.lower(ConfigurationItem.name) == name.casefold()]
    if serial_number:
        conditions.append(ConfigurationItem.serial_number == serial_number)
    return query.filter(db.or_(*conditions)).first()


def _rack_elevation_payload(rack, compact=False):
    cis = restrict_ci_query_to_readable_classes(
        tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
    ).filter_by(rack_id=rack.id).all()

    def ci_dict(ci):
        has_device_artwork = (
            ci.external_source == "netbox"
            and bool(ci.external_id and ci.external_id.startswith("dcim.device:"))
        )
        artwork_url = None
        local_artwork = local_device_artwork(ci.vendor, ci.model)
        if has_device_artwork:
            artwork_url = url_for("rack_device_artwork", ci_id=ci.id, face=(ci.rack_face or "front"))
        elif local_artwork:
            artwork_url = url_for(
                "static", filename=f"device-artwork/{local_artwork}.{ci.rack_face or 'front'}.png",
                v=APP_VERSION,
            )
        return {
            "id": ci.id, "name": ci.name, "ci_class": ci.ci_class,
            "status": ci.operational_status,
            "vendor": ci.vendor, "model": ci.model,
            "position": ci.rack_position if ci.rack_position is not None else 1,
            "u_height": ci.rack_u_height if ci.rack_u_height else 1,
            # The browser only talks to ServiceOps. This authenticated
            # endpoint retrieves artwork with the server-side NetBox
            # credential, so the API token and private NetBox URL are
            # never disclosed in page JSON or browser network requests.
            "artwork_url": artwork_url,
        }

    front = [ci_dict(ci) for ci in cis if ci.rack_face != "rear" and (ci.ci_class or "").lower() != "pdu"]
    rear = [ci_dict(ci) for ci in cis if ci.rack_face == "rear" and (ci.ci_class or "").lower() != "pdu"]
    pdus = [
        {
            "id": ci.id, "name": ci.name,
            "power_watts": (ci.attributes or {}).get("power_watts"),
        }
        for ci in cis if (ci.ci_class or "").lower() == "pdu"
    ]
    space_used = sum((ci.rack_u_height or 1) for ci in cis if ci.rack_position is not None)
    weights = [(ci.attributes or {}).get("weight_kg") for ci in cis if (ci.attributes or {}).get("weight_kg")]
    powers = [(ci.attributes or {}).get("power_watts") for ci in cis if (ci.attributes or {}).get("power_watts")]
    highlight_ci_id = request.args.get("highlight", type=int)
    return {
        "rack": {"id": rack.id, "name": rack.name, "site": rack.site, "u_height": rack.u_height},
        "front": front, "rear": rear, "pdus": pdus,
        "highlight_ci_id": highlight_ci_id,
        "compact": compact,
        "stats": {
            "space_used_u": space_used, "space_total_u": rack.u_height,
            "weight_kg": sum(weights) if weights else None,
            "power_watts": sum(powers) if powers else None,
        },
    }


def user_can_view_catalog_task(user, task):
    ritm = task.requested_item
    return (
        user_can_view_catalog_request(user, ritm.request)
        or user_in_group(user, task.assignment_group)
    )


def _admin_referrer_redirect(fallback_endpoint, **fallback_kwargs):
    """Isolated settings pages (B-320) all post to their one shared
    handler endpoint; send the user back to the specific page they
    came from instead of always landing on the handler's own index."""
    destination = request.referrer
    if destination and destination.startswith(request.host_url):
        return redirect(destination)
    return redirect(url_for(fallback_endpoint, **fallback_kwargs))


def analytics_kpis():
    """Every metric the Analytics dashboard shows, factored out so the
    CSV export (analytics_export_csv) can share it instead of
    recomputing the same aggregates a second way -- same pattern
    already used by manager_portal_context()/manager_portal_export()."""
    ticket_query = visible_ticket_query(current_user)
    # Subqueries rather than Python ID lists: a literal IN list binds one
    # parameter per ticket, and psycopg rejects statements over 65535.
    ticket_ids = ticket_query.with_entities(Ticket.id)
    record_ids = visible_enterprise_record_query(current_user).with_entities(EnterpriseRecord.id)

    ticket_states = dict(db.session.query(Ticket.state, func.count(Ticket.id)).filter(
        Ticket.id.in_(ticket_ids)
    ).group_by(Ticket.state).all())
    domain_counts = dict(db.session.query(EnterpriseRecord.domain, func.count(EnterpriseRecord.id)).filter(
        EnterpriseRecord.id.in_(record_ids)
    ).group_by(EnterpriseRecord.domain).all())
    priority_counts = dict(db.session.query(Ticket.priority, func.count(Ticket.id)).filter(
        Ticket.id.in_(ticket_ids), Ticket.state.notin_(TERMINAL_TICKET_STATES),
    ).group_by(Ticket.priority).all())
    overdue_investigations = EnterpriseRecord.query.filter(
        EnterpriseRecord.id.in_(record_ids), EnterpriseRecord.due_at < now(),
        EnterpriseRecord.state.notin_(["Closed", "Resolved", "Completed"])
    ).count()

    open_ticket_query = ticket_query.filter(Ticket.state.notin_(TERMINAL_TICKET_STATES))
    open_ticket_ids = open_ticket_query.with_entities(Ticket.id)
    open_count = open_ticket_query.count()

    # SLA exposure on currently open work, and 30-day compliance on resolved work,
    # both driven off TaskSLA the same way the dashboard's own SLA widgets are.
    sla_at_risk_hours = setting_int("SLA_AT_RISK_HOURS", 4)
    breach_horizon = now() + timedelta(hours=sla_at_risk_hours)
    # Only customer-facing SLAs count toward the headline breach/at-risk/compliance
    # widgets; OLA and UC agreements are internal/supplier commitments that still
    # breach and notify (see attach_slas/process_sla_breaches) but shouldn't be
    # blended into what's reported as the business's own SLA performance.
    sla_breached_open = sla_at_risk_open = 0
    if open_count:
        for row in TaskSLA.query.join(SLADefinition, TaskSLA.definition_id == SLADefinition.id).filter(
            TaskSLA.target_type == "ticket", TaskSLA.target_id.in_(open_ticket_ids),
            TaskSLA.stage == "In Progress", SLADefinition.agreement_type == "SLA",
        ).all():
            if row.breached:
                sla_breached_open += 1
            else:
                breach_at = row.breach_at if row.breach_at.tzinfo else row.breach_at.replace(tzinfo=timezone.utc)
                if breach_at <= breach_horizon:
                    sla_at_risk_open += 1

    thirty_days_ago = now() - timedelta(days=30)
    # resolved_at is recorded on resolution; updated_at only stands in for
    # tickets resolved before that column existed without ticket history.
    resolved_time = func.coalesce(Ticket.resolved_at, Ticket.updated_at)
    resolved_30d = ticket_query.filter(
        Ticket.state.in_(TERMINAL_TICKET_STATES), resolved_time >= thirty_days_ago,
    ).with_entities(
        Ticket.id, Ticket.kind, Ticket.priority, Ticket.created_at, Ticket.updated_at, Ticket.resolved_at,
        Ticket.category, Ticket.closure_category,
    ).all()
    resolved_30d_ids = [row.id for row in resolved_30d]
    sla_by_ticket = defaultdict(bool)
    if resolved_30d_ids:
        for row in TaskSLA.query.join(SLADefinition, TaskSLA.definition_id == SLADefinition.id).filter(
            TaskSLA.target_type == "ticket", TaskSLA.target_id.in_(resolved_30d_ids),
            SLADefinition.agreement_type == "SLA",
        ).all():
            sla_by_ticket[row.target_id] = sla_by_ticket[row.target_id] or row.breached
    tickets_with_sla = [row for row in resolved_30d if row.id in sla_by_ticket]
    sla_compliance_pct = (
        round(100 * sum(1 for row in tickets_with_sla if not sla_by_ticket[row.id]) / len(tickets_with_sla))
        if tickets_with_sla else None
    )

    # Mean time to resolve: created -> resolved_at for incidents resolved in
    # the last 30 days (updated_at only where resolved_at predates the column).
    mttr_by_priority = {}
    for priority in ("P1", "P2", "P3", "P4"):
        spans = [
            (align_tz(row.resolved_at or row.updated_at, row.created_at) - row.created_at).total_seconds() / 3600
            for row in resolved_30d if row.kind == "incident" and row.priority == priority
        ]
        mttr_by_priority[priority] = round(sum(spans) / len(spans), 1) if spans else None

    # Categorisation at closure (falling back to the logging category where
    # none was recorded), and how often closure differed from logging.
    resolved_incidents_30d = [row for row in resolved_30d if row.kind == "incident"]
    closure_category_counts = Counter(
        row.closure_category or row.category or UNCATEGORISED for row in resolved_incidents_30d
    ).most_common(10)
    with_closure = [row for row in resolved_incidents_30d if row.closure_category]
    recategorised_pct = (
        round(100 * sum(1 for row in with_closure if row.closure_category != row.category) / len(with_closure))
        if with_closure else None
    )

    # 14-day created-vs-resolved volume trend.
    today = now().date()
    volume_trend = []
    window_start = today - timedelta(days=13)
    created_counts = Counter()
    for row in ticket_query.filter(Ticket.created_at >= window_start).with_entities(Ticket.created_at).all():
        created_counts[row.created_at.date()] += 1
    resolved_counts = Counter()
    for row in resolved_30d:
        if row.updated_at.date() >= window_start:
            resolved_counts[row.updated_at.date()] += 1
    for offset in range(14):
        day = window_start + timedelta(days=offset)
        volume_trend.append({"day": day, "created": created_counts.get(day, 0), "resolved": resolved_counts.get(day, 0)})
    trend_max = max([1] + [max(d["created"], d["resolved"]) for d in volume_trend])

    # Backlog aging: how long currently-open tickets have been sitting.
    aging_buckets = {"0-1 day": 0, "1-3 days": 0, "3-7 days": 0, "7+ days": 0}
    for row in ticket_query.filter(Ticket.state.notin_(TERMINAL_TICKET_STATES)).with_entities(Ticket.created_at).all():
        current_time = now()
        age_days = (
            current_time - align_tz(row.created_at, current_time)
        ).total_seconds() / 86400
        if age_days <= 1:
            aging_buckets["0-1 day"] += 1
        elif age_days <= 3:
            aging_buckets["1-3 days"] += 1
        elif age_days <= 7:
            aging_buckets["3-7 days"] += 1
        else:
            aging_buckets["7+ days"] += 1

    # Change success rate: of changes that reached a terminal outcome in the
    # last 30 days, the share that closed out rather than being cancelled.
    change_outcomes = Counter(
        row.state for row in ticket_query.filter(
            Ticket.kind == "change", Ticket.state.in_(["Closed", "Cancelled"]),
            Ticket.updated_at >= thirty_days_ago,
        ).with_entities(Ticket.state).all()
    )
    change_total = change_outcomes.get("Closed", 0) + change_outcomes.get("Cancelled", 0)
    change_success_pct = round(100 * change_outcomes.get("Closed", 0) / change_total) if change_total else None

    # PIR-driven change success: unlike the state-based proxy above,
    # this reflects the actual reviewed outcome (see
    # ChangePostImplementationReview) -- "Closed" only tells you the
    # ticket reached a terminal state, not whether the change worked.
    change_ticket_ids = ticket_query.filter(Ticket.kind == "change").with_entities(Ticket.id)
    pir_rows = ChangePostImplementationReview.query.filter(
        ChangePostImplementationReview.ticket_id.in_(change_ticket_ids),
        ChangePostImplementationReview.reviewed_at >= thirty_days_ago,
    ).with_entities(ChangePostImplementationReview.outcome).all()
    pir_total = len(pir_rows)
    pir_success_pct = (
        round(100 * sum(1 for row in pir_rows if row.outcome == "Successful") / pir_total)
        if pir_total else None
    )

    # First Contact Resolution proxy: incidents resolved in the last 30
    # days that were never reopened. Not a strict "resolved on the very
    # first interaction" measure (this app doesn't track interaction
    # count), but a defensible, cheaply-computed FCR signal.
    resolved_incident_ids = [
        row.id for row in ticket_query.filter(
            Ticket.kind == "incident", Ticket.state.in_(TERMINAL_TICKET_STATES),
            func.coalesce(Ticket.resolved_at, Ticket.updated_at) >= thirty_days_ago,
        ).with_entities(Ticket.id).all()
    ]
    reopened_incident_ids = set()
    if resolved_incident_ids:
        reopened_incident_ids = {
            row.target_id for row in TaskHistory.query.filter(
                TaskHistory.target_type == "ticket",
                TaskHistory.target_id.in_(resolved_incident_ids),
                TaskHistory.details.ilike("Reopened by%"),
            ).with_entities(TaskHistory.target_id).all()
        }
    fcr_total = len(resolved_incident_ids)
    fcr_pct = (
        round(100 * (fcr_total - len(reopened_incident_ids)) / fcr_total) if fcr_total else None
    )

    # CSAT: average of ratings requesters submitted in the last 30 days.
    csat_ratings = [
        row.csat_rating for row in ticket_query.filter(
            Ticket.csat_rating.isnot(None), Ticket.csat_submitted_at >= thirty_days_ago,
        ).with_entities(Ticket.csat_rating).all()
    ]
    csat_count = len(csat_ratings)
    csat_avg = round(sum(csat_ratings) / csat_count, 1) if csat_count else None

    # Top assignment groups by open ticket volume.
    open_rows = ticket_query.filter(Ticket.state.notin_(TERMINAL_TICKET_STATES)).with_entities(Ticket.id, Ticket.kind).all()
    incident_ids = [r.id for r in open_rows if r.kind == "incident"]
    change_ids = [r.id for r in open_rows if r.kind == "change"]
    group_counts = Counter()
    if incident_ids:
        for group_id, count in db.session.query(TicketAssignmentGroup.group_id, func.count(TicketAssignmentGroup.id)).filter(
            TicketAssignmentGroup.ticket_id.in_(incident_ids)
        ).group_by(TicketAssignmentGroup.group_id).all():
            group_counts[group_id] += count
    if change_ids:
        for group_id, count in db.session.query(ChangeOwnership.group_id, func.count(ChangeOwnership.id)).filter(
            ChangeOwnership.ticket_id.in_(change_ids)
        ).group_by(ChangeOwnership.group_id).all():
            group_counts[group_id] += count
    top_groups = []
    if group_counts:
        groups_by_id = {g.id: g for g in SupportGroup.query.filter(SupportGroup.id.in_(group_counts.keys())).all()}
        top_groups = sorted(
            ({"group": groups_by_id[gid], "count": count} for gid, count in group_counts.items() if gid in groups_by_id),
            key=lambda row: row["count"], reverse=True,
        )[:8]
    top_groups_max = max([1] + [row["count"] for row in top_groups])

    kpi_history_rows = KpiSnapshot.query.filter_by(tenant_id=core.tenant_context_id()).filter(
        KpiSnapshot.snapshot_date >= (now().date() - timedelta(days=30))
    ).order_by(KpiSnapshot.snapshot_date.desc(), KpiSnapshot.metric_name).limit(120).all()
    kpi_metric_labels = {
        "sla_compliance_pct": "SLA compliance %",
        "change_success_pct": "Change success % (reviewed)",
        "fcr_pct": "First contact resolution %",
        "csat_avg": "CSAT avg (out of 5)",
    }
    # 30 days of daily snapshots were already captured (capture_kpi_snapshots)
    # but only ever rendered as a flat date-sorted table -- turn it into a
    # per-metric trend so the point of snapshotting (spotting movement) is
    # actually visible, not just archived.
    kpi_series = {key: [] for key in kpi_metric_labels}
    for row in sorted(kpi_history_rows, key=lambda r: r.snapshot_date):
        if row.metric_name in kpi_series:
            kpi_series[row.metric_name].append({"date": row.snapshot_date.isoformat(), "value": row.metric_value})
    kpi_trends = []
    spark_w, spark_h = 240, 48
    for key, label in kpi_metric_labels.items():
        points = kpi_series[key]
        latest = points[-1]["value"] if points else None
        previous = points[-2]["value"] if len(points) > 1 else None
        values = [p["value"] for p in points]
        lo, hi = (min(values), max(values)) if values else (0, 0)
        spread = (hi - lo) or 1
        step = spark_w / max(1, len(values) - 1) if len(values) > 1 else 0
        spark_points = " ".join(
            f"{round(i * step, 1)},{round(spark_h - ((v - lo) / spread) * spark_h, 1)}"
            for i, v in enumerate(values)
        ) if len(values) > 1 else ""
        kpi_trends.append({
            "key": key, "label": label, "points": points, "latest": latest,
            "delta": (round(latest - previous, 1) if latest is not None and previous is not None else None),
            "spark_points": spark_points,
        })

    # Availability management: uptime % per business service over the
    # trailing 30 days, derived from ServiceOutage (itself auto-derived
    # from High/Critical incidents -- see sync_service_outages). This is
    # the first place in the app an availability figure exists at all.
    service_availability = []
    for service in tenant_query(ServiceOffering).order_by(ServiceOffering.name).all():
        open_outage = ServiceOutage.query.filter_by(
            service_offering_id=service.id, ended_at=None
        ).first()
        last_outage = ServiceOutage.query.filter_by(
            service_offering_id=service.id
        ).order_by(ServiceOutage.started_at.desc()).first()
        service_availability.append({
            "service": service,
            "uptime_pct": service_availability_pct(service.id),
            "open_outage": open_outage,
            "last_outage": last_outage,
        })

    return dict(
        ticket_states=ticket_states, domain_counts=domain_counts,
        kpi_history_rows=kpi_history_rows, kpi_metric_labels=kpi_metric_labels, kpi_trends=kpi_trends,
        service_availability=service_availability,
        priority_counts=priority_counts, overdue_investigations=overdue_investigations,
        modules=DOMAIN_CONFIG, open_count=open_count,
        sla_breached_open=sla_breached_open, sla_at_risk_open=sla_at_risk_open,
        sla_compliance_pct=sla_compliance_pct, mttr_by_priority=mttr_by_priority,
        closure_category_counts=closure_category_counts, recategorised_pct=recategorised_pct,
        volume_trend=volume_trend, trend_max=trend_max, aging_buckets=aging_buckets,
        change_success_pct=change_success_pct, change_total=change_total,
        pir_success_pct=pir_success_pct, pir_total=pir_total,
        fcr_pct=fcr_pct, fcr_total=fcr_total,
        csat_avg=csat_avg, csat_count=csat_count,
        top_groups=top_groups, top_groups_max=top_groups_max,
    )


def save_ticket_attachment(ticket, upload, comment_id=None):
    """Validates, scans, and stores an uploaded file against a ticket,
    optionally linking it to a specific comment (work note attachment).
    Returns (attachment, None) on success or (None, flash_message) on
    failure -- callers flash the message and redirect. Shared by the
    dedicated attachment-upload route and the comment-with-attachment
    flow so both get identical malware scanning and type validation."""
    if not upload or not upload.filename:
        return None, "Choose a file to upload."
    original = secure_filename(upload.filename)
    if not original:
        abort(400, description="The attachment filename is invalid.")
    validated = validate_attachment_upload(upload)
    if not validated:
        return None, (
            "That file type isn't allowed. Accepted attachment types: "
            + ", ".join(sorted(ATTACHMENT_ALLOWED_TYPES)) + "."
        )
    _, verified_mime_type = validated
    stored = f"{uuid.uuid4().hex}-{original}"
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], stored)
    upload.save(path)
    scan_status = core.scan_attachment(path)
    if scan_status == "infected":
        os.remove(path)
        audit("attach-blocked", ticket.number, f"{original} (malware scan positive)")
        current_app.logger.warning(
            "Rejected infected attachment upload: ticket=%s file=%s user=%s",
            ticket.number, original, current_user.id,
        )
        return None, "That file was rejected by malware scanning and was not attached."
    sha256 = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            sha256.update(chunk)
    file_size = os.path.getsize(path)
    if core.object_storage_enabled():
        # Found via real failure-injection testing against a disposable
        # MinIO backend (B-052): an object-storage outage previously
        # crashed this into a generic 500 (confirmed via a real ~8s
        # timeout-then-retry-exhausted EndpointConnectionError) and
        # -- more importantly -- never reached the os.remove(path)
        # below, so the local temp file leaked forever on every failed
        # upload. Now a clean, user-facing error instead, matching the
        # existing malware-scan-rejected return shape.
        try:
            core.object_storage_client().upload_file(
                path, os.environ["OBJECT_STORAGE_BUCKET"], stored,
                ExtraArgs={"ContentType": verified_mime_type},
            )
        except Exception:
            os.remove(path)
            current_app.logger.warning(
                "Object storage upload failed: ticket=%s file=%s user=%s",
                ticket.number, original, current_user.id,
            )
            return None, "Attachment storage is temporarily unavailable. Please try again shortly."
        os.remove(path)
    ipfs_cid = None
    if core.ipfs_enabled():
        try:
            with open(path, "rb") as handle:
                ipfs_cid = current_storage().attach_file(stored, handle.read(), verified_mime_type)
        except Exception:
            os.remove(path)
            current_app.logger.warning(
                "IPFS attachment upload failed: ticket=%s file=%s user=%s",
                ticket.number, original, current_user.id,
            )
            return None, "Attachment storage is temporarily unavailable. Please try again shortly."
        os.remove(path)
    attachment = FileAttachment(
        ticket_id=ticket.id, comment_id=comment_id, uploaded_by_id=current_user.id,
        original_name=original, stored_name=stored, ipfs_cid=ipfs_cid,
        mime_type=verified_mime_type, size_bytes=file_size,
        sha256=sha256.hexdigest(), scan_status=scan_status, tenant_id=ticket.tenant_id,
    )
    db.session.add(attachment)
    audit("attach", ticket.number, original)
    return attachment, None
