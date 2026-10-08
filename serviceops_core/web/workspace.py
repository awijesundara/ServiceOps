"""Home, workspace, profile, notifications, search and analytics routes.

Moved from app.create_app(); endpoint names are unchanged."""
import csv
import io
import json
import os
import uuid
from collections import defaultdict
from datetime import timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlparse

from flask import (
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    Response,
    send_from_directory,
    session,
    url_for,
)
from flask_login import current_user, login_required

import app as core
from serviceops_core.localization import tr
from app import (
    active_approval_delegation,
    audit,
    csv_response,
    DOMAIN_CONFIG,
    highest_notification_severity,
    integration_endpoint_valid,
    is_safe_internal_path,
    notification_target_url,
    parse_form_datetime,
    record_reference,
    record_url,
    role_at_least,
    roles,
    setting_bool,
    setting_int,
    tenant_query,
    user_can_access_client_management,
    user_is_local,
    visible_catalog_request_query,
    visible_client_contact_query,
    visible_client_organization_query,
    visible_client_ticket_query,
    visible_enterprise_record_query,
    visible_knowledge_query,
    visible_ticket_query,
)
from serviceops_core.analytics import overdue_enterprise_records, OVERDUE_RECORDS_LIMIT
from serviceops_core.ci_class_policy import restrict_ci_query_to_readable_classes
from serviceops_core.config_schema import SETTING_GROUP_META
from serviceops_core.delivery import (
    PERSONAL_EVENT_SUBSCRIPTION_PATTERNS,
    PERSONAL_EVENT_SUBSCRIPTIONS,
    provider_endpoint_allowed,
    PROVIDER_LABELS,
)
from serviceops_core.navigation import navigation_entries
from serviceops_core.notification_templates import NON_MUTABLE_EVENT_TYPES, NOTIFICATION_EVENT_TYPES
from serviceops_core.projections import project_document
from serviceops_core.security import hash_password, verify_password
from serviceops_core.web.common import analytics_kpis, manager_portal_context, usertime_filter, visible_tickets
from serviceops_models import (
    THEMES,
    AIConnection,
    ApprovalDelegation,
    Asset,
    CatalogItem,
    CatalogRequest,
    CatalogTask,
    ClientContact,
    ClientOrganization,
    ClientTicket,
    Comment,
    ConfigurationItem,
    db,
    DirectoryProfile,
    EnterpriseRecord,
    ExternalIdentity,
    Favorite,
    GroupMember,
    IntegrationConnection,
    IntegrationDelivery,
    Knowledge,
    Notification,
    NotificationPreference,
    now,
    OperationalTask,
    RecentView,
    RequestedItem,
    settings_cipher,
    SupportGroup,
    TaskSLA,
    Ticket,
    User,
    UserPreference,
    UserSession,
)


def register(app):
    @app.route("/profile/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if not user_is_local(current_user):
            abort(403, description=tr("Your password is managed by your organization's login provider, not ServiceOps."))
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirmation = request.form.get("confirm_password", "")
            if not verify_password(current_user.password_hash, current_password):
                abort(400, description=tr("The current password is incorrect."))
            min_length = setting_int("PASSWORD_MIN_LENGTH", 14)
            if len(new_password) < min_length:
                abort(400, description=tr("The new password must contain at least {min_length} characters.", min_length=min_length))
            if new_password != confirmation:
                abort(400, description=tr("The password confirmation does not match."))
            if verify_password(current_user.password_hash, new_password):
                abort(400, description=tr("The new password must differ from the current password."))
            current_user.password_hash = hash_password(new_password)
            current_user.auth_version += 1
            session["_auth_version"] = current_user.auth_version
            audit("credential rotate", current_user.username, "Local password changed")
            db.session.commit()
            flash(tr("Password changed. Other browser sessions have been invalidated."), "success")
            return redirect(url_for("preferences"))
        return render_template("change_password.html")

    @app.get("/")
    @login_required
    def dashboard():
        visible_requests = visible_catalog_request_query(current_user)
        ticket_query = visible_ticket_query(current_user)
        terminal_states = ("Resolved", "Closed", "Cancelled")
        # A single (kind, priority, state) fetch replaces what used to be five
        # separate COUNT() round trips (incident/change/open/P1/P2) on the
        # single highest-traffic page in the app; only three narrow columns
        # are pulled, and the aggregation happens in Python instead of SQL.
        ticket_rows = ticket_query.with_entities(Ticket.kind, Ticket.priority, Ticket.state).all()
        counts = {"incident": 0, "change": 0, "request": visible_requests.count()}
        open_count = 0
        incident_priority_counts = {"p1": 0, "p2": 0}
        for kind, priority, state in ticket_rows:
            if kind in counts:
                counts[kind] += 1
            if state not in terminal_states:
                open_count += 1
                if kind == "incident" and priority in ("P1", "P2"):
                    incident_priority_counts[priority.lower()] += 1
        open_ticket_query = ticket_query.filter(Ticket.state.notin_(terminal_states))
        open_count += visible_requests.filter(
            CatalogRequest.state.notin_(["Closed Complete", "Closed Incomplete", "Cancelled"])
        ).count()
        show_recent = setting_bool("DASHBOARD_SHOW_RECENT", True)
        show_my_assigned = setting_bool("DASHBOARD_SHOW_MY_ASSIGNED", True)
        show_sla_widgets = setting_bool("DASHBOARD_SHOW_SLA_WIDGETS", True)
        recent = (
            visible_tickets().filter(Ticket.deleted_at.is_(None)).order_by(Ticket.updated_at.desc()).limit(8).all()
            if show_recent else []
        )
        my_assigned = (
            open_ticket_query.filter(Ticket.assignee_id == current_user.id)
            .order_by(Ticket.priority, Ticket.updated_at.desc()).limit(8).all()
            if show_my_assigned else []
        )
        sla_at_risk_hours = setting_int("SLA_AT_RISK_HOURS", 4)
        sla_breached, sla_at_risk, sla_tickets = [], [], {}
        if show_sla_widgets:
            sla_rows = TaskSLA.query.filter(
                TaskSLA.target_type == "ticket",
                TaskSLA.target_id.in_(open_ticket_query.with_entities(Ticket.id)),
                TaskSLA.stage == "In Progress",
            ).order_by(TaskSLA.breach_at).all()
            if sla_rows:
                sla_tickets = {
                    ticket.id: ticket
                    for ticket in Ticket.query.filter(
                        Ticket.id.in_({row.target_id for row in sla_rows})
                    ).all()
                }
            breach_horizon = now() + timedelta(hours=sla_at_risk_hours)
            sla_breached = [row for row in sla_rows if row.breached][:8]
            sla_at_risk = [
                row for row in sla_rows
                if not row.breached
                and (row.breach_at if row.breach_at.tzinfo else row.breach_at.replace(tzinfo=timezone.utc))
                <= breach_horizon
            ][:8]
        return render_template(
            "dashboard.html", counts=counts, open_count=open_count, recent=recent,
            show_recent=show_recent, show_my_assigned=show_my_assigned, show_sla_widgets=show_sla_widgets,
            sla_at_risk_hours=sla_at_risk_hours,
            my_assigned=my_assigned, incident_priority_counts=incident_priority_counts,
            sla_breached=sla_breached, sla_at_risk=sla_at_risk, sla_tickets=sla_tickets,
        )

    @app.get("/manager/portal")
    @roles("manager", "admin")
    def manager_portal():
        team_rows, member_rows_by_group = manager_portal_context()
        return render_template(
            "manager_portal.html", team_rows=team_rows,
            member_rows_by_group=member_rows_by_group,
        )

    @app.get("/manager/portal/export.csv")
    @roles("manager", "admin")
    def manager_portal_export():
        team_rows, member_rows_by_group = manager_portal_context()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([
            "Team", "Team manager", "Member", "Username", "Role", "Status",
            "Open incidents", "Open changes", "Open tasks",
            "Resolved (30 days)", "SLA breached", "SLA at risk",
        ])
        for row in team_rows:
            group = row["group"]
            members = member_rows_by_group.get(group.id, [])
            if not members:
                writer.writerow([
                    group.name, group.manager.name if group.manager else "Unassigned",
                    "", "", "", "", "", "", "", "", "", "",
                ])
                continue
            for member in members:
                writer.writerow([
                    group.name, group.manager.name if group.manager else "Unassigned",
                    member["user"].name, member["user"].username, member["role_in_group"],
                    member["status"], member["open_incidents"], member["open_changes"],
                    member["open_tasks"], member["resolved_30d"],
                    member["sla_breached"], member["sla_at_risk"],
                ])
        return csv_response(buffer.getvalue(), "manager-portal-team-performance.csv")

    @app.get("/org-chart")
    @login_required
    def org_chart():
        active_users = tenant_query(User).filter_by(active=True).all()
        by_id = {u.id: u for u in active_users}
        children = defaultdict(list)
        roots = []
        for u in active_users:
            if u.manager_id and u.manager_id in by_id:
                children[u.manager_id].append(u)
            else:
                roots.append(u)
        for group in children.values():
            group.sort(key=lambda u: u.name)
        roots.sort(key=lambda u: u.name)
        return render_template(
            "org_chart.html", roots=roots, children=children,
            can_edit=role_at_least(current_user.effective_role, "admin"),
        )

    @app.get("/profile/export")
    @login_required
    def profile_export():
        """GDPR Art. 20 (data portability): a structured, machine-readable
        export of this user's own account data -- distinct from the admin
        audit-log export, which is operational, not a subject-access export."""
        user = tenant_query(User).filter_by(id=current_user.id).first_or_404()
        payload = {
            "username": user.username, "name": user.name, "email": user.email,
            "title": user.title, "department": user.department, "division": user.division,
            "employee_id": user.employee_id, "employee_type": user.employee_type,
            "business_phone": user.business_phone, "mobile_phone": user.mobile_phone,
            "location": user.location, "timezone": user.timezone, "role": user.role,
            "manager": user.manager.name if user.manager else None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "tickets_requested": [
                {"number": row.number, "title": row.title, "state": row.state, "created_at": row.created_at.isoformat()}
                for row in tenant_query(Ticket).filter_by(requester_id=user.id).order_by(Ticket.created_at.desc()).all()
            ],
        }
        directory_profile = DirectoryProfile.query.filter_by(user_id=user.id).first()
        assigned_assets = tenant_query(Asset).filter_by(owner_id=user.id).order_by(Asset.name).all()
        owned_cis = tenant_query(ConfigurationItem).filter_by(
            owner_id=user.id
        ).order_by(ConfigurationItem.name).limit(50).all()
        payload["assigned_assets"] = [
            {"asset_tag": row.asset_tag, "name": row.name, "type": row.asset_type,
             "status": row.status, "serial_number": row.serial_number}
            for row in assigned_assets
        ]
        payload["owned_configuration_items"] = [
            {"name": row.name, "class": row.ci_class,
             "operational_status": row.operational_status}
            for row in owned_cis
        ]
        if directory_profile:
            payload["directory_profile"] = directory_profile.profile
            payload["directory_groups"] = directory_profile.group_names
            payload["directory_synchronized_at"] = directory_profile.synchronized_at.isoformat()
        response = Response(
            json.dumps(payload, indent=2, sort_keys=True), mimetype="application/json",
        )
        response.headers["Content-Disposition"] = f'attachment; filename="{user.username}-data-export.json"'
        return response

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user = tenant_query(User).filter_by(id=current_user.id).first_or_404()
        directory_identity = ExternalIdentity.query.filter_by(
            user_id=user.id, provider="ldap"
        ).first()
        email_managed_externally = directory_identity is not None
        if request.method == "POST":
            if not directory_identity:
                user.name = request.form["name"].strip()[:120]
                user.email = request.form["email"].strip()[:160]
                user.title = request.form.get("title", "").strip()[:120]
                user.location = request.form.get("location", "").strip()[:120]
                user.business_phone = request.form.get("business_phone", "").strip()[:40]
                user.mobile_phone = request.form.get("mobile_phone", "").strip()[:40]
            user.timezone = request.form.get("timezone", "Asia/Tokyo")[:80]
            user.date_format = request.form.get("date_format", "system")[:40]
            avatar = request.files.get("avatar")
            if avatar and avatar.filename:
                header = avatar.stream.read(8)
                avatar.stream.seek(0)
                if header[:8] == b"\x89PNG\r\n\x1a\n":
                    ext = "png"
                elif header[:3] == b"\xff\xd8\xff":
                    ext = "jpg"
                else:
                    ext = None
                if not ext:
                    flash(tr("Profile picture must be a PNG or JPEG image."), "error")
                    return redirect(url_for("profile"))
                if request.content_length and request.content_length > 5 * 1024 * 1024:
                    flash(tr("Profile picture must be smaller than 5 MB."), "error")
                    return redirect(url_for("profile"))
                avatar_dir = os.path.join(app.config["UPLOAD_FOLDER"], "avatars")
                os.makedirs(avatar_dir, exist_ok=True)
                stored = f"user-{user.id}.{ext}"
                avatar.save(os.path.join(avatar_dir, stored))
                user.avatar_path = stored
            audit("update", user.username, "Self-service profile updated")
            db.session.commit()
            flash(tr("Profile updated."), "success")
            return redirect(url_for("profile"))
        teams = [membership.group.name for membership in GroupMember.query.filter_by(
            user_id=user.id
        ).join(SupportGroup).filter(SupportGroup.active.is_(True)).all()]
        direct_reports = tenant_query(User).filter_by(
            manager_id=user.id, active=True,
        ).order_by(User.name).all()
        managed_teams = tenant_query(SupportGroup).filter_by(
            manager_id=user.id, active=True,
        ).order_by(SupportGroup.name).all()
        manager_chain = []
        manager = user.manager
        seen = {user.id}
        while manager and manager.id not in seen and len(manager_chain) < 6:
            seen.add(manager.id)
            manager_chain.append(manager)
            manager = manager.manager
        directory_profile = DirectoryProfile.query.filter_by(user_id=user.id).first()
        assigned_assets = tenant_query(Asset).filter_by(
            owner_id=user.id
        ).order_by(Asset.name).all()
        owned_cis = tenant_query(ConfigurationItem).filter_by(
            owner_id=user.id
        ).order_by(ConfigurationItem.name).limit(50).all()
        delegation_history = ApprovalDelegation.query.filter_by(
            from_user_id=user.id, tenant_id=user.tenant_id,
        ).order_by(ApprovalDelegation.created_at.desc()).limit(20).all()
        return render_template(
            "user_form.html", user=user, self_service=True,
            email_managed_externally=email_managed_externally, teams=teams,
            directory_managed=bool(directory_identity),
            directory_profile=directory_profile,
            direct_reports=direct_reports, managed_teams=managed_teams,
            manager_chain=manager_chain,
            assigned_assets=assigned_assets, owned_cis=owned_cis,
            is_people_manager=bool(direct_reports or managed_teams),
            active_delegation=active_approval_delegation(user.id),
            delegation_history=delegation_history,
        )

    @app.post("/profile/approval-delegation")
    @login_required
    def profile_approval_delegation():
        user = tenant_query(User).filter_by(id=current_user.id).first_or_404()
        if not (
            tenant_query(User).filter_by(manager_id=user.id, active=True).first()
            or tenant_query(SupportGroup).filter_by(manager_id=user.id, active=True).first()
        ):
            abort(403, description=(
                tr("Approval absence coverage is available only to a manager with an active direct report or managed team.")
            ))
        if not user.manager or not user.manager.active or user.manager.tenant_id != user.tenant_id:
            abort(409, description=(
                tr("Your active line manager must be recorded before absence approval coverage can be delegated upward.")
            ))
        starts_at = parse_form_datetime(request.form.get("starts_at", ""))
        ends_at = parse_form_datetime(request.form.get("ends_at", ""))
        reason = request.form.get("reason", "").strip()[:500]
        if not starts_at or not ends_at or ends_at <= starts_at:
            abort(400, description=tr("Enter a valid absence start and end time."))
        if ends_at - starts_at > timedelta(days=90):
            abort(400, description=tr("An absence delegation cannot exceed 90 days."))
        if not reason:
            abort(400, description=tr("A reason is required for approval delegation."))
        ApprovalDelegation.query.filter_by(
            from_user_id=user.id, active=True, tenant_id=user.tenant_id,
        ).update({"active": False})
        delegation = ApprovalDelegation(
            from_user_id=user.id, to_user_id=user.manager.id,
            tenant_id=user.tenant_id, starts_at=starts_at, ends_at=ends_at,
            reason=reason, created_by_id=user.id,
        )
        db.session.add(delegation)
        audit(
            "approval delegate", user.username,
            f"to={user.manager.username}; starts={starts_at.isoformat()}; ends={ends_at.isoformat()}",
        )
        db.session.commit()
        flash(
            tr("Approval coverage delegated to {name}. They will not receive the initial request notification; delegated decisions remain fully attributed.", name=user.manager.name),
            "success",
        )
        return redirect(url_for("profile"))

    @app.post("/profile/approval-delegation/<int:delegation_id>/cancel")
    @login_required
    def profile_approval_delegation_cancel(delegation_id):
        delegation = ApprovalDelegation.query.filter_by(
            id=delegation_id, from_user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        ).first_or_404()
        delegation.active = False
        audit("approval delegation cancel", current_user.username, f"delegation={delegation.id}")
        db.session.commit()
        flash(tr("Approval absence coverage cancelled."), "success")
        return redirect(url_for("profile"))

    @app.get("/profile/avatar/<int:user_id>")
    @login_required
    def profile_avatar(user_id):
        user = tenant_query(User).filter_by(id=user_id).first_or_404()
        if not user.avatar_path:
            abort(404)
        avatar_dir = os.path.join(app.config["UPLOAD_FOLDER"], "avatars")
        return send_from_directory(avatar_dir, user.avatar_path)

    @app.get("/profile/sessions")
    @login_required
    def my_sessions():
        rows = UserSession.query.filter_by(user_id=current_user.id).order_by(
            UserSession.last_seen_at.desc()
        ).all()
        return render_template("sessions.html", sessions=rows, admin_view=False)

    @app.get("/notifications/poll")
    @login_required
    def notifications_poll():
        """Lightweight JSON the bell icon polls to detect newly-arrived
        notifications and ring/recolor itself without a full page reload.
        Deliberately returns the same shape the initial page-load bell
        already renders from (recent rows + unread count/severity) so the
        client can re-render with one code path instead of two."""
        query = tenant_query(Notification).filter_by(user_id=current_user.id)
        recent = query.order_by(Notification.created_at.desc()).limit(6).all()
        return jsonify({
            "unread_count": query.filter_by(read=False).count(),
            "severity": highest_notification_severity(query),
            "latest_id": recent[0].id if recent else None,
            "notifications": [
                {
                    "id": row.id, "title": row.title, "body": row.body,
                    "severity": row.severity, "read": row.read,
                    "created_at": row.created_at.isoformat(),
                    "created_at_display": usertime_filter(row.created_at, "%b %d, %H:%M"),
                    # has_target distinguishes a real destination (mark-read
                    # via POST, then redirect there -- see notification_mark_read)
                    # from the no-target fallback (a plain link straight to
                    # the notifications list, never marked read from here),
                    # exactly matching base.html's server-rendered markup.
                    "has_target": bool(notification_target_url(row.target_type, row.target_id)),
                    "mark_read_url": url_for("notification_mark_read", notification_id=row.id),
                    "list_url": url_for("notifications"),
                }
                for row in recent
            ],
        })

    @app.get("/notifications")
    @login_required
    def notifications():
        query = tenant_query(Notification).filter_by(user_id=current_user.id)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.order_by(Notification.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        notification_urls = {
            row.id: notification_target_url(row.target_type, row.target_id) for row in rows
        }
        return render_template(
            "notifications.html", rows=rows, notification_urls=notification_urls,
            page=page, pages=pages, total=total,
        )

    @app.post("/notifications/<int:notification_id>/read")
    @login_required
    def notification_mark_read(notification_id):
        row = tenant_query(Notification).filter_by(
            id=notification_id, user_id=current_user.id
        ).first_or_404()
        row.read = True
        db.session.commit()
        return redirect(notification_target_url(row.target_type, row.target_id) or url_for("notifications"))

    @app.post("/notifications/read-all")
    @login_required
    def notifications_mark_all_read():
        tenant_query(Notification).filter_by(
            user_id=current_user.id, read=False
        ).update({"read": True})
        db.session.commit()
        return redirect(url_for("notifications"))

    @app.post("/notifications/clear")
    @login_required
    def notifications_clear():
        tenant_query(Notification).filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return redirect(url_for("notifications"))

    @app.get("/analytics")
    @roles("agent", "manager", "admin")
    def analytics():
        return render_template("analytics.html", **analytics_kpis())

    @app.get("/analytics/export.csv")
    @roles("agent", "manager", "admin")
    def analytics_export_csv():
        kpis = analytics_kpis()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Open records", kpis["open_count"]])
        writer.writerow(["SLA breached (open)", kpis["sla_breached_open"]])
        writer.writerow(["SLA at risk (open)", kpis["sla_at_risk_open"]])
        writer.writerow(["SLA compliance % (30d resolved)", kpis["sla_compliance_pct"]])
        for priority in ("P1", "P2", "P3", "P4"):
            writer.writerow([f"MTTR {priority} (hours)", kpis["mttr_by_priority"].get(priority)])
        writer.writerow(["Change success % (30d)", kpis["change_success_pct"]])
        writer.writerow(["Change success % (PIR-reviewed, 30d)", kpis["pir_success_pct"]])
        writer.writerow(["First contact resolution % (30d)", kpis["fcr_pct"]])
        writer.writerow(["CSAT average (30d)", kpis["csat_avg"]])
        writer.writerow(["CSAT responses (30d)", kpis["csat_count"]])
        writer.writerow([])
        writer.writerow(["Backlog age", "Open records"])
        for bucket, count in kpis["aging_buckets"].items():
            writer.writerow([bucket, count])
        writer.writerow([])
        writer.writerow(["Team", "Open records"])
        for row in kpis["top_groups"]:
            writer.writerow([row["group"].name, row["count"]])
        writer.writerow([])
        writer.writerow(["Service", "Uptime % (30d)"])
        for row in kpis["service_availability"]:
            writer.writerow([row["service"].name, row["uptime_pct"]])
        return csv_response(buffer.getvalue(), "analytics-summary.csv")

    @app.get("/analytics/overdue")
    @roles("agent", "manager", "admin")
    def analytics_overdue():
        record_ids = visible_enterprise_record_query(current_user).with_entities(EnterpriseRecord.id)
        overdue_records, overdue_truncated = overdue_enterprise_records(EnterpriseRecord, record_ids, now)
        return render_template(
            "analytics_overdue.html", overdue_records=overdue_records, modules=DOMAIN_CONFIG,
            overdue_truncated=overdue_truncated, overdue_limit=OVERDUE_RECORDS_LIMIT,
        )

    @app.get("/internal/lookup/cis")
    @login_required
    def lookup_cis():
        q = request.args.get("q", "").strip()
        query = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        )
        if q:
            pattern = f"%{q}%"
            query = query.filter(db.or_(
                ConfigurationItem.name.ilike(pattern),
                ConfigurationItem.ci_class.ilike(pattern),
            ))
        rows = query.order_by(ConfigurationItem.name).limit(15).all()
        return jsonify([{
            "value": ci.id,
            "label": ci.name,
            "description": f"{ci.ci_class} · {ci.environment} · {ci.operational_status}",
            "owning_team": ci.support_group.name if ci.support_group else None,
        } for ci in rows])

    @app.get("/internal/lookup/cis/browse")
    @login_required
    def lookup_cis_browse():
        q = request.args.get("q", "").strip()
        ci_class = request.args.get("ci_class", "").strip()
        environment = request.args.get("environment", "").strip()
        readable = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        )
        query = readable
        if q:
            pattern = f"%{q}%"
            query = query.filter(db.or_(
                ConfigurationItem.name.ilike(pattern),
                ConfigurationItem.ip_address.ilike(pattern),
            ))
        if ci_class:
            query = query.filter(ConfigurationItem.ci_class == ci_class)
        if environment:
            query = query.filter(ConfigurationItem.environment == environment)
        rows = query.order_by(ConfigurationItem.name).limit(200).all()
        classes = [
            row[0] for row in readable.with_entities(
                ConfigurationItem.ci_class
            ).distinct().order_by(ConfigurationItem.ci_class).all()
        ]
        environments = [
            row[0] for row in readable.with_entities(
                ConfigurationItem.environment
            ).distinct().order_by(ConfigurationItem.environment).all()
        ]
        return jsonify({
            "results": [{
                "id": ci.id, "name": ci.name, "ci_class": ci.ci_class,
                "environment": ci.environment, "ip_address": ci.ip_address or "—",
                "status": ci.operational_status,
                "owning_team": ci.support_group.name if ci.support_group else None,
            } for ci in rows],
            "classes": classes, "environments": environments,
        })

    @app.get("/internal/lookup/records")
    @login_required
    def lookup_records():
        q = request.args.get("q", "").strip()
        if len(q) < 2:
            return jsonify([])
        pattern = f"%{q}%"
        results = []
        # ID subqueries, not materialized ORM rows -- see global_search().
        ticket_ids = visible_ticket_query(current_user).with_entities(Ticket.id)
        for row in Ticket.query.filter(
            Ticket.id.in_(ticket_ids),
            db.or_(Ticket.number.ilike(pattern), Ticket.title.ilike(pattern)),
        ).order_by(Ticket.updated_at.desc()).limit(10):
            results.append({
                "value": row.number, "label": f"{row.number} — {row.title}",
                "description": f"{row.kind.title()} · {row.state}",
            })
        enterprise_ids = visible_enterprise_record_query(current_user).with_entities(EnterpriseRecord.id)
        for row in EnterpriseRecord.query.filter(
            EnterpriseRecord.id.in_(enterprise_ids),
            db.or_(EnterpriseRecord.number.ilike(pattern), EnterpriseRecord.title.ilike(pattern)),
        ).order_by(EnterpriseRecord.updated_at.desc()).limit(10):
            results.append({
                "value": row.number, "label": f"{row.number} — {row.title}",
                "description": f"{DOMAIN_CONFIG[row.domain]['name']} · {row.state}",
            })
        for row in visible_knowledge_query(current_user).filter(
            db.or_(Knowledge.title.ilike(pattern), Knowledge.body.ilike(pattern))
        ).limit(10):
            results.append({
                "value": f"KB{row.id:07d}", "label": f"KB{row.id:07d} — {row.title}",
                "description": f"Knowledge · {row.category}",
            })
        request_ids = visible_catalog_request_query(current_user).with_entities(CatalogRequest.id)
        for row in CatalogRequest.query.filter(
            CatalogRequest.id.in_(request_ids), CatalogRequest.number.ilike(pattern),
        ).limit(10):
            results.append({
                "value": row.number, "label": f"{row.number} — {row.requested_for.name}",
                "description": f"Service request · {row.state}",
            })
        for row in RequestedItem.query.filter(
            RequestedItem.request_id.in_(request_ids),
            RequestedItem.number.ilike(pattern),
        ).limit(10):
            results.append({
                "value": row.number, "label": f"{row.number} — {row.item.name}",
                "description": f"Requested item · {row.state}",
            })
        return jsonify(results[:15])

    @app.get("/ui/search")
    @login_required
    def global_search():
        q = request.args.get("q", "").strip()
        results = []
        if q:
            pattern = f"%{q}%"
            normalized_q = q.casefold()
            can_access_clients = user_can_access_client_management(current_user)
            for entry in navigation_entries(SETTING_GROUP_META):
                if entry.client_management and not can_access_clients:
                    continue
                if entry.minimum_role and not role_at_least(current_user.effective_role, entry.minimum_role):
                    continue
                if normalized_q in f"{entry.label} {entry.keywords}".casefold():
                    results.append({"type": "Navigation", "label": entry.label,
                                    "url": url_for(entry.endpoint, **entry.params), "meta": entry.keywords})
            # Keep authorization filtering inside PostgreSQL. The old code
            # loaded every visible ORM object into Python simply to collect
            # IDs, making global search memory and latency grow with the
            # tenant. These Query projections compile to bounded subqueries.
            visible_ticket_ids = visible_ticket_query(current_user).with_entities(Ticket.id)
            visible_enterprise_ids = visible_enterprise_record_query(current_user).with_entities(EnterpriseRecord.id)
            visible_request_ids = visible_catalog_request_query(current_user).with_entities(CatalogRequest.id)
            def all_terms(columns):
                """Every word must appear somewhere in the record, in any order ("vpn tokyo" finds both words)."""
                words = [w for w in q.split() if w][:6]
                return db.and_(*[db.or_(*[c.ilike(f"%{w}%") for c in columns]) for w in words])

            commented_ticket_ids = db.session.query(Comment.ticket_id).filter(
                Comment.tenant_id == current_user.tenant_id, Comment.body.ilike(pattern))
            for row in Ticket.query.filter(Ticket.id.in_(visible_ticket_ids), db.or_(
                                                   all_terms([Ticket.number, Ticket.title, Ticket.description]),
                                                   Ticket.id.in_(commented_ticket_ids))).limit(20):
                results.append({"type": row.kind.title(), "label": f"{row.number} · {row.title}",
                                "url": url_for("ticket_detail", ticket_id=row.id), "meta": row.state})
            for row in visible_knowledge_query(current_user).filter(all_terms(
                [Knowledge.title, Knowledge.body, Knowledge.category]
            )).limit(20):
                results.append({"type": "Knowledge", "label": row.title,
                                "url": url_for("knowledge_detail", article_id=row.id),
                                "meta": row.category})
            for row in EnterpriseRecord.query.filter(EnterpriseRecord.id.in_(visible_enterprise_ids), db.or_(
                                                             EnterpriseRecord.number.ilike(pattern),
                                                             EnterpriseRecord.title.ilike(pattern),
                                                             EnterpriseRecord.external_id.ilike(pattern))).limit(20):
                results.append({"type": DOMAIN_CONFIG[row.domain]["name"], "label": f"{row.number} · {row.title}",
                                "url": url_for("enterprise_detail", record_id=row.id), "meta": row.state})
            for row in restrict_ci_query_to_readable_classes(
                tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
            ).filter(all_terms([
                ConfigurationItem.name, ConfigurationItem.serial_number, ConfigurationItem.ip_address,
                ConfigurationItem.model, ConfigurationItem.vendor, ConfigurationItem.description,
                ConfigurationItem.location, ConfigurationItem.ci_class, ConfigurationItem.environment,
            ])).limit(20):
                ci_url = url_for("ci_edit", ci_id=row.id) if role_at_least(current_user.effective_role, "admin") else url_for("cmdb")
                results.append({"type": "Configuration item", "label": row.name,
                                "url": ci_url, "meta": row.ci_class})
            for row in CatalogRequest.query.filter(
                CatalogRequest.id.in_(visible_request_ids),
                CatalogRequest.number.ilike(pattern),
            ).limit(20):
                results.append({
                    "type": "Request", "label": row.number,
                    "url": url_for("request_detail", request_id=row.id), "meta": row.state,
                })
            for row in RequestedItem.query.filter(
                RequestedItem.request_id.in_(visible_request_ids),
                RequestedItem.number.ilike(pattern),
            ).limit(20):
                results.append({
                    "type": "Requested item", "label": f"{row.number} · {row.item.name}",
                    "url": url_for("request_detail", request_id=row.request_id), "meta": row.state,
                })
            for row in CatalogTask.query.join(RequestedItem).filter(
                RequestedItem.request_id.in_(visible_request_ids),
                db.or_(
                    CatalogTask.number.ilike(pattern), CatalogTask.title.ilike(pattern)
                ),
            ).limit(20):
                results.append({
                    "type": "Catalog task", "label": f"{row.number} · {row.title}",
                    "url": url_for("request_detail", request_id=row.requested_item.request_id),
                    "meta": row.state,
                })
            for row in OperationalTask.query.filter(db.or_(
                OperationalTask.number.ilike(pattern), OperationalTask.title.ilike(pattern)
            )).limit(20):
                parent = record_reference(row.parent_type, row.parent_id)
                if isinstance(parent, Ticket) and not visible_ticket_query(current_user).filter(Ticket.id == parent.id).first():
                    continue
                if isinstance(parent, EnterpriseRecord) and not visible_enterprise_record_query(current_user).filter(EnterpriseRecord.id == parent.id).first():
                    continue
                results.append({
                    "type": "Change task" if row.task_kind == "change" else "Problem task",
                    "label": f"{row.number} · {row.title}",
                    "url": record_url(parent), "meta": row.state,
                })
            for row in tenant_query(Asset).filter(all_terms([
                Asset.asset_tag, Asset.name, Asset.asset_type, Asset.serial_number,
            ])).limit(20):
                results.append({"type": "Asset", "label": f"{row.asset_tag} · {row.name}",
                                "url": url_for("assets"), "meta": f"{row.asset_type} · {row.status}"})
            for row in tenant_query(CatalogItem).filter(all_terms([
                CatalogItem.name, CatalogItem.category, CatalogItem.description,
            ])).limit(20):
                results.append({"type": "Catalog item", "label": row.name,
                                "url": url_for("catalog"), "meta": row.category})
            if user_can_access_client_management(current_user):
                for row in visible_client_ticket_query(current_user).join(ClientContact).join(ClientOrganization).filter(db.or_(
                    ClientTicket.number.ilike(pattern), ClientTicket.subject.ilike(pattern),
                    ClientTicket.description.ilike(pattern), ClientContact.name.ilike(pattern),
                    ClientContact.email.ilike(pattern), ClientOrganization.name.ilike(pattern),
                )).limit(20):
                    results.append({"type": "Customer ticket", "label": f"{row.number} · {row.subject}",
                                    "url": url_for("client_ticket_detail", ticket_id=row.id),
                                    "meta": f"{row.organization.name} · {row.status}"})
                for row in visible_client_organization_query(current_user).filter(db.or_(
                    ClientOrganization.name.ilike(pattern), ClientOrganization.domain.ilike(pattern),
                    ClientOrganization.external_id.ilike(pattern),
                )).limit(20):
                    results.append({"type": "Client organization", "label": row.name,
                                    "url": url_for("client_organizations"), "meta": row.domain})
                for row in visible_client_contact_query(current_user).filter(db.or_(
                    ClientContact.name.ilike(pattern), ClientContact.email.ilike(pattern),
                    ClientContact.phone.ilike(pattern),
                )).limit(20):
                    results.append({"type": "Client contact", "label": f"{row.name} · {row.email}",
                                    "url": url_for("client_contacts"), "meta": row.organization.name})
            if role_at_least(current_user.effective_role, "admin"):
                for row in tenant_query(User).filter(db.or_(
                    User.username.ilike(pattern), User.name.ilike(pattern),
                    User.email.ilike(pattern), User.department.ilike(pattern),
                )).limit(20):
                    results.append({"type": "User", "label": f"{row.name} · {row.username}",
                                    "url": url_for("user_edit", user_id=row.id), "meta": row.role})
                for row in tenant_query(SupportGroup).filter(
                    SupportGroup.name.ilike(pattern)
                ).limit(20):
                    results.append({"type": "Group", "label": row.name,
                                    "url": url_for("itil_admin_section", section="governance-groups"),
                                    "meta": row.group_type})
                for row in AIConnection.query.filter(AIConnection.tenant_id == current_user.tenant_id, all_terms([
                        AIConnection.name, AIConnection.provider, AIConnection.model, AIConnection.endpoint])).limit(10):
                    results.append({"type": "AI service", "label": f"{row.name} · {row.model}",
                                    "url": url_for("ai.settings"), "meta": "Outside your organization" if row.external else "Private"})
                for row in tenant_query(IntegrationConnection).filter(db.or_(
                    IntegrationConnection.name.ilike(pattern),
                    IntegrationConnection.kind.ilike(pattern),
                    IntegrationConnection.endpoint.ilike(pattern),
                )).limit(20):
                    results.append({"type": "Integration", "label": row.name,
                                    "url": url_for("integrations_admin"), "meta": row.kind.upper()})
            deduplicated = []
            seen = set()
            for result in results:
                identity = (result["type"], result["url"], result["label"])
                if identity not in seen:
                    seen.add(identity)
                    deduplicated.append(result)
            results = deduplicated
        if request.accept_mimetypes.best == "application/json":
            return jsonify(results=[
                project_document("search_result", current_user.effective_role, row)
                for row in results[:30]
            ])
        return render_template("search.html", q=q, results=results[:60])

    @app.post("/ui/favorite")
    @login_required
    def favorite_toggle():
        url = request.form.get("url", "")[:500]
        if not is_safe_internal_path(url):
            abort(400)
        label = request.form.get("label", "Saved page")[:180]
        existing = Favorite.query.filter_by(user_id=current_user.id, url=url).first()
        if existing:
            db.session.delete(existing)
            active = False
        else:
            db.session.add(Favorite(user_id=current_user.id, url=url, label=label,
                                    folder=request.form.get("folder", "My favorites")[:80]))
            active = True
        db.session.commit()
        return jsonify(project_document(
            "ui_action_ack", current_user.effective_role,
            {"active": active, "url": url, "label": label},
        ))

    @app.post("/ui/history")
    @login_required
    def history_record():
        url = request.form.get("url", "")[:500]
        if not is_safe_internal_path(url) or url.startswith(("/static", "/health", "/ui/")):
            return ("", 204)
        label = request.form.get("label", "Page")[:180]
        row = RecentView.query.filter_by(user_id=current_user.id, url=url).first()
        if row:
            row.label = label
            row.viewed_at = now()
        else:
            db.session.add(RecentView(user_id=current_user.id, url=url, label=label))
        db.session.commit()
        return jsonify(project_document(
            "ui_action_ack", current_user.effective_role, {"url": url, "label": label},
        ))

    @app.route("/preferences", methods=["GET", "POST"])
    @login_required
    def preferences():
        pref = UserPreference.query.filter_by(user_id=current_user.id).first()
        if not pref:
            pref = UserPreference(
                user_id=current_user.id, density=core.setting_value("DEFAULT_DENSITY", "comfortable"),
                language=core.initial_language_preference(),
            )
            db.session.add(pref)
        notification_pref = NotificationPreference.query.filter_by(user_id=current_user.id).first()
        if not notification_pref:
            notification_pref = NotificationPreference(user_id=current_user.id)
            db.session.add(notification_pref)
        mutable_event_types = {
            key: meta for key, meta in NOTIFICATION_EVENT_TYPES.items()
            if key not in NON_MUTABLE_EVENT_TYPES
        }
        personal_connections = IntegrationConnection.query.filter_by(
            tenant_id=current_user.tenant_id, scope_type="user",
            owner_user_id=current_user.id,
        ).order_by(IntegrationConnection.name).all()
        if request.method == "POST":
            action_value = request.form.get("action", "")
            action, _, action_identifier = action_value.partition(":")
            if action in {"create_personal_channel", "toggle_personal_channel", "delete_personal_channel", "test_personal_channel"}:
                if action == "create_personal_channel":
                    name = request.form.get("name", "").strip()
                    kind = request.form.get("kind", "")
                    endpoint = request.form.get("endpoint", "").strip()
                    configuration = {}
                    secret = ""
                    if kind == "telegram":
                        endpoint = "https://api.telegram.org"
                        secret = request.form.get("secret", "").strip()
                        chat_id = request.form.get("chat_id", "").strip()
                        if not secret or not chat_id or len(chat_id) > 120:
                            abort(400, description=tr("Telegram bot token and chat ID are required."))
                        configuration = {"chat_id": chat_id, "protect_content": True}
                    if kind not in {"google_chat", "telegram", "slack", "teams", "discord"}:
                        abort(400, description=tr("Select a supported personal notification provider."))
                    if not name or len(name) > 160 or not integration_endpoint_valid(endpoint) or not provider_endpoint_allowed(kind, urlparse(endpoint).hostname):
                        abort(400, description=tr("A name and valid provider HTTPS endpoint are required."))
                    patterns = list(dict.fromkeys(request.form.getlist("event_types")))
                    if not patterns or any(value not in PERSONAL_EVENT_SUBSCRIPTION_PATTERNS for value in patterns):
                        abort(400, description=tr("Select at least one personal notification event."))
                    parsed = urlparse(endpoint)
                    db.session.add(IntegrationConnection(
                        name=name, kind=kind,
                        endpoint=parsed._replace(query="", fragment="").geturl(),
                        endpoint_encrypted=settings_cipher().encrypt(endpoint.encode()).decode(),
                        configuration_encrypted=(settings_cipher().encrypt(json.dumps(configuration).encode()).decode() if configuration else None),
                        secret_encrypted=(settings_cipher().encrypt(secret.encode()).decode() if secret else None),
                        event_types_json=json.dumps(patterns), scope_type="user",
                        owner_user_id=current_user.id, created_by_id=current_user.id,
                        tenant_id=current_user.tenant_id,
                    ))
                    audit("personal notification channel create", name, kind)
                    flash(tr("Personal notification channel added."), "success")
                else:
                    connection = IntegrationConnection.query.filter_by(
                        id=int(action_identifier) if action_identifier.isdigit() else None,
                        tenant_id=current_user.tenant_id, scope_type="user",
                        owner_user_id=current_user.id,
                    ).first_or_404()
                    if action == "toggle_personal_channel":
                        connection.active = not connection.active
                        flash(tr("Personal channel status updated."), "success")
                    elif action == "delete_personal_channel":
                        IntegrationDelivery.query.filter_by(connection_id=connection.id).update({"connection_id": None})
                        db.session.delete(connection)
                        flash(tr("Personal notification channel removed."), "success")
                    else:
                        synthetic = SimpleNamespace(event_id=str(uuid.uuid4()), event_type="notification.created", created_at=now(), payload={"title": "ServiceOps personal notification test", "body": "This destination is connected to your account."})
                        try:
                            core.deliver_webhook(synthetic, connection)
                        except Exception as error:
                            flash(tr("Test failed: {error}", error=error), "error")
                        else:
                            flash(tr("Test notification delivered successfully."), "success")
                db.session.commit()
                return redirect(url_for("preferences") + "#notifications")
            if request.form.get("action") == "notifications":
                notification_pref.email_enabled = bool(request.form.get("email_enabled"))
                muted = [
                    key for key in mutable_event_types
                    if request.form.get(f"mute_{key}")
                ]
                notification_pref.muted_event_types = json.dumps(muted)
                audit("update", "Notification preferences", current_user.username)
                db.session.commit()
                flash(tr("Notification preferences saved."), "success")
                return redirect(url_for("preferences"))
            from serviceops_core.localization import AUTOMATIC, SELECTION_ENABLED, valid_language
            language = request.form.get("language", pref.language or AUTOMATIC) if SELECTION_ENABLED else (pref.language or AUTOMATIC)
            if language != AUTOMATIC and not valid_language(language):
                abort(400, description=tr("Select a supported interface language."))
            pref.language = language
            # Later messages in this request use the newly chosen language.
            g.pop("serviceops_language", None)
            pref.theme = request.form.get("theme") if request.form.get("theme") in THEMES else "light"
            pref.density = request.form.get("density", "comfortable")
            pref.font_scale = max(80, min(140, int(request.form.get("font_scale", 100))))
            pref.high_contrast = bool(request.form.get("high_contrast"))
            pref.reduced_motion = bool(request.form.get("reduced_motion"))
            pref.nav_pinned = bool(request.form.get("nav_pinned"))
            pref.accessible_tooltips = bool(request.form.get("accessible_tooltips"))
            pref.data_patterns = bool(request.form.get("data_patterns"))
            pref.compact_dates = bool(request.form.get("compact_dates"))
            pref.keyboard_shortcuts = bool(request.form.get("keyboard_shortcuts"))
            pref.date_time_display = request.form.get("date_time_display", "both") if request.form.get("date_time_display") in {"calendar", "relative", "both"} else "both"
            submitted_start_page = request.form.get("start_page", "/")[:500]
            pref.start_page = submitted_start_page if is_safe_internal_path(submitted_start_page) else "/"
            audit("update", "UI preferences", current_user.username)
            db.session.commit()
            flash(tr("Display and accessibility preferences saved."), "success")
            return redirect(url_for("preferences"))
        muted_types = set(json.loads(notification_pref.muted_event_types or "[]"))
        return render_template(
            "preferences.html", pref=pref, notification_pref=notification_pref,
            mutable_event_types=mutable_event_types, muted_types=muted_types,
            personal_connections=personal_connections,
            personal_event_subscriptions=PERSONAL_EVENT_SUBSCRIPTIONS,
            provider_labels=PROVIDER_LABELS,
        )
