"""Administration and settings routes.

Moved from app.create_app(); endpoint names are unchanged."""
import hashlib
import hmac
import json
import os
import re
import secrets
import time as time_module
import uuid
from datetime import date, datetime, time as dt_time, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlparse

import pyotp
from flask import abort, flash, jsonify, redirect, render_template, request, Response, session, url_for
from flask_login import current_user, login_required
from sqlalchemy import func
from sqlalchemy.orm import selectinload

import app as core
from app import (
    _export_response,
    _filtered_application_log_query,
    _read_and_filter_log_file,
    ALL_ROLES,
    API_SCOPES,
    APP_START_TIME,
    apply_filter_conditions,
    audit,
    audit_integrity_key,
    CATEGORY_LEVEL_OPTION_LIMIT,
    create_api_token,
    deploy_workflow_package,
    display_version,
    filter_conditions_breadcrumb,
    find_and_merge_duplicate_groups,
    generate_mfa_backup_codes,
    hash_backup_code,
    INSTALL_SETTINGS_ACTIONS,
    integration_endpoint_valid,
    latest_update_info,
    log_history,
    merge_support_group_into,
    parse_form_datetime,
    parse_list_filter_param,
    process_data_retention_purge,
    process_outbox,
    queue_workflow_event,
    recompute_base_role,
    require_action,
    require_install_settings_authority,
    roles,
    rotate_audit_integrity_key,
    setting_bool,
    setting_int,
    simulate_workflows,
    sync_implied_role_grants,
    tenant_query,
    tenant_record_or_404,
    ticket_workflow_context,
    user_requires_mfa_by_policy,
    verify_audit_chain,
)
from serviceops_core.business_time import validate_calendar
from serviceops_core.config_schema import SETTING_DEFINITIONS, SETTING_GROUP_META
from serviceops_core.delivery import (
    EVENT_SUBSCRIPTIONS,
    GROUP_EVENT_SUBSCRIPTION_PATTERNS,
    GROUP_EVENT_SUBSCRIPTIONS,
    provider_endpoint_allowed,
    PROVIDER_LABELS,
    SYSTEM_EVENT_SUBSCRIPTION_PATTERNS,
    SYSTEM_EVENT_SUBSCRIPTIONS,
    WEBHOOK_KINDS,
)
from serviceops_core.notification_templates import NOTIFICATION_EVENT_TYPES
from serviceops_core.projections import project_document
from serviceops_core.proxy_tunnel import parse_proxy_url
from serviceops_core.security import hash_password, load_policy, verify_password
from serviceops_core.web.common import (
    _admin_referrer_redirect,
    _infrastructure_rows,
    _recovery_set_status,
    ADMIN_PANEL_GATED_ACTIONS,
    audit_filter_field_spec,
    EDITABLE_POLICY_ROLES,
    GUIDED_TOUR_ROLES,
    ITIL_ADMIN_SECTIONS,
    UNENFORCED_ACTIONS,
)
from serviceops_core.workflow import load_workflow_package, package_digest
from serviceops_models import (
    APIClient,
    ApplicationLog,
    Asset,
    Audit,
    AuditIntegrityKey,
    AuditRetentionPolicy,
    BusinessSchedule,
    CatalogItem,
    CatalogItemRouting,
    ChangeFreezeWindow,
    ClientOrganization,
    ConfigurationItem,
    DATA_CLASSIFICATION_REGISTRY,
    DataRetentionPolicy,
    db,
    DirectoryGroupMapping,
    DirectoryManagedMembership,
    DirectoryProfile,
    ExternalIdentity,
    GroupMember,
    GuidedTour,
    GuidedTourStep,
    IntegrationConnection,
    IntegrationDelivery,
    ManagedRoleGrant,
    MonitoringSource,
    NotificationTemplate,
    now,
    OutboxEvent,
    PerformanceSample,
    PlatformSetting,
    RecordLegalHold,
    RolePolicyOverride,
    ScheduleHoliday,
    ServiceOffering,
    ServiceOfferingCI,
    settings_cipher,
    SLA_AGREEMENT_TYPES,
    SLADefinition,
    SupportGroup,
    SupportGroupAlias,
    Tenant,
    Ticket,
    TicketCategory,
    TicketSubcategory,
    User,
    UserRoleGrant,
    UserSession,
    UserTourProgress,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowJob,
    WorkflowSchedule,
)


def register(app):
    @app.route("/settings/mfa", methods=["GET", "POST"])
    @login_required
    def settings_mfa():
        """TOTP MFA enrollment/management (ISO 27001 A.8.5). GET shows
        status and, when not yet enrolled, a freshly generated (not-yet-
        persisted) secret's otpauth:// provisioning URI for the user to add
        to an authenticator app -- rendering an actual QR image client-side
        from that URI is a template concern, not a security one; the URI
        alone is sufficient provisioning data. The secret is only persisted
        (Fernet-encrypted, matching the existing settings_cipher() pattern
        used for other secrets) once the user proves possession by
        submitting a valid code, so an enrollment abandoned mid-flow never
        leaves a live-but-unverified secret on the account."""
        if request.method == "POST":
            action = request.form.get("action", "enable")
            if action == "disable":
                if not verify_password(current_user.password_hash, request.form.get("password", "")):
                    abort(400, description="Your current password is required to disable MFA.")
                if user_requires_mfa_by_policy(current_user):
                    abort(400, description="MFA is required for your role by administrator policy and cannot be disabled.")
                current_user.mfa_enabled = False
                current_user.mfa_secret_encrypted = None
                current_user.mfa_backup_codes_json = None
                current_user.mfa_enrolled_at = None
                audit("mfa disable", current_user.username)
                db.session.commit()
                session.pop("_mfa_pending_secret", None)
                flash("MFA has been disabled for your account.", "success")
                return redirect(url_for("settings_mfa"))
            if action == "regenerate_backup_codes":
                if not current_user.mfa_enabled:
                    abort(400, description="Enable MFA before generating backup codes.")
                codes = generate_mfa_backup_codes()
                current_user.mfa_backup_codes_json = json.dumps([hash_backup_code(c) for c in codes])
                audit("mfa backup codes regenerate", current_user.username)
                db.session.commit()
                flash("New backup codes generated. Save them now -- they will not be shown again.", "success")
                return render_template("settings_mfa.html", enrolled=True, backup_codes=codes,
                                       mfa_required=user_requires_mfa_by_policy(current_user))
            # action == "enable": confirm possession of the pending secret.
            pending_secret = session.get("_mfa_pending_secret")
            code = request.form.get("code", "").strip()
            if not pending_secret or not code or not pyotp.TOTP(pending_secret).verify(code, valid_window=1):
                flash("Invalid verification code. Scan the QR code again and try once more.", "error")
                return redirect(url_for("settings_mfa"))
            current_user.mfa_secret_encrypted = settings_cipher().encrypt(pending_secret.encode()).decode()
            current_user.mfa_enabled = True
            current_user.mfa_enrolled_at = now()
            backup_codes = generate_mfa_backup_codes()
            current_user.mfa_backup_codes_json = json.dumps([hash_backup_code(c) for c in backup_codes])
            current_user.auth_version += 1
            session["_auth_version"] = current_user.auth_version
            audit("mfa enroll", current_user.username)
            db.session.commit()
            session.pop("_mfa_pending_secret", None)
            flash("MFA is now enabled. Save your backup codes -- they will not be shown again.", "success")
            return render_template("settings_mfa.html", enrolled=True, backup_codes=backup_codes,
                                   mfa_required=user_requires_mfa_by_policy(current_user))
        if current_user.mfa_enabled:
            return render_template("settings_mfa.html", enrolled=True, backup_codes=None,
                                   mfa_required=user_requires_mfa_by_policy(current_user))
        secret = pyotp.random_base32()
        session["_mfa_pending_secret"] = secret
        provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
            name=current_user.username, issuer_name="ServiceOps"
        )
        return render_template(
            "settings_mfa.html", enrolled=False, backup_codes=None,
            provisioning_uri=provisioning_uri, secret=secret,
            mfa_required=user_requires_mfa_by_policy(current_user),
        )

    @app.get("/admin/users")
    @roles("admin")
    @require_action("security_administer")
    def users():
        tenant_group_ids = [
            group.id for group in tenant_query(SupportGroup).all()
        ]
        tenant_user_ids = [user.id for user in tenant_query(User).all()]
        memberships = GroupMember.query.filter(
            GroupMember.group_id.in_(tenant_group_ids),
            GroupMember.user_id.in_(tenant_user_ids),
        ).all()
        directory_managed = {
            (item.user_id, item.group_id)
            for item in DirectoryManagedMembership.query.filter(
                DirectoryManagedMembership.group_id.in_(tenant_group_ids),
                DirectoryManagedMembership.user_id.in_(tenant_user_ids),
            ).all()
        }
        search = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        user_query = tenant_query(User)
        if search:
            pattern = f"%{search}%"
            user_query = user_query.filter(db.or_(
                User.username.ilike(pattern), User.name.ilike(pattern),
                User.email.ilike(pattern), User.department.ilike(pattern),
            ))
        field_spec = {
            "username": {"label": "User ID", "type": "text", "column": User.username},
            "name": {"label": "Name", "type": "text", "column": User.name},
            "email": {"label": "Email", "type": "text", "column": User.email},
            "role": {"label": "Role", "type": "choice", "column": User.role,
                    "options": [(r, r) for r in ALL_ROLES]},
            "department": {"label": "Department", "type": "text", "column": User.department},
            "active": {"label": "Active", "type": "choice",
                      "options": [("true", "true"), ("false", "false")]},
        }

        def active_filter_handler(query, op, value):
            if op == "eq":
                return query.filter(User.active.is_(value == "true"))
            if op == "ne":
                return query.filter(User.active.is_(value != "true"))
            return query

        user_query = apply_filter_conditions(
            user_query, conditions, field_spec, extra_handlers={"active": active_filter_handler}
        )
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec)
        client_fields = {
            key: {"label": spec["label"], "type": spec["type"], "options": spec.get("options", [])}
            for key, spec in field_spec.items()
        }
        return render_template(
            "users.html",
            users=user_query.order_by(User.name).all(), search=search,
            raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts, filter_fields=client_fields,
            memberships=memberships, directory_managed=directory_managed,
        )

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def user_new():
        if request.method == "POST":
            min_length = setting_int("PASSWORD_MIN_LENGTH", 14)
            password = request.form["password"]
            if len(password) < min_length:
                flash(f"Password must contain at least {min_length} characters.", "error")
                return render_template("user_form.html", user=None, self_service=False)
            initial_role = request.form["role"]
            if initial_role not in ALL_ROLES:
                abort(400, description="Select a valid role.")
            if initial_role == "superadmin" and current_user.effective_role != "superadmin":
                flash("Only a superadmin can grant the superadmin role.", "error")
                return render_template("user_form.html", user=None, self_service=False)
            user = User(username=request.form["username"], name=request.form["name"], email=request.form["email"],
                        password_hash=hash_password(password), role=initial_role,
                        title=request.form.get("title", "")[:120],
                        department=request.form.get("department", "")[:120],
                        business_phone=request.form.get("business_phone", "")[:40],
                        mobile_phone=request.form.get("mobile_phone", "")[:40],
                        timezone=request.form.get("timezone", "Asia/Tokyo")[:80],
                        date_format=request.form.get("date_format", "system")[:40])
            db.session.add(user)
            db.session.flush()
            db.session.add(UserRoleGrant(user_id=user.id, role=initial_role))
            audit("create", user.username, user.role)
            db.session.commit()
            return redirect(url_for("users"))
        return render_template("user_form.html", user=None, self_service=False)

    @app.route("/admin/users/<int:user_id>", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def user_edit(user_id):
        user = tenant_query(User).filter_by(id=user_id).first_or_404()
        if request.method == "POST":
            previous_manager = user.manager
            before = {
                "name": user.name, "email": user.email, "role": user.role,
                "active": user.active, "department": user.department,
                "manager": user.manager.name if user.manager else "None",
            }
            user.name = request.form["name"].strip()[:120]
            user.email = request.form["email"].strip()[:160]
            requested_roles = set(request.form.getlist("granted_roles")) & set(ALL_ROLES)
            if not requested_roles:
                flash("A user must hold at least one role.", "error")
                return redirect(url_for("user_edit", user_id=user.id))
            current_roles = set(user.granted_roles)
            # Only an acting superadmin may grant or revoke the superadmin
            # role on anyone -- otherwise a plain admin could hand
            # themselves (or a peer) cross-tenant platform authority.
            if ("superadmin" in requested_roles) != ("superadmin" in current_roles):
                if current_user.effective_role != "superadmin":
                    flash("Only a superadmin can grant or revoke the superadmin role.", "error")
                    return redirect(url_for("user_edit", user_id=user.id))
            existing_grant_roles = {
                g.role for g in UserRoleGrant.query.filter_by(user_id=user.id).all()
            }
            for role in ALL_ROLES:
                held, requested = role in current_roles, role in requested_roles
                if requested and not held:
                    db.session.add(UserRoleGrant(user_id=user.id, role=role))
                elif requested and held and role not in existing_grant_roles:
                    # `held` can be true purely because it's still reflected
                    # in user.role (the granted_roles property merges that
                    # column in defensively) without an actual UserRoleGrant
                    # row ever having existed for it -- true for any account
                    # whose role was set by a path other than the normal
                    # create-user route (older data, an import, a fixture).
                    # recompute_base_role() below only trusts real grant
                    # rows, so leaving this role un-backed would make it
                    # silently vanish the moment *any* other role changes on
                    # this account, even though it was requested to stay.
                    # Backfilling the row here is a one-time, permanent fix
                    # for that account.
                    db.session.add(UserRoleGrant(user_id=user.id, role=role))
                elif held and not requested:
                    # A manual revoke here always takes effect immediately.
                    # If a directory-group mapping or team-responsibility
                    # rule still implies this role, it can be re-granted on
                    # this user's next login/team-change sync -- there is no
                    # "lock" that overrides directory sync going forward.
                    UserRoleGrant.query.filter_by(user_id=user.id, role=role).delete()
                    ManagedRoleGrant.query.filter_by(user_id=user.id, role=role).delete()
            db.session.flush()
            recompute_base_role(user)
            was_active = user.active
            user.active = bool(request.form.get("active"))
            if was_active and not user.active:
                # Mirror the SCIM deactivation path (POST /scim/v2/Users):
                # end every live session immediately rather than leaving a
                # deactivated user's existing login usable until it expires
                # on its own (see verify_session_version, which enforces
                # both of these together on every subsequent request).
                user.auth_version += 1
                UserSession.query.filter_by(user_id=user.id, revoked_at=None).update(
                    {"revoked_at": now(), "revoked_by_id": current_user.id}
                )
            user.title = request.form.get("title", "").strip()[:120]
            user.department = request.form.get("department", "").strip()[:120]
            user.location = request.form.get("location", "").strip()[:120]
            user.business_phone = request.form.get("business_phone", "").strip()[:40]
            user.mobile_phone = request.form.get("mobile_phone", "").strip()[:40]
            user.timezone = request.form.get("timezone", "Asia/Tokyo")[:80]
            user.date_format = request.form.get("date_format", "system")[:40]
            user.calendar_integration = request.form.get("calendar_integration", "None")[:40]
            manager_raw = request.form.get("manager_id", "")
            if manager_raw:
                manager_id = int(manager_raw)
                if manager_id == user.id:
                    flash("A user cannot be their own manager.", "error")
                    return redirect(url_for("user_edit", user_id=user.id))
                manager = tenant_query(User).filter_by(id=manager_id).first()
                if not manager:
                    flash("Select a valid manager.", "error")
                    return redirect(url_for("user_edit", user_id=user.id))
                walker = manager
                seen = set()
                while walker and walker.id not in seen:
                    if walker.id == user.id:
                        flash(
                            f"Cannot set {manager.name} as manager: that would create a "
                            "reporting-line loop.", "error",
                        )
                        return redirect(url_for("user_edit", user_id=user.id))
                    seen.add(walker.id)
                    walker = walker.manager
                user.manager_id = manager_id
            else:
                user.manager_id = None
            db.session.flush()
            if previous_manager:
                sync_implied_role_grants(previous_manager)
            if user.manager:
                sync_implied_role_grants(user.manager)
            if user.manager and user.manager.name != before["manager"]:
                log_history(
                    "user", user.id, "Field changed", "manager",
                    before["manager"], user.manager.name,
                )
            elif not user.manager and before["manager"] != "None":
                log_history(
                    "user", user.id, "Field changed", "manager",
                    before["manager"], "None",
                )
            audit("update", user.username, json.dumps({"before": before, "role": user.role, "active": user.active}))
            db.session.commit()
            flash("User record updated.", "success")
            return redirect(url_for("user_edit", user_id=user.id))
        manager_choices = tenant_query(User).filter(
            User.active.is_(True), User.id != user.id,
        ).order_by(User.name).all()
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
        return render_template(
            "user_form.html", user=user, self_service=False,
            manager_choices=manager_choices,
            teams=teams, direct_reports=direct_reports, managed_teams=managed_teams,
            manager_chain=manager_chain, directory_profile=directory_profile,
            assigned_assets=assigned_assets, owned_cis=owned_cis,
            is_people_manager=bool(direct_reports or managed_teams),
        )

    @app.post("/admin/users/<int:user_id>/erase")
    @roles("admin")
    @require_action("security_administer")
    def user_erase(user_id):
        """GDPR Art. 17 (right to erasure). Deactivating a user (the `active`
        flag) retains name/email/phone/department/title indefinitely -- this
        actually scrubs them, replacing personal fields with an opaque
        placeholder so foreign keys (audit target, ticket requester, etc.)
        keep resolving without exposing who the record used to belong to.
        Only ever applied to an already-deactivated account, is irreversible,
        and the audit entry records that erasure happened, not the erased
        content -- logging the old name/email defeats the purpose."""
        user = tenant_query(User).filter_by(id=user_id).first_or_404()
        if user.id == current_user.id:
            abort(400, description="You cannot erase your own account.")
        if user.active:
            abort(400, description="Deactivate this account before erasing its personal data.")
        if user.erased_at:
            abort(400, description="This account's personal data has already been erased.")
        placeholder = f"erased-user-{user.id}"
        user.name = f"Erased user #{user.id}"
        user.username = placeholder
        user.email = f"{placeholder}@erased.invalid"
        user.title = ""
        user.department = ""
        user.division = None
        user.employee_id = None
        user.employee_type = None
        user.business_phone = ""
        user.mobile_phone = ""
        user.location = ""
        user.avatar_path = None
        user.manager_id = None
        user.password_hash = hash_password(uuid.uuid4().hex)
        user.auth_version += 1
        user.erased_at = now()
        ExternalIdentity.query.filter_by(user_id=user.id).delete()
        from serviceops_core.ai import service as ai_service
        ai_service.purge_user_conversations(user.id)
        audit("erase", placeholder, "Personal data erased (GDPR Art. 17)")
        db.session.commit()
        flash(f"{placeholder}'s personal data has been erased.", "success")
        return redirect(url_for("users"))

    @app.route("/admin/guided-tours", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def guided_tours_admin():
        """B-120: admin authoring page for contextual guided tours. DB-backed
        (not Git-backed config) so a non-engineer admin can author/edit tour
        content without a deploy, matching ClientMacro/ClientTrigger's
        existing precedent for admin-editable per-tenant content."""
        if request.method == "POST":
            action = request.form.get("action", "create")
            if action == "create":
                key = request.form.get("key", "").strip().lower().replace(" ", "-")
                title = request.form.get("title", "").strip()
                if not key or not title:
                    flash("A key and title are required.", "error")
                elif tenant_query(GuidedTour).filter_by(key=key).first():
                    flash("A tour with that key already exists.", "error")
                else:
                    roles_selected = [r for r in request.form.getlist("target_roles") if r in GUIDED_TOUR_ROLES]
                    tour = GuidedTour(
                        tenant_id=current_user.tenant_id, key=key, title=title,
                        description=request.form.get("description", "").strip()[:500],
                        target_route=request.form.get("target_route", "*").strip() or "*",
                        target_roles=",".join(roles_selected),
                        created_by_id=current_user.id,
                    )
                    db.session.add(tour)
                    audit("guided tour created", key, title)
                    db.session.commit()
                    flash(f"{title} created. Add steps below.", "success")
            elif action == "update_tour":
                tour = tenant_record_or_404(GuidedTour, request.form.get("tour_id", type=int))
                title = request.form.get("title", "").strip()
                if not title:
                    flash("Title is required.", "error")
                else:
                    roles_selected = [r for r in request.form.getlist("target_roles") if r in GUIDED_TOUR_ROLES]
                    tour.title = title
                    tour.description = request.form.get("description", "").strip()[:500]
                    tour.target_route = request.form.get("target_route", "*").strip() or "*"
                    tour.target_roles = ",".join(roles_selected)
                    # Content changed -- bump version so users who already
                    # dismissed/completed the prior version are re-prompted
                    # (see UserTourProgress.tour_version_seen).
                    tour.version += 1
                    audit("guided tour updated", tour.key, f"version={tour.version}")
                    db.session.commit()
                    flash(f"{tour.title} updated (now version {tour.version}).", "success")
            elif action == "toggle_active":
                tour = tenant_record_or_404(GuidedTour, request.form.get("tour_id", type=int))
                tour.active = not tour.active
                audit("guided tour toggled", tour.key, "Active" if tour.active else "Inactive")
                db.session.commit()
                flash(f"{tour.title} is now {'active' if tour.active else 'inactive'}.", "success")
            elif action == "delete":
                tour = tenant_record_or_404(GuidedTour, request.form.get("tour_id", type=int))
                title = tour.title
                # GuidedTourStep cascades via the ORM relationship, but
                # UserTourProgress has no FK cascade -- delete it explicitly
                # first or this fails with a ForeignKeyViolation for any
                # tour a user has actually seen (found during verification).
                UserTourProgress.query.filter_by(tour_id=tour.id).delete()
                db.session.delete(tour)
                audit("guided tour deleted", title, "")
                db.session.commit()
                flash(f"{title} deleted.", "success")
            elif action == "add_step":
                tour = tenant_record_or_404(GuidedTour, request.form.get("tour_id", type=int))
                title = request.form.get("step_title", "").strip()
                body = request.form.get("step_body", "").strip()
                if not title or not body:
                    flash("Step title and body are required.", "error")
                else:
                    next_order = (
                        db.session.query(db.func.max(GuidedTourStep.step_order))
                        .filter_by(tour_id=tour.id).scalar() or 0
                    ) + 1
                    db.session.add(GuidedTourStep(
                        tenant_id=current_user.tenant_id, tour_id=tour.id, step_order=next_order,
                        target_selector=request.form.get("target_selector", "").strip()[:300],
                        title=title, body=body,
                        placement=request.form.get("placement", "bottom") if request.form.get("placement") in
                        ("top", "bottom", "left", "right", "center") else "bottom",
                    ))
                    tour.version += 1
                    audit("guided tour step added", tour.key, title)
                    db.session.commit()
                    flash("Step added.", "success")
            elif action == "delete_step":
                step = GuidedTourStep.query.join(GuidedTour).filter(
                    GuidedTourStep.id == request.form.get("step_id", type=int),
                    GuidedTour.tenant_id == current_user.tenant_id,
                ).first_or_404()
                tour = step.tour
                db.session.delete(step)
                tour.version += 1
                audit("guided tour step deleted", tour.key, step.title)
                db.session.commit()
                flash("Step removed.", "success")
            return redirect(url_for("guided_tours_admin"))
        tours = tenant_query(GuidedTour).options(selectinload(GuidedTour.steps)).order_by(GuidedTour.title).all()
        return render_template("guided_tours_admin.html", tours=tours, roles=GUIDED_TOUR_ROLES)

    @app.route("/admin/notification-templates", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def notification_templates_admin():
        """B-130: admin-editable subject/body per notification event_type.
        A row only exists once an admin has customized that event_type;
        create_notification() falls back to the caller's own literal
        default wording whenever no active template is found, so this page
        is purely additive -- nothing here can be misconfigured into
        silence the way a required-config page could."""
        if request.method == "POST":
            event_type = request.form.get("event_type", "")
            if event_type not in NOTIFICATION_EVENT_TYPES:
                abort(400, description="Unknown notification event type.")
            action = request.form.get("action", "save")
            template = NotificationTemplate.query.filter_by(
                tenant_id=current_user.tenant_id, event_type=event_type,
            ).first()
            if action == "reset":
                if template:
                    db.session.delete(template)
                    audit("notification template reset", event_type, "")
                    db.session.commit()
                    flash("Reverted to the default wording.", "success")
            else:
                subject = request.form.get("subject_template", "").strip()
                body = request.form.get("body_template", "").strip()
                if not subject or not body:
                    flash("Subject and body are both required.", "error")
                else:
                    if template:
                        template.subject_template = subject[:255]
                        template.body_template = body
                        template.active = True
                    else:
                        db.session.add(NotificationTemplate(
                            tenant_id=current_user.tenant_id, event_type=event_type,
                            subject_template=subject[:255], body_template=body,
                        ))
                    audit("notification template saved", event_type, "")
                    db.session.commit()
                    flash("Notification template saved.", "success")
            return redirect(url_for("notification_templates_admin"))
        templates_by_event = {
            row.event_type: row
            for row in tenant_query(NotificationTemplate).all()
        }
        return render_template(
            "notification_templates_admin.html",
            event_types=NOTIFICATION_EVENT_TYPES, templates_by_event=templates_by_event,
        )

    @app.get("/admin")
    @roles("admin")
    @require_action("security_administer")
    def admin_home():
        return render_template("admin_home.html", active_section=None, update_info=latest_update_info())

    @app.get("/admin/section/<section>")
    @roles("admin")
    @require_action("security_administer")
    def admin_section(section):
        if section not in {
            "people-access", "service-configuration", "connections-channels",
            "automation-content", "platform-security",
        }:
            abort(404)
        return render_template("admin_home.html", active_section=section)

    @app.get("/admin/access")
    @roles("admin")
    @require_action("security_administer")
    def admin_access():
        """Compatibility redirect for the retired duplicate access hub."""
        return redirect(url_for("admin_section", section="people-access"), code=302)

    @app.route("/admin/roles", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def admin_roles():
        # config/authorization.json is the Git-backed recommended baseline
        # (loaded once per process via serviceops_core.security.load_policy,
        # @lru_cache -- never mutated at runtime, so no cache-invalidation
        # concern). RolePolicyOverride is the DB-backed, tenant-scoped layer
        # an admin can adjust on top of it; "reset to recommended" for a
        # role is just deleting that role's override rows.
        policy = load_policy()
        tenant_id = current_user.tenant_id
        if request.method == "POST":
            action = request.form.get("action", "save")
            if action == "reset":
                role = request.form.get("role", "")
                if role not in EDITABLE_POLICY_ROLES:
                    abort(400)
                removed = RolePolicyOverride.query.filter_by(tenant_id=tenant_id, role=role).delete()
                audit("configure", "Role policy reset", f"{role} reset to recommended ({removed} override(s) removed)")
                db.session.commit()
                flash(f"{role.capitalize()}'s permissions were reset to the ITIL-recommended baseline.", "success")
            else:
                existing = {
                    (row.role, row.action): row
                    for row in RolePolicyOverride.query.filter_by(tenant_id=tenant_id).all()
                }
                changed = 0
                for role in EDITABLE_POLICY_ROLES:
                    baseline_actions = set(policy["roles"].get(role, ()))
                    for act in policy["actions"]:
                        if act in UNENFORCED_ACTIONS or (role != "admin" and act in ADMIN_PANEL_GATED_ACTIONS):
                            # Checkbox is hidden in the template for these
                            # (role, action) combinations -- the form never
                            # submits a value for them, which would
                            # otherwise read as "unchecked" and, for any
                            # action a role's baseline actually grants
                            # (e.g. manager's baseline includes "approve"),
                            # get misread as an explicit request to revoke
                            # it. Skip entirely so a save never touches
                            # overrides for something the UI doesn't even
                            # let the admin see or intend to change.
                            continue
                        granted = request.form.get(f"grant__{role}__{act}") == "on"
                        matches_baseline = granted == (act in baseline_actions)
                        row = existing.get((role, act))
                        if matches_baseline:
                            if row:
                                db.session.delete(row)
                                changed += 1
                        elif row:
                            if row.is_granted != granted:
                                row.is_granted = granted
                                row.updated_by_id = current_user.id
                                changed += 1
                        else:
                            db.session.add(RolePolicyOverride(
                                tenant_id=tenant_id, role=role, action=act,
                                is_granted=granted, updated_by_id=current_user.id,
                            ))
                            changed += 1
                if changed:
                    audit("configure", "Role policy", f"{changed} role/action override(s) changed")
                    db.session.commit()
                    flash(f"Saved {changed} permission change(s).", "success")
                else:
                    flash("No changes to save.", "success")
            return redirect(url_for("admin_roles"))

        overrides = {
            (row.role, row.action): row.is_granted
            for row in RolePolicyOverride.query.filter_by(tenant_id=tenant_id).all()
        }
        effective_role_actions = {}
        for role in policy["roles"]:
            baseline_actions = set(policy["roles"].get(role, ()))
            if role not in EDITABLE_POLICY_ROLES:
                effective_role_actions[role] = baseline_actions
                continue
            effective = set(baseline_actions)
            for act in policy["actions"]:
                override = overrides.get((role, act))
                if override is True:
                    effective.add(act)
                elif override is False:
                    effective.discard(act)
            effective_role_actions[role] = effective
        has_overrides = {
            role: any(r == role for r, _ in overrides) for role in EDITABLE_POLICY_ROLES
        }
        return render_template(
            "admin_roles.html", actions=policy["actions"], role_actions=effective_role_actions,
            editable_roles=EDITABLE_POLICY_ROLES, baseline_role_actions=policy["roles"],
            has_overrides=has_overrides,
            admin_panel_gated_actions=ADMIN_PANEL_GATED_ACTIONS,
            unenforced_actions=UNENFORCED_ACTIONS,
        )

    @app.get("/admin/sessions")
    @roles("admin")
    @require_action("security_administer")
    def admin_sessions():
        rows = tenant_query(UserSession).order_by(UserSession.last_seen_at.desc()).limit(1000).all()
        return render_template("sessions.html", sessions=rows, admin_view=True)

    @app.route("/platform/tenants", methods=["GET", "POST"])
    @roles("superadmin")
    @require_action("platform_administer")
    def platform_tenants():
        """Cross-tenant platform administration. Deliberately bypasses the
        normal tenant_query() scoping every other admin screen uses -- only
        a superadmin (not a plain per-tenant admin) reaches this route at
        all (see roles()/require_action() above), and every query here is
        Tenant.query, never tenant_query(Tenant), by design."""
        if request.method == "POST":
            action = request.form.get("action")
            if action == "create_tenant":
                slug = request.form.get("slug", "").strip().lower()[:80]
                name = request.form.get("name", "").strip()[:160]
                if not slug or not name or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
                    flash("Enter a name and a lowercase, hyphen-safe slug.", "error")
                    return redirect(url_for("platform_tenants"))
                if Tenant.query.filter_by(slug=slug).first():
                    flash(f"A tenant with slug \"{slug}\" already exists.", "error")
                    return redirect(url_for("platform_tenants"))
                tenant = Tenant(slug=slug, name=name)
                db.session.add(tenant)
                audit("create", f"Tenant {slug}", name)
                flash(f"Tenant \"{name}\" created.", "success")
            elif action == "set_tenant_active":
                tenant = Tenant.query.filter_by(id=int(request.form["tenant_id"])).first_or_404()
                if tenant.id == current_user.tenant_id and not request.form.get("active"):
                    flash("You cannot deactivate the tenant your own account belongs to.", "error")
                    return redirect(url_for("platform_tenants"))
                tenant.active = bool(request.form.get("active"))
                audit("configure", f"Tenant {tenant.slug}", f"active={tenant.active}")
                flash(f"Tenant \"{tenant.name}\" {'activated' if tenant.active else 'deactivated'}.", "success")
            else:
                abort(400)
            db.session.commit()
            return redirect(url_for("platform_tenants"))
        tenants = Tenant.query.order_by(Tenant.id).all()
        user_counts = dict(
            db.session.query(User.tenant_id, db.func.count(User.id)).group_by(User.tenant_id).all()
        )
        return render_template("platform_tenants.html", tenants=tenants, user_counts=user_counts)

    @app.route("/admin/api-clients", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def api_clients_admin():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            try:
                acting_user_id = int(request.form.get("acting_user_id", ""))
            except (TypeError, ValueError):
                abort(400, description="Select a valid acting user.")
            acting_user = tenant_query(User).filter_by(
                id=acting_user_id, active=True
            ).first()
            scopes = sorted(set(request.form.getlist("scopes")))
            if not name or len(name) > 160:
                abort(400, description="Client name must contain 1-160 characters.")
            if not acting_user:
                abort(400, description="The acting user must be active in this tenant.")
            if not scopes or not set(scopes).issubset(API_SCOPES):
                abort(400, description="Select one or more valid API scopes.")
            token, prefix, token_hash = create_api_token()
            client = APIClient(
                name=name, token_prefix=prefix, token_hash=token_hash,
                scopes_json=json.dumps(scopes),
                acting_user_id=acting_user.id,
                created_by_id=current_user.id,
                tenant_id=current_user.tenant_id,
            )
            db.session.add(client)
            audit(
                "api client create", name,
                f"acting_user={acting_user.username}; scopes={','.join(scopes)}",
            )
            db.session.commit()
            return render_template(
                "api_clients.html",
                clients=APIClient.query.filter_by(
                    tenant_id=current_user.tenant_id
                ).order_by(APIClient.created_at.desc()).all(),
                users=tenant_query(User).filter_by(active=True).order_by(User.name).all(),
                available_scopes=sorted(API_SCOPES),
                new_token=token,
                new_client_name=name,
            )
        return render_template(
            "api_clients.html",
            clients=APIClient.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(APIClient.created_at.desc()).all(),
            users=tenant_query(User).filter_by(active=True).order_by(User.name).all(),
            available_scopes=sorted(API_SCOPES),
            new_token=None,
            new_client_name=None,
        )

    @app.post("/admin/api-clients/<int:client_id>/revoke")
    @roles("admin")
    @require_action("security_administer")
    def api_client_revoke(client_id):
        client = APIClient.query.filter_by(
            id=client_id, tenant_id=current_user.tenant_id
        ).first_or_404()
        if client.active:
            client.active = False
            client.revoked_at = now()
            audit("api client revoke", client.name, client.client_id)
            db.session.commit()
        return redirect(url_for("api_clients_admin"))

    @app.route("/admin/integrations", methods=["GET", "POST"])
    @roles("admin")
    @require_action("configure")
    def integrations_admin():
        revealed_token = None
        revealed_secret = None
        active_view = request.args.get("view", "overview")
        if active_view not in {"overview", "channels", "channel", "add", "deliveries", "monitoring"}:
            abort(404)
        selected_connection = None
        if active_view == "channel":
            selected_connection = IntegrationConnection.query.filter_by(
                id=request.args.get("connection", type=int),
                tenant_id=current_user.tenant_id,
            ).first_or_404()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "create_connection":
                name = request.form.get("name", "").strip()
                kind = request.form.get("kind", "")
                endpoint = request.form.get("endpoint", "").strip()
                configuration = {}
                if kind == "telegram":
                    endpoint = "https://api.telegram.org"
                    chat_id = request.form.get("chat_id", "").strip()
                    thread_id = request.form.get("message_thread_id", "").strip()
                    if not chat_id or len(chat_id) > 120:
                        abort(400, description="A Telegram chat ID is required.")
                    if thread_id and (not thread_id.isdigit() or len(thread_id) > 20):
                        abort(400, description="Telegram topic ID must be numeric.")
                    configuration = {
                        "chat_id": chat_id,
                        "protect_content": request.form.get("protect_content") == "on",
                    }
                    if thread_id:
                        configuration["message_thread_id"] = int(thread_id)
                interactive_google_chat = (
                    kind == "google_chat" and request.form.get("delivery_mode") == "interactive"
                )
                if interactive_google_chat:
                    # The interactive app posts via the real Chat REST API
                    # (google_chat_post_message()), not a plain incoming
                    # webhook -- endpoint is the target space's resource
                    # name, not a URL, and secret is that app's own service
                    # account key rather than a webhook signing secret.
                    endpoint = request.form.get("space_id", "").strip()
                    if not re.fullmatch(r"spaces/[\w-]+", endpoint):
                        abort(400, description='Space ID must look like "spaces/AAAAxxxxx".')
                    configuration["interactive"] = True
                # Outbound proxy override, applicable to every provider kind
                # (not just Telegram): lets an administrator choose per
                # channel whether to inherit the OUTBOUND_PROXY_URL platform
                # default, bypass it, or use a different proxy just for this
                # one destination -- see resolve_outbound_proxies().
                proxy_mode = request.form.get("proxy_mode", "default")
                if proxy_mode not in ("default", "none", "custom"):
                    abort(400, description="Invalid outbound proxy mode.")
                if proxy_mode != "default":
                    configuration["proxy_mode"] = proxy_mode
                if proxy_mode == "custom":
                    proxy_url = request.form.get("proxy_url", "").strip()
                    try:
                        parse_proxy_url(proxy_url)
                    except ValueError:
                        abort(400, description="Custom outbound proxy must be a valid http:// or https:// URL.")
                    configuration["proxy_url"] = proxy_url
                if (
                    not name or len(name) > 160
                    or kind not in WEBHOOK_KINDS
                    or (not interactive_google_chat and (
                        not integration_endpoint_valid(endpoint)
                        or not provider_endpoint_allowed(kind, urlparse(endpoint).hostname)
                    ))
                ):
                    abort(400, description=(
                        "A name, supported kind and public HTTPS endpoint are required."
                    ))
                secret = request.form.get("secret", "").strip() if kind in {
                    "webhook", "siem", "telegram",
                } else ""
                if interactive_google_chat:
                    secret = request.form.get("service_account_json", "").strip()
                    try:
                        credentials = json.loads(secret)
                        if not credentials.get("private_key") or not credentials.get("client_email"):
                            raise ValueError
                    except (TypeError, ValueError):
                        abort(400, description=(
                            "A valid Google service-account JSON key (with private_key and "
                            "client_email) is required for the interactive app."
                        ))
                if kind == "telegram" and not secret:
                    abort(400, description="A Telegram bot token is required.")
                if kind in {"webhook", "siem"} and not secret:
                    secret = secrets.token_urlsafe(32)
                    revealed_secret = secret
                encrypted = (
                    settings_cipher().encrypt(secret.encode()).decode()
                    if secret else None
                )
                display_endpoint = endpoint
                if not interactive_google_chat:
                    parsed_endpoint = urlparse(endpoint)
                    display_endpoint = parsed_endpoint._replace(query="", fragment="").geturl()
                encrypted_endpoint = settings_cipher().encrypt(endpoint.encode()).decode()
                encrypted_configuration = (
                    settings_cipher().encrypt(json.dumps(configuration).encode()).decode()
                    if configuration else None
                )
                scope_type = request.form.get("scope_type", "tenant")
                support_group = None
                allowed_patterns = SYSTEM_EVENT_SUBSCRIPTION_PATTERNS
                if scope_type == "group":
                    support_group = tenant_record_or_404(
                        SupportGroup, request.form.get("support_group_id", type=int)
                    )
                    allowed_patterns = GROUP_EVENT_SUBSCRIPTION_PATTERNS
                elif scope_type != "tenant":
                    abort(400, description="Administrators can create organization or team channels here.")
                patterns = list(dict.fromkeys(request.form.getlist("event_types")))
                if not patterns or any(
                    pattern not in allowed_patterns for pattern in patterns
                ):
                    abort(400, description="Select at least one event supported by this audience.")
                db.session.add(IntegrationConnection(
                    name=name, kind=kind, endpoint=display_endpoint,
                    endpoint_encrypted=encrypted_endpoint,
                    configuration_encrypted=encrypted_configuration,
                    secret_encrypted=encrypted,
                    event_types_json=json.dumps(patterns),
                    scope_type=scope_type,
                    support_group_id=support_group.id if support_group else None,
                    created_by_id=current_user.id,
                    tenant_id=current_user.tenant_id,
                ))
                audit("integration create", name, kind)
            elif action == "test_connection":
                connection = IntegrationConnection.query.filter_by(
                    id=request.form.get("connection_id", type=int),
                    tenant_id=current_user.tenant_id,
                ).first_or_404()
                event_type = "audit.created" if connection.kind == "siem" else "notification.created"
                synthetic = SimpleNamespace(
                    event_id=str(uuid.uuid4()), event_type=event_type,
                    created_at=now(), payload={
                        "title": "ServiceOps test notification",
                        "body": f"{connection.name} is configured and can receive messages.",
                        "action": "integration test",
                    },
                )
                try:
                    status = core.deliver_webhook(synthetic, connection)
                except Exception as error:
                    audit("integration test failed", connection.name, type(error).__name__)
                    db.session.commit()
                    flash(f"Test failed: {error}", "error")
                else:
                    audit("integration test", connection.name, f"HTTP {status}")
                    db.session.commit()
                    flash("Test notification delivered successfully.", "success")
                return redirect(url_for("integrations_admin"))
            elif action == "toggle_connection":
                connection = IntegrationConnection.query.filter_by(
                    id=request.form.get("connection_id", type=int),
                    tenant_id=current_user.tenant_id,
                ).first_or_404()
                connection.active = not connection.active
                audit("integration toggle", connection.name, "active" if connection.active else "disabled")
            elif action == "update_connection_events":
                connection = IntegrationConnection.query.filter_by(
                    id=request.form.get("connection_id", type=int),
                    tenant_id=current_user.tenant_id,
                ).first_or_404()
                patterns = list(dict.fromkeys(request.form.getlist("event_types")))
                allowed_patterns = (
                    GROUP_EVENT_SUBSCRIPTION_PATTERNS
                    if connection.scope_type == "group" else SYSTEM_EVENT_SUBSCRIPTION_PATTERNS
                )
                if any(pattern not in allowed_patterns for pattern in patterns):
                    abort(400, description="Select only supported notification events.")
                connection.event_types_json = json.dumps(patterns or ["__none__"])
                audit(
                    "integration subscriptions updated", connection.name,
                    ", ".join(patterns) if patterns else "No events selected",
                )
                flash("Notification event subscriptions updated.", "success")
            elif action == "update_connection_proxy":
                connection = IntegrationConnection.query.filter_by(
                    id=request.form.get("connection_id", type=int),
                    tenant_id=current_user.tenant_id,
                ).first_or_404()
                proxy_mode = request.form.get("proxy_mode", "default")
                if proxy_mode not in ("default", "none", "custom"):
                    abort(400, description="Invalid outbound proxy mode.")
                # Merge into the existing configuration rather than replacing
                # it outright -- other provider-specific fields (Telegram's
                # chat_id/message_thread_id/protect_content) live in this
                # same encrypted JSON dict and must survive a proxy-only edit.
                configuration = dict(connection.configuration)
                configuration.pop("proxy_mode", None)
                configuration.pop("proxy_url", None)
                if proxy_mode != "default":
                    configuration["proxy_mode"] = proxy_mode
                if proxy_mode == "custom":
                    proxy_url = request.form.get("proxy_url", "").strip()
                    try:
                        parse_proxy_url(proxy_url)
                    except ValueError:
                        abort(400, description="Custom outbound proxy must be a valid http:// or https:// URL.")
                    configuration["proxy_url"] = proxy_url
                connection.configuration_encrypted = (
                    settings_cipher().encrypt(json.dumps(configuration).encode()).decode()
                    if configuration else None
                )
                audit("integration proxy updated", connection.name, proxy_mode)
                flash("Outbound proxy setting updated.", "success")
            elif action == "create_monitoring_source":
                name = request.form.get("name", "").strip()
                group = tenant_record_or_404(
                    SupportGroup, int(request.form.get("group_id", "0"))
                )
                if (
                    not name or len(name) > 160 or not group.active
                    or group.group_type != "IT Fulfillment"
                ):
                    abort(400, description=(
                        "A name and active IT fulfillment team are required."
                    ))
                token, prefix, token_hash = create_api_token()
                source = MonitoringSource(
                    name=name, token_prefix=prefix, token_hash=token_hash,
                    assignment_group_id=group.id,
                    created_by_id=current_user.id,
                    tenant_id=current_user.tenant_id,
                )
                db.session.add(source)
                db.session.flush()
                revealed_token = {
                    "token": token, "source_id": source.source_id, "name": name,
                }
                audit("monitoring source create", name, group.name)
            else:
                abort(400)
            db.session.commit()
        return render_template(
            "integrations.html",
            connections=IntegrationConnection.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(IntegrationConnection.name).all(),
            sources=MonitoringSource.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(MonitoringSource.name).all(),
            deliveries=IntegrationDelivery.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(IntegrationDelivery.id.desc()).limit(50).all(),
            outbox=OutboxEvent.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(OutboxEvent.id.desc()).limit(50).all(),
            teams=tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment", active=True
            ).order_by(SupportGroup.name).all(),
            revealed_token=revealed_token,
            revealed_secret=revealed_secret,
            provider_labels=PROVIDER_LABELS,
            event_subscriptions=EVENT_SUBSCRIPTIONS,
            group_event_subscriptions=GROUP_EVENT_SUBSCRIPTIONS,
            system_event_subscriptions=SYSTEM_EVENT_SUBSCRIPTIONS,
            active_view=active_view,
            selected_connection=selected_connection,
        )

    @app.post("/admin/integrations/process")
    @roles("admin")
    @require_action("configure")
    def integrations_process():
        # Capped tightly: this runs synchronously in the request thread, and
        # each event may make an SMTP/webhook call with its own network
        # timeout. The background tools/outbox_worker.py is the primary,
        # unbounded drain path; this route is a manual nudge, not a bulk tool.
        count = process_outbox(limit=5)
        audit("integration process", "Outbox", f"{count} event(s)")
        db.session.commit()
        flash(f"Processed {count} outbox event(s).", "success")
        return redirect(url_for("integrations_admin"))

    @app.route("/admin/workflows", methods=["GET", "POST"])
    @roles("admin")
    @require_action("configure")
    def workflows_admin():
        simulation = None
        if request.method == "POST":
            action = request.form.get("action")
            if action == "deploy":
                result = deploy_workflow_package(current_user.id)
                audit(
                    "workflow deploy", "Git workflow package",
                    f"{result['package_hash']}; {result['published']} published",
                )
                db.session.commit()
                flash(
                    f"Automation rules validated; {result['published']} new version(s) published.",
                    "success",
                )
                return redirect(url_for("workflows_admin"))
            if action == "simulate":
                try:
                    context = json.loads(request.form.get("context_json", "{}"))
                    if not isinstance(context, dict):
                        raise ValueError
                    simulation = simulate_workflows(
                        request.form.get("event_type", ""), context,
                        current_user.tenant_id,
                    )
                except (json.JSONDecodeError, ValueError, KeyError) as error:
                    abort(400, description=f"Simulation input is invalid: {error}")
                audit("workflow simulate", request.form.get("event_type", ""),
                      f"{len(simulation)} match(es)")
                db.session.commit()
            elif action == "manual_trigger":
                ticket = tenant_record_or_404(
                    Ticket, int(request.form.get("ticket_id", ""))
                )
                context = ticket_workflow_context(ticket)
                context["triggered_by"] = current_user.username
                job = queue_workflow_event(
                    "ticket.manual", "ticket", ticket.id, context,
                    tenant_id=ticket.tenant_id,
                )
                audit("workflow manual trigger", ticket.number, job.event_id)
                db.session.commit()
                flash(f"Manual workflow event queued for {ticket.number}.", "success")
                return redirect(url_for("workflows_admin"))
            elif action == "replay_dead":
                job = tenant_record_or_404(
                    WorkflowJob, int(request.form.get("job_id", ""))
                )
                if job.state != "Dead":
                    abort(409, description="Only dead workflow jobs can be replayed.")
                job.state = "Retry"
                job.attempts = 0
                job.available_at = now()
                job.last_error = None
                audit("workflow replay", job.event_id, f"{job.target_type}:{job.target_id}")
                db.session.commit()
                flash("Dead workflow job queued for controlled replay.", "success")
                return redirect(url_for("workflows_admin"))
            elif action == "create_schedule":
                key = request.form.get("schedule_key", "").strip()
                name = request.form.get("name", "").strip()
                if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,119}", key):
                    abort(400, description=(
                        "Schedule key must be 3-120 lowercase letters, numbers or hyphens."
                    ))
                if not name or len(name) > 160:
                    abort(400, description="Schedule name must contain 1-160 characters.")
                try:
                    ticket = tenant_record_or_404(
                        Ticket, int(request.form.get("ticket_id", ""))
                    )
                    interval = int(request.form.get("interval_minutes", ""))
                    start_text = request.form.get("next_run_at", "").strip()
                    next_run = datetime.fromisoformat(start_text) if start_text else now()
                    if next_run.tzinfo is None:
                        next_run = next_run.replace(tzinfo=timezone.utc)
                except (TypeError, ValueError):
                    abort(400, description="Schedule target, interval, or start time is invalid.")
                if interval < 1 or interval > 525600:
                    abort(400, description="Schedule interval must be 1-525600 minutes.")
                if tenant_query(WorkflowSchedule).filter_by(schedule_key=key).first():
                    abort(409, description="A schedule with that key already exists.")
                db.session.add(WorkflowSchedule(
                    schedule_key=key, name=name, ticket_id=ticket.id,
                    interval_minutes=interval, next_run_at=next_run,
                    created_by_id=current_user.id,
                ))
                audit("workflow schedule create", key,
                      f"{ticket.number}; every {interval} minute(s)")
                db.session.commit()
                flash(f"Workflow schedule {name} created.", "success")
                return _admin_referrer_redirect("workflows_admin")
            elif action == "toggle_schedule":
                schedule = tenant_record_or_404(
                    WorkflowSchedule, int(request.form.get("schedule_id", ""))
                )
                schedule.active = not schedule.active
                if schedule.active and schedule.next_run_at < now():
                    schedule.next_run_at = now()
                audit(
                    "workflow schedule toggle", schedule.schedule_key,
                    "active" if schedule.active else "disabled",
                )
                db.session.commit()
                flash("Workflow schedule status updated.", "success")
                return _admin_referrer_redirect("workflows_admin")
            else:
                abort(400)
        definitions = tenant_query(WorkflowDefinition).order_by(
            WorkflowDefinition.workflow_key
        ).all()
        return render_template(
            "workflows.html", definitions=definitions, simulation=simulation,
            package=load_workflow_package(),
            package_hash=package_digest(load_workflow_package()),
            jobs=WorkflowJob.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(WorkflowJob.id.desc()).limit(50).all(),
            executions=WorkflowExecution.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(WorkflowExecution.id.desc()).limit(50).all(),
            tickets=tenant_query(Ticket).order_by(Ticket.updated_at.desc()).limit(100).all(),
        )

    @app.get("/admin/workflows/scheduled")
    @roles("admin")
    @require_action("configure")
    def workflows_scheduled():
        """B-322: scheduled automation gets its own isolated page instead
        of sharing a URL/anchor with the published-rules page (previously
        both admin_home Quick Find cards led to the exact same page)."""
        return render_template(
            "workflows_scheduled.html",
            tickets=tenant_query(Ticket).order_by(Ticket.updated_at.desc()).limit(100).all(),
            schedules=tenant_query(WorkflowSchedule).order_by(
                WorkflowSchedule.name
            ).all(),
        )

    @app.get("/admin/settings")
    @roles("admin")
    @require_action("administer")
    def system_settings():
        """Compatibility redirect for the retired duplicate settings hub."""
        return redirect(url_for("admin_section", section="platform-security"), code=302)

    @app.get("/admin/settings/section/<section>")
    @roles("admin")
    @require_action("administer")
    def system_settings_section(section):
        destinations = {
            "experience": "platform-security",
            "identity": "platform-security",
            "connections": "connections-channels",
            "runtime": "platform-security",
        }
        destination = destinations.get(section)
        if not destination:
            abort(404)
        return redirect(url_for("admin_section", section=destination), code=302)

    @app.route("/admin/settings/<category>", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def system_settings_category(category):
        # "branding" (company logo) and "infrastructure" (read-only runtime
        # values) are not real SETTING_DEFINITIONS groups, but get the same
        # isolated-page treatment as the 9 real ones for consistency.
        if category not in SETTING_DEFINITIONS and category not in ("branding", "infrastructure"):
            abort(404)
        definitions = SETTING_DEFINITIONS.get(category, [])
        if request.method == "POST":
            require_install_settings_authority()
            errors, restart_required, changed = [], False, []
            for definition in definitions:
                key, field_type = definition["key"], definition["type"]
                # Every proxy URL (the system default and each component's
                # custom proxy) is a secret that can also be removed.
                is_proxy_url = key.endswith("_PROXY_URL")
                clear_requested = is_proxy_url and bool(request.form.get(f"{key}_CLEAR"))
                if key not in request.form and field_type != "bool" and not clear_requested:
                    continue
                submitted = request.form.get(key)
                if field_type == "bool":
                    submitted = "true" if submitted else "false"
                elif field_type == "secret" and not submitted:
                    if clear_requested:
                        submitted = ""
                    else:
                        continue
                else:
                    submitted = (submitted or "").strip()
                if field_type == "color" and not re.fullmatch(r"#[0-9a-fA-F]{6}", submitted):
                    errors.append(f"{definition['label']} must be a six-digit hex color.")
                    continue
                if field_type == "json":
                    try:
                        parsed = json.loads(submitted)
                        if not isinstance(parsed, dict):
                            raise ValueError
                        submitted = json.dumps(parsed, separators=(",", ":"))
                    except (json.JSONDecodeError, ValueError):
                        errors.append(f"{definition['label']} must be a JSON object.")
                        continue
                if field_type == "int":
                    try:
                        number = int(submitted)
                        if number < definition["min"] or number > definition["max"]:
                            raise ValueError
                        submitted = str(number)
                    except ValueError:
                        errors.append(
                            f"{definition['label']} must be between {definition['min']} and {definition['max']}.")
                        continue
                if field_type == "choice" and submitted not in definition["choices"]:
                    errors.append(f"{definition['label']} has an invalid value.")
                    continue
                if is_proxy_url and submitted:
                    try:
                        parse_proxy_url(submitted)
                    except ValueError as error:
                        errors.append(str(error))
                        continue
                old_value = core.setting_value(key, definition.get("default", ""))
                if old_value == submitted:
                    continue
                encrypted = field_type == "secret"
                stored = settings_cipher().encrypt(submitted.encode()).decode() if encrypted else submitted
                row = db.session.get(PlatformSetting, key)
                if not row:
                    row = PlatformSetting(key=key)
                    db.session.add(row)
                row.value, row.encrypted, row.updated_by_id = stored, encrypted, current_user.id
                changed.append(key)
                restart_required = restart_required or not definition["live"]
            # A component set to use a custom proxy must have one to use,
            # or its traffic would silently fall back to a direct connection.
            for definition in definitions:
                mode_key = definition["key"]
                if not mode_key.endswith("_PROXY_MODE") or request.form.get(mode_key) != "custom":
                    continue
                url_key = mode_key[:-len("_MODE")] + "_URL"
                if not core.setting_value(url_key, ""):
                    errors.append(f"{definition['label']} is set to a custom proxy, but no custom proxy URL is saved.")
            if category == "branding":
                logo = request.files.get("company_logo")
                if logo and logo.filename:
                    header = logo.stream.read(8)
                    logo.stream.seek(0)
                    if header != b"\x89PNG\r\n\x1a\n":
                        errors.append("Company logo must be a valid PNG file.")
                    elif request.content_length and request.content_length > 5 * 1024 * 1024:
                        errors.append("Company logo must be smaller than 5 MB.")
                    else:
                        logo.save(os.path.join(app.config["UPLOAD_FOLDER"], "company-logo.png"))
                        changed.append("COMPANY_LOGO")
            if category == "sign_in_and_directory":
                # Only meaningful (and only submitted at all) from this
                # category's own page -- checking it unconditionally used to
                # work because every category's fields lived in one shared
                # form; split across isolated pages, saving any *other*
                # category would submit none of these three fields and
                # always fail this check.
                effective_local = request.form.get("LOCAL_AUTH_ENABLED")
                effective_ldap = request.form.get("LDAP_ENABLED")
                effective_keycloak = request.form.get("KEYCLOAK_ENABLED")
                if not any((effective_local, effective_ldap, effective_keycloak)):
                    errors.append("At least one authentication method must remain enabled.")
            if category == "google_chat_app" and request.form.get("GOOGLE_CHAT_APP_ENABLED"):
                project_id = request.form.get("GOOGLE_CHAT_PROJECT_ID", "").strip()
                subscription_id = request.form.get("GOOGLE_CHAT_PUBSUB_SUBSCRIPTION", "").strip()
                bot_user_name = request.form.get("GOOGLE_CHAT_BOT_USER_NAME", "").strip()
                existing_credentials = core.setting_value("GOOGLE_CHAT_SERVICE_ACCOUNT_JSON", "")
                submitted_credentials = request.form.get("GOOGLE_CHAT_SERVICE_ACCOUNT_JSON", "").strip()
                if not re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", project_id):
                    errors.append("Google Cloud project ID is invalid.")
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9._~-]{2,254}", subscription_id):
                    errors.append("Google Chat Pub/Sub subscription ID is invalid.")
                if not re.fullmatch(r"users/[\w-]+", bot_user_name):
                    errors.append('Google Chat bot user resource name must look like "users/123456789".')
                if not (submitted_credentials or existing_credentials):
                    errors.append("Google Chat service-account credentials are required before enabling the bot.")
            if errors:
                db.session.rollback()
                for message in errors:
                    flash(message, "error")
            else:
                audit("update", "Administration settings", ", ".join(changed) or "No value changes")
                db.session.commit()
                flash("Administration settings saved." + (
                    " Restart or roll out all application instances to apply marked settings."
                    if restart_required else ""), "success")
            return _admin_referrer_redirect("system_settings_category", category=category)
        values = {}
        for definition in definitions:
            value = core.setting_value(definition["key"], definition.get("default", ""))
            values[definition["key"]] = "" if definition["type"] == "secret" else value
            definition["configured"] = bool(value) if definition["type"] == "secret" else False
        title, description = (
            ("Company logo", "PNG only, maximum 5 MB. Recommended transparent canvas, up to 600 × 200 px.")
            if category == "branding" else
            ("Runtime environment", "These values describe where this ServiceOps instance is running. They are read-only here because changing a database, volume, replica count, or TLS endpoint requires a controlled Docker Compose or Kubernetes rollout.")
            if category == "infrastructure" else
            SETTING_GROUP_META[category]
        )
        ad_context = {}
        if category == "sign_in_and_directory":
            # Keep the working sign-in-time AD group mapping controls beside
            # the LDAP connection settings.
            teams = tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment"
            ).order_by(SupportGroup.name).all()
            ad_context = dict(
                teams=teams,
                directory_mappings=DirectoryGroupMapping.query.join(SupportGroup).filter(
                    SupportGroup.tenant_id == current_user.tenant_id
                ).order_by(
                    DirectoryGroupMapping.directory_group
                ).all(),
            )
        admin_section_key = (
            "connections-channels"
            if category in {"email_delivery", "netbox_connection", "snipeit_connection", "request_tracker_connection"}
            else "platform-security"
        )
        return render_template(
            "system_settings_category.html", category=category, title=title, description=description,
            definitions=definitions, values=values,
            admin_section_key=admin_section_key,
            infrastructure=_infrastructure_rows() if category == "infrastructure" else None,
            has_company_logo_field=category == "branding",
            **ad_context,
        )

    @app.get("/admin/audit")
    @roles("admin")
    @require_action("report")
    def audit_log():
        # Integrity verification walks and HMAC-checks the entire tenant audit
        # history; running it on every page view does not scale as the log
        # grows, so it only runs when explicitly requested.
        integrity = verify_audit_chain(current_user.tenant_id) if request.args.get("verify") == "1" else None
        query = tenant_query(Audit)
        q = request.args.get("q", "").strip()
        if q:
            query = query.filter(db.or_(
                Audit.action.ilike(f"%{q}%"), Audit.target.ilike(f"%{q}%"),
            ))
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        field_spec = audit_filter_field_spec()
        query = apply_filter_conditions(query, conditions, field_spec)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 100
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.options(db.joinedload(Audit.user)).order_by(Audit.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        value_labels = {("user_id", key): label for key, label in field_spec["user_id"]["options"]}
        client_fields = {
            key: {"label": spec["label"], "type": spec["type"], "options": spec.get("options", [])}
            for key, spec in field_spec.items()
        }
        return render_template(
            "audit.html",
            rows=rows, q=q, page=page, pages=pages, total=total,
            raw_filter=raw_filter, filter_fields=client_fields,
            breadcrumb_parts=filter_conditions_breadcrumb(conditions, field_spec, value_labels),
            integrity=integrity,
            keys=AuditIntegrityKey.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(AuditIntegrityKey.id.desc()).all(),
            retention=AuditRetentionPolicy.query.filter_by(
                tenant_id=current_user.tenant_id
            ).one_or_none(),
            siem_connections=IntegrationConnection.query.filter_by(
                tenant_id=current_user.tenant_id, kind="siem", active=True
            ).count(),
        )

    @app.get("/admin/system-health")
    @roles("admin")
    @require_action("security_administer")
    def system_health():
        db_healthy, db_latency_ms = True, None
        db_check_started = time_module.monotonic()
        try:
            db.session.execute(db.text("SELECT 1"))
            db_latency_ms = round((time_module.monotonic() - db_check_started) * 1000, 2)
        except Exception:  # noqa: BLE001 - this check's whole point is surfacing DB failure
            db_healthy = False

        worker_heartbeat = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT")
        worker_last_seen = None
        worker_healthy = False
        if worker_heartbeat and worker_heartbeat.value:
            try:
                worker_last_seen = datetime.fromisoformat(worker_heartbeat.value)
                worker_healthy = (now() - worker_last_seen) < timedelta(seconds=30)
            except ValueError:
                pass

        active_cutoff = now() - timedelta(minutes=15)
        active_users = tenant_query(User).filter(
            User.last_seen_at.isnot(None), User.last_seen_at >= active_cutoff,
        ).order_by(User.last_seen_at.desc()).all()
        # Surfaces *how* each active user is connected (mobile app vs
        # browser) -- both now correctly count as "active" (see
        # authenticate_api_request()), but an admin watching this page
        # during an incident still needs to tell them apart.
        active_mobile_user_ids = {
            row.acting_user_id for row in APIClient.query.filter(
                APIClient.acting_user_id.in_([user.id for user in active_users]),
                APIClient.client_kind == "mobile",
                APIClient.active.is_(True),
                APIClient.last_used_at.isnot(None),
                APIClient.last_used_at >= active_cutoff,
            )
        } if active_users else set()

        error_query, filters = _filtered_application_log_query(current_user)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total_errors = error_query.count()
        pages = max(1, (total_errors + per_page - 1) // per_page)
        page = min(page, pages)
        error_rows = error_query.order_by(ApplicationLog.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()

        error_last_hour = ApplicationLog.query.filter(
            db.or_(ApplicationLog.tenant_id.is_(None), ApplicationLog.tenant_id == current_user.tenant_id),
            ApplicationLog.level.in_(["ERROR", "CRITICAL"]),
            ApplicationLog.created_at >= now() - timedelta(hours=1),
        ).count()
        last_backup_at, backup_healthy, backup_rpo_hours, _ = _recovery_set_status()

        return render_template(
            "system_health.html",
            app_version=display_version(),
            app_start_time=APP_START_TIME,
            db_healthy=db_healthy, db_latency_ms=db_latency_ms,
            worker_healthy=worker_healthy, worker_last_seen=worker_last_seen,
            active_users=active_users, active_user_count=len(active_users),
            active_mobile_user_ids=active_mobile_user_ids,
            error_rows=error_rows, page=page, pages=pages, total_errors=total_errors,
            error_last_hour=error_last_hour, **filters,
            last_backup_at=last_backup_at, backup_healthy=backup_healthy,
            backup_rpo_hours=backup_rpo_hours,
            backup_offsite=core.setting_value("LAST_BACKUP_OFFSITE_STATUS", "not-recorded"),
            total_users=tenant_query(User).filter_by(active=True).count(),
            open_tickets=tenant_query(Ticket).filter(
                Ticket.state.notin_(["Resolved", "Closed", "Cancelled"])
            ).count(),
            deployment_mode=os.getenv("DEPLOYMENT_MODE", "unknown"),
            gunicorn_workers=os.getenv("GUNICORN_WORKERS", "2"),
        )

    @app.get("/admin/system-health/performance.json")
    @roles("admin")
    @require_action("security_administer")
    def system_health_performance():
        try:
            hours = max(1, min(168, int(request.args.get("hours", "6"))))
        except ValueError:
            hours = 6
        since = now() - timedelta(hours=hours)
        samples = PerformanceSample.query.filter(
            PerformanceSample.sampled_at >= since,
        ).order_by(PerformanceSample.sampled_at).all()
        points = []
        previous = None
        for sample in samples:
            if previous is not None:
                elapsed = (sample.sampled_at - previous.sampled_at).total_seconds()
                request_delta = sample.cumulative_requests - previous.cumulative_requests
                error_delta = sample.cumulative_errors - previous.cumulative_errors
                duration_delta = sample.cumulative_duration_ms - previous.cumulative_duration_ms
                points.append({
                    "at": sample.sampled_at.isoformat(),
                    "requests_per_sec": round(request_delta / elapsed, 3) if elapsed > 0 and request_delta >= 0 else 0,
                    "error_rate": round(error_delta / request_delta, 4) if request_delta > 0 else 0,
                    "avg_latency_ms": round(duration_delta / request_delta, 2) if request_delta > 0 else 0,
                    "worker_healthy": sample.worker_healthy,
                })
            previous = sample
        return jsonify(
            deployment_mode=os.getenv("DEPLOYMENT_MODE", "unknown"),
            gunicorn_workers=os.getenv("GUNICORN_WORKERS", "2"),
            points=points,
        )

    @app.get("/admin/system-health/errors/export")
    @roles("admin")
    @require_action("security_administer")
    def system_health_errors_export():
        error_query, _filters = _filtered_application_log_query(current_user)
        rows = error_query.order_by(ApplicationLog.created_at.desc()).limit(10000).all()
        fmt = request.args.get("format", "csv").lower()
        fields = ["id", "created_at", "level", "logger_name", "message", "path", "method",
                  "request_id", "user_id", "tenant_id", "traceback"]

        def row_dict(row):
            return {
                "id": row.id,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "level": row.level,
                "logger_name": row.logger_name,
                "message": row.message,
                "path": row.path,
                "method": row.method,
                "request_id": row.request_id,
                "user_id": row.user_id,
                "tenant_id": row.tenant_id,
                "traceback": row.traceback,
            }

        audit("export", "Application error log", f"format={fmt} rows={len(rows)}")
        db.session.commit()
        return _export_response([row_dict(r) for r in rows], fields, fmt, "serviceops-error-log")

    @app.post("/admin/system-health/errors/clear")
    @roles("admin")
    @require_action("security_administer")
    def system_health_clear_errors():
        deleted = ApplicationLog.query.filter(
            db.or_(ApplicationLog.tenant_id.is_(None), ApplicationLog.tenant_id == current_user.tenant_id)
        ).delete(synchronize_session=False)
        audit("purge", "Application error log", f"{deleted} entries cleared")
        db.session.commit()
        flash(f"Cleared {deleted} error log entries.", "success")
        return redirect(url_for("system_health"))

    @app.get("/admin/system-health/logs")
    @roles("admin")
    @require_action("security_administer")
    def system_health_log_file():
        # The detailed request-level JSON log (every request, not just
        # errors -- see log_request_completion) lives on disk, not in the
        # database, because its volume would otherwise dwarf every other
        # table combined. Tails it here instead of requiring shell/`docker
        # logs` access. Not tenant-filterable (it's a shared process-wide
        # file across every tenant this instance serves) -- restricted to
        # admins for that reason, same as the rest of this page.
        parsed, error_message, log_path, filters = _read_and_filter_log_file()
        return render_template(
            "system_health_logs.html", entries=parsed,
            error_message=error_message, log_path=log_path, **filters,
        )

    @app.get("/admin/system-health/logs/export")
    @roles("admin")
    @require_action("security_administer")
    def system_health_log_file_export():
        parsed, error_message, _log_path, _filters = _read_and_filter_log_file()
        fmt = request.args.get("format", "ndjson").lower()
        fields = ["timestamp", "level", "logger", "message", "request_id", "method",
                   "path", "status_code", "duration_ms", "user_id", "tenant_id",
                   "remote_addr", "exception"]
        audit("export", "Application log file", f"format={fmt} rows={len(parsed)}")
        db.session.commit()
        if error_message and not parsed:
            flash(error_message, "error")
            return redirect(url_for("system_health_log_file"))
        return _export_response(parsed, fields, fmt, "serviceops-app-log")

    @app.post("/admin/audit/rotate-key")
    @roles("admin")
    @require_action("security_administer")
    def audit_rotate_key():
        if request.form.get("confirmation") != "ROTATE":
            abort(400, description="Type ROTATE to confirm audit-key rotation.")
        try:
            key = rotate_audit_integrity_key(
                current_user.tenant_id, current_user.id
            )
            db.session.commit()
        except RuntimeError as error:
            db.session.rollback()
            abort(409, description=str(error))
        flash(f"Audit signing key rotated to {key.key_id}.", "success")
        return redirect(url_for("audit_log"))

    @app.route("/admin/data-governance", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def data_governance_admin():
        """B-090: data classification reference, per-record-type retention
        policy, legal holds, and a regional-data note. Distinct from
        /admin/audit/retention (audit log has its own long, compliance-
        driven minimum unrelated to customer-data lifecycle)."""
        if request.method == "POST":
            action = request.form.get("action", "")
            if action == "save_retention_policy":
                record_type = request.form.get("record_type", "").strip()
                if record_type not in DATA_CLASSIFICATION_REGISTRY:
                    abort(400, description="Unknown record type.")
                try:
                    retention_days = int(request.form.get("retention_days", "0"))
                except ValueError:
                    abort(400, description="Retention must be an integer number of days.")
                if retention_days < 30 or retention_days > 36500:
                    abort(400, description="Retention must be between 30 and 36500 days.")
                policy = DataRetentionPolicy.query.filter_by(
                    tenant_id=current_user.tenant_id, record_type=record_type,
                ).one_or_none()
                if not policy:
                    policy = DataRetentionPolicy(
                        tenant_id=current_user.tenant_id, record_type=record_type,
                        updated_by_id=current_user.id,
                    )
                    db.session.add(policy)
                policy.retention_days = retention_days
                policy.legal_hold = request.form.get("legal_hold") == "on"
                policy.active = request.form.get("policy_active") == "on"
                policy.updated_by_id = current_user.id
                policy.updated_at = now()
                audit(
                    "data retention policy update", record_type,
                    f"days={retention_days}; legal_hold={policy.legal_hold}; active={policy.active}",
                )
                db.session.commit()
                flash(f"Retention policy for {DATA_CLASSIFICATION_REGISTRY[record_type]['label']} saved.", "success")
            elif action == "run_purge_now":
                count = process_data_retention_purge()
                flash(f"Retention purge complete: {count} record(s) erased.", "success")
            elif action == "add_legal_hold":
                record_type = request.form.get("record_type", "").strip()
                record_id = request.form.get("record_id", type=int)
                reason = request.form.get("reason", "").strip()[:500]
                if record_type not in DATA_CLASSIFICATION_REGISTRY or not record_id or not reason:
                    flash("Record type, record ID, and a reason are all required for a legal hold.", "error")
                else:
                    db.session.add(RecordLegalHold(
                        tenant_id=current_user.tenant_id, record_type=record_type,
                        record_id=record_id, reason=reason, applied_by_id=current_user.id,
                    ))
                    audit("legal hold applied", f"{record_type}:{record_id}", reason)
                    db.session.commit()
                    flash("Legal hold applied.", "success")
            elif action == "release_legal_hold":
                hold = tenant_record_or_404(RecordLegalHold, request.form.get("hold_id", type=int))
                hold.released_at = now()
                hold.released_by_id = current_user.id
                audit("legal hold released", f"{hold.record_type}:{hold.record_id}", hold.reason)
                db.session.commit()
                flash("Legal hold released.", "success")
            elif action == "save_data_region":
                region = request.form.get("data_region", "").strip()[:200]
                setting = PlatformSetting.query.filter_by(
                    tenant_id=current_user.tenant_id, key="DATA_REGION",
                ).one_or_none()
                if not setting:
                    setting = PlatformSetting(tenant_id=current_user.tenant_id, key="DATA_REGION", encrypted=False)
                    db.session.add(setting)
                setting.value = region
                audit("data region update", "DATA_REGION", region)
                db.session.commit()
                flash("Data region note saved.", "success")
            return redirect(url_for("data_governance_admin"))
        policies = {
            policy.record_type: policy
            for policy in DataRetentionPolicy.query.filter_by(tenant_id=current_user.tenant_id).all()
        }
        holds = RecordLegalHold.query.filter_by(
            tenant_id=current_user.tenant_id, released_at=None,
        ).order_by(RecordLegalHold.applied_at.desc()).all()
        region_setting = PlatformSetting.query.filter_by(
            tenant_id=current_user.tenant_id, key="DATA_REGION",
        ).one_or_none()
        return render_template(
            "data_governance_admin.html",
            classification_registry=DATA_CLASSIFICATION_REGISTRY,
            policies=policies, holds=holds,
            data_region=region_setting.value if region_setting else "",
        )

    @app.post("/admin/audit/retention")
    @roles("admin")
    @require_action("security_administer")
    def audit_retention():
        try:
            retention_days = int(request.form.get("retention_days", "0"))
        except ValueError:
            abort(400, description="Retention must be an integer number of days.")
        if retention_days < 2555 or retention_days > 36500:
            abort(400, description=(
                "Audit retention must be between 2555 and 36500 days."
            ))
        policy = AuditRetentionPolicy.query.filter_by(
            tenant_id=current_user.tenant_id
        ).one_or_none()
        if not policy:
            policy = AuditRetentionPolicy(
                tenant_id=current_user.tenant_id,
                updated_by_id=current_user.id,
            )
            db.session.add(policy)
        policy.retention_days = retention_days
        policy.legal_hold = request.form.get("legal_hold") == "on"
        policy.external_export_required = (
            request.form.get("external_export_required") == "on"
        )
        policy.updated_by_id = current_user.id
        policy.updated_at = now()
        audit(
            "audit retention update", "Audit retention policy",
            f"days={retention_days}; legal_hold={policy.legal_hold}; "
            f"external_export_required={policy.external_export_required}",
        )
        db.session.commit()
        flash("Audit retention policy saved.", "success")
        return redirect(url_for("audit_log"))

    @app.get("/admin/audit/export")
    @roles("admin")
    @require_action("export")
    def audit_export():
        rows = tenant_query(Audit).order_by(Audit.id).all()
        integrity = verify_audit_chain(current_user.tenant_id, rows=rows)
        if not integrity["valid"]:
            abort(409, description=(
                "Audit integrity verification failed; export is blocked pending "
                "security investigation."
            ))
        document = {
            "schema": "serviceops.audit-export.v1",
            "exported_at": now().isoformat(),
            "tenant_id": current_user.tenant_id,
            "integrity": integrity,
            "events": [project_document("audit_event", "admin", {
                "id": row.id,
                "event_id": row.event_id,
                "request_id": row.request_id,
                "user_id": row.user_id,
                "action": row.action,
                "target": row.target,
                "details": row.details,
                "source_ip": row.source_ip,
                "user_agent": row.user_agent,
                "security_context": json.loads(row.security_context_json or "{}"),
                "integrity_version": row.integrity_version,
                "integrity_key_id": row.integrity_key_id,
                "previous_hash": row.previous_hash,
                "event_hash": row.event_hash,
                "created_at": row.created_at.isoformat(),
            }) for row in rows],
        }
        body = json.dumps(document, indent=2, sort_keys=True).encode()
        active_key = AuditIntegrityKey.query.filter_by(
            tenant_id=current_user.tenant_id, active=True
        ).order_by(AuditIntegrityKey.id.desc()).first()
        signing_key_id = active_key.key_id if active_key else "environment-v1"
        signature = hmac.new(
            audit_integrity_key(signing_key_id, current_user.tenant_id),
            body, hashlib.sha256
        ).hexdigest()
        response = Response(body, mimetype="application/json")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="serviceops-audit-{now():%Y%m%dT%H%M%SZ}.json"'
        )
        response.headers["X-ServiceOps-Audit-Signature"] = signature
        response.headers["X-ServiceOps-Audit-Key-ID"] = signing_key_id
        return response

    @app.route("/itil/administration", methods=["GET", "POST"])
    @app.route("/service-operations/settings", methods=["GET", "POST"])
    @roles("admin")
    @require_action("configure")
    def itil_admin():
        if request.method == "GET":
            return redirect(url_for("admin_section", section="service-configuration"), code=302)
        if request.method == "POST":
            action = request.form.get("action")
            if action in INSTALL_SETTINGS_ACTIONS:
                require_install_settings_authority()
            if action == "create_support_group":
                name = request.form.get("name", "").strip()
                group_type = request.form.get("group_type", "IT Fulfillment")
                if not name or len(name) > 120:
                    abort(400, description="Team name must contain 1 to 120 characters.")
                if group_type not in ("IT Fulfillment", "Fulfillment", "Executive"):
                    abort(400, description="Select a supported team type.")
                if tenant_query(SupportGroup).filter(
                    func.lower(SupportGroup.name) == name.casefold()
                ).first():
                    abort(409, description="A team with that name already exists.")
                group = SupportGroup(
                    name=name, group_type=group_type, active=True,
                    tenant_id=current_user.tenant_id,
                )
                db.session.add(group)
                db.session.flush()
                audit("create", f"Support group: {name}", group_type)
                flash(f"Team {name} created. Assign its manager and members below.", "success")
            elif action == "update_support_group":
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if group.name in ("Change Control Board", "Executive Office"):
                    abort(400, description="Use the dedicated governance controls for this group.")
                name = request.form.get("name", "").strip()
                group_type = request.form.get("group_type", "IT Fulfillment")
                if not name or len(name) > 120:
                    abort(400, description="Team name must contain 1 to 120 characters.")
                if group_type not in ("IT Fulfillment", "Fulfillment", "Executive"):
                    abort(400, description="Select a supported team type.")
                duplicate = tenant_query(SupportGroup).filter(
                    SupportGroup.id != group.id,
                    func.lower(SupportGroup.name) == name.casefold(),
                ).first()
                if duplicate:
                    abort(409, description="A team with that name already exists.")
                before = f"{group.name}; {group.group_type}; active={group.active}"
                affected_users = [member.user for member in group.members]
                if group.manager:
                    affected_users.append(group.manager)
                group.name = name
                group.group_type = group_type
                group.active = bool(request.form.get("active"))
                for affected in {user.id: user for user in affected_users if user}.values():
                    sync_implied_role_grants(affected)
                audit("update", f"Support group: {name}", f"{before} -> {group_type}; active={group.active}")
                flash(f"Team {name} updated.", "success")
            elif action == "create_ticket_category":
                name = request.form.get("name", "").strip()
                if not name or len(name) > 80:
                    abort(400, description="Category name must contain 1 to 80 characters.")
                if tenant_query(TicketCategory).filter(func.lower(TicketCategory.name) == name.casefold()).first():
                    abort(409, description="A category with that name already exists.")
                category = TicketCategory(name=name, active=True, tenant_id=current_user.tenant_id)
                db.session.add(category)
                db.session.flush()
                audit("create", f"Ticket category: {name}", "")
                flash(f"Category {name} created.", "success")
            elif action == "update_ticket_category":
                category = tenant_record_or_404(TicketCategory, int(request.form["category_id"]))
                name = request.form.get("name", "").strip()
                if not name or len(name) > 80:
                    abort(400, description="Category name must contain 1 to 80 characters.")
                duplicate = tenant_query(TicketCategory).filter(
                    TicketCategory.id != category.id, func.lower(TicketCategory.name) == name.casefold(),
                ).first()
                if duplicate:
                    abort(409, description="A category with that name already exists.")
                before = f"{category.name}; active={category.active}"
                relabelled = 0
                if name != category.name:
                    # A rename relabels the same category, so tickets follow it; otherwise
                    # reporting splits across the old and new label.
                    for column in (Ticket.category, Ticket.closure_category):
                        relabelled += tenant_query(Ticket).filter(column == category.name).update(
                            {column: name}, synchronize_session=False,
                        )
                category.name = name
                category.active = bool(request.form.get("active"))
                audit("update", f"Ticket category: {name}",
                      f"{before} -> active={category.active}; tickets relabelled={relabelled}")
                flash(f"Category {name} updated.", "success")
            elif action == "create_ticket_subcategory":
                category = tenant_record_or_404(TicketCategory, int(request.form["category_id"]))
                name = request.form.get("name", "").strip()
                if not name or len(name) > 80:
                    abort(400, description="Subcategory name must contain 1 to 80 characters.")
                if TicketSubcategory.query.filter(
                    TicketSubcategory.category_id == category.id,
                    func.lower(TicketSubcategory.name) == name.casefold(),
                ).first():
                    abort(409, description="That category already has a subcategory with this name.")
                offering_id = request.form.get("default_service_offering_id") or None
                if offering_id:
                    tenant_record_or_404(ServiceOffering, int(offering_id))
                subcategory = TicketSubcategory(category_id=category.id, name=name, active=True,
                                                default_service_offering_id=offering_id, tenant_id=current_user.tenant_id)
                db.session.add(subcategory)
                db.session.flush()
                audit("create", f"Ticket subcategory: {category.name} / {name}", "")
                flash(f"Subcategory {name} created under {category.name}.", "success")
            elif action == "update_ticket_subcategory":
                subcategory = tenant_record_or_404(TicketSubcategory, int(request.form["subcategory_id"]))
                name = request.form.get("name", "").strip()
                if not name or len(name) > 80:
                    abort(400, description="Subcategory name must contain 1 to 80 characters.")
                duplicate = TicketSubcategory.query.filter(
                    TicketSubcategory.category_id == subcategory.category_id, TicketSubcategory.id != subcategory.id,
                    func.lower(TicketSubcategory.name) == name.casefold(),
                ).first()
                if duplicate:
                    abort(409, description="That category already has a subcategory with this name.")
                offering_id = request.form.get("default_service_offering_id") or None
                if offering_id:
                    tenant_record_or_404(ServiceOffering, int(offering_id))
                before = f"{subcategory.name}; active={subcategory.active}"
                if name != subcategory.name:
                    category_name = subcategory.category.name
                    for category_column, subcategory_column in (
                        (Ticket.category, Ticket.subcategory),
                        (Ticket.closure_category, Ticket.closure_subcategory),
                    ):
                        tenant_query(Ticket).filter(
                            category_column == category_name, subcategory_column == subcategory.name,
                        ).update({subcategory_column: name}, synchronize_session=False)
                subcategory.name = name
                subcategory.active = bool(request.form.get("active"))
                subcategory.default_service_offering_id = offering_id
                audit("update", f"Ticket subcategory: {name}", f"{before} -> active={subcategory.active}")
                flash(f"Subcategory {name} updated.", "success")
            elif action == "add_directory_mapping":
                directory_group = request.form.get("directory_group", "").strip()
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if not directory_group or len(directory_group) > 500:
                    abort(400)
                existing = DirectoryGroupMapping.query.join(SupportGroup).filter(
                    SupportGroup.tenant_id == current_user.tenant_id,
                    func.lower(DirectoryGroupMapping.directory_group)
                    == directory_group.casefold()
                ).first()
                if existing:
                    existing.support_group_id = group.id
                    existing.active = True
                else:
                    db.session.add(DirectoryGroupMapping(
                        directory_group=directory_group, support_group_id=group.id,
                        tenant_id=group.tenant_id,
                    ))
                audit("configure", "AD team mapping", f"{directory_group} -> {group.name}")
                flash("AD group mapping saved. It applies at each user's next login.", "success")
            elif action == "delete_directory_mapping":
                mapping = DirectoryGroupMapping.query.join(SupportGroup).filter(
                    DirectoryGroupMapping.id == int(request.form["mapping_id"]),
                    SupportGroup.tenant_id == current_user.tenant_id,
                ).first_or_404()
                mapping.active = False
                audit("disable", "AD team mapping", mapping.directory_group)
                flash("AD group mapping disabled. Memberships reconcile at next login.", "success")
            elif action == "add_support_group_alias":
                alias = request.form.get("alias", "").strip()
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if not alias or len(alias) > 160:
                    abort(400)
                existing = SupportGroupAlias.query.filter(
                    SupportGroupAlias.tenant_id == current_user.tenant_id,
                    func.lower(SupportGroupAlias.alias) == alias.casefold(),
                ).first()
                if existing:
                    existing.group_id = group.id
                else:
                    db.session.add(SupportGroupAlias(alias=alias, group_id=group.id))
                audit("configure", "Team name alias", f"{alias} -> {group.name}")
                # If a real SupportGroup with this exact name already exists
                # (e.g. it was created by an import before this alias was
                # registered), it's a duplicate of the target team -- merge
                # it in now so existing CIs/tickets/etc. that point at the
                # duplicate resolve correctly instead of erroring with
                # "team requires an active manager" or splitting approvals.
                duplicate_group = SupportGroup.query.filter(
                    SupportGroup.tenant_id == current_user.tenant_id,
                    SupportGroup.id != group.id,
                    func.lower(SupportGroup.name) == alias.casefold(),
                ).first()
                if duplicate_group:
                    moved = merge_support_group_into(duplicate_group, group)
                    audit("merge", "Support group",
                          f"{duplicate_group.name} -> {group.name} ({moved} records)")
                    flash(
                        f'"{alias}" now resolves to {group.name}. It also found an existing '
                        f'"{duplicate_group.name}" team and merged it into {group.name} '
                        f"({moved} records reassigned).", "success",
                    )
                else:
                    flash(f'"{alias}" now resolves to {group.name}.', "success")
            elif action == "delete_support_group_alias":
                group_alias = tenant_record_or_404(SupportGroupAlias, int(request.form["alias_id"]))
                audit("delete", "Team name alias", group_alias.alias)
                db.session.delete(group_alias)
                flash("Team name alias removed.", "success")
            elif action == "merge_duplicate_teams":
                merged = find_and_merge_duplicate_groups(current_user.tenant_id)
                audit("merge", "Support groups", f"{merged} duplicate teams merged")
                flash(
                    f"Merged {merged} duplicate team name(s)." if merged
                    else "No duplicate team names found.", "success",
                )
            elif action == "set_manager":
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if group.group_type not in ("IT Fulfillment", "Fulfillment", "Executive"):
                    abort(400)
                old_manager_id = group.manager_id
                try:
                    manager_id = int(request.form["manager_id"]) if request.form.get("manager_id") else None
                except ValueError:
                    abort(400, description="The manager identifier must be an integer.")
                manager = tenant_query(User).filter_by(id=manager_id, active=True).first() if manager_id else None
                if manager_id and not manager:
                    abort(400, description="Select an active manager in this organization.")
                if manager and not manager.active:
                    abort(400)
                if old_manager_id and old_manager_id != manager_id:
                    old_membership = GroupMember.query.filter_by(
                        group_id=group.id, user_id=old_manager_id, role="manager"
                    ).first()
                    if old_membership:
                        managed = DirectoryManagedMembership.query.filter_by(
                            group_id=group.id, user_id=old_manager_id
                        ).first()
                        if managed:
                            old_membership.role = "member"
                        else:
                            db.session.delete(old_membership)
                group.manager_id = manager_id
                if manager:
                    membership = GroupMember.query.filter_by(
                        group_id=group.id, user_id=manager.id
                    ).first()
                    if membership:
                        membership.role = "manager"
                    else:
                        db.session.add(GroupMember(
                            group_id=group.id, user_id=manager.id, role="manager", tenant_id=group.tenant_id
                        ))
                    sync_implied_role_grants(manager)
                if old_manager_id and old_manager_id != manager_id:
                    old_manager = db.session.get(User, old_manager_id)
                    sync_implied_role_grants(old_manager)
                audit("configure", f"{group.name} manager",
                      manager.username if manager else "Unassigned")
                flash(f"{group.name} manager updated.", "success")
            elif action == "set_ccb_authority":
                user = tenant_record_or_404(User, int(request.form["user_id"]))
                ccb = tenant_query(SupportGroup).filter_by(name="Change Control Board").one()
                membership = GroupMember.query.filter_by(
                    group_id=ccb.id, user_id=user.id
                ).first()
                enabled = request.form.get("enabled") == "true"
                if enabled and not user.active:
                    abort(400)
                if enabled:
                    if membership:
                        membership.role = "CCB approver"
                    else:
                        db.session.add(GroupMember(
                            group_id=ccb.id, user_id=user.id, role="CCB approver", tenant_id=ccb.tenant_id
                        ))
                elif membership:
                    db.session.delete(membership)
                audit("configure", "CCB approval authority",
                      f"{user.username}: {'granted' if enabled else 'revoked'}")
                flash("CCB approval authority updated.", "success")
            elif action == "add_group_member":
                # B-322: governance groups previously showed only a member
                # *count* with no way to see who was in a group or add
                # someone manually -- membership could only be changed
                # indirectly (AD group sync, or the separate manager/CCB
                # controls). This gives admins the same full manual liberty
                # AD-driven membership already has.
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                user = tenant_record_or_404(User, int(request.form["user_id"]))
                if not user.active:
                    abort(400, description="Only active users can be added to a group.")
                existing = GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first()
                if not existing:
                    db.session.add(GroupMember(
                        group_id=group.id, user_id=user.id, role="member", tenant_id=group.tenant_id,
                    ))
                    sync_implied_role_grants(user)
                    audit("configure", f"{group.name} membership", f"added {user.username}")
                    flash(f"{user.name} added to {group.name}.", "success")
                else:
                    flash(f"{user.name} is already a member of {group.name}.", "error")
            elif action == "remove_group_member":
                membership = tenant_record_or_404(GroupMember, int(request.form["member_id"]))
                group = db.session.get(SupportGroup, membership.group_id)
                user = membership.user
                if membership.role in ("manager", "CCB approver"):
                    abort(400, description=(
                        "Remove this person's manager/CCB authority first, from Team managers "
                        "or Approval authority, before removing their membership."
                    ))
                db.session.delete(membership)
                db.session.flush()
                sync_implied_role_grants(user)
                audit("configure", f"{group.name} membership", f"removed {user.username}")
                flash(f"{user.name} removed from {group.name}.", "success")
            elif action == "set_change_approval_policy":
                submitted = request.form.get("ccb_required_environments", "")
                environments = []
                seen = set()
                for value in submitted.split(","):
                    environment = value.strip()
                    normalized = environment.casefold()
                    if environment and normalized not in seen:
                        seen.add(normalized)
                        environments.append(environment)
                if not environments or len(environments) > 20 or any(len(value) > 80 for value in environments):
                    abort(400, description="Enter 1 to 20 environment names, separated by commas.")
                policy_value = ", ".join(environments)
                row = db.session.get(PlatformSetting, "CCB_REQUIRED_ENVIRONMENTS")
                if not row:
                    row = PlatformSetting(key="CCB_REQUIRED_ENVIRONMENTS")
                    db.session.add(row)
                row.value = policy_value
                row.encrypted = False
                row.updated_by_id = current_user.id
                audit("configure", "Change approval policy",
                      f"CCB required for: {policy_value}")
                flash("Change approval policy updated.", "success")
            elif action == "set_ticket_defaults":
                priority = request.form.get("default_ticket_priority", "")
                if priority not in ("P1", "P2", "P3", "P4"):
                    abort(400, description="Select a valid default ticket priority.")
                values = {
                    "DEFAULT_TICKET_PRIORITY": priority,
                    "SYNC_CHILD_INCIDENT_STATES": (
                        "true" if request.form.get("sync_child_incident_states") else "false"
                    ),
                }
                for key, value in values.items():
                    row = db.session.get(PlatformSetting, key)
                    if not row:
                        row = PlatformSetting(key=key)
                        db.session.add(row)
                    row.value = value
                    row.encrypted = False
                    row.updated_by_id = current_user.id
                audit("configure", "Ticket defaults",
                      f"priority={priority}; synchronize child incidents={values['SYNC_CHILD_INCIDENT_STATES']}")
                flash("Ticket defaults updated.", "success")
            elif action == "set_catalog_route":
                item = tenant_record_or_404(CatalogItem, int(request.form["catalog_item_id"]))
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if (
                    not group.active
                    or group.group_type not in ("Fulfillment", "IT Fulfillment")
                ):
                    abort(400, description=(
                        "Catalog items can route only to an active fulfillment team."
                    ))
                route = item.fulfillment_route
                if not route:
                    route = CatalogItemRouting(catalog_item_id=item.id, tenant_id=item.tenant_id)
                    db.session.add(route)
                route.support_group_id = group.id
                route.active = True
                route.updated_by_id = current_user.id
                audit(
                    "configure", f"{item.name} catalog route",
                    f"Default fulfillment team: {group.name}",
                )
                flash(
                    f"{item.name} will create fulfillment tasks for {group.name}.",
                    "success",
                )
            elif action in ("create_catalog_item", "update_catalog_item"):
                name = request.form.get("name", "").strip()
                category = request.form.get("category", "").strip()
                description = request.form.get("description", "").strip()
                try:
                    delivery_days = int(request.form.get("delivery_days", ""))
                    group_id = int(request.form.get("group_id", ""))
                except (TypeError, ValueError):
                    abort(400, description="Delivery target and fulfillment team are required.")
                if not name or len(name) > 160:
                    abort(400, description="Catalog item name must contain 1 to 160 characters.")
                if not category or len(category) > 80:
                    abort(400, description="Category must contain 1 to 80 characters.")
                if not description:
                    abort(400, description="Catalog item description is required.")
                if delivery_days < 1 or delivery_days > 365:
                    abort(400, description="Delivery target must be between 1 and 365 days.")
                group = tenant_record_or_404(SupportGroup, group_id)
                if (
                    not group.active
                    or group.group_type not in ("Fulfillment", "IT Fulfillment")
                ):
                    abort(400, description=(
                        "Catalog items can route only to an active fulfillment team."
                    ))
                item_id = (
                    int(request.form["catalog_item_id"])
                    if action == "update_catalog_item" else None
                )
                duplicate = CatalogItem.query.filter(
                    func.lower(CatalogItem.name) == name.casefold()
                )
                if item_id:
                    duplicate = duplicate.filter(CatalogItem.id != item_id)
                if duplicate.first():
                    abort(409, description="A catalog item with that name already exists.")
                if item_id:
                    item = tenant_record_or_404(CatalogItem, item_id)
                    previous_name = item.name
                else:
                    item = CatalogItem()
                    db.session.add(item)
                    previous_name = None
                item.name = name
                item.category = category
                item.description = description
                item.delivery_days = delivery_days
                item.approval_required = bool(request.form.get("approval_required"))
                item.active = bool(request.form.get("active"))
                db.session.flush()
                route = item.fulfillment_route
                if not route:
                    route = CatalogItemRouting(catalog_item_id=item.id, tenant_id=item.tenant_id)
                    db.session.add(route)
                route.support_group_id = group.id
                route.active = True
                route.updated_by_id = current_user.id
                audit(
                    "create" if action == "create_catalog_item" else "update",
                    f"Catalog item: {item.name}",
                    (
                        f"{category}; {delivery_days} day target; "
                        f"{'approval required' if item.approval_required else 'no approval'}; "
                        f"{'active' if item.active else 'inactive'}; route {group.name}"
                    ),
                )
                flash(
                    (
                        f"{item.name} created and routed to {group.name}."
                        if previous_name is None else
                        f"{previous_name} updated as {item.name}."
                    ),
                    "success",
                )
            elif action == "create_business_schedule":
                name = request.form.get("name", "").strip()
                timezone_name = request.form.get("timezone_name", "").strip()
                weekdays = sorted({
                    int(value) for value in request.form.getlist("weekdays")
                })
                start_text = request.form.get("start_time", "")
                end_text = request.form.get("end_time", "")
                if not name or len(name) > 160:
                    abort(400, description="Schedule name must contain 1 to 160 characters.")
                try:
                    start_time = dt_time.fromisoformat(start_text)
                    end_time = dt_time.fromisoformat(end_text)
                    validate_calendar(timezone_name, weekdays, start_time, end_time)
                except (ValueError, TypeError) as error:
                    abort(400, description=str(error))
                duplicate = tenant_query(BusinessSchedule).filter(
                    func.lower(BusinessSchedule.name) == name.casefold()
                ).first()
                if duplicate:
                    abort(409, description="A business schedule with that name already exists.")
                db.session.add(BusinessSchedule(
                    name=name, timezone_name=timezone_name,
                    weekdays_json=json.dumps(weekdays),
                    start_time_text=start_text, end_time_text=end_text,
                ))
                audit("create", f"Business schedule: {name}", timezone_name)
                flash(f"Business schedule {name} created.", "success")
            elif action == "add_schedule_holiday":
                schedule = tenant_record_or_404(
                    BusinessSchedule, int(request.form["schedule_id"])
                )
                holiday_name = request.form.get("name", "").strip()
                try:
                    holiday_date = date.fromisoformat(request.form.get("holiday_date", ""))
                except ValueError:
                    abort(400, description="Enter a valid holiday date.")
                if not holiday_name:
                    abort(400, description="Holiday name is required.")
                if ScheduleHoliday.query.filter_by(
                    schedule_id=schedule.id, holiday_date=holiday_date
                ).first():
                    abort(409, description="That date is already excluded.")
                db.session.add(ScheduleHoliday(
                    schedule_id=schedule.id, holiday_date=holiday_date, name=holiday_name
                ))
                audit("create", f"Schedule holiday: {schedule.name}",
                      f"{holiday_date.isoformat()} {holiday_name}")
                flash("Schedule holiday added.", "success")
            elif action == "create_sla_definition":
                name = request.form.get("name", "").strip()
                target_type = request.form.get("target_type", "")
                priority = request.form.get("priority") or None
                pause_states = request.form.get("pause_states", "").strip()
                try:
                    duration = int(request.form.get("duration_minutes", ""))
                    schedule_id = int(request.form["schedule_id"]) if request.form.get("schedule_id") else None
                except (TypeError, ValueError):
                    abort(400, description="SLA duration and schedule are invalid.")
                if not name or target_type not in ("ticket", "ritm", "client_ticket") or priority not in (None, "P1", "P2", "P3", "P4", "Low", "Normal", "High", "Urgent"):
                    abort(400, description="SLA name, target and priority are invalid.")
                if duration < 1 or duration > 525600:
                    abort(400, description="SLA duration must be between 1 and 525600 minutes.")
                schedule = tenant_record_or_404(BusinessSchedule, schedule_id) if schedule_id else None
                # Only meaningful (and only ever accepted) for a client_ticket
                # SLA -- an org-specific row overrides the tenant-wide default
                # for the same priority, see attach_slas()'s docstring.
                client_organization = None
                if target_type == "client_ticket" and request.form.get("client_organization_id"):
                    client_organization = tenant_record_or_404(
                        ClientOrganization, request.form.get("client_organization_id", type=int)
                    )
                if tenant_query(SLADefinition).filter(
                    func.lower(SLADefinition.name) == name.casefold()
                ).first():
                    abort(409, description="An SLA definition with that name already exists.")
                agreement_type = request.form.get("agreement_type", "SLA")
                if agreement_type not in SLA_AGREEMENT_TYPES:
                    abort(400, description="Select a valid agreement type.")
                counterparty = request.form.get("counterparty", "").strip()
                db.session.add(SLADefinition(
                    name=name, target_type=target_type, priority=priority,
                    duration_minutes=duration, pause_states=pause_states,
                    schedule_id=schedule.id if schedule else None,
                    agreement_type=agreement_type,
                    counterparty=counterparty if agreement_type != "SLA" else "",
                    client_organization_id=client_organization.id if client_organization else None,
                ))
                audit("create", f"SLA definition: {name}",
                      f"{agreement_type}; {duration} minutes; {schedule.name if schedule else '24x7'}"
                      + (f"; org override for {client_organization.name}" if client_organization else ""))
                flash(f"{agreement_type} definition {name} created.", "success")
            elif action == "create_change_freeze":
                title = request.form.get("title", "").strip()
                starts_at = parse_form_datetime(request.form.get("starts_at", ""))
                ends_at = parse_form_datetime(request.form.get("ends_at", ""))
                if not title or not starts_at or not ends_at:
                    abort(400, description="Freeze title, start and end are required.")
                if ends_at <= starts_at:
                    abort(400, description="Freeze end must be later than its start.")
                db.session.add(ChangeFreezeWindow(
                    title=title, starts_at=starts_at, ends_at=ends_at,
                    reason=request.form.get("reason", "").strip(), created_by_id=current_user.id,
                ))
                audit("create", f"Change freeze: {title}", f"{starts_at.isoformat()} – {ends_at.isoformat()}")
                flash(f"Change freeze \"{title}\" created. Standard/Normal changes cannot be scheduled inside it.", "success")
            elif action == "delete_change_freeze":
                window = tenant_record_or_404(ChangeFreezeWindow, int(request.form["window_id"]))
                audit("delete", f"Change freeze: {window.title}")
                db.session.delete(window)
                flash("Change freeze removed.", "success")
            elif action == "link_service_ci":
                service = tenant_record_or_404(ServiceOffering, int(request.form["service_offering_id"]))
                role = request.form.get("relationship_role", "Supporting")
                if role not in ("Primary", "Supporting"):
                    abort(400)
                try:
                    ci_ids = [int(raw) for raw in request.form.getlist("ci_id") if raw.strip()]
                except ValueError:
                    abort(400)
                if not ci_ids:
                    abort(400, description="Select at least one configuration item.")
                linked_names = []
                for link_ci_id in dict.fromkeys(ci_ids):
                    ci = tenant_record_or_404(ConfigurationItem, link_ci_id)
                    existing_link = ServiceOfferingCI.query.filter_by(
                        service_offering_id=service.id, ci_id=ci.id
                    ).first()
                    if existing_link:
                        existing_link.relationship_role = role
                    else:
                        db.session.add(ServiceOfferingCI(
                            service_offering_id=service.id, ci_id=ci.id, relationship_role=role,
                        ))
                    linked_names.append(ci.name)
                audit("configure", f"{service.name} service mapping",
                      f"{role}: {', '.join(linked_names)}")
                flash(f"{', '.join(linked_names)} linked to {service.name}.", "success")
            elif action == "unlink_service_ci":
                link = db.get_or_404(ServiceOfferingCI, int(request.form["link_id"]))
                if link.tenant_id != current_user.tenant_id:
                    abort(404)
                audit("configure", f"{link.service_offering.name} service mapping",
                      f"removed {link.ci.name}")
                db.session.delete(link)
                flash(f"{link.ci.name} unlinked from {link.service_offering.name}.", "success")
            elif action == "toggle_service_status_page_visibility":
                service = tenant_record_or_404(ServiceOffering, int(request.form["service_offering_id"]))
                service.status_page_visible = not service.status_page_visible
                audit("configure", f"{service.name} status page visibility",
                      "visible" if service.status_page_visible else "hidden")
                flash(
                    f"{service.name} is now {'visible on' if service.status_page_visible else 'hidden from'} "
                    "the public status page.", "success",
                )
            else:
                abort(400)
            db.session.commit()
            return _admin_referrer_redirect("itil_admin")

    @app.get("/service-operations/settings/directory-mapping")
    @app.get("/service-operations/settings/ldap-sync")
    @roles("admin")
    @require_action("configure")
    def itil_admin_section_ad_redirect():
        # B-322: AD/LDAP group mapping and directory sync moved onto the
        # Sign-in and directory settings page, alongside the rest of the
        # AD/LDAP connection config, instead of living in a separate area.
        return redirect(url_for("system_settings_category", category="sign_in_and_directory"))

    @app.route("/service-operations/settings/<section>")
    @roles("admin")
    @require_action("configure")
    def itil_admin_section(section):
        if section not in ITIL_ADMIN_SECTIONS:
            abort(404)
        title, description = ITIL_ADMIN_SECTIONS[section]
        groups = tenant_query(SupportGroup).order_by(SupportGroup.name).all()
        teams = [
            group for group in groups
            if group.group_type in ("IT Fulfillment", "Fulfillment", "Executive")
            and group.name not in ("Executive Office",)
        ]
        fulfillment_groups = [
            group for group in groups
            if group.active and group.group_type in ("Fulfillment", "IT Fulfillment")
        ]
        manager_candidates = tenant_query(User).filter(
            User.active.is_(True)
        ).order_by(User.name).all()
        ccb_candidates = tenant_query(User).join(
            UserRoleGrant, UserRoleGrant.user_id == User.id
        ).filter(
            User.active.is_(True),
            UserRoleGrant.role.in_(["manager", "admin", "superadmin"]),
        ).distinct().order_by(User.name).all()
        ccb = tenant_query(SupportGroup).filter_by(name="Change Control Board").first()
        if not ccb:
            ccb = SupportGroup(
                name="Change Control Board", group_type="CCB Approval",
                tenant_id=current_user.tenant_id,
            )
            db.session.add(ccb)
            db.session.flush()
        ccb_approver_ids = {
            member.user_id for member in ccb.members if member.role == "CCB approver"
        }
        executive_office = tenant_query(SupportGroup).filter_by(name="Executive Office").first()
        if not executive_office:
            executive_office = SupportGroup(
                name="Executive Office", group_type="Executive",
                tenant_id=current_user.tenant_id,
            )
            db.session.add(executive_office)
            db.session.flush()
        db.session.commit()
        directory_managed_member_keys = set()
        if section == "governance-groups":
            directory_managed_member_keys = {
                (row.group_id, row.user_id) for row in DirectoryManagedMembership.query.filter(
                    DirectoryManagedMembership.group_id.in_([group.id for group in groups])
                )
            }
        return render_template(
            "itil_admin_section.html", section=section, title=title, description=description,
            groups=groups, teams=teams,
            manager_candidates=manager_candidates, ccb_candidates=ccb_candidates,
            ccb=ccb, ccb_approver_ids=ccb_approver_ids,
            executive_office=executive_office,
            directory_managed_member_keys=directory_managed_member_keys,
            support_group_aliases=tenant_query(SupportGroupAlias).order_by(
                SupportGroupAlias.alias
            ).all(),
            services=tenant_query(ServiceOffering).all(),
            ticket_categories=tenant_query(TicketCategory).order_by(TicketCategory.name).all(),
            category_option_limit=CATEGORY_LEVEL_OPTION_LIMIT,
            sla_definitions=tenant_query(SLADefinition).all(),
            client_organizations=tenant_query(ClientOrganization).order_by(ClientOrganization.name).all(),
            business_schedules=tenant_query(BusinessSchedule).order_by(
                BusinessSchedule.name
            ).all(),
            catalog_items=tenant_query(CatalogItem).order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
            fulfillment_groups=fulfillment_groups,
            change_freeze_windows=tenant_query(ChangeFreezeWindow).order_by(
                ChangeFreezeWindow.starts_at.desc()
            ).all(),
            ccb_required_environments=core.setting_value(
                "CCB_REQUIRED_ENVIRONMENTS", "Production"
            ),
            default_ticket_priority=core.setting_value(
                "DEFAULT_TICKET_PRIORITY", "P3"
            ),
            sync_child_incident_states=setting_bool(
                "SYNC_CHILD_INCIDENT_STATES"
            ),
        )
