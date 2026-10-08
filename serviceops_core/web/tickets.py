"""Incident, change, problem and related work routes.

Moved from app.create_app(); endpoint names are unchanged."""
import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta

from flask import abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import func, or_
from sqlalchemy.orm import selectinload
from werkzeug.exceptions import HTTPException

import app as core
from app import (
    _conflict_descriptions,
    active_change_freeze,
    align_tz,
    allowed_enterprise_states,
    allowed_ticket_states,
    apply_filter_conditions,
    approval_chain_for,
    attach_slas,
    attachment_file_response,
    audit,
    current_storage,
    calculate_change_risk_score,
    cancel_approval_chain,
    change_approval_stages,
    change_task_gate_block,
    create_approval_chain,
    create_notification,
    create_ticket_with_unique_number,
    create_with_retry_on_number_collision,
    csv_response,
    DOMAIN_CONFIG,
    DOMAIN_ICONS,
    effective_role_has_action,
    filter_conditions_breadcrumb,
    find_record_by_number,
    follow_ticket,
    is_following_ticket,
    is_safe_internal_path,
    log_field_changes,
    log_history,
    next_enterprise_number,
    next_operational_task_number,
    normalize_ticket_category,
    normalize_ticket_subcategory,
    parse_form_datetime,
    parse_list_filter_param,
    post_ticket_comment,
    record_number,
    record_reference,
    record_tenant_id,
    record_title,
    record_type_for,
    record_url,
    related_records,
    RELATION_LABELS,
    require_resolution_notes,
    require_ticket_not_locked,
    require_ticket_team_access,
    role_at_least,
    roles,
    run_change_conflict_detection,
    sequence_number,
    setting_bool,
    setting_int,
    submitted_subcategory,
    supersede_change_approval,
    sync_service_outages,
    tenant_query,
    tenant_record_or_404,
    tenant_ticket_categories,
    tenant_ticket_subcategories,
    ticket_locked_for_edits,
    ticket_mentionable_users,
    ticket_owning_group,
    ticket_team_agents,
    transition_enterprise,
    transition_operational_task,
    transition_ticket,
    UNCATEGORISED,
    unfollow_ticket,
    user_can_manage_enterprise_record,
    user_can_manage_ritm,
    user_can_manage_ticket,
    user_can_view_catalog_request,
    user_can_view_enterprise_record,
    user_can_delete_attachment,
    user_can_view_ticket,
    user_in_group,
    user_support_group_ids,
    visible_catalog_request_query,
    visible_client_ticket_query,
    visible_enterprise_record_query,
    visible_ticket_query,
    workspace_widget_enabled,
    WORKSPACE_WIDGET_REGISTRY,
)
from serviceops_core.config_schema import SETTING_DEFINITIONS
from serviceops_core.priority import calculate_priority
from serviceops_core.projections import project_document
from serviceops_core.task_lifecycle import build_state_track, OPERATIONAL_TASK_TRANSITIONS
from serviceops_core.web.common import (
    save_ticket_attachment,
    ticket_filter_field_spec,
    ticket_list_query,
    usertime_filter,
    visible_tickets,
)
from serviceops_models import (
    Approval,
    ApprovalChain,
    ApprovalGate,
    ApprovalVote,
    CatalogRequest,
    CatalogTask,
    CHANGE_PIR_OUTCOMES,
    ChangeFreezeWindow,
    ChangeGovernance,
    ChangeOwnership,
    ChangePostImplementationReview,
    ChangeRevision,
    ChecklistItem,
    ConfigurationItem,
    db,
    EnterpriseRecord,
    FileAttachment,
    IMPROVEMENT_STATES,
    ImprovementItem,
    Knowledge,
    MajorIncidentProfile,
    MajorIncidentUpdate,
    now,
    OperationalTask,
    ProblemProfile,
    RecordLink,
    RequestedItem,
    RTImportJob,
    ServiceOffering,
    SupportGroup,
    TaskCI,
    TaskHistory,
    TaskNote,
    TaskSLA,
    Ticket,
    TicketAssignmentGroup,
    User,
    UserWorkspaceLayout,
)
from serviceops_core.localization import tr, tr_value


def register(app):
    @app.get("/work/open")
    @login_required
    def open_work():
        priority = request.args.get("priority", "").strip()
        ticket_query = visible_ticket_query(current_user)
        open_ticket_query = ticket_query.filter(
            Ticket.state.notin_(["Resolved", "Closed", "Cancelled"])
        )
        if priority:
            open_ticket_query = open_ticket_query.filter_by(priority=priority)
        # Capped to keep this route bounded for tenants with a large open-work
        # backlog; use /tickets/<kind> with pagination and filters to see the
        # rest.
        open_work_limit = 200
        open_tickets = open_ticket_query.order_by(
            Ticket.priority, Ticket.updated_at.desc()
        ).limit(open_work_limit + 1).all()
        open_tickets_truncated = len(open_tickets) > open_work_limit
        open_tickets = open_tickets[:open_work_limit]
        open_requests = visible_catalog_request_query(current_user).filter(
            CatalogRequest.state.notin_(["Closed Complete", "Closed Incomplete", "Cancelled"])
        ).order_by(CatalogRequest.opened_at.desc()).limit(open_work_limit + 1).all()
        open_requests_truncated = len(open_requests) > open_work_limit
        open_requests = open_requests[:open_work_limit]
        if priority:
            open_requests = []
            open_requests_truncated = False
        return render_template(
            "open_work.html", open_tickets=open_tickets, open_requests=open_requests, priority=priority,
            open_tickets_truncated=open_tickets_truncated, open_requests_truncated=open_requests_truncated,
        )

    @app.get("/work/open/export.csv")
    @login_required
    def open_work_export():
        priority = request.args.get("priority", "").strip()
        open_ticket_query = visible_ticket_query(current_user).filter(
            Ticket.state.notin_(["Resolved", "Closed", "Cancelled"])
        )
        if priority:
            open_ticket_query = open_ticket_query.filter_by(priority=priority)
        export_limit = 5000
        tickets_rows = open_ticket_query.order_by(
            Ticket.priority, Ticket.updated_at.desc()
        ).limit(export_limit).all()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Type", "Number", "Title", "State", "Priority", "Assignee", "Updated"])
        for ticket in tickets_rows:
            writer.writerow([
                ticket.kind.capitalize(), ticket.number, ticket.title, ticket.state, ticket.priority,
                ticket.assignee.name if ticket.assignee else "Unassigned",
                usertime_filter(ticket.updated_at, "%Y-%m-%d %H:%M"),
            ])
        if not priority:
            for req in visible_catalog_request_query(current_user).filter(
                CatalogRequest.state.notin_(["Closed Complete", "Closed Incomplete", "Cancelled"])
            ).order_by(CatalogRequest.opened_at.desc()).limit(export_limit).all():
                writer.writerow([
                    "Request", req.number, f"Request for {req.requested_for.name}", req.state, "",
                    req.requested_by.name if req.requested_by else "", usertime_filter(req.opened_at, "%Y-%m-%d %H:%M"),
                ])
        return csv_response(buffer.getvalue(), "open-work.csv")

    @app.route("/workspace", methods=["GET", "POST"])
    @login_required
    def my_workspace():
        """B-121: a user's personal, configurable landing page -- widgets
        picked from WORKSPACE_WIDGET_REGISTRY's closed catalog, arranged in
        a simple ordered list with a 1- or 2-column span each. Distinct
        from /dashboard (the fixed, admin-configured default), which is
        untouched by this feature."""
        layout_row = UserWorkspaceLayout.query.filter_by(user_id=current_user.id).one_or_none()
        if request.method == "POST":
            action = request.form.get("action", "save")
            if action == "save":
                new_layout = []
                for widget_key in request.form.getlist("widget_key"):
                    if widget_key not in WORKSPACE_WIDGET_REGISTRY:
                        continue
                    span = 2 if request.form.get(f"span_{widget_key}") == "2" else 1
                    new_layout.append({"widget_key": widget_key, "span": span})
                if not layout_row:
                    layout_row = UserWorkspaceLayout(
                        tenant_id=current_user.tenant_id, user_id=current_user.id, layout_json=new_layout,
                    )
                    db.session.add(layout_row)
                else:
                    layout_row.layout_json = new_layout
                db.session.commit()
                flash(tr("Workspace layout saved."), "success")
            elif action == "reset":
                if layout_row:
                    db.session.delete(layout_row)
                    db.session.commit()
                flash(tr("Workspace reset to the default widget set."), "success")
            return redirect(url_for("my_workspace"))

        available = {
            key: entry for key, entry in WORKSPACE_WIDGET_REGISTRY.items()
            if workspace_widget_enabled(key)
        }
        if layout_row and layout_row.layout_json:
            selected = [
                item for item in layout_row.layout_json
                if isinstance(item, dict) and item.get("widget_key") in available
            ]
        else:
            # No saved layout yet -- a reasonable default so /workspace
            # isn't a blank page on first visit, not auto-seeded data.
            selected = [
                {"widget_key": key, "span": entry["default_span"]}
                for key, entry in available.items()
                if key in ("ticket_stats", "my_open_tickets", "recent_tickets")
            ]
        widgets = []
        for item in selected:
            key = item["widget_key"]
            context = available[key]["data"](current_user)
            widgets.append({
                "key": key, "label": available[key]["label"], "span": item.get("span", 1),
                "context": context,
            })
        return render_template(
            "my_workspace.html", widgets=widgets, available=available,
            selected_keys={item["widget_key"] for item in selected},
            selected_spans={item["widget_key"]: item.get("span", 1) for item in selected},
        )

    @app.get("/work/tasks")
    @login_required
    def my_work_tasks():
        terminal = ["Closed Complete", "Closed Incomplete", "Closed Skipped"]
        group_ids = user_support_group_ids(current_user)

        def open_tasks(model):
            return model.query.filter(model.state.notin_(terminal))

        def row_for(task, kind_label):
            return {
                "number": task.number,
                "kind": kind_label,
                "title": task.title,
                "state": task.state,
                "group": task.assignment_group.name if task.assignment_group else "Unassigned",
                "assignee": task.assignee.name if task.assignee else "Unassigned",
                "due_at": getattr(task, "due_at", None) or getattr(task, "planned_end", None),
                "url": record_url(task),
            }

        assigned_to_me, team_tasks = [], []
        for model, kind_label in ((OperationalTask, None), (CatalogTask, "SCTASK")):
            mine = open_tasks(model).filter(model.assignee_id == current_user.id).all()
            mine_ids = {task.id for task in mine}
            assigned_to_me.extend(
                row_for(task, kind_label or task.task_kind.upper()) for task in mine
            )
            if role_at_least(current_user.effective_role, "admin"):
                team_query = open_tasks(model).join(
                    SupportGroup, model.assignment_group_id == SupportGroup.id
                ).filter(SupportGroup.tenant_id == current_user.tenant_id)
            elif group_ids:
                team_query = open_tasks(model).filter(model.assignment_group_id.in_(group_ids))
            else:
                team_query = None
            if team_query is not None:
                team_tasks.extend(
                    row_for(task, kind_label or task.task_kind.upper())
                    for task in team_query.all() if task.id not in mine_ids
                )

        def sort_key(row):
            return (row["due_at"] is None, row["due_at"] or now())

        assigned_to_me.sort(key=sort_key)
        team_tasks.sort(key=sort_key)
        return render_template(
            "task_queue.html", assigned_to_me=assigned_to_me, team_tasks=team_tasks,
        )

    @app.get("/tickets/<kind>")
    @login_required
    def tickets(kind):
        if kind not in ("incident", "change"):
            abort(404)
        q = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        query = ticket_list_query(kind, q=q, conditions=conditions)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.options(
            db.joinedload(Ticket.requester), db.joinedload(Ticket.assignee),
        ).order_by(Ticket.updated_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        # Batch-fetch owning groups for this page instead of one query per row
        # (ticket_owning_group() issues its own query per call).
        row_ids = [row.id for row in rows]
        assignment_groups = {
            a.ticket_id: a.group
            for a in TicketAssignmentGroup.query.filter(
                TicketAssignmentGroup.ticket_id.in_(row_ids)
            ).options(db.joinedload(TicketAssignmentGroup.group)).all()
        } if row_ids else {}
        ownership_groups = {
            o.ticket_id: o.group
            for o in ChangeOwnership.query.filter(
                ChangeOwnership.ticket_id.in_(row_ids)
            ).options(db.joinedload(ChangeOwnership.group)).all()
        } if row_ids else {}
        owning_groups = {
            row.id: ownership_groups.get(row.id) if row.kind == "change" else assignment_groups.get(row.id)
            for row in rows
        }
        filter_groups = SupportGroup.query.filter_by(
            tenant_id=core.tenant_context_id()
        ).order_by(SupportGroup.name).all()
        field_spec = ticket_filter_field_spec()
        field_spec["group"] = {"label": "Assignment group", "type": "choice",
                                "options": [(str(g.id), g.name) for g in filter_groups]}
        value_labels = {("group", str(g.id)): g.name for g in filter_groups}
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec, value_labels)
        client_fields = {
            key: {"label": tr_value(spec["label"]), "type": spec["type"],
                  "options": [(value, tr_value(label)) for value, label in spec.get("options", [])]}
            for key, spec in field_spec.items()
        }
        return render_template(
            "tickets.html", tickets=rows, kind=kind, q=q,
            raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts,
            filter_fields=client_fields,
            page=page, pages=pages, total=total,
            owning_groups=owning_groups,
        )

    @app.get("/tickets/<kind>/export.csv")
    @login_required
    def tickets_export(kind):
        if kind not in ("incident", "change"):
            abort(404)
        q = request.args.get("q", "").strip()
        conditions = parse_list_filter_param(request.args.get("filter", ""))
        query = ticket_list_query(kind, q=q, conditions=conditions)
        export_limit = 5000
        rows = query.options(
            db.joinedload(Ticket.requester), db.joinedload(Ticket.assignee),
        ).order_by(Ticket.updated_at.desc()).limit(export_limit).all()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Number", "Title", "State", "Priority", "Requester", "Assignee", "Updated"])
        for ticket in rows:
            writer.writerow([
                ticket.number, ticket.title, ticket.state, ticket.priority,
                ticket.requester.name if ticket.requester else "",
                ticket.assignee.name if ticket.assignee else "Unassigned",
                usertime_filter(ticket.updated_at, "%Y-%m-%d %H:%M"),
            ])
        return csv_response(buffer.getvalue(), f"{kind}-tickets.csv")

    @app.route("/tickets/new/<kind>", methods=["GET", "POST"])
    @login_required
    def ticket_new(kind):
        if kind not in ("incident", "change"):
            abort(404)
        team_ids = user_support_group_ids(current_user)
        eligible_it_team_ids = {
            group.id
            for group in SupportGroup.query.filter(
                SupportGroup.id.in_(team_ids),
                SupportGroup.group_type == "IT Fulfillment",
                SupportGroup.active.is_(True),
            ).all()
        }
        if kind == "change" and current_user.effective_role == "requester" and not eligible_it_team_ids:
            abort(403)

        # A draft prepared by the AI assistant arrives as query parameters. It only fills the form in; the person
        # reviews every field, picks the owning team and submits through the normal, fully validated path.
        ai_prefill = None
        if request.method == "GET" and request.args.get("ai") == "1":
            limits = {"title": 180, "description": 1500, "impact": 10, "urgency": 10, "category": 80, "subcategory": 80}
            ai_prefill = {name: request.args.get(name, "")[:size] for name, size in limits.items() if request.args.get(name)}

        def render_form(error=None):
            teams_query = core.team_groups()
            if kind == "change" and not role_at_least(current_user.effective_role, "admin"):
                teams_query = teams_query.filter(SupportGroup.id.in_(team_ids or {-1}))
            return render_template(
                "ticket_form.html", kind=kind, teams=teams_query.all(),
                state_track=build_state_track(kind, "New"),
                default_priority=core.setting_value("DEFAULT_TICKET_PRIORITY", "P3"),
                service_offerings=tenant_query(ServiceOffering).filter_by(
                    status="Operational"
                ).order_by(ServiceOffering.name).all(),
                ticket_categories=tenant_ticket_categories(current_user.tenant_id),
                ticket_subcategories=tenant_ticket_subcategories(current_user.tenant_id),
                # Active/upcoming freeze windows, surfaced on the form itself
                # so a Standard/Normal change author sees the block coming
                # instead of only discovering it after a failed submit.
                change_freeze_windows=(
                    tenant_query(ChangeFreezeWindow).filter(
                        ChangeFreezeWindow.ends_at >= now()
                    ).order_by(ChangeFreezeWindow.starts_at).all()
                    if kind == "change" else []
                ),
                form=request.form if error else ai_prefill, form_error=error, ai_prefill=bool(ai_prefill and not error),
            ), (400 if error else 200)

        if request.method == "POST":
            contact_type = request.form.get("contact_type", "Self-service")
            notify = request.form.get("notify", "Email")
            if contact_type not in {
                "Self-service", "Phone", "Email", "Chat", "Monitoring"
            }:
                return render_form("Select a valid contact type.")
            if notify not in {"Email", "In-app only", "Do not notify"}:
                return render_form("Select a valid notification preference.")
            offering = None
            if request.form.get("service_offering_id"):
                offering = tenant_query(ServiceOffering).filter_by(
                    id=int(request.form["service_offering_id"])
                ).first()
                if not offering:
                    return render_form("Select a valid service offering.")
                if offering.status != "Operational":
                    return render_form("Select an operational service offering.")
            try:
                group_id = int(request.form.get("group_id", ""))
            except (TypeError, ValueError):
                return render_form("Select a valid owning IT team.")
            owning_group = tenant_query(SupportGroup).filter_by(id=group_id).first()
            if not core.is_team_group(owning_group):
                return render_form("Select an active team.")
            if (
                kind == "change"
                and not role_at_least(current_user.effective_role, "admin")
                and owning_group.id not in team_ids
            ):
                return render_form("You can submit changes only for teams you belong to.")
            if kind == "change" and (
                not owning_group.manager
                or not owning_group.manager.active
            ):
                return render_form("The selected team must have an active manager before a change can be submitted.")
            if kind == "change":
                if not request.form.get("planned_start") or not request.form.get("planned_end"):
                    return render_form("Planned start and planned end are required for a change.")
                planned_start = parse_form_datetime(request.form["planned_start"])
                planned_end = parse_form_datetime(request.form["planned_end"])
                if not planned_start or not planned_end:
                    return render_form("Planned start and planned end must be valid dates.")
                if planned_end <= planned_start:
                    return render_form("Planned end must be later than planned start.")
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            if not title:
                return render_form("Short description is required.")
            if not description:
                return render_form("Description is required.")
            if kind == "change":
                for label, field in (
                    ("Implementation plan", "implementation_plan"),
                    ("Test plan", "test_plan"),
                    ("Backout plan", "backout_plan"),
                ):
                    if not request.form.get(field, "").strip():
                        return render_form(f"{label} is required.")
            ci_id = None
            selected_ci = None
            additional_ci_ids = set()
            if kind == "change":
                try:
                    change_ci_ids = [int(raw) for raw in request.form.getlist("ci_id") if raw.strip()]
                except (TypeError, ValueError):
                    return render_form("One of the selected configuration items is invalid.")
                seen_ci_ids = list(dict.fromkeys(change_ci_ids))
                seen_cis = {}
                for candidate_id in seen_ci_ids:
                    candidate = tenant_query(ConfigurationItem).filter_by(id=candidate_id).first()
                    if not candidate:
                        return render_form("One of the selected configuration items does not exist.")
                    seen_cis[candidate_id] = candidate
                if seen_ci_ids:
                    ci_id = seen_ci_ids[0]
                    selected_ci = seen_cis[ci_id]
                    additional_ci_ids = set(seen_ci_ids[1:])
            elif request.form.get("ci_id"):
                try:
                    ci_id = int(request.form["ci_id"])
                except (TypeError, ValueError):
                    return render_form("The selected configuration item is invalid.")
                selected_ci = tenant_query(ConfigurationItem).filter_by(id=ci_id).first()
                if not selected_ci:
                    return render_form("The selected configuration item does not exist.")
            if kind == "change" and seen_ci_ids:
                conflicts = _conflict_descriptions(
                    current_user.tenant_id, set(seen_ci_ids), planned_start, planned_end,
                )
                if conflicts:
                    return render_form(
                        f"This change cannot be created: it conflicts with {'; '.join(conflicts)}. "
                        "Reschedule the planned window or select a different configuration item."
                    )
            change_type_input = request.form.get("change_type", "Normal")
            if kind == "change" and change_type_input != "Emergency":
                freeze = active_change_freeze(current_user.tenant_id, planned_start, planned_end)
                if freeze:
                    return render_form(
                        f"This change cannot be created: it falls inside the change freeze "
                        f"\"{freeze.title}\" ({freeze.starts_at.strftime('%b %d')}–{freeze.ends_at.strftime('%b %d, %Y')}"
                        f"{': ' + freeze.reason if freeze.reason else ''}). Only Emergency changes are permitted during a freeze."
                    )
            if kind == "change" and seen_cis:
                calculated_risk_score = max(
                    calculate_change_risk_score(
                        request.form.get("change_type", "Normal"), candidate,
                    )
                    for candidate in seen_cis.values()
                )
            else:
                calculated_risk_score = calculate_change_risk_score(
                    request.form.get("change_type", "Normal"), selected_ci,
                )
            risk_score_input = request.form.get("risk_score", "").strip()
            if risk_score_input:
                try:
                    risk_score = max(0, min(100, int(risk_score_input)))
                except (TypeError, ValueError):
                    return render_form("Risk score must be a number between 0 and 100.")
                risk_score_overridden = risk_score != calculated_risk_score
            else:
                risk_score = calculated_risk_score
                risk_score_overridden = False
            impact = request.form.get("impact", "Medium")
            urgency = request.form.get("urgency", "Medium")
            priority = calculate_priority(impact, urgency)
            # Changes are classified by change model plus the affected CI/service,
            # not by the incident/request symptom tree.
            if kind == "change":
                category, subcategory = "", ""
            else:
                category = normalize_ticket_category(current_user.tenant_id, request.form.get("category", UNCATEGORISED))
                subcategory = normalize_ticket_subcategory(current_user.tenant_id, category, submitted_subcategory(request.form))
            ticket = create_ticket_with_unique_number(
                kind,
                title=title, description=description,
                category=category, priority=priority,
                impact=impact, urgency=urgency,
                subcategory=subcategory,
                contact_type=contact_type, notify=notify,
                service_offering_id=offering.id if offering else None,
                requester_id=current_user.id)
            if kind == "incident" and ci_id:
                db.session.add(TaskCI(
                    target_type="ticket", target_id=ticket.id, ci_id=ci_id,
                    relationship_role="Primary CI",
                ))
            if kind == "incident":
                sync_service_outages(ticket)
            attach_slas("ticket", ticket.id, ticket.priority)
            if kind == "change":
                governance = ChangeGovernance(ticket_id=ticket.id, change_type=request.form.get("change_type", "Normal"),
                                              risk_score=risk_score,
                                              impact=request.form.get("impact", "Medium"),
                                              implementation_plan=request.form.get("implementation_plan", "").strip(),
                                              test_plan=request.form.get("test_plan", "").strip(),
                                              backout_plan=request.form.get("backout_plan", "").strip(),
                                              planned_start=planned_start, planned_end=planned_end,
                                              ci_id=ci_id,
                                              risk_score_overridden=risk_score_overridden,
                                              risk_score_override_reason=(
                                                  request.form.get("risk_score_override_reason", "").strip()
                                                  if risk_score_overridden else ""
                                              ))
                db.session.add(governance)
                db.session.flush()
                db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=owning_group.id))
                db.session.add(ChangeRevision(ticket_id=ticket.id, revision=1))
                db.session.flush()
                for additional_ci_id in additional_ci_ids:
                    db.session.add(TaskCI(
                        target_type="ticket", target_id=ticket.id,
                        ci_id=additional_ci_id, relationship_role="Affected CI",
                    ))
                if additional_ci_ids:
                    db.session.flush()
                    log_history(
                        "ticket", ticket.id, "Configuration item linked",
                        details=f"Affected CI: {len(additional_ci_ids)} additional configuration item(s) linked at creation.",
                    )
                run_change_conflict_detection(ticket, governance)
                create_approval_chain(
                    f"{ticket.number} change authorization v1",
                    "ticket", ticket.id, change_approval_stages(ticket),
                )
                implementation_notes = "\n\n".join(filter(None, [
                    f"Implementation plan:\n{governance.implementation_plan}",
                    f"Test plan:\n{governance.test_plan}",
                    f"Backout plan:\n{governance.backout_plan}",
                ]))
                def build_initial_task():
                    initial_task = OperationalTask(
                        number=next_operational_task_number("change"),
                        task_kind="change", parent_type="ticket", parent_id=ticket.id,
                        title="Implementation", task_type="Implementation",
                        sequence=1, assignment_group_id=owning_group.id,
                        planned_start=governance.planned_start, planned_end=governance.planned_end,
                        required=True, work_notes=implementation_notes, state="Pending",
                    )
                    db.session.add(initial_task)
                    return initial_task
                initial_task = create_with_retry_on_number_collision(build_initial_task)
                log_history(
                    "ticket", ticket.id, "Change task created",
                    details=f"{initial_task.number} Implementation: created from the change's plan → {owning_group.name}",
                )
            else:
                db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=owning_group.id))
            log_history(
                "ticket", ticket.id, "Record created", details=(
                    f"{ticket.number} created and assigned to {owning_group.name}."
                ),
            )
            audit("create", ticket.number, ticket.title)
            db.session.commit()
            conflicts = kind == "change" and governance.conflict_status.startswith("Conflict")
            flash(
                tr("{number} created.", number=ticket.number)
                + (f" {tr_value(governance.conflict_status)}." if conflicts else ""),
                "error" if conflicts else "success",
            )
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        return render_form()

    @app.get("/ticket/<int:ticket_id>/mentionable-users")
    @login_required
    def ticket_mentionable_users_api(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if not user_can_view_ticket(current_user, ticket):
            abort(403)
        return jsonify({"users": [
            {"username": user.username, "name": user.name} for user in ticket_mentionable_users(ticket)
        ]})

    @app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
    @login_required
    def ticket_detail(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if not user_can_view_ticket(current_user, ticket):
            abort(403, description=tr("You are not involved in this ticket or its assigned work."))
        if request.method == "POST":
            action = request.form.get("action")
            if action not in ("comment", "reopen", "close", "follow", "unfollow") and ticket_locked_for_edits(ticket):
                require_ticket_not_locked(ticket)
                return redirect(url_for("ticket_detail", ticket_id=ticket.id))
            if action == "comment":
                if not effective_role_has_action(current_user.effective_role, "comment_public"):
                    abort(403)
                body = request.form.get("body", "").strip()
                upload = request.files.get("file")
                parent_id = request.form.get("parent_id", type=int)
                if body:
                    comment = post_ticket_comment(ticket, current_user, body, parent_id=parent_id)
                    log_history("ticket", ticket.id, "Comment added", details=body[:500])
                    audit("comment", ticket.number)
                    if upload and upload.filename:
                        attachment, error = save_ticket_attachment(ticket, upload, comment_id=comment.id)
                        if error:
                            flash(error, "error")
                        else:
                            log_history(
                                "ticket", ticket.id, "Attachment uploaded",
                                details=f"{attachment.original_name} ({attachment.size_bytes} bytes)",
                            )
            elif action == "reopen":
                if not effective_role_has_action(current_user.effective_role, "resolve"):
                    abort(403)
                require_ticket_team_access(ticket)
                if ticket.state not in ("Resolved", "Closed"):
                    flash(tr("{number} is not Resolved or Closed.", number=ticket.number), "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                before_state = ticket.state
                transition_ticket(ticket, "In Progress")
                log_history(
                    "ticket", ticket.id, "State changed", "state",
                    before_state, ticket.state,
                    details=f"Reopened by {current_user.name}.",
                )
                audit("reopen", ticket.number, f"{before_state} -> In Progress")
                db.session.commit()
                flash(tr("{number} reopened.", number=ticket.number), "success")
                return redirect(url_for("ticket_detail", ticket_id=ticket.id))
            elif action == "close":
                if not effective_role_has_action(current_user.effective_role, "resolve"):
                    abort(403)
                require_ticket_team_access(ticket)
                if ticket.state != "Resolved":
                    flash(tr("{number} is not Resolved.", number=ticket.number), "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                before_state = ticket.state
                try:
                    transition_ticket(ticket, "Closed")
                except HTTPException as error:
                    db.session.rollback()
                    flash(error.description or tr("That change could not be made."), "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                log_history(
                    "ticket", ticket.id, "State changed", "state",
                    before_state, ticket.state,
                    details=f"Closed by {current_user.name}.",
                )
                audit("close", ticket.number, f"{before_state} -> Closed")
                db.session.commit()
                flash(tr("{number} closed.", number=ticket.number), "success")
                return redirect(url_for("ticket_detail", ticket_id=ticket.id))
            elif action == "quick_resolve":
                if not effective_role_has_action(current_user.effective_role, "resolve"):
                    abort(403)
                require_ticket_team_access(ticket)
                before_state = ticket.state
                try:
                    require_resolution_notes(ticket, "Resolved")
                    transition_ticket(ticket, "Resolved")
                except HTTPException as error:
                    db.session.rollback()
                    flash(error.description or tr("That change could not be made."), "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                log_history(
                    "ticket", ticket.id, "State changed", "state",
                    before_state, ticket.state,
                    details="Resolved from the incident action bar.",
                )
                audit("resolve", ticket.number, f"{before_state} -> Resolved")
            elif action == "update":
                for required_action in ("update", "assign", "transition"):
                    if not effective_role_has_action(current_user.effective_role, required_action):
                        abort(403)
                require_ticket_team_access(ticket)
                assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
                eligible_ids = {agent.id for agent in ticket_team_agents(ticket)}
                if assignee_id is not None and assignee_id not in eligible_ids:
                    flash(tr("The assignee must be an active member of the owning team."), "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                impact = request.form.get("impact", ticket.impact)
                urgency = request.form.get("urgency", ticket.urgency)
                calculated = calculate_priority(impact, urgency)
                requested_priority = request.form.get("priority", calculated)
                reason = request.form.get("priority_override_reason", "").strip()
                governed_priority_input = "impact" in request.form or "urgency" in request.form
                if (
                    governed_priority_input and requested_priority != calculated
                    and (not role_at_least(current_user.effective_role, "manager") or len(reason) < 10)
                ):
                    flash(
                        tr("Only a manager or administrator may override calculated priority, with a reason of at least 10 characters."), "error",
                    )
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                before = {
                    "short description": ticket.title,
                    "description": ticket.description,
                    "state": ticket.state,
                    "priority": ticket.priority,
                    "impact": ticket.impact,
                    "urgency": ticket.urgency,
                    "category": ticket.category,
                    "subcategory": ticket.subcategory,
                    "contact type": ticket.contact_type,
                    "notification": ticket.notify,
                    "service offering": (
                        ticket.service_offering.name
                        if ticket.service_offering else "Not selected"
                    ),
                    "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned",
                }
                target_state = "Resolved" if request.form.get("resolve") else request.form["state"]
                if ticket.kind == "incident" and "resolution_notes" in request.form:
                    before["resolution notes"] = ticket.resolution_notes or ""
                    before["closure category"] = ticket.closure_category or ""
                    before["closure subcategory"] = ticket.closure_subcategory or ""
                    ticket.resolution_notes = request.form.get("resolution_notes", "").strip() or None
                    # Closure categorisation is only taken when resolving (or on an already
                    # resolved record); earlier, the prefilled value would go stale as
                    # triage changes the logging category.
                    closing = target_state in ("Resolved", "Closed") or ticket.state in ("Resolved", "Closed")
                    submitted_closure = request.form.get("closure_category", "") if closing else ""
                    if submitted_closure and submitted_closure != ticket.closure_category:
                        ticket.closure_category = normalize_ticket_category(current_user.tenant_id, submitted_closure)
                    if closing and ticket.closure_category:
                        ticket.closure_subcategory = normalize_ticket_subcategory(
                            current_user.tenant_id, ticket.closure_category,
                            submitted_subcategory(request.form, ticket.closure_subcategory or "", name="closure_subcategory"),
                        ) or None
                try:
                    require_resolution_notes(ticket, target_state)
                    transition_ticket(ticket, target_state)
                except HTTPException as error:
                    db.session.rollback()
                    flash(error.description or tr("That change could not be made."), "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                previous_override_reason = ticket.priority_override_reason
                if governed_priority_input and requested_priority != calculated:
                    ticket.priority_overridden = True
                    ticket.priority_override_reason = reason
                    if reason != previous_override_reason:
                        log_history(
                            "ticket", ticket.id, "Priority override reason recorded",
                            "priority override reason",
                            previous_override_reason or "None", reason,
                            details=(
                                f"{current_user.name} overrode priority to {requested_priority} "
                                f"(calculated: {calculated}): {reason}"
                            ),
                        )
                elif governed_priority_input:
                    ticket.priority_overridden = False
                    ticket.priority_override_reason = None
                    if previous_override_reason:
                        log_history(
                            "ticket", ticket.id, "Priority override cleared",
                            "priority override reason",
                            previous_override_reason, "None",
                        )
                ticket.impact = impact
                ticket.urgency = urgency
                ticket.priority = requested_priority
                ticket.assignee_id = assignee_id
                if assignee_id:
                    follow_ticket(ticket, db.session.get(User, assignee_id))
                if ticket.kind == "incident":
                    contact_type = request.form.get(
                        "contact_type", ticket.contact_type
                    )
                    notify = request.form.get("notify", ticket.notify)
                    if contact_type not in {
                        "Self-service", "Phone", "Email", "Chat", "Monitoring"
                    }:
                        abort(400, description=tr("Select a valid contact type."))
                    if notify not in {"Email", "In-app only", "Do not notify"}:
                        abort(400, description=tr("Select a valid notification preference."))
                    ticket.title = request.form.get("title", ticket.title).strip()
                    ticket.description = request.form.get(
                        "description", ticket.description
                    ).strip()
                    submitted_category = request.form.get("category", ticket.category)
                    # An unchanged category is kept even if it's since been
                    # retired from the active list -- otherwise merely saving
                    # an older incident would re-categorise it to "General".
                    if submitted_category != ticket.category:
                        ticket.category = normalize_ticket_category(current_user.tenant_id, submitted_category)
                    ticket.subcategory = normalize_ticket_subcategory(
                        current_user.tenant_id, ticket.category, submitted_subcategory(request.form, ticket.subcategory)
                    )
                    ticket.contact_type = contact_type
                    ticket.notify = notify
                    offering_id = request.form.get("service_offering_id", "")
                    offering = (
                        tenant_record_or_404(ServiceOffering, int(offering_id))
                        if offering_id else None
                    )
                    if offering and offering.status != "Operational":
                        abort(400, description=tr("Select an operational service offering."))
                    ticket.service_offering_id = offering.id if offering else None
                    ci_id = request.form.get("ci_id", "")
                    existing_primary = TaskCI.query.filter_by(
                        target_type="ticket", target_id=ticket.id,
                        relationship_role="Primary CI",
                    ).first()
                    old_ci_name = (
                        existing_primary.ci.name if existing_primary else "Not selected"
                    )
                    if ci_id:
                        ci = tenant_record_or_404(ConfigurationItem, int(ci_id))
                        if not existing_primary:
                            existing_primary = TaskCI(
                                target_type="ticket", target_id=ticket.id,
                                relationship_role="Primary CI",
                            )
                            db.session.add(existing_primary)
                        existing_primary.ci_id = ci.id
                        if old_ci_name != ci.name:
                            log_history(
                                "ticket", ticket.id, "Field changed",
                                "configuration item", old_ci_name, ci.name,
                            )
                    elif existing_primary:
                        db.session.delete(existing_primary)
                        log_history(
                            "ticket", ticket.id, "Field changed",
                            "configuration item", old_ci_name, "Not selected",
                        )
                # transition_ticket() above already synced outages once, but that
                # ran before impact/CI were updated to their new values for this
                # request -- resync now that they're final.
                sync_service_outages(ticket)
                assignee = db.session.get(User, assignee_id) if assignee_id else None
                log_field_changes("ticket", ticket.id, before, {
                    "short description": ticket.title,
                    "description": ticket.description,
                    "state": ticket.state,
                    "priority": ticket.priority,
                    "impact": ticket.impact,
                    "urgency": ticket.urgency,
                    "category": ticket.category,
                    "subcategory": ticket.subcategory,
                    "contact type": ticket.contact_type,
                    "notification": ticket.notify,
                    "service offering": (
                        ticket.service_offering.name
                        if ticket.service_offering else "Not selected"
                    ),
                    "assigned to": assignee.name if assignee else "Unassigned",
                    **({
                        "resolution notes": ticket.resolution_notes or "",
                        "closure category": ticket.closure_category or "",
                        "closure subcategory": ticket.closure_subcategory or "",
                    } if "resolution notes" in before else {}),
                })
                audit("update", ticket.number, f"{ticket.state}, {ticket.priority}")
            elif action == "reassign_team":
                if not user_can_manage_ticket(current_user, ticket):
                    abort(403, description=(
                        tr("Only the current owning team's manager or an admin can reassign this record.")
                    ))
                try:
                    new_group_id = int(request.form["new_group_id"])
                except (KeyError, ValueError):
                    abort(400, description=tr("Select a team to reassign to."))
                new_group = core.team_groups(ticket.tenant_id).filter(
                    SupportGroup.id == new_group_id,
                ).first()
                if not new_group:
                    abort(400, description=tr("Select an active team."))
                if ticket.kind == "change":
                    # Lock and re-read the owner so a double-submitted
                    # reassignment stops at the "already owned" check below
                    # instead of superseding the approval chain (and
                    # notifying every approver) a second time. Refresh, not
                    # a re-query: the session already holds these objects.
                    db.session.refresh(ticket, with_for_update=True)
                    if ticket.change_ownership:
                        db.session.refresh(ticket.change_ownership)
                current_group = ticket_owning_group(ticket)
                if current_group and current_group.id == new_group.id:
                    abort(400, description=tr("This record is already owned by that team."))
                if ticket.kind == "change" and (not new_group.manager or not new_group.manager.active):
                    abort(400, description=(
                        tr("The selected team must have an active manager before it can own a change.")
                    ))
                if ticket.kind == "change":
                    ticket.change_ownership.group_id = new_group.id
                else:
                    assignment = TicketAssignmentGroup.query.filter_by(ticket_id=ticket.id).first()
                    if assignment:
                        assignment.group_id = new_group.id
                    else:
                        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=new_group.id))
                ticket.assignee_id = None
                log_history(
                    "ticket", ticket.id, "Reassigned to another team",
                    "owning team",
                    current_group.name if current_group else "Unassigned", new_group.name,
                )
                audit(
                    "reassign", ticket.number,
                    f"{current_group.name if current_group else 'Unassigned'} -> {new_group.name}",
                )
                if ticket.kind == "change":
                    supersede_change_approval(ticket, ["owning team"])
                db.session.commit()
                flash(tr("{number} reassigned to {name}.", number=ticket.number, name=new_group.name), "success")
                return redirect(url_for("ticket_detail", ticket_id=ticket.id))
            elif action == "follow":
                follow_ticket(ticket, current_user)
            elif action == "unfollow":
                unfollow_ticket(ticket, current_user)
            db.session.commit()
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        agents = ticket_team_agents(ticket)
        owning_group = ticket_owning_group(ticket)
        ticket_locked = ticket_locked_for_edits(ticket)
        can_manage_ticket = user_can_manage_ticket(current_user, ticket) and not ticket_locked
        can_reopen = (
            ticket.state in ("Resolved", "Closed")
            and user_can_manage_ticket(current_user, ticket)
            and effective_role_has_action(current_user.effective_role, "resolve")
        )
        can_close = (
            ticket.state == "Resolved"
            and user_can_manage_ticket(current_user, ticket)
            and effective_role_has_action(current_user.effective_role, "resolve")
        )
        internal_view = effective_role_has_action(current_user.effective_role, "comment_internal")
        chains = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).options(
            selectinload(ApprovalChain.gates).selectinload(ApprovalGate.votes).selectinload(ApprovalVote.approver),
        ).all()
        slas = TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).all()
        work_tasks = OperationalTask.query.filter_by(
            parent_type="ticket", parent_id=ticket.id
        ).order_by(OperationalTask.sequence, OperationalTask.id).all()
        history = TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).options(selectinload(TaskHistory.actor)).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all()
        ci_links = TaskCI.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).order_by(TaskCI.relationship_role).all()
        return render_template(
            "incident_detail.html" if ticket.kind == "incident" else "ticket_detail.html",
            ticket=ticket, agents=agents, chains=chains, slas=slas,
            state_track=build_state_track(ticket.kind, ticket.state),
            ticket_state_options=allowed_ticket_states(ticket), owning_group=owning_group,
            can_manage_ticket=can_manage_ticket, ticket_locked=ticket_locked, can_reopen=can_reopen,
            can_close=can_close,
            related=related_records("ticket", ticket.id),
            relation_labels=RELATION_LABELS, work_tasks=work_tasks,
            work_task_states=OPERATIONAL_TASK_TRANSITIONS, history=history,
            internal_view=internal_view,
            ci_links=ci_links,
            teams=core.team_groups().all(),
            reassignable_teams=core.team_groups().filter(
                SupportGroup.id != (owning_group.id if owning_group else -1),
            ).options(selectinload(SupportGroup.manager)).all(),
            service_offerings=tenant_query(ServiceOffering).filter_by(
                status="Operational"
            ).order_by(ServiceOffering.name).all(),
            ticket_categories=tenant_ticket_categories(current_user.tenant_id),
            ticket_subcategories=tenant_ticket_subcategories(current_user.tenant_id),
            pir_outcomes=CHANGE_PIR_OUTCOMES,
            is_following=is_following_ticket(current_user, ticket),
            change_freeze_windows=(
                tenant_query(ChangeFreezeWindow).filter(
                    ChangeFreezeWindow.ends_at >= now()
                ).order_by(ChangeFreezeWindow.starts_at).all()
                if ticket.kind == "change" else []
            ),
        )

    @app.post("/change/<int:ticket_id>/delete")
    @roles("agent", "manager", "admin")
    def change_delete(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "change":
            abort(404)
        require_ticket_team_access(ticket)
        if ticket.deleted_at:
            abort(409, description=tr("{number} has already been deleted.", number=ticket.number))
        if ticket.state not in ("New", "Awaiting Approval"):
            abort(409, description=(
                tr("{number} cannot be deleted once it has progressed past approval. Cancel it through the normal state transition instead.", number=ticket.number)
            ))
        cancel_approval_chain(approval_chain_for("ticket", ticket.id))
        ticket.state = "Cancelled"
        ticket.deleted_at = now()
        ticket.deleted_by_id = current_user.id
        log_history(
            "ticket", ticket.id, "Change deleted",
            details=f"Soft-deleted by {current_user.name}; retained as Cancelled for the audit trail.",
        )
        audit("delete", ticket.number, f"soft-deleted by {current_user.name}")
        db.session.commit()
        flash(tr("{number} was deleted. It remains available for audit as a Cancelled change.", number=ticket.number))
        return redirect(url_for("tickets", kind="change"))

    @app.post("/change/<int:ticket_id>/plan")
    @roles("agent", "manager", "admin")
    def change_plan_update(ticket_id):
        # Locked: a double-submitted revision must see the first
        # submission's committed state before computing its own diff, or
        # both requests compute the same non-empty changed_fields against
        # the same pre-mutation "before" and each supersede the approval
        # chain + notify approvers -- see supersede_change_approval.
        ticket = tenant_record_or_404(Ticket, ticket_id, lock=True)
        if ticket.kind != "change" or not ticket.change_governance:
            abort(404)
        require_ticket_team_access(ticket)
        governance = ticket.change_governance

        def plan_form_error(message):
            flash(message, "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))

        if ticket.state in ("In Progress", "Pending", "Resolved", "Closed", "Cancelled"):
            return plan_form_error(
                "The change plan is locked once implementation has started or the change is closed. "
                "Reopen the change to New/Awaiting Approval before revising the plan."
            )
        try:
            planned_start = parse_form_datetime(request.form.get("planned_start"))
            planned_end = parse_form_datetime(request.form.get("planned_end"))
            ci_id = int(request.form["ci_id"]) if request.form.get("ci_id") else None
        except (TypeError, ValueError):
            return plan_form_error("Change plan dates or CI are invalid.")
        # Tenant-scope the CI lookup before it's used for anything, including
        # the risk-score calculation below -- fetching it unscoped first
        # would let a cross-tenant ci_id's attributes (class,
        # environment/criticality) feed calculated_risk_score before the
        # request is ultimately rejected for not owning that CI.
        ci = tenant_query(ConfigurationItem).filter(ConfigurationItem.id == ci_id).first() if ci_id else None
        if ci_id and not ci:
            return plan_form_error("The selected configuration item does not exist.")
        calculated_risk_score = calculate_change_risk_score(
            request.form.get("change_type", governance.change_type), ci,
        )
        risk_score_input = request.form.get("risk_score", "").strip()
        try:
            if risk_score_input:
                risk_score = max(0, min(100, int(risk_score_input)))
                risk_score_overridden = risk_score != calculated_risk_score
            else:
                risk_score = calculated_risk_score
                risk_score_overridden = False
        except (TypeError, ValueError):
            return plan_form_error("Risk score must be a number between 0 and 100.")
        if not planned_start or not planned_end:
            return plan_form_error("Planned start and planned end are required for a change.")
        if planned_end <= planned_start:
            return plan_form_error("Planned end must be later than planned start.")
        if ci_id:
            conflicts = _conflict_descriptions(
                ticket.tenant_id, {ci_id}, planned_start, planned_end,
                exclude_governance_id=governance.id, exclude_ticket_id=ticket.id,
            )
            if conflicts:
                return plan_form_error(
                    f"This revision conflicts with {'; '.join(conflicts)}. "
                    "Reschedule the planned window or select a different configuration item."
                )
        required_text = {
            "Short description": request.form.get("title", "").strip(),
            "Description": request.form.get("description", "").strip(),
            "Implementation plan": request.form.get("implementation_plan", "").strip(),
            "Test plan": request.form.get("test_plan", "").strip(),
            "Backout plan": request.form.get("backout_plan", "").strip(),
        }
        missing = [label for label, value in required_text.items() if not value]
        if missing:
            return plan_form_error(f"Required change-plan fields are missing: {', '.join(missing)}.")
        before = {
            "short description": ticket.title,
            "description": ticket.description,
            "change type": governance.change_type,
            "risk score": governance.risk_score,
            "impact": governance.impact,
            "implementation plan": governance.implementation_plan,
            "test plan": governance.test_plan,
            "backout plan": governance.backout_plan,
            "planned start": governance.planned_start.isoformat() if governance.planned_start else "",
            "planned end": governance.planned_end.isoformat() if governance.planned_end else "",
            "primary CI": governance.ci.name if governance.ci else "",
        }
        ticket.title = request.form.get("title", "").strip()
        ticket.description = request.form.get("description", "").strip()
        governance.change_type = request.form.get("change_type", "Normal")
        governance.risk_score = risk_score
        governance.risk_score_overridden = risk_score_overridden
        governance.risk_score_override_reason = (
            request.form.get("risk_score_override_reason", "").strip() if risk_score_overridden else ""
        )
        governance.impact = request.form.get("impact", "Medium")
        governance.implementation_plan = request.form.get("implementation_plan", "").strip()
        governance.test_plan = request.form.get("test_plan", "").strip()
        governance.backout_plan = request.form.get("backout_plan", "").strip()
        governance.planned_start = planned_start
        governance.planned_end = planned_end
        governance.ci_id = ci_id
        after = {
            "short description": ticket.title,
            "description": ticket.description,
            "change type": governance.change_type,
            "risk score": governance.risk_score,
            "impact": governance.impact,
            "implementation plan": governance.implementation_plan,
            "test plan": governance.test_plan,
            "backout plan": governance.backout_plan,
            "planned start": governance.planned_start.isoformat() if governance.planned_start else "",
            "planned end": governance.planned_end.isoformat() if governance.planned_end else "",
            "primary CI": db.session.get(ConfigurationItem, ci_id).name if ci_id else "",
        }
        changed_fields = log_field_changes(
            "ticket", ticket.id, before, after, event="Material change plan updated"
        )
        if not changed_fields:
            flash(tr("No change-plan values changed."), "success")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        conflicts = run_change_conflict_detection(ticket, governance)
        supersede_change_approval(ticket, changed_fields)
        audit("revise change plan", ticket.number, ", ".join(changed_fields))
        db.session.commit()
        flash(
            tr("Change plan revised. {number} returned to Awaiting Approval and approvers were notified.", number=ticket.number)
            + (" " + tr("Conflicts flagged: {conflicts}.", conflicts=", ".join(conflicts)) if conflicts else ""),
            "error" if conflicts else "success",
        )
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/change/<int:ticket_id>/pir")
    @roles("agent", "manager", "admin")
    def change_pir_update(ticket_id):
        """Records (or updates) the ITIL 4 post-implementation review a
        change needs before it can reach Closed -- see the gate in
        transition_ticket(). Updatable even after the change is closed, in
        case a follow-up action needs adding later."""
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "change" or not ticket.change_governance:
            abort(404)
        require_ticket_team_access(ticket)
        outcome = request.form.get("outcome", "")
        if outcome not in CHANGE_PIR_OUTCOMES:
            abort(400, description=tr("Select a valid review outcome."))
        summary = request.form.get("summary", "").strip()
        if not summary:
            abort(400, description=tr("A summary is required for the post-implementation review."))
        pir = ticket.post_implementation_review
        if pir:
            before = {"outcome": pir.outcome, "summary": pir.summary}
            pir.outcome = outcome
            pir.summary = summary
            pir.follow_up_actions = request.form.get("follow_up_actions", "").strip()
            pir.reviewed_by_id = current_user.id
            pir.reviewed_at = now()
            log_field_changes("ticket", ticket.id, before, {"outcome": outcome, "summary": summary},
                              event="Post-implementation review updated")
        else:
            pir = ChangePostImplementationReview(
                ticket_id=ticket.id, outcome=outcome, summary=summary,
                follow_up_actions=request.form.get("follow_up_actions", "").strip(),
                reviewed_by_id=current_user.id,
            )
            db.session.add(pir)
            log_history("ticket", ticket.id, "Post-implementation review recorded", details=outcome)
        audit("review", ticket.number, f"PIR outcome: {outcome}")
        db.session.commit()
        flash(tr("Post-implementation review saved for {number}.", number=ticket.number), "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/ticket/<int:ticket_id>/satisfaction")
    @login_required
    def ticket_satisfaction_update(ticket_id):
        """ITIL 4 service-desk CSAT: only the ticket's own requester can
        rate it, and only once it's actually Resolved/Closed -- rating an
        in-flight ticket wouldn't reflect a completed service interaction."""
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.requester_id != current_user.id:
            abort(403)
        if ticket.state not in ("Resolved", "Closed"):
            abort(409, description=tr("This ticket isn't resolved yet."))
        try:
            rating = int(request.form.get("rating", ""))
        except (TypeError, ValueError):
            abort(400, description=tr("Select a rating between 1 and 5."))
        if rating < 1 or rating > 5:
            abort(400, description=tr("Select a rating between 1 and 5."))
        ticket.csat_rating = rating
        ticket.csat_comment = request.form.get("comment", "").strip()
        ticket.csat_submitted_at = now()
        log_history("ticket", ticket.id, "Satisfaction rating submitted", details=f"{rating}/5")
        audit("csat", ticket.number, f"{rating}/5")
        db.session.commit()
        flash(tr("Thanks for the feedback!"), "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/incident/<int:ticket_id>/major-incident")
    @roles("agent", "manager", "admin")
    def major_incident_update(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "incident":
            abort(404)
        require_ticket_team_access(ticket)
        if not require_ticket_not_locked(ticket):
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        profile = ticket.major_incident_profile
        if not profile:
            profile = MajorIncidentProfile(ticket_id=ticket.id)
            db.session.add(profile)
        status = request.form.get("status", "Proposed")
        if status not in ("Proposed", "Accepted", "Rejected", "Resolved"):
            abort(400)
        before = {
            "major incident status": profile.status,
            "business impact": profile.business_impact,
            "communications": profile.communications,
        }
        profile.status = status
        profile.business_impact = request.form.get("business_impact", "").strip()
        profile.communications = request.form.get("communications", "").strip()
        profile.coordinator_id = current_user.id
        if status == "Accepted" and not profile.declared_at:
            profile.declared_at = now()
        log_field_changes("ticket", ticket.id, before, {
            "major incident status": profile.status,
            "business impact": profile.business_impact,
            "communications": profile.communications,
        }, event="Major incident coordination updated")
        audit("major incident", ticket.number, status)
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/incident/<int:ticket_id>/major-incident/status-update")
    @roles("agent", "manager", "admin")
    def major_incident_status_update(ticket_id):
        """Posts one discrete, timestamped entry to the public status-page
        timeline -- separate from major_incident_update()'s internal
        business_impact/communications fields, which never leave the
        authenticated app. Also the only place MajorIncidentProfile.public
        is set, so publishing is always accompanied by an actual update."""
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "incident":
            abort(404)
        require_ticket_team_access(ticket)
        profile = ticket.major_incident_profile
        if not profile:
            abort(404, description=tr("Propose this as a major incident before posting a public status update."))
        status = request.form.get("status", "")
        if status not in ("Investigating", "Identified", "Monitoring", "Resolved"):
            abort(400)
        message = request.form.get("message", "").strip()
        if not message:
            abort(400, description=tr("A status update message is required."))
        db.session.add(MajorIncidentUpdate(
            major_incident_profile_id=profile.id, status=status, message=message,
            posted_by_id=current_user.id, tenant_id=ticket.tenant_id,
        ))
        publish = request.form.get("publish") == "on"
        profile.public = publish
        audit("major incident status update", ticket.number, f"{status}{' · published' if publish else ' · not published'}")
        db.session.commit()
        flash(tr("Status update posted."), "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/incident/<int:ticket_id>/major-incident/review")
    @roles("agent", "manager", "admin")
    def major_incident_review_update(ticket_id):
        """A structured after-the-fact review, distinct from the live
        business_impact/communications fields major_incident_update()
        manages -- ITIL 4 continual improvement expects a documented
        lessons-learned artifact, not just whatever the live coordination
        log happened to capture while the incident was still active."""
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "incident":
            abort(404)
        # A structured review is expected of any P1, not only ones formally
        # walked through the "propose major incident" flow -- most P1s never
        # get declared major but still warrant documented lessons learned.
        if not ticket.major_incident_profile and ticket.priority != "P1":
            abort(404)
        require_ticket_team_access(ticket)
        profile = ticket.major_incident_profile
        if not profile:
            profile = MajorIncidentProfile(ticket_id=ticket.id, status="Resolved")
            db.session.add(profile)
        before = {
            "what went well": profile.review_what_went_well,
            "what went poorly": profile.review_what_went_poorly,
            "follow-up actions": profile.review_follow_up_actions,
        }
        profile.review_what_went_well = request.form.get("what_went_well", "").strip()
        profile.review_what_went_poorly = request.form.get("what_went_poorly", "").strip()
        profile.review_follow_up_actions = request.form.get("follow_up_actions", "").strip()
        profile.reviewed_by_id = current_user.id
        profile.reviewed_at = now()
        log_field_changes("ticket", ticket.id, before, {
            "what went well": profile.review_what_went_well,
            "what went poorly": profile.review_what_went_poorly,
            "follow-up actions": profile.review_follow_up_actions,
        }, event="Post-incident review recorded")
        audit("review", ticket.number, "Post-incident review recorded")
        db.session.commit()
        flash(tr("Post-incident review saved for {number}.", number=ticket.number), "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/record/<source_type>/<int:source_id>/relationships")
    @roles("agent", "manager", "admin")
    def record_link_add(source_type, source_id):
        source = record_reference(source_type, source_id)
        if not source:
            abort(404)
        if isinstance(source, Ticket):
            require_ticket_team_access(source)
            if source.kind == "change" and source.state not in ("New", "Awaiting Approval"):
                abort(409, description=(
                    tr("{number} is locked: related records can only be linked before a change is approved.", number=source.number)
                ))
            if source.kind != "change" and ticket_locked_for_edits(source):
                abort(409, description=(
                    tr("{number} is {state} and locked: only comments and notes can be added.", number=source.number, state=source.state)
                ))
        elif isinstance(source, EnterpriseRecord):
            if not user_can_manage_enterprise_record(current_user, source):
                abort(403)
        elif isinstance(source, RequestedItem):
            if not user_can_manage_ritm(current_user, source):
                abort(403)
        target = find_record_by_number(request.form.get("target_number"))
        if not target:
            abort(404, description=tr("No record matches the supplied number."))
        if isinstance(target, Ticket) and not user_can_view_ticket(current_user, target):
            abort(404)
        if (
            isinstance(target, EnterpriseRecord)
            and not user_can_view_enterprise_record(current_user, target)
        ):
            abort(404)
        if (
            isinstance(target, CatalogRequest)
            and not user_can_view_catalog_request(current_user, target)
        ):
            abort(404)
        if (
            isinstance(target, RequestedItem)
            and not user_can_view_catalog_request(current_user, target.request)
        ):
            abort(404)
        if (
            isinstance(target, (CatalogTask, OperationalTask, Knowledge))
            and record_tenant_id(target) != core.tenant_context_id()
        ):
            abort(404)
        target_type = record_type_for(target)
        relation_type = request.form.get("link_type", "")
        source_kind = (
            source.kind if isinstance(source, Ticket)
            else "problem" if isinstance(source, EnterpriseRecord) and source.domain == "problem"
            else source_type
        )
        target_kind = (
            target.kind if isinstance(target, Ticket)
            else "problem" if isinstance(target, EnterpriseRecord) and target.domain == "problem"
            else target_type
        )
        allowed = {
            ("incident", "incident"): {"parent_incident"},
            ("incident", "problem"): {"underlying_problem"},
            ("incident", "change"): {"resolution_change", "caused_by_change"},
            ("incident", "request"): {"converted_request"},
            ("incident", "knowledge"): {"knowledge_article"},
            ("problem", "incident"): {"related_incident"},
            ("problem", "change"): {"problem_change"},
            ("problem", "knowledge"): {"knowledge_article"},
            ("change", "incident"): {"related_incident"},
            ("change", "problem"): {"problem_change"},
            ("change", "ritm"): {"requested_item_change"},
            ("ritm", "change"): {"requested_item_change"},
        }
        if relation_type not in allowed.get((source_kind, target_kind), set()):
            abort(400, description=(
                tr("{relation_labels} is not valid between {source_kind} and {target_kind}.", relation_labels=RELATION_LABELS.get(relation_type, 'This relationship'), source_kind=source_kind, target_kind=target_kind)
            ))
        if source_type == target_type and source_id == target.id:
            abort(400, description=tr("A record cannot be related to itself."))
        exists = RecordLink.query.filter_by(
            source_type=source_type, source_id=source_id,
            target_type=target_type, target_id=target.id, link_type=relation_type,
        ).first()
        if not exists:
            db.session.add(RecordLink(
                source_type=source_type, source_id=source_id,
                target_type=target_type, target_id=target.id, link_type=relation_type,
            ))
            description = (
                f"{RELATION_LABELS[relation_type]} linked to "
                f"{record_number(target)}: {record_title(target)}"
            )
            log_history(source_type, source_id, "Related record linked", details=description)
            if target_type == "ticket":
                log_history(
                    "ticket", target.id, "Related record linked",
                    details=f"{record_number(source)} linked as {RELATION_LABELS[relation_type]}.",
                )
            audit("link", record_number(source), description)
            db.session.commit()
        return redirect(record_url(source))

    @app.post("/record/<target_type>/<int:target_id>/configuration-items")
    @roles("agent", "manager", "admin")
    def task_ci_add(target_type, target_id):
        target = record_reference(target_type, target_id)
        if not target or target_type not in ("ticket", "enterprise"):
            abort(404)
        if isinstance(target, Ticket):
            require_ticket_team_access(target)
        elif not user_can_manage_enterprise_record(current_user, target):
            abort(403)
        role = request.form.get("relationship_role")
        if role not in ("Primary CI", "Affected CI", "Impacted service"):
            abort(400)
        try:
            ci_ids = [int(raw) for raw in request.form.getlist("ci_id") if raw.strip()]
        except ValueError:
            abort(400)
        if not ci_ids:
            abort(400, description=tr("Select at least one configuration item."))
        if role == "Primary CI":
            # A record has exactly one primary CI; multi-select never applies here.
            ci_ids = ci_ids[:1]
            TaskCI.query.filter_by(
                target_type=target_type, target_id=target_id,
                relationship_role="Primary CI",
            ).delete()
        linked_names = []
        for ci_id in dict.fromkeys(ci_ids):
            ci = tenant_record_or_404(ConfigurationItem, ci_id)
            exists = TaskCI.query.filter_by(
                target_type=target_type, target_id=target_id, ci_id=ci.id,
                relationship_role=role,
            ).first()
            if exists:
                continue
            db.session.add(TaskCI(
                target_type=target_type, target_id=target_id,
                ci_id=ci.id, relationship_role=role,
            ))
            linked_names.append(ci.name)
        if linked_names:
            summary = f"{role}: {', '.join(linked_names)}"
            log_history(
                target_type, target_id, "Configuration item linked",
                details=summary,
            )
            audit("link CI", record_number(target), summary)
            # Affected CIs/impacted services are a material-change field (CLAUDE.md
            # governance rules): adding one to an already-approved change must
            # invalidate the current approval chain, the same as team/plan edits do.
            if isinstance(target, Ticket) and target.kind == "change":
                supersede_change_approval(target, [role.lower()])
            db.session.commit()
        return redirect(record_url(target))

    @app.post("/change/<int:ticket_id>/tasks")
    @roles("agent", "manager", "admin")
    def change_task_add(ticket_id):
        # Locked for the same reason as change_plan_update: adding a task can
        # supersede the approval chain, and a double-submit must serialize
        # against the running approval chain check below rather than both
        # requests reading it as not-yet-superseded and each notifying.
        ticket = tenant_record_or_404(Ticket, ticket_id, lock=True)
        if ticket.kind != "change":
            abort(404)
        require_ticket_team_access(ticket)
        if ticket.state in ("Resolved", "Closed", "Cancelled"):
            abort(409, description=(
                tr("{number} is {state}; change tasks cannot be added to a closed-out change.", number=ticket.number, state=ticket.state)
            ))
        group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
        if not core.is_team_group(group):
            abort(400, description=tr("Change tasks require an active team."))
        task_type = request.form.get("task_type")
        if task_type not in ("Planning", "Implementation", "Testing", "Review"):
            abort(400)
        if not request.form.get("planned_start") or not request.form.get("planned_end"):
            abort(400, description=tr("Task planned start and planned end are required."))
        planned_start = parse_form_datetime(request.form["planned_start"])
        planned_end = parse_form_datetime(request.form["planned_end"])
        governance = ticket.change_governance
        if planned_end <= planned_start:
            abort(400, description=tr("Task end must be later than task start."))
        if governance and governance.planned_start and governance.planned_end:
            if (
                align_tz(planned_start, governance.planned_start) < governance.planned_start
                or align_tz(planned_end, governance.planned_end) > governance.planned_end
            ):
                abort(409, description=(
                    tr("Task dates must fall within the parent change's planned window ({planned_start} → {planned_end}).", planned_start=governance.planned_start.strftime('%Y-%m-%d %H:%M'), planned_end=governance.planned_end.strftime('%Y-%m-%d %H:%M'))
                ))
        sequence = OperationalTask.query.filter_by(
            parent_type="ticket", parent_id=ticket.id
        ).count() + 1

        def build_task():
            task = OperationalTask(
                number=next_operational_task_number("change"),
                task_kind="change", parent_type="ticket", parent_id=ticket.id,
                title=request.form["title"].strip(), task_type=task_type,
                sequence=sequence,
                assignment_group_id=group.id,
                planned_start=planned_start, planned_end=planned_end,
                required=bool(request.form.get("required")),
                state="Open" if task_type == "Planning" else "Pending",
            )
            db.session.add(task)
            return task
        task = create_with_retry_on_number_collision(build_task)
        log_history(
            "ticket", ticket.id, "Change task created",
            details=f"{task.number} {task.task_type}: {task.title} → {group.name}",
        )
        audit("create", task.number, f"{ticket.number}: {task.title}")
        chain = approval_chain_for("ticket", ticket.id)
        reapproval_triggered = chain is not None and chain.state in ("Running", "Approved")
        if reapproval_triggered:
            supersede_change_approval(
                ticket, [f"Change tasks ({task.number} {task.task_type} added)"]
            )
        db.session.commit()
        if reapproval_triggered:
            flash(
                tr("{number} added. Adding a task after submission is a material change — {number2} returned to Awaiting Approval and approvers were notified.", number=task.number, number2=ticket.number),
                "error",
            )
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.get("/operational-task/<int:task_id>")
    @login_required
    def operational_task_detail(task_id):
        task = db.get_or_404(OperationalTask, task_id)
        parent = record_reference(task.parent_type, task.parent_id)
        if not parent:
            abort(404)
        if isinstance(parent, Ticket):
            can_view = user_can_view_ticket(current_user, parent)
        elif isinstance(parent, EnterpriseRecord):
            can_view = user_can_view_enterprise_record(current_user, parent)
        else:
            can_view = False
        if not can_view:
            abort(403)
        can_edit = user_in_group(current_user, task.assignment_group)
        member_ids = {member.user_id for member in task.assignment_group.members}
        if task.assignment_group.manager_id:
            member_ids.add(task.assignment_group.manager_id)
        agents = User.query.filter(
            User.id.in_(member_ids), User.active.is_(True),
            User.role.in_(["agent", "manager", "admin", "superadmin"]),
        ).order_by(User.name).all() if member_ids else []
        history = TaskHistory.query.filter_by(
            target_type=task.parent_type, target_id=task.parent_id
        ).filter(TaskHistory.details.contains(task.number)).options(selectinload(TaskHistory.actor)).order_by(
            TaskHistory.created_at.desc(), TaskHistory.id.desc()
        ).all()
        allowed_states = OPERATIONAL_TASK_TRANSITIONS.get(task.state, (task.state,))
        closing_state = "Closed Complete" if "Closed Complete" in allowed_states else task.state
        gate_block = None
        selectable_states = [task.state]
        for candidate in allowed_states:
            if candidate == task.state:
                continue
            block = change_task_gate_block(task, candidate)
            if block:
                gate_block = gate_block or block
            else:
                selectable_states.append(candidate)
        notes = TaskNote.query.filter_by(
            target_type="operational_task", target_id=task.id
        ).order_by(TaskNote.created_at.desc()).all()
        siblings = OperationalTask.query.filter_by(
            parent_type=task.parent_type, parent_id=task.parent_id,
        ).filter(OperationalTask.id != task.id).order_by(OperationalTask.sequence, OperationalTask.id).all()
        ci_links = TaskCI.query.filter_by(
            target_type=task.parent_type, target_id=task.parent_id
        ).order_by(TaskCI.relationship_role).all()
        approval_votes = []
        if task.task_kind == "change":
            chain = approval_chain_for("ticket", task.parent_id)
            if chain:
                approval_votes = [vote for gate in chain.gates for vote in gate.votes]
        return render_template(
            "operational_task_detail.html", task=task, parent=parent,
            parent_url=record_url(parent), can_edit=can_edit, agents=agents,
            work_task_states=OPERATIONAL_TASK_TRANSITIONS, history=history,
            closing_state=closing_state, notes=notes, siblings=siblings,
            ci_links=ci_links, approval_votes=approval_votes,
            selectable_states=selectable_states, gate_block=gate_block,
        )

    @app.post("/operational-task/<int:task_id>/notes")
    @roles("agent", "manager", "admin")
    def operational_task_note_add(task_id):
        task = db.get_or_404(OperationalTask, task_id)
        if not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                tr("Only active members of {name} can update {number}.", name=task.assignment_group.name, number=task.number)
            ))
        body = request.form.get("body", "").strip()
        if body:
            db.session.add(TaskNote(
                target_type="operational_task", target_id=task.id,
                visibility="internal", body=body, user_id=current_user.id,
            ))
            log_history(task.parent_type, task.parent_id, f"{task.number} note added", details=body[:500])
            audit("note", task.number, body[:120])
            db.session.commit()
        return redirect(url_for("operational_task_detail", task_id=task.id))

    @app.post("/operational-task/<int:task_id>")
    @roles("agent", "manager", "admin")
    def operational_task_update(task_id):
        task = db.get_or_404(OperationalTask, task_id)
        if not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                tr("Only active members of {name} can update {number}.", name=task.assignment_group.name, number=task.number)
            ))
        assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
        if assignee_id:
            assignee = db.session.get(User, assignee_id)
            if not assignee or not user_in_group(assignee, task.assignment_group):
                flash(tr("The assignee must belong to the task assignment group."), "error")
                return redirect(url_for("operational_task_detail", task_id=task.id))
        else:
            assignee = None
        requested_state = request.form.get("state", task.state)
        if requested_state != task.state:
            if requested_state not in OPERATIONAL_TASK_TRANSITIONS.get(task.state, (task.state,)):
                flash(tr("{number} cannot move from {state} to {requested_state}.", number=task.number, state=task.state, requested_state=requested_state), "error")
                return redirect(url_for("operational_task_detail", task_id=task.id))
            gate_block = change_task_gate_block(task, requested_state)
            if gate_block:
                flash(gate_block, "error")
                return redirect(url_for("operational_task_detail", task_id=task.id))
        before = {
            "state": task.state,
            "assigned to": task.assignee.name if task.assignee else "Unassigned",
            "work notes": task.work_notes,
        }
        transition_operational_task(task, requested_state)
        task.assignee_id = assignee_id
        task.work_notes = request.form.get("work_notes", "").strip()
        log_field_changes(task.parent_type, task.parent_id, before, {
            "state": task.state,
            "assigned to": assignee.name if assignee else "Unassigned",
            "work notes": task.work_notes,
        }, event=f"{task.number} updated")
        audit("update", task.number, task.state)
        db.session.commit()
        return redirect(url_for("operational_task_detail", task_id=task.id))

    @app.get("/modules")
    @login_required
    def modules():
        query = visible_enterprise_record_query(current_user)
        grouped = dict(query.with_entities(EnterpriseRecord.domain, func.count(EnterpriseRecord.id))
                       .group_by(EnterpriseRecord.domain).all())
        counts = {key: grouped.get(key, 0) for key in DOMAIN_CONFIG}
        return render_template("modules.html", modules=DOMAIN_CONFIG, counts=counts, domain_icons=DOMAIN_ICONS)

    @app.get("/module/<domain>")
    @login_required
    def module_records(domain):
        config = DOMAIN_CONFIG.get(domain)
        if not config:
            abort(404)
        query = visible_enterprise_record_query(current_user).filter_by(domain=domain)
        q = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        if q:
            query = query.filter(db.or_(EnterpriseRecord.number.ilike(f"%{q}%"),
                                        EnterpriseRecord.title.ilike(f"%{q}%"),
                                        EnterpriseRecord.external_id.ilike(f"%{q}%")))
        field_spec = {
            "number": {"label": "Number", "type": "text", "column": EnterpriseRecord.number},
            "title": {"label": "Short description", "type": "text", "column": EnterpriseRecord.title},
            "external_id": {"label": "Source ticket # (e.g. RT)", "type": "text", "column": EnterpriseRecord.external_id},
            "priority": {"label": "Priority", "type": "choice", "column": EnterpriseRecord.priority,
                        "options": [(p, p) for p in ["P1", "P2", "P3", "P4"]]},
            "state": {"label": "State", "type": "choice", "column": EnterpriseRecord.state,
                      "options": [(s, s) for s in
                                  ["New", "Open", "In Progress", "Awaiting Approval", "Approved",
                                   "Pending", "Resolved", "Closed", "Rejected"]]},
            "risk": {"label": "Risk", "type": "choice", "column": EnterpriseRecord.risk,
                    "options": [(r, r) for r in ["Low", "Medium", "High", "Critical"]]},
            "opened": {"label": "Opened", "type": "date", "column": EnterpriseRecord.created_at},
            "updated": {"label": "Updated", "type": "date", "column": EnterpriseRecord.updated_at},
        }
        query = apply_filter_conditions(query, conditions, field_spec)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.order_by(EnterpriseRecord.updated_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec)
        client_fields = {
            key: {"label": tr_value(spec["label"]), "type": spec["type"],
                  "options": [(value, tr_value(label)) for value, label in spec.get("options", [])]}
            for key, spec in field_spec.items()
        }
        return render_template(
            "module_records.html", domain=domain, config=config,
            records=rows, q=q, raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts,
            filter_fields=client_fields, page=page, pages=pages,
            total=total,
        )

    @app.route("/module/<domain>/new", methods=["GET", "POST"])
    @login_required
    def enterprise_new(domain):
        config = DOMAIN_CONFIG.get(domain)
        if not config:
            abort(404)
        if current_user.effective_role == "requester" and domain not in ("customer", "hr"):
            abort(403)
        if request.method == "POST":
            record = EnterpriseRecord(
                number=next_enterprise_number(domain), domain=domain, record_type=request.form["record_type"],
                title=request.form["title"].strip(), description=request.form["description"].strip(),
                priority=request.form.get("priority", "P3"), risk=request.form.get("risk", "Medium"),
                requester_id=current_user.id, due_at=datetime.fromisoformat(request.form["due_at"]) if request.form.get("due_at") else None,
            )
            db.session.add(record)
            db.session.flush()
            if domain == "problem":
                db.session.add(ProblemProfile(enterprise_record_id=record.id))
            if request.form.get("approval_required") and current_user.effective_role != "requester":
                admin = tenant_query(User).filter(User.role.in_(["admin", "superadmin"]), User.active.is_(True)).first()
                if not admin:
                    abort(409, description=tr("No active administrator is configured to approve this record."))
                db.session.add(Approval(enterprise_record_id=record.id, approver_id=admin.id, tenant_id=record.tenant_id))
                create_notification(
                    admin.id, f"Approval requested: {record.number}",
                    record.title, tenant_id=record.tenant_id,
                    target_type="enterprise", target_id=record.id,
                    event_type="enterprise.approval_requested",
                    template_vars={"record_number": record.number, "record_title": record.title},
                )
                record.state = "Awaiting Approval"
            log_history(
                "enterprise", record.id, "Record created",
                details=f"{record.number}: {record.title}",
            )
            audit("create", record.number, f"{config['name']}: {record.title}")
            db.session.commit()
            return redirect(url_for("enterprise_detail", record_id=record.id))
        return render_template("enterprise_form.html", domain=domain, config=config)

    @app.route("/enterprise/<int:record_id>", methods=["GET", "POST"])
    @login_required
    def enterprise_detail(record_id):
        record = tenant_record_or_404(EnterpriseRecord, record_id)
        if not user_can_view_enterprise_record(current_user, record):
            abort(403, description=tr("You are not involved in this record or its assigned work."))
        can_manage_record = user_can_manage_enterprise_record(current_user, record)
        if request.method == "POST":
            action = request.form.get("action")
            if action == "update":
                if not can_manage_record:
                    abort(403)
                before = {
                    "state": record.state,
                    "priority": record.priority,
                    "risk": record.risk,
                    "assigned to": record.assignee.name if record.assignee else "Unassigned",
                }
                try:
                    transition_enterprise(record, request.form["state"])
                except HTTPException as error:
                    db.session.rollback()
                    flash(error.description or tr("That change could not be made."), "error")
                    return redirect(url_for("enterprise_detail", record_id=record.id))
                record.priority = request.form["priority"]
                record.risk = request.form["risk"]
                record.assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
                assignee = db.session.get(User, record.assignee_id) if record.assignee_id else None
                log_field_changes("enterprise", record.id, before, {
                    "state": record.state,
                    "priority": record.priority,
                    "risk": record.risk,
                    "assigned to": assignee.name if assignee else "Unassigned",
                })
                audit("update", record.number, f"{record.state}, {record.priority}, risk {record.risk}")
            elif action in ("approve", "reject"):
                approval = Approval.query.filter_by(id=int(request.form["approval_id"]),
                                                    enterprise_record_id=record.id,
                                                    approver_id=current_user.id, state="Requested").first_or_404()
                approval.state = "Approved" if action == "approve" else "Rejected"
                approval.comments = request.form.get("comments", "")
                approval.decided_at = now()
                record.state = "Approved" if action == "approve" else "Rejected"
                create_notification(
                    record.requester_id, f"{record.number} {record.state.lower()}",
                    approval.comments or f"Your record was {record.state.lower()}.",
                    tenant_id=record.tenant_id,
                    target_type="enterprise", target_id=record.id,
                    event_type="enterprise.approval_decided",
                    template_vars={
                        "record_number": record.number, "decision": record.state.lower(),
                        "comments": approval.comments or f"Your record was {record.state.lower()}.",
                    },
                )
                log_history(
                    "enterprise", record.id, f"Approval {approval.state.lower()}",
                    details=approval.comments,
                )
                audit(action, record.number)
            db.session.commit()
            return redirect(url_for("enterprise_detail", record_id=record.id))
        agents = User.query.filter(User.role.in_(["agent", "manager", "admin", "superadmin"]), User.active.is_(True)).all()
        work_tasks = OperationalTask.query.filter_by(
            parent_type="enterprise", parent_id=record.id
        ).order_by(OperationalTask.sequence, OperationalTask.id).all()
        task_agents = {}
        task_permissions = {}
        for task in work_tasks:
            member_ids = {member.user_id for member in task.assignment_group.members}
            if task.assignment_group.manager_id:
                member_ids.add(task.assignment_group.manager_id)
            task_agents[task.id] = User.query.filter(
                User.id.in_(member_ids), User.active.is_(True),
                User.role.in_(["agent", "manager", "admin", "superadmin"]),
            ).order_by(User.name).all() if member_ids else []
            task_permissions[task.id] = user_in_group(current_user, task.assignment_group)
        return render_template(
            "enterprise_detail.html", record=record, config=DOMAIN_CONFIG[record.domain],
            state_track=build_state_track(record.domain, record.state),
            agents=agents, record_state_options=allowed_enterprise_states(record),
            related=related_records("enterprise", record.id), relation_labels=RELATION_LABELS,
            work_tasks=work_tasks, work_task_states=OPERATIONAL_TASK_TRANSITIONS,
            history=TaskHistory.query.filter_by(
                target_type="enterprise", target_id=record.id
            ).options(selectinload(TaskHistory.actor)).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all(),
            ci_links=TaskCI.query.filter_by(
                target_type="enterprise", target_id=record.id
            ).order_by(TaskCI.relationship_role).all(),
            teams=core.team_groups(record.tenant_id).all(),
            task_agents=task_agents, task_permissions=task_permissions,
            can_manage_record=can_manage_record,
        )

    @app.get("/known-errors")
    @roles("agent", "manager", "admin")
    def known_errors():
        """ITIL 4's Known Error Database, made real instead of just a flag on
        a problem record -- searchable, so an agent triaging a new incident
        can check "has this happened before" before starting from scratch."""
        q = request.args.get("q", "").strip()
        query = tenant_query(EnterpriseRecord).join(
            ProblemProfile, ProblemProfile.enterprise_record_id == EnterpriseRecord.id
        ).filter(
            EnterpriseRecord.domain == "problem", ProblemProfile.known_error.is_(True),
        )
        if q:
            like = f"%{q}%"
            query = query.filter(db.or_(
                EnterpriseRecord.title.ilike(like),
                ProblemProfile.root_cause.ilike(like),
                ProblemProfile.workaround.ilike(like),
            ))
        records = query.order_by(EnterpriseRecord.updated_at.desc()).all()
        return render_template("known_errors.html", records=records, q=q)

    @app.post("/problem/<int:record_id>/analysis")
    @roles("agent", "manager", "admin")
    def problem_analysis_update(record_id):
        record = tenant_record_or_404(EnterpriseRecord, record_id)
        if record.domain != "problem":
            abort(404)
        if not user_can_manage_enterprise_record(current_user, record):
            abort(403)
        profile = record.problem_profile
        if not profile:
            profile = ProblemProfile(enterprise_record_id=record.id)
            db.session.add(profile)
        before = {
            "known error": profile.known_error,
            "root cause": profile.root_cause,
            "workaround": profile.workaround,
            "permanent fix": profile.fix_notes,
            "primary CI": profile.primary_ci.name if profile.primary_ci else "",
        }
        ci_id = int(request.form["primary_ci_id"]) if request.form.get("primary_ci_id") else None
        selected_ci = (
            tenant_query(ConfigurationItem).filter(ConfigurationItem.id == ci_id).first()
            if ci_id else None
        )
        if ci_id and not selected_ci:
            abort(400)
        profile.known_error = bool(request.form.get("known_error"))
        profile.root_cause = request.form.get("root_cause", "").strip()
        profile.workaround = request.form.get("workaround", "").strip()
        profile.fix_notes = request.form.get("fix_notes", "").strip()
        profile.primary_ci_id = ci_id
        after = {
            "known error": profile.known_error,
            "root cause": profile.root_cause,
            "workaround": profile.workaround,
            "permanent fix": profile.fix_notes,
            "primary CI": selected_ci.name if selected_ci else "",
        }
        changed = log_field_changes(
            "enterprise", record.id, before, after, event="Problem analysis updated"
        )
        audit("update problem analysis", record.number, ", ".join(changed))
        db.session.commit()
        return redirect(url_for("enterprise_detail", record_id=record.id))

    @app.post("/problem/<int:record_id>/tasks")
    @roles("agent", "manager", "admin")
    def problem_task_add(record_id):
        record = tenant_record_or_404(EnterpriseRecord, record_id)
        if record.domain != "problem":
            abort(404)
        if not user_can_manage_enterprise_record(current_user, record):
            abort(403)
        group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
        if not core.is_team_group(group):
            abort(400, description=tr("Problem tasks require an active team."))
        sequence = OperationalTask.query.filter_by(
            parent_type="enterprise", parent_id=record.id
        ).count() + 1

        def build_task():
            task = OperationalTask(
                number=next_operational_task_number("problem"),
                task_kind="problem", parent_type="enterprise", parent_id=record.id,
                title=request.form["title"].strip(),
                task_type=request.form.get("task_type", "Investigation"),
                sequence=sequence,
                assignment_group_id=group.id,
                required=bool(request.form.get("required")),
            )
            db.session.add(task)
            return task
        task = create_with_retry_on_number_collision(build_task)
        log_history(
            "enterprise", record.id, "Problem task created",
            details=f"{task.number}: {task.title} → {group.name}",
        )
        audit("create", task.number, f"{record.number}: {task.title}")
        db.session.commit()
        return redirect(url_for("enterprise_detail", record_id=record.id))

    @app.get("/improvements")
    @roles("agent", "manager", "admin")
    def improvements():
        status_filter = request.args.get("status", "")
        query = tenant_query(ImprovementItem)
        if status_filter:
            if status_filter not in IMPROVEMENT_STATES:
                abort(400)
            query = query.filter_by(status=status_filter)
        items = query.order_by(ImprovementItem.created_at.desc()).all()
        return render_template(
            "improvements.html", items=items, status_filter=status_filter,
            states=IMPROVEMENT_STATES,
        )

    @app.post("/improvements/new")
    @roles("agent", "manager", "admin")
    def improvement_new():
        """Raised either standalone from the Improvements list, or via a
        "Raise improvement" quick-action on an incident/problem/change/event
        detail page (source_type/source_id then use the same (type, id)
        shape record_reference()/record_url() already understand)."""
        title = request.form.get("title", "").strip()
        if not title:
            abort(400, description=tr("A title is required."))
        source_type = request.form.get("source_type") or None
        source_id = request.form.get("source_id") or None
        def build():
            item = ImprovementItem(
                number=sequence_number(ImprovementItem, "IMP"),
                title=title[:200],
                description=request.form.get("description", "").strip(),
                expected_outcome=request.form.get("expected_outcome", "").strip(),
                source_type=source_type,
                source_id=int(source_id) if source_id else None,
                owner_id=current_user.id,
                created_by_id=current_user.id,
            )
            db.session.add(item)
            return item
        item = create_with_retry_on_number_collision(build)
        audit("create", item.number, item.title)
        db.session.commit()
        flash(tr("{number} raised as a continual-improvement item.", number=item.number), "success")
        redirect_to = request.form.get("redirect_to")
        if is_safe_internal_path(redirect_to):
            return redirect(redirect_to)
        return redirect(url_for("improvement_detail", item_id=item.id))

    @app.get("/improvement/<int:item_id>")
    @roles("agent", "manager", "admin")
    def improvement_detail(item_id):
        item = tenant_record_or_404(ImprovementItem, item_id)
        source = record_reference(item.source_type, item.source_id) if item.source_type and item.source_id else None
        agents = tenant_query(User).filter(
            User.role.in_(["agent", "manager", "admin", "superadmin"]), User.active.is_(True)
        ).order_by(User.name).all()
        return render_template(
            "improvement_detail.html", item=item, states=IMPROVEMENT_STATES,
            source_url=record_url(source) if source else None,
            source_label=f"{record_number(source)} · {record_title(source)}" if source else None,
            agents=agents,
        )

    @app.post("/improvement/<int:item_id>")
    @roles("agent", "manager", "admin")
    def improvement_update(item_id):
        item = tenant_record_or_404(ImprovementItem, item_id)
        new_status = request.form.get("status", item.status)
        if new_status not in IMPROVEMENT_STATES:
            abort(400)
        before = {"status": item.status, "owner": item.owner.name if item.owner else "Unassigned"}
        item.status = new_status
        item.expected_outcome = request.form.get("expected_outcome", item.expected_outcome)
        item.measured_result = request.form.get("measured_result", item.measured_result)
        owner_id = request.form.get("owner_id")
        item.owner_id = int(owner_id) if owner_id else None
        after = {
            "status": item.status,
            "owner": item.owner.name if item.owner else "Unassigned",
        }
        log_field_changes("improvement", item.id, before, after, event=f"{item.number} updated")
        audit("update", item.number, item.status)
        db.session.commit()
        flash(tr("{number} updated.", number=item.number), "success")
        return redirect(url_for("improvement_detail", item_id=item.id))

    @app.route("/tickets/import/rt", methods=["GET", "POST"])
    @roles("admin")
    def rt_import():
        if request.method == "POST":
            dry_run = bool(request.form.get("dry_run"))
            query = request.form.get("query", "").strip() or "id > 0"
            limit_raw = request.form.get("limit", "").strip()
            try:
                limit = int(limit_raw) if limit_raw else None
            except ValueError:
                limit = None
            if not setting_bool("RT_ENABLED"):
                flash(tr("RT import is not enabled."), "error")
                return redirect(url_for("rt_import"))
            # Enqueue only -- RT import can take many minutes against a real
            # (often slow) instance, and running it inline here routinely
            # exceeded gunicorn's worker timeout, which kills the whole
            # worker process (and every other in-flight request on it), not
            # just this one. The background worker does the actual work.
            job = RTImportJob(
                tenant_id=core.tenant_context_id(), actor_user_id=current_user.id,
                search_query=query, record_limit=limit, dry_run=dry_run,
            )
            db.session.add(job)
            audit("configure", "RT ticket import queued",
                  f"{'Preview' if dry_run else 'Apply'}: query={query!r}"
                  + (f" limit={limit}" if limit else ""))
            db.session.commit()
            flash(tr("RT import queued (job #{id}). This runs in the background.", id=job.id), "success")
            return redirect(url_for("rt_import"))
        recent_jobs = RTImportJob.query.filter_by(
            tenant_id=core.tenant_context_id()
        ).order_by(RTImportJob.id.desc()).limit(10).all()
        # B-322: RT connection settings (host/token/TLS) render directly on
        # this page instead of a separate administration settings page, so every
        # RT-related control lives in one place. Saving posts to the
        # existing system_settings_category("request_tracker_connection")
        # handler unchanged -- _admin_referrer_redirect there sends the
        # admin back here since this page is the referrer.
        rt_definitions = SETTING_DEFINITIONS["request_tracker_connection"]
        rt_values = {}
        for definition in rt_definitions:
            value = core.setting_value(definition["key"], definition.get("default", ""))
            rt_values[definition["key"]] = "" if definition["type"] == "secret" else value
            definition["configured"] = bool(value) if definition["type"] == "secret" else False
        return render_template(
            "rt_import.html", rt_enabled=setting_bool("RT_ENABLED"), recent_jobs=recent_jobs,
            rt_definitions=rt_definitions, rt_values=rt_values,
        )

    @app.post("/change/<int:ticket_id>/conflicts")
    @roles("agent", "manager", "admin")
    def detect_change_conflicts(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        require_ticket_team_access(ticket)
        governance = ticket.change_governance
        if not governance:
            abort(404)
        run_change_conflict_detection(ticket, governance)
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.get("/task-board")
    @login_required
    def task_board():
        scope = request.args.get("scope", "focus")
        if scope not in {"focus", "all"}:
            abort(400)
        priority_filter = request.args.get("priority", "")
        if priority_filter and priority_filter not in {"P1", "P2", "P3", "P4"}:
            abort(400)

        query = visible_tickets()
        if priority_filter:
            query = query.filter(Ticket.priority == priority_filter)

        current = now()
        focus_cutoff = current - timedelta(days=14)
        resolved_cutoff = current - timedelta(days=7)
        closed_cutoff = current - timedelta(days=2)
        lane_limit = 60 if scope == "focus" else 100
        at_risk_horizon = current + timedelta(hours=setting_int("SLA_AT_RISK_HOURS", 4))

        visible_ids = [row[0] for row in query.with_entities(Ticket.id).all()]
        active_slas = TaskSLA.query.filter(
            TaskSLA.target_type == "ticket",
            TaskSLA.target_id.in_(visible_ids or [-1]),
            TaskSLA.stage == "In Progress",
        ).order_by(TaskSLA.breach_at).all()
        sla_by_ticket = defaultdict(list)
        urgent_ticket_ids = set()
        for task_sla in active_slas:
            sla_by_ticket[task_sla.target_id].append(task_sla)
            breach_at = align_tz(task_sla.breach_at, current)
            if task_sla.breached or breach_at <= at_risk_horizon:
                urgent_ticket_ids.add(task_sla.target_id)

        priority_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
        sla_rank = {"breached": 0, "at-risk": 1, "healthy": 2, "none": 3}

        def board_sla(ticket):
            rows = sla_by_ticket.get(ticket.id, [])
            if not rows:
                return {"state": "none", "label": "No active SLA", "due": None}
            due = min(align_tz(row.breach_at, current) for row in rows)
            if any(row.breached or align_tz(row.breach_at, current) <= current for row in rows):
                state, label = "breached", "SLA exceeded"
            elif due <= at_risk_horizon:
                state, label = "at-risk", "SLA at risk"
            else:
                state, label = "healthy", "SLA on track"
            seconds = int((due - current).total_seconds())
            magnitude = abs(seconds)
            if magnitude < 3600:
                amount = f"{max(1, magnitude // 60)}m"
            elif magnitude < 86400:
                amount = f"{max(1, magnitude // 3600)}h"
            else:
                amount = f"{max(1, magnitude // 86400)}d"
            return {
                "state": state, "label": label,
                "due": f"{amount} overdue" if seconds < 0 else f"{amount} remaining",
            }

        tickets_by_state = {}
        board_meta = {}
        ticket_sla = {}
        for state in ["New", "In Progress", "Pending", "Resolved", "Closed"]:
            state_query = query.filter_by(state=state)
            if state == "Resolved":
                state_query = state_query.filter(Ticket.updated_at >= resolved_cutoff)
            elif state == "Closed":
                state_query = state_query.filter(Ticket.updated_at >= closed_cutoff)
            elif scope == "focus":
                state_query = state_query.filter(or_(
                    Ticket.priority.in_(["P1", "P2"]),
                    Ticket.id.in_(urgent_ticket_ids or [-1]),
                    Ticket.assignee_id == current_user.id,
                    Ticket.updated_at >= focus_cutoff,
                ))
            lane_tickets = state_query.options(selectinload(Ticket.assignee)).all()
            for ticket in lane_tickets:
                ticket_sla[ticket.id] = board_sla(ticket)
            lane_tickets.sort(key=lambda ticket: (
                sla_rank[ticket_sla[ticket.id]["state"]],
                priority_rank.get(ticket.priority, 9),
                -align_tz(ticket.updated_at, current).timestamp(),
            ))
            total = len(lane_tickets)
            tickets_by_state[state] = lane_tickets[:lane_limit]
            board_meta[state] = {"total": total, "hidden": max(0, total - lane_limit)}
        manageable_ticket_ids = {
            ticket.id for tickets in tickets_by_state.values() for ticket in tickets
            if user_can_manage_ticket(current_user, ticket)
        }
        return render_template(
            "task_board.html", tickets_by_state=tickets_by_state,
            manageable_ticket_ids=manageable_ticket_ids,
            ticket_sla=ticket_sla, board_meta=board_meta,
            scope=scope, priority_filter=priority_filter,
        )

    @app.post("/task-board/<int:ticket_id>/move")
    @roles("agent", "manager", "admin")
    def task_board_move(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        require_ticket_team_access(ticket)
        state = request.form.get("state")
        if state not in ("New", "In Progress", "Pending", "Resolved", "Closed"):
            abort(400)
        previous_state = ticket.state
        try:
            require_resolution_notes(ticket, state)
            transition_ticket(ticket, state)
        except HTTPException as error:
            db.session.rollback()
            return jsonify({"error": error.description}), error.code
        if previous_state != ticket.state:
            log_history(
                "ticket", ticket.id, "Board state changed",
                "state", previous_state, ticket.state,
            )
        audit("board move", ticket.number, state)
        db.session.commit()
        return jsonify(project_document(
            "ui_action_ack", current_user.effective_role, {"state": state}
        ))

    @app.post("/ticket/<int:ticket_id>/checklist")
    @roles("agent", "manager", "admin")
    def checklist_add(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        require_ticket_team_access(ticket)
        if not require_ticket_not_locked(ticket):
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        text = request.form.get("text", "").strip()
        if text:
            position = ChecklistItem.query.filter_by(ticket_id=ticket_id).count()
            db.session.add(ChecklistItem(ticket_id=ticket_id, text=text[:300], position=position))
            log_history(
                "ticket", ticket.id, "Checklist item added",
                details=text[:300],
            )
            db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.post("/checklist/<int:item_id>/toggle")
    @roles("agent", "manager", "admin")
    def checklist_toggle(item_id):
        item = db.get_or_404(ChecklistItem, item_id)
        ticket = tenant_record_or_404(Ticket, item.ticket_id)
        require_ticket_team_access(ticket)
        if not require_ticket_not_locked(ticket):
            return redirect(url_for("ticket_detail", ticket_id=item.ticket_id))
        item.completed = not item.completed
        log_history(
            "ticket", ticket.id, "Checklist item updated",
            item.text, not item.completed, item.completed,
        )
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=item.ticket_id))

    @app.post("/ticket/<int:ticket_id>/attachments")
    @login_required
    def attachment_upload(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if not user_can_view_ticket(current_user, ticket):
            abort(403)
        upload = request.files.get("file")
        attachment, error = save_ticket_attachment(ticket, upload)
        if error:
            flash(error, "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        log_history(
            "ticket", ticket.id, "Attachment uploaded",
            details=f"{attachment.original_name} ({attachment.size_bytes} bytes)",
        )
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.post("/attachments/<int:attachment_id>/delete")
    @login_required
    def attachment_delete(attachment_id):
        attachment = db.get_or_404(FileAttachment, attachment_id)
        if attachment.ticket_id is None:
            abort(404)
        if not user_can_delete_attachment(current_user, attachment):
            abort(403, description=tr("You do not have permission to delete this attachment."))
        ticket_id, name = attachment.ticket_id, attachment.original_name
        stored_name, reference = attachment.stored_name, attachment.ipfs_cid or attachment.stored_name
        log_history("ticket", ticket_id, "Attachment deleted", details=f"{name} ({attachment.size_bytes} bytes)")
        audit("attach-delete", attachment.ticket.number, name)
        db.session.delete(attachment)
        db.session.commit()
        # Only after the record is gone, so a failed commit never loses the file.
        try:
            current_storage().delete_file(stored_name, reference)
        except Exception:  # noqa: BLE001 - the record is already removed; keep the response clean
            current_app.logger.warning("Stored file for deleted attachment could not be removed: %s", stored_name)
        flash(tr("{name} was deleted.", name=name), "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id) + "#attachments")

    @app.get("/attachments/<int:attachment_id>")
    @login_required
    def attachment_download(attachment_id):
        attachment = db.get_or_404(FileAttachment, attachment_id)
        if attachment.enterprise_record_id:
            if not user_can_view_enterprise_record(current_user, attachment.enterprise_record):
                abort(403)
        elif attachment.client_ticket_id:
            if not visible_client_ticket_query(current_user).filter_by(id=attachment.client_ticket_id).first():
                abort(404)
        elif not user_can_view_ticket(current_user, attachment.ticket):
            abort(403)
        # Only the handful of types a browser renders safely natively
        # (never HTML/SVG, which could execute script if opened inline)
        # are ever served inline. The shared response path also powers the
        # authenticated mobile download API.
        return attachment_file_response(
            attachment, inline=request.args.get("view") == "1",
        )
