"""Client management (external customer support) routes.

Moved from app.create_app(); endpoint names are unchanged."""
import json
import re
from datetime import timedelta

from flask import abort, current_app, flash, redirect, render_template, request, Response, url_for
from flask_login import current_user
from sqlalchemy import func
from sqlalchemy.orm import selectinload

from app import (
    _poll_client_mailbox,
    apply_filter_conditions,
    attach_slas,
    audit,
    CLIENT_CUSTOM_FIELD_ENTITY_TYPES,
    CLIENT_CUSTOM_FIELD_TYPES,
    client_custom_fields_for,
    create_with_retry_on_number_collision,
    deliver_client_email_reply,
    erase_client_contact,
    evaluate_client_triggers,
    parse_client_custom_field_values,
    parse_list_filter_param,
    require_client_management,
    role_at_least,
    sequence_number,
    sync_slas,
    team_groups,
    tenant_query,
    tenant_record_or_404,
    visible_client_contact_query,
    visible_client_organization_query,
    visible_client_ticket_query,
)
from serviceops_core.client_automation import (
    CLIENT_TICKET_PRIORITIES,
    CLIENT_TICKET_STATUSES,
    CLIENT_TRIGGER_ACTION_TYPES,
    CLIENT_TRIGGER_EVENTS,
    CLIENT_TRIGGER_FIELDS,
    CLIENT_TRIGGER_OPERATORS,
    ClientTriggerConfigurationError,
    validate_trigger,
)
from serviceops_core.web.common import (
    client_ticket_filter_field_spec,
    CLIENT_VIEW_SORT_COLUMNS,
    client_workspace_context,
    visible_client_views,
)
from serviceops_models import (
    ClientContact,
    ClientCustomFieldDefinition,
    ClientMacro,
    ClientMailbox,
    ClientOrganization,
    ClientOrganizationAccess,
    ClientTicket,
    ClientTicketMessage,
    ClientTrigger,
    ClientView,
    db,
    now,
    SupportGroup,
    User,
)
from serviceops_core.localization import tr, tr_value


def register(app):
    @app.get("/client-management")
    @require_client_management
    def client_management_home():
        query = visible_client_ticket_query(current_user)
        counts = {
            "mine": query.filter(ClientTicket.assignee_id == current_user.id, ClientTicket.status.notin_(["Solved", "Closed"])).count(),
            "unassigned": query.filter(ClientTicket.assignee_id.is_(None), ClientTicket.status.notin_(["Solved", "Closed"])).count(),
            "unsolved": query.filter(ClientTicket.status.notin_(["Solved", "Closed"])).count(),
            "pending": query.filter(ClientTicket.status == "Pending").count(),
            "recent": query.filter(ClientTicket.updated_at >= now() - timedelta(days=7)).count(),
            "solved": query.filter(ClientTicket.status == "Solved").count(),
        }
        recent = query.options(
            selectinload(ClientTicket.contact), selectinload(ClientTicket.assignee),
            selectinload(ClientTicket.organization),
        ).order_by(ClientTicket.updated_at.desc()).limit(8).all()
        return render_template("client_management_home.html", counts=counts, recent=recent)

    @app.get("/client-management/tickets")
    @require_client_management
    def client_tickets():
        q = request.args.get("q", "").strip()
        view_id = request.args.get("view_id", type=int)
        active_view = None
        if view_id:
            active_view = ClientView.query.filter(
                ClientView.id == view_id, ClientView.tenant_id == current_user.tenant_id,
                db.or_(ClientView.created_by_id == current_user.id, ClientView.shared.is_(True)),
            ).first()
        query = visible_client_ticket_query(current_user).options(
            selectinload(ClientTicket.contact), selectinload(ClientTicket.assignee),
            selectinload(ClientTicket.organization),
        )
        if active_view:
            view = None
            raw_filter = active_view.conditions_json
            sort_field, sort_dir = active_view.sort_field, active_view.sort_dir
        else:
            view = request.args.get("view", "unsolved")
            raw_filter = request.args.get("filter", "")
            sort_field, sort_dir = "updated", "desc"
            if view == "mine":
                query = query.filter(ClientTicket.assignee_id == current_user.id, ClientTicket.status.notin_(["Solved", "Closed"]))
            elif view == "unassigned":
                query = query.filter(ClientTicket.assignee_id.is_(None), ClientTicket.status.notin_(["Solved", "Closed"]))
            elif view == "pending":
                query = query.filter(ClientTicket.status == "Pending")
            elif view == "recent":
                query = query.filter(ClientTicket.updated_at >= now() - timedelta(days=7))
            elif view == "solved":
                query = query.filter(ClientTicket.status.in_(["Solved", "Closed"]))
            else:
                view = "unsolved"
                query = query.filter(ClientTicket.status.notin_(["Solved", "Closed"]))
        conditions = parse_list_filter_param(raw_filter)
        field_spec = client_ticket_filter_field_spec()
        query = apply_filter_conditions(query, conditions, field_spec)
        if q:
            query = query.join(ClientContact).join(ClientOrganization).filter(db.or_(
                ClientTicket.number.ilike(f"%{q}%"), ClientTicket.subject.ilike(f"%{q}%"),
                ClientContact.name.ilike(f"%{q}%"), ClientContact.email.ilike(f"%{q}%"),
                ClientOrganization.name.ilike(f"%{q}%"),
            ))
        sort_column = CLIENT_VIEW_SORT_COLUMNS.get(sort_field, ClientTicket.updated_at)
        order = sort_column.asc() if sort_dir == "asc" else sort_column.desc()
        tickets = query.order_by(order).limit(250).all()
        client_fields = {
            key: {"label": tr_value(spec["label"]), "type": spec["type"],
                  "options": [(value, tr_value(label)) for value, label in spec.get("options", [])]}
            for key, spec in field_spec.items()
        }
        return render_template(
            "client_tickets.html", tickets=tickets, view=view, q=q,
            raw_filter=raw_filter, filter_fields=client_fields,
            views=visible_client_views(current_user), active_view=active_view,
            sort_field=sort_field, sort_dir=sort_dir,
        )

    @app.post("/client-management/views")
    @require_client_management
    def client_view_create():
        name = request.form.get("name", "").strip()
        raw_conditions = request.form.get("conditions_json", "[]")
        conditions = parse_list_filter_param(raw_conditions)
        sort_field = request.form.get("sort_field", "updated")
        if sort_field not in CLIENT_VIEW_SORT_COLUMNS:
            sort_field = "updated"
        sort_dir = request.form.get("sort_dir", "desc")
        if sort_dir not in ("asc", "desc"):
            sort_dir = "desc"
        if not name:
            flash(tr("Name your view before saving it."), "error")
        elif ClientView.query.filter_by(
            tenant_id=current_user.tenant_id, created_by_id=current_user.id, name=name
        ).first():
            flash(tr("You already have a view with that name."), "error")
        else:
            db.session.add(ClientView(
                tenant_id=current_user.tenant_id, name=name, created_by_id=current_user.id,
                shared=bool(request.form.get("shared")), conditions_json=json.dumps(conditions),
                sort_field=sort_field, sort_dir=sort_dir,
            ))
            audit("client view created", name, "shared" if request.form.get("shared") else "private")
            db.session.commit()
            flash(tr("View \"{name}\" saved.", name=name), "success")
        return redirect(url_for("client_tickets"))

    @app.post("/client-management/views/<int:view_id>/delete")
    @require_client_management
    def client_view_delete(view_id):
        view = ClientView.query.filter_by(id=view_id, tenant_id=current_user.tenant_id).first_or_404()
        if view.created_by_id != current_user.id and not role_at_least(current_user.effective_role, "admin"):
            abort(403, description=tr("Only the view's creator or an admin can delete it."))
        name = view.name
        db.session.delete(view)
        audit("client view deleted", name, "")
        db.session.commit()
        flash(tr("View \"{name}\" deleted.", name=name), "success")
        return redirect(url_for("client_tickets"))

    @app.route("/client-management/tickets/new", methods=["GET", "POST"])
    @require_client_management
    def client_ticket_new():
        group, agents = client_workspace_context()
        if not group:
            abort(409, description=tr("The SysOps client-support team is not configured."))
        contacts = visible_client_contact_query(current_user).filter_by(active=True).options(selectinload(ClientContact.organization)).order_by(ClientContact.name).all()
        if request.method == "POST":
            contact = visible_client_contact_query(current_user).filter_by(id=request.form.get("contact_id", type=int), active=True).first_or_404()
            subject = request.form.get("subject", "").strip()
            description = request.form.get("description", "").strip()
            resolved_fields = client_custom_fields_for("client_ticket", organization=contact.organization)
            custom_values, custom_error = parse_client_custom_field_values(resolved_fields, request.form)
            if not subject or not description:
                flash(tr("Subject and description are required."), "error")
            elif custom_error:
                flash(custom_error, "error")
            else:
                agent_ids = {agent.id for agent in agents}
                assignee_id = request.form.get("assignee_id", type=int)
                if assignee_id not in agent_ids:
                    assignee_id = None

                def build_client_ticket():
                    row = ClientTicket(
                        number=sequence_number(ClientTicket, "CXT"), tenant_id=current_user.tenant_id,
                        subject=subject, description=description,
                        status="New", priority=request.form.get("priority") if request.form.get("priority") in ["Low", "Normal", "High", "Urgent"] else "Normal",
                        ticket_type=request.form.get("ticket_type") if request.form.get("ticket_type") in ["Question", "Incident", "Problem", "Task"] else "Question",
                        channel=request.form.get("channel") if request.form.get("channel") in ["Web", "Email", "Phone", "Chat"] else "Web",
                        tags=request.form.get("tags", "").strip()[:500], custom_fields=custom_values,
                        contact_id=contact.id,
                        organization_id=contact.organization_id, assignee_id=assignee_id,
                        support_group_id=group.id, created_by_id=current_user.id,
                    )
                    db.session.add(row)
                    return row

                ticket = create_with_retry_on_number_collision(build_client_ticket, error_description="Could not allocate a client ticket number; please try again.")
                db.session.add(ClientTicketMessage(
                    tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                    author_id=current_user.id, body=description, visibility="public", event_type="opened",
                ))
                evaluate_client_triggers("created", ticket, agents)
                attach_slas("client_ticket", ticket.id, ticket.priority, organization_id=ticket.organization_id)
                audit("client ticket created", ticket.number, f"Customer {contact.email}; organization {contact.organization.name}")
                db.session.commit()
                return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
        ticket_fields = client_custom_fields_for("client_ticket")
        return render_template("client_ticket_form.html", contacts=contacts, agents=agents, ticket_fields=ticket_fields)

    @app.route("/client-management/tickets/<int:ticket_id>", methods=["GET", "POST"])
    @require_client_management
    def client_ticket_detail(ticket_id):
        ticket = visible_client_ticket_query(current_user).options(
            selectinload(ClientTicket.messages).selectinload(ClientTicketMessage.author),
            selectinload(ClientTicket.contact), selectinload(ClientTicket.organization),
            selectinload(ClientTicket.assignee),
        ).filter_by(id=ticket_id).first_or_404()
        group, agents = client_workspace_context()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "reply":
                body = request.form.get("body", "").strip()
                visibility = request.form.get("visibility", "public")
                if visibility not in ("public", "internal"):
                    abort(400)
                if not body:
                    flash(tr("Enter a reply or internal note."), "error")
                else:
                    reply_message = ClientTicketMessage(
                        tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                        author_id=current_user.id, body=body, visibility=visibility,
                    )
                    db.session.add(reply_message)
                    db.session.flush()
                    if visibility == "public":
                        # Prefer the mailbox the ticket actually came in on
                        # (or has since been replying through) so a reply
                        # never goes out from an unrelated mailbox just
                        # because it happens to be the first active one for
                        # the tenant. Manually-created tickets have no
                        # mailbox_id, so fall back to the tenant's sole
                        # active mailbox in that case only.
                        mailbox = ticket.mailbox if ticket.mailbox and ticket.mailbox.active else None
                        if not mailbox and not ticket.mailbox_id:
                            mailbox = ClientMailbox.query.filter_by(
                                tenant_id=ticket.tenant_id, active=True
                            ).first()
                        if mailbox:
                            try:
                                deliver_client_email_reply(ticket, reply_message, mailbox)
                            except Exception:
                                # A delivery failure must never lose the reply itself --
                                # it's already saved and visible in-app either way; only
                                # the "also emailed to the customer" half failed.
                                current_app.logger.exception(
                                    "Failed to email client ticket reply: ticket=%s", ticket.number,
                                )
                                flash(
                                    tr("Reply saved, but sending it by email failed -- check the mailbox configuration."),
                                    "error",
                                )
                        else:
                            current_app.logger.warning(
                                "No active mailbox available to email reply for ticket=%s", ticket.number,
                            )
                            flash(
                                tr("Reply saved, but no active mailbox is configured -- the customer was not emailed."),
                                "error",
                            )
                    ticket.updated_at = now()
                    audit("client ticket message", ticket.number, visibility)
                    db.session.commit()
                    return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
            elif action == "update":
                old_status = ticket.status
                status = request.form.get("status")
                priority = request.form.get("priority")
                ticket_type = request.form.get("ticket_type")
                if status not in ["New", "Open", "Pending", "On-hold", "Solved", "Closed"]:
                    abort(400)
                if priority not in ["Low", "Normal", "High", "Urgent"] or ticket_type not in ["Question", "Incident", "Problem", "Task"]:
                    abort(400)
                resolved_fields = client_custom_fields_for("client_ticket", organization=ticket.organization)
                custom_values, custom_error = parse_client_custom_field_values(resolved_fields, request.form)
                if custom_error:
                    flash(custom_error, "error")
                    return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
                ticket.custom_fields = custom_values
                agent_ids = {agent.id for agent in agents}
                assignee_id = request.form.get("assignee_id", type=int)
                ticket.assignee_id = assignee_id if assignee_id in agent_ids else None
                ticket.status, ticket.priority, ticket.ticket_type = status, priority, ticket_type
                ticket.tags = request.form.get("tags", "").strip()[:500]
                ticket.solved_at = now() if status == "Solved" and old_status != "Solved" else (None if status not in ["Solved", "Closed"] else ticket.solved_at)
                if old_status != status:
                    db.session.add(ClientTicketMessage(
                        tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                        author_id=current_user.id, body=f"Status changed from {old_status} to {status}.",
                        visibility="internal", event_type="status",
                    ))
                    evaluate_client_triggers("status_changed", ticket, agents)
                    sync_slas("client_ticket", ticket.id, ticket.status)
                evaluate_client_triggers("updated", ticket, agents)
                audit("client ticket updated", ticket.number, f"Status {old_status} -> {status}")
                db.session.commit()
                return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
            elif action == "apply_macro":
                macro = tenant_query(ClientMacro).filter_by(
                    id=request.form.get("macro_id", type=int), active=True
                ).first_or_404()
                try:
                    macro_actions = json.loads(macro.actions_json or "{}")
                except (TypeError, ValueError):
                    macro_actions = {}
                old_status = ticket.status
                if "status" in macro_actions and macro_actions["status"] in ["New", "Open", "Pending", "On-hold", "Solved", "Closed"]:
                    ticket.status = macro_actions["status"]
                if "priority" in macro_actions and macro_actions["priority"] in ["Low", "Normal", "High", "Urgent"]:
                    ticket.priority = macro_actions["priority"]
                if "ticket_type" in macro_actions and macro_actions["ticket_type"] in ["Question", "Incident", "Problem", "Task"]:
                    ticket.ticket_type = macro_actions["ticket_type"]
                if "tags" in macro_actions:
                    ticket.tags = str(macro_actions["tags"])[:500]
                if "assignee_id" in macro_actions:
                    agent_ids = {agent.id for agent in agents}
                    macro_assignee_id = macro_actions["assignee_id"]
                    ticket.assignee_id = macro_assignee_id if macro_assignee_id in agent_ids else None
                if ticket.status == "Solved" and old_status != "Solved":
                    ticket.solved_at = now()
                elif ticket.status not in ("Solved", "Closed"):
                    ticket.solved_at = None
                if old_status != ticket.status:
                    db.session.add(ClientTicketMessage(
                        tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                        author_id=current_user.id, body=f"Status changed from {old_status} to {ticket.status}.",
                        visibility="internal", event_type="status",
                    ))
                    evaluate_client_triggers("status_changed", ticket, agents)
                    sync_slas("client_ticket", ticket.id, ticket.status)
                if macro.reply_body:
                    db.session.add(ClientTicketMessage(
                        tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                        author_id=current_user.id, body=macro.reply_body,
                        visibility=macro.reply_visibility if macro.reply_visibility in ("public", "internal") else "public",
                    ))
                evaluate_client_triggers("updated", ticket, agents)
                ticket.updated_at = now()
                audit("client macro applied", ticket.number, macro.name)
                db.session.commit()
                flash(tr("Applied \"{name}\".", name=macro.name), "success")
                return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
        ticket_fields = client_custom_fields_for("client_ticket", organization=ticket.organization)
        macros = tenant_query(ClientMacro).filter_by(active=True).order_by(ClientMacro.name).all()
        return render_template(
            "client_ticket_detail.html", ticket=ticket, agents=agents, ticket_fields=ticket_fields, macros=macros,
            branding=(ticket.organization.settings or {}).get("branding", {}),
        )

    @app.route("/client-management/organizations", methods=["GET", "POST"])
    @require_client_management
    def client_organizations():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            if not name:
                flash(tr("Organization name is required."), "error")
            elif tenant_query(ClientOrganization).filter(func.lower(ClientOrganization.name) == name.lower()).first():
                flash(tr("That client organization already exists."), "error")
            else:
                row = ClientOrganization(
                    tenant_id=current_user.tenant_id, name=name,
                    domain=request.form.get("domain", "").strip().lower(),
                    external_id=request.form.get("external_id", "").strip() or None,
                    notes=request.form.get("notes", "").strip(),
                )
                db.session.add(row)
                audit("client organization created", name)
                db.session.commit()
                return redirect(url_for("client_organizations"))
        rows = visible_client_organization_query(current_user).options(selectinload(ClientOrganization.contacts)).order_by(ClientOrganization.name).all()
        return render_template("client_organizations.html", organizations=rows)

    @app.route("/client-management/organizations/<int:organization_id>", methods=["GET", "POST"])
    @require_client_management
    def client_organization_detail(organization_id):
        organization = visible_client_organization_query(current_user).options(
            selectinload(ClientOrganization.contacts), selectinload(ClientOrganization.access_grants),
        ).filter_by(id=organization_id).first_or_404()
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description=tr("Only an administrator can change organization visibility or access grants."))
            action = request.form.get("action")
            if action == "toggle_restricted":
                organization.restricted_visibility = not organization.restricted_visibility
                audit(
                    "client organization visibility", organization.name,
                    "Restricted" if organization.restricted_visibility else "Open to all SysOps members",
                )
                db.session.commit()
                flash(
                    tr("{name} is now {value}.", name=organization.name, value='restricted to explicitly granted users/teams' if organization.restricted_visibility else 'visible to every SysOps member'),
                    "success",
                )
            elif action == "add_grant":
                grantee = request.form.get("grantee", "")
                kind, _, raw_id = grantee.partition(":")
                try:
                    grantee_id = int(raw_id)
                except (TypeError, ValueError):
                    abort(400, description=tr("Select a valid user or team."))
                if kind == "user":
                    user_row = tenant_record_or_404(User, grantee_id)
                    existing = ClientOrganizationAccess.query.filter_by(
                        organization_id=organization.id, user_id=user_row.id
                    ).first()
                    if not existing:
                        db.session.add(ClientOrganizationAccess(
                            tenant_id=current_user.tenant_id, organization_id=organization.id,
                            user_id=user_row.id, updated_by_id=current_user.id,
                        ))
                        audit("client organization access granted", organization.name, f"user {user_row.username}")
                        db.session.commit()
                elif kind == "group":
                    group_row = tenant_record_or_404(SupportGroup, grantee_id)
                    existing = ClientOrganizationAccess.query.filter_by(
                        organization_id=organization.id, group_id=group_row.id
                    ).first()
                    if not existing:
                        db.session.add(ClientOrganizationAccess(
                            tenant_id=current_user.tenant_id, organization_id=organization.id,
                            group_id=group_row.id, updated_by_id=current_user.id,
                        ))
                        audit("client organization access granted", organization.name, f"team {group_row.name}")
                        db.session.commit()
                else:
                    abort(400, description=tr("Select a valid user or team."))
                flash(tr("Access grant added."), "success")
            elif action == "remove_grant":
                grant = ClientOrganizationAccess.query.filter_by(
                    id=request.form.get("grant_id", type=int), organization_id=organization.id,
                ).first_or_404()
                label = grant.user.username if grant.user_id else grant.group.name
                db.session.delete(grant)
                audit("client organization access revoked", organization.name, label)
                db.session.commit()
                flash(tr("Access grant removed."), "success")
            elif action == "update_custom_fields":
                org_fields = client_custom_fields_for("organization")
                values, error = parse_client_custom_field_values(org_fields, request.form)
                if error:
                    flash(error, "error")
                else:
                    organization.custom_fields = values
                    audit("client organization custom fields updated", organization.name, "")
                    db.session.commit()
                    flash(tr("Custom fields saved."), "success")
            elif action == "update_field_overrides":
                ticket_field_defs = tenant_query(ClientCustomFieldDefinition).filter_by(
                    entity_type="client_ticket", active=True,
                ).all()
                overrides = dict(organization.settings or {})
                field_overrides = {}
                for field in ticket_field_defs:
                    visible = request.form.get(f"visible__{field.key}") == "on"
                    required = request.form.get(f"required__{field.key}") == "on"
                    if not visible or required != field.required:
                        field_overrides[field.key] = {"visible": visible, "required": required}
                overrides["custom_field_overrides"] = field_overrides
                organization.settings = overrides
                audit("client organization field overrides updated", organization.name, "")
                db.session.commit()
                flash(tr("Ticket field overrides saved."), "success")
            elif action == "update_branding":
                # This app has no real multi-domain/multi-portal hosting --
                # "branding per organization" is scoped honestly to what
                # actually renders: a display name/accent color/logo shown
                # on that organization's own tickets, not a separate
                # branded site.
                settings = dict(organization.settings or {})
                settings["branding"] = {
                    "display_name": request.form.get("display_name", "").strip()[:180],
                    "color": request.form.get("color", "").strip()[:20],
                }
                organization.settings = settings
                audit("client organization branding updated", organization.name, "")
                db.session.commit()
                flash(tr("Branding saved."), "success")
            elif action == "update_notification_policy":
                escalation_hours = request.form.get("escalation_hours", "").strip()
                escalation_group_id = request.form.get("escalation_group_id", "").strip()
                settings = dict(organization.settings or {})
                notification = {}
                if escalation_hours and escalation_group_id:
                    try:
                        hours_value = float(escalation_hours)
                    except ValueError:
                        flash(tr("Escalation hours must be a number."), "error")
                        return redirect(url_for("client_organization_detail", organization_id=organization.id))
                    tenant_record_or_404(SupportGroup, int(escalation_group_id))
                    notification = {"escalation_hours": hours_value, "escalation_group_id": int(escalation_group_id)}
                settings["notification"] = notification
                organization.settings = settings
                audit("client organization notification policy updated", organization.name, "")
                db.session.commit()
                flash(tr("Notification and escalation policy saved."), "success")
            return redirect(url_for("client_organization_detail", organization_id=organization.id))
        agents = User.query.filter(
            User.tenant_id == current_user.tenant_id, User.active.is_(True),
            User.role.in_(["agent", "manager", "admin"]),
        ).order_by(User.name).all()
        groups = team_groups().all()
        org_custom_fields = client_custom_fields_for("organization")
        ticket_field_defs = tenant_query(ClientCustomFieldDefinition).filter_by(
            entity_type="client_ticket", active=True,
        ).order_by(ClientCustomFieldDefinition.position, ClientCustomFieldDefinition.label).all()
        ticket_field_overrides = (organization.settings or {}).get("custom_field_overrides", {})
        return render_template(
            "client_organization_detail.html", organization=organization, agents=agents, groups=groups,
            is_admin=role_at_least(current_user.effective_role, "admin"),
            org_custom_fields=org_custom_fields, ticket_field_defs=ticket_field_defs,
            ticket_field_overrides=ticket_field_overrides,
            branding=(organization.settings or {}).get("branding", {}),
            notification_policy=(organization.settings or {}).get("notification", {}),
        )

    @app.route("/client-management/custom-fields", methods=["GET", "POST"])
    @require_client_management
    def client_custom_fields_admin():
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description=tr("Only an administrator can manage custom fields."))
            action = request.form.get("action", "create")
            if action == "create":
                entity_type = request.form.get("entity_type", "")
                key = request.form.get("key", "").strip().lower().replace(" ", "_")
                label = request.form.get("label", "").strip()
                field_type = request.form.get("field_type", "text")
                options_raw = request.form.get("options", "")
                if entity_type not in CLIENT_CUSTOM_FIELD_ENTITY_TYPES:
                    abort(400, description=tr("Select a valid entity type."))
                if field_type not in CLIENT_CUSTOM_FIELD_TYPES:
                    abort(400, description=tr("Select a valid field type."))
                if not key or not re.match(r"^[a-z][a-z0-9_]{0,58}[a-z0-9]$", key):
                    flash(tr("Field key must be lowercase letters, numbers, and underscores."), "error")
                elif not label:
                    flash(tr("Field label is required."), "error")
                elif tenant_query(ClientCustomFieldDefinition).filter_by(
                    entity_type=entity_type, key=key
                ).first():
                    flash(tr("A field with that key already exists for this record type."), "error")
                else:
                    options = [line.strip() for line in options_raw.splitlines() if line.strip()] if field_type == "select" else []
                    db.session.add(ClientCustomFieldDefinition(
                        tenant_id=current_user.tenant_id, entity_type=entity_type, key=key,
                        label=label, field_type=field_type, options_json=json.dumps(options),
                        required=bool(request.form.get("required")), created_by_id=current_user.id,
                    ))
                    audit("client custom field created", label, entity_type)
                    db.session.commit()
                    flash(tr("{label} added.", label=label), "success")
            elif action == "toggle_active":
                field = tenant_record_or_404(ClientCustomFieldDefinition, request.form.get("field_id", type=int))
                field.active = not field.active
                audit("client custom field toggled", field.label, "Active" if field.active else "Inactive")
                db.session.commit()
                flash(tr("{label} is now {value}.", label=field.label, value='active' if field.active else 'inactive'), "success")
            return redirect(url_for("client_custom_fields_admin"))
        fields_by_entity = {
            entity_type: tenant_query(ClientCustomFieldDefinition).filter_by(
                entity_type=entity_type
            ).order_by(ClientCustomFieldDefinition.position, ClientCustomFieldDefinition.label).all()
            for entity_type in CLIENT_CUSTOM_FIELD_ENTITY_TYPES
        }
        return render_template(
            "client_custom_fields_admin.html", fields_by_entity=fields_by_entity,
            entity_types=CLIENT_CUSTOM_FIELD_ENTITY_TYPES, field_types=CLIENT_CUSTOM_FIELD_TYPES,
        )

    @app.route("/client-management/macros", methods=["GET", "POST"])
    @require_client_management
    def client_macros_admin():
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description=tr("Only an administrator can manage macros."))
            action = request.form.get("action", "create")
            if action == "create":
                name = request.form.get("name", "").strip()
                if not name:
                    flash(tr("Macro name is required."), "error")
                elif tenant_query(ClientMacro).filter_by(name=name).first():
                    flash(tr("A macro with that name already exists."), "error")
                else:
                    actions = {}
                    status = request.form.get("macro_status", "")
                    if status and status in ["New", "Open", "Pending", "On-hold", "Solved", "Closed"]:
                        actions["status"] = status
                    priority = request.form.get("macro_priority", "")
                    if priority and priority in ["Low", "Normal", "High", "Urgent"]:
                        actions["priority"] = priority
                    ticket_type = request.form.get("macro_ticket_type", "")
                    if ticket_type and ticket_type in ["Question", "Incident", "Problem", "Task"]:
                        actions["ticket_type"] = ticket_type
                    tags = request.form.get("macro_tags", "").strip()
                    if tags:
                        actions["tags"] = tags[:500]
                    reply_body = request.form.get("reply_body", "").strip()
                    reply_visibility = request.form.get("reply_visibility", "public")
                    if reply_visibility not in ("public", "internal"):
                        reply_visibility = "public"
                    db.session.add(ClientMacro(
                        tenant_id=current_user.tenant_id, name=name, actions_json=json.dumps(actions),
                        reply_body=reply_body, reply_visibility=reply_visibility, created_by_id=current_user.id,
                    ))
                    audit("client macro created", name, "")
                    db.session.commit()
                    flash(tr("{name} added.", name=name), "success")
            elif action == "toggle_active":
                macro = tenant_record_or_404(ClientMacro, request.form.get("macro_id", type=int))
                macro.active = not macro.active
                audit("client macro toggled", macro.name, "Active" if macro.active else "Inactive")
                db.session.commit()
                flash(tr("{name} is now {value}.", name=macro.name, value='active' if macro.active else 'inactive'), "success")
            return redirect(url_for("client_macros_admin"))
        macros = tenant_query(ClientMacro).order_by(ClientMacro.name).all()
        macro_rows = []
        for macro in macros:
            try:
                actions = json.loads(macro.actions_json or "{}")
            except (TypeError, ValueError):
                actions = {}
            macro_rows.append({"macro": macro, "actions": actions})
        return render_template(
            "client_macros_admin.html", macro_rows=macro_rows,
            statuses=["New", "Open", "Pending", "On-hold", "Solved", "Closed"],
            priorities=["Low", "Normal", "High", "Urgent"],
            ticket_types=["Question", "Incident", "Problem", "Task"],
        )

    @app.route("/client-management/triggers", methods=["GET", "POST"])
    @require_client_management
    def client_triggers_admin():
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description=tr("Only an administrator can manage triggers."))
            action = request.form.get("action", "create")
            if action == "create":
                name = request.form.get("name", "").strip()
                event = request.form.get("event", "")
                condition_field = request.form.get("condition_field", "")
                condition_op = request.form.get("condition_op", "")
                condition_value = request.form.get("condition_value", "").strip()
                action_type = request.form.get("action_type", "")
                action_value = request.form.get("action_value", "").strip()
                if not name:
                    flash(tr("Trigger name is required."), "error")
                elif tenant_query(ClientTrigger).filter_by(name=name).first():
                    flash(tr("A trigger with that name already exists."), "error")
                else:
                    try:
                        validate_trigger(event, condition_field, condition_op, action_type, action_value)
                    except ClientTriggerConfigurationError as error:
                        flash(str(error), "error")
                    else:
                        max_position = db.session.query(
                            func.coalesce(func.max(ClientTrigger.position), -1)
                        ).filter(ClientTrigger.tenant_id == current_user.tenant_id, ClientTrigger.event == event).scalar()
                        db.session.add(ClientTrigger(
                            tenant_id=current_user.tenant_id, name=name, event=event,
                            condition_field=condition_field, condition_op=condition_op,
                            condition_value=condition_value, action_type=action_type,
                            action_value=action_value, position=max_position + 1,
                            created_by_id=current_user.id,
                        ))
                        audit("client trigger created", name, event)
                        db.session.commit()
                        flash(tr("{name} added.", name=name), "success")
            elif action == "toggle_active":
                trigger = tenant_record_or_404(ClientTrigger, request.form.get("trigger_id", type=int))
                trigger.active = not trigger.active
                audit("client trigger toggled", trigger.name, "Active" if trigger.active else "Inactive")
                db.session.commit()
                flash(tr("{name} is now {value}.", name=trigger.name, value='active' if trigger.active else 'inactive'), "success")
            return redirect(url_for("client_triggers_admin"))
        triggers = tenant_query(ClientTrigger).order_by(ClientTrigger.event, ClientTrigger.position).all()
        return render_template(
            "client_triggers_admin.html", triggers=triggers, events=CLIENT_TRIGGER_EVENTS,
            fields=CLIENT_TRIGGER_FIELDS, operators=CLIENT_TRIGGER_OPERATORS,
            action_types=CLIENT_TRIGGER_ACTION_TYPES, statuses=CLIENT_TICKET_STATUSES,
            priorities=CLIENT_TICKET_PRIORITIES,
            groups=team_groups().all(),
            agents=User.query.filter(
                User.tenant_id == current_user.tenant_id, User.active.is_(True),
                User.role.in_(["agent", "manager", "admin"]),
            ).order_by(User.name).all(),
        )

    @app.route("/client-management/mailboxes", methods=["GET", "POST"])
    @require_client_management
    def client_mailboxes_admin():
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description=tr("Only an administrator can manage mailboxes."))
            action = request.form.get("action", "create")
            if action == "create":
                name = request.form.get("name", "").strip()
                if not name:
                    flash(tr("Mailbox name is required."), "error")
                elif tenant_query(ClientMailbox).filter_by(name=name).first():
                    flash(tr("A mailbox with that name already exists."), "error")
                else:
                    default_org_id = request.form.get("default_organization_id", type=int)
                    if default_org_id:
                        tenant_record_or_404(ClientOrganization, default_org_id)
                    mailbox = ClientMailbox(
                        tenant_id=current_user.tenant_id, name=name,
                        imap_host=request.form.get("imap_host", "").strip(),
                        imap_port=request.form.get("imap_port", type=int) or 993,
                        imap_use_ssl=bool(request.form.get("imap_use_ssl")),
                        imap_username=request.form.get("imap_username", "").strip(),
                        imap_folder=request.form.get("imap_folder", "INBOX").strip() or "INBOX",
                        smtp_host=request.form.get("smtp_host", "").strip(),
                        smtp_port=request.form.get("smtp_port", type=int) or 587,
                        smtp_use_tls=bool(request.form.get("smtp_use_tls")),
                        smtp_username=request.form.get("smtp_username", "").strip(),
                        from_address=request.form.get("from_address", "").strip(),
                        from_name=request.form.get("from_name", "").strip(),
                        default_organization_id=default_org_id or None,
                        auto_create_organization_by_domain=bool(request.form.get("auto_create_organization_by_domain")),
                        created_by_id=current_user.id,
                    )
                    if request.form.get("imap_password"):
                        mailbox.imap_password = request.form["imap_password"]
                    if request.form.get("smtp_password"):
                        mailbox.smtp_password = request.form["smtp_password"]
                    db.session.add(mailbox)
                    audit("client mailbox created", name, mailbox.imap_host)
                    db.session.commit()
                    flash(tr("{name} added.", name=name), "success")
            elif action == "toggle_active":
                mailbox = tenant_record_or_404(ClientMailbox, request.form.get("mailbox_id", type=int))
                mailbox.active = not mailbox.active
                audit("client mailbox toggled", mailbox.name, "Active" if mailbox.active else "Inactive")
                db.session.commit()
                flash(tr("{name} is now {value}.", name=mailbox.name, value='active' if mailbox.active else 'inactive'), "success")
            elif action == "delete":
                mailbox = tenant_record_or_404(ClientMailbox, request.form.get("mailbox_id", type=int))
                name = mailbox.name
                db.session.delete(mailbox)
                audit("client mailbox deleted", name, "")
                db.session.commit()
                flash(tr("{name} removed.", name=name), "success")
            elif action == "poll_now":
                mailbox = tenant_record_or_404(ClientMailbox, request.form.get("mailbox_id", type=int))
                try:
                    count = _poll_client_mailbox(mailbox)
                    flash(tr("Checked {name}: {count} new ticket/message(s) created.", name=mailbox.name, count=count), "success")
                except Exception as error:
                    mailbox.last_polled_at = now()
                    mailbox.last_poll_status = "error"
                    mailbox.last_poll_error = str(error)[:2000]
                    db.session.commit()
                    flash(tr("Could not connect to {name}: {error}", name=mailbox.name, error=error), "error")
            return redirect(url_for("client_mailboxes_admin"))
        mailboxes = tenant_query(ClientMailbox).order_by(ClientMailbox.name).all()
        organizations = tenant_query(ClientOrganization).order_by(ClientOrganization.name).all()
        return render_template(
            "client_mailboxes_admin.html", mailboxes=mailboxes, organizations=organizations,
        )

    @app.route("/client-management/contacts", methods=["GET", "POST"])
    @require_client_management
    def client_contacts():
        organizations = visible_client_organization_query(current_user).filter_by(active=True).order_by(ClientOrganization.name).all()
        if request.method == "POST" and request.form.get("action") == "erase":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description=tr("Only an administrator can erase a client contact's personal data."))
            contact = tenant_record_or_404(ClientContact, request.form.get("contact_id", type=int))
            original_email = contact.email
            try:
                erase_client_contact(contact)
                db.session.commit()
                flash(tr("{original_email}'s personal data has been erased.", original_email=original_email), "success")
            except ValueError as error:
                db.session.rollback()
                flash(str(error), "error")
            return redirect(url_for("client_contacts"))
        if request.method == "POST":
            organization = visible_client_organization_query(current_user).filter_by(id=request.form.get("organization_id", type=int), active=True).first_or_404()
            name, email = request.form.get("name", "").strip(), request.form.get("email", "").strip().lower()
            if not name or not email or "@" not in email:
                flash(tr("A valid name and email address are required."), "error")
            elif tenant_query(ClientContact).filter(func.lower(ClientContact.email) == email).first():
                flash(tr("That client email address already exists."), "error")
            else:
                contact_fields = client_custom_fields_for("contact")
                custom_values, custom_error = parse_client_custom_field_values(contact_fields, request.form)
                if custom_error:
                    flash(custom_error, "error")
                    return redirect(url_for("client_contacts"))
                row = ClientContact(
                    tenant_id=current_user.tenant_id, organization_id=organization.id,
                    name=name, email=email, phone=request.form.get("phone", "").strip(),
                    job_title=request.form.get("job_title", "").strip(),
                    preferred_language=request.form.get("preferred_language", "English").strip() or "English",
                    custom_fields=custom_values,
                )
                db.session.add(row)
                audit("client contact created", email, organization.name)
                db.session.commit()
                return redirect(url_for("client_contacts"))
        contacts = visible_client_contact_query(current_user).options(selectinload(ClientContact.organization)).order_by(ClientContact.name).all()
        contact_fields = client_custom_fields_for("contact")
        return render_template(
            "client_contacts.html", contacts=contacts, organizations=organizations, contact_fields=contact_fields,
        )

    @app.get("/client-management/contacts/<int:contact_id>/export")
    @require_client_management
    def client_contact_export(contact_id):
        """GDPR Art. 20 (data portability) for a customer contact, mirroring
        profile_export() -- a structured, machine-readable export of this
        contact's own data and support conversation history."""
        contact = visible_client_contact_query(current_user).filter_by(id=contact_id).first_or_404()
        payload = {
            "name": contact.name, "email": contact.email, "phone": contact.phone,
            "job_title": contact.job_title, "preferred_language": contact.preferred_language,
            "organization": contact.organization.name if contact.organization else None,
            "created_at": contact.created_at.isoformat() if contact.created_at else None,
            "erased_at": contact.erased_at.isoformat() if contact.erased_at else None,
            "tickets": [
                {
                    "number": ticket.number, "subject": ticket.subject, "status": ticket.status,
                    "created_at": ticket.created_at.isoformat(),
                    "messages": [
                        {
                            "body": message.body, "visibility": message.visibility,
                            "created_at": message.created_at.isoformat(),
                        }
                        for message in ticket.messages if message.visibility == "public"
                    ],
                }
                for ticket in ClientTicket.query.filter_by(
                    tenant_id=contact.tenant_id, contact_id=contact.id,
                ).order_by(ClientTicket.created_at.desc()).all()
            ],
        }
        response = Response(
            json.dumps(payload, indent=2, sort_keys=True), mimetype="application/json",
        )
        response.headers["Content-Disposition"] = f'attachment; filename="client-contact-{contact.id}-data-export.json"'
        audit("export", contact.email, "Client contact data export (GDPR Art. 20)")
        db.session.commit()
        return response
