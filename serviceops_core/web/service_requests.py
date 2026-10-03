"""Service catalog, requests, RITMs, catalog tasks and approvals routes.

Moved from app.create_app(); endpoint names are unchanged."""
import csv
import io
import json
import re
from datetime import timedelta

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy.orm import selectinload
from werkzeug.exceptions import HTTPException

from app import (
    active_approval_delegation,
    approval_chain_for,
    attach_slas,
    audit,
    catalog_approval_stages,
    create_approval_chain,
    create_catalog_task,
    create_notification,
    create_with_retry_on_number_collision,
    csv_response,
    decide_vote,
    delegated_pending_votes,
    enforce_approval_change_freeze,
    log_field_changes,
    log_history,
    related_records,
    ritm_linked_change,
    role_at_least,
    roles,
    sequence_number,
    sync_slas,
    tenant_query,
    tenant_record_or_404,
    transition_catalog_task,
    user_can_add_request_item,
    user_can_manage_ritm,
    user_can_view_catalog_request,
    user_can_view_ticket,
    user_in_group,
    visible_catalog_request_query,
)
from serviceops_core.task_lifecycle import build_state_track, CATALOG_TASK_TRANSITIONS
from serviceops_core.web.common import user_can_view_catalog_task, usertime_filter
from serviceops_models import (
    Approval,
    ApprovalChain,
    ApprovalGate,
    ApprovalVote,
    CatalogItem,
    CatalogRequest,
    CatalogTask,
    CatalogTaskControl,
    db,
    EnterpriseRecord,
    now,
    RequestedItem,
    SupportGroup,
    TaskCI,
    TaskHistory,
    TaskNote,
    TaskSLA,
    Ticket,
    User,
)
from serviceops_core.localization import tr


def register(app):
    @app.get("/catalog")
    @login_required
    def catalog():
        return render_template(
            "catalog.html",
            items=tenant_query(CatalogItem).filter_by(active=True).order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
        )

    @app.post("/catalog/<int:item_id>/order")
    @login_required
    def catalog_order(item_id):
        item = tenant_record_or_404(CatalogItem, item_id)
        if not item.active:
            abort(404)
        approval_stages = None
        if item.approval_required:
            try:
                approval_stages = catalog_approval_stages(current_user)
            except ValueError as error:
                flash(
                    tr("{name} cannot be requested yet: {error} Contact an administrator.", name=item.name, error=error),
                    "error",
                )
                return redirect(url_for("catalog"))
        def build_req():
            req = CatalogRequest(number=sequence_number(CatalogRequest, "REQ"), requested_by_id=current_user.id,
                                 requested_for_id=current_user.id)
            db.session.add(req)
            return req
        req = create_with_retry_on_number_collision(build_req)

        def build_ritm():
            ritm = RequestedItem(number=sequence_number(RequestedItem, "RITM"), request_id=req.id,
                                 catalog_item_id=item.id, state="Awaiting Approval" if item.approval_required else "Open",
                                 stage="Approval" if item.approval_required else "Fulfillment",
                                 variables_json=json.dumps({"details": request.form.get("details", "")}),
                                 due_at=now() + timedelta(days=item.delivery_days), tenant_id=req.tenant_id)
            db.session.add(ritm)
            return ritm
        ritm = create_with_retry_on_number_collision(build_ritm)
        attach_slas("ritm", ritm.id, None)
        if item.approval_required:
            create_approval_chain(
                f"{ritm.number} service fulfillment", "ritm", ritm.id, approval_stages
            )
        else:
            create_catalog_task(ritm)
        log_history("request", req.id, "Request created", details=f"{req.number} created.")
        log_history(
            "ritm", ritm.id, "Requested item created",
            details=f"{ritm.number}: {item.name}",
        )
        audit("order", req.number, f"{ritm.number}: {item.name}")
        db.session.commit()
        flash(tr("{name} requested as {number} / {number2}.", name=item.name, number=req.number, number2=ritm.number), "success")
        return redirect(url_for("request_detail", request_id=req.id))

    @app.get("/approvals")
    @login_required
    def approvals():
        query = Approval.query.join(EnterpriseRecord).filter(
            EnterpriseRecord.tenant_id == current_user.tenant_id
        )
        if not role_at_least(current_user.effective_role, "admin"):
            query = query.filter_by(approver_id=current_user.id)
        return render_template("approvals.html", approvals=query.order_by(Approval.id.desc()).all())

    @app.post("/approval-votes/<int:vote_id>/decide")
    @login_required
    def approval_vote_decide(vote_id):
        vote = db.get_or_404(ApprovalVote, vote_id)
        if vote.gate.chain.tenant_id != current_user.tenant_id:
            abort(403)
        delegation = None
        if vote.approver_id != current_user.id:
            delegation = active_approval_delegation(vote.approver_id, current_user.id)
            if not delegation:
                abort(403)
            original_approver_id = vote.approver_id
            vote.approver_id = current_user.id
            vote.delegated_from_id = original_approver_id
        decision = request.form.get("decision")
        if decision not in ("Approved", "Rejected"):
            abort(400)
        enforce_approval_change_freeze(vote, decision, current_user.tenant_id)
        decide_vote(vote, decision, request.form.get("comments", "").strip())
        log_history(
            vote.gate.chain.target_type, vote.gate.chain.target_id,
            f"Approval {decision.lower()}",
            details=(
                f"{vote.gate.name} · {current_user.name}"
                f"{' acting for ' + vote.delegated_from.name if vote.delegated_from else ''}: "
                f"{request.form.get('comments', '').strip() or 'No decision comments'}"
            ),
        )
        audit(
            decision.lower(), vote.gate.chain.name,
            vote.gate.name + (
                f"; delegated from {vote.delegated_from.username}" if vote.delegated_from else ""
            ),
        )
        db.session.commit()
        destination = request.referrer
        if destination and destination.startswith(request.host_url):
            return redirect(destination)
        return redirect(url_for("approval_chains"))

    @app.get("/approval-chains")
    @login_required
    def approval_chains():
        chains = []
        for chain in tenant_query(ApprovalChain).order_by(
            ApprovalChain.created_at.desc()
        ).all():
            if role_at_least(current_user.effective_role, "admin") or any(
                vote.approver_id == current_user.id
                for gate in chain.gates for vote in gate.votes
            ):
                chains.append(chain)
            elif chain.target_type == "ticket":
                target = db.session.get(Ticket, chain.target_id)
                if target and user_can_view_ticket(current_user, target):
                    chains.append(chain)
            elif chain.target_type == "ritm":
                target = db.session.get(RequestedItem, chain.target_id)
                if target and user_can_view_catalog_request(current_user, target.request):
                    chains.append(chain)
        pending = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
            ApprovalVote.approver_id == current_user.id,
            ApprovalVote.state == "Requested",
            ApprovalChain.tenant_id == current_user.tenant_id,
        ).all()
        delegated_pending = delegated_pending_votes(current_user)
        visible_chain_ids = {chain.id for chain in chains}
        for vote in delegated_pending:
            if vote.gate.chain.id not in visible_chain_ids:
                chains.append(vote.gate.chain)
                visible_chain_ids.add(vote.gate.chain.id)
        # Visibility above is computed per-chain in Python (it depends on
        # vote membership and, for ticket/ritm targets, a separate
        # permission check against another table) rather than a single SQL
        # query, so search/pagination are applied to the already-materialized
        # list instead of pushed into the query -- consistent with keeping
        # that visibility logic exactly as it already is.
        q = request.args.get("q", "").strip()
        if q:
            needle = q.lower()
            chains = [
                chain for chain in chains
                if needle in chain.name.lower()
                or needle in f"{chain.target_type} #{chain.target_id}".lower()
            ]
        # A material change to an approved change ticket doesn't edit the old
        # ApprovalChain -- it creates a whole new one against the same
        # (target_type, target_id) (see create_approval_chain() call sites;
        # the change-reapproval path names each one "... vN" from
        # ChangeRevision.revision). Left flat, a single real approval
        # process shows up as several unrelated-looking rows (v3/v2/v1).
        # Group by target so the latest chain is the visible row and older
        # ones collapse into its history -- chains is already created_at
        # desc, so the first chain seen per target is the latest.
        groups_by_target = {}
        group_order = []
        for chain in chains:
            key = (chain.target_type, chain.target_id)
            if key not in groups_by_target:
                groups_by_target[key] = {
                    "target_type": chain.target_type, "target_id": chain.target_id,
                    "latest": chain, "history": [],
                }
                group_order.append(key)
            else:
                groups_by_target[key]["history"].append(chain)
        groups = [groups_by_target[key] for key in group_order]
        for group in groups:
            # Only strip the "... vN" reapproval-revision suffix (see the
            # change-authorization naming above) when there's real history
            # to justify it -- a lone chain keeps its exact stored name.
            if group["history"]:
                group["display_name"] = re.sub(r"\s+v\d+$", "", group["latest"].name)
            else:
                group["display_name"] = group["latest"].name
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = len(groups)
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        page_groups = groups[(page - 1) * per_page: page * per_page]
        return render_template(
            "approval_chains.html", groups=page_groups, pending=pending,
            delegated_pending=delegated_pending, q=q, page=page, pages=pages, total=total,
        )

    @app.get("/requests")
    @login_required
    def requests_list():
        query = visible_catalog_request_query(current_user)
        q = request.args.get("q", "").strip()
        if q:
            query = query.filter(CatalogRequest.number.ilike(f"%{q}%"))
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.options(
            db.joinedload(CatalogRequest.requested_for),
            selectinload(CatalogRequest.items).joinedload(RequestedItem.item),
        ).order_by(CatalogRequest.opened_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        return render_template(
            "requests.html", requests=rows, q=q, page=page, pages=pages, total=total,
        )

    @app.get("/requests/export.csv")
    @login_required
    def requests_export():
        query = visible_catalog_request_query(current_user)
        q = request.args.get("q", "").strip()
        if q:
            query = query.filter(CatalogRequest.number.ilike(f"%{q}%"))
        export_limit = 5000
        rows = query.order_by(CatalogRequest.opened_at.desc()).limit(export_limit).all()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Number", "Requested for", "Requested by", "State", "Items", "Opened"])
        for req in rows:
            writer.writerow([
                req.number, req.requested_for.name if req.requested_for else "",
                req.requested_by.name if req.requested_by else "", req.state, len(req.items),
                usertime_filter(req.opened_at, "%Y-%m-%d %H:%M"),
            ])
        return csv_response(buffer.getvalue(), "requests.csv")

    @app.get("/request/<int:request_id>")
    @login_required
    def request_detail(request_id):
        req = tenant_record_or_404(CatalogRequest, request_id)
        if not user_can_view_catalog_request(current_user, req):
            abort(403, description=tr("You are not involved in this request or its fulfillment."))
        return render_template(
            "request_detail.html", req=req,
            catalog_items=tenant_query(CatalogItem).filter_by(active=True).order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
            can_add_request_item=user_can_add_request_item(current_user, req),
        )

    @app.get("/ritm/<int:ritm_id>")
    @login_required
    def ritm_detail(ritm_id):
        ritm = db.get_or_404(RequestedItem, ritm_id)
        req = ritm.request
        if req.tenant_id != current_user.tenant_id:
            abort(404)
        if not user_can_view_catalog_request(current_user, req):
            abort(403, description=tr("You are not involved in this request or its fulfillment."))
        can_manage = user_can_manage_ritm(current_user, ritm)
        chains = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm.id).all()
        slas = TaskSLA.query.filter_by(target_type="ritm", target_id=ritm.id).all()
        task_state_options = {
            task.id: CATALOG_TASK_TRANSITIONS.get(task.state, (task.state,))
            for task in ritm.tasks
        }
        catalog_task_permissions = {
            task.id: user_in_group(current_user, task.assignment_group)
            for task in ritm.tasks
        }
        try:
            variables = json.loads(ritm.variables_json or "{}")
        except (TypeError, ValueError):
            variables = {}
        return render_template(
            "ritm_detail.html", ritm=ritm, req=req, chains=chains, slas=slas,
            variables=variables,
            task_state_options=task_state_options,
            catalog_task_permissions=catalog_task_permissions,
            can_manage=can_manage,
            state_track=build_state_track("ritm", ritm.state),
            teams=tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment", active=True
            ).order_by(SupportGroup.name).all(),
            related=related_records("ritm", ritm.id),
            history=TaskHistory.query.filter_by(
                target_type="ritm", target_id=ritm.id
            ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all(),
        )

    @app.post("/request/<int:request_id>/items")
    @login_required
    def request_item_add(request_id):
        req = tenant_record_or_404(CatalogRequest, request_id)
        if req.state not in ("Open", "Awaiting Approval"):
            abort(409, description=tr("Items cannot be added to a completed request."))
        if not user_can_add_request_item(current_user, req):
            abort(403, description=tr("Only request participants or an administrator can add items."))
        item = tenant_record_or_404(CatalogItem, int(request.form["catalog_item_id"]))
        approval_stages = None
        if item.approval_required:
            try:
                approval_stages = catalog_approval_stages(req.requested_for)
            except ValueError as error:
                abort(409, description=str(error))
        def build_ritm():
            ritm = RequestedItem(
                number=sequence_number(RequestedItem, "RITM"), request_id=req.id,
                catalog_item_id=item.id,
                state="Awaiting Approval" if item.approval_required else "Open",
                stage="Approval" if item.approval_required else "Fulfillment",
                variables_json=json.dumps({"details": request.form.get("details", "")}),
                due_at=now() + timedelta(days=item.delivery_days), tenant_id=req.tenant_id,
            )
            db.session.add(ritm)
            return ritm
        ritm = create_with_retry_on_number_collision(build_ritm)
        attach_slas("ritm", ritm.id, None)
        if item.approval_required:
            create_approval_chain(
                f"{ritm.number} service fulfillment", "ritm", ritm.id, approval_stages,
            )
        else:
            create_catalog_task(ritm)
        log_history(
            "request", req.id, "Requested item added",
            details=f"{ritm.number}: {item.name}",
        )
        log_history(
            "ritm", ritm.id, "Requested item created",
            details=f"Added to {req.number}: {item.name}",
        )
        audit("add requested item", req.number, f"{ritm.number}: {item.name}")
        db.session.commit()
        return redirect(url_for("request_detail", request_id=req.id))

    @app.post("/ritm/<int:ritm_id>/tasks")
    @roles("agent", "manager", "admin")
    def catalog_task_add(ritm_id):
        ritm = db.get_or_404(RequestedItem, ritm_id)
        if not user_can_manage_ritm(current_user, ritm):
            abort(403, description=tr("Only the fulfillment team can add tasks to this requested item."))
        chain = approval_chain_for("ritm", ritm.id)
        if chain and chain.state != "Approved":
            abort(409, description=tr("Catalog tasks cannot be added until the RITM is approved."))
        group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
        if not group.active or group.group_type != "IT Fulfillment":
            abort(400, description=tr("Catalog tasks require an active IT fulfillment team."))
        def build_task():
            task = CatalogTask(
                number=sequence_number(CatalogTask, "SCTASK"),
                requested_item_id=ritm.id,
                title=request.form["title"].strip(),
                sequence=len(ritm.tasks) + 1,
                assignment_group_id=group.id,
                due_at=ritm.due_at, tenant_id=ritm.tenant_id,
            )
            db.session.add(task)
            return task
        task = create_with_retry_on_number_collision(build_task)
        execution_mode = request.form.get("execution_mode", "Parallel")
        predecessor = (
            CatalogTask.query.filter_by(requested_item_id=ritm.id)
            .filter(CatalogTask.id != task.id)
            .order_by(CatalogTask.sequence.desc(), CatalogTask.id.desc()).first()
        )
        if execution_mode not in ("Parallel", "Sequential"):
            abort(400)
        db.session.add(CatalogTaskControl(
            task_id=task.id, execution_mode=execution_mode,
            predecessor_task_id=(
                predecessor.id if execution_mode == "Sequential" and predecessor else None
            ),
        ))
        log_history(
            "ritm", ritm.id, "Catalog task created",
            details=(
                f"{task.number}: {task.title} → {group.name} · {execution_mode}"
                + (f" after {predecessor.number}" if execution_mode == "Sequential" and predecessor else "")
            ),
        )
        audit("create", task.number, f"{ritm.number}: {task.title}")
        db.session.commit()
        return redirect(url_for("request_detail", request_id=ritm.request_id))

    @app.get("/catalog-task/<int:task_id>")
    @login_required
    def catalog_task_detail(task_id):
        task = db.get_or_404(CatalogTask, task_id)
        if not user_can_view_catalog_task(current_user, task):
            abort(403, description=tr("You are not involved in this catalog task or its fulfillment."))
        ritm = task.requested_item
        can_edit = user_in_group(current_user, task.assignment_group)
        member_ids = {member.user_id for member in task.assignment_group.members} if task.assignment_group else set()
        if task.assignment_group and task.assignment_group.manager_id:
            member_ids.add(task.assignment_group.manager_id)
        agents = User.query.filter(
            User.id.in_(member_ids), User.active.is_(True),
            User.role.in_(["agent", "manager", "admin", "superadmin"]),
        ).order_by(User.name).all() if member_ids else []
        history = TaskHistory.query.filter_by(
            target_type="ritm", target_id=ritm.id
        ).filter(TaskHistory.details.contains(task.number)).order_by(
            TaskHistory.created_at.desc(), TaskHistory.id.desc()
        ).all()
        internal_notes = TaskNote.query.filter_by(
            target_type="catalog_task", target_id=task.id, visibility="internal"
        ).order_by(TaskNote.created_at.desc()).all() if can_edit else []
        ritm_comments = TaskNote.query.filter_by(
            target_type="ritm", target_id=ritm.id, visibility="customer"
        ).order_by(TaskNote.created_at.desc()).all()
        try:
            variables = json.loads(ritm.variables_json or "{}")
        except (TypeError, ValueError):
            variables = {}
        siblings = CatalogTask.query.filter_by(
            requested_item_id=ritm.id
        ).filter(CatalogTask.id != task.id).order_by(CatalogTask.sequence, CatalogTask.id).all()
        ci_links = TaskCI.query.filter_by(
            target_type="ritm", target_id=ritm.id
        ).order_by(TaskCI.relationship_role).all()
        chain = approval_chain_for("ritm", ritm.id)
        approval_votes = [vote for gate in chain.gates for vote in gate.votes] if chain else []
        allowed_states = CATALOG_TASK_TRANSITIONS.get(task.state, (task.state,))
        gate_block = None
        selectable_states = [task.state]
        linked_change = ritm_linked_change(ritm)
        for candidate in allowed_states:
            if candidate == task.state:
                continue
            if candidate == "Work in Progress" and linked_change and linked_change.state in ("New", "Awaiting Approval"):
                gate_block = (
                    f"{task.number} cannot start production work: it is linked to "
                    f"{linked_change.number}, which is not yet approved and authorized. "
                    "Coordination on this task (details, scheduling) is fine — set it to "
                    "Pending until the change is authorized."
                )
                continue
            selectable_states.append(candidate)
        return render_template(
            "catalog_task_detail.html", task=task, ritm=ritm,
            can_edit=can_edit, agents=agents, history=history,
            work_task_states=CATALOG_TASK_TRANSITIONS,
            internal_notes=internal_notes, ritm_comments=ritm_comments,
            variables=variables, siblings=siblings, ci_links=ci_links,
            approval_votes=approval_votes, chain=chain,
            selectable_states=selectable_states, gate_block=gate_block,
            state_track=build_state_track("catalog_task", task.state),
        )

    @app.post("/catalog-task/<int:task_id>/notes")
    @login_required
    def catalog_task_note_add(task_id):
        task = db.get_or_404(CatalogTask, task_id)
        if not user_can_view_catalog_task(current_user, task):
            abort(403)
        ritm = task.requested_item
        visibility = request.form.get("visibility")
        body = request.form.get("body", "").strip()
        if visibility not in ("internal", "customer"):
            abort(400, description=tr("Select a valid note visibility."))
        if visibility == "internal" and not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                tr("Only active members of {value} can add internal work notes.", value=task.assignment_group.name if task.assignment_group else 'the assignment group')
            ))
        if body:
            if visibility == "internal":
                db.session.add(TaskNote(
                    target_type="catalog_task", target_id=task.id,
                    visibility="internal", body=body, user_id=current_user.id,
                ))
                log_history("ritm", ritm.id, f"{task.number} note added", details=body[:500])
            else:
                db.session.add(TaskNote(
                    target_type="ritm", target_id=ritm.id,
                    visibility="customer", body=body, user_id=current_user.id,
                ))
                log_history("ritm", ritm.id, "Customer-visible comment added", details=body[:500])
                create_notification(
                    ritm.request.requested_for_id, f"New comment on {ritm.number}",
                    body[:500], tenant_id=task.assignment_group.tenant_id if task.assignment_group else current_user.tenant_id,
                    target_type="ritm", target_id=ritm.id,
                    event_type="ritm.comment_added",
                    template_vars={"ritm_number": ritm.number, "comment": body[:500]},
                )
            audit("note", task.number, body[:120])
            db.session.commit()
        return redirect(url_for("catalog_task_detail", task_id=task.id))

    @app.post("/catalog-task/<int:task_id>")
    @roles("agent", "manager", "admin")
    def catalog_task_update(task_id):
        task = db.get_or_404(CatalogTask, task_id)
        if not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                tr("Only active members of {value} can update {number}.", value=task.assignment_group.name if task.assignment_group else 'the assignment group', number=task.number)
            ))
        before = {"state": task.state, "work notes": task.work_notes}
        try:
            transition_catalog_task(task, request.form.get("state", task.state))
        except HTTPException as error:
            db.session.rollback()
            flash(error.description or tr("That change could not be made."), "error")
            destination = request.referrer
            if destination and destination.startswith(request.host_url):
                return redirect(destination)
            return redirect(url_for("request_detail", request_id=task.requested_item.request_id))
        task.work_notes = request.form.get("work_notes", "")
        task.assignee_id = current_user.id
        ritm = task.requested_item
        terminal_states = {"Closed Complete", "Closed Incomplete", "Closed Skipped"}
        all_terminal = all(item.state in terminal_states for item in ritm.tasks)
        if all_terminal and all(item.state == "Closed Complete" for item in ritm.tasks):
            ritm.state = "Closed Complete"
            ritm.stage = "Completed"
            sync_slas("ritm", ritm.id, ritm.state)
            if all(item.state == "Closed Complete" for item in ritm.request.items):
                ritm.request.state = "Closed Complete"
                ritm.request.closed_at = now()
        elif all_terminal and any(item.state == "Closed Incomplete" for item in ritm.tasks):
            ritm.state = "Closed Incomplete"
            ritm.stage = "Completed"
            ritm.request.state = "Closed Incomplete"
        log_field_changes("ritm", ritm.id, before, {
            "state": task.state, "work notes": task.work_notes,
        }, event=f"{task.number} updated")
        audit("update", task.number, task.state)
        db.session.commit()
        redirect_target = request.form.get("redirect_to")
        if redirect_target == "task":
            return redirect(url_for("catalog_task_detail", task_id=task.id))
        return redirect(url_for("request_detail", request_id=ritm.request_id))
