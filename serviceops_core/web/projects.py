"""Project management pages (B-443): projects, board, list, work items and
project settings. Rules live in serviceops_core.projects.service; this
module only parses requests and renders pages.

Every route needs a signed-in user and PROJECTS_ENABLED; private projects
answer 404 to anyone who is not a member."""
from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import service
from serviceops_core.projects.models import (
    ITEM_TYPES, LINK_TYPES, PRIORITIES, PROJECT_ROLES, STATUS_CATEGORIES, Project, ProjectMember, WorkItem,
    WorkItemComment, WorkItemHistory,
)
from serviceops_models import User, db

ITEM_TYPE_LABELS = {"epic": "Epic", "story": "Story", "task": "Task", "bug": "Bug", "subtask": "Subtask"}
PRIORITY_LABELS = {"highest": "Highest", "high": "High", "medium": "Medium", "low": "Low", "lowest": "Lowest"}
CATEGORY_LABELS = {"todo": "To do", "in_progress": "In progress", "done": "Done"}
ROLE_LABELS = {"admin": "Administrator", "member": "Member", "viewer": "Viewer", "reader": "Reader"}
LIST_PAGE = 100
BOARD_LIMIT = 200


def _wants_json():
    return request.is_json or request.accept_mimetypes.best == "application/json"


def _filters():
    keys = ("q", "type", "status", "category", "priority", "assignee", "label", "epic")
    return {key: request.args.get(key, "").strip() for key in keys if request.args.get(key, "").strip()}


def _item_json(item):
    return {
        "key": item.key, "id": item.id, "title": item.title, "type": item.item_type, "priority": item.priority,
        "status": {"id": item.status.id, "name": item.status.name, "category": item.status.category},
        "assignees": [{"id": user.id, "name": user.name} for user in item.assignees],
        "labels": [row.label for row in item.labels], "story_points": item.story_points,
        "due_date": item.due_date.isoformat() if item.due_date else None,
        "url": url_for("projects.item_detail", item_key=item.key),
    }


def register(app):
    blueprint = Blueprint("projects", __name__)

    @blueprint.before_request
    @login_required
    def gate():
        service.require_enabled()

    # Code-specific handlers: the application's own 403/404/409 handlers
    # would otherwise win over a class-based blueprint handler.
    @blueprint.errorhandler(400)
    @blueprint.errorhandler(403)
    @blueprint.errorhandler(404)
    @blueprint.errorhandler(409)
    @blueprint.errorhandler(HTTPException)
    def errors(error):
        db.session.rollback()
        if _wants_json():
            return jsonify({"error": error.description}), error.code
        return render_template("error.html", code=error.code, message=error.description), error.code

    common = dict(item_type_labels=ITEM_TYPE_LABELS, priority_labels=PRIORITY_LABELS,
                  category_labels=CATEGORY_LABELS, role_labels=ROLE_LABELS, item_types=ITEM_TYPES,
                  priorities=PRIORITIES, categories=STATUS_CATEGORIES, link_types=LINK_TYPES)

    def page(template, project=None, **context):
        if project is not None:
            role = service.project_role(current_user, project)
            context.update(project=project, project_role=role, can_edit=service.can_edit(current_user, project),
                           can_admin=service.can_administer(current_user, project),
                           can_comment=service.can_comment(current_user, project))
        return render_template(template, **common, **context)

    # --- projects -------------------------------------------------------------------

    @blueprint.get("/projects")
    def index():
        show_archived = request.args.get("archived") == "1"
        projects = service.visible_projects(current_user, include_archived=show_archived).order_by(
            Project.archived_at.isnot(None), Project.name).all()
        ids = [project.id for project in projects]
        open_counts, member_counts = {}, {}
        if ids:
            from serviceops_core.projects.models import ProjectStatus
            open_counts = dict(db.session.query(WorkItem.project_id, db.func.count()).join(
                ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
                WorkItem.project_id.in_(ids), ProjectStatus.category != "done").group_by(WorkItem.project_id))
            member_counts = dict(db.session.query(ProjectMember.project_id, db.func.count()).filter(
                ProjectMember.project_id.in_(ids)).group_by(ProjectMember.project_id))
        return page("projects/index.html", projects=projects, open_counts=open_counts, member_counts=member_counts,
                    show_archived=show_archived, can_create=service.can_create_projects(current_user))

    @blueprint.route("/projects/new", methods=["GET", "POST"])
    def new_project():
        if not service.can_create_projects(current_user):
            abort(403, description=tr("You are not allowed to create projects."))
        if request.method == "POST":
            project = service.create_project(
                current_user, request.form.get("key"), request.form.get("name"), request.form.get("description"),
                request.form.get("visibility", "private"), request.form.get("lead_id") or None,
                request.form.get("color"))
            db.session.commit()
            flash(tr("Project {key} created.", key=project.key), "success")
            return redirect(url_for("projects.board", key=project.key))
        users = User.query.filter_by(tenant_id=current_user.tenant_id, active=True).order_by(User.name).limit(2000)
        return page("projects/project_form.html", users=users)

    @blueprint.get("/projects/<key>")
    def project_home(key):
        project = service.project_or_404(current_user, key)
        return redirect(url_for("projects.board", key=project.key))

    def _board_context(project):
        filters = _filters()
        swimlane = request.args.get("swimlane", "none")
        swimlane = swimlane if swimlane in ("none", "assignee", "epic") else "none"
        statuses = list(project.statuses)
        query = service.item_query(project, filters, current_user)
        if not filters.get("type"):
            # Epics are planned on the list; the board shows the work itself.
            query = query.filter(WorkItem.item_type != "epic")
        items = service.sorted_query(query, "rank").limit(BOARD_LIMIT * max(len(statuses), 1)).all()
        lanes = []
        if swimlane == "assignee":
            people = {}
            for item in items:
                for user in item.assignees or [None]:
                    people.setdefault(user.id if user else 0, (user, []))[1].append(item)
            lanes = sorted(people.values(), key=lambda lane: (lane[0] is None, lane[0].name if lane[0] else ""))
            lanes = [(user.name if user else tr("Unassigned"), rows) for user, rows in lanes]
        elif swimlane == "epic":
            groups = {}
            for item in items:
                parent = item.parent if item.parent and item.parent.item_type == "epic" else None
                groups.setdefault(parent.id if parent else 0, (parent, []))[1].append(item)
            lanes = sorted(groups.values(), key=lambda lane: (lane[0] is None, lane[0].number if lane[0] else 0))
            lanes = [(f"{epic.key} · {epic.title}" if epic else tr("No epic"), rows) for epic, rows in lanes]
        else:
            lanes = [(None, items)]
        columns = [{"status": status, "lanes": [[item for item in rows if item.status_id == status.id]
                                               for _, rows in lanes]} for status in statuses]
        # Column counts are the cards this board shows (same filters, no
        # epics), counted in SQL so a column beyond the card limit is right.
        counts = dict(query.with_entities(WorkItem.status_id, db.func.count()).group_by(WorkItem.status_id).all())
        return dict(filters=filters, swimlane=swimlane, lane_titles=[title for title, _ in lanes], columns=columns,
                    counts=counts, members=service.assignable_users(project), labels=service.project_labels(project),
                    epics=service.epics(project))

    @blueprint.get("/projects/<key>/board")
    def board(key):
        project = service.project_or_404(current_user, key)
        return page("projects/board.html", project, tab="board", **_board_context(project))

    @blueprint.get("/projects/<key>/list")
    def item_list(key):
        project = service.project_or_404(current_user, key)
        filters = _filters()
        sort = request.args.get("sort", "rank")
        sort = sort if sort in service.SORTS else "rank"
        group = request.args.get("group", "none")
        group = group if group in ("none", "status", "type", "assignee", "epic") else "none"
        try:
            page_number = max(1, int(request.args.get("page", 1)))
        except ValueError:
            page_number = 1
        query = service.item_query(project, filters, current_user)
        total = query.count()
        items = service.sorted_query(query, sort).offset((page_number - 1) * LIST_PAGE).limit(LIST_PAGE).all()
        groups = _group_items(items, group, project)
        pages = max(1, -(-total // LIST_PAGE))

        def page_url(number):
            return url_for("projects.item_list", key=project.key, page=number, sort=sort, group=group, **filters)
        return page("projects/list.html", project, tab="list", filters=filters, sort=sort, group=group,
                    groups=groups, total=total, page_number=page_number, pages=pages,
                    prev_url=page_url(page_number - 1) if page_number > 1 else None,
                    next_url=page_url(page_number + 1) if page_number < pages else None,
                    members=service.assignable_users(project), labels=service.project_labels(project),
                    epics=service.epics(project))

    def _group_items(items, group, project):
        if group == "none":
            return [(None, items)]
        buckets = {}
        for item in items:
            if group == "status":
                keys = [(item.status.position, item.status.name)]
            elif group == "type":
                keys = [(ITEM_TYPES.index(item.item_type), tr(ITEM_TYPE_LABELS[item.item_type]))]
            elif group == "assignee":
                keys = [(0, user.name) for user in item.assignees] or [(1, tr("Unassigned"))]
            else:
                parent = item.parent if item.parent and item.parent.item_type == "epic" else None
                keys = [(0, f"{parent.key} · {parent.title}")] if parent else [(1, tr("No epic"))]
            for bucket in keys:
                buckets.setdefault(bucket, []).append(item)
        return [(name, rows) for (_, name), rows in sorted(buckets.items())]

    # --- work items ------------------------------------------------------------------

    def _item_fields(form):
        fields = {name: form.get(name) for name in ("title", "description", "item_type", "status_id", "priority",
                                                    "parent_id", "start_date", "due_date", "story_points",
                                                    "estimate_minutes", "labels") if name in form}
        if "assignee_ids" in form or "assignee_ids_present" in form:
            fields["assignee_ids"] = form.getlist("assignee_ids")
        if "estimate_hours" in form:
            hours = form.get("estimate_hours", "").strip()
            try:
                fields["estimate_minutes"] = int(round(float(hours) * 60)) if hours else None
            except ValueError:
                abort(400, description=tr("Estimate must be a number of hours."))
        return fields

    @blueprint.route("/projects/<key>/items/new", methods=["GET", "POST"])
    def new_item(key):
        project = service.project_or_404(current_user, key)
        service.require_edit(current_user, project)
        if request.method == "POST":
            fields = _item_fields(request.form)
            item = service.create_item(
                current_user, project, fields.pop("title", ""), item_type=fields.pop("item_type", "task"),
                description=fields.pop("description", ""), status_id=fields.pop("status_id", None),
                priority=fields.pop("priority", "medium"), assignee_ids=fields.pop("assignee_ids", None),
                labels=fields.pop("labels", None), parent_id=fields.pop("parent_id", None),
                start_date=fields.pop("start_date", None), due_date=fields.pop("due_date", None),
                story_points=fields.pop("story_points", None), estimate_minutes=fields.pop("estimate_minutes", None))
            db.session.commit()
            if _wants_json():
                return jsonify(_item_json(item)), 201
            flash(tr("{key} created.", key=item.key), "success")
            if request.form.get("return") == "board":
                return redirect(url_for("projects.board", key=project.key))
            if request.form.get("another"):
                return redirect(url_for("projects.new_item", key=project.key, type=item.item_type))
            return redirect(url_for("projects.item_detail", item_key=item.key))
        parent = None
        if request.args.get("parent", "").isdigit():
            parent = WorkItem.query.filter_by(project_id=project.id, id=int(request.args["parent"])).first()
        item_type = request.args.get("type", "task")
        item_type = item_type if item_type in ITEM_TYPES else "task"
        if parent and parent.item_type != "epic" and item_type not in ("subtask",):
            item_type = "subtask"
        return page("projects/item_form.html", project, item_type=item_type, parent=parent,
                    members=service.assignable_users(project), epics=service.epics(project),
                    parents=_parent_choices(project))

    def _parent_choices(project):
        return WorkItem.query.filter(WorkItem.project_id == project.id, WorkItem.item_type != "subtask").order_by(
            WorkItem.item_type != "epic", WorkItem.number.desc()).limit(500).all()

    @blueprint.get("/work-items/<item_key>")
    def item_detail(item_key):
        item = service.item_or_404(current_user, item_key)
        if item.key != item_key:
            return redirect(url_for("projects.item_detail", item_key=item.key))
        project = item.project
        comments = WorkItemComment.query.filter_by(work_item_id=item.id).order_by(WorkItemComment.created_at).all()
        history = WorkItemHistory.query.filter_by(work_item_id=item.id).order_by(
            WorkItemHistory.created_at.desc(), WorkItemHistory.id.desc()).limit(200).all()
        children = WorkItem.query.filter_by(parent_id=item.id).order_by(WorkItem.rank, WorkItem.id).all()
        attachments = core.FileAttachment.query.filter_by(work_item_id=item.id).order_by(
            core.FileAttachment.created_at).all()
        return page("projects/item.html", project, item=item, comments=comments, history=history,
                    children=children, links=service.links_for(current_user, item), attachments=attachments,
                    watching=service.is_watching(item, current_user), members=service.assignable_users(project),
                    parents=_parent_choices(project), statuses=list(project.statuses))

    @blueprint.post("/work-items/<item_key>/edit")
    def item_edit(item_key):
        item = service.item_or_404(current_user, item_key)
        service.update_item(current_user, item, _item_fields(request.form))
        db.session.commit()
        if _wants_json():
            return jsonify(_item_json(item))
        flash(tr("{key} updated.", key=item.key), "success")
        return redirect(url_for("projects.item_detail", item_key=item.key))

    @blueprint.post("/work-items/<item_key>/move")
    def item_move(item_key):
        item = service.item_or_404(current_user, item_key)
        data = request.get_json(silent=True) or request.form
        service.move_item(current_user, item, data.get("status_id"), data.get("before_id"), data.get("after_id"))
        db.session.commit()
        return jsonify(_item_json(item))

    @blueprint.post("/work-items/<item_key>/comments")
    def item_comment(item_key):
        item = service.item_or_404(current_user, item_key)
        service.add_comment(current_user, item, request.form.get("body"))
        db.session.commit()
        return redirect(url_for("projects.item_detail", item_key=item.key) + "#comments")

    @blueprint.post("/work-items/<item_key>/watch")
    def item_watch(item_key):
        item = service.item_or_404(current_user, item_key)
        service.set_watching(current_user, item, request.form.get("watch") == "1")
        db.session.commit()
        return redirect(url_for("projects.item_detail", item_key=item.key))

    @blueprint.post("/work-items/<item_key>/links")
    def item_link(item_key):
        item = service.item_or_404(current_user, item_key)
        service.add_link(current_user, item, request.form.get("link_type"), request.form.get("target"))
        db.session.commit()
        flash(tr("Link added."), "success")
        return redirect(url_for("projects.item_detail", item_key=item.key) + "#links")

    @blueprint.post("/work-items/<item_key>/links/<int:link_id>/delete")
    def item_unlink(item_key, link_id):
        item = service.item_or_404(current_user, item_key)
        service.remove_link(current_user, item, link_id)
        db.session.commit()
        return redirect(url_for("projects.item_detail", item_key=item.key) + "#links")

    @blueprint.post("/work-items/<item_key>/delete")
    def item_delete(item_key):
        item = service.item_or_404(current_user, item_key)
        project_key, deleted_key = item.project.key, item.key
        service.delete_item(current_user, item)
        db.session.commit()
        flash(tr("{key} deleted.", key=deleted_key), "success")
        return redirect(url_for("projects.item_list", key=project_key))

    @blueprint.post("/work-items/<item_key>/attachments")
    def item_attach(item_key):
        item = service.item_or_404(current_user, item_key)
        service.require_edit(current_user, item.project)
        from serviceops_core.web.common import save_record_attachment
        attachment, problem = save_record_attachment(item.key, item.tenant_id, request.files.get("file"),
                                                     {"work_item_id": item.id})
        if problem:
            db.session.rollback()
            flash(tr(problem), "error")
            return redirect(url_for("projects.item_detail", item_key=item.key) + "#attachments")
        db.session.add(WorkItemHistory(tenant_id=item.tenant_id, work_item_id=item.id, actor_id=current_user.id,
                                       field="attachment", new_value=attachment.original_name))
        db.session.commit()
        flash(tr("{name} attached.", name=attachment.original_name), "success")
        return redirect(url_for("projects.item_detail", item_key=item.key) + "#attachments")

    @blueprint.post("/work-items/<item_key>/attachments/<int:attachment_id>/delete")
    def item_attachment_delete(item_key, attachment_id):
        item = service.item_or_404(current_user, item_key)
        service.require_edit(current_user, item.project)
        attachment = core.FileAttachment.query.filter_by(id=attachment_id, work_item_id=item.id).first_or_404()
        stored_name, reference = attachment.stored_name, attachment.ipfs_cid or attachment.stored_name
        name = attachment.original_name
        db.session.add(WorkItemHistory(tenant_id=item.tenant_id, work_item_id=item.id, actor_id=current_user.id,
                                       field="attachment", old_value=name))
        core.audit("attach-delete", item.key, name)
        db.session.delete(attachment)
        db.session.commit()
        # Remove the bytes only after the deletion and its audit record are durable.
        try:
            core.current_storage().delete_file(stored_name, reference)
        except Exception:
            current_app.logger.exception("Stored file cleanup failed for work item attachment %s", attachment_id)
        flash(tr("{name} was deleted.", name=name), "success")
        return redirect(url_for("projects.item_detail", item_key=item.key) + "#attachments")

    @blueprint.get("/my/work-items")
    def my_items():
        items = service.my_open_items(current_user)
        return page("projects/my_items.html", items=items)

    # --- settings ---------------------------------------------------------------------------

    @blueprint.route("/projects/<key>/settings", methods=["GET", "POST"])
    def settings(key):
        project = service.project_or_404(current_user, key)
        service.require_admin(current_user, project)
        if request.method == "POST":
            action = request.form.get("action", "details")
            if action == "details":
                service.update_project(current_user, project, request.form.get("name"),
                                       request.form.get("description"), request.form.get("visibility"),
                                       request.form.get("lead_id", ""), request.form.get("color"))
            elif action == "member":
                service.set_member(current_user, project, request.form.get("user_id"), request.form.get("role"))
            elif action == "remove_member":
                service.remove_member(current_user, project, request.form.get("user_id", type=int))
            elif action == "add_status":
                service.add_status(current_user, project, request.form.get("name"), request.form.get("category"))
            elif action == "update_status":
                status = service.status_or_404(project, request.form.get("status_id"))
                service.update_status(current_user, project, status, request.form.get("name"),
                                      request.form.get("category"), request.form.get("wip_limit", ""))
            elif action == "move_status":
                status = service.status_or_404(project, request.form.get("status_id"))
                service.move_status(current_user, project, status, request.form.get("direction"))
            elif action == "delete_status":
                status = service.status_or_404(project, request.form.get("status_id"))
                replacement = service.status_or_404(project, request.form.get("replacement_id"))
                service.delete_status(current_user, project, status, replacement)
            elif action in ("archive", "restore"):
                service.set_archived(current_user, project, action == "archive")
            else:
                abort(400, description=tr("Unknown settings action."))
            db.session.commit()
            flash(tr("Project settings saved."), "success")
            return redirect(url_for("projects.settings", key=project.key) + f"#{request.form.get('section', '')}")
        members = ProjectMember.query.filter_by(project_id=project.id).join(User).order_by(User.name).all()
        users = User.query.filter_by(tenant_id=current_user.tenant_id, active=True).order_by(User.name).limit(2000)
        return page("projects/settings.html", project, tab="settings", members=members, users=users,
                    counts=service.status_counts(project), roles=PROJECT_ROLES)

    def linked_work_items(target_type, target_id):
        """Work items linked to an ITSM record that the viewer can see."""
        if not current_user.is_authenticated or not service.enabled():
            return []
        return service.items_linked_to_record(current_user, target_type, target_id)

    app.jinja_env.globals["linked_work_items"] = linked_work_items

    @app.context_processor
    def projects_nav():
        if not current_user.is_authenticated:
            return {"projects_enabled": False}
        return {"projects_enabled": service.enabled()}

    app.register_blueprint(blueprint)
    from serviceops_core.web import projects_api
    projects_api.register(app)
