"""Project management pages (B-443): projects, board, list, work items and
project settings. Rules live in serviceops_core.projects.service; this
module only parses requests and renders pages.

Every route needs a signed-in user and PROJECTS_ENABLED; private projects
answer 404 to anyone who is not a member."""
import re

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_core.localization import tr
from serviceops_core.safe_redirect import redirect_internal
from markupsafe import escape

from serviceops_core.projects import catalog, markdown, operations, releases, service, tracking
from serviceops_core.projects.models import (
    COMPONENT_ASSIGNEE_CHOICES, ITEM_TYPES, PRIORITIES, PROJECT_ROLES, REACTIONS, STATUS_CATEGORIES,
    Project, ProjectMember, WorkItem, WorkItemHistory,
)
from serviceops_models import User, db

ITEM_TYPE_LABELS = {"epic": "Epic", "story": "Story", "task": "Task", "bug": "Bug", "subtask": "Subtask"}
PRIORITY_LABELS = {"highest": "Highest", "high": "High", "medium": "Medium", "low": "Low", "lowest": "Lowest"}
CATEGORY_LABELS = {"todo": "To do", "in_progress": "In progress", "done": "Done"}
ROLE_LABELS = {"admin": "Administrator", "member": "Member", "viewer": "Viewer", "reader": "Reader"}
LIST_PAGE = 100
BOARD_COLUMN_LIMIT = 50
CHILD_LIMIT = 50
RELEASE_ITEM_LIMIT = 100


def _wants_json():
    return request.is_json or request.accept_mimetypes.best == "application/json"


def _filters():
    keys = ("q", "type", "status", "category", "priority", "assignee", "label", "epic", "component", "version",
            "flagged")
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


ITEM_KEY_IN_TEXT = re.compile(r"(?<![\w/-])([A-Z][A-Z0-9]{1,9}-\d{1,9})(?![\w-])")


def rich_text(text):
    """Markdown for descriptions and comments, with @mentions of people in
    the viewer's organisation and work item keys turned into links. The
    linked pages apply their own access checks."""
    people = {}
    names = {match.group(1).lower() for match in core.MENTION_PATTERN.finditer(text or "")}
    if names and current_user.is_authenticated:
        people = {row.username.lower(): row for row in User.query.filter(
            db.func.lower(User.username).in_(names), User.tenant_id == current_user.tenant_id)}

    def mention(escaped):
        def link(match):
            person = people.get(match.group(1).lower())
            if not person:
                return match.group(0)
            return f'<a class="mention" href="{escape(url_for("people_profile", user_id=person.id))}">@{match.group(1)}</a>'
        return core.MENTION_PATTERN.sub(link, escaped)

    def item_link(escaped):
        return ITEM_KEY_IN_TEXT.sub(
            lambda match: f'<a class="wi-key-link" href="{escape(url_for("projects.item_detail", item_key=match.group(1)))}">'
                          f'{match.group(1)}</a>', escaped)
    return markdown.render(text, mention=mention, item_link=item_link)


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
                  priorities=PRIORITIES, categories=STATUS_CATEGORIES)

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
        # Loaded first so each card's epic comes from the session, not a query.
        project_epics = service.epics(project)
        query = service.item_query(project, filters, current_user)
        if not filters.get("type"):
            # Epics are planned on the list; the board shows the work itself.
            query = query.filter(WorkItem.item_type != "epic")
        # The first cards of each column by rank; the rest are one click away
        # on the list (a column of thousands of cards helps nobody).
        items = []
        for status in statuses:
            items += service.sorted_query(query.filter(WorkItem.status_id == status.id), "rank").limit(
                BOARD_COLUMN_LIMIT).all()
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
        hidden = {status.id: max(0, counts.get(status.id, 0) - BOARD_COLUMN_LIMIT) for status in statuses}
        more_urls = {status.id: url_for("projects.item_list", key=project.key, **{**filters, "status": status.id})
                     for status in statuses if hidden[status.id]}
        return dict(filters=filters, swimlane=swimlane, lane_titles=[title for title, _ in lanes], columns=columns,
                    counts=counts, hidden=hidden, more_urls=more_urls, members=service.assignable_users(project),
                    labels=service.project_labels(project), epics=project_epics)

    @blueprint.get("/projects/<key>/overview")
    def overview(key):
        project = service.project_or_404(current_user, key)
        return page("projects/overview.html", project, tab="overview",
                    stats=service.overview(project, core.now().date()))

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
                                                    "estimate_minutes", "labels", "environment", "resolution_id",
                                                    "reporter_id") if name in form}
        if "assignee_ids" in form or "assignee_ids_present" in form:
            fields["assignee_ids"] = form.getlist("assignee_ids")
        for name in ("component_ids", "fix_version_ids", "affects_version_ids"):
            if name in form or f"{name}_present" in form:
                fields[name] = form.getlist(name)
        if "flagged_present" in form:
            fields["flagged"] = form.get("flagged") == "1"
        # Durations in Jira's notation ("1d 4h"); estimate_hours stays for old forms.
        if "estimate" in form:
            fields["estimate_minutes"] = tracking.parse_duration(form.get("estimate"), tr("Original estimate"))
        if "remaining" in form:
            fields["remaining_minutes"] = tracking.parse_duration(form.get("remaining"), tr("Remaining estimate"))
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
                story_points=fields.pop("story_points", None), estimate_minutes=fields.pop("estimate_minutes", None),
                component_ids=fields.pop("component_ids", None), fix_version_ids=fields.pop("fix_version_ids", None),
                affects_version_ids=fields.pop("affects_version_ids", None),
                environment=fields.pop("environment", "") or "")
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
                    parents=_parent_choices(project), components=releases.components(project),
                    versions=releases.versions(project, include_archived=False))

    def _parent_choices(project):
        return WorkItem.query.filter(WorkItem.project_id == project.id, WorkItem.item_type != "subtask").order_by(
            WorkItem.item_type != "epic", WorkItem.number.desc()).limit(500).all()

    def _item_or_redirect(item_key):
        """The work item, or a redirect for a moved (old) or differently-cased key."""
        item = service.find_visible_item(current_user, item_key)
        if item is None:
            item = operations.resolve_alias(current_user, item_key)
            if item is None:
                abort(404)
        if item.key != item_key:
            return None, redirect(url_for(request.endpoint, **{**request.view_args, "item_key": item.key}))
        return item, None

    @blueprint.get("/work-items/<item_key>")
    def item_detail(item_key):
        item, moved = _item_or_redirect(item_key)
        if moved:
            return moved
        project = item.project
        service.record_view(current_user, item)
        db.session.commit()
        comments = service.visible_comments(current_user, item)
        history = WorkItemHistory.query.filter_by(work_item_id=item.id).order_by(
            WorkItemHistory.created_at.desc(), WorkItemHistory.id.desc()).limit(200).all()
        # Progress counts every child; the page lists the first 50 (an epic
        # can hold hundreds), the rest are on the filtered list.
        from serviceops_core.projects.models import ProjectStatus
        child_query = WorkItem.query.filter_by(parent_id=item.id)
        child_total = child_query.count()
        child_done = child_query.join(ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
            ProjectStatus.category == "done").count()
        children = child_query.order_by(WorkItem.rank, WorkItem.id).limit(CHILD_LIMIT).all()
        attachments = core.FileAttachment.query.filter_by(work_item_id=item.id).order_by(
            core.FileAttachment.created_at).all()
        worklogs = tracking.worklogs_for(item)
        timeline = sorted(
            [("comment", row.created_at, row) for row in comments] + [("history", row.created_at, row) for row in history]
            + [("worklog", row.created_at, row) for row in worklogs], key=lambda entry: entry[1], reverse=True)[:300]
        voters = service.voters(item)
        return page("projects/item.html", project, item=item, comments=comments, history=history,
                    children=children, child_total=child_total, child_done=child_done,
                    links=service.links_for(current_user, item), attachments=attachments,
                    watching=service.is_watching(item, current_user), members=service.assignable_users(project),
                    parents=_parent_choices(project), statuses=list(project.statuses), worklogs=worklogs,
                    timeline=timeline, time=tracking.time_tracking(item), fmt=tracking.format_duration,
                    voters=voters, voted=any(user.id == current_user.id for user in voters),
                    starred=service.is_starred(current_user, "work_item", item.id),
                    reactions=service.reactions_for([row.id for row in comments], current_user),
                    components=releases.components(project), versions=releases.versions(project),
                    resolutions=catalog.resolutions(project.tenant_id), link_types=catalog.link_types(project.tenant_id),
                    move_targets=operations.project_choices(current_user, exclude=project),
                    watcher_list=service.watchers(item), project_role=service.project_role(current_user, project),
                    reaction_choices=REACTIONS, now_local=core.now())

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
                                       request.form.get("lead_id", ""), request.form.get("color"),
                                       request.form.get("category"), request.form.get("default_assignee"))
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
        categories_in_use = [row[0] for row in db.session.query(Project.category).filter(
            Project.tenant_id == project.tenant_id, Project.category.isnot(None)).distinct().order_by(Project.category)]
        return page("projects/settings.html", project, tab="settings", members=members, users=users,
                    counts=service.status_counts(project), roles=PROJECT_ROLES, categories_in_use=categories_in_use)

    # --- phase 2: work item operations (B-449) ---------------------------------------------

    def _back(item, anchor=""):
        return redirect(url_for("projects.item_detail", item_key=item.key) + anchor)

    @blueprint.post("/work-items/<item_key>/worklogs")
    def item_log_work(item_key):
        item = service.item_or_404(current_user, item_key)
        tracking.log_work(current_user, item, request.form.get("spent"), request.form.get("started"),
                          request.form.get("comment", ""), request.form.get("remaining_mode", "auto"),
                          request.form.get("new_remaining"), request.form.get("reduce_by"))
        db.session.commit()
        flash(tr("Work logged on {key}.", key=item.key), "success")
        return _back(item, "#activity")

    @blueprint.post("/work-items/<item_key>/worklogs/<int:worklog_id>/edit")
    def item_worklog_edit(item_key, worklog_id):
        item = service.item_or_404(current_user, item_key)
        tracking.update_worklog(current_user, item, tracking.worklog_or_404(item, worklog_id),
                                request.form.get("spent"), request.form.get("started") or None,
                                request.form.get("comment"))
        db.session.commit()
        return _back(item, "#activity")

    @blueprint.post("/work-items/<item_key>/worklogs/<int:worklog_id>/delete")
    def item_worklog_delete(item_key, worklog_id):
        item = service.item_or_404(current_user, item_key)
        tracking.delete_worklog(current_user, item, tracking.worklog_or_404(item, worklog_id))
        db.session.commit()
        return _back(item, "#activity")

    @blueprint.post("/work-items/<item_key>/vote")
    def item_vote(item_key):
        item = service.item_or_404(current_user, item_key)
        voted = service.toggle_vote(current_user, item)
        db.session.commit()
        if _wants_json():
            return jsonify({"voted": voted, "votes": len(service.voters(item))})
        return _back(item)

    @blueprint.post("/work-items/<item_key>/star")
    def item_star(item_key):
        item = service.item_or_404(current_user, item_key)
        starred = service.toggle_star(current_user, "work_item", item)
        db.session.commit()
        if _wants_json():
            return jsonify({"starred": starred})
        return _back(item)

    @blueprint.post("/projects/<key>/star")
    def project_star(key):
        project = service.project_or_404(current_user, key)
        service.toggle_star(current_user, "project", project)
        db.session.commit()
        return redirect_internal(request.form.get("next"), url_for("projects.index"))

    @blueprint.post("/work-items/<item_key>/flag")
    def item_flag(item_key):
        item = service.item_or_404(current_user, item_key)
        flagged = not item.flagged
        service.update_item(current_user, item, {"flagged": flagged})
        note = (request.form.get("comment") or "").strip()
        if note:
            service.add_comment(current_user, item, (tr("Flag added") if flagged else tr("Flag removed")) + "\n\n" + note)
        db.session.commit()
        return _back(item)

    @blueprint.post("/work-items/<item_key>/assign-to-me")
    def item_assign_me(item_key):
        item = service.item_or_404(current_user, item_key)
        ids = [user.id for user in item.assignees]
        if current_user.id not in ids:
            service.update_item(current_user, item, {"assignee_ids": ids + [current_user.id]})
            db.session.commit()
        if _wants_json():
            return jsonify(_item_json(item))
        return _back(item)

    @blueprint.post("/work-items/<item_key>/clone")
    def item_clone(item_key):
        item = service.item_or_404(current_user, item_key)
        copy = operations.clone_item(current_user, item, request.form.get("title") or None,
                                     include_subtasks=request.form.get("subtasks") == "1",
                                     include_links=request.form.get("links") == "1",
                                     include_attachments=request.form.get("attachments") == "1")
        db.session.commit()
        flash(tr("{key} cloned to {copy}.", key=item.key, copy=copy.key), "success")
        return redirect(url_for("projects.item_detail", item_key=copy.key))

    @blueprint.post("/work-items/<item_key>/move-project")
    def item_move_project(item_key):
        item = service.item_or_404(current_user, item_key)
        target = service.project_or_404(current_user, request.form.get("project"))
        old_key = item.key
        operations.move_item(current_user, item, target, request.form.get("item_type") or None,
                             request.form.get("status_id") or None)
        db.session.commit()
        flash(tr("{old} moved to {new}.", old=old_key, new=item.key), "success")
        return redirect(url_for("projects.item_detail", item_key=item.key))

    @blueprint.get("/projects/<key>/statuses.json")
    def project_statuses(key):
        project = service.project_or_404(current_user, key)
        return jsonify([{"id": status.id, "name": status.name} for status in project.statuses])

    @blueprint.post("/work-items/<item_key>/convert")
    def item_convert(item_key):
        item = service.item_or_404(current_user, item_key)
        operations.convert_item(current_user, item, request.form.get("item_type"), request.form.get("parent_id"))
        db.session.commit()
        flash(tr("{key} converted.", key=item.key), "success")
        return _back(item)

    @blueprint.post("/work-items/<item_key>/comments/<int:comment_id>/edit")
    def item_comment_edit(item_key, comment_id):
        item = service.item_or_404(current_user, item_key)
        service.edit_comment(current_user, item, service.comment_or_404(current_user, item, comment_id),
                             request.form.get("body"))
        db.session.commit()
        return _back(item, f"#comment-{comment_id}")

    @blueprint.post("/work-items/<item_key>/comments/<int:comment_id>/delete")
    def item_comment_delete(item_key, comment_id):
        item = service.item_or_404(current_user, item_key)
        service.delete_comment(current_user, item, service.comment_or_404(current_user, item, comment_id))
        db.session.commit()
        return _back(item, "#activity")

    @blueprint.post("/work-items/<item_key>/comments/<int:comment_id>/react")
    def item_comment_react(item_key, comment_id):
        item = service.item_or_404(current_user, item_key)
        comment = service.comment_or_404(current_user, item, comment_id)
        service.toggle_reaction(current_user, item, comment, request.form.get("emoji"))
        db.session.commit()
        if _wants_json():
            return jsonify({"reactions": service.reactions_for([comment.id], current_user)[comment.id]})
        return _back(item, f"#comment-{comment_id}")

    @blueprint.post("/work-items/<item_key>/share")
    def item_share(item_key):
        item = service.item_or_404(current_user, item_key)
        message = (request.form.get("message") or "").strip()[:1000]
        shared = 0
        for user_id in request.form.getlist("user_ids")[:20]:
            user = User.query.filter_by(id=user_id if str(user_id).isdigit() else 0, tenant_id=item.tenant_id,
                                        active=True).first()
            if user and user.id != current_user.id and service.can_view(user, item.project):
                core.create_notification(
                    user.id, tr("{name} shared {key} with you", name=current_user.name, key=item.key),
                    message or item.title, tenant_id=item.tenant_id, target_type="work_item", target_id=item.id,
                    event_type="work_item.shared",
                    template_vars={"key": item.key, "summary": message or item.title, "actor": current_user.name,
                                   "project": item.project.name})
                shared += 1
        core.audit("work item shared", item.key, f"{shared} people", user_id=current_user.id,
                   tenant_id=item.tenant_id)
        db.session.commit()
        flash(tr("Shared with {count} people.", count=shared) if shared else
              tr("Nobody was notified: choose people who can see this project."), "success" if shared else "error")
        return _back(item)

    @blueprint.get("/work-items/<item_key>/print")
    def item_print(item_key):
        item = service.item_or_404(current_user, item_key)
        return page("projects/print.html", item.project, item=item,
                    comments=service.visible_comments(current_user, item), time=tracking.time_tracking(item),
                    fmt=tracking.format_duration, links=service.links_for(current_user, item))

    @blueprint.post("/projects/markdown-preview")
    def markdown_preview():
        text = (request.get_json(silent=True) or {}).get("text", "")
        if not isinstance(text, str) or len(text) > 50000:
            abort(400, description=tr("Nothing to preview."))
        return jsonify({"html": str(rich_text(text))})

    # --- releases and components ------------------------------------------------------

    @blueprint.route("/projects/<key>/releases", methods=["GET", "POST"])
    def project_releases(key):
        project = service.project_or_404(current_user, key)
        if request.method == "POST":
            action = request.form.get("action")
            version = (releases.version_or_404(project, request.form.get("version_id", type=int))
                       if request.form.get("version_id") else None)

            def other(name):
                value = request.form.get(name)
                return releases.version_or_404(project, int(value)) if value and value.isdigit() else None
            if action == "save":
                releases.save_version(current_user, project, request.form.get("name"), request.form.get("description"),
                                      request.form.get("start_date"), request.form.get("release_date"), version)
            elif action == "release" and version:
                moved = releases.release_version(current_user, project, version, request.form.get("release_date"),
                                                 other("move_to"))
                flash(tr("{name} released; {count} unfinished work items moved.", name=version.name, count=moved),
                      "success")
            elif action == "unrelease" and version:
                releases.unrelease_version(current_user, project, version)
            elif action in ("archive", "restore") and version:
                releases.set_archived(current_user, project, version, action == "archive")
            elif action == "merge" and version:
                target = other("target_id")
                if target is None:
                    abort(400, description=tr("Choose the version to merge into."))
                releases.merge_versions(current_user, project, version, target)
            elif action == "delete" and version:
                releases.delete_version(current_user, project, version, other("fix_target_id"),
                                        other("affects_target_id"))
            elif action == "move" and version:
                releases.move_version(current_user, project, version, request.form.get("direction"))
            else:
                abort(400, description=tr("Unknown release action."))
            db.session.commit()
            if action not in ("release",):
                flash(tr("Releases updated."), "success")
            return redirect(url_for("projects.project_releases", key=project.key))
        rows = releases.versions(project)
        return page("projects/releases.html", project, tab="releases", versions=rows,
                    progress={row.id: releases.version_progress(row) for row in rows})

    @blueprint.get("/projects/<key>/releases/<int:version_id>")
    def project_release(key, version_id):
        project = service.project_or_404(current_user, key)
        version = releases.version_or_404(project, version_id)
        from serviceops_core.projects.models import ProjectStatus, WorkItemFixVersion
        in_version = WorkItem.query.join(WorkItemFixVersion, WorkItemFixVersion.work_item_id == WorkItem.id).filter(
            WorkItemFixVersion.version_id == version.id)
        # The page lists the first 100; the rest are on the version-filtered list.
        items = in_version.order_by(WorkItem.item_type, WorkItem.number).limit(RELEASE_ITEM_LIMIT).all()
        # Release notes need only keys and titles of finished work.
        notes = {}
        for item_type, number, title in in_version.join(ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
                ProjectStatus.category == "done").with_entities(WorkItem.item_type, WorkItem.number, WorkItem.title).order_by(
                WorkItem.number).limit(5000):
            notes.setdefault(item_type, []).append((f"{project.key}-{number}", title))
        progress = releases.version_progress(version)
        return page("projects/release.html", project, tab="releases", version=version, items=items, notes=notes,
                    progress=progress, more=max(0, progress["total"] - len(items)),
                    list_url=url_for("projects.item_list", key=project.key, version=version.id))

    @blueprint.route("/projects/<key>/components", methods=["GET", "POST"])
    def project_components(key):
        project = service.project_or_404(current_user, key)
        if request.method == "POST":
            action = request.form.get("action")
            component = (releases.component_or_404(project, request.form.get("component_id", type=int))
                         if request.form.get("component_id") else None)
            if action == "save":
                releases.save_component(current_user, project, request.form.get("name"),
                                        request.form.get("description"), request.form.get("lead_id") or None,
                                        request.form.get("default_assignee", "project_default"), component)
            elif action == "delete" and component:
                replacement = request.form.get("replacement_id")
                releases.delete_component(current_user, project, component,
                                          releases.component_or_404(project, int(replacement))
                                          if replacement and replacement.isdigit() else None)
            else:
                abort(400, description=tr("Unknown component action."))
            db.session.commit()
            flash(tr("Components updated."), "success")
            return redirect(url_for("projects.project_components", key=project.key))
        from serviceops_core.projects.models import WorkItemComponent
        rows = releases.components(project)
        counts = dict(db.session.query(WorkItemComponent.component_id, db.func.count()).filter(
            WorkItemComponent.component_id.in_([row.id for row in rows] or [0])).group_by(
            WorkItemComponent.component_id).all())
        users = User.query.filter_by(tenant_id=current_user.tenant_id, active=True).order_by(User.name).limit(2000)
        return page("projects/components.html", project, tab="components", components=rows, counts=counts,
                    users=users, assignee_choices=COMPONENT_ASSIGNEE_CHOICES)

    @blueprint.post("/projects/<key>/bulk")
    def project_bulk(key):
        project = service.project_or_404(current_user, key)
        changed = operations.bulk_change(current_user, project, request.form.getlist("item_ids"),
                                         request.form.get("action"), request.form.get("value"))
        db.session.commit()
        flash(tr("{count} work items changed.", count=changed), "success")
        return redirect_internal(request.form.get("next"), url_for("projects.item_list", key=project.key))

    # --- your work, global create, organisation settings --------------------------------------

    @blueprint.get("/your-work")
    def your_work():
        from serviceops_core.projects.models import ProjectStar, WorkItemView
        visible_ids = service.visible_projects(current_user).with_entities(Project.id)
        worked = WorkItem.query.filter(WorkItem.project_id.in_(visible_ids), WorkItem.id.in_(
            db.session.query(WorkItemHistory.work_item_id).filter(WorkItemHistory.actor_id == current_user.id))).order_by(
            WorkItem.updated_at.desc()).limit(50).all()
        viewed = WorkItem.query.join(WorkItemView, WorkItemView.work_item_id == WorkItem.id).filter(
            WorkItemView.user_id == current_user.id, WorkItem.project_id.in_(visible_ids)).order_by(
            WorkItemView.viewed_at.desc()).limit(50).all()
        starred_items = WorkItem.query.join(ProjectStar, db.and_(ProjectStar.target_type == "work_item",
                                                                  ProjectStar.target_id == WorkItem.id)).filter(
            ProjectStar.user_id == current_user.id, WorkItem.project_id.in_(visible_ids)).order_by(WorkItem.updated_at.desc()).all()
        starred_projects = Project.query.join(ProjectStar, db.and_(ProjectStar.target_type == "project",
                                                                    ProjectStar.target_id == Project.id)).filter(
            ProjectStar.user_id == current_user.id, Project.id.in_(visible_ids)).order_by(Project.name).all()
        recent_projects = Project.query.filter(Project.id.in_(
            db.session.query(WorkItem.project_id).filter(WorkItem.id.in_([row.id for row in viewed] or [0])))).all()
        tab = request.args.get("tab", "worked")
        return page("projects/your_work.html", tab=tab if tab in ("worked", "viewed", "assigned", "starred") else "worked",
                    worked=worked, viewed=viewed, assigned=service.my_open_items(current_user, 100),
                    starred_items=starred_items, starred_projects=starred_projects,
                    recent_projects=recent_projects)

    @blueprint.get("/work-items/new")
    def global_create():
        choices = operations.project_choices(current_user)
        chosen = request.args.get("project")
        if chosen:
            project = service.project_or_404(current_user, chosen)
            return redirect(url_for("projects.new_item", key=project.key, type=request.args.get("type", "task")))
        if len(choices) == 1:
            return redirect(url_for("projects.new_item", key=choices[0].key))
        return page("projects/choose_project.html", projects=choices)

    @blueprint.route("/projects/admin", methods=["GET", "POST"])
    def projects_admin():
        if not core.role_at_least(current_user.effective_role, "admin"):
            abort(403, description=tr("Only administrators can change project settings for the organisation."))
        tenant_id = current_user.tenant_id
        if request.method == "POST":
            action = request.form.get("action")
            if action == "save_resolution":
                catalog.save_resolution(current_user, request.form.get("name"), request.form.get("description"),
                                        request.form.get("resolution_id") or None, request.form.get("is_default") == "1")
            elif action == "delete_resolution":
                catalog.delete_resolution(current_user, request.form.get("resolution_id"),
                                          request.form.get("replacement_id"))
            elif action == "save_link_type":
                catalog.save_link_type(current_user, request.form.get("name"), request.form.get("outward"),
                                       request.form.get("inward"), request.form.get("link_type_id", type=int))
            elif action == "delete_link_type":
                catalog.delete_link_type(current_user, request.form.get("link_type_id", type=int))
            elif action == "time_tracking":
                for key_name, low, high in (("PROJECTS_HOURS_PER_DAY", 1, 24), ("PROJECTS_DAYS_PER_WEEK", 1, 7)):
                    value = request.form.get(key_name, "")
                    if not value.isdigit() or not low <= int(value) <= high:
                        abort(400, description=tr("Working hours per day are 1 to 24 and days per week 1 to 7."))
                    db.session.merge(core.PlatformSetting(key=key_name, value=value, tenant_id=tenant_id))
                core.audit("update", "Project time tracking", "hours per day / days per week",
                           user_id=current_user.id, tenant_id=tenant_id)
            else:
                abort(400, description=tr("Unknown settings action."))
            db.session.commit()
            flash(tr("Project settings saved."), "success")
            return redirect(url_for("projects.projects_admin") + f"#{request.form.get('section', '')}")
        resolution_rows = catalog.resolutions(tenant_id)
        link_type_rows = catalog.link_types(tenant_id)
        db.session.commit()
        return page("projects/admin.html", resolutions=resolution_rows, link_types=link_type_rows,
                    hours_per_day=tracking.hours_per_day(), days_per_week=tracking.days_per_week())

    def linked_work_items(target_type, target_id):
        """Work items linked to an ITSM record that the viewer can see."""
        if not current_user.is_authenticated or not service.enabled():
            return []
        return service.items_linked_to_record(current_user, target_type, target_id)

    app.jinja_env.globals["linked_work_items"] = linked_work_items
    app.jinja_env.globals["rich_text"] = rich_text
    app.jinja_env.globals["is_project_starred"] = lambda project: service.is_starred(current_user, "project", project.id)

    @app.context_processor
    def projects_nav():
        if not current_user.is_authenticated:
            return {"projects_enabled": False}
        return {"projects_enabled": service.enabled()}

    app.register_blueprint(blueprint)
    from serviceops_core.web import projects_api
    projects_api.register(app)
