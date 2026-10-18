"""Project management rules (B-443): who may see and change what, work
item numbering, field validation, history and notifications.

Access, in order:
- users of another tenant, inactive users: nothing;
- tenant administrators: administer every project;
- project members: their project role (admin, member or viewer);
- projects open to the organisation: everyone else may read ("reader");
- private projects: invisible (callers answer 404, never 403).

Members and admins edit work items; viewers comment; readers only read.
"""
import re
from datetime import date, timedelta

from flask import abort, current_app
from sqlalchemy import func, or_

import app as core
from serviceops_core.localization import tr
from serviceops_core.request_cache import request_cache
from serviceops_core.projects.models import (
    DEFAULT_STATUSES, ITEM_TYPES, PRIORITIES, PROJECT_ROLES, STATUS_CATEGORIES, VISIBILITIES,
    Project, ProjectMember, ProjectStatus, WorkItem, WorkItemAssignee, WorkItemComment, WorkItemHistory,
    WorkItemLabel, WorkItemLink, WorkItemWatcher,
)
from serviceops_models import User, db, now

KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9]{1,9}$")
ITEM_KEY_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9]{1,9})-(\d{1,9})$")
LABEL_PATTERN = re.compile(r"^[^\s,]{1,60}$")
CREATOR_LEVELS = ("everyone", "agent", "manager", "admin")
RANK_STEP = 1024.0
EDIT_ROLES = ("admin", "member")
COMMENT_ROLES = ("admin", "member", "viewer")
MAX_ASSIGNEES = 10


# --- settings and access -----------------------------------------------------

def enabled():
    return core.setting_bool("PROJECTS_ENABLED")


def require_enabled():
    if not enabled():
        abort(404)


def can_create_projects(user):
    if not user.is_authenticated or not enabled():
        return False
    level = core.setting_value("PROJECTS_CREATORS", "manager")
    level = level if level in CREATOR_LEVELS else "manager"
    if level == "everyone":
        return True
    return core.role_at_least(user.effective_role, level)


def _tenant_admin(user):
    return core.role_at_least(user.effective_role, "admin")


def _role_cache():
    """Per-request memo of project roles; pages check the same role many times."""
    cache = request_cache()
    return cache.setdefault("project_roles", {}) if cache is not None else None


def _forget_roles():
    cache = request_cache()
    if cache is not None:
        cache.pop("project_roles", None)


def project_role(user, project):
    """admin, member, viewer, reader (open project, not a member) or None."""
    cache = _role_cache()
    cache_key = (getattr(user, "id", None), project.id, project.visibility,
                 getattr(user, "effective_role", None), getattr(user, "active", False),
                 getattr(user, "tenant_id", None), project.tenant_id)
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    role = _project_role(user, project)
    if cache is not None:
        cache[cache_key] = role
    return role


def _project_role(user, project):
    if not user or not getattr(user, "is_authenticated", False) or not user.active:
        return None
    if project.tenant_id != user.tenant_id:
        return None
    if _tenant_admin(user):
        return "admin"
    member = ProjectMember.query.filter_by(project_id=project.id, user_id=user.id).populate_existing().first()
    if member:
        return member.role
    if project.visibility == "open":
        return "reader"
    return None


def can_view(user, project):
    return project_role(user, project) is not None


def can_edit(user, project):
    return project_role(user, project) in EDIT_ROLES and project.archived_at is None


def can_comment(user, project):
    return project_role(user, project) in COMMENT_ROLES and project.archived_at is None


def can_administer(user, project):
    return project_role(user, project) == "admin"


def visible_projects(user, include_archived=False):
    query = Project.query.filter(Project.tenant_id == user.tenant_id)
    if not include_archived:
        query = query.filter(Project.archived_at.is_(None))
    if not _tenant_admin(user):
        member_ids = db.session.query(ProjectMember.project_id).filter(ProjectMember.user_id == user.id)
        query = query.filter(or_(Project.visibility == "open", Project.id.in_(member_ids)))
    return query


def project_or_404(user, key):
    project = Project.query.filter(Project.tenant_id == user.tenant_id,
                                   Project.key == (key or "").upper()).first()
    if not project or not can_view(user, project):
        abort(404)
    return project


def parse_item_key(text):
    match = ITEM_KEY_PATTERN.match((text or "").strip())
    return (match.group(1).upper(), int(match.group(2))) if match else None


def item_or_404(user, item_key):
    item = find_visible_item(user, item_key)
    if item is None:
        abort(404)
    return item


def find_visible_item(user, item_key):
    parsed = parse_item_key(item_key)
    if not parsed:
        return None
    project = Project.query.filter_by(tenant_id=user.tenant_id, key=parsed[0]).first()
    if project and can_view(user, project):
        item = WorkItem.query.filter_by(project_id=project.id, number=parsed[1]).first()
        if item is not None:
            return item
    # An old key belongs to the destination item, even if access to its
    # original project has changed. resolve_alias checks destination access.
    from serviceops_core.projects.operations import resolve_alias
    return resolve_alias(user, item_key)


def require_edit(user, project):
    if not can_edit(user, project):
        abort(403, description=tr("You can view this project but not change its work items."))


def require_admin(user, project):
    if not can_administer(user, project):
        abort(403, description=tr("Only project administrators can change project settings."))


# --- projects ------------------------------------------------------------------

def suggest_key(name):
    words = re.findall(r"[A-Za-z0-9]+", name or "")
    letters = "".join(word[0] for word in words).upper() if len(words) > 1 else "".join(words).upper()[:4]
    letters = re.sub(r"^[0-9]+", "", letters)[:10]
    return letters if len(letters) >= 2 else (letters + "PRJ")[:3]


def _clean_text(value, limit, label, required=False):
    if value is not None and not isinstance(value, str):
        abort(400, description=tr("{label} must be text.", label=label))
    text = (value or "").strip()
    if required and not text:
        abort(400, description=tr("{label} is required.", label=label))
    if len(text) > limit:
        abort(400, description=tr("{label} can have at most {limit} characters.", label=label, limit=limit))
    return text


def _active_tenant_user(user_id, tenant_id, label):
    if user_id in (None, ""):
        return None
    user_id = _parse_number(user_id, label, integer=True, maximum=2**31 - 1)
    user = User.query.filter_by(id=user_id, tenant_id=tenant_id, active=True).first()
    if not user:
        abort(400, description=tr("{label} is not an active user in this organisation.", label=label))
    return user


def create_project(actor, key, name, description="", visibility="private", lead_id=None, color=None):
    if not can_create_projects(actor):
        abort(403, description=tr("You are not allowed to create projects."))
    name = _clean_text(name, 160, tr("Project name"), required=True)
    key = (key or "").strip().upper() or suggest_key(name)
    if not KEY_PATTERN.match(key):
        abort(400, description=tr("A project key has 2 to 10 letters or digits and starts with a letter."))
    if Project.query.filter_by(tenant_id=actor.tenant_id, key=key).first():
        abort(409, description=tr("The project key {key} is already in use.", key=key))
    if visibility not in VISIBILITIES:
        abort(400, description=tr("Choose private or open visibility."))
    lead = _active_tenant_user(lead_id, actor.tenant_id, tr("Project lead")) or actor
    project = Project(tenant_id=actor.tenant_id, key=key, name=name,
                      description=_clean_text(description, 10000, tr("Description")),
                      visibility=visibility, lead_id=lead.id, created_by_id=actor.id,
                      color=_clean_color(color))
    db.session.add(project)
    db.session.flush()
    for position, (status_name, category) in enumerate(DEFAULT_STATUSES):
        db.session.add(ProjectStatus(tenant_id=actor.tenant_id, project_id=project.id, name=status_name,
                                     category=category, position=position))
    for user in {actor.id: actor, lead.id: lead}.values():
        db.session.add(ProjectMember(tenant_id=actor.tenant_id, project_id=project.id, user_id=user.id, role="admin"))
    db.session.flush()
    core.audit("project created", key, f"name={name}; visibility={visibility}", user_id=actor.id,
               tenant_id=actor.tenant_id)
    return project


def _clean_color(value):
    value = (value or "").strip()
    return value if re.fullmatch(r"#[0-9a-fA-F]{6}", value) else "#0f6e7a"


def update_project(actor, project, name=None, description=None, visibility=None, lead_id=None, color=None,
                   category=None, default_assignee=None):
    require_admin(actor, project)
    changes = []
    if category is not None:
        project.category = _clean_text(category, 60, tr("Category")) or None
        changes.append("category")
    if default_assignee is not None:
        from serviceops_core.projects.models import DEFAULT_ASSIGNEE_CHOICES
        if default_assignee not in DEFAULT_ASSIGNEE_CHOICES:
            abort(400, description=tr("Choose a default assignee."))
        project.default_assignee = default_assignee
        changes.append("default assignee")
    if name is not None:
        project.name = _clean_text(name, 160, tr("Project name"), required=True)
        changes.append("name")
    if description is not None:
        project.description = _clean_text(description, 10000, tr("Description"))
        changes.append("description")
    if visibility is not None:
        if visibility not in VISIBILITIES:
            abort(400, description=tr("Choose private or open visibility."))
        project.visibility = visibility
        changes.append("visibility")
    if lead_id is not None:
        lead = _active_tenant_user(lead_id, project.tenant_id, tr("Project lead"))
        project.lead_id = lead.id if lead else None
        changes.append("lead")
    if color is not None:
        project.color = _clean_color(color)
    core.audit("project updated", project.key, ", ".join(changes) or "no changes", user_id=actor.id,
               tenant_id=project.tenant_id)


def set_archived(actor, project, archived):
    require_admin(actor, project)
    project.archived_at = now() if archived else None
    core.audit("project archived" if archived else "project restored", project.key, "", user_id=actor.id,
               tenant_id=project.tenant_id)


def set_member(actor, project, user_id, role):
    require_admin(actor, project)
    if role not in PROJECT_ROLES:
        abort(400, description=tr("Choose admin, member or viewer."))
    user = _active_tenant_user(user_id, project.tenant_id, tr("Member"))
    if not user:
        abort(400, description=tr("Choose a user."))
    # Serialize role changes and removals on the same project so concurrent
    # demotions cannot both remove its last administrator.
    Project.query.filter_by(id=project.id).with_for_update().one()
    member = ProjectMember.query.filter_by(project_id=project.id, user_id=user.id).populate_existing().first()
    if member and member.role == "admin" and role != "admin":
        if ProjectMember.query.filter_by(project_id=project.id, role="admin").count() <= 1:
            abort(409, description=tr("A project needs at least one administrator."))
    if member:
        member.role = role
    else:
        db.session.add(ProjectMember(tenant_id=project.tenant_id, project_id=project.id, user_id=user.id, role=role))
    _forget_roles()
    core.audit("project member set", project.key, f"user={user.username}; role={role}", user_id=actor.id,
               tenant_id=project.tenant_id)
    return user


def remove_member(actor, project, user_id):
    require_admin(actor, project)
    Project.query.filter_by(id=project.id).with_for_update().one()
    member = ProjectMember.query.filter_by(project_id=project.id, user_id=user_id).populate_existing().first()
    if not member:
        abort(404)
    admins = ProjectMember.query.filter_by(project_id=project.id, role="admin").count()
    if member.role == "admin" and admins <= 1:
        abort(409, description=tr("A project needs at least one administrator."))
    username = member.user.username
    db.session.delete(member)
    _forget_roles()
    core.audit("project member removed", project.key, f"user={username}", user_id=actor.id,
               tenant_id=project.tenant_id)


# --- statuses ----------------------------------------------------------------------

def add_status(actor, project, name, category):
    require_admin(actor, project)
    name = _clean_text(name, 60, tr("Status name"), required=True)
    if category not in STATUS_CATEGORIES:
        abort(400, description=tr("Choose To do, In progress or Done."))
    if ProjectStatus.query.filter(ProjectStatus.project_id == project.id,
                                  func.lower(ProjectStatus.name) == name.lower()).first():
        abort(409, description=tr("This project already has a status called {name}.", name=name))
    position = (db.session.query(func.max(ProjectStatus.position)).filter_by(project_id=project.id).scalar() or 0) + 1
    status = ProjectStatus(tenant_id=project.tenant_id, project_id=project.id, name=name, category=category,
                           position=position)
    db.session.add(status)
    db.session.flush()
    core.audit("project status added", project.key, name, user_id=actor.id, tenant_id=project.tenant_id)
    return status


def status_or_404(project, status_id):
    status_id = _parse_number(status_id, tr("Status"), integer=True, maximum=2**31 - 1)
    status = ProjectStatus.query.filter_by(id=status_id, project_id=project.id).first()
    if not status:
        abort(400, description=tr("That status does not belong to this project."))
    return status


def update_status(actor, project, status, name=None, category=None, wip_limit=None):
    require_admin(actor, project)
    if name is not None:
        name = _clean_text(name, 60, tr("Status name"), required=True)
        clash = ProjectStatus.query.filter(ProjectStatus.project_id == project.id, ProjectStatus.id != status.id,
                                           func.lower(ProjectStatus.name) == name.lower()).first()
        if clash:
            abort(409, description=tr("This project already has a status called {name}.", name=name))
        status.name = name
    if category is not None:
        if category not in STATUS_CATEGORIES:
            abort(400, description=tr("Choose To do, In progress or Done."))
        status.category = category
    if wip_limit is not None:
        if wip_limit == "":
            status.wip_limit = None
        else:
            try:
                limit = int(wip_limit)
            except (TypeError, ValueError):
                abort(400, description=tr("A work-in-progress limit is a whole number."))
            if not 0 < limit <= 999:
                abort(400, description=tr("A work-in-progress limit is between 1 and 999."))
            status.wip_limit = limit
    core.audit("project status updated", project.key, status.name, user_id=actor.id, tenant_id=project.tenant_id)


def move_status(actor, project, status, direction):
    require_admin(actor, project)
    ordered = list(project.statuses)
    index = ordered.index(status)
    other = index + (-1 if direction == "up" else 1)
    if 0 <= other < len(ordered):
        ordered[index], ordered[other] = ordered[other], ordered[index]
        for position, row in enumerate(ordered):
            row.position = position


def delete_status(actor, project, status, replacement):
    require_admin(actor, project)
    if len(project.statuses) <= 1:
        abort(409, description=tr("A project needs at least one status."))
    if replacement is None or replacement.id == status.id:
        abort(400, description=tr("Choose another status for the work items in {name}.", name=status.name))
    moved = WorkItem.query.filter_by(project_id=project.id, status_id=status.id).update(
        {"status_id": replacement.id}, synchronize_session=False)
    db.session.delete(status)
    core.audit("project status deleted", project.key, f"{status.name}; {moved} items moved to {replacement.name}",
               user_id=actor.id, tenant_id=project.tenant_id)


# --- work items ----------------------------------------------------------------------

def log_work_item_history(item, actor, field, old, new):
    db.session.add(WorkItemHistory(tenant_id=item.tenant_id, work_item_id=item.id,
                                   actor_id=actor.id if actor else None, field=field,
                                   old_value=None if old is None else str(old)[:4000],
                                   new_value=None if new is None else str(new)[:4000]))


def _watch(item, user):
    if not WorkItemWatcher.query.filter_by(work_item_id=item.id, user_id=user.id).first():
        db.session.add(WorkItemWatcher(tenant_id=item.tenant_id, work_item_id=item.id, user_id=user.id))


def watchers(item):
    return User.query.join(WorkItemWatcher, WorkItemWatcher.user_id == User.id).filter(
        WorkItemWatcher.work_item_id == item.id, User.active.is_(True)).all()


def is_watching(item, user):
    return WorkItemWatcher.query.filter_by(work_item_id=item.id, user_id=user.id).first() is not None


def set_watching(actor, item, watching):
    if watching:
        _watch(item, actor)
    else:
        WorkItemWatcher.query.filter_by(work_item_id=item.id, user_id=actor.id).delete()


def _notify(users, actor, item, title, body, event_type):
    """Notify each user once, never the actor, and only users who can still
    see the project (membership can change after someone started watching)."""
    seen = set()
    for user in users:
        if not user or user.id in seen or (actor and user.id == actor.id):
            continue
        seen.add(user.id)
        if not can_view(user, item.project):
            continue
        core.create_notification(user.id, title, body, tenant_id=item.tenant_id, target_type="work_item",
                                 target_id=item.id, event_type=event_type,
                                 template_vars={"key": item.key, "summary": item.title,
                                                "actor": actor.name if actor else "", "project": item.project.name})


def _parse_date(value, label):
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        abort(400, description=tr("{label} must be a date (YYYY-MM-DD).", label=label))


def _parse_number(value, label, integer=False, maximum=100000):
    if value in (None, ""):
        return None
    if isinstance(value, bool) or (integer and isinstance(value, float) and not value.is_integer()):
        abort(400, description=tr("{label} must be a whole number.", label=label))
    try:
        number = int(value) if integer else float(value)
    except (TypeError, ValueError, OverflowError):
        abort(400, description=tr("{label} must be a number.", label=label))
    if number < 0 or number > maximum or number != number:
        abort(400, description=tr("{label} must be between 0 and {maximum}.", label=label, maximum=maximum))
    return number


def _parse_labels(value):
    if value is None:
        return None
    if not isinstance(value, (str, list, tuple)) or (
        isinstance(value, (list, tuple)) and any(not isinstance(label, str) for label in value)
    ):
        abort(400, description=tr("Labels must be text or a list of text values."))
    raw = value if isinstance(value, (list, tuple)) else re.split(r"[,\s]+", value)
    labels = []
    for label in raw:
        label = str(label).strip()
        if not label:
            continue
        if not LABEL_PATTERN.match(label):
            abort(400, description=tr("Labels have no spaces or commas and at most 60 characters."))
        if label.lower() not in {existing.lower() for existing in labels}:
            labels.append(label)
    if len(labels) > 20:
        abort(400, description=tr("A work item can have at most 20 labels."))
    return labels


def _parse_assignees(value, project):
    if value is None:
        return None
    raw = value if isinstance(value, (list, tuple)) else [part for part in str(value).split(",") if part.strip()]
    users = []
    for user_id in raw:
        user = _active_tenant_user(user_id, project.tenant_id, tr("Assignee"))
        if user and user.id not in {existing.id for existing in users}:
            if project_role(user, project) not in EDIT_ROLES:
                abort(400, description=tr("{name} is not a member who can work on this project.", name=user.name))
            users.append(user)
    if len(users) > MAX_ASSIGNEES:
        abort(400, description=tr("A work item can have at most {count} assignees.", count=MAX_ASSIGNEES))
    return users


def _project_rows(model, project, raw, label):
    """Components or versions of this project from a list of ids (or a
    comma-separated string); unknown ids are refused."""
    if raw is None:
        return None
    raw = raw if isinstance(raw, (list, tuple)) else [part for part in str(raw).split(",") if part.strip()]
    rows = []
    for value in raw:
        value = _parse_number(value, label, integer=True, maximum=2**31 - 1)
        row = model.query.filter_by(id=value, project_id=project.id).first()
        if not row:
            abort(400, description=tr("{label} must belong to this project.", label=label))
        if row not in rows:
            rows.append(row)
    return rows


def _replace_links(model, item, column, rows, actor, field):
    old = sorted(getattr(row, "name") for row in getattr(item, field))
    new = sorted(row.name for row in rows)
    if old != new:
        model.query.filter_by(work_item_id=item.id).delete()
        for row in rows:
            db.session.add(model(tenant_id=item.tenant_id, work_item_id=item.id, **{column: row.id}))
        log_work_item_history(item, actor, field.replace("_", " "), ", ".join(old), ", ".join(new))


def _resolve(item, actor, status, resolution_id=None):
    """Entering a done status sets a resolution (the chosen one or the
    tenant default); leaving done clears it, as in Jira."""
    from serviceops_core.projects import catalog
    if status.category == "done":
        resolution = (catalog.resolution_or_400(item.tenant_id, resolution_id) if resolution_id not in (None, "")
                      else item.resolution or catalog.default_resolution(item.tenant_id))
        if resolution and resolution.id != item.resolution_id:
            log_work_item_history(item, actor, "resolution", item.resolution.name if item.resolution else None,
                                  resolution.name)
            item.resolution_id, item.resolution = resolution.id, resolution
        item.resolved_at = item.resolved_at or now()
    else:
        if item.resolution_id:
            log_work_item_history(item, actor, "resolution", item.resolution.name if item.resolution else None, None)
        item.resolution_id, item.resolution, item.resolved_at = None, None, None


def hierarchy_rows(item, ancestors=False):
    """Return same-project hierarchy members using a cycle-safe recursive query.

    UNION (not UNION ALL) bounds even damaged cyclic data. No Python recursion
    or product depth cap is used, and tenant/project scope applies to every edge.
    """
    try:
        tree = db.session.query(WorkItem.id, WorkItem.parent_id).filter_by(
            id=item.id, project_id=item.project_id, tenant_id=item.tenant_id).cte(recursive=True)
        edge = WorkItem.id == tree.c.parent_id if ancestors else WorkItem.parent_id == tree.c.id
        tree = tree.union(db.session.query(WorkItem.id, WorkItem.parent_id).join(tree, edge).filter(
            WorkItem.project_id == item.project_id, WorkItem.tenant_id == item.tenant_id))
        return WorkItem.query.join(tree, WorkItem.id == tree.c.id).filter(WorkItem.id != item.id).populate_existing().all()
    except Exception:
        current_app.logger.error("Project hierarchy query failed for work item %s", item.id)
        raise


def ancestor_path(item):
    """Root-first breadcrumbs, restricted to the current project and tenant."""
    try:
        rows = {row.id: row for row in hierarchy_rows(item, ancestors=True)}
        path, seen, parent_id = [], {item.id}, item.parent_id
        while parent_id in rows and parent_id not in seen:
            seen.add(parent_id)
            parent = rows[parent_id]
            path.append(parent)
            parent_id = parent.parent_id
        return list(reversed(path))
    except Exception:
        current_app.logger.error("Project ancestor path failed for work item %s", item.id)
        raise


def _validate_parent(project, item_type, parent_id, item=None):
    if parent_id in (None, ""):
        if item_type == "subtask":
            abort(400, description=tr("A subtask needs a parent work item."))
        return None
    parent = WorkItem.query.filter_by(id=_parse_number(parent_id, tr("Parent"), integer=True, maximum=2**31),
                                      project_id=project.id, tenant_id=project.tenant_id).populate_existing().first()
    if not parent:
        abort(400, description=tr("The parent must be a work item in this project."))
    if item is not None and parent.id == item.id:
        abort(400, description=tr("A work item cannot be its own parent."))
    if item_type == "epic":
        abort(400, description=tr("An epic cannot have a parent."))
    if item_type == "subtask":
        if parent.item_type == "epic":
            abort(400, description=tr("A subtask belongs to a story, task, bug or another subtask."))
    elif parent.item_type != "epic":
        abort(400, description=tr("Stories, tasks and bugs can only belong to an epic."))
    if item is not None and any(row.id == item.id for row in hierarchy_rows(parent, ancestors=True)):
        abort(400, description=tr("A work item cannot be placed beneath one of its descendants."))
    return parent


def _next_rank(project_id, status_id):
    top = db.session.query(func.max(WorkItem.rank)).filter_by(project_id=project_id, status_id=status_id).scalar()
    return (top or 0.0) + RANK_STEP


def default_status(project):
    statuses = list(project.statuses)
    return next((status for status in statuses if status.category == "todo"), statuses[0])


def create_item(actor, project, title, item_type="task", description="", status_id=None, priority="medium",
                assignee_ids=None, labels=None, parent_id=None, start_date=None, due_date=None,
                story_points=None, estimate_minutes=None, component_ids=None, fix_version_ids=None,
                affects_version_ids=None, environment="", resolution_id=None, flagged=False, remaining_minutes=None):
    require_edit(actor, project)
    if item_type not in ITEM_TYPES:
        abort(400, description=tr("Choose a work item type."))
    if priority not in PRIORITIES:
        abort(400, description=tr("Choose a priority."))
    title = _clean_text(title, 255, tr("Title"), required=True)
    description = _clean_text(description, 50000, tr("Description"))
    status = status_or_404(project, status_id) if status_id not in (None, "") else default_status(project)
    Project.query.filter_by(id=project.id).with_for_update().one()
    parent = _validate_parent(project, item_type, parent_id)
    assignees = _parse_assignees(assignee_ids, project) or []
    labels = _parse_labels(labels) or []
    from serviceops_core.projects.models import (ProjectComponent, ProjectVersion, WorkItemAffectsVersion,
                                                 WorkItemComponent, WorkItemFixVersion)
    components = _project_rows(ProjectComponent, project, component_ids, tr("Component")) or []
    fix_versions = _project_rows(ProjectVersion, project, fix_version_ids, tr("Fix version")) or []
    affects_versions = _project_rows(ProjectVersion, project, affects_version_ids, tr("Affects version")) or []
    if not assignees and assignee_ids is None:
        from serviceops_core.projects import releases
        assignees = [user for user in releases.default_assignees(project, components)
                     if project_role(user, project) in EDIT_ROLES]
    environment = _clean_text(environment, 10000, tr("Environment"))
    start, due = _parse_date(start_date, tr("Start date")), _parse_date(due_date, tr("Due date"))
    if start and due and due < start:
        abort(400, description=tr("The due date cannot be before the start date."))
    # Lock the project row so two people creating items at once get
    # different numbers.
    locked = Project.query.filter_by(id=project.id).with_for_update().populate_existing().one()
    number = locked.next_number
    locked.next_number = number + 1
    item = WorkItem(tenant_id=project.tenant_id, project_id=project.id, number=number, item_type=item_type,
                    title=title, description=description, status_id=status.id, priority=priority,
                    reporter_id=actor.id, parent_id=parent.id if parent else None,
                    rank=_next_rank(project.id, status.id), start_date=start, due_date=due,
                    story_points=_parse_number(story_points, tr("Story points"), maximum=1000),
                    estimate_minutes=_parse_number(estimate_minutes, tr("Estimate"), integer=True, maximum=10**6),
                    environment=environment, flagged=bool(flagged))
    item.remaining_minutes = (item.estimate_minutes if remaining_minutes is None else
                              _parse_number(remaining_minutes, tr("Remaining estimate"), integer=True, maximum=10**7))
    db.session.add(item)
    db.session.flush()
    for rows, model, column in ((components, WorkItemComponent, "component_id"),
                                (fix_versions, WorkItemFixVersion, "version_id"),
                                (affects_versions, WorkItemAffectsVersion, "version_id")):
        for row in rows:
            db.session.add(model(tenant_id=item.tenant_id, work_item_id=item.id, **{column: row.id}))
    if status.category == "done":
        _resolve(item, actor, status, resolution_id)
    for user in assignees:
        db.session.add(WorkItemAssignee(tenant_id=item.tenant_id, work_item_id=item.id, user_id=user.id))
    for label in labels:
        db.session.add(WorkItemLabel(tenant_id=item.tenant_id, work_item_id=item.id, label=label))
    _watch(item, actor)
    for user in assignees:
        _watch(item, user)
    log_work_item_history(item, actor, "created", None, item_type)
    db.session.flush()
    db.session.expire(item, ["assignees", "labels", "components", "fix_versions", "affects_versions"])
    _notify(assignees, actor, item, tr("{name} assigned {key} to you", name=actor.name, key=item.key),
            item.title, "work_item.assigned")
    from serviceops_core.projects import automation
    automation.dispatch(item, 'created')
    return item


EDITABLE_FIELDS = ("title", "description", "item_type", "status_id", "priority", "assignee_ids", "labels",
                   "parent_id", "start_date", "due_date", "story_points", "estimate_minutes", "remaining_minutes",
                   "component_ids", "fix_version_ids", "affects_version_ids", "environment", "resolution_id",
                   "reporter_id", "flagged")


def update_item(actor, item, changes):
    """Apply the given field changes; unknown keys are ignored. Records one
    history row per changed field and notifies assignees and watchers."""
    project = item.project
    require_edit(actor, project)
    with db.session.no_autoflush:
        Project.query.filter_by(id=project.id).with_for_update().populate_existing().one()
        db.session.refresh(item, [column.key for column in WorkItem.__table__.columns])
        if item.project_id != project.id or item.tenant_id != project.tenant_id:
            abort(409, description=tr("This work item moved to another project. Reload it before making changes."))
        db.session.expire(item, ["status"])
    _forget_roles()
    require_edit(actor, project)
    changes = {key: value for key, value in changes.items() if key in EDITABLE_FIELDS}
    if "parent_id" in changes or "item_type" in changes:
        Project.query.filter_by(id=project.id).with_for_update().one()
        db.session.refresh(item, ["parent_id", "item_type"])
    old_status = item.status
    if "title" in changes:
        _set(item, actor, "title", _clean_text(changes["title"], 255, tr("Title"), required=True))
    if "description" in changes:
        _set(item, actor, "description", _clean_text(changes["description"], 50000, tr("Description")))
    if "item_type" in changes:
        new_type = changes["item_type"]
        if new_type not in ITEM_TYPES:
            abort(400, description=tr("Choose a work item type."))
        if new_type != item.item_type and item.children and (new_type == "epic" or item.item_type == "epic"):
            abort(409, description=tr("Move or remove this item's children before changing its type."))
        _validate_parent(project, new_type, changes.get("parent_id", item.parent_id), item)
        _set(item, actor, "item_type", new_type)
    if "parent_id" in changes:
        parent = _validate_parent(project, item.item_type, changes["parent_id"], item)
        new_parent = parent.id if parent else None
        if new_parent != item.parent_id:
            log_work_item_history(item, actor, "parent", item.parent.key if item.parent else None, parent.key if parent else None)
            item.parent_id = new_parent
    if "priority" in changes:
        if changes["priority"] not in PRIORITIES:
            abort(400, description=tr("Choose a priority."))
        _set(item, actor, "priority", changes["priority"])
    if "status_id" in changes:
        status = status_or_404(project, changes["status_id"])
        if status.id != item.status_id:
            log_work_item_history(item, actor, "status", item.status.name, status.name)
            item.status_id = status.id
            item.status = status
            item.rank = _next_rank(project.id, status.id)
            _resolve(item, actor, status, changes.get("resolution_id"))
    elif changes.get("resolution_id") not in (None, "") and item.status.category == "done":
        _resolve(item, actor, item.status, changes["resolution_id"])
    if "environment" in changes:
        _set(item, actor, "environment", _clean_text(changes["environment"], 10000, tr("Environment")))
    if "reporter_id" in changes and changes["reporter_id"] not in (None, ""):
        if not can_administer(actor, project):
            abort(403, description=tr("Only project administrators can change the reporter."))
        reporter = _active_tenant_user(changes["reporter_id"], project.tenant_id, tr("Reporter"))
        if reporter.id != item.reporter_id:
            log_work_item_history(item, actor, "reporter", item.reporter.name if item.reporter else None, reporter.name)
            item.reporter_id = reporter.id
    if "flagged" in changes:
        flagged = str(changes["flagged"]).lower() in ("1", "true", "on", "yes")
        if flagged != item.flagged:
            log_work_item_history(item, actor, "flag", "Flagged" if item.flagged else None, "Flagged" if flagged else None)
            item.flagged = flagged
    if "remaining_minutes" in changes:
        _set(item, actor, "remaining_minutes",
             _parse_number(changes["remaining_minutes"], tr("Remaining estimate"), integer=True, maximum=10**7))
    from serviceops_core.projects.models import (ProjectComponent, ProjectVersion, WorkItemAffectsVersion,
                                                 WorkItemComponent, WorkItemFixVersion)
    for key, model, row_model, column, field, label in (
            ("component_ids", WorkItemComponent, ProjectComponent, "component_id", "components", tr("Component")),
            ("fix_version_ids", WorkItemFixVersion, ProjectVersion, "version_id", "fix_versions", tr("Fix version")),
            ("affects_version_ids", WorkItemAffectsVersion, ProjectVersion, "version_id", "affects_versions",
             tr("Affects version"))):
        if key in changes:
            _replace_links(model, item, column, _project_rows(row_model, project, changes[key], label) or [], actor,
                           field)
    start = _parse_date(changes["start_date"], tr("Start date")) if "start_date" in changes else item.start_date
    due = _parse_date(changes["due_date"], tr("Due date")) if "due_date" in changes else item.due_date
    if start and due and due < start:
        abort(400, description=tr("The due date cannot be before the start date."))
    if "start_date" in changes:
        _set(item, actor, "start_date", start)
    if "due_date" in changes:
        _set(item, actor, "due_date", due)
    if "story_points" in changes:
        _set(item, actor, "story_points", _parse_number(changes["story_points"], tr("Story points"), maximum=1000))
    if "estimate_minutes" in changes:
        estimate = _parse_number(changes["estimate_minutes"], tr("Estimate"), integer=True, maximum=10**6)
        if item.remaining_minutes is None or (item.remaining_minutes == item.estimate_minutes and not item.spent_minutes
                                              and "remaining_minutes" not in changes):
            item.remaining_minutes = estimate
        _set(item, actor, "estimate_minutes", estimate)
    if "labels" in changes:
        labels = _parse_labels(changes["labels"]) or []
        old = [row.label for row in item.labels]
        if sorted(old) != sorted(labels):
            WorkItemLabel.query.filter_by(work_item_id=item.id).delete()
            for label in labels:
                db.session.add(WorkItemLabel(tenant_id=item.tenant_id, work_item_id=item.id, label=label))
            log_work_item_history(item, actor, "labels", ", ".join(old), ", ".join(labels))
    added = []
    if "assignee_ids" in changes:
        assignees = _parse_assignees(changes["assignee_ids"], project) or []
        old_ids = {user.id for user in item.assignees}
        new_ids = {user.id for user in assignees}
        if old_ids != new_ids:
            WorkItemAssignee.query.filter_by(work_item_id=item.id).delete()
            for user in assignees:
                db.session.add(WorkItemAssignee(tenant_id=item.tenant_id, work_item_id=item.id, user_id=user.id))
                _watch(item, user)
            log_work_item_history(item, actor, "assignees", ", ".join(sorted(u.name for u in item.assignees)),
                     ", ".join(sorted(u.name for u in assignees)))
            added = [user for user in assignees if user.id not in old_ids]
    item.updated_at = now()
    db.session.flush()
    db.session.expire(item, ["assignees", "labels", "components", "fix_versions", "affects_versions"])
    _notify(added, actor, item, tr("{name} assigned {key} to you", name=actor.name, key=item.key), item.title,
            "work_item.assigned")
    if item.status_id != old_status.id:
        _notify(watchers(item), actor, item,
                tr("{key} moved to {status}", key=item.key, status=item.status.name),
                tr("{name} moved {key} from {old} to {new}.", name=actor.name, key=item.key, old=old_status.name,
                   new=item.status.name), "work_item.transitioned")
    from serviceops_core.projects import sprints
    sprints.capture(actor, item)
    from serviceops_core.projects import automation
    automation.dispatch(item, 'transitioned' if item.status_id != old_status.id else 'updated')
    return item


def _set(item, actor, field, value):
    old = getattr(item, field)
    if old != value:
        log_work_item_history(item, actor, field, old, value)
        setattr(item, field, value)


def move_item(actor, item, status_id=None, before_id=None, after_id=None):
    """Board drag: change status (optional) and place the item between two
    neighbours in the target column (before_id is above, after_id below)."""
    if status_id not in (None, "") and _parse_number(status_id, tr("Status"), integer=True, maximum=2**31 - 1) != item.status_id:
        update_item(actor, item, {"status_id": status_id})
    else:
        require_edit(actor, item.project)

    def neighbour(raw):
        if raw in (None, ""):
            return None
        row = WorkItem.query.filter_by(id=_parse_number(raw, "id", integer=True, maximum=2**31),
                                       project_id=item.project_id).first()
        return row if row and row.id != item.id else None
    above, below = neighbour(before_id), neighbour(after_id)
    if above and below:
        item.rank = (above.rank + below.rank) / 2
        if abs(above.rank - below.rank) < 1e-6:
            _renumber(item.project_id, item.status_id)
            db.session.refresh(above)
            db.session.refresh(below)
            item.rank = (above.rank + below.rank) / 2
    elif above:
        item.rank = above.rank + RANK_STEP
    elif below:
        item.rank = below.rank - RANK_STEP
    return item


def _renumber(project_id, status_id):
    rows = WorkItem.query.filter_by(project_id=project_id, status_id=status_id).order_by(WorkItem.rank, WorkItem.id)
    for index, row in enumerate(rows):
        row.rank = (index + 1) * RANK_STEP


def delete_item(actor, item):
    project = item.project
    with db.session.no_autoflush:
        Project.query.filter_by(id=project.id).with_for_update().populate_existing().one()
        db.session.refresh(item, [column.key for column in WorkItem.__table__.columns])
        if item.project_id != project.id or item.tenant_id != project.tenant_id:
            abort(409, description=tr("This work item moved to another project. Reload it before making changes."))
        db.session.expire(item, ["parent", "children"])
    _forget_roles()
    if not can_administer(actor, project) and actor.id != item.reporter_id:
        abort(403, description=tr("Only the reporter or a project administrator can delete a work item."))
    require_edit(actor, project)
    from serviceops_core.projects import sprints
    from serviceops_core.projects.models import ProjectSprintItem
    sprints.detach_for_removal(actor, item)
    ProjectSprintItem.query.filter_by(work_item_id=item.id).update({"work_item_id": None}, synchronize_session="fetch")
    for child in list(item.children):
        # Preserve nested descendants when deleting an intermediate subtask.
        new_parent = item.parent_id if child.item_type == "subtask" else None
        log_work_item_history(child, actor, "parent", item.key, item.parent.key if new_parent else None)
        child.parent = item.parent if new_parent else None
        child.parent_id = new_parent
        if child.item_type == "subtask" and new_parent is None:
            log_work_item_history(child, actor, "item_type", "subtask", "task")
            child.item_type = "task"
    WorkItemLink.query.filter_by(target_type="work_item", target_id=item.id).delete()
    core.audit("work item deleted", item.key, item.title, user_id=actor.id, tenant_id=item.tenant_id)
    db.session.delete(item)


# --- comments --------------------------------------------------------------------------

COMMENT_ROLE_RANK = {"admin": 3, "member": 2, "viewer": 1, "reader": 0}


def comment_visible_to(user, comment, project):
    """A comment restricted to a project role is shown to that role and above
    (Jira's comment visibility); its author always sees it."""
    if not comment.visibility or comment.user_id == user.id:
        return True
    role = project_role(user, project)
    return COMMENT_ROLE_RANK.get(role, -1) >= COMMENT_ROLE_RANK[comment.visibility]


def visible_comments(user, item):
    rows = WorkItemComment.query.filter_by(work_item_id=item.id).order_by(WorkItemComment.created_at,
                                                                           WorkItemComment.id).all()
    return [row for row in rows if comment_visible_to(user, row, item.project)]


def add_comment(actor, item, body, visibility=None):
    if not can_comment(actor, item.project):
        abort(403, description=tr("You can read this project but not comment on it."))
    body = _clean_text(body, 20000, tr("Comment"), required=True)
    visibility = visibility or None
    if visibility not in (None, "admin", "member"):
        abort(400, description=tr("Choose who can see the comment."))
    if visibility and COMMENT_ROLE_RANK.get(project_role(actor, item.project), -1) < COMMENT_ROLE_RANK[visibility]:
        abort(403, description=tr("You can only restrict a comment to a role you hold."))
    comment = WorkItemComment(tenant_id=item.tenant_id, work_item_id=item.id, user_id=actor.id, body=body,
                              visibility=visibility)
    db.session.add(comment)
    db.session.flush()
    usernames = {match.group(1).lower() for match in core.MENTION_PATTERN.finditer(body)}
    mentioned = []
    if usernames:
        mentioned = [user for user in User.query.filter(
            User.tenant_id == item.tenant_id, User.active.is_(True), func.lower(User.username).in_(usernames)).all()
            if can_view(user, item.project) and comment_visible_to(user, comment, item.project)]
    preview = body if len(body) <= 200 else body[:197] + "..."
    _watch(item, actor)
    for user in mentioned:
        _watch(item, user)
    core.audit("work item comment", item.key, f"comment={comment.id}", user_id=actor.id, tenant_id=item.tenant_id)
    _notify(mentioned, actor, item, tr("{name} mentioned you in {key}", name=actor.name, key=item.key), preview,
            "work_item.mentioned")
    mentioned_ids = {user.id for user in mentioned}
    _notify([user for user in watchers(item)
             if user.id not in mentioned_ids and comment_visible_to(user, comment, item.project)], actor, item,
            tr("New comment on {key}", key=item.key), f"{actor.name}: {preview}", "work_item.commented")
    item.updated_at = now()
    return comment


def comment_or_404(user, item, comment_id):
    comment = WorkItemComment.query.filter_by(id=comment_id, work_item_id=item.id).first()
    if not comment or not comment_visible_to(user, comment, item.project):
        abort(404)
    return comment


def _require_comment_owner_or_admin(actor, item, comment):
    if comment.user_id != actor.id and not can_administer(actor, item.project):
        abort(403, description=tr("Only the author or a project administrator can change this comment."))
    if item.project.archived_at is not None:
        abort(403, description=tr("This project is archived."))


def edit_comment(actor, item, comment, body):
    _require_comment_owner_or_admin(actor, item, comment)
    body = _clean_text(body, 20000, tr("Comment"), required=True)
    if body != comment.body:
        comment.body, comment.edited_at = body, now()
        core.audit("work item comment edited", item.key, f"comment={comment.id}", user_id=actor.id,
                   tenant_id=item.tenant_id)


def delete_comment(actor, item, comment):
    _require_comment_owner_or_admin(actor, item, comment)
    core.audit("work item comment deleted", item.key, f"comment={comment.id}", user_id=actor.id,
               tenant_id=item.tenant_id)
    db.session.delete(comment)


def toggle_reaction(actor, item, comment, emoji):
    from serviceops_core.projects.models import REACTIONS, WorkItemCommentReaction
    if not can_view(actor, item.project):
        abort(404)
    if emoji not in REACTIONS:
        abort(400, description=tr("Choose a reaction."))
    row = WorkItemCommentReaction.query.filter_by(comment_id=comment.id, user_id=actor.id, emoji=emoji).first()
    if row:
        db.session.delete(row)
        return False
    db.session.add(WorkItemCommentReaction(tenant_id=item.tenant_id, comment_id=comment.id, user_id=actor.id,
                                           emoji=emoji))
    return True


def reactions_for(comment_ids, user):
    """{comment_id: [(emoji, count, mine), ...]} in REACTIONS order."""
    from serviceops_core.projects.models import REACTIONS, WorkItemCommentReaction
    result = {}
    if not comment_ids:
        return result
    rows = WorkItemCommentReaction.query.filter(WorkItemCommentReaction.comment_id.in_(comment_ids)).all()
    for comment_id in comment_ids:
        mine = {row.emoji for row in rows if row.comment_id == comment_id and row.user_id == user.id}
        counts = {}
        for row in rows:
            if row.comment_id == comment_id:
                counts[row.emoji] = counts.get(row.emoji, 0) + 1
        result[comment_id] = [(emoji, counts[emoji], emoji in mine) for emoji in REACTIONS if emoji in counts]
    return result


# --- votes, stars and views ---------------------------------------------------------------------

def toggle_vote(actor, item):
    """Jira: you cannot vote on work you reported, or on resolved work."""
    from serviceops_core.projects.models import WorkItemVote
    if not can_view(actor, item.project):
        abort(404)
    if item.reporter_id == actor.id:
        abort(409, description=tr("You cannot vote for a work item you reported."))
    row = WorkItemVote.query.filter_by(work_item_id=item.id, user_id=actor.id).first()
    if row:
        db.session.delete(row)
        return False
    if item.status.category == "done":
        abort(409, description=tr("You cannot vote for resolved work."))
    db.session.add(WorkItemVote(tenant_id=item.tenant_id, work_item_id=item.id, user_id=actor.id))
    return True


def voters(item):
    from serviceops_core.projects.models import WorkItemVote
    return User.query.join(WorkItemVote, WorkItemVote.user_id == User.id).filter(
        WorkItemVote.work_item_id == item.id).order_by(User.name).all()


def toggle_star(actor, target_type, target):
    from serviceops_core.projects.models import ProjectStar
    project = target if target_type == "project" else target.project
    if not can_view(actor, project):
        abort(404)
    row = ProjectStar.query.filter_by(user_id=actor.id, target_type=target_type, target_id=target.id).first()
    if row:
        db.session.delete(row)
        return False
    db.session.add(ProjectStar(tenant_id=actor.tenant_id, user_id=actor.id, target_type=target_type,
                               target_id=target.id))
    return True


def is_starred(user, target_type, target_id):
    from serviceops_core.projects.models import ProjectStar
    return ProjectStar.query.filter_by(user_id=user.id, target_type=target_type, target_id=target_id).first() \
        is not None


def record_view(user, item):
    from serviceops_core.projects.models import WorkItemView
    row = db.session.get(WorkItemView, (user.id, item.id))
    if row:
        row.viewed_at = now()
    else:
        db.session.add(WorkItemView(tenant_id=item.tenant_id, user_id=user.id, work_item_id=item.id))


# --- links ----------------------------------------------------------------------------------

def add_link(actor, item, link_type, target_text):
    from serviceops_core.projects import catalog
    require_edit(actor, item.project)
    if catalog.link_type_named(item.tenant_id, link_type) is None:
        abort(400, description=tr("Choose a link type."))
    target_text = (target_text or "").strip()
    target = find_visible_item(actor, target_text)
    original_project = item.project_id
    target_project = target.project_id if target else None
    lock_ids = sorted({item.project_id} | ({target.project_id} if target else set()))
    Project.query.filter(Project.id.in_(lock_ids)).order_by(Project.id).with_for_update().all()
    db.session.refresh(item,['project_id','tenant_id'])
    db.session.expire(item,['project'])
    if item.project_id != original_project:abort(409,description=tr('This work item moved. Reload it before linking.'))
    if target:
        db.session.refresh(target,['project_id','tenant_id'])
        db.session.expire(target,['project'])
        if target.project_id != target_project:abort(409,description=tr('The link target moved. Reload it before linking.'))
        if not can_view(actor,target.project):abort(404)
    _forget_roles()
    require_edit(actor, item.project)
    if target:
        if target.id == item.id:
            abort(400, description=tr("A work item cannot link to itself."))
        target_type, target_id = "work_item", target.id
    else:
        record = core.find_record_by_number(target_text, tenant_id=actor.tenant_id)
        if record is None or not _can_view_record(actor, record):
            abort(400, description=tr("No work item or record {number} that you can see.", number=target_text))
        target_type = "ticket" if isinstance(record, core.Ticket) else "enterprise" \
            if isinstance(record, core.EnterpriseRecord) else None
        if target_type is None:
            abort(400, description=tr("Work items link to other work items, incidents, changes and problems."))
        target_id = record.id
    if WorkItemLink.query.filter_by(source_id=item.id, link_type=link_type, target_type=target_type,
                                    target_id=target_id).first():
        abort(409, description=tr("That link already exists."))
    link = WorkItemLink(tenant_id=item.tenant_id, source_id=item.id, link_type=link_type, target_type=target_type,
                        target_id=target_id, created_by_id=actor.id)
    db.session.add(link)
    log_work_item_history(item, actor, "link", None, f"{link_type} {target_text.upper()}")
    return link


def _can_view_record(user, record):
    if isinstance(record, core.Ticket):
        return core.user_can_view_ticket(user, record)
    if isinstance(record, core.EnterpriseRecord):
        return core.visible_enterprise_record_query(user).filter_by(id=record.id).first() is not None
    return False


def remove_link(actor, item, link_id):
    require_edit(actor, item.project)
    link = WorkItemLink.query.filter_by(id=link_id, source_id=item.id).first()
    incoming = None
    if not link:
        incoming = WorkItemLink.query.filter_by(id=link_id, target_type="work_item", target_id=item.id).first()
        if not incoming:
            abort(404)
        link = incoming
    endpoint_ids = {link.source_id} | ({link.target_id} if link.target_type == 'work_item' else set())
    project_ids = [p for (p,) in db.session.query(WorkItem.project_id).filter(WorkItem.id.in_(endpoint_ids))]
    Project.query.filter(Project.id.in_(project_ids)).order_by(Project.id).with_for_update().all()
    _forget_roles()
    require_edit(actor, item.project)
    log_work_item_history(item, actor, "link", f"{link.link_type} #{link.id}", None)
    db.session.delete(link)


def links_for(user, item):
    """Outgoing and incoming links as display rows, hiding targets the user
    cannot see."""
    rows = []
    for link in WorkItemLink.query.filter_by(source_id=item.id).order_by(WorkItemLink.id):
        rows.append(_link_row(user, link, outgoing=True))
    for link in WorkItemLink.query.filter_by(target_type="work_item", target_id=item.id).order_by(WorkItemLink.id):
        rows.append(_link_row(user, link, outgoing=False))
    return [row for row in rows if row]


def _link_row(user, link, outgoing):
    from serviceops_core.projects import catalog
    link_type = catalog.link_type_named(link.tenant_id, link.link_type)
    relation = (link_type.outward if outgoing else link_type.inward) if link_type else link.link_type
    if outgoing:
        if link.target_type == "work_item":
            target = db.session.get(WorkItem, link.target_id)
            if not target or not can_view(user, target.project):
                return None
            label, url, title, state = target.key, f"/work-items/{target.key}", target.title, target.status.name
        else:
            record = core.record_reference(link.target_type, link.target_id)
            if not record or not _can_view_record(user, record):
                return None
            label, url, title = record.number, core.record_url(record), record.title
            state = getattr(record, "state", "")
    else:
        source = db.session.get(WorkItem, link.source_id)
        if not source or not can_view(user, source.project):
            return None
        label, url, title, state = source.key, f"/work-items/{source.key}", source.title, source.status.name
    return {"id": link.id, "relation": relation, "label": label, "url": url, "title": title, "state": state}


def items_linked_to_record(user, target_type, target_id):
    """Work items linked to an ITSM record, for its detail page."""
    items = WorkItem.query.join(WorkItemLink, WorkItemLink.source_id == WorkItem.id).filter(
        WorkItemLink.target_type == target_type, WorkItemLink.target_id == target_id,
        WorkItem.tenant_id == user.tenant_id).all()
    return [item for item in items if can_view(user, item.project)]


# --- queries -----------------------------------------------------------------------------------

SORTS = {
    "rank": (WorkItem.rank, WorkItem.id),
    "key": (WorkItem.number.desc(),),
    "created": (WorkItem.created_at.desc(),),
    "updated": (WorkItem.updated_at.desc(),),
    "due": (WorkItem.due_date.is_(None), WorkItem.due_date, WorkItem.id),
    "priority": None,
}


def item_query(project, filters, user=None):
    """Work items of one project matching list/board filters. Filters:
    q (words or a key), type, status (id), category, priority, assignee
    (user id, "me" or "none"), label, parent (id), epic (id)."""
    query = WorkItem.query.filter(WorkItem.project_id == project.id, WorkItem.tenant_id == project.tenant_id)
    if filters.get('sprint'):
        from serviceops_core.projects import query as project_query, sprints
        if user is None: abort(400, description=tr('Sprint filtering requires a signed-in user.'))
        sprint = sprints.get(user,project,filters['sprint'])
        query = query.filter(project_query.Parser('',user).sprint_items(sprints.ProjectSprint.id == sprint.id))
    q = (filters.get("q") or "").strip()
    if q:
        parsed = parse_item_key(q)
        if parsed and parsed[0] == project.key:
            query = query.filter(WorkItem.number == parsed[1])
        else:
            for word in q.split()[:6]:
                query = query.filter(or_(WorkItem.title.ilike(f"%{word}%"), WorkItem.description.ilike(f"%{word}%")))
    if filters.get("type") in ITEM_TYPES:
        query = query.filter(WorkItem.item_type == filters["type"])
    if filters.get("priority") in PRIORITIES:
        query = query.filter(WorkItem.priority == filters["priority"])
    if str(filters.get("status") or "").isdigit():
        query = query.filter(WorkItem.status_id == int(filters["status"]))
    if filters.get("category") in STATUS_CATEGORIES:
        query = query.join(ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
            ProjectStatus.category == filters["category"])
    elif filters.get("category") == "open":
        query = query.join(ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
            ProjectStatus.category != "done")
    assignee = str(filters.get("assignee") or "")
    if assignee == "none":
        query = query.filter(~WorkItem.id.in_(db.session.query(WorkItemAssignee.work_item_id)))
    elif assignee == "me" and user is not None:
        query = query.filter(WorkItem.id.in_(db.session.query(WorkItemAssignee.work_item_id).filter(
            WorkItemAssignee.user_id == user.id)))
    elif assignee.isdigit():
        query = query.filter(WorkItem.id.in_(db.session.query(WorkItemAssignee.work_item_id).filter(
            WorkItemAssignee.user_id == int(assignee))))
    if filters.get("label"):
        query = query.filter(WorkItem.id.in_(db.session.query(WorkItemLabel.work_item_id).filter(
            func.lower(WorkItemLabel.label) == str(filters["label"]).lower())))
    if str(filters.get("epic") or "").isdigit():
        query = query.filter(WorkItem.parent_id == int(filters["epic"]))
    from serviceops_core.projects.models import WorkItemComponent, WorkItemFixVersion
    if str(filters.get("component") or "").isdigit():
        query = query.filter(WorkItem.id.in_(db.session.query(WorkItemComponent.work_item_id).filter(
            WorkItemComponent.component_id == int(filters["component"]))))
    if str(filters.get("version") or "").isdigit():
        query = query.filter(WorkItem.id.in_(db.session.query(WorkItemFixVersion.work_item_id).filter(
            WorkItemFixVersion.version_id == int(filters["version"]))))
    if filters.get("flagged") == "1":
        query = query.filter(WorkItem.flagged.is_(True))
    return query


def sorted_query(query, sort):
    if sort == "priority":
        order = core.db.case({name: index for index, name in enumerate(PRIORITIES)}, value=WorkItem.priority)
        return query.order_by(order, WorkItem.rank, WorkItem.id)
    return query.order_by(*(SORTS.get(sort) or SORTS["rank"]))


def project_members(project):
    return User.query.join(ProjectMember, ProjectMember.user_id == User.id).filter(
        ProjectMember.project_id == project.id, User.active.is_(True)).order_by(User.name).all()


def assignable_users(project):
    """Members who can edit; tenant administrators are added when assigned."""
    return User.query.join(ProjectMember, ProjectMember.user_id == User.id).filter(
        ProjectMember.project_id == project.id, ProjectMember.role.in_(EDIT_ROLES),
        User.active.is_(True)).order_by(User.name).all()


def project_labels(project):
    return [row[0] for row in db.session.query(WorkItemLabel.label).join(
        WorkItem, WorkItem.id == WorkItemLabel.work_item_id).filter(
        WorkItem.project_id == project.id).distinct().order_by(WorkItemLabel.label).limit(200)]


def epics(project):
    return WorkItem.query.filter_by(project_id=project.id, item_type="epic").order_by(WorkItem.number).all()


def status_counts(project):
    rows = db.session.query(WorkItem.status_id, func.count()).filter(WorkItem.project_id == project.id).group_by(
        WorkItem.status_id).all()
    return dict(rows)


def my_open_items(user, limit=200):
    """Open work items assigned to the user across visible projects."""
    visible_ids = visible_projects(user).with_entities(Project.id)
    return WorkItem.query.join(WorkItemAssignee, WorkItemAssignee.work_item_id == WorkItem.id).join(
        ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
        WorkItemAssignee.user_id == user.id, WorkItem.project_id.in_(visible_ids),
        ProjectStatus.category != "done").order_by(
        WorkItem.due_date.is_(None), WorkItem.due_date, WorkItem.updated_at.desc()).limit(limit).all()


def search(user, q, limit=20):
    """Global search: an exact key, or every word in the title or description."""
    q = (q or "").strip()
    if not q or not enabled():
        return []
    visible_ids = visible_projects(user).with_entities(Project.id)
    parsed = parse_item_key(q)
    if parsed:
        item = find_visible_item(user, q)
        return [item] if item else []
    query = WorkItem.query.filter(WorkItem.project_id.in_(visible_ids))
    for word in q.split()[:6]:
        query = query.filter(or_(WorkItem.title.ilike(f"%{word}%"), WorkItem.description.ilike(f"%{word}%")))
    return query.order_by(WorkItem.updated_at.desc()).limit(limit).all()


def overview(project, today):
    """Counts for the project overview, each computed in SQL."""
    base = WorkItem.query.filter(WorkItem.project_id == project.id)
    by_category = dict(base.join(ProjectStatus, ProjectStatus.id == WorkItem.status_id).with_entities(
        ProjectStatus.category, func.count()).group_by(ProjectStatus.category).all())
    open_items = base.join(ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
        ProjectStatus.category != "done")
    by_type = dict(open_items.with_entities(WorkItem.item_type, func.count()).group_by(WorkItem.item_type).all())
    by_priority = dict(open_items.with_entities(WorkItem.priority, func.count()).group_by(WorkItem.priority).all())
    workload = open_items.join(WorkItemAssignee, WorkItemAssignee.work_item_id == WorkItem.id).join(
        User, User.id == WorkItemAssignee.user_id).with_entities(User, func.count()).group_by(User.id).order_by(
        func.count().desc(), User.name).limit(10).all()
    unassigned = open_items.filter(~WorkItem.id.in_(db.session.query(WorkItemAssignee.work_item_id))).count()
    overdue = open_items.filter(WorkItem.due_date < today).order_by(WorkItem.due_date).limit(10).all()
    done_children = func.sum(db.case((ProjectStatus.category == "done", 1), else_=0))
    epic_rows = db.session.query(WorkItem.parent_id, func.count(), done_children).join(
        ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
        WorkItem.project_id == project.id, WorkItem.parent_id.isnot(None)).group_by(WorkItem.parent_id).all()
    progress = {parent_id: (total, int(done or 0)) for parent_id, total, done in epic_rows}
    epic_progress = [(epic, *progress.get(epic.id, (0, 0))) for epic in epics(project)]
    activity = db.session.query(WorkItemHistory, WorkItem).join(WorkItem, WorkItem.id == WorkItemHistory.work_item_id).filter(
        WorkItem.project_id == project.id).order_by(WorkItemHistory.created_at.desc(), WorkItemHistory.id.desc()).limit(15).all()
    cutoff=core.now()-timedelta(days=7)
    weekly=dict(done=base.filter(WorkItem.resolved_at>=cutoff).count(),updated=base.filter(WorkItem.updated_at>=cutoff).count(),
        created=base.filter(WorkItem.created_at>=cutoff).count(),due=open_items.filter(WorkItem.due_date>=today,WorkItem.due_date<=today+timedelta(days=7)).count())
    all_types=dict(base.with_entities(WorkItem.item_type,func.count()).group_by(WorkItem.item_type).all())
    all_priorities=dict(base.with_entities(WorkItem.priority,func.count()).group_by(WorkItem.priority).all())
    return {"weekly":weekly,"all_types":all_types,"all_priorities":all_priorities,"by_category": by_category, "total": sum(by_category.values()), "by_type": by_type,
            "by_priority": by_priority, "workload": workload, "unassigned": unassigned, "overdue": overdue,
            "epic_progress": epic_progress, "activity": activity}
