"""Work item operations (B-449), as in Jira: clone, move to another
project, convert between subtask and standard types, and bulk change."""
import uuid

from flask import abort, current_app

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import service
from serviceops_core.projects.models import (ITEM_TYPES, PRIORITIES, Project, ProjectStatus, WorkItem,
                                             WorkItemAssignee, WorkItemComponent, WorkItemFixVersion,
                                             WorkItemAffectsVersion, WorkItemKeyAlias, WorkItemLabel, WorkItemLink)
from serviceops_models import db

BULK_LIMIT = 500


# --- clone --------------------------------------------------------------------------------

def _copy_attachments(source, target, actor):
    """Each copy gets its own stored file, so deleting one never removes
    the other's bytes."""
    storage = core.current_storage()
    for attachment in core.FileAttachment.query.filter_by(work_item_id=source.id).all():
        try:
            data, _ = storage.read_file(attachment.stored_name, attachment.ipfs_cid or attachment.stored_name)
        except Exception:
            current_app.logger.warning("Attachment %s could not be read for a clone", attachment.id)
            continue
        stored = f"{uuid.uuid4().hex}-{attachment.original_name}"
        reference = storage.attach_file(stored, data, attachment.mime_type or "application/octet-stream")
        db.session.add(core.FileAttachment(
            work_item_id=target.id, uploaded_by_id=actor.id, original_name=attachment.original_name,
            stored_name=stored, ipfs_cid=reference if core.ipfs_enabled() else None, mime_type=attachment.mime_type,
            size_bytes=attachment.size_bytes, sha256=attachment.sha256, scan_status=attachment.scan_status,
            tenant_id=target.tenant_id))


def clone_item(actor, item, title=None, include_subtasks=False, include_links=False, include_attachments=False,
               _parent_id=None):
    project = item.project
    service.require_edit(actor, project)
    Project.query.filter_by(id=project.id).with_for_update().one()
    copy = service.create_item(
        actor, project, title or tr("CLONE - {title}", title=item.title)[:255], item_type=item.item_type,
        description=item.description, status_id=service.default_status(project).id, priority=item.priority,
        assignee_ids=[user.id for user in item.assignees], labels=[row.label for row in item.labels],
        parent_id=_parent_id if _parent_id is not None else item.parent_id, start_date=item.start_date,
        due_date=item.due_date, story_points=item.story_points, estimate_minutes=item.estimate_minutes,
        component_ids=[row.id for row in item.components], fix_version_ids=[row.id for row in item.fix_versions],
        affects_version_ids=[row.id for row in item.affects_versions], environment=item.environment)
    db.session.add(WorkItemLink(tenant_id=item.tenant_id, source_id=copy.id, link_type="clones",
                                target_type="work_item", target_id=item.id, created_by_id=actor.id))
    from serviceops_core.projects.models import ProjectFormResponse
    for response in item.form_responses:
        db.session.add(ProjectFormResponse(tenant_id=item.tenant_id,form_id=response.form_id,work_item_id=copy.id,name=response.name,schema_json=response.schema_json,answers_json=response.answers_json,submitted_by_id=actor.id))
    if include_links:
        for link in WorkItemLink.query.filter_by(source_id=item.id).all():
            if link.link_type != "clones":
                db.session.add(WorkItemLink(tenant_id=item.tenant_id, source_id=copy.id, link_type=link.link_type,
                                            target_type=link.target_type, target_id=link.target_id,
                                            created_by_id=actor.id))
    if include_attachments:
        _copy_attachments(item, copy, actor)
    if include_subtasks and item.item_type != "epic":
        remaining = service.hierarchy_rows(item)
        copies = {item.id: copy}
        while remaining:
            ready = [child for child in remaining if child.parent_id in copies]
            if not ready:
                abort(409, description=tr("The work item hierarchy must be repaired before cloning."))
            for child in ready:
                copies[child.id] = clone_item(actor, child, title=child.title,
                    include_links=include_links, include_attachments=include_attachments,
                    _parent_id=copies[child.parent_id].id)
            ready_ids = {child.id for child in ready}
            remaining = [child for child in remaining if child.id not in ready_ids]
    service.log_work_item_history(item, actor, "cloned", None, copy.key)
    return copy


# --- move ------------------------------------------------------------------------------------

def _status_in(project, old_status):
    """The target status with the same name, else the first of the same category."""
    statuses = list(project.statuses)
    return (next((s for s in statuses if s.name.lower() == old_status.name.lower()), None)
            or next((s for s in statuses if s.category == old_status.category), None)
            or service.default_status(project))


def move_item(actor, item, target_project, item_type=None, status_id=None):
    """Move to another project with a new key; the old key keeps working.
    Subtasks move along. Links to an epic in the old project are dropped,
    and components and versions (which belong to the old project) too."""
    source = item.project
    if target_project.id == source.id:
        abort(400, description=tr("Choose a different project."))
    service.require_edit(actor, source)
    service.require_edit(actor, target_project)
    Project.query.filter(Project.id.in_([source.id, target_project.id])).order_by(
        Project.id).with_for_update().all()
    db.session.refresh(item, ["parent_id", "item_type"])
    if item.item_type == "subtask":
        abort(400, description=tr("Move the parent work item; its subtasks move with it."))
    item_type = item_type or item.item_type
    if item_type not in ITEM_TYPES or item_type == "subtask":
        abort(400, description=tr("Choose a work item type."))
    if (item.item_type == "epic" or item_type == "epic") and WorkItem.query.filter_by(parent_id=item.id).count():
        abort(409, description=tr("Move or remove this item's children before moving it or changing its type."))
    moved = [item] + service.hierarchy_rows(item)
    from serviceops_core.projects import sprints
    for row in moved:
        sprints.detach_for_removal(actor, row)
    old_key = item.key
    locked = Project.query.filter_by(id=target_project.id).with_for_update().populate_existing().one()
    for row in moved:
        db.session.add(WorkItemKeyAlias(tenant_id=row.tenant_id, project_key=source.key, number=row.number,
                                        work_item_id=row.id))
        status = (service.status_or_404(target_project, status_id) if row is item and status_id not in (None, "")
                  else _status_in(target_project, row.status))
        row.project_id, row.project = target_project.id, target_project
        row.number = locked.next_number
        locked.next_number += 1
        row.status_id, row.status = status.id, status
        service._resolve(row, actor, status)
        row.rank = service._next_rank(target_project.id, status.id)
        for model in (WorkItemComponent, WorkItemFixVersion, WorkItemAffectsVersion):
            model.query.filter_by(work_item_id=row.id).delete()
        # Assignees must be able to work in the new project.
        for user in list(row.assignees):
            if service.project_role(user, target_project) not in service.EDIT_ROLES:
                WorkItemAssignee.query.filter_by(work_item_id=row.id, user_id=user.id).delete()
    if item.parent_id and item.parent and item.parent.project_id != target_project.id:
        item.parent_id = None
    item.item_type = item_type
    db.session.flush()
    db.session.expire(item, ["assignees", "components", "fix_versions", "affects_versions"])
    service.log_work_item_history(item, actor, "moved", old_key, item.key)
    core.audit("work item moved", old_key, f"to {item.key}", user_id=actor.id, tenant_id=item.tenant_id)
    return item


def resolve_alias(user, item_key):
    """The work item an old (moved) key now points to, if the user can see it."""
    parsed = service.parse_item_key(item_key)
    if not parsed:
        return None
    alias = WorkItemKeyAlias.query.filter_by(tenant_id=user.tenant_id, project_key=parsed[0],
                                             number=parsed[1]).first()
    if not alias:
        return None
    item = db.session.get(WorkItem, alias.work_item_id)
    return item if item and service.can_view(user, item.project) else None


# --- convert ---------------------------------------------------------------------------------

def convert_item(actor, item, item_type, parent_id=None):
    """Subtask to a standard type, or a standard type to a subtask of
    `parent_id`, preserving nested descendants and rejecting cycles."""
    service.require_edit(actor, item.project)
    if item_type not in ITEM_TYPES or item_type == item.item_type:
        abort(400, description=tr("Choose a different work item type."))
    if item_type == "subtask":
        service.update_item(actor, item, {"item_type": "subtask", "parent_id": parent_id})
    else:
        changes = {"item_type": item_type}
        if item.item_type == "subtask" or item_type == "epic":
            changes["parent_id"] = None
        service.update_item(actor, item, changes)
    return item


# --- bulk change -----------------------------------------------------------------------------

BULK_ACTIONS = ("status", "assign", "priority", "add_label", "watch", "unwatch", "delete")


def bulk_change(actor, project, item_ids, action, value=None):
    """Apply one change to many work items of a project; each item is
    checked as if changed by hand. Returns how many changed."""
    if action not in BULK_ACTIONS:
        abort(400, description=tr("Choose a bulk action."))
    try:
        ids = sorted({int(value) for value in item_ids})
    except (TypeError, ValueError):
        abort(400, description=tr("Select work items."))
    if not ids:
        abort(400, description=tr("Select work items."))
    if len(ids) > BULK_LIMIT:
        abort(400, description=tr("Change at most {count} work items at once.", count=BULK_LIMIT))
    items = WorkItem.query.filter(WorkItem.project_id == project.id, WorkItem.id.in_(ids)).all()
    if len(items) != len(ids):
        abort(400, description=tr("Some selected work items are not in this project."))
    changed = 0
    for item in items:
        if action == "status":
            if item.status_id != int(value or 0):
                service.update_item(actor, item, {"status_id": value})
                changed += 1
        elif action == "assign":
            assignee_ids = [] if value in (None, "", "none") else [value]
            service.update_item(actor, item, {"assignee_ids": assignee_ids})
            changed += 1
        elif action == "priority":
            if value not in PRIORITIES:
                abort(400, description=tr("Choose a priority."))
            service.update_item(actor, item, {"priority": value})
            changed += 1
        elif action == "add_label":
            labels = [row.label for row in item.labels]
            service.update_item(actor, item, {"labels": labels + [value]})
            changed += 1
        elif action in ("watch", "unwatch"):
            if not service.can_view(actor, project):
                abort(404)
            service.set_watching(actor, item, action == "watch")
            changed += 1
        elif action == "delete":
            service.delete_item(actor, item)
            changed += 1
    core.audit("work items bulk changed", project.key, f"{action} on {changed} items", user_id=actor.id,
               tenant_id=project.tenant_id)
    return changed


def project_choices(user, exclude=None):
    """Projects the user can create work in, for move and global create."""
    projects = service.visible_projects(user).order_by(Project.name).all()
    return [project for project in projects if service.can_edit(user, project)
            and (exclude is None or project.id != exclude.id)]


def statuses_of(project):
    return ProjectStatus.query.filter_by(project_id=project.id).order_by(ProjectStatus.position).all()


def labels_of(item):
    return [row.label for row in WorkItemLabel.query.filter_by(work_item_id=item.id)]
