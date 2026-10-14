"""Components and versions (B-449), as in Jira: components group work in a
project and may decide the default assignee; versions (releases) carry fix
and affects versions, can be released (moving unfinished work on), merged,
archived and deleted."""
from datetime import date

from flask import abort
from sqlalchemy import func

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import service
from serviceops_core.projects.models import (COMPONENT_ASSIGNEE_CHOICES, ProjectComponent, ProjectStatus,
                                             ProjectVersion, WorkItem, WorkItemAffectsVersion, WorkItemComponent,
                                             WorkItemFixVersion)
from serviceops_models import db, now


def _date(value, label):
    if value in (None, ""):
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        abort(400, description=tr("{label} must be a date (YYYY-MM-DD).", label=label))


# --- components -------------------------------------------------------------------------

def components(project):
    return ProjectComponent.query.filter_by(project_id=project.id).order_by(ProjectComponent.name).all()


def component_or_404(project, component_id):
    row = ProjectComponent.query.filter_by(id=component_id, project_id=project.id).first()
    if not row:
        abort(404)
    return row


def save_component(actor, project, name, description="", lead_id=None, default_assignee="project_default",
                   component=None):
    service.require_admin(actor, project)
    name = (name or "").strip()
    if not 0 < len(name) <= 100:
        abort(400, description=tr("A component name has 1 to 100 characters."))
    if default_assignee not in COMPONENT_ASSIGNEE_CHOICES:
        abort(400, description=tr("Choose a default assignee."))
    clash = ProjectComponent.query.filter(ProjectComponent.project_id == project.id,
                                          func.lower(ProjectComponent.name) == name.lower()).first()
    if clash and (component is None or clash.id != component.id):
        abort(409, description=tr("This project already has a component called {name}.", name=name))
    lead = service._active_tenant_user(lead_id, project.tenant_id, tr("Component lead")) if lead_id else None
    if default_assignee == "component_lead" and not lead:
        abort(400, description=tr("Choose a component lead to assign work to them."))
    if component is None:
        component = ProjectComponent(tenant_id=project.tenant_id, project_id=project.id)
        db.session.add(component)
    component.name, component.description = name, (description or "").strip()[:5000]
    component.lead_id, component.default_assignee = lead.id if lead else None, default_assignee
    db.session.flush()
    core.audit("project component saved", project.key, name, user_id=actor.id, tenant_id=project.tenant_id)
    return component


def delete_component(actor, project, component, replacement=None):
    service.require_admin(actor, project)
    if replacement is not None:
        if replacement.id == component.id or replacement.project_id != project.id:
            abort(400, description=tr("Choose another component of this project."))
        moved = [row.work_item_id for row in WorkItemComponent.query.filter_by(component_id=component.id)]
        already = {row.work_item_id for row in WorkItemComponent.query.filter(
            WorkItemComponent.component_id == replacement.id, WorkItemComponent.work_item_id.in_(moved or [0]))}
        for item_id in moved:
            if item_id not in already:
                db.session.add(WorkItemComponent(tenant_id=project.tenant_id, work_item_id=item_id,
                                                 component_id=replacement.id))
    db.session.delete(component)
    core.audit("project component deleted", project.key, component.name, user_id=actor.id,
               tenant_id=project.tenant_id)


def default_assignees(project, component_rows):
    """Jira's rule: the first component with its own default decides;
    otherwise the project default."""
    for component in component_rows:
        if component.default_assignee == "component_lead" and component.lead:
            return [component.lead]
        if component.default_assignee == "project_lead" and project.lead:
            return [project.lead]
        if component.default_assignee == "unassigned":
            return []
    if project.default_assignee == "project_lead" and project.lead:
        return [project.lead]
    return []


# --- versions ----------------------------------------------------------------------------------

def versions(project, include_archived=True):
    query = ProjectVersion.query.filter_by(project_id=project.id)
    if not include_archived:
        query = query.filter_by(archived=False)
    return query.order_by(ProjectVersion.position, ProjectVersion.id).all()


def unreleased_versions(project):
    return [row for row in versions(project, include_archived=False) if not row.released]


def version_or_404(project, version_id):
    row = ProjectVersion.query.filter_by(id=version_id, project_id=project.id).first()
    if not row:
        abort(404)
    return row


def save_version(actor, project, name, description="", start_date=None, release_date=None, version=None):
    service.require_admin(actor, project)
    name = (name or "").strip()
    if not 0 < len(name) <= 100:
        abort(400, description=tr("A version name has 1 to 100 characters."))
    start, release = _date(start_date, tr("Start date")), _date(release_date, tr("Release date"))
    if start and release and release < start:
        abort(400, description=tr("The release date cannot be before the start date."))
    clash = ProjectVersion.query.filter(ProjectVersion.project_id == project.id,
                                        func.lower(ProjectVersion.name) == name.lower()).first()
    if clash and (version is None or clash.id != version.id):
        abort(409, description=tr("This project already has a version called {name}.", name=name))
    if version is None:
        position = (db.session.query(func.max(ProjectVersion.position)).filter_by(project_id=project.id).scalar()
                    or 0) + 1
        version = ProjectVersion(tenant_id=project.tenant_id, project_id=project.id, position=position)
        db.session.add(version)
    version.name, version.description = name, (description or "").strip()[:5000]
    version.start_date, version.release_date = start, release
    db.session.flush()
    core.audit("project version saved", project.key, name, user_id=actor.id, tenant_id=project.tenant_id)
    return version


def unresolved_in(version):
    return WorkItem.query.join(WorkItemFixVersion, WorkItemFixVersion.work_item_id == WorkItem.id).join(
        ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
        WorkItemFixVersion.version_id == version.id, ProjectStatus.category != "done")


def release_version(actor, project, version, release_date=None, move_to=None):
    """Mark released. Unfinished work moves to `move_to` (another
    unreleased version) or keeps this fix version when None."""
    service.require_admin(actor, project)
    if version.released:
        abort(409, description=tr("{name} is already released.", name=version.name))
    moved = 0
    if move_to is not None:
        if move_to.id == version.id or move_to.released or move_to.project_id != project.id:
            abort(400, description=tr("Move unfinished work to another unreleased version."))
        for item in unresolved_in(version).all():
            WorkItemFixVersion.query.filter_by(work_item_id=item.id, version_id=version.id).delete()
            if not WorkItemFixVersion.query.filter_by(work_item_id=item.id, version_id=move_to.id).first():
                db.session.add(WorkItemFixVersion(tenant_id=project.tenant_id, work_item_id=item.id,
                                                  version_id=move_to.id))
            service.log_work_item_history(item, actor, "fix versions", version.name, move_to.name)
            moved += 1
    version.released, version.released_at = True, now()
    version.release_date = _date(release_date, tr("Release date")) or version.release_date or now().date()
    core.audit("project version released", project.key, f"{version.name}; {moved} unfinished moved",
               user_id=actor.id, tenant_id=project.tenant_id)
    return moved


def unrelease_version(actor, project, version):
    service.require_admin(actor, project)
    version.released, version.released_at = False, None
    core.audit("project version unreleased", project.key, version.name, user_id=actor.id,
               tenant_id=project.tenant_id)


def set_archived(actor, project, version, archived):
    service.require_admin(actor, project)
    version.archived = bool(archived)
    core.audit("project version archived" if archived else "project version restored", project.key,
               version.name, user_id=actor.id, tenant_id=project.tenant_id)


def _reassign(model, source, target, tenant_id):
    item_ids = [row.work_item_id for row in model.query.filter_by(version_id=source.id)]
    if target is not None:
        existing = {row.work_item_id for row in model.query.filter(model.version_id == target.id,
                                                                   model.work_item_id.in_(item_ids or [0]))}
        for item_id in item_ids:
            if item_id not in existing:
                db.session.add(model(tenant_id=tenant_id, work_item_id=item_id, version_id=target.id))
    model.query.filter_by(version_id=source.id).delete()
    return len(item_ids)


def merge_versions(actor, project, source, target):
    """Move every fix and affects version from `source` to `target`, then delete `source`."""
    service.require_admin(actor, project)
    if source.id == target.id:
        abort(400, description=tr("Choose two different versions."))
    moved = _reassign(WorkItemFixVersion, source, target, project.tenant_id)
    moved += _reassign(WorkItemAffectsVersion, source, target, project.tenant_id)
    db.session.delete(source)
    core.audit("project versions merged", project.key, f"{source.name} into {target.name}; {moved} links",
               user_id=actor.id, tenant_id=project.tenant_id)


def delete_version(actor, project, version, fix_target=None, affects_target=None):
    service.require_admin(actor, project)
    for target in (fix_target, affects_target):
        if target is not None and (target.id == version.id or target.project_id != project.id):
            abort(400, description=tr("Choose another version of this project."))
    _reassign(WorkItemFixVersion, version, fix_target, project.tenant_id)
    _reassign(WorkItemAffectsVersion, version, affects_target, project.tenant_id)
    db.session.delete(version)
    core.audit("project version deleted", project.key, version.name, user_id=actor.id, tenant_id=project.tenant_id)


def move_version(actor, project, version, direction):
    service.require_admin(actor, project)
    ordered = versions(project)
    index = ordered.index(version)
    other = index + (-1 if direction == "up" else 1)
    if 0 <= other < len(ordered):
        ordered[index], ordered[other] = ordered[other], ordered[index]
        for position, row in enumerate(ordered):
            row.position = position


def version_progress(version):
    rows = db.session.query(ProjectStatus.category, func.count()).join(
        WorkItem, WorkItem.status_id == ProjectStatus.id).join(
        WorkItemFixVersion, WorkItemFixVersion.work_item_id == WorkItem.id).filter(
        WorkItemFixVersion.version_id == version.id).group_by(ProjectStatus.category).all()
    counts = dict(rows)
    total = sum(counts.values())
    return {"total": total, "done": counts.get("done", 0), "in_progress": counts.get("in_progress", 0),
            "todo": counts.get("todo", 0)}
