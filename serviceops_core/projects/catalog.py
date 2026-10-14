"""Tenant-wide project settings (B-449): resolutions and link types, created
with Jira's defaults the first time a tenant needs them, and managed by
tenant administrators."""
from flask import abort
from sqlalchemy import func

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects.models import (DEFAULT_LINK_TYPES, DEFAULT_RESOLUTIONS, WorkItem, WorkItemLink,
                                             WorkItemLinkType, WorkItemResolution)
from serviceops_models import db


def _require_tenant_admin(user):
    if not core.role_at_least(user.effective_role, "admin"):
        abort(403, description=tr("Only administrators can change project settings for the organisation."))


def resolutions(tenant_id):
    rows = WorkItemResolution.query.filter_by(tenant_id=tenant_id).order_by(WorkItemResolution.position,
                                                                             WorkItemResolution.id).all()
    if rows:
        return rows
    for position, (name, description) in enumerate(DEFAULT_RESOLUTIONS):
        db.session.add(WorkItemResolution(tenant_id=tenant_id, name=name, description=description,
                                          position=position, is_default=position == 0))
    db.session.flush()
    return WorkItemResolution.query.filter_by(tenant_id=tenant_id).order_by(WorkItemResolution.position).all()


def default_resolution(tenant_id):
    rows = resolutions(tenant_id)
    return next((row for row in rows if row.is_default), rows[0] if rows else None)


def resolution_or_400(tenant_id, resolution_id):
    try:
        resolution_id = int(resolution_id)
    except (TypeError, ValueError):
        abort(400, description=tr("Choose a resolution."))
    resolutions(tenant_id)
    row = WorkItemResolution.query.filter_by(id=resolution_id, tenant_id=tenant_id).first()
    if not row:
        abort(400, description=tr("Choose a resolution."))
    return row


def save_resolution(actor, name, description="", resolution_id=None, is_default=False):
    _require_tenant_admin(actor)
    name = (name or "").strip()
    if not name or len(name) > 60:
        abort(400, description=tr("A resolution name has 1 to 60 characters."))
    existing = resolutions(actor.tenant_id)
    row = resolution_or_400(actor.tenant_id, resolution_id) if resolution_id else None
    clash = WorkItemResolution.query.filter(WorkItemResolution.tenant_id == actor.tenant_id,
                                            func.lower(WorkItemResolution.name) == name.lower()).first()
    if clash and (row is None or clash.id != row.id):
        abort(409, description=tr("A resolution called {name} already exists.", name=name))
    if row is None:
        row = WorkItemResolution(tenant_id=actor.tenant_id, position=len(existing))
        db.session.add(row)
    row.name, row.description = name, (description or "").strip()[:255]
    if is_default:
        for other in existing:
            other.is_default = False
        row.is_default = True
    db.session.flush()
    core.audit("work item resolution saved", name, "", user_id=actor.id, tenant_id=actor.tenant_id)
    return row


def delete_resolution(actor, resolution_id, replacement_id):
    _require_tenant_admin(actor)
    row = resolution_or_400(actor.tenant_id, resolution_id)
    replacement = resolution_or_400(actor.tenant_id, replacement_id)
    if replacement.id == row.id:
        abort(400, description=tr("Choose another resolution for the work items that use {name}.", name=row.name))
    WorkItem.query.filter_by(resolution_id=row.id).update({"resolution_id": replacement.id},
                                                          synchronize_session=False)
    if row.is_default:
        replacement.is_default = True
    db.session.delete(row)
    core.audit("work item resolution deleted", row.name, f"replaced by {replacement.name}", user_id=actor.id,
               tenant_id=actor.tenant_id)


def link_types(tenant_id):
    rows = WorkItemLinkType.query.filter_by(tenant_id=tenant_id).order_by(WorkItemLinkType.name).all()
    if rows:
        return rows
    for name, outward, inward in DEFAULT_LINK_TYPES:
        db.session.add(WorkItemLinkType(tenant_id=tenant_id, name=name, outward=outward, inward=inward))
    db.session.flush()
    return WorkItemLinkType.query.filter_by(tenant_id=tenant_id).order_by(WorkItemLinkType.name).all()


def link_type_named(tenant_id, name):
    return next((row for row in link_types(tenant_id) if row.name == name), None)


def save_link_type(actor, name, outward, inward, link_type_id=None):
    _require_tenant_admin(actor)
    name, outward, inward = ((value or "").strip() for value in (name, outward, inward))
    if not (0 < len(name) <= 40 and 0 < len(outward) <= 60 and 0 < len(inward) <= 60):
        abort(400, description=tr("A link type needs a name and its outward and inward descriptions."))
    link_types(actor.tenant_id)
    row = WorkItemLinkType.query.filter_by(id=link_type_id, tenant_id=actor.tenant_id).first() if link_type_id else None
    if link_type_id and not row:
        abort(404)
    clash = WorkItemLinkType.query.filter(WorkItemLinkType.tenant_id == actor.tenant_id,
                                          func.lower(WorkItemLinkType.name) == name.lower()).first()
    if clash and (row is None or clash.id != row.id):
        abort(409, description=tr("A link type called {name} already exists.", name=name))
    if row is None:
        row = WorkItemLinkType(tenant_id=actor.tenant_id, name=name, outward=outward, inward=inward)
        db.session.add(row)
    else:
        if row.name != name:
            # Existing links keep their meaning under the new name.
            WorkItemLink.query.filter_by(tenant_id=actor.tenant_id, link_type=row.name).update(
                {"link_type": name}, synchronize_session=False)
        row.name, row.outward, row.inward = name, outward, inward
    db.session.flush()
    core.audit("work item link type saved", name, f"{outward} / {inward}", user_id=actor.id,
               tenant_id=actor.tenant_id)
    return row


def delete_link_type(actor, link_type_id):
    _require_tenant_admin(actor)
    row = WorkItemLinkType.query.filter_by(id=link_type_id, tenant_id=actor.tenant_id).first()
    if not row:
        abort(404)
    removed = WorkItemLink.query.filter_by(tenant_id=actor.tenant_id, link_type=row.name).delete(
        synchronize_session=False)
    db.session.delete(row)
    core.audit("work item link type deleted", row.name, f"{removed} links removed", user_id=actor.id,
               tenant_id=actor.tenant_id)
