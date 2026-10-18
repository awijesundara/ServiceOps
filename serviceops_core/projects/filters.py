"""Owned/shared query definitions. Result access is checked again on execution."""
from flask import abort, current_app
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import query, service
from serviceops_core.projects.models import Project, ProjectFilterFavourite, ProjectSavedFilter
from serviceops_models import db


def visible(user):
    try:
        if not user.is_authenticated or not user.active:
            abort(403)
        projects=service.visible_projects(user).with_entities(Project.id)
        return ProjectSavedFilter.query.filter(ProjectSavedFilter.tenant_id==user.tenant_id,or_(
            ProjectSavedFilter.owner_id==user.id, ProjectSavedFilter.sharing=='tenant',
            and_(ProjectSavedFilter.sharing=='project',ProjectSavedFilter.project_id.in_(projects))))
    except HTTPException:
        raise
    except Exception:
        current_app.logger.error('Saved filter access query failed for tenant %s',user.tenant_id)
        raise


def get(user, filter_id):
    try:
        row=visible(user).filter(ProjectSavedFilter.id==filter_id).first()
        if row is None: abort(404)
        return row
    except HTTPException:
        raise
    except Exception:
        current_app.logger.error('Saved filter lookup failed for tenant %s',user.tenant_id)
        raise


def save(user, name, source, sharing='private', project_key=None, filter_id=None):
    try:
        if not user.is_authenticated or not user.active: abort(403)
        row=get(user,filter_id) if filter_id is not None else None
        if row is not None and row.owner_id!=user.id: abort(403)
        if not isinstance(name,str) or not name.strip() or len(name.strip())>100:
            abort(400,description=tr('Filter name must contain 1 to 100 characters.'))
        try:
            name.encode('utf-8')
        except UnicodeEncodeError:
            abort(400,description=tr('Filter name contains invalid characters.'))
        if any(ord(ch)<32 for ch in name):
            abort(400,description=tr('Filter name contains invalid characters.'))
        if sharing not in ('private','project','tenant'):
            abort(400,description=tr('Choose a valid filter sharing option.'))
        # Validate syntax independently of any current result count. The query
        # runs later with the viewing user's identity, not the owner's identity.
        query.search(user,source)
        project=None
        if sharing=='project':
            if not isinstance(project_key,str) or not service.KEY_PATTERN.fullmatch(project_key.upper()):
                abort(400,description=tr('Choose a valid filter sharing option.'))
            project=service.project_or_404(user,project_key)
            service.require_edit(user,project)
        if sharing=='tenant' and not service._tenant_admin(user):
            abort(403,description=tr('Only tenant administrators can share filters with the whole organisation.'))
        name=name.strip()
        duplicate=ProjectSavedFilter.query.filter_by(tenant_id=user.tenant_id,owner_id=user.id,name=name)
        if row is not None: duplicate=duplicate.filter(ProjectSavedFilter.id!=row.id)
        if duplicate.first(): abort(409,description=tr('You already have a filter with that name.'))
        if row is None:
            row=ProjectSavedFilter(tenant_id=user.tenant_id,owner_id=user.id,name=name,query_text=source)
            db.session.add(row)
        row.name=name; row.query_text=source; row.sharing=sharing; row.project_id=project.id if project else None
        db.session.flush()
        core.audit('project filter saved',str(row.id),sharing,user_id=user.id,tenant_id=user.tenant_id)
        return row
    except IntegrityError:
        db.session.rollback()
        abort(409,description=tr('The filter could not be saved because its name is already in use.'))
    except (HTTPException,query.QueryError):
        raise
    except Exception:
        current_app.logger.error('Saved filter write failed for tenant %s',user.tenant_id)
        raise


def delete(user,filter_id):
    try:
        row=get(user,filter_id)
        if row.owner_id!=user.id: abort(403)
        core.audit('project filter deleted',str(row.id),'',user_id=user.id,tenant_id=user.tenant_id)
        ProjectFilterFavourite.query.filter_by(filter_id=row.id).delete(synchronize_session=False)
        db.session.delete(row)
    except HTTPException:
        raise
    except Exception:
        current_app.logger.error('Saved filter deletion failed for tenant %s',user.tenant_id)
        raise


def favourite(user,filter_id,enabled):
    try:
        row=get(user,filter_id)
        # Serialize a user's repeated clicks; use explicit desired state, not a
        # toggle that double submissions can accidentally undo.
        from serviceops_models import User
        User.query.filter_by(id=user.id).with_for_update().one()
        existing=ProjectFilterFavourite.query.filter_by(filter_id=row.id,user_id=user.id).first()
        if enabled and existing is None:
            db.session.add(ProjectFilterFavourite(filter_id=row.id,user_id=user.id,tenant_id=user.tenant_id))
        elif not enabled and existing is not None:
            db.session.delete(existing)
    except HTTPException:
        raise
    except Exception:
        current_app.logger.error('Saved filter favourite failed for tenant %s',user.tenant_id)
        raise
