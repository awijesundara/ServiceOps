"""Permission-scoped quick filters and complete backlog insight totals."""
from functools import wraps

from flask import abort, current_app
from sqlalchemy import case, func, or_
from werkzeug.exceptions import HTTPException

from serviceops_core.localization import tr
from serviceops_core.projects import releases, service
from serviceops_core.projects.models import ProjectStatus, WorkItem
from serviceops_models import now

QUICK_FILTERS = ('', 'mine', 'unassigned', 'flagged', 'overdue', 'unestimated')


def guarded(fn):
    @wraps(fn)
    def call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except HTTPException:
            raise
        except Exception:
            current_app.logger.error('Project backlog controls failed: %s', fn.__name__)
            raise
    return call


@guarded
def read_filters(user, project, values):
    if not service.can_view(user, project):
        abort(404)
    result = {key: str(values.get(key, '')).strip() for key in ('q', 'assignee', 'version', 'epic', 'quick')}
    if len(result['q']) > 200 or result['quick'] not in QUICK_FILTERS:
        abort(400, description=tr('Choose a valid quick filter and search under 200 characters.'))
    for field in ('version', 'epic'):
        if result[field] and (not result[field].isdigit() or len(result[field]) > 10):
            abort(400, description=tr('Choose a valid version or epic.'))
    if result['version']:
        releases.version_or_404(project, int(result['version']))
    if result['epic']:
        epic = WorkItem.query.filter_by(tenant_id=user.tenant_id, project_id=project.id,
                                       id=int(result['epic']), item_type='epic').first()
        if epic is None:
            abort(404)
    assignee = result['assignee']
    if assignee and assignee not in ('me', 'none') and (not assignee.isdigit() or len(assignee) > 10):
        abort(400, description=tr('Choose a valid assignee.'))
    return result


@guarded
def filtered(user, project, items, filters):
    scoped = {key: value for key, value in filters.items() if key != 'quick' and value}
    quick = filters['quick']
    if quick == 'flagged':
        scoped['flagged'] = '1'
    query = items.filter(WorkItem.id.in_(service.item_query(project, scoped, user).with_entities(WorkItem.id)))
    if quick in ('mine','unassigned'):
        query=query.filter(WorkItem.id.in_(service.item_query(project,{'assignee':'me' if quick=='mine' else 'none'},user).with_entities(WorkItem.id)))
    if quick == 'overdue':
        query = query.filter(WorkItem.due_date < now().date(), WorkItem.status.has(ProjectStatus.category != 'done'))
    elif quick == 'unestimated':
        query = query.filter(or_(WorkItem.story_points.is_(None), WorkItem.estimate_minutes.is_(None)))
    return query


@guarded
def insights(items):
    row = items.order_by(None).with_entities(
        func.count(WorkItem.id),
        func.sum(case((ProjectStatus.category == 'todo', 1), else_=0)),
        func.sum(case((ProjectStatus.category == 'in_progress', 1), else_=0)),
        func.sum(case((ProjectStatus.category == 'done', 1), else_=0)),
        func.sum(func.coalesce(WorkItem.story_points, 0)),
        func.sum(case((WorkItem.flagged.is_(True), 1), else_=0)),
        func.sum(case((WorkItem.story_points.is_(None), 1), else_=0)),
        func.sum(case((WorkItem.estimate_minutes.is_(None), 1), else_=0)),
    ).join(ProjectStatus, ProjectStatus.id == WorkItem.status_id).one()
    return dict(zip(('count', 'todo', 'in_progress', 'done', 'points', 'flagged', 'missing_points', 'missing_estimates'),
                    (value or 0 for value in row)))
