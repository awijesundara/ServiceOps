"""Permission-scoped portfolio overview and a non-persistent scheduling preview."""
from datetime import timedelta

from flask import abort, current_app
from sqlalchemy import case, func
from werkzeug.exceptions import HTTPException

from serviceops_core.localization import tr
from serviceops_core.projects import service
from serviceops_core.projects.models import Project, ProjectStatus, WorkItem, WorkItemLink
from serviceops_models import db, now

PAGE_SIZE = 50
DEPENDENCY_LIMIT = 100


def portfolio(user, page=1, shift_days=0):
    """Aggregate all visible work in SQL; never materialize hidden project links.

    The schedule preview changes only displayed dates, never stored records.
    It is a portfolio baseline, not a team-capacity or automatic scheduling engine.
    """
    try:
        if page < 1 or abs(shift_days) > 3650:
            abort(400, description=tr("Choose a valid planning page and a date shift within ten years."))
        visible = service.visible_projects(user)
        ids = visible.with_entities(Project.id)
        today = now().date()
        delta = timedelta(days=shift_days)
        # Compare unshifted due dates so even the extreme supported date values
        # remain safe: displayed shifts are checked independently below.
        rows = visible.order_by(Project.name, Project.id).offset((page-1)*PAGE_SIZE).limit(PAGE_SIZE).all()
        count = visible.count()
        current_ids = [project.id for project in rows]
        aggregates = db.session.query(
            WorkItem.project_id, func.count(WorkItem.id),
            func.sum(case((ProjectStatus.category == 'done', 1), else_=0)),
            func.min(WorkItem.start_date), func.max(WorkItem.due_date),
            func.sum(case(((ProjectStatus.category != 'done') & (WorkItem.due_date < today-delta), 1), else_=0)),
            func.sum(case((ProjectStatus.category != 'done', func.coalesce(WorkItem.remaining_minutes, 0)), else_=0)),
            func.sum(case(((ProjectStatus.category != 'done') & WorkItem.due_date.is_(None), 1), else_=0)),
        ).join(ProjectStatus, ProjectStatus.id == WorkItem.status_id).filter(
            WorkItem.project_id.in_(current_ids), WorkItem.tenant_id == user.tenant_id
        ).group_by(WorkItem.project_id).all() if current_ids else []
        summaries = {}
        for project_id, total, done, start, due, overdue, remaining, unscheduled in aggregates:
            summaries[project_id] = dict(total=total, done=int(done or 0),
                start=(start+delta if start else None), due=(due+delta if due else None),
                overdue=int(overdue or 0), remaining=int(remaining or 0), unscheduled=int(unscheduled or 0))
        source = db.aliased(WorkItem)
        target = db.aliased(WorkItem)
        links = db.session.query(source, target).select_from(WorkItemLink).join(
            source, source.id == WorkItemLink.source_id).join(target, target.id == WorkItemLink.target_id).filter(
                WorkItemLink.tenant_id == user.tenant_id, WorkItemLink.link_type == 'blocks',
                WorkItemLink.target_type == 'work_item', source.tenant_id == user.tenant_id,
                target.tenant_id == user.tenant_id, source.project_id.in_(ids), target.project_id.in_(ids),
                source.project_id.in_(current_ids))
        link_total = links.count()
        dependencies = []
        for blocker, blocked in links.order_by(source.id, target.id).limit(DEPENDENCY_LIMIT):
            conflict = bool(blocker.due_date and blocked.start_date and blocker.due_date > blocked.start_date)
            dependencies.append(dict(source=blocker, target=blocked, conflict=conflict))
        return dict(projects=rows, summaries=summaries, dependencies=dependencies,
                    dependency_total=link_total, page_number=page, page_count=max(1,(count+PAGE_SIZE-1)//PAGE_SIZE),
                    project_total=count, shift_days=shift_days)
    except HTTPException:
        raise
    except OverflowError:
        abort(400, description=tr("The preview would move a date outside the supported calendar."))
    except Exception:
        current_app.logger.error("Project portfolio calculation failed for tenant %s", user.tenant_id)
        raise
