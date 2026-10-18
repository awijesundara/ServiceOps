"""Transactional sprint lifecycle, backlog membership and historical reports."""
import json
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import abort, current_app
from sqlalchemy.orm import joinedload
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import service
from serviceops_core.projects.models import Project, ProjectSprint, ProjectSprintEvent, ProjectSprintItem, ProjectStatus, WorkItem
from serviceops_models import db, now

MAX_MEMBERS = 5000
MAX_EVENTS = 50000


def guarded(fn):
    @wraps(fn)
    def call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except HTTPException:
            raise
        except Exception:
            current_app.logger.error('Project sprint operation failed: %s', fn.__name__)
            raise
    return call


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def timestamp(value):
    try:
        if value in (None, ''): return None
        if not isinstance(value, str) or len(value) > 40: raise ValueError()
        return utc(datetime.fromisoformat(value.replace('Z', '+00:00')))
    except (ValueError, TypeError, OverflowError):
        abort(400, description=tr('Enter a valid ISO date and time. Times without an offset use UTC.'))


def _lock(actor, project, manage=False):
    if not service.can_view(actor, project): abort(404)
    if manage:
        if not service.can_administer(actor, project): abort(403, description=tr('Only project administrators can manage sprints.'))
    service.require_edit(actor, project)
    with db.session.no_autoflush:
        Project.query.filter_by(id=project.id, tenant_id=actor.tenant_id).with_for_update().populate_existing().one()
    service._forget_roles()
    if manage and not service.can_administer(actor, project):
        abort(403, description=tr('Only project administrators can manage sprints.'))
    service.require_edit(actor, project)


def get(actor, project, sprint_id):
    if not service.can_view(actor, project): abort(404)
    try:
        if isinstance(sprint_id, bool): raise ValueError()
        sprint_id = int(sprint_id)
    except (ValueError, TypeError, OverflowError): abort(404)
    row = ProjectSprint.query.filter_by(id=sprint_id, project_id=project.id, tenant_id=actor.tenant_id).populate_existing().first()
    if row is None: abort(404)
    return row


def members(row):
    return ProjectSprintItem.query.filter_by(tenant_id=row.tenant_id, sprint_id=row.id, active=True).options(
        joinedload(ProjectSprintItem.item).joinedload(WorkItem.status)).order_by(ProjectSprintItem.id)


def snapshot(item):
    done = item.status.category == 'done'
    return dict(key=item.key, title=item.title, points=float(item.story_points or 0),
                points_missing=item.story_points is None, estimate_missing=item.estimate_minutes is None,
                estimate=int(item.estimate_minutes or 0),
                remaining=0 if done else int(item.remaining_minutes if item.remaining_minutes is not None else item.estimate_minutes or 0),
                done=done)


def totals(states):
    rows = list(states)
    result = {'unestimated_points':sum(r.get('points_missing',False) for r in rows),
              'unestimated_minutes':sum(r.get('estimate_missing',False) for r in rows)}
    for key in ('count', 'points', 'estimate', 'remaining'):
        result[key] = sum(1 if key == 'count' else r[key] for r in rows)
        result['done_'+key] = sum(1 if key == 'count' else r[key] for r in rows if r['done'])
    return result


def event(row, actor, kind, membership=None, payload=None):
    db.session.add(ProjectSprintEvent(tenant_id=row.tenant_id, sprint_id=row.id,
        membership_id=membership.id if membership else None, actor_id=actor.id,
        kind=kind, payload_json=json.dumps(payload or {}, sort_keys=True)))


def _dates(start, end, required=False):
    if bool(start) != bool(end) or required and not (start and end):
        abort(400, description=tr('Provide both sprint start and end times.'))
    if start and not timedelta(0) < end-start <= timedelta(days=366):
        abort(400, description=tr('Sprint end must follow start by no more than 366 days.'))


@guarded
def save(actor, project, data, sprint_id=None):
    _lock(actor, project, manage=True)
    allowed = {'name', 'goal', 'start_at', 'end_at'}
    if not isinstance(data, dict) or set(data)-allowed:
        abort(400, description=tr('Unknown sprint fields.'))
    row = get(actor, project, sprint_id) if sprint_id is not None else None
    if row and row.state == 'closed': abort(409, description=tr('A completed sprint cannot be edited.'))
    name = data.get('name', row.name if row else '')
    goal = data.get('goal', row.goal if row else '')
    if not isinstance(name, str) or not name.strip() or len(name) > 100 or any(ord(c) < 32 for c in name):
        abort(400, description=tr('Sprint name must contain 1 to 100 characters without control characters.'))
    if not isinstance(goal, str) or len(goal) > 10000 or '\x00' in goal:
        abort(400, description=tr('Sprint goal must contain at most 10,000 characters.'))
    try: name.encode('utf-8'); goal.encode('utf-8')
    except UnicodeEncodeError: abort(400, description=tr('Sprint text contains invalid Unicode.'))
    start = timestamp(data['start_at']) if 'start_at' in data else utc(row.start_at) if row and row.start_at else None
    end = timestamp(data['end_at']) if 'end_at' in data else utc(row.end_at) if row and row.end_at else None
    _dates(start, end, required=bool(row and row.state == 'active'))
    if row is None:
        row = ProjectSprint(tenant_id=actor.tenant_id, project_id=project.id, name=name.strip(),
                            goal=goal, created_by_id=actor.id, state='planned')
        db.session.add(row); db.session.flush()
    row.name, row.goal, row.start_at, row.end_at = name.strip(), goal, start, end
    event(row, actor, 'edited', payload={'name': row.name, 'goal': row.goal,
          'start_at': start.isoformat() if start else None, 'end_at': end.isoformat() if end else None})
    core.audit('sprint saved', str(row.id), row.name, user_id=actor.id, tenant_id=actor.tenant_id)
    return row


@guarded
def start(actor, project, sprint_id):
    _lock(actor, project, manage=True)
    row = get(actor, project, sprint_id)
    if row.state != 'planned': abort(409, description=tr('Only a planned sprint can be started.'))
    _dates(utc(row.start_at) if row.start_at else None, utc(row.end_at) if row.end_at else None, required=True)
    rows = members(row).all()
    row.state, row.started_at = 'active', now()
    row.baseline_json = json.dumps(totals(snapshot(m.item) for m in rows if m.item), sort_keys=True)
    for member in rows:
        if member.item: event(row, actor, 'baseline', member, snapshot(member.item))
    event(row, actor, 'started', payload=json.loads(row.baseline_json))
    core.audit('sprint started', str(row.id), row.name, user_id=actor.id, tenant_id=actor.tenant_id)
    return row


def _detach(actor, member, reason='removed'):
    row = member.sprint
    event(row, actor, reason, member, snapshot(member.item) if member.item else {})
    member.active, member.removed_at = False, now()
    db.session.flush()


def _assign(actor, project, item, target):
    if item.tenant_id != actor.tenant_id or item.project_id != project.id: abort(404)
    current = ProjectSprintItem.query.filter_by(tenant_id=actor.tenant_id, work_item_id=item.id, active=True).populate_existing().first()
    if current and target and current.sprint_id == target.id: return current
    if current is None and target is None: return None
    if target and (target.state == 'closed' or target.project_id != project.id):
        abort(409, description=tr('Choose a planned or active sprint in this project.'))
    if target and item.item_type not in ('story', 'task', 'bug'):
        abort(400, description=tr('Assign a story, task or bug. Subtasks follow their parent; epics are planned separately.'))
    if target and members(target).count() >= MAX_MEMBERS:
        abort(409, description=tr('A sprint can contain at most 5,000 work items.'))
    if current: _detach(actor, current)
    if target:
        member = ProjectSprintItem(tenant_id=actor.tenant_id, sprint_id=target.id, work_item_id=item.id,
                                   item_key=item.key, title=item.title, active=True)
        db.session.add(member); db.session.flush()
        event(target, actor, 'added', member, snapshot(item))
    else: member = None
    service.log_work_item_history(item, actor, 'sprint', current.sprint.name if current else None, target.name if target else None)
    return member


@guarded
def assign(actor, project, item_key, sprint_id=None, before_key=None):
    _lock(actor, project)
    item = service.item_or_404(actor, item_key)
    db.session.refresh(item, [column.key for column in WorkItem.__table__.columns])
    db.session.expire(item, ['status'])
    if item.project_id != project.id: abort(404)
    target = get(actor, project, sprint_id) if sprint_id is not None else None
    member = _assign(actor, project, item, target)
    if before_key:
        before = service.item_or_404(actor, before_key)
        if before.id == item.id or before.project_id != project.id: abort(400, description=tr('Choose a different work item in this project.'))
        before_member = ProjectSprintItem.query.filter_by(work_item_id=before.id, active=True, tenant_id=actor.tenant_id).first()
        if (before_member.sprint_id if before_member else None) != (target.id if target else None):
            abort(400, description=tr('Rank work items within the same backlog or sprint.'))
        if before.item_type not in ('story', 'task', 'bug') or before.status.category == 'done':
            abort(400, description=tr('Choose an unfinished story, task or bug as the ranking target.'))
        # One rank order is shared with the existing project board. Re-spacing
        # the two adjacent values avoids precision loss after repeated inserts.
        lower = WorkItem.query.filter(WorkItem.project_id == project.id, WorkItem.rank < before.rank,
                                      WorkItem.id != item.id).order_by(WorkItem.rank.desc()).first()
        item.rank = (lower.rank+before.rank)/2 if lower else before.rank-1000
        if lower and before.rank-lower.rank < 0.00001:
            ranked = WorkItem.query.filter_by(project_id=project.id).order_by(WorkItem.rank, WorkItem.id).all()
            for index, row in enumerate(ranked): row.rank = (index+1)*1000
            db.session.flush()
            return assign(actor, project, item_key, sprint_id, before_key)
    return member



def credited_outcome(row, rows):
    values = totals(snapshot(m.item) for m in rows if m.item)
    eligible = set()
    for e in ProjectSprintEvent.query.filter(ProjectSprintEvent.membership_id.in_([m.id for m in rows]), ProjectSprintEvent.sprint_id == row.id,
            ProjectSprintEvent.tenant_id == row.tenant_id, ProjectSprintEvent.created_at >= row.started_at).order_by(ProjectSprintEvent.id).yield_per(500):
        if e.membership_id and e.kind in ('baseline','added','state') and not json.loads(e.payload_json)['done']:
            eligible.add(e.membership_id)
    delivered = totals(snapshot(m.item) for m in rows if m.item and m.item.status.category == 'done' and m.id in eligible)
    for field in ('count','points','estimate'): values['delivered_'+field] = delivered[field]
    return values


def unfinished_descendants(rows, project):
    ids = [m.item.id for m in rows if m.item and m.item.status.category == 'done']
    if not ids: return False
    tree = db.session.query(WorkItem.id).filter(WorkItem.id.in_(ids), WorkItem.project_id == project.id,
                                              WorkItem.tenant_id == project.tenant_id).cte(recursive=True)
    tree = tree.union(db.session.query(WorkItem.id).join(tree, WorkItem.parent_id == tree.c.id).filter(
        WorkItem.project_id == project.id, WorkItem.tenant_id == project.tenant_id))
    return WorkItem.query.join(tree,WorkItem.id == tree.c.id).filter(~WorkItem.id.in_(ids),
        WorkItem.status.has(ProjectStatus.category != 'done')).first() is not None

@guarded
def complete(actor, project, sprint_id, destination_id=None):
    _lock(actor, project, manage=True)
    row = get(actor, project, sprint_id)
    if row.state != 'active': abort(409, description=tr('Only an active sprint can be completed.'))
    target = get(actor, project, destination_id) if destination_id is not None else None
    if target and (target.id == row.id or target.state == 'closed'):
        abort(400, description=tr('Choose another planned or active sprint, or the backlog.'))
    rows = members(row).all()
    if unfinished_descendants(rows, project):
        abort(409, description=tr('Complete the subtasks of finished parent work items, or reopen their parent before completing this sprint.'))
    if target:
        unfinished = sum(bool(m.item and m.item.status.category != 'done') for m in rows)
        if members(target).count()+unfinished > MAX_MEMBERS:
            abort(409, description=tr('The destination sprint would exceed 5,000 work items.'))
    row.outcome_json = json.dumps(credited_outcome(row,rows), sort_keys=True)
    row.state, row.completed_at = 'closed', now()
    for member in rows:
        if member.item: event(row, actor, 'state', member, snapshot(member.item))
        member.active, member.removed_at, member.completed = False, row.completed_at, True
    db.session.flush()
    for member in rows:
        if member.item: service.log_work_item_history(member.item, actor, 'sprint completed', row.name, target.name if target and member.item.status.category != 'done' else None)
        if member.item and member.item.status.category != 'done':
            _assign(actor, project, member.item, target)
    event(row, actor, 'completed', payload={'destination_id': target.id if target else None, **json.loads(row.outcome_json)})
    core.audit('sprint completed', str(row.id), row.name, user_id=actor.id, tenant_id=actor.tenant_id)
    return row


@guarded
def delete(actor, project, sprint_id):
    _lock(actor, project, manage=True)
    row = get(actor, project, sprint_id)
    if row.state != 'planned': abort(409, description=tr('Only a planned sprint can be deleted.'))
    for member in members(row).all():
        if member.item: service.log_work_item_history(member.item, actor, 'sprint', row.name, None)
    ProjectSprintEvent.query.filter_by(sprint_id=row.id).delete(synchronize_session=False)
    ProjectSprintItem.query.filter_by(sprint_id=row.id).delete(synchronize_session=False)
    core.audit('sprint deleted', str(row.id), row.name, user_id=actor.id, tenant_id=actor.tenant_id)
    db.session.delete(row)


@guarded
def capture(actor, item):
    member = ProjectSprintItem.query.filter_by(tenant_id=item.tenant_id, work_item_id=item.id, active=True).first()
    if not member: return
    if item.item_type not in ('story', 'task', 'bug'):
        abort(409, description=tr('Return this work item to the backlog before converting it to an epic or subtask.'))
    if member.sprint.state == 'active':
        payload = snapshot(item)
        previous = ProjectSprintEvent.query.filter_by(membership_id=member.id).order_by(ProjectSprintEvent.id.desc()).first()
        if previous is None or json.loads(previous.payload_json) != payload:
            event(member.sprint, actor, 'state', member, payload)


@guarded
def detach_for_removal(actor, item):
    member = ProjectSprintItem.query.filter_by(tenant_id=item.tenant_id, work_item_id=item.id, active=True).first()
    if member: _detach(actor, member)


@guarded
def report(actor, project, sprint_id, unit='points'):
    row = get(actor, project, sprint_id)
    if unit not in ('count', 'points', 'estimate', 'remaining'):
        abort(400, description=tr('Choose count, points, estimate or remaining as the report unit.'))
    baseline, outcome = json.loads(row.baseline_json), json.loads(row.outcome_json)
    events_query = ProjectSprintEvent.query.filter_by(tenant_id=actor.tenant_id, sprint_id=row.id)
    if events_query.count() > MAX_EVENTS:
        abort(422, description=tr('This sprint exceeds the 50,000-event reporting limit. Use the paginated event API.'))
    events = events_query.order_by(ProjectSprintEvent.created_at, ProjectSprintEvent.id).all()
    series, states = [], {}
    if row.started_at:
        start_at = utc(row.started_at)
        cutoff = utc(row.completed_at) if row.completed_at else now()
        # Edits cannot cause an unbounded chart. Actual activity may outlive the planned end.
        if (cutoff-start_at).days > 366:
            abort(422, description=tr('Sprint charts support at most 366 days of actual activity.'))
        relevant = [e for e in events if utc(e.created_at) >= start_at]
        cursor, day = 0, start_at.date()
        while day <= cutoff.date():
            end = min(datetime.combine(day+timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)-timedelta(microseconds=1), cutoff)
            while cursor < len(relevant) and utc(relevant[cursor].created_at) <= end:
                e = relevant[cursor]; payload = json.loads(e.payload_json)
                if e.membership_id:
                    if e.kind == 'removed': states.pop(e.membership_id, None)
                    elif e.kind in ('baseline', 'added', 'state'): states[e.membership_id] = payload
                cursor += 1
            values = totals(states.values())
            planned_days = max(1, (utc(row.end_at).date()-start_at.date()).days) if row.end_at else 1
            ideal = max(0, (baseline.get(unit,0)-baseline.get('done_'+unit,0))*(1-(day-start_at.date()).days/planned_days))
            remaining = values[unit]-values['done_'+unit]
            series.append({'date': day.isoformat(), 'scope': values[unit], 'completed': values['done_'+unit],
                           'remaining': remaining, 'ideal': round(ideal, 3)})
            day += timedelta(days=1)
    ever_open, last = set(), {}
    for e in events:
        if not e.membership_id: continue
        data = json.loads(e.payload_json)
        if e.kind in ('baseline','added','state','removed'):
            last[e.membership_id] = data
            if row.started_at and utc(e.created_at) >= utc(row.started_at) and e.kind in ('baseline','added','state'):
                if not data['done']: ever_open.add(e.membership_id)
    work = []
    for member in ProjectSprintItem.query.filter_by(tenant_id=row.tenant_id,sprint_id=row.id).order_by(ProjectSprintItem.id):
        data = last.get(member.id,{})
        if not data: continue
        removed = not member.active and not member.completed
        category = 'removed' if removed else 'incomplete' if not data['done'] else 'outside' if member.id not in ever_open else 'completed'
        work.append(dict(membership_id=member.id,category=category,**data))
    return dict(sprint=row, unit=unit, baseline=baseline, outcome=outcome, series=series,work=work,
                event_total=len(events), events=events[-100:])


@guarded
def velocity(actor, project):
    if not service.can_view(actor, project): abort(404)
    rows = ProjectSprint.query.filter_by(tenant_id=actor.tenant_id, project_id=project.id, state='closed').order_by(
        ProjectSprint.completed_at.desc(), ProjectSprint.id.desc()).limit(10).all()
    return [dict(id=r.id, name=r.name, committed=json.loads(r.baseline_json), delivered=json.loads(r.outcome_json)) for r in reversed(rows)]
