"""Bounded project planning, reviewable scheduling and goal/view persistence."""
import calendar
import hashlib
import json
import math
from collections import defaultdict
from datetime import date, timedelta
from functools import wraps

from flask import abort, current_app
from sqlalchemy import or_
from sqlalchemy.orm import joinedload
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import service
from serviceops_core.projects.models import (Project, ProjectGoal, ProjectGoalItem, ProjectMember,
    ProjectPlanningDraft, ProjectViewPreference, WorkItem, WorkItemLink)
from serviceops_models import db, now

MAX_ITEMS = 500
MAX_LINKS = 2000


def guarded(fn):
    @wraps(fn)
    def call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except HTTPException:
            raise
        except Exception:
            current_app.logger.error('Project planning operation failed: %s', fn.__name__)
            raise
    return call


@guarded
def iso(value):
    return value.isoformat() if value else None


@guarded
def parse_date(value, required=False):
    try:
        if value in (None, '') and not required:
            return None
        if not isinstance(value, str) or len(value) != 10:
            raise ValueError()
        result = date.fromisoformat(value)
        if not 1900 <= result.year <= 2200:
            raise ValueError()
        return result
    except (ValueError, TypeError):
        abort(400, description=tr('Use a date between 1900 and 2200 in YYYY-MM-DD format.'))


@guarded
def context(user, keys=None):
    projects = service.visible_projects(user, include_archived=bool(keys)).order_by(Project.id)
    if keys:
        if not isinstance(keys, list) or len(keys) > 50 or any(not isinstance(k, str) for k in keys):
            abort(400, description=tr('Choose up to 50 project keys.'))
        keys = set(k.upper() for k in keys)
        projects = projects.filter(Project.key.in_(keys))
    projects = projects.limit(51).all()
    if len(projects) > 50:
        abort(422, description=tr('Choose a smaller project scope: planning supports up to 50 projects.'))
    if keys and {p.key for p in projects} != keys:
        abort(404)
    ids = [p.id for p in projects]
    rows = WorkItem.query.filter(WorkItem.tenant_id == user.tenant_id, WorkItem.project_id.in_(ids)).options(
        joinedload(WorkItem.status), joinedload(WorkItem.project)).order_by(WorkItem.project_id, WorkItem.rank, WorkItem.id).limit(MAX_ITEMS+1).all()
    if len(rows) > MAX_ITEMS:
        abort(422, description=tr('This planning scope exceeds 500 work items. Choose a smaller project.'))
    item_ids = [r.id for r in rows]
    visible_ids = service.visible_projects(user, include_archived=True).with_entities(Project.id)
    a, b = db.aliased(WorkItem), db.aliased(WorkItem)
    edges = db.session.query(a, b).select_from(WorkItemLink).join(a, a.id == WorkItemLink.source_id).join(
        b, b.id == WorkItemLink.target_id).filter(WorkItemLink.tenant_id == user.tenant_id,
        WorkItemLink.target_type == 'work_item', WorkItemLink.link_type == 'blocks',
        a.tenant_id == user.tenant_id, b.tenant_id == user.tenant_id,
        a.project_id.in_(visible_ids), b.project_id.in_(visible_ids),
        or_(a.id.in_(item_ids), b.id.in_(item_ids))).order_by(a.id, b.id).limit(MAX_LINKS+1).all() if rows else []
    if len(edges) > MAX_LINKS:
        abort(422, description=tr('This planning scope exceeds 2,000 dependencies.'))
    editable = {p.id: service.can_edit(user, p) for p in projects}
    data = [dict(id=r.id, key=r.key, title=r.title, project=r.project.key, project_id=r.project_id,
        parent_id=r.parent_id, type=r.item_type, status=r.status.name, category=r.status.category,
        start=iso(r.start_date), due=iso(r.due_date), points=r.story_points,
        remaining=r.remaining_minutes, estimate=r.estimate_minutes, flagged=r.flagged,
        assignees=[dict(id=u.id, name=u.name) for u in r.assignees], editable=editable[r.project_id],
        updated=r.updated_at.isoformat()) for r in rows]
    external = {r.id: dict(id=r.id, project_id=r.project_id, key=r.key, start=iso(r.start_date), due=iso(r.due_date),
        category=r.status.category, updated=r.updated_at.isoformat()) for edge in edges for r in edge if r.id not in item_ids}
    dependencies = [dict(source=a.id, target=b.id, source_key=a.key, target_key=b.key,
        conflict=bool(a.due_date and b.start_date and a.due_date >= b.start_date)) for a,b in edges]
    payload = dict(items=data, dependencies=dependencies, external=list(external.values()), projects=[dict(key=p.key,id=p.id,name=p.name) for p in projects])
    payload['fingerprint'] = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return payload


@guarded
def hierarchy(items):
    by_id = {r['id']: r for r in items}
    children = defaultdict(list)
    for row in items:
        children[row['parent_id'] if row['parent_id'] in by_id else None].append(row)
    ordered, visited = [], set()
    stack = [(r,0) for r in reversed(children[None])]
    while stack:
        row, depth = stack.pop()
        if row['id'] in visited:
            abort(409, description=tr('Repair the work hierarchy before planning.'))
        visited.add(row['id']); ordered.append(dict(row,depth=depth))
        stack.extend((child,depth+1) for child in reversed(children[row['id']]))
    if len(ordered) != len(items):
        abort(409, description=tr('Repair the work hierarchy before planning.'))
    return ordered


@guarded
def next_workday(day, weekends):
    while not weekends and day.weekday() >= 5:
        day += timedelta(days=1)
    return day


@guarded
def schedule(payload, start, hours=8, weekends=False, reserve_people=True):
    start = parse_date(start, required=True)
    if type(hours) is not int or not 1 <= hours <= 24 or type(weekends) is not bool or type(reserve_people) is not bool:
        abort(400, description=tr('Choose 1 to 24 working hours per day and valid scheduling options.'))
    ordered = hierarchy(payload['items']); by_id = {r['id']:r for r in ordered}
    children = defaultdict(list)
    for row in ordered:
        if row['parent_id'] in by_id: children[row['parent_id']].append(row['id'])
    leaves = {}
    for row in reversed(ordered):
        leaves[row['id']] = [i for c in children[row['id']] for i in leaves[c]] if children[row['id']] else [row['id']]
    predecessors = defaultdict(set); successors = defaultdict(set)
    for edge in payload['dependencies']:
        if edge['target'] not in by_id: continue
        sources = leaves.get(edge['source'], [edge['source']])
        for target in leaves[edge['target']]:
            for source in sources:
                if source == target:
                    abort(409, description=tr('Dependency cycles prevent automatic scheduling.'))
                predecessors[target].add(source); successors[source].add(target)
                if sum(len(v) for v in predecessors.values()) > 10000:
                    abort(422, description=tr('The expanded dependency graph is too large.'))
    nodes = sorted({i for ids in leaves.values() for i in ids})
    indegree = {i:len(predecessors[i] & set(nodes)) for i in nodes}
    ready = sorted(i for i in nodes if not indegree[i]); result = {}; availability = {}
    if reserve_people:
        for row in ordered:
            if not row['editable'] and row['category']!='done' and row['due']:
                for person in row['assignees']:
                    availability[person['id']]=max(availability.get(person['id'],start),next_workday(parse_date(row['due'])+timedelta(days=1),weekends))
    external = {r['id']:r for r in payload['external']}
    while ready:
        item_id = ready.pop(0); row=by_id[item_id]
        if row['category']=='done' or not row['editable']:
            result[item_id] = (parse_date(row['start']),parse_date(row['due']))
        else:
            earliest = max(start,parse_date(row['start']) or start)
            for source in predecessors[item_id]:
                due = result[source][1] if source in result else parse_date(external.get(source,{}).get('due'))
                if not due:
                    abort(409, description=tr('A prerequisite has no due date. Date it before automatic scheduling.'))
                earliest = max(earliest,due+timedelta(days=1))
            people = [u['id'] for u in row['assignees']]
            if reserve_people:
                for person in people: earliest=max(earliest,availability.get(person,start))
            begin=next_workday(earliest,weekends)
            old_start,old_due=parse_date(row['start']),parse_date(row['due'])
            duration = max(1,sum(weekends or (old_start+timedelta(days=offset)).weekday()<5 for offset in range((old_due-old_start).days+1))) if old_start and old_due else max(1,math.ceil((row['remaining'] if row['remaining'] is not None else row['estimate'] or hours*60)/(hours*60)))
            if duration > 366:
                abort(422, description=tr('A work item exceeds the 366-day scheduling limit.'))
            end=begin
            for _ in range(duration-1):end=next_workday(end+timedelta(days=1),weekends)
            if end > start+timedelta(days=1825) or end.year>2200:
                abort(422, description=tr('The schedule exceeds the five-year planning horizon.'))
            result[item_id]=(begin,end)
            if reserve_people:
                for person in people:availability[person]=next_workday(end+timedelta(days=1),weekends)
        for target in sorted(successors[item_id]):
            if target not in indegree:continue
            indegree[target]-=1
            if indegree[target]==0:ready.append(target);ready.sort()
    if len(result)!=len(nodes):
        abort(409, description=tr('Dependency cycles prevent automatic scheduling.'))
    for row in reversed(ordered):
        if children[row['id']]:
            dates=[result[c] for c in children[row['id']]]
            result[row['id']]=(min((s for s,_ in dates if s),default=None),max((d for _,d in dates if d),default=None))
    return {str(i):dict(start=iso(s),due=iso(d)) for i,(s,d) in result.items() if by_id[i]['editable'] and by_id[i]['category']!='done' and (iso(s),iso(d))!=(by_id[i]['start'],by_id[i]['due'])}


@guarded
def create_draft(user, keys, name, mode='auto', changes=None, **options):
    payload=context(user,keys)
    if not isinstance(name,str) or not name.strip() or len(name)>100:
        abort(400,description=tr('Plan name must contain 1 to 100 characters.'))
    if mode=='auto':
        if 'start' not in options or set(options)-{'start','hours','weekends','reserve_people'}:abort(400,description=tr('Provide a schedule start and valid scheduling options.'))
        changes=schedule(payload,**options)
    elif mode!='manual':abort(400,description=tr('Choose automatic or manual planning.'))
    if not isinstance(changes,dict) or not 1<=len(changes)<=MAX_ITEMS:
        abort(400,description=tr('The plan must contain 1 to 500 changed work items.'))
    by_id={str(r['id']):r for r in payload['items']}
    cleaned={}
    for key,value in changes.items():
        if key not in by_id or not isinstance(value,dict) or set(value)!={'start','due'}:abort(400,description=tr('Invalid planned work item.'))
        row=by_id[key]
        if not row['editable']:abort(403)
        begin,end=parse_date(value['start']),parse_date(value['due'])
        if begin and end and end<begin:abort(400,description=tr('The due date cannot be before the start date.'))
        cleaned[key]=dict(start=iso(begin),due=iso(end))
    if ProjectPlanningDraft.query.filter_by(tenant_id=user.tenant_id,owner_id=user.id,applied_at=None).count()>=50:
        abort(409,description=tr('Discard an old draft before creating more than 50 pending plans.'))
    content=dict(keys=[p['key'] for p in payload['projects']],fingerprint=payload['fingerprint'],changes=cleaned,
                 before={k:by_id[k] for k in cleaned},options=options,mode=mode)
    row=ProjectPlanningDraft(tenant_id=user.tenant_id,owner_id=user.id,name=name.strip(),payload_json=json.dumps(content),created_at=now())
    db.session.add(row);db.session.flush()
    core.audit('planning draft created',str(row.id),f'changes={len(cleaned)}',user_id=user.id,tenant_id=user.tenant_id)
    return row


@guarded
def draft(user,draft_id):
    row=ProjectPlanningDraft.query.filter_by(id=draft_id,tenant_id=user.tenant_id,owner_id=user.id).first()
    if row is None:abort(404)
    data=json.loads(row.payload_json)
    # Revalidate every project before exposing stored record titles.
    context(user,data['keys'])
    return row,data


@guarded
def apply_draft(user,draft_id,selected):
    row,data=draft(user,draft_id)
    if row.applied_at:abort(409,description=tr('This planning draft has already been applied.'))
    if not isinstance(selected,list) or not selected or any(str(i) not in data['changes'] for i in selected):
        abort(400,description=tr('Select valid changes to apply.'))
    # All project/item writes take the same project-first lock order as existing work commands.
    initial=context(user,data['keys'])
    ids=sorted({p['id'] for p in initial['projects']} | {r['project_id'] for r in initial['external']})
    Project.query.filter(Project.id.in_(ids),Project.tenant_id==user.tenant_id).order_by(Project.id).with_for_update().all()
    row=ProjectPlanningDraft.query.filter_by(id=row.id,owner_id=user.id,tenant_id=user.tenant_id).with_for_update().populate_existing().one()
    if row.applied_at:abort(409,description=tr('This planning draft has already been applied.'))
    db.session.expire_all(); service._forget_roles()
    fresh=context(user,data['keys'])
    if fresh['fingerprint']!=data['fingerprint']:
        abort(409,description=tr('Work or dependencies changed after this draft was created. Create a fresh plan.'))
    if data['mode']=='auto':
        final={r['id']:dict(start=r['start'],due=r['due']) for r in fresh['items']+fresh['external']}
        for selected_id in selected:final[int(selected_id)].update(data['changes'][str(selected_id)])
        selected_ids={int(i) for i in selected}
        for edge in fresh['dependencies']:
            if edge['target'] in selected_ids or edge['source'] in selected_ids:
                source_due=final[edge['source']]['due'];target_start=final[edge['target']]['start']
                if target_start and ((not source_due and edge['target'] in selected_ids) or (source_due and source_due>=target_start)):
                    abort(409,description=tr('The selected changes omit a prerequisite or conflict with its dates. Include the prerequisite changes or create a new plan.'))
    for item_id in sorted(set(int(i) for i in selected)):
        item=WorkItem.query.filter_by(id=item_id,tenant_id=user.tenant_id).one()
        service.update_item(user,item,{'start_date':data['changes'][str(item_id)]['start'],'due_date':data['changes'][str(item_id)]['due']})
    row.applied_at=now()
    core.audit('planning draft applied',str(row.id),f'changes={len(set(selected))}',user_id=user.id,tenant_id=user.tenant_id)
    return row


@guarded
def discard_draft(user,draft_id):
    row=ProjectPlanningDraft.query.filter_by(id=draft_id,tenant_id=user.tenant_id,owner_id=user.id).first()
    if row is None:abort(404)
    if row.applied_at:abort(409,description=tr('Applied plan history cannot be discarded.'))
    db.session.delete(row)
    core.audit('planning draft discarded',str(draft_id),'',user_id=user.id,tenant_id=user.tenant_id)


@guarded
def view_settings(user,project,data=None):
    if not service.can_view(user,project):abort(404)
    row=ProjectViewPreference.query.filter_by(tenant_id=user.tenant_id,project_id=project.id,user_id=user.id).first()
    defaults=dict(show_points=True,show_assignees=True,show_versions=True,show_epics=True,show_priority=True,compact=False)
    if data is not None:
        if not isinstance(data,dict) or set(data)-set(defaults) or any(type(v) is not bool for v in data.values()):
            abort(400,description=tr('Choose valid view settings.'))
        if row is None:
            row=ProjectViewPreference(tenant_id=user.tenant_id,project_id=project.id,user_id=user.id);db.session.add(row)
        defaults.update(data);row.payload_json=json.dumps(defaults)
    elif row:defaults.update(json.loads(row.payload_json))
    return defaults


@guarded
def goals(user,project):
    if not service.can_view(user,project):abort(404)
    result=[]
    rows=ProjectGoal.query.filter_by(tenant_id=user.tenant_id,project_id=project.id).order_by(ProjectGoal.id.desc()).limit(201).all()
    if len(rows)>200:abort(422,description=tr('This project exceeds 200 goals.'))
    for row in rows:
        items=WorkItem.query.join(ProjectGoalItem,ProjectGoalItem.work_item_id==WorkItem.id).filter(
            ProjectGoalItem.goal_id==row.id,ProjectGoalItem.tenant_id==user.tenant_id,
            WorkItem.tenant_id==user.tenant_id,WorkItem.project_id==project.id).all()
        result.append(dict(id=row.id,title=row.title,description=row.description,state=row.state,target_date=iso(row.target_date),
            total=len(items),done=sum(i.status.category=='done' for i in items),item_keys=[i.key for i in items],
            overdue=bool(row.target_date and row.target_date<now().date() and row.state=='open')))
    return result


@guarded
def save_goal(user,project,data,goal_id=None):
    service.require_edit(user,project)
    Project.query.filter_by(id=project.id,tenant_id=user.tenant_id).with_for_update().populate_existing().one()
    service._forget_roles();service.require_edit(user,project)
    if not isinstance(data,dict) or set(data)-{'title','description','target_date','state','item_keys'}:abort(400)
    title=data.get('title','');description=data.get('description','');state=data.get('state','open');keys=data.get('item_keys',[])
    if not isinstance(title,str) or not title.strip() or len(title)>160 or not isinstance(description,str) or len(description)>10000 or state not in ('open','achieved','cancelled'):
        abort(400,description=tr('Choose a title, valid goal state and description under 10,000 characters.'))
    if not isinstance(keys,list) or len(keys)>500 or any(not isinstance(k,str) for k in keys):abort(400)
    items=[]
    for key in set(keys):
        item=service.item_or_404(user,key)
        if item.project_id!=project.id:abort(400,description=tr('Goal work must belong to this project.'))
        items.append(item)
    row=ProjectGoal.query.filter_by(id=goal_id,tenant_id=user.tenant_id,project_id=project.id).first() if goal_id else None
    if goal_id and row is None:abort(404)
    if row is None:
        if ProjectGoal.query.filter_by(project_id=project.id,tenant_id=user.tenant_id).count()>=200:abort(409,description=tr('This project already has 200 goals.'))
        row=ProjectGoal(tenant_id=user.tenant_id,project_id=project.id,created_by_id=user.id,title=title.strip());db.session.add(row);db.session.flush()
    row.title,row.description,row.state,row.target_date=title.strip(),description,state,parse_date(data.get('target_date'))
    ProjectGoalItem.query.filter_by(goal_id=row.id,tenant_id=user.tenant_id).delete()
    for item in items:db.session.add(ProjectGoalItem(tenant_id=user.tenant_id,goal_id=row.id,work_item_id=item.id))
    core.audit('project goal saved',str(row.id),f'project={project.key}',user_id=user.id,tenant_id=user.tenant_id)
    return row


@guarded
def calendar_days(payload,month):
    start=parse_date(month+'-01',True)
    cells=[]
    for week in calendar.Calendar(firstweekday=0).monthdatescalendar(start.year,start.month):
        for day in week:
            events=[dict(item=r,kind='Start' if r['start']==iso(day) else 'Due') for r in payload['items'] if r['start']==iso(day) or r['due']==iso(day)]
            cells.append(dict(date=iso(day),day=day.day,current=day.month==start.month,today=day==now().date(),events=events))
    return cells


@guarded
def team_summary(user,project,payload):
    members=ProjectMember.query.filter_by(tenant_id=user.tenant_id,project_id=project.id).all()
    result=[]
    for member in members:
        items=[r for r in payload['items'] if any(u['id']==member.user_id for u in r['assignees']) and r['category']!='done']
        result.append(dict(id=member.user_id,name=member.user.name,role=member.role,open=len(items),
            remaining=sum(r['remaining'] or 0 for r in items),points=sum(r['points'] or 0 for r in items)))
    return result
