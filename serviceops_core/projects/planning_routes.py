"""Web and REST planning interfaces over the same permission-checked services."""
from datetime import timedelta
from functools import wraps

from flask import abort, current_app, flash, jsonify, request, redirect, url_for
from flask_login import current_user
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import roadmap, service, releases
from serviceops_core.projects.models import ProjectPlanningDraft
from serviceops_models import db, now


def guarded(fn):
    @wraps(fn)
    def call(*args, **kwargs):
        try:return fn(*args,**kwargs)
        except HTTPException:
            db.session.rollback();raise
        except Exception:
            db.session.rollback();current_app.logger.error('Project planning request failed: %s',fn.__name__)
            abort(503,description=tr('Planning is temporarily unavailable. Please try again.'))
    return call


@roadmap.guarded
def display(payload,values):
    zoom=values.get('zoom','months')
    if zoom not in ('weeks','months','years'):abort(400,description=tr('Choose weeks, months or years.'))
    anchor=roadmap.parse_date(values.get('anchor') or now().date().isoformat(),True)
    days={'weeks':84,'months':183,'years':730}[zoom]
    start=anchor-timedelta(days=anchor.weekday() if zoom=='weeks' else anchor.day-1)
    end=start+timedelta(days=days-1)
    if start.year<1900 or end.year>2200:abort(400,description=tr('Choose a timeline between 1900 and 2200.'))
    rows=roadmap.hierarchy(payload['items']);q=values.get('q','').strip().lower()
    category=values.get('category','');assignee=values.get('assignee','')
    if len(q)>200 or category not in ('','todo','in_progress','done'):abort(400)
    if assignee and assignee!='none' and (not assignee.isdigit() or len(assignee)>10):abort(400)
    by_id={r['id']:r for r in rows};children={}
    people={person['id']:person for r in rows for person in r['assignees']}
    for row in rows:children.setdefault(row['parent_id'],[]).append(row)
    for row in reversed(rows):
        nested=children.get(row['id'],[])
        row['is_parent']=bool(nested)
        starts=[r['shown_start'] or r['shown_due'] for r in nested if r['shown_start'] or r['shown_due']]
        ends=[r['shown_due'] or r['shown_start'] for r in nested if r['shown_due'] or r['shown_start']]
        row['shown_start']=row['start'] or (min(starts) if starts else None)
        row['shown_due']=row['due'] or (max(ends) if ends else None)
        row['derived']=row['shown_start']!=row['start'] or row['shown_due']!=row['due']
    if q or category or assignee:
        keep=set()
        for r in rows:
            matches=(not q or q in (r['key']+' '+r['title']).lower()) and (not category or r['category']==category)
            matches=matches and (not assignee or (not r['assignees'] if assignee=='none' else any(str(person['id'])==assignee for person in r['assignees'])))
            if matches:
                cursor=r
                while cursor and cursor['id'] not in keep:
                    keep.add(cursor['id']);cursor=by_id.get(cursor['parent_id'])
        rows=[r for r in rows if r['id'] in keep]
    for row in rows:
        begin,due=roadmap.parse_date(row['shown_start']),roadmap.parse_date(row['shown_due'])
        row['left']=round(max(0,min(100,((begin or due or start)-start).days/days*100)),4)
        row['width']=round(max(.5,min(100-row['left'],(((due or begin or start)-max(begin or due or start,start)).days+1)/days*100)),4)
        row['on_chart']=bool((begin or due) and (due or begin)>=start and (begin or due)<=end)
    ticks=[]
    step=7 if zoom=='weeks' else 30 if zoom=='months' else 90
    for offset in range(0,days,step):ticks.append((start+timedelta(days=offset)).isoformat())
    chart_ticks=[];cursor=start
    if zoom=='weeks':
        while cursor<=end:
            following_tick=min(end+timedelta(days=1),cursor+timedelta(days=7))
            chart_ticks.append(dict(date=cursor.isoformat(),left=(cursor-start).days/days*100,width=(following_tick-cursor).days/days*100));cursor=following_tick
    else:
        while cursor<=end:
            following_tick=cursor
            for _ in range(3 if zoom=='years' else 1):following_tick=(following_tick.replace(day=28)+timedelta(days=4)).replace(day=1)
            following_tick=min(end+timedelta(days=1),following_tick)
            chart_ticks.append(dict(date=cursor.isoformat(),left=(cursor-start).days/days*100,width=(following_tick-cursor).days/days*100));cursor=following_tick
    warnings=[]
    for edge in payload['dependencies']:
        if edge['conflict']:warnings.append(tr('{source} finishes on or after {target} starts.',source=edge['source_key'],target=edge['target_key']))
    missing=sum(not r['due'] and r['category']!='done' for r in payload['items'])
    if missing:warnings.append(tr('{count} open work items have no due date.',count=missing))
    return dict(rows=rows,zoom=zoom,anchor=anchor.isoformat(),start=start.isoformat(),end=end.isoformat(),ticks=ticks,chart_ticks=chart_ticks,
        previous=(anchor-timedelta(days=days)).isoformat(),following=(anchor+timedelta(days=days)).isoformat(),
        today=now().date().isoformat(),today_in_range=start<=now().date()<=end,today_left=max(0,min(100,(now().date()-start).days/days*100)),warnings=warnings,
        dependencies=payload['dependencies'],fingerprint=payload['fingerprint'],q=values.get('q',''),category=category,assignee=assignee,people=sorted(people.values(),key=lambda person:person['name']))


@roadmap.guarded
def draft_document(user,row):
    _,data=roadmap.draft(user,row.id)
    return dict(id=row.id,name=row.name,applied_at=roadmap.iso(row.applied_at),created_at=row.created_at.isoformat(),**data)


@roadmap.guarded
def form_draft(user,keys):
    if request.is_json:
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)-{'projects','name','mode','changes','start','hours','weekends','reserve_people'}:abort(400)
        mode=data.get('mode','manual')
        return roadmap.create_draft(user,keys or data.get('projects'),data.get('name','Timeline changes'),mode=mode,changes=data.get('changes'),**{k:data[k] for k in ('start','hours','weekends','reserve_people') if k in data})
    mode=request.form.get('mode','auto')
    if mode=='manual':
        item=service.item_or_404(user,request.form.get('item_key',''))
        return roadmap.create_draft(user,keys,request.form.get('name','Date adjustment'),mode='manual',
            changes={str(item.id):dict(start=request.form.get('start') or None,due=request.form.get('due') or None)})
    try:hours=int(request.form.get('hours','8'))
    except ValueError:abort(400,description=tr('Working hours must be a whole number.'))
    return roadmap.create_draft(user,keys,request.form.get('name','Schedule proposal'),start=request.form.get('start'),
        hours=hours,weekends=request.form.get('weekends')=='1',reserve_people=request.form.get('reserve_people')=='1')


@roadmap.guarded
def visible_drafts(user,key):
    rows=ProjectPlanningDraft.query.filter_by(owner_id=user.id,tenant_id=user.tenant_id,applied_at=None).order_by(ProjectPlanningDraft.id.desc()).limit(50).all()
    result=[]
    for row in rows:
        try:
            _,data=roadmap.draft(user,row.id)
            if key in data['keys']:result.append(row)
        except HTTPException as error:
            if error.code not in (403,404):raise
    return result


def register_web(bp,page):
    @bp.get('/projects/<key>/timeline')
    @guarded
    def planning_timeline(key):
        project=service.project_or_404(current_user,key);payload=roadmap.context(current_user,[project.key])
        return page('projects/timeline.html',project,tab='timeline',payload=payload,**display(payload,request.args),
            drafts=visible_drafts(current_user,project.key),
            view=roadmap.view_settings(current_user,project))

    @bp.get('/projects/planning/timeline')
    @guarded
    def portfolio_timeline():
        keys=request.args.getlist('project');payload=roadmap.context(current_user,keys or None)
        return page('projects/timeline.html',payload=payload,**display(payload,request.args),drafts=[],view={},available_projects=service.visible_projects(current_user).limit(50).all(),can_edit=any(r['editable'] for r in payload['items']))

    @bp.post('/projects/<key>/planning-drafts')
    @guarded
    def planning_create_draft(key):
        project=service.project_or_404(current_user,key);row=form_draft(current_user,[project.key]);db.session.commit()
        if request.is_json:return jsonify(draft_id=row.id,review_url=url_for('projects.planning_review',draft_id=row.id))
        return redirect(url_for('projects.planning_review',draft_id=row.id))

    @bp.post('/projects/planning/drafts')
    @guarded
    def portfolio_create_draft():
        row=form_draft(current_user,request.form.getlist('project') or None);db.session.commit()
        if request.is_json:return jsonify(draft_id=row.id,review_url=url_for('projects.planning_review',draft_id=row.id))
        return redirect(url_for('projects.planning_review',draft_id=row.id))

    @bp.get('/projects/planning/drafts/<int:draft_id>')
    @guarded
    def planning_review(draft_id):
        row,data=roadmap.draft(current_user,draft_id)
        fresh=roadmap.context(current_user,data['keys'])
        return page('projects/plan_review.html',draft=draft_document(current_user,row),stale=fresh['fingerprint']!=data['fingerprint'])

    @bp.post('/projects/planning/drafts/<int:draft_id>/<action>')
    @guarded
    def planning_apply(draft_id,action):
        if action=='apply':roadmap.apply_draft(current_user,draft_id,request.form.getlist('item_ids'));message=tr('Selected date changes saved.')
        elif action=='discard':roadmap.discard_draft(current_user,draft_id);message=tr('Planning draft discarded.')
        else:abort(404)
        db.session.commit();flash(message,'success')
        return redirect(url_for('projects.planning_overview'))

    @bp.get('/projects/<key>/calendar')
    @guarded
    def planning_calendar(key):
        project=service.project_or_404(current_user,key);payload=roadmap.context(current_user,[project.key])
        month=request.args.get('month',now().date().strftime('%Y-%m'));start=roadmap.parse_date(month+'-01',True)
        previous=(start-timedelta(days=1)).strftime('%Y-%m');following=(start+timedelta(days=32)).strftime('%Y-%m')
        return page('projects/calendar.html',project,tab='calendar',cells=roadmap.calendar_days(payload,month),month=month,previous=previous,following=following,goals=roadmap.goals(current_user,project))

    @bp.get('/projects/<key>/team')
    @guarded
    def planning_teams(key):
        project=service.project_or_404(current_user,key);payload=roadmap.context(current_user,[project.key])
        return page('projects/team.html',project,tab='teams',members=roadmap.team_summary(current_user,project,payload),
            unassigned=sum(r['category']!='done' and not r['assignees'] for r in payload['items']),versions=releases.versions(project))

    @bp.route('/projects/<key>/goals',methods=['GET','POST'])
    @guarded
    def planning_goals(key):
        project=service.project_or_404(current_user,key)
        if request.method=='POST':
            try:goal_id=int(request.form['goal_id']) if request.form.get('goal_id') else None
            except ValueError:abort(400)
            roadmap.save_goal(current_user,project,dict(title=request.form.get('title',''),description=request.form.get('description',''),
                target_date=request.form.get('target_date'),state=request.form.get('state','open'),item_keys=request.form.getlist('item_keys')),goal_id)
            db.session.commit();flash(tr('Goal saved.'),'success');return redirect(url_for('projects.planning_goals',key=project.key))
        return page('projects/goals.html',project,tab='goals',goals=roadmap.goals(current_user,project),items=roadmap.context(current_user,[project.key])['items'])

    @bp.get('/projects/<key>/backlog/groups')
    @guarded
    def planning_grouped_backlog(key):
        from serviceops_core.projects import backlog_controls
        from serviceops_core.projects.models import ProjectSprint,ProjectSprintItem,WorkItem
        project=service.project_or_404(current_user,key)
        roadmap.context(current_user,[project.key])  # enforce the complete-view bound
        filters=backlog_controls.read_filters(current_user,project,request.args)
        rows=backlog_controls.filtered(current_user,project,WorkItem.query.filter_by(tenant_id=current_user.tenant_id,project_id=project.id).filter(WorkItem.item_type.in_(['story','task','bug'])),filters).order_by(WorkItem.rank,WorkItem.id).all()
        memberships=ProjectSprintItem.query.join(ProjectSprint,ProjectSprint.id==ProjectSprintItem.sprint_id).filter(ProjectSprintItem.tenant_id==current_user.tenant_id,ProjectSprintItem.active.is_(True),ProjectSprint.project_id==project.id).all()
        assigned={m.work_item_id:m.sprint_id for m in memberships}
        sprint_rows=ProjectSprint.query.filter_by(tenant_id=current_user.tenant_id,project_id=project.id).filter(ProjectSprint.state.in_(['active','planned'])).order_by(ProjectSprint.created_at,ProjectSprint.id).limit(100).all()
        sections=[dict(sprint=s,items=[r for r in rows if assigned.get(r.id)==s.id]) for s in sprint_rows]
        sections.append(dict(sprint=None,items=[r for r in rows if r.id not in assigned and r.status.category!='done']))
        return page('projects/grouped_backlog.html',project,tab='backlog',sections=sections,selected=None,backlog_filters=filters,
            insights=backlog_controls.insights(WorkItem.query.filter(WorkItem.id.in_([r.id for r in rows]))),
            versions=releases.versions(project),epics=WorkItem.query.filter_by(tenant_id=current_user.tenant_id,project_id=project.id,item_type='epic').all(),
            members=service.assignable_users(project),statuses=list(project.statuses))

    @bp.post('/projects/<key>/backlog-inline/<item_key>')
    @guarded
    def planning_inline(key,item_key):
        from serviceops_core.projects import backlog_controls, sprints
        project=service.project_or_404(current_user,key)
        item=service.item_or_404(current_user,item_key)
        if item.project_id!=project.id:abort(404)
        target=request.form.get('view_sprint')
        if target:sprints.get(current_user,project,target)
        controls=backlog_controls.read_filters(current_user,project,request.form)
        changes={k:request.form[k] for k in ('status_id','story_points') if k in request.form}
        service.update_item(current_user,item,changes);db.session.commit();flash(tr('Work item saved.'),'success')
        endpoint='planning_grouped_backlog' if request.form.get('view_mode')=='groups' else 'sprint_backlog'
        return redirect(url_for('projects.'+endpoint,key=project.key,sprint=target or None,**{k:v for k,v in controls.items() if v}))

    @bp.post('/projects/<key>/view-settings')
    @guarded
    def planning_view_settings(key):
        project=service.project_or_404(current_user,key)
        target=request.form.get('view','backlog');target=target if target in ('backlog','board','list','timeline','groups') else 'backlog'
        controls={}
        if target in ('backlog','groups'):
            from serviceops_core.projects import backlog_controls,sprints
            controls={k:v for k,v in backlog_controls.read_filters(current_user,project,request.form).items() if v}
            if request.form.get('view_sprint'):
                controls['sprint']=sprints.get(current_user,project,request.form['view_sprint']).id
        roadmap.view_settings(current_user,project,{k:request.form.get(k)=='1' for k in roadmap.view_settings(current_user,project)})
        db.session.commit();flash(tr('View settings saved.'),'success')
        endpoint={'backlog':'sprint_backlog','board':'board','list':'item_list','timeline':'planning_timeline','groups':'planning_grouped_backlog'}[target]
        return redirect(url_for('projects.'+endpoint,key=project.key,**controls))



def register_api(app,user):
    @app.get('/api/v1/project-planning/timeline')
    @guarded
    def api_planning_timeline():
        core.require_api_scope('projects:read');payload=roadmap.context(user(),request.args.getlist('project') or None)
        return jsonify(dict(data=payload,display=display(payload,request.args)))

    @app.route('/api/v1/project-planning/drafts',methods=['GET','POST'])
    @guarded
    def api_planning_drafts():
        actor=user();core.require_api_scope('projects:write' if request.method=='POST' else 'projects:read')
        if request.method=='GET':
            rows=ProjectPlanningDraft.query.filter_by(tenant_id=actor.tenant_id,owner_id=actor.id).order_by(ProjectPlanningDraft.id.desc()).limit(50).all()
            visible=[]
            for row in rows:
                try:visible.append(draft_document(actor,row))
                except HTTPException as error:
                    if error.code not in (403,404):raise
            return jsonify(data=visible)
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)-{'projects','name','mode','changes','start','hours','weekends','reserve_people'}:abort(400)
        projects=data.pop('projects',None);name=data.pop('name','Schedule proposal');mode=data.pop('mode','auto');changes=data.pop('changes',None)
        roadmap.context(actor,projects)
        idem,request_hash,replay=core.api_idempotency_context()
        if replay:return replay
        row=roadmap.create_draft(actor,projects,name,mode,changes,**data)
        document=draft_document(actor,row);core.store_api_idempotency(idem,request_hash,document,201)
        db.session.commit();return jsonify(document),201

    @app.route('/api/v1/project-planning/drafts/<int:draft_id>',methods=['GET','DELETE'])
    @guarded
    def api_planning_draft(draft_id):
        actor=user();core.require_api_scope('projects:write' if request.method=='DELETE' else 'projects:read')
        if request.method=='DELETE':roadmap.discard_draft(actor,draft_id);db.session.commit();return '',204
        row,_=roadmap.draft(actor,draft_id);return jsonify(draft_document(actor,row))

    @app.post('/api/v1/project-planning/drafts/<int:draft_id>/apply')
    @guarded
    def api_planning_apply(draft_id):
        core.require_api_scope('projects:write');data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)!={'item_ids'}:abort(400)
        roadmap.apply_draft(user(),draft_id,data['item_ids']);db.session.commit();return jsonify(status='saved')

    @app.route('/api/v1/projects/<key>/goals',methods=['GET','POST'])
    @guarded
    def api_planning_goals(key):
        core.require_api_scope('projects:write' if request.method=='POST' else 'projects:read')
        actor=user();project=service.project_or_404(actor,key)
        if request.method=='GET':return jsonify(data=roadmap.goals(actor,project))
        service.require_edit(actor,project)
        idem,request_hash,replay=core.api_idempotency_context()
        if replay:return replay
        row=roadmap.save_goal(actor,project,request.get_json(silent=True));document={'id':row.id}
        core.store_api_idempotency(idem,request_hash,document,201);db.session.commit();return jsonify(document),201

    @app.patch('/api/v1/projects/<key>/goals/<int:goal_id>')
    @guarded
    def api_planning_goal_update(key,goal_id):
        core.require_api_scope('projects:write');actor=user();project=service.project_or_404(actor,key)
        data=request.get_json(silent=True)
        if not isinstance(data,dict):abort(400)
        old=next((g for g in roadmap.goals(actor,project) if g['id']==goal_id),None)
        if old is None:abort(404)
        values={k:old[k] for k in ('title','description','target_date','state','item_keys')};values.update(data)
        roadmap.save_goal(actor,project,values,goal_id);db.session.commit();return jsonify(status='saved')

    @app.route('/api/v1/projects/<key>/view-preferences',methods=['GET','PUT'])
    @guarded
    def api_planning_preferences(key):
        core.require_api_scope('projects:write' if request.method=='PUT' else 'projects:read')
        actor=user();project=service.project_or_404(actor,key)
        data=request.get_json(silent=True) if request.method=='PUT' else None
        if request.method=='PUT' and not isinstance(data,dict):abort(400)
        result=roadmap.view_settings(actor,project,data)
        db.session.commit();return jsonify(result)

    @app.get('/api/v1/projects/<key>/planning-calendar')
    @guarded
    def api_planning_calendar(key):
        core.require_api_scope('projects:read');actor=user();project=service.project_or_404(actor,key)
        payload=roadmap.context(actor,[project.key]);return jsonify(data=roadmap.calendar_days(payload,request.args.get('month',now().date().strftime('%Y-%m'))))

    @app.get('/api/v1/projects/<key>/planning-team')
    @guarded
    def api_planning_team(key):
        core.require_api_scope('projects:read');actor=user();project=service.project_or_404(actor,key)
        return jsonify(data=roadmap.team_summary(actor,project,roadmap.context(actor,[project.key])))
