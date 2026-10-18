"""Project backlog, sprint controls and matching scoped REST interfaces."""
import json
from functools import wraps

from flask import abort, current_app, flash, jsonify, redirect, request, url_for
from flask_login import current_user
from sqlalchemy.orm import joinedload
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import service, sprints, backlog_controls, releases
from serviceops_core.projects.models import ProjectSprint, ProjectSprintEvent, ProjectSprintItem, ProjectStatus, WorkItem
from serviceops_core.projects.search_api import body_object, pagination
from serviceops_models import db


def guarded(fn):
    @wraps(fn)
    def call(*args, **kwargs):
        try: return fn(*args, **kwargs)
        except HTTPException:
            db.session.rollback(); raise
        except Exception:
            db.session.rollback()
            current_app.logger.error('Project sprint request failed: %s', fn.__name__)
            abort(503, description=tr('Sprint planning is temporarily unavailable. Please try again.'))
    return call


def document(row):
    return dict(id=row.id, project=row.project.key, name=row.name, goal=row.goal, state=row.state,
        **{f: sprints.utc(getattr(row, f)).isoformat() if getattr(row, f) else None
           for f in ('start_at', 'end_at', 'started_at', 'completed_at')})


def event_document(row):
    return dict(id=row.id, kind=row.kind, membership_id=row.membership_id, actor_id=row.actor_id,
                created_at=sprints.utc(row.created_at).isoformat(), data=json.loads(row.payload_json))


def assignment_body(data):
    if not isinstance(data, dict) or set(data)-{'item_keys', 'sprint_id', 'before_key'}:
        abort(400, description=tr('Unknown sprint assignment fields.'))
    keys = data.get('item_keys')
    if not isinstance(keys, list) or not 1 <= len(keys) <= 100 or any(not isinstance(k,str) or len(k)>32 for k in keys):
        abort(400, description=tr('Select between 1 and 100 work item keys.'))
    target = data.get('sprint_id')
    if target is not None and (type(target) is not int or target <= 0):
        abort(400, description=tr('Choose a valid sprint or the backlog.'))
    before = data.get('before_key')
    if before is not None and (not isinstance(before,str) or len(before)>32 or len(keys)!=1):
        abort(400, description=tr('Ranking requires one work item and one target key.'))
    return list(dict.fromkeys(keys)), target, before


def register_web(blueprint, page):
    @blueprint.get('/projects/<key>/sprints')
    @guarded
    def sprint_list(key):
        project=service.project_or_404(current_user,key)
        state=request.args.get('state','')
        if state and state not in ('planned','active','closed'): abort(400,description=tr('Choose a valid sprint state.'))
        try: number=int(request.args.get('page','1'))
        except ValueError: abort(400,description=tr('Choose a valid sprint page.'))
        if not 1<=number<=1000000: abort(400,description=tr('Choose a valid sprint page.'))
        rows=ProjectSprint.query.filter_by(tenant_id=current_user.tenant_id,project_id=project.id)
        if state: rows=rows.filter_by(state=state)
        total=rows.count(); pages=max(1,(total+49)//50); number=min(number,pages)
        return page('projects/sprints.html',project=project,tab='backlog',state=state,
                    rows=rows.order_by(ProjectSprint.id.desc()).offset((number-1)*50).limit(50).all(),
                    total=total,page_number=number,page_count=pages)

    @blueprint.get('/projects/<key>/backlog')
    @guarded
    def sprint_backlog(key):
        project = service.project_or_404(current_user, key)
        rows = ProjectSprint.query.filter_by(tenant_id=current_user.tenant_id, project_id=project.id)
        selected = sprints.get(current_user, project, request.args['sprint']) if request.args.get('sprint') else None
        available = rows.filter(ProjectSprint.state != 'closed').order_by(ProjectSprint.created_at, ProjectSprint.id).limit(100).all()
        if selected and selected.state != 'closed' and selected.id not in [r.id for r in available]: available.append(selected)
        try: number = int(request.args.get('page','1'))
        except ValueError: abort(400, description=tr('Choose a valid backlog page.'))
        if not 1 <= number <= 1000000: abort(400, description=tr('Choose a valid backlog page.'))
        current = ProjectSprintItem.query.with_entities(ProjectSprintItem.work_item_id).filter_by(
            tenant_id=current_user.tenant_id, active=True)
        items = WorkItem.query.filter(WorkItem.tenant_id == current_user.tenant_id, WorkItem.project_id == project.id,
            WorkItem.item_type.in_(('story','task','bug'))).options(joinedload(WorkItem.status))
        if selected:
            memberships = ProjectSprintItem.query.with_entities(ProjectSprintItem.work_item_id).filter_by(
                tenant_id=current_user.tenant_id, sprint_id=selected.id, active=True)
            items = items.filter(WorkItem.id.in_(memberships))
        else:
            items = items.filter(~WorkItem.id.in_(current.filter(ProjectSprintItem.work_item_id.isnot(None))),
                                 WorkItem.status.has(ProjectStatus.category != 'done'))
        controls=backlog_controls.read_filters(current_user,project,request.args)
        items=backlog_controls.filtered(current_user,project,items,controls)
        insight=backlog_controls.insights(items)
        total = items.count() if not selected or selected.state != 'closed' else 0
        number = min(number, max(1,(total+49)//50))
        visible = items.order_by(WorkItem.rank,WorkItem.id).offset((number-1)*50).limit(50).all() if total else []
        metrics = sprints.totals(sprints.snapshot(item) for item in visible)
        # Full sprint totals use scalar columns rather than loading every card and its relationships.
        if selected and selected.state != 'closed':
            all_values = items.with_entities(WorkItem.story_points,WorkItem.estimate_minutes,WorkItem.remaining_minutes,ProjectStatus.category).join(
                ProjectStatus, ProjectStatus.id == WorkItem.status_id).all()
            metrics = sprints.totals(dict(points=float(p or 0),estimate=int(e or 0),points_missing=p is None,estimate_missing=e is None,remaining=0 if c=='done' else int(r if r is not None else e or 0),done=c=='done') for p,e,r,c in all_values)
        return page('projects/backlog.html',project=project,tab='backlog',sprints=available,selected=selected,
            items=visible,total=total,page_number=number,page_count=max(1,(total+49)//50),metrics=metrics,
            backlog_filters=controls,insights=insight,versions=releases.versions(project),
            epics=WorkItem.query.filter_by(project_id=project.id,tenant_id=current_user.tenant_id,item_type='epic').order_by(WorkItem.number).all(),
            members=service.assignable_users(project),statuses=list(project.statuses),
            velocity=sprints.velocity(current_user,project),
            edit_start=sprints.utc(selected.start_at).strftime('%Y-%m-%dT%H:%M') if selected and selected.start_at else '',
            edit_end=sprints.utc(selected.end_at).strftime('%Y-%m-%dT%H:%M') if selected and selected.end_at else '')

    @blueprint.post('/projects/<key>/sprints/save')
    @guarded
    def sprint_save(key):
        project=service.project_or_404(current_user,key)
        row=sprints.save(current_user,project,{k:request.form.get(k,'') for k in ('name','goal','start_at','end_at')},
                         request.form.get('sprint_id') or None)
        db.session.commit(); flash(tr('Sprint saved.'),'success')
        return redirect(url_for('projects.sprint_backlog',key=project.key,sprint=row.id))

    @blueprint.post('/projects/<key>/sprints/<int:sprint_id>/<action>')
    @guarded
    def sprint_action(key,sprint_id,action):
        project=service.project_or_404(current_user,key)
        if action=='start': sprints.start(current_user,project,sprint_id)
        elif action=='complete': sprints.complete(current_user,project,sprint_id,request.form.get('destination_id') or None)
        elif action=='delete': sprints.delete(current_user,project,sprint_id)
        else: abort(404)
        db.session.commit(); flash(tr('Sprint updated.'),'success')
        return redirect(url_for('projects.sprint_backlog',key=project.key,**({'sprint':sprint_id} if action!='delete' else {})))

    @blueprint.post('/projects/<key>/sprint-items')
    @guarded
    def sprint_assign(key):
        project=service.project_or_404(current_user,key)
        if request.is_json: data=body_object()
        else:
            raw=request.form.get('sprint_id')
            try: target=int(raw) if raw else None
            except ValueError: abort(400,description=tr('Choose a valid sprint or the backlog.'))
            data={'item_keys':request.form.getlist('item_keys'),'sprint_id':target}
            if request.form.get('before_key'): data['before_key']=request.form['before_key']
        origin=request.form.get('view_sprint') if not request.is_json else None
        if origin: sprints.get(current_user,project,origin)
        try: origin_page=int(request.form.get('view_page','1')) if not request.is_json else 1
        except ValueError: abort(400,description=tr('Choose a valid backlog page.'))
        if not 1<=origin_page<=1000000: abort(400,description=tr('Choose a valid backlog page.'))
        from serviceops_core.projects import backlog_controls
        controls=backlog_controls.read_filters(current_user,project,request.form) if not request.is_json else {}
        keys,target,before=assignment_body(data)
        for item_key in keys: sprints.assign(current_user,project,item_key,target,before)
        db.session.commit()
        flash(tr('Backlog updated.'),'success')
        if request.is_json: return jsonify({'saved':True})
        # Restore the originating view rather than following the assignment destination.
        destination={'sprint':origin} if origin else {}
        destination.update({k:v for k,v in controls.items() if v})
        if origin_page>1: destination['page']=origin_page
        return redirect(url_for('projects.sprint_backlog',key=project.key,**destination))

    @blueprint.get('/projects/<key>/sprints/<int:sprint_id>/report')
    @guarded
    def sprint_report(key,sprint_id):
        project=service.project_or_404(current_user,key)
        context=sprints.report(current_user,project,sprint_id,request.args.get('unit','points'))
        series=context['series']; maximum=max([1]+[max(d['scope'],d['ideal']) for d in series])
        chart={field:' '.join(f'{40+i*720/max(1,len(series)-1):.2f},{220-190*d[field]/maximum:.2f}' for i,d in enumerate(series))
               for field in ('scope','completed','remaining','ideal')}
        labels=dict(added=tr('Work added'),removed=tr('Work removed'),baseline=tr('Starting scope'),state=tr('Work updated'),
                    started=tr('Sprint started'),completed=tr('Sprint completed'),edited=tr('Sprint edited'))
        event_rows=[dict(time=e.created_at,label=labels.get(e.kind,tr('Updated')),key=json.loads(e.payload_json).get('key','')) for e in context['events']]
        try: work_page=int(request.args.get('work_page','1'))
        except ValueError: abort(400,description=tr('Choose a valid report page.'))
        if not 1<=work_page<=1000000: abort(400,description=tr('Choose a valid report page.'))
        work_total=len(context['work']); work_pages=max(1,(work_total+49)//50); work_page=min(work_page,work_pages)
        context['work']=context['work'][(work_page-1)*50:work_page*50]
        return page('projects/sprint_report.html',project=project,tab='reports',chart=chart,maximum=maximum,event_rows=event_rows,
                    work_total=work_total,work_page=work_page,work_pages=work_pages,
                    velocity=sprints.velocity(current_user,project),**context)


def register_api(app, api_user, item_document):
    def project_for(key,write=False):
        core.require_api_scope('projects:write' if write else 'projects:read')
        user=api_user()
        return user,service.project_or_404(user,key)

    @app.route('/api/v1/projects/<key>/sprints',methods=['GET','POST'])
    @guarded
    def api_project_sprints(key):
        user,project=project_for(key,request.method=='POST')
        if request.method=='POST':
            idem,request_hash,replay=core.api_idempotency_context()
            if replay: return replay
            row=sprints.save(user,project,body_object())
            response={'data':document(row)}
            core.store_api_idempotency(idem,request_hash,response,201)
            db.session.commit()
            return jsonify(response),201
        limit,offset=pagination()
        query=ProjectSprint.query.filter_by(tenant_id=user.tenant_id,project_id=project.id)
        state=request.args.get('state')
        if state:
            if state not in ('planned','active','closed'): abort(400,description=tr('Choose a valid sprint state.'))
            query=query.filter_by(state=state)
        total=query.count()
        return jsonify({'data':[document(r) for r in query.order_by(ProjectSprint.id.desc()).offset(offset).limit(limit)],
                        'meta':{'total':total,'limit':limit,'offset':offset}})

    @app.route('/api/v1/projects/<key>/sprints/<int:sprint_id>',methods=['GET','PATCH','DELETE'])
    @guarded
    def api_project_sprint(key,sprint_id):
        user,project=project_for(key,request.method!='GET')
        if request.method=='PATCH': row=sprints.save(user,project,body_object(),sprint_id)
        elif request.method=='DELETE':
            sprints.delete(user,project,sprint_id); db.session.commit(); return '',204
        else: row=sprints.get(user,project,sprint_id)
        db.session.commit()
        return jsonify({'data':document(row)})

    @app.post('/api/v1/projects/<key>/sprints/<int:sprint_id>/start',defaults={'action':'start'})
    @app.post('/api/v1/projects/<key>/sprints/<int:sprint_id>/complete',defaults={'action':'complete'})
    @guarded
    def api_project_sprint_action(key,sprint_id,action):
        user,project=project_for(key,True); data=body_object()
        if action=='start':
            if data: abort(400,description=tr('Starting a sprint accepts an empty JSON object.'))
            row=sprints.start(user,project,sprint_id)
        elif action=='complete':
            if set(data)-{'destination_id'}: abort(400,description=tr('Unknown sprint completion fields.'))
            destination=data.get('destination_id')
            if destination is not None and (type(destination) is not int or destination<=0):
                abort(400,description=tr('Choose a valid destination sprint.'))
            row=sprints.complete(user,project,sprint_id,destination)
        else: abort(404)
        db.session.commit(); return jsonify({'data':document(row)})

    @app.put('/api/v1/projects/<key>/sprint-items')
    @guarded
    def api_project_sprint_assign(key):
        user,project=project_for(key,True)
        keys,target,before=assignment_body(body_object())
        for item_key in keys: sprints.assign(user,project,item_key,target,before)
        db.session.commit(); return jsonify({'data':{'saved':True,'item_keys':keys,'sprint_id':target}})

    @app.get('/api/v1/projects/<key>/sprints/<int:sprint_id>/items')
    @guarded
    def api_project_sprint_items(key,sprint_id):
        user,project=project_for(key); row=sprints.get(user,project,sprint_id); limit,offset=pagination()
        query=ProjectSprintItem.query.filter_by(tenant_id=user.tenant_id,sprint_id=row.id)
        if row.state!='closed':
            query=query.filter_by(active=True).options(joinedload(ProjectSprintItem.item.and_(
                WorkItem.project_id==project.id,WorkItem.tenant_id==user.tenant_id)).joinedload(WorkItem.status))
        total=query.count()
        data=[]
        for member in query.order_by(ProjectSprintItem.id).offset(offset).limit(limit):
            # Historical snapshots stay in the original project; moved/deleted live objects are never expanded.
            item=member.item if member.active else None
            data.append({'membership_id':member.id,'key':member.item_key,'title':member.title,'active':member.active,
                         'item':item_document(item) if member.active and item and item.project_id==project.id else None})
        return jsonify({'data':data,'meta':{'total':total,'offset':offset,'limit':limit}})

    @app.get('/api/v1/projects/<key>/sprints/<int:sprint_id>/events')
    @guarded
    def api_project_sprint_events(key,sprint_id):
        user,project=project_for(key); row=sprints.get(user,project,sprint_id); limit,offset=pagination()
        query=ProjectSprintEvent.query.filter_by(tenant_id=user.tenant_id,sprint_id=row.id)
        return jsonify({'data':[event_document(e) for e in query.order_by(ProjectSprintEvent.id).offset(offset).limit(limit)],
                        'meta':{'total':query.count(),'offset':offset,'limit':limit}})

    @app.get('/api/v1/projects/<key>/sprints/<int:sprint_id>/report')
    @guarded
    def api_project_sprint_report(key,sprint_id):
        user,project=project_for(key); result=sprints.report(user,project,sprint_id,request.args.get('unit','points'))
        result['sprint']=document(result['sprint']); result['events']=[event_document(e) for e in result['events']]
        return jsonify({'data':result})

    @app.get('/api/v1/projects/<key>/velocity')
    @guarded
    def api_project_velocity(key):
        user,project=project_for(key)
        return jsonify({'data':sprints.velocity(user,project)})
