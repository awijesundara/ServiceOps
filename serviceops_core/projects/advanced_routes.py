"""Web/REST contracts for saved plans, structures, program boards and rule editing."""
import json
import math

from flask import abort,flash,jsonify,redirect,request,url_for
from flask_login import current_user
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_models import db,now
from serviceops_core.localization import tr
from serviceops_core.projects import advanced_plans as plans,automation,roadmap,service
from serviceops_core.projects.planning_routes import guarded,display
from serviceops_core.projects.models import ProjectPlan,ProjectPlanNode,ProjectPlanTeam,ProjectPlanScenario,ProjectPlanAllocation,ProjectAutomationRule,ProjectAutomationRun,ProjectVersion


@roadmap.guarded
def number(value,nullable=False):
    if nullable and value in ('',None):return None
    if type(value) not in (str,int):abort(400)
    try:return int(value)
    except (ValueError,TypeError):abort(400,description=tr('Choose a valid whole number.'))


@roadmap.guarded
def decimal(value):
    try:
        if type(value) not in (str,int,float):raise ValueError()
        result=float(value)
        if not math.isfinite(result):raise ValueError()
        return result
    except (ValueError,TypeError,OverflowError):abort(400)


@roadmap.guarded
def document(plan):
    return dict(id=plan.id,name=plan.name,description=plan.description,owner_id=plan.owner_id,projects=json.loads(plan.projects_json),settings=json.loads(plan.settings_json),revision=plan.revision)


@roadmap.guarded
def visible_plans(actor):
    result=[]
    for row in ProjectPlan.query.filter_by(tenant_id=actor.tenant_id).order_by(ProjectPlan.updated_at.desc()).limit(100):
        try:
            for key in json.loads(row.projects_json):service.project_or_404(actor,key)
            result.append(row)
        except HTTPException as error:
            if error.code not in (403,404):raise
    return result


@roadmap.guarded
def rule(actor,identifier):
    row=ProjectAutomationRule.query.filter_by(id=identifier,tenant_id=actor.tenant_id,owner_id=actor.id).first()
    if row is None:abort(404)
    for key in json.loads(row.projects_json):
        if not service.can_administer(actor,service.project_or_404(actor,key)):abort(403)
    return row


@roadmap.guarded
def rule_document(row):
    return dict(id=row.id,name=row.name,enabled=row.enabled,projects=json.loads(row.projects_json),config=json.loads(row.config_json),revision=row.revision,owner_id=row.owner_id)


@roadmap.guarded
def plan_form():
    return dict(name=request.form.get('name'),description=request.form.get('description',''),projects=request.form.getlist('projects'),
        settings=dict(start=request.form.get('start'),weeks=number(request.form.get('weeks','2')),iterations=number(request.form.get('iterations','6'))))


@roadmap.guarded
def rule_form():
    try:config=json.loads(request.form.get('config',''))
    except (ValueError,TypeError):abort(400,description=tr('Choose valid automation components.'))
    return dict(name=request.form.get('name'),enabled=request.form.get('enabled')=='1',projects=request.form.getlist('projects'),config=config,
        revision=number(request.form.get('revision'),True))


@roadmap.guarded
def edit_command(actor,plan,payload,action,data):
    if action=='node':return plans.save_node(actor,plan,payload,data)
    if action=='team':return plans.save_team(actor,plan,payload,data)
    if action=='allocate':return plans.allocate(actor,plan,payload,data.get('item_id'),data.get('team_id'),data.get('iteration'))
    if action=='auto':return plans.auto_allocate(actor,plan,payload)
    if action=='settings':return plans.save_settings(actor,plan,data)
    if action=='scenario':return plans.scenario(actor,plan,data.get('name'))
    if action=='restore':return plans.restore(actor,plan,payload,data.get('scenario_id'))
    abort(404)


def register_web(bp,page):
    @bp.route('/projects/plans',methods=['GET','POST'])
    @guarded
    def advanced_plan_index():
        if request.method=='POST':
            plan=plans.create(current_user,plan_form());db.session.commit();flash(tr('Plan created.'),'success')
            return redirect(url_for('projects.advanced_plan_view',plan_id=plan.id,view='timeline'))
        return page('projects/plans.html',plans=visible_plans(current_user),projects=service.visible_projects(current_user).limit(100).all(),today=now().date().isoformat())

    @bp.get('/projects/plans/<int:plan_id>/<view>')
    @guarded
    def advanced_plan_view(plan_id,view):
        if view not in ('timeline','structure','program','teams','releases','dependencies','settings'):abort(404)
        plan,payload=plans.get(current_user,plan_id)
        editable=(plan.owner_id==current_user.id or service._tenant_admin(current_user)) and all(service.can_edit(current_user,service.project_or_404(current_user,p['key'])) for p in payload['projects'])
        context=dict(plan=plan,plan_document=document(plan),payload=payload,plan_view=view,plan_editable=editable,project_keys={p['id']:p['key'] for p in payload['projects']},plan_has_allocations=ProjectPlanAllocation.query.filter_by(tenant_id=current_user.tenant_id,plan_id=plan.id).first() is not None,
            scenarios=ProjectPlanScenario.query.filter_by(tenant_id=current_user.tenant_id,plan_id=plan.id).order_by(ProjectPlanScenario.id.desc()).limit(20).all())
        if view=='timeline':
            values=request.args.to_dict();view_index=number(values.pop('saved_view',None),True)
            if view_index is not None:
                views=json.loads(plan.settings_json).get('views',[])
                if not 0<=view_index<len(views):abort(404)
                values={k:v for k,v in views[view_index].items() if k!='name'}|values
            context.update(display(payload,values),drafts=[],view={},can_edit=False)
            return page('projects/plan_timeline.html',**context)
        if view=='structure':context.update(plans.structure(current_user,plan,payload))
        if view in ('program','teams','settings'):
            context.update(plans.program(current_user,plan,payload))
            context['team_members']={t.id:json.loads(t.members_json) for t in context['teams']}
            context['eligible_people']=sorted({u.id:u for p in payload['projects'] for u in service.assignable_users(service.project_or_404(current_user,p['key']))}.values(),key=lambda u:u.name)
        if view=='releases':
            context['versions']=ProjectVersion.query.filter(ProjectVersion.tenant_id==current_user.tenant_id,ProjectVersion.project_id.in_([p['id'] for p in payload['projects']])).order_by(ProjectVersion.release_date,ProjectVersion.id).all()
        return page('projects/plan_'+view+'.html',**context)

    @bp.post('/projects/plans/<int:plan_id>/edit/<action>')
    @guarded
    def advanced_plan_edit(plan_id,action):
        if request.is_json:
            data=request.get_json(silent=True)
            if not isinstance(data,dict):abort(400)
            revision=data.pop('revision',None);plan,payload=plans.get(current_user,plan_id,True,revision)
            edit_command(current_user,plan,payload,action,data);db.session.commit();return jsonify(revision=plan.revision)
        plan,payload=plans.get(current_user,plan_id,True,number(request.form.get('revision')))
        target={'node':'structure','team':'teams','allocate':'program','scenario':'program','restore':'program','settings':'settings','review':'program','auto':'program','delete-node':'structure','delete-team':'teams','save-view':'timeline'}.get(action)
        if not target:abort(404)
        if action=='node':
            plans.save_node(current_user,plan,payload,dict(name=request.form.get('name'),kind=request.form.get('kind'),parent_id=number(request.form.get('parent_id'),True),item_keys=request.form.getlist('item_keys'),position=number(request.form.get('position','0'))),number(request.form.get('node_id'),True))
        elif action=='team':
            plans.save_team(current_user,plan,payload,dict(name=request.form.get('name'),capacity=decimal(request.form.get('capacity')),unit=request.form.get('unit'),members=[number(x) for x in request.form.getlist('members')]),number(request.form.get('team_id'),True))
        elif action=='allocate':plans.allocate(current_user,plan,payload,number(request.form.get('item_id')),number(request.form.get('team_id'),True),number(request.form.get('iteration'),True))
        elif action=='auto':plans.auto_allocate(current_user,plan,payload)
        elif action=='scenario':plans.scenario(current_user,plan,request.form.get('name'))
        elif action=='restore':plans.restore(current_user,plan,payload,number(request.form.get('scenario_id')))
        elif action=='settings':
            options=json.loads(plan.settings_json);options.update(start=request.form.get('start'),weeks=number(request.form.get('weeks')),iterations=number(request.form.get('iterations')),estimate_mode=request.form.get('estimate_mode'))
            plans.save_settings(current_user,plan,options)
        elif action=='save-view':
            options=json.loads(plan.settings_json);view={k:request.form.get(k,'') for k in ('q','category','assignee','zoom')};display(payload,view)
            options.setdefault('views',[]).append(dict(name=request.form.get('name'),**view));plans.save_settings(current_user,plan,options)
        elif action=='review':
            draft=plans.date_draft(current_user,plan,payload);db.session.commit()
            return redirect(url_for('projects.planning_review',draft_id=draft.id))
        else:
            model=ProjectPlanNode if action=='delete-node' else ProjectPlanTeam
            row=model.query.filter_by(tenant_id=current_user.tenant_id,plan_id=plan.id,id=number(request.form.get('id'))).first()
            if row is None:abort(404)
            db.session.delete(row);plans.changed(current_user,plan,'component deleted')
        db.session.commit();flash(tr('Plan saved.'),'success')
        return redirect(url_for('projects.advanced_plan_view',plan_id=plan.id,view=target))

    @bp.route('/projects/automation',methods=['GET','POST'])
    @guarded
    def advanced_automation():
        if request.method=='POST':
            row=automation.save(current_user,rule_form());db.session.commit();flash(tr('Automation rule saved.'),'success')
            return redirect(url_for('projects.advanced_automation_rule',rule_id=row.id))
        rows=ProjectAutomationRule.query.filter_by(tenant_id=current_user.tenant_id,owner_id=current_user.id).order_by(ProjectAutomationRule.id.desc()).limit(100).all()
        projects=[p for p in service.visible_projects(current_user).limit(100) if service.can_administer(current_user,p)]
        return page('projects/automation.html',rules=rows,projects=projects)

    @bp.route('/projects/automation/<int:rule_id>',methods=['GET','POST'])
    @guarded
    def advanced_automation_rule(rule_id):
        row=rule(current_user,rule_id);preview=None
        if request.method=='POST':
            if request.form.get('action')=='preview':preview=automation.preview(current_user,row,service.item_or_404(current_user,request.form.get('item_key','')))
            else:
                automation.save(current_user,rule_form(),row.id);db.session.commit();flash(tr('Automation rule saved.'),'success')
                return redirect(url_for('projects.advanced_automation_rule',rule_id=row.id))
        return page('projects/automation_rule.html',rule=row,rule_document=rule_document(row),preview=preview,
            projects=[service.project_or_404(current_user,key) for key in json.loads(row.projects_json)],
            runs=ProjectAutomationRun.query.filter_by(tenant_id=current_user.tenant_id,rule_id=row.id).order_by(ProjectAutomationRun.id.desc()).limit(100).all())


def register_api(app,user):
    @app.route('/api/v1/project-plans',methods=['GET','POST'])
    @guarded
    def api_advanced_plans():
        core.require_api_scope('projects:write' if request.method=='POST' else 'projects:read');actor=user()
        if request.method=='GET':return jsonify(data=[document(r) for r in visible_plans(actor)])
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or not isinstance(data.get('projects'),list):abort(400)
        for key in data['projects']:service.require_edit(actor,service.project_or_404(actor,key))
        idem,request_hash,replay=core.api_idempotency_context()
        if replay:return replay
        row=plans.create(actor,data);result=document(row)
        core.store_api_idempotency(idem,request_hash,result,201);db.session.commit();return jsonify(result),201

    @app.get('/api/v1/project-plans/<int:plan_id>')
    @guarded
    def api_advanced_plan(plan_id):
        core.require_api_scope('projects:read');actor=user();plan,payload=plans.get(actor,plan_id)
        structured=plans.structure(actor,plan,payload);program=plans.program(actor,plan,payload)
        return jsonify(data=document(plan),context=payload,structure=[dict(id=r['node'].id,parent_id=r['node'].parent_id,name=r['node'].name,kind=r['node'].kind,depth=r['depth'],progress=r['progress']) for r in structured['nodes']],
            work=structured['work'],summary=structured['summary'],teams=[dict(id=t.id,name=t.name,capacity=t.capacity,unit=t.unit,members=json.loads(t.members_json)) for t in program['teams']],
            iterations=program['iterations'],allocations=[dict(team_id=c['team'].id,iterations=c['iterations']) for c in program['cells']],warnings=program['warnings'])

    @app.post('/api/v1/project-plans/<int:plan_id>/<action>')
    @guarded
    def api_advanced_plan_edit(plan_id,action):
        core.require_api_scope('projects:write');actor=user();data=request.get_json(silent=True)
        if not isinstance(data,dict):abort(400)
        revision=data.pop('revision',None);plan,payload=plans.get(actor,plan_id,True,revision)
        if action=='review':
            if data:abort(400)
            draft=plans.date_draft(actor,plan,payload);result=dict(draft_id=draft.id)
        else:
            row=edit_command(actor,plan,payload,action,data);db.session.flush();result=dict(revision=plan.revision,id=getattr(row,'id',None))
        db.session.commit();return jsonify(result)

    @app.route('/api/v1/project-automation',methods=['GET','POST'])
    @guarded
    def api_advanced_automation():
        core.require_api_scope('projects:write' if request.method=='POST' else 'projects:read');actor=user()
        if request.method=='GET':
            rows=ProjectAutomationRule.query.filter_by(tenant_id=actor.tenant_id,owner_id=actor.id).limit(100).all()
            result=[]
            for row in rows:
                try:rule(actor,row.id);result.append(rule_document(row))
                except HTTPException as error:
                    if error.code not in (403,404):raise
            return jsonify(data=result)
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or not isinstance(data.get('projects'),list):abort(400)
        for key in data['projects']:
            if not service.can_administer(actor,service.project_or_404(actor,key)):abort(403)
        idem,request_hash,replay=core.api_idempotency_context()
        if replay:return replay
        row=automation.save(actor,data);result=rule_document(row)
        core.store_api_idempotency(idem,request_hash,result,201);db.session.commit();return jsonify(result),201

    @app.route('/api/v1/project-automation/<int:rule_id>',methods=['GET','PUT'])
    @guarded
    def api_advanced_automation_rule(rule_id):
        core.require_api_scope('projects:write' if request.method=='PUT' else 'projects:read');actor=user();row=rule(actor,rule_id)
        if request.method=='PUT':row=automation.save(actor,request.get_json(silent=True),row.id);db.session.commit()
        runs=ProjectAutomationRun.query.filter_by(tenant_id=actor.tenant_id,rule_id=row.id).order_by(ProjectAutomationRun.id.desc()).limit(100)
        return jsonify(data=rule_document(row),runs=[dict(id=r.id,item_key=r.item_key,outcome=r.outcome,affected=r.affected,detail=r.detail,created_at=r.created_at.isoformat()) for r in runs])
