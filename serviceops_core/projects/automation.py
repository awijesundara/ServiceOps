"""Bounded, transactional work-item automation with current-owner permissions."""
import json
from contextvars import ContextVar

from flask import abort,current_app
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_models import db,User
from serviceops_core.localization import tr
from serviceops_core.projects import service,roadmap
from serviceops_core.projects.models import Project,ProjectAutomationRule,ProjectAutomationRun,WorkItem,WorkItemLink

_RUNNING=ContextVar('project_automation_running',default=False)
_BUDGET=ContextVar('project_automation_budget',default=1000)
FIELDS=('item_type','category','priority','flagged','title')
TRIGGERS=('created','updated','transitioned')
BRANCHES=('trigger','children','descendants','parent','linked')


@roadmap.guarded
def field(item,name):
    return item.status.category if name=='category' else getattr(item,name)


@roadmap.guarded
def validate(actor,data):
    if not isinstance(data,dict) or set(data)-{'trigger','conditions','branch','branch_conditions','actions'}:abort(400)
    if data.get('trigger') not in TRIGGERS or data.get('branch') not in BRANCHES:abort(400)
    for name in ('conditions','branch_conditions'):
        rows=data.get(name,[])
        if not isinstance(rows,list) or len(rows)>20:abort(400)
        for row in rows:
            if not isinstance(row,dict) or set(row)-{'field','operator','value','compare_field'} or row.get('field') not in FIELDS or row.get('operator') not in ('eq','ne','contains'):abort(400)
            if 'compare_field' in row and row['compare_field'] not in FIELDS:abort(400)
            if 'compare_field' not in row and (not isinstance(row.get('value'),(str,bool)) or len(str(row['value']))>255):abort(400)
    actions=data.get('actions')
    if not isinstance(actions,list) or not 1<=len(actions)<=10:abort(400)
    for action in actions:
        if not isinstance(action,dict) or action.get('type') not in ('transition','edit','comment'):abort(400)
        if action['type']=='transition':
            if set(action)-{'type','category','copy_trigger'} or (action.get('copy_trigger') is not True and action.get('category') not in ('todo','in_progress','done')):abort(400)
        elif action['type']=='edit':
            if set(action)!={'type','field','value'} or action['field'] not in ('priority','flagged','title') or not isinstance(action['value'],(str,bool)):abort(400)
            if action['field']=='title' and (not isinstance(action['value'],str) or not 1<=len(action['value'])<=255):abort(400)
            if action['field']=='priority' and action['value'] not in ('highest','high','medium','low','lowest'):abort(400)
            if action['field']=='flagged' and type(action['value']) is not bool:abort(400)
        elif set(action)!={'type','body'} or not isinstance(action['body'],str) or not 1<=len(action['body'])<=4000:abort(400)
    return {k:data.get(k,[]) for k in ('conditions','branch_conditions')}|{k:data[k] for k in ('trigger','branch','actions')}


@roadmap.guarded
def save(actor,data,rule_id=None):
    if not isinstance(data,dict) or set(data)-{'name','enabled','projects','config','revision'}:abort(400)
    keys=data.get('projects');name=data.get('name','')
    if not isinstance(name,str) or not 1<=len(name.strip())<=100 or type(data.get('enabled',False)) is not bool:abort(400)
    if not isinstance(keys,list) or not 1<=len(keys)<=50 or any(not isinstance(k,str) for k in keys):abort(400)
    keys=sorted(set(k.upper() for k in keys));projects=[service.project_or_404(actor,k) for k in keys]
    Project.query.filter(Project.id.in_([p.id for p in projects])).order_by(Project.id).with_for_update().populate_existing().all()
    service._forget_roles()
    if any(not service.can_administer(actor,p) for p in projects):abort(403)
    config=validate(actor,data.get('config'))
    row=ProjectAutomationRule.query.filter_by(id=rule_id,tenant_id=actor.tenant_id,owner_id=actor.id).with_for_update().populate_existing().first() if rule_id else None
    if rule_id and row is None:abort(404)
    if row and data.get('revision')!=row.revision:abort(409,description=tr('The rule changed. Reload before saving.'))
    if row is None:
        if ProjectAutomationRule.query.filter_by(tenant_id=actor.tenant_id).count()>=100:abort(409,description=tr('This tenant already has 100 automation rules.'))
        row=ProjectAutomationRule(tenant_id=actor.tenant_id,owner_id=actor.id,name=name.strip(),projects_json=json.dumps(keys),config_json=json.dumps(config));db.session.add(row)
    else:row.revision+=1
    row.name=name.strip();row.enabled=data.get('enabled',False);row.projects_json=json.dumps(keys);row.config_json=json.dumps(config)
    db.session.flush();core.audit('project automation saved',str(row.id),f'enabled={row.enabled}',user_id=actor.id,tenant_id=actor.tenant_id)
    return row


@roadmap.guarded
def matches(item,conditions,trigger):
    for condition in conditions:
        actual=field(item,condition['field']);expected=field(trigger,condition['compare_field']) if 'compare_field' in condition else condition['value']
        if condition['field']=='flagged' and isinstance(expected,str):expected=expected.lower()=='true'
        if condition['operator']=='eq' and actual!=expected:return False
        if condition['operator']=='ne' and actual==expected:return False
        if condition['operator']=='contains' and str(expected).casefold() not in str(actual).casefold():return False
    return True


@roadmap.guarded
def targets(owner,item,branch):
    if branch=='trigger':return [item]
    if branch=='parent':rows=[item.parent] if item.parent else []
    elif branch=='children':rows=WorkItem.query.filter_by(tenant_id=owner.tenant_id,parent_id=item.id).order_by(WorkItem.id).limit(101).all()
    elif branch=='linked':
        edges=WorkItemLink.query.filter_by(tenant_id=owner.tenant_id,source_id=item.id,target_type='work_item').limit(101).all()
        rows=WorkItem.query.filter(WorkItem.tenant_id==owner.tenant_id,WorkItem.id.in_([e.target_id for e in edges])).order_by(WorkItem.id).limit(101).all()
    else:
        ids={item.id};front=[item.id];rows=[]
        while front:
            found=WorkItem.query.filter(WorkItem.tenant_id==owner.tenant_id,WorkItem.parent_id.in_(front),~WorkItem.id.in_(ids)).order_by(WorkItem.id).limit(101).all()
            rows.extend(found);front=[r.id for r in found];ids.update(front)
            if len(rows)>100:break
    if len(rows)>100:abort(422,description=tr('Automation branches support at most 100 work items.'))
    return rows


@roadmap.guarded
def execute(owner,rule,item,dry_run=False):
    config=json.loads(rule.config_json)
    if not matches(item,config['conditions'],item):return []
    allowed=set(json.loads(rule.projects_json))
    rows=[r for r in targets(owner,item,config['branch']) if r.project.key in allowed and matches(r,config['branch_conditions'],item)]
    if any(not service.can_edit(owner,r.project) for r in rows):abort(403)
    # Resolve every action before writing, so missing target statuses cannot partially execute.
    commands=[]
    for target in rows:
        for action in config['actions']:
            if action['type']=='transition':
                category=item.status.category if action.get('copy_trigger') else action['category']
                status=next((s for s in target.project.statuses if s.category==category),None)
                if status is None:abort(409)
                commands.append((target,'edit',{'status_id':status.id}))
            elif action['type']=='edit':commands.append((target,'edit',{action['field']:action['value']}))
            else:commands.append((target,'comment',action['body']))
    if not dry_run:
        if len(commands)>_BUDGET.get():abort(422,description=tr('This event exceeds the 1,000-action automation budget.'))
        _BUDGET.set(_BUDGET.get()-len(commands))
        for target,kind,values in commands:
            if kind=='edit':service.update_item(owner,target,values)
            else:service.add_comment(owner,target,values)
    return sorted({target.key for target,_,_ in commands})


def dispatch(item,event):
    """Runs in the caller's transaction; nested writes never trigger more rules."""
    if _RUNNING.get():return
    token=_RUNNING.set(True);budget_token=_BUDGET.set(1000)
    try:
        rules=ProjectAutomationRule.query.filter_by(tenant_id=item.tenant_id,enabled=True).order_by(ProjectAutomationRule.id).limit(100).all()
        for rule in rules:
            if item.project.key not in json.loads(rule.projects_json):continue
            config=json.loads(rule.config_json)
            if config['trigger']!=event and not (config['trigger']=='updated' and event=='transitioned'):continue
            affected=[];outcome='success';detail=''
            owner=User.query.filter_by(id=rule.owner_id).populate_existing().first()
            try:
                with db.session.begin_nested():
                    service._forget_roles()
                    if owner is None or not owner.active or not service.can_administer(owner,item.project):abort(403)
                    affected=execute(owner,rule,item)
                    if not affected:outcome='no_match'
                    for key in affected:
                        target=service.item_or_404(owner,key)
                        service.log_work_item_history(target,owner,'automation',None,rule.name)
            except HTTPException as error:
                outcome='blocked';detail=f'permission_or_validation_{error.code}'
                current_app.logger.warning('Project automation blocked: rule=%s code=%s',rule.id,error.code)
            except Exception as error:
                outcome='failed';detail=type(error).__name__
                current_app.logger.error('Project automation failed: rule=%s error=%s',rule.id,type(error).__name__)
            db.session.add(ProjectAutomationRun(tenant_id=item.tenant_id,rule_id=rule.id,work_item_id=item.id,item_key=item.key,outcome=outcome,affected=len(affected) if outcome=='success' else 0,detail=detail))
    except Exception as error:
        current_app.logger.error('Project automation dispatch failed: %s',type(error).__name__)
        raise
    finally:
        _RUNNING.reset(token);_BUDGET.reset(budget_token)


@roadmap.guarded
def preview(owner,rule,item):
    if rule.owner_id!=owner.id or rule.tenant_id!=owner.tenant_id:abort(404)
    if item.project.key not in json.loads(rule.projects_json):abort(400,description=tr('Choose a trigger item in this rule scope.'))
    token=_RUNNING.set(True)
    try:return execute(owner,rule,item,True)
    finally:_RUNNING.reset(token)
