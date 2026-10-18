"""Project pages, typed intake forms, immutable answers and safe shortcuts."""
import json
import math
import re
from datetime import timedelta
from statistics import median
from urllib.parse import urlsplit

from flask import abort
from sqlalchemy import func

import app as core
from serviceops_models import db,now
from serviceops_core.localization import tr
from serviceops_core.projects import roadmap,service,advanced_plans
from serviceops_core.projects.models import Project,ProjectPage,ProjectForm,ProjectFormResponse,ProjectShortcut,WorkItem,ProjectStatus

FIELD_TYPES=('text','paragraph','integer','number','date','choice','multi_choice','boolean')


@roadmap.guarded
def lock(actor,project,admin=False):
    Project.query.filter_by(tenant_id=actor.tenant_id,id=project.id).with_for_update().populate_existing().one()
    service._forget_roles();service.require_edit(actor,project)
    if admin and not service.can_administer(actor,project):abort(403)


@roadmap.guarded
def get(actor,project,model,identifier):
    if not service.can_view(actor,project):abort(404)
    row=model.query.filter_by(id=identifier,project_id=project.id,tenant_id=actor.tenant_id).first()
    if row is None:abort(404)
    return row


@roadmap.guarded
def save_page(actor,project,data,identifier=None):
    lock(actor,project)
    if not isinstance(data,dict) or set(data)-{'title','body','revision'}:abort(400)
    title=advanced_plans.text(data.get('title'),160);body=data.get('body','')
    if not isinstance(body,str) or len(body)>100000 or '\x00' in body:abort(400)
    row=get(actor,project,ProjectPage,identifier) if identifier else None
    if row and data.get('revision')!=row.revision:abort(409,description=tr('The page changed. Reload before saving.'))
    if row is None:
        if ProjectPage.query.filter_by(tenant_id=actor.tenant_id,project_id=project.id).count()>=200:abort(409)
        row=ProjectPage(tenant_id=actor.tenant_id,project_id=project.id,title=title,body=body,updated_by_id=actor.id);db.session.add(row)
    else:row.revision+=1
    row.title=title;row.body=body;row.updated_by_id=actor.id;row.updated_at=now();db.session.flush()
    core.audit('project page saved',str(row.id),'revision='+str(row.revision),user_id=actor.id,tenant_id=actor.tenant_id);return row


@roadmap.guarded
def form_config(data):
    if not isinstance(data,dict) or set(data)-{'item_type','priority','fields'}:abort(400)
    item_type=data.get('item_type','task');priority=data.get('priority','medium');fields=data.get('fields',[])
    if item_type not in ('epic','story','task','bug') or priority not in ('highest','high','medium','low','lowest') or not isinstance(fields,list) or len(fields)>30:abort(400)
    cleaned=[];keys=set()
    for field in fields:
        if not isinstance(field,dict) or set(field)-{'key','label','type','required','choices'}:abort(400)
        key=field.get('key');kind=field.get('type');required=field.get('required',False)
        if not isinstance(key,str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,39}',key) or key in keys or kind not in FIELD_TYPES or type(required) is not bool:abort(400)
        keys.add(key);label=advanced_plans.text(field.get('label'),120);choices=field.get('choices',[])
        if not isinstance(choices,list) or len(choices)>100 or any(not isinstance(v,str) or not 1<=len(v)<=100 or '\x00' in v for v in choices):abort(400)
        if kind in ('choice','multi_choice') and not choices:abort(400)
        if kind not in ('choice','multi_choice') and choices:abort(400)
        cleaned.append(dict(key=key,label=label,type=kind,required=required,choices=list(dict.fromkeys(choices))))
    return dict(item_type=item_type,priority=priority,fields=cleaned)


@roadmap.guarded
def save_form(actor,project,data,identifier=None):
    lock(actor,project,True)
    if not isinstance(data,dict) or set(data)-{'name','description','config','enabled','revision'}:abort(400)
    name=advanced_plans.text(data.get('name'),100);description=data.get('description','');enabled=data.get('enabled',True)
    if not isinstance(description,str) or len(description)>10000 or '\x00' in description or type(enabled) is not bool:abort(400)
    config=form_config(data.get('config',{}));row=get(actor,project,ProjectForm,identifier) if identifier else None
    if row and data.get('revision')!=row.revision:abort(409,description=tr('The form changed. Reload before saving.'))
    if row is None:
        if ProjectForm.query.filter_by(project_id=project.id,tenant_id=actor.tenant_id).count()>=100:abort(409)
        row=ProjectForm(tenant_id=actor.tenant_id,project_id=project.id,name=name,config_json=json.dumps(config),updated_by_id=actor.id);db.session.add(row)
    else:row.revision+=1
    row.name=name;row.description=description;row.enabled=enabled;row.config_json=json.dumps(config);row.updated_by_id=actor.id;db.session.flush()
    core.audit('project form saved',str(row.id),'revision='+str(row.revision),user_id=actor.id,tenant_id=actor.tenant_id);return row


@roadmap.guarded
def validate_answers(config,answers):
    if not isinstance(answers,dict) or set(answers)-{f['key'] for f in config['fields']}:abort(400)
    result={}
    for field in config['fields']:
        value=answers.get(field['key']);kind=field['type']
        missing=value is None or value=='' or value==[]
        if field['required'] and missing:abort(400,description=tr('Complete the required field: {field}',field=field['label']))
        if missing:result[field['key']]=None;continue
        if kind in ('text','paragraph'):
            if not isinstance(value,str) or len(value)>(2000 if kind=='text' else 10000) or '\x00' in value:abort(400)
        elif kind in ('integer','number'):
            try:
                if type(value) is bool:raise ValueError()
                value=float(value)
                if not math.isfinite(value) or abs(value)>10**9 or (kind=='integer' and not value.is_integer()):raise ValueError()
                if kind=='integer':value=int(value)
            except (ValueError,TypeError,OverflowError):abort(400,description=tr('Enter a valid number for {field}.',field=field['label']))
        elif kind=='date':value=roadmap.parse_date(value,True).isoformat()
        elif kind=='boolean':
            if value in ('true','false'):value=value=='true'
            if type(value) is not bool:abort(400)
        elif kind=='choice':
            if not isinstance(value,str) or value not in field['choices']:abort(400)
        elif kind=='multi_choice':
            if not isinstance(value,list) or any(not isinstance(v,str) or v not in field['choices'] for v in value) or len(value)>100:abort(400)
            value=[v for v in field['choices'] if v in value]
        result[field['key']]=value
    return result


@roadmap.guarded
def submit_form(actor,project,form,data):
    lock(actor,project);db.session.refresh(form)
    if not form.enabled or form.project_id!=project.id or form.tenant_id!=actor.tenant_id:abort(404)
    if not isinstance(data,dict) or set(data)-{'title','description','answers'}:abort(400)
    config=json.loads(form.config_json);answers=validate_answers(config,data.get('answers',{}))
    item=service.create_item(actor,project,data.get('title'),description=data.get('description',''),item_type=config['item_type'],priority=config['priority'])
    db.session.add(ProjectFormResponse(tenant_id=actor.tenant_id,form_id=form.id,work_item_id=item.id,name=form.name,schema_json=json.dumps(config['fields']),answers_json=json.dumps(answers),submitted_by_id=actor.id))
    service.log_work_item_history(item,actor,'form',None,form.name);db.session.flush();db.session.expire(item,['form_responses']);return item


@roadmap.guarded
def responses(item):
    return [dict(id=r.id,name=r.name,fields=json.loads(r.schema_json),answers=json.loads(r.answers_json),submitted_at=r.created_at.isoformat()) for r in item.form_responses if r.tenant_id==item.tenant_id]


@roadmap.guarded
def shortcut(actor,project,label,url):
    lock(actor,project,True);label=advanced_plans.text(label,80)
    if not isinstance(url,str) or len(url)>2000 or any(ord(c)<32 for c in url):abort(400)
    try:parsed=urlsplit(url)
    except ValueError:abort(400)
    if not (core.is_safe_internal_path(url) or (parsed.scheme=='https' and parsed.hostname and not parsed.username and not parsed.password)):abort(400,description=tr('Use an internal path or a complete HTTPS URL.'))
    if ProjectShortcut.query.filter_by(tenant_id=actor.tenant_id,project_id=project.id).count()>=30:abort(409)
    row=ProjectShortcut(tenant_id=actor.tenant_id,project_id=project.id,label=label,url=url);db.session.add(row);db.session.flush()
    core.audit('project shortcut added',str(row.id),'project='+project.key,user_id=actor.id,tenant_id=actor.tenant_id);return row


@roadmap.guarded
def reports(actor,project,days=30):
    if not service.can_view(actor,project):abort(404)
    if type(days) is not int or days not in (7,30,90,365):abort(400)
    end=now().date();start=end-timedelta(days=days-1)
    base=WorkItem.query.filter_by(tenant_id=actor.tenant_id,project_id=project.id)
    created=dict((str(day),count) for day,count in base.filter(WorkItem.created_at>=start,WorkItem.created_at<end+timedelta(days=1)).with_entities(func.date(WorkItem.created_at),func.count()).group_by(func.date(WorkItem.created_at)))
    resolved=dict((str(day),count) for day,count in base.filter(WorkItem.resolved_at>=start,WorkItem.resolved_at<end+timedelta(days=1)).with_entities(func.date(WorkItem.resolved_at),func.count()).group_by(func.date(WorkItem.resolved_at)))
    durations=[(end-begin).total_seconds()/86400 for begin,end in base.filter(WorkItem.resolved_at>=start,WorkItem.resolved_at<end+timedelta(days=1)).with_entities(WorkItem.created_at,WorkItem.resolved_at) if end and end>=begin]
    counts=dict(base.join(ProjectStatus,WorkItem.status_id==ProjectStatus.id).with_entities(ProjectStatus.category,func.count()).group_by(ProjectStatus.category))
    return dict(days=days,start=start.isoformat(),end=end.isoformat(),series=[dict(date=(start+timedelta(days=i)).isoformat(),created=created.get((start+timedelta(days=i)).isoformat(),0),resolved=resolved.get((start+timedelta(days=i)).isoformat(),0)) for i in range(days)],
        median_lead_days=round(median(durations),2) if durations else None,categories=counts,created=sum(created.values()),resolved=sum(resolved.values()))
