"""Saved portfolio structures, scenarios and team/iteration planning commands."""
import json
import copy
import math
from datetime import timedelta

from flask import abort

import app as core
from serviceops_models import db,now
from serviceops_core.localization import tr
from serviceops_core.projects import roadmap,service
from serviceops_core.projects.models import ProjectPlan,ProjectPlanNode,ProjectPlanTeam,ProjectPlanAllocation,ProjectPlanScenario,Project


@roadmap.guarded
def text(value,maximum):
    if not isinstance(value,str) or not value.strip() or len(value)>maximum or '\x00' in value:abort(400)
    try:value.encode('utf-8')
    except UnicodeError:abort(400)
    return value.strip()


@roadmap.guarded
def get(actor,plan_id,edit=False,revision=None):
    query=ProjectPlan.query.filter_by(tenant_id=actor.tenant_id,id=plan_id)
    plan=query.with_for_update().populate_existing().first() if edit else query.first()
    if plan is None:abort(404)
    payload=roadmap.context(actor,json.loads(plan.projects_json))
    if edit:
        if plan.owner_id!=actor.id and not service._tenant_admin(actor):abort(403)
        Project.query.filter(Project.id.in_([p['id'] for p in payload['projects']])).order_by(Project.id).with_for_update().all()
        service._forget_roles();payload=roadmap.context(actor,json.loads(plan.projects_json))
        if any(not row['editable'] for row in payload['items']):abort(403)
        for key in json.loads(plan.projects_json):service.require_edit(actor,service.project_or_404(actor,key))
        if type(revision) is not int or revision!=plan.revision:abort(409,description=tr('The plan changed. Reload it before saving.'))
    return plan,payload


@roadmap.guarded
def changed(actor,plan,operation):
    plan.revision+=1;plan.updated_at=now()
    core.audit('project plan '+operation,str(plan.id),'revision='+str(plan.revision),user_id=actor.id,tenant_id=actor.tenant_id)


@roadmap.guarded
def settings(data):
    if not isinstance(data,dict) or set(data)-{'start','weeks','iterations','estimate_mode','views'}:abort(400)
    start=roadmap.parse_date(data.get('start'),True)
    weeks=data.get('weeks',2);iterations=data.get('iterations',6)
    if type(weeks) is not int or not 1<=weeks<=8 or type(iterations) is not int or not 1<=iterations<=52:abort(400)
    if (start+timedelta(weeks=weeks*iterations)).year>2200:abort(400)
    mode=data.get('estimate_mode','remaining')
    if mode not in ('remaining','original'):abort(400)
    views=data.get('views',[])
    if not isinstance(views,list) or len(views)>20:abort(400)
    clean=[]
    for view in views:
        if not isinstance(view,dict) or set(view)-{'name','q','category','assignee','zoom'}:abort(400)
        clean.append(dict(name=text(view.get('name'),60),**{k:str(view.get(k,'')) for k in ('q','category','assignee','zoom')}))
    return dict(start=start.isoformat(),weeks=weeks,iterations=iterations,estimate_mode=mode,views=clean)


@roadmap.guarded
def create(actor,data):
    if not isinstance(data,dict) or set(data)-{'name','description','projects','settings'}:abort(400)
    payload=roadmap.context(actor,data.get('projects'))
    if not isinstance(data.get('projects'),list) or not data['projects']:abort(400)
    for project in payload['projects']:service.require_edit(actor,service.project_or_404(actor,project['key']))
    if ProjectPlan.query.filter_by(tenant_id=actor.tenant_id).count()>=100:abort(409)
    description=data.get('description','')
    if not isinstance(description,str) or len(description)>10000:abort(400)
    row=ProjectPlan(tenant_id=actor.tenant_id,owner_id=actor.id,name=text(data.get('name'),100),description=description,
        projects_json=json.dumps([p['key'] for p in payload['projects']]),settings_json=json.dumps(settings(data.get('settings',dict(start=now().date().isoformat())))))
    db.session.add(row);db.session.flush();changed(actor,row,'created');return row


@roadmap.guarded
def save_settings(actor,plan,data):
    options=settings(data)
    if ProjectPlanAllocation.query.filter_by(plan_id=plan.id,tenant_id=actor.tenant_id).filter(ProjectPlanAllocation.iteration>=options['iterations']).first():abort(409,description=tr('Unschedule work outside the new iteration range first.'))
    plan.settings_json=json.dumps(options);changed(actor,plan,'settings saved')


@roadmap.guarded
def save_node(actor,plan,payload,data,node_id=None):
    if not isinstance(data,dict) or set(data)-{'name','kind','parent_id','item_keys','position'}:abort(400)
    rows=ProjectPlanNode.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id).all();by_id={r.id:r for r in rows}
    row=by_id.get(node_id) if node_id else None
    if node_id and row is None:abort(404)
    parent=data.get('parent_id')
    if parent is not None and (type(parent) is not int or parent not in by_id):abort(400)
    cursor=parent;seen={row.id} if row else set()
    while cursor:
        if cursor in seen:abort(409,description=tr('A portfolio hierarchy cannot contain a cycle.'))
        seen.add(cursor);cursor=by_id[cursor].parent_id
    keys=data.get('item_keys',[]);allowed={r['key'] for r in payload['items']}
    if not isinstance(keys,list) or len(keys)>500 or any(not isinstance(k,str) or k not in allowed for k in keys):abort(400)
    position=data.get('position',0)
    if type(position) is not int or not 0<=position<=100000:abort(400)
    if row is None:
        if len(rows)>=500:abort(409)
        row=ProjectPlanNode(tenant_id=actor.tenant_id,plan_id=plan.id,name=text(data.get('name'),160),kind=text(data.get('kind'),40));db.session.add(row)
    row.name=text(data.get('name'),160);row.kind=text(data.get('kind'),40);row.parent_id=parent;row.position=position;row.item_keys_json=json.dumps(sorted(set(keys)))
    db.session.flush();changed(actor,plan,'structure saved');return row


@roadmap.guarded
def save_team(actor,plan,payload,data,team_id=None):
    if not isinstance(data,dict) or set(data)-{'name','capacity','unit','members'}:abort(400)
    value=data.get('capacity');unit=data.get('unit','hours');members=data.get('members',[])
    if type(value) not in (int,float) or not 0<=value<=100000 or not math.isfinite(value) or unit not in ('hours','points'):abort(400)
    if not isinstance(members,list) or len(members)>500 or any(type(i) is not int for i in members):abort(400)
    eligible={u.id for p in payload['projects'] for u in service.assignable_users(service.project_or_404(actor,p['key']))}
    if not set(members)<=eligible:abort(400)
    row=ProjectPlanTeam.query.filter_by(id=team_id,tenant_id=actor.tenant_id,plan_id=plan.id).first() if team_id else None
    if team_id and row is None:abort(404)
    if row is None:
        if ProjectPlanTeam.query.filter_by(plan_id=plan.id).count()>=50:abort(409)
        row=ProjectPlanTeam(tenant_id=actor.tenant_id,plan_id=plan.id,name=text(data.get('name'),100));db.session.add(row)
    row.name=text(data.get('name'),100);row.capacity=float(value);row.unit=unit;row.members_json=json.dumps(sorted(set(members)))
    db.session.flush();changed(actor,plan,'team saved');return row


@roadmap.guarded
def allocate(actor,plan,payload,item_id,team_id,iteration):
    by_id={r['id']:r for r in payload['items']}
    if type(item_id) is not int or item_id not in by_id:abort(404)
    row=ProjectPlanAllocation.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id,work_item_id=item_id).first()
    if team_id is None:
        if row:db.session.delete(row)
    else:
        if type(team_id) is not int or team_id<=0:abort(400)
        team=ProjectPlanTeam.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id,id=team_id).first()
        if team is None:abort(404)
        if type(iteration) is not int or not 0<=iteration<json.loads(plan.settings_json)['iterations']:abort(400)
        if row is None:row=ProjectPlanAllocation(tenant_id=actor.tenant_id,plan_id=plan.id,work_item_id=item_id);db.session.add(row)
        row.team_id=team.id;row.iteration=iteration
    changed(actor,plan,'allocation saved')


@roadmap.guarded
def progress(rows):
    total=len(rows);done=sum(r['category']=='done' for r in rows)
    points=sum(r['points'] or 0 for r in rows);finished=sum(r['points'] or 0 for r in rows if r['category']=='done')
    return dict(total=total,done=done,percent=round(done/total*100) if total else 0,points=points,points_done=finished,
        points_percent=round(finished/points*100) if points else None,unestimated=sum(r['points'] is None for r in rows),
        estimate=sum(r['estimate'] or 0 for r in rows),remaining=sum(r['remaining'] or 0 for r in rows),
        start=min((r['start'] for r in rows if r['start']),default=None),due=max((r['due'] for r in rows if r['due']),default=None))


@roadmap.guarded
def structure(actor,plan,payload):
    work=roadmap.hierarchy(payload['items']);children={};descendants={}
    for row in work:children.setdefault(row['parent_id'],[]).append(row)
    for row in reversed(work):descendants[row['id']]={row['id']}|{i for child in children.get(row['id'],[]) for i in descendants[child['id']]}
    by_id={r['id']:r for r in work}
    for row in work:row['progress']=progress([by_id[i] for i in descendants[row['id']]])
    nodes=ProjectPlanNode.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id).order_by(ProjectPlanNode.position,ProjectPlanNode.id).all()
    by_key={r['key']:r for r in work};nested={};rendered=[];visiting=set()
    for node in nodes:nested.setdefault(node.parent_id,[]).append(node)
    stack=[(node,0,False) for node in reversed(nested.get(None,[]))];members={}
    while stack:
        node,depth,exit=stack.pop()
        if exit:
            members[node.id]={i for key in json.loads(node.item_keys_json) if key in by_key for i in descendants[by_key[key]['id']]}|{i for child in nested.get(node.id,[]) for i in members[child.id]}
            continue
        if node.id in visiting:abort(409)
        visiting.add(node.id);rendered.append(dict(node=node,depth=depth,item_keys=json.loads(node.item_keys_json)));stack.append((node,depth,True))
        stack.extend((child,depth+1,False) for child in reversed(nested.get(node.id,[])))
    if len(visiting)!=len(nodes):abort(409)
    for row in rendered:row['progress']=progress([by_id[i] for i in members[row['node'].id]])
    owner={}
    for node_row in sorted(rendered,key=lambda r:-r['depth']):
        for item_id in members[node_row['node'].id]:owner.setdefault(item_id,node_row['node'].id)
    entries={};branches={}
    for r in rendered:
        node=r['node'];uid='n'+str(node.id);parent='n'+str(node.parent_id) if node.parent_id else None
        entry=dict(uid=uid,parent=parent,node=node,work=None,progress=r['progress'])
        entries[uid]=entry;branches.setdefault(parent,[]).append(uid)
    for r in work:
        uid='w'+str(r['id']);parent='w'+str(r['parent_id']) if r['parent_id'] in by_id and owner.get(r['parent_id'])==owner.get(r['id']) else 'n'+str(owner[r['id']]) if r['id'] in owner else None
        entry=dict(uid=uid,parent=parent,node=None,work=r,progress=r['progress'])
        entries[uid]=entry;branches.setdefault(parent,[]).append(uid)
    tree=[];stack=[(uid,0) for uid in reversed(branches.get(None,[]))];seen=set()
    while stack:
        uid,depth=stack.pop()
        if uid in seen:abort(409)
        seen.add(uid);tree.append(dict(entries[uid],depth=depth));stack.extend((child,depth+1) for child in reversed(branches.get(uid,[])))
    if len(tree)!=len(entries):abort(409)
    return dict(nodes=rendered,work=work,tree=tree,summary=progress(work))


@roadmap.guarded
def effort(item,team,options):
    if options['estimate_mode']=='remaining' and item['category']=='done':return 0
    value=item['points'] if team.unit=='points' else (item['remaining'] if options['estimate_mode']=='remaining' and item['remaining'] is not None else item['estimate'])
    return None if value is None else value if team.unit=='points' else value/60


@roadmap.guarded
def program(actor,plan,payload):
    options=json.loads(plan.settings_json);start=roadmap.parse_date(options['start'],True)
    teams=ProjectPlanTeam.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id).order_by(ProjectPlanTeam.name,ProjectPlanTeam.id).all()
    allocations=ProjectPlanAllocation.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id).all();mapping={r.work_item_id:r for r in allocations}
    cells=[]
    for team in teams:
        iterations=[]
        for i in range(options['iterations']):
            items=[r for r in payload['items'] if r['id'] in mapping and mapping[r['id']].team_id==team.id and mapping[r['id']].iteration==i]
            amounts=[effort(r,team,options) for r in items];load=round(sum(n for n in amounts if n is not None),2)
            iterations.append(dict(index=i,items=items,load=load,unknown=amounts.count(None),over=load>team.capacity))
        cells.append(dict(team=team,iterations=iterations))
    warnings=[]
    for edge in payload['dependencies']:
        a=mapping.get(edge['source']);b=mapping.get(edge['target'])
        if a and b and a.iteration>=b.iteration:warnings.append(edge)
    return dict(teams=teams,cells=cells,unscheduled=[r for r in payload['items'] if r['id'] not in mapping],warnings=warnings,
        iterations=[dict(index=i,start=(start+timedelta(weeks=i*options['weeks'])).isoformat(),end=(start+timedelta(weeks=(i+1)*options['weeks'])-timedelta(days=1)).isoformat()) for i in range(options['iterations'])],options=options)


@roadmap.guarded
def scenario(actor,plan,name):
    if ProjectPlanScenario.query.filter_by(plan_id=plan.id).count()>=20:abort(409)
    allocations=ProjectPlanAllocation.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id).all()
    row=ProjectPlanScenario(tenant_id=actor.tenant_id,plan_id=plan.id,name=text(name,100),payload_json=json.dumps(dict(settings=json.loads(plan.settings_json),allocations=[dict(item_id=r.work_item_id,team_id=r.team_id,iteration=r.iteration) for r in allocations])))
    db.session.add(row);db.session.flush();changed(actor,plan,'scenario saved');return row


@roadmap.guarded
def restore(actor,plan,payload,scenario_id):
    row=ProjectPlanScenario.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id,id=scenario_id).first()
    if row is None:abort(404)
    data=json.loads(row.payload_json);options=settings(data['settings'])
    allowed={r['id'] for r in payload['items']};teams={r.id for r in ProjectPlanTeam.query.filter_by(plan_id=plan.id,tenant_id=actor.tenant_id)}
    if any(r['item_id'] not in allowed or r['team_id'] not in teams for r in data['allocations']):abort(409,description=tr('This scenario refers to removed work or teams.'))
    ProjectPlanAllocation.query.filter_by(plan_id=plan.id,tenant_id=actor.tenant_id).delete()
    for r in data['allocations']:db.session.add(ProjectPlanAllocation(tenant_id=actor.tenant_id,plan_id=plan.id,work_item_id=r['item_id'],team_id=r['team_id'],iteration=r['iteration']))
    plan.settings_json=json.dumps(options);changed(actor,plan,'scenario restored')


@roadmap.guarded
def date_draft(actor,plan,payload):
    view=program(actor,plan,payload);windows={}
    for group in view['cells']:
        for iteration in group['iterations']:
            span=view['iterations'][iteration['index']]
            for item in iteration['items']:windows[item['id']]=(span['start'],span['end'])
    candidate=copy.deepcopy(payload);managed=set();ordered=roadmap.hierarchy(candidate['items'])
    for row in ordered:
        if row['id'] not in windows and row['parent_id'] in windows:windows[row['id']]=windows[row['parent_id']]
        if row['id'] in windows and row['editable'] and row['category']!='done':
            managed.add(row['id']);old_start,old_due=roadmap.parse_date(row['start']),roadmap.parse_date(row['due'])
            if view['options']['estimate_mode']=='original':row['remaining']=row['estimate']
            if row['remaining'] is None and row['estimate'] is None and old_start and old_due:
                row['estimate']=max(1,sum((old_start+timedelta(days=i)).weekday()<5 for i in range((old_due-old_start).days+1)))*480
            row['start']=windows[row['id']][0];row['due']=None
        else:row['editable']=False
    by_id={r['id']:r for r in ordered}
    for row in reversed(ordered):
        if row['id'] in managed and row['parent_id'] in by_id:
            parent=by_id[row['parent_id']]
            if next(r for r in payload['items'] if r['id']==parent['id'])['editable']:
                parent['editable']=True;managed.add(parent['id'])
    candidate['items']=ordered
    proposed=roadmap.schedule(candidate,view['options']['start'],reserve_people=True)
    originals={str(r['id']):r for r in payload['items']};changes={}
    child_parents={r['parent_id'] for r in ordered if r['parent_id']}
    for key,dates in proposed.items():
        original=originals[key];identifier=int(key)
        if identifier in windows and identifier not in child_parents:
            lower,upper=windows[identifier]
            if dates['start']<lower or dates['due']>upper:
                abort(422,description=tr('The iteration cannot fit {key} with its dependencies and duration. Move it to a later iteration or increase the iteration length.',key=original['key']))
        if (dates['start'],dates['due'])!=(original['start'],original['due']):changes[key]=dates
    return roadmap.create_draft(actor,json.loads(plan.projects_json),(plan.name+' — iteration dates')[:100],mode='manual',changes=changes)



@roadmap.guarded
def auto_allocate(actor,plan,payload):
    """Build the complete proposal before replacing any plan allocation."""
    view=program(actor,plan,payload);teams=view['teams'];options=view['options']
    if not teams:abort(409,description=tr('Add a team and its iteration capacity before scheduling.'))
    proposed=roadmap.schedule(payload,options['start'],reserve_people=True)
    children={r['parent_id'] for r in payload['items'] if r['parent_id']}
    by_id={r['id']:r for r in payload['items']};leaves={}
    for row in reversed(roadmap.hierarchy(payload['items'])):
        nested=[r['id'] for r in payload['items'] if r['parent_id']==row['id']]
        leaves[row['id']]=[i for c in nested for i in leaves[c]] if nested else [row['id']]
    starts={r['id']:(proposed.get(str(r['id']),{}).get('start') or r['start'] or options['start']) for r in payload['items']}
    items=sorted((r for r in payload['items'] if r['id'] not in children and r['category']!='done'),key=lambda r:(starts[r['id']],r['id']))
    old={r.work_item_id:r.team_id for r in ProjectPlanAllocation.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id)}
    start=roadmap.parse_date(options['start'],True);span=options['weeks']*7;used={};chosen={};allocations=[]
    external={r['id']:r for r in payload['external']}
    for item in items:
        earliest=max(0,(roadmap.parse_date(starts[item['id']],True)-start).days//span)
        for edge in payload['dependencies']:
            if item['id'] not in leaves.get(edge['target'],[]):continue
            for source_id in leaves.get(edge['source'],[edge['source']]):
                if source_id in chosen:earliest=max(earliest,chosen[source_id]+1)
                else:
                    source=by_id.get(source_id) or external.get(source_id)
                    if source and source['due']:earliest=max(earliest,(roadmap.parse_date(source['due'])-start).days//span+1)
        candidates=[t for t in teams if t.id==old.get(item['id'])] if item['id'] in old else []
        if not candidates:
            people={u['id'] for u in item['assignees']};candidates=[t for t in teams if people & set(json.loads(t.members_json))] or teams
        placed=False
        for iteration in range(earliest,options['iterations']):
            for team in candidates:
                amount=effort(item,team,options)
                if amount is None:continue
                key=(team.id,iteration)
                if used.get(key,0)+amount<=team.capacity:
                    used[key]=used.get(key,0)+amount;chosen[item['id']]=iteration;allocations.append((item['id'],team.id,iteration));placed=True;break
            if placed:break
        if not placed:abort(422,description=tr('Work cannot fit within the plan. Check estimates, team capacity, dependencies and iteration dates.'))
    if not allocations:abort(409,description=tr('There is no open leaf work to schedule.'))
    ProjectPlanAllocation.query.filter_by(tenant_id=actor.tenant_id,plan_id=plan.id).delete()
    for item_id,team_id,iteration in allocations:db.session.add(ProjectPlanAllocation(tenant_id=actor.tenant_id,plan_id=plan.id,work_item_id=item_id,team_id=team_id,iteration=iteration))
    changed(actor,plan,'auto-scheduled proposal')
