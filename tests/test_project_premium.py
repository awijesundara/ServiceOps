"""Saved planning, permissions, rollups and bounded real automation behavior."""
import json
from datetime import date

import pytest
from werkzeug.exceptions import HTTPException
from tests.test_projects_phase2 import pm,project,u  # noqa: F401
from tests.test_app import app,client,login  # noqa: F401
from serviceops_models import db
from serviceops_core.projects import service,advanced_plans as plans,automation
from serviceops_core.projects.models import ProjectPlanAllocation,ProjectAutomationRun,WorkItemHistory


def reject(code,fn,*args,**kwargs):
    with pytest.raises(HTTPException) as error:fn(*args,**kwargs)
    assert error.value.code==code
    db.session.rollback()


def setup_plan():
    p=project();actor=u('database.manager')
    root=service.create_item(actor,p,'Epic outcome',item_type='epic')
    a=service.create_item(actor,p,'Build platform',parent_id=root.id,estimate_minutes=480,story_points=5)
    b=service.create_item(actor,p,'Validate platform',parent_id=root.id,estimate_minutes=240,story_points=3)
    plan=plans.create(actor,dict(name='Portfolio delivery',projects=[p.key],settings=dict(start='2026-10-19')))
    db.session.commit();return p,actor,plan,root,a,b


def test_plan_owner_permission_and_stale_revision(pm):
    p,actor,plan,root,a,b=setup_plan();identifier=plan.id
    assert len(plans.get(u('viewer.one'),identifier)[1]['items'])==3
    reject(404,plans.get,u('outsider'),identifier)
    reject(404,plans.get,u('other.admin'),identifier)
    plan,payload=plans.get(actor,identifier,True,plan.revision)
    plans.save_settings(actor,plan,dict(start='2026-10-19',iterations=8));db.session.commit()
    reject(409,plans.get,actor,identifier,True,plan.revision-1)
    reject(403,plans.get,u('viewer.one'),identifier,True,plan.revision)


def test_custom_hierarchy_cycle_and_unique_progress(pm):
    p,actor,plan,root,a,b=setup_plan();_,payload=plans.get(actor,plan.id)
    portfolio=plans.save_node(actor,plan,payload,dict(name='Cloud portfolio',kind='Portfolio',item_keys=[root.key]))
    initiative=plans.save_node(actor,plan,payload,dict(name='Secure delivery',kind='Initiative',parent_id=portfolio.id,item_keys=[a.key,b.key]))
    db.session.commit();result=plans.structure(actor,plan,payload)
    assert result['nodes'][0]['progress']['total']==3
    assert result['nodes'][0]['progress']['points']==8
    assert result['nodes'][1]['progress']['total']==2
    reject(409,plans.save_node,actor,plan,payload,dict(name='Cycle',kind='Portfolio',parent_id=initiative.id),portfolio.id)


def test_program_capacity_scenarios_and_review_only_dates(pm):
    p,actor,plan,root,a,b=setup_plan();_,payload=plans.get(actor,plan.id)
    team=plans.save_team(actor,plan,payload,dict(name='Platform team',capacity=8,unit='hours',members=[actor.id]))
    plans.allocate(actor,plan,payload,a.id,team.id,0);plans.allocate(actor,plan,payload,b.id,team.id,0)
    db.session.commit();view=plans.program(actor,plan,payload)
    assert view['cells'][0]['iterations'][0]['over'] and view['cells'][0]['iterations'][0]['load']==12
    saved=plans.scenario(actor,plan,'Baseline');db.session.commit()
    plans.allocate(actor,plan,payload,b.id,team.id,1);db.session.commit()
    assert not plans.program(actor,plan,payload)['cells'][0]['iterations'][0]['over']
    assert a.start_date is None
    draft=plans.date_draft(actor,plan,payload);db.session.commit()
    assert a.start_date is None and '2026-10-19' in draft.payload_json
    plans.restore(actor,plan,payload,saved.id);db.session.commit()
    assert ProjectPlanAllocation.query.filter_by(work_item_id=b.id).one().iteration==0
    reject(400,plans.allocate,actor,plan,payload,a.id,team.id,52)
    reject(400,plans.save_team,actor,plan,payload,dict(name='Bad',capacity=float('nan')))


def rule_data(project_key):
    return dict(name='Sync epic completion',enabled=True,projects=[project_key],config=dict(trigger='transitioned',conditions=[dict(field='item_type',operator='eq',value='epic')],branch='descendants',branch_conditions=[dict(field='category',operator='ne',value='done')],actions=[dict(type='transition',copy_trigger=True)]))


def test_actual_transition_runs_automation_and_does_not_loop(pm):
    p,actor,plan,root,a,b=setup_plan();rule=automation.save(actor,rule_data(p.key));db.session.commit()
    done=next(s for s in p.statuses if s.category=='done')
    service.update_item(actor,root,{'status_id':done.id});db.session.commit()
    assert a.status.category==b.status.category=='done'
    run=ProjectAutomationRun.query.filter_by(rule_id=rule.id).one()
    assert run.outcome=='success' and run.affected==2
    assert WorkItemHistory.query.filter_by(work_item_id=a.id,field='automation').count()==1


def test_automation_preview_no_mutation_and_permission_revocation(pm):
    p,actor,plan,root,a,b=setup_plan();owner=u('dev.one')
    service.set_member(actor,p,owner.id,'admin');db.session.commit()
    rule=automation.save(owner,rule_data(p.key));db.session.commit()
    assert set(automation.preview(owner,rule,root))=={a.key,b.key}
    assert a.status.category=='todo' and not ProjectAutomationRun.query.count()
    service.set_member(actor,p,owner.id,'viewer');db.session.commit()
    done=next(s for s in p.statuses if s.category=='done')
    service.update_item(actor,root,{'status_id':done.id});db.session.commit()
    assert a.status.category=='todo'
    assert ProjectAutomationRun.query.filter_by(rule_id=rule.id).one().outcome=='blocked'


def test_rule_failure_rolls_back_actions_but_preserves_user_command(pm,monkeypatch):
    p,actor,plan,root,a,b=setup_plan();rule=automation.save(actor,rule_data(p.key));db.session.commit()
    original=service.update_item;calls=[]
    def fail_second(owner,item,changes):
        calls.append(item.id)
        if len(calls)==2:raise RuntimeError('injected failure')
        return original(owner,item,changes)
    monkeypatch.setattr(service,'update_item',fail_second)
    done=next(s for s in p.statuses if s.category=='done')
    original(actor,root,{'status_id':done.id});db.session.commit()
    assert root.status.category=='done' and a.status.category==b.status.category=='todo'
    assert ProjectAutomationRun.query.filter_by(rule_id=rule.id).one().outcome=='failed'


def test_plan_and_rule_web_views_are_real_populated_pages(pm,client):
    from serviceops_core.projects import releases
    p,actor,plan,root,a,b=setup_plan();_,payload=plans.get(actor,plan.id)
    team=plans.save_team(actor,plan,payload,dict(name='Platform',capacity=8,unit='hours',members=[actor.id]))
    plans.allocate(actor,plan,payload,a.id,team.id,0)
    plans.save_node(actor,plan,payload,dict(name='Cloud programme',kind='Initiative',item_keys=[root.key]))
    db.session.commit();login(client)
    for view in ('timeline','structure','program','teams','releases','dependencies','settings'):
        response=client.get(f'/projects/plans/{plan.id}/{view}')
        assert response.status_code==200,(view,response.get_data(as_text=True)[:1000])
    for path in ('/projects/WEB/timeline','/projects/WEB/overview','/projects/plans','/projects/automation'):
        assert client.get(path).status_code==200,path
    data=rule_data(p.key)
    response=client.post('/projects/automation',data={'name':data['name'],'enabled':'1','projects':data['projects'],'config':json.dumps(data['config'])})
    assert response.status_code==302
    assert client.get(response.location).status_code==200


def test_auto_program_proposal_respects_units_and_preserves_work_dates(pm):
    p,actor,plan,root,a,b=setup_plan();_,payload=plans.get(actor,plan.id)
    team=plans.save_team(actor,plan,payload,dict(name='Small team',capacity=8,unit='hours'))
    service.add_link(actor,a,'blocks',b.key);db.session.commit();_,payload=plans.get(actor,plan.id)
    plans.auto_allocate(actor,plan,payload);db.session.commit()
    allocations={r.work_item_id:r.iteration for r in ProjectPlanAllocation.query.filter_by(plan_id=plan.id)}
    assert allocations[b.id]>allocations[a.id]
    assert a.start_date is None and b.due_date is None
    plans.save_team(actor,plan,payload,dict(name='Small team',capacity=0,unit='hours'),team.id);db.session.commit()
    reject(422,plans.auto_allocate,actor,plan,payload)
    assert {r.work_item_id:r.iteration for r in ProjectPlanAllocation.query.filter_by(plan_id=plan.id)}==allocations


def test_program_review_schedules_dependencies_inside_iteration_and_applies(pm):
    from serviceops_core.projects import roadmap
    p,actor,plan,root,a,b=setup_plan();service.add_link(actor,a,'blocks',b.key);db.session.commit()
    _,payload=plans.get(actor,plan.id);team=plans.save_team(actor,plan,payload,dict(name='Platform',capacity=80,unit='hours',members=[actor.id]))
    plans.allocate(actor,plan,payload,a.id,team.id,0);plans.allocate(actor,plan,payload,b.id,team.id,0);db.session.commit()
    draft=plans.date_draft(actor,plan,payload);db.session.commit();changes=json.loads(draft.payload_json)['changes']
    assert changes[str(a.id)]['due']<changes[str(b.id)]['start']
    assert a.start_date is None
    roadmap.apply_draft(actor,draft.id,list(changes));db.session.commit()
    assert a.due_date<b.start_date
