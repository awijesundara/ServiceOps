"""Sprint lifecycle, immutable snapshots, tenant boundaries, APIs and ranking."""
import json

import pytest
from werkzeug.exceptions import HTTPException

from app import db
from serviceops_core.projects import operations, query, service, sprints, tracking
from serviceops_core.projects.models import ProjectSprint, ProjectSprintEvent, ProjectSprintItem, WorkItemHistory
from tests.test_app import app, client  # noqa: F401
from tests.test_projects_service import pm, make_project, u, expect_abort  # noqa: F401


def setup():
    project=make_project()
    admin=u('database.manager'); member=u('dev.one')
    a=service.create_item(member,project,'First',story_points=5,estimate_minutes=120)
    b=service.create_item(member,project,'Second',story_points=3,estimate_minutes=60)
    child=service.create_item(member,project,'Child',item_type='subtask',parent_id=a.id,story_points=100)
    row=sprints.save(admin,project,{'name':'Sprint one','start_at':'2026-10-17T08:00:00Z','end_at':'2026-10-31T08:00:00Z'})
    db.session.commit()
    return project,admin,member,a,b,child,row


def test_parallel_sprints_and_nested_search_without_double_counting(pm):
    project,admin,member,a,b,child,row=setup()
    other=sprints.save(admin,project,{'name':'Parallel','start_at':'2026-10-17','end_at':'2026-10-30'})
    sprints.assign(member,project,a.key,row.id); sprints.assign(member,project,b.key,other.id)
    sprints.start(admin,project,row.id); sprints.start(admin,project,other.id); db.session.commit()
    assert json.loads(row.baseline_json)['points']==5
    assert json.loads(row.baseline_json)['count']==1
    assert {r.id for r in query.search(member,'sprint IN openSprints()')}=={a.id,b.id,child.id}
    assert {r.id for r in query.search(member,f'sprint = {row.id}')}=={a.id,child.id}
    assert query.search(member,'sprint IN futureSprints()').count()==0
    expect_abort(400,sprints.assign,member,project,child.key,row.id)
    expect_abort(403,sprints.start,member,project,row.id)
    expect_abort(409,sprints.start,admin,project,row.id)


def test_completion_carries_unfinished_and_freezes_history(pm):
    project,admin,member,a,b,child,row=setup()
    target=sprints.save(admin,project,{'name':'Next'})
    sprints.assign(member,project,a.key,row.id); sprints.assign(member,project,b.key,row.id)
    sprints.start(admin,project,row.id)
    done=next(status for status in project.statuses if status.category=='done')
    service.update_item(member,a,{'status_id':done.id,'story_points':8})
    db.session.commit()
    expect_abort(409,sprints.complete,admin,project,row.id,target.id)
    service.update_item(member,child,{'status_id':done.id})
    sprints.complete(admin,project,row.id,target.id); db.session.commit()
    assert row.state=='closed' and json.loads(row.baseline_json)['points']==8  # initial 5+3
    assert json.loads(row.outcome_json)['done_points']==8
    assert ProjectSprintItem.query.filter_by(work_item_id=b.id,active=True).one().sprint_id==target.id
    assert ProjectSprintItem.query.filter_by(work_item_id=a.id,active=True).count()==0
    assert {r.id for r in query.search(member,'sprint IN closedSprints()')}=={a.id,b.id,child.id}
    frozen=sprints.report(member,project,row.id)['series']
    service.update_item(member,a,{'story_points':21}); db.session.commit()
    assert sprints.report(member,project,row.id)['series']==frozen
    assert sprints.velocity(member,project)[0]['delivered']['done_points']==8
    expect_abort(409,sprints.save,admin,project,{'name':'Overwrite'},row.id)
    expect_abort(409,sprints.delete,admin,project,row.id)
    expect_abort(409,sprints.complete,admin,project,row.id)


def test_scope_removal_readdition_and_worklog_capture(pm):
    project,admin,member,a,b,child,row=setup()
    sprints.assign(member,project,a.key,row.id); sprints.start(admin,project,row.id)
    tracking.log_work(member,a,'30m')
    sprints.assign(member,project,a.key,None); sprints.assign(member,project,a.key,row.id)
    db.session.commit()
    assert ProjectSprintItem.query.filter_by(work_item_id=a.id,active=True).count()==1
    report=sprints.report(member,project,row.id,'remaining')
    assert report['baseline']['remaining']==120
    assert report['series'][-1]['remaining']==90
    kinds=[r.kind for r in ProjectSprintEvent.query.filter_by(sprint_id=row.id).order_by(ProjectSprintEvent.id)]
    assert 'removed' in kinds and 'state' in kinds
    sprints.complete(admin,project,row.id); db.session.commit()
    assert ProjectSprintItem.query.filter_by(sprint_id=row.id,completed=True).count()==1
    assert ProjectSprintItem.query.filter_by(sprint_id=row.id,completed=False).count()==1


def test_moves_deletes_and_conversion_cannot_leave_current_sprint_or_destroy_report(pm):
    project,admin,member,a,b,child,row=setup()
    sprints.assign(member,project,a.key,row.id); sprints.assign(member,project,b.key,row.id)
    sprints.start(admin,project,row.id); db.session.commit()
    expect_abort(409,service.update_item,member,a,{'item_type':'epic','parent_id':None})
    # An epic with children already has an independent hierarchy rejection.
    target=make_project('TARGET')
    operations.move_item(admin,b,target)
    service.delete_item(member,a); db.session.commit()
    assert ProjectSprintItem.query.filter_by(sprint_id=row.id,active=True).count()==0
    result=sprints.report(admin,project,row.id)
    assert result['baseline']['count']==2 and result['series'][-1]['scope']==0
    assert any(e.kind=='removed' for e in result['events'])


def test_ranking_noop_assignment_and_atomic_invalid_bulk_destination(pm):
    project,admin,member,a,b,child,row=setup()
    a.rank=1000; b.rank=2000; db.session.commit()
    before=WorkItemHistory.query.filter_by(field='sprint').count()
    sprints.assign(member,project,b.key,None,a.key); db.session.commit()
    assert b.rank<a.rank
    assert WorkItemHistory.query.filter_by(field='sprint').count()==before
    sprints.assign(member,project,a.key,row.id); db.session.commit()
    expect_abort(400,sprints.assign,member,project,b.key,None,a.key)
    assert ProjectSprintItem.query.filter_by(work_item_id=a.id,active=True).count()==1


@pytest.mark.parametrize('payload',[
    {'name':''},{'name':True},{'name':'bad\x00name'},{'name':'\ud800'}, {'name':'x'*101},
    {'name':'n','goal':[]},{'name':'n','start_at':'bad','end_at':'2026-10-30'},
    {'name':'n','start_at':'2026-10-30'},
    {'name':'n','start_at':'2026-10-30','end_at':'2026-10-29'},
    {'name':'n','start_at':'2026-10-30','end_at':'2028-10-30'}, {'name':'n','unknown':True},
])
def test_sprint_input_validation(pm,payload):
    project=make_project()
    expect_abort(400,sprints.save,u('database.manager'),project,payload)


def test_scope_privacy_role_revocation_and_future_function_arguments(pm):
    project,admin,member,a,b,child,row=setup()
    private=make_project('SECRET',members=())
    hidden=sprints.save(admin,private,{'name':'Private'})
    db.session.commit()
    expect_abort(404,sprints.get,u('outsider'),project,row.id)
    expect_abort(404,sprints.get,u('other.admin'),project,row.id)
    expect_abort(404,sprints.assign,member,project,a.key,hidden.id)
    assert query.search(u('outsider'),'sprint IN futureSprints() OR NOT sprint IN futureSprints()').count()==0
    for source in ('sprint IN openSprints(1)','key IN openSprints()','sprint = openSprints()'):
        with pytest.raises(query.QueryError): query.search(member,source)
    service.set_member(admin,project,member.id,'viewer'); db.session.commit()
    expect_abort(403,sprints.assign,member,project,a.key,row.id)


def test_web_forms_restore_view_and_report_and_api_idempotency(pm,client):
    from tests.test_projects_web import _api
    project,admin,member,a,b,child,row=setup()
    api=_api(pm,'database.manager',['projects:read','projects:write'])
    read=_api(pm,'dev.one',['projects:read'])
    response=client.post('/api/v1/projects/WEB/sprints',headers={**api,'Idempotency-Key':'sprint-new'},json={'name':'API sprint'})
    assert response.status_code==201,response.get_data(as_text=True)
    sprint_id=response.json['data']['id']
    replay=client.post('/api/v1/projects/WEB/sprints',headers={**api,'Idempotency-Key':'sprint-new'},json={'name':'API sprint'})
    assert replay.status_code==201 and replay.json['data']['id']==sprint_id
    assert client.put('/api/v1/projects/WEB/sprint-items',headers=api,json={'item_keys':[a.key],'sprint_id':row.id}).status_code==200
    assert client.get(f'/api/v1/projects/WEB/sprints/{row.id}/items',headers=read).json['data'][0]['item']['title']=='First'
    assert client.post(f'/api/v1/projects/WEB/sprints/{row.id}/start',headers=api,json={}).status_code==200
    assert client.get(f'/api/v1/projects/WEB/sprints/{row.id}/report',headers=read).json['data']['baseline']['points']==5
    assert client.get(f'/api/v1/projects/WEB/sprints/{row.id}/events',headers=read).json['meta']['total']>=3
    assert client.get('/api/v1/projects/WEB/velocity',headers=read).status_code==200
    filtered=client.get('/api/v1/projects/WEB/work-items',headers=read,query_string={'sprint':row.id})
    assert {r['title'] for r in filtered.json['data']}=={'First','Child'}
    assert client.post(f'/api/v1/projects/WEB/sprints/{row.id}/complete',headers=read,json={}).status_code==403
    for data in ({'item_keys':[]},{'item_keys':[a.key],'sprint_id':True},{'item_keys':[a.key],'extra':'x'},
                 {'item_keys':[a.key,b.key],'before_key':a.key}):
        assert client.put('/api/v1/projects/WEB/sprint-items',headers=api,json=data).status_code==400
    # Use the seeded administrator login, whose password is part of the disposable fixture.
    client.post('/login',data={'username':'admin','password':'Admin123!'})
    response=client.get('/projects/WEB/backlog')
    assert response.status_code==200
    assert client.get(f'/projects/WEB/backlog?sprint={row.id}').status_code==200
    assert client.get(f'/projects/WEB/board?sprint={row.id}').status_code==200
    assert client.get('/projects/WEB/sprints').status_code==200
    assert client.get('/projects/WEB/sprints?state=bad').status_code==400
    response=client.post('/projects/WEB/sprint-items',data={'item_keys':[b.key],'sprint_id':row.id,'view_sprint':''})
    assert response.status_code==302 and response.location.endswith('/projects/WEB/backlog')
    assert client.get(f'/projects/WEB/sprints/{row.id}/report').status_code==200
    assert client.post(f'/api/v1/projects/WEB/sprints/{row.id}/complete',headers=api,json={}).status_code==200
    assert client.delete(f'/api/v1/projects/WEB/sprints/{sprint_id}',headers=api).status_code==204


def test_already_done_scope_is_not_credited_as_delivered_velocity(pm):
    project,admin,member,a,b,child,row=setup()
    done=next(s for s in project.statuses if s.category=='done')
    service.update_item(member,b,{'status_id':done.id})
    sprints.assign(member,project,b.key,row.id); sprints.start(admin,project,row.id)
    sprints.complete(admin,project,row.id); db.session.commit()
    outcome=json.loads(row.outcome_json)
    assert outcome['done_points']==3 and outcome['delivered_points']==0
    report=sprints.report(member,project,row.id)
    assert report['series'][0]['ideal']==0
    assert report['work'][0]['category']=='outside'


def test_assignment_csrf_atomic_bulk_and_return_validation_before_write(pm,client):
    import re
    project,admin,member,a,b,child,row=setup()
    client.post('/login',data={'username':'admin','password':'Admin123!'})
    response=client.post('/projects/WEB/sprint-items',data={'item_keys':[a.key],'sprint_id':row.id,'view_sprint':'999999'})
    assert response.status_code==404
    assert ProjectSprintItem.query.filter_by(work_item_id=a.id,active=True).count()==0
    response=client.post('/projects/WEB/sprint-items',json={'item_keys':[a.key,child.key],'sprint_id':row.id})
    assert response.status_code==400
    assert ProjectSprintItem.query.filter_by(work_item_id=a.id,active=True).count()==0
    pm.config['CSRF_ENABLED']=True
    assert client.post('/projects/WEB/sprint-items',data={'item_keys':[a.key],'sprint_id':row.id}).status_code==400
    html=client.get('/projects/WEB/backlog').get_data(as_text=True)
    token=re.search(r'<meta name="csrf-token" content="([^"]+)"',html).group(1)
    assert client.post('/projects/WEB/sprint-items',data={'item_keys':[a.key],'sprint_id':row.id,'_csrf_token':token}).status_code==302


def test_daily_report_reconstructs_historical_values_instead_of_current_fields(pm):
    from datetime import datetime, timezone
    project,admin,member,a,b,child,row=setup()
    sprints.assign(member,project,b.key,row.id); sprints.start(admin,project,row.id)
    done=next(s for s in project.statuses if s.category=='done')
    service.update_item(member,b,{'status_id':done.id})
    sprints.complete(admin,project,row.id); db.session.flush()
    row.started_at=datetime(2026,2,1,tzinfo=timezone.utc)
    row.end_at=row.completed_at=datetime(2026,2,3,tzinfo=timezone.utc)
    changed=False
    for e in ProjectSprintEvent.query.filter_by(sprint_id=row.id).order_by(ProjectSprintEvent.id):
        day=1 if e.kind in ('baseline','started') else 3 if e.kind=='completed' else 31
        month=1 if day==31 else 2
        if e.kind=='state': day,month=2 if not changed else 3,2; changed=True
        e.created_at=datetime(2026,month,day,tzinfo=timezone.utc)
    db.session.commit()
    data=sprints.report(member,project,row.id)
    assert [d['remaining'] for d in data['series']]==[3,0,0]
    assert [d['ideal'] for d in data['series']]==[3,1.5,0]
    assert data['work'][0]['category']=='completed'


def test_pending_version_links_survive_assignment_and_item_updates(pm):
    from serviceops_core.projects.models import ProjectVersion
    project,admin,member,a,b,child,row=setup()
    version=ProjectVersion(tenant_id=project.tenant_id,project_id=project.id,name='Pending release')
    a.fix_versions=[version]
    sprints.assign(member,project,a.key,row.id)
    service.update_item(member,a,{'priority':'high'})
    db.session.commit(); db.session.expire(a,['fix_versions'])
    assert a.fix_versions[0].name=='Pending release'


def test_planned_delete_and_limits_preserve_work_and_expose_event_fallback(pm,monkeypatch):
    project,admin,member,a,b,child,row=setup()
    monkeypatch.setattr(sprints,'MAX_MEMBERS',1)
    sprints.assign(member,project,a.key,row.id); db.session.commit()
    expect_abort(409,sprints.assign,member,project,b.key,row.id)
    monkeypatch.setattr(sprints,'MAX_EVENTS',0)
    expect_abort(422,sprints.report,member,project,row.id)
    assert ProjectSprintEvent.query.filter_by(sprint_id=row.id).count()>0
    sprints.delete(admin,project,row.id); db.session.commit()
    assert db.session.get(ProjectSprint,row.id) is None
    assert a.title=='First' and ProjectSprintItem.query.filter_by(work_item_id=a.id).count()==0
