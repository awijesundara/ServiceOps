"""Planning drafts, permission boundaries, scheduling and persistent goals/views."""
from datetime import date

import pytest
from werkzeug.exceptions import HTTPException

from tests.test_app import app, client, login  # noqa: F401
from tests.test_projects_phase2 import pm, project, u  # noqa: F401
from tests.test_projects_web import _api
from serviceops_core.projects import roadmap, service, sprints
from serviceops_core.projects.models import ProjectGoalItem, ProjectPlanningDraft, WorkItem, WorkItemHistory
from serviceops_models import db


def example():
    row=project();actor=u('dev.one')
    epic=service.create_item(actor,row,'Release outcome',item_type='epic',assignee_ids=[])
    first=service.create_item(actor,row,'Build service',parent_id=epic.id,estimate_minutes=480,assignee_ids=[actor.id])
    second=service.create_item(actor,row,'Validate service',parent_id=epic.id,estimate_minutes=480,assignee_ids=[actor.id])
    service.add_link(actor,first,'blocks',second.key);db.session.commit()
    return row,actor,epic,first,second


def rejected(code,fn,*args,**kwargs):
    with pytest.raises(HTTPException) as error:fn(*args,**kwargs)
    assert error.value.code==code
    db.session.rollback()


def test_schedule_preview_review_apply_and_history(pm):
    row,actor,epic,a,b=example()
    draft=roadmap.create_draft(actor,[row.key],'Release schedule',start='2026-10-19',hours=8)
    db.session.commit();draft_id=draft.id
    assert a.start_date is None and b.due_date is None
    _,data=roadmap.draft(actor,draft_id)
    assert data['changes'][str(a.id)]=={'start':'2026-10-19','due':'2026-10-19'}
    assert data['changes'][str(b.id)]=={'start':'2026-10-20','due':'2026-10-20'}
    assert data['changes'][str(epic.id)]=={'start':'2026-10-19','due':'2026-10-20'}
    roadmap.apply_draft(actor,draft_id,list(data['changes']));db.session.commit()
    assert a.start_date==date(2026,10,19) and b.due_date==date(2026,10,20)
    assert WorkItemHistory.query.filter_by(work_item_id=a.id,field='start_date').count()==1
    rejected(409,roadmap.apply_draft,actor,draft_id,[str(a.id)])


def test_partial_apply_consumes_draft_and_leaves_unchecked_work(pm):
    row,actor,epic,a,b=example();draft=roadmap.create_draft(actor,[row.key],'Partial',start='2026-10-19');db.session.commit()
    roadmap.apply_draft(actor,draft.id,[str(a.id)]);db.session.commit()
    assert a.start_date and b.start_date is None and epic.start_date is None


@pytest.mark.parametrize('change',['date','dependency','estimate','role'])
def test_stale_drafts_rejected_without_partial_changes(pm,change):
    row,actor,epic,a,b=example();draft=roadmap.create_draft(actor,[row.key],'Stale',start='2026-10-19');db.session.commit();draft_id=draft.id
    if change=='date':service.update_item(actor,a,{'due_date':'2026-10-25'})
    elif change=='estimate':service.update_item(actor,a,{'estimate_minutes':960})
    elif change=='dependency':service.add_link(actor,b,'blocks',a.key)
    else:service.set_member(u('database.manager'),row,actor.id,'viewer')
    db.session.commit()
    rejected(409,roadmap.apply_draft,actor,draft_id,[str(b.id)])
    assert b.start_date is None


def test_dependency_cycle_missing_external_due_and_private_scope(pm):
    row,actor,epic,a,b=example();service.add_link(actor,b,'blocks',a.key);db.session.commit()
    rejected(409,roadmap.create_draft,actor,[row.key],'Cycle',start='2026-10-19')
    rejected(404,roadmap.context,u('outsider'),[row.key])
    rejected(404,roadmap.context,u('other.admin'),[row.key])


def test_external_prerequisite_and_weekends(pm):
    row,actor,epic,a,b=example();other=project('OTHER')
    prerequisite=service.create_item(actor,other,'External prerequisite',due_date='2026-10-23')
    service.add_link(actor,prerequisite,'blocks',a.key);db.session.commit()
    draft=roadmap.create_draft(actor,[row.key],'External',start='2026-10-19');db.session.commit()
    _,data=roadmap.draft(actor,draft.id)
    assert data['changes'][str(a.id)]['start']=='2026-10-26'
    assert data['changes'][str(b.id)]['start']=='2026-10-27'
    service.update_item(actor,prerequisite,{'due_date':'2026-10-24'});db.session.commit()
    rejected(409,roadmap.apply_draft,actor,draft.id,[str(a.id)])
    service.update_item(actor,prerequisite,{'due_date':None});db.session.commit()
    rejected(409,roadmap.create_draft,actor,[row.key],'Missing prerequisite',start='2026-10-19')


def test_manual_draft_ownership_and_limits(pm):
    row,actor,epic,a,b=example()
    draft=roadmap.create_draft(actor,[row.key],'Manual',mode='manual',changes={str(a.id):{'start':'2026-10-19','due':'2026-10-21'}});db.session.commit()
    rejected(404,roadmap.draft,u('dev.two'),draft.id)
    rejected(400,roadmap.create_draft,actor,[row.key],'Bad dates',mode='manual',changes={str(a.id):{'start':'2026-10-21','due':'2026-10-19'}})
    rejected(400,roadmap.create_draft,actor,[row.key],'Missing start')
    rejected(400,roadmap.create_draft,actor,[row.key],'Bad hours',start='2026-10-19',hours=True)
    rejected(400,roadmap.create_draft,actor,[row.key],'Calendar',start='9999-01-01')
    roadmap.discard_draft(actor,draft.id);db.session.commit();assert db.session.get(ProjectPlanningDraft,draft.id) is None


def test_goals_progress_preferences_are_personal_and_permission_scoped(pm):
    row,actor,epic,a,b=example()
    goal=roadmap.save_goal(actor,row,dict(title='Launch safely',description='Acceptance evidence',target_date='2026-11-01',item_keys=[a.key,b.key]))
    db.session.commit();goal_id=goal.id
    assert roadmap.goals(u('viewer.one'),row)[0]['total']==2
    done=next(s for s in row.statuses if s.category=='done');service.update_item(actor,a,{'status_id':done.id});db.session.commit()
    assert roadmap.goals(actor,row)[0]['done']==1
    rejected(403,roadmap.save_goal,u('viewer.one'),row,dict(title='Forbidden'))
    rejected(404,roadmap.goals,u('outsider'),row)
    roadmap.view_settings(u('viewer.one'),row,{'compact':True,'show_points':False});db.session.commit()
    assert roadmap.view_settings(u('viewer.one'),row)['compact']
    assert roadmap.view_settings(actor,row)['show_points']
    rejected(400,roadmap.view_settings,actor,row,{'compact':'yes'})
    assert ProjectGoalItem.query.filter_by(goal_id=goal_id).count()==2


def test_goal_cannot_link_other_project(pm):
    row,actor,epic,a,b=example();other=project('OTHER');target=service.create_item(actor,other,'Other work');db.session.commit()
    rejected(400,roadmap.save_goal,actor,row,dict(title='Bad scope',item_keys=[target.key]))


def test_web_routes_and_api_parity(pm,client):
    row,actor,epic,a,b=example();headers=_api(pm,'dev.one',['projects:read','projects:write']);read=_api(pm,'viewer.one',['projects:read'])
    response=client.get('/api/v1/project-planning/timeline?project=WEB',headers=headers)
    assert response.status_code==200,response.get_data(as_text=True)
    assert len(response.json['data']['items'])==3
    created=client.post('/api/v1/project-planning/drafts',headers={**headers,'Idempotency-Key':'plan-new'},json={'projects':['WEB'],'name':'API plan','start':'2026-10-19'})
    assert created.status_code==201,created.get_data(as_text=True)
    replay=client.post('/api/v1/project-planning/drafts',headers={**headers,'Idempotency-Key':'plan-new'},json={'projects':['WEB'],'name':'API plan','start':'2026-10-19'})
    assert replay.json['id']==created.json['id']
    draft_id=created.json['id'];assert client.get(f'/api/v1/project-planning/drafts/{draft_id}',headers=headers).status_code==200
    assert client.post(f'/api/v1/project-planning/drafts/{draft_id}/apply',headers=read,json={'item_ids':[str(a.id)]}).status_code==403
    assert client.post(f'/api/v1/project-planning/drafts/{draft_id}/apply',headers=headers,json={'item_ids':[str(a.id)]}).status_code==200
    assert client.post('/api/v1/projects/WEB/goals',headers={**headers,'Idempotency-Key':'goal-new'},json={'title':'API goal','item_keys':[a.key]}).status_code==201
    assert client.get('/api/v1/projects/WEB/goals',headers=read).json['data'][0]['title']=='API goal'
    assert client.get('/api/v1/projects/WEB/planning-calendar?month=2026-10',headers=read).status_code==200
    assert client.get('/api/v1/projects/WEB/planning-team',headers=read).status_code==200
    assert client.put('/api/v1/projects/WEB/view-preferences',headers=headers,json=None).status_code==400
    login(client)
    for path in ('timeline','calendar','team','goals','backlog','backlog/groups'):
        response=client.get('/projects/WEB/'+path)
        assert response.status_code==200,(path,response.get_data(as_text=True)[:1000])
    response=client.post(f'/projects/WEB/backlog-inline/{b.key}',data={'status_id':done_id(row),'story_points':'8','view_mode':'groups'})
    assert response.status_code==302 and '/backlog/groups' in response.location


def done_id(row):
    return next(s.id for s in row.statuses if s.category=='done')


def test_partial_auto_apply_cannot_omit_required_prerequisite(pm):
    row,actor,epic,a,b=example();draft=roadmap.create_draft(actor,[row.key],'Partial dependency',start='2026-10-19');db.session.commit()
    rejected(409,roadmap.apply_draft,actor,draft.id,[str(b.id)])
    assert a.start_date is None and b.start_date is None


def test_partial_schedule_cannot_push_prerequisite_past_unchanged_successor(pm):
    row,actor,epic,a,b=example()
    service.update_item(actor,a,{'start_date':'2026-10-19','due_date':'2026-10-19'})
    service.update_item(actor,b,{'start_date':'2026-10-20','due_date':'2026-10-20'})
    db.session.commit()
    draft=roadmap.create_draft(actor,[row.key],'Move release',start='2026-10-26');db.session.commit()
    rejected(409,roadmap.apply_draft,actor,draft.id,[str(a.id)])
    assert a.due_date==date(2026,10,19)


def test_timeline_derived_dates_and_filter_ancestors(pm):
    from serviceops_core.projects.planning_routes import display
    row,actor,epic,a,b=example()
    service.update_item(actor,a,{'start_date':'2026-10-19','due_date':'2026-10-20'})
    db.session.commit()
    result=display(roadmap.context(actor,[row.key]),{'q':'Build service','anchor':'2026-10-18','assignee':str(actor.id)})
    assert [r['id'] for r in result['rows']]==[epic.id,a.id]
    assert result['rows'][0]['shown_start']=='2026-10-19' and result['rows'][0]['derived']
    assert epic.start_date is None


def test_existing_weekend_span_preserves_working_day_duration(pm):
    row,actor,epic,a,b=example()
    service.update_item(actor,a,{'start_date':'2026-10-23','due_date':'2026-10-26'})
    db.session.commit()
    plan=roadmap.schedule(roadmap.context(actor,[row.key]),'2026-11-02')
    assert plan[str(a.id)]=={'start':'2026-11-02','due':'2026-11-03'}


def test_backlog_settings_and_assignment_restore_validated_filters(pm,client):
    from urllib.parse import parse_qs,urlsplit
    row,actor,epic,a,b=example();sprint=sprints.save(u('database.manager'),row,{'name':'Keep view'})
    db.session.commit();sprint_id=sprint.id
    login(client)
    response=client.post('/projects/WEB/view-settings',data={'view':'backlog','view_sprint':sprint_id,'q':'Build','quick':'unestimated','show_points':'1'})
    assert response.status_code==302
    assert parse_qs(urlsplit(response.location).query)=={'sprint':[str(sprint_id)],'q':['Build'],'quick':['unestimated']}
    response=client.post('/projects/WEB/sprint-items',data={'item_keys':a.key,'sprint_id':sprint_id,'view_sprint':sprint_id,'q':'Build','quick':'unestimated'})
    assert response.status_code==302
    assert parse_qs(urlsplit(response.location).query)=={'sprint':[str(sprint_id)],'q':['Build'],'quick':['unestimated']}
    response=client.post('/projects/WEB/view-settings',data={'view':'backlog','quick':'invalid'})
    assert response.status_code==400
