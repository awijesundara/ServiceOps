"""Malformed planning/intake values reject cleanly without partial writes."""
import json
import pytest
from tests.test_app import app,client,login  # noqa: F401
from tests.test_projects_phase2 import pm,project,u  # noqa: F401
from tests.test_project_premium import reject,setup_plan
from serviceops_models import db
from serviceops_core.projects import content,advanced_plans as plans
from serviceops_core.projects.models import WorkItem,ProjectFormResponse


def test_oversized_intake_number_is_bad_request_and_atomic(pm,client):
    p=project();actor=u('database.manager')
    form=content.save_form(actor,p,dict(name='Capacity',config=dict(fields=[dict(key='amount',label='Amount',type='number')])));db.session.commit()
    login(client)
    from app import APIClient,create_api_token
    token,prefix,digest=create_api_token()
    db.session.add(APIClient(name='review',token_prefix=prefix,token_hash=digest,scopes_json=json.dumps(['projects:write']),acting_user_id=actor.id,created_by_id=actor.id,tenant_id=actor.tenant_id));db.session.commit()
    response=client.post(f'/api/v1/projects/{p.key}/forms/{form.id}/submit',headers={'Authorization':'Bearer '+token},json=dict(title='Oversized',answers=dict(amount=10**400)))
    assert response.status_code==400
    reject(400,content.validate_answers,json.loads(form.config_json),dict(amount=10**400))
    assert WorkItem.query.count()==0 and ProjectFormResponse.query.count()==0


def test_oversized_team_capacity_and_non_integral_route_numbers(pm,client):
    p,actor,plan,root,a,b=setup_plan();_,payload=plans.get(actor,plan.id)
    reject(400,plans.save_team,actor,plan,payload,dict(name='Invalid',capacity=10**400))
    login(client)
    response=client.post(f'/projects/plans/{plan.id}/edit/team',data=dict(revision=plan.revision,name='Invalid',capacity='NaN',unit='hours'))
    assert response.status_code==400


@pytest.mark.parametrize('value',[1.5,True,[],{},float('inf')])
def test_route_identifiers_are_strict_whole_numbers(pm,value):
    from serviceops_core.projects.advanced_routes import number
    reject(400,number,value)
