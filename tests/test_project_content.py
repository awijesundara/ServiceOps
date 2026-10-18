"""Typed form snapshots, page revisions, safe links and rendered project tabs."""
import pytest
from tests.test_projects_phase2 import pm,project,u  # noqa: F401
from tests.test_app import app,client,login  # noqa: F401
from tests.test_project_premium import reject
from serviceops_models import db
from serviceops_core.projects import content,operations
from serviceops_core.projects.models import WorkItem


def config():
    return dict(item_type='task',priority='high',fields=[dict(key='reason',label='Reason',type='paragraph',required=True),dict(key='approved',label='Approved',type='boolean',required=True),dict(key='cost',label='Cost',type='number',required=False)])


def test_typed_forms_snapshots_permissions_and_clone(pm):
    p=project();actor=u('database.manager')
    form=content.save_form(actor,p,dict(name='Intake',config=config()));db.session.commit()
    reject(400,content.submit_form,actor,p,form,dict(title='No answer',answers={}))
    assert WorkItem.query.count()==0
    item=content.submit_form(actor,p,form,dict(title='New platform',answers=dict(reason='Capacity',approved=False,cost='12.5')));db.session.commit()
    assert content.responses(item)[0]['answers']==dict(reason='Capacity',approved=False,cost=12.5)
    content.save_form(actor,p,dict(name='Revised',config=dict(item_type='bug',fields=[]),revision=form.revision),form.id);db.session.commit()
    assert content.responses(item)[0]['name']=='Intake'
    clone=operations.clone_item(actor,item);db.session.commit();assert content.responses(clone)[0]['answers']==content.responses(item)[0]['answers']
    reject(403,content.submit_form,u('viewer.one'),p,form,dict(title='Forbidden'))
    reject(404,content.get,u('other.admin'),p,type(form),form.id)


def test_pages_revisions_and_safe_shortcuts(pm):
    p=project();actor=u('database.manager');page=content.save_page(actor,p,dict(title='Delivery',body='**Plan**'));db.session.commit()
    reject(409,content.save_page,actor,p,dict(title='Stale',revision=0),page.id)
    for link in ('javascript:alert(1)','//evil.example','https://name:password@example.com','https://[invalid'):
        reject(400,content.shortcut,actor,p,'Unsafe',link)
    content.shortcut(actor,p,'Documentation','https://example.com/guide');db.session.commit()
    assert content.reports(actor,p)['created']==0


def test_content_web_pages_and_submission(pm,client):
    p=project();actor=u('database.manager');form=content.save_form(actor,p,dict(name='Intake',config=config()));content.save_page(actor,p,dict(title='Guide',body='<script>alert(1)</script>'));db.session.commit()
    login(client)
    for view in ('forms','pages','reports','shortcuts'):
        response=client.get(f'/projects/{p.key}/content/{view}');assert response.status_code==200,response.data[-1000:]
    response=client.get(f'/projects/{p.key}/forms/{form.id}/submit');assert response.status_code==200
    response=client.post(f'/projects/{p.key}/forms/{form.id}/submit',data=dict(title='Request',answer_reason='Need capacity',answer_approved='false'));assert response.status_code==302
    assert b'Submitted form' in client.get(response.location).data
