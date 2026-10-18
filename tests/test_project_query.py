"""Core JQL, saved-query authorization and export regressions (B-450)."""
import pytest
from werkzeug.exceptions import HTTPException

from app import db
from serviceops_core.projects import filters, query, service
from serviceops_core.projects.models import ProjectFilterFavourite, ProjectSavedFilter, WorkItem
from tests.test_app import app, client  # noqa: F401
from tests.test_projects_service import pm, make_project, u  # noqa: F401


def seed():
    project=make_project()
    actor=u('dev.one')
    a=service.create_item(actor,project,'Upgrade database',priority='high',labels='maintenance',assignee_ids=[actor.id],
                          due_date='2026-01-01',story_points=5)
    b=service.create_item(actor,project,'Write docs',priority='low',labels='docs',story_points=2)
    c=service.create_item(actor,project,'Subtask',item_type='subtask',parent_id=a.id)
    db.session.commit()
    return project,a,b,c


def keys(source):
    return [item.title for item in query.search(u('dev.one'),source).all()]


def test_boolean_precedence_lists_functions_empty_fields_and_sorting(pm):
    project,a,b,c=seed()
    assert keys('assignee = currentUser()')==[a.title]
    assert keys('assignee != currentUser()')==[]  # empty assignees are excluded, as in JQL
    assert keys('assignee IS EMPTY ORDER BY summary')==[c.title,b.title]
    assert keys('NOT (labels = docs OR type = subtask)')==[a.title]
    assert keys('priority IN (high, highest) AND project = WEB')==[a.title]
    assert keys('priority NOT IN (high, highest) ORDER BY storyPoints DESC')==[b.title,c.title]
    assert keys('labels=docs OR labels=maintenance AND storyPoints > 3')==[a.title,b.title]
    assert keys('(labels=docs OR labels=maintenance) AND storyPoints > 3')==[a.title]
    assert keys('text ~ "upgrade*" AND due < startOfDay()')==[a.title]
    assert keys('parent = '+a.key)==[c.title]
    assert keys('key = '+b.key)==[b.title]
    assert keys('resolution IS EMPTY')==[a.title,b.title,c.title]


@pytest.mark.parametrize('source',[
    'summary = "a\x00b"', 'summary = "\ud800"',
    'summary = =', 'priority = >', 'type = !~',
    'project =', 'summary ~ "unclosed', 'assignee = unknown()', 'summary > 3',
    'unknownField = 1', 'status WAS Done', 'priority IN ()', 'priority IN (high,)',
    'due < "nonsense"', 'storyPoints = NaN', 'ORDER BY project', 'ORDER BY due, due, due, due',
    'assignee = currentUser(1)', 'labels = NULL', 'summary = "safe"; DROP TABLE work_item',
    'NOT '*18+'type=task', '('*18+'type=task'+')'*18, 'summary ~ '+('x'*4096),
])
def test_invalid_or_unsupported_queries_fail_with_position(pm,source):
    with pytest.raises(query.QueryError) as error:
        query.search(u('dev.one'),source)
    assert error.value.position>=1
    assert 'position' in str(error.value)


def test_search_cannot_or_not_or_function_around_project_and_tenant_scope(pm):
    project,a,b,c=seed()
    private=make_project('SECRET',members=())
    service.create_item(u('database.manager'),private,'Hidden secret')
    other=service.create_project(u('other.admin'),'OTHER','Other tenant')
    service.create_item(u('other.admin'),other,'Other tenant secret')
    db.session.commit()
    assert set(keys('project = SECRET OR project = WEB'))=={a.title,b.title,c.title}
    assert set(keys('NOT project = SECRET'))=={a.title,b.title,c.title}
    assert keys('project=SECRET')==[]
    assert query.search(u('other.admin'),'').count()==1


def test_saved_filter_owner_sharing_favourites_and_permission_revocation(pm):
    project,a,b,c=seed()
    owner,reader=u('dev.one'),u('outsider')
    row=filters.save(owner,'My high priority','priority=high')
    shared=filters.save(owner,'Shared work','project=WEB','project',project.key)
    db.session.commit()
    assert filters.visible(reader).count()==0
    with pytest.raises(HTTPException) as error: filters.get(reader,row.id)
    assert error.value.code==404
    db.session.rollback()
    service.set_member(u('database.manager'),project,reader.id,'viewer')
    db.session.commit()
    assert filters.get(reader,shared.id).id==shared.id
    with pytest.raises(HTTPException) as error:
        filters.save(reader,'Stolen','',filter_id=shared.id)
    assert error.value.code==403
    db.session.rollback()
    filters.favourite(reader,shared.id,True)
    filters.favourite(reader,shared.id,True)
    db.session.commit()
    assert ProjectFilterFavourite.query.filter_by(user_id=reader.id).count()==1
    # A favourite does not preserve access after project membership is revoked.
    from serviceops_core.projects.models import ProjectMember
    ProjectMember.query.filter_by(project_id=project.id,user_id=reader.id).delete()
    db.session.commit()
    assert filters.visible(reader).count()==0
    assert query.search(reader,shared.query_text).count()==0
    with pytest.raises(HTTPException): filters.favourite(reader,shared.id,False)


def test_filter_tenant_sharing_validation_uniqueness_and_deletion(pm):
    project,a,b,c=seed()
    owner=u('dev.one')
    with pytest.raises(HTTPException) as error: filters.save(owner,'Nope','','tenant')
    assert error.value.code==403
    db.session.rollback()
    with pytest.raises(query.QueryError): filters.save(owner,'Broken','summary > 4')
    db.session.rollback()
    row=filters.save(u('admin'),'Organisation work','project=WEB','tenant')
    db.session.commit()
    assert filters.get(u('outsider'),row.id)
    assert query.search(u('outsider'),row.query_text).count()==0
    with pytest.raises(HTTPException): filters.get(u('other.admin'),row.id)
    db.session.rollback()
    private=filters.save(owner,'Unique','')
    db.session.commit()
    with pytest.raises(HTTPException) as error: filters.save(owner,'Unique','')
    assert error.value.code==409
    db.session.rollback()
    filters.favourite(owner,private.id,True)
    db.session.commit()
    filters.delete(owner,private.id)
    db.session.commit()
    assert db.session.get(ProjectSavedFilter,private.id) is None
    assert ProjectFilterFavourite.query.filter_by(filter_id=private.id).count()==0


def test_navigator_save_favourite_csv_errors_and_cross_identity(pm,client):
    project,a,b,c=seed()
    a.title='=HYPERLINK("https://example.invalid")'
    db.session.commit()
    client.post('/login',data={'username':'dev.one','password':'Passw0rd!x'})
    response=client.get('/projects/search?jql=project=WEB')
    assert response.status_code==200 and 'Write docs' in response.get_data(as_text=True)
    assert client.get('/projects/search?jql=badfield=1').status_code==400
    assert client.get('/projects/search?page=-1').status_code==400
    assert 'Write docs' in client.get('/projects/search?page=999').get_data(as_text=True)
    export=client.get('/projects/search?export=csv')
    assert export.status_code==200 and export.mimetype=='text/csv'
    import csv,io
    records=list(csv.reader(io.StringIO(export.get_data(as_text=True).lstrip('\ufeff'))))
    assert records[1][3].startswith("'=HYPERLINK")
    response=client.post('/projects/filters/save',data={'name':'High priority','jql':'priority=high'})
    assert response.status_code==302
    saved_id=int(response.location.rsplit('=',1)[-1])
    assert 'Filter saved.' in client.get(response.location).get_data(as_text=True)
    assert client.post(f'/projects/filters/{saved_id}/favourite',data={'enabled':'1'}).status_code==302
    assert client.post(f'/projects/filters/{saved_id}/favourite',data={'enabled':'wat'}).status_code==400
    assert client.post('/projects/filters/save',data={'name':'Bad','jql':'bad=1'}).status_code==400
    assert client.post(f'/projects/filters/{saved_id}/delete').status_code==302


def test_query_api_saved_filters_idempotency_scope_and_visibility(pm,client):
    from tests.test_projects_web import _api
    seed()
    member=_api(pm,'dev.one',['projects:read','projects:write'])
    reader=_api(pm,'outsider',['projects:read'])
    created=client.post('/api/v1/project-filters',headers={**member,'Idempotency-Key':'saved-one'},
                        json={'name':'API filter','jql':'priority=high'})
    assert created.status_code==201
    filter_id=created.json['data']['id']
    replay=client.post('/api/v1/project-filters',headers={**member,'Idempotency-Key':'saved-one'},
                       json={'name':'API filter','jql':'priority=high'})
    assert replay.status_code==201 and replay.json['data']['id']==filter_id
    result=client.get('/api/v1/work-item-search',headers=member,query_string={'filter':filter_id})
    assert result.status_code==200 and result.json['meta']['total']==1
    assert result.json['data'][0]['title']=='Upgrade database'
    assert client.get('/api/v1/work-item-search',headers=reader).json['data']==[]
    assert client.get('/api/v1/work-item-search',headers=reader,query_string={'filter':filter_id}).status_code==404
    assert client.get('/api/v1/project-filters',headers=reader).json['data']==[]
    assert client.patch(f'/api/v1/project-filters/{filter_id}',headers=reader,json={'name':'Stolen'}).status_code==403
    assert client.put(f'/api/v1/project-filters/{filter_id}/favourite',headers=member,json={'enabled':True}).status_code==200
    assert client.get('/api/v1/project-filters',headers=member).json['data'][0]['favourite']
    assert client.put(f'/api/v1/project-filters/{filter_id}/favourite',headers=member,json={'enabled':'yes'}).status_code==400
    for payload in ({'name':42},{'name':'bad\x00name'},{'jql':[]},{'jql':'bad=1'},{'unknown':True},
                    {'sharing':'project','project_key':'bad\x00key'}):
        assert client.patch(f'/api/v1/project-filters/{filter_id}',headers=member,json=payload).status_code==400
    assert client.get('/api/v1/work-item-search?jql=bad=1',headers=member).status_code==400
    assert client.get('/api/v1/work-item-search?limit=201',headers=member).status_code==400
    assert client.delete(f'/api/v1/project-filters/{filter_id}',headers=member).status_code==204


def test_csv_export_limit_is_explicit_and_literal_wildcards_are_safe(pm,client,monkeypatch):
    from serviceops_core.projects import navigator
    project,a,b,c=seed()
    assert keys('summary ~ "%"')==[]
    assert keys('summary ~ "_"')==[]
    client.post('/login',data={'username':'dev.one','password':'Passw0rd!x'})
    monkeypatch.setattr(navigator,'EXPORT_LIMIT',1)
    assert client.get('/projects/search?export=csv').status_code==400


def test_supported_related_fields_and_numeric_date_comparisons(pm):
    from serviceops_core.projects import releases
    project,a,b,c=seed()
    manager=u('database.manager')
    component=releases.save_component(manager,project,'Backend')
    version=releases.save_version(manager,project,'Release 1')
    service.update_item(u('dev.one'),a,{'component_ids':[component.id],'fix_version_ids':[version.id],
        'affects_version_ids':[version.id],'flagged':True,'estimate_minutes':90,'remaining_minutes':60,
        'start_date':'2025-01-01'})
    db.session.commit()
    for expression in ('component = Backend','fixVersion = "Release 1"','affectsVersion="Release 1"',
                       'flagged=true','estimate >= 90','remaining <= 60','start < "2026-01-01"',
                       'reporter = currentUser() AND priority=high','description IS EMPTY AND priority=high'):
        assert keys(expression)==[a.title],expression
    assert keys('component IS NOT EMPTY')==[a.title]
    assert keys('flagged=false ORDER BY key')==[b.title,c.title]
    assert keys('type=task AND status="To do" AND category=todo ORDER BY priority')==[a.title,b.title]


def test_filter_mutations_require_csrf_in_the_web_ui(pm,client):
    import re
    seed()
    pm.config['CSRF_ENABLED']=True
    html=client.get('/login').get_data(as_text=True)
    token=re.search(r'<meta name="csrf-token" content="([^"]+)"',html).group(1)
    assert client.post('/login',data={'username':'dev.one','password':'Passw0rd!x','_csrf_token':token}).status_code==302
    html=client.get('/projects/search').get_data(as_text=True)
    token=re.search(r'<meta name="csrf-token" content="([^"]+)"',html).group(1)
    assert client.post('/projects/filters/save',data={'name':'Without token','jql':''}).status_code==400
    assert client.post('/projects/filters/save',data={'name':'With token','jql':'','_csrf_token':token}).status_code==302
