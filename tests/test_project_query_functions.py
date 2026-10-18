"""Reporting calendar and collection search functions, including access loss."""
from datetime import datetime, timezone

import pytest

from app import db
from serviceops_core.projects import query, service
from serviceops_core.projects.models import ProjectVersion, WorkItemVote, WorkItemView
from tests.test_app import app, client  # noqa: F401
from tests.test_projects_service import pm, make_project, u  # noqa: F401
from tests.test_project_query import seed, keys


@pytest.mark.parametrize(('name','arg','expected'), [
    ('startofweek', [], '2024-02-26T00:00:00+00:00'),
    ('endofweek', [], '2024-03-03T23:59:59.999999+00:00'),
    ('endofmonth', [], '2024-02-29T23:59:59.999999+00:00'),
    ('endofmonth', ['+1'], '2024-03-31T23:59:59.999999+00:00'),
    ('endofmonth', ['-1M'], '2024-01-31T23:59:59.999999+00:00'),
    ('endofyear', [], '2024-12-31T23:59:59.999999+00:00'),
    ('startofyear', ['+1'], '2025-01-01T00:00:00+00:00'),
    ('startofmonth', ['-2'], '2023-12-01T00:00:00+00:00'),
    ('startofday', ['+2h'], '2024-02-29T02:00:00+00:00'),
    ('endofday', ['-1y'], '2023-02-28T23:59:59.999999+00:00'),
    ('startofweek', ['1'], '2024-03-04T00:00:00+00:00'),
])
def test_reporting_periods_and_calendar_increments(name,arg,expected):
    clock=datetime(2024,2,29,12,30,tzinfo=timezone.utc)
    assert query.calendar_function(name,arg,clock,7).isoformat()==expected


@pytest.mark.parametrize('source', [
    'due < endOfMonth("nonsense")', 'due < endOfYear("99999y")',
    'due < now("1d")', 'due < startOfDay("1", "2")',
    'key = watchedIssues()', 'summary IN watchedIssues()',
    'key IN watchedIssues(1)', 'key IN releasedVersions()',
    'fixVersion IN releasedVersions("")', 'due < endOfMonth("1.5M")',
    'due < endOfMonth("1q")', 'due < endOfMonth(currentUser())',
])
def test_invalid_function_arguments_are_positioned_client_errors(pm,source):
    with pytest.raises(query.QueryError) as error:
        query.search(u('dev.one'),source)
    assert error.value.position > 0


def test_collections_recheck_current_user_tenant_and_project_access(pm):
    project,a,b,c=seed()
    actor=u('dev.one')
    # Creation subscribes the reporter, and history means personal viewed items.
    db.session.add(WorkItemVote(tenant_id=actor.tenant_id,user_id=actor.id,work_item_id=b.id))
    db.session.add(WorkItemView(tenant_id=actor.tenant_id,user_id=actor.id,work_item_id=c.id))
    private=make_project('SECRET',members=())
    hidden=service.create_item(u('database.manager'),private,'Hidden')
    from serviceops_core.projects.models import WorkItemWatcher
    db.session.add(WorkItemWatcher(tenant_id=actor.tenant_id,user_id=actor.id,work_item_id=hidden.id))
    db.session.commit()
    assert keys('key IN votedIssues()')==[b.title]
    assert keys('key IN (issueHistory())')==[c.title]
    assert set(keys('key NOT IN votedIssues()'))=={a.title,c.title}
    assert 'Hidden' not in keys('key IN watchedIssues() OR key IN votedIssues()')
    assert query.search(u('outsider'),'key IN watchedIssues() OR key IN votedIssues()').count()==0


def test_version_functions_use_project_identity_and_ignore_archived_versions(pm):
    project,a,b,c=seed()
    rows=[ProjectVersion(tenant_id=project.tenant_id,project_id=project.id,name=name,released=released,archived=archived)
          for name,released,archived in [('1.0',True,False),('2.0',False,False),('old',True,True)]]
    a.fix_versions=[rows[0]]; b.fix_versions=[rows[1]]; c.fix_versions=[rows[2]]
    a.affects_versions=[rows[0]]
    db.session.commit()
    assert keys('fixVersion IN releasedVersions()')==[a.title]
    assert keys('fixVersion IN unreleasedVersions(WEB)')==[b.title]
    assert keys('affectsVersion IN releasedVersions("WEB")')==[a.title]
    assert keys('fixVersion IN releasedVersions(SECRET)')==[]
    assert set(keys('fixVersion NOT IN releasedVersions()'))=={b.title,c.title}


def test_calendar_functions_work_in_web_and_api_queries(pm,client):
    from tests.test_projects_web import _api
    project,a,b,c=seed()
    header=_api(pm,'dev.one',['projects:read'])
    source='due < endOfYear("+1")'
    response=client.get('/api/v1/work-item-search',headers=header,query_string={'jql':source})
    assert response.status_code==200 and response.json['meta']['total']==1
    client.post('/login',data={'username':'dev.one','password':'Passw0rd!x'})
    response=client.get('/projects/search',query_string={'jql':source})
    assert response.status_code==200 and a.title in response.get_data(as_text=True)


def test_offset_dates_are_normalized_to_utc_before_calendar_comparison(pm):
    project,a,b,c=seed()
    assert keys('due = "2026-01-02T00:30:00+09:00"')==[a.title]
    assert keys('due = "2025-12-31T23:30:00-02:00"')==[a.title]


def test_changed_qualifiers_match_one_event_and_preserve_scope(pm):
    from serviceops_core.projects.models import WorkItemHistory
    project,a,b,c=seed()
    actor=u('dev.one')
    service.update_item(actor,a,{'priority':'low'})
    service.update_item(actor,a,{'priority':'highest'})
    service.update_item(actor,b,{'priority':'high'})
    db.session.flush()
    events=WorkItemHistory.query.filter_by(work_item_id=a.id,field='priority').order_by(WorkItemHistory.id).all()
    events[0].created_at=datetime(2024,2,1,tzinfo=timezone.utc)
    events[1].created_at=datetime(2024,3,1,tzinfo=timezone.utc)
    db.session.commit()
    assert keys('priority CHANGED FROM high TO low BY currentUser() BEFORE "2024-02-02"')==[a.title]
    assert keys('priority CHANGED FROM high TO highest')==[]  # same event, not independent matches
    assert keys('priority CHANGED TO highest AFTER "2024-02-29"')==[a.title]
    assert keys('priority CHANGED BY "dev.one" DURING ("2024-02-01", "2024-02-28")')==[a.title]
    assert keys('priority CHANGED BEFORE "2024-01-31T23:30:00-02:00"')==[a.title]
    assert query.search(u('outsider'),'priority CHANGED OR NOT priority CHANGED').count()==0


@pytest.mark.parametrize('source',[
    'priority CHANGED FROM high FROM low', 'priority CHANGED BY endOfDay()',
    'status CHANGED DURING ("2025-01-01", "2024-01-01")',
    'priority CHANGED AFTER "invalid"', 'labels CHANGED',
    'status CHANGED DURING (now(), currentUser())',
    'status CHANGED TO votedIssues()',
])
def test_invalid_history_qualifiers_fail_explicitly(pm,source):
    with pytest.raises(query.QueryError): query.search(u('dev.one'),source)


def test_scalar_version_functions_use_configured_order_not_dates(pm):
    project,a,b,c=seed()
    rows=[ProjectVersion(tenant_id=project.tenant_id,project_id=project.id,name=name,released=released,position=position)
          for name,released,position in [('older',True,0),('latest',True,2),('next',False,3),('later',False,4)]]
    a.fix_versions=[rows[1]]; b.fix_versions=[rows[0],rows[3]]; c.fix_versions=[rows[2]]
    db.session.commit()
    assert keys('fixVersion = latestReleasedVersion(WEB)')==[a.title]
    assert keys('fixVersion = earliestUnreleasedVersion(WEB)')==[c.title]
    assert set(keys('fixVersion != latestReleasedVersion(WEB)'))=={b.title,c.title}
    assert keys('fixVersion = latestReleasedVersion(SECRET)')==[]
    assert keys('affectedVersion IS EMPTY')==[a.title,b.title,c.title]
    for source in ('fixVersion IN latestReleasedVersion(WEB)', 'key = latestReleasedVersion(WEB)',
                   'fixVersion = latestReleasedVersion()', 'fixVersion ~ latestReleasedVersion(WEB)'):
        with pytest.raises(query.QueryError): keys(source)
