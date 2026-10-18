"""Nested project work survives navigation, reparenting, cloning and moving."""
import pytest
from werkzeug.exceptions import HTTPException

from app import db
from serviceops_core.projects import operations, service
from serviceops_core.projects.models import WorkItem
from tests.test_app import app, client  # noqa: F401
from tests.test_projects_service import pm, make_project, u  # noqa: F401


def branch(project, depth=5):
    actor = u("dev.one")
    rows = [service.create_item(actor, project, "Root")]
    for index in range(depth):
        rows.append(service.create_item(actor, project, f"Nested {index}", item_type="subtask", parent_id=rows[-1].id))
    db.session.commit()
    return rows


def test_nested_subtasks_have_root_first_path_and_cycle_rejection(pm):
    project = make_project()
    rows = branch(project, 12)
    assert [r.id for r in service.ancestor_path(rows[-1])] == [r.id for r in rows[:-1]]
    assert {r.id for r in service.hierarchy_rows(rows[0])} == {r.id for r in rows[1:]}
    with pytest.raises(HTTPException) as error:
        service.update_item(u("dev.one"), rows[1], {"parent_id": rows[-1].id})
    assert error.value.code == 400
    db.session.rollback()
    assert rows[1].parent_id == rows[0].id


def test_clone_and_move_preserve_the_complete_nested_branch(pm):
    project = make_project()
    rows = branch(project)
    actor = u("dev.one")
    cloned = operations.clone_item(actor, rows[0], include_subtasks=True)
    db.session.commit()
    children = service.hierarchy_rows(cloned)
    assert len(children) == len(rows)-1
    assert {r.title for r in children} == {r.title for r in rows[1:]}
    destination = make_project("DEST")
    operations.move_item(actor, rows[0], destination)
    db.session.commit()
    assert all(r.project_id == destination.id for r in rows)
    assert [r.id for r in service.ancestor_path(rows[-1])] == [r.id for r in rows[:-1]]
    assert cloned.project_id == project.id


def test_delete_intermediate_parent_preserves_children_and_no_orphan_subtasks(pm):
    rows = branch(make_project(), 3)
    service.delete_item(u("dev.one"), rows[1])
    db.session.commit()
    assert rows[2].parent_id == rows[0].id
    service.delete_item(u("dev.one"), rows[0])
    db.session.commit()
    assert rows[2].parent_id is None and rows[2].item_type == "task"
    assert rows[3].parent_id == rows[2].id


def test_convert_parent_with_children_to_nested_subtask(pm):
    project = make_project()
    rows = branch(project)
    new_root = service.create_item(u("dev.one"), project, "New root")
    operations.convert_item(u("dev.one"), rows[0], "subtask", new_root.id)
    db.session.commit()
    assert len(service.ancestor_path(rows[-1])) == len(rows)


def test_nested_creation_and_pages_keep_permission_boundaries(pm, client):
    project = make_project()
    rows = branch(project, 3)
    key, parent_id, root_key = rows[2].key, rows[2].id, rows[0].key
    project_key = project.key
    client.post('/login', data={'username':'dev.one','password':'Passw0rd!x'})
    page = client.get(f'/work-items/{key}')
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert f'/work-items/{root_key}' in html
    assert f'parent={parent_id}' in html and 'wi-children' in html
    response = client.post(f'/projects/{project_key}/items/new', data={
        'title':'From nested page','item_type':'subtask','parent_id':parent_id})
    assert response.status_code == 302
    client.get('/logout')
    client.post('/login', data={'username':'outsider','password':'Passw0rd!x'})
    assert client.get(f'/work-items/{key}').status_code == 404
    assert client.post(f'/projects/{project_key}/items/new', data={
        'title':'Denied','item_type':'subtask','parent_id':parent_id}).status_code == 404


def test_cross_project_and_readonly_nested_changes_denied(pm):
    project = make_project()
    rows = branch(project)
    other = make_project('OTH')
    foreign = service.create_item(u('dev.one'), other, 'Foreign')
    db.session.commit()
    for actor, parent, expected in [(u('dev.one'),foreign,400),(u('outsider'),rows[1],403)]:
        with pytest.raises(HTTPException) as error:
            service.create_item(actor,project,'Denied',item_type='subtask',parent_id=parent.id)
        assert error.value.code == expected
        db.session.rollback()


def test_portfolio_rollups_preview_and_hidden_dependencies(pm):
    from datetime import date
    from serviceops_core.projects import planning
    from serviceops_core.projects.models import WorkItemLink
    project = make_project()
    secret = make_project('SECRET',members=())
    actor = u('dev.one')
    first = service.create_item(actor,project,'Visible source',start_date='2026-10-01',due_date='2026-10-20',remaining_minutes=120)
    second = service.create_item(actor,project,'Visible target',start_date='2026-10-15',due_date='2026-10-21')
    hidden = service.create_item(u('database.manager'),secret,'Private dependency title')
    for source,target in [(first,second),(first,hidden),(hidden,second)]:
        db.session.add(WorkItemLink(tenant_id=actor.tenant_id,source_id=source.id,target_type='work_item',
            target_id=target.id,link_type='blocks',created_by_id=u('database.manager').id))
    db.session.commit()
    data = planning.portfolio(actor,shift_days=7)
    assert data['project_total']==1
    assert data['summaries'][project.id]['start']==date(2026,10,8)
    assert data['summaries'][project.id]['remaining']==120
    assert len(data['dependencies'])==data['dependency_total']==1
    assert data['dependencies'][0]['conflict']
    assert first.start_date==date(2026,10,1)
    with pytest.raises(HTTPException):
        planning.portfolio(actor,shift_days=3651)


def test_planning_route_renders_validates_and_does_not_save_dates(pm,client):
    project=make_project()
    branch(project,2)
    client.post('/login',data={'username':'dev.one','password':'Passw0rd!x'})
    response=client.get('/projects/planning?shift=3')
    assert response.status_code==200
    assert 'nothing has been saved' in response.get_data(as_text=True)
    for query in ('shift=no','shift=9999','page=0'):
        assert client.get('/projects/planning?'+query).status_code==400


def test_parent_selection_keeps_an_older_parent_beyond_option_limit(pm,client):
    project=make_project()
    rows=branch(project,2)
    actor=u('dev.one')
    for index in range(500):
        service.create_item(actor,project,f'Later task {index}')
    db.session.commit()
    parent_id=rows[1].id
    client.post('/login',data={'username':'dev.one','password':'Passw0rd!x'})
    response=client.get(f'/projects/{project.key}/items/new?type=subtask&parent={parent_id}')
    assert response.status_code==200
    assert f'value="{parent_id}" selected' in response.get_data(as_text=True)



def test_readonly_board_explains_why_dragging_is_unavailable(pm,client):
    project=make_project(visibility='open')
    branch(project,1)
    key=project.key
    client.post('/login',data={'username':'outsider','password':'Passw0rd!x'})
    response=client.get(f'/projects/{key}/board')
    assert response.status_code==200
    html=response.get_data(as_text=True)
    assert 'This board is read-only.' in html
    assert 'draggable="true"' not in html
