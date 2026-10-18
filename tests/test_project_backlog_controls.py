from datetime import timedelta

import pytest
from werkzeug.exceptions import HTTPException

from tests.test_app import app, client  # noqa: F401
from tests.test_projects_phase2 import pm, project, u  # noqa: F401
from serviceops_core.projects import backlog_controls as controls, releases, service
from serviceops_core.projects.models import WorkItem
from serviceops_models import db, now


def test_quick_filters_combine_with_versions_and_epics(pm):
    row = project()
    actor = u('dev.one')
    epic = service.create_item(actor, row, 'Foundation', item_type='epic')
    version = releases.save_version(u('database.manager'), row, 'First release')
    first = service.create_item(actor, row, 'Review access', parent_id=epic.id, assignee_ids=[actor.id],
                                flagged=True, fix_version_ids=[version.id], due_date=(now().date()-timedelta(days=1)).isoformat())
    service.create_item(actor, row, 'Unassigned work', assignee_ids=[], story_points=3, estimate_minutes=60)
    db.session.commit()
    base = WorkItem.query.filter_by(project_id=row.id, item_type='task')
    for quick in ('mine', 'flagged', 'overdue', 'unestimated'):
        values = controls.read_filters(actor, row, dict(quick=quick, version=str(version.id), epic=str(epic.id)))
        assert [i.id for i in controls.filtered(actor, row, base, values)] == [first.id]
    values = controls.read_filters(actor, row, dict(quick='unassigned'))
    assert [i.title for i in controls.filtered(actor, row, base, values)] == ['Unassigned work']
    result = controls.insights(base)
    assert result['count'] == 2 and result['todo'] == 2 and result['flagged'] == 1
    assert result['missing_points'] == 1 and result['points'] == 3


@pytest.mark.parametrize('values', [{'quick':'arbitrary'}, {'q':'x'*201}, {'version':'bad'}, {'epic':'-1'}, {'assignee':'bad'}])
def test_invalid_backlog_controls_rejected(pm, values):
    row = project()
    with pytest.raises(HTTPException) as error:
        controls.read_filters(u('dev.one'), row, values)
    assert error.value.code == 400


def test_private_scope_and_version_isolation(pm):
    row = project()
    other = project('OTHER')
    version = releases.save_version(u('database.manager'), other, 'Hidden release')
    db.session.commit()
    with pytest.raises(HTTPException) as error:
        controls.read_filters(u('outsider'), row, {})
    assert error.value.code == 404
    with pytest.raises(HTTPException) as error:
        controls.read_filters(u('dev.one'), row, {'version':str(version.id)})
    assert error.value.code == 404
