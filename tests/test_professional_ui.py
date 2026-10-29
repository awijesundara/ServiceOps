"""Privileged navigation responses retain explicit field allowlists."""
import pytest

from app import RecentView, User, db
from serviceops_core.projections import project_document, load_projection_policy
from tests.test_app import app, client, login  # noqa: F401


@pytest.mark.parametrize('resource', ['ticket', 'audit_event', 'search_result', 'workflow_ack', 'ui_action_ack'])
def test_superadmin_projection_is_explicit_and_bounded(resource):
    load_projection_policy.cache_clear()
    audiences = load_projection_policy()['resources'][resource]['audiences']
    assert audiences['superadmin'] == audiences['admin']
    document = {field: 'value' for field in audiences['admin']}
    document['private_unlisted_canary'] = 'must not leak'
    assert project_document(resource, 'superadmin', document) == {
        key: value for key, value in document.items() if key != 'private_unlisted_canary'
    }


def test_superadmin_navigation_history_saves_and_acknowledges(client, app):
    with app.app_context():
        user = User.query.filter_by(username='admin').one()
        user.role = 'superadmin'
        db.session.commit()
    login(client, 'admin', 'Admin123!')
    response = client.post('/ui/history', data={'url': '/catalog', 'label': 'Service catalog'})
    assert response.status_code == 200
    assert response.json == {'url': '/catalog', 'label': 'Service catalog'}
    with app.app_context():
        assert RecentView.query.filter_by(url='/catalog', label='Service catalog').count() == 1
