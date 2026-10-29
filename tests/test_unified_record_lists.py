"""List searches preserve lifecycle restrictions and supported filters."""
from app import ImprovementItem, OperationalTask, User, db
from tests.test_app import app, client, login  # noqa: F401
from tests.test_task_cancellation import _ctask
from tests.test_user_time import _change


def test_tasks_search_preserves_closed_task_exclusion(client, app):
    login(client)
    ticket_id = _change(client, app)
    first = _ctask(client, app, ticket_id, title='Unique network investigation')
    second = _ctask(client, app, ticket_id, title='Unrelated storage investigation')
    page = client.get('/work/tasks?q=unique+NETWORK').get_data(as_text=True)
    assert 'Unique network investigation' in page
    assert 'Unrelated storage investigation' not in page
    with app.app_context():
        db.session.get(OperationalTask, first).state = 'Cancelled'
        db.session.commit()
    page = client.get('/work/tasks?q=unique').get_data(as_text=True)
    assert 'Unique network investigation' not in page
    assert second != first


def test_improvement_search_combines_keyword_and_status(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        for index, status in enumerate(['Identified', 'Done']):
            db.session.add(ImprovementItem(number=f'IMP-SEARCH-{index}', title=f'Improve networks {index}',
                                          description='A searchable description', status=status,
                                          created_by_id=admin.id, tenant_id=1))
        db.session.commit()
    response = client.get('/improvements?q=SEARCHABLE&status=Identified')
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert 'Improve networks 0' in page and 'Improve networks 1' not in page
    assert client.get('/improvements?status=invalid').status_code == 400
    page = client.get('/improvements?q=no-such-improvement').get_data(as_text=True)
    assert 'Improve networks 0' not in page and 'Improve networks 1' not in page


def test_improvement_search_treats_wildcards_as_text(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        db.session.add(ImprovementItem(number='IMP-PCT-1', title='Cut cost 50%', description='',
                                      status='Identified', created_by_id=admin.id, tenant_id=1))
        db.session.add(ImprovementItem(number='IMP-PCT-2', title='Cut cost 500 dollars', description='',
                                      status='Identified', created_by_id=admin.id, tenant_id=1))
        db.session.commit()
    page = client.get('/improvements?q=50%25').get_data(as_text=True)
    assert 'Cut cost 50%' in page and 'Cut cost 500 dollars' not in page
    page = client.get('/improvements?q=_').get_data(as_text=True)
    assert 'Cut cost 50%' not in page
