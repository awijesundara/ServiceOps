"""Origin badges derive from authenticated clients and persist across reloads."""
from app import Comment, TaskHistory, Ticket, db
from tests.test_ticket_rack_location import app, client, incident  # noqa: F401
from tests.test_ticket_details_api import mobile, number, bearer
from tests.test_app import login


def test_ios_comment_and_record_events_keep_source_and_actor(app, client):
    ticket_id = incident(app)
    ticket_number = number(app, ticket_id)
    headers = mobile(client)
    response = client.post(f'/api/v1/tickets/{ticket_number}/comments', headers=headers,
                           json={'body': 'Evidence posted from my phone'})
    assert response.status_code == 201
    assert response.json['data']['source_platform'] == 'iOS'
    with app.app_context():
        comment = Comment.query.filter_by(ticket_id=ticket_id).one()
        event = TaskHistory.query.filter_by(target_type='ticket', target_id=ticket_id, event='Comment added').one()
        assert comment.source_platform == event.source_platform == 'iOS'
        assert event.actor_id == comment.user_id
    rows = client.get(f'/api/v1/tickets/{ticket_number}/comments', headers=headers).json['data']
    assert rows[0]['source_platform'] == 'iOS'
    patch = client.patch(f'/api/v1/tickets/{ticket_number}', headers={**headers, 'Idempotency-Key': 'ios-priority-origin'},
                         json={'priority': 'P4'})
    assert patch.status_code == 200, patch.json
    with app.app_context():
        assert TaskHistory.query.filter_by(target_type='ticket', target_id=ticket_id, source_platform='iOS').count() >= 2
    login(client)
    page = client.get(f'/ticket/{ticket_id}').get_data(as_text=True)
    assert 'Posted from iOS' in page and 'ai-collab-tag">iOS' in page


def test_web_header_and_integration_token_cannot_forge_ios_attribution(app, client):
    ticket_id = incident(app)
    ticket_number = number(app, ticket_id)
    login(client)
    response = client.post(f'/ticket/{ticket_id}', data={'action': 'comment', 'body': 'Posted on the web'},
                           headers={'X-ServiceOps-Platform': 'iOS'})
    assert response.status_code == 302
    with app.app_context():
        assert Comment.query.filter_by(ticket_id=ticket_id).one().source_platform is None
    token = bearer(app, scopes=('tickets:read', 'tickets:update'))
    response = client.post(f'/api/v1/tickets/{ticket_number}/comments', headers={**token, 'X-ServiceOps-Platform': 'iOS'},
                           json={'body': 'Posted by an integration'})
    assert response.status_code == 201
    assert response.json['data']['source_platform'] is None
    with app.app_context():
        event = TaskHistory.query.filter_by(target_type='ticket', target_id=ticket_id, event='Comment added').order_by(TaskHistory.id.desc()).first()
        assert event.source_platform is None and event.actor_id is not None


def test_origin_migration_preserves_existing_comments_and_history():
    import importlib.util
    from pathlib import Path
    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    path = Path(__file__).parents[1] / 'migrations/versions/20261011_0118_activity_origin.py'
    spec = importlib.util.spec_from_file_location('activity_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE comment (id INTEGER PRIMARY KEY, body TEXT)')
        connection.exec_driver_sql('CREATE TABLE task_history (id INTEGER PRIMARY KEY, event TEXT)')
        connection.exec_driver_sql("INSERT INTO comment VALUES (1, 'Existing note')")
        connection.exec_driver_sql("INSERT INTO task_history VALUES (1, 'Existing event')")
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            migration.upgrade()
            assert connection.exec_driver_sql('SELECT body, source_platform FROM comment').one() == ('Existing note', None)
            assert connection.exec_driver_sql('SELECT event, source_platform FROM task_history').one() == ('Existing event', None)
            migration.downgrade()
            assert connection.exec_driver_sql('SELECT body FROM comment').scalar() == 'Existing note'
            assert connection.exec_driver_sql('SELECT event FROM task_history').scalar() == 'Existing event'
    engine.dispose()
