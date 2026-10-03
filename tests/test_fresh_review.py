"""Transaction and tenant regressions from the fresh application review."""
import pytest
from types import SimpleNamespace
from flask import Flask, abort

import app as core
from test_app import app, client, login  # noqa: F401
from serviceops_models import ApplicationLog, GroupMember, SupportGroup, Tenant, User, db


def test_unhandled_failure_does_not_commit_pending_business_changes(app, client):
    @app.post('/fresh-review-failure')
    def failing_route():
        user = User.query.filter_by(username='employee').one()
        user.name = 'must-not-persist'
        raise RuntimeError('Synthetic transaction failure')
    login(client)
    assert client.post('/fresh-review-failure').status_code == 500
    with app.app_context():
        assert User.query.filter_by(username='employee').one().name == 'Test Employee'
        assert ApplicationLog.query.filter(ApplicationLog.message.contains('Unhandled exception')).count() >= 1


def test_warning_logging_does_not_commit_business_transaction(app):
    with app.app_context():
        user = User.query.filter_by(username='employee').one()
        user.name = 'must-not-persist'
        app.logger.warning('Synthetic warning during business transaction')
        db.session.rollback()
        assert User.query.filter_by(username='employee').one().name == 'Test Employee'
        assert ApplicationLog.query.filter_by(message='Synthetic warning during business transaction').count() == 1


@pytest.mark.parametrize('status', [400, 403, 404, 409, 413])
def test_http_failure_rolls_back_changes_before_error_rendering(app, client, status):
    @app.post('/fresh-review-rejection')
    def rejected_route():
        User.query.filter_by(username='employee').one().name = 'must-not-persist'
        abort(status)
    observed_names = []
    @app.after_request
    def diagnostic_warning(response):
        observed_names.append(User.query.filter_by(username='employee').one().name)
        if response.status_code >= 400:
            app.logger.warning('Synthetic diagnostic after rejected request')
        return response
    login(client)
    response = client.post('/fresh-review-rejection')
    assert response.status_code in (status, 302)
    assert observed_names and set(observed_names) == {'Test Employee'}
    with app.app_context():
        assert User.query.filter_by(username='employee').one().name == 'Test Employee'


@pytest.mark.parametrize('manager', ['foreign', 'missing'])
def test_team_manager_rejects_foreign_or_missing_identity(app, client, manager):
    with app.app_context():
        db.session.add(Tenant(id=2, slug='fresh-other', name='Other'))
        foreign = User(tenant_id=2, username='foreign-manager', name='Foreign', email='foreign@example.test',
                       password_hash=core.hash_password('SyntheticPassword123!'), role='manager')
        db.session.add(foreign)
        db.session.flush()
        group = SupportGroup.query.filter_by(name='Unix').one()
        group_id, old_id = group.id, group.manager_id
        selected = foreign.id if manager == 'foreign' else 999999
        db.session.commit()
    login(client)
    response = client.post('/itil/administration', data={'action':'set_manager', 'group_id':group_id, 'manager_id':selected})
    assert response.status_code in (400, 404)
    with app.app_context():
        group = db.session.get(SupportGroup, group_id)
        assert group.manager_id == old_id
        assert GroupMember.query.filter_by(group_id=group_id, user_id=selected).count() == 0


def test_diagnostics_do_not_commit_flushed_changes_on_shared_sqlite_connection():
    memory_app = Flask('shared-diagnostic-test')
    memory_app.config.update(SQLALCHEMY_DATABASE_URI='sqlite://', SQLALCHEMY_TRACK_MODIFICATIONS=False)
    db.init_app(memory_app)
    handler = core.DatabaseLogHandler()
    memory_app.logger.addHandler(handler)
    try:
        with memory_app.app_context():
            db.create_all()
            db.session.add(Tenant(id=1, slug='default', name='Default'))
            db.session.add(User(tenant_id=1, username='admin', name='Original', email='admin@example.test',
                                password_hash=core.hash_password('SyntheticPassword123!')))
            db.session.commit()
            admin = User.query.filter_by(username='admin').one()
            admin.name = 'must-not-persist'
            db.session.flush()
            memory_app.logger.warning('Synthetic shared-connection diagnostic')
            db.session.rollback()
            assert User.query.filter_by(username='admin').one().name == 'Original'
            assert ApplicationLog.query.filter_by(message='Synthetic shared-connection diagnostic').count() == 1
            db.session.remove()
            db.engine.dispose()
    finally:
        memory_app.logger.removeHandler(handler)


def test_diagnostic_write_failure_is_visible_without_committing_business_state(app, monkeypatch, capsys):
    import serviceops_core.log_storage as storage
    def unavailable_session(*args, **kwargs):
        raise RuntimeError('Synthetic log store outage')
    monkeypatch.setattr(storage, 'Session', unavailable_session)
    with app.app_context():
        User.query.filter_by(username='employee').one().name = 'must-not-persist'
        app.logger.warning('Synthetic diagnostic persistence failure')
        db.session.rollback()
        assert User.query.filter_by(username='employee').one().name == 'Test Employee'
    assert 'diagnostic persistence failed' in capsys.readouterr().err


def integration_headers(app):
    from serviceops_models import APIClient
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        token, prefix, digest = core.create_api_token()
        db.session.add(APIClient(name='Fresh review', tenant_id=1, token_prefix=prefix, token_hash=digest,
                                 scopes_json='["cmdb:write","incidents:create","tickets:update"]', acting_user_id=admin.id,
                                 created_by_id=admin.id))
        db.session.commit()
    return {'Authorization': 'Bearer ' + token, 'Idempotency-Key': 'fresh-review-input'}


@pytest.mark.parametrize('field,value', [('name', {'wrong':'type'}), ('ci_class', ['Server']),
                                         ('environment', 1), ('ip_address', {'wrong':'type'})])
def test_cmdb_api_rejects_non_string_fields(app, client, field, value):
    body = {'name':'fresh-input-ci', field:value}
    response = client.put('/api/v1/cmdb/configuration-items', headers=integration_headers(app), json=body)
    assert response.status_code == 400


def test_cmdb_long_name_does_not_update_another_record(app, client):
    from serviceops_models import ConfigurationItem
    with app.app_context():
        ci = ConfigurationItem(tenant_id=1, name='x' * 160, ci_class='Server', operational_status='Operational')
        db.session.add(ci)
        db.session.commit()
        identifier = ci.id
    response = client.put('/api/v1/cmdb/configuration-items', headers=integration_headers(app),
                          json={'name':'x' * 160 + '-different', 'operational_status':'Down'})
    assert response.status_code == 400
    with app.app_context():
        assert db.session.get(ConfigurationItem, identifier).operational_status == 'Operational'


@pytest.mark.parametrize('field,value', [('title', ['invalid']), ('description', {'invalid':'shape'})])
def test_incident_api_rejects_non_string_content(app, client, field, value):
    with app.app_context():
        group = SupportGroup.query.filter_by(name='Unix').one()
        group_id = group.id
    body = {'title':'Fresh incident', 'description':'Details', 'assignment_group_id':group_id, field:value}
    response = client.post('/api/v1/incidents', headers=integration_headers(app), json=body)
    assert response.status_code == 400


def test_ctask_api_respects_revoked_update_permission(app, client):
    from serviceops_models import APIClient, ChangeOwnership, OperationalTask, RolePolicyOverride, Ticket
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        group = SupportGroup.query.filter_by(name='Unix').one()
        ticket = Ticket(tenant_id=1, number='CHG0099001', kind='change', title='Synthetic change',
                        description='Details', priority='P3', state='Draft', requester_id=admin.id)
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=group.id))
        task = OperationalTask(number='CTASK0099001', task_kind='change', parent_type='ticket',
                               parent_id=ticket.id, title='Synthetic task', task_type='Implementation', state='Open', assignment_group_id=group.id)
        db.session.add(task)
        token, prefix, digest = core.create_api_token()
        db.session.add(APIClient(name='Fresh CTASK test', tenant_id=1, token_prefix=prefix, token_hash=digest,
                                 scopes_json='["tickets:update"]', acting_user_id=admin.id, created_by_id=admin.id))
        db.session.add(RolePolicyOverride(tenant_id=1, role=admin.role, action='update', is_granted=False))
        db.session.commit()
        identifier = task.id
    response = client.patch('/api/v1/tickets/CHG0099001/ctasks/CTASK0099001', json={'work_notes':'Forbidden update'},
                            headers={'Authorization':'Bearer '+token,'Idempotency-Key':'fresh-ctask'})
    assert response.status_code == 403
    with app.app_context():
        assert db.session.get(OperationalTask, identifier).work_notes != 'Forbidden update'


def test_rejected_api_patch_preserves_all_ticket_fields(app, client):
    from serviceops_models import Ticket, TicketAssignmentGroup
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        group = SupportGroup.query.filter_by(name='Unix').one()
        ticket = Ticket(tenant_id=1, number='INC0099001', kind='incident', title='Synthetic incident',
                        description='Details', priority='P3', state='New', requester_id=admin.id)
        db.session.add(ticket)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=group.id))
        db.session.commit()
        identifier = ticket.id
    response = client.patch('/api/v1/tickets/INC0099001', headers=integration_headers(app),
                            json={'resolution_notes':'Must not persist', 'priority':'Invalid'})
    assert response.status_code == 400
    with app.app_context():
        ticket = db.session.get(Ticket, identifier)
        assert ticket.resolution_notes is None
        assert ticket.priority == 'P3'


def test_incident_api_rejects_fractional_group_identifier(app, client):
    with app.app_context():
        group_id = SupportGroup.query.filter_by(name='Unix').one().id
    response = client.post('/api/v1/incidents', headers=integration_headers(app),
                           json={'title':'Synthetic invalid reference', 'description':'Details',
                                 'assignment_group_id':group_id + 0.5})
    assert response.status_code == 400


def test_unavailable_diagnostic_store_and_closed_stderr_do_not_break_rollback(app, monkeypatch):
    import io
    import serviceops_core.log_storage as storage
    def unavailable_session(*args, **kwargs):
        raise RuntimeError('Synthetic log store outage')
    broken_stream = io.StringIO()
    broken_stream.close()
    monkeypatch.setattr(storage, 'Session', unavailable_session)
    monkeypatch.setattr(storage, 'sys', SimpleNamespace(stderr=broken_stream))
    with app.app_context():
        User.query.filter_by(username='employee').one().name = 'must-not-persist'
        app.logger.warning('Synthetic double diagnostic failure')
        db.session.rollback()
        assert User.query.filter_by(username='employee').one().name == 'Test Employee'


def test_failed_request_cleanup_survives_closed_diagnostic_stream(app, client, monkeypatch):
    import io
    import serviceops_core.log_storage as storage
    @app.post('/fresh-review-cleanup-failure')
    def rejected_route():
        User.query.filter_by(username='employee').one().name = 'must-not-persist'
        abort(400)
    login(client)
    def failed_rollback():
        raise RuntimeError('Synthetic rollback failure')
    broken_stream = io.StringIO()
    broken_stream.close()
    monkeypatch.setattr(storage, 'sys', SimpleNamespace(stderr=broken_stream))
    monkeypatch.setattr(core, 'sys', SimpleNamespace(stderr=broken_stream))
    monkeypatch.setattr(db.session, 'rollback', failed_rollback)
    response = client.post('/fresh-review-cleanup-failure')
    assert response.status_code == 400
    with app.app_context():
        assert User.query.filter_by(username='employee').one().name == 'Test Employee'
