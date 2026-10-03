"""Route and recovery regressions for the 2026-10-03 strict review."""
import json
import logging
from datetime import timedelta
from email.message import EmailMessage
from types import SimpleNamespace

import pyotp
import pytest

import app as core
import installer.app as installer
from test_app import app, client, group_id, login, _FakeIMAPConnection  # noqa: F401
from serviceops_models import (
    APIClient, CiClassPermission, ClientMailbox, ClientTicket, ClientTicketMessage,
    ConfigurationItem, IntegrationSyncJob, PlatformSetting, Rack, SLADefinition,
    SupportGroup, TaskSLA, Tenant, Ticket, User, db, now,
)
from serviceops_core.security import RedactingFilter
from serviceops_core import network_discovery


MOBILE_HEADERS = {"X-ServiceOps-Platform": "iOS", "X-ServiceOps-Device": "regression",
                  "X-ServiceOps-App-Version": "1", "X-ServiceOps-App-Build": "1"}


def mobile_login(client):
    response = client.post('/api/v1/auth/mobile/login', headers=MOBILE_HEADERS,
                           json={'username': 'employee', 'password': 'Employee123!'})
    assert response.status_code == 200
    return response.get_json()


def other_tenant():
    db.session.add(Tenant(id=2, slug='regression-other', name='Other organization'))
    db.session.flush()


@pytest.mark.parametrize('role,grant,status', [('requester', False, 403), ('agent', False, 403),
                                             ('agent', True, 201), ('admin', False, 201)])
def test_cmdb_api_requires_acting_role_and_class_permission(app, client, role, grant, status):
    with app.app_context():
        user = User.query.filter_by(username='admin' if role == 'admin' else 'employee').one()
        user.role = role
        token, prefix, digest = core.create_api_token()
        db.session.add(APIClient(name='class-policy', token_prefix=prefix, token_hash=digest,
                                scopes_json=json.dumps(['cmdb:write']), acting_user_id=user.id,
                                created_by_id=user.id, tenant_id=1))
        if grant:
            db.session.add(CiClassPermission(tenant_id=1, ci_class='Server', role=role, can_create=True))
        db.session.commit()
    response = client.put('/api/v1/cmdb/configuration-items', json={'name': 'policy-ci', 'ci_class': 'Server'},
                          headers={'Authorization': 'Bearer ' + token})
    assert response.status_code == status
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name='policy-ci').count() == (status == 201)


@pytest.mark.parametrize('editing,field', [(False, 'rack_id'), (False, 'support_group_id'),
                                          (True, 'rack_id'), (True, 'support_group_id'), (True, 'owner_id')])
def test_cmdb_rejects_foreign_relationships_without_mutation(app, client, field, editing):
    with app.app_context():
        other_tenant()
        foreign = {'rack_id': Rack(tenant_id=2, name='foreign-rack'),
                   'support_group_id': SupportGroup(tenant_id=2, name='foreign-group'),
                   'owner_id': User(tenant_id=2, username='foreign-user', name='Foreign', email='foreign@example.test',
                                    password_hash=core.hash_password('SyntheticRegressionPassword'))}[field]
        db.session.add(foreign)
        ci = ConfigurationItem(tenant_id=1, name='original-ci', ci_class='Server')
        db.session.add(ci)
        db.session.commit()
        foreign_id, ci_id = foreign.id, ci.id
    login(client)
    response = client.post(f'/cmdb/{ci_id}/edit' if editing else '/cmdb/new', data={
        'name': 'changed-ci', 'ci_class': 'Server', 'environment': 'Production',
        'operational_status': 'Operational', field: str(foreign_id),
    })
    assert response.status_code == 400
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name='changed-ci').count() == 0
        assert db.session.get(ConfigurationItem, ci_id).name == 'original-ci'


def test_incident_rejects_foreign_owning_team(app, client):
    with app.app_context():
        other_tenant()
        group = SupportGroup(tenant_id=2, name='foreign-IT', group_type='IT Fulfillment', active=True)
        db.session.add(group)
        db.session.commit()
        foreign_id = group.id
    login(client)
    response = client.post('/tickets/new/incident', data={'title': 'foreign-incident', 'description': 'regression',
                           'category': 'Software', 'group_id': str(foreign_id)})
    assert response.status_code == 400
    assert b'active IT fulfillment team' in response.data
    with app.app_context():
        assert Ticket.query.filter_by(title='foreign-incident').count() == 0


def test_slas_use_target_tenant_even_without_request_context(app, client):
    with app.app_context():
        other_tenant()
        db.session.add(SLADefinition(tenant_id=2, name='foreign-SLA', target_type='ticket', duration_minutes=1))
        db.session.commit()
    login(client)
    response = client.post('/tickets/new/incident', data={'title': 'scoped-sla', 'description': 'regression',
                           'category': 'Software', 'priority': 'P3', 'group_id': str(group_id(app))})
    assert response.status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title='scoped-sla').one()
        slas = TaskSLA.query.filter_by(target_type='ticket', target_id=ticket.id).all()
        assert slas and all(row.definition.tenant_id == 1 for row in slas)
        core.attach_slas('ticket', ticket.id, 'P3')
        assert TaskSLA.query.filter_by(target_type='ticket', target_id=ticket.id).count() == len(slas)


def test_password_rotation_revokes_mobile_access_and_refresh(app, client):
    tokens = mobile_login(client)
    web = app.test_client()
    login(web, 'employee', 'Employee123!')
    assert web.post('/profile/password', data={'current_password': 'Employee123!',
        'new_password': 'RotatedRegressionPassword123!', 'confirm_password': 'RotatedRegressionPassword123!'}).status_code == 302
    assert client.get('/api/v1/tickets', headers={'Authorization': 'Bearer ' + tokens['access_token']}).status_code == 401
    assert client.post('/api/v1/auth/mobile/refresh', json={'refresh_token': tokens['refresh_token']}).status_code == 401
    assert web.get('/profile').status_code == 200


def test_tenant_deactivation_rejects_web_mobile_and_integration_auth(app, client):
    tokens = mobile_login(client)
    web = app.test_client()
    login(web, 'employee', 'Employee123!')
    with app.app_context():
        db.session.get(Tenant, 1).active = False
        db.session.commit()
    assert web.get('/profile').status_code == 302
    assert client.get('/api/v1/tickets', headers={'Authorization': 'Bearer ' + tokens['access_token']}).status_code == 403
    assert client.post('/api/v1/auth/mobile/refresh', json={'refresh_token': tokens['refresh_token']}).status_code == 401
    assert client.post('/api/v1/auth/mobile/login', headers=MOBILE_HEADERS, json={'username': 'employee', 'password': 'Employee123!'}).status_code == 403
    assert app.test_client().post('/login', data={'username': 'employee', 'password': 'Employee123!'}).status_code == 200


@pytest.mark.parametrize('invalidate', ['password', 'expired', 'future', 'tenant'])
def test_mfa_pending_state_expires_and_tracks_identity_version(app, client, invalidate):
    secret = pyotp.random_base32()
    with app.app_context():
        user = User.query.filter_by(username='employee').one()
        user.mfa_enabled = True
        user.mfa_secret_encrypted = core.settings_cipher().encrypt(secret.encode()).decode()
        db.session.commit()
    assert client.post('/login', data={'username': 'employee', 'password': 'Employee123!'}).status_code == 302
    if invalidate in ('password', 'tenant'):
        with app.app_context():
            if invalidate == 'password':
                User.query.filter_by(username='employee').one().auth_version += 1
            else:
                db.session.get(Tenant, 1).active = False
            db.session.commit()
    else:
        with client.session_transaction() as state:
            state['_mfa_pending_started_at'] = now().timestamp() + (60 if invalidate == 'future' else -301)
    response = client.post('/login/mfa', data={'code': pyotp.TOTP(secret).now()})
    assert response.status_code == 302 and response.headers['Location'].endswith('/login')
    assert client.get('/profile').status_code == 302
    with client.session_transaction() as state:
        assert '_mfa_pending_user_id' not in state


@pytest.mark.parametrize('payload', [['bad'], 'bad', 1, True, [], None])
def test_mobile_refresh_rejects_non_object_json(client, payload):
    assert client.post('/api/v1/auth/mobile/refresh', json=payload).status_code == 400


def test_request_logging_redacts_recovery_path_in_message_and_metadata():
    token = 'synthetic-recovery-token'
    record = logging.LogRecord('serviceops.request', logging.INFO, __file__, 1,
                               'GET /reset-password/%s -> 200', (token,), None)
    record.path = '/reset-password/' + token
    assert RedactingFilter().filter(record)
    assert token not in core.JsonLogFormatter().format(record)


def test_discovery_never_consumes_beyond_host_cap(monkeypatch):
    consumed = []
    def hosts():
        for value in range(10):
            consumed.append(value)
            assert len(consumed) <= 4
            yield f'192.0.2.{value + 1}'
    monkeypatch.setattr(network_discovery.ipaddress, 'ip_network', lambda *a, **k: SimpleNamespace(hosts=hosts))
    monkeypatch.setattr(network_discovery, 'probe_host', lambda address, *a, **k: {'address': address})
    assert len(network_discovery.discover_subnet('192.0.2.0/24', 'synthetic', max_hosts=4)) == 4
    assert len(consumed) == 4


@pytest.mark.parametrize('port', ['bad', -1, 65536, {'bad': True}, True, 0])
def test_installer_rejects_invalid_port_before_persistence(tmp_path, monkeypatch, port):
    monkeypatch.setattr(installer, 'STATE', tmp_path)
    installer.save_json('config.json', {'company_name': 'preserved'})
    response = installer.create_app().test_client().post('/api/validate', json={'app_port': port})
    assert response.status_code == 400 and response.is_json
    assert installer.load_json('config.json', {}) == {'company_name': 'preserved'}


def test_installer_corrupt_state_returns_recovery_error(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(installer, 'STATE', tmp_path)
    (tmp_path / 'config.json').write_text('{invalid')
    response = installer.create_app().test_client().post('/api/validate', json={})
    assert response.status_code == 503 and response.is_json
    assert (tmp_path / 'config.json').read_text() == '{invalid'
    assert 'state read failed' in caplog.text


def test_installer_atomic_write_failure_preserves_old_state(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(installer, 'STATE', tmp_path)
    installer.save_json('config.json', {'company_name': 'preserved'})
    monkeypatch.setattr(installer.os, 'replace', lambda *args: (_ for _ in ()).throw(OSError('synthetic')))
    response = installer.create_app().test_client().post('/api/validate', json={})
    assert response.status_code == 503 and response.is_json
    assert installer.load_json('config.json', {}) == {'company_name': 'preserved'}
    assert 'state write failed' in caplog.text
    assert not list(tmp_path.glob('.installer-*'))


@pytest.mark.parametrize('cancel', [False, True])
def test_ownerless_sync_jobs_recover_and_release_pending_work(app, monkeypatch, cancel):
    with app.app_context():
        actor = User.query.filter_by(username='admin').one()
        abandoned = IntegrationSyncJob(tenant_id=1, actor_user_id=actor.id, integration='netbox',
            status='Running', cancel_requested=cancel, started_at=now() - timedelta(days=2))
        pending = IntegrationSyncJob(tenant_id=1, actor_user_id=actor.id, integration='netbox')
        db.session.add_all([abandoned, pending])
        db.session.commit()
        monkeypatch.setattr('serviceops_core.netbox_sync.sync_from_netbox', lambda *a, **k: {'devices_seen': 0})
        assert core.process_integration_sync_jobs() == 1
        assert db.session.get(IntegrationSyncJob, abandoned.id).status == ('Cancelled' if cancel else 'Failed')
        assert core.process_integration_sync_jobs() == 1
        assert db.session.get(IntegrationSyncJob, pending.id).status == 'Completed'


def test_active_sync_ownership_prevents_recovery_or_second_runner(app):
    from serviceops_core.integration_job_lock import integration_job_lock
    with app.app_context():
        actor = User.query.filter_by(username='admin').one()
        job = IntegrationSyncJob(tenant_id=1, actor_user_id=actor.id, integration='netbox', status='Running')
        db.session.add(job)
        db.session.commit()
        with integration_job_lock(db.engine, 1, 'netbox') as acquired:
            assert acquired
            assert core.process_integration_sync_jobs() == 0
            assert db.session.get(IntegrationSyncJob, job.id).status == 'Running'


def test_inbound_email_failure_retries_without_marking_seen(app, monkeypatch):
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        mailbox = ClientMailbox(tenant_id=1, name='Retry inbox', imap_host='local.test', smtp_host='local.test',
                                from_address='support@local.test', created_by_id=admin.id)
        db.session.add(mailbox)
        db.session.commit()
        raw = EmailMessage()
        raw['From'] = 'customer@company.test'
        raw['Subject'] = 'Retry regression'
        raw.set_content('Please help')
        class RetryIMAP(_FakeIMAPConnection):
            def fetch(self, num, parts):
                assert parts == '(BODY.PEEK[])'
                return super().fetch(num, parts)
        connection = RetryIMAP([raw.as_bytes()])
        monkeypatch.setattr(core.imaplib, 'IMAP4_SSL', lambda *args: connection)
        original = core._create_client_ticket_from_email
        monkeypatch.setattr(core, '_create_client_ticket_from_email', lambda *args: (_ for _ in ()).throw(RuntimeError('transient')))
        assert core._poll_client_mailbox(mailbox) == 0
        assert connection.stored_flags == {}
        monkeypatch.setattr(core, '_create_client_ticket_from_email', original)
        assert core._poll_client_mailbox(mailbox) == 1
        assert connection.stored_flags[b'1'] == '\\Seen'
        assert core._poll_client_mailbox(mailbox) == 0
        assert ClientTicket.query.filter_by(subject='Retry regression').count() == 1
        assert ClientTicketMessage.query.count() == 1


@pytest.mark.parametrize('mode,status', [('valid', 200), ('list', 502), ('nested-list', 502),
                                        ('image-list', 502), ('oversize', 415), ('interrupt', 502)])
def test_artwork_streams_are_bounded_and_metadata_is_validated(app, client, monkeypatch, mode, status):
    import requests
    responses = []
    class Response:
        is_redirect = False
        def __init__(self, data, content_type='application/json'):
            self.data = data
            self.closed = False
            self.yielded = 0
            self.headers = {'Content-Type': content_type}
            responses.append(self)
        def raise_for_status(self):
            return None
        def iter_content(self, chunk_size):
            if self.headers['Content-Type'] == 'application/json':
                yield json.dumps(self.data).encode()
            elif mode == 'oversize':
                for _ in range(400):
                    self.yielded += 1
                    yield b'x' * 16384
            elif mode == 'interrupt':
                raise requests.ConnectionError('synthetic interrupted stream')
            else:
                yield b'\x89PNG\r\n\x1a\nfixture'
        def close(self):
            self.closed = True
    class Session:
        closed = False
        def get(self, url, **options):
            assert options['stream'] is True and options['allow_redirects'] is False
            if url.endswith('/devices/41/'):
                return Response(['bad'] if mode == 'list' else {'device_type': [] if mode == 'nested-list' else {'id': 9}})
            if url.endswith('/device-types/9/'):
                return Response({'front_image': ['bad'] if mode == 'image-list' else '/media/image.png'})
            assert url == 'https://netbox.example.test/media/image.png'
            return Response(None, 'image/png')
        def close(self):
            self.closed = True
    session = Session()
    monkeypatch.setattr('serviceops_core.netbox_sync._netbox_session', lambda *args: session)
    with app.app_context():
        for key, value in [('NETBOX_ENABLED', 'true'), ('NETBOX_BASE_URL', 'https://netbox.example.test'),
                           ('NETBOX_API_TOKEN', 'synthetic-token')]:
            db.session.add(PlatformSetting(key=key, value=value, tenant_id=1))
        ci = ConfigurationItem(tenant_id=1, name='artwork-regression', ci_class='Server',
                               external_source='netbox', external_id='dcim.device:41')
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    login(client)
    response = client.get(f'/cmdb/device-artwork/{ci_id}/front')
    assert response.status_code == status
    assert session.closed and all(item.closed for item in responses)
    if mode == 'oversize':
        assert responses[-1].yielded == 321
