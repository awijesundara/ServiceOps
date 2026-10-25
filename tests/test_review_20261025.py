"""Quota accounting regressions from the 2026-10-25 review."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import insert

from app import AICall, AIConnection, Tenant, db
from serviceops_core.ai import quota
from tests.test_app import app, client


def connection(**values):
    return SimpleNamespace(id=1, quota_tz='UTC', rpm_limit=None, tpm_limit=None, rpd_limit=None, **values)


def test_quota_counts_calls_beyond_old_global_row_limit(app):
    at = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
    with app.app_context():
        service = AIConnection(tenant_id=1, name='High volume', provider='self_hosted', model='test',
                               endpoint='http://localhost:11434', rpd_limit=20001)
        db.session.add(service)
        db.session.flush()
        db.session.execute(insert(AICall), [dict(tenant_id=1, connection_id=service.id,
            started_at=at - timedelta(seconds=10), prompt_tokens=2, completion_tokens=1) for _ in range(20001)])
        db.session.commit()
        head = quota.headroom(service, quota.recent_calls(1, at), at=at)
        assert head.rpd_used == 20001
        assert head.rpm_used == 20001 and head.tpm_used == 60003
        assert not head.ok and head.reason == 'day'


@pytest.mark.parametrize('at,hours', [
    (datetime(2026, 11, 1, 7, tzinfo=timezone.utc), 25),
    (datetime(2026, 3, 8, 8, tzinfo=timezone.utc), 23),
])
def test_daily_reset_wait_tracks_daylight_saving_transition(at, hours):
    service = connection()
    service.quota_tz = 'America/Los_Angeles'
    service.rpd_limit = 1
    calls = {1: [SimpleNamespace(started_at=at, prompt_tokens=1, completion_tokens=0)]}
    head = quota.headroom(service, calls, at=at)
    assert not head.ok and head.wait == hours * 3600


def test_aggregates_preserve_provider_midnights_minute_boundary_and_tenant(app):
    at = datetime(2026, 10, 25, 4, tzinfo=timezone.utc)
    with app.app_context():
        other = Tenant(name='Quota isolation', slug='quota-isolation')
        db.session.add(other)
        db.session.flush()
        services = [AIConnection(tenant_id=tenant, name=name, provider='self_hosted', model='test',
                                 endpoint='http://localhost:11434', quota_tz=zone, rpm_limit=2)
                    for tenant, name, zone in [(1, 'UTC', 'UTC'), (1, 'LA', 'America/Los_Angeles'),
                                                (other.id, 'Other', 'UTC')]]
        db.session.add_all(services)
        db.session.flush()
        for service in services:
            db.session.execute(insert(AICall), [dict(tenant_id=service.tenant_id, connection_id=service.id,
                started_at=moment, prompt_tokens=2, completion_tokens=3) for moment in
                (at - timedelta(hours=5), at - timedelta(seconds=61),
                 at - timedelta(seconds=60), at - timedelta(seconds=10))])
        db.session.commit()
        usage = quota.recent_calls(1, at)
        assert set(usage) == {s.id for s in services[:2]}
        assert all(isinstance(row, quota.CallUsage) for row in usage.values())
        for service, daily in zip(services, (3, 4)):
            head = quota.headroom(service, usage, at=at)
            assert (head.rpm_used, head.tpm_used, head.rpd_used) == (2, 10, daily)
            assert not head.ok and head.reason == 'minute' and head.wait == 1
        assert quota.recent_calls(999999, at) == {}


@pytest.mark.parametrize('transport', ['form', 'header'])
@pytest.mark.parametrize('token', ['é', '安全', 'wrong-ascii-token'])
def test_malformed_csrf_token_returns_400(client, app, transport, token):
    app.config['CSRF_ENABLED'] = True
    with client.session_transaction() as session:
        session['_csrf_token'] = 'a' * 43
    response = client.post('/login', data={'_csrf_token': token} if transport == 'form' else {},
                           headers={'X-CSRF-Token': token} if transport == 'header' else {})
    assert response.status_code == 400


def test_service_ci_link_reads_are_batched(client, app):
    from sqlalchemy import event
    from werkzeug.datastructures import MultiDict
    from app import ConfigurationItem, ServiceOfferingCI
    from tests.test_app import login
    from tests.test_service_offering_creation import PATH, form

    login(client)
    with app.app_context():
        cis = [ConfigurationItem(name=f'Batch CI {index}', ci_class='Server', tenant_id=1) for index in range(12)]
        db.session.add_all(cis)
        db.session.commit()
        identifiers = [ci.id for ci in cis]
        engine = db.engine
    data = MultiDict(form(app))
    for identifier in identifiers:
        data.add('ci_id', str(identifier))
    statements = []

    def capture(conn, cursor, statement, params, context, executemany):
        if statement.lstrip().upper().startswith('SELECT') and 'FROM service_offering_ci' in statement:
            statements.append(statement)

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        assert client.post(PATH, data=data).status_code == 303
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    assert len(statements) == 1, f'{len(statements)} mapping reads for 12 CIs'
    with app.app_context():
        assert ServiceOfferingCI.query.count() == 12


@pytest.mark.parametrize('supplied,status', [('é', 401), ('wrong', 401), ('scrape-secret', 200)])
def test_metrics_token_rejects_malformed_input(client, monkeypatch, supplied, status):
    monkeypatch.setenv('METRICS_TOKEN', 'scrape-secret')
    assert client.get('/metrics', headers={'Authorization': 'Bearer ' + supplied}).status_code == status
