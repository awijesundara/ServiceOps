"""Shared-boundary regressions found during the whole-code review."""
import gzip
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from flask import Flask, Response
from werkzeug.datastructures import MultiDict

from app import AIConversation, AIMessage, SLADefinition, Tenant, User, db, now
from serviceops_core import compression, input_limits
from serviceops_core.ai import access, service
from tests.test_app import app, client  # noqa: F401


def test_sla_context_is_tenant_scoped(app):
    with app.app_context():
        other = Tenant(name='Private SLA tenant', slug='private-sla')
        db.session.add(other)
        db.session.flush()
        db.session.add_all([
            SLADefinition(name='LOCAL-SLA', tenant_id=1, target_type='response', duration_minutes=15),
            SLADefinition(name='PRIVATE-SLA-CANARY', tenant_id=other.id, target_type='response', duration_minutes=25),
        ])
        db.session.commit()
        user = User.query.filter_by(username='admin').one()
        evidence = access.collect_chat_evidence(access.build_scope(user, 'admin'), 'What is the SLA response time?')
        text = json.dumps(evidence.items)
        assert 'LOCAL-SLA' in text and 'PRIVATE-SLA-CANARY' not in text


@pytest.mark.parametrize('location', ['query', 'form', 'large-json', 'deep-json'])
def test_input_validation_covers_every_value(app, location):
    probe = Flask(__name__)
    probe.before_request(input_limits.reject_nul_characters)
    probe.add_url_rule('/probe', view_func=lambda: 'accepted', methods=['GET', 'POST'])
    c = probe.test_client()
    if location == 'query':
        response = c.get('/probe?q=safe&q=bad%00value')
    elif location == 'form':
        response = c.post('/probe', data=MultiDict([('q', 'safe'), ('q', 'bad\x00value')]))
    elif location == 'large-json':
        response = c.post('/probe', json={'padding': 'a' * 2_000_000, 'q': 'bad\x00value'})
    else:
        response = c.post('/probe', data='[' * 30 + '"bad\\u0000value"' + ']' * 30, content_type='application/json')
    assert response.status_code == 400


@pytest.mark.parametrize('encoding', ['gzip;q=0', 'gzip;q=0, *;q=1', 'br', 'gzip;q=bogus'])
def test_gzip_respects_client_quality_and_varies_plain_responses(encoding):
    probe = Flask(__name__)
    with probe.test_request_context(headers={'Accept-Encoding': encoding}):
        response = compression.compress_response(Response('a' * 2000, mimetype='text/plain'))
        assert 'Content-Encoding' not in response.headers
        assert 'Accept-Encoding' in response.vary


def test_static_cache_uses_asset_identity_not_arbitrary_query_parameters(monkeypatch):
    probe = Flask(__name__)
    probe.add_url_rule('/asset', endpoint='static-probe', view_func=lambda: '')
    monkeypatch.setattr(compression, '_STATIC_CACHE', compression.OrderedDict())
    with probe.test_request_context('/asset?v=1&noise=first', headers={'Accept-Encoding': 'gzip'}):
        from flask import request
        request.url_rule.endpoint = 'static'
        first = compression.compress_response(Response('a' * 2000, headers={'ETag': '"asset1"'}))
    with probe.test_request_context('/asset?v=1&noise=second', headers={'Accept-Encoding': 'gzip'}):
        from flask import request
        request.url_rule.endpoint = 'static'
        second = compression.compress_response(Response('a' * 2000, headers={'ETag': '"asset1"'}))
        assert gzip.decompress(second.get_data()) == b'a' * 2000
    assert first.get_data() == second.get_data()
    assert len(compression._STATIC_CACHE) == 1


def test_chat_history_is_bounded_in_database_and_keeps_latest_completed_turns(app):
    from sqlalchemy import event
    with app.app_context():
        user = User.query.filter_by(username='admin').one()
        conversation = AIConversation(tenant_id=1, user_id=user.id, actor_role='admin')
        db.session.add(conversation)
        db.session.flush()
        at = now()
        db.session.add_all([AIMessage(id=f'{i:036d}', conversation_id=conversation.id, tenant_id=1,
            user_id=user.id, role='user', content=f'turn {i}', created_at=at + timedelta(seconds=i),
            status='completed' if i < 100 else 'failed') for i in range(102)])
        db.session.commit()
        run = SimpleNamespace(conversation_id=conversation.id, message_id='current', tenant_id=1)
        statements = []
        def capture(conn, cursor, statement, params, execution_context, executemany):
            if 'FROM ai_message' in statement:
                statements.append(statement)
        event.listen(db.engine, 'before_cursor_execute', capture)
        try:
            history = service.chat_history(run)
        finally:
            event.remove(db.engine, 'before_cursor_execute', capture)
        assert [m.content for m in history] == [f'turn {i}' for i in range(88, 100)]
        assert len(statements) == 1 and 'LIMIT' in statements[0].upper()


def test_monitoring_preserves_documented_long_summary_and_resource(client, app):
    from app import MonitoringEvent, MonitoringSource, OperationalTask, SupportGroup, create_api_token
    with app.app_context():
        user = User.query.filter_by(username='admin').one()
        group = SupportGroup.query.filter_by(name='Unix').one()
        token, prefix, hashed = create_api_token()
        source = MonitoringSource(name='Long event', token_prefix=prefix, token_hash=hashed,
                                  assignment_group_id=group.id, created_by_id=user.id)
        db.session.add(source)
        db.session.commit()
        endpoint = f'/api/v1/monitoring/{source.source_id}/events'
    payload = {'external_id': 'long-event', 'summary': 's' * 500, 'resource': 'r' * 255, 'severity': 'high'}
    response = client.post(endpoint, json=payload, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 201, response.get_json()
    with app.app_context():
        event = MonitoringEvent.query.filter_by(external_id='long-event').one()
        assert event.summary == payload['summary'] and event.resource == payload['resource']
        assert event.record.title == 's' * 180
        task = OperationalTask.query.filter_by(parent_type='enterprise', parent_id=event.record.id).one()
        assert len(task.title) == 180


def test_method_not_allowed_preserves_allow_header(client):
    response = client.put('/health')
    assert response.status_code == 405
    assert 'GET' in response.headers.get('Allow', '')


def test_extremely_nested_json_returns_bad_request():
    probe = Flask(__name__)
    probe.before_request(input_limits.reject_nul_characters)
    probe.add_url_rule('/probe', view_func=lambda: 'accepted', methods=['POST'])
    response = probe.test_client().post('/probe', data='[' * 102 + '0' + ']' * 102,
                                        content_type='application/json')
    assert response.status_code == 400


def test_static_cache_has_a_byte_budget(monkeypatch):
    probe = Flask(__name__)
    probe = Flask(__name__, static_folder=None)
    probe.add_url_rule('/asset', endpoint='static', view_func=lambda: '')
    monkeypatch.setattr(compression, '_STATIC_CACHE', compression.OrderedDict())
    monkeypatch.setattr(compression, '_STATIC_CACHE_MAX_BYTES', 10)
    with probe.test_request_context('/asset?v=1', headers={'Accept-Encoding': 'gzip'}):
        response = compression.compress_response(Response('a' * 2000, headers={'ETag': '"asset1"'}))
        assert response.headers['Content-Encoding'] == 'gzip'
        assert not compression._STATIC_CACHE
