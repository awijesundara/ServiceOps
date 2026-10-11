"""Regression coverage for actionable mobile lists and cursor boundaries."""
from datetime import timedelta
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from test_app import app, client
from serviceops_models import (
    ApprovalChain, ApprovalDelegation, ApprovalGate, ApprovalVote, ConfigurationItem,
    Knowledge, Notification, Tenant, User, db, now,
)


def bearer(client, username='admin', password='Admin123!'):
    response = client.post('/api/v1/auth/mobile/login', headers={
        'X-ServiceOps-App-Version': '1.3.0', 'X-ServiceOps-App-Build': '5',
        'X-ServiceOps-Platform': 'iOS', 'X-ServiceOps-Device': 'iPhone17,1',
    }, json={'username': username, 'password': password, 'provider': 'local'})
    assert response.status_code == 200
    return {'Authorization': 'Bearer ' + response.json['access_token']}


def pages(client, path, headers, limit=37):
    result, cursor = [], None
    while True:
        args = {'limit': limit}
        if cursor:
            args['cursor'] = cursor
        response = client.get(path, headers=headers, query_string=args)
        assert response.status_code == 200
        body = response.json
        assert body['meta']['returned'] == len(body['data'])
        result.extend(body['data'])
        cursor = body['meta']['next_cursor']
        assert bool(cursor) == body['meta']['has_more']
        if not cursor:
            return result


def test_requested_and_delegated_approvals_precede_history_and_all_pages_are_reachable(app, client):
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        manager = User.query.filter_by(username='database.manager').one()
        chain = ApprovalChain(tenant_id=1, name='Review', target_type='ritm', target_id=1)
        db.session.add(chain)
        db.session.flush()
        gate = ApprovalGate(tenant_id=1, chain_id=chain.id, sequence=1, name='Review')
        db.session.add(gate)
        db.session.flush()
        direct = ApprovalVote(tenant_id=1, gate_id=gate.id, approver_id=admin.id, state='Requested')
        delegated = ApprovalVote(tenant_id=1, gate_id=gate.id, approver_id=manager.id, state='Requested')
        db.session.add_all([direct, delegated])
        db.session.flush()
        requested_ids = {direct.id, delegated.id}
        db.session.add(ApprovalDelegation(tenant_id=1, from_user_id=manager.id, to_user_id=admin.id,
                                         starts_at=now()-timedelta(days=1), ends_at=now()+timedelta(days=1),
                                         active=True, created_by_id=manager.id))
        for _ in range(105):
            db.session.add(ApprovalVote(tenant_id=1, gate_id=gate.id, approver_id=admin.id, state='Approved'))
        db.session.commit()
    headers = bearer(client)
    first = client.get('/api/v1/mobile/approvals', headers=headers).json
    assert {row['id'] for row in first['data'][:2]} == requested_ids
    assert first['meta']['has_more']
    rows = pages(client, '/api/v1/mobile/approvals', headers)
    assert len(rows) == 107
    assert len({row['id'] for row in rows}) == 107


@pytest.mark.parametrize('path,model', [
    ('/api/v1/mobile/knowledge', Knowledge), ('/api/v1/mobile/cmdb', ConfigurationItem),
    ('/api/v1/mobile/notifications', Notification),
])
def test_mobile_lists_return_every_authorized_record_with_tied_sort_keys(app, client, path, model):
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        db.session.add(Tenant(id=2, slug='review-other', name='Other'))
        timestamp = now()
        for n in range(105):
            if model is Knowledge:
                row = model(tenant_id=1, title=f'Review {n}', body='Test', category='Test',
                            author_id=admin.id, created_at=timestamp, published=True, archived=False)
            elif model is ConfigurationItem:
                row = model(tenant_id=1, name=f'Review {n:03}', ci_class='Server', environment='Test')
            else:
                row = model(tenant_id=1, user_id=admin.id, title=f'Review {n}', body='Test', created_at=timestamp)
            db.session.add(row)
        db.session.flush()
        expected = {row.id for row in model.query.filter_by(tenant_id=1).all()}
        if model is Knowledge:
            db.session.add(model(tenant_id=2, title='Foreign', body='Private', category='Test', author_id=admin.id))
        elif model is ConfigurationItem:
            db.session.add(model(tenant_id=2, name='Foreign', ci_class='Server', environment='Test'))
        else:
            db.session.add(model(tenant_id=2, user_id=admin.id, title='Foreign', body='Private'))
        db.session.commit()
    rows = pages(client, path, bearer(client))
    assert {row['id'] for row in rows} == expected
    assert len(rows) == len(expected)


def test_cursors_fail_closed_for_tampering_search_endpoint_and_user(app, client):
    with app.app_context():
        for n in range(3):
            db.session.add(ConfigurationItem(tenant_id=1, name=f'Review {n}', ci_class='Server'))
        db.session.commit()
    headers = bearer(client)
    path = '/api/v1/mobile/cmdb'
    token = client.get(path, headers=headers, query_string={'limit': 1}).json['meta']['next_cursor']
    assert token
    for args in ({'cursor': token+'x'}, {'cursor': token, 'q': 'Review'},
                 {'limit': 0}, {'limit': 101}, {'limit': 'invalid'}, {'cursor': 'x'*4097}):
        assert client.get(path, headers=headers, query_string=args).status_code == 400
    assert client.get('/api/v1/mobile/knowledge', headers=headers, query_string={'cursor': token}).status_code == 400
    manager = bearer(client, 'database.manager', 'Manager123!')
    assert client.get(path, headers=manager, query_string={'cursor': token}).status_code == 400


def test_chart_preserves_proxy_false_and_routes_static_offload_separately():
    helm = shutil.which('helm') or os.path.expanduser('~/.local/bin/helm')
    if not Path(helm).is_file():
        pytest.skip('Helm is required for chart rendering validation')
    root = Path(__file__).resolve().parents[1]
    for enabled in (False, True):
        result = subprocess.run([helm, 'template', 'review', str(root/'charts/serviceops'),
                                 '--set', 'proxy.trustCloudflare=false',
                                 '--set', f'web.staticOffload.enabled={str(enabled).lower()}'],
                                check=True, capture_output=True, text=True)
        docs = list(yaml.safe_load_all(result.stdout))
        web = next(doc for doc in docs if doc and doc['kind'] == 'Deployment' and doc['metadata']['name'] == 'review')
        containers = web['spec']['template']['spec']['containers']
        app_container = containers[0]
        env = {row['name']: row.get('value') for row in app_container['env']}
        assert env['TRUST_CLOUDFLARE_PROXY'] == 'false'
        assert app_container['livenessProbe']['timeoutSeconds'] == 10
        assert app_container['livenessProbe']['failureThreshold'] == 6
        svc = next(doc for doc in docs if doc and doc['kind'] == 'Service' and doc['metadata']['name'] == 'review')
        assert svc['spec']['ports'][0]['targetPort'] == ('edge-http' if enabled else 'http')
        assert ('static-edge' in [row['name'] for row in containers]) == enabled
