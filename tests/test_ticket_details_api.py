"""Authenticated detail parity and tenant/role/class boundary regressions."""
import json

from test_ticket_rack_location import app, client, incident
from app import (APIClient, CiClassPermission, ConfigurationItem, TaskCI, TaskHistory,
                 Ticket, User, db, create_api_token)
from serviceops_models import ChangeGovernance, Tenant


def bearer(app, username="admin", scopes=("tickets:read",)):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        token, prefix, hashed = create_api_token()
        db.session.add(APIClient(name="Detail parity", token_prefix=prefix, token_hash=hashed,
                                 scopes_json=json.dumps(scopes), acting_user_id=user.id,
                                 created_by_id=user.id, tenant_id=user.tenant_id))
        db.session.commit()
    return {"Authorization": f"Bearer {token}"}


def number(app, ticket_id):
    with app.app_context():
        return db.session.get(Ticket, ticket_id).number


def mobile(client, username="admin", password="Admin123!"):
    response = client.post('/api/v1/auth/mobile/login', json={'username': username, 'password': password},
                           headers={'X-ServiceOps-Platform': 'iOS', 'X-ServiceOps-App-Version': '1.3.2',
                                    'X-ServiceOps-App-Build': '8', 'X-ServiceOps-Device': 'iPhone17,1'})
    assert response.status_code == 200, response.json
    return {'Authorization': f'Bearer {response.json["access_token"]}'}


def test_ticket_json_includes_primary_affected_services_and_locations(app, client):
    tid = incident(app, extra=("neighbour", "loose"))
    with app.app_context():
        db.session.add(TaskHistory(target_type="ticket", target_id=tid, event="Record created", details="Example history"))
        db.session.commit()
    n = number(app, tid)
    headers = bearer(app)
    response = client.get(f'/api/v1/tickets/{n}', headers=headers)
    assert response.status_code == 200, response.json
    doc = response.json['data']
    items = doc['configuration_items']
    assert [x['name'] for x in items] == ['db-prod-07', 'esx-prod-14', 'payroll-api']
    assert items[0]['relationship_role'] == 'Primary CI'
    assert items[0]['rack']['id'] == app.config['IDS']['rack']
    assert items[0]['rack']['position'] == 22
    assert items[2]['rack'] is None
    details = client.get(f'/api/v1/tickets/{n}/details', headers=headers).json['data']
    assert details == doc['details']
    sections = {x['id']: x for x in details['sections']}
    assert {'record', 'slas', 'approvals', 'work_tasks', 'related', 'history'} <= sections.keys()
    assert sections['history']['entries'][0]['fields'][-1]['value'] == 'Example history'
    assert 'configuration_items' not in client.get('/api/v1/tickets', headers=headers).json['data'][0]


def test_mobile_rack_route_matches_actual_relationships_and_deduplicates(app, client):
    tid = incident(app, extra=("mounted", "neighbour", "loose"))
    headers = mobile(client)
    n = number(app, tid)
    response = client.get(f'/api/v1/mobile/tickets/{n}/rack-placements', headers=headers)
    assert response.status_code == 200, response.json
    assert len(response.json['data']) == 2
    assert response.json['data'][0]['ci']['id'] == app.config['IDS']['mounted']
    assert response.json['data'][0]['label'] == 'B4-12 · Tokyo DC1 · U22, front'
    assert response.json['meta']['open_on_affected_cis'] is True


def test_requester_never_receives_internal_topology_or_history(app, client):
    tid = incident(app, requester_key='requester')
    headers = bearer(app, 'rack.requester')
    response = client.get(f'/api/v1/tickets/{number(app, tid)}', headers=headers)
    assert response.status_code == 200
    details = response.json['data']['details']
    assert details['configuration_items'] == []
    assert {x['id'] for x in details['sections']} == {'record', 'slas', 'related'}
    assert 'db-prod-07' not in response.get_data(as_text=True)
    assert client.get(f'/api/v1/mobile/tickets/{number(app, tid)}/rack-placements', headers=mobile(client, 'rack.requester', 'Requester123!')).status_code == 403


def test_ci_class_and_cross_tenant_links_are_filtered(app, client):
    tid = incident(app, extra=('loose',))
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        db.session.add(CiClassPermission(tenant_id=admin.tenant_id, ci_class='Server', role='manager', can_read=True))
        other = Tenant(name='Other detail tenant', slug='other-detail')
        db.session.add(other)
        db.session.flush()
        foreign = ConfigurationItem(name='Foreign secret server', ci_class='Application', tenant_id=other.id)
        db.session.add(foreign)
        db.session.flush()
        db.session.add(TaskCI(target_type='ticket', target_id=tid, ci_id=foreign.id, relationship_role='Affected CI'))
        db.session.commit()
    response = client.get(f'/api/v1/tickets/{number(app, tid)}', headers=bearer(app, 'dc.agent'))
    assert response.status_code == 200
    assert [x['name'] for x in response.json['data']['configuration_items']] == ['payroll-api']
    assert 'Foreign secret server' not in response.get_data(as_text=True)


def test_missing_or_invisible_ticket_and_missing_scope(app, client):
    tid = incident(app)
    n = number(app, tid)
    headers = bearer(app, 'rack.requester')
    for path in [f'/api/v1/tickets/{n}', f'/api/v1/tickets/{n}/details', '/api/v1/tickets/INC999999999/details']:
        assert client.get(path, headers=headers).status_code == 404
    assert client.get(f'/api/v1/tickets/{n}/details', headers=bearer(app, scopes=('cmdb:read',))).status_code == 403


def test_governance_primary_ci_and_empty_ticket_are_supported(app, client):
    tid = incident(app, ci_key=None)
    headers = bearer(app)
    n = number(app, tid)
    assert client.get(f'/api/v1/tickets/{n}', headers=headers).json['data']['configuration_items'] == []
    with app.app_context():
        ticket = db.session.get(Ticket, tid)
        ticket.kind = 'change'
        db.session.add(ChangeGovernance(ticket_id=tid, tenant_id=ticket.tenant_id, ci_id=app.config['IDS']['mounted'],
                                        implementation_plan='Replace PSU', test_plan='Check', backout_plan='Revert'))
        db.session.commit()
    doc = client.get(f'/api/v1/tickets/{n}', headers=headers).json['data']
    assert doc['configuration_items'][0]['relationship_role'] == 'Primary CI'
    gov = next(x for x in doc['details']['sections'] if x['id'] == 'governance')
    assert any(x['value'] == 'Replace PSU' for x in gov['entries'][0]['fields'])


def test_detail_failure_is_not_silently_returned_as_empty(app, client, monkeypatch):
    tid = incident(app)
    headers = bearer(app)
    import serviceops_core.ticket_details as contract
    def fail(*args):
        raise RuntimeError('projection failure')
    monkeypatch.setattr(contract, 'ticket_details', fail)
    response = client.get(f'/api/v1/tickets/{number(app, tid)}/details', headers=headers)
    assert response.status_code == 500
    assert 'projection failure' not in response.get_data(as_text=True)


def test_openapi_documents_detail_and_placement_routes(client):
    paths = client.get('/api/v1/openapi.json').json['paths']
    assert '/tickets/{number}/details' in paths
    assert '/mobile/tickets/{number}/rack-placements' in paths


def test_major_incident_approvals_tasks_and_slas_are_readable(app, client):
    from serviceops_models import (ApprovalChain, ApprovalGate, ApprovalVote, MajorIncidentProfile,
                                   MajorIncidentUpdate, OperationalTask, SLADefinition, TaskSLA, now)
    from datetime import timedelta
    tid = incident(app)
    with app.app_context():
        ticket = db.session.get(Ticket, tid)
        tenant = ticket.tenant_id
        admin_id = app.config['IDS']['admin']
        major = MajorIncidentProfile(ticket_id=tid, coordinator_id=admin_id, communications='Investigation ongoing')
        chain = ApprovalChain(target_type='ticket', target_id=tid, name='Infrastructure approval', tenant_id=tenant)
        definition = SLADefinition(name='Parity SLA', target_type='ticket', duration_minutes=60, tenant_id=tenant)
        db.session.add_all([major, chain, definition])
        db.session.flush()
        gate = ApprovalGate(chain_id=chain.id, sequence=1, name='Team manager', tenant_id=tenant)
        db.session.add(gate)
        db.session.flush()
        db.session.add_all([
            ApprovalVote(gate_id=gate.id, approver_id=admin_id, state='Requested', tenant_id=tenant),
            MajorIncidentUpdate(major_incident_profile_id=major.id, status='Investigating', message='Checking PSU', posted_by_id=admin_id, tenant_id=tenant),
            TaskSLA(definition_id=definition.id, target_type='ticket', target_id=tid, breach_at=now()+timedelta(hours=1)),
            OperationalTask(number='CTASK-PARITY-1', task_kind='change', parent_type='ticket', parent_id=tid,
                            title='Check hardware', task_type='Implementation', assignment_group_id=app.config['IDS']['dc'], work_notes='PSU checked'),
        ])
        db.session.commit()
    doc = client.get(f'/api/v1/tickets/{number(app, tid)}', headers=bearer(app)).json['data']['details']
    sections = {x['id']: x for x in doc['sections']}
    assert sections['approvals']['entries'][0]['title'] == 'Infrastructure approval · Team manager'
    assert sections['slas']['entries'][0]['title'] == 'Parity SLA'
    assert sections['work_tasks']['entries'][0]['fields'][-1]['value'] == 'PSU checked'
    assert sections['status_updates']['entries'][0]['fields'][0]['value'] == 'Checking PSU'
    assert any(f['value'] == 'Investigation ongoing' for f in sections['major_incident']['entries'][0]['fields'])


def test_foreign_rack_is_not_disclosed_and_missing_position_stays_null(app, client):
    from serviceops_models import Rack
    tid = incident(app)
    with app.app_context():
        ci = db.session.get(ConfigurationItem, app.config['IDS']['mounted'])
        ci.rack_position = None
        db.session.commit()
    headers = bearer(app)
    path = f'/api/v1/tickets/{number(app, tid)}'
    assert client.get(path, headers=headers).json['data']['configuration_items'][0]['rack']['position'] is None
    with app.app_context():
        other = Tenant(name='Foreign rack tenant', slug='foreign-rack')
        db.session.add(other)
        db.session.flush()
        rack = Rack(name='Foreign private rack', site='Foreign site', tenant_id=other.id)
        db.session.add(rack)
        db.session.flush()
        db.session.get(ConfigurationItem, app.config['IDS']['mounted']).rack_id = rack.id
        db.session.commit()
    response = client.get(path, headers=headers)
    assert response.json['data']['configuration_items'][0]['rack'] is None
    assert 'Foreign private rack' not in response.get_data(as_text=True)


def test_requester_related_records_respect_target_visibility(app, client):
    from serviceops_models import RecordLink
    own = incident(app, requester_key='requester')
    hidden = incident(app, requester_key='admin')
    with app.app_context():
        db.session.add(RecordLink(source_type='ticket', source_id=own, target_type='ticket', target_id=hidden, link_type='related_incident'))
        db.session.commit()
    response = client.get(f'/api/v1/tickets/{number(app, own)}/details', headers=bearer(app, 'rack.requester'))
    related = next(s for s in response.json['data']['sections'] if s['id'] == 'related')
    assert related['entries'] == []


def test_mobile_details_alias_and_machine_client_boundaries(app, client):
    tid = incident(app)
    n = number(app, tid)
    auth = mobile(client)
    assert client.get(f'/api/v1/mobile/tickets/{n}/details', headers=auth).json['data']['schema_version'] == 1
    assert client.get(f'/api/v1/mobile/tickets/{n}/rack-placements', headers=bearer(app)).status_code == 403


def test_mobile_avatar_failure_is_sanitized(app, client, monkeypatch):
    import serviceops_core.web.api as routes
    headers = mobile(client)
    with app.app_context():
        User.query.filter_by(username='admin').one().avatar_path = 'avatar.png'
        db.session.commit()

    def fail(*args, **kwargs):
        raise OSError('private storage diagnostic')

    monkeypatch.setattr(routes, 'send_from_directory', fail)
    response = client.get('/api/v1/mobile/profile/avatar', headers=headers)
    assert response.status_code == 500
    assert 'Unable to load the profile picture' in response.get_data(as_text=True)
    assert 'private storage diagnostic' not in response.get_data(as_text=True)
