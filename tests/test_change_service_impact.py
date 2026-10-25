"""Service creation -> CI mapping -> change impact, including read boundaries."""
from werkzeug.datastructures import MultiDict
import pytest
from app import (ChangeGovernance, CiClassPermission, ConfigurationItem, ServiceOffering,
                 ServiceOfferingCI, TaskCI, Tenant, Ticket, User, db)
from serviceops_core.change_service_impact import impacted_services
from tests.test_app import app, client, login, group_id  # noqa: F401
from tests.test_ticket_details_api import bearer


def create_change(client, app, ci_ids):
    data = MultiDict({"title": "Payment infrastructure maintenance", "description": "Maintenance",
        "category": "Software", "priority": "P3", "change_type": "Standard", "risk_score": "20",
        "impact": "Low", "group_id": group_id(app, "Unix"), "implementation_plan": "Implement",
        "test_plan": "Verify", "backout_plan": "Restore", "planned_start": "2026-12-01T09:00",
        "planned_end": "2026-12-01T10:00"})
    for ci_id in ci_ids:
        data.add("ci_id", str(ci_id))
    response = client.post('/tickets/new/change', data=data)
    assert response.status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Payment infrastructure maintenance").one()
        return ticket.id, ticket.number


def services_in_page(response):
    return response.get_data(as_text=True).split('id="gov-impacted-services"', 1)[1].split('</section>', 1)[0]


def test_web_creation_mapping_change_and_rest_show_each_service_once(client, app):
    login(client)
    with app.app_context():
        cis = [ConfigurationItem(name=name, ci_class='Server', tenant_id=1) for name in ['Payment DB', 'Payment API']]
        db.session.add_all(cis)
        db.session.commit()
        ids = [ci.id for ci in cis]
    for name in ['Payments', 'Reporting']:
        assert client.post('/service-operations/settings', data={
            'action': 'create_service_offering', 'name': name, 'support_group_id': group_id(app, 'Unix'),
            'criticality': 'High', 'return_section': 'service-offerings',
        }).status_code == 303
        with app.app_context():
            service_id = ServiceOffering.query.filter_by(name=name).one().id
        data = MultiDict({'action': 'link_service_ci', 'service_offering_id': str(service_id), 'relationship_role': 'Supporting'})
        for ci_id in ids if name == 'Payments' else ids[1:]:
            data.add('ci_id', str(ci_id))
        assert client.post('/service-operations/settings', data=data).status_code == 302
    tid, number = create_change(client, app, ids)
    panel = services_in_page(client.get(f'/ticket/{tid}'))
    assert panel.count('>Payments</td>') == 1 and panel.count('>Reporting</td>') == 1
    assert 'Payment DB (Supporting)' in panel and 'Payment API (Supporting)' in panel
    headers = bearer(app)
    result = client.get(f'/api/v1/tickets/{number}/details', headers=headers)
    assert result.status_code == 200
    services = result.json['data']['impacted_services']
    assert [s['name'] for s in services] == ['Payments', 'Reporting']
    assert {ci['id'] for ci in services[0]['configuration_items']} == set(ids)
    assert client.get(f'/api/v1/tickets/{number}', headers=headers).json['data']['details']['impacted_services'] == services
    # No synthetic impacted TaskCI rows are written by either reader.
    with app.app_context():
        assert TaskCI.query.filter_by(target_id=tid, relationship_role='Impacted service').count() == 0
        db.session.delete(TaskCI.query.filter_by(target_id=tid, ci_id=ids[1]).one())
        db.session.commit()
    services = client.get(f'/api/v1/tickets/{number}/details', headers=headers).json['data']['impacted_services']
    assert [s['name'] for s in services] == ['Payments']
    assert [ci['id'] for ci in services[0]['configuration_items']] == ids[:1]
    assert client.post(f'/record/ticket/{tid}/configuration-items', data={
        'ci_id': str(ids[1]), 'relationship_role': 'Affected CI',
    }).status_code == 302
    assert [s['name'] for s in client.get(f'/api/v1/tickets/{number}/details', headers=headers).json['data']['impacted_services']] == ['Payments', 'Reporting']
    with app.app_context():
        ServiceOfferingCI.query.delete()
        db.session.commit()
    assert client.get(f'/api/v1/tickets/{number}/details', headers=headers).json['data']['impacted_services'] == []
    assert 'No service offerings mapped' in services_in_page(client.get(f'/ticket/{tid}'))


def test_manual_impacted_cis_are_preserved_and_do_not_expand_derived_scope(client, app):
    login(client)
    with app.app_context():
        ci = ConfigurationItem(name='Manual downstream CI', ci_class='Application', tenant_id=1)
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    tid, number = create_change(client, app, [])
    assert client.post(f'/record/ticket/{tid}/configuration-items', data={'ci_id': str(ci_id), 'relationship_role': 'Impacted service'}).status_code == 302
    panel = services_in_page(client.get(f'/ticket/{tid}'))
    assert 'Manual downstream CI' in panel and 'No service offerings mapped' in panel
    with app.app_context():
        owner = User.query.filter_by(username='admin').one()
        service = ServiceOffering(name='Not in explicit scope', owner_id=owner.id, tenant_id=1)
        db.session.add(service)
        db.session.flush()
        db.session.add(ServiceOfferingCI(service_offering_id=service.id, ci_id=ci_id, tenant_id=1))
        db.session.commit()
        assert impacted_services(db.session.get(Ticket, tid), owner) == []


def test_tenant_and_ci_class_boundaries_fail_closed(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username='admin').one()
        ci = ConfigurationItem(name='Hidden DB', ci_class='Database', tenant_id=1)
        service = ServiceOffering(name='Restricted service', owner_id=admin.id, tenant_id=1)
        other = Tenant(name='Foreign tenant', slug='foreign-impact')
        db.session.add_all([ci, service, other]); db.session.flush()
        foreign_ci = ConfigurationItem(name='Foreign CI', ci_class='Server', tenant_id=other.id)
        foreign_service = ServiceOffering(name='Foreign service', owner_id=admin.id, tenant_id=other.id)
        db.session.add_all([foreign_ci, foreign_service]); db.session.flush()
        db.session.add_all([
            ServiceOfferingCI(service_offering_id=service.id, ci_id=ci.id, tenant_id=1),
            ServiceOfferingCI(service_offering_id=foreign_service.id, ci_id=ci.id, tenant_id=1),
            ServiceOfferingCI(service_offering_id=service.id, ci_id=foreign_ci.id, tenant_id=1),
            CiClassPermission(tenant_id=1, ci_class='Database', role='manager', can_read=True),
        ])
        db.session.commit(); ci_id, foreign_id = ci.id, foreign_ci.id
    # Create the change with an unrestricted class, then exercise denied classes on reads.
    tid, number = create_change(client, app, [])
    with app.app_context():
        gov = ChangeGovernance.query.filter_by(ticket_id=tid).one(); gov.ci_id = ci_id
        db.session.add(TaskCI(target_type='ticket', target_id=tid, ci_id=foreign_id, relationship_role='Affected CI'))
        db.session.commit()
        ticket = db.session.get(Ticket, tid)
        assert impacted_services(ticket, User.query.filter_by(username='employee').one()) == []
        assert impacted_services(ticket, User.query.filter_by(username='admin').one()) == []
        assert [s['name'] for s in impacted_services(ticket, User.query.filter_by(username='database.manager').one())] == ['Restricted service']
        assert all(ci['id'] == ci_id for s in impacted_services(ticket, User.query.filter_by(username='database.manager').one()) for ci in s['configuration_items'])
    response = client.get(f'/api/v1/tickets/{number}/details', headers=bearer(app))
    assert response.status_code == 200 and response.json['data']['impacted_services'] == []


def test_impact_query_failure_is_visible(app, monkeypatch):
    from types import SimpleNamespace
    from werkzeug.exceptions import ServiceUnavailable
    class FailingQuery:
        def filter_by(self, **kwargs):
            raise RuntimeError('unavailable')
    with app.app_context():
        monkeypatch.setattr(TaskCI, 'query', FailingQuery())
        with pytest.raises(ServiceUnavailable):
            impacted_services(SimpleNamespace(kind='change', id=1, tenant_id=1), SimpleNamespace(tenant_id=1))


def test_requester_and_foreign_identity_receive_no_service_topology(client, app):
    from types import SimpleNamespace
    login(client)
    tid, number = create_change(client, app, [])
    with app.app_context():
        employee = User.query.filter_by(username='employee').one()
        ticket = db.session.get(Ticket, tid)
        ticket.requester_id = employee.id
        ci = ConfigurationItem(name='Private infrastructure', ci_class='Server', tenant_id=1)
        service = ServiceOffering(name='Private business service', owner_id=employee.id, tenant_id=1)
        db.session.add_all([ci, service]); db.session.flush()
        ticket.change_governance.ci_id = ci.id
        db.session.add(ServiceOfferingCI(service_offering_id=service.id, ci_id=ci.id, tenant_id=1))
        db.session.commit()
        assert impacted_services(ticket, SimpleNamespace(tenant_id=999, effective_role='superadmin')) == []
    response = client.get(f'/api/v1/tickets/{number}/details', headers=bearer(app, 'employee'))
    assert response.status_code == 200
    assert response.json['data']['impacted_services'] == []
    assert 'Private business service' not in response.get_data(as_text=True)
    assert 'Private infrastructure' not in response.get_data(as_text=True)
