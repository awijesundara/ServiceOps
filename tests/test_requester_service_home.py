"""Real requester routes: health privacy, compact states and catalog navigation."""
from unittest.mock import patch
import pytest
from sqlalchemy.exc import SQLAlchemyError
from app import (CatalogItem, ServiceOffering, ServiceOutage,
                 Tenant, Ticket, User, db, now)
from tests.test_app import app, client, login  # noqa: F401


def test_published_health_and_catalog_links(client, app):
    with app.app_context():
        db.session.add(Tenant(id=2, name='Other', slug='other'))
        for name, status, visible, tenant in [('Healthy email','Operational',True,1),
                ('VPN degraded','Degraded',True,1),('Private service','Down',False,1),
                ('Other tenant service','Down',True,2)]:
            db.session.add(ServiceOffering(name=name,status=status,status_page_visible=visible,tenant_id=tenant))
        db.session.add(CatalogItem(name='VPN access',category='Access',description='Request VPN',tenant_id=1))
        db.session.add(CatalogItem(name='Hidden catalog item',category='Access',description='Private',active=False,tenant_id=1))
        db.session.add(CatalogItem(name='Other catalog item',category='Access',description='Private',tenant_id=2))
        db.session.commit()
    login(client,'employee','Employee123!')
    response=client.get('/'); assert response.status_code==200
    html=response.get_data(as_text=True)
    assert '1 service affected' in html and 'VPN degraded' in html
    assert 'Healthy email' not in html and 'Private service' not in html and 'Other tenant service' not in html
    for label in ('Get help','Request something','Find an answer'):
        assert label in html
    assert 'Hidden catalog item' not in html and 'Other catalog item' not in html
    category=client.get('/catalog?category=Access').get_data(as_text=True)
    assert 'VPN access' in category and 'Hidden catalog item' not in category
    assert 'Laptop' not in category
    assert 'No services are available in this category.' in client.get('/catalog?category=Missing').get_data(as_text=True)


def test_health_empty_healthy_outage_and_limit(client, app):
    login(client,'employee','Employee123!')
    assert b'portal-service-status' not in client.get('/').data  # nothing to report: no status bar
    with app.app_context():
        service=ServiceOffering(name='Published email',tenant_id=1,status_page_visible=True)
        db.session.add(service);db.session.commit()
    html=client.get('/').get_data(as_text=True)
    assert 'portal-service-status' not in html and 'All services operational' not in html
    with app.app_context():
        user=User.query.filter_by(username='employee').one()
        ticket=Ticket(number='INC990001',kind='incident',title='Outage',description='Down',category='Software',
                      state='Open',priority='P1',requester_id=user.id,tenant_id=1)
        db.session.add(ticket);db.session.flush()
        service=ServiceOffering.query.filter_by(name='Published email').one()
        db.session.add(ServiceOutage(service_offering_id=service.id,ticket_id=ticket.id,started_at=now(),tenant_id=1))
        for i in range(4):db.session.add(ServiceOffering(name=f'Degraded {i}',status='Degraded',tenant_id=1,status_page_visible=True))
        db.session.commit()
    html=client.get('/').get_data(as_text=True)
    assert '5 services affected' in html and html.count('class="portal-status-row"')==3
    assert html.index('Published email')<html.index('Degraded 0')
    assert 'Outage' in client.get('/status/default').get_data(as_text=True)


def test_optional_overview_failure_is_not_healthy(client, app):
    login(client,'employee','Employee123!')
    with patch('serviceops_core.web.workspace.published_service_health',side_effect=SQLAlchemyError('test unavailable')):
        response=client.get('/')
    assert response.status_code==200 and b'Service status is temporarily unavailable' in response.data
    assert b'All services operational' not in response.data and b'My open incidents' in response.data


def test_removed_home_clutter_and_authenticated_details(client):
    assert client.get('/service-status').status_code==302
    login(client,'employee','Employee123!')
    html=client.get('/').get_data(as_text=True)
    assert 'Popular services' not in html and 'Get access' not in html
    assert html.count('class="requester-action"')==3
    page=client.get('/service-status')
    assert page.status_code==200 and b'Freezes and planned work' in page.data


@pytest.mark.parametrize('role', ['requester', 'agent', 'manager', 'admin', 'superadmin'])
def test_all_employee_roles_share_services_without_switching(client, app, role):
    with app.app_context():
        user=User.query.filter_by(username='employee').one()
        user.role=role
        db.session.add(ServiceOffering(name='Staff VPN',tenant_id=1,status='Degraded',status_page_visible=True))
        db.session.commit()
    login(client,'employee','Employee123!')
    html=client.get('/').get_data(as_text=True)
    for label in ('Get help','Request something','Find an answer','Service status'):
        assert label in html
    assert html.count('class="requester-action"')==3
    assert 'Report an issue' not in html and 'Report an incident' not in html
    assert 'Staff VPN' in html
    assert ('Assigned to me' in html)==(role!='requester')
    with app.app_context():
        assert User.query.filter_by(username='employee').one().role==role
