"""Employee notices: tenant privacy, real downtime, approved work and pagination."""
from datetime import timedelta
from unittest.mock import patch
import re
from sqlalchemy.exc import SQLAlchemyError
from app import (ChangeFreezeWindow, ChangeGovernance, ConfigurationItem, ServiceOffering,
                 ServiceOfferingCI, TaskCI, Tenant, Ticket, User, db, now)
from tests.test_app import app, client, login  # noqa: F401


def test_freeze_scope_horizon_and_public_separation(client, app):
    with app.app_context():
        db.session.add(Tenant(id=2,name='Other organization',slug='other'))
        for title,start,end,tenant in [('Active tenant freeze',-1,1,1),('Upcoming freeze',2,3,1),
                ('Expired freeze',-3,-2,1),('Far future freeze',30,31,1),('Other tenant freeze',1,2,2)]:
            db.session.add(ChangeFreezeWindow(title=title,starts_at=now()+timedelta(days=start),
                ends_at=now()+timedelta(days=end),tenant_id=tenant))
        db.session.commit()
    login(client,'employee','Employee123!')
    html=client.get('/').get_data(as_text=True)
    assert '1 / 2' in html and 'Active tenant freeze' in html and 'Upcoming freeze' in html
    assert 'Expired freeze' not in html and 'Far future freeze' not in html and 'Other tenant freeze' not in html
    assert html.index('Active tenant freeze')<html.index('Upcoming freeze')
    assert 'data-service-feed' in html and ' hidden>' in html
    assert b'Upcoming freeze' not in client.get('/status/default').data
    page=client.get('/service-status').get_data(as_text=True)
    assert 'Active window' in page and 'Next 14 days' in page
    assert 'Other tenant freeze' not in page


def test_planned_work_requires_approved_visible_change_and_published_readable_service(client, app):
    with app.app_context():
        admin=User.query.filter_by(username='admin').one()
        primary=ConfigurationItem(name='internal-ci-secret',ci_class='Server',tenant_id=1)
        additional=ConfigurationItem(name='additional-ci-secret',ci_class='Server',tenant_id=1)
        public=ServiceOffering(name='Published payroll',tenant_id=1,status_page_visible=True)
        private=ServiceOffering(name='Private payroll backend',tenant_id=1,status_page_visible=False)
        db.session.add_all([primary,additional,public,private]);db.session.flush()
        for service,ci in ((public,primary),(public,additional),(private,primary)):
            db.session.add(ServiceOfferingCI(service_offering_id=service.id,ci_id=ci.id,tenant_id=1))
        for i,(state,offset,deleted) in enumerate([('Approved',1,False),('In Progress',-1,False),
                ('New',1,False),('Awaiting Approval',1,False),('Closed',1,False),
                ('Approved',30,False),('Approved',1,True)]):
            ticket=Ticket(number=f'CHG99000{i}',kind='change',title=f'Internal change {i}',description='Internal plans',
                category='Software',state=state,priority='P3',requester_id=admin.id,tenant_id=1,
                deleted_at=now() if deleted else None)
            db.session.add(ticket);db.session.flush()
            db.session.add(ChangeGovernance(ticket_id=ticket.id,ci_id=primary.id,tenant_id=1,
                planned_start=now()+timedelta(days=offset),planned_end=now()+timedelta(days=offset+2)))
            db.session.add(TaskCI(target_type='ticket',target_id=ticket.id,ci_id=additional.id,relationship_role='Affected CI'))
        db.session.commit()
    login(client)
    home=client.get('/').get_data(as_text=True)
    assert '1 / 2' in home and 'Published payroll' in home
    page=client.get('/service-status').get_data(as_text=True)
    assert page.count('class="service-notice-row"')==2
    assert 'CHG990000' in page and 'CHG990001' in page
    assert 'Potential service impact; downtime is not confirmed.' in page
    for hidden in ('CHG990002','CHG990003','CHG990004','CHG990005','CHG990006',
                   'Private payroll backend','internal-ci-secret','additional-ci-secret'):
        assert hidden not in page
    client.post('/logout');login(client,'employee','Employee123!')
    page=client.get('/service-status').get_data(as_text=True)
    assert 'CHG990000' not in page and 'CHG990001' not in page


def test_notices_paginate_and_home_stays_compact(client, app):
    with app.app_context():
        for i in range(25):
            db.session.add(ChangeFreezeWindow(title=f'Freeze {i:02d}',starts_at=now()+timedelta(hours=i+1),
                ends_at=now()+timedelta(hours=i+2),tenant_id=1))
        db.session.commit()
    login(client)
    home=client.get('/').get_data(as_text=True)
    assert home.count('class="service-headline"')==20
    assert len(re.findall(r'data-service-feed-item[^>]*\bhidden>', home))==19
    first=client.get('/service-status').get_data(as_text=True)
    second=client.get('/service-status?page=2').get_data(as_text=True)
    assert first.count('class="service-notice-row"')==20 and 'Page 1 of 2' in first
    assert second.count('class="service-notice-row"')==5 and 'Page 2 of 2' in second
    assert 'Freeze 00' in first and 'Freeze 00' not in second and 'Freeze 24' in second
    assert b'Page 2 of 2' in client.get('/service-status?page=999999999999999999').data
    assert b'Page 1 of 2' in client.get('/service-status?page=invalid').data
    assert b'Page 1 of 2' in client.get('/service-status?page=-1').data


def test_notice_failure_is_explicit_and_does_not_hide_current_health(client):
    login(client)
    with patch('serviceops_core.web.workspace.employee_service_notices',side_effect=SQLAlchemyError('test unavailable')):
        page=client.get('/')
    assert page.status_code==200
    assert b'Planned service notices are temporarily unavailable' in page.data
    assert b'No services published yet' in page.data


def test_single_notice_is_static_and_has_detail_fallback(client, app):
    with app.app_context():
        db.session.add(ChangeFreezeWindow(title='Only one notice',starts_at=now()+timedelta(days=1),
            ends_at=now()+timedelta(days=2),tenant_id=1))
        db.session.commit()
    login(client)
    page=client.get('/').get_data(as_text=True)
    assert 'Only one notice' in page and 'data-service-feed-item' in page
    assert 'data-service-feed-controls' not in page
    assert 'href="/service-status"' in page


def test_empty_updates_strip_is_omitted_for_employee_and_admin(client, app):
    with app.app_context():
        db.session.add(ServiceOffering(name='Healthy email',status='Operational',status_page_visible=True,tenant_id=1))
        db.session.add(ChangeFreezeWindow(title='Expired update',starts_at=now()-timedelta(days=2),ends_at=now()-timedelta(days=1),tenant_id=1))
        db.session.commit()
    for username,password in [('employee','Employee123!'),('admin','Admin123!')]:
        with client.session_transaction() as session:
            session.clear()
        login(client,username,password)
        html=client.get('/').get_data(as_text=True)
        assert 'class="portal-service-status"' not in html
        assert 'class="service-feed"' not in html
        assert 'class="service-feed-label"' not in html
        assert 'data-service-feed-controls' not in html
        assert 'Expired update' not in html
