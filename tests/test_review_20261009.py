from datetime import date, timedelta
from tests.test_app import app, client, login
import pytest
from app import GroupMember, SupportGroup, Tenant, Audit
from app import db, Supplier, Contract, User, Notification
from serviceops_core.itam.alerts import send_contract_alerts

def test_existing_supplier_is_preserved_when_outside_options(client, app):
    login(client)
    with app.app_context():
        db.session.add_all([Supplier(name=f'A{i:04}', tenant_id=1) for i in range(500)])
        supplier = Supplier(name='ZZ retained supplier', tenant_id=1)
        db.session.add(supplier)
        db.session.flush()
        contract = Contract(name='Original', tenant_id=1, supplier_id=supplier.id, active=True)
        db.session.add(contract)
        db.session.commit()
        cid, sid = contract.id, supplier.id
    page = client.get(f'/itam/contracts/{cid}').get_data(as_text=True)
    assert 'ZZ retained supplier' in page
    assert client.post(f'/itam/contracts/{cid}', data={'name':'Renamed', 'supplier_id':str(sid), 'active':'on'}).status_code == 302
    with app.app_context():
        assert db.session.get(Contract, cid).supplier_id == sid

def test_status_filter_can_find_record_beyond_first_500(client, app):
    login(client)
    today = date.today()
    with app.app_context():
        db.session.add_all([Contract(name=f'Expired {i}', tenant_id=1, active=True, end_date=today-timedelta(days=1)) for i in range(500)])
        db.session.add(Contract(name='Find active contract', tenant_id=1, active=True, end_date=today+timedelta(days=365)))
        db.session.commit()
    page = client.get('/itam/contracts?status=Active').get_data(as_text=True)
    assert 'Find active contract' in page

def test_undelivered_alert_is_retried_when_recipient_returns(app):
    with app.app_context():
        admins = User.query.filter(User.role.in_(['admin','superadmin'])).all()
        for user in admins:
            user.active = False
        contract = Contract(name='Retry notice', tenant_id=1, active=True, end_date=date.today()+timedelta(days=1), notice_days=30)
        db.session.add(contract)
        db.session.commit()
        send_contract_alerts()
        assert Notification.query.filter_by(target_type='contract', target_id=contract.id).count() == 0
        for user in admins:
            user.active = True
        db.session.commit()
        send_contract_alerts()
        assert Notification.query.filter_by(target_type='contract', target_id=contract.id).count() > 0


def test_ccb_picker_and_same_page_save_without_referrer(client, app):
    login(client)
    with app.app_context():
        uid = User.query.filter_by(username='admin').one().id
    page = client.get('/service-operations/settings/ccb').get_data(as_text=True)
    assert 'data-approval-users="ccb"' in page
    assert '<th>User</th>' not in page
    response = client.post('/service-operations/settings', data={
        'action':'set_ccb_authority', 'user_id':uid, 'enabled':'true', 'return_section':'ccb'}, follow_redirects=True)
    assert response.status_code == 200
    assert response.request.path.endswith('/settings/ccb')
    assert 'CCB approval authority updated.' in response.get_data(as_text=True)
    with app.app_context():
        ccb = SupportGroup.query.filter_by(name='Change Control Board').one()
        assert GroupMember.query.filter_by(group_id=ccb.id, user_id=uid, role='CCB approver').count() == 1


def test_group_add_returns_to_open_panel(client, app):
    login(client)
    with app.app_context():
        gid = SupportGroup.query.filter_by(name='Unix').one().id
        uid = User.query.filter_by(username='employee').one().id
    response = client.post('/service-operations/settings', data={
        'action':'add_group_member', 'group_id':gid, 'user_id':uid,
        'return_section':'governance-groups', 'return_panel':f'group-{gid}'}, follow_redirects=True)
    assert response.status_code == 200
    assert response.request.path.endswith('/settings/governance-groups')
    assert response.request.args['group'] == str(gid)
    assert f'id="group-{gid}" class="panel admin-section u-mb-14" open' in response.get_data(as_text=True)
    assert 'added to Unix.' in response.get_data(as_text=True)


def test_executive_incremental_changes_preserve_other_users_and_mode(client, app):
    login(client)
    with app.app_context():
        ids = [u.id for u in User.query.filter(User.username.in_(['admin','employee'])).all()]
    for uid in ids:
        assert client.post('/service-operations/settings', data={
            'action':'set_executive_authority', 'user_id':uid, 'enabled':'true',
            'return_section':'executive-approval'}).status_code == 303
    assert client.post('/service-operations/settings', data={
        'action':'set_executive_mode', 'approval_mode':'any', 'return_section':'executive-approval'}).status_code == 303
    assert client.post('/service-operations/settings', data={
        'action':'set_executive_authority', 'user_id':ids[0], 'enabled':'false',
        'return_section':'executive-approval'}).status_code == 303
    with app.app_context():
        office = SupportGroup.query.filter_by(name='Executive Office').one()
        assert office.approval_mode == 'any'
        assert {m.user_id for m in office.members if m.role=='executive approver'} == {ids[1]}
    page = client.get('/service-operations/settings/executive-approval').get_data(as_text=True)
    assert 'name="user_ids"' not in page
    assert 'data-approval-users="executive"' in page


@pytest.mark.parametrize('authority', ['ccb','executive'])
@pytest.mark.parametrize('uid', ['invalid', '9'*5000])
def test_bad_authority_identifier_rejected(client, authority, uid):
    login(client)
    assert client.post('/service-operations/settings', data={
        'action':f'set_{authority}_authority', 'user_id':uid, 'enabled':'true'}).status_code == 400


@pytest.mark.parametrize('authority', ['ccb','executive'])
def test_foreign_authority_user_rejected(client, app, authority):
    login(client)
    with app.app_context():
        tenant = Tenant(name='Foreign', slug='foreign-review')
        db.session.add(tenant); db.session.flush()
        user = User(username='foreign-review', name='Foreign', email='foreign@example.invalid',
                    password_hash='unused-test-hash', tenant_id=tenant.id, role='manager', active=True)
        db.session.add(user); db.session.commit(); uid=user.id
    assert client.post('/service-operations/settings', data={
        'action':f'set_{authority}_authority', 'user_id':uid, 'enabled':'true'}).status_code == 404


def test_incremental_executive_assignment_keeps_existing_limit(client, app):
    login(client)
    with app.app_context():
        executive = SupportGroup.query.filter_by(name='Executive Office').one()
        existing = {m.user_id for m in executive.members if m.role in {'manager', 'executive approver'}}
        if executive.manager_id:
            existing.add(executive.manager_id)
        for i in range(100-len(existing)):
            user = User(username=f'exec-limit-{i}', name=f'Executive {i}', email=f'exec-{i}@example.invalid',
                        password_hash='unused-test-hash', tenant_id=1, role='manager', active=True)
            db.session.add(user); db.session.flush()
            db.session.add(GroupMember(group_id=executive.id,user_id=user.id,role='executive approver',tenant_id=1))
        db.session.commit()
        uid = User.query.filter_by(username='employee').one().id
        executive_id = executive.id
    assert client.post('/service-operations/settings',data={
        'action':'set_executive_authority','user_id':uid,'enabled':'true'}).status_code == 400
    with app.app_context():
        assert not GroupMember.query.filter_by(group_id=executive_id,user_id=uid,role='executive approver').first()
