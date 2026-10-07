"""Route-level regressions for financial input and new administration paths."""
from datetime import date

import pytest
from werkzeug.security import generate_password_hash

from app import CiClassPermission, ConfigurationItem, Contract, MonitoringSource, PlatformSetting, SupportGroup, User, db
from serviceops_core.itam.definitions import contract_status
from tests.test_app import app, client, login  # noqa: F401


@pytest.mark.parametrize("cost", ["NaN", "sNaN", "Infinity", "-Infinity", "999999999999.999", "-0.001", "1" * 5000])
def test_contract_nonfinite_amounts_are_validation_errors(client, app, cost):
    login(client)
    response = client.post('/itam/contracts/new', data={'name': 'Invalid amount', 'cost': cost})
    assert response.status_code == 400
    with app.app_context():
        assert Contract.query.filter_by(name='Invalid amount').count() == 0


@pytest.mark.parametrize("field", ['supplier_id', 'owner_id', 'cis'])
@pytest.mark.parametrize("value", ['²', 'not-an-id', '9' * 5000])
def test_contract_malformed_reference_is_atomic_validation_error(client, app, field, value):
    login(client)
    response = client.post('/itam/contracts/new', data={'name': 'Invalid reference', field: value})
    assert response.status_code == 400
    with app.app_context():
        assert Contract.query.filter_by(name='Invalid reference').count() == 0


@pytest.mark.parametrize('group_id', ['invalid', '²', '9' * 5000])
def test_recovery_setup_bad_group_does_not_create_credentials(client, app, group_id):
    login(client)
    response = client.post('/admin/system-health/recovery-setup', data={'group_id': group_id, 'rpo_hours': '24'})
    assert response.status_code == 400
    with app.app_context():
        assert MonitoringSource.query.filter_by(name='Backup reporter').count() == 0


def test_contract_status_handles_earliest_supported_date():
    contract = Contract(name='Historic', active=True, end_date=date.min, notice_days=3650)
    assert contract_status(contract, date.min)[0] == 'Notice period'


def test_contract_cis_follow_cmdb_read_policy(client, app):
    with app.app_context():
        manager = User(username='contract-manager', name='Contract manager', email='cm@example.invalid',
                       tenant_id=1, role='manager', password_hash=generate_password_hash('Manager123!'))
        secret = ConfigurationItem(name='RESTRICTED-CI-NAME', ci_class='Server', tenant_id=1)
        db.session.add_all([manager, secret, CiClassPermission(tenant_id=1, ci_class='Server', role='manager', can_read=False)])
        db.session.flush()
        contract = Contract(name='Shared contract', tenant_id=1, active=True, cis=[secret])
        db.session.add(contract)
        db.session.commit()
        contract_id, secret_id = contract.id, secret.id
    login(client, 'contract-manager', 'Manager123!')
    for path in ['/itam/contracts/new', f'/itam/contracts/{contract_id}']:
        response = client.get(path)
        assert response.status_code == 200
        assert 'RESTRICTED-CI-NAME' not in response.get_data(as_text=True)
    response = client.post('/itam/contracts/new', data={'name': 'Forbidden CI', 'cis': str(secret_id)})
    assert response.status_code == 400
    with app.app_context():
        assert Contract.query.filter_by(name='Forbidden CI').count() == 0
    assert client.post(f'/itam/contracts/{contract_id}', data={'name': 'Renamed contract'}).status_code == 302
    with app.app_context():
        contract = db.session.get(Contract, contract_id)
        assert contract.name == 'Renamed contract'
        assert [ci.id for ci in contract.cis] == [secret_id]


def test_recovery_encryption_failure_preserves_existing_credential(client, app, monkeypatch):
    from serviceops_core.web import administration

    login(client)
    with app.app_context():
        team_id = SupportGroup.query.filter_by(name='Unix').one().id
    data = {'group_id': team_id, 'rpo_hours': '24'}
    assert client.post('/admin/system-health/recovery-setup', data=data).status_code == 302
    with app.app_context():
        original_id = MonitoringSource.query.filter_by(name='Backup reporter', active=True).one().id
        original_rpo = db.session.get(PlatformSetting, 'BACKUP_RPO_HOURS').value

    def unavailable_cipher():
        raise RuntimeError('Synthetic encryption outage')

    monkeypatch.setattr(administration, 'settings_cipher', unavailable_cipher)
    response = client.post('/admin/system-health/recovery-setup', data=dict(data, rpo_hours='12'))
    assert response.status_code == 503
    with app.app_context():
        assert MonitoringSource.query.filter_by(name='Backup reporter', active=True).one().id == original_id
        assert MonitoringSource.query.filter_by(name='Backup reporter').count() == 1
        assert db.session.get(PlatformSetting, 'BACKUP_RPO_HOURS').value == original_rpo
