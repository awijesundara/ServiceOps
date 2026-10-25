"""Service offering administration through the web form."""
import pytest
from app import Audit, ServiceOffering, SupportGroup, Tenant, User, db
from tests.test_app import app, client, login

PATH = "/service-operations/settings"
PAGE = PATH + "/service-offerings"


def form(app, **overrides):
    with app.app_context():
        team = SupportGroup.query.filter_by(name="Unix", tenant_id=1).one()
        values = dict(action="create_service_offering", name="Payments", support_group_id=str(team.id),
                      criticality="High", return_section="service-offerings")
    values.update(overrides)
    return values


def test_create_service_and_linking_page(client, app):
    login(client)
    page = client.get(PAGE)
    assert page.status_code == 200
    assert b'name="action" value="create_service_offering"' in page.data
    assert b'name="owner_id"' not in page.data
    assert b"Owning team" in page.data
    with app.app_context():
        group = SupportGroup.query.filter_by(tenant_id=1).first()
        group_id = group.id
    response = client.post(PATH, data=form(app, support_group_id=str(group_id)))
    assert response.status_code == 303
    assert PAGE + "?service=" in response.location
    page = client.get(response.location)
    assert b"Payments" in page.data and b"Service Payments saved." in page.data
    with app.app_context():
        service = ServiceOffering.query.filter_by(name="Payments").one()
        assert service.tenant_id == 1 and service.status == "Operational"
        assert service.owner_id is None
        assert service.criticality == "High" and service.support_group_id == group_id
        assert Audit.query.filter_by(action="create", target="Service offering: Payments").count() == 1


@pytest.mark.parametrize("overrides,status", [
    ({"name": "  "}, 400), ({"name": "x" * 161}, 400),
    ({"criticality": "invalid"}, 400), ({"support_group_id": ""}, 400),
    ({"support_group_id": "invalid"}, 400), ({"support_group_id": "999999"}, 404),
])
def test_invalid_service_is_not_saved(client, app, overrides, status):
    login(client)
    response = client.post(PATH, data=form(app, **overrides))
    assert response.status_code == status
    with app.app_context():
        assert ServiceOffering.query.count() == 0


def test_duplicate_and_inactive_team(client, app):
    login(client)
    assert client.post(PATH, data=form(app)).status_code == 303
    assert client.post(PATH, data=form(app, name=" payments ")).status_code == 409
    with app.app_context():
        team = SupportGroup.query.filter_by(name="Unix", tenant_id=1).one()
        team.active = False
        team_id = team.id
        db.session.commit()
    assert client.post(PATH, data=form(app, name="Other", support_group_id=str(team_id))).status_code == 400


def test_tenant_references_and_same_name(client, app):
    login(client)
    with app.app_context():
        tenant = Tenant(name="Other organization", slug="other-org")
        db.session.add(tenant)
        db.session.flush()
        owner = User(username="other.owner", name="Other owner", email="other@example.invalid",
                     password_hash="unused", tenant_id=tenant.id)
        group = SupportGroup(name="Other team", tenant_id=tenant.id)
        db.session.add_all([owner, group])
        db.session.flush()
        db.session.add(ServiceOffering(name="Payments", owner_id=owner.id, tenant_id=tenant.id))
        owner_id, group_id = owner.id, group.id
        db.session.commit()
    assert client.post(PATH, data=form(app, support_group_id=str(group_id))).status_code == 404
    assert client.post(PATH, data=form(app, owner_id=str(owner_id))).status_code == 303
    with app.app_context():
        assert ServiceOffering.query.filter_by(name="Payments").count() == 2
        assert ServiceOffering.query.filter_by(name="Payments", tenant_id=1).one().owner_id is None


def test_requester_cannot_create(client, app):
    login(client, "employee", "Employee123!")
    assert client.get(PAGE).status_code == 403
    assert client.post(PATH, data=form(app)).status_code == 403


def test_creation_requires_csrf(client, app):
    login(client)
    app.config["CSRF_ENABLED"] = True
    assert client.post(PATH, data=form(app)).status_code == 400


@pytest.mark.parametrize("error_type,expected", [("integrity", 409), ("database", 503)])
def test_failed_save_rolls_back_without_audit_or_service(client, app, monkeypatch, error_type, expected):
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    login(client)
    data = form(app)
    original_commit = db.session.commit
    def fail_commit():
        if error_type == "integrity":
            raise IntegrityError("insert", {}, Exception("constraint"))
        raise SQLAlchemyError("unavailable")
    monkeypatch.setattr(db.session, "commit", fail_commit)
    response = client.post(PATH, data=data)
    monkeypatch.setattr(db.session, "commit", original_commit)
    assert response.status_code == expected
    with app.app_context():
        assert ServiceOffering.query.filter_by(name="Payments").count() == 0
        assert Audit.query.filter_by(action="create", target="Service offering: Payments").count() == 0


def test_create_with_cis_is_atomic_and_deduplicated(client, app):
    from app import ConfigurationItem, ServiceOfferingCI
    from werkzeug.datastructures import MultiDict
    login(client)
    with app.app_context():
        ci = ConfigurationItem(name='Payments DB', ci_class='Database', tenant_id=1)
        db.session.add(ci); db.session.commit(); ci_id = ci.id
    invalid = form(app, ci_id='999999')
    assert client.post(PATH, data=invalid).status_code == 404
    with app.app_context():
        assert ServiceOffering.query.count() == 0
    data = MultiDict(form(app)); data.add('ci_id', str(ci_id)); data.add('ci_id', str(ci_id))
    response = client.post(PATH, data=data)
    assert response.status_code == 303
    with app.app_context():
        service = ServiceOffering.query.one()
        assert ServiceOfferingCI.query.filter_by(service_offering_id=service.id).count() == 1
        assert service.ci_links[0].relationship_role == 'Supporting'
        assert response.location.endswith(f'?service={service.id}#service-{service.id}')


def test_edit_preserves_links_and_role_save_restores_editor(client, app):
    from app import ConfigurationItem, ServiceOfferingCI
    login(client)
    assert client.post(PATH, data=form(app)).status_code == 303
    with app.app_context():
        service = ServiceOffering.query.one(); service_id = service.id
        ci = ConfigurationItem(name='Persistent CI', ci_class='Server', tenant_id=1)
        db.session.add(ci); db.session.flush()
        link = ServiceOfferingCI(service_offering_id=service_id, ci_id=ci.id, tenant_id=1)
        db.session.add(link); db.session.commit(); link_id = link.id
    response = client.post(PATH, data=form(app, action='update_service_offering', service_offering_id=str(service_id), name='Payments revised', criticality='Critical'))
    assert response.status_code == 303
    page = client.get(response.location).get_data(as_text=True)
    assert f'id="service-{service_id}" open' in page
    with app.app_context():
        service = db.session.get(ServiceOffering, service_id)
        assert service.name == 'Payments revised' and service.criticality == 'Critical'
        assert len(service.ci_links) == 1
    response = client.post(PATH, data={'action': 'update_service_ci_role', 'link_id': str(link_id), 'relationship_role': 'Primary', 'return_section': 'service-offerings', 'return_panel': f'service-{service_id}'})
    assert response.location.endswith(f'?service={service_id}#service-{service_id}')
    with app.app_context():
        assert db.session.get(ServiceOfferingCI, link_id).relationship_role == 'Primary'
    assert client.post(PATH, data={'action':'update_service_ci_role','link_id':str(link_id),'relationship_role':'Invalid'}).status_code == 400
    assert b'Payments revised' in client.get(PAGE+'?q=revised').data
    assert b'Payments revised' not in client.get(PAGE+'?q=missing').data


def test_foreign_edit_and_ci_selection_are_rejected(client, app):
    from app import ConfigurationItem, ServiceOfferingCI
    login(client)
    with app.app_context():
        tenant = Tenant(name='Foreign edit', slug='foreign-edit'); db.session.add(tenant); db.session.flush()
        admin = User.query.filter_by(username='admin').one()
        ci = ConfigurationItem(name='Foreign ci', ci_class='Server', tenant_id=tenant.id)
        service = ServiceOffering(name='Foreign service', owner_id=admin.id, tenant_id=tenant.id)
        db.session.add_all([ci, service]); db.session.flush()
        link = ServiceOfferingCI(service_offering_id=service.id, ci_id=ci.id, tenant_id=tenant.id)
        db.session.add(link); db.session.commit(); ci_id, service_id, link_id = ci.id, service.id, link.id
    assert client.post(PATH, data=form(app, ci_id=str(ci_id))).status_code == 404
    assert client.post(PATH, data=form(app, action='update_service_offering', service_offering_id=str(service_id))).status_code == 404
    assert client.post(PATH, data={'action':'update_service_ci_role','link_id':str(link_id),'relationship_role':'Primary'}).status_code == 404


def test_full_length_service_name_fits_audit_target(client, app):
    import json
    login(client)
    name = 'S' * 160
    assert client.post(PATH, data=form(app, name=name)).status_code == 303
    with app.app_context():
        service = ServiceOffering.query.filter_by(name=name).one()
        entry = Audit.query.filter_by(action='create').order_by(Audit.id.desc()).first()
        assert len(entry.target) <= Audit.__table__.c.target.type.length
        assert json.loads(entry.details)['after']['name'] == service.name


def test_historical_person_is_preserved_without_requiring_person_assignment(client, app):
    login(client)
    with app.app_context():
        owner = User.query.filter_by(username='admin').one()
        service = ServiceOffering(name='Legacy', owner_id=owner.id, tenant_id=1)
        db.session.add(service); db.session.commit(); service_id, owner_id = service.id, owner.id
    assert client.post(PATH, data=form(app, action='update_service_offering', service_offering_id=str(service_id), name='Legacy revised')).status_code == 303
    with app.app_context():
        service = db.session.get(ServiceOffering, service_id)
        assert service.owner_id == owner_id
        assert service.support_group.name == 'Unix'


def test_approval_group_cannot_be_selected_as_owning_team(client, app):
    login(client)
    with app.app_context():
        group_id = SupportGroup.query.filter_by(name='Change Control Board', tenant_id=1).one().id
    assert client.post(PATH, data=form(app, support_group_id=str(group_id))).status_code == 400
