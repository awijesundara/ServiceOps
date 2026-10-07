"""GLPI-style suppliers and contracts: create/edit/delete, CI links, status,
renewal alerts, permissions and tenant isolation."""
from datetime import date, timedelta

from werkzeug.security import generate_password_hash

from app import (Audit, ConfigurationItem, Contract, Notification, Supplier, Tenant, User, db)
from serviceops_core.itam.alerts import send_contract_alerts
from serviceops_core.itam.definitions import contract_status
from test_app import app, client, login  # noqa: F401 - pytest fixtures


def new_supplier(client, name="Dell Japan", **extra):
    data = {"name": name, "supplier_type": "Vendor", "email": "sales@dell.example", "active": "on"}
    data.update(extra)
    return client.post("/itam/suppliers/new", data=data)


def test_admin_creates_supplier_and_contract_covering_cis(client, app):
    login(client)
    assert new_supplier(client).status_code == 302
    with app.app_context():
        supplier_id = Supplier.query.filter_by(name="Dell Japan").one().id
        ci = ConfigurationItem(name="db01", ci_class="Server", tenant_id=1)
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    response = client.post("/itam/contracts/new", data={
        "name": "Server support 2026", "number": "DJ-001", "contract_type": "Support",
        "supplier_id": supplier_id, "start_date": "2026-01-01", "end_date": "2026-12-31",
        "notice_days": "60", "renewal": "tacit", "cost": "1,200,000", "currency": "JPY",
        "billing_period": "yearly", "cis": [ci_id], "active": "on",
    })
    assert response.status_code == 302
    with app.app_context():
        contract = Contract.query.filter_by(name="Server support 2026").one()
        assert contract.supplier_id == supplier_id and str(contract.cost) == "1200000.00"
        assert [c.id for c in contract.cis] == [ci_id]
        assert Audit.query.filter_by(action="create", target="Contract: Server support 2026").one()
        contract_id = contract.id
    # Saving stays on the record; the CI page lists the contract.
    assert response.headers["Location"].endswith(f"/itam/contracts/{contract_id}")
    assert "Server support 2026" in client.get(f"/cmdb/{ci_id}/edit").get_data(as_text=True)
    page = client.get("/itam/contracts").get_data(as_text=True)
    assert "Server support 2026" in page and "Dell Japan" in page


def test_validation_errors_are_shown_and_nothing_is_saved(client, app):
    login(client)
    response = client.post("/itam/contracts/new", data={
        "name": "Bad dates", "start_date": "2026-05-01", "end_date": "2026-01-01", "currency": "JPY"})
    assert response.status_code == 400
    assert client.post("/itam/contracts/new", data={"name": "", "currency": "JPY"}).status_code == 400
    assert client.post("/itam/suppliers/new", data={"name": "X", "website": "ftp://x"}).status_code == 400
    with app.app_context():
        assert Contract.query.count() == 0


def test_contract_status_follows_dates():
    today = date(2026, 6, 1)
    def c(**kw):
        return Contract(name="c", active=True, notice_days=30, **kw)
    assert contract_status(c(end_date=date(2026, 5, 1)), today)[0] == "Expired"
    assert contract_status(c(end_date=date(2026, 6, 20)), today)[0] == "Notice period"
    assert contract_status(c(end_date=date(2026, 7, 20)), today)[0] == "Expiring soon"
    assert contract_status(c(end_date=date(2027, 1, 1)), today)[0] == "Active"
    assert contract_status(c(start_date=date(2026, 7, 1)), today)[0] == "Not started"


def test_owner_is_alerted_once_when_notice_period_starts(app):
    with app.app_context():
        owner = User.query.filter_by(username="admin").one()
        contract = Contract(name="Firewall support", tenant_id=1, owner_id=owner.id, notice_days=30,
                            end_date=date.today() + timedelta(days=10), active=True)
        far = Contract(name="Far away", tenant_id=1, owner_id=owner.id, notice_days=30,
                       end_date=date.today() + timedelta(days=300), active=True)
        db.session.add_all([contract, far])
        db.session.commit()
        assert send_contract_alerts() == 1
        assert send_contract_alerts() == 0
        assert Notification.query.filter_by(target_type="contract", target_id=contract.id).count() == 1
        # A new end date re-arms the alert.
        contract.end_date = date.today() + timedelta(days=5)
        db.session.commit()
        assert send_contract_alerts() == 1


def test_supplier_with_contracts_cannot_be_deleted(client, app):
    login(client)
    new_supplier(client)
    with app.app_context():
        supplier = Supplier.query.one()
        db.session.add(Contract(name="k", tenant_id=1, supplier_id=supplier.id))
        db.session.commit()
        supplier_id = supplier.id
    client.post(f"/itam/suppliers/{supplier_id}/delete")
    with app.app_context():
        assert db.session.get(Supplier, supplier_id) is not None


def test_agent_can_view_but_not_change(client, app):
    with app.app_context():
        db.session.add(User(username="agent9", name="Agent", email="agent9@test.invalid", tenant_id=1,
                            password_hash=generate_password_hash("Agent9!password"), role="agent"))
        db.session.add(Supplier(name="Cisco", tenant_id=1))
        db.session.commit()
        supplier_id = Supplier.query.one().id
    login(client, "agent9", "Agent9!password")
    page = client.get(f"/itam/suppliers/{supplier_id}")
    assert page.status_code == 200 and "View only" in page.get_data(as_text=True)
    assert client.post(f"/itam/suppliers/{supplier_id}", data={"name": "Hacked"}).status_code == 403
    assert client.post("/itam/suppliers/new", data={"name": "New"}).status_code == 403
    assert client.post(f"/itam/suppliers/{supplier_id}/delete").status_code == 403


def test_records_never_cross_tenants(client, app):
    with app.app_context():
        other = Tenant(name="Other org", slug="other-org")
        db.session.add(other)
        db.session.flush()
        db.session.add(Supplier(name="Secret vendor", tenant_id=other.id))
        foreign_ci = ConfigurationItem(name="foreign", ci_class="Server", tenant_id=other.id)
        db.session.add(foreign_ci)
        db.session.commit()
        foreign_id = Supplier.query.filter_by(name="Secret vendor").one().id
        foreign_ci_id = foreign_ci.id
    login(client)
    assert "Secret vendor" not in client.get("/itam/suppliers").get_data(as_text=True)
    assert client.get(f"/itam/suppliers/{foreign_id}").status_code == 404
    client.post("/itam/contracts/new", data={"name": "Mine", "currency": "JPY", "cis": [foreign_ci_id],
                                             "supplier_id": foreign_id})
    with app.app_context():
        assert Contract.query.filter_by(name="Mine").first() is None


def test_unknown_kind_is_404(client):
    login(client)
    assert client.get("/itam/nothing").status_code == 404
