"""Global search authorization and enterprise record input validation."""
import pytest

from app import (Asset, Comment, ConfigurationItem, EnterpriseRecord, ServiceOffering, SupportGroup,
                 User, create_ticket_with_unique_number, db)
from tests.test_app import app, client, login


def search(client, term):
    return client.get("/ui/search", query_string={"q": term}).get_data(as_text=True)


def test_requester_search_excludes_cmdb_assets_and_internal_notes(client, app):
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        admin = User.query.filter_by(username="admin").one()
        ticket = create_ticket_with_unique_number(
            "incident", title="Printer jam on floor three", description="Paper stuck.",
            category="Hardware", priority="P3", requester_id=employee.id, tenant_id=1,
        )
        db.session.flush()
        db.session.add_all([
            Comment(ticket_id=ticket.id, user_id=admin.id, body="zebracorn internal workaround",
                    internal=True, tenant_id=1),
            Comment(ticket_id=ticket.id, user_id=admin.id, body="quokkablue public update",
                    internal=False, tenant_id=1),
            ConfigurationItem(name="xylophone-db-01", ci_class="Database", tenant_id=1),
            Asset(asset_tag="XYL-0001", name="xylophone laptop", asset_type="Laptop", tenant_id=1),
        ])
        db.session.commit()
        number = ticket.number

    login(client, "employee", "Employee123!")
    assert number in search(client, "quokkablue")
    assert number not in search(client, "zebracorn")
    page = search(client, "xylophone")
    assert "xylophone-db-01" not in page and "XYL-0001" not in page

    client.post("/logout")
    login(client)
    assert number in search(client, "zebracorn")
    page = search(client, "xylophone")
    assert "xylophone-db-01" in page and "XYL-0001" in page


def test_admin_search_finds_service_offerings(client, app):
    with app.app_context():
        team = SupportGroup.query.filter_by(name="Unix", tenant_id=1).one()
        db.session.add(ServiceOffering(name="Treasury Payments", support_group_id=team.id, tenant_id=1))
        db.session.commit()
        service_id = ServiceOffering.query.filter_by(name="Treasury Payments").one().id
    login(client)
    page = search(client, "treasury")
    assert "Treasury Payments" in page
    assert f"service={service_id}" in page
    client.post("/logout")
    login(client, "employee", "Employee123!")
    assert "Treasury Payments" not in search(client, "treasury")


def enterprise_form(**overrides):
    values = {"record_type": "Support case", "title": "Customer cannot log in",
              "description": "Locked out since this morning.", "priority": "P2", "risk": "High"}
    values.update(overrides)
    return values


@pytest.mark.parametrize("overrides", [
    {"record_type": "Not a type"}, {"title": "  "}, {"title": "x" * 181}, {"description": ""},
    {"priority": "P0"}, {"priority": "Urgent"}, {"risk": "Extreme"},
])
def test_enterprise_record_rejects_invalid_input(client, app, overrides):
    login(client)
    assert client.post("/module/customer/new", data=enterprise_form(**overrides)).status_code == 400
    with app.app_context():
        assert EnterpriseRecord.query.filter_by(domain="customer").count() == 0


def test_requester_cannot_set_enterprise_priority_or_risk(client, app):
    login(client, "employee", "Employee123!")
    response = client.post("/module/customer/new", data=enterprise_form(priority="P1", risk="Critical"))
    assert response.status_code == 302
    with app.app_context():
        record = EnterpriseRecord.query.filter_by(domain="customer").one()
        assert (record.priority, record.risk) == ("P3", "Medium")

    client.post("/logout")
    login(client)
    assert client.post("/module/customer/new", data=enterprise_form(title="Staff record")).status_code == 302
    with app.app_context():
        staff_record = EnterpriseRecord.query.filter_by(title="Staff record").one()
        assert (staff_record.priority, staff_record.risk) == ("P2", "High")
