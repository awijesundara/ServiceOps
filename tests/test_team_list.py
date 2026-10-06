"""One shared team list: a team created with any team type is selectable everywhere."""
import pytest

import app as core
from test_app import app, client, login  # noqa: F401
from serviceops_models import SupportGroup, Tenant, Ticket, db


def create_team(client, app, name, group_type):
    response = client.post("/service-operations/settings", data={
        "action": "create_support_group", "name": name, "group_type": group_type,
    })
    assert response.status_code == 302
    with app.app_context():
        return SupportGroup.query.filter_by(name=name).one().id


@pytest.mark.parametrize("group_type", ["IT Fulfillment", "Fulfillment", "Executive"])
def test_new_team_of_any_type_is_listed_on_every_team_picker(app, client, group_type):
    login(client)
    create_team(client, app, "Field Services", group_type)
    for path in ("/tickets/new/incident", "/tickets/new/change", "/cmdb/new"):
        assert b"Field Services" in client.get(path).data, path


def test_incident_can_be_owned_by_a_non_it_fulfillment_team(app, client):
    login(client)
    team_id = create_team(client, app, "Field Services", "Fulfillment")
    response = client.post("/tickets/new/incident", data={
        "title": "field-owned incident", "description": "shared team list",
        "category": "Software", "priority": "P3", "group_id": str(team_id),
    })
    assert response.status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="field-owned incident").one()
        assert ticket.assignment_group_record.group_id == team_id


def test_team_list_excludes_governance_bodies_and_inactive_teams(app):
    with app.app_context():
        db.session.add(SupportGroup(name="Retired", group_type="IT Fulfillment", active=False, tenant_id=1))
        db.session.commit()
        names = {group.name for group in core.team_groups(1)}
        assert "Change Control Board" not in names
        assert "Executive Office" not in names
        assert "Retired" not in names
        assert {"CoreApps", "Service Desk", "SysOps"} <= names


def test_team_list_is_tenant_scoped(app):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="team-list-other", name="Other organization"))
        db.session.flush()
        db.session.add(SupportGroup(name="Other Tenant Team", group_type="Fulfillment", tenant_id=2))
        db.session.commit()
        assert "Other Tenant Team" not in {group.name for group in core.team_groups(1)}
        assert [group.name for group in core.team_groups(2)] == ["Other Tenant Team"]


def test_client_support_team_keeps_its_type_when_updated(app, client):
    login(client)
    with app.app_context():
        sysops_id = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one().id
    response = client.post("/service-operations/settings", data={
        "action": "update_support_group", "group_id": sysops_id,
        "name": "SysOps", "group_type": "Client Support", "active": "on",
    })
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(SupportGroup, sysops_id).group_type == "Client Support"


def test_download_names_use_rfc6266_encoding():
    assert core.content_disposition("attachment", "report.pdf") == "attachment; filename=report.pdf"
    assert core.content_disposition("inline", "Résumé.pdf") == (
        "inline; filename=Resume.pdf; filename*=UTF-8''R%C3%A9sum%C3%A9.pdf"
    )
