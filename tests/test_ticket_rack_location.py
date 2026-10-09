"""Rack location on tickets: the location line under Configuration item, the
rack card in the Affected CIs tab, and Data Center teams whose tickets open
on that tab (serviceops_core/rack_location.py)."""
import os
import re
import tempfile

import pytest
from werkzeug.security import generate_password_hash

from app import (ChangeGovernance, ChangeOwnership, ChangeRevision, CiClassPermission, ConfigurationItem,
                 GroupMember, Rack, SupportGroup, TaskCI, Ticket, TicketAssignmentGroup, User, create_app,
                 create_ticket_with_unique_number, db, visible_ticket_query)

LOCATION = "Rack B4-12 · Tokyo DC1 · U22, front"


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        tenant = admin.tenant_id
        data_center = SupportGroup(name="Data Center Operations", group_type="Data Center", tenant_id=tenant)
        unix = SupportGroup(name="Rack Test Unix", group_type="IT Fulfillment", tenant_id=tenant)
        db.session.add_all([data_center, unix])
        db.session.flush()
        agent = User(username="dc.agent", name="DC Agent", email="dc.agent@test.invalid", role="agent",
                     password_hash=generate_password_hash("Agent123!"), tenant_id=tenant)
        requester = User(username="rack.requester", name="Rack Requester", email="rack.requester@test.invalid",
                         role="requester", password_hash=generate_password_hash("Requester123!"), tenant_id=tenant)
        db.session.add_all([agent, requester])
        db.session.flush()
        db.session.add(GroupMember(group_id=data_center.id, user_id=agent.id, role="member"))
        rack = Rack(name="B4-12", site="Tokyo DC1", u_height=42, tenant_id=tenant)
        db.session.add(rack)
        db.session.flush()
        mounted = ConfigurationItem(name="db-prod-07", ci_class="Server", tenant_id=tenant, rack_id=rack.id,
                                    rack_position=22, rack_u_height=2, rack_face="front")
        neighbour = ConfigurationItem(name="esx-prod-14", ci_class="Server", tenant_id=tenant, rack_id=rack.id,
                                      rack_position=25.0, rack_u_height=2, rack_face="front")
        loose = ConfigurationItem(name="payroll-api", ci_class="Application", tenant_id=tenant)
        db.session.add_all([mounted, neighbour, loose])
        db.session.commit()
        app.config["IDS"] = {"dc": data_center.id, "unix": unix.id, "mounted": mounted.id,
                             "neighbour": neighbour.id, "loose": loose.id, "rack": rack.id,
                             "requester": requester.id, "admin": admin.id}
    yield app
    os.unlink(path)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="admin", password="Admin123!"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def incident(app, group_key="dc", ci_key="mounted", requester_key="admin", extra=()):
    ids = app.config["IDS"]
    with app.app_context():
        ticket = create_ticket_with_unique_number(
            "incident", title="Database node unreachable", description="PDU-A breaker trip.",
            priority="P2", requester_id=ids[requester_key])
        db.session.flush()
        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=ids[group_key]))
        if ci_key:
            db.session.add(TaskCI(target_type="ticket", target_id=ticket.id, ci_id=ids[ci_key],
                                  relationship_role="Primary CI"))
        for key in extra:
            db.session.add(TaskCI(target_type="ticket", target_id=ticket.id, ci_id=ids[key],
                                  relationship_role="Affected CI"))
        db.session.commit()
        return ticket.id


def page(client, ticket_id):
    response = client.get(f"/ticket/{ticket_id}")
    assert response.status_code == 200
    return response.get_data(as_text=True)


def test_data_center_ticket_shows_location_and_opens_on_the_rack_view(app, client):
    ticket_id = incident(app, extra=("neighbour", "loose"))
    login(client)
    html = page(client, ticket_id)
    ids = app.config["IDS"]
    assert 'data-default-tab="affected-cis"' in html
    # Location line under the Configuration item field, linking to the tab.
    assert re.search(r'class="ci-rack-location"><a href="#affected-cis">' + re.escape(LOCATION) + "</a>", html)
    # The CI page's rack card, highlighting the primary CI.
    assert f'/cmdb/racks/{ids["rack"]}/embed?highlight={ids["mounted"]}' in html
    assert f'/cmdb/racks/{ids["rack"]}?highlight={ids["mounted"]}' in html
    # The other rack-mounted CI is listed; the CI without a rack is not.
    assert "esx-prod-14</a> <span class=\"muted\">&middot; B4-12 · Tokyo DC1 · U25, front" in html
    assert "payroll-api</a>" not in html


def test_other_teams_see_the_location_without_changing_the_default_tab(app, client):
    ticket_id = incident(app, group_key="unix")
    login(client)
    html = page(client, ticket_id)
    assert LOCATION in html
    assert "ticket-rack-placement" in html
    assert "data-default-tab" not in html


def test_a_ci_without_a_rack_shows_nothing_new(app, client):
    ticket_id = incident(app, ci_key="loose")
    login(client)
    html = page(client, ticket_id)
    assert "ci-rack-location" not in html
    assert "ticket-rack-placement" not in html
    assert "data-default-tab" not in html


def test_requesters_never_see_rack_locations(app, client):
    ticket_id = incident(app, requester_key="requester")
    login(client, "rack.requester", "Requester123!")
    html = page(client, ticket_id)
    assert "B4-12" not in html
    assert "/cmdb/racks/" not in html


def test_ci_class_read_restrictions_hide_the_location(app, client):
    ticket_id = incident(app)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        # Once a class has permission rows, roles without can_read are denied.
        db.session.add(CiClassPermission(tenant_id=admin.tenant_id, ci_class="Server", role="manager", can_read=True))
        db.session.commit()
    login(client, "dc.agent", "Agent123!")
    html = page(client, ticket_id)
    assert "B4-12" not in html
    assert "data-default-tab" not in html


def test_change_owned_by_a_data_center_team_opens_on_its_affected_cis_tab(app, client):
    ids = app.config["IDS"]
    with app.app_context():
        change = create_ticket_with_unique_number(
            "change", title="Replace PSU in db-prod-07", description="Swap PSU 1.", priority="P3",
            requester_id=ids["admin"])
        db.session.flush()
        db.session.add(ChangeGovernance(ticket_id=change.id, change_type="Normal", impact="Medium",
                                        ci_id=ids["mounted"], implementation_plan="Swap", test_plan="Check",
                                        backout_plan="Revert"))
        db.session.add(ChangeOwnership(ticket_id=change.id, group_id=ids["dc"]))
        db.session.add(ChangeRevision(ticket_id=change.id, revision=1))
        db.session.commit()
        change_id = change.id
    login(client)
    html = page(client, change_id)
    assert 'data-default-tab="gov-affected-cis"' in html
    assert re.search(r'class="ci-rack-location"><a href="#gov-affected-cis">' + re.escape(LOCATION), html)
    assert html.count('class="panel ticket-rack-placement"') == 1
    assert f'/cmdb/racks/{ids["rack"]}/embed?highlight={ids["mounted"]}' in html


def test_data_center_teams_keep_it_team_ticket_visibility(app):
    ids = app.config["IDS"]
    other_team_ticket = incident(app, group_key="unix", requester_key="admin")
    with app.app_context():
        agent = User.query.filter_by(username="dc.agent").one()
        visible = {ticket.id for ticket in visible_ticket_query(agent).all()}
        assert other_team_ticket in visible
        db.session.get(SupportGroup, ids["dc"]).group_type = "Fulfillment"
        db.session.commit()
        visible = {ticket.id for ticket in visible_ticket_query(agent).all()}
        assert other_team_ticket not in visible


def test_administrators_can_choose_the_data_center_group_type(app, client):
    ids = app.config["IDS"]
    login(client)
    form = client.get(f"/admin/groups/{ids['unix']}").get_data(as_text=True)
    assert '<option value="Data Center"' in form
