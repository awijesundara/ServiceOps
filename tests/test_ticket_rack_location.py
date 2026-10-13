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
    # A compact link: pin and "View location", the full position as tooltip and accessible name.
    assert re.search(r'<a class="ci-rack-location" href="#affected-cis" title="' + re.escape(LOCATION)
                     + r'" aria-label="View location: ' + re.escape(LOCATION) + r'"><svg class="icon ci-rack-pin"[^>]*>.*?</svg>'
                     r'<span>View location</span></a>', html)
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
    assert re.search(r'<a class="ci-rack-location" href="#gov-affected-cis" title="' + re.escape(LOCATION), html)
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


def change_with_governance(app):
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
        return change.id


def test_only_the_main_ci_pickers_ask_for_the_owning_team_field(app, client):
    # The field is opt-in: the incident form and the new-ticket form ask for
    # it; pickers on pages that already render it (change governance) or in
    # unrelated forms keep the one-line hint.
    login(client)
    html = page(client, incident(app))
    assert html.count("data-owning-team-field") == 1
    assert re.search(r'<input type="hidden" name="ci_id" value="\d+" data-owning-team-field', html)
    html = page(client, change_with_governance(app))
    assert "data-owning-team-field" not in html
    assert html.count("<span>CI owning team</span>") == 1
    new_ticket = client.get("/tickets/new/incident").get_data(as_text=True)
    assert '<input type="hidden" name="ci_id" data-owning-team-field>' in new_ticket
    assert "data-owning-team-field" not in client.get("/cmdb").get_data(as_text=True)


@pytest.mark.skipif(os.getenv("RUN_RACK_LOCATION_BROWSER") != "1",
                    reason="RUN_RACK_LOCATION_BROWSER=1 enables real local browser checks")
@pytest.mark.parametrize("width,height", [(1440, 1000), (390, 844)])
def test_owning_team_field_and_location_bar_in_a_browser(app, width, height):
    import threading

    from playwright.sync_api import expect, sync_playwright
    from werkzeug.serving import make_server

    ids = app.config["IDS"]
    with app.app_context():
        db.session.get(ConfigurationItem, ids["mounted"]).support_group_id = ids["dc"]
        db.session.commit()
    incident_id, change_id = incident(app), change_with_governance(app)
    app.config.update(CSRF_ENABLED=True, SESSION_COOKIE_SECURE=False)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(viewport={"width": width, "height": height}, reduced_motion="reduce")
            page_ = context.new_page()
            errors = []
            page_.on("pageerror", lambda error: errors.append(str(error)))
            page_.goto(base + "/login")
            page_.locator('input[name="username"]').fill("admin")
            page_.locator('input[name="password"]').fill("Admin123!")
            page_.locator("button.primary").click()
            page_.wait_for_load_state("networkidle")

            page_.goto(f"{base}/ticket/{incident_id}")
            owning = page_.get_by_role("textbox", name="CI owning team")
            expect(owning).to_have_count(1)
            expect(owning).to_have_value("Data Center Operations")
            bar = page_.locator("a.ci-rack-location")
            expect(bar).to_be_visible()
            # Picking another CI updates the owning team and hides the saved
            # CI's rack location; picking the saved CI again restores it.
            search = page_.locator('.lookup:has(input[name="ci_id"]) .lookup-search')
            search.fill("payroll")
            page_.locator(".lookup-result", has_text="payroll-api").click()
            expect(owning).to_have_value("Unassigned")
            expect(bar).to_be_hidden()
            search.fill("db-prod")
            page_.locator(".lookup-result", has_text="db-prod-07").click()
            expect(owning).to_have_value("Data Center Operations")
            expect(bar).to_be_visible()
            assert page_.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")

            page_.goto(f"{base}/ticket/{change_id}")
            expect(page_.get_by_role("textbox", name="CI owning team")).to_have_count(1)
            expect(page_.locator(".ci-owning-team-field")).to_have_count(0)

            page_.goto(f"{base}/tickets/new/incident")
            expect(page_.locator(".ci-owning-team-field")).to_be_hidden()
            page_.locator('.lookup:has(input[name="ci_id"]) .lookup-search').fill("db-prod")
            page_.locator(".lookup-result", has_text="db-prod-07").click()
            expect(page_.get_by_role("textbox", name="CI owning team")).to_have_value("Data Center Operations")

            axe = os.getenv("AXE_CORE_PATH")
            assert axe and os.path.isfile(axe), "AXE_CORE_PATH required for accessibility acceptance"
            page_.goto(f"{base}/ticket/{incident_id}")
            page_.evaluate(open(axe, encoding="utf-8").read())
            violations = page_.evaluate("async () => (await axe.run(document, {runOnly: {type:'tag',"
                                        "values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert not violations, [(v["id"], v["help"], [n["html"][:200] for n in v["nodes"]]) for v in violations]
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
