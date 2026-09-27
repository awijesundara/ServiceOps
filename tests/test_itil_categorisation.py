"""ITIL categorisation model: category at logging vs closure, resolution data,
change classification and taxonomy administration (docs/ITIL_V5_CATEGORISATION.md
in serviceops-notes)."""
from app import APIClient, Ticket, TicketCategory, TicketSubcategory, User, create_api_token, db, seed_itil
from tests.test_app import app, client, group_id, login  # noqa: F401  (pytest fixtures)

BASE = {"impact": "Medium", "urgency": "Medium", "contact_type": "Self-service", "notify": "Email"}


def new_incident(client, app, title, category="Network", subcategory="VPN"):
    client.post("/tickets/new/incident", data={
        **BASE, "title": title, "description": "d", "category": category, "subcategory": subcategory,
        "group_id": group_id(app, "Network"),
    })
    with app.app_context():
        return Ticket.query.filter_by(title=title).one().id


def update(client, ticket_id, **fields):
    return client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P3", "assignee_id": "", **fields,
    }, follow_redirects=True)


def test_resolving_from_the_record_requires_notes_and_records_closure_separately(client, app):
    login(client)
    ticket_id = new_incident(client, app, "VPN drops")
    refused = update(client, ticket_id, resolve="1")
    assert b"Record resolution notes" in refused.data
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state != "Resolved"

    update(client, ticket_id, resolve="1", resolution_notes="Renewed the expired VPN certificate.",
           closure_category="Security", closure_subcategory="Policy breach")
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.state == "Resolved" and ticket.resolved_at is not None
        assert (ticket.category, ticket.subcategory) == ("Network", "VPN")
        assert (ticket.closure_category, ticket.closure_subcategory) == ("Security", "Policy breach")
        assert ticket.resolution_notes == "Renewed the expired VPN certificate."


def test_closure_category_is_not_stamped_before_resolution_and_reopen_clears_resolved_at(client, app):
    login(client)
    ticket_id = new_incident(client, app, "Mail delay")
    update(client, ticket_id, resolution_notes="Draft notes", closure_category="Communication")
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.closure_category is None and ticket.resolution_notes == "Draft notes"
    update(client, ticket_id, resolve="1", resolution_notes="Cleared the queue.")
    client.post(f"/ticket/{ticket_id}", data={"action": "reopen"})
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.state == "In Progress" and ticket.resolved_at is None
        # Resolved without choosing one: the logging categorisation carries over.
        assert ticket.closure_category == "Network"


def test_task_board_explains_why_an_incident_cannot_be_resolved(client, app):
    login(client)
    ticket_id = new_incident(client, app, "Board resolve")
    response = client.post(f"/task-board/{ticket_id}/move", data={"state": "Resolved"})
    assert response.status_code == 409
    assert "resolution notes" in response.json["error"]


def test_api_resolution_keeps_notes_optional_and_accepts_closure_fields(client, app):
    login(client)
    first = new_incident(client, app, "API resolve one")
    second = new_incident(client, app, "API resolve two")
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(
            name="ITIL test", token_prefix=prefix, token_hash=token_hash,
            scopes_json='["tickets:read","tickets:update"]', acting_user_id=admin.id, created_by_id=admin.id,
        ))
        db.session.commit()
        numbers = [db.session.get(Ticket, first).number, db.session.get(Ticket, second).number]
    headers = {"Authorization": f"Bearer {token}"}

    plain = client.patch(f"/api/v1/tickets/{numbers[0]}", json={"state": "Resolved"},
                         headers={**headers, "Idempotency-Key": "itil-1"})
    assert plain.status_code == 200
    assert plain.json["data"]["closure_category"] == "Network"
    assert plain.json["data"]["resolved_at"]

    detailed = client.patch(f"/api/v1/tickets/{numbers[1]}", json={
        "state": "Resolved", "resolution_notes": "Replaced the firewall rule.",
        "closure_category": "network", "closure_subcategory": "Firewall",
    }, headers={**headers, "Idempotency-Key": "itil-2"})
    assert detailed.status_code == 200
    data = detailed.json["data"]
    assert (data["closure_category"], data["closure_subcategory"]) == ("Network", "Firewall")
    assert data["resolution_notes"] == "Replaced the firewall rule."


def test_changes_are_not_given_a_symptom_category(client, app):
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Patch hypervisors", "description": "d", "category": "Hardware", "change_type": "Normal",
        "risk_score": "40", "impact": "Medium", "group_id": group_id(app),
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": "2026-11-01T09:00", "planned_end": "2026-11-01T17:00",
    })
    with app.app_context():
        change = Ticket.query.filter_by(title="Patch hypervisors").one()
        assert (change.category, change.subcategory) == ("", "")


def test_renaming_a_category_relabels_its_tickets(client, app):
    login(client)
    ticket_id = new_incident(client, app, "Relabel me")
    with app.app_context():
        category_id = TicketCategory.query.filter_by(name="Network").one().id
        subcategory_id = TicketSubcategory.query.filter_by(category_id=category_id, name="VPN").one().id
    client.post("/service-operations/settings", data={
        "action": "update_ticket_category", "category_id": category_id, "name": "Networking", "active": "on",
    })
    client.post("/service-operations/settings", data={
        "action": "update_ticket_subcategory", "subcategory_id": subcategory_id, "name": "Remote access VPN",
        "active": "on",
    })
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert (ticket.category, ticket.subcategory) == ("Networking", "Remote access VPN")


def test_startup_seeding_does_not_recreate_an_administrators_changes(app):
    with app.app_context():
        TicketCategory.query.filter_by(name="Communication").one().name = "Messaging"
        db.session.commit()
        seed_itil(User.query.filter_by(username="admin").one())
        db.session.commit()
        names = {row.name for row in TicketCategory.query.all()}
        assert "Messaging" in names and "Communication" not in names


def test_fresh_tenant_gets_the_nine_category_model(app):
    with app.app_context():
        names = {row.name for row in TicketCategory.query.filter_by(tenant_id=1, active=True)}
    assert names == {
        "Hardware", "Software / Application", "Network", "Access / Identity", "Infrastructure / Platform",
        "Security", "Data / Database", "Communication", "Facilities / Endpoint services",
    }


def test_analytics_reports_closure_categories(client, app):
    login(client)
    ticket_id = new_incident(client, app, "Analytics closure")
    update(client, ticket_id, resolve="1", resolution_notes="Fixed.", closure_category="Data / Database")
    page = client.get("/analytics").get_data(as_text=True)
    assert "Incidents by closure category" in page and "Data / Database" in page
