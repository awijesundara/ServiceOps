"""Malformed form input is a 400 with a message, never an unhandled 500."""
from app import Ticket, db
from tests.test_app import app, client, group_id, login  # noqa: F401


def test_new_ticket_rejects_unknown_impact_and_urgency(client, app):
    login(client)
    response = client.post("/tickets/new/incident", data={
        "title": "Bad impact", "description": "Impact is not a matrix value.", "category": "Software",
        "group_id": group_id(app), "impact": "3", "urgency": "3",
    })
    assert response.status_code == 400
    assert b"Impact and urgency must be" in response.data
    with app.app_context():
        assert Ticket.query.filter_by(title="Bad impact").count() == 0


def test_ticket_update_rejects_unknown_impact_and_bad_assignee(client, app):
    login(client)
    assert client.post("/tickets/new/incident", data={
        "title": "Valid ticket", "description": "Created for update validation.", "category": "Software",
        "group_id": group_id(app), "impact": "Medium", "urgency": "Medium",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Valid ticket").one()
        ticket_id, priority = ticket.id, ticket.priority
    response = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "title": "Valid ticket", "description": "x", "impact": "nonsense", "urgency": "High",
    })
    assert response.status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "title": "Valid ticket", "description": "x", "assignee_id": "not-a-number",
    }).status_code == 400
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).priority == priority
