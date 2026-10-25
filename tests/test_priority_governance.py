"""Priority set through the REST API follows the same matrix and override rule as the web form."""
import itertools

from werkzeug.security import generate_password_hash

from app import APIClient, GroupMember, SupportGroup, TaskHistory, Ticket, User, create_api_token, db
from tests.test_app import app, client  # noqa: F401

_keys = itertools.count()


def api_headers(app, role):
    with app.app_context():
        coreapps = SupportGroup.query.filter_by(name="CoreApps", tenant_id=1).one()
        actor = User(username=f"api.{role}", name=f"API {role}", email=f"api.{role}@example.com",
                     password_hash=generate_password_hash("Unused-Password-1!"), role=role, tenant_id=1)
        db.session.add(actor)
        db.session.flush()
        db.session.add(GroupMember(group_id=coreapps.id, user_id=actor.id, role="member"))
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(name=f"Priority {role}", token_prefix=prefix, token_hash=token_hash,
                                 scopes_json='["incidents:create","tickets:read","tickets:update"]',
                                 acting_user_id=actor.id, created_by_id=actor.id, tenant_id=1))
        db.session.commit()
        return {"Authorization": f"Bearer {token}"}, coreapps.id


def create(client, headers, group_id, **fields):
    body = {"title": "Payments latency", "description": "Checkout is slow.", "assignment_group_id": group_id, **fields}
    return client.post("/api/v1/incidents", json=body, headers={**headers, "Idempotency-Key": f"k-{next(_keys)}"})


def patch(client, headers, number, **fields):
    return client.patch(f"/api/v1/tickets/{number}", json=fields,
                        headers={**headers, "Idempotency-Key": f"k-{next(_keys)}"})


def test_priority_defaults_to_matrix(client, app):
    headers, group_id = api_headers(app, "agent")
    created = create(client, headers, group_id, impact="Critical", urgency="High")
    assert created.status_code == 201, created.json
    with app.app_context():
        ticket = Ticket.query.filter_by(number=created.json["data"]["number"]).one()
        assert (ticket.impact, ticket.urgency, ticket.priority, ticket.priority_overridden) == ("Critical", "High", "P1", False)
    # A matching explicit priority is not an override.
    assert create(client, headers, group_id, impact="Low", urgency="Low", priority="P4").status_code == 201
    assert create(client, headers, group_id, impact="Severe").status_code == 400


def test_agent_cannot_override_priority(client, app):
    headers, group_id = api_headers(app, "agent")
    response = create(client, headers, group_id, priority="P1",
                      priority_override_reason="Customer-facing outage for every region")
    assert response.status_code == 403
    with app.app_context():
        assert Ticket.query.filter_by(title="Payments latency").count() == 0


def test_manager_override_needs_reason_and_is_recorded(client, app):
    headers, group_id = api_headers(app, "manager")
    assert create(client, headers, group_id, priority="P1").status_code == 400
    assert create(client, headers, group_id, priority="P1", priority_override_reason="too short").status_code == 400
    created = create(client, headers, group_id, priority="P1",
                     priority_override_reason="Board-level customer escalation")
    assert created.status_code == 201
    number = created.json["data"]["number"]
    with app.app_context():
        ticket = Ticket.query.filter_by(number=number).one()
        assert (ticket.priority, ticket.priority_overridden) == ("P1", True)
        assert ticket.priority_override_reason == "Board-level customer escalation"
        assert TaskHistory.query.filter_by(target_type="ticket", target_id=ticket.id,
                                           event="Priority override reason recorded").count() == 1

    # Changing impact/urgency without a priority recalculates and clears the override.
    updated = patch(client, headers, number, impact="Low", urgency="Low")
    assert updated.status_code == 200, updated.json
    with app.app_context():
        ticket = Ticket.query.filter_by(number=number).one()
        assert (ticket.priority, ticket.priority_overridden, ticket.priority_override_reason) == ("P4", False, None)


def test_patch_priority_alone_is_checked_against_current_matrix(client, app):
    headers, group_id = api_headers(app, "agent")
    number = create(client, headers, group_id).json["data"]["number"]  # Medium x Medium = P3
    assert patch(client, headers, number, priority="P1").status_code == 403
    assert patch(client, headers, number, priority="P3").status_code == 200
    with app.app_context():
        assert Ticket.query.filter_by(number=number).one().priority == "P3"


def test_rejected_priority_leaves_the_rest_of_the_update_unsaved(client, app):
    headers, group_id = api_headers(app, "agent")
    number = create(client, headers, group_id).json["data"]["number"]
    assert patch(client, headers, number, state="In Progress", priority="P1").status_code == 403
    with app.app_context():
        ticket = Ticket.query.filter_by(number=number).one()
        assert (ticket.state, ticket.priority) == ("New", "P3")


def test_ai_update_cannot_override_the_matrix(app):
    import json
    from types import SimpleNamespace

    import pytest
    from werkzeug.exceptions import Conflict

    from serviceops_core.ai import actions
    with app.test_request_context():
        admin = User.query.filter_by(username="admin").one()
        coreapps = SupportGroup.query.filter_by(name="CoreApps", tenant_id=1).one()
        ticket = Ticket(number="INC0098765", kind="incident", title="AI priority", description="x",
                        requester_id=admin.id, tenant_id=1, state="New", priority="P3")
        db.session.add(ticket)
        db.session.flush()
        from app import TicketAssignmentGroup
        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=coreapps.id))
        db.session.flush()
        action = SimpleNamespace(action_type="update_ticket", payload_json=json.dumps({"priority": "P1"}))
        with pytest.raises(Conflict):
            actions.execute(action, ticket, admin)
        assert ticket.priority == "P3"
        actions.execute(SimpleNamespace(action_type="update_ticket", payload_json=json.dumps({"priority": "P3"})),
                        ticket, admin)
        assert (ticket.priority, ticket.priority_overridden) == ("P3", False)
