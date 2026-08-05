"""Tests for the ITIL 4 gap-analysis P0 remediation items:
continual improvement register, change post-implementation review gate,
and CI-to-service mapping.
"""
import pytest
from werkzeug.exceptions import HTTPException

from app import (
    ApprovalChain, ChangePostImplementationReview, ConfigurationItem,
    ImprovementItem, OperationalTask, ServiceOffering, ServiceOfferingCI,
    Ticket, User, db, transition_ticket,
)
from tests.test_app import app, client, group_id, login


def test_change_cannot_close_without_post_implementation_review(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "PIR-gated change",
        "description": "Change must not close without a recorded review.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="PIR-gated change").one().id
        implementation_task_id = OperationalTask.query.filter_by(
            parent_id=ticket_id, task_type="Implementation",
        ).one().id
        vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id, state="Running",
        ).one().gates[0].votes[0].id

    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P3", "assignee_id": "",
    }).status_code == 302
    assert client.post(f"/operational-task/{implementation_task_id}", data={
        "state": "Closed Complete", "assignee_id": "", "work_notes": "Done.",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Resolved", "priority": "P3", "assignee_id": "",
    }).status_code == 302

    # The generic edit form is locked once Resolved (an unrelated, pre-existing
    # rule -- only comments/reopen are allowed), so the PIR gate itself is
    # exercised directly against transition_ticket() rather than through that
    # locked HTTP form.
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        with pytest.raises(HTTPException) as excinfo:
            transition_ticket(ticket, "Closed")
        assert "post-implementation review" in excinfo.value.description
        db.session.rollback()
        assert db.session.get(Ticket, ticket_id).state == "Resolved"

    saved = client.post(f"/change/{ticket_id}/pir", data={
        "outcome": "Successful", "summary": "Deployed without issue.", "follow_up_actions": "",
    })
    assert saved.status_code == 302
    with app.app_context():
        pir = ChangePostImplementationReview.query.filter_by(ticket_id=ticket_id).one()
        assert pir.outcome == "Successful"
        assert pir.reviewed_by.username == "database.manager"

        ticket = db.session.get(Ticket, ticket_id)
        transition_ticket(ticket, "Closed")
        db.session.commit()
        assert db.session.get(Ticket, ticket_id).state == "Closed"


def test_improvement_item_can_be_raised_from_a_ticket_and_updated(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(
            number="INC0009001", kind="incident", title="Source incident", description="desc",
            category="Software", priority="P3", impact="Low", urgency="Low",
            requester_id=admin_id, tenant_id=1,
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

    raised = client.post("/improvements/new", data={
        "title": "Improve alerting thresholds",
        "description": "Alerts fired too late during the incident.",
        "expected_outcome": "Faster detection next time.",
        "source_type": "ticket", "source_id": str(ticket_id),
    })
    assert raised.status_code == 302
    with app.app_context():
        item = ImprovementItem.query.filter_by(title="Improve alerting thresholds").one()
        assert item.status == "Identified"
        assert item.source_type == "ticket" and item.source_id == ticket_id
        item_id = item.id

    listing = client.get("/improvements")
    assert listing.status_code == 200
    assert b"Improve alerting thresholds" in listing.data

    detail = client.get(f"/improvement/{item_id}")
    assert detail.status_code == 200
    assert b"Source incident" in detail.data

    updated = client.post(f"/improvement/{item_id}", data={
        "status": "In Progress", "expected_outcome": "Faster detection next time.",
        "measured_result": "", "owner_id": "",
    })
    assert updated.status_code == 302
    with app.app_context():
        assert ImprovementItem.query.get(item_id).status == "In Progress"


def test_improvement_redirect_rejects_scheme_relative_external_url(client, app):
    login(client)
    response = client.post("/improvements/new", data={
        "title": "Safe redirect regression",
        "redirect_to": "//attacker.example/phishing",
    })
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/improvement/")
    assert "attacker.example" not in response.headers["Location"]


def test_ci_service_mapping_can_be_linked_and_unlinked(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        service = ServiceOffering(
            name="Trading Platform", owner_id=admin_id, criticality="Critical",
            status="Operational", tenant_id=1,
        )
        ci = ConfigurationItem(name="trade-db-01", ci_class="Database", tenant_id=1)
        db.session.add_all([service, ci])
        db.session.commit()
        service_id, ci_id = service.id, ci.id

    linked = client.post("/itil/administration", data={
        "action": "link_service_ci", "service_offering_id": str(service_id),
        "ci_id": str(ci_id), "relationship_role": "Primary",
    })
    assert linked.status_code == 302
    with app.app_context():
        link = ServiceOfferingCI.query.filter_by(service_offering_id=service_id, ci_id=ci_id).one()
        assert link.relationship_role == "Primary"
        link_id = link.id

    admin_page = client.get("/itil/administration")
    assert b"trade-db-01" in admin_page.data

    unlinked = client.post("/itil/administration", data={
        "action": "unlink_service_ci", "link_id": str(link_id),
    })
    assert unlinked.status_code == 302
    with app.app_context():
        assert ServiceOfferingCI.query.filter_by(service_offering_id=service_id, ci_id=ci_id).count() == 0
