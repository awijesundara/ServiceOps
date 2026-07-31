"""Tests for the round-3 ITIL 4 quick wins: post-incident review available
for any P1 (not only formally-declared major incidents), and OLA/UC
agreements no longer being blended into the customer-facing SLA
compliance number.
"""
from datetime import timedelta

from app import (
    MajorIncidentProfile, SLADefinition, TaskSLA, Ticket, User,
    capture_kpi_snapshots, db, now,
)
from tests.test_app import app, client, login


def test_p1_incident_gets_post_incident_review_without_major_incident_declaration(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(
            number="INC0009101", kind="incident", title="Quiet P1", description="desc",
            category="Software", priority="P1", impact="Critical", urgency="Critical",
            requester_id=admin_id, tenant_id=1,
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id
        assert ticket.major_incident_profile is None

    reviewed = client.post(f"/incident/{ticket_id}/major-incident/review", data={
        "what_went_well": "Caught by monitoring.",
        "what_went_poorly": "No one was ever paged.",
        "follow_up_actions": "Wire up alerting.",
    })
    assert reviewed.status_code == 302
    with app.app_context():
        profile = MajorIncidentProfile.query.filter_by(ticket_id=ticket_id).one()
        assert profile.review_what_went_poorly == "No one was ever paged."
        assert profile.reviewed_at is not None

    detail = client.get(f"/ticket/{ticket_id}")
    assert b"No one was ever paged." in detail.data


def test_non_p1_incident_without_major_declaration_cannot_be_reviewed(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(
            number="INC0009102", kind="incident", title="Minor blip", description="desc",
            category="Software", priority="P3", impact="Low", urgency="Low",
            requester_id=admin_id, tenant_id=1,
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

    response = client.post(f"/incident/{ticket_id}/major-incident/review", data={
        "what_went_well": "n/a",
    })
    assert response.status_code == 404


def test_ola_breach_is_excluded_from_customer_facing_sla_compliance(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        sla_def = SLADefinition(
            name="Customer SLA", agreement_type="SLA", target_type="ticket",
            duration_minutes=60, tenant_id=1,
        )
        ola_def = SLADefinition(
            name="Internal OLA", agreement_type="OLA", counterparty="Network team",
            target_type="ticket", duration_minutes=60, tenant_id=1,
        )
        db.session.add_all([sla_def, ola_def])
        db.session.flush()
        ticket = Ticket(
            number="INC0009103", kind="incident", title="Resolved with a breached OLA",
            description="desc", category="Software", priority="P2",
            impact="Medium", urgency="Medium", requester_id=admin_id,
            state="Resolved", tenant_id=1,
        )
        db.session.add(ticket)
        db.session.flush()
        started = now() - timedelta(days=1)
        db.session.add(TaskSLA(
            definition_id=sla_def.id, target_type="ticket", target_id=ticket.id,
            started_at=started, breach_at=started + timedelta(hours=1),
            stage="Completed", breached=False,
        ))
        db.session.add(TaskSLA(
            definition_id=ola_def.id, target_type="ticket", target_id=ticket.id,
            started_at=started, breach_at=started + timedelta(hours=1),
            stage="Completed", breached=True,
        ))
        db.session.commit()

        capture_kpi_snapshots(1)
        db.session.commit()
        from app import KpiSnapshot
        row = KpiSnapshot.query.filter_by(tenant_id=1, metric_name="sla_compliance_pct").first()
        assert row is not None
        # Only the SLA (met, not breached) counts -- the breached OLA is excluded,
        # so compliance should read 100%, not 50%.
        assert row.metric_value == 100.0
