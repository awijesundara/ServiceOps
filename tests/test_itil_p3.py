"""Tests for the round-3 ITIL 4 quick wins: post-incident review available
for any P1 (not only formally-declared major incidents), and OLA/UC
agreements no longer being blended into the customer-facing SLA
compliance number.
"""
from datetime import timedelta

from app import (
    ChangeFreezeWindow, CIRelationship, ConfigurationItem, MajorIncidentProfile,
    SLADefinition, TaskSLA, Ticket, User, capture_kpi_snapshots, ci_impact_set, db, now,
)
from tests.test_app import app, client, group_id, login


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


def test_ci_impact_set_walks_dependency_chain_transitively(app):
    with app.app_context():
        db_ci = ConfigurationItem(name="db-01", ci_class="Database", tenant_id=1)
        app_ci = ConfigurationItem(name="app-01", ci_class="Server", tenant_id=1)
        web_ci = ConfigurationItem(name="web-01", ci_class="Server", tenant_id=1)
        db.session.add_all([db_ci, app_ci, web_ci])
        db.session.flush()
        # app-01 depends on db-01; web-01 depends on app-01. db-01 going down
        # should transitively impact web-01 even though they aren't linked directly.
        db.session.add(CIRelationship(parent_id=app_ci.id, child_id=db_ci.id, relationship_type="Depends on", tenant_id=1))
        db.session.add(CIRelationship(parent_id=web_ci.id, child_id=app_ci.id, relationship_type="Depends on", tenant_id=1))
        db.session.commit()
        impacted = ci_impact_set(1, {db_ci.id})
        assert app_ci.id in impacted
        assert web_ci.id in impacted


def test_change_conflict_detection_reaches_a_dependent_ci_not_just_direct_links(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        host_ci = ConfigurationItem(name="hypervisor-01", ci_class="Server", environment="Production", owner_id=admin.id, tenant_id=1)
        guest_ci = ConfigurationItem(name="guest-vm-01", ci_class="Virtual Machine", environment="Production", owner_id=admin.id, tenant_id=1)
        db.session.add_all([host_ci, guest_ci])
        db.session.flush()
        # guest_vm "Runs on" the hypervisor -- guest is the parent, host is the child.
        db.session.add(CIRelationship(parent_id=guest_ci.id, child_id=host_ci.id, relationship_type="Runs on", tenant_id=1))
        db.session.commit()
        host_id, guest_id = host_ci.id, guest_ci.id
    login(client)
    assert client.post("/tickets/new/incident", data={
        "title": "Guest VM degraded", "description": "Ongoing incident on the dependent CI.",
        "category": "Software", "priority": "P2", "group_id": group_id(app),
        "ci_id": str(guest_id),
    }).status_code == 302
    blocked = client.post("/tickets/new/change", data={
        "title": "Change on the underlying host", "description": "Should be blocked by the dependent CI's open incident.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.", "ci_id": str(host_id),
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    })
    assert blocked.status_code == 400
    assert b"depends on this" in blocked.data.lower()


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


def test_change_freeze_window_blocks_standard_change_but_not_emergency(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ci = ConfigurationItem(name="freeze-test-ci", ci_class="Server", environment="Production", owner_id=admin.id, tenant_id=1)
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id

    created = client.post("/itil/administration", data={
        "action": "create_change_freeze", "title": "Year-end freeze",
        "starts_at": "2026-08-01T00:00", "ends_at": "2026-08-10T00:00",
        "reason": "Peak season.",
    })
    assert created.status_code == 302
    with app.app_context():
        assert ChangeFreezeWindow.query.filter_by(title="Year-end freeze").count() == 1

    blocked = client.post("/tickets/new/change", data={
        "title": "Standard change during freeze", "description": "Should be blocked.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.", "ci_id": str(ci_id),
        "planned_start": "2026-08-03T09:00", "planned_end": "2026-08-03T17:00",
    })
    assert blocked.status_code == 400
    assert b"change freeze" in blocked.data.lower()
    with app.app_context():
        assert Ticket.query.filter_by(title="Standard change during freeze").first() is None

    allowed = client.post("/tickets/new/change", data={
        "title": "Emergency change during freeze", "description": "Should be allowed.",
        "category": "Software", "priority": "P1", "change_type": "Emergency",
        "risk_score": "70", "impact": "High", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.", "ci_id": str(ci_id),
        "planned_start": "2026-08-03T09:00", "planned_end": "2026-08-03T17:00",
    })
    assert allowed.status_code == 302
    with app.app_context():
        assert Ticket.query.filter_by(title="Emergency change during freeze").first() is not None
