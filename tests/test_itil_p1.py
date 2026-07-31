"""Tests for the ITIL 4 gap-analysis P1 remediation items: change risk
score calculation, structured post-incident review, known errors list,
and incident-to-knowledge-article linking.
"""
from app import (
    ChangeGovernance, ConfigurationItem, EnterpriseRecord, Knowledge,
    MajorIncidentProfile, ProblemProfile, Ticket, User, db,
)
from tests.test_app import app, client, group_id, login


def test_change_risk_score_auto_calculates_when_left_blank(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ci = ConfigurationItem(
            name="payments-db-01", ci_class="Database", business_criticality="Critical",
            environment="Production", tenant_id=1,
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id

    response = client.post("/tickets/new/change", data={
        "title": "Auto risk score change",
        "description": "Risk score left blank to test auto-calculation.",
        "category": "Software", "change_type": "Emergency",
        "impact": "High", "urgency": "High",
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
        "group_id": group_id(app), "ci_id": str(ci_id),
        # risk_score intentionally omitted
    })
    assert response.status_code == 302
    with app.app_context():
        governance = ChangeGovernance.query.join(Ticket).filter(
            Ticket.title == "Auto risk score change"
        ).one()
        # Emergency (70) + Critical CI (+30) + Production (+15), clamped to 100.
        assert governance.risk_score == 100
        assert governance.risk_score_overridden is False


def test_change_risk_score_override_is_recorded_with_reason(client, app):
    login(client)
    response = client.post("/tickets/new/change", data={
        "title": "Overridden risk score change",
        "description": "Risk score explicitly typed to test override tracking.",
        "category": "Software", "change_type": "Standard",
        "impact": "Low", "urgency": "Low",
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
        "group_id": group_id(app),
        "risk_score": "90", "risk_score_override_reason": "Touches shared auth middleware.",
    })
    assert response.status_code == 302
    with app.app_context():
        governance = ChangeGovernance.query.join(Ticket).filter(
            Ticket.title == "Overridden risk score change"
        ).one()
        assert governance.risk_score == 90
        assert governance.risk_score_overridden is True
        assert governance.risk_score_override_reason == "Touches shared auth middleware."


def test_major_incident_post_incident_review_can_be_recorded(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(
            number="INC0009002", kind="incident", title="Major outage", description="desc",
            category="Software", priority="P1", impact="Critical", urgency="Critical",
            requester_id=admin_id, tenant_id=1,
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

    proposed = client.post(f"/incident/{ticket_id}/major-incident", data={
        "status": "Accepted", "business_impact": "Full outage.", "communications": "Bridge open.",
    })
    assert proposed.status_code == 302

    reviewed = client.post(f"/incident/{ticket_id}/major-incident/review", data={
        "what_went_well": "Fast detection.",
        "what_went_poorly": "Runbook was out of date.",
        "follow_up_actions": "Update the runbook.",
    })
    assert reviewed.status_code == 302
    with app.app_context():
        profile = MajorIncidentProfile.query.filter_by(ticket_id=ticket_id).one()
        assert profile.review_what_went_poorly == "Runbook was out of date."
        assert profile.reviewed_by is not None
        assert profile.reviewed_at is not None

    detail = client.get(f"/ticket/{ticket_id}")
    assert detail.status_code == 200
    assert b"Runbook was out of date." in detail.data


def test_known_errors_list_shows_flagged_problems_only(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        known = EnterpriseRecord(
            number="PRB0009001", domain="problem", record_type="Known error",
            title="Disk fills up on log rotation failure", description="desc",
            state="New", priority="P3", risk="Medium", requester_id=admin_id, tenant_id=1,
        )
        not_known = EnterpriseRecord(
            number="PRB0009002", domain="problem", record_type="Root cause analysis",
            title="Unrelated problem still under investigation", description="desc",
            state="New", priority="P3", risk="Medium", requester_id=admin_id, tenant_id=1,
        )
        db.session.add_all([known, not_known])
        db.session.flush()
        db.session.add(ProblemProfile(
            enterprise_record_id=known.id, known_error=True,
            root_cause="Log rotation cron silently failing.", workaround="Restart the cron job.",
        ))
        db.session.add(ProblemProfile(enterprise_record_id=not_known.id, known_error=False))
        db.session.commit()

    listing = client.get("/known-errors")
    assert listing.status_code == 200
    assert b"Disk fills up on log rotation failure" in listing.data
    assert b"Unrelated problem still under investigation" not in listing.data


def test_incident_can_link_a_knowledge_article(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(
            number="INC0009003", kind="incident", title="VPN drops for remote staff", description="desc",
            category="Network", priority="P3", impact="Medium", urgency="Medium",
            requester_id=admin_id, tenant_id=1,
        )
        article = Knowledge(
            title="Fixing VPN client drops", body="Reinstall the client.",
            category="Network", author_id=admin_id, published=True, tenant_id=1,
        )
        db.session.add_all([ticket, article])
        db.session.commit()
        ticket_id, article_number = ticket.id, f"KB{article.id:07d}"

    linked = client.post(f"/record/ticket/{ticket_id}/relationships", data={
        "link_type": "knowledge_article", "target_number": article_number,
    })
    assert linked.status_code == 302
    detail = client.get(f"/ticket/{ticket_id}")
    assert detail.status_code == 200
    assert b"Fixing VPN client drops" in detail.data
