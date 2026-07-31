"""Tests for the ITIL 4 gap-analysis P2 remediation items: CI relationship
type allowlist, CI change history, SLA agreement types (OLA/UC), CSAT
submission, and KPI snapshot capture.
"""
from datetime import timedelta

from app import (
    ChangePostImplementationReview, ConfigurationItem, KpiSnapshot, SLADefinition,
    Ticket, User, capture_kpi_snapshots, db, now,
)
from tests.test_app import app, client, login


def test_ci_relationship_requires_a_known_type(client, app):
    login(client)
    with app.app_context():
        parent = ConfigurationItem(name="app-server-01", ci_class="Server", tenant_id=1)
        child = ConfigurationItem(name="db-server-01", ci_class="Server", tenant_id=1)
        db.session.add_all([parent, child])
        db.session.commit()
        parent_id, child_id = parent.id, child.id

    rejected = client.post("/cmdb/relationships", data={
        "parent_id": str(parent_id), "child_id": str(child_id), "relationship_type": "made up type",
    })
    assert rejected.status_code == 400

    accepted = client.post("/cmdb/relationships", data={
        "parent_id": str(parent_id), "child_id": str(child_id), "relationship_type": "Runs on",
    })
    assert accepted.status_code == 302


def test_ci_edit_history_is_recorded_and_shown(client, app):
    login(client)
    with app.app_context():
        ci = ConfigurationItem(name="edge-router-01", ci_class="Network", tenant_id=1)
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id

    updated = client.post(f"/cmdb/{ci_id}/edit", data={
        "name": "edge-router-01", "ci_class": "Network", "environment": "Production",
        "operational_status": "Operational", "lifecycle_state": "In Use",
        "business_criticality": "High", "location": "DC1 Rack 4",
    })
    assert updated.status_code == 302

    detail = client.get(f"/cmdb/{ci_id}/edit")
    assert detail.status_code == 200
    assert b"Change history" in detail.data
    assert b"location" in detail.data.lower() or b"DC1 Rack 4" in detail.data


def test_sla_definition_can_be_created_as_ola_or_uc(client, app):
    login(client)
    created = client.post("/itil/administration", data={
        "action": "create_sla_definition", "name": "Network vendor UC",
        "agreement_type": "UC", "counterparty": "Acme Networks",
        "target_type": "ticket", "priority": "", "duration_minutes": "240",
        "pause_states": "Pending,On Hold",
    })
    assert created.status_code == 302
    with app.app_context():
        definition = SLADefinition.query.filter_by(name="Network vendor UC").one()
        assert definition.agreement_type == "UC"
        assert definition.counterparty == "Acme Networks"


def test_requester_can_submit_csat_after_resolution(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(
            number="INC0009010", kind="incident", title="Printer offline", description="desc",
            category="Hardware", priority="P4", impact="Low", urgency="Low",
            requester_id=admin_id, state="Resolved", tenant_id=1,
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

    submitted = client.post(f"/ticket/{ticket_id}/satisfaction", data={
        "rating": "5", "comment": "Fast fix!",
    })
    assert submitted.status_code == 302
    with app.app_context():
        updated = db.session.get(Ticket, ticket_id)
        assert updated.csat_rating == 5
        assert updated.csat_comment == "Fast fix!"
        assert updated.csat_submitted_at is not None


def test_kpi_snapshot_capture_records_change_success_from_pir(app):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(
            number="CHG0009010", kind="change", title="Rotate TLS cert", description="desc",
            category="Software", priority="P3", impact="Low", urgency="Low",
            requester_id=admin_id, state="Closed", tenant_id=1,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangePostImplementationReview(
            ticket_id=ticket.id, outcome="Successful", summary="Rotated without incident.",
            reviewed_by_id=admin_id, reviewed_at=now(), tenant_id=1,
        ))
        db.session.commit()

        capture_kpi_snapshots(1)
        db.session.commit()

        snapshot = KpiSnapshot.query.filter_by(tenant_id=1, metric_name="change_success_pct").one()
        assert snapshot.metric_value == 100.0

        # Re-running on the same day updates rather than duplicates.
        capture_kpi_snapshots(1)
        db.session.commit()
        assert KpiSnapshot.query.filter_by(tenant_id=1, metric_name="change_success_pct").count() == 1
