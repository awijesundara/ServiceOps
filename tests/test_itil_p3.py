"""Tests for the round-3 ITIL 4 quick wins: post-incident review available
for any P1 (not only formally-declared major incidents), and OLA/UC
agreements no longer being blended into the customer-facing SLA
compliance number.
"""
from datetime import timedelta

from app import (
    ChangeFreezeWindow, CIRelationship, ConfigurationItem, EnterpriseRecord,
    MajorIncidentProfile, ServiceOffering, ServiceOfferingCI, ServiceOutage,
    SLADefinition, TaskSLA, Ticket, User, capture_kpi_snapshots, ci_impact_set,
    db, now, service_availability_pct,
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


def test_critical_incident_opens_and_resolving_closes_a_service_outage(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ci = ConfigurationItem(name="payments-api-01", ci_class="Server", environment="Production", owner_id=admin.id, tenant_id=1)
        db.session.add(ci)
        db.session.flush()
        service = ServiceOffering(name="Payments", owner_id=admin.id, criticality="High", tenant_id=1)
        db.session.add(service)
        db.session.flush()
        db.session.add(ServiceOfferingCI(service_offering_id=service.id, ci_id=ci.id, relationship_role="Primary"))
        db.session.commit()
        ci_id, service_id = ci.id, service.id

    created = client.post("/tickets/new/incident", data={
        "title": "Payments API down", "description": "Critical outage.",
        "category": "Software", "priority": "P1", "impact": "Critical", "urgency": "Critical",
        "group_id": group_id(app), "ci_id": str(ci_id),
    })
    assert created.status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Payments API down").one()
        ticket_id = ticket.id
        outage = ServiceOutage.query.filter_by(service_offering_id=service_id, ticket_id=ticket_id).one()
        assert outage.ended_at is None
        # Backdate so there's measurable elapsed downtime to compute against --
        # right at creation the outage is only microseconds old.
        outage.started_at = now() - timedelta(hours=2)
        db.session.commit()
        assert service_availability_pct(service_id) < 100

    resolved = client.post(f"/ticket/{ticket_id}", data={"action": "quick_resolve"})
    assert resolved.status_code == 302
    with app.app_context():
        outage = ServiceOutage.query.filter_by(service_offering_id=service_id, ticket_id=ticket_id).one()
        assert outage.ended_at is not None


def test_service_availability_pct_merges_overlapping_outages(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        service = ServiceOffering(name="Overlap Service", owner_id=admin.id, tenant_id=1)
        ci = ConfigurationItem(name="overlap-ci", ci_class="Server", tenant_id=1)
        db.session.add_all([service, ci])
        db.session.flush()
        requester = admin
        ticket1 = Ticket(number="INC0009201", kind="incident", title="A", description="d", category="Software",
                          priority="P1", impact="Critical", urgency="Critical", requester_id=requester.id, tenant_id=1)
        ticket2 = Ticket(number="INC0009202", kind="incident", title="B", description="d", category="Software",
                          priority="P1", impact="Critical", urgency="Critical", requester_id=requester.id, tenant_id=1)
        db.session.add_all([ticket1, ticket2])
        db.session.flush()
        start = now() - timedelta(hours=10)
        # Two overlapping 4-hour outages, offset by 2 hours -- true downtime is
        # 6 hours, not 8, if they're correctly merged rather than summed.
        db.session.add(ServiceOutage(service_offering_id=service.id, ticket_id=ticket1.id, started_at=start, ended_at=start + timedelta(hours=4), tenant_id=1))
        db.session.add(ServiceOutage(service_offering_id=service.id, ticket_id=ticket2.id, started_at=start + timedelta(hours=2), ended_at=start + timedelta(hours=6), tenant_id=1))
        db.session.commit()
        service_id = service.id

        pct = service_availability_pct(service_id, days=1)
        window_seconds = 24 * 3600
        expected_downtime = 6 * 3600
        expected_pct = round(100 * (1 - expected_downtime / window_seconds), 3)
        assert pct == expected_pct


def test_enterprise_record_visible_to_fulfillment_team_member_not_just_admin(client, app):
    """RT-imported records (and any EnterpriseRecord) previously fell through
    visible_enterprise_record_query's cracks: it checked requester/assignee/
    approval/task-assignment-group but never the record's own support_group_id,
    and had no "IT Fulfillment members see everything" shortcut the way
    visible_ticket_query does -- so an owning team could never see their own
    imported tickets unless one happened to already have an OperationalTask.
    """
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        record = EnterpriseRecord(
            number="EVT0009301", domain="event", record_type="RT Ticket",
            title="Dev servers unavailable", description="Imported from RT",
            requester_id=admin.id, support_group_id=group_id(app), tenant_id=1,
        )
        db.session.add(record)
        db.session.commit()
        record_id = record.id

    login(client, username="database.manager", password="Manager123!")
    detail = client.get(f"/enterprise/{record_id}")
    assert detail.status_code == 200
    assert b"Dev servers unavailable" in detail.data

    listing = client.get("/module/event")
    assert b"Dev servers unavailable" in listing.data

    search = client.get("/ui/search?q=EVT0009301")
    assert search.status_code == 200
    assert b"EVT0009301" in search.data


def test_enterprise_record_owning_team_can_manage_not_just_view(client, app):
    """Companion to the visibility fix: user_can_manage_enterprise_record()
    ignored the record's own support_group_id, so a Unix-team RT-imported
    record was viewable (after the visibility fix) but every edit still
    403'd until someone created an OperationalTask on it.
    """
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        record = EnterpriseRecord(
            number="EVT0009302", domain="event", record_type="RT Ticket",
            title="Disk almost full", description="Imported from RT",
            requester_id=admin.id, support_group_id=group_id(app), tenant_id=1,
        )
        db.session.add(record)
        db.session.commit()
        record_id = record.id

    login(client, username="database.manager", password="Manager123!")
    updated = client.post(f"/enterprise/{record_id}", data={
        "action": "update", "state": "In Progress", "priority": "P3", "risk": "Medium",
    })
    assert updated.status_code == 302
    with app.app_context():
        assert EnterpriseRecord.query.get(record_id).state == "In Progress"




def test_hr_record_not_leaked_to_unrelated_it_fulfillment_team(client, app):
    """The "any IT Fulfillment member sees everything" shortcut added for
    events/problems/releases must not extend to HR/Security/Risk/Customer --
    those carry sensitive content unrelated to IT support, and Unix/Windows/
    etc. are "IT Fulfillment" groups that have nothing to do with HR cases.
    """
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        record = EnterpriseRecord(
            number="HRC0009501", domain="hr", record_type="Benefits",
            title="Confidential benefits question", description="d",
            requester_id=employee.id, tenant_id=1,
        )
        db.session.add(record)
        db.session.commit()
        record_id = record.id

    login(client, username="database.manager", password="Manager123!")
    assert client.get(f"/enterprise/{record_id}").status_code == 403
    listing = client.get("/module/hr")
    assert b"Confidential benefits question" not in listing.data
    search = client.get("/ui/search?q=HRC0009501", headers={"Accept": "application/json"})
    assert search.json == {"results": []}


def test_requester_cannot_self_manage_their_own_enterprise_record(client, app):
    """Tickets never let the requester self-manage (only the owning team
    can) -- an EnterpriseRecord shouldn't either, otherwise an agent who
    files their own HR/security/risk case could set its own state/priority/
    risk/assignee and bypass whoever is actually supposed to review it.
    """
    with app.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        record = EnterpriseRecord(
            number="HRC0009502", domain="hr", record_type="Benefits",
            title="Self-filed benefits case", description="d",
            requester_id=manager.id, tenant_id=1,
        )
        db.session.add(record)
        db.session.commit()
        record_id = record.id

    login(client, username="database.manager", password="Manager123!")
    detail = client.get(f"/enterprise/{record_id}")
    assert detail.status_code == 200
    assert b"disabled" in detail.data.lower()
    blocked = client.post(f"/enterprise/{record_id}", data={
        "action": "update", "state": "Resolved", "priority": "P1", "risk": "Critical",
    })
    assert blocked.status_code == 403
    with app.app_context():
        assert EnterpriseRecord.query.get(record_id).state == "New"
