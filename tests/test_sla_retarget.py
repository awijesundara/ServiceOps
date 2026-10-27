"""Changing priority moves a record's running SLAs to the new priority's targets without resetting the clock."""
from datetime import timedelta

from app import SLADefinition, SLAEvent, TaskSLA, Ticket, User, db, now, retarget_slas
from tests.test_app import app, client  # noqa: F401
from tests.test_priority_governance import api_headers, create, patch


def definitions(app):
    with app.app_context():
        for priority, minutes in (("P1", 60), ("P4", 4320)):
            db.session.add(SLADefinition(name=f"{priority} resolution", target_type="ticket", priority=priority,
                                         duration_minutes=minutes, tenant_id=1, active=True))
        db.session.commit()


def running(app, ticket_id):
    with app.app_context():
        return [(row.definition.priority, row.started_at, row.breach_at) for row in
                TaskSLA.query.filter_by(target_type="ticket", target_id=ticket_id).all()
                if row.stage not in ("Completed", "Cancelled")]


def test_raising_priority_keeps_the_start_time(app):
    definitions(app)
    with app.app_context():
        requester = User.query.filter_by(username="admin").one()
        ticket = Ticket(number="INC0088881", kind="incident", title="Slow", description="x", requester_id=requester.id,
                        tenant_id=1, state="New", priority="P4", impact="Low", urgency="Low")
        db.session.add(ticket)
        db.session.flush()
        from app import attach_slas
        attach_slas("ticket", ticket.id, "P4", started_at=now() - timedelta(minutes=30))
        original_start = min(row.started_at for row in TaskSLA.query.filter_by(target_id=ticket.id, target_type="ticket"))
        retarget_slas("ticket", ticket.id, "P1", ticket.state)
        db.session.commit()
        ticket_id = ticket.id
        cancelled = SLAEvent.query.filter(SLAEvent.details.like("Replaced: priority changed to P1")).count()
    rows = running(app, ticket_id)
    assert rows and {row[0] for row in rows} == {"P1"} and {row[1] for row in rows} == {original_start}
    assert any(breach - started == timedelta(minutes=60) for _, started, breach in rows)
    assert cancelled == 1


def test_api_priority_change_retargets(client, app):
    definitions(app)
    headers, group_id = api_headers(app, "agent")
    number = create(client, headers, group_id, impact="Low", urgency="Low").json["data"]["number"]
    with app.app_context():
        ticket_id = Ticket.query.filter_by(number=number).one().id
    assert {row[0] for row in running(app, ticket_id)} == {"P4"}
    assert patch(client, headers, number, impact="Critical", urgency="Critical").status_code == 200
    assert {row[0] for row in running(app, ticket_id)} == {"P1"}


def test_back_to_an_earlier_priority_restarts_its_sla(app):
    definitions(app)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ticket = Ticket(number="INC0088882", kind="incident", title="Flip", description="x", requester_id=admin.id,
                        tenant_id=1, state="New", priority="P1", impact="High", urgency="High")
        db.session.add(ticket)
        db.session.flush()
        from app import attach_slas
        attach_slas("ticket", ticket.id, "P1")
        retarget_slas("ticket", ticket.id, "P4", ticket.state)
        retarget_slas("ticket", ticket.id, "P1", ticket.state)
        db.session.commit()
        ticket_id = ticket.id
    assert {row[0] for row in running(app, ticket_id)} == {"P1"}


def test_a_pause_in_progress_is_carried_over(app):
    definitions(app)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ticket = Ticket(number="INC0088883", kind="incident", title="Paused", description="x", requester_id=admin.id,
                        tenant_id=1, state="Pending", priority="P4", impact="Low", urgency="Low")
        db.session.add(ticket)
        db.session.flush()
        from app import attach_slas
        attach_slas("ticket", ticket.id, "P4")
        for row in TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id):
            row.stage, row.paused_at = "Paused", now() - timedelta(hours=3)
        retarget_slas("ticket", ticket.id, "P1", "In Progress")
        db.session.commit()
        rows = [row for row in TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id)
                if row.stage != "Cancelled"]
        assert rows and all(row.paused_seconds >= 3 * 3600 - 5 for row in rows)
