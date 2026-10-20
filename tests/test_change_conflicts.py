"""Open incidents never stop a change: a change is how they get fixed. Only
another change at the same time on the same or a dependent CI is a conflict."""
from app import ChangeGovernance, ConfigurationItem, RecordLink, SupportGroup, TaskCI, Ticket, db
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_incident_hierarchy import _incident


def _ci(app, name):
    with app.app_context():
        ci = ConfigurationItem(name=name, ci_class="Server", support_group_id=SupportGroup.query.filter_by(name="Unix").one().id)
        db.session.add(ci)
        db.session.commit()
        return ci.id


def _change(client, app, ci_id, title, start="2026-12-01T09:00", end="2026-12-01T10:00", **extra):
    return client.post("/tickets/new/change", data={
        "title": title, "description": "x", "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app, "Unix"), "implementation_plan": "i",
        "test_plan": "t", "backout_plan": "b", "planned_start": start, "planned_end": end, "ci_id": str(ci_id), **extra},
        follow_redirects=True)


def test_change_from_an_incident_is_created_and_knows_it_resolves_it(client, app):
    login(client)
    ci_id = _ci(app, "conflict-db")
    _, incident_id, number = _incident(client, app, "Database down", ci_id=ci_id)
    page = _change(client, app, ci_id, "Fix the database", from_incident=number).get_data(as_text=True)
    assert "created" in page and "the incident this change resolves" in page
    with app.app_context():
        change = Ticket.query.filter_by(title="Fix the database").one()
        assert RecordLink.query.filter_by(source_id=incident_id, target_id=change.id, link_type="resolution_change").one()
        status = ChangeGovernance.query.filter_by(ticket_id=change.id).one().conflict_status
        assert status.startswith("Open incidents") and number in status


def test_other_open_incidents_are_noted_not_blocking(client, app):
    login(client)
    ci_id = _ci(app, "noted-db")
    _, _, number = _incident(client, app, "Unrelated outage on the same box", ci_id=ci_id)
    page = _change(client, app, ci_id, "Routine patch").get_data(as_text=True)
    assert "Routine patch" in page and f"{number} (open incident on the same CI)" in page
    assert "Conflicts and open incidents" in page


def test_overlapping_changes_still_conflict_but_finished_ones_do_not(client, app):
    login(client)
    ci_id = _ci(app, "shared-app")
    assert "created" in _change(client, app, ci_id, "First change").get_data(as_text=True)
    clash = _change(client, app, ci_id, "Second change")
    assert "overlaps" in clash.get_data(as_text=True)
    with app.app_context():
        assert Ticket.query.filter_by(title="Second change").count() == 0
        Ticket.query.filter_by(title="First change").one().state = "Closed"
        db.session.commit()
    assert "created" in _change(client, app, ci_id, "Second change").get_data(as_text=True)
