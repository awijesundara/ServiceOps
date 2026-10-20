"""Each kind of record counts on its own: no gaps from other kinds."""
from app import OperationalTask, Ticket, db
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_incident_hierarchy import _incident


def test_incident_numbers_do_not_skip_for_changes(client, app):
    login(client)
    _, _, first = _incident(client, app, "First incident")
    assert client.post("/tickets/new/change", data={
        "title": "A change in between", "description": "x", "category": "Software", "priority": "P3",
        "change_type": "Standard", "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": "2026-12-01T09:00", "planned_end": "2026-12-01T10:00"}).status_code == 302
    _, second_id, second = _incident(client, app, "Second incident")
    assert int(second[3:]) == int(first[3:]) + 1
    with app.app_context():
        change = Ticket.query.filter_by(kind="change").one()
        assert change.number == "CHG0000001"
        client.post(f"/incident/{second_id}/tasks", data={"title": "t", "group_id": group_id(app)})
        assert OperationalTask.query.filter_by(task_kind="incident").one().number == "ITASK0000001"
        assert db.session.get(Ticket, second_id).number == second
