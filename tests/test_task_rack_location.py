"""A data center engineer working from a task sees where the parent's devices sit."""
from app import ConfigurationItem, OperationalTask, Rack, TaskCI, db
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_incident_hierarchy import _incident


def test_task_page_shows_rack_location_of_affected_cis(client, app):
    login(client)
    _, ticket_id, _ = _incident(client, app, "Disk failed in DB host")
    with app.app_context():
        rack = Rack(name="B4-12", site="Tokyo DC1", u_height=42)
        ci = ConfigurationItem(name="DBHOST07", ci_class="Server", environment="Production")
        db.session.add_all([rack, ci])
        db.session.flush()
        ci.rack_id, ci.rack_position, ci.rack_face = rack.id, 22, "front"
        db.session.add(TaskCI(target_type="ticket", target_id=ticket_id, ci_id=ci.id, relationship_role="Affected CI"))
        db.session.commit()
    client.post(f"/incident/{ticket_id}/tasks", data={"title": "Swap disk", "group_id": group_id(app)})
    with app.app_context():
        task_id = OperationalTask.query.filter_by(parent_id=ticket_id, title="Swap disk").one().id
    page = client.get(f"/operational-task/{task_id}").get_data(as_text=True)
    assert "DBHOST07" in page and "B4-12 · Tokyo DC1 · U22, front" in page and "/racks/" in page
