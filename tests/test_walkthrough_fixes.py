"""Fixes from walking through the app as agents, approvers, managers and callers."""
from app import OperationalTask, Ticket, db
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_incident_hierarchy import _incident


def test_lists_open_on_open_work_with_one_click_views(client, app):
    login(client)
    _, open_id, open_number = _incident(client, app, "Still broken")
    _, closed_id, closed_number = _incident(client, app, "Long fixed")
    with app.app_context():
        db.session.get(Ticket, closed_id).state = "Closed"
        db.session.commit()
    client.get("/tickets/incident")  # shows and clears the "created" message
    page = client.get("/tickets/incident").get_data(as_text=True)
    assert open_number in page and closed_number not in page
    for view in ("Open", "Assigned to me", "My team", "Unassigned", "All"):
        assert f">{view}</a>" in page
    everything = client.get("/tickets/incident?filter=[]").get_data(as_text=True)
    assert closed_number in everything and open_number in everything


def test_a_team_task_can_be_taken_in_one_click(client, app):
    login(client)
    _, ticket_id, _ = _incident(client, app, "Needs a hand")
    client.post(f"/incident/{ticket_id}/tasks", data={"title": "Check logs", "group_id": group_id(app)})
    queue = client.get("/work/tasks").get_data(as_text=True)
    assert "Incident task" in queue and ">Take</button>" in queue
    with app.app_context():
        task = OperationalTask.query.filter_by(parent_id=ticket_id).one()
        task_id, notes = task.id, task.work_notes
    assert client.post(f"/work/tasks/operational/{task_id}/take").status_code == 302
    with app.app_context():
        task = db.session.get(OperationalTask, task_id)
        assert task.assignee.username == "admin" and task.work_notes == notes
    assert client.post(f"/work/tasks/operational/{task_id}/take", follow_redirects=True).status_code == 200


def test_approvers_see_their_decisions_with_a_summary(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Patch the app tier", "description": "x", "category": "Software", "priority": "P3",
        "change_type": "Standard", "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": "2026-12-01T09:00", "planned_end": "2026-12-01T10:00"}).status_code == 302
    client.get("/logout")
    login(client, "database.manager", "Manager123!")
    home = client.get("/").get_data(as_text=True)
    assert "Waiting for your approval" in home and "Patch the app tier" in home
    approvals = client.get("/approval-chains").get_data(as_text=True)
    assert "Window " in approvals and "risk 20" in approvals and "· ALL" not in approvals
    assert "every approver in this step decides" in approvals or "any one approver decides" in approvals


def test_manager_dashboard_starts_from_the_team_and_wording_fixes(client, app):
    login(client, "database.manager", "Manager123!")
    page = client.get("/dashboards", follow_redirects=True).get_data(as_text=True)
    assert "Created automatically" in page
    client.get("/logout")
    login(client)
    _, ticket_id, _ = _incident(client, app, "Clock wording")
    assert "Clock running" in client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    client.post(f"/incident/{ticket_id}/tasks", data={"title": "Block", "group_id": group_id(app, "Windows"),
                                                     "required": "1"})
    response = client.post(f"/ticket/{ticket_id}", data={"action": "update", "resolve": "1", "state": "New",
                                                         "resolution_notes": "Done.", "priority": "P3"},
                           follow_redirects=True)
    assert "for Windows is Open" in response.get_data(as_text=True)
