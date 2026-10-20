"""People on the support side hear about work that reaches them."""
from app import GroupMember, Notification, SupportGroup, TicketFollower, User, db
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_incident_hierarchy import _incident


def _titles(app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        return [n.title for n in Notification.query.filter_by(user_id=user.id)]


def test_team_hears_of_new_incidents_tasks_reassignment_and_caller_replies(client, app):
    with app.app_context():
        windows = SupportGroup.query.filter_by(name="Windows").one()

        employee = User.query.filter_by(username="employee").one()
        db.session.add(User(username="win.agent", name="Win Agent", email="w@test.invalid", role="agent",
                            password_hash=employee.password_hash))
        db.session.flush()
        db.session.add(GroupMember(group_id=windows.id, user_id=User.query.filter_by(username="win.agent").one().id,
                                   role="member"))
        db.session.commit()
        caller_id = employee.id
    login(client)
    _, ticket_id, number = _incident(client, app, "Printer offline", caller_id=caller_id)
    assert any(f"New incident for CoreApps: {number}" == t for t in _titles(app, "database.manager"))
    with app.app_context():
        followers = {db.session.get(User, row.user_id).username
                     for row in TicketFollower.query.filter_by(ticket_id=ticket_id)}
        assert followers >= {"employee", "admin"}
    client.post(f"/incident/{ticket_id}/tasks", data={"title": "Check driver", "group_id": group_id(app, "Windows")})
    assert any(t.startswith("New task for Windows") for t in _titles(app, "win.agent"))
    client.get("/logout")
    login(client, "employee", "Employee123!")
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Still offline."})
    assert any(t == f"The caller replied on {number}" for t in _titles(app, "database.manager"))
    client.get("/logout")
    login(client)
    client.post(f"/ticket/{ticket_id}", data={"action": "reassign_team", "new_group_id": group_id(app, "Windows")})
    assert any(t == f"{number} was reassigned to Windows" for t in _titles(app, "win.agent"))
