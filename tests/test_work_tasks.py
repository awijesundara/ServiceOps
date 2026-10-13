"""My tasks (/work/tasks): "My teams' open tasks" lists only the teams the
user belongs to or manages, for every role (administrators used to get
every team's tasks there)."""
from werkzeug.security import generate_password_hash

from app import GroupMember, OperationalTask, SupportGroup, User, db
from tests.test_app import app, client, login  # noqa: F401


def task(number, group, title, assignee=None, state="Open"):
    return OperationalTask(number=number, task_kind="event", parent_type="ticket", parent_id=1, title=title,
                           task_type="Investigation", state=state, assignment_group_id=group.id,
                           assignee_id=assignee.id if assignee else None)


def test_team_tasks_are_limited_to_the_users_own_teams(app, client):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        mine = SupportGroup(name="Queue Team A", group_type="IT Fulfillment", tenant_id=admin.tenant_id)
        other = SupportGroup(name="Queue Team B", group_type="IT Fulfillment", tenant_id=admin.tenant_id)
        db.session.add_all([mine, other]); db.session.flush()
        agent = User(username="queue.agent", name="Queue Agent", email="queue.agent@test.invalid", role="agent",
                     password_hash=generate_password_hash("Agent123!"), tenant_id=admin.tenant_id)
        db.session.add(agent); db.session.flush()
        db.session.add(GroupMember(group_id=mine.id, user_id=agent.id, role="member"))
        db.session.add_all([
            task("QT0000001", mine, "Own team task"),
            task("QT0000002", other, "Other team task"),
            task("QT0000003", other, "Admin's own task", assignee=admin),
            task("QT0000004", mine, "Finished own team task", state="Closed Complete"),
        ])
        db.session.commit()

    login(client, "queue.agent", "Agent123!")
    page = client.get("/work/tasks").get_data(as_text=True)
    assert "Own team task" in page
    assert "Other team task" not in page
    assert "Finished own team task" not in page
    client.post("/logout")

    login(client)  # an administrator in neither team
    page = client.get("/work/tasks").get_data(as_text=True)
    assert "Admin&#39;s own task" in page or "Admin's own task" in page  # assigned to them
    assert "Other team task" not in page and "Own team task" not in page
