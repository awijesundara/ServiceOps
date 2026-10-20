"""Records in a workspace (HR, security, ...) reach the team that handles it,
and nobody else outside the requester."""
from werkzeug.security import generate_password_hash

from app import EnterpriseRecord, GroupMember, Notification, SupportGroup, User, WorkspaceTeam, db
from tests.test_app import app, client, login  # noqa: F401


def _hr_team(app):
    with app.app_context():
        team = SupportGroup(name="HR Services", group_type="Fulfillment", tenant_id=1)
        db.session.add(team)
        db.session.flush()
        member = User(username="hr.agent", name="HR Agent", email="hr@test.invalid", role="agent",
                      password_hash=generate_password_hash("HrAgent123!x"))
        db.session.add(member)
        db.session.flush()
        db.session.add(GroupMember(group_id=team.id, user_id=member.id, role="member"))
        db.session.commit()
        return team.id


def test_hr_case_reaches_hr_and_stays_private(client, app):
    team_id = _hr_team(app)
    login(client)
    page = client.get("/admin/workspace-teams").get_data(as_text=True)
    assert "HR service delivery" in page and "No team" in page
    # A case raised before a team was set is handed over when the team is chosen.
    client.get("/logout")
    login(client, "employee", "Employee123!")
    form = client.get("/module/hr/new").get_data(as_text=True)
    assert "No team handles HR service delivery yet" in form and 'name="priority"' not in form
    client.post("/module/hr/new", data={"record_type": "Payroll", "title": "Early case", "description": "x"})
    client.get("/logout")
    login(client)
    assert client.post("/admin/workspace-teams", data={"domain": "hr", "group_id": team_id,
                                                        "assign_existing": "1"}).status_code == 302
    with app.app_context():
        assert EnterpriseRecord.query.filter_by(title="Early case").one().support_group_id == team_id
        assert WorkspaceTeam.query.filter_by(domain="hr").one().group_id == team_id
    client.get("/logout")
    login(client, "employee", "Employee123!")
    assert "HR Services handles HR service delivery" in client.get("/module/hr/new").get_data(as_text=True)
    created = client.post("/module/hr/new", data={"record_type": "Payroll", "title": "Salary paid short",
                                                  "description": "40,000 yen missing"}, follow_redirects=True)
    assert "HR Services will handle it." in created.get_data(as_text=True)
    with app.app_context():
        record = EnterpriseRecord.query.filter_by(title="Salary paid short").one()
        record_id = record.id
        assert record.support_group_id == team_id and record.priority == "P3"
        hr_agent = User.query.filter_by(username="hr.agent").one()
        assert Notification.query.filter_by(user_id=hr_agent.id, target_id=record_id).count() == 1
    client.get("/logout")
    login(client, "hr.agent", "HrAgent123!x")
    assert client.get(f"/enterprise/{record_id}").status_code == 200
    assert "Salary paid short" in client.get("/module/hr").get_data(as_text=True)
    # An IT manager outside HR never sees the case.
    client.get("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.get(f"/enterprise/{record_id}").status_code == 403
    assert "Salary paid short" not in client.get("/module/hr").get_data(as_text=True)
