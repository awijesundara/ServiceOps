"""Manager portal numbers open the matching tickets and tasks."""
import json
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from werkzeug.security import generate_password_hash

from app import GroupMember, OperationalTask, SupportGroup, Ticket, TicketAssignmentGroup, User, db, now
from tests.test_app import app, client, login  # noqa: F401


def _member_with_work(app):
    with app.app_context():
        database = SupportGroup.query.filter_by(name="Database").one()
        agent = User(username="portal.agent", name="Portal Agent", email="portal.agent@test.invalid", role="agent",
                     password_hash=generate_password_hash("PortalAgent123!"))
        db.session.add(agent)
        db.session.flush()
        db.session.add(GroupMember(group_id=database.id, user_id=agent.id))
        requester = User.query.filter_by(username="employee").one()
        for number, kind, state in (("INC9100001", "incident", "In Progress"), ("INC9100002", "incident", "New"),
                                    ("INC9100003", "incident", "Resolved"), ("CHG9100001", "change", "New")):
            ticket = Ticket(number=number, kind=kind, title=f"Portal {number}", description="d", state=state,
                            requester_id=requester.id, assignee_id=agent.id,
                            resolved_at=now() - timedelta(days=2) if state == "Resolved" else None)
            db.session.add(ticket)
            db.session.flush()
            db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=database.id))
        db.session.add(OperationalTask(number="PTASK9100001", task_kind="problem", parent_type="enterprise",
                                       parent_id=1, title="Portal task", task_type="Investigation", state="Open",
                                       sequence=1, assignment_group_id=database.id, assignee_id=agent.id))
        db.session.commit()
        return agent.id


def test_portal_numbers_link_to_the_filtered_lists(client, app):
    agent_id = _member_with_work(app)
    login(client, "database.manager", "Manager123!")
    page = client.get("/manager/portal").data.decode()
    incidents_url = next(part for part in page.split('href="')[1:]
                         if part.startswith("/tickets/incident?") and f'%22{agent_id}%22' in part.split('"')[0]
                         and "open" in part.split('"')[0]).split('"')[0].replace("&amp;", "&")
    conditions = json.loads(parse_qs(urlparse(incidents_url).query)["filter"][0])
    assert {"field": "assignee", "op": "eq", "value": str(agent_id)} in conditions
    listing = client.get(incidents_url).data.decode()
    assert "INC9100001" in listing and "INC9100002" in listing and "INC9100003" not in listing
    assert "Portal Agent" in listing  # breadcrumb names the assignee
    resolved = client.get(f'/tickets/incident?filter=[{{"field":"assignee","op":"eq","value":"{agent_id}"}},'
                          '{"field":"resolved_within_days","op":"eq","value":"30"}]').data.decode()
    assert "INC9100003" in resolved and "INC9100001" not in resolved
    assert f'/work/tasks?assignee={agent_id}' in page
    tasks = client.get(f"/work/tasks?assignee={agent_id}").data.decode()
    assert "PTASK9100001" in tasks and "Portal Agent" in tasks


def test_only_the_members_manager_can_open_their_task_queue(client, app):
    agent_id = _member_with_work(app)
    login(client, "employee", "Employee123!")
    assert client.get(f"/work/tasks?assignee={agent_id}").status_code == 403
