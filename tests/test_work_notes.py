"""Work notes stay with the support teams; the caller sees replies, her own
plain summary, and is told when the team waits for her."""
from io import BytesIO

from app import (APIClient, Comment, FileAttachment, Notification, Ticket, User, create_api_token, db)
from tests.test_app import app, client, login  # noqa: F401
from tests.test_incident_hierarchy import _incident, _update


def _setup(client, app):
    login(client)
    with app.app_context():
        caller_id = User.query.filter_by(username="employee").one().id
    _, ticket_id, number = _incident(client, app, "Mail not syncing", caller_id=caller_id)
    return ticket_id, number, caller_id


def _as_caller(client):
    client.get("/logout")
    login(client, "employee", "Employee123!")


def test_work_notes_are_hidden_from_the_caller_and_replies_are_not(client, app):
    ticket_id, _, caller_id = _setup(client, app)
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert 'name="visibility" value="internal" checked' in page
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Suspect her mailbox quota, check @employee"})
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "We are looking into it.", "visibility": "public"})
    agent_page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "Suspect her mailbox quota" in agent_page and "Work note · only support teams see this" in agent_page
    with app.app_context():
        titles = [n.title for n in Notification.query.filter_by(user_id=caller_id)]
        assert not any("work note" in t.lower() or "mentioned" in t.lower() for t in titles)
        assert any("New comment" in t for t in titles)
    _as_caller(client)
    caller_page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "Suspect her mailbox quota" not in caller_page and "We are looking into it." in caller_page
    assert 'name="visibility"' not in caller_page and "Write a reply to the support team" in caller_page
    # A caller cannot reply into a work note thread or post one herself.
    with app.app_context():
        note_id = Comment.query.filter_by(ticket_id=ticket_id, internal=True).one().id
    assert client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "x", "parent_id": note_id}).status_code == 400
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "My own note", "visibility": "internal"})
    with app.app_context():
        assert Comment.query.filter_by(ticket_id=ticket_id, body="My own note").one().internal is False


def test_files_on_work_notes_are_hidden_from_the_caller(client, app):
    ticket_id, _, _ = _setup(client, app)
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Trace attached.",
                                              "file": (BytesIO(b"secret trace"), "trace.log")},
                content_type="multipart/form-data")
    with app.app_context():
        attachment_id = FileAttachment.query.filter_by(ticket_id=ticket_id).one().id
    assert client.get(f"/attachments/{attachment_id}").status_code == 200
    _as_caller(client)
    assert client.get(f"/attachments/{attachment_id}").status_code == 404
    assert "trace.log" not in client.get(f"/ticket/{ticket_id}").get_data(as_text=True)


def test_api_respects_work_notes(client, app):
    ticket_id, number, _ = _setup(client, app)
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Internal only"})
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Visible reply", "visibility": "public"})
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(name="Caller app", token_prefix=prefix, token_hash=token_hash,
                                 scopes_json='["tickets:read","tickets:update"]', acting_user_id=employee.id,
                                 created_by_id=employee.id))
        db.session.commit()
    rows = client.get(f"/api/v1/tickets/{number}/comments", headers={"Authorization": f"Bearer {token}"}).json["data"]
    bodies = [row["body"] for row in rows]
    assert "Visible reply" in bodies and "Internal only" not in bodies


def test_caller_sees_a_plain_summary_and_when_the_team_waits_for_her(client, app):
    ticket_id, number, _ = _setup(client, app)
    assert _update(client, ticket_id, state="Pending", hold_reason="Awaiting caller").status_code == 302
    _as_caller(client)
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "The support team is waiting for your reply." in page and 'class="caller-summary"' in page
    for internal in ('id="incident-record-form"', 'id="incident-tasks"', 'id="child-incidents"', 'id="related-records"',
                     "Team manager"):
        assert internal not in page, internal
    reply = client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Here you go."}, follow_redirects=True)
    assert "Your reply was sent" in reply.get_data(as_text=True)
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "In Progress"


def test_employee_home_shows_her_own_work_and_what_waits_on_her(client, app):
    ticket_id, number, _ = _setup(client, app)
    assert _update(client, ticket_id, state="Pending", hold_reason="Awaiting caller").status_code == 302
    _as_caller(client)
    page = client.get("/").get_data(as_text=True)
    assert "My open incidents" in page and number in page and "My requests" in page
    assert "Get help" in page and "Request something" in page and "Find an answer" in page
    assert "waiting for your reply" in page
    assert "Open changes" not in page and "Assigned to me" not in page
