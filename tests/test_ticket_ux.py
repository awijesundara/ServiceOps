"""Ticket page behaviour: CIs chosen on the main form appear in the Affected CIs tab, attachments accept drag and drop, and who may delete an attachment."""
import os
import re
from io import BytesIO

from werkzeug.security import generate_password_hash

from app import ConfigurationItem, FileAttachment, GroupMember, SupportGroup, TaskHistory, Ticket, User, db
from tests.test_app import app, client, group_id, login  # noqa: F401 - pytest fixtures and helpers


def section(html, section_id):
    match = re.search(rf'<section[^>]*id="{section_id}".*?</section>', html, re.S)
    assert match, f"#{section_id} not rendered"
    return match.group(0)


def add_ci(app, name, **fields):
    with app.app_context():
        ci = ConfigurationItem(name=name, ci_class="Server", environment="Production", **fields)
        db.session.add(ci)
        db.session.commit()
        return ci.id


def test_incident_primary_ci_from_the_form_is_listed_in_affected_cis(client, app):
    ci_id = add_ci(app, "payroll-app-01")
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Payroll slow", "description": "Batch overruns.", "impact": "High", "urgency": "High",
        "group_id": group_id(app), "ci_id": str(ci_id),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(kind="incident").one().id
    tab = section(client.get(f"/ticket/{ticket_id}").get_data(as_text=True), "affected-cis")
    assert "payroll-app-01" in tab
    assert "Primary CI" in tab
    assert "No configuration items or services are linked yet." not in tab


def test_change_primary_ci_is_listed_in_its_affected_cis_tab(client, app):
    with app.app_context():
        database = SupportGroup.query.filter_by(name="Database").one().id
    ci_id = add_ci(app, "ledger-db-02", support_group_id=database)
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Patch the ledger DB", "description": "Apply a patch.", "category": "Software",
        "priority": "P3", "change_type": "Normal", "risk_score": "40", "impact": "Medium",
        "implementation_plan": "Patch it.", "test_plan": "Verify it.", "backout_plan": "Roll back.",
        "planned_start": "2026-11-01T09:00", "planned_end": "2026-11-01T17:00",
        "group_id": group_id(app, "Unix"), "ci_id": str(ci_id),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(kind="change").one().id
    tab = section(client.get(f"/ticket/{ticket_id}").get_data(as_text=True), "gov-affected-cis")
    assert "ledger-db-02" in tab and "Primary CI" in tab
    assert "1 linked" in tab
    assert "No affected CIs linked." not in tab


def test_ticket_attachments_are_a_drop_target_and_still_post_without_script(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Printer jam", "description": "Paper stuck.", "impact": "Low", "urgency": "Low",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="incident").one()
        ticket_id, number = ticket.id, ticket.number
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    form = re.search(r'<form[^>]*data-attachment-drop="([^"]+)"[^>]*>', section(page, "attachments"))
    assert form and form.group(1) == number
    assert 'action="/ticket/%d/attachments"' % ticket_id in form.group(0)
    assert "attachment-drop.js" in page
    # Only ticket pages load the script.
    assert "attachment-drop.js" not in client.get("/").get_data(as_text=True)


# --- Attachment deletion permissions -------------------------------------------------


def make_user(app, username, role, *, group=None, group_role="member"):
    with app.app_context():
        user = User(username=username, name=username.title(), email=f"{username}@test.invalid",
                    password_hash=generate_password_hash("Passw0rd!x"), role=role)
        db.session.add(user)
        db.session.flush()
        if group:
            db.session.add(GroupMember(group_id=SupportGroup.query.filter_by(name=group).one().id,
                                       user_id=user.id, role=group_role))
        db.session.commit()
        return user.id


def as_user(client, username, password="Passw0rd!x"):
    client.post("/logout")
    login(client, username, password)


def incident_with_attachment(client, app, *, requester=("employee", "Employee123!")):
    as_user(client, *requester)
    client.post("/tickets/new/incident", data={
        "title": "Laptop broken", "description": "Screen cracked.", "impact": "Low", "urgency": "Low",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Laptop broken").order_by(Ticket.id.desc()).first().id
    client.post(f"/ticket/{ticket_id}/attachments", data={"file": (BytesIO(b"photo"), "evidence.txt")},
                content_type="multipart/form-data")
    with app.app_context():
        attachment = FileAttachment.query.filter_by(ticket_id=ticket_id).one()
        return ticket_id, attachment.id, attachment.stored_name


def delete(client, attachment_id):
    return client.post(f"/attachments/{attachment_id}/delete")


def test_uploader_sees_the_button_and_deletes_with_history_and_file_removed(client, app):
    ticket_id, attachment_id, stored_name = incident_with_attachment(client, app)
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert f'action="/attachments/{attachment_id}/delete"' in page and "data-confirm=" in page
    response = delete(client, attachment_id)
    assert response.status_code == 302 and response.location.endswith("#attachments")
    with app.app_context():
        assert db.session.get(FileAttachment, attachment_id) is None
        assert TaskHistory.query.filter_by(target_type="ticket", target_id=ticket_id, event="Attachment deleted").one()
        assert not os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], stored_name))


def test_people_without_a_link_to_the_ticket_cannot_delete(client, app):
    ticket_id, attachment_id, _ = incident_with_attachment(client, app)
    make_user(app, "outsider.agent", "agent", group="Windows")
    as_user(client, "outsider.agent")
    assert f"/attachments/{attachment_id}/delete" not in client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert delete(client, attachment_id).status_code == 403
    with app.app_context():
        assert db.session.get(FileAttachment, attachment_id) is not None


def test_owning_team_member_manager_role_and_executive_can_delete(client, app):
    make_user(app, "team.agent", "agent", group="CoreApps")
    ticket_id, first, _ = incident_with_attachment(client, app)
    as_user(client, "team.agent")
    assert delete(client, first).status_code == 302

    _, second, _ = incident_with_attachment(client, app)
    as_user(client, "database.manager", "Manager123!")  # manager role, not on the owning team
    assert delete(client, second).status_code == 302

    # An executive approver with only requester authority, on a ticket they raised.
    make_user(app, "ceo", "requester", group="Executive Office", group_role="executive approver")
    _, third, _ = incident_with_attachment(client, app, requester=("ceo", "Passw0rd!x"))
    with app.app_context():
        attachment = db.session.get(FileAttachment, third)
        attachment.uploaded_by_id = User.query.filter_by(username="admin").one().id  # someone else's file
        db.session.commit()
    as_user(client, "ceo")
    assert delete(client, third).status_code == 302


def test_resolved_tickets_keep_their_files_except_for_administrators(client, app):
    make_user(app, "team.agent2", "agent", group="CoreApps")
    ticket_id, attachment_id, _ = incident_with_attachment(client, app)
    with app.app_context():
        db.session.get(Ticket, ticket_id).state = "Resolved"
        db.session.commit()
    as_user(client, "team.agent2")
    assert delete(client, attachment_id).status_code == 403
    as_user(client, "admin", "Admin123!")
    assert delete(client, attachment_id).status_code == 302
