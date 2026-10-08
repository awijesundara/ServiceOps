"""Ticket page behaviour: CIs chosen on the main form appear in the Affected CIs tab, and attachments accept drag and drop."""
import re

from app import ConfigurationItem, SupportGroup, Ticket, db
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
