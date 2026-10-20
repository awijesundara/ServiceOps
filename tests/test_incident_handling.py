"""Incident handling: caller and opener, hold reasons, incident tasks, problems and
changes raised from an incident, parent updates reaching children, assignment rules,
templates, similar incidents and the reassignment and reopen counts."""
from werkzeug.security import generate_password_hash

from app import (APIClient, AssignmentRule, Comment, ConfigurationItem, EnterpriseRecord, IncidentTemplate,
                 OperationalTask, RecordLink, SupportGroup, TaskCI, TaskHistory, Tenant, Ticket, User,
                 create_api_token, db, ticket_owning_group)
from serviceops_core import incident_handling
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_incident_hierarchy import _incident, _update


def _ticket(app, ticket_id):
    with app.app_context():
        row = db.session.get(Ticket, ticket_id)
        db.session.expunge(row)
        return row


def _user_id(app, username):
    with app.app_context():
        return User.query.filter_by(username=username).one().id


def _api_token(app, scopes='["tickets:read","tickets:update"]'):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(name="Incident handling", token_prefix=prefix, token_hash=token_hash,
                                 scopes_json=scopes, acting_user_id=admin.id, created_by_id=admin.id))
        db.session.commit()
    return token


# --- caller and opened by -----------------------------------------------------------------------

def test_agent_logs_an_incident_for_a_caller(client, app):
    login(client)
    employee_id = _user_id(app, "employee")
    response, ticket_id, _ = _incident(client, app, "Printer jams on floor 3", caller_id=employee_id)
    assert response.status_code == 302
    ticket = _ticket(app, ticket_id)
    assert ticket.requester_id == employee_id
    assert ticket.opened_by_id == _user_id(app, "admin")
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "Opened by" in page and 'name="caller_id" value="%d"' % employee_id in page
    # Without a caller the person logging it is the caller.
    _, own_id, _ = _incident(client, app, "My own laptop is slow")
    own = _ticket(app, own_id)
    assert own.requester_id == own.opened_by_id == _user_id(app, "admin")


def test_caller_change_is_recorded_and_requesters_cannot_choose_one(client, app):
    login(client)
    _, ticket_id, _ = _incident(client, app, "VPN drops every hour")
    employee_id = _user_id(app, "employee")
    assert _update(client, ticket_id, caller_id=str(employee_id)).status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).requester_id == employee_id
        assert TaskHistory.query.filter_by(target_type="ticket", target_id=ticket_id, field_name="caller").one().new_value \
            == "Test Employee"
    # An unknown caller is refused and changes nothing.
    assert _update(client, ticket_id, caller_id="999999").status_code == 302
    assert _ticket(app, ticket_id).requester_id == employee_id
    # A requester cannot log an incident for someone else.
    client.get("/logout")
    login(client, "employee", "Employee123!")
    admin_id = _user_id(app, "admin")
    client.post("/tickets/new/incident", data={"title": "Requester logged", "description": "x",
                                               "category": "Software / Application", "group_id": group_id(app), "caller_id": admin_id})
    with app.app_context():
        assert Ticket.query.filter_by(title="Requester logged").one().requester_id == _user_id(app, "employee")
    assert client.get("/internal/lookup/users?q=adm").status_code == 403


def test_user_lookup_is_tenant_scoped_and_active_only(client, app):
    login(client)
    with app.app_context():
        other = Tenant(slug="other-callers", name="Other callers")
        db.session.add(other)
        db.session.flush()
        db.session.add_all([
            User(username="callerx.other", name="Callerx Other", email="o@test.invalid", tenant_id=other.id,
                 password_hash=generate_password_hash("Other123!x"), role="requester"),
            User(username="callerx.gone", name="Callerx Gone", email="g@test.invalid", active=False,
                 password_hash=generate_password_hash("Gone123!x"), role="requester"),
            User(username="callerx.here", name="Callerx Here", email="h@test.invalid",
                 password_hash=generate_password_hash("Here123!x"), role="requester"),
        ])
        db.session.commit()
    rows = client.get("/internal/lookup/users?q=callerx").json
    assert [row["label"] for row in rows] == ["Callerx Here (callerx.here)"]
    assert client.get("/internal/lookup/users?q=c").json == []


# --- hold reasons -------------------------------------------------------------------------------

def test_pending_requires_a_hold_reason_and_other_states_clear_it(client, app):
    login(client)
    _, ticket_id, _ = _incident(client, app, "Waiting on the vendor")
    assert _update(client, ticket_id, state="Pending", hold_reason="").status_code == 302
    assert _ticket(app, ticket_id).state == "New"
    assert _update(client, ticket_id, state="Pending", hold_reason="Made up").status_code == 302
    assert _ticket(app, ticket_id).state == "New"
    assert _update(client, ticket_id, state="Pending", hold_reason="Awaiting vendor").status_code == 302
    ticket = _ticket(app, ticket_id)
    assert (ticket.state, ticket.hold_reason) == ("Pending", "Awaiting vendor")
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert '<option value="Awaiting vendor" selected>' in page
    with app.app_context():
        assert TaskHistory.query.filter_by(target_type="ticket", target_id=ticket_id, field_name="hold reason").one() \
            .new_value == "Awaiting vendor"
    assert _update(client, ticket_id, state="In Progress").status_code == 302
    ticket = _ticket(app, ticket_id)
    assert (ticket.state, ticket.hold_reason) == ("In Progress", None)


def test_caller_reply_resumes_an_incident_awaiting_the_caller(client, app):
    login(client)
    employee_id = _user_id(app, "employee")
    _, ticket_id, _ = _incident(client, app, "Need your screenshot", caller_id=employee_id)
    assert _update(client, ticket_id, state="Pending", hold_reason="Awaiting caller").status_code == 302
    # A comment from someone else keeps it waiting.
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Any news?"})
    assert _ticket(app, ticket_id).state == "Pending"
    client.get("/logout")
    login(client, "employee", "Employee123!")
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Screenshot attached."})
    ticket = _ticket(app, ticket_id)
    assert (ticket.state, ticket.hold_reason) == ("In Progress", None)


def test_caller_reply_does_not_resume_when_waiting_for_a_vendor(client, app):
    login(client)
    employee_id = _user_id(app, "employee")
    _, ticket_id, _ = _incident(client, app, "Vendor fix pending", caller_id=employee_id)
    assert _update(client, ticket_id, state="Pending", hold_reason="Awaiting vendor").status_code == 302
    client.get("/logout")
    login(client, "employee", "Employee123!")
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Still broken."})
    assert _ticket(app, ticket_id).state == "Pending"


def test_api_hold_reason_defaults_validates_and_is_reported(client, app):
    login(client)
    _, ticket_id, number = _incident(client, app, "API hold reason")
    token = _api_token(app)
    patch = lambda body, key: client.patch(f"/api/v1/tickets/{number}", json=body,
                                           headers={"Authorization": f"Bearer {token}", "Idempotency-Key": key})
    assert patch({"state": "In Progress", "hold_reason": "Awaiting vendor"}, "h0").status_code == 400
    assert patch({"state": "Pending", "hold_reason": "Nope"}, "h1").status_code == 400
    response = patch({"state": "Pending"}, "h2")
    assert response.status_code == 200 and response.json["data"]["hold_reason"] == "Awaiting caller"
    response = patch({"hold_reason": "Awaiting change"}, "h3")
    assert response.status_code == 200 and response.json["data"]["hold_reason"] == "Awaiting change"
    data = client.get(f"/api/v1/tickets/{number}", headers={"Authorization": f"Bearer {token}"}).json["data"]
    assert data["caller"]["name"] == data["opened_by"]["name"]
    assert (data["reassignment_count"], data["reopen_count"], data["parent_incident"]) == (0, 0, None)


# --- incident tasks -----------------------------------------------------------------------------

def test_required_incident_task_blocks_resolution_until_finished(client, app):
    login(client)
    _, ticket_id, number = _incident(client, app, "Network and app both broken")
    windows_id = group_id(app, "Windows")
    response = client.post(f"/incident/{ticket_id}/tasks", data={
        "title": "Check the switch firmware", "group_id": windows_id, "required": "1", "due_at": "2026-12-01T10:00"})
    assert response.status_code == 302 and response.headers["Location"].endswith("#incident-tasks")
    with app.app_context():
        task = OperationalTask.query.filter_by(parent_type="ticket", parent_id=ticket_id).one()
        task_id, task_number = task.id, task.number
        assert task_number.startswith("ITASK") and task.task_kind == "incident" and task.required
        assert task.planned_end is not None and task.assignment_group_id == windows_id
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "Incident tasks (1)" in page and task_number in page
    task_page = client.get(f"/operational-task/{task_id}").get_data(as_text=True)
    assert "Incident Task" in task_page and number in task_page
    assert _update(client, ticket_id, resolve="1", resolution_notes="Fixed.").status_code == 302
    assert _ticket(app, ticket_id).state != "Resolved"
    assert client.post(f"/operational-task/{task_id}", data={"state": "Closed Complete", "work_notes": "Done."}) \
        .status_code == 302
    assert _update(client, ticket_id, resolve="1", resolution_notes="Fixed.").status_code == 302
    assert _ticket(app, ticket_id).state == "Resolved"
    # A resolved incident takes no new tasks.
    assert client.post(f"/incident/{ticket_id}/tasks", data={"title": "Late", "group_id": windows_id}).status_code == 409


def test_optional_incident_task_and_task_validation(client, app):
    login(client)
    _, ticket_id, _ = _incident(client, app, "Optional follow-up")
    team = group_id(app)
    assert client.post(f"/incident/{ticket_id}/tasks", data={"title": "", "group_id": team}).status_code == 400
    assert client.post(f"/incident/{ticket_id}/tasks", data={"title": "x", "group_id": team, "due_at": "soon"}) \
        .status_code == 400
    assert client.post(f"/incident/{ticket_id}/tasks", data={"title": "Nice to have", "group_id": team}).status_code == 302
    assert _update(client, ticket_id, resolve="1", resolution_notes="Fixed.").status_code == 302
    assert _ticket(app, ticket_id).state == "Resolved"
    client.get("/logout")
    login(client, "employee", "Employee123!")
    assert client.post(f"/incident/{ticket_id}/tasks", data={"title": "x", "group_id": team}).status_code == 403


# --- problem and change from an incident --------------------------------------------------------

def test_create_problem_from_incident_links_it_and_copies_cis(client, app):
    login(client)
    with app.app_context():
        ci = ConfigurationItem(name="mail-gw-01", ci_class="Server", support_group_id=group_id(app))
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    _, ticket_id, number = _incident(client, app, "Mail gateway keeps crashing", ci_id=ci_id)
    response = client.post(f"/incident/{ticket_id}/problem")
    assert response.status_code == 302
    with app.app_context():
        link = RecordLink.query.filter_by(source_type="ticket", source_id=ticket_id, link_type="underlying_problem").one()
        problem = db.session.get(EnterpriseRecord, link.target_id)
        assert problem.domain == "problem" and problem.title == "Mail gateway keeps crashing"
        assert number in problem.description and problem.problem_profile is not None
        assert TaskCI.query.filter_by(target_type="enterprise", target_id=problem.id, ci_id=ci_id).count() == 1
        assert response.headers["Location"].endswith(f"/enterprise/{problem.id}")
    assert client.post(f"/incident/{ticket_id}/problem").status_code == 409
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "Problem from this incident" not in page and "Change from this incident" in page


def test_create_change_from_incident_prefills_and_links(client, app):
    login(client)
    _, ticket_id, number = _incident(client, app, "Disk full on db-02")
    form = client.get(f"/tickets/new/change?from_incident={number}").get_data(as_text=True)
    assert "Disk full on db-02" in form and f'name="from_incident" value="{number}"' in form
    assert client.get("/tickets/new/change?from_incident=INC9999999").status_code == 404
    assert client.post("/tickets/new/change", data={
        "title": "Grow db-02 volume", "description": "Add 200 GB.", "category": "Software / Application", "priority": "P3",
        "change_type": "Standard", "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Extend LVM.", "test_plan": "Check df.", "backout_plan": "Restore snapshot.",
        "planned_start": "2026-12-01T10:00", "planned_end": "2026-12-01T11:00", "from_incident": number,
    }).status_code == 302
    with app.app_context():
        change = Ticket.query.filter_by(title="Grow db-02 volume").one()
        assert RecordLink.query.filter_by(source_type="ticket", source_id=ticket_id, target_type="ticket",
                                          target_id=change.id, link_type="resolution_change").one()


# --- parent updates to children -----------------------------------------------------------------

def test_parent_comment_and_resolution_reach_children(client, app):
    login(client)
    _, parent_id, parent_number = _incident(client, app, "Datacenter power loss")
    _, child_id, _ = _incident(client, app, "Website down", parent_incident=parent_number)
    _, closed_child_id, _ = _incident(client, app, "Old duplicate", parent_incident=parent_number)
    with app.app_context():
        db.session.get(Ticket, closed_child_id).state = "Cancelled"
        db.session.commit()
    page = client.get(f"/ticket/{parent_id}").get_data(as_text=True)
    assert "Also post to all 2 child incidents" in page and "Parent of 2 incidents" in page
    assert "Child of" in client.get(f"/ticket/{child_id}").get_data(as_text=True)
    client.post(f"/ticket/{parent_id}", data={"action": "comment", "body": "Generators are on.", "copy_to_children": "1"})
    with app.app_context():
        bodies = [row.body for row in Comment.query.filter_by(ticket_id=child_id)]
        assert any("Generators are on." in body and parent_number in body for body in bodies)
        assert Comment.query.filter_by(ticket_id=closed_child_id).count() == 0
    # Without the box ticked the comment stays on the parent.
    client.post(f"/ticket/{parent_id}", data={"action": "comment", "body": "Internal only."})
    with app.app_context():
        assert not any("Internal only." in row.body for row in Comment.query.filter_by(ticket_id=child_id))
    assert _update(client, parent_id, resolve="1", resolution_notes="Power restored.").status_code == 302
    child = _ticket(app, child_id)
    assert child.state == "Resolved" and child.resolution_notes == "Power restored."


# --- assignment rules ---------------------------------------------------------------------------

def test_assignment_rules_admin_crud_order_and_validation(client, app):
    login(client)
    windows, core_apps = group_id(app, "Windows"), group_id(app)
    page = client.get("/admin/incident-handling")
    assert page.status_code == 200 and b"Assignment rules" in page.data
    post = lambda **data: client.post("/admin/incident-handling", data=data)
    assert post(action="save_rule", name="Hardware", group_id=windows, category="Hardware").status_code == 302
    assert post(action="save_rule", name="Software", group_id=core_apps, category="Software / Application").status_code == 302
    assert post(action="save_rule", name="No condition", group_id=core_apps).status_code == 400
    assert post(action="save_rule", name="Typo", group_id=core_apps, category="Sofware").status_code == 400
    assert post(action="save_rule", name="Wrong sub", group_id=core_apps, category="Hardware",
                subcategory="No such subcategory").status_code == 400
    assert post(action="save_rule", name="", group_id=core_apps, category="Software / Application").status_code == 400
    with app.app_context():
        names = [rule.name for rule in incident_handling.rules(1)]
        assert names == ["Hardware", "Software"]
        software_id = AssignmentRule.query.filter_by(name="Software").one().id
    assert post(action="move_rule", rule_id=software_id, direction="up").status_code == 302
    with app.app_context():
        assert [rule.name for rule in incident_handling.rules(1)] == ["Software", "Hardware"]
    assert post(action="save_rule", rule_id=software_id, name="Software apps", group_id=core_apps,
                category="Software / Application", active="0").status_code == 302
    with app.app_context():
        rule = db.session.get(AssignmentRule, software_id)
        assert (rule.name, rule.active) == ("Software apps", False)
    assert post(action="delete_rule", rule_id=software_id).status_code == 302
    with app.app_context():
        assert [(rule.name, rule.position) for rule in incident_handling.rules(1)] == [("Hardware", 0)]
    assert post(action="delete_rule", rule_id=999999).status_code == 404
    assert post(action="explode").status_code == 400
    client.get("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.get("/admin/incident-handling").status_code == 403


def test_automatic_assignment_uses_rules_then_ci_group(client, app):
    login(client)
    windows, core_apps = group_id(app, "Windows"), group_id(app)
    client.post("/admin/incident-handling", data={"action": "save_rule", "name": "Hardware to Windows",
                                                 "group_id": windows, "category": "Hardware"})
    client.post("/admin/incident-handling", data={"action": "save_rule", "name": "Inactive", "group_id": core_apps,
                                                 "category": "Hardware", "active": "0"})
    _, routed_id, _ = _incident(client, app, "Broken keyboard", category="Hardware", group_id="auto")
    with app.app_context():
        assert ticket_owning_group(db.session.get(Ticket, routed_id)).id == windows
        history = TaskHistory.query.filter_by(target_type="ticket", target_id=routed_id,
                                              event="Assignment group set").one()
        assert "Hardware to Windows" in history.details
    # No rule matches: the CI's support group is used.
    with app.app_context():
        ci = ConfigurationItem(name="app-07", ci_class="Application", support_group_id=core_apps)
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    _, ci_routed_id, _ = _incident(client, app, "App 07 slow", category="Software / Application", group_id="auto", ci_id=ci_id)
    with app.app_context():
        assert ticket_owning_group(db.session.get(Ticket, ci_routed_id)).id == core_apps
    # Nothing applies: the form asks for a group and nothing is created.
    response, missing_id, _ = _incident(client, app, "Nobody owns this", category="Software / Application", group_id="auto")
    assert response.status_code == 400 and missing_id is None
    assert b"No assignment rule matches" in response.data


def test_assignment_rule_routing_respects_ci_class_and_tenant(app):
    with app.app_context():
        windows = SupportGroup.query.filter_by(name="Windows").one()
        db.session.add(AssignmentRule(tenant_id=1, name="Servers", group_id=windows.id, ci_class="Server"))
        other = Tenant(slug="other-rules", name="Other rules")
        db.session.add(other)
        db.session.flush()
        db.session.add(AssignmentRule(tenant_id=other.id, name="Theirs", group_id=windows.id, category="Software / Application"))
        db.session.commit()
        server = ConfigurationItem(name="srv-1", ci_class="Server")
        assert incident_handling.route(1, "Software / Application", ci=server)[0] == windows
        assert incident_handling.route(1, "Software / Application") == (None, None)


# --- templates ----------------------------------------------------------------------------------

def test_templates_admin_and_prefill(client, app):
    login(client)
    post = lambda **data: client.post("/admin/incident-handling", data=data)
    assert post(action="save_template", name="Password reset", title="Cannot sign in", category="Software / Application",
                impact="Low", urgency="High", description="Caller is locked out.", group_id=group_id(app)) \
        .status_code == 302
    assert post(action="save_template", name="password RESET", title="dup").status_code == 409
    assert post(action="save_template", name="Bad", impact="Huge").status_code == 400
    assert post(action="save_template", name="Hidden one", title="Hidden", active="0").status_code == 302
    with app.app_context():
        template = IncidentTemplate.query.filter_by(name="Password reset").one()
        template_id, hidden_id = template.id, IncidentTemplate.query.filter_by(name="Hidden one").one().id
    form = client.get("/tickets/new/incident").get_data(as_text=True)
    assert "Password reset" in form and "Hidden one" not in form
    filled = client.get(f"/tickets/new/incident?template={template_id}").get_data(as_text=True)
    assert 'value="Cannot sign in"' in filled and "Caller is locked out." in filled
    assert "Cannot sign in" not in client.get(f"/tickets/new/incident?template={hidden_id}").get_data(as_text=True)
    assert client.get("/tickets/new/incident?template=999999").status_code == 404
    assert post(action="delete_template", template_id=template_id).status_code == 302
    with app.app_context():
        assert db.session.get(IncidentTemplate, template_id) is None


# --- similar incidents --------------------------------------------------------------------------

def test_similar_incidents_are_open_visible_and_ranked(client, app):
    login(client)
    _, outlook_id, outlook_number = _incident(client, app, "Outlook crashes when opening calendar")
    _, partial_id, _ = _incident(client, app, "Outlook calendar sync slow")
    _, resolved_id, _ = _incident(client, app, "Outlook crashes opening calendar invites")
    with app.app_context():
        db.session.get(Ticket, resolved_id).state = "Resolved"
        db.session.commit()
    rows = client.get("/internal/lookup/similar-incidents?q=Outlook crashes on calendar open").json
    assert [row["value"] for row in rows][0] == outlook_number
    assert all(resolved_id != int(row["url"].rsplit("/", 1)[1]) for row in rows)
    rows = client.get(f"/internal/lookup/similar-incidents?q=Outlook crashes calendar&exclude={outlook_id}").json
    assert outlook_number not in [row["value"] for row in rows]
    assert client.get("/internal/lookup/similar-incidents?q=the and for").json == []
    # A requester only sees their own incidents.
    client.get("/logout")
    login(client, "employee", "Employee123!")
    assert client.get("/internal/lookup/similar-incidents?q=Outlook crashes calendar").json == []


# --- counts -------------------------------------------------------------------------------------

def test_reassignment_and_reopen_counts(client, app):
    login(client)
    _, ticket_id, _ = _incident(client, app, "Bounced between teams")
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "reassign_team", "new_group_id": group_id(app, "Windows")}).status_code == 302
    assert _update(client, ticket_id, resolve="1", resolution_notes="Fixed.").status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={"action": "reopen"}).status_code == 302
    ticket = _ticket(app, ticket_id)
    assert (ticket.reassignment_count, ticket.reopen_count) == (1, 1)
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "reassigned 1 time" in page and "reopened 1 time" in page


# --- tenant isolation ---------------------------------------------------------------------------

def test_other_tenant_cannot_reach_incident_handling_records(client, app):
    login(client)
    _, ticket_id, number = _incident(client, app, "Tenant A outage")
    client.post("/admin/incident-handling", data={"action": "save_rule", "name": "A rule", "group_id": group_id(app),
                                                 "category": "Hardware"})
    client.post("/admin/incident-handling", data={"action": "save_template", "name": "A template", "title": "A"})
    with app.app_context():
        rule_id = AssignmentRule.query.filter_by(name="A rule").one().id
        template_id = IncidentTemplate.query.filter_by(name="A template").one().id
        other = Tenant(slug="tenant-b-incidents", name="Tenant B")
        db.session.add(other)
        db.session.flush()
        db.session.add(User(username="b.incident.admin", name="B Admin", email="b@b.invalid", role="admin",
                            tenant_id=other.id, password_hash=generate_password_hash("Badmin123!x")))
        b_team = SupportGroup(name="B team", tenant_id=other.id, group_type="IT Fulfillment")
        db.session.add(b_team)
        db.session.commit()
        b_team_id = b_team.id
    client.get("/logout")
    login(client, "b.incident.admin", "Badmin123!x")
    assert client.post(f"/incident/{ticket_id}/tasks", data={"title": "x", "group_id": b_team_id}).status_code == 404
    assert client.post(f"/incident/{ticket_id}/problem").status_code == 404
    assert client.get(f"/tickets/new/incident?template={template_id}").status_code == 404
    assert client.get(f"/tickets/new/change?from_incident={number}").status_code == 404
    for data in ({"action": "delete_rule", "rule_id": rule_id}, {"action": "move_rule", "rule_id": rule_id},
                 {"action": "delete_template", "template_id": template_id},
                 {"action": "save_rule", "name": "Steal", "group_id": group_id(app), "category": "Hardware"}):
        assert client.post("/admin/incident-handling", data=data).status_code == 404
    assert client.get("/internal/lookup/similar-incidents?q=Tenant outage").json == []
    assert "Tenant A outage" not in client.get("/internal/lookup/users?q=adm").get_data(as_text=True)
    with app.app_context():
        assert db.session.get(AssignmentRule, rule_id) and db.session.get(IncidentTemplate, template_id)
        assert OperationalTask.query.filter_by(parent_id=ticket_id).count() == 0
