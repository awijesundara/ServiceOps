import os
import tempfile
from io import BytesIO

import pytest

from app import (Approval, ApprovalChain, CatalogRequest, CatalogTask, EnterpriseRecord,
                 Favorite, FileAttachment, GroupMember, RequestedItem, SupportGroup,
                 TaskSLA, Ticket, UserPreference, create_app, db)


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    yield app
    os.unlink(path)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="admin", password="Admin123!"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}


def test_login_and_dashboard(client):
    response = login(client)
    assert response.status_code == 200
    assert b"Recently updated" in response.data


def test_incident_lifecycle(client, app):
    login(client)
    created = client.post("/tickets/new/incident", data={
        "title": "VPN is unavailable",
        "description": "Connection fails from the remote office.",
        "category": "Network",
        "priority": "P2",
    }, follow_redirects=True)
    assert created.status_code == 200
    assert b"INC0000001" in created.data
    with app.app_context():
        ticket = Ticket.query.one()
        ticket_id = ticket.id
    updated = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P1", "assignee_id": ""
    }, follow_redirects=True)
    assert b"In Progress" in updated.data


def test_requester_cannot_create_change(client):
    login(client, "employee", "Employee123!")
    assert client.get("/tickets/new/change").status_code == 403


def test_role_protection(client):
    login(client, "employee", "Employee123!")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/assets").status_code == 403


def test_enterprise_problem_workflow(client, app):
    login(client)
    response = client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Recurring database latency",
        "description": "Investigate repeated latency during peak usage.",
        "priority": "P2",
        "risk": "High",
        "approval_required": "1",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"PRB0000001" in response.data
    assert b"Awaiting Approval" in response.data
    with app.app_context():
        record = EnterpriseRecord.query.filter_by(domain="problem").one()
        approval = Approval.query.filter_by(enterprise_record_id=record.id).one()
        record_id, approval_id = record.id, approval.id
    decision = client.post(f"/enterprise/{record_id}", data={
        "action": "approve", "approval_id": approval_id, "comments": "Proceed with investigation."
    }, follow_redirects=True)
    assert b"Approved" in decision.data


def test_catalog_request_and_cmdb(client, app):
    login(client, "employee", "Employee123!")
    catalog = client.get("/catalog")
    assert b"Laptop computer" in catalog.data
    ordered = client.post("/catalog/1/order", data={"details": "Laptop for remote work"}, follow_redirects=True)
    assert b"REQ0000001" in ordered.data
    assert b"RITM0000001" in ordered.data
    assert b"Manager approval" in ordered.data
    client.post("/logout")
    login(client)
    cmdb = client.get("/cmdb")
    assert b"Customer Portal" in cmdb.data
    assert b"Depends on" in cmdb.data


def test_catalog_approval_chain_creates_fulfillment_task(client, app):
    login(client)
    client.post("/catalog/1/order", data={"details": "Engineering laptop"}, follow_redirects=True)
    with app.app_context():
        ritm = RequestedItem.query.one()
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm.id).one()
        first_vote = chain.gates[0].votes[0]
        ritm_id, first_vote_id = ritm.id, first_vote.id
    client.post(f"/approval-votes/{first_vote_id}/decide",
                data={"decision": "Approved", "comments": "Manager approved."})
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm_id).one()
        second_vote = chain.gates[1].votes[0]
        second_vote_id = second_vote.id
    client.post(f"/approval-votes/{second_vote_id}/decide",
                data={"decision": "Approved", "comments": "Fulfillment approved."})
    with app.app_context():
        ritm = db.session.get(RequestedItem, ritm_id)
        assert ritm.state == "Approved"
        assert CatalogTask.query.filter_by(requested_item_id=ritm.id).count() == 1
        assert TaskSLA.query.filter_by(target_type="ritm", target_id=ritm.id).count() == 1


def test_change_has_governance_approval_chain_and_sla(client, app):
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Upgrade database cluster",
        "description": "Apply the approved database release.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "75", "impact": "High",
        "implementation_plan": "Upgrade replicas, then primary.",
        "test_plan": "Run health and transaction tests.",
        "backout_plan": "Restore the previous release.",
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        assert ticket.change_governance.risk_score == 75
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).one()
        assert [gate.name for gate in chain.gates] == ["CoreApps manager assessment", "CCB weekly authorization"]
        assert chain.gates[1].mode == "majority"
        assert TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).count() == 1


def test_it_teams_managers_and_ccb_membership(client, app):
    expected = {"CoreApps", "Database", "Network", "Windows", "Unix", "SSD"}
    with app.app_context():
        teams = SupportGroup.query.filter_by(group_type="IT Fulfillment").all()
        assert {team.name for team in teams} == expected
        assert all(team.manager and team.manager.role == "manager" for team in teams)
        assert all(GroupMember.query.filter_by(group_id=team.id, user_id=team.manager_id,
                                               role="manager").one_or_none() for team in teams)
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
        ccb_user_ids = {member.user_id for member in ccb.members}
        assert ccb_user_ids == {team.manager_id for team in teams}
        assert {member.role for member in ccb.members} == {"CCB member"}


def test_team_manager_can_access_management_work(client):
    response = login(client, "database.manager", "Manager123!")
    assert b"Database Manager" in response.data
    assert client.get("/tickets/incident").status_code == 200
    assert client.get("/analytics").status_code == 200
    assert client.get("/admin/users").status_code == 403


def test_unified_search_favorites_and_preferences(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Global search verification", "description": "Searchable record",
        "category": "Software", "priority": "P3",
    })
    result = client.get("/ui/search?q=Global+search")
    assert b"Global search verification" in result.data
    assert client.post("/ui/favorite", data={"url": "/task-board", "label": "My board"}).json["active"]
    client.post("/preferences", data={
        "theme": "dark", "density": "compact", "font_scale": "115",
        "high_contrast": "1", "reduced_motion": "1", "nav_pinned": "1",
        "start_page": "/task-board",
    })
    with app.app_context():
        assert Favorite.query.filter_by(url="/task-board").one()
        pref = UserPreference.query.one()
        assert (pref.theme, pref.density, pref.font_scale, pref.start_page) == ("dark", "compact", 115, "/task-board")


def test_visual_board_checklist_and_attachment(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Workspace interaction test", "description": "Board, checklist, and files",
        "category": "Software", "priority": "P3",
    })
    with app.app_context():
        ticket_id = Ticket.query.one().id
    moved = client.post(f"/task-board/{ticket_id}/move", data={"state": "In Progress"})
    assert moved.json == {"state": "In Progress"}
    client.post(f"/ticket/{ticket_id}/checklist", data={"text": "Validate recovery"})
    uploaded = client.post(f"/ticket/{ticket_id}/attachments",
                           data={"file": (BytesIO(b"evidence"), "evidence.txt")},
                           content_type="multipart/form-data", follow_redirects=True)
    assert b"evidence.txt" in uploaded.data
    with app.app_context():
        assert FileAttachment.query.filter_by(ticket_id=ticket_id).one().size_bytes == 8
