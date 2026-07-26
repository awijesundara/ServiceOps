import os
import tempfile
from io import BytesIO

import pytest

from app import (Approval, ApprovalChain, CatalogRequest, CatalogTask, ChangeRevision,
                 EnterpriseRecord, CatalogItem, CatalogItemRouting, DirectoryGroupMapping,
                 DirectoryManagedMembership, ExternalIdentity, Favorite, FileAttachment,
                 GroupMember, Notification, OperationalTask, ProblemProfile, RecordLink,
                 RequestedItem, PlatformSetting, SupportGroup, TaskHistory, TaskSLA,
                 Ticket, TicketAssignmentGroup, User, UserPreference,
                 create_app, db, provision_external_user)
from werkzeug.security import generate_password_hash


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        employee = User(
            username="employee", name="Test Employee", email="employee@test.invalid",
            password_hash=generate_password_hash("Employee123!"), role="requester",
        )
        manager = User(
            username="database.manager", name="Database Manager",
            email="database.manager@test.invalid",
            password_hash=generate_password_hash("Manager123!"), role="manager",
        )
        db.session.add_all([employee, manager])
        db.session.flush()
        admin = User.query.filter_by(username="admin").one()
        for group in SupportGroup.query.filter_by(group_type="IT Fulfillment").all():
            group.manager_id = manager.id
            db.session.add(GroupMember(group_id=group.id, user_id=manager.id, role="manager"))
            db.session.add(GroupMember(group_id=group.id, user_id=admin.id, role="member"))
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
        db.session.add(GroupMember(group_id=ccb.id, user_id=manager.id, role="CCB approver"))
        service_desk = SupportGroup.query.filter_by(name="Service Desk").one()
        db.session.add(GroupMember(group_id=service_desk.id, user_id=manager.id, role="member"))
        catalog_item = CatalogItem(
            name="Laptop computer", category="Hardware", description="Test catalog item.",
            delivery_days=5, approval_required=True,
        )
        db.session.add(catalog_item)
        db.session.flush()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        db.session.add(CatalogItemRouting(
            catalog_item_id=catalog_item.id, support_group_id=windows.id,
            updated_by_id=admin.id,
        ))
        db.session.commit()
    yield app
    os.unlink(path)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="admin", password="Admin123!"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def group_id(app, name="CoreApps"):
    with app.app_context():
        return SupportGroup.query.filter_by(name=name).one().id


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}
    assert client.get("/live").json == {"status": "alive"}
    assert client.get("/ready").json == {"status": "ready"}


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
        "group_id": group_id(app, "Network"),
    }, follow_redirects=True)
    assert created.status_code == 200
    assert b"INC0000001" in created.data
    with app.app_context():
        ticket = Ticket.query.one()
        ticket_id = ticket.id
        assert ticket.assignment_group_record.group.name == "Network"
    updated = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P1", "assignee_id": ""
    }, follow_redirects=True)
    assert b"In Progress" in updated.data


def test_only_owning_team_can_operationally_update_ticket(client, app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        ssd = SupportGroup.query.filter_by(name="SSD").one()
        unix_agent = User(
            username="unix.agent", name="Unix Agent", email="unix.agent@test.invalid",
            password_hash=generate_password_hash("Unix123!"), role="agent",
        )
        ssd_agent = User(
            username="ssd.agent", name="SSD Agent", email="ssd.agent@test.invalid",
            password_hash=generate_password_hash("Ssd12345!"), role="agent",
        )
        db.session.add_all([unix_agent, ssd_agent])
        db.session.flush()
        db.session.add_all([
            GroupMember(group_id=unix.id, user_id=unix_agent.id, role="member"),
            GroupMember(group_id=ssd.id, user_id=ssd_agent.id, role="member"),
        ])
        db.session.commit()
        unix_id, ssd_agent_id = unix.id, ssd_agent.id

    login(client)
    response = client.post("/tickets/new/change", data={
        "title": "Unix-owned protected change",
        "description": "Operational control belongs to Unix.",
        "category": "Software", "priority": "P3", "change_type": "Normal",
        "risk_score": "50", "impact": "Medium", "group_id": unix_id,
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
    })
    assert response.status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Unix-owned protected change").one()
        ticket_id, current_state = ticket.id, ticket.state
        attachment = FileAttachment(
            ticket_id=ticket.id,
            uploaded_by_id=User.query.filter_by(username="admin").one().id,
            original_name="unix-plan.txt", stored_name="not-needed-in-access-test",
            mime_type="text/plain", size_bytes=4,
        )
        db.session.add(attachment)
        db.session.commit()
        attachment_id = attachment.id

    client.post("/logout")
    login(client, "ssd.agent", "Ssd12345!")
    detail = client.get(f"/ticket/{ticket_id}")
    assert detail.status_code == 403
    assert b"Unix-owned protected change" not in client.get("/tickets/change").data
    assert b"Unix-owned protected change" not in client.get(
        "/ui/search?q=Unix-owned", headers={"Accept": "application/json"}
    ).data
    assert client.get(f"/attachments/{attachment_id}").status_code == 403
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P1",
        "assignee_id": "",
    }).status_code == 403
    assert client.post(
        f"/task-board/{ticket_id}/move", data={"state": current_state}
    ).status_code == 403
    assert client.post(
        f"/ticket/{ticket_id}/checklist", data={"text": "Unauthorized"}
    ).status_code == 403
    assert client.post(f"/change/{ticket_id}/conflicts").status_code == 403

    client.post("/logout")
    login(client, "unix.agent", "Unix123!")
    owner_detail = client.get(f"/ticket/{ticket_id}")
    assert b"Save changes" in owner_detail.data
    assert b"Unix Agent" in owner_detail.data
    assert b"SSD Agent" not in owner_detail.data
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P2",
        "assignee_id": ssd_agent_id,
    }).status_code == 400
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P2",
        "assignee_id": "",
    }).status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.priority == "P2"
        assert ticket.state == current_state


def test_unrelated_team_cannot_view_or_mutate_catalog_request(client, app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        unix_agent = User(
            username="unix.catalog", name="Unix Catalog Agent",
            email="unix.catalog@test.invalid",
            password_hash=generate_password_hash("UnixCatalog123!"), role="agent",
        )
        windows_agent = User(
            username="windows.catalog", name="Windows Catalog Agent",
            email="windows.catalog@test.invalid",
            password_hash=generate_password_hash("WindowsCatalog123!"), role="agent",
        )
        db.session.add_all([unix_agent, windows_agent])
        db.session.flush()
        db.session.add_all([
            GroupMember(group_id=unix.id, user_id=unix_agent.id, role="member"),
            GroupMember(group_id=windows.id, user_id=windows_agent.id, role="member"),
        ])
        item = CatalogItem.query.filter_by(name="Laptop computer").one()
        item.approval_required = False
        db.session.commit()
        item_id = item.id

    login(client)
    assert client.post(f"/catalog/{item_id}/order", data={
        "details": "Windows-only fulfillment visibility",
    }).status_code == 302
    with app.app_context():
        req = CatalogRequest.query.one()
        request_id = req.id
        ritm_id = req.items[0].id

    client.post("/logout")
    login(client, "unix.catalog", "UnixCatalog123!")
    assert client.get("/requests").status_code == 200
    assert b"REQ0000001" not in client.get("/requests").data
    assert client.get(f"/request/{request_id}").status_code == 403
    assert client.get(
        "/ui/search?q=REQ0000001", headers={"Accept": "application/json"}
    ).json == {"results": []}
    assert client.post(f"/request/{request_id}/items", data={
        "catalog_item_id": item_id, "details": "Unauthorized extra item",
    }).status_code == 403
    assert client.post(f"/ritm/{ritm_id}/tasks", data={
        "title": "Unauthorized Unix task", "group_id": group_id(app, "Unix"),
        "execution_mode": "Parallel",
    }).status_code == 403

    client.post("/logout")
    login(client, "windows.catalog", "WindowsCatalog123!")
    assert client.get(f"/request/{request_id}").status_code == 200


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
    assert client.get("/cmdb").status_code == 200


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
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    client.post(f"/approval-votes/{second_vote_id}/decide",
                data={"decision": "Approved", "comments": "Fulfillment approved."})
    with app.app_context():
        ritm = db.session.get(RequestedItem, ritm_id)
        assert ritm.state == "Approved"
        task = CatalogTask.query.filter_by(requested_item_id=ritm.id).one()
        assert task.assignment_group.name == "Windows"
        assert TaskSLA.query.filter_by(target_type="ritm", target_id=ritm.id).count() == 1


def test_admin_can_route_future_catalog_items_to_any_fulfillment_team(client, app):
    with app.app_context():
        item = CatalogItem(
            name="Database access package", category="Access",
            description="Future catalog routing verification.",
            approval_required=False,
        )
        db.session.add(item)
        db.session.commit()
        item_id = item.id
        database_id = SupportGroup.query.filter_by(name="Database").one().id
    login(client)
    configured = client.post("/itil/administration", data={
        "action": "set_catalog_route",
        "catalog_item_id": item_id,
        "group_id": database_id,
    })
    assert configured.status_code == 302
    ordered = client.post(f"/catalog/{item_id}/order", data={
        "details": "Route this future use case to Database.",
    })
    assert ordered.status_code == 302
    with app.app_context():
        route = CatalogItemRouting.query.filter_by(catalog_item_id=item_id).one()
        task = CatalogTask.query.join(RequestedItem).filter(
            RequestedItem.catalog_item_id == item_id
        ).one()
        assert route.support_group.name == "Database"
        assert task.assignment_group.name == "Database"


def test_admin_can_create_and_edit_catalog_item_with_fulfillment_policy(client, app):
    login(client)
    database_id = group_id(app, "Database")
    created = client.post("/itil/administration", data={
        "action": "create_catalog_item",
        "name": "Managed database account",
        "category": "Access",
        "description": "Provision a governed database account.",
        "delivery_days": "4",
        "group_id": database_id,
        "approval_required": "1",
        "active": "1",
    })
    assert created.status_code == 302
    with app.app_context():
        item = CatalogItem.query.filter_by(name="Managed database account").one()
        item_id = item.id
        assert item.category == "Access"
        assert item.delivery_days == 4
        assert item.approval_required
        assert item.active
        assert item.fulfillment_route.support_group.name == "Database"

    windows_id = group_id(app, "Windows")
    updated = client.post("/itil/administration", data={
        "action": "update_catalog_item",
        "catalog_item_id": item_id,
        "name": "Managed application account",
        "category": "Software",
        "description": "Provision a governed application account.",
        "delivery_days": "2",
        "group_id": windows_id,
    })
    assert updated.status_code == 302
    with app.app_context():
        item = db.session.get(CatalogItem, item_id)
        assert item.name == "Managed application account"
        assert item.delivery_days == 2
        assert not item.approval_required
        assert not item.active
        assert item.fulfillment_route.support_group.name == "Windows"
    assert client.post(f"/catalog/{item_id}/order", data={
        "details": "Inactive items must remain unavailable.",
    }).status_code == 404


def test_catalog_request_visibility_is_limited_to_participants_and_fulfillment_team(client, app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        unix_user = User(
            username="visibility.unix", name="Visibility Unix",
            email="visibility.unix@test.invalid",
            password_hash=generate_password_hash("UnixVisibility123!"), role="agent",
        )
        windows_user = User(
            username="visibility.windows", name="Visibility Windows",
            email="visibility.windows@test.invalid",
            password_hash=generate_password_hash("WindowsVisibility123!"), role="agent",
        )
        db.session.add_all([unix_user, windows_user])
        db.session.flush()
        db.session.add_all([
            GroupMember(group_id=unix.id, user_id=unix_user.id, role="member"),
            GroupMember(group_id=windows.id, user_id=windows_user.id, role="member"),
        ])
        db.session.commit()

    login(client, "employee", "Employee123!")
    assert client.post("/catalog/1/order", data={
        "details": "Windows-routed laptop request.",
    }).status_code == 302
    with app.app_context():
        req = CatalogRequest.query.one()
        request_id, request_number = req.id, req.number

    client.post("/logout")
    login(client, "visibility.unix", "UnixVisibility123!")
    unix_list = client.get("/requests")
    assert request_number.encode() not in unix_list.data
    assert client.get(f"/request/{request_id}").status_code == 403
    unix_search = client.get(f"/ui/search?q={request_number}", headers={
        "Accept": "application/json",
    })
    assert unix_search.json == {"results": []}

    client.post("/logout")
    login(client, "visibility.windows", "WindowsVisibility123!")
    assert request_number.encode() in client.get("/requests").data
    assert client.get(f"/request/{request_id}").status_code == 200

    client.post("/logout")
    login(client, "employee", "Employee123!")
    assert request_number.encode() in client.get("/requests").data
    assert client.get(f"/request/{request_id}").status_code == 200

    client.post("/logout")
    login(client)
    assert request_number.encode() in client.get("/requests").data


def test_catalog_task_requires_valid_fulfillment_lifecycle(client, app):
    login(client)
    item = None
    with app.app_context():
        item = CatalogItem(
            name="No approval test item", category="Testing",
            description="Workflow transition test", approval_required=False,
        )
        db.session.add(item)
        db.session.commit()
        item_id = item.id
    client.post(f"/catalog/{item_id}/order", data={"details": "Test lifecycle"})
    with app.app_context():
        task_id = CatalogTask.query.one().id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/catalog-task/{task_id}", data={
        "state": "Closed Complete", "work_notes": "Attempted bypass",
    }).status_code == 409
    assert client.post(f"/catalog-task/{task_id}", data={
        "state": "Work in Progress", "work_notes": "Started",
    }).status_code == 302
    assert client.post(f"/catalog-task/{task_id}", data={
        "state": "Closed Complete", "work_notes": "Completed",
    }).status_code == 302


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
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        assert ticket.change_governance.risk_score == 75
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).one()
        assert [gate.name for gate in chain.gates] == ["CoreApps manager assessment", "CCB weekly authorization"]
        assert chain.gates[1].mode == "majority"
        assert TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).count() == 1


def test_change_cannot_bypass_approval_from_detail_or_board(client, app):
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Protected database change",
        "description": "Must complete manager and CCB authorization.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "70", "impact": "High",
        "implementation_plan": "Implement safely.", "test_plan": "Validate safely.",
        "backout_plan": "Back out safely.",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        ticket_id = ticket.id
        first_vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).one().gates[0].votes[0].id
    bypass = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P2",
        "assignee_id": "",
    })
    assert bypass.status_code == 409
    assert client.post(
        f"/task-board/{ticket_id}/move", data={"state": "In Progress"}
    ).status_code == 409
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Awaiting Approval"

    # Platform administrators cannot cast another named approver's vote.
    assert client.post(f"/approval-votes/{first_vote_id}/decide", data={
        "decision": "Approved", "comments": "Unauthorized override",
    }).status_code == 403

    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{first_vote_id}/decide", data={
        "decision": "Approved", "comments": "Manager authorization",
    }).status_code == 302
    with app.app_context():
        chain = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).one()
        ccb_vote_id = chain.gates[1].votes[0].id
    assert client.post(f"/approval-votes/{ccb_vote_id}/decide", data={
        "decision": "Approved", "comments": "CCB authorization",
    }).status_code == 302
    allowed = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P2",
        "assignee_id": "",
    })
    assert allowed.status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "In Progress"


def test_incident_problem_change_and_parent_relationship_network(client, app):
    login(client)
    coreapps_id = group_id(app)
    for title in ("Parent application outage", "Child user report"):
        assert client.post("/tickets/new/incident", data={
            "title": title, "description": "Relationship verification.",
            "category": "Software", "priority": "P2", "group_id": coreapps_id,
        }).status_code == 302
    assert client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Application outage root cause",
        "description": "Investigate the common cause.",
        "priority": "P2", "risk": "High",
    }).status_code == 302
    assert client.post("/tickets/new/change", data={
        "title": "Permanent application fix",
        "description": "Deploy the permanent correction.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "70", "impact": "High", "group_id": coreapps_id,
        "implementation_plan": "Deploy safely.", "test_plan": "Validate service.",
        "backout_plan": "Restore prior release.",
    }).status_code == 302
    with app.app_context():
        incidents = Ticket.query.filter_by(kind="incident").order_by(Ticket.id).all()
        parent, child = incidents
        problem = EnterpriseRecord.query.filter_by(domain="problem").one()
        change = Ticket.query.filter_by(kind="change").one()
        parent_id, child_id = parent.id, child.id
        problem_number, change_number, parent_number = (
            problem.number, change.number, parent.number
        )
    assert client.post(f"/record/ticket/{child_id}/relationships", data={
        "link_type": "parent_incident", "target_number": parent_number,
    }).status_code == 302
    assert client.post(f"/record/ticket/{parent_id}/relationships", data={
        "link_type": "underlying_problem", "target_number": problem_number,
    }).status_code == 302
    assert client.post(f"/record/ticket/{parent_id}/relationships", data={
        "link_type": "resolution_change", "target_number": change_number,
    }).status_code == 302
    assert client.post(f"/record/ticket/{parent_id}/relationships", data={
        "link_type": "caused_by_change", "target_number": change_number,
    }).status_code == 302
    page = client.get(f"/ticket/{parent_id}")
    assert b"Problem" in page.data
    assert b"Change request" in page.data
    assert b"Caused by change" in page.data
    with app.app_context():
        assert RecordLink.query.count() == 4
        history = TaskHistory.query.filter_by(
            target_type="ticket", target_id=parent_id,
            event="Related record linked",
        ).all()
        assert len(history) == 4


def test_material_change_edit_supersedes_approvals_and_notifies_approvers(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Approved production deployment",
        "description": "Original approved purpose.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "50", "impact": "Medium", "group_id": group_id(app),
        "implementation_plan": "Deploy version one.",
        "test_plan": "Test version one.",
        "backout_plan": "Restore version zero.",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Approved production deployment").one()
        ticket_id = ticket.id
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).one()
        manager_vote_id = chain.gates[0].votes[0].id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{manager_vote_id}/decide", data={
        "decision": "Approved", "comments": "Manager approved v1.",
    }).status_code == 302
    with app.app_context():
        chain = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).order_by(ApprovalChain.id.desc()).first()
        ccb_vote_id = chain.gates[1].votes[0].id
    assert client.post(f"/approval-votes/{ccb_vote_id}/decide", data={
        "decision": "Approved", "comments": "CCB approved v1.",
    }).status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Approved"
        old_chain_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).one().id
        notifications_before = Notification.query.count()
    revised = client.post(f"/change/{ticket_id}/plan", data={
        "title": "Approved production deployment",
        "description": "Revised production purpose.",
        "change_type": "Normal", "risk_score": "85", "impact": "High",
        "implementation_plan": "Deploy version two with a new sequence.",
        "test_plan": "Run expanded regression.",
        "backout_plan": "Restore version one.",
        "planned_start": "", "planned_end": "", "ci_id": "",
    })
    assert revised.status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        chains = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).order_by(ApprovalChain.id).all()
        assert ticket.state == "Awaiting Approval"
        assert db.session.get(ApprovalChain, old_chain_id).state == "Superseded"
        assert chains[-1].state == "Running"
        assert ticket.change_revision.revision == 2
        assert Notification.query.count() > notifications_before
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket_id,
            event="Approval restarted",
        ).one()


def test_required_change_tasks_block_parent_completion(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Task-controlled change",
        "description": "Completion requires its implementation task.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Task-controlled change").one()
        ticket_id = ticket.id
        vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).one().gates[0].votes[0].id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P3",
        "assignee_id": "",
    }).status_code == 302
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Deploy application package", "task_type": "Implementation",
        "group_id": group_id(app), "required": "1",
        "planned_start": "", "planned_end": "",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Resolved", "priority": "P3",
        "assignee_id": "",
    }).status_code == 409
    with app.app_context():
        task = OperationalTask.query.filter_by(parent_id=ticket_id).one()
        task_id = task.id
    assert client.post(f"/operational-task/{task_id}", data={
        "state": "Closed Complete", "assignee_id": "",
        "work_notes": "Deployment and validation completed.",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Resolved", "priority": "P3",
        "assignee_id": "",
    }).status_code == 302


def test_problem_profile_ptask_and_multiple_fix_changes(client, app):
    login(client)
    assert client.post("/module/problem/new", data={
        "record_type": "Root cause analysis", "title": "Recurring capacity failure",
        "description": "Investigate recurring failures.", "priority": "P2", "risk": "High",
    }).status_code == 302
    with app.app_context():
        problem = EnterpriseRecord.query.filter_by(title="Recurring capacity failure").one()
        problem_id = problem.id
    assert client.post(f"/problem/{problem_id}/analysis", data={
        "known_error": "1", "root_cause": "Version 4.2 leaks connections.",
        "workaround": "Restart at 900 sessions.",
        "fix_notes": "Upgrade to version 4.3.", "primary_ci_id": "",
    }).status_code == 302
    assert client.post(f"/problem/{problem_id}/tasks", data={
        "title": "Analyse active sessions", "task_type": "Investigation",
        "group_id": group_id(app, "Database"), "required": "1",
    }).status_code == 302
    with app.app_context():
        profile = ProblemProfile.query.filter_by(enterprise_record_id=problem_id).one()
        assert profile.known_error
        assert "900 sessions" in profile.workaround
        assert OperationalTask.query.filter_by(
            parent_type="enterprise", parent_id=problem_id,
            task_kind="problem",
        ).one().number.startswith("PTASK")


def test_request_supports_multiple_ritms_and_sctasks(client, app):
    login(client)
    with app.app_context():
        primary_item = CatalogItem(
            name="Standard workstation", category="Hardware",
            description="Primary requested item.", approval_required=False,
        )
        second_item = CatalogItem(
            name="VPN access", category="Access",
            description="Additional requested item.", approval_required=False,
        )
        db.session.add_all([primary_item, second_item])
        db.session.commit()
        primary_item_id, second_item_id = primary_item.id, second_item.id
    assert client.post(f"/catalog/{primary_item_id}/order", data={
        "details": "Primary laptop item",
    }).status_code == 302
    with app.app_context():
        req = CatalogRequest.query.one()
        req_id = req.id
    assert client.post(f"/request/{req_id}/items", data={
        "catalog_item_id": second_item_id, "details": "Also provide VPN.",
    }).status_code == 302
    with app.app_context():
        req = db.session.get(CatalogRequest, req_id)
        assert len(req.items) == 2
        first_ritm = req.items[0]
        first_ritm_id = first_ritm.id
    assert client.post(f"/ritm/{first_ritm_id}/tasks", data={
        "title": "Configure endpoint security", "group_id": group_id(app),
        "execution_mode": "Sequential",
    }).status_code == 302
    with app.app_context():
        tasks = CatalogTask.query.filter_by(
            requested_item_id=first_ritm_id
        ).order_by(CatalogTask.id).all()
        assert len(tasks) == 2
        first_task_id, second_task_id = tasks[0].id, tasks[1].id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/catalog-task/{second_task_id}", data={
        "state": "Work in Progress", "work_notes": "Premature start.",
    }).status_code == 409
    assert client.post(f"/catalog-task/{first_task_id}", data={
        "state": "Work in Progress", "work_notes": "Started.",
    }).status_code == 302
    assert client.post(f"/catalog-task/{first_task_id}", data={
        "state": "Closed Complete", "work_notes": "Completed.",
    }).status_code == 302
    with app.app_context():
        assert db.session.get(RequestedItem, first_ritm_id).state != "Closed Complete"
    assert client.post(f"/catalog-task/{second_task_id}", data={
        "state": "Work in Progress", "work_notes": "Started.",
    }).status_code == 302
    assert client.post(f"/catalog-task/{second_task_id}", data={
        "state": "Closed Complete", "work_notes": "Completed.",
    }).status_code == 302
    with app.app_context():
        assert db.session.get(RequestedItem, first_ritm_id).state == "Closed Complete"


def test_major_incident_remains_inc_and_parent_state_sync_is_audited(client, app):
    login(client)
    coreapps_id = group_id(app)
    for title in ("Major parent outage", "Major child report"):
        assert client.post("/tickets/new/incident", data={
            "title": title, "description": "Major incident verification.",
            "category": "Software", "priority": "P1", "group_id": coreapps_id,
        }).status_code == 302
    with app.app_context():
        parent, child = Ticket.query.filter_by(kind="incident").order_by(Ticket.id).all()
        parent_id, child_id, parent_number = parent.id, child.id, parent.number
        db.session.add(PlatformSetting(
            key="SYNC_CHILD_INCIDENT_STATES", value="true", encrypted=False,
        ))
        db.session.commit()
    assert client.post(f"/record/ticket/{child_id}/relationships", data={
        "link_type": "parent_incident", "target_number": parent_number,
    }).status_code == 302
    assert client.post(f"/incident/{parent_id}/major-incident", data={
        "status": "Accepted",
        "business_impact": "All production customers are affected.",
        "communications": "Updates every 30 minutes.",
    }).status_code == 302
    assert client.post(f"/ticket/{parent_id}", data={
        "action": "update", "state": "Pending", "priority": "P1",
        "assignee_id": "",
    }).status_code == 302
    with app.app_context():
        parent = db.session.get(Ticket, parent_id)
        child = db.session.get(Ticket, child_id)
        assert parent.number.startswith("INC")
        assert parent.major_incident_profile.status == "Accepted"
        assert child.state == "Pending"
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=child_id,
            event="State synchronized from parent incident",
        ).one()


def test_enterprise_record_cannot_bypass_requested_approval(client, app):
    login(client)
    client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Approval protected problem",
        "description": "Do not start before authorization.",
        "priority": "P2", "risk": "High", "approval_required": "1",
    })
    with app.app_context():
        record_id = EnterpriseRecord.query.filter_by(
            title="Approval protected problem"
        ).one().id
    bypass = client.post(f"/enterprise/{record_id}", data={
        "action": "update", "state": "In Progress", "priority": "P2",
        "risk": "High", "assignee_id": "",
    })
    assert bypass.status_code == 409
    with app.app_context():
        assert db.session.get(EnterpriseRecord, record_id).state == "Awaiting Approval"


def test_enterprise_approval_cannot_be_replayed_against_another_record(client, app):
    login(client)
    for title in ("Approval source", "Approval target"):
        assert client.post("/module/problem/new", data={
            "record_type": "Root cause analysis", "title": title,
            "description": "Approval binding verification.",
            "priority": "P2", "risk": "High", "approval_required": "1",
        }).status_code == 302
    with app.app_context():
        source, target = EnterpriseRecord.query.order_by(EnterpriseRecord.id).all()
        source_approval_id = source.approvals[0].id
        target_id = target.id
    assert client.post(f"/enterprise/{target_id}", data={
        "action": "approve", "approval_id": source_approval_id,
        "comments": "Attempted cross-record approval",
    }).status_code == 404
    with app.app_context():
        target = db.session.get(EnterpriseRecord, target_id)
        assert target.state == "Awaiting Approval"
        assert target.approvals[0].state == "Requested"


def test_inactive_catalog_item_cannot_be_ordered_directly(client, app):
    login(client)
    with app.app_context():
        item = CatalogItem.query.filter_by(name="Laptop computer").one()
        item.active = False
        db.session.commit()
        item_id = item.id
    assert client.post(f"/catalog/{item_id}/order", data={"details": "Hidden item"}).status_code == 404
    with app.app_context():
        assert CatalogRequest.query.count() == 0


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
        assert {member.role for member in ccb.members} == {"CCB approver"}


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
        "group_id": group_id(app),
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
        assert (pref.theme, pref.density, pref.font_scale, pref.start_page) == ("light", "compact", 115, "/task-board")


def test_visual_board_checklist_and_attachment(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Workspace interaction test", "description": "Board, checklist, and files",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
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


def test_visual_board_rejects_invalid_lifecycle_jump(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Strict lifecycle test", "description": "Cannot close from New",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.one().id
    assert client.post(
        f"/task-board/{ticket_id}/move", data={"state": "Closed"}
    ).status_code == 409
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "New"


def test_fresh_install_has_no_reserved_demo_personas(monkeypatch):
    fd, path = tempfile.mkstemp()
    os.close(fd)
    monkeypatch.setenv("DEPLOYMENT_PROFILE", "production")
    production = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
        "DEPLOYMENT_PROFILE": "production",
    })
    with production.app_context():
        assert User.query.filter_by(username="admin", active=True).one()
        assert User.query.filter_by(username="employee").count() == 0
        assert User.query.filter(User.username.like("%.agent"), User.active.is_(True)).count() == 0
        assert User.query.filter(User.username.like("%.manager")).count() == 0
        assert CatalogItem.query.count() == 0
    os.unlink(path)


def test_external_identity_is_stable_and_does_not_enable_local_password(app):
    with app.app_context():
        first = provision_external_user("keycloak", "subject-123", "alice", "Alice", "alice@example.test", "agent")
        db.session.commit()
        first_id = first.id
        second = provision_external_user("keycloak", "subject-123", "alice", "Alice Updated",
                                         "alice@example.test", "manager")
        db.session.commit()
        assert second.id == first_id
        assert second.role == "manager"
        assert ExternalIdentity.query.filter_by(provider="keycloak", subject="subject-123").count() == 1


def test_ldap_group_mapping_synchronizes_team_membership(app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        db.session.add(DirectoryGroupMapping(
            directory_group="gg_unix", support_group_id=unix.id
        ))
        db.session.commit()
        user = provision_external_user(
            "ldap", "CN=Alice,OU=Users,DC=example,DC=com", "alice", "Alice",
            "alice@example.test", "agent",
            groups=["CN=gg_unix,OU=Groups,DC=example,DC=com"],
        )
        db.session.commit()
        user_id = user.id
        assert GroupMember.query.filter_by(
            user_id=user_id, group_id=unix.id, role="member"
        ).one()
        assert DirectoryManagedMembership.query.filter_by(
            user_id=user_id, group_id=unix.id
        ).one()

        provision_external_user(
            "ldap", "CN=Alice,OU=Users,DC=example,DC=com", "alice", "Alice",
            "alice@example.test", "agent", groups=[],
        )
        db.session.commit()
        assert GroupMember.query.filter_by(user_id=user_id, group_id=unix.id).count() == 0
        assert DirectoryManagedMembership.query.filter_by(
            user_id=user_id, group_id=unix.id
        ).count() == 0


def test_admin_configures_ad_mapping_manager_and_ccb_authority(client, app):
    login(client)
    with app.app_context():
        unix_id = SupportGroup.query.filter_by(name="Unix").one().id
        manager = User.query.filter_by(username="database.manager").one()
        manager_id = manager.id
    assert client.post("/itil/administration", data={
        "action": "add_directory_mapping", "directory_group": "gg_unix",
        "group_id": unix_id,
    }).status_code == 302
    assert client.post("/itil/administration", data={
        "action": "set_manager", "group_id": unix_id, "manager_id": manager_id,
    }).status_code == 302
    assert client.post("/itil/administration", data={
        "action": "set_ccb_authority", "user_id": manager_id, "enabled": "true",
    }).status_code == 302
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
        assert DirectoryGroupMapping.query.filter_by(
            directory_group="gg_unix", support_group_id=unix.id, active=True
        ).one()
        assert unix.manager_id == manager_id
        assert GroupMember.query.filter_by(
            group_id=ccb.id, user_id=manager_id, role="CCB approver"
        ).one()


def test_admin_can_update_live_platform_branding(client, app):
    login(client)
    response = client.post("/admin/settings", data={
        "INSTANCE_NAME": "Operations Hub",
        "COMPANY_NAME": "Example Corporation",
        "SUPPORT_EMAIL": "support@example.test",
        "INSTANCE_TIMEZONE": "Australia/Sydney",
        "BRAND_TEAL": "#124c5a",
        "BRAND_AMBER": "#f4a340",
        "DEFAULT_DENSITY": "comfortable",
        "LOCAL_AUTH_ENABLED": "on",
        "LDAP_USER_FILTER": "(&(objectClass=user)(sAMAccountName={username}))",
        "LDAP_START_TLS": "on",
        "LDAP_VALIDATE_CERT": "on",
        "LDAP_ROLE_MAPPINGS": "{}",
        "KEYCLOAK_ROLE_MAPPINGS": "{}",
        "SESSION_HOURS": "8",
        "MAX_UPLOAD_MB": "20",
        "DEFAULT_TICKET_PRIORITY": "P3",
        "NOTIFICATION_FROM_NAME": "Operations Hub",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"System settings saved" in response.data
    assert b"Operations Hub" in response.data
    with app.app_context():
        assert db.session.get(PlatformSetting, "COMPANY_NAME").value == "Example Corporation"


def test_dark_theme_is_removed(client, app):
    login(client)
    response = client.get("/preferences")
    assert b'value="dark"' not in response.data
    with app.app_context():
        assert all(pref.theme == "light" for pref in UserPreference.query.all())
