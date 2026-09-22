"""The assistant reaches across the product, always within the asker's authority."""
from datetime import timedelta

from app import (ApprovalVote, Asset, CatalogItem, CatalogRequest, ConfigurationItem, EnterpriseRecord, Knowledge, OperationalTask,
                 RequestedItem, SLADefinition, SupportGroup, TaskCI, TaskSLA, Ticket, User, db, now)
from serviceops_core.ai import access, modules
from tests.test_ai_privacy import scope_for, world  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401


def facts(user_id, question):
    evidence = access.collect_chat_evidence(scope_for(user_id), question)
    return {i["title"]: i["text"] for i in evidence.items if i["kind"] == "summary"}


def seed(world):
    item = CatalogItem(name="Laptop request", category="Hardware", description="d", tenant_id=1)
    db.session.add(item)
    db.session.flush()
    group = SupportGroup.query.filter_by(group_type="IT Fulfillment").first()
    for number, owner in (("REQ0000001", world.employee), ("REQ0000002", world.other)):
        request = CatalogRequest(number=number, requested_by_id=owner, requested_for_id=owner, tenant_id=1)
        db.session.add(request)
        db.session.flush()
        db.session.add(RequestedItem(number=number.replace("REQ", "RITM"), request_id=request.id, catalog_item_id=item.id, tenant_id=1))
    db.session.add(EnterpriseRecord(number="PRB0000001", domain="problem", record_type="Root cause analysis", title="Recurring VPN drops",
                                    description="d", requester_id=world.admin, tenant_id=1))
    definition = SLADefinition(name="P3 resolve", target_type="resolution", priority="P3", duration_minutes=60)
    db.session.add(definition)
    db.session.flush()
    db.session.add(TaskSLA(definition_id=definition.id, target_type="ticket", target_id=world.tickets["own"], breach_at=now() - timedelta(hours=1),
                           breached=True))
    db.session.add_all([
        Knowledge(title="Email troubleshooting", body="b", category="Email", author_id=world.admin, tenant_id=1),
        Knowledge(title="VPN guide", body="b", category="Network", author_id=world.admin, tenant_id=1),
        ConfigurationItem(name="SAMPLE Dell R640 Front", ci_class="Server", tenant_id=1),
        Asset(asset_tag="A-1", name="Laptop", asset_type="Laptop", tenant_id=1),
        ApprovalVote(gate_id=1, approver_id=world.manager, state="Requested", tenant_id=1),
        OperationalTask(number="CTASK0000001", task_kind="change", parent_type="ticket", parent_id=world.tickets["own"], title="t",
                        task_type="Implementation", assignment_group_id=group.id, assignee_id=world.manager)])
    db.session.commit()


def test_a_requester_sees_only_their_own_requests_and_nothing_operational(app, world):
    with app.app_context():
        seed(world)
        mine = facts(world.employee, "what requests do I have?")
        assert "REQ0000001" in mine["Service requests"] and "REQ0000002" not in mine["Service requests"]
        assert "no problem, event or other" in facts(world.employee, "any problems or known errors?")["Problems, events and other records"]
        assert "does not include the configuration database" in facts(world.employee, "how many dell servers do we have?")["Configuration items and assets"]
        assert "only available to administrators" in facts(world.employee, "how many users are there?")["Accounts"]
        blocked = facts(world.employee, "what sections can I not access?")["What you can and cannot open in ServiceOps"]
        assert "Audit log" in blocked.split("does not include:")[1] and "Audit log" not in blocked.split("does not include:")[0]


def test_an_administrator_gets_the_whole_picture_as_numbers_never_as_people(app, world):
    with app.app_context():
        seed(world)
        found = facts(world.admin, "how many dell servers, users, problems and breached SLAs do we have? what about knowledge articles and tasks?")
        assert "Server 1" in found["Configuration items and assets"] and "In stock 1" in found["Configuration items and assets"]
        assert "active accounts" in found["Accounts (numbers only)"] and "Test Employee" not in found["Accounts (numbers only)"]
        assert "employee@test.invalid" not in str(found)
        assert "PRB0000001" in found["Problems, events and other records"]
        assert "1 open tickets have breached" in found["Service level breaches (tickets you can see)"]
        assert "3 published articles" in found["Knowledge base"] and "Email 1" in found["Knowledge base"]
        assert "REQ0000001" in facts(world.admin, "list requests")["Service requests"]
        access_map = facts(world.admin, "what can I access?")["What you can and cannot open in ServiceOps"]
        assert "Audit log" in access_map.split("You can open:")[1]


def test_approvals_and_tasks_belong_to_the_person_asking(app, world):
    with app.app_context():
        seed(world)
        assert "1 approvals are waiting" in facts(world.manager, "do I have approvals waiting?")["Approvals"]
        assert "No approvals are waiting" in facts(world.admin, "any approvals for me?")["Approvals"]
        assert "1 change or problem tasks" in facts(world.manager, "what tasks are assigned to me?")["Your tasks"]
        assert "0 change or problem tasks" in facts(world.employee, "my tasks")["Your tasks"]


def test_cmdb_serial_lookup_returns_specs_and_only_visible_related_tickets(app, world):
    with app.app_context():
        ci = ConfigurationItem(name="Production database", ci_class="Server", serial_number="SN000002", vendor="Dell",
                               model="PowerEdge R750", environment="Production", operational_status="Operational", tenant_id=1)
        db.session.add(ci)
        db.session.flush()
        db.session.add(TaskCI(target_type="ticket", target_id=world.tickets["own"], ci_id=ci.id))
        db.session.commit()
        evidence = access.collect_chat_evidence(scope_for(world.admin), "SN000002 give me the server spec and related tickets")
        cmdb = [item for item in evidence.items if item.get("kind") == "ci"]
        assert len(cmdb) == 1 and cmdb[0]["reference"] == "SN000002"
        assert "Dell" in cmdb[0]["text"] and "PowerEdge R750" in cmdb[0]["text"]
        summary = {item["title"]: item["text"] for item in evidence.items if item["kind"] == "summary"}
        assert "1 tickets" in summary["Visible tickets related to Production database"]


def test_last_incident_and_active_change_list_use_visible_records(app, world):
    with app.app_context():
        change = Ticket(number="CHG0100099", kind="change", title="Database maintenance", description="Apply updates", state="Pending",
                        requester_id=world.admin, tenant_id=1)
        db.session.add(change)
        db.session.commit()
        recent = access.collect_chat_evidence(scope_for(world.admin), "what is the last incident received?")
        assert any(item.get("reference", "").startswith("INC") for item in recent.items)
        active = access.collect_chat_evidence(scope_for(world.admin), "Show me active changes")
        assert any(item.get("reference") == "CHG0100099" for item in active.items)


def test_page_suggestions_never_point_somewhere_the_person_may_not_go(app, world):
    with app.app_context():
        seed(world)
        requester = [p["label"] for p in modules.suggested_pages(scope_for(world.employee), "show me the audit log and users and audit evidence")]
        assert "Audit log" not in requester and "Users and access" not in requester
        admin = [p["label"] for p in modules.suggested_pages(scope_for(world.admin), "show me the audit log", limit=5)]
        assert "Audit log" in admin
        active_changes = [p["label"] for p in modules.suggested_pages(scope_for(world.admin), "Show me active changes")]
        assert active_changes[0] == "Changes" and "Active sessions" not in active_changes
        serial = [p["label"] for p in modules.suggested_pages(scope_for(world.admin), "Find serial number SN000002")]
        assert serial[0] == "CMDB and service map"
        assert modules.suggested_pages(scope_for(world.employee), "asdfgh qwerty") == []


def test_pages_arrive_as_working_links_with_the_answer(app, client, world, monkeypatch):
    import uuid
    from app import AIConfiguration
    from serviceops_core.ai import service
    from tests.test_ai_assistant import fake_stream
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://127.0.0.1:18099/v1/chat/completions")
    with app.app_context():
        db.session.add(AIConfiguration(tenant_id=1, enabled=True, incident_enabled=True, chat_enabled=True, provider="self_hosted",
                                       endpoint="http://127.0.0.1:18099/v1/chat/completions", model="m"))
        db.session.commit()
    monkeypatch.setattr(service, "generate_stream", fake_stream("You can find them in the knowledge area.", {}))
    login(client, "employee", "Employee123!")
    reply = client.post("/ai/chat/messages", json={"text": "where are the knowledge articles?", "request_key": str(uuid.uuid4())}).get_json()
    with app.app_context():
        while service.process_one():
            pass
    pages = client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()["messages"][1]["route"]["pages"]
    assert any(p["label"] == "Knowledge" and p["url"].startswith("/") for p in pages)


def test_change_risk_is_explained_when_the_ticket_is_cited(app, world):
    from app import ChangeGovernance
    with app.app_context():
        change = Ticket(number="CHG0088001", kind="change", title="Patch routers", description="d",
                        requester_id=world.admin, tenant_id=1)
        db.session.add(change)
        db.session.flush()
        db.session.add(ChangeGovernance(ticket_id=change.id, change_type="Normal", risk_score=72, impact="High",
                                        ccb_required=True, conflict_status="Conflict detected",
                                        implementation_plan="Apply firmware update", backout_plan="Roll back firmware"))
        db.session.commit()
        evidence = access.collect_chat_evidence(scope_for(world.admin), "tell me about CHG0088001")
        text = next(i["text"] for i in evidence.items if i.get("reference") == "CHG0088001")
        assert "risk: score 72/100" in text and "CCB approval required: yes" in text and "Conflict detected" in text


def test_natural_language_ticket_search_uses_only_visible_tickets(app, world):
    from app import GroupMember, SupportGroup, TicketAssignmentGroup
    with app.app_context():
        group = SupportGroup.query.filter(SupportGroup.group_type == "IT Fulfillment", SupportGroup.id.in_(
            GroupMember.query.filter_by(user_id=world.insider).with_entities(GroupMember.group_id))).one()
        p1 = Ticket(number="INC0088010", kind="incident", title="Payroll outage", description="d",
                   requester_id=world.admin, tenant_id=1, priority="P1", state="New")
        db.session.add(p1)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(ticket_id=p1.id, group_id=group.id))
        db.session.commit()
        found = facts(world.insider, f"show me P1 incidents assigned to {group.name}")
        key = next(k for k in found if k.startswith("Tickets matching"))
        assert "INC0088010" in found[key] and "priority P1" in key and group.name in key
        # A requester never sees tickets outside their own, however the filters are phrased.
        requester_found = facts(world.other, "show me P1 incidents")
        rkey = next(k for k in requester_found if k.startswith("Tickets matching"))
        assert "INC0088010" not in requester_found[rkey]
