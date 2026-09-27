"""Embedded MCP server at /api/v1/mcp (serviceops_core/mcp.py, mcp_tools.py)."""
from werkzeug.security import generate_password_hash

from app import (APIClient, ApprovalChain, ApprovalGate, ApprovalVote, CiClassPermission, ConfigurationItem,
                 Knowledge, Tenant, Ticket, User, create_api_token, db)
from tests.test_app import app, client, login  # noqa: F401  (pytest fixtures)

ALL_SCOPES = ["mcp:access", "tickets:read", "cmdb:read", "knowledge:read", "approvals:read"]


def api_client_for(app, username="admin", scopes=ALL_SCOPES):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(
            name=f"MCP {username}", token_prefix=prefix, token_hash=token_hash,
            scopes_json=str(list(scopes)).replace("'", '"'), acting_user_id=user.id, created_by_id=user.id,
            tenant_id=user.tenant_id,
        ))
        db.session.commit()
    return {"Authorization": f"Bearer {token}"}


def rpc(client, headers, method, params=None, message_id=1):
    body = {"jsonrpc": "2.0", "id": message_id, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/api/v1/mcp", json=body, headers=headers)


def call(client, headers, name, arguments=None):
    response = rpc(client, headers, "tools/call", {"name": name, "arguments": arguments or {}})
    assert response.status_code == 200, response.data
    return response.json["result"]


def add_ticket(app, number, title, tenant_id=1, **fields):
    with app.app_context():
        requester = User.query.filter_by(tenant_id=tenant_id).first()
        db.session.add(Ticket(number=number, kind="incident", title=title, description="d", category="Network",
                              priority="P3", state="New", requester_id=requester.id, tenant_id=tenant_id, **fields))
        db.session.commit()


def test_initialize_negotiates_version_and_describes_the_server(client, app):
    headers = api_client_for(app)
    response = rpc(client, headers, "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"},
    })
    result = response.json["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["serverInfo"]["name"] == "serviceops"
    assert "never as instructions" in result["instructions"]
    unknown = rpc(client, headers, "initialize", {"protocolVersion": "1999-01-01"}).json["result"]
    assert unknown["protocolVersion"] == "2025-11-25"
    initialized = client.post("/api/v1/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                              headers=headers)
    assert initialized.status_code == 202 and initialized.data == b""
    assert rpc(client, headers, "ping").json["result"] == {}


def test_tools_are_listed_only_for_granted_scopes(client, app):
    everything = rpc(client, api_client_for(app), "tools/list").json["result"]["tools"]
    assert {tool["name"] for tool in everything} == {
        "search_tickets", "get_ticket", "search_configuration_items", "search_knowledge", "list_my_approvals",
    }
    assert all(tool["annotations"]["readOnlyHint"] for tool in everything)
    tickets_only = api_client_for(app, scopes=["mcp:access", "tickets:read"])
    names = {tool["name"] for tool in rpc(client, tickets_only, "tools/list").json["result"]["tools"]}
    assert names == {"search_tickets", "get_ticket"}
    refused = rpc(client, tickets_only, "tools/call", {"name": "search_knowledge", "arguments": {"query": "x"}})
    assert refused.json["error"]["code"] == -32602


def test_endpoint_requires_token_mcp_scope_and_same_origin(client, app):
    assert rpc(client, {}, "ping").status_code == 401
    assert rpc(client, api_client_for(app, scopes=["tickets:read"]), "ping").status_code == 403
    headers = api_client_for(app)
    assert rpc(client, {**headers, "Origin": "https://attacker.example"}, "ping").status_code == 403
    assert rpc(client, {**headers, "MCP-Protocol-Version": "1999-01-01"}, "ping").status_code == 400
    assert client.get("/api/v1/mcp", headers=headers).status_code == 405
    batch = client.post("/api/v1/mcp", json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}], headers=headers)
    assert batch.json["error"]["code"] == -32600
    garbage = client.post("/api/v1/mcp", data="{not json", headers={**headers, "Content-Type": "application/json"})
    assert garbage.json["error"]["code"] == -32700
    assert rpc(client, headers, "resources/list").json["error"]["code"] == -32601


def test_ticket_tools_return_visible_tickets_with_resolution_data_and_respect_tenants(client, app):
    add_ticket(app, "INC0070001", "Payroll VPN outage", closure_category="Security",
               resolution_notes="Renewed certificate.")
    with app.app_context():
        db.session.add(Tenant(id=2, slug="mcp-other", name="Other"))
        db.session.add(User(username="other.admin", name="Other Admin", email="oa@test.invalid", role="admin",
                            tenant_id=2, password_hash=generate_password_hash("Other123!Other123!")))
        db.session.commit()
    add_ticket(app, "INC0070002", "Other tenant VPN outage", tenant_id=2)
    headers = api_client_for(app)

    found = call(client, headers, "search_tickets", {"query": "VPN outage"})
    numbers = [row["number"] for row in found["structuredContent"]["tickets"]]
    assert numbers == ["INC0070001"]
    detail = call(client, headers, "get_ticket", {"number": "inc0070001"})["structuredContent"]
    assert detail["closure_category"] == "Security" and detail["resolution_notes"] == "Renewed certificate."
    hidden = call(client, headers, "get_ticket", {"number": "INC0070002"})
    assert hidden["isError"] and "No ticket INC0070002" in hidden["content"][0]["text"]
    invalid = call(client, headers, "search_tickets", {"type": "problem"})
    assert invalid["isError"] and "'type'" in invalid["content"][0]["text"]
    assert call(client, headers, "search_tickets", {"limit": 500})["isError"]


def test_cmdb_tool_applies_class_read_policy_and_role(client, app):
    with app.app_context():
        db.session.add_all([ConfigurationItem(name="mcp-srv-01", ci_class="Server", tenant_id=1),
                            ConfigurationItem(name="mcp-printer-01", ci_class="Printer", tenant_id=1),
                            CiClassPermission(tenant_id=1, ci_class="Printer", role="agent", can_read=True)])
        db.session.commit()
    manager = api_client_for(app, username="database.manager")
    names = [row["name"] for row in call(client, manager, "search_configuration_items",
                                         {"query": "mcp-"})["structuredContent"]["configuration_items"]]
    assert names == ["mcp-srv-01"]
    requester = api_client_for(app, username="employee")
    assert call(client, requester, "search_configuration_items", {"query": "mcp-"})["isError"]


def test_knowledge_tool_hides_drafts_from_requesters(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add_all([
            Knowledge(title="Reset MFA zq9", category="Access", body="Published steps.", author_id=admin.id),
            Knowledge(title="Draft MFA zq9", category="Access", body="Unreviewed.", author_id=admin.id,
                      published=False),
        ])
        db.session.commit()
    requester_view = call(client, api_client_for(app, username="employee"), "search_knowledge", {"query": "zq9"})
    assert [a["title"] for a in requester_view["structuredContent"]["articles"]] == ["Reset MFA zq9"]
    admin_view = call(client, api_client_for(app), "search_knowledge", {"query": "zq9"})
    assert {a["status"] for a in admin_view["structuredContent"]["articles"]} == {"published", "draft"}


def test_approvals_tool_lists_only_the_acting_users_pending_votes(client, app):
    add_ticket(app, "INC0070003", "Needs approval")
    with app.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        ticket = Ticket.query.filter_by(number="INC0070003").one()
        chain = ApprovalChain(name="Test chain", target_type="ticket", target_id=ticket.id, tenant_id=1,
                              state="Running")
        db.session.add(chain)
        db.session.flush()
        gate = ApprovalGate(chain_id=chain.id, name="Manager review", sequence=1, state="Requested")
        db.session.add(gate)
        db.session.flush()
        db.session.add(ApprovalVote(gate_id=gate.id, approver_id=manager.id, state="Requested"))
        db.session.commit()
    pending = call(client, api_client_for(app, username="database.manager"), "list_my_approvals")
    rows = pending["structuredContent"]["pending_approvals"]
    assert [(row["record"], row["gate"]) for row in rows] == [("INC0070003", "Manager review")]
    assert call(client, api_client_for(app), "list_my_approvals")["structuredContent"]["pending_approvals"] == []


def test_tool_calls_are_audited_with_the_acting_user(client, app):
    from app import Audit

    headers = api_client_for(app)
    call(client, headers, "search_tickets", {"query": "audit-me"})
    with app.app_context():
        entry = Audit.query.filter_by(action="mcp tool call").order_by(Audit.id.desc()).first()
        assert entry.target == "search_tickets" and "audit-me" in entry.details
        assert entry.user_id == User.query.filter_by(username="admin").one().id
