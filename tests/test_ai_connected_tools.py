"""Connected tools (MCP): administration, safety boundaries and use from chat, against a real local MCP server."""
import json
import socket
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app import AIConfiguration, Audit, Tenant, User
from serviceops_core.ai import access, mcp, routing, service
from serviceops_models import AITool, AIToolServer, db, settings_cipher
from tests.test_ai_context import chat_ready  # noqa: F401
from tests.test_ai_privacy import world  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401

TOOLS = [
    {"name": "get_device", "title": "Device details", "description": "Look up a network device by name.",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string", "maxLength": 64}},
                     "required": ["name"], "additionalProperties": False},
     "annotations": {"readOnlyHint": True}},
    {"name": "delete_device", "description": "Delete a device.",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
     "annotations": {"readOnlyHint": False, "destructiveHint": True}},
    {"name": "owner_lookup", "description": "Who owns a device.",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "bad schema", "description": "Invalid name.", "inputSchema": {"type": "object"}},
    {"name": "not_object", "description": "Input is not an object.", "inputSchema": {"type": "string"}},
]


class FakeMcp:
    """A Streamable HTTP MCP server: sessions, JSON or SSE answers, and a record of what it received."""

    def __init__(self):
        self.calls, self.headers, self.sse, self.fail_calls, self.reply = [], [], False, False, None
        self.oauth, self.token_requests, self.valid_token = False, [], None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_DELETE(self):
                self.send_response(204)
                self.end_headers()

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/token":
                    import base64
                    from urllib.parse import parse_qs
                    form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                    owner.token_requests.append(form)
                    good = self.headers.get("Authorization") == "Basic " + base64.b64encode(b"serviceops:client-secret-1").decode()
                    if not good or form.get("grant_type") != "client_credentials":
                        self.send_response(401)
                        self.end_headers()
                        return
                    owner.valid_token = f"token-{len(owner.token_requests)}"
                    payload = json.dumps({"access_token": owner.valid_token, "token_type": "Bearer", "expires_in": 300}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if owner.oauth and self.headers.get("Authorization") != f"Bearer {owner.valid_token}":
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.loads(raw)
                owner.headers.append(dict(self.headers))
                if "id" not in body:  # a notification
                    self.send_response(202)
                    self.end_headers()
                    return
                method, extra = body["method"], {}
                if method == "initialize":
                    result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                              "serverInfo": {"name": "fake-inventory", "version": "1.0"}}
                    extra["Mcp-Session-Id"] = "session-123"
                elif method == "tools/list":
                    result = {"tools": TOOLS}
                elif method == "tools/call":
                    owner.calls.append(body["params"])
                    if owner.fail_calls:
                        self.send_response(500)
                        self.end_headers()
                        return
                    text = owner.reply or f"core-sw-01: Cisco Nexus, rack B4, status active ({body['params']['arguments']})"
                    result = {"content": [{"type": "text", "text": text}], "isError": False}
                else:
                    result = {}
                payload = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
                self.send_response(200)
                if owner.sse:
                    payload = b"event: message\ndata: " + payload + b"\n\n"
                    self.send_header("Content-Type", "text/event-stream")
                else:
                    self.send_header("Content-Type", "application/json")
                for name, value in extra.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.http.server_address[1]}/mcp"
        threading.Thread(target=self.http.serve_forever, daemon=True).start()


@pytest.fixture
def fake_mcp(monkeypatch):
    server = FakeMcp()
    monkeypatch.setenv("AI_MCP_PRIVATE_ENDPOINTS", server.url.rsplit("/", 1)[0])
    yield server
    server.http.shutdown()


def add_server(app, fake, *, role="agent", share=False, enable=("get_device",), tenant_id=1):
    with app.app_context():
        server = AIToolServer(tenant_id=tenant_id, name=f"Inventory {uuid.uuid4().hex[:6]}", url=fake.url,
                              auth_encrypted=mcp.encrypt_credential("Bearer s3cret-token"), minimum_role=role,
                              share_external=share)
        db.session.add(server)
        db.session.flush()
        mcp.discover(server)
        for tool in server.tools:
            tool.enabled = tool.name in enable
        config = db.session.get(AIConfiguration, tenant_id)
        if config:
            config.tools_enabled = True
        db.session.commit()
        return server.id


def planner_and_answer(plan, answer="core-sw-01 is a Cisco Nexus in rack B4 [S1].", capture=None):
    """A provider stand-in: the planning request gets `plan`, the answering request gets `answer`."""
    def stream(config, messages, on_delta, thinking=None, max_tokens=None):
        if capture is not None:
            capture.append(messages)
        text = plan if messages[0]["content"] == mcp.PLANNER else answer
        if on_delta("content", text) is False:
            raise service.StreamCancelled()
        return text, "", {}
    return stream


def ask(app, client, text, username="insider.agent", password="Agent123!"):
    login(client, username, password)
    reply = client.post("/ai/chat/messages", json={"text": text, "request_key": str(uuid.uuid4())}).get_json()
    with app.app_context():
        while service.process_one():
            pass
    return client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()["messages"][1]


# ----------------------------------------------------------------------------- destinations

def test_private_servers_need_the_operator_allowlist_and_internet_servers_need_https(app, monkeypatch):
    monkeypatch.delenv("AI_MCP_PRIVATE_ENDPOINTS", raising=False)
    with app.app_context():
        with pytest.raises(mcp.McpError, match="AI_MCP_PRIVATE_ENDPOINTS"):
            mcp.check_destination("http://10.20.0.5:8000/mcp")
        with pytest.raises(mcp.McpError):
            mcp.check_destination("https://user:pw@tools.example.com/mcp")
        with pytest.raises(mcp.McpError):
            mcp.check_destination("https://tools.example.com/mcp?key=abc")
        real = socket.getaddrinfo
        monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 443))]
                            if host == "rebind.example.com" else real(host, *a, **k))
        with pytest.raises(mcp.McpError, match="public address"):
            mcp.check_destination("https://rebind.example.com/mcp")
        monkeypatch.setenv("AI_MCP_PRIVATE_ENDPOINTS", "http://169.254.169.254")
        with pytest.raises(mcp.McpError):
            mcp.check_destination("http://169.254.169.254/latest")  # link-local metadata: never, even allowlisted


# ----------------------------------------------------------------------------- administration

def test_discovery_keeps_tools_off_and_destructive_tools_can_never_be_enabled(app, client, world, chat_ready, fake_mcp):
    login(client)
    response = client.post("/admin/ai/tools/servers", data={"name": "Network inventory", "url": fake_mcp.url,
                                                             "auth_value": "Bearer s3cret-token", "minimum_role": "agent"})
    assert response.status_code == 302
    assert fake_mcp.headers[0]["Authorization"] == "Bearer s3cret-token"
    assert fake_mcp.headers[-1]["Mcp-Session-Id"] == "session-123"
    with app.app_context():
        server = AIToolServer.query.filter_by(name="Network inventory").one()
        assert server.auth_encrypted and "s3cret" not in server.auth_encrypted and server.last_ok
        assert server.server_info == "fake-inventory 1.0"
        tools = {tool.name: tool for tool in server.tools}
        assert set(tools) == {"get_device", "delete_device", "owner_lookup"}  # invalid ones skipped
        assert not any(tool.enabled for tool in tools.values())
        ids = {name: tool.id for name, tool in tools.items()}
    client.post(f"/admin/ai/tools/{ids['delete_device']}/enabled", data={"enabled": "on", "confirm_read_only": "on"})
    client.post(f"/admin/ai/tools/{ids['owner_lookup']}/enabled", data={"enabled": "on"})
    client.post(f"/admin/ai/tools/{ids['get_device']}/enabled", data={"enabled": "on"})
    with app.app_context():
        enabled = {t.name for t in AITool.query.filter_by(enabled=True)}
    assert enabled == {"get_device"}  # destructive refused; unmarked needs confirmation
    client.post(f"/admin/ai/tools/{ids['owner_lookup']}/enabled", data={"enabled": "on", "confirm_read_only": "on"})
    with app.app_context():
        assert {t.name for t in AITool.query.filter_by(enabled=True)} == {"get_device", "owner_lookup"}
        assert Audit.query.filter_by(action="ai tool enabled").count() == 2
    page = client.get("/admin/ai").get_data(as_text=True)
    assert "Connected tools (MCP)" in page and "Network inventory" in page and "s3cret" not in page


def test_changing_the_address_removes_the_credential_and_disables_tools(app, client, world, chat_ready, fake_mcp):
    server_id = add_server(app, fake_mcp)
    login(client)
    with app.app_context():
        name = db.session.get(AIToolServer, server_id).name
    client.post("/admin/ai/tools/servers", data={"server_id": server_id, "name": name, "url": fake_mcp.url + "/v2",
                                                 "minimum_role": "agent", "enabled": "on"})
    with app.app_context():
        server = db.session.get(AIToolServer, server_id)
        assert server.auth_encrypted == "" and not any(tool.enabled for tool in server.tools)


def test_tool_administration_is_admin_only_and_tenant_scoped(app, client, world, chat_ready, fake_mcp):
    server_id = add_server(app, fake_mcp)
    with app.app_context():
        tool_id = AITool.query.filter_by(server_id=server_id, name="get_device").one().id
        other = Tenant(slug="mcp-other", name="Other")
        db.session.add(other)
        db.session.flush()
        foreign = AIToolServer(tenant_id=other.id, name="Theirs", url=fake_mcp.url)
        db.session.add(foreign)
        db.session.flush()
        foreign_tool = AITool(tenant_id=other.id, server_id=foreign.id, name="get_device", input_schema_json="{}", read_only=True)
        db.session.add(foreign_tool)
        db.session.commit()
        foreign_id, foreign_tool_id = foreign.id, foreign_tool.id
    login(client, "insider.agent", "Agent123!")
    for url in (f"/admin/ai/tools/servers/{server_id}/discover", f"/admin/ai/tools/servers/{server_id}/delete",
                f"/admin/ai/tools/{tool_id}/enabled", "/admin/ai/tools/servers"):
        assert client.post(url, data={"enabled": "on", "name": "x", "url": fake_mcp.url}).status_code in (302, 403)
    with app.app_context():
        assert db.session.get(AIToolServer, server_id) and db.session.get(AITool, tool_id).enabled
        assert AIToolServer.query.count() == 2
    login(client)
    assert client.post(f"/admin/ai/tools/servers/{foreign_id}/delete").status_code == 404
    assert client.post(f"/admin/ai/tools/{foreign_tool_id}/enabled", data={"enabled": "on"}).status_code == 404
    with app.app_context():
        assert db.session.get(AIToolServer, foreign_id)


# ----------------------------------------------------------------------------- planning

def test_only_valid_planned_calls_are_run(app, fake_mcp):
    with app.app_context():
        server = AIToolServer(tenant_id=1, name="Inv", url=fake_mcp.url)
        db.session.add(server)
        db.session.flush()
        mcp.discover(server)
        tools = sorted(server.tools, key=lambda t: t.name)
        get_device = next(t for t in tools if t.name == "get_device")
        key = f"T{tools.index(get_device) + 1}"
        plan = json.dumps({"calls": [
            {"tool": key, "arguments": {"name": "core-sw-01"}},
            {"tool": key, "arguments": {"name": "core-sw-01"}},             # duplicate
            {"tool": key, "arguments": {"name": 7}},                        # wrong type
            {"tool": key, "arguments": {"name": "x", "extra": 1}},          # additionalProperties false
            {"tool": key, "arguments": {}},                                 # required missing
            {"tool": "T99", "arguments": {}},                               # unknown
            {"tool": "get_device", "arguments": {"name": "a" * 65}},        # maxLength
        ]})
        planned, refused = mcp.parse_plan("```json\n" + plan + "\n```", tools)
        # Only the first MAX_CALLS + 2 entries are considered: a duplicate is skipped, three are refused.
        assert [(t.name, a) for t, a in planned] == [("get_device", {"name": "core-sw-01"})] and refused == 3
        for bad in ({"tool": "T99", "arguments": {}}, {"tool": "get_device", "arguments": {"name": "a" * 65}}):
            assert mcp.parse_plan(json.dumps({"calls": [bad]}), tools) == ([], 1)
        many = json.dumps({"calls": [{"tool": key, "arguments": {"name": f"sw-{i}"}} for i in range(6)]})
        assert len(mcp.parse_plan(many, tools)[0]) == mcp.MAX_CALLS
        assert mcp.parse_plan("No tools needed.", tools) == ([], 0)


# ----------------------------------------------------------------------------- chat

def test_chat_uses_an_enabled_tool_cites_it_and_keeps_the_answer_private(app, client, world, chat_ready, fake_mcp, monkeypatch):
    add_server(app, fake_mcp)
    captured = []
    monkeypatch.setattr(service, "generate_stream", planner_and_answer(
        '{"calls": [{"tool": "T1", "arguments": {"name": "core-sw-01"}}]}', capture=captured))
    body = ask(app, client, "What is core-sw-01 and where is it?")
    assert body["status"] == "completed", body
    assert fake_mcp.calls == [{"name": "get_device", "arguments": {"name": "core-sw-01"}}]
    planner, answer = captured
    assert "get_device" in planner[1]["content"] and "delete_device" not in planner[1]["content"]
    assert "rack B4" in answer[-1]["content"] and "untrusted data" in answer[-1]["content"]
    sources = body["route"].get("sources") or body.get("sources") or []
    assert any(source["kind"] == "connected_tool" for source in sources)
    assert body["route"]["location"] == "private" and "connected tool" in body["route"]["reason"]
    with app.app_context():
        row = Audit.query.filter_by(action="ai tool call").one()
        assert "get_device" in row.target and "core-sw-01" not in row.details and "ok=True" in row.details


def test_sse_answers_and_secrets_in_results_are_redacted(app, client, world, chat_ready, fake_mcp, monkeypatch):
    add_server(app, fake_mcp)
    fake_mcp.sse = True
    fake_mcp.reply = "core-sw-01 admin password: hunter2-very-secret; contact noc@example.com"
    captured = []
    monkeypatch.setattr(service, "generate_stream", planner_and_answer(
        '{"calls": [{"tool": "T1", "arguments": {"name": "core-sw-01"}}]}', capture=captured))
    body = ask(app, client, "Show core-sw-01")
    assert body["status"] == "completed" and fake_mcp.calls
    final = captured[-1][-1]["content"]
    assert "hunter2-very-secret" not in final and "noc@example.com" not in final


def test_people_without_staff_access_or_below_the_servers_role_never_use_tools(app, client, world, chat_ready, fake_mcp, monkeypatch):
    add_server(app, fake_mcp, role="manager")
    captured = []
    monkeypatch.setattr(service, "generate_stream", planner_and_answer(
        '{"calls": [{"tool": "T1", "arguments": {"name": "core-sw-01"}}]}', answer="I can help with that.", capture=captured))
    ask(app, client, "What is core-sw-01?")  # an agent, below the manager-only server
    ask(app, client, "What is core-sw-01?", "employee", "Employee123!")  # a requester
    assert fake_mcp.calls == [] and all(messages[0]["content"] != mcp.PLANNER for messages in captured)


def test_switched_off_tools_are_never_planned(app, client, world, chat_ready, fake_mcp, monkeypatch):
    add_server(app, fake_mcp)
    with app.app_context():
        db.session.get(AIConfiguration, 1).tools_enabled = False
        db.session.commit()
    captured = []
    monkeypatch.setattr(service, "generate_stream", planner_and_answer("{}", answer="Answer.", capture=captured))
    ask(app, client, "What is core-sw-01?")
    assert fake_mcp.calls == [] and len(captured) == 1


def test_a_failing_tool_does_not_stop_the_answer(app, client, world, chat_ready, fake_mcp, monkeypatch):
    add_server(app, fake_mcp)
    fake_mcp.fail_calls = True
    monkeypatch.setattr(service, "generate_stream", planner_and_answer(
        '{"calls": [{"tool": "T1", "arguments": {"name": "core-sw-01"}}]}', answer="I could not reach the inventory."))
    body = ask(app, client, "What is core-sw-01?")
    assert body["status"] == "completed" and body["content"].startswith("I could not reach")
    with app.app_context():
        assert "ok=False" in Audit.query.filter_by(action="ai tool call").one().details


def test_disabling_a_tool_withholds_answers_that_used_it(app, world, chat_ready, fake_mcp):
    server_id = add_server(app, fake_mcp)
    with app.app_context():
        tool = AITool.query.filter_by(server_id=server_id, name="get_device").one()
        agent = User.query.filter_by(username="insider.agent").one()
        scope = access.build_scope(agent, agent.role)
        source = [{"id": "S1", "kind": "connected_tool", "record_id": tool.id, "title": "x", "number": ""}]
        assert access.sources_still_accessible(scope, source)
        tool.enabled = False
        db.session.commit()
        assert not access.sources_still_accessible(scope, source)


def test_results_from_unshared_servers_keep_requests_on_private_ai(app):
    assert mcp.REASON in routing.REASON_TEXT
    with app.app_context():
        config = AIConfiguration(tenant_id=1, external_consent=True, external_scope="not_sensitive")
        assert routing.external_allowed(config, False, {"ticket"})
        assert not routing.external_allowed(config, bool({mcp.REASON}), {"ticket", mcp.REASON})


def test_shareable_servers_do_not_add_the_private_reason(app, world, chat_ready, fake_mcp):
    server_id = add_server(app, fake_mcp, share=True)
    with app.app_context():
        tool = AITool.query.filter_by(server_id=server_id, name="get_device").one()
        agent = User.query.filter_by(username="insider.agent").one()
        scope = access.build_scope(agent, agent.role)
        results, reasons = mcp.run_calls([(tool, {"name": "core-sw-01"})], scope, db.session.get(AIConfiguration, 1))
        assert results[0]["ok"] and mcp.REASON not in reasons


def test_credentials_are_encrypted_with_the_settings_cipher(app):
    with app.app_context():
        token = mcp.encrypt_credential("Bearer abc")
        assert settings_cipher().decrypt(token.encode()).decode() == "Bearer abc"



# ----------------------------------------------------------------------------- OAuth client credentials

def oauth_server(app, fake, **extra):
    with app.app_context():
        server = AIToolServer(tenant_id=1, name=f"RT {uuid.uuid4().hex[:6]}", url=fake.url, auth_mode="client_credentials",
                              token_url=fake.url.rsplit("/", 1)[0] + "/token", client_id="serviceops",
                              token_scope="rt:read:service", auth_encrypted=mcp.encrypt_credential("client-secret-1"), **extra)
        db.session.add(server)
        db.session.commit()
        return server.id


def test_client_credentials_tokens_are_fetched_cached_and_sent_as_bearer(app, fake_mcp):
    fake_mcp.oauth = True
    server_id = oauth_server(app, fake_mcp)
    with app.app_context():
        server = db.session.get(AIToolServer, server_id)
        assert mcp.discover(server)[0] == 3
        mcp.discover(server)
        assert len(fake_mcp.token_requests) == 1  # cached between sessions
        assert fake_mcp.token_requests[0] == {"grant_type": "client_credentials", "scope": "rt:read:service"}
        assert fake_mcp.headers[-1]["Authorization"] == "Bearer token-1"
        assert "client-secret-1" not in json.dumps(fake_mcp.headers)


def test_a_rejected_token_is_refreshed_once(app, fake_mcp):
    fake_mcp.oauth = True
    server_id = oauth_server(app, fake_mcp)
    with app.app_context():
        server = db.session.get(AIToolServer, server_id)
        mcp.discover(server)
        fake_mcp.valid_token = "revoked-by-the-service"  # the cached token-1 is no longer accepted
        with mcp.Session(server) as session:
            text, failed = session.call("get_device", {"name": "core-sw-01"})
        assert not failed and len(fake_mcp.token_requests) == 2


def test_a_wrong_client_secret_is_reported_without_calling_the_server(app, fake_mcp):
    fake_mcp.oauth = True
    server_id = oauth_server(app, fake_mcp)
    with app.app_context():
        server = db.session.get(AIToolServer, server_id)
        server.auth_encrypted = mcp.encrypt_credential("wrong")
        db.session.commit()
        mcp.forget_token(server_id)
        with pytest.raises(mcp.McpError, match="rejected the client"):
            mcp.discover(server)
        assert not fake_mcp.calls and all(h.get("Authorization", "").startswith("Basic") is False for h in fake_mcp.headers)


def test_token_addresses_follow_the_same_destination_rules(app, fake_mcp, monkeypatch):
    server_id = oauth_server(app, fake_mcp, )
    with app.app_context():
        server = db.session.get(AIToolServer, server_id)
        server.token_url = "http://10.9.9.9:8080/token"  # private, not allowlisted
        db.session.commit()
        mcp.forget_token(server_id)
        with pytest.raises(mcp.McpError, match="AI_MCP_PRIVATE_ENDPOINTS"):
            mcp.access_token(server)


def test_admin_form_saves_oauth_and_changing_the_client_removes_the_secret(app, client, world, chat_ready, fake_mcp):
    fake_mcp.oauth = True
    login(client)
    token_url = fake_mcp.url.rsplit("/", 1)[0] + "/token"
    form = {"name": "RT tickets", "url": fake_mcp.url, "auth_mode": "client_credentials", "token_url": token_url,
            "client_id": "serviceops", "token_scope": "rt:read:service", "minimum_role": "agent"}
    client.post("/admin/ai/tools/servers", data=form)  # no secret: refused
    with app.app_context():
        assert not AIToolServer.query.filter_by(name="RT tickets").first()
    client.post("/admin/ai/tools/servers", data={**form, "auth_value": "client-secret-1"})
    with app.app_context():
        server = AIToolServer.query.filter_by(name="RT tickets").one()
        assert server.auth_mode == "client_credentials" and server.last_ok and len(server.tools) == 3
        server_id = server.id
    client.post("/admin/ai/tools/servers", data={**form, "server_id": server_id, "client_id": "other-client", "enabled": "on"})
    with app.app_context():
        assert db.session.get(AIToolServer, server_id).auth_encrypted == ""
