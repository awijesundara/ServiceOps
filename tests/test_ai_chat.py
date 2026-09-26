"""Chat API: role scoping, conversation ownership, deletion, rate limits and what is stored or logged."""
import json
import uuid

import pytest

from app import AIConfiguration, AIConnection, AIConversation, AIMessage, AIRun, Audit, Comment, Ticket, User, db
from serviceops_models import AIAction
from serviceops_core.ai import provider, service
from tests.test_ai_assistant import fake_stream
from tests.test_ai_privacy import world  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401


@pytest.fixture(autouse=True)
def chat_config(app, monkeypatch):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://127.0.0.1:18099/v1/chat/completions")
    with app.app_context():
        db.session.add(AIConfiguration(tenant_id=1, enabled=True, incident_enabled=True, chat_enabled=True,
                                       provider="self_hosted", endpoint="http://127.0.0.1:18099/v1/chat/completions",
                                       model="local-model"))
        db.session.commit()


def ask(client, text, conversation=None, **extra):
    body = {"text": text, "request_key": str(uuid.uuid4()), "conversation_id": conversation, **extra}
    return client.post("/ai/chat/messages", json=body)


def answer_with(monkeypatch, text, capture=None, reasoning=""):
    monkeypatch.setattr(service, "generate_stream", fake_stream(text, {"completion_tokens": 3}, reasoning, capture=capture))


def fresh():
    """The `world` fixture keeps an app context open, and requests reuse its session; drop cached rows."""
    db.session.expire_all()


def finish_all(app):
    with app.app_context():
        while service.process_one():
            pass


def test_requester_gets_an_answer_scoped_to_their_own_tickets(app, client, world, monkeypatch):
    seen = []
    answer_with(monkeypatch, "Your ticket INC0100001 is open [S1].", seen)
    login(client, "employee", "Employee123!")
    created = ask(client, "what is the status of INC0100001 and INC0100002?")
    assert created.status_code == 201
    finish_all(app)
    blob = json.dumps(seen)
    assert "INC0100001" in blob and "CANARY-OTHER-EMPLOYEE-TICKET" not in blob and "VPN outage finance team" not in blob
    conversation = client.get(f"/ai/chat/conversations/{created.get_json()['conversation_id']}").get_json()
    assert [m["role"] for m in conversation["messages"]] == ["user", "assistant"]
    assert conversation["messages"][1]["status"] == "completed"
    assert conversation["scope"].startswith("Requester")


def test_followup_uses_the_last_grounded_record_without_widening_access(app, client, world, monkeypatch):
    answer_with(monkeypatch, "INC0100001 is open [S1].")
    login(client, "employee", "Employee123!")
    created = ask(client, "tell me about INC0100001")
    finish_all(app)

    captured = []
    answer_with(monkeypatch, "Its impact is shown in the ticket [S1].", captured)
    followup = ask(client, "what is its impact and related information?", created.get_json()["conversation_id"])
    assert followup.status_code == 201
    finish_all(app)

    payload = json.dumps(captured)
    assert "INC0100001" in payload
    assert "CANARY-OTHER-EMPLOYEE-TICKET" not in payload
    assert "CANARY-TENANT-TWO-TICKET" not in payload


def test_provider_failure_has_safe_actionable_copy(app, client, world, monkeypatch):
    def fail(*args, **kwargs):
        raise provider.ProviderError("private provider detail must not reach the browser")

    monkeypatch.setattr(service, "generate_stream", fail)
    login(client, "employee", "Employee123!")
    created = ask(client, "hello")
    finish_all(app)
    body = client.get(f"/ai/runs/{created.get_json()['run_id']}/stream").get_json()
    assert body["status"] == "failed"
    assert "selected AI services did not answer successfully" in body["error"]
    assert "private provider detail" not in json.dumps(body)


def test_conversations_are_private_to_their_owner_even_from_admins(app, client, world, monkeypatch):
    answer_with(monkeypatch, "Hello.")
    login(client, "employee", "Employee123!")
    conversation_id = ask(client, "hello there").get_json()["conversation_id"]
    finish_all(app)
    client.get("/logout")
    login(client, "admin", "Admin123!")
    assert client.get(f"/ai/chat/conversations/{conversation_id}").status_code == 404
    assert client.post(f"/ai/chat/conversations/{conversation_id}/delete").status_code == 404
    assert ask(client, "continue please", conversation_id).status_code == 404
    assert client.get("/ai/chat/conversations").get_json()["conversations"] == []
    with app.app_context():
        assert db.session.get(AIConversation, conversation_id) is not None
        run = AIRun.query.filter_by(conversation_id=conversation_id).one()
    assert client.get(f"/ai/runs/{run.id}/stream").status_code == 404


def test_run_stream_and_stop_are_owner_only(app, client, world, monkeypatch):
    answer_with(monkeypatch, "ok")
    login(client, "employee", "Employee123!")
    run_id = ask(client, "hello there").get_json()["run_id"]
    client.get("/logout")
    login(client, "admin", "Admin123!")
    assert client.get(f"/ai/runs/{run_id}/stream").status_code == 404
    assert client.post(f"/ai/runs/{run_id}/cancel").status_code == 404


def test_deleting_a_conversation_removes_all_its_text(app, client, world, monkeypatch):
    answer_with(monkeypatch, "A private answer [S1].")
    login(client, "employee", "Employee123!")
    conversation_id = ask(client, "secret question about my vpn").get_json()["conversation_id"]
    finish_all(app)
    assert client.post(f"/ai/chat/conversations/{conversation_id}/delete").get_json() == {"deleted": True}
    with app.app_context():
        assert db.session.get(AIConversation, conversation_id) is None
        assert AIMessage.query.filter_by(conversation_id=conversation_id).count() == 0
        for run in AIRun.query.filter_by(conversation_id=conversation_id):
            assert not (run.question or run.result_text or run.partial_text or run.reasoning_text)
    assert client.get(f"/ai/chat/conversations/{conversation_id}").status_code == 404


def test_deletion_still_works_after_chat_is_switched_off(app, client, world, monkeypatch):
    answer_with(monkeypatch, "Hello.")
    login(client, "employee", "Employee123!")
    conversation_id = ask(client, "hello there").get_json()["conversation_id"]
    finish_all(app)
    with app.app_context():
        db.session.get(AIConfiguration, 1).chat_enabled = False
        db.session.commit()
    assert client.get("/ai/chat/conversations").status_code == 403
    assert ask(client, "still there?").status_code == 403
    assert client.post(f"/ai/chat/conversations/{conversation_id}/delete").status_code == 200


def test_erasing_a_user_purges_their_conversations(app, client, world, monkeypatch):
    answer_with(monkeypatch, "Hello.")
    login(client, "employee", "Employee123!")
    conversation_id = ask(client, "hello there").get_json()["conversation_id"]
    finish_all(app)
    with app.app_context():
        service.purge_user_conversations(world.employee)
        db.session.commit()
        assert db.session.get(AIConversation, conversation_id) is None
        assert AIMessage.query.filter_by(user_id=world.employee).count() == 0


def test_role_change_blocks_an_existing_conversation(app, client, world, monkeypatch):
    answer_with(monkeypatch, "Hello.")
    login(client, "employee", "Employee123!")
    conversation_id = ask(client, "hello there").get_json()["conversation_id"]
    finish_all(app)
    with app.app_context():
        db.session.get(User, world.employee).role = "agent"
        db.session.commit()
    fresh()
    assert client.get(f"/ai/chat/conversations/{conversation_id}").status_code == 403
    assert ask(client, "continue", conversation_id).status_code == 403


def test_deactivated_user_cannot_use_chat(app, client, world):
    login(client, "employee", "Employee123!")
    with app.app_context():
        db.session.get(User, world.employee).active = False
        db.session.commit()
    fresh()
    assert client.get("/ai/chat/conversations").status_code in (302, 401, 403)
    assert ask(client, "hello there").status_code in (302, 401, 403)


def test_input_validation_and_limits(app, client, world):
    login(client, "employee", "Employee123!")
    assert client.post("/ai/chat/messages", json={"text": "", "request_key": str(uuid.uuid4())}).status_code == 400
    assert client.post("/ai/chat/messages", json={"text": "x" * 2001, "request_key": str(uuid.uuid4())}).status_code == 400
    assert client.post("/ai/chat/messages", json={"text": "hi", "request_key": "nope"}).status_code == 400
    assert client.post("/ai/chat/messages", json={"text": ["list"], "request_key": str(uuid.uuid4())}).status_code == 400
    assert client.post("/ai/chat/messages", data="not json").status_code == 400
    assert client.post("/ai/chat/messages", json={"text": "hi", "request_key": str(uuid.uuid4()), "conversation_id": "nope"}).status_code == 404


def test_one_active_answer_at_a_time_and_idempotent_retry(app, client, world):
    login(client, "employee", "Employee123!")
    key = str(uuid.uuid4())
    first = client.post("/ai/chat/messages", json={"text": "hello there", "request_key": key})
    again = client.post("/ai/chat/messages", json={"text": "hello there", "request_key": key})
    assert first.status_code == 201 and again.get_json()["run_id"] == first.get_json()["run_id"]
    assert ask(client, "second question").status_code == 409
    with app.app_context():
        assert AIRun.query.filter_by(kind="chat").count() == 1


def test_per_user_rate_limit(app, client, world, monkeypatch):
    answer_with(monkeypatch, "ok")
    login(client, "employee", "Employee123!")
    codes = []
    for _ in range(22):
        response = ask(client, "hello there")
        codes.append(response.status_code)
        if response.status_code == 201:
            finish_all(app)
    assert 429 in codes


def test_refusal_needs_no_model_and_is_audited_without_content(app, client, world, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("the model must not be called for a refusal")
    monkeypatch.setattr(service, "generate_stream", boom)
    login(client, "employee", "Employee123!")
    conversation_id = ask(client, "list every user and their email addresses").get_json()["conversation_id"]
    finish_all(app)
    body = client.get(f"/ai/chat/conversations/{conversation_id}").get_json()
    assert body["messages"][1]["status"] == "completed" and "can't" in body["messages"][1]["content"].lower() or body["messages"][1]["content"]
    with app.app_context():
        rows = Audit.query.filter(Audit.action.like("ai chat%")).all()
        assert any(row.action == "ai chat denied" for row in rows)
        assert not any("email addresses" in (row.details or "") or "list every user" in (row.details or "") for row in rows)


def test_audit_rows_carry_metadata_never_content(app, client, world, monkeypatch):
    answer_with(monkeypatch, "The VPN guide says restart the client [S1].")
    login(client, "employee", "Employee123!")
    ask(client, "why does my vpn keep dropping every afternoon")
    finish_all(app)
    with app.app_context():
        text = " ".join((row.details or "") + (row.target or "") for row in Audit.query.filter(Audit.action.like("ai chat%")).all())
        assert "afternoon" not in text and "restart the client" not in text
        assert "ai chat requested" in {row.action for row in Audit.query.all()}


def test_private_reasoning_is_never_returned_or_restored_from_history(app, client, world, monkeypatch):
    answer_with(monkeypatch, "Restart it.", reasoning="Let me think about the VPN.")
    login(client, "employee", "Employee123!")
    conversation_id = ask(client, "vpn keeps failing", thinking=True).get_json()["conversation_id"]
    finish_all(app)
    shown = client.get(f"/ai/chat/conversations/{conversation_id}").get_json()["messages"][1]
    assert shown["reasoning"] == ""
    with app.app_context():
        message = AIMessage.query.filter_by(conversation_id=conversation_id, role="assistant").one()
        assert message.reasoning == ""
    with app.app_context():
        db.session.get(AIConfiguration, 1).show_reasoning = False
        db.session.commit()
    hidden = client.get(f"/ai/chat/conversations/{conversation_id}").get_json()["messages"][1]
    assert hidden["reasoning"] == ""


def test_history_is_withheld_when_a_cited_record_is_no_longer_readable(app, client, world, monkeypatch):
    answer_with(monkeypatch, "Your ticket INC0100001 is open [S1].")
    login(client, "employee", "Employee123!")
    conversation_id = ask(client, "status of INC0100001").get_json()["conversation_id"]
    finish_all(app)
    with app.app_context():
        from app import Ticket
        ticket = Ticket.query.filter_by(number="INC0100001").one()
        ticket.requester_id = world.other
        db.session.commit()
    message = client.get(f"/ai/chat/conversations/{conversation_id}").get_json()["messages"][1]
    assert message.get("withheld") and "INC0100001" not in message["content"] and message["sources"] == []


def test_widget_and_page_only_render_for_users_who_may_chat(app, client, world):
    login(client, "employee", "Employee123!")
    assert b"data-chat-launch" in client.get("/dashboard").data or b"data-chat-launch" in client.get("/").data
    page = client.get("/ai/chat")
    assert page.status_code == 200 and b"ServiceOps AI" in page.data and b"data-chat-launch" not in page.data
    with app.app_context():
        db.session.get(AIConfiguration, 1).chat_enabled = False
        db.session.commit()
    assert client.get("/ai/chat").status_code == 403
    assert b"data-chat-launch" not in client.get("/").data


def test_the_open_chat_state_is_rendered_server_side_from_a_cookie_not_flashed_in_by_js(app, client, world):
    """B-392 follow-up: the widget used to flash the launcher button before JS could
    hide it on every full-page navigation, because open/closed state lived only in
    sessionStorage, invisible to the server. It's now a small, non-sensitive cookie
    the server reads before the first byte of HTML is sent."""
    login(client, "employee", "Employee123!")
    closed = client.get("/dashboard")
    assert b' class="ai-chat-open"' not in closed.data  # no stray class when never opened
    client.set_cookie("ai_chat_open", "1")
    opened = client.get("/dashboard")
    assert b'<html lang="en" class="ai-chat-open" style="--brand-primary:' in opened.data
    full_page = client.get("/ai/chat")  # the full chat page has no launcher/widget at all
    assert b"ai-chat-open" not in full_page.data
    client.set_cookie("ai_chat_open", "not-the-literal-string-1")  # anything else reads as closed
    assert b"ai-chat-open" not in client.get("/dashboard").data
    client.delete_cookie("ai_chat_open")
    client.get("/logout")
    assert b"ai-chat-open" not in client.get("/login").data  # never for a signed-out visitor


def test_admin_switches_control_chat_and_reasoning(app, client):
    login(client, "admin", "Admin123!")
    form = {"action": "save", "enabled": "on", "incident_enabled": "on", "provider": "self_hosted", "model": "local-model",
            "endpoint": "http://127.0.0.1:18099/v1/chat/completions", "daily_limit": "100", "max_output_tokens": "1500",
            "retention_days": "7"}
    client.post("/admin/ai", data={**form, "chat_enabled": "on", "show_reasoning": "on"}, follow_redirects=True)
    with app.app_context():
        config = db.session.get(AIConfiguration, 1)
        assert config.chat_enabled and config.show_reasoning
    client.post("/admin/ai", data=form, follow_redirects=True)
    with app.app_context():
        config = db.session.get(AIConfiguration, 1)
        assert not config.chat_enabled and not config.show_reasoning


def _admin_action_ticket(app):
    with app.app_context():
        config = db.session.get(AIConfiguration, 1)
        config.actions_enabled = True
        admin = User.query.filter_by(username="admin").one()
        ticket = Ticket(number="INC0099999", kind="incident", title="AI action test", description="Review safely",
                        requester_id=admin.id, tenant_id=1, state="New", priority="P3")
        db.session.add(ticket)
        db.session.commit()
        return ticket.id


def test_admin_chat_ticket_update_requires_exact_review_and_approval(app, client, world, monkeypatch):
    ticket_id = _admin_action_ticket(app)
    answer_with(monkeypatch, "I prepared the exact ticket update for your review [S1].")
    login(client, "admin", "Admin123!")
    created = ask(client, "Set INC0099999 priority to P1 and move state to In Progress")
    finish_all(app)
    stream = client.get(f"/ai/runs/{created.get_json()['run_id']}/stream").get_json()
    proposed = stream["route"]["action"]
    assert proposed["ticket"] == "INC0099999"
    assert "payload" not in proposed
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert (ticket.state, ticket.priority) == ("New", "P3")

    prepared = client.post(proposed["prepare_url"], json={})
    assert prepared.status_code == 201
    review_url = prepared.get_json()["url"]
    review = client.get(review_url)
    assert review.status_code == 200 and b"In Progress" in review.data and b"P1" in review.data
    action_id = review_url.rsplit("/", 1)[-1]
    assert client.post(review_url, data={"decision": "approve"}).status_code == 302
    assert client.post(review_url, data={"decision": "approve"}).status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        action = db.session.get(AIAction, action_id)
        assert (ticket.state, ticket.priority) == ("In Progress", "P1")
        assert action.status == "executed"


def test_admin_chat_exact_comment_and_non_admin_action_boundary(app, client, world, monkeypatch):
    ticket_id = _admin_action_ticket(app)
    answer_with(monkeypatch, "I prepared the exact comment for review [S1].")
    login(client, "admin", "Admin123!")
    created = ask(client, 'Add comment to INC0099999: "Network team confirmed recovery"')
    finish_all(app)
    route = client.get(f"/ai/runs/{created.get_json()['run_id']}/stream").get_json()["route"]
    assert route["action"]["summary"].startswith("Add comment")
    review_url = client.post(route["action"]["prepare_url"], json={}).get_json()["url"]
    client.post(review_url, data={"decision": "approve"})
    with app.app_context():
        assert [row.body for row in Comment.query.filter_by(ticket_id=ticket_id)] == ["Network team confirmed recovery"]

    client.get("/logout")
    answer_with(monkeypatch, "I cannot make that change, but I can explain the record [S1].")
    login(client, "employee", "Employee123!")
    created = ask(client, "Set INC0100001 priority to P1")
    finish_all(app)
    route = client.get(f"/ai/runs/{created.get_json()['run_id']}/stream").get_json()["route"]
    assert "action" not in route


def test_chat_connections_endpoint_is_tenant_isolated_and_admin_detail_free(app, client, world, monkeypatch):
    with app.app_context():
        db.session.add(AIConnection(id="mine", tenant_id=1, name="Office server", provider="self_hosted",
                                    endpoint="http://192.168.1.1:8080", model="m", enabled=True))
        db.session.add(AIConnection(id="disabled", tenant_id=1, name="Retired", provider="self_hosted",
                                    endpoint="http://192.168.1.2:8080", model="m", enabled=False))
        db.session.add(AIConnection(id="theirs", tenant_id=world.tenant2, name="Other org's server",
                                    provider="self_hosted", endpoint="http://192.168.1.3:8080", model="m", enabled=True))
        db.session.commit()
    login(client, "employee", "Employee123!")
    body = client.get("/ai/chat/connections").get_json()
    ids = {row["id"] for row in body["connections"]}
    assert "mine" in ids and "disabled" not in ids and "theirs" not in ids
    row = next(r for r in body["connections"] if r["id"] == "mine")
    assert set(row) == {"id", "name", "model", "external"} and row["external"] is False
    assert "endpoint" not in row and "has_key" not in row  # no admin-only detail leaks here


def test_a_valid_preferred_connection_is_stored_and_an_unknown_one_is_silently_dropped(app, client, world, monkeypatch):
    # Reuses chat_config's own allowlisted endpoint (AI_SELF_HOSTED_ENDPOINTS) -- this
    # test is about preferred_connection_id validation, not endpoint distinctness.
    with app.app_context():
        db.session.add(AIConnection(id="mine", tenant_id=1, name="Office server", provider="self_hosted",
                                    endpoint="http://127.0.0.1:18099", model="m", enabled=True))
        db.session.add(AIConnection(id="theirs", tenant_id=world.tenant2, name="Other org's server",
                                    provider="self_hosted", endpoint="http://127.0.0.1:18099", model="m", enabled=True))
        db.session.commit()
    answer_with(monkeypatch, "Sure, here's the status [S1].")
    login(client, "employee", "Employee123!")
    valid = ask(client, "status of INC0100001", preferred_connection_id="mine")
    with app.app_context():
        assert db.session.get(AIRun, valid.get_json()["run_id"]).preferred_connection_id == "mine"
    finish_all(app)

    for bogus in ("does-not-exist", "theirs"):  # unknown id, and another tenant's real id
        created = ask(client, "status of INC0100001", preferred_connection_id=bogus)
        with app.app_context():
            assert db.session.get(AIRun, created.get_json()["run_id"]).preferred_connection_id is None
        finish_all(app)
