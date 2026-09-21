"""Assistant memory: explicit, private, visible, deletable, and never a place for secrets."""
import uuid

import pytest

from app import AIConfiguration, AIConnection, AIMemory, User, db
from serviceops_core.ai import access, memory, service
from serviceops_models import settings_cipher
from tests.test_ai_assistant import fake_stream
from tests.test_ai_privacy import scope_for, world  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401


@pytest.fixture()
def ready(app, monkeypatch):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://127.0.0.1:18099/v1/chat/completions")
    with app.app_context():
        db.session.add(AIConfiguration(tenant_id=1, enabled=True, incident_enabled=True, chat_enabled=True, external_consent=True))
        db.session.add(AIConnection(tenant_id=1, name="Mac", provider="self_hosted", model="qwen3", endpoint="http://127.0.0.1:18099/v1/chat/completions",
                                    key_encrypted=settings_cipher().encrypt(b"k").decode()))
        db.session.commit()


def chat(client, text, conversation=None):
    r = client.post("/ai/chat/messages", json={"text": text, "request_key": str(uuid.uuid4()), "conversation_id": conversation})
    assert r.status_code == 201, r.data
    return r.get_json()


def drain(app):
    with app.app_context():
        while service.process_one():
            pass


def last(client, reply):
    return client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()["messages"][-1]


@pytest.mark.parametrize("text,expected", [
    ("Remember that I prefer short answers", ("remember", "I prefer short answers")),
    ("please remember: our VPN gateway is in Tokyo.", ("remember", "our VPN gateway is in Tokyo")),
    ("From now on answer in simple language", ("remember", "From now on, answer in simple language")),
    ("forget everything", ("forget_all", "")),
    ("What do you remember about VPN?", None), ("I remember when it broke", None)])
def test_commands(text, expected):
    assert memory.parse_command(text) == expected


def test_a_note_is_saved_without_calling_the_model_and_shown_back(app, client, world, ready, monkeypatch):
    monkeypatch.setattr(service, "generate_stream", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no model call needed")))
    login(client, "employee", "Employee123!")
    reply = chat(client, "Remember that I prefer short answers")
    drain(app)
    assert "I'll remember that" in last(client, reply)["content"]
    notes = client.get("/ai/chat/memories").get_json()
    assert notes["enabled"] and [n["text"] for n in notes["notes"]] == ["I prefer short answers"] and notes["notes"][0]["kind"] == "preference"


def test_notes_are_used_as_context_for_later_questions_and_only_for_their_owner(app, client, world, ready, monkeypatch):
    seen = []
    monkeypatch.setattr(service, "generate_stream", fake_stream("Sure.", {}, capture=seen))
    login(client, "employee", "Employee123!")
    drain(app)
    chat(client, "Remember that our finance team uses the Tokyo VPN gateway")
    drain(app)
    chat(client, "Which VPN gateway should the finance team use?")
    drain(app)
    assert "Tokyo VPN gateway" in str(seen)
    client.get("/logout")
    seen.clear()
    login(client, "admin", "Admin123!")
    chat(client, "Which VPN gateway should the finance team use?")
    drain(app)
    assert "Tokyo" not in str(seen)
    assert client.get("/ai/chat/memories").get_json()["notes"] == []


def test_secrets_and_payment_numbers_are_refused_and_personal_details_keep_chats_private(app, client, world, ready, monkeypatch):
    login(client, "employee", "Employee123!")
    refused = chat(client, "Remember that my password is Hunter2-secret-x")
    drain(app)
    assert "won't remember" in last(client, refused)["content"]
    assert chat(client, "Remember my card number is 4111 1111 1111 1111") and (drain(app) or True)
    assert client.get("/ai/chat/memories").get_json()["notes"] == []
    with app.app_context():
        scope = scope_for(world.employee)
        note, _ = memory.store(scope, "my manager's mobile is +81 90 1234 5678")
        db.session.commit()
        assert note is not None
        evidence = access.collect_chat_evidence(scope, "my manager mobile")
        reasons = set()
        evidence.scanner = lambda text, kind: reasons.update(__import__("serviceops_core.ai.routing", fromlist=["scan"]).scan(text, type("C", (), {
            "detect_personal": True, "detect_credentials": True, "detect_financial": True, "sensitive_terms": ""})(), kind))
        memory.add_to_evidence(scope, "my manager mobile", evidence, None)
        assert "personal" in reasons


def test_limits_and_duplicates(app, world):
    with app.app_context():
        scope = scope_for(world.employee)
        assert memory.store(scope, "x" * 300)[0] is None
        first, _ = memory.store(scope, "I work from Osaka")
        again, message = memory.store(scope, "i work from osaka")
        assert again.id == first.id and "already" in message
        for i in range(memory.MAX_NOTES):
            memory.store(scope, f"note number {i}")
        assert memory.store(scope, "one too many")[0] is None


def test_owner_can_delete_one_or_clear_all_even_with_the_feature_off_and_others_cannot(app, client, world, ready):
    with app.app_context():
        scope = scope_for(world.employee)
        keep, _ = memory.store(scope, "I prefer detailed answers")
        gone, _ = memory.store(scope, "I sit on floor three")
        db.session.commit()
        keep_id, gone_id = keep.id, gone.id
        db.session.get(AIConfiguration, 1).memory_enabled = False
        db.session.commit()
    login(client, "admin", "Admin123!")
    assert client.post(f"/ai/chat/memories/{gone_id}/delete").status_code == 404  # not theirs
    client.get("/logout")
    login(client, "employee", "Employee123!")
    assert client.get("/ai/chat/memories").get_json() == {"enabled": False, "limit": 30, "notes": []}
    assert client.post("/ai/chat/memories", json={"text": "new note"}).status_code == 403
    assert client.post(f"/ai/chat/memories/{gone_id}/delete").get_json() == {"deleted": True}
    assert client.post("/ai/chat/memories/clear").get_json() == {"cleared": 1}
    with app.app_context():
        assert AIMemory.query.count() == 0


def test_forget_everything_by_asking_and_purge_on_erasure(app, client, world, ready):
    login(client, "employee", "Employee123!")
    chat(client, "remember that I like tea")
    drain(app)
    reply = chat(client, "forget everything")
    drain(app)
    assert "forgotten 1 note" in last(client, reply)["content"]
    with app.app_context():
        memory.store(scope_for(world.employee), "another note")
        db.session.commit()
        service.purge_user_conversations(world.employee)
        db.session.commit()
        assert AIMemory.query.count() == 0


def test_memory_can_be_switched_off_by_the_administrator(app, client, world, ready, monkeypatch):
    with app.app_context():
        db.session.get(AIConfiguration, 1).memory_enabled = False
        db.session.commit()
    monkeypatch.setattr(service, "generate_stream", fake_stream("Sure.", {}))
    login(client, "employee", "Employee123!")
    reply = chat(client, "Remember that I prefer short answers")
    drain(app)
    assert last(client, reply)["content"] == "Sure."  # treated as a normal question: nothing was stored
    with app.app_context():
        assert AIMemory.query.count() == 0


def test_a_suggested_note_is_parsed_and_only_saved_when_the_person_clicks(app, client, world, ready, monkeypatch):
    monkeypatch.setattr(service, "generate_stream", fake_stream("Noted, I'll keep answers brief.\n[[REMEMBER]] Prefers brief answers\n[[FOLLOWUPS]] Anything else?", {}))
    login(client, "employee", "Employee123!")
    reply = chat(client, "please keep your answers brief in future, thanks")
    drain(app)
    message = last(client, reply)
    assert message["route"]["remember"] == "Prefers brief answers" and "[[" not in message["content"]
    with app.app_context():
        assert AIMemory.query.count() == 0
    assert client.post("/ai/chat/memories", json={"text": message["route"]["remember"]}).status_code == 201
    assert client.post("/ai/chat/memories", json={"text": "the password is Hunter2-secret-x"}).status_code == 400
