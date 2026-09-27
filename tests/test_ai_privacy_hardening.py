"""AI privacy hardening: what external services never receive, contact details in
investigation evidence, and how long chat history is kept."""
import json
from datetime import timedelta

import pytest

from app import AIConfiguration, AIConnection, AIConversation, AIMessage, AIRun, Ticket, User, db, settings_cipher
from serviceops_core.ai import service
from serviceops_models import now
from tests.test_ai_chat import answer_with, ask, chat_config, finish_all  # noqa: F401  (autouse fixture)
from tests.test_ai_privacy import world  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401


def use_only(app, provider, endpoint):
    with app.app_context():
        config = db.session.get(AIConfiguration, 1)
        config.external_consent, config.external_scope = True, "not_sensitive"
        key = settings_cipher().encrypt(b"test-api-key").decode() if provider != "self_hosted" else ""
        db.session.add(AIConnection(tenant_id=1, name="Only service", provider=provider, endpoint=endpoint,
                                    model="test-model", key_encrypted=key))
        db.session.commit()


def asked_messages(app, client, monkeypatch, question="Which printer should I use on the third floor?"):
    seen = []
    answer_with(monkeypatch, "Restart the client.", seen)
    login(client, "employee", "Employee123!")
    assert ask(client, question).status_code == 201
    finish_all(app)
    assert seen, "the model was not called"
    return json.dumps(seen)


def without_contact_details(app, world):
    """The fixture ticket holds an email and phone number, which would keep every request private."""
    with app.app_context():
        db.session.get(Ticket, world.tickets["own"]).description = "Cannot reach VPN since this morning."
        db.session.commit()


def test_external_services_never_receive_the_askers_name_username_or_email(app, client, world, monkeypatch):
    use_only(app, "openai_compatible", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")
    without_contact_details(app, world)
    blob = asked_messages(app, client, monkeypatch, "Hi, I'm Test Employee. Which printer should I use on the third floor?")
    assert "Test Employee" not in blob and "employee@test.invalid" not in blob
    assert "the person asking" in blob
    assert "Requester" in blob  # the role is still stated, so the answer fits the person's access


def test_a_request_with_personal_details_never_goes_external(app, client, world, monkeypatch):
    """The employee's own VPN ticket holds an email and phone number: only private AI may see it."""
    use_only(app, "openai_compatible", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")
    monkeypatch.setattr(service, "generate_stream", lambda *_, **__: pytest.fail("sensitive request went external"))
    login(client, "employee", "Employee123!")
    assert ask(client, "What is happening with my VPN ticket?").status_code == 201
    finish_all(app)
    with app.app_context():
        route = json.loads(AIRun.query.one().route_json)
        assert route["location"] == "none" and route["sensitive"] is True


def test_the_organizations_own_ai_still_knows_who_is_asking(app, client, world, monkeypatch):
    use_only(app, "self_hosted", "http://127.0.0.1:18099/v1/chat/completions")
    without_contact_details(app, world)
    assert "Test Employee" in asked_messages(app, client, monkeypatch)


def test_identity_terms_leave_ordinary_words_alone():
    user = type("U", (), {"name": "Admin", "username": "admin", "email": ""})()
    messages = [{"role": "user", "content": "ask an admin or the administrator"}]
    assert service.withhold_identity(messages, service.identity_terms(user)) == messages
    named = type("U", (), {"name": "Anna Lee", "username": "anna.lee", "email": "Anna.Lee@corp.example"})()
    text = service.withhold_identity([{"role": "user", "content": "Anna Lee (ANNA.LEE@corp.example, anna.lee) and "
                                                                   "Annabel; hi Anna"}], service.identity_terms(named))
    assert text[0]["content"] == ("the person asking (the person asking, the person asking) and Annabel; "
                                  "hi the person asking")


def test_investigation_evidence_masks_contact_details_even_when_personal_detection_is_off(app, world):
    with app.app_context():
        db.session.get(AIConfiguration, 1).detect_personal = False
        identity = service.actor(db.session.get(User, world.admin), "admin")
        evidence, _ = service.collect_evidence(identity, world.tickets["own"])
        text = json.dumps(evidence)
        assert "employee@test.invalid" not in text and "090-1234-5678" not in text
        assert "[email removed]" in text and "10.20.0.5" in text


def conversation(tenant_id, user_id, last_message_at, running=False):
    row = AIConversation(tenant_id=tenant_id, user_id=user_id, actor_role="requester",
                         created_at=last_message_at, updated_at=last_message_at)
    db.session.add(row)
    db.session.flush()
    db.session.add(AIMessage(conversation_id=row.id, tenant_id=tenant_id, user_id=user_id, role="user",
                             content="question", created_at=last_message_at))
    if running:
        db.session.add(AIRun(tenant_id=tenant_id, user_id=user_id, actor_role="requester", config_revision=1,
                             request_key="k", status="running", provider="self_hosted", model="m",
                             conversation_id=row.id, kind="chat", created_at=last_message_at))
    return row.id


def test_idle_chats_are_deleted_after_the_retention_period(app, world):
    with app.app_context():
        config = db.session.get(AIConfiguration, 1)
        config.chat_retention_days = 30
        old = now() - timedelta(days=31)
        stale = conversation(1, world.employee, old)
        in_progress = conversation(1, world.employee, old, running=True)
        recent = conversation(1, world.employee, now() - timedelta(days=29))
        revived = conversation(1, world.employee, old)
        db.session.add(AIMessage(conversation_id=revived, tenant_id=1, user_id=world.employee, role="user",
                                 content="new question", created_at=now()))
        db.session.commit()

        assert service.purge_idle_conversations(config) == 1
        db.session.commit()
        remaining = {row.id for row in AIConversation.query.filter_by(tenant_id=1)}
        assert stale not in remaining and {in_progress, recent, revived} <= remaining
        assert AIMessage.query.filter_by(conversation_id=stale).count() == 0


@pytest.mark.parametrize("days, saved", [("90", 90), ("0", 30), ("400", 30)])
def test_admin_sets_chat_retention_within_bounds(app, client, days, saved):
    login(client, "admin", "Admin123!")
    client.post("/admin/ai", data={
        "action": "save", "enabled": "on", "chat_enabled": "on", "provider": "self_hosted", "model": "local-model",
        "endpoint": "http://127.0.0.1:18099/v1/chat/completions", "daily_limit": "100",
        "max_output_tokens": "1500", "retention_days": "7", "chat_retention_days": days,
    }, follow_redirects=True)
    with app.app_context():
        assert db.session.get(AIConfiguration, 1).chat_retention_days == saved


def test_chat_panel_tells_people_their_chats_are_private_and_when_they_are_deleted(app, client, world):
    with app.app_context():
        db.session.get(AIConfiguration, 1).chat_retention_days = 14
        db.session.commit()
    login(client, "employee", "Employee123!")
    page = client.get("/ai/chat").get_data(as_text=True)
    assert "Your chats are private to you and are deleted after 14 days without a message." in page
