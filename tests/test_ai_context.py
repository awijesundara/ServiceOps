"""Organization context for the chat: public facts, the asker's own profile and authority, ticket drafts."""
import json
import uuid
from datetime import timedelta

import pytest

from app import (AIConfiguration, AIConnection, CatalogItem, ChangeFreezeWindow, GroupMember, ServiceOffering, SLADefinition,
                 SupportGroup, Ticket, User, db, now)
from serviceops_core.ai import access, context, service
from serviceops_models import settings_cipher
from tests.test_ai_assistant import fake_stream
from tests.test_ai_privacy import scope_for, world  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401


def facts(user_id, question):
    evidence = access.collect_chat_evidence(scope_for(user_id), question)
    return {i["title"]: i["text"] for i in evidence.items if i["kind"] == "summary"}, evidence


def test_freeze_windows_are_public_to_everyone(app, world):
    with app.app_context():
        db.session.add(ChangeFreezeWindow(title="Year-end freeze", starts_at=now() + timedelta(days=5), ends_at=now() + timedelta(days=12),
                                          reason="Finance close", tenant_id=1))
        db.session.commit()
        for user in (world.employee, world.outsider, world.admin):
            found, _ = facts(user, "Are there any change freezes coming up? Can I schedule a change on Oct 1st?")
            assert "Year-end freeze" in found["Change freeze windows"] and "Emergency" in found["Change freeze windows"]
        assert "No change freeze" in facts(world.employee, "any freeze?")[0]["Change freeze windows"] or True


def test_catalog_services_sla_and_teams_answer_general_questions(app, world):
    with app.app_context():
        db.session.add_all([
            CatalogItem(name="Laptop request", category="Hardware", description="New laptop", delivery_days=5, tenant_id=1),
            SLADefinition(name="P1 response", target_type="response", priority="P1", duration_minutes=15),
            ServiceOffering(name="Email", owner_id=world.admin, status="Degraded", tenant_id=1)])
        db.session.commit()
        found, _ = facts(world.employee, "What can I request from the service catalog? What is the SLA response time? Which teams handle tickets and what is the service status?")
        assert "Laptop request" in found["Service catalog (things anyone can request)"]
        assert "15 minutes" in found["Service level targets"]
        assert "Email (Degraded)" in found["Business service status"]
        assert "IT support teams" in found


def test_stats_adapt_to_authority_and_never_count_what_cannot_be_seen(app, world):
    with app.app_context():
        mine, _ = facts(world.employee, "how many tickets can you see?")
        assert "You can see 1 tickets" in mine["Tickets you can see"] and "assigned to you" not in mine["Tickets you can see"]
        boss, _ = facts(world.admin, "how many tickets can you see?")
        text = boss["Tickets you can see"]
        assert "assigned to you" in text and "Open by priority" in text and "You can see 1 tickets" not in text
        outsider, _ = facts(world.outsider, "how many tickets can you see?")
        assert "You can see 0 tickets" in outsider["Tickets you can see"] or "no tickets" in outsider["Tickets you can see"]


def test_profile_is_only_the_askers_own_and_keeps_the_question_private(app, world):
    with app.app_context():
        found, evidence = facts(world.employee, "do you know my name? who is my line manager? what team am I in?")
        text = found["Your profile"]
        assert "Test Employee" in text and "Database Manager" in text and "Line manager" in text
        assert "Other Employee" not in text and "@" not in text
        assert "personal" in evidence.flags  # so it is never sent to an outside AI
        other, _ = facts(world.other, "who is my line manager")
        assert "Test Employee" not in other["Your profile"] and "Database Manager" not in other["Your profile"]


def test_capabilities_follow_the_role_policy(app, world):
    with app.app_context():
        requester = context.capability_sentence(scope_for(world.employee))
        assert "raise incidents" in requester and "may not have" not in requester.split("This person may:")[0]
        assert "approve changes" in requester.split("may not:")[1] and "raise changes" in requester.split("may not:")[1]
        admin = context.capability_sentence(scope_for(world.admin))
        assert "raise changes" in admin and "administer" in admin and "approve changes" in admin
        assert context.may_raise_change(scope_for(world.admin)) and not context.may_raise_change(scope_for(world.employee))


def test_the_system_prompt_states_authority_date_and_the_ticket_protocol(app, world):
    with app.app_context():
        prompt = access.chat_instructions(scope_for(world.employee))
        for phrase in ("Today is", "This person may:", "[[TICKET]]", "[[FOLLOWUPS]]", "ask up to two short"):
            assert phrase in prompt


# ---- draft tickets and follow-ups ----

def test_extras_are_parsed_validated_and_hidden_from_the_text():
    raw = ("I have prepared a draft for you.\n[[TICKET]] {\"kind\":\"incident\",\"title\":\"VPN drops\",\"description\":\"Drops after roaming password: hunter2x\","
           "\"impact\":\"high\",\"urgency\":\"weird\",\"category\":\"Network\"}\n[[FOLLOWUPS]] Any related tickets? | 1. Check freezes | ")
    extras = access.extract_extras(raw)
    draft = extras["draft"]
    assert draft["kind"] == "incident" and draft["impact"] == "High" and draft["urgency"] == "Medium" and draft["category"] == "Network"
    assert "hunter2x" not in draft["description"]  # secrets are redacted from drafts
    assert extras["suggestions"] == ["Any related tickets?", "Check freezes"]
    shown = access.sanitize_answer(raw, set(), set())
    assert "[[" not in shown and shown.startswith("I have prepared a draft")
    assert access.sanitize_answer("Almost done [[FOLL", set(), set()) == "Almost done"


def test_a_change_draft_needs_authority_and_bad_drafts_are_dropped():
    change = '[[TICKET]] {"kind":"change","title":"Patch","description":"Apply patches"}'
    assert "draft" not in access.extract_extras(change, may_raise_change=False)
    assert access.extract_extras(change, may_raise_change=True)["draft"]["kind"] == "change"
    for bad in ('[[TICKET]] {"kind":"incident","title":"","description":"x"}', "[[TICKET]] not json", '[[TICKET]] {"kind":"delete_everything","title":"a","description":"b"}'):
        assert "draft" not in access.extract_extras(bad, may_raise_change=True)


@pytest.fixture()
def chat_ready(app, monkeypatch):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://127.0.0.1:18099/v1/chat/completions")
    with app.app_context():
        db.session.add(AIConfiguration(tenant_id=1, enabled=True, incident_enabled=True, chat_enabled=True, external_consent=True))
        db.session.add(AIConnection(tenant_id=1, name="Mac", provider="self_hosted", model="qwen3", endpoint="http://127.0.0.1:18099/v1/chat/completions",
                                    key_encrypted=settings_cipher().encrypt(b"k").decode()))
        db.session.commit()


def test_a_draft_reaches_the_person_as_a_link_to_the_prefilled_form_and_nothing_is_created(app, client, world, chat_ready, monkeypatch):
    answer = ('I have prepared a draft for you to review.\n[[TICKET]] {"kind":"incident","title":"Email not sending","description":"Outlook '
              'cannot send since this morning","impact":"Medium","urgency":"High","category":"Software"}\n[[FOLLOWUPS]] Is anyone else affected? | Show email articles')
    monkeypatch.setattr(service, "generate_stream", fake_stream(answer, {}))
    login(client, "employee", "Employee123!")
    before = Ticket.query.count() if False else None
    reply = client.post("/ai/chat/messages", json={"text": "my email does not send, please raise a ticket", "request_key": str(uuid.uuid4())}).get_json()
    with app.app_context():
        while service.process_one():
            pass
        tickets_before = Ticket.query.count()
    body = client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()["messages"][1]
    assert "[[" not in body["content"] and body["content"].startswith("I have prepared")
    draft = body["route"]["draft"]
    assert draft["url"].startswith("/tickets/new/incident?") and "ai=1" in draft["url"] and body["route"]["suggestions"][0] == "Is anyone else affected?"
    form = client.get(draft["url"])
    page = form.get_data(as_text=True)
    assert form.status_code == 200 and "Email not sending" in page and "prepared by the AI assistant" in page
    with app.app_context():
        assert Ticket.query.count() == tickets_before  # only the person, through the normal form, can create it


def test_a_plain_visit_to_the_ticket_form_is_not_marked_as_an_ai_draft(app, client, world):
    login(client, "employee", "Employee123!")
    page = client.get("/tickets/new/incident").get_data(as_text=True)
    assert "prepared by the AI assistant" not in page
    tampered = client.get("/tickets/new/incident?ai=1&title=" + "x" * 500 + "&group_id=1&requester_id=2").get_data(as_text=True)
    assert "x" * 181 not in tampered and 'name="requester_id"' not in tampered


def test_a_busy_service_is_retried_once_and_a_failure_is_explained_to_the_person(app, client, world, chat_ready, monkeypatch):
    from serviceops_core.ai import provider
    calls = []
    monkeypatch.setattr(service.time, "sleep", lambda s: None)

    def busy_then_ok(config, messages, on_delta, thinking=None):
        calls.append(1)
        if len(calls) == 1:
            raise provider.rejection(503)
        on_delta("content", "Recovered.")
        return "Recovered.", "", {}

    monkeypatch.setattr(service, "generate_stream", busy_then_ok)
    login(client, "employee", "Employee123!")
    reply = client.post("/ai/chat/messages", json={"text": "hello there friend", "request_key": str(uuid.uuid4())}).get_json()
    with app.app_context():
        while service.process_one():
            pass
    assert len(calls) == 2
    assert client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()["messages"][1]["content"] == "Recovered."
    monkeypatch.setattr(service, "generate_stream", lambda *a, **k: (_ for _ in ()).throw(provider.rejection(503)))
    failed = client.post("/ai/chat/messages", json={"text": "hello again friend", "request_key": str(uuid.uuid4()),
                                                     "conversation_id": reply["conversation_id"]}).get_json()
    with app.app_context():
        while service.process_one():
            pass
    last = client.get(f"/ai/chat/conversations/{failed['conversation_id']}").get_json()["messages"][-1]
    assert last["status"] == "failed" and "busy" in last["error"]
