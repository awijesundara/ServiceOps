"""Staff-requested generated drafts (resolution/closure notes, suggested replies, sentiment, knowledge articles):
the model writes the text from evidence it was already given, a person reviews the exact words, and nothing is
saved until they approve. The draft's target ticket must be one the model was actually shown -- it can never
name a ticket outside its evidence."""
import json
import uuid

import pytest

from app import AIAction, AIConfiguration, AIConnection, Comment, GroupMember, Knowledge, SupportGroup, Ticket, User, db
from serviceops_core.ai import access, actions, service
from serviceops_models import settings_cipher
from tests.test_ai_assistant import fake_stream
from tests.test_ai_privacy import scope_for, world  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401

ENDPOINT = "http://127.0.0.1:18099/v1/chat/completions"


def draft_ticket(world, kind="incident", state="Resolved"):
    from serviceops_models import TicketAssignmentGroup
    group_id = GroupMember.query.filter_by(user_id=world.insider).with_entities(GroupMember.group_id).scalar()
    ticket = Ticket(number="INC0088001", kind=kind, title="Draft note test", description="A resolved incident",
                    requester_id=world.employee, tenant_id=1, state=state, priority="P3")
    db.session.add(ticket)
    db.session.flush()
    db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=group_id))
    db.session.commit()
    return ticket.id


@pytest.fixture()
def ready(app, monkeypatch):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", ENDPOINT)
    with app.app_context():
        db.session.add(AIConfiguration(tenant_id=1, enabled=True, incident_enabled=True, chat_enabled=True, actions_enabled=True,
                                       external_consent=False, provider="self_hosted", endpoint=ENDPOINT, model="local-model"))
        db.session.commit()


def ask(client, text, conversation=None):
    r = client.post("/ai/chat/messages", json={"text": text, "request_key": str(uuid.uuid4()), "conversation_id": conversation})
    assert r.status_code == 201, r.data
    return r.get_json()


def drain(app):
    with app.app_context():
        while service.process_one():
            pass


# ---- extraction: grounding, role, validation ----

def test_a_draft_must_target_a_ticket_the_model_was_actually_shown(app, world):
    with app.app_context():
        scope = scope_for(world.insider, "agent")
        text = 'Done.\n[[DRAFT]] {"type":"resolution_note","ticket":"INC0100099","text":"Restarted the service."}'
        assert access.extract_generated_draft(text, scope, {"INC0100001"}) is None  # not in evidence
        assert access.extract_generated_draft(text, scope, {"INC0100099"}) == {
            "type": "resolution_note", "ticket": "INC0100099", "text": "Restarted the service."}


def test_requesters_never_get_a_draft_even_if_the_model_tries():
    from types import SimpleNamespace
    requester = SimpleNamespace(is_staff=False)
    text = '[[DRAFT]] {"type":"resolution_note","ticket":"INC0100001","text":"x"}'
    assert access.extract_generated_draft(text, requester, {"INC0100001"}) is None


@pytest.mark.parametrize("bad", [
    '[[DRAFT]] {"type":"delete_everything","ticket":"INC0100001","text":"x"}',
    '[[DRAFT]] {"type":"resolution_note","ticket":"NOT-A-TICKET","text":"x"}',
    '[[DRAFT]] {"type":"resolution_note","ticket":"INC0100001","text":""}',
    '[[DRAFT]] not json',
    '[[DRAFT]] {"type":"kb_article","ticket":"INC0100001","text":"body","title":""}',
])
def test_malformed_or_out_of_scope_drafts_are_refused(bad):
    from types import SimpleNamespace
    scope = SimpleNamespace(is_staff=True)
    assert access.extract_generated_draft(bad, scope, {"INC0100001"}) is None


def test_secrets_in_a_draft_are_redacted():
    from types import SimpleNamespace
    scope = SimpleNamespace(is_staff=True)
    text = '[[DRAFT]] {"type":"resolution_note","ticket":"INC0100001","text":"password=hunter2secret fixed it"}'
    draft = access.extract_generated_draft(text, scope, {"INC0100001"})
    assert "hunter2secret" not in draft["text"]


def test_the_marker_is_stripped_from_the_visible_answer():
    text = 'All set [S1].\n[[DRAFT]] {"type":"sentiment","ticket":"INC0100001","text":"Calm and cooperative."}'
    shown = access.sanitize_answer(text, {"INC0100001"}, {"S1"})
    assert "[[" not in shown and shown.startswith("All set")


# ---- end to end: agent drafts a resolution note ----

def test_agent_can_draft_and_approve_a_resolution_note(app, client, world, ready, monkeypatch):
    with app.app_context():
        ticket_id = draft_ticket(world)
    answer = 'I drafted a resolution note from the ticket history [S1].\n[[DRAFT]] {"type":"resolution_note","ticket":"INC0088001","text":"Restarted the VPN service; confirmed with the requester that access is restored."}'
    monkeypatch.setattr(service, "generate_stream", fake_stream(answer, {}))
    login(client, "insider.agent", "Agent123!")
    reply = ask(client, "Draft a resolution note for INC0088001")
    drain(app)
    stream = client.get(f"/ai/runs/{reply['run_id']}/stream").get_json()
    proposed = stream["route"]["action"]
    assert proposed["type"] == "resolution_note" and proposed["ticket"] == "INC0088001" and "payload" not in proposed
    assert "[[" not in stream["text"]

    prepared = client.post(proposed["prepare_url"], json={})
    assert prepared.status_code == 201
    review_url = prepared.get_json()["url"]
    page = client.get(review_url)
    assert page.status_code == 200 and b"Restarted the VPN service" in page.data and b"Resolution note" in page.data
    assert client.post(review_url, data={"decision": "approve"}).status_code == 302
    with app.app_context():
        comments = [c.body for c in Comment.query.filter_by(ticket_id=ticket_id)]
        assert any("Resolution note (AI-drafted, human-approved): Restarted the VPN service" in c for c in comments)
        action_id = review_url.rsplit("/", 1)[-1]
        assert db.session.get(AIAction, action_id).status == "executed"


def test_a_draft_cannot_target_a_ticket_outside_the_evidence_even_via_the_route(app, client, world, ready, monkeypatch):
    with app.app_context():
        ticket_id = draft_ticket(world)
        other = Ticket(number="INC0088002", kind="incident", title="Outside evidence", description="d",
                       requester_id=world.employee, tenant_id=1)
        db.session.add(other)
        db.session.commit()
    # The model tries to name a ticket that was never in its evidence; extraction refuses it, so no action exists to prepare.
    answer = 'Here you go [S1].\n[[DRAFT]] {"type":"resolution_note","ticket":"INC0088002","text":"Unrelated ticket note."}'
    monkeypatch.setattr(service, "generate_stream", fake_stream(answer, {}))
    login(client, "insider.agent", "Agent123!")
    reply = ask(client, "Draft a resolution note for INC0088001")
    drain(app)
    route = client.get(f"/ai/runs/{reply['run_id']}/stream").get_json()["route"]
    assert "action" not in route


def test_requesters_get_no_action_even_if_they_ask(app, client, world, ready, monkeypatch):
    with app.app_context():
        ticket_id = draft_ticket(world)
    answer = 'Sure [S1].\n[[DRAFT]] {"type":"resolution_note","ticket":"INC0088001","text":"Fixed."}'
    monkeypatch.setattr(service, "generate_stream", fake_stream(answer, {}))
    login(client, "employee", "Employee123!")
    reply = ask(client, "please draft a resolution note for INC0088001")
    drain(app)
    route = client.get(f"/ai/runs/{reply['run_id']}/stream").get_json()["route"]
    assert "action" not in route


def test_a_suggested_reply_and_a_sentiment_note_both_post_as_labeled_comments(app, client, world, ready, monkeypatch):
    with app.app_context():
        ticket_id = draft_ticket(world)
    for draft_type, label, text in (
        ("suggested_response", "Suggested reply", "Thanks for reporting this, it is now resolved."),
        ("sentiment", "Sentiment assessment", "Neutral; requester was cooperative throughout."),
    ):
        answer = f'Ok [S1].\n[[DRAFT]] {{"type":"{draft_type}","ticket":"INC0088001","text":"{text}"}}'
        monkeypatch.setattr(service, "generate_stream", fake_stream(answer, {}))
        login(client, "insider.agent", "Agent123!")
        reply = ask(client, f"draft a {draft_type.replace('_', ' ')} for INC0088001")
        drain(app)
        route = client.get(f"/ai/runs/{reply['run_id']}/stream").get_json()["route"]
        review_url = client.post(route["action"]["prepare_url"], json={}).get_json()["url"]
        assert client.post(review_url, data={"decision": "approve"}).status_code == 302
        client.get("/logout")
        login(client, "insider.agent", "Agent123!")
    with app.app_context():
        bodies = [c.body for c in Comment.query.filter_by(ticket_id=ticket_id)]
        assert any(b.startswith("Suggested reply (AI-drafted, human-approved):") for b in bodies)
        assert any(b.startswith("Sentiment assessment (AI-drafted, human-approved):") for b in bodies)


def test_a_knowledge_article_draft_is_created_unpublished_and_never_auto_published(app, client, world, ready, monkeypatch):
    with app.app_context():
        ticket_id = draft_ticket(world)
    answer = ('Here is a draft article [S1].\n[[DRAFT]] {"type":"kb_article","ticket":"INC0088001",'
              '"title":"Fixing VPN service drops","text":"Restart the VPN service and confirm connectivity with the user."}')
    monkeypatch.setattr(service, "generate_stream", fake_stream(answer, {}))
    login(client, "insider.agent", "Agent123!")
    reply = ask(client, "write a knowledge article from INC0088001")
    drain(app)
    route = client.get(f"/ai/runs/{reply['run_id']}/stream").get_json()["route"]
    assert route["action"]["type"] == "kb_article"
    review_url = client.post(route["action"]["prepare_url"], json={}).get_json()["url"]
    page = client.get(review_url)
    assert b"Fixing VPN service drops" in page.data
    assert client.post(review_url, data={"decision": "approve"}).status_code == 302
    with app.app_context():
        article = Knowledge.query.filter_by(title="Fixing VPN service drops").one()
        assert article.published is False and article.author_id == world.insider


def test_ticket_state_priority_and_assignment_stay_administrator_only_even_though_drafts_are_open_to_staff(app, client, world, ready):
    with app.app_context():
        ticket_id = draft_ticket(world)
        action = actions.propose_from_question(scope_for(world.insider, "agent"), f"set INC0088001 priority to P1", True)
    assert action is None or action["type"] != "update_ticket"  # deterministic parsing only fires for admins anyway
    # And the prepare route itself refuses an update_ticket-typed proposal from a non-admin staff member.
    login(client, "insider.agent", "Agent123!")
    with app.app_context():
        run_id = None
        from app import AIRun
        from serviceops_models import now
        run = AIRun(tenant_id=1, user_id=world.insider, actor_role="agent", kind="chat", config_revision=1,
                    request_key=str(uuid.uuid4()), provider="self_hosted", model="m", status="completed",
                    route_json=json.dumps({"action": {"type": "update_ticket", "ticket": "INC0088001", "payload": {"priority": "P1"}}}),
                    sources_json="[]")
        db.session.add(run)
        db.session.commit()
        run_id = run.id
    forced = client.post(f"/ai/chat/runs/{run_id}/actions/prepare", json={})
    assert forced.status_code == 403
