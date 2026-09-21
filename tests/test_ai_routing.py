"""Routing between several AI services, and the privacy rules that decide what may leave the organization."""
import json
import random
import uuid
from types import SimpleNamespace

import pytest

from app import AIConfiguration, AIConnection, AIMessage, AIRun, Audit, User, db
from serviceops_core.ai import routing, service
from serviceops_core.ai.provider import ProviderError
from serviceops_models import settings_cipher
from tests.test_ai_assistant import fake_stream
from tests.test_ai_privacy import world  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401


def conn(name, external=False, **values):
    base = dict(id=name, tenant_id=1, name=name, provider="openai_compatible" if external else "self_hosted", endpoint="",
                model="m", enabled=True, priority=100, weight=1, max_concurrency=1, consecutive_failures=0,
                last_failure_at=None, capabilities_json="{}", key_encrypted="")
    base.update(values)
    return SimpleNamespace(external=external, **base)


def cfg(**values):
    base = dict(external_consent=True, external_scope="not_sensitive", routing_mode="smart", detect_personal=True,
                detect_credentials=True, detect_financial=True, sensitive_terms="")
    base.update(values)
    return SimpleNamespace(**base)


def names(result):
    return [c.name for c in result.candidates]


# ---- what counts as sensitive ----

@pytest.mark.parametrize("text,expected", [
    ("Please email anna@corp.example about it", {"personal"}),
    ("Call +81 90 1234 5678 tomorrow", {"personal"}),
    ("SSN is 123-45-6789", {"personal"}),
    ("password: Hunter2!x", {"credentials"}),
    ("the api key is sk-abcdefghijklmnopqrstuvwx", {"credentials"}),
    ("-----BEGIN RSA PRIVATE KEY-----", {"credentials"}),
    ("card 4111 1111 1111 1111 expires", {"financial"}),
    ("IBAN GB82 WEST 1234 5698 7654 32", {"financial"}),
    ("VPN drops after roaming between access points", set()),
    ("Ticket INC0100001 opened 2026-09-20 from 10.20.0.5", set()),
    ("order number 4111 1111 1111 1112", set()),  # fails the card checksum
])
def test_detection(text, expected):
    assert routing.scan(text, cfg()) == expected


def test_administrator_words_and_switches():
    assert routing.scan("the Payroll export failed", cfg(sensitive_terms="payroll, HR case")) == {"custom"}
    assert routing.scan("hr CASE 12", cfg(sensitive_terms="payroll\nhr case")) == {"custom"}
    assert routing.scan("mail a@b.example", cfg(detect_personal=False)) == set()
    assert routing.scan("Service desk +81 3 1234 5678", cfg(), "knowledge") == set()  # published, organization-written
    assert routing.scan("password: Hunter2!x", cfg(), "knowledge") == {"credentials"}
    assert routing.scan("password: Hunter2!x", cfg(detect_credentials=False)) == set()


# ---- the hard privacy rule ----

@pytest.mark.parametrize("mode", list(routing.ROUTING_MODES))
def test_sensitive_requests_never_reach_an_external_service_in_any_mode(mode):
    result = routing.plan(cfg(routing_mode=mode), [conn("mac"), conn("cloud", True)], {"personal"}, {"ticket"})
    assert names(result) == ["mac"] and result.sensitive and "personal details" in result.note


@pytest.mark.parametrize("mode", list(routing.ROUTING_MODES))
def test_sensitive_with_only_external_services_is_blocked_not_sent(mode):
    result = routing.plan(cfg(routing_mode=mode), [conn("cloud", True)], {"credentials"}, {"ticket"})
    assert result.candidates == [] and result.blocked == "sensitive_no_private"


def test_a_failing_or_busy_private_service_is_never_replaced_by_an_external_one_for_sensitive_data():
    down = conn("mac", consecutive_failures=5, last_failure_at=routing.now())
    result = routing.plan(cfg(), [down, conn("cloud", True)], {"personal"}, {"ticket"}, {"mac": 9})
    assert names(result) == ["mac"]


@pytest.mark.parametrize("scope,kinds,allowed", [
    ("never", {"knowledge"}, False), ("knowledge_only", {"knowledge"}, True), ("knowledge_only", {"knowledge", "ticket"}, False),
    ("knowledge_only", set(), False), ("not_sensitive", {"ticket"}, True)])
def test_external_scope(scope, kinds, allowed):
    result = routing.plan(cfg(external_scope=scope), [conn("cloud", True)], set(), kinds)
    assert bool(result.candidates) is allowed


def test_external_needs_the_organizations_authorization():
    result = routing.plan(cfg(external_consent=False), [conn("mac"), conn("cloud", True)], set(), {"ticket"})
    assert names(result) == ["mac"]
    assert routing.plan(cfg(external_consent=False), [conn("cloud", True)], set(), {"ticket"}).blocked == "external_not_permitted"


# ---- load and health ----

def test_smart_prefers_private_and_overflows_to_external_only_when_private_is_busy():
    both = [conn("mac"), conn("cloud", True)]
    assert names(routing.plan(cfg(), both, set(), {"ticket"}, {}))[:2] == ["mac", "cloud"]
    assert names(routing.plan(cfg(), both, set(), {"ticket"}, {"mac": 1}))[:2] == ["cloud", "mac"]


def test_private_first_keeps_private_ahead_even_when_busy():
    both = [conn("mac"), conn("cloud", True)]
    assert names(routing.plan(cfg(routing_mode="internal_first"), both, set(), {"ticket"}, {"mac": 1})) == ["mac", "cloud"]


def test_priority_mode_follows_the_configured_order():
    services = [conn("b", priority=20), conn("a", priority=10), conn("c", True, priority=5)]
    assert names(routing.plan(cfg(routing_mode="priority"), services, set(), {"ticket"})) == ["c", "a", "b"]


def test_balanced_spreads_by_weight():
    services = [conn("small", weight=1), conn("big", weight=4)]
    firsts = {"small": 0, "big": 0}
    rng = random.Random(7)
    for _ in range(2000):
        firsts[names(routing.plan(cfg(routing_mode="balanced"), services, set(), {"ticket"}, rng=rng))[0]] += 1
    assert 0.7 < firsts["big"] / 2000 < 0.9


def test_disabled_and_modelless_services_are_ignored_and_open_circuits_go_last_or_are_skipped():
    services = [conn("off", enabled=False), conn("empty", model=""), conn("ok")]
    assert names(routing.plan(cfg(), services, set(), {"ticket"})) == ["ok"]
    tripped = conn("flaky", consecutive_failures=3, last_failure_at=routing.now())
    assert names(routing.plan(cfg(), [tripped, conn("ok")], set(), {"ticket"})) == ["ok"]
    assert names(routing.plan(cfg(), [tripped], set(), {"ticket"})) == ["flaky"]  # everything failing: still try


def test_nothing_configured_says_so():
    assert routing.plan(cfg(), [], set(), set()).blocked == "no_service"


# ---- end to end through the worker ----

def add_service(name, provider="self_hosted", **values):
    row = AIConnection(tenant_id=1, name=name, provider=provider, model="m", endpoint="http://127.0.0.1:18099/v1/chat/completions"
                       if provider == "self_hosted" else "https://api.example.test/v1/chat/completions",
                       key_encrypted=settings_cipher().encrypt(b"k").decode(), **values)
    db.session.add(row)
    db.session.commit()
    return row.id


@pytest.fixture()
def ai(app, monkeypatch):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://127.0.0.1:18099/v1/chat/completions")
    with app.app_context():
        db.session.add(AIConfiguration(tenant_id=1, enabled=True, incident_enabled=True, chat_enabled=True, external_consent=True))
        db.session.commit()


def chat(client, text):
    r = client.post("/ai/chat/messages", json={"text": text, "request_key": str(uuid.uuid4())})
    assert r.status_code == 201, r.data
    return r.get_json()


def drain(app):
    with app.app_context():
        while service.process_one():
            pass


def last_route(app, conversation_id):
    with app.app_context():
        return json.loads(AIMessage.query.filter_by(conversation_id=conversation_id, role="assistant").one().route_json)


def test_sensitive_chat_goes_to_the_private_service_only_and_the_answer_says_so(app, client, world, ai, monkeypatch):
    with app.app_context():
        add_service("Mac", priority=50)
        add_service("Cloud", "openai_compatible", priority=1)
    used = []

    def stream(config, messages, on_delta, thinking=None):
        used.append(config.provider)
        on_delta("content", "Done.")
        return "Done.", "", {}

    monkeypatch.setattr(service, "generate_stream", stream)
    login(client, "employee", "Employee123!")
    normal = chat(client, "Explain how to request a new laptop please")
    drain(app)
    personal = chat(client, "My email is anna@corp.example and my VPN keeps dropping")
    drain(app)
    assert used == ["self_hosted", "self_hosted"]  # smart mode prefers the private service either way
    route = last_route(app, personal["conversation_id"])
    assert route["location"] == "private" and route["sensitive"] and "personal details" in route["reason"]
    assert last_route(app, normal["conversation_id"])["sensitive"] is False


def test_sensitive_chat_with_no_private_service_is_answered_with_a_plain_notice_and_nothing_is_sent(app, client, world, ai, monkeypatch):
    with app.app_context():
        add_service("Cloud", "openai_compatible")

    def boom(*a, **k):
        raise AssertionError("nothing may be sent to an external service")

    monkeypatch.setattr(service, "generate_stream", boom)
    login(client, "employee", "Employee123!")
    reply = chat(client, "the password is Hunter2-secret and login fails")
    drain(app)
    body = client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()["messages"][1]
    assert "only be handled by your organization's own AI" in body["content"]
    with app.app_context():
        assert any(a.action == "ai chat denied" and "sensitive_no_private" in (a.details or "") for a in Audit.query.all())


def test_failover_moves_to_the_next_service_but_never_across_the_privacy_line(app, client, world, ai, monkeypatch):
    with app.app_context():
        first = add_service("Mac A", priority=1)
        add_service("Mac B", priority=2)
        add_service("Cloud", "openai_compatible", priority=3)
    calls = []

    def stream(config, messages, on_delta, thinking=None):
        calls.append(config.endpoint or config.provider)
        if len(calls) == 1:
            raise ProviderError("down")
        on_delta("content", "Recovered.")
        return "Recovered.", "", {}

    monkeypatch.setattr(service, "generate_stream", stream)
    with app.app_context():
        db.session.get(AIConfiguration, 1).routing_mode = "priority"
        db.session.commit()
    login(client, "employee", "Employee123!")
    reply = chat(client, "My email is anna@corp.example and mail is broken")
    drain(app)
    assert len(calls) == 2 and all("api.example.test" not in c and c != "openai_compatible" for c in calls)
    assert client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()["messages"][1]["content"] == "Recovered."
    with app.app_context():
        assert db.session.get(AIConnection, first).consecutive_failures == 1


def test_no_failover_once_an_answer_has_started(app, client, world, ai, monkeypatch):
    with app.app_context():
        add_service("Mac A", priority=1)
        add_service("Mac B", priority=2)
    calls = []

    def stream(config, messages, on_delta, thinking=None):
        calls.append(1)
        on_delta("content", "Half an answer ")
        raise ProviderError("dropped")

    monkeypatch.setattr(service, "generate_stream", stream)
    with app.app_context():
        db.session.get(AIConfiguration, 1).routing_mode = "priority"
        db.session.commit()
    login(client, "employee", "Employee123!")
    chat(client, "hello there friend")
    drain(app)
    assert len(calls) == 1


def test_investigations_are_routed_too(app, client, ai, monkeypatch):
    from app import Ticket
    with app.app_context():
        add_service("Cloud", "openai_compatible")
        user = User.query.filter_by(username="admin").one()
        ticket = Ticket(number="INC-R-1", kind="incident", title="VPN down", requester_id=user.id, tenant_id=1,
                        description="Customer anna@corp.example cannot connect")
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id
    monkeypatch.setattr(service, "generate_stream", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not be sent")))
    login(client)
    response = client.post(f"/incidents/{ticket_id}/ai", data={"request_key": str(uuid.uuid4())})
    run_id = response.headers["Location"].split("/")[-1]
    drain(app)
    body = client.get(f"/ai/runs/{run_id}/stream").get_json()
    assert body["status"] == "failed" and "own AI" in body["error"]


# ---- administration ----

def test_service_management_is_admin_only_and_never_returns_keys(app, client):
    login(client, "employee", "Employee123!")
    assert client.post("/admin/ai/services", json={"name": "x", "provider": "self_hosted"}).status_code == 403
    client.get("/logout")
    login(client)
    body = {"name": "Mac", "provider": "self_hosted", "endpoint": "http://192.168.68.68:8080", "model": "qwen3",
            "api_key": "super-secret-key"}
    import os
    os.environ["AI_SELF_HOSTED_ENDPOINTS"] = "http://192.168.68.68:*"
    try:
        created = client.post("/admin/ai/services", json=body)
        assert created.status_code == 200
        text = created.get_data(as_text=True)
        assert "super-secret-key" not in text and created.get_json()["service"]["has_key"] is True
        sid = created.get_json()["service"]["id"]
        assert client.post("/admin/ai/services", json={**body, "name": "Mac"}).status_code == 400  # duplicate name
        renamed = client.post("/admin/ai/services", json={"id": sid, "name": "Mac mini", "weight": 3})
        assert renamed.get_json()["service"]["weight"] == 3 and renamed.get_json()["service"]["has_key"] is True
        assert "super-secret-key" not in client.get("/admin/ai").get_data(as_text=True)
        assert client.post(f"/admin/ai/services/{sid}/delete").get_json() == {"deleted": True}
    finally:
        os.environ.pop("AI_SELF_HOSTED_ENDPOINTS", None)


def test_services_are_tenant_scoped(app, client):
    from app import Tenant
    with app.app_context():
        other = Tenant(slug="other-org", name="Other")
        db.session.add(other)
        db.session.flush()
        row = AIConnection(tenant_id=other.id, name="Theirs", provider="self_hosted", model="m")
        db.session.add(row)
        db.session.commit()
        foreign = row.id
    login(client)
    assert client.post(f"/admin/ai/services/{foreign}/delete").status_code == 404
    assert client.post(f"/admin/ai/services/{foreign}/test").status_code == 404
    assert client.post("/admin/ai/services", json={"id": foreign, "name": "mine now"}).status_code == 404


def test_route_preview_uses_the_real_rules_and_sends_nothing(app, client, ai):
    with app.app_context():
        add_service("Mac")
        add_service("Cloud", "openai_compatible")
    login(client)
    normal = client.post("/admin/ai/preview", json={"text": "VPN drops after roaming"}).get_json()
    assert not normal["sensitive"] and [e["name"] for e in normal["eligible"]][0] == "Mac" and len(normal["eligible"]) == 2
    private = client.post("/admin/ai/preview", json={"text": "mail anna@corp.example"}).get_json()
    assert private["sensitive"] and [e["name"] for e in private["eligible"]] == ["Mac"] and "personal details" in private["reasons"]
    words = client.post("/admin/ai/preview", json={"text": "payroll run failed", "sensitive_terms": "payroll"}).get_json()
    assert words["sensitive"]


def test_migration_step_copies_the_single_configuration(app):
    from sqlalchemy import text
    with app.app_context():
        db.session.add(AIConfiguration(tenant_id=1, provider="self_hosted", endpoint="http://x:8080/v1/chat/completions", model="qwen"))
        db.session.commit()
        legacy = service.connections_for(db.session.get(AIConfiguration, 1))
        assert [c.name for c in legacy] == ["Primary"] and legacy[0].id == "legacy"
        assert db.session.execute(text("SELECT COUNT(*) FROM ai_connection")).scalar() == 0


def test_ready_requires_a_usable_service(app):
    with app.app_context():
        config = AIConfiguration(tenant_id=1, external_consent=True)
        db.session.add(config)
        db.session.commit()
        with pytest.raises(ProviderError):
            service.ready(config)
