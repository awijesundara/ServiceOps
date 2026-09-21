"""Provider allowances: counting what was used, avoiding spent services, spreading work, saving the scarce models."""
import random
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app import AICall, AIConfiguration, AIConnection, AIRun, db, now
from serviceops_core.ai import provider, quota, routing, service
from serviceops_models import settings_cipher
from tests.test_ai_assistant import fake_stream
from tests.test_ai_privacy import world  # noqa: F401
from tests.test_ai_routing import cfg, conn, names
from tests.test_app import app, client, login  # noqa: F401

GOOGLE = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"


def limited(name, rpm=None, tpm=None, rpd=None, model=None, tz="UTC", **values):
    return conn(name, True, model=model or name, rpm_limit=rpm, tpm_limit=tpm, rpd_limit=rpd, quota_tz=tz, cooldown_until=None, **values)


def calls_for(connection_id, count, seconds_ago=5, tokens=10):
    at = quota._aware(now())
    return {connection_id: [SimpleNamespace(started_at=at - timedelta(seconds=seconds_ago), prompt_tokens=tokens, completion_tokens=0)
                            for _ in range(count)]}


# ---- what the provider publishes, and what kind of model it is ----

@pytest.mark.parametrize("model,expected", [
    ("gemma-4-26b", (30, 16000, 14400)), ("gemini-3.5-flash-lite", (15, 250000, 500)), ("gemini-3.1-flash-lite", (15, 250000, 500)),
    ("gemini-2.5-flash-lite", (10, 250000, 20)), ("gemini-3.8-flash", (5, 250000, 20)), ("gemini-flash-lite-latest", (15, 250000, 500)),
    ("gemini-pro-latest", (0, 0, 0))])
def test_google_free_tier_presets(model, expected):
    preset = quota.preset_for("openai_compatible", GOOGLE, model)
    assert (preset["rpm_limit"], preset["tpm_limit"], preset["rpd_limit"]) == expected and preset["quota_tz"] == "America/Los_Angeles"
    assert quota.preset_for("openai_compatible", "https://api.groq.com/openai/v1/chat/completions", model) is None
    assert quota.preset_for("self_hosted", GOOGLE, model) is None


@pytest.mark.parametrize("model,tier", [("gemini-flash-lite-latest", "lite"), ("gemma-4-26b", "lite"), ("gemini-3.8-flash", "standard"),
                                        ("gemini-pro-latest", "pro"), ("claude-haiku-4-5", "lite"), ("Qwen/Qwen3-8B-GGUF:Q4_K_M", "standard")])
def test_tiers(model, tier):
    assert quota.tier_of(model) == tier


# ---- counting ----

def test_no_limits_means_no_constraint():
    assert quota.headroom(limited("a"), {}, 500).ok


def test_requests_per_minute_and_when_to_come_back():
    c = limited("a", rpm=3)
    assert quota.headroom(c, calls_for("a", 2), 0).ok and quota.headroom(c, calls_for("a", 2), 0).score == pytest.approx(1 / 3)
    full = quota.headroom(c, calls_for("a", 3, seconds_ago=20), 0)
    assert not full.ok and full.reason == "minute" and 35 <= full.wait <= 41
    assert quota.headroom(c, calls_for("a", 3, seconds_ago=90), 0).ok  # they have left the one-minute window


def test_tokens_per_minute_include_the_request_about_to_be_sent():
    c = limited("a", tpm=1000)
    assert quota.headroom(c, calls_for("a", 1, tokens=400), 500).ok
    assert quota.headroom(c, calls_for("a", 1, tokens=400), 700).reason == "minute"


def test_the_daily_allowance_resets_at_midnight_in_the_providers_time_zone():
    c = limited("a", rpd=2, tz="America/Los_Angeles")
    at = quota._aware(now())
    start = quota.day_start("America/Los_Angeles", at)
    spent = {"a": [SimpleNamespace(started_at=start + timedelta(minutes=5), prompt_tokens=1, completion_tokens=0)] * 2}
    result = quota.headroom(c, spent, 0, at)
    assert not result.ok and result.reason == "day" and 0 < result.wait <= 86400
    yesterday = {"a": [SimpleNamespace(started_at=start - timedelta(minutes=5), prompt_tokens=1, completion_tokens=0)] * 5}
    assert quota.headroom(c, yesterday, 0, at).ok
    assert quota.valid_timezone("Asia/Tokyo") and not quota.valid_timezone("Mars/Base")


def test_a_zero_allowance_means_the_plan_does_not_include_the_model():
    assert quota.headroom(limited("pro", rpm=0, tpm=0, rpd=0), {}, 0).reason == "none"


# ---- routing ----

def head(*pairs):
    return {c.id: h for c, h in pairs}


def test_spent_services_are_skipped_and_the_rest_are_used():
    a, b = limited("a", rpd=1), limited("b", rpd=10)
    calls = calls_for("a", 1)
    hd = {c.id: quota.headroom(c, calls, 0) for c in (a, b)}
    assert names(routing.plan(cfg(), [a, b], set(), {"ticket"}, headroom=hd)) == ["b"]


def test_when_everything_is_spent_the_person_is_told_when_it_comes_back():
    a = limited("a", rpd=1)
    hd = {a.id: quota.headroom(a, calls_for("a", 1), 0)}
    result = routing.plan(cfg(), [a], set(), {"ticket"}, headroom=hd)
    assert result.candidates == [] and result.blocked == "quota" and result.retry_after > 0
    assert "allowance is used up" in routing.blocked_message("quota", 7200) and "2 hours" in routing.blocked_message("quota", 7200)


def test_work_is_spread_in_proportion_to_what_each_allowance_has_left():
    big, small = limited("big", rpd=500, model="gemini-3.5-flash-lite"), limited("small", rpd=500, model="gemini-3.1-flash-lite")
    hd = {big.id: quota.Headroom(score=0.9), small.id: quota.Headroom(score=0.3)}
    rng, firsts = random.Random(3), {"big": 0, "small": 0}
    for _ in range(3000):
        firsts[names(routing.plan(cfg(routing_mode="balanced"), [big, small], set(), {"ticket"}, rng=rng, headroom=hd))[0]] += 1
    assert 0.65 < firsts["big"] / 3000 < 0.85  # about 3:1, matching 0.9 : 0.3


def test_chat_prefers_light_models_and_investigations_prefer_capable_ones_and_a_nearly_spent_one_steps_aside():
    lite, standard = limited("lite", model="gemini-flash-lite-latest"), limited("std", model="gemini-3.8-flash")
    plenty = {lite.id: quota.Headroom(score=1.0), standard.id: quota.Headroom(score=1.0)}
    assert names(routing.plan(cfg(), [lite, standard], set(), {"ticket"}, headroom=plenty, prefer="economy"))[0] == "lite"
    assert names(routing.plan(cfg(), [lite, standard], set(), {"ticket"}, headroom=plenty, prefer="quality"))[0] == "std"
    nearly = {lite.id: quota.Headroom(score=0.05), standard.id: quota.Headroom(score=1.0)}
    assert names(routing.plan(cfg(), [lite, standard], set(), {"ticket"}, headroom=nearly, prefer="economy"))[0] == "std"


def test_a_cooling_down_service_is_left_alone_briefly():
    cooling = limited("a")
    cooling.cooldown_until = now() + timedelta(seconds=30)
    assert names(routing.plan(cfg(), [cooling, limited("b")], set(), {"ticket"})) == ["b"]
    assert routing.usable(limited("c")) and not routing.usable(cooling)


# ---- end to end through the worker ----

def add(name, model, **values):
    row = AIConnection(tenant_id=1, name=name, provider="openai_compatible", model=model, endpoint=GOOGLE,
                       key_encrypted=settings_cipher().encrypt(b"k").decode(), **values)
    db.session.add(row)
    db.session.commit()
    return row.id


@pytest.fixture()
def ready(app):
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


def test_calls_are_logged_and_used_up_services_are_not_called(app, client, world, ready, monkeypatch):
    with app.app_context():
        lite = add("Lite", "gemini-flash-lite-latest", rpd_limit=2, rpm_limit=10)
        add("Standard", "gemini-3.8-flash", rpd_limit=20, rpm_limit=5)
    used = []

    def stream(config, messages, on_delta, thinking=None):
        used.append(config.model)
        on_delta("content", "Done.")
        return "Done.", "", {"prompt_tokens": 50, "completion_tokens": 7}

    monkeypatch.setattr(service, "generate_stream", stream)
    login(client, "employee", "Employee123!")
    for _ in range(3):
        chat(client, "Explain how to request a new laptop please")
        drain(app)
    assert used == ["gemini-flash-lite-latest", "gemini-flash-lite-latest", "gemini-3.8-flash"]  # the lite one ran out after two
    with app.app_context():
        rows = AICall.query.filter_by(connection_id=lite).all()
        assert len(rows) == 2 and all(r.status == "ok" and r.completion_tokens == 7 for r in rows)


def test_a_provider_rate_limit_pauses_the_service_without_counting_as_a_fault_and_falls_back(app, client, world, ready, monkeypatch):
    with app.app_context():
        first = add("Lite", "gemini-flash-lite-latest", priority=1)
        add("Std", "gemini-3.8-flash", priority=2)
    calls = []

    def stream(config, messages, on_delta, thinking=None):
        calls.append(config.model)
        if config.model == "gemini-flash-lite-latest":
            raise provider.rejection(429)
        on_delta("content", "Fine.")
        return "Fine.", "", {}

    monkeypatch.setattr(service, "generate_stream", stream)
    monkeypatch.setattr(service.time, "sleep", lambda s: None)
    login(client, "employee", "Employee123!")
    chat(client, "Explain how to request a new laptop please")
    drain(app)
    assert calls[-1] == "gemini-3.8-flash"
    with app.app_context():
        row = db.session.get(AIConnection, first)
        assert row.cooldown_until is not None and row.consecutive_failures == 0
        assert AICall.query.filter_by(connection_id=first, status="limited").count() >= 1


def test_every_allowance_spent_gives_a_plain_message_and_sends_nothing(app, client, world, ready, monkeypatch):
    with app.app_context():
        add("Only", "gemini-flash-lite-latest", rpd_limit=1)
        db.session.add(AICall(tenant_id=1, connection_id=AIConnection.query.one().id, prompt_tokens=1, status="ok"))
        db.session.commit()
    monkeypatch.setattr(service, "generate_stream", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not be sent")))
    login(client, "employee", "Employee123!")
    reply = chat(client, "Explain how to request a new laptop please")
    drain(app)
    body = client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()["messages"][1]
    assert "allowance is used up" in body["content"]


# ---- administration ----

def test_a_new_google_service_starts_from_the_published_allowance_and_shows_usage(app, client):
    login(client)
    created = client.post("/admin/ai/services", json={"name": "Lite", "provider": "openai_compatible", "endpoint": GOOGLE,
                                                      "model": "gemini-flash-lite-latest", "api_key": "k"}).get_json()["service"]
    assert created["limits"] == {"rpm": 15, "tpm": 250000, "rpd": 500, "tz": "America/Los_Angeles"} and created["tier"] == "lite"
    assert created["allowance"]["rpd_used"] == 0
    changed = client.post("/admin/ai/services", json={"id": created["id"], "limits": {"rpm": 3, "tpm": None, "rpd": 9, "tz": "Mars/Base"}}).get_json()["service"]
    assert changed["limits"] == {"rpm": 3, "tpm": None, "rpd": 9, "tz": "UTC"}


def test_several_models_can_be_added_at_once_and_share_the_key(app, client, monkeypatch):
    login(client)
    first = client.post("/admin/ai/services", json={"name": "Main", "provider": "openai_compatible", "endpoint": GOOGLE,
                                                    "model": "gemini-flash-lite-latest", "api_key": "secret-key-1"}).get_json()["service"]
    response = client.post("/admin/ai/services/bulk", json={"provider": "openai_compatible", "endpoint": GOOGLE, "from_service_id": first["id"],
                                                            "models": ["gemma-4-26b", "gemini-3.1-flash-lite", "gemini-flash-lite-latest"]})
    made = response.get_json()["services"]
    assert [s["model"] for s in made] == ["gemma-4-26b", "gemini-3.1-flash-lite"]  # the one already added is skipped
    assert made[0]["limits"]["rpd"] == 14400 and all(s["has_key"] for s in made) and "secret-key-1" not in response.get_data(as_text=True)
    with app.app_context():
        keys = {settings_cipher().decrypt(c.key_encrypted.encode()).decode() for c in AIConnection.query.all()}
        assert keys == {"secret-key-1"}
    assert client.post("/admin/ai/services/bulk", json={"models": "nope"}).status_code == 400
