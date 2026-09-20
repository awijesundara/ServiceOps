"""Tenant isolation, control-plane shutdown and read-only investigation regressions."""
import json
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app import AIConfiguration, AIRun, Knowledge, Tenant, Ticket, User, db, now
from serviceops_core.ai import provider, service
from tests.test_app import app, client, login  # noqa: F401


def configure(app, **overrides):
    with app.app_context():
        config = AIConfiguration(tenant_id=1, enabled=True, incident_enabled=True, provider="self_hosted",
                                 endpoint="http://127.0.0.1:18099/v1/chat/completions", model="local-model")
        for key, value in overrides.items():
            setattr(config, key, value)
        db.session.add(config)
        user = User.query.filter_by(username="admin").one()
        ticket = Ticket(number="INC-AI-001", kind="incident", title="VPN connection fails", description="VPN failure password=hidden",
                        requester_id=user.id, tenant_id=1)
        db.session.add(ticket)
        db.session.commit()
        return ticket.id


@pytest.fixture(autouse=True)
def allow_test_endpoint(monkeypatch):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://127.0.0.1:18099/v1/chat/completions")


def fake_stream(answer, usage=None, reasoning="", before=None, capture=None):
    """A stand-in for provider.generate_stream that honors the real contract: deliver
    deltas, and stop as soon as the worker says so."""
    def stream(config, messages, on_delta, thinking=None):
        if capture is not None:
            capture.extend(messages)
        if before:
            before()
        if reasoning and on_delta("reasoning", reasoning) is False:
            raise provider.StreamCancelled()
        if on_delta("content", answer) is False:
            raise provider.StreamCancelled()
        return answer, reasoning, usage or {}
    return stream


def submit(client, ticket_id, key=None):
    response = client.post(f"/incidents/{ticket_id}/ai", data={"request_key": key or str(uuid.uuid4())})
    assert response.status_code == 302, response.data
    return response.headers["Location"].split("/")[-1]


def test_disabled_default_and_admin_only(app, client):
    login(client)
    page = client.get("/admin/ai")
    assert page.status_code == 200 and b"Disabled" in page.data
    assert client.get("/incidents/1/ai").status_code == 403
    client.get("/logout")
    login(client, "employee", "Employee123!")
    assert client.get("/admin/ai").status_code == 403
    assert client.post("/admin/ai", data={"action": "disable"}).status_code == 403


def test_configuration_encrypted_and_external_consent_required(app, client):
    login(client)
    form = {"provider": "openai", "model": "test-model", "api_key": "not-a-real-key", "enabled": "on",
            "incident_enabled": "on"}
    response = client.post("/admin/ai", data=form, follow_redirects=True)
    assert b"Authorize external processing" in response.data
    with app.app_context():
        assert not db.session.get(AIConfiguration, 1)
    form["external_consent"] = "on"
    response = client.post("/admin/ai", data=form, follow_redirects=True)
    assert b"not-a-real-key" not in response.data
    with app.app_context():
        config = db.session.get(AIConfiguration, 1)
        assert config.enabled and config.key_encrypted and "not-a-real-key" not in config.key_encrypted
    # New destination must never receive an old provider's credential.
    form.pop("api_key")
    form.update(provider="self_hosted", endpoint="http://127.0.0.1:18099/v1/chat/completions")
    client.post("/admin/ai", data=form)
    with app.app_context():
        assert db.session.get(AIConfiguration, 1).key_encrypted == ""


def test_disable_is_independent_of_invalid_provider_config(app, client):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    client.post("/admin/ai", data={"action": "disable"})
    assert client.get(f"/ai/runs/{run_id}").status_code == 403
    assert client.post(f"/incidents/{ticket_id}/ai").status_code == 403
    with app.app_context():
        assert db.session.get(AIRun, run_id).status == "cancelled"
        assert service.process_one() is False


def test_duplicate_request_and_quota(app, client):
    ticket_id = configure(app, daily_limit=1)
    login(client)
    key = str(uuid.uuid4())
    assert submit(client, ticket_id, key) == submit(client, ticket_id, key)
    assert client.post(f"/incidents/{ticket_id}/ai", data={"request_key": str(uuid.uuid4())}).status_code == 429


def test_worker_retrieves_only_tenant_published_evidence_and_never_mutates(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        other = Tenant(slug="ai-other", name="Other")
        db.session.add(other)
        db.session.flush()
        db.session.add_all([
            Knowledge(title="VPN guide", body="Restart VPN client", author_id=admin.id, tenant_id=1),
            Knowledge(title="VPN private draft", body="DRAFT-DONT-SEND", author_id=admin.id, tenant_id=1, published=False),
            Knowledge(title="VPN other tenant", body="OTHER-DONT-SEND", author_id=admin.id, tenant_id=other.id),
        ])
        db.session.commit()
    captured = []

    monkeypatch.setattr(service, "generate_stream", fake_stream(
        "VPN investigation [S1]. Check published guidance [S2]. <script>alert(1)</script>", {"total_tokens": 12}, capture=captured))
    run_id = submit(client, ticket_id)
    with app.app_context():
        assert service.process_one()
        run = db.session.get(AIRun, run_id)
        assert run.status == "completed"
        assert db.session.get(Ticket, ticket_id).state == "New"
        assert "hidden" not in json.dumps(captured)
        assert "DRAFT-DONT-SEND" not in json.dumps(captured)
        assert "OTHER-DONT-SEND" not in json.dumps(captured)
    page = client.get(f"/ai/runs/{run_id}")
    assert page.status_code == 200
    assert b"&lt;script&gt;" in page.data
    with app.app_context():
        Knowledge.query.filter_by(title="VPN guide").one().published = False
        db.session.commit()
    assert client.get(f"/ai/runs/{run_id}").status_code == 403


def test_disable_during_provider_call_discards_answer(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)

    def disable_now():
        saved = db.session.get(AIConfiguration, 1)
        saved.enabled = False
        saved.revision += 1
        service.cancel_active(1)
        db.session.commit()

    monkeypatch.setattr(service, "generate_stream", fake_stream("Late answer [S1]", before=disable_now))
    with app.app_context():
        service.process_one()
        run = db.session.get(AIRun, run_id)
        assert run.status == "cancelled" and not run.result_text


def test_cancel_during_provider_call_and_role_revocation(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        user.active = False
        db.session.commit()
    monkeypatch.setattr(service, "generate_stream", lambda *_, **__: pytest.fail("revoked actor reached provider"))
    with app.app_context():
        service.process_one()
        assert db.session.get(AIRun, run_id).status == "cancelled"


def test_cross_tenant_config_and_results_are_isolated(app, client):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    with app.app_context():
        tenant = Tenant(slug="ai-isolated", name="Isolated")
        db.session.add(tenant)
        db.session.flush()
        user = User.query.filter_by(username="admin").one()
        user.tenant_id = tenant.id
        db.session.add(AIConfiguration(tenant_id=tenant.id, enabled=True, incident_enabled=True))
        db.session.commit()
    assert client.get(f"/ai/runs/{run_id}").status_code == 404
    assert client.get(f"/incidents/{ticket_id}/ai").status_code == 404
    client.post("/admin/ai", data={"action": "disable"})
    with app.app_context():
        assert db.session.get(AIConfiguration, 1).enabled
        assert db.session.get(AIRun, run_id).status == "queued"


def test_csrf_protects_admin_switch(app, client):
    login(client)
    app.config["CSRF_ENABLED"] = True
    assert client.post("/admin/ai", data={"action": "disable"}).status_code == 400


def test_expired_worker_not_retried_and_retention_purges(app, client, monkeypatch):
    ticket_id = configure(app, retention_days=1)
    login(client)
    run_id = submit(client, ticket_id)
    with app.app_context():
        run = db.session.get(AIRun, run_id)
        run.status = "running"
        run.started_at = now() - timedelta(minutes=10)
        db.session.commit()
        monkeypatch.setattr(service, "generate_stream", lambda *_, **__: pytest.fail("expired job was retried"))
        service.process_one()
        assert db.session.get(AIRun, run_id).status == "failed"
        run.created_at = now() - timedelta(days=2)
        db.session.commit()
        service.process_one()
        assert db.session.get(AIRun, run_id) is None


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data", "http://user:pass@127.0.0.1/v1/chat/completions",
                                  "https://example.com/v1/chat/completions", "file:///etc/passwd"])
def test_self_hosted_endpoint_requires_exact_allowlist(url):
    with pytest.raises(provider.ProviderError):
        provider.validate_configuration(SimpleNamespace(provider="self_hosted", endpoint=url, model="test"))


def test_hosted_private_resolution_rejected(monkeypatch):
    monkeypatch.setattr(provider.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(provider.ProviderError):
        provider.resolve_destination(provider.HOSTED_ENDPOINT, False)


@pytest.mark.parametrize("mode", ["self_hosted", "openai"])
def test_real_http_provider_contract(app, monkeypatch, mode):
    """Real socket and JSON transport against an isolated contract server, not model inference."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            captured.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            body = ({"status": "completed", "output": [{"type": "message", "content": [
                {"type": "output_text", "text": "Check VPN [S1]"}]}], "usage": {"total_tokens": 9}}
                if mode == "openai" else {"choices": [{"finish_reason": "stop", "message": {"content": "Check VPN [S1]"}}],
                                           "usage": {"total_tokens": 9}})
            body = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", url)
    if mode == "openai":
        monkeypatch.setattr(provider, "HOSTED_ENDPOINT", url)
        original = provider.resolve_destination
        monkeypatch.setattr(provider, "resolve_destination", lambda address, local: original(address, True))
    try:
        with app.app_context():
            from serviceops_models import settings_cipher
            config = SimpleNamespace(provider=mode, endpoint=url, model="contract-test", external_consent=True,
                                     key_encrypted=settings_cipher().encrypt(b"ephemeral-test-key").decode(), max_output_tokens=1500,
                                     capabilities_json=json.dumps({"model": "contract-test", "context_tokens": 8192}))
            answer, usage = provider.generate(config, [{"source": "S1", "text": "VPN failure"}])
        assert answer == "Check VPN [S1]" and usage["total_tokens"] == 9
        if mode == "openai":
            assert captured[0]["store"] is False
            assert captured[0]["max_output_tokens"] == 1500
        else:
            assert captured[0]["stream"] is False and captured[0]["max_tokens"] == 1500
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_invalid_citations_fail_closed(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "generate_stream", fake_stream("Unsupported claim [S999]"))
    with app.app_context():
        service.process_one()
        run = db.session.get(AIRun, run_id)
        assert run.status == "failed" and not run.result_text


def test_user_cancellation_discards_inflight_result(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)

    def cancel_now():
        AIRun.query.filter_by(id=run_id).update({"status": "cancelled"})
        db.session.commit()

    monkeypatch.setattr(service, "generate_stream", fake_stream("Late response [S1]", before=cancel_now))
    with app.app_context():
        service.process_one()
        assert db.session.get(AIRun, run_id).status == "cancelled"
        assert not db.session.get(AIRun, run_id).result_text


@pytest.mark.parametrize("raw,expected", [
    (None, 60), ("", 60), ("240", 240), ("5", 10), ("0", 10), ("-3", 10), ("9999", 270), ("abc", 60), (" 120 ", 120),
])
def test_provider_timeout_is_configurable_and_clamped(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("AI_PROVIDER_TIMEOUT_SECONDS", raising=False)
    else:
        monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", raw)
    assert provider.provider_timeout() == expected


def test_slow_self_hosted_model_needs_a_long_enough_timeout(app, monkeypatch):
    """A CPU-hosted model can take minutes; a too-short limit must fail closed and a longer one must succeed."""
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class SlowHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            time.sleep(3)
            body = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": "Slow but grounded [S1]"}}],
                               "usage": {"total_tokens": 5}}).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass  # the client gave up first, which is exactly the failure case under test

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    url = f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", url)
    monkeypatch.setattr(provider, "MIN_TIMEOUT_SECONDS", 1)
    config = SimpleNamespace(provider="self_hosted", endpoint=url, model="slow-test", external_consent=False,
                             key_encrypted="", max_output_tokens=256)
    try:
        with app.app_context():
            monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", "1")
            with pytest.raises(provider.ProviderError):
                provider.generate(config, [{"source": "S1", "text": "VPN failure"}])
            monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", "15")
            answer, usage = provider.generate(config, [{"source": "S1", "text": "VPN failure"}])
        assert answer == "Slow but grounded [S1]" and usage["duration_ms"] >= 2500
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
