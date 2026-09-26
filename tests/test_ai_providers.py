"""Universal provider support: address normalization, operator allowlist forms, model discovery,
hosted OpenAI-compatible validation and Anthropic streaming, all over real local sockets."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from app import AIConfiguration, AIConnection, db
from serviceops_core.ai import provider
from serviceops_models import settings_cipher
from tests.test_app import app, client, login  # noqa: F401


def config_for(**values):
    base = dict(provider="self_hosted", endpoint="", model="m", external_consent=False, key_encrypted="", max_output_tokens=500)
    base.update(values)
    return SimpleNamespace(**base)


class Server:
    """A local model server that records what it was sent and replies with a canned body."""

    def __init__(self, get_body=None, get_status=200, sse=None):
        outer = self
        self.seen = []
        self.get_body, self.get_status, self.sse = get_body, get_status, sse

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.seen.append(("GET", self.path, dict(self.headers)))
                if outer.get_status in (301, 302):
                    self.send_response(outer.get_status)
                    self.send_header("Location", "http://127.0.0.1:9/elsewhere")
                    self.end_headers()
                    return
                body = json.dumps(outer.get_body).encode()
                self.send_response(outer.get_status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.seen.append(("POST", self.path, dict(self.headers), payload))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for event in outer.sse or []:
                    self.wfile.write(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode())
                    self.wfile.flush()

            def log_message(self, *_):
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.http.server_port}"
        threading.Thread(target=self.http.serve_forever, daemon=True).start()

    def close(self):
        self.http.shutdown()
        self.http.server_close()


@pytest.fixture()
def server():
    servers = []

    def make(**kwargs):
        servers.append(Server(**kwargs))
        return servers[-1]
    yield make
    for item in servers:
        item.close()


# ---- how people write an address ----

@pytest.mark.parametrize("raw,expected", [
    ("http://192.168.68.68:8080", "http://192.168.68.68:8080/v1/chat/completions"),
    ("http://192.168.68.68:8080/", "http://192.168.68.68:8080/v1/chat/completions"),
    ("http://host:11434/v1", "http://host:11434/v1/chat/completions"),
    ("http://host:8080/v1/chat/completions", "http://host:8080/v1/chat/completions"),
    ("https://api.groq.com/openai/v1", "https://api.groq.com/openai/v1/chat/completions"),
    ("https://generativelanguage.googleapis.com/v1beta/openai", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
    ("", ""),
])
def test_addresses_are_normalized(raw, expected):
    assert provider.normalize_endpoint(raw) == expected


def test_models_url_follows_the_chat_url():
    assert provider.models_url(config_for(endpoint="http://h:8080")) == "http://h:8080/v1/models"
    assert provider.models_url(config_for(provider="openai_compatible", endpoint="https://api.groq.com/openai/v1")) == \
        "https://api.groq.com/openai/v1/models"


# ---- operator allowlist forms ----

@pytest.mark.parametrize("entry,url,allowed", [
    ("http://192.168.68.68:8080", "http://192.168.68.68:8080/v1/chat/completions", True),
    ("http://192.168.68.68:*", "http://192.168.68.68:9999/v1/chat/completions", True),
    ("http://192.168.68.68:*", "http://192.168.68.69:8080/v1/chat/completions", False),
    ("http://192.168.68.68:8080", "http://192.168.68.68:8081/v1/chat/completions", False),
    ("http://192.168.68.68:8080", "https://192.168.68.68:8080/v1/chat/completions", False),
    ("http://192.168.68.68:8080/v1/chat/completions", "http://192.168.68.68:8080/v1/chat/completions", True),
    ("http://192.168.68.68:8080/v1/chat/completions", "http://192.168.68.68:8080/other/chat/completions", False),
    ("http://Host.Local:8080", "http://host.local:8080/v1/chat/completions", True),
    ("http://good.example", "http://good.example.evil.test/v1/chat/completions", False),
    ("", "http://192.168.68.68:8080/v1/chat/completions", False),
])
def test_allowlist_forms(monkeypatch, entry, url, allowed):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", entry)
    assert provider.endpoint_allowed(url) is allowed


def test_unlisted_endpoint_tells_the_operator_exactly_what_to_add(monkeypatch):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "")
    with pytest.raises(provider.ProviderError) as error:
        provider.validate_configuration(config_for(endpoint="http://192.168.68.68:8080"))
    assert "http://192.168.68.68:8080 to AI_SELF_HOSTED_ENDPOINTS" in str(error.value)


# ---- hosted providers ----

def test_hosted_openai_compatible_requires_https_key_and_consent():
    base = dict(provider="openai_compatible", endpoint="https://api.groq.com/openai/v1", external_consent=True, key_encrypted="x")
    assert provider.validate_configuration(config_for(**base)) == "https://api.groq.com/openai/v1/chat/completions"
    for change in ({"endpoint": "http://api.groq.com/openai/v1"}, {"external_consent": False}, {"key_encrypted": ""}):
        with pytest.raises(provider.ProviderError):
            provider.validate_configuration(config_for(**{**base, **change}))


def test_hosted_openai_compatible_needs_no_operator_allowlist_but_only_reaches_public_addresses(monkeypatch):
    monkeypatch.delenv("AI_SELF_HOSTED_ENDPOINTS", raising=False)
    monkeypatch.setattr(provider.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))])
    with pytest.raises(provider.ProviderError):
        provider.resolve_destination("https://api.groq.com/openai/v1/chat/completions", False)


def test_fixed_providers_ignore_any_supplied_endpoint():
    for name, url in (("openai", provider.HOSTED_ENDPOINT), ("anthropic", provider.ANTHROPIC_ENDPOINT)):
        config = config_for(provider=name, endpoint="http://evil.internal", external_consent=True, key_encrypted="x")
        assert provider.validate_configuration(config) == url


def test_provider_proxy_policy_uses_default_custom_or_direct_and_ignores_process_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://environment-proxy:9999")
    default = config_for(proxy_mode="default", default_proxy_url="http://system-proxy:3128")
    custom = config_for(proxy_mode="custom", proxy_url="http://model-proxy:8080",
                        default_proxy_url="http://system-proxy:3128")
    direct = config_for(proxy_mode="none", default_proxy_url="http://system-proxy:3128")
    for config, expected in ((default, "http://system-proxy:3128"), (custom, "http://model-proxy:8080"),
                             (direct, None)):
        session, resolved = provider.provider_session(config)
        try:
            assert resolved == (expected or "")
            assert session.trust_env is False
            assert session.proxies.get("https") == expected
        finally:
            session.close()
    with pytest.raises(provider.ProviderError):
        provider.proxy_url(config_for(proxy_mode="custom", proxy_url="socks5://bad:1080"))


def test_a_connectivity_probe_fails_fast_instead_of_waiting_the_full_generation_timeout(monkeypatch):
    """admin/ai/services/<id>/test (service_test) calls generate(probe=True) synchronously
    from the browser's own request. A proxy or endpoint that accepts the TCP connection but
    never answers (the common shape of a broken/unreachable proxy, as opposed to a fast
    connection-refused) must not block that admin page for the full generation timeout --
    confirmed here against a real socket that accepts and then never writes a byte."""
    import socket
    import threading
    import time

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_and_hang():
        try:
            conn, _ = server.accept()
            time.sleep(30)  # longer than PROBE_TIMEOUT_SECONDS, shorter than the test would ever wait
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=accept_and_hang, daemon=True)
    thread.start()
    monkeypatch.setattr(provider, "PROBE_TIMEOUT_SECONDS", 1)
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", f"http://127.0.0.1:{port}")
    config = config_for(endpoint=f"http://127.0.0.1:{port}", proxy_mode="none")
    started = time.monotonic()
    with pytest.raises(provider.ProviderError):
        provider.generate(config, [], probe=True)
    elapsed = time.monotonic() - started
    assert elapsed < 5, f"probe took {elapsed:.1f}s -- it must fail near PROBE_TIMEOUT_SECONDS, not hang"
    server.close()


# ---- model discovery ----

def encrypted(key):
    return settings_cipher().encrypt(key.encode()).decode()


def test_models_are_listed_with_the_key_sent_and_junk_ignored(app, server, monkeypatch):
    item = server(get_body={"data": [{"id": "Qwen/Qwen3-8B-GGUF:Q4_K_M"}, {"id": "bad id with spaces"}, {"id": "x" * 500},
                                     {"id": "qwen3-4b"}, {"id": "qwen3-4b"}, {"nope": 1}]})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", item.origin)
    with app.app_context():
        models = provider.list_models(config_for(endpoint=item.origin, key_encrypted=encrypted("secret-key")))
    assert models == ["Qwen/Qwen3-8B-GGUF:Q4_K_M", "qwen3-4b"]
    assert item.seen[0][1] == "/v1/models" and item.seen[0][2]["Authorization"] == "Bearer secret-key"


def test_llama_cpp_style_model_list_is_understood(app, server, monkeypatch):
    item = server(get_body={"models": [{"name": "qwen3-8b", "model": "qwen3-8b"}], "data": []})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", item.origin)
    with app.app_context():
        assert provider.list_models(config_for(endpoint=item.origin)) == ["qwen3-8b"]


@pytest.mark.parametrize("status,fragment", [(401, "rejected the API key"), (500, "did not list"), (302, "did not list")])
def test_discovery_failures_are_display_safe_and_redirects_are_not_followed(app, server, monkeypatch, status, fragment):
    item = server(get_body={"secret": "SHOULD-NOT-LEAK"}, get_status=status)
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", item.origin)
    with app.app_context(), pytest.raises(provider.ProviderError) as error:
        provider.list_models(config_for(endpoint=item.origin))
    assert fragment in str(error.value) and "SHOULD-NOT-LEAK" not in str(error.value)
    assert len(item.seen) == 1  # the redirect target was never contacted


def test_discovery_respects_the_operator_allowlist(app, server, monkeypatch):
    item = server(get_body={"data": [{"id": "m"}]})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://192.168.68.68:8080")
    with app.app_context(), pytest.raises(provider.ProviderError):
        provider.list_models(config_for(endpoint=item.origin))
    assert item.seen == []


def test_detect_route_is_admin_only_and_never_echoes_the_key(app, client, server, monkeypatch):
    item = server(get_body={"data": [{"id": "qwen3-8b"}]})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", item.origin)
    body = {"provider": "self_hosted", "endpoint": item.origin, "api_key": "typed-secret"}
    login(client, "employee", "Employee123!")
    assert client.post("/admin/ai/models", json=body).status_code == 403
    client.get("/logout")
    login(client)
    response = client.post("/admin/ai/models", json=body)
    assert response.status_code == 200
    assert response.json["models"] == ["qwen3-8b"] and response.json["context"] == {}
    assert response.json["profiles"]["qwen3-8b"]["context_source"] == "unknown"
    assert response.json["discovery_token"]
    assert "typed-secret" not in response.get_data(as_text=True)
    assert item.seen[0][2]["Authorization"] == "Bearer typed-secret"
    assert client.post("/admin/ai/models", json={**body, "provider": "nope"}).status_code == 400
    bad = client.post("/admin/ai/models", json={**body, "endpoint": "http://192.168.68.99:8080"})
    assert bad.status_code == 400 and "allowlisted" in bad.get_json()["error"]


def test_detect_route_reuses_the_saved_key_only_for_the_same_destination(app, client, server, monkeypatch):
    item = server(get_body={"data": [{"id": "qwen3-8b"}]})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", item.origin)
    with app.app_context():
        db.session.add(AIConfiguration(tenant_id=1, provider="self_hosted", endpoint=provider.normalize_endpoint(item.origin),
                                       model="qwen3-8b", key_encrypted=encrypted("saved-key")))
        db.session.commit()
    login(client)
    assert client.post("/admin/ai/models", json={"provider": "self_hosted", "endpoint": item.origin}).status_code == 200
    assert item.seen[-1][2]["Authorization"] == "Bearer saved-key"
    other = server(get_body={"data": [{"id": "x"}]})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", f"{item.origin},{other.origin}")
    assert client.post("/admin/ai/models", json={"provider": "self_hosted", "endpoint": other.origin}).status_code == 200
    assert "Authorization" not in other.seen[-1][2]  # a saved key never travels to a different server


def test_saving_a_bare_address_stores_the_full_chat_url_and_fixed_providers_store_none(app, client, monkeypatch):
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://192.168.68.68:*")
    login(client)
    form = {"action": "save", "enabled": "on", "incident_enabled": "on", "model": "qwen3-8b", "daily_limit": "100",
            "max_output_tokens": "1500", "retention_days": "7"}
    client.post("/admin/ai", data={**form, "provider": "self_hosted", "endpoint": "http://192.168.68.68:8080"})
    with app.app_context():
        assert AIConnection.query.filter_by(name="Primary").one().endpoint == "http://192.168.68.68:8080/v1/chat/completions"
    client.post("/admin/ai", data={**form, "provider": "anthropic", "endpoint": "http://ignored", "external_consent": "on",
                                   "api_key": "sk-ant-test", "model": "claude-sonnet-5"})
    with app.app_context():
        saved = AIConnection.query.filter_by(name="Primary").one()
        assert saved.provider == "anthropic" and saved.endpoint == "" and saved.key_encrypted


# ---- Anthropic streaming ----

def test_anthropic_streams_text_and_thinking_with_the_right_headers(app, server, monkeypatch):
    events = [
        {"type": "message_start", "message": {"usage": {"input_tokens": 12}}},
        {"type": "content_block_delta", "delta": {"type": "thinking_delta", "thinking": "Weighing options. "}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Restart the client "}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "[S1]."}},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 7}},
        {"type": "message_stop"},
    ]
    item = server(sse=events)
    monkeypatch.setattr(provider, "ANTHROPIC_ENDPOINT", item.origin + "/v1/messages")
    original = provider.resolve_destination
    monkeypatch.setattr(provider, "resolve_destination", lambda address, local: original(address, True))
    got = []
    with app.app_context():
        config = config_for(provider="anthropic", model="claude-sonnet-5", external_consent=True,
                            key_encrypted=encrypted("sk-ant-test"), max_output_tokens=800)
        content, reasoning, usage = provider.generate_stream(
            config, [{"role": "system", "content": "SYS"}, {"role": "user", "content": "hi"}],
            lambda kind, text: got.append((kind, text)))
    assert content == "Restart the client [S1]." and reasoning.strip() == "Weighing options."
    assert usage["prompt_tokens"] == 12 and usage["completion_tokens"] == 7 and "first_token_ms" in usage
    assert [kind for kind, _ in got] == ["reasoning", "content", "content"]
    method, path, headers, payload = item.seen[0]
    assert path == "/v1/messages" and headers["x-api-key"] == "sk-ant-test" and headers["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in headers
    assert payload["system"] == "SYS" and payload["messages"] == [{"role": "user", "content": "hi"}] and payload["stream"] is True


def test_anthropic_error_event_fails_closed(app, server, monkeypatch):
    item = server(sse=[{"type": "error", "error": {"message": "overloaded SECRET-DETAIL"}}])
    monkeypatch.setattr(provider, "ANTHROPIC_ENDPOINT", item.origin + "/v1/messages")
    original = provider.resolve_destination
    monkeypatch.setattr(provider, "resolve_destination", lambda address, local: original(address, True))
    with app.app_context(), pytest.raises(provider.ProviderError) as error:
        provider.generate_stream(config_for(provider="anthropic", model="claude-sonnet-5", external_consent=True,
                                            key_encrypted=encrypted("k")), [{"role": "user", "content": "hi"}], lambda *a: None)
    assert "SECRET-DETAIL" not in str(error.value)


def test_context_window_is_reported_when_the_server_states_it(app, server, monkeypatch):
    item = server(get_body={"models": [{"name": "qwen3-8b"}], "data": [{"id": "qwen3-8b", "meta": {"n_ctx": 4096}},
                                                                          {"id": "other", "meta": {"n_ctx": "big"}}]})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", item.origin)
    details = {}
    with app.app_context():
        assert provider.list_models(config_for(endpoint=item.origin), details=details) == ["qwen3-8b", "other"]
    assert details == {"qwen3-8b": 4096}


@pytest.mark.parametrize("status,fragment", [(401, "access key"), (403, "access key"), (404, "model"), (503, "busy"), (429, "busy"), (418, "rejected")])
def test_rejections_say_what_to_fix(status, fragment):
    assert fragment in str(provider.rejection(status))


def test_gemini_is_asked_to_think_briefly_and_model_names_lose_the_models_prefix(app, server, monkeypatch):
    payload = {}
    gemini = config_for(provider="openai_compatible", endpoint="https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")
    assert provider._tuned_for_host(payload, gemini)["reasoning_effort"] == "low"
    other = {}
    assert "reasoning_effort" not in provider._tuned_for_host(other, config_for(provider="openai_compatible", endpoint="https://api.groq.com/openai/v1/chat/completions"))
    item = server(get_body={"data": [{"id": "models/gemini-2.5-flash"}, {"id": "models/gemini-2.5-pro"}]})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", item.origin)
    with app.app_context():
        assert provider.list_models(config_for(endpoint=item.origin)) == ["gemini-2.5-flash", "gemini-2.5-pro"]


def test_suggested_order_prefers_chat_models_and_rolling_latest_aliases():
    names = ["gemini-2.5-flash", "gemini-2.5-flash-preview-tts", "text-embedding-004", "gemini-flash-latest", "gemini-2.5-pro"]
    assert provider.suggested_order(names) == ["gemini-flash-latest", "gemini-2.5-flash", "gemini-2.5-pro",
                                               "gemini-2.5-flash-preview-tts", "text-embedding-004"]
    assert provider.suggested_order(["b", "a"]) == ["b", "a"]  # otherwise the server's own order is kept
