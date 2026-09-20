"""Streaming: real SSE transport, reasoning separation, Stop, time limits and progressive delivery."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from app import AIConfiguration, AIRun, db
from serviceops_core.ai import provider, service
from tests.test_ai_assistant import configure, fake_stream, submit  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401


@pytest.fixture(autouse=True)
def allow_test_endpoint(monkeypatch):
    # configure() points the tenant at this URL; the operator allowlist must include it.
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://127.0.0.1:18099/v1/chat/completions")


def chunk(content=None, reasoning=None, finish=None, usage=None):
    delta = {}
    if content is not None:
        delta["content"] = content
    if reasoning is not None:
        delta["reasoning_content"] = reasoning
    event = {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}] if not usage else [], }
    if usage:
        event["usage"] = usage
    return event


class SSE:
    """A real local model server that streams the given events, with an optional pause between them."""

    def __init__(self, events, pause=0.0, status=200):
        outer = self
        self.events, self.pause, self.status, self.disconnected = events, pause, status, False

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                if outer.status != 200:
                    self.send_response(outer.status)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                try:
                    for event in outer.events:
                        self.wfile.write(b"data: " + json.dumps(event).encode() + b"\n\n")
                        self.wfile.flush()
                        time.sleep(outer.pause)
                    self.wfile.write(b"data: [DONE]\n\n")
                except OSError:
                    outer.disconnected = True

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1/chat/completions"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture()
def sse(monkeypatch):
    made = []

    def make(events, **kwargs):
        server = SSE(events, **kwargs)
        made.append(server)
        monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", server.url)
        return server, SimpleNamespace(provider="self_hosted", endpoint=server.url, model="stream-test", external_consent=False,
                                        key_encrypted="", max_output_tokens=256)

    yield make
    for server in made:
        server.close()


MESSAGES = [{"role": "system", "content": "s"}, {"role": "user", "content": "q"}]


def collect():
    got = []
    return got, lambda kind, text: got.append((kind, text))


# --- the SSE transport ----------------------------------------------------------------------

def test_reasoning_and_answer_arrive_separately_with_usage(app, sse):
    server, config = sse([chunk(reasoning="Let me check. "), chunk(reasoning="The VPN evidence fits."),
                          chunk(content="It is a "), chunk(content="certificate issue [S1]."),
                          chunk(finish="stop"), chunk(usage={"prompt_tokens": 30, "completion_tokens": 9, "total_tokens": 39})])
    got, on_delta = collect()
    with app.app_context():
        answer, reasoning, usage = provider.generate_stream(config, MESSAGES, on_delta)
    assert answer == "It is a certificate issue [S1]."
    assert reasoning == "Let me check. The VPN evidence fits."
    assert [k for k, _ in got] == ["reasoning", "reasoning", "content", "content"]
    assert usage["total_tokens"] == 39 and usage["first_token_ms"] >= 0 and "duration_ms" in usage


def test_inline_think_tags_are_reasoning_even_when_split_across_chunks(app, sse):
    server, config = sse([chunk(content="<thi"), chunk(content="nk>Weigh the "), chunk(content="options</th"),
                          chunk(content="ink>The fix is to renew [S1]."), chunk(finish="stop")])
    with app.app_context():
        answer, reasoning, _ = provider.generate_stream(config, MESSAGES, lambda *_: True)
    assert reasoning == "Weigh the options" and answer == "The fix is to renew [S1]."
    assert "think" not in answer


def test_thinking_mode_is_requested_only_when_asked(app, sse, monkeypatch):
    seen = []
    real = provider.requests.Session.post

    def spy(self, url, **kwargs):
        seen.append(kwargs["json"])
        return real(self, url, **kwargs)

    monkeypatch.setattr(provider.requests.Session, "post", spy)
    server, config = sse([chunk(content="ok [S1]"), chunk(finish="stop")])
    with app.app_context():
        provider.generate_stream(config, MESSAGES, lambda *_: True)
        provider.generate_stream(config, MESSAGES, lambda *_: True, thinking=False)
        provider.generate_stream(config, MESSAGES, lambda *_: True, thinking=True)
    assert "chat_template_kwargs" not in seen[0]
    assert seen[1]["chat_template_kwargs"] == {"enable_thinking": False}
    assert seen[2]["chat_template_kwargs"] == {"enable_thinking": True}
    assert all(body["stream"] is True for body in seen)


def test_returning_false_stops_the_call(app, sse):
    server, config = sse([chunk(content="one ")] * 50, pause=0.02)
    with app.app_context():
        with pytest.raises(provider.StreamCancelled):
            provider.generate_stream(config, MESSAGES, lambda *_: False)


def test_a_rejected_request_is_a_provider_error(app, sse):
    server, config = sse([], status=401)
    with app.app_context(), pytest.raises(provider.ProviderError):
        provider.generate_stream(config, MESSAGES, lambda *_: True)


def test_a_stream_that_outlasts_the_time_limit_fails_closed(app, sse, monkeypatch):
    monkeypatch.setattr(provider, "MIN_TIMEOUT_SECONDS", 1)
    monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", "1")
    server, config = sse([chunk(content="slow ")] * 20, pause=0.2)
    with app.app_context(), pytest.raises(provider.ProviderError):
        provider.generate_stream(config, MESSAGES, lambda *_: True)


def test_output_cut_off_by_the_token_cap_is_flagged(app, sse):
    server, config = sse([chunk(content="Partial answer [S1]"), chunk(finish="length")])
    with app.app_context():
        _, _, usage = provider.generate_stream(config, MESSAGES, lambda *_: True)
    assert usage["truncated"] is True


# --- the worker publishes progress ------------------------------------------------------------

def test_worker_publishes_steps_reasoning_and_partial_text_while_running(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "FLUSH_INTERVAL", 0)
    polls = []

    def stream(config, messages, on_delta, thinking=None):
        on_delta("reasoning", "Checking the VPN evidence. ")
        polls.append(client.get(f"/ai/runs/{run_id}/stream?after=-1").get_json())
        on_delta("content", "The VPN drops after ")
        on_delta("content", "roaming [S1]. ")
        polls.append(client.get(f"/ai/runs/{run_id}/stream?after=-1").get_json())
        polls.append(client.get(f"/ai/runs/{run_id}/stream?after={polls[-1]['seq']}").get_json())
        return "The VPN drops after roaming [S1]. ", "Checking the VPN evidence. ", {"total_tokens": 7}

    monkeypatch.setattr(service, "generate_stream", stream)
    with app.app_context():
        assert service.process_one()
    first, second, unchanged = polls
    assert first["status"] == "running" and first["reasoning"].startswith("Checking") and first["text"] == ""
    labels = [step["label"] for step in first["steps"]]
    assert labels[:3] == ["Verified your access", "Collected evidence", "Sending to the model"]
    assert "The model is reasoning" in labels
    assert second["text"].startswith("The VPN drops after") and second["seq"] > first["seq"]
    assert unchanged == {"id": run_id, "status": "running", "seq": second["seq"], "changed": False}

    done = client.get(f"/ai/runs/{run_id}/stream?after=-1").get_json()
    assert done["status"] == "completed" and done["text"] == "The VPN drops after roaming [S1]. "
    assert done["reasoning"] == "Checking the VPN evidence. "
    assert [s["state"] for s in done["steps"]] == ["done"] * len(done["steps"])
    assert done["steps"][-1]["label"] == "Checked your access again"
    assert done["sources"][0]["url"].startswith("/tickets/") and done["usage"]["total_tokens"] == 7
    with app.app_context():
        run = db.session.get(AIRun, run_id)
        assert run.partial_text == "" and run.question == ""


def test_an_unfinished_word_is_held_back_from_the_partial_text(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "FLUSH_INTERVAL", 0)
    seen = []

    def stream(config, messages, on_delta, thinking=None):
        on_delta("content", "Check the INC010")
        seen.append(client.get(f"/ai/runs/{run_id}/stream?after=-1").get_json()["text"])
        return "Check the gateway [S1].", "", {}

    monkeypatch.setattr(service, "generate_stream", stream)
    with app.app_context():
        service.process_one()
    assert seen == ["Check the "]  # the half-typed reference is neither judged nor shown


def test_reasoning_is_hidden_and_thinking_disabled_when_the_administrator_turns_it_off(app, client, monkeypatch):
    ticket_id = configure(app, show_reasoning=False)
    login(client)
    run_id = submit(client, ticket_id)
    captured = {}

    def stream(config, messages, on_delta, thinking=None):
        captured["thinking"] = thinking
        on_delta("reasoning", "private chain of thought")
        on_delta("content", "Answer [S1].")
        return "Answer [S1].", "private chain of thought", {}

    monkeypatch.setattr(service, "generate_stream", stream)
    with app.app_context():
        service.process_one()
        assert db.session.get(AIRun, run_id).reasoning_text == ""
    assert captured["thinking"] is False
    body = client.get(f"/ai/runs/{run_id}/stream?after=-1").get_json()
    assert body["reasoning"] == "" and "private chain of thought" not in json.dumps(body)


def test_unbacked_references_never_appear_in_the_streamed_text(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "FLUSH_INTERVAL", 0)
    answer = "Also see CHG0000777 [S1] and [S42]. "
    monkeypatch.setattr(service, "generate_stream", fake_stream(answer))
    with app.app_context():
        service.process_one()
    text = client.get(f"/ai/runs/{run_id}/stream?after=-1").get_json()["text"]
    assert "CHG0000777" not in text and "[S42]" not in text and "[S1]" in text


# --- stop and disable ---------------------------------------------------------------------------

def test_stop_button_cancels_a_running_stream_and_keeps_nothing(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "FLUSH_INTERVAL", 0)

    def stream(config, messages, on_delta, thinking=None):
        on_delta("content", "Working on it now. ")
        assert client.post(f"/ai/runs/{run_id}/cancel").get_json()["status"] == "cancelled"
        if on_delta("content", "More text that must never be kept. ") is False:
            raise provider.StreamCancelled()
        return "unreachable", "", {}

    monkeypatch.setattr(service, "generate_stream", stream)
    with app.app_context():
        service.process_one()
        run = db.session.get(AIRun, run_id)
        assert run.status == "cancelled" and run.result_text == "" and run.partial_text == ""
    body = client.get(f"/ai/runs/{run_id}/stream?after=-1").get_json()
    assert body["status"] == "cancelled" and body["text"] == "" and body["error"].startswith("Stopped")


def test_disabling_ai_mid_stream_stops_and_discards_the_answer(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "FLUSH_INTERVAL", 0)

    def stream(config, messages, on_delta, thinking=None):
        on_delta("content", "Beginning of an answer. ")
        saved = db.session.get(AIConfiguration, 1)
        saved.revision += 1  # an administrator saved new settings
        db.session.commit()
        if on_delta("content", "The rest of it. ") is False:
            raise provider.StreamCancelled()
        return "Beginning of an answer. The rest of it. [S1]", "", {}

    monkeypatch.setattr(service, "generate_stream", stream)
    with app.app_context():
        service.process_one()
        run = db.session.get(AIRun, run_id)
        assert run.status == "cancelled" and run.result_text == "" and run.partial_text == ""


def test_only_the_owner_can_poll_or_stop_a_run(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    run_id = submit(client, ticket_id)
    other = app.test_client()
    login(other, "employee", "Employee123!")
    assert other.get(f"/ai/runs/{run_id}/stream").status_code in (403, 404)
    assert other.post(f"/ai/runs/{run_id}/cancel").status_code in (403, 404)
    with app.app_context():
        assert db.session.get(AIRun, run_id).status == "queued"
