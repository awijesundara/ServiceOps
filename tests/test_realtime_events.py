"""Live communication: ETag'd notification checks, the events auth endpoint,
PostgreSQL NOTIFY signals, the events service end to end, and the outbox
worker waking on a signal.

The PostgreSQL tests need REALTIME_DATABASE_URL naming a disposable database
whose name ends in _realtime_test (it is migrated and written to).
"""
import asyncio
import json
import os
import select
import socket
import threading
import time

import pytest
from werkzeug.security import generate_password_hash

from app import (Comment, Ticket, User, create_app, create_notification, create_ticket_with_unique_number, db)
from tests.test_app import app, client, login  # noqa: F401


# --- always: SQLite ----------------------------------------------------------

def test_notification_check_answers_304_when_nothing_changed(app, client):
    login(client)
    first = client.get("/notifications/poll")
    etag = first.headers["ETag"]
    assert first.status_code == 200 and etag
    again = client.get("/notifications/poll", headers={"If-None-Match": etag})
    assert again.status_code == 304 and again.data == b""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        create_notification(admin.id, "New", "Something happened", tenant_id=admin.tenant_id)
        db.session.commit()
    changed = client.get("/notifications/poll", headers={"If-None-Match": etag})
    assert changed.status_code == 200 and changed.headers["ETag"] != etag


def test_events_auth_names_the_user_and_only_visible_watched_records(app, client):
    assert client.get("/events/auth").status_code in (302, 401)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ticket = create_ticket_with_unique_number("incident", title="Watch me", description="x",
                                                  priority="P3", requester_id=admin.id)
        db.session.commit()
        ticket_id, admin_id = ticket.id, admin.id
    login(client)
    data = client.get(f"/events/auth?watch=ticket:{ticket_id},ticket:999999,ticket:abc,other:1").get_json()
    assert data["user_id"] == admin_id and data["watch"] == [f"ticket:{ticket_id}"]


def test_only_agents_may_watch_work_lists(app, client):
    login(client)
    assert client.get("/events/auth?watch=tickets").get_json()["watch"] == ["tickets"]
    client.post("/logout")
    login(client, "employee", "Employee123!")
    assert client.get("/events/auth?watch=tickets").get_json()["watch"] == []


def test_work_lists_hear_that_a_ticket_changed_but_not_which():
    from tools.events_server import Hub, Stream
    hub = Hub()
    board = Stream(None, 1, 7, ["tickets"], False, {})
    mine_elsewhere = Stream(None, 2, 7, ["tickets"], False, {})
    other_tenant = Stream(None, 3, 8, ["tickets"], False, {})
    record = Stream(None, 2, 7, ["ticket:42"], False, {})
    hub.streams.update({board, mine_elsewhere, other_tenant, record})
    hub.dispatch(json.dumps({"type": "ticket", "tenant": 7, "id": 42, "actor": 2}))
    frame = board.queue.get_nowait().decode()
    assert frame.startswith("event: tickets") and '"self":false' in frame and "42" not in frame
    assert '"self":true' in mine_elsewhere.queue.get_nowait().decode()
    assert other_tenant.queue.empty()
    assert record.queue.get_nowait().decode().startswith("event: ticket\n")


def test_signals_are_a_no_op_on_sqlite(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        create_notification(admin.id, "Quiet", "No PostgreSQL here", tenant_id=admin.tenant_id)
        db.session.commit()  # must not raise


def test_worker_wait_falls_back_to_sleep_without_postgresql(monkeypatch):
    import importlib
    import sys
    slept = []
    monkeypatch.setattr(time, "sleep", lambda seconds: slept.append(seconds))
    monkeypatch.setattr(sys, "argv", ["outbox_worker"])
    source = open(os.path.join(os.path.dirname(__file__), "..", "tools", "outbox_worker.py")).read()
    namespace = {}
    # Only the helper is needed; executing the module would start the loop.
    start = source.index("def wait_for_work")
    end = source.index("\ndef ", start + 10)
    exec("import time\n_listener = None\n" + source[start:end], namespace)
    fake_db = type("DB", (), {"engine": type("E", (), {"dialect": type("D", (), {"name": "sqlite"})()})()})()
    namespace["db"] = fake_db
    namespace["wait_for_work"](7)
    assert slept == [7]
    del importlib


# --- PostgreSQL ------------------------------------------------------------------

@pytest.fixture(scope="module")
def pg_app():
    url = os.getenv("REALTIME_DATABASE_URL", "")
    if not url:
        pytest.skip("REALTIME_DATABASE_URL is required for the PostgreSQL real-time tests")
    from sqlalchemy.engine import make_url
    if not url.startswith("postgresql") or not (make_url(url).database or "").endswith("_realtime_test"):
        pytest.fail("Refusing a database whose name does not end in _realtime_test")
    application = create_app({"TESTING": True, "AUTO_MIGRATE_IN_TESTS": True, "AUTO_MIGRATE": True,
                              "SQLALCHEMY_DATABASE_URI": url, "CSRF_ENABLED": False, "SESSION_COOKIE_SECURE": False})
    with application.app_context():
        if not User.query.filter_by(username="rt.other").first():
            admin = User.query.filter_by(username="admin").one()
            db.session.add(User(username="rt.other", name="Other Agent", email="rt.other@test.invalid", role="agent",
                                password_hash=generate_password_hash("Other123!"), tenant_id=admin.tenant_id))
            db.session.commit()
    return application


def _listen(url, channel):
    import psycopg
    connection = psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://"), autocommit=True)
    connection.execute(f"LISTEN {channel}")
    return connection


def _next_notify(connection, timeout=3):
    for notify in connection.notifies(timeout=timeout, stop_after=1):
        return notify
    return None


def test_commits_signal_and_rollbacks_do_not(pg_app):
    url = os.environ["REALTIME_DATABASE_URL"]
    events, outbox = _listen(url, "serviceops_events"), _listen(url, "serviceops_outbox")
    try:
        with pg_app.app_context():
            admin = User.query.filter_by(username="admin").one()
            create_notification(admin.id, "Rolled back", "never sent", tenant_id=admin.tenant_id)
            db.session.rollback()
            assert _next_notify(events, timeout=1) is None
            create_notification(admin.id, "Committed", "sent", tenant_id=admin.tenant_id)
            db.session.commit()
            payload = json.loads(_next_notify(events).payload)
            assert payload == {"type": "notification", "tenant": admin.tenant_id, "user": admin.id}
            assert _next_notify(outbox) is not None  # its outbox event wakes the worker
            ticket = create_ticket_with_unique_number("incident", title="Live", description="x",
                                                      priority="P3", requester_id=admin.id)
            db.session.commit()
            while _next_notify(events, timeout=0.5):
                pass
            db.session.add(Comment(ticket_id=ticket.id, user_id=admin.id, body="note", tenant_id=admin.tenant_id))
            db.session.commit()
            payload = json.loads(_next_notify(events).payload)
            assert payload["type"] == "ticket" and payload["id"] == ticket.id and payload["tenant"] == admin.tenant_id
    finally:
        events.close()
        outbox.close()


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _Stream:
    """Minimal SSE client over a raw socket."""

    def __init__(self, port, path, cookie=None):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        headers = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n"
        if cookie:
            headers += f"Cookie: {cookie}\r\n"
        self.sock.sendall((headers + "\r\n").encode())
        self.buffer = b""

    def read_until(self, marker, timeout=5):
        deadline = time.monotonic() + timeout
        while marker not in self.buffer and time.monotonic() < deadline:
            ready, _, _ = select.select([self.sock], [], [], 0.2)
            if ready:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                self.buffer += chunk
        return marker in self.buffer

    def close(self):
        self.sock.close()


def test_events_service_delivers_to_the_right_streams(pg_app, monkeypatch):
    from werkzeug.serving import make_server
    from tools import events_server
    web = make_server("127.0.0.1", 0, pg_app, threaded=True)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    monkeypatch.setenv("DATABASE_URL", os.environ["REALTIME_DATABASE_URL"])
    monkeypatch.setattr(events_server, "AUTH_URL", f"http://127.0.0.1:{web.server_port}/events/auth")
    loop = asyncio.new_event_loop()
    stop = asyncio.Event()
    port_box = []
    thread = threading.Thread(target=lambda: loop.run_until_complete(
        events_server.serve(stop, port=0, host="127.0.0.1", ready=port_box.append)), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not port_box and time.monotonic() < deadline:
        time.sleep(0.05)
    port = port_box[0]
    try:
        # Health turns ready once LISTEN is up.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            health = _Stream(port, "/healthz")
            if health.read_until(b"200 OK", timeout=1):
                health.close()
                break
            health.close()
        anonymous = _Stream(port, "/events/stream")
        assert anonymous.read_until(b"401")
        anonymous.close()

        browser = pg_app.test_client()
        browser.post("/login", data={"username": "admin", "password": "Admin123!"})
        cookie = "; ".join(f"{c.key}={c.value}" for c in browser._cookies.values())
        with pg_app.app_context():
            admin = User.query.filter_by(username="admin").one()
            other = User.query.filter_by(username="rt.other").one()
            ticket = create_ticket_with_unique_number("incident", title="Watched", description="x",
                                                      priority="P3", requester_id=admin.id)
            db.session.commit()
            ticket_id, admin_id, other_id, tenant_id = ticket.id, admin.id, other.id, admin.tenant_id
        stream = _Stream(port, f"/events/stream?watch=ticket:{ticket_id}", cookie)
        assert stream.read_until(b"event: hello")
        assert f'"user_id":{admin_id}'.encode() in stream.buffer
        with pg_app.app_context():
            create_notification(other_id, "Not yours", "x", tenant_id=tenant_id)
            db.session.commit()
            create_notification(admin_id, "Yours", "x", tenant_id=tenant_id)
            db.session.commit()
        assert stream.read_until(b"event: notification")
        assert stream.buffer.count(b"event: notification") == 1  # only the admin's own
        with pg_app.app_context():
            db.session.add(Comment(ticket_id=ticket_id, user_id=other_id, body="update", tenant_id=tenant_id))
            db.session.commit()
        assert stream.read_until(b"event: ticket")
        assert f'"id":{ticket_id}'.encode() in stream.buffer and f'"actor":{other_id}'.encode() in stream.buffer
        stream.close()

        board = _Stream(port, "/events/stream?watch=tickets&notifications=0", cookie)
        assert board.read_until(b"event: hello") and b'"tickets"' in board.buffer
        with pg_app.app_context():
            db.session.add(Comment(ticket_id=ticket_id, user_id=other_id, body="list", tenant_id=tenant_id))
            db.session.commit()
        assert board.read_until(b"event: tickets")
        assert b'"self":false' in board.buffer and f'"id":{ticket_id}'.encode() not in board.buffer
        board.close()
    finally:
        loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=5)
        web.shutdown()


def test_worker_wakes_on_an_outbox_signal(pg_app):
    import psycopg
    url = os.environ["REALTIME_DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://")
    listener = psycopg.connect(url, autocommit=True)
    listener.execute("LISTEN serviceops_outbox")
    started = time.monotonic()
    threading.Timer(0.3, lambda: psycopg.connect(url, autocommit=True).execute("SELECT pg_notify('serviceops_outbox', '')")).start()
    woke = any(True for _ in listener.notifies(timeout=5, stop_after=1))
    assert woke and time.monotonic() - started < 3
    listener.close()
