"""WEBHOOK_INTERNAL_HOSTS: administrator-configured webhooks to listed
in-cluster receivers (such as FlowOps' Kubernetes Service) may use http://
and private addresses; everything else keeps the public-HTTPS-only rule."""
import hashlib
import hmac
import json
import os
import tempfile

import pytest

from app import (IntegrationConnection, OutboxEvent, User, create_app, db, deliver_webhook, settings_cipher,
                 webhook_endpoint_valid)

FLOWOPS = "http://flowops.operations.svc.cluster.local/api/integrations/serviceops/events/flowops"


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    yield app
    os.unlink(path)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="admin", password="Admin123!"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def test_internal_hosts_are_opt_in_and_exact(monkeypatch, app):
    with app.app_context():
        monkeypatch.delenv("WEBHOOK_INTERNAL_HOSTS", raising=False)
        assert not webhook_endpoint_valid(FLOWOPS)
        monkeypatch.setenv("WEBHOOK_INTERNAL_HOSTS", "flowops.operations.svc.cluster.local, other.internal")
        assert webhook_endpoint_valid(FLOWOPS)
        assert webhook_endpoint_valid("https://flowops.operations.svc.cluster.local/x")
        # Not listed: unchanged public-HTTPS-only rule.
        assert not webhook_endpoint_valid("http://serviceops.operations.svc.cluster.local/x")
        assert not webhook_endpoint_valid("http://hooks.example.com/x")
        assert webhook_endpoint_valid("https://hooks.example.com/x")
        # Suffix tricks and credentials in the URL are refused.
        assert not webhook_endpoint_valid("http://evil.flowops.operations.svc.cluster.local/x")
        assert not webhook_endpoint_valid("http://user:pw@flowops.operations.svc.cluster.local/x")
        assert not webhook_endpoint_valid("ftp://flowops.operations.svc.cluster.local/x")


def test_listing_a_loopback_or_link_local_literal_never_allows_it(monkeypatch, app):
    with app.app_context():
        monkeypatch.setenv("WEBHOOK_INTERNAL_HOSTS", "127.0.0.1 169.254.169.254 10.152.183.20")
        assert not webhook_endpoint_valid("http://127.0.0.1/x")
        assert not webhook_endpoint_valid("http://169.254.169.254/latest/meta-data")
        assert webhook_endpoint_valid("http://10.152.183.20/x")


def _connection(app, endpoint):
    admin = User.query.filter_by(username="admin").one()
    connection = IntegrationConnection(
        name="FlowOps events", kind="webhook", endpoint=endpoint,
        secret_encrypted=settings_cipher().encrypt(b"flowops-signing-secret").decode(),
        created_by_id=admin.id,
    )
    event = OutboxEvent(event_type="change.state_changed", payload_json=json.dumps({"number": "CHG0001"}))
    db.session.add_all([connection, event])
    db.session.commit()
    return connection, event


def test_delivery_to_a_listed_internal_host_is_signed_and_dns_pinned(monkeypatch, app):
    sent = []

    class Response:
        status_code = 202
        is_redirect = False

    def post(url, data=None, json=None, headers=None, timeout=None, allow_redirects=False, proxies=None):
        import socket
        # The connection resolves through the pinned addresses.
        sent.append((url, data, headers, socket.getaddrinfo("flowops.operations.svc.cluster.local", 80)))
        return Response()

    resolved = []

    def getaddrinfo(host, port, *args, **kwargs):
        resolved.append(host)
        return [(2, 1, 6, "", ("10.152.183.20", port or 0))]

    monkeypatch.setattr("app.requests.post", post)
    monkeypatch.setattr("app.socket.getaddrinfo", getaddrinfo)
    monkeypatch.setenv("WEBHOOK_INTERNAL_HOSTS", "flowops.operations.svc.cluster.local")
    with app.app_context():
        connection, event = _connection(app, FLOWOPS)
        assert deliver_webhook(event, connection) == 202
    url, body, headers, pinned = sent[0]
    assert url == FLOWOPS
    assert pinned[0][4][0] == "10.152.183.20"
    expected = hmac.new(b"flowops-signing-secret", headers["X-ServiceOps-Timestamp"].encode() + b"." + body,
                        hashlib.sha256).hexdigest()
    assert headers["X-ServiceOps-Signature"] == f"sha256={expected}"


def test_delivery_to_an_unlisted_private_host_is_still_refused(monkeypatch, app):
    monkeypatch.setattr("app.requests.post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not send")))
    monkeypatch.setattr("app.socket.getaddrinfo", lambda host, port, *a, **k: [(2, 1, 6, "", ("10.0.0.9", 0))])
    monkeypatch.setenv("WEBHOOK_INTERNAL_HOSTS", "flowops.operations.svc.cluster.local")
    with app.app_context():
        connection, event = _connection(app, "https://hooks.example.test/x")
        try:
            deliver_webhook(event, connection)
        except RuntimeError as error:
            assert "private address" in str(error)
        else:
            raise AssertionError("an unlisted host resolving privately must be refused")


def test_administrators_can_add_a_listed_internal_receiver_only(monkeypatch, client, app):
    login(client)
    form = {"action": "create_connection", "name": "FlowOps", "kind": "webhook", "endpoint": FLOWOPS,
            "secret": "flowops-signing-secret", "scope_type": "tenant",
            "event_types": ["change.state_changed", "change_task.state_changed"]}
    monkeypatch.delenv("WEBHOOK_INTERNAL_HOSTS", raising=False)
    assert client.post("/admin/integrations", data=form).status_code == 400
    monkeypatch.setenv("WEBHOOK_INTERNAL_HOSTS", "flowops.operations.svc.cluster.local")
    assert client.post("/admin/integrations", data=form).status_code in (200, 302)
    with app.app_context():
        assert IntegrationConnection.query.filter_by(name="FlowOps").one().endpoint == FLOWOPS
