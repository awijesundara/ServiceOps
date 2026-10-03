"""Regression tests for the 2026-10-03 security review findings.

Each test exercises the real route or function and fails on the code as it
was before the corresponding fix.
"""
import datetime
import json
import logging
import os
import socket
import ssl
import tempfile
import threading

import pyotp
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from werkzeug.security import generate_password_hash

import app as app_module
from app import (
    APIClient, ClientMailbox, ConfigurationItem, Rack, SLADefinition, SupportGroup, TaskSLA,
    Tenant, Ticket, User, attach_slas, create_api_token, create_app, db, settings_cipher,
)
from serviceops_core import proxy_tunnel
from serviceops_core.security import redact
from serviceops_models import CiClassPermission
from tests.test_app import _FakeIMAPConnection, app, client, group_id, login  # noqa: F401

MOBILE_HEADERS = {
    "X-ServiceOps-App-Version": "1.1.0", "X-ServiceOps-App-Build": "42",
    "X-ServiceOps-Platform": "iOS", "X-ServiceOps-Device": "iPhone17,1",
}


def other_tenant(app, slug="sec-other"):
    with app.app_context():
        tenant = Tenant(slug=slug, name="Other organization")
        db.session.add(tenant)
        db.session.commit()
        return tenant.id


def mobile_login(client, username="admin", password="Admin123!"):
    response = client.post("/api/v1/auth/mobile/login", headers=MOBILE_HEADERS, json={
        "username": username, "password": password, "provider": "local",
    })
    assert response.status_code == 200, response.data
    return response.json


def api_headers(app, username, scopes):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(
            name=f"{username} test client", token_prefix=prefix, token_hash=token_hash,
            scopes_json=json.dumps(scopes), acting_user_id=user.id, created_by_id=user.id,
            tenant_id=user.tenant_id,
        ))
        db.session.commit()
    return {"Authorization": f"Bearer {token}"}


# 1. CMDB API honours per-class permissions -----------------------------------

def test_cmdb_api_upsert_requires_the_acting_users_class_permission(app, client):
    headers = api_headers(app, "database.manager", ["cmdb:write"])
    denied = client.put("/api/v1/cmdb/configuration-items", headers=headers,
                        json={"name": "api-srv-1", "ci_class": "Server"})
    assert denied.status_code == 403
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="api-srv-1").count() == 0
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Server", role="manager",
                                         can_read=True, can_create=True, can_update=True))
        db.session.commit()
    created = client.put("/api/v1/cmdb/configuration-items", headers=headers,
                         json={"name": "api-srv-1", "ci_class": "Server"})
    assert created.status_code in (200, 201), created.data
    moved = client.put("/api/v1/cmdb/configuration-items", headers=headers,
                       json={"name": "api-srv-1", "ci_class": "Firewall"})
    assert moved.status_code == 403
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="api-srv-1").one().ci_class == "Server"


# 2. Forms refuse another tenant's records ------------------------------------

def test_ci_forms_refuse_another_tenants_rack_group_and_owner(app, client):
    tenant_id = other_tenant(app)
    with app.app_context():
        foreign_rack = Rack(name="Other rack", tenant_id=tenant_id)
        foreign_group = SupportGroup(name="Other team", tenant_id=tenant_id)
        foreign_user = User(username="other.owner", name="Other Owner", email="other.owner@test.invalid",
                            password_hash=generate_password_hash("OtherOwner123!"), role="agent",
                            tenant_id=tenant_id)
        db.session.add_all([foreign_rack, foreign_group, foreign_user])
        db.session.commit()
        foreign = {"rack_id": foreign_rack.id, "support_group_id": foreign_group.id,
                   "owner_id": foreign_user.id}
    login(client)
    base = {"name": "tenant-check-srv", "ci_class": "Server", "environment": "Production",
            "operational_status": "Operational"}
    for field in ("rack_id", "support_group_id"):
        response = client.post("/cmdb/new", data={**base, field: str(foreign[field])})
        assert response.status_code == 400, field
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="tenant-check-srv").count() == 0
    assert client.post("/cmdb/new", data=base).status_code == 302
    with app.app_context():
        ci = ConfigurationItem.query.filter_by(name="tenant-check-srv").one()
        ci_id = ci.id
    for field in ("rack_id", "support_group_id", "owner_id"):
        response = client.post(f"/cmdb/{ci_id}/edit", data={**base, field: str(foreign[field])})
        assert response.status_code == 400, field
    with app.app_context():
        ci = db.session.get(ConfigurationItem, ci_id)
        assert ci.rack_id is None and ci.support_group_id is None
        assert ci.owner_id != foreign["owner_id"]


def test_new_ticket_refuses_another_tenants_owning_team(app, client):
    tenant_id = other_tenant(app)
    with app.app_context():
        foreign_group = SupportGroup(name="Other fulfillment", tenant_id=tenant_id,
                                     group_type="IT Fulfillment", active=True)
        db.session.add(foreign_group)
        db.session.commit()
        foreign_group_id = foreign_group.id
        before = Ticket.query.count()
    login(client)
    response = client.post("/tickets/new/incident", data={
        "title": "Cross-tenant team", "description": "x", "category": "Network",
        "subcategory": "x", "contact_type": "Self-service", "notify": "Email",
        "impact": "High", "urgency": "High", "group_id": str(foreign_group_id),
    })
    assert response.status_code != 302
    with app.app_context():
        assert Ticket.query.count() == before
    accepted = client.post("/tickets/new/incident", data={
        "title": "Own team", "description": "x", "category": "Network",
        "subcategory": "x", "contact_type": "Self-service", "notify": "Email",
        "impact": "High", "urgency": "High", "group_id": str(group_id(app, "Network")),
    })
    assert accepted.status_code == 302


# 3. SLA definitions stay inside their tenant ---------------------------------

def test_attach_slas_ignores_other_tenants_definitions(app, client):
    tenant_id = other_tenant(app)
    login(client)
    created = client.post("/tickets/new/incident", data={
        "title": "SLA tenant check", "description": "x", "category": "Network",
        "subcategory": "x", "contact_type": "Self-service", "notify": "Email",
        "impact": "Low", "urgency": "Low", "group_id": str(group_id(app, "Network")),
    })
    assert created.status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="SLA tenant check").one()
        foreign = SLADefinition(name="Other tenant P-any", target_type="ticket", priority=None,
                                duration_minutes=60, tenant_id=tenant_id)
        db.session.add(foreign)
        db.session.commit()
        attach_slas("ticket", ticket.id, ticket.priority)
        db.session.commit()
        assert TaskSLA.query.filter_by(definition_id=foreign.id).count() == 0


# 4. Mobile sessions end when credentials change ------------------------------

def test_mobile_tokens_stop_working_after_a_credential_change(app, client):
    session = mobile_login(client)
    bearer = {"Authorization": f"Bearer {session['access_token']}"}
    assert client.get("/api/v1/tickets", headers=bearer).status_code == 200
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin.auth_version += 1  # what every password change/reset/deactivation does
        db.session.commit()
    assert client.get("/api/v1/tickets", headers=bearer).status_code == 401
    refreshed = client.post("/api/v1/auth/mobile/refresh", json={"refresh_token": session["refresh_token"]})
    assert refreshed.status_code == 401
    with app.app_context():
        row = APIClient.query.filter_by(client_kind="mobile").one()
        assert row.active is False and row.refresh_token_hash is None


def test_refresh_on_a_stale_session_is_refused(app, client):
    session = mobile_login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin.auth_version += 1
        db.session.commit()
    response = client.post("/api/v1/auth/mobile/refresh", json={"refresh_token": session["refresh_token"]})
    assert response.status_code == 401


# 5. A deactivated tenant loses every kind of access ---------------------------

def make_tenant_user(app, tenant_id, username="tenant.user", password="TenantUser123!"):
    with app.app_context():
        db.session.add(User(username=username, name="Tenant User", email=f"{username}@test.invalid",
                            password_hash=generate_password_hash(password), role="agent",
                            tenant_id=tenant_id))
        db.session.commit()
    return username, password


def set_tenant_active(app, tenant_id, active):
    with app.app_context():
        db.session.get(Tenant, tenant_id).active = active
        db.session.commit()


def test_deactivated_tenant_cannot_log_in_and_loses_live_sessions(app, client):
    tenant_id = other_tenant(app)
    username, password = make_tenant_user(app, tenant_id)
    login(client, username, password)
    assert client.get("/").status_code == 200
    set_tenant_active(app, tenant_id, False)
    assert client.get("/").status_code == 302  # live session ended on the next request
    fresh = app.test_client()
    page = login(fresh, username, password)
    assert b"Invalid username or password" in page.data
    assert fresh.get("/").status_code == 302


def test_deactivated_tenant_loses_api_and_mobile_access(app, client):
    tenant_id = other_tenant(app)
    username, password = make_tenant_user(app, tenant_id)
    session = mobile_login(client, username, password)
    headers = api_headers(app, username, ["tickets:read"])
    set_tenant_active(app, tenant_id, False)
    assert client.get("/api/v1/tickets", headers=headers).status_code == 403
    assert client.get("/api/v1/tickets", headers={
        "Authorization": f"Bearer {session['access_token']}"}).status_code == 403
    assert client.post("/api/v1/auth/mobile/refresh",
                       json={"refresh_token": session["refresh_token"]}).status_code == 401
    assert client.post("/api/v1/auth/mobile/login", headers=MOBILE_HEADERS, json={
        "username": username, "password": password, "provider": "local"}).status_code in (401, 403)


# 6. HTTPS proxies are reached over TLS --------------------------------------

def _self_signed_certificate(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "proxy.pem", tmp_path / "proxy.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


def _serve_tls_proxy(listener, server_context, received):
    """A minimal TLS forward proxy: accepts one CONNECT, then echoes."""
    raw, _ = listener.accept()
    with server_context.wrap_socket(raw, server_side=True) as conn:
        request = b""
        while b"\r\n\r\n" not in request:
            request += conn.recv(1)
        received.append(request)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        data = conn.recv(1024)
        conn.sendall(b"echo:" + data)


def test_https_proxy_is_reached_over_verified_tls(tmp_path, monkeypatch):
    cert_path, key_path = _self_signed_certificate(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cafile=str(cert_path))
    monkeypatch.setattr(proxy_tunnel, "_proxy_tls_context", lambda: client_context)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    received = []
    server = threading.Thread(target=_serve_tls_proxy, args=(listener, server_context, received), daemon=True)
    server.start()
    with proxy_tunnel.tunnel_through_proxy(f"https://user:pa55@localhost:{port}"):
        tunnel = socket.create_connection(("mail.example.test", 587), timeout=5)
    tunnel.sendall(b"EHLO test")
    assert tunnel.recv(1024) == b"echo:EHLO test"
    tunnel.close()
    server.join(5)
    listener.close()
    assert received and received[0].startswith(b"CONNECT mail.example.test:587 HTTP/1.1")
    assert b"Proxy-Authorization: Basic" in received[0]


def test_https_proxy_never_falls_back_to_cleartext(monkeypatch):
    """A listener that does not speak TLS must see no credentials at all."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = []

    def plain_server():
        conn, _ = listener.accept()
        conn.settimeout(2)
        try:
            seen.append(conn.recv(4096))
        except OSError:
            seen.append(b"")
        conn.close()

    server = threading.Thread(target=plain_server, daemon=True)
    server.start()
    with pytest.raises(OSError):
        with proxy_tunnel.tunnel_through_proxy(f"https://user:pa55@127.0.0.1:{port}"):
            socket.create_connection(("mail.example.test", 587), timeout=3)
    server.join(5)
    listener.close()
    assert b"Proxy-Authorization" not in b"".join(seen)
    assert b"pa55" not in b"".join(seen)


# 7. Recovery tokens never reach logs ----------------------------------------

def test_recovery_token_is_redacted_from_request_logs(app, client, caplog):
    token = "R3c0very-T0ken_value"
    assert redact(f'GET /reset-password/{token} HTTP/1.1 "https://x/reset-password/{token}"').count(token) == 0
    with caplog.at_level(logging.INFO, logger="serviceops.request"):
        response = client.get(f"/reset-password/{token}")
    assert response.headers["Referrer-Policy"] == "no-referrer"
    logged = [record for record in caplog.records if record.name == "serviceops.request"]
    assert logged
    for record in logged:
        assert token not in record.getMessage()
        assert token not in str(getattr(record, "path", ""))



def test_startup_migrations_do_not_disable_existing_loggers():
    # Alembic's env.py runs logging.config.fileConfig(); with its default it
    # disables every logger that already exists, silencing the request log
    # and module loggers for the rest of the process.
    request_logger = logging.getLogger("serviceops.request")
    module_logger = logging.getLogger("serviceops_core.proxy_tunnel")
    request_logger.disabled = module_logger.disabled = False
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        create_app({"TESTING": True, "AUTO_MIGRATE_IN_TESTS": True,
                    "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
        assert not request_logger.disabled
        assert not module_logger.disabled
    finally:
        request_logger.disabled = module_logger.disabled = False
        os.unlink(path)

# 8. Inbound email is marked read only after it is saved ---------------------

class _RecordingIMAP(_FakeIMAPConnection):
    def __init__(self, raw_messages):
        super().__init__(raw_messages)
        self.fetch_parts = []

    def fetch(self, num, parts):
        self.fetch_parts.append(parts)
        return super().fetch(num, parts)


def _mailbox(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        mailbox = ClientMailbox(tenant_id=1, name="Inbound", imap_host="imap.example.test",
                                smtp_host="smtp.example.test", from_address="support@ourcompany.test",
                                created_by_id=admin.id)
        db.session.add(mailbox)
        db.session.commit()
        return mailbox.id


def _raw_email():
    from email.message import EmailMessage
    message = EmailMessage()
    message["From"] = "Customer <customer@realcompany.test>"
    message["To"] = "support@ourcompany.test"
    message["Subject"] = "Please help"
    message["Message-ID"] = "<retry-1@realcompany.test>"
    message.set_content("Help.")
    return message.as_bytes()


def test_failed_inbound_email_stays_unread_for_retry(app, client, monkeypatch):
    mailbox_id = _mailbox(app)
    connection = _RecordingIMAP([_raw_email()])
    monkeypatch.setattr(app_module.imaplib, "IMAP4_SSL", lambda host, port: connection)

    def failing(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(app_module, "_create_client_ticket_from_email", failing)
    with app.app_context():
        assert app_module._poll_client_mailbox(db.session.get(ClientMailbox, mailbox_id)) == 0
    assert connection.fetch_parts == ["(BODY.PEEK[])"]
    assert b"1" not in connection.stored_flags


def test_saved_inbound_email_is_marked_read(app, client, monkeypatch):
    mailbox_id = _mailbox(app)
    connection = _RecordingIMAP([_raw_email()])
    monkeypatch.setattr(app_module.imaplib, "IMAP4_SSL", lambda host, port: connection)
    with app.app_context():
        assert app_module._poll_client_mailbox(db.session.get(ClientMailbox, mailbox_id)) == 1
    assert connection.stored_flags[b"1"] == "\\Seen"


# 9. A pending MFA login dies with a credential change ------------------------

def test_pending_mfa_login_is_voided_by_a_password_change(app):
    secret = "JBSWY3DPEHPK3PXP"
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin.mfa_enabled = True
        admin.mfa_secret_encrypted = settings_cipher().encrypt(secret.encode()).decode()
        db.session.commit()
    browser = app.test_client()
    step_one = browser.post("/login", data={"username": "admin", "password": "Admin123!"})
    assert step_one.status_code == 302 and "/login/mfa" in step_one.headers["Location"]
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin.auth_version += 1  # password changed by someone else meanwhile
        db.session.commit()
    step_two = browser.post("/login/mfa", data={"code": pyotp.TOTP(secret).now()})
    assert step_two.status_code == 302 and step_two.headers["Location"].endswith("/login")
    assert browser.get("/").status_code == 302


# 10. Non-object JSON is a client error, not a server error -------------------

@pytest.mark.parametrize("path", [
    "/api/v1/auth/mobile/refresh",
    "/api/v1/auth/passkeys/authenticate/complete",
])
def test_unauthenticated_json_routes_reject_non_objects(app, client, path):
    for body in ([1, 2], "text", 5):
        assert client.post(path, json=body).status_code == 400, (path, body)


def test_authenticated_json_routes_reject_non_objects(app, client):
    session = mobile_login(client)
    bearer = {"Authorization": f"Bearer {session['access_token']}"}
    login(client)
    created = client.post("/tickets/new/incident", data={
        "title": "JSON check", "description": "x", "category": "Network",
        "subcategory": "x", "contact_type": "Self-service", "notify": "Email",
        "impact": "Low", "urgency": "Low", "group_id": str(group_id(app, "Network")),
    })
    assert created.status_code == 302
    with app.app_context():
        number = Ticket.query.filter_by(title="JSON check").one().number
    for path in ("/api/v1/auth/passkeys/register/complete",
                 "/api/v1/mobile/push-devices", "/api/v1/mobile/approvals/1/decide",
                 f"/api/v1/tickets/{number}/comments"):
        response = client.post(path, headers=bearer, json=["not", "an", "object"])
        assert response.status_code == 400, (path, response.status_code)
