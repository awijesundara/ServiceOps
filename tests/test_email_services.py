"""Saved email services: one default, an optional fallback, and the branded email."""
import email
import email.policy
from email.message import EmailMessage

import pytest

from app import OutboxEvent, PlatformSetting, User, create_notification, db, deliver_smtp, settings_cipher
from serviceops_models import MailService
from serviceops_core import mail
from tests.test_app import app, client, login  # noqa: F401


def setting(key, value, secret=False):
    row = db.session.get(PlatformSetting, key) or PlatformSetting(key=key)
    row.value = settings_cipher().encrypt(value.encode()).decode() if secret else value
    row.encrypted = secret
    db.session.add(row)


class Recorder:
    def __init__(self, fail=()):
        self.fail, self.calls = set(fail), []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        key = kwargs.get("headers", {}).get("Authorization", "")
        status = 401 if any(token in key for token in self.fail) else 202

        class Response:
            status_code, text = status, "unauthorized" if status == 401 else ""

            def raise_for_status(self):
                if status >= 400:
                    import requests
                    raise requests.HTTPError(response=self)
        return Response()


def sendgrid(name, key, sender="desk@example.test", **flags):
    service = MailService(name=name, provider="sendgrid", **flags)
    service.config = {"MAIL_API_KEY": key, "SMTP_FROM": sender, "SMTP_FROM_NAME": name}
    db.session.add(service)
    return service


def outgoing(to="person@example.test"):
    message = EmailMessage()
    message["To"] = to
    message["Subject"] = "Hello"
    message.set_content("Body")
    return message


def test_default_sends_with_its_own_sender_and_fallback_takes_over(app, monkeypatch):
    recorder = Recorder(fail={"bad-key"})
    monkeypatch.setattr(mail.requests, "post", recorder)
    with app.app_context():
        primary = sendgrid("Primary", "bad-key", "primary@example.test", is_default=True)
        backup = sendgrid("Backup", "good-key", "backup@example.test", is_fallback=True)
        db.session.commit()
        assert mail.send(outgoing()) == "Backup"
        assert primary.last_error and "HTTP 401" in primary.last_error
        assert backup.last_used_at and backup.last_error is None
    assert [call[1]["json"]["from"]["email"] for call in recorder.calls] == ["primary@example.test", "backup@example.test"]


def test_both_failing_reports_both_and_no_default_is_a_config_error(app, monkeypatch):
    monkeypatch.setattr(mail.requests, "post", Recorder(fail={"k"}))
    with app.app_context():
        sendgrid("A", "k", is_default=True)
        sendgrid("B", "k", is_fallback=True)
        db.session.commit()
        with pytest.raises(mail.MailError) as error:
            mail.send(outgoing())
        assert "Default service failed" in str(error.value) and "fallback failed" in str(error.value)
        MailService.query.update({"is_default": False, "is_fallback": False})
        db.session.commit()
        with pytest.raises(mail.MailError) as error:
            mail.send(outgoing())
        assert error.value.stage == "config"


def test_service_settings_never_leak_from_or_into_platform_settings(app, monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(mail.requests, "post", recorder)
    with app.app_context():
        setting("MAIL_TRANSPORT", "smtp")
        setting("SMTP_HOST", "legacy.example.test")
        sendgrid("Only", "svc-key", is_default=True)
        db.session.commit()
        mail.send(outgoing())
        assert mail._setting("SMTP_HOST") == "legacy.example.test"
    assert recorder.calls[0][1]["headers"]["Authorization"] == "Bearer svc-key"


def test_provider_forms_validate_only_the_chosen_method():
    config, errors = mail.validate_service("microsoft365", "relay", {"SMTP_HOST": "x.mail.protection.outlook.com",
                                                                      "SMTP_FROM": "a@b.test"})
    assert not errors and config["method"] == "relay" and "MS_TENANT_ID" not in config
    _, errors = mail.validate_service("microsoft365", "graph", {"SMTP_FROM": "a@b.test", "MS_TENANT_ID": "t",
                                                                 "MS_CLIENT_ID": "c", "MS_SENDER_MAILBOX": "a@b.test"})
    assert errors == ["Enter a client secret or a client certificate."]
    _, errors = mail.validate_service("smtp", None, {"SMTP_HOST": "h", "SMTP_FROM": "a@b.test",
                                                     "SMTP_SECURITY": "none", "SMTP_AUTH_MODE": "password"})
    assert errors and "encryption" in errors[0]
    config, errors = mail.validate_service("sendgrid", None, {"SMTP_FROM": "a@b.test"}, existing={"MAIL_API_KEY": "kept"})
    assert not errors and config["MAIL_API_KEY"] == "kept"
    config, errors = mail.validate_service("sendgrid", None, {"SMTP_FROM": "a@b.test", "clear_MAIL_API_KEY": "on"},
                                           existing={"MAIL_API_KEY": "kept"})
    assert not errors and config["MAIL_API_KEY"] == "kept", "a required secret cannot be removed"
    config, errors = mail.validate_service(
        "amazon_ses", None, {"SES_REGION": "eu-west-1", "SMTP_FROM": "a@b.test", "clear_SES_SECRET_ACCESS_KEY": "on"},
        existing={"SES_ACCESS_KEY_ID": "AKIA", "SES_SECRET_ACCESS_KEY": "s"})
    assert not errors and "SES_SECRET_ACCESS_KEY" not in config and "SES_ACCESS_KEY_ID" not in config
    settings = mail.service_settings("google", {"method": "oauth2", "SMTP_USERNAME": "u@g.test"})
    assert settings["SMTP_PROVIDER"] == "google_workspace_oauth2" and settings["MAIL_TRANSPORT"] == "smtp"


def test_admin_adds_tests_and_switches_services(client, app, monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(mail.requests, "post", recorder)
    login(client)
    page = client.get("/admin/email")
    assert page.status_code == 200 and b"Choose how ServiceOps sends email" in page.data
    assert client.get("/admin/settings/email_delivery").headers["Location"].endswith("/admin/email")
    form = client.get("/admin/email/new/sendgrid").data
    assert b'name="MAIL_API_KEY"' in form and b"SMTP_HOST" not in form and b"MS_TENANT_ID" not in form
    response = client.post("/admin/email/new/sendgrid", data={"name": "SendGrid", "MAIL_API_KEY": "SG.secret",
                                                               "SMTP_FROM": "desk@example.test"})
    assert response.status_code == 302
    with app.app_context():
        first = MailService.query.one()
        assert first.is_default and first.config["MAIL_API_KEY"] == "SG.secret"
        assert "SG.secret" not in first.config_encrypted
        first_id = first.id
    # Editing with a blank secret keeps it, and the page never shows it.
    edit = client.get(f"/admin/email/{first_id}")
    assert b"SG.secret" not in edit.data and b"Saved" in edit.data
    client.post(f"/admin/email/{first_id}", data={"name": "SendGrid main", "MAIL_API_KEY": "", "SMTP_FROM": "desk@example.test"})
    client.post("/admin/email/new/smtp", data={"name": "Relay", "SMTP_HOST": "relay.example.test", "SMTP_PORT": "25",
                                               "SMTP_SECURITY": "none", "SMTP_AUTH_MODE": "none", "SMTP_FROM": "desk@example.test"})
    with app.app_context():
        assert db.session.get(MailService, first_id).config["MAIL_API_KEY"] == "SG.secret"
        relay = MailService.query.filter_by(name="Relay").one()
        assert not relay.is_default
        relay_id = relay.id
    client.post(f"/admin/email/{relay_id}/role", data={"role": "fallback"})
    response = client.post(f"/admin/email/{first_id}/test", data={"recipient": "ops@example.test"}, follow_redirects=True)
    assert b"Test email accepted for delivery to" in response.data
    sent = recorder.calls[-1][1]["json"]
    assert sent["personalizations"][0]["to"] == [{"email": "ops@example.test"}]
    assert any(part["type"] == "text/html" and "Email delivery is working" in part["value"] for part in sent["content"])
    client.post(f"/admin/email/{relay_id}/role", data={"role": "default"})
    with app.app_context():
        assert db.session.get(MailService, relay_id).is_default
        assert not db.session.get(MailService, first_id).is_default
    assert b"Make another service the default" in client.post(f"/admin/email/{relay_id}/delete", follow_redirects=True).data
    client.post(f"/admin/email/{first_id}/delete")
    with app.app_context():
        assert MailService.query.count() == 1


def test_existing_email_settings_become_the_first_service_once(client, app):
    with app.app_context():
        setting("MAIL_TRANSPORT", "sendgrid")
        setting("MAIL_API_KEY", "SG.legacy", secret=True)
        setting("SMTP_FROM", "desk@example.test")
        db.session.commit()
    login(client)
    assert b"desk@example.test" in client.get("/admin/email").data
    with app.app_context():
        service = MailService.query.one()
        assert service.provider == "sendgrid" and service.is_default and service.config["MAIL_API_KEY"] == "SG.legacy"
        service_id = service.id
    client.post(f"/admin/email/{service_id}/delete")
    client.get("/admin/email")
    with app.app_context():
        assert MailService.query.count() == 0, "a removed import does not come back"
        with pytest.raises(mail.MailError):
            mail.send(outgoing())


def test_only_administrators_manage_email_services(client, app):
    with app.app_context():
        from werkzeug.security import generate_password_hash
        db.session.add(User(username="mailagent", name="Agent", email="mailagent@example.test", role="agent",
                            password_hash=generate_password_hash("Agent123!x")))
        db.session.commit()
    login(client, "mailagent", "Agent123!x")
    assert client.get("/admin/email").status_code in (302, 403)
    assert client.post("/admin/email/new/sendgrid", data={"name": "x"}).status_code in (302, 403)


def test_notification_email_is_branded_html_with_escaped_content_and_link(app, monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(mail.requests, "post", recorder)
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://desk.example.test")
    with app.app_context():
        setting("SMTP_ENABLED", "true")
        sendgrid("SendGrid", "k", is_default=True)
        admin = User.query.filter_by(username="admin").one()
        admin.email = "admin@example.test"
        db.session.commit()
        create_notification(admin.id, "SLA breached: <b>INC9</b>", "Line one\nLine <script>two</script>\n\nSecond paragraph",
                            tenant_id=admin.tenant_id, event_type="sla.breached")
        db.session.commit()
        event = OutboxEvent.query.filter_by(event_type="notification.created").order_by(OutboxEvent.id.desc()).first()
        assert deliver_smtp(event) is True
    body = recorder.calls[-1][1]["json"]
    text = body["content"][0]["value"]
    html = body["content"][1]["value"]
    assert "Line <script>two</script>" in text
    assert "<script>" not in html and "&lt;script&gt;two&lt;/script&gt;" in html
    assert "&lt;b&gt;INC9&lt;/b&gt;" in html
    assert "SLA breached" in html and "#b42318" in html, "critical events use the alert colour"
    assert "https://desk.example.test/preferences#notifications" in html
    assert "<p style" in html and "Second paragraph" in html


def test_company_logo_travels_inline(app, tmp_path, monkeypatch):
    from serviceops_core.email_render import render_email
    png = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
    monkeypatch.setitem(app.config, "UPLOAD_FOLDER", str(tmp_path))
    (tmp_path / "company-logo.png").write_bytes(png)
    with app.app_context(), app.test_request_context("/"):
        message = outgoing()
        render_email(message, title="T", body="B", link_url="https://desk.example.test/tickets/1")
    parsed = email.message_from_bytes(message.as_bytes(), policy=email.policy.default)
    image = next(part for part in parsed.walk() if part.get_content_type() == "image/png")
    html = next(part for part in parsed.walk() if part.get_content_type() == "text/html").get_content()
    assert image["Content-ID"].strip("<>") in html
    assert 'href="https://desk.example.test/tickets/1"' in html
