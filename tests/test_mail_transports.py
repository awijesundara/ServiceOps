"""Outgoing email works in every supported sending environment."""
import base64
import email
import os
import smtplib
import ssl
import stat
import sys
import types
from email.message import EmailMessage

import pytest

from app import PlatformSetting, User, db, settings_cipher
from serviceops_core import mail
from tests.test_app import app, client, login  # noqa: F401


def configure(**values):
    for key, value in values.items():
        secret = key in {"SMTP_PASSWORD", "MS_CLIENT_SECRET", "MS_CLIENT_CERTIFICATE", "MAIL_API_KEY",
                         "SES_SECRET_ACCESS_KEY", "SMTP_OAUTH_CLIENT_SECRET", "SMTP_OAUTH_REFRESH_TOKEN"}
        row = db.session.get(PlatformSetting, key) or PlatformSetting(key=key)
        row.value = settings_cipher().encrypt(value.encode()).decode() if secret else value
        row.encrypted = secret
        db.session.add(row)
    db.session.commit()


def message(to="person@example.test"):
    item = EmailMessage()
    item["From"] = "ServiceOps <serviceops@example.test>"
    item["To"] = to
    item["Subject"] = "INC0000001 updated"
    item["X-ServiceOps-Event-ID"] = "evt-1"
    item.set_content("Body text")
    item.add_alternative("<p>Body text</p>", subtype="html")
    return item


class FakeSMTP:
    instances = []

    def __init__(self, host, port, **kwargs):
        self.host, self.port, self.kwargs = host, port, kwargs
        self.commands, self.sent = [], []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def ehlo(self):
        self.commands.append("ehlo")

    def starttls(self, context):
        self.commands.append("starttls")
        self.context = context

    def login(self, username, password):
        self.commands.append(("login", username, password))

    def docmd(self, verb, argument):
        self.commands.append((verb, argument))
        return 235, b"ok"

    def send_message(self, item):
        self.sent.append(item)
        return {}


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    mail._ms_tokens.clear()
    return FakeSMTP


class Response:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code, self._payload, self.text = status, payload or {}, text

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(response=self)


def test_generic_smtp_keeps_its_defaults_and_adds_safe_headers(app, fake_smtp):
    with app.app_context():
        configure(SMTP_HOST="mail.example.test", SMTP_USERNAME="mailer", SMTP_PASSWORD="pw")
        mail.send(message())
        smtp = fake_smtp.instances[0]
        assert (smtp.host, smtp.port, smtp.kwargs) == ("mail.example.test", 587, {"timeout": 10})
        assert smtp.commands[:3] == ["ehlo", "starttls", "ehlo"]
        assert ("login", "mailer", "pw") in smtp.commands
        sent = smtp.sent[0]
        assert sent["Message-ID"].endswith("@example.test>")
        assert sent["X-Auto-Response-Suppress"] == "All"


def test_microsoft365_smtp_oauth2_uses_client_credentials_for_outlook(app, fake_smtp, monkeypatch):
    calls = []
    monkeypatch.setattr(mail.requests, "post", lambda url, **kw: calls.append((url, kw)) or Response(
        payload={"access_token": "ms-token", "expires_in": 3600}))
    with app.app_context():
        configure(SMTP_PROVIDER="microsoft365_oauth2", SMTP_USERNAME="alerts@contoso.test",
                  MS_TENANT_ID="contoso-tenant", MS_CLIENT_ID="app-id", MS_CLIENT_SECRET="app-secret")
        mail.send(message())
        mail.send(message())
    assert len(calls) == 1, "the token is cached"
    url, kwargs = calls[0]
    assert url == "https://login.microsoftonline.com/contoso-tenant/oauth2/v2.0/token"
    assert kwargs["data"]["scope"] == "https://outlook.office365.com/.default"
    assert kwargs["data"]["client_secret"] == "app-secret"
    smtp = fake_smtp.instances[0]
    assert (smtp.host, smtp.port) == ("smtp.office365.com", 587)
    verb, argument = next(c for c in smtp.commands if isinstance(c, tuple) and c[0] == "AUTH")
    decoded = base64.b64decode(argument.split()[1]).decode()
    assert decoded == "user=alerts@contoso.test\x01auth=Bearer ms-token\x01\x01"


def test_saved_form_defaults_do_not_override_a_provider_preset(app, fake_smtp, monkeypatch):
    monkeypatch.setattr(mail.requests, "post", lambda url, **kw: Response(payload={"access_token": "t"}))
    with app.app_context():
        configure(SMTP_PROVIDER="microsoft365_oauth2", SMTP_SECURITY="preset", SMTP_AUTH_MODE="preset",
                  SMTP_PORT="0", SMTP_USERNAME="a@contoso.test",
                  MS_TENANT_ID="t", MS_CLIENT_ID="c", MS_CLIENT_SECRET="s")
        profile = mail.smtp_profile()
    assert (profile["host"], profile["port"], profile["security"], profile["auth_mode"]) == (
        "smtp.office365.com", 587, "starttls", "microsoft_oauth2")


def test_relay_with_internal_ca_and_ehlo_name_and_implicit_tls(app, fake_smtp, monkeypatch):
    loaded = []
    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", lambda self, **kw: loaded.append(kw))
    with app.app_context():
        configure(SMTP_PROVIDER="exchange_onprem", SMTP_HOST="exch01.corp.test", SMTP_PORT="465",
                  SMTP_SECURITY="tls", SMTP_AUTH_MODE="none", SMTP_LOCAL_HOSTNAME="serviceops.corp.test",
                  SMTP_CA_CERT="-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----")
        mail.send(message())
    smtp = fake_smtp.instances[0]
    assert (smtp.host, smtp.port) == ("exch01.corp.test", 465)
    assert smtp.kwargs["local_hostname"] == "serviceops.corp.test"
    assert "context" in smtp.kwargs and "starttls" not in smtp.commands
    assert not any(isinstance(c, tuple) for c in smtp.commands), "no authentication on a trusted relay"
    assert loaded and "\n" in loaded[0]["cadata"]


def test_unauthenticated_plaintext_is_allowed_but_auth_without_tls_is_refused(app, fake_smtp):
    with app.app_context():
        configure(SMTP_HOST="relay.test", SMTP_SECURITY="none", SMTP_AUTH_MODE="password")
        with pytest.raises(mail.MailError) as error:
            mail.send(message())
        assert error.value.stage == "config" and error.value.permanent


def test_smtp_rejections_are_classified(app, monkeypatch):
    class Rejecting(FakeSMTP):
        def login(self, *_):
            raise smtplib.SMTPAuthenticationError(535, b"5.7.139 Authentication unsuccessful")
    monkeypatch.setattr(smtplib, "SMTP", Rejecting)
    with app.app_context():
        configure(SMTP_HOST="smtp.test", SMTP_USERNAME="u", SMTP_PASSWORD="p")
        with pytest.raises(mail.MailError) as error:
            mail.send(message())
    assert error.value.stage == "auth" and error.value.permanent and "5.7.139" in str(error.value)

    class Refusing(FakeSMTP):
        def send_message(self, item):
            raise smtplib.SMTPRecipientsRefused({"x@example.test": (450, b"try later")})
    monkeypatch.setattr(smtplib, "SMTP", Refusing)
    with app.app_context():
        with pytest.raises(mail.MailError) as error:
            mail.send(message("x@example.test"))
    assert error.value.stage == "send" and not error.value.permanent


def test_microsoft_graph_sends_raw_mime_in_the_right_cloud(app, monkeypatch):
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        if "oauth2" in url:
            return Response(payload={"access_token": "graph-token", "expires_in": 3600})
        return Response(status=202)
    monkeypatch.setattr(mail.requests, "post", post)
    mail._ms_tokens.clear()
    with app.app_context():
        configure(MAIL_TRANSPORT="microsoft_graph", MS_CLOUD="usgov_gcc_high", MS_TENANT_ID="t",
                  MS_CLIENT_ID="c", MS_CLIENT_SECRET="s", MS_SENDER_MAILBOX="alerts@agency.test")
        mail.send(message())
    token_url, token = calls[0]
    assert token_url.startswith("https://login.microsoftonline.us/t/")
    assert token["data"]["scope"] == "https://graph.microsoft.us/.default"
    send_url, send = calls[1]
    assert send_url == "https://graph.microsoft.us/v1.0/users/alerts%40agency.test/sendMail"
    assert send["headers"]["Authorization"] == "Bearer graph-token"
    parsed = email.message_from_bytes(base64.b64decode(send["data"]))
    assert parsed["Subject"] == "INC0000001 updated" and parsed["X-ServiceOps-Event-ID"] == "evt-1"


def test_microsoft_graph_permission_error_is_actionable(app, monkeypatch):
    monkeypatch.setattr(mail.requests, "post", lambda url, **kw: Response(
        payload={"access_token": "x"}) if "oauth2" in url else Response(status=403))
    mail._ms_tokens.clear()
    with app.app_context():
        configure(MAIL_TRANSPORT="microsoft_graph", MS_TENANT_ID="t", MS_CLIENT_ID="c", MS_CLIENT_SECRET="s")
        with pytest.raises(mail.MailError) as error:
            mail.send(message())
    assert error.value.stage == "auth" and "Mail.Send" in str(error.value)


def test_microsoft_certificate_credential_builds_a_signed_assertion(app, monkeypatch):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "serviceops")])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(1).not_valid_before(start).not_valid_after(start + datetime.timedelta(days=999))
                   .sign(key, hashes.SHA256()))
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()) + certificate.public_bytes(serialization.Encoding.PEM)
    calls = []
    monkeypatch.setattr(mail.requests, "post", lambda url, **kw: calls.append(kw) or Response(
        payload={"access_token": "x"}))
    mail._ms_tokens.clear()
    with app.app_context():
        configure(MS_TENANT_ID="t", MS_CLIENT_ID="c", MS_CLIENT_CERTIFICATE=pem.decode())
        mail.microsoft_token("graph")
    data = calls[0]["data"]
    assert "client_secret" not in data
    header = data["client_assertion"].split(".")[0]
    decoded = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
    assert b'"x5t#S256"' in decoded and b'"PS256"' in decoded


def test_amazon_ses_uses_the_role_when_no_keys_are_set(app, monkeypatch):
    clients = []

    class Client:
        def send_email(self, **request):
            self.request = request

    def client(name, **kwargs):
        clients.append((name, kwargs, Client()))
        return clients[-1][2]
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=client))
    with app.app_context():
        configure(MAIL_TRANSPORT="amazon_ses", SES_REGION="eu-west-1", SES_CONFIGURATION_SET="serviceops")
        mail.send(message())
    name, kwargs, sent = clients[0]
    assert name == "sesv2" and kwargs["region_name"] == "eu-west-1"
    assert "aws_access_key_id" not in kwargs
    assert sent.request["ConfigurationSetName"] == "serviceops"
    assert sent.request["Destination"]["ToAddresses"] == ["person@example.test"]
    assert b"INC0000001 updated" in sent.request["Content"]["Raw"]["Data"]


@pytest.mark.parametrize("transport,url", [
    ("sendgrid", "https://api.sendgrid.com/v3/mail/send"),
    ("postmark", "https://api.postmarkapp.com/email"),
    ("mailgun", "https://api.eu.mailgun.net/v3/mg.example.test/messages.mime"),
])
def test_http_email_apis(app, monkeypatch, transport, url):
    calls = []
    monkeypatch.setattr(mail.requests, "post", lambda u, **kw: calls.append((u, kw)) or Response(status=200))
    with app.app_context():
        configure(MAIL_TRANSPORT=transport, MAIL_API_KEY="key-1", MAILGUN_DOMAIN="mg.example.test", MAILGUN_REGION="eu")
        mail.send(message())
    sent_url, kwargs = calls[0]
    assert sent_url == url
    if transport == "sendgrid":
        assert kwargs["headers"]["Authorization"] == "Bearer key-1"
        assert kwargs["json"]["content"][1] == {"type": "text/html", "value": "<p>Body text</p>\n"}
        assert kwargs["json"]["headers"]["X-ServiceOps-Event-ID"] == "evt-1"
    elif transport == "postmark":
        assert kwargs["headers"]["X-Postmark-Server-Token"] == "key-1"
        assert kwargs["json"]["TextBody"] == "Body text\n"
    else:
        assert kwargs["auth"] == ("api", "key-1")
        assert kwargs["data"]["to"] == "person@example.test"


def test_http_api_rejection_is_permanent_and_rate_limit_is_not(app, monkeypatch):
    with app.app_context():
        configure(MAIL_TRANSPORT="sendgrid", MAIL_API_KEY="k")
        monkeypatch.setattr(mail.requests, "post", lambda u, **kw: Response(status=400, text="bad from"))
        with pytest.raises(mail.MailError) as error:
            mail.send(message())
        assert error.value.permanent and "bad from" in str(error.value)
        monkeypatch.setattr(mail.requests, "post", lambda u, **kw: Response(status=429))
        with pytest.raises(mail.MailError) as error:
            mail.send(message())
        assert not error.value.permanent


def test_sendmail_passes_recipients_as_arguments(app, tmp_path):
    output = tmp_path / "out"
    program = tmp_path / "sendmail"
    program.write_text(f"#!/bin/sh\necho \"$@\" > {output}.args\ncat > {output}\n")
    program.chmod(program.stat().st_mode | stat.S_IEXEC)
    with app.app_context():
        configure(MAIL_TRANSPORT="sendmail", SENDMAIL_PATH=str(program))
        mail.send(message("-oQ/tmp@example.test"))
    assert (tmp_path / "out.args").read_text().strip() == "-i -- -oQ/tmp@example.test"
    assert b"INC0000001 updated" in output.read_bytes()


def test_sendmail_refuses_a_program_that_is_not_a_mail_program(app):
    with app.app_context():
        configure(MAIL_TRANSPORT="sendmail", SENDMAIL_PATH="/bin/sh")
        with pytest.raises(mail.MailError) as error:
            mail.send(message())
    assert error.value.permanent and "not a mail program" in str(error.value)


def test_pickup_directory_writes_complete_eml_files(app, tmp_path):
    with app.app_context():
        configure(MAIL_TRANSPORT="pickup_directory", MAIL_PICKUP_DIRECTORY=str(tmp_path))
        mail.send(message())
    files = os.listdir(tmp_path)
    assert len(files) == 1 and files[0].endswith(".eml")
    assert email.message_from_bytes((tmp_path / files[0]).read_bytes())["To"] == "person@example.test"


def test_unknown_transport_and_missing_recipient_fail_cleanly(app):
    with app.app_context():
        configure(MAIL_TRANSPORT="carrier_pigeon")
        with pytest.raises(mail.MailError):
            mail.send(message())
        configure(MAIL_TRANSPORT="pickup_directory", MAIL_PICKUP_DIRECTORY="/")
        with pytest.raises(mail.MailError) as error:
            mail.send(message(to=""))
        assert "recipient" in str(error.value)


def test_internal_relay_sends_plain_smtp_on_port_25_without_sign_in(app, fake_smtp):
    config, errors = mail.validate_service("smtp_relay", None, {
        "SMTP_HOST": "mailrelay.corp.example.test", "SMTP_FROM": "serviceops@corp.example.test"})
    assert not errors
    with app.app_context():
        token = mail._service_settings.set(mail.service_settings("smtp_relay", config))
        try:
            mail._transmit(message("person@corp.example.test"))
        finally:
            mail._service_settings.reset(token)
    smtp = fake_smtp.instances[0]
    assert (smtp.host, smtp.port) == ("mailrelay.corp.example.test", 25)
    assert smtp.commands == ["ehlo"], "no STARTTLS and no sign-in"
    assert smtp.sent[0]["From"].addresses[0].addr_spec == "serviceops@corp.example.test"
    assert "mailrelay.corp.example.test" in mail.describe_service("smtp_relay", config)
