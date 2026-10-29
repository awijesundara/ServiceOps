"""Outgoing email for every kind of sending environment.

deliver_smtp() in app.py builds a notification's EmailMessage; send() hands
it to whichever transport MAIL_TRANSPORT names:

- smtp: any SMTP server or relay. SMTP_PROVIDER presets fill in the host and
  authentication for Google Workspace, Microsoft 365, Amazon SES, SendGrid,
  Mailgun, Postmark, Brevo and Zoho; "generic" covers Exchange on-premises,
  Postfix, Sendmail and internal relays. Authentication is none (IP-trusted
  relay), password, Google OAuth2 or Microsoft OAuth2 (XOAUTH2). TLS can trust
  a private CA, and the EHLO name can be set for relays that check it.
- microsoft_graph: Microsoft Graph sendMail with an Entra application
  (client secret or certificate), for tenants where SMTP AUTH is disabled.
  Commercial, US Government (GCC High, DoD) and China (21Vianet) clouds.
- amazon_ses: the SES v2 API, with keys or the pod's IAM role.
- sendgrid / mailgun / postmark: their HTTPS APIs, for networks that block
  outbound SMTP ports.
- sendmail: a local MTA binary (Postfix, Exim, msmtp, ssmtp).
- pickup_directory: writes .eml files for an MTA pickup folder (IIS SMTP,
  Exchange pickup) or for an air-gapped review.

Every HTTP transport and SMTP itself honour the email delivery proxy
(SMTP_PROXY_MODE / SMTP_PROXY_URL). Errors raise MailError, whose `stage`
says where it failed (connect, tls, auth, send), so the test button can show
an administrator something they can act on.
"""
import base64
import contextvars
import os
import smtplib
import socket
import ssl
import subprocess
import threading
import time
import uuid
from email.message import EmailMessage
from email.utils import formataddr, getaddresses, make_msgid, parseaddr

import requests

TRANSPORTS = ("smtp", "microsoft_graph", "amazon_ses", "sendgrid", "mailgun", "postmark", "sendmail", "pickup_directory")
TRANSPORT_LABELS = {
    "smtp": "SMTP server or relay",
    "microsoft_graph": "Microsoft 365 (Graph API)",
    "amazon_ses": "Amazon SES (API)",
    "sendgrid": "SendGrid (API)",
    "mailgun": "Mailgun (API)",
    "postmark": "Postmark (API)",
    "sendmail": "Local sendmail program",
    "pickup_directory": "Pickup directory (.eml files)",
}

# provider -> (host, port, security, auth mode, fixed username)
SMTP_PROVIDERS = {
    "generic": ("", None, None, None, None),
    "google_workspace_relay": ("smtp-relay.gmail.com", None, None, "none", None),
    "google_workspace_app_password": ("smtp.gmail.com", None, None, "password", None),
    "google_workspace_oauth2": ("smtp.gmail.com", None, None, "oauth2", None),
    "microsoft365_oauth2": ("smtp.office365.com", 587, "starttls", "microsoft_oauth2", None),
    "microsoft365_password": ("smtp.office365.com", 587, "starttls", "password", None),
    "microsoft365_relay": ("", 25, "starttls", "none", None),
    "exchange_onprem": ("", None, None, None, None),
    "amazon_ses_smtp": ("{ses}", 587, "starttls", "password", None),
    "sendgrid_smtp": ("smtp.sendgrid.net", 587, "starttls", "password", "apikey"),
    "mailgun_smtp": ("smtp.mailgun.org", 587, "starttls", "password", None),
    "postmark_smtp": ("smtp.postmarkapp.com", 587, "starttls", "password", None),
    "brevo_smtp": ("smtp-relay.brevo.com", 587, "starttls", "password", None),
    "zoho_smtp": ("smtp.zoho.com", 587, "starttls", "password", None),
}
SMTP_PROVIDER_LABELS = {
    "generic": "Generic SMTP server",
    "google_workspace_relay": "Google Workspace SMTP relay (IP allow-list)",
    "google_workspace_app_password": "Gmail / Google Workspace (app password)",
    "google_workspace_oauth2": "Gmail / Google Workspace (OAuth2)",
    "microsoft365_oauth2": "Microsoft 365 SMTP AUTH (OAuth2, app registration)",
    "microsoft365_password": "Microsoft 365 SMTP AUTH (password, legacy)",
    "microsoft365_relay": "Microsoft 365 connector relay (MX endpoint, IP or certificate)",
    "exchange_onprem": "Exchange Server (on-premises)",
    "amazon_ses_smtp": "Amazon SES (SMTP credentials)",
    "sendgrid_smtp": "SendGrid (SMTP)",
    "mailgun_smtp": "Mailgun (SMTP)",
    "postmark_smtp": "Postmark (SMTP)",
    "brevo_smtp": "Brevo (SMTP)",
    "zoho_smtp": "Zoho Mail (SMTP)",
}
AUTH_MODES = ("none", "password", "oauth2", "microsoft_oauth2")
AUTH_MODE_LABELS = {
    "none": "None (relay trusts this server)",
    "password": "Username and password",
    "oauth2": "Google OAuth2",
    "microsoft_oauth2": "Microsoft OAuth2 (app registration)",
}
MICROSOFT_CLOUDS = {
    "global": ("login.microsoftonline.com", "graph.microsoft.com", "outlook.office365.com"),
    "usgov_gcc_high": ("login.microsoftonline.us", "graph.microsoft.us", "outlook.office365.us"),
    "usgov_dod": ("login.microsoftonline.us", "dod-graph.microsoft.us", "outlook-dod.office365.us"),
    "china": ("login.chinacloudapi.cn", "microsoftgraph.chinacloudapi.cn", "partner.outlook.cn"),
}
MICROSOFT_CLOUD_LABELS = {
    "global": "Microsoft 365 (worldwide, including GCC)",
    "usgov_gcc_high": "US Government GCC High",
    "usgov_dod": "US Government DoD",
    "china": "Microsoft 365 operated by 21Vianet (China)",
}


class MailError(RuntimeError):
    """A delivery failure, tagged with the stage that failed. `permanent`
    is True when retrying the same message cannot succeed (a 5xx rejection
    or a configuration problem)."""

    def __init__(self, stage, message, permanent=False):
        super().__init__(message)
        self.stage, self.permanent = stage, permanent


def _core():
    import app as core
    return core


# A saved MailService's settings while it sends (see send_with_service);
# None means the legacy email platform settings.
_service_settings = contextvars.ContextVar("mail_service_settings", default=None)
PRESET = "preset"


def _setting(key, default=""):
    """The sending service's own value, or -- with no service -- the stored
    setting, then the environment variable, then `default`. Never the schema
    default, so a provider preset can fill the gap."""
    override = _service_settings.get()
    if override is not None:
        value = override.get(key)
        value = "" if value is None else str(value)
    else:
        value = _core().setting_value(key, os.getenv(key) or default)
    return default if value in ("", PRESET) else value


def _flag(key, default=False):
    value = _setting(key, "")
    return default if value == "" else value.strip().lower() in {"true", "1", "yes", "on"}


def _proxy_url():
    return _core().resolve_smtp_proxy_url()


def _proxies():
    url = _proxy_url()
    return {"http": url, "https": url} if url else None


def _timeout():
    return _core().setting_int("SMTP_TIMEOUT_SECONDS", 10)


def sender_address():
    return _setting("SMTP_FROM", "") or _setting("MS_SENDER_MAILBOX", "")


def ensure_headers(message):
    """Headers every transport needs. Message-ID is set here rather than
    by the server so the same ID is logged and reused on retry."""
    if not message["Message-ID"]:
        domain = (parseaddr(str(message["From"] or ""))[1].rpartition("@")[2] or "serviceops.invalid")
        message["Message-ID"] = make_msgid(domain=domain)
    if not message["X-Auto-Response-Suppress"]:
        # Out-of-office replies would otherwise loop back into inbound mail ingestion.
        message["X-Auto-Response-Suppress"] = "All"
    return message


def recipients_of(message):
    fields = [str(value) for name in ("To", "Cc", "Bcc") for value in (message.get_all(name) or [])]
    return [address for _, address in getaddresses(fields) if address]


def _transmit(message):
    """Sends with whatever settings are active: a service's or the legacy ones."""
    transport = _setting("MAIL_TRANSPORT", "smtp") or "smtp"
    handler = {
        "smtp": send_smtp, "microsoft_graph": send_microsoft_graph, "amazon_ses": send_amazon_ses,
        "sendgrid": send_sendgrid, "mailgun": send_mailgun, "postmark": send_postmark,
        "sendmail": send_sendmail, "pickup_directory": send_pickup_directory,
    }.get(transport)
    if handler is None:
        raise MailError("config", f"Unknown email transport {transport!r}.", permanent=True)
    sender = sender_address()
    if sender:
        # Each service sends as its own verified sender.
        name = _setting("SMTP_FROM_NAME", "") or (parseaddr(str(message["From"] or ""))[0]) or "ServiceOps"
        del message["From"]
        message["From"] = formataddr((name, sender))
        # The service's own reply-to, or none: never one left over from
        # the platform settings or another service.
        reply_to = _setting("SMTP_REPLY_TO", "")
        del message["Reply-To"]
        if reply_to:
            message["Reply-To"] = reply_to
    if not parseaddr(str(message["From"] or ""))[1]:
        raise MailError("config", "Set the from address for this email service.", permanent=True)
    if not recipients_of(message):
        raise MailError("config", "The message has no recipient.", permanent=True)
    ensure_headers(message)
    try:
        handler(message)
    except MailError:
        raise
    except requests.HTTPError as error:
        status = error.response.status_code if error.response is not None else 0
        detail = _http_error_detail(error.response)
        raise MailError("send", f"{TRANSPORT_LABELS[transport]} refused the message (HTTP {status}){detail}",
                        permanent=400 <= status < 500 and status not in (408, 429)) from error
    except requests.RequestException as error:
        raise MailError("connect", f"Could not reach {TRANSPORT_LABELS[transport]}: {error}") from error
    return transport


def send_with_service(message, service):
    """Sends with one saved MailService and records the outcome on it."""
    from serviceops_models import now
    token = _service_settings.set(service_settings(service.provider, service.config))
    try:
        _transmit(message)
    except MailError as error:
        service.last_error = f"{error.stage}: {error}"[:600]
        raise
    finally:
        _service_settings.reset(token)
    service.last_used_at, service.last_error = now(), None
    return service


def active_services():
    """(default, fallback) saved services; (None, None) when none are saved."""
    from serviceops_models import MailService
    rows = MailService.query.filter((MailService.is_default.is_(True)) | (MailService.is_fallback.is_(True))).all()
    default = next((row for row in rows if row.is_default), None)
    fallback = next((row for row in rows if row.is_fallback and row is not default), None)
    return default, fallback


def send(message):
    """Sends `message` with the default email service, then the fallback if
    the default fails. With no saved service, uses the email platform
    settings (installations configured before services existed). Returns a
    description of what sent it; raises MailError when nothing could."""
    from serviceops_models import MailService
    default, fallback = active_services()
    if default is None and fallback is None:
        if MailService.query.first() is not None or _core().setting_bool("MAIL_SERVICES_ACTIVE"):
            raise MailError("config", "No email service is set as the default.", permanent=True)
        return _transmit(message)
    errors = []
    for service in (default, fallback):
        if service is None:
            continue
        try:
            send_with_service(message, service)
            return service.name
        except MailError as error:
            errors.append(error)
    if len(errors) == 1:
        raise errors[0]
    first, last = errors
    raise MailError(last.stage, f"Default service failed ({first}); fallback failed ({last})",
                    permanent=first.permanent and last.permanent)


def _http_error_detail(response):
    if response is None:
        return "."
    try:
        text = response.text.strip()
    except Exception:  # noqa: BLE001 - detail is best effort
        return "."
    return f": {text[:300]}" if text else "."


# --- SMTP -----------------------------------------------------------------

def looks_like_email(value):
    """name@domain.tld, checked without a regular expression so a long
    hostile value cannot cause backtracking."""
    value = str(value or "")
    if len(value) > 254 or any(char.isspace() for char in value) or value.count("@") != 1:
        return False
    local, domain = value.split("@")
    labels = domain.split(".")
    return bool(local) and len(labels) > 1 and all(labels)


def smtp_profile():
    """The effective SMTP connection after applying the provider preset."""
    provider = _setting("SMTP_PROVIDER", "generic") or "generic"
    host, port, security, auth_mode, username = SMTP_PROVIDERS.get(provider, SMTP_PROVIDERS["generic"])
    if host == "{ses}":
        host = f"email-smtp.{_setting('SES_REGION', '') or 'us-east-1'}.amazonaws.com"
    security = _setting("SMTP_SECURITY", "") or security or (
        "starttls" if _flag("SMTP_STARTTLS", True) else "none")
    try:
        configured_port = int(_setting("SMTP_PORT", "0") or 0)
    except ValueError:
        configured_port = 0
    return {
        "provider": provider,
        "host": _setting("SMTP_HOST", "") or host,
        "security": security,
        "port": configured_port or port or (465 if security == "tls" else 587),
        "auth_mode": _setting("SMTP_AUTH_MODE", "") or auth_mode or "password",
        "username": _setting("SMTP_USERNAME", "") or username or "",
    }


def tls_context():
    """Default verification, plus an administrator-supplied private CA
    (Exchange on-premises and internal relays often use one). Turning
    verification off is a last resort and stays explicit."""
    context = ssl.create_default_context()
    ca = _setting("SMTP_CA_CERT", "").replace("\\n", "\n").strip()
    if ca:
        context.load_verify_locations(cadata=ca)
    if _flag("SMTP_TLS_INSECURE"):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def send_smtp(message):
    from serviceops_core.proxy_tunnel import tunnel_through_proxy
    profile = smtp_profile()
    host, port, security = profile["host"], profile["port"], profile["security"]
    if not host:
        raise MailError("config", "SMTP host is required for this email provider.", permanent=True)
    if security not in ("starttls", "tls", "none"):
        raise MailError("config", f"Unknown SMTP security {security!r}.", permanent=True)
    if security == "none" and profile["auth_mode"] != "none":
        raise MailError("config", "SMTP authentication requires STARTTLS or implicit TLS.", permanent=True)
    kwargs = {"timeout": _timeout()}
    local_hostname = _setting("SMTP_LOCAL_HOSTNAME", "")
    if local_hostname:
        kwargs["local_hostname"] = local_hostname
    if security == "tls":
        kwargs["context"] = tls_context()
    smtp_class = smtplib.SMTP_SSL if security == "tls" else smtplib.SMTP
    try:
        with tunnel_through_proxy(_proxy_url()), smtp_class(host, port, **kwargs) as smtp:
            smtp.ehlo()
            if security == "starttls":
                try:
                    smtp.starttls(context=tls_context())
                except (ssl.SSLError, smtplib.SMTPNotSupportedError) as error:
                    raise MailError("tls", f"STARTTLS with {host} failed: {error}", permanent=True) from error
                smtp.ehlo()
            _smtp_authenticate(smtp, profile)
            try:
                refused = smtp.send_message(message)
            except smtplib.SMTPRecipientsRefused as error:
                raise MailError("send", f"{host} refused every recipient: {_smtp_reasons(error.recipients)}",
                                permanent=_all_permanent(error.recipients)) from error
            except smtplib.SMTPSenderRefused as error:
                raise MailError("send", f"{host} refused the sender {error.sender}: {error.smtp_code} "
                                f"{_decode(error.smtp_error)}", permanent=error.smtp_code >= 500) from error
            except smtplib.SMTPDataError as error:
                raise MailError("send", f"{host} rejected the message: {error.smtp_code} {_decode(error.smtp_error)}",
                                permanent=error.smtp_code >= 500) from error
            if refused:
                raise MailError("send", f"{host} refused some recipients: {_smtp_reasons(refused)}",
                                permanent=_all_permanent(refused))
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError as error:
        raise MailError("auth", f"{host} rejected the sign-in: {error.smtp_code} {_decode(error.smtp_error)}",
                        permanent=True) from error
    except ssl.SSLError as error:
        raise MailError("tls", f"TLS with {host}:{port} failed: {error}", permanent=True) from error
    except (socket.timeout, TimeoutError) as error:
        raise MailError("connect", f"Timed out connecting to {host}:{port}.") from error
    except (OSError, smtplib.SMTPException) as error:
        raise MailError("connect", f"Could not deliver through {host}:{port}: {error}") from error


def _decode(value):
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def _smtp_reasons(recipients):
    return "; ".join(f"{address} ({code} {_decode(text)})" for address, (code, text) in recipients.items())[:500]


def _all_permanent(recipients):
    return all(code >= 500 for code, _ in recipients.values())


def _smtp_authenticate(smtp, profile):
    mode, username = profile["auth_mode"], profile["username"]
    if mode == "none":
        return
    if mode == "password":
        if username:
            smtp.login(username, _setting("SMTP_PASSWORD", ""))
        return
    if mode == "oauth2":
        token = _google_smtp_token(username)
    elif mode == "microsoft_oauth2":
        if not username:
            raise MailError("config", "Set SMTP username to the mailbox the app sends as.", permanent=True)
        token = microsoft_token("smtp")
    else:
        raise MailError("config", f"Unknown SMTP authentication {mode!r}.", permanent=True)
    auth = base64.b64encode(f"user={username}\x01auth=Bearer {token}\x01\x01".encode()).decode()
    code, response = smtp.docmd("AUTH", "XOAUTH2 " + auth)
    if code not in {235, 250}:
        raise MailError("auth", f"OAuth2 SMTP authentication failed ({code} {_decode(response)}).", permanent=True)


def _google_smtp_token(username):
    client_id = _setting("SMTP_OAUTH_CLIENT_ID", "")
    client_secret = _setting("SMTP_OAUTH_CLIENT_SECRET", "")
    refresh_token = _setting("SMTP_OAUTH_REFRESH_TOKEN", "")
    if not all((username, client_id, client_secret, refresh_token)):
        raise MailError("config", "Google OAuth username, client ID, client secret and refresh token are required.",
                        permanent=True)
    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={"client_id": client_id, "client_secret": client_secret,
              "refresh_token": refresh_token, "grant_type": "refresh_token"},
        proxies=_proxies(), timeout=_timeout(),
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as error:
        raise MailError("auth", f"Google refused the OAuth refresh token ({error}).", permanent=True) from error
    token = response.json().get("access_token")
    if not token:
        raise MailError("auth", "Google OAuth token response did not include an access token.")
    return token


# --- Microsoft identity platform ------------------------------------------

_ms_tokens = {}
_ms_lock = threading.Lock()


def microsoft_hosts():
    return MICROSOFT_CLOUDS.get(_setting("MS_CLOUD", "global") or "global", MICROSOFT_CLOUDS["global"])


def microsoft_token(audience):
    """An app-only token (client credentials grant) for Graph or for
    Exchange Online SMTP. Authenticates with a certificate when one is
    configured -- what most security teams require -- or a client secret."""
    tenant = _setting("MS_TENANT_ID", "").strip()
    client_id = _setting("MS_CLIENT_ID", "").strip()
    secret = _setting("MS_CLIENT_SECRET", "")
    certificate = _setting("MS_CLIENT_CERTIFICATE", "").replace("\\n", "\n").strip()
    if not tenant or not client_id or not (secret or certificate):
        raise MailError("config", "Microsoft tenant ID, client ID and a client secret or certificate are required.",
                        permanent=True)
    login_host, graph_host, outlook_host = microsoft_hosts()
    scope = f"https://{graph_host}/.default" if audience == "graph" else f"https://{outlook_host}/.default"
    cache_key = (tenant, client_id, scope, bool(certificate))
    with _ms_lock:
        cached = _ms_tokens.get(cache_key)
        if cached and cached[1] > time.monotonic():
            return cached[0]
    token_url = f"https://{login_host}/{tenant}/oauth2/v2.0/token"
    data = {"grant_type": "client_credentials", "client_id": client_id, "scope": scope}
    if certificate:
        data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        data["client_assertion"] = _client_assertion(certificate, client_id, token_url)
    else:
        data["client_secret"] = secret
    response = requests.post(token_url, data=data, proxies=_proxies(), timeout=_timeout())
    if response.status_code >= 400:
        try:
            detail = response.json().get("error_description", "").splitlines()[0]
        except (ValueError, AttributeError, IndexError):
            detail = ""
        raise MailError("auth", f"Microsoft sign-in failed (HTTP {response.status_code}) {detail}".strip(),
                        permanent=response.status_code in (400, 401))
    payload = response.json()
    with _ms_lock:
        _ms_tokens[cache_key] = (payload["access_token"],
                                 time.monotonic() + max(int(payload.get("expires_in", 3600)) - 120, 60))
    return payload["access_token"]


def _client_assertion(pem, client_id, audience):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from joserfc import jwt
    from joserfc.jwk import RSAKey
    data = pem.encode()
    try:
        certificate = x509.load_pem_x509_certificate(data)
        key = serialization.load_pem_private_key(data, password=None)
    except ValueError as error:
        raise MailError("config", "The Microsoft certificate must be one PEM with the private key and the certificate.",
                        permanent=True) from error
    thumbprint = base64.urlsafe_b64encode(certificate.fingerprint(hashes.SHA256())).rstrip(b"=").decode()
    issued = int(time.time())
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    token = jwt.encode(
        {"alg": "PS256", "typ": "JWT", "x5t#S256": thumbprint},
        {"aud": audience, "iss": client_id, "sub": client_id, "jti": str(uuid.uuid4()),
         "nbf": issued, "iat": issued, "exp": issued + 300},
        RSAKey.import_key(key_pem),
        algorithms=["PS256"],
    )
    return token.decode() if isinstance(token, bytes) else token


def send_microsoft_graph(message):
    """POST /users/{mailbox}/sendMail with the raw MIME, so threading and
    custom headers survive unchanged. Needs the Mail.Send application
    permission, ideally limited to this mailbox with an application access
    policy or RBAC for Applications."""
    mailbox = _setting("MS_SENDER_MAILBOX", "") or parseaddr(str(message["From"] or ""))[1]
    if not mailbox:
        raise MailError("config", "Set the Microsoft sender mailbox.", permanent=True)
    _, graph_host, _ = microsoft_hosts()
    response = requests.post(
        f"https://{graph_host}/v1.0/users/{requests.utils.quote(mailbox)}/sendMail",
        data=base64.b64encode(message.as_bytes()),
        headers={"Authorization": f"Bearer {microsoft_token('graph')}", "Content-Type": "text/plain"},
        proxies=_proxies(), timeout=_timeout(),
    )
    if response.status_code == 401:
        with _ms_lock:
            _ms_tokens.clear()
    if response.status_code == 403:
        raise MailError("auth", f"Microsoft Graph denied sending as {mailbox}. Grant the app Mail.Send for that mailbox.",
                        permanent=True)
    response.raise_for_status()


# --- HTTP email APIs ------------------------------------------------------

def _parts(message):
    text = html = None
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() == "text/plain" and text is None:
            text = part.get_content()
        elif part.get_content_type() == "text/html" and html is None:
            html = part.get_content()
    return text, html


_STANDARD_HEADERS = {"from", "to", "cc", "bcc", "subject", "content-type", "content-transfer-encoding",
                     "mime-version", "date", "reply-to"}


def _linked_images(message):
    """{content id: public URL} for inline images that also have a public
    copy, so an email API can link to them instead of attaching them."""
    return {part["Content-ID"].strip().strip("<>"): str(part["X-ServiceOps-Public-URL"])
            for part in message.walk()
            if part.get("Content-ID") and part.get("X-ServiceOps-Public-URL")}


def _link_images(html, linked):
    for content_id, url in linked.items():
        html = html.replace(f"cid:{content_id}", url)
    return html


def _inline_images(message):
    """The images an HTML body shows by cid: (the company logo), as
    (content id without brackets, MIME type, base64 data, filename).
    Images with a public copy are linked instead (see _linked_images)."""
    images = []
    linked = _linked_images(message)
    for part in message.walk():
        content_id = part.get("Content-ID")
        if part.is_multipart() or not content_id or part.get_content_maintype() != "image":
            continue
        if content_id.strip().strip("<>") in linked:
            continue
        data = base64.b64encode(part.get_payload(decode=True) or b"").decode("ascii")
        images.append((content_id.strip().strip("<>"), part.get_content_type(), data,
                       part.get_filename() or "image"))
    return images


def _custom_headers(message):
    return {name: str(value) for name, value in message.items() if name.lower() not in _STANDARD_HEADERS}


def _api_key():
    key = _setting("MAIL_API_KEY", "")
    if not key:
        raise MailError("config", "An API key for the email service is required.", permanent=True)
    return key


def send_sendgrid(message):
    text, html = _parts(message)
    html = _link_images(html, _linked_images(message)) if html else html
    content = [{"type": "text/plain", "value": text or ""}] + ([{"type": "text/html", "value": html}] if html else [])
    sender = parseaddr(str(message["From"]))
    body = {
        "personalizations": [{"to": [{"email": address} for address in recipients_of(message)]}],
        "from": {"email": sender[1], **({"name": sender[0]} if sender[0] else {})},
        "subject": str(message["Subject"] or ""),
        "content": content,
        # SendGrid reserves Message-ID; it threads by its own ID instead.
        "headers": {k: v for k, v in _custom_headers(message).items() if k.lower() != "message-id"},
    }
    images = _inline_images(message)
    if images:
        body["attachments"] = [{"content": data, "type": kind, "filename": name, "disposition": "inline",
                                "content_id": cid} for cid, kind, data, name in images]
    if message["Reply-To"]:
        body["reply_to"] = {"email": parseaddr(str(message["Reply-To"]))[1]}
    requests.post("https://api.sendgrid.com/v3/mail/send", json=body,
                  headers={"Authorization": f"Bearer {_api_key()}"},
                  proxies=_proxies(), timeout=_timeout()).raise_for_status()


def send_mailgun(message):
    domain = _setting("MAILGUN_DOMAIN", "").strip()
    if not domain:
        raise MailError("config", "Mailgun sending domain is required.", permanent=True)
    base = "https://api.eu.mailgun.net" if _setting("MAILGUN_REGION", "us") == "eu" else "https://api.mailgun.net"
    requests.post(f"{base}/v3/{domain}/messages.mime", auth=("api", _api_key()),
                  data={"to": ",".join(recipients_of(message))},
                  files={"message": ("message.eml", message.as_bytes())},
                  proxies=_proxies(), timeout=_timeout()).raise_for_status()


def send_postmark(message):
    text, html = _parts(message)
    html = _link_images(html, _linked_images(message)) if html else html
    body = {
        "From": str(message["From"]), "To": ",".join(recipients_of(message)),
        "Subject": str(message["Subject"] or ""), "TextBody": text or "",
        "Headers": [{"Name": k, "Value": v} for k, v in _custom_headers(message).items()],
        "MessageStream": _setting("POSTMARK_MESSAGE_STREAM", "outbound") or "outbound",
    }
    if html:
        body["HtmlBody"] = html
    images = _inline_images(message)
    if images:
        body["Attachments"] = [{"Name": name, "Content": data, "ContentType": kind, "ContentID": f"cid:{cid}"}
                               for cid, kind, data, name in images]
    if message["Reply-To"]:
        body["ReplyTo"] = str(message["Reply-To"])
    requests.post("https://api.postmarkapp.com/email", json=body,
                  headers={"X-Postmark-Server-Token": _api_key(), "Accept": "application/json"},
                  proxies=_proxies(), timeout=_timeout()).raise_for_status()


def send_amazon_ses(message):
    """SES v2 raw send. With no keys configured, boto3 uses the standard
    credential chain: IRSA / EKS Pod Identity, the instance role, or the
    AWS_* environment variables."""
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError
    region = _setting("SES_REGION", "").strip()
    if not region:
        raise MailError("config", "Amazon SES region is required.", permanent=True)
    proxy = _proxy_url()
    kwargs = {"region_name": region, "config": Config(
        connect_timeout=_timeout(), read_timeout=_timeout(), retries={"max_attempts": 2},
        proxies={"https": proxy} if proxy else None)}
    access_key, secret_key = _setting("SES_ACCESS_KEY_ID", ""), _setting("SES_SECRET_ACCESS_KEY", "")
    if access_key and secret_key:
        kwargs.update(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    request = {"Content": {"Raw": {"Data": message.as_bytes()}},
               "Destination": {"ToAddresses": recipients_of(message)}}
    configuration_set = _setting("SES_CONFIGURATION_SET", "").strip()
    if configuration_set:
        request["ConfigurationSetName"] = configuration_set
    try:
        boto3.client("sesv2", **kwargs).send_email(**request)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        raise MailError("auth" if "Access" in code or "Signature" in code else "send",
                        f"Amazon SES refused the message: {code} {error.response.get('Error', {}).get('Message', '')}",
                        permanent=code not in ("Throttling", "TooManyRequestsException", "LimitExceededException")) from error
    except BotoCoreError as error:
        raise MailError("connect", f"Could not reach Amazon SES: {error}") from error


# --- Local delivery -------------------------------------------------------

SENDMAIL_PROGRAMS = frozenset({"sendmail", "msmtp", "ssmtp", "exim", "exim4", "nullmailer-inject"})


def send_sendmail(message):
    path = _setting("SENDMAIL_PATH", "/usr/sbin/sendmail") or "/usr/sbin/sendmail"
    # Only a mail submission program: this path is set in the web UI, and
    # must never become a way to run any other program on the server.
    if os.path.basename(path) not in SENDMAIL_PROGRAMS:
        raise MailError("config", f"{path} is not a mail program ({', '.join(sorted(SENDMAIL_PROGRAMS))}).",
                        permanent=True)
    if not os.path.isabs(path) or not os.access(path, os.X_OK):
        raise MailError("config", f"{path} is not an executable program on this server.", permanent=True)
    try:
        # -i: a lone "." line is not end of input; -t would trust the headers,
        # so the recipients are passed explicitly instead.
        result = subprocess.run([path, "-i", "--", *recipients_of(message)], input=message.as_bytes(),
                                capture_output=True, timeout=_timeout() * 3, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MailError("connect", f"{path} could not run: {error}") from error
    if result.returncode:
        raise MailError("send", f"{path} exited with {result.returncode}: "
                        f"{result.stderr.decode(errors='replace').strip()[:300]}")


def send_pickup_directory(message):
    directory = _setting("MAIL_PICKUP_DIRECTORY", "").strip()
    if not directory or not os.path.isdir(directory):
        raise MailError("config", "The pickup directory does not exist on this server.", permanent=True)
    name = f"{int(time.time())}-{uuid.uuid4().hex}"
    temporary, final = os.path.join(directory, f".{name}.tmp"), os.path.join(directory, f"{name}.eml")
    try:
        with open(temporary, "wb") as handle:
            handle.write(message.as_bytes())
        os.replace(temporary, final)  # the MTA never sees a half-written file
    except OSError as error:
        raise MailError("send", f"Could not write to the pickup directory: {error}") from error


# --- Saved services -------------------------------------------------------
#
# Each provider asks only for its own fields. A field's `key` is the setting
# name the transports read, so a service is just a set of those settings.
# `methods` limits a field to some of the provider's methods.

def _f(key, label, kind="text", required=False, methods=None, help="", placeholder="", choices=None, default=""):
    return {"key": key, "label": label, "type": kind, "required": required, "methods": methods,
            "help": help, "placeholder": placeholder, "choices": choices, "default": default}


SENDER_FIELDS = [
    _f("SMTP_FROM", "From address", "email", True, help="The address recipients see. It must be verified or allowed by the provider.",
       placeholder="servicedesk@example.com"),
    _f("SMTP_FROM_NAME", "Sender name", placeholder="IT Service Desk"),
    _f("SMTP_REPLY_TO", "Reply-to address", "email", help="Optional. Where replies go, for example a support mailbox."),
]
_MS_APP = [
    _f("MS_CLOUD", "Microsoft cloud", "choice", choices=MICROSOFT_CLOUD_LABELS, default="global", methods=["graph", "smtp_oauth"]),
    _f("MS_TENANT_ID", "Directory (tenant) ID", required=True, methods=["graph", "smtp_oauth"],
       placeholder="00000000-0000-0000-0000-000000000000"),
    _f("MS_CLIENT_ID", "Application (client) ID", required=True, methods=["graph", "smtp_oauth"]),
    _f("MS_CLIENT_SECRET", "Client secret", "secret", methods=["graph", "smtp_oauth"],
       help="Or use a certificate below. One of the two is required."),
    _f("MS_CLIENT_CERTIFICATE", "Client certificate", "secret_textarea", methods=["graph", "smtp_oauth"],
       help="PEM with the private key and the certificate. Used instead of the secret."),
]
PROVIDERS = {
    "sendgrid": {
        "label": "SendGrid", "icon": "SG", "summary": "Twilio SendGrid over its HTTPS API.",
        "transport": "sendgrid",
        "fields": [_f("MAIL_API_KEY", "API key", "secret", True, help="Create one with only the Mail Send permission.",
                      placeholder="SG.…")],
    },
    "microsoft365": {
        "label": "Microsoft 365", "icon": "M365", "summary": "Exchange Online through Microsoft Graph, SMTP OAuth2 or a connector.",
        "methods": {
            "graph": ("Microsoft Graph API (recommended)", {"MAIL_TRANSPORT": "microsoft_graph"}),
            "smtp_oauth": ("SMTP with OAuth2", {"MAIL_TRANSPORT": "smtp", "SMTP_PROVIDER": "microsoft365_oauth2"}),
            "relay": ("Connector relay (no sign-in)", {"MAIL_TRANSPORT": "smtp", "SMTP_PROVIDER": "microsoft365_relay"}),
        },
        "fields": [
            *_MS_APP,
            _f("MS_SENDER_MAILBOX", "Mailbox to send as", "email", True, methods=["graph"],
               help="The app needs the Mail.Send application permission for this mailbox."),
            _f("SMTP_USERNAME", "Mailbox to send as", "email", True, methods=["smtp_oauth"],
               help="The app needs SMTP.SendAsApp and a service principal with access to this mailbox."),
            _f("SMTP_HOST", "Your MX endpoint", required=True, methods=["relay"],
               placeholder="contoso-com.mail.protection.outlook.com",
               help="The connector must trust this server's public IP address or certificate."),
        ],
    },
    "google": {
        "label": "Google Workspace", "icon": "G", "summary": "Gmail or Google Workspace by relay, app password or OAuth2.",
        "methods": {
            "relay": ("SMTP relay service (IP allow-list)", {"MAIL_TRANSPORT": "smtp", "SMTP_PROVIDER": "google_workspace_relay"}),
            "app_password": ("App password", {"MAIL_TRANSPORT": "smtp", "SMTP_PROVIDER": "google_workspace_app_password"}),
            "oauth2": ("OAuth2", {"MAIL_TRANSPORT": "smtp", "SMTP_PROVIDER": "google_workspace_oauth2"}),
        },
        "fields": [
            _f("SMTP_USERNAME", "Google account", "email", True, methods=["app_password", "oauth2"]),
            _f("SMTP_PASSWORD", "App password", "secret", True, methods=["app_password"]),
            _f("SMTP_OAUTH_CLIENT_ID", "OAuth client ID", required=True, methods=["oauth2"]),
            _f("SMTP_OAUTH_CLIENT_SECRET", "OAuth client secret", "secret", True, methods=["oauth2"]),
            _f("SMTP_OAUTH_REFRESH_TOKEN", "OAuth refresh token", "secret", True, methods=["oauth2"]),
        ],
    },
    "amazon_ses": {
        "label": "Amazon SES", "icon": "SES", "summary": "The SES v2 API with access keys or the server's IAM role.",
        "transport": "amazon_ses",
        "fields": [
            _f("SES_REGION", "Region", required=True, placeholder="eu-west-1"),
            _f("SES_ACCESS_KEY_ID", "Access key ID", help="Leave both keys blank to use the pod or instance IAM role."),
            _f("SES_SECRET_ACCESS_KEY", "Secret access key", "secret"),
            _f("SES_CONFIGURATION_SET", "Configuration set", help="Optional. For SES event publishing."),
        ],
    },
    "mailgun": {
        "label": "Mailgun", "icon": "MG", "summary": "Mailgun over its HTTPS API.", "transport": "mailgun",
        "fields": [
            _f("MAIL_API_KEY", "API key", "secret", True),
            _f("MAILGUN_DOMAIN", "Sending domain", required=True, placeholder="mg.example.com"),
            _f("MAILGUN_REGION", "Region", "choice", choices={"us": "US", "eu": "EU"}, default="us"),
        ],
    },
    "postmark": {
        "label": "Postmark", "icon": "PM", "summary": "Postmark over its HTTPS API.", "transport": "postmark",
        "fields": [
            _f("MAIL_API_KEY", "Server API token", "secret", True),
            _f("POSTMARK_MESSAGE_STREAM", "Message stream", default="outbound"),
        ],
    },
    "smtp": {
        "label": "SMTP server", "icon": "SMTP",
        "summary": "Exchange Server, Postfix, Brevo, Zoho or any other SMTP server or relay.",
        "transport": "smtp", "fixed": {"SMTP_PROVIDER": "generic"},
        "fields": [
            _f("SMTP_HOST", "Server", required=True, placeholder="smtp.example.com"),
            _f("SMTP_PORT", "Port", "int", default="587", help="587 for STARTTLS, 465 for implicit TLS, 25 for an internal relay."),
            _f("SMTP_SECURITY", "Encryption", "choice", default="starttls",
               choices={"starttls": "STARTTLS", "tls": "Implicit TLS (SMTPS)", "none": "None (internal relay only)"}),
            _f("SMTP_AUTH_MODE", "Sign-in", "choice", default="password",
               choices={"password": "Username and password", "none": "None (the relay trusts this server)"}),
            _f("SMTP_USERNAME", "Username"),
            _f("SMTP_PASSWORD", "Password", "secret"),
            _f("SMTP_LOCAL_HOSTNAME", "EHLO name", help="Optional. Some relays only accept a known host name."),
            _f("SMTP_CA_CERT", "Trusted CA certificate", "textarea",
               help="Optional. PEM of the CA that issued the server's certificate, for internal CAs."),
            _f("SMTP_TLS_INSECURE", "Skip certificate verification (insecure, last resort)", "bool"),
        ],
    },
    "smtp_relay": {
        "label": "Internal SMTP relay", "icon": "RLY",
        "summary": "A company mail relay that accepts mail from this server's IP address, with no sign-in (port 25).",
        "transport": "smtp", "fixed": {"SMTP_PROVIDER": "generic", "SMTP_AUTH_MODE": "none"},
        "fields": [
            _f("SMTP_HOST", "Relay server", required=True, placeholder="mailrelay.corp.example.com",
               help="Host name or IP address. This server's outgoing IP address must be allowed on the relay."),
            _f("SMTP_PORT", "Port", "int", default="25"),
            _f("SMTP_SECURITY", "Encryption", "choice", default="none",
               choices={"none": "None (plain SMTP on the internal network)", "starttls": "STARTTLS (the relay must support it)"}),
            _f("SMTP_LOCAL_HOSTNAME", "EHLO name", help="Optional. Some relays only accept a known host name."),
            _f("SMTP_CA_CERT", "Trusted CA certificate", "textarea",
               help="Optional, with STARTTLS. PEM of the CA that issued the relay's certificate."),
        ],
    },
    "sendmail": {
        "label": "Local sendmail", "icon": "MTA", "summary": "A mail program on this server: Postfix, Exim or msmtp.",
        "transport": "sendmail",
        "fields": [_f("SENDMAIL_PATH", "Program", default="/usr/sbin/sendmail", required=True)],
    },
    "pickup_directory": {
        "label": "Pickup directory", "icon": "EML", "summary": "Writes .eml files for an MTA pickup folder or offline review.",
        "transport": "pickup_directory",
        "fields": [_f("MAIL_PICKUP_DIRECTORY", "Directory", required=True, placeholder="/var/spool/serviceops-mail")],
    },
}


def provider_fields(provider):
    spec = PROVIDERS[provider]
    return [*spec["fields"], *SENDER_FIELDS]


def service_settings(provider, config):
    """The settings the transports read, for a saved service."""
    spec = PROVIDERS.get(provider)
    if spec is None:
        raise MailError("config", f"Unknown email provider {provider!r}.", permanent=True)
    method = config.get("method") or (next(iter(spec["methods"])) if spec.get("methods") else None)
    settings = {"MAIL_TRANSPORT": spec.get("transport", "smtp"), **spec.get("fixed", {})}
    if spec.get("methods"):
        settings.update(spec["methods"].get(method, next(iter(spec["methods"].values())))[1])
    for field in provider_fields(provider):
        if field["methods"] and method not in field["methods"]:
            continue
        settings[field["key"]] = config.get(field["key"], field["default"])
    return settings


def validate_service(provider, method, submitted, existing=None):
    """Returns (config, errors) from a submitted form. Blank secrets keep
    their saved value."""
    spec = PROVIDERS[provider]
    existing = existing or {}
    config, errors = {}, []
    if spec.get("methods"):
        if method not in spec["methods"]:
            method = next(iter(spec["methods"]))
        config["method"] = method
    for field in provider_fields(provider):
        if field["methods"] and method not in field["methods"]:
            continue
        key, kind = field["key"], field["type"]
        value = submitted.get(key)
        if kind == "bool":
            config[key] = "true" if value else "false"
            continue
        value = (value or "").strip()
        if kind in ("secret", "secret_textarea") and not value:
            # Blank keeps the saved secret; "remove" clears an optional one.
            value = "" if submitted.get(f"clear_{key}") and not field["required"] else existing.get(key, "")
        if kind == "choice" and value and value not in field["choices"]:
            errors.append(f"{field['label']} has an invalid value.")
            continue
        if kind == "int" and value:
            if not value.isdigit() or not 0 < int(value) < 65536:
                errors.append(f"{field['label']} must be between 1 and 65535.")
                continue
        if kind == "email" and value and not looks_like_email(value):
            errors.append(f"{field['label']} must be an email address.")
            continue
        if field["required"] and not value:
            errors.append(f"{field['label']} is required.")
            continue
        if value:
            config[key] = value[:8000]
    if provider in ("microsoft365",) and method in ("graph", "smtp_oauth") and not (
            config.get("MS_CLIENT_SECRET") or config.get("MS_CLIENT_CERTIFICATE")):
        errors.append("Enter a client secret or a client certificate.")
    if provider == "amazon_ses" and bool(config.get("SES_ACCESS_KEY_ID")) != bool(config.get("SES_SECRET_ACCESS_KEY")):
        errors.append("Enter both the access key ID and the secret access key, or neither.")
    if provider == "smtp" and config.get("SMTP_SECURITY") == "none" and config.get("SMTP_AUTH_MODE") != "none":
        errors.append("Sign-in needs encryption. Choose STARTTLS or implicit TLS, or no sign-in.")
    return config, errors


def describe_service(provider, config):
    """One line for the service list: what it connects to, without secrets."""
    spec = PROVIDERS.get(provider, {})
    method = config.get("method")
    parts = []
    if spec.get("methods") and method in spec["methods"]:
        parts.append(spec["methods"][method][0])
    for key in ("SMTP_HOST", "MAILGUN_DOMAIN", "SES_REGION", "MS_SENDER_MAILBOX", "SENDMAIL_PATH", "MAIL_PICKUP_DIRECTORY"):
        if config.get(key) and (key != "SMTP_HOST" or provider != "microsoft365" or method == "relay"):
            parts.append(config[key])
    if config.get("SMTP_FROM"):
        parts.append(f"from {config['SMTP_FROM']}")
    return " · ".join(parts)


def legacy_service_config():
    """The email platform settings as a saved service, so an installation
    configured before services existed keeps working when it moves over.
    Returns (provider, config) or None when nothing usable is configured."""
    transport = _setting("MAIL_TRANSPORT", "smtp") or "smtp"
    provider_by_transport = {"microsoft_graph": "microsoft365", "amazon_ses": "amazon_ses", "sendgrid": "sendgrid",
                             "mailgun": "mailgun", "postmark": "postmark", "sendmail": "sendmail",
                             "pickup_directory": "pickup_directory"}
    provider, config = provider_by_transport.get(transport), {}
    if provider == "microsoft365":
        config["method"] = "graph"
    elif transport == "smtp":
        preset = _setting("SMTP_PROVIDER", "generic")
        mapping = {"google_workspace_relay": ("google", "relay"), "google_workspace_app_password": ("google", "app_password"),
                   "google_workspace_oauth2": ("google", "oauth2"), "microsoft365_oauth2": ("microsoft365", "smtp_oauth"),
                   "microsoft365_relay": ("microsoft365", "relay")}
        provider, method = mapping.get(preset, ("smtp", None))
        if provider != "smtp":
            # A branded service always uses its provider's connection, so a
            # preset with its host, port or security overridden (for example
            # Gmail on 465 with implicit TLS) moves over as a generic SMTP
            # service instead -- unless it signs in with OAuth, which only
            # the branded service can do.
            preset_host, preset_port, preset_security, _, _ = SMTP_PROVIDERS.get(preset, SMTP_PROVIDERS["generic"])
            profile = smtp_profile()
            overridden = (profile["host"] != preset_host or profile["port"] != (preset_port or 587)
                          or profile["security"] != (preset_security or "starttls"))
            if overridden and profile["auth_mode"] in ("password", "none"):
                provider, method = "smtp", None
        if method:
            config["method"] = method
        if provider == "smtp":
            profile = smtp_profile()
            if not profile["host"]:
                return None
            config.update(SMTP_HOST=profile["host"], SMTP_PORT=str(profile["port"]), SMTP_SECURITY=profile["security"],
                          SMTP_AUTH_MODE="none" if profile["auth_mode"] == "none" else "password")
    if provider is None:
        return None
    for field in provider_fields(provider):
        if field["key"] in config:
            continue
        if field["methods"] and config.get("method") not in field["methods"]:
            continue
        value = _setting(field["key"], "")
        if value:
            config[field["key"]] = value
    if not config.get("SMTP_FROM"):
        return None
    return provider, config


# --- Test -----------------------------------------------------------------

def test_message(recipient, instance_name="ServiceOps", service_name=""):
    from serviceops_core.email_render import render_email
    message = EmailMessage()
    if sender_address():
        message["From"] = formataddr((_setting("SMTP_FROM_NAME", "ServiceOps") or "ServiceOps", sender_address()))
    message["To"] = recipient
    message["Subject"] = f"{instance_name} test email"
    message["Auto-Submitted"] = "auto-generated"
    render_email(
        message, title="Email delivery is working",
        body=(f"This test came from {instance_name} through {service_name or 'the configured email service'}.\n\n"
              "Notifications about tickets, approvals and SLAs will look like this."),
        eyebrow="Test email", reason="An administrator sent this test from the email delivery settings.",
    )
    return message


def describe():
    """A one-line summary of the legacy configuration."""
    transport = _setting("MAIL_TRANSPORT", "smtp") or "smtp"
    if transport == "smtp":
        profile = smtp_profile()
        return (f"SMTP {profile['host'] or '(no host)'}:{profile['port']} · {profile['security']} · "
                f"{AUTH_MODE_LABELS.get(profile['auth_mode'], profile['auth_mode'])}")
    return TRANSPORT_LABELS.get(transport, transport)


__all__ = ["MailError", "PROVIDERS", "send", "send_with_service", "test_message", "describe"]
