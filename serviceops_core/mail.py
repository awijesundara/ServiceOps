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
import os
import smtplib
import socket
import ssl
import subprocess
import threading
import time
import uuid
from email.message import EmailMessage
from email.utils import getaddresses, make_msgid, parseaddr

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


def _setting(key, default=""):
    """Stored setting, then the environment variable, then `default` --
    never the schema default, so a provider preset can fill the gap."""
    value = _core().setting_value(key, os.getenv(key) or default)
    return default if value == PRESET else value


PRESET = "preset"


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


def send(message):
    """Sends `message` with the configured transport. Returns the transport
    name; raises MailError on any failure."""
    ensure_headers(message)
    transport = _setting("MAIL_TRANSPORT", "smtp") or "smtp"
    handler = {
        "smtp": send_smtp, "microsoft_graph": send_microsoft_graph, "amazon_ses": send_amazon_ses,
        "sendgrid": send_sendgrid, "mailgun": send_mailgun, "postmark": send_postmark,
        "sendmail": send_sendmail, "pickup_directory": send_pickup_directory,
    }.get(transport)
    if handler is None:
        raise MailError("config", f"Unknown email transport {transport!r}.", permanent=True)
    if not recipients_of(message):
        raise MailError("config", "The message has no recipient.", permanent=True)
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


def _http_error_detail(response):
    if response is None:
        return "."
    try:
        text = response.text.strip()
    except Exception:  # noqa: BLE001 - detail is best effort
        return "."
    return f": {text[:300]}" if text else "."


# --- SMTP -----------------------------------------------------------------

def smtp_profile():
    """The effective SMTP connection after applying the provider preset."""
    provider = _setting("SMTP_PROVIDER", "generic") or "generic"
    host, port, security, auth_mode, username = SMTP_PROVIDERS.get(provider, SMTP_PROVIDERS["generic"])
    if host == "{ses}":
        host = f"email-smtp.{_setting('SES_REGION', '') or 'us-east-1'}.amazonaws.com"
    core = _core()
    security = _setting("SMTP_SECURITY", "") or security or (
        "starttls" if core.setting_bool("SMTP_STARTTLS", True) else "none")
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
    if _core().setting_bool("SMTP_TLS_INSECURE"):
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


def _custom_headers(message):
    return {name: str(value) for name, value in message.items() if name.lower() not in _STANDARD_HEADERS}


def _api_key():
    key = _setting("MAIL_API_KEY", "")
    if not key:
        raise MailError("config", "An API key for the email service is required.", permanent=True)
    return key


def send_sendgrid(message):
    text, html = _parts(message)
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
    body = {
        "From": str(message["From"]), "To": ",".join(recipients_of(message)),
        "Subject": str(message["Subject"] or ""), "TextBody": text or "",
        "Headers": [{"Name": k, "Value": v} for k, v in _custom_headers(message).items()],
        "MessageStream": _setting("POSTMARK_MESSAGE_STREAM", "outbound") or "outbound",
    }
    if html:
        body["HtmlBody"] = html
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

def send_sendmail(message):
    path = _setting("SENDMAIL_PATH", "/usr/sbin/sendmail") or "/usr/sbin/sendmail"
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


# --- Test -----------------------------------------------------------------

def test_message(recipient, instance_name="ServiceOps"):
    message = EmailMessage()
    sender = sender_address()
    if not sender:
        raise MailError("config", "Set the from address before sending a test email.", permanent=True)
    from email.utils import formataddr
    message["From"] = formataddr((_setting("SMTP_FROM_NAME", "ServiceOps") or "ServiceOps", sender))
    message["To"] = recipient
    message["Subject"] = f"{instance_name} test email"
    message["Auto-Submitted"] = "auto-generated"
    reply_to = _setting("SMTP_REPLY_TO", "")
    if reply_to:
        message["Reply-To"] = reply_to
    transport = _setting("MAIL_TRANSPORT", "smtp") or "smtp"
    message.set_content(
        f"This is a test email from {instance_name}.\n\n"
        f"Transport: {TRANSPORT_LABELS.get(transport, transport)}\n"
        "If you can read this, email notifications are working.\n")
    return message


def describe():
    """A one-line summary of the active configuration for the admin page."""
    transport = _setting("MAIL_TRANSPORT", "smtp") or "smtp"
    if transport == "smtp":
        profile = smtp_profile()
        return (f"SMTP {profile['host'] or '(no host)'}:{profile['port']} · {profile['security']} · "
                f"{AUTH_MODE_LABELS.get(profile['auth_mode'], profile['auth_mode'])}")
    return TRANSPORT_LABELS.get(transport, transport)


__all__ = ["MailError", "send", "test_message", "describe"]
