"""Browser Web Push (desktop notifications with the tab closed).

Implemented with the `cryptography` package already used by ServiceOps, so
no new dependency: VAPID application-server authentication (RFC 8292) and
aes128gcm payload encryption (RFC 8291 / RFC 8188). The payload reaches the
browser vendor's push service (Google, Mozilla, Apple, Microsoft) encrypted
end to end; only the browser can read it.

On by default (WEB_PUSH_ENABLED; administrators can turn it off). The VAPID key pair is
created on first use and stored encrypted like other secrets.
"""
import base64
import json
import os
import struct
import time
from urllib.parse import urlsplit

from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PRIVATE_KEY_SETTING = "WEB_PUSH_VAPID_PRIVATE_KEY"
RECORD_SIZE = 4096

# Push services browsers use. Subscriptions pointing anywhere else are
# refused: the worker would otherwise POST to an address a browser supplied.
PUSH_SERVICE_SUFFIXES = (
    "fcm.googleapis.com", "android.googleapis.com", "push.services.mozilla.com",
    "push.apple.com", "notify.windows.com",
)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text):
    text = str(text or "")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def endpoint_allowed(endpoint):
    try:
        parts = urlsplit(str(endpoint or ""))
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return (parts.scheme == "https" and not parts.username and not parts.password and len(str(endpoint)) <= 1000
            and any(host == suffix or host.endswith("." + suffix) for suffix in PUSH_SERVICE_SUFFIXES))


def _hkdf(salt, ikm, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def encrypt(payload, p256dh, auth, *, server_key=None, salt=None):
    """aes128gcm body for one subscription (RFC 8291 section 3.4). The
    optional server_key/salt exist for the RFC's test vector."""
    user_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
    server_key = server_key or ec.generate_private_key(ec.SECP256R1())
    server_public = server_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    salt = salt or os.urandom(16)
    shared = server_key.exchange(ec.ECDH(), user_public)
    ikm = _hkdf(auth, shared, b"WebPush: info\x00" + p256dh + server_public, 32)
    key = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    if len(payload) > RECORD_SIZE - 17 - 86:
        raise ValueError("Push payload too large")
    ciphertext = AESGCM(key).encrypt(nonce, payload + b"\x02", None)
    header = salt + struct.pack("!IB", RECORD_SIZE, len(server_public)) + server_public
    return header + ciphertext


def _vapid_private_key():
    import app as core
    from serviceops_models import PlatformSetting, db, settings_cipher
    stored = core.setting_value(PRIVATE_KEY_SETTING, "")
    if stored:
        return serialization.load_pem_private_key(stored.encode(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    row = db.session.get(PlatformSetting, PRIVATE_KEY_SETTING)
    if row is not None and row.value:
        # Another worker created it first: browsers may already hold that key.
        return serialization.load_pem_private_key(
            settings_cipher().decrypt(row.value.encode()), password=None)
    if row is None:
        row = PlatformSetting(key=PRIVATE_KEY_SETTING, tenant_id=1, encrypted=True)
        db.session.add(row)
    row.encrypted = True
    row.value = settings_cipher().encrypt(pem.encode()).decode()
    try:
        with db.session.begin_nested():
            db.session.flush()
    except IntegrityError:
        # Lost the race to create it: use the winner's key, never replace it.
        db.session.expire_all()
        row = db.session.get(PlatformSetting, PRIVATE_KEY_SETTING)
        return serialization.load_pem_private_key(
            settings_cipher().decrypt(row.value.encode()), password=None)
    return key


def public_key():
    """The application server key the browser subscribes with (base64url)."""
    point = _vapid_private_key().public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return b64url(point)


def vapid_authorization(endpoint, contact, key=None):
    key = key or _vapid_private_key()
    parts = urlsplit(endpoint)
    header = b64url(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = b64url(json.dumps({"aud": f"{parts.scheme}://{parts.netloc}", "exp": int(time.time()) + 12 * 3600,
                                "sub": contact}, separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    token = f"{header}.{claims}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return f"vapid t={token}, k={b64url(point)}"


def deliver(event):
    """Send one notification.created outbox event to the recipient's browser
    subscriptions. Returns how many were delivered; gone subscriptions
    (404/410) are removed; other failures raise so the outbox retries."""
    import httpx
    import app as core
    from serviceops_models import WebPushSubscription, db, now, settings_cipher
    if event.event_type != "notification.created" or not core.setting_bool("WEB_PUSH_ENABLED", True):
        return 0
    payload = event.payload
    subscriptions = WebPushSubscription.query.filter_by(
        tenant_id=event.tenant_id, user_id=payload.get("user_id"),
    ).all()
    if not subscriptions:
        return 0
    from serviceops_core.public_url import public_origin
    url = core.notification_target_url(payload.get("target_type"), payload.get("target_id")) if (
        payload.get("target_type")) else None
    body = json.dumps({
        "title": (payload.get("title") or "ServiceOps")[:120],
        "body": (payload.get("body") or "")[:300],
        "url": (public_origin() or "") + (url or "/notifications"),
        "tag": f"notification-{payload.get('notification_id')}",
    }).encode()
    contact = core.setting_value("WEB_PUSH_CONTACT", "") or core.setting_value("SUPPORT_EMAIL", "")
    if not contact:
        # Push services (Apple's in particular) reject a placeholder subject; the
        # public https address identifies this server when no email is configured.
        origin = public_origin() or ""
        contact = origin if origin.startswith("https:") else "mailto:admin@localhost"
    contact = contact if contact.startswith(("mailto:", "https:")) else f"mailto:{contact}"
    key = _vapid_private_key()
    delivered, failures = 0, []
    proxy_url = core.resolve_component_proxy_url("WEB_PUSH") if hasattr(core, "resolve_component_proxy_url") else None
    with httpx.Client(timeout=10.0, proxy=proxy_url, trust_env=False) as client:
        for subscription in subscriptions:
            if not endpoint_allowed(subscription.endpoint):
                db.session.delete(subscription)
                continue
            keys = json.loads(settings_cipher().decrypt(subscription.keys_encrypted.encode()).decode())
            message = encrypt(body, b64url_decode(keys["p256dh"]), b64url_decode(keys["auth"]))
            response = client.post(subscription.endpoint, content=message, headers={
                "Authorization": vapid_authorization(subscription.endpoint, contact, key),
                "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
                "TTL": "86400", "Urgency": "normal",
            })
            if response.status_code in (200, 201, 202):
                delivered += 1
                subscription.last_used_at = now()
            elif response.status_code in (404, 410):
                db.session.delete(subscription)
            else:
                failures.append(f"{urlsplit(subscription.endpoint).hostname}: HTTP {response.status_code}")
    if failures and not delivered:
        raise RuntimeError("; ".join(failures)[:900])
    return delivered
