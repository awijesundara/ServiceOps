"""Browser Web Push: RFC 8291 encryption (published test vector and a
round trip), VAPID signatures, subscription endpoints and outbox delivery."""
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app import (IntegrationDelivery, OutboxEvent, PlatformSetting, User, create_notification, db,
                 process_outbox)
from serviceops_core import webpush
from serviceops_core.webpush import b64url, b64url_decode
from serviceops_models import WebPushSubscription
from tests.test_app import app, client, login  # noqa: F401

# RFC 8291 Appendix A.
RFC = {
    "plaintext": "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24",
    "as_private": "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
    "ua_public": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    "auth": "BTBZMqHH6r4Tts7J_aSIgg",
    "salt": "DGv6ra1nlYgDCS1FRnbzlw",
    "result": ("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC"
               "8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"),
}


def test_encryption_matches_the_rfc_8291_test_vector():
    server_key = ec.derive_private_key(int.from_bytes(b64url_decode(RFC["as_private"]), "big"), ec.SECP256R1())
    body = webpush.encrypt(b64url_decode(RFC["plaintext"]), b64url_decode(RFC["ua_public"]),
                           b64url_decode(RFC["auth"]), server_key=server_key, salt=b64url_decode(RFC["salt"]))
    assert b64url(body) == RFC["result"]


def _decrypt(body, ua_key, auth):
    salt, record_size, id_len = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    server_public = body[21:21 + id_len]
    ciphertext = body[21 + id_len:]
    ua_public = ua_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    shared = ua_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public))
    hkdf = lambda salt_, ikm, info, n: HKDF(hashes.SHA256(), n, salt_, info).derive(ikm)  # noqa: E731
    ikm = hkdf(auth, shared, b"WebPush: info\x00" + ua_public + server_public, 32)
    plain = AESGCM(hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)).decrypt(
        hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12), ciphertext, None)
    assert record_size == 4096 and plain.endswith(b"\x02")
    return plain[:-1]


def test_encryption_round_trips_for_a_fresh_browser_key():
    ua_key, auth = ec.generate_private_key(ec.SECP256R1()), b"0123456789abcdef"
    ua_public = ua_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert _decrypt(webpush.encrypt(b'{"title":"Hi"}', ua_public, auth), ua_key, auth) == b'{"title":"Hi"}'


def test_vapid_header_is_a_valid_es256_token():
    key = ec.generate_private_key(ec.SECP256R1())
    value = webpush.vapid_authorization("https://fcm.googleapis.com/fcm/send/abc", "mailto:ops@example.com", key)
    token, public = value.removeprefix("vapid t=").split(", k=")
    header, claims, signature = token.split(".")
    assert json.loads(b64url_decode(claims))["aud"] == "https://fcm.googleapis.com"
    raw = b64url_decode(signature)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64url_decode(public)).verify(
        der, f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("endpoint,allowed", [
    ("https://fcm.googleapis.com/fcm/send/x", True),
    ("https://updates.push.services.mozilla.com/wpush/v2/x", True),
    ("https://web.push.apple.com/x", True),
    ("http://fcm.googleapis.com/x", False),
    ("https://evil.example/x", False),
    ("https://fcm.googleapis.com.evil.example/x", False),
    ("https://user:pw@fcm.googleapis.com/x", False),
    ("https://169.254.169.254/latest", False),
])
def test_only_browser_push_services_are_accepted(endpoint, allowed):
    assert webpush.endpoint_allowed(endpoint) is allowed


def _enable(app, value="true"):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.merge(PlatformSetting(key="WEB_PUSH_ENABLED", value=value, tenant_id=admin.tenant_id))
        db.session.commit()


def _subscription_json():
    ua_key = ec.generate_private_key(ec.SECP256R1())
    point = ua_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return ua_key, {"endpoint": "https://fcm.googleapis.com/fcm/send/device-1",
                    "keys": {"p256dh": b64url(point), "auth": b64url(b"0123456789abcdef")}}


def test_subscriptions_need_web_push_enabled_and_valid_input(app, client):
    _enable(app, "false")  # on by default; an administrator can turn it off
    login(client)
    _, body = _subscription_json()
    assert client.get("/push/config").get_json() == {"enabled": False, "public_key": None}
    assert client.post("/push/subscriptions", json=body).status_code == 404
    _enable(app)
    key = client.get("/push/config").get_json()["public_key"]
    assert len(b64url_decode(key)) == 65
    assert client.get("/push/config").get_json()["public_key"] == key  # stable once created
    assert client.post("/push/subscriptions", json={**body, "endpoint": "https://evil.example/x"}).status_code == 400
    assert client.post("/push/subscriptions", json={**body, "keys": {"p256dh": "AAAA", "auth": "AAAA"}}).status_code == 400
    assert client.post("/push/subscriptions", json=body).status_code == 201
    assert client.post("/push/subscriptions", json=body).status_code == 201  # same browser: one row
    with app.app_context():
        rows = WebPushSubscription.query.all()
        assert len(rows) == 1 and "device-1" not in rows[0].keys_encrypted  # keys encrypted at rest
    assert client.delete("/push/subscriptions", json={"endpoint": body["endpoint"]}).get_json() == {"removed": True}


class _FakeClient:
    status = 201
    sent = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, content=None, headers=None):
        _FakeClient.sent.append((url, content, headers))
        return type("R", (), {"status_code": _FakeClient.status})()


def test_the_outbox_delivers_encrypted_web_push_and_drops_gone_browsers(app, client, monkeypatch):
    import httpx
    _enable(app)
    login(client)
    ua_key, body = _subscription_json()
    client.post("/push/subscriptions", json=body)
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    _FakeClient.sent, _FakeClient.status = [], 201
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin_id, tenant_id = admin.id, admin.tenant_id
        OutboxEvent.query.delete()
        create_notification(admin_id, "Change approved", "CHG0000041 was approved", tenant_id=tenant_id)
        db.session.commit()
        process_outbox()
        assert IntegrationDelivery.query.filter_by(channel="webpush", state="Delivered").count() == 1
    url, content, headers = _FakeClient.sent[0]
    assert url == body["endpoint"] and headers["Content-Encoding"] == "aes128gcm"
    message = json.loads(_decrypt(content, ua_key, b"0123456789abcdef"))
    assert message["title"] == "Change approved" and message["body"] == "CHG0000041 was approved"
    _FakeClient.status = 410
    with app.app_context():
        create_notification(admin_id, "Second", "x", tenant_id=tenant_id)
        db.session.commit()
        process_outbox()
        assert WebPushSubscription.query.count() == 0  # the browser unsubscribed


def test_desktop_notifications_are_on_by_default(client, app):
    login(client)
    config = client.get("/push/config").get_json()
    assert config["enabled"] is True and config["public_key"]


def test_preferences_explain_when_desktop_notifications_are_off(client, app):
    _enable(app, "false")
    login(client)
    html = client.get("/preferences").get_data(as_text=True)
    # Visible (not hidden) so the reason can be shown; administrators get the setting link.
    assert '<div class="preference-row" data-web-push>' in html
    assert "data-web-push-admin" in html and "/admin/settings/email_delivery" in html
    assert client.get("/push/config").get_json() == {"enabled": False, "public_key": None}
    login(client, "employee", "Employee123!")
    assert "data-web-push-admin" not in client.get("/preferences").get_data(as_text=True)


def test_the_server_key_is_never_replaced_once_created(app):
    with app.app_context():
        first = webpush.public_key()
        db.session.commit()
        # A second worker that missed the cached value still gets the stored key.
        assert webpush.public_key() == first
