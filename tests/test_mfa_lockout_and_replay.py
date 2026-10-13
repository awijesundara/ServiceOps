"""Second-factor hardening (2026-10-12 review): wrong MFA codes count toward
the account lockout on the web and mobile sign-ins, a TOTP code is accepted
once, unknown usernames cost a full password check, signed-in responses are
not stored, and the OpenAPI document lists every /api/v1 route."""
import re

import pyotp
import pytest

import serviceops_core.security as security
from app import Audit, PlatformSetting, User, db, settings_cipher
from tests.test_app import app, client  # noqa: F401

MOBILE_HEADERS = {
    "X-ServiceOps-App-Version": "1.1.0", "X-ServiceOps-App-Build": "42",
    "X-ServiceOps-Platform": "iOS", "X-ServiceOps-Device": "iPhone17,1",
}


@pytest.fixture()
def secret(app):
    value = pyotp.random_base32()
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin.mfa_secret_encrypted = settings_cipher().encrypt(value.encode()).decode()
        admin.mfa_enabled = True
        db.session.add(PlatformSetting(key="LOGIN_MAX_ATTEMPTS", value="3", tenant_id=admin.tenant_id, encrypted=False))
        db.session.commit()
    return value


def admin(app):
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        return user.failed_login_count, user.locked_until


def password_step(client):
    return client.post("/login", data={"username": "admin", "password": "Admin123!"})


def test_wrong_web_mfa_codes_lock_the_account_and_password_reentry_does_not_reset(app, client, secret):
    password_step(client)
    assert b"Invalid verification code" in client.post("/login/mfa", data={"code": "000000"}).data
    # Entering the password again must not wipe the MFA failure.
    password_step(client)
    client.post("/login/mfa", data={"code": "000001"})
    assert admin(app)[0] == 2
    locked = client.post("/login/mfa", data={"code": "000002"})
    assert locked.status_code == 302 and locked.headers["Location"].endswith("/login")
    count, locked_until = admin(app)
    assert locked_until is not None and count == 0
    # Locked: even the right code is refused, at the password step.
    password_step(client)
    with client.session_transaction() as sess:
        assert "_mfa_pending_user_id" not in sess
    with app.app_context():
        assert Audit.query.filter_by(action="login_locked", target="admin").count() == 1


def test_an_empty_web_code_is_not_counted(app, client, secret):
    password_step(client)
    client.post("/login/mfa", data={"code": ""})
    assert admin(app)[0] == 0


def test_successful_mfa_resets_the_failure_count(app, client, secret):
    password_step(client)
    client.post("/login/mfa", data={"code": "000000"})
    assert admin(app)[0] == 1
    client.post("/login/mfa", data={"code": pyotp.TOTP(secret).now()})
    with client.session_transaction() as sess:
        assert sess.get("_user_id") is not None
    assert admin(app) == (0, None)


def test_a_totp_code_is_accepted_only_once(app, client, secret):
    code = pyotp.TOTP(secret).now()
    password_step(client)
    client.post("/login/mfa", data={"code": code})
    with client.session_transaction() as sess:
        assert sess.get("_user_id") is not None
    client.post("/logout")
    password_step(client)
    replay = client.post("/login/mfa", data={"code": code})
    assert b"Invalid verification code" in replay.data
    with client.session_transaction() as sess:
        assert sess.get("_user_id") is None


def test_mobile_wrong_codes_lock_but_a_missing_code_does_not_count(app, client, secret):
    def mobile(code=None):
        body = {"username": "admin", "password": "Admin123!"}
        if code is not None:
            body["mfa_code"] = code
        return client.post("/api/v1/auth/mobile/login", headers=MOBILE_HEADERS, json=body)
    assert mobile().status_code == 401
    assert admin(app)[0] == 0
    assert mobile("000000").status_code == 401
    assert mobile("000001").status_code == 401
    assert mobile("000002").status_code == 423
    assert mobile(pyotp.TOTP(secret).now()).status_code == 423


def test_mobile_totp_replay_is_refused(app, client, secret):
    code = pyotp.TOTP(secret).now()
    body = {"username": "admin", "password": "Admin123!", "mfa_code": code}
    assert client.post("/api/v1/auth/mobile/login", headers=MOBILE_HEADERS, json=body).status_code == 200
    assert client.post("/api/v1/auth/mobile/login", headers=MOBILE_HEADERS, json=body).status_code == 401


def test_unknown_usernames_spend_a_password_check(app, client, monkeypatch):
    calls = []
    real = security.burn_password_check
    monkeypatch.setattr("serviceops_core.web.auth.burn_password_check", lambda pw: calls.append("web") or real(pw))
    monkeypatch.setattr("serviceops_core.web.api.burn_password_check", lambda pw: calls.append("mobile") or real(pw))
    client.post("/login", data={"username": "nobody-here", "password": "x"})
    client.post("/api/v1/auth/mobile/login", headers=MOBILE_HEADERS, json={"username": "nobody-here", "password": "x"})
    assert calls == ["web", "mobile"]
    assert security.burn_password_check("anything") is False


def test_signed_in_pages_are_not_stored_but_static_assets_keep_their_caching(app, client):
    assert "no-store" not in client.get("/login").headers.get("Cache-Control", "")
    client.post("/login", data={"username": "admin", "password": "Admin123!"})
    assert client.get("/").headers["Cache-Control"] == "no-store"
    static = client.get("/static/app.css?v=1")
    assert "immutable" in static.headers["Cache-Control"]
    assert client.get("/api/v1/openapi.json").headers["Cache-Control"] == "no-store"


def test_openapi_covers_every_api_route(app, client):
    spec = client.get("/api/v1/openapi.json").get_json()
    documented = {(method.upper(), re.sub(r"\{[^}]+\}", "{}", "/api/v1" + path))
                  for path, item in spec["paths"].items() for method in item
                  if method in ("get", "post", "put", "patch", "delete")}
    missing = []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/v1/"):
            continue
        path = re.sub(r"<(?:\w+:)?\w+>", "{}", rule.rule)
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            if (method, path) not in documented:
                missing.append(f"{method} {rule.rule}")
    assert not missing, missing


def test_a_code_claimed_by_a_concurrent_sign_in_is_refused(app, secret):
    # This request loaded the user before another sign-in claimed the step.
    import time
    from sqlalchemy import text
    from serviceops_core.mfa import verify_second_factor
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        assert user.mfa_last_totp_step is None
        step = int(time.time() // 30)
        with db.engine.begin() as other:
            other.execute(text('UPDATE "user" SET mfa_last_totp_step = :s WHERE id = :i'), {"s": step + 1, "i": user.id})
        assert verify_second_factor(user, pyotp.TOTP(secret).now()) == (False, False)
        db.session.rollback()


def test_enrolling_a_new_secret_resets_the_replay_guard(app, client):
    client.post("/login", data={"username": "admin", "password": "Admin123!"})
    client.get("/settings/mfa")
    with client.session_transaction() as sess:
        pending = sess["_mfa_pending_secret"]
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin.mfa_last_totp_step = 10 ** 9  # left over from a previous secret
        db.session.commit()
    client.post("/settings/mfa", data={"action": "enable", "code": pyotp.TOTP(pending).now()})
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        assert admin.mfa_enabled and admin.mfa_last_totp_step is None
