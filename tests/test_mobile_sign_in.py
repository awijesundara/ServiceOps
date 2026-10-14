"""iOS sign-in beyond passwords: method discovery, Cloudflare Access and the Keycloak hand-off."""
import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest
from flask import redirect

import app as core
from app import User, db
from tests.test_app import app, client  # noqa: F401

IOS = {"X-ServiceOps-Platform": "iOS", "X-ServiceOps-App-Version": "1.3.2", "X-ServiceOps-App-Build": "8",
       "X-ServiceOps-Device": "iPhone17,1"}


def test_methods_describe_what_this_server_offers(app, client):
    response = client.get("/api/v1/auth/mobile/methods")
    assert response.status_code == 200
    assert response.json["data"] == {"local": True, "ldap": False, "passkeys": False, "keycloak": False,
                                     "cloudflare_access": False}
    app.config.update(KEYCLOAK_ENABLED=True, CLOUDFLARE_ACCESS_TEAM_DOMAIN="team.cloudflareaccess.com",
                      CLOUDFLARE_ACCESS_AUD="aud")
    data = client.get("/api/v1/auth/mobile/methods").json["data"]
    assert data["keycloak"] and data["cloudflare_access"]


# ------------------------------------------------------------------ Cloudflare Access

@pytest.fixture()
def access_token(app):
    from joserfc import jwt as joserfc_jwt
    from joserfc.jwk import KeySet, RSAKey
    key = RSAKey.generate_key(2048, parameters={"kid": "k1"}, private=True)
    app.config.update(CLOUDFLARE_ACCESS_TEAM_DOMAIN="team.cloudflareaccess.com", CLOUDFLARE_ACCESS_AUD="aud")
    core._cloudflare_access_jwks_cache.update(key_set=KeySet([key]), fetched_at=core.time_module.monotonic())

    def make(email, iss="https://team.cloudflareaccess.com"):
        return joserfc_jwt.encode({"alg": "RS256", "kid": "k1"},
                                  {"email": email, "aud": "aud", "exp": 9999999999, "iss": iss}, key)
    yield make
    core._cloudflare_access_jwks_cache.update(key_set=None, fetched_at=0.0)


def email_of(app, username):
    with app.app_context():
        return User.query.filter_by(username=username).one().email


def test_cloudflare_access_issues_a_mobile_session_for_exactly_one_account(app, client, access_token):
    response = client.post("/api/v1/auth/mobile/cloudflare-access", json={},
                           headers={**IOS, "Cf-Access-Jwt-Assertion": access_token(email_of(app, "employee"))})
    assert response.status_code == 200, response.json
    assert response.json["user"]["username"] == "employee"
    tickets = client.get("/api/v1/tickets", headers={"Authorization": f"Bearer {response.json['access_token']}"})
    assert tickets.status_code == 200

    for token, status in ((access_token("nobody@example.test"), 403),
                          (access_token(email_of(app, "employee"), iss="https://evil.cloudflareaccess.com"), 401),
                          ("not-a-jwt", 401)):
        assert client.post("/api/v1/auth/mobile/cloudflare-access", json={},
                           headers={"Cf-Access-Jwt-Assertion": token}).status_code == status


def test_cloudflare_access_refuses_ambiguous_email_and_still_requires_mfa(app, client, access_token):
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        secret = pyotp.random_base32()
        employee.mfa_secret_encrypted = core.settings_cipher().encrypt(secret.encode()).decode()
        employee.mfa_enabled = True
        db.session.commit()
        email = employee.email
    headers = {**IOS, "Cf-Access-Jwt-Assertion": access_token(email)}
    assert client.post("/api/v1/auth/mobile/cloudflare-access", json={}, headers=headers).status_code == 401
    ok = client.post("/api/v1/auth/mobile/cloudflare-access", json={"mfa_code": pyotp.TOTP(secret).now()},
                     headers=headers)
    assert ok.status_code == 200, ok.json

    with app.app_context():
        db.session.add(User(username="employee-twin", name="Twin", email=email.upper(),
                            password_hash=core.hash_password(secrets.token_hex(8)), role="requester"))
        db.session.commit()
    assert client.post("/api/v1/auth/mobile/cloudflare-access", json={}, headers=headers).status_code == 403


def test_cloudflare_access_is_unavailable_when_not_configured(client):
    assert client.post("/api/v1/auth/mobile/cloudflare-access", json={},
                       headers={"Cf-Access-Jwt-Assertion": "x"}).status_code == 404


# ------------------------------------------------------------------ Keycloak hand-off

class FakeKeycloak:
    def __init__(self, userinfo):
        self.userinfo = userinfo
        self.redirect_uri = None

    def authorize_redirect(self, redirect_uri):
        self.redirect_uri = redirect_uri
        return redirect("https://keycloak.example.test/auth")

    def authorize_access_token(self):
        return {"userinfo": self.userinfo}


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def start_and_finish(client, challenge, state):
    assert client.get(f"/auth/keycloak/mobile/start?code_challenge={challenge}&state={state}").status_code == 302
    location = client.get("/auth/keycloak/mobile/callback?code=idp&state=idp").headers["Location"]
    assert location.startswith("serviceops://keycloak?")
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}


@pytest.fixture()
def keycloak(app, monkeypatch):
    app.config["KEYCLOAK_ENABLED"] = True
    fake = FakeKeycloak({"sub": "kc-subject-1", "preferred_username": "kc.user", "name": "KC User",
                         "email": "kc.user@example.test", "email_verified": True})
    monkeypatch.setattr(core.oauth, "keycloak", fake, raising=False)
    return fake


def test_keycloak_hand_off_returns_a_single_use_code_bound_to_pkce(app, client, keycloak):
    verifier, challenge = pkce()
    result = start_and_finish(client, challenge, "state-123456")
    assert result["state"] == "state-123456" and result["code"]
    assert keycloak.redirect_uri.endswith("/auth/keycloak/mobile/callback")

    wrong = client.post("/api/v1/auth/mobile/keycloak/exchange",
                        json={"code": result["code"], "code_verifier": pkce()[0]}, headers=IOS)
    assert wrong.status_code == 401  # a wrong verifier also burns the code
    assert client.post("/api/v1/auth/mobile/keycloak/exchange",
                       json={"code": result["code"], "code_verifier": verifier}).status_code == 401

    verifier, challenge = pkce()
    result = start_and_finish(client, challenge, "state-abcdef")
    session = client.post("/api/v1/auth/mobile/keycloak/exchange",
                          json={"code": result["code"], "code_verifier": verifier}, headers=IOS)
    assert session.status_code == 200, session.json
    assert session.json["user"]["username"] == "kc.user"
    assert client.post("/api/v1/auth/mobile/keycloak/exchange",
                       json={"code": result["code"], "code_verifier": verifier}).status_code == 401


def test_keycloak_refusals_reach_the_app_as_error_codes(app, client, keycloak, monkeypatch):
    with app.app_context():
        admin_email = User.query.filter_by(username="admin").one().email
    keycloak.userinfo = {"sub": "kc-attacker", "preferred_username": "mallory", "email": admin_email,
                         "email_verified": False}
    result = start_and_finish(client, pkce()[1], "state-refused")
    assert result == {"error": "link_refused", "state": "state-refused"}

    monkeypatch.setenv("KEYCLOAK_REQUIRED_ACR", "mfa")
    keycloak.userinfo = {"sub": "kc-subject-2", "email": "x@example.test", "email_verified": True, "acr": "pwd"}
    assert start_and_finish(client, pkce()[1], "state-acr00")["error"] == "mfa_assurance"


def test_keycloak_start_validates_the_app_request(app, client, keycloak):
    assert client.get("/auth/keycloak/mobile/start?code_challenge=short&state=state-123456").status_code == 400
    assert client.get(f"/auth/keycloak/mobile/start?code_challenge={pkce()[1]}&state=a b").status_code == 400
    assert client.get("/auth/keycloak/mobile/callback?code=x").status_code == 400  # nothing pending
