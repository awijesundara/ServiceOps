"""Sign-in endpoints for the ServiceOps iOS app beyond username and password.

- GET  /api/v1/auth/mobile/methods: which sign-in methods this server offers.
- POST /api/v1/auth/mobile/cloudflare-access: exchange a verified Cloudflare
  Access token (the CF_Authorization JWT) for a mobile session. Same rules as
  the web shortcut: exactly one active account with that email, lockout and
  MFA still apply, nothing is created or elevated.
- GET  /auth/keycloak/mobile/start + /auth/keycloak/mobile/callback, then
  POST /api/v1/auth/mobile/keycloak/exchange: Keycloak sign-in in the system
  browser, handed back to the app with a single-use code bound to the app's
  PKCE challenge (RFC 7636, S256), so only the app that started the flow can
  redeem it.

Registered from serviceops_core.web.auth.register(); app.py exempts these
endpoint names from bearer-token authentication and CSRF, as it does for the
password and passkey sign-in endpoints.
"""
import base64
import hashlib
import hmac
import os
import re
from datetime import timedelta
from urllib.parse import urlencode

from flask import abort, jsonify, redirect, request, session
from sqlalchemy import func

import app as core
from serviceops_core.localization import tr
from serviceops_core.mfa import record_second_factor_failure, verify_second_factor
from serviceops_core.public_url import public_url_for
from serviceops_models import PasskeyChallenge, User, db, now

PUBLIC_ENDPOINTS = ("api_mobile_auth_methods", "api_mobile_cloudflare_access", "api_mobile_keycloak_exchange")
_PKCE_VALUE = re.compile(r"[A-Za-z0-9_-]{43,128}")
_STATE = re.compile(r"[A-Za-z0-9_-]{8,128}")
_HANDOFF_PURPOSE = "keycloak_mobile"
_APP_CALLBACK = "serviceops://keycloak"


def _session_payload(user, method, backup_used=False):
    access, refresh = core.issue_mobile_session(user, method, backup_used)
    db.session.commit()
    return jsonify({"access_token": access, "refresh_token": refresh, "expires_in": 900,
                    "user": {"id": user.id, "username": user.username, "name": user.name}})


def _rate_limited(bucket):
    ip = request.remote_addr or "unknown"
    allowed = core.route_rate_limit(bucket, f"ip:{ip}", core.setting_int("LOGIN_RATE_LIMIT_PER_IP_PER_MINUTE", 20))
    db.session.commit()
    if not allowed:
        abort(429, description=tr("Too many sign-in attempts. Try again later."))


def _passkeys_configured():
    origin = os.getenv("WEBAUTHN_ORIGIN", "").strip()
    return bool(os.getenv("WEBAUTHN_RP_ID", "").strip()) and origin.startswith("https://")


def _app_redirect(state, **params):
    return redirect(f"{_APP_CALLBACK}?{urlencode({**params, 'state': state})}")


def register(app):
    @app.get("/api/v1/auth/mobile/methods")
    def api_mobile_auth_methods():
        return jsonify({"data": {
            "local": core.setting_bool("LOCAL_AUTH_ENABLED", True),
            "ldap": core.setting_bool("LDAP_ENABLED"),
            "passkeys": _passkeys_configured(),
            "keycloak": bool(app.config.get("KEYCLOAK_ENABLED")),
            "cloudflare_access": bool(app.config.get("CLOUDFLARE_ACCESS_TEAM_DOMAIN")
                                      and app.config.get("CLOUDFLARE_ACCESS_AUD")),
        }})

    @app.post("/api/v1/auth/mobile/cloudflare-access")
    def api_mobile_cloudflare_access():
        if not (app.config.get("CLOUDFLARE_ACCESS_TEAM_DOMAIN") and app.config.get("CLOUDFLARE_ACCESS_AUD")):
            abort(404)
        _rate_limited("mobile_cloudflare_access")
        claims = core.verify_cloudflare_access_jwt(request.headers.get("Cf-Access-Jwt-Assertion", ""))
        email = str((claims or {}).get("email") or "").strip().lower()
        if not email:
            abort(401, description=tr("Cloudflare Access did not confirm your identity. Sign in to Access again."))
        matches = User.query.filter(func.lower(User.email) == email, User.active.is_(True)).limit(2).all()
        user = matches[0] if len(matches) == 1 else None
        if not user or not core.account_usable(user):
            core.audit("login_failed", email, "provider=cloudflare_access; platform=mobile; reason=no_single_account")
            db.session.commit()
            abort(403, description=tr("No active ServiceOps account matches your Cloudflare Access identity."))
        if user.locked_until and core.align_tz(user.locked_until, now()) > now():
            core.audit("login_blocked", user.username, "provider=cloudflare_access; platform=mobile; reason=locked",
                       user_id=user.id, tenant_id=user.tenant_id)
            db.session.commit()
            abort(423, description=tr("This account is temporarily locked."))
        body = request.get_json(silent=True)
        mfa_code = str((body or {}).get("mfa_code") or "").strip() if isinstance(body, dict) else ""
        verified, backup_used = verify_second_factor(user, mfa_code)
        if not verified:
            if mfa_code and record_second_factor_failure(user, "mobile"):
                db.session.commit()
                abort(423, description=tr("This account is temporarily locked."))
            core.audit("login_failed", user.username, "provider=cloudflare_access; platform=mobile; reason=mfa_required",
                       user_id=user.id, tenant_id=user.tenant_id)
            db.session.commit()
            abort(401, description=tr("A valid MFA or backup code is required."))
        user.failed_login_count, user.locked_until = 0, None
        core.audit("login", user.username, "provider=cloudflare_access; platform=mobile",
                   user_id=user.id, tenant_id=user.tenant_id)
        return _session_payload(user, "cloudflare_access", backup_used)

    @app.get("/auth/keycloak/mobile/start")
    def keycloak_mobile_start():
        if not app.config.get("KEYCLOAK_ENABLED"):
            abort(404)
        challenge = request.args.get("code_challenge", "")
        state = request.args.get("state", "")
        if not _PKCE_VALUE.fullmatch(challenge) or not _STATE.fullmatch(state):
            abort(400, description=tr("The sign-in request from the app is incomplete. Try again."))
        session["_keycloak_mobile"] = {"challenge": challenge, "state": state, "at": now().timestamp()}
        return core.oauth.keycloak.authorize_redirect(public_url_for("keycloak_mobile_callback"))

    @app.get("/auth/keycloak/mobile/callback")
    def keycloak_mobile_callback():
        if not app.config.get("KEYCLOAK_ENABLED"):
            abort(404)
        pending = session.pop("_keycloak_mobile", None)
        if not pending or now().timestamp() - float(pending.get("at", 0)) > 600:
            abort(400, description=tr("This sign-in has expired. Start again from the app."))
        state = pending["state"]
        if request.args.get("error"):
            return _app_redirect(state, error="access_denied")
        try:
            token = core.oauth.keycloak.authorize_access_token()
        except Exception:  # noqa: BLE001 - any provider failure ends the hand-off, never a 500
            app.logger.warning("Keycloak mobile sign-in could not complete the code exchange")
            return _app_redirect(state, error="failed")
        from serviceops_core.web.auth import resolve_keycloak_user
        user, error = resolve_keycloak_user(token.get("userinfo") or {}, platform="mobile")
        if error:
            return _app_redirect(state, error="failed" if error == "invalid" else error)
        handoff = PasskeyChallenge(challenge=pending["challenge"].encode(), purpose=_HANDOFF_PURPOSE,
                                   user_id=user.id, tenant_id=user.tenant_id,
                                   expires_at=now() + timedelta(minutes=2))
        db.session.add(handoff)
        db.session.commit()
        return _app_redirect(state, code=handoff.id)

    @app.post("/api/v1/auth/mobile/keycloak/exchange")
    def api_mobile_keycloak_exchange():
        if not app.config.get("KEYCLOAK_ENABLED"):
            abort(404)
        _rate_limited("mobile_keycloak_exchange")
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        code, verifier = str(body.get("code") or "")[:64], str(body.get("code_verifier") or "")
        if not code or not _PKCE_VALUE.fullmatch(verifier):
            abort(400, description=tr("The sign-in code or verifier is missing."))
        handoff = PasskeyChallenge.query.filter_by(id=code, purpose=_HANDOFF_PURPOSE).with_for_update().first()
        if handoff is not None:
            db.session.delete(handoff)  # single use, whatever the outcome
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
        if (handoff is None or core.align_tz(handoff.expires_at, now()) <= now()
                or not hmac.compare_digest(handoff.challenge, expected)):
            db.session.commit()
            abort(401, description=tr("This sign-in code is invalid or has expired. Sign in again."))
        user = db.session.get(User, handoff.user_id)
        if not user or not core.account_usable(user):
            db.session.commit()
            abort(403, description=tr("This account or its organization is not active."))
        core.audit("login", user.username, "provider=keycloak; platform=mobile",
                   user_id=user.id, tenant_id=user.tenant_id)
        return _session_payload(user, "keycloak")
