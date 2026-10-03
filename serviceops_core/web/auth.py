"""Sign-in, sign-out and session routes.

Moved from app.create_app(); endpoint names are unchanged."""
import hashlib
import hmac
import json
import os
import secrets
from datetime import timedelta

import pyotp
from flask import abort, current_app, flash, make_response, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func

import app as core
from app import (
    account_usable,
    align_tz,
    audit,
    create_notification,
    effective_role_has_action,
    hash_backup_code,
    is_safe_internal_path,
    ldap_authenticate,
    mapped_roles,
    oauth,
    provision_external_user,
    route_rate_limit,
    setting_bool,
    setting_int,
    tenant_query,
    user_is_local,
    verify_cloudflare_access_jwt,
)
from serviceops_core.security import hash_password, verify_and_upgrade_password
from serviceops_models import db, now, PasswordResetToken, settings_cipher, User, UserPreference, UserSession


def register(app):
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET" and current_user.is_authenticated:
            # Revisiting /login (bookmark, typed URL, back button) with a
            # live session should land the user back in the app, not
            # re-prompt for credentials -- this only ever applied to the
            # Cloudflare Access SSO branch below, so a plain GET with an
            # existing session fell through to rendering login.html
            # regardless of auth state. Scoped to GET only: a POST here
            # (submitting different credentials while already signed in)
            # is left to the existing password-check logic below, which
            # already supports switching accounts without an explicit
            # logout first.
            preference = UserPreference.query.filter_by(user_id=current_user.id).first()
            start_page = preference.start_page if preference else None
            if not is_safe_internal_path(start_page):
                start_page = url_for("dashboard")
            return redirect(start_page)
        if not current_user.is_authenticated and app.config["CLOUDFLARE_ACCESS_TEAM_DOMAIN"]:
            access_claims = verify_cloudflare_access_jwt(request.headers.get("Cf-Access-Jwt-Assertion", ""))
            if access_claims and access_claims.get("email"):
                sso_user = User.query.filter(
                    func.lower(User.email) == access_claims["email"].strip().lower(),
                    User.active.is_(True),
                ).first()
                # A verified Access identity is a login *shortcut* into an
                # existing account, not a bypass of that account's own
                # standing controls (CLAUDE.md's Authentication section):
                # a locked account must not be silently let in, and an
                # MFA-enrolled account must still complete MFA, exactly as
                # the local/password path below requires.
                if sso_user and not account_usable(sso_user):
                    sso_user = None
                if sso_user and sso_user.locked_until and align_tz(sso_user.locked_until, now()) > now():
                    audit("login_blocked", sso_user.username, "reason=locked; provider=cloudflare_access")
                    db.session.commit()
                    sso_user = None
                if sso_user and sso_user.mfa_enabled:
                    session["_mfa_pending_user_id"] = sso_user.id
                    session["_mfa_pending_auth_version"] = sso_user.auth_version
                    session["_mfa_pending_started_at"] = now().timestamp()
                    session["_mfa_pending_provider"] = "cloudflare_access"
                    return redirect(url_for("login_mfa"))
                if sso_user:
                    login_user(sso_user)
                    session.permanent = True
                    session["_auth_version"] = sso_user.auth_version
                    session["_auth_provider"] = "cloudflare_access"
                    session["_csrf_token"] = secrets.token_urlsafe(32)
                    sso_user.failed_login_count = 0
                    sso_user.locked_until = None
                    audit("login", sso_user.username, "provider=cloudflare_access")
                    db.session.commit()
                    preference = UserPreference.query.filter_by(user_id=sso_user.id).first()
                    start_page = preference.start_page if preference else None
                    if not is_safe_internal_path(start_page):
                        start_page = url_for("dashboard")
                    return redirect(start_page)
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            provider = request.form.get("provider", "local")
            # ISO 27001 A.8.16: general web rate limiting. Scoped per-IP so a
            # distributed low-and-slow credential-stuffing attack across many
            # usernames from one source is throttled even though it never
            # trips the existing per-account lockout (app.py LOGIN_MAX_ATTEMPTS),
            # and scoped per-account so many source IPs targeting one
            # username are also throttled -- without letting either limiter
            # lock out *other* legitimate users sharing an IP (e.g. NAT/VPN
            # egress), since each IP/account has its own independent counter.
            client_ip = request.remote_addr or "unknown"
            ip_limit = setting_int("LOGIN_RATE_LIMIT_PER_IP_PER_MINUTE", 20)
            user_limit = setting_int("LOGIN_RATE_LIMIT_PER_ACCOUNT_PER_MINUTE", 10)
            ip_ok = route_rate_limit("login", f"ip:{client_ip}", ip_limit)
            user_ok = (
                route_rate_limit("login", f"user:{username.lower()}", user_limit)
                if username else True
            )
            # Persist every accepted counter increment. In IPFS mode the
            # committed row joins the encrypted checkpoint like all other
            # application state, so limits survive restarts.
            db.session.commit()
            if not (ip_ok and user_ok):
                response = render_template(
                    "login.html", ldap_enabled=setting_bool("LDAP_ENABLED"),
                    keycloak_enabled=app.config["KEYCLOAK_ENABLED"],
                    local_enabled=setting_bool("LOCAL_AUTH_ENABLED", True),
                    deployment_profile=app.config["DEPLOYMENT_PROFILE"])
                flash("Too many sign-in attempts. Please wait a moment and try again.", "error")
                return response, 429
            lockout_record = User.query.filter_by(username=username).first()
            if lockout_record and lockout_record.locked_until and align_tz(lockout_record.locked_until, now()) > now():
                audit("login_blocked", username, "reason=locked")
                db.session.commit()
                flash("This account is temporarily locked due to repeated failed sign-ins. Try again later.", "error")
                return render_template(
                    "login.html", ldap_enabled=setting_bool("LDAP_ENABLED"),
                    keycloak_enabled=app.config["KEYCLOAK_ENABLED"],
                    local_enabled=setting_bool("LOCAL_AUTH_ENABLED", True),
                    deployment_profile=app.config["DEPLOYMENT_PROFILE"])
            user = None
            if provider == "ldap" and setting_bool("LDAP_ENABLED"):
                try:
                    user = ldap_authenticate(username, password)
                except Exception:
                    app.logger.exception("LDAP authentication failed")
            elif setting_bool("LOCAL_AUTH_ENABLED", True):
                candidate = User.query.filter_by(username=username).first()
                if candidate:
                    valid, upgraded_hash = verify_and_upgrade_password(
                        candidate.password_hash, password
                    )
                    if valid:
                        user = candidate
                        if upgraded_hash:
                            # Lazy migration off legacy PBKDF2 to Argon2id
                            # (ISO 27001 A.8.24) -- happens transparently on
                            # the next successful login, no bulk migration
                            # or forced reset required.
                            candidate.password_hash = upgraded_hash
            if user and not account_usable(user):
                user = None
            if user and user.mfa_enabled:
                # Password verified but MFA is required (ISO 27001 A.8.5):
                # do not issue a session yet. Stash the authenticated-but-
                # not-yet-MFA'd user id in a short-lived, server-signed
                # session value; /login/mfa completes the login only after a
                # valid TOTP code or backup code is presented.
                user.failed_login_count = 0
                user.locked_until = None
                db.session.commit()
                session["_mfa_pending_user_id"] = user.id
                session["_mfa_pending_auth_version"] = user.auth_version
                session["_mfa_pending_started_at"] = now().timestamp()
                session["_mfa_pending_provider"] = provider
                return redirect(url_for("login_mfa"))
            if user:
                user.failed_login_count = 0
                user.locked_until = None
                login_user(user)
                session.permanent = True
                session["_auth_version"] = user.auth_version
                session["_auth_provider"] = provider
                session["_csrf_token"] = secrets.token_urlsafe(32)
                audit("login", user.username, f"provider={provider}")
                db.session.commit()
                preference = UserPreference.query.filter_by(user_id=user.id).first()
                start_page = preference.start_page if preference else None
                if not is_safe_internal_path(start_page):
                    start_page = url_for("dashboard")
                return redirect(start_page)
            if lockout_record:
                lockout_record.failed_login_count = (lockout_record.failed_login_count or 0) + 1
                max_attempts = setting_int("LOGIN_MAX_ATTEMPTS", 5)
                if lockout_record.failed_login_count >= max_attempts:
                    lockout_record.locked_until = now() + timedelta(minutes=setting_int("LOGIN_LOCKOUT_MINUTES", 15))
                    lockout_record.failed_login_count = 0
                    audit("login_locked", username, f"attempts={max_attempts}")
                else:
                    audit("login_failed", username, f"attempts={lockout_record.failed_login_count}")
                db.session.commit()
            flash("Invalid username or password.", "error")
        return render_template("login.html", ldap_enabled=setting_bool("LDAP_ENABLED"),
                               keycloak_enabled=app.config["KEYCLOAK_ENABLED"],
                               local_enabled=setting_bool("LOCAL_AUTH_ENABLED", True),
                               deployment_profile=app.config["DEPLOYMENT_PROFILE"])

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            identity = request.form.get("identity", "").strip().lower()
            allowed = route_rate_limit(
                "password_reset", f"ip:{request.remote_addr or 'unknown'}",
                setting_int("PASSWORD_RESET_RATE_LIMIT_PER_HOUR", 5), window_seconds=3600,
            )
            db.session.commit()
            if not allowed:
                flash("Too many recovery requests. Please try again later.", "error")
                return render_template("forgot_password.html"), 429
            user = User.query.filter(
                db.or_(func.lower(User.username) == identity, func.lower(User.email) == identity),
                User.active.is_(True),
            ).first()
            if user and user_is_local(user):
                raw_token = secrets.token_urlsafe(32)
                token_hash = hmac.new(
                    current_app.config["SECRET_KEY"].encode(), raw_token.encode(), hashlib.sha256,
                ).hexdigest()
                PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).update({"used_at": now()})
                db.session.add(PasswordResetToken(
                    token_hash=token_hash, user_id=user.id, tenant_id=user.tenant_id,
                    expires_at=now() + timedelta(minutes=30),
                    requested_ip=(request.remote_addr or "")[:64],
                ))
                reset_url = url_for("reset_password", token=raw_token, _external=True)
                create_notification(
                    user.id, "ServiceOps password recovery",
                    f"Use this single-use link within 30 minutes to reset your password: {reset_url}",
                    tenant_id=user.tenant_id,
                    event_type="password.recovery",
                    template_vars={"reset_url": reset_url},
                )
                audit("password reset request", user.username, "recovery link issued",
                      user_id=user.id, tenant_id=user.tenant_id)
                db.session.commit()
            flash("If that active local account exists, recovery instructions have been sent.", "success")
            return redirect(url_for("login"))
        return render_template("forgot_password.html")

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        # The URL holds the one-time token: keep it out of Referer headers
        # sent with this page's own asset requests and any outbound link.
        response = make_response(_reset_password(token))
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def _reset_password(token):
        token_hash = hmac.new(
            current_app.config["SECRET_KEY"].encode(), token.encode(), hashlib.sha256,
        ).hexdigest()
        row = PasswordResetToken.query.filter_by(token_hash=token_hash, used_at=None).first()
        valid = bool(row and align_tz(row.expires_at, now()) > now() and row.user.active)
        if not valid:
            return render_template("error.html", code=400, message="This recovery link is invalid or expired."), 400
        if request.method == "POST":
            password = request.form.get("password", "")
            confirmation = request.form.get("confirmation", "")
            min_length = setting_int("PASSWORD_MIN_LENGTH", 14)
            if len(password) < min_length or password != confirmation:
                flash(f"Use matching passwords containing at least {min_length} characters.", "error")
                return render_template("reset_password.html", token=token)
            row.user.password_hash = hash_password(password)
            row.user.auth_version += 1
            row.user.failed_login_count = 0
            row.user.locked_until = None
            row.used_at = now()
            UserSession.query.filter_by(user_id=row.user_id, revoked_at=None).update(
                {"revoked_at": now(), "revoked_by_id": row.user_id}
            )
            audit("password reset", row.user.username, "self-service recovery completed",
                  user_id=row.user.id, tenant_id=row.tenant_id)
            db.session.commit()
            flash("Password reset. Sign in with your new password.", "success")
            return redirect(url_for("login"))
        return render_template("reset_password.html", token=token)

    @app.route("/login/mfa", methods=["GET", "POST"])
    def login_mfa():
        pending_user_id = session.get("_mfa_pending_user_id")
        if not pending_user_id:
            return redirect(url_for("login"))
        user = db.session.get(User, pending_user_id)
        started_at = session.get("_mfa_pending_started_at")
        # A password change, reset or deactivation after the password step
        # bumps auth_version and must void the half-finished login.
        if (
            not account_usable(user) or not user.mfa_enabled
            or session.get("_mfa_pending_auth_version") != user.auth_version
        ):
            session.pop("_mfa_pending_user_id", None)
            session.pop("_mfa_pending_auth_version", None)
            session.pop("_mfa_pending_provider", None)
            session.pop("_mfa_pending_started_at", None)
            return redirect(url_for("login"))
        if not isinstance(started_at, (int, float)) or not 0 <= now().timestamp() - started_at <= 300:
            session.pop("_mfa_pending_user_id", None)
            session.pop("_mfa_pending_auth_version", None)
            session.pop("_mfa_pending_provider", None)
            session.pop("_mfa_pending_started_at", None)
            return redirect(url_for("login"))
        if request.method == "POST":
            client_ip = request.remote_addr or "unknown"
            # ISO 27001 A.8.16: rate-limit MFA verification the same as the
            # password step -- otherwise a stolen password alone would let
            # an attacker brute-force a 6-digit TOTP code unthrottled.
            mfa_limit = setting_int("LOGIN_RATE_LIMIT_PER_ACCOUNT_PER_MINUTE", 10)
            mfa_ip_ok = route_rate_limit("mfa_verify", f"ip:{client_ip}", mfa_limit)
            mfa_user_ok = route_rate_limit("mfa_verify", f"user:{user.username.lower()}", mfa_limit)
            db.session.commit()
            if not (mfa_ip_ok and mfa_user_ok):
                flash("Too many verification attempts. Please wait a moment and try again.", "error")
                return render_template("login_mfa.html"), 429
            code = request.form.get("code", "").strip()
            verified = False
            backup_used = False
            if code and user.mfa_secret_encrypted:
                secret = settings_cipher().decrypt(user.mfa_secret_encrypted.encode()).decode()
                totp = pyotp.TOTP(secret)
                verified = totp.verify(code.replace(" ", ""), valid_window=1)
            if not verified and code and user.mfa_backup_codes_json:
                remaining = json.loads(user.mfa_backup_codes_json)
                code_hash = hash_backup_code(code.strip().lower())
                if code_hash in remaining:
                    remaining.remove(code_hash)
                    user.mfa_backup_codes_json = json.dumps(remaining)
                    verified = True
                    backup_used = True
            if verified:
                session.pop("_mfa_pending_user_id", None)
                session.pop("_mfa_pending_auth_version", None)
                session.pop("_mfa_pending_started_at", None)
                provider = session.pop("_mfa_pending_provider", "local")
                login_user(user)
                session.permanent = True
                session["_auth_version"] = user.auth_version
                session["_auth_provider"] = provider
                session["_csrf_token"] = secrets.token_urlsafe(32)
                audit(
                    "login", user.username,
                    f"provider={provider}; mfa=backup_code" if backup_used else f"provider={provider}; mfa=totp",
                )
                db.session.commit()
                if backup_used:
                    flash("Signed in with a backup code. Consider regenerating your backup codes.", "warning")
                preference = UserPreference.query.filter_by(user_id=user.id).first()
                start_page = preference.start_page if preference else None
                if not is_safe_internal_path(start_page):
                    start_page = url_for("dashboard")
                return redirect(start_page)
            audit("login_failed", user.username, "reason=invalid_mfa_code")
            db.session.commit()
            flash("Invalid verification code.", "error")
        return render_template("login_mfa.html")

    @app.get("/auth/keycloak/login")
    def keycloak_login():
        if not app.config["KEYCLOAK_ENABLED"]:
            abort(404)
        return oauth.keycloak.authorize_redirect(url_for("keycloak_callback", _external=True))

    @app.get("/auth/keycloak/callback")
    def keycloak_callback():
        if not app.config["KEYCLOAK_ENABLED"]:
            abort(404)
        token = oauth.keycloak.authorize_access_token()
        claims = token.get("userinfo") or {}
        subject = claims.get("sub")
        if not subject:
            abort(401)
        required_acr = os.getenv("KEYCLOAK_REQUIRED_ACR", "").strip()
        if required_acr and claims.get("acr") != required_acr:
            audit("login_blocked", str(claims.get("preferred_username", subject)),
                  f"provider=keycloak; required_acr={required_acr}")
            db.session.commit()
            abort(403, description="Your identity provider did not confirm the required MFA assurance level.")
        realm_roles = claims.get("realm_access", {}).get("roles", [])
        matched_roles = mapped_roles(realm_roles, "KEYCLOAK_ROLE_MAPPINGS")
        try:
            keycloak_attr_map = json.loads(core.setting_value("KEYCLOAK_ATTR_MAP", "{}"))
        except (json.JSONDecodeError, TypeError):
            keycloak_attr_map = {}
        if not isinstance(keycloak_attr_map, dict):
            keycloak_attr_map = {}
        profile_attrs = {
            field: claims.get(claim_name)
            for field, claim_name in keycloak_attr_map.items()
            if claims.get(claim_name)
        }
        user = provision_external_user(
            "keycloak", subject, claims.get("preferred_username", ""),
            claims.get("name", ""), claims.get("email", ""), matched_roles,
            profile_attrs=profile_attrs)
        if not account_usable(user):
            abort(403, description="This account or its organization is not active.")
        login_user(user)
        session.permanent = True
        session["_auth_version"] = user.auth_version
        session["_auth_provider"] = "keycloak"
        session["_csrf_token"] = secrets.token_urlsafe(32)
        audit("login", user.username, "provider=keycloak")
        db.session.commit()
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        audit("logout", current_user.username)
        active_session = UserSession.query.filter_by(
            session_id=session.get("_session_id"), user_id=current_user.id,
        ).first()
        if active_session:
            active_session.revoked_at = now()
            active_session.revoked_by_id = current_user.id
        db.session.commit()
        logout_user()
        session.clear()
        return redirect(url_for("login"))

    @app.post("/session/acting-role")
    @login_required
    def set_acting_role():
        """Switch which of the user's currently-granted roles authorization
        checks use for the rest of this session (User.effective_role) -- a
        real demotion, not a UI label: every @roles(...)/require_action()
        check and the direct role comparisons throughout this file read
        effective_role, so switching to a lower role genuinely blocks
        higher-privilege routes/actions until switched back."""
        requested = request.form.get("role", "")
        destination = request.referrer
        safe_target = (
            destination if destination and destination.startswith(request.host_url)
            else url_for("dashboard")
        )
        if not requested:
            session.pop("_acting_role", None)
            return redirect(safe_target)
        if requested not in current_user.granted_roles:
            abort(403, description="You do not currently hold that role.")
        session["_acting_role"] = requested
        return redirect(safe_target)

    @app.post("/sessions/<int:session_record_id>/revoke")
    @login_required
    def revoke_session(session_record_id):
        row = tenant_query(UserSession).filter_by(id=session_record_id).first_or_404()
        administering = effective_role_has_action(current_user.effective_role, "security_administer")
        if row.user_id != current_user.id and not administering:
            abort(403)
        if row.revoked_at is None:
            row.revoked_at = now()
            row.revoked_by_id = current_user.id
            audit("session revoke", row.user.username, f"session={row.session_id[:12]}")
            db.session.commit()
        if row.session_id == session.get("_session_id"):
            logout_user()
            session.clear()
            return redirect(url_for("login"))
        flash("Session revoked.", "success")
        return redirect(url_for("admin_sessions" if administering and request.form.get("admin_view") else "my_sessions"))
