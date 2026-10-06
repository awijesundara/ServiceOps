"""REST API, mobile API, SCIM and MCP.

Moved from app.create_app(); endpoint names are unchanged."""
import hashlib
import hmac
import json
import os
import re
import secrets
from contextlib import contextmanager
from datetime import timedelta
from urllib.parse import urlparse

from flask import abort, g, jsonify, render_template, request, Response
from flask_login import current_user, login_required
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from webauthn.helpers import base64url_to_bytes

import app as core
from app import (
    account_usable,
    end_stale_mobile_session,
    active_approval_delegation,
    align_tz,
    api_attachment_document,
    api_ctask_document,
    api_idempotency_context,
    api_ticket_document,
    api_token_hash,
    attach_slas,
    attachment_file_response,
    audit,
    CANONICAL_ENVIRONMENTS,
    consume_passkey_challenge,
    create_ticket_with_unique_number,
    create_with_retry_on_number_collision,
    decide_vote,
    delegated_pending_votes,
    display_version,
    effective_role_has_action,
    enforce_approval_change_freeze,
    enforce_passkey_attempt_limit,
    escape_like,
    issue_mobile_session,
    ldap_authenticate,
    log_field_changes,
    log_history,
    mobile_client_details,
    next_enterprise_number,
    next_operational_task_number,
    normalize_environment,
    normalize_ticket_category,
    normalize_ticket_subcategory,
    passkey_configuration,
    post_ticket_comment,
    queue_workflow_event,
    require_api_scope,
    role_at_least,
    route_rate_limit,
    setting_bool,
    setting_int,
    store_api_idempotency,
    tenant_query,
    tenant_record_or_404,
    ticket_team_agents,
    ticket_workflow_context,
    transition_operational_task,
    transition_ticket,
    UNCATEGORISED,
    user_can_manage_ticket,
    verify_mfa_code,
    visible_ticket_query,
)
from serviceops_core import mcp as mcp_protocol
from serviceops_core.ci_class_policy import ci_class_action_allowed, restrict_ci_query_to_readable_classes
from serviceops_core.mcp_tools import TOOLS as MCP_TOOLS
from serviceops_core.passkeys import (
    authentication_options as build_passkey_authentication_options,
    registration_options as build_passkey_registration_options,
    verify_registration as verify_passkey_registration,
)
from serviceops_core.projections import project_document
from serviceops_core.security import hash_password, verify_and_upgrade_password
from serviceops_core.web.common import mobile_only, require_scim_admin, scim_user_document
from serviceops_models import (
    APIClient,
    ApprovalChain,
    ApprovalGate,
    ApprovalVote,
    ConfigurationItem,
    db,
    EnterpriseRecord,
    ExternalIdentity,
    FileAttachment,
    GroupMember,
    GuidedTour,
    Knowledge,
    MobilePushDevice,
    MonitoringEvent,
    MonitoringSource,
    Notification,
    now,
    OperationalTask,
    PasskeyChallenge,
    PasskeyCredential,
    PlatformSetting,
    settings_cipher,
    SupportGroup,
    Ticket,
    TicketAssignmentGroup,
    User,
    UserRoleGrant,
    UserSession,
    UserTourProgress,
)
from serviceops_core.localization import tr


def scim_error(status, detail, scim_type="invalidValue"):
    abort(Response(json.dumps({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status), "scimType": scim_type, "detail": detail,
    }), status=status, mimetype="application/scim+json"))


def scim_body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        scim_error(400, "A JSON object is required.")
    return body


def scim_attributes(body):
    """Validate before mutating a user, including every operation in a PATCH."""
    values = {}
    if "active" in body:
        if not isinstance(body["active"], bool):
            scim_error(400, "active must be a JSON boolean.")
        values["active"] = body["active"]
    if "displayName" in body:
        if not isinstance(body["displayName"], str) or not body["displayName"].strip():
            scim_error(400, "displayName must be a nonempty string.")
        values["name"] = body["displayName"].strip()[:120]
    if "emails" in body:
        emails = body["emails"]
        if not isinstance(emails, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("value"), str)
            or not item["value"].strip() for item in emails
        ):
            scim_error(400, "emails must be an array of objects with nonempty string values.")
        if emails:
            values["email"] = emails[0]["value"].strip()[:160]
    return values


def scim_patch_attributes(body):
    operations = body.get("Operations")
    if not isinstance(operations, list) or not operations:
        scim_error(400, "Operations must be a nonempty array.")
    values = {}
    for operation in operations:
        if not isinstance(operation, dict) or not isinstance(operation.get("op"), str):
            scim_error(400, "Each operation must be an object with an op string.")
        if operation["op"].lower() not in {"add", "replace"}:
            scim_error(400, "Only add and replace operations are supported.")
        if "value" not in operation:
            scim_error(400, "Each operation requires a value.")
        if "path" in operation:
            path = operation["path"]
            if not isinstance(path, str) or path not in {"active", "displayName", "emails"}:
                scim_error(400, "Unsupported attribute path.", "invalidPath")
            attributes = {path: operation["value"]}
        else:
            attributes = operation["value"]
            if not isinstance(attributes, dict) or not attributes:
                scim_error(400, "A pathless operation requires an attribute object.")
            if attributes.keys() - {"active", "displayName", "emails"}:
                scim_error(400, "Unsupported attribute in pathless operation.", "invalidPath")
        values.update(scim_attributes(attributes))
    return values


def scim_check_email(email, user_id=None):
    query = User.query.filter(func.lower(User.email) == email.lower())
    if user_id is not None:
        query = query.filter(User.id != user_id)
    if query.first():
        scim_error(409, "A user with that email already exists.", "uniqueness")


@contextmanager
def scim_transaction():
    try:
        yield
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        # PostgreSQL and SQLite report unique violations differently. Do not
        # disguise unrelated integrity failures as a provisioning conflict.
        if getattr(exc.orig, "sqlstate", None) == "23505" or "UNIQUE constraint failed" in str(exc.orig):
            scim_error(409, "A user with those unique attributes already exists.", "uniqueness")
        raise


def register(app):
    @app.get("/api/v1/openapi.json")
    def api_openapi():
        return jsonify({
            "openapi": "3.1.0",
            "info": {
                "title": "ServiceOps REST API",
                "version": "1.0.0",
                "description": (
                    "Tenant-aware ServiceOps REST contract. API scopes never "
                    "bypass the acting user's role, team, lifecycle, or field policy."
                ),
            },
            "servers": [{"url": "/api/v1"}],
            "externalDocs": {
                "description": "Interactive API guide",
                "url": "/api/v1/docs",
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http", "scheme": "bearer",
                        "description": "One-time sop_ API-client token.",
                    },
                    "monitoringToken": {
                        "type": "http", "scheme": "bearer",
                        "description": "Token issued for one monitoring source.",
                    },
                },
                "parameters": {
                    "RequestId": {
                        "name": "X-Request-ID", "in": "header", "required": False,
                        "schema": {"type": "string", "format": "uuid"},
                    },
                    "IdempotencyKey": {
                        "name": "Idempotency-Key", "in": "header", "required": True,
                        "schema": {
                            "type": "string", "minLength": 1, "maxLength": 128,
                            "pattern": "^[A-Za-z0-9._:-]+$",
                        },
                    },
                },
            },
            "security": [{"bearerAuth": []}],
            "paths": {
                "/auth/mobile/login": {"post": {
                    "summary": "Authenticate a native mobile user",
                    "security": [],
                    "description": "Local or LDAP credentials with MFA when enabled; requires mobile client metadata headers.",
                }},
                "/auth/mobile/refresh": {"post": {
                    "summary": "Rotate a mobile access and refresh token",
                    "security": [],
                }},
                "/auth/mobile/logout": {"post": {
                    "summary": "Revoke the authenticated mobile session",
                }},
                "/auth/passkeys/register/options": {"post": {
                    "summary": "Issue an authenticated mobile passkey registration challenge",
                }},
                "/auth/passkeys/register/complete": {"post": {
                    "summary": "Verify and store a mobile passkey",
                }},
                "/auth/passkeys/authenticate/options": {"post": {
                    "summary": "Issue a discoverable passkey authentication challenge",
                    "security": [],
                }},
                "/auth/passkeys/authenticate/complete": {"post": {
                    "summary": "Verify a passkey and issue a mobile user session",
                    "security": [],
                }},
                "/auth/passkeys": {"get": {
                    "summary": "List the authenticated mobile user's passkeys",
                }},
                "/auth/passkeys/{credential_id}": {"delete": {
                    "summary": "Revoke one passkey owned by the authenticated mobile user",
                }},
                "/openapi.json": {
                    "get": {"summary": "OpenAPI contract", "security": []}
                },
                "/docs": {
                    "get": {"summary": "Complete Markdown API guide", "security": []}
                },
                "/tickets": {"get": {
                    "summary": "List visible incidents and changes",
                    "description": "Requires tickets:read. Cursor limit is 1-100.",
                    "parameters": [
                        {"$ref": "#/components/parameters/RequestId"},
                        {"name": "type", "in": "query", "schema": {
                            "type": "string", "enum": ["incident", "change"]
                        }},
                        {"name": "state", "in": "query", "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "schema": {
                            "type": "integer", "minimum": 1, "maximum": 100,
                            "default": 50,
                        }},
                        {"name": "cursor", "in": "query", "schema": {
                            "type": "integer", "minimum": 0, "default": 0,
                        }},
                    ],
                }},
                "/tickets/{number}": {
                    "parameters": [{"name": "number", "in": "path", "required": True,
                                    "schema": {"type": "string"}}],
                    "get": {
                        "summary": "Get a visible ticket",
                        "description": "Requires tickets:read.",
                    },
                    "patch": {
                        "summary": "Update an authorized owning-team ticket",
                        "description": (
                            "Requires tickets:update and an acting user with update, "
                            "assign, transition, and owning-team authority. Fields: state, "
                            "priority, assigned_to_id, resolution_notes, closure_category and "
                            "closure_subcategory (incidents; the categorisation at closure, "
                            "kept separate from the logging category). Resolution fields are "
                            "applied before the state change; when omitted on resolution the "
                            "closure category defaults to the logging category."
                        ),
                        "parameters": [{"$ref": "#/components/parameters/IdempotencyKey"}],
                    },
                },
                "/mcp": {
                    "post": {
                        "summary": "Model Context Protocol server (Streamable HTTP, JSON responses)",
                        "description": (
                            "One JSON-RPC 2.0 message per request: initialize, ping, tools/list, "
                            "tools/call. Requires mcp:access; each read-only tool also needs its "
                            "scope (tickets:read, cmdb:read, knowledge:read, approvals:read) and "
                            "tools/list shows only those granted. Stateless: GET/DELETE return 405."
                        ),
                    },
                },
                "/tickets/{number}/attachments": {
                    "parameters": [{"name": "number", "in": "path", "required": True,
                                    "schema": {"type": "string"}}],
                    "get": {
                        "summary": "List attachments on a visible ticket",
                        "description": (
                            "Requires tickets:read. Returns mobile-compatible metadata "
                            "and an authenticated relative downloadURL for each file."
                        ),
                    },
                },
                "/tickets/{number}/attachments/{attachment_id}/download": {
                    "parameters": [
                        {"name": "number", "in": "path", "required": True,
                         "schema": {"type": "string"}},
                        {"name": "attachment_id", "in": "path", "required": True,
                         "schema": {"type": "integer"}},
                    ],
                    "get": {
                        "summary": "Download an attachment from a visible ticket",
                        "description": (
                            "Requires tickets:read and streams the file from local, "
                            "object, or IPFS storage with private no-store caching."
                        ),
                    },
                },
                "/tickets/{number}/workflow-events": {
                    "parameters": [{"name": "number", "in": "path", "required": True,
                                    "schema": {"type": "string"}}],
                    "post": {
                        "summary": "Queue an authorized durable workflow event",
                        "description": "Requires workflows:execute.",
                        "parameters": [{"$ref": "#/components/parameters/IdempotencyKey"}],
                    },
                },
                "/incidents": {"post": {
                    "summary": "Create an incident",
                    "description": "Requires incidents:create.",
                    "parameters": [{"$ref": "#/components/parameters/IdempotencyKey"}],
                }},
                "/monitoring/{source_id}/events": {
                    "parameters": [{"name": "source_id", "in": "path", "required": True,
                                    "schema": {"type": "string", "format": "uuid"}}],
                    "post": {
                        "summary": "Ingest and deduplicate a monitoring event",
                        "security": [{"monitoringToken": []}],
                    },
                },
                "/monitoring/{source_id}/backup-report": {
                    "parameters": [{"name": "source_id", "in": "path", "required": True,
                                    "schema": {"type": "string", "format": "uuid"}}],
                    "post": {
                        "summary": "Record a successful backup for System Health's recovery-set status",
                        "description": (
                            "Routine, not an incident -- unlike /monitoring/{source_id}/events, "
                            "this never creates a record; it only updates the recovery-set "
                            "timestamp an external backup job (Kubernetes CronJob, cron, a "
                            "managed snapshot pipeline) reports after each successful run."
                        ),
                        "security": [{"monitoringToken": []}],
                    },
                },
                "/cmdb/configuration-items": {
                    "put": {
                        "summary": "Create or update a configuration item by name",
                        "description": (
                            "Requires cmdb:write. Idempotent by name within the "
                            "acting API client's tenant — safe to call on every "
                            "agent/cron run; no Idempotency-Key needed."
                        ),
                    },
                },
            },
        })

    @app.post("/api/v1/auth/mobile/login")
    def api_mobile_login():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        provider = str(body.get("provider", "local"))
        if provider not in {"local", "ldap"}:
            abort(400, description=tr("provider must be local or ldap."))
        ip = request.remote_addr or "unknown"
        allowed = route_rate_limit("mobile_login", f"ip:{ip}", setting_int("LOGIN_RATE_LIMIT_PER_IP_PER_MINUTE", 20))
        if username:
            allowed = route_rate_limit("mobile_login", f"user:{username.lower()}", setting_int("LOGIN_RATE_LIMIT_PER_ACCOUNT_PER_MINUTE", 10)) and allowed
        db.session.commit()
        if not allowed:
            abort(429, description=tr("Too many sign-in attempts. Try again later."))
        user = None
        candidate = User.query.filter_by(username=username).first()
        if candidate and candidate.locked_until and align_tz(candidate.locked_until, now()) > now():
            audit("login_blocked", candidate.username, "provider=mobile; reason=locked", user_id=candidate.id, tenant_id=candidate.tenant_id)
            db.session.commit()
            abort(423, description=tr("This account is temporarily locked."))
        if provider == "ldap" and setting_bool("LDAP_ENABLED"):
            try:
                user = ldap_authenticate(username, password)
            except Exception:
                app.logger.exception("Mobile LDAP authentication failed")
        elif provider == "local" and setting_bool("LOCAL_AUTH_ENABLED", True):
            if candidate:
                valid, upgraded = verify_and_upgrade_password(candidate.password_hash, password)
                if valid:
                    user = candidate
                    if upgraded:
                        user.password_hash = upgraded
        if not user or not user.active:
            if candidate:
                candidate.failed_login_count = (candidate.failed_login_count or 0) + 1
                maximum = setting_int("LOGIN_MAX_ATTEMPTS", 5)
                if candidate.failed_login_count >= maximum:
                    candidate.failed_login_count = 0
                    candidate.locked_until = now() + timedelta(minutes=setting_int("LOGIN_LOCKOUT_MINUTES", 15))
                    audit("login_locked", candidate.username, f"provider=mobile; attempts={maximum}", user_id=candidate.id, tenant_id=candidate.tenant_id)
                else:
                    audit("login_failed", candidate.username, f"provider=mobile; attempts={candidate.failed_login_count}", user_id=candidate.id, tenant_id=candidate.tenant_id)
                db.session.commit()
            abort(401, description=tr("Invalid username or password."))
        verified, backup_used = verify_mfa_code(user, body.get("mfa_code"))
        if not verified:
            audit("login_failed", user.username, "provider=mobile; reason=mfa_required_or_invalid", user_id=user.id, tenant_id=user.tenant_id)
            db.session.commit()
            abort(401, description=tr("A valid MFA or backup code is required."))
        user.failed_login_count = 0
        user.locked_until = None
        access, refresh = issue_mobile_session(user, "password", backup_used)
        db.session.commit()
        return jsonify({"access_token": access, "refresh_token": refresh, "expires_in": 900,
                        "user": {"id": user.id, "username": user.username, "name": user.name}})

    @app.post("/api/v1/auth/passkeys/register/options")
    def api_passkey_registration_options():
        if g.api_client.client_kind != "mobile":
            abort(403, description=tr("A mobile user session is required."))
        rp_id, _ = passkey_configuration()
        PasskeyChallenge.query.filter(
            PasskeyChallenge.expires_at <= now(),
            PasskeyChallenge.user_id == g.api_user.id,
        ).delete(synchronize_session=False)
        credentials = PasskeyCredential.query.filter_by(
            tenant_id=g.api_user.tenant_id, user_id=g.api_user.id,
        ).all()
        options, payload = build_passkey_registration_options(
            rp_id=rp_id, rp_name=os.getenv("WEBAUTHN_RP_NAME", "ServiceOps"),
            user=g.api_user, credentials=credentials,
        )
        challenge = PasskeyChallenge(
            challenge=options.challenge, purpose="registration", user_id=g.api_user.id,
            tenant_id=g.api_user.tenant_id, expires_at=now() + timedelta(minutes=5),
        )
        db.session.add(challenge)
        db.session.commit()
        return jsonify({"challenge_id": challenge.id, "options": payload})

    @app.post("/api/v1/auth/passkeys/register/complete")
    def api_passkey_registration_complete():
        if g.api_client.client_kind != "mobile":
            abort(403, description=tr("A mobile user session is required."))
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        challenge = consume_passkey_challenge(
            str(body.get("challenge_id") or body.get("challengeId") or ""), "registration",
        )
        if challenge.user_id != g.api_user.id or challenge.tenant_id != g.api_user.tenant_id:
            abort(403, description=tr("The passkey challenge belongs to another identity."))
        challenge_bytes = challenge.challenge
        db.session.commit()  # Consume before cryptographic verification to prevent replay.
        rp_id, origin = passkey_configuration()
        try:
            verified = verify_passkey_registration(
                credential=body.get("credential") or {}, challenge=challenge_bytes,
                rp_id=rp_id, origin=origin,
            )
        except Exception:
            abort(400, description=tr("Passkey registration verification failed."))
        if PasskeyCredential.query.filter_by(credential_id=verified.credential_id).first():
            abort(409, description=tr("This passkey is already registered."))
        name = str(body.get("name") or "iPhone passkey").strip()[:120] or "iPhone passkey"
        credential = body.get("credential")
        response = credential.get("response") if isinstance(credential, dict) else None
        transports = response.get("transports", []) if isinstance(response, dict) else None
        if not isinstance(transports, list) or not all(isinstance(value, str) for value in transports):
            abort(400, description=tr("Passkey transports must be a list of strings."))
        row = PasskeyCredential(
            credential_id=verified.credential_id, public_key=verified.credential_public_key,
            sign_count=verified.sign_count, name=name, transports_json=json.dumps(transports),
            user_id=g.api_user.id, tenant_id=g.api_user.tenant_id,
        )
        db.session.add(row)
        audit("passkey registered", g.api_user.username, f"passkey={name}; channel=mobile",
              user_id=g.api_user.id, tenant_id=g.api_user.tenant_id)
        db.session.commit()
        return jsonify({"id": row.id, "name": row.name}), 201

    @app.get("/api/v1/auth/passkeys")
    def api_passkeys_list():
        if g.api_client.client_kind != "mobile":
            abort(403, description=tr("A mobile user session is required."))
        rows = PasskeyCredential.query.filter_by(
            tenant_id=g.api_user.tenant_id, user_id=g.api_user.id,
        ).order_by(PasskeyCredential.created_at.desc()).all()
        return jsonify({"data": [{
            "id": row.id, "name": row.name,
            "created_at": row.created_at.isoformat(),
            "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        } for row in rows]})

    @app.delete("/api/v1/auth/passkeys/<int:credential_id>")
    def api_passkey_delete(credential_id):
        if g.api_client.client_kind != "mobile":
            abort(403, description=tr("A mobile user session is required."))
        row = PasskeyCredential.query.filter_by(
            id=credential_id, tenant_id=g.api_user.tenant_id, user_id=g.api_user.id,
        ).first_or_404()
        audit("passkey revoked", g.api_user.username, f"passkey={row.name}; channel=mobile",
              user_id=g.api_user.id, tenant_id=g.api_user.tenant_id)
        db.session.delete(row)
        db.session.commit()
        return "", 204

    @app.post("/api/v1/auth/passkeys/authenticate/options")
    def api_passkey_authentication_options():
        enforce_passkey_attempt_limit()
        rp_id, _ = passkey_configuration()
        PasskeyChallenge.query.filter(
            PasskeyChallenge.expires_at <= now(),
            PasskeyChallenge.purpose == "authentication",
        ).delete(synchronize_session=False)
        options, payload = build_passkey_authentication_options(rp_id=rp_id)
        challenge = PasskeyChallenge(
            challenge=options.challenge, purpose="authentication",
            expires_at=now() + timedelta(minutes=5),
        )
        db.session.add(challenge)
        db.session.commit()
        return jsonify({"challenge_id": challenge.id, "options": payload})

    @app.post("/api/v1/auth/passkeys/authenticate/complete")
    def api_passkey_authentication_complete():
        enforce_passkey_attempt_limit()
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        challenge = consume_passkey_challenge(
            str(body.get("challenge_id") or body.get("challengeId") or ""), "authentication",
        )
        credential = body.get("credential")
        if not isinstance(credential, dict) or not isinstance(credential.get("response"), dict):
            abort(400, description=tr("A passkey credential object with a response object is required."))
        try:
            credential_id = base64url_to_bytes(str(credential.get("rawId") or credential.get("id") or ""))
        except Exception:
            abort(400, description=tr("The passkey credential identifier is invalid."))
        stored = PasskeyCredential.query.filter_by(credential_id=credential_id).first()
        if not stored or not stored.user.active or stored.user.tenant_id != stored.tenant_id:
            abort(401, description=tr("The passkey is not registered or its user is inactive."))
        challenge_bytes = challenge.challenge
        db.session.commit()  # Consume before cryptographic verification to prevent replay.
        rp_id, origin = passkey_configuration()
        try:
            verified = core.verify_passkey_authentication(
                credential=credential, challenge=challenge_bytes, rp_id=rp_id,
                origin=origin, stored=stored,
            )
        except Exception:
            abort(401, description=tr("Passkey authentication failed."))
        stored.sign_count = verified.new_sign_count
        stored.last_used_at = now()
        access, refresh = issue_mobile_session(stored.user, "passkey")
        db.session.commit()
        return jsonify({"access_token": access, "refresh_token": refresh, "expires_in": 900,
                        "user": {"id": stored.user.id, "username": stored.user.username,
                                 "name": stored.user.name}})

    @app.get("/.well-known/apple-app-site-association")
    def apple_app_site_association():
        app_id = os.getenv("APPLE_PASSKEY_APP_ID", "").strip()
        if not app_id:
            abort(404)
        return jsonify({"webcredentials": {"apps": [app_id]}})

    @app.post("/api/v1/auth/mobile/refresh")
    def api_mobile_refresh():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        raw = str(body.get("refresh_token", ""))
        digest = api_token_hash(raw) if raw.startswith("sor_") else ""
        row = APIClient.query.filter_by(refresh_token_hash=digest, client_kind="mobile", active=True).first()
        if not row or not hmac.compare_digest(row.refresh_token_hash or "", digest) or align_tz(row.refresh_expires_at, now()) <= now() or not account_usable(row.acting_user):
            abort(401, description=tr("The mobile refresh token is invalid, expired, or revoked."))
        if row.auth_version != row.acting_user.auth_version:
            end_stale_mobile_session(row)
            abort(401, description=tr("The mobile session ended because the account's credentials changed."))
        access = f"som_{secrets.token_urlsafe(32)}"
        refresh = f"sor_{secrets.token_urlsafe(48)}"
        row.token_hash = api_token_hash(access)
        row.token_prefix = access[:12]
        row.refresh_token_hash = api_token_hash(refresh)
        row.access_expires_at = now() + timedelta(minutes=15)
        row.last_used_at = now()
        audit("mobile token refresh", row.acting_user.username, mobile_client_details(row), user_id=row.acting_user_id, tenant_id=row.tenant_id)
        db.session.commit()
        return jsonify({"access_token": access, "refresh_token": refresh, "expires_in": 900})

    @app.post("/api/v1/auth/mobile/logout")
    def api_mobile_logout():
        if g.api_client.client_kind != "mobile":
            abort(403, description=tr("A mobile user session is required."))
        g.api_client.active = False
        g.api_client.revoked_at = now()
        g.api_client.refresh_token_hash = None
        audit("mobile logout", g.api_user.username, mobile_client_details(g.api_client), user_id=g.api_user.id, tenant_id=g.api_client.tenant_id)
        db.session.commit()
        return "", 204

    @app.get("/api/v1/docs")
    def api_docs():
        # Self-contained so the reference never depends on the private
        # serviceops-notes repo (not publicly reachable) or a copy of
        # API_REFERENCE.md baked into this repo's git history, which
        # CLAUDE.md's documentation-control policy keeps out of here.
        # Renders the always-in-sync /api/v1/openapi.json via Swagger UI,
        # vendored (no CDN) so it also works with no internet egress.
        return render_template("api_docs.html", app_version=display_version())

    @app.post("/api/v1/monitoring/<source_id>/events")
    def monitoring_ingest(source_id):
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            abort(401, description=tr("A monitoring bearer token is required."))
        token = authorization[7:].strip()
        source = MonitoringSource.query.filter_by(
            source_id=source_id, active=True
        ).first()
        token_hash = api_token_hash(token) if token else ""
        if (
            not source or not token_hash
            or not hmac.compare_digest(source.token_hash, token_hash)
        ):
            abort(401, description=tr("The monitoring token is invalid or revoked."))
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        required = {"external_id", "severity", "resource", "summary"}
        if not required.issubset(body):
            abort(400, description=(
                tr("external_id, severity, resource and summary are required.")
            ))
        external_id = str(body["external_id"]).strip()
        severity = str(body["severity"]).strip().lower()
        resource = str(body["resource"]).strip()
        summary = str(body["summary"]).strip()
        if (
            not external_id or len(external_id) > 200
            or severity not in {"critical", "high", "medium", "low", "info"}
            or not resource or len(resource) > 255
            or not summary or len(summary) > 500
        ):
            abort(400, description=tr("Monitoring event fields are invalid."))
        existing = MonitoringEvent.query.filter_by(
            monitoring_source_id=source.id, external_id=external_id
        ).first()
        if existing:
            return jsonify({
                "data": project_document("monitoring_ack", "monitoring_source", {
                    "event_id": existing.id,
                    "record_number": existing.record.number,
                    "deduplicated": True,
                })
            })
        priority = {
            "critical": "P1", "high": "P2", "medium": "P3",
            "low": "P4", "info": "P4",
        }[severity]
        record = EnterpriseRecord(
            number=next_enterprise_number("event"),
            domain="event", record_type="Infrastructure event",
            title=summary, description=json.dumps(body, indent=2, sort_keys=True),
            state="New", priority=priority, risk=severity.title(),
            requester_id=source.created_by_id,
            metadata_json=json.dumps({
                "monitoring_source_id": source.source_id,
                "external_id": external_id,
                "resource": resource,
            }, sort_keys=True),
            tenant_id=source.tenant_id,
        )
        db.session.add(record)
        db.session.flush()
        event = MonitoringEvent(
            monitoring_source_id=source.id, external_id=external_id,
            severity=severity, resource=resource, summary=summary,
            payload_json=json.dumps(body, sort_keys=True),
            enterprise_record_id=record.id, tenant_id=source.tenant_id,
        )
        db.session.add(event)
        def build_task():
            task = OperationalTask(
                number=next_operational_task_number("event"),
                task_kind="event", parent_type="enterprise", parent_id=record.id,
                title=f"Investigate {resource}", task_type="Investigation",
                assignment_group_id=source.assignment_group_id, required=True,
            )
            db.session.add(task)
            return task
        create_with_retry_on_number_collision(build_task)
        source.last_seen_at = now()
        audit(
            "monitoring ingest", record.number,
            f"source={source.source_id}; external_id={external_id}",
            user_id=source.created_by_id, tenant_id=source.tenant_id,
        )
        db.session.commit()
        return jsonify({
            "data": project_document("monitoring_ack", "monitoring_source", {
                "event_id": event.id,
                "record_number": record.number,
                "deduplicated": False,
            })
        }), 201

    @app.post("/api/v1/monitoring/<source_id>/backup-report")
    def monitoring_backup_report(source_id):
        # A narrow sibling of monitoring_ingest(): a daily backup succeeding
        # is routine, not an incident, so unlike that endpoint this never
        # creates an EnterpriseRecord -- it only updates the same
        # PlatformSetting rows tools/record_backup_status.py already writes
        # for the Compose/RPM install path, so System Health's "Recovery
        # set" widget (see _recovery_set_status()) is accurate for a
        # Kubernetes deployment's backup CronJob too, without needing the
        # full application image (with database credentials and every
        # Python dependency) inside that job just to run one CLI script.
        # Reuses the same MonitoringSource credential a deployment already
        # created for backup-failure alerting -- no separate credential
        # type to manage.
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            abort(401, description=tr("A monitoring bearer token is required."))
        token = authorization[7:].strip()
        source = MonitoringSource.query.filter_by(
            source_id=source_id, active=True
        ).first()
        token_hash = api_token_hash(token) if token else ""
        if (
            not source or not token_hash
            or not hmac.compare_digest(source.token_hash, token_hash)
        ):
            abort(401, description=tr("The monitoring token is invalid or revoked."))
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        manifest = str(body.get("manifest", "")).strip()
        offsite = str(body.get("offsite", "")).strip()
        if not manifest or len(manifest) > 500 or offsite not in ("archived", "not-configured"):
            abort(400, description=(
                tr("manifest (non-empty, max 500 chars) and offsite (archived or not-configured) are required.")
            ))
        values = {
            "LAST_BACKUP_AT": now().isoformat(),
            "LAST_BACKUP_MANIFEST": manifest,
            "LAST_BACKUP_OFFSITE_STATUS": offsite,
        }
        for key, value in values.items():
            row = db.session.get(PlatformSetting, key)
            if row:
                row.value = value
            else:
                db.session.add(PlatformSetting(key=key, value=value))
        source.last_seen_at = now()
        audit(
            "backup report", manifest, f"source={source.source_id}; offsite={offsite}",
            user_id=source.created_by_id, tenant_id=source.tenant_id,
        )
        db.session.commit()
        return jsonify({
            "data": project_document("backup_report_ack", "monitoring_source", {
                "recorded_at": values["LAST_BACKUP_AT"],
            })
        }), 201

    @app.get("/api/v1/tickets")
    def api_tickets():
        require_api_scope("tickets:read")
        user = g.api_user
        query = visible_ticket_query(user)
        kind = request.args.get("type", "").strip()
        state = request.args.get("state", "").strip()
        if kind:
            if kind not in ("incident", "change"):
                abort(400, description=tr("type must be incident or change."))
            query = query.filter(Ticket.kind == kind)
        if state:
            query = query.filter(Ticket.state == state)
        try:
            limit = min(max(int(request.args.get("limit", "50")), 1), 100)
            cursor = int(request.args.get("cursor", "0"))
        except ValueError:
            abort(400, description=tr("limit and cursor must be integers."))
        rows = query.filter(Ticket.id > cursor).order_by(Ticket.id).limit(
            limit + 1
        ).all()
        page = rows[:limit]
        return jsonify({
            "data": [api_ticket_document(row, user) for row in page],
            "meta": {
                "limit": limit,
                "next_cursor": page[-1].id if len(rows) > limit and page else None,
                "request_id": g.request_id,
            },
        })

    @app.get("/api/v1/tickets/<number>")
    def api_ticket_get(number):
        require_api_scope("tickets:read")
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first()
        if not ticket:
            abort(404, description=tr("The requested ticket was not found."))
        return jsonify({"data": api_ticket_document(ticket, g.api_user)})

    @app.get("/api/v1/mobile/tickets/<number>/attachments")
    @app.get("/api/v1/tickets/<number>/attachments")
    def api_ticket_attachments(number):
        require_api_scope("tickets:read")
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first_or_404()
        rows = FileAttachment.query.filter_by(
            ticket_id=ticket.id, tenant_id=ticket.tenant_id,
        ).order_by(FileAttachment.created_at, FileAttachment.id).all()
        return jsonify({
            "data": [api_attachment_document(row, ticket.number) for row in rows],
            "meta": {"count": len(rows), "request_id": g.request_id},
        })

    @app.get("/api/v1/tickets/<number>/ctasks")
    def api_ticket_ctasks(number):
        require_api_scope("tickets:read")
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first_or_404()
        if ticket.kind != "change":
            abort(400, description=tr("CTASKs are only available for change tickets."))
        rows = OperationalTask.query.filter_by(
            parent_type="ticket", parent_id=ticket.id, task_kind="change",
        ).order_by(OperationalTask.sequence, OperationalTask.id).all()
        return jsonify({
            "data": [api_ctask_document(row) for row in rows],
            "meta": {"count": len(rows), "request_id": g.request_id},
        })

    @app.patch("/api/v1/tickets/<number>/ctasks/<ctask_number>")
    def api_ticket_ctask_update(number, ctask_number):
        require_api_scope("tickets:update")
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first_or_404()
        if ticket.kind != "change":
            abort(400, description=tr("CTASKs are only available for change tickets."))
        if not user_can_manage_ticket(g.api_user, ticket):
            abort(403, description=tr("The acting user cannot manage this ticket."))
        task = OperationalTask.query.filter_by(
            parent_type="ticket", parent_id=ticket.id, task_kind="change",
        ).filter(func.upper(OperationalTask.number) == ctask_number.upper()).first_or_404()
        key, request_hash, replay = api_idempotency_context()
        if replay:
            return replay
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not body:
            abort(400, description=tr("A non-empty JSON object is required."))
        if not effective_role_has_action(g.api_user.effective_role, "update", tenant_id=g.api_user.tenant_id):
            abort(403, description=tr("The acting user cannot update tasks."))
        if "state" in body and not effective_role_has_action(
            g.api_user.effective_role, "transition", tenant_id=g.api_user.tenant_id,
        ):
            abort(403, description=tr("The acting user cannot transition tasks."))
        allowed = {"state", "work_notes", "append_work_notes"}
        unknown = set(body) - allowed
        if unknown:
            abort(400, description=tr("Unknown fields: {unknown}.", unknown=', '.join(sorted(unknown))))
        before = {"state": task.state, "work notes": task.work_notes}
        if "state" in body:
            transition_operational_task(task, str(body["state"]))
        if "work_notes" in body:
            task.work_notes = str(body["work_notes"])[:2000]
        if "append_work_notes" in body:
            # Append-only evidence: an integration records what it did
            # without overwriting notes the owning team wrote. The newest
            # entries are kept when the 2000-character cap is reached.
            note = str(body["append_work_notes"]).strip()
            if not note:
                abort(400, description=tr("append_work_notes must not be empty."))
            stamp = now().strftime("%Y-%m-%d %H:%M UTC")
            entry = f"[{stamp} · {g.api_client.name}] {note}"
            existing = (task.work_notes or "").rstrip()
            combined = f"{existing}\n{entry}" if existing else entry
            task.work_notes = combined[-2000:]
        log_field_changes(task.parent_type, task.parent_id, before, {
            "state": task.state, "work notes": task.work_notes,
        }, event=f"{task.number} updated via REST API")
        document = {"data": api_ctask_document(task)}
        store_api_idempotency(key, request_hash, document, 200)
        audit(
            "api update", task.number, mobile_client_details(g.api_client),
            user_id=g.api_user.id, tenant_id=g.api_client.tenant_id,
        )
        db.session.commit()
        return jsonify(document)

    @app.get("/api/v1/mobile/tickets/<number>/attachments/<int:attachment_id>/download")
    @app.get("/api/v1/tickets/<number>/attachments/<int:attachment_id>/download")
    def api_ticket_attachment_download(number, attachment_id):
        require_api_scope("tickets:read")
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first_or_404()
        attachment = FileAttachment.query.filter_by(
            id=attachment_id, ticket_id=ticket.id, tenant_id=ticket.tenant_id,
        ).first_or_404()
        return attachment_file_response(attachment, inline=True)

    @app.post("/api/v1/incidents")
    def api_incident_create():
        require_api_scope("incidents:create")
        if not effective_role_has_action(g.api_user.role, "create", tenant_id=g.api_user.tenant_id):
            abort(403, description=tr("The acting user cannot create records."))
        key, request_hash, replay = api_idempotency_context()
        if replay:
            return replay
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        allowed = {"title", "description", "category", "priority", "assignment_group_id"}
        unknown = set(body) - allowed
        if unknown:
            abort(400, description=tr("Unknown fields: {unknown}.", unknown=', '.join(sorted(unknown))))
        for field in ("title", "description", "category", "priority"):
            if field in body and not isinstance(body[field], str):
                abort(400, description=tr("{field} must be a string.", field=field))
        title = body.get("title", "").strip()
        description = str(body.get("description", "")).strip()
        priority = str(body.get("priority", "P3"))
        if not title or len(title) > 180 or not description:
            abort(400, description=tr("title and description are required."))
        if priority not in ("P1", "P2", "P3", "P4"):
            abort(400, description=tr("priority must be P1, P2, P3 or P4."))
        if isinstance(body.get("assignment_group_id"), (bool, float)):
            abort(400, description=tr("assignment_group_id must be an integer."))
        try:
            group_id = int(body.get("assignment_group_id"))
        except (TypeError, ValueError):
            abort(400, description=tr("assignment_group_id is required."))
        group = core.team_groups(g.api_client.tenant_id).filter(SupportGroup.id == group_id).first()
        if not group:
            abort(400, description=tr("Select an active tenant team."))
        ticket = create_ticket_with_unique_number(
            "incident",
            title=title, description=description,
            category=normalize_ticket_category(g.api_client.tenant_id, str(body.get("category", UNCATEGORISED))[:80]),
            priority=priority, requester_id=g.api_user.id,
            tenant_id=g.api_client.tenant_id,
        )
        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=group.id))
        attach_slas("ticket", ticket.id, ticket.priority)
        log_history(
            "ticket", ticket.id, "Record created",
            details=f"{ticket.number} created through REST API and assigned to {group.name}.",
        )
        document = {"data": api_ticket_document(ticket, g.api_user)}
        store_api_idempotency(key, request_hash, document, 201)
        audit(
            "api create", ticket.number, mobile_client_details(g.api_client),
            user_id=g.api_user.id, tenant_id=g.api_client.tenant_id,
        )
        db.session.commit()
        return jsonify(document), 201

    @app.patch("/api/v1/tickets/<number>")
    def api_ticket_update(number):
        require_api_scope("tickets:update")
        for action in ("update", "assign", "transition"):
            if not effective_role_has_action(g.api_user.role, action, tenant_id=g.api_user.tenant_id):
                abort(403, description=tr("The acting user cannot perform {action}.", action=action))
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first()
        if not ticket:
            abort(404, description=tr("The requested ticket was not found."))
        if not user_can_manage_ticket(g.api_user, ticket):
            abort(403, description=tr("The acting user cannot manage this ticket."))
        key, request_hash, replay = api_idempotency_context()
        if replay:
            return replay
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not body:
            abort(400, description=tr("A non-empty JSON object is required."))
        allowed = {"state", "priority", "assigned_to_id", "resolution_notes", "closure_category", "closure_subcategory"}
        unknown = set(body) - allowed
        if unknown:
            abort(400, description=tr("Unknown fields: {unknown}.", unknown=', '.join(sorted(unknown))))
        before = {
            "state": ticket.state, "priority": ticket.priority,
            "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned",
            "resolution notes": ticket.resolution_notes or "",
            "closure category": ticket.closure_category or "",
            "closure subcategory": ticket.closure_subcategory or "",
        }
        # Applied before the state change so a resolving PATCH records them.
        if "resolution_notes" in body:
            ticket.resolution_notes = str(body["resolution_notes"] or "").strip()[:10000] or None
        if "closure_category" in body:
            if ticket.kind != "incident":
                abort(400, description=tr("closure_category applies to incidents only."))
            ticket.closure_category = normalize_ticket_category(
                g.api_user.tenant_id, str(body["closure_category"] or "")[:80],
            )
        if "closure_subcategory" in body:
            if not ticket.closure_category:
                abort(400, description=tr("closure_subcategory requires a closure_category."))
            ticket.closure_subcategory = normalize_ticket_subcategory(
                g.api_user.tenant_id, ticket.closure_category, str(body["closure_subcategory"] or "")[:80],
            ) or None
        if "state" in body:
            transition_ticket(ticket, str(body["state"]))
        if "priority" in body:
            priority = str(body["priority"])
            if priority not in ("P1", "P2", "P3", "P4"):
                abort(400, description=tr("priority must be P1, P2, P3 or P4."))
            ticket.priority = priority
        if "assigned_to_id" in body:
            assignee_id = body["assigned_to_id"]
            if assignee_id is not None:
                try:
                    assignee_id = int(assignee_id)
                except (TypeError, ValueError):
                    abort(400, description=tr("assigned_to_id must be an integer or null."))
                eligible_ids = {agent.id for agent in ticket_team_agents(ticket)}
                if assignee_id not in eligible_ids:
                    abort(400, description=tr("The assignee must belong to the owning team."))
            ticket.assignee_id = assignee_id
        log_field_changes("ticket", ticket.id, before, {
            "state": ticket.state, "priority": ticket.priority,
            "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned",
            "resolution notes": ticket.resolution_notes or "",
            "closure category": ticket.closure_category or "",
            "closure subcategory": ticket.closure_subcategory or "",
        }, event="REST API update")
        document = {"data": api_ticket_document(ticket, g.api_user)}
        store_api_idempotency(key, request_hash, document, 200)
        audit(
            "api update", ticket.number, mobile_client_details(g.api_client),
            user_id=g.api_user.id, tenant_id=g.api_client.tenant_id,
        )
        db.session.commit()
        return jsonify(document)

    @app.route("/api/v1/mcp", methods=["GET", "POST", "DELETE"])
    def api_mcp():
        """Embedded MCP server, Streamable HTTP transport with JSON responses.
        Stateless: no Mcp-Session-Id and no server-initiated SSE stream, so
        GET and DELETE are 405 as the transport allows."""
        require_api_scope("mcp:access")
        if request.method != "POST":
            return Response(status=405, headers={"Allow": "POST"})
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).netloc.lower() != request.host.lower():
            abort(403, description=tr("Cross-origin MCP requests are not accepted."))
        version = request.headers.get("MCP-Protocol-Version")
        if version and version not in mcp_protocol.SUPPORTED_PROTOCOL_VERSIONS:
            abort(400, description=tr("Unsupported MCP-Protocol-Version: {version}.", version=version))
        try:
            message = json.loads(request.get_data(as_text=True) or "")
        except ValueError:
            return jsonify({"jsonrpc": "2.0", "id": None,
                            "error": {"code": mcp_protocol.PARSE_ERROR, "message": "Invalid JSON."}}), 400
        response = mcp_protocol.handle_message(
            message, MCP_TOOLS, set(g.api_client.scopes), display_version(),
        )
        if isinstance(message, dict) and message.get("method") == "tools/call":
            # What an AI client read, and as whom, belongs in the audit trail.
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            audit(
                "mcp tool call", str(params.get("name", ""))[:80],
                f"client={g.api_client.name}; arguments={json.dumps(arguments, sort_keys=True)[:500]}",
                user_id=g.api_user.id, tenant_id=g.api_client.tenant_id,
            )
        db.session.commit()
        if response is None:
            return Response(status=202)
        return jsonify(response)

    @app.put("/api/v1/cmdb/configuration-items")
    def api_ci_upsert():
        require_api_scope("cmdb:write")
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        allowed = {"name", "ci_class", "environment", "operational_status", "ip_address"}
        unknown = set(body) - allowed
        if unknown:
            abort(400, description=tr("Unknown fields: {unknown}.", unknown=', '.join(sorted(unknown))))
        for field in allowed:
            if field in body and not isinstance(body[field], str):
                abort(400, description=tr("{field} must be a string.", field=field))
        for field, maximum in (("name", 160), ("ci_class", 80), ("ip_address", 60)):
            if len(body.get(field, "").strip()) > maximum:
                abort(400, description=tr("{field} must not exceed {maximum} characters.", field=field, maximum=maximum))
        name = body.get("name", "").strip()
        if not name:
            abort(400, description=tr("name is required."))
        environment = normalize_environment(str(body.get("environment", "Production")))
        if environment not in CANONICAL_ENVIRONMENTS:
            abort(400, description=tr("environment must be Production, Staging, Development or Test."))
        operational_status = str(body.get("operational_status", "Operational"))
        if operational_status not in ("Operational", "Degraded", "Down", "Maintenance", "Retired"):
            abort(400, description=tr("operational_status must be a recognized CI status."))
        ci_class = body.get("ci_class", "Server").strip() or "Server"
        ip_address = body.get("ip_address", "").strip() or None
        ci = ConfigurationItem.query.filter_by(name=name, tenant_id=g.api_client.tenant_id).first()
        created = ci is None
        # Same per-class policy the CMDB forms enforce, evaluated for the
        # acting user: create for a new CI; update on its current class and,
        # when the class changes, on the target class too.
        role = g.api_user.effective_role
        tenant_id = g.api_client.tenant_id
        if created and not ci_class_action_allowed(tenant_id, ci_class, role, "create"):
            abort(403, description=tr("The acting user may not create {ci_class} configuration items.", ci_class=ci_class))
        if not created and not ci_class_action_allowed(tenant_id, ci.ci_class, role, "update"):
            abort(403, description=tr("The acting user may not update {ci_class} configuration items.", ci_class=ci.ci_class))
        if not created and ci_class != ci.ci_class and not ci_class_action_allowed(tenant_id, ci_class, role, "update"):
            abort(403, description=tr("The acting user may not move this configuration item into {ci_class}.", ci_class=ci_class))
        if created:
            ci = ConfigurationItem(name=name, tenant_id=g.api_client.tenant_id, owner_id=g.api_user.id)
            db.session.add(ci)
        ci.ci_class = ci_class
        ci.environment = environment
        ci.operational_status = operational_status
        ci.ip_address = ip_address
        db.session.flush()
        document = {"data": {
            "id": ci.id, "name": ci.name, "ci_class": ci.ci_class,
            "environment": ci.environment, "operational_status": ci.operational_status,
            "ip_address": ci.ip_address, "created": created,
        }}
        audit(
            "api sync", "CI", f"{ci.name} via client={g.api_client.client_id}",
            user_id=g.api_user.id, tenant_id=g.api_client.tenant_id,
        )
        db.session.commit()
        return jsonify(document), 201 if created else 200

    @app.post("/api/v1/tickets/<number>/workflow-events")
    def api_workflow_event(number):
        require_api_scope("workflows:execute")
        if not effective_role_has_action(g.api_user.role, "transition", tenant_id=g.api_user.tenant_id):
            abort(403, description=tr("The acting user cannot execute workflows."))
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first()
        if not ticket:
            abort(404, description=tr("The requested ticket was not found."))
        if not user_can_manage_ticket(g.api_user, ticket):
            abort(403, description=tr("The acting user cannot manage this ticket."))
        key, request_hash, replay = api_idempotency_context()
        if replay:
            return replay
        body = request.get_json(silent=True)
        if body not in ({}, None) and not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        context = ticket_workflow_context(ticket)
        context["triggered_by"] = g.api_user.username
        job = queue_workflow_event(
            "ticket.api_trigger", "ticket", ticket.id, context,
            tenant_id=ticket.tenant_id,
        )
        db.session.flush()
        document = {"data": project_document("workflow_ack", g.api_user.role, {
            "event_id": job.event_id, "state": job.state,
            "ticket": ticket.number,
        })}
        store_api_idempotency(key, request_hash, document, 202)
        audit(
            "api workflow trigger", ticket.number,
            f"client={g.api_client.client_id}; event={job.event_id}",
            user_id=g.api_user.id, tenant_id=ticket.tenant_id,
        )
        db.session.commit()
        return jsonify(document), 202

    @app.get("/api/v1/mobile/bootstrap")
    def api_mobile_bootstrap():
        mobile_only()
        groups = SupportGroup.query.join(GroupMember).filter(
            SupportGroup.tenant_id == g.api_user.tenant_id,
            SupportGroup.active.is_(True), GroupMember.user_id == g.api_user.id,
        ).order_by(SupportGroup.name).all()
        if role_at_least(g.api_user.role, "manager"):
            groups = SupportGroup.query.filter_by(
                tenant_id=g.api_user.tenant_id, active=True,
            ).order_by(SupportGroup.name).all()
        pending_direct = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
            ApprovalVote.approver_id == g.api_user.id,
            ApprovalVote.state == "Requested",
            ApprovalChain.tenant_id == g.api_user.tenant_id,
        ).count()
        pending = pending_direct + len(delegated_pending_votes(g.api_user))
        unread = Notification.query.filter_by(
            tenant_id=g.api_user.tenant_id, user_id=g.api_user.id, read=False,
        ).count()
        return jsonify({"data": {
            "user": {"id": g.api_user.id, "username": g.api_user.username,
                     "name": g.api_user.name, "role": g.api_user.effective_role},
            "assignment_groups": [{"id": row.id, "name": row.name} for row in groups],
            "counts": {"pending_approvals": pending, "unread_notifications": unread},
            "capabilities": {
                "create_incident": effective_role_has_action(g.api_user.role, "create", tenant_id=g.api_user.tenant_id),
                "manage_tickets": effective_role_has_action(g.api_user.role, "update", tenant_id=g.api_user.tenant_id),
                "view_cmdb": role_at_least(g.api_user.effective_role, "agent"),
            },
        }})

    @app.post("/api/v1/mobile/push-devices")
    def api_mobile_push_register():
        mobile_only()
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        token = str(body.get("token", "")).strip().lower()
        device_id = str(body.get("device_id", "")).strip()
        environment = str(body.get("environment", "sandbox"))
        if not re.fullmatch(r"[0-9a-f]{64,200}", token):
            abort(400, description=tr("A valid APNs device token is required."))
        if not device_id or len(device_id) > 64 or environment not in {"sandbox", "production"}:
            abort(400, description=tr("A valid device_id and APNs environment are required."))
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = MobilePushDevice.query.filter_by(token_hash=token_hash).first()
        if row and (row.user_id != g.api_user.id or row.tenant_id != g.api_user.tenant_id):
            row.user_id = g.api_user.id
            row.tenant_id = g.api_user.tenant_id
            row.device_id = device_id
        if not row:
            row = MobilePushDevice(
                token_hash=token_hash, device_id=device_id,
                user_id=g.api_user.id, tenant_id=g.api_user.tenant_id,
                app_version=g.api_client.app_version, app_build=g.api_client.app_build,
                device_model=g.api_client.device_model,
            )
            db.session.add(row)
        row.token_encrypted = settings_cipher().encrypt(token.encode()).decode()
        row.environment = environment
        row.app_version = g.api_client.app_version
        row.app_build = g.api_client.app_build
        row.device_model = g.api_client.device_model
        row.enabled = True
        row.last_registered_at = now()
        row.last_error = None
        audit("mobile push registered", g.api_user.username, mobile_client_details(g.api_client),
              user_id=g.api_user.id, tenant_id=g.api_user.tenant_id)
        db.session.commit()
        return jsonify({"data": {"device_id": device_id, "enabled": True}}), 201

    @app.delete("/api/v1/mobile/push-devices/<device_id>")
    def api_mobile_push_unregister(device_id):
        mobile_only()
        MobilePushDevice.query.filter_by(
            tenant_id=g.api_user.tenant_id, user_id=g.api_user.id, device_id=device_id,
        ).update({"enabled": False})
        audit("mobile push unregistered", g.api_user.username, mobile_client_details(g.api_client),
              user_id=g.api_user.id, tenant_id=g.api_user.tenant_id)
        db.session.commit()
        return "", 204

    @app.get("/api/v1/mobile/notifications")
    def api_mobile_notifications():
        mobile_only()
        rows = Notification.query.filter_by(
            tenant_id=g.api_user.tenant_id, user_id=g.api_user.id,
        ).order_by(Notification.created_at.desc()).limit(100).all()
        return jsonify({"data": [{
            "id": row.id, "title": row.title, "body": row.body, "read": row.read,
            "created_at": row.created_at.isoformat(), "target_type": row.target_type,
            "target_id": row.target_id,
        } for row in rows]})

    @app.post("/api/v1/mobile/notifications/<int:notification_id>/read")
    def api_mobile_notification_read(notification_id):
        mobile_only()
        row = Notification.query.filter_by(
            id=notification_id, tenant_id=g.api_user.tenant_id, user_id=g.api_user.id,
        ).first_or_404()
        row.read = True
        db.session.commit()
        return jsonify({"data": {"id": row.id, "read": True}})

    @app.post("/api/v1/mobile/notifications/read-all")
    def api_mobile_notifications_read_all():
        mobile_only()
        Notification.query.filter_by(
            tenant_id=g.api_user.tenant_id, user_id=g.api_user.id, read=False,
        ).update({"read": True})
        db.session.commit()
        return "", 204

    @app.get("/api/v1/mobile/approvals")
    def api_mobile_approvals():
        mobile_only()
        direct_rows = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
            ApprovalVote.approver_id == g.api_user.id,
            ApprovalChain.tenant_id == g.api_user.tenant_id,
        ).order_by(ApprovalVote.id.desc()).limit(100).all()
        delegated_rows = delegated_pending_votes(g.api_user)
        rows = list({row.id: row for row in direct_rows + delegated_rows}.values())
        rows.sort(key=lambda row: row.id, reverse=True)
        return jsonify({"data": [{
            "id": row.id, "state": row.state, "comments": row.comments or "",
            "gate": row.gate.name, "chain": row.gate.chain.name,
            "target_type": row.gate.chain.target_type, "target_id": row.gate.chain.target_id,
            "delegated_for": (
                row.approver.name if row.approver_id != g.api_user.id else None
            ),
        } for row in rows[:100]]})

    @app.post("/api/v1/mobile/approvals/<int:vote_id>/decide")
    def api_mobile_approval_decide(vote_id):
        mobile_only()
        # A retried decide (client timeout/network retry after the first
        # attempt actually landed) must not re-run decide_vote() a second
        # time -- that could double-fire the gate-completion/notification
        # side effects, or fail outright against a vote already resolved.
        # Idempotency-Key replay is honored when sent, exactly like the
        # other mutating mobile/v1 endpoints in this file, but not required
        # -- unlike those, this endpoint's OpenAPI contract has never
        # documented it as required, so the shipped mobile app can't be
        # assumed to send one yet (see api_idempotency_context's docstring).
        key, request_hash, replay = api_idempotency_context(required=False)
        if replay:
            return replay
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description=tr("A JSON object is required."))
        decision = body.get("decision")
        if decision not in ("Approved", "Rejected"):
            abort(400, description=tr("decision must be Approved or Rejected."))
        vote = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
            ApprovalVote.id == vote_id,
            ApprovalChain.tenant_id == g.api_user.tenant_id,
        ).first_or_404()
        enforce_approval_change_freeze(vote, decision, g.api_user.tenant_id)
        if vote.approver_id != g.api_user.id:
            delegation = active_approval_delegation(vote.approver_id, g.api_user.id)
            if not delegation:
                abort(403)
            original_approver_id = vote.approver_id
            vote.approver_id = g.api_user.id
            vote.delegated_from_id = original_approver_id
        decide_vote(vote, decision, str(body.get("comments", "")).strip()[:2000])
        document = {"data": {
            "id": vote.id, "state": vote.state,
            "delegated_for": vote.delegated_from.name if vote.delegated_from else None,
        }}
        store_api_idempotency(key, request_hash, document, 200)
        audit("mobile approval " + decision.lower(), vote.gate.chain.name,
              mobile_client_details(g.api_client), user_id=g.api_user.id, tenant_id=g.api_user.tenant_id)
        db.session.commit()
        return jsonify(document)

    @app.get("/api/v1/mobile/knowledge")
    def api_mobile_knowledge():
        mobile_only()
        q = str(request.args.get("q", "")).strip()
        query = Knowledge.query.filter_by(
            tenant_id=g.api_user.tenant_id, published=True, archived=False,
        )
        if q:
            pattern = f"%{escape_like(q)}%"
            query = query.filter(or_(Knowledge.title.ilike(pattern, escape="\\"), Knowledge.body.ilike(pattern, escape="\\")))
        rows = query.order_by(Knowledge.created_at.desc()).limit(100).all()
        return jsonify({"data": [{"id": row.id, "title": row.title, "category": row.category,
                                  "body": row.body, "created_at": row.created_at.isoformat()} for row in rows]})

    @app.get("/api/v1/mobile/cmdb")
    def api_mobile_cmdb():
        mobile_only()
        if not role_at_least(g.api_user.effective_role, "agent"):
            abort(403, description=tr("CMDB mobile access requires the agent role."))
        q = str(request.args.get("q", "")).strip()
        query = restrict_ci_query_to_readable_classes(
            ConfigurationItem.query.filter_by(tenant_id=g.api_user.tenant_id),
            g.api_user.tenant_id, g.api_user.effective_role,
        )
        if q:
            pattern = f"%{escape_like(q)}%"
            query = query.filter(or_(ConfigurationItem.name.ilike(pattern, escape="\\"),
                                     ConfigurationItem.ip_address.ilike(pattern, escape="\\"),
                                     ConfigurationItem.serial_number.ilike(pattern, escape="\\")))
        rows = query.order_by(ConfigurationItem.name).limit(100).all()
        return jsonify({"data": [{"id": row.id, "name": row.name, "ci_class": row.ci_class,
                                  "environment": row.environment, "status": row.operational_status,
                                  "ip_address": row.ip_address} for row in rows]})

    @app.get("/api/v1/tickets/<number>/comments")
    def api_ticket_comments(number):
        require_api_scope("tickets:read")
        ticket = visible_ticket_query(g.api_user).filter(func.upper(Ticket.number) == number.upper()).first_or_404()
        return jsonify({"data": [{"id": row.id, "body": row.body, "author": row.author.name,
                                  "parent_id": row.parent_id,
                                  "created_at": row.created_at.isoformat()} for row in ticket.comments]})

    @app.post("/api/v1/tickets/<number>/comments")
    def api_ticket_comment_create(number):
        require_api_scope("tickets:update")
        ticket = visible_ticket_query(g.api_user).filter(func.upper(Ticket.number) == number.upper()).first_or_404()
        if not user_can_manage_ticket(g.api_user, ticket):
            abort(403, description=tr("The acting user cannot comment on this ticket."))
        # Optional, not required: unlike the mutating endpoints below whose
        # OpenAPI contract already documents Idempotency-Key as required,
        # this endpoint's contract never has, so an already-shipped client
        # can't be assumed to send one (see api_idempotency_context).
        key, request_hash, replay = api_idempotency_context(required=False)
        if replay:
            return replay
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            abort(400, description=tr("A JSON object is required."))
        body = str(payload.get("body", "")).strip()
        if not body or len(body) > 10000:
            abort(400, description=tr("A comment between 1 and 10000 characters is required."))
        parent_id = payload.get("parent_id")
        try:
            parent_id = int(parent_id) if parent_id not in (None, "") else None
        except (TypeError, ValueError):
            abort(400, description=tr("parent_id must be an integer comment identifier."))
        row = post_ticket_comment(ticket, g.api_user, body, parent_id=parent_id)
        log_history("ticket", ticket.id, "Comment added", details=f"Mobile app · {g.api_user.name}")
        document = {"data": {"id": row.id, "body": row.body, "author": g.api_user.name,
                              "created_at": row.created_at.isoformat()}}
        store_api_idempotency(key, request_hash, document, 201)
        audit("mobile comment", ticket.number, mobile_client_details(g.api_client),
              user_id=g.api_user.id, tenant_id=g.api_user.tenant_id)
        db.session.commit()
        return jsonify(document), 201

    @app.route("/scim/v2/Users", methods=["GET", "POST"])
    def scim_users():
        require_scim_admin()
        if request.method == "GET":
            query = User.query.filter_by(tenant_id=g.api_client.tenant_id)
            filter_value = request.args.get("filter", "")
            match = re.fullmatch(r'userName\s+eq\s+"([^"]+)"', filter_value, re.IGNORECASE)
            if filter_value and not match:
                abort(400, description=tr("Only the SCIM filter userName eq \"value\" is supported."))
            if match:
                query = query.filter(func.lower(User.username) == match.group(1).lower())
            rows = query.order_by(User.id).all()
            return jsonify(schemas=["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                           totalResults=len(rows), startIndex=1,
                           itemsPerPage=len(rows), Resources=[scim_user_document(user) for user in rows])
        body = scim_body()
        values = scim_attributes(body)
        if not isinstance(body.get("userName"), str):
            scim_error(400, "userName must be a string.")
        username = body["userName"].strip()[:80]
        email = values.get("email", "")
        name = values.get("name", username)
        if not username or not email:
            scim_error(400, "userName and an email value are required.")
        if User.query.filter(db.or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email.lower())).first():
            scim_error(409, "A user with that username or email already exists.", "uniqueness")
        user = User(
            username=username, email=email, name=name, active=values.get("active", True),
            employee_id=str(body.get("externalId", ""))[:80] or None,
            role="requester", tenant_id=g.api_client.tenant_id,
            password_hash=hash_password(secrets.token_urlsafe(48)),
        )
        with scim_transaction():
            db.session.add(user)
            db.session.flush()
            db.session.add(UserRoleGrant(user_id=user.id, role="requester"))
            db.session.add(ExternalIdentity(provider="scim", subject=str(body.get("externalId") or username), user_id=user.id))
            audit("scim create", user.username, f"client={g.api_client.client_id}",
                  user_id=g.api_user.id, tenant_id=user.tenant_id)
        return jsonify(scim_user_document(user)), 201

    @app.route("/scim/v2/Users/<int:user_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
    def scim_user(user_id):
        require_scim_admin()
        user = User.query.filter_by(id=user_id, tenant_id=g.api_client.tenant_id).first_or_404()
        if request.method == "GET":
            return jsonify(scim_user_document(user))
        if request.method == "DELETE":
            values = {"active": False}
        else:
            body = scim_body()
            values = scim_patch_attributes(body) if request.method == "PATCH" else scim_attributes(body)
        if "email" in values:
            scim_check_email(values["email"], user.id)
        with scim_transaction():
            for field, value in values.items():
                setattr(user, field, value)
            if not user.active:
                user.auth_version += 1
                UserSession.query.filter_by(user_id=user.id, revoked_at=None).update(
                    {"revoked_at": now(), "revoked_by_id": g.api_user.id}
                )
            audit("scim update", user.username, f"active={user.active}; client={g.api_client.client_id}",
                  user_id=g.api_user.id, tenant_id=user.tenant_id)
        return ("", 204) if request.method == "DELETE" else jsonify(scim_user_document(user))

    @app.get("/api/guided-tours/active")
    @login_required
    def guided_tours_active():
        """Returns tours the current user should be offered on the current
        route: active, role-targeted (or untargeted), route-matched (or
        global "*"), and not yet seen at the tour's current version. Scoped
        by tenant/role/route server-side -- the frontend player never
        decides eligibility itself, only rendering."""
        route = request.args.get("route", "")
        seen = {
            row.tour_id: row.tour_version_seen
            for row in UserTourProgress.query.filter_by(user_id=current_user.id).all()
        }
        candidates = tenant_query(GuidedTour).filter(
            GuidedTour.active.is_(True),
            db.or_(GuidedTour.target_route == "*", GuidedTour.target_route == route),
        ).options(selectinload(GuidedTour.steps)).all()
        results = []
        for tour in candidates:
            allowed_roles = [r for r in tour.target_roles.split(",") if r]
            if allowed_roles and current_user.effective_role not in allowed_roles:
                continue
            if seen.get(tour.id, 0) >= tour.version:
                continue
            if not tour.steps:
                continue
            results.append({
                "id": tour.id, "key": tour.key, "title": tour.title,
                "version": tour.version,
                "steps": [
                    {
                        "target_selector": step.target_selector, "title": step.title,
                        "body": step.body, "placement": step.placement,
                    }
                    for step in tour.steps
                ],
            })
        return jsonify({"tours": results})

    @app.post("/api/guided-tours/<int:tour_id>/progress")
    @login_required
    def guided_tours_progress(tour_id):
        tour = tenant_record_or_404(GuidedTour, tour_id)
        status = request.form.get("status", "dismissed")
        if status not in ("dismissed", "completed"):
            abort(400)
        row = UserTourProgress.query.filter_by(user_id=current_user.id, tour_id=tour.id).one_or_none()
        if not row:
            row = UserTourProgress(tenant_id=current_user.tenant_id, user_id=current_user.id, tour_id=tour.id)
            db.session.add(row)
        row.status = status
        row.tour_version_seen = tour.version
        db.session.commit()
        return ("", 204)
