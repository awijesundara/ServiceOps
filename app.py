import csv
import io
import json
import logging
import logging.handlers
import traceback as traceback_module
import time as time_module
import os
import sys
import ssl
import uuid
import base64
import hashlib
import hmac
import ipaddress
import socket
import re
import secrets
import smtplib
import imaplib
import email as email_module
from pathlib import Path
import collections
from collections import Counter, defaultdict
from datetime import date, datetime, time as dt_time, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urljoin, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
import httpx
import pyotp
import boto3
from flask import Flask, Response, abort, current_app, flash, g, has_app_context, has_request_context, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from markupsafe import Markup, escape
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt
from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from cryptography.fernet import Fernet, InvalidToken
from ldap3 import ALL, BASE, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge


def escape_like(value):
    """Escape user text before embedding it in a SQL LIKE pattern."""
    return str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

from serviceops_core.security import (
    hash_password, load_policy, mask_secret, redact, RedactingFilter, role_has_action,
    validate_policy, verify_and_upgrade_password, verify_password,
)
from serviceops_core.priority import calculate_priority, validate_priority_policy
from serviceops_core.business_time import add_business_minutes, validate_calendar
from serviceops_core.workflow import (
    canonical_json, load_workflow_package, materialize_workflow,
    package_digest, validate_workflow, workflow_matches,
)
from serviceops_core.projections import project_document, validate_projection_policy
from serviceops_core.ci_class_policy import (
    ci_class_action_allowed, ci_class_read_allowed, managed_ci_classes,
    restrict_ci_query_to_readable_classes,
)
from serviceops_core.dns_lookup import resolve_hostname, resolve_ip
from serviceops_core.dns_pin import pin_resolved_addresses
from serviceops_core.analytics import overdue_enterprise_records, OVERDUE_RECORDS_LIMIT
from serviceops_core.client_automation import (
    condition_matches, validate_trigger, ClientTriggerConfigurationError,
    CLIENT_TRIGGER_EVENTS, CLIENT_TRIGGER_FIELDS, CLIENT_TRIGGER_OPERATORS,
    CLIENT_TRIGGER_ACTION_TYPES, CLIENT_TICKET_STATUSES, CLIENT_TICKET_PRIORITIES,
)
from serviceops_core.email_ingest import (
    parse_inbound_email, extract_ticket_token, is_free_mail_domain,
    referenced_message_ids, build_references_header, MAX_ATTACHMENT_TOTAL_BYTES,
)
from serviceops_core.identity import (
    ldap_login_local_part, ldap_domain_suffix_from_base_dn,
    normalized_directory_groups, match_directory_role_mappings,
)
from serviceops_core.task_lifecycle import (
    TICKET_TRANSITIONS, ENTERPRISE_TRANSITIONS, CATALOG_TASK_TRANSITIONS,
    OPERATIONAL_TASK_TRANSITIONS, STATE_TRACK_ORDER, build_state_track, allowed_states,
)
from serviceops_core.config_schema import (
    SETTING_DEFINITIONS, SETTING_GROUP_META, find_setting_definition,
    coerce_bool, coerce_int,
)
from serviceops_core.notification_templates import (
    NOTIFICATION_EVENT_TYPES, NON_MUTABLE_EVENT_TYPES, render_notification_template, is_event_muted,
)
from serviceops_core.navigation import navigation_entries
from serviceops_core.storage import build_storage_backend, ipfs_enabled
from serviceops_core.passkeys import (
    authentication_options as build_passkey_authentication_options,
    registration_options as build_passkey_registration_options,
    verify_authentication as verify_passkey_authentication,
    verify_registration as verify_passkey_registration,
)
from webauthn.helpers import base64url_to_bytes

# VERSION is the release source of truth; shown in the UI, API, and health
# endpoint so operators can confirm the running build without host access.
APP_VERSION = (Path(__file__).resolve().parent / "VERSION").read_text().strip()
APP_START_MONOTONIC = time_module.monotonic()

TICKET_CATEGORY_OPTIONS = ["General", "Access", "Hardware", "Software", "Network", "Security"]

# Generic ServiceNow-style list filtering: a list view declares which
# columns are filterable (FilterField) and the client posts back a JSON
# array of {field, op, value} conditions (see static/list-filter.js). All
# lists share this one implementation instead of each route inventing its
# own ad hoc query params.
FILTER_OPERATOR_LABELS = {
    "eq": "is", "ne": "is not", "contains": "contains",
    "starts_with": "starts with", "is_empty": "is empty",
    "is_not_empty": "is not empty", "before": "before", "after": "after",
}
FILTER_OPERATORS_BY_TYPE = {
    "text": ["contains", "eq", "starts_with", "is_empty", "is_not_empty"],
    "choice": ["eq", "ne", "is_empty", "is_not_empty"],
    "date": ["before", "after"],
}
FILTER_MAX_CONDITIONS = 8


def parse_list_filter_param(raw):
    """Parses the `filter` query param (a JSON array of {field, op, value})
    into a validated list of condition dicts. Malformed input is dropped
    silently -- worst case is an unfiltered list, never a 500."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    conditions = []
    for item in parsed[:FILTER_MAX_CONDITIONS]:
        if not isinstance(item, dict):
            continue
        field = str(item.get("field", "")).strip()
        op = str(item.get("op", "")).strip()
        value = str(item.get("value", "")).strip()
        if not field or not op:
            continue
        conditions.append({"field": field, "op": op, "value": value})
    return conditions


def apply_filter_conditions(query, conditions, field_spec, extra_handlers=None):
    """Applies a validated condition list to `query`. `field_spec` maps
    field key -> {"column": InstrumentedAttribute, "type": "text"|"choice"|"date"}.
    `extra_handlers` maps field key -> callable(query, op, value) -> query,
    for fields that need a subquery instead of a plain column (e.g.
    assignment group, which lives on a different table per ticket kind)."""
    extra_handlers = extra_handlers or {}
    for condition in conditions:
        key, op, value = condition["field"], condition["op"], condition["value"]
        if key in extra_handlers:
            query = extra_handlers[key](query, op, value)
            continue
        spec = field_spec.get(key)
        if not spec or op not in FILTER_OPERATORS_BY_TYPE.get(spec["type"], ()):
            continue
        column = spec["column"]
        if op == "eq":
            query = query.filter(column == value)
        elif op == "ne":
            query = query.filter(column != value)
        elif op == "contains":
            query = query.filter(column.ilike(f"%{value}%"))
        elif op == "starts_with":
            query = query.filter(column.ilike(f"{value}%"))
        elif op == "is_empty":
            query = query.filter(db.or_(column.is_(None), column == ""))
        elif op == "is_not_empty":
            query = query.filter(db.and_(column.isnot(None), column != ""))
        elif op in ("before", "after"):
            parsed_date = None
            try:
                parsed_date = datetime.fromisoformat(value)
            except ValueError:
                continue
            query = query.filter(column < parsed_date if op == "before" else column > parsed_date)
    return query


def filter_conditions_breadcrumb(conditions, field_spec, value_labels=None):
    """Human-readable "Field is Value" breadcrumb text for the active
    filter, mirroring ServiceNow's list-view breadcrumb."""
    value_labels = value_labels or {}
    parts = []
    for condition in conditions:
        spec = field_spec.get(condition["field"])
        if not spec:
            continue
        op_label = FILTER_OPERATOR_LABELS.get(condition["op"], condition["op"])
        if condition["op"] in ("is_empty", "is_not_empty"):
            parts.append(f"{spec['label']} {op_label}")
        else:
            shown_value = value_labels.get((condition["field"], condition["value"]), condition["value"])
            parts.append(f"{spec['label']} {op_label} {shown_value}")
    return parts

# Phase 0 of the app.py blueprint decomposition (see the plan doc from that
# session): every model plus the few primitives they depend on for column
# defaults moved to serviceops_models.py so later route-extraction phases
# have one stable place to import models from without depending on
# create_app()'s internals. Star-imported (with an explicit __all__ in that
# module) so every existing `from app import Ticket/db/now/...` caller --
# tests, serviceops_core/*, tools/*, migrations/* -- keeps working unchanged.
from serviceops_models import *  # noqa: F401,F403

login_manager = LoginManager()
login_manager.login_view = "login"
oauth = OAuth()




def parse_form_datetime(value):
    """Parses a datetime-local form value into a UTC-aware datetime so it can
    be safely compared against tz-aware DateTime(timezone=True) columns."""
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_form_date(value):
    """Parses a date-only form value (YYYY-MM-DD) into a date, or None."""
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%d").date()


def align_tz(value, reference):
    """Matches value's tz-awareness to reference's. SQLite silently drops
    tzinfo on round-trip (unlike Postgres), so a value fresh off request.form
    and a value just read back from the database can disagree on awareness
    even when they represent the same instant; comparing them directly raises
    TypeError. This normalizes purely for in-Python comparison purposes."""
    if value is None or reference is None:
        return value
    if reference.tzinfo is None and value.tzinfo is not None:
        return value.replace(tzinfo=None)
    if reference.tzinfo is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def is_safe_internal_path(url):
    """Reject anything but a same-app relative path, to keep stored favorite/history links from becoming stored javascript: or open-redirect XSS."""
    return bool(url) and url.startswith("/") and not url.startswith("//")


def secret_value(name):
    """Read a secret from a mounted file first, then the legacy environment value."""
    file_path = os.getenv(f"{name}_FILE", "").strip()
    if file_path:
        try:
            value = open(file_path, encoding="utf-8").read().strip()
        except OSError as error:
            raise RuntimeError(f"Cannot read {name}_FILE: {error}") from error
        if not value:
            raise RuntimeError(f"{name}_FILE is empty.")
        return value
    return os.getenv(name, "")


def tenant_record_or_404(model, record_id):
    """Resolve a tenant-owned root without exposing another tenant's existence."""
    return model.query.filter_by(
        id=record_id, tenant_id=tenant_context_id()
    ).first_or_404()


def tenant_query(model):
    """Start a query constrained to the authenticated/default tenant."""
    return model.query.filter(model.tenant_id == tenant_context_id())


def object_storage_enabled():
    return os.getenv("OBJECT_STORAGE_BUCKET", "").strip() != ""


def current_storage():
    """The active StorageBackend (PostgresStorageBackend by default,
    IPFSStorageBackend under STORAGE_MODE=ipfs), built once at app boot."""
    return current_app.extensions["storage_backend"]


def object_storage_client():
    return boto3.client(
        "s3", endpoint_url=os.getenv("OBJECT_STORAGE_ENDPOINT") or None,
        region_name=os.getenv("OBJECT_STORAGE_REGION", "us-east-1"),
        aws_access_key_id=os.getenv("OBJECT_STORAGE_ACCESS_KEY") or None,
        aws_secret_access_key=os.getenv("OBJECT_STORAGE_SECRET_KEY") or None,
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def roles(*allowed):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            # superadmin is a strict superset of every other role's
            # authority within a tenant (see ROLE_RANK/role_at_least) --
            # it always satisfies a gate written for any narrower set of
            # roles, so routes never need "superadmin" added to their own
            # @roles(...) list by hand. This reads effective_role (the
            # session's "acting as" selection, not just the highest granted
            # role) so switching to a lower role is a real demotion here too.
            if current_user.effective_role == "superadmin" or current_user.effective_role in allowed:
                return fn(*args, **kwargs)
            abort(403)
        return wrapped
    return decorator


def effective_role_has_action(role, action, tenant_id=None):
    """Tenant-scoped role_has_action(): consults RolePolicyOverride first
    (an admin's explicit deviation from the Git-backed baseline), falling
    back to config/authorization.json's flat policy when no override row
    exists for this (tenant, role, action) -- see RolePolicyOverride's
    docstring. Deliberately not folded into serviceops_core.security's own
    role_has_action(), which stays DB-free by design; this wrapper lives
    here in app.py instead, the same way ci_class_policy.py sits alongside
    (not inside) security.py for the same reason."""
    tenant_id = tenant_id if tenant_id is not None else tenant_context_id()
    if tenant_id is not None:
        override = RolePolicyOverride.query.filter_by(
            tenant_id=tenant_id, role=role, action=action,
        ).first()
        if override:
            return override.is_granted
    return role_has_action(role, action)


def require_action(action):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if not effective_role_has_action(current_user.effective_role, action):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def audit_integrity_key(key_id="environment-v1", tenant_id=None):
    # Found via a real recovery/audit-verification rehearsal (B-009/B-004):
    # settings_cipher().decrypt() raises cryptography's InvalidToken when
    # the current SETTINGS_ENCRYPTION_KEY doesn't match whatever key a row
    # was encrypted under (e.g. the environment's encryption key was
    # regenerated at some point without a proper re-encryption migration --
    # a real, unrecoverable local-environment condition on at least one
    # deployment, not something this function can repair). Re-raised as a
    # RuntimeError with the same message shape as the "key row missing"
    # case below, so every caller already has one exception type to handle
    # instead of two.
    tenant_id = tenant_id or tenant_context_id()
    if key_id != "environment-v1":
        stored = AuditIntegrityKey.query.filter_by(
            tenant_id=tenant_id, key_id=key_id
        ).one_or_none()
        if not stored:
            raise RuntimeError(f"Audit integrity key {key_id!r} is unavailable.")
        try:
            return settings_cipher().decrypt(stored.secret_encrypted.encode())
        except InvalidToken:
            raise RuntimeError(f"Audit integrity key {key_id!r} could not be decrypted.")
    stored = AuditIntegrityKey.query.filter_by(
        tenant_id=tenant_id, key_id="environment-v1"
    ).one_or_none()
    if stored:
        try:
            return settings_cipher().decrypt(stored.secret_encrypted.encode())
        except InvalidToken:
            raise RuntimeError("Audit integrity key 'environment-v1' could not be decrypted.")
    configured = secret_value("AUDIT_INTEGRITY_KEY") or os.getenv(
        "SETTINGS_ENCRYPTION_KEY"
    )
    return (configured or current_app.config["SECRET_KEY"]).encode()


def audit_payload(row):
    created_at = row.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    payload = {
        "action": row.action,
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
        "details": row.details or "",
        "event_id": row.event_id,
        "previous_hash": row.previous_hash or "",
        "request_id": row.request_id,
        "source_ip": row.source_ip or "",
        "target": row.target,
        "tenant_id": row.tenant_id,
        "user_agent": row.user_agent or "",
        "user_id": row.user_id,
    }
    if row.integrity_version == "hmac-sha256-v2":
        payload["integrity_key_id"] = row.integrity_key_id
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()


def calculate_audit_hash(row):
    if row.integrity_version == "legacy-sha256-v1":
        return hashlib.sha256(audit_payload(row)).hexdigest()
    return hmac.new(
        audit_integrity_key(row.integrity_key_id, row.tenant_id),
        audit_payload(row), hashlib.sha256
    ).hexdigest()


def verify_audit_chain(tenant_id):
    previous_hash = ""
    checked = 0
    for row in Audit.query.filter_by(tenant_id=tenant_id).order_by(Audit.id):
        checked += 1
        if row.previous_hash != previous_hash:
            return {
                "valid": False, "checked": checked,
                "event_id": row.event_id, "reason": "previous hash mismatch",
            }
        try:
            computed_hash = calculate_audit_hash(row)
        except RuntimeError as error:
            # A row whose signing key can't be decrypted must be reported
            # as unverified, not silently skipped or allowed to crash the
            # whole chain walk -- tamper-evidence means "we can't confirm
            # this wasn't altered," which is exactly what this reports.
            return {
                "valid": False, "checked": checked,
                "event_id": row.event_id, "reason": str(error),
            }
        if not hmac.compare_digest(row.event_hash, computed_hash):
            return {
                "valid": False, "checked": checked,
                "event_id": row.event_id, "reason": "event hash mismatch",
            }
        previous_hash = row.event_hash
    return {
        "valid": True, "checked": checked,
        "head": previous_hash, "reason": None,
    }


def rotate_audit_integrity_key(tenant_id, user_id):
    integrity = verify_audit_chain(tenant_id)
    if not integrity["valid"]:
        raise RuntimeError("Audit key rotation is blocked while integrity is invalid.")
    environment_key = AuditIntegrityKey.query.filter_by(
        tenant_id=tenant_id, key_id="environment-v1"
    ).one_or_none()
    if not environment_key:
        environment_key = AuditIntegrityKey(
            key_id="environment-v1",
            secret_encrypted=settings_cipher().encrypt(
                audit_integrity_key("environment-v1", tenant_id)
            ).decode(),
            active=False,
            created_by_id=user_id,
            activated_at=now(),
            retired_at=now(),
            tenant_id=tenant_id,
        )
        db.session.add(environment_key)
    for existing in AuditIntegrityKey.query.filter_by(
        tenant_id=tenant_id, active=True
    ).all():
        existing.active = False
        existing.retired_at = now()
    key_id = f"audit-{now():%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"
    key = AuditIntegrityKey(
        key_id=key_id,
        secret_encrypted=settings_cipher().encrypt(secrets.token_bytes(32)).decode(),
        active=True,
        created_by_id=user_id,
        activated_at=now(),
        tenant_id=tenant_id,
    )
    db.session.add(key)
    db.session.flush()
    audit(
        "audit key rotate", key_id,
        f"previous_head={integrity.get('head') or 'empty'}",
        user_id=user_id, tenant_id=tenant_id,
    )
    return key


def audit(action, target, details="", user_id=None, tenant_id=None):
    tenant_id = tenant_id or tenant_context_id()
    if db.engine.dialect.name == "postgresql":
        db.session.execute(
            db.text("SELECT pg_advisory_xact_lock(:tenant_id)"),
            {"tenant_id": tenant_id},
        )
    pending = [
        row for row in db.session.new
        if isinstance(row, Audit) and row.tenant_id == tenant_id
    ]
    if pending:
        previous_hash = pending[-1].event_hash
    else:
        previous_hash = db.session.execute(
            db.select(Audit.event_hash).where(
                Audit.tenant_id == tenant_id
            ).order_by(Audit.id.desc()).limit(1)
        ).scalar_one_or_none() or ""
    active_key = AuditIntegrityKey.query.filter_by(
        tenant_id=tenant_id, active=True
    ).order_by(AuditIntegrityKey.id.desc()).first()
    row = Audit(
        event_id=str(uuid.uuid4()),
        user_id=(
            user_id if user_id is not None else
            current_user.id if has_request_context() and current_user.is_authenticated else None
        ),
        action=action,
        target=target,
        details=details,
        request_id=(
            getattr(g, "request_id", None) or str(uuid.uuid4())
            if has_request_context() else str(uuid.uuid4())
        ),
        source_ip=request.remote_addr if has_request_context() else None,
        user_agent=(
            str(request.user_agent)[:255] if has_request_context() else None
        ),
        integrity_version="hmac-sha256-v2",
        integrity_key_id=active_key.key_id if active_key else "environment-v1",
        previous_hash=previous_hash,
        created_at=now(),
        tenant_id=tenant_id,
    )
    row.event_hash = calculate_audit_hash(row)
    db.session.add(row)
    if setting_bool("AUDIT_STREAM_ENABLED", False):
        db.session.add(OutboxEvent(
            event_type="audit.created",
            payload_json=json.dumps({
                "event_id": row.event_id,
                "request_id": row.request_id,
                "user_id": row.user_id,
                "action": row.action,
                "target": row.target,
                "details": row.details or "",
                "source_ip": row.source_ip or "",
                "integrity_version": row.integrity_version,
                "integrity_key_id": row.integrity_key_id,
                "previous_hash": row.previous_hash,
                "event_hash": row.event_hash,
                "created_at": row.created_at.isoformat(),
                "tenant_id": row.tenant_id,
            }, sort_keys=True),
            tenant_id=tenant_id,
        ))


API_SCOPES = {
    "tickets:read",
    "incidents:create",
    "tickets:update",
    "workflows:execute",
    "cmdb:write",
    "users:provision",
}


def api_token_hash(token):
    pepper = os.getenv("API_TOKEN_PEPPER") or current_app.config["SECRET_KEY"]
    return hmac.new(
        pepper.encode(), token.encode(), hashlib.sha256
    ).hexdigest()


def create_api_token():
    token = f"sop_{secrets.token_urlsafe(32)}"
    return token, token[:12], api_token_hash(token)


MOBILE_API_SCOPES = {"tickets:read", "incidents:create", "tickets:update"}


def passkey_configuration():
    rp_id = os.getenv("WEBAUTHN_RP_ID", "").strip().lower()
    origin = os.getenv("WEBAUTHN_ORIGIN", "").strip().rstrip("/")
    if not rp_id or not origin or not origin.startswith("https://"):
        abort(503, description="Passkeys require WEBAUTHN_RP_ID and an HTTPS WEBAUTHN_ORIGIN.")
    return rp_id, origin


def issue_mobile_session(user, authentication_method, backup_used=False):
    app_version = _bounded_mobile_header("X-ServiceOps-App-Version", 40)
    app_build = _bounded_mobile_header("X-ServiceOps-App-Build", 40)
    platform = _bounded_mobile_header("X-ServiceOps-Platform", 40)
    device = _bounded_mobile_header("X-ServiceOps-Device", 120)
    access = f"som_{secrets.token_urlsafe(32)}"
    refresh = f"sor_{secrets.token_urlsafe(48)}"
    row = APIClient(
        name=f"{platform} mobile session for {user.username}", token_prefix=access[:12],
        token_hash=api_token_hash(access), refresh_token_hash=api_token_hash(refresh),
        scopes_json=json.dumps(sorted(MOBILE_API_SCOPES)), acting_user_id=user.id,
        created_by_id=user.id, tenant_id=user.tenant_id, client_kind="mobile",
        access_expires_at=now() + timedelta(minutes=15), refresh_expires_at=now() + timedelta(days=30),
        app_version=app_version, app_build=app_build, platform=platform, device_model=device,
    )
    db.session.add(row)
    db.session.flush()
    detail = f"; authentication={authentication_method}"
    if backup_used:
        detail += "; mfa=backup_code"
    elif user.mfa_enabled and authentication_method == "password":
        detail += "; mfa=totp"
    audit("mobile login", user.username, mobile_client_details(row) + detail,
          user_id=user.id, tenant_id=user.tenant_id)
    return access, refresh


def consume_passkey_challenge(challenge_id, purpose):
    row = PasskeyChallenge.query.filter_by(id=challenge_id, purpose=purpose).with_for_update().first()
    if not row or align_tz(row.expires_at, now()) <= now():
        abort(400, description="The passkey challenge is invalid or expired.")
    db.session.delete(row)
    return row


def enforce_passkey_attempt_limit():
    ip = request.remote_addr or "unknown"
    allowed = route_rate_limit(
        "passkey_authentication", f"ip:{ip}",
        setting_int("LOGIN_RATE_LIMIT_PER_IP_PER_MINUTE", 20),
    )
    db.session.commit()
    if not allowed:
        abort(429, description="Too many passkey attempts. Try again later.")


def _bounded_mobile_header(name, maximum):
    value = request.headers.get(name, "").strip()
    if not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        abort(400, description=f"A valid {name} header is required.")
    return value


def mobile_client_details(client):
    if getattr(client, "client_kind", "integration") != "mobile":
        return f"client={client.client_id}"
    return (
        f"client={client.client_id}; channel=mobile; platform={client.platform}; "
        f"app_version={client.app_version}; app_build={client.app_build}; "
        f"device={client.device_model}"
    )


def verify_mfa_code(user, code):
    code = str(code or "").strip()
    if not user.mfa_enabled:
        return True, False
    verified = False
    if code and user.mfa_secret_encrypted:
        secret = settings_cipher().decrypt(user.mfa_secret_encrypted.encode()).decode()
        verified = pyotp.TOTP(secret).verify(code.replace(" ", ""), valid_window=1)
    if not verified and code and user.mfa_backup_codes_json:
        remaining = json.loads(user.mfa_backup_codes_json)
        code_hash = hash_backup_code(code.lower())
        if code_hash in remaining:
            remaining.remove(code_hash)
            user.mfa_backup_codes_json = json.dumps(remaining)
            return True, True
    return verified, False


def authenticate_api_request():
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        abort(401, description="A bearer API token is required.")
    token = authorization[7:].strip()
    if not token:
        abort(401, description="A bearer API token is required.")
    token_hash = api_token_hash(token)
    client = APIClient.query.filter_by(token_hash=token_hash, active=True).first()
    if not client or not hmac.compare_digest(client.token_hash, token_hash):
        abort(401, description="The API token is invalid or revoked.")
    if client.access_expires_at and align_tz(client.access_expires_at, now()) <= now():
        abort(401, description="The mobile session has expired.")
    if not client.acting_user.active or client.acting_user.tenant_id != client.tenant_id:
        abort(403, description="The API identity is inactive or invalid.")
    enforce_api_rate_limit(client)
    client.last_used_at = now()
    # Mirrors track_last_seen()'s throttled web-session update below --
    # without this, mobile app users (and any other bearer-token API
    # client) never touched User.last_seen_at at all, since that only
    # runs on Flask-Login's current_user, and mobile auth never calls
    # login_user(). System Health's "Active users" list is filtered on
    # last_seen_at, so mobile-only users silently never appeared there,
    # even while actively using the iOS app.
    acting_user = client.acting_user
    if (
        acting_user.last_seen_at is None
        or (now() - align_tz(acting_user.last_seen_at, now())) > timedelta(minutes=1)
    ):
        acting_user.last_seen_at = now()
    g.api_client = client
    g.api_user = acting_user
    db.session.commit()


def enforce_api_rate_limit(client):
    limit = setting_int("API_RATE_LIMIT_PER_MINUTE", 120)
    window_start = now().replace(second=0, microsecond=0)
    row = APIRateLimitWindow.query.filter_by(
        api_client_id=client.id, window_start=window_start
    ).with_for_update().first()
    if not row:
        try:
            with db.session.begin_nested():
                row = APIRateLimitWindow(api_client_id=client.id, window_start=window_start, request_count=0)
                db.session.add(row)
                db.session.flush()
        except IntegrityError:
            # Another concurrent worker created this minute's row first (this
            # app runs multiple gunicorn workers) — re-fetch instead of
            # treating the race as an error.
            row = APIRateLimitWindow.query.filter_by(
                api_client_id=client.id, window_start=window_start
            ).with_for_update().one()
        # Bound table growth here rather than requiring a separate cleanup
        # job: prune old windows for this client whenever a new one starts.
        APIRateLimitWindow.query.filter(
            APIRateLimitWindow.api_client_id == client.id,
            APIRateLimitWindow.window_start < window_start - timedelta(hours=1),
        ).delete()
    row.request_count += 1
    if row.request_count > limit:
        db.session.commit()
        g.rate_limit_retry_after = 60 - now().second
        abort(429, description=f"Rate limit of {limit} requests/minute exceeded for this API client.")


def user_requires_mfa_by_policy(user):
    """Whether MFA is policy-mandatory for this user (ISO 27001 A.8.5):
    the `admin` role, or membership on the Change Control Board (any user
    with `GroupMember.role == "CCB approver"` on the tenant's "Change
    Control Board" support group -- the same membership CLAUDE.md's
    change-governance rules treat as CCB approval authority elsewhere in
    this file, e.g. app.py:3313, 10292)."""
    if not setting_bool("REQUIRE_MFA_FOR_ADMIN", False):
        return False
    if user.role == "admin":
        return True
    ccb = SupportGroup.query.filter_by(
        name="Change Control Board", tenant_id=user.tenant_id
    ).first()
    if not ccb:
        return False
    return GroupMember.query.filter_by(
        group_id=ccb.id, user_id=user.id, role="CCB approver"
    ).first() is not None


def generate_mfa_backup_codes(count=10):
    return [secrets.token_hex(5) for _ in range(count)]


def hash_backup_code(code):
    return hashlib.sha256(code.encode()).hexdigest()


def record_request_metric(method, status_code, duration_ms):
    """Increments the shared `RequestMetricTotal` row for this method+status.

    Runs on every request via `after_request`, so a failure here must never
    break the actual response -- caught and logged, not raised. A stale
    UniqueConstraint race (two workers creating the same row at once) is
    retried once via a fresh lookup rather than surfaced as a 500."""
    try:
        status = str(status_code)
        row = RequestMetricTotal.query.filter_by(method=method, status=status).with_for_update().first()
        if not row:
            row = RequestMetricTotal(method=method, status=status)
            db.session.add(row)
            db.session.flush()
        row.request_count += 1
        row.duration_sum_ms += duration_ms
        db.session.commit()
    except Exception:  # noqa: BLE001 - metrics must never break the actual request
        db.session.rollback()


def route_rate_limit(scope, key, limit, window_seconds=60):
    """General-purpose IP/account-scoped rate limiter for unauthenticated web
    routes (ISO 27001 A.8.16), generalized from `enforce_api_rate_limit`'s
    DB-backed windowed-counter pattern so it works correctly across multiple
    gunicorn workers. `scope` distinguishes routes (e.g. "login", "mfa"),
    `key` distinguishes the caller within that scope (e.g. the client IP or
    username) so a flood against one IP/account cannot exhaust another
    legitimate caller's quota. Sets `g.rate_limit_retry_after` and returns
    False (does not raise) when the limit is exceeded, so callers can render
    their own 429 response consistent with existing UX."""
    composite_key = f"{scope}:{key}"[:160]
    current = now()
    epoch_start = (int(current.timestamp()) // window_seconds) * window_seconds
    window_start = datetime.fromtimestamp(epoch_start, tz=timezone.utc)
    row = RouteRateLimitWindow.query.filter_by(
        key=composite_key, window_start=window_start
    ).with_for_update().first()
    if not row:
        try:
            with db.session.begin_nested():
                row = RouteRateLimitWindow(
                    key=composite_key, window_start=window_start, request_count=0
                )
                db.session.add(row)
                db.session.flush()
        except IntegrityError:
            row = RouteRateLimitWindow.query.filter_by(
                key=composite_key, window_start=window_start
            ).with_for_update().one()
        RouteRateLimitWindow.query.filter(
            RouteRateLimitWindow.key == composite_key,
            RouteRateLimitWindow.window_start < window_start - timedelta(hours=1),
        ).delete()
    row.request_count += 1
    if row.request_count > limit:
        g.rate_limit_retry_after = max(1, window_seconds - int((current - window_start).total_seconds()))
        return False
    return True


def require_api_scope(scope):
    if scope not in API_SCOPES:
        raise RuntimeError(f"Unknown API scope: {scope}")
    if scope not in g.api_client.scopes:
        abort(403, description=f"The API client lacks scope {scope}.")


def api_ticket_document(ticket, user):
    document = {
        "id": ticket.id,
        "number": ticket.number,
        "type": ticket.kind,
        "title": ticket.title,
        "description": ticket.description,
        "state": ticket.state,
        "priority": ticket.priority,
        "category": ticket.category,
        "opened_at": ticket.created_at.isoformat(),
        "updated_at": ticket.updated_at.isoformat(),
        "attachments": [api_attachment_document(row, ticket.number) for row in ticket.attachments],
    }
    group = ticket_owning_group(ticket)
    document["internal"] = {
        "assignment_group": (
            {"id": group.id, "name": group.name} if group else None
        ),
        "assigned_to": (
            {"id": ticket.assignee.id, "name": ticket.assignee.name}
            if ticket.assignee else None
        ),
    }
    return project_document("ticket", user.role, document)


def api_attachment_document(attachment, ticket_number):
    return {
        "id": attachment.id,
        "fileName": attachment.original_name,
        "contentType": attachment.mime_type or "application/octet-stream",
        "byteSize": attachment.size_bytes,
        "createdAt": attachment.created_at.isoformat(),
        "downloadURL": url_for(
            "api_ticket_attachment_download",
            number=ticket_number,
            attachment_id=attachment.id,
        ),
    }


def api_idempotency_context():
    key = request.headers.get("Idempotency-Key", "").strip()
    if not key or len(key) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]+", key):
        abort(400, description=(
            "Idempotency-Key is required and must contain 1-128 safe characters."
        ))
    request_hash = hashlib.sha256(
        request.method.encode() + b"\0" + request.path.encode() + b"\0"
        + request.get_data(cache=True)
    ).hexdigest()
    existing = APIIdempotencyRecord.query.filter_by(
        api_client_id=g.api_client.id, idempotency_key=key
    ).first()
    if existing:
        if (
            existing.method != request.method
            or existing.path != request.path
            or not hmac.compare_digest(existing.request_hash, request_hash)
        ):
            abort(409, description=(
                "The idempotency key was already used for a different request."
            ))
        response = Response(existing.response_body, status=existing.response_status)
        response.mimetype = "application/json"
        response.headers["Idempotency-Replayed"] = "true"
        return key, request_hash, response
    return key, request_hash, None


def store_api_idempotency(key, request_hash, response_body, status):
    db.session.add(APIIdempotencyRecord(
        api_client_id=g.api_client.id,
        idempotency_key=key,
        method=request.method,
        path=request.path,
        request_hash=request_hash,
        response_status=status,
        response_body=json.dumps(response_body, sort_keys=True),
        expires_at=now() + timedelta(hours=24),
        tenant_id=g.api_client.tenant_id,
    ))


def next_number(kind):
    prefix = {"incident": "INC", "change": "CHG"}[kind]
    maximum = db.session.query(func.max(Ticket.id)).scalar() or 0
    return f"{prefix}{maximum + 1:07d}"


def create_with_retry_on_number_collision(build_row, attempts=10, error_description=None):
    """next_number()/sequence_number()/next_operational_task_number() all
    derive a record's number from the current max id with no locking, so
    two near-simultaneous creators (double form submission, two browser
    tabs, two concurrent API/monitoring callers, two gunicorn workers) can
    compute the identical number before either commits. Every one of those
    number columns is unique=True, so the second insert previously
    surfaced as a raw IntegrityError/500 ("...number already exists...")
    instead of just quietly succeeding with the next available number.

    `build_row` must construct the row, call db.session.add() on it, and
    return it -- and must call a fresh next_number()/sequence_number()/etc.
    each time it runs, not reuse a number computed once outside this
    function, or the retry would just collide again identically. Retries
    inside a savepoint (the same pattern already used by
    enforce_api_rate_limit's concurrent-window handling) so only the failed
    insert rolls back, not the rest of this request's already-flushed work."""
    for _attempt in range(attempts):
        try:
            with db.session.begin_nested():
                row = build_row()
                db.session.flush()
        except IntegrityError:
            continue
        return row
    abort(409, description=error_description or "Could not allocate a unique record number; please try again.")


def create_ticket_with_unique_number(kind, **fields):
    def build():
        ticket = Ticket(number=next_number(kind), kind=kind, **fields)
        db.session.add(ticket)
        return ticket
    return create_with_retry_on_number_collision(
        build, error_description="Could not allocate a unique ticket number; please try again."
    )


DOMAIN_CONFIG = {
    "problem": {"name": "Problems", "prefix": "PRB", "types": ["Root cause analysis", "Known error"]},
    "customer": {"name": "Customer service", "prefix": "CS", "types": ["Support case", "Complaint", "Return / RMA", "Onboarding"]},
    "hr": {"name": "HR service delivery", "prefix": "HRC", "types": ["Benefits", "Payroll", "Employee relations", "HR systems", "Onboarding"]},
    "security": {"name": "Security operations", "prefix": "SIR", "types": ["Security incident", "Vulnerability", "Data loss", "Threat intelligence"]},
    "risk": {"name": "Risk & compliance", "prefix": "RSK", "types": ["Risk", "Control test", "Policy exception", "Audit finding"]},
    "portfolio": {"name": "Strategic portfolio", "prefix": "PRJ", "types": ["Demand", "Project", "Program", "Objective", "Agile epic"]},
    "field_service": {"name": "Field service", "prefix": "WO", "types": ["Work order", "Installation", "Repair", "Preventive maintenance"]},
    "event": {"name": "IT operations events", "prefix": "EVT", "types": ["Alert", "Infrastructure event", "Service degradation", "RT Ticket"]},
    "release": {"name": "Releases", "prefix": "REL", "types": ["Release", "Deployment", "Readiness review"]},
}






def setting_value(key, default=None):
    definition = find_setting_definition(key)
    fallback = default if default is not None else (
        os.getenv(key) if os.getenv(key) is not None else (definition or {}).get("default", ""))
    try:
        row = db.session.get(PlatformSetting, key)
    except Exception:
        return fallback
    if not row:
        return fallback
    if row.encrypted:
        try:
            return settings_cipher().decrypt(row.value.encode()).decode()
        except (InvalidToken, ValueError):
            current_app.logger.error("Unable to decrypt platform setting %s", key)
            return fallback
    return row.value


def setting_bool(key, default=False):
    return coerce_bool(setting_value(key, str(default)))


def setting_int(key, default=0):
    return coerce_int(setting_value(key, str(default)), default)


def create_notification(user_id, title, body, tenant_id=None, target_type=None, target_id=None,
                         event_type=None, template_vars=None):
    """`event_type`/`template_vars` are optional (B-130): when given, (1) a
    user who has muted that event_type in NotificationPreference gets
    nothing at all -- no row, no outbox event, not just a suppressed email
    -- and (2) an active tenant NotificationTemplate for that event_type
    overrides the caller's literal title/body via ${var} substitution.
    Callers that omit event_type behave exactly as before: always
    delivered, using the literal title/body given."""
    tenant_id = tenant_id or tenant_context_id()
    if event_type:
        preference = NotificationPreference.query.filter_by(user_id=user_id).first()
        if preference and is_event_muted(preference.muted_event_types, event_type):
            return None
        template = NotificationTemplate.query.filter_by(
            tenant_id=tenant_id, event_type=event_type, active=True,
        ).first()
        if template:
            title = render_notification_template(template.subject_template, template_vars)
            body = render_notification_template(template.body_template, template_vars)
    notification = Notification(
        user_id=user_id, title=title, body=body, tenant_id=tenant_id,
        target_type=target_type, target_id=target_id,
    )
    db.session.add(notification)
    db.session.flush()
    db.session.add(OutboxEvent(
        event_type="notification.created",
        payload_json=json.dumps({
            "user_id": user_id, "title": title, "body": body,
            "notification_id": notification.id,
            "target_type": target_type, "target_id": target_id,
            # Not to be confused with the OutboxEvent's own event_type
            # above (always "notification.created", the dispatch
            # category) -- this is B-130's per-notification category, kept
            # under its own key so deliver_smtp() can apply the same
            # NON_MUTABLE_EVENT_TYPES bypass create_notification() does.
            "notification_event_type": event_type,
        }, sort_keys=True),
        tenant_id=tenant_id,
    ))
    return notification


def _apns_authorization_token():
    private_key = setting_value("APNS_PRIVATE_KEY", "").replace("\\n", "\n")
    key_id = setting_value("APNS_KEY_ID", "")
    team_id = setting_value("APNS_TEAM_ID", "")
    if not private_key or not key_id or not team_id:
        raise RuntimeError("APNs team ID, key ID, and private key are required.")
    token = jwt.encode(
        {"alg": "ES256", "kid": key_id},
        {"iss": team_id, "iat": int(now().timestamp())},
        private_key,
    )
    return token.decode() if isinstance(token, bytes) else token


def deliver_mobile_push(event):
    """Deliver one notification event to every active installation.

    APNs responses are evaluated per device: expired/unregistered tokens are
    disabled immediately while transient failures keep the outbox event
    retryable. The payload contains only display text and opaque identifiers;
    record details are fetched again under the user's current authorization.
    """
    if event.event_type != "notification.created":
        return 0
    payload = event.payload
    devices = MobilePushDevice.query.filter_by(
        tenant_id=event.tenant_id, user_id=payload.get("user_id"), enabled=True,
    ).all()
    if not devices:
        return 0
    topic = setting_value("APNS_BUNDLE_ID", "")
    if not topic:
        raise RuntimeError("APNS_BUNDLE_ID is required.")
    authorization = _apns_authorization_token()
    delivered = 0
    with httpx.Client(http2=True, timeout=10.0) as client:
        for device in devices:
            token = settings_cipher().decrypt(device.token_encrypted.encode()).decode()
            host = "api.sandbox.push.apple.com" if device.environment == "sandbox" else "api.push.apple.com"
            response = client.post(
                f"https://{host}/3/device/{token}",
                headers={
                    "authorization": f"bearer {authorization}", "apns-topic": topic,
                    "apns-push-type": "alert", "apns-priority": "10",
                },
                json={
                    "aps": {
                        "alert": {"title": payload["title"], "body": payload["body"]},
                        "sound": "default", "badge": 1,
                    },
                    "notification_id": payload.get("notification_id"),
                    "target_type": payload.get("target_type"),
                    "target_id": payload.get("target_id"),
                },
            )
            if response.status_code == 200:
                device.last_delivered_at = now()
                device.last_error = None
                delivered += 1
                continue
            reason = ""
            try:
                reason = str(response.json().get("reason", ""))
            except ValueError:
                reason = response.text[:200]
            device.last_error = f"HTTP {response.status_code}: {reason}"[:500]
            if response.status_code in (400, 410) and reason in {
                "BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered",
            }:
                device.enabled = False
                continue
            raise RuntimeError(device.last_error)
    return delivered


def _integration_address_allowed(address, allow_private_network):
    """True if `address` is safe to connect to. Loopback/link-local/multicast/
    reserved/unspecified addresses are always rejected (they'd point the
    request at the app's own host or network infrastructure regardless of
    who configured the endpoint). Ordinary private-network addresses
    (RFC1918 etc.) are rejected too UNLESS `allow_private_network` is set --
    that's opt-in, for trusted admin-configured integrations that are
    expected to live on the internal network (e.g. a self-hosted NetBox),
    as opposed to arbitrary user-supplied targets like webhook URLs."""
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified:
        return False
    if address.is_global:
        return True
    return allow_private_network and address.is_private


def integration_endpoint_valid(endpoint, allow_private_network=False):
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username:
        return False
    hostname = parsed.hostname.lower()
    if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(hostname)
        if not _integration_address_allowed(address, allow_private_network):
            return False
    except ValueError:
        pass
    return True


def resolve_endpoint_addresses_safely(endpoint, allow_private_network=False):
    """Re-resolve the endpoint's hostname and reject it if any A/AAAA record is
    disallowed. A literal-IP/hostname string check alone (integration_endpoint_valid)
    cannot catch a public-looking hostname that resolves to a private address
    (DNS rebinding) -- this closes that gap at delivery time, immediately before
    the connection is made.

    Returns (ok, hostname, infos): `hostname` is None when `endpoint` was
    already a literal IP (nothing to pin -- there's no resolver step for the
    caller to race against); `infos` is the raw socket.getaddrinfo() result
    used for the validation, in the exact shape callers can hand to
    serviceops_core.dns_pin.pin_resolved_addresses() to pin the same
    addresses for the connection that follows, closing the TOCTOU window
    between this check and the actual HTTP client's own DNS lookup."""
    hostname = urlparse(endpoint).hostname
    if not hostname:
        return False, None, None
    try:
        address = ipaddress.ip_address(hostname)
        return _integration_address_allowed(address, allow_private_network), None, None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False, hostname, None
    if not infos:
        return False, hostname, None
    for info in infos:
        raw_address = info[4][0]
        try:
            if not _integration_address_allowed(ipaddress.ip_address(raw_address), allow_private_network):
                return False, hostname, None
        except ValueError:
            return False, hostname, None
    return True, hostname, infos


def integration_endpoint_resolves_safely(endpoint, allow_private_network=False):
    ok, _, _ = resolve_endpoint_addresses_safely(endpoint, allow_private_network)
    return ok


def deliver_smtp(event):
    """Returns True once actually sent, False if intentionally skipped
    because the recipient has disabled email notifications (B-130) --
    the caller must record that distinctly from a real failure, since a
    disabled preference is a successful, terminal, non-retryable outcome,
    not an error to back off and retry."""
    payload = event.payload
    user = db.session.get(User, payload["user_id"])
    if not user or user.tenant_id != event.tenant_id or not user.email:
        raise RuntimeError("Notification recipient is unavailable.")
    preference = NotificationPreference.query.filter_by(user_id=user.id).first()
    notification_event_type = payload.get("notification_event_type")
    if (
        preference and not preference.email_enabled
        and notification_event_type not in NON_MUTABLE_EVENT_TYPES
    ):
        return False
    host = setting_value("SMTP_HOST", "")
    sender = setting_value("SMTP_FROM", "")
    if not host or not sender:
        raise RuntimeError("SMTP host and from address are required.")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = user.email
    message["Subject"] = payload["title"]
    message.set_content(payload["body"])
    with smtplib.SMTP(host, int(setting_value("SMTP_PORT", "587")), timeout=10) as smtp:
        smtp.ehlo()
        if setting_bool("SMTP_STARTTLS", True):
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        username = setting_value("SMTP_USERNAME", "")
        if username:
            smtp.login(username, setting_value("SMTP_PASSWORD", ""))
        smtp.send_message(message)
    return True


def deliver_webhook(event, connection):
    payload = {
        "id": event.event_id,
        "type": event.event_type,
        "created_at": event.created_at.isoformat(),
        "data": event.payload,
    }
    if connection.kind == "teams":
        body = {
            "text": f"**{event.payload['title']}**\n\n{event.payload['body']}"
        }
        headers = {"Content-Type": "application/json"}
    else:
        body = payload
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        timestamp = str(int(now().timestamp()))
        signature = hmac.new(
            connection.secret.encode(),
            timestamp.encode() + b"." + encoded,
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-ServiceOps-Event-ID": event.event_id,
            "X-ServiceOps-Timestamp": timestamp,
            "X-ServiceOps-Signature": f"sha256={signature}",
        }
    target = connection.endpoint
    max_redirects = 3
    for _ in range(max_redirects + 1):
        if not integration_endpoint_valid(target):
            raise RuntimeError("Webhook destination resolves to a non-routable or private address.")
        ok, hostname, infos = resolve_endpoint_addresses_safely(target)
        if not ok:
            raise RuntimeError("Webhook destination resolves to a non-routable or private address.")
        # Pin the addresses just validated for exactly this connection attempt
        # -- requests' own internal DNS lookup would otherwise re-resolve
        # `hostname` independently, reopening the TOCTOU window between this
        # check and the actual connect (see serviceops_core/dns_pin.py).
        # `hostname` is None when `target` was already a literal IP, which
        # has no resolver step to pin against.
        if hostname and infos:
            with pin_resolved_addresses(hostname, infos):
                response = requests.post(
                    target, json=body, headers=headers, timeout=10, allow_redirects=False,
                )
        else:
            response = requests.post(
                target, json=body, headers=headers, timeout=10, allow_redirects=False,
            )
        if response.is_redirect:
            location = response.headers.get("Location", "")
            target = urljoin(target, location)
            continue
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"HTTP {response.status_code}")
        return response.status_code
    raise RuntimeError("Webhook delivery exceeded the maximum redirect hops.")


def process_outbox(limit=50):
    events = OutboxEvent.query.filter(
        OutboxEvent.state.in_(["Pending", "Retry"]),
        OutboxEvent.available_at <= now(),
    ).order_by(OutboxEvent.id).with_for_update(skip_locked=True).limit(limit).all()
    processed = 0
    for event in events:
        failures = []
        attempted = False
        if setting_bool("APNS_ENABLED") and event.event_type == "notification.created":
            prior = IntegrationDelivery.query.filter_by(
                outbox_event_id=event.id, channel="apns",
            ).filter(IntegrationDelivery.state.in_(["Delivered", "Skipped"])).first()
            if not prior:
                attempted = True
                try:
                    count = deliver_mobile_push(event)
                    db.session.add(IntegrationDelivery(
                        outbox_event_id=event.id, channel="apns",
                        state="Delivered" if count else "Skipped",
                        tenant_id=event.tenant_id,
                    ))
                except Exception as error:
                    failures.append(f"apns: {error}")
                    db.session.add(IntegrationDelivery(
                        outbox_event_id=event.id, channel="apns", state="Failed",
                        error=str(error)[:1000], tenant_id=event.tenant_id,
                    ))
        if setting_bool("SMTP_ENABLED"):
            prior = IntegrationDelivery.query.filter_by(
                outbox_event_id=event.id, channel="smtp",
            ).filter(IntegrationDelivery.state.in_(["Delivered", "Skipped"])).first()
            if not prior:
                attempted = True
                try:
                    sent = deliver_smtp(event)
                    db.session.add(IntegrationDelivery(
                        outbox_event_id=event.id, channel="smtp",
                        state="Delivered" if sent else "Skipped",
                        tenant_id=event.tenant_id,
                    ))
                except Exception as error:
                    failures.append(f"smtp: {error}")
                    db.session.add(IntegrationDelivery(
                        outbox_event_id=event.id, channel="smtp", state="Failed",
                        error=str(error)[:1000], tenant_id=event.tenant_id,
                    ))
        for connection in IntegrationConnection.query.filter_by(
            tenant_id=event.tenant_id, active=True
        ).all():
            if event.event_type == "audit.created" and connection.kind != "siem":
                continue
            if event.event_type != "audit.created" and connection.kind == "siem":
                continue
            prior = IntegrationDelivery.query.filter_by(
                outbox_event_id=event.id, connection_id=connection.id,
                state="Delivered",
            ).first()
            if prior:
                continue
            attempted = True
            try:
                status = deliver_webhook(event, connection)
                db.session.add(IntegrationDelivery(
                    outbox_event_id=event.id, connection_id=connection.id,
                    channel=connection.kind, state="Delivered",
                    status_code=status, tenant_id=event.tenant_id,
                ))
            except Exception as error:
                failures.append(f"{connection.name}: {error}")
                db.session.add(IntegrationDelivery(
                    outbox_event_id=event.id, connection_id=connection.id,
                    channel=connection.kind, state="Failed",
                    error=str(error)[:1000], tenant_id=event.tenant_id,
                ))
        event.attempts += 1
        if failures:
            event.last_error = "; ".join(failures)[:4000]
            event.state = "Dead" if event.attempts >= 5 else "Retry"
            event.available_at = now() + timedelta(
                seconds=min(300, 2 ** event.attempts * 5)
            )
        else:
            event.state = "Completed"
            event.completed_at = now()
            event.last_error = None if attempted else "No delivery channels enabled."
        processed += 1
    db.session.commit()
    return processed


def next_enterprise_number(domain):
    prefix = DOMAIN_CONFIG[domain]["prefix"]
    latest = EnterpriseRecord.query.filter_by(domain=domain).order_by(EnterpriseRecord.id.desc()).first()
    sequence = (latest.id + 1) if latest else 1
    return f"{prefix}{sequence:07d}"


def sequence_number(model, prefix):
    latest = model.query.order_by(model.id.desc()).first()
    return f"{prefix}{((latest.id if latest else 0) + 1):07d}"


def next_operational_task_number(task_kind):
    prefix = {"change": "CTASK", "problem": "PTASK", "event": "EVTASK"}.get(
        task_kind, "TASK"
    )
    latest = OperationalTask.query.filter_by(task_kind=task_kind).order_by(
        OperationalTask.id.desc()
    ).first()
    sequence = (latest.id + 1) if latest else 1
    return f"{prefix}{sequence:07d}"


def log_history(target_type, target_id, event, field_name=None, old_value=None,
                new_value=None, details="", actor_id=None):
    if actor_id is None and current_user and current_user.is_authenticated:
        actor_id = current_user.id
    row = TaskHistory(
        target_type=target_type, target_id=target_id, actor_id=actor_id,
        event=event, field_name=field_name,
        old_value="" if old_value is None else str(old_value),
        new_value="" if new_value is None else str(new_value),
        details=details,
    )
    db.session.add(row)
    return row


def log_field_changes(target_type, target_id, before, after, event="Field changed"):
    changed = []
    for field_name, old_value in before.items():
        new_value = after[field_name]
        if old_value != new_value:
            log_history(
                target_type, target_id, event, field_name,
                old_value, new_value,
            )
            changed.append(field_name)
    return changed


def record_reference(record_type, record_id):
    model_map = {
        "ticket": Ticket,
        "enterprise": EnterpriseRecord,
        "request": CatalogRequest,
        "ritm": RequestedItem,
        "sctask": CatalogTask,
        "work_task": OperationalTask,
        "knowledge": Knowledge,
    }
    model = model_map.get(record_type)
    return db.session.get(model, record_id) if model else None


def record_tenant_id(record):
    if isinstance(record, Knowledge):
        return record.tenant_id
    if isinstance(record, CatalogTask):
        return record.requested_item.request.tenant_id if record.requested_item else None
    if isinstance(record, OperationalTask):
        parent = record_reference(record.parent_type, record.parent_id)
        return record_tenant_id(parent) if parent else None
    if isinstance(record, RequestedItem):
        return record.request.tenant_id if record.request else None
    return getattr(record, "tenant_id", None)


def record_type_for(record):
    if isinstance(record, Ticket):
        return "ticket"
    if isinstance(record, EnterpriseRecord):
        return "enterprise"
    if isinstance(record, CatalogRequest):
        return "request"
    if isinstance(record, RequestedItem):
        return "ritm"
    if isinstance(record, CatalogTask):
        return "sctask"
    if isinstance(record, OperationalTask):
        return "work_task"
    if isinstance(record, Knowledge):
        return "knowledge"
    return None


def record_number(record):
    if isinstance(record, Knowledge):
        return f"KB{record.id:07d}"
    return getattr(record, "number", "")


def record_title(record):
    if isinstance(record, CatalogRequest):
        return f"Request for {record.requested_for.name}"
    if isinstance(record, RequestedItem):
        return record.item.name
    return getattr(record, "title", getattr(record, "name", "Related record"))


ATTACHMENT_ALLOWED_TYPES = {
    "png": (b"\x89PNG\r\n\x1a\n", "image/png"),
    "jpg": (b"\xff\xd8\xff", "image/jpeg"),
    "jpeg": (b"\xff\xd8\xff", "image/jpeg"),
    "gif": (b"GIF8", "image/gif"),
    "bmp": (b"BM", "image/bmp"),
    "pdf": (b"%PDF-", "application/pdf"),
    # Office Open XML formats (docx/xlsx/pptx/xlsm) and plain .zip all
    # share the ZIP local-file-header signature; the extension still
    # narrows what's accepted, this only rules out a non-ZIP file
    # masquerading with one of these extensions.
    "docx": (b"PK\x03\x04", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "xlsx": (b"PK\x03\x04", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "pptx": (b"PK\x03\x04", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    "xlsm": (b"PK\x03\x04", "application/vnd.ms-excel.sheet.macroEnabled.12"),
    "zip": (b"PK\x03\x04", "application/zip"),
    # Legacy (pre-2007) Office formats and Outlook .msg all share the OLE
    # Compound File signature.
    "doc": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/msword"),
    "xls": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/vnd.ms-excel"),
    "ppt": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/vnd.ms-powerpoint"),
    "msg": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/vnd.ms-outlook"),
    "7z": (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    "rar": (b"Rar!\x1a\x07", "application/vnd.rar"),
    "gz": (b"\x1f\x8b", "application/gzip"),
    "rtf": (b"{\\rtf", "application/rtf"),
    # No reliable magic-byte signature for plain text; extension allowlisting
    # plus a mime-type-gated inline-preview check (only png/jpeg/gif/pdf
    # are ever served inline, everything else always forces a download) is
    # the control for these.
    "txt": (None, "text/plain"),
    "csv": (None, "text/csv"),
    "log": (None, "text/plain"),
    "json": (None, "application/json"),
    "xml": (None, "application/xml"),
    "eml": (None, "message/rfc822"),
}


PREVIEWABLE_ATTACHMENT_TYPES = {"image/png", "image/jpeg", "image/gif", "application/pdf"}
IMAGE_ATTACHMENT_TYPES = {"image/png", "image/jpeg", "image/gif"}


def validate_attachment_upload(upload):
    """Returns (extension, mime_type) if the upload is an allowed attachment
    type, or None if it should be rejected. Extension-only allowlisting is not
    enough on its own — a disallowed type could be relabeled with an allowed
    extension — so this cross-checks the file's actual magic bytes wherever
    the format has one, rejecting a mismatch even if the extension looks fine."""
    ext = upload.filename.rsplit(".", 1)[-1].lower() if "." in upload.filename else ""
    if ext not in ATTACHMENT_ALLOWED_TYPES:
        return None
    signature, mime_type = ATTACHMENT_ALLOWED_TYPES[ext]
    if signature:
        header = upload.stream.read(len(signature))
        upload.stream.seek(0)
        if header != signature:
            return None
    return ext, mime_type


def validate_attachment_bytes(filename, data):
    """Same allowlist/magic-byte check as validate_attachment_upload(), for
    raw bytes (an email attachment) instead of a Flask FileStorage."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ATTACHMENT_ALLOWED_TYPES:
        return None
    signature, mime_type = ATTACHMENT_ALLOWED_TYPES[ext]
    if signature and data[:len(signature)] != signature:
        return None
    return ext, mime_type


def save_email_attachment(client_ticket, filename, data, uploaded_by_id):
    """The raw-bytes counterpart to save_ticket_attachment() -- same
    validation/malware-scan/hash/object-storage tail, adapted for an email
    attachment's already-decoded bytes instead of a Flask upload. Returns
    the FileAttachment on success, or None (silently skipped, matching
    Zendesk's own documented "infected attachments are dropped without
    surfacing them" convention -- logged via audit(), not raised, so one
    bad attachment never aborts the whole message)."""
    original = secure_filename(filename) or "attachment"
    validated = validate_attachment_bytes(original, data)
    if not validated:
        current_app.logger.info(
            "Skipped inbound email attachment of a disallowed type: ticket=%s file=%s",
            client_ticket.number, original,
        )
        return None
    _, verified_mime_type = validated
    stored = f"{uuid.uuid4().hex}-{original}"
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], stored)
    with open(path, "wb") as handle:
        handle.write(data)
    scan_status = scan_attachment(path)
    if scan_status == "infected":
        os.remove(path)
        audit("attach-blocked", client_ticket.number, f"{original} (malware scan positive, inbound email)",
              user_id=uploaded_by_id, tenant_id=client_ticket.tenant_id)
        return None
    sha256 = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            sha256.update(chunk)
    file_size = os.path.getsize(path)
    if object_storage_enabled():
        # Found via real failure-injection testing against a disposable
        # MinIO backend (B-052): an object-storage outage previously left
        # this unhandled, crashing whatever called it (here, the inbound
        # email poll loop, which isolates per-message failures anyway) and
        # -- more importantly -- never reaching the os.remove(path) below,
        # so the local temp file leaked forever on every failed upload.
        try:
            object_storage_client().upload_file(
                path, os.environ["OBJECT_STORAGE_BUCKET"], stored,
                ExtraArgs={"ContentType": verified_mime_type},
            )
        except Exception:
            os.remove(path)
            current_app.logger.warning(
                "Object storage upload failed for inbound email attachment: ticket=%s file=%s",
                client_ticket.number, original,
            )
            return None
        os.remove(path)
    ipfs_cid = None
    if ipfs_enabled():
        try:
            ipfs_cid = current_storage().attach_file(stored, data, verified_mime_type)
        except Exception:
            os.remove(path)
            current_app.logger.warning(
                "IPFS attachment upload failed for inbound email attachment: ticket=%s file=%s",
                client_ticket.number, original,
            )
            return None
        os.remove(path)
    attachment = FileAttachment(
        client_ticket_id=client_ticket.id, uploaded_by_id=uploaded_by_id,
        original_name=original, stored_name=stored, ipfs_cid=ipfs_cid,
        mime_type=verified_mime_type, size_bytes=file_size,
        sha256=sha256.hexdigest(), scan_status=scan_status, tenant_id=client_ticket.tenant_id,
    )
    db.session.add(attachment)
    audit("attach", client_ticket.number, f"{original} (inbound email)",
          user_id=uploaded_by_id, tenant_id=client_ticket.tenant_id)
    return attachment


CLAMAV_MAX_CHUNK = 4096


def scan_attachment(path):
    """Optional malware-scan adapter: speaks the ClamAV daemon's INSTREAM
    protocol directly over a socket (no clamd client dependency added — same
    zero-new-dependency preference this repo has applied elsewhere, e.g. the
    analytics CSS bar charts). Returns one of "clean", "infected",
    "scan_error", or "not_scanned" (the honest answer when no scanner is
    configured — this app must never claim a file was scanned when it
    wasn't). Fails open on scanner unavailability by design: this is an
    optional adapter per CLAUDE.md's integration model, and a misconfigured
    or down ClamAV instance rejecting every upload tenant-wide would itself
    be a production incident. Magic-byte/extension validation in
    validate_attachment_upload() runs unconditionally regardless of this."""
    if not setting_bool("CLAMAV_ENABLED", False):
        return "not_scanned"
    host = setting_value("CLAMAV_HOST", "") or ""
    port = setting_int("CLAMAV_PORT", 3310)
    if not host:
        return "not_scanned"
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.sendall(b"zINSTREAM\0")
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(CLAMAV_MAX_CHUNK)
                    if not chunk:
                        break
                    sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
            sock.sendall((0).to_bytes(4, "big"))
            response = sock.recv(4096).decode("utf-8", errors="replace")
    except OSError as exc:
        current_app.logger.warning("ClamAV scan unavailable for %s: %s", os.path.basename(path), exc)
        return "scan_error"
    if "FOUND" in response:
        return "infected"
    if "OK" in response:
        return "clean"
    current_app.logger.warning("Unrecognized ClamAV response for %s: %r", os.path.basename(path), response)
    return "scan_error"


def attachment_file_response(attachment, inline=False):
    """Serve an authorized attachment from the configured storage backend.

    Authorization belongs to the calling route because browser sessions and
    bearer-token API clients use different identities. This function keeps
    local disk, S3, and IPFS byte delivery identical once access is granted.
    """
    render_inline = inline and attachment.mime_type in PREVIEWABLE_ATTACHMENT_TYPES
    disposition = (
        f"inline; filename={json.dumps(attachment.original_name)}"
        if render_inline
        else f"attachment; filename={json.dumps(attachment.original_name)}"
    )
    if object_storage_enabled():
        try:
            stored = object_storage_client().get_object(
                Bucket=os.environ["OBJECT_STORAGE_BUCKET"], Key=attachment.stored_name,
            )
        except Exception:
            current_app.logger.warning(
                "Object storage download failed: attachment_id=%s", attachment.id,
            )
            abort(503, description="Attachment storage is temporarily unavailable. Please try again shortly.")
        headers = {
            "Content-Disposition": disposition,
            "Content-Length": str(stored["ContentLength"]),
            "Cache-Control": "private, no-store",
        }
        return Response(
            stored["Body"].iter_chunks(), headers=headers,
            mimetype=attachment.mime_type if render_inline else "application/octet-stream",
        )
    if attachment.ipfs_cid:
        try:
            data_bytes, _ = current_storage().read_file(
                attachment.stored_name, attachment.ipfs_cid,
            )
        except Exception:
            current_app.logger.warning(
                "IPFS attachment download failed: attachment_id=%s", attachment.id,
            )
            abort(503, description="Attachment storage is temporarily unavailable. Please try again shortly.")
        return Response(
            data_bytes,
            headers={
                "Content-Disposition": disposition,
                "Content-Length": str(len(data_bytes)),
                "Cache-Control": "private, no-store",
            },
            mimetype=attachment.mime_type if render_inline else "application/octet-stream",
        )
    response = send_from_directory(
        current_app.config["UPLOAD_FOLDER"], attachment.stored_name,
        as_attachment=not render_inline,
        download_name=attachment.original_name,
        mimetype=attachment.mime_type if render_inline else None,
    )
    response.headers["Cache-Control"] = "private, no-store"
    return response


def csv_response(csv_text, filename):
    """Wrap a CSV string as a downloadable attachment. Used by every
    'Export CSV' button across the app so list/report exports behave
    consistently (UTF-8 BOM for Excel, no caching of exported data)."""
    response = Response("﻿" + csv_text, mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"
    return response


def record_url(record):
    if isinstance(record, Ticket):
        return url_for("ticket_detail", ticket_id=record.id)
    if isinstance(record, EnterpriseRecord):
        return url_for("enterprise_detail", record_id=record.id)
    if isinstance(record, CatalogRequest):
        return url_for("request_detail", request_id=record.id)
    if isinstance(record, RequestedItem):
        return url_for("ritm_detail", ritm_id=record.id)
    if isinstance(record, CatalogTask):
        return url_for("catalog_task_detail", task_id=record.id)
    if isinstance(record, Knowledge):
        return url_for("knowledge")
    if isinstance(record, OperationalTask):
        parent = record_reference(record.parent_type, record.parent_id)
        return record_url(parent) if parent else "#"
    return "#"


def notification_target_url(target_type, target_id):
    if target_type == "approval_queue":
        return url_for("approval_chains")
    if not target_type or not target_id:
        return None
    record = record_reference(target_type, target_id)
    return record_url(record) if record else None


def find_record_by_number(number):
    """Looks up any ITIL record by its display number, strictly scoped to the
    caller's tenant. Every branch must filter by tenant before returning a
    record — this function is a cross-record-type lookup used for linking,
    and an unscoped branch here is a cross-tenant existence oracle."""
    normalized = (number or "").strip().upper()
    tenant_id = current_user.tenant_id if current_user.is_authenticated else None
    if tenant_id is None:
        return None
    if normalized.startswith(("INC", "CHG")):
        return Ticket.query.filter(
            func.upper(Ticket.number) == normalized, Ticket.tenant_id == tenant_id,
        ).first()
    if normalized.startswith("PRB"):
        return EnterpriseRecord.query.filter(
            EnterpriseRecord.domain == "problem",
            func.upper(EnterpriseRecord.number) == normalized,
            EnterpriseRecord.tenant_id == tenant_id,
        ).first()
    if normalized.startswith("REQ"):
        return CatalogRequest.query.filter(
            func.upper(CatalogRequest.number) == normalized, CatalogRequest.tenant_id == tenant_id,
        ).first()
    if normalized.startswith("RITM"):
        return RequestedItem.query.join(CatalogRequest).filter(
            func.upper(RequestedItem.number) == normalized, CatalogRequest.tenant_id == tenant_id,
        ).first()
    if normalized.startswith("SCTASK"):
        return CatalogTask.query.join(RequestedItem).join(CatalogRequest).filter(
            func.upper(CatalogTask.number) == normalized, CatalogRequest.tenant_id == tenant_id,
        ).first()
    if normalized.startswith(("CTASK", "PTASK")):
        task = OperationalTask.query.filter(func.upper(OperationalTask.number) == normalized).first()
        if not task:
            return None
        if task.parent_type == "ticket":
            parent = db.session.get(Ticket, task.parent_id)
        elif task.parent_type == "enterprise":
            parent = db.session.get(EnterpriseRecord, task.parent_id)
        else:
            parent = None
        if not parent or parent.tenant_id != tenant_id:
            return None
        return task
    if normalized.startswith("KB") and normalized[2:].isdigit():
        # Knowledge is not currently tenant-scoped; single-tenant deployments
        # are unaffected, but this remains a gap if multi-tenant KB ships.
        return db.session.get(Knowledge, int(normalized[2:]))
    return None


RELATION_LABELS = {
    "parent_incident": "Parent incident",
    "underlying_problem": "Problem",
    "resolution_change": "Change request",
    "caused_by_change": "Caused by change",
    "converted_request": "Service request",
    "related_incident": "Related incident",
    "problem_change": "Problem fix change",
    "requested_item_change": "Requested item change",
    "knowledge_article": "Knowledge article",
}


def related_records(target_type, target_id):
    rows = RecordLink.query.filter(db.or_(
        db.and_(RecordLink.source_type == target_type, RecordLink.source_id == target_id),
        db.and_(RecordLink.target_type == target_type, RecordLink.target_id == target_id),
    )).order_by(RecordLink.created_at).all()
    result = []
    for link in rows:
        outgoing = link.source_type == target_type and link.source_id == target_id
        other_type = link.target_type if outgoing else link.source_type
        other_id = link.target_id if outgoing else link.source_id
        other = record_reference(other_type, other_id)
        if other:
            result.append({
                "link": link, "record": other,
                "label": RELATION_LABELS.get(link.link_type, link.link_type.replace("_", " ").title()),
                "direction": "outgoing" if outgoing else "incoming",
                "number": record_number(other), "title": record_title(other),
                "url": record_url(other),
            })
    return result


def target_record(target_type, target_id):
    models = {"ticket": Ticket, "ritm": RequestedItem, "enterprise": EnterpriseRecord}
    model = models.get(target_type)
    return db.session.get(model, target_id) if model else None


def set_target_state(target_type, target_id, state):
    target = target_record(target_type, target_id)
    if target:
        target.state = state


# TICKET_TRANSITIONS, ENTERPRISE_TRANSITIONS, CATALOG_TASK_TRANSITIONS,
# OPERATIONAL_TASK_TRANSITIONS, STATE_TRACK_ORDER, and build_state_track()
# now live in serviceops_core.task_lifecycle (imported above) -- pure
# declarative state-machine data with no Flask/database dependency.


def approval_chain_for(target_type, target_id):
    return ApprovalChain.query.filter_by(
        target_type=target_type, target_id=target_id
    ).order_by(ApprovalChain.id.desc()).first()


def cancel_approval_chain(chain):
    if not chain or chain.state != "Running":
        return
    chain.state = "Cancelled"
    chain.completed_at = now()
    for gate in chain.gates:
        if gate.state in ("Pending", "Requested"):
            gate.state = "Cancelled"
        for vote in gate.votes:
            if vote.state in ("Not Requested", "Requested"):
                vote.state = "No Longer Required"


def allowed_ticket_states(ticket):
    chain = approval_chain_for("ticket", ticket.id)
    if ticket.kind == "change" and chain:
        if chain.state == "Running":
            return (ticket.state, "Cancelled")
        if chain.state == "Rejected":
            return ("Rejected",)
        if chain.state == "Cancelled":
            return ("Cancelled",)
    return TICKET_TRANSITIONS.get(ticket.state, (ticket.state,))


def sync_service_outages(ticket):
    """Idempotent -- safe to call on every incident create/update/transition.
    Opens a ServiceOutage for each business service backed by the incident's
    CI while it's open with High/Critical impact, and closes it otherwise."""
    if ticket.kind != "incident":
        return
    terminal_states = ("Resolved", "Closed", "Cancelled")
    ci_ids = {
        link.ci_id for link in TaskCI.query.filter_by(target_type="ticket", target_id=ticket.id).all()
    }
    service_ids = set()
    if ci_ids:
        service_ids = {
            row.service_offering_id for row in
            ServiceOfferingCI.query.filter(
                ServiceOfferingCI.ci_id.in_(ci_ids), ServiceOfferingCI.tenant_id == ticket.tenant_id,
            ).all()
        }
    should_be_open = ticket.state not in terminal_states and ticket.impact in ("Critical", "High")
    open_outages = ServiceOutage.query.filter_by(ticket_id=ticket.id, ended_at=None).all()
    open_service_ids = {row.service_offering_id for row in open_outages}
    if should_be_open:
        for service_id in service_ids - open_service_ids:
            db.session.add(ServiceOutage(
                service_offering_id=service_id, ticket_id=ticket.id,
                started_at=ticket.created_at or now(), tenant_id=ticket.tenant_id,
            ))
        for outage in open_outages:
            if outage.service_offering_id not in service_ids:
                outage.ended_at = now()
    else:
        for outage in open_outages:
            outage.ended_at = now()


def service_availability_pct(service_offering_id, days=30):
    """Uptime % over the trailing window, merging overlapping outage
    intervals so concurrent outages (e.g. two CIs backing the same service
    both down at once) aren't double-counted as downtime."""
    window_start = now() - timedelta(days=days)
    window_end = now()
    outages = ServiceOutage.query.filter(
        ServiceOutage.service_offering_id == service_offering_id,
        db.or_(ServiceOutage.ended_at.is_(None), ServiceOutage.ended_at > window_start),
        ServiceOutage.started_at < window_end,
    ).all()
    def aware(value):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    intervals = []
    for outage in outages:
        start = max(aware(outage.started_at), window_start)
        end = min(aware(outage.ended_at) if outage.ended_at else window_end, window_end)
        if end > start:
            intervals.append((start, end))
    intervals.sort()
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    downtime_seconds = sum((end - start).total_seconds() for start, end in merged)
    total_seconds = (window_end - window_start).total_seconds()
    return round(100 * (1 - downtime_seconds / total_seconds), 3) if total_seconds else 100.0


def transition_ticket(ticket, new_state):
    if new_state not in allowed_ticket_states(ticket):
        abort(409, description=(
            f"{ticket.number} cannot move from {ticket.state} to {new_state}. "
            "Complete the required approval chain and follow the permitted lifecycle."
        ))
    if new_state == "Cancelled" and ticket.kind == "change":
        cancel_approval_chain(approval_chain_for("ticket", ticket.id))
    if ticket.kind == "change" and new_state in ("Resolved", "Closed"):
        incomplete = OperationalTask.query.filter_by(
            parent_type="ticket", parent_id=ticket.id, task_kind="change", required=True
        ).filter(
            OperationalTask.state.notin_(["Closed Complete", "Cancelled"])
        ).first()
        if incomplete:
            abort(409, description=(
                f"{ticket.number} cannot complete while required task "
                f"{incomplete.number} remains {incomplete.state}."
            ))
    if ticket.kind == "change" and new_state == "Closed" and not ticket.post_implementation_review:
        abort(409, description=(
            f"{ticket.number} cannot close without a post-implementation review "
            "(ITIL 4 change enablement requires a documented outcome before a "
            "change is considered complete). Record the review first."
        ))
    old_state = ticket.state
    ticket.state = new_state
    sync_slas("ticket", ticket.id, new_state)
    if ticket.kind == "incident":
        sync_service_outages(ticket)
    if new_state != old_state:
        queue_workflow_event(
            "ticket.state_entry", "ticket", ticket.id,
            ticket_workflow_context(ticket, old_state),
            tenant_id=ticket.tenant_id,
        )
    if (
        ticket.kind == "incident"
        and setting_bool("SYNC_CHILD_INCIDENT_STATES", False)
        and new_state in ("Pending", "Resolved", "Closed", "Cancelled")
    ):
        child_links = RecordLink.query.filter_by(
            target_type="ticket", target_id=ticket.id, link_type="parent_incident"
        ).all()
        for link in child_links:
            child = db.session.get(Ticket, link.source_id)
            if (
                child and child.kind == "incident"
                and new_state in TICKET_TRANSITIONS.get(child.state, ())
                and child.state != new_state
            ):
                old_state = child.state
                child.state = new_state
                sync_slas("ticket", child.id, new_state)
                log_history(
                    "ticket", child.id, "State synchronized from parent incident",
                    "state", old_state, new_state,
                    f"Parent {ticket.number} moved to {new_state}.",
                )


def allowed_enterprise_states(record):
    approvals = list(record.approvals)
    if any(item.state == "Requested" for item in approvals):
        return (record.state,)
    if any(item.state == "Rejected" for item in approvals):
        return ("Rejected",)
    return ENTERPRISE_TRANSITIONS.get(record.state, (record.state,))


def transition_enterprise(record, new_state):
    if new_state in ("Awaiting Approval", "Approved", "Rejected") and new_state != record.state:
        abort(409, description="Approval-derived states can be changed only by an approval decision.")
    if new_state not in allowed_enterprise_states(record):
        abort(409, description=(
            f"{record.number} cannot move from {record.state} to {new_state} "
            "while its approval or lifecycle prerequisites are incomplete."
        ))
    if record.domain == "problem" and new_state in ("Resolved", "Completed", "Closed"):
        incomplete = OperationalTask.query.filter_by(
            parent_type="enterprise", parent_id=record.id,
            task_kind="problem", required=True,
        ).filter(
            OperationalTask.state.notin_(["Closed Complete", "Cancelled"])
        ).first()
        if incomplete:
            abort(409, description=(
                f"{record.number} cannot complete while required task "
                f"{incomplete.number} remains {incomplete.state}."
            ))
    record.state = new_state


def ritm_linked_change(ritm):
    """The Change Request linked to this RITM via record_link_add, if any.
    SCTASKs belong to the RITM, not the Change — this is a related record,
    not a parent-child relationship."""
    link = RecordLink.query.filter_by(
        source_type="ritm", source_id=ritm.id, link_type="requested_item_change",
    ).first()
    if not link:
        return None
    return db.session.get(Ticket, link.target_id)


def transition_catalog_task(task, new_state):
    chain = approval_chain_for("ritm", task.requested_item_id)
    if chain and chain.state != "Approved":
        abort(409, description="Fulfillment cannot start until the requested item is approved.")
    if new_state == "Work in Progress":
        linked_change = ritm_linked_change(task.requested_item)
        if linked_change and linked_change.state in ("New", "Awaiting Approval"):
            abort(409, description=(
                f"{task.number} cannot start production work: it is linked to "
                f"{linked_change.number}, which is not yet approved and authorized. "
                "Coordination on this task (details, scheduling) is fine — set it to "
                "Pending until the change is authorized."
            ))
    control = task.flow_control
    if (
        control and control.execution_mode == "Sequential"
        and control.predecessor
        and control.predecessor.state != "Closed Complete"
        and new_state not in ("Open", "Closed Skipped")
    ):
        abort(409, description=(
            f"{task.number} cannot start until predecessor "
            f"{control.predecessor.number} is Closed Complete."
        ))
    allowed = CATALOG_TASK_TRANSITIONS.get(task.state, (task.state,))
    if new_state not in allowed:
        abort(409, description=f"{task.number} cannot move from {task.state} to {new_state}.")
    task.state = new_state


def change_task_gate_block(task, new_state):
    """Enforce the change-task unlocking model: Planning may proceed before
    approval; Implementation/Testing stay Pending until the change is
    authorized and any predecessor implementation is done; Review stays
    Pending until implementation and testing are complete."""
    if task.task_kind != "change" or new_state in ("Pending", "Cancelled"):
        return None
    if task.task_type == "Planning":
        return None
    ticket = db.session.get(Ticket, task.parent_id)
    if not ticket:
        return None
    siblings = OperationalTask.query.filter_by(
        parent_type="ticket", parent_id=ticket.id, task_kind="change",
    ).all()
    if task.task_type == "Implementation":
        chain = approval_chain_for("ticket", ticket.id)
        if chain and chain.state != "Approved":
            return (
                f"{task.number} is an Implementation task and must stay Pending until "
                f"{ticket.number} has received all approvals for the current authorization gate."
            )
    elif task.task_type == "Testing":
        implementation_tasks = [t for t in siblings if t.task_type == "Implementation"]
        if implementation_tasks and not any(
            t.state == "Closed Complete" for t in implementation_tasks
        ):
            return (
                f"{task.number} is a Testing task and must stay Pending until at least one "
                "Implementation task is Closed Complete."
            )
    elif task.task_type == "Review":
        prerequisite_tasks = [
            t for t in siblings
            if t.task_type in ("Implementation", "Testing") and t.required and t.id != task.id
        ]
        incomplete = [
            t for t in prerequisite_tasks
            if t.state not in ("Closed Complete", "Closed Incomplete", "Cancelled")
        ]
        if incomplete:
            return (
                f"{task.number} is a Review task and must stay Pending until all required "
                "Implementation and Testing tasks are complete."
            )
    return None


def transition_operational_task(task, new_state):
    allowed = OPERATIONAL_TASK_TRANSITIONS.get(task.state, (task.state,))
    if new_state not in allowed:
        abort(409, description=f"{task.number} cannot move from {task.state} to {new_state}.")
    block = change_task_gate_block(task, new_state)
    if block:
        abort(409, description=block)
    task.state = new_state


def ticket_owning_group(ticket):
    if ticket.kind == "change" and ticket.change_ownership:
        return ticket.change_ownership.group
    assignment = TicketAssignmentGroup.query.filter_by(ticket_id=ticket.id).first()
    return assignment.group if assignment else None


def user_can_manage_ticket(user, ticket):
    if not user.is_authenticated or not user.active:
        return False
    if ticket.tenant_id != user.tenant_id:
        return False
    if user.role == "admin":
        return True
    group = ticket_owning_group(ticket)
    if not group:
        return False
    if group.manager_id == user.id:
        return True
    return GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first() is not None


def visible_ticket_query(user):
    query = Ticket.query
    if not user.is_authenticated or not user.active:
        return query.filter(Ticket.id == -1)
    query = query.filter(Ticket.tenant_id == user.tenant_id)
    if user.role == "admin":
        return query
    group_ids = user_support_group_ids(user)
    if group_ids and SupportGroup.query.filter(
        SupportGroup.id.in_(group_ids),
        SupportGroup.group_type == "IT Fulfillment",
        SupportGroup.active.is_(True),
    ).first():
        return query
    ticket_ids = {
        row[0] for row in db.session.query(Ticket.id).filter(
            Ticket.requester_id == user.id
        ).all()
    }
    ticket_ids.update(
        row[0] for row in db.session.query(ApprovalChain.target_id).join(
            ApprovalGate, ApprovalGate.chain_id == ApprovalChain.id
        ).join(ApprovalVote, ApprovalVote.gate_id == ApprovalGate.id).filter(
            ApprovalChain.target_type == "ticket",
            ApprovalVote.approver_id == user.id,
            ApprovalVote.state.in_(["Requested", "Approved", "Rejected"]),
        ).all()
    )
    if group_ids:
        ticket_ids.update(
            row[0] for row in db.session.query(OperationalTask.parent_id).filter(
                OperationalTask.parent_type == "ticket",
                OperationalTask.assignment_group_id.in_(group_ids),
            ).all()
        )
    return query.filter(Ticket.id.in_(ticket_ids)) if ticket_ids else query.filter(Ticket.id == -1)


def user_can_view_ticket(user, ticket):
    return visible_ticket_query(user).filter(Ticket.id == ticket.id).first() is not None


def require_ticket_team_access(ticket):
    if not user_can_manage_ticket(current_user, ticket):
        group = ticket_owning_group(ticket)
        abort(403, description=(
            f"Only active members of {group.name if group else 'the owning team'} "
            f"can update {ticket.number}."
        ))


TICKET_LOCKED_STATES = ("Resolved", "Closed", "Cancelled")


def ticket_locked_for_edits(ticket):
    return ticket.state in TICKET_LOCKED_STATES


def require_ticket_not_locked(ticket):
    if ticket_locked_for_edits(ticket):
        flash(
            f"{ticket.number} is {ticket.state} and locked: only comments and notes "
            "can be added. Reopen it first to make other changes.",
            "error",
        )
        return False
    return True


def ticket_team_agents(ticket):
    group = ticket_owning_group(ticket)
    if not group:
        return []
    user_ids = {member.user_id for member in group.members}
    if group.manager_id:
        user_ids.add(group.manager_id)
    if not user_ids:
        return []
    return User.query.filter(
        User.id.in_(user_ids), User.active.is_(True),
        User.role.in_(["agent", "manager", "admin", "superadmin"]),
    ).order_by(User.name).all()


# Canonical environment labels, plus the nicknames staff actually type/paste
# (spreadsheet imports, the public API) that must resolve to the same
# environment rather than being tracked as distinct values -- "Prod" and
# "Production" are the same environment, not two different ones.
CANONICAL_ENVIRONMENTS = ("Production", "Staging", "Development", "Test")
ENVIRONMENT_ALIASES = {
    "prod": "Production", "production": "Production", "prd": "Production",
    "dev": "Development", "development": "Development",
    "uat": "Staging", "staging": "Staging", "stage": "Staging",
    "test": "Test", "qa": "Test",
}


def calculate_change_risk_score(change_type, ci):
    """A transparent, repeatable starting point for change risk instead of
    every change defaulting to the same manually-typed 50 regardless of
    what's actually being changed -- ITIL 4 change enablement expects risk
    assessment to be systematic, not just individual judgment with no
    calculation trail. Still fully overridable: leaving the risk score
    field blank on the change form uses this value; typing a different
    number records it as an explicit override (ChangeGovernance.risk_score_overridden)
    with an optional reason, so the starting point and the human decision
    both stay visible."""
    base = {"Standard": 15, "Normal": 40, "Emergency": 70}.get(change_type, 40)
    if ci:
        base += {"Critical": 30, "High": 15, "Medium": 0, "Low": -10}.get(ci.business_criticality, 0)
        if normalize_environment(ci.environment) == "Production":
            base += 15
    return max(0, min(100, base))


def normalize_environment(value):
    """Maps a free-text environment value (e.g. "Prod", "UAT") to its
    canonical label ("Production", "Staging"). Unrecognized values are
    returned trimmed but otherwise unchanged, rather than discarded --
    normalization only collapses *known* synonyms, it never invents data."""
    if not value:
        return value
    stripped = value.strip()
    return ENVIRONMENT_ALIASES.get(stripped.casefold(), stripped)


def ci_class_is_management(ci_class):
    text = (ci_class or "").casefold()
    return "management" in text or "mgmt" in text


def ccb_required_environments():
    raw = setting_value("CCB_REQUIRED_ENVIRONMENTS", "Production")
    return {normalize_environment(value) for value in raw.split(",") if value.strip()}


def ci_always_requires_ccb(ci_class, environment, business_criticality):
    """Whether a CI's characteristics alone mandate CCB approval on any
    change against it, independent of the admin-configurable
    CCB_REQUIRED_ENVIRONMENTS setting: Production environment, a
    Management-class CI, or Critical business criticality."""
    return (
        normalize_environment(environment) == "Production"
        or ci_class_is_management(ci_class)
        or (business_criticality or "") == "Critical"
    )


def change_requires_ccb(governance):
    if not governance.ccb_required:
        return False
    ci = governance.ci
    if ci is None:
        return True
    if ci.require_ccb_approval:
        return True
    return normalize_environment(ci.environment) in ccb_required_environments()


def executive_office_group(tenant_id):
    """The support group whose manager is this tenant's designated executive
    (CEO) approver for change governance. Seeded automatically alongside the
    Change Control Board (see seed()); configured the same way a team's
    manager is (itil_admin's "Executive approval" section)."""
    return SupportGroup.query.filter_by(name="Executive Office", tenant_id=tenant_id).first()


def change_approval_stages(ticket):
    ownership = ticket.change_ownership
    governance = ticket.change_governance
    if not ownership or not ownership.group.manager or not ownership.group.manager.active:
        abort(409, description="The owning team requires an active manager.")
    stages = [{
        "name": f"{ownership.group.name} manager assessment",
        "mode": "all",
        "approver_ids": [ownership.group.manager_id],
    }]
    covered_group_ids = {ownership.group_id}
    ci = governance.ci
    ci_group = ci.support_group if ci else None
    if ci_group and ci_group.id != ownership.group_id:
        if not ci_group.manager or not ci_group.manager.active:
            abort(409, description=f"The {ci_group.name} team (owner of {ci.name}) requires an active manager.")
        stages.append({
            "name": f"{ci_group.name} manager assessment (CI owner)",
            "mode": "all",
            "approver_ids": [ci_group.manager_id],
        })
        covered_group_ids.add(ci_group.id)
    # If this change's CI backs a business service (ServiceOfferingCI) that is
    # also backed by other CIs owned by different teams, each of those teams
    # is exposed to the same change even though it's not "their" CI directly
    # -- e.g. a shared load balancer's change plan matters to every team whose
    # application sits behind it. Require each such team's manager too.
    if ci:
        service_ids = [
            row[0] for row in db.session.query(ServiceOfferingCI.service_offering_id)
            .filter_by(ci_id=ci.id, tenant_id=ticket.tenant_id).all()
        ]
        if service_ids:
            sibling_group_ids = {
                row[0] for row in db.session.query(ConfigurationItem.support_group_id)
                .join(ServiceOfferingCI, ServiceOfferingCI.ci_id == ConfigurationItem.id)
                .filter(
                    ServiceOfferingCI.service_offering_id.in_(service_ids),
                    ConfigurationItem.tenant_id == ticket.tenant_id,
                    ConfigurationItem.support_group_id.isnot(None),
                ).all()
            }
            for group_id in sorted(sibling_group_ids - covered_group_ids):
                sibling_group = db.session.get(SupportGroup, group_id)
                if not sibling_group or not sibling_group.active:
                    continue
                if not sibling_group.manager or not sibling_group.manager.active:
                    abort(409, description=(
                        f"The {sibling_group.name} team (co-owner of a service this CI backs) "
                        "requires an active manager."
                    ))
                stages.append({
                    "name": f"{sibling_group.name} manager assessment (service co-owner)",
                    "mode": "all",
                    "approver_ids": [sibling_group.manager_id],
                })
                covered_group_ids.add(group_id)
    if governance.change_type != "Standard" and change_requires_ccb(governance):
        ccb = SupportGroup.query.filter_by(name="Change Control Board", tenant_id=ticket.tenant_id).first()
        ccb_ids = [
            member.user_id for member in (ccb.members if ccb else [])
            if member.role == "CCB approver" and member.user.active
        ]
        if not ccb_ids:
            abort(409, description=(
                "CCB membership must be configured before a non-standard change can be submitted."
            ))
        # One active CCB approver authorizes -- not the whole board, and not
        # a majority. Emergency changes already worked this way (an
        # expedited/auditable route: CLAUDE.md "'Submitted late' is not an
        # emergency justification" -- this only shortens quorum, it never
        # skips CCB authorization or the audit trail); Normal changes now
        # require the same single-approver quorum rather than a majority.
        stages.append({
            "name": (
                "Emergency CCB authorization (expedited)"
                if governance.change_type == "Emergency" else "CCB authorization"
            ),
            "mode": "any",
            "approver_ids": ccb_ids,
        })
        executive = executive_office_group(ticket.tenant_id)
        if not executive or not executive.manager or not executive.manager.active:
            abort(409, description=(
                "Executive (CEO) approval authority must be configured "
                "(itil_admin's Executive approval section) before a "
                "non-standard change requiring CCB authorization can be submitted."
            ))
        stages.append({
            "name": "Executive (CEO) approval",
            "mode": "all",
            "approver_ids": [executive.manager_id],
        })
    return stages


def supersede_change_approval(ticket, changed_fields):
    previous = approval_chain_for("ticket", ticket.id)
    if previous:
        previous.state = "Superseded"
        previous.completed_at = now()
        for gate in previous.gates:
            if gate.state in ("Pending", "Requested"):
                gate.state = "Superseded"
            for vote in gate.votes:
                if vote.state in ("Not Requested", "Requested"):
                    vote.state = "No Longer Required"
    revision = ticket.change_revision
    if not revision:
        revision = ChangeRevision(ticket_id=ticket.id, revision=1)
        db.session.add(revision)
    revision.revision += 1
    revision.last_material_change_at = now()
    stages = change_approval_stages(ticket)
    summary = ", ".join(changed_fields)
    # Notify only once for the first (currently active) stage's approvers, with
    # reapproval-specific wording; later stages (e.g. CCB) are notified by
    # activate_gate() with its default wording once their gate actually opens.
    chain = create_approval_chain(
        f"{ticket.number} change authorization v{revision.revision}",
        "ticket", ticket.id, stages,
        first_gate_title=f"Reapproval required: {ticket.number} v{revision.revision}",
        first_gate_body=f"Material change fields were revised: {summary}. Review the new plan before implementation.",
    )
    log_history(
        "ticket", ticket.id, "Approval restarted",
        "approval revision",
        revision.revision - 1, revision.revision,
        f"Material fields changed: {summary}",
    )
    return chain


def ci_impact_set(tenant_id, ci_ids, max_depth=4):
    """Expand a set of CI ids to include everything that transitively depends on
    them, by walking CIRelationship upward (if X 'Depends on'/'Runs on'/'Hosted
    on'/etc. Y, X is the parent and Y the child -- so a CI going down impacts
    every ancestor reachable from it, not just what's directly linked). This is
    what lets change conflict detection and CI-page impact analysis answer
    "what actually breaks if this CI goes down" instead of stopping at direct
    links, which is otherwise the CMDB's biggest gap."""
    result = set(ci_ids)
    frontier = set(ci_ids)
    for _ in range(max_depth):
        if not frontier:
            break
        rows = CIRelationship.query.filter(
            CIRelationship.tenant_id == tenant_id, CIRelationship.child_id.in_(frontier)
        ).all()
        next_frontier = {row.parent_id for row in rows} - result
        if not next_frontier:
            break
        result |= next_frontier
        frontier = next_frontier
    return result


def _conflict_descriptions(tenant_id, ci_ids, planned_start, planned_end, exclude_governance_id=None, exclude_ticket_id=None):
    """Core schedule/CI overlap check shared by pre-creation and post-creation
    conflict detection. Returns human-readable conflict description strings."""
    conflicts = []
    if not (ci_ids and planned_start and planned_end):
        return conflicts
    impacted_ci_ids = ci_impact_set(tenant_id, ci_ids)
    overlapping_query = ChangeGovernance.query.join(
        Ticket, ChangeGovernance.ticket_id == Ticket.id
    ).filter(
        Ticket.tenant_id == tenant_id,
        Ticket.state.notin_(["Cancelled", "Rejected"]),
        ChangeGovernance.planned_start.isnot(None),
        ChangeGovernance.planned_end.isnot(None),
        ChangeGovernance.planned_start < planned_end,
        ChangeGovernance.planned_end > planned_start,
    )
    if exclude_governance_id is not None:
        overlapping_query = overlapping_query.filter(ChangeGovernance.id != exclude_governance_id)
    for other in overlapping_query.all():
        other_ci_ids = {
            link.ci_id for link in TaskCI.query.filter_by(
                target_type="ticket", target_id=other.ticket_id
            ).all()
        }
        if other.ci_id:
            other_ci_ids.add(other.ci_id)
        if ci_ids.intersection(other_ci_ids):
            conflicts.append(f"{other.ticket.number} (overlapping change)")
        elif impacted_ci_ids.intersection(other_ci_ids):
            conflicts.append(f"{other.ticket.number} (overlapping change on a dependent CI)")
    incident_query = Ticket.query.filter(
        Ticket.tenant_id == tenant_id,
        Ticket.kind == "incident",
        Ticket.state.notin_(["Resolved", "Closed", "Cancelled"]),
    ).join(
        TaskCI, db.and_(TaskCI.target_type == "ticket", TaskCI.target_id == Ticket.id)
    ).filter(TaskCI.ci_id.in_(impacted_ci_ids))
    if exclude_ticket_id is not None:
        incident_query = incident_query.filter(Ticket.id != exclude_ticket_id)
    for incident in incident_query.all():
        incident_ci_ids = {
            link.ci_id for link in TaskCI.query.filter_by(target_type="ticket", target_id=incident.id).all()
        }
        if ci_ids.intersection(incident_ci_ids):
            conflicts.append(f"{incident.number} (open incident on same CI)")
        else:
            conflicts.append(f"{incident.number} (open incident on a CI that depends on this one)")
    return conflicts


def precreate_change_conflicts(tenant_id, ci_id, planned_start, planned_end):
    """Checked while a change is still being filled out, before it exists, so the
    submitter is warned and blocked instead of discovering the conflict afterward."""
    ci_ids = {ci_id} if ci_id else set()
    return _conflict_descriptions(tenant_id, ci_ids, planned_start, planned_end)


def active_change_freeze(tenant_id, planned_start, planned_end):
    """Returns the first ChangeFreezeWindow whose range overlaps the given
    planned window, or None. Overlap uses the same open-interval test as
    _conflict_descriptions' change-overlap check."""
    if not (planned_start and planned_end):
        return None
    return ChangeFreezeWindow.query.filter(
        ChangeFreezeWindow.tenant_id == tenant_id,
        ChangeFreezeWindow.starts_at < planned_end,
        ChangeFreezeWindow.ends_at > planned_start,
    ).order_by(ChangeFreezeWindow.starts_at).first()


def run_change_conflict_detection(ticket, governance):
    """Flags scheduling conflicts against other changes and open incidents/problems
    sharing a CI during the same window. Tenant-scoped: joins through Ticket so a
    change in one tenant never leaks into another tenant's conflict check."""
    current_ci_ids = {
        link.ci_id for link in TaskCI.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).all()
    }
    if governance.ci_id:
        current_ci_ids.add(governance.ci_id)
    conflicts = _conflict_descriptions(
        ticket.tenant_id, current_ci_ids, governance.planned_start, governance.planned_end,
        exclude_governance_id=governance.id, exclude_ticket_id=ticket.id,
    )
    governance.conflict_status = (
        f"Conflict: {', '.join(conflicts)}" if conflicts else "No conflict"
    )[:500]
    # Matches this codebase's existing convention for routine automated
    # checks (e.g. the SLA-breach scan only logs a "breached" entry, never
    # a "checked, not breached" one for every non-breaching pass): the
    # ticket-facing timeline only gets an entry for the exceptional,
    # actionable outcome. The tamper-evident audit log below always
    # records the check regardless, so "checked, no conflict" is never
    # lost -- it's just not clutter in front of the user.
    if conflicts:
        log_history(
            "ticket", ticket.id, "Conflict detection completed",
            details=governance.conflict_status,
        )
    audit("conflict check", ticket.number, governance.conflict_status)
    return conflicts


def user_in_group(user, group):
    if not user.is_authenticated or not user.active or not group:
        return False
    # The "admin bypasses membership" shortcut must still respect tenant
    # boundaries -- an admin's role grants authority within their own
    # tenant, not over another tenant's teams, even though tenant admins
    # historically weren't checked here (found while hardening tenant_id
    # scoping across GroupMember/CatalogTask call sites).
    if group.tenant_id != user.tenant_id:
        return False
    return (
        user.role == "admin"
        or group.manager_id == user.id
        or GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first() is not None
    )


def activate_gate(gate, notify_title=None, notify_body=None):
    gate.state = "Requested"
    # Only route through the admin-editable template when the caller
    # didn't supply its own custom wording -- an explicit override (used
    # by some chain types for more specific phrasing) must always win.
    using_default_wording = notify_title is None and notify_body is None
    title = notify_title or f"Approval requested: {gate.name}"
    body = notify_body or f"Your decision is required for approval chain {gate.chain.name}."
    for vote in gate.votes:
        vote.state = "Requested"
        create_notification(
            vote.approver_id, title, body,
            tenant_id=gate.chain.tenant_id, target_type="approval_queue",
            event_type="approval.requested" if using_default_wording else None,
            template_vars={"gate_name": gate.name, "chain_name": gate.chain.name},
        )


def create_approval_chain(name, target_type, target_id, stages, first_gate_title=None, first_gate_body=None):
    if not stages or any(not [item for item in stage["approver_ids"] if item]
                         for stage in stages):
        raise ValueError("Every approval stage must have at least one configured approver.")
    chain = ApprovalChain(name=name, target_type=target_type, target_id=target_id)
    db.session.add(chain)
    db.session.flush()
    for sequence, stage in enumerate(stages, 1):
        gate = ApprovalGate(chain_id=chain.id, sequence=sequence, name=stage["name"],
                            mode=stage.get("mode", "all"))
        db.session.add(gate)
        db.session.flush()
        for approver_id in sorted(set(stage["approver_ids"])):
            db.session.add(ApprovalVote(gate_id=gate.id, approver_id=approver_id))
    db.session.flush()
    first_gate = ApprovalGate.query.filter_by(chain_id=chain.id, sequence=1).one()
    activate_gate(first_gate, notify_title=first_gate_title, notify_body=first_gate_body)
    set_target_state(target_type, target_id, "Awaiting Approval")
    log_history(
        target_type, target_id, "Approval requested",
        details=f"{name} started with {len(stages)} stage(s).",
    )
    return chain


def decide_vote(vote, decision, comments):
    if vote.state != "Requested" or vote.gate.state != "Requested" or vote.gate.chain.state != "Running":
        abort(409, description="This approval is no longer active.")
    vote.state = decision
    vote.comments = comments
    vote.decided_at = now()
    gate = vote.gate
    chain = gate.chain
    if decision == "Rejected":
        gate.state = "Rejected"
        chain.state = "Rejected"
        chain.completed_at = now()
        set_target_state(chain.target_type, chain.target_id, "Rejected")
        return
    requested = [item for item in gate.votes if item.state == "Requested"]
    approved = [item for item in gate.votes if item.state == "Approved"]
    majority = (len(gate.votes) // 2) + 1
    gate_complete = ((gate.mode == "any" and approved)
                     or (gate.mode == "all" and not requested)
                     or (gate.mode == "majority" and len(approved) >= majority))
    if not gate_complete:
        return
    gate.state = "Approved"
    for item in requested:
        item.state = "No Longer Required"
    next_gate = next((item for item in chain.gates if item.sequence == gate.sequence + 1), None)
    if next_gate:
        chain.current_stage = next_gate.sequence
        activate_gate(next_gate)
    else:
        chain.state = "Approved"
        chain.completed_at = now()
        set_target_state(chain.target_type, chain.target_id, "Approved")
        if chain.target_type == "ritm":
            ritm = db.session.get(RequestedItem, chain.target_id)
            ritm.stage = "Fulfillment"
            create_catalog_task(ritm)


def attach_slas(target_type, target_id, priority, organization_id=None):
    """`organization_id` (only meaningful for target_type == "client_ticket")
    lets a Client Management organization's own SLADefinition rows
    (client_organization_id set) override the tenant-wide default (rows with
    client_organization_id null) for the same priority -- every existing
    caller passes no organization_id, and every row before this parameter
    existed has client_organization_id null, so this is a no-op everywhere
    else in the app."""
    definitions = SLADefinition.query.filter_by(target_type=target_type, active=True).all()
    definitions = [d for d in definitions if d.client_organization_id in (None, organization_id)]
    if organization_id is not None:
        overridden_priorities = {
            d.priority for d in definitions if d.client_organization_id == organization_id
        }
        definitions = [
            d for d in definitions
            if d.client_organization_id == organization_id or d.priority not in overridden_priorities
        ]
    for definition in definitions:
        if definition.priority and definition.priority != priority:
            continue
        exists = TaskSLA.query.filter_by(definition_id=definition.id, target_type=target_type,
                                         target_id=target_id).first()
        if not exists:
            started = now()
            if definition.schedule:
                holidays = [row.holiday_date for row in definition.schedule.holidays]
                breach_at = add_business_minutes(
                    started, definition.duration_minutes, definition.schedule, holidays
                )
            else:
                breach_at = started + timedelta(minutes=definition.duration_minutes)
            task_sla = TaskSLA(
                definition_id=definition.id, target_type=target_type,
                target_id=target_id, started_at=started, breach_at=breach_at,
            )
            db.session.add(task_sla)
            db.session.flush()
            db.session.add(SLAEvent(
                task_sla_id=task_sla.id, event_type="Started",
                details=f"Target {breach_at.isoformat()}",
                tenant_id=definition.tenant_id,
            ))


def sync_slas(target_type, target_id, state):
    for task_sla in TaskSLA.query.filter_by(target_type=target_type, target_id=target_id).all():
        if task_sla.stage in ("Completed", "Cancelled"):
            continue
        pause_states = {value.strip() for value in task_sla.definition.pause_states.split(",")}
        if state in ("Resolved", "Closed", "Completed", "Closed Complete", "Solved"):
            task_sla.stage = "Completed"
            task_sla.stopped_at = now()
            db.session.add(SLAEvent(
                task_sla_id=task_sla.id, event_type="Completed",
                details=f"Stopped in state {state}",
                tenant_id=task_sla.definition.tenant_id,
            ))
        elif state in pause_states and task_sla.stage == "In Progress":
            task_sla.stage = "Paused"
            task_sla.paused_at = now()
            db.session.add(SLAEvent(
                task_sla_id=task_sla.id, event_type="Paused",
                details=f"Paused in state {state}",
                tenant_id=task_sla.definition.tenant_id,
            ))
        elif state not in pause_states and task_sla.stage == "Paused":
            current = now()
            if task_sla.paused_at.tzinfo is None:
                current = current.replace(tzinfo=None)
            paused = int((current - task_sla.paused_at).total_seconds())
            task_sla.paused_seconds += paused
            task_sla.breach_at += timedelta(seconds=paused)
            task_sla.paused_at = None
            task_sla.stage = "In Progress"
            db.session.add(SLAEvent(
                task_sla_id=task_sla.id, event_type="Resumed",
                details=f"Resumed after {paused} seconds",
                tenant_id=task_sla.definition.tenant_id,
            ))
        current = now()
        if task_sla.breach_at.tzinfo is None:
            current = current.replace(tzinfo=None)
        if task_sla.stage == "In Progress" and current > task_sla.breach_at:
            task_sla.breached = True


def _match_existing_client_ticket(tenant_id, parsed):
    """Threading: Message-ID/References headers first (most robust, per
    Zendesk's own documented convention), the bracketed [CXT...] subject
    token as fallback. Returns None if nothing matches (a new ticket)."""
    ref_ids = referenced_message_ids(parsed["in_reply_to"], parsed["references"])
    if ref_ids:
        message = ClientTicketMessage.query.filter(
            ClientTicketMessage.tenant_id == tenant_id,
            ClientTicketMessage.message_id.in_(ref_ids),
        ).first()
        if message:
            return message.ticket
    token = extract_ticket_token(parsed["subject"])
    if token:
        ticket = ClientTicket.query.filter_by(tenant_id=tenant_id, number=token).first()
        if ticket:
            return ticket
    return None


def _create_client_ticket_from_email(mailbox, parsed):
    """Auto-creates the ClientContact (always, from the From address) and,
    for a non-free-mail domain when the mailbox allows it, the
    ClientOrganization too (matching Freshdesk's documented "blacklist
    free-mail domains from company auto-linking" convention) -- otherwise
    falls back to the mailbox's configured default organization. Returns
    None (message dropped, logged) if there's nowhere to attach the ticket
    at all, rather than crashing the whole inbox poll on one bad sender."""
    tenant_id = mailbox.tenant_id
    contact = ClientContact.query.filter_by(tenant_id=tenant_id, email=parsed["from_email"]).first()
    if not contact:
        domain = parsed["from_email"].split("@")[-1] if "@" in parsed["from_email"] else ""
        organization = None
        if domain and mailbox.auto_create_organization_by_domain and not is_free_mail_domain(domain):
            organization = ClientOrganization.query.filter_by(tenant_id=tenant_id, domain=domain).first()
            if not organization:
                organization = ClientOrganization(tenant_id=tenant_id, name=domain, domain=domain)
                db.session.add(organization)
                db.session.flush()
        if not organization:
            organization = mailbox.default_organization
        if not organization:
            current_app.logger.warning(
                "No organization available for inbound email from %s (mailbox=%s) -- dropping",
                parsed["from_email"], mailbox.name,
            )
            return None
        contact = ClientContact(
            tenant_id=tenant_id, organization_id=organization.id,
            name=parsed["from_name"] or parsed["from_email"], email=parsed["from_email"],
        )
        db.session.add(contact)
        db.session.flush()
    group = client_sysops_group(tenant_id)
    if not group:
        current_app.logger.warning(
            "No SysOps team configured for tenant %s -- dropping inbound email", tenant_id,
        )
        return None
    subject = (parsed["subject"] or "(no subject)")[:200]
    description = (parsed["body_text"] or "(no message body)")[:5000]

    def build():
        row = ClientTicket(
            number=sequence_number(ClientTicket, "CXT"), tenant_id=tenant_id,
            subject=subject, description=description,
            status="New", priority="Normal", ticket_type="Question", channel="Email",
            contact_id=contact.id, organization_id=contact.organization_id,
            support_group_id=group.id, created_by_id=mailbox.created_by_id,
            mailbox_id=mailbox.id,
        )
        db.session.add(row)
        return row
    return create_with_retry_on_number_collision(
        build, error_description="Could not allocate a client ticket number for inbound email.",
    )


def _process_one_inbound_email(mailbox, connection, msg_num):
    status, msg_data = connection.fetch(msg_num, "(RFC822)")
    if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
        return False
    raw_bytes = msg_data[0][1]
    connection.store(msg_num, "+FLAGS", "\\Seen")
    parsed = parse_inbound_email(raw_bytes)
    if parsed["is_auto_generated"] or not parsed["from_email"]:
        return False
    # Last-resort loop/flood defense, on top of the Auto-Submitted check
    # above -- Zendesk documents an identical per-sender rate ceiling for
    # exactly this reason (a broken auto-responder loop that somehow
    # doesn't set Auto-Submitted correctly).
    if not route_rate_limit("inbound_email", parsed["from_email"], 20, window_seconds=3600):
        current_app.logger.warning("Inbound email rate limit exceeded for %s", parsed["from_email"])
        return False

    ticket = _match_existing_client_ticket(mailbox.tenant_id, parsed)
    is_new_ticket = ticket is None
    if is_new_ticket:
        ticket = _create_client_ticket_from_email(mailbox, parsed)
        if ticket is None:
            return False
    elif ticket.status in ("Solved", "Closed"):
        ticket.status = "Open"

    db.session.add(ClientTicketMessage(
        tenant_id=ticket.tenant_id, client_ticket_id=ticket.id, author_id=None,
        body=parsed["body_text"] or "(no message body)", visibility="public",
        event_type="opened" if is_new_ticket else "inbound_email",
        message_id=parsed["message_id"] or None, in_reply_to=parsed["in_reply_to"] or None,
    ))
    ticket.updated_at = now()

    total_size = 0
    for attachment in parsed["attachments"]:
        if total_size + len(attachment["data"]) > MAX_ATTACHMENT_TOTAL_BYTES:
            current_app.logger.info(
                "Skipped inbound email attachment over the size ceiling: ticket=%s", ticket.number,
            )
            continue
        if save_email_attachment(ticket, attachment["filename"], attachment["data"], mailbox.created_by_id):
            total_size += len(attachment["data"])

    if is_new_ticket:
        attach_slas("client_ticket", ticket.id, ticket.priority, organization_id=ticket.organization_id)
        agents = User.query.filter(
            User.tenant_id == ticket.tenant_id, User.active.is_(True),
            User.role.in_(["agent", "manager", "admin"]),
        ).all()
        evaluate_client_triggers("created", ticket, agents)
    audit("client email ingested", ticket.number, parsed["from_email"], tenant_id=ticket.tenant_id)
    db.session.commit()
    return True


def _poll_client_mailbox(mailbox, limit=50):
    connection_cls = imaplib.IMAP4_SSL if mailbox.imap_use_ssl else imaplib.IMAP4
    connection = connection_cls(mailbox.imap_host, mailbox.imap_port)
    try:
        connection.login(mailbox.imap_username, mailbox.imap_password)
        connection.select(mailbox.imap_folder)
        status, data = connection.search(None, "UNSEEN")
        if status != "OK":
            raise RuntimeError(f"IMAP search failed: {status}")
        message_numbers = data[0].split()[:limit]
        processed = 0
        for msg_num in message_numbers:
            try:
                if _process_one_inbound_email(mailbox, connection, msg_num):
                    processed += 1
            except Exception:
                current_app.logger.exception(
                    "Failed to process inbound email num=%s mailbox=%s", msg_num, mailbox.name,
                )
                db.session.rollback()
        mailbox.last_polled_at = now()
        mailbox.last_poll_status = "ok"
        mailbox.last_poll_error = ""
        db.session.commit()
        return processed
    finally:
        try:
            connection.logout()
        except Exception:
            pass


def process_client_email_inbox(limit=50):
    """Client Management email channel: polls every active ClientMailbox
    over IMAP. Mirrors process_sla_breaches()'s periodic-scan shape --
    returns an int count, isolates each mailbox's own failure so one
    broken mailbox config never stops another tenant's mailbox (or the
    rest of the worker loop) from running."""
    processed = 0
    for mailbox in ClientMailbox.query.filter_by(active=True).all():
        try:
            processed += _poll_client_mailbox(mailbox, limit=limit)
        except Exception as error:
            mailbox.last_polled_at = now()
            mailbox.last_poll_status = "error"
            mailbox.last_poll_error = str(error)[:2000]
            db.session.commit()
            current_app.logger.exception("Client mailbox poll failed: %s", mailbox.name)
    return processed


def deliver_client_email_reply(ticket, message, mailbox):
    """Sends an agent's public reply on a Client Management ticket as a
    real email to the customer, via `mailbox`'s SMTP settings. Threads
    correctly (In-Reply-To/References from the ticket's latest known
    Message-ID) and embeds the bracketed ticket token in the subject as
    the documented fallback signal for the customer's own reply to thread
    back in correctly, mirroring Zendesk's own encoded-ticket-ID
    convention. Stores the generated Message-ID back onto `message` so a
    later customer reply threads via the headers (the primary signal)."""
    prior = ClientTicketMessage.query.filter(
        ClientTicketMessage.client_ticket_id == ticket.id,
        ClientTicketMessage.id != message.id,
        ClientTicketMessage.message_id.isnot(None),
    ).order_by(ClientTicketMessage.created_at.desc()).first()

    outbound = EmailMessage()
    generated_message_id = email_module.utils.make_msgid()
    outbound["Message-ID"] = generated_message_id
    outbound["From"] = f"{mailbox.from_name} <{mailbox.from_address}>" if mailbox.from_name else mailbox.from_address
    outbound["To"] = ticket.contact.email
    subject = ticket.subject
    if f"[{ticket.number}]" not in subject:
        subject = f"Re: [{ticket.number}] {subject}"
    outbound["Subject"] = subject
    # This is a human-authored agent reply, not an automated notification --
    # deliberately the inverse of what an autoresponder would set, so this
    # message is never itself mistaken for auto-generated mail downstream.
    outbound["Auto-Submitted"] = "no"
    if prior:
        outbound["In-Reply-To"] = prior.message_id
        outbound["References"] = build_references_header(prior.message_id, prior.in_reply_to or "")
    outbound.set_content(message.body)

    with smtplib.SMTP(mailbox.smtp_host, mailbox.smtp_port, timeout=10) as smtp:
        smtp.ehlo()
        if mailbox.smtp_use_tls:
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        if mailbox.smtp_username:
            smtp.login(mailbox.smtp_username, mailbox.smtp_password)
        smtp.send_message(outbound)
    message.message_id = generated_message_id


def process_client_escalation_policies(limit=100):
    """Client Management phase 7: an organization whose settings configure
    an escalation policy (settings["notification"] = {"escalation_hours",
    "escalation_group_id"}) gets its open tickets older than that threshold
    escalated once -- reassigned to the escalation team, an internal note
    posted, and the team manager notified. Idempotent via an "auto-escalated"
    tag (mirrors process_sla_breaches()'s claim-once periodic-scan shape,
    but ClientTicket has no dedicated "already escalated" boolean column, so
    the tag is the marker instead of inventing a new column for one flag)."""
    processed = 0
    for organization in ClientOrganization.query.filter(ClientOrganization.active.is_(True)).all():
        policy = (organization.settings or {}).get("notification", {})
        hours, group_id = policy.get("escalation_hours"), policy.get("escalation_group_id")
        if not hours or not group_id:
            continue
        try:
            hours, group_id = float(hours), int(group_id)
        except (TypeError, ValueError):
            continue
        group = db.session.get(SupportGroup, group_id)
        if not group or not group.active or group.tenant_id != organization.tenant_id:
            continue
        threshold = now() - timedelta(hours=hours)
        candidates = ClientTicket.query.filter(
            ClientTicket.organization_id == organization.id,
            ClientTicket.status.notin_(["Solved", "Closed"]),
            ClientTicket.created_at <= threshold,
            db.not_(ClientTicket.tags.ilike("%auto-escalated%")),
        ).limit(limit).all()
        for ticket in candidates:
            ticket.support_group_id = group.id
            existing_tags = {value.strip() for value in ticket.tags.split(",") if value.strip()}
            existing_tags.add("auto-escalated")
            ticket.tags = ", ".join(sorted(existing_tags))[:500]
            db.session.add(ClientTicketMessage(
                tenant_id=organization.tenant_id, client_ticket_id=ticket.id,
                author_id=ticket.created_by_id, event_type="escalation", visibility="internal",
                body=f"Escalated to {group.name}: open longer than {hours:g} hours ({organization.name}'s escalation policy).",
            ))
            if group.manager_id:
                create_notification(
                    group.manager_id, f"Escalated: {ticket.number}",
                    f"{ticket.subject} has been open past {organization.name}'s escalation threshold.",
                    tenant_id=organization.tenant_id, target_type="client_ticket", target_id=ticket.id,
                    event_type="client_ticket.escalated",
                    template_vars={
                        "ticket_number": ticket.number, "ticket_subject": ticket.subject,
                        "organization_name": organization.name, "hours": f"{hours:g}",
                    },
                )
            processed += 1
    db.session.commit()
    return processed


def _has_active_legal_hold(tenant_id, record_type, record_id):
    return RecordLegalHold.query.filter_by(
        tenant_id=tenant_id, record_type=record_type, record_id=record_id, released_at=None,
    ).first() is not None


def erase_client_contact(contact, reason=""):
    """GDPR Art. 17 (right to erasure) for a customer contact, mirroring
    user_erase() exactly: scrubs personal fields to an opaque placeholder
    (keeping the row so ClientTicket/ClientTicketMessage foreign keys keep
    resolving) rather than deleting it. Shared by the admin-triggered route
    and the automatic retention purge below; raises ValueError (caller's
    responsibility to handle) if the contact is under an active legal hold
    or already erased, so both callers get the same guard for free."""
    if contact.erased_at:
        raise ValueError("This contact's personal data has already been erased.")
    if _has_active_legal_hold(contact.tenant_id, "client_contact", contact.id):
        raise ValueError("This contact is under an active legal hold and cannot be erased.")
    placeholder = f"erased-contact-{contact.id}"
    contact.name = f"Erased contact #{contact.id}"
    contact.email = f"{placeholder}@erased.invalid"
    contact.phone = ""
    contact.job_title = ""
    contact.erased_at = now()
    audit("erase", placeholder, f"Client contact personal data erased (GDPR Art. 17){': ' + reason if reason else ''}")


def process_data_retention_purge(limit=200):
    """B-090: enforces each tenant's DataRetentionPolicy rows by erasing
    (via erase_client_contact -- same scrub-not-delete pattern as manual
    GDPR erasure) client contacts whose most recent activity is older than
    the configured retention window, skipping anything under a blanket
    policy-level or a per-record RecordLegalHold. Only client_contact is
    enforced automatically this pass -- client_ticket has a Confidential,
    not PII, classification (see DATA_CLASSIFICATION_REGISTRY) and its
    conversation history has independent business/audit value, so it is
    deliberately not auto-purged; a ClientMailbox record_type policy row
    would currently have no effect. Mirrors process_sla_breaches()'s
    periodic-scan shape: returns an int count, isolates per-tenant failure."""
    processed = 0
    for policy in DataRetentionPolicy.query.filter_by(
        record_type="client_contact", active=True, legal_hold=False,
    ).all():
        try:
            threshold = now() - timedelta(days=policy.retention_days)
            candidates = ClientContact.query.filter(
                ClientContact.tenant_id == policy.tenant_id,
                ClientContact.erased_at.is_(None),
                ClientContact.active.is_(False),
                ClientContact.updated_at <= threshold,
            ).limit(limit).all()
            purged = 0
            for contact in candidates:
                if _has_active_legal_hold(policy.tenant_id, "client_contact", contact.id):
                    continue
                try:
                    erase_client_contact(contact, reason="Automatic retention purge")
                    purged += 1
                except ValueError:
                    continue
            policy.last_run_at = now()
            policy.last_run_count = purged
            db.session.commit()
            processed += purged
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Data retention purge failed for tenant=%s record_type=client_contact", policy.tenant_id,
            )
    return processed


def process_sla_breaches(limit=50):
    """Claim newly breached SLAs once and create durable escalation notifications."""
    current = now()
    rows = TaskSLA.query.filter_by(stage="In Progress", breached=False).filter(
        TaskSLA.breach_at <= current
    ).order_by(TaskSLA.breach_at).with_for_update(skip_locked=True).limit(limit).all()
    processed = 0
    for task_sla in rows:
        task_sla.breached = True
        definition = task_sla.definition
        db.session.add(SLAEvent(
            task_sla_id=task_sla.id, event_type="Breached",
            details=f"Breached at {current.isoformat()}",
            tenant_id=definition.tenant_id,
        ))
        recipients = set()
        reference = f"{task_sla.target_type}:{task_sla.target_id}"
        if task_sla.target_type == "ticket":
            ticket = db.session.get(Ticket, task_sla.target_id)
            if ticket and ticket.tenant_id == definition.tenant_id:
                reference = ticket.number
                group = ticket_owning_group(ticket)
                if group and group.manager_id:
                    recipients.add(group.manager_id)
                if ticket.assignee_id:
                    recipients.add(ticket.assignee_id)
                log_history("ticket", ticket.id, "SLA breached", details=definition.name)
                context = ticket_workflow_context(ticket)
                context["sla_name"] = definition.name
                queue_workflow_event(
                    "ticket.sla_breached", "ticket", ticket.id, context,
                    tenant_id=ticket.tenant_id,
                )
        for user_id in recipients:
            create_notification(
                user_id, f"SLA breached: {reference}",
                f"{definition.name} breached for {reference}. Immediate attention is required.",
                tenant_id=definition.tenant_id,
                target_type=task_sla.target_type, target_id=task_sla.target_id,
                event_type="sla.breached",
                template_vars={"reference": reference, "sla_name": definition.name},
            )
        processed += 1
    db.session.commit()
    return processed


def deploy_workflow_package(actor_id, package=None):
    """Validate and publish the Git-backed package as immutable runtime versions."""
    package = package or load_workflow_package()
    digest = package_digest(package)
    deployed = 0
    for specification in package["workflows"]:
        subflows = package.get("subflows", {})
        validate_workflow(specification, subflows)
        deployed_specification = materialize_workflow(specification, subflows)
        definition = tenant_query(WorkflowDefinition).filter_by(
            workflow_key=specification["key"]
        ).first()
        if not definition:
            definition = WorkflowDefinition(
                workflow_key=specification["key"], name=specification["name"],
                event_type=specification["event"],
            )
            db.session.add(definition)
            db.session.flush()
        definition.name = specification["name"]
        definition.event_type = specification["event"]
        latest = WorkflowVersion.query.filter_by(
            definition_id=definition.id
        ).order_by(WorkflowVersion.version.desc()).first()
        encoded = canonical_json(deployed_specification)
        if latest and latest.package_hash == digest and latest.definition_json == encoded:
            definition.published_version_id = latest.id
            definition.active = True
            continue
        version = WorkflowVersion(
            definition_id=definition.id,
            version=(latest.version + 1 if latest else 1),
            state="Published", definition_json=encoded, package_hash=digest,
            created_by_id=actor_id, published_at=now(),
        )
        db.session.add(version)
        db.session.flush()
        if latest and latest.state == "Published":
            latest.state = "Superseded"
        definition.published_version_id = version.id
        definition.active = True
        deployed += 1
    return {"package_hash": digest, "published": deployed}


def queue_workflow_event(event_type, target_type, target_id, context, tenant_id=None):
    job = WorkflowJob(
        event_type=event_type, target_type=target_type, target_id=target_id,
        context_json=canonical_json(context), tenant_id=tenant_id or tenant_context_id(),
    )
    db.session.add(job)
    return job


def ticket_workflow_context(ticket, previous_state=None):
    return {
        "number": ticket.number, "kind": ticket.kind, "state": ticket.state,
        "previous_state": previous_state if previous_state is not None else ticket.state,
        "priority": ticket.priority, "impact": ticket.impact,
        "urgency": ticket.urgency, "category": ticket.category,
    }


def workflow_action_preview(action, context):
    if action["type"] == "wait":
        return {
            "type": "wait", "minutes": action["minutes"],
            "resume_at": None,
        }
    return {
        "type": action["type"],
        "recipient": (
            "requester" if action["type"] == "notify_requester"
            else "team_manager" if action["type"] == "notify_team_manager"
            else None
        ),
        "title": action.get("title", "").format_map(context),
        "body": action.get("body", "").format_map(context),
        "event": action.get("event"),
        "details": action.get("details", "").format_map(context),
    }


def simulate_workflows(event_type, context, tenant_id=None):
    tenant_id = tenant_id or tenant_context_id()
    matches = []
    definitions = WorkflowDefinition.query.filter_by(
        tenant_id=tenant_id, event_type=event_type, active=True
    ).all()
    for definition in definitions:
        version = definition.published_version
        if not version:
            continue
        specification = version.specification
        if workflow_matches(specification, event_type, context):
            matches.append({
                "workflow_key": definition.workflow_key,
                "version": version.version,
                "actions": [
                    workflow_action_preview(action, context)
                    for action in specification["actions"]
                ],
            })
    return matches


def execute_workflow_action(action, job, context):
    preview = workflow_action_preview(action, context)
    ticket = db.session.get(Ticket, job.target_id) if job.target_type == "ticket" else None
    if not ticket or ticket.tenant_id != job.tenant_id:
        raise RuntimeError("Workflow target is unavailable.")
    if action["type"] == "add_history":
        log_history(
            "ticket", ticket.id, preview["event"], details=preview["details"]
        )
    elif action["type"] == "notify_requester":
        create_notification(
            ticket.requester_id, preview["title"], preview["body"],
            tenant_id=job.tenant_id, target_type="ticket", target_id=ticket.id,
        )
    elif action["type"] == "notify_team_manager":
        group = ticket_owning_group(ticket)
        if not group or not group.manager_id:
            raise RuntimeError("Owning team manager is unavailable.")
        create_notification(
            group.manager_id, preview["title"], preview["body"],
            tenant_id=job.tenant_id, target_type="ticket", target_id=ticket.id,
        )
    return preview


def compensate_workflow_execution(execution, job):
    specification = execution.version.specification
    for step in sorted(execution.steps, key=lambda item: item.action_index, reverse=True):
        action = specification["actions"][step.action_index]
        compensation = action.get("compensate")
        if step.state != "Completed" or not compensation or step.compensation_state == "Completed":
            continue
        try:
            execute_workflow_action(compensation, job, job.context)
            step.compensation_state = "Completed"
        except Exception as error:
            step.compensation_state = "Failed"
            step.error = f"{step.error or ''}\nCompensation: {error}".strip()


def workflow_rate_limited(version, specification, tenant_id):
    cutoff = now() - timedelta(minutes=1)
    count = WorkflowExecution.query.filter(
        WorkflowExecution.version_id == version.id,
        WorkflowExecution.tenant_id == tenant_id,
        WorkflowExecution.started_at >= cutoff,
    ).count()
    return count >= specification["rate_limit_per_minute"]


def process_workflow_schedules(limit=50):
    """Atomically emit one event per due schedule and advance past the current time."""
    current = now()
    schedules = WorkflowSchedule.query.filter(
        WorkflowSchedule.active.is_(True),
        WorkflowSchedule.next_run_at <= current,
    ).order_by(WorkflowSchedule.next_run_at).with_for_update(
        skip_locked=True
    ).limit(limit).all()
    processed = 0
    for schedule in schedules:
        ticket = schedule.ticket
        if not ticket or ticket.tenant_id != schedule.tenant_id:
            schedule.active = False
            processed += 1
            continue
        scheduled_for = schedule.next_run_at
        context = ticket_workflow_context(ticket)
        context["schedule_key"] = schedule.schedule_key
        context["scheduled_for"] = scheduled_for.isoformat()
        queue_workflow_event(
            "ticket.scheduled", "ticket", ticket.id, context,
            tenant_id=schedule.tenant_id,
        )
        schedule.last_run_at = current
        next_run = scheduled_for
        comparison_now = current
        if next_run.tzinfo is None:
            comparison_now = current.replace(tzinfo=None)
        interval = timedelta(minutes=schedule.interval_minutes)
        while next_run <= comparison_now:
            next_run += interval
        schedule.next_run_at = next_run
        processed += 1
    db.session.commit()
    return processed


def capture_kpi_snapshots(tenant_id):
    """Computes today's headline ITSM metrics for one tenant and writes/
    updates a KpiSnapshot row per metric for today's date -- re-running on
    the same day updates rather than duplicates, so a manual re-trigger is
    safe. Mirrors the same 30-day-window metric definitions /analytics
    uses (see the analytics() route) but scoped directly by tenant_id
    rather than through visible_ticket_query(), since this runs outside a
    request with no current_user."""
    thirty_days_ago = now() - timedelta(days=30)
    snapshot_date = now().date()

    def upsert(metric_name, value):
        if value is None:
            return
        row = KpiSnapshot.query.filter_by(
            tenant_id=tenant_id, snapshot_date=snapshot_date, metric_name=metric_name,
        ).first()
        if row:
            row.metric_value = value
        else:
            db.session.add(KpiSnapshot(
                tenant_id=tenant_id, snapshot_date=snapshot_date,
                metric_name=metric_name, metric_value=value,
            ))

    terminal_states = ("Resolved", "Closed", "Cancelled")
    # Customer-facing compliance only counts real SLAs -- an OLA (internal
    # team-to-team) or UC (external supplier) breach is tracked and still
    # notifies, but folding it into the number reported to the business
    # overstates what the business itself was actually promised.
    resolved_slas = TaskSLA.query.join(
        Ticket, db.and_(TaskSLA.target_type == "ticket", TaskSLA.target_id == Ticket.id)
    ).join(SLADefinition, TaskSLA.definition_id == SLADefinition.id).filter(
        Ticket.tenant_id == tenant_id, Ticket.state.in_(terminal_states),
        Ticket.updated_at >= thirty_days_ago, SLADefinition.agreement_type == "SLA",
    ).all()
    if resolved_slas:
        upsert("sla_compliance_pct", round(
            100 * sum(1 for row in resolved_slas if not row.breached) / len(resolved_slas), 1
        ))

    change_ticket_ids = [
        row.id for row in Ticket.query.filter_by(tenant_id=tenant_id, kind="change")
        .with_entities(Ticket.id).all()
    ]
    pir_rows = ChangePostImplementationReview.query.filter(
        ChangePostImplementationReview.ticket_id.in_(change_ticket_ids),
        ChangePostImplementationReview.reviewed_at >= thirty_days_ago,
    ).all()
    if pir_rows:
        upsert("change_success_pct", round(
            100 * sum(1 for row in pir_rows if row.outcome == "Successful") / len(pir_rows), 1
        ))

    resolved_incident_ids = [
        row.id for row in Ticket.query.filter(
            Ticket.tenant_id == tenant_id, Ticket.kind == "incident",
            Ticket.state.in_(terminal_states), Ticket.updated_at >= thirty_days_ago,
        ).with_entities(Ticket.id).all()
    ]
    if resolved_incident_ids:
        reopened_ids = {
            row.target_id for row in TaskHistory.query.filter(
                TaskHistory.target_type == "ticket",
                TaskHistory.target_id.in_(resolved_incident_ids),
                TaskHistory.details.ilike("Reopened by%"),
            ).with_entities(TaskHistory.target_id).all()
        }
        upsert("fcr_pct", round(
            100 * (len(resolved_incident_ids) - len(reopened_ids)) / len(resolved_incident_ids), 1
        ))

    csat_ratings = [
        row.csat_rating for row in Ticket.query.filter(
            Ticket.tenant_id == tenant_id, Ticket.csat_rating.isnot(None),
            Ticket.csat_submitted_at >= thirty_days_ago,
        ).with_entities(Ticket.csat_rating).all()
    ]
    if csat_ratings:
        upsert("csat_avg", round(sum(csat_ratings) / len(csat_ratings), 2))


def process_performance_sample_schedule(interval_seconds=60):
    """Snapshots cumulative `RequestMetricTotal` totals into one
    `PerformanceSample` row roughly every `interval_seconds`, backing the
    System Health performance chart. Uses the same PlatformSetting
    last-run-timestamp pattern as the worker heartbeat rather than a
    per-tenant state row, since request metrics are process/infra-level,
    not tenant-scoped."""
    state = db.session.get(PlatformSetting, "PERFORMANCE_SAMPLE_LAST_RUN")
    current = now()
    if state and state.value:
        try:
            last_run = datetime.fromisoformat(state.value)
            if (current - align_tz(last_run, current)).total_seconds() < interval_seconds:
                return False
        except (TypeError, ValueError):
            pass
    totals = RequestMetricTotal.query.all()
    cumulative_requests = sum(row.request_count for row in totals)
    cumulative_errors = sum(row.request_count for row in totals if row.status[:1] in ("4", "5"))
    cumulative_duration_ms = sum(row.duration_sum_ms for row in totals)
    heartbeat = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT")
    worker_healthy = False
    if heartbeat and heartbeat.value:
        try:
            worker_healthy = (current - align_tz(datetime.fromisoformat(heartbeat.value), current)) < timedelta(seconds=30)
        except (TypeError, ValueError):
            pass
    db.session.add(PerformanceSample(
        sampled_at=current, cumulative_requests=cumulative_requests,
        cumulative_errors=cumulative_errors, cumulative_duration_ms=cumulative_duration_ms,
        worker_healthy=worker_healthy,
        deployment_mode=os.getenv("DEPLOYMENT_MODE", "unknown"),
    ))
    if not state:
        state = PlatformSetting(key="PERFORMANCE_SAMPLE_LAST_RUN", tenant_id=1, encrypted=False)
        db.session.add(state)
    state.value = current.isoformat()
    # Keep roughly a week of minute-resolution samples; older rows add
    # nothing the chart uses and would otherwise grow unbounded forever.
    cutoff = current - timedelta(days=7)
    PerformanceSample.query.filter(PerformanceSample.sampled_at < cutoff).delete()
    db.session.commit()
    return True


def process_kpi_snapshot_schedule(limit=50):
    """Captures one day's worth of KPI snapshots per active tenant, once
    every 24h -- same per-tenant due-interval and one-tenant-failure-
    isolation shape as process_ldap_sync_schedule below."""
    interval = timedelta(hours=24)
    current = now()
    processed = 0
    tenants = Tenant.query.filter_by(active=True).order_by(Tenant.id).limit(limit).all()
    for tenant in tenants:
        try:
            state = db.session.get(KpiSnapshotState, tenant.id)
            if state and state.last_run_at and current - state.last_run_at < interval:
                continue
            if not state:
                state = KpiSnapshotState(tenant_id=tenant.id)
                db.session.add(state)
            capture_kpi_snapshots(tenant.id)
            state.last_run_at = current
            db.session.commit()
            processed += 1
        except Exception as error:  # noqa: BLE001 - one tenant's failure must never block others
            db.session.rollback()
            current_app.logger.error(
                "KPI snapshot capture failed for tenant %s: %s", tenant.id, type(error).__name__
            )
    return processed


def process_rt_import_jobs(limit=1):
    """Runs queued RT import jobs (see RTImportJob) in the background
    worker, outside any web-request timeout. Processes at most `limit` per
    call -- one at a time by default, since these are slow, infrequent
    admin-triggered runs, not something that needs parallelism, and a
    single stuck RT instance shouldn't block the rest of the worker loop
    from noticing it should give up on it."""
    from serviceops_core.rt_import import RTImportError, import_from_rt

    jobs = RTImportJob.query.filter_by(status="Pending").order_by(RTImportJob.id).limit(limit).all()
    processed = 0
    for job in jobs:
        job.status = "Running"
        job.started_at = now()
        db.session.commit()
        try:
            result = import_from_rt(
                job.tenant_id, job.actor_user_id, dry_run=job.dry_run,
                query=job.search_query, limit=job.record_limit,
            )
        except RTImportError as error:
            job.status = "Failed"
            job.error = str(error)
        except Exception as error:  # noqa: BLE001 - a bad RT response must not crash the worker loop
            db.session.rollback()
            job = db.session.get(RTImportJob, job.id)
            job.status = "Failed"
            job.error = f"{type(error).__name__}: {error}"
        else:
            job.status = "Completed"
            job.result_json = json.dumps(result)
        job.finished_at = now()
        db.session.commit()
        processed += 1
    return processed


def process_ldap_sync_schedule(limit=50):
    """Run the LDAP directory sync (serviceops_core.ldap_sync.sync_directory)
    for each active, LDAP-enabled tenant whose scheduled interval has
    elapsed. Tenant iteration is explicit and tenant-scoped: there is no
    global/default sync, matching the fail-closed tenant policy. One
    tenant's failure is caught and logged (no secrets) and never blocks or
    crashes the pass for other tenants."""
    if not setting_bool("LDAP_ENABLED") or not setting_bool("LDAP_SYNC_ENABLED"):
        return 0
    interval = timedelta(minutes=max(setting_int("LDAP_SYNC_INTERVAL_MINUTES", 60), 1))
    current = now()
    processed = 0
    tenants = Tenant.query.filter_by(active=True).order_by(Tenant.id).limit(limit).all()
    for tenant in tenants:
        try:
            state = db.session.get(LdapSyncState, tenant.id)
            if state and state.last_run_at:
                last_run = state.last_run_at
                comparison_now = current
                if last_run.tzinfo is None:
                    comparison_now = current.replace(tzinfo=None)
                if comparison_now - last_run < interval:
                    continue
            if not state:
                state = LdapSyncState(tenant_id=tenant.id)
                db.session.add(state)
            from serviceops_core.ldap_sync import sync_directory, DirectorySyncError
            try:
                summary = sync_directory(tenant.id, dry_run=False)
                state.last_run_at = current
                state.last_status = "ok" if not summary.get("errors") else "partial"
                state.last_error = None
            except DirectorySyncError as error:
                state.last_run_at = current
                state.last_status = "skipped"
                state.last_error = str(error)
            db.session.commit()
            processed += 1
        except Exception as error:  # noqa: BLE001 - one tenant's failure must never block others
            db.session.rollback()
            current_app.logger.error(
                "LDAP scheduled sync failed for tenant %s: %s", tenant.id, type(error).__name__
            )
            try:
                state = db.session.get(LdapSyncState, tenant.id) or LdapSyncState(tenant_id=tenant.id)
                state.last_run_at = current
                state.last_status = "error"
                state.last_error = type(error).__name__
                db.session.add(state)
                db.session.commit()
            except Exception:
                db.session.rollback()
            processed += 1
    return processed


def process_discovery_schedule(limit=50):
    """Runs agentless SNMP discovery (serviceops_core.network_discovery) for
    each active DiscoveryTarget with scheduling enabled whose interval has
    elapsed, across all tenants -- scheduling is per-row (each target has its
    own interval and last_run_at), unlike LDAP sync's per-tenant scheduling,
    since discovery targets are individually administrator-configured rather
    than a single tenant-wide toggle. One target's failure is caught and
    logged (no secrets -- never logs the decrypted community string) and
    never blocks or crashes the pass for other targets."""
    from serviceops_core.network_discovery import discover_subnet, probe_host

    current = now()
    processed = 0
    targets = DiscoveryTarget.query.filter_by(active=True, schedule_enabled=True).order_by(
        DiscoveryTarget.id
    ).limit(limit).all()
    for target in targets:
        interval = timedelta(minutes=max(target.schedule_interval_minutes, 5))
        if target.last_run_at:
            last_run = target.last_run_at
            comparison_now = current.replace(tzinfo=None) if last_run.tzinfo is None else current
            if comparison_now - last_run < interval:
                continue
        try:
            if target.target_type == "host":
                facts = probe_host(
                    target.address, target.community, port=target.snmp_port, version=target.snmp_version,
                )
                facts_list = [facts] if facts else []
            else:
                facts_list = discover_subnet(
                    target.address, target.community, port=target.snmp_port, version=target.snmp_version,
                )
            # Scheduled runs stage candidates for review too -- discovery
            # never auto-creates a CI on its own, scheduled or manual.
            DiscoveryCandidate.query.filter_by(target_id=target.id).delete()
            snmp_hosts = bare_hosts = 0
            for facts in facts_list:
                source = facts.get("discovery_source", "SNMP Discovery")
                if source == "SNMP Discovery":
                    snmp_hosts += 1
                else:
                    bare_hosts += 1
                db.session.add(DiscoveryCandidate(
                    target_id=target.id, host=facts["host"],
                    name=facts.get("sys_name") or facts["host"],
                    ci_class=facts.get("ci_class", "Device"),
                    vendor=facts.get("vendor") or None,
                    discovery_source=source, facts=facts,
                    tenant_id=target.tenant_id,
                ))
            target.last_run_status = "ok"
            target.last_run_summary = (
                f"{len(facts_list)} host(s) responded ({snmp_hosts} via SNMP, {bare_hosts} liveness-only) "
                f"-- awaiting review before anything is added to the CMDB."
            )
        except Exception as error:  # noqa: BLE001 - one target's failure must never block others
            db.session.rollback()
            target = db.session.get(DiscoveryTarget, target.id)
            target.last_run_status = "error"
            target.last_run_summary = type(error).__name__
            current_app.logger.error(
                "Scheduled discovery failed for target %s: %s", target.id, type(error).__name__
            )
        target.last_run_at = current
        db.session.commit()
        processed += 1
    return processed


def process_workflow_jobs(limit=50):
    jobs = WorkflowJob.query.filter(
        WorkflowJob.state.in_(["Pending", "Retry", "Waiting", "Rate Limited"]),
        WorkflowJob.available_at <= now(),
    ).order_by(WorkflowJob.id).with_for_update(skip_locked=True).limit(limit).all()
    processed = 0
    for job in jobs:
        try:
            job.state = "Running"
            matches = simulate_workflows(job.event_type, job.context, job.tenant_id)
            outputs = []
            for match in matches:
                definition = WorkflowDefinition.query.filter_by(
                    tenant_id=job.tenant_id, workflow_key=match["workflow_key"]
                ).one()
                version = definition.published_version
                existing = WorkflowExecution.query.filter_by(
                    job_id=job.id, version_id=version.id
                ).first()
                if existing and existing.state == "Completed":
                    continue
                if not existing and workflow_rate_limited(
                    version, version.specification, job.tenant_id
                ):
                    job.state = "Rate Limited"
                    job.available_at = now() + timedelta(minutes=1)
                    db.session.commit()
                    break
                execution = existing or WorkflowExecution(
                    job_id=job.id, version_id=version.id,
                    correlation_id=job.event_id, state="Running",
                    input_json=job.context_json, tenant_id=job.tenant_id,
                )
                execution.state = "Running"
                execution.resume_at = None
                db.session.add(execution)
                db.session.flush()
                action_outputs = [
                    json.loads(step.output_json) for step in execution.steps
                    if step.state == "Completed"
                ]
                actions = version.specification["actions"]
                waiting = False
                for index in range(execution.next_action_index, len(actions)):
                    action = actions[index]
                    step = WorkflowStepExecution.query.filter_by(
                        execution_id=execution.id, action_index=index
                    ).first()
                    if step and step.state == "Completed":
                        execution.next_action_index = index + 1
                        continue
                    step = step or WorkflowStepExecution(
                        execution_id=execution.id, action_index=index,
                        action_type=action["type"], state="Running",
                        input_json=canonical_json(action),
                        tenant_id=job.tenant_id,
                    )
                    db.session.add(step)
                    db.session.flush()
                    if action["type"] == "wait":
                        resume_at = now() + timedelta(minutes=action["minutes"])
                        output = {
                            "type": "wait", "minutes": action["minutes"],
                            "resume_at": resume_at.isoformat(),
                        }
                        step.output_json = canonical_json(output)
                        step.state = "Completed"
                        step.completed_at = now()
                        execution.next_action_index = index + 1
                        execution.state = "Waiting"
                        execution.resume_at = resume_at
                        job.state = "Waiting"
                        job.available_at = resume_at
                        action_outputs.append(output)
                        waiting = True
                        break
                    output = execute_workflow_action(action, job, job.context)
                    step.output_json = canonical_json(output)
                    step.state = "Completed"
                    step.completed_at = now()
                    execution.next_action_index = index + 1
                    action_outputs.append(output)
                execution.output_json = canonical_json(action_outputs)
                if waiting:
                    db.session.commit()
                    break
                execution.state = "Completed"
                execution.resume_at = None
                execution.completed_at = now()
                outputs.extend(action_outputs)
            if job.state in ("Waiting", "Rate Limited"):
                processed += 1
                continue
            job.state = "Completed"
            job.completed_at = now()
            job.last_error = None
            db.session.commit()
        except Exception as error:
            db.session.rollback()
            claimed = db.session.get(WorkflowJob, job.id)
            execution = WorkflowExecution.query.filter_by(
                job_id=claimed.id
            ).order_by(WorkflowExecution.id.desc()).first()
            if execution:
                execution.state = "Retry"
                execution.error = str(error)[:2000]
            claimed.attempts += 1
            claimed.last_error = str(error)[:2000]
            if claimed.attempts >= 5:
                claimed.state = "Dead"
                if execution:
                    execution.state = "Failed"
                    execution.completed_at = now()
                    compensate_workflow_execution(execution, claimed)
            else:
                claimed.state = "Retry"
                claimed.available_at = now() + timedelta(
                    seconds=min(300, 2 ** claimed.attempts)
                )
            db.session.commit()
        processed += 1
    return processed


def catalog_fulfillment_group(item):
    route = item.fulfillment_route
    if route and route.active and route.support_group and route.support_group.active:
        return route.support_group
    return SupportGroup.query.filter_by(name="Service Desk", active=True, tenant_id=item.tenant_id).first()


def user_support_group_ids(user):
    if not user.is_authenticated or not user.active:
        return set()
    group_ids = {
        membership.group_id
        for membership in GroupMember.query.filter_by(user_id=user.id).all()
        if membership.group.active and membership.group.tenant_id == user.tenant_id
    }
    group_ids.update(
        group.id for group in SupportGroup.query.filter_by(
            manager_id=user.id, active=True, tenant_id=user.tenant_id
        ).all()
    )
    return group_ids


def client_sysops_group(tenant_id):
    return SupportGroup.query.filter(
        SupportGroup.tenant_id == tenant_id,
        func.lower(SupportGroup.name) == "sysops",
        SupportGroup.active.is_(True),
    ).first()


def user_can_access_client_management(user):
    """Client support is isolated to SysOps and active administrators."""
    if not user.is_authenticated or not user.active:
        return False
    if role_at_least(user.effective_role, "admin"):
        return True
    group = client_sysops_group(user.tenant_id)
    return bool(group and (
        group.manager_id == user.id
        or GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first()
    ))


def require_client_management(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not user_can_access_client_management(current_user):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def visible_client_organization_query(user):
    """Client Management access was previously all-or-nothing: any SysOps
    member/admin saw every organization in the tenant. Organizations stay
    that way (restricted_visibility defaults False, zero behavior change)
    unless an admin explicitly opts one into restricted visibility, at
    which point only admins and users/groups with an explicit
    ClientOrganizationAccess grant can see it."""
    query = tenant_query(ClientOrganization)
    if role_at_least(user.effective_role, "admin"):
        return query
    group_ids = user_support_group_ids(user)
    granted_org_ids = {
        row.organization_id for row in ClientOrganizationAccess.query.filter(
            ClientOrganizationAccess.tenant_id == user.tenant_id,
            db.or_(
                ClientOrganizationAccess.user_id == user.id,
                ClientOrganizationAccess.group_id.in_(group_ids),
            ),
        ).all()
    }
    return query.filter(db.or_(
        ClientOrganization.restricted_visibility.is_(False),
        ClientOrganization.id.in_(granted_org_ids),
    ))


def visible_client_ticket_query(user):
    query = tenant_query(ClientTicket)
    if role_at_least(user.effective_role, "admin"):
        return query
    visible_org_ids = visible_client_organization_query(user).with_entities(ClientOrganization.id)
    return query.filter(ClientTicket.organization_id.in_(visible_org_ids))


def visible_client_contact_query(user):
    query = tenant_query(ClientContact)
    if role_at_least(user.effective_role, "admin"):
        return query
    visible_org_ids = visible_client_organization_query(user).with_entities(ClientOrganization.id)
    return query.filter(ClientContact.organization_id.in_(visible_org_ids))


CLIENT_CUSTOM_FIELD_ENTITY_TYPES = ("client_ticket", "organization", "contact")
CLIENT_CUSTOM_FIELD_TYPES = ("text", "number", "date", "select")


def client_custom_fields_for(entity_type, organization=None):
    """Active tenant-wide field definitions for `entity_type`, each resolved
    against `organization`'s per-org required/visible overrides (stored in
    ClientOrganization.settings["custom_field_overrides"][key] -- field
    EXISTENCE is tenant-wide, matching Zendesk's own custom-field model;
    only required/visible are ever overridden per organization). A field
    with no override uses its tenant-wide `required` default and is always
    visible. Returns a list of {"definition", "required", "options"} dicts,
    already filtered to only the currently-visible fields."""
    definitions = ClientCustomFieldDefinition.query.filter_by(
        tenant_id=current_user.tenant_id, entity_type=entity_type, active=True,
    ).order_by(ClientCustomFieldDefinition.position, ClientCustomFieldDefinition.label).all()
    overrides = ((organization.settings or {}).get("custom_field_overrides", {}) if organization else {})
    resolved = []
    for definition in definitions:
        override = overrides.get(definition.key, {})
        if not override.get("visible", True):
            continue
        try:
            options = json.loads(definition.options_json or "[]")
        except (TypeError, ValueError):
            options = []
        resolved.append({
            "definition": definition,
            "required": override.get("required", definition.required),
            "options": options,
        })
    return resolved


def parse_client_custom_field_values(fields, form):
    """Reads `custom__<key>` form inputs for the given resolved `fields`
    (client_custom_fields_for()'s return value), enforcing required-ness.
    Returns (values, error) -- error is a user-facing string naming the
    first missing required field, or None."""
    values = {}
    for field in fields:
        key = field["definition"].key
        value = form.get(f"custom__{key}", "").strip()
        if field["required"] and not value:
            return {}, f"{field['definition'].label} is required."
        if value:
            values[key] = value
    return values, None


def evaluate_client_triggers(event, ticket, agents):
    """Evaluates active ClientTrigger rows for `event` (in position order)
    against `ticket`'s current field values, applying the first-matching
    action of each. Mutates `ticket` in place; caller is responsible for
    db.session.commit(). Returns the list of trigger names that fired, for
    the caller to surface (or not) to the user -- always logged internally
    on the ticket so "why did this change" is never a mystery."""
    context = {
        "status": ticket.status, "priority": ticket.priority, "ticket_type": ticket.ticket_type,
        "channel": ticket.channel, "tags": ticket.tags, "subject": ticket.subject,
    }
    triggers = tenant_query(ClientTrigger).filter_by(event=event, active=True).order_by(
        ClientTrigger.position, ClientTrigger.id
    ).all()
    agent_ids = {agent.id for agent in agents}
    fired = []
    for trigger in triggers:
        if not condition_matches(trigger.condition_field, trigger.condition_op, trigger.condition_value, context):
            continue
        if trigger.action_type == "set_status" and trigger.action_value in CLIENT_TICKET_STATUSES:
            ticket.status = trigger.action_value
            context["status"] = trigger.action_value
        elif trigger.action_type == "set_priority" and trigger.action_value in CLIENT_TICKET_PRIORITIES:
            ticket.priority = trigger.action_value
            context["priority"] = trigger.action_value
        elif trigger.action_type == "add_tag":
            existing_tags = {value.strip() for value in ticket.tags.split(",") if value.strip()}
            existing_tags.add(trigger.action_value.strip())
            ticket.tags = ", ".join(sorted(existing_tags))[:500]
            context["tags"] = ticket.tags
        elif trigger.action_type == "assign_to_group":
            group_id = int(trigger.action_value) if trigger.action_value.isdigit() else None
            if group_id and tenant_query(SupportGroup).filter_by(id=group_id, active=True).first():
                ticket.support_group_id = group_id
        elif trigger.action_type == "assign_to_user":
            user_id = int(trigger.action_value) if trigger.action_value.isdigit() else None
            if user_id in agent_ids:
                ticket.assignee_id = user_id
        elif trigger.action_type == "notify_assignee" and ticket.assignee_id:
            create_notification(
                ticket.assignee_id, f"Automation: {trigger.name}", trigger.action_value,
                tenant_id=ticket.tenant_id, target_type="client_ticket", target_id=ticket.id,
            )
        elif trigger.action_type == "notify_org_contact":
            db.session.add(ClientTicketMessage(
                tenant_id=ticket.tenant_id, client_ticket_id=ticket.id,
                author_id=ticket.created_by_id, body=trigger.action_value, visibility="public",
            ))
        fired.append(trigger.name)
    if fired:
        db.session.add(ClientTicketMessage(
            tenant_id=ticket.tenant_id, client_ticket_id=ticket.id, author_id=ticket.created_by_id,
            body=f"Automation triggered: {', '.join(fired)}.", visibility="internal", event_type="automation",
        ))
    return fired


def visible_catalog_request_query(user):
    query = CatalogRequest.query
    if not user.is_authenticated or not user.active:
        return query.filter(CatalogRequest.id == -1)
    query = query.filter(CatalogRequest.tenant_id == user.tenant_id)
    if user.role == "admin":
        return query
    # Unlike tickets/enterprise records, catalog fulfillment is deliberately
    # routing-scoped: a request routed to Windows must not be visible to Unix
    # agents just because both are "IT Fulfillment" groups (see
    # test_catalog_request_visibility_is_limited_to_participants_and_fulfillment_team
    # and test_unrelated_team_cannot_view_or_mutate_catalog_request), so there's
    # no "any fulfillment member sees everything" shortcut here on purpose.
    request_ids = {
        row[0] for row in db.session.query(CatalogRequest.id).filter(db.or_(
            CatalogRequest.requested_by_id == user.id,
            CatalogRequest.requested_for_id == user.id,
        )).all()
    }
    group_ids = user_support_group_ids(user)
    if group_ids:
        routed_item_ids = {
            row[0] for row in db.session.query(CatalogItemRouting.catalog_item_id).filter(
                CatalogItemRouting.active.is_(True),
                CatalogItemRouting.support_group_id.in_(group_ids),
            ).all()
        }
        if routed_item_ids:
            request_ids.update(
                row[0] for row in db.session.query(RequestedItem.request_id).filter(
                    RequestedItem.catalog_item_id.in_(routed_item_ids)
                ).all()
            )
        request_ids.update(
            row[0] for row in db.session.query(RequestedItem.request_id).join(
                CatalogTask, CatalogTask.requested_item_id == RequestedItem.id
            ).filter(CatalogTask.assignment_group_id.in_(group_ids)).all()
        )
    approved_ritm_ids = {
        row[0] for row in db.session.query(ApprovalChain.target_id).join(
            ApprovalGate, ApprovalGate.chain_id == ApprovalChain.id
        ).join(
            ApprovalVote, ApprovalVote.gate_id == ApprovalGate.id
        ).filter(
            ApprovalChain.target_type == "ritm",
            ApprovalVote.approver_id == user.id,
            ApprovalVote.state.in_(["Requested", "Approved", "Rejected"]),
        ).all()
    }
    if approved_ritm_ids:
        request_ids.update(
            row[0] for row in db.session.query(RequestedItem.request_id).filter(
                RequestedItem.id.in_(approved_ritm_ids)
            ).all()
        )
    if not request_ids:
        return query.filter(CatalogRequest.id == -1)
    return query.filter(CatalogRequest.id.in_(request_ids))


def user_can_view_catalog_request(user, catalog_request):
    return visible_catalog_request_query(user).filter(
        CatalogRequest.id == catalog_request.id
    ).first() is not None


def user_can_add_request_item(user, catalog_request):
    return (
        user.is_authenticated and user.active
        and (
            user.role == "admin"
            or catalog_request.requested_by_id == user.id
            or catalog_request.requested_for_id == user.id
        )
    )


def user_can_manage_ritm(user, ritm):
    if not user.is_authenticated or not user.active:
        return False
    if ritm.tenant_id != user.tenant_id:
        return False
    if user.role == "admin":
        return True
    group_ids = user_support_group_ids(user)
    route_group = catalog_fulfillment_group(ritm.item)
    return (
        bool(route_group and route_group.id in group_ids)
        or any(task.assignment_group_id in group_ids for task in ritm.tasks)
    )


ENTERPRISE_DOMAINS_RESTRICTED_TO_OWNING_TEAM = {"hr", "security", "risk", "customer"}


def visible_enterprise_record_query(user):
    query = EnterpriseRecord.query
    if not user.is_authenticated or not user.active:
        return query.filter(EnterpriseRecord.id == -1)
    query = query.filter(EnterpriseRecord.tenant_id == user.tenant_id)
    if user.role == "admin":
        return query
    group_ids = user_support_group_ids(user)
    record_ids = set()
    # Mirrors visible_ticket_query(): a member of any active IT Fulfillment
    # group is support staff and sees all IT-operational records, the same
    # as they see all tickets -- previously this shortcut only existed for
    # tickets, so an imported/created event/problem/release record owned by
    # a member's own team was invisible to them unless they happened to be
    # the requester/assignee or had a task on it.
    #
    # This must NOT extend to HR/Security/Risk/Customer domains: those carry
    # sensitive content (benefits cases, security incidents, compliance
    # findings) that has nothing to do with general IT fulfillment, and a
    # blanket "any Unix/Windows/etc. agent sees everything" shortcut would
    # leak that data tenant-wide. Those domains only ever fall through to the
    # strict requester/assignee/approver/actual-owning-group checks below.
    if group_ids and SupportGroup.query.filter(
        SupportGroup.id.in_(group_ids),
        SupportGroup.group_type == "IT Fulfillment",
        SupportGroup.active.is_(True),
    ).first():
        record_ids.update(
            row[0] for row in db.session.query(EnterpriseRecord.id).filter(
                EnterpriseRecord.tenant_id == user.tenant_id,
                EnterpriseRecord.domain.notin_(ENTERPRISE_DOMAINS_RESTRICTED_TO_OWNING_TEAM),
            ).all()
        )
    record_ids.update(
        row[0] for row in db.session.query(EnterpriseRecord.id).filter(
            EnterpriseRecord.tenant_id == user.tenant_id,
            db.or_(
                EnterpriseRecord.requester_id == user.id,
                EnterpriseRecord.assignee_id == user.id,
            ),
        ).all()
    )
    record_ids.update(
        row[0] for row in db.session.query(Approval.enterprise_record_id).join(
            EnterpriseRecord, EnterpriseRecord.id == Approval.enterprise_record_id
        ).filter(
            Approval.approver_id == user.id, EnterpriseRecord.tenant_id == user.tenant_id,
        ).all()
    )
    if group_ids:
        record_ids.update(
            row[0] for row in db.session.query(EnterpriseRecord.id).filter(
                EnterpriseRecord.tenant_id == user.tenant_id,
                EnterpriseRecord.support_group_id.in_(group_ids),
            ).all()
        )
        record_ids.update(
            row[0] for row in db.session.query(OperationalTask.parent_id).join(
                EnterpriseRecord, EnterpriseRecord.id == OperationalTask.parent_id
            ).filter(
                OperationalTask.parent_type == "enterprise",
                OperationalTask.assignment_group_id.in_(group_ids),
                EnterpriseRecord.tenant_id == user.tenant_id,
            ).all()
        )
    return (
        query.filter(EnterpriseRecord.id.in_(record_ids))
        if record_ids else query.filter(EnterpriseRecord.id == -1)
    )


def user_can_view_enterprise_record(user, record):
    return visible_enterprise_record_query(user).filter(
        EnterpriseRecord.id == record.id
    ).first() is not None


def user_can_manage_enterprise_record(user, record):
    if not user.is_authenticated or not user.active:
        return False
    if record.tenant_id != user.tenant_id:
        return False
    if user.role == "admin":
        return True
    if user.role not in ("agent", "manager"):
        return False
    # Deliberately NOT granting manage rights just because requester_id ==
    # user.id: tickets never let the requester self-manage (user_can_manage_ticket
    # only checks the owning group), and an EnterpriseRecord shouldn't either --
    # otherwise an agent who happens to file their own HR/security/risk case
    # could set its own state/priority/risk/assignee, bypassing whichever team
    # is actually supposed to review it. Being the assignee is still sufficient,
    # since an assignment is itself an act of authority by someone who could
    # already manage the record.
    if record.assignee_id == user.id:
        return True
    # Mirrors user_can_manage_ticket(): the record's own owning team (not
    # "any IT Fulfillment member," which is deliberately broader and reserved
    # for *viewing*) can manage it -- previously only requester/assignee/an
    # explicit OperationalTask assignment group counted, so the team a record
    # was actually assigned to (support_group_id) couldn't act on it even
    # after they were able to see it.
    if record.support_group_id:
        group = db.session.get(SupportGroup, record.support_group_id)
        if group and (
            group.manager_id == user.id
            or GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first()
        ):
            return True
    group_ids = user_support_group_ids(user)
    return any(
        task.assignment_group_id in group_ids
        for task in OperationalTask.query.filter_by(
            parent_type="enterprise", parent_id=record.id
        ).all()
    )


def create_catalog_task(ritm):
    if ritm.tasks:
        return ritm.tasks[0]
    group = catalog_fulfillment_group(ritm.item)
    if not group:
        abort(409, description=(
            f"{ritm.item.name} has no active fulfillment route and no active Service Desk fallback."
        ))
    def build():
        task = CatalogTask(number=sequence_number(CatalogTask, "SCTASK"), requested_item_id=ritm.id,
                           title=f"Fulfill {ritm.item.name}", assignment_group_id=group.id,
                           due_at=ritm.due_at, tenant_id=ritm.tenant_id)
        db.session.add(task)
        return task
    task = create_with_retry_on_number_collision(build)
    log_history(
        "ritm", ritm.id, "Catalog task created",
        details=f"{task.number}: {task.title} → {group.name}",
    )
    return task


_SUPPORT_GROUP_SUFFIX_RE = re.compile(r"\bteams?\b")
_SUPPORT_GROUP_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


def support_group_dedup_key(name):
    """Normalizes a team name for duplicate detection: case, whitespace,
    punctuation, and a trailing "team"/"teams" word are all ignored, so
    "CoreApps", "Core apps", and "CoreApps team" collapse to the same key.
    This is deliberately narrow (spelling/formatting variants only) -- it
    never treats genuinely different words (e.g. "DBA" vs "Database") as
    the same team; that distinction is what SupportGroupAlias is for."""
    text = _SUPPORT_GROUP_SUFFIX_RE.sub("", (name or "").casefold())
    return _SUPPORT_GROUP_NON_ALNUM_RE.sub("", text)


def resolve_support_group_by_name(name, tenant_id):
    """Case-insensitive lookup of a SupportGroup by its name, a configured
    alias (SupportGroupAlias, e.g. "DBA" -> "Database"), or a
    spelling/formatting variant (e.g. "Core apps" -> "CoreApps"). Used
    wherever a team is looked up from free text (CSV import's Owner column,
    etc.) instead of a support_group_id dropdown, so nicknames and format
    variants don't silently spawn duplicate groups."""
    if not name:
        return None
    group = SupportGroup.query.filter(
        SupportGroup.tenant_id == tenant_id,
        func.lower(SupportGroup.name) == name.casefold(),
    ).first()
    if group:
        return group
    alias = SupportGroupAlias.query.filter(
        SupportGroupAlias.tenant_id == tenant_id,
        func.lower(SupportGroupAlias.alias) == name.casefold(),
    ).first()
    if alias:
        return alias.group
    key = support_group_dedup_key(name)
    if not key:
        return None
    for candidate in SupportGroup.query.filter_by(tenant_id=tenant_id).all():
        if support_group_dedup_key(candidate.name) == key:
            return candidate
    return None


# Every model that references a SupportGroup by foreign key. Consulted by
# merge_support_group_into so merging a duplicate team (e.g. a leftover
# "DBA" group that predates the "DBA" -> "Database" alias) reassigns every
# record that pointed at it, instead of leaving orphaned references behind.
SUPPORT_GROUP_FK_MODELS = (
    (MonitoringSource, "assignment_group_id"),
    (CatalogItemRouting, "support_group_id"),
    (ConfigurationItem, "support_group_id"),
    (DirectoryGroupMapping, "support_group_id"),
    (DirectoryManagedMembership, "group_id"),
    (ServiceOffering, "support_group_id"),
    (CatalogTask, "assignment_group_id"),
    (ChangeOwnership, "group_id"),
    (TicketAssignmentGroup, "group_id"),
    (OperationalTask, "assignment_group_id"),
    (ClientTicket, "support_group_id"),
)


def merge_support_group_into(source, target):
    """Reassigns every reference to `source` support group over to `target`
    (CIs, change/ticket ownership, catalog routing, AD mappings, monitoring
    sources, ...), merges membership without duplicating rows, and deletes
    `source`. Used to fix a team that got duplicated under two names (e.g.
    a "DBA" group created before "DBA" was registered as an alias of
    "Database") -- adding the alias alone doesn't move records that already
    point at the duplicate. Caller commits."""
    if source.id == target.id:
        return 0
    moved = 0
    for model, field in SUPPORT_GROUP_FK_MODELS:
        column = getattr(model, field)
        moved += model.query.filter(column == source.id).update(
            {field: target.id}, synchronize_session=False
        )
    for membership in GroupMember.query.filter_by(group_id=source.id).all():
        exists = GroupMember.query.filter_by(
            group_id=target.id, user_id=membership.user_id, role=membership.role
        ).first()
        if exists:
            db.session.delete(membership)
        else:
            membership.group_id = target.id
            moved += 1
    SupportGroupAlias.query.filter_by(group_id=source.id).update(
        {"group_id": target.id}, synchronize_session=False
    )
    if not target.manager_id and source.manager_id:
        target.manager_id = source.manager_id
    db.session.flush()
    db.session.delete(source)
    return moved


def find_and_merge_duplicate_groups(tenant_id):
    """Clusters every SupportGroup in a tenant by support_group_dedup_key
    and merges each cluster (e.g. "SSD", "SSD Team") into one canonical
    group, so dropdowns never show spelling/formatting duplicates of the
    same team. The canonical pick is whichever cluster member already has
    a manager (else the oldest / lowest id, as the likely original).
    Returns the number of duplicate groups merged away."""
    clusters = {}
    for group in SupportGroup.query.filter_by(tenant_id=tenant_id).order_by(SupportGroup.id).all():
        clusters.setdefault(support_group_dedup_key(group.name), []).append(group)
    merged = 0
    for members in clusters.values():
        if len(members) < 2:
            continue
        canonical = sorted(members, key=lambda g: (g.manager_id is None, g.id))[0]
        for duplicate in members:
            if duplicate.id != canonical.id:
                merge_support_group_into(duplicate, canonical)
                merged += 1
    return merged


def seed_itil(admin):
    # SupportGroup.name currently carries a database-wide unique constraint
    # (not yet scoped to tenant_id), so a second tenant seeding "Service Desk"
    # etc. would collide at the DB level. Filtering by tenant_id here at least
    # makes seeding correctly detect "this tenant doesn't have one yet" instead
    # of silently reusing another tenant's group id -- the collision (if any)
    # then surfaces as a clear IntegrityError rather than cross-tenant reuse.
    # A composite (tenant_id, name) unique constraint is the real fix and
    # needs its own migration.
    if not SupportGroup.query.filter_by(name="Service Desk", tenant_id=admin.tenant_id).first():
        service_desk = SupportGroup(name="Service Desk", group_type="Fulfillment", tenant_id=admin.tenant_id)
        security = SupportGroup(name="Security Operations", group_type="Fulfillment", tenant_id=admin.tenant_id)
        db.session.add_all([service_desk, security])
    if not SupportGroup.query.filter(
        SupportGroup.tenant_id == admin.tenant_id,
        func.lower(SupportGroup.name) == "sysops",
    ).first():
        db.session.add(SupportGroup(
            name="SysOps", group_type="Client Support", tenant_id=admin.tenant_id,
        ))
    team_names = ["CoreApps", "Database", "Network", "Windows", "Unix", "SSD"]
    for team_name in team_names:
        group = SupportGroup.query.filter_by(name=team_name, tenant_id=admin.tenant_id).first()
        if not group:
            group = SupportGroup(name=team_name, group_type="IT Fulfillment", tenant_id=admin.tenant_id)
            db.session.add(group)
        else:
            group.group_type = "IT Fulfillment"
    ccb = SupportGroup.query.filter_by(name="Change Control Board", tenant_id=admin.tenant_id).first()
    if not ccb:
        ccb = SupportGroup(name="Change Control Board", group_type="CCB Approval", tenant_id=admin.tenant_id)
        db.session.add(ccb)
    executive_office = SupportGroup.query.filter_by(name="Executive Office", tenant_id=admin.tenant_id).first()
    if not executive_office:
        executive_office = SupportGroup(
            name="Executive Office", group_type="Executive", tenant_id=admin.tenant_id
        )
        db.session.add(executive_office)
    db.session.flush()
    database_group = SupportGroup.query.filter_by(name="Database", tenant_id=admin.tenant_id).first()
    if database_group:
        for nickname in ("DBA", "DBA Team"):
            if not SupportGroupAlias.query.filter(
                func.lower(SupportGroupAlias.alias) == nickname.casefold(),
                SupportGroupAlias.tenant_id == database_group.tenant_id,
            ).first():
                db.session.add(SupportGroupAlias(
                    alias=nickname, group_id=database_group.id, tenant_id=database_group.tenant_id,
                ))
    windows = SupportGroup.query.filter_by(name="Windows").first()
    if windows and not CatalogItem.query.first():
        # Administrator-configurable defaults per governed catalog routing:
        # these are starting points, not hard-coded routing logic — an admin
        # can change or deactivate them at any time via /admin/catalog.
        db.session.add_all([
            CatalogItem(
                name="Laptop Request", category="Hardware",
                description="Request a standard-issue laptop for a new or replacement device.",
                delivery_days=5, approval_required=True,
            ),
            CatalogItem(
                name="Software Request", category="Access",
                description="Request installation or license access for approved software.",
                delivery_days=2, approval_required=True,
            ),
        ])
        db.session.flush()
    if windows:
        for item in CatalogItem.query.filter_by(tenant_id=admin.tenant_id).all():
            normalized = f"{item.name} {item.category}".lower()
            if (
                ("laptop" in normalized or "software" in normalized)
                and not item.fulfillment_route
            ):
                db.session.add(CatalogItemRouting(
                    catalog_item_id=item.id, support_group_id=windows.id,
                    updated_by_id=admin.id, tenant_id=admin.tenant_id,
                ))
    if not SLADefinition.query.first():
        db.session.add_all([
            SLADefinition(name="P1 incident response", target_type="ticket", priority="P1", duration_minutes=15),
            SLADefinition(name="P1 incident resolution", target_type="ticket", priority="P1", duration_minutes=240),
            SLADefinition(name="P2 incident resolution", target_type="ticket", priority="P2", duration_minutes=480),
            SLADefinition(name="P3 incident resolution", target_type="ticket", priority="P3", duration_minutes=1440),
            SLADefinition(name="Catalog fulfillment", target_type="ritm", duration_minutes=4320),
        ])


def seed():
    if User.query.first():
        admin = User.query.filter(User.role.in_(["admin", "superadmin"])).first()
        if not admin:
            raise RuntimeError("The database has users but no administrator account.")
        seed_itil(admin)
        deploy_workflow_package(admin.id)
        db.session.commit()
        return
    admin_password = (
        current_app.config.get("BOOTSTRAP_ADMIN_PASSWORD")
        or secret_value("ADMIN_PASSWORD")
    )
    if not admin_password:
        raise RuntimeError("ADMIN_PASSWORD is required to bootstrap the first administrator.")
    if not current_app.config.get("TESTING") and len(admin_password) < 14:
        raise RuntimeError("ADMIN_PASSWORD must contain at least 14 characters.")
    admin = User(username="admin", name="System Administrator", email="admin@example.local",
                 password_hash=hash_password(admin_password), role="admin")
    db.session.add(admin)
    db.session.flush()
    db.session.add(UserRoleGrant(user_id=admin.id, role="admin"))
    seed_itil(admin)
    deploy_workflow_package(admin.id)
    db.session.commit()


ALL_ROLES = tuple(sorted(ROLE_RANK, key=ROLE_RANK.get))


def role_at_least(role, minimum):
    """True if `role` is at or above `minimum` in the role hierarchy."""
    return ROLE_RANK.get(role, -1) >= ROLE_RANK.get(minimum, 999)


def mapped_roles(groups, mapping_name, default="requester"):
    """Thin DB-backed wrapper: fetches and parses the mapping setting, then
    delegates the actual matching logic to
    serviceops_core.identity.match_directory_role_mappings()."""
    try:
        mappings = json.loads(setting_value(mapping_name, "{}"))
    except json.JSONDecodeError:
        mappings = {}
    configured_default = setting_value(f"{mapping_name}_DEFAULT", default)
    return match_directory_role_mappings(groups, mappings, configured_default, default)


def sync_directory_team_memberships(user, groups):
    """Synchronize only memberships owned by AD mapping automation."""
    aliases = normalized_directory_groups(groups)
    mappings = DirectoryGroupMapping.query.filter_by(active=True).all()
    desired = {
        mapping.support_group_id: mapping
        for mapping in mappings
        if mapping.directory_group.strip().casefold() in aliases
    }
    existing = {
        membership.group_id: membership
        for membership in DirectoryManagedMembership.query.filter_by(user_id=user.id).all()
    }
    for group_id, managed in existing.items():
        if group_id in desired:
            managed.directory_group = desired[group_id].directory_group
            managed.synchronized_at = now()
            continue
        membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
        if membership and membership.role == "member":
            db.session.delete(membership)
        db.session.delete(managed)
    for group_id, mapping in desired.items():
        membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
        if not membership:
            db.session.add(GroupMember(group_id=group_id, user_id=user.id, role="member", tenant_id=user.tenant_id))
        if group_id not in existing:
            db.session.add(DirectoryManagedMembership(
                user_id=user.id, group_id=group_id, directory_group=mapping.directory_group
            ))
    audit(
        "directory group sync", user.username,
        ", ".join(sorted(mapping.support_group.name for mapping in desired.values()))
        or "No mapped teams",
        user_id=user.id,
    )


def sync_role_grants(user, source, desired_roles, detail_by_role=None):
    """Reconcile the roles `source` currently justifies for `user` against
    `desired_roles`, without touching a role justified by a different
    source or granted manually (a manual grant never has a ManagedRoleGrant
    row, so it's never a candidate for removal here). Recomputes User.role
    (the highest currently-held role) afterward."""
    detail_by_role = detail_by_role or {}
    desired_roles = set(desired_roles)
    existing = {
        managed.role: managed
        for managed in ManagedRoleGrant.query.filter_by(user_id=user.id, source=source).all()
    }
    for role in desired_roles:
        if role not in ROLE_RANK:
            continue
        if role in existing:
            existing[role].detail = detail_by_role.get(role, existing[role].detail)
            existing[role].synchronized_at = now()
            continue
        if not UserRoleGrant.query.filter_by(user_id=user.id, role=role).first():
            db.session.add(UserRoleGrant(user_id=user.id, role=role))
        db.session.add(ManagedRoleGrant(
            user_id=user.id, role=role, source=source, detail=detail_by_role.get(role)
        ))
    for role, managed in existing.items():
        if role in desired_roles:
            continue
        db.session.delete(managed)
        db.session.flush()
        if not ManagedRoleGrant.query.filter_by(user_id=user.id, role=role).first():
            grant = UserRoleGrant.query.filter_by(user_id=user.id, role=role).first()
            if grant:
                db.session.delete(grant)
    return recompute_base_role(user)


def recompute_base_role(user):
    """User.role always reflects the highest role currently granted, so any
    code that still reads it directly (rather than the session-aware
    effective_role) keeps its previous "assume the best/highest role"
    behavior. Falls back to "requester" -- every user always holds at
    least that -- if every grant was somehow removed."""
    db.session.flush()
    grants = {g.role for g in UserRoleGrant.query.filter_by(user_id=user.id).all()}
    if not grants:
        db.session.add(UserRoleGrant(user_id=user.id, role="requester"))
        grants = {"requester"}
    user.role = max(grants, key=lambda r: ROLE_RANK.get(r, -1))
    return user.role


def sync_implied_role_grants(user):
    """Ensure manager/agent role grants reflect actual team responsibility.
    Grants (never overwrites) -- adds or revokes only the
    "team_responsibility"-sourced manager/agent grants, never touching a
    directory-derived or manually-granted role (including admin/
    superadmin), unlike the single-role overwrite this replaced."""
    if not user:
        return
    desired = set()
    if SupportGroup.query.filter_by(manager_id=user.id, active=True).first():
        desired.add("manager")
    if GroupMember.query.join(
        SupportGroup, GroupMember.group_id == SupportGroup.id
    ).filter(
        GroupMember.user_id == user.id,
        SupportGroup.active.is_(True),
    ).first():
        desired.add("agent")
    sync_role_grants(user, "team_responsibility", desired)


def user_is_local(user):
    """True if `user` authenticates with a local ServiceOps password rather
    than an external identity provider (LDAP, SSO). Externally-provisioned
    users have no usable local password -- provision_external_user() sets
    password_hash to a random, never-communicated value -- so the in-app
    change-password flow must only be offered to local accounts."""
    if user is None or not getattr(user, "id", None):
        return False
    return ExternalIdentity.query.filter_by(user_id=user.id).first() is None


def apply_external_profile_attrs(user, profile_attrs):
    """Copy directory/SSO-sourced profile fields (title, department, employee
    id, phone, mobile, location, ...) onto ``user``, never nulling out an
    existing value for an attribute the provider didn't send this time
    (sparse claim sets are normal for OIDC userinfo)."""
    if not profile_attrs:
        return
    from serviceops_core.ldap_sync import PROFILE_FIELDS
    for field in PROFILE_FIELDS:
        value = profile_attrs.get(field)
        if value:
            setattr(user, field, str(value).strip())


def provision_external_user(provider, subject, username, name, email, matched_roles, groups=None, profile_attrs=None):
    """`matched_roles` is normally a {role: matched_group_or_None} dict from
    mapped_roles() -- every one of these roles is granted via
    sync_role_grants(..., source="directory"), and any previously
    directory-granted role no longer matched is revoked, without ever
    touching a manually-granted or team-responsibility-granted role. A bare
    role string or an iterable of role strings is also accepted for
    callers that only have a single/plain set of roles.

    ``profile_attrs``, when given, is a {User-column-name: value} dict of
    directory/SSO profile fields (see PROFILE_FIELDS in ldap_sync.py) applied
    to the user record on every login -- e.g. Keycloak/OIDC's department,
    employee ID, phone, mobile, location claims (KEYCLOAK_ATTR_MAP setting).
    """
    if isinstance(matched_roles, str):
        matched_roles = {matched_roles: None}
    elif not isinstance(matched_roles, dict):
        matched_roles = {role: None for role in matched_roles}

    identity = ExternalIdentity.query.filter_by(provider=provider, subject=subject).first()
    if identity:
        user = identity.user
        user.name, user.email = name, email
        user.active = True
        apply_external_profile_attrs(user, profile_attrs)
        sync_role_grants(user, "directory", matched_roles, detail_by_role=matched_roles)
        if provider == "ldap":
            sync_directory_team_memberships(user, groups)
            sync_implied_role_grants(user)
        return user

    base = (username or f"{provider}-{uuid.uuid4().hex[:8]}").strip().lower()[:70]
    email_lower = (email or "").strip().lower()

    # A user account that already exists under this username or email --
    # e.g. a placeholder auto-created by RT import (serviceops_core/rt_import.py)
    # matching an RT Requestor/Owner by email, or any other manually-created
    # local account -- must be adopted into this identity on first login
    # rather than getting a second, disconnected account with a suffixed
    # username. Without this, an RT-imported person's real LDAP login never
    # picks up their group memberships/team assignments (sync_directory_team_memberships
    # never runs against their real account), and they end up with two
    # unrelated users: the orphaned RT one holding all their imported
    # tickets, and a fresh empty one they actually log into.
    existing_user = None
    if email_lower:
        existing_user = User.query.filter(db.func.lower(User.email) == email_lower).first()
    if not existing_user and base:
        existing_user = User.query.filter_by(username=base).first()
    if existing_user and not ExternalIdentity.query.filter_by(
        provider=provider, user_id=existing_user.id
    ).first():
        existing_user.name = name or existing_user.name
        existing_user.email = email or existing_user.email
        existing_user.active = True
        apply_external_profile_attrs(existing_user, profile_attrs)
        db.session.add(ExternalIdentity(provider=provider, subject=subject, user_id=existing_user.id))
        sync_role_grants(existing_user, "directory", matched_roles, detail_by_role=matched_roles)
        if provider == "ldap":
            sync_directory_team_memberships(existing_user, groups)
            sync_implied_role_grants(existing_user)
        return existing_user

    candidate, suffix = base, 1
    while User.query.filter_by(username=candidate).first():
        suffix += 1
        candidate = f"{base[:70]}-{suffix}"
    unique_email = (email or f"{candidate}@external.serviceops.local").lower()
    existing = User.query.filter_by(email=unique_email).first()
    if existing:
        unique_email = f"{provider}-{uuid.uuid4().hex[:8]}@external.serviceops.local"
    initial_role = (
        max(matched_roles, key=lambda r: ROLE_RANK.get(r, -1)) if matched_roles else "requester"
    )
    user = User(username=candidate, name=name or candidate, email=unique_email,
                password_hash=hash_password(uuid.uuid4().hex), role=initial_role)
    db.session.add(user)
    db.session.flush()
    apply_external_profile_attrs(user, profile_attrs)
    db.session.add(ExternalIdentity(provider=provider, subject=subject, user_id=user.id))
    sync_role_grants(user, "directory", matched_roles, detail_by_role=matched_roles)
    if provider == "ldap":
        sync_directory_team_memberships(user, groups)
        sync_implied_role_grants(user)
    return user


class LdapBindError(RuntimeError):
    """Raised when a service-account LDAP bind cannot be established."""


def ldap_server_and_service_connection():
    """Build the ldap3 Server plus a bound service-account Connection, shared by
    interactive login (ldap_authenticate) and the directory sync job. Raises
    LdapBindError rather than returning a half-usable connection so callers
    never mistake a failed bind for "no directory configured"."""
    uri = setting_value("LDAP_SERVER_URI", "")
    if not uri:
        raise LdapBindError("LDAP_SERVER_URI is not configured.")
    use_ssl = uri.lower().startswith("ldaps://")
    host = uri.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    port = int(os.getenv("LDAP_PORT", "636" if use_ssl else "389"))
    validate = ssl.CERT_REQUIRED if setting_bool("LDAP_VALIDATE_CERT", True) else ssl.CERT_NONE
    tls = Tls(validate=validate, ca_certs_file=os.getenv("LDAP_CA_CERT") or None)
    server = Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL,
                    connect_timeout=int(os.getenv("LDAP_TIMEOUT", "8")))
    bind_dn = setting_value("LDAP_BIND_DN") or None
    bind_password = None
    if bind_dn:
        # Resolve the bind password directly rather than through setting_value(),
        # which silently falls back to "" (anonymous bind) if decryption fails —
        # a key-rotation or config mistake must not silently degrade a configured
        # authenticated bind into an anonymous one.
        password_row = db.session.get(PlatformSetting, "LDAP_BIND_PASSWORD")
        if password_row and password_row.encrypted:
            try:
                bind_password = settings_cipher().decrypt(password_row.value.encode()).decode() or None
            except (InvalidToken, ValueError):
                current_app.logger.error(
                    "LDAP bind password could not be decrypted; refusing to fall back "
                    "to an anonymous bind for a configured bind DN."
                )
                raise LdapBindError("LDAP bind password could not be decrypted.")
        elif password_row:
            bind_password = password_row.value or None
    service = Connection(server, user=bind_dn, password=bind_password,
                         auto_bind=False, receive_timeout=int(os.getenv("LDAP_TIMEOUT", "8")))
    service.open()
    if not use_ssl and setting_bool("LDAP_START_TLS", True):
        if not service.start_tls():
            raise LdapBindError("LDAP StartTLS negotiation failed.")
    if not service.bind():
        raise LdapBindError("LDAP service-account bind failed.")
    return server, service


def sync_ldap_manager_on_login(user, entry_dn, manager_dn, merged_attr_map):
    """Best-effort manager mapping for LDAP login.

    Runs on successful login so org-chart links stay current without relying
    on periodic/full-directory sync. Never raises -- login must continue even
    if manager lookup fails.
    """
    if not user or not entry_dn or not manager_dn:
        return
    entry_key = str(entry_dn).strip().casefold()
    manager_key = str(manager_dn).strip().casefold()
    if not entry_key or not manager_key:
        return
    if entry_key == manager_key:
        current_app.logger.warning(
            "Self-manager LDAP record skipped for user %s.",
            user.username,
        )
        return

    try:
        manager_identity = ExternalIdentity.query.filter_by(
            provider="ldap", subject=manager_dn
        ).first()
        manager_user = manager_identity.user if manager_identity else None

        if not manager_user:
            _server, service = ldap_server_and_service_connection()
            try:
                if not service.search(
                    search_base=manager_dn,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=sorted(set([
                        merged_attr_map.get("username", "sAMAccountName"),
                        merged_attr_map.get("display_name", "displayName"),
                        merged_attr_map.get("email", "mail"),
                        "memberOf",
                    ])),
                    size_limit=1,
                ):
                    return
                entries = list(service.entries)
            finally:
                try:
                    service.unbind()
                except Exception:
                    pass
            if not entries:
                return
            values = entries[0].entry_attributes_as_dict
            first = lambda key, fallback="": (values.get(key) or [fallback])[0]
            manager_username = first(merged_attr_map.get("username", "sAMAccountName"), "")
            if not manager_username:
                return
            manager_groups = values.get("memberOf", [])
            manager_roles = mapped_roles(manager_groups, "LDAP_ROLE_MAPPINGS")
            manager_profile_attrs = {}
            from serviceops_core.ldap_sync import PROFILE_FIELDS
            for field in PROFILE_FIELDS:
                ldap_attr = merged_attr_map.get(field)
                if not ldap_attr:
                    continue
                val = first(ldap_attr, "")
                if val:
                    manager_profile_attrs[field] = val
            manager_user = provision_external_user(
                "ldap",
                manager_dn,
                manager_username,
                first(merged_attr_map.get("display_name", "displayName"), manager_username),
                first(merged_attr_map.get("email", "mail"), ""),
                manager_roles,
                groups=manager_groups,
                profile_attrs=manager_profile_attrs,
            )

        if manager_user and manager_user.id != user.id and manager_user.tenant_id == user.tenant_id:
            if user.manager_id != manager_user.id:
                user.manager_id = manager_user.id
    except Exception as error:  # noqa: BLE001 - login must not fail on manager sync
        current_app.logger.warning(
            "LDAP manager sync on login failed for %s: %s",
            user.username,
            type(error).__name__,
        )


def ldap_username_placeholder():
    """Ghost text for the login form's username field. Thin DB-backed
    wrapper: fetches LDAP_ENABLED/LDAP_BASE_DN, delegates the actual
    domain-derivation to serviceops_core.identity.ldap_domain_suffix_from_base_dn()."""
    if not setting_bool("LDAP_ENABLED"):
        return "Username"
    domain = ldap_domain_suffix_from_base_dn(setting_value("LDAP_BASE_DN", ""))
    return f"jsmith or jsmith@{domain}" if domain else "jsmith"


def ldap_authenticate(username, password):
    if not password or not setting_bool("LDAP_ENABLED"):
        return None
    try:
        server, service = ldap_server_and_service_connection()
    except LdapBindError:
        return None
    use_ssl = bool(server.ssl)
    filter_template = setting_value(
        "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
    )
    base_dn = setting_value("LDAP_BASE_DN", "")
    try:
        ldap_attr_map = json.loads(setting_value("LDAP_ATTR_MAP", "{}"))
    except (TypeError, json.JSONDecodeError):
        ldap_attr_map = {}
    attr_names = {
        "distinguishedName", "cn", "displayName", "mail", "memberOf", "userPrincipalName"
    }
    for mapped in ldap_attr_map.values() if isinstance(ldap_attr_map, dict) else []:
        if isinstance(mapped, str) and mapped.strip():
            attr_names.add(mapped.strip())
    attrs = sorted(attr_names)
    # Try the bare local part first (e.g. "jsmith" from either "jsmith",
    # "jsmith@company.com", or "CORP\jsmith") since sAMAccountName -- what
    # the default filter and most deployments match against -- only ever
    # holds that bare form. If a site has customized LDAP_USER_FILTER to
    # match userPrincipalName instead, the bare local part alone won't
    # match a full UPN there, so fall back to the exact string the user
    # typed. This fixes every existing deployment (default or
    # sAMAccountName-based custom filters) immediately, with no settings
    # change required, while staying backward-compatible with filters that
    # deliberately expect a full UPN.
    local_part = ldap_login_local_part(username)
    candidates = [local_part] if local_part == username else [local_part, username]
    entries = []
    for candidate in candidates:
        search_filter = filter_template.replace("{username}", escape_filter_chars(candidate))
        if service.search(base_dn, search_filter, search_scope=SUBTREE, attributes=attrs, size_limit=2):
            entries = list(service.entries)
            if len(entries) == 1:
                break
    service.unbind()
    if len(entries) != 1:
        return None
    entry = entries[0]
    user_conn = Connection(server, user=entry.entry_dn, password=password, auto_bind=False)
    user_conn.open()
    # Every early return below must unbind first -- only the success path
    # used to, leaking one open socket per failed login attempt (wrong
    # password, or a server that always rejects StartTLS) until GC/timeout
    # reclaimed it.
    if not use_ssl and setting_bool("LDAP_START_TLS", True) and not user_conn.start_tls():
        user_conn.unbind()
        return None
    if not user_conn.bind():
        user_conn.unbind()
        return None
    user_conn.unbind()
    values = entry.entry_attributes_as_dict
    first = lambda key, fallback="": (values.get(key) or [fallback])[0]
    groups = values.get("memberOf", [])
    matched_roles = mapped_roles(groups, "LDAP_ROLE_MAPPINGS")
    from serviceops_core.ldap_sync import DEFAULT_ATTR_MAP, PROFILE_FIELDS
    merged_attr_map = dict(DEFAULT_ATTR_MAP)
    if isinstance(ldap_attr_map, dict):
        merged_attr_map.update({k: v for k, v in ldap_attr_map.items() if isinstance(v, str) and v})
    profile_attrs = {}
    for field in PROFILE_FIELDS:
        ldap_attr = merged_attr_map.get(field)
        if not ldap_attr:
            continue
        val = first(ldap_attr, "")
        if val:
            profile_attrs[field] = val
    # Use the bare local part, not whatever form the user happened to type
    # this time, as the new account's username -- entry.entry_dn is the
    # actual matching key for returning logins (see
    # provision_external_user's ExternalIdentity lookup), so this only
    # affects the username assigned the very first time this person logs
    # in, but "jsmith@company.com" as a permanent account name would be an
    # ugly, confusing artifact of whichever login form they happened to
    # type first.
    user = provision_external_user(
        "ldap", entry.entry_dn, local_part, first("displayName", first("cn", local_part)),
        first("mail", first("userPrincipalName", "")), matched_roles, groups=groups,
        profile_attrs=profile_attrs,
    )
    manager_dn = first(merged_attr_map.get("manager", "manager"), "")
    sync_ldap_manager_on_login(user, entry.entry_dn, manager_dn, merged_attr_map)
    return user


APP_START_TIME = now()


class JsonLogFormatter(logging.Formatter):
    """One JSON object per line -- detailed enough to reconstruct what
    happened around an incident (request_id ties every request-scoped log
    line together; exc_info carries the full traceback) without needing raw
    text log parsing. Written to LOG_DIR so operators can read it from the
    admin System Health log viewer instead of `docker logs`."""

    def format(self, record):
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for attr in ("request_id", "trace_id", "method", "path", "status_code", "duration_ms", "user_id", "tenant_id", "remote_addr"):
            value = getattr(record, attr, None)
            if value is not None:
                payload[attr] = value
        if record.exc_info:
            payload["exception"] = "".join(traceback_module.format_exception(*record.exc_info))
        return json.dumps(payload, default=str)


class DatabaseLogHandler(logging.Handler):
    """Persists WARNING+ records to ApplicationLog so they survive a
    container restart/crash and are readable from the admin System Health
    page without shell/`docker logs` access (the stated goal: "every error
    must be recorded" and readable "from the admin menu"). Silently drops
    the record (never raises) if there's no request/app context or the DB
    write itself fails -- a logging failure must never crash the request
    that triggered the log in the first place."""

    def emit(self, record):
        if not has_app_context():
            return
        try:
            db.session.add(ApplicationLog(
                level=record.levelname,
                logger_name=record.name,
                message=self.format(record) if not record.exc_info else record.getMessage(),
                traceback=(
                    "".join(traceback_module.format_exception(*record.exc_info))
                    if record.exc_info else None
                ),
                path=request.path if has_request_context() else getattr(record, "path", None),
                method=request.method if has_request_context() else getattr(record, "method", None),
                request_id=(
                    g.get("request_id") if has_request_context() else getattr(record, "request_id", None)
                ),
                user_id=(
                    current_user.id
                    if has_request_context() and current_user.is_authenticated else None
                ),
                tenant_id=(
                    current_user.tenant_id
                    if has_request_context() and current_user.is_authenticated else None
                ),
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()


def configure_detailed_logging(app):
    """LOG_DIR-backed rotating JSON file (all loggers, INFO+) plus the
    always-on DatabaseLogHandler (app logger, WARNING+). LOG_DIR is only set
    in the container images (see compose.yaml's serviceops_logs volume --
    the app/worker containers run read_only, so this must be a mounted
    volume, not the read-only root filesystem); local/test runs without it
    just skip the file handler and keep the DB-backed one."""
    # app.logger is logging.getLogger(app.import_name) -- a single
    # process-wide named logger, not something scoped to this particular
    # Flask instance. create_app() can run more than once in the same
    # process (every test in this suite does exactly that), so handlers
    # added here must be cleared first or they silently accumulate one set
    # per call -- each duplicate DatabaseLogHandler/file handler processing
    # the same record, eventually including ones bound to a long-torn-down
    # SQLite tempfile from an earlier test whose emit() failures then mask
    # the current, valid handler's own successful write.
    for logger_name in ("app", "gunicorn.access"):
        target_logger = logging.getLogger(logger_name)
        for handler in list(target_logger.handlers):
            if isinstance(handler, (DatabaseLogHandler, logging.handlers.RotatingFileHandler)):
                target_logger.removeHandler(handler)
    for existing in list(logging.getLogger().handlers):
        if isinstance(existing, logging.handlers.RotatingFileHandler):
            logging.getLogger().removeHandler(existing)

    log_level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)

    # `docker logs`/`kubectl logs` must show the exact same detail as the
    # in-app log viewer and LOG_DIR file -- an operator without shell access
    # to the volume (or debugging before it's mounted) still needs full
    # context. Same JsonLogFormatter/RedactingFilter as the file handler, so
    # every line is identical in both places, just duplicated sinks.
    for existing in list(logging.getLogger().handlers):
        if isinstance(existing, logging.StreamHandler) and getattr(existing, "_serviceops_stdout", False):
            logging.getLogger().removeHandler(existing)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(JsonLogFormatter())
    stdout_handler.addFilter(RedactingFilter())
    stdout_handler.setLevel(log_level)
    stdout_handler._serviceops_stdout = True
    root_logger = logging.getLogger()
    root_logger.addHandler(stdout_handler)
    root_logger.setLevel(min(root_logger.level or logging.WARNING, log_level))
    logging.getLogger("gunicorn.access").addHandler(stdout_handler)

    log_dir = os.getenv("LOG_DIR", "").strip()
    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, "serviceops.json.log"),
                maxBytes=20 * 1024 * 1024, backupCount=10,
            )
            file_handler.setFormatter(JsonLogFormatter())
            file_handler.addFilter(RedactingFilter())
            file_handler.setLevel(log_level)
            root_logger = logging.getLogger()
            root_logger.addHandler(file_handler)
            root_logger.setLevel(min(root_logger.level or logging.WARNING, log_level))
            logging.getLogger("gunicorn.access").addHandler(file_handler)
        except OSError as error:
            app.logger.warning("Could not open LOG_DIR for the detailed log file: %s", error)

    db_handler = DatabaseLogHandler()
    db_handler.setLevel(logging.WARNING)
    db_handler.addFilter(RedactingFilter())
    app.logger.addHandler(db_handler)
    app.logger.setLevel(log_level)


def _parse_log_timestamp(value):
    """Best-effort parse of a datetime-local/ISO query-string value used by
    the System Health "from"/"to" filters; returns None (never raises) so a
    malformed filter degrades to "no bound" instead of a 500."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _filtered_application_log_query(current_user):
    """Splunk-style filtering over the persisted ApplicationLog error/warning
    table: free-text message search plus level/logger/path/request_id/date
    range facets, all combinable. Shared by the System Health page and its
    CSV/JSON export so filters and export always see identical results.
    Not tenant_query(): many real errors have no tenant context at all (a
    failed login before authentication, an LDAP bind failure, a background
    worker error) -- strictly filtering by tenant_id would make exactly the
    crashes an admin most needs to see permanently invisible. Include this
    tenant's own errors plus every tenant-less one; still never another
    tenant's."""
    query = ApplicationLog.query.filter(
        db.or_(ApplicationLog.tenant_id.is_(None), ApplicationLog.tenant_id == current_user.tenant_id)
    )
    level_filter = request.args.get("level", "")
    if level_filter in ("ERROR", "CRITICAL", "WARNING"):
        query = query.filter(ApplicationLog.level == level_filter)
    q = request.args.get("q", "").strip()
    if q:
        query = query.filter(ApplicationLog.message.ilike(f"%{q}%"))
    logger_filter = request.args.get("logger", "").strip()
    if logger_filter:
        query = query.filter(ApplicationLog.logger_name.ilike(f"%{logger_filter}%"))
    path_filter = request.args.get("path", "").strip()
    if path_filter:
        query = query.filter(ApplicationLog.path.ilike(f"%{path_filter}%"))
    request_id_filter = request.args.get("request_id", "").strip()
    if request_id_filter:
        query = query.filter(ApplicationLog.request_id == request_id_filter)
    from_dt = _parse_log_timestamp(request.args.get("from", "").strip())
    if from_dt:
        query = query.filter(ApplicationLog.created_at >= from_dt)
    to_dt = _parse_log_timestamp(request.args.get("to", "").strip())
    if to_dt:
        query = query.filter(ApplicationLog.created_at <= to_dt)
    filters = {
        "level_filter": level_filter, "q": q, "logger_filter": logger_filter,
        "path_filter": path_filter, "request_id_filter": request_id_filter,
        "from_filter": request.args.get("from", "").strip(),
        "to_filter": request.args.get("to", "").strip(),
    }
    return query, filters


def _export_response(rows, fields, fmt, filename_stem):
    """Renders `rows` (list of dicts already limited to `fields`) as CSV,
    NDJSON, pretty JSON, or plain text -- the "export logs in multiple
    famous file formats" requirement. Defaults to CSV (most portable into
    Excel/Splunk/other SIEM tooling) for an unrecognized format rather than
    erroring."""
    timestamp = now().strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        body = json.dumps(rows, indent=2, default=str)
        mimetype, ext = "application/json", "json"
    elif fmt == "ndjson":
        body = "\n".join(json.dumps(row, default=str) for row in rows)
        mimetype, ext = "application/x-ndjson", "ndjson"
    elif fmt == "txt":
        lines = []
        for row in rows:
            lines.append(" | ".join(f"{field}={row.get(field)}" for field in fields))
        body = "\n".join(lines)
        mimetype, ext = "text/plain", "txt"
    else:
        fmt = "csv"
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        body = buffer.getvalue()
        mimetype, ext = "text/csv", "csv"
    response = Response(body, mimetype=mimetype)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{filename_stem}-{timestamp}.{ext}"'
    )
    return response


def _read_and_filter_log_file():
    """Reads the shared LOG_DIR JSON log file and applies Splunk-style
    facet filters (free-text q, level, logger, path, method, status_code,
    request_id, from/to date range), all combinable -- shared by the log
    viewer page and its export endpoint so what an admin sees on screen is
    exactly what gets exported. Returns (parsed_entries, error_message,
    log_path); parsed_entries is newest-first."""
    log_dir = os.getenv("LOG_DIR", "").strip()
    log_path = os.path.join(log_dir, "serviceops.json.log") if log_dir else None
    lines = []
    error_message = None
    if not log_path or not os.path.isfile(log_path):
        error_message = (
            "No detailed log file is available. LOG_DIR is not configured for this "
            "deployment, or no requests have been logged to it yet."
        )
    else:
        try:
            max_lines = min(max(int(request.args.get("lines", "500")), 1), 20000)
        except ValueError:
            max_lines = 500
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
                lines = collections.deque(handle, maxlen=max_lines)
        except OSError as error:
            error_message = f"Could not read the log file: {error}"

    q = request.args.get("q", "").strip()
    level_filter = request.args.get("level", "").strip().upper()
    logger_filter = request.args.get("logger", "").strip()
    path_filter = request.args.get("path", "").strip()
    method_filter = request.args.get("method", "").strip().upper()
    status_filter = request.args.get("status_code", "").strip()
    request_id_filter = request.args.get("request_id", "").strip()
    from_dt = _parse_log_timestamp(request.args.get("from", "").strip())
    to_dt = _parse_log_timestamp(request.args.get("to", "").strip())

    parsed = []
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            entry = {"level": "", "message": line.rstrip("\n")}
        if q and q.casefold() not in json.dumps(entry, default=str).casefold():
            continue
        if level_filter and str(entry.get("level", "")).upper() != level_filter:
            continue
        if logger_filter and logger_filter.casefold() not in str(entry.get("logger", "")).casefold():
            continue
        if path_filter and path_filter.casefold() not in str(entry.get("path", "")).casefold():
            continue
        if method_filter and str(entry.get("method", "")).upper() != method_filter:
            continue
        if status_filter and str(entry.get("status_code", "")) != status_filter:
            continue
        if request_id_filter and str(entry.get("request_id", "")) != request_id_filter:
            continue
        if from_dt or to_dt:
            entry_ts = None
            try:
                entry_ts = datetime.fromisoformat(entry.get("timestamp", ""))
            except (ValueError, TypeError):
                pass
            if entry_ts is not None:
                if from_dt and entry_ts < from_dt:
                    continue
                if to_dt and entry_ts > to_dt:
                    continue
        parsed.append(entry)
    parsed.reverse()
    filters = {
        "q": q, "level_filter": level_filter, "logger_filter": logger_filter,
        "path_filter": path_filter, "method_filter": method_filter,
        "status_filter": status_filter, "request_id_filter": request_id_filter,
        "from_filter": request.args.get("from", "").strip(),
        "to_filter": request.args.get("to", "").strip(),
    }
    return parsed, error_message, log_path, filters


def _workspace_widget_my_open_tickets(user):
    terminal = ("Resolved", "Closed", "Cancelled")
    rows = visible_ticket_query(user).filter(
        Ticket.assignee_id == user.id, Ticket.state.notin_(terminal),
    ).order_by(Ticket.priority, Ticket.updated_at.desc()).limit(8).all()
    return {"tickets": rows}


def _workspace_widget_recent_tickets(user):
    rows = visible_ticket_query(user).filter(Ticket.deleted_at.is_(None)).order_by(
        Ticket.updated_at.desc()
    ).limit(8).all()
    return {"tickets": rows}


def _workspace_widget_sla_at_risk(user):
    terminal = ("Resolved", "Closed", "Cancelled")
    ticket_ids = [
        row[0] for row in visible_ticket_query(user).filter(Ticket.state.notin_(terminal))
        .with_entities(Ticket.id).all()
    ]
    rows = []
    if ticket_ids:
        breach_horizon = now() + timedelta(hours=setting_int("SLA_AT_RISK_HOURS", 4))
        sla_rows = TaskSLA.query.filter(
            TaskSLA.target_type == "ticket", TaskSLA.target_id.in_(ticket_ids),
            TaskSLA.stage == "In Progress", TaskSLA.breached.is_(False),
        ).order_by(TaskSLA.breach_at).all()
        tickets_by_id = {t.id: t for t in Ticket.query.filter(Ticket.id.in_(ticket_ids)).all()}
        for row in sla_rows:
            breach_at = row.breach_at if row.breach_at.tzinfo else row.breach_at.replace(tzinfo=timezone.utc)
            if breach_at <= breach_horizon and row.target_id in tickets_by_id:
                rows.append(tickets_by_id[row.target_id])
    return {"tickets": rows[:8]}


def _workspace_widget_approvals_awaiting_me(user):
    votes = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
        ApprovalVote.approver_id == user.id, ApprovalVote.state == "Requested",
        ApprovalChain.tenant_id == user.tenant_id,
    ).limit(8).all()
    return {"votes": votes}


def _workspace_widget_favorites(user):
    rows = Favorite.query.filter_by(user_id=user.id).order_by(Favorite.created_at.desc()).limit(8).all()
    return {"favorites": rows}


def _workspace_widget_recently_viewed(user):
    rows = RecentView.query.filter_by(user_id=user.id).order_by(RecentView.viewed_at.desc()).limit(8).all()
    return {"views": rows}


def _workspace_widget_notifications(user):
    rows = Notification.query.filter_by(user_id=user.id).order_by(
        Notification.read.asc(), Notification.created_at.desc()
    ).limit(8).all()
    return {"notifications": rows}


def _workspace_widget_ticket_stats(user):
    terminal = ("Resolved", "Closed", "Cancelled")
    rows = visible_ticket_query(user).with_entities(Ticket.kind, Ticket.state).all()
    counts = {"incident": 0, "change": 0, "open": 0}
    for kind, state in rows:
        if kind in ("incident", "change"):
            counts[kind] += 1
        if state not in terminal:
            counts["open"] += 1
    return {"counts": counts}


# B-121: the closed catalog a personal workspace layout can be built from --
# pre-built, server-rendered widgets reusing existing queries/authorization
# (visible_ticket_query etc.), never arbitrary user-supplied content. Adding
# a widget here means adding both a data function above and rendering logic
# in my_workspace.html; removing/renaming one is safe -- UserWorkspaceLayout
# .layout_json rows referencing a since-removed key are silently skipped at
# render time. Enablement is governed instance-wide via the
# WORKSPACE_WIDGET_<KEY>_ENABLED settings (see SETTING_DEFINITIONS) --
# PlatformSetting is a single global row per key across the whole install,
# same as every other entry in SETTING_DEFINITIONS, not actually per-tenant
# despite the column existing on the table.
WORKSPACE_WIDGET_REGISTRY = {
    "ticket_stats": {"label": "Ticket counts", "default_span": 2, "data": _workspace_widget_ticket_stats},
    "my_open_tickets": {"label": "My open tickets", "default_span": 1, "data": _workspace_widget_my_open_tickets},
    "recent_tickets": {"label": "Recently updated tickets", "default_span": 1, "data": _workspace_widget_recent_tickets},
    "sla_at_risk": {"label": "SLA at risk", "default_span": 1, "data": _workspace_widget_sla_at_risk},
    "approvals_awaiting_me": {"label": "Approvals awaiting me", "default_span": 1, "data": _workspace_widget_approvals_awaiting_me},
    "favorites": {"label": "Favorites", "default_span": 1, "data": _workspace_widget_favorites},
    "recently_viewed": {"label": "Recently viewed", "default_span": 1, "data": _workspace_widget_recently_viewed},
    "notifications": {"label": "Notifications", "default_span": 1, "data": _workspace_widget_notifications},
}


def workspace_widget_enabled(widget_key):
    return setting_bool(f"WORKSPACE_WIDGET_{widget_key.upper()}_ENABLED", True)


def create_app(test_config=None):
    app = Flask(__name__)
    # ISO 27001 A.8.11: never let passwords/tokens/connection strings/LDAP
    # bind passwords/session identifiers reach a log sink in the clear, even
    # if a call site accidentally logs a raw dict/exception containing one.
    # Same accumulation concern as configure_detailed_logging() below: clear
    # any filter this same process already added on a previous create_app()
    # call before adding a fresh one.
    for logger_name in ("app", "gunicorn.error", "gunicorn.access"):
        target_logger = logging.getLogger(logger_name)
        for existing_filter in list(target_logger.filters):
            if isinstance(existing_filter, RedactingFilter):
                target_logger.removeFilter(existing_filter)
    _redacting_filter = RedactingFilter()
    app.logger.addFilter(_redacting_filter)
    configure_detailed_logging(app)
    logging.getLogger("gunicorn.error").addFilter(_redacting_filter)
    logging.getLogger("gunicorn.access").addFilter(_redacting_filter)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///serviceops.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.getenv("UPLOAD_FOLDER", os.path.join(app.instance_path, "uploads")),
        MAX_CONTENT_LENGTH=20 * 1024 * 1024,
        # Werkzeug's own default here is 500_000 bytes and is enforced
        # independently of MAX_CONTENT_LENGTH -- it caps a single non-file
        # form field's size, not just uploaded files. The CMDB CSV import's
        # preview-then-apply flow round-trips the pasted/uploaded CSV through
        # a plain hidden field (see cmdb_import route, templates/cmdb_import.html),
        # so anything past ~488 KiB tripped this silently with a misleading
        # "file too large" message even though MAX_UPLOAD_MB was nowhere near
        # hit. Tied to the same admin-configurable MAX_UPLOAD_MB setting below.
        MAX_FORM_MEMORY_SIZE=20 * 1024 * 1024,
        DEPLOYMENT_PROFILE="production",
        LDAP_ENABLED=env_bool("LDAP_ENABLED"),
        KEYCLOAK_ENABLED=env_bool("KEYCLOAK_ENABLED"),
        LOCAL_AUTH_ENABLED=env_bool("LOCAL_AUTH_ENABLED", True),
        CSRF_ENABLED=env_bool("CSRF_ENABLED", True),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=env_bool("SESSION_COOKIE_SECURE", True),
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=int(os.getenv("SESSION_LIFETIME_MINUTES", "480"))
        ),
        AUTO_MIGRATE=env_bool("AUTO_MIGRATE", True),
        STORAGE_MODE=os.getenv("STORAGE_MODE", "postgres").strip().lower(),
    )
    if test_config:
        app.config.update(test_config)
    if app.config["TESTING"]:
        if not test_config or "CSRF_ENABLED" not in test_config:
            app.config["CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or "test-only-secret"
        app.config["BOOTSTRAP_ADMIN_PASSWORD"] = app.config.get(
            "BOOTSTRAP_ADMIN_PASSWORD", "Admin123!"
        )
    elif not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY is required and must contain at least 32 characters.")
    if (
        not app.config["TESTING"]
        and not app.config["SESSION_COOKIE_SECURE"]
        and not env_bool("ALLOW_INSECURE_SESSION_COOKIES")
    ):
        raise RuntimeError(
            "SESSION_COOKIE_SECURE=false requires TLS termination in front of this app. "
            "Set SESSION_COOKIE_SECURE=true (default) behind TLS, or explicitly set "
            "ALLOW_INSECURE_SESSION_COOKIES=true for a non-TLS development deployment only."
        )
    if env_bool("TRUST_PROXY_HEADERS"):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=int(os.getenv("PROXY_FIX_X_FOR", "1")),
            x_proto=int(os.getenv("PROXY_FIX_X_PROTO", "1")),
            x_host=int(os.getenv("PROXY_FIX_X_HOST", "1")),
            x_prefix=int(os.getenv("PROXY_FIX_X_PREFIX", "0")),
        )
    db.init_app(app)
    login_manager.init_app(app)
    oauth.init_app(app)
    validate_policy()
    validate_priority_policy()
    validate_projection_policy()

    with app.app_context():
        if app.config["TESTING"] and not app.config.get("AUTO_MIGRATE_IN_TESTS"):
            db.create_all()
        else:
            migration_config = AlembicConfig(
                os.path.join(os.path.dirname(__file__), "alembic.ini")
            )
            migration_config.set_main_option(
                "script_location", os.path.join(os.path.dirname(__file__), "migrations")
            )
            migration_config.set_main_option(
                "sqlalchemy.url", str(db.engine.url).replace("%", "%%")
            )
            if app.config["AUTO_MIGRATE"]:
                command.upgrade(migration_config, "head")
            else:
                with db.engine.connect() as migration_connection:
                    current_revision = MigrationContext.configure(
                        migration_connection
                    ).get_current_revision()
                required_revision = ScriptDirectory.from_config(
                    migration_config
                ).get_current_head()
                if current_revision != required_revision:
                    raise RuntimeError(
                        "Database migration required: current revision "
                        f"{current_revision or 'unversioned'}, required {required_revision}. "
                        "Run the migration job before starting ServiceOps."
                    )
        default_tenant = db.session.get(Tenant, 1)
        if not default_tenant:
            default_tenant = Tenant(
                id=1,
                slug=os.getenv("DEFAULT_TENANT_SLUG", "default"),
                name=os.getenv("DEFAULT_TENANT_NAME", "Default organisation"),
            )
            db.session.add(default_tenant)
            db.session.commit()
        seed()
        UserPreference.query.filter(UserPreference.theme != "light").update({"theme": "light"})
        db.session.commit()
        app.config["LOCAL_AUTH_ENABLED"] = setting_bool("LOCAL_AUTH_ENABLED", True)
        app.config["LDAP_ENABLED"] = setting_bool("LDAP_ENABLED")
        app.config["KEYCLOAK_ENABLED"] = setting_bool("KEYCLOAK_ENABLED")
        app.config["MAX_CONTENT_LENGTH"] = int(setting_value("MAX_UPLOAD_MB", "20")) * 1024 * 1024
        app.config["MAX_FORM_MEMORY_SIZE"] = app.config["MAX_CONTENT_LENGTH"]
        # SESSION_HOURS ("live": False, i.e. restart-required) used to be
        # defined in the settings schema and shown as configurable on
        # Platform Settings, but nothing ever actually read it -- session
        # lifetime was purely env-var driven (SESSION_LIFETIME_MINUTES,
        # set once above before the database was even connected). An admin
        # could set and save "Session lifetime in hours" with zero effect,
        # no error. The env var's own value (already resolved into
        # app.config above) is passed as the fallback default here so
        # deployments that only ever used the env var keep working
        # identically until an admin actually sets this in the UI.
        env_default_hours = int(app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() // 3600) or 8
        app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
            hours=setting_int("SESSION_HOURS", env_default_hours)
        )
        if app.config["KEYCLOAK_ENABLED"]:
            oauth.register(
                name="keycloak",
                client_id=setting_value("KEYCLOAK_CLIENT_ID"),
                client_secret=setting_value("KEYCLOAK_CLIENT_SECRET"),
                server_metadata_url=setting_value("KEYCLOAK_DISCOVERY_URL"),
                client_kwargs={"scope": "openid profile email"},
            )
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        # Optional database-less deployment mode (STORAGE_MODE=ipfs): this
        # first slice only moves file-attachment bytes onto IPFS -- every
        # other entity (tickets, users, ...) still requires PostgreSQL
        # exactly as above; that migration happens in later rollout waves
        # per the storage-mode plan. PostgreSQL-mode deployments (the
        # default) are unaffected: build_storage_backend() returns
        # PostgresStorageBackend, which replicates today's local-disk/S3
        # attachment behavior with no change.
        app.extensions["storage_backend"] = build_storage_backend(
            upload_folder=app.config["UPLOAD_FOLDER"],
            object_storage_client_factory=object_storage_client,
            object_storage_bucket=os.getenv("OBJECT_STORAGE_BUCKET", "").strip() or None,
        )
        # Gunicorn preloads the application before forking workers. Do not let
        # workers inherit PostgreSQL connections or prepared-statement state.
        db.engine.dispose()

    def csrf_token():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    @app.before_request
    def assign_request_id():
        supplied = request.headers.get("X-Request-ID", "").strip()
        try:
            g.request_id = str(uuid.UUID(supplied)) if supplied else str(uuid.uuid4())
        except ValueError:
            g.request_id = str(uuid.uuid4())
        traceparent = request.headers.get("traceparent", "")
        trace_match = re.fullmatch(r"[\da-f]{2}-([\da-f]{32})-[\da-f]{16}-[\da-f]{2}", traceparent.lower())
        g.trace_id = trace_match.group(1) if trace_match else secrets.token_hex(16)
        g._request_started_at = time_module.monotonic()

    @app.before_request
    def track_last_seen():
        # Throttled to at most once/minute/user -- an UPDATE on every single
        # request would otherwise add write load proportional to traffic for
        # a stat that only needs minute-level precision (System Health's
        # "currently active users").
        if not current_user.is_authenticated:
            return
        stale = (
            current_user.last_seen_at is None
            or (now() - align_tz(current_user.last_seen_at, now())) > timedelta(minutes=1)
        )
        if stale:
            current_user.last_seen_at = now()
            db.session.commit()

    @app.before_request
    def enforce_session_inventory():
        if not current_user.is_authenticated:
            return None
        session_id = session.get("_session_id")
        record = UserSession.query.filter_by(session_id=session_id).first() if session_id else None
        if record and (record.revoked_at or align_tz(record.expires_at, now()) <= now()):
            logout_user()
            session.clear()
            return redirect(url_for("login"))
        if not record:
            session_id = secrets.token_urlsafe(32)
            session["_session_id"] = session_id
            record = UserSession(
                session_id=session_id, user_id=current_user.id,
                tenant_id=current_user.tenant_id,
                provider=session.get("_auth_provider", "local"),
                ip_address=(request.remote_addr or "")[:64],
                user_agent=request.headers.get("User-Agent", "")[:500],
                expires_at=now() + app.config["PERMANENT_SESSION_LIFETIME"],
            )
            db.session.add(record)
            db.session.commit()
        elif (now() - align_tz(record.last_seen_at, now())) > timedelta(minutes=1):
            record.last_seen_at = now()
            db.session.commit()
        g.user_session = record
        return None

    @app.before_request
    def verify_api_identity():
        if (
            (request.path.startswith("/api/v1/") or request.path.startswith("/scim/v2/"))
            and request.endpoint not in {
                "api_openapi", "api_docs", "monitoring_ingest",
                "api_mobile_login", "api_mobile_refresh",
                "api_passkey_authentication_options", "api_passkey_authentication_complete",
                "apple_app_site_association",
            }
        ):
            authenticate_api_request()

    @app.before_request
    def verify_csrf():
        if (
            request.endpoint in {
                "api_mobile_login", "api_mobile_refresh",
                "api_passkey_authentication_options", "api_passkey_authentication_complete",
            }
            or
            request.path.startswith("/api/v1/monitoring/")
            or (request.path.startswith("/api/v1/") or request.path.startswith("/scim/v2/"))
            and getattr(g, "api_client", None)
        ):
            return None
        if not app.config["CSRF_ENABLED"] or request.method not in {
            "POST", "PUT", "PATCH", "DELETE",
        }:
            return None
        expected = session.get("_csrf_token")
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("_csrf_token")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            abort(400, description=(
                "The security token is missing or expired. Refresh the page and try again."
            ))
        return None

    @app.before_request
    def verify_session_version():
        if (
            current_user.is_authenticated
            and session.get("_auth_version") != current_user.auth_version
        ):
            logout_user()
            session.clear()
            if request.path.startswith("/api/"):
                abort(401, description="The authenticated session is no longer valid.")
            return redirect(url_for("login"))
        return None

    @app.after_request
    def inject_csrf(response):
        # Deliberately NOT gated on response.status_code < 400: a form that
        # re-renders itself with a 400/409 on validation failure (e.g.
        # render_form() rejecting a change inside a freeze window) needs a
        # working CSRF token in THAT error page too, since the user edits
        # and resubmits from it without a fresh page load. Excluding 4xx
        # here previously meant that exact retry got "security token is
        # missing" -- the token was fine, the error page just never got
        # one embedded. 3xx responses have no HTML body to inject into and
        # a fresh GET follows anyway, so they're skipped by the mimetype
        # check below on their own merits, not by a status-code gate.
        if (
            app.config["CSRF_ENABLED"]
            and response.mimetype == "text/html"
        ):
            body = response.get_data(as_text=True)
            token = csrf_token()
            hidden = f'<input type="hidden" name="_csrf_token" value="{token}">'
            body = re.sub(
                r'(<form\b[^>]*\bmethod=["\']post["\'][^>]*>)',
                rf"\1{hidden}", body, flags=re.IGNORECASE,
            )
            meta = f'<meta name="csrf-token" content="{token}">'
            if "</head>" in body:
                body = body.replace("</head>", f"{meta}</head>", 1)
            response.set_data(body)
            response.headers["Content-Length"] = str(len(response.get_data()))
        return response

    @app.after_request
    def log_request_completion(response):
        # Every request, not just errors -- this is what "very detailed
        # logs" actually needs: reconstructing the full sequence of what a
        # user/client did, not just the moments something broke. Goes to
        # the rotating JSON file (INFO) via the root logger, not the
        # DB-backed handler (WARNING+ only, to keep ApplicationLog to
        # actual problems worth an admin's attention).
        duration_ms = None
        started_at = g.get("_request_started_at")
        if started_at is not None:
            duration_ms = round((time_module.monotonic() - started_at) * 1000, 2)
            record_request_metric(request.method, response.status_code, duration_ms)
        logging.getLogger("serviceops.request").info(
            "%s %s -> %s", request.method, request.path, response.status_code,
            extra={
                "request_id": g.get("request_id"),
                "trace_id": g.get("trace_id"),
                "method": request.method,
                "path": request.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "user_id": current_user.id if current_user.is_authenticated else None,
                "tenant_id": current_user.tenant_id if current_user.is_authenticated else None,
                "remote_addr": request.remote_addr,
            },
        )
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def request_entity_too_large(error):
        max_mb = app.config.get("MAX_CONTENT_LENGTH", 20 * 1024 * 1024) // (1024 * 1024)
        message = f"That file is too large. The maximum upload size is {max_mb} MB."
        if request.path.startswith("/api/"):
            return jsonify({
                "error": {
                    "status": 413,
                    "title": "Payload Too Large",
                    "detail": message,
                    "request_id": g.get("request_id"),
                }
            }), 413
        flash(message, "error")
        destination = request.referrer
        if destination and destination.startswith(request.host_url):
            return redirect(destination)
        return redirect(url_for("dashboard"))

    @app.errorhandler(HTTPException)
    def http_error(error):
        if request.path.startswith("/api/"):
            return jsonify({
                "error": {
                    "status": error.code,
                    "title": error.name,
                    "detail": error.description,
                    "request_id": g.get("request_id"),
                }
            }), error.code
        return render_template(
            "error.html", code=error.code, message=error.description
        ), error.code

    @app.errorhandler(TenantResolutionError)
    def tenant_resolution_error(error):
        logout_user()
        if request.path.startswith("/api/"):
            return jsonify({
                "error": {
                    "status": 403,
                    "title": "Forbidden",
                    "detail": "Account has no tenant assignment.",
                    "request_id": g.get("request_id"),
                }
            }), 403
        return render_template(
            "error.html", code=403, message="Your account has no tenant assignment. Contact an administrator."
        ), 403

    @app.errorhandler(Exception)
    def unhandled_exception(error):
        # Flask/Werkzeug route error lookups by MRO specificity, so
        # HTTPException (including RequestEntityTooLarge/TenantResolutionError
        # above) is always dispatched to its own more-specific handler first
        # -- this only ever actually receives a genuine bug: something with
        # no handler of its own. "Every error must be recorded": the
        # DatabaseLogHandler attached to app.logger persists this to
        # ApplicationLog (visible on System Health) before anything else
        # happens, and a dirty/half-written transaction from whatever failed
        # is rolled back so the next request on this connection starts clean.
        app.logger.error(
            "Unhandled exception on %s %s", request.method, request.path, exc_info=error,
        )
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001 - never let cleanup mask the original error
            pass
        if request.path.startswith("/api/"):
            return jsonify({
                "error": {
                    "status": 500,
                    "title": "Internal Server Error",
                    "detail": "An unexpected error occurred. This has been logged.",
                    "request_id": g.get("request_id"),
                }
            }), 500
        return render_template(
            "error.html", code=500,
            message="An unexpected error occurred. This has been logged and an administrator can review it.",
        ), 500

    def nav_active(endpoint, **params):
        if request.endpoint != endpoint:
            return False
        return all(request.view_args.get(key) == value for key, value in params.items())

    @app.template_filter("usertime")
    def usertime_filter(value, fmt="%b %d, %H:%M"):
        if value is None:
            return ""
        tz_name = getattr(current_user, "timezone", None) if current_user.is_authenticated else None
        try:
            tz = ZoneInfo(tz_name) if tz_name else ZoneInfo("UTC")
        except (ZoneInfoNotFoundError, ValueError):
            tz = ZoneInfo("UTC")
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(tz).strftime(fmt)

    def user_avatar_html(user, css_class="avatar"):
        if user is None:
            return Markup(f'<div class="{escape(css_class)}" title="System">S</div>')
        if getattr(user, "avatar_path", None):
            return Markup(
                f'<img class="{escape(css_class)}" src="{escape(url_for("profile_avatar", user_id=user.id))}" '
                f'alt="{escape(user.name)}" title="{escape(user.name)}">'
            )
        initial = escape(user.name[0].upper()) if user.name else "?"
        return Markup(f'<div class="{escape(css_class)}" title="{escape(user.name)}">{initial}</div>')

    app.jinja_env.globals["user_avatar"] = user_avatar_html
    app.jinja_env.globals["PREVIEWABLE_ATTACHMENT_TYPES"] = PREVIEWABLE_ATTACHMENT_TYPES
    app.jinja_env.globals["IMAGE_ATTACHMENT_TYPES"] = IMAGE_ATTACHMENT_TYPES
    app.jinja_env.globals["now"] = now
    app.jinja_env.globals["all_roles"] = ALL_ROLES
    app.jinja_env.globals["role_at_least"] = role_at_least

    @app.context_processor
    def ui_context():
        platform_context = {
            "nav_active": nav_active,
            "instance_name": setting_value("INSTANCE_NAME", "ServiceOps"),
            "company_name": setting_value("COMPANY_NAME", "Your Company"),
            "brand_teal": setting_value("BRAND_TEAL", "#003e4c"),
            "brand_amber": setting_value("BRAND_AMBER", "#f9aa3c"),
            "support_email": setting_value("SUPPORT_EMAIL", ""),
            "has_company_logo": os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], "company-logo.png")),
            "test_fixture_active": setting_bool("TEST_FIXTURE_ACTIVE"),
            "app_version": APP_VERSION,
            "ldap_username_placeholder": ldap_username_placeholder(),
        }
        if not current_user.is_authenticated:
            return platform_context
        preference = UserPreference.query.filter_by(user_id=current_user.id).first()
        if not preference:
            # DEFAULT_DENSITY ("live": True, shown as configurable on
            # Platform Settings) used to have zero effect -- new
            # UserPreference rows always got "comfortable" from the
            # model column's own hardcoded default, never this setting.
            preference = UserPreference(
                user_id=current_user.id, density=setting_value("DEFAULT_DENSITY", "comfortable"),
            )
            db.session.add(preference)
            db.session.commit()
        favorites = Favorite.query.filter_by(user_id=current_user.id).order_by(Favorite.folder, Favorite.label).all()
        current_page_url = request.path + (f"?{request.query_string.decode()}" if request.query_string else "")
        return platform_context | {
            "ui_preference": preference,
            "ui_favorites": favorites,
            "current_user_is_local": user_is_local(current_user),
            "ui_history": RecentView.query.filter_by(user_id=current_user.id).order_by(RecentView.viewed_at.desc()).limit(12).all(),
            "current_page_url": current_page_url,
            "current_page_is_favorite": any(favorite.url == current_page_url for favorite in favorites),
            "unread_notifications": tenant_query(Notification).filter_by(
                user_id=current_user.id, read=False
            ).count(),
            "pending_approvals_count": ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
                ApprovalVote.approver_id == current_user.id,
                ApprovalVote.state == "Requested",
                ApprovalChain.tenant_id == current_user.tenant_id,
            ).count(),
            "my_open_tasks_count": (
                OperationalTask.query.filter(
                    OperationalTask.assignee_id == current_user.id,
                    OperationalTask.state.notin_(["Closed Complete", "Closed Incomplete", "Cancelled"]),
                ).count()
                + CatalogTask.query.filter(
                    CatalogTask.assignee_id == current_user.id,
                    CatalogTask.state.notin_(["Closed Complete", "Closed Incomplete", "Closed Skipped"]),
                ).count()
            ),
            "client_management_access": user_can_access_client_management(current_user),
            "client_open_ticket_count": (
                visible_client_ticket_query(current_user).filter(
                    ClientTicket.status.notin_(["Solved", "Closed"])
                ).count()
                if user_can_access_client_management(current_user) else 0
            ),
        }

    @app.get("/health")
    def health():
        # Found via real failure-injection testing (B-071): a DB outage
        # previously made this raise an unhandled OperationalError straight
        # into a generic 500, logged as an ERROR-level "Unhandled exception"
        # stack trace on every poll -- indistinguishable from a real bug and
        # noisy for the whole outage, since this is also the container
        # healthcheck target (see compose.yaml) polled on a short interval.
        # /ready already degrades gracefully on the same failure; this now
        # matches that pattern instead of letting Flask's default handler
        # treat a downstream outage as an application bug.
        try:
            db.session.execute(db.select(func.count(User.id))).scalar()
        except Exception:
            db.session.rollback()
            return jsonify(status="unhealthy", version=APP_VERSION), 503
        return jsonify(status="ok", version=APP_VERSION)

    @app.get("/live")
    def live():
        return jsonify(status="alive")

    @app.get("/ready")
    def ready():
        checks = {}
        try:
            db.session.execute(db.text("SELECT 1"))
            checks["database"] = {"ok": True}
        except Exception as error:  # readiness must report each failed prerequisite
            db.session.rollback()
            checks["database"] = {"ok": False, "reason": type(error).__name__}
        try:
            context = MigrationContext.configure(db.session.connection())
            current_heads = set(context.get_current_heads())
            config = AlembicConfig(str(Path(__file__).parent / "alembic.ini"))
            expected_heads = set(ScriptDirectory.from_config(config).get_heads())
            checks["migrations"] = {
                "ok": current_heads == expected_heads,
                "current": sorted(current_heads), "expected": sorted(expected_heads),
            }
        except Exception as error:
            checks["migrations"] = {"ok": False, "reason": type(error).__name__}
        try:
            tenants = Tenant.query.filter_by(active=True).all()
            for tenant in tenants:
                active_key = AuditIntegrityKey.query.filter_by(
                    tenant_id=tenant.id, active=True,
                ).order_by(AuditIntegrityKey.id.desc()).first()
                if active_key:
                    audit_integrity_key(active_key.key_id, tenant.id)
            checks["audit_encryption"] = {"ok": True, "tenants_checked": len(tenants)}
        except Exception as error:
            db.session.rollback()
            checks["audit_encryption"] = {"ok": False, "reason": type(error).__name__}
        heartbeat = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT") if checks["database"]["ok"] else None
        try:
            heartbeat_at = datetime.fromisoformat(heartbeat.value) if heartbeat and heartbeat.value else None
            heartbeat_age = (now() - align_tz(heartbeat_at, now())).total_seconds() if heartbeat_at else None
            checks["worker"] = {"ok": heartbeat_age is not None and heartbeat_age < 30, "age_seconds": heartbeat_age}
        except (TypeError, ValueError):
            checks["worker"] = {"ok": False, "reason": "invalid heartbeat"}
        upload_folder = app.config["UPLOAD_FOLDER"]
        checks["uploads"] = {
            "ok": os.path.isdir(upload_folder) and os.access(upload_folder, os.R_OK | os.W_OK),
            "path_configured": bool(upload_folder),
        }
        if object_storage_enabled():
            try:
                object_storage_client().head_bucket(Bucket=os.environ["OBJECT_STORAGE_BUCKET"])
                checks["object_storage"] = {"ok": True, "bucket_configured": True}
            except Exception as error:
                checks["object_storage"] = {"ok": False, "reason": type(error).__name__}
        if ipfs_enabled():
            try:
                current_storage().client.node_id()
                checks["ipfs"] = {"ok": True, "file_index_size": len(current_storage()._file_index)}
            except Exception as error:
                checks["ipfs"] = {"ok": False, "reason": type(error).__name__}
        overall = all(check["ok"] for check in checks.values())
        return jsonify(status="ready" if overall else "not_ready", version=APP_VERSION, checks=checks), 200 if overall else 503

    def _recovery_set_status():
        """Single source of truth for backup/RPO freshness -- read by both
        /metrics and system_health(), which previously computed this
        independently and could silently drift apart."""
        last_backup_row = db.session.get(PlatformSetting, "LAST_BACKUP_AT")
        last_backup_at = None
        if last_backup_row and last_backup_row.value:
            try:
                last_backup_at = datetime.fromisoformat(last_backup_row.value)
            except ValueError:
                pass
        backup_rpo_hours = setting_int("BACKUP_RPO_HOURS", int(os.getenv("BACKUP_RPO_HOURS", "24")))
        backup_age_seconds = -1
        if last_backup_at:
            backup_age_seconds = max(0, (now() - align_tz(last_backup_at, now())).total_seconds())
        backup_healthy = bool(
            last_backup_at is not None and backup_age_seconds <= backup_rpo_hours * 3600
        )
        return last_backup_at, backup_healthy, backup_rpo_hours, backup_age_seconds

    @app.get("/metrics")
    def prometheus_metrics():
        if not env_bool("METRICS_ENABLED", True):
            abort(404)
        configured_token = os.getenv("METRICS_TOKEN", "").strip()
        supplied_token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if configured_token and not hmac.compare_digest(configured_token, supplied_token):
            abort(401)
        heartbeat = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT")
        worker_up = 0
        if heartbeat and heartbeat.value:
            try:
                worker_up = int((now() - align_tz(datetime.fromisoformat(heartbeat.value), now())) < timedelta(seconds=30))
            except (TypeError, ValueError):
                pass
        error_hour = ApplicationLog.query.filter(
            ApplicationLog.level.in_(["ERROR", "CRITICAL"]),
            ApplicationLog.created_at >= now() - timedelta(hours=1),
        ).count()
        _, _, _, backup_age = _recovery_set_status()
        lines = [
            "# HELP serviceops_up Whether the application can query its database.",
            "# TYPE serviceops_up gauge", "serviceops_up 1",
            "# HELP serviceops_info Build information.", "# TYPE serviceops_info gauge",
            f'serviceops_info{{version="{APP_VERSION}"}} 1',
            "# HELP serviceops_worker_up Whether the worker heartbeat is fresh.",
            "# TYPE serviceops_worker_up gauge", f"serviceops_worker_up {worker_up}",
            "# HELP serviceops_application_errors_last_hour Error and critical records in the last hour.",
            "# TYPE serviceops_application_errors_last_hour gauge",
            f"serviceops_application_errors_last_hour {error_hour}",
            "# HELP serviceops_backup_age_seconds Age of the last successful recovery set, or -1 if none is recorded.",
            "# TYPE serviceops_backup_age_seconds gauge", f"serviceops_backup_age_seconds {backup_age:.0f}",
            "# HELP serviceops_process_uptime_seconds Process uptime.",
            "# TYPE serviceops_process_uptime_seconds gauge",
            f"serviceops_process_uptime_seconds {time_module.monotonic() - APP_START_MONOTONIC:.3f}",
        ]
        for row in RequestMetricTotal.query.order_by(
            RequestMetricTotal.method, RequestMetricTotal.status,
        ).all():
            lines.append(
                f'serviceops_http_requests_total{{method="{row.method}",status="{row.status}"}} '
                f'{row.request_count}'
            )
            lines.append(
                f'serviceops_http_request_duration_seconds_sum{{method="{row.method}",status="{row.status}"}} '
                f'{row.duration_sum_ms / 1000:.6f}'
            )
        return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

    @app.get("/manifest.webmanifest")
    def pwa_manifest():
        manifest = {
            "id": "/",
            "name": setting_value("INSTANCE_NAME", "ServiceOps"),
            "short_name": setting_value("INSTANCE_NAME", "ServiceOps")[:30],
            "description": "Enterprise service operations",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "background_color": "#f4f7f8",
            "theme_color": setting_value("BRAND_TEAL", "#003e4c"),
            "icons": [
                {"src": url_for("static", filename="icons/serviceops-icon-192.png"), "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
                {"src": url_for("static", filename="icons/serviceops-icon-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
            ],
        }
        response = jsonify(manifest)
        response.mimetype = "application/manifest+json"
        return response

    @app.get("/service-worker.js")
    def pwa_service_worker():
        response = send_from_directory(
            app.static_folder, "service-worker.js",
            mimetype="application/javascript", max_age=0,
        )
        response.headers["Service-Worker-Allowed"] = "/"
        return response

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
                            "assign, transition, and owning-team authority."
                        ),
                        "parameters": [{"$ref": "#/components/parameters/IdempotencyKey"}],
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
            abort(400, description="A JSON object is required.")
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        provider = str(body.get("provider", "local"))
        if provider not in {"local", "ldap"}:
            abort(400, description="provider must be local or ldap.")
        ip = request.remote_addr or "unknown"
        allowed = route_rate_limit("mobile_login", f"ip:{ip}", setting_int("LOGIN_RATE_LIMIT_PER_IP_PER_MINUTE", 20))
        if username:
            allowed = route_rate_limit("mobile_login", f"user:{username.lower()}", setting_int("LOGIN_RATE_LIMIT_PER_ACCOUNT_PER_MINUTE", 10)) and allowed
        db.session.commit()
        if not allowed:
            abort(429, description="Too many sign-in attempts. Try again later.")
        user = None
        candidate = User.query.filter_by(username=username).first()
        if candidate and candidate.locked_until and align_tz(candidate.locked_until, now()) > now():
            audit("login_blocked", candidate.username, "provider=mobile; reason=locked", user_id=candidate.id, tenant_id=candidate.tenant_id)
            db.session.commit()
            abort(423, description="This account is temporarily locked.")
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
            abort(401, description="Invalid username or password.")
        verified, backup_used = verify_mfa_code(user, body.get("mfa_code"))
        if not verified:
            audit("login_failed", user.username, "provider=mobile; reason=mfa_required_or_invalid", user_id=user.id, tenant_id=user.tenant_id)
            db.session.commit()
            abort(401, description="A valid MFA or backup code is required.")
        user.failed_login_count = 0
        user.locked_until = None
        access, refresh = issue_mobile_session(user, "password", backup_used)
        db.session.commit()
        return jsonify({"access_token": access, "refresh_token": refresh, "expires_in": 900,
                        "user": {"id": user.id, "username": user.username, "name": user.name}})

    @app.post("/api/v1/auth/passkeys/register/options")
    def api_passkey_registration_options():
        if g.api_client.client_kind != "mobile":
            abort(403, description="A mobile user session is required.")
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
            abort(403, description="A mobile user session is required.")
        body = request.get_json(silent=True) or {}
        challenge = consume_passkey_challenge(
            str(body.get("challenge_id") or body.get("challengeId") or ""), "registration",
        )
        if challenge.user_id != g.api_user.id or challenge.tenant_id != g.api_user.tenant_id:
            abort(403, description="The passkey challenge belongs to another identity.")
        challenge_bytes = challenge.challenge
        db.session.commit()  # Consume before cryptographic verification to prevent replay.
        rp_id, origin = passkey_configuration()
        try:
            verified = verify_passkey_registration(
                credential=body.get("credential") or {}, challenge=challenge_bytes,
                rp_id=rp_id, origin=origin,
            )
        except Exception:
            abort(400, description="Passkey registration verification failed.")
        if PasskeyCredential.query.filter_by(credential_id=verified.credential_id).first():
            abort(409, description="This passkey is already registered.")
        name = str(body.get("name") or "iPhone passkey").strip()[:120] or "iPhone passkey"
        transports = ((body.get("credential") or {}).get("response") or {}).get("transports") or []
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
            abort(403, description="A mobile user session is required.")
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
            abort(403, description="A mobile user session is required.")
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
        body = request.get_json(silent=True) or {}
        challenge = consume_passkey_challenge(
            str(body.get("challenge_id") or body.get("challengeId") or ""), "authentication",
        )
        credential = body.get("credential") or {}
        try:
            credential_id = base64url_to_bytes(str(credential.get("rawId") or credential.get("id") or ""))
        except Exception:
            abort(400, description="The passkey credential identifier is invalid.")
        stored = PasskeyCredential.query.filter_by(credential_id=credential_id).first()
        if not stored or not stored.user.active or stored.user.tenant_id != stored.tenant_id:
            abort(401, description="The passkey is not registered or its user is inactive.")
        challenge_bytes = challenge.challenge
        db.session.commit()  # Consume before cryptographic verification to prevent replay.
        rp_id, origin = passkey_configuration()
        try:
            verified = verify_passkey_authentication(
                credential=credential, challenge=challenge_bytes, rp_id=rp_id,
                origin=origin, stored=stored,
            )
        except Exception:
            abort(401, description="Passkey authentication failed.")
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
        body = request.get_json(silent=True) or {}
        raw = str(body.get("refresh_token", ""))
        digest = api_token_hash(raw) if raw.startswith("sor_") else ""
        row = APIClient.query.filter_by(refresh_token_hash=digest, client_kind="mobile", active=True).first()
        if not row or not hmac.compare_digest(row.refresh_token_hash or "", digest) or align_tz(row.refresh_expires_at, now()) <= now() or not row.acting_user.active:
            abort(401, description="The mobile refresh token is invalid, expired, or revoked.")
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
            abort(403, description="A mobile user session is required.")
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
        return render_template("api_docs.html", app_version=APP_VERSION)

    @app.post("/api/v1/monitoring/<source_id>/events")
    def monitoring_ingest(source_id):
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            abort(401, description="A monitoring bearer token is required.")
        token = authorization[7:].strip()
        source = MonitoringSource.query.filter_by(
            source_id=source_id, active=True
        ).first()
        token_hash = api_token_hash(token) if token else ""
        if (
            not source or not token_hash
            or not hmac.compare_digest(source.token_hash, token_hash)
        ):
            abort(401, description="The monitoring token is invalid or revoked.")
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description="A JSON object is required.")
        required = {"external_id", "severity", "resource", "summary"}
        if not required.issubset(body):
            abort(400, description=(
                "external_id, severity, resource and summary are required."
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
            abort(400, description="Monitoring event fields are invalid.")
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
        task = create_with_retry_on_number_collision(build_task)
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

    @app.get("/api/v1/tickets")
    def api_tickets():
        require_api_scope("tickets:read")
        user = g.api_user
        query = visible_ticket_query(user)
        kind = request.args.get("type", "").strip()
        state = request.args.get("state", "").strip()
        if kind:
            if kind not in ("incident", "change"):
                abort(400, description="type must be incident or change.")
            query = query.filter(Ticket.kind == kind)
        if state:
            query = query.filter(Ticket.state == state)
        try:
            limit = min(max(int(request.args.get("limit", "50")), 1), 100)
            cursor = int(request.args.get("cursor", "0"))
        except ValueError:
            abort(400, description="limit and cursor must be integers.")
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
            abort(404, description="The requested ticket was not found.")
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
            abort(403, description="The acting user cannot create records.")
        key, request_hash, replay = api_idempotency_context()
        if replay:
            return replay
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description="A JSON object is required.")
        allowed = {"title", "description", "category", "priority", "assignment_group_id"}
        unknown = set(body) - allowed
        if unknown:
            abort(400, description=f"Unknown fields: {', '.join(sorted(unknown))}.")
        title = str(body.get("title", "")).strip()
        description = str(body.get("description", "")).strip()
        priority = str(body.get("priority", "P3"))
        if not title or len(title) > 180 or not description:
            abort(400, description="title and description are required.")
        if priority not in ("P1", "P2", "P3", "P4"):
            abort(400, description="priority must be P1, P2, P3 or P4.")
        try:
            group_id = int(body.get("assignment_group_id"))
        except (TypeError, ValueError):
            abort(400, description="assignment_group_id is required.")
        group = SupportGroup.query.filter_by(
            id=group_id, tenant_id=g.api_client.tenant_id,
            active=True, group_type="IT Fulfillment",
        ).first()
        if not group:
            abort(400, description="Select an active tenant IT fulfillment team.")
        ticket = create_ticket_with_unique_number(
            "incident",
            title=title, description=description,
            category=str(body.get("category", "General"))[:80],
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
                abort(403, description=f"The acting user cannot perform {action}.")
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first()
        if not ticket:
            abort(404, description="The requested ticket was not found.")
        if not user_can_manage_ticket(g.api_user, ticket):
            abort(403, description="The acting user cannot manage this ticket.")
        key, request_hash, replay = api_idempotency_context()
        if replay:
            return replay
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not body:
            abort(400, description="A non-empty JSON object is required.")
        allowed = {"state", "priority", "assigned_to_id"}
        unknown = set(body) - allowed
        if unknown:
            abort(400, description=f"Unknown fields: {', '.join(sorted(unknown))}.")
        before = {
            "state": ticket.state, "priority": ticket.priority,
            "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned",
        }
        if "state" in body:
            transition_ticket(ticket, str(body["state"]))
        if "priority" in body:
            priority = str(body["priority"])
            if priority not in ("P1", "P2", "P3", "P4"):
                abort(400, description="priority must be P1, P2, P3 or P4.")
            ticket.priority = priority
        if "assigned_to_id" in body:
            assignee_id = body["assigned_to_id"]
            if assignee_id is not None:
                try:
                    assignee_id = int(assignee_id)
                except (TypeError, ValueError):
                    abort(400, description="assigned_to_id must be an integer or null.")
                eligible_ids = {agent.id for agent in ticket_team_agents(ticket)}
                if assignee_id not in eligible_ids:
                    abort(400, description="The assignee must belong to the owning team.")
            ticket.assignee_id = assignee_id
        log_field_changes("ticket", ticket.id, before, {
            "state": ticket.state, "priority": ticket.priority,
            "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned",
        }, event="REST API update")
        document = {"data": api_ticket_document(ticket, g.api_user)}
        store_api_idempotency(key, request_hash, document, 200)
        audit(
            "api update", ticket.number, mobile_client_details(g.api_client),
            user_id=g.api_user.id, tenant_id=g.api_client.tenant_id,
        )
        db.session.commit()
        return jsonify(document)

    @app.put("/api/v1/cmdb/configuration-items")
    def api_ci_upsert():
        require_api_scope("cmdb:write")
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description="A JSON object is required.")
        allowed = {"name", "ci_class", "environment", "operational_status", "ip_address"}
        unknown = set(body) - allowed
        if unknown:
            abort(400, description=f"Unknown fields: {', '.join(sorted(unknown))}.")
        name = str(body.get("name", "")).strip()[:160]
        if not name:
            abort(400, description="name is required.")
        environment = normalize_environment(str(body.get("environment", "Production")))
        if environment not in CANONICAL_ENVIRONMENTS:
            abort(400, description="environment must be Production, Staging, Development or Test.")
        operational_status = str(body.get("operational_status", "Operational"))
        if operational_status not in ("Operational", "Degraded", "Down", "Maintenance", "Retired"):
            abort(400, description="operational_status must be a recognized CI status.")
        ci_class = str(body.get("ci_class", "Server")).strip()[:80] or "Server"
        ip_address = str(body.get("ip_address", "")).strip()[:60] or None
        ci = ConfigurationItem.query.filter_by(name=name, tenant_id=g.api_client.tenant_id).first()
        created = ci is None
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
            abort(403, description="The acting user cannot execute workflows.")
        ticket = visible_ticket_query(g.api_user).filter(
            func.upper(Ticket.number) == number.upper()
        ).first()
        if not ticket:
            abort(404, description="The requested ticket was not found.")
        if not user_can_manage_ticket(g.api_user, ticket):
            abort(403, description="The acting user cannot manage this ticket.")
        key, request_hash, replay = api_idempotency_context()
        if replay:
            return replay
        body = request.get_json(silent=True)
        if body not in ({}, None) and not isinstance(body, dict):
            abort(400, description="A JSON object is required.")
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

    def mobile_only():
        if g.api_client.client_kind != "mobile":
            abort(403, description="A mobile user session is required.")

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
        pending = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
            ApprovalVote.approver_id == g.api_user.id,
            ApprovalVote.state == "Requested",
            ApprovalChain.tenant_id == g.api_user.tenant_id,
        ).count()
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
        body = request.get_json(silent=True) or {}
        token = str(body.get("token", "")).strip().lower()
        device_id = str(body.get("device_id", "")).strip()
        environment = str(body.get("environment", "sandbox"))
        if not re.fullmatch(r"[0-9a-f]{64,200}", token):
            abort(400, description="A valid APNs device token is required.")
        if not device_id or len(device_id) > 64 or environment not in {"sandbox", "production"}:
            abort(400, description="A valid device_id and APNs environment are required.")
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
        rows = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
            ApprovalVote.approver_id == g.api_user.id,
            ApprovalChain.tenant_id == g.api_user.tenant_id,
        ).order_by(ApprovalVote.id.desc()).limit(100).all()
        return jsonify({"data": [{
            "id": row.id, "state": row.state, "comments": row.comments or "",
            "gate": row.gate.name, "chain": row.gate.chain.name,
            "target_type": row.gate.chain.target_type, "target_id": row.gate.chain.target_id,
        } for row in rows]})

    @app.post("/api/v1/mobile/approvals/<int:vote_id>/decide")
    def api_mobile_approval_decide(vote_id):
        mobile_only()
        body = request.get_json(silent=True) or {}
        decision = body.get("decision")
        if decision not in ("Approved", "Rejected"):
            abort(400, description="decision must be Approved or Rejected.")
        vote = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
            ApprovalVote.id == vote_id, ApprovalVote.approver_id == g.api_user.id,
            ApprovalChain.tenant_id == g.api_user.tenant_id,
        ).first_or_404()
        decide_vote(vote, decision, str(body.get("comments", "")).strip()[:2000])
        audit("mobile approval " + decision.lower(), vote.gate.chain.name,
              mobile_client_details(g.api_client), user_id=g.api_user.id, tenant_id=g.api_user.tenant_id)
        db.session.commit()
        return jsonify({"data": {"id": vote.id, "state": vote.state}})

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
            abort(403, description="CMDB mobile access requires the agent role.")
        q = str(request.args.get("q", "")).strip()
        query = ConfigurationItem.query.filter_by(tenant_id=g.api_user.tenant_id)
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
                                  "created_at": row.created_at.isoformat()} for row in ticket.comments]})

    @app.post("/api/v1/tickets/<number>/comments")
    def api_ticket_comment_create(number):
        require_api_scope("tickets:update")
        ticket = visible_ticket_query(g.api_user).filter(func.upper(Ticket.number) == number.upper()).first_or_404()
        if not user_can_manage_ticket(g.api_user, ticket):
            abort(403, description="The acting user cannot comment on this ticket.")
        body = str((request.get_json(silent=True) or {}).get("body", "")).strip()
        if not body or len(body) > 10000:
            abort(400, description="A comment between 1 and 10000 characters is required.")
        row = Comment(ticket_id=ticket.id, user_id=g.api_user.id, body=body, tenant_id=ticket.tenant_id)
        db.session.add(row)
        log_history("ticket", ticket.id, "Comment added", details=f"Mobile app · {g.api_user.name}")
        audit("mobile comment", ticket.number, mobile_client_details(g.api_client),
              user_id=g.api_user.id, tenant_id=g.api_user.tenant_id)
        db.session.commit()
        return jsonify({"data": {"id": row.id, "body": row.body, "author": g.api_user.name,
                                  "created_at": row.created_at.isoformat()}}), 201

    def scim_user_document(user):
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": str(user.id), "externalId": user.employee_id,
            "userName": user.username, "displayName": user.name,
            "active": user.active,
            "emails": [{"value": user.email, "primary": True}],
            "meta": {"resourceType": "User", "created": user.created_at.isoformat(),
                     "location": url_for("scim_user", user_id=user.id, _external=True)},
        }

    def require_scim_admin():
        require_api_scope("users:provision")
        if not effective_role_has_action(g.api_user.role, "security_administer", tenant_id=g.api_user.tenant_id):
            abort(403, description="The SCIM client must act as a security administrator.")

    @app.route("/scim/v2/Users", methods=["GET", "POST"])
    def scim_users():
        require_scim_admin()
        if request.method == "GET":
            query = User.query.filter_by(tenant_id=g.api_client.tenant_id)
            filter_value = request.args.get("filter", "")
            match = re.fullmatch(r'userName\s+eq\s+"([^"]+)"', filter_value, re.IGNORECASE)
            if filter_value and not match:
                abort(400, description="Only the SCIM filter userName eq \"value\" is supported.")
            if match:
                query = query.filter(func.lower(User.username) == match.group(1).lower())
            rows = query.order_by(User.id).all()
            return jsonify(schemas=["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                           totalResults=len(rows), startIndex=1,
                           itemsPerPage=len(rows), Resources=[scim_user_document(user) for user in rows])
        body = request.get_json(silent=True) or {}
        username = str(body.get("userName", "")).strip()[:80]
        emails = body.get("emails") if isinstance(body.get("emails"), list) else []
        email = str(next((item.get("value") for item in emails if isinstance(item, dict) and item.get("value")), "")).strip()[:160]
        name = str(body.get("displayName") or username).strip()[:120]
        if not username or not email:
            abort(400, description="userName and an email value are required.")
        if User.query.filter(db.or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email.lower())).first():
            abort(409, description="A user with that username or email already exists.")
        user = User(
            username=username, email=email, name=name, active=bool(body.get("active", True)),
            employee_id=str(body.get("externalId", ""))[:80] or None,
            role="requester", tenant_id=g.api_client.tenant_id,
            password_hash=hash_password(secrets.token_urlsafe(48)),
        )
        db.session.add(user)
        db.session.flush()
        db.session.add(UserRoleGrant(user_id=user.id, role="requester"))
        db.session.add(ExternalIdentity(provider="scim", subject=str(body.get("externalId") or username), user_id=user.id))
        audit("scim create", user.username, f"client={g.api_client.client_id}",
              user_id=g.api_user.id, tenant_id=user.tenant_id)
        db.session.commit()
        return jsonify(scim_user_document(user)), 201

    @app.route("/scim/v2/Users/<int:user_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
    def scim_user(user_id):
        require_scim_admin()
        user = User.query.filter_by(id=user_id, tenant_id=g.api_client.tenant_id).first_or_404()
        if request.method == "GET":
            return jsonify(scim_user_document(user))
        if request.method == "DELETE":
            user.active = False
        else:
            body = request.get_json(silent=True) or {}
            if request.method == "PATCH":
                for operation in body.get("Operations", []):
                    if str(operation.get("op", "")).lower() not in {"add", "replace"}:
                        continue
                    path, value = operation.get("path"), operation.get("value")
                    if path == "active":
                        user.active = bool(value)
                    elif path == "displayName":
                        user.name = str(value).strip()[:120]
            else:
                user.name = str(body.get("displayName") or user.name).strip()[:120]
                user.active = bool(body.get("active", user.active))
                emails = body.get("emails") if isinstance(body.get("emails"), list) else []
                email = next((item.get("value") for item in emails if isinstance(item, dict) and item.get("value")), None)
                if email:
                    user.email = str(email).strip()[:160]
        if not user.active:
            user.auth_version += 1
            UserSession.query.filter_by(user_id=user.id, revoked_at=None).update(
                {"revoked_at": now(), "revoked_by_id": g.api_user.id}
            )
        audit("scim update", user.username, f"active={user.active}; client={g.api_client.client_id}",
              user_id=g.api_user.id, tenant_id=user.tenant_id)
        db.session.commit()
        return ("", 204) if request.method == "DELETE" else jsonify(scim_user_document(user))

    @app.after_request
    def security_headers(response):
        response.headers["X-Request-ID"] = g.get("request_id", str(uuid.uuid4()))
        response.headers["traceparent"] = f"00-{g.get('trace_id', secrets.token_hex(16))}-{secrets.token_hex(8)}-01"
        if g.get("rate_limit_retry_after") is not None:
            response.headers["Retry-After"] = str(g.rate_limit_retry_after)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        if setting_bool("ENABLE_HSTS"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
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
            # Persist the counter increment even when the request is within
            # limits -- otherwise it's only ever committed on the request
            # that trips the 429, and every allowed request's contribution
            # to the window is silently lost.
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
            if lockout_record and lockout_record.locked_until and lockout_record.locked_until > now():
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
            if user and user.active and user.mfa_enabled:
                # Password verified but MFA is required (ISO 27001 A.8.5):
                # do not issue a session yet. Stash the authenticated-but-
                # not-yet-MFA'd user id in a short-lived, server-signed
                # session value; /login/mfa completes the login only after a
                # valid TOTP code or backup code is presented.
                user.failed_login_count = 0
                user.locked_until = None
                db.session.commit()
                session["_mfa_pending_user_id"] = user.id
                session["_mfa_pending_provider"] = provider
                return redirect(url_for("login_mfa"))
            if user and user.active:
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
        user = User.query.get(pending_user_id)
        if not user or not user.active or not user.mfa_enabled:
            session.pop("_mfa_pending_user_id", None)
            session.pop("_mfa_pending_provider", None)
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
            keycloak_attr_map = json.loads(setting_value("KEYCLOAK_ATTR_MAP", "{}"))
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

    @app.route("/profile/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if not user_is_local(current_user):
            abort(403, description="Your password is managed by your organization's login provider, not ServiceOps.")
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirmation = request.form.get("confirm_password", "")
            if not verify_password(current_user.password_hash, current_password):
                abort(400, description="The current password is incorrect.")
            min_length = setting_int("PASSWORD_MIN_LENGTH", 14)
            if len(new_password) < min_length:
                abort(400, description=f"The new password must contain at least {min_length} characters.")
            if new_password != confirmation:
                abort(400, description="The password confirmation does not match.")
            if verify_password(current_user.password_hash, new_password):
                abort(400, description="The new password must differ from the current password.")
            current_user.password_hash = hash_password(new_password)
            current_user.auth_version += 1
            session["_auth_version"] = current_user.auth_version
            audit("credential rotate", current_user.username, "Local password changed")
            db.session.commit()
            flash("Password changed. Other browser sessions have been invalidated.", "success")
            return redirect(url_for("preferences"))
        return render_template("change_password.html")

    @app.route("/settings/mfa", methods=["GET", "POST"])
    @login_required
    def settings_mfa():
        """TOTP MFA enrollment/management (ISO 27001 A.8.5). GET shows
        status and, when not yet enrolled, a freshly generated (not-yet-
        persisted) secret's otpauth:// provisioning URI for the user to add
        to an authenticator app -- rendering an actual QR image client-side
        from that URI is a template concern, not a security one; the URI
        alone is sufficient provisioning data. The secret is only persisted
        (Fernet-encrypted, matching the existing settings_cipher() pattern
        used for other secrets) once the user proves possession by
        submitting a valid code, so an enrollment abandoned mid-flow never
        leaves a live-but-unverified secret on the account."""
        if request.method == "POST":
            action = request.form.get("action", "enable")
            if action == "disable":
                if not verify_password(current_user.password_hash, request.form.get("password", "")):
                    abort(400, description="Your current password is required to disable MFA.")
                if user_requires_mfa_by_policy(current_user):
                    abort(400, description="MFA is required for your role by administrator policy and cannot be disabled.")
                current_user.mfa_enabled = False
                current_user.mfa_secret_encrypted = None
                current_user.mfa_backup_codes_json = None
                current_user.mfa_enrolled_at = None
                audit("mfa disable", current_user.username)
                db.session.commit()
                session.pop("_mfa_pending_secret", None)
                flash("MFA has been disabled for your account.", "success")
                return redirect(url_for("settings_mfa"))
            if action == "regenerate_backup_codes":
                if not current_user.mfa_enabled:
                    abort(400, description="Enable MFA before generating backup codes.")
                codes = generate_mfa_backup_codes()
                current_user.mfa_backup_codes_json = json.dumps([hash_backup_code(c) for c in codes])
                audit("mfa backup codes regenerate", current_user.username)
                db.session.commit()
                flash("New backup codes generated. Save them now -- they will not be shown again.", "success")
                return render_template("settings_mfa.html", enrolled=True, backup_codes=codes,
                                       mfa_required=user_requires_mfa_by_policy(current_user))
            # action == "enable": confirm possession of the pending secret.
            pending_secret = session.get("_mfa_pending_secret")
            code = request.form.get("code", "").strip()
            if not pending_secret or not code or not pyotp.TOTP(pending_secret).verify(code, valid_window=1):
                flash("Invalid verification code. Scan the QR code again and try once more.", "error")
                return redirect(url_for("settings_mfa"))
            current_user.mfa_secret_encrypted = settings_cipher().encrypt(pending_secret.encode()).decode()
            current_user.mfa_enabled = True
            current_user.mfa_enrolled_at = now()
            backup_codes = generate_mfa_backup_codes()
            current_user.mfa_backup_codes_json = json.dumps([hash_backup_code(c) for c in backup_codes])
            current_user.auth_version += 1
            session["_auth_version"] = current_user.auth_version
            audit("mfa enroll", current_user.username)
            db.session.commit()
            session.pop("_mfa_pending_secret", None)
            flash("MFA is now enabled. Save your backup codes -- they will not be shown again.", "success")
            return render_template("settings_mfa.html", enrolled=True, backup_codes=backup_codes,
                                   mfa_required=user_requires_mfa_by_policy(current_user))
        if current_user.mfa_enabled:
            return render_template("settings_mfa.html", enrolled=True, backup_codes=None,
                                   mfa_required=user_requires_mfa_by_policy(current_user))
        secret = pyotp.random_base32()
        session["_mfa_pending_secret"] = secret
        provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
            name=current_user.username, issuer_name="ServiceOps"
        )
        return render_template(
            "settings_mfa.html", enrolled=False, backup_codes=None,
            provisioning_uri=provisioning_uri, secret=secret,
            mfa_required=user_requires_mfa_by_policy(current_user),
        )

    @app.get("/work/open")
    @login_required
    def open_work():
        priority = request.args.get("priority", "").strip()
        ticket_query = visible_ticket_query(current_user)
        open_ticket_query = ticket_query.filter(
            Ticket.state.notin_(["Resolved", "Closed", "Cancelled"])
        )
        if priority:
            open_ticket_query = open_ticket_query.filter_by(priority=priority)
        # Capped to keep this route bounded for tenants with a large open-work
        # backlog; use /tickets/<kind> with pagination and filters to see the
        # rest.
        open_work_limit = 200
        open_tickets = open_ticket_query.order_by(
            Ticket.priority, Ticket.updated_at.desc()
        ).limit(open_work_limit + 1).all()
        open_tickets_truncated = len(open_tickets) > open_work_limit
        open_tickets = open_tickets[:open_work_limit]
        open_requests = visible_catalog_request_query(current_user).filter(
            CatalogRequest.state.notin_(["Closed Complete", "Closed Incomplete", "Cancelled"])
        ).order_by(CatalogRequest.opened_at.desc()).limit(open_work_limit + 1).all()
        open_requests_truncated = len(open_requests) > open_work_limit
        open_requests = open_requests[:open_work_limit]
        if priority:
            open_requests = []
            open_requests_truncated = False
        return render_template(
            "open_work.html", open_tickets=open_tickets, open_requests=open_requests, priority=priority,
            open_tickets_truncated=open_tickets_truncated, open_requests_truncated=open_requests_truncated,
        )

    @app.get("/work/open/export.csv")
    @login_required
    def open_work_export():
        priority = request.args.get("priority", "").strip()
        open_ticket_query = visible_ticket_query(current_user).filter(
            Ticket.state.notin_(["Resolved", "Closed", "Cancelled"])
        )
        if priority:
            open_ticket_query = open_ticket_query.filter_by(priority=priority)
        export_limit = 5000
        tickets_rows = open_ticket_query.order_by(
            Ticket.priority, Ticket.updated_at.desc()
        ).limit(export_limit).all()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Type", "Number", "Title", "State", "Priority", "Assignee", "Updated"])
        for ticket in tickets_rows:
            writer.writerow([
                ticket.kind.capitalize(), ticket.number, ticket.title, ticket.state, ticket.priority,
                ticket.assignee.name if ticket.assignee else "Unassigned",
                usertime_filter(ticket.updated_at, "%Y-%m-%d %H:%M"),
            ])
        if not priority:
            for req in visible_catalog_request_query(current_user).filter(
                CatalogRequest.state.notin_(["Closed Complete", "Closed Incomplete", "Cancelled"])
            ).order_by(CatalogRequest.opened_at.desc()).limit(export_limit).all():
                writer.writerow([
                    "Request", req.number, f"Request for {req.requested_for.name}", req.state, "",
                    req.requested_by.name if req.requested_by else "", usertime_filter(req.opened_at, "%Y-%m-%d %H:%M"),
                ])
        return csv_response(buffer.getvalue(), "open-work.csv")

    @app.get("/")
    @login_required
    def dashboard():
        visible_requests = visible_catalog_request_query(current_user)
        ticket_query = visible_ticket_query(current_user)
        terminal_states = ("Resolved", "Closed", "Cancelled")
        # A single (kind, priority, state) fetch replaces what used to be five
        # separate COUNT() round trips (incident/change/open/P1/P2) on the
        # single highest-traffic page in the app; only three narrow columns
        # are pulled, and the aggregation happens in Python instead of SQL.
        ticket_rows = ticket_query.with_entities(Ticket.kind, Ticket.priority, Ticket.state).all()
        counts = {"incident": 0, "change": 0, "request": visible_requests.count()}
        open_count = 0
        incident_priority_counts = {"p1": 0, "p2": 0}
        for kind, priority, state in ticket_rows:
            if kind in counts:
                counts[kind] += 1
            if state not in terminal_states:
                open_count += 1
                if kind == "incident" and priority in ("P1", "P2"):
                    incident_priority_counts[priority.lower()] += 1
        open_ticket_query = ticket_query.filter(Ticket.state.notin_(terminal_states))
        open_count += visible_requests.filter(
            CatalogRequest.state.notin_(["Closed Complete", "Closed Incomplete", "Cancelled"])
        ).count()
        show_recent = setting_bool("DASHBOARD_SHOW_RECENT", True)
        show_my_assigned = setting_bool("DASHBOARD_SHOW_MY_ASSIGNED", True)
        show_sla_widgets = setting_bool("DASHBOARD_SHOW_SLA_WIDGETS", True)
        recent = (
            visible_tickets().filter(Ticket.deleted_at.is_(None)).order_by(Ticket.updated_at.desc()).limit(8).all()
            if show_recent else []
        )
        my_assigned = (
            open_ticket_query.filter(Ticket.assignee_id == current_user.id)
            .order_by(Ticket.priority, Ticket.updated_at.desc()).limit(8).all()
            if show_my_assigned else []
        )
        sla_at_risk_hours = setting_int("SLA_AT_RISK_HOURS", 4)
        sla_breached, sla_at_risk, sla_tickets = [], [], {}
        if show_sla_widgets:
            open_ticket_ids = [row[0] for row in open_ticket_query.with_entities(Ticket.id).all()]
            sla_rows = []
            if open_ticket_ids:
                sla_rows = TaskSLA.query.filter(
                    TaskSLA.target_type == "ticket",
                    TaskSLA.target_id.in_(open_ticket_ids),
                    TaskSLA.stage == "In Progress",
                ).order_by(TaskSLA.breach_at).all()
            if sla_rows:
                sla_tickets = {
                    ticket.id: ticket
                    for ticket in Ticket.query.filter(
                        Ticket.id.in_({row.target_id for row in sla_rows})
                    ).all()
                }
            breach_horizon = now() + timedelta(hours=sla_at_risk_hours)
            sla_breached = [row for row in sla_rows if row.breached][:8]
            sla_at_risk = [
                row for row in sla_rows
                if not row.breached
                and (row.breach_at if row.breach_at.tzinfo else row.breach_at.replace(tzinfo=timezone.utc))
                <= breach_horizon
            ][:8]
        return render_template(
            "dashboard.html", counts=counts, open_count=open_count, recent=recent,
            show_recent=show_recent, show_my_assigned=show_my_assigned, show_sla_widgets=show_sla_widgets,
            sla_at_risk_hours=sla_at_risk_hours,
            my_assigned=my_assigned, incident_priority_counts=incident_priority_counts,
            sla_breached=sla_breached, sla_at_risk=sla_at_risk, sla_tickets=sla_tickets,
        )

    @app.route("/workspace", methods=["GET", "POST"])
    @login_required
    def my_workspace():
        """B-121: a user's personal, configurable landing page -- widgets
        picked from WORKSPACE_WIDGET_REGISTRY's closed catalog, arranged in
        a simple ordered list with a 1- or 2-column span each. Distinct
        from /dashboard (the fixed, admin-configured default), which is
        untouched by this feature."""
        layout_row = UserWorkspaceLayout.query.filter_by(user_id=current_user.id).one_or_none()
        if request.method == "POST":
            action = request.form.get("action", "save")
            if action == "save":
                new_layout = []
                for widget_key in request.form.getlist("widget_key"):
                    if widget_key not in WORKSPACE_WIDGET_REGISTRY:
                        continue
                    span = 2 if request.form.get(f"span_{widget_key}") == "2" else 1
                    new_layout.append({"widget_key": widget_key, "span": span})
                if not layout_row:
                    layout_row = UserWorkspaceLayout(
                        tenant_id=current_user.tenant_id, user_id=current_user.id, layout_json=new_layout,
                    )
                    db.session.add(layout_row)
                else:
                    layout_row.layout_json = new_layout
                db.session.commit()
                flash("Workspace layout saved.", "success")
            elif action == "reset":
                if layout_row:
                    db.session.delete(layout_row)
                    db.session.commit()
                flash("Workspace reset to the default widget set.", "success")
            return redirect(url_for("my_workspace"))

        available = {
            key: entry for key, entry in WORKSPACE_WIDGET_REGISTRY.items()
            if workspace_widget_enabled(key)
        }
        if layout_row and layout_row.layout_json:
            selected = [
                item for item in layout_row.layout_json
                if isinstance(item, dict) and item.get("widget_key") in available
            ]
        else:
            # No saved layout yet -- a reasonable default so /workspace
            # isn't a blank page on first visit, not auto-seeded data.
            selected = [
                {"widget_key": key, "span": entry["default_span"]}
                for key, entry in available.items()
                if key in ("ticket_stats", "my_open_tickets", "recent_tickets")
            ]
        widgets = []
        for item in selected:
            key = item["widget_key"]
            context = available[key]["data"](current_user)
            widgets.append({
                "key": key, "label": available[key]["label"], "span": item.get("span", 1),
                "context": context,
            })
        return render_template(
            "my_workspace.html", widgets=widgets, available=available,
            selected_keys={item["widget_key"] for item in selected},
            selected_spans={item["widget_key"]: item.get("span", 1) for item in selected},
        )

    def visible_tickets():
        return visible_ticket_query(current_user)

    TICKET_STATE_OPTIONS = ["New", "In Progress", "Pending", "Resolved", "Closed", "Cancelled"]

    def ticket_filter_field_spec():
        return {
            "number": {"label": "Number", "type": "text", "column": Ticket.number},
            "title": {"label": "Short description", "type": "text", "column": Ticket.title},
            "priority": {"label": "Priority", "type": "choice", "column": Ticket.priority,
                        "options": [(p, p) for p in ["P1", "P2", "P3", "P4"]]},
            "state": {"label": "State", "type": "choice", "column": Ticket.state,
                      "options": [(s, s) for s in TICKET_STATE_OPTIONS]},
            "category": {"label": "Category", "type": "choice", "column": Ticket.category,
                        "options": [(c, c) for c in TICKET_CATEGORY_OPTIONS]},
            "opened": {"label": "Opened", "type": "date", "column": Ticket.created_at},
            "updated": {"label": "Updated", "type": "date", "column": Ticket.updated_at},
        }

    def ticket_group_filter_handler(kind):
        """Assignment group lives on TicketAssignmentGroup (incidents) or
        ChangeOwnership (changes), not a plain Ticket column, so it needs a
        subquery instead of the generic column-based filter path."""
        link_model = ChangeOwnership if kind == "change" else TicketAssignmentGroup

        def handler(query, op, value):
            if op == "eq" and value:
                try:
                    group_id_value = int(value)
                except ValueError:
                    return query
                return query.filter(Ticket.id.in_(
                    db.session.query(link_model.ticket_id).filter(link_model.group_id == group_id_value)
                ))
            if op == "ne" and value:
                try:
                    group_id_value = int(value)
                except ValueError:
                    return query
                return query.filter(~Ticket.id.in_(
                    db.session.query(link_model.ticket_id).filter(link_model.group_id == group_id_value)
                ))
            if op == "is_empty":
                return query.filter(~Ticket.id.in_(db.session.query(link_model.ticket_id)))
            if op == "is_not_empty":
                return query.filter(Ticket.id.in_(db.session.query(link_model.ticket_id)))
            return query
        return handler

    def ticket_list_query(kind, q="", conditions=None):
        """Shared filtering for the ticket list view and its CSV export, so
        both stay consistent: free-text search plus the generic filter
        condition list (see apply_filter_conditions)."""
        query = visible_tickets().filter_by(kind=kind).filter(Ticket.deleted_at.is_(None))
        if q:
            query = query.filter(db.or_(Ticket.number.ilike(f"%{q}%"), Ticket.title.ilike(f"%{q}%")))
        query = apply_filter_conditions(
            query, conditions or [], ticket_filter_field_spec(),
            extra_handlers={"group": ticket_group_filter_handler(kind)},
        )
        return query

    TERMINAL_TICKET_STATES = ["Resolved", "Closed", "Cancelled"]
    TERMINAL_TASK_STATES = ["Closed Complete", "Closed Incomplete", "Closed Skipped", "Cancelled"]

    def manager_portal_groups():
        if role_at_least(current_user.effective_role, "admin"):
            return tenant_query(SupportGroup).filter(
                SupportGroup.group_type == "IT Fulfillment",
                SupportGroup.active.is_(True),
            ).order_by(SupportGroup.name).all()
        return tenant_query(SupportGroup).filter(
            SupportGroup.group_type == "IT Fulfillment",
            SupportGroup.active.is_(True),
            SupportGroup.manager_id == current_user.id,
        ).order_by(SupportGroup.name).all()

    def manager_portal_context():
        """Team and per-member workload/SLA snapshot for the manager portal,
        shared by the HTML view and the CSV export so both stay consistent."""
        groups = manager_portal_groups()
        group_ids = [group.id for group in groups]
        memberships = GroupMember.query.filter(
            GroupMember.group_id.in_(group_ids)
        ).options(db.joinedload(GroupMember.user)).all() if group_ids else []
        member_ids = sorted({m.user_id for m in memberships})

        open_ticket_rows = Ticket.query.filter(
            Ticket.assignee_id.in_(member_ids),
            Ticket.state.notin_(TERMINAL_TICKET_STATES),
        ).with_entities(Ticket.id, Ticket.assignee_id, Ticket.kind).all() if member_ids else []
        open_ticket_ids_by_member = defaultdict(list)
        open_incidents_by_member = Counter()
        open_changes_by_member = Counter()
        for ticket_id, assignee_id, kind in open_ticket_rows:
            open_ticket_ids_by_member[assignee_id].append(ticket_id)
            if kind == "incident":
                open_incidents_by_member[assignee_id] += 1
            elif kind == "change":
                open_changes_by_member[assignee_id] += 1

        thirty_days_ago = now() - timedelta(days=30)
        resolved_30d_by_member = Counter()
        if member_ids:
            for assignee_id, count in db.session.query(
                Ticket.assignee_id, func.count(Ticket.id)
            ).filter(
                Ticket.assignee_id.in_(member_ids),
                Ticket.state.in_(TERMINAL_TICKET_STATES),
                Ticket.updated_at >= thirty_days_ago,
            ).group_by(Ticket.assignee_id).all():
                resolved_30d_by_member[assignee_id] = count

        open_tasks_by_member = Counter()
        if member_ids:
            for model in (OperationalTask, CatalogTask):
                for assignee_id, count in db.session.query(
                    model.assignee_id, func.count(model.id)
                ).filter(
                    model.assignee_id.in_(member_ids),
                    model.state.notin_(TERMINAL_TASK_STATES),
                ).group_by(model.assignee_id).all():
                    open_tasks_by_member[assignee_id] += count

        sla_at_risk_hours = setting_int("SLA_AT_RISK_HOURS", 4)
        breach_horizon = now() + timedelta(hours=sla_at_risk_hours)
        all_open_ticket_ids = [row[0] for row in open_ticket_rows]
        sla_breached_by_member = Counter()
        sla_at_risk_by_member = Counter()
        if all_open_ticket_ids:
            ticket_to_member = {
                ticket_id: assignee_id for ticket_id, assignee_id, _ in open_ticket_rows
            }
            sla_rows = TaskSLA.query.filter(
                TaskSLA.target_type == "ticket",
                TaskSLA.target_id.in_(all_open_ticket_ids),
                TaskSLA.stage == "In Progress",
            ).all()
            for row in sla_rows:
                assignee_id = ticket_to_member.get(row.target_id)
                if assignee_id is None:
                    continue
                if row.breached:
                    sla_breached_by_member[assignee_id] += 1
                else:
                    breach_at = row.breach_at if row.breach_at.tzinfo else row.breach_at.replace(tzinfo=timezone.utc)
                    if breach_at <= breach_horizon:
                        sla_at_risk_by_member[assignee_id] += 1

        team_rows = []
        member_rows_by_group = {}
        for group in groups:
            group_members = sorted(
                (m for m in memberships if m.group_id == group.id),
                key=lambda m: m.user.name,
            )
            member_rows = []
            for membership in group_members:
                user = membership.user
                member_rows.append({
                    "user": user,
                    "role_in_group": membership.role,
                    "status": "Active" if user.active else "Inactive",
                    "open_incidents": open_incidents_by_member.get(user.id, 0),
                    "open_changes": open_changes_by_member.get(user.id, 0),
                    "open_tasks": open_tasks_by_member.get(user.id, 0),
                    "resolved_30d": resolved_30d_by_member.get(user.id, 0),
                    "sla_breached": sla_breached_by_member.get(user.id, 0),
                    "sla_at_risk": sla_at_risk_by_member.get(user.id, 0),
                })
            member_rows_by_group[group.id] = member_rows
            team_rows.append({
                "group": group,
                "open_incidents": sum(row["open_incidents"] for row in member_rows),
                "open_changes": sum(row["open_changes"] for row in member_rows),
                "open_tasks": sum(row["open_tasks"] for row in member_rows),
                "sla_breached": sum(row["sla_breached"] for row in member_rows),
                "member_count": len(member_rows),
            })
        return team_rows, member_rows_by_group

    @app.get("/manager/portal")
    @roles("manager", "admin")
    def manager_portal():
        team_rows, member_rows_by_group = manager_portal_context()
        return render_template(
            "manager_portal.html", team_rows=team_rows,
            member_rows_by_group=member_rows_by_group,
        )

    @app.get("/manager/portal/export.csv")
    @roles("manager", "admin")
    def manager_portal_export():
        team_rows, member_rows_by_group = manager_portal_context()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([
            "Team", "Team manager", "Member", "Username", "Role", "Status",
            "Open incidents", "Open changes", "Open tasks",
            "Resolved (30 days)", "SLA breached", "SLA at risk",
        ])
        for row in team_rows:
            group = row["group"]
            members = member_rows_by_group.get(group.id, [])
            if not members:
                writer.writerow([
                    group.name, group.manager.name if group.manager else "Unassigned",
                    "", "", "", "", "", "", "", "", "", "",
                ])
                continue
            for member in members:
                writer.writerow([
                    group.name, group.manager.name if group.manager else "Unassigned",
                    member["user"].name, member["user"].username, member["role_in_group"],
                    member["status"], member["open_incidents"], member["open_changes"],
                    member["open_tasks"], member["resolved_30d"],
                    member["sla_breached"], member["sla_at_risk"],
                ])
        return csv_response(buffer.getvalue(), "manager-portal-team-performance.csv")

    @app.get("/work/tasks")
    @login_required
    def my_work_tasks():
        terminal = ["Closed Complete", "Closed Incomplete", "Closed Skipped"]
        group_ids = user_support_group_ids(current_user)

        def open_tasks(model):
            return model.query.filter(model.state.notin_(terminal))

        def row_for(task, kind_label):
            return {
                "number": task.number,
                "kind": kind_label,
                "title": task.title,
                "state": task.state,
                "group": task.assignment_group.name if task.assignment_group else "Unassigned",
                "assignee": task.assignee.name if task.assignee else "Unassigned",
                "due_at": getattr(task, "due_at", None) or getattr(task, "planned_end", None),
                "url": record_url(task),
            }

        assigned_to_me, team_tasks = [], []
        for model, kind_label in ((OperationalTask, None), (CatalogTask, "SCTASK")):
            mine = open_tasks(model).filter(model.assignee_id == current_user.id).all()
            mine_ids = {task.id for task in mine}
            assigned_to_me.extend(
                row_for(task, kind_label or task.task_kind.upper()) for task in mine
            )
            if role_at_least(current_user.effective_role, "admin"):
                team_query = open_tasks(model).join(
                    SupportGroup, model.assignment_group_id == SupportGroup.id
                ).filter(SupportGroup.tenant_id == current_user.tenant_id)
            elif group_ids:
                team_query = open_tasks(model).filter(model.assignment_group_id.in_(group_ids))
            else:
                team_query = None
            if team_query is not None:
                team_tasks.extend(
                    row_for(task, kind_label or task.task_kind.upper())
                    for task in team_query.all() if task.id not in mine_ids
                )

        def sort_key(row):
            return (row["due_at"] is None, row["due_at"] or now())

        assigned_to_me.sort(key=sort_key)
        team_tasks.sort(key=sort_key)
        return render_template(
            "task_queue.html", assigned_to_me=assigned_to_me, team_tasks=team_tasks,
        )

    @app.get("/tickets/<kind>")
    @login_required
    def tickets(kind):
        if kind not in ("incident", "change"):
            abort(404)
        q = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        query = ticket_list_query(kind, q=q, conditions=conditions)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.options(
            db.joinedload(Ticket.requester), db.joinedload(Ticket.assignee),
        ).order_by(Ticket.updated_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        # Batch-fetch owning groups for this page instead of one query per row
        # (ticket_owning_group() issues its own query per call).
        row_ids = [row.id for row in rows]
        assignment_groups = {
            a.ticket_id: a.group
            for a in TicketAssignmentGroup.query.filter(
                TicketAssignmentGroup.ticket_id.in_(row_ids)
            ).options(db.joinedload(TicketAssignmentGroup.group)).all()
        } if row_ids else {}
        ownership_groups = {
            o.ticket_id: o.group
            for o in ChangeOwnership.query.filter(
                ChangeOwnership.ticket_id.in_(row_ids)
            ).options(db.joinedload(ChangeOwnership.group)).all()
        } if row_ids else {}
        owning_groups = {
            row.id: ownership_groups.get(row.id) if row.kind == "change" else assignment_groups.get(row.id)
            for row in rows
        }
        filter_groups = SupportGroup.query.filter_by(
            tenant_id=tenant_context_id()
        ).order_by(SupportGroup.name).all()
        field_spec = ticket_filter_field_spec()
        field_spec["group"] = {"label": "Assignment group", "type": "choice",
                                "options": [(str(g.id), g.name) for g in filter_groups]}
        value_labels = {("group", str(g.id)): g.name for g in filter_groups}
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec, value_labels)
        client_fields = {
            key: {"label": spec["label"], "type": spec["type"], "options": spec.get("options", [])}
            for key, spec in field_spec.items()
        }
        return render_template(
            "tickets.html", tickets=rows, kind=kind, q=q,
            raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts,
            filter_fields=client_fields,
            page=page, pages=pages, total=total,
            owning_groups=owning_groups,
        )

    @app.get("/tickets/<kind>/export.csv")
    @login_required
    def tickets_export(kind):
        if kind not in ("incident", "change"):
            abort(404)
        q = request.args.get("q", "").strip()
        conditions = parse_list_filter_param(request.args.get("filter", ""))
        query = ticket_list_query(kind, q=q, conditions=conditions)
        export_limit = 5000
        rows = query.options(
            db.joinedload(Ticket.requester), db.joinedload(Ticket.assignee),
        ).order_by(Ticket.updated_at.desc()).limit(export_limit).all()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Number", "Title", "State", "Priority", "Requester", "Assignee", "Updated"])
        for ticket in rows:
            writer.writerow([
                ticket.number, ticket.title, ticket.state, ticket.priority,
                ticket.requester.name if ticket.requester else "",
                ticket.assignee.name if ticket.assignee else "Unassigned",
                usertime_filter(ticket.updated_at, "%Y-%m-%d %H:%M"),
            ])
        return csv_response(buffer.getvalue(), f"{kind}-tickets.csv")

    @app.route("/tickets/new/<kind>", methods=["GET", "POST"])
    @login_required
    def ticket_new(kind):
        if kind not in ("incident", "change"):
            abort(404)
        team_ids = user_support_group_ids(current_user)
        eligible_it_team_ids = {
            group.id
            for group in SupportGroup.query.filter(
                SupportGroup.id.in_(team_ids),
                SupportGroup.group_type == "IT Fulfillment",
                SupportGroup.active.is_(True),
            ).all()
        }
        if kind == "change" and current_user.effective_role == "requester" and not eligible_it_team_ids:
            abort(403)

        def render_form(error=None):
            teams_query = tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment", active=True
            )
            if kind == "change" and not role_at_least(current_user.effective_role, "admin"):
                if eligible_it_team_ids:
                    teams_query = teams_query.filter(SupportGroup.id.in_(eligible_it_team_ids))
                else:
                    teams_query = teams_query.filter(SupportGroup.id == -1)
            return render_template(
                "ticket_form.html", kind=kind, teams=teams_query.order_by(SupportGroup.name).all(),
                state_track=build_state_track(kind, "New"),
                default_priority=setting_value("DEFAULT_TICKET_PRIORITY", "P3"),
                service_offerings=tenant_query(ServiceOffering).filter_by(
                    status="Operational"
                ).order_by(ServiceOffering.name).all(),
                # Active/upcoming freeze windows, surfaced on the form itself
                # so a Standard/Normal change author sees the block coming
                # instead of only discovering it after a failed submit.
                change_freeze_windows=(
                    tenant_query(ChangeFreezeWindow).filter(
                        ChangeFreezeWindow.ends_at >= now()
                    ).order_by(ChangeFreezeWindow.starts_at).all()
                    if kind == "change" else []
                ),
                form=request.form if error else None, form_error=error,
            ), (400 if error else 200)

        if request.method == "POST":
            contact_type = request.form.get("contact_type", "Self-service")
            notify = request.form.get("notify", "Email")
            if contact_type not in {
                "Self-service", "Phone", "Email", "Chat", "Monitoring"
            }:
                return render_form("Select a valid contact type.")
            if notify not in {"Email", "In-app only", "Do not notify"}:
                return render_form("Select a valid notification preference.")
            offering = None
            if request.form.get("service_offering_id"):
                offering = tenant_query(ServiceOffering).filter_by(
                    id=int(request.form["service_offering_id"])
                ).first()
                if not offering:
                    return render_form("Select a valid service offering.")
                if offering.status != "Operational":
                    return render_form("Select an operational service offering.")
            try:
                group_id = int(request.form.get("group_id", ""))
            except (TypeError, ValueError):
                return render_form("Select a valid owning IT team.")
            owning_group = db.session.get(SupportGroup, group_id)
            if (
                not owning_group
                or not owning_group.active
                or owning_group.group_type != "IT Fulfillment"
            ):
                return render_form("Select an active IT fulfillment team.")
            if (
                kind == "change"
                and not role_at_least(current_user.effective_role, "admin")
                and owning_group.id not in eligible_it_team_ids
            ):
                return render_form("You can submit changes only for IT fulfillment teams you belong to.")
            if kind == "change" and (
                not owning_group.manager
                or not owning_group.manager.active
            ):
                return render_form("The selected team must have an active manager before a change can be submitted.")
            if kind == "change":
                if not request.form.get("planned_start") or not request.form.get("planned_end"):
                    return render_form("Planned start and planned end are required for a change.")
                planned_start = parse_form_datetime(request.form["planned_start"])
                planned_end = parse_form_datetime(request.form["planned_end"])
                if not planned_start or not planned_end:
                    return render_form("Planned start and planned end must be valid dates.")
                if planned_end <= planned_start:
                    return render_form("Planned end must be later than planned start.")
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            if not title:
                return render_form("Short description is required.")
            if not description:
                return render_form("Description is required.")
            if kind == "change":
                for label, field in (
                    ("Implementation plan", "implementation_plan"),
                    ("Test plan", "test_plan"),
                    ("Backout plan", "backout_plan"),
                ):
                    if not request.form.get(field, "").strip():
                        return render_form(f"{label} is required.")
            ci_id = None
            selected_ci = None
            additional_ci_ids = set()
            if kind == "change":
                try:
                    change_ci_ids = [int(raw) for raw in request.form.getlist("ci_id") if raw.strip()]
                except (TypeError, ValueError):
                    return render_form("One of the selected configuration items is invalid.")
                seen_ci_ids = list(dict.fromkeys(change_ci_ids))
                seen_cis = {}
                for candidate_id in seen_ci_ids:
                    candidate = tenant_query(ConfigurationItem).filter_by(id=candidate_id).first()
                    if not candidate:
                        return render_form("One of the selected configuration items does not exist.")
                    seen_cis[candidate_id] = candidate
                if seen_ci_ids:
                    ci_id = seen_ci_ids[0]
                    selected_ci = seen_cis[ci_id]
                    additional_ci_ids = set(seen_ci_ids[1:])
            elif request.form.get("ci_id"):
                try:
                    ci_id = int(request.form["ci_id"])
                except (TypeError, ValueError):
                    return render_form("The selected configuration item is invalid.")
                selected_ci = tenant_query(ConfigurationItem).filter_by(id=ci_id).first()
                if not selected_ci:
                    return render_form("The selected configuration item does not exist.")
            if kind == "change" and ci_id:
                conflicts = precreate_change_conflicts(current_user.tenant_id, ci_id, planned_start, planned_end)
                if conflicts:
                    return render_form(
                        f"This change cannot be created: it conflicts with {'; '.join(conflicts)}. "
                        "Reschedule the planned window or select a different configuration item."
                    )
            change_type_input = request.form.get("change_type", "Normal")
            if kind == "change" and change_type_input != "Emergency":
                freeze = active_change_freeze(current_user.tenant_id, planned_start, planned_end)
                if freeze:
                    return render_form(
                        f"This change cannot be created: it falls inside the change freeze "
                        f"\"{freeze.title}\" ({freeze.starts_at.strftime('%b %d')}–{freeze.ends_at.strftime('%b %d, %Y')}"
                        f"{': ' + freeze.reason if freeze.reason else ''}). Only Emergency changes are permitted during a freeze."
                    )
            calculated_risk_score = calculate_change_risk_score(
                request.form.get("change_type", "Normal"), selected_ci,
            )
            risk_score_input = request.form.get("risk_score", "").strip()
            if risk_score_input:
                try:
                    risk_score = max(0, min(100, int(risk_score_input)))
                except (TypeError, ValueError):
                    return render_form("Risk score must be a number between 0 and 100.")
                risk_score_overridden = risk_score != calculated_risk_score
            else:
                risk_score = calculated_risk_score
                risk_score_overridden = False
            impact = request.form.get("impact", "Medium")
            urgency = request.form.get("urgency", "Medium")
            priority = calculate_priority(impact, urgency)
            ticket = create_ticket_with_unique_number(
                kind,
                title=title, description=description,
                category=request.form.get("category", "General"), priority=priority,
                impact=impact, urgency=urgency,
                subcategory=request.form.get("subcategory", "").strip(),
                contact_type=contact_type, notify=notify,
                service_offering_id=offering.id if offering else None,
                requester_id=current_user.id)
            if kind == "incident" and ci_id:
                db.session.add(TaskCI(
                    target_type="ticket", target_id=ticket.id, ci_id=ci_id,
                    relationship_role="Primary CI",
                ))
            if kind == "incident":
                sync_service_outages(ticket)
            attach_slas("ticket", ticket.id, ticket.priority)
            if kind == "change":
                governance = ChangeGovernance(ticket_id=ticket.id, change_type=request.form.get("change_type", "Normal"),
                                              risk_score=risk_score,
                                              impact=request.form.get("impact", "Medium"),
                                              implementation_plan=request.form.get("implementation_plan", "").strip(),
                                              test_plan=request.form.get("test_plan", "").strip(),
                                              backout_plan=request.form.get("backout_plan", "").strip(),
                                              planned_start=planned_start, planned_end=planned_end,
                                              ci_id=ci_id,
                                              risk_score_overridden=risk_score_overridden,
                                              risk_score_override_reason=(
                                                  request.form.get("risk_score_override_reason", "").strip()
                                                  if risk_score_overridden else ""
                                              ))
                db.session.add(governance)
                db.session.flush()
                db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=owning_group.id))
                db.session.add(ChangeRevision(ticket_id=ticket.id, revision=1))
                db.session.flush()
                for additional_ci_id in additional_ci_ids:
                    db.session.add(TaskCI(
                        target_type="ticket", target_id=ticket.id,
                        ci_id=additional_ci_id, relationship_role="Affected CI",
                    ))
                if additional_ci_ids:
                    db.session.flush()
                    log_history(
                        "ticket", ticket.id, "Configuration item linked",
                        details=f"Affected CI: {len(additional_ci_ids)} additional configuration item(s) linked at creation.",
                    )
                run_change_conflict_detection(ticket, governance)
                create_approval_chain(
                    f"{ticket.number} change authorization v1",
                    "ticket", ticket.id, change_approval_stages(ticket),
                )
                implementation_notes = "\n\n".join(filter(None, [
                    f"Implementation plan:\n{governance.implementation_plan}",
                    f"Test plan:\n{governance.test_plan}",
                    f"Backout plan:\n{governance.backout_plan}",
                ]))
                def build_initial_task():
                    initial_task = OperationalTask(
                        number=next_operational_task_number("change"),
                        task_kind="change", parent_type="ticket", parent_id=ticket.id,
                        title="Implementation", task_type="Implementation",
                        sequence=1, assignment_group_id=owning_group.id,
                        planned_start=governance.planned_start, planned_end=governance.planned_end,
                        required=True, work_notes=implementation_notes, state="Pending",
                    )
                    db.session.add(initial_task)
                    return initial_task
                initial_task = create_with_retry_on_number_collision(build_initial_task)
                log_history(
                    "ticket", ticket.id, "Change task created",
                    details=f"{initial_task.number} Implementation: created from the change's plan → {owning_group.name}",
                )
            else:
                db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=owning_group.id))
            log_history(
                "ticket", ticket.id, "Record created", details=(
                    f"{ticket.number} created and assigned to {owning_group.name}."
                ),
            )
            audit("create", ticket.number, ticket.title)
            db.session.commit()
            conflicts = kind == "change" and governance.conflict_status.startswith("Conflict")
            flash(
                f"{ticket.number} created."
                + (f" {governance.conflict_status}." if conflicts else ""),
                "error" if conflicts else "success",
            )
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        return render_form()

    @app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
    @login_required
    def ticket_detail(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if not user_can_view_ticket(current_user, ticket):
            abort(403, description="You are not involved in this ticket or its assigned work.")
        if request.method == "POST":
            action = request.form.get("action")
            if action not in ("comment", "reopen") and ticket_locked_for_edits(ticket):
                require_ticket_not_locked(ticket)
                return redirect(url_for("ticket_detail", ticket_id=ticket.id))
            if action == "comment":
                if not effective_role_has_action(current_user.effective_role, "comment_public"):
                    abort(403)
                body = request.form.get("body", "").strip()
                upload = request.files.get("file")
                if body:
                    comment = Comment(ticket_id=ticket.id, user_id=current_user.id, body=body, tenant_id=ticket.tenant_id)
                    db.session.add(comment)
                    db.session.flush()
                    log_history("ticket", ticket.id, "Comment added", details=body[:500])
                    audit("comment", ticket.number)
                    if upload and upload.filename:
                        attachment, error = save_ticket_attachment(ticket, upload, comment_id=comment.id)
                        if error:
                            flash(error, "error")
                        else:
                            log_history(
                                "ticket", ticket.id, "Attachment uploaded",
                                details=f"{attachment.original_name} ({attachment.size_bytes} bytes)",
                            )
            elif action == "reopen":
                if not effective_role_has_action(current_user.effective_role, "resolve"):
                    abort(403)
                require_ticket_team_access(ticket)
                if ticket.state not in ("Resolved", "Closed"):
                    flash(f"{ticket.number} is not Resolved or Closed.", "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                before_state = ticket.state
                transition_ticket(ticket, "In Progress")
                log_history(
                    "ticket", ticket.id, "State changed", "state",
                    before_state, ticket.state,
                    details=f"Reopened by {current_user.name}.",
                )
                audit("reopen", ticket.number, f"{before_state} -> In Progress")
                db.session.commit()
                flash(f"{ticket.number} reopened.", "success")
                return redirect(url_for("ticket_detail", ticket_id=ticket.id))
            elif action == "quick_resolve":
                if not effective_role_has_action(current_user.effective_role, "resolve"):
                    abort(403)
                require_ticket_team_access(ticket)
                before_state = ticket.state
                try:
                    transition_ticket(ticket, "Resolved")
                except HTTPException as error:
                    db.session.rollback()
                    flash(error.description or "That change could not be made.", "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                log_history(
                    "ticket", ticket.id, "State changed", "state",
                    before_state, ticket.state,
                    details="Resolved from the incident action bar.",
                )
                audit("resolve", ticket.number, f"{before_state} -> Resolved")
            elif action == "update":
                for required_action in ("update", "assign", "transition"):
                    if not effective_role_has_action(current_user.effective_role, required_action):
                        abort(403)
                require_ticket_team_access(ticket)
                assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
                eligible_ids = {agent.id for agent in ticket_team_agents(ticket)}
                if assignee_id is not None and assignee_id not in eligible_ids:
                    flash("The assignee must be an active member of the owning team.", "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                impact = request.form.get("impact", ticket.impact)
                urgency = request.form.get("urgency", ticket.urgency)
                calculated = calculate_priority(impact, urgency)
                requested_priority = request.form.get("priority", calculated)
                reason = request.form.get("priority_override_reason", "").strip()
                governed_priority_input = "impact" in request.form or "urgency" in request.form
                if (
                    governed_priority_input and requested_priority != calculated
                    and (not role_at_least(current_user.effective_role, "manager") or len(reason) < 10)
                ):
                    flash(
                        "Only a manager or administrator may override calculated priority, "
                        "with a reason of at least 10 characters.", "error",
                    )
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                before = {
                    "short description": ticket.title,
                    "description": ticket.description,
                    "state": ticket.state,
                    "priority": ticket.priority,
                    "impact": ticket.impact,
                    "urgency": ticket.urgency,
                    "category": ticket.category,
                    "subcategory": ticket.subcategory,
                    "contact type": ticket.contact_type,
                    "notification": ticket.notify,
                    "service offering": (
                        ticket.service_offering.name
                        if ticket.service_offering else "Not selected"
                    ),
                    "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned",
                }
                try:
                    transition_ticket(ticket, request.form["state"])
                except HTTPException as error:
                    db.session.rollback()
                    flash(error.description or "That change could not be made.", "error")
                    return redirect(url_for("ticket_detail", ticket_id=ticket.id))
                previous_override_reason = ticket.priority_override_reason
                if governed_priority_input and requested_priority != calculated:
                    ticket.priority_overridden = True
                    ticket.priority_override_reason = reason
                    if reason != previous_override_reason:
                        log_history(
                            "ticket", ticket.id, "Priority override reason recorded",
                            "priority override reason",
                            previous_override_reason or "None", reason,
                            details=(
                                f"{current_user.name} overrode priority to {requested_priority} "
                                f"(calculated: {calculated}): {reason}"
                            ),
                        )
                elif governed_priority_input:
                    ticket.priority_overridden = False
                    ticket.priority_override_reason = None
                    if previous_override_reason:
                        log_history(
                            "ticket", ticket.id, "Priority override cleared",
                            "priority override reason",
                            previous_override_reason, "None",
                        )
                ticket.impact = impact
                ticket.urgency = urgency
                ticket.priority = requested_priority
                ticket.assignee_id = assignee_id
                if ticket.kind == "incident":
                    contact_type = request.form.get(
                        "contact_type", ticket.contact_type
                    )
                    notify = request.form.get("notify", ticket.notify)
                    if contact_type not in {
                        "Self-service", "Phone", "Email", "Chat", "Monitoring"
                    }:
                        abort(400, description="Select a valid contact type.")
                    if notify not in {"Email", "In-app only", "Do not notify"}:
                        abort(400, description="Select a valid notification preference.")
                    ticket.title = request.form.get("title", ticket.title).strip()
                    ticket.description = request.form.get(
                        "description", ticket.description
                    ).strip()
                    ticket.category = request.form.get(
                        "category", ticket.category
                    ).strip()
                    ticket.subcategory = request.form.get(
                        "subcategory", ticket.subcategory
                    ).strip()
                    ticket.contact_type = contact_type
                    ticket.notify = notify
                    offering_id = request.form.get("service_offering_id", "")
                    offering = (
                        tenant_record_or_404(ServiceOffering, int(offering_id))
                        if offering_id else None
                    )
                    if offering and offering.status != "Operational":
                        abort(400, description="Select an operational service offering.")
                    ticket.service_offering_id = offering.id if offering else None
                    ci_id = request.form.get("ci_id", "")
                    existing_primary = TaskCI.query.filter_by(
                        target_type="ticket", target_id=ticket.id,
                        relationship_role="Primary CI",
                    ).first()
                    old_ci_name = (
                        existing_primary.ci.name if existing_primary else "Not selected"
                    )
                    if ci_id:
                        ci = tenant_record_or_404(ConfigurationItem, int(ci_id))
                        if not existing_primary:
                            existing_primary = TaskCI(
                                target_type="ticket", target_id=ticket.id,
                                relationship_role="Primary CI",
                            )
                            db.session.add(existing_primary)
                        existing_primary.ci_id = ci.id
                        if old_ci_name != ci.name:
                            log_history(
                                "ticket", ticket.id, "Field changed",
                                "configuration item", old_ci_name, ci.name,
                            )
                    elif existing_primary:
                        db.session.delete(existing_primary)
                        log_history(
                            "ticket", ticket.id, "Field changed",
                            "configuration item", old_ci_name, "Not selected",
                        )
                # transition_ticket() above already synced outages once, but that
                # ran before impact/CI were updated to their new values for this
                # request -- resync now that they're final.
                sync_service_outages(ticket)
                assignee = db.session.get(User, assignee_id) if assignee_id else None
                log_field_changes("ticket", ticket.id, before, {
                    "short description": ticket.title,
                    "description": ticket.description,
                    "state": ticket.state,
                    "priority": ticket.priority,
                    "impact": ticket.impact,
                    "urgency": ticket.urgency,
                    "category": ticket.category,
                    "subcategory": ticket.subcategory,
                    "contact type": ticket.contact_type,
                    "notification": ticket.notify,
                    "service offering": (
                        ticket.service_offering.name
                        if ticket.service_offering else "Not selected"
                    ),
                    "assigned to": assignee.name if assignee else "Unassigned",
                })
                audit("update", ticket.number, f"{ticket.state}, {ticket.priority}")
            elif action == "reassign_team":
                if not user_can_manage_ticket(current_user, ticket):
                    abort(403, description=(
                        "Only the current owning team's manager or an admin can reassign this record."
                    ))
                try:
                    new_group_id = int(request.form["new_group_id"])
                except (KeyError, ValueError):
                    abort(400, description="Select a team to reassign to.")
                new_group = SupportGroup.query.filter_by(
                    id=new_group_id, tenant_id=ticket.tenant_id,
                    active=True, group_type="IT Fulfillment",
                ).first()
                if not new_group:
                    abort(400, description="Select an active IT fulfillment team.")
                current_group = ticket_owning_group(ticket)
                if current_group and current_group.id == new_group.id:
                    abort(400, description="This record is already owned by that team.")
                if ticket.kind == "change" and (not new_group.manager or not new_group.manager.active):
                    abort(400, description=(
                        "The selected team must have an active manager before it can own a change."
                    ))
                if ticket.kind == "change":
                    ticket.change_ownership.group_id = new_group.id
                else:
                    assignment = TicketAssignmentGroup.query.filter_by(ticket_id=ticket.id).first()
                    if assignment:
                        assignment.group_id = new_group.id
                    else:
                        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=new_group.id))
                ticket.assignee_id = None
                log_history(
                    "ticket", ticket.id, "Reassigned to another team",
                    "owning team",
                    current_group.name if current_group else "Unassigned", new_group.name,
                )
                audit(
                    "reassign", ticket.number,
                    f"{current_group.name if current_group else 'Unassigned'} -> {new_group.name}",
                )
                if ticket.kind == "change":
                    supersede_change_approval(ticket, ["owning team"])
                db.session.commit()
                flash(f"{ticket.number} reassigned to {new_group.name}.", "success")
                return redirect(url_for("ticket_detail", ticket_id=ticket.id))
            db.session.commit()
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        agents = ticket_team_agents(ticket)
        owning_group = ticket_owning_group(ticket)
        ticket_locked = ticket_locked_for_edits(ticket)
        can_manage_ticket = user_can_manage_ticket(current_user, ticket) and not ticket_locked
        can_reopen = (
            ticket.state in ("Resolved", "Closed")
            and user_can_manage_ticket(current_user, ticket)
            and effective_role_has_action(current_user.effective_role, "resolve")
        )
        internal_view = effective_role_has_action(current_user.effective_role, "comment_internal")
        chains = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).all()
        slas = TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).all()
        work_tasks = OperationalTask.query.filter_by(
            parent_type="ticket", parent_id=ticket.id
        ).order_by(OperationalTask.sequence, OperationalTask.id).all()
        history = TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all()
        ci_links = TaskCI.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).order_by(TaskCI.relationship_role).all()
        return render_template(
            "incident_detail.html" if ticket.kind == "incident" else "ticket_detail.html",
            ticket=ticket, agents=agents, chains=chains, slas=slas,
            state_track=build_state_track(ticket.kind, ticket.state),
            ticket_state_options=allowed_ticket_states(ticket), owning_group=owning_group,
            can_manage_ticket=can_manage_ticket, ticket_locked=ticket_locked, can_reopen=can_reopen,
            related=related_records("ticket", ticket.id),
            relation_labels=RELATION_LABELS, work_tasks=work_tasks,
            work_task_states=OPERATIONAL_TASK_TRANSITIONS, history=history,
            internal_view=internal_view,
            ci_links=ci_links,
            teams=tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment", active=True
            ).order_by(SupportGroup.name).all(),
            reassignable_teams=tenant_query(SupportGroup).filter(
                SupportGroup.group_type == "IT Fulfillment",
                SupportGroup.active.is_(True),
                SupportGroup.id != (owning_group.id if owning_group else -1),
            ).order_by(SupportGroup.name).all(),
            service_offerings=tenant_query(ServiceOffering).filter_by(
                status="Operational"
            ).order_by(ServiceOffering.name).all(),
            pir_outcomes=CHANGE_PIR_OUTCOMES,
            change_freeze_windows=(
                tenant_query(ChangeFreezeWindow).filter(
                    ChangeFreezeWindow.ends_at >= now()
                ).order_by(ChangeFreezeWindow.starts_at).all()
                if ticket.kind == "change" else []
            ),
        )

    @app.post("/change/<int:ticket_id>/delete")
    @roles("agent", "manager", "admin")
    def change_delete(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "change":
            abort(404)
        require_ticket_team_access(ticket)
        if ticket.deleted_at:
            abort(409, description=f"{ticket.number} has already been deleted.")
        if ticket.state not in ("New", "Awaiting Approval"):
            abort(409, description=(
                f"{ticket.number} cannot be deleted once it has progressed past approval. "
                "Cancel it through the normal state transition instead."
            ))
        cancel_approval_chain(approval_chain_for("ticket", ticket.id))
        ticket.state = "Cancelled"
        ticket.deleted_at = now()
        ticket.deleted_by_id = current_user.id
        log_history(
            "ticket", ticket.id, "Change deleted",
            details=f"Soft-deleted by {current_user.name}; retained as Cancelled for the audit trail.",
        )
        audit("delete", ticket.number, f"soft-deleted by {current_user.name}")
        db.session.commit()
        flash(f"{ticket.number} was deleted. It remains available for audit as a Cancelled change.")
        return redirect(url_for("tickets", kind="change"))

    @app.post("/change/<int:ticket_id>/plan")
    @roles("agent", "manager", "admin")
    def change_plan_update(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "change" or not ticket.change_governance:
            abort(404)
        require_ticket_team_access(ticket)
        governance = ticket.change_governance

        def plan_form_error(message):
            flash(message, "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))

        if ticket.state in ("In Progress", "Pending", "Resolved", "Closed", "Cancelled"):
            return plan_form_error(
                "The change plan is locked once implementation has started or the change is closed. "
                "Reopen the change to New/Awaiting Approval before revising the plan."
            )
        try:
            planned_start = parse_form_datetime(request.form.get("planned_start"))
            planned_end = parse_form_datetime(request.form.get("planned_end"))
            ci_id = int(request.form["ci_id"]) if request.form.get("ci_id") else None
        except (TypeError, ValueError):
            return plan_form_error("Change plan dates or CI are invalid.")
        # Tenant-scope the CI lookup before it's used for anything, including
        # the risk-score calculation below -- fetching it unscoped first
        # would let a cross-tenant ci_id's attributes (class,
        # environment/criticality) feed calculated_risk_score before the
        # request is ultimately rejected for not owning that CI.
        ci = tenant_query(ConfigurationItem).filter(ConfigurationItem.id == ci_id).first() if ci_id else None
        if ci_id and not ci:
            return plan_form_error("The selected configuration item does not exist.")
        calculated_risk_score = calculate_change_risk_score(
            request.form.get("change_type", governance.change_type), ci,
        )
        risk_score_input = request.form.get("risk_score", "").strip()
        try:
            if risk_score_input:
                risk_score = max(0, min(100, int(risk_score_input)))
                risk_score_overridden = risk_score != calculated_risk_score
            else:
                risk_score = calculated_risk_score
                risk_score_overridden = False
        except (TypeError, ValueError):
            return plan_form_error("Risk score must be a number between 0 and 100.")
        if not planned_start or not planned_end:
            return plan_form_error("Planned start and planned end are required for a change.")
        if planned_end <= planned_start:
            return plan_form_error("Planned end must be later than planned start.")
        if ci_id:
            conflicts = _conflict_descriptions(
                ticket.tenant_id, {ci_id}, planned_start, planned_end,
                exclude_governance_id=governance.id, exclude_ticket_id=ticket.id,
            )
            if conflicts:
                return plan_form_error(
                    f"This revision conflicts with {'; '.join(conflicts)}. "
                    "Reschedule the planned window or select a different configuration item."
                )
        required_text = {
            "Short description": request.form.get("title", "").strip(),
            "Description": request.form.get("description", "").strip(),
            "Implementation plan": request.form.get("implementation_plan", "").strip(),
            "Test plan": request.form.get("test_plan", "").strip(),
            "Backout plan": request.form.get("backout_plan", "").strip(),
        }
        missing = [label for label, value in required_text.items() if not value]
        if missing:
            return plan_form_error(f"Required change-plan fields are missing: {', '.join(missing)}.")
        before = {
            "short description": ticket.title,
            "description": ticket.description,
            "change type": governance.change_type,
            "risk score": governance.risk_score,
            "impact": governance.impact,
            "implementation plan": governance.implementation_plan,
            "test plan": governance.test_plan,
            "backout plan": governance.backout_plan,
            "planned start": governance.planned_start.isoformat() if governance.planned_start else "",
            "planned end": governance.planned_end.isoformat() if governance.planned_end else "",
            "primary CI": governance.ci.name if governance.ci else "",
        }
        ticket.title = request.form.get("title", "").strip()
        ticket.description = request.form.get("description", "").strip()
        governance.change_type = request.form.get("change_type", "Normal")
        governance.risk_score = risk_score
        governance.risk_score_overridden = risk_score_overridden
        governance.risk_score_override_reason = (
            request.form.get("risk_score_override_reason", "").strip() if risk_score_overridden else ""
        )
        governance.impact = request.form.get("impact", "Medium")
        governance.implementation_plan = request.form.get("implementation_plan", "").strip()
        governance.test_plan = request.form.get("test_plan", "").strip()
        governance.backout_plan = request.form.get("backout_plan", "").strip()
        governance.planned_start = planned_start
        governance.planned_end = planned_end
        governance.ci_id = ci_id
        after = {
            "short description": ticket.title,
            "description": ticket.description,
            "change type": governance.change_type,
            "risk score": governance.risk_score,
            "impact": governance.impact,
            "implementation plan": governance.implementation_plan,
            "test plan": governance.test_plan,
            "backout plan": governance.backout_plan,
            "planned start": governance.planned_start.isoformat() if governance.planned_start else "",
            "planned end": governance.planned_end.isoformat() if governance.planned_end else "",
            "primary CI": db.session.get(ConfigurationItem, ci_id).name if ci_id else "",
        }
        changed_fields = log_field_changes(
            "ticket", ticket.id, before, after, event="Material change plan updated"
        )
        if not changed_fields:
            flash("No change-plan values changed.", "success")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        conflicts = run_change_conflict_detection(ticket, governance)
        supersede_change_approval(ticket, changed_fields)
        audit("revise change plan", ticket.number, ", ".join(changed_fields))
        db.session.commit()
        flash(
            f"Change plan revised. {ticket.number} returned to Awaiting Approval and approvers were notified."
            + (f" Conflicts flagged: {', '.join(conflicts)}." if conflicts else ""),
            "error" if conflicts else "success",
        )
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/change/<int:ticket_id>/pir")
    @roles("agent", "manager", "admin")
    def change_pir_update(ticket_id):
        """Records (or updates) the ITIL 4 post-implementation review a
        change needs before it can reach Closed -- see the gate in
        transition_ticket(). Updatable even after the change is closed, in
        case a follow-up action needs adding later."""
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "change" or not ticket.change_governance:
            abort(404)
        require_ticket_team_access(ticket)
        outcome = request.form.get("outcome", "")
        if outcome not in CHANGE_PIR_OUTCOMES:
            abort(400, description="Select a valid review outcome.")
        summary = request.form.get("summary", "").strip()
        if not summary:
            abort(400, description="A summary is required for the post-implementation review.")
        pir = ticket.post_implementation_review
        if pir:
            before = {"outcome": pir.outcome, "summary": pir.summary}
            pir.outcome = outcome
            pir.summary = summary
            pir.follow_up_actions = request.form.get("follow_up_actions", "").strip()
            pir.reviewed_by_id = current_user.id
            pir.reviewed_at = now()
            log_field_changes("ticket", ticket.id, before, {"outcome": outcome, "summary": summary},
                              event="Post-implementation review updated")
        else:
            pir = ChangePostImplementationReview(
                ticket_id=ticket.id, outcome=outcome, summary=summary,
                follow_up_actions=request.form.get("follow_up_actions", "").strip(),
                reviewed_by_id=current_user.id,
            )
            db.session.add(pir)
            log_history("ticket", ticket.id, "Post-implementation review recorded", details=outcome)
        audit("review", ticket.number, f"PIR outcome: {outcome}")
        db.session.commit()
        flash(f"Post-implementation review saved for {ticket.number}.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/ticket/<int:ticket_id>/satisfaction")
    @login_required
    def ticket_satisfaction_update(ticket_id):
        """ITIL 4 service-desk CSAT: only the ticket's own requester can
        rate it, and only once it's actually Resolved/Closed -- rating an
        in-flight ticket wouldn't reflect a completed service interaction."""
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.requester_id != current_user.id:
            abort(403)
        if ticket.state not in ("Resolved", "Closed"):
            abort(409, description="This ticket isn't resolved yet.")
        try:
            rating = int(request.form.get("rating", ""))
        except (TypeError, ValueError):
            abort(400, description="Select a rating between 1 and 5.")
        if rating < 1 or rating > 5:
            abort(400, description="Select a rating between 1 and 5.")
        ticket.csat_rating = rating
        ticket.csat_comment = request.form.get("comment", "").strip()
        ticket.csat_submitted_at = now()
        log_history("ticket", ticket.id, "Satisfaction rating submitted", details=f"{rating}/5")
        audit("csat", ticket.number, f"{rating}/5")
        db.session.commit()
        flash("Thanks for the feedback!", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/incident/<int:ticket_id>/major-incident")
    @roles("agent", "manager", "admin")
    def major_incident_update(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "incident":
            abort(404)
        require_ticket_team_access(ticket)
        if not require_ticket_not_locked(ticket):
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        profile = ticket.major_incident_profile
        if not profile:
            profile = MajorIncidentProfile(ticket_id=ticket.id)
            db.session.add(profile)
        status = request.form.get("status", "Proposed")
        if status not in ("Proposed", "Accepted", "Rejected", "Resolved"):
            abort(400)
        before = {
            "major incident status": profile.status,
            "business impact": profile.business_impact,
            "communications": profile.communications,
        }
        profile.status = status
        profile.business_impact = request.form.get("business_impact", "").strip()
        profile.communications = request.form.get("communications", "").strip()
        profile.coordinator_id = current_user.id
        if status == "Accepted" and not profile.declared_at:
            profile.declared_at = now()
        log_field_changes("ticket", ticket.id, before, {
            "major incident status": profile.status,
            "business impact": profile.business_impact,
            "communications": profile.communications,
        }, event="Major incident coordination updated")
        audit("major incident", ticket.number, status)
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/incident/<int:ticket_id>/major-incident/review")
    @roles("agent", "manager", "admin")
    def major_incident_review_update(ticket_id):
        """A structured after-the-fact review, distinct from the live
        business_impact/communications fields major_incident_update()
        manages -- ITIL 4 continual improvement expects a documented
        lessons-learned artifact, not just whatever the live coordination
        log happened to capture while the incident was still active."""
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "incident":
            abort(404)
        # A structured review is expected of any P1, not only ones formally
        # walked through the "propose major incident" flow -- most P1s never
        # get declared major but still warrant documented lessons learned.
        if not ticket.major_incident_profile and ticket.priority != "P1":
            abort(404)
        require_ticket_team_access(ticket)
        profile = ticket.major_incident_profile
        if not profile:
            profile = MajorIncidentProfile(ticket_id=ticket.id, status="Resolved")
            db.session.add(profile)
        before = {
            "what went well": profile.review_what_went_well,
            "what went poorly": profile.review_what_went_poorly,
            "follow-up actions": profile.review_follow_up_actions,
        }
        profile.review_what_went_well = request.form.get("what_went_well", "").strip()
        profile.review_what_went_poorly = request.form.get("what_went_poorly", "").strip()
        profile.review_follow_up_actions = request.form.get("follow_up_actions", "").strip()
        profile.reviewed_by_id = current_user.id
        profile.reviewed_at = now()
        log_field_changes("ticket", ticket.id, before, {
            "what went well": profile.review_what_went_well,
            "what went poorly": profile.review_what_went_poorly,
            "follow-up actions": profile.review_follow_up_actions,
        }, event="Post-incident review recorded")
        audit("review", ticket.number, "Post-incident review recorded")
        db.session.commit()
        flash(f"Post-incident review saved for {ticket.number}.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/record/<source_type>/<int:source_id>/relationships")
    @roles("agent", "manager", "admin")
    def record_link_add(source_type, source_id):
        source = record_reference(source_type, source_id)
        if not source:
            abort(404)
        if isinstance(source, Ticket):
            require_ticket_team_access(source)
            if source.kind == "change" and source.state not in ("New", "Awaiting Approval"):
                abort(409, description=(
                    f"{source.number} is locked: related records can only be linked before a change is approved."
                ))
            if source.kind != "change" and ticket_locked_for_edits(source):
                abort(409, description=(
                    f"{source.number} is {source.state} and locked: only comments and notes can be added."
                ))
        elif isinstance(source, EnterpriseRecord):
            if not user_can_manage_enterprise_record(current_user, source):
                abort(403)
        elif isinstance(source, RequestedItem):
            if not user_can_manage_ritm(current_user, source):
                abort(403)
        target = find_record_by_number(request.form.get("target_number"))
        if not target:
            abort(404, description="No record matches the supplied number.")
        if isinstance(target, Ticket) and not user_can_view_ticket(current_user, target):
            abort(404)
        if (
            isinstance(target, EnterpriseRecord)
            and not user_can_view_enterprise_record(current_user, target)
        ):
            abort(404)
        if (
            isinstance(target, CatalogRequest)
            and not user_can_view_catalog_request(current_user, target)
        ):
            abort(404)
        if (
            isinstance(target, RequestedItem)
            and not user_can_view_catalog_request(current_user, target.request)
        ):
            abort(404)
        if (
            isinstance(target, (CatalogTask, OperationalTask, Knowledge))
            and record_tenant_id(target) != tenant_context_id()
        ):
            abort(404)
        target_type = record_type_for(target)
        relation_type = request.form.get("link_type", "")
        source_kind = (
            source.kind if isinstance(source, Ticket)
            else "problem" if isinstance(source, EnterpriseRecord) and source.domain == "problem"
            else source_type
        )
        target_kind = (
            target.kind if isinstance(target, Ticket)
            else "problem" if isinstance(target, EnterpriseRecord) and target.domain == "problem"
            else target_type
        )
        allowed = {
            ("incident", "incident"): {"parent_incident"},
            ("incident", "problem"): {"underlying_problem"},
            ("incident", "change"): {"resolution_change", "caused_by_change"},
            ("incident", "request"): {"converted_request"},
            ("incident", "knowledge"): {"knowledge_article"},
            ("problem", "incident"): {"related_incident"},
            ("problem", "change"): {"problem_change"},
            ("problem", "knowledge"): {"knowledge_article"},
            ("change", "incident"): {"related_incident"},
            ("change", "problem"): {"problem_change"},
            ("change", "ritm"): {"requested_item_change"},
            ("ritm", "change"): {"requested_item_change"},
        }
        if relation_type not in allowed.get((source_kind, target_kind), set()):
            abort(400, description=(
                f"{RELATION_LABELS.get(relation_type, 'This relationship')} is not valid "
                f"between {source_kind} and {target_kind}."
            ))
        if source_type == target_type and source_id == target.id:
            abort(400, description="A record cannot be related to itself.")
        exists = RecordLink.query.filter_by(
            source_type=source_type, source_id=source_id,
            target_type=target_type, target_id=target.id, link_type=relation_type,
        ).first()
        if not exists:
            db.session.add(RecordLink(
                source_type=source_type, source_id=source_id,
                target_type=target_type, target_id=target.id, link_type=relation_type,
            ))
            description = (
                f"{RELATION_LABELS[relation_type]} linked to "
                f"{record_number(target)}: {record_title(target)}"
            )
            log_history(source_type, source_id, "Related record linked", details=description)
            if target_type == "ticket":
                log_history(
                    "ticket", target.id, "Related record linked",
                    details=f"{record_number(source)} linked as {RELATION_LABELS[relation_type]}.",
                )
            audit("link", record_number(source), description)
            db.session.commit()
        return redirect(record_url(source))

    @app.post("/record/<target_type>/<int:target_id>/configuration-items")
    @roles("agent", "manager", "admin")
    def task_ci_add(target_type, target_id):
        target = record_reference(target_type, target_id)
        if not target or target_type not in ("ticket", "enterprise"):
            abort(404)
        if isinstance(target, Ticket):
            require_ticket_team_access(target)
        elif not user_can_manage_enterprise_record(current_user, target):
            abort(403)
        role = request.form.get("relationship_role")
        if role not in ("Primary CI", "Affected CI", "Impacted service"):
            abort(400)
        try:
            ci_ids = [int(raw) for raw in request.form.getlist("ci_id") if raw.strip()]
        except ValueError:
            abort(400)
        if not ci_ids:
            abort(400, description="Select at least one configuration item.")
        if role == "Primary CI":
            # A record has exactly one primary CI; multi-select never applies here.
            ci_ids = ci_ids[:1]
            TaskCI.query.filter_by(
                target_type=target_type, target_id=target_id,
                relationship_role="Primary CI",
            ).delete()
        linked_names = []
        for ci_id in dict.fromkeys(ci_ids):
            ci = tenant_record_or_404(ConfigurationItem, ci_id)
            exists = TaskCI.query.filter_by(
                target_type=target_type, target_id=target_id, ci_id=ci.id,
                relationship_role=role,
            ).first()
            if exists:
                continue
            db.session.add(TaskCI(
                target_type=target_type, target_id=target_id,
                ci_id=ci.id, relationship_role=role,
            ))
            linked_names.append(ci.name)
        if linked_names:
            summary = f"{role}: {', '.join(linked_names)}"
            log_history(
                target_type, target_id, "Configuration item linked",
                details=summary,
            )
            audit("link CI", record_number(target), summary)
            # Affected CIs/impacted services are a material-change field (CLAUDE.md
            # governance rules): adding one to an already-approved change must
            # invalidate the current approval chain, the same as team/plan edits do.
            if isinstance(target, Ticket) and target.kind == "change":
                supersede_change_approval(target, [role.lower()])
            db.session.commit()
        return redirect(record_url(target))

    @app.post("/change/<int:ticket_id>/tasks")
    @roles("agent", "manager", "admin")
    def change_task_add(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if ticket.kind != "change":
            abort(404)
        require_ticket_team_access(ticket)
        if ticket.state in ("Resolved", "Closed", "Cancelled"):
            abort(409, description=(
                f"{ticket.number} is {ticket.state}; change tasks cannot be added to a closed-out change."
            ))
        group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
        if not group.active or group.group_type != "IT Fulfillment":
            abort(400, description="Change tasks require an active IT fulfillment team.")
        task_type = request.form.get("task_type")
        if task_type not in ("Planning", "Implementation", "Testing", "Review"):
            abort(400)
        if not request.form.get("planned_start") or not request.form.get("planned_end"):
            abort(400, description="Task planned start and planned end are required.")
        planned_start = parse_form_datetime(request.form["planned_start"])
        planned_end = parse_form_datetime(request.form["planned_end"])
        governance = ticket.change_governance
        if planned_end <= planned_start:
            abort(400, description="Task end must be later than task start.")
        if governance and governance.planned_start and governance.planned_end:
            if (
                align_tz(planned_start, governance.planned_start) < governance.planned_start
                or align_tz(planned_end, governance.planned_end) > governance.planned_end
            ):
                abort(409, description=(
                    "Task dates must fall within the parent change's planned window "
                    f"({governance.planned_start.strftime('%Y-%m-%d %H:%M')} → "
                    f"{governance.planned_end.strftime('%Y-%m-%d %H:%M')})."
                ))
        sequence = OperationalTask.query.filter_by(
            parent_type="ticket", parent_id=ticket.id
        ).count() + 1

        def build_task():
            task = OperationalTask(
                number=next_operational_task_number("change"),
                task_kind="change", parent_type="ticket", parent_id=ticket.id,
                title=request.form["title"].strip(), task_type=task_type,
                sequence=sequence,
                assignment_group_id=group.id,
                planned_start=planned_start, planned_end=planned_end,
                required=bool(request.form.get("required")),
                state="Open" if task_type == "Planning" else "Pending",
            )
            db.session.add(task)
            return task
        task = create_with_retry_on_number_collision(build_task)
        log_history(
            "ticket", ticket.id, "Change task created",
            details=f"{task.number} {task.task_type}: {task.title} → {group.name}",
        )
        audit("create", task.number, f"{ticket.number}: {task.title}")
        chain = approval_chain_for("ticket", ticket.id)
        reapproval_triggered = chain is not None and chain.state in ("Running", "Approved")
        if reapproval_triggered:
            supersede_change_approval(
                ticket, [f"Change tasks ({task.number} {task.task_type} added)"]
            )
        db.session.commit()
        if reapproval_triggered:
            flash(
                f"{task.number} added. Adding a task after submission is a material change — "
                f"{ticket.number} returned to Awaiting Approval and approvers were notified.",
                "error",
            )
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.get("/operational-task/<int:task_id>")
    @login_required
    def operational_task_detail(task_id):
        task = db.get_or_404(OperationalTask, task_id)
        parent = record_reference(task.parent_type, task.parent_id)
        if not parent:
            abort(404)
        if isinstance(parent, Ticket):
            can_view = user_can_view_ticket(current_user, parent)
        elif isinstance(parent, EnterpriseRecord):
            can_view = user_can_view_enterprise_record(current_user, parent)
        else:
            can_view = False
        if not can_view:
            abort(403)
        can_edit = user_in_group(current_user, task.assignment_group)
        member_ids = {member.user_id for member in task.assignment_group.members}
        if task.assignment_group.manager_id:
            member_ids.add(task.assignment_group.manager_id)
        agents = User.query.filter(
            User.id.in_(member_ids), User.active.is_(True),
            User.role.in_(["agent", "manager", "admin", "superadmin"]),
        ).order_by(User.name).all() if member_ids else []
        history = TaskHistory.query.filter_by(
            target_type=task.parent_type, target_id=task.parent_id
        ).filter(TaskHistory.details.contains(task.number)).order_by(
            TaskHistory.created_at.desc(), TaskHistory.id.desc()
        ).all()
        allowed_states = OPERATIONAL_TASK_TRANSITIONS.get(task.state, (task.state,))
        closing_state = "Closed Complete" if "Closed Complete" in allowed_states else task.state
        gate_block = None
        selectable_states = [task.state]
        for candidate in allowed_states:
            if candidate == task.state:
                continue
            block = change_task_gate_block(task, candidate)
            if block:
                gate_block = gate_block or block
            else:
                selectable_states.append(candidate)
        notes = TaskNote.query.filter_by(
            target_type="operational_task", target_id=task.id
        ).order_by(TaskNote.created_at.desc()).all()
        siblings = OperationalTask.query.filter_by(
            parent_type=task.parent_type, parent_id=task.parent_id,
        ).filter(OperationalTask.id != task.id).order_by(OperationalTask.sequence, OperationalTask.id).all()
        ci_links = TaskCI.query.filter_by(
            target_type=task.parent_type, target_id=task.parent_id
        ).order_by(TaskCI.relationship_role).all()
        approval_votes = []
        if task.task_kind == "change":
            chain = approval_chain_for("ticket", task.parent_id)
            if chain:
                approval_votes = [vote for gate in chain.gates for vote in gate.votes]
        return render_template(
            "operational_task_detail.html", task=task, parent=parent,
            parent_url=record_url(parent), can_edit=can_edit, agents=agents,
            work_task_states=OPERATIONAL_TASK_TRANSITIONS, history=history,
            closing_state=closing_state, notes=notes, siblings=siblings,
            ci_links=ci_links, approval_votes=approval_votes,
            selectable_states=selectable_states, gate_block=gate_block,
        )

    @app.post("/operational-task/<int:task_id>/notes")
    @roles("agent", "manager", "admin")
    def operational_task_note_add(task_id):
        task = db.get_or_404(OperationalTask, task_id)
        if not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                f"Only active members of {task.assignment_group.name} can update {task.number}."
            ))
        body = request.form.get("body", "").strip()
        if body:
            db.session.add(TaskNote(
                target_type="operational_task", target_id=task.id,
                visibility="internal", body=body, user_id=current_user.id,
            ))
            log_history(task.parent_type, task.parent_id, f"{task.number} note added", details=body[:500])
            audit("note", task.number, body[:120])
            db.session.commit()
        return redirect(url_for("operational_task_detail", task_id=task.id))

    @app.post("/operational-task/<int:task_id>")
    @roles("agent", "manager", "admin")
    def operational_task_update(task_id):
        task = db.get_or_404(OperationalTask, task_id)
        if not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                f"Only active members of {task.assignment_group.name} can update {task.number}."
            ))
        assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
        if assignee_id:
            assignee = db.session.get(User, assignee_id)
            if not assignee or not user_in_group(assignee, task.assignment_group):
                flash("The assignee must belong to the task assignment group.", "error")
                return redirect(url_for("operational_task_detail", task_id=task.id))
        else:
            assignee = None
        requested_state = request.form.get("state", task.state)
        if requested_state != task.state:
            if requested_state not in OPERATIONAL_TASK_TRANSITIONS.get(task.state, (task.state,)):
                flash(f"{task.number} cannot move from {task.state} to {requested_state}.", "error")
                return redirect(url_for("operational_task_detail", task_id=task.id))
            gate_block = change_task_gate_block(task, requested_state)
            if gate_block:
                flash(gate_block, "error")
                return redirect(url_for("operational_task_detail", task_id=task.id))
        before = {
            "state": task.state,
            "assigned to": task.assignee.name if task.assignee else "Unassigned",
            "work notes": task.work_notes,
        }
        transition_operational_task(task, requested_state)
        task.assignee_id = assignee_id
        task.work_notes = request.form.get("work_notes", "").strip()
        parent = record_reference(task.parent_type, task.parent_id)
        log_field_changes(task.parent_type, task.parent_id, before, {
            "state": task.state,
            "assigned to": assignee.name if assignee else "Unassigned",
            "work notes": task.work_notes,
        }, event=f"{task.number} updated")
        audit("update", task.number, task.state)
        db.session.commit()
        return redirect(url_for("operational_task_detail", task_id=task.id))

    @app.get("/knowledge")
    @login_required
    def knowledge():
        q = request.args.get("q", "").strip()
        query = tenant_query(Knowledge).filter_by(published=True, archived=False)
        if q:
            query = query.filter(db.or_(Knowledge.title.ilike(f"%{q}%"), Knowledge.body.ilike(f"%{q}%")))
        return render_template("knowledge.html", articles=query.order_by(Knowledge.created_at.desc()).all(), q=q)

    @app.route("/knowledge/new", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def knowledge_new():
        if request.method == "POST":
            article = Knowledge(title=request.form["title"], category=request.form["category"],
                                body=request.form["body"], author_id=current_user.id)
            db.session.add(article)
            db.session.flush()
            audit("create", f"KB{article.id:06d}", article.title)
            db.session.commit()
            return redirect(url_for("knowledge"))
        return render_template("knowledge_form.html")

    @app.get("/knowledge/<int:article_id>")
    @login_required
    def knowledge_detail(article_id):
        article = tenant_query(Knowledge).filter_by(id=article_id).first_or_404()
        history = tenant_query(Knowledge).filter_by(superseded_by_id=article.id).order_by(Knowledge.created_at.desc()).all()
        return render_template("knowledge_detail.html", article=article, history=history)

    @app.route("/knowledge/<int:article_id>/edit", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def knowledge_edit(article_id):
        article = tenant_query(Knowledge).filter_by(id=article_id).first_or_404()
        if article.archived:
            abort(409, description="This article is archived. Create a new article instead of editing an archived version.")
        if request.method == "POST":
            new_version = Knowledge(
                title=request.form["title"], category=request.form["category"],
                body=request.form["body"], author_id=current_user.id, published=True,
            )
            db.session.add(new_version)
            db.session.flush()
            article.archived = True
            article.published = False
            article.superseded_by_id = new_version.id
            audit("supersede", f"KB{article.id:06d}", f"Replaced by KB{new_version.id:06d}")
            audit("create", f"KB{new_version.id:06d}", new_version.title)
            db.session.commit()
            flash("Published an updated version. The previous version is preserved and archived.", "success")
            return redirect(url_for("knowledge_detail", article_id=new_version.id))
        return render_template("knowledge_form.html", article=article)

    @app.post("/knowledge/<int:article_id>/archive")
    @roles("agent", "manager", "admin")
    def knowledge_archive(article_id):
        article = tenant_query(Knowledge).filter_by(id=article_id).first_or_404()
        article.archived = True
        article.published = False
        audit("archive", f"KB{article.id:06d}", article.title)
        db.session.commit()
        flash("Article archived. It no longer appears in knowledge search but its history is preserved.", "success")
        return redirect(url_for("knowledge_detail", article_id=article.id))

    @app.get("/assets")
    @roles("agent", "manager", "admin")
    def assets():
        query = tenant_query(Asset)
        q = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        if q:
            query = query.filter(db.or_(
                Asset.asset_tag.ilike(f"%{q}%"), Asset.name.ilike(f"%{q}%"),
                Asset.serial_number.ilike(f"%{q}%"),
            ))
        field_spec = {
            "asset_tag": {"label": "Asset tag", "type": "text", "column": Asset.asset_tag},
            "name": {"label": "Name", "type": "text", "column": Asset.name},
            "asset_type": {"label": "Type", "type": "text", "column": Asset.asset_type},
            "status": {"label": "Status", "type": "choice", "column": Asset.status,
                      "options": [(s, s) for s in ["In stock", "In use", "In repair", "Retired"]]},
            "serial_number": {"label": "Serial", "type": "text", "column": Asset.serial_number},
        }
        query = apply_filter_conditions(query, conditions, field_spec)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.order_by(Asset.asset_tag).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec)
        client_fields = {
            key: {"label": spec["label"], "type": spec["type"], "options": spec.get("options", [])}
            for key, spec in field_spec.items()
        }
        return render_template(
            "assets.html", assets=rows, q=q, raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts,
            filter_fields=client_fields, page=page, pages=pages, total=total,
        )

    @app.route("/assets/new", methods=["GET", "POST"])
    @roles("admin")
    def asset_new():
        if request.method == "POST":
            asset = Asset(asset_tag=request.form["asset_tag"], name=request.form["name"],
                          asset_type=request.form["asset_type"], status=request.form["status"],
                          serial_number=request.form.get("serial_number"))
            db.session.add(asset)
            audit("create", asset.asset_tag, asset.name)
            db.session.commit()
            return redirect(url_for("assets"))
        return render_template("asset_form.html")

    @app.get("/org-chart")
    @login_required
    def org_chart():
        active_users = tenant_query(User).filter_by(active=True).all()
        by_id = {u.id: u for u in active_users}
        children = defaultdict(list)
        roots = []
        for u in active_users:
            if u.manager_id and u.manager_id in by_id:
                children[u.manager_id].append(u)
            else:
                roots.append(u)
        for group in children.values():
            group.sort(key=lambda u: u.name)
        roots.sort(key=lambda u: u.name)
        return render_template(
            "org_chart.html", roots=roots, children=children,
            can_edit=role_at_least(current_user.effective_role, "admin"),
        )

    @app.get("/admin/users")
    @roles("admin")
    @require_action("security_administer")
    def users():
        tenant_group_ids = [
            group.id for group in tenant_query(SupportGroup).all()
        ]
        tenant_user_ids = [user.id for user in tenant_query(User).all()]
        memberships = GroupMember.query.filter(
            GroupMember.group_id.in_(tenant_group_ids),
            GroupMember.user_id.in_(tenant_user_ids),
        ).all()
        directory_managed = {
            (item.user_id, item.group_id)
            for item in DirectoryManagedMembership.query.filter(
                DirectoryManagedMembership.group_id.in_(tenant_group_ids),
                DirectoryManagedMembership.user_id.in_(tenant_user_ids),
            ).all()
        }
        search = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        user_query = tenant_query(User)
        if search:
            pattern = f"%{search}%"
            user_query = user_query.filter(db.or_(
                User.username.ilike(pattern), User.name.ilike(pattern),
                User.email.ilike(pattern), User.department.ilike(pattern),
            ))
        field_spec = {
            "username": {"label": "User ID", "type": "text", "column": User.username},
            "name": {"label": "Name", "type": "text", "column": User.name},
            "email": {"label": "Email", "type": "text", "column": User.email},
            "role": {"label": "Role", "type": "choice", "column": User.role,
                    "options": [(r, r) for r in ALL_ROLES]},
            "department": {"label": "Department", "type": "text", "column": User.department},
            "active": {"label": "Active", "type": "choice",
                      "options": [("true", "true"), ("false", "false")]},
        }

        def active_filter_handler(query, op, value):
            if op == "eq":
                return query.filter(User.active.is_(value == "true"))
            if op == "ne":
                return query.filter(User.active.is_(value != "true"))
            return query

        user_query = apply_filter_conditions(
            user_query, conditions, field_spec, extra_handlers={"active": active_filter_handler}
        )
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec)
        client_fields = {
            key: {"label": spec["label"], "type": spec["type"], "options": spec.get("options", [])}
            for key, spec in field_spec.items()
        }
        return render_template(
            "users.html",
            users=user_query.order_by(User.name).all(), search=search,
            raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts, filter_fields=client_fields,
            memberships=memberships, directory_managed=directory_managed,
        )

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def user_new():
        if request.method == "POST":
            min_length = setting_int("PASSWORD_MIN_LENGTH", 14)
            password = request.form["password"]
            if len(password) < min_length:
                flash(f"Password must contain at least {min_length} characters.", "error")
                return render_template("user_form.html", user=None, self_service=False)
            initial_role = request.form["role"]
            if initial_role not in ALL_ROLES:
                abort(400, description="Select a valid role.")
            if initial_role == "superadmin" and current_user.effective_role != "superadmin":
                flash("Only a superadmin can grant the superadmin role.", "error")
                return render_template("user_form.html", user=None, self_service=False)
            user = User(username=request.form["username"], name=request.form["name"], email=request.form["email"],
                        password_hash=hash_password(password), role=initial_role,
                        title=request.form.get("title", "")[:120],
                        department=request.form.get("department", "")[:120],
                        business_phone=request.form.get("business_phone", "")[:40],
                        mobile_phone=request.form.get("mobile_phone", "")[:40],
                        timezone=request.form.get("timezone", "Asia/Tokyo")[:80],
                        date_format=request.form.get("date_format", "system")[:40])
            db.session.add(user)
            db.session.flush()
            db.session.add(UserRoleGrant(user_id=user.id, role=initial_role))
            audit("create", user.username, user.role)
            db.session.commit()
            return redirect(url_for("users"))
        return render_template("user_form.html", user=None, self_service=False)

    @app.route("/admin/users/<int:user_id>", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def user_edit(user_id):
        user = tenant_query(User).filter_by(id=user_id).first_or_404()
        if request.method == "POST":
            before = {
                "name": user.name, "email": user.email, "role": user.role,
                "active": user.active, "department": user.department,
                "manager": user.manager.name if user.manager else "None",
            }
            user.name = request.form["name"].strip()[:120]
            user.email = request.form["email"].strip()[:160]
            requested_roles = set(request.form.getlist("granted_roles")) & set(ALL_ROLES)
            if not requested_roles:
                flash("A user must hold at least one role.", "error")
                return redirect(url_for("user_edit", user_id=user.id))
            current_roles = set(user.granted_roles)
            # Only an acting superadmin may grant or revoke the superadmin
            # role on anyone -- otherwise a plain admin could hand
            # themselves (or a peer) cross-tenant platform authority.
            if ("superadmin" in requested_roles) != ("superadmin" in current_roles):
                if current_user.effective_role != "superadmin":
                    flash("Only a superadmin can grant or revoke the superadmin role.", "error")
                    return redirect(url_for("user_edit", user_id=user.id))
            existing_grant_roles = {
                g.role for g in UserRoleGrant.query.filter_by(user_id=user.id).all()
            }
            for role in ALL_ROLES:
                held, requested = role in current_roles, role in requested_roles
                if requested and not held:
                    db.session.add(UserRoleGrant(user_id=user.id, role=role))
                elif requested and held and role not in existing_grant_roles:
                    # `held` can be true purely because it's still reflected
                    # in user.role (the granted_roles property merges that
                    # column in defensively) without an actual UserRoleGrant
                    # row ever having existed for it -- true for any account
                    # whose role was set by a path other than the normal
                    # create-user route (older data, an import, a fixture).
                    # recompute_base_role() below only trusts real grant
                    # rows, so leaving this role un-backed would make it
                    # silently vanish the moment *any* other role changes on
                    # this account, even though it was requested to stay.
                    # Backfilling the row here is a one-time, permanent fix
                    # for that account.
                    db.session.add(UserRoleGrant(user_id=user.id, role=role))
                elif held and not requested:
                    # A manual revoke here always takes effect immediately.
                    # If a directory-group mapping or team-responsibility
                    # rule still implies this role, it can be re-granted on
                    # this user's next login/team-change sync -- there is no
                    # "lock" that overrides directory sync going forward.
                    UserRoleGrant.query.filter_by(user_id=user.id, role=role).delete()
                    ManagedRoleGrant.query.filter_by(user_id=user.id, role=role).delete()
            db.session.flush()
            recompute_base_role(user)
            user.active = bool(request.form.get("active"))
            user.title = request.form.get("title", "").strip()[:120]
            user.department = request.form.get("department", "").strip()[:120]
            user.location = request.form.get("location", "").strip()[:120]
            user.business_phone = request.form.get("business_phone", "").strip()[:40]
            user.mobile_phone = request.form.get("mobile_phone", "").strip()[:40]
            user.timezone = request.form.get("timezone", "Asia/Tokyo")[:80]
            user.date_format = request.form.get("date_format", "system")[:40]
            user.calendar_integration = request.form.get("calendar_integration", "None")[:40]
            manager_raw = request.form.get("manager_id", "")
            if manager_raw:
                manager_id = int(manager_raw)
                if manager_id == user.id:
                    flash("A user cannot be their own manager.", "error")
                    return redirect(url_for("user_edit", user_id=user.id))
                manager = tenant_query(User).filter_by(id=manager_id).first()
                if not manager:
                    flash("Select a valid manager.", "error")
                    return redirect(url_for("user_edit", user_id=user.id))
                walker = manager
                seen = set()
                while walker and walker.id not in seen:
                    if walker.id == user.id:
                        flash(
                            f"Cannot set {manager.name} as manager: that would create a "
                            "reporting-line loop.", "error",
                        )
                        return redirect(url_for("user_edit", user_id=user.id))
                    seen.add(walker.id)
                    walker = walker.manager
                user.manager_id = manager_id
            else:
                user.manager_id = None
            if user.manager and user.manager.name != before["manager"]:
                log_history(
                    "user", user.id, "Field changed", "manager",
                    before["manager"], user.manager.name,
                )
            elif not user.manager and before["manager"] != "None":
                log_history(
                    "user", user.id, "Field changed", "manager",
                    before["manager"], "None",
                )
            audit("update", user.username, json.dumps({"before": before, "role": user.role, "active": user.active}))
            db.session.commit()
            flash("User record updated.", "success")
            return redirect(url_for("user_edit", user_id=user.id))
        manager_choices = tenant_query(User).filter(
            User.active.is_(True), User.id != user.id,
        ).order_by(User.name).all()
        return render_template(
            "user_form.html", user=user, self_service=False,
            manager_choices=manager_choices,
        )

    @app.post("/admin/users/<int:user_id>/erase")
    @roles("admin")
    @require_action("security_administer")
    def user_erase(user_id):
        """GDPR Art. 17 (right to erasure). Deactivating a user (the `active`
        flag) retains name/email/phone/department/title indefinitely -- this
        actually scrubs them, replacing personal fields with an opaque
        placeholder so foreign keys (audit target, ticket requester, etc.)
        keep resolving without exposing who the record used to belong to.
        Only ever applied to an already-deactivated account, is irreversible,
        and the audit entry records that erasure happened, not the erased
        content -- logging the old name/email defeats the purpose."""
        user = tenant_query(User).filter_by(id=user_id).first_or_404()
        if user.id == current_user.id:
            abort(400, description="You cannot erase your own account.")
        if user.active:
            abort(400, description="Deactivate this account before erasing its personal data.")
        if user.erased_at:
            abort(400, description="This account's personal data has already been erased.")
        placeholder = f"erased-user-{user.id}"
        user.name = f"Erased user #{user.id}"
        user.username = placeholder
        user.email = f"{placeholder}@erased.invalid"
        user.title = ""
        user.department = ""
        user.division = None
        user.employee_id = None
        user.employee_type = None
        user.business_phone = ""
        user.mobile_phone = ""
        user.location = ""
        user.avatar_path = None
        user.manager_id = None
        user.password_hash = hash_password(uuid.uuid4().hex)
        user.auth_version += 1
        user.erased_at = now()
        ExternalIdentity.query.filter_by(user_id=user.id).delete()
        audit("erase", placeholder, "Personal data erased (GDPR Art. 17)")
        db.session.commit()
        flash(f"{placeholder}'s personal data has been erased.", "success")
        return redirect(url_for("users"))

    @app.get("/profile/export")
    @login_required
    def profile_export():
        """GDPR Art. 20 (data portability): a structured, machine-readable
        export of this user's own account data -- distinct from the admin
        audit-log export, which is operational, not a subject-access export."""
        user = tenant_query(User).filter_by(id=current_user.id).first_or_404()
        payload = {
            "username": user.username, "name": user.name, "email": user.email,
            "title": user.title, "department": user.department, "division": user.division,
            "business_phone": user.business_phone, "mobile_phone": user.mobile_phone,
            "location": user.location, "timezone": user.timezone, "role": user.role,
            "manager": user.manager.name if user.manager else None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "tickets_requested": [
                {"number": row.number, "title": row.title, "state": row.state, "created_at": row.created_at.isoformat()}
                for row in tenant_query(Ticket).filter_by(requester_id=user.id).order_by(Ticket.created_at.desc()).all()
            ],
        }
        response = Response(
            json.dumps(payload, indent=2, sort_keys=True), mimetype="application/json",
        )
        response.headers["Content-Disposition"] = f'attachment; filename="{user.username}-data-export.json"'
        return response

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user = tenant_query(User).filter_by(id=current_user.id).first_or_404()
        directory_identity = ExternalIdentity.query.filter_by(
            user_id=user.id, provider="ldap"
        ).first()
        email_managed_externally = directory_identity is not None
        if request.method == "POST":
            user.name = request.form["name"].strip()[:120]
            if not email_managed_externally:
                user.email = request.form["email"].strip()[:160]
            user.title = request.form.get("title", "").strip()[:120]
            user.location = request.form.get("location", "").strip()[:120]
            user.business_phone = request.form.get("business_phone", "").strip()[:40]
            user.mobile_phone = request.form.get("mobile_phone", "").strip()[:40]
            user.timezone = request.form.get("timezone", "Asia/Tokyo")[:80]
            user.date_format = request.form.get("date_format", "system")[:40]
            avatar = request.files.get("avatar")
            if avatar and avatar.filename:
                header = avatar.stream.read(8)
                avatar.stream.seek(0)
                if header[:8] == b"\x89PNG\r\n\x1a\n":
                    ext = "png"
                elif header[:3] == b"\xff\xd8\xff":
                    ext = "jpg"
                else:
                    ext = None
                if not ext:
                    flash("Profile picture must be a PNG or JPEG image.", "error")
                    return redirect(url_for("profile"))
                if request.content_length and request.content_length > 5 * 1024 * 1024:
                    flash("Profile picture must be smaller than 5 MB.", "error")
                    return redirect(url_for("profile"))
                avatar_dir = os.path.join(app.config["UPLOAD_FOLDER"], "avatars")
                os.makedirs(avatar_dir, exist_ok=True)
                stored = f"user-{user.id}.{ext}"
                avatar.save(os.path.join(avatar_dir, stored))
                user.avatar_path = stored
            audit("update", user.username, "Self-service profile updated")
            db.session.commit()
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
        teams = [membership.group.name for membership in GroupMember.query.filter_by(
            user_id=user.id
        ).join(SupportGroup).filter(SupportGroup.active.is_(True)).all()]
        return render_template(
            "user_form.html", user=user, self_service=True,
            email_managed_externally=email_managed_externally, teams=teams,
        )

    @app.get("/profile/avatar/<int:user_id>")
    @login_required
    def profile_avatar(user_id):
        user = tenant_query(User).filter_by(id=user_id).first_or_404()
        if not user.avatar_path:
            abort(404)
        avatar_dir = os.path.join(app.config["UPLOAD_FOLDER"], "avatars")
        return send_from_directory(avatar_dir, user.avatar_path)

    def client_workspace_context():
        group = client_sysops_group(current_user.tenant_id)
        user_ids = set()
        if group:
            user_ids.update(member.user_id for member in group.members if member.user.active)
            if group.manager and group.manager.active:
                user_ids.add(group.manager_id)
        if current_user.id not in user_ids and role_at_least(current_user.effective_role, "admin"):
            user_ids.add(current_user.id)
        agents = tenant_query(User).filter(User.id.in_(user_ids), User.active.is_(True)).order_by(User.name).all() if user_ids else []
        return group, agents

    @app.get("/client-management")
    @require_client_management
    def client_management_home():
        query = visible_client_ticket_query(current_user)
        counts = {
            "mine": query.filter(ClientTicket.assignee_id == current_user.id, ClientTicket.status.notin_(["Solved", "Closed"])).count(),
            "unassigned": query.filter(ClientTicket.assignee_id.is_(None), ClientTicket.status.notin_(["Solved", "Closed"])).count(),
            "unsolved": query.filter(ClientTicket.status.notin_(["Solved", "Closed"])).count(),
            "pending": query.filter(ClientTicket.status == "Pending").count(),
            "recent": query.filter(ClientTicket.updated_at >= now() - timedelta(days=7)).count(),
            "solved": query.filter(ClientTicket.status == "Solved").count(),
        }
        recent = query.options(
            selectinload(ClientTicket.contact), selectinload(ClientTicket.assignee),
            selectinload(ClientTicket.organization),
        ).order_by(ClientTicket.updated_at.desc()).limit(8).all()
        return render_template("client_management_home.html", counts=counts, recent=recent)

    def client_ticket_filter_field_spec():
        return {
            "number": {"label": "Number", "type": "text", "column": ClientTicket.number},
            "subject": {"label": "Subject", "type": "text", "column": ClientTicket.subject},
            "status": {"label": "Status", "type": "choice", "column": ClientTicket.status,
                       "options": [(s, s) for s in ["New", "Open", "Pending", "On-hold", "Solved", "Closed"]]},
            "priority": {"label": "Priority", "type": "choice", "column": ClientTicket.priority,
                         "options": [(p, p) for p in ["Low", "Normal", "High", "Urgent"]]},
            "ticket_type": {"label": "Type", "type": "choice", "column": ClientTicket.ticket_type,
                            "options": [(t, t) for t in ["Question", "Incident", "Problem", "Task"]]},
            "channel": {"label": "Channel", "type": "choice", "column": ClientTicket.channel,
                        "options": [(c, c) for c in ["Web", "Email", "Phone", "Chat"]]},
            "tags": {"label": "Tags", "type": "text", "column": ClientTicket.tags},
            "created": {"label": "Opened", "type": "date", "column": ClientTicket.created_at},
            "updated": {"label": "Updated", "type": "date", "column": ClientTicket.updated_at},
        }

    CLIENT_VIEW_SORT_COLUMNS = {
        "updated": ClientTicket.updated_at, "created": ClientTicket.created_at,
        "priority": ClientTicket.priority, "status": ClientTicket.status,
    }

    def visible_client_views(user):
        return ClientView.query.filter(
            ClientView.tenant_id == user.tenant_id,
            db.or_(ClientView.created_by_id == user.id, ClientView.shared.is_(True)),
        ).order_by(ClientView.name).all()

    @app.get("/client-management/tickets")
    @require_client_management
    def client_tickets():
        q = request.args.get("q", "").strip()
        view_id = request.args.get("view_id", type=int)
        active_view = None
        if view_id:
            active_view = ClientView.query.filter(
                ClientView.id == view_id, ClientView.tenant_id == current_user.tenant_id,
                db.or_(ClientView.created_by_id == current_user.id, ClientView.shared.is_(True)),
            ).first()
        query = visible_client_ticket_query(current_user).options(
            selectinload(ClientTicket.contact), selectinload(ClientTicket.assignee),
            selectinload(ClientTicket.organization),
        )
        if active_view:
            view = None
            raw_filter = active_view.conditions_json
            sort_field, sort_dir = active_view.sort_field, active_view.sort_dir
        else:
            view = request.args.get("view", "unsolved")
            raw_filter = request.args.get("filter", "")
            sort_field, sort_dir = "updated", "desc"
            if view == "mine":
                query = query.filter(ClientTicket.assignee_id == current_user.id, ClientTicket.status.notin_(["Solved", "Closed"]))
            elif view == "unassigned":
                query = query.filter(ClientTicket.assignee_id.is_(None), ClientTicket.status.notin_(["Solved", "Closed"]))
            elif view == "pending":
                query = query.filter(ClientTicket.status == "Pending")
            elif view == "recent":
                query = query.filter(ClientTicket.updated_at >= now() - timedelta(days=7))
            elif view == "solved":
                query = query.filter(ClientTicket.status.in_(["Solved", "Closed"]))
            else:
                view = "unsolved"
                query = query.filter(ClientTicket.status.notin_(["Solved", "Closed"]))
        conditions = parse_list_filter_param(raw_filter)
        field_spec = client_ticket_filter_field_spec()
        query = apply_filter_conditions(query, conditions, field_spec)
        if q:
            query = query.join(ClientContact).join(ClientOrganization).filter(db.or_(
                ClientTicket.number.ilike(f"%{q}%"), ClientTicket.subject.ilike(f"%{q}%"),
                ClientContact.name.ilike(f"%{q}%"), ClientContact.email.ilike(f"%{q}%"),
                ClientOrganization.name.ilike(f"%{q}%"),
            ))
        sort_column = CLIENT_VIEW_SORT_COLUMNS.get(sort_field, ClientTicket.updated_at)
        order = sort_column.asc() if sort_dir == "asc" else sort_column.desc()
        tickets = query.order_by(order).limit(250).all()
        client_fields = {
            key: {"label": spec["label"], "type": spec["type"], "options": spec.get("options", [])}
            for key, spec in field_spec.items()
        }
        return render_template(
            "client_tickets.html", tickets=tickets, view=view, q=q,
            raw_filter=raw_filter, filter_fields=client_fields,
            views=visible_client_views(current_user), active_view=active_view,
            sort_field=sort_field, sort_dir=sort_dir,
        )

    @app.post("/client-management/views")
    @require_client_management
    def client_view_create():
        name = request.form.get("name", "").strip()
        raw_conditions = request.form.get("conditions_json", "[]")
        conditions = parse_list_filter_param(raw_conditions)
        sort_field = request.form.get("sort_field", "updated")
        if sort_field not in CLIENT_VIEW_SORT_COLUMNS:
            sort_field = "updated"
        sort_dir = request.form.get("sort_dir", "desc")
        if sort_dir not in ("asc", "desc"):
            sort_dir = "desc"
        if not name:
            flash("Name your view before saving it.", "error")
        elif ClientView.query.filter_by(
            tenant_id=current_user.tenant_id, created_by_id=current_user.id, name=name
        ).first():
            flash("You already have a view with that name.", "error")
        else:
            db.session.add(ClientView(
                tenant_id=current_user.tenant_id, name=name, created_by_id=current_user.id,
                shared=bool(request.form.get("shared")), conditions_json=json.dumps(conditions),
                sort_field=sort_field, sort_dir=sort_dir,
            ))
            audit("client view created", name, "shared" if request.form.get("shared") else "private")
            db.session.commit()
            flash(f'View "{name}" saved.', "success")
        return redirect(url_for("client_tickets"))

    @app.post("/client-management/views/<int:view_id>/delete")
    @require_client_management
    def client_view_delete(view_id):
        view = ClientView.query.filter_by(id=view_id, tenant_id=current_user.tenant_id).first_or_404()
        if view.created_by_id != current_user.id and not role_at_least(current_user.effective_role, "admin"):
            abort(403, description="Only the view's creator or an admin can delete it.")
        name = view.name
        db.session.delete(view)
        audit("client view deleted", name, "")
        db.session.commit()
        flash(f'View "{name}" deleted.', "success")
        return redirect(url_for("client_tickets"))

    @app.route("/client-management/tickets/new", methods=["GET", "POST"])
    @require_client_management
    def client_ticket_new():
        group, agents = client_workspace_context()
        if not group:
            abort(409, description="The SysOps client-support team is not configured.")
        contacts = visible_client_contact_query(current_user).filter_by(active=True).options(selectinload(ClientContact.organization)).order_by(ClientContact.name).all()
        if request.method == "POST":
            contact = visible_client_contact_query(current_user).filter_by(id=request.form.get("contact_id", type=int), active=True).first_or_404()
            subject = request.form.get("subject", "").strip()
            description = request.form.get("description", "").strip()
            resolved_fields = client_custom_fields_for("client_ticket", organization=contact.organization)
            custom_values, custom_error = parse_client_custom_field_values(resolved_fields, request.form)
            if not subject or not description:
                flash("Subject and description are required.", "error")
            elif custom_error:
                flash(custom_error, "error")
            else:
                agent_ids = {agent.id for agent in agents}
                assignee_id = request.form.get("assignee_id", type=int)
                if assignee_id not in agent_ids:
                    assignee_id = None

                def build_client_ticket():
                    row = ClientTicket(
                        number=sequence_number(ClientTicket, "CXT"), tenant_id=current_user.tenant_id,
                        subject=subject, description=description,
                        status="New", priority=request.form.get("priority") if request.form.get("priority") in ["Low", "Normal", "High", "Urgent"] else "Normal",
                        ticket_type=request.form.get("ticket_type") if request.form.get("ticket_type") in ["Question", "Incident", "Problem", "Task"] else "Question",
                        channel=request.form.get("channel") if request.form.get("channel") in ["Web", "Email", "Phone", "Chat"] else "Web",
                        tags=request.form.get("tags", "").strip()[:500], custom_fields=custom_values,
                        contact_id=contact.id,
                        organization_id=contact.organization_id, assignee_id=assignee_id,
                        support_group_id=group.id, created_by_id=current_user.id,
                    )
                    db.session.add(row)
                    return row

                ticket = create_with_retry_on_number_collision(build_client_ticket, error_description="Could not allocate a client ticket number; please try again.")
                db.session.add(ClientTicketMessage(
                    tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                    author_id=current_user.id, body=description, visibility="public", event_type="opened",
                ))
                evaluate_client_triggers("created", ticket, agents)
                attach_slas("client_ticket", ticket.id, ticket.priority, organization_id=ticket.organization_id)
                audit("client ticket created", ticket.number, f"Customer {contact.email}; organization {contact.organization.name}")
                db.session.commit()
                return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
        ticket_fields = client_custom_fields_for("client_ticket")
        return render_template("client_ticket_form.html", contacts=contacts, agents=agents, ticket_fields=ticket_fields)

    @app.route("/client-management/tickets/<int:ticket_id>", methods=["GET", "POST"])
    @require_client_management
    def client_ticket_detail(ticket_id):
        ticket = visible_client_ticket_query(current_user).options(
            selectinload(ClientTicket.messages).selectinload(ClientTicketMessage.author),
            selectinload(ClientTicket.contact), selectinload(ClientTicket.organization),
            selectinload(ClientTicket.assignee),
        ).filter_by(id=ticket_id).first_or_404()
        group, agents = client_workspace_context()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "reply":
                body = request.form.get("body", "").strip()
                visibility = request.form.get("visibility", "public")
                if visibility not in ("public", "internal"):
                    abort(400)
                if not body:
                    flash("Enter a reply or internal note.", "error")
                else:
                    reply_message = ClientTicketMessage(
                        tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                        author_id=current_user.id, body=body, visibility=visibility,
                    )
                    db.session.add(reply_message)
                    db.session.flush()
                    if visibility == "public":
                        # Prefer the mailbox the ticket actually came in on
                        # (or has since been replying through) so a reply
                        # never goes out from an unrelated mailbox just
                        # because it happens to be the first active one for
                        # the tenant. Manually-created tickets have no
                        # mailbox_id, so fall back to the tenant's sole
                        # active mailbox in that case only.
                        mailbox = ticket.mailbox if ticket.mailbox and ticket.mailbox.active else None
                        if not mailbox and not ticket.mailbox_id:
                            mailbox = ClientMailbox.query.filter_by(
                                tenant_id=ticket.tenant_id, active=True
                            ).first()
                        if mailbox:
                            try:
                                deliver_client_email_reply(ticket, reply_message, mailbox)
                            except Exception:
                                # A delivery failure must never lose the reply itself --
                                # it's already saved and visible in-app either way; only
                                # the "also emailed to the customer" half failed.
                                current_app.logger.exception(
                                    "Failed to email client ticket reply: ticket=%s", ticket.number,
                                )
                                flash(
                                    "Reply saved, but sending it by email failed -- check the mailbox configuration.",
                                    "error",
                                )
                        else:
                            current_app.logger.warning(
                                "No active mailbox available to email reply for ticket=%s", ticket.number,
                            )
                            flash(
                                "Reply saved, but no active mailbox is configured -- the customer was not emailed.",
                                "error",
                            )
                    ticket.updated_at = now()
                    audit("client ticket message", ticket.number, visibility)
                    db.session.commit()
                    return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
            elif action == "update":
                old_status = ticket.status
                status = request.form.get("status")
                priority = request.form.get("priority")
                ticket_type = request.form.get("ticket_type")
                if status not in ["New", "Open", "Pending", "On-hold", "Solved", "Closed"]:
                    abort(400)
                if priority not in ["Low", "Normal", "High", "Urgent"] or ticket_type not in ["Question", "Incident", "Problem", "Task"]:
                    abort(400)
                resolved_fields = client_custom_fields_for("client_ticket", organization=ticket.organization)
                custom_values, custom_error = parse_client_custom_field_values(resolved_fields, request.form)
                if custom_error:
                    flash(custom_error, "error")
                    return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
                ticket.custom_fields = custom_values
                agent_ids = {agent.id for agent in agents}
                assignee_id = request.form.get("assignee_id", type=int)
                ticket.assignee_id = assignee_id if assignee_id in agent_ids else None
                ticket.status, ticket.priority, ticket.ticket_type = status, priority, ticket_type
                ticket.tags = request.form.get("tags", "").strip()[:500]
                ticket.solved_at = now() if status == "Solved" and old_status != "Solved" else (None if status not in ["Solved", "Closed"] else ticket.solved_at)
                if old_status != status:
                    db.session.add(ClientTicketMessage(
                        tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                        author_id=current_user.id, body=f"Status changed from {old_status} to {status}.",
                        visibility="internal", event_type="status",
                    ))
                    evaluate_client_triggers("status_changed", ticket, agents)
                    sync_slas("client_ticket", ticket.id, ticket.status)
                evaluate_client_triggers("updated", ticket, agents)
                audit("client ticket updated", ticket.number, f"Status {old_status} -> {status}")
                db.session.commit()
                return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
            elif action == "apply_macro":
                macro = tenant_query(ClientMacro).filter_by(
                    id=request.form.get("macro_id", type=int), active=True
                ).first_or_404()
                try:
                    macro_actions = json.loads(macro.actions_json or "{}")
                except (TypeError, ValueError):
                    macro_actions = {}
                old_status = ticket.status
                if "status" in macro_actions and macro_actions["status"] in ["New", "Open", "Pending", "On-hold", "Solved", "Closed"]:
                    ticket.status = macro_actions["status"]
                if "priority" in macro_actions and macro_actions["priority"] in ["Low", "Normal", "High", "Urgent"]:
                    ticket.priority = macro_actions["priority"]
                if "ticket_type" in macro_actions and macro_actions["ticket_type"] in ["Question", "Incident", "Problem", "Task"]:
                    ticket.ticket_type = macro_actions["ticket_type"]
                if "tags" in macro_actions:
                    ticket.tags = str(macro_actions["tags"])[:500]
                if "assignee_id" in macro_actions:
                    agent_ids = {agent.id for agent in agents}
                    macro_assignee_id = macro_actions["assignee_id"]
                    ticket.assignee_id = macro_assignee_id if macro_assignee_id in agent_ids else None
                if ticket.status == "Solved" and old_status != "Solved":
                    ticket.solved_at = now()
                elif ticket.status not in ("Solved", "Closed"):
                    ticket.solved_at = None
                if old_status != ticket.status:
                    db.session.add(ClientTicketMessage(
                        tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                        author_id=current_user.id, body=f"Status changed from {old_status} to {ticket.status}.",
                        visibility="internal", event_type="status",
                    ))
                    evaluate_client_triggers("status_changed", ticket, agents)
                    sync_slas("client_ticket", ticket.id, ticket.status)
                if macro.reply_body:
                    db.session.add(ClientTicketMessage(
                        tenant_id=current_user.tenant_id, client_ticket_id=ticket.id,
                        author_id=current_user.id, body=macro.reply_body,
                        visibility=macro.reply_visibility if macro.reply_visibility in ("public", "internal") else "public",
                    ))
                evaluate_client_triggers("updated", ticket, agents)
                ticket.updated_at = now()
                audit("client macro applied", ticket.number, macro.name)
                db.session.commit()
                flash(f'Applied "{macro.name}".', "success")
                return redirect(url_for("client_ticket_detail", ticket_id=ticket.id))
        ticket_fields = client_custom_fields_for("client_ticket", organization=ticket.organization)
        macros = tenant_query(ClientMacro).filter_by(active=True).order_by(ClientMacro.name).all()
        return render_template(
            "client_ticket_detail.html", ticket=ticket, agents=agents, ticket_fields=ticket_fields, macros=macros,
            branding=(ticket.organization.settings or {}).get("branding", {}),
        )

    @app.route("/client-management/organizations", methods=["GET", "POST"])
    @require_client_management
    def client_organizations():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            if not name:
                flash("Organization name is required.", "error")
            elif tenant_query(ClientOrganization).filter(func.lower(ClientOrganization.name) == name.lower()).first():
                flash("That client organization already exists.", "error")
            else:
                row = ClientOrganization(
                    tenant_id=current_user.tenant_id, name=name,
                    domain=request.form.get("domain", "").strip().lower(),
                    external_id=request.form.get("external_id", "").strip() or None,
                    notes=request.form.get("notes", "").strip(),
                )
                db.session.add(row)
                audit("client organization created", name)
                db.session.commit()
                return redirect(url_for("client_organizations"))
        rows = visible_client_organization_query(current_user).options(selectinload(ClientOrganization.contacts)).order_by(ClientOrganization.name).all()
        return render_template("client_organizations.html", organizations=rows)

    @app.route("/client-management/organizations/<int:organization_id>", methods=["GET", "POST"])
    @require_client_management
    def client_organization_detail(organization_id):
        organization = visible_client_organization_query(current_user).options(
            selectinload(ClientOrganization.contacts), selectinload(ClientOrganization.access_grants),
        ).filter_by(id=organization_id).first_or_404()
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description="Only an administrator can change organization visibility or access grants.")
            action = request.form.get("action")
            if action == "toggle_restricted":
                organization.restricted_visibility = not organization.restricted_visibility
                audit(
                    "client organization visibility", organization.name,
                    "Restricted" if organization.restricted_visibility else "Open to all SysOps members",
                )
                db.session.commit()
                flash(
                    f"{organization.name} is now "
                    f"{'restricted to explicitly granted users/teams' if organization.restricted_visibility else 'visible to every SysOps member'}.",
                    "success",
                )
            elif action == "add_grant":
                grantee = request.form.get("grantee", "")
                kind, _, raw_id = grantee.partition(":")
                try:
                    grantee_id = int(raw_id)
                except (TypeError, ValueError):
                    abort(400, description="Select a valid user or team.")
                if kind == "user":
                    user_row = tenant_record_or_404(User, grantee_id)
                    existing = ClientOrganizationAccess.query.filter_by(
                        organization_id=organization.id, user_id=user_row.id
                    ).first()
                    if not existing:
                        db.session.add(ClientOrganizationAccess(
                            tenant_id=current_user.tenant_id, organization_id=organization.id,
                            user_id=user_row.id, updated_by_id=current_user.id,
                        ))
                        audit("client organization access granted", organization.name, f"user {user_row.username}")
                        db.session.commit()
                elif kind == "group":
                    group_row = tenant_record_or_404(SupportGroup, grantee_id)
                    existing = ClientOrganizationAccess.query.filter_by(
                        organization_id=organization.id, group_id=group_row.id
                    ).first()
                    if not existing:
                        db.session.add(ClientOrganizationAccess(
                            tenant_id=current_user.tenant_id, organization_id=organization.id,
                            group_id=group_row.id, updated_by_id=current_user.id,
                        ))
                        audit("client organization access granted", organization.name, f"team {group_row.name}")
                        db.session.commit()
                else:
                    abort(400, description="Select a valid user or team.")
                flash("Access grant added.", "success")
            elif action == "remove_grant":
                grant = ClientOrganizationAccess.query.filter_by(
                    id=request.form.get("grant_id", type=int), organization_id=organization.id,
                ).first_or_404()
                label = grant.user.username if grant.user_id else grant.group.name
                db.session.delete(grant)
                audit("client organization access revoked", organization.name, label)
                db.session.commit()
                flash("Access grant removed.", "success")
            elif action == "update_custom_fields":
                org_fields = client_custom_fields_for("organization")
                values, error = parse_client_custom_field_values(org_fields, request.form)
                if error:
                    flash(error, "error")
                else:
                    organization.custom_fields = values
                    audit("client organization custom fields updated", organization.name, "")
                    db.session.commit()
                    flash("Custom fields saved.", "success")
            elif action == "update_field_overrides":
                ticket_field_defs = tenant_query(ClientCustomFieldDefinition).filter_by(
                    entity_type="client_ticket", active=True,
                ).all()
                overrides = dict(organization.settings or {})
                field_overrides = {}
                for field in ticket_field_defs:
                    visible = request.form.get(f"visible__{field.key}") == "on"
                    required = request.form.get(f"required__{field.key}") == "on"
                    if not visible or required != field.required:
                        field_overrides[field.key] = {"visible": visible, "required": required}
                overrides["custom_field_overrides"] = field_overrides
                organization.settings = overrides
                audit("client organization field overrides updated", organization.name, "")
                db.session.commit()
                flash("Ticket field overrides saved.", "success")
            elif action == "update_branding":
                # This app has no real multi-domain/multi-portal hosting --
                # "branding per organization" is scoped honestly to what
                # actually renders: a display name/accent color/logo shown
                # on that organization's own tickets, not a separate
                # branded site.
                settings = dict(organization.settings or {})
                settings["branding"] = {
                    "display_name": request.form.get("display_name", "").strip()[:180],
                    "color": request.form.get("color", "").strip()[:20],
                }
                organization.settings = settings
                audit("client organization branding updated", organization.name, "")
                db.session.commit()
                flash("Branding saved.", "success")
            elif action == "update_notification_policy":
                escalation_hours = request.form.get("escalation_hours", "").strip()
                escalation_group_id = request.form.get("escalation_group_id", "").strip()
                settings = dict(organization.settings or {})
                notification = {}
                if escalation_hours and escalation_group_id:
                    try:
                        hours_value = float(escalation_hours)
                    except ValueError:
                        flash("Escalation hours must be a number.", "error")
                        return redirect(url_for("client_organization_detail", organization_id=organization.id))
                    tenant_record_or_404(SupportGroup, int(escalation_group_id))
                    notification = {"escalation_hours": hours_value, "escalation_group_id": int(escalation_group_id)}
                settings["notification"] = notification
                organization.settings = settings
                audit("client organization notification policy updated", organization.name, "")
                db.session.commit()
                flash("Notification and escalation policy saved.", "success")
            return redirect(url_for("client_organization_detail", organization_id=organization.id))
        agents = User.query.filter(
            User.tenant_id == current_user.tenant_id, User.active.is_(True),
            User.role.in_(["agent", "manager", "admin"]),
        ).order_by(User.name).all()
        groups = tenant_query(SupportGroup).filter_by(active=True).order_by(SupportGroup.name).all()
        org_custom_fields = client_custom_fields_for("organization")
        ticket_field_defs = tenant_query(ClientCustomFieldDefinition).filter_by(
            entity_type="client_ticket", active=True,
        ).order_by(ClientCustomFieldDefinition.position, ClientCustomFieldDefinition.label).all()
        ticket_field_overrides = (organization.settings or {}).get("custom_field_overrides", {})
        return render_template(
            "client_organization_detail.html", organization=organization, agents=agents, groups=groups,
            is_admin=role_at_least(current_user.effective_role, "admin"),
            org_custom_fields=org_custom_fields, ticket_field_defs=ticket_field_defs,
            ticket_field_overrides=ticket_field_overrides,
            branding=(organization.settings or {}).get("branding", {}),
            notification_policy=(organization.settings or {}).get("notification", {}),
        )

    @app.route("/client-management/custom-fields", methods=["GET", "POST"])
    @require_client_management
    def client_custom_fields_admin():
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description="Only an administrator can manage custom fields.")
            action = request.form.get("action", "create")
            if action == "create":
                entity_type = request.form.get("entity_type", "")
                key = request.form.get("key", "").strip().lower().replace(" ", "_")
                label = request.form.get("label", "").strip()
                field_type = request.form.get("field_type", "text")
                options_raw = request.form.get("options", "")
                if entity_type not in CLIENT_CUSTOM_FIELD_ENTITY_TYPES:
                    abort(400, description="Select a valid entity type.")
                if field_type not in CLIENT_CUSTOM_FIELD_TYPES:
                    abort(400, description="Select a valid field type.")
                if not key or not re.match(r"^[a-z][a-z0-9_]{0,58}[a-z0-9]$", key):
                    flash("Field key must be lowercase letters, numbers, and underscores.", "error")
                elif not label:
                    flash("Field label is required.", "error")
                elif tenant_query(ClientCustomFieldDefinition).filter_by(
                    entity_type=entity_type, key=key
                ).first():
                    flash("A field with that key already exists for this record type.", "error")
                else:
                    options = [line.strip() for line in options_raw.splitlines() if line.strip()] if field_type == "select" else []
                    db.session.add(ClientCustomFieldDefinition(
                        tenant_id=current_user.tenant_id, entity_type=entity_type, key=key,
                        label=label, field_type=field_type, options_json=json.dumps(options),
                        required=bool(request.form.get("required")), created_by_id=current_user.id,
                    ))
                    audit("client custom field created", label, entity_type)
                    db.session.commit()
                    flash(f"{label} added.", "success")
            elif action == "toggle_active":
                field = tenant_record_or_404(ClientCustomFieldDefinition, request.form.get("field_id", type=int))
                field.active = not field.active
                audit("client custom field toggled", field.label, "Active" if field.active else "Inactive")
                db.session.commit()
                flash(f"{field.label} is now {'active' if field.active else 'inactive'}.", "success")
            return redirect(url_for("client_custom_fields_admin"))
        fields_by_entity = {
            entity_type: tenant_query(ClientCustomFieldDefinition).filter_by(
                entity_type=entity_type
            ).order_by(ClientCustomFieldDefinition.position, ClientCustomFieldDefinition.label).all()
            for entity_type in CLIENT_CUSTOM_FIELD_ENTITY_TYPES
        }
        return render_template(
            "client_custom_fields_admin.html", fields_by_entity=fields_by_entity,
            entity_types=CLIENT_CUSTOM_FIELD_ENTITY_TYPES, field_types=CLIENT_CUSTOM_FIELD_TYPES,
        )

    GUIDED_TOUR_ROLES = ("requester", "agent", "manager", "admin")

    @app.route("/admin/guided-tours", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def guided_tours_admin():
        """B-120: admin authoring page for contextual guided tours. DB-backed
        (not Git-backed config) so a non-engineer admin can author/edit tour
        content without a deploy, matching ClientMacro/ClientTrigger's
        existing precedent for admin-editable per-tenant content."""
        if request.method == "POST":
            action = request.form.get("action", "create")
            if action == "create":
                key = request.form.get("key", "").strip().lower().replace(" ", "-")
                title = request.form.get("title", "").strip()
                if not key or not title:
                    flash("A key and title are required.", "error")
                elif tenant_query(GuidedTour).filter_by(key=key).first():
                    flash("A tour with that key already exists.", "error")
                else:
                    roles_selected = [r for r in request.form.getlist("target_roles") if r in GUIDED_TOUR_ROLES]
                    tour = GuidedTour(
                        tenant_id=current_user.tenant_id, key=key, title=title,
                        description=request.form.get("description", "").strip()[:500],
                        target_route=request.form.get("target_route", "*").strip() or "*",
                        target_roles=",".join(roles_selected),
                        created_by_id=current_user.id,
                    )
                    db.session.add(tour)
                    audit("guided tour created", key, title)
                    db.session.commit()
                    flash(f"{title} created. Add steps below.", "success")
            elif action == "update_tour":
                tour = tenant_record_or_404(GuidedTour, request.form.get("tour_id", type=int))
                title = request.form.get("title", "").strip()
                if not title:
                    flash("Title is required.", "error")
                else:
                    roles_selected = [r for r in request.form.getlist("target_roles") if r in GUIDED_TOUR_ROLES]
                    tour.title = title
                    tour.description = request.form.get("description", "").strip()[:500]
                    tour.target_route = request.form.get("target_route", "*").strip() or "*"
                    tour.target_roles = ",".join(roles_selected)
                    # Content changed -- bump version so users who already
                    # dismissed/completed the prior version are re-prompted
                    # (see UserTourProgress.tour_version_seen).
                    tour.version += 1
                    audit("guided tour updated", tour.key, f"version={tour.version}")
                    db.session.commit()
                    flash(f"{tour.title} updated (now version {tour.version}).", "success")
            elif action == "toggle_active":
                tour = tenant_record_or_404(GuidedTour, request.form.get("tour_id", type=int))
                tour.active = not tour.active
                audit("guided tour toggled", tour.key, "Active" if tour.active else "Inactive")
                db.session.commit()
                flash(f"{tour.title} is now {'active' if tour.active else 'inactive'}.", "success")
            elif action == "delete":
                tour = tenant_record_or_404(GuidedTour, request.form.get("tour_id", type=int))
                title = tour.title
                # GuidedTourStep cascades via the ORM relationship, but
                # UserTourProgress has no FK cascade -- delete it explicitly
                # first or this fails with a ForeignKeyViolation for any
                # tour a user has actually seen (found during verification).
                UserTourProgress.query.filter_by(tour_id=tour.id).delete()
                db.session.delete(tour)
                audit("guided tour deleted", title, "")
                db.session.commit()
                flash(f"{title} deleted.", "success")
            elif action == "add_step":
                tour = tenant_record_or_404(GuidedTour, request.form.get("tour_id", type=int))
                title = request.form.get("step_title", "").strip()
                body = request.form.get("step_body", "").strip()
                if not title or not body:
                    flash("Step title and body are required.", "error")
                else:
                    next_order = (
                        db.session.query(db.func.max(GuidedTourStep.step_order))
                        .filter_by(tour_id=tour.id).scalar() or 0
                    ) + 1
                    db.session.add(GuidedTourStep(
                        tenant_id=current_user.tenant_id, tour_id=tour.id, step_order=next_order,
                        target_selector=request.form.get("target_selector", "").strip()[:300],
                        title=title, body=body,
                        placement=request.form.get("placement", "bottom") if request.form.get("placement") in
                        ("top", "bottom", "left", "right", "center") else "bottom",
                    ))
                    tour.version += 1
                    audit("guided tour step added", tour.key, title)
                    db.session.commit()
                    flash("Step added.", "success")
            elif action == "delete_step":
                step = GuidedTourStep.query.join(GuidedTour).filter(
                    GuidedTourStep.id == request.form.get("step_id", type=int),
                    GuidedTour.tenant_id == current_user.tenant_id,
                ).first_or_404()
                tour = step.tour
                db.session.delete(step)
                tour.version += 1
                audit("guided tour step deleted", tour.key, step.title)
                db.session.commit()
                flash("Step removed.", "success")
            return redirect(url_for("guided_tours_admin"))
        tours = tenant_query(GuidedTour).options(selectinload(GuidedTour.steps)).order_by(GuidedTour.title).all()
        return render_template("guided_tours_admin.html", tours=tours, roles=GUIDED_TOUR_ROLES)

    @app.route("/admin/notification-templates", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def notification_templates_admin():
        """B-130: admin-editable subject/body per notification event_type.
        A row only exists once an admin has customized that event_type;
        create_notification() falls back to the caller's own literal
        default wording whenever no active template is found, so this page
        is purely additive -- nothing here can be misconfigured into
        silence the way a required-config page could."""
        if request.method == "POST":
            event_type = request.form.get("event_type", "")
            if event_type not in NOTIFICATION_EVENT_TYPES:
                abort(400, description="Unknown notification event type.")
            action = request.form.get("action", "save")
            template = NotificationTemplate.query.filter_by(
                tenant_id=current_user.tenant_id, event_type=event_type,
            ).first()
            if action == "reset":
                if template:
                    db.session.delete(template)
                    audit("notification template reset", event_type, "")
                    db.session.commit()
                    flash("Reverted to the default wording.", "success")
            else:
                subject = request.form.get("subject_template", "").strip()
                body = request.form.get("body_template", "").strip()
                if not subject or not body:
                    flash("Subject and body are both required.", "error")
                else:
                    if template:
                        template.subject_template = subject[:255]
                        template.body_template = body
                        template.active = True
                    else:
                        db.session.add(NotificationTemplate(
                            tenant_id=current_user.tenant_id, event_type=event_type,
                            subject_template=subject[:255], body_template=body,
                        ))
                    audit("notification template saved", event_type, "")
                    db.session.commit()
                    flash("Notification template saved.", "success")
            return redirect(url_for("notification_templates_admin"))
        templates_by_event = {
            row.event_type: row
            for row in tenant_query(NotificationTemplate).all()
        }
        return render_template(
            "notification_templates_admin.html",
            event_types=NOTIFICATION_EVENT_TYPES, templates_by_event=templates_by_event,
        )

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

    @app.route("/client-management/macros", methods=["GET", "POST"])
    @require_client_management
    def client_macros_admin():
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description="Only an administrator can manage macros.")
            action = request.form.get("action", "create")
            if action == "create":
                name = request.form.get("name", "").strip()
                if not name:
                    flash("Macro name is required.", "error")
                elif tenant_query(ClientMacro).filter_by(name=name).first():
                    flash("A macro with that name already exists.", "error")
                else:
                    actions = {}
                    status = request.form.get("macro_status", "")
                    if status and status in ["New", "Open", "Pending", "On-hold", "Solved", "Closed"]:
                        actions["status"] = status
                    priority = request.form.get("macro_priority", "")
                    if priority and priority in ["Low", "Normal", "High", "Urgent"]:
                        actions["priority"] = priority
                    ticket_type = request.form.get("macro_ticket_type", "")
                    if ticket_type and ticket_type in ["Question", "Incident", "Problem", "Task"]:
                        actions["ticket_type"] = ticket_type
                    tags = request.form.get("macro_tags", "").strip()
                    if tags:
                        actions["tags"] = tags[:500]
                    reply_body = request.form.get("reply_body", "").strip()
                    reply_visibility = request.form.get("reply_visibility", "public")
                    if reply_visibility not in ("public", "internal"):
                        reply_visibility = "public"
                    db.session.add(ClientMacro(
                        tenant_id=current_user.tenant_id, name=name, actions_json=json.dumps(actions),
                        reply_body=reply_body, reply_visibility=reply_visibility, created_by_id=current_user.id,
                    ))
                    audit("client macro created", name, "")
                    db.session.commit()
                    flash(f"{name} added.", "success")
            elif action == "toggle_active":
                macro = tenant_record_or_404(ClientMacro, request.form.get("macro_id", type=int))
                macro.active = not macro.active
                audit("client macro toggled", macro.name, "Active" if macro.active else "Inactive")
                db.session.commit()
                flash(f"{macro.name} is now {'active' if macro.active else 'inactive'}.", "success")
            return redirect(url_for("client_macros_admin"))
        macros = tenant_query(ClientMacro).order_by(ClientMacro.name).all()
        macro_rows = []
        for macro in macros:
            try:
                actions = json.loads(macro.actions_json or "{}")
            except (TypeError, ValueError):
                actions = {}
            macro_rows.append({"macro": macro, "actions": actions})
        return render_template(
            "client_macros_admin.html", macro_rows=macro_rows,
            statuses=["New", "Open", "Pending", "On-hold", "Solved", "Closed"],
            priorities=["Low", "Normal", "High", "Urgent"],
            ticket_types=["Question", "Incident", "Problem", "Task"],
        )

    @app.route("/client-management/triggers", methods=["GET", "POST"])
    @require_client_management
    def client_triggers_admin():
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description="Only an administrator can manage triggers.")
            action = request.form.get("action", "create")
            if action == "create":
                name = request.form.get("name", "").strip()
                event = request.form.get("event", "")
                condition_field = request.form.get("condition_field", "")
                condition_op = request.form.get("condition_op", "")
                condition_value = request.form.get("condition_value", "").strip()
                action_type = request.form.get("action_type", "")
                action_value = request.form.get("action_value", "").strip()
                if not name:
                    flash("Trigger name is required.", "error")
                elif tenant_query(ClientTrigger).filter_by(name=name).first():
                    flash("A trigger with that name already exists.", "error")
                else:
                    try:
                        validate_trigger(event, condition_field, condition_op, action_type, action_value)
                    except ClientTriggerConfigurationError as error:
                        flash(str(error), "error")
                    else:
                        max_position = db.session.query(
                            func.coalesce(func.max(ClientTrigger.position), -1)
                        ).filter(ClientTrigger.tenant_id == current_user.tenant_id, ClientTrigger.event == event).scalar()
                        db.session.add(ClientTrigger(
                            tenant_id=current_user.tenant_id, name=name, event=event,
                            condition_field=condition_field, condition_op=condition_op,
                            condition_value=condition_value, action_type=action_type,
                            action_value=action_value, position=max_position + 1,
                            created_by_id=current_user.id,
                        ))
                        audit("client trigger created", name, event)
                        db.session.commit()
                        flash(f"{name} added.", "success")
            elif action == "toggle_active":
                trigger = tenant_record_or_404(ClientTrigger, request.form.get("trigger_id", type=int))
                trigger.active = not trigger.active
                audit("client trigger toggled", trigger.name, "Active" if trigger.active else "Inactive")
                db.session.commit()
                flash(f"{trigger.name} is now {'active' if trigger.active else 'inactive'}.", "success")
            return redirect(url_for("client_triggers_admin"))
        triggers = tenant_query(ClientTrigger).order_by(ClientTrigger.event, ClientTrigger.position).all()
        return render_template(
            "client_triggers_admin.html", triggers=triggers, events=CLIENT_TRIGGER_EVENTS,
            fields=CLIENT_TRIGGER_FIELDS, operators=CLIENT_TRIGGER_OPERATORS,
            action_types=CLIENT_TRIGGER_ACTION_TYPES, statuses=CLIENT_TICKET_STATUSES,
            priorities=CLIENT_TICKET_PRIORITIES,
            groups=tenant_query(SupportGroup).filter_by(active=True).order_by(SupportGroup.name).all(),
            agents=User.query.filter(
                User.tenant_id == current_user.tenant_id, User.active.is_(True),
                User.role.in_(["agent", "manager", "admin"]),
            ).order_by(User.name).all(),
        )

    @app.route("/client-management/mailboxes", methods=["GET", "POST"])
    @require_client_management
    def client_mailboxes_admin():
        if request.method == "POST":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description="Only an administrator can manage mailboxes.")
            action = request.form.get("action", "create")
            if action == "create":
                name = request.form.get("name", "").strip()
                if not name:
                    flash("Mailbox name is required.", "error")
                elif tenant_query(ClientMailbox).filter_by(name=name).first():
                    flash("A mailbox with that name already exists.", "error")
                else:
                    default_org_id = request.form.get("default_organization_id", type=int)
                    if default_org_id:
                        tenant_record_or_404(ClientOrganization, default_org_id)
                    mailbox = ClientMailbox(
                        tenant_id=current_user.tenant_id, name=name,
                        imap_host=request.form.get("imap_host", "").strip(),
                        imap_port=request.form.get("imap_port", type=int) or 993,
                        imap_use_ssl=bool(request.form.get("imap_use_ssl")),
                        imap_username=request.form.get("imap_username", "").strip(),
                        imap_folder=request.form.get("imap_folder", "INBOX").strip() or "INBOX",
                        smtp_host=request.form.get("smtp_host", "").strip(),
                        smtp_port=request.form.get("smtp_port", type=int) or 587,
                        smtp_use_tls=bool(request.form.get("smtp_use_tls")),
                        smtp_username=request.form.get("smtp_username", "").strip(),
                        from_address=request.form.get("from_address", "").strip(),
                        from_name=request.form.get("from_name", "").strip(),
                        default_organization_id=default_org_id or None,
                        auto_create_organization_by_domain=bool(request.form.get("auto_create_organization_by_domain")),
                        created_by_id=current_user.id,
                    )
                    if request.form.get("imap_password"):
                        mailbox.imap_password = request.form["imap_password"]
                    if request.form.get("smtp_password"):
                        mailbox.smtp_password = request.form["smtp_password"]
                    db.session.add(mailbox)
                    audit("client mailbox created", name, mailbox.imap_host)
                    db.session.commit()
                    flash(f"{name} added.", "success")
            elif action == "toggle_active":
                mailbox = tenant_record_or_404(ClientMailbox, request.form.get("mailbox_id", type=int))
                mailbox.active = not mailbox.active
                audit("client mailbox toggled", mailbox.name, "Active" if mailbox.active else "Inactive")
                db.session.commit()
                flash(f"{mailbox.name} is now {'active' if mailbox.active else 'inactive'}.", "success")
            elif action == "delete":
                mailbox = tenant_record_or_404(ClientMailbox, request.form.get("mailbox_id", type=int))
                name = mailbox.name
                db.session.delete(mailbox)
                audit("client mailbox deleted", name, "")
                db.session.commit()
                flash(f"{name} removed.", "success")
            elif action == "poll_now":
                mailbox = tenant_record_or_404(ClientMailbox, request.form.get("mailbox_id", type=int))
                try:
                    count = _poll_client_mailbox(mailbox)
                    flash(f"Checked {mailbox.name}: {count} new ticket/message(s) created.", "success")
                except Exception as error:
                    mailbox.last_polled_at = now()
                    mailbox.last_poll_status = "error"
                    mailbox.last_poll_error = str(error)[:2000]
                    db.session.commit()
                    flash(f"Could not connect to {mailbox.name}: {error}", "error")
            return redirect(url_for("client_mailboxes_admin"))
        mailboxes = tenant_query(ClientMailbox).order_by(ClientMailbox.name).all()
        organizations = tenant_query(ClientOrganization).order_by(ClientOrganization.name).all()
        return render_template(
            "client_mailboxes_admin.html", mailboxes=mailboxes, organizations=organizations,
        )

    @app.route("/client-management/contacts", methods=["GET", "POST"])
    @require_client_management
    def client_contacts():
        organizations = visible_client_organization_query(current_user).filter_by(active=True).order_by(ClientOrganization.name).all()
        if request.method == "POST" and request.form.get("action") == "erase":
            if not role_at_least(current_user.effective_role, "admin"):
                abort(403, description="Only an administrator can erase a client contact's personal data.")
            contact = tenant_record_or_404(ClientContact, request.form.get("contact_id", type=int))
            original_email = contact.email
            try:
                erase_client_contact(contact)
                db.session.commit()
                flash(f"{original_email}'s personal data has been erased.", "success")
            except ValueError as error:
                db.session.rollback()
                flash(str(error), "error")
            return redirect(url_for("client_contacts"))
        if request.method == "POST":
            organization = visible_client_organization_query(current_user).filter_by(id=request.form.get("organization_id", type=int), active=True).first_or_404()
            name, email = request.form.get("name", "").strip(), request.form.get("email", "").strip().lower()
            if not name or not email or "@" not in email:
                flash("A valid name and email address are required.", "error")
            elif tenant_query(ClientContact).filter(func.lower(ClientContact.email) == email).first():
                flash("That client email address already exists.", "error")
            else:
                contact_fields = client_custom_fields_for("contact")
                custom_values, custom_error = parse_client_custom_field_values(contact_fields, request.form)
                if custom_error:
                    flash(custom_error, "error")
                    return redirect(url_for("client_contacts"))
                row = ClientContact(
                    tenant_id=current_user.tenant_id, organization_id=organization.id,
                    name=name, email=email, phone=request.form.get("phone", "").strip(),
                    job_title=request.form.get("job_title", "").strip(),
                    preferred_language=request.form.get("preferred_language", "English").strip() or "English",
                    custom_fields=custom_values,
                )
                db.session.add(row)
                audit("client contact created", email, organization.name)
                db.session.commit()
                return redirect(url_for("client_contacts"))
        contacts = visible_client_contact_query(current_user).options(selectinload(ClientContact.organization)).order_by(ClientContact.name).all()
        contact_fields = client_custom_fields_for("contact")
        return render_template(
            "client_contacts.html", contacts=contacts, organizations=organizations, contact_fields=contact_fields,
        )

    @app.get("/client-management/contacts/<int:contact_id>/export")
    @require_client_management
    def client_contact_export(contact_id):
        """GDPR Art. 20 (data portability) for a customer contact, mirroring
        profile_export() -- a structured, machine-readable export of this
        contact's own data and support conversation history."""
        contact = visible_client_contact_query(current_user).filter_by(id=contact_id).first_or_404()
        payload = {
            "name": contact.name, "email": contact.email, "phone": contact.phone,
            "job_title": contact.job_title, "preferred_language": contact.preferred_language,
            "organization": contact.organization.name if contact.organization else None,
            "created_at": contact.created_at.isoformat() if contact.created_at else None,
            "erased_at": contact.erased_at.isoformat() if contact.erased_at else None,
            "tickets": [
                {
                    "number": ticket.number, "subject": ticket.subject, "status": ticket.status,
                    "created_at": ticket.created_at.isoformat(),
                    "messages": [
                        {
                            "body": message.body, "visibility": message.visibility,
                            "created_at": message.created_at.isoformat(),
                        }
                        for message in ticket.messages if message.visibility == "public"
                    ],
                }
                for ticket in ClientTicket.query.filter_by(
                    tenant_id=contact.tenant_id, contact_id=contact.id,
                ).order_by(ClientTicket.created_at.desc()).all()
            ],
        }
        response = Response(
            json.dumps(payload, indent=2, sort_keys=True), mimetype="application/json",
        )
        response.headers["Content-Disposition"] = f'attachment; filename="client-contact-{contact.id}-data-export.json"'
        audit("export", contact.email, "Client contact data export (GDPR Art. 20)")
        db.session.commit()
        return response

    @app.get("/admin")
    @roles("admin")
    @require_action("security_administer")
    def admin_home():
        return render_template("admin_home.html")

    @app.get("/admin/access")
    @roles("admin")
    @require_action("security_administer")
    def admin_access():
        # A GLPI-style Access Control hub: Users has its own dedicated route
        # already; Groups & Teams and Directory link into the existing
        # itil_admin() sections (that mega-page's team/AD-mapping logic is
        # not duplicated here, just linked to by anchor) rather than being
        # torn out into new routes in this pass -- Roles & Permissions is
        # the one genuinely new page (see admin_roles()).
        return render_template("admin_access.html")

    # requester/agent/manager/admin are editable; superadmin is never
    # overridable (always implicitly granted everywhere, per this app's
    # existing convention -- see RolePolicyOverride's docstring).
    EDITABLE_POLICY_ROLES = ("requester", "agent", "manager", "admin")

    # Every admin panel route is gated by @roles("admin")/@roles("superadmin")
    # -- a hardcoded role-membership check that runs before, and completely
    # independently of, this action-based policy system. Granting a
    # non-admin role one of these three admin-tier actions here can
    # therefore never open panel access for them (confirmed: every route
    # checking these actions is also @roles("admin")-gated, except the
    # CMDB Discovery routes, which check security_administer alone -- so
    # that one exception is deliberately still left editable for agent/
    # manager below). Hiding the other, structurally pointless checkboxes
    # for non-admin roles avoids silently configuring something that can
    # never take effect, with no error or explanation, the way it
    # previously did.
    ADMIN_PANEL_GATED_ACTIONS = {"administer", "platform_administer"}

    # A full audit (every effective_role_has_action()/@require_action call
    # site in app.py, both decorator and inline) found these actions are
    # never checked anywhere, for any role, browser or REST API -- real
    # authorization for the operations they'd nominally cover (ticket
    # delete, approval decisions, task close/reopen, etc.) happens through
    # entirely separate, hardcoded @roles(...) + team-membership checks
    # that don't consult this policy at all. Toggling these here is a
    # structural no-op for every role, not a role-specific gap like
    # ADMIN_PANEL_GATED_ACTIONS above -- shown as fixed/informational
    # rather than editable, so this page never again promises control it
    # can't deliver. "create" is a partial case (checked for REST API v1
    # clients, not the browser UI) and is called out separately in the
    # page copy rather than lumped in here, since it does have real effect
    # for one surface.
    UNENFORCED_ACTIONS = {
        "delete", "purge", "approve", "accept", "close", "reopen",
        "delegate", "relate", "discover", "read",
    }

    @app.route("/admin/roles", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def admin_roles():
        # config/authorization.json is the Git-backed recommended baseline
        # (loaded once per process via serviceops_core.security.load_policy,
        # @lru_cache -- never mutated at runtime, so no cache-invalidation
        # concern). RolePolicyOverride is the DB-backed, tenant-scoped layer
        # an admin can adjust on top of it; "reset to recommended" for a
        # role is just deleting that role's override rows.
        policy = load_policy()
        tenant_id = current_user.tenant_id
        if request.method == "POST":
            action = request.form.get("action", "save")
            if action == "reset":
                role = request.form.get("role", "")
                if role not in EDITABLE_POLICY_ROLES:
                    abort(400)
                removed = RolePolicyOverride.query.filter_by(tenant_id=tenant_id, role=role).delete()
                audit("configure", "Role policy reset", f"{role} reset to recommended ({removed} override(s) removed)")
                db.session.commit()
                flash(f"{role.capitalize()}'s permissions were reset to the ITIL-recommended baseline.", "success")
            else:
                existing = {
                    (row.role, row.action): row
                    for row in RolePolicyOverride.query.filter_by(tenant_id=tenant_id).all()
                }
                changed = 0
                for role in EDITABLE_POLICY_ROLES:
                    baseline_actions = set(policy["roles"].get(role, ()))
                    for act in policy["actions"]:
                        if act in UNENFORCED_ACTIONS or (role != "admin" and act in ADMIN_PANEL_GATED_ACTIONS):
                            # Checkbox is hidden in the template for these
                            # (role, action) combinations -- the form never
                            # submits a value for them, which would
                            # otherwise read as "unchecked" and, for any
                            # action a role's baseline actually grants
                            # (e.g. manager's baseline includes "approve"),
                            # get misread as an explicit request to revoke
                            # it. Skip entirely so a save never touches
                            # overrides for something the UI doesn't even
                            # let the admin see or intend to change.
                            continue
                        granted = request.form.get(f"grant__{role}__{act}") == "on"
                        matches_baseline = granted == (act in baseline_actions)
                        row = existing.get((role, act))
                        if matches_baseline:
                            if row:
                                db.session.delete(row)
                                changed += 1
                        elif row:
                            if row.is_granted != granted:
                                row.is_granted = granted
                                row.updated_by_id = current_user.id
                                changed += 1
                        else:
                            db.session.add(RolePolicyOverride(
                                tenant_id=tenant_id, role=role, action=act,
                                is_granted=granted, updated_by_id=current_user.id,
                            ))
                            changed += 1
                if changed:
                    audit("configure", "Role policy", f"{changed} role/action override(s) changed")
                    db.session.commit()
                    flash(f"Saved {changed} permission change(s).", "success")
                else:
                    flash("No changes to save.", "success")
            return redirect(url_for("admin_roles"))

        overrides = {
            (row.role, row.action): row.is_granted
            for row in RolePolicyOverride.query.filter_by(tenant_id=tenant_id).all()
        }
        effective_role_actions = {}
        for role in policy["roles"]:
            baseline_actions = set(policy["roles"].get(role, ()))
            if role not in EDITABLE_POLICY_ROLES:
                effective_role_actions[role] = baseline_actions
                continue
            effective = set(baseline_actions)
            for act in policy["actions"]:
                override = overrides.get((role, act))
                if override is True:
                    effective.add(act)
                elif override is False:
                    effective.discard(act)
            effective_role_actions[role] = effective
        has_overrides = {
            role: any(r == role for r, _ in overrides) for role in EDITABLE_POLICY_ROLES
        }
        return render_template(
            "admin_roles.html", actions=policy["actions"], role_actions=effective_role_actions,
            editable_roles=EDITABLE_POLICY_ROLES, baseline_role_actions=policy["roles"],
            has_overrides=has_overrides,
            admin_panel_gated_actions=ADMIN_PANEL_GATED_ACTIONS,
            unenforced_actions=UNENFORCED_ACTIONS,
        )

    @app.get("/profile/sessions")
    @login_required
    def my_sessions():
        rows = UserSession.query.filter_by(user_id=current_user.id).order_by(
            UserSession.last_seen_at.desc()
        ).all()
        return render_template("sessions.html", sessions=rows, admin_view=False)

    @app.get("/admin/sessions")
    @roles("admin")
    @require_action("security_administer")
    def admin_sessions():
        rows = tenant_query(UserSession).order_by(UserSession.last_seen_at.desc()).limit(1000).all()
        return render_template("sessions.html", sessions=rows, admin_view=True)

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

    @app.route("/platform/tenants", methods=["GET", "POST"])
    @roles("superadmin")
    @require_action("platform_administer")
    def platform_tenants():
        """Cross-tenant platform administration. Deliberately bypasses the
        normal tenant_query() scoping every other admin screen uses -- only
        a superadmin (not a plain per-tenant admin) reaches this route at
        all (see roles()/require_action() above), and every query here is
        Tenant.query, never tenant_query(Tenant), by design."""
        if request.method == "POST":
            action = request.form.get("action")
            if action == "create_tenant":
                slug = request.form.get("slug", "").strip().lower()[:80]
                name = request.form.get("name", "").strip()[:160]
                if not slug or not name or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
                    flash("Enter a name and a lowercase, hyphen-safe slug.", "error")
                    return redirect(url_for("platform_tenants"))
                if Tenant.query.filter_by(slug=slug).first():
                    flash(f"A tenant with slug \"{slug}\" already exists.", "error")
                    return redirect(url_for("platform_tenants"))
                tenant = Tenant(slug=slug, name=name)
                db.session.add(tenant)
                audit("create", f"Tenant {slug}", name)
                flash(f"Tenant \"{name}\" created.", "success")
            elif action == "set_tenant_active":
                tenant = Tenant.query.filter_by(id=int(request.form["tenant_id"])).first_or_404()
                if tenant.id == current_user.tenant_id and not request.form.get("active"):
                    flash("You cannot deactivate the tenant your own account belongs to.", "error")
                    return redirect(url_for("platform_tenants"))
                tenant.active = bool(request.form.get("active"))
                audit("configure", f"Tenant {tenant.slug}", f"active={tenant.active}")
                flash(f"Tenant \"{tenant.name}\" {'activated' if tenant.active else 'deactivated'}.", "success")
            else:
                abort(400)
            db.session.commit()
            return redirect(url_for("platform_tenants"))
        tenants = Tenant.query.order_by(Tenant.id).all()
        user_counts = dict(
            db.session.query(User.tenant_id, db.func.count(User.id)).group_by(User.tenant_id).all()
        )
        return render_template("platform_tenants.html", tenants=tenants, user_counts=user_counts)

    @app.route("/admin/api-clients", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def api_clients_admin():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            try:
                acting_user_id = int(request.form.get("acting_user_id", ""))
            except (TypeError, ValueError):
                abort(400, description="Select a valid acting user.")
            acting_user = tenant_query(User).filter_by(
                id=acting_user_id, active=True
            ).first()
            scopes = sorted(set(request.form.getlist("scopes")))
            if not name or len(name) > 160:
                abort(400, description="Client name must contain 1-160 characters.")
            if not acting_user:
                abort(400, description="The acting user must be active in this tenant.")
            if not scopes or not set(scopes).issubset(API_SCOPES):
                abort(400, description="Select one or more valid API scopes.")
            token, prefix, token_hash = create_api_token()
            client = APIClient(
                name=name, token_prefix=prefix, token_hash=token_hash,
                scopes_json=json.dumps(scopes),
                acting_user_id=acting_user.id,
                created_by_id=current_user.id,
                tenant_id=current_user.tenant_id,
            )
            db.session.add(client)
            audit(
                "api client create", name,
                f"acting_user={acting_user.username}; scopes={','.join(scopes)}",
            )
            db.session.commit()
            return render_template(
                "api_clients.html",
                clients=APIClient.query.filter_by(
                    tenant_id=current_user.tenant_id
                ).order_by(APIClient.created_at.desc()).all(),
                users=tenant_query(User).filter_by(active=True).order_by(User.name).all(),
                available_scopes=sorted(API_SCOPES),
                new_token=token,
                new_client_name=name,
            )
        return render_template(
            "api_clients.html",
            clients=APIClient.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(APIClient.created_at.desc()).all(),
            users=tenant_query(User).filter_by(active=True).order_by(User.name).all(),
            available_scopes=sorted(API_SCOPES),
            new_token=None,
            new_client_name=None,
        )

    @app.post("/admin/api-clients/<int:client_id>/revoke")
    @roles("admin")
    @require_action("security_administer")
    def api_client_revoke(client_id):
        client = APIClient.query.filter_by(
            id=client_id, tenant_id=current_user.tenant_id
        ).first_or_404()
        if client.active:
            client.active = False
            client.revoked_at = now()
            audit("api client revoke", client.name, client.client_id)
            db.session.commit()
        return redirect(url_for("api_clients_admin"))

    @app.route("/admin/integrations", methods=["GET", "POST"])
    @roles("admin")
    @require_action("configure")
    def integrations_admin():
        revealed_token = None
        revealed_secret = None
        if request.method == "POST":
            action = request.form.get("action")
            if action == "create_connection":
                name = request.form.get("name", "").strip()
                kind = request.form.get("kind", "")
                endpoint = request.form.get("endpoint", "").strip()
                if (
                    not name or len(name) > 160
                    or kind not in {"webhook", "teams", "siem"}
                    or not integration_endpoint_valid(endpoint)
                ):
                    abort(400, description=(
                        "A name, supported kind and public HTTPS endpoint are required."
                    ))
                secret = (
                    request.form.get("secret", "").strip()
                    if kind in {"webhook", "siem"} else ""
                )
                if kind in {"webhook", "siem"} and not secret:
                    secret = secrets.token_urlsafe(32)
                    revealed_secret = secret
                encrypted = (
                    settings_cipher().encrypt(secret.encode()).decode()
                    if secret else None
                )
                db.session.add(IntegrationConnection(
                    name=name, kind=kind, endpoint=endpoint,
                    secret_encrypted=encrypted,
                    created_by_id=current_user.id,
                    tenant_id=current_user.tenant_id,
                ))
                audit("integration create", name, kind)
            elif action == "create_monitoring_source":
                name = request.form.get("name", "").strip()
                group = tenant_record_or_404(
                    SupportGroup, int(request.form.get("group_id", "0"))
                )
                if (
                    not name or len(name) > 160 or not group.active
                    or group.group_type != "IT Fulfillment"
                ):
                    abort(400, description=(
                        "A name and active IT fulfillment team are required."
                    ))
                token, prefix, token_hash = create_api_token()
                source = MonitoringSource(
                    name=name, token_prefix=prefix, token_hash=token_hash,
                    assignment_group_id=group.id,
                    created_by_id=current_user.id,
                    tenant_id=current_user.tenant_id,
                )
                db.session.add(source)
                db.session.flush()
                revealed_token = {
                    "token": token, "source_id": source.source_id, "name": name,
                }
                audit("monitoring source create", name, group.name)
            else:
                abort(400)
            db.session.commit()
        return render_template(
            "integrations.html",
            connections=IntegrationConnection.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(IntegrationConnection.name).all(),
            sources=MonitoringSource.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(MonitoringSource.name).all(),
            deliveries=IntegrationDelivery.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(IntegrationDelivery.id.desc()).limit(50).all(),
            outbox=OutboxEvent.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(OutboxEvent.id.desc()).limit(50).all(),
            teams=tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment", active=True
            ).order_by(SupportGroup.name).all(),
            revealed_token=revealed_token,
            revealed_secret=revealed_secret,
        )

    @app.post("/admin/integrations/process")
    @roles("admin")
    @require_action("configure")
    def integrations_process():
        # Capped tightly: this runs synchronously in the request thread, and
        # each event may make an SMTP/webhook call with its own network
        # timeout. The background tools/outbox_worker.py is the primary,
        # unbounded drain path; this route is a manual nudge, not a bulk tool.
        count = process_outbox(limit=5)
        audit("integration process", "Outbox", f"{count} event(s)")
        db.session.commit()
        flash(f"Processed {count} outbox event(s).", "success")
        return redirect(url_for("integrations_admin"))

    @app.route("/admin/workflows", methods=["GET", "POST"])
    @roles("admin")
    @require_action("configure")
    def workflows_admin():
        simulation = None
        if request.method == "POST":
            action = request.form.get("action")
            if action == "deploy":
                result = deploy_workflow_package(current_user.id)
                audit(
                    "workflow deploy", "Git workflow package",
                    f"{result['package_hash']}; {result['published']} published",
                )
                db.session.commit()
                flash(
                    f"Automation rules validated; {result['published']} new version(s) published.",
                    "success",
                )
                return redirect(url_for("workflows_admin"))
            if action == "simulate":
                try:
                    context = json.loads(request.form.get("context_json", "{}"))
                    if not isinstance(context, dict):
                        raise ValueError
                    simulation = simulate_workflows(
                        request.form.get("event_type", ""), context,
                        current_user.tenant_id,
                    )
                except (json.JSONDecodeError, ValueError, KeyError) as error:
                    abort(400, description=f"Simulation input is invalid: {error}")
                audit("workflow simulate", request.form.get("event_type", ""),
                      f"{len(simulation)} match(es)")
                db.session.commit()
            elif action == "manual_trigger":
                ticket = tenant_record_or_404(
                    Ticket, int(request.form.get("ticket_id", ""))
                )
                context = ticket_workflow_context(ticket)
                context["triggered_by"] = current_user.username
                job = queue_workflow_event(
                    "ticket.manual", "ticket", ticket.id, context,
                    tenant_id=ticket.tenant_id,
                )
                audit("workflow manual trigger", ticket.number, job.event_id)
                db.session.commit()
                flash(f"Manual workflow event queued for {ticket.number}.", "success")
                return redirect(url_for("workflows_admin"))
            elif action == "replay_dead":
                job = tenant_record_or_404(
                    WorkflowJob, int(request.form.get("job_id", ""))
                )
                if job.state != "Dead":
                    abort(409, description="Only dead workflow jobs can be replayed.")
                job.state = "Retry"
                job.attempts = 0
                job.available_at = now()
                job.last_error = None
                audit("workflow replay", job.event_id, f"{job.target_type}:{job.target_id}")
                db.session.commit()
                flash("Dead workflow job queued for controlled replay.", "success")
                return redirect(url_for("workflows_admin"))
            elif action == "create_schedule":
                key = request.form.get("schedule_key", "").strip()
                name = request.form.get("name", "").strip()
                if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,119}", key):
                    abort(400, description=(
                        "Schedule key must be 3-120 lowercase letters, numbers or hyphens."
                    ))
                if not name or len(name) > 160:
                    abort(400, description="Schedule name must contain 1-160 characters.")
                try:
                    ticket = tenant_record_or_404(
                        Ticket, int(request.form.get("ticket_id", ""))
                    )
                    interval = int(request.form.get("interval_minutes", ""))
                    start_text = request.form.get("next_run_at", "").strip()
                    next_run = datetime.fromisoformat(start_text) if start_text else now()
                    if next_run.tzinfo is None:
                        next_run = next_run.replace(tzinfo=timezone.utc)
                except (TypeError, ValueError):
                    abort(400, description="Schedule target, interval, or start time is invalid.")
                if interval < 1 or interval > 525600:
                    abort(400, description="Schedule interval must be 1-525600 minutes.")
                if tenant_query(WorkflowSchedule).filter_by(schedule_key=key).first():
                    abort(409, description="A schedule with that key already exists.")
                db.session.add(WorkflowSchedule(
                    schedule_key=key, name=name, ticket_id=ticket.id,
                    interval_minutes=interval, next_run_at=next_run,
                    created_by_id=current_user.id,
                ))
                audit("workflow schedule create", key,
                      f"{ticket.number}; every {interval} minute(s)")
                db.session.commit()
                flash(f"Workflow schedule {name} created.", "success")
                return _admin_referrer_redirect("workflows_admin")
            elif action == "toggle_schedule":
                schedule = tenant_record_or_404(
                    WorkflowSchedule, int(request.form.get("schedule_id", ""))
                )
                schedule.active = not schedule.active
                if schedule.active and schedule.next_run_at < now():
                    schedule.next_run_at = now()
                audit(
                    "workflow schedule toggle", schedule.schedule_key,
                    "active" if schedule.active else "disabled",
                )
                db.session.commit()
                flash("Workflow schedule status updated.", "success")
                return _admin_referrer_redirect("workflows_admin")
            else:
                abort(400)
        definitions = tenant_query(WorkflowDefinition).order_by(
            WorkflowDefinition.workflow_key
        ).all()
        return render_template(
            "workflows.html", definitions=definitions, simulation=simulation,
            package=load_workflow_package(),
            package_hash=package_digest(load_workflow_package()),
            jobs=WorkflowJob.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(WorkflowJob.id.desc()).limit(50).all(),
            executions=WorkflowExecution.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(WorkflowExecution.id.desc()).limit(50).all(),
            tickets=tenant_query(Ticket).order_by(Ticket.updated_at.desc()).limit(100).all(),
        )

    @app.get("/admin/workflows/scheduled")
    @roles("admin")
    @require_action("configure")
    def workflows_scheduled():
        """B-322: scheduled automation gets its own isolated page instead
        of sharing a URL/anchor with the published-rules page (previously
        both admin_home Quick Find cards led to the exact same page)."""
        return render_template(
            "workflows_scheduled.html",
            tickets=tenant_query(Ticket).order_by(Ticket.updated_at.desc()).limit(100).all(),
            schedules=tenant_query(WorkflowSchedule).order_by(
                WorkflowSchedule.name
            ).all(),
        )

    @app.get("/branding/company-logo.png")
    def company_logo():
        path = os.path.join(app.config["UPLOAD_FOLDER"], "company-logo.png")
        if not os.path.exists(path):
            abort(404)
        return send_from_directory(app.config["UPLOAD_FOLDER"], "company-logo.png",
                                   mimetype="image/png", max_age=300)

    @app.get("/admin/settings")
    @roles("admin")
    @require_action("administer")
    def system_settings():
        """B-320: isolated settings pages, not one long scrolling/tabbed
        mega-page -- this is now just an index card grid; the actual
        editable fields live on system_settings_category(), one real URL
        per category, matching how every other admin destination works."""
        return render_template(
            "system_settings.html", group_meta=SETTING_GROUP_META,
            categories=list(SETTING_DEFINITIONS.keys()),
        )

    def _infrastructure_rows():
        return [
            ("Deployment profile", app.config.get("DEPLOYMENT_PROFILE") or "Default profile", "Docker environment / Helm values"),
            ("Database", app.config["SQLALCHEMY_DATABASE_URI"].split("@")[-1], "DATABASE_URL / Kubernetes Secret"),
            ("Upload storage", app.config.get("UPLOAD_FOLDER") or "Not configured", "Docker volume / Kubernetes PVC"),
            ("Application replicas", os.getenv("REPLICA_COUNT") or "1 (local Compose default)", "Docker Compose / Helm"),
            ("Ingress and TLS", os.getenv("PUBLIC_BASE_URL") or "Managed outside ServiceOps", "Reverse proxy / Kubernetes Ingress"),
        ]

    @app.route("/admin/settings/<category>", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def system_settings_category(category):
        # "branding" (company logo) and "infrastructure" (read-only runtime
        # values) are not real SETTING_DEFINITIONS groups, but get the same
        # isolated-page treatment as the 9 real ones for consistency.
        if category not in SETTING_DEFINITIONS and category not in ("branding", "infrastructure"):
            abort(404)
        definitions = SETTING_DEFINITIONS.get(category, [])
        if request.method == "POST":
            errors, restart_required, changed = [], False, []
            for definition in definitions:
                key, field_type = definition["key"], definition["type"]
                if key not in request.form and field_type != "bool":
                    continue
                submitted = request.form.get(key)
                if field_type == "bool":
                    submitted = "true" if submitted else "false"
                elif field_type == "secret" and not submitted:
                    continue
                else:
                    submitted = (submitted or "").strip()
                if field_type == "color" and not re.fullmatch(r"#[0-9a-fA-F]{6}", submitted):
                    errors.append(f"{definition['label']} must be a six-digit hex color.")
                    continue
                if field_type == "json":
                    try:
                        parsed = json.loads(submitted)
                        if not isinstance(parsed, dict):
                            raise ValueError
                        submitted = json.dumps(parsed, separators=(",", ":"))
                    except (json.JSONDecodeError, ValueError):
                        errors.append(f"{definition['label']} must be a JSON object.")
                        continue
                if field_type == "int":
                    try:
                        number = int(submitted)
                        if number < definition["min"] or number > definition["max"]:
                            raise ValueError
                        submitted = str(number)
                    except ValueError:
                        errors.append(
                            f"{definition['label']} must be between {definition['min']} and {definition['max']}.")
                        continue
                if field_type == "choice" and submitted not in definition["choices"]:
                    errors.append(f"{definition['label']} has an invalid value.")
                    continue
                old_value = setting_value(key, definition.get("default", ""))
                if old_value == submitted:
                    continue
                encrypted = field_type == "secret"
                stored = settings_cipher().encrypt(submitted.encode()).decode() if encrypted else submitted
                row = db.session.get(PlatformSetting, key)
                if not row:
                    row = PlatformSetting(key=key)
                    db.session.add(row)
                row.value, row.encrypted, row.updated_by_id = stored, encrypted, current_user.id
                changed.append(key)
                restart_required = restart_required or not definition["live"]
            if category == "branding":
                logo = request.files.get("company_logo")
                if logo and logo.filename:
                    header = logo.stream.read(8)
                    logo.stream.seek(0)
                    if header != b"\x89PNG\r\n\x1a\n":
                        errors.append("Company logo must be a valid PNG file.")
                    elif request.content_length and request.content_length > 5 * 1024 * 1024:
                        errors.append("Company logo must be smaller than 5 MB.")
                    else:
                        logo.save(os.path.join(app.config["UPLOAD_FOLDER"], "company-logo.png"))
                        changed.append("COMPANY_LOGO")
            if category == "sign_in_and_directory":
                # Only meaningful (and only submitted at all) from this
                # category's own page -- checking it unconditionally used to
                # work because every category's fields lived in one shared
                # form; split across isolated pages, saving any *other*
                # category would submit none of these three fields and
                # always fail this check.
                effective_local = request.form.get("LOCAL_AUTH_ENABLED")
                effective_ldap = request.form.get("LDAP_ENABLED")
                effective_keycloak = request.form.get("KEYCLOAK_ENABLED")
                if not any((effective_local, effective_ldap, effective_keycloak)):
                    errors.append("At least one authentication method must remain enabled.")
            if errors:
                db.session.rollback()
                for message in errors:
                    flash(message, "error")
            else:
                audit("update", "Platform settings", ", ".join(changed) or "No value changes")
                db.session.commit()
                flash("Platform settings saved." + (
                    " Restart or roll out all application instances to apply marked settings."
                    if restart_required else ""), "success")
            return _admin_referrer_redirect("system_settings_category", category=category)
        values = {}
        for definition in definitions:
            value = setting_value(definition["key"], definition.get("default", ""))
            values[definition["key"]] = "" if definition["type"] == "secret" else value
            definition["configured"] = bool(value) if definition["type"] == "secret" else False
        title, description = (
            ("Company logo", "PNG only, maximum 5 MB. Recommended transparent canvas, up to 600 × 200 px.")
            if category == "branding" else
            ("Runtime environment", "These values describe where this ServiceOps instance is running. They are read-only here because changing a database, volume, replica count, or TLS endpoint requires a controlled Docker Compose or Kubernetes rollout.")
            if category == "infrastructure" else
            SETTING_GROUP_META[category]
        )
        ad_context = {}
        if category == "sign_in_and_directory":
            # B-322: AD group mapping and directory sync render on this same
            # page, right below the LDAP/Keycloak connection fields above --
            # user-reported complaint that "AD related configs" were split
            # across Platform settings and Service delivery & governance.
            teams = tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment"
            ).order_by(SupportGroup.name).all()
            ad_context = dict(
                teams=teams,
                directory_mappings=DirectoryGroupMapping.query.order_by(
                    DirectoryGroupMapping.directory_group
                ).all(),
                ldap_enabled=setting_bool("LDAP_ENABLED"),
                ldap_sync_enabled=setting_bool("LDAP_SYNC_ENABLED"),
                ldap_sync_interval_minutes=setting_int("LDAP_SYNC_INTERVAL_MINUTES", 60),
                ldap_sync_result=session.pop("ldap_sync_result", None),
            )
        return render_template(
            "system_settings_category.html", category=category, title=title, description=description,
            definitions=definitions, values=values,
            infrastructure=_infrastructure_rows() if category == "infrastructure" else None,
            has_company_logo_field=category == "branding",
            **ad_context,
        )

    @app.get("/admin/audit")
    @roles("admin")
    @require_action("report")
    def audit_log():
        # Integrity verification walks and HMAC-checks the entire tenant audit
        # history; running it on every page view does not scale as the log
        # grows, so it only runs when explicitly requested.
        integrity = verify_audit_chain(current_user.tenant_id) if request.args.get("verify") == "1" else None
        query = tenant_query(Audit)
        q = request.args.get("q", "").strip()
        if q:
            query = query.filter(db.or_(
                Audit.action.ilike(f"%{q}%"), Audit.target.ilike(f"%{q}%"),
            ))
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 100
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.order_by(Audit.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        return render_template(
            "audit.html",
            rows=rows, q=q, page=page, pages=pages, total=total,
            integrity=integrity,
            keys=AuditIntegrityKey.query.filter_by(
                tenant_id=current_user.tenant_id
            ).order_by(AuditIntegrityKey.id.desc()).all(),
            retention=AuditRetentionPolicy.query.filter_by(
                tenant_id=current_user.tenant_id
            ).one_or_none(),
            siem_connections=IntegrationConnection.query.filter_by(
                tenant_id=current_user.tenant_id, kind="siem", active=True
            ).count(),
        )

    @app.get("/admin/system-health")
    @roles("admin")
    @require_action("security_administer")
    def system_health():
        db_healthy, db_latency_ms = True, None
        db_check_started = time_module.monotonic()
        try:
            db.session.execute(db.text("SELECT 1"))
            db_latency_ms = round((time_module.monotonic() - db_check_started) * 1000, 2)
        except Exception:  # noqa: BLE001 - this check's whole point is surfacing DB failure
            db_healthy = False

        worker_heartbeat = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT")
        worker_last_seen = None
        worker_healthy = False
        if worker_heartbeat and worker_heartbeat.value:
            try:
                worker_last_seen = datetime.fromisoformat(worker_heartbeat.value)
                worker_healthy = (now() - worker_last_seen) < timedelta(seconds=30)
            except ValueError:
                pass

        active_cutoff = now() - timedelta(minutes=15)
        active_users = tenant_query(User).filter(
            User.last_seen_at.isnot(None), User.last_seen_at >= active_cutoff,
        ).order_by(User.last_seen_at.desc()).all()
        # Surfaces *how* each active user is connected (mobile app vs
        # browser) -- both now correctly count as "active" (see
        # authenticate_api_request()), but an admin watching this page
        # during an incident still needs to tell them apart.
        active_mobile_user_ids = {
            row.acting_user_id for row in APIClient.query.filter(
                APIClient.acting_user_id.in_([user.id for user in active_users]),
                APIClient.client_kind == "mobile",
                APIClient.active.is_(True),
                APIClient.last_used_at.isnot(None),
                APIClient.last_used_at >= active_cutoff,
            )
        } if active_users else set()

        error_query, filters = _filtered_application_log_query(current_user)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total_errors = error_query.count()
        pages = max(1, (total_errors + per_page - 1) // per_page)
        page = min(page, pages)
        error_rows = error_query.order_by(ApplicationLog.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()

        error_last_hour = ApplicationLog.query.filter(
            db.or_(ApplicationLog.tenant_id.is_(None), ApplicationLog.tenant_id == current_user.tenant_id),
            ApplicationLog.level.in_(["ERROR", "CRITICAL"]),
            ApplicationLog.created_at >= now() - timedelta(hours=1),
        ).count()
        last_backup_at, backup_healthy, backup_rpo_hours, _ = _recovery_set_status()

        return render_template(
            "system_health.html",
            app_version=APP_VERSION,
            app_start_time=APP_START_TIME,
            db_healthy=db_healthy, db_latency_ms=db_latency_ms,
            worker_healthy=worker_healthy, worker_last_seen=worker_last_seen,
            active_users=active_users, active_user_count=len(active_users),
            active_mobile_user_ids=active_mobile_user_ids,
            error_rows=error_rows, page=page, pages=pages, total_errors=total_errors,
            error_last_hour=error_last_hour, **filters,
            last_backup_at=last_backup_at, backup_healthy=backup_healthy,
            backup_rpo_hours=backup_rpo_hours,
            backup_offsite=setting_value("LAST_BACKUP_OFFSITE_STATUS", "not-recorded"),
            total_users=tenant_query(User).filter_by(active=True).count(),
            open_tickets=tenant_query(Ticket).filter(
                Ticket.state.notin_(["Resolved", "Closed", "Cancelled"])
            ).count(),
            deployment_mode=os.getenv("DEPLOYMENT_MODE", "unknown"),
            gunicorn_workers=os.getenv("GUNICORN_WORKERS", "2"),
        )

    @app.get("/admin/system-health/performance.json")
    @roles("admin")
    @require_action("security_administer")
    def system_health_performance():
        try:
            hours = max(1, min(168, int(request.args.get("hours", "6"))))
        except ValueError:
            hours = 6
        since = now() - timedelta(hours=hours)
        samples = PerformanceSample.query.filter(
            PerformanceSample.sampled_at >= since,
        ).order_by(PerformanceSample.sampled_at).all()
        points = []
        previous = None
        for sample in samples:
            if previous is not None:
                elapsed = (sample.sampled_at - previous.sampled_at).total_seconds()
                request_delta = sample.cumulative_requests - previous.cumulative_requests
                error_delta = sample.cumulative_errors - previous.cumulative_errors
                duration_delta = sample.cumulative_duration_ms - previous.cumulative_duration_ms
                points.append({
                    "at": sample.sampled_at.isoformat(),
                    "requests_per_sec": round(request_delta / elapsed, 3) if elapsed > 0 and request_delta >= 0 else 0,
                    "error_rate": round(error_delta / request_delta, 4) if request_delta > 0 else 0,
                    "avg_latency_ms": round(duration_delta / request_delta, 2) if request_delta > 0 else 0,
                    "worker_healthy": sample.worker_healthy,
                })
            previous = sample
        return jsonify(
            deployment_mode=os.getenv("DEPLOYMENT_MODE", "unknown"),
            gunicorn_workers=os.getenv("GUNICORN_WORKERS", "2"),
            points=points,
        )

    @app.get("/admin/system-health/errors/export")
    @roles("admin")
    @require_action("security_administer")
    def system_health_errors_export():
        error_query, _filters = _filtered_application_log_query(current_user)
        rows = error_query.order_by(ApplicationLog.created_at.desc()).limit(10000).all()
        fmt = request.args.get("format", "csv").lower()
        fields = ["id", "created_at", "level", "logger_name", "message", "path", "method",
                  "request_id", "user_id", "tenant_id", "traceback"]

        def row_dict(row):
            return {
                "id": row.id,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "level": row.level,
                "logger_name": row.logger_name,
                "message": row.message,
                "path": row.path,
                "method": row.method,
                "request_id": row.request_id,
                "user_id": row.user_id,
                "tenant_id": row.tenant_id,
                "traceback": row.traceback,
            }

        audit("export", "Application error log", f"format={fmt} rows={len(rows)}")
        db.session.commit()
        return _export_response([row_dict(r) for r in rows], fields, fmt, "serviceops-error-log")

    @app.post("/admin/system-health/errors/clear")
    @roles("admin")
    @require_action("security_administer")
    def system_health_clear_errors():
        deleted = ApplicationLog.query.filter(
            db.or_(ApplicationLog.tenant_id.is_(None), ApplicationLog.tenant_id == current_user.tenant_id)
        ).delete(synchronize_session=False)
        audit("purge", "Application error log", f"{deleted} entries cleared")
        db.session.commit()
        flash(f"Cleared {deleted} error log entries.", "success")
        return redirect(url_for("system_health"))

    @app.get("/admin/system-health/logs")
    @roles("admin")
    @require_action("security_administer")
    def system_health_log_file():
        # The detailed request-level JSON log (every request, not just
        # errors -- see log_request_completion) lives on disk, not in the
        # database, because its volume would otherwise dwarf every other
        # table combined. Tails it here instead of requiring shell/`docker
        # logs` access. Not tenant-filterable (it's a shared process-wide
        # file across every tenant this instance serves) -- restricted to
        # admins for that reason, same as the rest of this page.
        parsed, error_message, log_path, filters = _read_and_filter_log_file()
        return render_template(
            "system_health_logs.html", entries=parsed,
            error_message=error_message, log_path=log_path, **filters,
        )

    @app.get("/admin/system-health/logs/export")
    @roles("admin")
    @require_action("security_administer")
    def system_health_log_file_export():
        parsed, error_message, _log_path, _filters = _read_and_filter_log_file()
        fmt = request.args.get("format", "ndjson").lower()
        fields = ["timestamp", "level", "logger", "message", "request_id", "method",
                   "path", "status_code", "duration_ms", "user_id", "tenant_id",
                   "remote_addr", "exception"]
        audit("export", "Application log file", f"format={fmt} rows={len(parsed)}")
        db.session.commit()
        if error_message and not parsed:
            flash(error_message, "error")
            return redirect(url_for("system_health_log_file"))
        return _export_response(parsed, fields, fmt, "serviceops-app-log")

    @app.post("/admin/audit/rotate-key")
    @roles("admin")
    @require_action("security_administer")
    def audit_rotate_key():
        if request.form.get("confirmation") != "ROTATE":
            abort(400, description="Type ROTATE to confirm audit-key rotation.")
        try:
            key = rotate_audit_integrity_key(
                current_user.tenant_id, current_user.id
            )
            db.session.commit()
        except RuntimeError as error:
            db.session.rollback()
            abort(409, description=str(error))
        flash(f"Audit signing key rotated to {key.key_id}.", "success")
        return redirect(url_for("audit_log"))

    @app.route("/admin/data-governance", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def data_governance_admin():
        """B-090: data classification reference, per-record-type retention
        policy, legal holds, and a regional-data note. Distinct from
        /admin/audit/retention (audit log has its own long, compliance-
        driven minimum unrelated to customer-data lifecycle)."""
        if request.method == "POST":
            action = request.form.get("action", "")
            if action == "save_retention_policy":
                record_type = request.form.get("record_type", "").strip()
                if record_type not in DATA_CLASSIFICATION_REGISTRY:
                    abort(400, description="Unknown record type.")
                try:
                    retention_days = int(request.form.get("retention_days", "0"))
                except ValueError:
                    abort(400, description="Retention must be an integer number of days.")
                if retention_days < 30 or retention_days > 36500:
                    abort(400, description="Retention must be between 30 and 36500 days.")
                policy = DataRetentionPolicy.query.filter_by(
                    tenant_id=current_user.tenant_id, record_type=record_type,
                ).one_or_none()
                if not policy:
                    policy = DataRetentionPolicy(
                        tenant_id=current_user.tenant_id, record_type=record_type,
                        updated_by_id=current_user.id,
                    )
                    db.session.add(policy)
                policy.retention_days = retention_days
                policy.legal_hold = request.form.get("legal_hold") == "on"
                policy.active = request.form.get("policy_active") == "on"
                policy.updated_by_id = current_user.id
                policy.updated_at = now()
                audit(
                    "data retention policy update", record_type,
                    f"days={retention_days}; legal_hold={policy.legal_hold}; active={policy.active}",
                )
                db.session.commit()
                flash(f"Retention policy for {DATA_CLASSIFICATION_REGISTRY[record_type]['label']} saved.", "success")
            elif action == "run_purge_now":
                count = process_data_retention_purge()
                flash(f"Retention purge complete: {count} record(s) erased.", "success")
            elif action == "add_legal_hold":
                record_type = request.form.get("record_type", "").strip()
                record_id = request.form.get("record_id", type=int)
                reason = request.form.get("reason", "").strip()[:500]
                if record_type not in DATA_CLASSIFICATION_REGISTRY or not record_id or not reason:
                    flash("Record type, record ID, and a reason are all required for a legal hold.", "error")
                else:
                    db.session.add(RecordLegalHold(
                        tenant_id=current_user.tenant_id, record_type=record_type,
                        record_id=record_id, reason=reason, applied_by_id=current_user.id,
                    ))
                    audit("legal hold applied", f"{record_type}:{record_id}", reason)
                    db.session.commit()
                    flash("Legal hold applied.", "success")
            elif action == "release_legal_hold":
                hold = tenant_record_or_404(RecordLegalHold, request.form.get("hold_id", type=int))
                hold.released_at = now()
                hold.released_by_id = current_user.id
                audit("legal hold released", f"{hold.record_type}:{hold.record_id}", hold.reason)
                db.session.commit()
                flash("Legal hold released.", "success")
            elif action == "save_data_region":
                region = request.form.get("data_region", "").strip()[:200]
                setting = PlatformSetting.query.filter_by(
                    tenant_id=current_user.tenant_id, key="DATA_REGION",
                ).one_or_none()
                if not setting:
                    setting = PlatformSetting(tenant_id=current_user.tenant_id, key="DATA_REGION", encrypted=False)
                    db.session.add(setting)
                setting.value = region
                audit("data region update", "DATA_REGION", region)
                db.session.commit()
                flash("Data region note saved.", "success")
            return redirect(url_for("data_governance_admin"))
        policies = {
            policy.record_type: policy
            for policy in DataRetentionPolicy.query.filter_by(tenant_id=current_user.tenant_id).all()
        }
        holds = RecordLegalHold.query.filter_by(
            tenant_id=current_user.tenant_id, released_at=None,
        ).order_by(RecordLegalHold.applied_at.desc()).all()
        region_setting = PlatformSetting.query.filter_by(
            tenant_id=current_user.tenant_id, key="DATA_REGION",
        ).one_or_none()
        return render_template(
            "data_governance_admin.html",
            classification_registry=DATA_CLASSIFICATION_REGISTRY,
            policies=policies, holds=holds,
            data_region=region_setting.value if region_setting else "",
        )

    @app.post("/admin/audit/retention")
    @roles("admin")
    @require_action("security_administer")
    def audit_retention():
        try:
            retention_days = int(request.form.get("retention_days", "0"))
        except ValueError:
            abort(400, description="Retention must be an integer number of days.")
        if retention_days < 2555 or retention_days > 36500:
            abort(400, description=(
                "Audit retention must be between 2555 and 36500 days."
            ))
        policy = AuditRetentionPolicy.query.filter_by(
            tenant_id=current_user.tenant_id
        ).one_or_none()
        if not policy:
            policy = AuditRetentionPolicy(
                tenant_id=current_user.tenant_id,
                updated_by_id=current_user.id,
            )
            db.session.add(policy)
        policy.retention_days = retention_days
        policy.legal_hold = request.form.get("legal_hold") == "on"
        policy.external_export_required = (
            request.form.get("external_export_required") == "on"
        )
        policy.updated_by_id = current_user.id
        policy.updated_at = now()
        audit(
            "audit retention update", "Audit retention policy",
            f"days={retention_days}; legal_hold={policy.legal_hold}; "
            f"external_export_required={policy.external_export_required}",
        )
        db.session.commit()
        flash("Audit retention policy saved.", "success")
        return redirect(url_for("audit_log"))

    @app.get("/admin/audit/export")
    @roles("admin")
    @require_action("export")
    def audit_export():
        integrity = verify_audit_chain(current_user.tenant_id)
        if not integrity["valid"]:
            abort(409, description=(
                "Audit integrity verification failed; export is blocked pending "
                "security investigation."
            ))
        rows = tenant_query(Audit).order_by(Audit.id).all()
        document = {
            "schema": "serviceops.audit-export.v1",
            "exported_at": now().isoformat(),
            "tenant_id": current_user.tenant_id,
            "integrity": integrity,
            "events": [project_document("audit_event", "admin", {
                "id": row.id,
                "event_id": row.event_id,
                "request_id": row.request_id,
                "user_id": row.user_id,
                "action": row.action,
                "target": row.target,
                "details": row.details,
                "source_ip": row.source_ip,
                "user_agent": row.user_agent,
                "integrity_version": row.integrity_version,
                "integrity_key_id": row.integrity_key_id,
                "previous_hash": row.previous_hash,
                "event_hash": row.event_hash,
                "created_at": row.created_at.isoformat(),
            }) for row in rows],
        }
        body = json.dumps(document, indent=2, sort_keys=True).encode()
        active_key = AuditIntegrityKey.query.filter_by(
            tenant_id=current_user.tenant_id, active=True
        ).order_by(AuditIntegrityKey.id.desc()).first()
        signing_key_id = active_key.key_id if active_key else "environment-v1"
        signature = hmac.new(
            audit_integrity_key(signing_key_id, current_user.tenant_id),
            body, hashlib.sha256
        ).hexdigest()
        response = Response(body, mimetype="application/json")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="serviceops-audit-{now():%Y%m%dT%H%M%SZ}.json"'
        )
        response.headers["X-ServiceOps-Audit-Signature"] = signature
        response.headers["X-ServiceOps-Audit-Key-ID"] = signing_key_id
        return response

    @app.get("/modules")
    @login_required
    def modules():
        query = visible_enterprise_record_query(current_user)
        counts = {key: query.filter_by(domain=key).count() for key in DOMAIN_CONFIG}
        return render_template("modules.html", modules=DOMAIN_CONFIG, counts=counts)

    @app.get("/module/<domain>")
    @login_required
    def module_records(domain):
        config = DOMAIN_CONFIG.get(domain)
        if not config:
            abort(404)
        query = visible_enterprise_record_query(current_user).filter_by(domain=domain)
        q = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        if q:
            query = query.filter(db.or_(EnterpriseRecord.number.ilike(f"%{q}%"),
                                        EnterpriseRecord.title.ilike(f"%{q}%"),
                                        EnterpriseRecord.external_id.ilike(f"%{q}%")))
        field_spec = {
            "number": {"label": "Number", "type": "text", "column": EnterpriseRecord.number},
            "title": {"label": "Short description", "type": "text", "column": EnterpriseRecord.title},
            "external_id": {"label": "Source ticket # (e.g. RT)", "type": "text", "column": EnterpriseRecord.external_id},
            "priority": {"label": "Priority", "type": "choice", "column": EnterpriseRecord.priority,
                        "options": [(p, p) for p in ["P1", "P2", "P3", "P4"]]},
            "state": {"label": "State", "type": "choice", "column": EnterpriseRecord.state,
                      "options": [(s, s) for s in
                                  ["New", "Open", "In Progress", "Awaiting Approval", "Approved",
                                   "Pending", "Resolved", "Closed", "Rejected"]]},
            "risk": {"label": "Risk", "type": "choice", "column": EnterpriseRecord.risk,
                    "options": [(r, r) for r in ["Low", "Medium", "High", "Critical"]]},
            "opened": {"label": "Opened", "type": "date", "column": EnterpriseRecord.created_at},
            "updated": {"label": "Updated", "type": "date", "column": EnterpriseRecord.updated_at},
        }
        query = apply_filter_conditions(query, conditions, field_spec)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.order_by(EnterpriseRecord.updated_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec)
        client_fields = {
            key: {"label": spec["label"], "type": spec["type"], "options": spec.get("options", [])}
            for key, spec in field_spec.items()
        }
        return render_template(
            "module_records.html", domain=domain, config=config,
            records=rows, q=q, raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts,
            filter_fields=client_fields, page=page, pages=pages,
            total=total,
        )

    @app.route("/module/<domain>/new", methods=["GET", "POST"])
    @login_required
    def enterprise_new(domain):
        config = DOMAIN_CONFIG.get(domain)
        if not config:
            abort(404)
        if current_user.effective_role == "requester" and domain not in ("customer", "hr"):
            abort(403)
        if request.method == "POST":
            record = EnterpriseRecord(
                number=next_enterprise_number(domain), domain=domain, record_type=request.form["record_type"],
                title=request.form["title"].strip(), description=request.form["description"].strip(),
                priority=request.form.get("priority", "P3"), risk=request.form.get("risk", "Medium"),
                requester_id=current_user.id, due_at=datetime.fromisoformat(request.form["due_at"]) if request.form.get("due_at") else None,
            )
            db.session.add(record)
            db.session.flush()
            if domain == "problem":
                db.session.add(ProblemProfile(enterprise_record_id=record.id))
            if request.form.get("approval_required") and current_user.effective_role != "requester":
                admin = tenant_query(User).filter(User.role.in_(["admin", "superadmin"]), User.active.is_(True)).first()
                if not admin:
                    abort(409, description="No active administrator is configured to approve this record.")
                db.session.add(Approval(enterprise_record_id=record.id, approver_id=admin.id, tenant_id=record.tenant_id))
                create_notification(
                    admin.id, f"Approval requested: {record.number}",
                    record.title, tenant_id=record.tenant_id,
                    target_type="enterprise", target_id=record.id,
                    event_type="enterprise.approval_requested",
                    template_vars={"record_number": record.number, "record_title": record.title},
                )
                record.state = "Awaiting Approval"
            log_history(
                "enterprise", record.id, "Record created",
                details=f"{record.number}: {record.title}",
            )
            audit("create", record.number, f"{config['name']}: {record.title}")
            db.session.commit()
            return redirect(url_for("enterprise_detail", record_id=record.id))
        return render_template("enterprise_form.html", domain=domain, config=config)

    @app.route("/enterprise/<int:record_id>", methods=["GET", "POST"])
    @login_required
    def enterprise_detail(record_id):
        record = tenant_record_or_404(EnterpriseRecord, record_id)
        if not user_can_view_enterprise_record(current_user, record):
            abort(403, description="You are not involved in this record or its assigned work.")
        can_manage_record = user_can_manage_enterprise_record(current_user, record)
        if request.method == "POST":
            action = request.form.get("action")
            if action == "update":
                if not can_manage_record:
                    abort(403)
                before = {
                    "state": record.state,
                    "priority": record.priority,
                    "risk": record.risk,
                    "assigned to": record.assignee.name if record.assignee else "Unassigned",
                }
                try:
                    transition_enterprise(record, request.form["state"])
                except HTTPException as error:
                    db.session.rollback()
                    flash(error.description or "That change could not be made.", "error")
                    return redirect(url_for("enterprise_detail", record_id=record.id))
                record.priority = request.form["priority"]
                record.risk = request.form["risk"]
                record.assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
                assignee = db.session.get(User, record.assignee_id) if record.assignee_id else None
                log_field_changes("enterprise", record.id, before, {
                    "state": record.state,
                    "priority": record.priority,
                    "risk": record.risk,
                    "assigned to": assignee.name if assignee else "Unassigned",
                })
                audit("update", record.number, f"{record.state}, {record.priority}, risk {record.risk}")
            elif action in ("approve", "reject"):
                approval = Approval.query.filter_by(id=int(request.form["approval_id"]),
                                                    enterprise_record_id=record.id,
                                                    approver_id=current_user.id, state="Requested").first_or_404()
                approval.state = "Approved" if action == "approve" else "Rejected"
                approval.comments = request.form.get("comments", "")
                approval.decided_at = now()
                record.state = "Approved" if action == "approve" else "Rejected"
                create_notification(
                    record.requester_id, f"{record.number} {record.state.lower()}",
                    approval.comments or f"Your record was {record.state.lower()}.",
                    tenant_id=record.tenant_id,
                    target_type="enterprise", target_id=record.id,
                    event_type="enterprise.approval_decided",
                    template_vars={
                        "record_number": record.number, "decision": record.state.lower(),
                        "comments": approval.comments or f"Your record was {record.state.lower()}.",
                    },
                )
                log_history(
                    "enterprise", record.id, f"Approval {approval.state.lower()}",
                    details=approval.comments,
                )
                audit(action, record.number)
            db.session.commit()
            return redirect(url_for("enterprise_detail", record_id=record.id))
        agents = User.query.filter(User.role.in_(["agent", "manager", "admin", "superadmin"]), User.active.is_(True)).all()
        work_tasks = OperationalTask.query.filter_by(
            parent_type="enterprise", parent_id=record.id
        ).order_by(OperationalTask.sequence, OperationalTask.id).all()
        task_agents = {}
        task_permissions = {}
        for task in work_tasks:
            member_ids = {member.user_id for member in task.assignment_group.members}
            if task.assignment_group.manager_id:
                member_ids.add(task.assignment_group.manager_id)
            task_agents[task.id] = User.query.filter(
                User.id.in_(member_ids), User.active.is_(True),
                User.role.in_(["agent", "manager", "admin", "superadmin"]),
            ).order_by(User.name).all() if member_ids else []
            task_permissions[task.id] = user_in_group(current_user, task.assignment_group)
        return render_template(
            "enterprise_detail.html", record=record, config=DOMAIN_CONFIG[record.domain],
            state_track=build_state_track(record.domain, record.state),
            agents=agents, record_state_options=allowed_enterprise_states(record),
            related=related_records("enterprise", record.id), relation_labels=RELATION_LABELS,
            work_tasks=work_tasks, work_task_states=OPERATIONAL_TASK_TRANSITIONS,
            history=TaskHistory.query.filter_by(
                target_type="enterprise", target_id=record.id
            ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all(),
            ci_links=TaskCI.query.filter_by(
                target_type="enterprise", target_id=record.id
            ).order_by(TaskCI.relationship_role).all(),
            teams=SupportGroup.query.filter_by(
                group_type="IT Fulfillment", active=True
            ).order_by(SupportGroup.name).all(),
            task_agents=task_agents, task_permissions=task_permissions,
            can_manage_record=can_manage_record,
        )

    @app.get("/known-errors")
    @roles("agent", "manager", "admin")
    def known_errors():
        """ITIL 4's Known Error Database, made real instead of just a flag on
        a problem record -- searchable, so an agent triaging a new incident
        can check "has this happened before" before starting from scratch."""
        q = request.args.get("q", "").strip()
        query = tenant_query(EnterpriseRecord).join(
            ProblemProfile, ProblemProfile.enterprise_record_id == EnterpriseRecord.id
        ).filter(
            EnterpriseRecord.domain == "problem", ProblemProfile.known_error.is_(True),
        )
        if q:
            like = f"%{q}%"
            query = query.filter(db.or_(
                EnterpriseRecord.title.ilike(like),
                ProblemProfile.root_cause.ilike(like),
                ProblemProfile.workaround.ilike(like),
            ))
        records = query.order_by(EnterpriseRecord.updated_at.desc()).all()
        return render_template("known_errors.html", records=records, q=q)

    @app.post("/problem/<int:record_id>/analysis")
    @roles("agent", "manager", "admin")
    def problem_analysis_update(record_id):
        record = tenant_record_or_404(EnterpriseRecord, record_id)
        if record.domain != "problem":
            abort(404)
        if not user_can_manage_enterprise_record(current_user, record):
            abort(403)
        profile = record.problem_profile
        if not profile:
            profile = ProblemProfile(enterprise_record_id=record.id)
            db.session.add(profile)
        before = {
            "known error": profile.known_error,
            "root cause": profile.root_cause,
            "workaround": profile.workaround,
            "permanent fix": profile.fix_notes,
            "primary CI": profile.primary_ci.name if profile.primary_ci else "",
        }
        ci_id = int(request.form["primary_ci_id"]) if request.form.get("primary_ci_id") else None
        selected_ci = (
            tenant_query(ConfigurationItem).filter(ConfigurationItem.id == ci_id).first()
            if ci_id else None
        )
        if ci_id and not selected_ci:
            abort(400)
        profile.known_error = bool(request.form.get("known_error"))
        profile.root_cause = request.form.get("root_cause", "").strip()
        profile.workaround = request.form.get("workaround", "").strip()
        profile.fix_notes = request.form.get("fix_notes", "").strip()
        profile.primary_ci_id = ci_id
        after = {
            "known error": profile.known_error,
            "root cause": profile.root_cause,
            "workaround": profile.workaround,
            "permanent fix": profile.fix_notes,
            "primary CI": selected_ci.name if selected_ci else "",
        }
        changed = log_field_changes(
            "enterprise", record.id, before, after, event="Problem analysis updated"
        )
        audit("update problem analysis", record.number, ", ".join(changed))
        db.session.commit()
        return redirect(url_for("enterprise_detail", record_id=record.id))

    @app.post("/problem/<int:record_id>/tasks")
    @roles("agent", "manager", "admin")
    def problem_task_add(record_id):
        record = tenant_record_or_404(EnterpriseRecord, record_id)
        if record.domain != "problem":
            abort(404)
        if not user_can_manage_enterprise_record(current_user, record):
            abort(403)
        group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
        if not group.active or group.group_type != "IT Fulfillment":
            abort(400, description="Problem tasks require an active IT fulfillment team.")
        sequence = OperationalTask.query.filter_by(
            parent_type="enterprise", parent_id=record.id
        ).count() + 1

        def build_task():
            task = OperationalTask(
                number=next_operational_task_number("problem"),
                task_kind="problem", parent_type="enterprise", parent_id=record.id,
                title=request.form["title"].strip(),
                task_type=request.form.get("task_type", "Investigation"),
                sequence=sequence,
                assignment_group_id=group.id,
                required=bool(request.form.get("required")),
            )
            db.session.add(task)
            return task
        task = create_with_retry_on_number_collision(build_task)
        log_history(
            "enterprise", record.id, "Problem task created",
            details=f"{task.number}: {task.title} → {group.name}",
        )
        audit("create", task.number, f"{record.number}: {task.title}")
        db.session.commit()
        return redirect(url_for("enterprise_detail", record_id=record.id))

    @app.get("/improvements")
    @roles("agent", "manager", "admin")
    def improvements():
        status_filter = request.args.get("status", "")
        query = tenant_query(ImprovementItem)
        if status_filter:
            if status_filter not in IMPROVEMENT_STATES:
                abort(400)
            query = query.filter_by(status=status_filter)
        items = query.order_by(ImprovementItem.created_at.desc()).all()
        return render_template(
            "improvements.html", items=items, status_filter=status_filter,
            states=IMPROVEMENT_STATES,
        )

    @app.post("/improvements/new")
    @roles("agent", "manager", "admin")
    def improvement_new():
        """Raised either standalone from the Improvements list, or via a
        "Raise improvement" quick-action on an incident/problem/change/event
        detail page (source_type/source_id then use the same (type, id)
        shape record_reference()/record_url() already understand)."""
        title = request.form.get("title", "").strip()
        if not title:
            abort(400, description="A title is required.")
        source_type = request.form.get("source_type") or None
        source_id = request.form.get("source_id") or None
        def build():
            item = ImprovementItem(
                number=sequence_number(ImprovementItem, "IMP"),
                title=title[:200],
                description=request.form.get("description", "").strip(),
                expected_outcome=request.form.get("expected_outcome", "").strip(),
                source_type=source_type,
                source_id=int(source_id) if source_id else None,
                owner_id=current_user.id,
                created_by_id=current_user.id,
            )
            db.session.add(item)
            return item
        item = create_with_retry_on_number_collision(build)
        audit("create", item.number, item.title)
        db.session.commit()
        flash(f"{item.number} raised as a continual-improvement item.", "success")
        redirect_to = request.form.get("redirect_to")
        if is_safe_internal_path(redirect_to):
            return redirect(redirect_to)
        return redirect(url_for("improvement_detail", item_id=item.id))

    @app.get("/improvement/<int:item_id>")
    @roles("agent", "manager", "admin")
    def improvement_detail(item_id):
        item = tenant_record_or_404(ImprovementItem, item_id)
        source = record_reference(item.source_type, item.source_id) if item.source_type and item.source_id else None
        agents = tenant_query(User).filter(
            User.role.in_(["agent", "manager", "admin", "superadmin"]), User.active.is_(True)
        ).order_by(User.name).all()
        return render_template(
            "improvement_detail.html", item=item, states=IMPROVEMENT_STATES,
            source_url=record_url(source) if source else None,
            source_label=f"{record_number(source)} · {record_title(source)}" if source else None,
            agents=agents,
        )

    @app.post("/improvement/<int:item_id>")
    @roles("agent", "manager", "admin")
    def improvement_update(item_id):
        item = tenant_record_or_404(ImprovementItem, item_id)
        new_status = request.form.get("status", item.status)
        if new_status not in IMPROVEMENT_STATES:
            abort(400)
        before = {"status": item.status, "owner": item.owner.name if item.owner else "Unassigned"}
        item.status = new_status
        item.expected_outcome = request.form.get("expected_outcome", item.expected_outcome)
        item.measured_result = request.form.get("measured_result", item.measured_result)
        owner_id = request.form.get("owner_id")
        item.owner_id = int(owner_id) if owner_id else None
        after = {
            "status": item.status,
            "owner": item.owner.name if item.owner else "Unassigned",
        }
        log_field_changes("improvement", item.id, before, after, event=f"{item.number} updated")
        audit("update", item.number, item.status)
        db.session.commit()
        flash(f"{item.number} updated.", "success")
        return redirect(url_for("improvement_detail", item_id=item.id))

    @app.get("/catalog")
    @login_required
    def catalog():
        return render_template(
            "catalog.html",
            items=tenant_query(CatalogItem).filter_by(active=True).order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
        )

    @app.post("/catalog/<int:item_id>/order")
    @login_required
    def catalog_order(item_id):
        item = tenant_record_or_404(CatalogItem, item_id)
        if not item.active:
            abort(404)
        if item.approval_required:
            manager = tenant_query(User).filter(User.role.in_(["admin", "superadmin"]), User.active.is_(True)).first()
            fulfillment = tenant_query(SupportGroup).filter_by(name="Service Desk", active=True).first()
            fulfillment_approver_ids = [member.user_id for member in fulfillment.members] if fulfillment else []
            if not manager or not fulfillment_approver_ids:
                flash(
                    f"{item.name} cannot be requested yet: no active administrator or "
                    "Service Desk team member is configured to approve it. Contact an administrator.",
                    "error",
                )
                return redirect(url_for("catalog"))
        def build_req():
            req = CatalogRequest(number=sequence_number(CatalogRequest, "REQ"), requested_by_id=current_user.id,
                                 requested_for_id=current_user.id)
            db.session.add(req)
            return req
        req = create_with_retry_on_number_collision(build_req)

        def build_ritm():
            ritm = RequestedItem(number=sequence_number(RequestedItem, "RITM"), request_id=req.id,
                                 catalog_item_id=item.id, state="Awaiting Approval" if item.approval_required else "Open",
                                 stage="Approval" if item.approval_required else "Fulfillment",
                                 variables_json=json.dumps({"details": request.form.get("details", "")}),
                                 due_at=now() + timedelta(days=item.delivery_days), tenant_id=req.tenant_id)
            db.session.add(ritm)
            return ritm
        ritm = create_with_retry_on_number_collision(build_ritm)
        attach_slas("ritm", ritm.id, None)
        if item.approval_required:
            stages = [
                {"name": "Manager approval", "mode": "all", "approver_ids": [manager.id]},
                {"name": "Fulfillment authorization", "mode": "any",
                 "approver_ids": fulfillment_approver_ids},
            ]
            create_approval_chain(f"{ritm.number} service fulfillment", "ritm", ritm.id, stages)
        else:
            create_catalog_task(ritm)
        log_history("request", req.id, "Request created", details=f"{req.number} created.")
        log_history(
            "ritm", ritm.id, "Requested item created",
            details=f"{ritm.number}: {item.name}",
        )
        audit("order", req.number, f"{ritm.number}: {item.name}")
        db.session.commit()
        flash(f"{item.name} requested as {req.number} / {ritm.number}.", "success")
        return redirect(url_for("request_detail", request_id=req.id))

    def cmdb_filter_field_spec():
        support_groups = SupportGroup.query.filter_by(
            tenant_id=tenant_context_id()
        ).order_by(SupportGroup.name).all()
        return {
            "name": {"label": "Name", "type": "text", "column": ConfigurationItem.name},
            "ci_class": {"label": "Class", "type": "text", "column": ConfigurationItem.ci_class},
            "environment": {"label": "Environment", "type": "choice", "column": ConfigurationItem.environment,
                            "options": [(v, v) for v in ["Production", "Staging", "Development", "Test"]]},
            "operational_status": {"label": "Status", "type": "choice", "column": ConfigurationItem.operational_status,
                                   "options": [(v, v) for v in ["Operational", "Degraded", "Down", "Maintenance", "Retired"]]},
            "lifecycle_state": {"label": "Lifecycle", "type": "choice", "column": ConfigurationItem.lifecycle_state,
                                "options": [(v, v) for v in ["Planned", "In Use", "Maintenance", "Retired", "Disposed"]]},
            "business_criticality": {"label": "Criticality", "type": "choice", "column": ConfigurationItem.business_criticality,
                                     "options": [(v, v) for v in ["Critical", "High", "Medium", "Low"]]},
            "location": {"label": "Location", "type": "text", "column": ConfigurationItem.location},
            "support_group_id": {"label": "Owning team", "type": "choice", "column": ConfigurationItem.support_group_id,
                                 "options": [(str(g.id), g.name) for g in support_groups]},
        }

    @app.get("/cmdb")
    @roles("agent", "manager", "admin")
    def cmdb():
        status = request.args.get("status", "").strip()
        q = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        query = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        )
        if status:
            query = query.filter(ConfigurationItem.operational_status == status)
        if q:
            pattern = f"%{q}%"
            query = query.filter(db.or_(
                ConfigurationItem.name.ilike(pattern),
                ConfigurationItem.serial_number.ilike(pattern),
                ConfigurationItem.ip_address.ilike(pattern),
                ConfigurationItem.model.ilike(pattern),
                ConfigurationItem.vendor.ilike(pattern),
                ConfigurationItem.location.ilike(pattern),
                ConfigurationItem.description.ilike(pattern),
            ))
        field_spec = cmdb_filter_field_spec()
        query = apply_filter_conditions(query, conditions, field_spec)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        visible_cis = query.order_by(
            ConfigurationItem.ci_class, ConfigurationItem.name
        ).offset((page - 1) * per_page).limit(per_page).all()
        readable_ci_ids = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        )
        cis_total = readable_ci_ids.count()
        operational_total = readable_ci_ids.filter(
            ConfigurationItem.operational_status == "Operational"
        ).count()
        relationships = [
            rel for rel in tenant_query(CIRelationship).all()
            if ci_class_read_allowed(current_user.tenant_id, rel.parent.ci_class, current_user.effective_role)
            and ci_class_read_allowed(current_user.tenant_id, rel.child.ci_class, current_user.effective_role)
        ]
        # CIs pulled in from NetBox/CSV carry many more fields than the default
        # table shows (attributes is a free-form JSON bag); surface whatever keys
        # actually appear on this page so users can opt into columns beyond the
        # fixed set via the "Columns" picker, instead of that data being hidden.
        extra_attribute_keys = sorted({
            key for ci in visible_cis for key in (ci.attributes or {}).keys()
        })
        default_hidden_columns = [
            "ip_address", "vendor", "model", "cost_center", "discovery_source",
            "owner", "install_date", "warranty_expiry_date",
        ] + [f"attr:{key}" for key in extra_attribute_keys]
        value_labels = {("support_group_id", key): label
                        for key, label in field_spec["support_group_id"]["options"]}
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec, value_labels)
        client_fields = {
            key: {"label": spec["label"], "type": spec["type"], "options": spec.get("options", [])}
            for key, spec in field_spec.items()
        }
        return render_template(
            "cmdb.html", visible_cis=visible_cis, relationships=relationships, status=status,
            q=q, raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts, filter_fields=client_fields,
            page=page, pages=pages, total=total, cis_total=cis_total, operational_total=operational_total,
            ci_relationship_types=CI_RELATIONSHIP_TYPES, extra_attribute_keys=extra_attribute_keys,
            default_hidden_columns=default_hidden_columns,
        )

    @app.get("/cmdb/export.csv")
    @roles("agent", "manager", "admin")
    def cmdb_export():
        status = request.args.get("status", "").strip()
        conditions = parse_list_filter_param(request.args.get("filter", ""))
        query = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        )
        if status:
            query = query.filter(ConfigurationItem.operational_status == status)
        query = apply_filter_conditions(query, conditions, cmdb_filter_field_spec())
        export_limit = 5000
        cis = query.order_by(ConfigurationItem.ci_class, ConfigurationItem.name).limit(export_limit).all()
        # Attribute keys vary per CI (they come from whatever columns a CSV
        # import happened to have), so the export's extra columns are the
        # union of every key seen across the CIs being exported, in first-
        # seen order -- that way nothing captured on import is left out of
        # the export.
        attribute_keys = []
        seen_keys = set()
        for ci in cis:
            for key in (ci.attributes or {}):
                if key not in seen_keys:
                    seen_keys.add(key)
                    attribute_keys.append(key)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([
            "Name", "Class", "Environment", "Operational status", "Lifecycle state",
            "Business criticality", "IP address", "Serial number", "Vendor", "Model",
            "Location", "Cost center", "Owning team", "Owner", *attribute_keys,
        ])
        for ci in cis:
            attributes = ci.attributes or {}
            writer.writerow([
                ci.name, ci.ci_class, ci.environment, ci.operational_status, ci.lifecycle_state,
                ci.business_criticality, ci.ip_address or "", ci.serial_number or "", ci.vendor or "",
                ci.model or "", ci.location or "", ci.cost_center or "",
                ci.support_group.name if ci.support_group else "", ci.owner.name if ci.owner else "",
                *[attributes.get(key, "") for key in attribute_keys],
            ])
        return csv_response(buffer.getvalue(), "cmdb.csv")

    # Structured facts written by agentless discovery (serviceops_core/
    # network_discovery.py's reconcile_facts_into_cmdb) -- rendered as their
    # own read-only panels/tables on the CI form (see ci_form.html), never as
    # editable "Additional imported fields" rows, since a raw Python list-of-
    # dicts str()'d into a text input is unreadable (the exact "[{'index':
    # '1', ...}]" wall of text an administrator flagged from a live scan).
    CI_DISCOVERY_ATTRIBUTE_KEYS = {
        "sys_descr", "sys_object_id", "sys_uptime", "interfaces",
        "lldp_neighbors", "discovered_via", "discovered_at",
    }

    def _ci_attributes_from_form(existing_attributes=None):
        """Merges the editable free-form attribute rows with whatever
        discovery-structured keys (see CI_DISCOVERY_ATTRIBUTE_KEYS) the CI
        already has -- those never appear as editable rows, so without this
        merge saving the form would silently wipe discovered interfaces/LLDP
        data every time an admin edits an unrelated field."""
        keys = request.form.getlist("attr_key")
        values = request.form.getlist("attr_value")
        attributes = {
            key: value for key, value in (
                (k.strip(), v.strip()) for k, v in zip(keys, values)
            ) if key and key not in CI_DISCOVERY_ATTRIBUTE_KEYS and value
        }
        if existing_attributes:
            for key in CI_DISCOVERY_ATTRIBUTE_KEYS:
                if key in existing_attributes:
                    attributes[key] = existing_attributes[key]
        return attributes

    def _ci_duplicate_of(name, serial_number, exclude_id=None):
        """Hostname and serial number are each supposed to identify exactly
        one physical/virtual asset, so a second CI with the same name or
        serial within a tenant is almost always a mistake (a re-created
        record, a copy-pasted form) rather than a legitimate second CI.
        Returns the existing CI it collides with, or None."""
        query = tenant_query(ConfigurationItem)
        if exclude_id:
            query = query.filter(ConfigurationItem.id != exclude_id)
        conditions = [func.lower(ConfigurationItem.name) == name.casefold()]
        if serial_number:
            conditions.append(ConfigurationItem.serial_number == serial_number)
        return query.filter(db.or_(*conditions)).first()

    @app.route("/cmdb/new", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def ci_new():
        if request.method == "POST":
            name = request.form["name"].strip()
            serial_number = request.form.get("serial_number", "").strip() or None
            ci_class = request.form["ci_class"].strip()
            if not ci_class_action_allowed(
                current_user.tenant_id, ci_class, current_user.effective_role, "create",
            ):
                abort(403, description=f"You are not permitted to create {ci_class} configuration items.")
            duplicate = _ci_duplicate_of(name, serial_number)
            if duplicate:
                flash(
                    f"{duplicate.name} already exists in the CMDB (matched by "
                    f"{'serial number' if duplicate.serial_number == serial_number else 'name'}) "
                    "— edit that record instead of creating a duplicate.", "error",
                )
                return redirect(url_for("ci_edit", ci_id=duplicate.id))
            install_date = request.form.get("install_date") or None
            warranty_expiry_date = request.form.get("warranty_expiry_date") or None
            support_group_id = request.form.get("support_group_id") or None
            environment = normalize_environment(request.form["environment"])
            business_criticality = request.form.get("business_criticality", "Medium")
            rack_id = request.form.get("rack_id") or None
            ci = ConfigurationItem(
                name=request.form["name"].strip(), ci_class=ci_class,
                description=request.form.get("description", "").strip() or None,
                environment=environment, operational_status=request.form["operational_status"],
                lifecycle_state=request.form.get("lifecycle_state", "In Use"),
                business_criticality=business_criticality,
                ip_address=request.form.get("ip_address", "").strip() or None,
                serial_number=request.form.get("serial_number", "").strip() or None,
                vendor=request.form.get("vendor", "").strip() or None,
                model=request.form.get("model", "").strip() or None,
                location=request.form.get("location", "").strip() or None,
                cost_center=request.form.get("cost_center", "").strip() or None,
                discovery_source=request.form.get("discovery_source", "Manual"),
                install_date=parse_form_date(install_date),
                warranty_expiry_date=parse_form_date(warranty_expiry_date),
                support_group_id=int(support_group_id) if support_group_id else None,
                owner_id=current_user.id,
                attributes=_ci_attributes_from_form(),
                require_ccb_approval=(
                    ci_always_requires_ccb(ci_class, environment, business_criticality)
                    or request.form.get("require_ccb_approval") == "on"
                ),
                rack_id=int(rack_id) if rack_id else None,
                rack_position=request.form.get("rack_position", type=float),
                rack_u_height=request.form.get("rack_u_height", type=int),
                rack_face=request.form.get("rack_face", "").strip() or None,
            )
            db.session.add(ci)
            audit("create", "CI", ci.name)
            db.session.commit()
            flash(f"{ci.name} created.", "success")
            return redirect(url_for("cmdb"))
        support_groups = tenant_query(SupportGroup).filter_by(active=True).order_by(SupportGroup.name).all()
        racks = tenant_query(Rack).filter_by(active=True).order_by(Rack.name).all()
        return render_template("ci_form.html", support_groups=support_groups, racks=racks)

    @app.route("/cmdb/<int:ci_id>/edit", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def ci_edit(ci_id):
        ci = tenant_record_or_404(ConfigurationItem, ci_id)
        if not ci_class_action_allowed(
            current_user.tenant_id, ci.ci_class, current_user.effective_role, "update",
        ):
            abort(403, description=f"You are not permitted to edit {ci.ci_class} configuration items.")
        if request.method == "POST":
            name = request.form["name"].strip()
            serial_number = request.form.get("serial_number", "").strip() or None
            duplicate = _ci_duplicate_of(name, serial_number, exclude_id=ci.id)
            if duplicate:
                flash(
                    f"{duplicate.name} already has this "
                    f"{'serial number' if duplicate.serial_number == serial_number else 'name'} "
                    "— resolve the conflict before saving.", "error",
                )
                return redirect(url_for("ci_edit", ci_id=ci.id))
            tracked_fields = [
                "name", "ci_class", "environment", "operational_status", "lifecycle_state",
                "business_criticality", "ip_address", "serial_number", "vendor", "model",
                "location", "cost_center",
            ]
            new_ci_class = request.form["ci_class"].strip()
            if new_ci_class != ci.ci_class and not ci_class_action_allowed(
                current_user.tenant_id, new_ci_class, current_user.effective_role, "update",
            ):
                abort(403, description=f"You are not permitted to move this CI into {new_ci_class}.")
            before = {field: getattr(ci, field) or "" for field in tracked_fields}
            before["attributes"] = json.dumps(ci.attributes or {}, sort_keys=True)
            ci.name = request.form["name"].strip()
            ci.ci_class = new_ci_class
            ci.description = request.form.get("description", "").strip() or None
            ci.environment = normalize_environment(request.form["environment"])
            ci.operational_status = request.form["operational_status"]
            ci.lifecycle_state = request.form.get("lifecycle_state", "In Use")
            ci.business_criticality = request.form.get("business_criticality", "Medium")
            ci.ip_address = request.form.get("ip_address", "").strip() or None
            ci.serial_number = request.form.get("serial_number", "").strip() or None
            ci.vendor = request.form.get("vendor", "").strip() or None
            ci.model = request.form.get("model", "").strip() or None
            ci.location = request.form.get("location", "").strip() or None
            ci.cost_center = request.form.get("cost_center", "").strip() or None
            ci.discovery_source = request.form.get("discovery_source", ci.discovery_source)
            ci.install_date = parse_form_date(request.form.get("install_date") or None)
            ci.warranty_expiry_date = parse_form_date(request.form.get("warranty_expiry_date") or None)
            support_group_id = request.form.get("support_group_id")
            ci.support_group_id = int(support_group_id) if support_group_id else None
            owner_id = request.form.get("owner_id")
            ci.owner_id = int(owner_id) if owner_id else None
            ci.attributes = _ci_attributes_from_form(ci.attributes)
            ci.require_ccb_approval = (
                ci_always_requires_ccb(ci.ci_class, ci.environment, ci.business_criticality)
                or request.form.get("require_ccb_approval") == "on"
            )
            rack_id = request.form.get("rack_id") or None
            ci.rack_id = int(rack_id) if rack_id else None
            ci.rack_position = request.form.get("rack_position", type=float)
            ci.rack_u_height = request.form.get("rack_u_height", type=int)
            ci.rack_face = request.form.get("rack_face", "").strip() or None
            after = {field: getattr(ci, field) or "" for field in tracked_fields}
            after["attributes"] = json.dumps(ci.attributes or {}, sort_keys=True)
            log_field_changes("ci", ci.id, before, after)
            audit("update", "CI", ci.name)
            db.session.commit()
            flash(f"{ci.name} updated.", "success")
            return redirect(url_for("cmdb"))
        owners = tenant_query(User).filter_by(active=True).order_by(User.name).all()
        support_groups = tenant_query(SupportGroup).filter_by(active=True).order_by(SupportGroup.name).all()
        racks = tenant_query(Rack).filter_by(active=True).order_by(Rack.name).all()
        history = TaskHistory.query.filter_by(
            target_type="ci", target_id=ci.id
        ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).limit(50).all()
        impacted_ids = ci_impact_set(ci.tenant_id, {ci.id}) - {ci.id}
        impacted_cis = tenant_query(ConfigurationItem).filter(ConfigurationItem.id.in_(impacted_ids)).all() if impacted_ids else []
        lldp_neighbor_cis = {}
        for neighbor in (ci.attributes or {}).get("lldp_neighbors") or []:
            neighbor_name = (neighbor.get("neighbor_name") or "").strip()
            if not neighbor_name or neighbor_name in lldp_neighbor_cis:
                continue
            match = tenant_query(ConfigurationItem).filter(
                func.lower(ConfigurationItem.name) == neighbor_name.casefold()
            ).first()
            if match:
                lldp_neighbor_cis[neighbor_name] = match
        # "Connects to" is the physical/network-link relationship type this
        # CI's own discovered LLDP data (or a manually-drawn relationship)
        # produces -- see B-289/cmdb_topology. Surfaced here directly
        # (both directions: this CI as parent or child) so a switch shows
        # every server plugged into it and a server shows the switch it's
        # plugged into, without leaving the CI page for the topology map.
        connects_to_rels = tenant_query(CIRelationship).filter(
            CIRelationship.relationship_type == "Connects to",
            db.or_(CIRelationship.parent_id == ci.id, CIRelationship.child_id == ci.id),
        ).all()
        network_connections = []
        for rel in connects_to_rels:
            other = rel.child if rel.parent_id == ci.id else rel.parent
            if not other or not ci_class_read_allowed(
                current_user.tenant_id, other.ci_class, current_user.effective_role,
            ):
                continue
            local_port, other_port = "", ""
            if rel.label and "<->" in rel.label:
                left, right = rel.label.split("<->", 1)
                local_port, other_port = (left.strip(), right.strip()) if rel.parent_id == ci.id else (right.strip(), left.strip())
            network_connections.append({
                "ci": other, "local_port": local_port, "other_port": other_port,
            })
        return render_template(
            "ci_form.html", ci=ci, owners=owners, support_groups=support_groups, racks=racks, history=history,
            impacted_cis=impacted_cis, lldp_neighbor_cis=lldp_neighbor_cis,
            network_connections=network_connections,
        )

    @app.route("/cmdb/import", methods=["GET", "POST"])
    @roles("admin")
    def cmdb_import():
        from serviceops_core.cmdb_import import CmdbImportError, import_ci_rows, parse_ci_rows

        preview = None
        csv_text = ""
        if request.method == "POST":
            action = request.form.get("action", "preview")
            if action == "preview":
                upload = request.files.get("file")
                sheet_url = request.form.get("sheet_url", "").strip()
                pasted = request.form.get("csv_text", "")
                if upload and upload.filename:
                    csv_text = upload.read().decode("utf-8-sig", errors="replace")
                elif sheet_url:
                    if "docs.google.com/spreadsheets/d/" not in sheet_url:
                        flash("Enter a valid Google Sheets URL.", "error")
                        return render_template("cmdb_import.html", preview=None, csv_text="",
                                                netbox_enabled=setting_bool("NETBOX_ENABLED"),
                                                netbox_sync_result=session.pop("netbox_sync_result", None))
                    sheet_id = sheet_url.split("/d/")[1].split("/")[0]
                    gid = "0"
                    if "gid=" in sheet_url:
                        gid = sheet_url.split("gid=")[1].split("&")[0].split("#")[0] or "0"
                    export_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}"
                    if not integration_endpoint_valid(export_url):
                        flash("That sheet URL could not be reached safely.", "error")
                        return render_template("cmdb_import.html", preview=None, csv_text="",
                                                netbox_enabled=setting_bool("NETBOX_ENABLED"),
                                                netbox_sync_result=session.pop("netbox_sync_result", None))
                    ok, hostname, infos = resolve_endpoint_addresses_safely(export_url)
                    if not ok:
                        flash("That sheet URL could not be reached safely.", "error")
                        return render_template("cmdb_import.html", preview=None, csv_text="",
                                                netbox_enabled=setting_bool("NETBOX_ENABLED"),
                                                netbox_sync_result=session.pop("netbox_sync_result", None))
                    try:
                        # Pin the addresses just validated: requests' own
                        # internal DNS lookup would otherwise re-resolve
                        # `hostname` independently of the safety check above,
                        # reopening the same DNS-rebinding TOCTOU window
                        # deliver_webhook() already closes for outbound
                        # webhooks (see serviceops_core/dns_pin.py).
                        if hostname and infos:
                            with pin_resolved_addresses(hostname, infos):
                                response = requests.get(export_url, timeout=15, allow_redirects=False)
                        else:
                            response = requests.get(export_url, timeout=15, allow_redirects=False)
                        response.raise_for_status()
                        csv_text = response.text
                    except requests.RequestException as error:
                        flash(f"Could not fetch the sheet: {error}", "error")
                        return render_template("cmdb_import.html", preview=None, csv_text="",
                                                netbox_enabled=setting_bool("NETBOX_ENABLED"),
                                                netbox_sync_result=session.pop("netbox_sync_result", None))
                else:
                    csv_text = pasted
                try:
                    rows = parse_ci_rows(csv_text)
                    preview = import_ci_rows(rows, tenant_context_id(), dry_run=True)
                except CmdbImportError as error:
                    flash(str(error), "error")
            elif action == "apply":
                csv_text = request.form.get("csv_text", "")
                try:
                    rows = parse_ci_rows(csv_text)
                    result = import_ci_rows(rows, tenant_context_id(), dry_run=False)
                except CmdbImportError as error:
                    flash(str(error), "error")
                else:
                    audit(
                        "configure", "CMDB import",
                        f"{result['cis_created']} created, {result['cis_updated']} updated, "
                        f"{result['fields_skipped_netbox_owned']} NetBox-owned fields preserved, "
                        f"{len(result['errors'])} errors",
                    )
                    flash(
                        f"CMDB import applied: {result['cis_created']} created, "
                        f"{result['cis_updated']} updated, {len(result['errors'])} errors.",
                        "success" if not result["errors"] else "warning",
                    )
                    return redirect(url_for("cmdb"))
            else:
                abort(400)
        return render_template(
            "cmdb_import.html", preview=preview, csv_text=csv_text,
            netbox_enabled=setting_bool("NETBOX_ENABLED"),
            netbox_sync_result=session.pop("netbox_sync_result", None),
        )

    @app.post("/cmdb/import/netbox")
    @roles("admin")
    def cmdb_import_netbox():
        from serviceops_core.netbox_sync import NetboxSyncError, sync_from_netbox

        dry_run = bool(request.form.get("dry_run"))
        try:
            result = sync_from_netbox(tenant_context_id(), dry_run=dry_run)
        except NetboxSyncError as error:
            flash(f"NetBox sync could not run: {error}", "error")
        else:
            audit(
                "configure", "NetBox CMDB sync",
                f"{'Preview' if dry_run else 'Applied'}: "
                f"{result['devices_seen']} devices seen, {result['cis_created']} created, "
                f"{result['cis_updated']} updated, {result['racks_created']} racks created, "
                f"{result['racks_updated']} racks updated, {len(result['errors'])} errors",
            )
            session["netbox_sync_result"] = result
            flash(
                (
                    "NetBox sync preview: " if dry_run else "NetBox sync applied: "
                ) + (
                    f"{result['devices_seen']} devices seen, {result['cis_created']} created, "
                    f"{result['cis_updated']} updated, {result['racks_created']} racks created, "
                    f"{result['racks_updated']} racks updated, {len(result['errors'])} errors."
                ),
                "success" if not result["errors"] else "warning",
            )
        return redirect(url_for("cmdb_import"))

    @app.route("/cmdb/racks", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def rack_list():
        if request.method == "POST":
            if current_user.effective_role not in ("admin", "superadmin"):
                abort(403)
            name = request.form.get("name", "").strip()
            if not name:
                flash("Rack name is required.", "error")
            elif tenant_query(Rack).filter(func.lower(Rack.name) == name.casefold()).first():
                flash("A rack with that name already exists.", "error")
            else:
                rack = Rack(
                    tenant_id=current_user.tenant_id, name=name,
                    site=request.form.get("site", "").strip(),
                    u_height=request.form.get("u_height", type=int) or 42,
                    notes=request.form.get("notes", "").strip(),
                )
                db.session.add(rack)
                audit("create", "Rack", name)
                db.session.commit()
                flash(f"{name} created.", "success")
                return redirect(url_for("rack_list"))
        racks = tenant_query(Rack).filter_by(active=True).order_by(Rack.site, Rack.name).all()
        occupied_u = {
            row.rack_id: row.total
            for row in db.session.query(
                ConfigurationItem.rack_id,
                # A CI with no height set defaults to 1U everywhere else in
                # this feature (see ci_dict() in rack_elevation()) -- must
                # coalesce per-row here too, not just at the end: SUM() of
                # an all-NULL group returns SQL NULL, not 0, which crashed
                # the template's "used / rack.u_height" division outright.
                func.sum(func.coalesce(ConfigurationItem.rack_u_height, 1)).label("total"),
            ).filter(ConfigurationItem.rack_id.isnot(None), ConfigurationItem.tenant_id == current_user.tenant_id)
            .group_by(ConfigurationItem.rack_id).all()
        }
        return render_template("rack_list.html", racks=racks, occupied_u=occupied_u)

    @app.route("/cmdb/racks/<int:rack_id>/edit", methods=["GET", "POST"])
    @roles("admin")
    def rack_edit(rack_id):
        rack = tenant_record_or_404(Rack, rack_id)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            duplicate = tenant_query(Rack).filter(
                func.lower(Rack.name) == name.casefold(), Rack.id != rack.id,
            ).first()
            if not name:
                flash("Rack name is required.", "error")
            elif duplicate:
                flash("A rack with that name already exists.", "error")
            else:
                rack.name = name
                rack.site = request.form.get("site", "").strip()
                rack.u_height = request.form.get("u_height", type=int) or rack.u_height
                rack.notes = request.form.get("notes", "").strip()
                audit("update", "Rack", rack.name)
                db.session.commit()
                flash(f"{rack.name} updated.", "success")
                return redirect(url_for("rack_list"))
        return render_template("rack_form.html", rack=rack)

    @app.post("/cmdb/racks/<int:rack_id>/delete")
    @roles("admin")
    def rack_delete(rack_id):
        rack = tenant_record_or_404(Rack, rack_id)
        still_mounted = tenant_query(ConfigurationItem).filter_by(rack_id=rack.id).count()
        if still_mounted:
            flash(
                f"Cannot delete {rack.name}: {still_mounted} configuration item(s) are still "
                "mounted in it. Unassign them first.", "error",
            )
            return redirect(url_for("rack_list"))
        audit("delete", "Rack", rack.name)
        db.session.delete(rack)
        db.session.commit()
        flash(f"{rack.name} deleted.", "success")
        return redirect(url_for("rack_list"))

    def _rack_elevation_payload(rack, compact=False):
        cis = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        ).filter_by(rack_id=rack.id).all()

        def ci_dict(ci):
            return {
                "id": ci.id, "name": ci.name, "ci_class": ci.ci_class,
                "status": ci.operational_status,
                "position": ci.rack_position if ci.rack_position is not None else 1,
                "u_height": ci.rack_u_height if ci.rack_u_height else 1,
            }

        front = [ci_dict(ci) for ci in cis if ci.rack_face != "rear" and (ci.ci_class or "").lower() != "pdu"]
        rear = [ci_dict(ci) for ci in cis if ci.rack_face == "rear" and (ci.ci_class or "").lower() != "pdu"]
        pdus = [
            {
                "id": ci.id, "name": ci.name,
                "power_watts": (ci.attributes or {}).get("power_watts"),
            }
            for ci in cis if (ci.ci_class or "").lower() == "pdu"
        ]
        space_used = sum((ci.rack_u_height or 1) for ci in cis if ci.rack_position is not None)
        weights = [(ci.attributes or {}).get("weight_kg") for ci in cis if (ci.attributes or {}).get("weight_kg")]
        powers = [(ci.attributes or {}).get("power_watts") for ci in cis if (ci.attributes or {}).get("power_watts")]
        highlight_ci_id = request.args.get("highlight", type=int)
        return {
            "rack": {"id": rack.id, "name": rack.name, "site": rack.site, "u_height": rack.u_height},
            "front": front, "rear": rear, "pdus": pdus,
            "highlight_ci_id": highlight_ci_id,
            "compact": compact,
            "stats": {
                "space_used_u": space_used, "space_total_u": rack.u_height,
                "weight_kg": sum(weights) if weights else None,
                "power_watts": sum(powers) if powers else None,
            },
        }

    @app.get("/cmdb/racks/<int:rack_id>")
    @roles("agent", "manager", "admin")
    def rack_elevation(rack_id):
        rack = tenant_record_or_404(Rack, rack_id)
        payload = _rack_elevation_payload(rack)
        return render_template("rack_elevation.html", rack=rack, rack_json=json.dumps(payload))

    @app.get("/cmdb/racks/<int:rack_id>/embed")
    @roles("agent", "manager", "admin")
    def rack_elevation_embed(rack_id):
        # A compact, chrome-free version of the same view (no sidebar nav,
        # no stats/PDU panels) meant to be iframed directly into a CI's own
        # detail page -- see ci_form.html -- so "where does this device sit"
        # is visible without leaving the CI you're already looking at.
        rack = tenant_record_or_404(Rack, rack_id)
        payload = _rack_elevation_payload(rack, compact=True)
        return render_template("rack_elevation_embed.html", rack=rack, rack_json=json.dumps(payload))

    @app.route("/tickets/import/rt", methods=["GET", "POST"])
    @roles("admin")
    def rt_import():
        if request.method == "POST":
            dry_run = bool(request.form.get("dry_run"))
            query = request.form.get("query", "").strip() or "id > 0"
            limit_raw = request.form.get("limit", "").strip()
            try:
                limit = int(limit_raw) if limit_raw else None
            except ValueError:
                limit = None
            if not setting_bool("RT_ENABLED"):
                flash("RT import is not enabled.", "error")
                return redirect(url_for("rt_import"))
            # Enqueue only -- RT import can take many minutes against a real
            # (often slow) instance, and running it inline here routinely
            # exceeded gunicorn's worker timeout, which kills the whole
            # worker process (and every other in-flight request on it), not
            # just this one. The background worker does the actual work.
            job = RTImportJob(
                tenant_id=tenant_context_id(), actor_user_id=current_user.id,
                search_query=query, record_limit=limit, dry_run=dry_run,
            )
            db.session.add(job)
            audit("configure", "RT ticket import queued",
                  f"{'Preview' if dry_run else 'Apply'}: query={query!r}"
                  + (f" limit={limit}" if limit else ""))
            db.session.commit()
            flash(f"RT import queued (job #{job.id}). This runs in the background.", "success")
            return redirect(url_for("rt_import"))
        recent_jobs = RTImportJob.query.filter_by(
            tenant_id=tenant_context_id()
        ).order_by(RTImportJob.id.desc()).limit(10).all()
        # B-322: RT connection settings (host/token/TLS) render directly on
        # this page instead of a separate Platform settings page, so every
        # RT-related control lives in one place. Saving posts to the
        # existing system_settings_category("request_tracker_connection")
        # handler unchanged -- _admin_referrer_redirect there sends the
        # admin back here since this page is the referrer.
        rt_definitions = SETTING_DEFINITIONS["request_tracker_connection"]
        rt_values = {}
        for definition in rt_definitions:
            value = setting_value(definition["key"], definition.get("default", ""))
            rt_values[definition["key"]] = "" if definition["type"] == "secret" else value
            definition["configured"] = bool(value) if definition["type"] == "secret" else False
        return render_template(
            "rt_import.html", rt_enabled=setting_bool("RT_ENABLED"), recent_jobs=recent_jobs,
            rt_definitions=rt_definitions, rt_values=rt_values,
        )

    @app.post("/cmdb/relationships")
    @roles("agent", "manager", "admin")
    def ci_relationship_add():
        parent = tenant_record_or_404(ConfigurationItem, int(request.form["parent_id"]))
        if not ci_class_action_allowed(
            current_user.tenant_id, parent.ci_class, current_user.effective_role, "update",
        ):
            abort(403, description=f"You are not permitted to edit {parent.ci_class} configuration items.")
        relationship_type = request.form.get("relationship_type", "Depends on")
        if relationship_type not in CI_RELATIONSHIP_TYPES:
            abort(400, description="Select a valid relationship type.")
        try:
            child_ids = [int(raw) for raw in request.form.getlist("child_id") if raw.strip()]
        except ValueError:
            abort(400)
        if not child_ids:
            abort(400, description="Select at least one child configuration item.")
        linked_names = []
        for child_id in dict.fromkeys(child_ids):
            child = tenant_record_or_404(ConfigurationItem, child_id)
            if parent.id == child.id:
                abort(400, description="A configuration item cannot depend on itself.")
            if not ci_class_action_allowed(
                current_user.tenant_id, child.ci_class, current_user.effective_role, "update",
            ):
                abort(403, description=f"You are not permitted to edit {child.ci_class} configuration items.")
            existing = tenant_query(CIRelationship).filter_by(
                parent_id=parent.id, child_id=child.id, relationship_type=relationship_type,
            ).first()
            if existing:
                continue
            db.session.add(CIRelationship(parent_id=parent.id, child_id=child.id, relationship_type=relationship_type))
            linked_names.append(child.name)
        if linked_names:
            audit("create", "CI relationship",
                  f"{parent.name} — {relationship_type} → {', '.join(linked_names)}")
            db.session.commit()
            flash(f"Linked {parent.name} to {', '.join(linked_names)}.", "success")
        return redirect(url_for("cmdb"))

    @app.post("/cmdb/relationships/<int:relationship_id>/delete")
    @roles("agent", "manager", "admin")
    def ci_relationship_delete(relationship_id):
        relationship = tenant_record_or_404(CIRelationship, relationship_id)
        for endpoint_class in (relationship.parent.ci_class, relationship.child.ci_class):
            if not ci_class_action_allowed(
                current_user.tenant_id, endpoint_class, current_user.effective_role, "update",
            ):
                abort(403, description=f"You are not permitted to edit {endpoint_class} configuration items.")
        audit("delete", "CI relationship", f"{relationship.parent.name} — {relationship.child.name}")
        db.session.delete(relationship)
        db.session.commit()
        flash("Relationship removed.", "success")
        return redirect(url_for("cmdb"))

    @app.get("/cmdb/discovery")
    @require_action("security_administer")
    def cmdb_discovery():
        targets = tenant_query(DiscoveryTarget).order_by(DiscoveryTarget.name).all()
        pending_counts = dict(
            db.session.query(DiscoveryCandidate.target_id, db.func.count(DiscoveryCandidate.id))
            .filter(DiscoveryCandidate.target_id.in_([t.id for t in targets]))
            .group_by(DiscoveryCandidate.target_id).all()
        ) if targets else {}
        return render_template("cmdb_discovery.html", targets=targets, pending_counts=pending_counts)

    @app.post("/cmdb/discovery")
    @require_action("security_administer")
    def cmdb_discovery_add():
        name = request.form.get("name", "").strip()
        target_type = request.form.get("target_type", "host")
        address = request.form.get("address", "").strip()
        community = request.form.get("community", "")
        if not name or not address:
            flash("Name and address are required.", "error")
            return redirect(url_for("cmdb_discovery"))
        if target_type not in ("host", "subnet"):
            abort(400, description="Invalid target type.")
        try:
            if target_type == "host":
                ipaddress.ip_address(address)
            else:
                ipaddress.ip_network(address, strict=False)
        except ValueError:
            flash("Address must be a valid IP address (host) or CIDR range (subnet).", "error")
            return redirect(url_for("cmdb_discovery"))
        target = DiscoveryTarget(
            name=name, target_type=target_type, address=address,
            snmp_version=request.form.get("snmp_version", "2c"),
            snmp_port=int(request.form.get("snmp_port") or 161),
            schedule_enabled=request.form.get("schedule_enabled") == "on",
            schedule_interval_minutes=max(int(request.form.get("schedule_interval_minutes") or 1440), 5),
            created_by_id=current_user.id,
        )
        target.community = community
        db.session.add(target)
        audit("create", "Discovery target", f"{name} ({target_type}: {address})")
        db.session.commit()
        flash(f"Discovery target {name} created.", "success")
        return redirect(url_for("cmdb_discovery"))

    @app.post("/cmdb/discovery/<int:target_id>/run")
    @require_action("security_administer")
    def cmdb_discovery_run(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        from serviceops_core.network_discovery import discover_subnet, probe_host
        try:
            if target.target_type == "host":
                facts = probe_host(
                    target.address, target.community,
                    port=target.snmp_port, version=target.snmp_version,
                )
                facts_list = [facts] if facts else []
            else:
                facts_list = discover_subnet(
                    target.address, target.community,
                    port=target.snmp_port, version=target.snmp_version,
                )
            # A run only stages candidates for review -- it never creates a
            # CI by itself. Clear this target's previous pending candidates
            # first so re-running doesn't pile up stale ones alongside
            # fresh results for the same address.
            DiscoveryCandidate.query.filter_by(target_id=target.id).delete()
            snmp_hosts = bare_hosts = 0
            for facts in facts_list:
                source = facts.get("discovery_source", "SNMP Discovery")
                if source == "SNMP Discovery":
                    snmp_hosts += 1
                else:
                    bare_hosts += 1
                db.session.add(DiscoveryCandidate(
                    target_id=target.id, host=facts["host"],
                    name=facts.get("sys_name") or facts["host"],
                    ci_class=facts.get("ci_class", "Device"),
                    vendor=facts.get("vendor") or None,
                    discovery_source=source, facts=facts,
                    tenant_id=target.tenant_id,
                ))
            target.last_run_status = "ok"
            target.last_run_summary = (
                f"{len(facts_list)} host(s) responded ({snmp_hosts} via SNMP, {bare_hosts} liveness-only) "
                f"-- awaiting review before anything is added to the CMDB."
            )
            flash(
                f"{target.last_run_summary} Review and add them below." if facts_list
                else "No hosts responded.",
                "success" if facts_list else "warning",
            )
        except Exception as error:  # noqa: BLE001 - a bad target must surface, not crash the request
            target.last_run_status = "failed"
            target.last_run_summary = str(error)[:2000]
            flash(f"Discovery run failed: {error}", "error")
        target.last_run_at = now()
        audit("run", "Discovery target", f"{target.name}: {target.last_run_status}")
        db.session.commit()
        return redirect(url_for("cmdb_discovery"))

    @app.get("/cmdb/discovery/<int:target_id>/review")
    @require_action("security_administer")
    def cmdb_discovery_review(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        candidates = DiscoveryCandidate.query.filter_by(target_id=target.id).order_by(
            DiscoveryCandidate.discovery_source.desc(), DiscoveryCandidate.name
        ).all()
        return render_template("cmdb_discovery_review.html", target=target, candidates=candidates)

    @app.post("/cmdb/discovery/<int:target_id>/import")
    @require_action("security_administer")
    def cmdb_discovery_import(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        from serviceops_core.network_discovery import reconcile_facts_into_cmdb

        query = DiscoveryCandidate.query.filter_by(target_id=target.id)
        if request.form.get("select_all") != "1":
            selected_ids = {int(value) for value in request.form.getlist("candidate_id")}
            if not selected_ids:
                flash("No devices selected -- nothing was added.", "warning")
                return redirect(url_for("cmdb_discovery_review", target_id=target.id))
            query = query.filter(DiscoveryCandidate.id.in_(selected_ids))
        candidates = query.all()
        facts_list = [candidate.facts for candidate in candidates]
        summary = reconcile_facts_into_cmdb(target.tenant_id, target.name, facts_list)
        for candidate in candidates:
            db.session.delete(candidate)
        audit(
            "import", "Discovery target",
            f"{target.name}: {summary['created']} created, {summary['updated']} updated from review",
        )
        db.session.commit()
        flash(
            f"Added {summary['created']} new and updated {summary['updated']} existing CI(s), "
            f"{summary['relationships_created']} relationship(s) created.",
            "success" if not summary["errors"] else "warning",
        )
        remaining = DiscoveryCandidate.query.filter_by(target_id=target.id).count()
        return redirect(
            url_for("cmdb_discovery_review", target_id=target.id) if remaining
            else url_for("cmdb_discovery")
        )

    @app.post("/cmdb/discovery/<int:target_id>/discard")
    @require_action("security_administer")
    def cmdb_discovery_discard(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        deleted = DiscoveryCandidate.query.filter_by(target_id=target.id).delete()
        audit("discard", "Discovery target", f"{target.name}: {deleted} candidate(s) discarded")
        db.session.commit()
        flash(f"Discarded {deleted} discovered device(s) without adding them to the CMDB.", "success")
        return redirect(url_for("cmdb_discovery"))

    @app.post("/cmdb/discovery/<int:target_id>/delete")
    @require_action("security_administer")
    def cmdb_discovery_delete(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        DiscoveryCandidate.query.filter_by(target_id=target.id).delete()
        audit("delete", "Discovery target", target.name)
        db.session.delete(target)
        db.session.commit()
        flash("Discovery target removed.", "success")
        return redirect(url_for("cmdb_discovery"))

    @app.get("/cmdb/topology")
    @roles("agent", "manager", "admin")
    def cmdb_topology():
        # Virtual machines are excluded from the physical connectivity map --
        # a VM's meaningful "connection" is to its hypervisor host (oVirt,
        # not LLDP-discoverable switch-port topology), which is a separate,
        # not-yet-built concern. Showing VMs here today would only add noise
        # with no physical-port information behind it.
        cis = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        ).filter(ConfigurationItem.ci_class != "Virtual Machine").all()
        visible_ci_ids = {ci.id for ci in cis}
        relationships = [
            rel for rel in tenant_query(CIRelationship).all()
            if rel.parent_id in visible_ci_ids and rel.child_id in visible_ci_ids
        ]
        graph = {
            "nodes": [
                {
                    "id": ci.id, "name": ci.name, "ci_class": ci.ci_class,
                    "status": ci.operational_status, "discovery_source": ci.discovery_source,
                }
                for ci in cis
            ],
            "edges": [
                {
                    "source": rel.parent_id, "target": rel.child_id, "type": rel.relationship_type,
                    "label": rel.label,
                }
                for rel in relationships
            ],
        }
        return render_template("cmdb_topology.html", graph_json=json.dumps(graph))

    @app.get("/cmdb/<int:ci_id>/network-info")
    @roles("agent", "manager", "admin")
    def cmdb_network_info(ci_id):
        # Purely informational hostname<->IP resolution for the topology
        # detail panel and the CI edit page's discovered-interfaces table --
        # never used to open an outbound connection, so this only needs the
        # same read-permission check ci_edit already applies, not the
        # SSRF-focused address allowlist used for webhook delivery.
        ci = tenant_record_or_404(ConfigurationItem, ci_id)
        if not ci_class_read_allowed(current_user.tenant_id, ci.ci_class, current_user.effective_role):
            abort(403)
        ips = []
        if ci.ip_address:
            ips.append(ci.ip_address)
        for iface in (ci.attributes or {}).get("interfaces") or []:
            addr = iface.get("ip_address") if isinstance(iface, dict) else None
            if addr and addr not in ips:
                ips.append(addr)
        hostnames = [ci.name] if ci.name else []
        addresses = [{"ip": ip, "hostname": resolve_hostname(ip)} for ip in ips]
        hostname_results = [{"hostname": name, "ips": resolve_ip(name)} for name in hostnames]
        return jsonify({"addresses": addresses, "hostnames": hostname_results})

    # requester is deliberately excluded: no CMDB route (read or write) has
    # ever let requester through, so a requester column would be an inert
    # checkbox that can never take effect -- the same footgun avoided
    # elsewhere in this feature. admin's create/update/delete are always
    # implicitly allowed (see ci_class_action_allowed) and rendered as an
    # "Always" badge in the template rather than a checkbox that would be
    # equally inert; admin's Read column stays a real, restrictable checkbox.
    CI_CLASS_PERMISSION_ROLES = ("agent", "manager", "admin")
    CI_CLASS_PERMISSION_CRUD_ROLES = ("agent", "manager")

    @app.route("/cmdb/permissions", methods=["GET", "POST"])
    @roles("admin")
    def cmdb_permissions():
        tenant_id = current_user.tenant_id
        if request.method == "POST":
            new_class = request.form.get("new_class", "").strip()
            submitted_classes = set(request.form.getlist("ci_class")) | ({new_class} if new_class else set())
            changed = []
            for ci_class in submitted_classes:
                if not ci_class:
                    continue
                for role in CI_CLASS_PERMISSION_ROLES:
                    can_read = request.form.get(f"read__{ci_class}__{role}") == "on"
                    can_create = (
                        request.form.get(f"create__{ci_class}__{role}") == "on"
                        if role in CI_CLASS_PERMISSION_CRUD_ROLES else False
                    )
                    can_update = (
                        request.form.get(f"update__{ci_class}__{role}") == "on"
                        if role in CI_CLASS_PERMISSION_CRUD_ROLES else False
                    )
                    can_delete = (
                        request.form.get(f"delete__{ci_class}__{role}") == "on"
                        if role in CI_CLASS_PERMISSION_CRUD_ROLES else False
                    )
                    row = CiClassPermission.query.filter_by(
                        tenant_id=tenant_id, ci_class=ci_class, role=role,
                    ).first()
                    if not row:
                        # Only create a row when it actually grants something,
                        # or when this class is newly opted-in via "Add" (an
                        # all-unchecked row still needs to exist so the class
                        # shows up as managed going forward).
                        if not (can_read or can_create or can_update or can_delete) and ci_class != new_class:
                            continue
                        row = CiClassPermission(tenant_id=tenant_id, ci_class=ci_class, role=role)
                        db.session.add(row)
                    if (
                        row.can_read != can_read or row.can_create != can_create
                        or row.can_update != can_update or row.can_delete != can_delete
                    ):
                        row.can_read, row.can_create = can_read, can_create
                        row.can_update, row.can_delete = can_update, can_delete
                        row.updated_by_id = current_user.id
                        changed.append(
                            f"{ci_class}/{role}=read:{can_read},create:{can_create},"
                            f"update:{can_update},delete:{can_delete}"
                        )
            if changed:
                audit("configure", "CI class permission", "; ".join(changed))
            db.session.commit()
            flash("CI class permissions saved.", "success")
            return redirect(url_for("cmdb_permissions"))

        classes_in_use = {
            row[0] for row in tenant_query(ConfigurationItem)
            .with_entities(ConfigurationItem.ci_class).distinct().all()
        }
        all_classes = sorted(classes_in_use | managed_ci_classes(tenant_id))
        existing = CiClassPermission.query.filter_by(tenant_id=tenant_id).all()
        grants = {
            (row.ci_class, row.role): {
                "read": row.can_read, "create": row.can_create,
                "update": row.can_update, "delete": row.can_delete,
            }
            for row in existing
        }
        return render_template(
            "cmdb_permissions.html", ci_classes=all_classes, roles=CI_CLASS_PERMISSION_ROLES,
            crud_roles=CI_CLASS_PERMISSION_CRUD_ROLES, grants=grants,
            managed_classes=managed_ci_classes(tenant_id),
        )

    @app.get("/approvals")
    @login_required
    def approvals():
        query = Approval.query.join(EnterpriseRecord).filter(
            EnterpriseRecord.tenant_id == current_user.tenant_id
        )
        if not role_at_least(current_user.effective_role, "admin"):
            query = query.filter_by(approver_id=current_user.id)
        return render_template("approvals.html", approvals=query.order_by(Approval.id.desc()).all())

    @app.post("/approval-votes/<int:vote_id>/decide")
    @login_required
    def approval_vote_decide(vote_id):
        vote = db.get_or_404(ApprovalVote, vote_id)
        if (
            vote.approver_id != current_user.id
            or vote.gate.chain.tenant_id != current_user.tenant_id
        ):
            abort(403)
        decision = request.form.get("decision")
        if decision not in ("Approved", "Rejected"):
            abort(400)
        if decision == "Approved" and vote.gate.chain.target_type == "ticket":
            target = db.session.get(Ticket, vote.gate.chain.target_id)
            governance = target.change_governance if target else None
            if governance and governance.change_type != "Emergency":
                freeze = active_change_freeze(current_user.tenant_id, governance.planned_start, governance.planned_end)
                if freeze:
                    abort(409, description=(
                        f"Cannot approve: this change's planned window falls inside the "
                        f'change freeze "{freeze.title}". Only Emergency changes can be approved during a freeze.'
                    ))
        decide_vote(vote, decision, request.form.get("comments", "").strip())
        log_history(
            vote.gate.chain.target_type, vote.gate.chain.target_id,
            f"Approval {decision.lower()}",
            details=(
                f"{vote.gate.name} · {current_user.name}: "
                f"{request.form.get('comments', '').strip() or 'No decision comments'}"
            ),
        )
        audit(decision.lower(), vote.gate.chain.name, vote.gate.name)
        db.session.commit()
        return redirect(request.referrer or url_for("approval_chains"))

    @app.get("/approval-chains")
    @login_required
    def approval_chains():
        chains = []
        for chain in tenant_query(ApprovalChain).order_by(
            ApprovalChain.created_at.desc()
        ).all():
            if role_at_least(current_user.effective_role, "admin") or any(
                vote.approver_id == current_user.id
                for gate in chain.gates for vote in gate.votes
            ):
                chains.append(chain)
            elif chain.target_type == "ticket":
                target = db.session.get(Ticket, chain.target_id)
                if target and user_can_view_ticket(current_user, target):
                    chains.append(chain)
            elif chain.target_type == "ritm":
                target = db.session.get(RequestedItem, chain.target_id)
                if target and user_can_view_catalog_request(current_user, target.request):
                    chains.append(chain)
        pending = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
            ApprovalVote.approver_id == current_user.id,
            ApprovalVote.state == "Requested",
            ApprovalChain.tenant_id == current_user.tenant_id,
        ).all()
        return render_template("approval_chains.html", chains=chains, pending=pending)

    @app.get("/requests")
    @login_required
    def requests_list():
        query = visible_catalog_request_query(current_user)
        q = request.args.get("q", "").strip()
        if q:
            query = query.filter(CatalogRequest.number.ilike(f"%{q}%"))
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.order_by(CatalogRequest.opened_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        return render_template(
            "requests.html", requests=rows, q=q, page=page, pages=pages, total=total,
        )

    @app.get("/requests/export.csv")
    @login_required
    def requests_export():
        query = visible_catalog_request_query(current_user)
        q = request.args.get("q", "").strip()
        if q:
            query = query.filter(CatalogRequest.number.ilike(f"%{q}%"))
        export_limit = 5000
        rows = query.order_by(CatalogRequest.opened_at.desc()).limit(export_limit).all()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Number", "Requested for", "Requested by", "State", "Items", "Opened"])
        for req in rows:
            writer.writerow([
                req.number, req.requested_for.name if req.requested_for else "",
                req.requested_by.name if req.requested_by else "", req.state, len(req.items),
                usertime_filter(req.opened_at, "%Y-%m-%d %H:%M"),
            ])
        return csv_response(buffer.getvalue(), "requests.csv")

    @app.get("/request/<int:request_id>")
    @login_required
    def request_detail(request_id):
        req = tenant_record_or_404(CatalogRequest, request_id)
        if not user_can_view_catalog_request(current_user, req):
            abort(403, description="You are not involved in this request or its fulfillment.")
        return render_template(
            "request_detail.html", req=req,
            catalog_items=tenant_query(CatalogItem).filter_by(active=True).order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
            can_add_request_item=user_can_add_request_item(current_user, req),
        )

    @app.get("/ritm/<int:ritm_id>")
    @login_required
    def ritm_detail(ritm_id):
        ritm = db.get_or_404(RequestedItem, ritm_id)
        req = ritm.request
        if req.tenant_id != current_user.tenant_id:
            abort(404)
        if not user_can_view_catalog_request(current_user, req):
            abort(403, description="You are not involved in this request or its fulfillment.")
        can_manage = user_can_manage_ritm(current_user, ritm)
        chains = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm.id).all()
        slas = TaskSLA.query.filter_by(target_type="ritm", target_id=ritm.id).all()
        task_state_options = {
            task.id: CATALOG_TASK_TRANSITIONS.get(task.state, (task.state,))
            for task in ritm.tasks
        }
        catalog_task_permissions = {
            task.id: user_in_group(current_user, task.assignment_group)
            for task in ritm.tasks
        }
        try:
            variables = json.loads(ritm.variables_json or "{}")
        except (TypeError, ValueError):
            variables = {}
        return render_template(
            "ritm_detail.html", ritm=ritm, req=req, chains=chains, slas=slas,
            variables=variables,
            task_state_options=task_state_options,
            catalog_task_permissions=catalog_task_permissions,
            can_manage=can_manage,
            state_track=build_state_track("ritm", ritm.state),
            teams=tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment", active=True
            ).order_by(SupportGroup.name).all(),
            related=related_records("ritm", ritm.id),
            history=TaskHistory.query.filter_by(
                target_type="ritm", target_id=ritm.id
            ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all(),
        )

    @app.post("/request/<int:request_id>/items")
    @login_required
    def request_item_add(request_id):
        req = tenant_record_or_404(CatalogRequest, request_id)
        if req.state not in ("Open", "Awaiting Approval"):
            abort(409, description="Items cannot be added to a completed request.")
        if not user_can_add_request_item(current_user, req):
            abort(403, description="Only request participants or an administrator can add items.")
        item = tenant_record_or_404(CatalogItem, int(request.form["catalog_item_id"]))
        def build_ritm():
            ritm = RequestedItem(
                number=sequence_number(RequestedItem, "RITM"), request_id=req.id,
                catalog_item_id=item.id,
                state="Awaiting Approval" if item.approval_required else "Open",
                stage="Approval" if item.approval_required else "Fulfillment",
                variables_json=json.dumps({"details": request.form.get("details", "")}),
                due_at=now() + timedelta(days=item.delivery_days), tenant_id=req.tenant_id,
            )
            db.session.add(ritm)
            return ritm
        ritm = create_with_retry_on_number_collision(build_ritm)
        attach_slas("ritm", ritm.id, None)
        if item.approval_required:
            manager = tenant_query(User).filter(User.role.in_(["admin", "superadmin"]), User.active.is_(True)).first()
            fulfillment = tenant_query(SupportGroup).filter_by(name="Service Desk").first()
            approvers = [member.user_id for member in fulfillment.members if member.user.active] if fulfillment else []
            if not manager or not approvers:
                abort(409, description="Request approval and fulfillment approvers must be configured.")
            create_approval_chain(
                f"{ritm.number} service fulfillment", "ritm", ritm.id, [
                    {"name": "Manager approval", "mode": "all", "approver_ids": [manager.id]},
                    {"name": "Fulfillment authorization", "mode": "any", "approver_ids": approvers},
                ],
            )
        else:
            create_catalog_task(ritm)
        log_history(
            "request", req.id, "Requested item added",
            details=f"{ritm.number}: {item.name}",
        )
        log_history(
            "ritm", ritm.id, "Requested item created",
            details=f"Added to {req.number}: {item.name}",
        )
        audit("add requested item", req.number, f"{ritm.number}: {item.name}")
        db.session.commit()
        return redirect(url_for("request_detail", request_id=req.id))

    @app.post("/ritm/<int:ritm_id>/tasks")
    @roles("agent", "manager", "admin")
    def catalog_task_add(ritm_id):
        ritm = db.get_or_404(RequestedItem, ritm_id)
        if not user_can_manage_ritm(current_user, ritm):
            abort(403, description="Only the fulfillment team can add tasks to this requested item.")
        chain = approval_chain_for("ritm", ritm.id)
        if chain and chain.state != "Approved":
            abort(409, description="Catalog tasks cannot be added until the RITM is approved.")
        group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
        if not group.active or group.group_type != "IT Fulfillment":
            abort(400, description="Catalog tasks require an active IT fulfillment team.")
        def build_task():
            task = CatalogTask(
                number=sequence_number(CatalogTask, "SCTASK"),
                requested_item_id=ritm.id,
                title=request.form["title"].strip(),
                sequence=len(ritm.tasks) + 1,
                assignment_group_id=group.id,
                due_at=ritm.due_at, tenant_id=ritm.tenant_id,
            )
            db.session.add(task)
            return task
        task = create_with_retry_on_number_collision(build_task)
        execution_mode = request.form.get("execution_mode", "Parallel")
        predecessor = (
            CatalogTask.query.filter_by(requested_item_id=ritm.id)
            .filter(CatalogTask.id != task.id)
            .order_by(CatalogTask.sequence.desc(), CatalogTask.id.desc()).first()
        )
        if execution_mode not in ("Parallel", "Sequential"):
            abort(400)
        db.session.add(CatalogTaskControl(
            task_id=task.id, execution_mode=execution_mode,
            predecessor_task_id=(
                predecessor.id if execution_mode == "Sequential" and predecessor else None
            ),
        ))
        log_history(
            "ritm", ritm.id, "Catalog task created",
            details=(
                f"{task.number}: {task.title} → {group.name} · {execution_mode}"
                + (f" after {predecessor.number}" if execution_mode == "Sequential" and predecessor else "")
            ),
        )
        audit("create", task.number, f"{ritm.number}: {task.title}")
        db.session.commit()
        return redirect(url_for("request_detail", request_id=ritm.request_id))

    def user_can_view_catalog_task(user, task):
        ritm = task.requested_item
        return (
            user_can_view_catalog_request(user, ritm.request)
            or user_in_group(user, task.assignment_group)
        )

    @app.get("/catalog-task/<int:task_id>")
    @login_required
    def catalog_task_detail(task_id):
        task = db.get_or_404(CatalogTask, task_id)
        if not user_can_view_catalog_task(current_user, task):
            abort(403, description="You are not involved in this catalog task or its fulfillment.")
        ritm = task.requested_item
        can_edit = user_in_group(current_user, task.assignment_group)
        member_ids = {member.user_id for member in task.assignment_group.members} if task.assignment_group else set()
        if task.assignment_group and task.assignment_group.manager_id:
            member_ids.add(task.assignment_group.manager_id)
        agents = User.query.filter(
            User.id.in_(member_ids), User.active.is_(True),
            User.role.in_(["agent", "manager", "admin", "superadmin"]),
        ).order_by(User.name).all() if member_ids else []
        history = TaskHistory.query.filter_by(
            target_type="ritm", target_id=ritm.id
        ).filter(TaskHistory.details.contains(task.number)).order_by(
            TaskHistory.created_at.desc(), TaskHistory.id.desc()
        ).all()
        internal_notes = TaskNote.query.filter_by(
            target_type="catalog_task", target_id=task.id, visibility="internal"
        ).order_by(TaskNote.created_at.desc()).all() if can_edit else []
        ritm_comments = TaskNote.query.filter_by(
            target_type="ritm", target_id=ritm.id, visibility="customer"
        ).order_by(TaskNote.created_at.desc()).all()
        try:
            variables = json.loads(ritm.variables_json or "{}")
        except (TypeError, ValueError):
            variables = {}
        siblings = CatalogTask.query.filter_by(
            requested_item_id=ritm.id
        ).filter(CatalogTask.id != task.id).order_by(CatalogTask.sequence, CatalogTask.id).all()
        ci_links = TaskCI.query.filter_by(
            target_type="ritm", target_id=ritm.id
        ).order_by(TaskCI.relationship_role).all()
        chain = approval_chain_for("ritm", ritm.id)
        approval_votes = [vote for gate in chain.gates for vote in gate.votes] if chain else []
        allowed_states = CATALOG_TASK_TRANSITIONS.get(task.state, (task.state,))
        gate_block = None
        selectable_states = [task.state]
        linked_change = ritm_linked_change(ritm)
        for candidate in allowed_states:
            if candidate == task.state:
                continue
            if candidate == "Work in Progress" and linked_change and linked_change.state in ("New", "Awaiting Approval"):
                gate_block = (
                    f"{task.number} cannot start production work: it is linked to "
                    f"{linked_change.number}, which is not yet approved and authorized. "
                    "Coordination on this task (details, scheduling) is fine — set it to "
                    "Pending until the change is authorized."
                )
                continue
            selectable_states.append(candidate)
        return render_template(
            "catalog_task_detail.html", task=task, ritm=ritm,
            can_edit=can_edit, agents=agents, history=history,
            work_task_states=CATALOG_TASK_TRANSITIONS,
            internal_notes=internal_notes, ritm_comments=ritm_comments,
            variables=variables, siblings=siblings, ci_links=ci_links,
            approval_votes=approval_votes, chain=chain,
            selectable_states=selectable_states, gate_block=gate_block,
            state_track=build_state_track("catalog_task", task.state),
        )

    @app.post("/catalog-task/<int:task_id>/notes")
    @login_required
    def catalog_task_note_add(task_id):
        task = db.get_or_404(CatalogTask, task_id)
        if not user_can_view_catalog_task(current_user, task):
            abort(403)
        ritm = task.requested_item
        visibility = request.form.get("visibility")
        body = request.form.get("body", "").strip()
        if visibility not in ("internal", "customer"):
            abort(400, description="Select a valid note visibility.")
        if visibility == "internal" and not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                f"Only active members of {task.assignment_group.name if task.assignment_group else 'the assignment group'} "
                "can add internal work notes."
            ))
        if body:
            if visibility == "internal":
                db.session.add(TaskNote(
                    target_type="catalog_task", target_id=task.id,
                    visibility="internal", body=body, user_id=current_user.id,
                ))
                log_history("ritm", ritm.id, f"{task.number} note added", details=body[:500])
            else:
                db.session.add(TaskNote(
                    target_type="ritm", target_id=ritm.id,
                    visibility="customer", body=body, user_id=current_user.id,
                ))
                log_history("ritm", ritm.id, "Customer-visible comment added", details=body[:500])
                create_notification(
                    ritm.request.requested_for_id, f"New comment on {ritm.number}",
                    body[:500], tenant_id=task.assignment_group.tenant_id if task.assignment_group else current_user.tenant_id,
                    target_type="ritm", target_id=ritm.id,
                    event_type="ritm.comment_added",
                    template_vars={"ritm_number": ritm.number, "comment": body[:500]},
                )
            audit("note", task.number, body[:120])
            db.session.commit()
        return redirect(url_for("catalog_task_detail", task_id=task.id))

    @app.post("/catalog-task/<int:task_id>")
    @roles("agent", "manager", "admin")
    def catalog_task_update(task_id):
        task = db.get_or_404(CatalogTask, task_id)
        if not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                f"Only active members of {task.assignment_group.name if task.assignment_group else 'the assignment group'} "
                f"can update {task.number}."
            ))
        before = {"state": task.state, "work notes": task.work_notes}
        try:
            transition_catalog_task(task, request.form.get("state", task.state))
        except HTTPException as error:
            db.session.rollback()
            flash(error.description or "That change could not be made.", "error")
            return redirect(request.referrer or url_for("request_detail", request_id=task.requested_item.request_id))
        task.work_notes = request.form.get("work_notes", "")
        task.assignee_id = current_user.id
        ritm = task.requested_item
        terminal_states = {"Closed Complete", "Closed Incomplete", "Closed Skipped"}
        all_terminal = all(item.state in terminal_states for item in ritm.tasks)
        if all_terminal and all(item.state == "Closed Complete" for item in ritm.tasks):
            ritm.state = "Closed Complete"
            ritm.stage = "Completed"
            sync_slas("ritm", ritm.id, ritm.state)
            if all(item.state == "Closed Complete" for item in ritm.request.items):
                ritm.request.state = "Closed Complete"
                ritm.request.closed_at = now()
        elif all_terminal and any(item.state == "Closed Incomplete" for item in ritm.tasks):
            ritm.state = "Closed Incomplete"
            ritm.stage = "Completed"
            ritm.request.state = "Closed Incomplete"
        log_field_changes("ritm", ritm.id, before, {
            "state": task.state, "work notes": task.work_notes,
        }, event=f"{task.number} updated")
        audit("update", task.number, task.state)
        db.session.commit()
        redirect_target = request.form.get("redirect_to")
        if redirect_target == "task":
            return redirect(url_for("catalog_task_detail", task_id=task.id))
        return redirect(url_for("request_detail", request_id=ritm.request_id))

    def _admin_referrer_redirect(fallback_endpoint, **fallback_kwargs):
        """Isolated settings pages (B-320) all post to their one shared
        handler endpoint; send the user back to the specific page they
        came from instead of always landing on the handler's own index."""
        destination = request.referrer
        if destination and destination.startswith(request.host_url):
            return redirect(destination)
        return redirect(url_for(fallback_endpoint, **fallback_kwargs))

    @app.route("/itil/administration", methods=["GET", "POST"])
    @app.route("/service-operations/settings", methods=["GET", "POST"])
    @roles("admin")
    @require_action("configure")
    def itil_admin():
        if request.method == "POST":
            action = request.form.get("action")
            if action == "add_directory_mapping":
                directory_group = request.form.get("directory_group", "").strip()
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if not directory_group or len(directory_group) > 500:
                    abort(400)
                existing = DirectoryGroupMapping.query.filter(
                    func.lower(DirectoryGroupMapping.directory_group)
                    == directory_group.casefold()
                ).first()
                if existing:
                    existing.support_group_id = group.id
                    existing.active = True
                else:
                    db.session.add(DirectoryGroupMapping(
                        directory_group=directory_group, support_group_id=group.id
                    ))
                audit("configure", "AD team mapping", f"{directory_group} -> {group.name}")
                flash("AD group mapping saved. It applies at each user's next login.", "success")
            elif action == "delete_directory_mapping":
                mapping = db.get_or_404(DirectoryGroupMapping, int(request.form["mapping_id"]))
                mapping.active = False
                audit("disable", "AD team mapping", mapping.directory_group)
                flash("AD group mapping disabled. Memberships reconcile at next login.", "success")
            elif action == "add_support_group_alias":
                alias = request.form.get("alias", "").strip()
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if not alias or len(alias) > 160:
                    abort(400)
                existing = SupportGroupAlias.query.filter(
                    SupportGroupAlias.tenant_id == current_user.tenant_id,
                    func.lower(SupportGroupAlias.alias) == alias.casefold(),
                ).first()
                if existing:
                    existing.group_id = group.id
                else:
                    db.session.add(SupportGroupAlias(alias=alias, group_id=group.id))
                audit("configure", "Team name alias", f"{alias} -> {group.name}")
                # If a real SupportGroup with this exact name already exists
                # (e.g. it was created by an import before this alias was
                # registered), it's a duplicate of the target team -- merge
                # it in now so existing CIs/tickets/etc. that point at the
                # duplicate resolve correctly instead of erroring with
                # "team requires an active manager" or splitting approvals.
                duplicate_group = SupportGroup.query.filter(
                    SupportGroup.tenant_id == current_user.tenant_id,
                    SupportGroup.id != group.id,
                    func.lower(SupportGroup.name) == alias.casefold(),
                ).first()
                if duplicate_group:
                    moved = merge_support_group_into(duplicate_group, group)
                    audit("merge", "Support group",
                          f"{duplicate_group.name} -> {group.name} ({moved} records)")
                    flash(
                        f'"{alias}" now resolves to {group.name}. It also found an existing '
                        f'"{duplicate_group.name}" team and merged it into {group.name} '
                        f"({moved} records reassigned).", "success",
                    )
                else:
                    flash(f'"{alias}" now resolves to {group.name}.', "success")
            elif action == "delete_support_group_alias":
                group_alias = tenant_record_or_404(SupportGroupAlias, int(request.form["alias_id"]))
                audit("delete", "Team name alias", group_alias.alias)
                db.session.delete(group_alias)
                flash("Team name alias removed.", "success")
            elif action == "merge_duplicate_teams":
                merged = find_and_merge_duplicate_groups(current_user.tenant_id)
                audit("merge", "Support groups", f"{merged} duplicate teams merged")
                flash(
                    f"Merged {merged} duplicate team name(s)." if merged
                    else "No duplicate team names found.", "success",
                )
            elif action == "set_manager":
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if group.group_type not in ("IT Fulfillment", "Executive"):
                    abort(400)
                old_manager_id = group.manager_id
                manager_id = int(request.form["manager_id"]) if request.form.get("manager_id") else None
                manager = db.session.get(User, manager_id) if manager_id else None
                if manager and not manager.active:
                    abort(400)
                if old_manager_id and old_manager_id != manager_id:
                    old_membership = GroupMember.query.filter_by(
                        group_id=group.id, user_id=old_manager_id, role="manager"
                    ).first()
                    if old_membership:
                        managed = DirectoryManagedMembership.query.filter_by(
                            group_id=group.id, user_id=old_manager_id
                        ).first()
                        if managed:
                            old_membership.role = "member"
                        else:
                            db.session.delete(old_membership)
                group.manager_id = manager_id
                if manager:
                    membership = GroupMember.query.filter_by(
                        group_id=group.id, user_id=manager.id
                    ).first()
                    if membership:
                        membership.role = "manager"
                    else:
                        db.session.add(GroupMember(
                            group_id=group.id, user_id=manager.id, role="manager", tenant_id=group.tenant_id
                        ))
                    sync_implied_role_grants(manager)
                if old_manager_id and old_manager_id != manager_id:
                    old_manager = db.session.get(User, old_manager_id)
                    sync_implied_role_grants(old_manager)
                audit("configure", f"{group.name} manager",
                      manager.username if manager else "Unassigned")
                flash(f"{group.name} manager updated.", "success")
            elif action == "set_ccb_authority":
                user = tenant_record_or_404(User, int(request.form["user_id"]))
                ccb = tenant_query(SupportGroup).filter_by(name="Change Control Board").one()
                membership = GroupMember.query.filter_by(
                    group_id=ccb.id, user_id=user.id
                ).first()
                enabled = request.form.get("enabled") == "true"
                if enabled and not user.active:
                    abort(400)
                if enabled:
                    if membership:
                        membership.role = "CCB approver"
                    else:
                        db.session.add(GroupMember(
                            group_id=ccb.id, user_id=user.id, role="CCB approver", tenant_id=ccb.tenant_id
                        ))
                elif membership:
                    db.session.delete(membership)
                audit("configure", "CCB approval authority",
                      f"{user.username}: {'granted' if enabled else 'revoked'}")
                flash("CCB approval authority updated.", "success")
            elif action == "add_group_member":
                # B-322: governance groups previously showed only a member
                # *count* with no way to see who was in a group or add
                # someone manually -- membership could only be changed
                # indirectly (AD group sync, or the separate manager/CCB
                # controls). This gives admins the same full manual liberty
                # AD-driven membership already has.
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                user = tenant_record_or_404(User, int(request.form["user_id"]))
                if not user.active:
                    abort(400, description="Only active users can be added to a group.")
                existing = GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first()
                if not existing:
                    db.session.add(GroupMember(
                        group_id=group.id, user_id=user.id, role="member", tenant_id=group.tenant_id,
                    ))
                    sync_implied_role_grants(user)
                    audit("configure", f"{group.name} membership", f"added {user.username}")
                    flash(f"{user.name} added to {group.name}.", "success")
                else:
                    flash(f"{user.name} is already a member of {group.name}.", "error")
            elif action == "remove_group_member":
                membership = tenant_record_or_404(GroupMember, int(request.form["member_id"]))
                group = db.session.get(SupportGroup, membership.group_id)
                user = membership.user
                if membership.role in ("manager", "CCB approver"):
                    abort(400, description=(
                        "Remove this person's manager/CCB authority first, from Team managers "
                        "or Approval authority, before removing their membership."
                    ))
                db.session.delete(membership)
                db.session.flush()
                sync_implied_role_grants(user)
                audit("configure", f"{group.name} membership", f"removed {user.username}")
                flash(f"{user.name} removed from {group.name}.", "success")
            elif action == "set_change_approval_policy":
                submitted = request.form.get("ccb_required_environments", "")
                environments = []
                seen = set()
                for value in submitted.split(","):
                    environment = value.strip()
                    normalized = environment.casefold()
                    if environment and normalized not in seen:
                        seen.add(normalized)
                        environments.append(environment)
                if not environments or len(environments) > 20 or any(len(value) > 80 for value in environments):
                    abort(400, description="Enter 1 to 20 environment names, separated by commas.")
                policy_value = ", ".join(environments)
                row = db.session.get(PlatformSetting, "CCB_REQUIRED_ENVIRONMENTS")
                if not row:
                    row = PlatformSetting(key="CCB_REQUIRED_ENVIRONMENTS")
                    db.session.add(row)
                row.value = policy_value
                row.encrypted = False
                row.updated_by_id = current_user.id
                audit("configure", "Change approval policy",
                      f"CCB required for: {policy_value}")
                flash("Change approval policy updated.", "success")
            elif action == "set_ticket_defaults":
                priority = request.form.get("default_ticket_priority", "")
                if priority not in ("P1", "P2", "P3", "P4"):
                    abort(400, description="Select a valid default ticket priority.")
                values = {
                    "DEFAULT_TICKET_PRIORITY": priority,
                    "SYNC_CHILD_INCIDENT_STATES": (
                        "true" if request.form.get("sync_child_incident_states") else "false"
                    ),
                }
                for key, value in values.items():
                    row = db.session.get(PlatformSetting, key)
                    if not row:
                        row = PlatformSetting(key=key)
                        db.session.add(row)
                    row.value = value
                    row.encrypted = False
                    row.updated_by_id = current_user.id
                audit("configure", "Ticket defaults",
                      f"priority={priority}; synchronize child incidents={values['SYNC_CHILD_INCIDENT_STATES']}")
                flash("Ticket defaults updated.", "success")
            elif action == "set_catalog_route":
                item = tenant_record_or_404(CatalogItem, int(request.form["catalog_item_id"]))
                group = tenant_record_or_404(SupportGroup, int(request.form["group_id"]))
                if (
                    not group.active
                    or group.group_type not in ("Fulfillment", "IT Fulfillment")
                ):
                    abort(400, description=(
                        "Catalog items can route only to an active fulfillment team."
                    ))
                route = item.fulfillment_route
                if not route:
                    route = CatalogItemRouting(catalog_item_id=item.id, tenant_id=item.tenant_id)
                    db.session.add(route)
                route.support_group_id = group.id
                route.active = True
                route.updated_by_id = current_user.id
                audit(
                    "configure", f"{item.name} catalog route",
                    f"Default fulfillment team: {group.name}",
                )
                flash(
                    f"{item.name} will create fulfillment tasks for {group.name}.",
                    "success",
                )
            elif action in ("create_catalog_item", "update_catalog_item"):
                name = request.form.get("name", "").strip()
                category = request.form.get("category", "").strip()
                description = request.form.get("description", "").strip()
                try:
                    delivery_days = int(request.form.get("delivery_days", ""))
                    group_id = int(request.form.get("group_id", ""))
                except (TypeError, ValueError):
                    abort(400, description="Delivery target and fulfillment team are required.")
                if not name or len(name) > 160:
                    abort(400, description="Catalog item name must contain 1 to 160 characters.")
                if not category or len(category) > 80:
                    abort(400, description="Category must contain 1 to 80 characters.")
                if not description:
                    abort(400, description="Catalog item description is required.")
                if delivery_days < 1 or delivery_days > 365:
                    abort(400, description="Delivery target must be between 1 and 365 days.")
                group = tenant_record_or_404(SupportGroup, group_id)
                if (
                    not group.active
                    or group.group_type not in ("Fulfillment", "IT Fulfillment")
                ):
                    abort(400, description=(
                        "Catalog items can route only to an active fulfillment team."
                    ))
                item_id = (
                    int(request.form["catalog_item_id"])
                    if action == "update_catalog_item" else None
                )
                duplicate = CatalogItem.query.filter(
                    func.lower(CatalogItem.name) == name.casefold()
                )
                if item_id:
                    duplicate = duplicate.filter(CatalogItem.id != item_id)
                if duplicate.first():
                    abort(409, description="A catalog item with that name already exists.")
                if item_id:
                    item = tenant_record_or_404(CatalogItem, item_id)
                    previous_name = item.name
                else:
                    item = CatalogItem()
                    db.session.add(item)
                    previous_name = None
                item.name = name
                item.category = category
                item.description = description
                item.delivery_days = delivery_days
                item.approval_required = bool(request.form.get("approval_required"))
                item.active = bool(request.form.get("active"))
                db.session.flush()
                route = item.fulfillment_route
                if not route:
                    route = CatalogItemRouting(catalog_item_id=item.id, tenant_id=item.tenant_id)
                    db.session.add(route)
                route.support_group_id = group.id
                route.active = True
                route.updated_by_id = current_user.id
                audit(
                    "create" if action == "create_catalog_item" else "update",
                    f"Catalog item: {item.name}",
                    (
                        f"{category}; {delivery_days} day target; "
                        f"{'approval required' if item.approval_required else 'no approval'}; "
                        f"{'active' if item.active else 'inactive'}; route {group.name}"
                    ),
                )
                flash(
                    (
                        f"{item.name} created and routed to {group.name}."
                        if previous_name is None else
                        f"{previous_name} updated as {item.name}."
                    ),
                    "success",
                )
            elif action == "create_business_schedule":
                name = request.form.get("name", "").strip()
                timezone_name = request.form.get("timezone_name", "").strip()
                weekdays = sorted({
                    int(value) for value in request.form.getlist("weekdays")
                })
                start_text = request.form.get("start_time", "")
                end_text = request.form.get("end_time", "")
                if not name or len(name) > 160:
                    abort(400, description="Schedule name must contain 1 to 160 characters.")
                try:
                    start_time = dt_time.fromisoformat(start_text)
                    end_time = dt_time.fromisoformat(end_text)
                    validate_calendar(timezone_name, weekdays, start_time, end_time)
                except (ValueError, TypeError) as error:
                    abort(400, description=str(error))
                duplicate = tenant_query(BusinessSchedule).filter(
                    func.lower(BusinessSchedule.name) == name.casefold()
                ).first()
                if duplicate:
                    abort(409, description="A business schedule with that name already exists.")
                db.session.add(BusinessSchedule(
                    name=name, timezone_name=timezone_name,
                    weekdays_json=json.dumps(weekdays),
                    start_time_text=start_text, end_time_text=end_text,
                ))
                audit("create", f"Business schedule: {name}", timezone_name)
                flash(f"Business schedule {name} created.", "success")
            elif action == "add_schedule_holiday":
                schedule = tenant_record_or_404(
                    BusinessSchedule, int(request.form["schedule_id"])
                )
                holiday_name = request.form.get("name", "").strip()
                try:
                    holiday_date = date.fromisoformat(request.form.get("holiday_date", ""))
                except ValueError:
                    abort(400, description="Enter a valid holiday date.")
                if not holiday_name:
                    abort(400, description="Holiday name is required.")
                if ScheduleHoliday.query.filter_by(
                    schedule_id=schedule.id, holiday_date=holiday_date
                ).first():
                    abort(409, description="That date is already excluded.")
                db.session.add(ScheduleHoliday(
                    schedule_id=schedule.id, holiday_date=holiday_date, name=holiday_name
                ))
                audit("create", f"Schedule holiday: {schedule.name}",
                      f"{holiday_date.isoformat()} {holiday_name}")
                flash("Schedule holiday added.", "success")
            elif action == "create_sla_definition":
                name = request.form.get("name", "").strip()
                target_type = request.form.get("target_type", "")
                priority = request.form.get("priority") or None
                pause_states = request.form.get("pause_states", "").strip()
                try:
                    duration = int(request.form.get("duration_minutes", ""))
                    schedule_id = int(request.form["schedule_id"]) if request.form.get("schedule_id") else None
                except (TypeError, ValueError):
                    abort(400, description="SLA duration and schedule are invalid.")
                if not name or target_type not in ("ticket", "ritm", "client_ticket") or priority not in (None, "P1", "P2", "P3", "P4", "Low", "Normal", "High", "Urgent"):
                    abort(400, description="SLA name, target and priority are invalid.")
                if duration < 1 or duration > 525600:
                    abort(400, description="SLA duration must be between 1 and 525600 minutes.")
                schedule = tenant_record_or_404(BusinessSchedule, schedule_id) if schedule_id else None
                # Only meaningful (and only ever accepted) for a client_ticket
                # SLA -- an org-specific row overrides the tenant-wide default
                # for the same priority, see attach_slas()'s docstring.
                client_organization = None
                if target_type == "client_ticket" and request.form.get("client_organization_id"):
                    client_organization = tenant_record_or_404(
                        ClientOrganization, request.form.get("client_organization_id", type=int)
                    )
                if tenant_query(SLADefinition).filter(
                    func.lower(SLADefinition.name) == name.casefold()
                ).first():
                    abort(409, description="An SLA definition with that name already exists.")
                agreement_type = request.form.get("agreement_type", "SLA")
                if agreement_type not in SLA_AGREEMENT_TYPES:
                    abort(400, description="Select a valid agreement type.")
                counterparty = request.form.get("counterparty", "").strip()
                db.session.add(SLADefinition(
                    name=name, target_type=target_type, priority=priority,
                    duration_minutes=duration, pause_states=pause_states,
                    schedule_id=schedule.id if schedule else None,
                    agreement_type=agreement_type,
                    counterparty=counterparty if agreement_type != "SLA" else "",
                    client_organization_id=client_organization.id if client_organization else None,
                ))
                audit("create", f"SLA definition: {name}",
                      f"{agreement_type}; {duration} minutes; {schedule.name if schedule else '24x7'}"
                      + (f"; org override for {client_organization.name}" if client_organization else ""))
                flash(f"{agreement_type} definition {name} created.", "success")
            elif action == "create_change_freeze":
                title = request.form.get("title", "").strip()
                starts_at = parse_form_datetime(request.form.get("starts_at", ""))
                ends_at = parse_form_datetime(request.form.get("ends_at", ""))
                if not title or not starts_at or not ends_at:
                    abort(400, description="Freeze title, start and end are required.")
                if ends_at <= starts_at:
                    abort(400, description="Freeze end must be later than its start.")
                db.session.add(ChangeFreezeWindow(
                    title=title, starts_at=starts_at, ends_at=ends_at,
                    reason=request.form.get("reason", "").strip(), created_by_id=current_user.id,
                ))
                audit("create", f"Change freeze: {title}", f"{starts_at.isoformat()} – {ends_at.isoformat()}")
                flash(f"Change freeze \"{title}\" created. Standard/Normal changes cannot be scheduled inside it.", "success")
            elif action == "delete_change_freeze":
                window = tenant_record_or_404(ChangeFreezeWindow, int(request.form["window_id"]))
                audit("delete", f"Change freeze: {window.title}")
                db.session.delete(window)
                flash("Change freeze removed.", "success")
            elif action == "link_service_ci":
                service = tenant_record_or_404(ServiceOffering, int(request.form["service_offering_id"]))
                role = request.form.get("relationship_role", "Supporting")
                if role not in ("Primary", "Supporting"):
                    abort(400)
                try:
                    ci_ids = [int(raw) for raw in request.form.getlist("ci_id") if raw.strip()]
                except ValueError:
                    abort(400)
                if not ci_ids:
                    abort(400, description="Select at least one configuration item.")
                linked_names = []
                for link_ci_id in dict.fromkeys(ci_ids):
                    ci = tenant_record_or_404(ConfigurationItem, link_ci_id)
                    existing_link = ServiceOfferingCI.query.filter_by(
                        service_offering_id=service.id, ci_id=ci.id
                    ).first()
                    if existing_link:
                        existing_link.relationship_role = role
                    else:
                        db.session.add(ServiceOfferingCI(
                            service_offering_id=service.id, ci_id=ci.id, relationship_role=role,
                        ))
                    linked_names.append(ci.name)
                audit("configure", f"{service.name} service mapping",
                      f"{role}: {', '.join(linked_names)}")
                flash(f"{', '.join(linked_names)} linked to {service.name}.", "success")
            elif action == "unlink_service_ci":
                link = db.get_or_404(ServiceOfferingCI, int(request.form["link_id"]))
                if link.tenant_id != current_user.tenant_id:
                    abort(404)
                audit("configure", f"{link.service_offering.name} service mapping",
                      f"removed {link.ci.name}")
                db.session.delete(link)
                flash(f"{link.ci.name} unlinked from {link.service_offering.name}.", "success")
            elif action == "sync_directory":
                # This action manages its own transaction (sync_directory commits
                # or rolls back internally) so it is handled separately from the
                # generic commit-and-redirect flow below.
                from serviceops_core.ldap_sync import DirectorySyncError, sync_directory
                dry_run = bool(request.form.get("dry_run"))
                try:
                    result = sync_directory(tenant_context_id(), dry_run=dry_run)
                except DirectorySyncError as error:
                    flash(f"Directory sync could not run: {error}", "error")
                except LdapBindError as error:
                    flash(f"Directory sync could not bind to LDAP: {error}", "error")
                else:
                    audit(
                        "configure", "LDAP directory sync",
                        f"{'Preview' if dry_run else 'Applied'}: "
                        f"{result['users_updated']} users updated, "
                        f"{result['managers_resolved']} managers resolved, "
                        f"{result['managers_provisioned']} managers provisioned, "
                        f"{result.get('self_manager_skipped', 0)} self-manager records skipped, "
                        f"{result['memberships_added']} memberships added, "
                        f"{result['memberships_removed']} memberships removed, "
                        f"{result['users_unmatched']} unmatched, "
                        f"{len(result['errors'])} errors",
                    )
                    session["ldap_sync_result"] = result
                    flash(
                        (
                            "Directory sync preview: " if dry_run else "Directory sync applied: "
                        ) + (
                            f"{result['users_updated']} users updated, "
                            f"{result['managers_resolved']} managers resolved, "
                            f"{result['managers_provisioned']} managers provisioned, "
                            f"{result.get('self_manager_skipped', 0)} self-manager records skipped, "
                            f"{result['memberships_added']} memberships added, "
                            f"{result['memberships_removed']} memberships removed, "
                            f"{result['users_unmatched']} unmatched entries, "
                            f"{len(result['errors'])} errors."
                        ),
                        "success" if not result["errors"] else "warning",
                    )
                return _admin_referrer_redirect("itil_admin")
            else:
                abort(400)
            db.session.commit()
            return _admin_referrer_redirect("itil_admin")
        return render_template("itil_admin.html")

    ITIL_ADMIN_SECTIONS = {
        "ticket-defaults": ("Ticket defaults", "Initial priority for new tickets and parent/child incident state sync."),
        "catalog": ("Catalog and fulfillment routing", "Service catalog items and which team fulfills each one by default."),
        "team-aliases": ("Team name aliases", "Historical/imported team name spellings that safely merge into one canonical team."),
        "team-managers": ("Team managers", "The named manager who holds change-approval authority for each team."),
        "executive-approval": ("Executive approval (CEO)", "The named user required to approve every Normal/Emergency change."),
        "governance-groups": ("Governance groups", "Review accountable groups, their type, manager, and current membership."),
        "change-approval-policy": ("Change approval policy", "Which CMDB environment names require Change Control Board approval."),
        "ccb": ("Change Control Board approvers", "Users granted CCB voting authority for non-standard changes."),
        "change-freeze": ("Change freeze windows", "Blocks Standard/Normal change scheduling and approval during active windows."),
        "service-offerings": ("Service offerings", "Map services to their supporting configuration items."),
        "sla": ("SLA definitions and business calendars", "Business schedules and SLA target durations by priority."),
    }

    @app.get("/service-operations/settings/directory-mapping")
    @app.get("/service-operations/settings/ldap-sync")
    @roles("admin")
    @require_action("configure")
    def itil_admin_section_ad_redirect():
        # B-322: AD/LDAP group mapping and directory sync moved onto the
        # Sign-in and directory settings page, alongside the rest of the
        # AD/LDAP connection config, instead of living in a separate area.
        return redirect(url_for("system_settings_category", category="sign_in_and_directory"))

    @app.route("/service-operations/settings/<section>")
    @roles("admin")
    @require_action("configure")
    def itil_admin_section(section):
        if section not in ITIL_ADMIN_SECTIONS:
            abort(404)
        title, description = ITIL_ADMIN_SECTIONS[section]
        groups = tenant_query(SupportGroup).order_by(SupportGroup.name).all()
        teams = [group for group in groups if group.group_type == "IT Fulfillment"]
        fulfillment_groups = [
            group for group in groups
            if group.active and group.group_type in ("Fulfillment", "IT Fulfillment")
        ]
        manager_candidates = tenant_query(User).filter(
            User.active.is_(True)
        ).order_by(User.name).all()
        ccb_candidates = tenant_query(User).join(
            UserRoleGrant, UserRoleGrant.user_id == User.id
        ).filter(
            User.active.is_(True),
            UserRoleGrant.role.in_(["manager", "admin", "superadmin"]),
        ).distinct().order_by(User.name).all()
        ccb = tenant_query(SupportGroup).filter_by(name="Change Control Board").first()
        if not ccb:
            ccb = SupportGroup(
                name="Change Control Board", group_type="CCB Approval",
                tenant_id=current_user.tenant_id,
            )
            db.session.add(ccb)
            db.session.flush()
        ccb_approver_ids = {
            member.user_id for member in ccb.members if member.role == "CCB approver"
        }
        executive_office = tenant_query(SupportGroup).filter_by(name="Executive Office").first()
        if not executive_office:
            executive_office = SupportGroup(
                name="Executive Office", group_type="Executive",
                tenant_id=current_user.tenant_id,
            )
            db.session.add(executive_office)
            db.session.flush()
        db.session.commit()
        directory_managed_member_keys = set()
        if section == "governance-groups":
            directory_managed_member_keys = {
                (row.group_id, row.user_id) for row in DirectoryManagedMembership.query.filter(
                    DirectoryManagedMembership.group_id.in_([group.id for group in groups])
                )
            }
        return render_template(
            "itil_admin_section.html", section=section, title=title, description=description,
            groups=groups, teams=teams,
            manager_candidates=manager_candidates, ccb_candidates=ccb_candidates,
            ccb=ccb, ccb_approver_ids=ccb_approver_ids,
            executive_office=executive_office,
            directory_managed_member_keys=directory_managed_member_keys,
            support_group_aliases=tenant_query(SupportGroupAlias).order_by(
                SupportGroupAlias.alias
            ).all(),
            services=tenant_query(ServiceOffering).all(),
            sla_definitions=tenant_query(SLADefinition).all(),
            client_organizations=tenant_query(ClientOrganization).order_by(ClientOrganization.name).all(),
            business_schedules=tenant_query(BusinessSchedule).order_by(
                BusinessSchedule.name
            ).all(),
            catalog_items=tenant_query(CatalogItem).order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
            fulfillment_groups=fulfillment_groups,
            change_freeze_windows=tenant_query(ChangeFreezeWindow).order_by(
                ChangeFreezeWindow.starts_at.desc()
            ).all(),
            ccb_required_environments=setting_value(
                "CCB_REQUIRED_ENVIRONMENTS", "Production"
            ),
            default_ticket_priority=setting_value(
                "DEFAULT_TICKET_PRIORITY", "P3"
            ),
            sync_child_incident_states=setting_bool(
                "SYNC_CHILD_INCIDENT_STATES"
            ),
        )

    @app.post("/change/<int:ticket_id>/conflicts")
    @roles("agent", "manager", "admin")
    def detect_change_conflicts(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        require_ticket_team_access(ticket)
        governance = ticket.change_governance
        if not governance:
            abort(404)
        run_change_conflict_detection(ticket, governance)
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.get("/notifications")
    @login_required
    def notifications():
        query = tenant_query(Notification).filter_by(user_id=current_user.id)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.order_by(Notification.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        notification_urls = {
            row.id: notification_target_url(row.target_type, row.target_id) for row in rows
        }
        return render_template(
            "notifications.html", rows=rows, notification_urls=notification_urls,
            page=page, pages=pages, total=total,
        )

    @app.post("/notifications/<int:notification_id>/read")
    @login_required
    def notification_mark_read(notification_id):
        row = tenant_query(Notification).filter_by(
            id=notification_id, user_id=current_user.id
        ).first_or_404()
        row.read = True
        db.session.commit()
        return redirect(notification_target_url(row.target_type, row.target_id) or url_for("notifications"))

    @app.post("/notifications/read-all")
    @login_required
    def notifications_mark_all_read():
        tenant_query(Notification).filter_by(
            user_id=current_user.id, read=False
        ).update({"read": True})
        db.session.commit()
        return redirect(url_for("notifications"))

    @app.post("/notifications/clear")
    @login_required
    def notifications_clear():
        tenant_query(Notification).filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return redirect(url_for("notifications"))

    @app.get("/analytics")
    @roles("agent", "manager", "admin")
    def analytics():
        ticket_query = visible_ticket_query(current_user)
        ticket_ids = [row.id for row in ticket_query.with_entities(Ticket.id).all()]
        record_ids = [row.id for row in visible_enterprise_record_query(current_user).with_entities(EnterpriseRecord.id).all()]

        ticket_states = dict(db.session.query(Ticket.state, func.count(Ticket.id)).filter(
            Ticket.id.in_(ticket_ids)
        ).group_by(Ticket.state).all()) if ticket_ids else {}
        domain_counts = dict(db.session.query(EnterpriseRecord.domain, func.count(EnterpriseRecord.id)).filter(
            EnterpriseRecord.id.in_(record_ids)
        ).group_by(EnterpriseRecord.domain).all()) if record_ids else {}
        priority_counts = dict(db.session.query(Ticket.priority, func.count(Ticket.id)).filter(
            Ticket.id.in_(ticket_ids), Ticket.state.notin_(TERMINAL_TICKET_STATES),
        ).group_by(Ticket.priority).all()) if ticket_ids else {}
        overdue_investigations = EnterpriseRecord.query.filter(
            EnterpriseRecord.id.in_(record_ids), EnterpriseRecord.due_at < now(),
            EnterpriseRecord.state.notin_(["Closed", "Resolved", "Completed"])
        ).count() if record_ids else 0

        open_ticket_ids = [
            row.id for row in ticket_query.filter(Ticket.state.notin_(TERMINAL_TICKET_STATES)).with_entities(Ticket.id).all()
        ]
        open_count = len(open_ticket_ids)

        # SLA exposure on currently open work, and 30-day compliance on resolved work,
        # both driven off TaskSLA the same way the dashboard's own SLA widgets are.
        sla_at_risk_hours = setting_int("SLA_AT_RISK_HOURS", 4)
        breach_horizon = now() + timedelta(hours=sla_at_risk_hours)
        # Only customer-facing SLAs count toward the headline breach/at-risk/compliance
        # widgets; OLA and UC agreements are internal/supplier commitments that still
        # breach and notify (see attach_slas/process_sla_breaches) but shouldn't be
        # blended into what's reported as the business's own SLA performance.
        sla_breached_open = sla_at_risk_open = 0
        if open_ticket_ids:
            for row in TaskSLA.query.join(SLADefinition, TaskSLA.definition_id == SLADefinition.id).filter(
                TaskSLA.target_type == "ticket", TaskSLA.target_id.in_(open_ticket_ids),
                TaskSLA.stage == "In Progress", SLADefinition.agreement_type == "SLA",
            ).all():
                if row.breached:
                    sla_breached_open += 1
                else:
                    breach_at = row.breach_at if row.breach_at.tzinfo else row.breach_at.replace(tzinfo=timezone.utc)
                    if breach_at <= breach_horizon:
                        sla_at_risk_open += 1

        thirty_days_ago = now() - timedelta(days=30)
        resolved_30d = ticket_query.filter(
            Ticket.state.in_(TERMINAL_TICKET_STATES), Ticket.updated_at >= thirty_days_ago,
        ).with_entities(Ticket.id, Ticket.kind, Ticket.priority, Ticket.created_at, Ticket.updated_at).all()
        resolved_30d_ids = [row.id for row in resolved_30d]
        sla_by_ticket = defaultdict(bool)
        if resolved_30d_ids:
            for row in TaskSLA.query.join(SLADefinition, TaskSLA.definition_id == SLADefinition.id).filter(
                TaskSLA.target_type == "ticket", TaskSLA.target_id.in_(resolved_30d_ids),
                SLADefinition.agreement_type == "SLA",
            ).all():
                sla_by_ticket[row.target_id] = sla_by_ticket[row.target_id] or row.breached
        tickets_with_sla = [row for row in resolved_30d if row.id in sla_by_ticket]
        sla_compliance_pct = (
            round(100 * sum(1 for row in tickets_with_sla if not sla_by_ticket[row.id]) / len(tickets_with_sla))
            if tickets_with_sla else None
        )

        # MTTR proxy: created→updated_at span for incidents that reached a terminal
        # state in the last 30 days. There is no dedicated resolved_at column, so
        # this mirrors the same updated_at convention already used for the manager
        # portal's "resolved in 30 days" metric.
        mttr_by_priority = {}
        for priority in ("P1", "P2", "P3", "P4"):
            spans = [
                (row.updated_at - row.created_at).total_seconds() / 3600
                for row in resolved_30d if row.kind == "incident" and row.priority == priority
            ]
            mttr_by_priority[priority] = round(sum(spans) / len(spans), 1) if spans else None

        # 14-day created-vs-resolved volume trend.
        today = now().date()
        volume_trend = []
        window_start = today - timedelta(days=13)
        created_counts = Counter()
        for row in ticket_query.filter(Ticket.created_at >= window_start).with_entities(Ticket.created_at).all():
            created_counts[row.created_at.date()] += 1
        resolved_counts = Counter()
        for row in resolved_30d:
            if row.updated_at.date() >= window_start:
                resolved_counts[row.updated_at.date()] += 1
        for offset in range(14):
            day = window_start + timedelta(days=offset)
            volume_trend.append({"day": day, "created": created_counts.get(day, 0), "resolved": resolved_counts.get(day, 0)})
        trend_max = max([1] + [max(d["created"], d["resolved"]) for d in volume_trend])

        # Backlog aging: how long currently-open tickets have been sitting.
        aging_buckets = {"0-1 day": 0, "1-3 days": 0, "3-7 days": 0, "7+ days": 0}
        for row in ticket_query.filter(Ticket.state.notin_(TERMINAL_TICKET_STATES)).with_entities(Ticket.created_at).all():
            age_days = (now() - row.created_at).total_seconds() / 86400
            if age_days <= 1:
                aging_buckets["0-1 day"] += 1
            elif age_days <= 3:
                aging_buckets["1-3 days"] += 1
            elif age_days <= 7:
                aging_buckets["3-7 days"] += 1
            else:
                aging_buckets["7+ days"] += 1

        # Change success rate: of changes that reached a terminal outcome in the
        # last 30 days, the share that closed out rather than being cancelled.
        change_outcomes = Counter(
            row.state for row in ticket_query.filter(
                Ticket.kind == "change", Ticket.state.in_(["Closed", "Cancelled"]),
                Ticket.updated_at >= thirty_days_ago,
            ).with_entities(Ticket.state).all()
        )
        change_total = change_outcomes.get("Closed", 0) + change_outcomes.get("Cancelled", 0)
        change_success_pct = round(100 * change_outcomes.get("Closed", 0) / change_total) if change_total else None

        # PIR-driven change success: unlike the state-based proxy above,
        # this reflects the actual reviewed outcome (see
        # ChangePostImplementationReview) -- "Closed" only tells you the
        # ticket reached a terminal state, not whether the change worked.
        change_ticket_ids = ticket_query.filter(Ticket.kind == "change").with_entities(Ticket.id).all()
        pir_rows = ChangePostImplementationReview.query.filter(
            ChangePostImplementationReview.ticket_id.in_([row.id for row in change_ticket_ids]),
            ChangePostImplementationReview.reviewed_at >= thirty_days_ago,
        ).with_entities(ChangePostImplementationReview.outcome).all()
        pir_total = len(pir_rows)
        pir_success_pct = (
            round(100 * sum(1 for row in pir_rows if row.outcome == "Successful") / pir_total)
            if pir_total else None
        )

        # First Contact Resolution proxy: incidents resolved in the last 30
        # days that were never reopened. Not a strict "resolved on the very
        # first interaction" measure (this app doesn't track interaction
        # count), but a defensible, cheaply-computed FCR signal.
        resolved_incident_ids = [
            row.id for row in ticket_query.filter(
                Ticket.kind == "incident", Ticket.state.in_(TERMINAL_TICKET_STATES),
                Ticket.updated_at >= thirty_days_ago,
            ).with_entities(Ticket.id).all()
        ]
        reopened_incident_ids = set()
        if resolved_incident_ids:
            reopened_incident_ids = {
                row.target_id for row in TaskHistory.query.filter(
                    TaskHistory.target_type == "ticket",
                    TaskHistory.target_id.in_(resolved_incident_ids),
                    TaskHistory.details.ilike("Reopened by%"),
                ).with_entities(TaskHistory.target_id).all()
            }
        fcr_total = len(resolved_incident_ids)
        fcr_pct = (
            round(100 * (fcr_total - len(reopened_incident_ids)) / fcr_total) if fcr_total else None
        )

        # CSAT: average of ratings requesters submitted in the last 30 days.
        csat_ratings = [
            row.csat_rating for row in ticket_query.filter(
                Ticket.csat_rating.isnot(None), Ticket.csat_submitted_at >= thirty_days_ago,
            ).with_entities(Ticket.csat_rating).all()
        ]
        csat_count = len(csat_ratings)
        csat_avg = round(sum(csat_ratings) / csat_count, 1) if csat_count else None

        # Top assignment groups by open ticket volume.
        open_rows = ticket_query.filter(Ticket.state.notin_(TERMINAL_TICKET_STATES)).with_entities(Ticket.id, Ticket.kind).all()
        incident_ids = [r.id for r in open_rows if r.kind == "incident"]
        change_ids = [r.id for r in open_rows if r.kind == "change"]
        group_counts = Counter()
        if incident_ids:
            for group_id, count in db.session.query(TicketAssignmentGroup.group_id, func.count(TicketAssignmentGroup.id)).filter(
                TicketAssignmentGroup.ticket_id.in_(incident_ids)
            ).group_by(TicketAssignmentGroup.group_id).all():
                group_counts[group_id] += count
        if change_ids:
            for group_id, count in db.session.query(ChangeOwnership.group_id, func.count(ChangeOwnership.id)).filter(
                ChangeOwnership.ticket_id.in_(change_ids)
            ).group_by(ChangeOwnership.group_id).all():
                group_counts[group_id] += count
        top_groups = []
        if group_counts:
            groups_by_id = {g.id: g for g in SupportGroup.query.filter(SupportGroup.id.in_(group_counts.keys())).all()}
            top_groups = sorted(
                ({"group": groups_by_id[gid], "count": count} for gid, count in group_counts.items() if gid in groups_by_id),
                key=lambda row: row["count"], reverse=True,
            )[:8]
        top_groups_max = max([1] + [row["count"] for row in top_groups])

        kpi_history_rows = KpiSnapshot.query.filter_by(tenant_id=tenant_context_id()).filter(
            KpiSnapshot.snapshot_date >= (now().date() - timedelta(days=30))
        ).order_by(KpiSnapshot.snapshot_date.desc(), KpiSnapshot.metric_name).limit(120).all()
        kpi_metric_labels = {
            "sla_compliance_pct": "SLA compliance %",
            "change_success_pct": "Change success % (reviewed)",
            "fcr_pct": "First contact resolution %",
            "csat_avg": "CSAT avg (out of 5)",
        }
        # 30 days of daily snapshots were already captured (capture_kpi_snapshots)
        # but only ever rendered as a flat date-sorted table -- turn it into a
        # per-metric trend so the point of snapshotting (spotting movement) is
        # actually visible, not just archived.
        kpi_series = {key: [] for key in kpi_metric_labels}
        for row in sorted(kpi_history_rows, key=lambda r: r.snapshot_date):
            if row.metric_name in kpi_series:
                kpi_series[row.metric_name].append({"date": row.snapshot_date.isoformat(), "value": row.metric_value})
        kpi_trends = []
        spark_w, spark_h = 240, 48
        for key, label in kpi_metric_labels.items():
            points = kpi_series[key]
            latest = points[-1]["value"] if points else None
            previous = points[-2]["value"] if len(points) > 1 else None
            values = [p["value"] for p in points]
            lo, hi = (min(values), max(values)) if values else (0, 0)
            spread = (hi - lo) or 1
            step = spark_w / max(1, len(values) - 1) if len(values) > 1 else 0
            spark_points = " ".join(
                f"{round(i * step, 1)},{round(spark_h - ((v - lo) / spread) * spark_h, 1)}"
                for i, v in enumerate(values)
            ) if len(values) > 1 else ""
            kpi_trends.append({
                "key": key, "label": label, "points": points, "latest": latest,
                "delta": (round(latest - previous, 1) if latest is not None and previous is not None else None),
                "spark_points": spark_points,
            })

        # Availability management: uptime % per business service over the
        # trailing 30 days, derived from ServiceOutage (itself auto-derived
        # from High/Critical incidents -- see sync_service_outages). This is
        # the first place in the app an availability figure exists at all.
        service_availability = []
        for service in tenant_query(ServiceOffering).order_by(ServiceOffering.name).all():
            open_outage = ServiceOutage.query.filter_by(
                service_offering_id=service.id, ended_at=None
            ).first()
            last_outage = ServiceOutage.query.filter_by(
                service_offering_id=service.id
            ).order_by(ServiceOutage.started_at.desc()).first()
            service_availability.append({
                "service": service,
                "uptime_pct": service_availability_pct(service.id),
                "open_outage": open_outage,
                "last_outage": last_outage,
            })

        return render_template(
            "analytics.html", ticket_states=ticket_states, domain_counts=domain_counts,
            kpi_history_rows=kpi_history_rows, kpi_metric_labels=kpi_metric_labels, kpi_trends=kpi_trends,
            service_availability=service_availability,
            priority_counts=priority_counts, overdue_investigations=overdue_investigations,
            modules=DOMAIN_CONFIG, open_count=open_count,
            sla_breached_open=sla_breached_open, sla_at_risk_open=sla_at_risk_open,
            sla_compliance_pct=sla_compliance_pct, mttr_by_priority=mttr_by_priority,
            volume_trend=volume_trend, trend_max=trend_max, aging_buckets=aging_buckets,
            change_success_pct=change_success_pct, change_total=change_total,
            pir_success_pct=pir_success_pct, pir_total=pir_total,
            fcr_pct=fcr_pct, fcr_total=fcr_total,
            csat_avg=csat_avg, csat_count=csat_count,
            top_groups=top_groups, top_groups_max=top_groups_max,
        )

    @app.get("/analytics/overdue")
    @roles("agent", "manager", "admin")
    def analytics_overdue():
        record_ids = [
            row.id for row in visible_enterprise_record_query(current_user).with_entities(EnterpriseRecord.id).all()
        ]
        overdue_records, overdue_truncated = overdue_enterprise_records(EnterpriseRecord, record_ids, now)
        return render_template(
            "analytics_overdue.html", overdue_records=overdue_records, modules=DOMAIN_CONFIG,
            overdue_truncated=overdue_truncated, overdue_limit=OVERDUE_RECORDS_LIMIT,
        )

    @app.get("/internal/lookup/cis")
    @login_required
    def lookup_cis():
        q = request.args.get("q", "").strip()
        query = tenant_query(ConfigurationItem)
        if q:
            pattern = f"%{q}%"
            query = query.filter(db.or_(
                ConfigurationItem.name.ilike(pattern),
                ConfigurationItem.ci_class.ilike(pattern),
            ))
        rows = query.order_by(ConfigurationItem.name).limit(15).all()
        return jsonify([{
            "value": ci.id,
            "label": ci.name,
            "description": f"{ci.ci_class} · {ci.environment} · {ci.operational_status}",
            "owning_team": ci.support_group.name if ci.support_group else None,
        } for ci in rows])

    @app.get("/internal/lookup/cis/browse")
    @login_required
    def lookup_cis_browse():
        q = request.args.get("q", "").strip()
        ci_class = request.args.get("ci_class", "").strip()
        environment = request.args.get("environment", "").strip()
        query = tenant_query(ConfigurationItem)
        if q:
            pattern = f"%{q}%"
            query = query.filter(db.or_(
                ConfigurationItem.name.ilike(pattern),
                ConfigurationItem.ip_address.ilike(pattern),
            ))
        if ci_class:
            query = query.filter(ConfigurationItem.ci_class == ci_class)
        if environment:
            query = query.filter(ConfigurationItem.environment == environment)
        rows = query.order_by(ConfigurationItem.name).limit(200).all()
        classes = [
            row[0] for row in tenant_query(ConfigurationItem).with_entities(
                ConfigurationItem.ci_class
            ).distinct().order_by(ConfigurationItem.ci_class).all()
        ]
        environments = [
            row[0] for row in tenant_query(ConfigurationItem).with_entities(
                ConfigurationItem.environment
            ).distinct().order_by(ConfigurationItem.environment).all()
        ]
        return jsonify({
            "results": [{
                "id": ci.id, "name": ci.name, "ci_class": ci.ci_class,
                "environment": ci.environment, "ip_address": ci.ip_address or "—",
                "status": ci.operational_status,
                "owning_team": ci.support_group.name if ci.support_group else None,
            } for ci in rows],
            "classes": classes, "environments": environments,
        })

    @app.get("/internal/lookup/records")
    @login_required
    def lookup_records():
        q = request.args.get("q", "").strip()
        if len(q) < 2:
            return jsonify([])
        pattern = f"%{q}%"
        results = []
        ticket_ids = {row.id for row in visible_ticket_query(current_user).all()}
        for row in Ticket.query.filter(
            Ticket.id.in_(ticket_ids),
            db.or_(Ticket.number.ilike(pattern), Ticket.title.ilike(pattern)),
        ).order_by(Ticket.updated_at.desc()).limit(10):
            results.append({
                "value": row.number, "label": f"{row.number} — {row.title}",
                "description": f"{row.kind.title()} · {row.state}",
            })
        enterprise_ids = {row.id for row in visible_enterprise_record_query(current_user).all()}
        for row in EnterpriseRecord.query.filter(
            EnterpriseRecord.id.in_(enterprise_ids),
            db.or_(EnterpriseRecord.number.ilike(pattern), EnterpriseRecord.title.ilike(pattern)),
        ).order_by(EnterpriseRecord.updated_at.desc()).limit(10):
            results.append({
                "value": row.number, "label": f"{row.number} — {row.title}",
                "description": f"{DOMAIN_CONFIG[row.domain]['name']} · {row.state}",
            })
        for row in tenant_query(Knowledge).filter(
            db.or_(Knowledge.title.ilike(pattern), Knowledge.body.ilike(pattern))
        ).limit(10):
            results.append({
                "value": f"KB{row.id:07d}", "label": f"KB{row.id:07d} — {row.title}",
                "description": f"Knowledge · {row.category}",
            })
        request_ids = {row.id for row in visible_catalog_request_query(current_user).all()}
        for row in CatalogRequest.query.filter(
            CatalogRequest.id.in_(request_ids), CatalogRequest.number.ilike(pattern),
        ).limit(10):
            results.append({
                "value": row.number, "label": f"{row.number} — {row.requested_for.name}",
                "description": f"Service request · {row.state}",
            })
        for row in RequestedItem.query.filter(
            RequestedItem.request_id.in_(request_ids),
            RequestedItem.number.ilike(pattern),
        ).limit(10):
            results.append({
                "value": row.number, "label": f"{row.number} — {row.item.name}",
                "description": f"Requested item · {row.state}",
            })
        return jsonify(results[:15])

    @app.get("/ui/search")
    @login_required
    def global_search():
        q = request.args.get("q", "").strip()
        results = []
        if q:
            pattern = f"%{q}%"
            normalized_q = q.casefold()
            can_access_clients = user_can_access_client_management(current_user)
            for entry in navigation_entries(SETTING_GROUP_META):
                if entry.client_management and not can_access_clients:
                    continue
                if entry.minimum_role and not role_at_least(current_user.effective_role, entry.minimum_role):
                    continue
                if normalized_q in f"{entry.label} {entry.keywords}".casefold():
                    results.append({"type": "Navigation", "label": entry.label,
                                    "url": url_for(entry.endpoint, **entry.params), "meta": entry.keywords})
            # Keep authorization filtering inside PostgreSQL. The old code
            # loaded every visible ORM object into Python simply to collect
            # IDs, making global search memory and latency grow with the
            # tenant. These Query projections compile to bounded subqueries.
            visible_ticket_ids = visible_ticket_query(current_user).with_entities(Ticket.id)
            visible_enterprise_ids = visible_enterprise_record_query(current_user).with_entities(EnterpriseRecord.id)
            visible_request_ids = visible_catalog_request_query(current_user).with_entities(CatalogRequest.id)
            for row in Ticket.query.filter(Ticket.id.in_(visible_ticket_ids), db.or_(
                                                   Ticket.number.ilike(pattern), Ticket.title.ilike(pattern),
                                                   Ticket.description.ilike(pattern))).limit(20):
                results.append({"type": row.kind.title(), "label": f"{row.number} · {row.title}",
                                "url": url_for("ticket_detail", ticket_id=row.id), "meta": row.state})
            for row in tenant_query(Knowledge).filter(db.or_(
                Knowledge.title.ilike(pattern), Knowledge.body.ilike(pattern)
            )).limit(20):
                results.append({"type": "Knowledge", "label": row.title, "url": url_for("knowledge"),
                                "meta": row.category})
            for row in EnterpriseRecord.query.filter(EnterpriseRecord.id.in_(visible_enterprise_ids), db.or_(
                                                             EnterpriseRecord.number.ilike(pattern),
                                                             EnterpriseRecord.title.ilike(pattern),
                                                             EnterpriseRecord.external_id.ilike(pattern))).limit(20):
                results.append({"type": DOMAIN_CONFIG[row.domain]["name"], "label": f"{row.number} · {row.title}",
                                "url": url_for("enterprise_detail", record_id=row.id), "meta": row.state})
            for row in tenant_query(ConfigurationItem).filter(db.or_(
                ConfigurationItem.name.ilike(pattern),
                ConfigurationItem.serial_number.ilike(pattern),
                ConfigurationItem.ip_address.ilike(pattern),
                ConfigurationItem.model.ilike(pattern),
                ConfigurationItem.vendor.ilike(pattern),
                ConfigurationItem.description.ilike(pattern),
                ConfigurationItem.location.ilike(pattern),
            )).limit(20):
                ci_url = url_for("ci_edit", ci_id=row.id) if role_at_least(current_user.effective_role, "admin") else url_for("cmdb")
                results.append({"type": "Configuration item", "label": row.name,
                                "url": ci_url, "meta": row.ci_class})
            for row in CatalogRequest.query.filter(
                CatalogRequest.id.in_(visible_request_ids),
                CatalogRequest.number.ilike(pattern),
            ).limit(20):
                results.append({
                    "type": "Request", "label": row.number,
                    "url": url_for("request_detail", request_id=row.id), "meta": row.state,
                })
            for row in RequestedItem.query.filter(
                RequestedItem.request_id.in_(visible_request_ids),
                RequestedItem.number.ilike(pattern),
            ).limit(20):
                results.append({
                    "type": "Requested item", "label": f"{row.number} · {row.item.name}",
                    "url": url_for("request_detail", request_id=row.request_id), "meta": row.state,
                })
            for row in CatalogTask.query.join(RequestedItem).filter(
                RequestedItem.request_id.in_(visible_request_ids),
                db.or_(
                    CatalogTask.number.ilike(pattern), CatalogTask.title.ilike(pattern)
                ),
            ).limit(20):
                results.append({
                    "type": "Catalog task", "label": f"{row.number} · {row.title}",
                    "url": url_for("request_detail", request_id=row.requested_item.request_id),
                    "meta": row.state,
                })
            for row in OperationalTask.query.filter(db.or_(
                OperationalTask.number.ilike(pattern), OperationalTask.title.ilike(pattern)
            )).limit(20):
                parent = record_reference(row.parent_type, row.parent_id)
                if isinstance(parent, Ticket) and not visible_ticket_query(current_user).filter(Ticket.id == parent.id).first():
                    continue
                if isinstance(parent, EnterpriseRecord) and not visible_enterprise_record_query(current_user).filter(EnterpriseRecord.id == parent.id).first():
                    continue
                results.append({
                    "type": "Change task" if row.task_kind == "change" else "Problem task",
                    "label": f"{row.number} · {row.title}",
                    "url": record_url(parent), "meta": row.state,
                })
            for row in tenant_query(Asset).filter(db.or_(
                Asset.asset_tag.ilike(pattern), Asset.name.ilike(pattern),
                Asset.asset_type.ilike(pattern), Asset.serial_number.ilike(pattern),
            )).limit(20):
                results.append({"type": "Asset", "label": f"{row.asset_tag} · {row.name}",
                                "url": url_for("assets"), "meta": f"{row.asset_type} · {row.status}"})
            for row in tenant_query(CatalogItem).filter(db.or_(
                CatalogItem.name.ilike(pattern), CatalogItem.category.ilike(pattern),
                CatalogItem.description.ilike(pattern),
            )).limit(20):
                results.append({"type": "Catalog item", "label": row.name,
                                "url": url_for("catalog"), "meta": row.category})
            if user_can_access_client_management(current_user):
                for row in visible_client_ticket_query(current_user).join(ClientContact).join(ClientOrganization).filter(db.or_(
                    ClientTicket.number.ilike(pattern), ClientTicket.subject.ilike(pattern),
                    ClientTicket.description.ilike(pattern), ClientContact.name.ilike(pattern),
                    ClientContact.email.ilike(pattern), ClientOrganization.name.ilike(pattern),
                )).limit(20):
                    results.append({"type": "Customer ticket", "label": f"{row.number} · {row.subject}",
                                    "url": url_for("client_ticket_detail", ticket_id=row.id),
                                    "meta": f"{row.organization.name} · {row.status}"})
                for row in visible_client_organization_query(current_user).filter(db.or_(
                    ClientOrganization.name.ilike(pattern), ClientOrganization.domain.ilike(pattern),
                    ClientOrganization.external_id.ilike(pattern),
                )).limit(20):
                    results.append({"type": "Client organization", "label": row.name,
                                    "url": url_for("client_organizations"), "meta": row.domain})
                for row in visible_client_contact_query(current_user).filter(db.or_(
                    ClientContact.name.ilike(pattern), ClientContact.email.ilike(pattern),
                    ClientContact.phone.ilike(pattern),
                )).limit(20):
                    results.append({"type": "Client contact", "label": f"{row.name} · {row.email}",
                                    "url": url_for("client_contacts"), "meta": row.organization.name})
            if role_at_least(current_user.effective_role, "admin"):
                for row in tenant_query(User).filter(db.or_(
                    User.username.ilike(pattern), User.name.ilike(pattern),
                    User.email.ilike(pattern), User.department.ilike(pattern),
                )).limit(20):
                    results.append({"type": "User", "label": f"{row.name} · {row.username}",
                                    "url": url_for("user_edit", user_id=row.id), "meta": row.role})
                for row in tenant_query(SupportGroup).filter(
                    SupportGroup.name.ilike(pattern)
                ).limit(20):
                    results.append({"type": "Group", "label": row.name,
                                    "url": url_for("itil_admin_section", section="governance-groups"),
                                    "meta": row.group_type})
                for row in tenant_query(IntegrationConnection).filter(db.or_(
                    IntegrationConnection.name.ilike(pattern),
                    IntegrationConnection.kind.ilike(pattern),
                    IntegrationConnection.endpoint.ilike(pattern),
                )).limit(20):
                    results.append({"type": "Integration", "label": row.name,
                                    "url": url_for("integrations_admin"), "meta": row.kind.upper()})
            deduplicated = []
            seen = set()
            for result in results:
                identity = (result["type"], result["url"], result["label"])
                if identity not in seen:
                    seen.add(identity)
                    deduplicated.append(result)
            results = deduplicated
        if request.accept_mimetypes.best == "application/json":
            return jsonify(results=[
                project_document("search_result", current_user.effective_role, row)
                for row in results[:30]
            ])
        return render_template("search.html", q=q, results=results[:60])

    @app.post("/ui/favorite")
    @login_required
    def favorite_toggle():
        url = request.form.get("url", "")[:500]
        if not is_safe_internal_path(url):
            abort(400)
        label = request.form.get("label", "Saved page")[:180]
        existing = Favorite.query.filter_by(user_id=current_user.id, url=url).first()
        if existing:
            db.session.delete(existing)
            active = False
        else:
            db.session.add(Favorite(user_id=current_user.id, url=url, label=label,
                                    folder=request.form.get("folder", "My favorites")[:80]))
            active = True
        db.session.commit()
        return jsonify(project_document(
            "ui_action_ack", current_user.effective_role,
            {"active": active, "url": url, "label": label},
        ))

    @app.post("/ui/history")
    @login_required
    def history_record():
        url = request.form.get("url", "")[:500]
        if not is_safe_internal_path(url) or url.startswith(("/static", "/health", "/ui/")):
            return ("", 204)
        label = request.form.get("label", "Page")[:180]
        row = RecentView.query.filter_by(user_id=current_user.id, url=url).first()
        if row:
            row.label = label
            row.viewed_at = now()
        else:
            db.session.add(RecentView(user_id=current_user.id, url=url, label=label))
        db.session.commit()
        return jsonify(project_document(
            "ui_action_ack", current_user.effective_role, {"url": url, "label": label},
        ))

    @app.route("/preferences", methods=["GET", "POST"])
    @login_required
    def preferences():
        pref = UserPreference.query.filter_by(user_id=current_user.id).first()
        if not pref:
            pref = UserPreference(
                user_id=current_user.id, density=setting_value("DEFAULT_DENSITY", "comfortable"),
            )
            db.session.add(pref)
        notification_pref = NotificationPreference.query.filter_by(user_id=current_user.id).first()
        if not notification_pref:
            notification_pref = NotificationPreference(user_id=current_user.id)
            db.session.add(notification_pref)
        mutable_event_types = {
            key: meta for key, meta in NOTIFICATION_EVENT_TYPES.items()
            if key not in NON_MUTABLE_EVENT_TYPES
        }
        if request.method == "POST":
            if request.form.get("action") == "notifications":
                notification_pref.email_enabled = bool(request.form.get("email_enabled"))
                muted = [
                    key for key in mutable_event_types
                    if request.form.get(f"mute_{key}")
                ]
                notification_pref.muted_event_types = json.dumps(muted)
                audit("update", "Notification preferences", current_user.username)
                db.session.commit()
                flash("Notification preferences saved.", "success")
                return redirect(url_for("preferences"))
            pref.theme = "light"
            pref.density = request.form.get("density", "comfortable")
            pref.font_scale = max(80, min(140, int(request.form.get("font_scale", 100))))
            pref.high_contrast = bool(request.form.get("high_contrast"))
            pref.reduced_motion = bool(request.form.get("reduced_motion"))
            pref.nav_pinned = bool(request.form.get("nav_pinned"))
            pref.accessible_tooltips = bool(request.form.get("accessible_tooltips"))
            pref.data_patterns = bool(request.form.get("data_patterns"))
            pref.compact_dates = bool(request.form.get("compact_dates"))
            pref.keyboard_shortcuts = bool(request.form.get("keyboard_shortcuts"))
            pref.date_time_display = request.form.get("date_time_display", "both") if request.form.get("date_time_display") in {"calendar", "relative", "both"} else "both"
            submitted_start_page = request.form.get("start_page", "/")[:500]
            pref.start_page = submitted_start_page if is_safe_internal_path(submitted_start_page) else "/"
            audit("update", "UI preferences", current_user.username)
            db.session.commit()
            flash("Display and accessibility preferences saved.", "success")
            return redirect(url_for("preferences"))
        muted_types = set(json.loads(notification_pref.muted_event_types or "[]"))
        return render_template(
            "preferences.html", pref=pref, notification_pref=notification_pref,
            mutable_event_types=mutable_event_types, muted_types=muted_types,
        )

    @app.get("/task-board")
    @login_required
    def task_board():
        query = visible_tickets()
        board_cutoff = now() - timedelta(days=30)
        tickets_by_state = {}
        for state in ["New", "In Progress", "Pending", "Resolved", "Closed"]:
            state_query = query.filter_by(state=state)
            if state in ("Resolved", "Closed"):
                state_query = state_query.filter(Ticket.updated_at >= board_cutoff)
            tickets_by_state[state] = state_query.order_by(Ticket.priority, Ticket.updated_at.desc()).all()
        manageable_ticket_ids = {
            ticket.id for tickets in tickets_by_state.values() for ticket in tickets
            if user_can_manage_ticket(current_user, ticket)
        }
        return render_template(
            "task_board.html", tickets_by_state=tickets_by_state,
            manageable_ticket_ids=manageable_ticket_ids,
        )

    @app.post("/task-board/<int:ticket_id>/move")
    @roles("agent", "manager", "admin")
    def task_board_move(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        require_ticket_team_access(ticket)
        state = request.form.get("state")
        if state not in ("New", "In Progress", "Pending", "Resolved", "Closed"):
            abort(400)
        previous_state = ticket.state
        transition_ticket(ticket, state)
        if previous_state != ticket.state:
            log_history(
                "ticket", ticket.id, "Board state changed",
                "state", previous_state, ticket.state,
            )
        audit("board move", ticket.number, state)
        db.session.commit()
        return jsonify(project_document(
            "ui_action_ack", current_user.effective_role, {"state": state}
        ))

    @app.post("/ticket/<int:ticket_id>/checklist")
    @roles("agent", "manager", "admin")
    def checklist_add(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        require_ticket_team_access(ticket)
        if not require_ticket_not_locked(ticket):
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        text = request.form.get("text", "").strip()
        if text:
            position = ChecklistItem.query.filter_by(ticket_id=ticket_id).count()
            db.session.add(ChecklistItem(ticket_id=ticket_id, text=text[:300], position=position))
            log_history(
                "ticket", ticket.id, "Checklist item added",
                details=text[:300],
            )
            db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.post("/checklist/<int:item_id>/toggle")
    @roles("agent", "manager", "admin")
    def checklist_toggle(item_id):
        item = db.get_or_404(ChecklistItem, item_id)
        ticket = tenant_record_or_404(Ticket, item.ticket_id)
        require_ticket_team_access(ticket)
        if not require_ticket_not_locked(ticket):
            return redirect(url_for("ticket_detail", ticket_id=item.ticket_id))
        item.completed = not item.completed
        log_history(
            "ticket", ticket.id, "Checklist item updated",
            item.text, not item.completed, item.completed,
        )
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=item.ticket_id))

    def save_ticket_attachment(ticket, upload, comment_id=None):
        """Validates, scans, and stores an uploaded file against a ticket,
        optionally linking it to a specific comment (work note attachment).
        Returns (attachment, None) on success or (None, flash_message) on
        failure -- callers flash the message and redirect. Shared by the
        dedicated attachment-upload route and the comment-with-attachment
        flow so both get identical malware scanning and type validation."""
        if not upload or not upload.filename:
            return None, "Choose a file to upload."
        original = secure_filename(upload.filename)
        if not original:
            abort(400, description="The attachment filename is invalid.")
        validated = validate_attachment_upload(upload)
        if not validated:
            return None, (
                "That file type isn't allowed. Accepted attachment types: "
                + ", ".join(sorted(ATTACHMENT_ALLOWED_TYPES)) + "."
            )
        _, verified_mime_type = validated
        stored = f"{uuid.uuid4().hex}-{original}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
        upload.save(path)
        scan_status = scan_attachment(path)
        if scan_status == "infected":
            os.remove(path)
            audit("attach-blocked", ticket.number, f"{original} (malware scan positive)")
            current_app.logger.warning(
                "Rejected infected attachment upload: ticket=%s file=%s user=%s",
                ticket.number, original, current_user.id,
            )
            return None, "That file was rejected by malware scanning and was not attached."
        sha256 = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                sha256.update(chunk)
        file_size = os.path.getsize(path)
        if object_storage_enabled():
            # Found via real failure-injection testing against a disposable
            # MinIO backend (B-052): an object-storage outage previously
            # crashed this into a generic 500 (confirmed via a real ~8s
            # timeout-then-retry-exhausted EndpointConnectionError) and
            # -- more importantly -- never reached the os.remove(path)
            # below, so the local temp file leaked forever on every failed
            # upload. Now a clean, user-facing error instead, matching the
            # existing malware-scan-rejected return shape.
            try:
                object_storage_client().upload_file(
                    path, os.environ["OBJECT_STORAGE_BUCKET"], stored,
                    ExtraArgs={"ContentType": verified_mime_type},
                )
            except Exception:
                os.remove(path)
                current_app.logger.warning(
                    "Object storage upload failed: ticket=%s file=%s user=%s",
                    ticket.number, original, current_user.id,
                )
                return None, "Attachment storage is temporarily unavailable. Please try again shortly."
            os.remove(path)
        ipfs_cid = None
        if ipfs_enabled():
            try:
                with open(path, "rb") as handle:
                    ipfs_cid = current_storage().attach_file(stored, handle.read(), verified_mime_type)
            except Exception:
                os.remove(path)
                current_app.logger.warning(
                    "IPFS attachment upload failed: ticket=%s file=%s user=%s",
                    ticket.number, original, current_user.id,
                )
                return None, "Attachment storage is temporarily unavailable. Please try again shortly."
            os.remove(path)
        attachment = FileAttachment(
            ticket_id=ticket.id, comment_id=comment_id, uploaded_by_id=current_user.id,
            original_name=original, stored_name=stored, ipfs_cid=ipfs_cid,
            mime_type=verified_mime_type, size_bytes=file_size,
            sha256=sha256.hexdigest(), scan_status=scan_status, tenant_id=ticket.tenant_id,
        )
        db.session.add(attachment)
        audit("attach", ticket.number, original)
        return attachment, None

    @app.post("/ticket/<int:ticket_id>/attachments")
    @login_required
    def attachment_upload(ticket_id):
        ticket = tenant_record_or_404(Ticket, ticket_id)
        if not user_can_view_ticket(current_user, ticket):
            abort(403)
        upload = request.files.get("file")
        attachment, error = save_ticket_attachment(ticket, upload)
        if error:
            flash(error, "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        log_history(
            "ticket", ticket.id, "Attachment uploaded",
            details=f"{attachment.original_name} ({attachment.size_bytes} bytes)",
        )
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.get("/attachments/<int:attachment_id>")
    @login_required
    def attachment_download(attachment_id):
        attachment = db.get_or_404(FileAttachment, attachment_id)
        if attachment.enterprise_record_id:
            if not user_can_view_enterprise_record(current_user, attachment.enterprise_record):
                abort(403)
        elif attachment.client_ticket_id:
            if not visible_client_ticket_query(current_user).filter_by(id=attachment.client_ticket_id).first():
                abort(404)
        elif not user_can_view_ticket(current_user, attachment.ticket):
            abort(403)
        # Only the handful of types a browser renders safely natively
        # (never HTML/SVG, which could execute script if opened inline)
        # are ever served inline. The shared response path also powers the
        # authenticated mobile download API.
        return attachment_file_response(
            attachment, inline=request.args.get("view") == "1",
        )

    @app.get("/help")
    @login_required
    def help_center():
        return render_template("help.html")

    @app.get("/mobile-app")
    @login_required
    def mobile_app():
        return render_template("mobile_app.html", mobile_version="1.3.2", mobile_build="8")

    @app.errorhandler(403)
    def forbidden(error):
        if request.path.startswith("/api/"):
            return http_error(error)
        return render_template(
            "error.html", code=403,
            message=error.description or "You do not have permission to access this page.",
        ), 403

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return http_error(error)
        return render_template("error.html", code=404, message="The requested record was not found."), 404

    @app.errorhandler(409)
    def workflow_conflict(error):
        if request.path.startswith("/api/"):
            return http_error(error)
        return render_template(
            "error.html", code=409,
            message=error.description or "The requested workflow transition is not allowed.",
        ), 409

    # Alembic's AlembicConfig(alembic.ini) above runs migrations/env.py,
    # which calls logging.config.fileConfig(alembic.ini) -- that defaults
    # to disable_existing_loggers=True, silently setting `app.logger.disabled
    # = True` as a side effect on every migration run (this shared,
    # process-wide named logger, not anything scoped to this Flask
    # instance -- see configure_detailed_logging's docstring). Nothing else
    # ever re-enables it, so this must run after the migration step, not
    # just once inside configure_detailed_logging near the top of this
    # function, or every log call -- including "every error must be
    # recorded" -- silently no-ops for the rest of the process.
    app.logger.disabled = False

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080, debug=True)
