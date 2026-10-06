import csv
import io
import json
import logging
import logging.handlers
import traceback as traceback_module
import time as time_module
import threading
import os
import sys
import ssl
import unicodedata
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
from types import SimpleNamespace
import collections
from collections import Counter, defaultdict
from datetime import date, datetime, time as dt_time, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr
from functools import wraps
from urllib.parse import quote, urljoin, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
import httpx
import pyotp
import boto3
from botocore.config import Config as BotoConfig
from flask import Flask, Response, abort, current_app, flash, g, has_app_context, has_request_context, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from markupsafe import Markup, escape
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from authlib.integrations.flask_client import OAuth
from joserfc import jwt
from joserfc.jwk import ECKey, KeySet, RSAKey
from joserfc.jwt import JWTClaimsRegistry
from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from cryptography.fernet import InvalidToken
from ldap3 import ALL, BASE, FIRST, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased, selectinload
from sqlalchemy.pool import StaticPool
from serviceops_core.log_storage import DatabaseLogHandler, report_diagnostic_failure
# Not called directly in this file (ServiceOps hashes local passwords with
# Argon2id via serviceops_core.security -- see hash_password/verify_password
# above). Kept because serviceops_core/rt_import.py's _resolve_or_create_user()
# reaches it as core_app.generate_password_hash(...) via `import app as
# core_app`, the lazy-import pattern this module and its siblings
# (netbox_sync.py, network_discovery.py, ...) use to avoid a circular
# import with app.py at module load time -- that makes every name app.py
# imports at module scope part of its cross-module surface, not just what
# this file's own body references. A static per-file unused-import check
# (this repo's ruff config deliberately doesn't run one -- see CI) cannot
# see that cross-module use and would flag this as dead.
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.http import dump_options_header
from serviceops_core.localization import tr, tr_value


def escape_like(value):
    """Escape user text before embedding it in a SQL LIKE pattern."""
    return str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

from serviceops_core.security import (
    hash_password, load_policy, redact, RedactingFilter, role_has_action,
    validate_policy, verify_and_upgrade_password, verify_password,
)
from serviceops_core.priority import calculate_priority, validate_priority_policy
from serviceops_core.business_time import add_business_minutes, validate_calendar
from serviceops_core.workflow import (
    canonical_json, load_workflow_package, materialize_workflow,
    package_digest, validate_workflow, workflow_matches,
)
from serviceops_core.projections import project_document, validate_projection_policy
from serviceops_core import mcp as mcp_protocol
from serviceops_core.mcp_tools import TOOLS as MCP_TOOLS
from serviceops_core.ci_class_policy import (
    ci_class_action_allowed, ci_class_read_allowed, managed_ci_classes,
    restrict_ci_query_to_readable_classes, unreadable_ci_classes,
)
from serviceops_core.dns_lookup import resolve_hostname, resolve_ip
from serviceops_core.dns_pin import pin_resolved_addresses
from serviceops_core.proxy_tunnel import parse_proxy_url, tunnel_through_proxy
from serviceops_core.google_chat import decode_pubsub_message, extract_message_event, parse_command
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
    OPERATIONAL_TASK_TRANSITIONS, build_state_track,
)
from serviceops_core.config_schema import (
    SETTING_DEFINITIONS, SETTING_GROUP_META, find_setting_definition,
    coerce_bool, coerce_int,
)
from serviceops_core.feature_flags import feature_enabled
from serviceops_core.notification_templates import (
    NOTIFICATION_EVENT_TYPES, NON_MUTABLE_EVENT_TYPES, render_notification_template, is_event_muted,
)
from serviceops_core.delivery import (
    EVENT_SUBSCRIPTIONS, PROVIDER_LABELS,
    PERSONAL_EVENT_SUBSCRIPTIONS, PERSONAL_EVENT_SUBSCRIPTION_PATTERNS,
    GROUP_EVENT_SUBSCRIPTIONS, GROUP_EVENT_SUBSCRIPTION_PATTERNS,
    SYSTEM_EVENT_SUBSCRIPTIONS, SYSTEM_EVENT_SUBSCRIPTION_PATTERNS,
    WEBHOOK_KINDS, activity_category, connection_accepts_event, event_matches,
    provider_endpoint_allowed, provider_payload,
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


def display_version():
    # STORAGE_MODE=ipfs is a database-less deployment with real, disclosed
    # operating-boundary differences from the default PostgreSQL mode (see
    # docs/IPFS_STORAGE_MODE.md) -- an admin/operator looking at the UI,
    # /health, /ready, or the Prometheus metrics should be able to tell
    # which one they're looking at without checking STORAGE_MODE directly.
    return f"{APP_VERSION}-ipfs" if ipfs_enabled() else APP_VERSION

# The adopted ITIL category model (serviceops-notes docs/ITIL_V5_CATEGORISATION.md):
# two levels, categorised by the affected service or CI rather than by the
# fix, at most about ten options per level. Seeded for a tenant that has no
# categories yet (seed_itil()); existing tenants were aligned by migration
# 20260927_0106, which keeps its own copy because a migration must never
# import app.py. Administrators may adapt the tree afterwards.
TICKET_CATEGORY_TAXONOMY = {
    "Hardware": ["Desktop", "Laptop", "Server", "Storage", "Peripheral"],
    "Software / Application": ["Business application", "OS", "Licensing", "Patching"],
    "Network": ["LAN", "WAN", "VPN", "DNS", "Firewall", "Wi-Fi"],
    "Access / Identity": ["Account creation", "Password reset", "Permissions", "MFA"],
    "Infrastructure / Platform": ["Compute", "Virtualisation", "Containers", "Cloud", "Backup"],
    "Security": ["Malware", "Phishing", "Vulnerability", "Policy breach"],
    "Data / Database": ["Availability", "Performance", "Corruption", "Restore"],
    "Communication": ["Email", "Telephony", "Collaboration tools"],
    "Facilities / Endpoint services": ["Printing", "Workplace equipment"],
}
# Last-resort fallback if a tenant's category table is ever empty.
TICKET_CATEGORY_OPTIONS = list(TICKET_CATEGORY_TAXONOMY)
# Stored when a submitted category matches nothing (older integrations); it is
# not offered on the form, so these tickets show up as uncategorised.
UNCATEGORISED = "General"
# Guidance from the category model: no more than about ten options per level.
CATEGORY_LEVEL_OPTION_LIMIT = 10


def tenant_ticket_categories(tenant_id):
    """Active, admin-managed ticket categories for one tenant, alphabetical."""
    rows = TicketCategory.query.filter_by(tenant_id=tenant_id, active=True).order_by(TicketCategory.name).all()
    return rows or [SimpleNamespace(id=None, name=name) for name in TICKET_CATEGORY_OPTIONS]


def tenant_ticket_subcategories(tenant_id):
    """Active subcategories for one tenant, grouped by their (active) category,
    for building a <select><optgroup> subcategory list on the ticket form."""
    return (TicketSubcategory.query.join(TicketCategory)
            .filter(TicketSubcategory.tenant_id == tenant_id, TicketSubcategory.active.is_(True),
                    TicketCategory.active.is_(True))
            .order_by(TicketCategory.name, TicketSubcategory.name).all())


def normalize_ticket_category(tenant_id, submitted):
    """Canonicalizes a submitted category against the tenant's active list
    (case-insensitive). Never rejects outright -- an unrecognized value (e.g.
    from an older integration, or a tenant with a since-renamed category)
    is stored as UNCATEGORISED, matching this field's already-lenient historical
    default rather than breaking ticket creation on a taxonomy mismatch."""
    submitted = (submitted or "").strip()
    for category in tenant_ticket_categories(tenant_id):
        if category.name.casefold() == submitted.casefold():
            return category.name
    return UNCATEGORISED


def normalize_ticket_subcategory(tenant_id, category_name, submitted):
    """Canonicalizes a submitted subcategory against the ones modeled under
    `category_name`; anything else (including a category with none modeled
    yet) is kept as free text -- the "Other" path, preserving this field's
    historical fully-free-text behavior for whatever an administrator hasn't
    modeled yet."""
    submitted = (submitted or "").strip()[:80]
    if not submitted:
        return submitted
    for subcategory in tenant_ticket_subcategories(tenant_id):
        if subcategory.category.name.casefold() == category_name.casefold() and subcategory.name.casefold() == submitted.casefold():
            return subcategory.name
    return submitted


def submitted_subcategory(form, fallback="", name="subcategory"):
    """The ticket form's subcategory <select> posts the sentinel "__other__"
    when the person typed a value not in the modeled list (see
    _ticket_category_fields.html/static/ticket-category.js) -- resolve that
    back to the actual typed text before it reaches normalize_ticket_subcategory()."""
    value = form.get(name, fallback)
    return form.get(f"{name}_other", "") if value == "__other__" else value

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


from serviceops_core.equipment_artwork import local_device_artwork


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
        op_label = tr_value(FILTER_OPERATOR_LABELS.get(condition["op"], condition["op"]))
        field_label = tr_value(spec["label"])
        if condition["op"] in ("is_empty", "is_not_empty"):
            parts.append(tr("{field} {operator}", field=field_label, operator=op_label))
        else:
            shown_value = value_labels.get((condition["field"], condition["value"]), condition["value"])
            parts.append(tr("{field} {operator} {value}", field=field_label, operator=op_label, value=tr_value(shown_value)))
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
    if not url or not url.startswith("/") or url.startswith("//") or "\\" in url:
        # Browsers normalize backslashes to forward slashes when resolving a
        # relative reference for http(s) pages, so "/\evil.com" resolves as
        # the scheme-relative "//evil.com" even though it doesn't literally
        # start with "//" here. Reject any backslash outright.
        return False
    parsed = urlparse(url)
    return not parsed.scheme and not parsed.netloc


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


def tenant_record_or_404(model, record_id, lock=False):
    """Resolve a tenant-owned root without exposing another tenant's existence.

    `lock=True` takes a row lock (SELECT ... FOR UPDATE) so a second
    concurrent request against the same record blocks until the first
    commits, instead of both reading the same pre-mutation state. Used
    sparingly, only where a race would double-fire a side effect like a
    reapproval notification -- not on every read, which would serialize
    unrelated page views.
    """
    query = model.query.filter_by(id=record_id, tenant_id=tenant_context_id())
    if lock:
        query = query.with_for_update()
    return query.first_or_404()


def tenant_query(model):
    """Start a query constrained to the authenticated/default tenant."""
    return model.query.filter(model.tenant_id == tenant_context_id())


def account_usable(user):
    """True only for an active user whose tenant is also active. A deactivated
    tenant must lose access everywhere -- web sessions, every login path, API
    tokens and mobile sessions -- not just its background jobs."""
    if user is None or not user.active:
        return False
    tenant = db.session.get(Tenant, user.tenant_id)
    return bool(tenant and tenant.active)


def object_storage_enabled():
    return os.getenv("OBJECT_STORAGE_BUCKET", "").strip() != ""


def current_storage():
    """The active StorageBackend (PostgresStorageBackend by default,
    IPFSStorageBackend under STORAGE_MODE=ipfs), built once at app boot."""
    return current_app.extensions["storage_backend"]


def ipfs_find_user_by_username(username):
    rows = current_storage().query("user", tenant_id=None, filters=[("username", "eq", username)])
    return ipfs_user_from_dict(rows[0]) if rows else None


def ipfs_user_from_dict(fields):
    """Wraps a plain dict from IPFSStorageBackend.get/query("user", ...) as
    a transient (never added to a db.session) User instance, so the exact
    same model class -- same UserMixin behavior, same plain-Column
    attributes templates/routes already read (name, username, role,
    tenant_id, mfa_enabled, ...) -- works under STORAGE_MODE=ipfs with no
    database at all. Only plain Column attributes are safe to read on a
    transient instance; relationship-backed properties (granted_roles,
    manager, ...) would try to issue a real query and must not be touched
    on this object -- login-only milestone, see BACKLOG B-335."""
    return User(**fields)


def object_storage_client():
    proxies = resolve_component_proxies("OBJECT_STORAGE")
    return boto3.client(
        "s3", endpoint_url=os.getenv("OBJECT_STORAGE_ENDPOINT") or None,
        region_name=os.getenv("OBJECT_STORAGE_REGION", "us-east-1"),
        aws_access_key_id=os.getenv("OBJECT_STORAGE_ACCESS_KEY") or None,
        aws_secret_access_key=os.getenv("OBJECT_STORAGE_SECRET_KEY") or None,
        config=BotoConfig(proxies=proxies) if proxies else BotoConfig(proxies={}),
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


INSTALL_SETTINGS_ACTIONS = {"set_change_approval_policy", "set_ticket_defaults"}


def require_install_settings_authority():
    """PlatformSetting holds one install-wide row per key, shared by every
    tenant. While the install has a single tenant its administrator owns
    them; once there is a second tenant, one tenant's admin must not change
    settings for the others, so only a platform administrator may."""
    if Tenant.query.count() > 1 and not effective_role_has_action(
            current_user.effective_role, "platform_administer"):
        abort(403, description=(
            tr("These settings apply to every organization on this installation. Only a platform administrator can change them.")
        ))


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
    if row.integrity_version in {"hmac-sha256-v2", "hmac-sha256-v3"}:
        payload["integrity_key_id"] = row.integrity_key_id
    if row.integrity_version == "hmac-sha256-v3":
        payload["security_context_json"] = row.security_context_json or "{}"
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


def verify_audit_chain(tenant_id, rows=None):
    """Walk a tenant's audit chain in order, verifying each row's hash link.

    Accepts a pre-fetched `rows` list so callers that also need the rows
    materialized (e.g. an export) don't force a second full table scan.
    """
    previous_hash = ""
    checked = 0
    query = rows if rows is not None else Audit.query.filter_by(tenant_id=tenant_id).order_by(Audit.id)
    for row in query:
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


def audit_security_context():
    """Bounded request evidence useful for incident response.

    Never records cookies, authorization/CSRF headers, request bodies, raw
    proxy chains, or session/API bearer tokens. ``remote_addr`` is already the
    proxy-trust-normalized peer address configured by the deployment.
    """
    if not has_request_context():
        return {}
    referrer = request.referrer or ""
    if referrer:
        parsed = urlparse(referrer)
        referrer = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"[:500]
    session_record = getattr(g, "user_session", None)
    api_client = getattr(g, "api_client", None)
    return {
        "trace_id": getattr(g, "trace_id", None),
        "http_method": request.method,
        "request_path": request.path[:500],
        "request_host": request.host[:255],
        "referrer": referrer or None,
        "content_type": (request.mimetype or "")[:120] or None,
        "client_language": request.headers.get("Accept-Language", "")[:120] or None,
        "client_hostname": (
            getattr(session_record, "client_hostname", None)
            or verified_client_hostname(request.remote_addr)
        ),
        "device": (
            getattr(session_record, "device_label", None)
            or describe_user_agent(request.headers.get("User-Agent", ""))
        ),
        "authentication_provider": (
            getattr(session_record, "provider", None)
            or session.get("_auth_provider")
            or ("api" if api_client else None)
        ),
        "session_reference": (
            hashlib.sha256(session_record.session_id.encode()).hexdigest()[:16]
            if session_record and session_record.session_id else None
        ),
        "api_client_id": getattr(api_client, "client_id", None),
    }


def _support_group_ids_for_target(target, tenant_id):
    """Resolve only explicit record ownership; unknown targets remain unscoped."""
    reference = str(target or "").split()[0].strip("#:;,()")[:30]
    if not reference:
        return []
    group_ids = set()
    ticket = Ticket.query.filter_by(number=reference, tenant_id=tenant_id).first()
    if ticket:
        if ticket.assignment_group_record:
            group_ids.add(ticket.assignment_group_record.group_id)
        if ticket.change_ownership:
            group_ids.add(ticket.change_ownership.group_id)
    record = EnterpriseRecord.query.filter_by(number=reference, tenant_id=tenant_id).first()
    if record and record.support_group_id:
        group_ids.add(record.support_group_id)
    catalog_task = CatalogTask.query.filter_by(number=reference, tenant_id=tenant_id).first()
    if catalog_task and catalog_task.assignment_group_id:
        group_ids.add(catalog_task.assignment_group_id)
    operational_task = OperationalTask.query.filter_by(number=reference).first()
    if operational_task and operational_task.assignment_group_id:
        group_ids.add(operational_task.assignment_group_id)
    return sorted(group_ids)


def audit(action, target, details="", user_id=None, tenant_id=None, support_group_ids=None):
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
        security_context_json=json.dumps(audit_security_context(), sort_keys=True),
        integrity_version="hmac-sha256-v3",
        integrity_key_id=active_key.key_id if active_key else "environment-v1",
        previous_hash=previous_hash,
        created_at=now(),
        tenant_id=tenant_id,
    )
    row.event_hash = calculate_audit_hash(row)
    db.session.add(row)
    activity_payload = {
        "title": f"ServiceOps activity: {row.action}",
        "body": f"{row.target}{' — ' + row.details if row.details else ''}",
        "action": row.action,
        "target": row.target,
        "activity_category": activity_category(row.action, row.target),
        "actor_user_id": row.user_id,
        "created_at": row.created_at.isoformat(),
        "support_group_ids": (
            sorted({int(value) for value in support_group_ids})
            if support_group_ids is not None
            else _support_group_ids_for_target(target, tenant_id)
        ),
    }
    activity_connections = IntegrationConnection.query.filter_by(
        tenant_id=tenant_id, active=True,
    ).filter(IntegrationConnection.kind != "siem").all()
    if any(
        connection_accepts_event(connection, "activity.created", activity_payload)
        for connection in activity_connections
    ):
        db.session.add(OutboxEvent(
            event_type="activity.created",
            payload_json=json.dumps(activity_payload, sort_keys=True),
            tenant_id=tenant_id,
        ))
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
                "user_agent": row.user_agent or "",
                "security_context": json.loads(row.security_context_json or "{}"),
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
    # Embedded MCP server (/api/v1/mcp): mcp:access to use the endpoint; each
    # tool also needs its own read scope, and tools/list only shows those granted.
    "mcp:access",
    "cmdb:read",
    "knowledge:read",
    "approvals:read",
}


def api_token_hash(token):
    pepper = secret_value("API_TOKEN_PEPPER") or current_app.config["SECRET_KEY"]
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
        abort(503, description=tr("Passkeys require WEBAUTHN_RP_ID and an HTTPS WEBAUTHN_ORIGIN."))
    return rp_id, origin


def issue_mobile_session(user, authentication_method, backup_used=False):
    app_version = _bounded_mobile_header("X-ServiceOps-App-Version", 40)
    app_build = _bounded_mobile_header("X-ServiceOps-App-Build", 40)
    platform = _bounded_mobile_header("X-ServiceOps-Platform", 40)
    device = _bounded_mobile_header("X-ServiceOps-Device", 120)
    if not account_usable(user):
        abort(403, description=tr("This account or its organization is not active."))
    access = f"som_{secrets.token_urlsafe(32)}"
    refresh = f"sor_{secrets.token_urlsafe(48)}"
    row = APIClient(
        name=f"{platform} mobile session for {user.username}", token_prefix=access[:12],
        token_hash=api_token_hash(access), refresh_token_hash=api_token_hash(refresh),
        scopes_json=json.dumps(sorted(MOBILE_API_SCOPES)), acting_user_id=user.id,
        created_by_id=user.id, tenant_id=user.tenant_id, client_kind="mobile",
        access_expires_at=now() + timedelta(minutes=15), refresh_expires_at=now() + timedelta(days=30),
        app_version=app_version, app_build=app_build, platform=platform, device_model=device,
        auth_version=user.auth_version,
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
        abort(400, description=tr("The passkey challenge is invalid or expired."))
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
        abort(429, description=tr("Too many passkey attempts. Try again later."))


def _bounded_mobile_header(name, maximum):
    value = request.headers.get(name, "").strip()
    if not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        abort(400, description=tr("A valid {name} header is required.", name=name))
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
        abort(401, description=tr("A bearer API token is required."))
    token = authorization[7:].strip()
    if not token:
        abort(401, description=tr("A bearer API token is required."))
    token_hash = api_token_hash(token)
    client = APIClient.query.filter_by(token_hash=token_hash, active=True).first()
    if not client or not hmac.compare_digest(client.token_hash, token_hash):
        # Unlike the web login form, an invalid bearer token previously hit
        # this 401 with no rate limiting at all -- enforce_api_rate_limit()
        # below only runs once a *valid* client has already been resolved,
        # so brute-forcing random tokens against /api/v1 or /scim/v2 was
        # entirely unthrottled. Reuses the same per-IP windowed counter the
        # login/MFA routes already use.
        ip = request.remote_addr or "unknown"
        allowed = route_rate_limit(
            "api_invalid_token", f"ip:{ip}", setting_int("API_INVALID_TOKEN_RATE_LIMIT_PER_IP_PER_MINUTE", 30),
        )
        db.session.commit()
        if not allowed:
            abort(429, description=tr("Too many invalid API token attempts. Try again later."))
        abort(401, description=tr("The API token is invalid or revoked."))
    if client.access_expires_at and align_tz(client.access_expires_at, now()) <= now():
        abort(401, description=tr("The mobile session has expired."))
    if not account_usable(client.acting_user) or client.acting_user.tenant_id != client.tenant_id:
        abort(403, description=tr("The API identity is inactive or invalid."))
    if client.client_kind == "mobile" and client.auth_version != client.acting_user.auth_version:
        end_stale_mobile_session(client)
        abort(401, description=tr("The mobile session ended because the account's credentials changed."))
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


def end_stale_mobile_session(client):
    """Revoke a mobile session whose credential version no longer matches its
    user's, so neither its access nor its refresh token works again."""
    client.active = False
    client.revoked_at = now()
    client.refresh_token_hash = None
    audit("mobile session ended", client.acting_user.username,
          "credentials changed since the session was issued",
          user_id=client.acting_user_id, tenant_id=client.tenant_id)
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
        abort(429, description=tr("Rate limit of {limit} requests/minute exceeded for this API client.", limit=limit))


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


_ipfs_rate_limit_windows = {}
_ipfs_rate_limit_lock = threading.Lock()


def _ipfs_route_rate_limit(scope, key, limit, window_seconds):
    """In-memory equivalent of the DB-backed windowed counter below, for
    STORAGE_MODE=ipfs (BACKLOG B-335, known first-slice gap): counters
    live only in this process's memory, so they reset on every restart
    and aren't shared across multiple app instances -- acceptable for now
    since IPFS mode is already constrained to a single app process (see
    the storage-mode plan's "Deployment/process shape" section). That
    single-process constraint only rules out cross-process races, not
    cross-thread ones -- gunicorn's gthread worker class runs several
    request-handling threads inside that one process, so the
    read-increment-write below is guarded by a lock rather than relying
    on the GIL to make it atomic across the two dict operations."""
    composite_key = f"{scope}:{key}"[:160]
    current = now()
    epoch_start = (int(current.timestamp()) // window_seconds) * window_seconds
    window_start = datetime.fromtimestamp(epoch_start, tz=timezone.utc)
    with _ipfs_rate_limit_lock:
        # Opportunistic cleanup of stale windows so this dict doesn't grow
        # unboundedly for the lifetime of a long-running process.
        stale_cutoff = window_start - timedelta(hours=1)
        for existing_key, existing_window in list(_ipfs_rate_limit_windows):
            if existing_window < stale_cutoff:
                del _ipfs_rate_limit_windows[(existing_key, existing_window)]
        count = _ipfs_rate_limit_windows.get((composite_key, window_start), 0) + 1
        _ipfs_rate_limit_windows[(composite_key, window_start)] = count
    if count > limit:
        g.rate_limit_retry_after = max(1, window_seconds - int((current - window_start).total_seconds()))
        return False
    return True


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
        abort(403, description=tr("The API client lacks scope {scope}.", scope=scope))


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
        "subcategory": ticket.subcategory,
        "closure_category": ticket.closure_category,
        "closure_subcategory": ticket.closure_subcategory,
        "resolution_notes": ticket.resolution_notes,
        "opened_at": ticket.created_at.isoformat(),
        "updated_at": ticket.updated_at.isoformat(),
        "resolved_at": ticket.resolved_at.isoformat() if ticket.resolved_at else None,
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


def api_ctask_document(task):
    return {
        "number": task.number,
        "title": task.title,
        "taskType": task.task_type,
        "state": task.state,
        "required": task.required,
        "sequence": task.sequence,
        "assignmentGroup": task.assignment_group.name if task.assignment_group else None,
        "assignee": task.assignee.name if task.assignee else None,
        "plannedStart": task.planned_start.isoformat() if task.planned_start else None,
        "plannedEnd": task.planned_end.isoformat() if task.planned_end else None,
        "workNotes": task.work_notes or "",
    }


def api_idempotency_context(required=True):
    """`required=False` is for endpoints that predate this mechanism and
    whose OpenAPI contract has never documented Idempotency-Key as
    required -- an already-shipped client (the native mobile app) can't
    be assumed to send it, so making it mandatory now would break that
    client outright rather than add safety. Those callers still get
    real dedupe/replay protection when a client *does* send the header
    (new clients, or the app once it's updated to), just without forcing
    every existing caller to start sending one immediately. Returns
    (None, None, None) when optional and no key was sent, so callers
    should skip store_api_idempotency() in that case."""
    key = request.headers.get("Idempotency-Key", "").strip()
    if not key:
        if not required:
            return None, None, None
        abort(400, description=(
            tr("Idempotency-Key is required and must contain 1-128 safe characters.")
        ))
    if len(key) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]+", key):
        abort(400, description=(
            tr("Idempotency-Key is required and must contain 1-128 safe characters.")
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
                tr("The idempotency key was already used for a different request.")
            ))
        response = Response(existing.response_body, status=existing.response_status)
        response.mimetype = "application/json"
        response.headers["Idempotency-Replayed"] = "true"
        return key, request_hash, response
    return key, request_hash, None


def store_api_idempotency(key, request_hash, response_body, status):
    if key is None:  # optional idempotency (see api_idempotency_context) and none was sent
        return
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


def serialize_number_allocation(key):
    """Serializes the read-current-max/compute-next-number critical section
    in next_number()/next_enterprise_number()/sequence_number()/
    next_operational_task_number() against other concurrent callers
    allocating the same kind of number, using a PostgreSQL transaction-scoped
    advisory lock (auto-released at commit/rollback -- nothing to explicitly
    unlock, and safe to call again on a retry within the same transaction:
    re-acquiring an already-held advisory xact lock in the same session is a
    cheap no-op in Postgres, and a savepoint rollback does not release it).

    Found via real load testing (tools/stress_test.py), not theorized: at
    concurrency 80, concurrent incident-creation requests raced to compute
    an identical `MAX(Ticket.id) + 1` before either committed, burning
    through create_with_retry_on_number_collision's 10 retry attempts often
    enough to produce a measured 4.33% request failure rate (65/1500,
    surfaced as 409s) -- optimistic retry alone doesn't scale with
    concurrency the way true serialization does.

    PostgreSQL-only: a no-op under STORAGE_MODE=ipfs's SQLite projection,
    which has no advisory-lock equivalent. That mode is already constrained
    to a single Gunicorn worker (see tools/gunicorn-entrypoint.sh), which
    substantially narrows this exact race even without this lock; the
    existing retry-on-collision behavior is unchanged there as a fallback.
    """
    if db.engine.dialect.name != "postgresql":
        return
    db.session.execute(db.text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": key})


def next_number(kind):
    prefix = {"incident": "INC", "change": "CHG"}[kind]
    serialize_number_allocation(f"ticket:{kind}")
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
    abort(409, description=error_description or tr("Could not allocate a unique record number; please try again."))


def create_ticket_with_unique_number(kind, **fields):
    def build():
        ticket = Ticket(number=next_number(kind), kind=kind, **fields)
        db.session.add(ticket)
        return ticket
    ticket = create_with_retry_on_number_collision(
        build, error_description="Could not allocate a unique ticket number; please try again."
    )
    # Every ticket's requester automatically follows their own ticket -- the
    # single choke point every ticket-creation call site (web forms, the
    # mobile API, catalog fulfilment, monitoring-ingested events) already
    # goes through, so this can't be missed by adding a new one.
    if ticket.requester_id:
        follow_ticket(ticket, ticket.requester)
    return ticket


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

CMDB_RELATIONSHIP_DISPLAY_LIMIT = 200

# One glyph per workspace on /modules, matching this app's existing
# hand-authored feather-style icon set (viewBox 0 0 24 24, stroke-based --
# see the topbar/nav icons in base.html). Hardcoded, developer-authored
# markup only (never derived from user/DB input), so rendering it with
# |safe in modules.html carries no injection risk.
DOMAIN_ICONS = {
    "problem": '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "customer": '<circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/>',
    "hr": '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    "security": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "risk": '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><polyline points="9 14 11 16 15 12"/>',
    "portfolio": '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
    "field_service": '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
    "event": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "release": '<path d="M16.5 9.4 7.55 4.24"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.29 7 12 12 20.71 7"/><line x1="12" y1="22" x2="12" y2="12"/>',
}






def initial_language_preference():
    """New accounts start on the administrator's default interface language,
    or follow their browser language when that default is automatic."""
    from serviceops_core.localization import AUTOMATIC, canonical_language
    return canonical_language(setting_value("DEFAULT_LANGUAGE", AUTOMATIC)) or AUTOMATIC


def setting_value(key, default=None):
    definition = find_setting_definition(key)
    fallback = default if default is not None else (
        os.getenv(key) if os.getenv(key) is not None else (definition or {}).get("default", ""))
    try:
        row = db.session.get(PlatformSetting, key)
    except Exception:
        # Deliberately still falls back rather than raising -- this is called
        # pervasively for feature flags/thresholds throughout request
        # handling, and a transient DB hiccup shouldn't take down every
        # feature gated by a setting lookup. But it was previously silent,
        # so a real, ongoing DB problem degraded every setting app-wide with
        # no trace in the logs. Log it instead -- via the stdlib logger by
        # name (matching Flask's own app.logger, which is just
        # logging.getLogger(app.import_name)) rather than current_app,
        # since setting_value() is called from places with no active app
        # context (e.g. serviceops_core helpers exercised directly in
        # tests), and current_app itself would raise in that situation.
        logging.getLogger("app").exception("Unable to read platform setting %s", key)
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


def _env_or_default(key, default):
    # setting_value() only consults the environment when the call-site default
    # is None, so a typed helper that always supplies a default silently ignored
    # deployment configuration (ENABLE_HSTS=true never enabled HSTS). Precedence
    # is: administrator database setting > environment > call-site default. A
    # blank variable counts as unset: Compose passes unset variables through as
    # empty strings, and that must never override a secure default.
    value = os.getenv(key)
    return value if value is not None and value.strip() else str(default)


def setting_bool(key, default=False):
    return coerce_bool(setting_value(key, _env_or_default(key, default)))


def setting_int(key, default=0):
    return coerce_int(setting_value(key, _env_or_default(key, default)), default)


NOTIFICATION_SEVERITY_BY_EVENT = {
    "sla.breached": "critical",
    "client_ticket.escalated": "critical",
    "approval.requested": "warning",
    "enterprise.approval_requested": "warning",
    "ticket.mentioned": "warning",
}


def notification_severity_for_event(event_type):
    """Maps a create_notification() event_type to "critical"/"warning"/"info"
    for the bell icon's badge color and the notification list's accent bar.
    Unclassified and absent event types are "info" -- the pre-existing,
    unstyled appearance -- so this is purely additive for callers that
    already pass a recognized event_type."""
    return NOTIFICATION_SEVERITY_BY_EVENT.get(event_type, "info")


def highest_notification_severity(unread_query):
    """The single most severe value among a user's unread notifications, or
    None when there are no unread notifications -- drives the bell icon's
    badge color (a bell showing 5 unread where only one is critical should
    still read as critical, not be diluted to the count's own color)."""
    severities = {
        row[0] for row in unread_query.filter_by(read=False).with_entities(Notification.severity).distinct()
    }
    for level in ("critical", "warning", "info"):
        if level in severities:
            return level
    return None


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
        severity=notification_severity_for_event(event_type),
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
        ECKey.import_key(private_key),
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
    proxy_url = resolve_component_proxy_url("APNS")
    with httpx.Client(http2=True, timeout=10.0, proxy=proxy_url, trust_env=False) as client:
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


def resolve_outbound_proxies(configuration=None):
    """Returns a requests-compatible {"http": url, "https": url} proxies
    dict for one outbound notification delivery (webhook/chat channel or
    the GitHub update check), or None for a direct connection -- for
    deployments without direct internet access to Google Chat, Telegram,
    Teams, Slack, Discord, or GitHub.

    `configuration` is an IntegrationConnection's decrypted configuration
    dict, which may hold a per-channel override:
      proxy_mode "none"   -- explicit bypass, even if a default is set.
      proxy_mode "custom" -- use this same dict's proxy_url.
      anything else (including missing/"default") -- inherit the
        OUTBOUND_PROXY_URL platform default (itself already env-var-seeded
        and admin-overridable via setting_value()'s existing precedence).
    Pass configuration=None for a call with no per-item override (the
    update check has no connection to attach one to) -- it always uses the
    platform default.

    A malformed proxy URL is treated as "no proxy" rather than raising --
    a broken admin-entered value must never silently block every
    notification through this channel; the resulting direct-connection
    attempt fails visibly in the delivery log instead, which is far easier
    to diagnose than every delivery through this channel erroring inside
    proxy parsing instead of at the actual network call.
    """
    configuration = configuration or {}
    mode = configuration.get("proxy_mode", "default")
    if mode == "none":
        return None
    proxy_url = configuration.get("proxy_url", "") if mode == "custom" else setting_value("OUTBOUND_PROXY_URL", "")
    if not proxy_url:
        return None
    try:
        parse_proxy_url(proxy_url)
    except ValueError:
        return None
    return {"http": proxy_url, "https": proxy_url}


def resolve_component_proxy_url(prefix):
    """Same three-state precedence as resolve_outbound_proxies(), for an
    outbound component configured through platform settings instead of an
    IntegrationConnection: <prefix>_PROXY_MODE picks "default" (inherit
    OUTBOUND_PROXY_URL), "none" (connect directly) or "custom" (use
    <prefix>_PROXY_URL). Returns a plain URL string or None. A malformed
    URL falls back to a direct connection for the reason given in
    resolve_outbound_proxies()."""
    mode = setting_value(f"{prefix}_PROXY_MODE", "default")
    if mode == "none":
        return None
    proxy_url = (setting_value(f"{prefix}_PROXY_URL", "") if mode == "custom"
                 else setting_value("OUTBOUND_PROXY_URL", ""))
    if not proxy_url:
        return None
    try:
        parse_proxy_url(proxy_url)
    except ValueError:
        return None
    return proxy_url


def resolve_component_proxies(prefix):
    """resolve_component_proxy_url() as a requests-compatible proxies dict,
    or None for a direct connection."""
    proxy_url = resolve_component_proxy_url(prefix)
    return {"http": proxy_url, "https": proxy_url} if proxy_url else None


def describe_component_egress(prefix):
    """A plain-language label for the route resolve_component_proxy_url()
    picks, for connection-test results. Never includes the proxy URL,
    which may carry credentials."""
    if not resolve_component_proxy_url(prefix):
        return "a direct connection"
    if setting_value(f"{prefix}_PROXY_MODE", "default") == "custom":
        return "its custom proxy"
    return "the system default proxy"


def resolve_smtp_proxy_url():
    """The email relay's egress policy (SMTP_PROXY_MODE/SMTP_PROXY_URL) as
    a plain URL string, since the caller is
    serviceops_core.proxy_tunnel.tunnel_through_proxy(), not requests. SMTP
    has no native HTTP-proxy support (it isn't HTTP), so it tunnels through
    an HTTP(S) proxy's CONNECT method instead."""
    return resolve_component_proxy_url("SMTP")


def single_line_header(value):
    """EmailMessage raises instead of sending when a header contains CR/LF,
    and ticket titles/subjects can arrive multi-line (API, integrations,
    older ingested mail)."""
    return " ".join(str(value).split())


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
    provider = setting_value("SMTP_PROVIDER", "generic")
    provider_defaults = {
        "google_workspace_relay": ("smtp-relay.gmail.com", "none"),
        "google_workspace_app_password": ("smtp.gmail.com", "password"),
        "google_workspace_oauth2": ("smtp.gmail.com", "oauth2"),
    }
    default_host, default_auth = provider_defaults.get(provider, ("", "password"))
    host = setting_value("SMTP_HOST", "") or default_host
    sender = setting_value("SMTP_FROM", "")
    if not host or not sender:
        raise RuntimeError("SMTP host and from address are required.")
    message = EmailMessage()
    message["From"] = formataddr((setting_value("SMTP_FROM_NAME", "ServiceOps"), sender))
    message["To"] = user.email
    message["Subject"] = single_line_header(payload["title"])
    reply_to = setting_value("SMTP_REPLY_TO", "")
    if reply_to:
        message["Reply-To"] = reply_to
    message["X-ServiceOps-Event-ID"] = event.event_id
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(payload["body"])
    security = setting_value(
        "SMTP_SECURITY", "starttls" if setting_bool("SMTP_STARTTLS", True) else "none"
    )
    port = setting_int("SMTP_PORT", 465 if security == "tls" else 587)
    timeout = setting_int("SMTP_TIMEOUT_SECONDS", 10)
    smtp_class = smtplib.SMTP_SSL if security == "tls" else smtplib.SMTP
    kwargs = {"timeout": timeout}
    if security == "tls":
        kwargs["context"] = ssl.create_default_context()
    smtp_proxy_url = resolve_smtp_proxy_url()
    smtp_proxies = {"http": smtp_proxy_url, "https": smtp_proxy_url} if smtp_proxy_url else None
    # tunnel_through_proxy(None) is a deliberate no-op (see its docstring),
    # so this always wraps rather than branching on whether a proxy is
    # configured -- smtplib has no native proxy support (SMTP isn't HTTP),
    # so reaching an external mail relay in a deployment without direct
    # internet access requires tunneling the raw TCP connection through an
    # HTTP(S) proxy's CONNECT method.
    with tunnel_through_proxy(smtp_proxy_url), smtp_class(host, port, **kwargs) as smtp:
        smtp.ehlo()
        if security == "starttls":
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        username = setting_value("SMTP_USERNAME", "")
        auth_mode = setting_value("SMTP_AUTH_MODE", default_auth)
        if security == "none" and auth_mode != "none":
            raise RuntimeError("SMTP authentication requires STARTTLS or implicit TLS.")
        if auth_mode == "oauth2":
            client_id = setting_value("SMTP_OAUTH_CLIENT_ID", "")
            client_secret = setting_value("SMTP_OAUTH_CLIENT_SECRET", "")
            refresh_token = setting_value("SMTP_OAUTH_REFRESH_TOKEN", "")
            if not all((username, client_id, client_secret, refresh_token)):
                raise RuntimeError("Google OAuth username, client ID, client secret and refresh token are required.")
            token_response = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": client_id, "client_secret": client_secret,
                    "refresh_token": refresh_token, "grant_type": "refresh_token",
                },
                proxies=smtp_proxies, timeout=timeout,
            )
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")
            if not access_token:
                raise RuntimeError("Google OAuth token response did not include an access token.")
            auth = base64.b64encode(
                f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode()
            ).decode()
            code, response = smtp.docmd("AUTH", "XOAUTH2 " + auth)
            if code not in {235, 250}:
                raise RuntimeError(f"Google OAuth SMTP authentication failed ({code}).")
        elif auth_mode == "password" and username:
            smtp.login(username, setting_value("SMTP_PASSWORD", ""))
        smtp.send_message(message)
    return True


_google_access_token_cache = {}
_google_access_token_lock = threading.Lock()


def _google_service_account_access_token(service_account_json, scopes, proxies=None):
    """Exchanges a Google service-account key for a short-lived OAuth2
    access token via the standard JWT-bearer grant (RFC 7523) -- the same
    flow Google's own client libraries use under the hood, implemented
    directly with joserfc (already a dependency here for Cloudflare Access
    JWT verification) rather than adding a Google Cloud SDK dependency for
    one token exchange. Cached per (service account, scope set), guarded
    the same way as _cloudflare_access_key_set() so concurrent request/
    worker threads racing in at expiry don't each independently
    re-exchange. `proxies` is the caller's own egress policy, so the token
    exchange leaves the network the same way as the call it authorizes."""
    scope_string = " ".join(sorted(scopes))
    cache_key = hashlib.sha256((service_account_json + "|" + scope_string).encode()).hexdigest()
    with _google_access_token_lock:
        cached = _google_access_token_cache.get(cache_key)
        if cached and cached["expires_at"] > time_module.monotonic():
            return cached["access_token"]
    credentials = json.loads(service_account_json)
    key = RSAKey.import_key(credentials["private_key"])
    issued_at = int(time_module.time())
    assertion = jwt.encode(
        {"alg": "RS256"},
        {
            "iss": credentials["client_email"], "sub": credentials["client_email"],
            "scope": scope_string, "aud": "https://oauth2.googleapis.com/token",
            "iat": issued_at, "exp": issued_at + 3600,
        },
        key,
    )
    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion},
        proxies=proxies, timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    access_token = payload["access_token"]
    with _google_access_token_lock:
        _google_access_token_cache[cache_key] = {
            "access_token": access_token,
            # A little under the real expiry so a caller never starts a
            # request with a token that's about to expire mid-flight.
            "expires_at": time_module.monotonic() + max(payload.get("expires_in", 3600) - 60, 60),
        }
    return access_token


def google_chat_post_message(connection, text, thread_name=None, message_id=None):
    """Posts a message to a Google Chat space via the real Chat REST API
    (not a plain incoming webhook), using this interactive connection's own
    service account (connection.secret holds the service-account JSON key;
    see GOOGLE_CHAT_APP_ENABLED). `connection.delivery_endpoint` holds the
    target space's resource name (e.g. "spaces/AAAAxxxxx") for this mode,
    not a webhook URL. Passing `thread_name` continues that existing
    thread instead of starting a new one. Returns the created message's
    own thread name either way, so the very first call (no thread_name
    yet) tells the caller what thread a later reply should be linked to.
    """
    proxies = resolve_outbound_proxies(connection.configuration)
    access_token = _google_service_account_access_token(
        connection.secret, {"https://www.googleapis.com/auth/chat.bot"}, proxies,
    )
    body = {"text": text}
    params = {}
    if thread_name:
        body["thread"] = {"name": thread_name}
        params["messageReplyOption"] = "REPLY_MESSAGE_OR_NEW_THREAD"
    if message_id:
        params["messageId"] = message_id
    response = requests.post(
        f"https://chat.googleapis.com/v1/{connection.delivery_endpoint}/messages",
        json=body, params=params,
        headers={"Authorization": f"Bearer {access_token}"},
        proxies=proxies, timeout=10,
    )
    # A retried Pub/Sub command uses a deterministic client message ID.
    # Google's 409 means that exact reply was already created, so treating it
    # as delivered prevents a crash between POST and our local replied_at
    # commit from producing duplicate replies.
    if not (message_id and getattr(response, "status_code", None) == 409):
        response.raise_for_status()
    return response.json().get("thread", {}).get("name", "")


def deliver_google_chat_interactive(event, connection):
    """Delivers to a Google Chat connection configured as the interactive
    app (GOOGLE_CHAT_APP_ENABLED, connection.configuration["interactive"])
    -- posts via the real Chat REST API and records the resulting thread
    against the alerted record (ChatThreadLink), so a later /ack or
    /escalate reply typed in that thread (process_google_chat_pubsub_schedule())
    can resolve which record to act on. Only meaningful for the
    group/tenant-scoped activity.created events this kind of channel
    actually receives (connection_accepts_event already excludes personal
    notification.created bodies from non-personal channels) -- `target` is
    the record's display number, set by every audit() call.

    Google's own chat.googleapis.com host is not admin-supplied here, so
    the DNS-pin/private-address pre-check the rest of deliver_webhook
    applies to arbitrary destinations does not apply to this path."""
    record_number = str(event.payload.get("target") or "").strip()
    text = provider_payload("google_chat", event.payload, connection.configuration)["text"]
    thread_name = google_chat_post_message(connection, text)
    if record_number and thread_name:
        db.session.add(ChatThreadLink(
            connection_id=connection.id, thread_name=thread_name,
            record_number=record_number, tenant_id=connection.tenant_id,
        ))
    return 200


def deliver_webhook(event, connection):
    if connection.kind == "google_chat" and connection.configuration.get("interactive"):
        return deliver_google_chat_interactive(event, connection)
    payload = {
        "id": event.event_id,
        "type": event.event_type,
        "created_at": event.created_at.isoformat(),
        "data": event.payload,
    }
    # Signed deliveries transmit exactly the bytes that were signed, so a
    # receiver can verify the HMAC over the raw request body as documented.
    # Passing `json=` to requests re-serialises with different separators
    # and key order, which made raw-body verification impossible.
    encoded = None
    if connection.kind in {"teams", "google_chat", "slack", "discord", "telegram"}:
        body = provider_payload(connection.kind, event.payload, connection.configuration)
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
    target = connection.delivery_endpoint
    if connection.kind == "telegram":
        token = connection.secret
        if not token:
            raise RuntimeError("Telegram bot token is not configured.")
        target = f"https://api.telegram.org/bot{token}/sendMessage"
    # A configured proxy (per-channel override, or the OUTBOUND_PROXY_URL
    # platform default) is a deliberate deployment-level trust boundary for
    # deployments without direct internet access -- when it's in use, the
    # local DNS-pin/private-address pre-check below is both inapplicable
    # (the proxy resolves the destination on its side, not this host, so
    # there is no local resolution here to pin against or validate) and
    # potentially impossible to satisfy at all (a public hostname like
    # chat.googleapis.com may not even resolve from inside an air-gapped
    # network without going through the proxy). The administrator who
    # configured the proxy is asserting that outbound path as the trust
    # boundary, the same way NetworkPolicy egress rules already are in this
    # deployment's Kubernetes chart -- ServiceOps is not the enforcement
    # point for what a trusted, admin-configured egress proxy is allowed to
    # reach.
    request_body = {"data": encoded} if encoded is not None else {"json": body}
    proxies = resolve_outbound_proxies(connection.configuration)
    max_redirects = 3
    for _ in range(max_redirects + 1):
        if proxies:
            try:
                response = requests.post(
                    target, **request_body, headers=headers, timeout=10,
                    allow_redirects=False, proxies=proxies,
                )
            except requests.RequestException as error:
                raise RuntimeError("Notification provider request failed.") from error
        else:
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
                    try:
                        response = requests.post(
                            target, **request_body, headers=headers, timeout=10,
                            allow_redirects=False,
                        )
                    except requests.RequestException as error:
                        raise RuntimeError("Notification provider request failed.") from error
            else:
                try:
                    response = requests.post(
                        target, **request_body, headers=headers, timeout=10,
                        allow_redirects=False,
                    )
                except requests.RequestException as error:
                    raise RuntimeError("Notification provider request failed.") from error
        if response.is_redirect:
            location = response.headers.get("Location", "")
            target = urljoin(target, location)
            continue
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"HTTP {response.status_code}")
        return response.status_code
    raise RuntimeError("Webhook delivery exceeded the maximum redirect hops.")


# Worst realistic case for the claim lease below: `limit` events each
# attempting up to 3 channels (apns/smtp/webhook-or-connection) at the
# per-request timeout used throughout this module (10s) -- rounded up
# generously so a merely-slow (not stuck) batch never has an event's
# lease expire out from under it mid-processing.
OUTBOX_CLAIM_LEASE_SECONDS = 1800


def process_outbox(limit=50):
    """Claims due events, delivers them, and records each outcome.

    Claiming and persisting are separate, short transactions so no
    database transaction -- and therefore no row lock -- is held across
    the actual outbound network calls, which can take up to ~10s each and
    are attempted for as many as `limit` events in one pass. The
    previous version claimed the whole batch with one
    `SELECT ... FOR UPDATE` and committed once at the very end, holding
    that lock (and a pooled connection) for the full batch's worst-case
    delivery time: a single slow or unreachable channel held up every
    other event in the batch, and a crash mid-batch rolled back
    already-recorded deliveries for events that had, in fact, already
    gone out -- the same class of bug found and fixed via load testing
    in the FlowOps webhook dispatcher (see that project's server.py).

    Claiming moves each event straight to "Processing" and commits
    immediately, which both releases the row lock right away and stops
    any other worker (multiple gunicorn workers/replicas all run this
    loop) from picking up the same event. A "Processing" event whose
    lease (`available_at`) has expired is treated as claimable again, so
    a crash between claim and persist just delays that one event by up
    to OUTBOX_CLAIM_LEASE_SECONDS rather than losing or double-delivering
    it -- self-healing on the very next call, with no separate sweep.
    """
    claim_deadline = now() + timedelta(seconds=OUTBOX_CLAIM_LEASE_SECONDS)
    events = OutboxEvent.query.filter(
        db.or_(
            db.and_(OutboxEvent.state.in_(["Pending", "Retry"]), OutboxEvent.available_at <= now()),
            db.and_(OutboxEvent.state == "Processing", OutboxEvent.available_at <= now()),
        )
    ).order_by(OutboxEvent.id).with_for_update(skip_locked=True).limit(limit).all()
    for event in events:
        event.state = "Processing"
        event.available_at = claim_deadline
    db.session.commit()

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
        if setting_bool("SMTP_ENABLED") and event.event_type == "notification.created":
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
            if not connection_accepts_event(connection, event.event_type, event.payload):
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
        # Committed per event, not once for the whole batch: this is the
        # actual fix -- see the docstring above. Each event's outcome (and
        # any device/delivery-record side effects from the channels just
        # attempted) is durable before moving on, so a slow or crashing
        # later event in the batch can never roll back an earlier one that
        # already succeeded.
        db.session.commit()
        processed += 1
    return processed


def next_enterprise_number(domain):
    prefix = DOMAIN_CONFIG[domain]["prefix"]
    serialize_number_allocation(f"enterprise:{domain}")
    latest = EnterpriseRecord.query.filter_by(domain=domain).order_by(EnterpriseRecord.id.desc()).first()
    sequence = (latest.id + 1) if latest else 1
    return f"{prefix}{sequence:07d}"


def sequence_number(model, prefix):
    serialize_number_allocation(f"model:{model.__name__}")
    latest = model.query.order_by(model.id.desc()).first()
    return f"{prefix}{((latest.id if latest else 0) + 1):07d}"


def next_operational_task_number(task_kind):
    prefix = {"change": "CTASK", "problem": "PTASK", "event": "EVTASK"}.get(
        task_kind, "TASK"
    )
    serialize_number_allocation(f"task:{task_kind}")
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
    if attachment.scan_status == "scan_error" and setting_bool("CLAMAV_ENABLED", False):
        # Scanning is turned on and this specific file's scan genuinely
        # failed (transient ClamAV error), so we don't know if it's safe.
        # "not_scanned" is left servable: it's the honest, expected status
        # for every attachment when scanning is disabled, and blocking it
        # would make files uploaded before scanning was enabled permanently
        # inaccessible.
        current_app.logger.warning(
            "Blocked download of unscanned attachment after scan error: attachment_id=%s", attachment.id,
        )
        abort(503, description=tr("This attachment could not be verified as safe and is temporarily unavailable. Please contact an administrator."))
    render_inline = inline and attachment.mime_type in PREVIEWABLE_ATTACHMENT_TYPES
    disposition = content_disposition(
        "inline" if render_inline else "attachment", attachment.original_name,
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
            abort(503, description=tr("Attachment storage is temporarily unavailable. Please try again shortly."))
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
            abort(503, description=tr("Attachment storage is temporarily unavailable. Please try again shortly."))
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


def content_disposition(disposition, filename):
    """RFC 6266 Content-Disposition, encoded the way send_file encodes local
    downloads, so object-storage and IPFS downloads keep non-ASCII names."""
    try:
        filename.encode("ascii")
    except UnicodeEncodeError:
        simple = unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode("ascii")
        names = {"filename": simple, "filename*": f"UTF-8''{quote(filename, safe='!#$&+-.^_`|~')}"}
    else:
        names = {"filename": filename}
    return dump_options_header(disposition, names)


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


def find_record_by_number(number, tenant_id=None):
    """Looks up any ITIL record by its display number, strictly scoped to the
    caller's tenant. Every branch must filter by tenant before returning a
    record — this function is a cross-record-type lookup used for linking,
    and an unscoped branch here is a cross-tenant existence oracle.

    `tenant_id` defaults to the logged-in current_user's tenant; pass it
    explicitly for a caller with no Flask-Login session at all (e.g. the
    Google Chat Pub/Sub handler, which resolves its own acting user by
    email and must use *that* user's tenant, not a nonexistent session)."""
    normalized = (number or "").strip().upper()
    if tenant_id is None:
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


def active_approval_delegation(from_user_id, to_user_id=None, at=None):
    """Return a current, tenant-safe absence delegation, if one exists."""
    at = at or now()
    query = ApprovalDelegation.query.filter(
        ApprovalDelegation.from_user_id == from_user_id,
        ApprovalDelegation.active.is_(True),
        ApprovalDelegation.starts_at <= at,
        ApprovalDelegation.ends_at >= at,
    )
    if to_user_id is not None:
        query = query.filter(ApprovalDelegation.to_user_id == to_user_id)
    return query.order_by(ApprovalDelegation.created_at.desc()).first()


def delegated_pending_votes(user):
    delegations = ApprovalDelegation.query.filter(
        ApprovalDelegation.to_user_id == user.id,
        ApprovalDelegation.tenant_id == user.tenant_id,
        ApprovalDelegation.active.is_(True),
        ApprovalDelegation.starts_at <= now(),
        ApprovalDelegation.ends_at >= now(),
    ).all()
    source_ids = {row.from_user_id for row in delegations}
    if not source_ids:
        return []
    return ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
        ApprovalVote.approver_id.in_(source_ids),
        ApprovalVote.state == "Requested",
        ApprovalChain.tenant_id == user.tenant_id,
    ).all()


def enforce_approval_change_freeze(vote, decision, tenant_id):
    """Apply the same change-freeze policy to every approval channel."""
    if decision != "Approved" or vote.gate.chain.target_type != "ticket":
        return
    target = db.session.get(Ticket, vote.gate.chain.target_id)
    governance = target.change_governance if target else None
    if not governance or governance.change_type == "Emergency":
        return
    freeze = active_change_freeze(
        tenant_id, governance.planned_start, governance.planned_end,
    )
    if freeze:
        abort(409, description=(
            tr("Cannot approve: this change's planned window falls inside the change freeze \"{title}\". Only Emergency changes can be approved during a freeze.", title=freeze.title)
        ))


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


def record_resolution_state(ticket, old_state, new_state):
    """Keeps resolution data consistent on every path that changes a ticket's
    state. resolved_at marks the latest entry into Resolved (or into Closed
    without passing through Resolved) and is cleared on reopen; an incident
    resolved without an explicit closure categorisation keeps its logging
    categorisation as the closure one."""
    if new_state == old_state:
        return
    if new_state == "Resolved" or (new_state == "Closed" and ticket.resolved_at is None):
        ticket.resolved_at = now()
        if ticket.kind == "incident" and not ticket.closure_category:
            ticket.closure_category = ticket.category
            ticket.closure_subcategory = ticket.subcategory or None
    elif new_state not in ("Resolved", "Closed", "Cancelled"):
        ticket.resolved_at = None


def require_resolution_notes(ticket, new_state):
    """Web resolution paths: an incident isn't resolved until how service was
    restored is documented. The v1 API keeps resolution notes optional so
    existing integrations don't break."""
    if (
        ticket.kind == "incident"
        and new_state in ("Resolved", "Closed")
        and ticket.state not in ("Resolved", "Closed")
        and not (ticket.resolution_notes or "").strip()
    ):
        abort(409, description=(
            tr("Record resolution notes (in Resolution information) before resolving {number}.", number=ticket.number)
        ))


def transition_ticket(ticket, new_state):
    if new_state not in allowed_ticket_states(ticket):
        abort(409, description=(
            tr("{number} cannot move from {state} to {new_state}. Complete the required approval chain and follow the permitted lifecycle.", number=ticket.number, state=ticket.state, new_state=new_state)
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
                tr("{number} cannot complete while required task {number2} remains {state}.", number=ticket.number, number2=incomplete.number, state=incomplete.state)
            ))
    if ticket.kind == "change" and new_state == "Closed" and not ticket.post_implementation_review:
        abort(409, description=(
            tr("{number} cannot close without a post-implementation review (ITIL 4 change enablement requires a documented outcome before a change is considered complete). Record the review first.", number=ticket.number)
        ))
    old_state = ticket.state
    ticket.state = new_state
    record_resolution_state(ticket, old_state, new_state)
    sync_slas("ticket", ticket.id, new_state)
    if ticket.kind == "incident":
        sync_service_outages(ticket)
    if new_state != old_state:
        queue_workflow_event(
            "ticket.state_entry", "ticket", ticket.id,
            ticket_workflow_context(ticket, old_state),
            tenant_id=ticket.tenant_id,
        )
        if ticket.kind == "change":
            change_payload = ticket_workflow_context(ticket, old_state)
            change_connections = IntegrationConnection.query.filter_by(
                tenant_id=ticket.tenant_id, active=True,
            ).filter(IntegrationConnection.kind != "siem").all()
            if any(
                event_matches(connection.event_types_json, "change.state_changed", change_payload)
                for connection in change_connections
            ):
                db.session.add(OutboxEvent(
                    event_type="change.state_changed",
                    payload_json=json.dumps(change_payload, sort_keys=True),
                    tenant_id=ticket.tenant_id,
                ))
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
                record_resolution_state(child, old_state, new_state)
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
        abort(409, description=tr("Approval-derived states can be changed only by an approval decision."))
    if new_state not in allowed_enterprise_states(record):
        abort(409, description=(
            tr("{number} cannot move from {state} to {new_state} while its approval or lifecycle prerequisites are incomplete.", number=record.number, state=record.state, new_state=new_state)
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
                tr("{number} cannot complete while required task {number2} remains {state}.", number=record.number, number2=incomplete.number, state=incomplete.state)
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
        abort(409, description=tr("Fulfillment cannot start until the requested item is approved."))
    if new_state == "Work in Progress":
        linked_change = ritm_linked_change(task.requested_item)
        if linked_change and linked_change.state in ("New", "Awaiting Approval"):
            abort(409, description=(
                tr("{number} cannot start production work: it is linked to {number2}, which is not yet approved and authorized. Coordination on this task (details, scheduling) is fine — set it to Pending until the change is authorized.", number=task.number, number2=linked_change.number)
            ))
    control = task.flow_control
    if (
        control and control.execution_mode == "Sequential"
        and control.predecessor
        and control.predecessor.state != "Closed Complete"
        and new_state not in ("Open", "Closed Skipped")
    ):
        abort(409, description=(
            tr("{number} cannot start until predecessor {number2} is Closed Complete.", number=task.number, number2=control.predecessor.number)
        ))
    allowed = CATALOG_TASK_TRANSITIONS.get(task.state, (task.state,))
    if new_state not in allowed:
        abort(409, description=tr("{number} cannot move from {state} to {new_state}.", number=task.number, state=task.state, new_state=new_state))
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
        abort(409, description=tr("{number} cannot move from {state} to {new_state}.", number=task.number, state=task.state, new_state=new_state))
    block = change_task_gate_block(task, new_state)
    if block:
        abort(409, description=block)
    old_state = task.state
    task.state = new_state
    if task.task_kind == "change" and new_state != old_state:
        queue_change_task_state_event(task, old_state)


def change_task_event_payload(task, previous_state):
    ticket = db.session.get(Ticket, task.parent_id) if task.parent_type == "ticket" else None
    return {
        "number": task.number,
        "ticket": ticket.number if ticket else None,
        "title": task.title,
        "task_type": task.task_type,
        "state": task.state,
        "previous_state": previous_state,
        "required": bool(task.required),
        "sequence": task.sequence,
        "assignment_group": task.assignment_group.name if task.assignment_group else None,
        "assignee": task.assignee.name if task.assignee else None,
    }


def queue_change_task_state_event(task, previous_state):
    """Publishes change_task.state_changed for subscribed webhook
    connections, so an orchestration tool (FlowOps) learns about a CTASK
    closed directly in ServiceOps without polling. Mirrors the
    change.state_changed emission in transition_ticket: the event is only
    written when at least one active connection would receive it."""
    ticket = db.session.get(Ticket, task.parent_id) if task.parent_type == "ticket" else None
    if not ticket:
        return
    payload = change_task_event_payload(task, previous_state)
    tenant_id = ticket.tenant_id
    connections = IntegrationConnection.query.filter_by(
        tenant_id=tenant_id, active=True,
    ).filter(IntegrationConnection.kind != "siem").all()
    if any(
        event_matches(connection.event_types_json, "change_task.state_changed", payload)
        for connection in connections
    ):
        db.session.add(OutboxEvent(
            event_type="change_task.state_changed",
            payload_json=json.dumps(payload, sort_keys=True),
            tenant_id=tenant_id,
        ))


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


def is_following_ticket(user, ticket):
    return TicketFollower.query.filter_by(ticket_id=ticket.id, user_id=user.id).first() is not None


def follow_ticket(ticket, user):
    """Idempotent: safe to call from every auto-follow trigger (creation,
    assignment, commenting) without first checking whether a row already
    exists."""
    if is_following_ticket(user, ticket):
        return
    # The unique constraint is the final authority: two concurrent comment or
    # assignment requests can both pass the lookup above. Keep that harmless
    # race inside a savepoint so it cannot roll back the surrounding comment.
    try:
        with db.session.begin_nested():
            db.session.add(TicketFollower(
                ticket_id=ticket.id, user_id=user.id, tenant_id=ticket.tenant_id,
            ))
            db.session.flush()
    except IntegrityError:
        pass


def unfollow_ticket(ticket, user):
    TicketFollower.query.filter_by(ticket_id=ticket.id, user_id=user.id).delete()


def ticket_followers(ticket, exclude_user_ids=()):
    """Active users following this ticket, excluding the given ids (always
    pass the acting user's own id here -- nobody needs a notification about
    their own comment)."""
    query = User.query.join(TicketFollower, TicketFollower.user_id == User.id).filter(
        TicketFollower.ticket_id == ticket.id, User.active.is_(True),
    )
    if exclude_user_ids:
        query = query.filter(~User.id.in_(exclude_user_ids))
    # Following is not an authorization grant. Assignment/team changes can
    # remove access after a follower row was created, so re-check access before
    # putting ticket titles or comment bodies into a notification.
    return [user for user in query.all() if user_can_view_ticket(user, ticket)]


MENTION_PATTERN = re.compile(r"(?<!\w)@([a-zA-Z0-9_.-]{2,80})")


def mentioned_users_in_comment(body, ticket):
    """Users named with "@username" in a comment, restricted to users who
    can currently view this ticket -- mentioning (and therefore notifying,
    with the ticket's title in the notification body) someone who isn't
    authorized to see the ticket would itself be a disclosure, so an
    @mention of an unauthorized or nonexistent username is silently just
    text, not a working mention."""
    usernames = {match.group(1).lower() for match in MENTION_PATTERN.finditer(body)}
    if not usernames:
        return []
    candidates = User.query.filter(
        User.tenant_id == ticket.tenant_id, User.active.is_(True),
        func.lower(User.username).in_(usernames),
    ).all()
    return [candidate for candidate in candidates if user_can_view_ticket(candidate, ticket)]


def ticket_mentionable_users(ticket):
    """The candidate pool offered by the @mention autocomplete: everyone
    already authorized to view the ticket (its requester/assignee plus the
    owning team's agents/manager) rather than every user in the tenant --
    matches mentioned_users_in_comment's own authorization check, so
    anything the autocomplete offers will actually work."""
    ids = {ticket.requester_id}
    if ticket.assignee_id:
        ids.add(ticket.assignee_id)
    ids.update(agent.id for agent in ticket_team_agents(ticket))
    ids.discard(None)
    return User.query.filter(User.id.in_(ids), User.active.is_(True)).order_by(User.name).all()


def post_ticket_comment(ticket, author, body, parent_id=None, ai_assisted=False):
    """Single source of truth for creating a ticket comment, shared by the
    web UI and the mobile REST API, so threading/follow/mention behavior
    can't drift between the two entry points."""
    if parent_id is not None:
        parent = db.session.get(Comment, parent_id)
        if not parent or parent.ticket_id != ticket.id:
            abort(400, description=tr("That comment thread no longer exists."))
        # The discussion UI intentionally has one reply level. A reply to a
        # reply therefore joins the same top-level thread instead of creating
        # a hidden/deceptive deeper hierarchy through the API.
        parent_id = parent.parent_id or parent.id
    comment = Comment(ticket_id=ticket.id, user_id=author.id, body=body, tenant_id=ticket.tenant_id,
                      parent_id=parent_id, ai_assisted=ai_assisted)
    db.session.add(comment)
    db.session.flush()
    follow_ticket(ticket, author)
    mentioned = mentioned_users_in_comment(body, ticket)
    preview = body if len(body) <= 200 else body[:197] + "..."
    for user in mentioned:
        follow_ticket(ticket, user)
        create_notification(
            user.id, f"{author.name} mentioned you in {ticket.number}", preview,
            tenant_id=ticket.tenant_id, target_type="ticket", target_id=ticket.id,
            event_type="ticket.mentioned",
        )
    already_notified = {author.id, *(user.id for user in mentioned)}
    for user in ticket_followers(ticket, exclude_user_ids=already_notified):
        create_notification(
            user.id, f"New comment on {ticket.number}", f"{author.name}: {preview}",
            tenant_id=ticket.tenant_id, target_type="ticket", target_id=ticket.id,
            event_type="ticket.comment_added",
        )
    return comment


def require_ticket_team_access(ticket):
    if not user_can_manage_ticket(current_user, ticket):
        group = ticket_owning_group(ticket)
        abort(403, description=(
            tr("Only active members of {value} can update {number}.", value=group.name if group else 'the owning team', number=ticket.number)
        ))


TICKET_LOCKED_STATES = ("Resolved", "Closed", "Cancelled")


def ticket_locked_for_edits(ticket):
    return ticket.state in TICKET_LOCKED_STATES


def require_ticket_not_locked(ticket):
    if ticket_locked_for_edits(ticket):
        flash(
            tr("{number} is {state} and locked: only comments and notes can be added. Reopen it first to make other changes.", number=ticket.number, state=ticket.state),
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


def change_target_cis(ticket):
    """Return every CI explicitly in a change's governed scope.

    The primary CI lives on ChangeGovernance and additional affected CIs live
    in TaskCI.  Keeping that storage detail behind one helper prevents change
    controls from silently evaluating only the first CI selected on the form.
    """
    cis_by_id = {}
    governance = ticket.change_governance
    if governance and governance.ci:
        cis_by_id[governance.ci.id] = governance.ci
    for link in TaskCI.query.filter_by(
        target_type="ticket", target_id=ticket.id,
    ).all():
        if link.ci:
            cis_by_id[link.ci_id] = link.ci
    return [cis_by_id[ci_id] for ci_id in sorted(cis_by_id)]


def change_requires_ccb(governance, cis=None):
    if not governance.ccb_required:
        return False
    scoped_cis = list(cis) if cis is not None else ([governance.ci] if governance.ci else [])
    if not scoped_cis:
        return True
    return any(
        ci.require_ccb_approval
        or normalize_environment(ci.environment) in ccb_required_environments()
        for ci in scoped_cis
    )


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
        abort(409, description=tr("The owning team requires an active manager."))
    stages = [{
        "name": f"{ownership.group.name} manager assessment",
        "mode": "all",
        "approver_ids": [ownership.group.manager_id],
    }]
    covered_group_ids = {ownership.group_id}
    scoped_cis = change_target_cis(ticket)
    ci_groups = {}
    for ci in scoped_cis:
        if ci.support_group:
            ci_groups.setdefault(ci.support_group.id, (ci.support_group, ci))
    for group_id in sorted(set(ci_groups) - covered_group_ids):
        ci_group, representative_ci = ci_groups[group_id]
        if not ci_group.active or not ci_group.manager or not ci_group.manager.active:
            abort(409, description=tr("The {name} team (owner of {name2}) requires an active manager.", name=ci_group.name, name2=representative_ci.name))
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
    if scoped_cis:
        service_ids = [
            row[0] for row in db.session.query(ServiceOfferingCI.service_offering_id)
            .filter(
                ServiceOfferingCI.ci_id.in_([ci.id for ci in scoped_cis]),
                ServiceOfferingCI.tenant_id == ticket.tenant_id,
            ).all()
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
                        tr("The {name} team (co-owner of a service this CI backs) requires an active manager.", name=sibling_group.name)
                    ))
                stages.append({
                    "name": f"{sibling_group.name} manager assessment (service co-owner)",
                    "mode": "all",
                    "approver_ids": [sibling_group.manager_id],
                })
                covered_group_ids.add(group_id)
    if governance.change_type != "Standard" and change_requires_ccb(governance, scoped_cis):
        ccb = SupportGroup.query.filter_by(name="Change Control Board", tenant_id=ticket.tenant_id).first()
        ccb_ids = [
            member.user_id for member in (ccb.members if ccb else [])
            if member.role == "CCB approver" and member.user.active
        ]
        if not ccb_ids:
            abort(409, description=(
                tr("CCB membership must be configured before a non-standard change can be submitted.")
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
        executive_ids = sorted({
            member.user_id for member in (executive.members if executive and executive.active else [])
            if member.role == "executive approver" and member.user.active
        } | ({executive.manager_id} if executive and executive.active and executive.manager and executive.manager.active else set()))
        if not executive_ids:
            abort(409, description=(
                tr("Executive (CEO) approval authority must be configured (itil_admin's Executive approval section) before a non-standard change requiring CCB authorization can be submitted.")
            ))
        stages.append({
            "name": "Executive (CEO) approval",
            "mode": executive.approval_mode if executive.approval_mode in {"all", "any"} else "all",
            "approver_ids": executive_ids,
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
        raise ValueError(tr("Every approval stage must have at least one configured approver."))
    # Tenant of the record being approved, not the request context: a caller
    # without a logged-in user (API client, worker) would otherwise get tenant 1.
    target = record_reference(target_type, target_id)
    tenant_id = (record_tenant_id(target) if target else None) or tenant_context_id()
    chain = ApprovalChain(name=name, target_type=target_type, target_id=target_id, tenant_id=tenant_id)
    db.session.add(chain)
    db.session.flush()
    for sequence, stage in enumerate(stages, 1):
        gate = ApprovalGate(chain_id=chain.id, sequence=sequence, name=stage["name"],
                            mode=stage.get("mode", "all"), tenant_id=tenant_id)
        db.session.add(gate)
        db.session.flush()
        for approver_id in sorted(set(stage["approver_ids"])):
            db.session.add(ApprovalVote(gate_id=gate.id, approver_id=approver_id, tenant_id=tenant_id))
    db.session.flush()
    first_gate = ApprovalGate.query.filter_by(chain_id=chain.id, sequence=1).one()
    activate_gate(first_gate, notify_title=first_gate_title, notify_body=first_gate_body)
    set_target_state(target_type, target_id, "Awaiting Approval")
    log_history(
        target_type, target_id, "Approval requested",
        details=f"{name} started with {len(stages)} stage(s).",
    )
    return chain


def catalog_approval_stages(requested_for):
    """Build the governed catalog chain for the request beneficiary.

    The first approver is deliberately resolved once, at submission time, and
    persisted in ApprovalVote.  Later directory or org-chart changes therefore
    affect future requests without silently rewriting an in-flight decision.
    """
    manager = requested_for.manager if requested_for else None
    if (
        not manager
        or not manager.active
        or manager.tenant_id != requested_for.tenant_id
        or manager.id == requested_for.id
    ):
        raise ValueError(
            tr("An active, same-tenant line manager must be assigned to the requested-for user before an approval-required item can be submitted.")
        )

    fulfillment = SupportGroup.query.filter_by(
        tenant_id=requested_for.tenant_id, name="Service Desk", active=True
    ).first()
    fulfillment_approver_ids = sorted({
        member.user_id
        for member in fulfillment.members
        if member.user and member.user.active
        and member.user.tenant_id == requested_for.tenant_id
    }) if fulfillment else []
    if not fulfillment_approver_ids:
        raise ValueError(
            tr("At least one active, same-tenant Service Desk member must be configured for fulfillment authorization.")
        )
    return [
        {"name": "Line manager approval", "mode": "all", "approver_ids": [manager.id]},
        {"name": "Fulfillment authorization", "mode": "any",
         "approver_ids": fulfillment_approver_ids},
    ]


def decide_vote(vote, decision, comments):
    if vote.state != "Requested" or vote.gate.state != "Requested" or vote.gate.chain.state != "Running":
        abort(409, description=tr("This approval is no longer active."))
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
    # SLA definitions are tenant configuration: only the target record's own
    # tenant's definitions may ever apply to it.
    target_model = {"ticket": Ticket, "ritm": RequestedItem, "client_ticket": ClientTicket}.get(target_type)
    target = db.session.get(target_model, target_id) if target_model else None
    if target is None:
        current_app.logger.warning(
            "SLA attachment skipped: no %s record with id %s", target_type, target_id,
        )
        return
    definitions = SLADefinition.query.filter_by(
        target_type=target_type, active=True, tenant_id=target.tenant_id,
    ).all()
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
            paused = int((current - align_tz(task_sla.paused_at, current)).total_seconds())
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
    # BODY.PEEK[] leaves the message unread (a plain RFC822/BODY[] fetch marks
    # it \Seen on the server). It is marked read only once it has been saved,
    # or deliberately dropped below, so a failure in between is retried on the
    # next poll instead of being lost.
    status, msg_data = connection.fetch(msg_num, "(BODY.PEEK[])")
    if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
        return False
    raw_bytes = msg_data[0][1]
    parsed = parse_inbound_email(raw_bytes)
    if parsed["is_auto_generated"] or not parsed["from_email"]:
        _acknowledge_inbound_email(connection, msg_num)
        return False
    fingerprint = "serviceops-sha256:" + hashlib.sha256(raw_bytes).hexdigest()
    existing = ClientTicketMessage.query.join(ClientTicket).filter(
        ClientTicketMessage.tenant_id == mailbox.tenant_id,
        ClientTicket.mailbox_id == mailbox.id,
        ClientTicketMessage.message_id == (parsed["message_id"] or fingerprint),
    ).first()
    if existing:
        _acknowledge_inbound_email(connection, msg_num)
        return False
    # Last-resort loop/flood defense, on top of the Auto-Submitted check
    # above -- Zendesk documents an identical per-sender rate ceiling for
    # exactly this reason (a broken auto-responder loop that somehow
    # doesn't set Auto-Submitted correctly).
    if not route_rate_limit("inbound_email", parsed["from_email"], 20, window_seconds=3600):
        current_app.logger.warning("Inbound email rate limit exceeded for %s", parsed["from_email"])
        # A deliberate drop: left unread, a mail loop would refill the first
        # `limit` UNSEEN slots on every poll and starve legitimate mail.
        db.session.commit()
        _acknowledge_inbound_email(connection, msg_num)
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
        message_id=parsed["message_id"] or fingerprint, in_reply_to=parsed["in_reply_to"] or None,
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
    _acknowledge_inbound_email(connection, msg_num)
    return True


def _acknowledge_inbound_email(connection, msg_num):
    status, _ = connection.store(msg_num, "+FLAGS", "\\Seen")
    if status != "OK":
        raise RuntimeError("IMAP acknowledgement failed; the committed message will be deduplicated on retry.")


def _poll_client_mailbox(mailbox, limit=50):
    connection_cls = imaplib.IMAP4_SSL if mailbox.imap_use_ssl else imaplib.IMAP4
    with tunnel_through_proxy(resolve_smtp_proxy_url()):
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
    subject = single_line_header(ticket.subject)
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

    with tunnel_through_proxy(resolve_smtp_proxy_url()):
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
        raise ValueError(tr("This contact's personal data has already been erased."))
    if _has_active_legal_hold(contact.tenant_id, "client_contact", contact.id):
        raise ValueError(tr("This contact is under an active legal hold and cannot be erased."))
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
        func.coalesce(Ticket.resolved_at, Ticket.updated_at) >= thirty_days_ago, SLADefinition.agreement_type == "SLA",
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
            Ticket.state.in_(terminal_states), func.coalesce(Ticket.resolved_at, Ticket.updated_at) >= thirty_days_ago,
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


UPDATE_CHECK_INTERVAL_SECONDS = 86400  # once a day


def process_update_check_schedule():
    """Checks GitHub for a ServiceOps release newer than the one currently
    running, at most once a day (same PlatformSetting last-run-timestamp
    gate as process_performance_sample_schedule), and caches the result for
    latest_update_info() to read without making its own network call on
    every admin page view. Routed through the same outbound proxy
    configuration as notification channels (resolve_outbound_proxies()),
    since github.com may not be directly reachable in this deployment
    either. A failed check (network error, rate limit, proxy down) is
    logged and simply leaves the previous cached result in place -- it
    never raises into the worker loop over a routine, retriable GitHub
    reachability problem."""
    if not setting_bool("UPDATE_CHECK_ENABLED", True):
        return False
    state = db.session.get(PlatformSetting, "UPDATE_CHECK_LAST_RUN")
    current = now()
    if state and state.value:
        try:
            last_run = datetime.fromisoformat(state.value)
            if (current - align_tz(last_run, current)).total_seconds() < UPDATE_CHECK_INTERVAL_SECONDS:
                return False
        except (TypeError, ValueError):
            pass
    if not state:
        state = PlatformSetting(key="UPDATE_CHECK_LAST_RUN", tenant_id=1, encrypted=False)
        db.session.add(state)
    state.value = current.isoformat()
    try:
        response = requests.get(
            "https://api.github.com/repos/awijesundara/ServiceOps/releases/latest",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "ServiceOps-update-check"},
            proxies=resolve_component_proxies("UPDATE_CHECK"), timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        tag = str(data.get("tag_name", "")).strip().lstrip("v")
        url = str(data.get("html_url", "")).strip()
    except Exception as error:
        current_app.logger.info("Update check against GitHub did not complete: %s", type(error).__name__)
        tag, url = "", ""
    if tag:
        result = db.session.get(PlatformSetting, "UPDATE_CHECK_LATEST_VERSION")
        if not result:
            result = PlatformSetting(key="UPDATE_CHECK_LATEST_VERSION", tenant_id=1, encrypted=False)
            db.session.add(result)
        result.value = json.dumps({"version": tag, "url": url})
    db.session.commit()
    return True


def latest_update_info():
    """Returns {"version": "1.90.0", "url": "https://github.com/.../releases/tag/v1.90.0"}
    if the cached GitHub check (process_update_check_schedule) found a
    release newer than the version currently running, else None. A pure
    cache read -- never makes a network call itself, so pages that call
    this stay fast regardless of GitHub's reachability."""
    if not setting_bool("UPDATE_CHECK_ENABLED", True):
        return None
    row = db.session.get(PlatformSetting, "UPDATE_CHECK_LATEST_VERSION")
    if not row or not row.value:
        return None
    try:
        cached = json.loads(row.value)
        latest = str(cached.get("version", ""))
        latest_tuple = tuple(int(part) for part in latest.split("."))
        current_tuple = tuple(int(part) for part in APP_VERSION.split("."))
    except (TypeError, ValueError, AttributeError):
        return None
    if latest_tuple <= current_tuple:
        return None
    return {"version": latest, "url": cached.get("url", "")}


def google_chat_handle_command(command, args, record, actor):
    """Executes one slash command against `record` on behalf of `actor` (the
    ServiceOps user matched by the Chat message sender's email) and
    returns the reply text to post back into the thread. Reuses the exact
    transition/reassignment rules the web UI's ticket and enterprise-record
    detail pages already enforce (transition_ticket/transition_enterprise,
    ticket_owning_group) rather than a parallel, possibly-inconsistent
    implementation of the same business rules -- this dispatcher is just
    another caller of that same authorized path. An invalid transition
    raised by those functions (abort()/HTTPException) is caught here and
    its description reused as the reply, the same way the web route
    already surfaces it as a flash message."""
    target_type = "ticket" if isinstance(record, Ticket) else "enterprise"
    can_manage = (
        user_can_manage_ticket(actor, record)
        if target_type == "ticket"
        else user_can_manage_enterprise_record(actor, record)
    )
    required_actions = ("update", "assign", "transition")
    if not can_manage or any(
        not effective_role_has_action(actor.effective_role, action, tenant_id=record.tenant_id)
        for action in required_actions
    ):
        return f"You do not have permission to update {record.number}."
    try:
        if command == "ack":
            if record.assignee_id and record.assignee_id != actor.id:
                return f"{record.number} is already assigned to {record.assignee.name}."
            before = {
                "state": record.state,
                "assigned to": record.assignee.name if record.assignee else "Unassigned",
            }
            record.assignee_id = actor.id
            transitions = TICKET_TRANSITIONS if target_type == "ticket" else ENTERPRISE_TRANSITIONS
            if "In Progress" in transitions.get(record.state, ()):
                if target_type == "ticket":
                    transition_ticket(record, "In Progress")
                else:
                    transition_enterprise(record, "In Progress")
            log_field_changes(
                target_type, record.id, before,
                {"state": record.state, "assigned to": actor.name}, event="Acknowledged via Google Chat",
            )
            audit("update", record.number, f"Acknowledged by {actor.name} via Google Chat")
            return f"{record.number} acknowledged and assigned to {actor.name}."
        if command == "escalate":
            if not args:
                return "Usage: /escalate <team name>"
            group = SupportGroup.query.filter(
                func.lower(SupportGroup.name) == args.strip().lower(),
                SupportGroup.tenant_id == record.tenant_id, SupportGroup.active.is_(True),
            ).first()
            if not group:
                return f'No active team named "{args}" was found.'
            if target_type == "ticket":
                current_group = ticket_owning_group(record)
                if current_group and current_group.id == group.id:
                    return f"{record.number} is already owned by {group.name}."
                if record.kind == "change" and (not group.manager or not group.manager.active):
                    return f"{group.name} must have an active manager before it can own a change."
                if record.kind == "change":
                    record.change_ownership.group_id = group.id
                else:
                    assignment = TicketAssignmentGroup.query.filter_by(ticket_id=record.id).first()
                    if assignment:
                        assignment.group_id = group.id
                    else:
                        db.session.add(TicketAssignmentGroup(ticket_id=record.id, group_id=group.id))
                record.assignee_id = None
                log_history(
                    "ticket", record.id, "Reassigned to another team via Google Chat", "owning team",
                    current_group.name if current_group else "Unassigned", group.name, actor_id=actor.id,
                )
            else:
                if record.support_group_id == group.id:
                    return f"{record.number} is already owned by {group.name}."
                before_group = record.support_group.name if record.support_group else "Unassigned"
                record.support_group_id = group.id
                record.assignee_id = None
                log_history(
                    "enterprise", record.id, "Reassigned to another team via Google Chat", "owning team",
                    before_group, group.name, actor_id=actor.id,
                )
            audit("escalate", record.number, f"Escalated to {group.name} by {actor.name} via Google Chat")
            return f"{record.number} escalated to {group.name}."
    except HTTPException as error:
        return error.description or f"{record.number} could not be updated."
    return f'Unknown command "/{command}". Supported: /ack, /escalate <team name>.'


def process_google_chat_pubsub_schedule(max_messages=20):
    """Pulls pending Google Chat events from the configured Pub/Sub
    subscription (Chat API -> Configuration -> Connection settings ->
    Cloud Pub/Sub topic -- chosen specifically so nothing needs to be
    reachable from the internet; ServiceOps only ever calls outward to
    pubsub.googleapis.com, through the GOOGLE_CHAT_PROXY_MODE egress
    policy), dispatches any /command found in a
    threaded reply to the record its alert was sent about
    (ChatThreadLink), and acknowledges every pulled message either way --
    a message this deployment can't or won't act on (no matching thread,
    unrecognized sender, a plain non-command chat message) is still
    acknowledged, never left to redeliver forever."""
    if not setting_bool("GOOGLE_CHAT_APP_ENABLED", False):
        return 0
    project_id = setting_value("GOOGLE_CHAT_PROJECT_ID", "")
    subscription_id = setting_value("GOOGLE_CHAT_PUBSUB_SUBSCRIPTION", "")
    service_account_json = setting_value("GOOGLE_CHAT_SERVICE_ACCOUNT_JSON", "")
    expected_bot_name = setting_value("GOOGLE_CHAT_BOT_USER_NAME", "")
    if not re.fullmatch(r"users/[\w-]+", expected_bot_name or ""):
        return 0
    if not (project_id and subscription_id and service_account_json):
        return 0
    max_messages = max(1, min(int(max_messages), 20))
    subscription = f"projects/{project_id}/subscriptions/{subscription_id}"
    proxies = resolve_component_proxies("GOOGLE_CHAT")
    try:
        access_token = _google_service_account_access_token(
            service_account_json, {"https://www.googleapis.com/auth/pubsub"}, proxies,
        )
        response = requests.post(
            f"https://pubsub.googleapis.com/v1/{subscription}:pull",
            json={"maxMessages": max_messages},
            headers={"Authorization": f"Bearer {access_token}"},
            proxies=proxies, timeout=15,
        )
        response.raise_for_status()
        received = response.json().get("receivedMessages", []) or []
    except Exception:
        current_app.logger.exception("Could not pull Google Chat events from Pub/Sub")
        return 0
    if not received:
        return 0
    lease_ack_ids = [entry.get("ackId") for entry in received if entry.get("ackId")]
    # One reply can consume the full outbound timeout. Extend the lease for
    # the whole bounded batch before mutating anything so another worker does
    # not receive the same command while this worker is still handling it.
    try:
        lease_response = requests.post(
            f"https://pubsub.googleapis.com/v1/{subscription}:modifyAckDeadline",
            json={"ackIds": lease_ack_ids, "ackDeadlineSeconds": 300},
            headers={"Authorization": f"Bearer {access_token}"},
            proxies=proxies, timeout=15,
        )
        lease_response.raise_for_status()
    except Exception:
        current_app.logger.exception("Could not extend the Google Chat Pub/Sub acknowledgement deadline")
        return 0

    ack_ids = []
    for entry in received:
        chat_event, ack_id = decode_pubsub_message(entry)
        try:
            message_event = extract_message_event(chat_event, expected_bot_name)
            if not message_event:
                if ack_id:
                    ack_ids.append(ack_id)
                continue
            parsed = parse_command(message_event["text"])
            if not parsed:
                if ack_id:
                    ack_ids.append(ack_id)
                continue
            message_id = str((entry.get("message") or {}).get("messageId") or "").strip()
            if not message_id:
                current_app.logger.warning("Ignored Google Chat command without a Pub/Sub message ID")
                if ack_id:
                    ack_ids.append(ack_id)
                continue
            command, args = parsed
            link = ChatThreadLink.query.filter_by(thread_name=message_event["thread_name"]).first()
            if not link:
                if ack_id:
                    ack_ids.append(ack_id)
                continue
            receipt = GoogleChatCommandReceipt.query.filter_by(message_id=message_id).first()
            if not receipt:
                record = find_record_by_number(link.record_number, tenant_id=link.tenant_id)
                if not record:
                    if ack_id:
                        ack_ids.append(ack_id)
                    continue
                actor = User.query.filter(
                    func.lower(User.email) == message_event["sender_email"],
                    User.tenant_id == link.tenant_id, User.active.is_(True),
                ).first()
                reply = (
                    google_chat_handle_command(command, args, record, actor) if actor
                    else "Your Google account email doesn't match an active ServiceOps user, so this command was not run."
                )
                receipt = GoogleChatCommandReceipt(
                    message_id=message_id, connection_id=link.connection_id,
                    thread_name=link.thread_name, reply_text=reply,
                    tenant_id=link.tenant_id,
                )
                db.session.add(receipt)
                # Commit the record mutation and its idempotency receipt in
                # one transaction before making the external reply call.
                db.session.commit()
            if not receipt.replied_at:
                reply_message_id = "client-serviceops-" + hashlib.sha256(message_id.encode()).hexdigest()[:32]
                google_chat_post_message(
                    receipt.connection, receipt.reply_text,
                    thread_name=receipt.thread_name, message_id=reply_message_id,
                )
                receipt.replied_at = now()
                db.session.commit()
            if ack_id:
                ack_ids.append(ack_id)
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to process a Google Chat event")
    if ack_ids:
        try:
            ack_response = requests.post(
                f"https://pubsub.googleapis.com/v1/{subscription}:acknowledge",
                json={"ackIds": ack_ids},
                headers={"Authorization": f"Bearer {access_token}"},
                proxies=proxies, timeout=15,
            )
            ack_response.raise_for_status()
        except Exception:
            current_app.logger.exception("Could not acknowledge pulled Google Chat events")
    return len(received)


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
            if (
                state and state.last_run_at
                and current - align_tz(state.last_run_at, current) < interval
            ):
                continue
            if not state:
                state = KpiSnapshotState(tenant_id=tenant.id)
                db.session.add(state)
            capture_kpi_snapshots(tenant.id)
            state.last_run_at = current
            db.session.commit()
            processed += 1
        except Exception:  # noqa: BLE001 - one tenant's failure must never block others
            db.session.rollback()
            current_app.logger.exception("KPI snapshot capture failed for tenant %s", tenant.id)
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


def process_integration_sync_jobs(limit=1):
    """Recover ownerless jobs and run reconciliations under exclusive ownership."""
    from serviceops_core.integration_job_lock import integration_job_lock
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError(tr("The synchronization job limit must be between 1 and 100."))
    candidates = db.session.query(IntegrationSyncJob.id, IntegrationSyncJob.tenant_id,
                                  IntegrationSyncJob.integration).filter(
        IntegrationSyncJob.status.in_(["Running", "Pending"])
    ).order_by(IntegrationSyncJob.created_at, IntegrationSyncJob.id).limit(100).all()
    processed = 0
    for job_id, tenant_id, integration in candidates:
        if processed >= limit:
            break
        with integration_job_lock(db.engine, tenant_id, integration) as acquired:
            if not acquired:
                continue
            db.session.expire_all()
            job = db.session.get(IntegrationSyncJob, job_id)
            if not job or job.status not in ("Running", "Pending"):
                continue
            if job.status == "Running":
                job.status = "Cancelled" if job.cancel_requested else "Failed"
                job.phase = "Recovered after worker interruption"
                job.error = None if job.cancel_requested else "Worker ownership was lost; review and enqueue reconciliation again."
                job.finished_at = job.updated_at = now()
                current_app.logger.warning("Recovered abandoned integration job id=%s", job.id)
                audit("configure", "CMDB sync recovered", f"Job {job.id}; status={job.status}",
                      user_id=job.actor_user_id, tenant_id=job.tenant_id)
                db.session.commit()
            elif job.cancel_requested or not Tenant.query.filter_by(id=job.tenant_id, active=True).first():
                job.status = "Cancelled"
                job.phase = "Cancelled before execution"
                job.finished_at = job.updated_at = now()
                db.session.commit()
            else:
                _run_integration_sync_job(job, acquired)
            processed += 1
    return processed


def _run_integration_sync_job(job, assert_owned):
    job.status = "Running"
    job.phase = "Connecting"
    job.started_at = now()
    db.session.commit()
    path_processed = {}
    path_totals = {}

    def cancelled():
        assert_owned()
        with db.engine.connect() as connection:
            return bool(connection.execute(
                select(IntegrationSyncJob.cancel_requested).where(
                    IntegrationSyncJob.id == job.id
                )
            ).scalar())

    def progress(path, count, total):
        assert_owned()
        path_processed[path] = path_processed.get(path, 0) + count
        if isinstance(total, int):
            path_totals[path] = total
        values = {
            "phase": re.sub(r"^/api/(v1/)?", "", path).strip("/").replace("/", " / "),
            "processed": sum(path_processed.values()),
            "total": sum(path_totals.values()) if path_totals else None,
            "updated_at": now(),
        }
        # Separate transaction keeps progress observable without committing
        # a dry-run's in-memory reconciliation changes.
        with db.engine.begin() as connection:
            connection.execute(update(IntegrationSyncJob).where(
                IntegrationSyncJob.id == job.id
            ).values(**values))

    from serviceops_core.netbox_sync import NetboxSyncError, sync_from_netbox
    from serviceops_core.snipeit_sync import SnipeitSyncError, sync_from_snipeit
    runners = {
        "netbox": ("NetBox", sync_from_netbox, "NETBOX_SYNC_BATCH_SIZE"),
        "snipeit": ("Snipe-IT", sync_from_snipeit, "SNIPEIT_SYNC_BATCH_SIZE"),
    }
    label = runners.get(job.integration, (job.integration,))[0]
    try:
        if job.integration not in runners:
            raise RuntimeError("Unsupported integration job type")
        _, run_sync, batch_setting = runners[job.integration]
        result = run_sync(
            job.tenant_id, dry_run=job.dry_run,
            page_size=max(10, min(setting_int(batch_setting, 100), 500)),
            progress_callback=progress, cancel_check=cancelled,
        )
    except Exception as error:  # noqa: BLE001 - isolate external integration failure
        db.session.rollback()
        job = db.session.get(IntegrationSyncJob, job.id)
        if job.cancel_requested or "cancelled" in str(error).casefold():
            job.status = "Cancelled"
            job.phase = "Cancelled safely between batches"
            job.error = None
        else:
            job.status = "Failed"
            job.phase = "Failed"
            job.error = (str(error) if isinstance(error, (NetboxSyncError, SnipeitSyncError))
                         else f"{type(error).__name__}: {error}")[:800]
    else:
        db.session.expire_all()
        job = db.session.get(IntegrationSyncJob, job.id)
        job.status = "Completed"
        job.phase = "Completed"
        job.result_json = json.dumps(result)
    job.finished_at = now()
    job.updated_at = now()
    audit(
        "configure", f"{label} CMDB sync {job.status.casefold()}",
        f"Job {job.id}; processed={job.processed}; phase={job.phase}",
        user_id=job.actor_user_id, tenant_id=job.tenant_id,
    )
    db.session.commit()


def process_ldap_sync_schedule(limit=50):
    """Run the LDAP directory sync (serviceops_core.ldap_sync.sync_directory)
    for each active, LDAP-enabled tenant whose scheduled interval has
    elapsed. Tenant iteration is explicit and tenant-scoped: there is no
    global/default sync, matching the fail-closed tenant policy. One
    tenant's failure is caught and logged (no secrets) and never blocks or
    crashes the pass for other tenants."""
    if not setting_bool("LDAP_ENABLED") or not setting_bool("LDAP_SYNC_ENABLED"):
        return 0
    interval = timedelta(minutes=max(setting_int("LDAP_SYNC_INTERVAL_MINUTES", 60), 15))
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
                # A failed/bind-rejected directory is cooled down instead of
                # hammering AD every worker cycle. A later success restores
                # the normal cadence automatically.
                effective_interval = interval * (4 if state.last_status in ("error", "skipped") else 1)
                if comparison_now - last_run < effective_interval:
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


# The Change Control Board and Executive Office are approval bodies managed by
# their own governance controls, not teams that own or fulfil work.
GOVERNANCE_GROUP_NAMES = ("Change Control Board", "Executive Office")


def team_group_filter():
    """The single definition of a ServiceOps team: every active group in the
    tenant except the governance bodies, whatever its team type. Every team
    picker and its server-side check uses this, so a newly created team is
    selectable everywhere. Team type still decides access (see
    visible_ticket_query), never whether a team is listed."""
    return db.and_(
        SupportGroup.active.is_(True),
        SupportGroup.group_type != "CCB Approval",
        SupportGroup.name.notin_(GOVERNANCE_GROUP_NAMES),
    )


def team_groups(tenant_id=None):
    """All teams for the tenant (the current tenant context by default), by name."""
    return SupportGroup.query.filter(
        SupportGroup.tenant_id == (tenant_id if tenant_id is not None else tenant_context_id()),
        team_group_filter(),
    ).order_by(SupportGroup.name)


def is_team_group(group, tenant_id=None):
    return bool(
        group
        and group.active
        and group.group_type != "CCB Approval"
        and group.name not in GOVERNANCE_GROUP_NAMES
        and (tenant_id is None or group.tenant_id == tenant_id)
    )


def client_sysops_group(tenant_id):
    return SupportGroup.query.filter(
        SupportGroup.tenant_id == tenant_id,
        SupportGroup.group_type == "Client Support",
        SupportGroup.active.is_(True),
    ).order_by(SupportGroup.id).first()


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


def visible_knowledge_query(user):
    """Never-published drafts (the AI assistant drafts these from incidents)
    are for agents and above to review and publish; requesters only ever see
    published articles and archived versions. Scoped by the user's own tenant
    so it's also correct for bearer-token callers, which have no logged-in
    current_user for tenant_query() to resolve."""
    query = Knowledge.query.filter(Knowledge.tenant_id == user.tenant_id)
    if role_at_least(user.effective_role, "agent"):
        return query
    return query.filter(db.or_(Knowledge.published.is_(True), Knowledge.archived.is_(True)))


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
            tr("{name} has no active fulfillment route and no active Service Desk fallback.", name=ritm.item.name)
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
        SupportGroup.group_type == "Client Support",
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
                tenant_id=admin.tenant_id,
                name="Laptop Request", category="Hardware",
                description="Request a standard-issue laptop for a new or replacement device.",
                delivery_days=5, approval_required=True,
            ),
            CatalogItem(
                tenant_id=admin.tenant_id,
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
            SLADefinition(name="P1 incident response", target_type="ticket", priority="P1", duration_minutes=15, tenant_id=admin.tenant_id),
            SLADefinition(name="P1 incident resolution", target_type="ticket", priority="P1", duration_minutes=240, tenant_id=admin.tenant_id),
            SLADefinition(name="P2 incident resolution", target_type="ticket", priority="P2", duration_minutes=480, tenant_id=admin.tenant_id),
            SLADefinition(name="P3 incident resolution", target_type="ticket", priority="P3", duration_minutes=1440, tenant_id=admin.tenant_id),
            SLADefinition(name="Catalog fulfillment", target_type="ritm", duration_minutes=4320, tenant_id=admin.tenant_id),
        ])
    # The ITIL category model, seeded only for a tenant with no categories yet
    # (tests, a new tenant, `./serviceops install`, which build the schema from
    # the ORM rather than replaying migrations). This runs on every startup, so
    # seeding into a tenant that already has a tree would re-create entries an
    # administrator renamed or removed. Deployed tenants were aligned by
    # migration 20260927_0106 instead.
    if not TicketCategory.query.filter_by(tenant_id=admin.tenant_id).first():
        for category_name, subcategory_names in TICKET_CATEGORY_TAXONOMY.items():
            category = TicketCategory(name=category_name, active=True, tenant_id=admin.tenant_id)
            db.session.add(category)
            db.session.flush()
            for subcategory_name in subcategory_names:
                db.session.add(TicketSubcategory(
                    category_id=category.id, name=subcategory_name, active=True, tenant_id=admin.tenant_id,
                ))


def bootstrap_ipfs_tenant_and_admin():
    """Minimal STORAGE_MODE=ipfs equivalent of seed()'s bootstrap-admin
    path (BACKLOG B-335, login-only milestone) -- creates a default
    tenant and administrator directly in IPFSStorageBackend if none
    exists yet. Does not call seed_itil()/deploy_workflow_package(): those
    create dozens of Postgres-only entities (support groups, catalog
    items, workflow definitions, ...) this storage backend doesn't
    implement. A fresh IPFS-mode instance only has login working; there
    is deliberately no catalog/workflow/CMDB seed data yet."""
    storage = current_storage()
    if storage.query("tenant", tenant_id=None):
        return
    admin_password = secret_value("ADMIN_PASSWORD")
    if not admin_password:
        raise RuntimeError("ADMIN_PASSWORD is required to bootstrap the first administrator.")
    if len(admin_password) < 14:
        raise RuntimeError("ADMIN_PASSWORD must contain at least 14 characters.")
    storage.create("tenant", slug=os.getenv("DEFAULT_TENANT_SLUG", "default"),
                    name=os.getenv("DEFAULT_TENANT_NAME", "Default organisation"))
    storage.create(
        "user", username="admin", name="System Administrator", email="admin@example.local",
        password_hash=hash_password(admin_password), role="admin", tenant_id=1,
        active=True, auth_version=1, failed_login_count=0, mfa_enabled=False,
        title="", department="", business_phone="", mobile_phone="", location="",
        timezone="Asia/Tokyo", date_format="system", calendar_integration="None",
    )


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


def sync_directory_team_memberships(user, groups, declared_team=None):
    """Synchronize only memberships owned by directory automation.

    Explicit AD-group mappings remain authoritative.  When the separately
    controlled LDAP_AUTO_CREATE_TEAMS setting is enabled, a bounded
    teamName-style profile attribute may also create/reuse one canonical IT
    Fulfillment team.  We never turn every memberOf value into a ServiceOps
    team: application/security groups are not operational support teams.
    """
    aliases = normalized_directory_groups(groups)
    mappings = DirectoryGroupMapping.query.join(SupportGroup).filter(
        DirectoryGroupMapping.active.is_(True),
        SupportGroup.tenant_id == user.tenant_id,
    ).all()
    desired = {
        mapping.support_group_id: mapping.directory_group
        for mapping in mappings
        if mapping.directory_group.strip().casefold() in aliases
    }
    created_team = None
    team_name = str(declared_team or "").strip()[:120]
    if team_name and setting_bool("LDAP_AUTO_CREATE_TEAMS", False):
        group = SupportGroup.query.filter(
            SupportGroup.tenant_id == user.tenant_id,
            func.lower(SupportGroup.name) == team_name.casefold(),
        ).first()
        if not group:
            group_alias = SupportGroupAlias.query.filter(
                SupportGroupAlias.tenant_id == user.tenant_id,
                func.lower(SupportGroupAlias.alias) == team_name.casefold(),
            ).first()
            group = group_alias.group if group_alias else None
        if not group:
            group = SupportGroup(
                name=team_name, group_type="IT Fulfillment", active=True,
                tenant_id=user.tenant_id,
            )
            db.session.add(group)
            db.session.flush()
            created_team = group
        desired[group.id] = f"profile-team:{team_name}"
    existing = {
        membership.group_id: membership
        for membership in DirectoryManagedMembership.query.filter_by(
            user_id=user.id, tenant_id=user.tenant_id
        ).all()
    }
    for group_id, managed in existing.items():
        if group_id in desired:
            managed.directory_group = desired[group_id]
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
                user_id=user.id, group_id=group_id, directory_group=mapping,
                tenant_id=user.tenant_id,
            ))
    audit(
        "directory group sync", user.username,
        ", ".join(sorted(
            db.session.get(SupportGroup, group_id).name for group_id in desired
            if db.session.get(SupportGroup, group_id)
        ))
        or "No mapped teams",
        user_id=user.id,
    )
    return created_team


def reconcile_directory_team_managers(user):
    """Infer an unassigned auto-created team's manager from its org chart.

    Assignment happens only when every active, directory-managed team member
    with a manager points to the same active same-tenant person. Ambiguity is
    left for an administrator; an existing explicit manager is never replaced.
    """
    assigned = 0
    managed_rows = DirectoryManagedMembership.query.filter_by(
        user_id=user.id, tenant_id=user.tenant_id
    ).all()
    for managed in managed_rows:
        if not managed.directory_group.startswith("profile-team:"):
            continue
        group = db.session.get(SupportGroup, managed.group_id)
        if not group or group.manager_id or not group.active:
            continue
        member_users = [member.user for member in group.members if member.user and member.user.active]
        manager_ids = {
            member.manager_id for member in member_users
            if member.manager and member.manager.active
            and member.manager.tenant_id == group.tenant_id
        }
        if len(manager_ids) != 1:
            continue
        manager = db.session.get(User, manager_ids.pop())
        group.manager_id = manager.id
        membership = GroupMember.query.filter_by(group_id=group.id, user_id=manager.id).first()
        if membership:
            membership.role = "manager"
        else:
            db.session.add(GroupMember(
                group_id=group.id, user_id=manager.id, role="manager",
                tenant_id=group.tenant_id,
            ))
        sync_implied_role_grants(manager)
        audit(
            "directory team manager", group.name,
            f"Inferred from consistent reporting line: {manager.username}",
            user_id=manager.id, tenant_id=group.tenant_id,
        )
        assigned += 1
    return assigned


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
    manages_team = SupportGroup.query.filter_by(
        manager_id=user.id, active=True, tenant_id=user.tenant_id,
    ).first()
    has_direct_report = User.query.filter_by(
        manager_id=user.id, active=True, tenant_id=user.tenant_id,
    ).first()
    if manages_team or has_direct_report:
        desired.add("manager")
    if GroupMember.query.join(
        SupportGroup, GroupMember.group_id == SupportGroup.id
    ).filter(
        GroupMember.user_id == user.id,
        SupportGroup.active.is_(True),
    ).first():
        desired.add("agent")
    sync_role_grants(user, "team_responsibility", desired)
    # Access levels a group grants to every member (set on the group itself).
    group_roles = {}
    for group in SupportGroup.query.join(GroupMember, GroupMember.group_id == SupportGroup.id).filter(
        GroupMember.user_id == user.id, SupportGroup.active.is_(True),
        SupportGroup.tenant_id == user.tenant_id, SupportGroup.access_roles != "",
    ):
        for role in group_access_roles(group):
            group_roles.setdefault(role, group.name)
    sync_role_grants(user, "group", group_roles, detail_by_role=group_roles)


def record_group_rename(group, old_name):
    """Keep a renamed group findable by its old name (CSV imports, free-text
    team names) through an alias, and record the rename."""
    alias = SupportGroupAlias.query.filter(
        SupportGroupAlias.tenant_id == group.tenant_id,
        func.lower(SupportGroupAlias.alias) == old_name.casefold(),
    ).first()
    if alias and alias.group_id != group.id:
        abort(409, description=tr("The old group name is already an alias of another team."))
    if not alias:
        db.session.add(SupportGroupAlias(alias=old_name, group_id=group.id, tenant_id=group.tenant_id))
    audit("team renamed", f"support_group:{group.id}", f"{old_name} → {group.name}")


def group_access_roles(group):
    """The access levels a group grants its members. Platform administrator
    is never granted through a group."""
    from serviceops_core.ldap_access import ACCESS_LEVELS
    return [role for role in (group.access_roles or "").split(",") if role in ACCESS_LEVELS]


def user_is_local(user):
    """True if `user` authenticates with a local ServiceOps password rather
    than an external identity provider (LDAP, SSO). Externally-provisioned
    users have no usable local password -- provision_external_user() sets
    password_hash to a random, never-communicated value -- so the in-app
    change-password flow must only be offered to local accounts."""
    if user is None or not getattr(user, "id", None):
        return False
    return ExternalIdentity.query.filter_by(user_id=user.id).first() is None


def describe_user_agent(user_agent):
    """Return a compact, non-fingerprinting browser/OS label for session UI."""
    value = str(user_agent or "")
    browser = "Browser"
    for marker, label in (
        ("Edg/", "Microsoft Edge"), ("OPR/", "Opera"),
        ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
    ):
        if marker in value:
            browser = label
            break
    operating_system = "Unknown OS"
    for marker, label in (
        ("Windows", "Windows"), ("Android", "Android"),
        ("iPhone", "iOS"), ("iPad", "iPadOS"),
        ("Mac OS X", "macOS"), ("Linux", "Linux"),
    ):
        if marker in value:
            operating_system = label
            break
    return f"{browser} on {operating_system}"[:160]


def verified_client_hostname(address):
    """Best-effort forward-confirmed reverse DNS, never a trusted identity.

    Disabled by default because some sites do not want DNS lookups on web
    requests. When enabled, a PTR name is retained only when resolving it
    forward includes the same source address, preventing an arbitrary PTR
    record from being presented as verified endpoint metadata.
    """
    if not address or not setting_bool("CLIENT_HOSTNAME_LOOKUP", False):
        return None
    hostname = resolve_hostname(address)
    if not hostname:
        return None
    try:
        normalized = str(ipaddress.ip_address(address))
        resolved = {str(ipaddress.ip_address(item)) for item in resolve_ip(hostname)}
    except ValueError:
        return None
    return hostname[:255] if normalized in resolved else None


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


def apply_directory_profile(user, profile, group_names=None):
    """Persist only the normalized LDAP snapshot produced by ldap_sync.

    This is intentionally separate from User columns: it gives self-service
    and administrators richer directory context without letting opaque AD
    blobs leak into the database or become authorization inputs.
    """
    if not user or not isinstance(profile, dict):
        return None
    row = DirectoryProfile.query.filter_by(user_id=user.id).first()
    if not row:
        row = DirectoryProfile(user_id=user.id, tenant_id=user.tenant_id)
        db.session.add(row)
    row.profile_json = json.dumps(profile, sort_keys=True)
    row.groups_json = json.dumps(sorted(set(group_names or []), key=str.casefold))
    row.synchronized_at = now()
    return row


def find_external_identity(provider, subject):
    """Return an existing external identity using provider-correct equality.

    LDAP distinguished names are not stable byte strings: equivalent DNs can
    be returned with different character casing (including between the user's
    login search and the manager base-object lookup).  Treating them as exact,
    case-sensitive subjects can create a second placeholder user and make a
    reporting relationship appear to flap.  Other identity providers keep
    exact subject matching because their subject identifiers are opaque.
    """
    provider = str(provider or "").strip()
    subject = str(subject or "").strip()
    if not provider or not subject:
        return None
    query = ExternalIdentity.query.filter_by(provider=provider)
    if provider.casefold() == "ldap":
        return query.filter(
            db.func.lower(db.func.trim(ExternalIdentity.subject)) == subject.casefold()
        ).first()
    return query.filter_by(subject=subject).first()


def provision_external_user(
    provider, subject, username, name, email, matched_roles, groups=None,
    profile_attrs=None, directory_profile=None, directory_group_names=None,
):
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

    identity = find_external_identity(provider, subject)
    if identity:
        user = identity.user
        user.name, user.email = name, email
        # Deliberately does NOT force user.active = True here: an
        # administrator deactivating a directory-linked account is an
        # explicit access decision (the platform manual promises
        # "re-enablement remains an explicit administrative decision"),
        # and a successful directory bind must not silently override it.
        # A brand-new account (below) still defaults active via the User
        # model's own column default.
        apply_external_profile_attrs(user, profile_attrs)
        if provider == "ldap" and directory_profile is not None:
            apply_directory_profile(user, directory_profile, directory_group_names)
        sync_role_grants(user, "directory", matched_roles, detail_by_role=matched_roles)
        if provider == "ldap":
            sync_directory_team_memberships(
                user, groups, declared_team=(profile_attrs or {}).get("team_name")
            )
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
        # Same reasoning as the returning-identity branch above: don't
        # override an administrator's explicit deactivation just because
        # this local account is being linked to a directory identity.
        apply_external_profile_attrs(existing_user, profile_attrs)
        if provider == "ldap" and directory_profile is not None:
            apply_directory_profile(existing_user, directory_profile, directory_group_names)
        db.session.add(ExternalIdentity(provider=provider, subject=subject, user_id=existing_user.id))
        sync_role_grants(existing_user, "directory", matched_roles, detail_by_role=matched_roles)
        if provider == "ldap":
            sync_directory_team_memberships(
                existing_user, groups, declared_team=(profile_attrs or {}).get("team_name")
            )
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
    if provider == "ldap" and directory_profile is not None:
        apply_directory_profile(user, directory_profile, directory_group_names)
    db.session.add(ExternalIdentity(provider=provider, subject=subject, user_id=user.id))
    sync_role_grants(user, "directory", matched_roles, detail_by_role=matched_roles)
    if provider == "ldap":
        sync_directory_team_memberships(
            user, groups, declared_team=(profile_attrs or {}).get("team_name")
        )
        sync_implied_role_grants(user)
    return user


class LdapBindError(RuntimeError):
    """Raised when a service-account LDAP bind cannot be established."""


def ldap_server_and_service_connection():
    """Build the ldap3 Server plus a bound service-account Connection, shared by
    interactive login (ldap_authenticate) and the directory sync job. Raises
    LdapBindError rather than returning a half-usable connection so callers
    never mistake a failed bind for "no directory configured"."""
    from serviceops_core.ldap_access import server_uris
    uris = server_uris(setting_value("LDAP_SERVER_URI", ""))
    if not uris:
        raise LdapBindError("LDAP_SERVER_URI is not configured.")
    use_ssl = uris[0].lower().startswith("ldaps://")
    if any(uri.lower().startswith("ldaps://") != use_ssl for uri in uris):
        raise LdapBindError("Every LDAP server URI must use the same scheme (ldap:// or ldaps://).")
    validate = ssl.CERT_REQUIRED if setting_bool("LDAP_VALIDATE_CERT", True) else ssl.CERT_NONE
    tls = Tls(validate=validate, ca_certs_file=os.getenv("LDAP_CA_CERT") or None)
    servers = []
    for uri in uris:
        address = uri.split("://", 1)[-1].split("/", 1)[0]
        host, _, explicit_port = address.partition(":")
        port = int(explicit_port or os.getenv("LDAP_PORT", "636" if use_ssl else "389"))
        servers.append(Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL,
                              connect_timeout=int(os.getenv("LDAP_TIMEOUT", "8"))))
    # Several servers fail over in the order listed; a server that does not
    # answer is skipped until it recovers.
    server = servers[0] if len(servers) == 1 else ServerPool(servers, FIRST, active=1, exhaust=60)
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
        previous_manager = db.session.get(User, user.manager_id) if user.manager_id else None
        manager_identity = find_external_identity("ldap", manager_dn)
        manager_user = manager_identity.user if manager_identity else None

        if not manager_user:
            _server, service = ldap_server_and_service_connection()
            try:
                if not service.search(
                    search_base=manager_dn,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=sorted(set(merged_attr_map.values()) | {
                        merged_attr_map.get("username", "sAMAccountName"),
                        merged_attr_map.get("display_name", "displayName"),
                        merged_attr_map.get("email", "mail"),
                        "memberOf",
                    }),
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
            from serviceops_core.ldap_sync import (
                PROFILE_FIELDS, directory_profile_payload,
            )
            for field in PROFILE_FIELDS:
                ldap_attr = merged_attr_map.get(field)
                if not ldap_attr:
                    continue
                val = first(ldap_attr, "")
                if val:
                    manager_profile_attrs[field] = val
            manager_directory_profile, manager_group_names = directory_profile_payload(
                values, manager_groups, merged_attr_map, manager_dn
            )
            manager_profile_attrs["team_name"] = manager_directory_profile.get("team_name")
            manager_user = provision_external_user(
                "ldap",
                manager_dn,
                manager_username,
                first(merged_attr_map.get("display_name", "displayName"), manager_username),
                first(merged_attr_map.get("email", "mail"), ""),
                manager_roles,
                groups=manager_groups,
                profile_attrs=manager_profile_attrs,
                directory_profile=manager_directory_profile,
                directory_group_names=manager_group_names,
            )

        if manager_user and manager_user.id != user.id and manager_user.tenant_id == user.tenant_id:
            if user.manager_id != manager_user.id:
                user.manager_id = manager_user.id
            sync_implied_role_grants(manager_user)
            reconcile_directory_team_managers(user)
            if previous_manager and previous_manager.id != manager_user.id:
                sync_implied_role_grants(previous_manager)
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


_cloudflare_access_jwks_cache = {"fetched_at": 0.0, "key_set": None}
_cloudflare_access_jwks_lock = threading.Lock()


def _cloudflare_access_key_set():
    """Fetches (and caches for 1 hour, per worker process) Cloudflare
    Access's RS256 public keys for this team as a joserfc KeySet.

    Guarded by a lock so that several request-handling threads (gunicorn's
    gthread worker class) racing in at the moment the cache expires don't
    each independently fire a redundant fetch against Cloudflare -- the
    lock is held only around the check-refresh, never across a verified
    JWT's own signature check."""
    with _cloudflare_access_jwks_lock:
        if time_module.monotonic() - _cloudflare_access_jwks_cache["fetched_at"] < 3600 and _cloudflare_access_jwks_cache["key_set"] is not None:
            return _cloudflare_access_jwks_cache["key_set"]
        team_domain = current_app.config["CLOUDFLARE_ACCESS_TEAM_DOMAIN"]
        response = requests.get(f"https://{team_domain}/cdn-cgi/access/certs", timeout=5,
                                proxies=resolve_component_proxies("CLOUDFLARE_ACCESS"))
        response.raise_for_status()
        key_set = KeySet.import_key_set(response.json())
        _cloudflare_access_jwks_cache["key_set"] = key_set
        _cloudflare_access_jwks_cache["fetched_at"] = time_module.monotonic()
        return key_set


def verify_cloudflare_access_jwt(token):
    """Verifies a Cloudflare Access-issued JWT (the Cf-Access-Jwt-Assertion
    header Access forwards to the origin once a request has passed the edge)
    against this team's public keys: signature, audience, and expiry.
    Returns the verified claims dict on success, None on any failure --
    never raises, since a missing/invalid header must fall back to the
    existing local/LDAP/Keycloak login form, not error out."""
    team_domain = current_app.config["CLOUDFLARE_ACCESS_TEAM_DOMAIN"]
    aud = current_app.config["CLOUDFLARE_ACCESS_AUD"]
    if not team_domain or not aud or not token:
        return None
    try:
        key_set = _cloudflare_access_key_set()
        decoded = jwt.decode(token, key_set, algorithms=["RS256"])
        claims_registry = JWTClaimsRegistry(aud={"essential": True, "value": aud})
        claims_registry.validate(decoded.claims)
        return decoded.claims
    except Exception:
        current_app.logger.info("Cloudflare Access JWT verification failed", exc_info=True)
        return None


def ldap_authenticate(username, password):
    if not password or not setting_bool("LDAP_ENABLED"):
        return None
    try:
        server, service = ldap_server_and_service_connection()
    except LdapBindError:
        return None
    use_ssl = setting_value("LDAP_SERVER_URI", "").strip().lower().startswith("ldaps://")
    filter_template = setting_value(
        "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
    )
    base_dn = setting_value("LDAP_BASE_DN", "")
    try:
        ldap_attr_map = json.loads(setting_value("LDAP_ATTR_MAP", "{}"))
    except (TypeError, json.JSONDecodeError):
        ldap_attr_map = {}
    from serviceops_core.ldap_sync import (
        DEFAULT_ATTR_MAP, PROFILE_FIELDS, directory_profile_payload,
    )
    attr_names = {
        "distinguishedName", "cn", "displayName", "mail", "memberOf", "userPrincipalName"
    }
    attr_names.update(DEFAULT_ATTR_MAP.values())
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
    if len(entries) != 1:
        service.unbind()
        return None
    entry = entries[0]
    from serviceops_core.ldap_access import resolve_groups, sign_in_allowed
    try:
        groups = resolve_groups(
            service, entry.entry_dn, ldap_login_local_part(username),
            entry.entry_attributes_as_dict.get("memberOf", []),
        )
    finally:
        service.unbind()
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
    if not sign_in_allowed(groups):
        # Checked only after the password bind succeeds, so the refusal never
        # reveals whether an account exists or is merely outside the mapped groups.
        # The caller records the failed sign-in in the audit log.
        current_app.logger.info("LDAP sign-in refused: user is not in a mapped access group.")
        return None
    matched_roles = mapped_roles(groups, "LDAP_ROLE_MAPPINGS")
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
    directory_profile, directory_group_names = directory_profile_payload(
        values, groups, merged_attr_map, entry.entry_dn
    )
    profile_attrs["team_name"] = directory_profile.get("team_name")
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
        directory_profile=directory_profile,
        directory_group_names=directory_group_names,
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
            payload["exception"] = redact("".join(traceback_module.format_exception(*record.exc_info)))
        return json.dumps(payload, default=str)


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
    from serviceops_core.web.common import usertime_filter
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
        CLOUDFLARE_ACCESS_TEAM_DOMAIN=os.getenv("CLOUDFLARE_ACCESS_TEAM_DOMAIN", ""),
        CLOUDFLARE_ACCESS_AUD=os.getenv("CLOUDFLARE_ACCESS_AUD", ""),
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
    if app.config["STORAGE_MODE"] == "ipfs":
        # IPFS is the sole durable store. SQLAlchemy is retained as the
        # application's domain/query engine over one process-local,
        # volatile projection rebuilt from the encrypted IPFS checkpoint.
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite+pysqlite://"
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "poolclass": StaticPool,
            "connect_args": {"check_same_thread": False},
        }
    elif app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres"):
        # Without pool_pre_ping, a connection the database (or an
        # in-between pooler/load balancer) has silently closed -- after an
        # idle timeout, a failover, or a routine network blip -- surfaces to
        # the *next* request as an unhandled OperationalError instead of
        # being transparently replaced, which previously meant an
        # otherwise-healthy pod could start 500ing until its pool happened
        # to cycle. pool_recycle proactively retires connections before
        # they're likely to hit such a server-side idle timeout. Pool sizing
        # is set to comfortably cover this process's own concurrency (2
        # gthread workers x 4 threads = 8 threads that can hold a
        # connection at once; see tools/gunicorn-entrypoint.sh).
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_pre_ping": True,
            "pool_recycle": int(os.getenv("DB_POOL_RECYCLE_SECONDS", "1800")),
            "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
            "max_overflow": int(os.getenv("DB_POOL_MAX_OVERFLOW", "10")),
        }
    if app.config["TESTING"]:
        if not test_config or "CSRF_ENABLED" not in test_config:
            app.config["CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or "test-only-secret"
        app.config["BOOTSTRAP_ADMIN_PASSWORD"] = app.config.get(
            "BOOTSTRAP_ADMIN_PASSWORD", "Admin123!"
        )
    elif not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY is required and must contain at least 32 characters.")
    else:
        # Both fall back to SECRET_KEY, so rotating it would silently invalidate every
        # API token and break audit-chain verification. Setting each to the current
        # SECRET_KEY value decouples them without invalidating anything.
        for name, consequence in (
            ("API_TOKEN_PEPPER", "every API token"),
            ("AUDIT_INTEGRITY_KEY", "audit-log integrity verification"),
        ):
            if not secret_value(name) and not (name == "AUDIT_INTEGRITY_KEY" and os.getenv("SETTINGS_ENCRYPTION_KEY")):
                app.logger.warning(
                    "%s is not set and falls back to SECRET_KEY; rotating SECRET_KEY would break %s. "
                    "Set %s to the current SECRET_KEY value to decouple them.", name, consequence, name,
                )
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
        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres"):
            from serviceops_core.database_pool import install_process_guard
            install_process_guard(db.engine)
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        # Optional database-less deployment mode (STORAGE_MODE=ipfs): this
        # milestone (BACKLOG B-335) covers file attachments plus login --
        # every other entity (tickets, CMDB, catalog, workflows, ...)
        # still requires PostgreSQL, that migration happens in later
        # rollout waves per the storage-mode plan. PostgreSQL-mode
        # deployments (the default) are unaffected: build_storage_backend()
        # returns PostgresStorageBackend, which replicates today's
        # local-disk/S3 attachment behavior with no change, and the whole
        # Alembic/seed() branch below runs exactly as it always has.
        app.extensions["storage_backend"] = build_storage_backend(
            upload_folder=app.config["UPLOAD_FOLDER"],
            object_storage_client_factory=object_storage_client,
            object_storage_bucket=os.getenv("OBJECT_STORAGE_BUCKET", "").strip() or None,
        )
        if ipfs_enabled():
            from serviceops_core.storage.ipfs_projection import IPFSRelationalProjection
            db.create_all()
            projection = IPFSRelationalProjection(db, current_storage())
            restored = projection.restore()
            if not restored:
                projection.import_legacy_identity()
            projection.install_commit_tracking()
            app.extensions["ipfs_projection"] = projection
            # The normal seed is intentionally used: catalog, workflow,
            # service-delivery, CMDB, and administration defaults therefore
            # exist in IPFS mode exactly as they do in PostgreSQL mode.
            seed()
            projection.checkpoint_if_dirty(force=True)
            app.config["LOCAL_AUTH_ENABLED"] = setting_bool("LOCAL_AUTH_ENABLED", True)
            app.config["LDAP_ENABLED"] = setting_bool("LDAP_ENABLED")
            app.config["KEYCLOAK_ENABLED"] = setting_bool("KEYCLOAK_ENABLED")
            app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
            app.config["MAX_FORM_MEMORY_SIZE"] = app.config["MAX_CONTENT_LENGTH"]
        else:
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

    def csrf_token():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    @app.before_request
    def serialize_ipfs_projection_access():
        if ipfs_enabled():
            app.extensions["ipfs_projection"]._lock.acquire()
            g._ipfs_projection_lock_held = True

    @app.teardown_request
    def release_ipfs_projection_access(_error):
        if g.get("_ipfs_projection_lock_held"):
            # Return the sole StaticPool connection before another request,
            # the checkpoint thread, or the integrated worker can acquire it.
            db.session.remove()
            app.extensions["ipfs_projection"]._lock.release()
            g._ipfs_projection_lock_held = False

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
                client_hostname=verified_client_hostname(request.remote_addr),
                device_label=describe_user_agent(request.headers.get("User-Agent", "")),
                client_language=request.headers.get("Accept-Language", "")[:120],
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
                "api_openapi", "api_docs", "monitoring_ingest", "monitoring_backup_report",
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
                tr("The security token is missing or expired. Refresh the page and try again.")
            ))
        return None

    @app.before_request
    def verify_session_version():
        if current_user.is_authenticated and (
            session.get("_auth_version") != current_user.auth_version
            # A deactivated account must lose access on its very next
            # request, not merely at its next fresh login -- otherwise an
            # administrator "deactivating" a user with a live session
            # (e.g. emergency access removal) has no actual effect until
            # that session happens to expire on its own.
            or not account_usable(current_user)
        ):
            logout_user()
            session.clear()
            if request.path.startswith("/api/"):
                abort(401, description=tr("The authenticated session is no longer valid."))
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
        # Some paths carry a secret (a password-recovery token); never log it.
        logged_path = redact(request.path)
        logging.getLogger("serviceops.request").info(
            "%s %s -> %s", request.method, logged_path, response.status_code,
            extra={
                "request_id": g.get("request_id"),
                "trace_id": g.get("trace_id"),
                "method": request.method,
                "path": logged_path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "user_id": current_user.id if current_user.is_authenticated else None,
                "tenant_id": current_user.tenant_id if current_user.is_authenticated else None,
                "remote_addr": request.remote_addr,
            },
        )
        return response

    def rollback_failed_request():
        try:
            db.session.rollback()
        except Exception:
            report_diagnostic_failure("ServiceOps failed-request rollback failed; discarding session.")
            try:
                db.session.remove()
            except Exception:
                report_diagnostic_failure("ServiceOps failed-request session cleanup failed.")

    @app.errorhandler(RequestEntityTooLarge)
    def request_entity_too_large(error):
        rollback_failed_request()
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
        rollback_failed_request()
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
        rollback_failed_request()
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
        rollback_failed_request()
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
    app.template_filter("usertime")(usertime_filter)

    @app.template_filter("from_json")
    def from_json_filter(value):
        try:
            parsed = json.loads(value or "{}")
        except (TypeError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

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

    def mentions_html(body):
        """Escapes comment body text (user input) then wraps each
        "@username" token in a highlight span -- built by manually escaping
        each plain-text segment and only ever concatenating already-escaped
        pieces, so this can't become an XSS vector through a comment body
        containing HTML-looking text."""
        pieces = []
        last_end = 0
        for match in MENTION_PATTERN.finditer(body):
            pieces.append(escape(body[last_end:match.start()]))
            pieces.append(Markup(f'<span class="mention">@{escape(match.group(1))}</span>'))
            last_end = match.end()
        pieces.append(escape(body[last_end:]))
        return Markup("").join(pieces)

    app.jinja_env.globals["mentions_html"] = mentions_html

    def ai_note_html(body):
        from serviceops_core.ai_note import render_ai_note
        return render_ai_note(body, mentions_html)

    app.jinja_env.globals["ai_note_html"] = ai_note_html
    app.jinja_env.globals["user_avatar"] = user_avatar_html
    app.jinja_env.globals["PREVIEWABLE_ATTACHMENT_TYPES"] = PREVIEWABLE_ATTACHMENT_TYPES
    app.jinja_env.globals["IMAGE_ATTACHMENT_TYPES"] = IMAGE_ATTACHMENT_TYPES
    app.jinja_env.globals["now"] = now
    app.jinja_env.globals["all_roles"] = ALL_ROLES
    app.jinja_env.globals["role_at_least"] = role_at_least
    from serviceops_core.localization import init_app as init_localization
    init_localization(app, default_language=lambda: setting_value("DEFAULT_LANGUAGE", "auto"))

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
            "app_version": display_version(),
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
                language=initial_language_preference(),
            )
            db.session.add(preference)
            db.session.commit()
        favorites = Favorite.query.filter_by(user_id=current_user.id).order_by(Favorite.folder, Favorite.label).all()
        notification_query = tenant_query(Notification).filter_by(user_id=current_user.id)
        recent_notifications = notification_query.order_by(Notification.created_at.desc()).limit(6).all()
        current_page_url = request.path + (f"?{request.query_string.decode()}" if request.query_string else "")
        current_tenant = db.session.get(Tenant, current_user.tenant_id)
        return platform_context | {
            "current_tenant_slug": current_tenant.slug if current_tenant else None,
            "ui_preference": preference,
            "ui_favorites": favorites,
            "current_user_is_local": user_is_local(current_user),
            "ui_history": RecentView.query.filter_by(user_id=current_user.id).order_by(RecentView.viewed_at.desc()).limit(12).all(),
            "current_page_url": current_page_url,
            "current_page_is_favorite": any(favorite.url == current_page_url for favorite in favorites),
            "ui_notifications": recent_notifications,
            "ui_notification_urls": {
                row.id: notification_target_url(row.target_type, row.target_id)
                for row in recent_notifications
            },
            "unread_notifications": notification_query.filter_by(read=False).count(),
            "unread_notification_severity": highest_notification_severity(notification_query),
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

    from serviceops_core.web import (
        administration,
        api,
        auth,
        client_management,
        cmdb,
        groups,
        knowledge,
        platform,
        service_requests,
        tickets,
        workspace,
    )

    platform.register(app)
    api.register(app)
    auth.register(app)
    workspace.register(app)
    administration.register(app)
    groups.register(app)
    tickets.register(app)
    knowledge.register(app)
    cmdb.register(app)
    client_management.register(app)
    service_requests.register(app)

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
            "img-src 'self' data: blob:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        if setting_bool("ENABLE_HSTS"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.errorhandler(403)
    def forbidden(error):
        rollback_failed_request()
        if request.path.startswith("/api/"):
            return http_error(error)
        return render_template(
            "error.html", code=403,
            message=error.description or "You do not have permission to access this page.",
        ), 403

    @app.errorhandler(404)
    def not_found(error):
        rollback_failed_request()
        if request.path.startswith("/api/"):
            return http_error(error)
        return render_template("error.html", code=404, message="The requested record was not found."), 404

    @app.errorhandler(409)
    def workflow_conflict(error):
        rollback_failed_request()
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

    from serviceops_core.syslog_forwarding import install as install_syslog
    install_syslog(app, setting_value, JsonLogFormatter(), RedactingFilter())

    if ipfs_enabled() and os.getenv("SERVICEOPS_SERVING") == "1":
        app.extensions["ipfs_projection"].start_checkpoint_loop()

        def ipfs_background_worker():
            with app.app_context():
                while True:
                    processed = 0
                    try:
                        with app.extensions["ipfs_projection"]._lock:
                            processed = (
                                process_sla_breaches() + process_workflow_schedules()
                                + process_workflow_jobs() + process_outbox()
                                + process_ldap_sync_schedule() + process_kpi_snapshot_schedule()
                                + process_rt_import_jobs() + process_discovery_schedule()
                                + process_client_escalation_policies() + process_client_email_inbox()
                                + process_data_retention_purge() + process_google_chat_pubsub_schedule()
                            )
                            process_performance_sample_schedule()
                            process_update_check_schedule()
                            heartbeat = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT")
                            if not heartbeat:
                                heartbeat = PlatformSetting(
                                    key="WORKER_LAST_HEARTBEAT", tenant_id=1, encrypted=False,
                                )
                                db.session.add(heartbeat)
                            heartbeat.value = now().isoformat()
                            db.session.commit()
                    except Exception:
                        app.logger.exception("Unhandled error in the IPFS background worker loop")
                        with app.extensions["ipfs_projection"]._lock:
                            db.session.rollback()
                    time_module.sleep(0.25 if processed else 5)

        threading.Thread(
            target=ipfs_background_worker,
            name="serviceops-ipfs-worker",
            daemon=True,
        ).start()

    from serviceops_core.ai.routes import register as register_ai
    register_ai(app)
    if os.getenv("SERVICEOPS_SERVING") == "1":
        from serviceops_core.crash_reports import install_request_watchdog
        install_request_watchdog(app)
    # Configuration reads (including syslog setup) can reopen the pool. Release
    # sessions and connections only after every startup component has finished.
    if not ipfs_enabled():
        try:
            with app.app_context():
                db.session.remove()
                db.engine.dispose()
        except Exception:
            app.logger.exception("Unable to clear startup database connections before serving")
            raise
    return app


if __name__ == "__main__":
    # Route modules in serviceops_core/web import from `app`; run through that
    # module so they share its state instead of loading a second copy of it.
    import app as _serviceops_app

    _serviceops_app.create_app().run(host="0.0.0.0", port=8080, debug=True)
