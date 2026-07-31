import csv
import io
import json
import os
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
from collections import Counter, defaultdict
from datetime import date, datetime, time as dt_time, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urljoin, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
from flask import Flask, Response, abort, current_app, flash, g, has_request_context, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from markupsafe import Markup, escape
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from cryptography.fernet import Fernet, InvalidToken
from ldap3 import ALL, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from serviceops_core.security import role_has_action, validate_policy
from serviceops_core.priority import calculate_priority, validate_priority_policy
from serviceops_core.business_time import add_business_minutes, validate_calendar
from serviceops_core.workflow import (
    canonical_json, load_workflow_package, materialize_workflow,
    package_digest, validate_workflow, workflow_matches,
)
from serviceops_core.projections import project_document, validate_projection_policy

# Bumped alongside charts/serviceops/Chart.yaml and installer/app.py on every
# release; shown in the UI (sidebar, login page, /health) so operators can
# confirm which build is actually running without SSHing into the host.
APP_VERSION = "1.29.49"

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

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"
oauth = OAuth()


def now():
    return datetime.now(timezone.utc)


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


class TenantResolutionError(RuntimeError):
    """Raised when an authenticated user has no tenant_id to fail closed on."""


def tenant_context_id():
    try:
        is_authenticated = current_user.is_authenticated
    except AttributeError:
        is_authenticated = False
    if is_authenticated:
        tenant_id = getattr(current_user, "tenant_id", None)
        if tenant_id:
            return tenant_id
        # An authenticated user is only ever missing tenant_id if the data is
        # corrupt (the column is NOT NULL) -- fail closed instead of silently
        # attaching their action to tenant 1's data.
        if has_request_context():
            current_app.logger.error(
                "Authenticated user %s has no tenant_id; refusing to default to tenant 1",
                getattr(current_user, "username", "unknown"),
            )
        raise TenantResolutionError("Authenticated user has no tenant_id.")
    return 1


def tenant_record_or_404(model, record_id):
    """Resolve a tenant-owned root without exposing another tenant's existence."""
    return model.query.filter_by(
        id=record_id, tenant_id=tenant_context_id()
    ).first_or_404()


def tenant_query(model):
    """Start a query constrained to the authenticated/default tenant."""
    return model.query.filter(model.tenant_id == tenant_context_id())


class Tenant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(160), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    title = db.Column(db.String(120), nullable=False, default="")
    department = db.Column(db.String(120), nullable=False, default="")
    division = db.Column(db.String(120))
    employee_id = db.Column(db.String(80))
    employee_type = db.Column(db.String(80))
    business_phone = db.Column(db.String(40), nullable=False, default="")
    mobile_phone = db.Column(db.String(40), nullable=False, default="")
    timezone = db.Column(db.String(80), nullable=False, default="Asia/Tokyo")
    date_format = db.Column(db.String(40), nullable=False, default="system")
    calendar_integration = db.Column(db.String(40), nullable=False, default="None")
    avatar_path = db.Column(db.String(255))
    location = db.Column(db.String(120), nullable=False, default="")
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="requester")
    active = db.Column(db.Boolean, default=True, nullable=False)
    auth_version = db.Column(db.Integer, nullable=False, default=1)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    manager_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    manager = db.relationship("User", remote_side=[id], foreign_keys=[manager_id])

    @property
    def is_active(self):
        return bool(self.active)


class ExternalIdentity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("provider", "subject", name="uq_external_identity"),)


class PlatformSetting(db.Model):
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")
    encrypted = db.Column(db.Boolean, nullable=False, default=False)
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    updated_by = db.relationship("User")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class KpiSnapshot(db.Model):
    """One captured value of a headline ITSM metric on a given day. /analytics
    computes everything live from current data, which means it can only
    ever show "right now" -- continual improvement runs on trend data, so a
    nightly job (process_kpi_snapshot_schedule) writes each day's computed
    metrics here instead."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, index=True)
    snapshot_date = db.Column(db.Date, nullable=False)
    metric_name = db.Column(db.String(40), nullable=False)
    metric_value = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "snapshot_date", "metric_name", name="uq_kpi_snapshot"),
    )


class KpiSnapshotState(db.Model):
    """Per-tenant scheduler bookkeeping for process_kpi_snapshot_schedule,
    same shape as LdapSyncState below."""
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), primary_key=True)
    last_run_at = db.Column(db.DateTime(timezone=True))


class RTImportJob(db.Model):
    """A queued/running/finished RT import run. RT import can take many
    minutes against a real (often slow) RT instance -- running it inline
    inside a web request routinely exceeded gunicorn's worker timeout,
    which kills the entire worker process (and every other request it was
    serving) mid-import, not just that one request. The web route now only
    ever enqueues a row here and returns immediately; the background
    worker (process_rt_import_jobs, tools/outbox_worker.py) does the
    actual work with no request-timeout ceiling."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    search_query = db.Column(db.String(500), nullable=False)
    record_limit = db.Column(db.Integer)
    dry_run = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(20), nullable=False, default="Pending")
    result_json = db.Column(db.Text)
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    started_at = db.Column(db.DateTime(timezone=True))
    finished_at = db.Column(db.DateTime(timezone=True))
    actor = db.relationship("User")

    @property
    def result(self):
        return json.loads(self.result_json) if self.result_json else None


class LdapSyncState(db.Model):
    """Per-tenant scheduler bookkeeping for the LDAP directory sync
    (serviceops_core.ldap_sync.sync_directory), so the background worker can
    tell whether a tenant's sync is due without ever defaulting to a global
    or tenant-1 last-run value. One row per tenant, created on first run."""
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), primary_key=True)
    last_run_at = db.Column(db.DateTime(timezone=True))
    last_status = db.Column(db.String(20))
    last_error = db.Column(db.Text)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(24), unique=True, index=True, nullable=False)
    kind = db.Column(db.String(20), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, nullable=False)
    state = db.Column(db.String(30), nullable=False, default="New", index=True)
    priority = db.Column(db.String(10), nullable=False, default="P3")
    impact = db.Column(db.String(20), nullable=False, default="Medium")
    urgency = db.Column(db.String(20), nullable=False, default="Medium")
    priority_overridden = db.Column(db.Boolean, nullable=False, default=False)
    priority_override_reason = db.Column(db.Text)
    category = db.Column(db.String(80), nullable=False, default="General")
    subcategory = db.Column(db.String(80), nullable=False, default="")
    contact_type = db.Column(db.String(40), nullable=False, default="Self-service")
    notify = db.Column(db.String(40), nullable=False, default="Email")
    service_offering_id = db.Column(db.Integer, db.ForeignKey("service_offering.id"))
    requester_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    deleted_at = db.Column(db.DateTime(timezone=True))
    deleted_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    requester = db.relationship("User", foreign_keys=[requester_id])
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    deleted_by = db.relationship("User", foreign_keys=[deleted_by_id])
    service_offering = db.relationship("ServiceOffering", foreign_keys=[service_offering_id])
    comments = db.relationship("Comment", cascade="all, delete-orphan", backref="ticket")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    # Populated by bulk import (serviceops_core/rt_import.py) so a re-run
    # matches existing rows instead of creating duplicates. Null for
    # tickets created normally through the app.
    external_source = db.Column(db.String(20))
    external_id = db.Column(db.String(120))
    # ITIL 4 service-desk CSAT -- one rating per ticket, submitted by the
    # requester once it's Resolved/Closed. Nullable/unsubmitted is the
    # normal, expected state for most tickets (most requesters never rate).
    csat_rating = db.Column(db.Integer)
    csat_comment = db.Column(db.Text)
    csat_submitted_at = db.Column(db.DateTime(timezone=True))


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    author = db.relationship("User")


class TaskNote(db.Model):
    """Polymorphic activity note, used for CTASK/PTASK work notes and
    SCTASK internal/customer-visible (RITM) commentary."""
    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(30), nullable=False, index=True)
    target_id = db.Column(db.Integer, nullable=False, index=True)
    visibility = db.Column(db.String(20), nullable=False, default="internal")
    body = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    author = db.relationship("User")


class Knowledge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="General")
    body = db.Column(db.Text, nullable=False)
    published = db.Column(db.Boolean, nullable=False, default=True)
    archived = db.Column(db.Boolean, nullable=False, default=False)
    superseded_by_id = db.Column(db.Integer, db.ForeignKey("knowledge.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    author = db.relationship("User")
    superseded_by = db.relationship("Knowledge", remote_side=[id])
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_tag = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(160), nullable=False)
    asset_type = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="In stock")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    serial_number = db.Column(db.String(120))
    owner = db.relationship("User")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(120), nullable=False)
    target = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, default="")
    request_id = db.Column(db.String(36), nullable=False, index=True)
    source_ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    integrity_version = db.Column(db.String(30), nullable=False, default="hmac-sha256-v1")
    integrity_key_id = db.Column(
        db.String(80), nullable=False, default="environment-v1"
    )
    previous_hash = db.Column(db.String(64), nullable=False, default="")
    event_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class AuditIntegrityKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.String(80), nullable=False)
    secret_encrypted = db.Column(db.Text, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    activated_at = db.Column(db.DateTime(timezone=True), nullable=False)
    retired_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, index=True,
    )
    created_by = db.relationship("User")
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "key_id", name="uq_audit_key_tenant_key"),
    )


class AuditRetentionPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    retention_days = db.Column(db.Integer, nullable=False, default=2555)
    legal_hold = db.Column(db.Boolean, nullable=False, default=False)
    external_export_required = db.Column(db.Boolean, nullable=False, default=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, unique=True, index=True,
    )
    updated_by = db.relationship("User")


class APIClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    name = db.Column(db.String(160), nullable=False)
    token_prefix = db.Column(db.String(16), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    scopes_json = db.Column(db.Text, nullable=False, default="[]")
    acting_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    last_used_at = db.Column(db.DateTime(timezone=True))
    revoked_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, index=True,
    )
    acting_user = db.relationship("User", foreign_keys=[acting_user_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])

    @property
    def scopes(self):
        try:
            return set(json.loads(self.scopes_json))
        except (TypeError, json.JSONDecodeError):
            return set()


class APIIdempotencyRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_client_id = db.Column(
        db.Integer, db.ForeignKey("api_client.id"), nullable=False
    )
    idempotency_key = db.Column(db.String(128), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    request_hash = db.Column(db.String(64), nullable=False)
    response_status = db.Column(db.Integer, nullable=False)
    response_body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, index=True,
    )
    api_client = db.relationship("APIClient")
    __table_args__ = (
        db.UniqueConstraint(
            "api_client_id", "idempotency_key",
            name="uq_api_idempotency_client_key",
        ),
    )


class APIRateLimitWindow(db.Model):
    """Per-client, per-minute request counter backing REST API rate limiting.
    DB-backed (not in-process) because the app runs multiple gunicorn workers,
    so an in-memory counter would undercount and let each worker allow its own
    full quota."""
    id = db.Column(db.Integer, primary_key=True)
    api_client_id = db.Column(db.Integer, db.ForeignKey("api_client.id"), nullable=False, index=True)
    window_start = db.Column(db.DateTime(timezone=True), nullable=False)
    request_count = db.Column(db.Integer, nullable=False, default=0)
    __table_args__ = (
        db.UniqueConstraint("api_client_id", "window_start", name="uq_api_rate_limit_window"),
    )


class IntegrationConnection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    kind = db.Column(db.String(30), nullable=False)
    endpoint = db.Column(db.String(500), nullable=False)
    secret_encrypted = db.Column(db.Text)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, index=True,
    )
    created_by = db.relationship("User")

    @property
    def secret(self):
        if not self.secret_encrypted:
            return ""
        return settings_cipher().decrypt(self.secret_encrypted.encode()).decode()


class OutboxEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    event_type = db.Column(db.String(120), nullable=False, index=True)
    payload_json = db.Column(db.Text, nullable=False)
    state = db.Column(db.String(30), nullable=False, default="Pending", index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    available_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    last_error = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, index=True,
    )

    @property
    def payload(self):
        return json.loads(self.payload_json)


class IntegrationDelivery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    outbox_event_id = db.Column(
        db.Integer, db.ForeignKey("outbox_event.id"), nullable=False
    )
    connection_id = db.Column(db.Integer, db.ForeignKey("integration_connection.id"))
    channel = db.Column(db.String(30), nullable=False)
    state = db.Column(db.String(30), nullable=False)
    status_code = db.Column(db.Integer)
    error = db.Column(db.Text)
    attempted_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, index=True,
    )
    event = db.relationship("OutboxEvent")
    connection = db.relationship("IntegrationConnection")


class MonitoringSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    name = db.Column(db.String(160), nullable=False)
    token_prefix = db.Column(db.String(16), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    assignment_group_id = db.Column(
        db.Integer, db.ForeignKey("support_group.id"), nullable=False
    )
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    last_seen_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, index=True,
    )
    assignment_group = db.relationship("SupportGroup")
    created_by = db.relationship("User")


class MonitoringEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    monitoring_source_id = db.Column(
        db.Integer, db.ForeignKey("monitoring_source.id"), nullable=False
    )
    external_id = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    resource = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.String(500), nullable=False)
    payload_json = db.Column(db.Text, nullable=False)
    enterprise_record_id = db.Column(
        db.Integer, db.ForeignKey("enterprise_record.id"), nullable=False
    )
    received_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(
        db.Integer, db.ForeignKey("tenant.id"), nullable=False,
        default=tenant_context_id, index=True,
    )
    source = db.relationship("MonitoringSource")
    record = db.relationship("EnterpriseRecord")
    __table_args__ = (
        db.UniqueConstraint(
            "monitoring_source_id", "external_id",
            name="uq_monitoring_source_external_event",
        ),
    )


class EnterpriseRecord(db.Model):
    """Shared task engine for enterprise workflows outside the core ITSM ticket table."""
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(30), unique=True, nullable=False, index=True)
    domain = db.Column(db.String(30), nullable=False, index=True)
    record_type = db.Column(db.String(50), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, nullable=False)
    state = db.Column(db.String(40), nullable=False, default="New", index=True)
    priority = db.Column(db.String(10), nullable=False, default="P3")
    risk = db.Column(db.String(20), nullable=False, default="Medium")
    requester_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    support_group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"))
    due_at = db.Column(db.DateTime(timezone=True))
    metadata_json = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    requester = db.relationship("User", foreign_keys=[requester_id])
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    support_group = db.relationship("SupportGroup")
    approvals = db.relationship("Approval", cascade="all, delete-orphan", backref="record")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    # Populated by bulk import (serviceops_core/rt_import.py) so a re-run
    # matches existing rows instead of creating duplicates. Null for
    # records created normally through the app.
    external_source = db.Column(db.String(20))
    external_id = db.Column(db.String(120))

    @property
    def metadata_dict(self):
        try:
            return json.loads(self.metadata_json) if self.metadata_json else {}
        except (TypeError, ValueError):
            return {}


class Approval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    enterprise_record_id = db.Column(db.Integer, db.ForeignKey("enterprise_record.id"), nullable=False)
    approver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    state = db.Column(db.String(20), nullable=False, default="Requested")
    comments = db.Column(db.Text, default="")
    decided_at = db.Column(db.DateTime(timezone=True))
    approver = db.relationship("User")


class CatalogItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    delivery_days = db.Column(db.Integer, nullable=False, default=3)
    approval_required = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class CatalogItemRouting(db.Model):
    """Administrator-managed default fulfillment route for a catalog item."""
    id = db.Column(db.Integer, primary_key=True)
    catalog_item_id = db.Column(
        db.Integer, db.ForeignKey("catalog_item.id"), unique=True, nullable=False
    )
    support_group_id = db.Column(
        db.Integer, db.ForeignKey("support_group.id"), nullable=False
    )
    active = db.Column(db.Boolean, nullable=False, default=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_at = db.Column(
        db.DateTime(timezone=True), default=now, onupdate=now, nullable=False
    )
    item = db.relationship(
        "CatalogItem", backref=db.backref(
            "fulfillment_route", uselist=False, cascade="all, delete-orphan"
        )
    )
    support_group = db.relationship("SupportGroup", foreign_keys=[support_group_id])
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])


class ConfigurationItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    ci_class = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text)
    environment = db.Column(db.String(30), nullable=False, default="Production")
    operational_status = db.Column(db.String(40), nullable=False, default="Operational")
    lifecycle_state = db.Column(db.String(30), nullable=False, default="In Use")
    business_criticality = db.Column(db.String(20), nullable=False, default="Medium")
    ip_address = db.Column(db.String(60))
    serial_number = db.Column(db.String(120))
    vendor = db.Column(db.String(120))
    model = db.Column(db.String(120))
    location = db.Column(db.String(160))
    cost_center = db.Column(db.String(80))
    discovery_source = db.Column(db.String(40), nullable=False, default="Manual")
    install_date = db.Column(db.Date)
    warranty_expiry_date = db.Column(db.Date)
    attributes = db.Column(db.JSON, nullable=False, default=dict)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    support_group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"))
    owner = db.relationship("User")
    support_group = db.relationship("SupportGroup")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    # Populated by bulk import (serviceops_core/netbox_sync.py, cmdb_import.py) so a
    # re-run matches existing rows instead of creating duplicates. Null for
    # manually-created CIs.
    external_source = db.Column(db.String(20))
    external_id = db.Column(db.String(120))
    # Forces CCB authorization on changes against this CI even when its
    # environment isn't in CCB_REQUIRED_ENVIRONMENTS (e.g. a Dev box that's
    # still business-critical enough to need board sign-off).
    require_ccb_approval = db.Column(db.Boolean, nullable=False, default=False)


CI_RELATIONSHIP_TYPES = ["Depends on", "Runs on", "Connects to", "Hosted on", "Backs up"]


class CIRelationship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"), nullable=False)
    child_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"), nullable=False)
    relationship_type = db.Column(db.String(60), nullable=False, default="Depends on")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    parent = db.relationship("ConfigurationItem", foreign_keys=[parent_id])
    child = db.relationship("ConfigurationItem", foreign_keys=[child_id])
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    __table_args__ = (
        db.UniqueConstraint("parent_id", "child_id", "relationship_type", name="uq_ci_relationship"),
    )


class ServiceOfferingCI(db.Model):
    """ITIL 4 service configuration management: maps a business service
    (ServiceOffering) to the configuration items that realize it. Without
    this, a service's criticality is set by hand with no link to the CIs
    that actually back it, and there's no way to answer "what services does
    this CI support" for impact analysis or change risk."""
    id = db.Column(db.Integer, primary_key=True)
    service_offering_id = db.Column(db.Integer, db.ForeignKey("service_offering.id"), nullable=False)
    ci_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"), nullable=False)
    relationship_role = db.Column(db.String(30), nullable=False, default="Supporting")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    service_offering = db.relationship("ServiceOffering", backref=db.backref("ci_links", cascade="all, delete-orphan"))
    ci = db.relationship("ConfigurationItem", backref=db.backref("service_links", cascade="all, delete-orphan"))
    __table_args__ = (
        db.UniqueConstraint("service_offering_id", "ci_id", name="uq_service_offering_ci"),
    )


class ServiceOutage(db.Model):
    """ITIL 4 availability management. Auto-derived from incidents (see
    sync_service_outages) rather than a separate manual log: a High/Critical
    impact incident on a CI opens an outage for every business service that
    CI backs, and resolving/downgrading the incident closes it. Deriving
    from incidents avoids asking agents to double-enter the same window,
    and it's what makes an uptime % computable at all -- previously there
    was no downtime history anywhere in the system."""
    id = db.Column(db.Integer, primary_key=True)
    service_offering_id = db.Column(db.Integer, db.ForeignKey("service_offering.id"), nullable=False, index=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    started_at = db.Column(db.DateTime(timezone=True), nullable=False)
    ended_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    service_offering = db.relationship("ServiceOffering")
    ticket = db.relationship("Ticket")


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(180), nullable=False)
    body = db.Column(db.Text, nullable=False)
    target_type = db.Column(db.String(30))
    target_id = db.Column(db.Integer)
    read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class SupportGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    group_type = db.Column(db.String(40), nullable=False, default="Fulfillment")
    manager_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    active = db.Column(db.Boolean, nullable=False, default=True)
    manager = db.relationship("User")
    members = db.relationship("GroupMember", cascade="all, delete-orphan", backref="group")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="member")
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("group_id", "user_id"),)


class DirectoryGroupMapping(db.Model):
    """Map an AD group name or full DN to a ServiceOps support group."""
    id = db.Column(db.Integer, primary_key=True)
    directory_group = db.Column(db.String(500), unique=True, nullable=False)
    support_group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    support_group = db.relationship("SupportGroup")


class SupportGroupAlias(db.Model):
    """Alternate name staff use for a support group (e.g. "DBA" for the
    "Database" team). Consulted by free-text team resolution -- CSV import's
    Owner column, and anywhere else a team name arrives as a string rather
    than a support_group_id -- before falling back to an exact-name match or
    auto-creating a new (likely duplicate) group."""
    id = db.Column(db.Integer, primary_key=True)
    alias = db.Column(db.String(160), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    group = db.relationship("SupportGroup")
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "alias", name="uq_support_group_alias_tenant_alias"),
    )


class DirectoryManagedMembership(db.Model):
    """Tracks memberships ServiceOps may safely remove during AD resynchronization."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False)
    directory_group = db.Column(db.String(500), nullable=False)
    synchronized_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    user = db.relationship("User")
    group = db.relationship("SupportGroup")
    __table_args__ = (db.UniqueConstraint("user_id", "group_id", name="uq_directory_membership"),)


class ApprovalChain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(180), nullable=False)
    target_type = db.Column(db.String(30), nullable=False, index=True)
    target_id = db.Column(db.Integer, nullable=False, index=True)
    state = db.Column(db.String(30), nullable=False, default="Running")
    current_stage = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True))
    gates = db.relationship("ApprovalGate", cascade="all, delete-orphan", backref="chain", order_by="ApprovalGate.sequence")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class ApprovalGate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chain_id = db.Column(db.Integer, db.ForeignKey("approval_chain.id"), nullable=False)
    sequence = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(160), nullable=False)
    mode = db.Column(db.String(20), nullable=False, default="all")
    state = db.Column(db.String(30), nullable=False, default="Pending")
    votes = db.relationship("ApprovalVote", cascade="all, delete-orphan", backref="gate")
    # Redundant with chain.tenant_id but kept as its own enforced column (same
    # defense-in-depth rationale as ci_relationship.tenant_id in B-253): a
    # decision record like this should not depend solely on every future query
    # remembering to join back through approval_chain.
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    __table_args__ = (db.UniqueConstraint("chain_id", "sequence"),)


class ApprovalVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gate_id = db.Column(db.Integer, db.ForeignKey("approval_gate.id"), nullable=False)
    approver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    delegated_from_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    state = db.Column(db.String(30), nullable=False, default="Not Requested")
    comments = db.Column(db.Text, default="")
    decided_at = db.Column(db.DateTime(timezone=True))
    approver = db.relationship("User", foreign_keys=[approver_id])
    delegated_from = db.relationship("User", foreign_keys=[delegated_from_id])
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class ServiceOffering(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    support_group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"))
    criticality = db.Column(db.String(20), nullable=False, default="Medium")
    status = db.Column(db.String(30), nullable=False, default="Operational")
    owner = db.relationship("User")
    support_group = db.relationship("SupportGroup")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


SLA_AGREEMENT_TYPES = ["SLA", "OLA", "UC"]


class SLADefinition(db.Model):
    """agreement_type distinguishes a customer-facing SLA from an internal
    Operating Level Agreement (OLA, between two internal support teams) or
    an external Underpinning Contract (UC, with a vendor) -- ITIL 4 service
    level management treats these as distinct agreement types even though
    they're tracked/breached the same mechanical way here."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), unique=True, nullable=False)
    target_type = db.Column(db.String(30), nullable=False)
    priority = db.Column(db.String(10))
    duration_minutes = db.Column(db.Integer, nullable=False)
    pause_states = db.Column(db.String(200), nullable=False, default="Pending,On Hold")
    active = db.Column(db.Boolean, nullable=False, default=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey("business_schedule.id"))
    agreement_type = db.Column(db.String(10), nullable=False, default="SLA")
    counterparty = db.Column(db.String(160), default="")
    schedule = db.relationship("BusinessSchedule")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class TaskSLA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    definition_id = db.Column(db.Integer, db.ForeignKey("sla_definition.id"), nullable=False)
    target_type = db.Column(db.String(30), nullable=False, index=True)
    target_id = db.Column(db.Integer, nullable=False, index=True)
    stage = db.Column(db.String(30), nullable=False, default="In Progress")
    started_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    breach_at = db.Column(db.DateTime(timezone=True), nullable=False)
    stopped_at = db.Column(db.DateTime(timezone=True))
    paused_at = db.Column(db.DateTime(timezone=True))
    paused_seconds = db.Column(db.Integer, nullable=False, default=0)
    breached = db.Column(db.Boolean, nullable=False, default=False)
    definition = db.relationship("SLADefinition")


class BusinessSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    timezone_name = db.Column(db.String(80), nullable=False, default="UTC")
    weekdays_json = db.Column(db.Text, nullable=False, default="[0,1,2,3,4]")
    start_time_text = db.Column(db.String(5), nullable=False, default="09:00")
    end_time_text = db.Column(db.String(5), nullable=False, default="17:00")
    active = db.Column(db.Boolean, nullable=False, default=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    holidays = db.relationship("ScheduleHoliday", cascade="all, delete-orphan", backref="schedule")
    __table_args__ = (db.UniqueConstraint("tenant_id", "name", name="uq_business_schedule_tenant_name"),)

    @property
    def weekdays(self):
        return json.loads(self.weekdays_json)

    @property
    def start_time(self):
        return dt_time.fromisoformat(self.start_time_text)

    @property
    def end_time(self):
        return dt_time.fromisoformat(self.end_time_text)


class ScheduleHoliday(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey("business_schedule.id"), nullable=False)
    holiday_date = db.Column(db.Date, nullable=False)
    name = db.Column(db.String(160), nullable=False)
    __table_args__ = (db.UniqueConstraint("schedule_id", "holiday_date", name="uq_schedule_holiday_date"),)


class SLAEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_sla_id = db.Column(db.Integer, db.ForeignKey("task_sla.id"), nullable=False)
    event_type = db.Column(db.String(30), nullable=False)
    occurred_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    details = db.Column(db.Text, nullable=False, default="")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class WorkflowDefinition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workflow_key = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(160), nullable=False)
    event_type = db.Column(db.String(80), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    published_version_id = db.Column(db.Integer)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    versions = db.relationship(
        "WorkflowVersion", cascade="all, delete-orphan", backref="definition",
        foreign_keys="WorkflowVersion.definition_id",
    )
    __table_args__ = (db.UniqueConstraint(
        "tenant_id", "workflow_key", name="uq_workflow_definition_key"
    ),)

    @property
    def published_version(self):
        return db.session.get(WorkflowVersion, self.published_version_id)


class WorkflowVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    definition_id = db.Column(db.Integer, db.ForeignKey("workflow_definition.id"), nullable=False)
    version = db.Column(db.Integer, nullable=False)
    state = db.Column(db.String(20), nullable=False, default="Draft")
    definition_json = db.Column(db.Text, nullable=False)
    package_hash = db.Column(db.String(64), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    published_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    created_by = db.relationship("User")
    __table_args__ = (db.UniqueConstraint(
        "definition_id", "version", name="uq_workflow_definition_version"
    ),)

    @property
    def specification(self):
        return json.loads(self.definition_json)


class WorkflowJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    event_type = db.Column(db.String(80), nullable=False, index=True)
    target_type = db.Column(db.String(30), nullable=False)
    target_id = db.Column(db.Integer, nullable=False)
    context_json = db.Column(db.Text, nullable=False)
    state = db.Column(db.String(20), nullable=False, default="Pending", index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    available_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    last_error = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)

    @property
    def context(self):
        return json.loads(self.context_json)


class WorkflowExecution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("workflow_job.id"), nullable=False)
    version_id = db.Column(db.Integer, db.ForeignKey("workflow_version.id"), nullable=False)
    correlation_id = db.Column(db.String(36), nullable=False)
    state = db.Column(db.String(20), nullable=False)
    input_json = db.Column(db.Text, nullable=False)
    output_json = db.Column(db.Text, nullable=False, default="[]")
    error = db.Column(db.Text)
    started_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True))
    next_action_index = db.Column(db.Integer, nullable=False, default=0)
    resume_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    version = db.relationship("WorkflowVersion")
    job = db.relationship("WorkflowJob")
    __table_args__ = (db.UniqueConstraint(
        "job_id", "version_id", name="uq_workflow_job_version"
    ),)


class WorkflowStepExecution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    execution_id = db.Column(db.Integer, db.ForeignKey("workflow_execution.id"), nullable=False)
    action_index = db.Column(db.Integer, nullable=False)
    action_type = db.Column(db.String(40), nullable=False)
    state = db.Column(db.String(20), nullable=False)
    input_json = db.Column(db.Text, nullable=False)
    output_json = db.Column(db.Text, nullable=False, default="{}")
    error = db.Column(db.Text)
    started_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True))
    compensation_state = db.Column(db.String(20))
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    execution = db.relationship(
        "WorkflowExecution", backref=db.backref(
            "steps", order_by="WorkflowStepExecution.action_index",
            cascade="all, delete-orphan",
        )
    )
    __table_args__ = (db.UniqueConstraint(
        "execution_id", "action_index", name="uq_workflow_execution_action"
    ),)


class WorkflowSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    schedule_key = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(160), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    interval_minutes = db.Column(db.Integer, nullable=False)
    next_run_at = db.Column(db.DateTime(timezone=True), nullable=False)
    last_run_at = db.Column(db.DateTime(timezone=True))
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    ticket = db.relationship("Ticket")
    created_by = db.relationship("User")
    __table_args__ = (db.UniqueConstraint(
        "tenant_id", "schedule_key", name="uq_workflow_schedule_key"
    ),)


class CatalogRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(24), unique=True, nullable=False)
    requested_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    requested_for_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    state = db.Column(db.String(40), nullable=False, default="Open")
    opened_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    closed_at = db.Column(db.DateTime(timezone=True))
    requested_by = db.relationship("User", foreign_keys=[requested_by_id])
    requested_for = db.relationship("User", foreign_keys=[requested_for_id])
    items = db.relationship("RequestedItem", cascade="all, delete-orphan", backref="request")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class RequestedItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(24), unique=True, nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey("catalog_request.id"), nullable=False)
    catalog_item_id = db.Column(db.Integer, db.ForeignKey("catalog_item.id"), nullable=False)
    state = db.Column(db.String(40), nullable=False, default="Open")
    stage = db.Column(db.String(40), nullable=False, default="Request Approved")
    variables_json = db.Column(db.Text, nullable=False, default="{}")
    due_at = db.Column(db.DateTime(timezone=True))
    item = db.relationship("CatalogItem")
    tasks = db.relationship("CatalogTask", cascade="all, delete-orphan", backref="requested_item")


class CatalogTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(24), unique=True, nullable=False)
    requested_item_id = db.Column(db.Integer, db.ForeignKey("requested_item.id"), nullable=False)
    title = db.Column(db.String(180), nullable=False)
    state = db.Column(db.String(40), nullable=False, default="Open")
    sequence = db.Column(db.Integer, nullable=False, default=1)
    assignment_group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"))
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    due_at = db.Column(db.DateTime(timezone=True))
    work_notes = db.Column(db.Text, default="")
    assignment_group = db.relationship("SupportGroup")
    assignee = db.relationship("User")


class CatalogTaskControl(db.Model):
    """Optional sequential dependency metadata for SCTASK fulfillment flows."""
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("catalog_task.id"), unique=True, nullable=False)
    execution_mode = db.Column(db.String(20), nullable=False, default="Parallel")
    predecessor_task_id = db.Column(db.Integer, db.ForeignKey("catalog_task.id"))
    task = db.relationship(
        "CatalogTask", foreign_keys=[task_id],
        backref=db.backref("flow_control", uselist=False),
    )
    predecessor = db.relationship("CatalogTask", foreign_keys=[predecessor_task_id])


class ChangeGovernance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), unique=True, nullable=False)
    change_type = db.Column(db.String(30), nullable=False, default="Normal")
    risk_score = db.Column(db.Integer, nullable=False, default=50)
    impact = db.Column(db.String(20), nullable=False, default="Medium")
    implementation_plan = db.Column(db.Text, default="")
    test_plan = db.Column(db.Text, default="")
    backout_plan = db.Column(db.Text, default="")
    planned_start = db.Column(db.DateTime(timezone=True))
    planned_end = db.Column(db.DateTime(timezone=True))
    ci_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"))
    conflict_status = db.Column(db.String(500), nullable=False, default="Not Run")
    ccb_required = db.Column(db.Boolean, nullable=False, default=True)
    risk_score_overridden = db.Column(db.Boolean, nullable=False, default=False)
    risk_score_override_reason = db.Column(db.Text, default="")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    ticket = db.relationship("Ticket", backref=db.backref("change_governance", uselist=False))
    ci = db.relationship("ConfigurationItem")


class ChangeFreezeWindow(db.Model):
    """A real blackout window: while active, Standard/Normal changes whose
    planned window falls inside it are blocked at submission (see
    active_change_freeze() and its call site in the change-creation route).
    Only Emergency changes are exempt, matching ITIL 4 change-enablement
    practice -- previously CHANGE_FREEZE_MESSAGE was a banner with no
    enforcement behind it at all."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    starts_at = db.Column(db.DateTime(timezone=True), nullable=False)
    ends_at = db.Column(db.DateTime(timezone=True), nullable=False)
    reason = db.Column(db.Text, default="")
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    created_by = db.relationship("User")


CHANGE_PIR_OUTCOMES = ["Successful", "Successful with issues", "Failed", "Backed out"]


class ChangePostImplementationReview(db.Model):
    """ITIL 4 change enablement post-implementation review. Required before a
    change ticket can reach "Closed" -- see the gate in transition_ticket()
    -- so "closed" always means "reviewed," not just "someone moved the
    dropdown." Also the basis for a real change-success-rate metric instead
    of inferring success from Closed-vs-Cancelled ticket state."""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), unique=True, nullable=False)
    outcome = db.Column(db.String(30), nullable=False)
    summary = db.Column(db.Text, default="")
    follow_up_actions = db.Column(db.Text, default="")
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reviewed_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    ticket = db.relationship("Ticket", backref=db.backref("post_implementation_review", uselist=False))
    reviewed_by = db.relationship("User")


class ChangeOwnership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), unique=True, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False)
    ticket = db.relationship("Ticket", backref=db.backref("change_ownership", uselist=False))
    group = db.relationship("SupportGroup")


class TicketAssignmentGroup(db.Model):
    """Assignment-group ownership for incidents and service-request tickets."""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), unique=True, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False)
    ticket = db.relationship(
        "Ticket", backref=db.backref("assignment_group_record", uselist=False)
    )
    group = db.relationship("SupportGroup")


class RecordLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_type = db.Column(db.String(30), nullable=False)
    source_id = db.Column(db.Integer, nullable=False)
    target_type = db.Column(db.String(30), nullable=False)
    target_id = db.Column(db.Integer, nullable=False)
    link_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)


class TaskHistory(db.Model):
    """Append-only activity history rendered on the related operational record."""
    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(30), nullable=False, index=True)
    target_id = db.Column(db.Integer, nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    event = db.Column(db.String(60), nullable=False)
    field_name = db.Column(db.String(80))
    old_value = db.Column(db.Text, default="")
    new_value = db.Column(db.Text, default="")
    details = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    actor = db.relationship("User")


class OperationalTask(db.Model):
    """PTASK and CTASK work packages with independent team ownership."""
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(24), unique=True, nullable=False, index=True)
    task_kind = db.Column(db.String(20), nullable=False, index=True)
    parent_type = db.Column(db.String(30), nullable=False, index=True)
    parent_id = db.Column(db.Integer, nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    task_type = db.Column(db.String(30), nullable=False)
    state = db.Column(db.String(30), nullable=False, default="Open")
    required = db.Column(db.Boolean, nullable=False, default=True)
    sequence = db.Column(db.Integer, nullable=False, default=1)
    assignment_group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    planned_start = db.Column(db.DateTime(timezone=True))
    planned_end = db.Column(db.DateTime(timezone=True))
    work_notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    assignment_group = db.relationship("SupportGroup")
    assignee = db.relationship("User")


class TaskCI(db.Model):
    """Many-to-many affected and impacted CI/service relationships."""
    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(30), nullable=False, index=True)
    target_id = db.Column(db.Integer, nullable=False, index=True)
    ci_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"), nullable=False)
    relationship_role = db.Column(db.String(30), nullable=False, default="Affected CI")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    ci = db.relationship("ConfigurationItem")
    __table_args__ = (
        db.UniqueConstraint(
            "target_type", "target_id", "ci_id", "relationship_role",
            name="uq_task_ci_relationship",
        ),
    )


class ProblemProfile(db.Model):
    """Problem-specific root cause, known-error, workaround, and fix information."""
    id = db.Column(db.Integer, primary_key=True)
    enterprise_record_id = db.Column(
        db.Integer, db.ForeignKey("enterprise_record.id"), unique=True, nullable=False
    )
    known_error = db.Column(db.Boolean, nullable=False, default=False)
    root_cause = db.Column(db.Text, default="")
    workaround = db.Column(db.Text, default="")
    fix_notes = db.Column(db.Text, default="")
    primary_ci_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"))
    primary_ci = db.relationship("ConfigurationItem")
    record = db.relationship(
        "EnterpriseRecord", backref=db.backref("problem_profile", uselist=False)
    )
    primary_ci = db.relationship("ConfigurationItem")


class ChangeRevision(db.Model):
    """Tracks approval-relevant plan revisions without overwriting prior decisions."""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), unique=True, nullable=False)
    revision = db.Column(db.Integer, nullable=False, default=1)
    last_material_change_at = db.Column(db.DateTime(timezone=True))
    ticket = db.relationship(
        "Ticket", backref=db.backref("change_revision", uselist=False)
    )


class MajorIncidentProfile(db.Model):
    """Major-incident coordination remains an extension of the parent INC.
    business_impact/communications are live-updated during the incident;
    the review_* fields are a distinct after-the-fact artifact (ITIL 4
    continual improvement expects a structured post-incident review, not
    just whatever the live communications log happened to capture)."""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), unique=True, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Proposed")
    business_impact = db.Column(db.Text, default="")
    communications = db.Column(db.Text, default="")
    coordinator_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    declared_at = db.Column(db.DateTime(timezone=True))
    review_what_went_well = db.Column(db.Text, default="")
    review_what_went_poorly = db.Column(db.Text, default="")
    review_follow_up_actions = db.Column(db.Text, default="")
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    reviewed_at = db.Column(db.DateTime(timezone=True))
    ticket = db.relationship(
        "Ticket", backref=db.backref("major_incident_profile", uselist=False)
    )
    coordinator = db.relationship("User", foreign_keys=[coordinator_id])
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])


IMPROVEMENT_STATES = ["Identified", "Assessed", "In Progress", "Done", "Rejected"]


class ImprovementItem(db.Model):
    """ITIL 4 continual improvement register: tracks improvement opportunities
    as trackable records with an owner and outcome, independent of any single
    ticket's own lifecycle. Can be raised standalone or from an incident,
    problem, change, request, or IT operations event -- source_type/source_id
    use the same (type, id) shape as record_reference()/record_url() so a
    source link can be rendered without a bespoke lookup."""
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(20), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    source_type = db.Column(db.String(20))
    source_id = db.Column(db.Integer)
    status = db.Column(db.String(20), nullable=False, default="Identified")
    expected_outcome = db.Column(db.Text, default="")
    measured_result = db.Column(db.Text, default="")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    label = db.Column(db.String(180), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    folder = db.Column(db.String(80), nullable=False, default="My favorites")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("user_id", "url"),)


class RecentView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    label = db.Column(db.String(180), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    viewed_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("user_id", "url"),)


class UserPreference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    theme = db.Column(db.String(30), nullable=False, default="light")
    density = db.Column(db.String(30), nullable=False, default="comfortable")
    font_scale = db.Column(db.Integer, nullable=False, default=100)
    high_contrast = db.Column(db.Boolean, nullable=False, default=False)
    reduced_motion = db.Column(db.Boolean, nullable=False, default=False)
    nav_pinned = db.Column(db.Boolean, nullable=False, default=True)
    start_page = db.Column(db.String(500), nullable=False, default="/")
    accessible_tooltips = db.Column(db.Boolean, nullable=False, default=True)
    data_patterns = db.Column(db.Boolean, nullable=False, default=False)
    compact_dates = db.Column(db.Boolean, nullable=False, default=False)
    keyboard_shortcuts = db.Column(db.Boolean, nullable=False, default=True)
    date_time_display = db.Column(db.String(20), nullable=False, default="both")
    user = db.relationship("User")


class ChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    text = db.Column(db.String(300), nullable=False)
    completed = db.Column(db.Boolean, nullable=False, default=False)
    position = db.Column(db.Integer, nullable=False, default=0)
    ticket = db.relationship("Ticket", backref=db.backref("checklist", cascade="all, delete-orphan"))


class FileAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # ticket_id is nullable because RT import (serviceops_core/rt_import.py)
    # can also attach files to an EnterpriseRecord ("IT operations event")
    # instead -- exactly one of ticket_id/enterprise_record_id is set.
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=True)
    enterprise_record_id = db.Column(db.Integer, db.ForeignKey("enterprise_record.id"), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("comment.id"), nullable=True)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)
    mime_type = db.Column(db.String(120))
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64))
    scan_status = db.Column(db.String(20), nullable=False, default="not_scanned")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    ticket = db.relationship("Ticket", backref=db.backref("attachments", cascade="all, delete-orphan"))
    enterprise_record = db.relationship("EnterpriseRecord", backref=db.backref("attachments", cascade="all, delete-orphan"))
    comment = db.relationship("Comment", backref=db.backref("attachments", cascade="all, delete-orphan"))
    uploaded_by = db.relationship("User")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def roles(*allowed):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in allowed:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def require_action(action):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if not role_has_action(current_user.role, action):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def audit_integrity_key(key_id="environment-v1", tenant_id=None):
    tenant_id = tenant_id or tenant_context_id()
    if key_id != "environment-v1":
        stored = AuditIntegrityKey.query.filter_by(
            tenant_id=tenant_id, key_id=key_id
        ).one_or_none()
        if not stored:
            raise RuntimeError(f"Audit integrity key {key_id!r} is unavailable.")
        return settings_cipher().decrypt(stored.secret_encrypted.encode())
    stored = AuditIntegrityKey.query.filter_by(
        tenant_id=tenant_id, key_id="environment-v1"
    ).one_or_none()
    if stored:
        return settings_cipher().decrypt(stored.secret_encrypted.encode())
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
        if not hmac.compare_digest(row.event_hash, calculate_audit_hash(row)):
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
}


def api_token_hash(token):
    pepper = os.getenv("API_TOKEN_PEPPER") or current_app.config["SECRET_KEY"]
    return hmac.new(
        pepper.encode(), token.encode(), hashlib.sha256
    ).hexdigest()


def create_api_token():
    token = f"sop_{secrets.token_urlsafe(32)}"
    return token, token[:12], api_token_hash(token)


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
    if not client.acting_user.active or client.acting_user.tenant_id != client.tenant_id:
        abort(403, description="The API identity is inactive or invalid.")
    enforce_api_rate_limit(client)
    client.last_used_at = now()
    g.api_client = client
    g.api_user = client.acting_user
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


SETTING_DEFINITIONS = {
    "general": [
        {"key": "INSTANCE_NAME", "label": "Instance name", "type": "text", "default": "ServiceOps", "live": True},
        {"key": "COMPANY_NAME", "label": "Company name", "type": "text", "default": "Your Company", "live": True},
        {"key": "SUPPORT_EMAIL", "label": "Support email", "type": "email", "default": "", "live": True},
    ],
    "appearance": [
        {"key": "BRAND_TEAL", "label": "Primary brand color", "type": "color", "default": "#003e4c", "live": True},
        {"key": "BRAND_AMBER", "label": "Accent brand color", "type": "color", "default": "#f9aa3c", "live": True},
        {"key": "DEFAULT_DENSITY", "label": "Default density", "type": "choice", "choices": ["comfortable", "compact"], "default": "comfortable", "live": True},
    ],
    "authentication": [
        {"key": "LOCAL_AUTH_ENABLED", "label": "Enable local authentication", "type": "bool", "default": "true", "live": True},
        {"key": "LDAP_ENABLED", "label": "Enable AD/LDAP", "type": "bool", "default": "false", "live": True},
        {"key": "LDAP_SERVER_URI", "label": "LDAP server URI", "type": "text", "default": "", "live": True},
        {"key": "LDAP_BIND_DN", "label": "LDAP bind DN", "type": "text", "default": "", "live": True},
        {"key": "LDAP_BIND_PASSWORD", "label": "LDAP bind password", "type": "secret", "default": "", "live": True},
        {"key": "LDAP_BASE_DN", "label": "LDAP base DN", "type": "text", "default": "", "live": True},
        {"key": "LDAP_USER_FILTER", "label": "LDAP user filter", "type": "text", "default": "(&(objectClass=user)(sAMAccountName={username}))", "live": True},
        {"key": "LDAP_START_TLS", "label": "Use LDAP StartTLS", "type": "bool", "default": "true", "live": True},
        {"key": "LDAP_VALIDATE_CERT", "label": "Validate LDAP certificate", "type": "bool", "default": "true", "live": True},
        {"key": "LDAP_ROLE_MAPPINGS", "label": "LDAP group role mappings", "type": "json", "default": "{}", "live": True},
        {
            "key": "LDAP_ATTR_MAP", "label": "LDAP directory attribute map", "type": "json",
            "default": json.dumps({
                "title": "title", "department": "department", "division": "division",
                "employee_id": "employeeID", "employee_type": "employeeType", "manager": "manager",
                "email": "mail", "display_name": "displayName", "username": "sAMAccountName",
            }),
            "live": True,
        },
        {"key": "LDAP_SYNC_ENABLED", "label": "Enable scheduled LDAP directory sync", "type": "bool", "default": "false", "live": True},
        {"key": "LDAP_SYNC_INTERVAL_MINUTES", "label": "LDAP directory sync interval (minutes)", "type": "int", "default": "60", "min": 5, "max": 10080, "live": True},
        {"key": "KEYCLOAK_ENABLED", "label": "Enable Keycloak", "type": "bool", "default": "false", "live": False},
        {"key": "KEYCLOAK_DISCOVERY_URL", "label": "Keycloak discovery URL", "type": "url", "default": "", "live": False},
        {"key": "KEYCLOAK_CLIENT_ID", "label": "Keycloak client ID", "type": "text", "default": "", "live": False},
        {"key": "KEYCLOAK_CLIENT_SECRET", "label": "Keycloak client secret", "type": "secret", "default": "", "live": False},
        {"key": "KEYCLOAK_ROLE_MAPPINGS", "label": "Keycloak realm-role mappings", "type": "json", "default": "{}", "live": True},
    ],
    "security": [
        {"key": "ENABLE_HSTS", "label": "Enable HSTS", "type": "bool", "default": "false", "live": True},
        {"key": "SESSION_HOURS", "label": "Session lifetime in hours", "type": "int", "default": "8", "min": 1, "max": 168, "live": False},
        {"key": "PASSWORD_MIN_LENGTH", "label": "Minimum local password length", "type": "int", "default": "14", "min": 8, "max": 64, "live": True},
        {"key": "MAX_UPLOAD_MB", "label": "Maximum upload size (MB)", "type": "int", "default": "20", "min": 1, "max": 500, "live": True},
        {"key": "AUDIT_STREAM_ENABLED", "label": "Stream audit events to SIEM", "type": "bool", "default": "false", "live": True},
        {"key": "LOGIN_MAX_ATTEMPTS", "label": "Failed logins before lockout", "type": "int", "default": "5", "min": 3, "max": 20, "live": True},
        {"key": "LOGIN_LOCKOUT_MINUTES", "label": "Lockout duration in minutes", "type": "int", "default": "15", "min": 1, "max": 1440, "live": True},
        {"key": "API_RATE_LIMIT_PER_MINUTE", "label": "REST API requests per minute (per client)", "type": "int", "default": "120", "min": 10, "max": 6000, "live": True},
        {"key": "CLAMAV_ENABLED", "label": "Scan attachments with ClamAV", "type": "bool", "default": "false", "live": True},
        {"key": "CLAMAV_HOST", "label": "ClamAV daemon host", "type": "text", "default": "", "live": True},
        {"key": "CLAMAV_PORT", "label": "ClamAV daemon port", "type": "int", "default": "3310", "min": 1, "max": 65535, "live": True},
    ],
    "workflow": [
        {"key": "DEFAULT_TICKET_PRIORITY", "label": "Default ticket priority", "type": "choice", "choices": ["P1", "P2", "P3", "P4"], "default": "P3", "live": True},
        {"key": "CHANGE_FREEZE_MESSAGE", "label": "Change freeze message", "type": "text", "default": "", "live": True},
        {"key": "SYNC_CHILD_INCIDENT_STATES", "label": "Synchronize parent incident state to children", "type": "bool", "default": "false", "live": True},
    ],
    "dashboard": [
        {"key": "DASHBOARD_SHOW_MY_ASSIGNED", "label": "Show \"Assigned to me\"", "type": "bool", "default": "true", "live": True},
        {"key": "DASHBOARD_SHOW_SLA_WIDGETS", "label": "Show SLA breached / at-risk widgets", "type": "bool", "default": "true", "live": True},
        {"key": "DASHBOARD_SHOW_RECENT", "label": "Show \"Recently updated\"", "type": "bool", "default": "true", "live": True},
        {"key": "SLA_AT_RISK_HOURS", "label": "SLA \"at risk\" warning window (hours)", "type": "int", "default": "4", "min": 1, "max": 72, "live": True},
    ],
    "email": [
        {"key": "SMTP_ENABLED", "label": "Enable SMTP delivery", "type": "bool", "default": "false", "live": True},
        {"key": "SMTP_HOST", "label": "SMTP host", "type": "text", "default": "", "live": True},
        {"key": "SMTP_PORT", "label": "SMTP port", "type": "int", "default": "587", "min": 1, "max": 65535, "live": True},
        {"key": "SMTP_STARTTLS", "label": "Require SMTP STARTTLS", "type": "bool", "default": "true", "live": True},
        {"key": "SMTP_USERNAME", "label": "SMTP username", "type": "text", "default": "", "live": True},
        {"key": "SMTP_PASSWORD", "label": "SMTP password", "type": "secret", "default": "", "live": True},
        {"key": "SMTP_FROM", "label": "SMTP from address", "type": "email", "default": "", "live": True},
    ],
    "change_governance": [
        {
            "key": "CCB_REQUIRED_ENVIRONMENTS", "type": "text", "default": "Production", "live": True,
            "label": "Environments that require CCB approval (comma-separated, e.g. Production, Staging)",
        },
    ],
    "cmdb_import": [
        {"key": "NETBOX_ENABLED", "label": "Enable NetBox sync", "type": "bool", "default": "false", "live": True},
        {"key": "NETBOX_BASE_URL", "label": "NetBox base URL", "type": "url", "default": "", "live": True},
        {"key": "NETBOX_API_TOKEN", "label": "NetBox API token", "type": "secret", "default": "", "live": True},
        {
            "key": "NETBOX_CA_CERT", "type": "text", "default": "", "live": True,
            "label": "NetBox CA certificate (PEM, only needed if NetBox uses an internal CA)",
        },
        {
            "key": "NETBOX_TLS_INSECURE", "type": "bool", "default": "false", "live": True,
            "label": "Skip NetBox TLS certificate verification (insecure — last resort, prefer the CA certificate above)",
        },
    ],
    "rt_import": [
        {"key": "RT_ENABLED", "label": "Enable Request Tracker (RT) import", "type": "bool", "default": "false", "live": True},
        {"key": "RT_BASE_URL", "label": "RT base URL", "type": "url", "default": "", "live": True},
        {"key": "RT_API_TOKEN", "label": "RT API token", "type": "secret", "default": "", "live": True},
        {
            "key": "RT_CA_CERT", "type": "text", "default": "", "live": True,
            "label": "RT CA certificate (PEM, only needed if RT uses an internal CA)",
        },
        {
            "key": "RT_TLS_INSECURE", "type": "bool", "default": "false", "live": True,
            "label": "Skip RT TLS certificate verification (insecure — last resort, prefer the CA certificate above)",
        },
    ],
}


def settings_cipher():
    configured = os.getenv("SETTINGS_ENCRYPTION_KEY", "")
    if configured:
        key = configured.encode()
    else:
        digest = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
        key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def setting_value(key, default=None):
    definition = next((item for group in SETTING_DEFINITIONS.values()
                       for item in group if item["key"] == key), None)
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
    return str(setting_value(key, str(default))).lower() in {"1", "true", "yes", "on"}


def setting_int(key, default=0):
    try:
        return int(setting_value(key, str(default)))
    except (TypeError, ValueError):
        return default


def create_notification(user_id, title, body, tenant_id=None, target_type=None, target_id=None):
    tenant_id = tenant_id or tenant_context_id()
    notification = Notification(
        user_id=user_id, title=title, body=body, tenant_id=tenant_id,
        target_type=target_type, target_id=target_id,
    )
    db.session.add(notification)
    db.session.add(OutboxEvent(
        event_type="notification.created",
        payload_json=json.dumps({
            "user_id": user_id, "title": title, "body": body,
        }, sort_keys=True),
        tenant_id=tenant_id,
    ))
    return notification


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


def integration_endpoint_resolves_safely(endpoint, allow_private_network=False):
    """Re-resolve the endpoint's hostname and reject it if any A/AAAA record is
    disallowed. A literal-IP/hostname string check alone (integration_endpoint_valid)
    cannot catch a public-looking hostname that resolves to a private address
    (DNS rebinding) -- this closes that gap at delivery time, immediately before
    the connection is made."""
    hostname = urlparse(endpoint).hostname
    if not hostname:
        return False
    try:
        address = ipaddress.ip_address(hostname)
        return _integration_address_allowed(address, allow_private_network)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False
    if not infos:
        return False
    for info in infos:
        raw_address = info[4][0]
        try:
            if not _integration_address_allowed(ipaddress.ip_address(raw_address), allow_private_network):
                return False
        except ValueError:
            return False
    return True


def deliver_smtp(event):
    payload = event.payload
    user = db.session.get(User, payload["user_id"])
    if not user or user.tenant_id != event.tenant_id or not user.email:
        raise RuntimeError("Notification recipient is unavailable.")
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
        if not integration_endpoint_valid(target) or not integration_endpoint_resolves_safely(target):
            raise RuntimeError("Webhook destination resolves to a non-routable or private address.")
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
        if setting_bool("SMTP_ENABLED"):
            prior = IntegrationDelivery.query.filter_by(
                outbox_event_id=event.id, channel="smtp", state="Delivered"
            ).first()
            if not prior:
                attempted = True
                try:
                    deliver_smtp(event)
                    db.session.add(IntegrationDelivery(
                        outbox_event_id=event.id, channel="smtp", state="Delivered",
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


TICKET_TRANSITIONS = {
    "New": ("New", "In Progress", "Pending", "Resolved", "Cancelled"),
    "In Progress": ("In Progress", "Pending", "Resolved", "Cancelled"),
    "Pending": ("Pending", "In Progress", "Resolved", "Cancelled"),
    "Resolved": ("Resolved", "In Progress", "Closed"),
    "Closed": ("Closed",),
    "Cancelled": ("Cancelled",),
    "Approved": ("Approved", "In Progress", "Cancelled"),
    "Awaiting Approval": ("Awaiting Approval", "Cancelled"),
    "Rejected": ("Rejected",),
}
ENTERPRISE_TRANSITIONS = {
    "New": ("New", "Open", "In Progress", "Pending", "Resolved", "Completed", "Closed"),
    "Open": ("Open", "In Progress", "Pending", "Resolved", "Completed", "Closed"),
    "In Progress": ("In Progress", "Pending", "Resolved", "Completed", "Closed"),
    "Pending": ("Pending", "In Progress", "Resolved", "Completed", "Closed"),
    "Resolved": ("Resolved", "In Progress", "Closed"),
    "Completed": ("Completed", "Closed"),
    "Closed": ("Closed",),
    "Approved": ("Approved", "In Progress", "Pending", "Completed", "Closed"),
    "Awaiting Approval": ("Awaiting Approval",),
    "Rejected": ("Rejected",),
}
STATE_TRACK_ORDER = {
    "incident": ["New", "In Progress", "Pending", "Resolved", "Closed"],
    "request": ["New", "In Progress", "Pending", "Resolved", "Closed"],
    "change": ["New", "Awaiting Approval", "Approved", "In Progress", "Pending", "Resolved", "Closed"],
    "problem": ["New", "Open", "In Progress", "Pending", "Resolved", "Completed", "Closed"],
    "ritm": ["Awaiting Approval", "Open", "Closed Complete"],
    "catalog_task": ["Open", "Work in Progress", "Pending", "Closed Complete"],
}


def build_state_track(kind, current_state):
    order = STATE_TRACK_ORDER.get(kind, STATE_TRACK_ORDER["incident"])
    if current_state not in order:
        return [{"name": step, "status": "upcoming"} for step in order] + [
            {"name": current_state, "status": "current"}
        ]
    idx = order.index(current_state)
    return [
        {"name": step, "status": "done" if i < idx else ("current" if i == idx else "upcoming")}
        for i, step in enumerate(order)
    ]


CATALOG_TASK_TRANSITIONS = {
    "Open": ("Open", "Work in Progress", "Pending", "Closed Incomplete", "Closed Skipped"),
    "Work in Progress": ("Work in Progress", "Pending", "Closed Complete", "Closed Incomplete", "Closed Skipped"),
    "Pending": ("Pending", "Work in Progress", "Closed Complete", "Closed Incomplete", "Closed Skipped"),
    "Closed Complete": ("Closed Complete",),
    "Closed Incomplete": ("Closed Incomplete",),
    "Closed Skipped": ("Closed Skipped",),
}
OPERATIONAL_TASK_TRANSITIONS = {
    "Open": ("Open", "Work in Progress", "Pending", "Closed Complete", "Closed Incomplete", "Cancelled"),
    "Work in Progress": ("Work in Progress", "Pending", "Closed Complete", "Closed Incomplete", "Cancelled"),
    "Pending": ("Pending", "Work in Progress", "Closed Complete", "Closed Incomplete", "Cancelled"),
    "Closed Complete": ("Closed Complete",),
    "Closed Incomplete": ("Closed Incomplete",),
    "Cancelled": ("Cancelled",),
}


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
        User.role.in_(["agent", "manager", "admin"]),
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
    if governance.change_type != "Standard" and change_requires_ccb(governance):
        ccb = SupportGroup.query.filter_by(name="Change Control Board").first()
        ccb_ids = [
            member.user_id for member in (ccb.members if ccb else [])
            if member.role == "CCB approver" and member.user.active
        ]
        if not ccb_ids:
            abort(409, description=(
                "CCB membership must be configured before a non-standard change can be submitted."
            ))
        if governance.change_type == "Emergency":
            # Accelerated but still auditable: one active CCB approver can
            # authorize immediately instead of waiting on the full board's
            # scheduled majority review (CLAUDE.md: "Submitted late" is not an
            # emergency justification — this only shortens the quorum required,
            # it never skips CCB authorization or the audit trail).
            stages.append({
                "name": "Emergency CCB authorization (expedited)", "mode": "any",
                "approver_ids": ccb_ids,
            })
        else:
            stages.append({
                "name": "CCB weekly authorization", "mode": "majority",
                "approver_ids": ccb_ids,
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
    log_history(
        "ticket", ticket.id, "Conflict detection completed",
        details=governance.conflict_status,
    )
    audit("conflict check", ticket.number, governance.conflict_status)
    return conflicts


def user_in_group(user, group):
    if not user.is_authenticated or not user.active or not group:
        return False
    return (
        user.role == "admin"
        or group.manager_id == user.id
        or GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first() is not None
    )


def activate_gate(gate, notify_title=None, notify_body=None):
    gate.state = "Requested"
    title = notify_title or f"Approval requested: {gate.name}"
    body = notify_body or f"Your decision is required for approval chain {gate.chain.name}."
    for vote in gate.votes:
        vote.state = "Requested"
        create_notification(
            vote.approver_id, title, body,
            tenant_id=gate.chain.tenant_id, target_type="approval_queue",
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


def attach_slas(target_type, target_id, priority):
    for definition in SLADefinition.query.filter_by(target_type=target_type, active=True).all():
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
        if state in ("Resolved", "Closed", "Completed", "Closed Complete"):
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
    return SupportGroup.query.filter_by(name="Service Desk", active=True).first()


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
    task = CatalogTask(number=sequence_number(CatalogTask, "SCTASK"), requested_item_id=ritm.id,
                       title=f"Fulfill {ritm.item.name}", assignment_group_id=group.id,
                       due_at=ritm.due_at)
    db.session.add(task)
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
    if not SupportGroup.query.filter_by(name="Service Desk").first():
        service_desk = SupportGroup(name="Service Desk", group_type="Fulfillment")
        security = SupportGroup(name="Security Operations", group_type="Fulfillment")
        db.session.add_all([service_desk, security])
    team_names = ["CoreApps", "Database", "Network", "Windows", "Unix", "SSD"]
    for team_name in team_names:
        group = SupportGroup.query.filter_by(name=team_name).first()
        if not group:
            group = SupportGroup(name=team_name, group_type="IT Fulfillment")
            db.session.add(group)
        else:
            group.group_type = "IT Fulfillment"
    ccb = SupportGroup.query.filter_by(name="Change Control Board").first()
    if not ccb:
        ccb = SupportGroup(name="Change Control Board", group_type="CCB Approval")
        db.session.add(ccb)
    db.session.flush()
    database_group = SupportGroup.query.filter_by(name="Database").first()
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
        for item in CatalogItem.query.all():
            normalized = f"{item.name} {item.category}".lower()
            if (
                ("laptop" in normalized or "software" in normalized)
                and not item.fulfillment_route
            ):
                db.session.add(CatalogItemRouting(
                    catalog_item_id=item.id, support_group_id=windows.id,
                    updated_by_id=admin.id,
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
        admin = User.query.filter_by(role="admin").first()
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
                 password_hash=generate_password_hash(admin_password), role="admin")
    db.session.add(admin)
    db.session.flush()
    seed_itil(admin)
    deploy_workflow_package(admin.id)
    db.session.commit()


def mapped_role(groups, mapping_name, default="requester"):
    """Map directory/realm groups to a ServiceOps role without trusting user input."""
    allowed = {"requester", "agent", "manager", "admin"}
    try:
        mappings = json.loads(setting_value(mapping_name, "{}"))
    except json.JSONDecodeError:
        mappings = {}
    normalized = normalized_directory_groups(groups)
    for group, role in mappings.items():
        if str(group).strip().casefold() in normalized and role in allowed:
            return role
    configured = setting_value(f"{mapping_name}_DEFAULT", default)
    return configured if configured in allowed else default


def normalized_directory_groups(groups):
    """Return case-insensitive full-DN and first-CN aliases for AD memberships."""
    normalized = set()
    for value in groups or []:
        group = str(value).strip()
        if not group:
            continue
        normalized.add(group.casefold())
        first_rdn = group.split(",", 1)[0].strip()
        if first_rdn.casefold().startswith("cn="):
            normalized.add(first_rdn[3:].strip().casefold())
    return normalized


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
            db.session.add(GroupMember(group_id=group_id, user_id=user.id, role="member"))
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


def normalize_user_role_from_assignments(user):
    """Keep non-admin user roles aligned with actual team responsibilities."""
    if not user or user.role == "admin":
        return user.role if user else "requester"
    manages_team = SupportGroup.query.filter_by(
        manager_id=user.id, active=True
    ).first() is not None
    if manages_team:
        user.role = "manager"
        return user.role
    has_team_membership = GroupMember.query.join(
        SupportGroup, GroupMember.group_id == SupportGroup.id
    ).filter(
        GroupMember.user_id == user.id,
        SupportGroup.active.is_(True),
    ).first() is not None
    user.role = "agent" if has_team_membership else "requester"
    return user.role


def user_is_local(user):
    """True if `user` authenticates with a local ServiceOps password rather
    than an external identity provider (LDAP, SSO). Externally-provisioned
    users have no usable local password -- provision_external_user() sets
    password_hash to a random, never-communicated value -- so the in-app
    change-password flow must only be offered to local accounts."""
    if user is None or not getattr(user, "id", None):
        return False
    return ExternalIdentity.query.filter_by(user_id=user.id).first() is None


def provision_external_user(provider, subject, username, name, email, role, groups=None):
    identity = ExternalIdentity.query.filter_by(provider=provider, subject=subject).first()
    if identity:
        user = identity.user
        user.name, user.email, user.role = name, email, role
        user.active = True
        if provider == "ldap":
            sync_directory_team_memberships(user, groups)
            normalize_user_role_from_assignments(user)
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
        existing_user.role = role
        existing_user.active = True
        db.session.add(ExternalIdentity(provider=provider, subject=subject, user_id=existing_user.id))
        if provider == "ldap":
            sync_directory_team_memberships(existing_user, groups)
            normalize_user_role_from_assignments(existing_user)
        return existing_user

    candidate, suffix = base, 1
    while User.query.filter_by(username=candidate).first():
        suffix += 1
        candidate = f"{base[:70]}-{suffix}"
    unique_email = (email or f"{candidate}@external.serviceops.local").lower()
    existing = User.query.filter_by(email=unique_email).first()
    if existing:
        unique_email = f"{provider}-{uuid.uuid4().hex[:8]}@external.serviceops.local"
    user = User(username=candidate, name=name or candidate, email=unique_email,
                password_hash=generate_password_hash(uuid.uuid4().hex), role=role)
    db.session.add(user)
    db.session.flush()
    db.session.add(ExternalIdentity(provider=provider, subject=subject, user_id=user.id))
    if provider == "ldap":
        sync_directory_team_memberships(user, groups)
        normalize_user_role_from_assignments(user)
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


def ldap_authenticate(username, password):
    if not password or not setting_bool("LDAP_ENABLED"):
        return None
    try:
        server, service = ldap_server_and_service_connection()
    except LdapBindError:
        return None
    use_ssl = bool(server.ssl)
    safe_username = escape_filter_chars(username)
    search_filter = setting_value(
        "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
    ).replace("{username}", safe_username)
    attrs = ["distinguishedName", "cn", "displayName", "mail", "memberOf", "userPrincipalName"]
    if not service.search(setting_value("LDAP_BASE_DN", ""), search_filter,
                          search_scope=SUBTREE, attributes=attrs, size_limit=2):
        service.unbind()
        return None
    entries = list(service.entries)
    service.unbind()
    if len(entries) != 1:
        return None
    entry = entries[0]
    user_conn = Connection(server, user=entry.entry_dn, password=password, auto_bind=False)
    user_conn.open()
    if not use_ssl and setting_bool("LDAP_START_TLS", True) and not user_conn.start_tls():
        return None
    if not user_conn.bind():
        return None
    user_conn.unbind()
    values = entry.entry_attributes_as_dict
    first = lambda key, fallback="": (values.get(key) or [fallback])[0]
    groups = values.get("memberOf", [])
    role = mapped_role(groups, "LDAP_ROLE_MAPPINGS")
    return provision_external_user(
        "ldap", entry.entry_dn, username, first("displayName", first("cn", username)),
        first("mail", first("userPrincipalName", "")), role, groups=groups)


def create_app(test_config=None):
    app = Flask(__name__)
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
        if app.config["KEYCLOAK_ENABLED"]:
            oauth.register(
                name="keycloak",
                client_id=setting_value("KEYCLOAK_CLIENT_ID"),
                client_secret=setting_value("KEYCLOAK_CLIENT_SECRET"),
                server_metadata_url=setting_value("KEYCLOAK_DISCOVERY_URL"),
                client_kwargs={"scope": "openid profile email"},
            )
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
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

    @app.before_request
    def verify_api_identity():
        if (
            request.path.startswith("/api/v1/")
            and request.endpoint not in {
                "api_openapi", "api_docs", "monitoring_ingest",
            }
        ):
            authenticate_api_request()

    @app.before_request
    def verify_csrf():
        if (
            request.path.startswith("/api/v1/monitoring/")
            or request.path.startswith("/api/v1/")
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
        if (
            app.config["CSRF_ENABLED"]
            and response.status_code < 400
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
        }
        if not current_user.is_authenticated:
            return platform_context
        preference = UserPreference.query.filter_by(user_id=current_user.id).first()
        if not preference:
            preference = UserPreference(user_id=current_user.id)
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
        }

    @app.get("/health")
    def health():
        db.session.execute(db.select(func.count(User.id))).scalar()
        return jsonify(status="ok", version=APP_VERSION)

    @app.get("/live")
    def live():
        return jsonify(status="alive")

    @app.get("/ready")
    def ready():
        db.session.execute(db.select(func.count(User.id))).scalar()
        return jsonify(status="ready")

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
        }
        if os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], "company-logo.png")):
            manifest["icons"] = [{
                "src": url_for("company_logo"),
                "sizes": "any",
                "type": "image/png",
                "purpose": "any maskable",
            }]
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
            "externalDocs": {"description": "Complete API guide", "url": "/api/v1/docs"},
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

    @app.get("/api/v1/docs")
    def api_docs():
        return send_from_directory(
            os.path.join(app.root_path, "docs"),
            "API_REFERENCE.md",
            mimetype="text/markdown",
            max_age=0,
        )

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
        task = OperationalTask(
            number=next_operational_task_number("event"),
            task_kind="event", parent_type="enterprise", parent_id=record.id,
            title=f"Investigate {resource}", task_type="Investigation",
            assignment_group_id=source.assignment_group_id, required=True,
        )
        db.session.add(task)
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

    @app.post("/api/v1/incidents")
    def api_incident_create():
        require_api_scope("incidents:create")
        if not role_has_action(g.api_user.role, "create"):
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
        ticket = Ticket(
            number=next_number("incident"), kind="incident",
            title=title, description=description,
            category=str(body.get("category", "General"))[:80],
            priority=priority, requester_id=g.api_user.id,
            tenant_id=g.api_client.tenant_id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=group.id))
        attach_slas("ticket", ticket.id, ticket.priority)
        log_history(
            "ticket", ticket.id, "Record created",
            details=f"{ticket.number} created through REST API and assigned to {group.name}.",
        )
        document = {"data": api_ticket_document(ticket, g.api_user)}
        store_api_idempotency(key, request_hash, document, 201)
        audit(
            "api create", ticket.number, f"client={g.api_client.client_id}",
            user_id=g.api_user.id, tenant_id=g.api_client.tenant_id,
        )
        db.session.commit()
        return jsonify(document), 201

    @app.patch("/api/v1/tickets/<number>")
    def api_ticket_update(number):
        require_api_scope("tickets:update")
        for action in ("update", "assign", "transition"):
            if not role_has_action(g.api_user.role, action):
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
            "api update", ticket.number, f"client={g.api_client.client_id}",
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
        if not role_has_action(g.api_user.role, "transition"):
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

    @app.after_request
    def security_headers(response):
        response.headers["X-Request-ID"] = g.get("request_id", str(uuid.uuid4()))
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
                if candidate and check_password_hash(candidate.password_hash, password):
                    user = candidate
            if user and user.active:
                user.failed_login_count = 0
                user.locked_until = None
                login_user(user)
                session.permanent = True
                session["_auth_version"] = user.auth_version
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
        realm_roles = claims.get("realm_access", {}).get("roles", [])
        role = mapped_role(realm_roles, "KEYCLOAK_ROLE_MAPPINGS")
        user = provision_external_user(
            "keycloak", subject, claims.get("preferred_username", ""),
            claims.get("name", ""), claims.get("email", ""), role)
        login_user(user)
        session.permanent = True
        session["_auth_version"] = user.auth_version
        session["_csrf_token"] = secrets.token_urlsafe(32)
        audit("login", user.username, "provider=keycloak")
        db.session.commit()
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        audit("logout", current_user.username)
        db.session.commit()
        logout_user()
        session.clear()
        return redirect(url_for("login"))

    @app.route("/profile/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if not user_is_local(current_user):
            abort(403, description="Your password is managed by your organization's login provider, not ServiceOps.")
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirmation = request.form.get("confirm_password", "")
            if not check_password_hash(current_user.password_hash, current_password):
                abort(400, description="The current password is incorrect.")
            min_length = setting_int("PASSWORD_MIN_LENGTH", 14)
            if len(new_password) < min_length:
                abort(400, description=f"The new password must contain at least {min_length} characters.")
            if new_password != confirmation:
                abort(400, description="The password confirmation does not match.")
            if check_password_hash(current_user.password_hash, new_password):
                abort(400, description="The new password must differ from the current password.")
            current_user.password_hash = generate_password_hash(new_password)
            current_user.auth_version += 1
            session["_auth_version"] = current_user.auth_version
            audit("credential rotate", current_user.username, "Local password changed")
            db.session.commit()
            flash("Password changed. Other browser sessions have been invalidated.", "success")
            return redirect(url_for("preferences"))
        return render_template("change_password.html")

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
        if current_user.role == "admin":
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
            if current_user.role == "admin":
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
        if kind == "change" and current_user.role == "requester" and not eligible_it_team_ids:
            abort(403)

        def render_form(error=None):
            teams_query = tenant_query(SupportGroup).filter_by(
                group_type="IT Fulfillment", active=True
            )
            if kind == "change" and current_user.role != "admin":
                if eligible_it_team_ids:
                    teams_query = teams_query.filter(SupportGroup.id.in_(eligible_it_team_ids))
                else:
                    teams_query = teams_query.filter(SupportGroup.id == -1)
            return render_template(
                "ticket_form.html", kind=kind, teams=teams_query.order_by(SupportGroup.name).all(),
                state_track=build_state_track(kind, "New"),
                default_priority=setting_value("DEFAULT_TICKET_PRIORITY", "P3"),
                change_freeze_message=setting_value("CHANGE_FREEZE_MESSAGE", ""),
                service_offerings=tenant_query(ServiceOffering).filter_by(
                    status="Operational"
                ).order_by(ServiceOffering.name).all(),
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
                and current_user.role != "admin"
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
            if request.form.get("ci_id"):
                try:
                    ci_id = int(request.form["ci_id"])
                except (TypeError, ValueError):
                    return render_form("The selected configuration item is invalid.")
                if not tenant_query(ConfigurationItem).filter_by(id=ci_id).first():
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
                request.form.get("change_type", "Normal"),
                db.session.get(ConfigurationItem, ci_id) if ci_id else None,
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
            ticket = Ticket(number=next_number(kind), kind=kind,
                            title=title, description=description,
                            category=request.form.get("category", "General"), priority=priority,
                            impact=impact, urgency=urgency,
                            subcategory=request.form.get("subcategory", "").strip(),
                            contact_type=contact_type, notify=notify,
                            service_offering_id=offering.id if offering else None,
                            requester_id=current_user.id)
            db.session.add(ticket)
            db.session.flush()
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
                initial_task = OperationalTask(
                    number=next_operational_task_number("change"),
                    task_kind="change", parent_type="ticket", parent_id=ticket.id,
                    title="Implementation", task_type="Implementation",
                    sequence=1, assignment_group_id=owning_group.id,
                    planned_start=governance.planned_start, planned_end=governance.planned_end,
                    required=True, work_notes=implementation_notes, state="Pending",
                )
                db.session.add(initial_task)
                db.session.flush()
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
                if not role_has_action(current_user.role, "comment_public"):
                    abort(403)
                body = request.form.get("body", "").strip()
                upload = request.files.get("file")
                if body:
                    comment = Comment(ticket_id=ticket.id, user_id=current_user.id, body=body)
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
                if not role_has_action(current_user.role, "resolve"):
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
                if not role_has_action(current_user.role, "resolve"):
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
                    if not role_has_action(current_user.role, required_action):
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
                    and (current_user.role not in ("manager", "admin") or len(reason) < 10)
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
            and role_has_action(current_user.role, "resolve")
        )
        internal_view = role_has_action(current_user.role, "comment_internal")
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
        calculated_risk_score = calculate_change_risk_score(
            request.form.get("change_type", governance.change_type),
            db.session.get(ConfigurationItem, ci_id) if ci_id else None,
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
        if ci_id and not tenant_query(ConfigurationItem).filter(ConfigurationItem.id == ci_id).first():
            return plan_form_error("The selected configuration item does not exist.")
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
        ci = tenant_record_or_404(ConfigurationItem, int(request.form["ci_id"]))
        role = request.form.get("relationship_role")
        if role not in ("Primary CI", "Affected CI", "Impacted service"):
            abort(400)
        if role == "Primary CI":
            TaskCI.query.filter_by(
                target_type=target_type, target_id=target_id,
                relationship_role="Primary CI",
            ).delete()
        exists = TaskCI.query.filter_by(
            target_type=target_type, target_id=target_id, ci_id=ci.id,
            relationship_role=role,
        ).first()
        if not exists:
            db.session.add(TaskCI(
                target_type=target_type, target_id=target_id,
                ci_id=ci.id, relationship_role=role,
            ))
            log_history(
                target_type, target_id, "Configuration item linked",
                details=f"{role}: {ci.name}",
            )
            audit("link CI", record_number(target), f"{role}: {ci.name}")
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
        task = OperationalTask(
            number=next_operational_task_number("change"),
            task_kind="change", parent_type="ticket", parent_id=ticket.id,
            title=request.form["title"].strip(), task_type=task_type,
            sequence=OperationalTask.query.filter_by(
                parent_type="ticket", parent_id=ticket.id
            ).count() + 1,
            assignment_group_id=group.id,
            planned_start=planned_start, planned_end=planned_end,
            required=bool(request.form.get("required")),
            state="Open" if task_type == "Planning" else "Pending",
        )
        db.session.add(task)
        db.session.flush()
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
            User.role.in_(["agent", "manager", "admin"]),
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
            can_edit=current_user.role == "admin",
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
                    "options": [(r, r) for r in ["requester", "agent", "manager", "admin"]]},
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
            user = User(username=request.form["username"], name=request.form["name"], email=request.form["email"],
                        password_hash=generate_password_hash(request.form["password"]), role=request.form["role"],
                        title=request.form.get("title", "")[:120],
                        department=request.form.get("department", "")[:120],
                        business_phone=request.form.get("business_phone", "")[:40],
                        mobile_phone=request.form.get("mobile_phone", "")[:40],
                        timezone=request.form.get("timezone", "Asia/Tokyo")[:80],
                        date_format=request.form.get("date_format", "system")[:40])
            db.session.add(user)
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
            user.role = request.form["role"]
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

    @app.get("/admin")
    @roles("admin")
    @require_action("security_administer")
    def admin_home():
        return render_template("admin_home.html")

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
                    f"Workflow package validated; {result['published']} new version(s) published.",
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
                return redirect(url_for("workflows_admin"))
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
                return redirect(url_for("workflows_admin"))
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

    @app.route("/admin/settings", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def system_settings():
        definitions = [item for group in SETTING_DEFINITIONS.values() for item in group]
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
                audit("update", "System settings", ", ".join(changed) or "No value changes")
                db.session.commit()
                flash("System settings saved." + (
                    " Restart or roll out all application instances to apply marked settings."
                    if restart_required else ""), "success")
                return redirect(url_for("system_settings"))
        values = {}
        for definition in definitions:
            value = setting_value(definition["key"], definition.get("default", ""))
            values[definition["key"]] = "" if definition["type"] == "secret" else value
            definition["configured"] = bool(value) if definition["type"] == "secret" else False
        infrastructure = [
            ("Deployment profile", app.config["DEPLOYMENT_PROFILE"], "Docker environment / Helm values"),
            ("Database", app.config["SQLALCHEMY_DATABASE_URI"].split("@")[-1], "DATABASE_URL / Kubernetes Secret"),
            ("Upload storage", app.config["UPLOAD_FOLDER"], "Docker volume / Kubernetes PVC"),
            ("Application replicas", os.getenv("REPLICA_COUNT", "Controlled externally"), "Docker Compose / Helm"),
            ("Ingress and TLS", "Controlled externally", "Reverse proxy / Kubernetes Ingress"),
        ]
        return render_template("system_settings.html", groups=SETTING_DEFINITIONS,
                               values=values, infrastructure=infrastructure)

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
        if current_user.role == "requester" and domain not in ("customer", "hr"):
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
            if request.form.get("approval_required") and current_user.role != "requester":
                admin = User.query.filter_by(role="admin", active=True).first()
                db.session.add(Approval(enterprise_record_id=record.id, approver_id=admin.id))
                create_notification(
                    admin.id, f"Approval requested: {record.number}",
                    record.title, tenant_id=record.tenant_id,
                    target_type="enterprise", target_id=record.id,
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
                )
                log_history(
                    "enterprise", record.id, f"Approval {approval.state.lower()}",
                    details=approval.comments,
                )
                audit(action, record.number)
            db.session.commit()
            return redirect(url_for("enterprise_detail", record_id=record.id))
        agents = User.query.filter(User.role.in_(["agent", "manager", "admin"]), User.active.is_(True)).all()
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
                User.role.in_(["agent", "manager", "admin"]),
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
        task = OperationalTask(
            number=next_operational_task_number("problem"),
            task_kind="problem", parent_type="enterprise", parent_id=record.id,
            title=request.form["title"].strip(),
            task_type=request.form.get("task_type", "Investigation"),
            sequence=OperationalTask.query.filter_by(
                parent_type="enterprise", parent_id=record.id
            ).count() + 1,
            assignment_group_id=group.id,
            required=bool(request.form.get("required")),
        )
        db.session.add(task)
        db.session.flush()
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
        db.session.flush()
        audit("create", item.number, item.title)
        db.session.commit()
        flash(f"{item.number} raised as a continual-improvement item.", "success")
        redirect_to = request.form.get("redirect_to")
        if redirect_to and redirect_to.startswith("/"):
            return redirect(redirect_to)
        return redirect(url_for("improvement_detail", item_id=item.id))

    @app.get("/improvement/<int:item_id>")
    @roles("agent", "manager", "admin")
    def improvement_detail(item_id):
        item = tenant_record_or_404(ImprovementItem, item_id)
        source = record_reference(item.source_type, item.source_id) if item.source_type and item.source_id else None
        agents = tenant_query(User).filter(
            User.role.in_(["agent", "manager", "admin"]), User.active.is_(True)
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
            manager = tenant_query(User).filter_by(role="admin", active=True).first()
            fulfillment = tenant_query(SupportGroup).filter_by(name="Service Desk", active=True).first()
            fulfillment_approver_ids = [member.user_id for member in fulfillment.members] if fulfillment else []
            if not manager or not fulfillment_approver_ids:
                flash(
                    f"{item.name} cannot be requested yet: no active administrator or "
                    "Service Desk team member is configured to approve it. Contact an administrator.",
                    "error",
                )
                return redirect(url_for("catalog"))
        req = CatalogRequest(number=sequence_number(CatalogRequest, "REQ"), requested_by_id=current_user.id,
                             requested_for_id=current_user.id)
        db.session.add(req)
        db.session.flush()
        ritm = RequestedItem(number=sequence_number(RequestedItem, "RITM"), request_id=req.id,
                             catalog_item_id=item.id, state="Awaiting Approval" if item.approval_required else "Open",
                             stage="Approval" if item.approval_required else "Fulfillment",
                             variables_json=json.dumps({"details": request.form.get("details", "")}),
                             due_at=now() + timedelta(days=item.delivery_days))
        db.session.add(ritm)
        db.session.flush()
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
        query = tenant_query(ConfigurationItem)
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
        cis_total = tenant_query(ConfigurationItem).count()
        operational_total = tenant_query(ConfigurationItem).filter(
            ConfigurationItem.operational_status == "Operational"
        ).count()
        relationships = tenant_query(CIRelationship).all()
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
        query = tenant_query(ConfigurationItem)
        if status:
            query = query.filter(ConfigurationItem.operational_status == status)
        query = apply_filter_conditions(query, conditions, cmdb_filter_field_spec())
        cis = query.order_by(ConfigurationItem.ci_class, ConfigurationItem.name).all()
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

    def _ci_attributes_from_form():
        keys = request.form.getlist("attr_key")
        values = request.form.getlist("attr_value")
        attributes = {}
        for key, value in zip(keys, values):
            key = key.strip()
            value = value.strip()
            if key and value:
                attributes[key] = value
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
    @roles("admin")
    def ci_new():
        if request.method == "POST":
            name = request.form["name"].strip()
            serial_number = request.form.get("serial_number", "").strip() or None
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
            ci_class = request.form["ci_class"].strip()
            environment = normalize_environment(request.form["environment"])
            business_criticality = request.form.get("business_criticality", "Medium")
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
            )
            db.session.add(ci)
            audit("create", "CI", ci.name)
            db.session.commit()
            flash(f"{ci.name} created.", "success")
            return redirect(url_for("cmdb"))
        support_groups = tenant_query(SupportGroup).filter_by(active=True).order_by(SupportGroup.name).all()
        return render_template("ci_form.html", support_groups=support_groups)

    @app.route("/cmdb/<int:ci_id>/edit", methods=["GET", "POST"])
    @roles("admin")
    def ci_edit(ci_id):
        ci = tenant_record_or_404(ConfigurationItem, ci_id)
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
            before = {field: getattr(ci, field) or "" for field in tracked_fields}
            before["attributes"] = json.dumps(ci.attributes or {}, sort_keys=True)
            ci.name = request.form["name"].strip()
            ci.ci_class = request.form["ci_class"].strip()
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
            ci.attributes = _ci_attributes_from_form()
            ci.require_ccb_approval = (
                ci_always_requires_ccb(ci.ci_class, ci.environment, ci.business_criticality)
                or request.form.get("require_ccb_approval") == "on"
            )
            after = {field: getattr(ci, field) or "" for field in tracked_fields}
            after["attributes"] = json.dumps(ci.attributes or {}, sort_keys=True)
            log_field_changes("ci", ci.id, before, after)
            audit("update", "CI", ci.name)
            db.session.commit()
            flash(f"{ci.name} updated.", "success")
            return redirect(url_for("cmdb"))
        owners = tenant_query(User).filter_by(active=True).order_by(User.name).all()
        support_groups = tenant_query(SupportGroup).filter_by(active=True).order_by(SupportGroup.name).all()
        history = TaskHistory.query.filter_by(
            target_type="ci", target_id=ci.id
        ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).limit(50).all()
        impacted_ids = ci_impact_set(ci.tenant_id, {ci.id}) - {ci.id}
        impacted_cis = tenant_query(ConfigurationItem).filter(ConfigurationItem.id.in_(impacted_ids)).all() if impacted_ids else []
        return render_template(
            "ci_form.html", ci=ci, owners=owners, support_groups=support_groups, history=history,
            impacted_cis=impacted_cis,
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
                    if not integration_endpoint_valid(export_url) or not integration_endpoint_resolves_safely(export_url):
                        flash("That sheet URL could not be reached safely.", "error")
                        return render_template("cmdb_import.html", preview=None, csv_text="",
                                                netbox_enabled=setting_bool("NETBOX_ENABLED"),
                                                netbox_sync_result=session.pop("netbox_sync_result", None))
                    try:
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
                f"{result['cis_updated']} updated, {len(result['errors'])} errors",
            )
            session["netbox_sync_result"] = result
            flash(
                (
                    "NetBox sync preview: " if dry_run else "NetBox sync applied: "
                ) + (
                    f"{result['devices_seen']} devices seen, {result['cis_created']} created, "
                    f"{result['cis_updated']} updated, {len(result['errors'])} errors."
                ),
                "success" if not result["errors"] else "warning",
            )
        return redirect(url_for("cmdb_import"))

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
        return render_template(
            "rt_import.html", rt_enabled=setting_bool("RT_ENABLED"), recent_jobs=recent_jobs,
        )

    @app.post("/cmdb/relationships")
    @roles("admin")
    def ci_relationship_add():
        parent = tenant_record_or_404(ConfigurationItem, int(request.form["parent_id"]))
        child = tenant_record_or_404(ConfigurationItem, int(request.form["child_id"]))
        if parent.id == child.id:
            abort(400, description="A configuration item cannot depend on itself.")
        relationship_type = request.form.get("relationship_type", "Depends on")
        if relationship_type not in CI_RELATIONSHIP_TYPES:
            abort(400, description="Select a valid relationship type.")
        existing = tenant_query(CIRelationship).filter_by(
            parent_id=parent.id, child_id=child.id, relationship_type=relationship_type,
        ).first()
        if not existing:
            db.session.add(CIRelationship(parent_id=parent.id, child_id=child.id, relationship_type=relationship_type))
            audit("create", "CI relationship", f"{parent.name} — {relationship_type} → {child.name}")
            db.session.commit()
            flash(f"Linked {parent.name} to {child.name}.", "success")
        return redirect(url_for("cmdb"))

    @app.post("/cmdb/relationships/<int:relationship_id>/delete")
    @roles("admin")
    def ci_relationship_delete(relationship_id):
        relationship = tenant_record_or_404(CIRelationship, relationship_id)
        audit("delete", "CI relationship", f"{relationship.parent.name} — {relationship.child.name}")
        db.session.delete(relationship)
        db.session.commit()
        flash("Relationship removed.", "success")
        return redirect(url_for("cmdb"))

    @app.get("/approvals")
    @login_required
    def approvals():
        query = Approval.query.join(EnterpriseRecord).filter(
            EnterpriseRecord.tenant_id == current_user.tenant_id
        )
        if current_user.role != "admin":
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
            if current_user.role == "admin" or any(
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
        ritm = RequestedItem(
            number=sequence_number(RequestedItem, "RITM"), request_id=req.id,
            catalog_item_id=item.id,
            state="Awaiting Approval" if item.approval_required else "Open",
            stage="Approval" if item.approval_required else "Fulfillment",
            variables_json=json.dumps({"details": request.form.get("details", "")}),
            due_at=now() + timedelta(days=item.delivery_days),
        )
        db.session.add(ritm)
        db.session.flush()
        attach_slas("ritm", ritm.id, None)
        if item.approval_required:
            manager = User.query.filter_by(role="admin", active=True).first()
            fulfillment = SupportGroup.query.filter_by(name="Service Desk").first()
            approvers = [member.user_id for member in fulfillment.members if member.user.active]
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
        task = CatalogTask(
            number=sequence_number(CatalogTask, "SCTASK"),
            requested_item_id=ritm.id,
            title=request.form["title"].strip(),
            sequence=len(ritm.tasks) + 1,
            assignment_group_id=group.id,
            due_at=ritm.due_at,
        )
        db.session.add(task)
        db.session.flush()
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
            User.role.in_(["agent", "manager", "admin"]),
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

    @app.route("/itil/administration", methods=["GET", "POST"])
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
                if group.group_type != "IT Fulfillment":
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
                            group_id=group.id, user_id=manager.id, role="manager"
                        ))
                    normalize_user_role_from_assignments(manager)
                if old_manager_id and old_manager_id != manager_id:
                    old_manager = db.session.get(User, old_manager_id)
                    normalize_user_role_from_assignments(old_manager)
                audit("configure", f"{group.name} manager",
                      manager.username if manager else "Unassigned")
                flash(f"{group.name} manager updated.", "success")
            elif action == "set_ccb_authority":
                user = tenant_record_or_404(User, int(request.form["user_id"]))
                ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
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
                            group_id=ccb.id, user_id=user.id, role="CCB approver"
                        ))
                elif membership:
                    db.session.delete(membership)
                audit("configure", "CCB approval authority",
                      f"{user.username}: {'granted' if enabled else 'revoked'}")
                flash("CCB approval authority updated.", "success")
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
                    route = CatalogItemRouting(catalog_item_id=item.id)
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
                    route = CatalogItemRouting(catalog_item_id=item.id)
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
                if not name or target_type not in ("ticket", "ritm") or priority not in (None, "P1", "P2", "P3", "P4"):
                    abort(400, description="SLA name, target and priority are invalid.")
                if duration < 1 or duration > 525600:
                    abort(400, description="SLA duration must be between 1 and 525600 minutes.")
                schedule = tenant_record_or_404(BusinessSchedule, schedule_id) if schedule_id else None
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
                ))
                audit("create", f"SLA definition: {name}",
                      f"{agreement_type}; {duration} minutes; {schedule.name if schedule else '24x7'}")
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
                ci = tenant_record_or_404(ConfigurationItem, int(request.form["ci_id"]))
                role = request.form.get("relationship_role", "Supporting")
                if role not in ("Primary", "Supporting"):
                    abort(400)
                existing_link = ServiceOfferingCI.query.filter_by(
                    service_offering_id=service.id, ci_id=ci.id
                ).first()
                if existing_link:
                    existing_link.relationship_role = role
                else:
                    db.session.add(ServiceOfferingCI(
                        service_offering_id=service.id, ci_id=ci.id, relationship_role=role,
                    ))
                audit("configure", f"{service.name} service mapping", f"{role}: {ci.name}")
                flash(f"{ci.name} linked to {service.name}.", "success")
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
                            f"{result['memberships_added']} memberships added, "
                            f"{result['memberships_removed']} memberships removed, "
                            f"{result['users_unmatched']} unmatched entries, "
                            f"{len(result['errors'])} errors."
                        ),
                        "success" if not result["errors"] else "warning",
                    )
                return redirect(url_for("itil_admin"))
            else:
                abort(400)
            db.session.commit()
            return redirect(url_for("itil_admin"))
        groups = tenant_query(SupportGroup).order_by(SupportGroup.name).all()
        teams = [group for group in groups if group.group_type == "IT Fulfillment"]
        fulfillment_groups = [
            group for group in groups
            if group.active and group.group_type in ("Fulfillment", "IT Fulfillment")
        ]
        manager_candidates = tenant_query(User).filter(
            User.active.is_(True)
        ).order_by(User.name).all()
        ccb_candidates = tenant_query(User).filter(
            User.active.is_(True),
            User.role == "manager",
        ).order_by(User.name).all()
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
        ccb_approver_ids = {
            member.user_id for member in ccb.members if member.role == "CCB approver"
        }
        return render_template(
            "itil_admin.html", groups=groups, teams=teams,
            manager_candidates=manager_candidates, ccb_candidates=ccb_candidates,
            ccb=ccb, ccb_approver_ids=ccb_approver_ids,
            directory_mappings=DirectoryGroupMapping.query.order_by(
                DirectoryGroupMapping.directory_group
            ).all(),
            support_group_aliases=tenant_query(SupportGroupAlias).order_by(
                SupportGroupAlias.alias
            ).all(),
            services=tenant_query(ServiceOffering).all(),
            sla_definitions=tenant_query(SLADefinition).all(),
            business_schedules=tenant_query(BusinessSchedule).order_by(
                BusinessSchedule.name
            ).all(),
            catalog_items=tenant_query(CatalogItem).order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
            fulfillment_groups=fulfillment_groups,
            ldap_enabled=setting_bool("LDAP_ENABLED"),
            ldap_sync_result=session.pop("ldap_sync_result", None),
            change_freeze_windows=tenant_query(ChangeFreezeWindow).order_by(
                ChangeFreezeWindow.starts_at.desc()
            ).all(),
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
        record_ids = [row.id for row in visible_enterprise_record_query(current_user).all()]
        overdue_records = EnterpriseRecord.query.filter(
            EnterpriseRecord.id.in_(record_ids), EnterpriseRecord.due_at < now(),
            EnterpriseRecord.state.notin_(["Closed", "Resolved", "Completed"])
        ).order_by(EnterpriseRecord.due_at).all()
        return render_template("analytics_overdue.html", overdue_records=overdue_records, modules=DOMAIN_CONFIG)

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
            visible_ticket_ids = {
                row.id for row in visible_ticket_query(current_user).all()
            }
            visible_enterprise_ids = {
                row.id for row in visible_enterprise_record_query(current_user).all()
            }
            visible_request_ids = {
                row.id for row in visible_catalog_request_query(current_user).all()
            }
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
                ci_url = url_for("ci_edit", ci_id=row.id) if current_user.role == "admin" else url_for("cmdb")
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
                if isinstance(parent, Ticket) and parent.id not in visible_ticket_ids:
                    continue
                if isinstance(parent, EnterpriseRecord) and parent.id not in visible_enterprise_ids:
                    continue
                results.append({
                    "type": "Change task" if row.task_kind == "change" else "Problem task",
                    "label": f"{row.number} · {row.title}",
                    "url": record_url(parent), "meta": row.state,
                })
        if request.accept_mimetypes.best == "application/json":
            return jsonify(results=[
                project_document("search_result", current_user.role, row)
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
            "ui_action_ack", current_user.role, {"active": active}
        ))

    @app.post("/ui/history")
    @login_required
    def history_record():
        url = request.form.get("url", "")[:500]
        if not is_safe_internal_path(url) or url.startswith(("/static", "/health", "/ui/")):
            return ("", 204)
        row = RecentView.query.filter_by(user_id=current_user.id, url=url).first()
        if row:
            row.label = request.form.get("label", row.label)[:180]
            row.viewed_at = now()
        else:
            db.session.add(RecentView(user_id=current_user.id, url=url,
                                      label=request.form.get("label", "Page")[:180]))
        db.session.commit()
        return ("", 204)

    @app.route("/preferences", methods=["GET", "POST"])
    @login_required
    def preferences():
        pref = UserPreference.query.filter_by(user_id=current_user.id).first()
        if not pref:
            pref = UserPreference(user_id=current_user.id)
            db.session.add(pref)
        if request.method == "POST":
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
        return render_template("preferences.html", pref=pref)

    @app.get("/task-board")
    @login_required
    def task_board():
        query = visible_tickets()
        tickets_by_state = {state: query.filter_by(state=state).order_by(Ticket.priority, Ticket.updated_at.desc()).all()
                            for state in ["New", "In Progress", "Pending", "Resolved", "Closed"]}
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
            "ui_action_ack", current_user.role, {"state": state}
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
        attachment = FileAttachment(
            ticket_id=ticket.id, comment_id=comment_id, uploaded_by_id=current_user.id,
            original_name=original, stored_name=stored,
            mime_type=verified_mime_type, size_bytes=os.path.getsize(path),
            sha256=sha256.hexdigest(), scan_status=scan_status,
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
        elif not user_can_view_ticket(current_user, attachment.ticket):
            abort(403)
        # Only the handful of types a browser renders safely natively
        # (never HTML/SVG, which could execute script if opened inline)
        # are ever served inline -- everything else always forces a
        # download regardless of the `view` param.
        inline = (
            request.args.get("view") == "1"
            and attachment.mime_type in PREVIEWABLE_ATTACHMENT_TYPES
        )
        return send_from_directory(
            app.config["UPLOAD_FOLDER"], attachment.stored_name,
            as_attachment=not inline, download_name=attachment.original_name,
            mimetype=attachment.mime_type if inline else None,
        )

    @app.get("/help")
    @login_required
    def help_center():
        return render_template("help.html")

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

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080, debug=True)
