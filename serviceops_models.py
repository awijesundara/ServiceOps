"""SQLAlchemy models for ServiceOps.

Extracted from app.py (Phase 0 of the app.py blueprint decomposition --
see the plan at the time of this change) so every model has one stable
home that later route-extraction phases can import from without
depending on app.py's create_app() internals.

Also holds the handful of small primitives models directly depend on for
column defaults/properties (db, now(), tenant_context_id(),
settings_cipher(), ROLE_RANK, TenantResolutionError) -- these moved here
specifically to avoid a circular import (app.py needs models from this
module; these primitives have zero model dependencies of their own, so
the dependency only ever points one way).

app.py re-exports every name from this module unchanged, so
`from app import Ticket, db, now, ...` keeps working exactly as before
for every existing caller (tests, serviceops_core/*, tools/*,
migrations/*) -- this module is additive, not a behavior change.
"""
import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, time as dt_time, timedelta, timezone

from cryptography.fernet import Fernet
from flask import current_app, has_request_context, session
from flask_login import UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy

__all__ = [
    "db",
    "now",
    "tenant_context_id",
    "settings_cipher",
    "ROLE_RANK",
    "TenantResolutionError",
    "CI_RELATIONSHIP_TYPES",
    "SLA_AGREEMENT_TYPES",
    "CHANGE_PIR_OUTCOMES",
    "IMPROVEMENT_STATES",
    "Tenant",
    "User",
    "ExternalIdentity",
    "UserSession",
    "PasswordResetToken",
    "PlatformSetting",
    "KpiSnapshot",
    "KpiSnapshotState",
    "RTImportJob",
    "LdapSyncState",
    "Ticket",
    "Comment",
    "TaskNote",
    "Knowledge",
    "Asset",
    "Audit",
    "AuditIntegrityKey",
    "AuditRetentionPolicy",
    "ApplicationLog",
    "APIClient",
    "APIIdempotencyRecord",
    "APIRateLimitWindow",
    "RouteRateLimitWindow",
    "RequestMetricTotal",
    "PerformanceSample",
    "IntegrationConnection",
    "OutboxEvent",
    "IntegrationDelivery",
    "MonitoringSource",
    "MonitoringEvent",
    "EnterpriseRecord",
    "ClientOrganization",
    "ClientOrganizationAccess",
    "ClientCustomFieldDefinition",
    "ClientView",
    "ClientMacro",
    "ClientTrigger",
    "ClientMailbox",
    "ClientContact",
    "ClientTicket",
    "ClientTicketMessage",
    "Approval",
    "CatalogItem",
    "CatalogItemRouting",
    "ConfigurationItem",
    "Rack",
    "RolePolicyOverride",
    "CiClassPermission",
    "CIRelationship",
    "DiscoveryTarget",
    "DiscoveryCandidate",
    "ServiceOfferingCI",
    "ServiceOutage",
    "Notification",
    "SupportGroup",
    "GroupMember",
    "DirectoryGroupMapping",
    "SupportGroupAlias",
    "DirectoryManagedMembership",
    "UserRoleGrant",
    "ManagedRoleGrant",
    "ApprovalChain",
    "ApprovalGate",
    "ApprovalVote",
    "ServiceOffering",
    "SLADefinition",
    "TaskSLA",
    "BusinessSchedule",
    "ScheduleHoliday",
    "SLAEvent",
    "WorkflowDefinition",
    "WorkflowVersion",
    "WorkflowJob",
    "WorkflowExecution",
    "WorkflowStepExecution",
    "WorkflowSchedule",
    "CatalogRequest",
    "RequestedItem",
    "CatalogTask",
    "CatalogTaskControl",
    "ChangeGovernance",
    "ChangeFreezeWindow",
    "ChangePostImplementationReview",
    "ChangeOwnership",
    "TicketAssignmentGroup",
    "RecordLink",
    "TaskHistory",
    "OperationalTask",
    "TaskCI",
    "ProblemProfile",
    "ChangeRevision",
    "MajorIncidentProfile",
    "ImprovementItem",
    "Favorite",
    "RecentView",
    "UserPreference",
    "ChecklistItem",
    "FileAttachment",
    "DATA_CLASSIFICATION_REGISTRY",
    "DataRetentionPolicy",
    "RecordLegalHold",
    "GuidedTour",
    "GuidedTourStep",
    "UserTourProgress",
]

db = SQLAlchemy()

ROLE_RANK = {"requester": 0, "agent": 1, "manager": 2, "admin": 3, "superadmin": 4}


def now():
    return datetime.now(timezone.utc)


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


def settings_cipher():
    configured = os.getenv("SETTINGS_ENCRYPTION_KEY", "")
    if configured:
        key = configured.encode()
    else:
        digest = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
        key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


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
    # GDPR Art. 17 (right to erasure): set when an admin scrubs this account's
    # personal data. Distinct from `active` -- deactivation alone retains
    # name/email/phone/department indefinitely, which is not erasure.
    erased_at = db.Column(db.DateTime(timezone=True))
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    manager_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    manager = db.relationship("User", remote_side=[id], foreign_keys=[manager_id])
    # TOTP MFA (ISO 27001 A.8.5). The TOTP secret and backup-code hashes are
    # Fernet-encrypted at rest via settings_cipher(), same as other secrets
    # (see app.py's SETTING_SCHEMA "secret" fields). Backup codes are stored
    # hashed (not merely encrypted) so even a key-compromise-plus-DB-read
    # can't be used to log in with a backup code without brute-forcing it.
    mfa_secret_encrypted = db.Column(db.Text)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    mfa_enrolled_at = db.Column(db.DateTime(timezone=True))
    mfa_backup_codes_json = db.Column(db.Text)
    # Updated at most once/minute per user (see track_last_seen) -- backs
    # the System Health "currently active users" count, not an exact
    # per-request timestamp.
    last_seen_at = db.Column(db.DateTime(timezone=True))

    @property
    def is_active(self):
        return bool(self.active)

    @property
    def granted_roles(self):
        """Every role this user currently holds (may be more than one --
        e.g. both "manager" and "admin"), highest-ranked first."""
        roles = {grant.role for grant in UserRoleGrant.query.filter_by(user_id=self.id).all()}
        roles.add(self.role)  # defensive: self.role should always be a member already
        return sorted(roles, key=lambda r: ROLE_RANK.get(r, -1), reverse=True)

    @property
    def effective_role(self):
        """The role authorization checks should use for this request: the
        session's "acting as" selection if the user actually still holds
        that role, else their highest granted role (self.role). This is a
        real demotion, not a UI label -- every authorization check in this
        file reads effective_role, so a superadmin+admin+manager who
        switches to "requester" genuinely loses admin/manager authority
        until they switch back, including against direct route/API calls."""
        acting_as = session.get("_acting_role") if has_request_context() else None
        if acting_as and acting_as in self.granted_roles:
            return acting_as
        return self.role


class ExternalIdentity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("provider", "subject", name="uq_external_identity"),)


class UserSession(db.Model):
    """Server-side inventory/revocation record for a signed browser session.

    Flask still stores the session payload in its signed cookie; this record
    gives users and administrators a durable way to see and revoke that cookie
    without storing its contents or bearer value server-side.
    """
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, index=True)
    provider = db.Column(db.String(30), nullable=False, default="local")
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    last_seen_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True))
    revoked_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship("User", foreign_keys=[user_id])
    revoked_by = db.relationship("User", foreign_keys=[revoked_by_id])


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True))
    requested_ip = db.Column(db.String(64))
    user = db.relationship("User")


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
    # Redundant with ticket.tenant_id but kept as its own enforced column --
    # same defense-in-depth rationale as ApprovalGate.tenant_id: a comment
    # lookup shouldn't depend on every future query site remembering to join
    # back through ticket.
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


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


# Data classification is deliberately a static, Git-backed registry rather
# than an admin-editable table (matches CLAUDE.md's "configuration should
# be Git-backed and declarative where practical" direction) -- what counts
# as PII/confidential for a given record type is a governance decision, not
# a runtime setting. Retention days and legal-hold state, which genuinely
# vary per tenant, live in DataRetentionPolicy below instead.
DATA_CLASSIFICATION_REGISTRY = {
    "client_contact": {
        "label": "Client contact", "classification": "PII",
        "description": "External customer name, email, phone, job title.",
    },
    "client_ticket": {
        "label": "Client ticket", "classification": "Confidential",
        "description": "Customer support conversations; may contain PII in free-text bodies.",
    },
    "user": {
        "label": "Internal user", "classification": "PII",
        "description": "Employee/agent identity and contact details.",
    },
    "audit": {
        "label": "Audit log", "classification": "Confidential",
        "description": "Tamper-evident record of security-relevant actions. Governed separately by AuditRetentionPolicy.",
    },
}


class DataRetentionPolicy(db.Model):
    """Per-tenant, per-record-type retention window (B-090). Distinct from
    AuditRetentionPolicy (audit log has its own long, compliance-driven
    minimum unrelated to customer-data lifecycle). A row's absence means
    "no automatic purge configured" for that record_type -- opt-in, so an
    existing tenant sees zero behavior change until an admin sets one."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    record_type = db.Column(db.String(40), nullable=False)
    retention_days = db.Column(db.Integer, nullable=False, default=730)
    # Blanket hold on the whole record_type, distinct from a RecordLegalHold
    # on one specific record -- e.g. "freeze all client_contact purges
    # tenant-wide" without having to hold every row individually.
    legal_hold = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    last_run_at = db.Column(db.DateTime(timezone=True))
    last_run_count = db.Column(db.Integer, nullable=False, default=0)
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    updated_by = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("tenant_id", "record_type", name="uq_data_retention_policy_tenant_record_type"),)


class RecordLegalHold(db.Model):
    """Exempts one specific record from the automatic retention purge
    regardless of DataRetentionPolicy, for active litigation/investigation/
    regulatory-request holds that don't justify freezing an entire record
    type. Mirrors AuditRetentionPolicy/DataRetentionPolicy's legal_hold
    concept but scoped to a single row via (record_type, record_id)."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    record_type = db.Column(db.String(40), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    applied_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    applied_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    released_at = db.Column(db.DateTime(timezone=True))
    released_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    applied_by = db.relationship("User", foreign_keys=[applied_by_id])
    released_by = db.relationship("User", foreign_keys=[released_by_id])
    __table_args__ = (
        db.Index("ix_record_legal_hold_lookup", "tenant_id", "record_type", "record_id"),
    )


class ApplicationLog(db.Model):
    """Every WARNING+ log record the application logger emits, persisted so
    it survives a container restart/crash and is readable from the admin
    System Health page (see DatabaseLogHandler) without shell/`docker logs`
    access. tenant_id/user_id are nullable -- a crash can happen before
    authentication, in a background worker, or with no tenant context at
    all, and logging a failure must never itself raise (e.g. via a
    tenant-fail-closed default)."""
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(10), nullable=False, index=True)
    logger_name = db.Column(db.String(120))
    message = db.Column(db.Text, nullable=False)
    traceback = db.Column(db.Text)
    path = db.Column(db.String(255))
    method = db.Column(db.String(10))
    request_id = db.Column(db.String(36), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False, index=True)
    user = db.relationship("User")


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


class RouteRateLimitWindow(db.Model):
    """Per-key, per-minute request counter backing rate limiting on
    unauthenticated web routes (/login, password reset, MFA verification --
    ISO 27001 A.8.16). `key` is a route+scope-qualified string such as
    `login:ip:203.0.113.5` or `login:user:alice` so an attacker hammering one
    IP or one account cannot exhaust another legitimate user's quota. Reuses
    the same DB-backed windowed-counter design as APIRateLimitWindow (an
    in-process counter would undercount across gunicorn workers)."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(160), nullable=False, index=True)
    window_start = db.Column(db.DateTime(timezone=True), nullable=False)
    request_count = db.Column(db.Integer, nullable=False, default=0)
    __table_args__ = (
        db.UniqueConstraint("key", "window_start", name="uq_route_rate_limit_window"),
    )


class RequestMetricTotal(db.Model):
    """Cumulative, DB-backed HTTP request counters, keyed by method+status.

    Replaces an earlier in-process `Counter()`/`defaultdict()` pair, which
    silently undercounted: Gunicorn runs multiple worker *processes* (see
    `GUNICORN_WORKERS`), each with its own private Python memory, so an
    in-process counter only ever reflected whichever one worker happened to
    handle a given request -- a `/metrics` scrape saw a different, partial
    number depending on which worker the reverse proxy happened to route it
    to. A DB row is shared truth across every process, matching the same
    reasoning already applied to rate limiting (see RouteRateLimitWindow)."""
    id = db.Column(db.Integer, primary_key=True)
    method = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    request_count = db.Column(db.Integer, nullable=False, default=0)
    duration_sum_ms = db.Column(db.Float, nullable=False, default=0.0)
    __table_args__ = (
        db.UniqueConstraint("method", "status", name="uq_request_metric_total_method_status"),
    )


class PerformanceSample(db.Model):
    """Periodic snapshot of `RequestMetricTotal`'s cumulative totals plus
    worker/deployment context, written roughly once a minute by the
    background worker (see `process_performance_sample_schedule`). Two
    consecutive rows let a viewer compute a real per-interval request rate
    and average latency -- exactly what backs the System Health performance
    chart and the `tools/stress_test.py` load-test evidence."""
    id = db.Column(db.Integer, primary_key=True)
    sampled_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False, index=True)
    cumulative_requests = db.Column(db.Integer, nullable=False, default=0)
    cumulative_errors = db.Column(db.Integer, nullable=False, default=0)
    cumulative_duration_ms = db.Column(db.Float, nullable=False, default=0.0)
    worker_healthy = db.Column(db.Boolean, nullable=False, default=False)
    deployment_mode = db.Column(db.String(30), nullable=False, default="unknown")


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


class ClientOrganization(db.Model):
    """External customer account, kept separate from internal users/teams."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    name = db.Column(db.String(180), nullable=False)
    domain = db.Column(db.String(180), nullable=False, default="")
    external_id = db.Column(db.String(120))
    notes = db.Column(db.Text, nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    # Opt-in: False (the default) means every existing/new org keeps today's
    # all-or-nothing behavior -- any SysOps member/admin sees it, exactly as
    # before this column existed. Only when an admin explicitly flips this on
    # does ClientOrganizationAccess start being consulted at all, so adding
    # the capability is zero-risk to every org that never uses it.
    restricted_visibility = db.Column(db.Boolean, nullable=False, default=False)
    # Structured, admin-editable configuration that doesn't warrant its own
    # column/table -- branding and notification/escalation policy (phase 7).
    # Same db.JSON pattern as ConfigurationItem.attributes.
    settings = db.Column(db.JSON, nullable=False, default=dict)
    # Custom field VALUES for this org (schema lives tenant-wide in
    # ClientCustomFieldDefinition; per-org required/visible overrides live
    # in settings["custom_field_overrides"]).
    custom_fields = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    contacts = db.relationship("ClientContact", cascade="all, delete-orphan", backref="organization")
    access_grants = db.relationship("ClientOrganizationAccess", cascade="all, delete-orphan", backref="organization")
    __table_args__ = (db.UniqueConstraint("tenant_id", "name", name="uq_client_organization_tenant_name"),)


class ClientCustomFieldDefinition(db.Model):
    """Tenant-wide custom field schema for Client Management (field
    EXISTENCE is tenant-wide, matching Zendesk's own model -- fields aren't
    per-organization; per-org required/visible overrides live in
    ClientOrganization.settings["custom_field_overrides"] instead of a
    second table). entity_type selects which of ClientOrganization/
    ClientContact/ClientTicket this field applies to; values are stored in
    that model's own custom_fields JSON column, keyed by `key`."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    entity_type = db.Column(db.String(20), nullable=False)
    key = db.Column(db.String(60), nullable=False)
    label = db.Column(db.String(120), nullable=False)
    field_type = db.Column(db.String(20), nullable=False, default="text")
    options_json = db.Column(db.Text, nullable=False, default="[]")
    required = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    position = db.Column(db.Integer, nullable=False, default=0)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "entity_type", "key", name="uq_client_custom_field_tenant_entity_key"),
    )


class ClientOrganizationAccess(db.Model):
    """Grants a specific user OR support group visibility into a
    restricted-visibility ClientOrganization -- consulted only when that
    org's restricted_visibility is True (see its docstring). Exactly one of
    user_id/group_id is set per row. No row for a restricted org simply
    means no one but admins can see it, matching this app's "no row = no
    grant" convention (CiClassPermission, RolePolicyOverride)."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("client_organization.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"))
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    user = db.relationship("User", foreign_keys=[user_id])
    group = db.relationship("SupportGroup", foreign_keys=[group_id])
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])
    __table_args__ = (
        db.UniqueConstraint("organization_id", "user_id", "group_id", name="uq_client_org_access_org_user_group"),
        db.CheckConstraint(
            "(user_id IS NOT NULL AND group_id IS NULL) OR (user_id IS NULL AND group_id IS NOT NULL)",
            name="ck_client_org_access_exactly_one_grantee",
        ),
    )


class ClientView(db.Model):
    """A saved filter+sort for the Client Management ticket list, sitting on
    top of the existing generic filter-condition engine (parse_list_filter_param/
    apply_filter_conditions, already used by CMDB/ticket lists) rather than
    inventing bespoke filtering -- conditions_json is exactly the JSON shape
    parse_list_filter_param() produces/consumes. `shared` makes a view
    visible to every Client Management user in the tenant; unshared views
    are visible only to their creator. The six built-in views (mine,
    unassigned, pending, recent, solved, unsolved) are not rows here -- they
    stay hardcoded in the route, unchanged, exactly as before this model
    existed; ClientView only ever adds new views alongside them."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    name = db.Column(db.String(120), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    shared = db.Column(db.Boolean, nullable=False, default=False)
    conditions_json = db.Column(db.Text, nullable=False, default="[]")
    sort_field = db.Column(db.String(30), nullable=False, default="updated")
    sort_dir = db.Column(db.String(4), nullable=False, default="desc")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    created_by = db.relationship("User")
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "created_by_id", "name", name="uq_client_view_tenant_owner_name"),
    )


class ClientTrigger(db.Model):
    """A single condition -> single action automation rule, evaluated by
    serviceops_core/client_automation.py against a ClientTicket whenever
    `event` fires (created/status_changed/updated). `position` is the
    evaluation order for a given event, matching workflow.py's stage
    ordering convention. Kept single-condition/single-action deliberately
    -- see client_automation.py's module docstring."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    name = db.Column(db.String(120), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    event = db.Column(db.String(30), nullable=False)
    condition_field = db.Column(db.String(30), nullable=False)
    condition_op = db.Column(db.String(20), nullable=False)
    condition_value = db.Column(db.String(200), nullable=False, default="")
    action_type = db.Column(db.String(30), nullable=False)
    action_value = db.Column(db.String(500), nullable=False, default="")
    position = db.Column(db.Integer, nullable=False, default=0)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    created_by = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("tenant_id", "name", name="uq_client_trigger_tenant_name"),)


class ClientMacro(db.Model):
    """A one-click bulk action (optionally including a canned reply) an
    agent can apply to a ClientTicket -- Zendesk-style macro. `actions_json`
    is a JSON dict of field -> value for any of status/priority/ticket_type/
    tags/assignee_id (only keys present are applied; omitted fields are left
    untouched on the ticket). A macro with no reply_body just changes fields
    silently; one with a reply_body also posts a ClientTicketMessage in
    reply_visibility ("public" or "internal")."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    name = db.Column(db.String(120), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    actions_json = db.Column(db.Text, nullable=False, default="{}")
    reply_body = db.Column(db.Text, nullable=False, default="")
    reply_visibility = db.Column(db.String(20), nullable=False, default="public")
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    created_by = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("tenant_id", "name", name="uq_client_macro_tenant_name"),)


class ClientMailbox(db.Model):
    """A support email address polled via IMAP (inbound -> ClientTicket)
    and sent through via SMTP (agent public replies -> real email). Modeled
    as a list even though most tenants configure just one, mirroring
    IntegrationConnection's per-row shape rather than the global
    PlatformSetting mechanism, since this needs tenant scoping and
    eventual multi-mailbox support the global settings mechanism doesn't
    offer. Passwords use the same settings_cipher()-encrypted-column
    pattern as IntegrationConnection.secret_encrypted/.secret."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    name = db.Column(db.String(120), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    imap_host = db.Column(db.String(255), nullable=False, default="")
    imap_port = db.Column(db.Integer, nullable=False, default=993)
    imap_use_ssl = db.Column(db.Boolean, nullable=False, default=True)
    imap_username = db.Column(db.String(255), nullable=False, default="")
    imap_password_encrypted = db.Column(db.Text)
    imap_folder = db.Column(db.String(120), nullable=False, default="INBOX")
    smtp_host = db.Column(db.String(255), nullable=False, default="")
    smtp_port = db.Column(db.Integer, nullable=False, default=587)
    smtp_use_tls = db.Column(db.Boolean, nullable=False, default=True)
    smtp_username = db.Column(db.String(255), nullable=False, default="")
    smtp_password_encrypted = db.Column(db.Text)
    from_address = db.Column(db.String(254), nullable=False, default="")
    from_name = db.Column(db.String(160), nullable=False, default="")
    default_organization_id = db.Column(db.Integer, db.ForeignKey("client_organization.id"))
    auto_create_organization_by_domain = db.Column(db.Boolean, nullable=False, default=True)
    last_polled_at = db.Column(db.DateTime(timezone=True))
    last_poll_status = db.Column(db.String(20), nullable=False, default="never_run")
    last_poll_error = db.Column(db.Text, nullable=False, default="")
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    default_organization = db.relationship("ClientOrganization")
    created_by = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("tenant_id", "name", name="uq_client_mailbox_tenant_name"),)

    @property
    def imap_password(self):
        if not self.imap_password_encrypted:
            return ""
        return settings_cipher().decrypt(self.imap_password_encrypted.encode()).decode()

    @imap_password.setter
    def imap_password(self, value):
        self.imap_password_encrypted = settings_cipher().encrypt(value.encode()).decode() if value else None

    @property
    def smtp_password(self):
        if not self.smtp_password_encrypted:
            return ""
        return settings_cipher().decrypt(self.smtp_password_encrypted.encode()).decode()

    @smtp_password.setter
    def smtp_password(self, value):
        self.smtp_password_encrypted = settings_cipher().encrypt(value.encode()).decode() if value else None


class ClientContact(db.Model):
    """Customer identity used for support communication, not application login."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("client_organization.id"), nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    email = db.Column(db.String(254), nullable=False)
    phone = db.Column(db.String(60), nullable=False, default="")
    job_title = db.Column(db.String(120), nullable=False, default="")
    preferred_language = db.Column(db.String(30), nullable=False, default="English")
    active = db.Column(db.Boolean, nullable=False, default=True)
    custom_fields = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    # GDPR Art. 17 (right to erasure), mirroring User.erased_at exactly:
    # set when this contact's personal data has been scrubbed, either by an
    # admin's explicit request or by the automatic retention purge (see
    # DataRetentionPolicy/process_data_retention_purge). Distinct from
    # `active` -- deactivation alone retains name/email/phone indefinitely.
    erased_at = db.Column(db.DateTime(timezone=True))
    __table_args__ = (db.UniqueConstraint("tenant_id", "email", name="uq_client_contact_tenant_email"),)


class ClientTicket(db.Model):
    """External support conversation with Zendesk-style queue semantics."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    number = db.Column(db.String(24), unique=True, nullable=False, index=True)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="New", index=True)
    priority = db.Column(db.String(20), nullable=False, default="Normal", index=True)
    ticket_type = db.Column(db.String(30), nullable=False, default="Question")
    channel = db.Column(db.String(30), nullable=False, default="Web")
    tags = db.Column(db.String(500), nullable=False, default="")
    custom_fields = db.Column(db.JSON, nullable=False, default=dict)
    contact_id = db.Column(db.Integer, db.ForeignKey("client_contact.id"), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("client_organization.id"), nullable=False, index=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    support_group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Nullable: only set when the ticket originated from (or has since
    # replied through) a specific ClientMailbox, so outbound replies go out
    # via the same mailbox the customer is actually talking to -- not
    # "whichever mailbox happens to be active" (see deliver reply wiring in
    # app.py's client_ticket_detail).
    mailbox_id = db.Column(db.Integer, db.ForeignKey("client_mailbox.id"), index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    solved_at = db.Column(db.DateTime(timezone=True))
    contact = db.relationship("ClientContact")
    organization = db.relationship("ClientOrganization")
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    support_group = db.relationship("SupportGroup")
    mailbox = db.relationship("ClientMailbox")
    messages = db.relationship("ClientTicketMessage", cascade="all, delete-orphan", backref="ticket", order_by="ClientTicketMessage.created_at")


class ClientTicketMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    client_ticket_id = db.Column(db.Integer, db.ForeignKey("client_ticket.id"), nullable=False, index=True)
    # Nullable: a message ingested from an inbound email has no internal
    # User author -- it's attributed to the ticket's own contact instead
    # (see event_type "inbound_email"; rendered as "<contact name> (via
    # email)" rather than an agent's name).
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    body = db.Column(db.Text, nullable=False)
    visibility = db.Column(db.String(20), nullable=False, default="public")
    event_type = db.Column(db.String(30), nullable=False, default="reply")
    # Email threading (Client Management email channel): message_id is the
    # inbound email's own Message-ID, or our generated one for an outbound
    # reply; in_reply_to is the raw header from an inbound email, kept to
    # build outbound References chains. Both null for in-app-only messages.
    message_id = db.Column(db.String(255), index=True)
    in_reply_to = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    author = db.relationship("User")


class Approval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    enterprise_record_id = db.Column(db.Integer, db.ForeignKey("enterprise_record.id"), nullable=False)
    approver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    state = db.Column(db.String(20), nullable=False, default="Requested")
    comments = db.Column(db.Text, default="")
    decided_at = db.Column(db.DateTime(timezone=True))
    approver = db.relationship("User")
    # Same defense-in-depth rationale as ApprovalGate.tenant_id -- see there.
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


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
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


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
    # Physical rack placement -- all four nullable/optional, meaningless and
    # simply blank for any CI that isn't rack-mounted (a Business Application
    # CI, for instance), exactly like `location` already works today. Sourced
    # from either serviceops_core/netbox_sync.py (a NetBox-managed rack) or
    # direct admin entry on the CI edit form.
    rack_id = db.Column(db.Integer, db.ForeignKey("rack.id"), index=True)
    rack_position = db.Column(db.Float)
    rack_u_height = db.Column(db.Integer)
    rack_face = db.Column(db.String(10))
    rack = db.relationship("Rack")


class Rack(db.Model):
    """A physical rack a ConfigurationItem can be mounted in -- either
    synced from NetBox's own /api/dcim/racks/ or created by hand for a site
    without NetBox. Not itself a ConfigurationItem/ci_class: racks are
    physical containers, not managed/monitored assets in their own right."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    name = db.Column(db.String(120), nullable=False)
    site = db.Column(db.String(120), nullable=False, default="")
    u_height = db.Column(db.Integer, nullable=False, default=42)
    notes = db.Column(db.Text, nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    # Populated by netbox_sync.py so a re-run matches existing rows instead
    # of creating duplicates. Null for manually-created racks.
    external_source = db.Column(db.String(20))
    external_id = db.Column(db.String(120))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    __table_args__ = (db.UniqueConstraint("tenant_id", "name", name="uq_rack_tenant_name"),)


class CiClassPermission(db.Model):
    """Per-(tenant, CI class, role) CRUD grant, additive to the flat
    role/action policy in config/authorization.json. Read and
    create/update/delete have deliberately OPPOSITE default semantics for a
    class with no rows at all ("unmanaged"):

    - Read defaults OPEN: an unmanaged class is visible to every role that
      could see CMDB at all before this table existed (agent/manager/admin)
      -- zero behavior change for a deployment that never configures this.
    - Create/update/delete default CLOSED for agent/manager: agent and
      manager only reached the CMDB mutation routes at all once this table
      let create/update/delete be granted per class (they were previously
      @roles("admin")-only); an agent/manager row with no can_create/
      can_update/can_delete grant for a class -- including a class with NO
      rows configured yet -- means no capability, so shipping this never
      grants anyone new write access until an administrator explicitly
      checks a box. admin (and superadmin, which never needs a row at all)
      always has full CRUD regardless of what the grid says -- this table
      only ever grants agent/manager capability they didn't have, never
      restricts admin's pre-existing access.

    Once at least one row exists for a class, it is "managed" for READ
    purposes: any role with no row for it, or can_read=False, is denied
    read access to that class's CIs. Create/update/delete are always
    per-(class, agent/manager-role) opt-in regardless of "managed" state."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    ci_class = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    can_read = db.Column(db.Boolean, nullable=False, default=False)
    can_create = db.Column(db.Boolean, nullable=False, default=False)
    can_update = db.Column(db.Boolean, nullable=False, default=False)
    can_delete = db.Column(db.Boolean, nullable=False, default=False)
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "ci_class", "role", name="uq_ci_class_permission_tenant_class_role"),
    )


class RolePolicyOverride(db.Model):
    """Per-(tenant, role, action) override of config/authorization.json's
    flat role -> action policy. A row only exists when an admin has
    explicitly deviated a role's grant for that action away from the
    Git-backed baseline -- there is no row for the common case of "matches
    the baseline", mirroring CiClassPermission's "no row = default" storage
    philosophy. `is_granted` records the admin's explicit choice (True to
    grant an action the baseline denies, False to revoke one the baseline
    grants); "reset to recommended" for a role is simply deleting that
    role's override rows, which is why no separate baseline-snapshot
    table is needed -- config/authorization.json IS the recommended
    baseline. superadmin is never overridable (always implicitly granted
    everywhere, per this app's existing convention)."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    role = db.Column(db.String(20), nullable=False)
    action = db.Column(db.String(40), nullable=False)
    is_granted = db.Column(db.Boolean, nullable=False)
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "role", "action", name="uq_role_policy_override_tenant_role_action"),
    )


CI_RELATIONSHIP_TYPES = ["Depends on", "Runs on", "Connects to", "Hosted on", "Backs up"]


class CIRelationship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"), nullable=False)
    child_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"), nullable=False)
    relationship_type = db.Column(db.String(60), nullable=False, default="Depends on")
    # Port-level detail for an LLDP-derived "Connects to" edge (e.g.
    # "Ethernet51 <-> eth0"), so the topology map can show which physical
    # port each side is plugged into, not just that they're connected.
    # Null for manually-created relationships, which have no port concept.
    label = db.Column(db.String(160))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    parent = db.relationship("ConfigurationItem", foreign_keys=[parent_id])
    child = db.relationship("ConfigurationItem", foreign_keys=[child_id])
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    __table_args__ = (
        db.UniqueConstraint("parent_id", "child_id", "relationship_type", name="uq_ci_relationship"),
    )


class DiscoveryTarget(db.Model):
    """An administrator-configured agentless SNMP discovery target -- either
    a single host or a CIDR subnet -- with its own encrypted community
    string (see serviceops_core/network_discovery.py). Never a substitute for
    tools/cmdb_sync_agent.sh's agent-based self-registration; this is the
    complementary agentless path for devices (switches, appliances) that
    can't run an agent themselves."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    target_type = db.Column(db.String(10), nullable=False, default="host")  # "host" or "subnet"
    address = db.Column(db.String(80), nullable=False)  # IP or CIDR
    snmp_version = db.Column(db.String(4), nullable=False, default="2c")
    snmp_port = db.Column(db.Integer, nullable=False, default=161)
    community_encrypted = db.Column(db.Text)
    schedule_enabled = db.Column(db.Boolean, nullable=False, default=False)
    schedule_interval_minutes = db.Column(db.Integer, nullable=False, default=1440)
    active = db.Column(db.Boolean, nullable=False, default=True)
    last_run_at = db.Column(db.DateTime(timezone=True))
    last_run_status = db.Column(db.String(20))
    last_run_summary = db.Column(db.Text)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    created_by = db.relationship("User")

    @property
    def community(self):
        if not self.community_encrypted:
            return ""
        return settings_cipher().decrypt(self.community_encrypted.encode()).decode()

    @community.setter
    def community(self, value):
        self.community_encrypted = settings_cipher().encrypt((value or "").encode()).decode() if value else None


class DiscoveryCandidate(db.Model):
    """A device found by a DiscoveryTarget run, held for administrator
    review before anything lands in the CMDB -- discovery no longer
    auto-creates CIs; a run only stages candidates here, and an explicit
    "Add selected" / "Add all" / "Discard" decision on the review page is
    what actually calls reconcile_facts_into_cmdb. ``facts`` is the full
    probe_host()-shaped dict, replayed unchanged into reconciliation at
    import time so nothing needs to be re-scanned to commit a decision."""
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("discovery_target.id"), nullable=False, index=True)
    host = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(160), nullable=False)
    ci_class = db.Column(db.String(80), nullable=False)
    vendor = db.Column(db.String(120))
    discovery_source = db.Column(db.String(40), nullable=False)
    facts = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    target = db.relationship("DiscoveryTarget")


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
    # Uniqueness is scoped to (tenant_id, name) -- not name alone -- so a
    # second tenant can have its own "Service Desk"/"Change Control Board"
    # instead of colliding with tenant 1's (see migration 20260731_0049).
    name = db.Column(db.String(120), nullable=False)
    group_type = db.Column(db.String(40), nullable=False, default="Fulfillment")
    manager_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    active = db.Column(db.Boolean, nullable=False, default=True)
    manager = db.relationship("User")
    members = db.relationship("GroupMember", cascade="all, delete-orphan", backref="group")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "name", name="uq_support_group_tenant_name"),
    )


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="member")
    user = db.relationship("User")
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
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


class UserRoleGrant(db.Model):
    """A role a user currently holds. A user may hold several at once (e.g.
    both "manager" and "admin") -- User.role (recomputed by
    recompute_base_role()) is always the highest-ranked one, so any code that
    still reads User.role directly keeps its previous "assume the best/
    highest role" behavior unchanged. The "acting as" toggle
    (User.effective_role) lets a multi-role user deliberately act as a lower
    one for a session without losing any grant."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("user_id", "role", name="uq_user_role_grant"),)


class ManagedRoleGrant(db.Model):
    """Tracks which UserRoleGrant rows a specific automatic source currently
    justifies, so that source's resync can safely revoke a role it granted
    once no longer justified, without touching a role granted for a
    different reason (including a plain manual admin grant, which never has
    a row here at all). `source` scopes independent resync passes from each
    other: "directory" (AD/SSO group->role mapping) and
    "team_responsibility" (manages or belongs to a support group) currently
    never interfere with each other or with a manual grant."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(30), nullable=False)
    detail = db.Column(db.String(500))
    synchronized_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    user = db.relationship("User")
    __table_args__ = (
        db.UniqueConstraint("user_id", "role", "source", name="uq_managed_role_grant"),
    )


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
    name = db.Column(db.String(160), nullable=False)
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
    # Client Management phase 5: null (the default, and every row before this
    # column existed) means a tenant-wide default for target_type/priority,
    # same "null = default" convention this app already uses elsewhere. A row
    # with this set is an override specific to that organization's tickets
    # -- only meaningful when target_type == "client_ticket". attach_slas()
    # prefers an org-specific row over the tenant-wide default for the same
    # priority when both exist.
    client_organization_id = db.Column(db.Integer, db.ForeignKey("client_organization.id"))
    client_organization = db.relationship("ClientOrganization")
    __table_args__ = (
        db.UniqueConstraint("tenant_id", "name", name="uq_sla_definition_tenant_name"),
    )


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
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


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
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


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


class GuidedTour(db.Model):
    """B-120: admin-authored contextual help, DB-backed (not Git-backed
    config) since the whole point is non-engineer admins can author/edit
    tour content without a deploy -- same reasoning that already makes
    ClientMacro/ClientTrigger DB rows instead of Git-backed config.
    target_route is a Flask endpoint name ("dashboard") or "*" for every
    page; target_roles is a comma-separated ROLE_RANK role list, empty
    meaning every role. `version` increments on any content edit so a
    user who already saw an older version is correctly re-prompted (see
    UserTourProgress.tour_version_seen) rather than the tour going silent
    forever the moment it changes."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    key = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.String(500), nullable=False, default="")
    target_route = db.Column(db.String(120), nullable=False, default="*")
    target_roles = db.Column(db.String(200), nullable=False, default="")
    version = db.Column(db.Integer, nullable=False, default=1)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    created_by = db.relationship("User")
    steps = db.relationship(
        "GuidedTourStep", cascade="all, delete-orphan", backref="tour",
        order_by="GuidedTourStep.step_order",
    )
    __table_args__ = (db.UniqueConstraint("tenant_id", "key", name="uq_guided_tour_tenant_key"),)


class GuidedTourStep(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    tour_id = db.Column(db.Integer, db.ForeignKey("guided_tour.id"), nullable=False, index=True)
    step_order = db.Column(db.Integer, nullable=False, default=0)
    # A CSS selector for the element this step highlights, e.g.
    # "[data-tour='dashboard-kpis']" -- pages opt into being tour targets
    # by adding a data-tour attribute, not by the tour reaching into
    # arbitrary markup. Empty selector means an unanchored, centered step
    # (an intro/outro slide with no specific element to point at).
    target_selector = db.Column(db.String(300), nullable=False, default="")
    title = db.Column(db.String(160), nullable=False)
    body = db.Column(db.Text, nullable=False)
    placement = db.Column(db.String(20), nullable=False, default="bottom")


class UserTourProgress(db.Model):
    """Per-user dismiss/completion state so a tour doesn't nag every page
    load, and so a content edit (GuidedTour.version bump) correctly
    re-prompts a user who saw an older version."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    tour_id = db.Column(db.Integer, db.ForeignKey("guided_tour.id"), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="dismissed")
    tour_version_seen = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "tour_id", name="uq_user_tour_progress_user_tour"),)


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
    # A fourth parent option: a Client Management customer ticket -- email
    # attachments land on the ticket directly (not per-message), matching
    # how ITIL ticket attachments already work.
    client_ticket_id = db.Column(db.Integer, db.ForeignKey("client_ticket.id"), nullable=True)
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
    client_ticket = db.relationship("ClientTicket", backref=db.backref("attachments", cascade="all, delete-orphan"))
    uploaded_by = db.relationship("User")
    # File bytes are the most sensitive data this table points at, and its
    # tenant is otherwise only reachable through whichever ONE of three
    # different parents (ticket/enterprise_record/comment) happens to be
    # set -- an own tenant_id makes every attachment query uniform instead
    # of branching per parent type.
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)
