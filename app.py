import json
import os
import ssl
import uuid
import base64
import hashlib
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, abort, current_app, flash, jsonify, redirect, render_template, request, send_from_directory, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from cryptography.fernet import Fernet, InvalidToken
from ldap3 import ALL, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"
oauth = OAuth()


def now():
    return datetime.now(timezone.utc)


def env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="requester")
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)

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


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(24), unique=True, index=True, nullable=False)
    kind = db.Column(db.String(20), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, nullable=False)
    state = db.Column(db.String(30), nullable=False, default="New", index=True)
    priority = db.Column(db.String(10), nullable=False, default="P3")
    category = db.Column(db.String(80), nullable=False, default="General")
    requester_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    requester = db.relationship("User", foreign_keys=[requester_id])
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    comments = db.relationship("Comment", cascade="all, delete-orphan", backref="ticket")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    author = db.relationship("User")


class Knowledge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="General")
    body = db.Column(db.Text, nullable=False)
    published = db.Column(db.Boolean, nullable=False, default=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    author = db.relationship("User")


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_tag = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(160), nullable=False)
    asset_type = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="In stock")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    serial_number = db.Column(db.String(120))
    owner = db.relationship("User")


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(120), nullable=False)
    target = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")


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
    due_at = db.Column(db.DateTime(timezone=True))
    metadata_json = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    requester = db.relationship("User", foreign_keys=[requester_id])
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    approvals = db.relationship("Approval", cascade="all, delete-orphan", backref="record")


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
    environment = db.Column(db.String(30), nullable=False, default="Production")
    operational_status = db.Column(db.String(40), nullable=False, default="Operational")
    ip_address = db.Column(db.String(60))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    owner = db.relationship("User")


class CIRelationship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"), nullable=False)
    child_id = db.Column(db.Integer, db.ForeignKey("configuration_item.id"), nullable=False)
    relationship_type = db.Column(db.String(60), nullable=False, default="Depends on")
    parent = db.relationship("ConfigurationItem", foreign_keys=[parent_id])
    child = db.relationship("ConfigurationItem", foreign_keys=[child_id])


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(180), nullable=False)
    body = db.Column(db.Text, nullable=False)
    read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")


class SupportGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    group_type = db.Column(db.String(40), nullable=False, default="Fulfillment")
    manager_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    active = db.Column(db.Boolean, nullable=False, default=True)
    manager = db.relationship("User")
    members = db.relationship("GroupMember", cascade="all, delete-orphan", backref="group")


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


class ApprovalGate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chain_id = db.Column(db.Integer, db.ForeignKey("approval_chain.id"), nullable=False)
    sequence = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(160), nullable=False)
    mode = db.Column(db.String(20), nullable=False, default="all")
    state = db.Column(db.String(30), nullable=False, default="Pending")
    votes = db.relationship("ApprovalVote", cascade="all, delete-orphan", backref="gate")
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


class ServiceOffering(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    support_group_id = db.Column(db.Integer, db.ForeignKey("support_group.id"))
    criticality = db.Column(db.String(20), nullable=False, default="Medium")
    status = db.Column(db.String(30), nullable=False, default="Operational")
    owner = db.relationship("User")
    support_group = db.relationship("SupportGroup")


class SLADefinition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), unique=True, nullable=False)
    target_type = db.Column(db.String(30), nullable=False)
    priority = db.Column(db.String(10))
    duration_minutes = db.Column(db.Integer, nullable=False)
    pause_states = db.Column(db.String(200), nullable=False, default="Pending,On Hold")
    active = db.Column(db.Boolean, nullable=False, default=True)


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
    conflict_status = db.Column(db.String(40), nullable=False, default="Not Run")
    ccb_required = db.Column(db.Boolean, nullable=False, default=True)
    ticket = db.relationship("Ticket", backref=db.backref("change_governance", uselist=False))
    ci = db.relationship("ConfigurationItem")


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
    """Major-incident coordination remains an extension of the parent INC."""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), unique=True, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Proposed")
    business_impact = db.Column(db.Text, default="")
    communications = db.Column(db.Text, default="")
    coordinator_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    declared_at = db.Column(db.DateTime(timezone=True))
    ticket = db.relationship(
        "Ticket", backref=db.backref("major_incident_profile", uselist=False)
    )
    coordinator = db.relationship("User")


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
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)
    mime_type = db.Column(db.String(120))
    size_bytes = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    ticket = db.relationship("Ticket", backref=db.backref("attachments", cascade="all, delete-orphan"))
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


def audit(action, target, details=""):
    db.session.add(Audit(user_id=current_user.id if current_user.is_authenticated else None,
                         action=action, target=target, details=details))


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
    "event": {"name": "IT operations events", "prefix": "EVT", "types": ["Alert", "Infrastructure event", "Service degradation"]},
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
        {"key": "KEYCLOAK_ENABLED", "label": "Enable Keycloak", "type": "bool", "default": "false", "live": False},
        {"key": "KEYCLOAK_DISCOVERY_URL", "label": "Keycloak discovery URL", "type": "url", "default": "", "live": False},
        {"key": "KEYCLOAK_CLIENT_ID", "label": "Keycloak client ID", "type": "text", "default": "", "live": False},
        {"key": "KEYCLOAK_CLIENT_SECRET", "label": "Keycloak client secret", "type": "secret", "default": "", "live": False},
        {"key": "KEYCLOAK_ROLE_MAPPINGS", "label": "Keycloak realm-role mappings", "type": "json", "default": "{}", "live": True},
    ],
    "security": [
        {"key": "ENABLE_HSTS", "label": "Enable HSTS", "type": "bool", "default": "false", "live": True},
        {"key": "SESSION_HOURS", "label": "Session lifetime in hours", "type": "int", "default": "8", "min": 1, "max": 168, "live": False},
        {"key": "MAX_UPLOAD_MB", "label": "Maximum upload size (MB)", "type": "int", "default": "20", "min": 1, "max": 500, "live": True},
    ],
    "workflow": [
        {"key": "DEFAULT_TICKET_PRIORITY", "label": "Default ticket priority", "type": "choice", "choices": ["P1", "P2", "P3", "P4"], "default": "P3", "live": True},
        {"key": "CHANGE_FREEZE_MESSAGE", "label": "Change freeze message", "type": "text", "default": "", "live": True},
        {"key": "SYNC_CHILD_INCIDENT_STATES", "label": "Synchronize parent incident state to children", "type": "bool", "default": "false", "live": True},
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


def next_enterprise_number(domain):
    prefix = DOMAIN_CONFIG[domain]["prefix"]
    latest = EnterpriseRecord.query.filter_by(domain=domain).order_by(EnterpriseRecord.id.desc()).first()
    sequence = (latest.id + 1) if latest else 1
    return f"{prefix}{sequence:07d}"


def sequence_number(model, prefix):
    latest = model.query.order_by(model.id.desc()).first()
    return f"{prefix}{((latest.id if latest else 0) + 1):07d}"


def next_operational_task_number(task_kind):
    prefix = "CTASK" if task_kind == "change" else "PTASK"
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


def record_url(record):
    if isinstance(record, Ticket):
        return url_for("ticket_detail", ticket_id=record.id)
    if isinstance(record, EnterpriseRecord):
        return url_for("enterprise_detail", record_id=record.id)
    if isinstance(record, (CatalogRequest, RequestedItem, CatalogTask)):
        request_id = (
            record.id if isinstance(record, CatalogRequest)
            else record.request_id if isinstance(record, RequestedItem)
            else record.requested_item.request_id
        )
        return url_for("request_detail", request_id=request_id)
    if isinstance(record, Knowledge):
        return url_for("knowledge")
    if isinstance(record, OperationalTask):
        parent = record_reference(record.parent_type, record.parent_id)
        return record_url(parent) if parent else "#"
    return "#"


def find_record_by_number(number):
    normalized = (number or "").strip().upper()
    if normalized.startswith(("INC", "CHG")):
        return Ticket.query.filter(func.upper(Ticket.number) == normalized).first()
    if normalized.startswith("PRB"):
        return EnterpriseRecord.query.filter(
            EnterpriseRecord.domain == "problem",
            func.upper(EnterpriseRecord.number) == normalized,
        ).first()
    if normalized.startswith("REQ"):
        return CatalogRequest.query.filter(func.upper(CatalogRequest.number) == normalized).first()
    if normalized.startswith("RITM"):
        return RequestedItem.query.filter(func.upper(RequestedItem.number) == normalized).first()
    if normalized.startswith("SCTASK"):
        return CatalogTask.query.filter(func.upper(CatalogTask.number) == normalized).first()
    if normalized.startswith(("CTASK", "PTASK")):
        return OperationalTask.query.filter(func.upper(OperationalTask.number) == normalized).first()
    if normalized.startswith("KB") and normalized[2:].isdigit():
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
    ticket.state = new_state
    sync_slas("ticket", ticket.id, new_state)
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


def transition_catalog_task(task, new_state):
    chain = approval_chain_for("ritm", task.requested_item_id)
    if chain and chain.state != "Approved":
        abort(409, description="Fulfillment cannot start until the requested item is approved.")
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


def transition_operational_task(task, new_state):
    allowed = OPERATIONAL_TASK_TRANSITIONS.get(task.state, (task.state,))
    if new_state not in allowed:
        abort(409, description=f"{task.number} cannot move from {task.state} to {new_state}.")
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
    if user.role == "admin":
        return query
    ticket_ids = {
        row[0] for row in db.session.query(Ticket.id).filter(
            Ticket.requester_id == user.id
        ).all()
    }
    group_ids = user_support_group_ids(user)
    if group_ids:
        ticket_ids.update(
            row[0] for row in db.session.query(TicketAssignmentGroup.ticket_id).filter(
                TicketAssignmentGroup.group_id.in_(group_ids)
            ).all()
        )
        ticket_ids.update(
            row[0] for row in db.session.query(ChangeOwnership.ticket_id).filter(
                ChangeOwnership.group_id.in_(group_ids)
            ).all()
        )
        ticket_ids.update(
            row[0] for row in db.session.query(OperationalTask.parent_id).filter(
                OperationalTask.parent_type == "ticket",
                OperationalTask.assignment_group_id.in_(group_ids),
            ).all()
        )
    ticket_ids.update(
        row[0] for row in db.session.query(ApprovalChain.target_id).join(
            ApprovalGate, ApprovalGate.chain_id == ApprovalChain.id
        ).join(ApprovalVote, ApprovalVote.gate_id == ApprovalGate.id).filter(
            ApprovalChain.target_type == "ticket",
            ApprovalVote.approver_id == user.id,
            ApprovalVote.state.in_(["Requested", "Approved", "Rejected"]),
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
    if governance.change_type != "Standard":
        ccb = SupportGroup.query.filter_by(name="Change Control Board").first()
        ccb_ids = [
            member.user_id for member in (ccb.members if ccb else [])
            if member.role == "CCB approver" and member.user.active
        ]
        if not ccb_ids:
            abort(409, description=(
                "CCB membership must be configured before a non-standard change can be submitted."
            ))
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
    chain = create_approval_chain(
        f"{ticket.number} change authorization v{revision.revision}",
        "ticket", ticket.id, stages,
    )
    approver_ids = {
        approver_id for stage in stages for approver_id in stage["approver_ids"]
    }
    summary = ", ".join(changed_fields)
    for approver_id in approver_ids:
        db.session.add(Notification(
            user_id=approver_id,
            title=f"Reapproval required: {ticket.number} v{revision.revision}",
            body=f"Material change fields were revised: {summary}. Review the new plan before implementation.",
        ))
    log_history(
        "ticket", ticket.id, "Approval restarted",
        "approval revision",
        revision.revision - 1, revision.revision,
        f"Material fields changed: {summary}",
    )
    return chain


def user_in_group(user, group):
    if not user.is_authenticated or not user.active or not group:
        return False
    return (
        user.role == "admin"
        or group.manager_id == user.id
        or GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first() is not None
    )


def activate_gate(gate):
    gate.state = "Requested"
    for vote in gate.votes:
        vote.state = "Requested"
        db.session.add(Notification(user_id=vote.approver_id, title=f"Approval requested: {gate.name}",
                                    body=f"Your decision is required for approval chain {gate.chain.name}."))


def create_approval_chain(name, target_type, target_id, stages):
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
    activate_gate(first_gate)
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
            db.session.add(TaskSLA(definition_id=definition.id, target_type=target_type, target_id=target_id,
                                   breach_at=now() + timedelta(minutes=definition.duration_minutes)))


def sync_slas(target_type, target_id, state):
    for task_sla in TaskSLA.query.filter_by(target_type=target_type, target_id=target_id).all():
        if task_sla.stage in ("Completed", "Cancelled"):
            continue
        pause_states = {value.strip() for value in task_sla.definition.pause_states.split(",")}
        if state in ("Resolved", "Closed", "Completed", "Closed Complete"):
            task_sla.stage = "Completed"
            task_sla.stopped_at = now()
        elif state in pause_states and task_sla.stage == "In Progress":
            task_sla.stage = "Paused"
            task_sla.paused_at = now()
        elif state not in pause_states and task_sla.stage == "Paused":
            current = now()
            if task_sla.paused_at.tzinfo is None:
                current = current.replace(tzinfo=None)
            paused = int((current - task_sla.paused_at).total_seconds())
            task_sla.paused_seconds += paused
            task_sla.breach_at += timedelta(seconds=paused)
            task_sla.paused_at = None
            task_sla.stage = "In Progress"
        current = now()
        if task_sla.breach_at.tzinfo is None:
            current = current.replace(tzinfo=None)
        if task_sla.stage == "In Progress" and current > task_sla.breach_at:
            task_sla.breached = True


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
        if membership.group.active
    }
    group_ids.update(
        group.id for group in SupportGroup.query.filter_by(
            manager_id=user.id, active=True
        ).all()
    )
    return group_ids


def visible_catalog_request_query(user):
    query = CatalogRequest.query
    if not user.is_authenticated or not user.active:
        return query.filter(CatalogRequest.id == -1)
    if user.role == "admin":
        return query
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


def visible_enterprise_record_query(user):
    query = EnterpriseRecord.query
    if not user.is_authenticated or not user.active:
        return query.filter(EnterpriseRecord.id == -1)
    if user.role == "admin":
        return query
    record_ids = {
        row[0] for row in db.session.query(EnterpriseRecord.id).filter(db.or_(
            EnterpriseRecord.requester_id == user.id,
            EnterpriseRecord.assignee_id == user.id,
        )).all()
    }
    record_ids.update(
        row[0] for row in db.session.query(Approval.enterprise_record_id).filter(
            Approval.approver_id == user.id
        ).all()
    )
    group_ids = user_support_group_ids(user)
    if group_ids:
        record_ids.update(
            row[0] for row in db.session.query(OperationalTask.parent_id).filter(
                OperationalTask.parent_type == "enterprise",
                OperationalTask.assignment_group_id.in_(group_ids),
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
    if record.requester_id == user.id or record.assignee_id == user.id:
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
    windows = SupportGroup.query.filter_by(name="Windows").first()
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
        db.session.commit()
        return
    admin_password = current_app.config.get("BOOTSTRAP_ADMIN_PASSWORD") or os.getenv("ADMIN_PASSWORD")
    if not admin_password:
        raise RuntimeError("ADMIN_PASSWORD is required to bootstrap the first administrator.")
    if not current_app.config.get("TESTING") and len(admin_password) < 14:
        raise RuntimeError("ADMIN_PASSWORD must contain at least 14 characters.")
    admin = User(username="admin", name="System Administrator", email="admin@example.local",
                 password_hash=generate_password_hash(admin_password), role="admin")
    db.session.add(admin)
    db.session.flush()
    seed_itil(admin)
    db.session.commit()


def mapped_role(groups, mapping_name, default="requester"):
    """Map directory/realm groups to a ServiceOps role without trusting user input."""
    allowed = {"requester", "agent", "manager", "admin"}
    try:
        mappings = json.loads(setting_value(mapping_name, "{}"))
    except json.JSONDecodeError:
        mappings = {}
    normalized = {str(group).lower() for group in groups}
    for group, role in mappings.items():
        if str(group).lower() in normalized and role in allowed:
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
    db.session.add(Audit(
        user_id=user.id, action="directory group sync", target=user.username,
        details=", ".join(sorted(mapping.support_group.name for mapping in desired.values()))
                or "No mapped teams",
    ))


def provision_external_user(provider, subject, username, name, email, role, groups=None):
    identity = ExternalIdentity.query.filter_by(provider=provider, subject=subject).first()
    if identity:
        user = identity.user
        user.name, user.email, user.role = name, email, role
        user.active = True
        if provider == "ldap":
            sync_directory_team_memberships(user, groups)
        return user
    base = (username or f"{provider}-{uuid.uuid4().hex[:8]}").strip().lower()[:70]
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
    return user


def ldap_authenticate(username, password):
    if not password or not setting_bool("LDAP_ENABLED"):
        return None
    uri = setting_value("LDAP_SERVER_URI", "")
    use_ssl = uri.lower().startswith("ldaps://")
    host = uri.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    port = int(os.getenv("LDAP_PORT", "636" if use_ssl else "389"))
    validate = ssl.CERT_REQUIRED if setting_bool("LDAP_VALIDATE_CERT", True) else ssl.CERT_NONE
    tls = Tls(validate=validate, ca_certs_file=os.getenv("LDAP_CA_CERT") or None)
    server = Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL,
                    connect_timeout=int(os.getenv("LDAP_TIMEOUT", "8")))
    service = Connection(server, user=setting_value("LDAP_BIND_DN") or None,
                         password=setting_value("LDAP_BIND_PASSWORD") or None,
                         auto_bind=False, receive_timeout=int(os.getenv("LDAP_TIMEOUT", "8")))
    service.open()
    if not use_ssl and setting_bool("LDAP_START_TLS", True):
        if not service.start_tls():
            return None
    if not service.bind():
        return None
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
        DEPLOYMENT_PROFILE="production",
        LDAP_ENABLED=env_bool("LDAP_ENABLED"),
        KEYCLOAK_ENABLED=env_bool("KEYCLOAK_ENABLED"),
        LOCAL_AUTH_ENABLED=env_bool("LOCAL_AUTH_ENABLED", True),
    )
    if test_config:
        app.config.update(test_config)
    if app.config["TESTING"]:
        app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or "test-only-secret"
        app.config["BOOTSTRAP_ADMIN_PASSWORD"] = app.config.get(
            "BOOTSTRAP_ADMIN_PASSWORD", "Admin123!"
        )
    elif not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY is required and must contain at least 32 characters.")
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

    with app.app_context():
        db.create_all()
        seed()
        UserPreference.query.filter(UserPreference.theme != "light").update({"theme": "light"})
        db.session.commit()
        app.config["LOCAL_AUTH_ENABLED"] = setting_bool("LOCAL_AUTH_ENABLED", True)
        app.config["LDAP_ENABLED"] = setting_bool("LDAP_ENABLED")
        app.config["KEYCLOAK_ENABLED"] = setting_bool("KEYCLOAK_ENABLED")
        app.config["MAX_CONTENT_LENGTH"] = int(setting_value("MAX_UPLOAD_MB", "20")) * 1024 * 1024
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

    @app.context_processor
    def ui_context():
        platform_context = {
            "instance_name": setting_value("INSTANCE_NAME", "ServiceOps"),
            "company_name": setting_value("COMPANY_NAME", "Your Company"),
            "brand_teal": setting_value("BRAND_TEAL", "#003e4c"),
            "brand_amber": setting_value("BRAND_AMBER", "#f9aa3c"),
            "support_email": setting_value("SUPPORT_EMAIL", ""),
            "has_company_logo": os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], "company-logo.png")),
            "test_fixture_active": setting_bool("TEST_FIXTURE_ACTIVE"),
        }
        if not current_user.is_authenticated:
            return platform_context
        preference = UserPreference.query.filter_by(user_id=current_user.id).first()
        if not preference:
            preference = UserPreference(user_id=current_user.id)
            db.session.add(preference)
            db.session.commit()
        return platform_context | {
            "ui_preference": preference,
            "ui_favorites": Favorite.query.filter_by(user_id=current_user.id).order_by(Favorite.folder, Favorite.label).all(),
            "ui_history": RecentView.query.filter_by(user_id=current_user.id).order_by(RecentView.viewed_at.desc()).limit(12).all(),
            "unread_notifications": Notification.query.filter_by(user_id=current_user.id, read=False).count(),
        }

    @app.get("/health")
    def health():
        db.session.execute(db.select(func.count(User.id))).scalar()
        return jsonify(status="ok")

    @app.get("/live")
    def live():
        return jsonify(status="alive")

    @app.get("/ready")
    def ready():
        db.session.execute(db.select(func.count(User.id))).scalar()
        return jsonify(status="ready")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if setting_bool("ENABLE_HSTS"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            provider = request.form.get("provider", "local")
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
                login_user(user)
                audit("login", user.username, f"provider={provider}")
                db.session.commit()
                preference = UserPreference.query.filter_by(user_id=user.id).first()
                return redirect(preference.start_page if preference else url_for("dashboard"))
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
        audit("login", user.username, "provider=keycloak")
        db.session.commit()
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard():
        visible_requests = visible_catalog_request_query(current_user)
        ticket_query = visible_ticket_query(current_user)
        counts = {
            "incident": ticket_query.filter_by(kind="incident").count(),
            "request": visible_requests.count(),
            "change": ticket_query.filter_by(kind="change").count(),
        }
        open_count = (
            ticket_query.filter(Ticket.state.notin_(["Resolved", "Closed", "Cancelled"])).count()
            + visible_requests.filter(
                CatalogRequest.state.notin_(["Closed Complete", "Closed Incomplete", "Cancelled"])
            ).count()
        )
        recent = visible_tickets().order_by(Ticket.updated_at.desc()).limit(8).all()
        return render_template("dashboard.html", counts=counts, open_count=open_count, recent=recent)

    def visible_tickets():
        return visible_ticket_query(current_user)

    @app.get("/tickets/<kind>")
    @login_required
    def tickets(kind):
        if kind not in ("incident", "change"):
            abort(404)
        query = visible_tickets().filter_by(kind=kind)
        q = request.args.get("q", "").strip()
        state = request.args.get("state", "").strip()
        if q:
            query = query.filter(db.or_(Ticket.number.ilike(f"%{q}%"), Ticket.title.ilike(f"%{q}%")))
        if state:
            query = query.filter_by(state=state)
        return render_template("tickets.html", tickets=query.order_by(Ticket.updated_at.desc()).all(),
                               kind=kind, q=q, state=state)

    @app.route("/tickets/new/<kind>", methods=["GET", "POST"])
    @login_required
    def ticket_new(kind):
        if kind not in ("incident", "change"):
            abort(404)
        if kind == "change" and current_user.role == "requester":
            abort(403)
        if request.method == "POST":
            try:
                group_id = int(request.form.get("group_id", ""))
            except (TypeError, ValueError):
                abort(400, description="Select a valid owning IT team.")
            owning_group = db.session.get(SupportGroup, group_id)
            if (
                not owning_group
                or not owning_group.active
                or owning_group.group_type != "IT Fulfillment"
            ):
                abort(400, description="Select an active IT fulfillment team.")
            if kind == "change" and (
                not owning_group.manager
                or not owning_group.manager.active
            ):
                abort(409, description=(
                    "The selected team must have an active manager before a change can be submitted."
                ))
            ticket = Ticket(number=next_number(kind), kind=kind,
                            title=request.form["title"].strip(), description=request.form["description"].strip(),
                            category=request.form.get("category", "General"), priority=request.form.get("priority", "P3"),
                            requester_id=current_user.id)
            db.session.add(ticket)
            db.session.flush()
            attach_slas("ticket", ticket.id, ticket.priority)
            if kind == "change":
                governance = ChangeGovernance(ticket_id=ticket.id, change_type=request.form.get("change_type", "Normal"),
                                              risk_score=int(request.form.get("risk_score", 50)),
                                              impact=request.form.get("impact", "Medium"),
                                              implementation_plan=request.form.get("implementation_plan", ""),
                                              test_plan=request.form.get("test_plan", ""),
                                              backout_plan=request.form.get("backout_plan", ""),
                                              planned_start=datetime.fromisoformat(request.form["planned_start"]) if request.form.get("planned_start") else None,
                                              planned_end=datetime.fromisoformat(request.form["planned_end"]) if request.form.get("planned_end") else None,
                                              ci_id=int(request.form["ci_id"]) if request.form.get("ci_id") else None)
                db.session.add(governance)
                db.session.flush()
                db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=owning_group.id))
                db.session.add(ChangeRevision(ticket_id=ticket.id, revision=1))
                db.session.flush()
                create_approval_chain(
                    f"{ticket.number} change authorization v1",
                    "ticket", ticket.id, change_approval_stages(ticket),
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
            flash(f"{ticket.number} created.", "success")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        teams = SupportGroup.query.filter_by(group_type="IT Fulfillment", active=True).order_by(SupportGroup.name).all()
        return render_template("ticket_form.html", kind=kind, cis=ConfigurationItem.query.order_by(ConfigurationItem.name).all(),
                               teams=teams, default_priority=setting_value("DEFAULT_TICKET_PRIORITY", "P3"),
                               change_freeze_message=setting_value("CHANGE_FREEZE_MESSAGE", ""))

    @app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
    @login_required
    def ticket_detail(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        if not user_can_view_ticket(current_user, ticket):
            abort(403, description="You are not involved in this ticket or its assigned work.")
        if request.method == "POST":
            action = request.form.get("action")
            if action == "comment":
                body = request.form.get("body", "").strip()
                if body:
                    db.session.add(Comment(ticket_id=ticket.id, user_id=current_user.id, body=body))
                    log_history("ticket", ticket.id, "Comment added", details=body[:500])
                    audit("comment", ticket.number)
            elif action == "update":
                require_ticket_team_access(ticket)
                assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
                eligible_ids = {agent.id for agent in ticket_team_agents(ticket)}
                if assignee_id is not None and assignee_id not in eligible_ids:
                    abort(400, description="The assignee must be an active member of the owning team.")
                before = {
                    "state": ticket.state,
                    "priority": ticket.priority,
                    "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned",
                }
                transition_ticket(ticket, request.form["state"])
                ticket.priority = request.form["priority"]
                ticket.assignee_id = assignee_id
                assignee = db.session.get(User, assignee_id) if assignee_id else None
                log_field_changes("ticket", ticket.id, before, {
                    "state": ticket.state,
                    "priority": ticket.priority,
                    "assigned to": assignee.name if assignee else "Unassigned",
                })
                audit("update", ticket.number, f"{ticket.state}, {ticket.priority}")
            db.session.commit()
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        agents = ticket_team_agents(ticket)
        owning_group = ticket_owning_group(ticket)
        can_manage_ticket = user_can_manage_ticket(current_user, ticket)
        chains = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).all()
        slas = TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).all()
        work_tasks = OperationalTask.query.filter_by(
            parent_type="ticket", parent_id=ticket.id
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
        history = TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all()
        ci_links = TaskCI.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).order_by(TaskCI.relationship_role).all()
        return render_template(
            "ticket_detail.html", ticket=ticket, agents=agents, chains=chains, slas=slas,
            ticket_state_options=allowed_ticket_states(ticket), owning_group=owning_group,
            can_manage_ticket=can_manage_ticket, related=related_records("ticket", ticket.id),
            relation_labels=RELATION_LABELS, work_tasks=work_tasks,
            work_task_states=OPERATIONAL_TASK_TRANSITIONS, history=history,
            ci_links=ci_links, cis=ConfigurationItem.query.order_by(ConfigurationItem.name).all(),
            teams=SupportGroup.query.filter_by(group_type="IT Fulfillment", active=True).order_by(SupportGroup.name).all(),
            task_agents=task_agents, task_permissions=task_permissions,
        )

    @app.post("/change/<int:ticket_id>/plan")
    @roles("agent", "manager", "admin")
    def change_plan_update(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        if ticket.kind != "change" or not ticket.change_governance:
            abort(404)
        require_ticket_team_access(ticket)
        governance = ticket.change_governance
        try:
            risk_score = max(0, min(100, int(request.form.get("risk_score", "50"))))
            planned_start = (
                datetime.fromisoformat(request.form["planned_start"])
                if request.form.get("planned_start") else None
            )
            planned_end = (
                datetime.fromisoformat(request.form["planned_end"])
                if request.form.get("planned_end") else None
            )
            ci_id = int(request.form["ci_id"]) if request.form.get("ci_id") else None
        except (TypeError, ValueError):
            abort(400, description="Change plan dates, risk, or CI are invalid.")
        if planned_start and planned_end and planned_end <= planned_start:
            abort(400, description="Planned end must be later than planned start.")
        if ci_id and not db.session.get(ConfigurationItem, ci_id):
            abort(400, description="The selected configuration item does not exist.")
        required_text = {
            "Short description": request.form.get("title", "").strip(),
            "Description": request.form.get("description", "").strip(),
            "Implementation plan": request.form.get("implementation_plan", "").strip(),
            "Test plan": request.form.get("test_plan", "").strip(),
            "Backout plan": request.form.get("backout_plan", "").strip(),
        }
        missing = [label for label, value in required_text.items() if not value]
        if missing:
            abort(400, description=f"Required change-plan fields are missing: {', '.join(missing)}.")
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
        governance.impact = request.form.get("impact", "Medium")
        governance.implementation_plan = request.form.get("implementation_plan", "").strip()
        governance.test_plan = request.form.get("test_plan", "").strip()
        governance.backout_plan = request.form.get("backout_plan", "").strip()
        governance.planned_start = planned_start
        governance.planned_end = planned_end
        governance.ci_id = ci_id
        governance.conflict_status = "Not Run"
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
        supersede_change_approval(ticket, changed_fields)
        audit("revise change plan", ticket.number, ", ".join(changed_fields))
        db.session.commit()
        flash(
            f"Change plan revised. {ticket.number} returned to Awaiting Approval and approvers were notified.",
            "success",
        )
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/incident/<int:ticket_id>/major-incident")
    @roles("agent", "manager", "admin")
    def major_incident_update(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        if ticket.kind != "incident":
            abort(404)
        require_ticket_team_access(ticket)
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

    @app.post("/record/<source_type>/<int:source_id>/relationships")
    @roles("agent", "manager", "admin")
    def record_link_add(source_type, source_id):
        source = record_reference(source_type, source_id)
        if not source:
            abort(404)
        if isinstance(source, Ticket):
            require_ticket_team_access(source)
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
        ci = db.get_or_404(ConfigurationItem, int(request.form["ci_id"]))
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
            db.session.commit()
        return redirect(record_url(target))

    @app.post("/change/<int:ticket_id>/tasks")
    @roles("agent", "manager", "admin")
    def change_task_add(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        if ticket.kind != "change":
            abort(404)
        require_ticket_team_access(ticket)
        group = db.get_or_404(SupportGroup, int(request.form["group_id"]))
        if not group.active or group.group_type != "IT Fulfillment":
            abort(400, description="Change tasks require an active IT fulfillment team.")
        task_type = request.form.get("task_type")
        if task_type not in ("Planning", "Implementation", "Testing", "Review"):
            abort(400)
        planned_start = (
            datetime.fromisoformat(request.form["planned_start"])
            if request.form.get("planned_start") else None
        )
        planned_end = (
            datetime.fromisoformat(request.form["planned_end"])
            if request.form.get("planned_end") else None
        )
        governance = ticket.change_governance
        if planned_start and planned_end and planned_end <= planned_start:
            abort(400, description="Task end must be later than task start.")
        if task_type == "Implementation" and governance:
            if (
                governance.planned_start and planned_start
                and planned_start < governance.planned_start
            ) or (
                governance.planned_end and planned_end
                and planned_end > governance.planned_end
            ):
                abort(409, description=(
                    "Implementation task dates must fall within the parent change window."
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
        )
        db.session.add(task)
        db.session.flush()
        log_history(
            "ticket", ticket.id, "Change task created",
            details=f"{task.number} {task.task_type}: {task.title} → {group.name}",
        )
        audit("create", task.number, f"{ticket.number}: {task.title}")
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.post("/operational-task/<int:task_id>")
    @roles("agent", "manager", "admin")
    def operational_task_update(task_id):
        task = db.get_or_404(OperationalTask, task_id)
        if not user_in_group(current_user, task.assignment_group):
            abort(403, description=(
                f"Only active members of {task.assignment_group.name} can update {task.number}."
            ))
        before = {
            "state": task.state,
            "assigned to": task.assignee.name if task.assignee else "Unassigned",
            "work notes": task.work_notes,
        }
        assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
        if assignee_id:
            assignee = db.session.get(User, assignee_id)
            if not assignee or not user_in_group(assignee, task.assignment_group):
                abort(400, description="The assignee must belong to the task assignment group.")
        else:
            assignee = None
        transition_operational_task(task, request.form["state"])
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
        return redirect(record_url(parent))

    @app.get("/knowledge")
    @login_required
    def knowledge():
        q = request.args.get("q", "").strip()
        query = Knowledge.query.filter_by(published=True)
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

    @app.get("/assets")
    @roles("agent", "manager", "admin")
    def assets():
        return render_template("assets.html", assets=Asset.query.order_by(Asset.asset_tag).all())

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

    @app.get("/admin/users")
    @roles("admin")
    def users():
        memberships = GroupMember.query.all()
        directory_managed = {
            (item.user_id, item.group_id)
            for item in DirectoryManagedMembership.query.all()
        }
        return render_template(
            "users.html", users=User.query.order_by(User.name).all(),
            memberships=memberships, directory_managed=directory_managed,
        )

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @roles("admin")
    def user_new():
        if request.method == "POST":
            user = User(username=request.form["username"], name=request.form["name"], email=request.form["email"],
                        password_hash=generate_password_hash(request.form["password"]), role=request.form["role"])
            db.session.add(user)
            audit("create", user.username, user.role)
            db.session.commit()
            return redirect(url_for("users"))
        return render_template("user_form.html")

    @app.get("/branding/company-logo.png")
    def company_logo():
        path = os.path.join(app.config["UPLOAD_FOLDER"], "company-logo.png")
        if not os.path.exists(path):
            abort(404)
        return send_from_directory(app.config["UPLOAD_FOLDER"], "company-logo.png",
                                   mimetype="image/png", max_age=300)

    @app.route("/admin/settings", methods=["GET", "POST"])
    @roles("admin")
    def system_settings():
        definitions = [item for group in SETTING_DEFINITIONS.values() for item in group]
        if request.method == "POST":
            errors, restart_required, changed = [], False, []
            for definition in definitions:
                key, field_type = definition["key"], definition["type"]
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
    def audit_log():
        return render_template("audit.html", rows=Audit.query.order_by(Audit.created_at.desc()).limit(250).all())

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
        state = request.args.get("state", "").strip()
        if q:
            query = query.filter(db.or_(EnterpriseRecord.number.ilike(f"%{q}%"),
                                        EnterpriseRecord.title.ilike(f"%{q}%")))
        if state:
            query = query.filter_by(state=state)
        return render_template("module_records.html", domain=domain, config=config,
                               records=query.order_by(EnterpriseRecord.updated_at.desc()).all(), q=q, state=state)

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
                db.session.add(Notification(user_id=admin.id, title=f"Approval requested: {record.number}",
                                            body=record.title))
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
        record = db.get_or_404(EnterpriseRecord, record_id)
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
                transition_enterprise(record, request.form["state"])
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
                db.session.add(Notification(user_id=record.requester_id, title=f"{record.number} {record.state.lower()}",
                                            body=approval.comments or f"Your record was {record.state.lower()}."))
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
            agents=agents, record_state_options=allowed_enterprise_states(record),
            related=related_records("enterprise", record.id), relation_labels=RELATION_LABELS,
            work_tasks=work_tasks, work_task_states=OPERATIONAL_TASK_TRANSITIONS,
            history=TaskHistory.query.filter_by(
                target_type="enterprise", target_id=record.id
            ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all(),
            ci_links=TaskCI.query.filter_by(
                target_type="enterprise", target_id=record.id
            ).order_by(TaskCI.relationship_role).all(),
            cis=ConfigurationItem.query.order_by(ConfigurationItem.name).all(),
            teams=SupportGroup.query.filter_by(
                group_type="IT Fulfillment", active=True
            ).order_by(SupportGroup.name).all(),
            task_agents=task_agents, task_permissions=task_permissions,
            can_manage_record=can_manage_record,
        )

    @app.post("/problem/<int:record_id>/analysis")
    @roles("agent", "manager", "admin")
    def problem_analysis_update(record_id):
        record = db.get_or_404(EnterpriseRecord, record_id)
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
        if ci_id and not db.session.get(ConfigurationItem, ci_id):
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
            "primary CI": db.session.get(ConfigurationItem, ci_id).name if ci_id else "",
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
        record = db.get_or_404(EnterpriseRecord, record_id)
        if record.domain != "problem":
            abort(404)
        if not user_can_manage_enterprise_record(current_user, record):
            abort(403)
        group = db.get_or_404(SupportGroup, int(request.form["group_id"]))
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

    @app.get("/catalog")
    @login_required
    def catalog():
        return render_template("catalog.html", items=CatalogItem.query.filter_by(active=True).order_by(CatalogItem.category, CatalogItem.name).all())

    @app.post("/catalog/<int:item_id>/order")
    @login_required
    def catalog_order(item_id):
        item = db.get_or_404(CatalogItem, item_id)
        if not item.active:
            abort(404)
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
            manager = User.query.filter_by(role="admin", active=True).first()
            fulfillment = SupportGroup.query.filter_by(name="Service Desk").first()
            stages = [
                {"name": "Manager approval", "mode": "all", "approver_ids": [manager.id]},
                {"name": "Fulfillment authorization", "mode": "any",
                 "approver_ids": [member.user_id for member in fulfillment.members]},
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

    @app.get("/cmdb")
    @roles("agent", "manager", "admin")
    def cmdb():
        return render_template("cmdb.html", cis=ConfigurationItem.query.order_by(ConfigurationItem.ci_class, ConfigurationItem.name).all(),
                               relationships=CIRelationship.query.all())

    @app.route("/cmdb/new", methods=["GET", "POST"])
    @roles("admin")
    def ci_new():
        if request.method == "POST":
            ci = ConfigurationItem(name=request.form["name"], ci_class=request.form["ci_class"],
                                   environment=request.form["environment"], operational_status=request.form["operational_status"],
                                   ip_address=request.form.get("ip_address"), owner_id=current_user.id)
            db.session.add(ci)
            audit("create", "CI", ci.name)
            db.session.commit()
            return redirect(url_for("cmdb"))
        return render_template("ci_form.html")

    @app.get("/approvals")
    @login_required
    def approvals():
        query = Approval.query
        if current_user.role != "admin":
            query = query.filter_by(approver_id=current_user.id)
        return render_template("approvals.html", approvals=query.order_by(Approval.id.desc()).all())

    @app.post("/approval-votes/<int:vote_id>/decide")
    @login_required
    def approval_vote_decide(vote_id):
        vote = db.get_or_404(ApprovalVote, vote_id)
        if vote.approver_id != current_user.id:
            abort(403)
        decision = request.form.get("decision")
        if decision not in ("Approved", "Rejected"):
            abort(400)
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
        for chain in ApprovalChain.query.order_by(ApprovalChain.created_at.desc()).all():
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
        pending = ApprovalVote.query.filter_by(approver_id=current_user.id, state="Requested").all()
        return render_template("approval_chains.html", chains=chains, pending=pending)

    @app.get("/requests")
    @login_required
    def requests_list():
        query = visible_catalog_request_query(current_user)
        return render_template("requests.html", requests=query.order_by(CatalogRequest.opened_at.desc()).all())

    @app.get("/request/<int:request_id>")
    @login_required
    def request_detail(request_id):
        req = db.get_or_404(CatalogRequest, request_id)
        if not user_can_view_catalog_request(current_user, req):
            abort(403, description="You are not involved in this request or its fulfillment.")
        chains = {}
        slas = {}
        task_state_options = {}
        catalog_task_permissions = {}
        catalog_task_create_permissions = {}
        for ritm in req.items:
            catalog_task_create_permissions[ritm.id] = user_can_manage_ritm(
                current_user, ritm
            )
            chains[ritm.id] = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm.id).all()
            slas[ritm.id] = TaskSLA.query.filter_by(target_type="ritm", target_id=ritm.id).all()
            for task in ritm.tasks:
                task_state_options[task.id] = CATALOG_TASK_TRANSITIONS.get(
                    task.state, (task.state,)
                )
                catalog_task_permissions[task.id] = user_in_group(
                    current_user, task.assignment_group
                )
        return render_template(
            "request_detail.html", req=req, chains=chains, slas=slas,
            task_state_options=task_state_options,
            teams=SupportGroup.query.filter_by(
                group_type="IT Fulfillment", active=True
            ).order_by(SupportGroup.name).all(),
            catalog_items=CatalogItem.query.filter_by(active=True).order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
            related_by_ritm={
                ritm.id: related_records("ritm", ritm.id) for ritm in req.items
            },
            history_by_ritm={
                ritm.id: TaskHistory.query.filter_by(
                    target_type="ritm", target_id=ritm.id
                ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all()
                for ritm in req.items
            },
            catalog_task_permissions=catalog_task_permissions,
            can_add_request_item=user_can_add_request_item(current_user, req),
            catalog_task_create_permissions=catalog_task_create_permissions,
        )

    @app.post("/request/<int:request_id>/items")
    @login_required
    def request_item_add(request_id):
        req = db.get_or_404(CatalogRequest, request_id)
        if req.state not in ("Open", "Awaiting Approval"):
            abort(409, description="Items cannot be added to a completed request.")
        if not user_can_add_request_item(current_user, req):
            abort(403, description="Only request participants or an administrator can add items.")
        item = db.get_or_404(CatalogItem, int(request.form["catalog_item_id"]))
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
        group = db.get_or_404(SupportGroup, int(request.form["group_id"]))
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
        transition_catalog_task(task, request.form["state"])
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
        return redirect(url_for("request_detail", request_id=ritm.request_id))

    @app.route("/itil/administration", methods=["GET", "POST"])
    @roles("admin")
    def itil_admin():
        if request.method == "POST":
            action = request.form.get("action")
            if action == "add_directory_mapping":
                directory_group = request.form.get("directory_group", "").strip()
                group = db.get_or_404(SupportGroup, int(request.form["group_id"]))
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
            elif action == "set_manager":
                group = db.get_or_404(SupportGroup, int(request.form["group_id"]))
                if group.group_type != "IT Fulfillment":
                    abort(400)
                old_manager_id = group.manager_id
                manager_id = int(request.form["manager_id"]) if request.form.get("manager_id") else None
                manager = db.session.get(User, manager_id) if manager_id else None
                if manager and (not manager.active or manager.role not in ("agent", "manager", "admin")):
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
                    if manager.role != "admin":
                        manager.role = "manager"
                audit("configure", f"{group.name} manager",
                      manager.username if manager else "Unassigned")
                flash(f"{group.name} manager updated.", "success")
            elif action == "set_ccb_authority":
                user = db.get_or_404(User, int(request.form["user_id"]))
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
                item = db.get_or_404(CatalogItem, int(request.form["catalog_item_id"]))
                group = db.get_or_404(SupportGroup, int(request.form["group_id"]))
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
                group = db.get_or_404(SupportGroup, group_id)
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
                    item = db.get_or_404(CatalogItem, item_id)
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
            else:
                abort(400)
            db.session.commit()
            return redirect(url_for("itil_admin"))
        groups = SupportGroup.query.order_by(SupportGroup.name).all()
        teams = [group for group in groups if group.group_type == "IT Fulfillment"]
        fulfillment_groups = [
            group for group in groups
            if group.active and group.group_type in ("Fulfillment", "IT Fulfillment")
        ]
        candidates = User.query.filter(
            User.active.is_(True), User.role.in_(["agent", "manager", "admin"])
        ).order_by(User.name).all()
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
        ccb_approver_ids = {
            member.user_id for member in ccb.members if member.role == "CCB approver"
        }
        return render_template(
            "itil_admin.html", groups=groups, teams=teams, candidates=candidates,
            ccb=ccb, ccb_approver_ids=ccb_approver_ids,
            directory_mappings=DirectoryGroupMapping.query.order_by(
                DirectoryGroupMapping.directory_group
            ).all(),
            services=ServiceOffering.query.all(), sla_definitions=SLADefinition.query.all(),
            catalog_items=CatalogItem.query.order_by(
                CatalogItem.category, CatalogItem.name
            ).all(),
            fulfillment_groups=fulfillment_groups,
        )

    @app.post("/change/<int:ticket_id>/conflicts")
    @roles("agent", "manager", "admin")
    def detect_change_conflicts(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        require_ticket_team_access(ticket)
        governance = ticket.change_governance
        if not governance:
            abort(404)
        conflicts = []
        if governance.planned_start and governance.planned_end:
            overlapping = ChangeGovernance.query.filter(
                ChangeGovernance.id != governance.id,
                ChangeGovernance.planned_start < governance.planned_end,
                ChangeGovernance.planned_end > governance.planned_start,
            ).all()
            current_ci_ids = {
                link.ci_id for link in TaskCI.query.filter_by(
                    target_type="ticket", target_id=ticket.id
                ).all()
            }
            if governance.ci_id:
                current_ci_ids.add(governance.ci_id)
            for other in overlapping:
                other_ci_ids = {
                    link.ci_id for link in TaskCI.query.filter_by(
                        target_type="ticket", target_id=other.ticket_id
                    ).all()
                }
                if other.ci_id:
                    other_ci_ids.add(other.ci_id)
                if current_ci_ids.intersection(other_ci_ids):
                    conflicts.append(other.ticket.number)
        governance.conflict_status = f"Conflict: {', '.join(conflicts)}" if conflicts else "No conflict"
        log_history(
            "ticket", ticket.id, "Conflict detection completed",
            details=governance.conflict_status,
        )
        audit("conflict check", ticket.number, governance.conflict_status)
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    @app.get("/notifications")
    @login_required
    def notifications():
        rows = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
        Notification.query.filter_by(user_id=current_user.id, read=False).update({"read": True})
        db.session.commit()
        return render_template("notifications.html", rows=rows)

    @app.get("/analytics")
    @roles("agent", "manager", "admin")
    def analytics():
        ticket_ids = [row.id for row in visible_ticket_query(current_user).all()]
        record_ids = [row.id for row in visible_enterprise_record_query(current_user).all()]
        ticket_states = dict(db.session.query(Ticket.state, func.count(Ticket.id)).filter(
            Ticket.id.in_(ticket_ids)
        ).group_by(Ticket.state).all())
        domain_counts = dict(db.session.query(EnterpriseRecord.domain, func.count(EnterpriseRecord.id)).filter(
            EnterpriseRecord.id.in_(record_ids)
        ).group_by(EnterpriseRecord.domain).all())
        priority_counts = dict(db.session.query(Ticket.priority, func.count(Ticket.id)).filter(
            Ticket.id.in_(ticket_ids)
        ).group_by(Ticket.priority).all())
        overdue = EnterpriseRecord.query.filter(
            EnterpriseRecord.id.in_(record_ids), EnterpriseRecord.due_at < now(),
            EnterpriseRecord.state.notin_(["Closed", "Resolved", "Completed"])
        ).count()
        return render_template("analytics.html", ticket_states=ticket_states, domain_counts=domain_counts,
                               priority_counts=priority_counts, overdue=overdue, modules=DOMAIN_CONFIG)

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
            for row in Knowledge.query.filter(db.or_(Knowledge.title.ilike(pattern), Knowledge.body.ilike(pattern))).limit(20):
                results.append({"type": "Knowledge", "label": row.title, "url": url_for("knowledge"),
                                "meta": row.category})
            for row in EnterpriseRecord.query.filter(EnterpriseRecord.id.in_(visible_enterprise_ids), db.or_(
                                                             EnterpriseRecord.number.ilike(pattern),
                                                             EnterpriseRecord.title.ilike(pattern))).limit(20):
                results.append({"type": DOMAIN_CONFIG[row.domain]["name"], "label": f"{row.number} · {row.title}",
                                "url": url_for("enterprise_detail", record_id=row.id), "meta": row.state})
            for row in ConfigurationItem.query.filter(ConfigurationItem.name.ilike(pattern)).limit(20):
                results.append({"type": "Configuration item", "label": row.name, "url": url_for("cmdb"),
                                "meta": row.ci_class})
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
            return jsonify(results=results[:30])
        return render_template("search.html", q=q, results=results[:60])

    @app.post("/ui/favorite")
    @login_required
    def favorite_toggle():
        url = request.form.get("url", "")[:500]
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
        return jsonify(active=active)

    @app.post("/ui/history")
    @login_required
    def history_record():
        url = request.form.get("url", "")[:500]
        if not url or url.startswith(("/static", "/health", "/ui/")):
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
            pref.start_page = request.form.get("start_page", "/")[:500]
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
        ticket = db.get_or_404(Ticket, ticket_id)
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
        return jsonify(state=state)

    @app.post("/ticket/<int:ticket_id>/checklist")
    @roles("agent", "manager", "admin")
    def checklist_add(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        require_ticket_team_access(ticket)
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
        ticket = db.get_or_404(Ticket, item.ticket_id)
        require_ticket_team_access(ticket)
        item.completed = not item.completed
        log_history(
            "ticket", ticket.id, "Checklist item updated",
            item.text, not item.completed, item.completed,
        )
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=item.ticket_id))

    @app.post("/ticket/<int:ticket_id>/attachments")
    @login_required
    def attachment_upload(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        if not user_can_view_ticket(current_user, ticket):
            abort(403)
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Choose a file to upload.", "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        original = secure_filename(upload.filename)
        if not original:
            abort(400, description="The attachment filename is invalid.")
        stored = f"{uuid.uuid4().hex}-{original}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
        upload.save(path)
        db.session.add(FileAttachment(ticket_id=ticket_id, uploaded_by_id=current_user.id,
                                      original_name=original, stored_name=stored,
                                      mime_type=upload.mimetype, size_bytes=os.path.getsize(path)))
        log_history(
            "ticket", ticket.id, "Attachment uploaded",
            details=f"{original} ({os.path.getsize(path)} bytes)",
        )
        audit("attach", ticket.number, original)
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.get("/attachments/<int:attachment_id>")
    @login_required
    def attachment_download(attachment_id):
        attachment = db.get_or_404(FileAttachment, attachment_id)
        if not user_can_view_ticket(current_user, attachment.ticket):
            abort(403)
        return send_from_directory(app.config["UPLOAD_FOLDER"], attachment.stored_name,
                                   as_attachment=True, download_name=attachment.original_name)

    @app.get("/help")
    @login_required
    def help_center():
        return render_template("help.html")

    @app.errorhandler(403)
    def forbidden(error):
        return render_template(
            "error.html", code=403,
            message=error.description or "You do not have permission to access this page.",
        ), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, message="The requested record was not found."), 404

    @app.errorhandler(409)
    def workflow_conflict(error):
        return render_template(
            "error.html", code=409,
            message=error.description or "The requested workflow transition is not allowed.",
        ), 409

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080, debug=True)
