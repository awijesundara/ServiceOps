import json
import os
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_from_directory, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
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


class ExternalIdentity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("provider", "subject", name="uq_external_identity"),)


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


class RecordLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_type = db.Column(db.String(30), nullable=False)
    source_id = db.Column(db.Integer, nullable=False)
    target_type = db.Column(db.String(30), nullable=False)
    target_id = db.Column(db.Integer, nullable=False)
    link_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)


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
    theme = db.Column(db.String(30), nullable=False, default="system")
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
    prefix = {"incident": "INC", "request": "REQ", "change": "CHG"}[kind]
    maximum = db.session.query(func.max(Ticket.id)).scalar() or 0
    return f"{prefix}{maximum + 1:07d}"


DOMAIN_CONFIG = {
    "problem": {"name": "Problems", "prefix": "PRB", "types": ["Root cause analysis", "Known error"]},
    "major_incident": {"name": "Major incidents", "prefix": "MIM", "types": ["Critical outage", "Service degradation"]},
    "customer": {"name": "Customer service", "prefix": "CS", "types": ["Support case", "Complaint", "Return / RMA", "Onboarding"]},
    "hr": {"name": "HR service delivery", "prefix": "HRC", "types": ["Benefits", "Payroll", "Employee relations", "HR systems", "Onboarding"]},
    "security": {"name": "Security operations", "prefix": "SIR", "types": ["Security incident", "Vulnerability", "Data loss", "Threat intelligence"]},
    "risk": {"name": "Risk & compliance", "prefix": "RSK", "types": ["Risk", "Control test", "Policy exception", "Audit finding"]},
    "portfolio": {"name": "Strategic portfolio", "prefix": "PRJ", "types": ["Demand", "Project", "Program", "Objective", "Agile epic"]},
    "field_service": {"name": "Field service", "prefix": "WO", "types": ["Work order", "Installation", "Repair", "Preventive maintenance"]},
    "event": {"name": "IT operations events", "prefix": "EVT", "types": ["Alert", "Infrastructure event", "Service degradation"]},
    "release": {"name": "Releases", "prefix": "REL", "types": ["Release", "Deployment", "Readiness review"]},
}


def next_enterprise_number(domain):
    prefix = DOMAIN_CONFIG[domain]["prefix"]
    latest = EnterpriseRecord.query.filter_by(domain=domain).order_by(EnterpriseRecord.id.desc()).first()
    sequence = (latest.id + 1) if latest else 1
    return f"{prefix}{sequence:07d}"


def sequence_number(model, prefix):
    latest = model.query.order_by(model.id.desc()).first()
    return f"{prefix}{((latest.id if latest else 0) + 1):07d}"


def target_record(target_type, target_id):
    models = {"ticket": Ticket, "ritm": RequestedItem, "enterprise": EnterpriseRecord}
    model = models.get(target_type)
    return db.session.get(model, target_id) if model else None


def set_target_state(target_type, target_id, state):
    target = target_record(target_type, target_id)
    if target:
        target.state = state


def activate_gate(gate):
    gate.state = "Requested"
    for vote in gate.votes:
        vote.state = "Requested"
        db.session.add(Notification(user_id=vote.approver_id, title=f"Approval requested: {gate.name}",
                                    body=f"Your decision is required for approval chain {gate.chain.name}."))


def create_approval_chain(name, target_type, target_id, stages):
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
    return chain


def decide_vote(vote, decision, comments):
    if vote.state != "Requested":
        abort(409)
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


def create_catalog_task(ritm):
    if ritm.tasks:
        return ritm.tasks[0]
    group = SupportGroup.query.filter_by(name="Service Desk").first()
    task = CatalogTask(number=sequence_number(CatalogTask, "SCTASK"), requested_item_id=ritm.id,
                       title=f"Fulfill {ritm.item.name}", assignment_group_id=group.id if group else None,
                       due_at=ritm.due_at)
    db.session.add(task)
    return task


def seed_itil(admin, agent, demo_mode=True):
    if not SupportGroup.query.filter_by(name="Service Desk").first():
        service_desk = SupportGroup(name="Service Desk", group_type="Fulfillment", manager_id=agent.id)
        security = SupportGroup(name="Security Operations", group_type="Fulfillment", manager_id=admin.id)
        db.session.add_all([service_desk, security])
        db.session.flush()
        db.session.add_all([
            GroupMember(group_id=service_desk.id, user_id=agent.id, role="member"),
            GroupMember(group_id=security.id, user_id=admin.id, role="manager"),
        ])
    team_names = ["CoreApps", "Database", "Network", "Windows", "Unix", "SSD"]
    manager_password = os.getenv("TEAM_MANAGER_PASSWORD", "Manager123!")
    managers = []
    for team_name in team_names:
        slug = team_name.lower()
        manager = User.query.filter_by(username=f"{slug}.manager").first()
        if not manager:
            manager = User(username=f"{slug}.manager", name=f"{team_name} Manager",
                           email=f"{slug}.manager@example.local",
                           password_hash=generate_password_hash(
                               manager_password if demo_mode else uuid.uuid4().hex),
                           role="manager", active=demo_mode)
            db.session.add(manager)
            db.session.flush()
        managers.append(manager)
        group = SupportGroup.query.filter_by(name=team_name).first()
        if not group:
            group = SupportGroup(name=team_name, group_type="IT Fulfillment", manager_id=manager.id)
            db.session.add(group)
            db.session.flush()
        else:
            group.manager_id = manager.id
            group.group_type = "IT Fulfillment"
        if not GroupMember.query.filter_by(group_id=group.id, user_id=manager.id).first():
            db.session.add(GroupMember(group_id=group.id, user_id=manager.id, role="manager"))
        if demo_mode:
            demo_password = os.getenv("DEMO_USER_PASSWORD", "ServiceOpsDemo123!")
            team_user = User.query.filter_by(username=f"{slug}.agent").first()
            if not team_user:
                team_user = User(
                    username=f"{slug}.agent", name=f"{team_name} Demo Agent",
                    email=f"{slug}.agent@demo.serviceops.local",
                    password_hash=generate_password_hash(demo_password), role="agent")
                db.session.add(team_user)
                db.session.flush()
            if not GroupMember.query.filter_by(group_id=group.id, user_id=team_user.id).first():
                db.session.add(GroupMember(group_id=group.id, user_id=team_user.id, role="member"))
    ccb = SupportGroup.query.filter_by(name="Change Control Board").first()
    if not ccb:
        ccb = SupportGroup(name="Change Control Board", group_type="CCB Approval",
                           manager_id=managers[0].id)
        db.session.add(ccb)
        db.session.flush()
    ccb.manager_id = managers[0].id
    for membership in list(ccb.members):
        if membership.user.role != "manager":
            db.session.delete(membership)
    for manager in managers:
        if not GroupMember.query.filter_by(group_id=ccb.id, user_id=manager.id).first():
            db.session.add(GroupMember(group_id=ccb.id, user_id=manager.id, role="CCB member"))
    if not ServiceOffering.query.first():
        group = SupportGroup.query.filter_by(name="Service Desk").first()
        db.session.add_all([
            ServiceOffering(name="Employee Technology Service", owner_id=admin.id, support_group_id=group.id, criticality="High"),
            ServiceOffering(name="Customer Digital Service", owner_id=admin.id, support_group_id=group.id, criticality="Critical"),
        ])
    if not SLADefinition.query.first():
        db.session.add_all([
            SLADefinition(name="P1 incident response", target_type="ticket", priority="P1", duration_minutes=15),
            SLADefinition(name="P1 incident resolution", target_type="ticket", priority="P1", duration_minutes=240),
            SLADefinition(name="P2 incident resolution", target_type="ticket", priority="P2", duration_minutes=480),
            SLADefinition(name="P3 incident resolution", target_type="ticket", priority="P3", duration_minutes=1440),
            SLADefinition(name="Catalog fulfillment", target_type="ritm", duration_minutes=4320),
        ])


def seed():
    demo_mode = os.getenv("DEPLOYMENT_PROFILE", "demo").lower() == "demo"
    if User.query.first():
        admin = User.query.filter_by(role="admin").first()
        agent = User.query.filter_by(role="agent").first() or admin
        seed_itil(admin, agent, demo_mode)
        demo_names = ["agent", "employee"] + [
            f"{team}.{kind}"
            for team in ("coreapps", "database", "network", "windows", "unix", "ssd")
            for kind in ("agent", "manager")
        ]
        for demo_user in User.query.filter(User.username.in_(demo_names)).all():
            if demo_user.email.endswith(("@example.local", "@demo.serviceops.local")):
                demo_user.active = demo_mode
        if not CatalogItem.query.first():
            db.session.add_all([
                CatalogItem(name="Laptop computer", category="Hardware", description="Request a standard business laptop with approved software.", delivery_days=5, approval_required=True),
                CatalogItem(name="Software access", category="Access", description="Request access to an approved business application.", delivery_days=2, approval_required=True),
                CatalogItem(name="Password reset", category="Access", description="Get help restoring access to your corporate account.", delivery_days=1),
                CatalogItem(name="New employee onboarding", category="People", description="Coordinate accounts, equipment, workspace, and orientation.", delivery_days=7, approval_required=True),
            ])
        if not ConfigurationItem.query.first():
            web = ConfigurationItem(name="Customer Portal", ci_class="Business Application", owner_id=admin.id)
            api = ConfigurationItem(name="Portal API", ci_class="Application Service", owner_id=agent.id, ip_address="10.10.1.20")
            database = ConfigurationItem(name="Customer Database", ci_class="Database", owner_id=agent.id, ip_address="10.10.1.30")
            db.session.add_all([web, api, database])
            db.session.flush()
            db.session.add_all([
                CIRelationship(parent_id=web.id, child_id=api.id, relationship_type="Depends on"),
                CIRelationship(parent_id=api.id, child_id=database.id, relationship_type="Depends on"),
            ])
        db.session.commit()
        return
    admin = User(username="admin", name="System Administrator", email="admin@example.local",
                 password_hash=generate_password_hash(os.getenv("ADMIN_PASSWORD", "Admin123!")), role="admin")
    users = [admin]
    if demo_mode:
        agent = User(username="agent", name="IT Support Agent", email="agent@example.local",
                     password_hash=generate_password_hash("Agent123!"), role="agent")
        requester = User(username="employee", name="Example Employee", email="employee@example.local",
                         password_hash=generate_password_hash("Employee123!"), role="requester")
        users.extend([agent, requester])
    else:
        agent = admin
        requester = admin
    db.session.add_all(users)
    db.session.flush()
    seed_itil(admin, agent, demo_mode)
    if demo_mode:
        db.session.add(Knowledge(title="Reset your password", category="Access",
                                 body="Use the company identity portal. Select Forgot password, verify your identity, and choose a new password.",
                                 author_id=admin.id))
        db.session.add(Asset(asset_tag="LAP-0001", name="Demo laptop", asset_type="Laptop",
                             status="In use", owner_id=requester.id, serial_number="DEMO-001"))
    db.session.add_all([
        CatalogItem(name="Laptop computer", category="Hardware", description="Request a standard business laptop with approved software.", delivery_days=5, approval_required=True),
        CatalogItem(name="Software access", category="Access", description="Request access to an approved business application.", delivery_days=2, approval_required=True),
        CatalogItem(name="Password reset", category="Access", description="Get help restoring access to your corporate account.", delivery_days=1),
        CatalogItem(name="New employee onboarding", category="People", description="Coordinate accounts, equipment, workspace, and orientation.", delivery_days=7, approval_required=True),
    ])
    web = ConfigurationItem(name="Customer Portal", ci_class="Business Application", owner_id=admin.id)
    api = ConfigurationItem(name="Portal API", ci_class="Application Service", owner_id=agent.id, ip_address="10.10.1.20")
    database = ConfigurationItem(name="Customer Database", ci_class="Database", owner_id=agent.id, ip_address="10.10.1.30")
    db.session.add_all([web, api, database])
    db.session.flush()
    db.session.add_all([
        CIRelationship(parent_id=web.id, child_id=api.id, relationship_type="Depends on"),
        CIRelationship(parent_id=api.id, child_id=database.id, relationship_type="Depends on"),
    ])
    db.session.commit()


def mapped_role(groups, mapping_name, default="requester"):
    """Map directory/realm groups to a ServiceOps role without trusting user input."""
    allowed = {"requester", "agent", "manager", "admin"}
    try:
        mappings = json.loads(os.getenv(mapping_name, "{}"))
    except json.JSONDecodeError:
        mappings = {}
    normalized = {str(group).lower() for group in groups}
    for group, role in mappings.items():
        if str(group).lower() in normalized and role in allowed:
            return role
    configured = os.getenv(f"{mapping_name}_DEFAULT", default)
    return configured if configured in allowed else default


def provision_external_user(provider, subject, username, name, email, role):
    identity = ExternalIdentity.query.filter_by(provider=provider, subject=subject).first()
    if identity:
        user = identity.user
        user.name, user.email, user.role = name, email, role
        user.active = True
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
    return user


def ldap_authenticate(username, password):
    if not password or not env_bool("LDAP_ENABLED"):
        return None
    uri = os.getenv("LDAP_SERVER_URI", "")
    use_ssl = uri.lower().startswith("ldaps://")
    host = uri.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    port = int(os.getenv("LDAP_PORT", "636" if use_ssl else "389"))
    validate = ssl.CERT_REQUIRED if env_bool("LDAP_VALIDATE_CERT", True) else ssl.CERT_NONE
    tls = Tls(validate=validate, ca_certs_file=os.getenv("LDAP_CA_CERT") or None)
    server = Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL,
                    connect_timeout=int(os.getenv("LDAP_TIMEOUT", "8")))
    service = Connection(server, user=os.getenv("LDAP_BIND_DN") or None,
                         password=os.getenv("LDAP_BIND_PASSWORD") or None,
                         auto_bind=False, receive_timeout=int(os.getenv("LDAP_TIMEOUT", "8")))
    service.open()
    if not use_ssl and env_bool("LDAP_START_TLS", True):
        if not service.start_tls():
            return None
    if not service.bind():
        return None
    safe_username = escape_filter_chars(username)
    search_filter = os.getenv(
        "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
    ).replace("{username}", safe_username)
    attrs = ["distinguishedName", "cn", "displayName", "mail", "memberOf", "userPrincipalName"]
    if not service.search(os.getenv("LDAP_BASE_DN", ""), search_filter,
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
    if not use_ssl and env_bool("LDAP_START_TLS", True) and not user_conn.start_tls():
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
        first("mail", first("userPrincipalName", "")), role)


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "development-only-secret"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///serviceops.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.getenv("UPLOAD_FOLDER", os.path.join(app.instance_path, "uploads")),
        MAX_CONTENT_LENGTH=20 * 1024 * 1024,
        DEPLOYMENT_PROFILE=os.getenv("DEPLOYMENT_PROFILE", "demo").lower(),
        LDAP_ENABLED=env_bool("LDAP_ENABLED"),
        KEYCLOAK_ENABLED=env_bool("KEYCLOAK_ENABLED"),
        LOCAL_AUTH_ENABLED=env_bool("LOCAL_AUTH_ENABLED", True),
    )
    if test_config:
        app.config.update(test_config)
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
    if app.config["KEYCLOAK_ENABLED"]:
        oauth.register(
            name="keycloak",
            client_id=os.getenv("KEYCLOAK_CLIENT_ID"),
            client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET"),
            server_metadata_url=os.getenv("KEYCLOAK_DISCOVERY_URL"),
            client_kwargs={"scope": "openid profile email"},
        )

    with app.app_context():
        db.create_all()
        seed()
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        # Gunicorn preloads the application before forking workers. Do not let
        # workers inherit PostgreSQL connections or prepared-statement state.
        db.engine.dispose()

    @app.context_processor
    def ui_context():
        if not current_user.is_authenticated:
            return {}
        preference = UserPreference.query.filter_by(user_id=current_user.id).first()
        if not preference:
            preference = UserPreference(user_id=current_user.id)
            db.session.add(preference)
            db.session.commit()
        return {
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
        if env_bool("ENABLE_HSTS"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            provider = request.form.get("provider", "local")
            user = None
            if provider == "ldap" and app.config["LDAP_ENABLED"]:
                try:
                    user = ldap_authenticate(username, password)
                except Exception:
                    app.logger.exception("LDAP authentication failed")
            elif app.config["LOCAL_AUTH_ENABLED"]:
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
        return render_template("login.html", ldap_enabled=app.config["LDAP_ENABLED"],
                               keycloak_enabled=app.config["KEYCLOAK_ENABLED"],
                               local_enabled=app.config["LOCAL_AUTH_ENABLED"],
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
        counts = {kind: Ticket.query.filter_by(kind=kind).count() for kind in ("incident", "request", "change")}
        open_count = Ticket.query.filter(Ticket.state.notin_(["Resolved", "Closed", "Cancelled"])).count()
        recent = visible_tickets().order_by(Ticket.updated_at.desc()).limit(8).all()
        return render_template("dashboard.html", counts=counts, open_count=open_count, recent=recent)

    def visible_tickets():
        query = Ticket.query
        if current_user.role == "requester":
            query = query.filter_by(requester_id=current_user.id)
        return query

    @app.get("/tickets/<kind>")
    @login_required
    def tickets(kind):
        if kind not in ("incident", "request", "change"):
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
        if kind not in ("incident", "request", "change"):
            abort(404)
        if kind == "change" and current_user.role == "requester":
            abort(403)
        if request.method == "POST":
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
                owning_group = db.session.get(SupportGroup, int(request.form["group_id"])) if request.form.get("group_id") else SupportGroup.query.filter_by(name="CoreApps").first()
                db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=owning_group.id))
                ccb = SupportGroup.query.filter_by(name="Change Control Board").first()
                ccb_ids = [member.user_id for member in GroupMember.query.filter_by(group_id=ccb.id).all()
                           if member.user.role == "manager"]
                stages = [{"name": f"{owning_group.name} manager assessment", "mode": "all",
                           "approver_ids": [owning_group.manager_id]}]
                if governance.change_type != "Standard":
                    stages.append({"name": "CCB weekly authorization", "mode": "majority",
                                   "approver_ids": ccb_ids})
                create_approval_chain(f"{ticket.number} change authorization", "ticket", ticket.id, stages)
            audit("create", ticket.number, ticket.title)
            db.session.commit()
            flash(f"{ticket.number} created.", "success")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        teams = SupportGroup.query.filter_by(group_type="IT Fulfillment", active=True).order_by(SupportGroup.name).all()
        return render_template("ticket_form.html", kind=kind, cis=ConfigurationItem.query.order_by(ConfigurationItem.name).all(),
                               teams=teams)

    @app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
    @login_required
    def ticket_detail(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        if current_user.role == "requester" and ticket.requester_id != current_user.id:
            abort(403)
        if request.method == "POST":
            action = request.form.get("action")
            if action == "comment":
                body = request.form.get("body", "").strip()
                if body:
                    db.session.add(Comment(ticket_id=ticket.id, user_id=current_user.id, body=body))
                    audit("comment", ticket.number)
            elif action == "update" and current_user.role in ("agent", "manager", "admin"):
                ticket.state = request.form["state"]
                ticket.priority = request.form["priority"]
                ticket.assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
                sync_slas("ticket", ticket.id, ticket.state)
                audit("update", ticket.number, f"{ticket.state}, {ticket.priority}")
            db.session.commit()
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))
        agents = User.query.filter(User.role.in_(["agent", "manager", "admin"]), User.active.is_(True)).all()
        chains = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).all()
        slas = TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).all()
        return render_template("ticket_detail.html", ticket=ticket, agents=agents, chains=chains, slas=slas)

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
        return render_template("users.html", users=User.query.order_by(User.name).all())

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

    @app.get("/admin/audit")
    @roles("admin")
    def audit_log():
        return render_template("audit.html", rows=Audit.query.order_by(Audit.created_at.desc()).limit(250).all())

    @app.get("/modules")
    @login_required
    def modules():
        counts = {key: EnterpriseRecord.query.filter_by(domain=key).count() for key in DOMAIN_CONFIG}
        return render_template("modules.html", modules=DOMAIN_CONFIG, counts=counts)

    @app.get("/module/<domain>")
    @login_required
    def module_records(domain):
        config = DOMAIN_CONFIG.get(domain)
        if not config:
            abort(404)
        query = EnterpriseRecord.query.filter_by(domain=domain)
        if current_user.role == "requester" and domain not in ("customer", "hr"):
            query = query.filter_by(requester_id=current_user.id)
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
            if request.form.get("approval_required") and current_user.role != "requester":
                admin = User.query.filter_by(role="admin", active=True).first()
                db.session.add(Approval(enterprise_record_id=record.id, approver_id=admin.id))
                db.session.add(Notification(user_id=admin.id, title=f"Approval requested: {record.number}",
                                            body=record.title))
                record.state = "Awaiting Approval"
            audit("create", record.number, f"{config['name']}: {record.title}")
            db.session.commit()
            return redirect(url_for("enterprise_detail", record_id=record.id))
        return render_template("enterprise_form.html", domain=domain, config=config)

    @app.route("/enterprise/<int:record_id>", methods=["GET", "POST"])
    @login_required
    def enterprise_detail(record_id):
        record = db.get_or_404(EnterpriseRecord, record_id)
        if current_user.role == "requester" and record.requester_id != current_user.id:
            abort(403)
        if request.method == "POST":
            action = request.form.get("action")
            if action == "update" and current_user.role in ("agent", "manager", "admin"):
                record.state = request.form["state"]
                record.priority = request.form["priority"]
                record.risk = request.form["risk"]
                record.assignee_id = int(request.form["assignee_id"]) if request.form.get("assignee_id") else None
                audit("update", record.number, f"{record.state}, {record.priority}, risk {record.risk}")
            elif action in ("approve", "reject"):
                approval = Approval.query.filter_by(id=int(request.form["approval_id"]),
                                                    approver_id=current_user.id, state="Requested").first_or_404()
                approval.state = "Approved" if action == "approve" else "Rejected"
                approval.comments = request.form.get("comments", "")
                approval.decided_at = now()
                record.state = "Approved" if action == "approve" else "Rejected"
                db.session.add(Notification(user_id=record.requester_id, title=f"{record.number} {record.state.lower()}",
                                            body=approval.comments or f"Your record was {record.state.lower()}."))
                audit(action, record.number)
            db.session.commit()
            return redirect(url_for("enterprise_detail", record_id=record.id))
        agents = User.query.filter(User.role.in_(["agent", "manager", "admin"]), User.active.is_(True)).all()
        return render_template("enterprise_detail.html", record=record, config=DOMAIN_CONFIG[record.domain], agents=agents)

    @app.get("/catalog")
    @login_required
    def catalog():
        return render_template("catalog.html", items=CatalogItem.query.filter_by(active=True).order_by(CatalogItem.category, CatalogItem.name).all())

    @app.post("/catalog/<int:item_id>/order")
    @login_required
    def catalog_order(item_id):
        item = db.get_or_404(CatalogItem, item_id)
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
        if vote.approver_id != current_user.id and current_user.role != "admin":
            abort(403)
        decision = request.form.get("decision")
        if decision not in ("Approved", "Rejected"):
            abort(400)
        decide_vote(vote, decision, request.form.get("comments", "").strip())
        audit(decision.lower(), vote.gate.chain.name, vote.gate.name)
        db.session.commit()
        return redirect(request.referrer or url_for("approval_chains"))

    @app.get("/approval-chains")
    @login_required
    def approval_chains():
        chains = ApprovalChain.query.order_by(ApprovalChain.created_at.desc()).all()
        pending = ApprovalVote.query.filter_by(approver_id=current_user.id, state="Requested").all()
        return render_template("approval_chains.html", chains=chains, pending=pending)

    @app.get("/requests")
    @login_required
    def requests_list():
        query = CatalogRequest.query
        if current_user.role == "requester":
            query = query.filter_by(requested_for_id=current_user.id)
        return render_template("requests.html", requests=query.order_by(CatalogRequest.opened_at.desc()).all())

    @app.get("/request/<int:request_id>")
    @login_required
    def request_detail(request_id):
        req = db.get_or_404(CatalogRequest, request_id)
        if current_user.role == "requester" and req.requested_for_id != current_user.id:
            abort(403)
        chains = {}
        slas = {}
        for ritm in req.items:
            chains[ritm.id] = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm.id).all()
            slas[ritm.id] = TaskSLA.query.filter_by(target_type="ritm", target_id=ritm.id).all()
        return render_template("request_detail.html", req=req, chains=chains, slas=slas)

    @app.post("/catalog-task/<int:task_id>")
    @roles("agent", "manager", "admin")
    def catalog_task_update(task_id):
        task = db.get_or_404(CatalogTask, task_id)
        task.state = request.form["state"]
        task.work_notes = request.form.get("work_notes", "")
        task.assignee_id = current_user.id
        ritm = task.requested_item
        if task.state == "Closed Complete":
            ritm.state = "Closed Complete"
            ritm.stage = "Completed"
            sync_slas("ritm", ritm.id, ritm.state)
            if all(item.state == "Closed Complete" for item in ritm.request.items):
                ritm.request.state = "Closed Complete"
                ritm.request.closed_at = now()
        elif task.state == "Closed Incomplete":
            ritm.state = "Closed Incomplete"
            ritm.stage = "Completed"
            ritm.request.state = "Closed Incomplete"
        audit("update", task.number, task.state)
        db.session.commit()
        return redirect(url_for("request_detail", request_id=ritm.request_id))

    @app.get("/itil/administration")
    @roles("admin")
    def itil_admin():
        return render_template("itil_admin.html", groups=SupportGroup.query.all(),
                               services=ServiceOffering.query.all(), sla_definitions=SLADefinition.query.all())

    @app.post("/change/<int:ticket_id>/conflicts")
    @roles("agent", "manager", "admin")
    def detect_change_conflicts(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
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
            for other in overlapping:
                if governance.ci_id and other.ci_id == governance.ci_id:
                    conflicts.append(other.ticket.number)
        governance.conflict_status = f"Conflict: {', '.join(conflicts)}" if conflicts else "No conflict"
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
        ticket_states = dict(db.session.query(Ticket.state, func.count(Ticket.id)).group_by(Ticket.state).all())
        domain_counts = dict(db.session.query(EnterpriseRecord.domain, func.count(EnterpriseRecord.id)).group_by(EnterpriseRecord.domain).all())
        priority_counts = dict(db.session.query(Ticket.priority, func.count(Ticket.id)).group_by(Ticket.priority).all())
        overdue = EnterpriseRecord.query.filter(EnterpriseRecord.due_at < now(),
                                                EnterpriseRecord.state.notin_(["Closed", "Resolved", "Completed"])).count()
        return render_template("analytics.html", ticket_states=ticket_states, domain_counts=domain_counts,
                               priority_counts=priority_counts, overdue=overdue, modules=DOMAIN_CONFIG)

    @app.get("/ui/search")
    @login_required
    def global_search():
        q = request.args.get("q", "").strip()
        results = []
        if q:
            pattern = f"%{q}%"
            for row in Ticket.query.filter(db.or_(Ticket.number.ilike(pattern), Ticket.title.ilike(pattern),
                                                   Ticket.description.ilike(pattern))).limit(20):
                results.append({"type": row.kind.title(), "label": f"{row.number} · {row.title}",
                                "url": url_for("ticket_detail", ticket_id=row.id), "meta": row.state})
            for row in Knowledge.query.filter(db.or_(Knowledge.title.ilike(pattern), Knowledge.body.ilike(pattern))).limit(20):
                results.append({"type": "Knowledge", "label": row.title, "url": url_for("knowledge"),
                                "meta": row.category})
            for row in EnterpriseRecord.query.filter(db.or_(EnterpriseRecord.number.ilike(pattern),
                                                             EnterpriseRecord.title.ilike(pattern))).limit(20):
                results.append({"type": DOMAIN_CONFIG[row.domain]["name"], "label": f"{row.number} · {row.title}",
                                "url": url_for("enterprise_detail", record_id=row.id), "meta": row.state})
            for row in ConfigurationItem.query.filter(ConfigurationItem.name.ilike(pattern)).limit(20):
                results.append({"type": "Configuration item", "label": row.name, "url": url_for("cmdb"),
                                "meta": row.ci_class})
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
            pref.theme = request.form.get("theme", "system")
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
        return render_template("task_board.html", tickets_by_state=tickets_by_state)

    @app.post("/task-board/<int:ticket_id>/move")
    @roles("agent", "manager", "admin")
    def task_board_move(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        state = request.form.get("state")
        if state not in ("New", "In Progress", "Pending", "Resolved", "Closed"):
            abort(400)
        ticket.state = state
        sync_slas("ticket", ticket.id, state)
        audit("board move", ticket.number, state)
        db.session.commit()
        return jsonify(state=state)

    @app.post("/ticket/<int:ticket_id>/checklist")
    @roles("agent", "manager", "admin")
    def checklist_add(ticket_id):
        db.get_or_404(Ticket, ticket_id)
        text = request.form.get("text", "").strip()
        if text:
            position = ChecklistItem.query.filter_by(ticket_id=ticket_id).count()
            db.session.add(ChecklistItem(ticket_id=ticket_id, text=text[:300], position=position))
            db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.post("/checklist/<int:item_id>/toggle")
    @roles("agent", "manager", "admin")
    def checklist_toggle(item_id):
        item = db.get_or_404(ChecklistItem, item_id)
        item.completed = not item.completed
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=item.ticket_id))

    @app.post("/ticket/<int:ticket_id>/attachments")
    @login_required
    def attachment_upload(ticket_id):
        ticket = db.get_or_404(Ticket, ticket_id)
        if current_user.role == "requester" and ticket.requester_id != current_user.id:
            abort(403)
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Choose a file to upload.", "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        original = secure_filename(upload.filename)
        stored = f"{uuid.uuid4().hex}-{original}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
        upload.save(path)
        db.session.add(FileAttachment(ticket_id=ticket_id, uploaded_by_id=current_user.id,
                                      original_name=original, stored_name=stored,
                                      mime_type=upload.mimetype, size_bytes=os.path.getsize(path)))
        audit("attach", ticket.number, original)
        db.session.commit()
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.get("/attachments/<int:attachment_id>")
    @login_required
    def attachment_download(attachment_id):
        attachment = db.get_or_404(FileAttachment, attachment_id)
        if current_user.role == "requester" and attachment.ticket.requester_id != current_user.id:
            abort(403)
        return send_from_directory(app.config["UPLOAD_FOLDER"], attachment.stored_name,
                                   as_attachment=True, download_name=attachment.original_name)

    @app.get("/help")
    @login_required
    def help_center():
        return render_template("help.html")

    @app.errorhandler(403)
    def forbidden(_):
        return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, message="The requested record was not found."), 404

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080, debug=True)
