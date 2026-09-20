"""Tenant and actor authorization, bounded retrieval, durable job execution."""
import json
import re
from datetime import timedelta
from types import SimpleNamespace

from flask import abort
from sqlalchemy import or_

from serviceops_models import (AIConfiguration, AIRun, Comment, ConfigurationItem, Knowledge,
                              TaskCI, Tenant, Ticket, User, db, now)
from serviceops_core.ai.provider import ProviderError, generate
from serviceops_core.ci_class_policy import ci_class_read_allowed
from serviceops_core.security import redact
from serviceops_core.storage import ipfs_enabled

ALLOWED_ROLES = {"agent", "manager", "admin", "superadmin"}
ACTIVE = ("queued", "running")


def actor(user, role=None):
    role = role or user.effective_role
    if not user.active or not user.tenant_id or role not in ALLOWED_ROLES or role not in user.granted_roles:
        abort(403)
    tenant = db.session.get(Tenant, user.tenant_id)
    if not tenant or not tenant.active:
        abort(403)
    # Existing ticket helper consults role; preserve the submitted effective role in jobs.
    return SimpleNamespace(id=user.id, tenant_id=user.tenant_id, role=role, effective_role=role,
                           is_authenticated=True, active=True)


def enabled_config(tenant_id, *, lock=False):
    query = AIConfiguration.query.filter_by(tenant_id=tenant_id)
    config = (query.with_for_update() if lock else query).first()
    if ipfs_enabled() or not config or not config.enabled or not config.incident_enabled:
        abort(403, description="AI incident assistance is disabled by your administrator.")
    return config


def visible_incident(identity, ticket_id):
    from app import visible_ticket_query
    return visible_ticket_query(identity).filter_by(id=ticket_id, kind="incident", deleted_at=None).first_or_404()


def available(user):
    if not user.is_authenticated or not user.active or user.effective_role not in ALLOWED_ROLES or ipfs_enabled():
        return False
    config = db.session.get(AIConfiguration, user.tenant_id)
    return bool(config and config.enabled and config.incident_enabled)


def collect_evidence(identity, ticket_id):
    from app import visible_ticket_query
    ticket = visible_incident(identity, ticket_id)
    sources = []
    evidence = []

    def add(kind, row, title, body):
        source_id = f"S{len(sources) + 1}"
        sources.append({"id": source_id, "kind": kind, "record_id": row.id, "title": redact(title)[:180]})
        evidence.append({"source": source_id, "kind": kind, "title": redact(title)[:180], "text": redact(body)[:5000]})

    comments = Comment.query.filter_by(tenant_id=identity.tenant_id, ticket_id=ticket.id).order_by(
        Comment.created_at.desc()).limit(5).all()
    add("ticket", ticket, ticket.number + " " + ticket.title,
        f"State: {ticket.state}; Priority: {ticket.priority}\n{ticket.description[:3000]}\n" +
        "\n".join(redact(row.body)[:350] for row in comments))
    words = list(dict.fromkeys(re.findall(r"[A-Za-z0-9]{3,}", ticket.title.lower())))[:6]
    if words:
        kb = Knowledge.query.filter_by(tenant_id=identity.tenant_id, published=True, archived=False).filter(
            or_(*[Knowledge.title.ilike(f"%{word}%") for word in words])).order_by(Knowledge.created_at.desc()).limit(3)
        for row in kb:
            add("knowledge", row, row.title, row.body)
        similar = visible_ticket_query(identity).filter(
            Ticket.id != ticket.id, Ticket.kind == "incident", Ticket.deleted_at.is_(None),
            Ticket.state.in_(["Resolved", "Closed"]),
            or_(*[Ticket.title.ilike(f"%{word}%") for word in words]),
        ).order_by(Ticket.updated_at.desc()).limit(2)
        for row in similar:
            add("ticket", row, row.number + " " + row.title, row.description)
    ci_ids = [row.ci_id for row in TaskCI.query.filter_by(
        target_type="ticket", target_id=ticket.id).limit(20)]
    for row in ConfigurationItem.query.filter(ConfigurationItem.tenant_id == identity.tenant_id,
                                              ConfigurationItem.id.in_(ci_ids)).order_by(ConfigurationItem.id).limit(3):
        if ci_class_read_allowed(identity.tenant_id, row.ci_class, identity.role):
            add("ci", row, row.name, f"Class: {row.ci_class}; Environment: {row.environment}; Status: {row.operational_status}")
    return evidence, sources


def sources_accessible(identity, sources):
    from app import visible_ticket_query
    for source in sources:
        kind, record_id = source["kind"], source["record_id"]
        if kind == "ticket":
            if not visible_ticket_query(identity).filter_by(id=record_id, deleted_at=None).first():
                return False
        elif kind == "knowledge":
            if not Knowledge.query.filter_by(id=record_id, tenant_id=identity.tenant_id, published=True, archived=False).first():
                return False
        elif kind == "ci":
            row = ConfigurationItem.query.filter_by(id=record_id, tenant_id=identity.tenant_id).first()
            if not row or not ci_class_read_allowed(identity.tenant_id, row.ci_class, identity.role):
                return False
        else:
            return False
    return True


def cancel_active(tenant_id):
    AIRun.query.filter(AIRun.tenant_id == tenant_id, AIRun.status.in_(ACTIVE)).update(
        {"status": "cancelled", "completed_at": now(), "error_code": "configuration_changed"}, synchronize_session=False)


def process_one():
    """Claim once; never repeat a provider call after an uncertain worker failure."""
    from app import audit
    from werkzeug.exceptions import HTTPException
    cutoff = now() - timedelta(minutes=5)
    AIRun.query.filter(AIRun.status == "running", AIRun.started_at < cutoff).update(
        {"status": "failed", "error_code": "worker_interrupted", "completed_at": now()}, synchronize_session=False)
    for config in AIConfiguration.query.all():
        AIRun.query.filter(AIRun.tenant_id == config.tenant_id, AIRun.created_at < now() - timedelta(days=config.retention_days),
                           ~AIRun.status.in_(ACTIVE)).delete(synchronize_session=False)
    db.session.commit()
    run = AIRun.query.filter_by(status="queued").order_by(AIRun.created_at).with_for_update(skip_locked=True).first()
    if not run:
        db.session.rollback()
        return False
    run_id = run.id
    # Conditional update also guards SQLite tests; PostgreSQL uses row locking.
    claimed = AIRun.query.filter_by(id=run_id, status="queued").update(
        {"status": "running", "started_at": now()}, synchronize_session=False)
    db.session.commit()
    if not claimed:
        return True
    try:
        run = db.session.get(AIRun, run_id)
        config = enabled_config(run.tenant_id)
        if run.status != "running" or config.revision != run.config_revision:
            abort(403)
        user = db.session.get(User, run.user_id)
        if not user or user.tenant_id != run.tenant_id:
            abort(403)
        identity = actor(user, run.actor_role)
        evidence, sources = collect_evidence(identity, run.ticket_id)
        # Detach a bounded config snapshot; do not hold DB transactions during network I/O.
        snapshot = SimpleNamespace(**{name: getattr(config, name) for name in
            ("provider", "model", "endpoint", "key_encrypted", "external_consent", "max_output_tokens")})
        db.session.commit()
        answer, usage = generate(snapshot, evidence)
        valid_ids = {source["id"] for source in sources}
        if any(item not in valid_ids for item in re.findall(r"\[(S\d+)\]", answer)):
            raise ProviderError("Provider returned an unknown evidence citation.")
        if not re.search(r"\[S\d+\]", answer):
            raise ProviderError("Provider returned an answer without evidence citations.")
        db.session.expire_all()
        # Serialize publication with configuration changes, taking locks in config -> run order.
        config = enabled_config(run.tenant_id, lock=True)
        run = AIRun.query.filter_by(id=run_id).populate_existing().with_for_update().one()
        user = db.session.get(User, run.user_id, populate_existing=True)
        if run.status != "running" or config.revision != run.config_revision or not user or user.tenant_id != run.tenant_id:
            abort(403)
        identity = actor(user, run.actor_role)
        if not sources_accessible(identity, sources):
            abort(403)
        run.result_text, run.sources_json, run.usage_json = answer, json.dumps(sources), json.dumps(usage)
        run.status, run.completed_at = "completed", now()
        audit("ai completed", run.id, "Read-only incident investigation", user_id=run.user_id, tenant_id=run.tenant_id)
        db.session.commit()
    except (ProviderError, HTTPException) as error:
        db.session.rollback()
        AIRun.query.filter_by(id=run_id, status="running").update({
            "status": "cancelled" if isinstance(error, HTTPException) else "failed",
            "error_code": "access_or_configuration_changed" if isinstance(error, HTTPException) else "provider_failed",
            "completed_at": now(),
        }, synchronize_session=False)
        db.session.commit()
    return True
