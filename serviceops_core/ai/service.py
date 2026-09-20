"""Tenant and actor authorization, bounded retrieval, durable job execution."""
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from types import SimpleNamespace

from flask import abort
from sqlalchemy import or_

from serviceops_models import (AIConfiguration, AIConversation, AIMessage, AIRun, Comment, ConfigurationItem, Knowledge,
                              TaskCI, Tenant, Ticket, User, db, now)
from serviceops_core.ai import access
from serviceops_core.ai.provider import INSTRUCTIONS, ProviderError, StreamCancelled, generate_stream, provider_timeout
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


def enabled_config(tenant_id, *, lock=False, feature="incident"):
    query = AIConfiguration.query.filter_by(tenant_id=tenant_id)
    config = (query.with_for_update() if lock else query).first()
    switch = config.chat_enabled if config and feature == "chat" else (config.incident_enabled if config else False)
    if ipfs_enabled() or not config or not config.enabled or not switch:
        abort(403, description="AI assistance is disabled by your administrator.")
    return config


def visible_incident(identity, ticket_id):
    from app import visible_ticket_query
    return visible_ticket_query(identity).filter_by(id=ticket_id, kind="incident", deleted_at=None).first_or_404()


def chat_available(user):
    """Whether this person may see the chatbot: signed in, an allowed role, and enabled by the administrator."""
    if not user.is_authenticated or not user.active or user.effective_role not in access.CHAT_ROLES or ipfs_enabled():
        return False
    config = db.session.get(AIConfiguration, user.tenant_id)
    return bool(config and config.enabled and config.chat_enabled)


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


FLUSH_INTERVAL = 0.4


class Steps:
    """Real pipeline events, shown to the user as a timeline. Never written by the model."""

    def __init__(self):
        self.items, self._start = [], time.monotonic()

    def add(self, label, detail=""):
        for item in self.items:
            item["state"] = "done"
        self.items.append({"label": label, "detail": detail, "state": "active", "t": round(time.monotonic() - self._start, 1)})

    def finish(self):
        for item in self.items:
            item["state"] = "done"

    def dump(self):
        return json.dumps(self.items)


@dataclass
class Prepared:
    messages: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    allowed: set = field(default_factory=set)
    typed: tuple = ()
    cite_required: bool = True
    thinking: object = None
    refusal: str = ""


def _describe(counts):
    labels = (("ticket", "ticket", "tickets"), ("knowledge", "knowledge article", "knowledge articles"), ("ci", "configuration item", "configuration items"))
    parts = [f"{counts[k]} {one if counts[k] == 1 else many}" for k, one, many in labels if counts.get(k)]
    return ", ".join(parts) or "nothing relevant"


def _run_options(run):
    try:
        return json.loads(run.usage_json or "{}")
    except ValueError:
        return {}


def _prepare_investigation(run, user, config, steps):
    identity = actor(user, run.actor_role)
    steps.add("Verified your access", f"Acting as {run.actor_role}")
    evidence, sources = collect_evidence(identity, run.ticket_id)
    steps.add("Collected evidence", _describe(Counter(source["kind"] for source in sources)))
    prompt = json.dumps(evidence, ensure_ascii=True)
    if len(prompt) > 40000:
        raise ProviderError("Evidence exceeds the request limit.")
    return Prepared([{"role": "system", "content": INSTRUCTIONS}, {"role": "user", "content": prompt}], sources,
                    access.identifiers_in(prompt), (), True, bool(config.show_reasoning))


def _prepare_chat(run, user, config, steps):
    scope = access.build_scope(user, run.actor_role)
    steps.add("Confirmed who is asking", scope.summary())
    question = run.question
    code = access.screen_question(scope, question)
    if code:
        steps.add("Declined", "This asks for something the assistant never has access to")
        return Prepared(refusal=code)
    evidence = access.collect_chat_evidence(scope, question)
    detail = _describe(evidence.counts())
    if evidence.unavailable:
        detail += f"; {len(evidence.unavailable)} reference(s) not available to you"
    steps.add("Looked up records you can access", detail)
    earlier = AIMessage.query.filter_by(conversation_id=run.conversation_id).order_by(AIMessage.created_at).all()
    history = access.history_for_model(scope, [m for m in earlier if m.status == "completed" and m.id != run.message_id])
    messages, _ = access.build_chat_messages(scope, question, history, evidence)
    grounded = access.identifiers_in(json.dumps(evidence.items)) | evidence.identifiers
    options = _run_options(run)
    thinking = bool(options.get("thinking")) if config.show_reasoning else False
    return Prepared(messages, evidence.sources, grounded, tuple(access.record_numbers(question)), False, thinking)


def _stable_prefix(text):
    """Hold back an unfinished trailing word so a half-typed reference is never judged or shown."""
    if not text or text[-1] in " \n\t.,;:!?)]}":
        return text
    cut = max(text.rfind(ch) for ch in " \n\t.,;:!?)]}")
    return text[:cut + 1] if cut >= 0 else ""


def _publish_progress(run_id, **values):
    """Write progressive output. False means the run is no longer running (stopped or disabled)."""
    values.update(heartbeat_at=now(), seq=AIRun.seq + 1)
    changed = AIRun.query.filter(AIRun.id == run_id, AIRun.status == "running").update(values, synchronize_session=False)
    db.session.commit()
    return bool(changed)


def _stream(run, config, prepared, steps):
    run_id, tenant_id, revision = run.id, run.tenant_id, run.config_revision
    snapshot = SimpleNamespace(**{name: getattr(config, name) for name in
                                  ("provider", "model", "endpoint", "key_encrypted", "external_consent", "max_output_tokens")})
    valid_ids = {source["id"] for source in prepared.sources}
    state = {"content": "", "reasoning": "", "last": 0.0, "began_reasoning": False, "began_answer": False}

    def sanitize(text):
        return access.sanitize_answer(text, prepared.allowed, valid_ids, prepared.typed)

    def flush(force=False):
        if not force and time.monotonic() - state["last"] < FLUSH_INTERVAL:
            return True
        state["last"] = time.monotonic()
        text = state["content"] if force else _stable_prefix(state["content"])
        if not _publish_progress(run_id, partial_text=sanitize(text), reasoning_text=state["reasoning"], steps_json=steps.dump()):
            return False
        current = db.session.get(AIConfiguration, tenant_id, populate_existing=True)
        return bool(current and current.enabled and current.revision == revision)

    def on_delta(kind, text):
        state[kind] += text
        marker = "began_reasoning" if kind == "reasoning" else "began_answer"
        if not state[marker]:
            state[marker] = True
            steps.add("The model is reasoning" if kind == "reasoning" else "Writing the answer")
            state["last"] = 0.0
        return flush()

    steps.add("Sending to the model", f"{config.model}")
    _publish_progress(run_id, steps_json=steps.dump())
    db.session.commit()  # no transaction is held open across the network call
    content, reasoning, usage = generate_stream(snapshot, prepared.messages, on_delta, thinking=prepared.thinking)
    flush(force=True)
    return content, reasoning, usage, sanitize


def _finish(run_id, prepared, steps, content, reasoning, usage, sanitize, feature):
    """Publish under locks (configuration first, then run), re-authorizing at the last moment."""
    from app import audit
    db.session.expire_all()
    config = enabled_config(db.session.get(AIRun, run_id).tenant_id, lock=True, feature=feature)
    run = AIRun.query.filter_by(id=run_id).populate_existing().with_for_update().one()
    user = db.session.get(User, run.user_id, populate_existing=True)
    if run.status != "running" or config.revision != run.config_revision or not user or user.tenant_id != run.tenant_id:
        abort(403)
    if run.kind == "chat":
        scope = access.build_scope(user, run.actor_role)
        if not access.sources_still_accessible(scope, prepared.sources):
            abort(403)
    else:
        if not sources_accessible(actor(user, run.actor_role), prepared.sources):
            abort(403)
    final = sanitize(content)
    if prepared.cite_required and not re.search(r"\[S\d+\]", final):
        raise ProviderError("Provider returned an answer without evidence citations.")
    steps.add("Checked your access again", "Every source is still readable by you")
    steps.finish()
    show = bool(config.show_reasoning)
    run.result_text, run.partial_text, run.reasoning_text = final, "", (reasoning if show else "")
    run.sources_json, run.usage_json, run.steps_json, run.question = json.dumps(prepared.sources), json.dumps(usage), steps.dump(), ""
    run.status, run.completed_at, run.seq = "completed", now(), run.seq + 1
    if run.kind == "chat":
        message = db.session.get(AIMessage, run.message_id)
        message.content, message.reasoning, message.status, message.run_id = final, (reasoning if show else ""), "completed", run.id
        message.sources_json, message.steps_json = json.dumps(prepared.sources), steps.dump()
        db.session.get(AIConversation, run.conversation_id).updated_at = now()
        audit("ai chat answered", run.id, f"sources={_describe(Counter(s['kind'] for s in prepared.sources))}",
              user_id=run.user_id, tenant_id=run.tenant_id)
    else:
        audit("ai completed", run.id, "Read-only incident investigation", user_id=run.user_id, tenant_id=run.tenant_id)
    db.session.commit()


def _decline(run_id, prepared, steps):
    """A refusal needs no model call: the answer is a fixed sentence."""
    from app import audit
    run = AIRun.query.filter_by(id=run_id).populate_existing().with_for_update().one()
    if run.status != "running":
        return
    steps.finish()
    text = access.REFUSALS[prepared.refusal]
    run.result_text, run.partial_text, run.steps_json, run.question = text, "", steps.dump(), ""
    run.status, run.completed_at, run.seq = "completed", now(), run.seq + 1
    message = db.session.get(AIMessage, run.message_id)
    message.content, message.status, message.run_id, message.steps_json = text, "completed", run.id, steps.dump()
    db.session.get(AIConversation, run.conversation_id).updated_at = now()
    audit("ai chat denied", run.id, f"reason={prepared.refusal}", user_id=run.user_id, tenant_id=run.tenant_id)
    db.session.commit()


def process_one():
    """Claim once; never repeat a provider call after an uncertain worker failure."""
    from werkzeug.exceptions import HTTPException
    # A run with no heartbeat for longer than a provider call may last is assumed dead.
    cutoff = now() - timedelta(seconds=provider_timeout() + 60)
    AIRun.query.filter(AIRun.status == "running", db.func.coalesce(AIRun.heartbeat_at, AIRun.started_at) < cutoff).update(
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
        {"status": "running", "started_at": now(), "heartbeat_at": now()}, synchronize_session=False)
    db.session.commit()
    if not claimed:
        return True
    message_id = None
    try:
        run = db.session.get(AIRun, run_id)
        message_id = run.message_id
        feature = "chat" if run.kind == "chat" else "incident"
        config = enabled_config(run.tenant_id, feature=feature)
        if run.status != "running" or config.revision != run.config_revision:
            abort(403)
        user = db.session.get(User, run.user_id)
        if not user or user.tenant_id != run.tenant_id:
            abort(403)
        steps = Steps()
        prepared = (_prepare_chat if run.kind == "chat" else _prepare_investigation)(run, user, config, steps)
        if prepared.refusal:
            _decline(run_id, prepared, steps)
            return True
        content, reasoning, usage, sanitize = _stream(run, config, prepared, steps)
        _finish(run_id, prepared, steps, content, reasoning, usage, sanitize, feature)
    except (ProviderError, StreamCancelled, HTTPException, access.ScopeError) as error:
        db.session.rollback()
        cancelled = isinstance(error, (StreamCancelled, HTTPException, access.ScopeError))
        status, code = ("cancelled", "access_or_configuration_changed") if cancelled else ("failed", "provider_failed")
        AIRun.query.filter_by(id=run_id, status="running").update({
            "status": status, "error_code": code, "completed_at": now(), "partial_text": "", "reasoning_text": "",
            "question": "", "seq": AIRun.seq + 1,
        }, synchronize_session=False)
        if message_id:
            AIMessage.query.filter_by(id=message_id).update({"status": status, "content": "", "reasoning": ""},
                                                            synchronize_session=False)
        db.session.commit()
    return True
