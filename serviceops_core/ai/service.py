"""Tenant and actor authorization, bounded retrieval, durable job execution."""
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import timedelta
from types import SimpleNamespace

from flask import abort
from sqlalchemy import or_

from serviceops_models import (AIConfiguration, AIConnection, AIConversation, AIMessage, AIRun, Comment, ConfigurationItem, Knowledge,
                              TaskCI, Tenant, Ticket, User, db, now)
from serviceops_core.ai import access, routing
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


def collect_evidence(identity, ticket_id, scanner=None):
    from app import visible_ticket_query
    ticket = visible_incident(identity, ticket_id)
    sources = []
    evidence = []

    def add(kind, row, title, body):
        if scanner:
            scanner(f"{title}\n{body}", kind)
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


def connections_for(config):
    """The AI services an organization has set up. An older single-provider configuration that was
    never migrated to a service row is treated as one service, so nothing stops working."""
    rows = AIConnection.query.filter_by(tenant_id=config.tenant_id).order_by(AIConnection.priority, AIConnection.name).all()
    if rows or not getattr(config, "model", ""):
        return rows
    return [AIConnection(id="legacy", tenant_id=config.tenant_id, name="Primary", provider=config.provider,
                         endpoint=config.endpoint, model=config.model, key_encrypted=config.key_encrypted,
                         capabilities_json=getattr(config, "capabilities_json", "{}") or "{}", enabled=True, priority=100,
                         weight=1, max_concurrency=1, consecutive_failures=0)]


def ready(config):
    """At least one enabled AI service that is set up correctly; raises a display-safe error otherwise."""
    from serviceops_core.ai.provider import validate_configuration
    problems, good = [], 0
    for connection in connections_for(config):
        if not routing.usable(connection):
            continue
        try:
            validate_configuration(_snapshot(config, connection))
            good += 1
        except ProviderError as error:
            problems.append(str(error))
    if not good:
        raise ProviderError(problems[0] if problems else "Set up and enable at least one AI service first.")
    return good


def _snapshot(config, connection):
    """What the provider adapter needs to call one service."""
    return SimpleNamespace(provider=connection.provider, model=connection.model, endpoint=connection.endpoint,
                           key_encrypted=connection.key_encrypted, external_consent=config.external_consent,
                           max_output_tokens=config.max_output_tokens, capabilities_json=connection.capabilities_json or "{}")


def cancel_active(tenant_id):
    AIRun.query.filter(AIRun.tenant_id == tenant_id, AIRun.status.in_(ACTIVE)).update(
        {"status": "cancelled", "completed_at": now(), "error_code": "configuration_changed"}, synchronize_session=False)


FLUSH_INTERVAL = 0.4
PURGE_INTERVAL = 300
_last_purge = None  # monotonic time of the last sweep
REASONING_ALLOWANCE = 1500  # extra output tokens granted when the model is asked to think


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
    reasons: set = field(default_factory=set)
    kinds: set = field(default_factory=set)


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
    reasons = set()
    evidence, sources = collect_evidence(identity, run.ticket_id, lambda text, kind: reasons.update(routing.scan(text, config, kind)))
    steps.add("Collected evidence", _describe(Counter(source["kind"] for source in sources)))
    prompt = json.dumps(evidence, ensure_ascii=True)
    if len(prompt) > 40000:
        raise ProviderError("Evidence exceeds the request limit.")
    return Prepared([{"role": "system", "content": INSTRUCTIONS}, {"role": "user", "content": prompt}], sources,
                    access.identifiers_in(prompt), (), True, bool(config.show_reasoning), reasons=reasons,
                    kinds={source["kind"] for source in sources})


def _prepare_chat(run, user, config, steps):
    scope = access.build_scope(user, run.actor_role)
    steps.add("Confirmed who is asking", scope.summary())
    question = run.question
    code = access.screen_question(scope, question)
    if code:
        steps.add("Declined", "This asks for something the assistant never has access to")
        return Prepared(refusal=code)
    reasons = set(routing.scan(question, config))
    evidence = access.collect_chat_evidence(scope, question, lambda text, kind: reasons.update(routing.scan(text, config, kind)))
    detail = _describe(evidence.counts())
    if evidence.unavailable:
        detail += f"; {len(evidence.unavailable)} reference(s) not available to you"
    steps.add("Looked up records you can access", detail)
    earlier = AIMessage.query.filter_by(conversation_id=run.conversation_id).order_by(AIMessage.created_at).all()
    history = access.history_for_model(scope, [m for m in earlier if m.status == "completed" and m.id != run.message_id])
    for turn in history:
        reasons.update(routing.scan(turn.get("content", ""), config))
    messages, _ = access.build_chat_messages(scope, question, history, evidence)
    grounded = access.identifiers_in(json.dumps(evidence.items)) | evidence.identifiers
    options = _run_options(run)
    # Chat replies are fast: the model is asked not to spend time on a long reasoning pass.
    return Prepared(messages, evidence.sources, grounded, tuple(access.record_numbers(question)), False, False,
                    reasons=reasons, kinds={s["kind"] for s in evidence.sources})


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


def _stream(run, config, prepared, steps, connection):
    run_id, tenant_id, revision = run.id, run.tenant_id, run.config_revision
    snapshot = _snapshot(config, connection)
    prepared = replace(prepared, messages=[dict(m) for m in prepared.messages], sources=list(prepared.sources),
                       allowed=set(prepared.allowed))
    if prepared.thinking:
        # A reasoning model spends part of the token cap on thinking before it writes the answer.
        snapshot.max_output_tokens = min(snapshot.max_output_tokens + REASONING_ALLOWANCE, 6000)
    from serviceops_core.ai.capabilities import fit_messages
    prepared.messages, snapshot.max_output_tokens, budget = fit_messages(snapshot, prepared.messages, snapshot.max_output_tokens)
    if budget["prompt_shortened"]:
        retained = set(re.findall(r'"source"\s*:\s*"(S\d+)"', prepared.messages[-1]["content"]))
        prepared.sources = [source for source in prepared.sources if source["id"] in retained]
        prepared.allowed &= access.identifiers_in(json.dumps(prepared.messages))
        steps.add("Adapted to model context", "Shortened evidence or older turns; kept your question and access rules")
    valid_ids = {source["id"] for source in prepared.sources}
    state = {"content": "", "reasoning": "", "last": 0.0, "began_reasoning": False, "began_answer": False}

    def sanitize(text):
        return access.sanitize_answer(text, prepared.allowed, valid_ids, prepared.typed)

    def flush(force=False):
        if not force and time.monotonic() - state["last"] < FLUSH_INTERVAL:
            return True
        state["last"] = time.monotonic()
        text = state["content"] if force else _stable_prefix(state["content"])
        # Reasoning controls the transient activity label, but private chain-of-thought is never persisted or sent to browsers.
        if not _publish_progress(run_id, partial_text=sanitize(text), reasoning_text="", steps_json=steps.dump()):
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

    steps.add("Sending to the model", connection.name)
    _publish_progress(run_id, steps_json=steps.dump())
    db.session.commit()  # no transaction is held open across the network call
    try:
        content, reasoning, usage = generate_stream(snapshot, prepared.messages, on_delta, thinking=prepared.thinking)
    except ProviderError as error:
        # Only a service that never started answering may be replaced by the next choice.
        error.delivered = bool(state["content"] or state["reasoning"])
        raise
    flush(force=True)
    return content, reasoning, usage, sanitize, prepared


def _finish(run_id, prepared, steps, content, reasoning, usage, sanitize, feature, route):
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
    run.result_text, run.partial_text, run.reasoning_text = final, "", ""
    run.sources_json, run.usage_json, run.steps_json, run.question = json.dumps(prepared.sources), json.dumps(usage), steps.dump(), ""
    run.status, run.completed_at, run.seq = "completed", now(), run.seq + 1
    run.route_json = json.dumps(route)
    if run.kind == "chat":
        message = db.session.get(AIMessage, run.message_id)
        message.route_json = json.dumps(route)
        message.content, message.reasoning, message.status, message.run_id = final, "", "completed", run.id
        message.sources_json, message.steps_json = json.dumps(prepared.sources), steps.dump()
        db.session.get(AIConversation, run.conversation_id).updated_at = now()
        audit("ai chat answered", run.id, f"sources={_describe(Counter(s['kind'] for s in prepared.sources))}; "
              f"service={route['name']}; location={route['location']}; sensitive={route['sensitive']}",
              user_id=run.user_id, tenant_id=run.tenant_id)
    else:
        audit("ai completed", run.id, f"Read-only incident investigation; service={route['name']}; "
              f"location={route['location']}; sensitive={route['sensitive']}", user_id=run.user_id, tenant_id=run.tenant_id)
    db.session.commit()


def _record_health(connection, ok):
    if connection.id == "legacy":
        return
    row = db.session.get(AIConnection, connection.id)
    if row:
        (routing.record_success if ok else routing.record_failure)(row)
        db.session.commit()


def _block(run_id, steps, code, prepared):
    """Nothing may answer this request (for example sensitive text and no private AI): say so plainly."""
    from app import audit
    run = AIRun.query.filter_by(id=run_id).populate_existing().with_for_update().one()
    if run.status != "running":
        return
    steps.finish()
    text = routing.BLOCKED_TEXT.get(code, routing.BLOCKED_TEXT["no_service"])
    route = {"name": "", "location": "none", "reason": text, "sensitive": bool(prepared.reasons)}
    run.steps_json, run.question, run.partial_text = steps.dump(), "", ""
    run.completed_at, run.seq, run.route_json = now(), run.seq + 1, json.dumps(route)
    if run.kind == "chat":
        run.result_text, run.status = text, "completed"
        message = db.session.get(AIMessage, run.message_id)
        message.content, message.status, message.run_id, message.route_json = text, "completed", run.id, json.dumps(route)
        db.session.get(AIConversation, run.conversation_id).updated_at = now()
        audit("ai chat denied", run.id, f"reason={code}", user_id=run.user_id, tenant_id=run.tenant_id)
    else:
        run.status, run.error_code = "failed", code
        audit("ai blocked", run.id, f"reason={code}", user_id=run.user_id, tenant_id=run.tenant_id)
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
    global _last_purge
    if _last_purge is None or time.monotonic() - _last_purge > PURGE_INTERVAL:  # retention is in days; no need to sweep on every poll
        _last_purge = time.monotonic()
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
        chosen = routing.plan(config, connections_for(config), prepared.reasons, prepared.kinds,
                              routing.running_counts(run.tenant_id))
        if not chosen.candidates:
            _block(run_id, steps, chosen.blocked, prepared)
            return True
        outcome = None
        for attempt, connection in enumerate(chosen.candidates[:3]):
            route = routing.describe(connection, chosen, attempt)
            AIRun.query.filter_by(id=run_id, status="running").update(
                {"connection_id": connection.id if connection.id != "legacy" else None, "provider": connection.provider,
                 "model": connection.model, "route_json": json.dumps(route)}, synchronize_session=False)
            db.session.commit()
            try:
                outcome = _stream(run, config, prepared, steps, connection)
            except ProviderError as failure:
                _record_health(connection, ok=False)
                if getattr(failure, "delivered", False) or attempt + 1 >= len(chosen.candidates[:3]):
                    raise
                continue
            _record_health(connection, ok=True)
            break
        content, reasoning, usage, sanitize, used = outcome
        _finish(run_id, used, steps, content, reasoning, usage, sanitize, feature, route)
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


def delete_conversation(conversation):
    """Remove a conversation and everything derived from it: messages, and any run text still held."""
    AIRun.query.filter_by(conversation_id=conversation.id).update(
        {"status": "cancelled", "question": "", "partial_text": "", "reasoning_text": "", "result_text": "",
         "sources_json": "[]"}, synchronize_session=False)
    AIMessage.query.filter_by(conversation_id=conversation.id).delete(synchronize_session=False)
    db.session.delete(conversation)


def purge_user_conversations(user_id):
    """Used when a person is erased: their chat history goes with their personal data."""
    for conversation in AIConversation.query.filter_by(user_id=user_id).all():
        delete_conversation(conversation)
