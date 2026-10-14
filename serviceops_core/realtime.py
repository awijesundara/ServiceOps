"""Real-time signals through PostgreSQL LISTEN/NOTIFY.

While a transaction writes, this collects small signals and sends them with
``pg_notify`` just before it commits, so they are delivered only if the
change commits and never for a rollback:

- ``serviceops_events``: ``{"type": "notification", "tenant": t, "user": u}``
  when a notification is created, and ``{"type": "ticket", "tenant": t,
  "id": ticket_id, "actor": user_id}`` when a ticket, its comments or its
  history change. The events service (tools/events_server.py) forwards them
  to the browsers that may see them.
  Project pages get ``{"type": "watch", "tenant": t, "key": "project:N" or
  "work_item:N", "actor": user_id}`` when a work item, its comments or its
  history change; streams watching that key are told something changed.
- ``serviceops_outbox``: an empty signal when an outbox event is queued, so
  the background worker starts delivering at once instead of on its next
  timed pass.

Payloads carry only ids: what a browser then fetches is authorised by the
web application as usual. Other databases (SQLite in tests and IPFS mode)
skip all of this; browsers fall back to polling.
"""
import json

from flask import has_request_context
from sqlalchemy import event, text
from sqlalchemy.orm import Session

EVENTS_CHANNEL = "serviceops_events"
OUTBOX_CHANNEL = "serviceops_outbox"
_PENDING = "serviceops_realtime_pending"


def _actor_id():
    if not has_request_context():
        return None
    try:
        from flask_login import current_user
        return current_user.id if current_user.is_authenticated else None
    except Exception:
        return None


def _collect(session):
    from serviceops_models import (Comment, Notification, OutboxEvent, TaskHistory, Ticket, WorkItem,
                                   WorkItemComment, WorkItemHistory)
    pending = session.info.setdefault(_PENDING, {"events": set(), "outbox": False})
    actor = _actor_id()

    def watch(tenant, key):
        pending["events"].add(("watch", tenant, key, actor))

    for obj in list(session.new) + list(session.dirty) + list(session.deleted):
        if isinstance(obj, WorkItem) and obj.id:
            watch(obj.tenant_id, f"project:{obj.project_id}")
            watch(obj.tenant_id, f"work_item:{obj.id}")
        elif isinstance(obj, (WorkItemComment, WorkItemHistory)) and obj.work_item_id and obj in session.new:
            # Field changes also mark the work item itself dirty, which
            # signals its project; comments and attachments concern the item.
            watch(obj.tenant_id, f"work_item:{obj.work_item_id}")
    for obj in session.new:
        if isinstance(obj, Notification) and obj.user_id:
            pending["events"].add(("notification", obj.tenant_id, obj.user_id, None))
        elif isinstance(obj, Comment) and obj.ticket_id:
            pending["events"].add(("ticket", obj.tenant_id, obj.ticket_id, actor or obj.user_id))
        elif isinstance(obj, TaskHistory) and obj.target_type == "ticket" and obj.target_id:
            pending["events"].add(("ticket", None, obj.target_id, actor or obj.actor_id))
        elif isinstance(obj, OutboxEvent):
            pending["outbox"] = True
    for obj in session.dirty:
        if isinstance(obj, Ticket) and obj.id and session.is_modified(obj, include_collections=False):
            pending["events"].add(("ticket", obj.tenant_id, obj.id, actor))


@event.listens_for(Session, "after_flush")
def _after_flush(session, flush_context):
    try:
        _collect(session)
    except Exception:
        # Signals are an optimisation; a failure here must never break a write.
        session.info.pop(_PENDING, None)


@event.listens_for(Session, "before_commit")
def _before_commit(session):
    # Commit runs this hook before its own final flush: flush now so the
    # changes being committed are collected too.
    if session.new or session.dirty or session.deleted:
        session.flush()
    pending = session.info.pop(_PENDING, None)
    if not pending or (not pending["events"] and not pending["outbox"]):
        return
    try:
        bind = session.get_bind()
        if bind.dialect.name != "postgresql":
            return
        ticket_tenants = {}
        for kind, tenant, target, actor in sorted(pending["events"], key=str):
            if kind == "ticket" and tenant is None:
                # History rows carry no tenant: take the ticket's.
                if target not in ticket_tenants:
                    ticket_tenants[target] = session.execute(
                        text("SELECT tenant_id FROM ticket WHERE id = :id"), {"id": target},
                    ).scalar()
                tenant = ticket_tenants[target]
            if tenant is None:
                continue
            payload = {"type": kind, "tenant": tenant}
            if kind == "notification":
                payload["user"] = target
            elif kind == "watch":
                payload.update({"key": target, "actor": actor})
            else:
                payload.update({"id": target, "actor": actor})
            session.execute(text("SELECT pg_notify(:channel, :payload)"),
                            {"channel": EVENTS_CHANNEL, "payload": json.dumps(payload, separators=(",", ":"))})
        if pending["outbox"]:
            session.execute(text("SELECT pg_notify(:channel, '')"), {"channel": OUTBOX_CHANNEL})
    except Exception:
        # Never fail the commit for a signal; browsers and the worker still
        # catch up through their periodic checks.
        import logging
        logging.getLogger("app").warning("Real-time signal could not be queued", exc_info=True)
