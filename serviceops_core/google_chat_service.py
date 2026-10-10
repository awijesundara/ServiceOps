"""Google Chat inbound handling: pulling the Pub/Sub subscription, and
running the slash commands (/ack, /escalate) agents type in a ticket's
Chat thread.

Moved from app.py; app.py re-exports both entry points. Parsing stays in the
pure serviceops_core.google_chat module. App helpers -- and the names tests
patch on the app module (`google_chat_post_message`,
`_google_service_account_access_token`, `now`, `setting_value`) -- are read
through `core_app` at call time.
"""
import hashlib
import re

import requests
from flask import current_app
from sqlalchemy import func
from werkzeug.exceptions import HTTPException

from serviceops_core.google_chat import decode_pubsub_message, extract_message_event, parse_command
from serviceops_core.task_lifecycle import ENTERPRISE_TRANSITIONS, TICKET_TRANSITIONS
from serviceops_models import (
    ChatThreadLink, GoogleChatCommandReceipt, SupportGroup, Ticket, TicketAssignmentGroup, User, db,
)


class _CoreApp:
    """Resolves app-module attributes at call time; importing app at module
    level would be circular (app.py imports this module while initializing)."""

    def __getattr__(self, name):
        import app
        return getattr(app, name)


core_app = _CoreApp()


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
        core_app.user_can_manage_ticket(actor, record)
        if target_type == "ticket"
        else core_app.user_can_manage_enterprise_record(actor, record)
    )
    required_actions = ("update", "assign", "transition")
    if not can_manage or any(
        not core_app.effective_role_has_action(actor.effective_role, action, tenant_id=record.tenant_id)
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
                    core_app.transition_ticket(record, "In Progress")
                else:
                    core_app.transition_enterprise(record, "In Progress")
            core_app.log_field_changes(
                target_type, record.id, before,
                {"state": record.state, "assigned to": actor.name}, event="Acknowledged via Google Chat",
            )
            core_app.audit("update", record.number, f"Acknowledged by {actor.name} via Google Chat")
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
                current_group = core_app.ticket_owning_group(record)
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
                core_app.log_history(
                    "ticket", record.id, "Reassigned to another team via Google Chat", "owning team",
                    current_group.name if current_group else "Unassigned", group.name, actor_id=actor.id,
                )
            else:
                if record.support_group_id == group.id:
                    return f"{record.number} is already owned by {group.name}."
                before_group = record.support_group.name if record.support_group else "Unassigned"
                record.support_group_id = group.id
                record.assignee_id = None
                core_app.log_history(
                    "enterprise", record.id, "Reassigned to another team via Google Chat", "owning team",
                    before_group, group.name, actor_id=actor.id,
                )
            core_app.audit("escalate", record.number, f"Escalated to {group.name} by {actor.name} via Google Chat")
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
    if not core_app.setting_bool("GOOGLE_CHAT_APP_ENABLED", False):
        return 0
    project_id = core_app.setting_value("GOOGLE_CHAT_PROJECT_ID", "")
    subscription_id = core_app.setting_value("GOOGLE_CHAT_PUBSUB_SUBSCRIPTION", "")
    service_account_json = core_app.setting_value("GOOGLE_CHAT_SERVICE_ACCOUNT_JSON", "")
    expected_bot_name = core_app.setting_value("GOOGLE_CHAT_BOT_USER_NAME", "")
    if not re.fullmatch(r"users/[\w-]+", expected_bot_name or ""):
        return 0
    if not (project_id and subscription_id and service_account_json):
        return 0
    max_messages = max(1, min(int(max_messages), 20))
    subscription = f"projects/{project_id}/subscriptions/{subscription_id}"
    proxies = core_app.resolve_component_proxies("GOOGLE_CHAT")
    try:
        access_token = core_app._google_service_account_access_token(
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
                record = core_app.find_record_by_number(link.record_number, tenant_id=link.tenant_id)
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
                core_app.google_chat_post_message(
                    receipt.connection, receipt.reply_text,
                    thread_name=receipt.thread_name, message_id=reply_message_id,
                )
                receipt.replied_at = core_app.now()
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
