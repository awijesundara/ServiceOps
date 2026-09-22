"""Deterministic, human-approved AI actions.

The model never chooses a database row or executes a write.  This module turns an
administrator's explicit chat command into a bounded proposal, then repeats all
authorization and lifecycle checks immediately before execution.
"""
import re

from flask import abort

from serviceops_core.ai.access import record_numbers  # noqa: F401 (re-exported for callers that import it from here)
from serviceops_core.security import redact
from serviceops_models import Knowledge, Ticket, User, db

ADMIN_ROLES = frozenset({"admin", "superadmin"})
PRIORITIES = ("P1", "P2", "P3", "P4")
ACTION_VERB = re.compile(r"\b(set|change|update|move|mark|assign|unassign|add|post)\b", re.I)


def _visible_ticket(scope, number):
    from app import visible_ticket_query
    return visible_ticket_query(scope.identity).filter(
        db.func.upper(Ticket.number) == number.upper(), Ticket.deleted_at.is_(None)
    ).first()


def propose_from_question(scope, question, enabled):
    """Return a safe action preview only for an explicit single-ticket admin command."""
    if not enabled or scope.role not in ADMIN_ROLES or not ACTION_VERB.search(question or ""):
        return None
    numbers = record_numbers(question)
    if len(numbers) != 1:
        return None
    ticket = _visible_ticket(scope, numbers[0])
    if not ticket:
        return None

    from app import allowed_ticket_states, ticket_team_agents, user_can_manage_ticket
    if not user_can_manage_ticket(scope.identity, ticket):
        return None

    quoted = re.search(r"\b(?:add|post)\s+(?:an?\s+)?comment\b.*?[\"“](.{1,2000}?)[\"”]", question, re.I | re.S)
    if quoted:
        body = redact(quoted.group(1).strip())
        if body:
            return {"type": "add_comment", "ticket": ticket.number, "summary": f'Add comment: “{body[:160]}”',
                    "payload": {"body": body}}

    changes = {}
    priority = re.search(r"\b(P[1-4])\b", question, re.I)
    if priority and re.search(r"\b(set|change|update|make|mark)\b", question, re.I):
        changes["priority"] = priority.group(1).upper()

    lowered = question.lower()
    allowed_states = allowed_ticket_states(ticket)
    explicit_state = next((state for phrase, state in (
        (r"\breopen\b", "In Progress"), (r"\bresolve\b", "Resolved"),
        (r"\bclose\b", "Closed"), (r"\bcancel\b", "Cancelled"),
    ) if re.search(phrase, lowered) and state in allowed_states), None)
    if explicit_state:
        changes["state"] = explicit_state
    for state in allowed_states:
        if "state" in changes:
            break
        if state.lower() in lowered and re.search(r"\b(set|change|update|move|mark|reopen|resolve|close|cancel)\b", lowered):
            changes["state"] = state
            break

    if re.search(r"\bunassign\b", question, re.I):
        changes["assigned_to_id"] = None
        changes["assigned_to_label"] = "Unassigned"
    elif re.search(r"\bassign\b.*\bto\s+me\b", question, re.I | re.S):
        if scope.user_id in {user.id for user in ticket_team_agents(ticket)}:
            changes["assigned_to_id"] = scope.user_id
            changes["assigned_to_label"] = scope.display_name
    else:
        username = re.search(r"\bassign\b.*\bto\s+@([A-Za-z0-9_.-]{2,80})\b", question, re.I | re.S)
        if username:
            eligible = {user.username.lower(): user for user in ticket_team_agents(ticket)}
            assignee = eligible.get(username.group(1).lower())
            if assignee:
                changes["assigned_to_id"] = assignee.id
                changes["assigned_to_label"] = assignee.name

    if not changes:
        return None
    labels = []
    if "state" in changes:
        labels.append(f"state to {changes['state']}")
    if "priority" in changes:
        labels.append(f"priority to {changes['priority']}")
    if "assigned_to_id" in changes:
        labels.append(f"assignee to {changes['assigned_to_label']}")
    payload = {key: value for key, value in changes.items() if key != "assigned_to_label"}
    return {"type": "update_ticket", "ticket": ticket.number,
            "summary": "Set " + ", ".join(labels), "payload": payload}


DRAFT_LABELS = {"resolution_note": "Resolution note", "closure_note": "Closure note",
                "suggested_response": "Suggested reply", "sentiment": "Sentiment assessment", "kb_article": "Knowledge article"}
DRAFT_COMMENT_PREFIX = {"resolution_note": "Resolution note (AI-drafted, human-approved)",
                        "closure_note": "Closure note (AI-drafted, human-approved)",
                        "suggested_response": "Suggested reply (AI-drafted, human-approved)",
                        "sentiment": "Sentiment assessment (AI-drafted, human-approved)"}


def action_label(action_type):
    if action_type in DRAFT_LABELS:
        return DRAFT_LABELS[action_type]
    return {"add_comment": "Add ticket comment", "update_ticket": "Update ticket"}.get(action_type, "ServiceOps action")


def prepare_from_draft(draft):
    """Turn a validated generated draft (from access.extract_generated_draft) into the same proposal shape
    propose_from_question produces, so both flow through one review-and-approve path."""
    if draft["type"] == "kb_article":
        summary = f'Create draft knowledge article "{draft["title"]}"'
        payload = {"title": draft["title"], "body": draft["text"]}
    else:
        summary = f"{DRAFT_LABELS[draft['type']]}: {draft['text'][:160]}"
        payload = {"body": draft["text"]}
    return {"type": draft["type"], "ticket": draft["ticket"], "summary": summary, "payload": payload}


def describe_payload(action_type, payload):
    if action_type == "kb_article":
        return [("Title", payload["title"]), ("Body", payload["body"])]
    if action_type in ("add_comment", *DRAFT_COMMENT_PREFIX):
        return [("Comment", payload["body"])]
    labels = {"state": "State", "priority": "Priority", "assigned_to_id": "Assigned to"}
    values = []
    for key in ("state", "priority", "assigned_to_id"):
        if key not in payload:
            continue
        value = payload[key]
        if key == "assigned_to_id":
            user = db.session.get(User, value) if value is not None else None
            value = user.name if user else "Unassigned"
        values.append((labels[key], value))
    return values


def execute(action, ticket, actor):
    """Execute a locked, current proposal through the same domain services as the UI."""
    from app import (audit, effective_role_has_action, follow_ticket, log_field_changes, log_history,
                     post_ticket_comment, ticket_team_agents, transition_ticket, user_can_manage_ticket)
    import json

    payload = json.loads(action.payload_json)
    if action.action_type == "add_comment":
        if not effective_role_has_action(actor.effective_role, "comment_public", tenant_id=actor.tenant_id):
            abort(403)
        body = str(payload.get("body", "")).strip()
        if not body or len(body) > 10000:
            abort(400, description="The proposed comment is no longer valid.")
        comment = post_ticket_comment(ticket, actor, body)
        log_history("ticket", ticket.id, "AI-assisted comment added", details=body[:500])
        audit("ai action execute", ticket.number, f"type=add_comment; comment={comment.id}")
        return
    if action.action_type in DRAFT_COMMENT_PREFIX:
        if actor.effective_role not in ADMIN_ROLES | {"agent", "manager"} or not user_can_manage_ticket(actor, ticket):
            abort(403)
        if not effective_role_has_action(actor.effective_role, "comment_public", tenant_id=actor.tenant_id):
            abort(403)
        body = str(payload.get("body", "")).strip()
        if not body or len(body) > 10000:
            abort(400, description="The proposed note is no longer valid.")
        text = f"{DRAFT_COMMENT_PREFIX[action.action_type]}: {body}"
        comment = post_ticket_comment(ticket, actor, text)
        log_history("ticket", ticket.id, f"AI-assisted {action.action_type.replace('_', ' ')} added", details=body[:500])
        audit("ai action execute", ticket.number, f"type={action.action_type}; comment={comment.id}")
        return
    if action.action_type == "kb_article":
        if actor.effective_role not in ADMIN_ROLES | {"agent", "manager"}:
            abort(403)
        if not effective_role_has_action(actor.effective_role, "create", tenant_id=actor.tenant_id):
            abort(403)
        title = str(payload.get("title", "")).strip()[:180]
        body = str(payload.get("body", "")).strip()
        if not title or not body:
            abort(400, description="The proposed article is no longer valid.")
        article = Knowledge(title=title, category="General", body=body, author_id=actor.id,
                            tenant_id=actor.tenant_id, published=False)
        db.session.add(article)
        db.session.flush()
        log_history("ticket", ticket.id, "AI-drafted knowledge article created (unpublished)", details=title[:500])
        audit("ai action execute", ticket.number, f"type=kb_article; article=KB{article.id:07d}")
        return
    if action.action_type != "update_ticket":
        abort(400, description="This AI action type is not supported.")
    if actor.effective_role not in ADMIN_ROLES or not user_can_manage_ticket(actor, ticket):
        abort(403)
    for required in ("update", "assign", "transition"):
        if not effective_role_has_action(actor.effective_role, required, tenant_id=actor.tenant_id):
            abort(403)
    unknown = set(payload) - {"state", "priority", "assigned_to_id"}
    if unknown or not payload:
        abort(400, description="The proposed ticket update is not valid.")
    before = {"state": ticket.state, "priority": ticket.priority,
              "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned"}
    if "state" in payload:
        transition_ticket(ticket, str(payload["state"]))
    if "priority" in payload:
        priority = str(payload["priority"])
        if priority not in PRIORITIES:
            abort(400, description="The proposed priority is not valid.")
        ticket.priority = priority
    if "assigned_to_id" in payload:
        assignee_id = payload["assigned_to_id"]
        if assignee_id is not None:
            try:
                assignee_id = int(assignee_id)
            except (TypeError, ValueError):
                abort(400, description="The proposed assignee is not valid.")
            eligible = {user.id for user in ticket_team_agents(ticket)}
            if assignee_id not in eligible:
                abort(409, description="The proposed assignee is no longer eligible for this ticket.")
        ticket.assignee_id = assignee_id
        if assignee_id:
            follow_ticket(ticket, db.session.get(User, assignee_id))
    log_field_changes("ticket", ticket.id, before, {
        "state": ticket.state, "priority": ticket.priority,
        "assigned to": ticket.assignee.name if ticket.assignee else "Unassigned",
    }, event="AI-approved update")
    audit("ai action execute", ticket.number, f"type=update_ticket; fields={','.join(sorted(payload))}")
