"""Pure outbound-delivery policy helpers.

Network I/O and database access intentionally remain in app.py.  Keeping event
matching and Google Chat formatting here makes subscription policy testable
without Flask or external services.
"""
import fnmatch
import html
import json


WEBHOOK_KINDS = {
    "webhook", "google_chat", "telegram", "slack", "teams", "discord", "siem",
}

PROVIDER_LABELS = {
    "google_chat": "Google Chat",
    "telegram": "Telegram bot",
    "slack": "Slack",
    "teams": "Microsoft Teams",
    "discord": "Discord",
    "webhook": "Signed webhook",
    "siem": "Audit / SIEM webhook",
}

PROVIDER_HOSTS = {
    "google_chat": {"chat.googleapis.com"},
    "telegram": {"api.telegram.org"},
    "slack": {"hooks.slack.com", "hooks.slack-gov.com"},
    "discord": {"discord.com", "discordapp.com"},
}

EVENT_SUBSCRIPTIONS = (
    ("notification.created", "User notifications", "All notifications created for ServiceOps users."),
    ("notification.created:approval.requested", "Approval requests", "New approval decisions requiring attention."),
    ("notification.created:sla.breached", "SLA breaches", "Breached service-level targets."),
    ("notification.created:client_ticket.escalated", "Client escalations", "Escalated customer tickets."),
    ("notification.created:ritm.comment_added", "Request comments", "New customer-visible request comments."),
    ("notification.created:enterprise.*", "Enterprise approvals", "Enterprise record approval decisions and requests."),
    ("activity.created:approvals", "Approval activity", "Approval decisions, delegations, and workflow changes."),
    ("activity.created:incidents", "Incident activity", "Incident creation, updates, resolution, and reviews."),
    ("activity.created:changes", "Change activity", "Change plans, governance, implementation, and reviews."),
    ("activity.created:requests", "Request and task activity", "Catalog requests, RITMs, and operational tasks."),
    ("activity.created:cmdb", "CMDB and asset activity", "Configuration item, relationship, asset, and NetBox changes."),
    ("activity.created:knowledge", "Knowledge activity", "Knowledge article lifecycle changes."),
    ("activity.created:directory", "Users, teams, and directory", "User, team, SCIM, and LDAP administration."),
    ("activity.created:integrations", "Integration activity", "Notification, monitoring, import, and integration changes."),
    ("activity.created:sla", "SLA and escalation activity", "SLA, escalation, and service-impact operations."),
    ("activity.created:security", "Security activity", "Authentication and credential security events; no secrets are sent."),
    ("activity.created:other", "Other operational activity", "Activity not covered by another category."),
)

EVENT_SUBSCRIPTION_PATTERNS = {item[0] for item in EVENT_SUBSCRIPTIONS}


def activity_category(action, target=""):
    """Map an immutable audit action to a stable, administrator-friendly topic."""
    action_text = str(action or "").lower()
    target_text = str(target or "").upper()
    if "approval" in action_text or "delegation" in action_text:
        return "approvals"
    if target_text.startswith("CHG") or any(word in action_text for word in ("change plan", "conflict check", "freeze")):
        return "changes"
    if target_text.startswith("INC") or any(word in action_text for word in ("major incident", "post-incident")):
        return "incidents"
    if target_text.startswith(("REQ", "RITM", "SCTASK")) or any(word in action_text for word in ("catalog", "task", "request item")):
        return "requests"
    if target_text.startswith(("CI", "AST")) or any(word in action_text for word in ("link ci", "netbox", "cmdb", "asset")):
        return "cmdb"
    if target_text.startswith("KB") or "knowledge" in action_text:
        return "knowledge"
    if any(word in action_text for word in ("ldap", "scim", "user", "team", "group", "profile")):
        return "directory"
    if any(word in action_text for word in ("integration", "webhook", "monitoring source", "import")):
        return "integrations"
    if any(word in action_text for word in ("sla", "escalat", "outage", "service impact")):
        return "sla"
    if any(word in action_text for word in ("login", "logout", "password", "credential", "mfa", "passkey", "token", "api client", "audit key")):
        return "security"
    return "other"


def provider_endpoint_allowed(kind, hostname):
    """Reject a copied URL for the wrong provider before storing its secret."""
    allowed = PROVIDER_HOSTS.get(kind)
    return not allowed or str(hostname or "").lower() in allowed


def parse_event_patterns(raw):
    """Return a conservative list of exact/glob event patterns.

    Empty configuration means all events for backwards compatibility. Invalid
    JSON matches nothing instead of accidentally widening delivery.
    """
    if raw in (None, "", "[]"):
        return ["*"]
    try:
        values = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return []
    if not isinstance(values, list):
        return []
    return [value.strip() for value in values if isinstance(value, str) and value.strip()]


def event_matches(patterns_json, event_type, payload=None):
    """Match the envelope type or its useful domain subtype.

    Notifications expose ``notification.created:<notification_event_type>``;
    audit streams expose ``audit.created:<action>``. This preserves the stable
    envelope while allowing precise subscriptions without duplicating events.
    """
    candidates = [event_type]
    payload = payload or {}
    subtype = (
        payload.get("notification_event_type")
        if event_type == "notification.created"
        else payload.get("activity_category") if event_type == "activity.created"
        else payload.get("action") if event_type == "audit.created" else None
    )
    if subtype:
        candidates.append(f"{event_type}:{subtype}")
    return any(
        fnmatch.fnmatchcase(candidate, pattern)
        for pattern in parse_event_patterns(patterns_json)
        for candidate in candidates
    )


def google_chat_message(event_payload):
    """Build the documented Google Chat incoming-webhook text payload."""
    title = str(event_payload.get("title") or "ServiceOps event").strip()
    body = str(event_payload.get("body") or "").strip()
    return {"text": f"*{title}*\n{body}" if body else f"*{title}*"}


def plain_chat_message(event_payload):
    """Build a portable bounded message for chat providers."""
    title = str(event_payload.get("title") or "ServiceOps event").strip()
    body = str(event_payload.get("body") or "").strip()
    return f"{title}\n{body}" if body else title


def provider_payload(kind, event_payload, configuration=None):
    """Return the provider's documented JSON message shape."""
    configuration = configuration or {}
    message = plain_chat_message(event_payload)
    if kind == "google_chat":
        return google_chat_message(event_payload)
    if kind == "teams":
        title = str(event_payload.get("title") or "ServiceOps event").strip()
        body = str(event_payload.get("body") or "").strip()
        return {"text": f"**{title}**\n\n{body}" if body else f"**{title}**"}
    if kind == "slack":
        return {"text": message}
    if kind == "discord":
        return {"content": message[:2000]}
    if kind == "telegram":
        payload = {
            "chat_id": configuration.get("chat_id", ""),
            "text": message[:4096],
            "protect_content": bool(configuration.get("protect_content", False)),
        }
        if configuration.get("message_thread_id"):
            payload["message_thread_id"] = configuration["message_thread_id"]
        return payload
    raise ValueError(f"Unsupported chat provider: {html.escape(str(kind))}")
