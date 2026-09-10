"""Pure outbound-delivery policy helpers.

Network I/O and database access intentionally remain in app.py.  Keeping event
matching and Google Chat formatting here makes subscription policy testable
without Flask or external services.
"""
import fnmatch
import json


WEBHOOK_KINDS = {"webhook", "google_chat", "teams", "siem"}


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
