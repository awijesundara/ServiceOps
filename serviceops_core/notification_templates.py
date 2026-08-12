"""Pure notification-template rendering and event-catalog logic -- no
Flask or database dependency, matching the bounded-interface pattern
already established by serviceops_core.security. app.py's
create_notification()/deliver_smtp() own the actual NotificationTemplate/
NotificationPreference database lookups and call into this module for the
rendering/matching decisions themselves.
"""
import json
from string import Template

# The known notification event types, matching create_notification()'s
# call sites in app.py. `variables` lists what a template author can use
# in ${var} placeholders for that event -- documented here once rather
# than scattered across call sites, since it's what the admin template
# editor needs to show as available fields.
NOTIFICATION_EVENT_TYPES = {
    "approval.requested": {
        "label": "Approval requested",
        "description": "Sent to an approver when their decision is needed on an approval gate.",
        "variables": ["gate_name", "chain_name"],
        "default_subject": "Approval requested: ${gate_name}",
        "default_body": "Your decision is required for approval chain ${chain_name}.",
    },
    "client_ticket.escalated": {
        "label": "Client ticket escalated",
        "description": "Sent to a team manager when a client ticket breaches its organization's escalation threshold.",
        "variables": ["ticket_number", "ticket_subject", "organization_name", "hours"],
        "default_subject": "Escalated: ${ticket_number}",
        "default_body": "${ticket_subject} has been open past ${organization_name}'s escalation threshold.",
    },
    "sla.breached": {
        "label": "SLA breached",
        "description": "Sent to configured recipients when an SLA target is missed.",
        "variables": ["reference", "sla_name"],
        "default_subject": "SLA breached: ${reference}",
        "default_body": "${sla_name} breached for ${reference}. Immediate attention is required.",
    },
    "password.recovery": {
        "label": "Password recovery",
        "description": "Sent with a single-use password reset link.",
        "variables": ["reset_url"],
        "default_subject": "ServiceOps password recovery",
        "default_body": "Use this single-use link within 30 minutes to reset your password: ${reset_url}",
    },
    "enterprise.approval_requested": {
        "label": "Enterprise record approval requested",
        "description": "Sent to an administrator when an enterprise record needs approval.",
        "variables": ["record_number", "record_title"],
        "default_subject": "Approval requested: ${record_number}",
        "default_body": "${record_title}",
    },
    "enterprise.approval_decided": {
        "label": "Enterprise record approval decided",
        "description": "Sent to the requester once their enterprise record approval is decided.",
        "variables": ["record_number", "decision", "comments"],
        "default_subject": "${record_number} ${decision}",
        "default_body": "${comments}",
    },
    "ritm.comment_added": {
        "label": "RITM comment added",
        "description": "Sent to the requester when a customer-visible comment is added to their request.",
        "variables": ["ritm_number", "comment"],
        "default_subject": "New comment on ${ritm_number}",
        "default_body": "${comment}",
    },
}


def render_notification_template(template_string, variables):
    """${var}-style safe substitution: a variable missing from `variables`
    is left as literal text (e.g. "${typo}") instead of raising, since a
    malformed admin-edited template must degrade to visibly-odd-but-safe
    output, never a 500 on every notification of that type."""
    return Template(template_string).safe_substitute(variables or {})


# Security-critical, user-initiated event types that must never be
# silently muteable -- a user who clicked "forgot password" themselves
# unambiguously wants that email, and letting a stale mute preference
# (set for an unrelated reason, possibly years earlier) block their only
# self-service recovery path would be a real lockout trap, not a
# harmless preference.
NON_MUTABLE_EVENT_TYPES = {"password.recovery"}


def is_event_muted(muted_event_types_json, event_type):
    """True if `event_type` is in the user's muted-events list. Tolerant
    of malformed/legacy JSON (treats it as an empty mute list) since a
    parse failure here must never block a notification from being sent."""
    if not event_type or event_type in NON_MUTABLE_EVENT_TYPES:
        return False
    try:
        muted = json.loads(muted_event_types_json or "[]")
    except (TypeError, ValueError):
        return False
    return isinstance(muted, list) and event_type in muted
