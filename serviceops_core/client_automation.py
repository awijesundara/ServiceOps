"""Client Management trigger engine (phase 6 of the Zendesk-style build-out).

Mirrors workflow.py's validation-first, closed-vocabulary shape, but scoped
to ClientTicket's own fields -- workflow.py's own EVENTS/FIELDS are all
`ticket.*` (ITIL tickets), not client-ticket-shaped, so this is a small,
parallel engine rather than an extension of it (see workflow.py's own
narrower FIELDS list for why reuse wasn't a clean fit).

A trigger is one condition (field/op/value, using the exact same operator
vocabulary parse_list_filter_param/apply_filter_conditions already use
elsewhere in this app) and one action (type/value), evaluated against a
plain dict "context" built from the ClientTicket that changed -- kept
single-condition/single-action deliberately, not a multi-row rule builder,
to keep the admin UI and this module small; a trigger needing more than one
condition can be expressed as two triggers on the same event.
"""

CLIENT_TRIGGER_EVENTS = ("created", "status_changed", "updated")
CLIENT_TRIGGER_FIELDS = ("status", "priority", "ticket_type", "channel", "tags", "subject")
CLIENT_TRIGGER_OPERATORS = ("eq", "ne", "contains", "starts_with", "is_empty", "is_not_empty")
CLIENT_TRIGGER_ACTION_TYPES = (
    "set_status", "set_priority", "add_tag", "assign_to_group", "assign_to_user",
    "notify_assignee", "notify_org_contact",
)
CLIENT_TICKET_STATUSES = ("New", "Open", "Pending", "On-hold", "Solved", "Closed")
CLIENT_TICKET_PRIORITIES = ("Low", "Normal", "High", "Urgent")


class ClientTriggerConfigurationError(ValueError):
    pass


def validate_trigger(event, condition_field, condition_op, action_type, action_value):
    """Raises ClientTriggerConfigurationError with a user-facing message on
    the first invalid piece; returns None when everything is valid."""
    if event not in CLIENT_TRIGGER_EVENTS:
        raise ClientTriggerConfigurationError("Select a valid trigger event.")
    if condition_field not in CLIENT_TRIGGER_FIELDS:
        raise ClientTriggerConfigurationError("Select a valid condition field.")
    if condition_op not in CLIENT_TRIGGER_OPERATORS:
        raise ClientTriggerConfigurationError("Select a valid condition operator.")
    if action_type not in CLIENT_TRIGGER_ACTION_TYPES:
        raise ClientTriggerConfigurationError("Select a valid action.")
    if action_type == "set_status" and action_value not in CLIENT_TICKET_STATUSES:
        raise ClientTriggerConfigurationError("Select a valid status for the action.")
    if action_type == "set_priority" and action_value not in CLIENT_TICKET_PRIORITIES:
        raise ClientTriggerConfigurationError("Select a valid priority for the action.")
    if action_type in ("assign_to_group", "assign_to_user") and not action_value:
        raise ClientTriggerConfigurationError("Select who or which team to assign to.")
    if action_type in ("add_tag", "notify_assignee", "notify_org_contact") and not action_value.strip():
        raise ClientTriggerConfigurationError("This action needs a value.")


def condition_matches(field, op, value, context):
    """`context` is a plain dict of the ClientTicket's own field values
    (already-lowercased-nothing -- comparisons below casefold as needed).
    Unknown field/op always fails closed (no match) rather than raising, so
    a trigger row that somehow predates a vocabulary change never silently
    matches everything."""
    if field not in CLIENT_TRIGGER_FIELDS or op not in CLIENT_TRIGGER_OPERATORS:
        return False
    actual = str(context.get(field) or "")
    value = value or ""
    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op == "contains":
        return value.casefold() in actual.casefold()
    if op == "starts_with":
        return actual.casefold().startswith(value.casefold())
    if op == "is_empty":
        return not actual
    if op == "is_not_empty":
        return bool(actual)
    return False
