"""Which notifications are emailed by default: the ones that involve the
recipient.

A notification involves someone when it is addressed to them personally
(a mention, an assignment, a share, an approval waiting on their decision)
or when it is about a record they raised, are the caller or requester on,
or are assigned to. Team-queue notices, SLA alerts and other broadcasts
stay in the in-app inbox unless the recipient chooses to receive
everything by email (NotificationPreference.email_scope = "all").
"""

INVOLVING_ME = "involving_me"
EVERYTHING = "all"
EMAIL_SCOPES = (INVOLVING_ME, EVERYTHING)

# Addressed to the recipient personally, whatever the record.
PERSONAL_EVENT_TYPES = {
    "ticket.mentioned", "work_item.mentioned", "work_item.assigned", "work_item.shared",
    "approval.requested", "enterprise.approval_requested",
}

# People fields that make someone part of a record.
_PEOPLE_FIELDS = ("assignee_id", "requester_id", "opened_by_id", "created_by_id",
                  "requested_by_id", "requested_for_id", "reporter_id")


def _record(target_type, target_id):
    import app as core
    from serviceops_models import CatalogRequest, CatalogTask, ClientTicket, OperationalTask
    extra = {"client_ticket": ClientTicket, "catalog_task": CatalogTask,
             "operational_task": OperationalTask, "request": CatalogRequest}
    model = extra.get(target_type)
    if model is not None:
        return core.db.session.get(model, target_id)
    return core.record_reference(target_type, target_id)


def _people(record, depth=0):
    """Everyone a record belongs to, including its parent records (a catalog
    task's request, a change task's change)."""
    if record is None or depth > 3:
        return set()
    people = {getattr(record, field, None) for field in _PEOPLE_FIELDS}
    people.update(user.id for user in getattr(record, "assignees", None) or [])
    for parent in ("requested_item", "request"):
        people |= _people(getattr(record, parent, None), depth + 1)
    if getattr(record, "parent_type", None) == "ticket" and getattr(record, "parent_id", None):
        people |= _people(_record("ticket", record.parent_id), depth + 1)
    people.discard(None)
    return people


def involves_recipient(user_id, payload):
    """True when the notification in `payload` involves `user_id`."""
    if payload.get("notification_event_type") in PERSONAL_EVENT_TYPES:
        return True
    target_type, target_id = payload.get("target_type"), payload.get("target_id")
    if not target_type or not target_id:
        return False
    try:
        return user_id in _people(_record(target_type, int(target_id)))
    except (TypeError, ValueError):
        return False
