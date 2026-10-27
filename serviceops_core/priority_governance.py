"""One priority rule for every way a ticket's priority can change.

Priority follows the impact/urgency matrix (config/priority_matrix.json). A
different priority is an override: only a manager or administrator may make
one, with a reason of at least 10 characters, and it is flagged on the
ticket and recorded in its history. The web form enforces this itself; the
REST API and approved AI actions use this module so they cannot bypass it.
"""
from flask import abort

from serviceops_core.localization import tr
from serviceops_core.priority import calculate_priority

PRIORITIES = ("P1", "P2", "P3", "P4")
MIN_OVERRIDE_REASON = 10


def check_governed_priority(actor, *, impact, urgency, priority=None, reason=None, overridden=False):
    """Validate without touching a ticket; returns (calculated, requested). Aborts 400/403.

    ``overridden`` says the ticket already carries a manager override: removing
    it (by landing on the calculated priority) needs the same authority as setting it.
    """
    import app as core

    try:
        calculated = calculate_priority(impact, urgency)
    except ValueError as error:
        abort(400, description=str(error))
    requested = calculated if priority is None else str(priority)
    if requested not in PRIORITIES:
        abort(400, description=tr("priority must be P1, P2, P3 or P4."))
    if overridden and requested == calculated and not core.role_at_least(actor.effective_role, "manager"):
        abort(403, description=tr("Only a manager or administrator may clear a priority override."))
    if requested != calculated:
        if not core.role_at_least(actor.effective_role, "manager"):
            abort(403, description=tr(
                "Only a manager or administrator may override the calculated priority ({calculated}).",
                calculated=calculated))
        if len((reason or "").strip()) < MIN_OVERRIDE_REASON:
            abort(400, description=tr("A priority override needs a reason of at least 10 characters."))
    return calculated, requested


def apply_governed_priority(ticket, actor, *, impact=None, urgency=None, priority=None, reason=None, source):
    """Set impact, urgency and priority on ``ticket`` or abort with 400/403.

    Omitted values keep the ticket's current impact/urgency, and an omitted
    priority means "use the calculated one". ``source`` names the channel in
    the history entry (for example "REST API").
    """
    import app as core

    impact = ticket.impact if impact is None else str(impact)
    urgency = ticket.urgency if urgency is None else str(urgency)
    calculated, requested = check_governed_priority(actor, impact=impact, urgency=urgency,
                                                    priority=priority, reason=reason,
                                                    overridden=bool(ticket.priority_overridden))
    reason = (reason or "").strip()
    previous_reason = ticket.priority_override_reason
    if requested != calculated:
        ticket.priority_overridden = True
        ticket.priority_override_reason = reason
        if reason != previous_reason and ticket.id:
            core.log_history(
                "ticket", ticket.id, "Priority override reason recorded", "priority override reason",
                previous_reason or "None", reason,
                details=f"{actor.name} overrode priority to {requested} (calculated: {calculated}) via {source}: {reason}",
            )
    else:
        if ticket.priority_overridden and ticket.id:
            core.log_history("ticket", ticket.id, "Priority override cleared", "priority override reason",
                             previous_reason or "None", "None", details=f"Cleared via {source}.")
        ticket.priority_overridden = False
        ticket.priority_override_reason = None
    previous_priority = ticket.priority
    ticket.impact, ticket.urgency, ticket.priority = impact, urgency, requested
    if ticket.id and requested != previous_priority:
        core.retarget_slas("ticket", ticket.id, requested, ticket.state)
    return requested
