"""Pure ticket/task state-machine tables and lookup logic -- no Flask or
database dependency, matching the bounded-interface pattern already
established by serviceops_core.security. The actual transition *guards*
(approval-chain checks, workflow event emission, ORM writes) stay in
app.py's transition_*() functions since those inherently need the
database; only the declarative "what states can X move to" data and its
lookup helper live here.
"""

TICKET_TRANSITIONS = {
    "New": ("New", "In Progress", "Pending", "Resolved", "Cancelled"),
    "In Progress": ("In Progress", "Pending", "Resolved", "Cancelled"),
    "Pending": ("Pending", "In Progress", "Resolved", "Cancelled"),
    "Resolved": ("Resolved", "In Progress", "Closed"),
    "Closed": ("Closed",),
    "Cancelled": ("Cancelled",),
    "Approved": ("Approved", "In Progress", "Cancelled"),
    "Awaiting Approval": ("Awaiting Approval", "Cancelled"),
    "Rejected": ("Rejected",),
}

ENTERPRISE_TRANSITIONS = {
    "New": ("New", "Open", "In Progress", "Pending", "Resolved", "Completed", "Closed"),
    "Open": ("Open", "In Progress", "Pending", "Resolved", "Completed", "Closed"),
    "In Progress": ("In Progress", "Pending", "Resolved", "Completed", "Closed"),
    "Pending": ("Pending", "In Progress", "Resolved", "Completed", "Closed"),
    "Resolved": ("Resolved", "In Progress", "Closed"),
    "Completed": ("Completed", "Closed"),
    "Closed": ("Closed",),
    "Approved": ("Approved", "In Progress", "Pending", "Completed", "Closed"),
    "Awaiting Approval": ("Awaiting Approval",),
    "Rejected": ("Rejected",),
}

CATALOG_TASK_TRANSITIONS = {
    "Open": ("Open", "Work in Progress", "Pending", "Closed Incomplete", "Closed Skipped"),
    "Work in Progress": ("Work in Progress", "Pending", "Closed Complete", "Closed Incomplete", "Closed Skipped"),
    "Pending": ("Pending", "Work in Progress", "Closed Complete", "Closed Incomplete", "Closed Skipped"),
    "Closed Complete": ("Closed Complete",),
    "Closed Incomplete": ("Closed Incomplete",),
    "Closed Skipped": ("Closed Skipped",),
}

OPERATIONAL_TASK_TRANSITIONS = {
    "Open": ("Open", "Work in Progress", "Pending", "Closed Complete", "Closed Incomplete", "Cancelled"),
    "Work in Progress": ("Work in Progress", "Pending", "Closed Complete", "Closed Incomplete", "Cancelled"),
    "Pending": ("Pending", "Work in Progress", "Closed Complete", "Closed Incomplete", "Cancelled"),
    "Closed Complete": ("Closed Complete",),
    "Closed Incomplete": ("Closed Incomplete",),
    "Cancelled": ("Cancelled",),
}

STATE_TRACK_ORDER = {
    "incident": ["New", "In Progress", "Pending", "Resolved", "Closed"],
    "request": ["New", "In Progress", "Pending", "Resolved", "Closed"],
    "change": ["New", "Awaiting Approval", "Approved", "In Progress", "Pending", "Resolved", "Closed"],
    "problem": ["New", "Open", "In Progress", "Pending", "Resolved", "Completed", "Closed"],
    "ritm": ["Awaiting Approval", "Open", "Closed Complete"],
    "catalog_task": ["Open", "Work in Progress", "Pending", "Closed Complete"],
}


def allowed_states(transition_table, current_state):
    """The shared `.get(state, (state,))` lookup pattern used at every
    transition-table call site: an unrecognized current_state is treated
    as a terminal state of one (itself), rather than raising -- a record
    somehow left in an unmapped state can still be read/displayed, just
    never transitioned anywhere new until corrected.
    """
    return transition_table.get(current_state, (current_state,))


def build_state_track(kind, current_state):
    """Ordered lifecycle steps for the visual stepper, with each step
    marked done/current/upcoming relative to current_state. A
    current_state not present in the kind's own order (e.g. legacy data)
    still renders: the whole known order as upcoming, plus the actual
    current_state appended as the current step, rather than raising or
    silently misrepresenting where the record actually is.
    """
    order = STATE_TRACK_ORDER.get(kind, STATE_TRACK_ORDER["incident"])
    if current_state not in order:
        return [{"name": step, "status": "upcoming"} for step in order] + [
            {"name": current_state, "status": "current"}
        ]
    idx = order.index(current_state)
    return [
        {"name": step, "status": "done" if i < idx else ("current" if i == idx else "upcoming")}
        for i, step in enumerate(order)
    ]
