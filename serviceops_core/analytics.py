"""Overdue-investigations reporting, extracted out of app.py's /analytics
routes (item #13's app.py decomposition -- the sibling /analytics route
itself is a much larger, more deeply interlinked computation and was left
in place rather than mechanically relocated at real risk of a subtle
behavior change with no automated way to diff it; this is the bounded,
low-risk slice of that pair). Pure data-computation: no route decorator,
no template rendering, no `current_user`/`request` access -- the caller
passes in exactly what it needs, matching the DB-model-only import style
`ci_class_policy.py`/`workflow.py` already use.
"""

OVERDUE_RECORDS_LIMIT = 2000


def overdue_enterprise_records(enterprise_record_model, visible_record_ids, now_fn):
    """Overdue (past due_at, not yet closed) records the caller is allowed to
    see, oldest-due-first, capped at OVERDUE_RECORDS_LIMIT so a tenant with
    an unusually large overdue backlog can't pull every matching row into
    memory in one request. Returns (rows, truncated)."""
    query = enterprise_record_model.query.filter(
        enterprise_record_model.id.in_(visible_record_ids),
        enterprise_record_model.due_at < now_fn(),
        enterprise_record_model.state.notin_(["Closed", "Resolved", "Completed"]),
    ).order_by(enterprise_record_model.due_at)
    rows = query.limit(OVERDUE_RECORDS_LIMIT + 1).all()
    truncated = len(rows) > OVERDUE_RECORDS_LIMIT
    return rows[:OVERDUE_RECORDS_LIMIT], truncated
