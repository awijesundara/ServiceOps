"""Work left behind by finished records is tidied up.

Cancelling, rejecting, deleting or closing a change, incident or problem left
its unfinished tasks open: they stayed in My work and their teams could not
remove them. A rejection also left the other approvers asked to decide, kept
the record's SLA running, and kept a rejected catalog item's REQ open. The
application now handles all of this; this repairs what was already left
behind and notes cancelled tasks in each record's history. Data only.

Revision ID: 20261021_0141
Revises: 20261020_0140
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "20261021_0141"
down_revision = "20261020_0140"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

OPEN_TASK = "t.state NOT IN ('Closed Complete', 'Closed Incomplete', 'Closed Skipped', 'Cancelled')"
ORPHANED = (
    "SELECT t.id, t.number, t.parent_type, t.parent_id, p.number FROM operational_task t "
    "JOIN ticket p ON t.parent_type = 'ticket' AND p.id = t.parent_id "
    f"WHERE {OPEN_TASK} AND (p.state IN ('Cancelled', 'Rejected', 'Closed') OR p.deleted_at IS NOT NULL) "
    "UNION ALL "
    "SELECT t.id, t.number, t.parent_type, t.parent_id, p.number FROM operational_task t "
    "JOIN enterprise_record p ON t.parent_type = 'enterprise' AND p.id = t.parent_id "
    f"WHERE {OPEN_TASK} AND p.state IN ('Closed', 'Rejected')"
)


def upgrade():
    bind = op.get_bind()
    rows = bind.execute(sa.text(ORPHANED)).fetchall()
    by_parent = {}
    for task_id, number, parent_type, parent_id, parent_number in rows:
        bind.execute(sa.text("UPDATE operational_task SET state = 'Cancelled' WHERE id = :id"), {"id": task_id})
        by_parent.setdefault((parent_type, parent_id, parent_number), []).append(number)
    stamp = datetime.now(timezone.utc)
    for (parent_type, parent_id, parent_number), numbers in by_parent.items():
        bind.execute(sa.text(
            "INSERT INTO task_history (target_type, target_id, event, old_value, new_value, details, created_at) "
            "VALUES (:type, :id, 'Tasks cancelled', '', '', :details, :at)"),
            {"type": parent_type, "id": parent_id, "at": stamp,
             "details": f"{parent_number} had already ended; its open tasks were cancelled: {', '.join(numbers)}"})

    # Decided or cancelled approvals no longer ask anyone.
    bind.execute(sa.text(
        "UPDATE approval_vote SET state = 'No Longer Required' WHERE state IN ('Requested', 'Not Requested') "
        "AND gate_id IN (SELECT g.id FROM approval_gate g JOIN approval_chain c ON c.id = g.chain_id "
        "WHERE c.state <> 'Running')"))
    bind.execute(sa.text(
        "UPDATE approval_gate SET state = 'Cancelled' WHERE state IN ('Pending', 'Requested') "
        "AND chain_id IN (SELECT id FROM approval_chain WHERE state <> 'Running')"))

    # SLAs stop on records that were rejected, cancelled or closed incomplete.
    for target_type, table in (("ticket", "ticket"), ("ritm", "requested_item")):
        bind.execute(sa.text(
            "UPDATE task_sla SET stage = 'Cancelled', stopped_at = :at "
            "WHERE target_type = :type AND stage IN ('In Progress', 'Paused') "
            f"AND target_id IN (SELECT id FROM {table} WHERE state IN ('Rejected', 'Cancelled'))"),
            {"at": stamp, "type": target_type})
    bind.execute(sa.text(
        "UPDATE task_sla SET stage = 'Completed', stopped_at = :at "
        "WHERE target_type = 'ritm' AND stage IN ('In Progress', 'Paused') "
        "AND target_id IN (SELECT id FROM requested_item WHERE state IN ('Closed Incomplete', 'Closed Skipped'))"),
        {"at": stamp})

    # A REQ whose items have all finished is closed, as the application does.
    terminal = ("Closed Complete", "Closed Incomplete", "Closed Skipped", "Rejected", "Cancelled")
    open_requests = bind.execute(sa.text(
        "SELECT id FROM catalog_request WHERE state NOT IN ('Closed Complete', 'Closed Incomplete', 'Cancelled')"
    )).fetchall()
    for (request_id,) in open_requests:
        states = [row[0] for row in bind.execute(sa.text(
            "SELECT state FROM requested_item WHERE request_id = :id"), {"id": request_id})]
        if not states or any(state not in terminal for state in states):
            continue
        if all(state == "Cancelled" for state in states):
            final = "Cancelled"
        elif all(state in ("Closed Complete", "Cancelled") for state in states):
            final = "Closed Complete"
        else:
            final = "Closed Incomplete"
        bind.execute(sa.text(
            "UPDATE catalog_request SET state = :state, closed_at = COALESCE(closed_at, :at) WHERE id = :id"),
            {"state": final, "at": stamp, "id": request_id})


def downgrade():
    # Which tasks were open before cannot be told apart from ones cancelled by
    # hand, so the repair is kept.
    pass
