"""Backfill an initial Implementation CTASK for changes created before auto-seeding existed.

Change creation seeds a first CTASK from the change's implementation/test/backout
plan, but that logic post-dates several already-deployed changes, which are
left with an approved plan and zero visible tasks. This creates exactly one
"Implementation" CTASK for any change_governance row with no operational_task
rows at all, using its own plan text and owning team, so no data is invented -
only wiring an existing plan into a task record.

Revision ID: 20260729_0019
Revises: 20260729_0018
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0019"
down_revision = "20260729_0018"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    missing = bind.execute(sa.text("""
        SELECT cg.id, cg.ticket_id, cg.implementation_plan, cg.test_plan, cg.backout_plan,
               cg.planned_start, cg.planned_end, co.group_id, t.number
        FROM change_governance cg
        JOIN ticket t ON t.id = cg.ticket_id
        LEFT JOIN change_ownership co ON co.ticket_id = cg.ticket_id
        WHERE NOT EXISTS (
            SELECT 1 FROM operational_task ot
            WHERE ot.parent_type = 'ticket' AND ot.parent_id = cg.ticket_id
              AND ot.task_kind = 'change'
        )
    """)).fetchall()
    for row in missing:
        if not row.group_id:
            continue
        notes = "\n\n".join(filter(None, [
            f"Implementation plan:\n{row.implementation_plan}" if row.implementation_plan else "",
            f"Test plan:\n{row.test_plan}" if row.test_plan else "",
            f"Backout plan:\n{row.backout_plan}" if row.backout_plan else "",
        ]))
        inserted = bind.execute(sa.text("""
            INSERT INTO operational_task
                (number, task_kind, parent_type, parent_id, title, task_type, state,
                 required, sequence, assignment_group_id, planned_start, planned_end,
                 work_notes, created_at, updated_at)
            VALUES
                (:number, 'change', 'ticket', :ticket_id, 'Implementation', 'Implementation', 'Open',
                 true, 1, :group_id, :planned_start, :planned_end,
                 :notes, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING id
        """), {
            "number": f"CTASK-BACKFILL-{row.ticket_id}",
            "ticket_id": row.ticket_id, "group_id": row.group_id,
            "planned_start": row.planned_start, "planned_end": row.planned_end,
            "notes": notes,
        }).fetchone()
        task_id = inserted[0]
        bind.execute(sa.text(
            "UPDATE operational_task SET number = :number WHERE id = :id"
        ), {"number": f"CTASK{task_id:07d}", "id": task_id})
        bind.execute(sa.text("""
            INSERT INTO task_history (target_type, target_id, event, details, created_at)
            VALUES ('ticket', :ticket_id, 'Change task created',
                    :details, CURRENT_TIMESTAMP)
        """), {
            "ticket_id": row.ticket_id,
            "details": f"CTASK{task_id:07d} Implementation: backfilled from the change's existing plan ({row.number}).",
        })


def downgrade():
    op.execute("""
        DELETE FROM operational_task
        WHERE id IN (
            SELECT ot.id FROM operational_task ot
            JOIN task_history th
                ON th.target_type = 'ticket' AND th.target_id = ot.parent_id
            WHERE ot.task_kind = 'change'
              AND th.event = 'Change task created'
              AND th.details LIKE '%backfilled from the change%'
              AND th.details LIKE '%' || ot.number || '%'
        )
    """)
    op.execute("""
        DELETE FROM task_history
        WHERE event = 'Change task created' AND details LIKE '%backfilled from the change%'
    """)
