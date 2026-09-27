"""Record incident categorisation at closure separately from logging.

Ticket.category/subcategory stay the categorisation recorded when the ticket
was logged. closure_category/closure_subcategory hold the categorisation at
closure, so reporting reflects the actual cause rather than the first guess;
resolution_notes documents how the service was restored; resolved_at is the
time the ticket last entered Resolved, replacing the created->updated_at
proxy analytics used for mean time to resolve (updated_at moves whenever a
resolved ticket is touched again).

resolved_at is backfilled from ticket history for tickets already Resolved or
Closed. Closure categorisation is left empty for historical tickets rather
than guessed; reporting falls back to the logging category where it's empty.

Revision ID: 20260927_0105
Revises: 20260926_0104
"""
from alembic import op
import sqlalchemy as sa

revision = "20260927_0105"
down_revision = "20260926_0104"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

NEW_COLUMNS = (
    ("closure_category", sa.String(80)),
    ("closure_subcategory", sa.String(80)),
    ("resolution_notes", sa.Text()),
    ("resolved_at", sa.DateTime(timezone=True)),
)


def upgrade():
    bind = op.get_bind()
    existing = {column["name"] for column in sa.inspect(bind).get_columns("ticket")}
    for name, column_type in NEW_COLUMNS:
        if name not in existing:
            op.add_column("ticket", sa.Column(name, column_type))
    # Latest entry into Resolved; Closed only for tickets that were closed
    # without passing through Resolved.
    bind.execute(sa.text("""
        UPDATE ticket SET resolved_at = COALESCE(
            (SELECT MAX(h.created_at) FROM task_history h
             WHERE h.target_type = 'ticket' AND h.target_id = ticket.id
               AND h.field_name = 'state' AND h.new_value = 'Resolved'),
            (SELECT MAX(h.created_at) FROM task_history h
             WHERE h.target_type = 'ticket' AND h.target_id = ticket.id
               AND h.field_name = 'state' AND h.new_value = 'Closed')
        )
        WHERE ticket.state IN ('Resolved', 'Closed') AND ticket.resolved_at IS NULL
    """))


def downgrade():
    for name, _column_type in reversed(NEW_COLUMNS):
        op.drop_column("ticket", name)
