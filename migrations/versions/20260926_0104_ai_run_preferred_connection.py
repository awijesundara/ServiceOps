"""Let a chat message carry the user's preferred AI connection.

A soft preference only, read by routing.plan() to reorder an already
privacy-gated candidate list -- see serviceops_core/ai/routing.py. No FK,
matching the existing ai_run.connection_id column, since a connection can be
renamed or deleted independently of run history.

Revision ID: 20260926_0104
Revises: 20260926_0103
"""
from alembic import op
import sqlalchemy as sa

revision = "20260926_0104"
down_revision = "20260926_0103"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ai_run")}
    if "preferred_connection_id" not in columns:
        op.add_column("ai_run", sa.Column("preferred_connection_id", sa.String(36)))


def downgrade():
    op.drop_column("ai_run", "preferred_connection_id")
