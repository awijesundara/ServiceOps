"""Add archived/superseded_by_id to knowledge so articles archive+version instead of deleting.

Revision ID: 20260728_0014
Revises: 20260727_0013
"""
from alembic import op
import sqlalchemy as sa

revision = "20260728_0014"
down_revision = "20260727_0013"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("knowledge")}
    with op.batch_alter_table("knowledge") as batch:
        if "archived" not in columns:
            batch.add_column(sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()))
        if "superseded_by_id" not in columns:
            # Plain integer, not a DB-level foreign key -- matches the existing
            # target_type/target_id precedent on notification (20260727_0013):
            # self-referential FK constraints hit SQLite batch-mode limitations
            # in the migration-rehearsal/test suite, and the relationship is
            # already enforced at the application layer.
            batch.add_column(sa.Column("superseded_by_id", sa.Integer()))


def downgrade():
    with op.batch_alter_table("knowledge") as batch:
        batch.drop_column("superseded_by_id")
        batch.drop_column("archived")
