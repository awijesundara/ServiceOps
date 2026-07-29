"""Add soft-delete fields to ticket for pre-progress change deletion.

Revision ID: 20260729_0020
Revises: 20260729_0019
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0020"
down_revision = "20260729_0019"
branch_labels = None
depends_on = None


def _add_missing(table, definitions):
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns(table)}
    with op.batch_alter_table(table) as batch:
        for name, column in definitions:
            if name not in columns:
                batch.add_column(column)


def upgrade():
    _add_missing("ticket", [
        ("deleted_at", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True)),
        ("deleted_by_id", sa.Column("deleted_by_id", sa.Integer(), nullable=True)),
    ])


def downgrade():
    with op.batch_alter_table("ticket") as batch:
        for name in ["deleted_by_id", "deleted_at"]:
            batch.drop_column(name)
