"""Add manager_id to user for the organization chart.

Revision ID: 20260729_0021
Revises: 20260729_0020
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0021"
down_revision = "20260729_0020"
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
    _add_missing("user", [
        ("manager_id", sa.Column("manager_id", sa.Integer(), nullable=True)),
    ])


def downgrade():
    with op.batch_alter_table("user") as batch:
        batch.drop_column("manager_id")
