"""Add encrypted provider-specific notification configuration.

Revision ID: 20260910_0088
Revises: 20260910_0087
"""
from alembic import op
import sqlalchemy as sa

revision = "20260910_0088"
down_revision = "20260910_0087"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns("integration_connection")
    }
    if "configuration_encrypted" not in columns:
        op.add_column(
            "integration_connection", sa.Column("configuration_encrypted", sa.Text())
        )


def downgrade():
    # Expand/contract policy: retain encrypted configuration during rollback.
    pass
