"""Support configurable multiple-executive approval quorum.

Revision ID: 20261003_0111
Revises: 20261003_0110
"""
from alembic import op
import sqlalchemy as sa

revision = "20261003_0111"
down_revision = "20261003_0110"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("support_group")}
    if "approval_mode" not in columns:
        op.add_column("support_group", sa.Column("approval_mode", sa.String(3), nullable=False, server_default="all"))


def downgrade():
    with op.batch_alter_table("support_group") as batch:
        batch.drop_column("approval_mode")
