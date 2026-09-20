"""Persist administrator-discovered model limits without changing existing enablement.

Revision ID: 20260921_0097
Revises: 20260921_0096
"""
from alembic import op
import sqlalchemy as sa

revision = "20260921_0097"
down_revision = "20260921_0096"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    if "capabilities_json" not in {c["name"] for c in sa.inspect(op.get_bind()).get_columns("ai_configuration")}:
        op.add_column("ai_configuration", sa.Column("capabilities_json", sa.Text(), nullable=False, server_default="{}"))


def downgrade():
    # Configuration remains intact; only derived, re-discoverable metadata is removed.
    with op.batch_alter_table("ai_configuration") as batch:
        batch.drop_column("capabilities_json")
