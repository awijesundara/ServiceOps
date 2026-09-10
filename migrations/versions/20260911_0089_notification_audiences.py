"""Add explicit user, support-group, and tenant notification audiences.

Revision ID: 20260911_0089
Revises: 20260910_0088
"""
from alembic import op
import sqlalchemy as sa

revision = "20260911_0089"
down_revision = "20260910_0088"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("integration_connection")}
    if "scope_type" not in columns:
        op.add_column("integration_connection", sa.Column("scope_type", sa.String(20), nullable=False, server_default="tenant"))
        op.add_column("integration_connection", sa.Column("owner_user_id", sa.Integer(), nullable=True))
        op.add_column("integration_connection", sa.Column("support_group_id", sa.Integer(), nullable=True))
        op.create_foreign_key("fk_integration_connection_owner_user", "integration_connection", "user", ["owner_user_id"], ["id"])
        op.create_foreign_key("fk_integration_connection_support_group", "integration_connection", "support_group", ["support_group_id"], ["id"])
        op.create_index("ix_integration_connection_scope_type", "integration_connection", ["scope_type"])
        op.create_index("ix_integration_connection_owner_user_id", "integration_connection", ["owner_user_id"])
        op.create_index("ix_integration_connection_support_group_id", "integration_connection", ["support_group_id"])
        op.create_check_constraint(
            "ck_integration_connection_scope_owner", "integration_connection",
            "(scope_type = 'tenant' AND owner_user_id IS NULL AND support_group_id IS NULL) OR "
            "(scope_type = 'user' AND owner_user_id IS NOT NULL AND support_group_id IS NULL) OR "
            "(scope_type = 'group' AND owner_user_id IS NULL AND support_group_id IS NOT NULL)",
        )


def downgrade():
    # Audience ownership is security-relevant and intentionally retained.
    pass
