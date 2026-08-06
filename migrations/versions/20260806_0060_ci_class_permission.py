"""Add ci_class_permission for per-CI-class CMDB read-visibility grants.

Revision ID: 20260806_0060
Revises: 20260805_0059
"""
from alembic import op
import sqlalchemy as sa

revision = "20260806_0060"
down_revision = "20260805_0059"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("ci_class_permission"):
        op.create_table(
            "ci_class_permission",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("ci_class", sa.String(80), nullable=False),
            sa.Column("role", sa.String(20), nullable=False),
            sa.Column("can_read", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("updated_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("tenant_id", "ci_class", "role", name="uq_ci_class_permission_tenant_class_role"),
        )
        op.create_index("ix_ci_class_permission_tenant_id", "ci_class_permission", ["tenant_id"])


def downgrade():
    op.drop_table("ci_class_permission")
