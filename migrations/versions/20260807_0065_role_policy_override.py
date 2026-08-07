"""Add role_policy_override for admin-editable role->action grants.

Revision ID: 20260807_0065
Revises: 20260807_0064
"""
from alembic import op
import sqlalchemy as sa

revision = "20260807_0065"
down_revision = "20260807_0064"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    # 20260726_0001 (the baseline migration) creates every table present in
    # the current ORM metadata on a fresh database, so this table already
    # exists there by the time this migration runs; on a DB that predates
    # this change, it doesn't. Guard the same way every other post-baseline
    # migration that adds a table already does (e.g. 20260807_0064).
    if not inspector.has_table("role_policy_override"):
        op.create_table(
            "role_policy_override",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("role", sa.String(20), nullable=False),
            sa.Column("action", sa.String(40), nullable=False),
            sa.Column("is_granted", sa.Boolean(), nullable=False),
            sa.Column("updated_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "role", "action", name="uq_role_policy_override_tenant_role_action"),
        )
        op.create_index("ix_role_policy_override_tenant_id", "role_policy_override", ["tenant_id"])


def downgrade():
    op.drop_table("role_policy_override")
