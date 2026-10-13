"""Browser Web Push subscriptions (desktop notifications with the tab closed).

Revision ID: 20261013_0122
Revises: 20261012_0121
"""
from alembic import op
import sqlalchemy as sa

revision = "20261013_0122"
down_revision = "20261012_0121"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    if "web_push_subscription" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "web_push_subscription",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("endpoint", sa.Text(), nullable=False),
        sa.Column("endpoint_hash", sa.String(64), nullable=False),
        sa.Column("keys_encrypted", sa.Text(), nullable=False),
        sa.Column("user_agent", sa.String(200), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
    )
    op.create_index("ix_web_push_subscription_endpoint_hash", "web_push_subscription", ["endpoint_hash"], unique=True)
    op.create_index("ix_web_push_subscription_user_id", "web_push_subscription", ["user_id"])
    op.create_index("ix_web_push_subscription_tenant_id", "web_push_subscription", ["tenant_id"])


def downgrade():
    op.drop_table("web_push_subscription")
