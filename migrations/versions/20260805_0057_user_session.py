"""Add revocable browser-session inventory.

Revision ID: 20260805_0057
Revises: 20260805_0056
"""
from alembic import op
import sqlalchemy as sa

revision = "20260805_0057"
down_revision = "20260805_0056"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("user_session"):
        op.create_table(
            "user_session",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("session_id", sa.String(64), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("provider", sa.String(30), nullable=False, server_default="local"),
            sa.Column("ip_address", sa.String(64)),
            sa.Column("user_agent", sa.String(500)),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True)),
            sa.Column("revoked_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.UniqueConstraint("session_id", name="uq_user_session_session_id"),
        )
        op.create_index("ix_user_session_session_id", "user_session", ["session_id"])
        op.create_index("ix_user_session_user_id", "user_session", ["user_id"])
        op.create_index("ix_user_session_tenant_id", "user_session", ["tenant_id"])


def downgrade():
    op.drop_table("user_session")
