"""Add single-use password-reset tokens.

Revision ID: 20260805_0058
Revises: 20260805_0057
"""
from alembic import op
import sqlalchemy as sa

revision = "20260805_0058"
down_revision = "20260805_0057"
branch_labels = None
depends_on = None


def upgrade():
    if not sa.inspect(op.get_bind()).has_table("password_reset_token"):
        op.create_table(
            "password_reset_token",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True)),
            sa.Column("requested_ip", sa.String(64)),
        )
        op.create_index("ix_password_reset_token_token_hash", "password_reset_token", ["token_hash"])
        op.create_index("ix_password_reset_token_user_id", "password_reset_token", ["user_id"])
        op.create_index("ix_password_reset_token_tenant_id", "password_reset_token", ["tenant_id"])


def downgrade():
    op.drop_table("password_reset_token")
