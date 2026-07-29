"""Add api_rate_limit_window table backing per-client REST API rate limiting.

Revision ID: 20260729_0024
Revises: 20260729_0023
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0024"
down_revision = "20260729_0023"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if "api_rate_limit_window" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "api_rate_limit_window",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("api_client_id", sa.Integer(), sa.ForeignKey("api_client.id"), nullable=False),
            sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
            sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
            sa.UniqueConstraint("api_client_id", "window_start", name="uq_api_rate_limit_window"),
        )
        op.create_index(
            "ix_api_rate_limit_window_client", "api_rate_limit_window", ["api_client_id"]
        )


def downgrade():
    op.drop_index("ix_api_rate_limit_window_client", table_name="api_rate_limit_window")
    op.drop_table("api_rate_limit_window")
