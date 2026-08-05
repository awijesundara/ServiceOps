"""Add DB-backed request metrics and periodic performance samples.

Revision ID: 20260805_0059
Revises: 20260805_0058
"""
from alembic import op
import sqlalchemy as sa

revision = "20260805_0059"
down_revision = "20260805_0058"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("request_metric_total"):
        op.create_table(
            "request_metric_total",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("method", sa.String(10), nullable=False),
            sa.Column("status", sa.String(10), nullable=False),
            sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("duration_sum_ms", sa.Float(), nullable=False, server_default="0"),
            sa.UniqueConstraint("method", "status", name="uq_request_metric_total_method_status"),
        )
    if not inspector.has_table("performance_sample"):
        op.create_table(
            "performance_sample",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("sampled_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("cumulative_requests", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("cumulative_errors", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("cumulative_duration_ms", sa.Float(), nullable=False, server_default="0"),
            sa.Column("worker_healthy", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("deployment_mode", sa.String(30), nullable=False, server_default="unknown"),
        )
        op.create_index("ix_performance_sample_sampled_at", "performance_sample", ["sampled_at"])


def downgrade():
    op.drop_table("performance_sample")
    op.drop_table("request_metric_total")
