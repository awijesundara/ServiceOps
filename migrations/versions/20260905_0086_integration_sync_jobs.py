"""Add durable cancellable integration sync jobs.

Revision ID: 20260905_0086
Revises: 20260904_0085
"""
from alembic import op
import sqlalchemy as sa

revision = "20260905_0086"
down_revision = "20260904_0085"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if "integration_sync_job" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "integration_sync_job",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("integration", sa.String(30), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(20), nullable=False, server_default="Pending"),
        sa.Column("phase", sa.String(120), nullable=False, server_default="Queued"),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total", sa.Integer()),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("result_json", sa.Text()),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_integration_sync_job_tenant_id", "integration_sync_job", ["tenant_id"])
    op.create_index("ix_integration_sync_job_integration", "integration_sync_job", ["integration"])
    op.create_index("ix_integration_sync_job_status", "integration_sync_job", ["status"])


def downgrade():
    bind = op.get_bind()
    if "integration_sync_job" in sa.inspect(bind).get_table_names():
        op.drop_table("integration_sync_job")
