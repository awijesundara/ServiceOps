"""Add tenant-aware recurring workflow schedules.

Revision ID: 20260726_0009
Revises: 20260726_0008
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0009"
down_revision = "20260726_0008"
branch_labels = None
depends_on = None


def upgrade():
    if "workflow_schedule" not in set(sa.inspect(op.get_bind()).get_table_names()):
        op.create_table(
            "workflow_schedule",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("schedule_key", sa.String(120), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("ticket.id"), nullable=False),
            sa.Column("interval_minutes", sa.Integer(), nullable=False),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_run_at", sa.DateTime(timezone=True)),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("tenant_id", "schedule_key", name="uq_workflow_schedule_key"),
        )
        op.create_index("ix_workflow_schedule_next_run_at", "workflow_schedule", ["next_run_at"])
        op.create_index("ix_workflow_schedule_tenant_id", "workflow_schedule", ["tenant_id"])


def downgrade():
    if "workflow_schedule" in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table("workflow_schedule")
