"""Add durable workflow waits and step evidence.

Revision ID: 20260726_0008
Revises: 20260726_0007
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0008"
down_revision = "20260726_0007"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("workflow_execution")}
    with op.batch_alter_table("workflow_execution") as batch:
        if "next_action_index" not in columns:
            batch.add_column(sa.Column("next_action_index", sa.Integer(), nullable=False, server_default="0"))
        if "resume_at" not in columns:
            batch.add_column(sa.Column("resume_at", sa.DateTime(timezone=True)))
    if "workflow_step_execution" not in set(sa.inspect(bind).get_table_names()):
        op.create_table(
            "workflow_step_execution",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("execution_id", sa.Integer(), sa.ForeignKey("workflow_execution.id"), nullable=False),
            sa.Column("action_index", sa.Integer(), nullable=False),
            sa.Column("action_type", sa.String(40), nullable=False),
            sa.Column("state", sa.String(20), nullable=False),
            sa.Column("input_json", sa.Text(), nullable=False),
            sa.Column("output_json", sa.Text(), nullable=False),
            sa.Column("error", sa.Text()),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True)),
            sa.Column("compensation_state", sa.String(20)),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("execution_id", "action_index", name="uq_workflow_execution_action"),
        )
        op.create_index("ix_workflow_step_execution_tenant_id", "workflow_step_execution", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    if "workflow_step_execution" in set(sa.inspect(bind).get_table_names()):
        op.drop_table("workflow_step_execution")
    columns = {c["name"] for c in sa.inspect(bind).get_columns("workflow_execution")}
    with op.batch_alter_table("workflow_execution") as batch:
        for column in ("resume_at", "next_action_index"):
            if column in columns:
                batch.drop_column(column)
