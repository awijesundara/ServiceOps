"""Add separately controlled, expiring AI action proposals.

Revision ID: 20260923_0099
Revises: 20260922_0098
"""
from alembic import op
import sqlalchemy as sa


revision = "20260923_0099"
down_revision = "20260922_0098"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "actions_enabled" not in {column["name"] for column in inspector.get_columns("ai_configuration")}:
        op.add_column("ai_configuration", sa.Column(
            "actions_enabled", sa.Boolean(), nullable=False, server_default=sa.false()
        ))
    if "ai_action" not in inspector.get_table_names():
        op.create_table(
            "ai_action",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.Integer(), nullable=False),
            sa.Column("run_id", sa.String(length=36), nullable=False),
            sa.Column("ticket_id", sa.Integer(), nullable=False),
            sa.Column("proposed_by_id", sa.Integer(), nullable=False),
            sa.Column("approved_by_id", sa.Integer(), nullable=True),
            sa.Column("actor_role", sa.String(length=30), nullable=False),
            sa.Column("action_type", sa.String(length=40), nullable=False),
            sa.Column("payload_json", sa.Text(), nullable=False),
            sa.Column("target_updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"]),
            sa.ForeignKeyConstraint(["run_id"], ["ai_run.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["ticket_id"], ["ticket.id"]),
            sa.ForeignKeyConstraint(["proposed_by_id"], ["user.id"]),
            sa.ForeignKeyConstraint(["approved_by_id"], ["user.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("run_id", "action_type", name="uq_ai_action_run_type"),
        )
        op.create_index("ix_ai_action_tenant_id", "ai_action", ["tenant_id"])
        op.create_index("ix_ai_action_run_id", "ai_action", ["run_id"])
        op.create_index("ix_ai_action_ticket_id", "ai_action", ["ticket_id"])
        op.create_index("ix_ai_action_status", "ai_action", ["status"])


def downgrade():
    count = op.get_bind().execute(sa.text("SELECT COUNT(*) FROM ai_action")).scalar()
    if count:
        raise RuntimeError("Refusing to drop AI action history. Remove the action records first.")
    op.drop_index("ix_ai_action_status", table_name="ai_action")
    op.drop_index("ix_ai_action_ticket_id", table_name="ai_action")
    op.drop_index("ix_ai_action_run_id", table_name="ai_action")
    op.drop_index("ix_ai_action_tenant_id", table_name="ai_action")
    op.drop_table("ai_action")
    op.drop_column("ai_configuration", "actions_enabled")
