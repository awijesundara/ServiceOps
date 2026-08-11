"""Client Management phase 6: ClientTrigger (condition -> action automation
rules for customer tickets).

Revision ID: 20260811_0072
Revises: 20260811_0071
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0072"
down_revision = "20260811_0071"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("client_trigger"):
        op.create_table(
            "client_trigger",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("event", sa.String(30), nullable=False),
            sa.Column("condition_field", sa.String(30), nullable=False),
            sa.Column("condition_op", sa.String(20), nullable=False),
            sa.Column("condition_value", sa.String(200), nullable=False, server_default=""),
            sa.Column("action_type", sa.String(30), nullable=False),
            sa.Column("action_value", sa.String(500), nullable=False, server_default=""),
            sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "name", name="uq_client_trigger_tenant_name"),
        )
        op.create_index("ix_client_trigger_tenant_id", "client_trigger", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("client_trigger"):
        op.drop_table("client_trigger")
