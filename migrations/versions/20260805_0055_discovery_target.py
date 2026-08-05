"""Add discovery_target (agentless SNMP CMDB discovery -- see
serviceops_core/network_discovery.py and DiscoveryTarget in app.py).

Revision ID: 20260805_0055
Revises: 20260805_0054
"""
from alembic import op
import sqlalchemy as sa

revision = "20260805_0055"
down_revision = "20260805_0054"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("discovery_target"):
        op.create_table(
            "discovery_target",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("target_type", sa.String(length=10), nullable=False, server_default="host"),
            sa.Column("address", sa.String(length=80), nullable=False),
            sa.Column("snmp_version", sa.String(length=4), nullable=False, server_default="2c"),
            sa.Column("snmp_port", sa.Integer(), nullable=False, server_default="161"),
            sa.Column("community_encrypted", sa.Text()),
            sa.Column("schedule_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("schedule_interval_minutes", sa.Integer(), nullable=False, server_default="1440"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("last_run_at", sa.DateTime(timezone=True)),
            sa.Column("last_run_status", sa.String(length=20)),
            sa.Column("last_run_summary", sa.Text()),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_discovery_target_tenant_id", "discovery_target", ["tenant_id"])


def downgrade():
    op.drop_index("ix_discovery_target_tenant_id", table_name="discovery_target")
    op.drop_table("discovery_target")
