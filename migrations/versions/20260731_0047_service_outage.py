"""ITIL 4 availability management: ServiceOutage tracks downtime windows so
an uptime % is computable at all -- previously nothing in the system
recorded outage history. Rows are auto-derived from High/Critical impact
incidents by sync_service_outages(), not manually logged.

Revision ID: 20260731_0047
Revises: 20260731_0046
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0047"
down_revision = "20260731_0046"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "service_outage" in inspector.get_table_names():
        return
    op.create_table(
        "service_outage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("service_offering_id", sa.Integer(), sa.ForeignKey("service_offering.id"), nullable=False),
        sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("ticket.id"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
    )
    op.create_index("ix_service_outage_service_offering_id", "service_outage", ["service_offering_id"])
    op.create_index("ix_service_outage_tenant_id", "service_outage", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "service_outage" in inspector.get_table_names():
        op.drop_table("service_outage")
