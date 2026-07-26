"""Add durable integration outbox and monitoring ingestion.

Revision ID: 20260726_0005
Revises: 20260726_0004
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0005"
down_revision = "20260726_0004"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "integration_connection" not in tables:
        op.create_table(
            "integration_connection",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("kind", sa.String(30), nullable=False),
            sa.Column("endpoint", sa.String(500), nullable=False),
            sa.Column("secret_encrypted", sa.Text()),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_integration_connection_tenant_id", "integration_connection", ["tenant_id"])
    if "outbox_event" not in tables:
        op.create_table(
            "outbox_event",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("event_id", sa.String(36), nullable=False, unique=True),
            sa.Column("event_type", sa.String(120), nullable=False),
            sa.Column("payload_json", sa.Text(), nullable=False),
            sa.Column("state", sa.String(30), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_error", sa.Text()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True)),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_outbox_event_event_type", "outbox_event", ["event_type"])
        op.create_index("ix_outbox_event_state", "outbox_event", ["state"])
        op.create_index("ix_outbox_event_tenant_id", "outbox_event", ["tenant_id"])
    if "integration_delivery" not in tables:
        op.create_table(
            "integration_delivery",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("outbox_event_id", sa.Integer(), sa.ForeignKey("outbox_event.id"), nullable=False),
            sa.Column("connection_id", sa.Integer(), sa.ForeignKey("integration_connection.id")),
            sa.Column("channel", sa.String(30), nullable=False),
            sa.Column("state", sa.String(30), nullable=False),
            sa.Column("status_code", sa.Integer()),
            sa.Column("error", sa.Text()),
            sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_integration_delivery_tenant_id", "integration_delivery", ["tenant_id"])
    if "monitoring_source" not in tables:
        op.create_table(
            "monitoring_source",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("source_id", sa.String(36), nullable=False, unique=True),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("token_prefix", sa.String(16), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("assignment_group_id", sa.Integer(), sa.ForeignKey("support_group.id"), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True)),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_monitoring_source_tenant_id", "monitoring_source", ["tenant_id"])
    if "monitoring_event" not in tables:
        op.create_table(
            "monitoring_event",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("monitoring_source_id", sa.Integer(), sa.ForeignKey("monitoring_source.id"), nullable=False),
            sa.Column("external_id", sa.String(200), nullable=False),
            sa.Column("severity", sa.String(20), nullable=False),
            sa.Column("resource", sa.String(255), nullable=False),
            sa.Column("summary", sa.String(500), nullable=False),
            sa.Column("payload_json", sa.Text(), nullable=False),
            sa.Column("enterprise_record_id", sa.Integer(), sa.ForeignKey("enterprise_record.id"), nullable=False),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("monitoring_source_id", "external_id", name="uq_monitoring_source_external_event"),
        )
        op.create_index("ix_monitoring_event_tenant_id", "monitoring_event", ["tenant_id"])


def downgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for name in (
        "monitoring_event", "monitoring_source", "integration_delivery",
        "outbox_event", "integration_connection",
    ):
        if name in tables:
            op.drop_table(name)
