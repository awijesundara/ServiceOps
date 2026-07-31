"""ITIL 4 gap-analysis P2 remediation: SLA agreement type (SLA/OLA/UC),
ticket CSAT fields, and the KPI snapshot history tables.

Revision ID: 20260731_0044
Revises: 20260731_0043
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0044"
down_revision = "20260731_0043"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "sla_definition" in existing:
        columns = {c["name"] for c in inspector.get_columns("sla_definition")}
        with op.batch_alter_table("sla_definition") as batch_op:
            if "agreement_type" not in columns:
                batch_op.add_column(
                    sa.Column("agreement_type", sa.String(length=10), nullable=False, server_default="SLA")
                )
            if "counterparty" not in columns:
                batch_op.add_column(sa.Column("counterparty", sa.String(length=160), nullable=True))

    if "ticket" in existing:
        columns = {c["name"] for c in inspector.get_columns("ticket")}
        with op.batch_alter_table("ticket") as batch_op:
            if "csat_rating" not in columns:
                batch_op.add_column(sa.Column("csat_rating", sa.Integer(), nullable=True))
            if "csat_comment" not in columns:
                batch_op.add_column(sa.Column("csat_comment", sa.Text(), nullable=True))
            if "csat_submitted_at" not in columns:
                batch_op.add_column(sa.Column("csat_submitted_at", sa.DateTime(timezone=True), nullable=True))

    if "kpi_snapshot" not in existing:
        op.create_table(
            "kpi_snapshot",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("snapshot_date", sa.Date(), nullable=False),
            sa.Column("metric_name", sa.String(length=40), nullable=False),
            sa.Column("metric_value", sa.Float(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "snapshot_date", "metric_name", name="uq_kpi_snapshot"),
        )
        op.create_index("ix_kpi_snapshot_tenant_id", "kpi_snapshot", ["tenant_id"])

    if "kpi_snapshot_state" not in existing:
        op.create_table(
            "kpi_snapshot_state",
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), primary_key=True),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "kpi_snapshot_state" in existing:
        op.drop_table("kpi_snapshot_state")
    if "kpi_snapshot" in existing:
        op.drop_table("kpi_snapshot")

    if "ticket" in existing:
        columns = {c["name"] for c in inspector.get_columns("ticket")}
        with op.batch_alter_table("ticket") as batch_op:
            if "csat_submitted_at" in columns:
                batch_op.drop_column("csat_submitted_at")
            if "csat_comment" in columns:
                batch_op.drop_column("csat_comment")
            if "csat_rating" in columns:
                batch_op.drop_column("csat_rating")

    if "sla_definition" in existing:
        columns = {c["name"] for c in inspector.get_columns("sla_definition")}
        with op.batch_alter_table("sla_definition") as batch_op:
            if "counterparty" in columns:
                batch_op.drop_column("counterparty")
            if "agreement_type" in columns:
                batch_op.drop_column("agreement_type")
