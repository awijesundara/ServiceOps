"""Add governed priority and business-calendar SLA execution.

Revision ID: 20260726_0006
Revises: 20260726_0005
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0006"
down_revision = "20260726_0005"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    ticket_columns = {c["name"] for c in inspector.get_columns("ticket")}
    with op.batch_alter_table("ticket") as batch:
        if "impact" not in ticket_columns:
            batch.add_column(sa.Column("impact", sa.String(20), nullable=False, server_default="Medium"))
        if "urgency" not in ticket_columns:
            batch.add_column(sa.Column("urgency", sa.String(20), nullable=False, server_default="Medium"))
        if "priority_overridden" not in ticket_columns:
            batch.add_column(sa.Column("priority_overridden", sa.Boolean(), nullable=False, server_default=sa.false()))
        if "priority_override_reason" not in ticket_columns:
            batch.add_column(sa.Column("priority_override_reason", sa.Text()))
    tables = set(inspector.get_table_names())
    if "business_schedule" not in tables:
        op.create_table(
            "business_schedule",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("timezone_name", sa.String(80), nullable=False),
            sa.Column("weekdays_json", sa.Text(), nullable=False),
            sa.Column("start_time_text", sa.String(5), nullable=False),
            sa.Column("end_time_text", sa.String(5), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("tenant_id", "name", name="uq_business_schedule_tenant_name"),
        )
        op.create_index("ix_business_schedule_tenant_id", "business_schedule", ["tenant_id"])
    if "schedule_holiday" not in tables:
        op.create_table(
            "schedule_holiday",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("schedule_id", sa.Integer(), sa.ForeignKey("business_schedule.id"), nullable=False),
            sa.Column("holiday_date", sa.Date(), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.UniqueConstraint("schedule_id", "holiday_date", name="uq_schedule_holiday_date"),
        )
    if "sla_event" not in tables:
        op.create_table(
            "sla_event",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("task_sla_id", sa.Integer(), sa.ForeignKey("task_sla.id"), nullable=False),
            sa.Column("event_type", sa.String(30), nullable=False),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("details", sa.Text(), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_sla_event_tenant_id", "sla_event", ["tenant_id"])
    sla_columns = {c["name"] for c in sa.inspect(bind).get_columns("sla_definition")}
    if "schedule_id" not in sla_columns:
        with op.batch_alter_table("sla_definition") as batch:
            batch.add_column(sa.Column("schedule_id", sa.Integer()))
            batch.create_foreign_key(
                "fk_sla_definition_schedule_id", "business_schedule",
                ["schedule_id"], ["id"],
            )


def downgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    sla_columns = {c["name"] for c in sa.inspect(bind).get_columns("sla_definition")}
    if "schedule_id" in sla_columns:
        with op.batch_alter_table("sla_definition") as batch:
            batch.drop_column("schedule_id")
    for table in ("sla_event", "schedule_holiday", "business_schedule"):
        if table in tables:
            op.drop_table(table)
    ticket_columns = {c["name"] for c in sa.inspect(bind).get_columns("ticket")}
    with op.batch_alter_table("ticket") as batch:
        for column in ("priority_override_reason", "priority_overridden", "urgency", "impact"):
            if column in ticket_columns:
                batch.drop_column(column)
