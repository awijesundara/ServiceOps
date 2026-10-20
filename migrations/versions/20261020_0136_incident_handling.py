"""Incident handling: caller and opener, hold reasons, counts, templates and assignment rules.

- ticket.opened_by_id: who logged the record (requester_id remains the caller);
  existing rows are backfilled with their caller.
- ticket.hold_reason: why a Pending incident is waiting.
- ticket.reassignment_count and ticket.reopen_count.
- incident_template and assignment_rule tables.

Revision ID: 20261020_0136
Revises: 20261020_0135
"""
from alembic import op
import sqlalchemy as sa

revision = "20261020_0136"
down_revision = "20261020_0135"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


NEW_COLUMNS = (
    ("opened_by_id", sa.Integer(), {}),
    ("hold_reason", sa.String(40), {}),
    ("reassignment_count", sa.Integer(), {"nullable": False, "server_default": "0"}),
    ("reopen_count", sa.Integer(), {"nullable": False, "server_default": "0"}),
)


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {column["name"] for column in inspector.get_columns("ticket")}
    for name, column_type, options in NEW_COLUMNS:
        if name not in existing:
            op.add_column("ticket", sa.Column(name, column_type, **options))
    if bind.dialect.name == "postgresql" and "opened_by_id" not in existing:
        op.create_foreign_key("fk_ticket_opened_by_id_user", "ticket", "user", ["opened_by_id"], ["id"])
    op.execute("UPDATE ticket SET opened_by_id = requester_id WHERE opened_by_id IS NULL")
    tables = set(inspector.get_table_names())
    if "incident_template" not in tables:
        op.create_table(
            "incident_template",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
            sa.Column("name", sa.String(80), nullable=False),
            sa.Column("title", sa.String(180), nullable=False, server_default=""),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("category", sa.String(80), nullable=False, server_default=""),
            sa.Column("subcategory", sa.String(80), nullable=False, server_default=""),
            sa.Column("impact", sa.String(20), nullable=False, server_default="Medium"),
            sa.Column("urgency", sa.String(20), nullable=False, server_default="Medium"),
            sa.Column("group_id", sa.Integer(), sa.ForeignKey("support_group.id"), nullable=True),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("tenant_id", "name", name="uq_incident_template_tenant_name"),
        )
    if "assignment_rule" not in tables:
        op.create_table(
            "assignment_rule",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
            sa.Column("name", sa.String(80), nullable=False),
            sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("category", sa.String(80), nullable=False, server_default=""),
            sa.Column("subcategory", sa.String(80), nullable=False, server_default=""),
            sa.Column("ci_class", sa.String(80), nullable=False, server_default=""),
            sa.Column("service_offering_id", sa.Integer(), sa.ForeignKey("service_offering.id"), nullable=True),
            sa.Column("group_id", sa.Integer(), sa.ForeignKey("support_group.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )


def downgrade():
    op.drop_table("assignment_rule")
    op.drop_table("incident_template")
    with op.batch_alter_table("ticket") as batch:
        batch.drop_column("reopen_count")
        batch.drop_column("reassignment_count")
        batch.drop_column("hold_reason")
        batch.drop_column("opened_by_id")
