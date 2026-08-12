"""B-130 notification templates and per-user delivery preferences:
NotificationTemplate (tenant-scoped, admin-editable subject/body per
event_type) and NotificationPreference (per-user email opt-out and
per-event-type mute list).

Revision ID: 20260812_0078
Revises: 20260811_0077
"""
from alembic import op
import sqlalchemy as sa

revision = "20260812_0078"
down_revision = "20260811_0077"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("notification_preference"):
        op.create_table(
            "notification_preference",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False, unique=True),
            sa.Column("email_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("muted_event_types", sa.Text(), nullable=False, server_default="[]"),
        )
    if not inspector.has_table("notification_template"):
        op.create_table(
            "notification_template",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("event_type", sa.String(length=64), nullable=False),
            sa.Column("subject_template", sa.String(length=255), nullable=False),
            sa.Column("body_template", sa.Text(), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "event_type", name="uq_notification_template_tenant_event"),
        )
        op.create_index("ix_notification_template_tenant_id", "notification_template", ["tenant_id"])


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("notification_template"):
        op.drop_table("notification_template")
    if inspector.has_table("notification_preference"):
        op.drop_table("notification_preference")
