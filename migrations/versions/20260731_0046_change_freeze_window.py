"""Change freeze windows -- real blackout enforcement for change enablement.
Previously CHANGE_FREEZE_MESSAGE was a banner with no gate behind it; this
table plus active_change_freeze() actually blocks Standard/Normal change
submission and approval inside a declared window.

Revision ID: 20260731_0046
Revises: 20260731_0045
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0046"
down_revision = "20260731_0045"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "change_freeze_window" in inspector.get_table_names():
        return
    op.create_table(
        "change_freeze_window",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
    )
    op.create_index("ix_change_freeze_window_tenant_id", "change_freeze_window", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "change_freeze_window" in inspector.get_table_names():
        op.drop_table("change_freeze_window")
