"""mobile push devices

Revision ID: 20260814_0082
Revises: 20260814_0081
"""
from alembic import op
import sqlalchemy as sa

revision = "20260814_0082"
down_revision = "20260814_0081"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if "mobile_push_device" in set(sa.inspect(bind).get_table_names()):
        return
    op.create_table(
        "mobile_push_device",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_encrypted", sa.Text(), nullable=False),
        sa.Column("environment", sa.String(length=12), nullable=False, server_default="sandbox"),
        sa.Column("app_version", sa.String(length=40), nullable=False),
        sa.Column("app_build", sa.String(length=40), nullable=False),
        sa.Column("device_model", sa.String(length=120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_delivered_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(length=500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_mobile_push_device_token_hash"),
        sa.UniqueConstraint("tenant_id", "user_id", "device_id", name="uq_mobile_push_device_owner_device"),
    )
    op.create_index("ix_mobile_push_device_token_hash", "mobile_push_device", ["token_hash"])
    op.create_index("ix_mobile_push_device_user_id", "mobile_push_device", ["user_id"])
    op.create_index("ix_mobile_push_device_tenant_id", "mobile_push_device", ["tenant_id"])


def downgrade():
    # Additive and safely ignored by revision 0081. Retaining registrations
    # avoids silently disabling every user's push installation on rollback.
    pass
