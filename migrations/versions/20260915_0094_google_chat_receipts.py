"""Add durable idempotency receipts for inbound Google Chat commands.

Revision ID: 20260915_0094
Revises: 20260915_0093
"""
from alembic import op
import sqlalchemy as sa


revision = "20260915_0094"
down_revision = "20260915_0093"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "google_chat_command_receipt" not in inspector.get_table_names():
        op.create_table(
            "google_chat_command_receipt",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("message_id", sa.String(200), nullable=False),
            sa.Column("connection_id", sa.Integer(), sa.ForeignKey("integration_connection.id"), nullable=False),
            sa.Column("thread_name", sa.String(200), nullable=False),
            sa.Column("reply_text", sa.Text(), nullable=False),
            sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("replied_at", sa.DateTime(timezone=True)),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index(
            "ix_google_chat_command_receipt_message_id",
            "google_chat_command_receipt", ["message_id"], unique=True,
        )
        op.create_index(
            "ix_google_chat_command_receipt_tenant_id",
            "google_chat_command_receipt", ["tenant_id"],
        )


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if "google_chat_command_receipt" in inspector.get_table_names():
        op.drop_table("google_chat_command_receipt")
