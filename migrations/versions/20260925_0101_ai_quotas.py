"""Respect provider allowances: per-service limits and a short call log.

Revision ID: 20260925_0101
Revises: 20260924_0100
"""
from alembic import op
import sqlalchemy as sa

revision = "20260925_0101"
down_revision = "20260924_0100"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

COLUMNS = (("rpm_limit", sa.Integer(), None), ("tpm_limit", sa.Integer(), None), ("rpd_limit", sa.Integer(), None),
           ("quota_tz", sa.String(40), "UTC"), ("cooldown_until", sa.DateTime(timezone=True), None))


def upgrade():
    inspector = sa.inspect(op.get_bind())
    have = {c["name"] for c in inspector.get_columns("ai_connection")}
    for name, kind, default in COLUMNS:
        if name not in have:
            op.add_column("ai_connection", sa.Column(name, kind, nullable=default is None,
                                                     server_default=default if default is not None else None))
    if "ai_call" not in inspector.get_table_names():
        op.create_table(
            "ai_call",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("connection_id", sa.String(36), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("status", sa.String(12), nullable=False, server_default="started"),
        )
        op.create_index("ix_ai_call_tenant_id", "ai_call", ["tenant_id"])
        op.create_index("ix_ai_call_connection_id", "ai_call", ["connection_id"])
        op.create_index("ix_ai_call_started_at", "ai_call", ["started_at"])


def downgrade():
    bind = op.get_bind()
    if "ai_call" in sa.inspect(bind).get_table_names():
        op.drop_table("ai_call")  # a short-lived operational log; nothing to preserve
    with op.batch_alter_table("ai_connection") as batch:
        for name, _, _ in COLUMNS:
            batch.drop_column(name)
