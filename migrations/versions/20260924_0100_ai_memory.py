"""Per-person assistant memory: short notes a person explicitly asked the assistant to keep.

Revision ID: 20260924_0100
Revises: 20260923_0099
"""
from alembic import op
import sqlalchemy as sa

revision = "20260924_0100"
down_revision = "20260923_0099"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "memory_enabled" not in {c["name"] for c in inspector.get_columns("ai_configuration")}:
        op.add_column("ai_configuration", sa.Column("memory_enabled", sa.Boolean(), nullable=False, server_default=sa.true()))
    if "ai_memory" not in inspector.get_table_names():
        op.create_table(
            "ai_memory",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("kind", sa.String(20), nullable=False, server_default="fact"),
            sa.Column("text", sa.String(240), nullable=False),
            sa.Column("source", sa.String(30), nullable=False, server_default="asked"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_used_at", sa.DateTime(timezone=True)),
            sa.Column("use_count", sa.Integer(), nullable=False, server_default="0"),
        )
        op.create_index("ix_ai_memory_tenant_id", "ai_memory", ["tenant_id"])
        op.create_index("ix_ai_memory_user_id", "ai_memory", ["user_id"])


def downgrade():
    bind = op.get_bind()
    if "ai_memory" in sa.inspect(bind).get_table_names():
        if bind.execute(sa.text("SELECT COUNT(*) FROM ai_memory")).scalar():
            raise RuntimeError("Refusing to drop assistant memories. Ask people to clear them, or archive them first.")
        op.drop_table("ai_memory")
    with op.batch_alter_table("ai_configuration") as batch:
        batch.drop_column("memory_enabled")
