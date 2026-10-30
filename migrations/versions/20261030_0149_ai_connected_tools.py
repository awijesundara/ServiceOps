"""Connected tools (MCP) for the chat assistant.

Adds ai_tool_server (remote MCP servers an administrator registers), ai_tool
(the tools each server offers, off until enabled one by one) and
ai_configuration.tools_enabled (the master switch, off by default).
Expand only; earlier versions never read these.

Revision ID: 20261030_0149
Revises: 20261029_0148
"""
from alembic import op
import sqlalchemy as sa

revision = "20261030_0149"
down_revision = "20261029_0148"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "ai_tool_server" not in tables:  # a new database's baseline already created it from the models
        op.create_table(
            "ai_tool_server",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("name", sa.String(length=80), nullable=False),
            sa.Column("url", sa.String(length=500), nullable=False),
            sa.Column("auth_header", sa.String(length=80), nullable=False, server_default="Authorization"),
            sa.Column("auth_encrypted", sa.Text(), nullable=False, server_default=""),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("minimum_role", sa.String(length=20), nullable=False, server_default="agent"),
            sa.Column("share_external", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("server_info", sa.String(length=200), nullable=False, server_default=""),
            sa.Column("last_ok", sa.Boolean()),
            sa.Column("last_checked_at", sa.DateTime(timezone=True)),
            sa.Column("last_error", sa.String(length=300), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("tenant_id", "name", name="uq_ai_tool_server_name"),
        )
        op.create_index("ix_ai_tool_server_tenant_id", "ai_tool_server", ["tenant_id"])
    if "ai_tool" not in tables:
        op.create_table(
            "ai_tool",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("server_id", sa.String(length=36), sa.ForeignKey("ai_tool_server.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False, server_default=""),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("input_schema_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("read_only", sa.Boolean()),
            sa.Column("destructive", sa.Boolean()),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("server_id", "name", name="uq_ai_tool_name"),
        )
        op.create_index("ix_ai_tool_tenant_id", "ai_tool", ["tenant_id"])
        op.create_index("ix_ai_tool_server_id", "ai_tool", ["server_id"])
    columns = {column["name"] for column in inspector.get_columns("ai_configuration")}
    if "tools_enabled" not in columns:
        op.add_column("ai_configuration", sa.Column("tools_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("ai_configuration", "tools_enabled")
    op.drop_index("ix_ai_tool_server_id", table_name="ai_tool")
    op.drop_index("ix_ai_tool_tenant_id", table_name="ai_tool")
    op.drop_table("ai_tool")
    op.drop_index("ix_ai_tool_server_tenant_id", table_name="ai_tool_server")
    op.drop_table("ai_tool_server")
