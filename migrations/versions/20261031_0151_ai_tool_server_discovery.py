"""Standard sign-in discovery for connected MCP servers.

Adds ai_tool_server.issuer and resource (from the server's protected resource
metadata, RFC 9728) and token_url_manual (an administrator override of the
discovered token endpoint). Existing client-credentials servers keep their
token address, marked as set by hand. Expand only.

Revision ID: 20261031_0151
Revises: 20261030_0150
"""
from alembic import op
import sqlalchemy as sa

revision = "20261031_0151"
down_revision = "20261030_0150"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ai_tool_server")}
    if "issuer" not in existing:  # a new database's baseline already created them from the models
        op.add_column("ai_tool_server", sa.Column("issuer", sa.String(length=500), nullable=False, server_default=""))
    if "resource" not in existing:
        op.add_column("ai_tool_server", sa.Column("resource", sa.String(length=500), nullable=False, server_default=""))
    if "token_url_manual" not in existing:
        op.add_column("ai_tool_server", sa.Column("token_url_manual", sa.Boolean(), nullable=False, server_default=sa.false()))
        op.execute("UPDATE ai_tool_server SET token_url_manual = TRUE WHERE auth_mode = 'client_credentials' AND token_url <> ''")


def downgrade():
    op.drop_column("ai_tool_server", "token_url_manual")
    op.drop_column("ai_tool_server", "resource")
    op.drop_column("ai_tool_server", "issuer")
